//! Encrypted, source-addressed reference host for one owned conversation.

use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use contextdb_agent_runtime::{
    ExecutionAdapters, InteractionAnswer, NoExternalTools, OwnedAgentRuntime, OwnedHybridSettings,
    OwnerDispatchFence, RuntimeSettings, StartRun,
};
use contextdb_continuity::{OwnedRunIdentity, OwnedRunStatus};
use contextdb_core::TimestampMicros;
use contextdb_native_service::NativeService;
use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::{
    AuthenticatedRequestContext, AuthenticationEvidence, Capability, CapturePort,
    CognitiveMemoryService, ErrorCode, OwnedRunPort, RequestContext, SavedRunCheckpoint,
    Sensitivity, ServiceError, TextEmbeddingAdapter, VerifyRequest,
};
use serde::Deserialize;
use serde_json::json;

use crate::codex_service::open_native_owner;
use crate::production::ProductionService;
use crate::{CliError, CliResult, TokenKey, codex_operator_authority, load_state};

mod binding;
mod config;
mod hybrid_encoder;
mod hybrid_index;
mod kev;
mod preparation;
mod reader;

use config::HostConfig;
pub(crate) use hybrid_index::RoutedStage;
use preparation::NativePreparation;
use reader::LocalReader;

const MAX_COMMAND_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROCESS_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMMANDS: usize = 256;
const OWNED_WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;

const HYBRID_STARTUP_TIME_MS: u64 = 120_000;
const HYBRID_STARTUP_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const HYBRID_STARTUP_MAX_WORK: u64 = 1_000_000;
const HYBRID_SHUTDOWN_TIME_MS: u64 = 10_000;
const HYBRID_SHUTDOWN_MAX_BYTES: u64 = 1024 * 1024;
const HYBRID_SHUTDOWN_MAX_WORK: u64 = 100_000;
const ROUTED_MAINTENANCE_MAX_WORK: u64 = 250_000_000;
const ROUTED_MAINTENANCE_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const ROUTED_MAINTENANCE_TIME_MS: u64 = 180_000;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    User { text: String },
    Continue,
    Finish,
}

/// Bound the physical stack for the two owned CLI commands. Owners and models
/// are opened by the closure inside this worker; logical allowances are unchanged.
pub(crate) fn run_on_owned_stack(
    operation: impl FnOnce() -> CliResult<()> + Send + 'static,
) -> CliResult<()> {
    let worker = std::thread::Builder::new()
        .name("contextdb-owned-cli".into())
        .stack_size(OWNED_WORKER_STACK_BYTES)
        .spawn(operation)
        .map_err(|_| {
            CliError::from(ServiceError::new(
                ErrorCode::Unavailable,
                "owned CLI worker could not start",
                false,
            ))
        })?;
    worker.join().map_err(|_| {
        CliError::from(ServiceError::new(
            ErrorCode::Unavailable,
            "owned CLI worker panicked; inspect retained operation state before continuing",
            false,
        ))
    })?
}

pub(crate) fn run(path: &Path, config_path: &Path, start: bool) -> CliResult<()> {
    let config = HostConfig::read(config_path)?;
    let identity = config.identity();
    let digest = config.digest()?;
    let settings = config.settings()?;
    let timeout = Duration::from_millis(config.reader.timeout_millis) + Duration::from_secs(30);

    // Keep the authenticated lifecycle writer lock for the entire process. A
    // live broker or another owner cannot share this publication authority.
    let state = load_state(path)?;
    let lifecycle = ProductionService::open(path, state.clone())?;
    lifecycle.verify(VerifyRequest {
        context: codex_operator_authority(&state.key, "owned-conversation")?.request,
        deep: true,
    })?;
    let (native, _) = open_native_owner(path, &state, true)?;
    let kev = config
        .development_kev
        .as_ref()
        .map(kev::KevScorer::new)
        .transpose()?
        .map(Arc::new);
    let native = if let Some(scorer) = &kev {
        native.with_preparation_scorer(scorer.clone())?
    } else {
        native
    };
    let owner = Arc::new(native);
    let mut context = authority(&state.key, &identity, &digest)?;
    if kev.is_some() || config.automatic_hybrid.is_some() {
        context
            .capability_grants
            .insert(Capability::ModelProcessing);
    }
    owner.recover_record_writes(&context, &mut budget(timeout))?;
    let previous = owner.load_run_checkpoint(&context, identity.run_id, &mut budget(timeout))?;
    if start && previous.is_some() {
        return Err(invalid("owned run already exists; use explicit resume"));
    }
    if !start && previous.is_none() {
        return Err(ServiceError::new(
            ErrorCode::NotFound,
            "owned run has no checkpoint; resume cannot start a run",
            false,
        )
        .into());
    }
    if previous.as_ref().is_some_and(|saved| {
        saved.checkpoint.identity != identity
            || saved.checkpoint.model_profile != config.reader.model_profile
    }) {
        return Err(invalid(
            "configured run or reader differs from its checkpoint",
        ));
    }
    if start {
        owner.initialize_state_catalog(&context, &mut budget(timeout))?;
    }
    let binding = binding::require_binding(&owner, &context, &identity, &digest, start)?;
    if let Some(scorer) = &kev {
        scorer.warm()?;
    }

    // Launch only after retained ownership and exact run configuration admission.
    let hybrid = config.automatic_hybrid;
    hybrid_encoder::with_encoder(hybrid.as_ref(), |encoder| {
        let mut settings = settings;
        let preparation = match encoder {
            Some(encoder) => {
                let limits = hybrid.as_ref().expect("declared hybrid encoder").limits;
                settings.automatic_hybrid = Some(OwnedHybridSettings {
                    query_encoder: encoder.clone(),
                    limits,
                });
                if limits.routed.is_some() {
                    NativePreparation::with_routed(owner.clone(), encoder, limits)
                } else {
                    NativePreparation::with_hybrid(owner.clone(), encoder)
                }
            }
            None => NativePreparation::new(owner.clone()),
        };
        drive(
            BoundHost {
                owner,
                context,
                identity,
                binding,
                timeout,
            },
            config.reader,
            settings,
            preparation,
            start,
        )
    })
}

struct BoundHost {
    owner: Arc<NativeService>,
    context: AuthenticatedRequestContext,
    identity: OwnedRunIdentity,
    binding: binding::AcceptedBinding,
    timeout: Duration,
}

fn drive(
    host: BoundHost,
    reader_config: reader::LocalReaderConfig,
    settings: RuntimeSettings,
    preparation: NativePreparation,
    start: bool,
) -> CliResult<()> {
    let BoundHost {
        owner,
        context,
        identity,
        binding,
        timeout,
    } = host;
    let reader = LocalReader::spawn(reader_config)?;
    reader.begin_turn()?;
    let mut runtime = if start {
        OwnedAgentRuntime::start(
            owner.clone(),
            context.clone(),
            StartRun {
                identity: identity.clone(),
                model_profile: reader.model_profile().clone(),
                recorded_at: binding.recorded_at,
            },
            settings,
            &mut budget(timeout),
        )?
    } else {
        OwnedAgentRuntime::resume(
            owner.clone(),
            context.clone(),
            identity.run_id,
            settings,
            now()?,
            &mut budget(timeout),
        )?
    };
    let saved = checkpoint(&owner, &context, &runtime, &mut budget(timeout))?;
    emit(&json!({
        "type":"ready", "run_id":identity.run_id,
        "checkpoint_revision":saved.checkpoint.revision,
        "checkpoint_receipt":saved.receipt, "config_receipt":binding.receipt,
        "run_status":saved.checkpoint.status,
        "model_outcome_unknown":runtime.model_outcome_unknown()
    }))?;

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let fence = OwnerDispatchFence::new(owner.clone());
    let adapters = ExecutionAdapters {
        reader: &reader,
        model_fence: &fence,
        tool_fence: &fence,
        preparation: &preparation,
        tools: &NoExternalTools,
    };
    let mut total_bytes = 0_usize;
    let mut commands = 0_usize;
    while let Some(bytes) = read_line(&mut input)? {
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("conversation input counter overflow"))?;
        commands += 1;
        if total_bytes > MAX_PROCESS_INPUT_BYTES || commands > MAX_COMMANDS {
            return Err(invalid(
                "conversation process input allowance exhausted; resume explicitly",
            ));
        }
        let command: Input = serde_json::from_slice(&bytes).map_err(|_| {
            invalid("invalid conversation command; expected user, continue or finish")
        })?;
        reader.begin_turn()?;
        let mut allowance = budget(timeout);
        let result = execute(
            command,
            &owner,
            &context,
            &mut runtime,
            &adapters,
            &mut allowance,
        );
        if let Err(error) = result {
            emit(&json!({
                "type":"failed", "run_id":identity.run_id,
                "error_code":error.0.code,
                "model_outcome_unknown":runtime.model_outcome_unknown(),
                "measurements":runtime.drain_measurements()
            }))?;
            return Err(error);
        }
        if runtime.checkpoint().status != OwnedRunStatus::Active {
            return Ok(());
        }
    }
    let saved = checkpoint(&owner, &context, &runtime, &mut budget(timeout))?;
    emit(&json!({
        "type":"paused", "run_id":identity.run_id,
        "checkpoint_revision":saved.checkpoint.revision, "checkpoint_receipt":saved.receipt,
        "run_status":saved.checkpoint.status,
        "model_outcome_unknown":runtime.model_outcome_unknown(),
        "measurements":runtime.drain_measurements()
    }))
}

pub(crate) fn index(
    path: &Path,
    config_path: &Path,
    bootstrap: bool,
    routed_stage: Option<RoutedStage>,
) -> CliResult<()> {
    let config = HostConfig::read(config_path)?;
    let hybrid = config
        .automatic_hybrid
        .as_ref()
        .ok_or_else(|| invalid("owned hybrid indexing requires automatic_hybrid configuration"))?;
    if hybrid.limits.routed.is_some() != routed_stage.is_some() {
        return Err(invalid(
            "routed indexing requires matching routed configuration and an explicit stage",
        ));
    }
    if bootstrap && routed_stage.is_some_and(|stage| stage != RoutedStage::Raw) {
        return Err(invalid("routed bootstrap requires the raw stage"));
    }
    let identity = config.identity();
    let digest = config.digest()?;
    let timeout = Duration::from_millis(config.reader.timeout_millis) + Duration::from_secs(30);
    let state = load_state(path)?;
    let lifecycle = ProductionService::open(path, state.clone())?;
    lifecycle.verify(VerifyRequest {
        context: codex_operator_authority(&state.key, "owned-hybrid-index")?.request,
        deep: true,
    })?;
    let (owner, _) = open_native_owner(path, &state, true)?;
    let mut context = authority(&state.key, &identity, &digest)?;
    context
        .capability_grants
        .insert(Capability::ModelProcessing);
    owner.recover_record_writes(&context, &mut budget(timeout))?;
    if let Some(stage) = routed_stage {
        let mode = if bootstrap {
            hybrid_index::Mode::Bootstrap
        } else {
            hybrid_index::Mode::Continue
        };
        let mut allowance = routed_maintenance_budget();
        let needs_encoder = match stage {
            RoutedStage::Raw | RoutedStage::Router => false,
            RoutedStage::Base | RoutedStage::Seal => {
                let target =
                    owner.original_span_routed_maintenance_target(&context, &mut allowance)?;
                match stage {
                    RoutedStage::Base => {
                        target.base.is_none()
                            && target.dense.as_ref().is_none_or(|dense| dense.spans == 0)
                    }
                    RoutedStage::Seal => target
                        .dense
                        .as_ref()
                        .zip(target.covered.as_ref())
                        .is_some_and(|(dense, covered)| {
                            dense.sources == covered.sources
                                && dense.commitment == covered.commitment
                                && (!dense.caught_up || !target.dense_matches_raw)
                        }),
                    _ => unreachable!("source stage matched"),
                }
            }
        };
        return hybrid_encoder::with_encoder(needs_encoder.then_some(hybrid), |encoder| {
            let progress = hybrid_index::advance_routed(
                &owner,
                &context,
                encoder
                    .as_deref()
                    .map(|encoder| encoder as &dyn TextEmbeddingAdapter),
                mode,
                stage,
                &mut allowance,
                |request| {
                    emit(&json!({
                        "type": "routed_index_request", "stage": stage, "request": request
                    }))
                },
            )?;
            emit(&json!({ "type": "routed_hybrid_index", "progress": progress }))
        });
    }
    hybrid_encoder::with_encoder(Some(hybrid), |encoder| {
        let encoder = encoder.ok_or_else(|| invalid("owned hybrid encoder was not launched"))?;
        let mode = if bootstrap {
            hybrid_index::Mode::Bootstrap
        } else {
            hybrid_index::Mode::Continue
        };
        let progress = hybrid_index::advance(
            &owner,
            &context,
            encoder.as_ref(),
            mode,
            &mut budget(timeout),
        )?;
        emit(&json!({ "type": "hybrid_index", "progress": progress }))
    })
}

fn execute(
    command: Input,
    owner: &Arc<NativeService>,
    context: &AuthenticatedRequestContext,
    runtime: &mut OwnedAgentRuntime<NativeService>,
    adapters: &ExecutionAdapters<'_>,
    allowance: &mut QueryBudget,
) -> CliResult<()> {
    if let Input::Finish = command {
        runtime.finish(OwnedRunStatus::Completed, now()?, allowance)?;
        let saved = checkpoint(owner, context, runtime, allowance)?;
        return emit(&json!({
            "type":"finished", "run_id":saved.checkpoint.identity.run_id,
            "checkpoint_revision":saved.checkpoint.revision, "checkpoint_receipt":saved.receipt,
            "measurements":runtime.drain_measurements()
        }));
    }
    if let Input::User { text } = command {
        let receipt = runtime.accept_user(text, now()?, allowance)?;
        let saved = checkpoint(owner, context, runtime, allowance)?;
        emit(&json!({
            "type":"accepted", "source_receipt":receipt,
            "checkpoint_revision":saved.checkpoint.revision, "checkpoint_receipt":saved.receipt
        }))?;
    }
    let answer = runtime.drive(adapters, 4, now()?, allowance)?;
    let saved = checkpoint(owner, context, runtime, allowance)?;
    let (output_receipt, recovered) = match &answer {
        InteractionAnswer::Generated(turn) => (&turn.output_receipt, false),
        InteractionAnswer::Recovered(turn) => (&turn.output_receipt, true),
    };
    emit(&json!({
        "type":"answer", "reply":answer.reply(), "output_receipt":output_receipt,
        "checkpoint_revision":saved.checkpoint.revision, "checkpoint_receipt":saved.receipt,
        "recovered":recovered, "measurements":runtime.drain_measurements()
    }))
}

fn checkpoint(
    owner: &NativeService,
    context: &AuthenticatedRequestContext,
    runtime: &OwnedAgentRuntime<NativeService>,
    allowance: &mut QueryBudget,
) -> CliResult<SavedRunCheckpoint> {
    let saved = owner
        .load_run_checkpoint(context, runtime.checkpoint().identity.run_id, allowance)?
        .ok_or_else(|| invalid("durable owned checkpoint is absent"))?;
    if &saved.checkpoint != runtime.checkpoint() {
        return Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "owned checkpoint acknowledgement differs from current runtime",
            false,
        )
        .into());
    }
    owner.resolve_capture_receipt(context, &saved.receipt)?;
    Ok(saved)
}

fn authority(
    key: &TokenKey,
    identity: &OwnedRunIdentity,
    digest: &str,
) -> CliResult<AuthenticatedRequestContext> {
    let channel_id = "cli:owned-conversation.v1";
    let context = AuthenticatedRequestContext {
        request: RequestContext {
            request_id: format!("owned-conversation:{}", identity.run_id),
            workspace_id: identity.workspace_id.to_string(),
            subject_id: identity.subject_id.clone(),
            audiences: BTreeSet::from([identity.subject_id.clone()]),
            scopes: identity.scopes.iter().map(ToString::to_string).collect(),
            purpose: "conversation".into(),
            clearance: Sensitivity::Private,
        },
        actor_id: identity.actor_id.clone(),
        agent_id: identity.agent_id.clone(),
        session_id: Some(identity.session_id.to_string()),
        capability_grants: BTreeSet::from([
            Capability::Runtime,
            Capability::Admin,
            Capability::Observe,
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ReadMemory,
            Capability::ReadConflict,
            Capability::Maintenance,
        ]),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: channel_id.into(),
            peer_identity: identity.actor_id.clone(),
            binding_digest: blake3::keyed_hash(
                &blake3::derive_key("contextdb/cli/owned-host-authority/v1", &key.expose_copy()),
                digest.as_bytes(),
            )
            .to_hex()
            .to_string(),
        },
    };
    context.validate_authentication()?;
    Ok(context)
}

fn budget(timeout: Duration) -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        512 * 1024 * 1024,
        timeout,
        QueryCancellation::default(),
    )
}

fn routed_maintenance_budget() -> QueryBudget {
    QueryBudget::new(
        ROUTED_MAINTENANCE_MAX_WORK,
        ROUTED_MAINTENANCE_MAX_BYTES,
        Duration::from_millis(ROUTED_MAINTENANCE_TIME_MS),
        QueryCancellation::default(),
    )
}

fn now() -> CliResult<TimestampMicros> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("host clock precedes the supported epoch"))?
        .as_micros();
    Ok(TimestampMicros(i64::try_from(micros).map_err(|_| {
        invalid("host clock exceeds timestamp range")
    })?))
}

fn invalid(message: &'static str) -> CliError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false).into()
}

fn read_line(input: &mut impl BufRead) -> CliResult<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let available = input
            .fill_buf()
            .map_err(|_| invalid("conversation input cannot be read"))?;
        if available.is_empty() {
            return Ok((!bytes.is_empty()).then_some(bytes));
        }
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1);
        let count = end.unwrap_or(available.len());
        if count > MAX_COMMAND_BYTES.saturating_sub(bytes.len()) {
            return Err(invalid("conversation command exceeds 2 MiB"));
        }
        bytes.extend_from_slice(&available[..count]);
        input.consume(count);
        if end.is_some() {
            return Ok(Some(bytes));
        }
    }
}

fn emit(value: &serde_json::Value) -> CliResult<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)
        .map_err(|_| invalid("conversation response cannot be encoded"))?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|_| invalid("conversation response cannot be acknowledged"))
}

#[cfg(test)]
mod stack_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn owned_worker_joins_typed_errors_and_unwinds_before_reporting_a_panic() {
        let error = run_on_owned_stack(|| {
            Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "retained source admission refused",
                false,
            )
            .into())
        })
        .expect_err("worker returns the genuine typed error");
        assert_eq!(error.0.code, ErrorCode::IndexTooStale);
        assert!(!error.0.retryable);
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let observation = dropped.clone();
        let error = run_on_owned_stack(move || {
            let _guard = Dropped(observation);
            panic!("controlled owned worker panic");
        })
        .expect_err("panic is not a successful operation or an implicit retry");
        assert_eq!(error.0.code, ErrorCode::Unavailable);
        assert!(!error.0.retryable);
        assert!(
            dropped.load(Ordering::SeqCst),
            "join waits for worker resource unwinding"
        );
    }
}
