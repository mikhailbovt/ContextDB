//! Encrypted, source-addressed reference host for one owned conversation.

use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use contextdb_agent_runtime::{
    ExecutionAdapters, InteractionAnswer, NoExternalTools, OwnedAgentRuntime, OwnerDispatchFence,
    StartRun,
};
use contextdb_continuity::{OwnedRunIdentity, OwnedRunStatus};
use contextdb_core::TimestampMicros;
use contextdb_native_service::NativeService;
use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::{
    AuthenticatedRequestContext, AuthenticationEvidence, Capability, CapturePort,
    CognitiveMemoryService, ErrorCode, OwnedRunPort, RequestContext, SavedRunCheckpoint,
    Sensitivity, ServiceError, VerifyRequest,
};
use serde::Deserialize;
use serde_json::json;

use crate::codex_service::open_native_owner;
use crate::production::ProductionService;
use crate::{CliError, CliResult, TokenKey, codex_operator_authority, load_state};

mod binding;
mod config;
mod preparation;
mod reader;

use config::HostConfig;
use preparation::NativePreparation;
use reader::LocalReader;

const MAX_COMMAND_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROCESS_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMMANDS: usize = 256;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    User { text: String },
    Continue,
    Finish,
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
    let owner = Arc::new(native);
    let context = authority(&state.key, &identity, &digest)?;
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

    // No reader process or tokenizer operation occurs before all retained owner,
    // profile, identity and configuration bindings have passed verification.
    let reader = LocalReader::spawn(config.reader)?;
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
    let preparation = NativePreparation::new(owner.clone());
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
