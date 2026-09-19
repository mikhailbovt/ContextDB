use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use contextdb_context::{Result, *};
use contextdb_continuity::*;
use contextdb_core::*;
use contextdb_native_service::NativeService;
use contextdb_recall::QueryBudget;
use contextdb_service::{Capability, *};

use super::*;

fn budget() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}
fn now() -> TimestampMicros {
    TimestampMicros(1_000_000)
}
fn profile() -> ModelProfile {
    ModelProfile {
        id: "scripted-text-reader".into(),
        family: "deterministic-fixture".into(),
        tokenizer_id: ReferenceTokenizer::ID.into(),
        renderer: RendererKind::Compact,
        max_context_tokens: 32000,
        reserved_output_tokens: 4000,
        preferred_structured_format: StructuredFormat::CompactText,
        supports_tool_results: false,
        supports_native_citations: false,
        supports_prompt_caching: false,
        position_profile: PositionProfile::CriticalFirst,
        instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
        max_schema_complexity: 64,
        external_processing: false,
    }
}
fn settings() -> RuntimeSettings {
    RuntimeSettings {
        control: vec![],
        purpose: PackPurpose::Conversation,
        memory_budget: ContextBudgets {
            hard_tokens: 14000,
            soft_tokens: 12000,
            max_blocks: 64,
            max_evidence_blocks: 128,
            max_raw_evidence_tokens: 10000,
            max_history_tokens: 10000,
            max_conflict_tokens: 10000,
            max_serialized_bytes: 2 * 1024 * 1024,
            max_selection_evaluations: 128,
        },
        outgoing_budget: OutgoingBudget {
            max_input_tokens: 27000,
            safety_tokens: 1000,
            max_wire_bytes: 2 * 1024 * 1024,
        },
        rolling: RollingPolicy {
            high_tokens: 3200,
            low_tokens: 2100,
            keep_complete_groups: 1,
            chunk_groups: 2,
            max_prepare_attempts: 3,
        },
    }
}
fn identity() -> (AuthenticatedRequestContext, OwnedRunIdentity) {
    let identity = OwnedRunIdentity {
        workspace_id: WorkspaceId::new(),
        session_id: SessionId::new(),
        run_id: AgentRunId::new(),
        actor_id: "fixture-owner".into(),
        agent_id: "fixture-agent".into(),
        subject_id: MemorySubjectId::new().to_string(),
        scopes: BTreeSet::from([ScopeId::new()]),
    };
    let context = AuthenticatedRequestContext {
        request: RequestContext {
            request_id: "runtime-fixture".into(),
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
            Capability::Observe,
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ReadMemory,
            Capability::ReadConflict,
            Capability::Runtime,
            Capability::Admin,
            Capability::Maintenance,
        ]),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "test-embedded".into(),
            peer_identity: "fixture-owner".into(),
            binding_digest: "aa".repeat(32),
        },
    };
    (context, identity)
}
#[derive(Debug, Default)]
struct ScriptedReader {
    calls: AtomicUsize,
    uncertain: AtomicBool,
    requests: Mutex<Vec<Vec<OutgoingMessage>>>,
    model_id: Option<&'static str>,
}
impl OutgoingEncoder for ScriptedReader {
    fn id(&self) -> &str {
        "contextdb.reference-request-json.v1"
    }
    fn tokenizer_id(&self) -> &str {
        ReferenceTokenizer::ID
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> Result<EncodedOutgoing> {
        ReferenceOutgoingEncoder(&ReferenceTokenizer).encode(messages, budget)
    }
}
impl ReaderAdapter for ScriptedReader {
    fn profile(&self) -> ModelProfile {
        let mut profile = profile();
        if let Some(id) = self.model_id {
            profile.id = id.into();
        }
        profile
    }
    fn capabilities(&self) -> ReaderCapabilities {
        ReaderCapabilities {
            history: ReaderHistory::Stateless,
            history_contract:
                "test fixture decodes only the passed JSON bytes; no hidden session state".into(),
            can_reconcile: true,
        }
    }
    fn tokenizer(&self) -> &dyn TokenCounter {
        &ReferenceTokenizer
    }
    fn capture_manifest(
        &self,
        call: ModelCallId,
        messages: &[OutgoingMessage],
        wire: &EncodedOutgoing,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ModelRequestManifest> {
        ReferenceOutgoingEncoder(&ReferenceTokenizer)
            .capture_manifest(call, messages, wire, budget)
            .map_err(context_error)
    }
    fn complete(&self, _: ModelCallId, wire: &EncodedOutgoing) -> ServiceResult<ReaderReply> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("requests")
            .push(serde_json::from_slice(&wire.wire).expect("exact request JSON"));
        if self.uncertain.load(Ordering::SeqCst) {
            return Err(ServiceError::new(
                ErrorCode::ProviderUnavailable,
                "simulated lost response",
                false,
            ));
        }
        Ok(ReaderReply {
            text: "Visible fixture reply: punctuation \"quotes\", backslash \\ and newline\n"
                .into(),
        })
    }
    fn reconcile(
        &self,
        _: ModelCallId,
        wire_digest: ContentDigest,
    ) -> ServiceResult<ModelReconciliation> {
        Ok(ModelReconciliation::Completed {
            wire_digest,
            reply: ReaderReply {
                text: "Recovered exact visible reply".into(),
            },
        })
    }
}
/// Only this synthetic corpus is explicitly known to contain no state assertions.
/// This fixture is not a natural-language interpreter or a production default.
#[derive(Debug)]
struct FixturePreparation(Arc<NativeService>);
impl PreparationHook for FixturePreparation {
    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for scope in &context.request.scopes {
            let scope = scope.parse().expect("scope");
            let input = self.0.interpretation_inputs(context, scope, budget)?;
            self.0.publish_assertions(
                PublishAssertionsRequest {
                    context: context.clone(),
                    idempotency_key: format!("fixture-coverage/{scope}/{}", input.scope_epoch),
                    scope,
                    expected_scope_epoch: input.scope_epoch,
                    covered_through: input.through,
                    pipeline: PipelineIdentity {
                        name: "synthetic-no-state-corpus".into(),
                        version: "1".into(),
                        schema_version: "1".into(),
                    },
                    interpretations: input
                        .events
                        .into_iter()
                        .map(|event_id| EventInterpretation {
                            event_id,
                            disposition: InterpretationDisposition::NoStateChange,
                        })
                        .collect(),
                    mutations: vec![],
                    after_receipt: None,
                },
                budget,
            )?;
        }
        self.0.project_originals(context, false, 256, budget)?;
        Ok(())
    }
}
/// Lifecycle tests deliberately use a guard stub. Native atomic dispatch leases
/// have separate integration gates; these tests make no concurrency fence claim.
#[derive(Debug)]
struct FixtureFence;
impl ModelDispatchFence for FixtureFence {
    fn before_model(
        &self,
        _: &AuthenticatedRequestContext,
        _: &CaptureReceipt,
        _: ModelCallId,
        _: &CaptureReceipt,
        _: &PreparedContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        charge(budget, 1, 0)
    }
}

#[test]
fn automatic_rolling_recalls_exact_old_incidental_text_and_resumes_without_summaries() {
    let directory = tempfile::tempdir().expect("directory");
    let owner = Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
    let (context, identity) = identity();
    owner
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&owner),
        context.clone(),
        StartRun {
            identity: identity.clone(),
            model_profile: profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    let reader = ScriptedReader::default();
    let hook = FixturePreparation(Arc::clone(&owner));
    let joke =
        "Лапшекорабль: отвергнутая шутка между фильмом и рецептом. Код «7319», а не пересказ.\n";
    runtime
        .accept_user(joke.into(), now(), &mut budget())
        .expect("capture joke");
    let joke_event = runtime.checkpoint().groups[0].messages[0].source.event_id;
    runtime
        .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
        .expect("first turn");
    let mut rotations = 0;
    for index in 0..12 {
        runtime
            .accept_user(
                format!(
                    "Независимая беседа {index}. {}",
                    "Обычная реплика о погоде, фильме и повседневных делах. ".repeat(20)
                ),
                now(),
                &mut budget(),
            )
            .expect("user");
        rotations += runtime
            .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
            .expect("turn")
            .evicted_groups;
    }
    assert!(rotations >= 4, "cross several resident windows");
    assert!(
        !runtime
            .checkpoint()
            .groups
            .iter()
            .flat_map(|group| &group.messages)
            .any(|message| message.source.event_id == joke_event)
    );
    drop(runtime);
    drop(hook);
    drop(owner);
    let owner =
        Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("reopen"));
    let mut runtime = OwnedAgentRuntime::resume(
        Arc::clone(&owner),
        context.clone(),
        identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("resume");
    runtime
        .accept_user(
            "Лапшекорабль — какая была точная шутка?".into(),
            now(),
            &mut budget(),
        )
        .expect("return to old topic");
    let turn = runtime
        .step(
            &reader,
            &FixtureFence,
            &FixturePreparation(Arc::clone(&owner)),
            &[],
            now(),
            &mut budget(),
        )
        .expect("automatic recall");
    assert!(
        turn.prepared
            .messages
            .iter()
            .any(|message| message.text.contains(joke)
                && message
                    .originals
                    .iter()
                    .any(|original| original.span.event_id == joke_event)),
        "exact incidental original reaches actual reader wire"
    );
    assert!(
        turn.prepared
            .messages
            .iter()
            .all(|message| message.text.len() < 20_000)
    );
    assert_eq!(reader.calls.load(Ordering::SeqCst), 14);
    owner
        .verify(VerifyRequest {
            context: context.request.clone(),
            deep: true,
        })
        .expect("captured complete wires and run-head history");
}

#[test]
fn restart_reconciles_an_uncertain_model_call_without_duplicate_dispatch() {
    let directory = tempfile::tempdir().expect("directory");
    let owner = Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
    let (context, identity) = identity();
    owner
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&owner),
        context.clone(),
        StartRun {
            identity: identity.clone(),
            model_profile: profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    runtime
        .accept_user(
            "What happened to that model request?".into(),
            now(),
            &mut budget(),
        )
        .expect("user");
    let reader = ScriptedReader::default();
    reader.uncertain.store(true, Ordering::SeqCst);
    let hook = FixturePreparation(Arc::clone(&owner));
    assert_eq!(
        runtime
            .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
            .expect_err("uncertain outcome")
            .code,
        ErrorCode::ProviderUnavailable
    );
    drop(runtime);
    let mut runtime = OwnedAgentRuntime::resume(
        Arc::clone(&owner),
        context.clone(),
        identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("resume unknown");
    assert!(runtime.model_outcome_unknown());
    assert!(
        runtime
            .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
            .is_err()
    );
    assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        runtime
            .reconcile_model(&reader, now(), &mut budget())
            .expect("reconcile")
            .expect("result")
            .text,
        "Recovered exact visible reply"
    );
    assert!(!runtime.model_outcome_unknown());
    assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    assert!(runtime.checkpoint().groups.last().expect("group").complete);
    owner
        .verify(VerifyRequest {
            context: context.request.clone(),
            deep: true,
        })
        .expect("reconciled capture");
}

#[test]
fn model_switch_preserves_identity_and_terminal_obligation_unpins_its_original() {
    let directory = tempfile::tempdir().expect("directory");
    let owner = Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
    let (context, identity) = identity();
    owner
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&owner),
        context,
        StartRun {
            identity: identity.clone(),
            model_profile: profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    let first = ScriptedReader::default();
    let hook = FixturePreparation(Arc::clone(&owner));
    runtime
        .accept_user(
            "Сохрани точный голос персонажа, включая его странную шутку.".into(),
            now(),
            &mut budget(),
        )
        .expect("source");
    let source = runtime.checkpoint().groups[0].messages[0].source.clone();
    runtime
        .add_obligation(
            ScopedObligation {
                id: "character-voice".into(),
                scope: *identity.scopes.first().expect("scope"),
                source: source.clone(),
                status: ObligationStatus::Open,
            },
            now(),
            &mut budget(),
        )
        .expect("obligation");
    let turn = runtime
        .step(&first, &FixtureFence, &hook, &[], now(), &mut budget())
        .expect("first reader");
    assert!(turn.prepared.messages.iter().any(|message| {
        message.zone == OutgoingZone::WorkingState
            && message
                .originals
                .iter()
                .any(|original| original.span == source)
    }));
    let second = ScriptedReader {
        model_id: Some("different-fixture-reader"),
        ..Default::default()
    };
    runtime
        .switch_reader(&second, settings(), now(), &mut budget())
        .expect("controlled switch");
    assert_eq!(runtime.checkpoint().identity, identity);
    assert_eq!(
        runtime.checkpoint().model_profile.id,
        "different-fixture-reader"
    );
    runtime
        .close_obligation(
            "character-voice",
            ObligationStatus::Completed,
            now(),
            &mut budget(),
        )
        .expect("terminal unpin");
    runtime
        .accept_user("Продолжим разговор.".into(), now(), &mut budget())
        .expect("next input");
    let turn = runtime
        .step(&second, &FixtureFence, &hook, &[], now(), &mut budget())
        .expect("second reader");
    assert!(
        !turn
            .prepared
            .messages
            .iter()
            .any(|message| message.id.as_str() == "obligation:character-voice")
    );
    assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
}

#[derive(Debug)]
struct LostOutputAcknowledgement {
    owner: Arc<NativeService>,
    lose_once: AtomicBool,
}
impl CapturePort for LostOutputAcknowledgement {
    fn append_event_with_status(
        &self,
        request: CaptureRequest,
    ) -> ServiceResult<CaptureAcceptance> {
        let output = request.event.kind == EventKind::ModelResponseCompleted;
        let accepted = self.owner.append_event_with_status(request)?;
        if output && self.lose_once.swap(false, Ordering::SeqCst) {
            return Err(ServiceError::new(
                ErrorCode::Unavailable,
                "simulated acknowledgement loss after sync",
                true,
            ));
        }
        Ok(accepted)
    }
    fn read_original(&self, request: ReadOriginalRequest) -> ServiceResult<CapturedOriginal> {
        self.owner.read_original(request)
    }
    fn resolve_capture_receipt(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &CaptureReceipt,
    ) -> ServiceResult<()> {
        self.owner.resolve_capture_receipt(context, receipt)
    }
    fn producer_coverage(
        &self,
        context: &AuthenticatedRequestContext,
        producer: StreamId,
    ) -> ServiceResult<ProducerCoverage> {
        self.owner.producer_coverage(context, producer)
    }
}
impl PayloadPort for LostOutputAcknowledgement {
    fn stage_payload(&self, request: StagePayloadRequest) -> ServiceResult<PayloadReceipt> {
        self.owner.stage_payload(request)
    }
    fn read_original_span(
        &self,
        context: &AuthenticatedRequestContext,
        span: &OriginalSourceSpan,
    ) -> ServiceResult<Vec<u8>> {
        self.owner.read_original_span(context, span)
    }
}
impl OwnedRunPort for LostOutputAcknowledgement {
    fn save_run_checkpoint(
        &self,
        request: SaveRunCheckpointRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<SavedRunCheckpoint> {
        self.owner.save_run_checkpoint(request, budget)
    }
    fn load_run_checkpoint(
        &self,
        context: &AuthenticatedRequestContext,
        run: AgentRunId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<SavedRunCheckpoint>> {
        self.owner.load_run_checkpoint(context, run, budget)
    }
    fn read_run_tail(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RunCaptureTail> {
        self.owner.read_run_tail(context, checkpoint, budget)
    }
}
impl PrepareContextPort for LostOutputAcknowledgement {
    fn prepare_context(
        &self,
        request: PrepareContextRequest,
        tokenizer: &dyn TokenCounter,
        encoder: &dyn OutgoingEncoder,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PreparedContext> {
        self.owner
            .prepare_context(request, tokenizer, encoder, budget)
    }
}

#[test]
fn lost_output_acknowledgement_pauses_until_persistence_retry_without_calling_reader_again() {
    let directory = tempfile::tempdir().expect("directory");
    let native = Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
    let owner = Arc::new(LostOutputAcknowledgement {
        owner: Arc::clone(&native),
        lose_once: AtomicBool::new(true),
    });
    let (context, identity) = identity();
    native
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let mut runtime = OwnedAgentRuntime::start(
        owner,
        context.clone(),
        StartRun {
            identity,
            model_profile: profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    let reader = ScriptedReader::default();
    let hook = FixturePreparation(Arc::clone(&native));
    runtime
        .accept_user(
            "Every visible byte must survive a lost capture acknowledgement.".into(),
            now(),
            &mut budget(),
        )
        .expect("input");
    assert_eq!(
        runtime
            .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
            .expect_err("ack loss")
            .code,
        ErrorCode::Unavailable
    );
    assert!(
        runtime
            .accept_user("Do not evict unresolved input".into(), now(), &mut budget())
            .is_err()
    );
    assert!(
        runtime
            .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
            .is_err()
    );
    runtime
        .retry_persistence(now(), &mut budget())
        .expect("same capture, no model call");
    assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    let group = runtime.checkpoint().groups.last().expect("group");
    assert!(group.complete);
    assert_eq!(group.messages.len(), 2);
    let output = native
        .read_original_span(&context, &group.messages[1].source)
        .expect("full response");
    assert_eq!(
        String::from_utf8(output).expect("UTF-8"),
        "Visible fixture reply: punctuation \"quotes\", backslash \\ and newline\n"
    );
}
