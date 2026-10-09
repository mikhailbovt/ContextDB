//! Actual protected publication and recovery on the existing encrypted owner.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use contextdb_agent_runtime::{
    ModelReconciliation, OwnedAgentRuntime, OwnerDispatchFence, PreparationHook, ReaderAdapter,
    ReaderCapabilities, ReaderHistory, ReaderOutcome, ReaderReply, RollingPolicy, RuntimeSettings,
    StartRun,
};
use contextdb_capture::CaptureHost;
use contextdb_continuity::{
    CapturedMessage, InteractionGroup, OwnedRunCheckpoint, OwnedRunIdentity, OwnedRunStatus,
    PendingModelCall,
};
use contextdb_core::{
    AgentRunId, ContentDigest, EventKind, EventPayload, EventProvenance, EventRole, ModelCallId,
    ModelOutputFormat, ModelRequestManifest, ObservationId, OriginalSourceSpan, SessionId,
    StreamId,
};
use contextdb_service::{
    AuthenticatedRequestContext, CaptureAcceptance, ContextLeasePort, OwnedRunPort,
    ReadOriginalRequest, SaveRunCheckpointRequest, SavedRunCheckpoint, ServiceResult,
};

use super::*;

mod policy;
mod replay;

pub(in crate::router_trace) struct TraceCaptureFixture {
    pub context: AuthenticatedRequestContext,
    pub checkpoint: SavedRunCheckpoint,
    pub prepared: PreparedContext,
    pub request: CaptureRequest,
    pub acceptance: CaptureAcceptance,
}

struct PlannedFixture {
    source: CaptureRequest,
    checkpoint: SavedRunCheckpoint,
    prepared: PreparedContext,
    request: CaptureRequest,
}

fn capture_request(
    source: &CaptureRequest,
    checkpoint: &SavedRunCheckpoint,
    prepared: &PreparedContext,
) -> CaptureRequest {
    let pending = checkpoint
        .checkpoint
        .pending_model
        .as_ref()
        .expect("owned intent");
    let mut manifest = ReferenceOutgoingEncoder(&ReferenceTokenizer)
        .capture_manifest(
            pending.call_id,
            &prepared.messages,
            &prepared.outgoing,
            &mut budget(),
        )
        .expect("exact reader manifest");
    manifest.router_trace = Some(Box::new(
        prepared
            .router_trace
            .as_ref()
            .expect("Required trace")
            .attach(pending.call_id, &mut budget())
            .expect("bound attachment"),
    ));
    let mut capture = source.clone();
    capture.idempotency_key = "protected-owned-request".into();
    capture.event.event_id = pending.request_event;
    capture.event.producer_id = checkpoint.checkpoint.producer_id;
    capture.event.producer_sequence = checkpoint.checkpoint.next_sequence;
    capture.event.kind = EventKind::ModelRequested;
    capture.event.role = EventRole::Host;
    capture.event.provenance = Some(EventProvenance::ModelRequest {
        model_call_id: pending.call_id,
    });
    capture.event.payload = EventPayload::Assembly { manifest };
    capture
}

fn planned_fixture(service: &NativeService) -> PlannedFixture {
    planned_fixture_with_raw(service, false)
}

fn planned_fixture_with_raw(service: &NativeService, raw: bool) -> PlannedFixture {
    planned_fixture_with_setup(service, raw, None)
}

pub(in crate::router_trace) type FixtureSetup =
    fn(&NativeService, &CaptureRequest, &mut PrepareContextRequest);

fn planned_fixture_with_setup(
    service: &NativeService,
    raw: bool,
    setup: Option<FixtureSetup>,
) -> PlannedFixture {
    planned_fixture_with_ports(
        service,
        raw,
        setup,
        "Current original remains a source, never a synthetic summary.",
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
    )
}

fn planned_fixture_with_ports(
    service: &NativeService,
    raw: bool,
    setup: Option<FixtureSetup>,
    source_text: &str,
    encoder: &dyn OutgoingEncoder,
) -> PlannedFixture {
    let session = SessionId::new();
    let run = AgentRunId::new();
    let mut original = source(1, source_text);
    original.context = request(&original).context;
    original.context.session_id = Some(session.to_string());
    original.event.session_id = Some(session);
    original.event.run_id = Some(run);
    if source_text.len() > crate::CAPTURE_MAX_INLINE_BYTES {
        let payload = contextdb_service::PayloadPort::stage_payload(
            service,
            contextdb_service::StagePayloadRequest {
                context: original.context.clone(),
                idempotency_key: "protected-fixture-staged-source".into(),
                block_id: contextdb_core::ContentBlockId::new(),
                bytes: source_text.as_bytes().to_vec(),
            },
        )
        .expect("actual staged source fixture");
        original.event.payload = EventPayload::Staged {
            reference: payload.reference,
            media_type: "text/plain; charset=utf-8".into(),
        };
    }
    service
        .append_event(original.clone())
        .expect("original capture");
    let mut plan = request(&original);
    if raw {
        let mut ids = BTreeSet::new();
        for (sequence, text) in [
            (2, "Independent optional original: amber."),
            (3, "Independent optional original: cobalt."),
        ] {
            let mut item = source(sequence, text);
            item.context = original.context.clone();
            ids.insert(item.event.event_id);
            service
                .append_event(item)
                .expect("optional original capture");
        }
        plan.memory_budget.max_blocks = 3;
        plan.raw_queries.push(IndexedQuery {
            filter: RawFilter {
                event_ids: ids,
                ..Default::default()
            },
            text: None,
            neighbor_of: None,
            selection: IndexedSelection::TopK { limit: 2 },
        });
    }
    if let Some(setup) = setup {
        setup(service, &original, &mut plan);
    }
    prepare_catalog(service, &original, raw);
    let source_span = OriginalSourceSpan {
        event_id: original.event.event_id,
        payload_digest: original.event.payload.digest().expect("original digest"),
        start: 0,
        end: source_text.len() as u64,
        span_digest: original.event.payload.digest().expect("span digest"),
    };
    let checkpoint = service
        .save_run_checkpoint(
            SaveRunCheckpointRequest {
                context: original.context.clone(),
                idempotency_key: "protected-owned-checkpoint".into(),
                event_id: ObservationId::new(),
                expected_revision: 0,
                checkpoint: OwnedRunCheckpoint {
                    version: 1,
                    identity: OwnedRunIdentity {
                        workspace_id: original.event.workspace_id,
                        session_id: session,
                        run_id: run,
                        actor_id: original.context.actor_id.clone(),
                        agent_id: original.context.agent_id.clone(),
                        subject_id: original.context.request.subject_id.clone(),
                        scopes: original.event.scope_ids.clone(),
                    },
                    revision: 1,
                    producer_id: StreamId::from_uuid(run.as_uuid()).expect("run producer"),
                    next_sequence: 2,
                    recorded_at: original.event.recorded_at,
                    model_profile: plan.model_profile.clone(),
                    groups: vec![InteractionGroup {
                        sequence: 1,
                        complete: false,
                        messages: vec![CapturedMessage {
                            id: BlockId::new("current-original").expect("message identity"),
                            source: source_span,
                            role: OutgoingRole::User,
                            tool_calls: Vec::new(),
                            tool_result: None,
                        }],
                    }],
                    obligations: Vec::new(),
                    pending_model: Some(PendingModelCall {
                        call_id: ModelCallId::new(),
                        request_event: ObservationId::new(),
                        wire_digest: None,
                        interrupted_output: None,
                    }),
                    pending_tool: None,
                    last_model_output: None,
                    status: OwnedRunStatus::Active,
                },
            },
            &mut budget(),
        )
        .expect("actual owned checkpoint");
    let prepared = service
        .prepare_context(plan, &ReferenceTokenizer, encoder, &mut budget())
        .expect("actual fixture preparation with its trusted encoder");
    let request = capture_request(&original, &checkpoint, &prepared);
    PlannedFixture {
        source: original,
        checkpoint,
        prepared,
        request,
    }
}

fn publish(service: &Arc<NativeService>, fixture: &PlannedFixture) -> CaptureAcceptance {
    let EventPayload::Assembly { manifest } = &fixture.request.event.payload else {
        panic!("protected request manifest");
    };
    CaptureHost::new(Arc::clone(service))
        .capture_prepared_model_request(
            fixture.request.clone(),
            manifest.clone(),
            &fixture.prepared,
            Some(&fixture.checkpoint.receipt),
            &mut budget(),
        )
        .expect("actual protected owner capture")
}

pub(in crate::router_trace) fn accepted_fixture(
    service: &Arc<NativeService>,
) -> TraceCaptureFixture {
    let fixture = planned_fixture(service);
    accepted_from_planned(service, fixture)
}

pub(in crate::router_trace) fn accepted_fixture_with_setup(
    service: &Arc<NativeService>,
    setup: FixtureSetup,
) -> TraceCaptureFixture {
    accepted_from_planned(
        service,
        planned_fixture_with_setup(service, false, Some(setup)),
    )
}

pub(in crate::router_trace) fn accepted_fixture_with_ports(
    service: &Arc<NativeService>,
    source_text: &str,
    setup: FixtureSetup,
    encoder: &dyn OutgoingEncoder,
) -> TraceCaptureFixture {
    accepted_from_planned(
        service,
        planned_fixture_with_ports(service, false, Some(setup), source_text, encoder),
    )
}

pub(in crate::router_trace) fn accepted_fixture_with_manifest(
    service: &Arc<NativeService>,
    source_text: &str,
    setup: FixtureSetup,
    encoder: &dyn OutgoingEncoder,
    manifest_setup: fn(&NativeService, &mut CaptureRequest),
) -> TraceCaptureFixture {
    let mut fixture = planned_fixture_with_ports(service, false, Some(setup), source_text, encoder);
    manifest_setup(service, &mut fixture.request);
    accepted_from_planned(service, fixture)
}

pub(in crate::router_trace) fn accepted_unselected_fixture(
    service: &Arc<NativeService>,
) -> (TraceCaptureFixture, ObservationId) {
    let fixture = planned_fixture_with_raw(service, true);
    accepted_unselected_from_planned(service, fixture)
}

pub(in crate::router_trace) fn replay_profile(
    _: &NativeService,
    _: &CaptureRequest,
    plan: &mut PrepareContextRequest,
) {
    plan.router_trace_profile = RouterTraceProfile::RequiredReplayV2;
}

pub(in crate::router_trace) fn accepted_unselected_replay_fixture(
    service: &Arc<NativeService>,
) -> (TraceCaptureFixture, ObservationId) {
    let fixture = planned_fixture_with_setup(service, true, Some(replay_profile));
    accepted_unselected_from_planned(service, fixture)
}

fn accepted_unselected_from_planned(
    service: &Arc<NativeService>,
    fixture: PlannedFixture,
) -> (TraceCaptureFixture, ObservationId) {
    let retained = envelope(&fixture.prepared);
    let discarded = retained
        .request
        .units
        .iter()
        .find(|unit| {
            unit.kind == PackBlockKind::RawObservation
                && !retained.plan.selected_ids.contains(&unit.id)
        })
        .expect("one actual discarded raw candidate");
    let original = *retained.unit_origins[&discarded.id]
        .controls
        .originals
        .first()
        .expect("discarded original");
    (accepted_from_planned(service, fixture), original)
}

fn accepted_from_planned(
    service: &Arc<NativeService>,
    fixture: PlannedFixture,
) -> TraceCaptureFixture {
    let acceptance = publish(service, &fixture);
    TraceCaptureFixture {
        context: fixture.source.context,
        checkpoint: fixture.checkpoint,
        prepared: fixture.prepared,
        request: fixture.request,
        acceptance,
    }
}

fn runtime_settings(source: &CaptureRequest) -> RuntimeSettings {
    let plan = request(source);
    RuntimeSettings {
        control: Vec::new(),
        purpose: plan.purpose,
        memory_budget: plan.memory_budget,
        outgoing_budget: plan.outgoing_budget,
        rolling: RollingPolicy {
            high_tokens: 3200,
            low_tokens: 2100,
            keep_complete_groups: 1,
            chunk_groups: 2,
            max_prepare_attempts: 3,
        },
        cache_residency: None,
        automatic_recall_filter: RawFilter::default(),
        router_trace_profile: RouterTraceProfile::Required,
    }
}

#[test]
fn protected_capture_rejects_wrong_owned_intent_and_rehashed_unsealed_material() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_keys_directory, keys) = crate::encryption::tests::authority("trace-owned-gates");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("trace-owned-gates");
    let service = Arc::new(
        NativeService::open_encrypted(directory.path(), "trace-owned-gates", [7; 32], ledger, keys)
            .expect("encrypted native owner"),
    );
    let fixture = planned_fixture(&service);
    let mut wrong_call = fixture.request.clone();
    let EventPayload::Assembly { manifest } = &mut wrong_call.event.payload else {
        panic!("manifest");
    };
    let other_call = ModelCallId::new();
    manifest.model_call_id = other_call;
    manifest.router_trace = Some(Box::new(
        fixture
            .prepared
            .router_trace
            .as_ref()
            .expect("trace")
            .attach(other_call, &mut budget())
            .expect("locally consistent wrong call"),
    ));
    wrong_call.event.provenance = Some(EventProvenance::ModelRequest {
        model_call_id: other_call,
    });
    assert_eq!(
        service
            .capture_prepared_model_request(
                wrong_call,
                &fixture.prepared,
                Some(&fixture.checkpoint.receipt),
                &mut budget(),
            )
            .expect_err("wrong pending call cannot publish")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut wrong_producer = fixture.request.clone();
    wrong_producer.event.producer_id = StreamId::new();
    assert_eq!(
        service
            .capture_prepared_model_request(
                wrong_producer,
                &fixture.prepared,
                Some(&fixture.checkpoint.receipt),
                &mut budget(),
            )
            .expect_err("request cannot escape the owned producer sequence")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut wrong_profile_plan = request(&fixture.source);
    wrong_profile_plan.model_profile.id = "another-valid-reader-profile".into();
    let wrong_profile = prepare(&service, wrong_profile_plan);
    let wrong_profile_request =
        capture_request(&fixture.source, &fixture.checkpoint, &wrong_profile);
    assert_eq!(
        service
            .capture_prepared_model_request(
                wrong_profile_request,
                &wrong_profile,
                Some(&fixture.checkpoint.receipt),
                &mut budget(),
            )
            .expect_err("owner seal does not override the checkpoint reader contract")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut forged = fixture.prepared.clone();
    let mut forged_envelope = envelope(&forged);
    forged_envelope.materials.candidates[0].representations[0]
        .fields
        .insert("unsealed_material".into(), "tampered retained text".into());
    let text = canonical_bytes(&forged_envelope, &mut budget()).expect("bounded canonical forgery");
    let trace = forged.router_trace.as_mut().expect("trace");
    trace.trace_digest = ContentDigest::from_bytes(*blake3::hash(&text).as_bytes());
    trace.canonical_json = String::from_utf8(text).expect("UTF-8");
    trace
        .validate()
        .expect("public hashes and bounds are internally consistent");
    let forged_request = capture_request(&fixture.source, &fixture.checkpoint, &forged);
    assert_eq!(
        service
            .capture_prepared_model_request(
                forged_request,
                &forged,
                Some(&fixture.checkpoint.receipt),
                &mut budget(),
            )
            .expect_err("a rehashed body still requires its native seal")
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(
        service
            .read_original(ReadOriginalRequest {
                context: fixture.source.context.clone(),
                event_id: fixture.request.event.event_id,
                after_receipt: None,
            })
            .is_err(),
        "rejected attempts publish no request occurrence"
    );
    assert!(
        service.append_event(fixture.request.clone()).is_err(),
        "ordinary capture cannot mint trace custody"
    );
    let accepted = publish(&service, &fixture);
    assert!(accepted.newly_accepted);
    let original = service
        .read_original(ReadOriginalRequest {
            context: fixture.source.context,
            event_id: fixture.request.event.event_id,
            after_receipt: Some(accepted.receipt.clone()),
        })
        .expect("actual captured occurrence");
    assert_eq!(original.event, fixture.request.event);
    assert_eq!(
        original.receipt.payload_digest,
        Some(fixture.prepared.assembly.wire_digest)
    );
    service
        .verify_native(true)
        .expect("encrypted capture and trace closure");
}

#[test]
fn accepted_protected_request_replays_after_issuer_expiry_and_cold_resume_stays_unknown() {
    for trace_profile in [
        RouterTraceProfile::Required,
        RouterTraceProfile::RequiredReplayV2,
    ] {
        cold_retry_for_profile(trace_profile);
    }
}

fn cold_retry_for_profile(trace_profile: RouterTraceProfile) {
    let directory = tempfile::tempdir().expect("native directory");
    let (_keys_directory, keys) = crate::encryption::tests::authority("trace-owned-recovery");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("trace-owned-recovery");
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "trace-owned-recovery",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("encrypted native owner"),
    );
    let fixture = match trace_profile {
        RouterTraceProfile::Required => accepted_fixture(&service),
        RouterTraceProfile::RequiredReplayV2 => {
            accepted_fixture_with_setup(&service, replay_profile)
        }
        RouterTraceProfile::Off => unreachable!("protected fixture"),
    };
    assert!(fixture.acceptance.newly_accepted);
    let replay = service
        .capture_prepared_model_request(
            fixture.request.clone(),
            &fixture.prepared,
            Some(&fixture.checkpoint.receipt),
            &mut budget(),
        )
        .expect("exact same-process replay");
    assert!(!replay.newly_accepted);
    assert_eq!(replay.receipt, fixture.acceptance.receipt);
    service
        .verify_native(true)
        .expect("accepted protected history");
    drop(service);
    let reopened = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "trace-owned-recovery",
            [7; 32],
            ledger,
            keys,
        )
        .expect("reopened encrypted owner"),
    );
    assert_eq!(
        reopened
            .register_context_lease(&fixture.context, &fixture.prepared, &mut budget(),)
            .expect_err("old process preparation has expired")
            .code,
        ErrorCode::ContinuationExpired
    );
    let replay = reopened
        .capture_prepared_model_request(
            fixture.request.clone(),
            &fixture.prepared,
            Some(&fixture.checkpoint.receipt),
            &mut budget(),
        )
        .expect("accepted replay resolves before issuer freshness");
    assert!(!replay.newly_accepted);
    assert_eq!(replay.receipt, fixture.acceptance.receipt);
    let resumed = OwnedAgentRuntime::resume(
        Arc::clone(&reopened),
        fixture.context,
        fixture.checkpoint.checkpoint.identity.run_id,
        {
            let mut settings = runtime_settings(&fixture.request);
            settings.router_trace_profile = trace_profile;
            settings
        },
        TimestampMicros(2_000_000),
        &mut budget(),
    )
    .expect("native captured tail resumes");
    assert!(
        resumed.model_outcome_unknown(),
        "accepted request cannot be automatically resent"
    );
    assert_eq!(
        resumed
            .checkpoint()
            .pending_model
            .as_ref()
            .expect("uncertain call")
            .wire_digest,
        Some(fixture.prepared.assembly.wire_digest)
    );
    reopened
        .verify_native(true)
        .expect("reopened protected history and recovery checkpoint");
}

#[test]
fn revoking_unselected_trace_origin_restricts_request_output_and_owned_checkpoint() {
    for trace_profile in [
        RouterTraceProfile::Required,
        RouterTraceProfile::RequiredReplayV2,
    ] {
        revocation_for_profile(trace_profile);
    }
}

fn revocation_for_profile(trace_profile: RouterTraceProfile) {
    let directory = tempfile::tempdir().expect("native directory");
    let (_keys_directory, keys) = crate::encryption::tests::authority("trace-unselected-custody");
    let (_ledger_directory, ledger) =
        crate::suppression::tests::authority("trace-unselected-custody");
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "trace-unselected-custody",
            [7; 32],
            ledger,
            keys,
        )
        .expect("encrypted native owner"),
    );
    let fixture = match trace_profile {
        RouterTraceProfile::Required => planned_fixture_with_raw(&service, true),
        RouterTraceProfile::RequiredReplayV2 => {
            planned_fixture_with_setup(&service, true, Some(replay_profile))
        }
        RouterTraceProfile::Off => unreachable!("protected fixture"),
    };
    let retained = envelope(&fixture.prepared);
    let discarded = retained
        .request
        .units
        .iter()
        .find(|unit| {
            unit.kind == PackBlockKind::RawObservation
                && !retained.plan.selected_ids.contains(&unit.id)
        })
        .expect("one actual raw candidate is discarded");
    let discarded_origin = *retained.unit_origins[&discarded.id]
        .controls
        .originals
        .first()
        .expect("discarded actual captured origin");
    assert!(
        !fixture
            .prepared
            .assembly
            .read_set
            .originals
            .iter()
            .any(|span| span.event_id == discarded_origin),
        "ordinary selected-wire custody does not include it"
    );
    assert!(retained.origins.originals.contains(&discarded_origin));
    let accepted = publish(&service, &fixture);
    let pending = fixture
        .checkpoint
        .checkpoint
        .pending_model
        .as_ref()
        .expect("owned call");
    let mut output = source(
        4,
        "Captured model output depends on the complete protected invocation.",
    );
    output.context = fixture.source.context.clone();
    output.event.producer_id = fixture.checkpoint.checkpoint.producer_id;
    output.event.producer_sequence = fixture.checkpoint.checkpoint.next_sequence + 1;
    output.event.kind = EventKind::ModelResponseCompleted;
    output.event.role = EventRole::Assistant;
    output.event.run_id = fixture.request.event.run_id;
    output.event.session_id = fixture.request.event.session_id;
    output
        .event
        .parent_event_ids
        .insert(fixture.request.event.event_id);
    output.event.provenance = Some(EventProvenance::ModelOutput {
        model_call_id: pending.call_id,
        request_event_id: fixture.request.event.event_id,
        format: ModelOutputFormat::PlainText,
        tool_calls: Vec::new(),
    });
    let output_receipt = service
        .append_event(output.clone())
        .expect("actual derived output capture");
    let mut checkpoint = fixture.checkpoint.checkpoint.clone();
    checkpoint.revision += 1;
    checkpoint.next_sequence += 3;
    checkpoint.pending_model = None;
    checkpoint.last_model_output = Some(output.event.event_id);
    checkpoint.groups[0].complete = true;
    checkpoint.groups[0].messages.push(CapturedMessage {
        id: BlockId::new("captured-derived-output").expect("message identity"),
        source: OriginalSourceSpan {
            event_id: output.event.event_id,
            payload_digest: output_receipt.payload_digest.expect("output digest"),
            start: 0,
            end: output
                .event
                .payload
                .original_bytes()
                .expect("output bytes")
                .len() as u64,
            span_digest: output_receipt.payload_digest.expect("output span digest"),
        },
        role: OutgoingRole::Assistant,
        tool_calls: Vec::new(),
        tool_result: None,
    });
    let saved = service
        .save_run_checkpoint(
            SaveRunCheckpointRequest {
                context: fixture.source.context.clone(),
                idempotency_key: "protected-derived-checkpoint".into(),
                event_id: ObservationId::new(),
                expected_revision: fixture.checkpoint.checkpoint.revision,
                checkpoint,
            },
            &mut budget(),
        )
        .expect("actual checkpoint inherits protected output");
    for event_id in [
        accepted.receipt.event_id,
        output_receipt.event_id,
        saved.receipt.event_id,
    ] {
        service
            .read_original(ReadOriginalRequest {
                context: fixture.source.context.clone(),
                event_id,
                after_receipt: None,
            })
            .expect("authorized derived body before revocation");
    }
    service
        .revoke_original(
            &fixture.source.context,
            discarded_origin,
            "revoke-unselected-protected-origin",
            &mut budget(),
        )
        .expect("revoke inspected origin");
    let mut caught_up = false;
    for _ in 0..16 {
        if service
            .maintain_custody(&fixture.source.context, 64, &mut budget())
            .expect("bounded custody propagation")
            .caught_up
        {
            caught_up = true;
            break;
        }
    }
    assert!(
        caught_up,
        "small fixture custody converges within its explicit bound"
    );
    for event_id in [
        accepted.receipt.event_id,
        output_receipt.event_id,
        saved.receipt.event_id,
    ] {
        assert_eq!(
            service
                .read_original(ReadOriginalRequest {
                    context: fixture.source.context.clone(),
                    event_id,
                    after_receipt: None,
                })
                .expect_err("discarded origin still restricts every derived body")
                .code,
            ErrorCode::PermissionDenied
        );
    }
    service
        .verify_native(true)
        .expect("retained encrypted provenance after revocation");
}

#[derive(Debug)]
struct ReferenceReader {
    profile: ModelProfile,
    calls: AtomicUsize,
    received: Mutex<Vec<u8>>,
}

impl OutgoingEncoder for ReferenceReader {
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

impl ReaderAdapter for ReferenceReader {
    fn profile(&self) -> ModelProfile {
        self.profile.clone()
    }
    fn capabilities(&self) -> ReaderCapabilities {
        ReaderCapabilities {
            history: ReaderHistory::Stateless,
            history_contract: "Synthetic reader consumes only the complete passed JSON wire."
                .into(),
            can_reconcile: false,
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
            .map_err(|_| invalid("fixture reader manifest is invalid"))
    }
    fn complete(&self, _: ModelCallId, request: &EncodedOutgoing) -> ServiceResult<ReaderOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.received.lock().expect("observed wire") = request.wire.clone();
        Ok(ReaderOutcome::Completed(ReaderReply::text(
            "Exact synthetic reader output.",
        )))
    }
    fn reconcile(&self, _: ModelCallId, _: ContentDigest) -> ServiceResult<ModelReconciliation> {
        Ok(ModelReconciliation::Unknown)
    }
}

#[derive(Debug)]
struct ProjectOriginals(Arc<NativeService>);
impl PreparationHook for ProjectOriginals {
    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let progress = self.0.project_originals(context, false, 256, budget)?;
        assert!(
            progress.caught_up,
            "small fixture indexes its actual originals"
        );
        Ok(())
    }
}

#[test]
fn required_owned_runtime_captures_fences_exact_wire_and_inherits_trace_into_output_checkpoint() {
    for trace_profile in [
        RouterTraceProfile::Required,
        RouterTraceProfile::RequiredReplayV2,
    ] {
        owned_runtime_for_profile(trace_profile);
    }
}

fn owned_runtime_for_profile(trace_profile: RouterTraceProfile) {
    let directory = tempfile::tempdir().expect("native directory");
    let (_keys_directory, keys) = crate::encryption::tests::authority("trace-live-runtime");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("trace-live-runtime");
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "trace-live-runtime",
            [7; 32],
            ledger,
            keys,
        )
        .expect("encrypted native owner"),
    );
    let mut input = source(1, "fixture authority");
    let session = SessionId::new();
    input.context = request(&input).context;
    input.context.session_id = Some(session.to_string());
    let identity = OwnedRunIdentity {
        workspace_id: input.event.workspace_id,
        session_id: session,
        run_id: AgentRunId::new(),
        actor_id: input.context.actor_id.clone(),
        agent_id: input.context.agent_id.clone(),
        subject_id: input.context.request.subject_id.clone(),
        scopes: input.event.scope_ids.clone(),
    };
    let profile = request(&input).model_profile;
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&service),
        input.context.clone(),
        StartRun {
            identity: identity.clone(),
            model_profile: profile.clone(),
            recorded_at: TimestampMicros(1_000_000),
        },
        {
            let mut settings = runtime_settings(&input);
            settings.router_trace_profile = trace_profile;
            settings
        },
        &mut budget(),
    )
    .expect("actual runtime starts durably");
    service
        .initialize_state_catalog(&input.context, &mut budget())
        .expect("native state catalog");
    let original = runtime
        .accept_user(
            "Private current input sentinel: avocado 7391.".into(),
            TimestampMicros(2_000_000),
            &mut budget(),
        )
        .expect("actual owned original");
    let reader = ReferenceReader {
        profile,
        calls: AtomicUsize::new(0),
        received: Mutex::new(Vec::new()),
    };
    let completed = runtime
        .step(
            &reader,
            &OwnerDispatchFence::new(Arc::clone(&service)),
            &ProjectOriginals(Arc::clone(&service)),
            &[],
            TimestampMicros(3_000_000),
            &mut budget(),
        )
        .expect("actual Required preparation, capture, native dispatch and output checkpoint");
    assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *reader.received.lock().expect("actual sent wire"),
        completed.prepared.outgoing.wire
    );
    let wire = String::from_utf8(completed.prepared.outgoing.wire.clone()).expect("reference wire");
    assert!(wire.contains("avocado 7391"));
    assert!(
        !wire.contains(FORMAT),
        "protected envelope stays outside reader wire"
    );
    assert!(!wire.contains(REPLAY_FORMAT));
    let retained = envelope(&completed.prepared);
    assert!(retained.origins.originals.contains(&original.event_id));
    assert!(retained.base_origins.originals.contains(&original.event_id));
    let output = service
        .read_original(ReadOriginalRequest {
            context: input.context.clone(),
            event_id: completed.output_receipt.event_id,
            after_receipt: None,
        })
        .expect("actual completed model occurrence");
    let Some(EventProvenance::ModelOutput {
        request_event_id, ..
    }) = output.event.provenance
    else {
        panic!("actual model lineage");
    };
    let captured = service
        .read_original(ReadOriginalRequest {
            context: input.context.clone(),
            event_id: request_event_id,
            after_receipt: None,
        })
        .expect("durable prepared model request");
    let EventPayload::Assembly { manifest } = captured.event.payload else {
        panic!("model manifest");
    };
    assert_eq!(
        manifest.wire_digest,
        completed.prepared.assembly.wire_digest
    );
    assert_eq!(
        manifest
            .router_trace
            .as_ref()
            .expect("actual trace")
            .header
            .trace_digest,
        completed
            .prepared
            .router_trace
            .as_ref()
            .expect("prepared trace")
            .trace_digest
    );
    assert_eq!(
        manifest
            .router_trace
            .as_ref()
            .expect("profile trace")
            .header
            .version,
        trace_profile.version().expect("explicit protected profile"),
    );
    let saved = service
        .load_run_checkpoint(&input.context, identity.run_id, &mut budget())
        .expect("actual owned head")
        .expect("completed checkpoint");
    assert_eq!(
        saved.checkpoint.last_model_output,
        Some(completed.output_receipt.event_id)
    );
    assert!(saved.checkpoint.pending_model.is_none());
    service
        .verify_native(true)
        .expect("actual encrypted runtime and provenance closure");
    service
        .revoke_original(
            &input.context,
            original.event_id,
            "revoke-live-runtime-input",
            &mut budget(),
        )
        .expect("source revocation");
    let mut caught_up = false;
    for _ in 0..16 {
        if service
            .maintain_custody(&input.context, 64, &mut budget())
            .expect("custody propagation")
            .caught_up
        {
            caught_up = true;
            break;
        }
    }
    assert!(caught_up);
    for event_id in [
        request_event_id,
        completed.output_receipt.event_id,
        saved.receipt.event_id,
    ] {
        assert_eq!(
            service
                .read_original(ReadOriginalRequest {
                    context: input.context.clone(),
                    event_id,
                    after_receipt: None,
                })
                .expect_err("actual protected runtime lineage retains current source authority")
                .code,
            ErrorCode::PermissionDenied
        );
    }
}
