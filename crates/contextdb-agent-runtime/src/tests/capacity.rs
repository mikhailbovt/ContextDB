use contextdb_capture::{
    ExternalTool, ToolAction, ToolObservation, ToolOutcome, ToolReconciliation, ToolReplaySafety,
};
use contextdb_native_service::{CustodyMasterKey, NativeCustodyKeys, NativeSuppressionLedger};
use contextdb_recall::QueryCancellation;

use super::*;

#[derive(Clone, Copy, Debug)]
struct Allowance {
    address: usize,
    work: u64,
    bytes: u64,
    timeout: u64,
}

#[derive(Debug)]
struct ObservedPreparation {
    native: Arc<NativeService>,
    entries: Mutex<Vec<Allowance>>,
}
impl PreparationHook for ObservedPreparation {
    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.entries.lock().expect("entries").push(Allowance {
            address: std::ptr::from_ref(allowance) as usize,
            work: allowance.remaining_work(),
            bytes: allowance.remaining_bytes(),
            timeout: allowance.remaining_timeout_micros().expect("live parent"),
        });
        FixturePreparation(Arc::clone(&self.native)).before_prepare(context, allowance)
    }
}

struct RecordedTool;
impl ExternalTool for RecordedTool {
    fn replay_safety(&self) -> ToolReplaySafety {
        ToolReplaySafety::NoAutomaticReplay
    }
    fn execute(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        _: &ToolAction,
    ) -> ServiceResult<ToolObservation> {
        Ok(ToolObservation {
            outcome: ToolOutcome::Completed,
            bytes: Some(b"capacity-tool-original-7391".to_vec()),
            media_type: "text/plain".into(),
            upstream_truncated: false,
        })
    }
    fn reconcile(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        _: ContentDigest,
    ) -> ServiceResult<ToolReconciliation> {
        Ok(ToolReconciliation::Unknown)
    }
}

struct Fixture {
    native: Arc<NativeService>,
    context: AuthenticatedRequestContext,
    runtime: OwnedAgentRuntime<NativeService>,
    reader: ScriptedReader,
    settings: RuntimeSettings,
    // Windows must close the owned native/key/ledger handles before removal.
    _directory: tempfile::TempDir,
}

fn fixture(trace_profile: RouterTraceProfile) -> Fixture {
    let directory = tempfile::tempdir().expect("encrypted fixture");
    let keys = NativeCustodyKeys::create(
        directory.path().join("keys"),
        "capacity-runtime",
        CustodyMasterKey::from_zeroizing([79u8; 32].into()).expect("fixture master"),
    )
    .expect("independent keys");
    let ledger =
        NativeSuppressionLedger::create(directory.path().join("ledger"), "capacity-runtime")
            .expect("independent suppression authority");
    let native = Arc::new(
        NativeService::open_encrypted(
            directory.path().join("native"),
            "capacity-runtime",
            [7; 32],
            ledger,
            keys,
        )
        .expect("encrypted owner"),
    );
    let (context, identity) = identity();
    native
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let reader = ScriptedReader {
        tool_proposal: Some(RequestedTool {
            call_id: ToolCallId::new(),
            action: ToolAction {
                operation: "fixture.capacity".into(),
                input: vec![],
                expected_target_version: None,
            },
        }),
        ..Default::default()
    };
    let mut settings = settings();
    settings.router_trace_profile = trace_profile;
    settings.rolling.high_tokens = 24_000;
    settings.rolling.low_tokens = 23_000;
    // This synthetic fixture isolates mandatory preparation capacity from
    // optional raw discovery; it does not claim semantic recall completeness.
    settings.automatic_recall_filter.event_ids = BTreeSet::from([ObservationId::new()]);
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&native),
        context.clone(),
        StartRun {
            identity,
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        settings.clone(),
        &mut budget(),
    )
    .expect("start");
    let hook = FixturePreparation(Arc::clone(&native));
    let fence = OwnerDispatchFence::new(Arc::clone(&native));
    for index in 0..3 {
        runtime
            .accept_user(
                format!(
                    "Captured exchange {index}. {}",
                    "Exact historical alpha beta gamma delta epsilon. ".repeat(80)
                ),
                now(),
                &mut budget(),
            )
            .expect("automatic user capture");
        runtime
            .step(&reader, &fence, &hook, &[], now(), &mut budget())
            .expect("captured history");
        if index == 0 {
            runtime
                .execute_next_tool(
                    "fixture.capacity",
                    &RecordedTool,
                    &fence,
                    now(),
                    &mut budget(),
                )
                .expect("actual captured tool result");
            runtime
                .step(&reader, &fence, &hook, &[], now(), &mut budget())
                .expect("complete tool exchange");
        }
    }
    assert!(
        runtime
            .checkpoint()
            .groups
            .iter()
            .all(|group| group.complete)
    );
    let tool_source = runtime.checkpoint().groups[0]
        .messages
        .iter()
        .find(|message| message.role == OutgoingRole::Tool)
        .expect("tool original")
        .source
        .clone();
    runtime
        .add_obligation(
            ScopedObligation {
                id: "preserve-tool-observation".into(),
                scope: *runtime.checkpoint().identity.scopes.first().expect("scope"),
                source: tool_source,
                status: ObligationStatus::Open,
            },
            now(),
            &mut budget(),
        )
        .expect("source-backed working pin");
    runtime
        .accept_user(
            "Continue with the exact pending input.".into(),
            now(),
            &mut budget(),
        )
        .expect("durable current input");
    Fixture {
        _directory: directory,
        native,
        context,
        runtime,
        reader,
        settings,
    }
}

fn originals(fixture: &Fixture) -> Vec<(OriginalSourceSpan, Vec<u8>)> {
    fixture
        .runtime
        .checkpoint()
        .groups
        .iter()
        .flat_map(|group| &group.messages)
        .map(|message| {
            let bytes = fixture
                .native
                .read_original_span(&fixture.context, &message.source)
                .expect("actual durable original");
            (message.source.clone(), bytes)
        })
        .collect()
}

#[test]
fn protected_capacity_retries_below_rotation_high_with_same_parent_and_exact_trace() {
    for trace_profile in [
        RouterTraceProfile::Required,
        RouterTraceProfile::RequiredReplayV2,
    ] {
        let mut fixture = fixture(trace_profile);
        let retained = originals(&fixture);
        let before_groups = fixture.runtime.checkpoint().groups.clone();
        let hook = FixturePreparation(Arc::clone(&fixture.native));
        hook.before_prepare(&fixture.context, &mut budget())
            .expect("fixed synthetic coverage");
        let base = rehydrate(
            fixture.native.as_ref(),
            &fixture.context,
            fixture.runtime.checkpoint(),
            &[],
            &mut budget(),
        )
        .expect("actual resident base");
        let bare_tokens = count_base(&fixture.reader, &base, &mut budget()).expect("base count");
        let head = fixture
            .native
            .load_run_checkpoint(
                &fixture.context,
                fixture.runtime.checkpoint().identity.run_id,
                &mut budget(),
            )
            .expect("head")
            .expect("checkpoint");
        let priced = fixture
            .native
            .prepare_context(
                PrepareContextRequest {
                    context: fixture.context.clone(),
                    pack_id: ContextPackId::new(),
                    purpose: fixture.settings.purpose,
                    known_at: None,
                    valid_at: None,
                    after_receipt: Some(head.receipt),
                    raw_queries: vec![],
                    memory_query: None,
                    required_facets: vec![],
                    memory_budget: fixture.settings.memory_budget,
                    model_profile: fixture.reader.profile(),
                    base,
                    outgoing_budget: fixture.settings.outgoing_budget,
                    explicit_memory_request: false,
                    router_trace_profile: trace_profile,
                },
                fixture.reader.tokenizer(),
                &fixture.reader,
                &mut budget(),
            )
            .expect("actual mandatory price");
        let mandatory_extra = priced
            .outgoing
            .input_tokens
            .checked_sub(bare_tokens)
            .expect("added mandatory wire");
        assert!(
            mandatory_extra > 8,
            "complete compiler control and mandatory material have a real cost"
        );
        fixture.settings.outgoing_budget.max_input_tokens = bare_tokens + mandatory_extra / 2;
        fixture.settings.rolling.high_tokens =
            fixture.settings.outgoing_budget.max_input_tokens - 1;
        fixture.settings.rolling.low_tokens = fixture.settings.rolling.high_tokens - 1;
        assert!(bare_tokens < fixture.settings.rolling.high_tokens);
        assert!(priced.outgoing.input_tokens > fixture.settings.outgoing_budget.max_input_tokens);
        fixture
            .runtime
            .switch_reader(
                &fixture.reader,
                fixture.settings.clone(),
                now(),
                &mut budget(),
            )
            .expect("explicit capacity profile");
        fixture.runtime.drain_measurements();
        let hook = ObservedPreparation {
            native: Arc::clone(&fixture.native),
            entries: Mutex::new(vec![]),
        };
        let calls = fixture.reader.calls.load(Ordering::SeqCst);
        let mut parent = budget();
        let address = std::ptr::from_ref(&parent) as usize;
        let result = fixture
            .runtime
            .step(
                &fixture.reader,
                &OwnerDispatchFence::new(Arc::clone(&fixture.native)),
                &hook,
                &[],
                now(),
                &mut parent,
            )
            .expect("mandatory capacity permits only complete-group retry");
        assert_eq!(result.evicted_groups, 2);
        let entries = hook.entries.lock().expect("observed allowance");
        assert_eq!(
            entries.len(),
            2,
            "no rotation before the actual protected capacity refusal"
        );
        assert!(entries.iter().all(|entry| entry.address == address));
        assert!(entries[1].work < entries[0].work && entries[1].bytes < entries[0].bytes);
        assert!(entries[1].timeout <= entries[0].timeout);
        assert!(
            parent.remaining_work() < entries[1].work
                && parent.remaining_bytes() < entries[1].bytes
        );
        assert_eq!(fixture.reader.calls.load(Ordering::SeqCst), calls + 1);
        assert_eq!(fixture.runtime.checkpoint().groups[0], before_groups[2]);
        assert_eq!(
            fixture.runtime.checkpoint().groups[1].messages[0],
            before_groups[3].messages[0]
        );
        assert!(fixture.runtime.checkpoint().groups[1].complete);
        assert!(
            result
                .prepared
                .messages
                .iter()
                .any(|message| message.zone == OutgoingZone::WorkingState
                    && message.text == "capacity-tool-original-7391")
        );
        assert!(
            result.prepared.outgoing.input_tokens
                <= fixture.settings.outgoing_budget.max_input_tokens
        );
        assert_eq!(
            serde_json::to_vec(
                fixture
                    .reader
                    .requests
                    .lock()
                    .expect("wire")
                    .last()
                    .expect("one dispatch")
            )
            .expect("actual protocol bytes"),
            result.prepared.outgoing.wire
        );
        let output = fixture
            .native
            .read_original(ReadOriginalRequest {
                context: fixture.context.clone(),
                event_id: result.output_receipt.event_id,
                after_receipt: Some(result.output_receipt.clone()),
            })
            .expect("completed output");
        let Some(EventProvenance::ModelOutput {
            request_event_id, ..
        }) = output.event.provenance
        else {
            panic!("exact request lineage");
        };
        let captured = fixture
            .native
            .read_original(ReadOriginalRequest {
                context: fixture.context.clone(),
                event_id: request_event_id,
                after_receipt: None,
            })
            .expect("actual accepted request");
        let EventPayload::Assembly { manifest } = captured.event.payload else {
            panic!("actual assembly");
        };
        assert_eq!(manifest.wire_digest, result.prepared.assembly.wire_digest);
        let trace = manifest
            .router_trace
            .expect("required trace remains required");
        assert_eq!(
            trace.header.version,
            trace_profile.version().expect("protected version")
        );
        assert_eq!(
            trace.header.trace_digest,
            result
                .prepared
                .router_trace
                .as_ref()
                .expect("prepared trace")
                .trace_digest
        );
        for (span, bytes) in retained {
            assert_eq!(
                fixture
                    .native
                    .read_original_span(&fixture.context, &span)
                    .expect("eviction preserves archive"),
                bytes
            );
        }
        let measurements = fixture.runtime.drain_measurements();
        assert_eq!(measurements.steps.len(), 1);
        assert_eq!(measurements.steps[0].prepare_attempts, 2);
        assert_eq!(measurements.steps[0].evicted_groups, 2);
        assert!(measurements.steps[0].dispatched);
        fixture
            .native
            .verify(VerifyRequest {
                context: fixture.context.request,
                deep: true,
            })
            .expect("accepted protected lifecycle");
    }
}

#[test]
fn protected_memory_and_shared_budget_failures_do_not_evict_or_dispatch() {
    let mut fixture = fixture(RouterTraceProfile::RequiredReplayV2);
    let retained = originals(&fixture);
    let groups = fixture.runtime.checkpoint().groups.clone();
    let calls = fixture.reader.calls.load(Ordering::SeqCst);
    fixture.settings.memory_budget.hard_tokens = 1;
    fixture.settings.memory_budget.soft_tokens = 1;
    fixture
        .runtime
        .switch_reader(
            &fixture.reader,
            fixture.settings.clone(),
            now(),
            &mut budget(),
        )
        .expect("mandatory-memory failure profile");
    fixture.runtime.drain_measurements();
    let hook = FixturePreparation(Arc::clone(&fixture.native));
    let fence = OwnerDispatchFence::new(Arc::clone(&fixture.native));
    let error = fixture
        .runtime
        .step(&fixture.reader, &fence, &hook, &[], now(), &mut budget())
        .expect_err("mandatory memory is not outgoing-base capacity pressure");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(!error.retryable);
    assert_eq!(fixture.runtime.checkpoint().groups, groups);
    let measurement = fixture
        .runtime
        .drain_measurements()
        .steps
        .pop()
        .expect("failed preparation");
    assert_eq!(measurement.prepare_attempts, 1);
    assert_eq!(measurement.evicted_groups, 0);
    assert!(!measurement.dispatched);
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    for mut allowance in [
        QueryBudget::new(0, 0, Duration::from_secs(30), Default::default()),
        QueryBudget::new(
            2_000_000,
            512 * 1024 * 1024,
            Duration::from_secs(30),
            cancellation,
        ),
    ] {
        let error = fixture
            .runtime
            .step(&fixture.reader, &fence, &hook, &[], now(), &mut allowance)
            .expect_err("caller exhaustion and cancellation stop before dispatch");
        assert!(matches!(
            error.code,
            ErrorCode::BudgetExhausted | ErrorCode::ResourceExhausted
        ));
        assert!(!error.retryable);
        assert_eq!(fixture.runtime.checkpoint().groups, groups);
        assert!(!fixture.runtime.model_outcome_unknown());
    }
    assert_eq!(fixture.reader.calls.load(Ordering::SeqCst), calls);
    let pending = fixture
        .runtime
        .checkpoint()
        .pending_model
        .as_ref()
        .expect("resumable undispatched intent");
    assert!(pending.wire_digest.is_none());
    assert_eq!(
        fixture
            .native
            .read_original(ReadOriginalRequest {
                context: fixture.context.clone(),
                event_id: pending.request_event,
                after_receipt: None
            })
            .expect_err("no request captured before successful preparation")
            .code,
        ErrorCode::NotFound
    );
    for (span, bytes) in retained {
        assert_eq!(
            fixture
                .native
                .read_original_span(&fixture.context, &span)
                .expect("unchanged automatic capture"),
            bytes
        );
    }
}
