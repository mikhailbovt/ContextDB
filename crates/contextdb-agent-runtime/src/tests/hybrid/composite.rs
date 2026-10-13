//! Host wiring refusals only; native proof reuse has its own encrypted gates.
use super::*;

#[derive(Debug)]
struct Attempt {
    intent: OwnedHybridIntent,
    checkpoint: CaptureReceipt,
    parent: usize,
    work: u64,
    bytes: u64,
}

#[derive(Debug)]
struct ObservedComposite {
    owner: Arc<NativeService>,
    legacy_calls: AtomicUsize,
    attempts: Mutex<Vec<Attempt>>,
    retry_first: bool,
}
impl PreparationHook for ObservedComposite {
    fn owned_hybrid_preparer(&self) -> Option<&dyn OwnedHybridPreparer> {
        Some(self)
    }

    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        FixturePreparation(self.owner.clone()).before_prepare(context, parent)
    }
}
impl OwnedHybridPreparer for ObservedComposite {
    fn prepare_owned_hybrid(
        &self,
        request: PrepareContextRequest,
        intent: OwnedHybridIntent,
        _: &dyn TokenCounter,
        _: &dyn OutgoingEncoder,
        _: &dyn TextEmbeddingAdapter,
        parent: &mut QueryBudget,
        timings: &mut PreparationPhaseTimings,
    ) -> ServiceResult<PreparedContext> {
        timings.hook_micros = 11;
        timings.prepare_micros = 31;
        let mut attempts = self.attempts.lock().expect("attempts");
        attempts.push(Attempt {
            intent,
            checkpoint: request.after_receipt.expect("actual current checkpoint"),
            parent: std::ptr::from_ref(parent) as usize,
            work: parent.remaining_work(),
            bytes: parent.remaining_bytes(),
        });
        parent
            .charge(17, 23)
            .map_err(|_| exhausted("composite parent exhausted"))?;
        if self.retry_first && attempts.len() == 1 {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "fixture outgoing pressure requires a new owned attempt",
                true,
            ));
        }
        Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "fixture composite refuses before model dispatch",
            false,
        ))
    }
}

fn hybrid_settings(routed: bool) -> OwnedHybridSettings {
    let mut limits = OwnedHybridLimits::default();
    if routed {
        limits.routed = Some(OwnedRoutedLimits {
            max_fine_paths: 8,
            coarse_node_reads: 64,
            coarse_vector_reads: 64,
            coarse_discovered: 64,
            coarse_ef_search: 32,
        });
    }
    OwnedHybridSettings {
        query_encoder: Arc::new(UncalledQueryEncoder(
            TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(ContentDigest::from_bytes([3; 32])),
        )),
        limits,
    }
}

#[test]
fn composite_is_selected_only_for_routed_and_refusal_keeps_phase_timings() {
    for mode in [None, Some(false), Some(true)] {
        let directory = tempfile::tempdir().expect("owner directory");
        let native =
            Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("owner"));
        let owner = Arc::new(LostOutputAcknowledgement {
            owner: native.clone(),
            lose_once: AtomicBool::new(false),
            output_kind: EventKind::ModelResponseCompleted,
        });
        let (context, identity) = identity();
        native
            .initialize_state_catalog(&context, &mut budget())
            .expect("catalog");
        let mut config = settings();
        if let Some(routed) = mode {
            config.router_trace_profile = RouterTraceProfile::RequiredReplayV2;
            config.automatic_hybrid = Some(hybrid_settings(routed));
        }
        let mut runtime = OwnedAgentRuntime::start(
            owner,
            context,
            StartRun {
                identity,
                model_profile: profile(),
                recorded_at: now(),
            },
            config,
            &mut budget(),
        )
        .expect("owned start");
        runtime
            .accept_user(
                "Actual current source for adapter selection.".into(),
                now(),
                &mut budget(),
            )
            .expect("accepted current source");
        let hook = ObservedComposite {
            owner: native,
            legacy_calls: AtomicUsize::new(0),
            attempts: Mutex::new(vec![]),
            retry_first: false,
        };
        let reader = ScriptedReader::default();
        let outcome = runtime.step(&reader, &FixtureFence, &hook, &[], now(), &mut budget());
        match mode {
            None => {
                outcome.expect("legacy hook and ordinary prepare port retain their order");
                assert_eq!(hook.legacy_calls.load(Ordering::SeqCst), 1);
                assert!(hook.attempts.lock().expect("attempts").is_empty());
                assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
                assert!(
                    reader
                        .requests
                        .lock()
                        .expect("wire")
                        .iter()
                        .flatten()
                        .all(|message| !message
                            .text
                            .contains("Relevant original interpretation or capture is incomplete")),
                    "the real coverage hook must run before ordinary preparation"
                );
            }
            Some(false) => {
                assert_eq!(
                    outcome.expect_err("nonrouted uses the original port").code,
                    ErrorCode::Unsupported
                );
                assert_eq!(hook.legacy_calls.load(Ordering::SeqCst), 1);
                assert!(hook.attempts.lock().expect("attempts").is_empty());
                assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
            }
            Some(true) => {
                assert_eq!(
                    outcome.expect_err("composite refusal is final").code,
                    ErrorCode::PermissionDenied
                );
                assert_eq!(hook.legacy_calls.load(Ordering::SeqCst), 0);
                assert_eq!(hook.attempts.lock().expect("attempts").len(), 1);
                assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
                let measured = runtime
                    .drain_measurements()
                    .steps
                    .pop()
                    .expect("failed attempt");
                assert_eq!(measured.preparation_hook_micros, 11);
                assert_eq!(measured.prepare_micros, 31);
                assert_eq!(measured.prepare_attempts, 1);
                assert!(!measured.dispatched);
                assert!(
                    runtime
                        .checkpoint()
                        .pending_model
                        .as_ref()
                        .expect("pending call")
                        .wire_digest
                        .is_none()
                );
            }
        }
    }
}

#[test]
fn composite_eviction_retry_uses_new_checkpoint_same_call_and_remaining_parent() {
    let directory = tempfile::tempdir().expect("owner directory");
    let keys = contextdb_native_service::NativeCustodyKeys::create(
        directory.path().join("keys"),
        "runtime",
        contextdb_native_service::CustodyMasterKey::from_zeroizing([79u8; 32].into())
            .expect("fixture master"),
    )
    .expect("independent keys");
    let ledger = contextdb_native_service::NativeSuppressionLedger::create(
        directory.path().join("ledger"),
        "runtime",
    )
    .expect("independent suppression authority");
    let native = Arc::new(
        NativeService::open_encrypted(
            directory.path().join("native"),
            "runtime",
            [7; 32],
            ledger,
            keys,
        )
        .expect("encrypted owner for actual protected completed interactions"),
    );
    let (context, identity) = identity();
    native
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let reader = ScriptedReader::default();
    let mut config = settings();
    config.router_trace_profile = RouterTraceProfile::RequiredReplayV2;
    config.rolling.high_tokens = 24000;
    config.rolling.low_tokens = 23000;
    let mut runtime = OwnedAgentRuntime::start(
        native.clone(),
        context.clone(),
        StartRun {
            identity,
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        config.clone(),
        &mut budget(),
    )
    .expect("owned start");
    let hook = FixturePreparation(native.clone());
    for text in [
        "First actual completed interaction.",
        "Second actual completed interaction.",
    ] {
        runtime
            .accept_user(text.into(), now(), &mut budget())
            .expect("accepted source");
        runtime
            .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
            .expect("actual completed interaction");
    }
    config.automatic_hybrid = Some(hybrid_settings(true));
    runtime
        .switch_reader(&reader, config, now(), &mut budget())
        .expect("explicit owned settings checkpoint");
    runtime
        .accept_user(
            "Current interaction must survive retry eviction.".into(),
            now(),
            &mut budget(),
        )
        .expect("current source");
    runtime.drain_measurements();
    let hook = ObservedComposite {
        owner: native,
        legacy_calls: AtomicUsize::new(0),
        attempts: Mutex::new(vec![]),
        retry_first: true,
    };
    let mut parent = budget();
    let parent_address = std::ptr::from_ref(&parent) as usize;
    assert_eq!(
        runtime
            .step(&reader, &FixtureFence, &hook, &[], now(), &mut parent)
            .expect_err("second full composite deliberately refuses")
            .code,
        ErrorCode::PermissionDenied
    );
    let attempts = hook.attempts.lock().expect("attempts");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].intent.attempt, 0);
    assert_eq!(attempts[1].intent.attempt, 1);
    assert_eq!(attempts[0].intent.call_id, attempts[1].intent.call_id);
    assert_eq!(
        attempts[0].intent.request_event,
        attempts[1].intent.request_event
    );
    assert_eq!(attempts[0].parent, parent_address);
    assert_eq!(attempts[1].parent, parent_address);
    assert!(attempts[1].work < attempts[0].work);
    assert!(attempts[1].bytes < attempts[0].bytes);
    assert_ne!(attempts[0].checkpoint, attempts[1].checkpoint);
    assert!(attempts[1].checkpoint.workspace_commit > attempts[0].checkpoint.workspace_commit);
    assert_eq!(hook.legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        reader.calls.load(Ordering::SeqCst),
        2,
        "no extra main forward on either refusal"
    );
    let measured = runtime
        .drain_measurements()
        .steps
        .pop()
        .expect("failed retry");
    assert_eq!(measured.preparation_hook_micros, 22);
    assert_eq!(measured.prepare_micros, 62);
    assert_eq!(measured.prepare_attempts, 2);
    assert!(measured.evicted_groups > 0);
    assert!(!measured.dispatched);
    let current = &runtime
        .checkpoint()
        .groups
        .last()
        .expect("current interaction")
        .messages[0]
        .source;
    assert_eq!(
        hook.owner
            .read_original_span(&context, current)
            .expect("current durable original")
            .as_slice(),
        b"Current interaction must survive retry eviction."
    );
}
