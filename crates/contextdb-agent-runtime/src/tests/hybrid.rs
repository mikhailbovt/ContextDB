//! Runtime dispatch wiring only; native query/source admission has separate gates.

use super::*;

#[derive(Debug)]
struct UncalledQueryEncoder(TextEmbeddingProfile);
impl TextEmbeddingAdapter for UncalledQueryEncoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.0
    }
    fn measure_tokens(
        &self,
        _: EmbeddingTextKind,
        _: &str,
        _: &mut QueryBudget,
    ) -> ServiceResult<TokenizedText> {
        panic!("runtime must not tokenize outside the native owned preparation boundary")
    }
    fn embed(
        &self,
        _: EmbeddingTextKind,
        _: &str,
        _: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        panic!("runtime must not infer outside the native owned preparation boundary")
    }
}

#[test]
fn configured_hybrid_refuses_a_legacy_port_without_direct_encoding_or_main_reader_fallback() {
    let directory = tempfile::tempdir().expect("directory");
    let native = Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
    // This wrapper intentionally implements only the original prepare method.
    // A default Unsupported hybrid boundary must not invoke that old method.
    let owner = Arc::new(LostOutputAcknowledgement {
        owner: Arc::clone(&native),
        lose_once: AtomicBool::new(false),
        output_kind: EventKind::ModelResponseCompleted,
    });
    let (context, identity) = identity();
    native
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let mut settings = settings();
    settings.router_trace_profile = RouterTraceProfile::RequiredReplayV2;
    settings.automatic_hybrid = Some(OwnedHybridSettings {
        query_encoder: Arc::new(UncalledQueryEncoder(
            TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(ContentDigest::from_bytes([3; 32])),
        )),
        limits: OwnedHybridLimits::default(),
    });
    let mut runtime = OwnedAgentRuntime::start(
        owner,
        context,
        StartRun {
            identity,
            model_profile: profile(),
            recorded_at: now(),
        },
        settings,
        &mut budget(),
    )
    .expect("explicit hybrid configuration");
    runtime
        .accept_user(
            "Actual current source remains protected on refusal.".into(),
            now(),
            &mut budget(),
        )
        .expect("captured current interaction");
    let reader = ScriptedReader::default();
    let hook = FixturePreparation(native);
    let error = runtime
        .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
        .expect_err("legacy owner has no owned hybrid preparation capability");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
    assert!(reader.requests.lock().expect("reader requests").is_empty());
    let checkpoint = runtime.checkpoint();
    let pending = checkpoint
        .pending_model
        .as_ref()
        .expect("resumable pending intent");
    assert!(pending.wire_digest.is_none());
    assert!(pending.interrupted_output.is_none());
    let group = checkpoint.groups.last().expect("current interaction");
    assert!(!group.complete);
    assert_eq!(
        group.messages.len(),
        1,
        "no model request/output or source loss is fabricated"
    );
}
