//! Automatic routed preparation and real tool continuation; no learned quality claim.
use super::*;
use crate::router_trace::hybrid::HybridRouteKind;
use crate::router_trace::hybrid::routed::{
    ROUTED_HYBRID_FEATURE, ROUTED_HYBRID_OBSERVATION_REVISION,
};
use crate::{decode, encode};

fn routed_settings(encoder: Arc<Encoder>) -> RuntimeSettings {
    let mut configured = settings(encoder);
    configured
        .automatic_hybrid
        .as_mut()
        .expect("owned hybrid")
        .limits
        .routed = Some(OwnedRoutedLimits {
        max_fine_paths: 4,
        coarse_node_reads: 32,
        coarse_vector_reads: 32,
        coarse_discovered: 32,
        coarse_ef_search: 32,
    });
    configured
}

fn check_routed_envelope(envelope: &RouterEnvelope, original: ObservationId) {
    let observation = envelope
        .owned_hybrid
        .as_ref()
        .expect("protected owner query");
    assert_eq!(observation.revision, ROUTED_HYBRID_OBSERVATION_REVISION);
    assert!(observation.intent.limits.routed.is_some());
    assert!(observation.intent.limits.segments.is_none());
    let dense = observation
        .routes
        .iter()
        .find(|r| r.route == HybridRouteKind::Dense)
        .expect("one dense route");
    assert!(dense.routed_dense_witness.is_some());
    assert!(dense.segmented_dense_witness.is_none() && dense.dense_witness.is_none());
    assert!(
        dense.admitted_sources.contains(&original),
        "genuine fine source frontier"
    );
    assert!(
        dense
            .admitted_sources
            .is_subset(&envelope.retrieval_origins.originals)
    );
    assert!(dense.tail_witness_complete && dense.tail_scoring_complete);
    assert!(dense.vector_reads <= u64::from(observation.intent.limits.vector_reads));
    assert!(dense.node_reads <= u64::from(observation.intent.limits.node_reads));
    assert!(dense.discovered <= u64::from(observation.intent.limits.discovered));
}

#[test]
fn encrypted_owned_routed_prepares_each_model_step_after_registered_tool_and_cold_resume() {
    let f = routed_fixture();
    let reader = Reader::new();
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&f.native),
        f.context.clone(),
        StartRun {
            identity: f.identity.clone(),
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        routed_settings(Arc::clone(&f.encoder)),
        &mut budget(),
    )
    .expect("routed owned run");
    runtime
        .accept_user(
            "Find the archived ARCHIVE_COPPER seal, then inspect the registered registry.".into(),
            now(),
            &mut budget(),
        )
        .expect("captured genuine user input");
    let fence = OwnerDispatchFence::new(Arc::clone(&f.native));
    let hook = Preparation {
        native: Arc::clone(&f.native),
        encoder: Arc::clone(&f.encoder),
    };
    let first = runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("automatic routed preparation with no caller path IDs");
    assert!(
        first.reply.text.contains(COPPER),
        "actual outgoing original reaches reader"
    );
    let (_, first_envelope) =
        accepted_envelope(&f.native, &f.context, &first.output_receipt, &f.encoder);
    check_routed_envelope(&first_envelope, f.copper);
    let registry = Registry {
        tool: Arc::new(CueTool {
            calls: AtomicUsize::new(0),
        }),
    };
    let second = runtime
        .drive(
            &ExecutionAdapters {
                reader: &reader,
                model_fence: &fence,
                tool_fence: &fence,
                preparation: &hook,
                tools: &registry,
            },
            1,
            now(),
            &mut budget(),
        )
        .expect("registered tool then next routed model step");
    let InteractionAnswer::Generated(second_output) = second else {
        panic!("fresh after-tool answer required");
    };
    assert!(
        second_output.reply.text.contains(SILVER),
        "actual tool cue selects delivered archive"
    );
    let (_, second_envelope) = accepted_envelope(
        &f.native,
        &f.context,
        &second_output.output_receipt,
        &f.encoder,
    );
    check_routed_envelope(&second_envelope, f.silver);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 2);
    assert_eq!(registry.tool.calls.load(Ordering::SeqCst), 1);
    let queries = f.encoder.query_texts.lock().expect("actual query texts");
    assert_eq!(queries.len(), 2);
    assert!(queries[1].contains("ARCHIVE_SILVER"));
    drop(queries);
    assert!(
        f.native
            .verify_native(true)
            .expect("full replay with routed feature")
            .valid
    );
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("format snapshot");
    let manifest: crate::Manifest = decode(
        &snapshot
            .get(&f.native.keyspaces.meta, crate::META_MANIFEST_KEY)
            .expect("format read")
            .expect("format manifest"),
        "format",
    )
    .expect("decode format");
    assert!(manifest.features.contains(ROUTED_HYBRID_FEATURE));
    let saved = snapshot
        .get(&f.native.keyspaces.meta, crate::META_MANIFEST_KEY)
        .expect("saved format")
        .expect("format");
    drop(snapshot);
    let mut stripped = manifest;
    assert!(stripped.features.remove(ROUTED_HYBRID_FEATURE));
    stripped.checksum = crate::manifest_checksum(&stripped).expect("modified ordinary checksum");
    let mut tx = f.native.engine.begin_write().expect("format-only fault");
    use contextdb_storage::WriteTransaction;
    tx.put(
        &f.native.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&stripped).expect("format bytes"),
    )
    .expect("replace format");
    tx.commit(contextdb_storage::Durability::Sync)
        .expect("fault sync");
    let refused = f.native.verify_native(true);
    let mut tx = f.native.engine.begin_write().expect("exact format restore");
    tx.put(
        &f.native.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        saved,
    )
    .expect("restore bytes");
    tx.commit(contextdb_storage::Durability::Sync)
        .expect("restore sync");
    assert_eq!(
        refused
            .expect_err("accepted routed controls require their declaration")
            .code,
        ErrorCode::IntegrityFailure
    );
    drop(runtime);
    drop(hook);
    drop(fence);
    drop(f.native);
    let cold = Arc::new(
        NativeService::open_encrypted(
            f.root.path().join("native"),
            DATABASE,
            [29; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("cold native owner"),
    );
    assert!(
        cold.verify_native(true)
            .expect("cold protected routed replay")
            .valid
    );
    let _resumed = OwnedAgentRuntime::resume(
        cold,
        f.context.clone(),
        f.identity.run_id,
        routed_settings(Arc::clone(&f.encoder)),
        now(),
        &mut budget(),
    )
    .expect("routed cold checkpoint resume");
}

#[test]
fn encrypted_owned_routed_stale_coverage_refuses_before_any_tokenizer_or_query_forward() {
    let f = routed_fixture();
    let mut original =
        crate::capture::tests::request(25, "A real new interval changes the fine directory.");
    original.context = f.context.clone();
    original.event.session_id = Some(f.identity.session_id);
    f.native
        .append_event(original)
        .expect("new permitted archive original");
    let hook = Preparation {
        native: Arc::clone(&f.native),
        encoder: Arc::clone(&f.encoder),
    };
    hook.before_prepare(&f.context, &mut budget())
        .expect("real source projection");
    let target = f
        .native
        .project_original_spans(&f.context, f.encoder.as_ref(), 64, &mut budget())
        .expect("current accepted dense target");
    f.native
        .seal_original_span_prefix_segment(
            &f.context,
            &crate::PrefixSegmentSealRequestV2 {
                generation: 1,
                previous: None,
                target,
            },
            &mut budget(),
        )
        .expect("first genuine sealed interval");
    let reader = Reader::new();
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&f.native),
        f.context.clone(),
        StartRun {
            identity: f.identity.clone(),
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        routed_settings(Arc::clone(&f.encoder)),
        &mut budget(),
    )
    .expect("owned run");
    runtime
        .accept_user("Return the archived seal.".into(), now(), &mut budget())
        .expect("actual user");
    let fence = OwnerDispatchFence::new(Arc::clone(&f.native));
    runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect_err("stale base-only router cannot serve the newer fine directory");
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 0);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 0);
    assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn encrypted_owned_routed_revocation_after_tokenization_prevents_query_inference_and_reader_dispatch()
 {
    let f = routed_fixture();
    let reader = Reader::new();
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&f.native),
        f.context.clone(),
        StartRun {
            identity: f.identity.clone(),
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        routed_settings(Arc::clone(&f.encoder)),
        &mut budget(),
    )
    .expect("owned run");
    runtime
        .accept_user("Find ARCHIVE_COPPER.".into(), now(), &mut budget())
        .expect("actual user");
    *f.encoder
        .revocation
        .lock()
        .expect("declared callback mutation") =
        Some((Arc::clone(&f.native), f.context.clone(), f.copper));
    f.encoder.revoke_after_measure.store(true, Ordering::SeqCst);
    let fence = OwnerDispatchFence::new(Arc::clone(&f.native));
    let hook = Preparation {
        native: Arc::clone(&f.native),
        encoder: Arc::clone(&f.encoder),
    };
    runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect_err("current source revocation invalidates the admitted routed view");
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 1);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 0);
    assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
}

#[derive(Debug)]
struct RootChangingReader {
    inner: Reader,
    native: Arc<NativeService>,
    context: AuthenticatedRequestContext,
    encoder: Arc<Encoder>,
    before_capture: bool,
}
impl RootChangingReader {
    fn replace_router(&self, parent: &mut QueryBudget) -> ServiceResult<()> {
        // The already admitted dense tail contains actual current user/checkpoint
        // work. Sealing it changes only fine/router roots, not source permissions.
        let target =
            self.native
                .project_original_spans(&self.context, self.encoder.as_ref(), 64, parent)?;
        self.native.seal_original_span_prefix_segment(
            &self.context,
            &crate::PrefixSegmentSealRequestV2 {
                generation: 1,
                previous: None,
                target,
            },
            parent,
        )?;
        let request =
            self.native
                .original_span_directory_router_target(&self.context, 1, parent)?;
        self.native
            .publish_original_span_directory_router(&self.context, &request, parent)?;
        Ok(())
    }
}
impl OutgoingEncoder for RootChangingReader {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn tokenizer_id(&self) -> &str {
        self.inner.tokenizer_id()
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        parent: &mut QueryBudget,
    ) -> Result<EncodedOutgoing> {
        self.inner.encode(messages, parent)
    }
}
impl ReaderAdapter for RootChangingReader {
    fn profile(&self) -> ModelProfile {
        self.inner.profile()
    }
    fn capabilities(&self) -> ReaderCapabilities {
        self.inner.capabilities()
    }
    fn tokenizer(&self) -> &dyn TokenCounter {
        self.inner.tokenizer()
    }
    fn capture_manifest(
        &self,
        call: ModelCallId,
        messages: &[OutgoingMessage],
        wire: &EncodedOutgoing,
        parent: &mut QueryBudget,
    ) -> ServiceResult<ModelRequestManifest> {
        if self.before_capture {
            self.replace_router(parent)?;
        }
        self.inner.capture_manifest(call, messages, wire, parent)
    }
    fn complete(&self, call: ModelCallId, wire: &EncodedOutgoing) -> ServiceResult<ReaderOutcome> {
        self.inner.complete(call, wire)
    }
    fn reconcile(
        &self,
        call: ModelCallId,
        digest: ContentDigest,
    ) -> ServiceResult<ModelReconciliation> {
        self.inner.reconcile(call, digest)
    }
}
impl ModelDispatchFence for RootChangingReader {
    fn before_model(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        call: ModelCallId,
        request: &CaptureReceipt,
        prepared: &PreparedContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if !self.before_capture {
            self.replace_router(parent)?;
        }
        OwnerDispatchFence::new(Arc::clone(&self.native))
            .before_model(context, checkpoint, call, request, prepared, parent)
    }
}

#[test]
fn encrypted_owned_routed_root_republication_before_capture_and_dispatch_refuses_reader_call() {
    for before_capture in [true, false] {
        let f = routed_fixture();
        let reader = RootChangingReader {
            inner: Reader::new(),
            native: Arc::clone(&f.native),
            context: f.context.clone(),
            encoder: Arc::clone(&f.encoder),
            before_capture,
        };
        let mut runtime = OwnedAgentRuntime::start(
            Arc::clone(&f.native),
            f.context.clone(),
            StartRun {
                identity: f.identity.clone(),
                model_profile: reader.profile(),
                recorded_at: now(),
            },
            routed_settings(Arc::clone(&f.encoder)),
            &mut budget(),
        )
        .expect("owned run");
        runtime
            .accept_user("Find ARCHIVE_COPPER.".into(), now(), &mut budget())
            .expect("actual user");
        let hook = Preparation {
            native: Arc::clone(&f.native),
            encoder: Arc::clone(&f.encoder),
        };
        let error = runtime
            .step(&reader, &reader, &hook, &[], now(), &mut budget())
            .expect_err("a genuinely replaced fine/router root invalidates the prepared lease");
        assert!(
            matches!(
                error.code,
                ErrorCode::IndexTooStale | ErrorCode::ContinuationExpired
            ),
            "actual root refusal: {error:?}"
        );
        assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 1);
        assert_eq!(reader.inner.calls.load(Ordering::SeqCst), 0);
        let next = f
            .native
            .original_span_directory_router_target(&f.context, 1, &mut budget())
            .expect("replacement was genuinely accepted");
        assert_eq!(next.previous.expect("accepted replacement").serial, 2);
    }
}
