//! Real encrypted owned calls and publications; constant vectors are not recall quality.

use super::*;
use crate::router_trace::hybrid::segments::{
    HybridDensePathKind, SEGMENTED_HYBRID_OBSERVATION_REVISION,
};
use crate::router_trace::hybrid::{HybridCompletion, HybridRouteKind, OwnedHybridObservation};
use crate::{DenseProjectionReceipt, DenseSegmentPublication, DenseSegmentSealRequest};
use std::sync::Mutex;
mod features;

fn segmented_settings(encoder: Arc<Encoder>) -> RuntimeSettings {
    let mut configured = settings(encoder);
    configured
        .automatic_hybrid
        .as_mut()
        .expect("owned opt-in")
        .limits
        .segments = Some(OwnedSegmentLimits { max_segments: 64 });
    configured
}

fn original(f: &Fixture, sequence: u64, text: &str) -> CaptureRequest {
    let mut request = crate::capture::tests::request(sequence, text);
    request.context = f.context.clone();
    request.event.session_id = Some(f.identity.session_id);
    request.event.source_version = Some(format!("owned-segment-source-{sequence}"));
    request
}

fn project(f: &Fixture, parent: &mut QueryBudget) -> DenseProjectionReceipt {
    Preparation {
        native: Arc::clone(&f.native),
        encoder: Arc::clone(&f.encoder),
    }
    .before_prepare(&f.context, parent)
    .expect("real interpreted raw and dense source maintenance");
    let receipt = f
        .native
        .project_original_spans(&f.context, f.encoder.as_ref(), 64, parent)
        .expect("exact current accepted dense receipt");
    assert!(receipt.caught_up);
    receipt
}

fn seal(
    f: &Fixture,
    target: DenseProjectionReceipt,
    parent: &mut QueryBudget,
) -> DenseSegmentPublication {
    let previous = f
        .native
        .original_span_segment_head(&f.context, 1, parent)
        .expect("native admitted predecessor");
    f.native
        .seal_original_span_segment(
            &f.context,
            &DenseSegmentSealRequest {
                generation: 1,
                previous,
                target,
            },
            parent,
        )
        .expect("actual accepted immutable segment")
}

fn segmented_fixture() -> (Fixture, [ObservationId; 3], DenseSegmentPublication) {
    let f = fixture();
    let mut sources = Vec::new();
    let mut preceding: Option<DenseSegmentPublication> = None;
    for sequence in 25..=26 {
        let request = original(
            &f,
            sequence,
            &format!("Independent segmented archive item {sequence} retains its exact original."),
        );
        sources.push(request.event.event_id);
        f.native
            .append_event(request)
            .expect("actual delta original");
        let target = project(&f, &mut budget());
        assert_eq!(target.sources, sequence);
        let publication = seal(&f, target, &mut budget());
        assert_eq!(publication.delta.manifest.ordinal, sequence - 24);
        assert_eq!(publication.delta.manifest.nodes, 1);
        if let Some(previous) = &preceding {
            assert_eq!(
                &publication.delta.manifest.before,
                &previous.directory.head.covered
            );
        }
        preceding = Some(publication);
    }
    let fresh = original(
        &f,
        27,
        "A genuine projected fresh original remains outside both sealed intervals.",
    );
    sources.push(fresh.event.event_id);
    f.native.append_event(fresh).expect("actual fresh original");
    let target = project(&f, &mut budget());
    assert_eq!(target.sources, 27);
    assert_eq!(f.encoder.source_forwards.load(Ordering::SeqCst), 27);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 0);
    (
        f,
        sources.try_into().expect("two deltas and one fresh source"),
        preceding.expect("second real accepted segment"),
    )
}

fn check_segmented_envelope(
    envelope: &RouterEnvelope,
    prepared: &PreparedContext,
    head: &DenseSegmentPublication,
    expected_sources: &[ObservationId; 3],
) -> OwnedHybridObservation {
    let observation = envelope
        .owned_hybrid
        .as_ref()
        .expect("protected owned observation");
    assert_eq!(observation.revision, SEGMENTED_HYBRID_OBSERVATION_REVISION);
    assert_eq!(
        observation.intent.limits.segments,
        Some(OwnedSegmentLimits { max_segments: 64 })
    );
    let dense_routes = observation
        .routes
        .iter()
        .filter(|route| route.route == HybridRouteKind::Dense)
        .collect::<Vec<_>>();
    assert_eq!(
        dense_routes.len(),
        1,
        "all immutable paths contribute one dense RRF route"
    );
    let dense = dense_routes[0];
    assert_eq!(dense.completion, HybridCompletion::Complete);
    assert!(dense.dense_witness.is_none());
    assert!(dense.tail_witness_complete && dense.tail_scoring_complete);
    let witness = dense
        .segmented_dense_witness
        .as_ref()
        .expect("segmented protected witness");
    assert_eq!(witness.head.count, 2);
    assert_eq!(
        witness.head.content_digest,
        head.directory.head.content_digest
    );
    assert_eq!(witness.head.global_commit, head.directory.global_commit);
    assert_eq!(
        witness.latest.manifest_digest,
        head.delta.manifest.content_digest
    );
    assert_eq!(witness.selected_ordinals, [1, 2]);
    assert!(witness.selection_complete);
    assert_eq!(
        witness
            .paths
            .iter()
            .map(|path| path.kind)
            .collect::<Vec<_>>(),
        [
            HybridDensePathKind::Base,
            HybridDensePathKind::Segment,
            HybridDensePathKind::Segment,
            HybridDensePathKind::FreshTail
        ]
    );
    assert_eq!(
        witness.covered_dense_commitment,
        head.directory.head.covered.commitment
    );
    assert_eq!(
        witness.proven_dense_commitment,
        witness.observed_dense_commitment
    );
    assert!(witness.observed_dense_through > witness.covered_through);
    assert!(
        witness
            .paths
            .last()
            .expect("actual fresh path")
            .vector_reads
            > 0
    );
    assert!(
        expected_sources
            .iter()
            .all(|source| dense.admitted_sources.contains(source))
    );
    assert!(
        dense.admitted_sources.len() > observation.selected.len(),
        "discarded visited suppliers remain in the protected frontier"
    );
    assert!(
        dense
            .admitted_sources
            .is_subset(&envelope.retrieval_origins.originals)
    );
    for selected in &observation.selected {
        assert!(
            selected
                .route_ranks
                .iter()
                .filter(|rank| rank.route == HybridRouteKind::Dense)
                .count()
                <= 1
        );
        let expected_prior = selected
            .route_ranks
            .iter()
            .map(|rank| 1_000_000 / (60 + u64::from(rank.rank)))
            .sum::<u64>();
        assert_eq!(
            selected.routing_micros, expected_prior,
            "a segment is not an additional RRF vote"
        );
    }
    let controls = prepared
        .messages
        .iter()
        .filter(|message| message.zone == OutgoingZone::Control)
        .map(|message| message.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for private_field in [
        "segmented_dense_witness",
        "selected_ordinals",
        "covered_dense_commitment",
        "max_segments",
        "max_node_reads",
        "max_vector_reads",
        "receipt_digest",
    ] {
        assert!(
            !controls.contains(private_field),
            "protected field leaked into reader control: {private_field}"
        );
    }
    assert!(!controls.contains(&witness.head.content_digest.to_string()));
    observation.clone()
}

#[test]
fn encrypted_owned_segmented_user_tool_and_cold_protected_frontier() {
    let (f, sources, head) = segmented_fixture();
    let before_graph = graph_rows(&f.native, &f.context);
    let reader = Reader::new();
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&f.native),
        f.context.clone(),
        StartRun {
            identity: f.identity.clone(),
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        segmented_settings(Arc::clone(&f.encoder)),
        &mut budget(),
    )
    .expect("owned segmented run");
    runtime
        .accept_user(
            "Find ARCHIVE_COPPER and inspect the registered registry.".into(),
            now(),
            &mut budget(),
        )
        .expect("actual current user input");
    let fence = OwnerDispatchFence::new(Arc::clone(&f.native));
    let hook = Preparation {
        native: Arc::clone(&f.native),
        encoder: Arc::clone(&f.encoder),
    };
    let first = runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("owned segmented preparation and actual captured model call");
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 1);
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 1);
    assert!(
        first.reply.text.contains(COPPER),
        "scripted reader copies actual delivered original bytes"
    );
    let (first_request, first_envelope) =
        accepted_envelope(&f.native, &f.context, &first.output_receipt, &f.encoder);
    let first_observation =
        check_segmented_envelope(&first_envelope, &first.prepared, &head, &sources);
    let registry = Registry {
        tool: Arc::new(CueTool {
            calls: AtomicUsize::new(0),
        }),
    };
    let answer = runtime
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
        .expect("registered tool executes and next owned step prepares automatically");
    let InteractionAnswer::Generated(second) = answer else {
        panic!("actual after-tool generation required")
    };
    assert_eq!(registry.tool.calls.load(Ordering::SeqCst), 1);
    assert_eq!(reader.calls.load(Ordering::SeqCst), 2);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 2);
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 2);
    assert!(second.reply.text.contains(SILVER));
    let tool_source = runtime
        .checkpoint()
        .groups
        .last()
        .expect("current group")
        .messages
        .iter()
        .find(|message| message.role == OutgoingRole::Tool)
        .expect("actual captured tool result")
        .source
        .event_id;
    let (second_request, second_envelope) =
        accepted_envelope(&f.native, &f.context, &second.output_receipt, &f.encoder);
    let second_observation =
        check_segmented_envelope(&second_envelope, &second.prepared, &head, &sources);
    assert_ne!(
        first_observation.intent.call_id,
        second_observation.intent.call_id
    );
    assert_eq!(
        first_observation.intent.interaction_sequence,
        second_observation.intent.interaction_sequence
    );
    assert!(
        second_observation
            .preflights
            .last()
            .expect("after-tool sample")
            .fragments
            .iter()
            .any(|fragment| fragment.channel
                == crate::router_trace::hybrid::HybridCueChannel::Tool
                && fragment.source.event_id == tool_source)
    );
    assert!(
        second_envelope
            .retrieval_origins
            .originals
            .contains(&tool_source)
    );
    assert_eq!(
        graph_rows(&f.native, &f.context),
        before_graph,
        "preparing never publishes another segment or base"
    );
    let traces = [
        (
            first_request,
            first
                .prepared
                .router_trace
                .as_ref()
                .expect("first trace")
                .trace_digest,
            first_observation,
        ),
        (
            second_request,
            second
                .prepared
                .router_trace
                .as_ref()
                .expect("second trace")
                .trace_digest,
            second_observation,
        ),
    ];
    drop(runtime);
    drop(fence);
    drop(hook);
    drop(f.native);
    let cold = Arc::new(
        NativeService::open_encrypted(
            f.root.path().join("native"),
            DATABASE,
            [29; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("cold encrypted owner"),
    );
    for (request, trace_digest, expected_observation) in traces {
        let restored = cold
            .read_accepted_router_trace(
                ReadAcceptedRouterTraceRequest {
                    context: f.context.clone(),
                    receipt: request.receipt.clone(),
                },
                &mut budget(),
            )
            .expect("cold accepted protected trace read");
        let AcceptedRouterTraceReadResult::Complete(restored) = restored else {
            panic!("complete retained protected metadata required");
        };
        assert_eq!(restored.header.trace_digest, trace_digest);
        let captured = cold
            .read_original(ReadOriginalRequest {
                context: f.context.clone(),
                event_id: expected_observation.intent.request_event,
                after_receipt: Some(request.receipt),
            })
            .expect("actual cold captured request");
        assert!(
            crate::router_trace::hybrid::event_has_segmented_hybrid(&captured.event)
                .expect("retained segmented feature marker")
        );
        let envelope = crate::router_trace::decode_envelope(&captured.event, &mut budget())
            .expect("strict cold protected replay")
            .expect("retained attachment");
        assert_eq!(envelope.owned_hybrid.as_ref(), Some(&expected_observation));
        assert!(
            restored
                .lineage
                .originals
                .is_superset(&envelope.retrieval_origins.originals)
        );
    }
    let resumed = OwnedAgentRuntime::resume(
        Arc::clone(&cold),
        f.context.clone(),
        f.identity.run_id,
        segmented_settings(Arc::clone(&f.encoder)),
        now(),
        &mut budget(),
    )
    .expect("cold owned segmented resume");
    assert_eq!(
        resumed.checkpoint().last_model_output,
        Some(second.output_receipt.event_id)
    );
    assert!(!resumed.model_outcome_unknown());
    assert_eq!(
        f.encoder.query_forwards.load(Ordering::SeqCst),
        2,
        "cold metadata recovery executes no query"
    );
    assert_eq!(graph_rows(&cold, &f.context), before_graph);
    assert!(
        cold.verify(VerifyRequest {
            context: f.context.request.clone(),
            deep: true
        })
        .expect("actual cold source/segment/protected deep verification")
        .valid
    );
    features::assert_feature_retention(&cold, &f.context);
}

#[derive(Debug)]
struct AdvancingEncoder {
    inner: Arc<Encoder>,
    native: Arc<NativeService>,
    context: AuthenticatedRequestContext,
    capture: Mutex<Option<CaptureRequest>>,
    published: Mutex<Option<DenseSegmentPublication>>,
}
impl TextEmbeddingAdapter for AdvancingEncoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        self.inner.profile()
    }
    fn measure_tokens(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<TokenizedText> {
        let measured = self.inner.measure_tokens(kind, text, parent)?;
        let capture = self
            .capture
            .lock()
            .expect("one callback mutation")
            .take()
            .expect("first real measured callback");
        self.native.append_event(capture)?;
        // The native guard must release read snapshots before a callback. This
        // same-thread real maintenance and publication cannot use a stale lease.
        Preparation {
            native: Arc::clone(&self.native),
            encoder: Arc::clone(&self.inner),
        }
        .before_prepare(&self.context, parent)?;
        let target =
            self.native
                .project_original_spans(&self.context, self.inner.as_ref(), 64, parent)?;
        let previous = self
            .native
            .original_span_segment_head(&self.context, 1, parent)?;
        let accepted = self.native.seal_original_span_segment(
            &self.context,
            &DenseSegmentSealRequest {
                generation: 1,
                previous,
                target,
            },
            parent,
        )?;
        *self.published.lock().expect("actual accepted mutation") = Some(accepted);
        Ok(measured)
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        self.inner.embed(kind, text, parent)
    }
}

#[test]
fn actual_dense_and_segment_head_advance_during_measurement_stops_query_forward() {
    let (f, _, head) = segmented_fixture();
    let (request, mut intent) = refusals::pending(&f);
    intent.limits.segments = Some(OwnedSegmentLimits { max_segments: 64 });
    let source_forwards = f.encoder.source_forwards.load(Ordering::SeqCst);
    let encoder = AdvancingEncoder {
        inner: Arc::clone(&f.encoder),
        native: Arc::clone(&f.native),
        context: f.context.clone(),
        capture: Mutex::new(Some(original(
            &f,
            28,
            "New actual source captured inside the measured callback before query inference.",
        ))),
        published: Mutex::new(None),
    };
    assert_eq!(
        f.native
            .prepare_context_with_query_encoder(
                request,
                intent,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &encoder,
                &mut budget()
            )
            .expect_err("current dense prefix and accepted head changed after tokenization")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 1);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.encoder.source_forwards.load(Ordering::SeqCst),
        source_forwards + 1,
        "only the newly captured source was encoded by actual maintenance"
    );
    let published = encoder
        .published
        .lock()
        .expect("actual completed callback publication");
    let published = published
        .as_ref()
        .expect("mutation committed before guard refusal");
    assert_eq!(published.delta.manifest.ordinal, 3);
    assert_eq!(published.delta.manifest.before, head.directory.head.covered);
    assert!(published.delta.manifest.after.through > head.directory.head.covered.through);
    assert_eq!(
        f.native
            .original_span_segment_head(&f.context, 1, &mut budget())
            .expect("new exact accepted current head")
            .expect("third head")
            .count,
        3
    );
}

#[test]
fn genuine_base_without_segment_head_refuses_before_query_tokenizer() {
    let f = fixture();
    let (request, mut intent) = refusals::pending(&f);
    intent.limits.segments = Some(OwnedSegmentLimits { max_segments: 64 });
    assert!(
        f.native
            .original_span_segment_head(&f.context, 1, &mut budget())
            .expect("actual accepted absence of segmented history")
            .is_none()
    );
    assert_eq!(
        f.native
            .prepare_context_with_query_encoder(
                request,
                intent,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                f.encoder.as_ref(),
                &mut budget()
            )
            .expect_err("explicit segmented request cannot silently use the old base-only profile")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 0);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 0);
}
