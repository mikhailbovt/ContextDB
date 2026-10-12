//! Encrypted owned execution with observed callbacks; no semantic-quality score.

use super::*;
use contextdb_agent_runtime::*;
use contextdb_core::*;
use contextdb_service::Capability;
use contextdb_service::*;
use contextdb_storage::{ReadSnapshot, SnapshotSelector, StorageEngine};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

mod fixture;
mod real;
mod refusals;
use fixture::*;

fn request_for_output(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    output: &CaptureReceipt,
) -> CapturedOriginal {
    let output = native
        .read_original(ReadOriginalRequest {
            context: context.clone(),
            event_id: output.event_id,
            after_receipt: Some(output.clone()),
        })
        .expect("actual captured reader output");
    let Some(EventProvenance::ModelOutput {
        request_event_id, ..
    }) = output.event.provenance
    else {
        panic!("reader output must name its actual captured request");
    };
    native
        .read_original(ReadOriginalRequest {
            context: context.clone(),
            event_id: request_event_id,
            after_receipt: None,
        })
        .expect("actual captured protected request")
}

fn accepted_envelope(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
    output: &CaptureReceipt,
    encoder: &Encoder,
) -> (CapturedOriginal, RouterEnvelope) {
    let request = request_for_output(native, context, output);
    let envelope = crate::router_trace::decode_envelope(&request.event, &mut budget())
        .expect("validate actual protected attachment")
        .expect("replay attachment exists");
    assert_eq!(
        envelope.trace_version().expect("trace version"),
        ROUTER_REPLAY_TRACE_VERSION
    );
    let observation = envelope
        .owned_hybrid
        .as_ref()
        .expect("protected owned hybrid observation");
    assert_eq!(observation.intent.request_event, request.event.event_id);
    assert_eq!(observation.embedding_profile, *encoder.profile());
    assert_eq!(
        observation.profile_digest,
        encoder.profile().digest().expect("actual encoder profile")
    );
    if encoder.controlled() {
        assert_eq!(
            observation.preflights.len(),
            1,
            "controlled exact tokenizer fits its first measured sample"
        );
    }
    let final_preflight = observation
        .preflights
        .last()
        .expect("admitted token preflight");
    assert_eq!(
        final_preflight.tokens.token_count,
        observation.vector.token_count
    );
    assert_eq!(
        final_preflight.tokens.tokens_digest,
        observation.vector.tokens_digest
    );
    assert!(final_preflight.tokens.token_count <= encoder.profile().max_input_tokens);
    assert!(
        observation.preflights[..observation.preflights.len() - 1]
            .iter()
            .all(|preflight| preflight.tokens.token_count > encoder.profile().max_input_tokens)
    );
    for route in &observation.routes {
        assert!(
            route
                .admitted_sources
                .is_subset(&envelope.retrieval_origins.originals),
            "every admitted source survives top-k in protected retrieval origins"
        );
    }
    for preflight in &observation.preflights {
        for fragment in &preflight.fragments {
            assert!(
                envelope
                    .retrieval_origins
                    .originals
                    .contains(&fragment.source.event_id)
            );
        }
    }
    (request, envelope)
}

fn graph_rows(
    native: &NativeService,
    context: &AuthenticatedRequestContext,
) -> Vec<contextdb_storage::Entry> {
    native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("graph snapshot")
        .scan_prefix(
            &native.keyspaces.continuous,
            &crate::raw_index::dense::graph::graph_prefix(
                &digest_bytes(context.request.workspace_id.as_bytes()),
                1,
            ),
        )
        .expect("immutable graph inventory")
}

#[test]
fn encrypted_owned_hybrid_repeats_after_registered_tool_and_recovers_complete_protected_frontier() {
    drop(run_vertical(fixture()));
}

fn run_vertical(f: Fixture) -> Arc<Encoder> {
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
        settings(Arc::clone(&f.encoder)),
        &mut f.encoder.budget(),
    )
    .expect("owned opt-in run");
    runtime
        .accept_user(
            "Find the archived ARCHIVE_COPPER seal, then inspect the registered registry.".into(),
            now(),
            &mut f.encoder.budget(),
        )
        .expect("actual source-backed current input");
    let fence = OwnerDispatchFence::new(Arc::clone(&f.native));
    let hook = Preparation {
        native: Arc::clone(&f.native),
        encoder: Arc::clone(&f.encoder),
    };
    let first = runtime
        .step(&reader, &fence, &hook, &[], now(), &mut f.encoder.budget())
        .expect("automatic owned preparation without explicit routes or target IDs");
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 1);
    assert!(
        first.reply.text.contains(COPPER),
        "reader copies attributable bytes from the actual wire"
    );
    let (first_request, first_envelope) =
        accepted_envelope(&f.native, &f.context, &first.output_receipt, &f.encoder);
    let first_observation = first_envelope
        .owned_hybrid
        .as_ref()
        .expect("first observation");
    assert_eq!(
        f.encoder.measurements.load(Ordering::SeqCst),
        first_observation.preflights.len(),
        "each actual measured callback is recorded without probe inference"
    );
    let all_routes = first_observation
        .routes
        .iter()
        .flat_map(|route| &route.admitted_sources)
        .copied()
        .collect::<BTreeSet<_>>();
    assert!(all_routes.len() > first_observation.intent.limits.sources as usize);
    assert!(
        all_routes.iter().any(|id| !first_observation
            .selected
            .iter()
            .any(|selected| selected.event_id == *id)),
        "unselected inspected supplier remains protected"
    );
    assert!(
        first_envelope
            .retrieval_origins
            .originals
            .contains(&f.copper)
    );
    assert!(
        first_envelope
            .retrieval_origins
            .originals
            .contains(&f.silver)
    );
    assert!(first.prepared.messages.iter().any(|message| {
        message.zone == OutgoingZone::Evidence
            && message
                .originals
                .iter()
                .any(|original| original.span.event_id == f.copper)
            && message.text.contains(COPPER)
    }));
    let registry = Registry {
        tool: Arc::new(CueTool {
            calls: AtomicUsize::new(0),
        }),
    };
    let result = runtime
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
            &mut f.encoder.budget(),
        )
        .expect("actual registered tool capture and next automatic owned preparation");
    let InteractionAnswer::Generated(second) = result else {
        panic!("fresh after-tool answer required");
    };
    assert_eq!(registry.tool.calls.load(Ordering::SeqCst), 1);
    assert_eq!(reader.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        f.encoder.query_forwards.load(Ordering::SeqCst),
        2,
        "one query forward per prepare, no probe inference"
    );
    assert!(second.reply.text.contains(SILVER));
    let tool_source = runtime
        .checkpoint()
        .groups
        .last()
        .expect("current group")
        .messages
        .iter()
        .find(|message| message.role == OutgoingRole::Tool)
        .expect("actually captured tool result")
        .source
        .event_id;
    let (second_request, second_envelope) =
        accepted_envelope(&f.native, &f.context, &second.output_receipt, &f.encoder);
    let second_observation = second_envelope
        .owned_hybrid
        .as_ref()
        .expect("after-tool observation");
    assert_eq!(
        f.encoder.measurements.load(Ordering::SeqCst),
        first_observation.preflights.len() + second_observation.preflights.len()
    );
    if f.encoder.controlled() {
        assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 2);
    }
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
            .expect("final admitted after-tool cues")
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
    assert!(f.encoder.query_texts.lock().expect("actual callbacks")[1].contains("ARCHIVE_SILVER"));
    assert!(second.prepared.messages.iter().any(|message| {
        message.zone == OutgoingZone::Evidence
            && message
                .originals
                .iter()
                .any(|original| original.span.event_id == f.silver)
            && message.text.contains(SILVER)
    }));
    assert_eq!(
        graph_rows(&f.native, &f.context),
        before_graph,
        "no per-step graph publication/rebuild"
    );
    let first_digest = first
        .prepared
        .router_trace
        .as_ref()
        .expect("prepared trace")
        .trace_digest;
    let second_digest = second
        .prepared
        .router_trace
        .as_ref()
        .expect("prepared trace")
        .trace_digest;
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
    for (request, expected_digest, expected_event) in [
        (
            &first_request,
            first_digest,
            first_observation.intent.request_event,
        ),
        (
            &second_request,
            second_digest,
            second_observation.intent.request_event,
        ),
    ] {
        let read = cold
            .read_accepted_router_trace(
                ReadAcceptedRouterTraceRequest {
                    context: f.context.clone(),
                    receipt: request.receipt.clone(),
                },
                &mut f.encoder.budget(),
            )
            .expect("cold current-authorized protected read");
        let AcceptedRouterTraceReadResult::Complete(read) = read else {
            panic!("retained protected read required");
        };
        assert_eq!(read.header.trace_digest, expected_digest);
        assert_eq!(read.receipt.event_id, expected_event);
        let restored = cold
            .read_original(ReadOriginalRequest {
                context: f.context.clone(),
                event_id: expected_event,
                after_receipt: Some(request.receipt.clone()),
            })
            .expect("cold original protected attachment");
        let envelope = crate::router_trace::decode_envelope(&restored.event, &mut budget())
            .expect("cold accepted envelope")
            .expect("actual protected attachment retained");
        assert!(envelope.owned_hybrid.is_some());
        assert!(all_routes.is_subset(&first_envelope.retrieval_origins.originals));
        assert!(
            read.lineage
                .originals
                .is_superset(&envelope.retrieval_origins.originals)
        );
    }
    let resumed = OwnedAgentRuntime::resume(
        Arc::clone(&cold),
        f.context.clone(),
        f.identity.run_id,
        settings(Arc::clone(&f.encoder)),
        now(),
        &mut f.encoder.budget(),
    )
    .expect("cold owned resume");
    assert_eq!(
        resumed.checkpoint().last_model_output,
        Some(second.output_receipt.event_id)
    );
    assert!(!resumed.model_outcome_unknown());
    assert_eq!(
        f.encoder.query_forwards.load(Ordering::SeqCst),
        2,
        "cold recovery executes no query forward"
    );
    assert_eq!(graph_rows(&cold, &f.context), before_graph);
    cold.verify_native(true)
        .expect("deep source/graph/protected capture verification");
    if !f.encoder.controlled() {
        println!(
            "{}",
            serde_json::json!({
                "proof": "native-owned-hybrid-real-encoder-v1",
                "embedding_profile": f.encoder.profile(),
                "profile_digest": f.encoder.profile().digest().expect("actual profile digest"),
                "graph_nodes": f.graph_nodes,
                "graph_rows": before_graph.len(),
                "graph_unchanged": true,
                "first_admitted_sources": all_routes.len(),
                "first_selected_sources": first_observation.selected.len(),
                "after_tool_admitted_sources": second_observation.routes.iter()
                    .flat_map(|route| &route.admitted_sources).collect::<BTreeSet<_>>().len(),
                "first_query_vector": first_observation.vector,
                "after_tool_query_vector": second_observation.vector,
                "source_forwards": f.encoder.source_forwards.load(Ordering::SeqCst),
                "query_token_measurements": f.encoder.measurements.load(Ordering::SeqCst),
                "query_forwards": f.encoder.query_forwards.load(Ordering::SeqCst),
                "tool_executions": registry.tool.calls.load(Ordering::SeqCst),
                "reader_calls": reader.calls.load(Ordering::SeqCst),
                "cold_accepted_traces": 2,
                "cold_resume": true,
                "deep_verification": true,
                "reader_quality_measured": false,
                "semantic_recall_measured": false,
                "benchmark_score": null
            })
        );
    }
    drop(resumed);
    drop(cold);
    f.encoder
}
