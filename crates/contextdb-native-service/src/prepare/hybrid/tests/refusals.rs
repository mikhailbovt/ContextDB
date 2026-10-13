//! One reusable current pending head; refusal precedes the next encoder callback.

use super::*;
use contextdb_context::{ReferenceTokenizer, VisibleOriginal};
use contextdb_continuity::PendingModelCall;

pub(super) fn pending(f: &Fixture) -> (PrepareContextRequest, OwnedHybridIntent) {
    let reader = Reader::new();
    let configured = settings(Arc::clone(&f.encoder));
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&f.native),
        f.context.clone(),
        StartRun {
            identity: f.identity.clone(),
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        configured.clone(),
        &mut budget(),
    )
    .expect("run for pending owner admission");
    runtime
        .accept_user(
            "Find ARCHIVE_COPPER from the current observed request.".into(),
            now(),
            &mut budget(),
        )
        .expect("current captured input");
    let mut checkpoint = runtime.checkpoint().clone();
    let expected_revision = checkpoint.revision;
    checkpoint.revision += 1;
    checkpoint.next_sequence += 1;
    let call = PendingModelCall {
        call_id: ModelCallId::new(),
        request_event: ObservationId::new(),
        wire_digest: None,
        interrupted_output: None,
    };
    checkpoint.pending_model = Some(call.clone());
    let saved = f
        .native
        .save_run_checkpoint(
            SaveRunCheckpointRequest {
                context: f.context.clone(),
                idempotency_key: "hybrid-controlled-planned-head".into(),
                event_id: ObservationId::new(),
                expected_revision,
                checkpoint,
            },
            &mut budget(),
        )
        .expect("exact accepted planned checkpoint");
    drop(runtime);
    let hook = Preparation {
        native: Arc::clone(&f.native),
        encoder: Arc::clone(&f.encoder),
    };
    hook.before_prepare(&f.context, &mut budget())
        .expect("source maintenance before query fence");
    let group = saved.checkpoint.groups.last().expect("current group");
    let message = group.messages.last().expect("current message");
    let text = String::from_utf8(
        f.native
            .read_original_span(&f.context, &message.source)
            .expect("actual current original"),
    )
    .expect("fixture UTF-8");
    let base = OutgoingBase {
        control: vec![],
        working: vec![],
        hot: vec![],
        current: vec![OutgoingMessage {
            id: message.id.clone(),
            zone: OutgoingZone::CurrentTurn,
            role: message.role,
            originals: vec![VisibleOriginal {
                span: message.source.clone(),
                text_start: 0,
                text_end: text.len() as u64,
            }],
            text,
            tool_calls: vec![],
            tool_result: None,
        }],
    };
    let request = PrepareContextRequest {
        context: f.context.clone(),
        pack_id: ContextPackId::new(),
        purpose: PackPurpose::Conversation,
        known_at: None,
        valid_at: None,
        after_receipt: Some(saved.receipt),
        raw_queries: vec![],
        memory_query: None,
        bm25_query: None,
        required_facets: vec![],
        memory_budget: configured.memory_budget,
        model_profile: reader.profile(),
        base,
        outgoing_budget: configured.outgoing_budget,
        explicit_memory_request: false,
        router_trace_profile: RouterTraceProfile::RequiredReplayV2,
    };
    let intent = OwnedHybridIntent {
        call_id: call.call_id,
        request_event: call.request_event,
        interaction_sequence: group.sequence,
        attempt: 0,
        limits: configured.automatic_hybrid.expect("opt-in").limits,
    };
    (request, intent)
}

fn prepare(
    f: &Fixture,
    request: PrepareContextRequest,
    intent: OwnedHybridIntent,
) -> ServiceResult<PreparedContext> {
    f.native.prepare_context_with_query_encoder(
        request,
        intent,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        f.encoder.as_ref(),
        &mut budget(),
    )
}

#[test]
fn wrong_rendered_range_noncurrent_source_call_replay_and_callback_revocation_stop_before_forward()
{
    let f = fixture();
    let (request, intent) = pending(&f);
    let mut legacy_route = request.clone();
    legacy_route
        .raw_queries
        .push(contextdb_recall::IndexedQuery {
            filter: RawFilter::default(),
            text: Some(RawTextQuery::AllTerms("ARCHIVE_COPPER".into())),
            neighbor_of: None,
            selection: contextdb_recall::IndexedSelection::TopK { limit: 8 },
        });
    assert_eq!(
        prepare(&f, legacy_route, intent.clone())
            .expect_err("owned hybrid refuses an extra legacy route")
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 0);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 0);
    let mut wrong = request.clone();
    wrong.base.current[0].text.replace_range(0..1, "X");
    assert!(
        prepare(&f, wrong, intent.clone()).is_err(),
        "same alleged source cannot authorize invented rendered bytes"
    );
    let archived = f
        .native
        .read_original(ReadOriginalRequest {
            context: f.context.clone(),
            event_id: f.copper,
            after_receipt: None,
        })
        .expect("archive is accessible for ordinary recall");
    let bytes = archived
        .event
        .payload
        .original_bytes()
        .expect("fixture original");
    let mut wrong = request.clone();
    wrong.base.current[0].text = String::from_utf8(bytes.to_vec()).expect("archive UTF-8");
    wrong.base.current[0].originals[0] = VisibleOriginal {
        span: OriginalSourceSpan {
            event_id: archived.event.event_id,
            payload_digest: archived.event.payload.digest().expect("digest"),
            start: 0,
            end: bytes.len() as u64,
            span_digest: archived.event.payload.digest().expect("digest"),
        },
        text_start: 0,
        text_end: bytes.len() as u64,
    };
    assert!(
        prepare(&f, wrong, intent.clone()).is_err(),
        "accessible archive cannot impersonate this current input"
    );
    let mut wrong_call = intent.clone();
    wrong_call.call_id = ModelCallId::new();
    assert!(
        prepare(&f, request.clone(), wrong_call).is_err(),
        "call replay must match the accepted pending head"
    );
    let mut literal = request.clone();
    literal.base.current[0].originals.clear();
    assert!(
        prepare(&f, literal, intent.clone()).is_err(),
        "source-free current literal cannot impersonate an owned source"
    );
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 0);
    assert_eq!(f.encoder.query_forwards.load(Ordering::SeqCst), 0);
    let current = request.base.current[0].originals[0].span.event_id;
    *f.encoder.revocation.lock().expect("callback revocation") =
        Some((Arc::clone(&f.native), f.context.clone(), current));
    f.encoder.revoke_after_measure.store(true, Ordering::SeqCst);
    assert!(
        prepare(&f, request, intent).is_err(),
        "fresh owner guard refuses revocation after measured callback"
    );
    assert_eq!(f.encoder.measurements.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.encoder.query_forwards.load(Ordering::SeqCst),
        0,
        "no NN forward after current source revocation"
    );
    f.encoder
        .revocation
        .lock()
        .expect("release callback owner reference")
        .take();
}
