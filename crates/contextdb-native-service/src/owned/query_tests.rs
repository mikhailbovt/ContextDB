//! Current-step owner gates. Encoder execution belongs to the composed proof.
use super::*;
use contextdb_context::{
    InstructionHierarchy, PositionProfile, ReferenceTokenizer, RendererKind, StructuredFormat,
    VisibleOriginal,
};
use contextdb_continuity::{
    CapturedMessage, InteractionGroup, OriginalPageHandle, PendingModelCall, ScopedObligation,
    ToolResultPageView,
};
use contextdb_core::{SessionId, StreamId};
use contextdb_service::CapturePort;
use std::time::Duration;

fn budget() -> QueryBudget {
    QueryBudget::new(
        200_000,
        64 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}
fn fixture(native: &NativeService) -> SaveRunCheckpointRequest {
    let mut source =
        crate::capture::tests::request(1, "current exact original, no invented query authority");
    let session = SessionId::new();
    let run = AgentRunId::new();
    source.context.session_id = Some(session.to_string());
    source
        .context
        .capability_grants
        .extend([Capability::Runtime, Capability::ModelProcessing]);
    source.event.session_id = Some(session);
    source.event.run_id = Some(run);
    native
        .append_event(source.clone())
        .expect("captured current input");
    let span = OriginalSourceSpan {
        event_id: source.event.event_id,
        payload_digest: source.event.payload.digest().expect("digest"),
        start: 0,
        end: source.event.payload.original_bytes().expect("bytes").len() as u64,
        span_digest: source.event.payload.digest().expect("digest"),
    };
    SaveRunCheckpointRequest {
        context: source.context.clone(),
        idempotency_key: "query-checkpoint/1".into(),
        event_id: ObservationId::new(),
        expected_revision: 0,
        checkpoint: OwnedRunCheckpoint {
            version: 1,
            identity: OwnedRunIdentity {
                workspace_id: source.event.workspace_id,
                session_id: session,
                run_id: run,
                actor_id: source.context.actor_id,
                agent_id: source.context.agent_id,
                subject_id: source.context.request.subject_id,
                scopes: source.event.scope_ids.clone(),
            },
            revision: 1,
            producer_id: source.event.producer_id,
            next_sequence: 3,
            recorded_at: source.event.recorded_at,
            model_profile: ModelProfile {
                id: "reference-reader".into(),
                family: "reference".into(),
                tokenizer_id: ReferenceTokenizer::ID.into(),
                renderer: RendererKind::Compact,
                max_context_tokens: 32000,
                reserved_output_tokens: 4000,
                preferred_structured_format: StructuredFormat::CompactText,
                supports_tool_results: true,
                supports_native_citations: false,
                supports_prompt_caching: false,
                position_profile: PositionProfile::CriticalFirst,
                instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
                max_schema_complexity: 64,
                external_processing: false,
            },
            groups: vec![InteractionGroup {
                sequence: 1,
                complete: false,
                messages: vec![CapturedMessage {
                    id: BlockId::new("current/1").expect("id"),
                    source: span.clone(),
                    role: OutgoingRole::User,
                    tool_calls: vec![],
                    tool_result: None,
                    tool_page: None,
                }],
            }],
            obligations: vec![ScopedObligation {
                id: "current-goal".into(),
                scope: *source.event.scope_ids.first().expect("scope"),
                source: span,
                status: ObligationStatus::Open,
            }],
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
    }
}
fn admit(
    native: &NativeService,
    request: &SaveRunCheckpointRequest,
    receipt: &CaptureReceipt,
) -> ServiceResult<OwnedQueryAdmission> {
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(storage_error)?;
    let call = request
        .checkpoint
        .pending_model
        .as_ref()
        .expect("planned call");
    native.admit_owned_query(
        &snapshot,
        &request.context,
        receipt,
        &request.checkpoint.model_profile,
        call.call_id,
        call.request_event,
        1,
        &mut budget(),
    )
}

#[test]
fn encrypted_current_query_admission_binds_head_and_refuses_captured_reserved_slot() {
    let directory = tempfile::tempdir().expect("native");
    let (_ld, ledger) = crate::suppression::tests::authority("owned-query");
    let (_kd, keys) = crate::encryption::tests::authority("owned-query");
    let native = NativeService::open_encrypted(
        directory.path(),
        "owned-query",
        [23; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted owner");
    let request = fixture(&native);
    let saved = native
        .save_run_checkpoint(request.clone(), &mut budget())
        .expect("planned checkpoint");
    let admitted = admit(&native, &request, &saved.receipt).expect("current owner admission");
    assert_eq!(admitted.checkpoint, request.checkpoint);
    assert_eq!(
        Some(admitted.checkpoint_digest),
        saved.receipt.payload_digest
    );
    let call = request
        .checkpoint
        .pending_model
        .as_ref()
        .expect("planned call");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        native
            .admit_owned_query(
                &snapshot,
                &request.context,
                &saved.receipt,
                &request.checkpoint.model_profile,
                ModelCallId::new(),
                call.request_event,
                1,
                &mut budget()
            )
            .expect_err("call replay")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut profile = request.checkpoint.model_profile.clone();
    profile.id = "other-reader".into();
    assert_eq!(
        native
            .admit_owned_query(
                &snapshot,
                &request.context,
                &saved.receipt,
                &profile,
                call.call_id,
                call.request_event,
                1,
                &mut budget()
            )
            .expect_err("reader changed")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut no_model = request.context.clone();
    no_model
        .capability_grants
        .remove(&Capability::ModelProcessing);
    assert_eq!(
        native
            .admit_owned_query(
                &snapshot,
                &no_model,
                &saved.receipt,
                &request.checkpoint.model_profile,
                call.call_id,
                call.request_event,
                1,
                &mut budget()
            )
            .expect_err("local model processing requires grant")
            .code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        native
            .admit_owned_query(
                &snapshot,
                &request.context,
                &saved.receipt,
                &request.checkpoint.model_profile,
                call.call_id,
                call.request_event,
                1,
                &mut QueryBudget::new(100, 1024, Duration::from_secs(5), Default::default())
            )
            .expect_err("one bounded parent")
            .code,
        ErrorCode::BudgetExhausted
    );
    drop(snapshot);
    drop(native);
    let cold =
        NativeService::open_encrypted(directory.path(), "owned-query", [23; 32], ledger, keys)
            .expect("cold owner");
    assert_eq!(
        admit(&cold, &request, &saved.receipt)
            .expect("cold admission")
            .checkpoint_digest,
        admitted.checkpoint_digest
    );
    // Another accepted source occupying the reserved ID cannot pretend that
    // preparation never happened, even when the owned producer is unchanged.
    let mut collision = crate::capture::tests::request(1, "already occupied reserved occurrence");
    collision.context = request.context.clone();
    collision.event.event_id = call.request_event;
    collision.event.producer_id = StreamId::new();
    collision.event.session_id = Some(request.checkpoint.identity.session_id);
    collision.event.run_id = Some(request.checkpoint.identity.run_id);
    collision.idempotency_key = "reserved-slot-collision".into();
    cold.append_event(collision)
        .expect("accepted occupied slot");
    assert!(
        admit(&cold, &request, &saved.receipt)
            .expect_err("reserved request cannot replay")
            .message
            .contains("already captured")
    );
    let mut late = crate::capture::tests::request(3, "owned producer advanced before recovery");
    late.context = request.context.clone();
    late.event.producer_id = request.checkpoint.producer_id;
    late.event.session_id = Some(request.checkpoint.identity.session_id);
    late.event.run_id = Some(request.checkpoint.identity.run_id);
    late.idempotency_key = "unreconciled-owned-input".into();
    cold.append_event(late).expect("later accepted owned event");
    assert_eq!(
        admit(&cold, &request, &saved.receipt)
            .expect_err("producer tail must be recovered before query processing")
            .code,
        ErrorCode::IndexTooStale
    );
}

#[test]
fn owned_sample_membership_keeps_current_working_and_tool_preview_boundaries() {
    let directory = tempfile::tempdir().expect("native");
    let native =
        NativeService::open(directory.path(), "owned-query-membership", [24; 32]).expect("owner");
    let request = fixture(&native);
    let saved = native
        .save_run_checkpoint(request.clone(), &mut budget())
        .expect("checkpoint");
    let mut admitted = admit(&native, &request, &saved.receipt).expect("current owner");
    let message = &admitted.checkpoint.groups[0].messages[0];
    let id = message.id.clone();
    let mut child = message.source.clone();
    let text = "current exact original, no invented query authority".to_owned();
    let current = OutgoingMessage {
        id: id.clone(),
        zone: OutgoingZone::CurrentTurn,
        role: OutgoingRole::User,
        text: text.clone(),
        originals: vec![VisibleOriginal {
            span: message.source.clone(),
            text_start: 0,
            text_end: text.len() as u64,
        }],
        tool_calls: vec![],
        tool_result: None,
    };
    let working = OutgoingMessage {
        id: BlockId::new("obligation:current-goal").expect("id"),
        zone: OutgoingZone::WorkingState,
        role: OutgoingRole::User,
        text: text.clone(),
        originals: current.originals.clone(),
        tool_calls: vec![],
        tool_result: None,
    };
    let base = OutgoingBase {
        control: vec![],
        working: vec![working],
        hot: vec![],
        current: vec![current],
    };
    native
        .validate_owned_query_base(&admitted, &base, &mut budget())
        .expect("exact owned current and working layout");
    let mut duplicated = base.clone();
    duplicated.current.push(duplicated.current[0].clone());
    assert!(
        native
            .validate_owned_query_base(&admitted, &duplicated, &mut budget())
            .is_err()
    );
    let mut literal = base.clone();
    literal.current[0].text.push_str("caller-added cue literal");
    assert!(
        native
            .validate_owned_query_base(&admitted, &literal, &mut budget())
            .is_err()
    );
    let mut altered = base.clone();
    altered.current[0].originals[0].text_start = 1;
    assert!(
        native
            .validate_owned_query_base(&admitted, &altered, &mut budget())
            .is_err()
    );
    // Same source in a second distinct message still has an exact order. This
    // is a pure layout fixture, not another accepted checkpoint declaration.
    let mut two = OwnedQueryAdmission {
        checkpoint: admitted.checkpoint.clone(),
        checkpoint_digest: admitted.checkpoint_digest,
    };
    let mut second = two.checkpoint.groups[0].messages[0].clone();
    second.id = BlockId::new("current/2").expect("id");
    two.checkpoint.groups[0].messages.push(second);
    let mut ordered = base.clone();
    let mut second = ordered.current[0].clone();
    second.id = BlockId::new("current/2").expect("id");
    ordered.current.push(second);
    native
        .validate_owned_query_base(&two, &ordered, &mut budget())
        .expect("declared message order");
    ordered.current.swap(0, 1);
    assert!(
        native
            .validate_owned_query_base(&two, &ordered, &mut budget())
            .is_err()
    );
    child.end = 10;
    child.span_digest = ContentDigest::from_bytes(*blake3::hash(b"current ex").as_bytes());
    native
        .validate_owned_query_source(
            &admitted,
            &id,
            OutgoingZone::CurrentTurn,
            OutgoingRole::User,
            Some(&child),
            &mut budget(),
        )
        .expect("current child range");
    native
        .validate_owned_query_source(
            &admitted,
            &BlockId::new("obligation:current-goal").expect("id"),
            OutgoingZone::WorkingState,
            OutgoingRole::User,
            Some(&child),
            &mut budget(),
        )
        .expect("open working child range");
    let mut foreign = child.clone();
    foreign.event_id = ObservationId::new();
    assert!(
        native
            .validate_owned_query_source(
                &admitted,
                &id,
                OutgoingZone::CurrentTurn,
                OutgoingRole::User,
                Some(&foreign),
                &mut budget()
            )
            .is_err()
    );
    assert!(
        native
            .validate_owned_query_source(
                &admitted,
                &id,
                OutgoingZone::HotHistory,
                OutgoingRole::User,
                Some(&child),
                &mut budget()
            )
            .is_err()
    );
    assert!(
        native
            .validate_owned_query_source(
                &admitted,
                &id,
                OutgoingZone::CurrentTurn,
                OutgoingRole::Assistant,
                Some(&child),
                &mut budget()
            )
            .is_err()
    );
    assert_eq!(
        native
            .validate_owned_query_source(
                &admitted,
                &id,
                OutgoingZone::CurrentTurn,
                OutgoingRole::User,
                None,
                &mut budget()
            )
            .expect_err("source-free spoof")
            .code,
        ErrorCode::Unsupported
    );
    admitted.checkpoint.obligations[0].status = ObligationStatus::Completed;
    assert!(
        native
            .validate_owned_query_source(
                &admitted,
                &BlockId::new("obligation:current-goal").expect("id"),
                OutgoingZone::WorkingState,
                OutgoingRole::User,
                Some(&child),
                &mut budget()
            )
            .is_err()
    );
    // Shape-only membership test: actual page/call and byte authentication is
    // exercised by native checkpoint paging proof and the owner admission above.
    let preview = OriginalSourceSpan {
        event_id: ObservationId::new(),
        payload_digest: ContentDigest::from_bytes([31; 32]),
        start: 5000,
        end: 6000,
        span_digest: ContentDigest::from_bytes([32; 32]),
    };
    let message = &mut admitted.checkpoint.groups[0].messages[0];
    message.role = OutgoingRole::Tool;
    message.tool_result = Some("completed-call".into());
    message.tool_page = Some(ToolResultPageView {
        handle: OriginalPageHandle {
            database_id: "owned-query-membership".into(),
            event_id: preview.event_id,
            payload_digest: preview.payload_digest,
            byte_length: 20000,
        },
        preview: preview.clone(),
    });
    native
        .validate_owned_query_source(
            &admitted,
            &id,
            OutgoingZone::CurrentTurn,
            OutgoingRole::Tool,
            Some(&preview),
            &mut budget(),
        )
        .expect("authentic checkpoint page preview membership");
    let mut outside = preview;
    outside.end = 6001;
    assert!(
        native
            .validate_owned_query_source(
                &admitted,
                &id,
                OutgoingZone::CurrentTurn,
                OutgoingRole::Tool,
                Some(&outside),
                &mut budget()
            )
            .is_err()
    );
    let mut next = request.clone();
    next.expected_revision = 1;
    next.checkpoint.revision = 2;
    next.checkpoint.next_sequence = 4;
    next.event_id = ObservationId::new();
    next.idempotency_key = "query-checkpoint/2".into();
    native
        .save_run_checkpoint(next, &mut budget())
        .expect("new exact run head");
    assert_eq!(
        admit(&native, &request, &saved.receipt)
            .expect_err("old checkpoint replay")
            .code,
        ErrorCode::IndexTooStale
    );
}
