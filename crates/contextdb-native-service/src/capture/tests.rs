use std::{collections::BTreeSet, process::Command, sync::Arc};

use contextdb_core::{
    EVENT_ENVELOPE_VERSION, EventCoverage, EventKind, EventPayload, EventRole, ModelCallId,
    ScopeId, SourceId, TimestampMicros, WorkspaceId,
};
use contextdb_service::{CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest};
use uuid::Uuid;

use super::*;

pub(crate) fn request(sequence: u64, text: &str) -> CaptureRequest {
    let workspace = WorkspaceId::from_uuid(Uuid::from_u128(1)).expect("workspace");
    let scope = ScopeId::from_uuid(Uuid::from_u128(2)).expect("scope");
    let mut context = crate::tests::authenticated(
        "capture",
        &workspace.to_string(),
        "owner",
        [
            Capability::Observe,
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::Admin,
        ],
    );
    context.request.scopes = BTreeSet::from([scope.to_string()]);
    CaptureRequest {
        context,
        idempotency_key: format!("event-{sequence}"),
        event: EventEnvelope {
            version: EVENT_ENVELOPE_VERSION,
            event_id: ObservationId::from_uuid(Uuid::from_u128(100 + u128::from(sequence)))
                .expect("event"),
            workspace_id: workspace,
            scope_ids: BTreeSet::from([scope]),
            producer_id: StreamId::from_uuid(Uuid::from_u128(3)).expect("producer"),
            producer_sequence: sequence,
            kind: EventKind::MessageCreated,
            recorded_at: TimestampMicros(1_000_000),
            observed_at: None,
            source_id: SourceId::from_uuid(Uuid::from_u128(4)).expect("source"),
            source_version: None,
            adapter_id: "test-host".into(),
            role: EventRole::User,
            session_id: None,
            run_id: None,
            task_id: None,
            parent_event_ids: BTreeSet::new(),
            supersedes_event_id: None,
            payload: EventPayload::InlineUtf8 {
                text: text.into(),
                digest: ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes()),
            },
            coverage: EventCoverage::CompleteObservation,
            upstream_truncated: false,
            gap_reason: None,
            response_stream: None,
            provenance: None,
        },
    }
}

fn read(service: &NativeService, request: &CaptureRequest) -> ServiceResult<CapturedOriginal> {
    service.read_original(ReadOriginalRequest {
        context: request.context.clone(),
        event_id: request.event.event_id,
        after_receipt: None,
    })
}

#[test]
fn conversation_adapter_preserves_raw_input_and_enforces_registered_authority() {
    use contextdb_chat::{ConversationAuthorityBinding, NativeConversationCapture};
    let dir = tempfile::tempdir().expect("tempdir");
    let service = Arc::new(NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open"));
    let input = request(1, "no extractor, no importance gate\n原文");
    let authority = input.context.clone();
    let adapter = NativeConversationCapture::new(
        Arc::clone(&service),
        move |_: &ConversationAuthorityBinding| Ok(authority.clone()),
    );
    let binding = ConversationAuthorityBinding {
        request_id: input.context.request.request_id.clone(),
        workspace_id: input.context.request.workspace_id.clone(),
        subject_id: input.context.request.subject_id.clone(),
        actor_id: input.context.actor_id.clone(),
        agent_id: input.context.agent_id.clone(),
        session_id: None,
        scopes: input.context.request.scopes.clone(),
        purpose: input.context.request.purpose.clone(),
        required_capabilities: BTreeSet::new(),
    };
    let mut binding = binding;
    binding.session_id = input.context.session_id.clone();
    // A host session with an arbitrary legacy name cannot label a typed native event.
    assert_eq!(
        adapter
            .capture(&binding, input.event.clone(), input.idempotency_key.clone())
            .expect_err("session binding")
            .code,
        ErrorCode::PermissionDenied
    );
    let mut input = input;
    input.context.session_id = None;
    binding.session_id = None;
    let authority = input.context.clone();
    let adapter = NativeConversationCapture::new(
        Arc::clone(&service),
        move |_: &ConversationAuthorityBinding| Ok(authority.clone()),
    );
    adapter
        .capture(&binding, input.event.clone(), input.idempotency_key.clone())
        .expect("native capture");
    assert_eq!(
        read(&service, &input).expect("raw bytes").event,
        input.event
    );
    let mut changed_scope = binding;
    changed_scope.scopes.insert(ScopeId::new().to_string());
    assert_eq!(
        adapter
            .capture(&changed_scope, request(2, "denied").event, "denied".into())
            .expect_err("authority drift")
            .code,
        ErrorCode::PermissionDenied
    );
}

#[test]
fn original_and_receipt_survive_restart_and_lost_response() {
    let dir = tempfile::tempdir().expect("tempdir");
    let input = request(1, "  Точный оригинал\r\nCode: 7319\0\t");
    let receipt = {
        let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
        let receipt = service.append_event(input.clone()).expect("capture");
        assert_eq!(read(&service, &input).expect("original").event, input.event);
        assert_eq!(service.append_event(input.clone()).expect("retry"), receipt);
        service.verify_native(true).expect("deep verification");
        receipt
    };
    let reopened = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("reopen");
    assert_eq!(
        reopened
            .append_event(input.clone())
            .expect("lost reply retry"),
        receipt
    );
    assert_eq!(read(&reopened, &input).expect("original").receipt, receipt);
    reopened
        .resolve_capture_receipt(&input.context, &receipt)
        .expect("receipt fence");
    let mut conflict = input.clone();
    conflict.event = request(1, "changed").event;
    assert_eq!(
        reopened.append_event(conflict).expect_err("conflict").code,
        ErrorCode::IdempotencyConflict
    );
    assert_eq!(receipt.workspace_commit, 1);
}

#[test]
fn current_authority_precedes_materialization_and_receipts_do_not_grant_access() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let input = request(1, "private original");
    let receipt = service.append_event(input.clone()).expect("capture");
    let mut denied = input.clone();
    denied.context.request.subject_id = "other".into();
    denied.context.request.audiences = BTreeSet::from(["other".into()]);
    // Invalid bytes must remain unread by a denied reader.
    let mut tx = service.engine.begin_write().expect("tx");
    tx.put(
        &service.keyspaces.observations_content,
        digest_bytes(input.event.event_id.to_string().as_bytes()).into_bytes(),
        b"broken".to_vec(),
    )
    .expect("damage fixture");
    tx.commit(Durability::Sync).expect("commit fixture");
    assert_eq!(
        read(&service, &denied).expect_err("denied").code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        service
            .resolve_capture_receipt(&denied.context, &receipt)
            .expect_err("denied fence")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        read(&service, &input)
            .expect_err("authorized corruption")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn foreign_and_modified_receipts_are_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let input = request(1, "raw");
    let receipt = service.append_event(input.clone()).expect("capture");
    for field in ["domain", "database"] {
        let mut other = receipt.clone();
        if field == "domain" {
            other.domain = "chat-journal/v1".into();
        } else {
            other.database_id = "other-db".into();
        }
        assert_eq!(
            service
                .resolve_capture_receipt(&input.context, &other)
                .expect_err("foreign receipt")
                .code,
            ErrorCode::FormatIncompatible
        );
    }
    let mut altered = receipt;
    altered.token.push('a');
    assert_eq!(
        service
            .resolve_capture_receipt(&input.context, &altered)
            .expect_err("tampered receipt")
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn producer_gaps_close_without_reordering_durable_arrival() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let first = request(3, "third produced, first received");
    assert_eq!(
        service
            .append_event(first.clone())
            .expect("capture")
            .workspace_commit,
        1
    );
    let coverage = service
        .producer_coverage(&first.context, first.event.producer_id)
        .expect("coverage");
    assert_eq!(
        coverage,
        ProducerCoverage {
            head: 3,
            contiguous_through: 0,
            gaps: vec![CaptureGapRange {
                from: 1,
                through: 2
            }]
        }
    );
    service
        .append_event(request(1, "first late"))
        .expect("fill first");
    assert_eq!(
        service
            .append_event(request(2, "second late"))
            .expect("fill second")
            .workspace_commit,
        3
    );
    let mut refreshed = first.context.clone();
    refreshed.request.scopes.insert(ScopeId::new().to_string());
    assert_eq!(
        service
            .producer_coverage(&refreshed, first.event.producer_id)
            .expect("stable producer"),
        ProducerCoverage {
            head: 3,
            contiguous_through: 3,
            gaps: vec![]
        }
    );
    service.verify_native(true).expect("verify");
}

#[test]
fn strict_capture_rejects_bad_digest_and_overflow_without_acknowledgement() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let large = request(1, &"x".repeat(CAPTURE_MAX_INLINE_BYTES + 1));
    assert_eq!(
        service
            .append_event(large)
            .expect_err("bounded capture")
            .code,
        ErrorCode::ResourceExhausted
    );
    let mut bad = request(1, "good");
    if let EventPayload::InlineUtf8 { text, .. } = &mut bad.event.payload {
        *text = "bad".into();
    }
    assert_eq!(
        service.append_event(bad).expect_err("digest check").code,
        ErrorCode::InvalidArgument
    );
    let input = request(1, "accepted");
    assert_eq!(
        service
            .append_event(input.clone())
            .expect("capture")
            .workspace_commit,
        1
    );
    let mut legacy_role = request(2, "omitted");
    legacy_role.event.upstream_truncated = true;
    assert_eq!(
        service
            .append_event(legacy_role)
            .expect_err("false complete")
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn response_chunks_and_abort_are_durable_and_cannot_claim_completion() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let response = ModelCallId::new();
    let mut chunk = request(1, "visible partial");
    chunk.event.role = EventRole::Assistant;
    chunk.event.kind = EventKind::ModelResponseChunk;
    chunk.event.coverage = EventCoverage::PartialObservation;
    chunk.event.response_stream = Some(ResponseStream::Chunk {
        response_id: response,
        index: 0,
    });
    service.append_event(chunk.clone()).expect("chunk");
    let mut abort = request(2, "cancelled by host");
    abort.event.kind = EventKind::ModelResponseAborted;
    abort.event.coverage = EventCoverage::PartialObservation;
    abort.event.response_stream = Some(ResponseStream::Finished {
        response_id: response,
        chunk_count: 2,
    });
    assert_eq!(
        service
            .append_event(abort.clone())
            .expect_err("missing chunk")
            .code,
        ErrorCode::InvalidArgument
    );
    abort.event.response_stream = Some(ResponseStream::Finished {
        response_id: response,
        chunk_count: 1,
    });
    service.append_event(abort.clone()).expect("abort");
    let mut after = request(3, "late chunk");
    after.event.kind = EventKind::ModelResponseChunk;
    after.event.response_stream = Some(ResponseStream::Chunk {
        response_id: response,
        index: 1,
    });
    assert_eq!(
        service.append_event(after).expect_err("closed stream").code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        read(&service, &chunk).expect("chunk bytes").event,
        chunk.event
    );
    assert_eq!(
        read(&service, &abort).expect("abort status").event.coverage,
        EventCoverage::PartialObservation
    );
    service.verify_native(true).expect("verify");
}

#[test]
fn edits_preserve_both_originals_and_require_the_same_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let original = request(1, "code 7319");
    service.append_event(original.clone()).expect("original");
    let mut edit = request(2, "code 8426");
    edit.event.kind = EventKind::MessageEdited;
    edit.event.supersedes_event_id = Some(original.event.event_id);
    let mut wrong = edit.clone();
    wrong.event.source_id = SourceId::new();
    assert_eq!(
        service
            .append_event(wrong)
            .expect_err("foreign source")
            .code,
        ErrorCode::InvalidArgument
    );
    service.append_event(edit.clone()).expect("edit");
    assert_eq!(
        read(&service, &original).expect("original").event,
        original.event
    );
    assert_eq!(read(&service, &edit).expect("edit").event, edit.event);
}

#[test]
fn concurrent_retries_publish_one_native_frame() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = Arc::new(NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open"));
    let input = request(1, "once");
    let threads = (0..8)
        .map(|_| {
            let service = Arc::clone(&service);
            let input = input.clone();
            std::thread::spawn(move || service.append_event(input).expect("capture"))
        })
        .collect::<Vec<_>>();
    let receipts = threads
        .into_iter()
        .map(|thread| thread.join().expect("join"))
        .collect::<Vec<_>>();
    assert!(receipts.iter().all(|receipt| receipt == &receipts[0]));
    assert_eq!(service.verify_native(true).expect("verify").commit_seq, 1);
}

#[test]
fn backup_preserves_capture_closure_and_receipts_with_rotated_host_key() {
    let source = tempfile::tempdir().expect("source");
    let target = tempfile::tempdir().expect("target");
    let service = NativeService::open(source.path(), "capture-db", [7; 32]).expect("open");
    let input = request(1, "原文\nexact bytes");
    let receipt = service.append_event(input.clone()).expect("capture");
    let backup = service
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("backup");
    assert_eq!(backup.format, crate::NATIVE_CONTINUOUS_BACKUP_FORMAT);
    let restored = NativeService::open(target.path(), "capture-db", [9; 32]).expect("target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: input.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    assert_eq!(read(&restored, &input).expect("raw").event, input.event);
    assert_eq!(
        restored.append_event(input.clone()).expect("retry"),
        receipt
    );
    restored
        .resolve_capture_receipt(&input.context, &receipt)
        .expect("restored fence");
}

#[test]
fn capture_crash_child() {
    let Ok(path) = std::env::var("CONTEXTDB_CAPTURE_CRASH_PATH") else {
        return;
    };
    let service = NativeService::open(path, "capture-db", [7; 32]).expect("child open");
    service
        .append_event(request(1, "durable across abrupt exit"))
        .expect("child capture");
    panic!("crash injection did not execute");
}

#[test]
fn missing_outbox_is_detected_and_gap_budget_pauses_without_data_loss() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    for index in 1..=CAPTURE_MAX_PRODUCER_GAPS {
        service
            .append_event(request(
                u64::try_from(index).expect("ordinal") * 2,
                "bounded gaps",
            ))
            .expect("capture");
    }
    let overflow = request(
        u64::try_from(CAPTURE_MAX_PRODUCER_GAPS + 1).expect("ordinal") * 2,
        "paused until gap recovery",
    );
    assert_eq!(
        service
            .append_event(overflow.clone())
            .expect_err("pause")
            .code,
        ErrorCode::ResourceExhausted
    );
    assert!(read(&service, &overflow).is_err());
    service
        .append_event(request(1, "fill first gap"))
        .expect("recover missing original");
    let receipt = service
        .append_event(overflow.clone())
        .expect("same key after backpressure");
    service.verify_native(true).expect("coverage and rows");
    let mut transaction = service.engine.begin_write().expect("tx");
    transaction
        .delete(
            &service.keyspaces.continuous,
            work_key(
                &digest_bytes(overflow.context.request.workspace_id.as_bytes()),
                receipt.workspace_commit,
            ),
        )
        .expect("remove outbox fixture");
    transaction.commit(Durability::Sync).expect("tamper");
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("missing derived row")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn process_crash_before_and_after_sync_never_leaves_half_a_capture() {
    for stage in ["after_payload", "before_commit", "after_commit"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let status = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "capture::tests::capture_crash_child",
                "--nocapture",
            ])
            .env("CONTEXTDB_CAPTURE_CRASH_PATH", dir.path())
            .env("CONTEXTDB_CAPTURE_CRASH", stage)
            .status()
            .expect("crash subprocess");
        assert_eq!(status.code(), Some(86), "{stage}");
        let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("recover");
        let input = request(1, "durable across abrupt exit");
        let before = service.verify_native(true).expect("verify recovered");
        assert_eq!(
            before.commit_seq,
            u64::from(stage == "after_commit"),
            "{stage}"
        );
        assert_eq!(
            read(&service, &input).is_ok(),
            stage == "after_commit",
            "{stage}"
        );
        let receipt = service.append_event(input.clone()).expect("retry");
        assert_eq!(receipt.workspace_commit, 1);
        assert_eq!(
            read(&service, &input).expect("recovered original").event,
            input.event
        );
        service.verify_native(true).expect("complete closure");
    }
}
