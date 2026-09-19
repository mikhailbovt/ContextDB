use std::collections::BTreeSet;

use contextdb_core::{
    EventCoverage, EventKind, EventPayload, EventRole, ObservationId, PayloadOmission, RawFilter,
    RawTextQuery, SessionId, SourceId, TimeRange, TimestampMicros,
};
use contextdb_service::{CaptureRequest, MaterializeOriginalRequest, RawRecallBudget};
use contextdb_storage::{Durability, WriteTransaction};

use super::*;

fn request(input: &CaptureRequest) -> RawRecallRequest {
    RawRecallRequest {
        context: input.context.clone(),
        filter: RawFilter::default(),
        text: None,
        known_at: None,
        after_receipt: None,
        page_size: 256,
        budget: RawRecallBudget::default(),
        continuation: None,
    }
}

fn collect(service: &NativeService, mut query: RawRecallRequest) -> Vec<RawRecallHit> {
    let mut result = Vec::new();
    loop {
        let page = service
            .recall_originals_oracle(query.clone())
            .expect("raw page");
        result.extend(page.hits);
        let Some(cursor) = page.continuation else {
            assert_eq!(page.status, RawPageStatus::Complete);
            return result;
        };
        query.continuation = Some(cursor);
    }
}

#[test]
fn old_exact_quotes_duplicates_and_versions_survive_reopen_without_extraction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = crate::capture::tests::request(1, "🙂 Не загружать cloud_data. Код: 7319\r\n");
    let receipt = {
        let service = NativeService::open(dir.path(), "raw-db", [7; 32]).expect("open");
        let receipt = service.append_event(first.clone()).expect("capture");
        for seq in 2..75 {
            service
                .append_event(crate::capture::tests::request(seq, "ordinary distractor"))
                .expect("distractor");
        }
        let mut duplicate =
            crate::capture::tests::request(75, "🙂 Не загружать cloud_data. Код: 7319\r\n");
        duplicate.event.source_id = SourceId::new();
        service
            .append_event(duplicate)
            .expect("separate identical occurrence");
        let mut edited = crate::capture::tests::request(76, "Новый код: 8426");
        edited.event.kind = EventKind::MessageEdited;
        edited.event.supersedes_event_id = Some(first.event.event_id);
        service.append_event(edited).expect("edit");
        receipt
    };
    let service = NativeService::open(dir.path(), "raw-db", [7; 32]).expect("reopen");
    let mut query = request(&first);
    query.text = Some(RawTextQuery::ExactPhrase("Код: 7319\r\n".into()));
    query.budget.max_records = 7;
    let hits = collect(&service, query.clone());
    assert_eq!(hits.len(), 2);
    assert_ne!(hits[0].source.event_id, hits[1].source.event_id);
    let span = &hits[0].matches[0];
    let materialized = service
        .materialize_original(MaterializeOriginalRequest {
            context: first.context.clone(),
            event_id: span.event_id,
            payload_digest: span.payload_digest,
            start: span.start,
            end: span.end,
        })
        .expect("quote");
    assert_eq!(materialized.bytes, "Код: 7319\r\n".as_bytes());
    assert_eq!(&materialized.span, span);
    query.text = None;
    query.known_at = Some(receipt.workspace_commit);
    query.after_receipt = Some(receipt);
    assert_eq!(
        collect(&service, query).len(),
        1,
        "logical history survives physical snapshot eviction and reopen"
    );
    service.verify_native(true).expect("deep");
}

#[test]
fn source_session_time_and_id_routes_preserve_omission_and_partial_status() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "raw-db", [7; 32]).expect("open");
    let session = SessionId::new();
    let mut first = crate::capture::tests::request(1, "partial quote");
    first.event.session_id = Some(session);
    first.event.recorded_at = TimestampMicros(100);
    first.event.coverage = EventCoverage::PartialObservation;
    first.event.upstream_truncated = true;
    service.append_event(first.clone()).expect("partial");
    let mut omitted = crate::capture::tests::request(2, "");
    omitted.event.recorded_at = TimestampMicros(200);
    omitted.event.session_id = Some(session);
    omitted.event.payload = EventPayload::Omitted {
        reason: PayloadOmission::LegacyMissing,
    };
    omitted.event.coverage = EventCoverage::PartialObservation;
    service
        .append_event(omitted.clone())
        .expect("explicit missing original");
    service
        .append_event(crate::capture::tests::request(3, "outside session"))
        .expect("other");
    let mut query = request(&first);
    query.filter.session_id = Some(session);
    query.filter.source_id = Some(first.event.source_id);
    query.filter.recorded_range =
        Some(TimeRange::new(TimestampMicros(100), Some(TimestampMicros(200))).expect("time"));
    let hits = collect(&service, query);
    assert_eq!(hits.len(), 1);
    assert!(hits[0].source.upstream_truncated);
    let mut query = request(&first);
    query.filter.event_ids = BTreeSet::from([omitted.event.event_id, ObservationId::new()]);
    let hits = collect(&service, query.clone());
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].source.omission,
        Some(PayloadOmission::LegacyMissing)
    );
    assert_eq!(hits[0].source.payload_digest, None);
    query.text = Some(RawTextQuery::AllTerms("partial".into()));
    assert!(collect(&service, query).is_empty());
}

#[test]
fn logical_cursor_freezes_capture_but_rechecks_current_policy_before_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "raw-db", [7; 32]).expect("open");
    let first = crate::capture::tests::request(1, "visible");
    let second = crate::capture::tests::request(2, "revoked after first page");
    service.append_event(first.clone()).expect("first");
    service.append_event(second.clone()).expect("second");
    let mut query = request(&first);
    query.page_size = 1;
    let page = service.recall_originals(query.clone()).expect("page one");
    let cursor = page.continuation.expect("continuation");
    let cursor_bytes = decode_hex(&cursor).expect("opaque ciphertext");
    assert!(
        !cursor_bytes
            .windows(b"known_at".len())
            .any(|window| window == b"known_at")
    );
    query.continuation = Some(cursor);
    let mut tampered = query.clone();
    let token = tampered.continuation.as_mut().expect("cursor");
    token.replace_range(..2, if &token[..2] == "00" { "ff" } else { "00" });
    assert_eq!(
        service
            .recall_originals(tampered)
            .expect_err("authenticated cursor")
            .code,
        ErrorCode::InvalidContinuation
    );
    service
        .append_event(crate::capture::tests::request(3, "later event"))
        .expect("later");
    let digest = digest_bytes(second.event.event_id.to_string().as_bytes());
    let mut tx = service.engine.begin_write().expect("policy transaction");
    let mut policy: crate::StoredObservationPolicy = decode(
        &tx.get(&service.keyspaces.observations_policy, digest.as_bytes())
            .expect("read")
            .expect("policy"),
        "policy",
    )
    .expect("decode");
    policy.access.retrievable = false;
    tx.put(
        &service.keyspaces.observations_policy,
        digest.as_bytes().to_vec(),
        encode(&policy).expect("encode"),
    )
    .expect("revoke");
    tx.put(
        &service.keyspaces.observations_content,
        digest.as_bytes().to_vec(),
        b"corrupt forbidden body".to_vec(),
    )
    .expect("corrupt");
    tx.commit(Durability::Sync).expect("commit");
    let page = service
        .recall_originals(query.clone())
        .expect("no forbidden body read");
    assert!(page.hits.is_empty());
    assert_eq!(page.status, RawPageStatus::Complete);
    assert_eq!(
        page.snapshot,
        service
            .recall_originals(query.clone())
            .expect("same logical view")
            .snapshot
    );
    let mut changed = query.clone();
    changed.context.request.purpose = "other".into();
    assert_eq!(
        service
            .recall_originals(changed)
            .expect_err("principal binding")
            .code,
        ErrorCode::InvalidContinuation
    );
    let mut changed = query;
    changed.filter.source_id = Some(SourceId::new());
    assert_eq!(
        service
            .recall_originals(changed)
            .expect_err("query binding")
            .code,
        ErrorCode::InvalidContinuation
    );
    assert_eq!(
        service
            .materialize_original(MaterializeOriginalRequest {
                context: second.context,
                event_id: second.event.event_id,
                payload_digest: second.event.payload.digest().expect("digest"),
                start: 0,
                end: 1,
            })
            .expect_err("revocation before corrupt body")
            .code,
        ErrorCode::PermissionDenied
    );
}

#[test]
fn work_and_byte_limits_are_explicit_and_cursor_resumes_without_losing_sources() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "raw-db", [7; 32]).expect("open");
    let first = crate::capture::tests::request(1, "small");
    service.append_event(first.clone()).expect("first");
    service
        .append_event(crate::capture::tests::request(
            2,
            "larger original with needle",
        ))
        .expect("second");
    let mut query = request(&first);
    query.text = Some(RawTextQuery::AllTerms("needle".into()));
    query.budget.max_payload_bytes = 8;
    let page = service
        .recall_originals(query.clone())
        .expect("bounded partial");
    assert!(page.hits.is_empty());
    assert_eq!(page.status, RawPageStatus::ByteLimit);
    query.continuation = page.continuation;
    assert_eq!(
        service
            .recall_originals(query.clone())
            .expect_err("one record exceeds budget")
            .code,
        ErrorCode::ResourceExhausted
    );
    query.budget.max_payload_bytes = 100;
    assert_eq!(collect(&service, query).len(), 1);
    let mut query = request(&first);
    query.budget.max_records = 1;
    let page = service.recall_originals(query).expect("one scanned record");
    assert_eq!(page.status, RawPageStatus::WorkLimit);
    assert_eq!(page.hits.len(), 1);
}

#[test]
fn request_occurrences_are_auditable_but_never_independent_evidence_roots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "raw-db", [7; 32]).expect("open");
    let first = crate::capture::tests::request(1, "same statement");
    service.append_event(first.clone()).expect("original");
    let mut echo = crate::capture::tests::request(2, "same statement");
    echo.event.kind = EventKind::ModelRequested;
    echo.event.role = EventRole::Host;
    service.append_event(echo).expect("request occurrence");
    let mut query = request(&first);
    query.text = Some(RawTextQuery::AllTerms("statement".into()));
    assert_eq!(collect(&service, query.clone()).len(), 1);
    query.filter.include_request_occurrences = true;
    let hits = collect(&service, query);
    assert_eq!(hits.len(), 2);
    assert!(!hits[1].source.independent_source);
}

#[test]
fn chunked_original_matches_and_materializes_across_a_chunk_boundary() {
    use contextdb_core::ContentBlockId;
    use contextdb_service::{PayloadPort, StagePayloadRequest};
    let dir = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(dir.path(), "raw-db", [7; 32]).expect("open");
    let mut input = crate::capture::tests::request(1, "");
    let quote = "🙂 exact cross-chunk quote";
    let mut bytes = vec![b' '; 256 * 1024 - 2];
    let start = bytes.len() as u64;
    bytes.extend_from_slice(quote.as_bytes());
    bytes.extend_from_slice(&vec![b'x'; 300_000]);
    let receipt = service
        .stage_payload(StagePayloadRequest {
            context: input.context.clone(),
            idempotency_key: "chunked-source".into(),
            block_id: ContentBlockId::new(),
            bytes,
        })
        .expect("staged");
    input.event.payload = EventPayload::Staged {
        reference: receipt.reference.clone(),
        media_type: "text/plain".into(),
    };
    service.append_event(input.clone()).expect("capture");
    let mut query = request(&input);
    query.text = Some(RawTextQuery::ExactPhrase(quote.into()));
    let hits = collect(&service, query);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].matches[0].start, start);
    let selected = service
        .materialize_original(MaterializeOriginalRequest {
            context: input.context,
            event_id: input.event.event_id,
            payload_digest: receipt.reference.digest,
            start,
            end: start + quote.len() as u64,
        })
        .expect("bounded cross-chunk read");
    assert_eq!(selected.bytes, quote.as_bytes());
    assert_eq!(selected.span, hits[0].matches[0]);
}
