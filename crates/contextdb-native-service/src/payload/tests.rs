use std::sync::Arc;

use contextdb_core::{ModelCallId, ModelRequestManifest};
use contextdb_service::{CapturePort, ReadOriginalRequest};

use super::*;
use crate::capture::tests::request;

fn span(event: &EventEnvelope, bytes: &[u8]) -> OriginalSourceSpan {
    OriginalSourceSpan {
        event_id: event.event_id,
        payload_digest: event.payload.digest().expect("payload digest"),
        start: 0,
        end: u64::try_from(bytes.len()).expect("length"),
        span_digest: raw_digest(bytes),
    }
}

#[test]
fn large_original_stages_before_publication_and_replays_a_small_cross_chunk_span() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let mut input = request(1, "placeholder");
    let bytes = (0..1_048_577)
        .map(|index| u8::try_from(index % 251).expect("byte"))
        .collect::<Vec<_>>();
    let staging = StagePayloadRequest {
        context: input.context.clone(),
        idempotency_key: "large-original".into(),
        block_id: ContentBlockId::new(),
        bytes: bytes.clone(),
    };
    let receipt = service.stage_payload(staging.clone()).expect("stage");
    assert_eq!(service.stage_payload(staging).expect("retry"), receipt);
    assert!(
        service
            .read_original(ReadOriginalRequest {
                context: input.context.clone(),
                event_id: input.event.event_id,
                after_receipt: None
            })
            .is_err(),
        "staging is not event publication"
    );
    input.event.payload = EventPayload::Staged {
        reference: receipt.reference,
        media_type: "application/octet-stream".into(),
    };
    service
        .append_event(input.clone())
        .expect("publish reference");
    let mut selected = span(&input.event, &bytes);
    selected.start = u64::try_from(CHUNK_BYTES - 3).expect("start");
    selected.end = u64::try_from(CHUNK_BYTES + 4).expect("end");
    selected.span_digest = raw_digest(&bytes[CHUNK_BYTES - 3..CHUNK_BYTES + 4]);
    assert_eq!(
        service
            .read_original_span(&input.context, &selected)
            .expect("range"),
        bytes[CHUNK_BYTES - 3..CHUNK_BYTES + 4]
    );
    drop(service);
    let reopened = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("reopen");
    assert_eq!(
        reopened
            .read_original_span(&input.context, &span(&input.event, &bytes))
            .expect("complete original"),
        bytes
    );
    reopened.verify_native(true).expect("closed durable chunks");
}

#[test]
fn request_manifest_replays_exact_wire_and_rejects_echo_roots_and_reordering() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let original = request(1, "Код 7319\n");
    service.append_event(original.clone()).expect("original");
    let source = original.event.payload.original_bytes().expect("source");
    let wire = [b"\x00<user>".as_slice(), source, b"</user>\r\n".as_slice()].concat();
    let manifest = ModelRequestManifest {
        model_call_id: ModelCallId::new(),
        renderer: "test-wire/v1".into(),
        wire_digest: raw_digest(&wire),
        byte_length: u64::try_from(wire.len()).expect("wire length"),
        parts: vec![
            RequestPart::Novel {
                bytes: b"\x00<user>".to_vec(),
            },
            RequestPart::Source {
                span: span(&original.event, source),
            },
            RequestPart::Novel {
                bytes: b"</user>\r\n".to_vec(),
            },
        ],
    };
    let mut occurrence = request(2, "placeholder");
    occurrence.event.kind = EventKind::ModelRequested;
    occurrence.event.payload = EventPayload::Assembly {
        manifest: manifest.clone(),
    };
    let mut reordered = occurrence.clone();
    if let EventPayload::Assembly { manifest } = &mut reordered.event.payload {
        manifest.parts.swap(0, 1);
    }
    assert_eq!(
        service
            .append_event(reordered)
            .expect_err("layout binding")
            .code,
        ErrorCode::InvalidArgument
    );
    service
        .append_event(occurrence.clone())
        .expect("request occurrence");
    assert_eq!(
        service
            .read_original_span(&occurrence.context, &span(&occurrence.event, &wire))
            .expect("wire replay"),
        wire
    );
    let mut echo = request(3, "placeholder");
    echo.event.kind = EventKind::ModelRequested;
    echo.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            parts: vec![RequestPart::Source {
                span: span(&occurrence.event, &wire),
            }],
            ..manifest
        },
    };
    assert_eq!(
        service
            .append_event(echo)
            .expect_err("echo not independent")
            .code,
        ErrorCode::InvalidArgument
    );
    service.verify_native(true).expect("wire closure");
}

#[test]
fn request_source_permission_is_checked_before_request_body_materialization() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open");
    let original = request(1, "sensitive source");
    service.append_event(original.clone()).expect("original");
    let bytes = original.event.payload.original_bytes().expect("bytes");
    let mut occurrence = request(2, "placeholder");
    occurrence.event.kind = EventKind::ModelRequested;
    occurrence.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            model_call_id: ModelCallId::new(),
            renderer: "raw/v1".into(),
            wire_digest: raw_digest(bytes),
            byte_length: u64::try_from(bytes.len()).expect("length"),
            parts: vec![RequestPart::Source {
                span: span(&original.event, bytes),
            }],
        },
    };
    service.append_event(occurrence.clone()).expect("request");
    let mut tx = service.engine.begin_write().expect("tx");
    let source_key =
        crate::digest_bytes(original.event.event_id.to_string().as_bytes()).into_bytes();
    let mut policy: crate::StoredObservationPolicy = decode(
        &tx.get(&service.keyspaces.observations_policy, &source_key)
            .expect("read")
            .expect("policy"),
        "source policy",
    )
    .expect("decode");
    policy.access.retrievable = false;
    tx.put(
        &service.keyspaces.observations_policy,
        source_key,
        encode(&policy).expect("encode"),
    )
    .expect("revoke fixture");
    tx.put(
        &service.keyspaces.observations_content,
        crate::digest_bytes(occurrence.event.event_id.to_string().as_bytes()).into_bytes(),
        b"unreadable body".to_vec(),
    )
    .expect("corrupt body fixture");
    tx.commit(Durability::Sync).expect("fixture");
    assert_eq!(
        service
            .read_original(ReadOriginalRequest {
                context: occurrence.context,
                event_id: occurrence.event.event_id,
                after_receipt: None
            })
            .expect_err("source denied before body")
            .code,
        ErrorCode::PermissionDenied
    );
}

#[test]
fn exactly_one_concurrent_caller_observes_first_publication() {
    let dir = tempfile::tempdir().expect("directory");
    let service = Arc::new(NativeService::open(dir.path(), "capture-db", [7; 32]).expect("open"));
    let threads = (0..8)
        .map(|_| {
            let service = Arc::clone(&service);
            std::thread::spawn(move || {
                service
                    .append_event_with_status(request(1, "once"))
                    .expect("append")
            })
        })
        .collect::<Vec<_>>();
    let accepted = threads
        .into_iter()
        .map(|thread| thread.join().expect("join"))
        .collect::<Vec<_>>();
    assert_eq!(
        accepted.iter().filter(|value| value.newly_accepted).count(),
        1
    );
    assert!(
        accepted
            .iter()
            .all(|value| value.receipt == accepted[0].receipt)
    );
}

#[test]
fn backup_restores_chunked_original_and_deep_verify_rejects_lost_payload() {
    use contextdb_service::{CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest};
    let source = tempfile::tempdir().expect("source");
    let target = tempfile::tempdir().expect("target");
    let owner = Arc::new(NativeService::open(source.path(), "capture-db", [7; 32]).expect("open"));
    let host = contextdb_capture::CaptureHost::new(Arc::clone(&owner));
    let input = request(1, "");
    let bytes = vec![17; CHUNK_BYTES + 97];
    let receipt = host
        .capture_bytes(
            input.clone(),
            bytes.clone(),
            "application/octet-stream".into(),
        )
        .expect("capture")
        .receipt;
    let backup = owner
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("backup");
    let restored = NativeService::open(target.path(), "capture-db", [9; 32]).expect("target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: input.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    let selected = OriginalSourceSpan {
        event_id: receipt.event_id,
        payload_digest: raw_digest(&bytes),
        start: 0,
        end: u64::try_from(bytes.len()).expect("length"),
        span_digest: raw_digest(&bytes),
    };
    assert_eq!(
        restored
            .read_original_span(&input.context, &selected)
            .expect("restored bytes"),
        bytes
    );
    let mut tx = restored.engine.begin_write().expect("tx");
    for entry in tx
        .scan_prefix(&restored.keyspaces.continuous, b"payload/")
        .expect("payload rows")
    {
        tx.delete(&restored.keyspaces.continuous, entry.key)
            .expect("remove fixture payload");
    }
    tx.commit(Durability::Sync).expect("damaged fixture");
    assert_eq!(
        restored
            .verify_native(true)
            .expect_err("missing source closure")
            .code,
        ErrorCode::IntegrityFailure
    );
}
