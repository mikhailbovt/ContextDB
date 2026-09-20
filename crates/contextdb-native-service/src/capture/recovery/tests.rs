use contextdb_core::{ContentBlockId, ModelCallId, ModelRequestManifest, OriginalSourceSpan};
use contextdb_service::{
    CognitiveMemoryService, CreateBackupRequest, PayloadPort, RestoreBackupRequest,
    StagePayloadRequest,
};

use super::*;
use crate::capture::tests::request;

fn record(service: &NativeService, event: ObservationId) -> CaptureRecord {
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    read_required(&snapshot, service, &record_key(event)).expect("capture record")
}

#[test]
fn encrypted_witnesses_preserve_inputs_without_copying_originals_and_restore_exactly() {
    let dir = tempfile::tempdir().expect("directory");
    let (_keys_dir, keys) = crate::encryption::tests::authority("recovery");
    let (_ledger_dir, ledger) = crate::suppression::tests::authority("recovery");
    let service = NativeService::open_encrypted(
        dir.path().join("source"),
        "recovery",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("open");
    let mut original = request(1, "original_sentinel_74819\r\nШутку сохраняем дословно.\0");
    original.event.adapter_id = "adapter_sentinel_87143".into();
    original.event.source_version = Some("version_sentinel_87284".into());
    let receipt = service.append_event(original.clone()).expect("original");
    let bytes = original.event.payload.original_bytes().expect("bytes");
    let payload = service
        .stage_payload(StagePayloadRequest {
            context: original.context.clone(),
            idempotency_key: "stored-novel".into(),
            block_id: ContentBlockId::new(),
            bytes: b"staged_sentinel_79426".to_vec(),
        })
        .expect("stage")
        .reference;
    let mut staged = request(2, "placeholder");
    staged.event.payload = EventPayload::Staged {
        reference: payload.clone(),
        media_type: "application/media_sentinel_83124".into(),
    };
    service
        .append_event(staged.clone())
        .expect("shared staged owner");
    let wire = [bytes, b"novel_sentinel_64218", b"staged_sentinel_79426"].concat();
    let mut assembly = request(3, "placeholder");
    assembly.event.kind = EventKind::ModelRequested;
    assembly.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            model_call_id: ModelCallId::new(),
            renderer: "renderer_sentinel_79210".into(),
            wire_digest: digest(&wire),
            byte_length: wire.len() as u64,
            parts: vec![
                RequestPart::Source {
                    span: OriginalSourceSpan {
                        event_id: original.event.event_id,
                        payload_digest: digest(bytes),
                        start: 0,
                        end: bytes.len() as u64,
                        span_digest: digest(bytes),
                    },
                },
                RequestPart::Novel {
                    bytes: b"novel_sentinel_64218".to_vec(),
                },
                RequestPart::StoredNovel {
                    payload: payload.clone(),
                },
            ],
        },
    };
    service.append_event(assembly.clone()).expect("request");
    let mut partial = request(4, "partial_sentinel_62031");
    partial.event.coverage = EventCoverage::PartialObservation;
    partial.event.upstream_truncated = true;
    partial.event.gap_reason = Some("gap_sentinel_94571".into());
    service
        .append_event(partial.clone())
        .expect("partial observation");

    let records = [&original, &staged, &assembly, &partial].map(|input| {
        let record = record(&service, input.event.event_id);
        let metadata = record.recovery.as_ref().expect("mandatory witness");
        let encoded = String::from_utf8(encode(metadata).expect("metadata")).expect("JSON");
        assert!(
            !encoded.contains("sentinel"),
            "no arbitrary content in witness"
        );
        record
    });
    // Shared staged ownership and exact source inputs survive the compact form.
    let inputs = serde_json::to_value(&records[2].recovery.as_ref().expect("recovery").inputs)
        .expect("input graph");
    assert_eq!(
        inputs["sources"],
        serde_json::json!([original.event.event_id])
    );
    assert_eq!(inputs["payloads"], serde_json::json!([payload]));
    assert_eq!(records[0].receipt, receipt);
    let before = service.verify_native(true).expect("live closure");
    let backup = service
        .create_backup(CreateBackupRequest {
            context: original.context.clone(),
        })
        .expect("verified encrypted backup");
    drop(service);
    let reopened = NativeService::open_encrypted(
        dir.path().join("source"),
        "recovery",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("reopen with rotated token key");
    assert_eq!(record(&reopened, original.event.event_id), records[0]);
    let restored = NativeService::open_encrypted(
        dir.path().join("restored"),
        "recovery",
        [9; 32],
        ledger,
        keys,
    )
    .expect("restore target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: original.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    for (input, expected) in [&original, &staged, &assembly, &partial]
        .into_iter()
        .zip(records)
    {
        assert_eq!(record(&restored, input.event.event_id), expected);
        let raw = restored
            .read_original(ReadOriginalRequest {
                context: input.context.clone(),
                event_id: input.event.event_id,
                after_receipt: None,
            })
            .expect("exact original");
        assert_eq!(raw.event, input.event);
        assert_eq!(raw.receipt, expected.receipt);
    }
    assert_eq!(
        restored
            .verify_native(true)
            .expect("restored closure")
            .archive_digest,
        before.archive_digest
    );
}

#[test]
fn recovery_loss_tampering_and_missing_original_cannot_be_accepted_as_legacy() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "recovery", [7; 32]).expect("open");
    let input = request(1, "an accepted original is still mandatory");
    service.append_event(input.clone()).expect("capture");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let original = record(&service, input.event.event_id);
    let workspace = digest_bytes(input.context.request.workspace_id.as_bytes());
    let capture_key = record_key(input.event.event_id);
    let outbox_key = work_key(&workspace, original.receipt.workspace_commit);
    for damage in [
        "metadata",
        "metadata-loss",
        "activation-loss",
        "outbox",
        "journal",
        "body",
    ] {
        let (space, key, replacement) = match damage {
            "metadata" | "metadata-loss" => {
                let mut changed = original.clone();
                if damage == "metadata" {
                    changed
                        .recovery
                        .as_mut()
                        .expect("metadata")
                        .scope_ids
                        .clear();
                } else {
                    changed.recovery = None;
                }
                (
                    &service.keyspaces.continuous,
                    capture_key.clone(),
                    Some(encode(&changed).expect("encode")),
                )
            }
            "activation-loss" => (&service.keyspaces.continuous, ACTIVATED.to_vec(), None),
            "outbox" => {
                let mut changed = original.work().expect("work");
                changed.recovery_digest = Some(digest(b"different witness"));
                (
                    &service.keyspaces.continuous,
                    outbox_key.clone(),
                    Some(encode(&changed).expect("encode")),
                )
            }
            "journal" => {
                let key = 1_u64.to_be_bytes().to_vec();
                let mut changed: crate::StoredEvent = decode(
                    &snapshot
                        .get(&service.keyspaces.events, &key)
                        .expect("journal")
                        .expect("present"),
                    "journal",
                )
                .expect("decode");
                changed
                    .accepted_original
                    .as_mut()
                    .expect("capture")
                    .recovery_digest = None;
                (
                    &service.keyspaces.events,
                    key,
                    Some(encode(&changed).expect("encode")),
                )
            }
            _ => (
                &service.keyspaces.observations_content,
                digest_bytes(input.event.event_id.to_string().as_bytes()).into_bytes(),
                None,
            ),
        };
        let saved = snapshot
            .get(space, &key)
            .expect("saved row")
            .expect("present");
        let mut tx = service.engine.begin_write().expect("write");
        match replacement {
            Some(value) => tx.put(space, key.clone(), value).expect("corrupt"),
            None => tx.delete(space, key.clone()).expect("remove"),
        }
        tx.commit(Durability::Sync).expect("damage commit");
        assert_eq!(
            service.verify_native(true).expect_err(damage).code,
            ErrorCode::IntegrityFailure,
            "{damage}"
        );
        let mut tx = service.engine.begin_write().expect("repair");
        tx.put(space, key, saved).expect("restore row");
        tx.commit(Durability::Sync).expect("repair commit");
    }
    service
        .verify_native(true)
        .expect("all fixture damage repaired");
}

#[test]
fn legacy_prefix_remains_readable_but_new_captures_require_bound_metadata() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "recovery", [7; 32]).expect("open");
    let input = request(1, "before recovery format activation");
    let receipt = service.append_event(input.clone()).expect("capture");
    let mut legacy = record(&service, input.event.event_id);
    legacy.recovery = None;
    let mut tx = service.engine.begin_write().expect("write legacy fixture");
    tx.put(
        &service.keyspaces.continuous,
        record_key(input.event.event_id),
        encode(&legacy).expect("legacy capture"),
    )
    .expect("put");
    tx.put(
        &service.keyspaces.continuous,
        work_key(
            &digest_bytes(input.context.request.workspace_id.as_bytes()),
            1,
        ),
        encode(&legacy.work().expect("work")).expect("legacy outbox"),
    )
    .expect("put");
    tx.delete(&service.keyspaces.continuous, ACTIVATED.to_vec())
        .expect("remove activation");
    let mut manifest: Manifest = decode(
        &tx.get(&service.keyspaces.meta, META_MANIFEST_KEY)
            .expect("manifest")
            .expect("present"),
        "manifest",
    )
    .expect("decode");
    manifest.features.remove(RECOVERY_FEATURE);
    manifest.checksum = manifest_checksum(&manifest).expect("checksum");
    tx.put(
        &service.keyspaces.meta,
        META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest"),
    )
    .expect("put");
    // Produce the exact pre-extension journal representation and its valid head.
    let mut journal: crate::StoredEvent = decode(
        &tx.get(&service.keyspaces.events, &1_u64.to_be_bytes())
            .expect("journal")
            .expect("present"),
        "journal",
    )
    .expect("decode");
    journal.accepted_original = Some(legacy.work().expect("work"));
    journal.event_digest = crate::event_digest(&journal).expect("journal digest");
    tx.put(
        &service.keyspaces.events,
        1_u64.to_be_bytes().to_vec(),
        encode(&journal).expect("journal"),
    )
    .expect("put");
    tx.put(
        &service.keyspaces.meta,
        crate::META_EVENT_DIGEST_KEY.to_vec(),
        journal.event_digest.into_bytes(),
    )
    .expect("head");
    tx.commit(Durability::Sync).expect("legacy fixture");
    service.verify_native(true).expect("legacy history");
    assert_eq!(
        service.append_event(input.clone()).expect("legacy retry"),
        receipt
    );
    let next = request(2, "after activation");
    service
        .append_event(next.clone())
        .expect("activate on next capture");
    drop(service);
    let service = NativeService::open(dir.path(), "recovery", [8; 32]).expect("reopen");
    service.verify_native(true).expect("mixed format history");
    assert!(record(&service, input.event.event_id).recovery.is_none());
    assert!(record(&service, next.event.event_id).recovery.is_some());
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        service
            .verify_capture_recovery_format(&snapshot)
            .expect("activation"),
        Some(2)
    );
    assert_eq!(
        service
            .load_captured_original(&snapshot, input.event.event_id)
            .expect("legacy bytes")
            .event,
        input.event
    );
    assert_eq!(
        service
            .load_captured_original(&snapshot, next.event.event_id)
            .expect("new bytes")
            .event,
        next.event
    );
    let mut budget = contextdb_recall::QueryBudget::new(
        100_000,
        32 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        Default::default(),
    );
    assert_eq!(
        service
            .inspect_original_deletion(
                &input.context,
                &BTreeSet::from([input.event.event_id]),
                &mut budget
            )
            .expect_err("legacy source needs explicit recovery migration")
            .code,
        ErrorCode::FormatIncompatible
    );
    let current = service
        .inspect_original_deletion(
            &next.context,
            &BTreeSet::from([next.event.event_id]),
            &mut budget,
        )
        .expect("independent new source");
    assert_eq!(current.sources.len(), 1);
    assert_eq!(current.sources[0].receipt.event_id, next.event.event_id);
}
