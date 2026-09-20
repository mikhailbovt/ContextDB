use super::*;
use crate::capture::tests::request;
use contextdb_core::{EventProvenance, EventRole, ModelCallId, ModelRequestManifest};
use contextdb_service::{
    CapturePort, CaptureRequest, CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest,
};
use std::{collections::BTreeSet, sync::Arc};

fn budget() -> contextdb_recall::QueryBudget {
    contextdb_recall::QueryBudget::new(
        1_000_000,
        256 * 1024 * 1024,
        std::time::Duration::from_secs(60),
        Default::default(),
    )
}
fn stage(
    native: &NativeService,
    source: &CaptureRequest,
    name: &str,
    bytes: Vec<u8>,
) -> (OriginalPayloadRef, StagePayloadRequest) {
    let input = StagePayloadRequest {
        context: source.context.clone(),
        idempotency_key: name.into(),
        block_id: ContentBlockId::new(),
        bytes,
    };
    (
        native
            .stage_payload(input.clone())
            .expect("stage")
            .reference,
        input,
    )
}
fn staged(sequence: u64, reference: &OriginalPayloadRef) -> CaptureRequest {
    let mut input = request(sequence, "placeholder");
    input.event.payload = EventPayload::Staged {
        reference: reference.clone(),
        media_type: "text/plain".into(),
    };
    input
}
fn prepare(
    native: &NativeService,
    source: &CaptureRequest,
    receipt: &NativeRemovalRequestReceipt,
) -> BTreeSet<contextdb_core::ObservationId> {
    let inventory = native
        .read_original_removal_inventory(&source.context, receipt, &mut budget())
        .expect("inventory");
    let ids = inventory
        .sources
        .iter()
        .map(|source| source.receipt.event_id)
        .collect();
    native
        .prepare_original_removal_sources(&source.context, receipt, &ids, &mut budget())
        .expect("prepare sources");
    native
        .maintain_custody(&source.context, 256, &mut budget())
        .expect("custody");
    native
        .project_originals(&source.context, true, 256, &mut budget())
        .expect("rebuild without sources");
    for _ in 0..10 {
        let result = native
            .reclaim_raw_generations(&source.context, 1024, &mut budget())
            .expect("reclaim index");
        if result.finished && result.retained_generations == 1 {
            break;
        }
    }
    ids
}

#[test]
fn encrypted_chunk_pruning_restarts_and_restores_while_preserving_independent_shared_blocks() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = crate::suppression::tests::authority("payload-cleanup");
    let (_keys_dir, keys) = crate::encryption::tests::authority("payload-cleanup");
    let path = root.path().join("native");
    let native = NativeService::open_encrypted(
        &path,
        "payload-cleanup",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let setup = request(1, "setup");
    let source_bytes = b"privateblockplaintextq "
        .iter()
        .copied()
        .cycle()
        .take(3 * CHUNK_BYTES + 17)
        .collect::<Vec<_>>();
    let (block, staged_input) = stage(&native, &setup, "root-block", source_bytes.clone());
    let early = staged(1, &block);
    native.append_event(early.clone()).expect("early owner");
    let keep_bytes = b"independentsharednovelz".to_vec();
    let (keep, _) = stage(&native, &setup, "shared-block", keep_bytes.clone());
    let independent = staged(2, &keep);
    native
        .append_event(independent.clone())
        .expect("independent shared owner");
    let orphan_bytes = b"requestonlynovelplaintextq".to_vec();
    let (orphan, _) = stage(&native, &setup, "request-only-block", orphan_bytes.clone());
    let mut call = request(3, "placeholder");
    call.context.capability_grants.insert(Capability::Runtime);
    call.event.role = EventRole::Host;
    call.event.kind = EventKind::ModelRequested;
    let call_id = ModelCallId::new();
    call.event.provenance = Some(EventProvenance::ModelRequest {
        model_call_id: call_id,
    });
    let wire = [
        source_bytes.as_slice(),
        keep_bytes.as_slice(),
        orphan_bytes.as_slice(),
    ]
    .concat();
    call.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            model_call_id: call_id,
            renderer: "payload-cleanup/v1".into(),
            byte_length: wire.len() as u64,
            wire_digest: raw_digest(&wire),
            parts: vec![
                RequestPart::Source {
                    span: OriginalSourceSpan {
                        event_id: early.event.event_id,
                        payload_digest: block.digest,
                        start: 0,
                        end: block.byte_length,
                        span_digest: block.digest,
                    },
                },
                RequestPart::StoredNovel {
                    payload: keep.clone(),
                },
                RequestPart::StoredNovel {
                    payload: orphan.clone(),
                },
            ],
        },
    };
    native
        .append_event(call)
        .expect("request sharing an independent block");
    let selected = staged(4, &block);
    native
        .append_event(selected.clone())
        .expect("later selected owner");
    native
        .project_originals(&selected.context, false, 256, &mut budget())
        .expect("initial index");
    let old = native
        .create_backup(CreateBackupRequest {
            context: selected.context.clone(),
        })
        .expect("old full archive");
    let removal = native
        .request_original_removal(
            &selected.context,
            &BTreeSet::from([selected.event.event_id]),
            "delete",
            &mut budget(),
        )
        .expect("request");
    let ids = prepare(&native, &selected, &removal);
    assert_eq!(
        ids.len(),
        3,
        "earlier shared owner and dependent request are selected"
    );
    assert!(
        native
            .prune_original_payload(
                &selected.context,
                &removal,
                block.block_id,
                1,
                &mut budget()
            )
            .is_err(),
        "live primary owners prevent chunk pruning"
    );
    native
        .prune_original_sources(&selected.context, &removal, &ids, &mut budget())
        .expect("primary pruning");
    assert!(
        native
            .prune_original_payload(&selected.context, &removal, keep.block_id, 1, &mut budget())
            .is_err(),
        "shared independent data was never selected"
    );
    let first = native
        .prune_original_payload(
            &selected.context,
            &removal,
            block.block_id,
            1,
            &mut budget(),
        )
        .expect("first chunk");
    assert_eq!(
        (first.removed_chunks, first.total_chunks, first.complete),
        (1, 4, false)
    );
    let partial = native
        .create_backup(CreateBackupRequest {
            context: selected.context.clone(),
        })
        .expect("partial cleanup archive");
    drop(native);
    let native = NativeService::open_encrypted(
        &path,
        "payload-cleanup",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("reopen unfinished cleanup");
    native
        .verify_native(true)
        .expect("exact missing prefix and remaining chunk suffix");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let header = native
        .payload_header(&snapshot, block.block_id)
        .expect("retained controls");
    assert!(
        snapshot
            .get(&native.keyspaces.continuous, &chunk_key(block.block_id, 0))
            .expect("removed chunk")
            .is_none()
    );
    assert!(
        snapshot
            .get(&native.keyspaces.continuous, &chunk_key(block.block_id, 1))
            .expect("remaining chunk")
            .is_some()
    );
    assert_eq!(
        native
            .payload_range(&snapshot, &header, 0, 0)
            .expect_err("even empty ranges cannot reuse a removed source")
            .code,
        ErrorCode::PermissionDenied
    );
    drop(snapshot);
    let mut last = first;
    for _ in 0..4 {
        last = native
            .prune_original_payload(
                &selected.context,
                &removal,
                block.block_id,
                1,
                &mut budget(),
            )
            .expect("resume");
        if last.complete {
            break;
        }
    }
    assert!(last.complete);
    assert_eq!(
        native
            .prune_original_payload(
                &selected.context,
                &removal,
                block.block_id,
                1,
                &mut budget()
            )
            .expect("completed retry"),
        last
    );
    assert!(
        native.stage_payload(staged_input).is_err(),
        "original retry cannot reattach a removed block"
    );
    assert!(
        native
            .prune_original_payload(
                &selected.context,
                &removal,
                orphan.block_id,
                32,
                &mut budget()
            )
            .expect("request-only novel block")
            .complete
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        native
            .payload_bytes(
                &snapshot,
                &native
                    .payload_header(&snapshot, keep.block_id)
                    .expect("keep header")
            )
            .expect("independent block"),
        keep_bytes
    );
    assert_eq!(
        native
            .load_captured_original(&snapshot, independent.event.event_id)
            .expect("independent original")
            .event,
        independent.event
    );
    for keyspace in native.keyspaces.all() {
        for row in snapshot.scan_prefix(keyspace, b"").expect("logical rows") {
            let value = String::from_utf8_lossy(&row.value);
            assert!(
                !value.contains("privateblockplaintextq")
                    && !value.contains("requestonlynovelplaintextq")
            );
        }
    }
    drop(snapshot);
    let complete = native
        .create_backup(CreateBackupRequest {
            context: selected.context.clone(),
        })
        .expect("fully pruned local archive");
    for (name, archive) in [("old", old), ("partial", partial), ("complete", complete)] {
        let restored = NativeService::open_encrypted(
            root.path().join(name),
            "payload-cleanup",
            [9; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: selected.context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("restore exact remaining rows");
        restored
            .verify_native(true)
            .expect("restored payload closure");
        if name != "old" {
            assert!(
                restored
                    .prune_original_payload(
                        &selected.context,
                        &removal,
                        block.block_id,
                        32,
                        &mut budget()
                    )
                    .expect("restored cleanup resumes")
                    .complete
            );
            restored
                .prune_original_payload(
                    &selected.context,
                    &removal,
                    orphan.block_id,
                    32,
                    &mut budget(),
                )
                .expect("restored novel cleanup");
            restored
                .verify_native(true)
                .expect("resumed archive closure");
        }
        assert_eq!(
            restored
                .read_original_span(
                    &selected.context,
                    &OriginalSourceSpan {
                        event_id: early.event.event_id,
                        payload_digest: block.digest,
                        start: 0,
                        end: 1,
                        span_digest: raw_digest(&source_bytes[..1])
                    }
                )
                .expect_err("retained authority keeps old archives closed")
                .code,
            ErrorCode::IndexTooStale
        );
    }
}

#[test]
fn chunk_cleanup_rejects_concurrent_history_marker_loss_resurrection_and_unexplained_holes() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = crate::suppression::tests::authority("payload-damage");
    let native = Arc::new(
        NativeService::open_with_suppression(root.path(), "payload-damage", [7; 32], ledger)
            .expect("native"),
    );
    let (block, _) = stage(
        &native,
        &request(1, "setup"),
        "block",
        vec![42; 2 * CHUNK_BYTES + 1],
    );
    let source = staged(1, &block);
    native.append_event(source.clone()).expect("source");
    let removal = native
        .request_original_removal(
            &source.context,
            &BTreeSet::from([source.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("request");
    let ids = prepare(&native, &source, &removal);
    native
        .prune_original_sources(&source.context, &removal, &ids, &mut budget())
        .expect("primary");
    let competing = native.clone();
    BEFORE_PUBLICATION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            competing
                .append_event(request(2, "independent append during cleanup analysis"))
                .expect("concurrent capture");
        }))
    });
    assert_eq!(
        native
            .prune_original_payload(&source.context, &removal, block.block_id, 1, &mut budget())
            .expect_err("stale analysis")
            .code,
        ErrorCode::IndexTooStale
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        native
            .payload_pruning_state(&snapshot, block.block_id)
            .expect("state")
            .is_none()
    );
    let first = snapshot
        .get(&native.keyspaces.continuous, &chunk_key(block.block_id, 0))
        .expect("first")
        .expect("present");
    let last = snapshot
        .get(&native.keyspaces.continuous, &chunk_key(block.block_id, 2))
        .expect("last")
        .expect("present");
    drop(snapshot);
    let mut empty = contextdb_recall::QueryBudget::new(
        0,
        0,
        std::time::Duration::from_secs(30),
        Default::default(),
    );
    assert!(
        native
            .prune_original_payload(&source.context, &removal, block.block_id, 1, &mut empty)
            .is_err()
    );
    native
        .prune_original_payload(&source.context, &removal, block.block_id, 1, &mut budget())
        .expect("first chunk");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let marker = snapshot
        .get(&native.keyspaces.continuous, &pruning_key(block.block_id))
        .expect("marker")
        .expect("present");
    let header_bytes = snapshot
        .get(&native.keyspaces.continuous, &header_key(block.block_id))
        .expect("header")
        .expect("present");
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.delete(&native.keyspaces.continuous, pruning_key(block.block_id))
        .expect("lose family");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .verify_native(true)
            .expect_err("undeclared missing prefix")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.continuous,
        pruning_key(block.block_id),
        marker.clone(),
    )
    .expect("repair marker");
    tx.put(
        &native.keyspaces.continuous,
        chunk_key(block.block_id, 0),
        first,
    )
    .expect("resurrect chunk");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native.verify_native(true).expect_err("resurrection").code,
        ErrorCode::IntegrityFailure
    );
    assert!(
        native
            .prune_original_payload(&source.context, &removal, block.block_id, 32, &mut budget())
            .is_err()
    );
    let mut tx = native.engine.begin_write().expect("tx");
    tx.delete(&native.keyspaces.continuous, chunk_key(block.block_id, 0))
        .expect("repair first");
    tx.delete(&native.keyspaces.continuous, chunk_key(block.block_id, 2))
        .expect("lose unpruned last chunk");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .verify_native(true)
            .expect_err("remaining suffix hole")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert!(
        native
            .prune_original_payload(&source.context, &removal, block.block_id, 32, &mut budget())
            .is_err()
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        snapshot
            .get(&native.keyspaces.continuous, &chunk_key(block.block_id, 1))
            .expect("batch rollback")
            .is_some()
    );
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.continuous,
        chunk_key(block.block_id, 2),
        last,
    )
    .expect("repair suffix");
    let mut changed: PayloadPruningState = decode(&marker, "marker").expect("marker");
    changed.through = 2;
    tx.put(
        &native.keyspaces.continuous,
        pruning_key(block.block_id),
        encode(&changed).expect("marker"),
    )
    .expect("forge progress");
    tx.commit(Durability::Sync).expect("commit");
    assert!(
        native
            .prune_original_payload(&source.context, &removal, block.block_id, 32, &mut budget())
            .is_err()
    );
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.continuous,
        pruning_key(block.block_id),
        marker,
    )
    .expect("repair marker");
    let mut header: PayloadHeader = decode(&header_bytes, "header").expect("header");
    header.access.retrievable = false;
    tx.put(
        &native.keyspaces.continuous,
        header_key(block.block_id),
        encode(&header).expect("header"),
    )
    .expect("change retained control");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .verify_native(true)
            .expect_err("changed header control")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.continuous,
        header_key(block.block_id),
        header_bytes,
    )
    .expect("repair header");
    tx.commit(Durability::Sync).expect("commit");
    assert!(
        native
            .prune_original_payload(&source.context, &removal, block.block_id, 32, &mut budget())
            .expect("finish repaired state")
            .complete
    );
    native.verify_native(true).expect("closed payload cleanup");
}

#[test]
fn empty_payload_pruning_is_a_durable_terminal_state() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = crate::suppression::tests::authority("empty-payload");
    let native =
        NativeService::open_with_suppression(root.path(), "empty-payload", [7; 32], ledger)
            .expect("native");
    let (block, _) = stage(&native, &request(1, "setup"), "empty", Vec::new());
    let source = staged(1, &block);
    native.append_event(source.clone()).expect("empty source");
    let removal = native
        .request_original_removal(
            &source.context,
            &BTreeSet::from([source.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("request");
    let ids = prepare(&native, &source, &removal);
    native
        .prune_original_sources(&source.context, &removal, &ids, &mut budget())
        .expect("primary");
    let result = native
        .prune_original_payload(&source.context, &removal, block.block_id, 1, &mut budget())
        .expect("empty block");
    assert_eq!(
        (result.removed_chunks, result.total_chunks, result.complete),
        (0, 0, true)
    );
    assert_eq!(
        native
            .prune_original_payload(&source.context, &removal, block.block_id, 32, &mut budget())
            .expect("empty retry"),
        result
    );
    native
        .verify_native(true)
        .expect("empty block is explicitly pruned");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let head = native.global_head(&snapshot).expect("head");
    let marker = snapshot
        .get(&native.keyspaces.continuous, &pruning_key(block.block_id))
        .expect("marker")
        .expect("present");
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.delete(&native.keyspaces.continuous, pruning_key(block.block_id))
        .expect("lose empty marker");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .prune_original_payload(&source.context, &removal, block.block_id, 1, &mut budget())
            .expect_err("empty marker loss cannot restart cleanup")
            .code,
        ErrorCode::IntegrityFailure
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(native.global_head(&snapshot).expect("unchanged head"), head);
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.continuous,
        pruning_key(block.block_id),
        marker,
    )
    .expect("repair empty marker");
    tx.commit(Durability::Sync).expect("commit");
    native.verify_native(true).expect("empty cleanup repaired");
}
