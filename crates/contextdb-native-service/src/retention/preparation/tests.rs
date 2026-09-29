use super::*;
use crate::capture::tests::request;
use contextdb_service::{CapturePort, ReadOriginalRequest};
use std::{sync::Arc, time::Duration};

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

#[test]
fn prepared_controls_reopen_and_restore_without_erasing_originals_or_opening_disclosure() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = suppression::tests::authority("prepared");
    let (_keys_dir, keys) = encryption::tests::authority("prepared");
    let path = root.path().join("native");
    let service =
        NativeService::open_encrypted(&path, "prepared", [7; 32], ledger.clone(), keys.clone())
            .expect("native");
    let source = request(1, "erase only after dependent copies are pruned");
    let mut child = request(2, "dependent revision");
    child.event.supersedes_event_id = Some(source.event.event_id);
    let independent = request(3, "independent original remains useful");
    for input in [&source, &child, &independent] {
        service.append_event(input.clone()).expect("capture");
    }
    let removal = service
        .request_original_removal(
            &source.context,
            &BTreeSet::from([source.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("removal");
    let sources = BTreeSet::from([source.event.event_id, child.event.event_id]);
    let prepared = service
        .prepare_original_removal_sources(&source.context, &removal, &sources, &mut budget())
        .expect("prepare");
    assert_eq!(prepared.workspace_commit, 6); // Two native revocations, then preparation.
    assert_eq!(
        service
            .prepare_original_removal_sources(&source.context, &removal, &sources, &mut budget())
            .expect("exact retry"),
        prepared
    );
    service
        .verify_native(true)
        .expect("complete original/control closure");
    let archive = service
        .create_backup(CreateBackupRequest {
            context: source.context.clone(),
        })
        .expect("prepared archive");
    drop(service);
    let reopened =
        NativeService::open_encrypted(&path, "prepared", [8; 32], ledger.clone(), keys.clone())
            .expect("reopen");
    let restored = NativeService::open_encrypted(
        root.path().join("restore"),
        "prepared",
        [9; 32],
        ledger,
        keys,
    )
    .expect("target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: source.context.clone(),
            format: archive.format,
            bytes: archive.bytes,
            digest: archive.digest,
        })
        .expect("restore");
    for native in [&reopened, &restored] {
        let snapshot = native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        for input in [&source, &child, &independent] {
            assert_eq!(
                native
                    .load_captured_original(&snapshot, input.event.event_id)
                    .expect("still retained exact body")
                    .event,
                input.event
            );
        }
        assert_eq!(
            native
                .prepare_original_removal_sources(
                    &source.context,
                    &removal,
                    &sources,
                    &mut budget()
                )
                .expect("restored retry"),
            prepared
        );
        native.verify_native(true).expect("restored controls");
        assert_eq!(
            native
                .read_original(ReadOriginalRequest {
                    context: source.context.clone(),
                    event_id: source.event.event_id,
                    after_receipt: None
                })
                .expect_err("preparation is not completion")
                .code,
            ErrorCode::IndexTooStale
        );
        assert_eq!(
            native
                .prepare_original_removal_sources(
                    &source.context,
                    &removal,
                    &BTreeSet::from([independent.event.event_id]),
                    &mut budget()
                )
                .expect_err("independent source is outside the accepted request")
                .code,
            ErrorCode::IntegrityFailure
        );
    }
}

#[test]
fn preparation_rejects_a_changed_retry_control_and_missing_native_markers() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = suppression::tests::authority("control-damage");
    let native =
        NativeService::open_with_suppression(root.path(), "control-damage", [7; 32], ledger)
            .expect("native");
    let input = request(1, "control commitment must cover the whole capture record");
    native.append_event(input.clone()).expect("capture");
    let sources = BTreeSet::from([input.event.event_id]);
    let removal = native
        .request_original_removal(&input.context, &sources, "remove", &mut budget())
        .expect("removal");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let key = format!("receipt/{}", input.event.event_id).into_bytes();
    let original = snapshot
        .get(&native.keyspaces.continuous, &key)
        .expect("read")
        .expect("record");
    let modified: serde_json::Value = decode(&original, "fixture").expect("record JSON");
    let old_retry = modified["idempotency_digest"].as_str().expect("retry");
    let retry_bytes = snapshot
        .get(&native.keyspaces.idempotency, old_retry.as_bytes())
        .expect("read")
        .expect("retry");
    let alternate = digest_bytes(b"alternate-valid-retry-with-the-same-response");
    let modified = String::from_utf8(original.clone())
        .expect("JSON")
        .replace(old_retry, &alternate);
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.continuous,
        key.clone(),
        modified.into_bytes(),
    )
    .expect("modify control");
    tx.put(
        &native.keyspaces.idempotency,
        alternate.clone().into_bytes(),
        retry_bytes,
    )
    .expect("copy exact retry");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .prepare_original_removal_sources(&input.context, &removal, &sources, &mut budget())
            .expect_err("same receipt is insufficient for a changed control record")
            .code,
        ErrorCode::IntegrityFailure
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        snapshot
            .scan_prefix(&native.keyspaces.continuous, b"removal/")
            .expect("markers")
            .is_empty()
    );
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(&native.keyspaces.continuous, key, original)
        .expect("repair fixture");
    tx.delete(&native.keyspaces.idempotency, alternate.into_bytes())
        .expect("repair fixture");
    tx.commit(Durability::Sync).expect("repair");
    native
        .prepare_original_removal_sources(&input.context, &removal, &sources, &mut budget())
        .expect("prepare repaired source");
    native.verify_native(true).expect("valid preparation");
    let mut tx = native.engine.begin_write().expect("tx");
    tx.delete(
        &native.keyspaces.continuous,
        prepared_key(input.event.event_id),
    )
    .expect("lose entire marker family");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .verify_native(true)
            .expect_err("native journal detects marker loss")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn preparation_rechecks_the_workspace_after_analysis_and_writes_no_partial_batch() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = suppression::tests::authority("prepare-race");
    let native = Arc::new(
        NativeService::open_with_suppression(root.path(), "prepare-race", [7; 32], ledger)
            .expect("native"),
    );
    let input = request(1, "source");
    native.append_event(input.clone()).expect("capture");
    let sources = BTreeSet::from([input.event.event_id]);
    let removal = native
        .request_original_removal(&input.context, &sources, "remove", &mut budget())
        .expect("removal");
    let concurrent = native.clone();
    BEFORE_PUBLICATION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            concurrent
                .append_event(request(2, "independent capture during analysis"))
                .expect("concurrent capture");
        }))
    });
    assert_eq!(
        native
            .prepare_original_removal_sources(&input.context, &removal, &sources, &mut budget())
            .expect_err("workspace compare")
            .code,
        ErrorCode::IndexTooStale
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        snapshot
            .scan_prefix(&native.keyspaces.continuous, b"removal/")
            .expect("markers")
            .is_empty()
    );
    drop(snapshot);
    native
        .prepare_original_removal_sources(&input.context, &removal, &sources, &mut budget())
        .expect("retry current prefix");
    native
        .verify_native(true)
        .expect("concurrent retry closure");
}

#[test]
fn rebuilt_and_reclaimed_indexes_remove_prepared_sources_but_preserve_independent_terms() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = suppression::tests::authority("index-removal");
    let (_keys_dir, keys) = encryption::tests::authority("index-removal");
    let path = root.path().join("native");
    let native = NativeService::open_encrypted(
        &path,
        "index-removal",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let first = request(1, "sensitivelexicaltermx");
    let mut child = request(2, "sensitivelexicaltermy");
    child.event.supersedes_event_id = Some(first.event.event_id);
    let independent = request(3, "independentlexicaltermz");
    for input in [&first, &child, &independent] {
        native.append_event(input.clone()).expect("capture");
    }
    assert!(
        native
            .project_originals(&first.context, false, 256, &mut budget())
            .expect("old index")
            .caught_up
    );
    let old = native
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("archive with all terms");
    let request = native
        .request_original_removal(
            &first.context,
            &BTreeSet::from([first.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("request");
    let targets = BTreeSet::from([first.event.event_id, child.event.event_id]);
    native
        .prepare_original_removal_sources(&first.context, &request, &targets, &mut budget())
        .expect("prepare");
    assert!(
        native
            .maintain_custody(&first.context, 256, &mut budget())
            .expect("propagate denial")
            .caught_up
    );
    // Omission must still verify the outbox; otherwise a prepared ID could hide
    // corruption while advancing a generation over an unverified capture prefix.
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let head = native.global_head(&snapshot).expect("head");
    let work_key = capture::work_key(
        &digest_bytes(first.context.request.workspace_id.as_bytes()),
        1,
    );
    let saved_work = snapshot
        .get(&native.keyspaces.continuous, &work_key)
        .expect("outbox")
        .expect("present");
    let mut corrupt: capture::CaptureWork = decode(&saved_work, "fixture work").expect("work");
    corrupt.event_digest = ContentDigest::from_bytes([57; 32]);
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(
        &native.keyspaces.continuous,
        work_key.clone(),
        encode(&corrupt).expect("work"),
    )
    .expect("corrupt outbox");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        native
            .project_originals(&first.context, true, 1, &mut budget())
            .expect_err("prepared source still needs accepted outbox identity")
            .code,
        ErrorCode::IntegrityFailure
    );
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        native
            .global_head(&snapshot)
            .expect("no partial publication"),
        head
    );
    drop(snapshot);
    let mut tx = native.engine.begin_write().expect("tx");
    tx.put(&native.keyspaces.continuous, work_key, saved_work)
        .expect("repair fixture");
    tx.commit(Durability::Sync).expect("repair");
    let mut projection = native
        .project_originals(&first.context, true, 1, &mut budget())
        .expect("start rebuild");
    assert_eq!(projection.projected_sources, 0);
    while !projection.caught_up {
        projection = native
            .project_originals(&first.context, false, 1, &mut budget())
            .expect("bounded rebuild");
    }
    assert_eq!(projection.projected_sources, 1);
    native
        .verify_native(true)
        .expect("old and new generations before reclamation");
    let first_page = native
        .reclaim_raw_generations(&first.context, 2, &mut budget())
        .expect("start old-copy reclamation");
    assert!(!first_page.finished);
    drop(native);
    let reopened = NativeService::open_encrypted(
        &path,
        "index-removal",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("reopen mid-reclamation");
    for _ in 0..100 {
        let progress = reopened
            .reclaim_raw_generations(&first.context, 2, &mut budget())
            .expect("continue reclamation");
        if progress.retained_generations == 1 && progress.finished {
            break;
        }
    }
    let snapshot = reopened
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let rows = snapshot
        .scan_prefix(&reopened.keyspaces.continuous, b"raw/g/")
        .expect("remaining index rows");
    assert!(!rows.is_empty());
    let bytes = rows
        .iter()
        .flat_map(|row| row.value.iter().copied())
        .collect::<Vec<_>>();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("sensitivelexicaltermx"));
    assert!(!text.contains("sensitivelexicaltermy"));
    assert!(text.contains("independentlexicaltermz"));
    assert!(
        reopened
            .load_captured_original(&snapshot, first.event.event_id)
            .is_ok(),
        "this stage removes index copies only"
    );
    drop(snapshot);
    reopened
        .verify_native(true)
        .expect("reclaimed index closure");
    reopened
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("archive after index cleanup");
    let restored = NativeService::open_encrypted(
        root.path().join("restore"),
        "index-removal",
        [9; 32],
        ledger,
        keys,
    )
    .expect("restore target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: first.context.clone(),
            format: old.format,
            bytes: old.bytes,
            digest: old.digest,
        })
        .expect("older archive");
    assert_eq!(
        restored
            .read_original(ReadOriginalRequest {
                context: first.context.clone(),
                event_id: first.event.event_id,
                after_receipt: None
            })
            .expect_err("old index cannot reopen disclosure")
            .code,
        ErrorCode::IndexTooStale
    );
    restored
        .prepare_original_removal_sources(&first.context, &request, &targets, &mut budget())
        .expect("reconcile preparation again");
    restored
        .verify_native(true)
        .expect("old copy remains closed and prepared for cleanup");
}
