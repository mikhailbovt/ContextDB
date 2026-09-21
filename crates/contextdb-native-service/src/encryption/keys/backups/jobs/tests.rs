use super::*;
use crate::backup::jobs::tests::{cold, finish, prepared};
use crate::retention::keys::witness::tests::budget;

#[test]
fn archive_job_start_and_finish_sync_uncertainty_reuses_exact_acceptance() {
    let (f, worker, _, original) = prepared();
    let before = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("initial frontier");
    for after in [false, true] {
        let hook: Box<dyn FnOnce() -> ServiceResult<()>> =
            Box::new(|| Err(integrity("injected job Sync uncertainty")));
        if after {
            publication::AFTER_JOB_SYNC.with(|slot| *slot.borrow_mut() = Some(hook));
        } else {
            publication::BEFORE_JOB_SYNC.with(|slot| *slot.borrow_mut() = Some(hook));
        }
        assert!(
            worker
                .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
                .is_err()
        );
        let view = f
            .keys
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("view");
        assert_eq!(
            f.keys.backup_head(&view).expect("head").jobs.is_some(),
            after
        );
        f.keys
            .verify_backup_catalog(&view)
            .expect("closure after uncertainty");
    }
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("recover start");
    assert_eq!(start.receipt.sequence, 1);
    assert_eq!(
        f.keys
            .require_backup_frontier(&before.frontier, &mut budget())
            .expect_err("job publication changes frontier")
            .code,
        ErrorCode::IndexTooStale
    );
    publication::BEFORE_JOB_SYNC.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|| {
            Err(integrity("injected import acknowledgement failure"))
        }))
    });
    assert!(
        worker
            .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    assert!(
        !worker
            .read_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .expect("unacknowledged import")
            .initialized
    );
    let imported_head = worker.engine.head_sequence().expect("imported head");
    let (f, worker) = cold(f, worker);
    let imported = worker
        .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("verify actual prior import");
    assert!(imported.job.initialized);
    assert_eq!(
        worker.engine.head_sequence().expect("no repeated import"),
        imported_head
    );
    publication::AFTER_JOB_SYNC.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|| {
            Err(integrity("injected terminal lost response"))
        }))
    });
    for _ in 0..32 {
        let result = worker.advance_removal_backup_job(
            &f.input.context,
            &f.removal,
            &start.receipt,
            &mut budget(),
        );
        if let Err(error) = result {
            assert!(error.message.contains("injected"));
            break;
        }
    }
    let done = worker
        .read_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("recover finish");
    assert!(done.terminal.is_some());
    assert_eq!(done.receipt.sequence, 3);
    let head = f.keys.engine.head_sequence().expect("custody head");
    let (_, repeated) = finish(&f, &worker, &f.removal, &start.receipt);
    assert_eq!(repeated, done);
    assert_eq!(
        f.keys.engine.head_sequence().expect("no new custody event"),
        head
    );
}

#[test]
fn archive_job_catalog_rejects_missing_extra_and_rehashed_controls() {
    let (f, worker, _, original) = prepared();
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("start");
    let (_, done) = finish(&f, &worker, &f.removal, &start.receipt);
    let keys = &f.keys;
    let snapshot = keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    let rows = snapshot
        .scan_prefix(&keys.rows, b"backup/job/")
        .expect("controls");
    drop(snapshot);
    for row in &rows {
        let mut tx = keys.engine.begin_write().expect("tx");
        tx.delete(&keys.rows, row.key.clone()).expect("omit");
        assert!(
            keys.selected_backup_keys_at(&tx, &BTreeMap::new(), &mut budget())
                .is_err(),
            "missing {:?}",
            row.key
        );
        assert!(keys.verify_backup_catalog(&tx).is_err());
    }
    let mut tx = keys.engine.begin_write().expect("tx");
    tx.put(&keys.rows, b"backup/job/extra".to_vec(), vec![1])
        .expect("extra");
    assert!(
        keys.selected_backup_keys_at(&tx, &BTreeMap::new(), &mut budget())
            .is_err()
    );
    drop(tx);
    // Rehash and reseal a changed terminal binding, including indexes and head.
    // The immutable start still prevents replacing its registered worker.
    let mut tx = keys.engine.begin_write().expect("tx");
    let key = event_key(done.receipt.sequence);
    let mut event: JobEvent = keys
        .read_job_record(&tx, &key, &mut budget())
        .expect("event");
    event.value.binding.worker_instance = f
        .native
        .engine
        .registered_instance()
        .expect("different registered owner");
    event.value.receipt.digest = event.commitment().expect("rehash");
    let mut head = keys.backup_head(&tx).expect("head");
    head.jobs = Some(event.value.receipt.clone());
    for (key, bytes) in [
        (
            key.clone(),
            keys.seal_backup_record(&key, &event).expect("seal"),
        ),
        (
            HEAD.to_vec(),
            keys.seal_backup_record(HEAD, &head).expect("seal"),
        ),
        (
            job_key(&event.value.binding),
            keys.seal_backup_record(&job_key(&event.value.binding), &event.value.receipt)
                .expect("seal"),
        ),
        (
            original_key(&original.archive_digest),
            keys.seal_backup_record(
                &original_key(&original.archive_digest),
                &event.value.receipt,
            )
            .expect("seal"),
        ),
    ] {
        tx.put(&keys.rows, key, bytes).expect("alter");
    }
    assert!(
        keys.selected_backup_keys_at(&tx, &BTreeMap::new(), &mut budget())
            .is_err()
    );
    assert!(keys.verify_backup_catalog(&tx).is_err());
}
