use super::*;
use crate::backup::jobs::tests::{cold_owner, finish, prepared};
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::budget;
use crate::{NativeArchiveCleanup, NativeArchiveCleanupAction};
use contextdb_service::{CapturePort, CognitiveMemoryService};
use std::sync::Arc;

#[test]
fn archive_worker_seal_survives_lost_ack_and_cold_reopen_without_erasing_copy_history() {
    let (f, worker, _, original) = prepared();
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("start");
    let (_, done) = finish(&f, &worker, &f.removal, &start.receipt);
    let before = f
        .native
        .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
        .expect("copy history")
        .native_use
        .expect("tracked use");
    let native_sequence = worker.engine.head_sequence().expect("actual native head");
    // Hold a real staged writer across the seal; commit must check current authority.
    let mut staged = worker.engine.begin_write().expect("staged before seal");
    let value = staged
        .get(&worker.keyspaces.meta, META_MANIFEST_KEY)
        .expect("manifest")
        .expect("present");
    staged
        .put(&worker.keyspaces.meta, META_MANIFEST_KEY.to_vec(), value)
        .expect("staged write");
    crate::encryption::BEFORE_SEAL_SYNC.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| Err(integrity("injected before seal Sync"))))
    });
    assert!(
        worker
            .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    assert!(
        f.native
            .read_removal_backup_worker_seal(
                &f.input.context,
                &f.removal,
                &start.receipt,
                &mut budget()
            )
            .expect("no acceptance")
            .is_none()
    );
    crate::encryption::AFTER_SEAL_SYNC.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| {
            Err(integrity("injected lost seal acknowledgement"))
        }))
    });
    assert!(
        worker
            .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    let seal = worker
        .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("retry recovers accepted seal");
    assert_eq!(seal.job, done.receipt);
    assert_eq!(seal.native_sequence, native_sequence);
    assert!(staged.commit(Durability::Sync).is_err());
    assert!(worker.engine.begin_write().is_err());
    assert!(worker.engine.begin_read(SnapshotSelector::Latest).is_err());
    assert_eq!(
        worker
            .engine
            .head_sequence()
            .expect("unchanged native head"),
        native_sequence
    );
    let after = f
        .native
        .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
        .expect("retained copy obligations")
        .native_use
        .expect("tracked use");
    assert_eq!(after.addresses, before.addresses);
    assert!(after.revision > before.revision);
    let (target, _, _) = done.next_source().expect("preserved input");
    let preserved = f
        .native
        .read_removal_backup_input(
            &f.input.context,
            &f.removal,
            &target.registration,
            &mut budget(),
        )
        .expect("readable retained bytes after seal");
    assert_eq!(preserved.backup.digest, target.registration.archive_digest);
    drop(worker);
    let f = cold_owner(f);
    assert_eq!(
        f.native
            .read_removal_backup_worker_seal(
                &f.input.context,
                &f.removal,
                &start.receipt,
                &mut budget()
            )
            .expect("cold receipt"),
        Some(seal.clone())
    );
    assert!(f.root.path().join("worker").is_dir());
    assert!(
        NativeService::open_encrypted(
            f.root.path().join("worker"),
            "primary-decisions",
            [7; 32],
            f.ledger.clone(),
            f.keys.clone()
        )
        .is_err()
    );
    f.native
        .append_event(request(3, "independent primary remains writable"))
        .expect("other instance unaffected");
    let next = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "later-after-seal",
            &mut budget(),
        )
        .expect("later request");
    let root = f.root.path().join("managed");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    assert!(
        matches!(executor.advance(&f.input.context, &next, &mut budget()).expect("explicit sealed obligation").action,
        Some(NativeArchiveCleanupAction::WorkerSealed { seal: current, .. }) if current == seal)
    );
    assert!(
        !root.exists(),
        "sealed history cannot bootstrap another worker"
    );
}

#[test]
fn archive_worker_seal_requires_current_authority_latest_completion_and_unchanged_bytes() {
    let (f, worker, _, original) = prepared();
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("start");
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        worker
            .seal_removal_backup_worker(&denied, &f.removal, &start.receipt, &mut budget())
            .expect_err("Admin required")
            .code,
        ErrorCode::Unauthorized
    );
    let mut wrong_scope = f.input.context.clone();
    wrong_scope.request.workspace_id = "another-workspace".into();
    assert!(
        worker
            .seal_removal_backup_worker(&wrong_scope, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    let mut zero = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert_eq!(
        worker
            .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut zero)
            .expect_err("bounded")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert!(
        worker
            .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    let (_, done) = finish(&f, &worker, &f.removal, &start.receipt);
    assert!(
        f.native
            .seal_removal_backup_worker(&f.input.context, &f.removal, &done.receipt, &mut budget())
            .is_err(),
        "primary cannot seal a different instance"
    );
    let next = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "newer-running",
            &mut budget(),
        )
        .expect("next request");
    let started = worker
        .start_removal_backup_job(&f.input.context, &next, &original, &mut budget())
        .expect("newer job");
    assert!(
        worker
            .seal_removal_backup_worker(&f.input.context, &f.removal, &done.receipt, &mut budget())
            .is_err(),
        "old terminal job cannot seal a newer active worker"
    );
    let (_, done) = finish(&f, &worker, &next, &started.receipt);
    worker
        .append_event(request(3, "new independent data after cleanup"))
        .expect("actual later write");
    assert!(
        worker
            .seal_removal_backup_worker(&f.input.context, &next, &done.receipt, &mut budget())
            .is_err()
    );
    assert!(
        worker
            .read_removal_backup_worker_seal(&f.input.context, &next, &done.receipt, &mut budget())
            .expect("still live")
            .is_none()
    );
    worker
        .verify_native(true)
        .expect("later independent data retained");
}

#[test]
fn archive_worker_seal_rechecks_native_and_preservation_publication_frontiers() {
    let (f, worker, _, original) = prepared();
    let worker = Arc::new(worker);
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("start");
    finish(&f, &worker, &f.removal, &start.receipt);
    let primary = f.native.clone();
    let context = f.input.context.clone();
    BEFORE_WORKER_SEAL.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            primary.append_event(request(3, "concurrent primary publication"))?;
            primary.create_backup(CreateBackupRequest { context })?;
            Ok(())
        }))
    });
    assert_eq!(
        worker
            .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .expect_err("archive frontier changed")
            .code,
        ErrorCode::IndexTooStale
    );
    let racing = worker.clone();
    BEFORE_WORKER_SEAL.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            // Empty physical commit changes the native-use marker, without changing
            // the previously verified logical archive or its encrypted values.
            let tx = racing.engine.begin_write().map_err(storage_error)?;
            tx.commit(Durability::Sync).map_err(storage_error)?;
            Ok(())
        }))
    });
    assert_eq!(
        worker
            .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .expect_err("native frontier changed")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert!(
        worker
            .read_removal_backup_worker_seal(
                &f.input.context,
                &f.removal,
                &start.receipt,
                &mut budget()
            )
            .expect("neither race seals")
            .is_none()
    );
    worker
        .seal_removal_backup_worker(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("fresh retry");
}
