use super::*;

#[test]
fn archive_maintenance_resumes_retained_worker_disposal_after_restart_with_fresh_authority() {
    let f = fixture();
    let original = issued(&f, true);
    let root = f.root.path().join("workers");
    let source = root
        .join(f.keys.authority_id().to_string())
        .join(&original.digest);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    executor::tests::finish(&f, &mut executor, &f.removal);
    drop(executor);
    let job = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("jobs")
        .jobs
        .pop()
        .expect("terminal");
    let worker = NativeService::open_encrypted(
        &source,
        "primary-decisions",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("same worker");
    worker
        .seal_removal_backup_worker(&f.input.context, &f.removal, &job.receipt, &mut budget())
        .expect("seal");
    drop(worker);
    let host = start(&f, authority(&f));
    wait(&host, |status| is_covered(status, f.removal.sequence));
    host.shutdown().expect("joined");
    assert!(source.is_dir());
    assert!(
        f.native
            .read_removal_backup_worker_disposal(
                &f.input.context,
                &f.removal,
                &job.receipt,
                &mut budget()
            )
            .expect("no implicit intent from seal")
            .is_none()
    );
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("explicit controller");
    assert!(matches!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .expect("explicit intent"),
        NativeArchiveWorkerDisposalProgress::Prepared { .. }
    ));
    drop(executor);
    let f = cold(f);
    let auth = authority(&f);
    auth.context
        .lock()
        .expect("grants")
        .capability_grants
        .remove(&Capability::Admin);
    let host = start(&f, auth.clone());
    wait(&host, |status| {
        status.workspaces.values().any(|entry| {
            matches!(
                entry.outcome,
                NativeArchiveMaintenanceOutcome::Failed {
                    code: ErrorCode::Unauthorized,
                    ..
                }
            )
        })
    });
    assert!(source.is_dir());
    *auth.context.lock().expect("current grant restored") = f.input.context.clone();
    // The actual owned thread discovers the intent. No manual advance/dispose call.
    let done = wait(&host, |status| {
        status.workspaces.values().any(|entry| matches!(&entry.outcome,
        NativeArchiveMaintenanceOutcome::Inspected {
            operation: Some(NativeArchiveMaintenanceOperation::DisposalAdvanced { progress, .. }), ..
        } if matches!(progress.as_ref(), NativeArchiveWorkerDisposalProgress::DirectoryAbsent { .. })))
    });
    assert!(auth.calls.load(Ordering::SeqCst) as u64 >= done.ticks);
    assert!(!source.exists());
    assert_eq!(
        std::fs::read_dir(source.parent().expect("namespace"))
            .expect("actual directory")
            .count(),
        0
    );
    host.shutdown().expect("joined actual disposal worker");
    drop(auth);
    let f = cold(f);
    assert!(
        f.native
            .read_removal_backup_worker_disposal(
                &f.input.context,
                &f.removal,
                &job.receipt,
                &mut budget()
            )
            .expect("cold result")
            .expect("retained")
            .directory_absent
    );
    f.native
        .append_event(request(3, "capture survives worker disposal"))
        .expect("continued capture");
    f.native
        .verify_native(true)
        .expect("retained authorities and capture remain valid");
}
