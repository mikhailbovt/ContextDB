use super::*;

fn latest(f: &Fixture, original: &NativeBackupRegistration) -> NativeBackupCleanupJob {
    f.keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("retained jobs")
        .jobs
        .into_iter()
        .rev()
        .find(|job| job.binding.original == *original)
        .expect("latest job")
}

fn body(worker: &NativeService, sequence: u64) -> Option<Vec<u8>> {
    worker
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("native snapshot")
        .get(
            &worker.keyspaces.observations_content,
            digest_bytes(request(sequence, "").event.event_id.to_string().as_bytes()).as_bytes(),
        )
        .expect("native body")
}

#[test]
fn archive_replacement_generations_recover_bootstrap_and_preserve_permitted_bytes() {
    let f = fixture();
    f.native
        .append_event(request(3, "permitted incidental detail"))
        .expect("independent original");
    let permitted = body(&f.native, 3).expect("actual permitted bytes");
    let original = issued(&f, true);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    let first = latest(&f, &original);
    let seal = executor
        .worker
        .as_ref()
        .expect("first worker")
        .1
        .seal_removal_backup_worker(&f.input.context, &f.removal, &first.receipt, &mut budget())
        .expect("first fence");
    let next = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "replacement-next",
            &mut budget(),
        )
        .expect("next request");
    let instance = managed_replacement_instance(&seal);
    crate::encryption::AFTER_MANAGED_REGISTRATION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| {
            Err(integrity("replacement registration failure"))
        }))
    });
    assert!(
        executor
            .advance(&f.input.context, &next, &mut budget())
            .is_err()
    );
    assert_eq!(
        f.keys
            .managed_instance_state(instance, &mut budget())
            .expect("registration"),
        crate::encryption::ManagedInstanceState::RegisteredOnly
    );
    drop(executor);
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    let Some(NativeArchiveCleanupAction::Started { job }) = executor
        .advance(&f.input.context, &next, &mut budget())
        .expect("same replacement registration")
        .action
    else {
        panic!("expected replacement start")
    };
    assert_eq!(job.binding.worker_instance, instance);
    assert_eq!(job.binding.worker_seal, Some(seal.clone()));
    assert!(!job.initialized);
    let (source, path, artifact) = first.next_source().expect("first clean result");
    assert_eq!(job.binding.source, source);
    assert_eq!(job.binding.source_path, path);
    assert_eq!(job.binding.source_artifact, artifact);
    let replacement_path = executor.worker.as_ref().expect("replacement").0.clone();
    let first_path = worker_path(&root, &original)
        .canonicalize()
        .expect("retained old directory");
    assert_ne!(replacement_path, first_path);
    assert_eq!(replacement_path.parent(), first_path.parent());
    drop(executor);

    // Accepted replacement history cannot authorize another empty bootstrap.
    let held = f.root.path().join("held-replacement");
    std::fs::rename(&replacement_path, &held).expect("temporarily unavailable replacement");
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    assert!(matches!(
        executor.advance(&f.input.context, &next, &mut budget()).expect("explicit missing worker").action,
        Some(NativeArchiveCleanupAction::AwaitingWorker { worker_instance, .. }) if worker_instance == instance
    ));
    assert!(!replacement_path.exists());
    std::fs::rename(&held, &replacement_path).expect("recover actual replacement");
    finish(&f, &mut executor, &next);
    let second = latest(&f, &original);
    let worker = &executor.worker.as_ref().expect("same generation").1;
    assert_eq!(body(worker, 1), None);
    assert_eq!(body(worker, 2), None);
    assert_eq!(body(worker, 3), Some(permitted));
    worker.verify_native(true).expect("replacement replay");
    assert_eq!(
        f.keys
            .backup_worker_seal(seal.worker_instance, &mut budget())
            .expect("old retained seal"),
        Some(seal)
    );
    drop(executor);
    let f = cold(f);

    // A later request on this generation uses its retained path and no import.
    let repeated = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "same-generation-later",
            &mut budget(),
        )
        .expect("later request");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    let Some(NativeArchiveCleanupAction::Started { job }) = executor
        .advance(&f.input.context, &repeated, &mut budget())
        .expect("continue replacement")
        .action
    else {
        panic!("expected same-worker start")
    };
    assert_eq!(job.binding.worker_instance, instance);
    assert!(job.binding.worker_seal.is_none());
    assert!(job.binding.restore_at.is_none());
    assert!(job.initialized);
    assert_eq!(
        executor.worker.as_ref().expect("same path").0,
        replacement_path
    );
    finish(&f, &mut executor, &repeated);
    let unchanged = latest(&f, &original);
    assert_eq!(
        unchanged.terminal.as_ref().expect("terminal").stage,
        NativeBackupCleanupStage::Unchanged
    );
    let seal = executor
        .worker
        .as_ref()
        .expect("second worker")
        .1
        .seal_removal_backup_worker(
            &f.input.context,
            &repeated,
            &unchanged.receipt,
            &mut budget(),
        )
        .expect("second generation fence");
    let last = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(3, "").event.event_id]),
            "third-generation",
            &mut budget(),
        )
        .expect("last request");
    drop(executor);
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    finish(&f, &mut executor, &last);
    let third = latest(&f, &original);
    assert_eq!(third.binding.worker_seal, Some(seal));
    assert_ne!(
        third.binding.worker_instance,
        second.binding.worker_instance
    );
    assert_ne!(third.binding.worker_instance, first.binding.worker_instance);
    let worker = &executor.worker.as_ref().expect("third worker").1;
    for sequence in 1..=3 {
        assert_eq!(body(worker, sequence), None);
    }
    worker.verify_native(true).expect("third native replay");
    for request in [&f.removal, &next, &repeated, &last] {
        let report = executor
            .inspect(&f.input.context, request, &mut budget())
            .expect("all prior cleanup retained");
        assert!(
            report
                .archives
                .iter()
                .all(|entry| matches!(entry.state, NativeArchiveCleanupState::Covered { .. }))
        );
    }
    assert!(first_path.is_dir());
    assert!(replacement_path.is_dir());
    assert_eq!(
        std::fs::read_dir(first_path.parent().expect("sibling namespace"))
            .expect("generations")
            .count(),
        3
    );
    drop(executor);
    cold(f)
        .native
        .verify_native(true)
        .expect("full custody survives cold reopen");
}
