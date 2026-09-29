use super::super::disposal::{
    AFTER_QUARANTINE, BEFORE_DISPOSAL_FINISH, BEFORE_DISPOSAL_PUBLICATION,
};
use super::*;
use crate::NativeArchiveWorkerDisposalProgress;

fn terminal(f: &Fixture) -> NativeBackupCleanupJob {
    f.keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("jobs")
        .jobs
        .pop()
        .expect("terminal")
}

#[test]
fn worker_disposal_rejects_scope_missing_identity_and_stale_intent_before_touching_files() {
    let f = fixture();
    let original = issued(&f, true);
    let root = f.root.path().join("workers");
    let source = worker_path(&root, &original);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    let job = terminal(&f);
    for maximum in [0, 257] {
        assert!(
            executor
                .dispose_worker(
                    &f.input.context,
                    &f.removal,
                    &job.receipt,
                    maximum,
                    &mut budget()
                )
                .is_err()
        );
    }
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        executor
            .dispose_worker(&denied, &f.removal, &job.receipt, 1, &mut budget())
            .expect_err("current Admin required")
            .code,
        ErrorCode::Unauthorized
    );
    let mut wrong = f.input.context.clone();
    wrong.request.workspace_id = "another-workspace".into();
    assert!(
        executor
            .dispose_worker(&wrong, &f.removal, &job.receipt, 1, &mut budget())
            .is_err()
    );
    assert_eq!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .expect_err("unsealed instance")
            .code,
        ErrorCode::EvidenceRequired
    );
    let worker = &executor.worker.as_ref().expect("worker").1;
    worker
        .seal_removal_backup_worker(&f.input.context, &f.removal, &job.receipt, &mut budget())
        .expect("seal");
    executor.worker = None;
    let held = f.root.path().join("held-worker");
    std::fs::rename(&source, &held).expect("temporarily missing");
    assert!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .is_err()
    );
    assert!(!source.exists());
    // An unrelated real database at the right path cannot satisfy native identity.
    let unrelated =
        contextdb_storage_fjall::FjallStorage::open(&source).expect("unrelated backend");
    drop(unrelated);
    assert!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .is_err()
    );
    assert!(source.join("version").is_file());
    std::fs::rename(&source, f.root.path().join("unrelated-backend")).expect("preserve other DB");
    std::fs::rename(&held, &source).expect("restore exact worker");
    let primary = f.native.clone();
    let scope = f.input.context.clone();
    let removal = f.removal.clone();
    let receipt = job.receipt.clone();
    let same_root = root.clone();
    BEFORE_DISPOSAL_PUBLICATION.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            let mut second = NativeArchiveCleanup::new(&primary, &same_root)?;
            assert!(matches!(
                second.dispose_worker(&scope, &removal, &receipt, 1, &mut budget())?,
                NativeArchiveWorkerDisposalProgress::Prepared { .. }
            ));
            Ok(())
        }))
    });
    assert_eq!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .expect_err("concurrent accepted intent")
            .code,
        ErrorCode::IndexTooStale
    );
    assert!(source.is_dir());
    let intent = f
        .native
        .read_removal_backup_worker_disposal(
            &f.input.context,
            &f.removal,
            &job.receipt,
            &mut budget(),
        )
        .expect("read intent")
        .expect("accepted");
    let changed_root = f.root.path().join("different-root");
    let mut wrong_root =
        NativeArchiveCleanup::new(&f.native, &changed_root).expect("different root");
    assert!(
        wrong_root
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .is_err()
    );
    assert!(!changed_root.exists());
    let canonical = source.canonicalize().expect("source");
    let quarantine = canonical.with_file_name(format!(
        ".{}.dispose.{}",
        canonical
            .file_name()
            .expect("name")
            .to_str()
            .expect("Unicode"),
        intent.binding.seal.digest
    ));
    std::fs::create_dir(&quarantine).expect("unexpected sibling");
    assert!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .is_err()
    );
    assert!(source.is_dir() && quarantine.is_dir());
    std::fs::remove_dir(&quarantine).expect("remove owned empty fixture");
    let cancellation = contextdb_recall::QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        1_000_000,
        256 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        cancellation,
    );
    assert!(
        executor
            .dispose_worker(
                &f.input.context,
                &f.removal,
                &job.receipt,
                1,
                &mut cancelled
            )
            .is_err()
    );
    assert!(source.is_dir());
    f.native
        .verify_native(true)
        .expect("all refusal paths retain valid evidence");
}

#[test]
fn worker_disposal_drains_cloned_views_and_recovers_filesystem_and_sync_interruptions() {
    let f = fixture();
    f.native
        .append_event(request(3, "permitted after worker disposal"))
        .expect("independent data");
    let original = issued(&f, true);
    let root = f.root.path().join("workers");
    let source = worker_path(&root, &original);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    let job = terminal(&f);
    let worker = &executor.worker.as_ref().expect("worker").1;
    let view = worker
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("admitted snapshot");
    let clone = view.clone();
    let seal = worker
        .seal_removal_backup_worker(&f.input.context, &f.removal, &job.receipt, &mut budget())
        .expect("seal");
    let before = f
        .native
        .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
        .expect("copy history")
        .native_use
        .expect("tracked");
    assert!(matches!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .expect("held snapshot"),
        NativeArchiveWorkerDisposalProgress::AwaitingHandles { .. }
    ));
    assert!(executor.worker.is_none());
    drop(view);
    assert!(matches!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .expect("held clone"),
        NativeArchiveWorkerDisposalProgress::AwaitingHandles { .. }
    ));
    assert!(source.is_dir());
    assert!(
        f.native
            .read_removal_backup_worker_disposal(
                &f.input.context,
                &f.removal,
                &job.receipt,
                &mut budget()
            )
            .expect("no intent before drainage")
            .is_none()
    );
    drop(clone);
    for after in [false, true] {
        let hook: Box<dyn FnOnce() -> ServiceResult<()>> =
            Box::new(|| Err(integrity("injected disposal intent Sync failure")));
        if after {
            crate::encryption::AFTER_DISPOSAL_SYNC.with(|slot| *slot.borrow_mut() = Some(hook));
        } else {
            crate::encryption::BEFORE_DISPOSAL_SYNC.with(|slot| *slot.borrow_mut() = Some(hook));
        }
        assert!(
            executor
                .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
                .is_err()
        );
        let retained = f
            .native
            .read_removal_backup_worker_disposal(
                &f.input.context,
                &f.removal,
                &job.receipt,
                &mut budget(),
            )
            .expect("actual retained intent");
        assert_eq!(retained.is_some(), after);
        assert!(source.is_dir());
    }
    let intent = f
        .native
        .read_removal_backup_worker_disposal(
            &f.input.context,
            &f.removal,
            &job.receipt,
            &mut budget(),
        )
        .expect("intent")
        .expect("accepted");
    assert_eq!(intent.binding.seal, seal);
    assert!(!intent.directory_absent);
    AFTER_QUARANTINE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|| Err(integrity("lost quarantine response"))))
    });
    let failure = executor
        .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
        .expect_err("injected quarantine interruption");
    assert!(
        failure.message.contains("lost quarantine response"),
        "{failure:?}"
    );
    assert!(!source.exists());
    drop(executor);
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    assert_eq!(
        f.native
            .read_removal_backup_worker_disposal(
                &f.input.context,
                &f.removal,
                &job.receipt,
                &mut budget()
            )
            .expect("cold intent"),
        Some(intent.clone())
    );
    BEFORE_DISPOSAL_FINISH.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|| {
            Err(integrity("removed before finish acceptance"))
        }))
    });
    let mut interrupted = false;
    for _ in 0..128 {
        match executor.dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
        {
            Ok(NativeArchiveWorkerDisposalProgress::Removing {
                removed_entries, ..
            }) => assert!(removed_entries <= 1),
            Err(error) => {
                assert!(error.message.contains("removed before finish"), "{error:?}");
                interrupted = true;
                break;
            }
            other => panic!("unexpected disposal result {other:?}"),
        }
    }
    assert!(interrupted);
    assert_eq!(
        std::fs::read_dir(source.parent().expect("namespace"))
            .expect("remaining directories")
            .count(),
        0
    );
    drop(executor);
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    crate::encryption::AFTER_DISPOSAL_SYNC.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|| Err(integrity("lost disposal finish response"))))
    });
    assert!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .is_err()
    );
    let finished = f
        .native
        .read_removal_backup_worker_disposal(
            &f.input.context,
            &f.removal,
            &job.receipt,
            &mut budget(),
        )
        .expect("recover finish")
        .expect("accepted");
    assert!(finished.directory_absent);
    assert_eq!(finished.binding, intent.binding);
    assert!(
        matches!(executor.dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget()).expect("exact completed retry"), NativeArchiveWorkerDisposalProgress::DirectoryAbsent { disposal } if *disposal == finished)
    );
    let after = f
        .native
        .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
        .expect("retained copy history")
        .native_use
        .expect("tracked");
    assert_eq!(after.addresses, before.addresses);
    let next = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "after-disposal",
            &mut budget(),
        )
        .expect("later request");
    finish(&f, &mut executor, &next);
    let replacement = &executor.worker.as_ref().expect("fresh generation").1;
    replacement
        .verify_native(true)
        .expect("permitted archive restored after old disposal");
    let snapshot = replacement
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    for sequence in 1..=3 {
        let body = snapshot
            .get(
                &replacement.keyspaces.observations_content,
                digest_bytes(request(sequence, "").event.event_id.to_string().as_bytes())
                    .as_bytes(),
            )
            .expect("body");
        assert_eq!(body.is_some(), sequence == 3);
    }
    drop(snapshot);
    // Historical absence is not a claim about a reintroduced copy at that path.
    std::fs::create_dir(&source).expect("reintroduced directory");
    std::fs::write(source.join("unrelated"), b"preserve unexpected host file").expect("host file");
    assert!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .is_err()
    );
    assert_eq!(
        std::fs::read(source.join("unrelated")).expect("not removed"),
        b"preserve unexpected host file"
    );
    drop(executor);
    cold(f)
        .native
        .verify_native(true)
        .expect("retained authorities remain valid");
}
