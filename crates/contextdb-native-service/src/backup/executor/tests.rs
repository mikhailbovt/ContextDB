use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use crate::{CustodyMasterKey, NativeCustodyKeys, NativeSuppressionLedger};
use contextdb_service::{CapturePort, CognitiveMemoryService};
use std::sync::Arc;
use zeroize::Zeroizing;

fn issued(f: &Fixture, retain: bool) -> NativeBackupRegistration {
    let backup = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("archive");
    if retain {
        assert!(
            f.native
                .retain_issued_backup(&f.input.context, &backup, 0, 16, &mut budget())
                .expect("bytes")
                .complete
        );
    }
    f.keys
        .backup_registration(&backup.digest)
        .expect("catalog")
        .expect("issued")
}

fn cold(f: Fixture) -> Fixture {
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_id,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master"),
    )
    .expect("cold keys");
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "primary-decisions", ledger_id)
            .expect("cold ledger");
    let native = Arc::new(
        NativeService::open_encrypted(
            f.root.path().join("native"),
            "primary-decisions",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("cold primary"),
    );
    Fixture {
        root: f.root,
        native,
        keys,
        ledger,
        input: f.input,
        removal: f.removal,
        witness: f.witness,
    }
}

fn finish(
    f: &Fixture,
    executor: &mut NativeArchiveCleanup<'_>,
    request: &NativeRemovalRequestReceipt,
) -> NativeArchiveCleanupInventory {
    for _ in 0..96 {
        let result = executor
            .advance(&f.input.context, request, &mut budget())
            .expect("owned advance");
        if result.action.is_none() {
            assert!(
                result
                    .before
                    .archives
                    .iter()
                    .all(|entry| matches!(entry.state, NativeArchiveCleanupState::Covered { .. })),
                "{:?}",
                result.before
            );
            return result.before;
        }
        assert!(!matches!(
            result.action,
            Some(NativeArchiveCleanupAction::AwaitingWorker { .. })
        ));
    }
    panic!("owned archive execution did not settle");
}

fn worker_path(root: &Path, original: &NativeBackupRegistration) -> PathBuf {
    root.join(original.authority_id.to_string())
        .join(&original.archive_digest)
}

#[test]
fn archive_executor_reopens_two_workers_and_reuses_successor_aliases_across_requests() {
    let f = fixture();
    let first = issued(&f, true);
    let extra = request(3, "independent later original");
    f.native.append_event(extra.clone()).expect("later branch");
    let second = issued(&f, true);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    let mut ids = BTreeSet::new();
    for _ in 0..2 {
        let step = executor
            .advance(&f.input.context, &f.removal, &mut budget())
            .expect("start round robin");
        let Some(NativeArchiveCleanupAction::Started { job }) = step.action else {
            panic!("expected start")
        };
        ids.insert(job.binding.worker_instance);
    }
    assert_eq!(ids.len(), 2);
    drop(executor);
    let first_path = worker_path(&root, &first);
    let second_path = worker_path(&root, &second);
    let held = f.root.path().join("swapped-worker");
    std::fs::rename(&first_path, &held).expect("hold first");
    std::fs::rename(&second_path, &first_path).expect("wrong first directory");
    std::fs::rename(&held, &second_path).expect("wrong second directory");
    let before = f
        .keys
        .native_use_catalog_page(None, 1, &mut budget())
        .expect("use frontier")
        .revision;
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    assert!(
        executor
            .advance(&f.input.context, &f.removal, &mut budget())
            .is_err()
    );
    assert_eq!(
        f.keys
            .native_use_catalog_page(None, 1, &mut budget())
            .expect("no reconciliation on wrong owner")
            .revision,
        before
    );
    drop(executor);
    std::fs::rename(&first_path, &held).expect("hold second");
    std::fs::rename(&second_path, &first_path).expect("recover first");
    std::fs::rename(&held, &second_path).expect("recover second");
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    let report = finish(&f, &mut executor, &f.removal);
    assert_eq!(report.archives.len(), 4);
    let next = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "owned-next",
            &mut budget(),
        )
        .expect("next request");
    let pending = executor
        .inspect(&f.input.context, &next, &mut budget())
        .expect("next plan");
    assert_eq!(
        pending
            .archives
            .iter()
            .filter(|entry| matches!(entry.state, NativeArchiveCleanupState::Ready { .. }))
            .count(),
        2
    );
    assert_eq!(
        pending
            .archives
            .iter()
            .filter(|entry| matches!(
                entry.state,
                NativeArchiveCleanupState::WaitingForOwner { .. }
            ))
            .count(),
        2
    );
    let report = finish(&f, &mut executor, &next);
    assert_eq!(report.archives.len(), 6);
    let (catalog, _) = f
        .keys
        .selected_backup_keys_for_request(
            &BTreeMap::new(),
            &digest_bytes(f.input.context.request.workspace_id.as_bytes()),
            &next,
            &mut budget(),
        )
        .expect("catalog");
    assert_eq!(catalog.jobs.len(), 4);
    assert_eq!(
        catalog
            .jobs
            .iter()
            .map(|job| job.binding.worker_instance)
            .collect::<BTreeSet<_>>(),
        ids
    );
    assert!(catalog.jobs.iter().all(|job| job.terminal.is_some()));
    drop(executor);
    let f = cold(f);
    for original in [&first, &second] {
        let worker = NativeService::open_encrypted(
            worker_path(&root, original),
            "primary-decisions",
            [7; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("actual stable worker");
        assert_eq!(
            worker.engine.registered_instance().expect("id"),
            managed_instance(f.keys.authority_id(), &original.archive_digest)
        );
        worker.verify_native(true).expect("clean native replay");
        let snapshot = worker
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("view");
        for id in f.removal.roots.iter().chain(&next.roots) {
            assert!(
                snapshot
                    .get(
                        &worker.keyspaces.observations_content,
                        digest_bytes(id.to_string().as_bytes()).as_bytes()
                    )
                    .expect("removed body")
                    .is_none()
            );
        }
        if original == &second {
            assert!(
                snapshot
                    .get(
                        &worker.keyspaces.observations_content,
                        digest_bytes(extra.event.event_id.to_string().as_bytes()).as_bytes()
                    )
                    .expect("independent body")
                    .is_some()
            );
        }
    }
    assert_eq!(
        std::fs::read_dir(root.join(f.keys.authority_id().to_string()))
            .expect("workers")
            .count(),
        2
    );
}

#[test]
fn archive_executor_recovers_registration_only_bootstrap_without_another_identity() {
    let f = fixture();
    let original = issued(&f, true);
    let instance = managed_instance(f.keys.authority_id(), &original.archive_digest);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    crate::encryption::AFTER_MANAGED_REGISTRATION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| {
            Err(integrity("injected registration-only interruption"))
        }))
    });
    assert!(
        executor
            .advance(&f.input.context, &f.removal, &mut budget())
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
    let step = executor
        .advance(&f.input.context, &f.removal, &mut budget())
        .expect("recover same bootstrap");
    let Some(NativeArchiveCleanupAction::Started { job }) = step.action else {
        panic!("expected recovered start")
    };
    assert_eq!(job.binding.worker_instance, instance);
    finish(&f, &mut executor, &f.removal);
    drop(executor);
    cold(f)
        .native
        .verify_native(true)
        .expect("all authorities accept non-duplicate registration");
}

#[test]
fn archive_executor_missing_worker_before_job_admission_is_not_recreated() {
    let f = fixture();
    let original = issued(&f, true);
    let instance = managed_instance(f.keys.authority_id(), &original.archive_digest);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    BEFORE_MANAGED_JOB.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| Err(integrity("injected pre-job interruption"))))
    });
    assert!(
        executor
            .advance(&f.input.context, &f.removal, &mut budget())
            .is_err()
    );
    assert_eq!(
        f.keys
            .managed_instance_state(instance, &mut budget())
            .expect("native accepted"),
        crate::encryption::ManagedInstanceState::Active
    );
    drop(executor);
    let original_path = worker_path(&root, &original);
    let held = f.root.path().join("held-worker");
    std::fs::rename(&original_path, &held).expect("temporarily unavailable worker");
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    let unavailable = executor
        .advance(&f.input.context, &f.removal, &mut budget())
        .expect("explicit missing state");
    assert!(
        matches!(unavailable.action, Some(NativeArchiveCleanupAction::AwaitingWorker { worker_instance, .. }) if worker_instance == instance)
    );
    assert!(!original_path.exists());
    assert!(unavailable.before.frontier.jobs.is_none());
    std::fs::rename(&held, &original_path).expect("recover original directory");
    finish(&f, &mut executor, &f.removal);
}

#[test]
fn archive_executor_unavailable_inputs_authority_budget_and_protected_paths_create_no_workers() {
    let f = fixture();
    let original = issued(&f, false);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    let waiting = executor
        .advance(&f.input.context, &f.removal, &mut budget())
        .expect("input state");
    assert!(waiting.action.is_none());
    assert!(matches!(
        waiting.before.archives[0].state,
        NativeArchiveCleanupState::AwaitingInput {
            input: NativeBackupRecoveryState::AwaitingArtifact { .. }
        }
    ));
    assert!(!root.exists());
    issued(&f, true);
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert!(
        executor
            .advance(&denied, &f.removal, &mut budget())
            .is_err()
    );
    let mut zero = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert!(
        executor
            .advance(&f.input.context, &f.removal, &mut zero)
            .is_err()
    );
    assert!(!root.exists());
    for path in [
        f.root.path().join("native/workers"),
        f.root.path().join("keys/workers"),
        f.root.path().join("ledger/workers"),
        f.root.path().to_path_buf(),
    ] {
        let mut executor = NativeArchiveCleanup::new(&f.native, path)
            .expect("configuration has no filesystem effects");
        assert!(
            executor
                .advance(&f.input.context, &f.removal, &mut budget())
                .is_err()
        );
    }
    assert_eq!(
        f.keys
            .managed_instance_state(
                managed_instance(f.keys.authority_id(), &original.archive_digest),
                &mut budget()
            )
            .expect("no worker"),
        crate::encryption::ManagedInstanceState::Missing
    );
    assert!(!f.root.path().join("native/workers").exists());
}
