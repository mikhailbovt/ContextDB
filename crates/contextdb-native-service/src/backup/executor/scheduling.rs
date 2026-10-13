//! Real retained jobs and filesystem obligations across interleaved requests.

use super::tests::{finish, issued, worker_path};
use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use contextdb_service::CapturePort;

fn originals(f: &Fixture) -> [NativeBackupRegistration; 3] {
    let first = issued(f, true);
    f.native
        .append_event(request(3, "second archive"))
        .expect("capture");
    let second = issued(f, true);
    f.native
        .append_event(request(4, "third archive"))
        .expect("capture");
    [first, second, issued(f, true)]
}

fn next_request(f: &Fixture) -> NativeRemovalRequestReceipt {
    f.native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "interleaved-next",
            &mut budget(),
        )
        .expect("separate retained request")
}

fn start(
    f: &Fixture,
    root: &Path,
    original: &NativeBackupRegistration,
    request: &NativeRemovalRequestReceipt,
) -> (NativeService, NativeBackupCleanupJob) {
    let path = worker_path(root, original);
    let engine = crate::encryption::NativeStorage::open_managed_archive(
        &path,
        f.keys.clone(),
        managed_instance(f.keys.authority_id(), &original.archive_digest),
        &mut budget(),
    )
    .expect("managed worker");
    let worker = NativeService::finish_open(
        &path,
        f.native.database_id.clone(),
        *f.native.token_key,
        Some(f.ledger.clone()),
        engine,
    )
    .expect("worker");
    let job = worker
        .start_removal_backup_job(&f.input.context, request, original, &mut budget())
        .expect("actual admitted job");
    (worker, job)
}

fn terminal(
    f: &Fixture,
    worker: &NativeService,
    request: &NativeRemovalRequestReceipt,
    mut job: NativeBackupCleanupJob,
) -> NativeBackupCleanupJob {
    for _ in 0..64 {
        if job.terminal.is_some() {
            return job;
        }
        job = worker
            .advance_removal_backup_job(&f.input.context, request, &job.receipt, &mut budget())
            .expect("actual cleanup")
            .job;
    }
    panic!("job did not finish");
}

#[test]
fn archive_interleaved_requests_do_not_reset_each_others_failed_worker_cursor() {
    let f = fixture();
    let originals = originals(&f);
    let next = next_request(&f);
    let root = f.root.path().join("workers");
    for (index, original) in originals.iter().enumerate() {
        let owner = if index == 1 { &next } else { &f.removal };
        let (worker, job) = start(&f, &root, original, owner);
        assert!(!job.initialized);
        drop(worker);
    }
    let unavailable: Vec<_> = [1, 2]
        .into_iter()
        .map(|index| {
            let source = worker_path(&root, &originals[index]);
            let held = f.root.path().join(format!("held-{index}"));
            std::fs::rename(&source, &held).expect("temporarily missing owned worker");
            (source, held)
        })
        .collect();
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    for round in 0..3 {
        let a = executor
            .advance(&f.input.context, &f.removal, &mut budget())
            .expect("request A");
        if round == 1 {
            assert!(
                matches!(a.action, Some(NativeArchiveCleanupAction::AwaitingWorker { original, .. }) if original == originals[2])
            );
        } else {
            assert!(
                matches!(a.action, Some(NativeArchiveCleanupAction::Advanced { result }) if result.job.binding.original == originals[0])
            );
        }
        let b = executor
            .advance(&f.input.context, &next, &mut budget())
            .expect("request B");
        assert!(
            matches!(b.action, Some(NativeArchiveCleanupAction::AwaitingWorker { original, .. }) if original == originals[1])
        );
    }
    drop(executor);
    for (source, held) in unavailable {
        std::fs::rename(held, source).expect("restore owned worker");
    }
    f.native
        .verify_native(true)
        .expect("accepted jobs remain valid");
}

#[test]
fn archive_interleaved_disposals_alternate_classes_and_progress_past_recurring_failures() {
    let f = fixture();
    let originals = originals(&f);
    let next = next_request(&f);
    let root = f.root.path().join("workers");
    let mut jobs = Vec::new();
    let mut seals = Vec::new();
    for (index, original) in originals.iter().enumerate() {
        let owner = if index == 1 { &next } else { &f.removal };
        let (worker, job) = start(&f, &root, original, owner);
        let job = terminal(&f, &worker, owner, job);
        let seal = worker
            .seal_removal_backup_worker(&f.input.context, owner, &job.receipt, &mut budget())
            .expect("seal in A1, B2, A3 order");
        drop(worker);
        let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("intent controller");
        assert!(matches!(
            executor
                .dispose_worker(&f.input.context, owner, &job.receipt, 1, &mut budget())
                .expect("explicit accepted intent"),
            NativeArchiveWorkerDisposalProgress::Prepared { .. }
        ));
        jobs.push(job);
        seals.push(seal);
    }
    assert!(seals[0].sequence < seals[1].sequence && seals[1].sequence < seals[2].sequence);
    // More than one bounded chunk on A1, while A3/B2 retain real refusal paths.
    let source = worker_path(&root, &originals[0]);
    let extra = source.join("owned-fixture-files");
    std::fs::create_dir(&extra).expect("owned fixture directory");
    for entry in 0..40 {
        std::fs::write(extra.join(format!("part-{entry:02}")), b"fixture").expect("owned file");
    }
    let mut conflicts = Vec::new();
    for index in [1, 2] {
        let source = worker_path(&root, &originals[index])
            .canonicalize()
            .expect("source");
        let conflict = source.with_file_name(format!(
            ".{}.dispose.{}",
            source.file_name().expect("name").to_str().expect("Unicode"),
            seals[index].digest
        ));
        std::fs::create_dir(&conflict).expect("conflicting owned sibling");
        conflicts.push(conflict);
    }
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("shared controller");
    let mut successful_chunks = 0;
    for round in 0..5 {
        for (index, owner) in [(0, &f.removal), (1, &next)] {
            let archive_turn = round % 2 == 1;
            if archive_turn {
                BEFORE_MANAGED_JOB.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(|| {
                        Err(integrity("recurring archive publication failure"))
                    }));
                });
            }
            let step = executor.advance(&f.input.context, owner, &mut budget());
            if archive_turn {
                assert!(
                    step.expect_err("archive class still receives a turn")
                        .message
                        .contains("recurring archive publication failure")
                );
            } else if index == 0 && round != 2 {
                let step = step.expect("A1 receives another disposal chunk");
                assert!(
                    matches!(step.action, Some(NativeArchiveCleanupAction::DisposalAdvanced { original, progress }) if original == originals[0] && matches!(progress.as_ref(), NativeArchiveWorkerDisposalProgress::Removing { removed_entries: 1..=16, .. }))
                );
                successful_chunks += 1;
            } else {
                assert!(
                    step.expect_err("A3/B2 keep their explicit refusal")
                        .message
                        .contains("source and quarantine both exist")
                );
            }
        }
    }
    assert_eq!(successful_chunks, 2);
    drop(executor);
    for conflict in conflicts {
        std::fs::remove_dir(conflict).expect("remove owned empty conflict");
    }
    f.native
        .verify_native(true)
        .expect("failed attempts preserve all authorities");
    assert!(jobs.iter().all(|job| job.terminal.is_some()));
}

#[test]
fn archive_request_scheduling_reports_exhaustion_and_releases_observed_idle_state() {
    let f = fixture();
    issued(&f, true);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    // Fill only volatile cursor metadata; no request or retained authority is forged.
    for sequence in 0..MAX_REQUEST_SCHEDULES as u64 {
        executor
            .schedules
            .insert((uuid::Uuid::nil(), sequence), RequestSchedule::default());
    }
    let error = executor
        .advance(&f.input.context, &f.removal, &mut budget())
        .expect_err("explicit active cursor bound");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(error.message.contains("65,536 active request cursors"));
    assert_eq!(executor.schedules.len(), MAX_REQUEST_SCHEDULES);
    assert!(!root.exists());
    executor.schedules.clear();
    let first = executor
        .advance(&f.input.context, &f.removal, &mut budget())
        .expect("actual eligible request");
    assert!(matches!(
        first.action,
        Some(NativeArchiveCleanupAction::Started { .. })
    ));
    assert_eq!(executor.schedules.len(), 1);
    finish(&f, &mut executor, &f.removal);
    assert!(
        executor.schedules.is_empty(),
        "idle request does not retain scheduling metadata"
    );
    f.native
        .verify_native(true)
        .expect("exhaustion changed no retained authority");
}
