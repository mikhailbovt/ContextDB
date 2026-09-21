use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use crate::{CustodyMasterKey, NativeCustodyKeys, NativeSuppressionLedger};
use contextdb_service::{CapturePort, CognitiveMemoryService};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) fn prepared() -> (
    Fixture,
    NativeService,
    BackupResponse,
    NativeBackupRegistration,
) {
    let f = fixture();
    let backup = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("archive");
    let complete = f
        .native
        .retain_issued_backup(&f.input.context, &backup, 0, 16, &mut budget())
        .expect("bytes");
    assert!(complete.complete);
    let worker = open(&f, "worker");
    (f, worker, backup, complete.contents.registration)
}

fn open(f: &Fixture, name: &str) -> NativeService {
    NativeService::open_encrypted(
        f.root.path().join(name),
        "primary-decisions",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("worker")
}

pub(crate) fn cold(f: Fixture, worker: NativeService) -> (Fixture, NativeService) {
    let keys_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((worker, f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        keys_id,
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
    let f = Fixture {
        root: f.root,
        native,
        keys,
        ledger,
        input: f.input,
        removal: f.removal,
        witness: f.witness,
    };
    let worker = open(&f, "worker");
    (f, worker)
}

pub(crate) fn finish(
    f: &Fixture,
    worker: &NativeService,
    request: &NativeRemovalRequestReceipt,
    start: &NativeBackupCleanupJobReceipt,
) -> (Vec<NativeBackupCleanupStage>, NativeBackupCleanupJob) {
    let mut stages = Vec::new();
    for _ in 0..32 {
        let result = worker
            .advance_removal_backup_job(&f.input.context, request, start, &mut budget())
            .expect("job advance");
        stages.push(result.progress.stage);
        if result.job.terminal.is_some() {
            return (stages, result.job);
        }
    }
    panic!("job did not finish: {stages:?}");
}

#[test]
fn archive_job_cold_reopen_resumes_one_worker_and_returns_terminal_without_writes() {
    let (f, worker, _, original) = prepared();
    let native_head = worker.engine.head_sequence().expect("head");
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("start");
    assert!(start.terminal.is_none());
    assert_eq!(worker.engine.head_sequence().expect("head"), native_head);
    assert_eq!(
        worker
            .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
            .expect("lost response retry"),
        start
    );
    let (f, worker) = cold(f, worker);
    assert_eq!(
        worker
            .read_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .expect("retained start"),
        start
    );
    let imported = worker
        .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("import");
    assert_eq!(imported.progress.stage, NativeBackupCleanupStage::Restored);
    let (f, worker) = cold(f, worker);
    let next = worker
        .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("lost import response retry");
    assert_ne!(next.progress.stage, NativeBackupCleanupStage::Restored);
    let (f, worker) = cold(f, worker);
    let (_, terminal) = finish(&f, &worker, &f.removal, &start.receipt);
    assert_eq!(terminal.binding, start.binding);
    assert_eq!(
        terminal.terminal.as_ref().expect("result").stage,
        NativeBackupCleanupStage::Available
    );
    require_bodies_absent(&worker, &f.removal);
    let (f, worker) = cold(f, worker);
    let before = worker.engine.head_sequence().expect("head");
    assert_eq!(
        worker
            .read_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .expect("start resolves latest"),
        terminal
    );
    let repeated = worker
        .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("terminal retry");
    assert_eq!(repeated.job, terminal);
    assert_eq!(
        worker
            .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
            .expect("start retry after finish"),
        terminal
    );
    assert_eq!(worker.engine.head_sequence().expect("head"), before);
}

#[test]
fn archive_job_next_request_uses_prior_result_without_import_or_resurrection() {
    let f = fixture();
    let extra = request(3, "second selected source");
    f.native.append_event(extra.clone()).expect("extra");
    let backup = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("archive");
    let complete = f
        .native
        .retain_issued_backup(&f.input.context, &backup, 0, 16, &mut budget())
        .expect("bytes");
    let original = complete.contents.registration;
    let worker = open(&f, "worker");
    let first = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("first start");
    let second = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([extra.event.event_id]),
            "next-job",
            &mut budget(),
        )
        .expect("second request");
    assert_eq!(
        worker
            .start_removal_backup_job(&f.input.context, &second, &original, &mut budget())
            .expect_err("unfinished job cannot be replaced")
            .code,
        ErrorCode::EvidenceRequired
    );
    let (_, first_done) = finish(&f, &worker, &f.removal, &first.receipt);
    let proof = first_done
        .terminal
        .as_ref()
        .expect("done")
        .replacement
        .as_ref()
        .expect("replacement");
    let next = worker
        .start_removal_backup_job(&f.input.context, &second, &original, &mut budget())
        .expect("next start");
    assert_eq!(next.binding.source, proof.target);
    assert_eq!(next.binding.source_path, vec![proof.receipt.clone()]);
    assert_eq!(next.binding.worker_instance, first.binding.worker_instance);
    assert_eq!(next.binding.restore_at, None);
    let (stages, done) = finish(&f, &worker, &second, &next.receipt);
    assert!(!stages.contains(&NativeBackupCleanupStage::Restored));
    assert_eq!(
        done.terminal.as_ref().expect("done").stage,
        NativeBackupCleanupStage::Available
    );
    for request in [&f.removal, &second] {
        require_bodies_absent(&worker, request);
    }
    assert_eq!(
        worker
            .read_removal_backup_job(&f.input.context, &f.removal, &first.receipt, &mut budget())
            .expect("prior immutable"),
        first_done
    );
    let (f, worker) = cold(f, worker);
    assert_eq!(
        worker
            .read_removal_backup_job(&f.input.context, &second, &next.receipt, &mut budget())
            .expect("cold next"),
        done
    );
}

#[test]
fn archive_job_rejects_wrong_owner_request_scope_and_divergent_active_history() {
    let (f, worker, _, original) = prepared();
    assert!(
        f.native
            .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
            .is_err()
    );
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("start");
    let other = open(&f, "other-worker");
    let before = other.engine.head_sequence().expect("head");
    assert!(
        other
            .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
            .is_err()
    );
    assert!(
        other
            .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    assert_eq!(other.engine.head_sequence().expect("head"), before);
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert!(
        worker
            .read_removal_backup_job(&denied, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    let mut changed = f.removal.clone();
    changed.roots.clear();
    assert!(
        worker
            .advance_removal_backup_job(&f.input.context, &changed, &start.receipt, &mut budget())
            .is_err()
    );
    let mut foreign = f.input.context.clone();
    foreign.request.workspace_id = "other-workspace".into();
    assert!(
        worker
            .read_removal_backup_job(&foreign, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    let mut zero = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert!(
        worker
            .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut zero)
            .is_err()
    );
    worker
        .append_event(request(3, "divergent worker history"))
        .expect("unexpected host write");
    let before = worker.engine.head_sequence().expect("head");
    assert!(
        worker
            .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .is_err()
    );
    assert_eq!(worker.engine.head_sequence().expect("head"), before);
    assert!(
        worker
            .read_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .expect("still active")
            .terminal
            .is_none()
    );
}

fn require_bodies_absent(worker: &NativeService, request: &NativeRemovalRequestReceipt) {
    let snapshot = worker
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    for id in &request.roots {
        assert!(
            snapshot
                .get(
                    &worker.keyspaces.observations_content,
                    digest_bytes(id.to_string().as_bytes()).as_bytes()
                )
                .expect("selected body")
                .is_none()
        );
    }
}

#[test]
fn archive_job_recovers_cleanup_completed_before_terminal_acceptance() {
    let (f, worker, backup, original) = prepared();
    let start = worker
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("start");
    BEFORE_JOB_FINISH.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| Err(integrity("injected finish interruption"))))
    });
    let mut interrupted = false;
    for _ in 0..32 {
        match worker.advance_removal_backup_job(
            &f.input.context,
            &f.removal,
            &start.receipt,
            &mut budget(),
        ) {
            Ok(result) => assert!(result.job.terminal.is_none()),
            Err(error) => {
                assert!(error.message.contains("injected"));
                interrupted = true;
                break;
            }
        }
    }
    assert!(interrupted);
    assert!(
        worker
            .read_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .expect("no accepted finish")
            .terminal
            .is_none()
    );
    let (f, worker) = cold(f, worker);
    let mut primary_done = false;
    for _ in 0..32 {
        let progress = f
            .native
            .advance_removal_backup(&f.input.context, &f.removal, &backup, &mut budget())
            .expect("primary cleanup");
        if progress.stage == NativeBackupCleanupStage::Available {
            primary_done = true;
            break;
        }
    }
    assert!(primary_done);
    let selected = f
        .witness
        .dispositions
        .values()
        .flatten()
        .map(|key| key.allocation.key_id)
        .collect();
    let retire = || {
        f.native.retire_removal_keys(
            &f.input.context,
            &f.removal,
            &crate::NativeRemovalKeySelection::Originals,
            &selected,
            &mut budget(),
        )
    };
    let refused = retire().expect_err("fixed input remains needed before finish Sync");
    assert_eq!(refused.code, ErrorCode::EvidenceRequired);
    assert!(
        refused.message.contains("unfinished archive job"),
        "{refused:?}"
    );
    let before = worker.engine.head_sequence().expect("head");
    let done = worker
        .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("resume accepted native cleanup");
    assert_eq!(done.progress.stage, NativeBackupCleanupStage::Available);
    assert!(done.job.terminal.is_some());
    assert_eq!(worker.engine.head_sequence().expect("head"), before);
    retire().expect("finished job releases input key dependency");
    assert!(
        worker
            .verify_encrypted_archive(&backup, &mut budget())
            .is_err()
    );
    assert_eq!(
        worker
            .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
            .expect("terminal retry needs no refused input"),
        done
    );
}

#[test]
fn archive_job_partial_replacement_is_fixed_input_not_terminal_cleanup() {
    let f = fixture();
    let second = request(2, "").event.event_id;
    let removal = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([f.input.event.event_id, second]),
            "both",
            &mut budget(),
        )
        .expect("request");
    let backup = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("archive");
    let issued = f
        .keys
        .backup_registration(&backup.digest)
        .expect("catalog")
        .expect("issued");
    f.native
        .prepare_original_removal_sources(&f.input.context, &removal, &removal.roots, &mut budget())
        .expect("prepare");
    f.native
        .maintain_custody(&f.input.context, 256, &mut budget())
        .expect("custody");
    f.native
        .prune_original_sources(
            &f.input.context,
            &removal,
            &BTreeSet::from([f.input.event.event_id]),
            &mut budget(),
        )
        .expect("partial cleanup");
    let partial = f
        .native
        .create_removal_backup(&f.input.context, &removal, &backup, &mut budget())
        .expect("partial replacement");
    f.native
        .retain_removal_backup(&f.input.context, &removal, &partial, 0, 16, &mut budget())
        .expect("bytes");
    let worker = open(&f, "worker");
    let start = worker
        .start_removal_backup_job(&f.input.context, &removal, &issued, &mut budget())
        .expect("use readable partial replacement");
    assert_eq!(start.binding.source, partial.replacement.target);
    assert_eq!(start.binding.source_path, vec![partial.replacement.receipt]);
    assert!(start.terminal.is_none());
    let (stages, done) = finish(&f, &worker, &removal, &start.receipt);
    assert!(stages.contains(&NativeBackupCleanupStage::Originals));
    let result = done.terminal.expect("finished actual cleanup");
    assert_eq!(result.stage, NativeBackupCleanupStage::Available);
    assert_eq!(result.replacement.expect("proof").pruning.sources, 1);
    require_bodies_absent(&worker, &removal);
    worker.verify_native(true).expect("complete replay");
}

#[test]
fn archive_job_empty_input_is_imported_once_and_finishes_unchanged() {
    let f = fixture();
    let empty = open(&f, "empty-source");
    let backup = empty
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("empty archive");
    let complete = empty
        .retain_issued_backup(&f.input.context, &backup, 0, 16, &mut budget())
        .expect("bytes");
    let worker = open(&f, "worker");
    let start = worker
        .start_removal_backup_job(
            &f.input.context,
            &f.removal,
            &complete.contents.registration,
            &mut budget(),
        )
        .expect("empty job");
    let imported = worker
        .advance_removal_backup_job(&f.input.context, &f.removal, &start.receipt, &mut budget())
        .expect("import empty");
    assert_eq!(imported.progress.stage, NativeBackupCleanupStage::Restored);
    assert_eq!(
        worker
            .global_head(
                &worker
                    .engine
                    .begin_read(SnapshotSelector::Latest)
                    .expect("view")
            )
            .expect("head"),
        0
    );
    let (stages, done) = finish(&f, &worker, &f.removal, &start.receipt);
    assert!(!stages.contains(&NativeBackupCleanupStage::Restored));
    assert_eq!(
        done.terminal.expect("done").stage,
        NativeBackupCleanupStage::Unchanged
    );
    assert_eq!(
        done.terminal_archive_digest,
        Some(
            worker
                .build_native_backup()
                .expect("actual terminal")
                .1
                .digest
        )
    );
    let second = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "empty-next",
            &mut budget(),
        )
        .expect("next request");
    let next = worker
        .start_removal_backup_job(
            &f.input.context,
            &second,
            &complete.contents.registration,
            &mut budget(),
        )
        .expect("continue maintenance-only result");
    let (stages, done) = finish(&f, &worker, &second, &next.receipt);
    assert!(!stages.contains(&NativeBackupCleanupStage::Restored));
    assert_eq!(
        done.terminal.expect("done").stage,
        NativeBackupCleanupStage::Unchanged
    );
}
