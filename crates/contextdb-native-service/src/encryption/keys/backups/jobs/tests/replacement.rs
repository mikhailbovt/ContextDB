use super::*;
use crate::NativeService;
use crate::backup::jobs::tests::cold_owner;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::Fixture;

fn open(f: &Fixture) -> NativeService {
    NativeService::open_encrypted(
        f.root.path().join("replacement"),
        "primary-decisions",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("replacement native")
}

fn next(f: &Fixture) -> NativeRemovalRequestReceipt {
    f.native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "replace-worker",
            &mut budget(),
        )
        .expect("next request")
}

#[test]
fn archive_replacement_import_recovers_sync_uncertainty_and_holds_input_keys() {
    let (f, old, _, original) = prepared();
    let first = old
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("first job");
    assert!(
        !serde_json::to_string(&first.binding)
            .expect("legacy binding")
            .contains("worker_seal")
    );
    let request = next(&f);
    let worker = open(&f);
    assert!(
        worker
            .start_removal_backup_job(&f.input.context, &request, &original, &mut budget())
            .is_err(),
        "unfinished predecessor"
    );
    let (_, done) = finish(&f, &old, &f.removal, &first.receipt);
    assert!(
        worker
            .start_removal_backup_job(&f.input.context, &request, &original, &mut budget())
            .is_err(),
        "unsealed predecessor"
    );
    let seal = old
        .seal_removal_backup_worker(&f.input.context, &f.removal, &done.receipt, &mut budget())
        .expect("fence");
    assert!(
        f.native
            .start_removal_backup_job(&f.input.context, &request, &original, &mut budget())
            .is_err(),
        "non-pristine replacement"
    );
    assert!(
        worker
            .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
            .is_err(),
        "completed request cannot change worker"
    );
    let mut denied = f.input.context.clone();
    denied
        .capability_grants
        .remove(&contextdb_service::Capability::Admin);
    assert!(
        worker
            .start_removal_backup_job(&denied, &request, &original, &mut budget())
            .is_err()
    );
    let mut wrong_scope = f.input.context.clone();
    wrong_scope.request.workspace_id = "another-workspace".into();
    assert!(
        worker
            .start_removal_backup_job(&wrong_scope, &request, &original, &mut budget())
            .is_err()
    );
    let mut zero = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert!(
        worker
            .start_removal_backup_job(&f.input.context, &request, &original, &mut zero)
            .is_err()
    );
    for after in [false, true] {
        let hook: Box<dyn FnOnce() -> ServiceResult<()>> =
            Box::new(|| Err(integrity("replacement start Sync interruption")));
        if after {
            publication::AFTER_JOB_SYNC.with(|slot| *slot.borrow_mut() = Some(hook));
        } else {
            publication::BEFORE_JOB_SYNC.with(|slot| *slot.borrow_mut() = Some(hook));
        }
        assert!(
            worker
                .start_removal_backup_job(&f.input.context, &request, &original, &mut budget())
                .is_err()
        );
        let report = f
            .keys
            .selected_backup_keys(&BTreeMap::new(), &mut budget())
            .expect("complete journal after uncertainty");
        assert_eq!(report.jobs.len(), if after { 2 } else { 1 });
    }
    let start = worker
        .start_removal_backup_job(&f.input.context, &request, &original, &mut budget())
        .expect("recover exact start");
    assert_eq!(start.binding.worker_seal, Some(seal));
    assert!(!start.initialized);
    let instance = start.binding.worker_instance;
    let page = f
        .keys
        .backup_contents_page(&start.binding.source.receipt, 0, &mut budget())
        .expect("actual input keys");
    let held = BTreeSet::from([page.copies[0].version.key_id]);
    drop((worker, old));
    let f = cold_owner(f);
    let worker = open(&f);
    publication::BEFORE_JOB_SYNC.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|| {
            Err(integrity("import acknowledgement interruption"))
        }))
    });
    assert!(
        worker
            .advance_removal_backup_job(&f.input.context, &request, &start.receipt, &mut budget())
            .is_err()
    );
    let imported_head = worker
        .engine
        .head_sequence()
        .expect("actual imported sequence");
    assert_eq!(
        Some(imported_head),
        start.binding.restore_at.map(|value| value + 1)
    );
    assert!(
        !worker
            .read_removal_backup_job(&f.input.context, &request, &start.receipt, &mut budget())
            .expect("import unacknowledged")
            .initialized
    );
    let snapshot = f
        .keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("custody");
    assert_eq!(
        f.keys
            .require_active_job_keys(&snapshot, &held, &mut budget())
            .expect_err("fixed input retained")
            .code,
        ErrorCode::EvidenceRequired
    );
    drop(snapshot);
    drop(worker);
    let f = cold_owner(f);
    let worker = open(&f);
    assert_eq!(
        worker.engine.registered_instance().expect("same identity"),
        instance
    );
    let imported = worker
        .advance_removal_backup_job(&f.input.context, &request, &start.receipt, &mut budget())
        .expect("recover exact prior import");
    assert!(imported.job.initialized);
    assert_eq!(
        worker
            .engine
            .head_sequence()
            .expect("no repeated native import"),
        imported_head
    );
    let (_, done) = finish(&f, &worker, &request, &start.receipt);
    let snapshot = f
        .keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("custody");
    f.keys
        .require_active_job_keys(&snapshot, &held, &mut budget())
        .expect("job dependency released after finish; other retirement gates still apply");
    f.keys
        .verify_backup_catalog(&snapshot)
        .expect("complete old and new history");
    drop(snapshot);
    assert_eq!(
        worker
            .advance_removal_backup_job(&f.input.context, &request, &start.receipt, &mut budget())
            .expect("terminal retry")
            .job,
        done
    );
    worker
        .verify_native(true)
        .expect("actual cleaned replacement");
}

#[test]
fn archive_replacement_rejects_rehashed_seals_reused_identities_and_missing_indexes() {
    let (f, old, _, original) = prepared();
    let first = old
        .start_removal_backup_job(&f.input.context, &f.removal, &original, &mut budget())
        .expect("first job");
    let (_, done) = finish(&f, &old, &f.removal, &first.receipt);
    let seal = old
        .seal_removal_backup_worker(&f.input.context, &f.removal, &done.receipt, &mut budget())
        .expect("fence");
    let request = next(&f);
    let worker = open(&f);
    let start = worker
        .start_removal_backup_job(&f.input.context, &request, &original, &mut budget())
        .expect("replacement start");
    let workers = BTreeMap::from([(seal.worker_instance, original.archive_digest.clone())]);
    verification::require_transition(&start, None, Some(&done), &workers)
        .expect("valid succession");
    for variant in 0..7 {
        let mut altered = start.clone();
        match variant {
            0 => altered.binding.worker_seal = None,
            1 => altered.binding.worker_seal.as_mut().expect("seal").job = first.receipt.clone(),
            2 => {
                altered
                    .binding
                    .worker_seal
                    .as_mut()
                    .expect("seal")
                    .worker_instance = start.binding.worker_instance
            }
            3 => altered.binding.worker_instance = seal.worker_instance,
            4 => altered.binding.restore_at = None,
            5 => altered.binding.source = done.binding.source.clone(),
            6 => altered.binding.workspace_digest = "ab".repeat(32),
            _ => unreachable!(),
        }
        assert!(
            verification::require_transition(&altered, None, Some(&done), &workers).is_err(),
            "invalid transition {variant}"
        );
    }
    let mut occupied = workers.clone();
    occupied.insert(
        start.binding.worker_instance,
        original.archive_digest.clone(),
    );
    assert!(
        verification::require_transition(&start, None, Some(&done), &occupied).is_err(),
        "previously used identity even for this original"
    );
    assert!(
        verification::require_transition(&start, None, None, &workers).is_err(),
        "seal without a predecessor"
    );
    for instance in [seal.worker_instance, start.binding.worker_instance] {
        let mut tx = f.keys.engine.begin_write().expect("tx");
        tx.delete(&f.keys.rows, worker_key(instance))
            .expect("omit index");
        assert!(f.keys.verify_backup_catalog(&tx).is_err());
    }
    // Cryptographically valid edits to all job locators cannot replace retained
    // seal authority with a caller's claimed native checkpoint.
    let mut tx = f.keys.engine.begin_write().expect("tx");
    let key = event_key(start.receipt.sequence);
    let mut event: JobEvent = f
        .keys
        .read_job_record(&tx, &key, &mut budget())
        .expect("accepted start");
    event
        .value
        .binding
        .worker_seal
        .as_mut()
        .expect("seal")
        .native_sequence += 1;
    event.value.receipt.digest = event.commitment().expect("rehash");
    let mut head = f.keys.backup_head(&tx).expect("head");
    head.jobs = Some(event.value.receipt.clone());
    tx.put(
        &f.keys.rows,
        key.clone(),
        f.keys
            .seal_backup_record(&key, &event)
            .expect("reseal event"),
    )
    .expect("write");
    tx.put(
        &f.keys.rows,
        HEAD.to_vec(),
        f.keys.seal_backup_record(HEAD, &head).expect("reseal head"),
    )
    .expect("write");
    for key in [
        job_key(&event.value.binding),
        original_key(&original.archive_digest),
    ] {
        tx.put(
            &f.keys.rows,
            key.clone(),
            f.keys
                .seal_backup_record(&key, &event.value.receipt)
                .expect("reseal locator"),
        )
        .expect("write");
    }
    assert!(
        f.keys
            .selected_backup_keys_at(&tx, &BTreeMap::new(), &mut budget())
            .is_err()
    );
    assert!(f.keys.verify_backup_catalog(&tx).is_err());
}
