use super::*;
use crate::backup::executor::tests::worker_path;
use crate::{NativeArchiveCleanup, NativeArchiveCleanupState, NativeArchiveWorkerDisposalProgress};

fn finish(
    f: &Fixture,
    executor: &mut NativeArchiveCleanup<'_>,
    request: &NativeRemovalRequestReceipt,
) {
    for _ in 0..96 {
        let result = executor
            .advance(&f.first.context, request, &mut budget())
            .expect("actual archive cleanup");
        if result.action.is_none() {
            assert!(
                result
                    .before
                    .archives
                    .iter()
                    .all(|entry| matches!(entry.state, NativeArchiveCleanupState::Covered { .. })),
                "request {}: {:?}",
                request.sequence,
                result.before
            );
            return;
        }
    }
    panic!("assertion archive cleanup did not settle");
}

#[test]
fn managed_disposal_releases_shared_obligations_and_preserves_classified_controls() {
    let f = fixture();
    assert!(
        f.native
            .retain_issued_backup(&f.first.context, &f.empty, 0, 16, &mut budget())
            .expect("actual empty archive availability")
            .complete
    );
    assert!(
        f.native
            .retain_issued_backup(&f.first.context, &f.old, 0, 16, &mut budget())
            .expect("actual dirty archive availability")
            .complete
    );
    let original = f
        .keys
        .backup_registration(&f.old.digest)
        .expect("registration")
        .expect("issued");
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    drop(executor);
    let first_job = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("complete catalog")
        .jobs
        .into_iter()
        .find(|job| job.binding.original == original && job.binding.request == f.removal)
        .expect("A terminal job");
    let worker = NativeService::open_encrypted(
        worker_path(&root, &original),
        "assertion-archives",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual A worker");
    let seal = worker
        .seal_removal_backup_worker(
            &f.first.context,
            &f.removal,
            &first_job.receipt,
            &mut budget(),
        )
        .expect("permanent terminal A seal");
    drop(worker);
    prune(&f);
    let next = remove(&f.native, &f.second, "B after A");
    let next_witness = f
        .native
        .prepare_assertion_removal(
            &f.second.context,
            &next,
            f.witness.scope,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("retained B assertion ownership");
    clean_batch(&f.native, &f, &f.second, &next);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("fresh B controller");
    finish(&f, &mut executor, &next);
    let selected = keys_for(&f.native, &f.second.context, &next, &next_witness);
    assert!(!selected.is_empty());
    let retire_b = |keys: &BTreeSet<Uuid>| {
        f.native.retire_removal_keys(
            &f.second.context,
            &next,
            &NativeRemovalKeySelection::Assertions {
                witness: next_witness.clone(),
            },
            keys,
            &mut budget(),
        )
    };
    assert!(
        retire_b(&selected).is_err(),
        "seal retains B native obligations"
    );
    let before = f
        .native
        .read_assertion_backup_inventory(&f.second.context, &next, &next_witness, &mut budget())
        .expect("current shared report")
        .key_inventory
        .native_use
        .expect("complete use history");
    assert!(before.disposed_workers.is_empty());
    assert!(before.addresses.values().any(|address| {
        address
            .acknowledged
            .get(&seal.worker_instance)
            .is_some_and(|value| selected.contains(&value.key_id))
    }));
    assert!(matches!(
        executor
            .dispose_worker(
                &f.first.context,
                &f.removal,
                &first_job.receipt,
                1,
                &mut budget(),
            )
            .expect("actual intent"),
        NativeArchiveWorkerDisposalProgress::Prepared { .. }
    ));
    assert!(
        retire_b(&selected).is_err(),
        "pending intent retains obligations"
    );
    let mut absent = false;
    for _ in 0..32 {
        if matches!(
            executor
                .dispose_worker(
                    &f.first.context,
                    &f.removal,
                    &first_job.receipt,
                    16,
                    &mut budget(),
                )
                .expect("bounded real directory disposal"),
            NativeArchiveWorkerDisposalProgress::DirectoryAbsent { .. }
        ) {
            absent = true;
            break;
        }
    }
    assert!(absent);
    let report = f
        .native
        .read_assertion_backup_inventory(&f.second.context, &next, &next_witness, &mut budget())
        .expect("replayed shared dispositions");
    let after = report.key_inventory.native_use.as_ref().expect("use");
    assert_eq!(after.addresses, before.addresses);
    assert_eq!(
        after.disposed_workers[&seal.worker_instance].binding.seal,
        seal
    );
    let controls: BTreeSet<_> = report
        .key_inventory
        .value_ownership
        .as_ref()
        .expect("classification")
        .addresses
        .values()
        .flatten()
        .filter(|value| value.disposition == NativeAssertionValueDisposition::PreserveControl)
        .map(|value| value.version.key_id)
        .collect();
    assert!(!controls.is_empty());
    assert!(
        retire_b(&controls).is_err(),
        "control keys remain independently needed"
    );
    let accepted = retire_b(&selected).expect("complete verified disposal releases B");
    assert!(accepted.evidence.classification.is_some());
    assert_eq!(retire_b(&selected).expect("exact retry"), accepted);
    f.native
        .verify_native(true)
        .expect("primary control replay");
    assert_eq!(
        f.keys
            .key_retirement(&accepted.receipt, &mut budget())
            .expect("full custody replay"),
        accepted
    );
}
