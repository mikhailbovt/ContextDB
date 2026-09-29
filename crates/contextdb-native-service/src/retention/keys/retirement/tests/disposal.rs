use super::*;
use crate::backup::executor::tests::{finish, issued, worker_path};
use crate::{NativeArchiveCleanup, NativeArchiveWorkerDisposalProgress};

#[test]
fn managed_disposal_releases_current_key_obligations_without_rewriting_history() {
    let f = fixture();
    f.native
        .append_event(request(3, "independent preserved C"))
        .expect("C");
    let space = f.native.keyspaces.observations_content.clone();
    let kept = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view")
        .get(&space, &source_key(3))
        .expect("C")
        .expect("present");
    let original = issued(&f, true);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    let job = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("jobs")
        .jobs
        .pop()
        .expect("terminal A");
    drop(executor);
    let old = NativeService::open_encrypted(
        worker_path(&root, &original),
        "primary-decisions",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual A worker");
    let seal = old
        .seal_removal_backup_worker(&f.input.context, &f.removal, &job.receipt, &mut budget())
        .expect("A seal");
    drop(old);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    let next = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "B-after-A",
            &mut budget(),
        )
        .expect("B request");
    let selected: BTreeSet<_> = f
        .native
        .read_original_key_inventory(&f.input.context, &next, &mut budget())
        .expect("B ownership")
        .sources
        .into_values()
        .flatten()
        .map(|key| key.key_id)
        .collect();
    let prior = f
        .native
        .retain_original_key_removal(&f.input.context, &next, &mut budget())
        .expect("historical B witness");
    assert!(
        prior
            .dispositions
            .values()
            .flatten()
            .all(|key| key.active_instances.is_none()
                && key.current_instances() == &key.acknowledged_instances)
    );
    finish(&f, &mut executor, &next);
    prune(&f, &next);
    let retire_b = || {
        f.native.retire_removal_keys(
            &f.input.context,
            &next,
            &NativeRemovalKeySelection::Originals,
            &selected,
            &mut budget(),
        )
    };
    assert!(
        retire_b().is_err(),
        "seal alone leaves A's B acknowledgements active"
    );
    let before = f
        .native
        .read_original_key_inventory(&f.input.context, &next, &mut budget())
        .expect("native history")
        .native_use
        .expect("v4");
    assert!(before.disposed_workers.is_empty());
    assert!(
        before
            .addresses
            .values()
            .any(|address| address.acknowledged.contains_key(&seal.worker_instance))
    );
    assert!(matches!(
        executor
            .dispose_worker(&f.input.context, &f.removal, &job.receipt, 1, &mut budget())
            .expect("intent"),
        NativeArchiveWorkerDisposalProgress::Prepared { .. }
    ));
    let pending = f
        .native
        .read_original_key_inventory(&f.input.context, &next, &mut budget())
        .expect("pending inventory")
        .native_use
        .expect("v4");
    assert!(pending.disposed_workers.is_empty());
    assert_eq!(pending.addresses, before.addresses);
    assert!(
        retire_b().is_err(),
        "pending disposal cannot clear copies or its held input keys"
    );
    let mut finished = false;
    for _ in 0..32 {
        if matches!(
            executor
                .dispose_worker(
                    &f.input.context,
                    &f.removal,
                    &job.receipt,
                    16,
                    &mut budget()
                )
                .expect("actual bounded disposal"),
            NativeArchiveWorkerDisposalProgress::DirectoryAbsent { .. }
        ) {
            finished = true;
            break;
        }
    }
    assert!(finished);
    let completed = f
        .native
        .retain_original_key_removal(&f.input.context, &next, &mut budget())
        .expect("verified current B decision");
    let current = completed.inventory.native_use.as_ref().expect("v4");
    assert_eq!(
        current.addresses, before.addresses,
        "full acknowledgements and transitions remain"
    );
    assert_eq!(current.disposed_workers.len(), 1);
    assert_eq!(current.managed_disposition_version, Some(1));
    assert_eq!(
        current.disposed_workers[&seal.worker_instance].binding.seal,
        seal
    );
    assert!(completed.dispositions.values().flatten().all(|key| {
        key.action == NativeOwnedKeyAction::AssessRetainedCopies
            && key.acknowledged_instances.contains(&seal.worker_instance)
            && key
                .active_instances
                .as_ref()
                .is_some_and(BTreeSet::is_empty)
    }));
    assert_eq!(
        f.native
            .read_original_key_removal(&f.input.context, &next, &prior.receipt, &mut budget())
            .expect("older prefix does not inherit future disposal"),
        prior
    );
    let mut omitted = current.clone();
    omitted.disposed_workers.clear();
    assert!(decisions::verify_use_prefix(current, &omitted, &mut budget()).is_err());
    let mut substituted = current.clone();
    substituted
        .disposed_workers
        .get_mut(&seal.worker_instance)
        .expect("entry")
        .directory_absent = false;
    assert!(decisions::verify_use_prefix(current, &substituted, &mut budget()).is_err());
    let mut unknown = current.clone();
    unknown.managed_disposition_version = Some(2);
    assert!(decisions::verify_use_prefix(current, &unknown, &mut budget()).is_err());
    let mut unsupported = current.clone();
    unsupported.managed_disposition_version = None;
    assert!(decisions::verify_use_prefix(current, &unsupported, &mut budget()).is_err());

    // Publish the old inventory wire shape through its actual fenced ledger path,
    // as the preceding binary could after disposal. It keeps every old obligation.
    f.native
        .engine
        .begin_write()
        .expect("new native frontier")
        .commit(Durability::Sync)
        .expect("actual new frontier Sync");
    let mut legacy = f
        .native
        .read_original_key_inventory(&f.input.context, &next, &mut budget())
        .expect("later historical inventory");
    let legacy_use = legacy.native_use.as_mut().expect("v4");
    legacy_use.managed_disposition_version = None;
    legacy_use.disposed_workers.clear();
    let legacy_bytes = encode(&legacy).expect("old wire shape");
    assert!(!String::from_utf8_lossy(&legacy_bytes).contains("managed_disposition_version"));
    assert!(!String::from_utf8_lossy(&legacy_bytes).contains("disposed_workers"));
    let guard = f
        .keys
        .lock_inventory_frontier(
            legacy.allocation_revision,
            legacy.allocation_digest.as_deref(),
            legacy.native_use.as_ref().expect("use"),
            &mut budget(),
        )
        .expect("actual old publication fence");
    let legacy_receipt = f
        .ledger
        .retain_primary_key_witness(&legacy, &mut budget())
        .expect("old-format publication");
    drop(guard);
    let legacy_read = f
        .native
        .read_original_key_removal(&f.input.context, &next, &legacy_receipt, &mut budget())
        .expect("old post-disposal witness remains readable after upgrade");
    assert_eq!(legacy_read.inventory, legacy);
    assert_eq!(
        encode(&legacy_read.inventory).expect("old exact bytes"),
        legacy_bytes
    );
    assert!(
        legacy_read
            .dispositions
            .values()
            .flatten()
            .all(|key| key.active_instances.is_none()
                && key.current_instances() == &key.acknowledged_instances
                && key.action == NativeOwnedKeyAction::RemoveAcknowledgedCopies)
    );
    let accepted = retire_b().expect("complete disposal permits current B key refusal");
    assert_eq!(
        accepted
            .keys
            .iter()
            .map(|key| key.key_id)
            .collect::<BTreeSet<_>>(),
        selected
    );
    assert_eq!(retire_b().expect("exact retry"), accepted);
    assert_eq!(
        f.native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("view")
            .get(&space, &source_key(3))
            .expect("C"),
        Some(kept)
    );
    drop(executor);
    let key_authority = f.keys.authority_id();
    let ledger_authority = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_authority,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master"),
    )
    .expect("cold custody");
    let ledger = NativeSuppressionLedger::open(
        f.root.path().join("ledger"),
        "primary-decisions",
        ledger_authority,
    )
    .expect("cold removal authority");
    let native = NativeService::open_encrypted(
        f.root.path().join("native"),
        "primary-decisions",
        [7; 32],
        ledger,
        keys.clone(),
    )
    .expect("cold primary");
    assert_eq!(
        keys.key_retirement(&accepted.receipt, &mut budget())
            .expect("cold refusal"),
        accepted
    );
    assert_eq!(
        native
            .read_original_key_removal(&f.input.context, &next, &completed.receipt, &mut budget())
            .expect("cold completed decision"),
        completed
    );
    let cold_legacy = native
        .read_original_key_removal(&f.input.context, &next, &legacy_receipt, &mut budget())
        .expect("cold old-format receipt");
    assert_eq!(cold_legacy, legacy_read);
    native
        .verify_native(true)
        .expect("all history remains valid");
}
