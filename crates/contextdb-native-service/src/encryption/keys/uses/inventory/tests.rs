use super::*;
use crate::encryption::NativeStorage;
use std::time::Duration;

mod witness;

fn budget() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        256 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([64; 32])).expect("master")
}

fn selected(
    keys: &NativeCustodyKeys,
    addresses: &[String],
) -> (BTreeMap<String, BTreeSet<Uuid>>, u64, Option<String>) {
    let mut selected: BTreeMap<_, BTreeSet<_>> = addresses
        .iter()
        .map(|address| (address.clone(), BTreeSet::new()))
        .collect();
    let mut cursor = None;
    loop {
        let page = keys
            .key_catalog_page(cursor.as_deref(), 256, &mut budget())
            .expect("allocations");
        for entry in page.entries {
            if let Some(ids) = selected.get_mut(&entry.address_digest) {
                ids.insert(entry.key_id);
            }
        }
        match page.continuation {
            Some(next) => cursor = Some(next),
            None => return (selected, page.revision, page.revision_digest),
        }
    }
}

#[test]
fn selected_use_replays_exact_versions_across_rewrite_import_and_logical_deletion() {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "use-selection", master())
        .expect("keys");
    let store =
        NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native");
    let space = Keyspace::new("fixture").expect("space");
    let absent = address(&space, b"absent");
    let address = address(&space, b"shared");
    let mut tx = store.begin_write().expect("tx");
    tx.put(
        &space,
        b"shared".to_vec(),
        b"private and independent".to_vec(),
    )
    .expect("mixed value");
    tx.put(
        &space,
        b"unselected".to_vec(),
        b"independent secret".to_vec(),
    )
    .expect("other scope");
    tx.commit(Durability::Sync).expect("commit");
    let cipher = store
        .physical()
        .begin_read(SnapshotSelector::Latest)
        .expect("view")
        .get(&space, b"shared")
        .expect("cipher")
        .expect("present");
    let mut tx = store.begin_write().expect("rewrite");
    tx.put(&space, b"shared".to_vec(), b"independent".to_vec())
        .expect("cleaned");
    tx.commit(Durability::Sync).expect("replacement");
    let replica =
        NativeStorage::open(&root.path().join("replica"), Some(keys.clone())).expect("replica");
    let mut tx = replica.begin_write().expect("import");
    tx.put_ciphertext(&space, b"shared".to_vec(), cipher)
        .expect("exact older cipher");
    tx.commit(Durability::Sync).expect("import commit");
    let (selection, revision, digest) = selected(&keys, &[address.clone(), absent.clone()]);
    let inventory = keys
        .selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
        .expect("complete join")
        .expect("tracked");
    assert_eq!(inventory.addresses.len(), 2);
    let copies = &inventory.addresses[&address];
    assert_eq!(copies.transitions.len(), 3);
    assert_eq!(copies.acknowledged.len(), 2);
    assert!(
        copies
            .transitions
            .iter()
            .all(|change| change.transaction.outcome == NativeKeyUseOutcome::Committed)
    );
    assert_eq!(copies.transitions[0].after, copies.transitions[1].before);
    assert_ne!(copies.transitions[0].after, copies.transitions[1].after);
    assert_eq!(copies.transitions[0].after, copies.transitions[2].after);
    assert!(inventory.addresses[&absent].transitions.is_empty());
    assert!(
        !String::from_utf8(encode(&inventory).expect("report"))
            .expect("json")
            .contains("independent secret")
    );
    let mut tx = store.begin_write().expect("prune");
    tx.delete(&space, b"shared".to_vec()).expect("delete");
    tx.commit(Durability::Sync).expect("pruned");
    let inventory = keys
        .selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
        .expect("delete allocates no key")
        .expect("tracked");
    let copies = &inventory.addresses[&address];
    assert_eq!(copies.transitions.len(), 4);
    assert_eq!(
        copies.acknowledged.len(),
        1,
        "old replica remains an acknowledged copy"
    );
    assert!(copies.transitions.last().expect("deletion").after.is_none());
    keys.verify().expect("unmodified full verifier");
    let id = keys.authority_id();
    drop((replica, store, keys));
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "use-selection", id, master())
        .expect("actual authority reopen");
    let _store = NativeStorage::open(&root.path().join("native"), Some(keys.clone()))
        .expect("actual native reopen");
    assert_eq!(
        keys.selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
            .expect("reopened history"),
        Some(inventory)
    );
}

#[test]
fn selected_use_keeps_unused_allocations_pending_values_and_aborted_versions_distinct() {
    for publish in [false, true] {
        let root = tempfile::tempdir().expect("root");
        let keys =
            NativeCustodyKeys::create(root.path().join("keys"), "use-outcome-selection", master())
                .expect("keys");
        let store =
            NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native");
        let space = Keyspace::new("fixture").expect("space");
        let address = address(&space, b"value");
        let mut tx = store.begin_write().expect("initial");
        tx.put(&space, b"value".to_vec(), b"acknowledged".to_vec())
            .expect("old value");
        tx.commit(Durability::Sync).expect("commit");
        let mut unused = PendingKeys::new();
        keys.seal_value(
            &space,
            b"value",
            b"allocated but never prepared",
            &mut unused,
        )
        .expect("unused allocation");
        let unused_id = unused[&address].record.id;
        keys.publish(&unused).expect("independent allocation only");
        let publication = keys.use_publication().expect("hold publisher");
        let previous = publication.reconcile(store.physical()).expect("base");
        let before_bytes = store
            .physical()
            .begin_read(SnapshotSelector::Latest)
            .expect("physical")
            .get(&space, b"value")
            .expect("before")
            .expect("present");
        let before = keys
            .observe_use_version(&space, b"value", &before_bytes, None)
            .expect("old version");
        let mut pending = PendingKeys::new();
        let ciphertext = keys
            .seal_value(&space, b"value", b"replacement", &mut pending)
            .expect("new cipher");
        let after = keys
            .observe_use_version(&space, b"value", &ciphertext, Some(&pending))
            .expect("new version");
        let marker = publication
            .prepare(
                &previous,
                &BTreeMap::from([(
                    address.clone(),
                    NativeKeyUseChange {
                        address_digest: address.clone(),
                        before: Some(before.clone()),
                        after: Some(after.clone()),
                    },
                )]),
                &pending,
            )
            .expect("prepared");
        if publish {
            let mut tx = store
                .physical()
                .begin_write()
                .expect("uncertain publication");
            tx.put(&space, b"value".to_vec(), ciphertext)
                .expect("native bytes");
            tx.put(
                &Keyspace::new(LOCAL_SPACE).expect("marker space"),
                LOCAL_HEAD.to_vec(),
                keys.seal_local_marker(&marker).expect("marker"),
            )
            .expect("native marker");
            tx.commit(Durability::Ephemeral)
                .expect("visible but not acknowledged");
        }
        let (selection, revision, digest) = selected(&keys, std::slice::from_ref(&address));
        let sequence = keys.engine.head_sequence().expect("authority");
        let pending_report = keys
            .selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
            .expect("pending report without taking publisher")
            .expect("tracked");
        assert_eq!(
            keys.engine
                .head_sequence()
                .expect("no recovery by inspection"),
            sequence
        );
        let copies = &pending_report.addresses[&address];
        assert_eq!(selection[&address].len(), 3);
        assert_eq!(copies.transitions.len(), 2);
        assert!(copies.transitions.iter().all(|change| {
            change
                .after
                .as_ref()
                .is_none_or(|version| version.key_id != unused_id)
        }));
        assert_eq!(copies.acknowledged[&previous.instance], before);
        assert_eq!(
            copies.transitions[1].transaction.outcome,
            NativeKeyUseOutcome::Prepared
        );
        assert!(copies.transitions[1].transaction.resolution.is_none());
        drop(publication);
        store
            .begin_read(SnapshotSelector::Latest)
            .expect("idle reconciliation");
        let resolved = keys
            .selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
            .expect("outcome")
            .expect("tracked");
        let copies = &resolved.addresses[&address];
        assert_eq!(
            copies.transitions[1].transaction.outcome,
            if publish {
                NativeKeyUseOutcome::Committed
            } else {
                NativeKeyUseOutcome::Aborted
            }
        );
        assert!(copies.transitions[1].transaction.resolution.is_some());
        assert_eq!(
            copies.acknowledged[&previous.instance],
            if publish { after } else { before }
        );
    }
}

#[test]
fn selected_use_enforces_budgets_and_both_frontiers_without_inventing_legacy_history() {
    let root = tempfile::tempdir().expect("root");
    let keys =
        NativeCustodyKeys::create(root.path().join("keys"), "use-selection-limits", master())
            .expect("keys");
    let store = Arc::new(
        NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native"),
    );
    let space = Keyspace::new("fixture").expect("space");
    let mut tx = store.begin_write().expect("large tx");
    for index in 0..600 {
        tx.put(
            &space,
            format!("row-{index:04}").into_bytes(),
            format!("value-{index}").into_bytes(),
        )
        .expect("row");
    }
    tx.commit(Durability::Sync).expect("three use pages");
    let wanted = [address(&space, b"row-0000"), address(&space, b"row-0599")];
    let (selection, revision, digest) = selected(&keys, &wanted);
    let complete = keys
        .selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
        .expect("multi-page replay")
        .expect("tracked");
    assert_eq!(complete.addresses.len(), 2);
    assert!(
        complete
            .addresses
            .values()
            .all(|address| address.transitions.len() == 1
                && address.transitions[0].transaction.pages == 3)
    );
    let cancelled = contextdb_recall::QueryCancellation::default();
    cancelled.cancel();
    for mut limited in [
        QueryBudget::new(0, 1024, Duration::from_secs(5), Default::default()),
        QueryBudget::new(1_000_000, 8, Duration::from_secs(5), Default::default()),
        QueryBudget::new(1_000_000, 1024 * 1024, Duration::ZERO, Default::default()),
        QueryBudget::new(1_000_000, 1024 * 1024, Duration::from_secs(5), cancelled),
    ] {
        let prior = keys.engine.head_sequence().expect("prior");
        assert_eq!(
            keys.selected_native_use_inventory(
                &selection,
                revision,
                digest.as_deref(),
                &mut limited
            )
            .expect_err("no partial result")
            .code,
            ErrorCode::BudgetExhausted
        );
        assert_eq!(keys.engine.head_sequence().expect("read only"), prior);
    }
    let clone = store.clone();
    BEFORE_INVENTORY_FRONTIER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let mut tx = clone.begin_write().expect("concurrent delete");
            tx.delete(
                &Keyspace::new("fixture").expect("space"),
                b"row-0000".to_vec(),
            )
            .expect("delete");
            tx.commit(Durability::Sync)
                .expect("native-use growth without allocation");
        }))
    });
    assert_eq!(
        keys.selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
            .expect_err("use frontier changed")
            .code,
        ErrorCode::IndexTooStale
    );
    let clone = keys.clone();
    BEFORE_INVENTORY_FRONTIER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let mut pending = PendingKeys::new();
            clone
                .seal_value(
                    &Keyspace::new("fixture").expect("space"),
                    b"unused",
                    b"unused",
                    &mut pending,
                )
                .expect("key");
            clone
                .publish(&pending)
                .expect("allocation growth without native use");
        }))
    });
    assert_eq!(
        keys.selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
            .expect_err("allocation frontier changed")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        keys.selected_native_use_inventory(&selection, revision, digest.as_deref(), &mut budget())
            .expect_err("stale initial allocation report")
            .code,
        ErrorCode::IndexTooStale
    );
    let legacy = NativeCustodyKeys::create_version(
        &root.path().join("legacy-keys"),
        "use-legacy-selection",
        master(),
        3,
    )
    .expect("legacy authority");
    assert!(
        legacy
            .selected_native_use_inventory(&BTreeMap::new(), 0, None, &mut budget())
            .expect("legacy remains explicit")
            .is_none()
    );
}
