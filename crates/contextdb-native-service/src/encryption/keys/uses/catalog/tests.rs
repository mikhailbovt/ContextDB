use super::*;
use crate::encryption::NativeStorage;

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([64; 32])).expect("master")
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        64 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        Default::default(),
    )
}

fn catalog(keys: &NativeCustodyKeys, events: u32) -> Vec<NativeKeyUseTransaction> {
    let mut result = Vec::new();
    let mut cursor = None;
    loop {
        let page = keys
            .native_use_catalog_page(cursor.as_deref(), events, &mut budget())
            .expect("catalog page");
        result.extend(page.transactions);
        cursor = page.continuation;
        if cursor.is_none() {
            return result;
        }
    }
}

#[test]
fn native_use_catalog_pages_cover_exact_changes_and_preserve_cursors_across_reopen() {
    let root = tempfile::tempdir().expect("root");
    let keys =
        NativeCustodyKeys::create(root.path().join("keys"), "use-catalog", master()).expect("keys");
    let id = keys.authority_id();
    let store =
        NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native");
    let space = Keyspace::new("fixture").expect("space");
    let mut tx = store.begin_write().expect("tx");
    for index in 0..600 {
        tx.put(
            &space,
            format!("row-{index:04}").into_bytes(),
            format!("source value {index}").into_bytes(),
        )
        .expect("stage");
    }
    tx.commit(Durability::Sync).expect("publish");
    let first = keys
        .native_use_catalog_page(None, 1, &mut budget())
        .expect("register page");
    assert!(first.transactions.is_empty());
    let cursor = first.continuation.expect("empty page still continues");
    let transactions = catalog(&keys, 1);
    assert_eq!(transactions.len(), 1);
    let transaction = &transactions[0];
    assert_eq!(transaction.outcome, NativeKeyUseOutcome::Committed);
    assert!(transaction.resolution.is_some());
    assert_eq!((transaction.pages, transaction.changed_addresses), (3, 600));
    let physical = store
        .physical()
        .begin_read(SnapshotSelector::Latest)
        .expect("physical");
    let mut actual = BTreeMap::new();
    for index in 0..transaction.pages {
        let page = keys
            .native_use_changes_page(&transaction.preparation, index, &mut budget())
            .expect("changes");
        assert_eq!(page.transaction, *transaction);
        for change in page.changes {
            assert!(
                actual
                    .insert(change.address_digest.clone(), change)
                    .is_none()
            );
        }
    }
    for index in 0..600 {
        let key = format!("row-{index:04}").into_bytes();
        let ciphertext = physical
            .get(&space, &key)
            .expect("physical row")
            .expect("present");
        let observed = keys
            .observe_use_version(&space, &key, &ciphertext, None)
            .expect("observed version");
        let change = actual
            .remove(&address(&space, &key))
            .expect("covered address");
        assert!(change.before.is_none());
        assert_eq!(change.after, Some(observed));
    }
    assert!(actual.is_empty());
    // Independent allocation does not modify the native-use frontier.
    let mut unused = PendingKeys::new();
    keys.seal_value(&space, b"unused", b"not a native publication", &mut unused)
        .expect("allocate");
    keys.publish(&unused).expect("independent allocation");
    keys.native_use_catalog_page(Some(&cursor), 1, &mut budget())
        .expect("allocation permits continuation");
    drop((unused, physical, store, keys));
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "use-catalog", id, master())
        .expect("reopen authority");
    keys.native_use_catalog_page(Some(&cursor), 1, &mut budget())
        .expect("same authority continuation");
    assert_eq!(catalog(&keys, 64), transactions);
    let before = keys.engine.head_sequence().expect("read-only frontier");
    assert!(
        keys.native_use_catalog_page(None, 0, &mut budget())
            .is_err()
    );
    assert!(
        keys.native_use_catalog_page(None, 65, &mut budget())
            .is_err()
    );
    let mut forged = cursor.clone();
    *forged.last_mut().expect("tag") ^= 1;
    assert!(
        keys.native_use_catalog_page(Some(&forged), 1, &mut budget())
            .is_err()
    );
    assert!(
        keys.native_use_changes_page(&transaction.preparation, 3, &mut budget())
            .is_err()
    );
    assert!(
        keys.native_use_catalog_page(
            None,
            64,
            &mut QueryBudget::new(1, 1, std::time::Duration::from_secs(1), Default::default())
        )
        .is_err()
    );
    assert_eq!(keys.engine.head_sequence().expect("no writes"), before);
    let store = NativeStorage::open(&root.path().join("native"), Some(keys.clone()))
        .expect("reopen native");
    let mut tx = store.begin_write().expect("later tx");
    tx.delete(&space, b"row-0000".to_vec()).expect("delete");
    tx.commit(Durability::Sync).expect("later native use");
    assert_eq!(
        keys.native_use_catalog_page(Some(&cursor), 1, &mut budget())
            .expect_err("changed use history")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        keys.native_use_changes_page(&transaction.preparation, 0, &mut budget())
            .expect("old use remains readable")
            .transaction,
        *transaction
    );
}

fn prepare(
    keys: &NativeCustodyKeys,
    store: &NativeStorage,
    space: &Keyspace,
    value: &[u8],
) -> (LocalMarker, Vec<u8>) {
    let publication = keys.use_publication().expect("guard");
    let previous = publication.reconcile(store.physical()).expect("base");
    let physical = store
        .physical()
        .begin_read(SnapshotSelector::Latest)
        .expect("physical");
    let before = physical
        .get(space, b"value")
        .expect("preimage")
        .map(|value| {
            keys.observe_use_version(space, b"value", &value, None)
                .expect("version")
        });
    let mut pending = PendingKeys::new();
    let ciphertext = keys
        .seal_value(space, b"value", value, &mut pending)
        .expect("ciphertext");
    let after = keys
        .observe_use_version(space, b"value", &ciphertext, Some(&pending))
        .expect("new version");
    let address_digest = address(space, b"value");
    let changes = BTreeMap::from([(
        address_digest.clone(),
        NativeKeyUseChange {
            address_digest,
            before,
            after: Some(after),
        },
    )]);
    let marker = publication
        .prepare(&previous, &changes, &pending)
        .expect("independent preparation");
    (marker, ciphertext)
}

#[test]
fn native_use_outcomes_distinguish_pending_aborted_and_synchronized_recovery() {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "use-outcomes", master())
        .expect("keys");
    let id = keys.authority_id();
    let store =
        NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native");
    let space = Keyspace::new("fixture").expect("space");
    let (marker, ciphertext) = prepare(&keys, &store, &space, b"accepted during uncertain Sync");
    let pending = catalog(&keys, 64).pop().expect("pending transaction");
    assert_eq!(pending.outcome, NativeKeyUseOutcome::Prepared);
    assert!(pending.resolution.is_none());
    let mut native = store
        .physical()
        .begin_write()
        .expect("ambiguous native result fixture");
    native
        .put(&space, b"value".to_vec(), ciphertext)
        .expect("native data");
    native
        .put(
            &Keyspace::new(LOCAL_SPACE).expect("marker space"),
            LOCAL_HEAD.to_vec(),
            keys.seal_local_marker(&marker).expect("marker"),
        )
        .expect("native marker");
    native
        .commit(Durability::Ephemeral)
        .expect("visible but not yet acknowledged durable");
    assert_eq!(
        catalog(&keys, 64).pop().expect("still pending").outcome,
        NativeKeyUseOutcome::Prepared
    );
    let sequence = store
        .physical()
        .head_sequence()
        .expect("visible native sequence");
    store
        .begin_read(SnapshotSelector::Latest)
        .expect("recovery synchronizes existing journal");
    assert_eq!(
        store
            .physical()
            .head_sequence()
            .expect("no rewritten transaction"),
        sequence
    );
    assert_eq!(
        catalog(&keys, 64).pop().expect("committed").outcome,
        NativeKeyUseOutcome::Committed
    );
    prepare(&keys, &store, &space, b"never published replacement");
    let last = catalog(&keys, 64).pop().expect("new pending");
    assert_eq!(last.outcome, NativeKeyUseOutcome::Prepared);
    store
        .begin_read(SnapshotSelector::Latest)
        .expect("recover unchanged base");
    assert_eq!(
        store
            .physical()
            .head_sequence()
            .expect("same native commit"),
        sequence
    );
    let transactions = catalog(&keys, 64);
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0].outcome, NativeKeyUseOutcome::Committed);
    assert_eq!(transactions[1].outcome, NativeKeyUseOutcome::Aborted);
    let page = keys
        .native_use_changes_page(&last.preparation, 0, &mut budget())
        .expect("aborted prepared versions remain explicit");
    assert_eq!(page.transaction.outcome, NativeKeyUseOutcome::Aborted);
    assert_ne!(
        page.changes[0]
            .before
            .as_ref()
            .expect("accepted preimage")
            .key_id,
        page.changes[0]
            .after
            .as_ref()
            .expect("unused new allocation")
            .key_id
    );
    keys.verify().expect("complete native-use replay");
    drop((store, keys));
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "use-outcomes", id, master())
        .expect("key reopen");
    let store = NativeStorage::open(&root.path().join("native"), Some(keys.clone()))
        .expect("native reopen");
    assert_eq!(
        store
            .begin_read(SnapshotSelector::Latest)
            .expect("view")
            .get(&space, b"value")
            .expect("durable original"),
        Some(b"accepted during uncertain Sync".to_vec())
    );
    assert_eq!(catalog(&keys, 64), transactions);
}

#[test]
fn native_use_catalog_rejects_missing_history_and_deep_replay_rejects_false_preimages() {
    for damage in [
        "head",
        "head-replay",
        "page",
        "outcome",
        "instance",
        "instance-reference",
        "false-preimage",
    ] {
        let root = tempfile::tempdir().expect("root");
        let keys = NativeCustodyKeys::create(root.path().join("keys"), "use-damage", master())
            .expect("keys");
        let store =
            NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native");
        let space = Keyspace::new("fixture").expect("space");
        let registered = keys
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("registered state");
        let initial_head = registered
            .get(&keys.rows, HEAD)
            .expect("head")
            .expect("genesis");
        drop(registered);
        for value in [b"first".as_slice(), b"second".as_slice()] {
            let mut tx = store.begin_write().expect("tx");
            tx.put(&space, b"value".to_vec(), value.to_vec())
                .expect("value");
            tx.commit(Durability::Sync).expect("commit");
        }
        let transaction = catalog(&keys, 64).pop().expect("transaction");
        let prepared = transaction.preparation.sequence;
        let completed = transaction.resolution.as_ref().expect("committed").sequence;
        let mut tx = keys.engine.begin_write().expect("damage fixture");
        match damage {
            "head" => tx.delete(&keys.rows, HEAD.to_vec()).expect("remove head"),
            "head-replay" => tx
                .put(&keys.rows, HEAD.to_vec(), initial_head)
                .expect("replay old head"),
            "page" => tx
                .delete(&keys.rows, event_key(prepared - 1))
                .expect("remove page"),
            "outcome" => tx
                .delete(&keys.rows, outcome_key(prepared))
                .expect("remove outcome"),
            "instance" => tx
                .delete(&keys.rows, state_key(transaction.native_instance))
                .expect("remove instance"),
            "instance-reference" => {
                let state = keys
                    .use_state(&tx, transaction.native_instance)
                    .expect("state");
                tx.delete(
                    &keys.rows,
                    instance_key(transaction.native_instance, state.revision),
                )
                .expect("remove reference");
            }
            "false-preimage" => {
                let mut page = keys.use_event(&tx, prepared - 1).expect("page");
                let UseOperation::Page { changes, .. } = &mut page.change else {
                    panic!("page");
                };
                changes[0]
                    .before
                    .as_mut()
                    .expect("prior version")
                    .value_digest = "0".repeat(64);
                page.checkpoint.digest = Some(page.digest().expect("rehash page"));
                let mut preparation = keys.use_event(&tx, prepared).expect("preparation");
                preparation.previous_digest = page.checkpoint.digest.clone();
                preparation.checkpoint.digest =
                    Some(preparation.digest().expect("rehash preparation"));
                let mut complete = keys.use_event(&tx, completed).expect("complete");
                complete.previous_digest = preparation.checkpoint.digest.clone();
                let UseOperation::Complete {
                    prepared: reference,
                    ..
                } = &mut complete.change
                else {
                    panic!("complete");
                };
                *reference = preparation.checkpoint.clone();
                complete.checkpoint.digest = Some(complete.digest().expect("rehash outcome"));
                let mut state = keys
                    .use_state(&tx, transaction.native_instance)
                    .expect("original state");
                state.accepted = complete.checkpoint.clone();
                state.marker.usage = Some(preparation.checkpoint.clone());
                for event in [&page, &preparation, &complete] {
                    let key = event_key(event.checkpoint.sequence);
                    tx.put(
                        &keys.rows,
                        key.clone(),
                        keys.seal_use(&key, &encode(event).expect("event"), "journal")
                            .expect("reseal event"),
                    )
                    .expect("write event");
                }
                for (key, value) in [
                    (HEAD.to_vec(), encode(&complete.checkpoint).expect("head")),
                    (
                        state_key(transaction.native_instance),
                        encode(&state).expect("state"),
                    ),
                    (
                        instance_key(transaction.native_instance, state.revision - 1),
                        encode(&preparation.checkpoint).expect("prepare reference"),
                    ),
                    (
                        instance_key(transaction.native_instance, state.revision),
                        encode(&complete.checkpoint).expect("complete reference"),
                    ),
                    (
                        outcome_key(prepared),
                        encode(&complete.checkpoint).expect("outcome"),
                    ),
                ] {
                    tx.put(
                        &keys.rows,
                        key.clone(),
                        keys.seal_use(&key, &value, "journal")
                            .expect("reseal index"),
                    )
                    .expect("write index");
                }
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("inject corruption");
        assert!(
            keys.verify().is_err(),
            "{damage}: complete replay must fail"
        );
        if !matches!(damage, "instance" | "instance-reference" | "false-preimage") {
            assert!(
                keys.native_use_catalog_page(None, 64, &mut budget())
                    .is_err(),
                "{damage}: catalog must not hide missing evidence"
            );
        }
        assert!(
            keys.native_use_changes_page(&transaction.preparation, 0, &mut budget())
                .is_err()
                || matches!(damage, "instance" | "instance-reference"),
            "{damage}: known receipt must not acquire another page"
        );
    }
}
