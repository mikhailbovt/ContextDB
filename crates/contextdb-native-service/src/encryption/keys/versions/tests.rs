use super::*;
use crate::encryption::NativeStorage;

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([71; 32])).expect("fixture key")
}

#[test]
fn immutable_ciphertext_versions_preserve_old_views_and_reopen_without_reusing_keys() {
    let root = tempfile::tempdir().expect("root");
    let keys =
        NativeCustodyKeys::create(root.path().join("keys"), "versions", master()).expect("keys");
    let id = keys.authority_id();
    let store =
        NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("store");
    let space = Keyspace::new("fixture").expect("space");
    let mut tx = store.begin_write().expect("transaction");
    tx.put(
        &space,
        b"mixed".to_vec(),
        b"private plus independent".to_vec(),
    )
    .expect("old value");
    tx.commit(Durability::Sync).expect("old commit");
    let before = store
        .begin_read(SnapshotSelector::Latest)
        .expect("old snapshot");
    let old_ciphertext = before
        .inner
        .get(&space, b"mixed")
        .expect("ciphertext")
        .expect("row");
    let mut tx = store.begin_write().expect("transaction");
    tx.put(&space, b"mixed".to_vec(), b"independent".to_vec())
        .expect("rebuilt value");
    tx.commit(Durability::Sync).expect("new commit");
    let after = store
        .begin_read(SnapshotSelector::Latest)
        .expect("new snapshot");
    let new_ciphertext = after
        .inner
        .get(&space, b"mixed")
        .expect("ciphertext")
        .expect("row");
    let old_id = Uuid::from_slice(&old_ciphertext[VALUE_MAGIC.len()..VALUE_MAGIC.len() + 16])
        .expect("old ID");
    let new_id = Uuid::from_slice(&new_ciphertext[VALUE_MAGIC.len()..VALUE_MAGIC.len() + 16])
        .expect("new ID");
    assert_ne!(old_id, new_id);
    assert_eq!(
        before.get(&space, b"mixed").expect("old view"),
        Some(b"private plus independent".to_vec())
    );
    assert_eq!(
        after.get(&space, b"mixed").expect("new view"),
        Some(b"independent".to_vec())
    );
    let replica =
        NativeStorage::open(&root.path().join("replica"), Some(keys.clone())).expect("replica");
    let mut tx = replica.begin_write().expect("replica transaction");
    tx.put(
        &space,
        b"mixed".to_vec(),
        b"another retained version".to_vec(),
    )
    .expect("replica version");
    tx.commit(Durability::Sync)
        .expect("distinct key at the same logical address");
    assert_eq!(
        store
            .begin_read(SnapshotSelector::Latest)
            .expect("current view")
            .get(&space, b"mixed")
            .expect("current value"),
        Some(b"independent".to_vec())
    );
    let key_snapshot = keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("key snapshot");
    assert_eq!(
        key_snapshot
            .scan_prefix(&keys.rows, b"key/")
            .expect("key versions")
            .len(),
        3
    );
    keys.verify().expect("closed key history");
    drop((before, after, key_snapshot, store, replica, keys));
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "versions", id, master())
        .expect("retained versions reopen");
    assert_eq!(
        keys.open_value(&space, b"mixed", &old_ciphertext, None)
            .expect("old ciphertext retained"),
        b"private plus independent"
    );
    assert_eq!(
        keys.open_value(&space, b"mixed", &new_ciphertext, None)
            .expect("new ciphertext"),
        b"independent"
    );
    assert!(
        keys.open_value(&space, b"other", &old_ciphertext, None)
            .is_err()
    );
}

#[test]
fn authenticated_ciphertext_import_keeps_key_identity_without_an_allocation_batch() {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "cipher-import", master())
        .expect("keys");
    let source =
        NativeStorage::open(&root.path().join("source"), Some(keys.clone())).expect("source");
    let target =
        NativeStorage::open(&root.path().join("target"), Some(keys.clone())).expect("target");
    let space = Keyspace::new("fixture").expect("space");
    let mut tx = source.begin_write().expect("transaction");
    tx.put(&space, b"saved".to_vec(), b"original".to_vec())
        .expect("value");
    tx.commit(Durability::Sync).expect("commit");
    let snapshot = source
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let cipher = snapshot
        .inner
        .get(&space, b"saved")
        .expect("ciphertext")
        .expect("row");
    let key_sequence = keys.engine.head_sequence().expect("key head");
    let mut tx = target.begin_write().expect("transaction");
    assert!(
        tx.put_ciphertext(&space, b"wrong-address".to_vec(), cipher.clone())
            .is_err()
    );
    let mut corrupt = cipher.clone();
    *corrupt.last_mut().expect("tag") ^= 1;
    assert!(
        tx.put_ciphertext(&space, b"saved".to_vec(), corrupt)
            .is_err()
    );
    tx.put_ciphertext(&space, b"saved".to_vec(), cipher.clone())
        .expect("authenticated import");
    tx.commit(Durability::Sync).expect("commit");
    assert_eq!(
        keys.engine.head_sequence().expect("same key inventory"),
        key_sequence
    );
    let restored = target.begin_read(SnapshotSelector::Latest).expect("view");
    assert_eq!(
        restored.inner.get(&space, b"saved").expect("ciphertext"),
        Some(cipher)
    );
    assert_eq!(
        restored.get(&space, b"saved").expect("plaintext"),
        Some(b"original".to_vec())
    );
    assert!(
        restored
            .get(&space, b"wrong-address")
            .expect("no rejected row")
            .is_none()
    );
}

#[test]
fn versioned_key_journal_rejects_lost_replayed_forged_or_orphaned_allocations() {
    for damage in [
        "head",
        "batch",
        "version",
        "head-replay",
        "record",
        "orphan",
    ] {
        let root = tempfile::tempdir().expect("root");
        let keys =
            NativeCustodyKeys::create(root.path().join("keys"), "damaged-versions", master())
                .expect("keys");
        let initial = keys
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        let genesis = initial
            .get(&keys.rows, HEAD)
            .expect("head")
            .expect("genesis");
        let space = Keyspace::new("fixture").expect("space");
        let mut pending = PendingKeys::new();
        keys.seal_value(&space, b"first", b"old value", &mut pending)
            .expect("stage");
        keys.publish(&pending).expect("allocate");
        let row = version_key(
            &address(&space, b"first"),
            pending.values().next().expect("key").record.id,
        );
        let mut tx = keys.engine.begin_write().expect("transaction");
        match damage {
            "head" => tx.delete(&keys.rows, HEAD.to_vec()).expect("head"),
            "batch" => tx.delete(&keys.rows, batch_key(1)).expect("batch"),
            "version" => tx.delete(&keys.rows, row.clone()).expect("version"),
            "head-replay" => tx
                .put(&keys.rows, HEAD.to_vec(), genesis)
                .expect("old head"),
            "record" => tx
                .put(&keys.rows, row.clone(), b"{}".to_vec())
                .expect("changed key"),
            "orphan" => tx
                .put(&keys.rows, b"key/orphan".to_vec(), b"{}".to_vec())
                .expect("orphan"),
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("damage");
        assert!(keys.verify().is_err(), "{damage}");
        if matches!(damage, "head" | "batch" | "head-replay") {
            let before = keys.engine.head_sequence().expect("head");
            let mut next = PendingKeys::new();
            keys.seal_value(&space, b"next", b"next value", &mut next)
                .expect("stage another key");
            assert!(keys.publish(&next).is_err(), "{damage}");
            assert_eq!(keys.engine.head_sequence().expect("unchanged"), before);
        }
    }
}
