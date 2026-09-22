use super::*;
use crate::encryption::NativeStorage;

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([63; 32])).expect("master")
}

fn latest_changes(
    keys: &NativeCustodyKeys,
    store: &NativeStorage,
) -> (LocalMarker, Vec<NativeKeyUseChange>) {
    let native = store
        .physical()
        .begin_read(SnapshotSelector::Latest)
        .expect("physical");
    let marker = keys.read_local_marker(&native).expect("marker");
    let view = keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("authority");
    let checkpoint = marker.usage.clone().expect("accepted use");
    let event = keys
        .use_event(&view, checkpoint.sequence)
        .expect("preparation");
    let UseOperation::Prepare { preparation } = event.change else {
        panic!("prepare");
    };
    let mut changes = Vec::new();
    keys.visit_use_changes(
        &view,
        &PendingUse {
            preparation,
            checkpoint,
        },
        |change| {
            changes.push(change);
            Ok(())
        },
    )
    .expect("exact pages");
    assert!(
        keys.use_state(&view, marker.instance)
            .expect("state")
            .pending
            .is_none()
    );
    (marker, changes)
}

#[test]
fn tracked_native_use_preserves_final_versions_preimages_imports_and_reopen() {
    let root = tempfile::tempdir().expect("root");
    let keys =
        NativeCustodyKeys::create(root.path().join("keys"), "tracked", master()).expect("keys");
    let id = keys.authority_id();
    let store =
        NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native");
    let space = Keyspace::new("fixture").expect("space");
    let mut tx = store.begin_write().expect("tx");
    tx.put(&space, b"value".to_vec(), b"intermediate".to_vec())
        .expect("first staged value");
    tx.put(
        &space,
        b"value".to_vec(),
        b"private and independent".to_vec(),
    )
    .expect("final value");
    tx.put(&space, b"discarded".to_vec(), b"never committed".to_vec())
        .expect("staged");
    tx.delete(&space, b"discarded".to_vec())
        .expect("discard before commit");
    tx.commit(Durability::Sync).expect("native commit");
    let old = store
        .begin_read(SnapshotSelector::Latest)
        .expect("old view");
    let cipher = old
        .inner
        .get(&space, b"value")
        .expect("cipher")
        .expect("present");
    let (first_marker, first) = latest_changes(&keys, &store);
    let address = address(&space, b"value");
    let first = first
        .iter()
        .find(|change| change.address_digest == address)
        .expect("value transition");
    assert!(first.before.is_none());
    let version = first.after.clone().expect("committed version");
    assert_eq!(version.ciphertext_digest, crate::digest_bytes(&cipher));
    assert_eq!(
        version.value_digest,
        crate::digest_bytes(b"private and independent")
    );

    let mut tx = store.begin_write().expect("rewrite");
    tx.put(&space, b"value".to_vec(), b"independent".to_vec())
        .expect("cleaned replacement");
    tx.commit(Durability::Sync).expect("replacement");
    let (_, changes) = latest_changes(&keys, &store);
    assert_eq!(changes[0].before, Some(version.clone()));
    assert_ne!(
        changes[0].after.as_ref().expect("new key").key_id,
        version.key_id
    );
    let cleaned = changes[0].after.clone();
    let mut tx = store.begin_write().expect("delete");
    tx.delete(&space, b"value".to_vec()).expect("delete");
    tx.commit(Durability::Sync).expect("logical deletion");
    let (_, changes) = latest_changes(&keys, &store);
    assert_eq!(changes[0].before, cleaned);
    assert!(changes[0].after.is_none());
    assert_eq!(
        old.get(&space, b"value").expect("old lease"),
        Some(b"private and independent".to_vec())
    );

    let replica =
        NativeStorage::open(&root.path().join("replica"), Some(keys.clone())).expect("replica");
    let mut tx = replica.begin_write().expect("import");
    tx.put_ciphertext(&space, b"value".to_vec(), cipher.clone())
        .expect("authenticated import");
    tx.commit(Durability::Sync).expect("import commit");
    let (replica_marker, changes) = latest_changes(&keys, &replica);
    assert_ne!(replica_marker.instance, first_marker.instance);
    assert_eq!(changes[0].before, None);
    assert_eq!(changes[0].after, Some(version));
    keys.verify().expect("complete version/use histories");
    let bytes = encode(&changes).expect("content-free metadata");
    assert!(
        !String::from_utf8(bytes)
            .expect("json")
            .contains("private and independent")
    );
    drop((old, store, replica, keys));
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "tracked", id, master())
        .expect("key authority reopen");
    let replica = NativeStorage::open(&root.path().join("replica"), Some(keys.clone()))
        .expect("native reopen");
    assert_eq!(
        replica
            .begin_read(SnapshotSelector::Latest)
            .expect("read")
            .get(&space, b"value")
            .expect("original"),
        Some(b"private and independent".to_vec())
    );
    assert_eq!(latest_changes(&keys, &replica).0, replica_marker);
}

#[test]
fn tracked_native_use_rejects_untracked_physical_writes_and_lost_markers() {
    for remove_marker in [false, true] {
        let root = tempfile::tempdir().expect("root");
        let keys = NativeCustodyKeys::create(root.path().join("keys"), "untracked", master())
            .expect("keys");
        let store =
            NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native");
        let space = Keyspace::new("fixture").expect("space");
        let mut tx = store.begin_write().expect("tx");
        tx.put(&space, b"value".to_vec(), b"accepted".to_vec())
            .expect("value");
        let accepted = tx.commit(Durability::Sync).expect("commit");
        let external = keys.engine.head_sequence().expect("authority head");
        let mut fault = store.physical().begin_write().expect("fault");
        if remove_marker {
            fault
                .delete(
                    &Keyspace::new(LOCAL_SPACE).expect("control space"),
                    LOCAL_HEAD.to_vec(),
                )
                .expect("remove marker");
        } else {
            fault
                .put(
                    &space,
                    b"untracked".to_vec(),
                    b"untracked ciphertext".to_vec(),
                )
                .expect("untracked mutation");
        }
        fault.commit(Durability::Sync).expect("fault commit");
        assert!(store.begin_read(SnapshotSelector::Latest).is_err());
        assert!(
            store
                .begin_read(SnapshotSelector::At(accepted.sequence))
                .is_err()
        );
        assert!(store.begin_write().is_err());
        assert_eq!(
            keys.engine.head_sequence().expect("no repair guess"),
            external
        );
        drop(store);
        assert!(NativeStorage::open(&root.path().join("native"), Some(keys)).is_err());
    }
}

#[test]
fn native_use_admission_rejects_a_whole_physical_rollback() {
    fn copy_closed_fixture(source: &Path, target: &Path) {
        std::fs::create_dir(target).expect("copy directory");
        for entry in std::fs::read_dir(source).expect("closed fixture") {
            let entry = entry.expect("entry");
            let target = target.join(entry.file_name());
            if entry.file_type().expect("type").is_dir() {
                copy_closed_fixture(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).expect("copy file");
            }
        }
    }
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "physical-rollback", master())
        .expect("keys");
    let native = root.path().join("native");
    let old = root.path().join("old-copy");
    let space = Keyspace::new("fixture").expect("space");
    let store = NativeStorage::open(&native, Some(keys.clone())).expect("native");
    let mut tx = store.begin_write().expect("first");
    tx.put(&space, b"value".to_vec(), b"old".to_vec())
        .expect("value");
    tx.commit(Durability::Sync).expect("first commit");
    drop(store);
    copy_closed_fixture(&native, &old);
    let store = NativeStorage::open(&native, Some(keys.clone())).expect("reopen");
    let old_snapshot = store
        .physical()
        .begin_read(SnapshotSelector::Latest)
        .expect("old retained view");
    let mut tx = store.begin_write().expect("second");
    tx.put(&space, b"value".to_vec(), b"new".to_vec())
        .expect("value");
    tx.commit(Durability::Sync).expect("second commit");
    keys.admit_use_snapshot(store.physical(), &old_snapshot)
        .expect("historical view of current storage remains valid");
    let external = keys.engine.head_sequence().expect("authority");
    let rolled_back = FjallStorage::open(&old).expect("valid older physical storage");
    let view = rolled_back
        .begin_read(SnapshotSelector::Latest)
        .expect("old marker and data");
    assert!(keys.admit_use_snapshot(&rolled_back, &view).is_err());
    drop((view, rolled_back));
    assert!(NativeStorage::open(&old, Some(keys.clone())).is_err());
    assert_eq!(
        keys.engine.head_sequence().expect("no guessed repair"),
        external
    );
    keys.verify().expect("retained authority remains complete");
}

#[test]
fn native_key_use_crash_after_native_sync_child() {
    let Some(root) = std::env::var_os("CONTEXTDB_USE_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let key_id = std::env::var("CONTEXTDB_USE_CRASH_ID")
        .expect("ID")
        .parse()
        .expect("UUID");
    let keys =
        NativeCustodyKeys::open(root.join("keys"), "use-crash", key_id, master()).expect("keys");
    let store = NativeStorage::open(&root.join("native"), Some(keys)).expect("native");
    storage::AFTER_NATIVE_COMMIT
        .with(|hook| *hook.borrow_mut() = Some(Box::new(|| std::process::exit(75))));
    let mut tx = store.begin_write().expect("tx");
    tx.put(
        &Keyspace::new("fixture").expect("space"),
        b"value".to_vec(),
        b"durable despite lost ack".to_vec(),
    )
    .expect("value");
    tx.commit(Durability::Sync)
        .expect("crash before external acknowledgement");
    panic!("crash hook not reached");
}

#[test]
fn native_key_use_recovers_lost_ack_after_actual_native_sync_without_rewriting_data() {
    let root = tempfile::tempdir().expect("root");
    let keys =
        NativeCustodyKeys::create(root.path().join("keys"), "use-crash", master()).expect("keys");
    let id = keys.authority_id();
    let store =
        NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native");
    drop((store, keys));
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "encryption::keys::uses::tests::native_key_use_crash_after_native_sync_child",
            "--nocapture",
        ])
        .env("CONTEXTDB_USE_CRASH_ROOT", root.path())
        .env("CONTEXTDB_USE_CRASH_ID", id.to_string())
        .status()
        .expect("child");
    assert_eq!(status.code(), Some(75));
    let keys = NativeCustodyKeys::open(root.path().join("keys"), "use-crash", id, master())
        .expect("pending use is retained");
    let physical = FjallStorage::open(root.path().join("native")).expect("raw native");
    let before = physical
        .head_sequence()
        .expect("committed physical sequence");
    let marker = keys
        .read_local_marker(
            &physical
                .begin_read(SnapshotSelector::Latest)
                .expect("raw view"),
        )
        .expect("committed marker");
    let authority = keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("authority view");
    assert!(
        keys.use_state(&authority, marker.instance)
            .expect("pending")
            .pending
            .is_some()
    );
    drop((authority, physical));
    let store = NativeStorage::open(&root.path().join("native"), Some(keys.clone()))
        .expect("recover acknowledgement");
    assert_eq!(
        store
            .physical()
            .head_sequence()
            .expect("same native sequence"),
        before
    );
    assert_eq!(latest_changes(&keys, &store).0, marker);
    assert_eq!(
        store
            .begin_read(SnapshotSelector::Latest)
            .expect("read")
            .get(&Keyspace::new("fixture").expect("space"), b"value")
            .expect("value"),
        Some(b"durable despite lost ack".to_vec())
    );
    let acknowledged = keys.engine.head_sequence().expect("acknowledged");
    store
        .begin_read(SnapshotSelector::Latest)
        .expect("idempotent read");
    assert_eq!(
        keys.engine
            .head_sequence()
            .expect("no duplicate acknowledgement"),
        acknowledged
    );
    keys.verify()
        .expect("complete independently retained use history");
}

#[test]
fn acknowledged_native_reads_do_not_wait_for_the_custody_writer() {
    for stage in 0..3 {
        let root = tempfile::tempdir().expect("root");
        let keys = NativeCustodyKeys::create(root.path().join("keys"), "use-read", master())
            .expect("keys");
        let store = Arc::new(
            NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("native"),
        );
        let space = Keyspace::new("fixture").expect("space");
        let mut tx = store.begin_write().expect("tx");
        tx.put(&space, b"value".to_vec(), b"already acknowledged".to_vec())
            .expect("value");
        tx.commit(Durability::Sync).expect("commit");
        let historical = store
            .physical()
            .begin_read(SnapshotSelector::Latest)
            .expect("old physical view");
        let held = keys
            .use_publication()
            .expect("another custody publication owns the writer");
        if stage != 0 {
            let previous = held.reconcile(store.physical()).expect("base");
            let marker = held
                .prepare(&previous, &BTreeMap::new(), &PendingKeys::new())
                .expect("pending next publication");
            if stage == 2 {
                let mut native = store.physical().begin_write().expect("native fixture");
                native
                    .put(
                        &Keyspace::new(LOCAL_SPACE).expect("space"),
                        LOCAL_HEAD.to_vec(),
                        keys.seal_local_marker(&marker).expect("marker"),
                    )
                    .expect("visible marker");
                native
                    .commit(Durability::Ephemeral)
                    .expect("unacknowledged view");
            }
        }
        let authority_sequence = keys.engine.head_sequence().expect("before read");
        let (send, receive) = std::sync::mpsc::channel();
        let reader_store = store.clone();
        let reader = std::thread::spawn(move || {
            let result = reader_store
                .begin_read(SnapshotSelector::Latest)
                .and_then(|view| view.get(&space, b"value"));
            send.send(result).expect("reader result");
        });
        let result = receive.recv_timeout(std::time::Duration::from_secs(3));
        let after_read = keys.engine.head_sequence().expect("after read");
        drop(held);
        reader.join().expect("reader joins");
        let result = result.expect("read admission must finish while the writer remains held");
        if stage == 2 {
            let error = crate::storage_error(result.expect_err("unacknowledged view stays closed"));
            assert_eq!(error.code, contextdb_service::ErrorCode::Unavailable);
            assert!(error.retryable);
        } else {
            assert_eq!(
                result.expect("acknowledged read"),
                Some(b"already acknowledged".to_vec())
            );
        }
        assert_eq!(
            after_read, authority_sequence,
            "reader never takes over an active publication"
        );
        keys.admit_use_snapshot(store.physical(), &historical)
            .expect("old accepted snapshot remains admissible across recovery");
        store
            .begin_read(SnapshotSelector::Latest)
            .expect("recovery when idle");
        keys.verify().expect("valid outcomes after contention");
    }
}
