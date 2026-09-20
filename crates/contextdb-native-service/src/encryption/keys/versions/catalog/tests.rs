use std::time::Duration;

use contextdb_recall::QueryCancellation;

use super::*;
use crate::encryption::NativeStorage;

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([91; 32])).expect("fixture master")
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        100_000,
        64 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

fn allocate(keys: &NativeCustodyKeys, start: usize, count: usize) {
    let space = Keyspace::new("fixture").expect("space");
    let mut pending = PendingKeys::new();
    for value in start..start + count {
        keys.seal_value(
            &space,
            format!("key-{value}").as_bytes(),
            b"unused allocation",
            &mut pending,
        )
        .expect("stage key");
    }
    keys.publish(&pending).expect("accepted allocation batch");
}

#[test]
fn key_catalog_covers_historical_and_unused_allocations_across_pages_backup_and_reopen() {
    let root = tempfile::tempdir().expect("root");
    let keys =
        NativeCustodyKeys::create(root.path().join("keys"), "key-catalog", master()).expect("keys");
    let authority = keys.authority_id();
    let store =
        NativeStorage::open(&root.path().join("native"), Some(keys.clone())).expect("store");
    let space = Keyspace::new("fixture").expect("space");
    let empty = keys
        .key_catalog_page(None, 2, &mut budget())
        .expect("empty catalog");
    assert_eq!(empty.revision, 0);
    assert!(
        empty.entries.is_empty() && empty.continuation.is_none() && empty.revision_digest.is_none()
    );
    let mut tx = store.begin_write().expect("transaction");
    for key in [b"a", b"b", b"c"] {
        tx.put(
            &space,
            key.to_vec(),
            b"private original plus independent data".to_vec(),
        )
        .expect("original");
    }
    tx.commit(Durability::Sync).expect("first batch");
    let old = store
        .begin_read(SnapshotSelector::Latest)
        .expect("old view");
    let original = old.inner.get(&space, b"a").expect("cipher").expect("row");
    let original_id =
        Uuid::from_slice(&original[VALUE_MAGIC.len()..VALUE_MAGIC.len() + 16]).expect("key ID");
    let mut tx = store.begin_write().expect("transaction");
    for key in [b"a", b"b"] {
        tx.put(&space, key.to_vec(), b"independent data".to_vec())
            .expect("replacement");
    }
    tx.commit(Durability::Sync).expect("second batch");
    let current = store
        .begin_read(SnapshotSelector::Latest)
        .expect("current view");
    let replaced = current
        .inner
        .get(&space, b"a")
        .expect("cipher")
        .expect("row");
    let replaced_id =
        Uuid::from_slice(&replaced[VALUE_MAGIC.len()..VALUE_MAGIC.len() + 16]).expect("key ID");
    // Key Sync can precede an interrupted native publication. Such an allocation
    // remains in the catalog; a missing current native row cannot prove non-use.
    allocate(&keys, 100, 1);
    let first = keys
        .key_catalog_page(None, 2, &mut budget())
        .expect("first page");
    assert_eq!((first.revision, first.entries.len()), (3, 2));
    assert!(first.continuation.is_some());
    // This isolated registry fixture changes the key-store commit but allocates
    // no data keys. Real archive registration is covered by the backup tests.
    keys.register_backup(
        &crate::digest_bytes(b"catalog archive"),
        1,
        &crate::digest_bytes(b"catalog logical fixture"),
        64,
    )
    .expect("backup registration");
    let second = keys
        .key_catalog_page(first.continuation.as_deref(), 2, &mut budget())
        .expect("second page");
    assert_eq!(second.revision_digest, first.revision_digest);
    drop((old, current, store, keys));
    let keys =
        NativeCustodyKeys::open(root.path().join("keys"), "key-catalog", authority, master())
            .expect("reopen");
    let final_page = keys
        .key_catalog_page(second.continuation.as_deref(), 2, &mut budget())
        .expect("reopened continuation");
    assert!(final_page.continuation.is_none());
    let entries: Vec<_> = [&first, &second, &final_page]
        .into_iter()
        .flat_map(|page| page.entries.iter())
        .collect();
    assert_eq!(entries.len(), 6);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.key_id)
            .collect::<BTreeSet<_>>()
            .len(),
        6
    );
    let same_address: BTreeSet<_> = entries
        .iter()
        .filter(|entry| entry.address_digest == address(&space, b"a"))
        .map(|entry| entry.key_id)
        .collect();
    assert_eq!(same_address, BTreeSet::from([original_id, replaced_id]));
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.allocation_sequence)
            .collect::<Vec<_>>(),
        [1, 1, 1, 2, 2, 3]
    );
    assert_eq!(
        keys.open_value(&space, b"a", &original, None)
            .expect("historical version"),
        b"private original plus independent data"
    );
    assert_eq!(
        keys.open_value(&space, b"a", &replaced, None)
            .expect("current version"),
        b"independent data"
    );
    let encoded = serde_json::to_string(&[first, second, final_page]).expect("public catalog");
    assert!(
        !encoded.contains("wrapped")
            && !encoded.contains("private original")
            && !encoded.contains("independent data")
    );
}

#[test]
fn key_catalog_rejects_stale_foreign_forged_and_overbudget_continuations_without_writes() {
    let root = tempfile::tempdir().expect("root");
    let keys =
        NativeCustodyKeys::create(root.path().join("keys"), "key-cursor", master()).expect("keys");
    allocate(&keys, 0, 4);
    let first = keys.key_catalog_page(None, 1, &mut budget()).expect("page");
    let cursor = first.continuation.expect("continuation");
    let before = keys.engine.head_sequence().expect("head");
    for limit in [0, 257] {
        assert_eq!(
            keys.key_catalog_page(None, limit, &mut budget())
                .expect_err("limit")
                .code,
            ErrorCode::InvalidArgument
        );
    }
    let mut forged = cursor.clone();
    *forged.last_mut().expect("tag") ^= 1;
    assert!(
        keys.key_catalog_page(Some(&forged), 1, &mut budget())
            .is_err()
    );
    assert!(
        keys.key_catalog_page(Some(&vec![0; MAX_CURSOR_BYTES + 1]), 1, &mut budget())
            .is_err()
    );
    let foreign = NativeCustodyKeys::create(root.path().join("foreign"), "key-cursor", master())
        .expect("foreign authority");
    allocate(&foreign, 0, 4);
    assert!(
        foreign
            .key_catalog_page(Some(&cursor), 1, &mut budget())
            .is_err()
    );
    let legacy =
        NativeCustodyKeys::create_version(&root.path().join("legacy"), "key-cursor", master(), 2)
            .expect("legacy");
    assert_eq!(
        legacy
            .key_catalog_page(None, 1, &mut budget())
            .expect_err("explicit migration")
            .code,
        ErrorCode::FormatIncompatible
    );
    for (work, bytes, duration) in [
        (0, 1_000_000, Duration::from_secs(30)),
        (100_000, 0, Duration::from_secs(30)),
        (100_000, 1_000_000, Duration::ZERO),
    ] {
        let mut limited = QueryBudget::new(work, bytes, duration, Default::default());
        assert_eq!(
            keys.key_catalog_page(Some(&cursor), 1, &mut limited)
                .expect_err("budget")
                .code,
            ErrorCode::BudgetExhausted
        );
    }
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(100_000, 1_000_000, Duration::from_secs(30), cancellation);
    assert_eq!(
        keys.key_catalog_page(Some(&cursor), 1, &mut cancelled)
            .expect_err("cancelled")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(keys.engine.head_sequence().expect("no publication"), before);
    assert_eq!(
        keys.key_catalog_page(Some(&cursor), 1, &mut budget())
            .expect("retry unchanged cursor")
            .entries
            .len(),
        1
    );
    allocate(&keys, 10, 1);
    assert_eq!(
        keys.key_catalog_page(Some(&cursor), 1, &mut budget())
            .expect_err("changed allocation head")
            .code,
        ErrorCode::IndexTooStale
    );
}

#[test]
fn key_catalog_page_budget_stays_bounded_as_new_allocation_batches_grow() {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "catalog-scale", master())
        .expect("keys");
    let mut start = 0;
    for end in [512, 8192] {
        allocate(&keys, start, end - start);
        start = end;
        let mut bounded = QueryBudget::new(
            1000,
            256 * 1024,
            Duration::from_secs(30),
            Default::default(),
        );
        let first = keys
            .key_catalog_page(None, 256, &mut bounded)
            .expect("bounded first page");
        assert_eq!(first.entries.len(), 256);
        assert!(first.continuation.is_some());
        let mut bounded = QueryBudget::new(
            1000,
            256 * 1024,
            Duration::from_secs(30),
            Default::default(),
        );
        let next = keys
            .key_catalog_page(first.continuation.as_deref(), 256, &mut bounded)
            .expect("bounded continuation");
        assert_eq!(next.entries.len(), 256);
    }
    keys.verify()
        .expect("chunked allocations retain exact reverse closure");
}

#[test]
fn key_catalog_preserves_pre_chunking_v3_batches_and_appends_after_reopen() {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "old-key-batch", master())
        .expect("keys");
    let authority = keys.authority_id();
    allocate(&keys, 0, 600);
    let snapshot = keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let head = keys.key_version_head(&snapshot).expect("head");
    let mut references = Vec::new();
    let mut tx = keys.engine.begin_write().expect("fixture transaction");
    for sequence in 1..=head.sequence {
        let key = batch_key(sequence);
        let bytes = snapshot.get(&keys.rows, &key).expect("batch").expect("row");
        let batch: Batch =
            decode(&keys.open_key_log(&key, &bytes).expect("open batch")).expect("batch");
        references.extend(batch.keys);
        tx.delete(&keys.rows, key).expect("replace batch framing");
    }
    // Synthetic wire fixture for the original v3 writer, which accepted all
    // transaction references in one journal record. Key descriptors are unchanged.
    let batch = Batch {
        sequence: 1,
        previous_digest: None,
        keys: references,
    };
    let bytes = encode(&batch).expect("old batch");
    let head = Head {
        sequence: 1,
        digest: Some(crate::digest_bytes(&bytes)),
    };
    tx.put(
        &keys.rows,
        batch_key(1),
        keys.seal_key_log(&batch_key(1), &bytes)
            .expect("seal batch"),
    )
    .expect("old batch");
    tx.put(
        &keys.rows,
        HEAD.to_vec(),
        keys.seal_key_log(HEAD, &encode(&head).expect("head"))
            .expect("seal head"),
    )
    .expect("old head");
    tx.commit(Durability::Sync).expect("fixture");
    drop((snapshot, keys));
    let keys = NativeCustodyKeys::open(
        root.path().join("keys"),
        "old-key-batch",
        authority,
        master(),
    )
    .expect("old larger batch reopens");
    let first = keys
        .key_catalog_page(None, 256, &mut budget())
        .expect("first old page");
    let second = keys
        .key_catalog_page(first.continuation.as_deref(), 256, &mut budget())
        .expect("second old page");
    let last = keys
        .key_catalog_page(second.continuation.as_deref(), 256, &mut budget())
        .expect("last old page");
    assert_eq!(
        (
            first.entries.len(),
            second.entries.len(),
            last.entries.len()
        ),
        (256, 256, 88)
    );
    assert_eq!(last.revision, 1);
    assert!(last.continuation.is_none());
    allocate(&keys, 1000, 1);
    keys.verify()
        .expect("new writer extends the old authenticated chain");
    assert_eq!(
        keys.key_catalog_page(None, 1, &mut budget())
            .expect("new head")
            .revision,
        2
    );
    assert_eq!(
        keys.key_catalog_page(first.continuation.as_deref(), 256, &mut budget())
            .expect_err("old enumeration is now stale")
            .code,
        ErrorCode::IndexTooStale
    );
}

#[test]
fn key_catalog_cannot_finish_after_lost_or_changed_accepted_rows_or_replayed_head() {
    for damage in ["head", "batch", "key", "descriptor", "head-replay"] {
        let root = tempfile::tempdir().expect("root");
        let keys = NativeCustodyKeys::create(root.path().join("keys"), "damaged-catalog", master())
            .expect("keys");
        let snapshot = keys
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        let genesis = snapshot
            .get(&keys.rows, HEAD)
            .expect("head")
            .expect("genesis");
        allocate(&keys, 0, 3);
        allocate(&keys, 10, 2);
        let first = keys
            .key_catalog_page(None, 1, &mut budget())
            .expect("first page");
        let snapshot = keys
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        let bytes = snapshot
            .get(&keys.rows, &batch_key(2))
            .expect("batch")
            .expect("row");
        let batch: Batch =
            decode(&keys.open_key_log(&batch_key(2), &bytes).expect("open")).expect("batch");
        let reference = &batch.keys[1];
        let key = version_key(&reference.address, reference.id);
        let mut tx = keys.engine.begin_write().expect("damage transaction");
        match damage {
            "head" => tx.delete(&keys.rows, HEAD.to_vec()).expect("remove head"),
            "batch" => tx
                .delete(&keys.rows, batch_key(2))
                .expect("remove last batch"),
            "key" => tx.delete(&keys.rows, key).expect("remove unseen key"),
            "descriptor" => {
                let bytes = tx.get(&keys.rows, &key).expect("key").expect("row");
                let mut record: KeyRecord = decode(&bytes).expect("descriptor");
                *record.wrapped.last_mut().expect("tag") ^= 1;
                tx.put(
                    &keys.rows,
                    key,
                    encode(&record).expect("changed descriptor"),
                )
                .expect("damage");
            }
            "head-replay" => tx
                .put(&keys.rows, HEAD.to_vec(), genesis)
                .expect("replay genesis"),
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("damage commit");
        let before = keys.engine.head_sequence().expect("head");
        let mut cursor = first.continuation;
        let mut rejected = false;
        for _ in 0..5 {
            match keys.key_catalog_page(cursor.as_deref(), 1, &mut budget()) {
                Err(_) => {
                    rejected = true;
                    break;
                }
                Ok(page) => {
                    assert!(page.continuation.is_some(), "{damage} silently completed");
                    cursor = page.continuation;
                }
            }
        }
        assert!(
            rejected,
            "{damage} did not reach a rejection within its remaining pages"
        );
        assert_eq!(
            keys.engine.head_sequence().expect("read-only failure"),
            before
        );
    }
}
