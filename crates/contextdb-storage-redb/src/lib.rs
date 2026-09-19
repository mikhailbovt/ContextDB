//! redb conformance adapter for the ContextDB physical storage boundary.

#![forbid(unsafe_code)]

use std::ops::Bound::{Excluded, Included, Unbounded};
use std::path::Path;
use std::sync::{Arc, Mutex};

use contextdb_storage::{
    CheckpointManifest, CommitReceipt, CompactReport, CompactRequest, Durability, Entry, Keyspace,
    ReadSnapshot, Result, ScanPage, ScanPageRequest, SnapshotSelector, StorageEngine, StorageError,
    StorageSequence, VerifyMode, VerifyReport, WriteTransaction, collect_prefix_pages,
    collect_scan_page,
};
use redb::{
    Database, Durability as RedbDurability, ReadTransaction, ReadableDatabase, ReadableTable,
    ReadableTableMetadata, TableDefinition, WriteTransaction as RedbWriteTransaction,
};

const RECORDS: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("contextdb_records_v1");
const META: TableDefinition<'static, u8, u64> = TableDefinition::new("contextdb_meta_v1");
const HEAD_KEY: u8 = 0;

fn backend(error: impl std::fmt::Display) -> StorageError {
    StorageError::Backend {
        backend: "redb",
        message: error.to_string(),
    }
}

fn composite_prefix(keyspace: &Keyspace, suffix: &[u8]) -> Vec<u8> {
    let name = keyspace.as_str().as_bytes();
    let mut encoded = Vec::with_capacity(2 + name.len() + suffix.len());
    let length = u16::try_from(name.len()).unwrap_or(u16::MAX);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(name);
    encoded.extend_from_slice(suffix);
    encoded
}

fn head_from_read(transaction: &ReadTransaction) -> Result<StorageSequence> {
    let table = transaction.open_table(META).map_err(backend)?;
    table
        .get(HEAD_KEY)
        .map_err(backend)
        .map(|value| value.map_or(0, |guard| guard.value()))
}

fn head_from_write(transaction: &RedbWriteTransaction) -> Result<StorageSequence> {
    let table = transaction.open_table(META).map_err(backend)?;
    table
        .get(HEAD_KEY)
        .map_err(backend)
        .map(|value| value.map_or(0, |guard| guard.value()))
}

/// Pure-Rust B-tree/MVCC conformance backend evaluated in M2.
#[derive(Clone)]
pub struct RedbStorage {
    database: Arc<Mutex<Database>>,
}

impl std::fmt::Debug for RedbStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedbStorage")
            .finish_non_exhaustive()
    }
}

impl RedbStorage {
    /// Opens or creates a redb database file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let database = Database::create(path).map_err(backend)?;
        let transaction = database.begin_write().map_err(backend)?;
        {
            let _records = transaction.open_table(RECORDS).map_err(backend)?;
            let mut meta = transaction.open_table(META).map_err(backend)?;
            if meta.get(HEAD_KEY).map_err(backend)?.is_none() {
                meta.insert(HEAD_KEY, 0).map_err(backend)?;
            }
        }
        transaction.commit().map_err(backend)?;
        Ok(Self {
            database: Arc::new(Mutex::new(database)),
        })
    }

    fn database(&self) -> Result<std::sync::MutexGuard<'_, Database>> {
        self.database.lock().map_err(|_| StorageError::LockPoisoned)
    }

    /// Try physical compaction without waiting for open MVCC transactions.
    /// `None` means deferred, not compacted; callers may retry within their own
    /// deadline after releasing snapshots. Other backend failures remain errors.
    pub fn try_compact(&self, _request: CompactRequest) -> Result<Option<CompactReport>> {
        let mut database = self.database()?;
        let sequence = {
            let transaction = database.begin_read().map_err(backend)?;
            head_from_read(&transaction)?
        };
        match database.compact() {
            Ok(compacted) => Ok(Some(CompactReport {
                sequence,
                bytes_reclaimed: u64::from(compacted),
            })),
            Err(redb::CompactionError::TransactionInProgress) => Ok(None),
            Err(error) => Err(backend(error)),
        }
    }
}

/// Immutable redb MVCC read transaction.
pub struct RedbSnapshot {
    sequence: StorageSequence,
    transaction: ReadTransaction,
}

impl std::fmt::Debug for RedbSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedbSnapshot")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

fn scan_table_page<T>(
    table: &T,
    keyspace: &Keyspace,
    request: ScanPageRequest<'_>,
) -> Result<ScanPage>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    request.validate()?;
    let encoded_keyspace = composite_prefix(keyspace, &[]);
    let encoded_start = composite_prefix(keyspace, request.start_after.unwrap_or(request.prefix));
    let lower = if request.start_after.is_some() {
        Excluded(encoded_start.as_slice())
    } else {
        Included(encoded_start.as_slice())
    };
    let range = table.range::<&[u8]>((lower, Unbounded)).map_err(backend)?;
    let key_offset = encoded_keyspace.len();
    let mut outside_keyspace = false;
    let entries = range.scan(&mut outside_keyspace, |outside, item| {
        if **outside {
            return None;
        }
        let (key, value) = match item {
            Ok(pair) => pair,
            Err(error) => return Some(Err(backend(error))),
        };
        let encoded_key = key.value();
        if !encoded_key.starts_with(&encoded_keyspace) {
            **outside = true;
            return None;
        }
        let logical_key = match encoded_key.get(key_offset..) {
            Some(key) => key,
            None => {
                return Some(Err(StorageError::Backend {
                    backend: "redb",
                    message: "invalid composite key".to_owned(),
                }));
            }
        };
        Some(Ok(Entry {
            key: logical_key.to_vec(),
            value: value.value().to_vec(),
        }))
    });
    collect_scan_page(request, entries)
}

impl ReadSnapshot for RedbSnapshot {
    fn sequence(&self) -> StorageSequence {
        self.sequence
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let table = self.transaction.open_table(RECORDS).map_err(backend)?;
        table
            .get(composite_prefix(keyspace, key).as_slice())
            .map_err(backend)
            .map(|value| value.map(|guard| guard.value().to_vec()))
    }

    fn scan_prefix(&self, keyspace: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        collect_prefix_pages(self, keyspace, prefix)
    }

    fn scan_prefix_page(
        &self,
        keyspace: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> Result<ScanPage> {
        let table = self.transaction.open_table(RECORDS).map_err(backend)?;
        scan_table_page(&table, keyspace, request)
    }
}

/// Atomic redb writer. redb serializes writers and provides read-your-writes.
pub struct RedbTransaction {
    base: StorageSequence,
    transaction: RedbWriteTransaction,
}

impl std::fmt::Debug for RedbTransaction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedbTransaction")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl ReadSnapshot for RedbTransaction {
    fn sequence(&self) -> StorageSequence {
        self.base
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let table = self.transaction.open_table(RECORDS).map_err(backend)?;
        table
            .get(composite_prefix(keyspace, key).as_slice())
            .map_err(backend)
            .map(|value| value.map(|guard| guard.value().to_vec()))
    }

    fn scan_prefix(&self, keyspace: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        collect_prefix_pages(self, keyspace, prefix)
    }

    fn scan_prefix_page(
        &self,
        keyspace: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> Result<ScanPage> {
        let table = self.transaction.open_table(RECORDS).map_err(backend)?;
        scan_table_page(&table, keyspace, request)
    }
}

impl WriteTransaction for RedbTransaction {
    fn put(&mut self, keyspace: &Keyspace, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let mut table = self.transaction.open_table(RECORDS).map_err(backend)?;
        table
            .insert(
                composite_prefix(keyspace, &key).as_slice(),
                value.as_slice(),
            )
            .map_err(backend)?;
        Ok(())
    }

    fn delete(&mut self, keyspace: &Keyspace, key: Vec<u8>) -> Result<()> {
        let mut table = self.transaction.open_table(RECORDS).map_err(backend)?;
        table
            .remove(composite_prefix(keyspace, &key).as_slice())
            .map_err(backend)?;
        Ok(())
    }

    fn commit(mut self, durability: Durability) -> Result<CommitReceipt> {
        let current = head_from_write(&self.transaction)?;
        if current != self.base {
            self.transaction.abort().map_err(backend)?;
            return Err(StorageError::WriteConflict {
                base: self.base,
                head: current,
            });
        }
        let sequence = current
            .checked_add(1)
            .ok_or_else(|| StorageError::Backend {
                backend: "redb",
                message: "commit sequence exhausted".to_owned(),
            })?;
        {
            let mut meta = self.transaction.open_table(META).map_err(backend)?;
            meta.insert(HEAD_KEY, sequence).map_err(backend)?;
        }
        let redb_durability = match durability {
            Durability::Ephemeral => RedbDurability::None,
            Durability::Sync => RedbDurability::Immediate,
        };
        self.transaction
            .set_durability(redb_durability)
            .map_err(backend)?;
        self.transaction.commit().map_err(backend)?;
        Ok(CommitReceipt {
            sequence,
            durability,
        })
    }

    fn rollback(self) -> Result<()> {
        self.transaction.abort().map_err(backend)
    }
}

impl StorageEngine for RedbStorage {
    type ReadSnapshot<'a> = RedbSnapshot;
    type WriteTransaction<'a> = RedbTransaction;

    fn head_sequence(&self) -> Result<StorageSequence> {
        let transaction = self.database()?.begin_read().map_err(backend)?;
        head_from_read(&transaction)
    }

    fn begin_read(&self, selector: SnapshotSelector) -> Result<Self::ReadSnapshot<'_>> {
        let transaction = self.database()?.begin_read().map_err(backend)?;
        let head = head_from_read(&transaction)?;
        let requested = match selector {
            SnapshotSelector::Latest => head,
            SnapshotSelector::At(sequence) => sequence,
        };
        if requested != head {
            return Err(StorageError::SnapshotUnavailable { requested, head });
        }
        Ok(RedbSnapshot {
            sequence: head,
            transaction,
        })
    }

    fn begin_write(&self) -> Result<Self::WriteTransaction<'_>> {
        let transaction = self.database()?.begin_write().map_err(backend)?;
        let base = head_from_write(&transaction)?;
        Ok(RedbTransaction { base, transaction })
    }

    fn checkpoint(&self, _target: &Path) -> Result<CheckpointManifest> {
        Err(StorageError::Unsupported {
            backend: "redb",
            operation: "online physical checkpoint",
        })
    }

    fn compact(&self, request: CompactRequest) -> Result<CompactReport> {
        self.try_compact(request)?
            .ok_or_else(|| backend(redb::CompactionError::TransactionInProgress))
    }

    fn verify(&self, _mode: VerifyMode) -> Result<VerifyReport> {
        let transaction = self.database()?.begin_read().map_err(backend)?;
        let sequence = head_from_read(&transaction)?;
        let table = transaction.open_table(RECORDS).map_err(backend)?;
        Ok(VerifyReport {
            sequence,
            keyspaces: 1,
            records: table.len().map_err(backend)?,
            warnings: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test fixtures use immediate failure semantics"
    )]

    use contextdb_storage::{
        Durability, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine,
        WriteTransaction,
    };

    use super::RedbStorage;

    #[test]
    fn compaction_is_explicitly_deferred_until_the_snapshot_is_released() {
        let directory = tempfile::tempdir().expect("directory");
        let db = RedbStorage::open(directory.path().join("compaction.redb")).expect("open");
        let held = db
            .begin_read(SnapshotSelector::Latest)
            .expect("held snapshot");
        let request = contextdb_storage::CompactRequest { max_bytes: None };
        assert!(db.try_compact(request).expect("try while held").is_none());
        assert_eq!(held.sequence(), 0);
        drop(held);
        assert_eq!(
            db.try_compact(request)
                .expect("idle compaction")
                .expect("performed")
                .sequence,
            0
        );
    }

    #[test]
    fn synced_commit_survives_reopen() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("contextdb.redb");
        let space = Keyspace::new("records").expect("keyspace");
        {
            let db = RedbStorage::open(&path).expect("open");
            let mut transaction = db.begin_write().expect("write");
            transaction
                .put(&space, b"key".to_vec(), b"value".to_vec())
                .expect("stage");
            transaction.commit(Durability::Sync).expect("commit");
        }
        let reopened = RedbStorage::open(&path).expect("reopen");
        let snapshot = reopened.begin_read(SnapshotSelector::Latest).expect("read");
        assert_eq!(
            snapshot.get(&space, b"key").expect("get"),
            Some(b"value".to_vec())
        );
        assert_eq!(snapshot.sequence(), 1);
    }

    fn collect_paged(snapshot: &impl ReadSnapshot, keyspace: &Keyspace) -> Vec<Vec<u8>> {
        let mut cursor = None;
        let mut keys = Vec::new();
        loop {
            let page = snapshot
                .scan_prefix_page(
                    keyspace,
                    ScanPageRequest {
                        prefix: b"a",
                        start_after: cursor.as_deref(),
                        max_entries: 2,
                        max_bytes: 100,
                    },
                )
                .expect("page scan");
            keys.extend(page.entries.into_iter().map(|entry| entry.key));
            let Some(next) = page.continuation else {
                return keys;
            };
            assert!(cursor.as_ref().is_none_or(|previous| &next > previous));
            cursor = Some(next);
        }
    }

    #[test]
    fn paged_snapshot_and_write_transaction_are_ordered_and_exclusive() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("contextdb.redb");
        let db = RedbStorage::open(path).expect("open");
        let space = Keyspace::new("records").expect("keyspace");
        let mut write = db.begin_write().expect("writer");
        for key in [b"a0", b"a2", b"a4", b"b0"] {
            write
                .put(&space, key.to_vec(), b"v".to_vec())
                .expect("put base");
        }
        write.commit(Durability::Ephemeral).expect("commit base");
        let snapshot = db.begin_read(SnapshotSelector::Latest).expect("snapshot");
        assert_eq!(
            collect_paged(&snapshot, &space),
            [b"a0", b"a2", b"a4"].map(|key| key.to_vec())
        );
        drop(snapshot);

        let mut transaction = db.begin_write().expect("transaction");
        transaction
            .delete(&space, b"a2".to_vec())
            .expect("delete staged");
        transaction
            .put(&space, b"a1".to_vec(), b"v".to_vec())
            .expect("put staged");
        transaction
            .put(&space, b"a3".to_vec(), b"v".to_vec())
            .expect("put staged");
        assert_eq!(
            collect_paged(&transaction, &space),
            [b"a0", b"a1", b"a3", b"a4"].map(|key| key.to_vec())
        );
        transaction.rollback().expect("rollback");
    }
}
