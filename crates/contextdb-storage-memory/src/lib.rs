//! Deterministic in-memory implementation of the physical storage contract.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::path::Path;
use std::sync::{Arc, RwLock};

use contextdb_storage::{
    CheckpointManifest, CommitReceipt, CompactReport, CompactRequest, Durability, Entry, Keyspace,
    ReadSnapshot, Result, ScanPage, ScanPageRequest, SnapshotSelector, StorageEngine, StorageError,
    StorageSequence, VerifyMode, VerifyReport, WriteTransaction, collect_prefix_pages,
    collect_scan_page,
};

type Table = BTreeMap<Vec<u8>, Vec<u8>>;
type Tables = BTreeMap<String, Table>;

#[derive(Debug, Clone, Default)]
struct State {
    head: StorageSequence,
    retained: BTreeMap<StorageSequence, Arc<Tables>>,
}

/// In-memory MVCC backend used by tests and deterministic baselines.
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    state: Arc<RwLock<State>>,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        let mut state = State::default();
        state.retained.insert(0, Arc::new(Tables::new()));
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }
}

impl MemoryStorage {
    /// Creates an empty database at sequence zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Immutable in-memory snapshot.
#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    sequence: StorageSequence,
    tables: Arc<Tables>,
}

impl ReadSnapshot for MemorySnapshot {
    fn sequence(&self) -> StorageSequence {
        self.sequence
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .tables
            .get(keyspace.as_str())
            .and_then(|table| table.get(key))
            .cloned())
    }

    fn scan_prefix(&self, keyspace: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        collect_prefix_pages(self, keyspace, prefix)
    }

    fn scan_prefix_page(
        &self,
        keyspace: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> Result<ScanPage> {
        let Some(table) = self.tables.get(keyspace.as_str()) else {
            request.validate()?;
            return Ok(ScanPage {
                entries: Vec::new(),
                continuation: None,
            });
        };
        let start = request.start_after.unwrap_or(request.prefix).to_vec();
        let lower = if request.start_after.is_some() {
            Excluded(start)
        } else {
            Included(start)
        };
        collect_scan_page(
            request,
            table.range((lower, Unbounded)).map(|(key, value)| {
                Ok(Entry {
                    key: key.clone(),
                    value: value.clone(),
                })
            }),
        )
    }
}

#[derive(Debug, Clone)]
enum Change {
    Put(Vec<u8>),
    Delete,
}

/// Optimistic atomic in-memory transaction.
#[derive(Debug)]
pub struct MemoryTransaction<'a> {
    storage: &'a MemoryStorage,
    base: MemorySnapshot,
    changes: HashMap<(String, Vec<u8>), Change>,
}

impl ReadSnapshot for MemoryTransaction<'_> {
    fn sequence(&self) -> StorageSequence {
        self.base.sequence
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let lookup = (keyspace.as_str().to_owned(), key.to_vec());
        match self.changes.get(&lookup) {
            Some(Change::Put(value)) => Ok(Some(value.clone())),
            Some(Change::Delete) => Ok(None),
            None => self.base.get(keyspace, key),
        }
    }

    fn scan_prefix(&self, keyspace: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        collect_prefix_pages(self, keyspace, prefix)
    }

    fn scan_prefix_page(
        &self,
        keyspace: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> Result<ScanPage> {
        request.validate()?;
        let start = request.start_after.unwrap_or(request.prefix).to_vec();
        let lower = if request.start_after.is_some() {
            Excluded(start)
        } else {
            Included(start)
        };
        let base = self
            .base
            .tables
            .get(keyspace.as_str())
            .into_iter()
            .flat_map(move |table| table.range((lower.clone(), Unbounded)))
            .map(|(key, value)| {
                Ok(Entry {
                    key: key.clone(),
                    value: value.clone(),
                })
            });
        let mut staged = self
            .changes
            .iter()
            .filter(|((space, key), _)| {
                space == keyspace.as_str()
                    && key.starts_with(request.prefix)
                    && request
                        .start_after
                        .is_none_or(|start_after| key.as_slice() > start_after)
            })
            .map(|((_, key), change)| (key, change))
            .collect::<Vec<_>>();
        staged.sort_unstable_by(|left, right| left.0.cmp(right.0));
        collect_scan_page(request, merge_staged(base, staged.into_iter()))
    }
}

fn merge_staged<'a, I>(
    base: I,
    staged: impl Iterator<Item = (&'a Vec<u8>, &'a Change)> + 'a,
) -> impl Iterator<Item = Result<Entry>> + 'a
where
    I: Iterator<Item = Result<Entry>> + 'a,
{
    let mut base = base.peekable();
    let mut staged = staged.peekable();
    std::iter::from_fn(move || {
        loop {
            let ordering = match (base.peek(), staged.peek()) {
                (Some(Ok(entry)), Some((key, _))) => Some(entry.key.cmp(key)),
                (Some(Err(_)), _) => return base.next(),
                (Some(_), None) => return base.next(),
                (None, Some(_)) => None,
                (None, None) => return None,
            };
            match ordering {
                Some(std::cmp::Ordering::Less) => return base.next(),
                Some(std::cmp::Ordering::Equal) => {
                    let _ = base.next();
                }
                Some(std::cmp::Ordering::Greater) | None => {}
            }
            let (key, change) = staged.next().expect("peeked staged change exists");
            if let Change::Put(value) = change {
                return Some(Ok(Entry {
                    key: key.clone(),
                    value: value.clone(),
                }));
            }
        }
    })
}

impl WriteTransaction for MemoryTransaction<'_> {
    fn put(&mut self, keyspace: &Keyspace, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.changes
            .insert((keyspace.as_str().to_owned(), key), Change::Put(value));
        Ok(())
    }

    fn delete(&mut self, keyspace: &Keyspace, key: Vec<u8>) -> Result<()> {
        self.changes
            .insert((keyspace.as_str().to_owned(), key), Change::Delete);
        Ok(())
    }

    fn commit(self, durability: Durability) -> Result<CommitReceipt> {
        let mut state = self
            .storage
            .state
            .write()
            .map_err(|_| StorageError::LockPoisoned)?;
        if state.head != self.base.sequence {
            return Err(StorageError::WriteConflict {
                base: self.base.sequence,
                head: state.head,
            });
        }
        let mut next = (*self.base.tables).clone();
        for ((space, key), change) in self.changes {
            let table = next.entry(space).or_default();
            match change {
                Change::Put(value) => {
                    table.insert(key, value);
                }
                Change::Delete => {
                    table.remove(&key);
                }
            }
        }
        let sequence = state
            .head
            .checked_add(1)
            .ok_or_else(|| StorageError::Backend {
                backend: "memory",
                message: "commit sequence exhausted".to_owned(),
            })?;
        state.head = sequence;
        state.retained.insert(sequence, Arc::new(next));
        Ok(CommitReceipt {
            sequence,
            durability,
        })
    }

    fn rollback(self) -> Result<()> {
        Ok(())
    }
}

impl StorageEngine for MemoryStorage {
    type ReadSnapshot<'a> = MemorySnapshot;
    type WriteTransaction<'a> = MemoryTransaction<'a>;

    fn head_sequence(&self) -> Result<StorageSequence> {
        self.state
            .read()
            .map(|state| state.head)
            .map_err(|_| StorageError::LockPoisoned)
    }

    fn begin_read(&self, selector: SnapshotSelector) -> Result<Self::ReadSnapshot<'_>> {
        let state = self.state.read().map_err(|_| StorageError::LockPoisoned)?;
        let requested = match selector {
            SnapshotSelector::Latest => state.head,
            SnapshotSelector::At(sequence) => sequence,
        };
        let tables =
            state
                .retained
                .get(&requested)
                .cloned()
                .ok_or(StorageError::SnapshotUnavailable {
                    requested,
                    head: state.head,
                })?;
        Ok(MemorySnapshot {
            sequence: requested,
            tables,
        })
    }

    fn begin_write(&self) -> Result<Self::WriteTransaction<'_>> {
        let base = self.begin_read(SnapshotSelector::Latest)?;
        Ok(MemoryTransaction {
            storage: self,
            base,
            changes: HashMap::new(),
        })
    }

    fn checkpoint(&self, _target: &Path) -> Result<CheckpointManifest> {
        Err(StorageError::Unsupported {
            backend: "memory",
            operation: "physical checkpoint; use journal portable backup",
        })
    }

    fn compact(&self, _request: CompactRequest) -> Result<CompactReport> {
        Ok(CompactReport {
            sequence: self.head_sequence()?,
            bytes_reclaimed: 0,
        })
    }

    fn verify(&self, _mode: VerifyMode) -> Result<VerifyReport> {
        let snapshot = self.begin_read(SnapshotSelector::Latest)?;
        let keyspaces = u64::try_from(snapshot.tables.len()).unwrap_or(u64::MAX);
        let records = snapshot
            .tables
            .values()
            .map(BTreeMap::len)
            .try_fold(0_u64, |sum, len| {
                sum.checked_add(u64::try_from(len).unwrap_or(u64::MAX))
            })
            .unwrap_or(u64::MAX);
        Ok(VerifyReport {
            sequence: snapshot.sequence,
            keyspaces,
            records,
            warnings: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use contextdb_storage::{
        Durability, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine,
        StorageError, WriteTransaction,
    };

    use super::MemoryStorage;

    fn space() -> Keyspace {
        Keyspace::new("records").expect("fixture keyspace is valid")
    }

    #[test]
    fn snapshot_isolation_and_historical_reads() {
        let db = MemoryStorage::new();
        let mut write = db.begin_write().expect("writer");
        write
            .put(&space(), b"a".to_vec(), b"one".to_vec())
            .expect("stage");
        let receipt = write.commit(Durability::Ephemeral).expect("commit");
        let old = db
            .begin_read(SnapshotSelector::At(0))
            .expect("old snapshot");
        let new = db
            .begin_read(SnapshotSelector::At(receipt.sequence))
            .expect("new snapshot");
        assert_eq!(old.get(&space(), b"a").expect("read"), None);
        assert_eq!(
            new.get(&space(), b"a").expect("read"),
            Some(b"one".to_vec())
        );
    }

    #[test]
    fn stale_writer_fails_without_partial_change() {
        let db = MemoryStorage::new();
        let mut first = db.begin_write().expect("first");
        let mut stale = db.begin_write().expect("stale");
        first
            .put(&space(), b"a".to_vec(), b"one".to_vec())
            .expect("stage first");
        first.commit(Durability::Ephemeral).expect("first commit");
        stale
            .put(&space(), b"b".to_vec(), b"two".to_vec())
            .expect("stage stale");
        assert!(matches!(
            stale.commit(Durability::Ephemeral),
            Err(StorageError::WriteConflict { .. })
        ));
        let head = db.begin_read(SnapshotSelector::Latest).expect("head");
        assert_eq!(head.get(&space(), b"b").expect("read"), None);
    }

    #[test]
    fn transaction_reads_its_staged_changes_in_order() {
        let db = MemoryStorage::new();
        let mut write = db.begin_write().expect("writer");
        write
            .put(&space(), b"ab".to_vec(), b"one".to_vec())
            .expect("put");
        write
            .put(&space(), b"aa".to_vec(), b"two".to_vec())
            .expect("put");
        let entries = write.scan_prefix(&space(), b"a").expect("scan");
        assert_eq!(entries[0].key, b"aa");
        assert_eq!(entries[1].key, b"ab");
        write.delete(&space(), b"aa".to_vec()).expect("delete");
        assert_eq!(write.get(&space(), b"aa").expect("read"), None);
    }

    fn collect_paged(
        snapshot: &impl ReadSnapshot,
        keyspace: &Keyspace,
        max_entries: usize,
        max_bytes: usize,
    ) -> Vec<Vec<u8>> {
        let mut cursor = None;
        let mut keys = Vec::new();
        loop {
            let page = snapshot
                .scan_prefix_page(
                    keyspace,
                    ScanPageRequest {
                        prefix: b"a",
                        start_after: cursor.as_deref(),
                        max_entries,
                        max_bytes,
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
    fn paged_snapshot_and_transaction_scans_neither_skip_nor_duplicate() {
        let db = MemoryStorage::new();
        let keyspace = space();
        let mut write = db.begin_write().expect("writer");
        for key in [b"a0", b"a2", b"a4", b"b0"] {
            write
                .put(&keyspace, key.to_vec(), b"v".to_vec())
                .expect("put base");
        }
        write.commit(Durability::Ephemeral).expect("commit base");

        let snapshot = db.begin_read(SnapshotSelector::Latest).expect("snapshot");
        assert_eq!(
            collect_paged(&snapshot, &keyspace, 2, 100),
            [b"a0", b"a2", b"a4"].map(|key| key.to_vec())
        );
        assert_eq!(
            collect_paged(&snapshot, &keyspace, 10, 3),
            [b"a0", b"a2", b"a4"].map(|key| key.to_vec()),
            "the byte budget must also drive exclusive continuation"
        );

        let mut transaction = db.begin_write().expect("transaction");
        transaction
            .delete(&keyspace, b"a2".to_vec())
            .expect("delete staged");
        transaction
            .put(&keyspace, b"a1".to_vec(), b"v".to_vec())
            .expect("put staged");
        transaction
            .put(&keyspace, b"a3".to_vec(), b"v".to_vec())
            .expect("put staged");
        assert_eq!(
            collect_paged(&transaction, &keyspace, 2, 100),
            [b"a0", b"a1", b"a3", b"a4"].map(|key| key.to_vec())
        );
    }

    #[test]
    fn paged_snapshot_rejects_an_oversized_first_entry() {
        let db = MemoryStorage::new();
        let keyspace = space();
        let mut write = db.begin_write().expect("writer");
        write
            .put(&keyspace, b"aa".to_vec(), b"vv".to_vec())
            .expect("put");
        write.commit(Durability::Ephemeral).expect("commit");
        let snapshot = db.begin_read(SnapshotSelector::Latest).expect("snapshot");
        assert!(matches!(
            snapshot.scan_prefix_page(
                &keyspace,
                ScanPageRequest {
                    prefix: b"a",
                    start_after: None,
                    max_entries: 1,
                    max_bytes: 3,
                }
            ),
            Err(StorageError::ResourceExhausted {
                resource: "scan_page_bytes",
                limit: 3,
                required: 4
            })
        ));
    }
}
