//! Fjall adapter for the backend-neutral ContextDB storage contract.

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
use fjall::{
    KeyspaceCreateOptions, PersistMode, Readable, SingleWriterTxDatabase, SingleWriterTxKeyspace,
};

/// Physical Fjall keyspace used by this adapter for its monotonic sequence.
///
/// Higher-level formats may use this name when enforcing an exact physical
/// keyspace allowlist. The contents remain owned by this adapter.
pub const FJALL_INTERNAL_META_KEYSPACE: &str = "contextdb_meta";
/// Sole key admitted in [`FJALL_INTERNAL_META_KEYSPACE`].
pub const FJALL_INTERNAL_HEAD_SEQUENCE_KEY: &[u8] = b"head_sequence";

/// Maximum number of committed Fjall snapshots retained for exact historical
/// reads. A snapshot already handed to a reader remains valid until its handle
/// is dropped; older unleased selectors fail with `SnapshotUnavailable`.
const MAX_RETAINED_SNAPSHOTS: usize = 64;

fn backend(error: impl std::fmt::Display) -> StorageError {
    StorageError::Backend {
        backend: "fjall",
        message: error.to_string(),
    }
}

fn decode_sequence(bytes: Option<impl AsRef<[u8]>>) -> Result<StorageSequence> {
    let Some(bytes) = bytes else {
        return Ok(0);
    };
    let bytes = bytes.as_ref();
    let array: [u8; 8] = bytes.try_into().map_err(|_| StorageError::Backend {
        backend: "fjall",
        message: "invalid head sequence metadata".to_owned(),
    })?;
    Ok(u64::from_be_bytes(array))
}

/// Persistent LSM adapter evaluated by the M2 substrate bake-off.
#[derive(Clone)]
pub struct FjallStorage {
    db: SingleWriterTxDatabase,
    retained: Arc<RwLock<BTreeMap<StorageSequence, fjall::Snapshot>>>,
}

impl std::fmt::Debug for FjallStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FjallStorage")
            .field("keyspaces", &self.db.keyspace_count())
            .finish_non_exhaustive()
    }
}

impl FjallStorage {
    /// Synchronize the existing write journal without adding a transaction or
    /// changing the logical sequence. Recovery can durably acknowledge an
    /// already visible commit whose original Sync result was not observed.
    pub fn synchronize(&self) -> Result<()> {
        self.db.persist(PersistMode::SyncAll).map_err(backend)
    }

    /// Opens or creates a Fjall database directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = SingleWriterTxDatabase::builder(path)
            .manual_journal_persist(true)
            .open()
            .map_err(backend)?;
        let meta = db
            .keyspace(FJALL_INTERNAL_META_KEYSPACE, KeyspaceCreateOptions::default)
            .map_err(backend)?;
        let snapshot = db.read_tx();
        let head = decode_sequence(
            snapshot
                .get(&meta, FJALL_INTERNAL_HEAD_SEQUENCE_KEY)
                .map_err(backend)?,
        )?;
        let retained = BTreeMap::from([(head, snapshot)]);
        Ok(Self {
            db,
            retained: Arc::new(RwLock::new(retained)),
        })
    }

    fn keyspace(&self, name: &str) -> Result<SingleWriterTxKeyspace> {
        self.db
            .keyspace(name, KeyspaceCreateOptions::default)
            .map_err(backend)
    }

    /// Returns the exact portable physical keyspace names in sorted order.
    ///
    /// This is deliberately read-only: callers can validate a closed-world
    /// on-disk format without gaining a second path for creating keyspaces.
    pub fn physical_keyspace_names(&self) -> Vec<String> {
        let mut names = self
            .db
            .list_keyspace_names()
            .into_iter()
            .map(|name| name.as_ref().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn latest_snapshot(&self) -> Result<FjallSnapshot> {
        let snapshot = self.db.read_tx();
        let meta = self.keyspace(FJALL_INTERNAL_META_KEYSPACE)?;
        let sequence = decode_sequence(
            snapshot
                .get(&meta, FJALL_INTERNAL_HEAD_SEQUENCE_KEY)
                .map_err(backend)?,
        )?;
        Ok(FjallSnapshot {
            db: self.db.clone(),
            sequence,
            snapshot,
        })
    }
}

/// Stable Fjall snapshot tied to the ContextDB physical sequence.
#[derive(Clone)]
pub struct FjallSnapshot {
    db: SingleWriterTxDatabase,
    sequence: StorageSequence,
    snapshot: fjall::Snapshot,
}

impl std::fmt::Debug for FjallSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FjallSnapshot")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl FjallSnapshot {
    fn keyspace(&self, keyspace: &Keyspace) -> Result<Option<SingleWriterTxKeyspace>> {
        if !self.db.keyspace_exists(keyspace.as_str()) {
            return Ok(None);
        }
        self.db
            .keyspace(keyspace.as_str(), KeyspaceCreateOptions::default)
            .map(Some)
            .map_err(backend)
    }
}

impl ReadSnapshot for FjallSnapshot {
    fn sequence(&self) -> StorageSequence {
        self.sequence
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(keyspace) = self.keyspace(keyspace)? else {
            return Ok(None);
        };
        self.snapshot
            .get(&keyspace, key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(backend)
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
        let Some(keyspace) = self.keyspace(keyspace)? else {
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
            self.snapshot
                .range(&keyspace, (lower, Unbounded))
                .map(|guard| {
                    guard
                        .into_inner()
                        .map(|(key, value)| Entry {
                            key: key.to_vec(),
                            value: value.to_vec(),
                        })
                        .map_err(backend)
                }),
        )
    }
}

#[derive(Debug, Clone)]
enum Change {
    Put(Vec<u8>),
    Delete,
}

/// Staged Fjall writer. The physical transaction is acquired only at commit.
#[derive(Debug)]
pub struct FjallTransaction<'a> {
    storage: &'a FjallStorage,
    base: FjallSnapshot,
    changes: HashMap<(String, Vec<u8>), Change>,
}

impl ReadSnapshot for FjallTransaction<'_> {
    fn sequence(&self) -> StorageSequence {
        self.base.sequence()
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
        let base: Box<dyn Iterator<Item = Result<Entry>> + '_> = match self
            .base
            .keyspace(keyspace)?
        {
            Some(handle) => Box::new(self.base.snapshot.range(&handle, (lower, Unbounded)).map(
                |guard| {
                    guard
                        .into_inner()
                        .map(|(key, value)| Entry {
                            key: key.to_vec(),
                            value: value.to_vec(),
                        })
                        .map_err(backend)
                },
            )),
            None => Box::new(std::iter::empty()),
        };
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

impl WriteTransaction for FjallTransaction<'_> {
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
        if !self
            .storage
            .db
            .keyspace_exists(FJALL_INTERNAL_META_KEYSPACE)
        {
            return Err(StorageError::Backend {
                backend: "fjall",
                message: "internal metadata keyspace is missing".to_owned(),
            });
        }
        let meta = self.storage.keyspace(FJALL_INTERNAL_META_KEYSPACE)?;
        let persist_mode = match durability {
            Durability::Ephemeral => PersistMode::Buffer,
            Durability::Sync => PersistMode::SyncAll,
        };
        let mut transaction = self.storage.db.write_tx().durability(Some(persist_mode));
        let current = decode_sequence(
            transaction
                .get(&meta, FJALL_INTERNAL_HEAD_SEQUENCE_KEY)
                .map_err(backend)?,
        )?;
        if current != self.base.sequence {
            transaction.rollback();
            return Err(StorageError::WriteConflict {
                base: self.base.sequence,
                head: current,
            });
        }
        // `keyspace` creates a missing physical keyspace immediately rather
        // than staging it in the Fjall transaction. Resolve those handles only
        // after the serialized sequence check, so a losing optimistic writer
        // has no physical side effects before returning WriteConflict.
        let mut handles = BTreeMap::new();
        for (space, _) in self.changes.keys() {
            if !handles.contains_key(space) {
                handles.insert(space.clone(), self.storage.keyspace(space)?);
            }
        }
        let sequence = current
            .checked_add(1)
            .ok_or_else(|| StorageError::Backend {
                backend: "fjall",
                message: "commit sequence exhausted".to_owned(),
            })?;
        for ((space, key), change) in self.changes {
            let handle = handles.get(&space).ok_or_else(|| StorageError::Backend {
                backend: "fjall",
                message: "keyspace handle disappeared during commit".to_owned(),
            })?;
            match change {
                Change::Put(value) => transaction.insert(handle, key, value),
                Change::Delete => transaction.remove(handle, key),
            }
        }
        transaction.insert(
            &meta,
            FJALL_INTERNAL_HEAD_SEQUENCE_KEY,
            sequence.to_be_bytes(),
        );
        transaction.commit().map_err(backend)?;
        let snapshot = self.storage.db.read_tx();
        let mut retained = self
            .storage
            .retained
            .write()
            .map_err(|_| StorageError::LockPoisoned)?;
        retained.insert(sequence, snapshot);
        while retained.len() > MAX_RETAINED_SNAPSHOTS {
            let _ = retained.pop_first();
        }
        Ok(CommitReceipt {
            sequence,
            durability,
        })
    }

    fn rollback(self) -> Result<()> {
        Ok(())
    }
}

impl StorageEngine for FjallStorage {
    type ReadSnapshot<'a> = FjallSnapshot;
    type WriteTransaction<'a> = FjallTransaction<'a>;

    fn head_sequence(&self) -> Result<StorageSequence> {
        self.latest_snapshot().map(|snapshot| snapshot.sequence)
    }

    fn begin_read(&self, selector: SnapshotSelector) -> Result<Self::ReadSnapshot<'_>> {
        if matches!(selector, SnapshotSelector::Latest) {
            return self.latest_snapshot();
        }
        let SnapshotSelector::At(requested) = selector else {
            return self.latest_snapshot();
        };
        let retained = self
            .retained
            .read()
            .map_err(|_| StorageError::LockPoisoned)?;
        let snapshot =
            retained
                .get(&requested)
                .cloned()
                .ok_or(StorageError::SnapshotUnavailable {
                    requested,
                    head: self.head_sequence()?,
                })?;
        Ok(FjallSnapshot {
            db: self.db.clone(),
            sequence: requested,
            snapshot,
        })
    }

    fn begin_write(&self) -> Result<Self::WriteTransaction<'_>> {
        Ok(FjallTransaction {
            storage: self,
            base: self.latest_snapshot()?,
            changes: HashMap::new(),
        })
    }

    fn checkpoint(&self, _target: &Path) -> Result<CheckpointManifest> {
        Err(StorageError::Unsupported {
            backend: "fjall",
            operation: "online physical checkpoint",
        })
    }

    fn compact(&self, _request: CompactRequest) -> Result<CompactReport> {
        // Fjall schedules physical compaction in its background supervisor.
        Ok(CompactReport {
            sequence: self.head_sequence()?,
            bytes_reclaimed: 0,
        })
    }

    fn verify(&self, _mode: VerifyMode) -> Result<VerifyReport> {
        let snapshot = self.latest_snapshot()?;
        let mut records = 0_u64;
        let mut keyspaces = 0_u64;
        for name in self.db.list_keyspace_names() {
            if name.as_ref() == FJALL_INTERNAL_META_KEYSPACE {
                continue;
            }
            keyspaces = keyspaces.saturating_add(1);
            let handle = self
                .db
                .keyspace(name.as_ref(), KeyspaceCreateOptions::default)
                .map_err(backend)?;
            for guard in snapshot.snapshot.iter(&handle) {
                guard.into_inner().map_err(backend)?;
                records = records.saturating_add(1);
            }
        }
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
    #![allow(
        clippy::unwrap_used,
        reason = "test fixtures use immediate failure semantics"
    )]

    use contextdb_storage::{
        Durability, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine,
        StorageError, WriteTransaction,
    };

    use super::FjallStorage;

    #[test]
    fn synced_commit_survives_reopen() {
        let directory = tempfile::tempdir().expect("tempdir");
        let space = Keyspace::new("records").expect("keyspace");
        {
            let db = FjallStorage::open(directory.path()).expect("open");
            let mut transaction = db.begin_write().expect("write");
            transaction
                .put(&space, b"key".to_vec(), b"value".to_vec())
                .expect("stage");
            transaction.commit(Durability::Sync).expect("commit");
        }
        let reopened = FjallStorage::open(directory.path()).expect("reopen");
        let snapshot = reopened.begin_read(SnapshotSelector::Latest).expect("read");
        assert_eq!(
            snapshot.get(&space, b"key").expect("get"),
            Some(b"value".to_vec())
        );
        assert_eq!(snapshot.sequence(), 1);
    }

    #[test]
    fn losing_write_conflict_does_not_materialize_its_new_keyspace() {
        let directory = tempfile::tempdir().expect("tempdir");
        let winner_space = Keyspace::new("winner_records").expect("winner keyspace");
        let loser_space = Keyspace::new("loser_records").expect("loser keyspace");
        {
            let db = FjallStorage::open(directory.path()).expect("open");
            let mut winner = db.begin_write().expect("winner writer");
            let mut loser = db.begin_write().expect("loser writer");
            winner
                .put(&winner_space, b"winner".to_vec(), b"value".to_vec())
                .expect("stage winner");
            loser
                .put(&loser_space, b"loser".to_vec(), b"value".to_vec())
                .expect("stage loser");
            winner.commit(Durability::Sync).expect("commit winner");
            let error = loser
                .commit(Durability::Sync)
                .expect_err("stale writer must conflict");
            assert!(matches!(
                error,
                StorageError::WriteConflict { base: 0, head: 1 }
            ));
            assert!(
                !db.physical_keyspace_names()
                    .iter()
                    .any(|name| name == loser_space.as_str())
            );
        }

        let reopened = FjallStorage::open(directory.path()).expect("reopen");
        let names = reopened.physical_keyspace_names();
        assert!(names.iter().any(|name| name == winner_space.as_str()));
        assert!(!names.iter().any(|name| name == loser_space.as_str()));
        let snapshot = reopened.begin_read(SnapshotSelector::Latest).expect("read");
        assert_eq!(snapshot.sequence(), 1);
        assert_eq!(
            snapshot.get(&winner_space, b"winner").expect("get winner"),
            Some(b"value".to_vec())
        );
    }

    #[test]
    fn committed_snapshot_retention_is_bounded_and_leases_remain_stable() {
        let directory = tempfile::tempdir().expect("tempdir");
        let space = Keyspace::new("records").expect("keyspace");
        let db = FjallStorage::open(directory.path()).expect("open");
        let leased_initial = db
            .begin_read(SnapshotSelector::At(0))
            .expect("initial lease");

        let commit_count = super::MAX_RETAINED_SNAPSHOTS as u64 + 2;
        for sequence in 1..=commit_count {
            let mut transaction = db.begin_write().expect("write");
            transaction
                .put(&space, b"key".to_vec(), sequence.to_be_bytes().to_vec())
                .expect("stage");
            let receipt = transaction.commit(Durability::Ephemeral).expect("commit");
            assert_eq!(receipt.sequence, sequence);
        }

        assert_eq!(
            db.retained.read().expect("retention lock").len(),
            super::MAX_RETAINED_SNAPSHOTS
        );
        assert!(matches!(
            db.begin_read(SnapshotSelector::At(0)),
            Err(StorageError::SnapshotUnavailable {
                requested: 0,
                head
            }) if head == commit_count
        ));
        let oldest_retained = commit_count - super::MAX_RETAINED_SNAPSHOTS as u64 + 1;
        let retained = db
            .begin_read(SnapshotSelector::At(oldest_retained))
            .expect("oldest retained snapshot");
        assert_eq!(
            retained.get(&space, b"key").expect("retained read"),
            Some(oldest_retained.to_be_bytes().to_vec())
        );
        assert_eq!(
            leased_initial.get(&space, b"key").expect("leased read"),
            None,
            "a lease opened before eviction must remain a stable snapshot"
        );
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
    fn paged_snapshot_and_staged_transaction_are_ordered_and_exclusive() {
        let directory = tempfile::tempdir().expect("tempdir");
        let db = FjallStorage::open(directory.path()).expect("open");
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
    }
}
