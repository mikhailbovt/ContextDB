//! Benchmark-only RocksDB implementation of the ContextDB physical boundary.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use contextdb_storage::{
    CheckpointManifest, CommitReceipt, CompactReport, CompactRequest, Durability, Entry, Keyspace,
    ReadSnapshot, Result, SnapshotSelector, StorageEngine, StorageError, StorageSequence,
    VerifyMode, VerifyReport, WriteTransaction,
};
use rocksdb::{DB, IteratorMode, Options, WriteBatch, WriteOptions};

const BACKEND: &str = "rocksdb-benchmark";
const HEAD_KEY: &[u8] = b"\xffcontextdb/head/v1";

type LogicalKey = (String, Vec<u8>);
type LogicalMap = BTreeMap<LogicalKey, Vec<u8>>;

/// RocksDB comparison backend. It is intentionally absent from v1 runtime deps.
#[derive(Debug)]
pub struct RocksDbStorage {
    database: Arc<DB>,
    writer: Mutex<()>,
}

impl RocksDbStorage {
    /// Opens or creates a benchmark database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.set_paranoid_checks(true);
        let database = DB::open(&options, path).map_err(error)?;
        Ok(Self {
            database: Arc::new(database),
            writer: Mutex::new(()),
        })
    }

    fn materialize(&self) -> Result<LogicalMap> {
        let mut values = BTreeMap::new();
        for item in self.database.iterator(IteratorMode::Start) {
            let (key, value) = item.map_err(error)?;
            if key.as_ref() == HEAD_KEY {
                continue;
            }
            let logical = decode_key(&key)?;
            if values.insert(logical, value.to_vec()).is_some() {
                return Err(backend_error("duplicate logical key"));
            }
        }
        Ok(values)
    }
}

/// Owned stable view used by the comparison adapter.
#[derive(Clone, Debug)]
pub struct RocksDbSnapshot {
    sequence: StorageSequence,
    values: Arc<LogicalMap>,
}

impl ReadSnapshot for RocksDbSnapshot {
    fn sequence(&self) -> StorageSequence {
        self.sequence
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .values
            .get(&(keyspace.as_str().to_owned(), key.to_vec()))
            .cloned())
    }

    fn scan_prefix(&self, keyspace: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        for ((name, key), value) in self.values.iter() {
            if name == keyspace.as_str() && key.starts_with(prefix) {
                entries.push(Entry {
                    key: key.clone(),
                    value: value.clone(),
                });
            }
        }
        Ok(entries)
    }
}

/// Single-writer transaction with read-your-writes semantics.
#[derive(Debug)]
pub struct RocksDbTransaction<'a> {
    storage: &'a RocksDbStorage,
    _guard: MutexGuard<'a, ()>,
    base: StorageSequence,
    staged: BTreeMap<LogicalKey, Option<Vec<u8>>>,
}

impl ReadSnapshot for RocksDbTransaction<'_> {
    fn sequence(&self) -> StorageSequence {
        self.base
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let logical = (keyspace.as_str().to_owned(), key.to_vec());
        if let Some(staged) = self.staged.get(&logical) {
            return Ok(staged.clone());
        }
        self.storage
            .database
            .get(encode_key(keyspace.as_str(), key)?)
            .map_err(error)
    }

    fn scan_prefix(&self, keyspace: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        let mut values = self.storage.materialize()?;
        for (key, value) in &self.staged {
            match value {
                Some(bytes) => {
                    values.insert(key.clone(), bytes.clone());
                }
                None => {
                    values.remove(key);
                }
            }
        }
        RocksDbSnapshot {
            sequence: self.base,
            values: Arc::new(values),
        }
        .scan_prefix(keyspace, prefix)
    }
}

impl WriteTransaction for RocksDbTransaction<'_> {
    fn put(&mut self, keyspace: &Keyspace, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let logical = (keyspace.as_str().to_owned(), key);
        self.staged.insert(logical, Some(value));
        Ok(())
    }

    fn delete(&mut self, keyspace: &Keyspace, key: Vec<u8>) -> Result<()> {
        let logical = (keyspace.as_str().to_owned(), key);
        self.staged.insert(logical, None);
        Ok(())
    }

    fn commit(self, durability: Durability) -> Result<CommitReceipt> {
        let head = read_head(&self.storage.database)?;
        if head != self.base {
            return Err(StorageError::WriteConflict {
                base: self.base,
                head,
            });
        }
        let next = head
            .checked_add(1)
            .ok_or_else(|| backend_error("physical sequence exhausted"))?;
        let mut batch = WriteBatch::default();
        for ((keyspace, key), value) in self.staged {
            let physical = encode_key(&keyspace, &key)?;
            match value {
                Some(bytes) => batch.put(physical, bytes),
                None => batch.delete(physical),
            }
        }
        batch.put(HEAD_KEY, next.to_be_bytes());
        let mut options = WriteOptions::default();
        options.set_sync(durability == Durability::Sync);
        options.disable_wal(false);
        self.storage
            .database
            .write_opt(batch, &options)
            .map_err(error)?;
        Ok(CommitReceipt {
            sequence: next,
            durability,
        })
    }

    fn rollback(self) -> Result<()> {
        Ok(())
    }
}

impl StorageEngine for RocksDbStorage {
    type ReadSnapshot<'a>
        = RocksDbSnapshot
    where
        Self: 'a;
    type WriteTransaction<'a>
        = RocksDbTransaction<'a>
    where
        Self: 'a;

    fn head_sequence(&self) -> Result<StorageSequence> {
        read_head(&self.database)
    }

    fn begin_read(&self, selector: SnapshotSelector) -> Result<Self::ReadSnapshot<'_>> {
        let head = self.head_sequence()?;
        if let SnapshotSelector::At(requested) = selector
            && requested != head
        {
            return Err(StorageError::SnapshotUnavailable { requested, head });
        }
        Ok(RocksDbSnapshot {
            sequence: head,
            values: Arc::new(self.materialize()?),
        })
    }

    fn begin_write(&self) -> Result<Self::WriteTransaction<'_>> {
        let guard = self.writer.lock().map_err(|_| StorageError::LockPoisoned)?;
        let base = self.head_sequence()?;
        Ok(RocksDbTransaction {
            storage: self,
            _guard: guard,
            base,
            staged: BTreeMap::new(),
        })
    }

    fn checkpoint(&self, target: &Path) -> Result<CheckpointManifest> {
        let _guard = self.writer.lock().map_err(|_| StorageError::LockPoisoned)?;
        self.database.flush().map_err(error)?;
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.database).map_err(error)?;
        checkpoint.create_checkpoint(target).map_err(error)?;
        Ok(CheckpointManifest {
            format_version: 1,
            sequence: self.head_sequence()?,
            backend: BACKEND.to_owned(),
        })
    }

    fn compact(&self, _request: CompactRequest) -> Result<CompactReport> {
        let _guard = self.writer.lock().map_err(|_| StorageError::LockPoisoned)?;
        let sequence = self.head_sequence()?;
        self.database.compact_range(None::<&[u8]>, None::<&[u8]>);
        Ok(CompactReport {
            sequence,
            bytes_reclaimed: 0,
        })
    }

    fn verify(&self, _mode: VerifyMode) -> Result<VerifyReport> {
        let sequence = self.head_sequence()?;
        let values = self.materialize()?;
        let keyspaces = values
            .keys()
            .map(|(keyspace, _)| keyspace)
            .collect::<BTreeSet<_>>()
            .len();
        Ok(VerifyReport {
            sequence,
            keyspaces: u64::try_from(keyspaces).unwrap_or(u64::MAX),
            records: u64::try_from(values.len()).unwrap_or(u64::MAX),
            warnings: vec![
                "benchmark-only FFI adapter; retained historical physical snapshots are unsupported"
                    .to_owned(),
            ],
        })
    }
}

fn read_head(database: &DB) -> Result<StorageSequence> {
    let Some(bytes) = database.get(HEAD_KEY).map_err(error)? else {
        return Ok(0);
    };
    let bytes: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| backend_error("head sequence has invalid length"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn encode_key(keyspace: &str, key: &[u8]) -> Result<Vec<u8>> {
    let length =
        u16::try_from(keyspace.len()).map_err(|_| backend_error("keyspace name exceeds u16"))?;
    let mut encoded = Vec::with_capacity(2 + keyspace.len() + key.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(keyspace.as_bytes());
    encoded.extend_from_slice(key);
    Ok(encoded)
}

fn decode_key(key: &[u8]) -> Result<LogicalKey> {
    let length_bytes: [u8; 2] = key
        .get(..2)
        .ok_or_else(|| backend_error("physical key is truncated"))?
        .try_into()
        .map_err(|_| backend_error("physical key length is invalid"))?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    let name_end = 2_usize
        .checked_add(length)
        .ok_or_else(|| backend_error("physical key length overflow"))?;
    let name = std::str::from_utf8(
        key.get(2..name_end)
            .ok_or_else(|| backend_error("physical keyspace is truncated"))?,
    )
    .map_err(|_| backend_error("physical keyspace is not UTF-8"))?;
    Keyspace::new(name.to_owned())?;
    let logical = key
        .get(name_end..)
        .ok_or_else(|| backend_error("physical logical key is truncated"))?;
    Ok((name.to_owned(), logical.to_vec()))
}

fn error(error: rocksdb::Error) -> StorageError {
    backend_error(error.to_string())
}

fn backend_error(message: impl Into<String>) -> StorageError {
    StorageError::Backend {
        backend: BACKEND,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use contextdb_storage::{
        Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
    };

    use super::RocksDbStorage;

    #[test]
    fn synced_atomic_batch_reopens() {
        let directory = tempfile::tempdir().expect("temporary RocksDB directory");
        let path = directory.path().join("rocksdb");
        let keyspace = Keyspace::new("semantic").expect("portable keyspace");
        {
            let storage = RocksDbStorage::open(&path).expect("open RocksDB");
            let mut transaction = storage.begin_write().expect("writer");
            transaction
                .put(&keyspace, b"b".to_vec(), b"two".to_vec())
                .expect("put b");
            transaction
                .put(&keyspace, b"a".to_vec(), b"one".to_vec())
                .expect("put a");
            let receipt = transaction.commit(Durability::Sync).expect("sync commit");
            assert_eq!(receipt.sequence, 1);
        }
        let reopened = RocksDbStorage::open(&path).expect("reopen RocksDB");
        let snapshot = reopened
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        assert_eq!(
            snapshot.get(&keyspace, b"a").expect("read a"),
            Some(b"one".to_vec())
        );
        assert_eq!(
            snapshot
                .scan_prefix(&keyspace, b"")
                .expect("ordered scan")
                .into_iter()
                .map(|entry| entry.key)
                .collect::<Vec<_>>(),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
    }
}
