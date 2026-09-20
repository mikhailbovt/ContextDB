use std::{path::Path, sync::Arc};

use contextdb_storage::{
    CheckpointManifest, CommitReceipt, CompactReport, CompactRequest, Durability, Entry,
    ReadSnapshot, Result, ScanPage, ScanPageRequest, SnapshotSelector, StorageEngine,
    StorageSequence, VerifyMode, VerifyReport, WriteTransaction, collect_prefix_pages,
};
use contextdb_storage_fjall::{FjallSnapshot, FjallStorage, FjallTransaction};

use super::{keys::PendingKeys, *};

pub(crate) struct NativeStorage {
    inner: FjallStorage,
    pub(crate) keys: Option<Arc<NativeCustodyKeys>>,
}

#[derive(Clone)]
pub(crate) struct DecodedSnapshot<S> {
    pub(crate) inner: S,
    keys: Option<Arc<NativeCustodyKeys>>,
}

pub(crate) type NativeSnapshot = DecodedSnapshot<FjallSnapshot>;

impl<S: std::fmt::Debug> std::fmt::Debug for DecodedSnapshot<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSnapshot")
            .field("physical", &self.inner)
            .field("encrypted", &self.keys.is_some())
            .finish()
    }
}

pub(crate) struct NativeTransaction<'a> {
    inner: FjallTransaction<'a>,
    keys: Option<Arc<NativeCustodyKeys>>,
    pending: PendingKeys,
}

impl NativeStorage {
    #[cfg(test)]
    pub(super) fn physical(&self) -> &FjallStorage {
        &self.inner
    }
    pub(crate) fn open(path: &Path, keys: Option<Arc<NativeCustodyKeys>>) -> Result<Self> {
        Ok(Self {
            inner: FjallStorage::open(path)?,
            keys,
        })
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        self.keys.is_some()
    }

    pub(crate) fn physical_keyspace_names(&self) -> Vec<String> {
        self.inner.physical_keyspace_names()
    }

    pub(crate) fn decode_snapshot<S: ReadSnapshot>(&self, snapshot: S) -> DecodedSnapshot<S> {
        DecodedSnapshot {
            inner: snapshot,
            keys: self.keys.clone(),
        }
    }
}

impl<S: ReadSnapshot> ReadSnapshot for DecodedSnapshot<S> {
    fn sequence(&self) -> StorageSequence {
        self.inner.sequence()
    }

    fn get(&self, space: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner
            .get(space, key)?
            .map(|value| decode_value(self.keys.as_deref(), space, key, value, None))
            .transpose()
    }

    fn scan_prefix(&self, space: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        collect_prefix_pages(self, space, prefix)
    }

    fn scan_prefix_page(&self, space: &Keyspace, request: ScanPageRequest<'_>) -> Result<ScanPage> {
        decode_page(
            self.inner.scan_prefix_page(space, request)?,
            self.keys.as_deref(),
            space,
            None,
        )
    }
}

impl ReadSnapshot for NativeTransaction<'_> {
    fn sequence(&self) -> StorageSequence {
        self.inner.sequence()
    }

    fn get(&self, space: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner
            .get(space, key)?
            .map(|value| decode_value(self.keys.as_deref(), space, key, value, Some(&self.pending)))
            .transpose()
    }

    fn scan_prefix(&self, space: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        collect_prefix_pages(self, space, prefix)
    }

    fn scan_prefix_page(&self, space: &Keyspace, request: ScanPageRequest<'_>) -> Result<ScanPage> {
        decode_page(
            self.inner.scan_prefix_page(space, request)?,
            self.keys.as_deref(),
            space,
            Some(&self.pending),
        )
    }
}

impl WriteTransaction for NativeTransaction<'_> {
    fn put(&mut self, space: &Keyspace, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let value = match &self.keys {
            Some(keys) => keys.seal_value(space, &key, &value, &mut self.pending)?,
            None => value,
        };
        self.inner.put(space, key, value)
    }

    fn delete(&mut self, space: &Keyspace, key: Vec<u8>) -> Result<()> {
        // Row GC does not destroy keys while short physical views may exist.
        // Complete deletion requires a separately inventoried closure executor.
        self.inner.delete(space, key)
    }

    fn commit(self, durability: Durability) -> Result<CommitReceipt> {
        if let Some(keys) = &self.keys {
            keys.publish(&self.pending)?;
        }
        #[cfg(test)]
        BEFORE_NATIVE_COMMIT.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        self.inner.commit(durability)
    }

    fn rollback(self) -> Result<()> {
        self.inner.rollback()
    }
}

impl StorageEngine for NativeStorage {
    type ReadSnapshot<'a> = NativeSnapshot;
    type WriteTransaction<'a> = NativeTransaction<'a>;

    fn head_sequence(&self) -> Result<StorageSequence> {
        self.inner.head_sequence()
    }
    fn begin_read(&self, selector: SnapshotSelector) -> Result<Self::ReadSnapshot<'_>> {
        Ok(self.decode_snapshot(self.inner.begin_read(selector)?))
    }
    fn begin_write(&self) -> Result<Self::WriteTransaction<'_>> {
        Ok(NativeTransaction {
            inner: self.inner.begin_write()?,
            keys: self.keys.clone(),
            pending: Default::default(),
        })
    }
    fn checkpoint(&self, target: &Path) -> Result<CheckpointManifest> {
        self.inner.checkpoint(target)
    }
    fn compact(&self, request: CompactRequest) -> Result<CompactReport> {
        self.inner.compact(request)
    }
    fn verify(&self, mode: VerifyMode) -> Result<VerifyReport> {
        self.inner.verify(mode)
    }
}

fn decode_value(
    keys: Option<&NativeCustodyKeys>,
    space: &Keyspace,
    key: &[u8],
    value: Vec<u8>,
    pending: Option<&PendingKeys>,
) -> Result<Vec<u8>> {
    match keys {
        Some(keys) => keys.open_value(space, key, &value, pending),
        None => Ok(value),
    }
}

fn decode_page(
    mut page: ScanPage,
    keys: Option<&NativeCustodyKeys>,
    space: &Keyspace,
    pending: Option<&PendingKeys>,
) -> Result<ScanPage> {
    if let Some(keys) = keys {
        for entry in &mut page.entries {
            entry.value = keys.open_value(space, &entry.key, &entry.value, pending)?;
        }
    }
    Ok(page)
}

#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_NATIVE_COMMIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
