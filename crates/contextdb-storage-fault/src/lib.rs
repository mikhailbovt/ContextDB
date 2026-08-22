//! Deterministic storage-boundary fault injection.
//!
//! This crate is test infrastructure, not a runtime backend. It permits the
//! journal and higher layers to distinguish a rejected atomic commit, a commit
//! whose response was lost, and a backend that reports weaker durability.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use contextdb_storage::{
    CheckpointManifest, CommitReceipt, CompactReport, CompactRequest, Durability, Entry, Keyspace,
    ReadSnapshot, Result, ScanPage, ScanPageRequest, SnapshotSelector, StorageEngine, StorageError,
    StorageSequence, VerifyMode, VerifyReport, WriteTransaction,
};

const BACKEND: &str = "fault-injection";

/// One deterministic action consumed by the next matching write commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultAction {
    /// Return an ENOSPC-like error before the underlying atomic commit.
    NoSpaceBeforeCommit,
    /// Commit atomically, then lose the response before the caller sees it.
    LoseResponseAfterCommit,
    /// Commit but falsely report only ephemeral durability.
    WeakenDurabilityReceipt,
}

/// Shared FIFO fault schedule controlled by a test harness.
#[derive(Clone, Debug, Default)]
pub struct FaultController {
    actions: Arc<Mutex<VecDeque<FaultAction>>>,
}

impl FaultController {
    /// Appends one action to the deterministic schedule.
    pub fn arm(&self, action: FaultAction) -> Result<()> {
        self.actions
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .push_back(action);
        Ok(())
    }

    /// Returns the number of scheduled actions not yet consumed.
    pub fn pending(&self) -> Result<usize> {
        Ok(self
            .actions
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .len())
    }

    fn take(&self) -> Result<Option<FaultAction>> {
        Ok(self
            .actions
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .pop_front())
    }
}

/// Transparent engine wrapper paired with a deterministic [`FaultController`].
pub struct FaultStorage<E> {
    engine: E,
    controller: FaultController,
}

impl<E> fmt::Debug for FaultStorage<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FaultStorage")
            .finish_non_exhaustive()
    }
}

impl<E> FaultStorage<E> {
    /// Wraps an engine and returns its independent control handle.
    #[must_use]
    pub fn new(engine: E) -> (Self, FaultController) {
        let controller = FaultController::default();
        (
            Self {
                engine,
                controller: controller.clone(),
            },
            controller,
        )
    }

    /// Consumes the wrapper without changing the underlying engine.
    #[must_use]
    pub fn into_inner(self) -> E {
        self.engine
    }
}

/// Write transaction which consumes at most one scheduled commit action.
pub struct FaultTransaction<T> {
    inner: T,
    controller: FaultController,
}

impl<T> fmt::Debug for FaultTransaction<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FaultTransaction")
            .finish_non_exhaustive()
    }
}

impl<T: ReadSnapshot> ReadSnapshot for FaultTransaction<T> {
    fn sequence(&self) -> StorageSequence {
        self.inner.sequence()
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner.get(keyspace, key)
    }

    fn scan_prefix(&self, keyspace: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>> {
        self.inner.scan_prefix(keyspace, prefix)
    }

    fn scan_prefix_page(
        &self,
        keyspace: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> Result<ScanPage> {
        self.inner.scan_prefix_page(keyspace, request)
    }
}

impl<T: WriteTransaction> WriteTransaction for FaultTransaction<T> {
    fn put(&mut self, keyspace: &Keyspace, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.inner.put(keyspace, key, value)
    }

    fn delete(&mut self, keyspace: &Keyspace, key: Vec<u8>) -> Result<()> {
        self.inner.delete(keyspace, key)
    }

    fn commit(self, durability: Durability) -> Result<CommitReceipt> {
        match self.controller.take()? {
            Some(FaultAction::NoSpaceBeforeCommit) => Err(StorageError::Backend {
                backend: BACKEND,
                message: "injected no space left on device before atomic commit".to_owned(),
            }),
            Some(FaultAction::LoseResponseAfterCommit) => {
                self.inner.commit(durability)?;
                Err(StorageError::Backend {
                    backend: BACKEND,
                    message: "injected response loss after atomic commit".to_owned(),
                })
            }
            Some(FaultAction::WeakenDurabilityReceipt) => {
                let mut receipt = self.inner.commit(durability)?;
                receipt.durability = Durability::Ephemeral;
                Ok(receipt)
            }
            None => self.inner.commit(durability),
        }
    }

    fn rollback(self) -> Result<()> {
        self.inner.rollback()
    }
}

impl<E: StorageEngine> StorageEngine for FaultStorage<E> {
    type ReadSnapshot<'a>
        = E::ReadSnapshot<'a>
    where
        Self: 'a;
    type WriteTransaction<'a>
        = FaultTransaction<E::WriteTransaction<'a>>
    where
        Self: 'a;

    fn head_sequence(&self) -> Result<StorageSequence> {
        self.engine.head_sequence()
    }

    fn begin_read(&self, selector: SnapshotSelector) -> Result<Self::ReadSnapshot<'_>> {
        self.engine.begin_read(selector)
    }

    fn begin_write(&self) -> Result<Self::WriteTransaction<'_>> {
        Ok(FaultTransaction {
            inner: self.engine.begin_write()?,
            controller: self.controller.clone(),
        })
    }

    fn checkpoint(&self, target: &Path) -> Result<CheckpointManifest> {
        self.engine.checkpoint(target)
    }

    fn compact(&self, request: CompactRequest) -> Result<CompactReport> {
        self.engine.compact(request)
    }

    fn verify(&self, mode: VerifyMode) -> Result<VerifyReport> {
        self.engine.verify(mode)
    }
}

#[cfg(test)]
mod tests {
    use contextdb_storage::{
        Durability, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine,
        WriteTransaction,
    };
    use contextdb_storage_memory::MemoryStorage;

    use super::{FaultAction, FaultStorage};

    #[test]
    fn differentiates_precommit_failure_response_loss_and_weak_receipt() {
        let (storage, faults) = FaultStorage::new(MemoryStorage::new());
        let keyspace = Keyspace::new("fault_test").expect("keyspace");

        faults
            .arm(FaultAction::NoSpaceBeforeCommit)
            .expect("arm no-space");
        let mut rejected = storage.begin_write().expect("writer");
        rejected
            .put(&keyspace, b"rejected".to_vec(), b"no".to_vec())
            .expect("stage rejected value");
        assert!(rejected.commit(Durability::Sync).is_err());
        assert_eq!(storage.head_sequence().expect("head"), 0);

        faults
            .arm(FaultAction::LoseResponseAfterCommit)
            .expect("arm response loss");
        let mut lost = storage.begin_write().expect("writer");
        lost.put(&keyspace, b"durable".to_vec(), b"yes".to_vec())
            .expect("stage durable value");
        assert!(lost.commit(Durability::Sync).is_err());
        assert_eq!(storage.head_sequence().expect("head"), 1);
        assert_eq!(
            storage
                .begin_read(SnapshotSelector::Latest)
                .expect("snapshot")
                .get(&keyspace, b"durable")
                .expect("read durable value"),
            Some(b"yes".to_vec())
        );

        faults
            .arm(FaultAction::WeakenDurabilityReceipt)
            .expect("arm weak receipt");
        let weak = storage
            .begin_write()
            .expect("writer")
            .commit(Durability::Sync)
            .expect("underlying commit");
        assert_eq!(weak.durability, Durability::Ephemeral);
        assert_eq!(faults.pending().expect("pending actions"), 0);
    }

    #[test]
    fn write_transaction_delegates_bounded_page_scans() {
        let (storage, _faults) = FaultStorage::new(MemoryStorage::new());
        let keyspace = Keyspace::new("fault_test").expect("keyspace");
        let mut transaction = storage.begin_write().expect("writer");
        for key in [b"a0", b"a1", b"a2"] {
            transaction
                .put(&keyspace, key.to_vec(), b"v".to_vec())
                .expect("put");
        }
        let page = transaction
            .scan_prefix_page(
                &keyspace,
                ScanPageRequest {
                    prefix: b"a",
                    start_after: None,
                    max_entries: 2,
                    max_bytes: 100,
                },
            )
            .expect("first page");
        assert_eq!(
            page.entries
                .iter()
                .map(|entry| entry.key.as_slice())
                .collect::<Vec<_>>(),
            vec![b"a0".as_slice(), b"a1".as_slice()]
        );
        assert_eq!(page.continuation.as_deref(), Some(b"a1".as_slice()));
    }
}
