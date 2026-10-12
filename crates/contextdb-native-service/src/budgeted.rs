//! Parent-owned bounded native reads. Ordinary readers retain their old paths.

use crate::raw_index::budget_error;
use contextdb_recall::{QueryBudget, QueryLimit};
use contextdb_service::ServiceResult;
use contextdb_storage::{ReadSnapshot, ScanPageRequest};

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
use contextdb_storage::{Entry, Keyspace, ScanPage, StorageError, StorageSequence};
use std::cell::Cell;

/// Bound the encrypted row before native decoding. The maximum is a cap, not a
/// charge: small metadata pays its actual returned size. The retained caller's
/// decode/validation charges use the same parent allowance after this read.
pub(crate) fn read_value<S: ReadSnapshot>(
    snapshot: &S,
    space: &Keyspace,
    key: &[u8],
    max_value_bytes: usize,
    budget: &mut QueryBudget,
) -> ServiceResult<Option<Vec<u8>>> {
    metadata(snapshot, budget, |meter| {
        meter
            .get_row(space, key, max_value_bytes, 4)
            .map_err(crate::storage_error)
    })
}

pub(crate) fn metadata<S: ReadSnapshot, T>(
    snapshot: &S,
    budget: &mut QueryBudget,
    read: impl FnOnce(&Meter<'_, S>) -> ServiceResult<T>,
) -> ServiceResult<T> {
    let (result, work, bytes, failure) = {
        let meter = Meter {
            snapshot,
            budget,
            work: Cell::new(0),
            bytes: Cell::new(0),
            failure: Cell::new(None),
        };
        let result = read(&meter);
        (
            result,
            meter.work.get(),
            meter.bytes.get(),
            meter.failure.get(),
        )
    };
    budget.charge(work, bytes).map_err(budget_error)?;
    if let Some(reason) = failure {
        return Err(budget_error(reason));
    }
    result
}

pub(crate) struct Meter<'a, S> {
    snapshot: &'a S,
    budget: &'a QueryBudget,
    work: Cell<u64>,
    bytes: Cell<u64>,
    failure: Cell<Option<QueryLimit>>,
}
impl<S> Meter<'_, S> {
    fn charge(&self, work: u64, bytes: u64) -> contextdb_storage::Result<()> {
        let next_work = self.work.get().saturating_add(work);
        let next_bytes = self.bytes.get().saturating_add(bytes);
        let reason = self
            .budget
            .check()
            .err()
            .or_else(|| (next_work > self.budget.remaining_work()).then_some(QueryLimit::Work))
            .or_else(|| (next_bytes > self.budget.remaining_bytes()).then_some(QueryLimit::Bytes));
        if let Some(reason) = reason {
            self.failure.set(Some(reason));
            return Err(StorageError::Backend {
                backend: "native-bm25-budget",
                message: "parent retrieval allowance exceeded".into(),
            });
        }
        self.work.set(next_work);
        self.bytes.set(next_bytes);
        Ok(())
    }
}

impl<S: ReadSnapshot> Meter<'_, S> {
    fn get_row(
        &self,
        keyspace: &Keyspace,
        key: &[u8],
        max_value_bytes: usize,
        allocation_factor: u64,
    ) -> contextdb_storage::Result<Option<Vec<u8>>> {
        self.charge(2, key.len() as u64 + 64)?;
        let bytes = self
            .budget
            .remaining_bytes()
            .saturating_sub(self.bytes.get())
            / allocation_factor;
        if bytes == 0 {
            self.failure.set(Some(QueryLimit::Bytes));
            return Err(StorageError::Backend {
                backend: "native-bm25-budget",
                message: "parent point-read allowance exhausted".into(),
            });
        }
        let row_bound = max_value_bytes
            .saturating_add(key.len())
            .saturating_add(256);
        let max_bytes = row_bound.min(bytes.min(usize::MAX as u64) as usize);
        let page = self.snapshot.scan_prefix_page(
            keyspace,
            ScanPageRequest {
                prefix: key,
                start_after: None,
                max_entries: 1,
                max_bytes,
            },
        );
        let page = match page {
            Ok(page) => page,
            Err(error) => {
                if matches!(
                    error,
                    StorageError::ResourceExhausted {
                        resource: "scan_page_bytes",
                        ..
                    }
                ) && bytes < row_bound as u64
                {
                    self.failure.set(Some(QueryLimit::Bytes));
                }
                return Err(error);
            }
        };
        self.charge(
            0,
            page.entries
                .iter()
                .map(|row| 2 * (row.key.len() + row.value.len()) as u64)
                .sum(),
        )?;
        let Some(row) = page.entries.into_iter().next().filter(|row| row.key == key) else {
            return Ok(None);
        };
        if allocation_factor == 4 && row.value.len() > max_value_bytes {
            return Err(StorageError::Backend {
                backend: "native-bm25-budget",
                message: "native point row exceeds its declared bound".into(),
            });
        }
        Ok(Some(row.value))
    }
}
impl<S: ReadSnapshot> ReadSnapshot for Meter<'_, S> {
    fn sequence(&self) -> StorageSequence {
        self.snapshot.sequence()
    }
    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
        self.get_row(keyspace, key, MAX_RECORD_BYTES, 2)
    }
    fn scan_prefix(&self, _: &Keyspace, _: &[u8]) -> contextdb_storage::Result<Vec<Entry>> {
        Err(StorageError::Unsupported {
            backend: "native-bm25-budget",
            operation: "unbounded prefix scan",
        })
    }
    fn scan_prefix_page(
        &self,
        keyspace: &Keyspace,
        mut request: ScanPageRequest<'_>,
    ) -> contextdb_storage::Result<ScanPage> {
        self.charge(1, request.prefix.len() as u64)?;
        let work = self.budget.remaining_work().saturating_sub(self.work.get());
        let available_bytes = self
            .budget
            .remaining_bytes()
            .saturating_sub(self.bytes.get());
        if work == 0 || available_bytes < 128 {
            self.failure.set(Some(if work == 0 {
                QueryLimit::Work
            } else {
                QueryLimit::Bytes
            }));
            return Err(StorageError::Backend {
                backend: "native-bm25-budget",
                message: "parent scan allowance exhausted".into(),
            });
        }
        let work_limited = request.max_entries as u64 > work;
        let entries = request
            .max_entries
            .min(work.min(usize::MAX as u64) as usize)
            .min((available_bytes / 128).min(usize::MAX as u64) as usize);
        let headers_limited = entries < request.max_entries && !work_limited;
        self.charge(0, entries as u64 * 64)?;
        let bytes = self
            .budget
            .remaining_bytes()
            .saturating_sub(self.bytes.get())
            / 2;
        let byte_limited = headers_limited || request.max_bytes as u64 > bytes;
        request.max_entries = entries;
        request.max_bytes = request.max_bytes.min(bytes.min(usize::MAX as u64) as usize);
        let page = match self.snapshot.scan_prefix_page(keyspace, request) {
            Ok(page) => page,
            Err(error) => {
                if byte_limited
                    && matches!(
                        error,
                        StorageError::ResourceExhausted {
                            resource: "scan_page_bytes",
                            ..
                        }
                    )
                {
                    self.failure.set(Some(QueryLimit::Bytes));
                }
                return Err(error);
            }
        };
        self.charge(
            page.entries.len() as u64,
            page.entries
                .iter()
                .map(|entry| 2 * (entry.key.len() + entry.value.len()) as u64)
                .sum(),
        )?;
        if page.continuation.is_some() && (work_limited || byte_limited) {
            self.failure.set(Some(if work_limited {
                QueryLimit::Work
            } else {
                QueryLimit::Bytes
            }));
            return Err(StorageError::Backend {
                backend: "native-bm25-budget",
                message: "parent bounded page allowance exhausted".into(),
            });
        }
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeService;
    use contextdb_core::ContentBlockId;
    use contextdb_service::{ErrorCode, PayloadPort, StagePayloadRequest};
    use contextdb_storage::{SnapshotSelector, StorageEngine};

    struct BoundedChunk<'a, S> {
        snapshot: &'a S,
        requested: Cell<Option<usize>>,
    }
    impl<S: ReadSnapshot> ReadSnapshot for BoundedChunk<'_, S> {
        fn sequence(&self) -> StorageSequence {
            self.snapshot.sequence()
        }
        fn get(&self, _: &Keyspace, _: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
            panic!("authenticated chunk must not use an unbounded point read")
        }
        fn scan_prefix(&self, _: &Keyspace, _: &[u8]) -> contextdb_storage::Result<Vec<Entry>> {
            panic!("point admission must not scan a whole prefix")
        }
        fn scan_prefix_page(
            &self,
            space: &Keyspace,
            request: ScanPageRequest<'_>,
        ) -> contextdb_storage::Result<ScanPage> {
            assert_eq!(request.max_entries, 1);
            assert!(
                request.max_bytes <= 16 * 1024,
                "budget bounds ciphertext before native decode"
            );
            self.requested.set(Some(request.max_bytes));
            self.snapshot.scan_prefix_page(space, request)
        }
    }

    #[test]
    fn authenticated_large_chunk_is_refused_by_small_parent_before_decode() {
        let root = tempfile::tempdir().expect("native directory");
        let (_ledger_root, ledger) = crate::suppression::tests::authority("bounded-chunk");
        let (_keys_root, keys) = crate::encryption::tests::authority("bounded-chunk");
        let native =
            NativeService::open_encrypted(root.path(), "bounded-chunk", [29; 32], ledger, keys)
                .expect("encrypted native");
        let request = crate::capture::tests::request(1, "chunk staging authority");
        let block = ContentBlockId::new();
        native
            .stage_payload(StagePayloadRequest {
                context: request.context,
                idempotency_key: "authenticated-chunk".into(),
                block_id: block,
                bytes: vec![b'z'; 256 * 1024],
            })
            .expect("durable authenticated chunk");
        let snapshot = native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("read snapshot");
        let reader = BoundedChunk {
            snapshot: &snapshot,
            requested: Cell::new(None),
        };
        let key = crate::payload::chunk_key(block, 0);
        let mut parent = QueryBudget::new(
            100,
            64 * 1024,
            std::time::Duration::from_secs(10),
            Default::default(),
        );
        let error = read_value(
            &reader,
            &native.keyspaces.continuous,
            &key,
            256 * 1024,
            &mut parent,
        )
        .expect_err("parent cannot admit the full encrypted chunk");
        assert_eq!(error.code, ErrorCode::BudgetExhausted);
        assert!(reader.requested.get().is_some());
        assert!(
            parent.remaining_bytes() > 63 * 1024,
            "only attempted IO metadata is charged on pre-decode refusal"
        );
    }
}
