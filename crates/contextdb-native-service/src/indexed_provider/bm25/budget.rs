//! Bounded accounting for metadata helpers without changing legacy readers.

use super::*;
use contextdb_storage::{Entry, Keyspace, ScanPage, StorageError, StorageSequence};
use std::cell::Cell;

pub(super) fn metadata<S: ReadSnapshot, T>(
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

pub(super) struct Meter<'a, S> {
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
impl<S: ReadSnapshot> ReadSnapshot for Meter<'_, S> {
    fn sequence(&self) -> StorageSequence {
        self.snapshot.sequence()
    }
    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
        self.charge(2, key.len() as u64 + 64)?;
        let bytes = self
            .budget
            .remaining_bytes()
            .saturating_sub(self.bytes.get())
            / 2;
        if bytes == 0 {
            self.failure.set(Some(QueryLimit::Bytes));
            return Err(StorageError::Backend {
                backend: "native-bm25-budget",
                message: "parent point-read allowance exhausted".into(),
            });
        }
        // Native pages bound the ciphertext row before decoding. An exact key is
        // the first possible row under this prefix; nearby rows never stand in.
        let max_bytes =
            (MAX_RECORD_BYTES + key.len() + 256).min(bytes.min(usize::MAX as u64) as usize);
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
                ) && bytes < (MAX_RECORD_BYTES + key.len() + 256) as u64
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
        Ok(page
            .entries
            .into_iter()
            .next()
            .filter(|row| row.key == key)
            .map(|row| row.value))
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
