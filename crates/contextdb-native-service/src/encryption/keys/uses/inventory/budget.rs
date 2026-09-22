//! Charge the existing full journal verifier at its storage boundary. Budget
//! failures keep their service error code instead of becoming storage failures.

use std::cell::RefCell;

use contextdb_recall::QueryBudget;
use contextdb_service::{ServiceError, ServiceResult};
use contextdb_storage::{Entry, ScanPage, StorageSequence, collect_prefix_pages};

use super::*;

pub(super) struct BudgetedSnapshot<'a, S> {
    snapshot: S,
    budget: RefCell<&'a mut QueryBudget>,
    error: RefCell<Option<ServiceError>>,
}

impl<'a, S> BudgetedSnapshot<'a, S> {
    pub(super) fn new(snapshot: S, budget: &'a mut QueryBudget) -> Self {
        Self {
            snapshot,
            budget: RefCell::new(budget),
            error: RefCell::new(None),
        }
    }

    pub(super) fn reject(&self, error: ServiceError) -> StorageError {
        self.error.borrow_mut().get_or_insert(error);
        failure("native-use inventory inspection was interrupted")
    }

    pub(super) fn charge(&self, work: u64, bytes: u64) -> contextdb_storage::Result<()> {
        self.budget
            .borrow_mut()
            .charge(work, bytes)
            .map_err(|error| self.reject(crate::raw_index::budget_error(error)))
    }

    pub(super) fn complete<T>(self, result: contextdb_storage::Result<T>) -> ServiceResult<T> {
        result.map_err(|error| {
            self.error
                .into_inner()
                .unwrap_or_else(|| crate::storage_error(error))
        })
    }
}

impl<S: ReadSnapshot> ReadSnapshot for BudgetedSnapshot<'_, S> {
    fn sequence(&self) -> StorageSequence {
        self.snapshot.sequence()
    }

    fn get(&self, space: &Keyspace, key: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
        self.charge(1, key.len() as u64)?;
        let value = self.snapshot.get(space, key)?;
        self.charge(0, value.as_ref().map_or(0, |value| value.len()) as u64)?;
        Ok(value)
    }

    fn scan_prefix(
        &self,
        space: &Keyspace,
        prefix: &[u8],
    ) -> contextdb_storage::Result<Vec<Entry>> {
        collect_prefix_pages(self, space, prefix)
    }

    fn scan_prefix_page(
        &self,
        space: &Keyspace,
        mut request: ScanPageRequest<'_>,
    ) -> contextdb_storage::Result<ScanPage> {
        self.charge(1, 0)?;
        request.max_entries = request.max_entries.min(256);
        request.max_bytes = request.max_bytes.min(8 * 1024 * 1024);
        let page = self.snapshot.scan_prefix_page(space, request)?;
        self.charge(
            page.entries.len() as u64,
            page.entries
                .iter()
                .map(|row| (row.key.len() + row.value.len()) as u64)
                .sum(),
        )?;
        Ok(page)
    }
}
