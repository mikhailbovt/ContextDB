//! Verify exact retained control acceptance; a lost locator is never absence.

use super::*;

impl NativeSuppressionLedger {
    // Follow the accepted suffix even on retries: a lost index is never absence
    // evidence. No history is restarted, and all work shares the caller's budget.
    pub(super) fn find_retained_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        requested: &RemovalCheckpoint,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<(RemovalCheckpoint, Operation)>> {
        let head = self.removal_global_head(snapshot)?;
        let tail = snapshot
            .scan_prefix_page(
                &self.rows,
                ScanPageRequest {
                    prefix: b"removal/event/",
                    start_after: Some(&event_key(head.sequence)),
                    max_entries: 1,
                    max_bytes: 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        for row in &tail.entries {
            budget
                .charge(1, (row.key.len() + row.value.len()) as u64)
                .map_err(budget_error)?;
        }
        if !tail.entries.is_empty() {
            return Err(integrity(
                "retained control head is behind its accepted journal",
            ));
        }
        if requested.sequence == 0 || requested.sequence > head.sequence {
            return Err(integrity(
                "retained control removal request is outside retained history",
            ));
        }
        let request = self.budgeted_removal_event(snapshot, requested.sequence, budget)?;
        if request.checkpoint() != *requested
            || !matches!(&request.operation, Operation::Request { intent, .. } if intent.workspace == workspace)
        {
            return Err(integrity("retained control removal request differs"));
        }
        let mut previous = request.checkpoint();
        let mut found = None;
        for sequence in requested.sequence..head.sequence {
            let event = self.budgeted_removal_event(snapshot, sequence + 1, budget)?;
            if event.previous != previous.digest {
                return Err(integrity("retained control suffix is discontinuous"));
            }
            let matches = match &event.operation {
                Operation::RecordWitness { witness } => witness.key() == key,
                Operation::AssertionWitness { witness } => witness.key() == key,
                Operation::RecordValidation { validation } => validation.key() == key,
                Operation::RawIndexInventory { witness } => witness.key() == key,
                Operation::PrimaryKeys { witness } => witness.key() == key,
                _ => false,
            };
            if matches {
                if found.is_some() {
                    return Err(integrity("duplicate retained control"));
                }
                found = Some((event.checkpoint(), event.operation.clone()));
            }
            previous = event.checkpoint();
        }
        if previous != head {
            return Err(integrity("retained control terminal differs"));
        }
        let locator = snapshot.get(&self.rows, key).map_err(storage_error)?;
        if let Some(bytes) = &locator {
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        }
        if locator
            != found
                .as_ref()
                .map(|(checkpoint, _)| encode(checkpoint))
                .transpose()?
        {
            return Err(integrity(
                "retained control locator differs from accepted history",
            ));
        }
        Ok(found)
    }

    pub(super) fn budgeted_removal_event<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        sequence: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Event> {
        let bytes = snapshot
            .get(&self.rows, &event_key(sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retained witness event absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > 1024 * 1024 {
            return Err(exhausted("retained witness event exceeds its bound"));
        }
        self.decode_removal_event(&bytes, sequence)
    }
}
