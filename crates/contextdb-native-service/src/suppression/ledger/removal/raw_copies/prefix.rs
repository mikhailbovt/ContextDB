//! Authenticate a fixed observation prefix against the complete retained journal.

use super::*;
use crate::NativeRawObservationFrontier;

#[cfg(test)]
mod tests;

impl NativeSuppressionLedger {
    pub(crate) fn walk_raw_copy_prefix(
        &self,
        workspace: &str,
        frozen: Option<&NativeRawObservationFrontier>,
        budget: &mut QueryBudget,
        visit: impl FnMut(
            NativeRawCopyReceipt,
            NativeRawCopyWitness,
            &mut QueryBudget,
        ) -> ServiceResult<()>,
    ) -> ServiceResult<NativeRawObservationFrontier> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.removal_global_head(&snapshot)?;
        let frontier = frozen.cloned().unwrap_or(NativeRawObservationFrontier {
            authority_id: self.authority_id(),
            sequence: head.sequence,
            digest: head.digest,
        });
        self.walk_raw_copy_prefix_at(&snapshot, workspace, &frontier, budget, visit)?;
        Ok(frontier)
    }

    pub(crate) fn walk_raw_copy_prefix_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        frontier: &NativeRawObservationFrontier,
        budget: &mut QueryBudget,
        mut visit: impl FnMut(
            NativeRawCopyReceipt,
            NativeRawCopyWitness,
            &mut QueryBudget,
        ) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        self.require_removal_authority()?;
        let head = self.removal_global_head(snapshot)?;
        let mut previous = genesis(&self.identity)?;
        if frontier.authority_id != self.authority_id()
            || frontier.sequence > head.sequence
            || (frontier.sequence == 0 && frontier.digest != previous.digest)
        {
            return Err(integrity(
                "raw observation frontier is outside retained history",
            ));
        }
        for sequence in 1..=head.sequence {
            let event = self.budgeted_removal_event(snapshot, sequence, budget)?;
            if event.previous != previous.digest {
                return Err(integrity(
                    "raw observation prefix or later journal is discontinuous",
                ));
            }
            if sequence == frontier.sequence && event.digest != frontier.digest {
                return Err(integrity("raw observation frontier commitment differs"));
            }
            if sequence <= frontier.sequence
                && let Operation::RawCopies { observation } = &event.operation
                && observation.workspace == workspace
            {
                let witness =
                    self.load_raw_copy_witness(snapshot, sequence, observation, budget)?;
                self.verify_raw_copy_predecessor(snapshot, &witness, sequence, budget)?;
                visit(
                    NativeRawCopyReceipt {
                        authority_id: self.authority_id(),
                        sequence,
                        digest: event.digest.clone(),
                    },
                    witness,
                    budget,
                )?;
            }
            previous = event.checkpoint();
        }
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
        if previous != head || !tail.entries.is_empty() || tail.continuation.is_some() {
            return Err(integrity("raw observation journal terminal differs"));
        }
        budget.check().map_err(budget_error)
    }
}
