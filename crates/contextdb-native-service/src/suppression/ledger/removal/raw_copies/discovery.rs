//! Walk an exact retained prefix without trusting optional lookup rows.

use super::*;
use crate::raw_index::copies::discovery::{RawCopyScan, RawCopyScanPage};

const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

#[cfg(test)]
mod tests;

impl NativeSuppressionLedger {
    pub(crate) fn scan_raw_copy_witnesses(
        &self,
        workspace: &str,
        cursor: Option<&RawCopyScan>,
        max_events: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RawCopyScanPage> {
        self.require_removal_authority()?;
        if !(1..=64).contains(&max_events) {
            return Err(invalid("raw copy discovery requires 1..64 journal events"));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let frontier = self.removal_global_head(&snapshot)?;
        let tail = snapshot
            .scan_prefix_page(
                &self.rows,
                ScanPageRequest {
                    prefix: b"removal/event/",
                    start_after: Some(&event_key(frontier.sequence)),
                    max_entries: 1,
                    max_bytes: 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        for entry in &tail.entries {
            budget
                .charge(1, (entry.key.len() + entry.value.len()) as u64)
                .map_err(budget_error)?;
        }
        if !tail.entries.is_empty() {
            return Err(integrity(
                "raw copy frontier is behind its accepted journal",
            ));
        }
        let mut through = if let Some(cursor) = cursor {
            if cursor.frontier != frontier {
                return Err(discovery_stale());
            }
            if cursor.through.sequence > frontier.sequence {
                return Err(integrity("raw copy cursor exceeds its retained frontier"));
            }
            let expected = if cursor.through.sequence == 0 {
                genesis(&self.identity)?
            } else {
                self.budgeted_removal_event(&snapshot, cursor.through.sequence, budget)?
                    .checkpoint()
            };
            if expected != cursor.through {
                return Err(integrity("raw copy cursor lost its accepted prefix"));
            }
            cursor.through.clone()
        } else {
            genesis(&self.identity)?
        };
        let mut witnesses = Vec::new();
        let mut bytes = 0;
        let mut examined = 0;
        for sequence in through.sequence.saturating_add(1)..=frontier.sequence {
            if examined == max_events {
                break;
            }
            let event = self.budgeted_removal_event(&snapshot, sequence, budget)?;
            if event.previous != through.digest {
                return Err(integrity("raw copy discovery journal is discontinuous"));
            }
            if let Operation::RawCopies { observation } = &event.operation
                && observation.workspace == workspace
            {
                let witness =
                    self.load_raw_copy_witness(&snapshot, sequence, observation, budget)?;
                self.verify_raw_copy_predecessor(&snapshot, &witness, sequence, budget)?;
                let length = encode(&witness)?.len();
                if !witnesses.is_empty() && bytes + length > MAX_PAGE_BYTES {
                    break;
                }
                bytes += length;
                witnesses.push((
                    NativeRawCopyReceipt {
                        authority_id: self.authority_id(),
                        sequence,
                        digest: event.digest.clone(),
                    },
                    witness,
                ));
            }
            through = event.checkpoint();
            examined += 1;
        }
        if through.sequence == frontier.sequence && through != frontier {
            return Err(integrity("raw copy discovery terminal differs"));
        }
        self.require_raw_copy_frontier(&frontier, budget)?;
        Ok(RawCopyScanPage {
            state: RawCopyScan { frontier, through },
            examined,
            witnesses,
        })
    }

    pub(crate) fn require_raw_copy_frontier(
        &self,
        expected: &RemovalCheckpoint,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let current = self.removal_global_head(&snapshot)?;
        budget
            .charge(1, encode(&current)?.len() as u64)
            .map_err(budget_error)?;
        if &current != expected {
            return Err(discovery_stale());
        }
        Ok(())
    }
}

fn discovery_stale() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "retained raw copy journal changed; restart discovery",
        true,
    )
}
