//! Bounded host inspection of native-use preparations and their retained outcomes.

use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};

use super::*;
use crate::{integrity, invalid, raw_index::budget_error, storage_error};

const MAX_CURSOR_BYTES: usize = 2048;
const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;

#[cfg(test)]
mod tests;

/// Exact independent acceptance of a native-use preparation or outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseReceipt {
    /// Current independently retained custody authority.
    pub authority_id: Uuid,
    /// Native-use journal position, independent of allocation/native sequences.
    pub sequence: u64,
    /// Exact accepted journal commitment.
    pub digest: String,
}

/// A preparation alone does not prove either native acceptance or non-use.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeKeyUseOutcome {
    /// Outcome remains unacknowledged; data may already be durably committed.
    Prepared,
    /// Its native marker and data were synchronized and independently acknowledged.
    Committed,
    /// Recovery synchronized the unchanged base before recording non-publication.
    Aborted,
}

/// One transaction's exact version-transition declaration and current outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseTransaction {
    /// Exact preparation acceptance; use it to read the immutable change pages.
    pub preparation: NativeKeyUseReceipt,
    /// Independently registered native instance. Logical restore uses a new instance.
    pub native_instance: Uuid,
    /// Unique preparation identity, including attempts that did not publish.
    pub transaction_id: Uuid,
    /// Physical native sequence at the inspected base.
    pub base_native_sequence: u64,
    /// Intended next sequence. Only a Committed outcome confirms its acceptance.
    pub intended_native_sequence: u64,
    /// Number of address-transition pages, each containing at most 256 rows.
    pub pages: u32,
    /// Final distinct changed addresses, including absent-to-absent staged deletions.
    pub changed_addresses: u64,
    /// Retained outcome at this read's independent journal snapshot.
    pub outcome: NativeKeyUseOutcome,
    /// Exact outcome acceptance, absent only for the still-pending preparation.
    pub resolution: Option<NativeKeyUseReceipt>,
}

/// A frontier-bound scan page. Empty transaction pages can still continue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseCatalogPage {
    /// Authority supplying this complete scan.
    pub authority_id: Uuid,
    /// Mandatory native-use journal frontier examined.
    pub revision: u64,
    /// Frontier commitment, absent only at genesis.
    pub revision_digest: Option<String>,
    /// Preparations encountered in at most max_events journal entries.
    pub transactions: Vec<NativeKeyUseTransaction>,
    /// Authenticated continuation. Native-use journal growth requires restarting.
    pub continuation: Option<Vec<u8>>,
}

/// One authenticated transition page. Complete historical coverage additionally
/// requires finishing the catalog and every declared page, including pending uses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyUseChangesPage {
    /// Exact preparation and its outcome at this read's snapshot.
    pub transaction: NativeKeyUseTransaction,
    /// Zero-based page within the preparation.
    pub page: u32,
    /// Up to 256 final address transitions. Aborted after-values are not native use.
    pub changes: Vec<NativeKeyUseChange>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    frontier: UseCheckpoint,
    through: UseCheckpoint,
}

impl NativeCustodyKeys {
    /// Scan 1..64 mandatory journal events, at most 8 MiB, under one work budget.
    /// All events advance the authenticated chain even when no preparation is
    /// returned. Allocation or backup-only changes do not invalidate this cursor.
    /// No keys or payloads are returned and no deletion permission is conferred.
    pub fn native_use_catalog_page(
        &self,
        continuation: Option<&[u8]>,
        max_events: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeKeyUseCatalogPage> {
        self.require_use_catalog()?;
        if !(1..=64).contains(&max_events)
            || continuation.is_some_and(|bytes| bytes.len() > MAX_CURSOR_BYTES)
        {
            return Err(invalid(
                "native-use catalog requires 1..64 events and a bounded cursor",
            ));
        }
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let frontier = self.budgeted_use_head(&snapshot, budget)?;
        let mut through = if let Some(token) = continuation {
            budget.charge(1, token.len() as u64).map_err(budget_error)?;
            let bytes = self
                .open_use(b"cursor", token, "catalog")
                .map_err(|_| invalid("native-use cursor does not authenticate"))?;
            let cursor: Cursor = decode(&bytes).map_err(storage_error)?;
            if cursor.frontier != frontier {
                return Err(stale());
            }
            validate_checkpoint(&cursor.through, true).map_err(storage_error)?;
            if cursor.through.sequence > frontier.sequence {
                return Err(invalid("native-use cursor is outside its frontier"));
            }
            if cursor.through.sequence != 0
                && self
                    .budgeted_use_event(&snapshot, cursor.through.sequence, budget)?
                    .checkpoint
                    != cursor.through
            {
                return Err(integrity("native-use cursor prefix differs"));
            }
            cursor.through
        } else {
            UseCheckpoint::default()
        };
        let mut transactions = Vec::new();
        let mut scanned = 0_usize;
        for _ in 0..max_events {
            if through.sequence == frontier.sequence {
                break;
            }
            let event = self.budgeted_use_event(&snapshot, through.sequence + 1, budget)?;
            let bytes = encode(&event).map_err(storage_error)?.len();
            if scanned + bytes > MAX_SCAN_BYTES {
                break;
            }
            scanned += bytes;
            if event.previous_digest != through.digest {
                return Err(integrity("native-use catalog journal is discontinuous"));
            }
            if let UseOperation::Prepare { preparation } = &event.change {
                transactions.push(self.use_transaction(
                    &snapshot,
                    &frontier,
                    &PendingUse {
                        preparation: preparation.clone(),
                        checkpoint: event.checkpoint.clone(),
                    },
                    budget,
                )?);
            }
            through = event.checkpoint;
        }
        if through.sequence == frontier.sequence && through != frontier {
            return Err(integrity("native-use catalog terminal differs"));
        }
        let continuation = if through == frontier {
            None
        } else {
            let token = self
                .seal_use(
                    b"cursor",
                    &encode(&Cursor {
                        frontier: frontier.clone(),
                        through,
                    })
                    .map_err(storage_error)?,
                    "catalog",
                )
                .map_err(storage_error)?;
            if token.len() > MAX_CURSOR_BYTES {
                return Err(crate::exhausted(
                    "native-use catalog cursor exceeds its bound",
                ));
            }
            Some(token)
        };
        let page = NativeKeyUseCatalogPage {
            authority_id: self.authority_id(),
            revision: frontier.sequence,
            revision_digest: frontier.digest.clone(),
            transactions,
            continuation,
        };
        crate::retention::keys::charge_report(&page, budget)?;
        self.require_use_frontier(&frontier, budget)?;
        Ok(page)
    }

    /// Read one exact 256-row transition page, including after native pruning or
    /// older restore. The declared range and adjacent journal links remain required.
    /// One page is not proof of complete transaction or historical copy coverage.
    pub fn native_use_changes_page(
        &self,
        receipt: &NativeKeyUseReceipt,
        page: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeKeyUseChangesPage> {
        self.require_use_catalog()?;
        budget.check().map_err(budget_error)?;
        if receipt.authority_id != self.authority_id() || receipt.sequence == 0 {
            return Err(invalid("native-use receipt belongs to another authority"));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let frontier = self.budgeted_use_head(&snapshot, budget)?;
        if receipt.sequence > frontier.sequence {
            return Err(integrity(
                "native-use receipt is beyond the retained frontier",
            ));
        }
        let event = self.budgeted_use_event(&snapshot, receipt.sequence, budget)?;
        if event.checkpoint.digest.as_ref() != Some(&receipt.digest) {
            return Err(integrity("native-use receipt commitment differs"));
        }
        let UseOperation::Prepare { preparation } = event.change else {
            return Err(invalid("native-use receipt is not a preparation"));
        };
        let pending = PendingUse {
            preparation,
            checkpoint: event.checkpoint,
        };
        let transaction = self.use_transaction(&snapshot, &frontier, &pending, budget)?;
        if page >= transaction.pages {
            return Err(invalid("native-use change page is outside its declaration"));
        }
        let sequence = receipt
            .sequence
            .checked_sub(u64::from(transaction.pages))
            .and_then(|start| start.checked_add(u64::from(page)))
            .ok_or_else(|| integrity("native-use change page range overflows"))?;
        let event = self.budgeted_use_event(&snapshot, sequence, budget)?;
        let next = self.budgeted_use_event(&snapshot, sequence + 1, budget)?;
        if next.previous_digest != event.checkpoint.digest {
            return Err(integrity(
                "native-use change page lost its successor commitment",
            ));
        }
        if sequence > 1
            && event.previous_digest
                != self
                    .budgeted_use_event(&snapshot, sequence - 1, budget)?
                    .checkpoint
                    .digest
        {
            return Err(integrity(
                "native-use change page lost its predecessor commitment",
            ));
        }
        let UseOperation::Page {
            transaction: id,
            index,
            changes,
        } = event.change
        else {
            return Err(integrity("native-use change page is absent"));
        };
        let expected = (transaction.changed_addresses - u64::from(page) * CHANGES_PER_PAGE as u64)
            .min(CHANGES_PER_PAGE as u64);
        if id != transaction.transaction_id || index != page || changes.len() as u64 != expected {
            return Err(integrity(
                "native-use change page identity or length differs",
            ));
        }
        let mut last = None;
        for change in &changes {
            budget
                .charge(1, encode(change).map_err(storage_error)?.len() as u64)
                .map_err(budget_error)?;
            if last.is_some_and(|last: &String| last >= &change.address_digest) {
                return Err(integrity("native-use change page addresses repeat"));
            }
            let key_bytes = self
                .validate_use_keys(&snapshot, change)
                .map_err(storage_error)?;
            budget
                .charge(
                    u64::from(change.before.is_some()) + u64::from(change.after.is_some()),
                    key_bytes,
                )
                .map_err(budget_error)?;
            last = Some(&change.address_digest);
        }
        let result = NativeKeyUseChangesPage {
            transaction,
            page,
            changes,
        };
        crate::retention::keys::charge_report(&result, budget)?;
        self.require_use_frontier(&frontier, budget)?;
        Ok(result)
    }

    fn use_transaction<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        frontier: &UseCheckpoint,
        pending: &PendingUse,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeKeyUseTransaction> {
        let preparation = &pending.preparation;
        if preparation.transaction.is_nil()
            || preparation.previous.native_sequence == 0
            || preparation.previous.instance.is_nil()
            || preparation.changes > MAX_CHANGES as u64
            || u64::from(preparation.pages) != preparation.changes.div_ceil(CHANGES_PER_PAGE as u64)
            || u64::from(preparation.pages) >= pending.checkpoint.sequence
        {
            return Err(integrity(
                "native-use preparation range or identity differs",
            ));
        }
        let key = outcome_key(pending.checkpoint.sequence);
        let bytes = snapshot.get(&self.rows, &key).map_err(storage_error)?;
        budget
            .charge(1, bytes.as_ref().map_or(0, |bytes| bytes.len()) as u64)
            .map_err(budget_error)?;
        let (outcome, resolution) = if let Some(bytes) = bytes {
            let receipt: UseCheckpoint = decode(
                &self
                    .open_use(&key, &bytes, "journal")
                    .map_err(storage_error)?,
            )
            .map_err(storage_error)?;
            if receipt.sequence <= pending.checkpoint.sequence
                || receipt.sequence > frontier.sequence
            {
                return Err(integrity("native-use outcome is outside retained history"));
            }
            let event = self.budgeted_use_event(snapshot, receipt.sequence, budget)?;
            let UseOperation::Complete {
                prepared,
                instance,
                committed,
            } = event.change
            else {
                return Err(integrity("native-use outcome operation differs"));
            };
            if event.checkpoint != receipt
                || prepared != pending.checkpoint
                || instance != preparation.previous.instance
            {
                return Err(integrity("native-use outcome binding differs"));
            }
            (
                if committed {
                    NativeKeyUseOutcome::Committed
                } else {
                    NativeKeyUseOutcome::Aborted
                },
                Some(self.use_receipt(&receipt)?),
            )
        } else {
            let state = self
                .use_state(snapshot, preparation.previous.instance)
                .map_err(storage_error)?;
            budget
                .charge(4, encode(&state).map_err(storage_error)?.len() as u64)
                .map_err(budget_error)?;
            if state.pending.as_ref() != Some(pending) {
                return Err(integrity(
                    "native-use outcome is missing rather than pending",
                ));
            }
            (NativeKeyUseOutcome::Prepared, None)
        };
        Ok(NativeKeyUseTransaction {
            preparation: self.use_receipt(&pending.checkpoint)?,
            native_instance: preparation.previous.instance,
            transaction_id: preparation.transaction,
            base_native_sequence: preparation.previous.native_sequence,
            intended_native_sequence: pending.expected().map_err(storage_error)?.native_sequence,
            pages: preparation.pages,
            changed_addresses: preparation.changes,
            outcome,
            resolution,
        })
    }

    fn use_receipt(&self, checkpoint: &UseCheckpoint) -> ServiceResult<NativeKeyUseReceipt> {
        validate_checkpoint(checkpoint, false).map_err(storage_error)?;
        Ok(NativeKeyUseReceipt {
            authority_id: self.authority_id(),
            sequence: checkpoint.sequence,
            digest: checkpoint
                .digest
                .clone()
                .ok_or_else(|| integrity("native-use receipt digest absent"))?,
        })
    }

    fn budgeted_use_event<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        sequence: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<UseEvent> {
        budget.check().map_err(budget_error)?;
        let event = self.use_event(snapshot, sequence).map_err(storage_error)?;
        budget
            .charge(1, encode(&event).map_err(storage_error)?.len() as u64)
            .map_err(budget_error)?;
        Ok(event)
    }

    fn budgeted_use_head<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<UseCheckpoint> {
        budget.check().map_err(budget_error)?;
        let head = self.use_head(snapshot).map_err(storage_error)?;
        budget
            .charge(3, encode(&head).map_err(storage_error)?.len() as u64)
            .map_err(budget_error)?;
        if head.sequence != 0 {
            self.budgeted_use_event(snapshot, head.sequence, budget)?;
        }
        Ok(head)
    }

    fn require_use_frontier(
        &self,
        frontier: &UseCheckpoint,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self.budgeted_use_head(&snapshot, budget)? != *frontier {
            return Err(stale());
        }
        Ok(())
    }

    fn require_use_catalog(&self) -> ServiceResult<()> {
        if !self.tracks_native_use() {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "native-use history requires explicit custody version 4 migration",
                false,
            ));
        }
        Ok(())
    }
}

fn stale() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "native-use journal changed; restart enumeration",
        true,
    )
}
