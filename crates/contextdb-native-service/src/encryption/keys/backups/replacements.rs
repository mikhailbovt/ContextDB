//! Accepted archive preservation proofs. Neither archive availability nor erasure
//! follows from this journal; the caller must retain the returned archive bytes.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_recall::QueryBudget;
use contextdb_service::{BackupResponse, ServiceResult};

use super::*;
use crate::{
    NativeRemovalRequestReceipt, backup::replacements::ReplacementProof, integrity,
    raw_index::budget_error, storage_error,
};

const EVENTS: &[u8] = b"backup/replacement/event/";
const MAX_EVENT_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests;

/// Accepted pruning publications between the original and replacement histories.
/// These are logical operations, not counts of erased bytes or physical copies.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupPruningCounts {
    /// Primary-source cleanup publications.
    pub sources: u64,
    /// Staged-payload cleanup publications, possibly partial.
    pub payloads: u64,
    /// Source-supported assertion cleanup publications.
    pub assertions: u64,
    /// Generic revision-body cleanup publications.
    pub records: u64,
}

impl NativeBackupPruningCounts {
    pub(crate) fn total(&self) -> Option<u64> {
        self.sources
            .checked_add(self.payloads)?
            .checked_add(self.assertions)?
            .checked_add(self.records)
    }
}

/// Immutable receipt in the custody authority, outside native backup/restore.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupReplacementReceipt {
    /// Exact authority retaining both archives' issuance and contents.
    pub authority_id: Uuid,
    /// Position in the independent replacement journal.
    pub sequence: u64,
    /// Commitment to the preservation proof and previous replacement event.
    pub digest: String,
}

impl NativeBackupReplacementReceipt {
    pub(super) fn validate(&self, keys: &NativeCustodyKeys) -> contextdb_storage::Result<()> {
        if keys.identity.version < 4
            || self.authority_id != keys.authority_id()
            || self.sequence == 0
        {
            return Err(failure("archive replacement authority or sequence differs"));
        }
        valid_digest(&self.digest)
    }
}

/// Verified preservation of an issued archive through request-bound native cleanup.
/// Other copies may remain. This never authorizes key retirement or completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupReplacement {
    /// Independently retained acceptance.
    pub receipt: NativeBackupReplacementReceipt,
    /// Hashed workspace whose removal request authorizes the pruning suffix.
    pub workspace_digest: String,
    /// Exact verified request; it remains an intent, not a completion receipt.
    pub request: NativeRemovalRequestReceipt,
    /// Original issuance and complete membership, including verified legacy backfill.
    pub source: NativeBackupContentsInventory,
    /// Replacement issuance and complete membership accepted with this proof.
    pub target: NativeBackupContentsInventory,
    /// Request-bound cleanup in the strictly extending native history.
    pub pruning: NativeBackupPruningCounts,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplacementEvent {
    pub(super) value: NativeBackupReplacement,
    previous: Option<String>,
}

impl ReplacementEvent {
    fn commitment(&self) -> ServiceResult<String> {
        let value = &self.value;
        crate::canonical_digest(&(
            "contextdb/native-backup-replacement/v1",
            value.receipt.authority_id,
            value.receipt.sequence,
            &self.previous,
            &value.workspace_digest,
            &value.request,
            &value.source,
            &value.target,
            &value.pruning,
        ))
    }

    fn index_key(&self) -> Vec<u8> {
        let value = &self.value;
        // All components have already passed canonical digest validation.
        format!(
            "backup/replacement/index/{}/{}/{}/{}",
            value.workspace_digest,
            value.request.digest,
            value.source.receipt.archive_digest,
            value.target.receipt.archive_digest,
        )
        .into_bytes()
    }

    pub(super) fn add_expected_keys(&self, expected: &mut BTreeSet<Vec<u8>>) {
        expected.insert(event_key(self.value.receipt.sequence));
        expected.insert(self.index_key());
    }
}

impl NativeCustodyKeys {
    /// Recover a retained preservation proof after native restore or lost response.
    /// Verifies the complete custody archive catalog under the supplied budget.
    pub fn backup_replacement(
        &self,
        receipt: &NativeBackupReplacementReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupReplacement> {
        self.read_backup_replacement(receipt, None, budget)
    }

    pub(crate) fn backup_replacement_for_request(
        &self,
        receipt: &NativeBackupReplacementReceipt,
        workspace_digest: &str,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupReplacement> {
        self.read_backup_replacement(receipt, Some((workspace_digest, request)), budget)
    }

    fn read_backup_replacement(
        &self,
        receipt: &NativeBackupReplacementReceipt,
        request: Option<(&str, &NativeRemovalRequestReceipt)>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupReplacement> {
        self.require_backup_contents()?;
        receipt.validate(self).map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let event: ReplacementEvent =
            self.read_replacement_record(&snapshot, &event_key(receipt.sequence), budget)?;
        if event.value.receipt != *receipt {
            return Err(integrity("archive replacement receipt differs"));
        }
        // Request binding precedes catalog verification, which now reads actual
        // artifact bytes. The full catalog still validates this proof before return.
        if request.is_some_and(|(workspace, request)| {
            event.value.workspace_digest != workspace || event.value.request != *request
        }) {
            return Err(integrity(
                "retained archive replacement belongs to another request",
            ));
        }
        self.selected_backup_keys_at(&snapshot, &BTreeMap::new(), budget)?;
        Ok(event.value)
    }

    // Only the native verifier constructs this proof, after exact-history and
    // request-bound preservation checks. Target issuance and provenance share Sync.
    pub(crate) fn accept_backup_replacement(
        &self,
        archive: &BackupResponse,
        logical_digest: &str,
        copies: impl Iterator<Item = ServiceResult<NativeBackupKeyCopy>>,
        proof: ReplacementProof,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupReplacement> {
        self.require_backup_contents()?;
        valid_digest(&archive.digest).map_err(storage_error)?;
        valid_digest(logical_digest).map_err(storage_error)?;
        let _guard = self.writes.enter(|| budget.check().map_err(budget_error))?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        // Check complete forward and reverse closure before staging anything.
        // Lost locators may not manufacture another accepted replacement.
        self.selected_backup_keys_at(&tx, &BTreeMap::new(), budget)?;
        self.require_replacement_contents(&tx, &proof.source, budget)?;
        let (target, changed) =
            self.stage_backup_contents(&mut tx, archive, logical_digest, copies, true, budget)?;
        let mut head = self.backup_head(&tx).map_err(storage_error)?;
        let mut event = ReplacementEvent {
            value: NativeBackupReplacement {
                receipt: NativeBackupReplacementReceipt {
                    authority_id: self.authority_id(),
                    sequence: 0,
                    digest: String::new(),
                },
                workspace_digest: proof.workspace_digest,
                request: proof.request,
                source: proof.source,
                target,
                pruning: proof.pruning,
            },
            previous: head
                .replacements
                .as_ref()
                .map(|receipt| receipt.digest.clone()),
        };
        let index = event.index_key();
        if let Some(bytes) = tx.get(&self.rows, &index).map_err(storage_error)? {
            let receipt: NativeBackupReplacementReceipt = self
                .open_backup_record(&index, &bytes)
                .map_err(storage_error)?;
            let existing: ReplacementEvent =
                self.read_replacement_record(&tx, &event_key(receipt.sequence), budget)?;
            event.value.receipt = existing.value.receipt.clone();
            event.previous = existing.previous.clone();
            if changed || event != existing {
                return Err(integrity(
                    "archive replacement retry changes accepted preservation",
                ));
            }
            budget.check().map_err(budget_error)?;
            return Ok(existing.value);
        }
        event.value.receipt.sequence = head
            .replacements
            .as_ref()
            .map_or(0, |value| value.sequence)
            .checked_add(1)
            .ok_or_else(|| crate::exhausted("replacement sequence exhausted"))?;
        event.value.receipt.digest = event.commitment()?;
        self.validate_replacement(&tx, &event, budget)?;
        let key = event_key(event.value.receipt.sequence);
        let encoded = encode(&event).map_err(storage_error)?;
        budget
            .charge(1, encoded.len() as u64)
            .map_err(budget_error)?;
        if encoded.len() > MAX_EVENT_BYTES {
            return Err(crate::exhausted("archive replacement proof exceeds 64 KiB"));
        }
        tx.put(
            &self.rows,
            key.clone(),
            self.seal_backup_record(&key, &event)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        tx.put(
            &self.rows,
            index.clone(),
            self.seal_backup_record(&index, &event.value.receipt)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        head.replacements = Some(event.value.receipt.clone());
        tx.put(
            &self.rows,
            HEAD.to_vec(),
            self.seal_backup_record(HEAD, &head)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        #[cfg(test)]
        BEFORE_REPLACEMENT_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        budget.check().map_err(budget_error)?;
        crate::require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(event.value)
    }

    fn require_replacement_contents<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        inventory: &NativeBackupContentsInventory,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let actual =
            self.find_contents(snapshot, &inventory.registration.archive_digest, budget)?;
        if actual.as_ref().map(|event| event.inventory()).as_ref() != Some(inventory) {
            return Err(integrity(
                "archive replacement lost its accepted complete contents",
            ));
        }
        Ok(())
    }

    fn validate_replacement<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &ReplacementEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let value = &event.value;
        value.receipt.validate(self).map_err(storage_error)?;
        valid_digest(&value.workspace_digest).map_err(storage_error)?;
        valid_digest(&value.request.digest).map_err(storage_error)?;
        let distance = value
            .target
            .registration
            .native_commit
            .checked_sub(value.source.registration.native_commit);
        if value.receipt.digest != event.commitment()?
            || value.request.sequence == 0
            || value.request.authority_id.is_nil()
            || !(1..=256).contains(&value.request.roots.len())
            || value.source.registration.archive_digest == value.target.registration.archive_digest
            || value
                .pruning
                .total()
                .is_none_or(|total| total == 0 || distance.is_none_or(|distance| total > distance))
        {
            return Err(integrity(
                "archive replacement preservation proof is invalid",
            ));
        }
        self.require_replacement_contents(snapshot, &value.source, budget)?;
        self.require_replacement_contents(snapshot, &value.target, budget)
    }

    pub(super) fn walk_backup_replacements<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        head: &Head,
        budget: &mut QueryBudget,
        mut visit: impl FnMut(&ReplacementEvent, &mut QueryBudget) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        let mut previous = None;
        let end = head
            .replacements
            .as_ref()
            .map_or(0, |receipt| receipt.sequence);
        let mut seen = BTreeSet::new();
        for sequence in 1..=end {
            let event: ReplacementEvent =
                self.read_replacement_record(snapshot, &event_key(sequence), budget)?;
            self.validate_replacement(snapshot, &event, budget)?;
            let receipt = &event.value.receipt;
            if receipt.sequence != sequence
                || event.previous != previous
                || !seen.insert(event.index_key())
            {
                return Err(integrity("archive replacement chain differs"));
            }
            let indexed: NativeBackupReplacementReceipt =
                self.read_replacement_record(snapshot, &event.index_key(), budget)?;
            if indexed != *receipt
                || (sequence == end && head.replacements.as_ref() != Some(receipt))
            {
                return Err(integrity("archive replacement index or terminal differs"));
            }
            previous = Some(receipt.digest.clone());
            visit(&event, budget)?;
        }
        let tail = snapshot
            .scan_prefix_page(
                &self.rows,
                ScanPageRequest {
                    prefix: EVENTS,
                    start_after: Some(&event_key(end)),
                    max_entries: 1,
                    max_bytes: MAX_EVENT_BYTES + 128,
                },
            )
            .map_err(storage_error)?;
        for row in &tail.entries {
            budget
                .charge(1, (row.key.len() + row.value.len()) as u64)
                .map_err(budget_error)?;
        }
        if !tail.entries.is_empty() || tail.continuation.is_some() {
            return Err(integrity(
                "archive replacement exceeds its accepted terminal",
            ));
        }
        budget.check().map_err(budget_error)
    }

    fn read_replacement_record<S: ReadSnapshot, T: serde::de::DeserializeOwned>(
        &self,
        snapshot: &S,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<T> {
        budget.check().map_err(budget_error)?;
        let bytes = snapshot
            .get(&self.rows, key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("archive replacement record is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_EVENT_BYTES + 64 {
            return Err(integrity("archive replacement record exceeds its bound"));
        }
        self.open_backup_record(key, &bytes).map_err(storage_error)
    }

    pub(super) fn verify_backup_replacements<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        head: &Head,
        expected: &mut BTreeSet<Vec<u8>>,
    ) -> contextdb_storage::Result<()> {
        let mut budget = QueryBudget::new(
            u64::MAX,
            u64::MAX,
            std::time::Duration::from_secs(300),
            Default::default(),
        );
        self.walk_backup_replacements(snapshot, head, &mut budget, |event, _| {
            event.add_expected_keys(expected);
            Ok(())
        })
        .map_err(|_| failure("archive replacement verification failed"))
    }
}

fn event_key(sequence: u64) -> Vec<u8> {
    format!("backup/replacement/event/{sequence:020}").into_bytes()
}

#[cfg(test)]
type PublicationHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    pub(crate) static BEFORE_REPLACEMENT_SYNC: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
}
