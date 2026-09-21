//! Monotonic current refusal, independent of native snapshots and archives.

use std::{collections::BTreeSet, sync::RwLockReadGuard, time::Duration};

use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::ScanPageRequest;

use super::*;
use crate::{
    NativeRemovalKeySelection, NativeRemovalRequestReceipt, integrity, invalid,
    raw_index::budget_error, storage_error,
};

const PREFIX: &[u8] = b"key-retirement/";
const MAX_EVENT_BYTES: usize = 128 * 1024;
pub(crate) const MAX_RETIREMENT_KEYS: usize = 256;

#[cfg(test)]
mod tests;

/// Immutable acceptance of current key refusal; this does not certify destruction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyRetirementReceipt {
    /// Independent custody authority, unaffected by native restore.
    pub authority_id: Uuid,
    /// Position in the monotonic retirement journal.
    pub sequence: u64,
    /// Commitment to the complete acceptance and its predecessor.
    pub digest: String,
}

impl NativeKeyRetirementReceipt {
    pub(super) fn validate(&self, keys: &NativeCustodyKeys) -> contextdb_storage::Result<()> {
        if !keys.tracks_native_use()
            || self.authority_id != keys.authority_id()
            || self.sequence == 0
            || blake3::Hash::from_hex(&self.digest).is_err()
        {
            return Err(failure("key retirement receipt is invalid"));
        }
        Ok(())
    }
}

/// Verified ownership/use/archive snapshot from which current refusal was accepted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyRetirementEvidence {
    /// Complete allocation journal position.
    pub allocation_revision: u64,
    /// Allocation commitment at that position.
    pub allocation_digest: Option<String>,
    /// Complete tracked native-use position, including preparations and outcomes.
    pub use_revision: u64,
    /// Native-use commitment at that position.
    pub use_digest: Option<String>,
    /// Verified complete archive histories, including preservation and byte progress.
    pub backups: NativeBackupFrontier,
    /// Commitment to the exact service-derived ownership and preservation report.
    pub report_digest: String,
}

/// Independently retained refusal of exclusively owned ciphertext-version keys.
/// Wrapped descriptors remain for verification; physical erasure is separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyRetirement {
    /// Durable current refusal, recoverable after a lost acknowledgement.
    pub receipt: NativeKeyRetirementReceipt,
    /// Hashed authenticated workspace.
    pub workspace_digest: String,
    /// Exact independently retained removal request.
    pub request: NativeRemovalRequestReceipt,
    /// Ownership selection verified by the service before acceptance.
    pub selection: NativeRemovalKeySelection,
    /// At most 256 exact immutable allocations, sorted by UUID.
    pub keys: Vec<NativeKeyAllocation>,
    /// Verified frontiers and report commitment; not an all-copy completion receipt.
    pub evidence: NativeKeyRetirementEvidence,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    value: NativeKeyRetirement,
    previous: Option<NativeKeyRetirementReceipt>,
}

impl Event {
    fn intent(&self) -> contextdb_storage::Result<String> {
        intent(
            &self.value.workspace_digest,
            &self.value.request,
            &self.value.selection,
            &self.value.keys.iter().map(|key| key.key_id).collect(),
        )
    }

    fn commitment(&self) -> contextdb_storage::Result<String> {
        let value = &self.value;
        Ok(crate::digest_bytes(&encode(&(
            "contextdb/native-key-retirement/v1",
            value.receipt.authority_id,
            value.receipt.sequence,
            &self.previous,
            &value.workspace_digest,
            &value.request,
            &value.selection,
            &value.keys,
            &value.evidence,
        ))?))
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RetiredKey {
    address: String,
    receipt: NativeKeyRetirementReceipt,
}

#[derive(Default, Eq, PartialEq)]
pub(super) struct RetirementState {
    frontier: Option<NativeKeyRetirementReceipt>,
    keys: BTreeMap<Uuid, RetiredKey>,
    uncertain: bool,
}

impl RetirementState {
    pub(super) fn frontier(&self) -> Option<NativeKeyRetirementReceipt> {
        self.frontier.clone()
    }

    pub(super) fn contains(&self, id: Uuid) -> bool {
        self.keys.contains_key(&id)
    }
}

impl NativeCustodyKeys {
    /// Read an immutable current-refusal acceptance from retained host custody.
    /// The full retirement journal remains verified; no key material is returned.
    pub fn key_retirement(
        &self,
        receipt: &NativeKeyRetirementReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeKeyRetirement> {
        receipt.validate(self).map_err(storage_error)?;
        self.retirement_frontier().map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.load_retirements(&snapshot, budget)?;
        let event: Event =
            self.read_retirement_row(&snapshot, &event_key(receipt.sequence), budget)?;
        if event.value.receipt != *receipt {
            return Err(integrity("key retirement receipt differs"));
        }
        Ok(event.value)
    }

    // Only the service's current ownership/use/preservation verifier constructs
    // this acceptance. Caller-provided serialized reports never enter this path.
    pub(crate) fn accept_key_retirement(
        &self,
        mut value: NativeKeyRetirement,
        usage: &NativeKeyUseInventory,
        targets: &BTreeSet<String>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeKeyRetirement> {
        if value.evidence.use_revision != usage.revision
            || value.evidence.use_digest != usage.revision_digest
        {
            return Err(integrity("key retirement use evidence differs"));
        }
        let _guard = self.lock_inventory_frontier(
            value.evidence.allocation_revision,
            value.evidence.allocation_digest.as_deref(),
            usage,
            budget,
        )?;
        self.require_backup_frontier(&value.evidence.backups, budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let mut next = self.load_retirements(&tx, budget)?;
        {
            let current = self
                .retirement
                .read()
                .map_err(|_| integrity("key retirement state is poisoned"))?;
            if *current != next {
                return Err(integrity(
                    "key retirement state differs from retained history; reopen custody",
                ));
            }
        }
        let selected: BTreeSet<_> = value.keys.iter().map(|key| key.key_id).collect();
        let locator = index_key(
            &intent(
                &value.workspace_digest,
                &value.request,
                &value.selection,
                &selected,
            )
            .map_err(storage_error)?,
        );
        if tx
            .get(&self.rows, &locator)
            .map_err(storage_error)?
            .is_some()
        {
            let receipt: NativeKeyRetirementReceipt =
                self.read_retirement_row(&tx, &locator, budget)?;
            let event: Event =
                self.read_retirement_row(&tx, &event_key(receipt.sequence), budget)?;
            return Ok(event.value);
        }
        if selected.iter().any(|key| next.keys.contains_key(key)) {
            return Err(invalid(
                "selection includes a key already retired by another acceptance",
            ));
        }
        self.require_backup_available_keys(&tx, targets, &selected, budget)?;
        value.receipt = NativeKeyRetirementReceipt {
            authority_id: self.authority_id(),
            sequence: next
                .frontier
                .as_ref()
                .map_or(0, |receipt| receipt.sequence)
                .checked_add(1)
                .ok_or_else(|| crate::exhausted("key retirement sequence exhausted"))?,
            digest: String::new(),
        };
        let mut event = Event {
            value,
            previous: next.frontier.clone(),
        };
        event.value.receipt.digest = event.commitment().map_err(storage_error)?;
        self.validate_retirement(&tx, &event, budget)?;
        let encoded = encode(&event).map_err(storage_error)?;
        budget
            .charge(1, encoded.len() as u64)
            .map_err(budget_error)?;
        if encoded.len() > MAX_EVENT_BYTES {
            return Err(crate::exhausted(
                "key retirement acceptance exceeds 128 KiB",
            ));
        }
        let row = event_key(event.value.receipt.sequence);
        for (key, bytes) in [
            (row, encoded),
            (
                locator,
                encode(&event.value.receipt).map_err(storage_error)?,
            ),
        ] {
            let sealed = seal(
                &self.master.0,
                &self.retirement_aad(&key).map_err(storage_error)?,
                &bytes,
            )
            .map_err(storage_error)?;
            tx.put(&self.rows, key, sealed).map_err(storage_error)?;
        }
        let mut head = self.key_version_head(&tx).map_err(storage_error)?;
        if head.retirements != next.frontier {
            return Err(integrity("key retirement anchor changed"));
        }
        head.retirements = Some(event.value.receipt.clone());
        tx.put(
            &self.rows,
            versions::HEAD.to_vec(),
            self.seal_key_log(versions::HEAD, &encode(&head).map_err(storage_error)?)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        for key in &event.value.keys {
            next.keys.insert(
                key.key_id,
                RetiredKey {
                    address: key.address_digest.clone(),
                    receipt: event.value.receipt.clone(),
                },
            );
        }
        next.frontier = Some(event.value.receipt.clone());
        let mut current = self
            .retirement
            .write()
            .map_err(|_| integrity("key retirement state is poisoned"))?;
        #[cfg(test)]
        BEFORE_RETIREMENT_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        budget.check().map_err(budget_error)?;
        // Any ambiguous Sync leaves all key use closed. Reopen verifies the actual
        // durable terminal before reconstructing a usable current state.
        current.uncertain = true;
        crate::require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        #[cfg(test)]
        AFTER_RETIREMENT_DURABLE.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        *current = next;
        drop(current);
        #[cfg(test)]
        AFTER_RETIREMENT_SYNC.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        Ok(event.value)
    }

    pub(in crate::encryption) fn retirement_frontier(
        &self,
    ) -> contextdb_storage::Result<Option<NativeKeyRetirementReceipt>> {
        Ok(self.current_retirements()?.frontier())
    }

    pub(super) fn current_retirements(
        &self,
    ) -> contextdb_storage::Result<RwLockReadGuard<'_, RetirementState>> {
        let state = self
            .retirement
            .read()
            .map_err(|_| failure("key retirement state is poisoned"))?;
        if state.uncertain {
            return Err(failure(
                "key retirement outcome is uncertain; reopen custody",
            ));
        }
        Ok(state)
    }

    pub(in crate::encryption) fn require_retirement_frontier(
        &self,
        expected: Option<&NativeKeyRetirementReceipt>,
    ) -> contextdb_storage::Result<()> {
        if self.retirement_frontier()?.as_ref() != expected {
            return Err(failure(
                "key retirement changed during native transaction; retry",
            ));
        }
        Ok(())
    }

    // Held through decryption. Publication takes the same lock exclusively after
    // the custody writer queue, so an in-flight read linearizes before retirement.
    pub(super) fn admit_key(
        &self,
        id: Uuid,
    ) -> contextdb_storage::Result<RwLockReadGuard<'_, RetirementState>> {
        let state = self.current_retirements()?;
        if state.contains(id) {
            return Err(failure("ciphertext key is retired"));
        }
        Ok(state)
    }

    pub(super) fn verify_key_retirements<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> contextdb_storage::Result<RetirementState> {
        let mut budget = QueryBudget::new(
            u64::MAX,
            u64::MAX,
            Duration::from_secs(300),
            Default::default(),
        );
        self.load_retirements(snapshot, &mut budget)
            .map_err(|_| failure("key retirement journal verification failed"))
    }

    fn load_retirements<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RetirementState> {
        let head = if self.tracks_native_use() {
            self.key_version_head(snapshot)
                .map_err(storage_error)?
                .retirements
        } else {
            None
        };
        let mut state = RetirementState::default();
        let mut expected = BTreeSet::new();
        for sequence in 1..=head.as_ref().map_or(0, |receipt| receipt.sequence) {
            let row = event_key(sequence);
            let event: Event = self.read_retirement_row(snapshot, &row, budget)?;
            self.validate_retirement(snapshot, &event, budget)?;
            if event.value.receipt.sequence != sequence || event.previous != state.frontier {
                return Err(integrity("key retirement journal is discontinuous"));
            }
            let locator = index_key(&event.intent().map_err(storage_error)?);
            let indexed: NativeKeyRetirementReceipt =
                self.read_retirement_row(snapshot, &locator, budget)?;
            if indexed != event.value.receipt || !expected.insert(locator) {
                return Err(integrity(
                    "key retirement intent locator differs or repeats",
                ));
            }
            expected.insert(row);
            for key in &event.value.keys {
                if state
                    .keys
                    .insert(
                        key.key_id,
                        RetiredKey {
                            address: key.address_digest.clone(),
                            receipt: event.value.receipt.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(integrity("key was retired more than once"));
                }
            }
            state.frontier = Some(event.value.receipt);
        }
        if state.frontier != head {
            return Err(integrity("key retirement terminal differs"));
        }
        let mut after = None;
        loop {
            budget.check().map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.rows,
                    ScanPageRequest {
                        prefix: PREFIX,
                        start_after: after.as_deref(),
                        max_entries: 256,
                        max_bytes: 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                budget
                    .charge(1, (row.key.len() + row.value.len()) as u64)
                    .map_err(budget_error)?;
                if !expected.remove(&row.key) {
                    return Err(integrity("key retirement journal has undeclared rows"));
                }
            }
            let Some(next) = page.continuation else { break };
            after = Some(next);
        }
        if !expected.is_empty() {
            return Err(integrity("key retirement journal lost accepted rows"));
        }
        Ok(state)
    }

    fn validate_retirement<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &Event,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let value = &event.value;
        value.receipt.validate(self).map_err(storage_error)?;
        if let Some(retired) = &value.evidence.backups.retirements {
            retired.validate(self).map_err(storage_error)?;
            if event.previous.as_ref() != Some(retired) {
                return Err(integrity(
                    "key retirement evidence has a different predecessor",
                ));
            }
        }
        for digest in [
            &value.workspace_digest,
            &value.request.digest,
            &value.evidence.report_digest,
        ] {
            blake3::Hash::from_hex(digest)
                .map_err(|_| integrity("key retirement commitment is invalid"))?;
        }
        if value.receipt.digest != event.commitment().map_err(storage_error)?
            || value.request.authority_id.is_nil()
            || value.request.sequence == 0
            || !(1..=256).contains(&value.request.roots.len())
            || !(1..=MAX_RETIREMENT_KEYS).contains(&value.keys.len())
            || value
                .keys
                .windows(2)
                .any(|pair| pair[0].key_id >= pair[1].key_id)
            || value.evidence.backups.authority_id != self.authority_id()
        {
            return Err(integrity("key retirement acceptance is invalid"));
        }
        self.verify_retirement_allocations(
            snapshot,
            &value.keys,
            value.evidence.allocation_revision,
            budget,
        )?;
        self.verify_inventory_checkpoints(
            value.evidence.allocation_revision,
            value.evidence.allocation_digest.as_deref(),
            &NativeKeyUseInventory {
                authority_id: self.authority_id(),
                revision: value.evidence.use_revision,
                revision_digest: value.evidence.use_digest.clone(),
                addresses: BTreeMap::new(),
            },
            budget,
        )?;
        Ok(())
    }

    fn read_retirement_row<S: ReadSnapshot, T: serde::de::DeserializeOwned>(
        &self,
        snapshot: &S,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<T> {
        budget.check().map_err(budget_error)?;
        let bytes = snapshot
            .get(&self.rows, key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("accepted key retirement row is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > MAX_EVENT_BYTES + NONCE_BYTES + TAG_BYTES {
            return Err(integrity("key retirement row exceeds its bound"));
        }
        let plaintext = open(
            &self.master.0,
            &self.retirement_aad(key).map_err(storage_error)?,
            &bytes,
        )
        .map_err(storage_error)?;
        decode(&plaintext).map_err(storage_error)
    }

    fn retirement_aad(&self, key: &[u8]) -> contextdb_storage::Result<Vec<u8>> {
        encode(&(
            "contextdb/native-key-retirement-record/v1",
            &self.identity,
            key,
        ))
    }
}

fn intent(
    workspace: &str,
    request: &NativeRemovalRequestReceipt,
    selection: &NativeRemovalKeySelection,
    keys: &BTreeSet<Uuid>,
) -> contextdb_storage::Result<String> {
    Ok(crate::digest_bytes(&encode(&(
        "contextdb/native-key-retirement-intent/v1",
        workspace,
        request,
        selection,
        keys,
    ))?))
}

fn event_key(sequence: u64) -> Vec<u8> {
    format!("key-retirement/event/{sequence:020}").into_bytes()
}
fn index_key(intent: &str) -> Vec<u8> {
    format!("key-retirement/intent/{intent}").into_bytes()
}

#[cfg(test)]
type PublicationHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    pub(crate) static BEFORE_RETIREMENT_SYNC: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
    pub(crate) static AFTER_RETIREMENT_DURABLE: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
    pub(crate) static AFTER_RETIREMENT_SYNC: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
}
