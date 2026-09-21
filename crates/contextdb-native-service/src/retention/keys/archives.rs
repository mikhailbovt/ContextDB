//! Current archive obligations joined to request-owned value-key decisions.

use super::*;
use crate::{
    NativeBackupKeyInventory, NativeRawIndexInventoryReceipt, NativeRawObservationFrontier,
    NativeRecordRemovalWitnessReceipt,
};
use contextdb_core::ContentBlockId;

#[cfg(test)]
mod tests;

/// Explicit scope of a request-owned archive inspection. Shared assertion
/// versions require their separate composition/preservation contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeRemovalKeySelection {
    /// Primary values of all retained sources in this removal request.
    Originals,
    /// All chunks of an exclusively selected payload.
    Payload {
        /// Exact independently retained block identity.
        block_id: ContentBlockId,
    },
    /// Primary, birth and closure bodies of a selected generic revision.
    Record {
        /// Exact independently retained ownership, including stored access labels.
        witness: NativeRecordRemovalWitnessReceipt,
    },
    /// Source-owned raw rows in an explicit retained GC prefix.
    ReclaimedRaw {
        /// Fixed observation coverage; later/unobserved rows remain separate.
        frontier: NativeRawObservationFrontier,
    },
    /// Source-owned raw rows in one complete retained native inspection.
    InspectedRaw {
        /// Terminal receipt; all declared pages must remain verifiable.
        inventory: NativeRawIndexInventoryReceipt,
    },
}

/// Exact independently verified ownership and current allocation/use histories.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeRemovalKeyInventory {
    /// Complete primary-source selection, including empty allocation lists.
    Originals(NativePrimaryKeyInventory),
    /// Exact payload, revision or observed raw-address selection.
    Owned(NativeOwnedKeyInventory),
}

/// Administrative evidence for the selected removal scope. This does not disable
/// keys, replace archives, establish physical erasure or authorize completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRemovalBackupInventory {
    /// Exact request, owner, scope and verified custody frontiers.
    pub key_inventory: NativeRemovalKeyInventory,
    /// Current native tasks for each selected address and immutable key.
    pub dispositions: BTreeMap<String, Vec<NativeOwnedKeyDisposition>>,
    /// Every issued archive, including unknown membership and zero matches.
    /// Archive copies are separate observations, not invented native transitions.
    pub backups: NativeBackupKeyInventory,
}

impl NativeService {
    /// Join all issued archives to one request-owned key family. Current Admin,
    /// workspace and owner policy checks precede any archive inspection. All
    /// allocation/use and archive histories are verified under one work budget;
    /// partial or stale coverage returns an error, never a partial report.
    ///
    /// One custody publication guard checks allocation, native-use, issuance and
    /// membership and replacement frontiers together before returning. Subsequent publication
    /// must acquire that guard and revalidate those frontiers again. The report
    /// covers at most 65,536 selected allocations and 32 MiB of output.
    pub fn read_removal_backup_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        selection: &NativeRemovalKeySelection,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRemovalBackupInventory> {
        let inventory = match selection {
            NativeRemovalKeySelection::Originals => NativeRemovalKeyInventory::Originals(
                self.read_original_key_inventory(context, request, budget)?,
            ),
            NativeRemovalKeySelection::Payload { block_id } => NativeRemovalKeyInventory::Owned(
                self.owned_payload_inventory(context, request, *block_id, budget)?,
            ),
            NativeRemovalKeySelection::Record { witness } => NativeRemovalKeyInventory::Owned(
                self.owned_record_inventory(context, request, witness, budget)?,
            ),
            NativeRemovalKeySelection::ReclaimedRaw { frontier } => {
                NativeRemovalKeyInventory::Owned(
                    self.owned_reclaimed_raw_inventory(context, request, frontier, budget)?,
                )
            }
            NativeRemovalKeySelection::InspectedRaw { inventory } => {
                NativeRemovalKeyInventory::Owned(
                    self.owned_inspected_raw_inventory(context, request, inventory, budget)?,
                )
            }
        };
        let (revision, digest, usage, addresses) = match &inventory {
            NativeRemovalKeyInventory::Originals(primary) => {
                let mut addresses: BTreeMap<_, Vec<_>> = witness::tracked(primary)?
                    .addresses
                    .keys()
                    .map(|key| (key.clone(), Vec::new()))
                    .collect();
                for allocation in primary.sources.values().flatten() {
                    addresses
                        .get_mut(&allocation.address_digest)
                        .ok_or_else(|| integrity("primary allocation has no use address"))?
                        .push(allocation.clone());
                }
                (
                    primary.allocation_revision,
                    primary.allocation_digest.as_deref(),
                    witness::tracked(primary)?,
                    addresses,
                )
            }
            NativeRemovalKeyInventory::Owned(owned) => (
                owned.allocation_revision,
                owned.allocation_digest.as_deref(),
                &owned.native_use,
                owned.addresses()?,
            ),
        };
        let dispositions = decisions::dispositions(usage, &addresses, budget)?;
        let mut selected = BTreeMap::new();
        for allocation in addresses.values().flatten() {
            budget.charge(1, 80).map_err(raw_index::budget_error)?;
            if selected
                .insert(allocation.key_id, allocation.address_digest.clone())
                .is_some()
            {
                return Err(integrity("archive key selection repeats an allocation"));
            }
        }
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| unsupported("archive key inventory requires independent custody"))?;
        let backups = keys.selected_backup_keys(&selected, budget)?;
        #[cfg(test)]
        BEFORE_ARCHIVE_FENCE.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = keys.lock_inventory_frontier(revision, digest, usage, budget)?;
        keys.require_backup_frontier(&backups.frontier, budget)?;
        let report = NativeRemovalBackupInventory {
            key_inventory: inventory,
            dispositions,
            backups,
        };
        charge_report(&report, budget)?;
        Ok(report)
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_ARCHIVE_FENCE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
