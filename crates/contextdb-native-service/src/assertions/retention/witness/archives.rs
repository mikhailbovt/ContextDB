//! Archive obligations keep mixed values separate from exclusively owned keys.

use super::*;
use crate::{NativeBackupKeyInventory, retention::keys::charge_report};

#[cfg(test)]
pub(super) mod tests;

/// Complete selected assertion-key coverage across all issued native archives.
/// Content classifications, native uses and archive observations remain distinct;
/// this neither retires keys nor acknowledges deletion or preservation completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssertionBackupInventory {
    /// Exact independently retained request authorizing this inspection.
    pub request: NativeRemovalRequestReceipt,
    /// Selected allocation/use history and authenticated native/archive values.
    /// Mixed, independently needed, control-only and unknown values stay distinct.
    pub key_inventory: NativeAssertionKeyInventory,
    /// Every issued archive, including unknown legacy membership and zero matches.
    /// Presence here is archive evidence, never a fabricated native-use transition.
    pub backups: NativeBackupKeyInventory,
    /// Proven replacement paths for each issued archive, relative to the selected
    /// mutations. Independent and control-only values need no replacement here.
    pub preservation: BTreeMap<u64, crate::NativeBackupPreservation>,
}

impl NativeService {
    /// Join selected assertion batches and mutation keys to every issued archive.
    /// Admin, exact retained request, witness and current scope/policy precede any
    /// catalog read. Shared values retain their authenticated content composition;
    /// an old archived version need not have a tracked native-use observation.
    ///
    /// One shared budget bounds all scans and the complete 32 MiB result. Custody
    /// frontiers are fenced together, then the independent classification frontier
    /// is rechecked while custody remains held. Future retirement must revalidate
    /// both authorities; this read-only report never confers retirement authority.
    pub fn read_assertion_backup_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        witness: &NativeAssertionRemovalWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeAssertionBackupInventory> {
        self.read_original_removal_inventory(context, request, budget)?;
        if witness.authority_id != request.authority_id
            || witness.removal_sequence != request.sequence
        {
            return Err(invalid(
                "assertion archive witness belongs to another removal request",
            ));
        }
        let (mut inventory, owner, selected) =
            self.assertion_key_inventory(context, witness, budget)?;
        let usage = inventory.native_use.as_ref().ok_or_else(|| {
            crate::unsupported("assertion archive inspection requires tracked v4 custody")
        })?;
        let mut allocations = BTreeMap::new();
        for allocation in inventory.batches.values().flatten().chain(
            inventory
                .mutations
                .values()
                .flat_map(|families| families.values().flatten()),
        ) {
            budget.charge(1, 80).map_err(budget_error)?;
            if !usage.addresses.contains_key(&allocation.address_digest)
                || allocations
                    .insert(allocation.key_id, allocation.address_digest.clone())
                    .is_some()
            {
                return Err(integrity(
                    "assertion archive selection has ambiguous allocations",
                ));
            }
        }
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("assertion archive custody absent"))?;
        let (backups, replacements) = keys.selected_backup_keys_for_request(
            &allocations,
            &digest_bytes(context.request.workspace_id.as_bytes()),
            request,
            budget,
        )?;
        self.verify_backup_replacement_requests(context, request, &replacements, budget)?;
        inventory.value_ownership =
            self.assertion_value_inventory(&owner, &selected, &inventory, Some(&backups), budget)?;
        let values = inventory
            .value_ownership
            .as_ref()
            .ok_or_else(|| integrity("assertion archive classifications absent"))?;
        let mut classifications = BTreeMap::new();
        for (address, versions) in &values.addresses {
            for version in versions {
                budget.charge(1, 0).map_err(budget_error)?;
                classifications.insert(
                    (
                        address,
                        &version.version.ciphertext_digest,
                        version.version.key_id,
                    ),
                    &version.disposition,
                );
            }
        }
        let preservation = crate::backup::preservation::inventory(
            &backups,
            &replacements,
            |copy| {
                use crate::backup::preservation::CopyDisposition;
                Ok(
                    match classifications.get(&(
                        &copy.address_digest,
                        &copy.version.ciphertext_digest,
                        copy.version.key_id,
                    )) {
                        Some(NativeAssertionValueDisposition::RequiresRemoval { .. }) => {
                            CopyDisposition::Remove
                        }
                        Some(
                            NativeAssertionValueDisposition::PreserveIndependent { .. }
                            | NativeAssertionValueDisposition::PreserveControl,
                        ) => CopyDisposition::Retain,
                        _ => CopyDisposition::Unknown,
                    },
                )
            },
            budget,
        )?;
        #[cfg(test)]
        BEFORE_ARCHIVE_FENCE.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = keys.lock_inventory_frontier(
            inventory.allocation_revision,
            inventory.allocation_digest.as_deref(),
            usage,
            budget,
        )?;
        keys.require_backup_frontier(&backups.frontier, budget)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("assertion archive authority absent"))?;
        ledger.require_removal_frontier(
            &RemovalCheckpoint {
                sequence: values.revision,
                digest: values.revision_digest.clone(),
            },
            budget,
        )?;
        let report = NativeAssertionBackupInventory {
            request: request.clone(),
            key_inventory: inventory,
            backups,
            preservation,
        };
        charge_report(&report, budget)?;
        Ok(report)
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_ARCHIVE_FENCE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
