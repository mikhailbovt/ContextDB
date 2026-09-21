//! Retain decisions against explicit, reproducible raw-copy coverage.

use super::*;

#[cfg(test)]
mod tests;

impl NativeService {
    /// Retain decisions for the selected GC-observation prefix. Obtain the frontier
    /// from `read_reclaimed_raw_key_inventory`; later journal appends do not change
    /// this target or its exact retry. Current generations and unobserved copies
    /// remain outside the prefix. Admin and the exact removal request are required.
    pub fn retain_reclaimed_raw_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        frontier: &NativeRawObservationFrontier,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let inventory = self.owned_reclaimed_raw_inventory(context, request, frontier, budget)?;
        self.retain_owned_key_inventory(inventory, budget)
    }

    /// Recover exact earlier decisions for the same GC-observation prefix. Both
    /// custody histories and the complete retained observation prefix are verified.
    /// Later observations and old restores cannot rewrite the saved version tasks.
    pub fn read_reclaimed_raw_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        frontier: &NativeRawObservationFrontier,
        receipt: &NativeOwnedKeyRemovalReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let current = self.owned_reclaimed_raw_inventory(context, request, frontier, budget)?;
        self.read_owned_key_inventory(current, receipt, budget)
    }

    /// Retain source-owned key decisions for a complete native inspection. Its
    /// terminal receipt binds every page, shared/unknown row and reclaimed prefix;
    /// those obligations and foreign key authorities do not become absence.
    pub fn retain_raw_index_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        inspection: &NativeRawIndexInventoryReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let inventory = self.owned_inspected_raw_inventory(context, request, inspection, budget)?;
        self.retain_owned_key_inventory(inventory, budget)
    }

    /// Read exact historical decisions for the supplied complete inspection with
    /// current Admin/request authorization. This does not retire or destroy keys.
    pub fn read_raw_index_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        inspection: &NativeRawIndexInventoryReceipt,
        receipt: &NativeOwnedKeyRemovalReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let current = self.owned_inspected_raw_inventory(context, request, inspection, budget)?;
        self.read_owned_key_inventory(current, receipt, budget)
    }

    pub(in crate::retention::keys) fn owned_reclaimed_raw_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        frontier: &NativeRawObservationFrontier,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyInventory> {
        let report = self.read_reclaimed_raw_keys_at(context, request, Some(frontier), budget)?;
        Ok(NativeOwnedKeyInventory {
            database_id: report.database_id,
            workspace_id: report.workspace_id,
            request: report.request,
            custody_authority_id: report.custody_authority_id,
            allocation_revision: report.allocation_revision,
            allocation_digest: report.allocation_digest,
            native_use: require_tracked(report.native_use)?,
            owner: NativeOwnedKeyOwner::ReclaimedRaw {
                frontier: frontier.clone(),
                sources: report.sources,
                witnesses: report.witnesses,
            },
        })
    }

    pub(in crate::retention::keys) fn owned_inspected_raw_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        inspection: &NativeRawIndexInventoryReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyInventory> {
        let report = self.read_raw_index_key_inventory(context, request, inspection, budget)?;
        Ok(NativeOwnedKeyInventory {
            database_id: report.database_id,
            workspace_id: report.workspace_id,
            request: report.request,
            custody_authority_id: report.custody_authority_id,
            allocation_revision: report.allocation_revision,
            allocation_digest: report.allocation_digest,
            native_use: require_tracked(report.native_use)?,
            owner: NativeOwnedKeyOwner::InspectedRaw {
                snapshot: report.snapshot,
                inventory: report.inventory,
                inspected_pages: report.inspected_pages,
                sources: report.sources,
            },
        })
    }
}
