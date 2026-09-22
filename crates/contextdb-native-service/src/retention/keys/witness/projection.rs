use super::*;

pub(super) fn dispositions(
    inventory: &NativePrimaryKeyInventory,
    budget: &mut QueryBudget,
) -> ServiceResult<BTreeMap<ObservationId, Vec<NativePrimaryKeyDisposition>>> {
    decisions::dispositions(tracked(inventory)?, &inventory.sources, budget)
}

pub(super) fn verify_prefix(
    current: &NativePrimaryKeyInventory,
    retained: &NativePrimaryKeyInventory,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    let usage = tracked(retained)?;
    let current_use = tracked(current)?;
    if current.database_id != retained.database_id
        || current.workspace_id != retained.workspace_id
        || current.request != retained.request
        || current.custody_authority_id != retained.custody_authority_id
        || current_use.authority_id != usage.authority_id
        || usage.authority_id != retained.custody_authority_id
        || retained.allocation_revision > current.allocation_revision
        || usage.revision > current_use.revision
        || current.sources.keys().ne(retained.sources.keys())
        || current_use.addresses.keys().ne(usage.addresses.keys())
    {
        return Err(integrity("primary witness ownership or frontier differs"));
    }
    decisions::verify_allocations(
        &current.sources,
        &retained.sources,
        retained.allocation_revision,
        budget,
    )?;
    decisions::verify_use_prefix(current_use, usage, budget)
}
