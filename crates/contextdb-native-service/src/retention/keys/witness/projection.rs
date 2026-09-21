use super::*;

pub(super) fn dispositions(
    inventory: &NativePrimaryKeyInventory,
    budget: &mut QueryBudget,
) -> ServiceResult<BTreeMap<ObservationId, Vec<NativePrimaryKeyDisposition>>> {
    let usage = tracked(inventory)?;
    let mut output = BTreeMap::new();
    for (source, allocations) in &inventory.sources {
        let mut selected = Vec::new();
        for allocation in allocations {
            let address = usage
                .addresses
                .get(&allocation.address_digest)
                .ok_or_else(|| integrity("primary key history is absent"))?;
            let mut versions = BTreeMap::new();
            let mut unresolved = Vec::new();
            for change in &address.transitions {
                budget.charge(1, 0).map_err(raw_index::budget_error)?;
                let mut involved = false;
                for version in change
                    .before
                    .iter()
                    .chain(change.after.iter())
                    .filter(|version| version.key_id == allocation.key_id)
                {
                    involved = true;
                    if versions
                        .insert(version.ciphertext_digest.clone(), version.clone())
                        .is_some_and(|previous| previous != *version)
                    {
                        return Err(integrity("primary ciphertext has contradictory versions"));
                    }
                }
                if involved && change.transaction.outcome == NativeKeyUseOutcome::Prepared {
                    unresolved.push(change.transaction.clone());
                }
            }
            let acknowledged: BTreeSet<_> = address
                .acknowledged
                .iter()
                .filter(|(_, version)| version.key_id == allocation.key_id)
                .map(|(instance, _)| *instance)
                .collect();
            let action = if !unresolved.is_empty() {
                NativePrimaryKeyAction::ResolvePreparedUse
            } else if !acknowledged.is_empty() {
                NativePrimaryKeyAction::RemoveAcknowledgedCopies
            } else {
                NativePrimaryKeyAction::AssessRetainedCopies
            };
            selected.push(NativePrimaryKeyDisposition {
                allocation: allocation.clone(),
                versions: versions.into_values().collect(),
                acknowledged_instances: acknowledged,
                unresolved_preparations: unresolved,
                action,
            });
        }
        output.insert(*source, selected);
    }
    charge_report(&output, budget)?;
    Ok(output)
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
    for (source, allocations) in &current.sources {
        let prior: Vec<_> = allocations
            .iter()
            .filter(|entry| entry.allocation_sequence <= retained.allocation_revision)
            .cloned()
            .collect();
        budget
            .charge(allocations.len() as u64, 0)
            .map_err(raw_index::budget_error)?;
        if prior != retained.sources[source] {
            return Err(integrity(
                "primary witness allocations differ from retained history",
            ));
        }
    }
    for (key, address) in &current_use.addresses {
        let mut prior = NativeKeyUseAddressInventory {
            transitions: Vec::new(),
            acknowledged: BTreeMap::new(),
        };
        for change in &address.transitions {
            budget.charge(1, 0).map_err(raw_index::budget_error)?;
            if change.transaction.preparation.sequence > usage.revision {
                break;
            }
            let mut change = change.clone();
            if change
                .transaction
                .resolution
                .as_ref()
                .is_some_and(|outcome| outcome.sequence > usage.revision)
            {
                change.transaction.resolution = None;
                change.transaction.outcome = NativeKeyUseOutcome::Prepared;
            }
            if change.transaction.outcome == NativeKeyUseOutcome::Committed {
                let instance = change.transaction.native_instance;
                if let Some(after) = &change.after {
                    prior.acknowledged.insert(instance, after.clone());
                } else {
                    prior.acknowledged.remove(&instance);
                }
            }
            prior.transitions.push(change);
        }
        if prior != usage.addresses[key] {
            return Err(integrity(
                "primary witness use differs from retained history",
            ));
        }
    }
    Ok(())
}
