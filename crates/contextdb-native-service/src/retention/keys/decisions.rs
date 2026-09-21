//! Shared decisions and historical replay for exclusively selected value keys.

use super::*;
use uuid::Uuid;

/// First unresolved task for an exclusively selected key. Every action still
/// requires separate archive, external-copy and physical-erasure evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeOwnedKeyAction {
    /// Resolve preparations involving this key; their data may already be durable.
    ResolvePreparedUse,
    /// Remove acknowledged values from the listed registered native instances.
    RemoveAcknowledgedCopies,
    /// No tracked current value remains. Assess historical and outside copies;
    /// unused or aborted allocations do not establish their absence.
    AssessRetainedCopies,
}

/// An exclusively selected allocation with exact versions and outstanding work.
/// This is evidence for deletion planning, never permission to disable a key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOwnedKeyDisposition {
    /// Immutable descriptor selected by retained ownership.
    pub allocation: NativeKeyAllocation,
    /// Exact versions, including aborted and unresolved after-values.
    pub versions: Vec<NativeKeyUseVersion>,
    /// Instances whose last acknowledged value still uses this key.
    pub acknowledged_instances: BTreeSet<Uuid>,
    /// Unresolved changes involving either a preimage or an after-value.
    pub unresolved_preparations: Vec<NativeKeyUseTransaction>,
    /// First unresolved native task; other obligations remain relevant.
    pub action: NativeOwnedKeyAction,
}

pub(super) fn dispositions<T: Ord + Clone + Serialize>(
    usage: &NativeKeyUseInventory,
    owners: &BTreeMap<T, Vec<NativeKeyAllocation>>,
    budget: &mut QueryBudget,
) -> ServiceResult<BTreeMap<T, Vec<NativeOwnedKeyDisposition>>> {
    let mut output = BTreeMap::new();
    for (owner, allocations) in owners {
        let mut selected = Vec::new();
        for allocation in allocations {
            let address = usage
                .addresses
                .get(&allocation.address_digest)
                .ok_or_else(|| integrity("owned key history is absent"))?;
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
                        return Err(integrity("owned ciphertext has contradictory versions"));
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
                NativeOwnedKeyAction::ResolvePreparedUse
            } else if !acknowledged.is_empty() {
                NativeOwnedKeyAction::RemoveAcknowledgedCopies
            } else {
                NativeOwnedKeyAction::AssessRetainedCopies
            };
            selected.push(NativeOwnedKeyDisposition {
                allocation: allocation.clone(),
                versions: versions.into_values().collect(),
                acknowledged_instances: acknowledged,
                unresolved_preparations: unresolved,
                action,
            });
        }
        output.insert(owner.clone(), selected);
    }
    charge_report(&output, budget)?;
    Ok(output)
}

pub(super) fn verify_allocations<T: Ord>(
    current: &BTreeMap<T, Vec<NativeKeyAllocation>>,
    retained: &BTreeMap<T, Vec<NativeKeyAllocation>>,
    revision: u64,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    if current.keys().ne(retained.keys()) {
        return Err(integrity("owned key allocation coverage differs"));
    }
    for (owner, allocations) in current {
        budget
            .charge(allocations.len() as u64, 0)
            .map_err(raw_index::budget_error)?;
        let prior: Vec<_> = allocations
            .iter()
            .filter(|entry| entry.allocation_sequence <= revision)
            .cloned()
            .collect();
        if prior != retained[owner] {
            return Err(integrity(
                "owned key allocations differ from retained history",
            ));
        }
    }
    Ok(())
}

pub(super) fn verify_use_prefix(
    current: &NativeKeyUseInventory,
    retained: &NativeKeyUseInventory,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    if current.authority_id != retained.authority_id
        || retained.revision > current.revision
        || current.addresses.keys().ne(retained.addresses.keys())
    {
        return Err(integrity("owned key use authority or frontier differs"));
    }
    for (key, address) in &current.addresses {
        let mut prior = NativeKeyUseAddressInventory {
            transitions: Vec::new(),
            acknowledged: BTreeMap::new(),
        };
        for change in &address.transitions {
            budget.charge(1, 0).map_err(raw_index::budget_error)?;
            if change.transaction.preparation.sequence > retained.revision {
                break;
            }
            let mut change = change.clone();
            if change
                .transaction
                .resolution
                .as_ref()
                .is_some_and(|outcome| outcome.sequence > retained.revision)
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
        if prior != retained.addresses[key] {
            return Err(integrity("owned key use differs from retained history"));
        }
    }
    Ok(())
}
