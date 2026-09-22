//! Preserve each native instance before refusing shared assertion-value keys.

use super::*;
use crate::{
    NativeKeyAllocation, NativeKeyRetirement, NativeKeyRetirementClassification,
    NativeKeyRetirementEvidence, NativeKeyRetirementReceipt, NativeKeyUseOutcome,
    NativeKeyUseVersion, NativeRemovalKeySelection,
};
use uuid::Uuid;

#[cfg(test)]
mod tests;

impl NativeService {
    pub(crate) fn retire_assertion_keys(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        witness: &NativeAssertionRemovalWitnessReceipt,
        selected: &BTreeSet<Uuid>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeKeyRetirement> {
        let report = self.read_assertion_backup_inventory(context, request, witness, budget)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("removal authority absent"))?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("key custody absent"))?;
        let (owner, _) = ledger.read_assertion_removal_witness(witness, budget)?;
        let values = report
            .key_inventory
            .value_ownership
            .as_ref()
            .ok_or_else(|| integrity("assertion classifications absent"))?;
        let usage = report
            .key_inventory
            .native_use
            .as_ref()
            .ok_or_else(|| integrity("assertion native-use history absent"))?;

        // A different accepted removal can legitimately eliminate an originally
        // independent mutation. Verify its exact retained ownership/selection;
        // matching commit numbers or an absent live ordinal confer no permission.
        let mut authorized = BTreeSet::new();
        let mut authorizations = BTreeMap::new();
        for receipt in &values.witnesses {
            let classified = ledger.read_assertion_value_witness(receipt, budget)?;
            classified.verify(keys)?;
            let authority = &classified.body.owner;
            let (retained, ordinals) = ledger.read_assertion_removal_witness(authority, budget)?;
            if retained != owner {
                return Err(integrity(
                    "shared retirement authorization has different ownership",
                ));
            }
            if let Some(previous) =
                authorizations.insert(authority.witness_sequence, authority.clone())
                && previous != *authority
            {
                return Err(integrity(
                    "shared retirement authorization repeats with different fields",
                ));
            }
            authorized.extend(ordinals);
        }
        let (allocations, native) =
            preserve_native(&report, selected, &owner, &authorized, budget)?;
        let targets = crate::backup::preservation::retained_targets(
            &report.backups,
            &report.preservation,
            budget,
        )?;
        let proof = (&report, &authorizations, &native);
        crate::retention::keys::charge_report(&proof, budget)?;
        let value = NativeKeyRetirement {
            receipt: NativeKeyRetirementReceipt {
                authority_id: usage.authority_id,
                sequence: 0,
                digest: String::new(),
            },
            workspace_digest: digest_bytes(context.request.workspace_id.as_bytes()),
            request: request.clone(),
            selection: NativeRemovalKeySelection::Assertions {
                witness: witness.clone(),
            },
            keys: allocations,
            evidence: NativeKeyRetirementEvidence {
                allocation_revision: report.key_inventory.allocation_revision,
                allocation_digest: report.key_inventory.allocation_digest.clone(),
                use_revision: usage.revision,
                use_digest: usage.revision_digest.clone(),
                backups: report.backups.frontier.clone(),
                report_digest: digest_bytes(&encode(&proof)?),
                classification: Some(NativeKeyRetirementClassification {
                    authority_id: values.authority_id,
                    sequence: values.revision,
                    digest: values.revision_digest.clone(),
                }),
            },
        };
        let preserved = native.values().map(|version| version.key_id).collect();
        #[cfg(test)]
        BEFORE_SHARED_RETIREMENT_FENCE.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        keys.accept_key_retirement(value, usage, &targets, &preserved, Some(ledger), budget)
    }
}

fn preserve_native(
    report: &NativeAssertionBackupInventory,
    selected: &BTreeSet<Uuid>,
    owner: &AssertionRemovalWitness,
    authorized: &BTreeSet<usize>,
    budget: &mut QueryBudget,
) -> ServiceResult<(
    Vec<NativeKeyAllocation>,
    BTreeMap<Uuid, NativeKeyUseVersion>,
)> {
    let inventory = &report.key_inventory;
    let values = inventory
        .value_ownership
        .as_ref()
        .ok_or_else(|| integrity("classification absent"))?;
    let usage = inventory
        .native_use
        .as_ref()
        .ok_or_else(|| integrity("native use absent"))?;
    let all = inventory.batches.values().flatten().chain(
        inventory
            .mutations
            .values()
            .flat_map(|families| families.values().flatten()),
    );
    let mut allocations = BTreeMap::new();
    for allocation in all {
        budget.charge(1, 0).map_err(budget_error)?;
        if selected.contains(&allocation.key_id) {
            allocations.insert(allocation.key_id, allocation.clone());
        }
    }
    if allocations.keys().ne(selected.iter()) {
        return Err(invalid(
            "shared retirement contains keys outside retained ownership",
        ));
    }
    let mut instances = BTreeMap::<Uuid, BTreeSet<usize>>::new();
    for allocation in allocations.values() {
        let versions = values
            .addresses
            .get(&allocation.address_digest)
            .ok_or_else(|| integrity("shared retirement value history absent"))?;
        let mut known = false;
        let mut needed = BTreeSet::new();
        for value in versions {
            budget.charge(1, 0).map_err(budget_error)?;
            if value.version.key_id != allocation.key_id {
                continue;
            }
            let NativeAssertionValueDisposition::RequiresRemoval {
                independent_mutations,
                ..
            } = &value.disposition
            else {
                return Err(invalid(
                    "shared retirement key is unclassified, independent or control-only",
                ));
            };
            known = true;
            needed.extend(independent_mutations.difference(authorized).copied());
        }
        if !known {
            return Err(invalid("shared retirement key has no classified value"));
        }
        let history = usage
            .addresses
            .get(&allocation.address_digest)
            .ok_or_else(|| integrity("shared retirement native history absent"))?;
        budget
            .charge(history.acknowledged.len() as u64, 0)
            .map_err(budget_error)?;
        if history
            .acknowledged
            .values()
            .any(|version| version.key_id == allocation.key_id)
        {
            return Err(invalid(
                "shared retirement key still has acknowledged native copies",
            ));
        }
        for change in &history.transitions {
            budget.charge(1, 0).map_err(budget_error)?;
            if !change
                .before
                .iter()
                .chain(change.after.iter())
                .any(|v| v.key_id == allocation.key_id)
            {
                continue;
            }
            match change.transaction.outcome {
                NativeKeyUseOutcome::Prepared => {
                    return Err(invalid("shared retirement key has unresolved native use"));
                }
                NativeKeyUseOutcome::Committed => {
                    instances
                        .entry(change.transaction.native_instance)
                        .or_default()
                        .extend(&needed);
                }
                NativeKeyUseOutcome::Aborted => {}
            }
        }
    }
    let batches: BTreeSet<_> = inventory
        .batches
        .values()
        .flatten()
        .map(|key| &key.address_digest)
        .collect();
    let mut preservation = BTreeMap::new();
    for (instance, mut needed) in instances {
        // Host policy mutations are never removable source assertions, including
        // when the retiring value itself is only a source body or label.
        needed.extend(
            owner
                .mutations
                .iter()
                .enumerate()
                .filter_map(|(i, m)| m.is_none().then_some(i)),
        );
        let mut kept = None;
        for address in &batches {
            let history = usage
                .addresses
                .get(*address)
                .ok_or_else(|| integrity("batch use history absent"))?;
            for change in &history.transitions {
                budget.charge(1, 0).map_err(budget_error)?;
                if change.transaction.native_instance == instance
                    && change.transaction.outcome == NativeKeyUseOutcome::Prepared
                {
                    return Err(invalid(
                        "native preservation has an unresolved batch publication",
                    ));
                }
            }
            let Some(current) = history.acknowledged.get(&instance) else {
                continue;
            };
            if selected.contains(&current.key_id) {
                continue;
            }
            let mut disposition = None;
            for value in values.addresses.get(*address).into_iter().flatten() {
                budget.charge(1, 0).map_err(budget_error)?;
                if value.version == *current {
                    disposition = Some(&value.disposition);
                    break;
                }
            }
            let complete = match disposition {
                Some(NativeAssertionValueDisposition::PreserveIndependent { mutations }) => {
                    needed.is_subset(mutations)
                }
                Some(NativeAssertionValueDisposition::PreserveControl) => needed.is_empty(),
                _ => false,
            };
            if complete {
                kept = Some(current.clone());
            }
        }
        preservation.insert(
            instance,
            kept.ok_or_else(|| {
                invalid("native instance lacks classified independent/control preservation")
            })?,
        );
    }
    Ok((allocations.into_values().collect(), preservation))
}

#[cfg(test)]
thread_local! {
    static BEFORE_SHARED_RETIREMENT_FENCE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
