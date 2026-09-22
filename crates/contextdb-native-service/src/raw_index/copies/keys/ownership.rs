//! Reconstruct exact observed ownership independently of allocated-key claims.

use super::*;
use crate::{NativeKeyUseAddressInventory, NativeKeyUseInventory};

impl RawKeyFamilies {
    pub(crate) fn verify_owned_inventory<'a>(
        &self,
        reported: &'a BTreeMap<ObservationId, BTreeMap<String, NativeRawKeyFamily>>,
        usage: &NativeKeyUseInventory,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<String, &'a Vec<NativeKeyAllocation>>> {
        if self.sources.keys().ne(reported.keys())
            || reported.values().map(BTreeMap::len).sum::<usize>() != self.addresses.len()
        {
            return Err(integrity(
                "raw key witness source or address coverage differs",
            ));
        }
        let mut groups = BTreeMap::new();
        for (address, owner) in &self.addresses {
            budget
                .charge(1, address.len() as u64)
                .map_err(budget_error)?;
            let family = reported
                .get(&owner.0)
                .and_then(|rows| rows.get(address))
                .ok_or_else(|| integrity("raw key witness source/address family absent"))?;
            let empty = BTreeMap::new();
            let observed = self.observed.get(owner).unwrap_or(&empty);
            let expected: Vec<_> = observed
                .values()
                .map(|(version, _)| version.clone())
                .collect();
            budget
                .charge(expected.len() as u64, 0)
                .map_err(budget_error)?;
            if family.observed_versions != expected {
                return Err(integrity(
                    "raw key witness observations differ from retained pages",
                ));
            }
            let history = usage
                .addresses
                .get(address)
                .ok_or_else(|| integrity("raw key witness use address absent"))?;
            verify_observations(observed, usage.authority_id, history, budget)?;
            groups.insert(address.clone(), &family.allocations);
        }
        Ok(groups)
    }
}

pub(super) fn verify_observations(
    versions: &ObservedVersions,
    authority: Uuid,
    history: &NativeKeyUseAddressInventory,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    let mut committed = BTreeSet::new();
    for change in &history.transitions {
        budget.charge(1, 0).map_err(budget_error)?;
        if change.transaction.outcome == crate::NativeKeyUseOutcome::Committed
            && let Some(after) = &change.after
        {
            committed.insert((
                after.key_id,
                after.ciphertext_digest.as_str(),
                after.value_digest.as_str(),
            ));
        }
    }
    for (version, value_digest) in versions.values() {
        budget.charge(1, 0).map_err(budget_error)?;
        if version.authority_id == authority
            && !committed.contains(&(
                version.key_id,
                version.ciphertext_digest.as_str(),
                value_digest.as_str(),
            ))
        {
            return Err(integrity(
                "observed raw ciphertext differs from committed native use",
            ));
        }
    }
    Ok(())
}
