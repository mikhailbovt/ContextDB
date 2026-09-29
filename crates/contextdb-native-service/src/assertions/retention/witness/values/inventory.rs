//! Join authenticated value composition to exact tracked ciphertext versions.

use super::*;
use crate::NativeKeyUseVersion;

/// What one exact assertion value contains relative to this removal request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeAssertionValueDisposition {
    /// Selected data remains. Preserve any independent contents before retiring
    /// this value/key, including copies in older archives and other instances.
    RequiresRemoval {
        /// Live mutation bodies/envelopes supported by selected originals.
        selected_mutations: BTreeSet<usize>,
        /// Independently needed live mutations, including host policies.
        independent_mutations: BTreeSet<usize>,
    },
    /// Only independently needed live mutations remain alongside replay controls.
    PreserveIndependent {
        /// Exact live mutation ordinals retained by this version.
        mutations: BTreeSet<usize>,
    },
    /// The classified value contains replay controls without live bodies/envelopes.
    PreserveControl,
    /// No authenticated composition matches this exact value. Never absence,
    /// independence or permission to retire the enclosing key.
    Unclassified,
}

/// One exact known ciphertext with its request-relative content classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssertionVersionOwnership {
    /// Exact native or archived version. This does not establish native acceptance;
    /// consult native-use and archive inventories for their distinct observations.
    pub version: NativeKeyUseVersion,
    /// Authenticated composition or explicit missing evidence.
    pub disposition: NativeAssertionValueDisposition,
}

/// Classification history at one complete independent removal-journal snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssertionValueInventory {
    /// Suppression authority retaining the classification witnesses.
    pub authority_id: uuid::Uuid,
    /// Complete removal-journal frontier examined.
    pub revision: u64,
    /// Commitment at that frontier.
    pub revision_digest: String,
    /// Exact verified acceptances used to recover the value compositions.
    pub witnesses: Vec<NativeAssertionValueWitnessReceipt>,
    /// Selected addresses, including addresses with no declared native values.
    pub addresses: BTreeMap<String, Vec<NativeAssertionVersionOwnership>>,
}

impl NativeService {
    pub(in crate::assertions::retention::witness) fn assertion_value_inventory(
        &self,
        owner: &AssertionRemovalWitness,
        selected: &BTreeSet<usize>,
        report: &NativeAssertionKeyInventory,
        archives: Option<&crate::NativeBackupKeyInventory>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<NativeAssertionValueInventory>> {
        let Some(usage) = &report.native_use else {
            return Ok(None);
        };
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("assertion value authority absent"))?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("assertion value custody absent"))?;
        let (frontier, witnesses) =
            ledger.assertion_value_history(owner.workspace(), owner.assertion_commit(), budget)?;
        let owner_digest = canonical_digest(owner)?;
        let mut classifications = BTreeMap::new();
        let mut receipts = Vec::new();
        for (receipt, witness) in witnesses {
            // Different original branches or custody authorities can share local
            // commit numbers. Their evidence cannot classify this exact batch.
            if witness.body.ownership_digest != owner_digest
                || witness.body.custody_authority_id != keys.authority_id()
            {
                continue;
            }
            witness.verify(keys)?;
            witness.body.validate(owner)?;
            for value in witness.body.values {
                budget.charge(1, 0).map_err(budget_error)?;
                let key = (value.address_digest, value.value_digest);
                if classifications
                    .insert(key, value.live_mutations.clone())
                    .is_some_and(|previous| previous != value.live_mutations)
                {
                    return Err(integrity(
                        "authenticated assertion value classifications conflict",
                    ));
                }
            }
            receipts.push(receipt);
        }
        let mut archived = BTreeMap::<_, Vec<_>>::new();
        for copy in archives
            .into_iter()
            .flat_map(|inventory| &inventory.archives)
            .flat_map(|archive| &archive.copies)
        {
            budget.charge(1, 0).map_err(budget_error)?;
            if !usage.addresses.contains_key(&copy.address_digest) {
                return Err(integrity("archived assertion copy has no selected address"));
            }
            archived
                .entry(&copy.address_digest)
                .or_default()
                .push(&copy.version);
        }
        let mut addresses = BTreeMap::new();
        for (address, history) in &usage.addresses {
            let mut versions = BTreeMap::new();
            for version in history
                .transitions
                .iter()
                .flat_map(|change| change.before.iter().chain(change.after.iter()))
                .chain(history.acknowledged.values())
                .chain(archived.get(address).into_iter().flatten().copied())
            {
                budget.charge(1, 0).map_err(budget_error)?;
                let key = (version.key_id, version.ciphertext_digest.clone());
                if versions
                    .insert(key, version.clone())
                    .is_some_and(|previous| previous != *version)
                {
                    return Err(integrity(
                        "same assertion ciphertext has contradictory values",
                    ));
                }
            }
            let values = versions
                .into_values()
                .map(|version| {
                    let disposition = match classifications
                        .get(&(address.clone(), version.value_digest.clone()))
                    {
                        None => NativeAssertionValueDisposition::Unclassified,
                        Some(live) => {
                            let removed: BTreeSet<_> =
                                live.intersection(selected).copied().collect();
                            let independent: BTreeSet<_> =
                                live.difference(selected).copied().collect();
                            if !removed.is_empty() {
                                NativeAssertionValueDisposition::RequiresRemoval {
                                    selected_mutations: removed,
                                    independent_mutations: independent,
                                }
                            } else if !independent.is_empty() {
                                NativeAssertionValueDisposition::PreserveIndependent {
                                    mutations: independent,
                                }
                            } else {
                                NativeAssertionValueDisposition::PreserveControl
                            }
                        }
                    };
                    NativeAssertionVersionOwnership {
                        version,
                        disposition,
                    }
                })
                .collect();
            addresses.insert(address.clone(), values);
        }
        let inventory = NativeAssertionValueInventory {
            authority_id: ledger.authority_id(),
            revision: frontier.sequence,
            revision_digest: frontier.digest,
            witnesses: receipts,
            addresses,
        };
        crate::retention::keys::charge_report(&inventory, budget)?;
        Ok(Some(inventory))
    }
}
