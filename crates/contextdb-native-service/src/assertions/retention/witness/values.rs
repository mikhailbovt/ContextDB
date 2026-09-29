//! Classify exact mixed values while verified before/after bytes still exist.
//! The attestation authenticates classification, not native publication or erasure.

use super::*;
use crate::NativeCustodyKeys;

mod inventory;
#[cfg(test)]
pub(crate) mod tests;
pub use inventory::{
    NativeAssertionValueDisposition, NativeAssertionValueInventory, NativeAssertionVersionOwnership,
};
use keys::Owner;

pub(crate) const MAX_VALUE_WITNESS_BYTES: usize = 1024 * 1024;

/// Independent acceptance of exact assertion-value ownership metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssertionValueWitnessReceipt {
    /// Suppression authority retaining this classification outside native backups.
    pub authority_id: uuid::Uuid,
    /// Accepted position in the authority's removal journal.
    pub witness_sequence: u64,
    /// Exact accepted event commitment.
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifiedValue {
    owner: Owner,
    address_digest: String,
    value_digest: String,
    // Includes independently configured host policies in shared batch values.
    // Empty means replay controls without live mutation bodies or envelopes.
    live_mutations: BTreeSet<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssertionValueOwnership {
    version: u16,
    pub(crate) custody_authority_id: uuid::Uuid,
    pub(crate) owner: NativeAssertionRemovalWitnessReceipt,
    pub(crate) ownership_digest: String,
    pub(crate) workspace_id: String,
    /// Intended pruning position, not proof that native Sync happened.
    pub(crate) pruning_commit: u64,
    values: Vec<ClassifiedValue>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttestedAssertionValues {
    pub(crate) body: AssertionValueOwnership,
    pub(crate) proof: Vec<u8>,
}

pub(in crate::assertions) struct PruningValues<'a> {
    pub request: &'a RemovalCheckpoint,
    pub receipt: &'a AssertionReceipt,
    pub before: &'a RetainedAssertions,
    pub after: &'a RetainedAssertions,
    pub old_key: &'a [u8],
    pub old_value: &'a [u8],
    pub commit: u64,
}

impl AttestedAssertionValues {
    pub(crate) fn verify(&self, keys: &NativeCustodyKeys) -> ServiceResult<()> {
        if self.body.custody_authority_id != keys.authority_id() {
            return Err(integrity(
                "assertion value witness has another custody authority",
            ));
        }
        keys.verify_assertion_value_attestation(&canonical_digest(&self.body)?, &self.proof)
    }
}

impl AssertionValueOwnership {
    pub(crate) fn validate(&self, owner: &AssertionRemovalWitness) -> ServiceResult<()> {
        if self.version != 1
            || self.custody_authority_id.is_nil()
            || self.owner.assertion_commit != owner.assertion_commit()
            || self.owner.scope != owner.scope()
            || self.workspace_id != owner.workspace()
            || self.ownership_digest != canonical_digest(owner)?
            || self.pruning_commit <= owner.assertion_commit()
            || self.values.is_empty()
            || self.values.len() > 512
        {
            return Err(integrity("assertion value witness ownership differs"));
        }
        let ordinals = owner
            .mutations
            .iter()
            .enumerate()
            .filter_map(|(i, m)| m.as_ref().map(|_| i))
            .collect();
        let space = crate::Keyspaces::new()?.continuous;
        let addresses: BTreeMap<_, _> = owner
            .copy_keys(&ordinals)?
            .into_iter()
            .map(|(key, kind)| (kind, crate::encryption::address(&space, &key)))
            .collect();
        let mut seen = BTreeSet::new();
        for value in &self.values {
            if addresses.get(&value.owner) != Some(&value.address_digest)
                || blake3::Hash::from_hex(&value.value_digest).is_err()
                || !seen.insert((value.owner.clone(), value.value_digest.clone()))
                || value
                    .live_mutations
                    .iter()
                    .any(|i| *i >= owner.mutations.len())
            {
                return Err(integrity(
                    "assertion value witness address or mutation set differs",
                ));
            }
            match &value.owner {
                Owner::Batch(NativeAssertionBatchKind::Original) => {
                    if value.value_digest != digest_bytes_of_receipt(&owner.receipt)
                        || value.live_mutations != (0..owner.mutations.len()).collect()
                    {
                        return Err(integrity(
                            "original assertion classification differs from receipt",
                        ));
                    }
                }
                Owner::Batch(NativeAssertionBatchKind::Retained) => {}
                Owner::Mutation(ordinal, copy) => {
                    if !value.live_mutations.is_subset(&BTreeSet::from([*ordinal])) {
                        return Err(integrity(
                            "assertion mutation classification widens ownership",
                        ));
                    }
                    if *copy == NativeAssertionCopyKind::Body {
                        let control = owner.mutations[*ordinal]
                            .as_ref()
                            .ok_or_else(|| integrity("assertion body control absent"))?;
                        if value.value_digest != control.body_digest
                            || value.live_mutations != BTreeSet::from([*ordinal])
                        {
                            return Err(integrity(
                                "assertion body classification differs from accepted digest",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl NativeService {
    pub(in crate::assertions) fn verify_pruning_value_ownership(
        &self,
        publication: &AssertionPruningPublication,
        control: &BatchControl,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("assertion value authority absent"))?;
        // Legacy publications explicitly lack this evidence. Commit numbers may
        // repeat after restore; a newer attempt must not reclassify an old event.
        if let Some(receipt) = &publication.value_ownership {
            let witness = ledger.read_assertion_value_witness(receipt, budget)?;
            let keys = self
                .engine
                .keys
                .as_ref()
                .ok_or_else(|| integrity("assertion value custody absent"))?;
            witness.verify(keys)?;
            let (owner, _) = ledger.read_assertion_removal_witness(&witness.body.owner, budget)?;
            if owner.control != *control
                || owner.receipt != publication.receipt
                || witness.body.owner.removal_sequence != publication.request.sequence
                || witness.body.pruning_commit != publication.workspace_commit
            {
                return Err(integrity(
                    "assertion value classification belongs to another batch",
                ));
            }
        }
        Ok(())
    }

    // Called under native publication admission after semantic replay and workspace
    // CAS. It captures verified values before destructive native staging/Sync.
    pub(in crate::assertions) fn retain_pruning_value_ownership(
        &self,
        input: PruningValues<'_>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<NativeAssertionValueWitnessReceipt>> {
        let Some(keys) = self
            .engine
            .keys
            .as_ref()
            .filter(|keys| keys.supports_value_ownership())
        else {
            return Ok(None); // Existing plaintext/legacy pruning supplies no such evidence.
        };
        let owner = AssertionRemovalWitness::from_batch(input.receipt.clone(), input.before)?;
        if owner != AssertionRemovalWitness::from_batch(input.receipt.clone(), input.after)? {
            return Err(integrity(
                "pruning changes independently owned assertion controls",
            ));
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("assertion value authority absent"))?;
        if !ledger.supports_record_sources() {
            return Ok(None);
        }
        let accepted = ledger.retain_assertion_removal_witness(input.request, &owner, budget)?;
        let owner_receipt = NativeAssertionRemovalWitnessReceipt {
            authority_id: ledger.authority_id(),
            removal_sequence: input.request.sequence,
            witness_sequence: accepted.sequence,
            digest: accepted.digest,
            assertion_commit: owner.assertion_commit(),
            scope: owner.scope(),
        };
        let mut values = BTreeMap::new();
        collect_values(
            &owner,
            input.before,
            input.old_key,
            input.old_value,
            &mut values,
            budget,
        )?;
        let new_key = retained_key(
            &digest_bytes(owner.workspace().as_bytes()),
            owner.assertion_commit(),
        );
        collect_values(
            &owner,
            input.after,
            &new_key,
            &encode(input.after)?,
            &mut values,
            budget,
        )?;
        let body = AssertionValueOwnership {
            version: 1,
            custody_authority_id: keys.authority_id(),
            owner: owner_receipt,
            ownership_digest: canonical_digest(&owner)?,
            workspace_id: owner.workspace().into(),
            pruning_commit: input.commit,
            values: values.into_values().collect(),
        };
        body.validate(&owner)?;
        let witness = AttestedAssertionValues {
            proof: keys.attest_assertion_values(&canonical_digest(&body)?)?,
            body,
        };
        let receipt =
            ledger.retain_assertion_value_witness(input.request, &witness, keys, budget)?;
        #[cfg(test)]
        AFTER_VALUES_SYNC.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        Ok(Some(receipt))
    }
}

fn collect_values(
    owner: &AssertionRemovalWitness,
    batch: &RetainedAssertions,
    batch_key: &[u8],
    batch_value: &[u8],
    output: &mut BTreeMap<(Owner, String), ClassifiedValue>,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    let mut rows = retained_rows(batch)?;
    rows.insert(batch_key.to_vec(), batch_value.to_vec());
    let ordinals = owner
        .mutations
        .iter()
        .enumerate()
        .filter_map(|(i, m)| m.as_ref().map(|_| i))
        .collect();
    let space = crate::Keyspaces::new()?.continuous;
    for (key, kind) in owner.copy_keys(&ordinals)? {
        let Some(bytes) = rows.get(&key) else {
            continue;
        };
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let live_mutations = match &kind {
            Owner::Batch(_) => batch
                .mutations
                .iter()
                .enumerate()
                .filter_map(|(ordinal, mutation)| {
                    matches!(mutation, RetainedMutation::Live { .. }).then_some(ordinal)
                })
                .collect(),
            Owner::Mutation(ordinal, NativeAssertionCopyKind::Body) => BTreeSet::from([*ordinal]),
            Owner::Mutation(ordinal, _) => {
                let label: MutationLabel = decode(bytes, "assertion value ownership label")?;
                if label.envelope.is_some() {
                    BTreeSet::from([*ordinal])
                } else {
                    BTreeSet::new()
                }
            }
        };
        let value = ClassifiedValue {
            address_digest: crate::encryption::address(&space, &key),
            value_digest: digest_bytes(bytes),
            owner: kind.clone(),
            live_mutations,
        };
        if output
            .insert((kind, value.value_digest.clone()), value.clone())
            .is_some_and(|previous| previous != value)
        {
            return Err(integrity(
                "same assertion value has conflicting classification",
            ));
        }
    }
    Ok(())
}

fn digest_bytes_of_receipt(receipt: &AssertionReceipt) -> String {
    receipt.mutation_digest.to_string()
}

#[cfg(test)]
thread_local! {
    static AFTER_VALUES_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
