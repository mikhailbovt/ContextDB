//! Allocation evidence preserves shared batch and mutation copy boundaries.

use super::*;
use crate::{NativeKeyAllocation, encryption};

/// A mixed batch can also contain independently needed mutations or host policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAssertionBatchKind {
    /// Original complete accepted semantic publication.
    Original,
    /// Replacements with removed mutations represented by compact controls.
    Retained,
}

/// A source mutation has a body and labels that may contain its full envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAssertionCopyKind {
    /// Exact assertion or retraction body.
    Body,
    /// State-slot label, including historical envelopes before pruning.
    SlotLabel,
    /// Assertion claim label; retractions do not have this copy.
    ClaimLabel,
}

/// Historical allocation families selected by independent assertion ownership.
/// Shared batches and current cleaned labels can still be required. Tracked use
/// and authenticated composition are attached separately; allocation alone never
/// establishes native publication, physical absence or safe key retirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssertionKeyInventory {
    /// Database owning these value addresses.
    pub database_id: String,
    /// Workspace admitted by the independently retained batch policy.
    pub workspace_id: String,
    /// Exact independent removal witness selecting mutation ordinals.
    pub witness: NativeAssertionRemovalWitnessReceipt,
    /// Supplied custody authority; no other key copies are enumerated.
    pub custody_authority_id: uuid::Uuid,
    /// Complete authenticated allocation revision inspected.
    pub allocation_revision: u64,
    /// Commitment at that revision.
    pub allocation_digest: Option<String>,
    /// Tracked history for these selected addresses. None supplies no use evidence
    /// (legacy profile or older serialized report). This does not retire keys.
    #[serde(default)]
    pub native_use: Option<crate::NativeKeyUseInventory>,
    /// Custody-authenticated classifications of exact known values. Unclassified
    /// versions remain explicit; this does not authorize key disablement.
    #[serde(default)]
    pub value_ownership: Option<NativeAssertionValueInventory>,
    /// All allocated keys of original and rewritten shared batch addresses.
    pub batches: BTreeMap<NativeAssertionBatchKind, Vec<NativeKeyAllocation>>,
    /// Selected source mutation ordinals, their body/label families and all keys.
    /// Independent mutation addresses and metadata-only evidence rows are excluded.
    pub mutations: BTreeMap<usize, BTreeMap<NativeAssertionCopyKind, Vec<NativeKeyAllocation>>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Owner {
    Batch(NativeAssertionBatchKind),
    Mutation(usize, NativeAssertionCopyKind),
}

impl NativeService {
    /// Inventory source-selected mutation copies and their shared semantic batches,
    /// even after pruning or restore of an archive predating the batch. The retained
    /// witness, current Admin/scope and batch policy precede catalog access. A shared
    /// budget, consistent allocation revision, 65,536 keys and 32 MiB bound the
    /// complete result. Historical/unused and cleaned replacement allocations are
    /// included; this report is not a key-removal witness or erasure permission.
    pub fn read_assertion_key_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeAssertionRemovalWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeAssertionKeyInventory> {
        let (mut report, witness, selected) =
            self.assertion_key_inventory(context, receipt, budget)?;
        report.value_ownership =
            self.assertion_value_inventory(&witness, &selected, &report, None, budget)?;
        crate::retention::keys::charge_report(&report, budget)?;
        Ok(report)
    }

    pub(super) fn assertion_key_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeAssertionRemovalWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(
        NativeAssertionKeyInventory,
        AssertionRemovalWitness,
        BTreeSet<usize>,
    )> {
        require_scope(context, receipt.scope, Capability::Admin)?;
        let ledger = self.suppression.as_ref().ok_or_else(|| {
            crate::unsupported("assertion key inventory requires retained removal authority")
        })?;
        let (witness, selected) = ledger.read_assertion_removal_witness(receipt, budget)?;
        if !policy_allows(&context.request, &witness.control.access) {
            return Err(crate::permission_denied());
        }
        let copies = witness.copy_keys(&selected)?;
        let mut addresses = BTreeMap::new();
        for (key, owner) in copies {
            budget
                .charge(1, (key.len() + 80) as u64)
                .map_err(budget_error)?;
            let address = encryption::address(&self.keyspaces.continuous, &key);
            if addresses.insert(address, owner).is_some() {
                return Err(integrity("assertion copy key addresses are ambiguous"));
            }
        }
        let allocations = self.select_key_allocations(addresses, budget)?;
        let mut batches = BTreeMap::new();
        let mut mutations: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();
        for (owner, keys) in allocations.owners {
            match owner {
                Owner::Batch(kind) => {
                    batches.insert(kind, keys);
                }
                Owner::Mutation(ordinal, kind) => {
                    mutations.entry(ordinal).or_default().insert(kind, keys);
                }
            }
        }
        let report = NativeAssertionKeyInventory {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            witness: receipt.clone(),
            custody_authority_id: allocations.authority_id,
            allocation_revision: allocations.revision,
            allocation_digest: allocations.digest,
            native_use: allocations.native_use,
            value_ownership: None,
            batches,
            mutations,
        };
        Ok((report, witness, selected))
    }
}

impl AssertionRemovalWitness {
    pub(super) fn copy_keys(
        &self,
        selected: &BTreeSet<usize>,
    ) -> ServiceResult<Vec<(Vec<u8>, Owner)>> {
        let workspace = digest_bytes(self.workspace().as_bytes());
        let commit = self.control.commit;
        let mut copies = vec![
            (
                journal_key(&workspace, commit),
                Owner::Batch(NativeAssertionBatchKind::Original),
            ),
            (
                retained_key(&workspace, commit),
                Owner::Batch(NativeAssertionBatchKind::Retained),
            ),
        ];
        for &ordinal in selected {
            let mutation = self
                .mutations
                .get(ordinal)
                .and_then(Option::as_ref)
                .ok_or_else(|| integrity("selected assertion witness mutation is absent"))?;
            let body = match mutation.kind {
                RemovedKind::Assert { claim, .. } => {
                    copies.push((
                        claim_label_key(claim),
                        Owner::Mutation(ordinal, NativeAssertionCopyKind::ClaimLabel),
                    ));
                    claim_key(claim)
                }
                RemovedKind::Retract { .. } => retraction_key(&workspace, commit, ordinal),
            };
            copies.push((
                body,
                Owner::Mutation(ordinal, NativeAssertionCopyKind::Body),
            ));
            copies.push((
                format!(
                    "{}{:020}/{ordinal:03}",
                    slot_prefix(&workspace, &canonical_digest(&mutation.key)?),
                    commit
                )
                .into_bytes(),
                Owner::Mutation(ordinal, NativeAssertionCopyKind::SlotLabel),
            ));
        }
        Ok(copies)
    }
}
