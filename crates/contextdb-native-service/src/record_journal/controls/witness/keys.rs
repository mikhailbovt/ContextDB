//! Key addresses from independently verified birth/closure controls, without
//! reconstructing removed bodies or assuming that allocated keys prove use.

use super::*;
use crate::{NativeKeyAllocation, encryption, retention};

/// One independently identified body family of a generic record revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRecordBodyKind {
    /// Current or historical primary revision body; may have several key versions.
    ContentHistory,
    /// Full revision body committed by its accepted birth mutation.
    AcceptedBirth,
    /// Full revision body committed by its accepted closure mutation, when closed.
    AcceptedClosure,
}

/// Allocated keys of a revision's primary and accepted mutation body families.
/// Old/unused allocations remain represented. This is not an independently
/// retained key-removal witness, physical-absence proof or erasure permission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordKeyInventory {
    /// Database owning the verified record body addresses.
    pub database_id: String,
    /// Workspace authorized against the retained revision policy.
    pub workspace_id: String,
    /// Exact independently retained birth/closure and source-removal witness.
    pub witness: NativeRecordRemovalWitnessReceipt,
    /// Supplied encryption authority containing the selected allocations.
    pub custody_authority_id: uuid::Uuid,
    /// Complete allocation-catalog revision examined.
    pub allocation_revision: u64,
    /// Authenticated commitment at that revision.
    pub allocation_digest: Option<String>,
    /// Every expected body family and all accepted keys for its address.
    /// An empty allocation list does not prove native or physical absence.
    pub bodies: BTreeMap<NativeRecordBodyKind, Vec<NativeKeyAllocation>>,
}

impl NativeService {
    /// Select historical keys from the exact independent record-removal witness.
    /// Admin plus the stored revision's other access labels remain required;
    /// non-retrievable revisions can be inventoried without changing their policy.
    /// This works after pruning and older restore. Limits are the supplied budget,
    /// 65,536 selected allocations and 32 MiB; no partial inventory is returned.
    pub fn read_record_key_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRecordRemovalWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordKeyInventory> {
        require_capability(context, Capability::Admin)?;
        let ledger = self.suppression.as_ref().ok_or_else(|| {
            unsupported("record key inventory requires retained removal authority")
        })?;
        let witness = ledger.read_record_removal_witness(receipt, budget)?;
        let policy = witness.policy();
        let mut access = policy.access.clone();
        access.retrievable = true;
        if !policy_allows(&context.request, &access) {
            return Err(permission_denied());
        }
        let history = encryption::address(
            &self.keyspaces.content_history,
            &history_key(&policy.record_digest, policy.revision),
        );
        let mut addresses = BTreeMap::from([(history, NativeRecordBodyKind::ContentHistory)]);
        for control in witness.controls() {
            let closed = control.policy.transaction_to;
            let mutation = closed.unwrap_or(control.policy.transaction_from);
            let address = encryption::address(
                &self.keyspaces.continuous,
                &pruning::mutation_address(mutation, &policy.record_digest, policy.revision),
            );
            let kind = if closed.is_some() {
                NativeRecordBodyKind::AcceptedClosure
            } else {
                NativeRecordBodyKind::AcceptedBirth
            };
            if addresses.insert(address, kind).is_some() {
                return Err(integrity("record body key addresses are ambiguous"));
            }
        }
        budget
            .charge(addresses.len() as u64, (addresses.len() * 72) as u64)
            .map_err(raw_index::budget_error)?;
        let selected = self.select_key_allocations(addresses, budget)?;
        let report = NativeRecordKeyInventory {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            witness: receipt.clone(),
            custody_authority_id: selected.authority_id,
            allocation_revision: selected.revision,
            allocation_digest: selected.digest,
            bodies: selected.owners,
        };
        retention::keys::charge_report(&report, budget)?;
        Ok(report)
    }
}
