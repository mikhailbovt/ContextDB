//! Durable primary-version decisions. Shared rows and key disablement are separate.

use super::*;
use uuid::Uuid;

mod projection;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) const MAX_WITNESS_BYTES: usize = 5 * 1024 * 1024;

pub use super::decisions::{
    NativeOwnedKeyAction as NativePrimaryKeyAction,
    NativeOwnedKeyDisposition as NativePrimaryKeyDisposition,
};

/// Exact independent acceptance of one primary inventory and its derived decisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePrimaryKeyRemovalReceipt {
    /// Current suppression authority retaining the witness outside native backups.
    pub authority_id: Uuid,
    /// Original removal request position.
    pub removal_sequence: u64,
    /// Witness position in the same authority's append-only journal.
    pub witness_sequence: u64,
    /// Accepted witness-event commitment.
    pub digest: String,
}

/// Immutable historical evidence, never a current erasure or completion receipt.
/// Decisions are recomputed from the retained inventory; no second mutable copy
/// of those decisions is stored. Reading verifies both authorities' histories.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePrimaryKeyRemovalWitness {
    /// Independently retained acceptance.
    pub receipt: NativePrimaryKeyRemovalReceipt,
    /// Exact request, ownership, allocation frontier and native-use frontier.
    pub inventory: NativePrimaryKeyInventory,
    /// Every selected source, including sources without known allocated keys.
    pub dispositions: BTreeMap<ObservationId, Vec<NativePrimaryKeyDisposition>>,
}

impl NativeService {
    /// Retain a complete v4 primary inventory under the custody publication fence.
    /// Exact frontier retries return the same receipt; newer frontiers append new
    /// witnesses. At most 5 MiB is retained per witness, under the shared budget.
    /// No native data, key availability or disclosure gate is changed.
    pub fn retain_original_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePrimaryKeyRemovalWitness> {
        let inventory = self.read_original_key_inventory(context, request, budget)?;
        let dispositions = projection::dispositions(&inventory, budget)?;
        #[cfg(test)]
        BEFORE_WITNESS_FENCE.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| unsupported("primary witness requires custody"))?;
        let usage = tracked(&inventory)?;
        let _guard = keys.lock_inventory_frontier(
            inventory.allocation_revision,
            inventory.allocation_digest.as_deref(),
            usage,
            budget,
        )?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("primary witness requires removal authority"))?;
        let receipt = ledger.retain_primary_key_witness(&inventory, budget)?;
        Ok(NativePrimaryKeyRemovalWitness {
            receipt,
            inventory,
            dispositions,
        })
    }

    /// Recover an immutable decision after pruning, restart or older restore.
    /// Current Admin/request checks precede all witness/key inspection. Complete
    /// current replay is projected back to the saved frontiers, including outcomes
    /// that were still unresolved then. Later growth does not rewrite old evidence.
    pub fn read_original_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativePrimaryKeyRemovalReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePrimaryKeyRemovalWitness> {
        self.read_original_removal_inventory(context, request, budget)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("primary witness requires removal authority"))?;
        let inventory = ledger.read_primary_key_witness(context, request, receipt, budget)?;
        let current = self.read_original_key_inventory(context, request, budget)?;
        projection::verify_prefix(&current, &inventory, budget)?;
        self.engine
            .keys
            .as_ref()
            .ok_or_else(|| unsupported("primary witness requires custody"))?
            .verify_inventory_checkpoints(
                inventory.allocation_revision,
                inventory.allocation_digest.as_deref(),
                tracked(&inventory)?,
                budget,
            )?;
        let dispositions = projection::dispositions(&inventory, budget)?;
        Ok(NativePrimaryKeyRemovalWitness {
            receipt: receipt.clone(),
            inventory,
            dispositions,
        })
    }
}

pub(crate) fn tracked(
    inventory: &NativePrimaryKeyInventory,
) -> ServiceResult<&NativeKeyUseInventory> {
    inventory.native_use.as_ref().ok_or_else(|| {
        ServiceError::new(
            ErrorCode::FormatIncompatible,
            "primary key decisions require tracked v4 custody history",
            false,
        )
    })
}

#[cfg(test)]
thread_local! {
    static BEFORE_WITNESS_FENCE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
