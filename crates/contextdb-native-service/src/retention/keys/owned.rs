//! Durable decisions for selected payload chunks and generic revision bodies.

use super::*;
use crate::{NativeRecordBodyKind, NativeRecordRemovalWitnessReceipt};
use contextdb_core::{ContentBlockId, OriginalPayloadRef};

#[cfg(test)]
pub(crate) mod tests;

/// Exact retained owner and all of its selected value-key allocations.
/// Shared blocks are excluded. Mixed assertions and raw indexes have other contracts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeOwnedKeyOwner {
    /// One immutable staged payload selected by the removal request.
    Payload {
        /// Retained identity, length and commitments, without payload bytes.
        payload: OriginalPayloadRef,
        /// Every expected chunk ordinal, including empty allocation lists.
        chunks: BTreeMap<u32, Vec<NativeKeyAllocation>>,
    },
    /// One generic revision's primary, birth and optional closure bodies.
    Record {
        /// Exact independently retained source/control ownership.
        witness: NativeRecordRemovalWitnessReceipt,
        /// Every expected body family, including empty allocation lists.
        bodies: BTreeMap<NativeRecordBodyKind, Vec<NativeKeyAllocation>>,
    },
}

/// A complete tracked inventory at immutable custody frontiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOwnedKeyInventory {
    /// Database containing the selected native addresses.
    pub database_id: String,
    /// Authorized workspace of the retained removal request.
    pub workspace_id: String,
    /// Exact independently retained source-removal intent.
    pub request: NativeRemovalRequestReceipt,
    /// Authority containing the allocation and native-use histories.
    pub custody_authority_id: uuid::Uuid,
    /// Complete allocation-catalog revision.
    pub allocation_revision: u64,
    /// Commitment at that allocation revision.
    pub allocation_digest: Option<String>,
    /// Complete v4 use history for the selected addresses; legacy gaps are rejected.
    pub native_use: NativeKeyUseInventory,
    /// Selected owner with all accepted allocations.
    pub owner: NativeOwnedKeyOwner,
}

/// Independent acceptance of one immutable owned-key inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOwnedKeyRemovalReceipt {
    /// Suppression authority retaining the inventory outside native restore.
    pub authority_id: uuid::Uuid,
    /// Accepted source-removal request position.
    pub removal_sequence: u64,
    /// Accepted inventory position in the independent journal.
    pub witness_sequence: u64,
    /// Exact witness-event commitment.
    pub digest: String,
}

/// Historical decisions reconstructed from one retained inventory.
/// This proves neither physical erasure nor current permission to disable keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOwnedKeyRemovalWitness {
    /// Independent immutable acceptance.
    pub receipt: NativeOwnedKeyRemovalReceipt,
    /// Exact source ownership and allocation/use frontiers.
    pub inventory: NativeOwnedKeyInventory,
    /// Decisions by address digest; empty families remain explicit.
    pub dispositions: BTreeMap<String, Vec<NativeOwnedKeyDisposition>>,
}

impl NativeOwnedKeyOwner {
    pub(crate) fn identity(&self) -> ServiceResult<String> {
        match self {
            Self::Payload { payload, .. } => canonical_digest(&("payload", payload)),
            Self::Record { witness, .. } => canonical_digest(&("record", witness)),
        }
    }

    pub(crate) fn allocations(&self) -> impl Iterator<Item = &NativeKeyAllocation> {
        let (chunks, bodies) = match self {
            Self::Payload { chunks, .. } => (Some(chunks), None),
            Self::Record { bodies, .. } => (None, Some(bodies)),
        };
        chunks
            .into_iter()
            .flat_map(|m| m.values().flatten())
            .chain(bodies.into_iter().flat_map(|m| m.values().flatten()))
    }
}

impl NativeOwnedKeyInventory {
    fn addresses(&self) -> ServiceResult<BTreeMap<String, Vec<NativeKeyAllocation>>> {
        let mut addresses: BTreeMap<_, Vec<_>> = self
            .native_use
            .addresses
            .keys()
            .map(|key| (key.clone(), Vec::new()))
            .collect();
        for allocation in self.owner.allocations() {
            addresses
                .get_mut(&allocation.address_digest)
                .ok_or_else(|| integrity("owned allocation has no native-use address"))?
                .push(allocation.clone());
        }
        Ok(addresses)
    }
}

impl NativeService {
    /// Retain chunk-key decisions for an exclusively selected payload. Current
    /// Admin/request checks and complete custody replay precede the fenced Sync.
    /// Exact frontier retries recover the same receipt. At most 5 MiB is retained.
    pub fn retain_payload_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        block: ContentBlockId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let inventory = self.owned_payload_inventory(context, request, block, budget)?;
        self.retain_owned_key_inventory(inventory, budget)
    }

    /// Read an exact historical payload decision with current Admin/request policy.
    /// Both custody frontiers and complete projected history are verified again.
    pub fn read_payload_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        block: ContentBlockId,
        receipt: &NativeOwnedKeyRemovalReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let current = self.owned_payload_inventory(context, request, block, budget)?;
        self.read_owned_key_inventory(current, receipt, budget)
    }

    /// Retain decisions for one source-bound revision, including historical,
    /// birth and closure bodies. Admin and all other stored access labels apply.
    /// Shared/mixed values require their own preservation contract.
    pub fn retain_record_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        owner: &NativeRecordRemovalWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let inventory = self.owned_record_inventory(context, request, owner, budget)?;
        self.retain_owned_key_inventory(inventory, budget)
    }

    /// Read a retained revision-key decision after pruning, restart or older restore.
    /// Current revision policy is checked before inspecting the key witness.
    pub fn read_record_key_removal(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        owner: &NativeRecordRemovalWitnessReceipt,
        receipt: &NativeOwnedKeyRemovalReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let current = self.owned_record_inventory(context, request, owner, budget)?;
        self.read_owned_key_inventory(current, receipt, budget)
    }

    fn owned_payload_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        block: ContentBlockId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyInventory> {
        self.read_original_removal_inventory(context, request, budget)?;
        let report = self.read_payload_key_inventory(context, request, block, budget)?;
        Ok(NativeOwnedKeyInventory {
            database_id: report.database_id,
            workspace_id: report.workspace_id,
            request: report.request,
            custody_authority_id: report.custody_authority_id,
            allocation_revision: report.allocation_revision,
            allocation_digest: report.allocation_digest,
            native_use: require_tracked(report.native_use)?,
            owner: NativeOwnedKeyOwner::Payload {
                payload: report.payload,
                chunks: report.chunks,
            },
        })
    }

    fn owned_record_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        owner: &NativeRecordRemovalWitnessReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyInventory> {
        self.read_original_removal_inventory(context, request, budget)?;
        if owner.authority_id != request.authority_id || owner.removal_sequence != request.sequence
        {
            return Err(invalid(
                "record key owner belongs to another removal request",
            ));
        }
        let report = self.read_record_key_inventory(context, owner, budget)?;
        Ok(NativeOwnedKeyInventory {
            database_id: report.database_id,
            workspace_id: report.workspace_id,
            request: request.clone(),
            custody_authority_id: report.custody_authority_id,
            allocation_revision: report.allocation_revision,
            allocation_digest: report.allocation_digest,
            native_use: require_tracked(report.native_use)?,
            owner: NativeOwnedKeyOwner::Record {
                witness: report.witness,
                bodies: report.bodies,
            },
        })
    }

    fn retain_owned_key_inventory(
        &self,
        inventory: NativeOwnedKeyInventory,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let dispositions =
            decisions::dispositions(&inventory.native_use, &inventory.addresses()?, budget)?;
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
            .ok_or_else(|| unsupported("owned witness requires custody"))?;
        let _guard = keys.lock_inventory_frontier(
            inventory.allocation_revision,
            inventory.allocation_digest.as_deref(),
            &inventory.native_use,
            budget,
        )?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("owned witness requires removal authority"))?;
        let receipt = ledger.retain_owned_key_witness(&inventory, budget)?;
        Ok(NativeOwnedKeyRemovalWitness {
            receipt,
            inventory,
            dispositions,
        })
    }

    fn read_owned_key_inventory(
        &self,
        current: NativeOwnedKeyInventory,
        receipt: &NativeOwnedKeyRemovalReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeOwnedKeyRemovalWitness> {
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| unsupported("owned witness requires removal authority"))?;
        let inventory = ledger.read_owned_key_witness(&current.request, receipt, budget)?;
        if current.database_id != inventory.database_id
            || current.workspace_id != inventory.workspace_id
            || current.request != inventory.request
            || current.owner.identity()? != inventory.owner.identity()?
            || current.custody_authority_id != inventory.custody_authority_id
            || inventory.custody_authority_id != inventory.native_use.authority_id
            || inventory.allocation_revision > current.allocation_revision
        {
            return Err(integrity("owned key witness owner or frontier differs"));
        }
        decisions::verify_allocations(
            &current.addresses()?,
            &inventory.addresses()?,
            inventory.allocation_revision,
            budget,
        )?;
        decisions::verify_use_prefix(&current.native_use, &inventory.native_use, budget)?;
        self.engine
            .keys
            .as_ref()
            .ok_or_else(|| unsupported("owned witness requires custody"))?
            .verify_inventory_checkpoints(
                inventory.allocation_revision,
                inventory.allocation_digest.as_deref(),
                &inventory.native_use,
                budget,
            )?;
        let dispositions =
            decisions::dispositions(&inventory.native_use, &inventory.addresses()?, budget)?;
        Ok(NativeOwnedKeyRemovalWitness {
            receipt: receipt.clone(),
            inventory,
            dispositions,
        })
    }
}

fn require_tracked(usage: Option<NativeKeyUseInventory>) -> ServiceResult<NativeKeyUseInventory> {
    usage.ok_or_else(|| {
        ServiceError::new(
            ErrorCode::FormatIncompatible,
            "owned key decisions require tracked v4 custody history",
            false,
        )
    })
}

#[cfg(test)]
thread_local! {
    static BEFORE_WITNESS_FENCE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
