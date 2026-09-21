//! Retained block ownership identifies chunk-key addresses after body pruning.

use std::collections::BTreeMap;

use contextdb_recall::QueryBudget;

use super::*;
use crate::suppression::RemovalCheckpoint;
use crate::{
    NativeKeyAllocation, NativeRemovalRequestReceipt, digest_bytes, encryption, retention,
};

/// Allocated chunk keys for one block selected by an independent removal request.
/// This excludes retained shared blocks and includes historical/unused allocations;
/// the separate native-use field reports tracked outcomes, not physical erasure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePayloadKeyInventory {
    /// Database owning this staged block.
    pub database_id: String,
    /// Administratively authorized workspace of the retained request.
    pub workspace_id: String,
    /// Exact retained request selecting this block for removal.
    pub request: NativeRemovalRequestReceipt,
    /// Independently retained block identity, length and commitments.
    pub payload: OriginalPayloadRef,
    /// Supplied current encryption authority; no other authority is enumerated.
    pub custody_authority_id: uuid::Uuid,
    /// Complete allocation-catalog revision examined.
    pub allocation_revision: u64,
    /// Authenticated commitment at that allocation revision.
    pub allocation_digest: Option<String>,
    /// Tracked history for these selected addresses. None supplies no use evidence
    /// (legacy profile or older serialized report). This does not retire keys.
    #[serde(default)]
    pub native_use: Option<crate::NativeKeyUseInventory>,
    /// Every expected chunk ordinal with all accepted keys for its value address.
    /// An empty list is not physical-absence evidence.
    pub chunks: BTreeMap<u32, Vec<NativeKeyAllocation>>,
}

impl NativeService {
    /// Inventory one selected block's historical chunk keys using retained
    /// ownership, even if an older replica lacks the block or its bodies are gone.
    /// Independent shared blocks are rejected. The header/control rows are not
    /// body copies. At most 65,536 keys/32 MiB and the supplied budget are admitted;
    /// this read-only result is not a removal or disclosure-admission receipt.
    pub fn read_payload_key_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRemovalRequestReceipt,
        block: ContentBlockId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePayloadKeyInventory> {
        require_capability(context, Capability::Admin)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| invalid("payload key inventory requires retained removal authority"))?;
        if receipt.authority_id != ledger.authority_id() {
            return Err(invalid("payload key inventory authority differs"));
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let request = RemovalCheckpoint {
            sequence: receipt.sequence,
            digest: receipt.digest.clone(),
        };
        let intent = ledger.retained_removal_intent(&workspace, &request)?;
        if retention::removal_receipt(ledger, &request, &intent) != *receipt {
            return Err(invalid("payload key inventory request differs"));
        }
        let payload = ledger.removal_payload(&workspace, &request, block, budget)?;
        if payload.byte_length > CAPTURE_MAX_PAYLOAD_BYTES as u64 {
            return Err(integrity(
                "retained payload exceeds its accepted size profile",
            ));
        }
        let mut addresses = BTreeMap::new();
        let count = payload.byte_length.div_ceil(CHUNK_BYTES as u64) as u32;
        for ordinal in 0..count {
            budget
                .charge(1, 68)
                .map_err(crate::raw_index::budget_error)?;
            let address =
                encryption::address(&self.keyspaces.continuous, &chunk_key(block, ordinal));
            if addresses.insert(address, ordinal).is_some() {
                return Err(integrity("payload chunk key addresses are ambiguous"));
            }
        }
        let selected = self.select_key_allocations(addresses, budget)?;
        let report = NativePayloadKeyInventory {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            request: receipt.clone(),
            payload,
            custody_authority_id: selected.authority_id,
            allocation_revision: selected.revision,
            allocation_digest: selected.digest,
            native_use: selected.native_use,
            chunks: selected.owners,
        };
        retention::keys::charge_report(&report, budget)?;
        Ok(report)
    }
}
