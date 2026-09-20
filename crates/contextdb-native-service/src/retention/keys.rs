//! Join retained source ownership to accepted historical primary-value keys.
//! Other copy classes, key retirement and completion remain separate.

use super::*;

const MAX_ALLOCATIONS: usize = 65_536;
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// Primary-value key allocations selected by a retained removal request.
/// Allocations may precede interrupted native writes. An empty source list proves
/// no physical absence, and this report authorizes neither key retirement nor
/// deletion completion. Staged chunks, derived rows and external copies differ.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePrimaryKeyInventory {
    /// Database owning the selected primary-value addresses.
    pub database_id: String,
    /// Administratively authorized workspace of the retained source lineage.
    pub workspace_id: String,
    /// Exact retained removal intent used to select roots and descendants.
    pub request: NativeRemovalRequestReceipt,
    /// Independently retained encryption authority containing these allocations.
    pub custody_authority_id: uuid::Uuid,
    /// Complete allocation-catalog revision examined, not a native commit.
    pub allocation_revision: u64,
    /// Authenticated journal commitment at that allocation revision.
    pub allocation_digest: Option<String>,
    /// Every retained source, including descendants, with all allocated keys for
    /// its primary-value address. Independent source addresses are excluded.
    pub sources: BTreeMap<ObservationId, Vec<NativeKeyAllocation>>,
}

impl NativeService {
    /// Inspect all accepted primary-value key versions for a retained request.
    /// This survives native pruning and older restore because source ownership
    /// and allocated keys come from their current independent authorities.
    ///
    /// The whole key journal is traversed with one shared budget and a consistent
    /// revision. Exhaustion or allocation changes return no partial report.
    /// At most 65,536 selected allocations and 32 MiB of output are admitted.
    /// The report is administrative evidence, not an erasure or admission receipt.
    pub fn read_original_key_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePrimaryKeyInventory> {
        // Authenticate the retained request and workspace before inspecting any
        // descriptor, including requests for sources absent from an old replica.
        let lineage = self.read_original_removal_inventory(context, receipt, budget)?;
        let keys = self.engine.keys.as_ref().ok_or_else(|| {
            unsupported("primary key inventory requires independently retained encrypted custody")
        })?;
        let mut addresses = BTreeMap::new();
        let mut sources = BTreeMap::new();
        for source in lineage.sources {
            let id = source.receipt.event_id;
            let address = encryption::address(
                &self.keyspaces.observations_content,
                digest_bytes(id.to_string().as_bytes()).as_bytes(),
            );
            budget
                .charge(1, (address.len() + 16) as u64)
                .map_err(raw_index::budget_error)?;
            if addresses.insert(address, id).is_some() || sources.insert(id, Vec::new()).is_some() {
                return Err(integrity("primary source key addresses are ambiguous"));
            }
        }
        let mut cursor = None;
        let mut count = 0;
        let last = loop {
            let mut page = keys.key_catalog_page(cursor.as_deref(), 256, budget)?;
            for entry in &page.entries {
                if let Some(id) = addresses.get(&entry.address_digest) {
                    if count == MAX_ALLOCATIONS {
                        return Err(exhausted("primary key inventory exceeds 65536 allocations"));
                    }
                    budget
                        .charge(1, encode(entry)?.len() as u64)
                        .map_err(raw_index::budget_error)?;
                    sources
                        .get_mut(id)
                        .ok_or_else(|| integrity("primary source key owner is absent"))?
                        .push(entry.clone());
                    count += 1;
                }
            }
            let Some(next) = page.continuation.take() else {
                break page;
            };
            cursor = Some(next);
        };
        let report = NativePrimaryKeyInventory {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            request: receipt.clone(),
            custody_authority_id: last.authority_id,
            allocation_revision: last.revision,
            allocation_digest: last.revision_digest,
            sources,
        };
        let bytes = encode(&report)?;
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(exhausted("primary key inventory exceeds 32 MiB"));
        }
        budget
            .charge(0, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        Ok(report)
    }
}
