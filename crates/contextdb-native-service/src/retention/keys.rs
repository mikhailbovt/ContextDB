//! Join retained source ownership to accepted historical primary-value keys.
//! Other copy classes, key retirement and completion remain separate.

use super::*;

pub(crate) mod witness;
pub use witness::{
    NativePrimaryKeyAction, NativePrimaryKeyDisposition, NativePrimaryKeyRemovalReceipt,
    NativePrimaryKeyRemovalWitness,
};

const MAX_ALLOCATIONS: usize = 65_536;
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;

pub(crate) struct KeyAllocationSelection<T> {
    pub authority_id: uuid::Uuid,
    pub revision: u64,
    pub digest: Option<String>,
    pub owners: BTreeMap<T, Vec<NativeKeyAllocation>>,
    pub native_use: Option<NativeKeyUseInventory>,
}

pub(crate) fn charge_report<T: Serialize>(
    report: &T,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    let bytes = encode(report)?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(exhausted("key inventory exceeds 32 MiB"));
    }
    budget
        .charge(0, bytes.len() as u64)
        .map_err(raw_index::budget_error)
}

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
    /// Tracked history for these selected addresses. None supplies no use evidence
    /// (legacy profile or older serialized report). This does not retire keys.
    #[serde(default)]
    pub native_use: Option<NativeKeyUseInventory>,
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
        let mut addresses = BTreeMap::new();
        for source in lineage.sources {
            let id = source.receipt.event_id;
            let address = encryption::address(
                &self.keyspaces.observations_content,
                digest_bytes(id.to_string().as_bytes()).as_bytes(),
            );
            budget
                .charge(1, (address.len() + 16) as u64)
                .map_err(raw_index::budget_error)?;
            if addresses.insert(address, id).is_some() {
                return Err(integrity("primary source key addresses are ambiguous"));
            }
        }
        let selected = self.select_key_allocations(addresses, budget)?;
        let report = NativePrimaryKeyInventory {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            request: receipt.clone(),
            custody_authority_id: selected.authority_id,
            allocation_revision: selected.revision,
            allocation_digest: selected.digest,
            native_use: selected.native_use,
            sources: selected.owners,
        };
        charge_report(&report, budget)?;
        Ok(report)
    }

    // Callers authenticate retained ownership before selecting any descriptors.
    // One traversal keeps all requested copy addresses at one allocation revision.
    pub(crate) fn select_key_allocations<T: Ord + Clone>(
        &self,
        addresses: BTreeMap<String, T>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<KeyAllocationSelection<T>> {
        if addresses.len() > MAX_ALLOCATIONS {
            return Err(exhausted("key inventory exceeds 65536 addresses"));
        }
        let keys = self.engine.keys.as_ref().ok_or_else(|| {
            unsupported("key inventory requires independently retained encrypted custody")
        })?;
        let mut owners: BTreeMap<_, Vec<_>> = addresses
            .values()
            .cloned()
            .map(|owner| (owner, Vec::new()))
            .collect();
        let mut used_keys: BTreeMap<_, BTreeSet<_>> = addresses
            .keys()
            .map(|address| (address.clone(), BTreeSet::new()))
            .collect();
        let mut cursor = None;
        let mut count = 0;
        let last = loop {
            let mut page = keys.key_catalog_page(cursor.as_deref(), 256, budget)?;
            for entry in &page.entries {
                if let Some(id) = addresses.get(&entry.address_digest) {
                    if count == MAX_ALLOCATIONS {
                        return Err(exhausted("key inventory exceeds 65536 allocations"));
                    }
                    budget
                        .charge(1, encode(entry)?.len() as u64)
                        .map_err(raw_index::budget_error)?;
                    owners
                        .get_mut(id)
                        .ok_or_else(|| integrity("key inventory owner is absent"))?
                        .push(entry.clone());
                    used_keys
                        .get_mut(&entry.address_digest)
                        .ok_or_else(|| integrity("selected key address is absent"))?
                        .insert(entry.key_id);
                    count += 1;
                }
            }
            let Some(next) = page.continuation.take() else {
                break page;
            };
            cursor = Some(next);
        };
        let native_use = keys.selected_native_use_inventory(
            &used_keys,
            last.revision,
            last.revision_digest.as_deref(),
            budget,
        )?;
        Ok(KeyAllocationSelection {
            authority_id: last.authority_id,
            revision: last.revision,
            digest: last.revision_digest,
            owners,
            native_use,
        })
    }
}
