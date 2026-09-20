//! Join observed source-owned raw addresses to the current key allocation catalog.

use super::*;
use crate::{NativeKeyAllocation, NativeRemovalRequestReceipt};

/// Allocations and exact observed ciphertexts at one source-owned raw address.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawKeyFamily {
    /// All accepted allocations in the reported custody authority. Some may be
    /// unused or unobserved; their presence does not authorize retirement.
    pub allocations: Vec<NativeKeyAllocation>,
    /// Exact observed ciphertexts, including other custody authorities. Repeated
    /// observations are deduplicated; this is not a count of physical copies.
    pub observed_versions: Vec<NativeRawValueVersion>,
}

/// Historical key families selected from independently retained GC observations.
/// Current generations and untracked history remain outside this inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawKeyInventory {
    /// Database of the selected observations.
    pub database_id: String,
    /// Authorized workspace.
    pub workspace_id: String,
    /// Exact independently retained source-removal request.
    pub request: NativeRemovalRequestReceipt,
    /// Current authority used for allocation lookup; other observed authorities
    /// remain explicit in each family and require their own disposition.
    pub custody_authority_id: Uuid,
    /// Complete allocation catalog revision examined.
    pub allocation_revision: u64,
    /// Allocation journal commitment at that revision.
    pub allocation_digest: Option<String>,
    /// Complete retained observation journal frontier examined.
    pub observation_sequence: u64,
    /// Commitment to that retained frontier.
    pub observation_digest: String,
    /// Every request source, indexed by source ID then address digest. An empty
    /// family map is lack of observed ownership, never physical absence.
    pub sources: BTreeMap<ObservationId, BTreeMap<String, NativeRawKeyFamily>>,
    /// Pages with selected rows, shared/unknown obligations or untracked prefixes.
    /// Their exact rows and history can be recovered with read_raw_copy_witness.
    pub witnesses: Vec<NativeRawCopyReceipt>,
}

impl NativeService {
    /// Enumerate retained raw-copy observations and all allocated keys at their
    /// selected addresses. Addresses, allocations, observed ciphertexts and
    /// witness pages are each capped at 65,536, with 32 MiB of output and one
    /// shared budget. Both journal frontiers must remain unchanged during their
    /// scans. No partial result or retirement authority is returned.
    pub fn read_reclaimed_raw_key_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawKeyInventory> {
        let lineage = self.read_original_removal_inventory(context, request, budget)?;
        let controls = discovery::source_controls(&lineage, budget)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("raw copy authority absent"))?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let mut scan = None;
        let mut addresses = BTreeMap::new();
        let mut sources: BTreeMap<_, BTreeMap<String, NativeRawKeyFamily>> = lineage
            .sources
            .iter()
            .map(|source| (source.receipt.event_id, BTreeMap::new()))
            .collect();
        let mut observed = BTreeMap::<
            (ObservationId, String),
            BTreeMap<(Uuid, Uuid, String), NativeRawValueVersion>,
        >::new();
        let mut witnesses = Vec::new();
        let mut observed_count = 0;
        let frontier = loop {
            let page = ledger.scan_raw_copy_witnesses(&workspace, scan.as_ref(), 64, budget)?;
            for copy in discovery::select_copies(page.witnesses, &controls, budget)? {
                budget
                    .charge(1, encode(&copy)?.len() as u64)
                    .map_err(budget_error)?;
                witnesses.push(copy.witness);
                if witnesses.len() > 65_536 {
                    return Err(exhausted("raw key inventory exceeds 65536 witness pages"));
                }
                for row in copy.rows {
                    let Some(source) = row.source else {
                        continue;
                    };
                    let owner = (source, row.address_digest.clone());
                    if addresses
                        .get(&row.address_digest)
                        .is_some_and(|previous| previous != &owner)
                    {
                        return Err(integrity("raw key address has ambiguous source ownership"));
                    }
                    addresses.insert(row.address_digest, owner.clone());
                    if addresses.len() > 65_536 {
                        return Err(exhausted("raw key inventory exceeds 65536 addresses"));
                    }
                    if let Some(version) = row.version {
                        if observed
                            .entry(owner)
                            .or_default()
                            .insert(
                                (
                                    version.authority_id,
                                    version.key_id,
                                    version.ciphertext_digest.clone(),
                                ),
                                version,
                            )
                            .is_none()
                        {
                            observed_count += 1;
                        }
                        if observed_count > 65_536 {
                            return Err(exhausted(
                                "raw key inventory exceeds 65536 observed ciphertexts",
                            ));
                        }
                    }
                }
            }
            if page.state.through == page.state.frontier {
                break page.state.frontier;
            }
            scan = Some(page.state);
        };
        let selected = self.select_key_allocations(addresses, budget)?;
        for ((source, address), allocations) in selected.owners {
            let observed_versions: Vec<NativeRawValueVersion> = observed
                .remove(&(source, address.clone()))
                .unwrap_or_default()
                .into_values()
                .collect();
            let allocated: BTreeSet<_> = allocations.iter().map(|key| key.key_id).collect();
            budget
                .charge(observed_versions.len() as u64, 0)
                .map_err(budget_error)?;
            if observed_versions.iter().any(|version| {
                version.authority_id == selected.authority_id
                    && !allocated.contains(&version.key_id)
            }) {
                return Err(integrity(
                    "observed raw ciphertext has no accepted key allocation",
                ));
            }
            sources
                .get_mut(&source)
                .ok_or_else(|| integrity("raw key inventory source absent"))?
                .insert(
                    address,
                    NativeRawKeyFamily {
                        allocations,
                        observed_versions,
                    },
                );
        }
        let report = NativeRawKeyInventory {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            request: request.clone(),
            custody_authority_id: selected.authority_id,
            allocation_revision: selected.revision,
            allocation_digest: selected.digest,
            observation_sequence: frontier.sequence,
            observation_digest: frontier.digest.clone(),
            sources,
            witnesses,
        };
        crate::retention::keys::charge_report(&report, budget)?;
        ledger.require_raw_copy_frontier(&frontier, budget)?;
        Ok(report)
    }
}
