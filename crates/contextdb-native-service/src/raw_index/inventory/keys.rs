//! Key families from a complete retained inspection chain, independent of native restore.

use super::*;
use crate::raw_index::copies::keys::RawKeyFamilies;

/// Selected key families at an inspected native snapshot. The terminal receipt
/// preserves shared/unknown obligations and reclaimed prefixes in its page chain.
/// Historical unobserved copies and accepted native-use closure remain separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawIndexKeyInventory {
    /// Native database of the inspection.
    pub database_id: String,
    /// Administratively authorized workspace.
    pub workspace_id: String,
    /// Exact independently retained removal request.
    pub request: NativeRemovalRequestReceipt,
    /// Current key authority used to look up allocations.
    pub custody_authority_id: Uuid,
    /// Allocation journal frontier examined.
    pub allocation_revision: u64,
    /// Commitment at that allocation frontier.
    pub allocation_digest: Option<String>,
    /// Tracked history for these selected addresses. None supplies no use evidence
    /// (legacy profile or older serialized report). This does not retire keys.
    #[serde(default)]
    pub native_use: Option<crate::NativeKeyUseInventory>,
    /// The observed snapshot; it need not match the currently restored native store.
    pub snapshot: NativeRawIndexSnapshot,
    /// Terminal receipt anchoring every inspected page, including shared/unknown rows.
    pub inventory: NativeRawIndexInventoryReceipt,
    /// Number of independently retained pages validated back to the initial page.
    pub inspected_pages: u32,
    /// Every request source, including empty observed maps. Independent owners are
    /// excluded; allocations and exact observed ciphertexts remain distinct.
    pub sources: BTreeMap<ObservationId, BTreeMap<String, NativeRawKeyFamily>>,
}

impl NativeService {
    /// Join all pages of a finished inspection to its selected source key families.
    /// Up to 65,536 pages, selected addresses, ciphertexts and allocations are
    /// admitted with one shared budget and 32 MiB output. A broken page chain or an
    /// unallocated observed key returns no partial report. This does not retire keys.
    pub fn read_raw_index_key_inventory(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        inventory: &NativeRawIndexInventoryReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawIndexKeyInventory> {
        let lineage = self.read_original_removal_inventory(context, request, budget)?;
        let selected_sources: BTreeSet<_> = lineage
            .sources
            .iter()
            .map(|source| source.receipt.event_id)
            .collect();
        let mut families = RawKeyFamilies::new(selected_sources.iter().copied());
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("raw inventory authority absent"))?;
        let (snapshot, inspected_pages) = ledger.walk_raw_index_inventory(
            inventory,
            &digest_bytes(context.request.workspace_id.as_bytes()),
            request,
            budget,
            |witness, budget| {
                budget
                    .charge(witness.rows.len() as u64, 0)
                    .map_err(budget_error)?;
                for row in witness.rows {
                    if row
                        .source
                        .is_some_and(|source| selected_sources.contains(&source))
                    {
                        families.observe(row)?;
                    }
                }
                Ok(())
            },
        )?;
        let selected = families.select(self, budget)?;
        let report = NativeRawIndexKeyInventory {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            request: request.clone(),
            custody_authority_id: selected.authority_id,
            allocation_revision: selected.revision,
            allocation_digest: selected.digest,
            native_use: selected.native_use,
            snapshot,
            inventory: inventory.clone(),
            inspected_pages,
            sources: selected.sources,
        };
        crate::retention::keys::charge_report(&report, budget)?;
        Ok(report)
    }
}
