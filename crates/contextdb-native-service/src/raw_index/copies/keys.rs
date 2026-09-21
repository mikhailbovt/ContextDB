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
    /// Tracked history for these selected addresses. None supplies no use evidence
    /// (legacy profile or older serialized report). This does not retire keys.
    #[serde(default)]
    pub native_use: Option<crate::NativeKeyUseInventory>,
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
        let mut families = RawKeyFamilies::new(controls.keys().copied());
        let mut witnesses = Vec::new();
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
                    families.observe(row)?;
                }
            }
            if page.state.through == page.state.frontier {
                break page.state.frontier;
            }
            scan = Some(page.state);
        };
        let selected = families.select(self, budget)?;
        let report = NativeRawKeyInventory {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            request: request.clone(),
            custody_authority_id: selected.authority_id,
            allocation_revision: selected.revision,
            allocation_digest: selected.digest,
            native_use: selected.native_use,
            observation_sequence: frontier.sequence,
            observation_digest: frontier.digest.clone(),
            sources: selected.sources,
            witnesses,
        };
        crate::retention::keys::charge_report(&report, budget)?;
        ledger.require_raw_copy_frontier(&frontier, budget)?;
        Ok(report)
    }
}

// Shared source/address/version selection for reclamation and live observations.
type RawKeyOwner = (ObservationId, String);
type ObservedVersions = BTreeMap<(Uuid, Uuid, String), (NativeRawValueVersion, String)>;

pub(in crate::raw_index) struct RawKeyFamilies {
    addresses: BTreeMap<String, RawKeyOwner>,
    observed: BTreeMap<RawKeyOwner, ObservedVersions>,
    sources: BTreeMap<ObservationId, BTreeMap<String, NativeRawKeyFamily>>,
    observed_count: usize,
}

pub(in crate::raw_index) struct RawFamilySelection {
    pub native_use: Option<crate::NativeKeyUseInventory>,
    pub authority_id: Uuid,
    pub revision: u64,
    pub digest: Option<String>,
    pub sources: BTreeMap<ObservationId, BTreeMap<String, NativeRawKeyFamily>>,
}

impl RawKeyFamilies {
    pub(in crate::raw_index) fn new(sources: impl Iterator<Item = ObservationId>) -> Self {
        Self {
            addresses: BTreeMap::new(),
            observed: BTreeMap::new(),
            observed_count: 0,
            sources: sources.map(|source| (source, BTreeMap::new())).collect(),
        }
    }

    pub(in crate::raw_index) fn observe(
        &mut self,
        row: NativeRawCopyObservation,
    ) -> ServiceResult<()> {
        let Some(source) = row.source else {
            return Ok(());
        };
        if !self.sources.contains_key(&source) {
            return Err(integrity(
                "raw key row is outside selected source ownership",
            ));
        }
        let owner = (source, row.address_digest.clone());
        if self
            .addresses
            .get(&row.address_digest)
            .is_some_and(|previous| previous != &owner)
        {
            return Err(integrity("raw key address has ambiguous source ownership"));
        }
        self.addresses.insert(row.address_digest, owner.clone());
        if self.addresses.len() > 65_536 {
            return Err(exhausted("raw key inventory exceeds 65536 addresses"));
        }
        if let Some(version) = row.version {
            let previous = self.observed.entry(owner).or_default().insert(
                (
                    version.authority_id,
                    version.key_id,
                    version.ciphertext_digest.clone(),
                ),
                (version, row.value_digest.clone()),
            );
            if previous
                .as_ref()
                .is_some_and(|(_, digest)| *digest != row.value_digest)
            {
                return Err(integrity(
                    "repeated raw ciphertext observations disagree on their value",
                ));
            }
            if previous.is_none() {
                self.observed_count += 1;
            }
            if self.observed_count > 65_536 {
                return Err(exhausted(
                    "raw key inventory exceeds 65536 observed ciphertexts",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::raw_index) fn select(
        self,
        native: &NativeService,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RawFamilySelection> {
        let selected = native.select_key_allocations(self.addresses, budget)?;
        let mut observed = self.observed;
        let mut sources = self.sources;
        for ((source, address), allocations) in selected.owners {
            let versions = observed
                .remove(&(source, address.clone()))
                .unwrap_or_default();
            if let Some(usage) = &selected.native_use {
                let history = usage
                    .addresses
                    .get(&address)
                    .ok_or_else(|| integrity("observed raw address lost its native-use history"))?;
                let mut committed = BTreeSet::new();
                for change in &history.transitions {
                    budget.charge(1, 0).map_err(budget_error)?;
                    if change.transaction.outcome == crate::NativeKeyUseOutcome::Committed
                        && let Some(after) = &change.after
                    {
                        committed.insert((
                            after.key_id,
                            after.ciphertext_digest.as_str(),
                            after.value_digest.as_str(),
                        ));
                    }
                }
                for (version, value_digest) in versions.values() {
                    budget.charge(1, 0).map_err(budget_error)?;
                    if version.authority_id == selected.authority_id
                        && !committed.contains(&(
                            version.key_id,
                            version.ciphertext_digest.as_str(),
                            value_digest.as_str(),
                        ))
                    {
                        return Err(integrity(
                            "observed raw ciphertext differs from committed native use",
                        ));
                    }
                }
            }
            let observed_versions: Vec<NativeRawValueVersion> =
                versions.into_values().map(|(version, _)| version).collect();
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
        if !observed.is_empty() {
            return Err(integrity(
                "raw key observations lost their address families",
            ));
        }
        Ok(RawFamilySelection {
            native_use: selected.native_use,
            authority_id: selected.authority_id,
            revision: selected.revision,
            digest: selected.digest,
            sources,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_index::copies::tests::{budget, fixture, reclaim};

    #[test]
    fn raw_key_join_checks_ciphertext_and_value_against_committed_use() {
        let f = fixture();
        let receipt = reclaim(&f, 64).copies.expect("copy receipt");
        let witness = f
            .native
            .read_raw_copy_witness(&f.first.context, &receipt, &mut budget())
            .expect("retained observation");
        let original = witness
            .rows
            .into_iter()
            .find(|row| row.source == Some(f.first.event.event_id))
            .expect("selected row");
        for damage in ["none", "cipher", "value", "foreign"] {
            let mut row = original.clone();
            match damage {
                "cipher" => {
                    row.version.as_mut().expect("encrypted").ciphertext_digest = "0".repeat(64)
                }
                "value" => row.value_digest = "0".repeat(64),
                "foreign" => {
                    row.version.as_mut().expect("encrypted").authority_id = Uuid::from_u128(99)
                }
                _ => {}
            }
            let mut families = RawKeyFamilies::new(std::iter::once(f.first.event.event_id));
            families.observe(row).expect("observation input");
            let result = families.select(&f.native, &mut budget());
            if matches!(damage, "cipher" | "value") {
                assert!(
                    result.is_err(),
                    "allocated UUID alone must not validate {damage}"
                );
            } else {
                let report = result.expect("exact use or explicit foreign obligation");
                assert!(report.native_use.is_some());
                assert_eq!(
                    report.sources[&f.first.event.event_id][&original.address_digest]
                        .observed_versions
                        .len(),
                    1
                );
            }
        }
        let mut families = RawKeyFamilies::new(std::iter::once(f.first.event.event_id));
        families
            .observe(original.clone())
            .expect("first observation");
        let mut contradictory = original;
        contradictory.value_digest = "0".repeat(64);
        assert!(families.observe(contradictory).is_err());
    }
}
