//! Independent observations of rows in retained generations, before reclamation.
//! Finishing this scan does not prove missing historical copies absent or erase
//! anything. Its separate acceptance cannot be mistaken for a native GC receipt.

use super::*;
use crate::NativeRemovalRequestReceipt;
use uuid::Uuid;

mod keys;
mod page;
pub use keys::NativeRawIndexKeyInventory;
#[cfg(test)]
pub(crate) mod tests;

/// Role recorded in the observed native index state, not query admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRawGenerationRole {
    /// The state's active generation, possibly awaiting an authorization rebuild.
    Active,
    /// The state's unfinished build.
    Building,
    /// An older retained generation.
    Retained,
    /// An unreachable generation being reclaimed.
    Reclaiming,
}

/// A retained generation and its exact observed manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawIndexGeneration {
    /// Local generation number; not a global identity.
    pub number: u64,
    /// Hash of the manifest bytes at this snapshot.
    pub manifest_digest: String,
    /// Role at this snapshot.
    pub role: NativeRawGenerationRole,
    /// Reclaimed prefix outside this scan, including any untracked older pages.
    pub removed_before: u64,
    /// Most recent independently retained reclamation observation, when present.
    pub reclamation: Option<NativeRawCopyReceipt>,
}

/// The immutable identity required across all pages of one native inspection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawIndexSnapshot {
    /// Global native commit; event commitment disambiguates restored histories.
    pub native_commit: u64,
    /// Accepted native event commitment, or an explicit empty-history commitment.
    pub native_event_digest: String,
    /// Commitment to the optional complete index state, including GC progress.
    pub state_digest: String,
    /// All retained manifests, in ascending generation order.
    pub generations: Vec<NativeRawIndexGeneration>,
}

/// Independent acceptance of an inspection page; never a deletion receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawIndexInventoryReceipt {
    /// Independently retained removal authority.
    pub authority_id: Uuid,
    /// Acceptance position in that authority.
    pub sequence: u64,
    /// Exact accepted journal commitment.
    pub digest: String,
}

/// Present rows observed for an exact removal request. All source controls are
/// retained, including independent owners, so later selection remains verifiable.
/// Shared and unknown rows have no invented owner. This is not proof of complete
/// native-use history, expected projection coverage, physical absence or erasure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawIndexInventoryWitness {
    /// Native database identity.
    pub database_id: String,
    /// Authorized workspace identity.
    pub workspace_id: String,
    /// Exact independently retained removal request.
    pub request: NativeRemovalRequestReceipt,
    /// Snapshot shared by the entire page chain.
    pub snapshot: NativeRawIndexSnapshot,
    /// Index into the snapshot's retained generation list; zero for an empty list.
    pub generation_index: u32,
    /// Number of generation rows in preceding inspection pages, excluding manifests.
    pub rows_before: u64,
    /// Requested page bound; part of the retry identity.
    pub max_rows: u32,
    /// Address commitment after which this page started; no raw cursor key retained.
    pub after_digest: Option<String>,
    /// Last generation-row address commitment, excluding the manifest.
    pub last_digest: Option<String>,
    /// Previous page in this exact inspection, possibly from the preceding generation.
    pub previous: Option<NativeRawIndexInventoryReceipt>,
    /// The page reached the end of its generation at this snapshot.
    pub generation_finished: bool,
    /// The page reached the last retained generation, or there were none.
    pub finished: bool,
    /// Exact capture identity for every source-owned observed row.
    pub sources: BTreeMap<ObservationId, NativeRawSourceControl>,
    /// At most max_rows present generation rows, plus its manifest on the final page.
    pub rows: Vec<NativeRawCopyObservation>,
}

/// One durably retained inspection page and an opaque continuation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawIndexInventoryPage {
    /// Independent acceptance, retained even if acknowledgement is lost.
    pub receipt: NativeRawIndexInventoryReceipt,
    /// Accepted observation metadata without source payloads or raw row keys.
    pub witness: NativeRawIndexInventoryWitness,
    /// Encrypted continuation bound to caller, request, snapshot and token key.
    /// Native changes require restarting; retained old observations remain readable.
    pub continuation: Option<String>,
}

impl NativeRawIndexInventoryWitness {
    pub(crate) fn row_count(&self) -> u64 {
        self.rows
            .iter()
            .filter(|row| row.kind != NativeRawCopyKind::Manifest)
            .count() as u64
    }

    pub(crate) fn identity_digest(&self) -> ServiceResult<String> {
        canonical_digest(&(
            "contextdb/raw-index-inventory/v1",
            &self.request,
            &self.snapshot,
            self.generation_index,
            self.rows_before,
            self.max_rows,
            &self.after_digest,
            &self.previous,
        ))
    }

    pub(crate) fn validate(&self, database: &str) -> ServiceResult<()> {
        let generations = &self.snapshot.generations;
        let empty = generations.is_empty();
        let manifests = self
            .rows
            .iter()
            .filter(|row| row.kind == NativeRawCopyKind::Manifest)
            .count();
        if digest_bytes(self.database_id.as_bytes()) != database
            || self.workspace_id.is_empty()
            || (self.snapshot.native_commit == 0 && !empty)
            || !(1..=1024).contains(&self.max_rows)
            || generations.len() > MAX_GENERATIONS as usize
            || (!empty && self.generation_index as usize >= generations.len())
            || self.row_count() > u64::from(self.max_rows)
            || self.rows.len() > 1025
            || encode(self)?.len() > copies::MAX_WITNESS_BYTES
            || manifests != usize::from(self.generation_finished && !empty)
            || self.finished
                != (self.generation_finished
                    && (empty || self.generation_index as usize + 1 == generations.len()))
            || (empty
                && (self.generation_index != 0
                    || self.rows_before != 0
                    || !self.rows.is_empty()
                    || !self.finished))
            || (!self.generation_finished && self.row_count() == 0)
            || (self.rows_before == 0) != self.after_digest.is_none()
            || self.last_digest.as_ref()
                != self
                    .rows
                    .iter()
                    .rev()
                    .find(|row| row.kind != NativeRawCopyKind::Manifest)
                    .map(|row| &row.address_digest)
            || (self.previous.is_none() && (self.generation_index != 0 || self.rows_before != 0))
            || generations
                .windows(2)
                .any(|pair| pair[0].number >= pair[1].number)
            || generations.iter().any(|generation| {
                generation.number == 0
                    || (generation.role != NativeRawGenerationRole::Reclaiming
                        && (generation.removed_before != 0 || generation.reclamation.is_some()))
            })
        {
            return Err(integrity(
                "raw index inspection binding or bound is invalid",
            ));
        }
        for digest in std::iter::once(&self.snapshot.native_event_digest)
            .chain(std::iter::once(&self.snapshot.state_digest))
            .chain(
                generations
                    .iter()
                    .map(|generation| &generation.manifest_digest),
            )
            .chain(self.after_digest.iter())
            .chain(self.last_digest.iter())
        {
            if blake3::Hash::from_hex(digest).is_err() {
                return Err(integrity("raw index inspection digest is invalid"));
            }
        }
        if self.snapshot.native_commit == 0
            && self.snapshot.native_event_digest
                != canonical_digest(&("contextdb/raw-index-empty-history/v1", &self.database_id))?
        {
            return Err(integrity(
                "raw index inspection empty-history commitment differs",
            ));
        }
        if let Some(generation) = generations.get(self.generation_index as usize) {
            for row in self
                .rows
                .iter()
                .filter(|row| row.kind == NativeRawCopyKind::Manifest)
            {
                let space = crate::keyspace("contextdb_native_continuous")?;
                let address = crate::encryption::address(
                    &space,
                    &generation_key(
                        &digest_bytes(self.workspace_id.as_bytes()),
                        generation.number,
                    ),
                );
                if row.value_digest != generation.manifest_digest || row.address_digest != address {
                    return Err(integrity(
                        "raw index inspection manifest observation differs",
                    ));
                }
            }
        }
        copies::validate_observed_rows(&self.sources, &self.rows)
    }
}
