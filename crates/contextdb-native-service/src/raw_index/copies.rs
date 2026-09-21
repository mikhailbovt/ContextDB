//! Observed raw-index copies retained before logical generation reclamation.
//! These records do not establish unobserved history or authorize key retirement.

use super::*;
use uuid::Uuid;

pub(crate) mod discovery;
mod observe;
mod verify;
pub use discovery::{NativeRawRemovalCopy, NativeRawRemovalCopyPage};
pub(super) mod keys;
pub use keys::{NativeRawKeyFamily, NativeRawKeyInventory};

#[cfg(test)]
pub(crate) mod tests;

pub(crate) const MAX_WITNESS_BYTES: usize = 1024 * 1024;

/// Independent acceptance of a bounded page of observed raw-index copies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawCopyReceipt {
    /// Current independently retained suppression authority.
    pub authority_id: Uuid,
    /// Acceptance position in that authority, not a native commit.
    pub sequence: u64,
    /// Exact accepted journal commitment.
    pub digest: String,
}

/// A row's role in the observed generation. Shared metadata has no single owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRawCopyKind {
    /// Normalized words and spans from one captured original.
    Document,
    /// A route whose stored value identifies one captured original.
    Route,
    /// Generation-wide policy or scope routing metadata.
    SharedMetadata,
    /// The generation manifest at the observed snapshot.
    Manifest,
    /// Unrecognized row; its ownership remains unresolved.
    Unknown,
}

/// Exact ciphertext observed in a committed native snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawValueVersion {
    /// Independently retained key authority.
    pub authority_id: Uuid,
    /// Key named by the authenticated envelope. Legacy authorities reuse keys.
    pub key_id: Uuid,
    /// Commitment to this exact ciphertext, including nonce and authentication tag.
    pub ciphertext_digest: String,
}

/// Content-free evidence for one observed native row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawCopyObservation {
    /// Domain-separated hash of the native keyspace and row address.
    pub address_digest: String,
    /// Commitment to the decoded value; no value or normalized term is retained.
    pub value_digest: String,
    /// Known row role, or explicit unresolved ownership.
    pub kind: NativeRawCopyKind,
    /// Owner of a document/route. Shared and unknown rows have no single owner.
    pub source: Option<ObservationId>,
    /// Present only for encrypted native storage.
    pub version: Option<NativeRawValueVersion>,
}

/// Immutable capture controls for an observed document or route owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawSourceControl {
    /// Accepted workspace-local capture position.
    pub capture_commit: u64,
    /// Commitment to the complete original event.
    pub event_digest: ContentDigest,
    /// Commitment to its accepted capture/recovery control record.
    pub control_digest: ContentDigest,
}

/// Copies observed immediately before one logical reclamation page.
///
/// A witness survives native rollback. It proves observation, not that the later
/// native GC committed, that all historical versions were observed, or that any
/// physical copy/key was erased. A first page with `removed_before > 0` explicitly
/// lacks the earlier prefix. Generation numbers alone are not global identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawCopyWitness {
    /// Database containing the observed rows.
    pub database_id: String,
    /// Workspace of the observed generation.
    pub workspace_id: String,
    /// Native global commit of the observed snapshot.
    pub native_commit: u64,
    /// Native event digest distinguishes restored/forked commit histories.
    pub native_event_digest: String,
    /// Local generation number; use its manifest and native commitments together.
    pub generation: u64,
    /// Commitment to the generation manifest at observation.
    pub generation_digest: String,
    /// Rows already reclaimed before this page, excluding its manifest.
    pub removed_before: u64,
    /// Accepted witness for the preceding page, absent for untracked prefixes.
    pub previous: Option<NativeRawCopyReceipt>,
    /// Whether this scan reached the end, before the native deletion attempt.
    pub finished: bool,
    /// Exact source controls for the document/route owners on this page.
    pub sources: BTreeMap<ObservationId, NativeRawSourceControl>,
    /// At most 1024 generation rows plus its final manifest.
    pub rows: Vec<NativeRawCopyObservation>,
}

impl NativeRawCopyWitness {
    pub(crate) fn row_count(&self) -> u64 {
        self.rows
            .iter()
            .filter(|row| row.kind != NativeRawCopyKind::Manifest)
            .count() as u64
    }

    pub(crate) fn validate(&self, database: &str) -> ServiceResult<()> {
        let digests = [&self.native_event_digest, &self.generation_digest];
        if digest_bytes(self.database_id.as_bytes()) != database
            || self.workspace_id.is_empty()
            || self.native_commit == 0
            || self.generation == 0
            || self.row_count() > 1024
            || self.rows.is_empty()
            || self.rows.len() > 1025
            || self
                .rows
                .iter()
                .filter(|row| row.kind == NativeRawCopyKind::Manifest)
                .count()
                != usize::from(self.finished)
            || encode(self)?.len() > MAX_WITNESS_BYTES
            || digests
                .iter()
                .any(|digest| blake3::Hash::from_hex(digest).is_err())
        {
            return Err(integrity("raw copy witness binding or bound is invalid"));
        }
        validate_observed_rows(&self.sources, &self.rows)?;
        Ok(())
    }
}

impl NativeService {
    /// Read one independently retained observation page, including after native
    /// restore or source pruning. Admin authority for its workspace is required.
    pub fn read_raw_copy_witness(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRawCopyReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawCopyWitness> {
        require_capability(context, Capability::Admin)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("raw copy authority absent"))?;
        ledger.read_raw_copy_witness(
            receipt,
            &digest_bytes(context.request.workspace_id.as_bytes()),
            budget,
        )
    }
}

pub(in crate::raw_index) fn validate_observed_rows(
    sources: &BTreeMap<ObservationId, NativeRawSourceControl>,
    rows: &[NativeRawCopyObservation],
) -> ServiceResult<()> {
    let mut addresses = BTreeSet::new();
    let mut owners = BTreeSet::new();
    for row in rows {
        if !addresses.insert(&row.address_digest)
            || blake3::Hash::from_hex(&row.address_digest).is_err()
            || blake3::Hash::from_hex(&row.value_digest).is_err()
            || row.version.as_ref().is_some_and(|version| {
                version.authority_id.is_nil()
                    || version.key_id.is_nil()
                    || blake3::Hash::from_hex(&version.ciphertext_digest).is_err()
            })
            || row.source.is_some()
                != matches!(
                    row.kind,
                    NativeRawCopyKind::Document | NativeRawCopyKind::Route
                )
        {
            return Err(integrity("raw copy row binding differs"));
        }
        owners.extend(row.source);
    }
    if owners != sources.keys().copied().collect()
        || sources.values().any(|source| source.capture_commit == 0)
    {
        return Err(integrity("raw copy source controls differ"));
    }
    Ok(())
}
