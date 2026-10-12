//! One immutable owner-published ANN base for exact native policy cohorts.

use super::*;
use contextdb_core::{Modality, RepresentationId, TimestampMicros};
use contextdb_index::{AnnAlgorithmV2, AnnBuildParametersV2, AnnPartitionSchemeV2};
use contextdb_index::{AnnPartitionManifestV2, VectorMetric, VectorSpace};

mod publication;
mod query;
#[cfg(test)]
mod tests;
mod verification;

pub(crate) const FEATURE: &str = "continuous-raw-span-ann-v1";
pub(crate) const OPERATION: &str = "raw_span_ann";
const MAX_NODES: usize = 4096;
const MAX_COHORTS: usize = 64;
const ROW_BYTES: usize = 128 * 1024;
const RECEIPT_MAC: &[u8] = b"contextdb.native-span-ann-receipt.v1\0";
const MEMBER_MAC: &[u8] = b"contextdb.native-span-ann-member.v1\0";
const COHORT_MAC: &[u8] = b"contextdb.native-span-ann-cohort.v1\0";
const NODE_MAC: &[u8] = b"contextdb.native-span-ann-node.v1\0";

/// Frozen ANN base; advancement requires a new raw generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenseGraphManifest {
    pub(crate) revision: u16,
    pub(crate) generation: u64,
    pub(crate) source_generation_digest: String,
    pub(crate) source_generation: Vec<u8>,
    pub(crate) dense: DenseManifest,
    pub(crate) authorization_epoch: u64,
    pub(crate) builder_revision: String,
    pub(crate) nodes: u64,
    pub(crate) cohorts: Vec<GraphCohortSummary>,
    pub(crate) content_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphCohortSummary {
    pub(crate) policy_domain: String,
    pub(crate) partition_digest: ContentDigest,
    pub(crate) nodes: u64,
}

/// Synchronized owner declaration; graph quality and physical erasure are separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenseGraphReceipt {
    /// Native database identity.
    pub database_id: String,
    /// Workspace whose complete finite graph input was admitted.
    pub workspace_id: String,
    /// Full immutable graph contract and final content commitment.
    pub manifest: DenseGraphManifest,
    /// Actual native owner publication position.
    pub global_commit: u64,
    /// Native owner authentication over all preceding fields.
    pub token: String,
}

/// Source-owned exact member lookup. Its UUID is also checked against full hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphMember {
    pub(crate) representation_id: RepresentationId,
    pub(crate) identity_digest: ContentDigest,
    pub(crate) source: RawSource,
    pub(crate) event_digest: ContentDigest,
    pub(crate) commit: u64,
    pub(crate) ordinal: u32,
    pub(crate) span: OriginalSourceSpan,
    pub(crate) policy_domain: String,
    pub(crate) profile_digest: ContentDigest,
    pub(crate) vector_digest: ContentDigest,
    pub(crate) graph_digest: ContentDigest,
    pub(crate) token: String,
}

/// Shared cohort restriction and canonical portable partition, never IndexPolicy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphCohort {
    pub(crate) policy_domain: String,
    pub(crate) policies: Vec<AccessPolicy>,
    pub(crate) partition: Vec<u8>,
    pub(crate) graph_digest: ContentDigest,
    pub(crate) token: String,
}

/// Shared topology; neighbors derive from multiple sources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GraphNode {
    pub(crate) representation_id: RepresentationId,
    pub(crate) policy_domain: String,
    pub(crate) canonical_node: Vec<u8>,
    pub(crate) graph_digest: ContentDigest,
    pub(crate) token: String,
}

/// Operation-wide local traversal caps, independent of the parent byte/deadline budget.
#[derive(Clone, Copy, Debug)]
pub struct DenseGraphQueryLimits {
    /// Maximum returned exact span observations.
    pub limit: usize,
    /// Total node reads across admitted cohorts.
    pub max_node_reads: usize,
    /// Total materialized vectors across admitted cohorts.
    pub max_vector_reads: usize,
    /// Total discovered identities across admitted cohorts.
    pub max_discovered: usize,
    /// Per-cohort best-first beam, bounded by remaining operation limits.
    pub ef_search: usize,
}

/// Approximate discovery with authenticated source attribution, not truth or a lease.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DenseGraphHit {
    /// Exact owner representation.
    pub representation_id: RepresentationId,
    /// Authentic immutable captured source.
    pub source: RawSource,
    /// Exact byte range in that complete original.
    pub span: OriginalSourceSpan,
    /// Exact finite score for this visited full-dimensional vector.
    pub score: f32,
}

/// Point-only observations. Complete traversal never means exhaustive recall.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DenseGraphQueryResult {
    /// Source-span observations in descending score order.
    pub hits: Vec<DenseGraphHit>,
    /// Portable local cap status; owner failures discard the whole result.
    pub completion: contextdb_index::AnnPartitionQueryCompletionV2,
    /// Actual point node reads across admitted cohorts.
    pub node_reads: u64,
    /// Actual full-vector reads across admitted cohorts.
    pub vector_reads: u64,
    /// Actual distinct discoveries across admitted cohorts.
    pub discovered: u64,
    /// Authenticated graph base used; no default runtime activation follows.
    pub graph_digest: ContentDigest,
}

pub(crate) fn graph_prefix(workspace: &str, generation: u64) -> Vec<u8> {
    format!("{}dense/graph/", generation_prefix(workspace, generation)).into_bytes()
}
pub(crate) fn receipt_key(workspace: &str, generation: u64) -> Vec<u8> {
    format!(
        "{}receipt",
        String::from_utf8_lossy(&graph_prefix(workspace, generation))
    )
    .into_bytes()
}
pub(crate) fn member_key(workspace: &str, generation: u64, id: RepresentationId) -> Vec<u8> {
    format!(
        "{}member/{id}",
        String::from_utf8_lossy(&graph_prefix(workspace, generation))
    )
    .into_bytes()
}
pub(crate) fn cohort_key(workspace: &str, generation: u64, domain: &str) -> Vec<u8> {
    format!(
        "{}cohort/{domain}",
        String::from_utf8_lossy(&graph_prefix(workspace, generation))
    )
    .into_bytes()
}
pub(crate) fn node_key(workspace: &str, generation: u64, id: RepresentationId) -> Vec<u8> {
    format!(
        "{}node/{id}",
        String::from_utf8_lossy(&graph_prefix(workspace, generation))
    )
    .into_bytes()
}
fn source_generation_digest(generation: &Generation) -> ServiceResult<String> {
    let mut source = generation.clone();
    source.dense_graph = None;
    canonical_digest(&("native-span-ann-source-generation/v1", source))
}
fn vector_space(dense: &DenseManifest) -> VectorSpace {
    VectorSpace {
        id: dense.vector_space_id,
        dimensions: dense.profile.dimensions,
        metric: VectorMetric::Cosine,
        model_family: dense.profile.model_family.clone(),
        model_revision: dense.profile.model_revision.clone(),
        preprocessing_revision: dense.profile_digest.to_string(),
        modality: Modality::Text,
    }
}
fn portable_epoch(epoch: u64) -> ServiceResult<u64> {
    epoch
        .checked_add(1)
        .ok_or_else(|| exhausted("graph membership epoch overflow"))
}
fn identity(
    database: &str,
    workspace: &str,
    generation: u64,
    vector: &DenseVector,
) -> ServiceResult<(ContentDigest, RepresentationId)> {
    let full = digest(&encode(&(
        "native-span-ann-member/v1",
        database,
        workspace,
        generation,
        &vector.source,
        vector.event_digest,
        vector.commit,
        vector.ordinal,
        &vector.span,
        &vector.policy_domain,
        vector.profile_digest,
        vector.vector_digest,
    ))?);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&full.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 15) | 128;
    bytes[8] = (bytes[8] & 63) | 128;
    let id = RepresentationId::from_uuid(uuid::Uuid::from_bytes(bytes))
        .map_err(|_| integrity("graph representation identity invalid"))?;
    Ok((full, id))
}
fn ann_error(error: impl std::fmt::Display) -> ServiceError {
    integrity(format!("native graph contract: {error}"))
}

fn parameters() -> AnnBuildParametersV2 {
    AnnBuildParametersV2 {
        algorithm: AnnAlgorithmV2::DeterministicHnswV1,
        partition_scheme: AnnPartitionSchemeV2::ExactPolicyV1,
        max_level: 4,
        neighbours_per_level: 16,
        construction_max_visits: 256,
    }
}
impl DenseGraphManifest {
    fn validate(&self) -> ServiceResult<()> {
        self.dense.validate(self.dense.through)?;
        if self.revision != 1
            || self.generation == 0
            || self.builder_revision != contextdb_index::ANN_PARTITION_BUILD_REVISION_V2
            || self.nodes > MAX_NODES as u64
            || self.cohorts.len() > MAX_COHORTS
            || self.nodes != self.dense.spans
            || self.source_generation_digest.len() != 64
            || self.content_digest.as_bytes() == &[0; 32]
            || self
                .cohorts
                .windows(2)
                .any(|p| p[0].policy_domain >= p[1].policy_domain)
            || self
                .cohorts
                .iter()
                .any(|c| c.policy_domain.len() != 64 || c.nodes == 0 || c.nodes > MAX_NODES as u64)
            || self.cohorts.iter().map(|c| c.nodes).sum::<u64>() != self.nodes
        {
            return Err(integrity("native graph manifest contract differs"));
        }
        portable_epoch(self.authorization_epoch)?;
        Ok(())
    }
}
impl NativeService {
    fn graph_read<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        keyspace: &contextdb_storage::Keyspace,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<T>> {
        let bytes = crate::budgeted::read_value(snapshot, keyspace, key, ROW_BYTES, budget)?;
        bytes
            .map(|v| {
                budget.charge(1, v.len() as u64 * 2).map_err(budget_error)?;
                decode(&v, "native graph row")
            })
            .transpose()
    }
    fn graph_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        prefix: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<contextdb_storage::Entry>> {
        let mut rows = Vec::new();
        let mut after = None;
        loop {
            let cap = (budget.remaining_bytes().saturating_sub(256) / 4).min(512 * 1024) as usize;
            if cap < ROW_BYTES + prefix.len() + 128 {
                return Err(exhausted("native graph scan allowance exhausted"));
            }
            budget
                .charge(33, cap as u64 * 4 + 256)
                .map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix,
                        start_after: after.as_deref(),
                        max_entries: 32,
                        max_bytes: cap,
                    },
                )
                .map_err(storage_error)?;
            if rows.len() + page.entries.len() > 32768 {
                return Err(exhausted("native graph source census exceeds finite cap"));
            }
            rows.extend(page.entries);
            let Some(next) = page.continuation else { break };
            if after.as_ref().is_some_and(|p: &Vec<u8>| next <= *p) {
                return Err(integrity("native graph scan made no progress"));
            }
            after = Some(next);
        }
        Ok(rows)
    }
    fn graph_epoch<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<u64> {
        Ok(self
            .graph_read(
                snapshot,
                &self.keyspaces.continuous,
                &auth_key(workspace),
                budget,
            )?
            .unwrap_or_default())
    }
    fn require_graph_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let m: crate::Manifest = self
            .graph_read(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                budget,
            )?
            .ok_or_else(|| integrity("native graph format manifest absent"))?;
        crate::validate_manifest(&m, &self.database_id)?;
        if !m.features.contains(FEATURE) {
            return Err(integrity("native graph feature absent"));
        }
        Ok(())
    }
    fn sign_graph_receipt(&self, r: &mut DenseGraphReceipt) -> ServiceResult<()> {
        r.token.clear();
        r.token = crate::keyed_token(&self.token_key, RECEIPT_MAC, &encode(r)?);
        Ok(())
    }
    fn check_graph_receipt(&self, r: &DenseGraphReceipt) -> ServiceResult<()> {
        r.manifest.validate()?;
        let mut expected = r.clone();
        self.sign_graph_receipt(&mut expected)?;
        if r.database_id != self.database_id || r.global_commit == 0 || r.token != expected.token {
            return Err(integrity("native graph receipt authentication differs"));
        }
        Ok(())
    }
    fn graph_tag_allowance(
        &self,
        m: &DenseGraphManifest,
        row_bytes: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget
            .charge(
                m.cohorts.len() as u64 + 1,
                m.source_generation.len() as u64 * 8
                    + m.cohorts.len() as u64 * 1024
                    + 32768
                    + row_bytes * 4,
            )
            .map_err(budget_error)
    }
    fn graph_member_token(
        &self,
        m: &DenseGraphManifest,
        row: &GraphMember,
        budget: &mut QueryBudget,
    ) -> ServiceResult<String> {
        self.graph_tag_allowance(
            m,
            8192 + row
                .source
                .source_version
                .as_ref()
                .map_or(0, |s| s.len() as u64 * 6),
            budget,
        )?;
        let mut row = row.clone();
        row.token.clear();
        Ok(crate::keyed_token(
            &self.token_key,
            MEMBER_MAC,
            &encode(&(m, row))?,
        ))
    }
    fn graph_cohort_token(
        &self,
        m: &DenseGraphManifest,
        row: &GraphCohort,
        budget: &mut QueryBudget,
    ) -> ServiceResult<String> {
        self.graph_tag_allowance(m, ROW_BYTES as u64, budget)?;
        let mut row = row.clone();
        row.token.clear();
        Ok(crate::keyed_token(
            &self.token_key,
            COHORT_MAC,
            &encode(&(m, row))?,
        ))
    }
    fn graph_node_token(
        &self,
        m: &DenseGraphManifest,
        row: &GraphNode,
        budget: &mut QueryBudget,
    ) -> ServiceResult<String> {
        self.graph_tag_allowance(m, row.canonical_node.len() as u64 * 4 + 2048, budget)?;
        let mut row = row.clone();
        row.token.clear();
        Ok(crate::keyed_token(
            &self.token_key,
            NODE_MAC,
            &encode(&(m, row))?,
        ))
    }
}
