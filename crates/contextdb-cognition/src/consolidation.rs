use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    ClaimId, ContentDigest, DerivedWorkItem, LineageNode, MaintenanceMutationSet, NodeId,
    SemanticEnvelope, SnapshotRef, SummaryId, TimeRange,
};
use serde::{Deserialize, Serialize};

/// Why a bounded semantic region needs derived maintenance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirtyReason {
    NodeChanged,
    ClaimChanged,
    ConflictChanged,
    TypedMemoryChanged,
    Correction,
    SummaryDependencyChanged,
    ReflectionCandidate,
}

/// Snapshot-bound local consolidation unit. It is a work descriptor, not
/// primary truth and never implies a workspace-wide scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirtyRegion {
    pub based_on: SnapshotRef,
    pub roots: BTreeSet<NodeId>,
    pub claims: BTreeSet<ClaimId>,
    pub reasons: BTreeSet<DirtyReason>,
}

impl DirtyRegion {
    /// Converts a region into deterministic core outbox descriptors.
    #[must_use]
    pub fn derived_work(&self) -> Vec<DerivedWorkItem> {
        if self.roots.is_empty() && self.claims.is_empty() {
            return Vec::new();
        }
        let roots: Vec<_> = self.roots.iter().copied().collect();
        let claims: Vec<_> = self.claims.iter().copied().collect();
        let mut work = vec![
            DerivedWorkItem::LexicalIndex {
                node_ids: roots.clone(),
                claim_ids: claims,
            },
            DerivedWorkItem::UpdateFilterBitmaps {
                nodes: roots.clone(),
            },
            DerivedWorkItem::DirtyHierarchyRegion {
                roots: roots.clone(),
            },
            DerivedWorkItem::InvalidateSummaries {
                nodes: roots.clone(),
            },
            DerivedWorkItem::Consolidate {
                roots: roots.clone(),
            },
        ];
        if !roots.is_empty() {
            work.insert(1, DerivedWorkItem::Vectorize { nodes: roots });
        }
        work
    }
}

/// Validated summary materialization plan. A later maintenance coordinator may
/// persist it, but it is never evidence independent of `sources`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedSummary {
    pub id: SummaryId,
    pub owner: NodeId,
    pub level: u8,
    pub content: serde_json::Value,
    pub sources: Vec<LineageNode>,
    pub source_digest: ContentDigest,
    pub covered_time: TimeRange,
    pub known_omissions: Vec<String>,
    pub envelope: SemanticEnvelope,
    pub freshness: SummaryFreshness,
    /// Ordered publication record for the derived summary generation. The
    /// content and full lineage remain in this validated plan.
    pub publication: MaintenanceMutationSet,
}

/// Summary freshness is explicit; stale materializations remain available for
/// historical replay but are excluded from current selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SummaryFreshness {
    Current,
    Stale { invalidated_at: SnapshotRef },
}

/// In-memory reference catalogue for dependency invalidation semantics.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SummaryCatalog(pub BTreeMap<SummaryId, ValidatedSummary>);

impl SummaryCatalog {
    /// Marks only summaries whose owner or source revisions intersect a dirty
    /// region. Existing summary IDs and content are retained.
    pub fn invalidate(&mut self, region: &DirtyRegion, at: SnapshotRef) -> Vec<SummaryId> {
        let mut invalidated = Vec::new();
        for summary in self.0.values_mut() {
            let affected = region.roots.contains(&summary.owner)
                || summary.sources.iter().any(|source| match source {
                    LineageNode::NodeRevision { id, .. } => region.roots.contains(id),
                    LineageNode::ClaimRevision { id, .. } => region.claims.contains(id),
                    _ => false,
                });
            if affected && summary.freshness == SummaryFreshness::Current {
                summary.freshness = SummaryFreshness::Stale { invalidated_at: at };
                invalidated.push(summary.id);
            }
        }
        invalidated
    }

    /// Iterates only summaries safe for current recall.
    pub fn current(&self) -> impl Iterator<Item = &ValidatedSummary> {
        self.0
            .values()
            .filter(|summary| summary.freshness == SummaryFreshness::Current)
    }
}

/// Validated reflective output. Publication, when requested, must preserve the
/// hypothesis epistemic basis; this record cannot be upgraded to fact by score.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternHypothesis {
    pub node_id: NodeId,
    pub label: String,
    pub hypothesis: String,
    pub supporting_evidence: Vec<contextdb_core::EvidenceId>,
    pub negative_evidence: Vec<contextdb_core::EvidenceId>,
    pub required_verification: Vec<String>,
    pub envelope: SemanticEnvelope,
}

/// Computes a stable summary dependency digest from ordered lineage sources.
pub fn summary_source_digest(sources: &[LineageNode]) -> ContentDigest {
    let mut ordered = sources.to_vec();
    ordered.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-summary-sources-v1\0");
    for source in ordered {
        let encoded = serde_json::to_vec(&source).unwrap_or_default();
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(&encoded);
    }
    ContentDigest::from_bytes(*hasher.finalize().as_bytes())
}
