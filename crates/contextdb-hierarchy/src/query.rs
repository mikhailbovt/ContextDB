use std::collections::BTreeSet;

use contextdb_core::{CommitSeq, HierarchyViewId, SnapshotRef, TimestampMicros};

use crate::{
    Confidence, HierarchyEpoch, HierarchyGenerationRef, HierarchyItemId, HierarchyMembership,
    HierarchyNode,
};

/// Whether a caller permits an explicitly marked stale hierarchy projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshnessRequirement {
    /// Reject a generation that does not cover the requested semantic snapshot
    /// or a recorded invalidation watermark.
    RequireCurrent,
    /// Return safe older structure with an explicit freshness report.
    AllowStale,
}

/// Relationship between a selected generation and the requested primary state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationFreshness {
    /// Generation primary-state watermark.
    pub covered_through: CommitSeq,
    /// Primary semantic snapshot requested by the caller.
    pub requested: CommitSeq,
    /// Latest invalidation watermark visible in the hierarchy snapshot.
    pub dirty_through: Option<CommitSeq>,
    /// True only when coverage and invalidation requirements are satisfied.
    pub current: bool,
}

/// Bounded request for deterministic root-to-target route materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRequest {
    /// View family.
    pub view_id: HierarchyViewId,
    /// Target semantic item or synthetic branch.
    pub target: HierarchyItemId,
    /// Primary state snapshot the recall operation uses.
    pub semantic_snapshot: SnapshotRef,
    /// Optional domain-time filter.
    pub domain_time: Option<TimestampMicros>,
    /// Maximum alternative root-to-target routes.
    pub max_routes: usize,
    /// Maximum edges in one route.
    pub max_depth: usize,
    /// Required projection freshness.
    pub freshness: FreshnessRequirement,
}

/// One policy-filtered, deletion-closed, snapshot-bound navigation route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HierarchyRoute {
    /// Published immutable generation.
    pub generation: HierarchyGenerationRef,
    /// Hierarchy catalog snapshot which materialized the route.
    pub hierarchy_epoch: HierarchyEpoch,
    /// Current deletion barrier epoch at materialization.
    pub deletion_epoch: HierarchyEpoch,
    /// Primary semantic snapshot.
    pub semantic_snapshot: SnapshotRef,
    /// Domain-time instant used when filtering temporal memberships.
    pub domain_time: Option<TimestampMicros>,
    /// Root-to-target ordered items.
    pub items: Vec<HierarchyItemId>,
    /// Policy-filtered navigation metadata for `items` in the same order.
    pub nodes: Vec<HierarchyNode>,
    /// Ordered memberships connecting adjacent items.
    pub memberships: Vec<HierarchyMembership>,
    /// Deterministic combined confidence.
    pub confidence: Confidence,
    /// Explicit projection freshness.
    pub freshness: GenerationFreshness,
    /// Tamper/staleness digest recomputed by route validation.
    pub integrity_digest: [u8; 32],
}

/// Bounded route materialization result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteMaterialization {
    /// Canonically ordered alternative routes.
    pub routes: Vec<HierarchyRoute>,
    /// True when route or depth budget stopped exhaustive enumeration.
    pub truncated: bool,
    /// Generation freshness shared by all routes.
    pub freshness: GenerationFreshness,
}

/// Bounded deterministic beam traversal request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeamTraversalRequest {
    /// View family.
    pub view_id: HierarchyViewId,
    /// Primary state snapshot.
    pub semantic_snapshot: SnapshotRef,
    /// Optional domain-time filter.
    pub domain_time: Option<TimestampMicros>,
    /// Empty means every authorized root; otherwise only declared roots here.
    pub roots: BTreeSet<HierarchyItemId>,
    /// Paths retained at each depth.
    pub beam_width: usize,
    /// Maximum hierarchy edges traversed.
    pub max_depth: usize,
    /// Hard bound on considered child expansions.
    pub max_expansions: usize,
    /// Required projection freshness.
    pub freshness: FreshnessRequirement,
}

/// One visible path reached by beam traversal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraversalHit {
    /// Current item.
    pub item: HierarchyItemId,
    /// Root-to-item route.
    pub path: Vec<HierarchyItemId>,
    /// Combined fixed-point confidence.
    pub confidence: Confidence,
    /// Number of traversed edges.
    pub depth: usize,
}

/// Beam traversal output with hard-budget accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeamTraversalResult {
    /// Deterministically ordered visible hits.
    pub hits: Vec<TraversalHit>,
    /// Number of candidate child memberships examined.
    pub expansions: usize,
    /// True when depth, beam, or expansion budget stopped traversal.
    pub truncated: bool,
    /// Explicit projection freshness.
    pub freshness: GenerationFreshness,
    /// Selected immutable generation.
    pub generation: HierarchyGenerationRef,
}
