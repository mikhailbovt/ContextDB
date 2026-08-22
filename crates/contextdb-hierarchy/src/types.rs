use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use contextdb_core::{
    CommitRange, CommitSeq, ContentDigest, DerivationRef, HierarchyViewId, LineageNode,
    MemorySpaceId, NodeId, ScopeRef, SnapshotRef, TimeRange, WorkspaceId,
};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{HierarchyError, Result};

const MAX_TEXT_BYTES: usize = 1_024;

/// Deterministic fixed-point confidence in basis points (`0..=10_000`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Confidence(u16);

impl Confidence {
    /// No confidence.
    pub const ZERO: Self = Self(0);
    /// Maximum confidence.
    pub const ONE: Self = Self(10_000);

    /// Creates a confidence value without floating-point ordering ambiguity.
    pub fn from_basis_points(value: u16) -> Result<Self> {
        if value > 10_000 {
            return Err(HierarchyError::InvalidConfidence(value));
        }
        Ok(Self(value))
    }

    /// Returns the stable basis-point representation.
    #[must_use]
    pub const fn basis_points(self) -> u16 {
        self.0
    }

    /// Multiplies two unit confidences using deterministic integer arithmetic.
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        let product = u32::from(self.0).saturating_mul(u32::from(other.0));
        let rounded = product.saturating_add(5_000) / 10_000;
        Self(u16::try_from(rounded).unwrap_or(10_000).min(10_000))
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::from_basis_points(value).map_err(serde::de::Error::custom)
    }
}

/// Immutable hierarchy generation number. Zero is reserved for no generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GenerationNumber(u64);

impl GenerationNumber {
    /// Creates a non-zero generation number.
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(HierarchyError::InvalidGeneration);
        }
        Ok(Self(value))
    }

    /// Returns the stable integer representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn checked_next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(HierarchyError::SequenceExhausted)
    }
}

impl<'de> Deserialize<'de> for GenerationNumber {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for GenerationNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Monotonic publication epoch of the hierarchy catalog, independent of the
/// primary semantic commit sequence.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct HierarchyEpoch(u64);

impl HierarchyEpoch {
    /// Empty hierarchy catalog.
    pub const GENESIS: Self = Self(0);

    /// Creates an epoch from its stable representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the stable integer representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn checked_next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(HierarchyError::SequenceExhausted)
    }
}

impl fmt::Display for HierarchyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Policy-partition fingerprint. Membership edges never cross fingerprints.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyPartitionId([u8; 32]);

impl PolicyPartitionId {
    /// Returns the canonical digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Exact authorization boundary used to shard derived hierarchy structure.
///
/// The identifier includes workspace, memory spaces, semantic scopes, and the
/// policy revision. A policy change therefore makes old cached structure
/// inaccessible until a newly authorized partition is supplied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPartition {
    /// Canonical boundary digest.
    pub id: PolicyPartitionId,
    /// Administrative isolation boundary.
    pub workspace_id: WorkspaceId,
    /// Memory-space filters applied before traversal.
    pub memory_spaces: BTreeSet<MemorySpaceId>,
    /// Semantic scope filters applied before traversal.
    pub scopes: BTreeSet<ScopeRef>,
    /// Policy revision used to derive this partition.
    pub policy_revision: CommitSeq,
}

impl PolicyPartition {
    /// Derives a canonical policy partition.
    pub fn new(
        workspace_id: WorkspaceId,
        memory_spaces: BTreeSet<MemorySpaceId>,
        scopes: BTreeSet<ScopeRef>,
        policy_revision: CommitSeq,
    ) -> Result<Self> {
        let id = partition_digest(workspace_id, &memory_spaces, &scopes, policy_revision)?;
        Ok(Self {
            id,
            workspace_id,
            memory_spaces,
            scopes,
            policy_revision,
        })
    }

    pub(crate) fn validate_digest(&self) -> Result<()> {
        let expected = partition_digest(
            self.workspace_id,
            &self.memory_spaces,
            &self.scopes,
            self.policy_revision,
        )?;
        if expected != self.id {
            return Err(HierarchyError::InvalidPolicyPartition);
        }
        Ok(())
    }
}

fn partition_digest(
    workspace_id: WorkspaceId,
    memory_spaces: &BTreeSet<MemorySpaceId>,
    scopes: &BTreeSet<ScopeRef>,
    policy_revision: CommitSeq,
) -> Result<PolicyPartitionId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-hierarchy-policy-partition-v1\0");
    hasher.update(workspace_id.as_uuid().as_bytes());
    hasher.update(&policy_revision.get().to_be_bytes());
    hasher.update(&serde_json::to_vec(memory_spaces)?);
    hasher.update(&[0]);
    hasher.update(&serde_json::to_vec(scopes)?);
    Ok(PolicyPartitionId(*hasher.finalize().as_bytes()))
}

/// Result of current policy evaluation supplied by the graph/policy adapter.
///
/// This is an input capability, not an authentication mechanism. Callers must
/// only construct it from an already authorized primary snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSnapshot {
    workspace_id: WorkspaceId,
    partitions: BTreeSet<PolicyPartitionId>,
    evaluated_at: CommitSeq,
}

impl AuthorizationSnapshot {
    /// Captures the exact policy partitions a principal may traverse.
    #[must_use]
    pub fn new(
        workspace_id: WorkspaceId,
        partitions: BTreeSet<PolicyPartitionId>,
        evaluated_at: CommitSeq,
    ) -> Self {
        Self {
            workspace_id,
            partitions,
            evaluated_at,
        }
    }

    /// Workspace for which authorization was evaluated.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Policy revision/watermark represented by this capability.
    #[must_use]
    pub const fn evaluated_at(&self) -> CommitSeq {
        self.evaluated_at
    }

    pub(crate) fn allows(&self, partition: PolicyPartitionId) -> bool {
        self.partitions.contains(&partition)
    }
}

/// Universal or domain-supplied navigation view kind.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HierarchyKind {
    /// Subject life periods, episodes, and evidence.
    Autobiographical,
    /// People, roles, relationships, and shared history.
    PeopleRelationships,
    /// Topics, concepts, claims, and knowledge sources.
    TopicsKnowledge,
    /// Calendar or domain-time organization.
    Time,
    /// Goals, commitments, open loops, and triggers.
    GoalsOpenLoops,
    /// Places and location-scoped activity.
    Places,
    /// Procedures, steps, and outcomes.
    Procedures,
    /// Projects, components, decisions, and artifacts.
    Projects,
    /// Source/document structure.
    KnowledgeSources,
    /// Domain extension whose label is a versioned API value, not a fact.
    Domain(String),
}

/// Precedence of evidence used for deterministic membership assignment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentSource {
    /// Model-generated proposal; never self-publishing.
    ModelProposal,
    /// Deterministic graph community or clustering result.
    DeterministicCommunity,
    /// Scope containment or membership.
    ScopeRelation,
    /// Typed semantic relation.
    TypedRelation,
    /// Explicit structure emitted by an adapter.
    AdapterStructure,
    /// Explicit human override, always above automatic assignments.
    ManualOverride,
}

impl AssignmentSource {
    pub(crate) const fn precedence(self) -> u8 {
        match self {
            Self::ModelProposal => 0,
            Self::DeterministicCommunity => 1,
            Self::ScopeRelation => 2,
            Self::TypedRelation => 3,
            Self::AdapterStructure => 4,
            Self::ManualOverride => 5,
        }
    }
}

/// Deterministic assignment thresholds. `max_parents = None` is the default;
/// callers must opt into a bound rather than accidentally collapsing a DAG to a
/// tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentPolicy {
    /// Minimum membership confidence retained.
    pub minimum_confidence: Confidence,
    /// Optional explicit per-child cap after deterministic ordering.
    pub max_parents: Option<u16>,
    /// Mark the strongest retained path primary for cheaper navigation while
    /// preserving every other retained parent as an alternative.
    pub select_primary: bool,
}

impl Default for AssignmentPolicy {
    fn default() -> Self {
        Self {
            minimum_confidence: Confidence::ZERO,
            max_parents: None,
            select_primary: true,
        }
    }
}

/// Stable digest-derived identity for a view-local synthetic navigation branch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HierarchyBranchId([u8; 32]);

impl HierarchyBranchId {
    /// Derives an identity from view, policy boundary, and a caller-stable key.
    pub fn derive(
        view_id: HierarchyViewId,
        partition: PolicyPartitionId,
        stable_key: &str,
    ) -> Result<Self> {
        validate_text(stable_key, "hierarchy_branch.stable_key")?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"contextdb-hierarchy-branch-v1\0");
        hasher.update(view_id.as_uuid().as_bytes());
        hasher.update(&partition.0);
        hasher.update(stable_key.as_bytes());
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    /// Restores an already validated stable digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns stable digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A canonical semantic item or a synthetic view-local navigation branch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum HierarchyItemId {
    /// Stable primary graph identity.
    Semantic(NodeId),
    /// Rebuildable navigation-only branch.
    Branch(HierarchyBranchId),
}

/// Domain and transaction validity inherited from primary dependencies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyValidity {
    /// Optional domain-time visibility.
    pub valid_time: Option<TimeRange>,
    /// Semantic snapshots for which the dependency revision is visible.
    pub transaction_time: CommitRange,
}

impl HierarchyValidity {
    /// A projection item current from one primary commit onward.
    #[must_use]
    pub const fn current_from(commit_seq: CommitSeq) -> Self {
        Self {
            valid_time: None,
            transaction_time: CommitRange::current(commit_seq),
        }
    }

    pub(crate) fn visible_at(
        self,
        semantic_snapshot: SnapshotRef,
        domain_time: Option<contextdb_core::TimestampMicros>,
    ) -> bool {
        self.transaction_time.contains(semantic_snapshot.commit_seq)
            && domain_time.is_none_or(|instant| {
                self.valid_time
                    .is_none_or(|valid_time| valid_time.contains(instant))
            })
    }
}

/// Explainable source and rationale for a derived hierarchy item or edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyProvenance {
    /// Precedence class used by deterministic assignment.
    pub source: AssignmentSource,
    /// Core lineage and versioned builder identity.
    pub derivation: DerivationRef,
    /// Bounded explanation of why this projection item exists.
    pub rationale: String,
}

/// One node in a view generation. A label is navigational metadata, not a
/// canonical name or semantic assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyNode {
    /// Semantic or view-local identity.
    pub id: HierarchyItemId,
    /// Policy-safe navigational label.
    pub label: String,
    /// Exact authorization shard.
    pub partition: PolicyPartitionId,
    /// Fixed-point assignment/summary confidence.
    pub confidence: Confidence,
    /// Inherited source validity.
    pub validity: HierarchyValidity,
    /// Explainable derivation.
    pub provenance: HierarchyProvenance,
}

/// Optional primary path versus preserved alternative path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    /// Cheap default route. It does not imply canonical truth.
    Primary,
    /// Equally valid overlapping navigation route.
    Alternative,
}

/// Directed parent-to-child membership in one hierarchy-view DAG.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyMembership {
    /// Parent navigation item.
    pub parent: HierarchyItemId,
    /// Child navigation item.
    pub child: HierarchyItemId,
    /// Primary or preserved alternative route.
    pub role: MembershipRole,
    /// Stable ordering among siblings.
    pub order_key: u64,
    /// Membership confidence.
    pub confidence: Confidence,
    /// Inherited source validity.
    pub validity: HierarchyValidity,
    /// Explainable derivation.
    pub provenance: HierarchyProvenance,
}

/// Versioned configuration for one hierarchy-view family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyProfile {
    /// Stable view identity across rebuilds.
    pub id: HierarchyViewId,
    /// Administrative isolation boundary.
    pub workspace_id: WorkspaceId,
    /// Universal or domain-supplied view kind.
    pub kind: HierarchyKind,
    /// Human-readable navigation label.
    pub name: String,
    /// Version of profile/builder configuration.
    pub profile_revision: u64,
    /// Exact policy shards from which this view may be assembled.
    pub partitions: BTreeMap<PolicyPartitionId, PolicyPartition>,
    /// Deterministic assignment rules.
    pub assignment: AssignmentPolicy,
}

/// Side-by-side build proposal. It is not query-visible until validated and
/// atomically published by a repository.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyProposal {
    /// View profile used for the build.
    pub profile: HierarchyProfile,
    /// Proposed immutable generation number.
    pub generation: GenerationNumber,
    /// Optimistic active generation observed when the build started.
    pub expected_active: Option<GenerationNumber>,
    /// Primary semantic snapshot completely covered by the build.
    pub built_from: SnapshotRef,
    /// Explicit roots; validation compares them with DAG-computed roots.
    pub roots: BTreeSet<HierarchyItemId>,
    /// All generation items.
    pub nodes: BTreeMap<HierarchyItemId, HierarchyNode>,
    /// Parent-child memberships; validation canonicalizes their order.
    pub memberships: Vec<HierarchyMembership>,
    /// Provenance of the build itself.
    pub build_provenance: HierarchyProvenance,
}

/// Proposal whose schema, policy partitions, roots, validity, provenance, and
/// acyclicity were checked. Fields remain private so validation cannot be
/// bypassed before publication.
#[derive(Clone, Debug)]
pub struct ValidatedHierarchyProposal {
    pub(crate) proposal: HierarchyProposal,
    pub(crate) digest: ContentDigest,
    pub(crate) statistics: BTreeMap<HierarchyItemId, BranchStatistics>,
}

impl ValidatedHierarchyProposal {
    /// Stable digest over the canonicalized validated proposal.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Strongly typed generation-manifest digest consumed by the future
    /// ordered maintenance publication adapter.
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.digest
    }

    /// Validated view identity.
    #[must_use]
    pub const fn view_id(&self) -> HierarchyViewId {
        self.proposal.profile.id
    }

    /// Proposed generation.
    #[must_use]
    pub const fn generation(&self) -> GenerationNumber {
        self.proposal.generation
    }

    /// Covered semantic snapshot.
    #[must_use]
    pub const fn built_from(&self) -> SnapshotRef {
        self.proposal.built_from
    }
}

/// Deterministic, content-free branch summary safe to rebuild without an LLM.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchStatistics {
    /// Direct outgoing memberships.
    pub direct_children: u64,
    /// Unique reachable descendants.
    pub unique_descendants: u64,
    /// Unique reachable leaves.
    pub leaf_descendants: u64,
    /// Longest downward path in edges.
    pub max_depth: u32,
    /// Number of distinct root-to-item routes, saturating at `u64::MAX`.
    pub routes_from_roots: u64,
}

/// Immutable generation published into a hierarchy snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyGeneration {
    /// View profile used to build this generation.
    pub profile: HierarchyProfile,
    /// Immutable generation number.
    pub generation: GenerationNumber,
    /// Primary semantic watermark.
    pub built_from: SnapshotRef,
    /// Atomic hierarchy publication epoch.
    pub published_epoch: HierarchyEpoch,
    /// Roots of this DAG.
    pub roots: BTreeSet<HierarchyItemId>,
    /// Generation items.
    pub nodes: BTreeMap<HierarchyItemId, HierarchyNode>,
    /// Canonically ordered memberships.
    pub memberships: Vec<HierarchyMembership>,
    /// Deterministic branch statistics.
    pub statistics: BTreeMap<HierarchyItemId, BranchStatistics>,
    /// Domain-separated canonical generation-manifest digest.
    pub manifest_digest: ContentDigest,
    /// Build provenance.
    pub build_provenance: HierarchyProvenance,
}

impl HierarchyGeneration {
    /// Revalidates a generation loaded by a persistent adapter and checks its
    /// domain-separated manifest digest and deterministic statistics.
    pub fn verify_manifest(&self) -> Result<()> {
        if self.published_epoch == HierarchyEpoch::GENESIS {
            return Err(HierarchyError::ManifestMismatch);
        }
        let expected_active = if self.generation.get() == 1 {
            None
        } else {
            Some(GenerationNumber::new(
                self.generation.get().saturating_sub(1),
            )?)
        };
        let validated = crate::validate_proposal(HierarchyProposal {
            profile: self.profile.clone(),
            generation: self.generation,
            expected_active,
            built_from: self.built_from,
            roots: self.roots.clone(),
            nodes: self.nodes.clone(),
            memberships: self.memberships.clone(),
            build_provenance: self.build_provenance.clone(),
        })?;
        if validated.manifest_digest() != self.manifest_digest
            || validated.statistics != self.statistics
        {
            return Err(HierarchyError::ManifestMismatch);
        }
        Ok(())
    }
}

/// Stable reference returned after atomic generation publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyGenerationRef {
    /// View identity.
    pub view_id: HierarchyViewId,
    /// Immutable generation.
    pub generation: GenerationNumber,
    /// Hierarchy catalog epoch at publication.
    pub published_epoch: HierarchyEpoch,
    /// Covered primary semantic snapshot.
    pub built_from: SnapshotRef,
    /// Validated generation-manifest digest. This is directly compatible with
    /// `MaintenanceOperation::HierarchyPublication.manifest_digest`.
    pub manifest_digest: ContentDigest,
}

/// Why a view or region requires maintenance.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    /// Primary node/edge/claim revision changed.
    SemanticRevision,
    /// Source adapter reported rename, move, or reorganization.
    AdapterStructureChanged,
    /// Policy boundary changed.
    PolicyChanged,
    /// A semantic dependency was deleted.
    Deletion,
    /// Summary coverage or statistics became stale.
    SummaryStale,
    /// Manual hierarchy override changed.
    ManualOverride,
    /// Domain-specific maintenance trigger.
    Domain(String),
}

/// Immutable invalidation event; it marks a generation stale but never mutates
/// it in place.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyInvalidation {
    /// View requiring rebuild.
    pub view_id: HierarchyViewId,
    /// Workspace isolation boundary.
    pub workspace_id: WorkspaceId,
    /// Semantic watermark that a replacement must cover.
    pub dirty_through: CommitSeq,
    /// Maintenance reason.
    pub reason: InvalidationReason,
    /// Optional affected navigation items. Empty means whole view.
    pub affected_items: BTreeSet<HierarchyItemId>,
}

/// Current deletion barrier applied to every hierarchy snapshot, including
/// historical semantic snapshots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionRecord {
    /// Workspace isolation boundary.
    pub workspace_id: WorkspaceId,
    /// Deleted canonical semantic nodes.
    pub node_ids: BTreeSet<NodeId>,
    /// Exact non-node lineage dependencies (claim/edge/evidence revisions and
    /// similar inputs) whose derived hierarchy output must be closed. Node
    /// deletion should normally use `node_ids` so every revision is covered.
    #[serde(default)]
    pub lineage_dependencies: BTreeSet<LineageNode>,
    /// Commit at which deletion became effective.
    pub effective_at: CommitSeq,
}

/// Selects an immutable hierarchy catalog snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HierarchySnapshotSelector {
    /// Most recently published/invalidated catalog.
    Latest,
    /// Exact retained hierarchy epoch.
    At(HierarchyEpoch),
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(HierarchyError::InvalidText {
            field,
            reason: "must not be blank",
        });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(HierarchyError::InvalidText {
            field,
            reason: "exceeds 1024 UTF-8 bytes",
        });
    }
    Ok(())
}
