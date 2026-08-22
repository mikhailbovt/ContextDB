use contextdb_core::{CommitSeq, HierarchyViewId, LineageNode, NodeId, WorkspaceId};
use thiserror::Error;

use crate::{GenerationNumber, HierarchyEpoch, HierarchyItemId, PolicyPartitionId};

/// Hierarchy proposal, publication, snapshot, policy, and traversal failures.
#[derive(Debug, Error)]
pub enum HierarchyError {
    /// Human-readable identifiers and rationales must be bounded and non-blank.
    #[error("invalid {field}: {reason}")]
    InvalidText {
        /// Contract field.
        field: &'static str,
        /// Sanitized reason.
        reason: &'static str,
    },
    /// A fixed-point confidence was outside the supported unit interval.
    #[error("confidence basis points {0} exceed 10000")]
    InvalidConfidence(u16),
    /// Generation numbers start at one.
    #[error("hierarchy generation must be greater than zero")]
    InvalidGeneration,
    /// A profile contains no policy partitions.
    #[error("hierarchy profile must declare at least one policy partition")]
    EmptyPolicyPartitions,
    /// A policy partition digest does not match its authorization boundary.
    #[error("policy partition identifier does not match its canonical boundary")]
    InvalidPolicyPartition,
    /// A node references a policy partition outside its view profile.
    #[error("hierarchy item {item:?} references unknown policy partition {partition:?}")]
    UnknownPolicyPartition {
        /// Hierarchy item.
        item: HierarchyItemId,
        /// Missing partition.
        partition: PolicyPartitionId,
    },
    /// The proposal repeats an item identity.
    #[error("duplicate hierarchy item {0:?}")]
    DuplicateItem(HierarchyItemId),
    /// A map key does not match the embedded item identity.
    #[error("hierarchy node map key does not match embedded item identity")]
    ItemKeyMismatch,
    /// The proposal repeats a parent-child membership.
    #[error("duplicate hierarchy membership {parent:?} -> {child:?}")]
    DuplicateMembership {
        /// Parent item.
        parent: HierarchyItemId,
        /// Child item.
        child: HierarchyItemId,
    },
    /// A membership endpoint does not exist in the proposal.
    #[error("hierarchy membership references unknown item {0:?}")]
    UnknownItem(HierarchyItemId),
    /// A hierarchy item cannot parent itself.
    #[error("hierarchy item cannot be its own parent: {0:?}")]
    SelfMembership(HierarchyItemId),
    /// Cross-policy edges could disclose protected structure during traversal.
    #[error("hierarchy membership crosses policy partitions")]
    CrossPartitionMembership,
    /// A hierarchy generation must be a DAG.
    #[error("hierarchy proposal contains a cycle")]
    Cycle,
    /// Declared roots differ from the roots implied by memberships.
    #[error("declared hierarchy roots do not match computed DAG roots")]
    RootMismatch,
    /// A non-empty generation has no root.
    #[error("non-empty hierarchy generation has no root")]
    MissingRoot,
    /// Only one optional cheap-navigation primary edge is allowed per child.
    #[error("hierarchy item {0:?} has multiple primary parents")]
    MultiplePrimaryParents(HierarchyItemId),
    /// A proposal exceeds an explicitly configured parent bound.
    #[error("hierarchy item {item:?} has {actual} parents; profile allows {maximum}")]
    ParentLimitExceeded {
        /// Child item.
        item: HierarchyItemId,
        /// Retained parent count.
        actual: usize,
        /// Configured maximum.
        maximum: u16,
    },
    /// A manually assembled proposal bypassed its profile's minimum confidence.
    #[error(
        "hierarchy membership for {item:?} has confidence {actual}; profile requires {minimum}"
    )]
    MembershipBelowMinimum {
        /// Child item.
        item: HierarchyItemId,
        /// Membership confidence in basis points.
        actual: u16,
        /// Profile minimum in basis points.
        minimum: u16,
    },
    /// Primary-role presence must match the view assignment policy.
    #[error("hierarchy primary-parent role does not match assignment policy for {0:?}")]
    PrimarySelectionMismatch(HierarchyItemId),
    /// A validity interval is malformed or does not include the build snapshot.
    #[error("hierarchy validity does not include build snapshot {0}")]
    InvalidValidity(CommitSeq),
    /// Core provenance validation failed.
    #[error("invalid hierarchy provenance: {0}")]
    InvalidProvenance(String),
    /// Canonical proposal serialization failed.
    #[error("hierarchy canonical serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Maintenance publication rejects the all-zero manifest sentinel.
    #[error("hierarchy generation manifest digest must not be zero")]
    InvalidManifestDigest,
    /// A loaded generation does not match its validated manifest digest or
    /// deterministic statistics.
    #[error("hierarchy generation does not match its validated manifest")]
    ManifestMismatch,
    /// A view was not published in the selected hierarchy snapshot.
    #[error("hierarchy view is unavailable")]
    ViewUnavailable,
    /// No generation is safe for the requested semantic snapshot.
    #[error("no hierarchy generation is visible for semantic snapshot {0}")]
    GenerationUnavailable(CommitSeq),
    /// Optimistic side-by-side publication observed a different active version.
    #[error("active hierarchy generation changed while proposal was building")]
    ActiveGenerationConflict,
    /// A proposal version is not the next generation.
    #[error("expected generation {expected}, proposed {proposed}")]
    GenerationConflict {
        /// Next required generation.
        expected: GenerationNumber,
        /// Proposal generation.
        proposed: GenerationNumber,
    },
    /// Profile configuration cannot move backward across generations.
    #[error("hierarchy profile revision regressed from {active} to {proposed}")]
    ProfileRevisionRegression {
        /// Active profile revision.
        active: u64,
        /// Proposed profile revision.
        proposed: u64,
    },
    /// Changed profile configuration must advance its explicit revision.
    #[error("hierarchy profile revision {0} was reused for different configuration")]
    ProfileRevisionReuse(u64),
    /// A proposal was built from older primary state than the current generation
    /// or an outstanding invalidation.
    #[error("hierarchy proposal is stale: built from {built_from}, requires at least {required}")]
    StaleProposal {
        /// Proposal semantic watermark.
        built_from: CommitSeq,
        /// Required watermark.
        required: CommitSeq,
    },
    /// A stale rebuild attempts to resurrect deleted semantic material.
    #[error("hierarchy proposal includes deleted semantic dependency {0}")]
    DeletedDependency(NodeId),
    /// A stale rebuild includes an exactly deleted non-node lineage input.
    #[error("hierarchy proposal includes deleted lineage dependency {0:?}")]
    DeletedLineageDependency(LineageNode),
    /// Requested hierarchy epoch was not retained.
    #[error("hierarchy snapshot epoch {requested} is unavailable; head is {head}")]
    SnapshotUnavailable {
        /// Requested epoch.
        requested: HierarchyEpoch,
        /// Latest epoch.
        head: HierarchyEpoch,
    },
    /// The selected generation does not cover the requested primary snapshot.
    #[error("hierarchy generation is stale: covered {covered}, requested {requested}")]
    StaleGeneration {
        /// Generation semantic watermark.
        covered: CommitSeq,
        /// Requested primary snapshot.
        requested: CommitSeq,
    },
    /// Traversal budgets must be strictly positive.
    #[error("hierarchy traversal budget {0} must be greater than zero")]
    InvalidBudget(&'static str),
    /// Missing, unauthorized, deleted, or temporally invisible routes collapse
    /// to one error to avoid an existence oracle.
    #[error("hierarchy route is unavailable")]
    RouteUnavailable,
    /// A materialized route belongs to an old generation, policy boundary, or
    /// deletion epoch and must be recomputed.
    #[error("materialized hierarchy route is stale")]
    StaleRoute,
    /// An invalidation targeted a view in a different workspace.
    #[error("view {view_id} does not belong to workspace {workspace_id}")]
    WorkspaceMismatch {
        /// View identity.
        view_id: HierarchyViewId,
        /// Supplied workspace.
        workspace_id: WorkspaceId,
    },
    /// A synchronization primitive was poisoned.
    #[error("hierarchy engine lock poisoned")]
    LockPoisoned,
    /// Epoch, generation, or route arithmetic exhausted its integer domain.
    #[error("hierarchy sequence exhausted")]
    SequenceExhausted,
}

/// Hierarchy result type.
pub type Result<T> = std::result::Result<T, HierarchyError>;
