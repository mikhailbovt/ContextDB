//! Versioned derived hierarchy views for policy-safe navigation.
//!
//! Hierarchies are rebuildable navigation projections over semantic state. They
//! never assert truth, rewrite the source graph, or force a single canonical
//! parent. Model-produced structure remains a proposal until deterministic
//! validation and atomic generation publication succeed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod builder;
mod engine;
mod error;
mod query;
mod types;
mod validation;

pub use builder::{AssignmentCandidate, HierarchyProposalBuilder};
pub use engine::{
    HierarchyRead, HierarchyRepository, HierarchySnapshot, InMemoryHierarchyEngine,
    PersistentHierarchyBundle,
};
pub use error::{HierarchyError, Result};
pub use query::{
    BeamTraversalRequest, BeamTraversalResult, FreshnessRequirement, GenerationFreshness,
    HierarchyRoute, RouteMaterialization, RouteRequest, TraversalHit,
};
pub use types::{
    AssignmentPolicy, AssignmentSource, AuthorizationSnapshot, BranchStatistics, Confidence,
    DeletionRecord, GenerationNumber, HierarchyBranchId, HierarchyEpoch, HierarchyGeneration,
    HierarchyGenerationRef, HierarchyInvalidation, HierarchyItemId, HierarchyKind,
    HierarchyMembership, HierarchyNode, HierarchyProfile, HierarchyProposal, HierarchyProvenance,
    HierarchySnapshotSelector, HierarchyValidity, InvalidationReason, MembershipRole,
    PolicyPartition, PolicyPartitionId, ValidatedHierarchyProposal,
};
pub use validation::validate_proposal;

/// Schema version of serialized M6 projection contracts.
pub const FORMAT_VERSION: u16 = 1;

#[cfg(test)]
mod tests;
