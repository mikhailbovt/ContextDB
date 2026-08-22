//! Rebuildable retrieval representations for ContextDB.
//!
//! The primary semantic graph remains authoritative. Every index record carries
//! policy routing metadata, lineage, and a projection watermark; authorization
//! creates an opaque universe before lexical/vector bytes are inspected.

#![forbid(unsafe_code)]

mod ann_v2;
#[cfg(feature = "ann-hnsw")]
mod ann_v2_runtime;
#[cfg(feature = "ann-hnsw")]
mod ann_v2_source;
mod artifact;
mod error;
mod lexical;
mod vector;

pub use ann_v2::*;
#[cfg(feature = "ann-hnsw")]
pub use ann_v2_runtime::*;
#[cfg(feature = "ann-hnsw")]
pub use ann_v2_source::*;
pub use artifact::*;
pub use error::{IndexError, Result};
pub use lexical::*;
pub use vector::*;

use std::collections::BTreeSet;

use contextdb_core::{
    CommitSeq, MemorySpaceId, MemorySubjectId, Purpose, ScopeId, SecurityClassification, Validate,
    WorkspaceId,
};
use serde::{Deserialize, Serialize};

/// Routing-only labels consulted before any indexed content is materialized.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexPolicy {
    pub workspace_id: WorkspaceId,
    pub memory_spaces: BTreeSet<MemorySpaceId>,
    pub subjects: BTreeSet<MemorySubjectId>,
    pub owners: BTreeSet<MemorySubjectId>,
    pub scopes: BTreeSet<ScopeId>,
    pub purposes: BTreeSet<Purpose>,
    pub classification: SecurityClassification,
    pub security_labels: BTreeSet<String>,
    pub required_compartments: BTreeSet<ScopeId>,
    pub allow_external_processing: bool,
    pub retrieve_allowed: bool,
    pub deleted_at: Option<CommitSeq>,
}

/// Authenticated retrieval context. It contains no content-derived fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexPrincipal {
    pub workspace_id: WorkspaceId,
    pub memory_spaces: BTreeSet<MemorySpaceId>,
    pub subjects: BTreeSet<MemorySubjectId>,
    pub owner_identities: BTreeSet<MemorySubjectId>,
    pub scopes: BTreeSet<ScopeId>,
    pub purpose: Purpose,
}

impl IndexPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.memory_spaces.is_empty() || self.owners.is_empty() || self.purposes.is_empty() {
            return Err(IndexError::Invalid(
                "index policy requires memory space, owner, and purpose",
            ));
        }
        for purpose in &self.purposes {
            purpose
                .validate()
                .map_err(|_| IndexError::Invalid("index purpose is invalid"))?;
        }
        if self
            .security_labels
            .iter()
            .any(|label| label.trim().is_empty())
        {
            return Err(IndexError::Invalid("security label must not be blank"));
        }
        Ok(())
    }

    fn authorizes(&self, principal: &IndexPrincipal, snapshot: CommitSeq) -> bool {
        self.retrieve_allowed
            && self.workspace_id == principal.workspace_id
            && !self.memory_spaces.is_disjoint(&principal.memory_spaces)
            && (self.subjects.is_empty() || !self.subjects.is_disjoint(&principal.subjects))
            && !self.owners.is_disjoint(&principal.owner_identities)
            && self.purposes.contains(&principal.purpose)
            && self.scopes.is_subset(&principal.scopes)
            && self.required_compartments.is_subset(&principal.scopes)
            && self.deleted_at.is_none_or(|deleted| deleted > snapshot)
    }
}

#[cfg(all(test, feature = "ann-hnsw"))]
mod ann_v2_source_tests;
#[cfg(test)]
mod ann_v2_tests;
#[cfg(test)]
mod tests;
