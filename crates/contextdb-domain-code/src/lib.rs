//! Coding and software-engineering domain pack.
//!
//! The crate deliberately lives outside `contextdb-core`. Compiler, Git, CI,
//! symbol, and repository concepts are domain records which can be projected
//! into the universal graph without becoming universal logical types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod git;
mod go;
mod projection;
mod query;
mod store;
mod types;

pub use error::{CodeDomainError, Result};
pub use git::{GitChange, GitChangeKind, GitCommitDescriptor};
pub use go::{GoCompilerIndex, GoIndexRelation, GoIndexSymbol, GoSnapshotAdapter, GoSourceFile};
pub use projection::{CodeDomainProjection, CodeDomainRecord};
pub use query::{
    CodeQuery, CodeQueryResult, ImpactReport, PreflightReport, RationaleResult,
    RepositoryHierarchy, ResolvedCodeLocation,
};
pub use store::{CodeMemory, PortableCodeMemory};
pub use types::*;

/// Serialized coding-domain format version.
pub const FORMAT_VERSION: u16 = 1;

#[cfg(test)]
mod tests;
