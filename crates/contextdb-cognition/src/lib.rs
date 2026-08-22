//! Deterministic adjudication for AI-assisted ContextDB writes.
//!
//! Provider output is untrusted, proposal-only computation.  It never receives
//! canonical identifiers to mint, a storage transaction, or commit authority.
//! This crate validates a versioned proposal against authorized evidence,
//! resolves identity and time, classifies conflicts, applies deterministic
//! promotion rules, and prepares a [`contextdb_core::SemanticMutationSet`] for
//! the ordered journal commit coordinator.

#![forbid(unsafe_code)]

mod config;
mod consolidation;
mod error;
mod evaluation;
mod evidence;
mod extraction;
mod pipeline;
mod proposal;
mod resolution;

pub use config::*;
pub use consolidation::*;
pub use error::*;
pub use evaluation::*;
pub use evidence::*;
pub use extraction::*;
pub use pipeline::*;
pub use proposal::*;
pub use resolution::*;

#[cfg(test)]
mod tests;
