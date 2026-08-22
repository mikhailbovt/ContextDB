//! Deterministic accumulating-knowledge ingestion and recall for ContextDB.
//!
//! This crate turns generic document revisions into evidence-backed temporal
//! knowledge proposals while keeping source history immutable and disagreement
//! explicit. Persistence and model execution remain behind narrow adapters.

#![forbid(unsafe_code)]

mod adapter;
mod bench;
mod error;
mod ledger;
mod model;
mod pack;

pub use adapter::*;
pub use bench::*;
pub use error::*;
pub use ledger::*;
pub use model::*;
pub use pack::*;

#[cfg(test)]
mod tests;
