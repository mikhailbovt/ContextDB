//! Deterministic cross-model operational continuity for ContextDB.
//!
//! This crate plans and validates portable checkpoints, model compatibility,
//! bootstrap, preflight/postflight, re-embedding work, and privacy-safe
//! handoffs. It never claims psychological identity and performs no storage,
//! provider, network, tool, or embedding execution.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod benchmark;
mod bootstrap;
mod checkpoint;
mod compatibility;
mod error;
mod handoff;
mod lifecycle;
mod preflight;
mod profile;
mod reembedding;
mod types;

pub use benchmark::*;
pub use bootstrap::*;
pub use checkpoint::*;
pub use compatibility::*;
pub use error::{ContinuityError, Result};
pub use handoff::*;
pub use lifecycle::*;
pub use preflight::*;
pub use profile::*;
pub use reembedding::*;
pub use types::*;

/// Stable serialization format version for M12 continuity artifacts.
pub const CONTINUITY_FORMAT_VERSION: u16 = 1;

#[cfg(test)]
mod tests;
