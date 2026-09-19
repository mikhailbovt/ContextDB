//! Deterministic universal recall for ContextDB.
//!
//! This crate plans and executes bounded, explainable recall over an authorized
//! provider snapshot. It contains no storage, network, model-provider, or Codex
//! integration.

#![forbid(unsafe_code)]

mod engine;
mod error;
mod indexed;
mod provider;
mod reference;
mod types;

pub use engine::RecallEngine;
pub use error::{RecallError, Result};
pub use indexed::*;
pub use provider::{AuthorizedCorpus, RecallProvider};
pub use reference::ReferenceProvider;
pub use types::*;

#[cfg(test)]
mod tests;
