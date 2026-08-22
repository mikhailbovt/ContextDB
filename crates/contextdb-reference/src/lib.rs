//! Deterministic in-memory correctness oracle for ContextDB.
//!
//! The reference engine is deliberately slow and explicit. It provides atomic clone-on-write
//! transactions, bitemporal snapshots, policy-first exact reads, deterministic logical export,
//! and failpoints for differential/crash testing. It has no model, disk, network, or ANN logic.

mod canonical;
pub mod core_adapter;
mod db;
mod error;
mod model;

pub use db::ContextDb;
pub use error::{ReferenceError, Result};
pub use model::*;
