//! Persistent bitemporal graph, subject-local policy indexes, and immutable adjacency segments.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod keyspace;
mod model;
mod policy;
mod store;

pub use error::{GraphError, Result};
pub use model::*;
pub use store::{GraphMutation, GraphStore};

/// Maximum directional edge records admitted by one authenticated segment-v2 generation.
///
/// A directed logical edge consumes one outgoing and one incoming record. This is a
/// format-capacity boundary, not evidence that any workload at the boundary has completed.
/// Generations above the former 100-million-record boundary cannot be opened by older
/// binaries which still enforce that lower runtime cap.
pub const SEGMENT_V2_MAX_DIRECTIONAL_RECORDS: u64 = 200_000_000;
