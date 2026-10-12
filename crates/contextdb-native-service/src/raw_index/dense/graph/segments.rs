//! Accepted immutable deltas and a current directory for growing dense history.
//!
//! Old ANN bases retain their codec and ownership. Append and serving activation
//! require complete prefix, publication, current-head and source-custody proofs.

mod construction;
mod copies;
pub(in crate::raw_index::dense::graph) mod crypto;
pub(crate) mod heads;
mod publication;
pub(crate) mod query;
mod reconstruction;
pub(crate) mod types;
pub(in crate::raw_index::dense::graph) mod verification;

use super::*;
