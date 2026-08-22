//! Persistent conversational-memory vertical for ContextDB.
//!
//! The crate will compose durable observation capture, policy-safe recall,
//! context compilation, proposal-only cognition, restart recovery, and
//! provider-neutral chat adapters without moving those responsibilities into
//! the storage or semantic core.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod benchmark;
mod clock;
mod cognition;
mod control;
mod error;
mod middleware;
mod recall;
mod runtime;
#[cfg(feature = "service-adapter")]
mod service_adapter;
mod store;
mod types;

pub use benchmark::*;
pub use clock::*;
pub use cognition::*;
pub use control::*;
pub use error::{ChatError, Result};
pub use middleware::*;
pub use recall::*;
pub use runtime::*;
#[cfg(feature = "service-adapter")]
pub use service_adapter::*;
pub use store::*;
pub use types::*;

/// Schema version of the M11 conversational middleware contracts.
pub const FORMAT_VERSION: u16 = 1;

#[cfg(test)]
mod tests;
