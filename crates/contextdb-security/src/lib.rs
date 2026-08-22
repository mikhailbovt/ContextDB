//! Security and privacy primitives for the ContextDB v1 release profile.
//!
//! The crate is deliberately independent from storage engines and model
//! providers. Hosts supply keys and durable sinks; this crate owns canonical
//! cryptographic envelopes, audit-chain validation, deletion completion,
//! secret handling, taint classification, and deterministic admission limits.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod admission;
mod audit;
mod backup;
mod benchmark;
mod deletion;
mod error;
mod field_encryption;
mod policy;
mod secrets;
mod taint;

pub use admission::*;
pub use audit::*;
pub use backup::*;
pub use benchmark::*;
pub use deletion::*;
pub use error::*;
pub use field_encryption::*;
pub use policy::*;
pub use secrets::*;
pub use taint::*;

#[cfg(test)]
mod tests;
