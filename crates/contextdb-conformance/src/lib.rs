//! Deterministic cross-interface conformance proof for ContextDB v1.
//!
//! The crate treats the embedded service contract as the semantic boundary and
//! exercises transport adapters without moving authorization or business logic
//! into the harness. A missing external executable is reported as
//! `not_exercised`; it can never silently become a passing CLI result.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod capability;
mod contract;
mod error;
mod fixture;
mod profiles;
mod report;
mod schema;
mod streaming;
mod suite;

pub mod adapters;

pub use capability::{Capability, CapabilityManifest, InterfaceKind, Support};
pub use contract::{CanonicalError, CanonicalOperation, CanonicalOutcome, CanonicalResponse};
pub use error::{ConformanceError, ConformanceResult};
pub use fixture::ConformanceFixture;
pub use profiles::{cli_manifest, embedded_manifest, grpc_manifest, http_manifest, mcp_manifest};
pub use report::{CheckResult, CheckStatus, ConformanceReport};
pub use schema::{
    FieldSignature, RpcSignature, SchemaCompatibilityReport, SchemaManifest,
    compare_schema_compatibility, current_schema_manifest, parse_proto_schema,
};
pub use streaming::{GrpcStreamingProof, StreamAckOutcome, prove_grpc_network_streaming};
pub use suite::{run_archive_round_trip, run_conformance_suite};

/// Version of the deterministic conformance report schema.
pub const CONFORMANCE_SCHEMA_VERSION: u16 = 1;

#[cfg(test)]
mod tests;
