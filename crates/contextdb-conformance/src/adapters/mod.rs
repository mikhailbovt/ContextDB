//! Concrete adapters which invoke the real ContextDB interface boundaries.

mod cli;
mod embedded;
mod grpc;
mod http;
mod mcp;

use std::future::Future;
use std::pin::Pin;

pub use embedded::EmbeddedAdapter;
pub use grpc::GrpcAdapter;
pub use http::{HttpAdapter, HttpProtocolProof, prove_http_protocol_errors};
pub use mcp::{McpAdapter, McpR19Proof};

use crate::{
    CanonicalOperation, CanonicalOutcome, CapabilityManifest, ConformanceResult, InterfaceKind,
};

/// Heap-erased adapter future without a runtime-specific trait dependency.
pub type AdapterFuture<'a> =
    Pin<Box<dyn Future<Output = ConformanceResult<CanonicalOutcome>> + Send + 'a>>;

/// Common execution surface used by the deterministic conformance suite.
pub trait ConformanceAdapter: Send {
    /// Interface kind.
    fn interface(&self) -> InterfaceKind;

    /// Explicit supported/gap capability declaration.
    fn manifest(&self) -> CapabilityManifest;

    /// Executes one canonical operation through the actual interface adapter.
    fn invoke(&mut self, operation: CanonicalOperation) -> AdapterFuture<'_>;
}
pub use cli::{CliExternalProof, CliProcessAdapter};
