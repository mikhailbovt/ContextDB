//! Deterministic, model-neutral ContextPack compilation and rendering.
//!
//! The compiler is policy-first: unauthorized material is discarded before
//! content is inspected, scored, budgeted, traced, or serialized. Provider and
//! storage integrations remain outside this crate.

#![forbid(unsafe_code)]

mod adapter;
mod assembly;
mod compiler;
mod continuation;
mod error;
mod provider;
mod render;
mod token;
mod types;
mod wire;

pub use assembly::*;
pub use compiler::ContextCompiler;
pub use error::{ContextError, Result};
pub use provider::{
    CandidatePolicyLabel, ContextProvider, EvidencePolicyLabel, InMemoryContextProvider,
    ProviderCandidate, ProviderEvidence,
};
pub use render::{ContextRenderer, RenderedContext};
pub use token::{ReferenceTokenizer, TokenCounter};
pub use types::*;
pub use wire::CanonicalSerializer;

/// Canonical ContextPack schema version emitted by this crate.
pub const CONTEXT_PACK_SCHEMA_VERSION: &str = "contextdb.context_pack.v1";

/// Public identifier for the exact canonical Protobuf bytes emitted by the
/// compiler. The normative schema is `contextdb.v1.CanonicalContextPackV1`.
pub const CONTEXT_PACK_CANONICAL_ENCODING: &str = "contextdb.context_pack.protobuf.v1";

/// Digest algorithm applied to the canonical Protobuf bytes.
pub const CONTEXT_PACK_CANONICAL_DIGEST_ALGORITHM: &str = "blake3-256";

/// Deterministic selection, continuation, and provenance implementation version.
pub const CONTEXT_COMPILER_VERSION: &str = "contextdb.context_compiler.v1";

#[cfg(test)]
mod tests;
pub use adapter::{RecallBoundProvider, RecallContextBinding};
