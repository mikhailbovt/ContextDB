//! Complete outgoing-context preparation for an authenticated owned runtime.

use crate::{AuthenticatedRequestContext, CaptureReceipt, ServiceResult};
use contextdb_context::{
    ContextBudgets, ContextPack, EncodedOutgoing, ModelProfile, OutgoingAssemblyManifest,
    OutgoingBase, OutgoingBudget, OutgoingEncoder, OutgoingMessage, PackFacetRequirement,
    PackPurpose, TokenCounter,
};
use contextdb_core::{ContextPackId, RawSource, TimestampMicros};
use contextdb_recall::{IndexedCompletion, IndexedQuery, QueryBudget};
use serde::{Deserialize, Serialize};

/// The host supplies H* and a bounded discovery frontier. Mandatory applicable
/// state is enumerated by the publication owner, not selected by the model.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareContextRequest {
    /// Host-authenticated runtime and reader capabilities.
    pub context: AuthenticatedRequestContext,
    /// Stable request pack identity.
    pub pack_id: ContextPackId,
    /// Governing use purpose, equal to the authenticated purpose.
    pub purpose: PackPurpose,
    /// Logical knowledge time; None pins current knowledge.
    pub known_at: Option<u64>,
    /// Fixed applicability time, or None for the current wall clock.
    pub valid_at: Option<TimestampMicros>,
    /// Optional native read-your-capture requirement.
    pub after_receipt: Option<CaptureReceipt>,
    /// At most eight indexed discovery routes; their closure shares one budget.
    pub raw_queries: Vec<IndexedQuery>,
    /// Task facets, in addition to owner-enumerated mandatory current state.
    pub required_facets: Vec<PackFacetRequirement>,
    /// Maximum additional memory allocation.
    pub memory_budget: ContextBudgets,
    /// Exact renderer/tokenizer and model capacity contract.
    pub model_profile: ModelProfile,
    /// Actual post-eviction recent history and current turn.
    pub base: OutgoingBase,
    /// Complete request limits, with output and safety reserves.
    pub outgoing_budget: OutgoingBudget,
    /// Whether the user explicitly requested disclosure of stored memory.
    pub explicit_memory_request: bool,
}

/// The exact rendered request and its disclosure dependencies. Dispatch requires
/// a separate owner fence; a prepared response is not an execution lease.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedContext {
    /// Owner seal of this exact assembly and its preparation-time validity.
    /// It is not a registered lease and cannot authorize a different wire.
    pub admission_token: String,
    /// Existing canonical ContextPack with exact original spans.
    pub context_pack: ContextPack,
    /// Canonical protobuf payload; manifest binds its BLAKE3 digest.
    pub canonical_bytes: Vec<u8>,
    /// Ordered messages, including control, state, evidence, hot and current data.
    pub messages: Vec<OutgoingMessage>,
    /// Exact provider-protocol wire and declared complete input charge.
    pub outgoing: EncodedOutgoing,
    /// Opaque policy/scope binding, source read-set and full layout digest.
    pub assembly: OutgoingAssemblyManifest,
    /// Completion of each bounded discovery route; a top-k is not exhaustive.
    pub discovery: Vec<IndexedCompletion>,
    /// Pending/gapped original interpretation prevents claiming complete state.
    pub pending_interpretation: bool,
    /// Authorized discovery hits requiring a different range or media adapter.
    /// These also appear as mandatory unknown markers in the outgoing request.
    pub unrendered_sources: Vec<UnrenderedSource>,
}

/// A retained original that this bounded text renderer could not materialize.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnrenderedSource {
    /// Authorized source address; never a substitute for original bytes.
    pub source: RawSource,
    /// Why no exact source excerpt was included.
    pub reason: OriginalRenderOmission,
}

/// Explicit text-renderer limits, distinct from archive retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginalRenderOmission {
    /// Upstream never supplied these bytes, or the original is empty.
    Unavailable,
    /// A large source needs a bounded content/range query.
    RangeRequired,
    /// Exact bytes require a media adapter rather than UTF-8 text decoding.
    NonText,
}

/// Embedded host boundary. Encoders/tokenizers are trusted runtime integrations;
/// untrusted transports cannot upload executable implementations of these traits.
pub trait PrepareContextPort: Send + Sync {
    /// Discover, authorize, close dependencies and render one complete request.
    fn prepare_context(
        &self,
        request: PrepareContextRequest,
        tokenizer: &dyn TokenCounter,
        encoder: &dyn OutgoingEncoder,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PreparedContext>;
}
