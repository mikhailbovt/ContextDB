//! Complete outgoing-context preparation for an authenticated owned runtime.

use crate::{
    AuthenticatedRequestContext, CaptureAcceptance, CaptureReceipt, CaptureRequest, ErrorCode,
    ServiceError, ServiceResult,
};
use contextdb_context::{
    ContextBudgets, ContextPack, EncodedOutgoing, ModelProfile, OutgoingAssemblyManifest,
    OutgoingBase, OutgoingBudget, OutgoingEncoder, OutgoingMessage, PackFacetRequirement,
    PackPurpose, TokenCounter,
};
use contextdb_core::{
    ContentDigest, ContextPackId, MAX_ROUTER_TRACE_BYTES, ModelCallId, ROUTER_REPLAY_TRACE_VERSION,
    ROUTER_TRACE_VERSION, RawFilter, RawSource, RecallIntent, RouterTraceAttachment,
    TimestampMicros,
};
use contextdb_recall::{
    IndexedCompletion, IndexedQuery, QueryBudget, RecallLimits, RecallMode, SuppliedVector,
};
use serde::{Deserialize, Serialize};

mod hybrid;
mod recall;
#[cfg(test)]
mod tests;
pub use hybrid::{OwnedHybridIntent, OwnedHybridLimits, OwnedSegmentLimits};
pub use recall::deterministic_prepare_recall;

/// Explicit protected trace mode. Required never falls back to an omitted trace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterTraceProfile {
    /// Existing wire-only capture behavior.
    #[default]
    Off,
    /// Retain a complete bounded query-time trace through native owner admission.
    Required,
    /// Retain explicit prepared-state replay inputs and behavior observations.
    RequiredReplayV2,
}

impl RouterTraceProfile {
    /// Whether the legacy omitted profile applies.
    pub const fn is_off(&self) -> bool {
        matches!(self, Self::Off)
    }

    /// Required attachment contract. Off retains the legacy absent field.
    pub const fn version(&self) -> Option<u16> {
        match self {
            Self::Off => None,
            Self::Required => Some(ROUTER_TRACE_VERSION),
            Self::RequiredReplayV2 => Some(ROUTER_REPLAY_TRACE_VERSION),
        }
    }
}

fn legacy_trace_version() -> u16 {
    ROUTER_TRACE_VERSION
}
fn is_legacy_trace_version(version: &u16) -> bool {
    *version == ROUTER_TRACE_VERSION
}

/// Bounded generic memory discovery cue, under the enclosing preparation authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRecallQuery {
    /// Actual current query, with no second authority or snapshot configuration.
    pub query: String,
    /// Typed discovery and temporal intent.
    pub intent: RecallIntent,
    /// Existing deterministic recall gate.
    pub mode: RecallMode,
    /// Bounded route/graph/evidence work.
    pub limits: RecallLimits,
    /// Optional exact host vector in an explicitly named space.
    pub query_vector: Option<SuppliedVector>,
}

/// Separate opt-in lexical ranking intent; it contains no authorization or model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBm25Query {
    /// Bounded actual current-step text, analyzed with the native raw analyzer.
    pub text: String,
    /// Initially only the unrestricted, request-echo-excluding filter is supported.
    pub filter: RawFilter,
    /// Maximum returned source candidates, from one through one hundred.
    pub limit: u32,
}

/// Population support is distinct from rank/scan completion and semantic coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawBm25ProfileStatus {
    /// The captured lexical population supports this scoring profile.
    Supported,
    /// No explicitly declared BM25 generation is active.
    MissingProjection,
    /// The filter cannot use the fixed population statistics.
    UnsupportedFilter,
    /// Current statistics cannot represent the requested historical snapshot.
    UnsupportedHistorical,
    /// Some accepted sources exceed the lexical or rendering profile.
    IncompleteLexicalCoverage,
    /// Fresh source population exceeds the bounded join.
    TailOverflow,
}

/// Completion of this bounded OR-posting operation, never whole-memory recall.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawBm25Completion {
    /// Every posting within this bounded query was considered.
    Complete,
    /// The requested top-K retained a subset of positively ranked sources.
    RankedLimit,
    /// The fixed posting cap prevented a complete ranking.
    PostingLimit,
    /// The shared work allowance stopped the query.
    WorkLimit,
    /// The shared byte allowance stopped the query.
    ByteLimit,
}

/// An admitted source and authenticated matching ranges; score grants no authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBm25Hit {
    /// Complete admitted original identity.
    pub source: RawSource,
    /// Exact authenticated first-term ranges in original bytes.
    pub matches: Vec<contextdb_core::OriginalSourceSpan>,
    /// Finite nonnegative rank value, not a utility probability.
    pub score: f64,
}

/// Process observation of the actual bounded candidate path, not an owner lease.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBm25Page {
    /// Actual bounded normalized query terms; this observation grants no access.
    pub terms: Vec<String>,
    /// Selected source candidates in deterministic score order.
    pub hits: Vec<RawBm25Hit>,
    /// Support or explicit limitations of the captured lexical population.
    pub profile_status: RawBm25ProfileStatus,
    /// Completion of posting work, distinct from memory completeness.
    pub completion: RawBm25Completion,
    /// Opaque native view identity; contains no global activity counters.
    pub snapshot: String,
}

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
    /// Optional generic discovery through the same owner and shared allowance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_query: Option<PrepareRecallQuery>,
    /// Optional persistent native BM25 discovery, sharing this complete budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bm25_query: Option<RawBm25Query>,
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
    /// Protected trace mode, bound into the owner-prepared assembly.
    #[serde(default, skip_serializing_if = "RouterTraceProfile::is_off")]
    pub router_trace_profile: RouterTraceProfile,
}

/// The exact rendered request and its disclosure dependencies. Dispatch requires
/// a separate owner fence; a prepared response is not an execution lease.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedContext {
    /// Measured successful compiler scorer time; never a model usage counter.
    pub scorer_micros: u64,
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
    /// Bounded sealed native routing envelope, without a final model-call ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_trace: Option<PreparedRouterTrace>,
    /// The owner rendered a selected historical tool page and its complete locator.
    /// This encoding marker never authorizes the original or a proposed page call.
    #[serde(default, skip_serializing_if = "is_false")]
    pub original_page_recall: bool,
    /// Actual BM25 process observation; it is not standalone sealed authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bm25_discovery: Option<RawBm25Page>,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// Owner-prepared routing material. Public fields and hashes alone grant no
/// permission; the native owner verifies the seal, envelope and origin controls.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRouterTrace {
    /// Explicit v2 contract; omitted v1 preserves the original transport bytes.
    #[serde(
        default = "legacy_trace_version",
        skip_serializing_if = "is_legacy_trace_version"
    )]
    pub version: u16,
    /// Exact prepared pack identity.
    pub pack_id: ContextPackId,
    /// Exact model wire digest.
    pub wire_digest: ContentDigest,
    /// Exact model wire length.
    pub wire_byte_length: u64,
    /// Authorized request commitment.
    pub router_request_digest: ContentDigest,
    /// Accepted plan commitment.
    pub router_plan_digest: ContentDigest,
    /// Accepted compiler manifest commitment.
    pub router_manifest_digest: ContentDigest,
    /// Complete owner-resolved origin/control commitment.
    pub origin_closure_digest: ContentDigest,
    /// BLAKE3 of the complete canonical envelope bytes.
    pub trace_digest: ContentDigest,
    /// Sensitive native envelope, outside model input and owned checkpoints.
    pub canonical_json: String,
    /// Opaque native commitment to this preparation, not a transferable grant.
    pub seal: String,
}

impl std::fmt::Debug for PreparedRouterTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRouterTrace")
            .field("version", &self.version)
            .field("byte_length", &self.canonical_json.len())
            .field("trace_digest", &self.trace_digest)
            .field("origin_closure_digest", &self.origin_closure_digest)
            .finish_non_exhaustive()
    }
}

impl PreparedRouterTrace {
    /// Check bounded local consistency; this does not validate native authority.
    pub fn validate(&self) -> ServiceResult<()> {
        if !matches!(
            self.version,
            ROUTER_TRACE_VERSION | ROUTER_REPLAY_TRACE_VERSION
        ) || self.canonical_json.is_empty()
            || self.canonical_json.len() > MAX_ROUTER_TRACE_BYTES
            || self.wire_byte_length == 0
            || self.seal.is_empty()
            || self.seal.len() > 16384
            || self.seal.chars().any(char::is_control)
            || self.trace_digest
                != ContentDigest::from_bytes(
                    *blake3::hash(self.canonical_json.as_bytes()).as_bytes(),
                )
        {
            return Err(ServiceError::new(
                ErrorCode::IntegrityFailure,
                "prepared router trace is invalid or excessive",
                false,
            ));
        }
        Ok(())
    }

    /// Bind the checkpointed pending call and page this exact native envelope.
    pub fn attach(
        &self,
        model_call_id: ModelCallId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RouterTraceAttachment> {
        if self.canonical_json.len() > MAX_ROUTER_TRACE_BYTES {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "prepared router trace exceeds its byte ceiling",
                false,
            ));
        }
        budget
            .charge(1, self.canonical_json.len() as u64 * 6)
            .map_err(|_| {
                ServiceError::new(
                    ErrorCode::ResourceExhausted,
                    "router trace allowance exhausted",
                    false,
                )
            })?;
        self.validate()?;
        RouterTraceAttachment::new_with_version(
            self.version,
            model_call_id,
            self.pack_id,
            self.wire_digest,
            self.wire_byte_length,
            self.router_request_digest,
            self.router_plan_digest,
            self.router_manifest_digest,
            self.origin_closure_digest,
            &self.canonical_json,
        )
        .map_err(|_| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "router trace paging refused",
                false,
            )
        })
    }
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

    /// Trusted embedded-host query encoder boundary. The implementation must
    /// authenticate the current owned attempt and every sampled source before
    /// tokenization or inference; a serialized vector cannot replace this path.
    /// Existing service profiles explicitly refuse this optional capability.
    fn prepare_context_with_query_encoder(
        &self,
        _request: PrepareContextRequest,
        _intent: OwnedHybridIntent,
        _tokenizer: &dyn TokenCounter,
        _encoder: &dyn OutgoingEncoder,
        _query_encoder: &dyn crate::TextEmbeddingAdapter,
        budget: &mut QueryBudget,
    ) -> ServiceResult<PreparedContext> {
        budget.charge(1, 0).map_err(|_| {
            ServiceError::new(
                ErrorCode::BudgetExhausted,
                "owned hybrid allowance exhausted",
                false,
            )
        })?;
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "owned hybrid query preparation is unavailable in this service profile",
            false,
        ))
    }

    /// Accept a trace-bearing request through the prepared owner's atomic capture
    /// boundary. Ordinary append cannot substitute for this admission path.
    fn capture_prepared_model_request(
        &self,
        _request: CaptureRequest,
        _prepared: &PreparedContext,
        _current_checkpoint: Option<&CaptureReceipt>,
        _budget: &mut QueryBudget,
    ) -> ServiceResult<CaptureAcceptance> {
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "prepared model request capture is unavailable in this service profile",
            false,
        ))
    }
}
