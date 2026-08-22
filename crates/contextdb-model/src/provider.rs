use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use contextdb_core::{ContentDigest, ModelCallId, ModelProfileId};

use crate::{
    ModelCapability, ModelRuntimeError, ModelUsage, PreparedModelInput, PromptAssetRef, ProviderId,
    Result, SchemaRef,
};

/// Bounded schema-repair metadata. It contains no provider output content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairContext {
    /// Digest of the rejected output.
    pub rejected_output_digest: ContentDigest,
    /// Payload-free structural violation class.
    pub violation: RepairViolation,
}

/// Safe violation classes sent to a provider for at most one repair attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairViolation {
    /// Output was not JSON.
    MalformedJson,
    /// Output violated the structural schema.
    StructuralSchema,
    /// Output violated a schema-specific semantic invariant.
    SemanticSchema,
    /// Output exceeded its hard byte bound.
    OutputLimit,
}

/// Production, repair, or isolated shadow execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptKind {
    /// Normal production proposal.
    Production,
    /// One bounded repair of a rejected response.
    SchemaRepair(RepairContext),
    /// Isolated evaluation whose output cannot enter production caches.
    Shadow,
}

/// Deadline and lineage of one provider attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAttemptContext {
    /// Model-call audit identity.
    pub call_id: ModelCallId,
    /// One-based attempt number within this route.
    pub attempt: u8,
    /// Stable digest for infrastructure retries of the same logical provider
    /// operation. A schema-repair phase receives a distinct key.
    pub idempotency_key: ContentDigest,
    /// Absolute monotonic deadline in runtime milliseconds.
    pub deadline_ms: u64,
    /// Production, repair, or shadow boundary.
    pub kind: AttemptKind,
}

/// Provider request with instruction and source-data channels kept separate.
#[derive(Clone)]
pub struct ProviderRequest {
    /// Specialized operation.
    pub capability: ModelCapability,
    /// Model profile selected by the registry.
    pub model_profile: ModelProfileId,
    /// Exact model revision.
    pub model_revision: crate::ModelRevision,
    /// Prompt reference for audit/replay.
    pub prompt: PromptAssetRef,
    /// Exact output schema.
    pub output_schema: SchemaRef,
    /// Maximum output tokens.
    pub max_output_tokens: u32,
    system_prompt: Arc<str>,
    input: PreparedModelInput,
}

/// Parameters used to construct an isolated provider request.
pub(crate) struct ProviderRequestParts {
    pub(crate) capability: ModelCapability,
    pub(crate) model_profile: ModelProfileId,
    pub(crate) model_revision: crate::ModelRevision,
    pub(crate) prompt: PromptAssetRef,
    pub(crate) output_schema: SchemaRef,
    pub(crate) max_output_tokens: u32,
    pub(crate) system_prompt: Arc<str>,
    pub(crate) input: PreparedModelInput,
}

impl fmt::Debug for ProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRequest")
            .field("capability", &self.capability)
            .field("model_profile", &self.model_profile)
            .field("model_revision", &self.model_revision)
            .field("prompt", &self.prompt)
            .field("output_schema", &self.output_schema)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("system_prompt_digest", &self.prompt.digest)
            .field("input", &self.input)
            .finish_non_exhaustive()
    }
}

impl ProviderRequest {
    pub(crate) fn from_parts(parts: ProviderRequestParts) -> Self {
        Self {
            capability: parts.capability,
            model_profile: parts.model_profile,
            model_revision: parts.model_revision,
            prompt: parts.prompt,
            output_schema: parts.output_schema,
            max_output_tokens: parts.max_output_tokens,
            system_prompt: parts.system_prompt,
            input: parts.input,
        }
    }

    /// Returns the immutable instruction-channel prompt asset text.
    #[must_use]
    pub fn system_prompt(&self) -> &str {
        &self.system_prompt
    }

    /// Returns minimized source-data bytes through a distinct channel.
    #[must_use]
    pub const fn input(&self) -> &PreparedModelInput {
        &self.input
    }
}

/// Provider-independent response envelope. Raw output remains untrusted until
/// the schema registry creates a `ValidatedModelProposal`.
#[derive(Clone)]
pub struct ProviderResponse {
    /// Untrusted response bytes.
    pub output: Vec<u8>,
    /// Provider-safe usage metadata.
    pub usage: ModelUsage,
}

impl fmt::Debug for ProviderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderResponse")
            .field("output_bytes", &self.output.len())
            .field("usage", &self.usage)
            .finish()
    }
}

impl ProviderResponse {
    /// Creates a response from already encoded provider bytes.
    #[must_use]
    pub fn new(output: Vec<u8>, usage: ModelUsage) -> Self {
        Self { output, usage }
    }

    /// Creates a deterministic JSON response.
    pub fn json(value: &serde_json::Value, usage: ModelUsage) -> Result<Self> {
        Ok(Self::new(serde_json::to_vec(value)?, usage))
    }
}

/// Stable provider failure class used by retry and circuit-breaker policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    /// Adapter deadline elapsed.
    Timeout,
    /// Provider or local runtime is unavailable.
    Unavailable,
    /// Provider rate limited the call.
    RateLimited,
    /// Model refused the requested computation.
    Refusal,
    /// Provider rejected the request contract.
    InvalidRequest,
    /// Other payload-free provider failure.
    Internal,
}

impl ProviderErrorKind {
    /// Whether another attempt or fallback route is normally safe.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Unavailable | Self::RateLimited | Self::Internal
        )
    }

    /// Whether the failure contributes to circuit health.
    #[must_use]
    pub const fn affects_circuit(self) -> bool {
        self.retryable()
    }
}

/// Payload-free provider error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError {
    /// Stable class.
    pub kind: ProviderErrorKind,
    /// Optional safe retry delay supplied by the provider.
    pub retry_after_ms: Option<u64>,
}

impl ProviderError {
    /// Creates a provider error without copying provider payloads.
    #[must_use]
    pub const fn new(kind: ProviderErrorKind) -> Self {
        Self {
            kind,
            retry_after_ms: None,
        }
    }

    /// Adds a bounded retry-after delay.
    #[must_use]
    pub const fn with_retry_after(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }
}

/// Isolated provider boundary. Implementations receive no storage engine,
/// journal coordinator, credentials from core, or mutation capability.
pub trait ModelProvider: Send + Sync {
    /// Stable adapter identity used by the capability registry.
    fn id(&self) -> &ProviderId;

    /// Executes one deadline-aware request.
    fn invoke(
        &self,
        request: &ProviderRequest,
        context: &ProviderAttemptContext,
    ) -> std::result::Result<ProviderResponse, ProviderError>;

    /// Executes a compatible batch. The default preserves request ordering and
    /// delegates to `invoke`; real adapters can issue one native batch.
    fn invoke_batch(
        &self,
        requests: &[ProviderRequest],
        context: &ProviderAttemptContext,
    ) -> Vec<std::result::Result<ProviderResponse, ProviderError>> {
        requests
            .iter()
            .map(|request| self.invoke(request, context))
            .collect()
    }
}

/// Deterministic deployment-local adapter backed by recorded validated test or
/// evaluation responses. It performs no network access.
pub struct RecordedLocalProvider {
    id: ProviderId,
    responses: RwLock<BTreeMap<RecordedRequestKey, ProviderResponse>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RecordedRequestKey {
    capability: ModelCapability,
    schema_digest: ContentDigest,
    prompt_digest: ContentDigest,
    input_digest: ContentDigest,
}

impl fmt::Debug for RecordedLocalProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedLocalProvider")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl RecordedLocalProvider {
    /// Creates an empty deterministic local adapter.
    #[must_use]
    pub fn new(id: ProviderId) -> Self {
        Self {
            id,
            responses: RwLock::new(BTreeMap::new()),
        }
    }

    /// Records one exact deterministic response keyed only by immutable
    /// capability/schema/prompt/input digests.
    pub fn insert(
        &self,
        capability: ModelCapability,
        schema: &SchemaRef,
        prompt: &PromptAssetRef,
        input_digest: ContentDigest,
        response: ProviderResponse,
    ) -> Result<()> {
        let key = RecordedRequestKey {
            capability,
            schema_digest: schema.digest,
            prompt_digest: prompt.digest,
            input_digest,
        };
        let mut responses = self
            .responses
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        if responses.contains_key(&key) {
            return Err(ModelRuntimeError::RegistryConflict(
                "recorded provider response".to_owned(),
            ));
        }
        responses.insert(key, response);
        Ok(())
    }
}

impl ModelProvider for RecordedLocalProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn invoke(
        &self,
        request: &ProviderRequest,
        _context: &ProviderAttemptContext,
    ) -> std::result::Result<ProviderResponse, ProviderError> {
        let key = RecordedRequestKey {
            capability: request.capability.clone(),
            schema_digest: request.output_schema.digest,
            prompt_digest: request.prompt.digest,
            input_digest: request.input.digest,
        };
        self.responses
            .read()
            .map_err(|_| ProviderError::new(ProviderErrorKind::Internal))?
            .get(&key)
            .cloned()
            .ok_or_else(|| ProviderError::new(ProviderErrorKind::Unavailable))
    }
}
