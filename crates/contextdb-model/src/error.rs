use contextdb_core::ModelCallId;
use thiserror::Error;

use crate::{ModelCapability, ProviderId, SchemaRef};

/// Failures at the model capability boundary.
#[derive(Debug, Error)]
pub enum ModelRuntimeError {
    /// A bounded identifier or description is invalid.
    #[error("invalid {field}: {reason}")]
    InvalidText {
        /// Contract field.
        field: &'static str,
        /// Safe validation reason.
        reason: &'static str,
    },
    /// A numeric contract invariant is invalid.
    #[error("invalid {field}: {reason}")]
    InvalidNumber {
        /// Contract field.
        field: &'static str,
        /// Safe validation reason.
        reason: &'static str,
    },
    /// A stable identifier is already registered with different contents.
    #[error("registry identifier is already bound to different contents: {0}")]
    RegistryConflict(String),
    /// A requested model profile does not exist.
    #[error("model profile is not registered")]
    ProfileUnavailable,
    /// A requested schema is not registered or its digest differs.
    #[error("structured-output schema is unavailable or mismatched: {0:?}")]
    SchemaUnavailable(SchemaRef),
    /// A prompt asset is not registered or its digest differs.
    #[error("prompt asset is unavailable or mismatched")]
    PromptUnavailable,
    /// A prompt is incompatible with the requested capability or schema.
    #[error("prompt asset is incompatible with the model request")]
    PromptMismatch,
    /// JSON parsing failed before schema validation.
    #[error("provider output is not valid JSON: {0}")]
    MalformedJson(String),
    /// Internal canonical JSON serialization failed.
    #[error("model runtime serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// A structured output violates its versioned schema.
    #[error("provider output violates schema at {path}: {reason}")]
    SchemaViolation {
        /// JSON-pointer-like location.
        path: String,
        /// Safe structural reason without response content.
        reason: String,
    },
    /// A schema-specific semantic validator rejected the output.
    #[error("provider output failed semantic validation: {0}")]
    SemanticViolation(String),
    /// A provider output exceeded the configured byte budget.
    #[error("provider output exceeded {maximum} bytes")]
    OutputTooLarge {
        /// Maximum accepted bytes.
        maximum: usize,
    },
    /// No registered route is compatible with capability and effective policy.
    #[error("no policy-compatible route for capability {0:?}")]
    NoCompatibleRoute(ModelCapability),
    /// Sensitive input cannot cross the selected provider boundary.
    #[error("model input is unavailable under effective privacy policy")]
    PrivacyDenied,
    /// Route cost does not fit every supplied budget scope.
    #[error("model route exceeds effective cost budget")]
    BudgetExhausted,
    /// A provider circuit is currently open.
    #[error("provider circuit is open: {0}")]
    CircuitOpen(ProviderId),
    /// The provider refused the request.
    #[error("model provider refused the request")]
    ProviderRefusal,
    /// The provider is unavailable after bounded fallback attempts.
    #[error("model provider is unavailable")]
    ProviderUnavailable,
    /// A provider request exceeded its deadline.
    #[error("model provider deadline exceeded")]
    Timeout,
    /// A provider rejected a request contract.
    #[error("model provider rejected the request")]
    ProviderInvalidRequest,
    /// A provider failed without exposing provider payloads.
    #[error("model provider failed")]
    ProviderFailure,
    /// Arithmetic required for a deadline, token, cost, or sequence overflowed.
    #[error("model runtime arithmetic exhausted")]
    ArithmeticOverflow,
    /// A runtime synchronization primitive was poisoned.
    #[error("model runtime lock poisoned")]
    LockPoisoned,
    /// Audit persistence failed; external execution is aborted fail-closed.
    #[error("model call audit failed: {0}")]
    Audit(String),
    /// A retry chain references an unknown call.
    #[error("model retry references unknown call {0}")]
    UnknownRetry(ModelCallId),
    /// Batch queue capacity or drain limits were exceeded.
    #[error("model batch scheduler capacity exhausted")]
    BatchCapacity,
    /// Deterministic fallback was selected but produced no proposal.
    #[error("deterministic mode has no proposal for this capability")]
    DeterministicUnavailable,
}

/// Model runtime result.
pub type Result<T> = std::result::Result<T, ModelRuntimeError>;
