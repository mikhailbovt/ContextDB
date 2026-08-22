//! Provider-neutral, policy-gated model capability runtime for ContextDB.
//!
//! Provider responses are untrusted proposals. This crate never grants model
//! adapters storage access and never converts an unvalidated response into a
//! semantic mutation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod audit;
mod batch;
mod error;
mod fallback;
mod gateway;
mod mock;
mod policy;
mod prompt;
mod provider;
mod registry;
mod reliability;
mod schema;
mod types;

pub use audit::{
    InMemoryAuditSink, ModelAuditEvent, ModelAuditSink, ModelCallFinished, ModelCallStarted,
    ModelCallStatus, ModelExecutionPath,
};
pub use batch::{
    BatchJobId, BatchPartition, BatchPriority, BatchScheduler, BatchSchedulerConfig, CoalesceKey,
    EnqueueDisposition, EnqueueReceipt, ScheduledBatch, ScheduledModelCall,
};
pub use error::{ModelRuntimeError, Result};
pub use fallback::{
    DeterministicFallback, DeterministicFallbackRequest, FallbackRegistry, RecordedFallback,
};
pub use gateway::{
    DegradedModelOutcome, DegradedReason, ModelCallRequest, ModelExecution, ModelGateway,
    ModelGatewayConfig, ModelGatewayOutcome, ShadowEvaluation, ValidatedModelResult,
};
pub use mock::{MockAttemptRecord, MockProvider, MockStep};
pub use policy::{
    BudgetScope, CostBudget, EvaluatedRoute, ModelInput, PolicyDecision, PreparedModelInput,
    RoutingPolicy, evaluate_routes,
};
pub use prompt::{PromptAsset, PromptAssetDefinition, PromptRegistry};
pub use provider::{
    AttemptKind, ModelProvider, ProviderAttemptContext, ProviderError, ProviderErrorKind,
    ProviderRequest, ProviderResponse, RecordedLocalProvider, RepairContext, RepairViolation,
};
pub use registry::CapabilityRegistry;
pub use reliability::{
    AvailabilityRegistry, CircuitBreaker, CircuitBreakerConfig, CircuitKey, CircuitSnapshot,
    ManualTimer, RetryPolicy, RuntimeTimer, SystemTimer,
};
pub use schema::{
    NoopSemanticValidator, SchemaNode, SchemaRegistry, SemanticOutputValidator, StructuredSchema,
    ValidatedModelProposal,
};
pub use types::{
    BasisPoints, CapabilityDescriptor, CapabilityRoute, CostProfile, CurrencyCode,
    DataHandlingPolicy, ExecutionLocality, InstructionHierarchy, LanguageTag, LatencyProfile,
    Modality, ModelCapability, ModelProfile, ModelProfileMap, ModelRevision, ModelUsage,
    PositionProfile, PromptAssetId, PromptAssetRef, ProviderId, RegionId, RouteSummary, SchemaId,
    SchemaRef, Sensitivity, StructuredFormat,
};

/// Schema version of the M9 runtime contracts.
pub const FORMAT_VERSION: u16 = 1;

#[cfg(test)]
mod tests;
