use std::collections::BTreeSet;
use std::fmt;
use std::sync::RwLock;

use contextdb_core::{ContentDigest, LineageNode, ModelCallId, ModelProfileId};
use serde::{Deserialize, Serialize};

use crate::{
    ModelCapability, ModelRevision, ModelRuntimeError, ModelUsage, PolicyDecision, PromptAssetRef,
    ProviderId, Result, SchemaRef,
};

/// Execution path recorded without provider payload content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelExecutionPath {
    /// Registered provider adapter.
    Provider,
    /// Validated production cache hit.
    ValidatedCache,
    /// Deterministic no-model fallback.
    DeterministicFallback,
}

/// Terminal attempt status used by audit and low-cardinality metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCallStatus {
    /// Strict schema and semantic validation succeeded.
    Succeeded,
    /// A validated cache entry was used.
    CacheHit,
    /// Provider output was malformed or schema-invalid.
    SchemaRejected,
    /// Model refusal.
    Refused,
    /// Attempt deadline elapsed.
    Timeout,
    /// Provider unavailable or rate limited.
    ProviderUnavailable,
    /// Provider rejected the request contract.
    InvalidRequest,
    /// Other provider failure.
    Failed,
    /// No-model fallback produced a validated proposal.
    DeterministicFallback,
}

/// Pre-execution audit record. A provider call must not begin unless this event
/// is accepted by the configured sink.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallStarted {
    /// Stable call identity.
    pub id: ModelCallId,
    /// Specialized purpose.
    pub capability: ModelCapability,
    /// Execution path.
    pub path: ModelExecutionPath,
    /// Provider for adapter execution; absent for cache/fallback.
    pub provider: Option<ProviderId>,
    /// Model profile, if a model route is used.
    pub model_profile: Option<ModelProfileId>,
    /// Exact model revision, if used.
    pub model_revision: Option<ModelRevision>,
    /// Exact prompt asset reference.
    pub prompt: PromptAssetRef,
    /// Exact schema reference.
    pub schema: SchemaRef,
    /// Digest of the selected minimized input, never the payload.
    pub input_digest: ContentDigest,
    /// Source lineage references, never source payload.
    pub source_refs: Vec<LineageNode>,
    /// Monotonic start instant.
    pub started_at_ms: u64,
    /// One-based attempt number.
    pub attempt: u8,
    /// Prior call in a retry/repair chain.
    pub retry_of: Option<ModelCallId>,
    /// True for isolated shadow evaluation.
    pub shadow: bool,
    /// Payload-free effective policy decision.
    pub policy_decision: Option<PolicyDecision>,
}

/// Terminal payload-free model-call audit record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallFinished {
    /// Call identity from the start record.
    pub id: ModelCallId,
    /// Terminal status.
    pub status: ModelCallStatus,
    /// Digest of validated or rejected output, if bytes were received.
    pub output_digest: Option<ContentDigest>,
    /// Elapsed monotonic milliseconds.
    pub latency_ms: u64,
    /// Provider-safe usage and cost metadata.
    pub usage: ModelUsage,
}

/// Append-only audit event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ModelAuditEvent {
    /// Pre-execution event.
    Started(Box<ModelCallStarted>),
    /// Terminal event.
    Finished(ModelCallFinished),
}

/// Audit sink boundary. Persistent implementations can append-chain or sign
/// these payload-free events without receiving provider content.
pub trait ModelAuditSink: Send + Sync {
    /// Records one immutable event.
    fn record(&self, event: ModelAuditEvent) -> std::result::Result<(), String>;
}

/// In-memory reference audit sink with start/finish consistency checks.
#[derive(Default)]
pub struct InMemoryAuditSink {
    events: RwLock<Vec<ModelAuditEvent>>,
    started: RwLock<BTreeSet<ModelCallId>>,
    finished: RwLock<BTreeSet<ModelCallId>>,
}

impl fmt::Debug for InMemoryAuditSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryAuditSink")
            .finish_non_exhaustive()
    }
}

impl InMemoryAuditSink {
    /// Creates an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns an immutable event snapshot.
    pub fn events(&self) -> Result<Vec<ModelAuditEvent>> {
        Ok(self
            .events
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .clone())
    }
}

impl ModelAuditSink for InMemoryAuditSink {
    fn record(&self, event: ModelAuditEvent) -> std::result::Result<(), String> {
        match &event {
            ModelAuditEvent::Started(started) => {
                let mut ids = self
                    .started
                    .write()
                    .map_err(|_| "audit start lock poisoned".to_owned())?;
                if !ids.insert(started.id) {
                    return Err("duplicate model-call start".to_owned());
                }
            }
            ModelAuditEvent::Finished(finished) => {
                if !self
                    .started
                    .read()
                    .map_err(|_| "audit start lock poisoned".to_owned())?
                    .contains(&finished.id)
                {
                    return Err("model-call finish has no start".to_owned());
                }
                let mut ids = self
                    .finished
                    .write()
                    .map_err(|_| "audit finish lock poisoned".to_owned())?;
                if !ids.insert(finished.id) {
                    return Err("duplicate model-call finish".to_owned());
                }
            }
        }
        self.events
            .write()
            .map_err(|_| "audit event lock poisoned".to_owned())?
            .push(event);
        Ok(())
    }
}
