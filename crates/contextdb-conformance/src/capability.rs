use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Public ContextDB interface exercised by the harness.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    /// Direct `CognitiveMemoryService` calls.
    Embedded,
    /// HTTP/JSON router calls.
    Http,
    /// Canonical Protobuf/gRPC calls.
    Grpc,
    /// The `contextdb` command-line process.
    Cli,
    /// Standard initialized or stateless MCP JSON-RPC calls.
    Mcp,
}

/// Independently testable compatibility capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Unary observation ingestion.
    ObserveUnary,
    /// Ordered, bounded observation streaming with per-item acknowledgement.
    ObserveStreaming,
    /// Unary recall.
    RecallUnary,
    /// Ordered started/page/completed recall streaming.
    RecallStreaming,
    /// Snapshot- and filter-bound continuation.
    BoundContinuation,
    /// Stable idempotency replay and conflict semantics.
    Idempotency,
    /// Stable structured error code and retryability.
    StructuredErrors,
    /// RFC extended error fields beyond the current v1 profile.
    ExtendedErrorDetails,
    /// Canonical logical archive export/import/replay.
    PortableArchive,
    /// Machine-readable JSON output.
    JsonOutput,
    /// Machine-readable Protobuf output.
    ProtobufOutput,
    /// MCP standard initialization plus 2026-07-28 stateless discovery and metadata.
    Mcp20260728,
    /// Backward-compatible public schema evolution.
    SchemaCompatibility,
    /// Resumable source-revision manifest/item/completion ingestion.
    ResumableIngestion,
    /// Explicit compression negotiation, execution or typed fail-closed proof,
    /// and unknown-value rejection.
    SourceCompression,
    /// Explicit digest-checked snapshot-complete publication marker.
    SnapshotCompletion,
    /// At-least-once subscriptions with stable event IDs and resume cursors.
    AtLeastOnceSubscriptions,
    /// Actor/agent/subject/session/capability/authentication evidence boundary.
    AuthenticatedV1Boundary,
    /// Typed executable correct/retract/hard-delete operations.
    MemoryControl,
    /// Typed node/timeline/evidence/conflict/traversal operations.
    MemoryReadTraverse,
    /// Pure continuity preflight evaluator which can block but never grants authority.
    RuntimePreflight,
    /// Durable content-free receipt for a validated caller-asserted postflight record.
    RuntimePostflightReceipt,
    /// Complete bootstrap/postflight/checkpoint/resume/handoff stateful lifecycle.
    RuntimeLifecycle,
    /// Aggregate executable maintenance/admin surface. A profile remains a gap
    /// until consolidation, reflection, reindex, compaction, status, backup,
    /// restore, and migration claims are all satisfied; one production-only
    /// projection rebuild must not promote the aggregate to exercised.
    MaintenanceAdmin,
    /// Versioned machine-readable runtime capability profile on status/health.
    RuntimeCapabilityManifest,
    /// RFC 21.22 high-level conversation operations.
    ConversationHighLevel,
    /// RFC 21.23 high-level memory controls and subject transfer.
    MemoryControlHighLevel,
    /// RFC 21.24 subject and relationship operations.
    SubjectRelationshipHighLevel,
    /// RFC 21.25 artifact metadata, selector, blob, and lineage operations.
    ArtifactHighLevel,
}

impl Capability {
    /// Complete v1 conformance capability vocabulary in stable order.
    pub const ALL: [Self; 29] = [
        Self::ObserveUnary,
        Self::ObserveStreaming,
        Self::RecallUnary,
        Self::RecallStreaming,
        Self::BoundContinuation,
        Self::Idempotency,
        Self::StructuredErrors,
        Self::ExtendedErrorDetails,
        Self::PortableArchive,
        Self::JsonOutput,
        Self::ProtobufOutput,
        Self::Mcp20260728,
        Self::SchemaCompatibility,
        Self::ResumableIngestion,
        Self::SourceCompression,
        Self::SnapshotCompletion,
        Self::AtLeastOnceSubscriptions,
        Self::AuthenticatedV1Boundary,
        Self::MemoryControl,
        Self::MemoryReadTraverse,
        Self::RuntimePreflight,
        Self::RuntimePostflightReceipt,
        Self::RuntimeLifecycle,
        Self::MaintenanceAdmin,
        Self::RuntimeCapabilityManifest,
        Self::ConversationHighLevel,
        Self::MemoryControlHighLevel,
        Self::SubjectRelationshipHighLevel,
        Self::ArtifactHighLevel,
    ];
}

/// Declared support and proof state for one capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Support {
    /// Implemented and covered by the in-process harness.
    Exercised,
    /// Implemented, but proof needs an explicitly supplied external artifact.
    ExternalProofRequired {
        /// Exact missing artifact or action.
        reason: String,
    },
    /// Intentionally unavailable on this interface.
    NotApplicable {
        /// Why the capability does not belong on this surface.
        reason: String,
    },
    /// Known RFC/profile gap; must not count as conformance success.
    ProfileGap {
        /// Precise missing behavior.
        reason: String,
    },
}

/// Stable declared feature surface for one adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    /// Interface this manifest describes.
    pub interface: InterfaceKind,
    /// Canonical service schema version.
    pub service_schema_version: u16,
    /// Interface protocol identifier.
    pub protocol: String,
    /// Complete deterministic capability map.
    pub capabilities: BTreeMap<Capability, Support>,
}

impl CapabilityManifest {
    /// Creates a manifest. Callers must explicitly classify every capability
    /// before a strict report can pass.
    #[must_use]
    pub fn new(interface: InterfaceKind, protocol: impl Into<String>) -> Self {
        Self {
            interface,
            service_schema_version: contextdb_service::SERVICE_SCHEMA_VERSION,
            protocol: protocol.into(),
            capabilities: BTreeMap::new(),
        }
    }

    /// Adds or replaces one capability classification.
    #[must_use]
    pub fn with(mut self, capability: Capability, support: Support) -> Self {
        self.capabilities.insert(capability, support);
        self
    }

    /// Returns capabilities which have not been explicitly classified.
    #[must_use]
    pub fn unclassified(&self) -> Vec<Capability> {
        Capability::ALL
            .into_iter()
            .filter(|capability| !self.capabilities.contains_key(capability))
            .collect()
    }

    /// True only when no capability is omitted or declared as a gap/external
    /// proof requirement.
    #[must_use]
    pub fn is_strictly_satisfied(&self) -> bool {
        self.unclassified().is_empty()
            && self.capabilities.values().all(|support| {
                matches!(support, Support::Exercised | Support::NotApplicable { .. })
            })
    }
}
