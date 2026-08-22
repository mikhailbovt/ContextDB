use crate::{Capability, CapabilityManifest, InterfaceKind, Support};

fn not_applicable(reason: &str) -> Support {
    Support::NotApplicable {
        reason: reason.to_owned(),
    }
}

fn gap(reason: &str) -> Support {
    Support::ProfileGap {
        reason: reason.to_owned(),
    }
}

/// Capability declaration for direct embedded calls.
#[must_use]
pub fn embedded_manifest() -> CapabilityManifest {
    CapabilityManifest::new(InterfaceKind::Embedded, "contextdb-service/v1")
        .with(Capability::ObserveUnary, Support::Exercised)
        .with(
            Capability::ObserveStreaming,
            Support::Exercised,
        )
        .with(Capability::RecallUnary, Support::Exercised)
        .with(
            Capability::RecallStreaming,
            not_applicable("embedded recall returns a complete typed result"),
        )
        .with(Capability::BoundContinuation, Support::Exercised)
        .with(Capability::Idempotency, Support::Exercised)
        .with(Capability::StructuredErrors, Support::Exercised)
        .with(Capability::ExtendedErrorDetails, Support::Exercised)
        .with(
            Capability::PortableArchive,
            not_applicable(
                "database-global archives require the separate local host-authority boundary",
            ),
        )
        .with(
            Capability::JsonOutput,
            not_applicable("embedded output is a Rust type"),
        )
        .with(
            Capability::ProtobufOutput,
            not_applicable("embedded output is a Rust type"),
        )
        .with(
            Capability::Mcp20260728,
            not_applicable("MCP belongs to the external MCP adapter"),
        )
        .with(
            Capability::SchemaCompatibility,
            not_applicable("wire schema evolution is checked independently"),
        )
        .with(Capability::ResumableIngestion, Support::Exercised)
        .with(Capability::SourceCompression, Support::Exercised)
        .with(Capability::SnapshotCompletion, Support::Exercised)
        .with(Capability::AtLeastOnceSubscriptions, Support::Exercised)
        .with(Capability::AuthenticatedV1Boundary, Support::Exercised)
        .with(Capability::MemoryControl, Support::Exercised)
        .with(Capability::MemoryReadTraverse, Support::Exercised)
        .with(Capability::RuntimePreflight, Support::Exercised)
        .with(
            Capability::RuntimePostflightReceipt,
            gap("the embedded reference service has no durable runtime receipt adapter"),
        )
        .with(
            Capability::RuntimeLifecycle,
            gap("bootstrap/postflight/checkpoint/resume/handoff stateful lifecycle executors are not configured"),
        )
        .with(
            Capability::MaintenanceAdmin,
            gap("status is executable; workspace backup/restore and maintenance executors are unavailable"),
        )
        .with(Capability::RuntimeCapabilityManifest, Support::Exercised)
        .with(Capability::ConversationHighLevel, Support::Exercised)
        .with(
            Capability::MemoryControlHighLevel,
            gap("remember/explain/list plus suppression and exact audience-policy revisions are executable; pin, retention revision, and subject transfer remain absent"),
        )
        .with(
            Capability::SubjectRelationshipHighLevel,
            gap("subject/relationship capture, continuity recall, and shared audience publish/revoke execute; role/runtime executors are absent"),
        )
        .with(
            Capability::ArtifactHighLevel,
            gap("artifact attachment/selector/metadata execute; blob hashing, derived representation, and lineage erasure executors are absent"),
        )
}

/// Capability declaration for HTTP/JSON.
#[must_use]
pub fn http_manifest() -> CapabilityManifest {
    CapabilityManifest::new(InterfaceKind::Http, "HTTP/JSON v1")
        .with(Capability::ObserveUnary, Support::Exercised)
        .with(
            Capability::ObserveStreaming,
            not_applicable("HTTP v1 exposes unary observation and frame calls"),
        )
        .with(Capability::RecallUnary, Support::Exercised)
        .with(
            Capability::RecallStreaming,
            not_applicable("the v1 streaming recall surface is canonical gRPC"),
        )
        .with(Capability::BoundContinuation, Support::Exercised)
        .with(Capability::Idempotency, Support::Exercised)
        .with(Capability::StructuredErrors, Support::Exercised)
        .with(Capability::ExtendedErrorDetails, Support::Exercised)
        .with(
            Capability::PortableArchive,
            not_applicable(
                "database-global archives require the separate local host-authority boundary",
            ),
        )
        .with(Capability::JsonOutput, Support::Exercised)
        .with(
            Capability::ProtobufOutput,
            not_applicable("HTTP v1 uses JSON"),
        )
        .with(
            Capability::Mcp20260728,
            not_applicable("MCP belongs to the external MCP adapter"),
        )
        .with(Capability::SchemaCompatibility, Support::Exercised)
        .with(
            Capability::ResumableIngestion,
            not_applicable(
                "HTTP exposes deterministic frame/page calls; bidirectional resume proof is gRPC",
            ),
        )
        .with(
            Capability::SourceCompression,
            not_applicable(
                "HTTP carries structured JSON; identity executes and non-identity negotiation is proven on canonical gRPC",
            ),
        )
        .with(
            Capability::SnapshotCompletion,
            not_applicable(
                "HTTP supports the marker as a frame call; stream ordering proof is gRPC",
            ),
        )
        .with(
            Capability::AtLeastOnceSubscriptions,
            not_applicable("HTTP exposes finite resume pages; server-stream delivery is gRPC"),
        )
        .with(Capability::AuthenticatedV1Boundary, Support::Exercised)
        .with(Capability::MemoryControl, Support::Exercised)
        .with(Capability::MemoryReadTraverse, Support::Exercised)
        .with(Capability::RuntimePreflight, Support::Exercised)
        .with(
            Capability::RuntimePostflightReceipt,
            gap("HTTP conformance uses the embedded reference service, not the production Fjall receipt adapter"),
        )
        .with(
            Capability::RuntimeLifecycle,
            gap("HTTP bootstrap/postflight/checkpoint/resume/handoff routes are typed but their stateful executors are absent"),
        )
        .with(
            Capability::MaintenanceAdmin,
            gap("HTTP reference status works; workspace backup/restore and maintenance executors return Unsupported"),
        )
        .with(Capability::RuntimeCapabilityManifest, Support::Exercised)
        .with(Capability::ConversationHighLevel, Support::Exercised)
        .with(
            Capability::MemoryControlHighLevel,
            gap("HTTP executes suppression and exact audience-policy revisions; pin, retention revision, and subject transfer remain absent"),
        )
        .with(
            Capability::SubjectRelationshipHighLevel,
            gap("HTTP executes shared audience publish/revoke; role/runtime mutation executors remain absent"),
        )
        .with(
            Capability::ArtifactHighLevel,
            gap("HTTP exposes every named route; external blob and verified lineage-erasure executors remain absent"),
        )
}

/// Capability declaration for canonical gRPC.
#[must_use]
pub fn grpc_manifest() -> CapabilityManifest {
    CapabilityManifest::new(InterfaceKind::Grpc, "contextdb.v1 protobuf/gRPC")
        .with(Capability::ObserveUnary, Support::Exercised)
        .with(Capability::ObserveStreaming, Support::Exercised)
        .with(Capability::RecallUnary, Support::Exercised)
        .with(Capability::RecallStreaming, Support::Exercised)
        .with(Capability::BoundContinuation, Support::Exercised)
        .with(Capability::Idempotency, Support::Exercised)
        .with(Capability::StructuredErrors, Support::Exercised)
        .with(Capability::ExtendedErrorDetails, Support::Exercised)
        .with(
            Capability::PortableArchive,
            not_applicable(
                "database-global archives require the separate local host-authority boundary",
            ),
        )
        .with(
            Capability::JsonOutput,
            not_applicable("gRPC v1 uses Protobuf"),
        )
        .with(Capability::ProtobufOutput, Support::Exercised)
        .with(
            Capability::Mcp20260728,
            not_applicable("MCP belongs to the external MCP adapter"),
        )
        .with(Capability::SchemaCompatibility, Support::Exercised)
        .with(Capability::ResumableIngestion, Support::Exercised)
        .with(Capability::SourceCompression, Support::Exercised)
        .with(Capability::SnapshotCompletion, Support::Exercised)
        .with(Capability::AtLeastOnceSubscriptions, Support::Exercised)
        .with(Capability::AuthenticatedV1Boundary, Support::Exercised)
        .with(Capability::MemoryControl, Support::Exercised)
        .with(Capability::MemoryReadTraverse, Support::Exercised)
        .with(Capability::RuntimePreflight, Support::Exercised)
        .with(
            Capability::RuntimePostflightReceipt,
            gap("gRPC conformance uses the embedded reference service, not the production Fjall receipt adapter"),
        )
        .with(
            Capability::RuntimeLifecycle,
            gap("gRPC bootstrap/postflight/checkpoint/resume/handoff methods are typed but their stateful executors are absent"),
        )
        .with(
            Capability::MaintenanceAdmin,
            gap("gRPC reference status works; workspace backup/restore and maintenance executors return Unsupported"),
        )
        .with(Capability::RuntimeCapabilityManifest, Support::Exercised)
        .with(Capability::ConversationHighLevel, Support::Exercised)
        .with(
            Capability::MemoryControlHighLevel,
            gap("gRPC executes suppression and exact audience-policy revisions; pin, retention revision, and subject transfer remain absent"),
        )
        .with(
            Capability::SubjectRelationshipHighLevel,
            gap("gRPC executes shared audience publish/revoke; role/runtime mutation executors remain absent"),
        )
        .with(
            Capability::ArtifactHighLevel,
            gap("gRPC exposes every named RPC; external blob and verified lineage-erasure executors remain absent"),
        )
}

/// Capability declaration for the CLI subprocess adapter.
#[must_use]
pub fn cli_manifest(executable_available: bool) -> CapabilityManifest {
    let external = || Support::ExternalProofRequired {
        reason: "set an explicit contextdb executable or CONTEXTDB_CONFORMANCE_CLI".to_owned(),
    };
    let exercised = || {
        if executable_available {
            Support::Exercised
        } else {
            external()
        }
    };
    CapabilityManifest::new(InterfaceKind::Cli, "contextdb CLI v1")
        .with(Capability::ObserveUnary, exercised())
        .with(
            Capability::ObserveStreaming,
            not_applicable("CLI ingestion is one request per invocation"),
        )
        .with(Capability::RecallUnary, exercised())
        .with(
            Capability::RecallStreaming,
            not_applicable("CLI recall emits one result per invocation"),
        )
        .with(Capability::BoundContinuation, exercised())
        .with(Capability::Idempotency, exercised())
        .with(Capability::StructuredErrors, exercised())
        .with(Capability::ExtendedErrorDetails, exercised())
        .with(Capability::PortableArchive, exercised())
        .with(Capability::JsonOutput, exercised())
        .with(Capability::ProtobufOutput, exercised())
        .with(
            Capability::Mcp20260728,
            not_applicable("the separate `mcp` subcommand hosts the MCP adapter"),
        )
        .with(Capability::SchemaCompatibility, exercised())
        .with(
            Capability::ResumableIngestion,
            not_applicable("resumable bidirectional ingestion is the canonical gRPC surface"),
        )
        .with(
            Capability::SourceCompression,
            not_applicable("source stream compression is the canonical gRPC surface"),
        )
        .with(
            Capability::SnapshotCompletion,
            not_applicable("source snapshot streams are the canonical gRPC surface"),
        )
        .with(
            Capability::AtLeastOnceSubscriptions,
            not_applicable("the one-shot CLI is not a subscription transport"),
        )
        .with(
            Capability::AuthenticatedV1Boundary,
            exercised(),
        )
        .with(
            Capability::MemoryControl,
            gap("CLI correct/forget are exposed, but the external conformance transcript does not yet exercise both mutation paths"),
        )
        .with(
            Capability::MemoryReadTraverse,
            gap("CLI node/timeline/evidence/conflict/traverse are exposed, but the external conformance transcript does not yet seed and exercise every read family"),
        )
        .with(Capability::RuntimePreflight, exercised())
        .with(Capability::RuntimePostflightReceipt, exercised())
        .with(
            Capability::RuntimeLifecycle,
            Support::ExternalProofRequired {
                reason: "the production CLI implements durable bootstrap/postflight/checkpoint/resume/handoff, but the conformance transcript does not yet exercise a restart-bound lifecycle sequence".to_owned(),
            },
        )
        .with(
            Capability::MaintenanceAdmin,
            gap("the production CLI/Fjall profile executes status, verified policy-graph reindex, bounded scheduler-owned physical compact observation, and restart-safe runtime-ledger GC; consolidation, reflection, live restore, format rewrite, offline repair, lexical/vector/HNSW rebuilds, and an SLO remain absent or unproved"),
        )
        .with(Capability::RuntimeCapabilityManifest, exercised())
        .with(
            Capability::ConversationHighLevel,
            gap("CLI exposes every RFC 21.22 command; the external conformance transcript does not yet exercise the complete group"),
        )
        .with(
            Capability::MemoryControlHighLevel,
            gap("CLI executes suppression and exact audience-policy revisions; pin, retention revision, and subject transfer remain unimplemented or unexercised externally"),
        )
        .with(
            Capability::SubjectRelationshipHighLevel,
            gap("CLI executes shared audience publish/revoke; role/runtime mutation executors remain unimplemented or unexercised externally"),
        )
        .with(
            Capability::ArtifactHighLevel,
            gap("CLI exposes every RFC 21.25 command; external blob and verified lineage-erasure executors remain absent"),
        )
}

/// Capability declaration for initialized MCP and the stateless 2026-07-28 profile.
#[must_use]
pub fn mcp_manifest() -> CapabilityManifest {
    CapabilityManifest::new(InterfaceKind::Mcp, contextdb_mcp::MCP_PROTOCOL_VERSION)
        .with(Capability::ObserveUnary, Support::Exercised)
        .with(
            Capability::ObserveStreaming,
            not_applicable("the MCP tool contract is request/response"),
        )
        .with(Capability::RecallUnary, Support::Exercised)
        .with(
            Capability::RecallStreaming,
            not_applicable("the MCP tool contract returns resultType=complete"),
        )
        .with(Capability::BoundContinuation, Support::Exercised)
        .with(Capability::Idempotency, Support::Exercised)
        .with(Capability::StructuredErrors, Support::Exercised)
        .with(Capability::ExtendedErrorDetails, Support::Exercised)
        .with(
            Capability::PortableArchive,
            not_applicable("global archive tools are deliberately absent from MCP"),
        )
        .with(Capability::JsonOutput, Support::Exercised)
        .with(
            Capability::ProtobufOutput,
            not_applicable("MCP uses JSON-RPC structuredContent"),
        )
        .with(Capability::Mcp20260728, Support::Exercised)
        .with(Capability::SchemaCompatibility, Support::Exercised)
        .with(
            Capability::ResumableIngestion,
            not_applicable("MCP tools are stateless request/response; source streaming is gRPC"),
        )
        .with(
            Capability::SourceCompression,
            not_applicable("source stream compression is the canonical gRPC surface"),
        )
        .with(
            Capability::SnapshotCompletion,
            not_applicable("source snapshot streams are the canonical gRPC surface"),
        )
        .with(
            Capability::AtLeastOnceSubscriptions,
            not_applicable("stateless MCP tools do not hold subscription streams"),
        )
        .with(
            Capability::AuthenticatedV1Boundary,
            Support::Exercised,
        )
        .with(
            Capability::MemoryControl,
            gap("MCP correct is authenticated and executable; retract/hard-delete tools are not part of the RFC 21.11 MCP profile"),
        )
        .with(
            Capability::MemoryReadTraverse,
            gap("MCP node/timeline/evidence/conflict/traverse tools are not exposed"),
        )
        .with(Capability::RuntimePreflight, Support::Exercised)
        .with(
            Capability::RuntimePostflightReceipt,
            gap("MCP conformance uses the embedded reference service, not the production Fjall receipt adapter"),
        )
        .with(
            Capability::RuntimeLifecycle,
            gap("MCP postflight/checkpoint/resume/handoff are authenticated and typed but their stateful executors are not configured; bootstrap is not an RFC 21.11 MCP tool"),
        )
        .with(
            Capability::MaintenanceAdmin,
            gap("MCP exposes verification only, not archive or the complete maintenance/admin surface"),
        )
        .with(
            Capability::RuntimeCapabilityManifest,
            not_applicable("the stateless RFC 21.11 MCP profile has no administrative status or health tool"),
        )
        .with(
            Capability::ConversationHighLevel,
            gap("MCP does not expose RFC 21.22 high-level conversation tools"),
        )
        .with(
            Capability::MemoryControlHighLevel,
            gap("MCP does not expose RFC 21.23 high-level memory controls"),
        )
        .with(
            Capability::SubjectRelationshipHighLevel,
            gap("MCP does not expose RFC 21.24 subject/relationship tools"),
        )
        .with(
            Capability::ArtifactHighLevel,
            gap("MCP does not expose RFC 21.25 artifact tools"),
        )
}
