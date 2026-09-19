//! Fjall-backed production composition for the standalone host.
//!
//! Fjall is the durable primary for domain-separated canonical request digests,
//! content-free receipts, and the current semantic archive projection. It does
//! not retain historical plaintext request payloads. Resumable stream frames
//! use separately derived XChaCha20-Poly1305 envelopes and bounded staging
//! keyspaces. The external state head remains the rollback authority for both
//! semantic projection and the complete monotonic durable-state root. A
//! response is returned only after Fjall and that authority accept the exact
//! generation; startup verifies the successor chain and repairs only a proven
//! lagging authority before exposing reads.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::ops::Deref;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use contextdb_context::{
    CanonicalSerializer, ContextPack, InMemoryContextProvider, ProviderCandidate, ProviderEvidence,
    ReferenceTokenizer, RendererKind,
};
use contextdb_continuity::{
    BootstrapCompiler, BootstrapRequest, ContinuityError, ContinuityPolicyEnvelope,
    HandoffCompiler, HandoffManifest, HandoffRequest, PortableCheckpoint, RuntimeDescriptor,
};
use contextdb_core::{Checkpoint, ContinuityProfile, TimestampMicros};
#[cfg(feature = "current-server")]
use contextdb_server::{
    HealthChecks, HealthProfile, HealthProvider, HealthReason, HealthState, HealthSummary,
};
use contextdb_service::{
    BackupResponse, Capability, CapabilityState, CognitiveMemoryService, CompileContextRequest,
    CompileContextResponse, Compression, CorrectRequest, CreateBackupRequest, ErrorCode,
    ExplainRecallRequest, ExportRequest, ExportResponse, ForgetMode, ForgetRequest,
    GetMemoryRequest, GetStatusRequest, GetTimelineRequest, HighLevelControlRequest,
    HostArchiveAuthority, ImportRequest, ImportResponse, IngestAck, IngestDisposition, IngestFrame,
    IngestFrameValue, MaintenanceRequest, MaintenanceResponse, MemoryRecord, MigrateFormatRequest,
    MutationResponse, ObserveRequest, ObserveResponse, PublishMemoryRequest, RecallRequest,
    RecallResponse, RecallTrace, ReferenceService, RestoreBackupRequest, RestoreBackupResponse,
    RuntimeRequest, RuntimeResponse, ServiceError, ServiceResult, StatusResponse, SubscribeRequest,
    SubscriptionPage, TimelineResponse, TraverseRequest, TraverseResponse, VerifyRequest,
    VerifyResponse, service_capability_manifest_v1, stream_lease_expired_error,
    validate_postflight_submission,
};
use contextdb_storage::{
    CompactRequest, Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine,
    VerifyMode, WriteTransaction,
};
use contextdb_storage_fjall::{
    FJALL_INTERNAL_HEAD_SEQUENCE_KEY, FJALL_INTERNAL_META_KEYSPACE, FjallStorage,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(test)]
use super::admin_context;
use super::{CliError, CliResult, LoadedState, durable_checkpoint_error, service_from_archive};

const STORE_SCHEMA_VERSION: u16 = 1;
const STREAM_SCHEMA_VERSION: u16 = 1;
const STATE_ROOT_VERSION: u16 = 2;
const PROFILE: &str = "production-fjall-v1+reference-canonical-authority+rebuildable-persistent-policy-graph-projection+policy-graph-reindex+encrypted-stream-ingest+pure-runtime-preflight+durable-content-free-postflight-assertion-receipt+durable-runtime-lifecycle-v1+verified-runtime-ledger-health-v1+bounded-runtime-ledger-gc-v1+verified-current-format-preflight-v1;nonclaims=core-native-graph,indexed-graph,vector-index,lexical-index,hnsw,observation-semantic-extraction,tool-execution-verification,offline-repair,async-maintenance,retained-index-generations,reindex-slo,manual-physical-compaction,online-physical-checkpoint;unsupported=hard_delete,live_restore,consolidate,reflect,format-rewrite";

fn production_capability_manifest(profile: &str) -> contextdb_service::CapabilityManifestV1 {
    let mut manifest = service_capability_manifest_v1(
        profile,
        &[
            "bootstrap",
            "checkpoint",
            "compact",
            "context_pack_recall",
            "durable_fjall_storage",
            "durable_postflight_receipt",
            "handoff",
            "restart_verification",
            "resume",
            "runtime_state",
            "status",
            "verify",
        ],
        &[],
    );
    if cfg!(feature = "current-server") {
        manifest
            .capabilities
            .insert("grpc_transport".to_owned(), CapabilityState::Available);
        manifest
            .capabilities
            .insert("http_transport".to_owned(), CapabilityState::Available);
    }
    if cfg!(feature = "server-v1") {
        for capability in [
            "ann_hnsw_runtime",
            "compression_zstd",
            "lexical_tantivy",
            "native_graph_store",
        ] {
            manifest
                .capabilities
                .insert(capability.to_owned(), CapabilityState::CompiledOnly);
        }
    }
    if cfg!(feature = "mcp") {
        manifest
            .capabilities
            .insert("mcp_transport".to_owned(), CapabilityState::Available);
        manifest.capabilities.insert(
            "native_service_executor".to_owned(),
            CapabilityState::CompiledOnly,
        );
    }
    manifest
}
const PRODUCTION_FORMAT_ID: &str = "contextdb.production-fjall.state-root-v2.runtime-ledger-v1";
const HEADER_KEY: &[u8] = b"header";
const HEAD_KEY: &[u8] = b"head";
const CURRENT_PROJECTION_KEY: &[u8] = b"current_projection";
const POLICY_GRAPH_KEY: &[u8] = b"policy_graph_projection";
const DURABLE_GENERATION_KEY: &[u8] = b"durable_generation";
const DURABLE_HEAD_KEY: &[u8] = b"durable_head";
// The byte name is retained for state-root compatibility with stores created
// before maintenance receipts existed. Its value now roots the combined count
// of all non-event receipts (runtime postflight plus policy-graph reindex).
const NON_EVENT_RECEIPT_COUNT_KEY: &[u8] = b"runtime_postflight_count";
const DURABLE_HISTORY_PREFIX: &[u8] = b"durable_history/";
const EVENT_PREFIX: &[u8] = b"event/";
const STREAM_STATE_PREFIX: &[u8] = b"state/";
const STREAM_FRAME_PREFIX: &[u8] = b"frame/";
const STREAM_RECEIPT_PREFIX: &[u8] = b"receipt/";
const STREAM_EXPIRED_PREFIX: &[u8] = b"expired/";
const STREAM_NONCE_PREFIX: &[u8] = b"nonce/";
// Legacy semantic idempotency keys are exactly 64 lowercase ASCII hex bytes.
// A leading NUL therefore makes this runtime namespace structurally disjoint
// without reinterpreting any existing durable state root.
const RUNTIME_POSTFLIGHT_PREFIX: &[u8] = b"\0runtime/postflight/v1/";
const REINDEX_RECEIPT_PREFIX: &[u8] = b"\0maintenance/reindex/v1/";
const RUNTIME_GC_RECEIPT_PREFIX: &[u8] = b"\0maintenance/runtime-gc/v1/";
const RUNTIME_STATE_PREFIX: &[u8] = b"state/v1/";
const RUNTIME_HEAD_PREFIX: &[u8] = b"head/v1/";
const RUNTIME_CHECKPOINT_HEAD_PREFIX: &[u8] = b"checkpoint/v1/";
const RUNTIME_LIFECYCLE_RECEIPT_PREFIX: &[u8] = b"receipt/v1/";
const RUNTIME_GC_ANCHOR_PREFIX: &[u8] = b"gc-anchor/v1/";
const STREAM_RECORD_MAGIC: &[u8; 8] = b"CDBSTRM1";
const STREAM_NONCE_BYTES: usize = 24;
const STREAM_TAG_BYTES: usize = 16;
const MAX_STREAM_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_BUFFERED_BYTES: usize = 64 * 1024 * 1024;
const MAX_STREAM_ITEMS: u64 = 4_096;
const MAX_OPEN_STREAMS: usize = 8;
const MAX_OPEN_STREAMS_PER_WORKSPACE: usize = 2;
const MAX_EXPIRED_STREAMS: usize = 1_000_000;
const MAX_EXPIRED_STREAM_BYTES: usize = 1024 * 1024;
const STREAM_LEASE_MILLIS: u64 = 60 * 60 * 1_000;
const MAX_NON_EVENT_RECEIPTS: usize = 10_000_000;
const MAX_RUNTIME_POSTFLIGHT_RECEIPT_BYTES: usize = 4 * 1024;
const MAX_RUNTIME_LIFECYCLE_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_RUNTIME_LIFECYCLE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RUNTIME_LIFECYCLE_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RUNTIME_LIFECYCLE_RECEIPT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RUNTIME_LIFECYCLE_JSON_DEPTH: usize = 64;
const MAX_RUNTIME_PROVIDER_CANDIDATES: usize = 4_096;
const MAX_RUNTIME_PROVIDER_EVIDENCE: usize = 4_096;
const MAX_RUNTIME_LEDGER_RECORDS: usize = 20_000_000;
const MIN_RUNTIME_RETAINED_STATES: u64 = 2;
const MAX_RUNTIME_RETAINED_STATES: u64 = 4_096;
const MAX_RUNTIME_GC_RECORD_WORK: u64 = 100_000;
const MAX_RUNTIME_GC_PAYLOAD_BYTES: usize = 4 * 1024;
const MAX_RUNTIME_GC_RECEIPT_BYTES: usize = 8 * 1024;
const MAX_RUNTIME_GC_JSON_DEPTH: usize = 16;
const MAX_REINDEX_RECEIPT_BYTES: usize = 4 * 1024;
const MAX_REINDEX_PAYLOAD_BYTES: usize = 4 * 1024;
const MAX_REINDEX_JSON_DEPTH: usize = 16;
const MAX_REINDEX_CANDIDATE_BYTES: usize = 512 * 1024 * 1024;
const MAX_GRAPH_RECORDS: usize = 10_000_000;
const MAX_GRAPH_REVISIONS: usize = 20_000_000;
const MAX_GRAPH_POLICY_VALUES: usize = 4_096;
const MAX_GRAPH_TRAVERSAL_WORK: usize = 2_000_000;
const MAX_GRAPH_ADJACENCY_BYTES: usize = 512 * 1024 * 1024;
const PRODUCTION_META_KEYSPACE: &str = "production_meta";
const PRODUCTION_GRAPH_KEYSPACE: &str = "production_policy_graph_v1";
const PRODUCTION_EVENTS_KEYSPACE: &str = "production_events";
const PRODUCTION_IDEMPOTENCY_KEYSPACE: &str = "production_idempotency";
const PRODUCTION_STREAMS_KEYSPACE: &str = "production_streams";
const PRODUCTION_DURABLE_HISTORY_KEYSPACE: &str = "production_durable_history";
const PRODUCTION_RUNTIME_KEYSPACE: &str = "production_runtime_v1";
// Deleting this impossible application key is a no-op that nevertheless asks
// Fjall to materialize each empty production keyspace in the same transaction.
const KEYSPACE_MATERIALIZATION_KEY: &[u8] = b"\0contextdb/materialize-keyspace/v2";

fn unix_time_millis() -> ServiceResult<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        ServiceError::new(
            ErrorCode::Unavailable,
            "host clock is before the Unix epoch",
            true,
        )
    })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| {
        ServiceError::new(
            ErrorCode::ResourceExhausted,
            "host clock exceeds the production lease representation",
            false,
        )
    })
}

fn stream_lease_deadline(now_ms: u64) -> ServiceResult<u64> {
    now_ms.checked_add(STREAM_LEASE_MILLIS).ok_or_else(|| {
        ServiceError::new(
            ErrorCode::ResourceExhausted,
            "production stream lease deadline is exhausted",
            false,
        )
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Observe,
    PublishMemory,
    Correct,
    Forget,
    Suppress,
    ChangeAudience,
    PublishToSharedMemory,
    RevokeSharedMemory,
    StreamIngest,
}

impl Operation {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Observe => b"observe",
            Self::PublishMemory => b"publish_memory",
            Self::Correct => b"correct",
            Self::Forget => b"forget",
            Self::Suppress => b"suppress",
            Self::ChangeAudience => b"change_audience",
            Self::PublishToSharedMemory => b"publish_to_shared_memory",
            Self::RevokeSharedMemory => b"revoke_shared_memory",
            Self::StreamIngest => b"stream_ingest",
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreHeader {
    schema_version: u16,
    database_id: String,
    base_commit_seq: u64,
    initial_archive_digest: String,
    checksum: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CurrentProjection {
    schema_version: u16,
    database_id: String,
    commit_seq: u64,
    archive_digest: String,
    archive: Vec<u8>,
    checksum: String,
}

/// Rebuildable, content-free projection of the exact canonical logical
/// archive. This is deliberately not the core-native `contextdb-graph`
/// format: the generic logical archive does not contain the UUID identities,
/// spaces, provenance, or exact mutation bytes required to construct that
/// format without inventing semantic facts. It intentionally duplicates stable
/// IDs and policy metadata, so it is part of the closure that a future secure
/// store / hard-delete workflow must suppress, rotate, and verify.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyGraphProjection {
    schema_version: u16,
    database_id: String,
    generation: u64,
    archive_commit_seq: u64,
    archive_digest: String,
    watermarks: GraphWatermarks,
    histories: BTreeMap<String, Vec<GraphRevision>>,
    tombstones: BTreeMap<String, GraphTombstone>,
    journal: Vec<GraphJournalEntry>,
    record_count: u64,
    revision_count: u64,
    edge_revision_count: u64,
    digest: String,
    checksum: String,
}

type PolicyAdjacency =
    BTreeMap<String, BTreeMap<String, BTreeMap<GraphPolicyPartition, BTreeSet<String>>>>;

/// Request-time graph accelerator built only from an already authenticated,
/// byte-exact policy projection. It is deliberately ephemeral: the canonical
/// singleton remains the durable source of truth and this index is rebuilt at
/// open/mutation boundaries. Candidate keys are workspace-partitioned so one
/// tenant's hidden graph cannot add work to another tenant's traversal.
#[derive(Debug)]
struct VerifiedPolicyGraph {
    projection: PolicyGraphProjection,
    /// Candidate edges are partitioned by workspace and endpoint before the
    /// exact policy selector that can make them visible. Requests never inspect
    /// edge revisions from another workspace, do not enumerate unrelated
    /// endpoints, and only inspect edge IDs from policy partitions that already
    /// authorize the caller. This is a bounded-availability index, not a
    /// constant-time/ORAM claim.
    adjacency: PolicyAdjacency,
    semantic_commits: Vec<u64>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GraphPolicyPartition {
    workspace: String,
    scopes: BTreeSet<String>,
    owners: BTreeSet<String>,
    audience: BTreeSet<String>,
    audience_purpose_grants: BTreeMap<String, BTreeSet<String>>,
    purposes: BTreeSet<String>,
    sensitivity: GraphSensitivity,
    consent: GraphConsent,
    retrievable: bool,
}

impl From<&GraphAccess> for GraphPolicyPartition {
    fn from(access: &GraphAccess) -> Self {
        Self {
            workspace: access.workspace.clone(),
            scopes: access.scopes.clone(),
            owners: access.owners.clone(),
            audience: access.audience.clone(),
            audience_purpose_grants: access.audience_purpose_grants.clone(),
            purposes: access.purposes.clone(),
            sensitivity: access.sensitivity,
            consent: access.consent,
            retrievable: access.retrievable,
        }
    }
}

impl GraphPolicyPartition {
    fn allows(&self, principal: &contextdb_service::RequestContext) -> bool {
        graph_policy_allows_parts(
            &self.workspace,
            &self.scopes,
            &self.owners,
            &self.audience,
            &self.audience_purpose_grants,
            &self.purposes,
            self.sensitivity,
            self.consent,
            self.retrievable,
            principal,
        )
    }
}

impl Deref for VerifiedPolicyGraph {
    type Target = PolicyGraphProjection;

    fn deref(&self) -> &Self::Target {
        &self.projection
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphWatermarks {
    journal: u64,
    semantic: u64,
    lexical: u64,
    vector: u64,
    graph: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GraphRecordKind {
    Node,
    Claim,
    Edge,
    Conflict,
    Evidence,
    Candidate,
    SemanticObject,
    RuntimeState,
    DomainExtension,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GraphLifecycle {
    Active,
    Superseded,
    Retracted,
    Suppressed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum GraphSensitivity {
    Public,
    Internal,
    Private,
    Restricted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum GraphConsent {
    Granted,
    Unknown,
    Denied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GraphAccess {
    workspace: String,
    scopes: BTreeSet<String>,
    owners: BTreeSet<String>,
    audience: BTreeSet<String>,
    #[serde(default)]
    audience_purpose_grants: BTreeMap<String, BTreeSet<String>>,
    purposes: BTreeSet<String>,
    sensitivity: GraphSensitivity,
    consent: GraphConsent,
    #[serde(default = "graph_default_true")]
    retrievable: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct GraphValidTime {
    from: Option<i128>,
    to: Option<i128>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct GraphLinks {
    subject: Option<String>,
    source: Option<String>,
    target: Option<String>,
    predicate: Option<String>,
    conflict_set: Option<String>,
    supersedes: BTreeSet<String>,
    evidence: BTreeSet<String>,
    conflict_members: BTreeSet<String>,
    single_valued: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GraphRecordMetadata {
    kind: GraphRecordKind,
    access: GraphAccess,
    valid_time: GraphValidTime,
    lifecycle: GraphLifecycle,
    links: GraphLinks,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GraphRevision {
    id: String,
    revision: u32,
    transaction_from: u64,
    transaction_to: Option<u64>,
    record: GraphRecordMetadata,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GraphTombstone {
    target: String,
    effective_seq: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GraphJournalClass {
    ObservationAccepted,
    SemanticPublished,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GraphJournalEntry {
    commit_seq: u64,
    previous_digest: Option<String>,
    record_digest: String,
    class: GraphJournalClass,
    affected_ids: BTreeSet<String>,
}

#[derive(Deserialize)]
struct GraphArchiveSource {
    format: String,
    database_id: String,
    head: u64,
    watermarks: GraphWatermarks,
    histories: BTreeMap<String, Vec<GraphRevisionSource>>,
    tombstones: BTreeMap<String, GraphTombstoneSource>,
    journal: Vec<GraphJournalSource>,
}

#[derive(Deserialize)]
struct GraphRevisionSource {
    id: String,
    revision: u32,
    transaction_from: u64,
    transaction_to: Option<u64>,
    record: GraphRecordMetadata,
}

#[derive(Deserialize)]
struct GraphTombstoneSource {
    target: String,
    effective_seq: u64,
}

#[derive(Deserialize)]
struct GraphJournalSource {
    commit_seq: u64,
    previous_digest: Option<String>,
    record_digest: String,
    event: GraphJournalEventSource,
}

#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum GraphJournalEventSource {
    ObservationAccepted {},
    SemanticPublished { affected_ids: BTreeSet<String> },
}

const fn graph_default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEvent {
    schema_version: u16,
    sequence: u64,
    operation: Operation,
    previous_event_checksum: Option<String>,
    idempotency_digest: String,
    request_digest: String,
    response_digest: String,
    response_bytes: Vec<u8>,
    projection_commit_seq: u64,
    projection_digest: String,
    checksum: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IdempotencyIndex {
    schema_version: u16,
    sequence: u64,
    request_digest: String,
    checksum: String,
}

/// Content-free runtime receipt. The submission commitment is secret-keyed;
/// no raw identity, outcome, reason, public digest, or request/response bytes
/// are retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRuntimePostflightReceipt {
    schema_version: u16,
    receipt_id: String,
    submission_commitment: String,
    durable_generation: u64,
    checksum: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeLifecycleMethod {
    Bootstrap,
    Checkpoint,
    Resume,
    Handoff,
}

impl RuntimeLifecycleMethod {
    const fn key_name(self) -> &'static [u8] {
        match self {
            Self::Bootstrap => b"bootstrap",
            Self::Checkpoint => b"checkpoint",
            Self::Resume => b"resume",
            Self::Handoff => b"handoff",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum RuntimeCheckpointInputV1 {
    Seal {
        schema_version: u16,
        checkpoint: Box<Checkpoint>,
        continuity_profile: Box<ContinuityProfile>,
        source_runtime: Box<RuntimeDescriptor>,
        policy: Box<ContinuityPolicyEnvelope>,
    },
    Revoke {
        schema_version: u16,
        checkpoint_digest: String,
        expected_version: u64,
        revoked_at: TimestampMicros,
    },
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProviderInputV1 {
    candidates: Vec<ProviderCandidate>,
    evidence: Vec<ProviderEvidence>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBootstrapInputV1 {
    schema_version: u16,
    expected_checkpoint_version: u64,
    request: BootstrapRequest,
    target_runtime: RuntimeDescriptor,
    provider: RuntimeProviderInputV1,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeResumeInputV1 {
    schema_version: u16,
    expected_checkpoint_version: u64,
    request: BootstrapRequest,
    target_runtime: RuntimeDescriptor,
    provider: RuntimeProviderInputV1,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeHandoffInputV1 {
    schema_version: u16,
    expected_checkpoint_version: u64,
    request: HandoffRequest,
    provider: RuntimeProviderInputV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRenderedContextV1 {
    profile_id: String,
    renderer: RendererKind,
    trusted_control: String,
    untrusted_data: String,
    control_tokens: u32,
    data_tokens: u32,
    total_tokens: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCompiledContextV1 {
    pack: ContextPack,
    rendered: RuntimeRenderedContextV1,
    canonical_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBootstrapArtifactV1 {
    migration_id: String,
    workspace_id: String,
    agent_id: String,
    stable_subject: String,
    source_profile: String,
    target_profile: String,
    checkpoint_digest: String,
    compatibility_digest: String,
    target_runtime_digest: String,
    trace_digest: String,
    open_loops_preserved: bool,
    required_memory_refs_preserved: bool,
    compiled: RuntimeCompiledContextV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeHandoffArtifactV1 {
    manifest: HandoffManifest,
    open_loops_preserved: bool,
    compiled: RuntimeCompiledContextV1,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RuntimeLifecycleArtifactV1 {
    Checkpoint {
        checkpoint: Box<PortableCheckpoint>,
    },
    CheckpointRevoked {
        checkpoint_digest: String,
        revoked_at: TimestampMicros,
    },
    Bootstrap {
        result: Box<RuntimeBootstrapArtifactV1>,
    },
    Resume {
        result: Box<RuntimeBootstrapArtifactV1>,
    },
    Handoff {
        result: Box<RuntimeHandoffArtifactV1>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeCheckpointStatus {
    Sealed,
    Bootstrapped,
    Resumed,
    Revoked,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCheckpointStateSummaryV1 {
    checkpoint_digest: String,
    version: u64,
    status: RuntimeCheckpointStatus,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLifecyclePayloadV1 {
    schema_version: u16,
    method: RuntimeLifecycleMethod,
    receipt_id: String,
    state: RuntimeCheckpointStateSummaryV1,
    artifact: RuntimeLifecycleArtifactV1,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRuntimeState {
    schema_version: u16,
    identity_digest: String,
    version: u64,
    previous_state_digest: Option<String>,
    checkpoint: PortableCheckpoint,
    active_runtime: RuntimeDescriptor,
    active_runtime_digest: String,
    status: RuntimeCheckpointStatus,
    last_bootstrap_trace_digest: Option<String>,
    last_pack_digest: Option<String>,
    handoff_count: u64,
    updated_at: TimestampMicros,
    state_digest: String,
    checksum: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRuntimeHead {
    schema_version: u16,
    identity_digest: String,
    version: u64,
    checkpoint_digest: String,
    state_digest: String,
    checksum: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCheckpointHead {
    schema_version: u16,
    checkpoint_digest: String,
    identity_digest: String,
    version: u64,
    status: RuntimeCheckpointStatus,
    state_digest: String,
    checksum: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRuntimeLifecycleReceipt {
    schema_version: u16,
    method: RuntimeLifecycleMethod,
    receipt_id: String,
    request_commitment: String,
    response_digest: String,
    response_bytes: Vec<u8>,
    state_identity_digest: String,
    state_version: u64,
    state_digest: String,
    durable_generation: u64,
    /// A retired receipt keeps the keyed request/response commitments and
    /// durable-generation binding, but deliberately drops the potentially
    /// large response payload. Exact retries then fail with
    /// `ContinuationExpired` instead of aliasing the old operation ID.
    #[serde(default)]
    retired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_at_generation: Option<u64>,
    checksum: String,
}

/// Content-free prefix anchor for a pruned runtime state chain. It preserves
/// the terminal state digest and a keyed accumulator over every removed state,
/// allowing startup verification to resume at the first retained revision
/// without retaining portable checkpoint/model payloads indefinitely.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRuntimeGcAnchor {
    schema_version: u16,
    identity_digest: String,
    pruned_through_version: u64,
    terminal_state_digest: String,
    accumulator_digest: String,
    updated_at_generation: u64,
    checksum: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeLedgerPressure {
    Nominal,
    Elevated,
    Critical,
    Exhausted,
}

/// Aggregate operational proof. It contains no workspace, subject, runtime,
/// checkpoint, operation, or record identifiers and never materializes stored
/// response/checkpoint bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLedgerHealthV1 {
    schema_version: u16,
    verified: bool,
    bounded: bool,
    pressure: RuntimeLedgerPressure,
    gc_available: bool,
    online_physical_checkpoint_available: bool,
    manual_physical_compaction_available: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum CompactPayloadV1 {
    /// Ask the backend for its physical-only compact report. Fjall currently
    /// schedules compaction itself, so this is an observation rather than a
    /// claim that bytes were synchronously reclaimed.
    Physical {
        schema_version: u16,
        max_bytes: Option<u64>,
    },
    /// Prune a bounded prefix of runtime state/checkpoint payload history and
    /// retire affected replay receipts to content-free commitments.
    RuntimeLedgerGc {
        schema_version: u16,
        retain_state_versions: u64,
        max_record_work: u64,
        dry_run: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeLedgerGcReportV1 {
    schema_version: u16,
    status: String,
    dry_run: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    replayed: bool,
    durable_receipt_recorded: bool,
    state_records_pruned: u64,
    checkpoint_heads_pruned: u64,
    receipts_retired: u64,
    anchors_updated: u64,
    logical_state_changed: bool,
    physical_bytes_reclaimed: Option<u64>,
    replay_policy: String,
}

struct RuntimeLedgerGcPlan {
    state_keys: BTreeSet<Vec<u8>>,
    checkpoint_head_keys: BTreeSet<Vec<u8>>,
    retired_receipts: BTreeMap<Vec<u8>, StoredRuntimeLifecycleReceipt>,
    anchors: BTreeMap<Vec<u8>, StoredRuntimeGcAnchor>,
}

struct RuntimeLedgerMutation {
    expected: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    writes: BTreeMap<Vec<u8>, Vec<u8>>,
    resulting_state: StoredRuntimeState,
}

struct LoadedRuntimeState {
    state: StoredRuntimeState,
    runtime_head: StoredRuntimeHead,
    runtime_head_bytes: Vec<u8>,
    checkpoint_head: StoredCheckpointHead,
    checkpoint_head_bytes: Vec<u8>,
}

struct RuntimeTransition {
    expected_version: u64,
    status: RuntimeCheckpointStatus,
    active_runtime: RuntimeDescriptor,
    updated_at: TimestampMicros,
    bootstrap_trace_digest: Option<String>,
    pack_digest: Option<String>,
    increment_handoff: bool,
}

struct RuntimeBootstrapExecution {
    method: RuntimeLifecycleMethod,
    expected_checkpoint_version: u64,
    request: BootstrapRequest,
    target_runtime: RuntimeDescriptor,
    provider: RuntimeProviderInputV1,
}

/// Exact, bounded maintenance DTO for the only production reindex slice.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReindexPayloadV1 {
    schema_version: u16,
    projection: String,
}

/// Content-free receipt for a verified rebuild of the current policy graph.
/// Both commitments are secret-keyed; caller identity, operation ID, archive
/// identity, graph identity, and payload bytes are deliberately absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredReindexReceipt {
    schema_version: u16,
    receipt_id: String,
    request_commitment: String,
    source_commitment: String,
    durable_generation: u64,
    checksum: String,
}

/// Content-free exact-retry receipt for one applied runtime-ledger GC request.
/// The response contains aggregate counts only; operation/caller identity is
/// represented solely by secret-keyed commitments and the namespaced key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRuntimeGcReceipt {
    schema_version: u16,
    receipt_id: String,
    request_commitment: String,
    response_payload: serde_json::Value,
    durable_generation: u64,
    checksum: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableLedgerHead {
    schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_root_version: Option<u16>,
    generation: u64,
    previous_digest: Option<String>,
    state_root: String,
    digest: String,
    checksum: String,
}

/// Exact process-local proof of the Fjall tip which was fully verified,
/// reconciled with the external authority, and published. This is only a
/// cache: any physical sequence or point-read mismatch discards it and returns
/// to the complete closed-world verification/replay path.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ReconciledTip {
    storage_sequence: u64,
    production_head: u64,
    database_id: String,
    projection_commit_seq: u64,
    projection_digest: String,
    durable: DurableLedgerHead,
    runtime_health: RuntimeLedgerHealthV1,
}

/// Exact output of one synchronized semantic Fjall transaction. Every member
/// is prepared and checked before commit, then point-bound to the committed
/// physical sequence before the external authority and in-process publication
/// may advance.
struct CommittedSemanticPublication {
    storage_sequence: u64,
    identity: super::state_head::ArchiveIdentity,
    durable: DurableLedgerHead,
    graph: Arc<VerifiedPolicyGraph>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredStreamState {
    schema_version: u16,
    stream_digest: String,
    workspace_id: String,
    stream_id: String,
    authorization_digest: String,
    next_position: u64,
    buffered_bytes: u64,
    /// Host-controlled absolute lease. Zero is the legacy pre-lease encoding
    /// and is reclaimed before another frame can be accepted.
    #[serde(default)]
    lease_expires_at_ms: u64,
}

/// Minimal replay material. Authentication evidence, transient request IDs,
/// and capability grants are deliberately never persisted, even encrypted.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredStreamFrame {
    schema_version: u16,
    stream_id: String,
    position: u64,
    resume_cursor: Option<String>,
    value: IngestFrameValue,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredStreamReceipt {
    schema_version: u16,
    position: u64,
    request_digest: String,
    acknowledgement: IngestAck,
}

/// Encrypted, content-free permanent reservation for an expired stream ID.
/// Request digests are secret-keyed and retain no frame or authentication
/// payload. The tombstone makes stale retries deterministic without allowing a
/// former cursor to alias a new stream incarnation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredExpiredStream {
    schema_version: u16,
    stream_digest: String,
    workspace_id: String,
    stream_id: String,
    authorization_digest: String,
    lease_expires_at_ms: u64,
    request_digests: BTreeMap<u64, String>,
}

struct LoadedStream {
    state: StoredStreamState,
    frames: BTreeMap<u64, StoredStreamFrame>,
    receipts: BTreeMap<u64, StoredStreamReceipt>,
}

/// Marks a durable mutation receipt as an exact replay without rewriting the
/// immutable first-response bytes stored in the Fjall event log.
trait ReplayReceipt {
    fn mark_replayed(&mut self);
}

impl ReplayReceipt for ObserveResponse {
    fn mark_replayed(&mut self) {
        self.replayed = true;
    }
}

impl ReplayReceipt for MutationResponse {
    fn mark_replayed(&mut self) {
        self.replayed = true;
    }
}

struct ProductionStore {
    engine: FjallStorage,
    meta: Keyspace,
    graph: Keyspace,
    events: Keyspace,
    idempotency: Keyspace,
    streams: Keyspace,
    durable_history: Keyspace,
    runtime: Keyspace,
    mac_key: Arc<Zeroizing<[u8; 32]>>,
    stream_aead_key: Arc<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for ProductionStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionStore")
            .field("backend", &"fjall")
            .field("mac_key", &"[REDACTED]")
            .field("stream_aead_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ProductionStore {
    fn initialize(path: &Path, archive: &[u8], token_key: &[u8; 32]) -> CliResult<Self> {
        let store_path = store_path(path);
        let engine = FjallStorage::open(&store_path).map_err(storage_error)?;
        let store = Self::new(engine, token_key)?;
        let snapshot = store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if snapshot
            .get(&store.meta, HEADER_KEY)
            .map_err(storage_error)?
            .is_some()
        {
            drop(snapshot);
            let header = store.header()?;
            if header.initial_archive_digest != blake3::hash(archive).to_hex().to_string() {
                return Err(integrity("production store is bound to another base archive").into());
            }
            store.ensure_current_format()?;
            return Ok(store);
        }
        drop(snapshot);

        let identity = super::state_head::inspect_archive(archive).map_err(CliError::from)?;
        let mut header = StoreHeader {
            schema_version: STORE_SCHEMA_VERSION,
            database_id: identity.database_id.clone(),
            base_commit_seq: identity.commit_seq,
            initial_archive_digest: identity.archive_digest.clone(),
            checksum: String::new(),
        };
        header.checksum = store.record_checksum(b"production-header-v1", &header)?;
        let mut projection = CurrentProjection {
            schema_version: STORE_SCHEMA_VERSION,
            database_id: identity.database_id,
            commit_seq: identity.commit_seq,
            archive_digest: identity.archive_digest,
            archive: archive.to_vec(),
            checksum: String::new(),
        };
        projection.checksum = store.record_checksum(b"production-projection-v1", &projection)?;
        let graph = store.build_policy_graph_projection(archive, 0)?;
        let bytes = canonical_bytes(&header)?;
        let mut transaction = store.engine.begin_write().map_err(storage_error)?;
        store.materialize_production_keyspaces(&mut transaction)?;
        transaction
            .put(&store.meta, HEADER_KEY.to_vec(), bytes)
            .map_err(storage_error)?;
        transaction
            .put(
                &store.meta,
                CURRENT_PROJECTION_KEY.to_vec(),
                canonical_bytes(&projection)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &store.graph,
                POLICY_GRAPH_KEY.to_vec(),
                canonical_bytes(&graph)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(&store.meta, HEAD_KEY.to_vec(), 0_u64.to_be_bytes().to_vec())
            .map_err(storage_error)?;
        transaction
            .put(
                &store.meta,
                NON_EVENT_RECEIPT_COUNT_KEY.to_vec(),
                0_u64.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        let state_root = store.compute_state_root_v2(&transaction)?;
        let mut durable = DurableLedgerHead {
            schema_version: STREAM_SCHEMA_VERSION,
            state_root_version: Some(STATE_ROOT_VERSION),
            generation: 0,
            previous_digest: None,
            state_root,
            digest: String::new(),
            checksum: String::new(),
        };
        durable.digest = store.durable_digest(&durable)?;
        durable.checksum = store.record_checksum(b"production-durable-head-v1", &durable)?;
        transaction
            .put(
                &store.meta,
                DURABLE_GENERATION_KEY.to_vec(),
                0_u64.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &store.meta,
                DURABLE_HEAD_KEY.to_vec(),
                canonical_bytes(&durable)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &store.durable_history,
                durable_history_key(0),
                canonical_bytes(&durable)?,
            )
            .map_err(storage_error)?;
        let receipt = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        if receipt.durability != Durability::Sync {
            return Err(unavailable("Fjall did not achieve synchronized durability").into());
        }
        Ok(store)
    }

    fn open(path: &Path, token_key: &[u8; 32]) -> CliResult<Self> {
        let store_path = store_path(path);
        if !store_path.is_dir() {
            return Err(ServiceError::new(
                ErrorCode::Unavailable,
                "production Fjall state is absent; initialize or import this database with the current ContextDB CLI",
                false,
            )
            .into());
        }
        let store = Self::new(
            FjallStorage::open(store_path).map_err(storage_error)?,
            token_key,
        )?;
        store.header()?;
        store.ensure_current_format()?;
        Ok(store)
    }

    fn new(engine: FjallStorage, token_key: &[u8; 32]) -> CliResult<Self> {
        let mac_key = blake3::derive_key("contextdb/production-ledger-mac-key/v1", token_key);
        let stream_aead_key =
            blake3::derive_key("contextdb/production-stream-aead-key/v1", token_key);
        Ok(Self {
            engine,
            meta: Keyspace::new(PRODUCTION_META_KEYSPACE).map_err(storage_error)?,
            graph: Keyspace::new(PRODUCTION_GRAPH_KEYSPACE).map_err(storage_error)?,
            events: Keyspace::new(PRODUCTION_EVENTS_KEYSPACE).map_err(storage_error)?,
            idempotency: Keyspace::new(PRODUCTION_IDEMPOTENCY_KEYSPACE).map_err(storage_error)?,
            streams: Keyspace::new(PRODUCTION_STREAMS_KEYSPACE).map_err(storage_error)?,
            durable_history: Keyspace::new(PRODUCTION_DURABLE_HISTORY_KEYSPACE)
                .map_err(storage_error)?,
            runtime: Keyspace::new(PRODUCTION_RUNTIME_KEYSPACE).map_err(storage_error)?,
            mac_key: Arc::new(Zeroizing::new(mac_key)),
            stream_aead_key: Arc::new(Zeroizing::new(stream_aead_key)),
        })
    }

    fn materialize_production_keyspaces(
        &self,
        transaction: &mut impl WriteTransaction,
    ) -> CliResult<()> {
        for keyspace in [
            &self.meta,
            &self.graph,
            &self.events,
            &self.idempotency,
            &self.streams,
            &self.durable_history,
            &self.runtime,
        ] {
            transaction
                .delete(keyspace, KEYSPACE_MATERIALIZATION_KEY.to_vec())
                .map_err(storage_error)?;
        }
        Ok(())
    }

    fn materialize_runtime_keyspace_if_missing(&self) -> CliResult<()> {
        if self
            .engine
            .physical_keyspace_names()
            .iter()
            .any(|name| name == PRODUCTION_RUNTIME_KEYSPACE)
        {
            return Ok(());
        }
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        transaction
            .delete(&self.runtime, KEYSPACE_MATERIALIZATION_KEY.to_vec())
            .map_err(storage_error)?;
        let committed = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(committed.durability)
    }

    fn verify_physical_keyspaces(&self, require_complete: bool) -> CliResult<()> {
        let expected = BTreeSet::from([
            FJALL_INTERNAL_META_KEYSPACE.to_owned(),
            PRODUCTION_META_KEYSPACE.to_owned(),
            PRODUCTION_GRAPH_KEYSPACE.to_owned(),
            PRODUCTION_EVENTS_KEYSPACE.to_owned(),
            PRODUCTION_IDEMPOTENCY_KEYSPACE.to_owned(),
            PRODUCTION_STREAMS_KEYSPACE.to_owned(),
            PRODUCTION_DURABLE_HISTORY_KEYSPACE.to_owned(),
            PRODUCTION_RUNTIME_KEYSPACE.to_owned(),
        ]);
        let actual = self
            .engine
            .physical_keyspace_names()
            .into_iter()
            .collect::<BTreeSet<_>>();
        if !actual.is_subset(&expected) || require_complete && actual != expected {
            return Err(integrity("production physical keyspace set is not exact").into());
        }
        Ok(())
    }

    /// Closed-world classification for every physical record. Prefix scans
    /// elsewhere are safe only after this rejects non-prefix and future keys.
    fn verify_key_layout(
        &self,
        snapshot: &impl ReadSnapshot,
        allow_missing_graph: bool,
        allow_missing_non_event_receipt_count: bool,
    ) -> CliResult<u64> {
        let backend_meta = Keyspace::new(FJALL_INTERNAL_META_KEYSPACE).map_err(storage_error)?;
        let backend_entries = snapshot
            .scan_prefix(&backend_meta, b"")
            .map_err(storage_error)?;
        if backend_entries.len() != 1
            || backend_entries[0].key != FJALL_INTERNAL_HEAD_SEQUENCE_KEY
            || decode_u64_exact(&backend_entries[0].value, "Fjall head sequence")?
                != snapshot.sequence()
        {
            return Err(integrity("Fjall internal metadata is not exact").into());
        }

        let meta_entries = snapshot
            .scan_prefix(&self.meta, b"")
            .map_err(storage_error)?;
        let actual_meta = meta_entries
            .iter()
            .map(|entry| entry.key.as_slice())
            .collect::<BTreeSet<_>>();
        let required_meta = BTreeSet::from([
            HEADER_KEY,
            HEAD_KEY,
            CURRENT_PROJECTION_KEY,
            DURABLE_GENERATION_KEY,
            DURABLE_HEAD_KEY,
        ]);
        let mut permitted_meta = required_meta.clone();
        permitted_meta.insert(NON_EVENT_RECEIPT_COUNT_KEY);
        if !required_meta.is_subset(&actual_meta)
            || !actual_meta.is_subset(&permitted_meta)
            || !allow_missing_non_event_receipt_count
                && !actual_meta.contains(NON_EVENT_RECEIPT_COUNT_KEY)
        {
            return Err(integrity("production metadata key set is not exact").into());
        }

        let graph_entries = snapshot
            .scan_prefix(&self.graph, b"")
            .map_err(storage_error)?;
        if !(graph_entries.len() == 1 && graph_entries[0].key == POLICY_GRAPH_KEY)
            && !(allow_missing_graph && graph_entries.is_empty())
        {
            return Err(integrity("production policy graph key set is not exact").into());
        }

        for entry in snapshot
            .scan_prefix(&self.events, b"")
            .map_err(storage_error)?
        {
            parse_exact_sequence_key(&entry.key, EVENT_PREFIX, "production event")?;
        }
        for entry in snapshot
            .scan_prefix(&self.durable_history, b"")
            .map_err(storage_error)?
        {
            parse_exact_sequence_key(
                &entry.key,
                DURABLE_HISTORY_PREFIX,
                "production durable history",
            )?;
        }

        let mut non_event_receipt_count = 0_u64;
        for entry in snapshot
            .scan_prefix(&self.idempotency, b"")
            .map_err(storage_error)?
        {
            if entry.key.starts_with(RUNTIME_POSTFLIGHT_PREFIX) {
                validate_runtime_postflight_key(&entry.key)?;
                non_event_receipt_count = non_event_receipt_count
                    .checked_add(1)
                    .ok_or_else(|| integrity("production non-event receipt count is exhausted"))?;
            } else if entry.key.starts_with(REINDEX_RECEIPT_PREFIX) {
                validate_reindex_receipt_key(&entry.key)?;
                non_event_receipt_count = non_event_receipt_count
                    .checked_add(1)
                    .ok_or_else(|| integrity("production non-event receipt count is exhausted"))?;
            } else if entry.key.starts_with(RUNTIME_GC_RECEIPT_PREFIX) {
                validate_runtime_gc_receipt_key(&entry.key)?;
                non_event_receipt_count = non_event_receipt_count
                    .checked_add(1)
                    .ok_or_else(|| integrity("production non-event receipt count is exhausted"))?;
            } else if !is_canonical_digest_bytes(&entry.key) {
                return Err(integrity(
                    "production idempotency keyspace contains an unknown namespace",
                )
                .into());
            }
        }
        let runtime_entries = snapshot
            .scan_prefix(&self.runtime, b"")
            .map_err(storage_error)?;
        if runtime_entries.len() > MAX_RUNTIME_LEDGER_RECORDS {
            return Err(integrity("production runtime ledger record cap was exceeded").into());
        }
        for entry in runtime_entries {
            if classify_runtime_ledger_key(&entry.key)? == RuntimeLedgerKeyKind::Receipt {
                non_event_receipt_count = non_event_receipt_count
                    .checked_add(1)
                    .ok_or_else(|| integrity("production non-event receipt count is exhausted"))?;
            }
        }
        if non_event_receipt_count > u64::try_from(MAX_NON_EVENT_RECEIPTS).unwrap_or(u64::MAX) {
            return Err(integrity("production non-event receipt cap was exceeded").into());
        }

        for entry in snapshot
            .scan_prefix(&self.streams, b"")
            .map_err(storage_error)?
        {
            classify_stream_key(&entry.key)?;
        }
        Ok(non_event_receipt_count)
    }

    fn header(&self) -> CliResult<StoreHeader> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let bytes = snapshot
            .get(&self.meta, HEADER_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production store header is missing"))?;
        let header: StoreHeader = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("production store header is invalid"))?;
        validate_header(&self.mac_key, &header)?;
        Ok(header)
    }

    fn current_projection(&self) -> CliResult<CurrentProjection> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let bytes = snapshot
            .get(&self.meta, CURRENT_PROJECTION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production current projection is missing"))?;
        let projection: CurrentProjection = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("production current projection is invalid"))?;
        validate_projection(&self.mac_key, &projection)?;
        Ok(projection)
    }

    fn build_policy_graph_projection(
        &self,
        archive: &[u8],
        generation: u64,
    ) -> CliResult<PolicyGraphProjection> {
        let mut projection = project_archive_metadata(archive, generation)?;
        VerifiedPolicyGraph::validate_bounds(&projection)?;
        projection.digest = policy_graph_digest(&projection)?;
        projection.checksum = self.record_checksum(b"production-policy-graph-v1", &projection)?;
        Ok(projection)
    }

    fn policy_graph_from(&self, snapshot: &impl ReadSnapshot) -> CliResult<PolicyGraphProjection> {
        let entries = snapshot
            .scan_prefix(&self.graph, b"")
            .map_err(storage_error)?;
        if entries.len() != 1 || entries[0].key != POLICY_GRAPH_KEY {
            return Err(integrity(
                "production policy graph keyspace is absent, incomplete, or contains orphan records",
            )
            .into());
        }
        let graph: PolicyGraphProjection = serde_json::from_slice(&entries[0].value)
            .map_err(|_| integrity("production policy graph projection is invalid"))?;
        if graph.schema_version != STORE_SCHEMA_VERSION
            || graph.digest != policy_graph_digest(&graph)?
            || graph.checksum != self.record_checksum(b"production-policy-graph-v1", &graph)?
        {
            return Err(integrity(
                "production policy graph projection failed integrity validation",
            )
            .into());
        }
        let current_bytes = snapshot
            .get(&self.meta, CURRENT_PROJECTION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production current projection is missing"))?;
        let current: CurrentProjection = serde_json::from_slice(&current_bytes)
            .map_err(|_| integrity("production current projection is invalid"))?;
        validate_projection(&self.mac_key, &current)?;
        let production_head = self.head(snapshot)?;
        let expected = self.build_policy_graph_projection(&current.archive, production_head)?;
        if graph != expected
            || graph.database_id != current.database_id
            || graph.archive_commit_seq != current.commit_seq
            || graph.archive_digest != current.archive_digest
            || graph.generation != production_head
        {
            return Err(integrity(
                "production policy graph does not exactly rebuild from the canonical archive",
            )
            .into());
        }
        Ok(graph)
    }

    fn policy_graph(&self) -> CliResult<PolicyGraphProjection> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.policy_graph_from(&snapshot)
    }

    /// The only implicit migration admitted by this format: an otherwise
    /// exact, untouched generation-zero store created by the immediately
    /// preceding production profile. The graph and a new durable successor
    /// are installed atomically; any mutation, open stream, unknown key, or
    /// inconsistent legacy root makes migration fail closed.
    fn ensure_current_format(&self) -> CliResult<()> {
        self.verify_physical_keyspaces(false)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let durable = self.durable_head_from(&snapshot)?;
        let graph_entries = snapshot
            .scan_prefix(&self.graph, b"")
            .map_err(storage_error)?;
        let graph_missing = graph_entries.is_empty();
        let legacy = durable.state_root_version.is_none();
        let non_event_receipt_count = self.verify_key_layout(&snapshot, legacy, legacy)?;
        self.verify_durable_history()?;

        if !legacy {
            if graph_missing {
                return Err(
                    integrity("current production format is missing its policy graph").into(),
                );
            }
            let rooted_count = self.non_event_receipt_count(&snapshot)?;
            if rooted_count != non_event_receipt_count {
                return Err(integrity("production non-event receipt count changed").into());
            }
            drop(snapshot);
            self.materialize_runtime_keyspace_if_missing()?;
            self.verify_physical_keyspaces(true)?;
            return Ok(());
        }

        if snapshot
            .get(&self.meta, NON_EVENT_RECEIPT_COUNT_KEY)
            .map_err(storage_error)?
            .is_some()
        {
            return Err(
                integrity("legacy production root contains an unrooted receipt count").into(),
            );
        }
        if !snapshot
            .scan_prefix(&self.runtime, b"")
            .map_err(storage_error)?
            .is_empty()
        {
            return Err(integrity("legacy production root contains unrooted runtime state").into());
        }
        if graph_missing
            && (self.head(&snapshot)? != 0
                || !snapshot
                    .scan_prefix(&self.events, b"")
                    .map_err(storage_error)?
                    .is_empty()
                || !snapshot
                    .scan_prefix(&self.idempotency, b"")
                    .map_err(storage_error)?
                    .is_empty()
                || !snapshot
                    .scan_prefix(&self.streams, b"")
                    .map_err(storage_error)?
                    .is_empty()
                || non_event_receipt_count != 0)
        {
            return Err(integrity(
                "policy graph migration is permitted only for an exact fresh production generation",
            )
            .into());
        }
        let history = snapshot
            .scan_prefix(&self.durable_history, b"")
            .map_err(storage_error)?;
        if graph_missing
            && (durable.generation != 0
                || history.len() != 1
                || history[0].key != durable_history_key(0)
                || serde_json::from_slice::<DurableLedgerHead>(&history[0].value)
                    .map_or(true, |record| record != durable)
                || durable.state_root != self.compute_legacy_state_root(&snapshot)?)
        {
            return Err(integrity(
                "missing policy graph is not bound to an exact legacy generation-zero root",
            )
            .into());
        }
        let graph = if graph_missing {
            let current = self.current_projection()?;
            Some(self.build_policy_graph_projection(&current.archive, 0)?)
        } else {
            None
        };
        drop(snapshot);

        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if self.durable_head_from(&transaction)? != durable
            || transaction
                .get(&self.meta, NON_EVENT_RECEIPT_COUNT_KEY)
                .map_err(storage_error)?
                .is_some()
            || graph_missing
                && (self.head(&transaction)? != 0
                    || !transaction
                        .scan_prefix(&self.graph, b"")
                        .map_err(storage_error)?
                        .is_empty())
        {
            return Err(integrity("production state changed during format migration").into());
        }
        self.materialize_production_keyspaces(&mut transaction)?;
        if let Some(graph) = graph {
            transaction
                .put(
                    &self.graph,
                    POLICY_GRAPH_KEY.to_vec(),
                    canonical_bytes(&graph)?,
                )
                .map_err(storage_error)?;
        }
        transaction
            .put(
                &self.meta,
                NON_EVENT_RECEIPT_COUNT_KEY.to_vec(),
                non_event_receipt_count.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        self.stage_durable_successor(&mut transaction)?;
        let receipt = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(receipt.durability)?;
        self.verify_physical_keyspaces(true)
    }

    fn compute_legacy_state_root(&self, snapshot: &impl ReadSnapshot) -> CliResult<String> {
        #[derive(Serialize)]
        struct LegacyStateRoot<'a> {
            schema_version: u16,
            production_head: u64,
            projection_digest: &'a str,
            projection_commit_seq: u64,
            event_entries: Vec<(Vec<u8>, String)>,
            idempotency_entries: Vec<(Vec<u8>, String)>,
            stream_entries: Vec<(Vec<u8>, String)>,
        }

        let projection_bytes = snapshot
            .get(&self.meta, CURRENT_PROJECTION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production current projection is missing"))?;
        let projection: CurrentProjection = serde_json::from_slice(&projection_bytes)
            .map_err(|_| integrity("production current projection is invalid"))?;
        validate_projection(&self.mac_key, &projection)?;
        let map_entries = |entries: Vec<contextdb_storage::Entry>| {
            entries
                .into_iter()
                .map(|entry| (entry.key, self.digest(b"durable_state_value", &entry.value)))
                .collect::<Vec<_>>()
        };
        let root = LegacyStateRoot {
            schema_version: STREAM_SCHEMA_VERSION,
            production_head: self.head(snapshot)?,
            projection_digest: &projection.archive_digest,
            projection_commit_seq: projection.commit_seq,
            event_entries: map_entries(
                snapshot
                    .scan_prefix(&self.events, b"")
                    .map_err(storage_error)?,
            ),
            idempotency_entries: map_entries(
                snapshot
                    .scan_prefix(&self.idempotency, b"")
                    .map_err(storage_error)?,
            ),
            stream_entries: map_entries(
                snapshot
                    .scan_prefix(&self.streams, b"")
                    .map_err(storage_error)?,
            ),
        };
        Ok(self.digest(b"durable_state_root", &canonical_bytes(&root)?))
    }

    fn head(&self, snapshot: &impl ReadSnapshot) -> CliResult<u64> {
        let bytes = snapshot
            .get(&self.meta, HEAD_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production store head is missing"))?;
        let value: [u8; 8] = bytes
            .try_into()
            .map_err(|_| integrity("production store head is malformed"))?;
        Ok(u64::from_be_bytes(value))
    }

    fn head_from_latest(&self) -> CliResult<u64> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.head(&snapshot)
    }

    fn durable_head_from(&self, snapshot: &impl ReadSnapshot) -> CliResult<DurableLedgerHead> {
        let generation_bytes = snapshot
            .get(&self.meta, DURABLE_GENERATION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production durable generation is missing"))?;
        let generation: [u8; 8] = generation_bytes
            .try_into()
            .map_err(|_| integrity("production durable generation is malformed"))?;
        let generation = u64::from_be_bytes(generation);
        let bytes = snapshot
            .get(&self.meta, DURABLE_HEAD_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production durable head is missing"))?;
        let head: DurableLedgerHead = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("production durable head is invalid"))?;
        self.validate_durable_head(&head, generation)?;
        Ok(head)
    }

    fn validate_durable_head(&self, head: &DurableLedgerHead, generation: u64) -> CliResult<()> {
        if head.schema_version != STREAM_SCHEMA_VERSION
            || !matches!(head.state_root_version, None | Some(STATE_ROOT_VERSION))
            || head.generation != generation
            || head.generation == 0 && head.previous_digest.is_some()
            || head.generation > 0 && head.previous_digest.is_none()
            || head
                .previous_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest, "previous durable digest").is_err())
            || validate_digest(&head.state_root, "durable state root").is_err()
            || validate_digest(&head.digest, "durable ledger digest").is_err()
            || head.digest != self.durable_digest(head)?
            || head.checksum != self.record_checksum(b"production-durable-head-v1", head)?
        {
            return Err(integrity("production durable ledger head failed validation").into());
        }
        Ok(())
    }

    fn durable_digest(&self, head: &DurableLedgerHead) -> CliResult<String> {
        let mut unsigned = head.clone();
        unsigned.digest.clear();
        unsigned.checksum.clear();
        Ok(self.digest(b"durable_ledger_head", &canonical_bytes(&unsigned)?))
    }

    fn prepare_durable_successor(
        &self,
        transaction: &impl ReadSnapshot,
    ) -> CliResult<DurableLedgerHead> {
        let current = self.durable_head_from(transaction)?;
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| integrity("production durable generation is exhausted"))?;
        let state_root = self.compute_state_root_v2(transaction)?;
        let mut successor = DurableLedgerHead {
            schema_version: STREAM_SCHEMA_VERSION,
            state_root_version: Some(STATE_ROOT_VERSION),
            generation,
            previous_digest: Some(current.digest),
            state_root,
            digest: String::new(),
            checksum: String::new(),
        };
        successor.digest = self.durable_digest(&successor)?;
        successor.checksum = self.record_checksum(b"production-durable-head-v1", &successor)?;
        Ok(successor)
    }

    fn stage_durable_successor(
        &self,
        transaction: &mut impl WriteTransaction,
    ) -> CliResult<DurableLedgerHead> {
        let successor = self.prepare_durable_successor(transaction)?;
        if transaction
            .get(
                &self.durable_history,
                &durable_history_key(successor.generation),
            )
            .map_err(storage_error)?
            .is_some()
        {
            return Err(integrity("production durable history changed concurrently").into());
        }
        transaction
            .put(
                &self.meta,
                DURABLE_GENERATION_KEY.to_vec(),
                successor.generation.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                DURABLE_HEAD_KEY.to_vec(),
                canonical_bytes(&successor)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.durable_history,
                durable_history_key(successor.generation),
                canonical_bytes(&successor)?,
            )
            .map_err(storage_error)?;
        Ok(successor)
    }

    /// Legacy graph-aware root used by the immediately preceding production
    /// format. It must remain byte-for-byte stable so an old head can be
    /// authenticated before the one-way v2 successor migration.
    fn compute_state_root_v1(&self, snapshot: &impl ReadSnapshot) -> CliResult<String> {
        #[derive(Serialize)]
        struct StateRoot<'a> {
            schema_version: u16,
            production_head: u64,
            projection_digest: &'a str,
            projection_commit_seq: u64,
            graph_entries: Vec<(Vec<u8>, String)>,
            event_entries: Vec<(Vec<u8>, String)>,
            idempotency_entries: Vec<(Vec<u8>, String)>,
            stream_entries: Vec<(Vec<u8>, String)>,
        }

        let production_head = self.head(snapshot)?;
        let projection_bytes = snapshot
            .get(&self.meta, CURRENT_PROJECTION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production current projection is missing"))?;
        let projection: CurrentProjection = serde_json::from_slice(&projection_bytes)
            .map_err(|_| integrity("production current projection is invalid"))?;
        validate_projection(&self.mac_key, &projection)?;
        let map_entries = |entries: Vec<contextdb_storage::Entry>| {
            entries
                .into_iter()
                .map(|entry| {
                    let digest = self.digest(b"durable_state_value", &entry.value);
                    (entry.key, digest)
                })
                .collect::<Vec<_>>()
        };
        let events = map_entries(
            snapshot
                .scan_prefix(&self.events, b"")
                .map_err(storage_error)?,
        );
        let graph = map_entries(
            snapshot
                .scan_prefix(&self.graph, b"")
                .map_err(storage_error)?,
        );
        let idempotency = map_entries(
            snapshot
                .scan_prefix(&self.idempotency, b"")
                .map_err(storage_error)?,
        );
        let streams = map_entries(
            snapshot
                .scan_prefix(&self.streams, b"")
                .map_err(storage_error)?,
        );
        let root = StateRoot {
            schema_version: STREAM_SCHEMA_VERSION,
            production_head,
            projection_digest: &projection.archive_digest,
            projection_commit_seq: projection.commit_seq,
            graph_entries: graph,
            event_entries: events,
            idempotency_entries: idempotency,
            stream_entries: streams,
        };
        Ok(self.digest(b"durable_state_root", &canonical_bytes(&root)?))
    }

    /// Current closed-world durable root. The immutable header and every
    /// non-recursive application meta value are bound by keyed digests.
    ///
    /// `durable_generation`, `durable_head`, and `production_durable_history`
    /// are intentionally excluded because a head cannot contain a root that
    /// contains that same head. Their exact key set, framing, MACs, and
    /// contiguous predecessor chain are verified separately. Fjall's
    /// `head_sequence` is likewise excluded because its value is assigned by
    /// the physical commit after this root is prepared; its sole-key framing
    /// and equality to the snapshot sequence are verified separately.
    fn compute_state_root_v2(&self, snapshot: &impl ReadSnapshot) -> CliResult<String> {
        #[derive(Serialize)]
        struct StateRootV2 {
            state_root_version: u16,
            production_head: u64,
            header_digest: String,
            projection_digest: String,
            projection_commit_seq: u64,
            meta_entries: Vec<(Vec<u8>, String)>,
            graph_entries: Vec<(Vec<u8>, String)>,
            event_entries: Vec<(Vec<u8>, String)>,
            idempotency_entries: Vec<(Vec<u8>, String)>,
            stream_entries: Vec<(Vec<u8>, String)>,
        }

        let header_bytes = snapshot
            .get(&self.meta, HEADER_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production store header is missing"))?;
        let header: StoreHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| integrity("production store header is invalid"))?;
        validate_header(&self.mac_key, &header)?;
        let head_bytes = snapshot
            .get(&self.meta, HEAD_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production store head is missing"))?;
        let production_head = self.head(snapshot)?;
        let projection_bytes = snapshot
            .get(&self.meta, CURRENT_PROJECTION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production current projection is missing"))?;
        let projection: CurrentProjection = serde_json::from_slice(&projection_bytes)
            .map_err(|_| integrity("production current projection is invalid"))?;
        validate_projection(&self.mac_key, &projection)?;
        let non_event_receipt_count_bytes = snapshot
            .get(&self.meta, NON_EVENT_RECEIPT_COUNT_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production non-event receipt count is missing"))?;
        decode_non_event_receipt_count(&non_event_receipt_count_bytes)?;

        let map_entries = |entries: Vec<contextdb_storage::Entry>| {
            entries
                .into_iter()
                .map(|entry| {
                    let digest = self.digest(b"durable_state_value", &entry.value);
                    (entry.key, digest)
                })
                .collect::<Vec<_>>()
        };
        let mut idempotency_entries = map_entries(
            snapshot
                .scan_prefix(&self.idempotency, b"")
                .map_err(storage_error)?,
        );
        idempotency_entries.extend(
            map_entries(
                snapshot
                    .scan_prefix(&self.runtime, b"")
                    .map_err(storage_error)?,
            )
            .into_iter()
            .map(|(key, digest)| {
                let mut rooted_key = b"runtime_keyspace_v1/".to_vec();
                rooted_key.extend_from_slice(&key);
                (rooted_key, digest)
            }),
        );
        let root = StateRootV2 {
            state_root_version: STATE_ROOT_VERSION,
            production_head,
            header_digest: self.digest(b"durable_state_header", &header_bytes),
            projection_digest: projection.archive_digest,
            projection_commit_seq: projection.commit_seq,
            meta_entries: [
                (HEAD_KEY.to_vec(), head_bytes),
                (CURRENT_PROJECTION_KEY.to_vec(), projection_bytes),
                (
                    NON_EVENT_RECEIPT_COUNT_KEY.to_vec(),
                    non_event_receipt_count_bytes,
                ),
            ]
            .into_iter()
            .map(|(key, value)| (key, self.digest(b"durable_state_value", &value)))
            .collect(),
            graph_entries: map_entries(
                snapshot
                    .scan_prefix(&self.graph, b"")
                    .map_err(storage_error)?,
            ),
            event_entries: map_entries(
                snapshot
                    .scan_prefix(&self.events, b"")
                    .map_err(storage_error)?,
            ),
            // Kept in the existing field so an empty newly materialized
            // runtime keyspace leaves every pre-D4 v2 state root byte-exact.
            idempotency_entries,
            stream_entries: map_entries(
                snapshot
                    .scan_prefix(&self.streams, b"")
                    .map_err(storage_error)?,
            ),
        };
        Ok(self.digest(b"durable_state_root_v2", &canonical_bytes(&root)?))
    }

    fn verify_durable_history(&self) -> CliResult<DurableLedgerHead> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.durable_head_from(&snapshot)?;
        let entries = snapshot
            .scan_prefix(&self.durable_history, DURABLE_HISTORY_PREFIX)
            .map_err(storage_error)?;
        let expected_count = usize::try_from(head.generation)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        if entries.len() != expected_count {
            return Err(integrity("production durable history is not contiguous").into());
        }
        let mut previous = None;
        for (offset, entry) in entries.into_iter().enumerate() {
            let generation = u64::try_from(offset)
                .map_err(|_| integrity("production durable history exceeds this platform"))?;
            if entry.key != durable_history_key(generation) {
                return Err(integrity("production durable history key is out of order").into());
            }
            let record: DurableLedgerHead = serde_json::from_slice(&entry.value)
                .map_err(|_| integrity("production durable history record is invalid"))?;
            self.validate_durable_head(&record, generation)?;
            if record.previous_digest != previous {
                return Err(integrity("production durable history chain changed").into());
            }
            previous = Some(record.digest.clone());
            if generation == head.generation && record != head {
                return Err(integrity("production durable head differs from history").into());
            }
        }
        let current_root = match head.state_root_version {
            None if head.generation == 0
                && snapshot
                    .scan_prefix(&self.graph, b"")
                    .map_err(storage_error)?
                    .is_empty() =>
            {
                self.compute_legacy_state_root(&snapshot)?
            }
            None => self.compute_state_root_v1(&snapshot)?,
            Some(STATE_ROOT_VERSION) => self.compute_state_root_v2(&snapshot)?,
            Some(_) => {
                return Err(integrity("production durable state-root version is unknown").into());
            }
        };
        if current_root != head.state_root {
            return Err(integrity("production durable state root changed").into());
        }
        Ok(head)
    }

    fn verify_durable_successor(
        &self,
        anchored: &super::state_head::DurableIdentity,
        current: &DurableLedgerHead,
    ) -> CliResult<()> {
        if anchored.generation > current.generation {
            return Err(integrity("external durable generation is ahead of Fjall").into());
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let anchored_bytes = snapshot
            .get(
                &self.durable_history,
                &durable_history_key(anchored.generation),
            )
            .map_err(storage_error)?
            .ok_or_else(|| integrity("externally anchored durable history is absent from Fjall"))?;
        let anchored_record: DurableLedgerHead = serde_json::from_slice(&anchored_bytes)
            .map_err(|_| integrity("externally anchored durable history is invalid"))?;
        self.validate_durable_head(&anchored_record, anchored.generation)?;
        if anchored_record.digest != anchored.ledger_digest {
            return Err(
                integrity("externally anchored durable digest is absent from Fjall").into(),
            );
        }
        let mut previous = anchored_record.digest;
        for generation in anchored.generation.saturating_add(1)..=current.generation {
            let bytes = snapshot
                .get(&self.durable_history, &durable_history_key(generation))
                .map_err(storage_error)?
                .ok_or_else(|| integrity("production durable successor history is incomplete"))?;
            let record: DurableLedgerHead = serde_json::from_slice(&bytes)
                .map_err(|_| integrity("production durable successor history is invalid"))?;
            self.validate_durable_head(&record, generation)?;
            if record.previous_digest.as_deref() != Some(previous.as_str()) {
                return Err(integrity("production durable successor chain diverges").into());
            }
            previous = record.digest;
        }
        if previous != current.digest {
            return Err(
                integrity("production durable successor did not reach current head").into(),
            );
        }
        Ok(())
    }

    /// Captures the small Fjall tip records paired with a projection and graph
    /// which have already passed complete verification (or were produced by the
    /// just-synchronized semantic transaction). The snapshot sequence makes this
    /// cache invalid after every committed physical change, including a
    /// semantically inert receipt or an adversarial writer using this adapter;
    /// the archive-bearing projection and graph blob are never reread here.
    fn reconciled_tip_from_verified(
        &self,
        expected: &super::state_head::ArchiveIdentity,
        durable: &DurableLedgerHead,
        graph: &PolicyGraphProjection,
    ) -> CliResult<ReconciledTip> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let production_head = self.head(&snapshot)?;

        let generation_bytes = snapshot
            .get(&self.meta, DURABLE_GENERATION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production durable generation is missing"))?;
        let generation = decode_u64_exact(&generation_bytes, "production durable generation")?;
        let stored_durable = self.durable_head_from(&snapshot)?;
        let history_bytes = snapshot
            .get(&self.durable_history, &durable_history_key(generation))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production durable history tail is missing"))?;
        let history_tail: DurableLedgerHead = serde_json::from_slice(&history_bytes)
            .map_err(|_| integrity("production durable history tail is invalid"))?;
        self.validate_durable_head(&history_tail, generation)?;

        if production_head != graph.generation
            || graph.database_id != expected.database_id
            || graph.archive_commit_seq != expected.commit_seq
            || graph.archive_digest != expected.archive_digest
            || generation != durable.generation
            || stored_durable != *durable
            || history_tail != *durable
        {
            return Err(
                integrity("production reconciled tip changed after complete verification").into(),
            );
        }
        let storage_sequence = snapshot.sequence();
        let runtime_health = self.runtime_ledger_health_from(&snapshot, durable.generation)?;
        if self.engine.head_sequence().map_err(storage_error)? != storage_sequence {
            return Err(integrity(
                "production physical state changed while capturing reconciled tip",
            )
            .into());
        }
        Ok(ReconciledTip {
            storage_sequence,
            production_head,
            database_id: expected.database_id.clone(),
            projection_commit_seq: expected.commit_seq,
            projection_digest: expected.archive_digest.clone(),
            durable: durable.clone(),
            runtime_health,
        })
    }

    /// Cheap proof for an unchanged, previously fully verified publication.
    /// Fjall's global commit sequence changes for every successful write, so
    /// an exact unchanged sequence preserves the projection and graph bytes
    /// which were authenticated by the preceding full verification. This path
    /// deliberately reads only small head/durable-tail records; it never
    /// materializes the archive-bearing projection or graph blob. Returning
    /// `false` (or any error at the caller) is never acceptance: it selects the
    /// full closed-world verification and canonical replay path.
    fn reconciled_tip_matches(&self, expected: &ReconciledTip) -> CliResult<bool> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if snapshot.sequence() != expected.storage_sequence
            || self.engine.head_sequence().map_err(storage_error)? != expected.storage_sequence
            || self.head(&snapshot)? != expected.production_head
        {
            return Ok(false);
        }

        let generation_bytes = snapshot
            .get(&self.meta, DURABLE_GENERATION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production durable generation is missing"))?;
        let generation = decode_u64_exact(&generation_bytes, "production durable generation")?;
        if generation != expected.durable.generation {
            return Ok(false);
        }
        let durable = self.durable_head_from(&snapshot)?;
        if durable != expected.durable {
            return Ok(false);
        }
        let history_bytes = snapshot
            .get(&self.durable_history, &durable_history_key(generation))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production durable history tail is missing"))?;
        let history_tail: DurableLedgerHead = serde_json::from_slice(&history_bytes)
            .map_err(|_| integrity("production durable history tail is invalid"))?;
        self.validate_durable_head(&history_tail, generation)?;
        if history_tail != expected.durable {
            return Ok(false);
        }

        // Recheck after the bounded point reads to close the window in which a
        // concurrent Fjall transaction could advance the physical state.
        Ok(self.engine.head_sequence().map_err(storage_error)? == expected.storage_sequence)
    }

    fn events(&self) -> CliResult<Vec<StoredEvent>> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.head(&snapshot)?;
        let entries = snapshot
            .scan_prefix(&self.events, EVENT_PREFIX)
            .map_err(storage_error)?;
        if u64::try_from(entries.len()).unwrap_or(u64::MAX) != head {
            return Err(integrity("production event ledger is not contiguous").into());
        }
        let mut previous_checksum = None;
        let mut events = Vec::with_capacity(entries.len());
        for (offset, entry) in entries.into_iter().enumerate() {
            let expected = u64::try_from(offset).unwrap_or(u64::MAX).saturating_add(1);
            if entry.key != event_key(expected) {
                return Err(integrity("production event key is out of order").into());
            }
            let event: StoredEvent = serde_json::from_slice(&entry.value)
                .map_err(|_| integrity("production event is invalid"))?;
            validate_event(
                &self.mac_key,
                &event,
                expected,
                previous_checksum.as_deref(),
            )?;
            let index_bytes = snapshot
                .get(&self.idempotency, event.idempotency_digest.as_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("production idempotency index is missing"))?;
            let index: IdempotencyIndex = serde_json::from_slice(&index_bytes)
                .map_err(|_| integrity("production idempotency index is invalid"))?;
            validate_index(&self.mac_key, &index, &event)?;
            previous_checksum = Some(event.checksum.clone());
            events.push(event);
        }
        Ok(events)
    }

    fn idempotent_event(
        &self,
        idempotency_digest: &str,
        request_digest: &str,
    ) -> CliResult<Option<StoredEvent>> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let Some(bytes) = snapshot
            .get(&self.idempotency, idempotency_digest.as_bytes())
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let index: IdempotencyIndex = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("production idempotency index is invalid"))?;
        let event_bytes = snapshot
            .get(&self.events, &event_key(index.sequence))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("indexed production event is missing"))?;
        let event: StoredEvent = serde_json::from_slice(&event_bytes)
            .map_err(|_| integrity("indexed production event is invalid"))?;
        // Full chain validation is performed before every read/mutation. Here
        // the indexed event still receives its local framing validation.
        validate_event(
            &self.mac_key,
            &event,
            index.sequence,
            event.previous_event_checksum.as_deref(),
        )?;
        validate_index(&self.mac_key, &index, &event)?;
        if index.request_digest != request_digest {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "idempotency key was reused with different canonical input",
                false,
            )
            .into());
        }
        Ok(Some(event))
    }

    fn runtime_postflight_identity_digest(
        &self,
        context: &contextdb_service::AuthenticatedRequestContext,
        operation_id: &str,
    ) -> CliResult<String> {
        let header = self.header()?;
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            "runtime_postflight",
            &header.database_id,
            &context.request.workspace_id,
            &context.actor_id,
            &context.agent_id,
            &context.request.subject_id,
            &context.session_id,
            operation_id,
        ))?);
        Ok(self.digest(b"runtime_postflight_identity", &material))
    }

    fn runtime_postflight_receipt(
        &self,
        key: &[u8],
        submission_commitment: &str,
    ) -> CliResult<Option<StoredRuntimePostflightReceipt>> {
        validate_runtime_postflight_key(key)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let Some(bytes) = snapshot
            .get(&self.idempotency, key)
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        if bytes.is_empty() || bytes.len() > MAX_RUNTIME_POSTFLIGHT_RECEIPT_BYTES {
            return Err(integrity("production runtime postflight receipt is out of bounds").into());
        }
        let receipt: StoredRuntimePostflightReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("production runtime postflight receipt is invalid"))?;
        let durable = self.durable_head_from(&snapshot)?;
        self.validate_runtime_postflight_receipt(key, &receipt, durable.generation)?;
        if receipt.submission_commitment != submission_commitment {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "runtime operation ID was reused with different canonical input or authority",
                false,
            )
            .into());
        }
        Ok(Some(receipt))
    }

    fn non_event_receipt_count(&self, snapshot: &impl ReadSnapshot) -> CliResult<u64> {
        let bytes = snapshot
            .get(&self.meta, NON_EVENT_RECEIPT_COUNT_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production non-event receipt count is missing"))?;
        decode_non_event_receipt_count(&bytes)
    }

    fn non_event_receipt_entries(&self, snapshot: &impl ReadSnapshot) -> CliResult<usize> {
        let count = self.verify_key_layout(snapshot, false, false)?;
        usize::try_from(count).map_err(|_| {
            integrity("production non-event receipt count exceeds this platform").into()
        })
    }

    fn append_runtime_postflight_receipt(
        &self,
        key: &[u8],
        submission_commitment: String,
    ) -> CliResult<StoredRuntimePostflightReceipt> {
        self.append_runtime_postflight_receipt_with_limit(
            key,
            submission_commitment,
            MAX_NON_EVENT_RECEIPTS,
        )
    }

    fn append_runtime_postflight_receipt_with_limit(
        &self,
        key: &[u8],
        submission_commitment: String,
        limit: usize,
    ) -> CliResult<StoredRuntimePostflightReceipt> {
        validate_runtime_postflight_key(key)?;
        validate_digest(
            &submission_commitment,
            "runtime postflight submission commitment",
        )?;
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if transaction
            .get(&self.idempotency, key)
            .map_err(storage_error)?
            .is_some()
        {
            return Err(integrity(
                "production runtime postflight idempotency changed concurrently",
            )
            .into());
        }
        let rooted_count = self.non_event_receipt_count(&transaction)?;
        let actual_count = self.non_event_receipt_entries(&transaction)?;
        if usize::try_from(rooted_count).ok() != Some(actual_count) {
            return Err(
                integrity("production non-event receipt count changed before admission").into(),
            );
        }
        if actual_count >= limit {
            return Err(resource_exhausted(
                "production non-event receipt limit is exhausted",
                false,
            )
            .into());
        }
        let next_count = rooted_count.checked_add(1).ok_or_else(|| {
            resource_exhausted("production non-event receipt count is exhausted", false)
        })?;

        // Randomness is requested only after every admission control passes.
        let mut receipt_random = [0_u8; 32];
        getrandom::fill(&mut receipt_random)
            .map_err(|_| unavailable("runtime receipt randomness is unavailable"))?;
        let receipt_id = blake3::Hash::from_bytes(receipt_random)
            .to_hex()
            .to_string();
        let current = self.durable_head_from(&transaction)?;
        let durable_generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| integrity("production durable generation is exhausted"))?;
        let mut receipt = StoredRuntimePostflightReceipt {
            schema_version: STORE_SCHEMA_VERSION,
            receipt_id,
            submission_commitment,
            durable_generation,
            checksum: String::new(),
        };
        receipt.checksum = self.runtime_postflight_checksum(key, &receipt)?;
        transaction
            .put(&self.idempotency, key.to_vec(), canonical_bytes(&receipt)?)
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                NON_EVENT_RECEIPT_COUNT_KEY.to_vec(),
                next_count.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        let successor = self.stage_durable_successor(&mut transaction)?;
        if successor.generation != receipt.durable_generation {
            return Err(integrity(
                "runtime postflight receipt selected another durable generation",
            )
            .into());
        }
        let committed = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(committed.durability)?;
        Ok(receipt)
    }

    fn runtime_postflight_checksum(
        &self,
        key: &[u8],
        receipt: &StoredRuntimePostflightReceipt,
    ) -> CliResult<String> {
        let mut unsigned = receipt.clone();
        unsigned.checksum.clear();
        Ok(self.digest(
            b"runtime_postflight_receipt",
            &canonical_bytes(&(key, unsigned))?,
        ))
    }

    fn validate_runtime_postflight_receipt(
        &self,
        key: &[u8],
        receipt: &StoredRuntimePostflightReceipt,
        current_generation: u64,
    ) -> CliResult<()> {
        validate_runtime_postflight_key(key)?;
        if receipt.schema_version != STORE_SCHEMA_VERSION
            || validate_digest(&receipt.receipt_id, "runtime postflight receipt ID").is_err()
            || validate_digest(
                &receipt.submission_commitment,
                "runtime postflight submission commitment",
            )
            .is_err()
            || receipt.durable_generation == 0
            || receipt.durable_generation > current_generation
            || receipt.checksum != self.runtime_postflight_checksum(key, receipt)?
        {
            return Err(integrity(
                "production runtime postflight receipt failed integrity validation",
            )
            .into());
        }
        Ok(())
    }

    fn continuity_compiler_key(&self) -> [u8; 32] {
        blake3::derive_key(
            "contextdb/production-continuity-compiler-key/v1",
            &self.mac_key[..],
        )
    }

    fn runtime_lifecycle_identity_digest(
        &self,
        method: RuntimeLifecycleMethod,
        context: &contextdb_service::AuthenticatedRequestContext,
        operation_id: &str,
    ) -> CliResult<String> {
        let header = self.header()?;
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            method,
            &header.database_id,
            &context.request.workspace_id,
            &context.request.subject_id,
            &context.actor_id,
            &context.agent_id,
            &context.session_id,
            operation_id,
        ))?);
        Ok(self.digest(b"runtime_lifecycle_identity", &material))
    }

    fn runtime_state_identity_digest(&self, checkpoint: &PortableCheckpoint) -> CliResult<String> {
        let header = self.header()?;
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            "runtime_state",
            &header.database_id,
            checkpoint.workspace_id,
            checkpoint.agent_id,
            checkpoint.stable_subject,
            checkpoint.continuity_profile_id,
        ))?);
        Ok(self.digest(b"runtime_state_identity", &material))
    }

    fn runtime_lifecycle_request_commitment(
        &self,
        method: RuntimeLifecycleMethod,
        identity_digest: &str,
        authorization_digest: &str,
        canonical_payload: &[u8],
    ) -> CliResult<String> {
        validate_digest(identity_digest, "runtime lifecycle identity")?;
        validate_digest(
            authorization_digest,
            "runtime lifecycle authorization binding",
        )?;
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            method,
            identity_digest,
            authorization_digest,
            canonical_payload,
        ))?);
        Ok(self.digest(b"runtime_lifecycle_request", &material))
    }

    fn runtime_lifecycle_receipt_id(
        &self,
        method: RuntimeLifecycleMethod,
        identity_digest: &str,
        request_commitment: &str,
    ) -> CliResult<String> {
        validate_digest(identity_digest, "runtime lifecycle identity")?;
        validate_digest(request_commitment, "runtime lifecycle request commitment")?;
        Ok(self.digest(
            b"runtime_lifecycle_receipt_id",
            &canonical_bytes(&(method, identity_digest, request_commitment))?,
        ))
    }

    fn runtime_lifecycle_receipt(
        &self,
        key: &[u8],
        request_commitment: &str,
    ) -> CliResult<Option<StoredRuntimeLifecycleReceipt>> {
        let method = parse_runtime_lifecycle_receipt_key(key)?;
        validate_digest(request_commitment, "runtime lifecycle request commitment")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let Some(bytes) = snapshot.get(&self.runtime, key).map_err(storage_error)? else {
            return Ok(None);
        };
        if bytes.is_empty() || bytes.len() > MAX_RUNTIME_LIFECYCLE_RECEIPT_BYTES {
            return Err(integrity("production runtime lifecycle receipt is out of bounds").into());
        }
        let receipt: StoredRuntimeLifecycleReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("production runtime lifecycle receipt is invalid"))?;
        let durable = self.durable_head_from(&snapshot)?;
        self.validate_runtime_lifecycle_receipt(key, method, &receipt, durable.generation)?;
        if receipt.request_commitment != request_commitment {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "runtime operation ID was reused with different canonical input or authority",
                false,
            )
            .into());
        }
        if receipt.retired {
            return Err(ServiceError::new(
                ErrorCode::ContinuationExpired,
                "runtime operation replay expired at the configured ledger-retention boundary",
                false,
            )
            .with_context(
                Vec::new(),
                Some("runtime_ledger_retention".to_owned()),
                Some("submit a new operation ID against the current checkpoint state".to_owned()),
                None,
            )
            .into());
        }
        Ok(Some(receipt))
    }

    fn runtime_state_checksum(&self, key: &[u8], state: &StoredRuntimeState) -> CliResult<String> {
        let mut unsigned = state.clone();
        unsigned.checksum.clear();
        Ok(self.digest(
            b"runtime_lifecycle_state_checksum",
            &canonical_bytes(&(key, unsigned))?,
        ))
    }

    fn seal_runtime_state(&self, mut state: StoredRuntimeState) -> CliResult<StoredRuntimeState> {
        let key = runtime_state_key(&state.identity_digest, state.version)?;
        state.state_digest.clear();
        state.checksum.clear();
        state.state_digest = self.digest(b"runtime_lifecycle_state", &canonical_bytes(&state)?);
        state.checksum = self.runtime_state_checksum(&key, &state)?;
        self.validate_runtime_state(&key, &state)?;
        Ok(state)
    }

    fn validate_runtime_state(&self, key: &[u8], state: &StoredRuntimeState) -> CliResult<()> {
        let (identity_digest, version) = parse_runtime_state_key(key)?;
        state
            .checkpoint
            .validate()
            .map_err(map_continuity_service_error)?;
        state
            .active_runtime
            .validate()
            .map_err(map_continuity_service_error)?;
        let active_runtime_digest = continuity_value_digest(&state.active_runtime)?;
        let mut unsigned = state.clone();
        unsigned.state_digest.clear();
        unsigned.checksum.clear();
        let expected_state_digest =
            self.digest(b"runtime_lifecycle_state", &canonical_bytes(&unsigned)?);
        let compiled_state = matches!(
            state.status,
            RuntimeCheckpointStatus::Bootstrapped | RuntimeCheckpointStatus::Resumed
        );
        let has_trace = state.last_bootstrap_trace_digest.is_some();
        let has_pack = state.last_pack_digest.is_some();
        if state.schema_version != STORE_SCHEMA_VERSION
            || state.identity_digest != identity_digest
            || state.version != version
            || state.version == 0
            || state.version == 1 && state.previous_state_digest.is_some()
            || state.version > 1 && state.previous_state_digest.is_none()
            || state
                .previous_state_digest
                .as_ref()
                .is_some_and(|digest| validate_digest(digest, "previous runtime state").is_err())
            || validate_digest(&state.active_runtime_digest, "active runtime digest").is_err()
            || state.active_runtime_digest != active_runtime_digest
            || validate_digest(&state.state_digest, "runtime state digest").is_err()
            || state.state_digest != expected_state_digest
            || state.checksum != self.runtime_state_checksum(key, state)?
            || state.updated_at < state.checkpoint.checkpoint.frame_snapshot.captured_at
            || has_trace != has_pack
            || compiled_state && !has_trace
            || state.status == RuntimeCheckpointStatus::Sealed && has_trace
            || state
                .last_bootstrap_trace_digest
                .as_ref()
                .is_some_and(|digest| {
                    validate_digest(digest, "runtime bootstrap trace digest").is_err()
                })
            || state.last_pack_digest.as_ref().is_some_and(|digest| {
                validate_digest(digest, "runtime ContextPack digest").is_err()
            })
            || state.status == RuntimeCheckpointStatus::Sealed
                && state.active_runtime_digest != state.checkpoint.source_runtime_digest.to_string()
        {
            return Err(integrity("production runtime state failed integrity validation").into());
        }
        Ok(())
    }

    fn runtime_head_checksum(&self, key: &[u8], head: &StoredRuntimeHead) -> CliResult<String> {
        let mut unsigned = head.clone();
        unsigned.checksum.clear();
        Ok(self.digest(
            b"runtime_lifecycle_head_checksum",
            &canonical_bytes(&(key, unsigned))?,
        ))
    }

    fn checkpoint_head_checksum(
        &self,
        key: &[u8],
        head: &StoredCheckpointHead,
    ) -> CliResult<String> {
        let mut unsigned = head.clone();
        unsigned.checksum.clear();
        Ok(self.digest(
            b"runtime_checkpoint_head_checksum",
            &canonical_bytes(&(key, unsigned))?,
        ))
    }

    fn runtime_gc_anchor_checksum(
        &self,
        key: &[u8],
        anchor: &StoredRuntimeGcAnchor,
    ) -> CliResult<String> {
        let mut unsigned = anchor.clone();
        unsigned.checksum.clear();
        Ok(self.digest(
            b"runtime_gc_anchor_checksum",
            &canonical_bytes(&(key, unsigned))?,
        ))
    }

    fn validate_runtime_gc_anchor(
        &self,
        key: &[u8],
        anchor: &StoredRuntimeGcAnchor,
        current_generation: u64,
    ) -> CliResult<()> {
        let identity_digest = parse_runtime_gc_anchor_key(key)?;
        if anchor.schema_version != STORE_SCHEMA_VERSION
            || anchor.identity_digest != identity_digest
            || anchor.pruned_through_version == 0
            || validate_digest(&anchor.terminal_state_digest, "runtime GC terminal state").is_err()
            || validate_digest(&anchor.accumulator_digest, "runtime GC accumulator").is_err()
            || anchor.updated_at_generation == 0
            || anchor.updated_at_generation > current_generation
            || anchor.checksum != self.runtime_gc_anchor_checksum(key, anchor)?
        {
            return Err(
                integrity("production runtime GC anchor failed integrity validation").into(),
            );
        }
        Ok(())
    }

    fn extend_runtime_gc_accumulator(
        &self,
        previous: Option<&StoredRuntimeGcAnchor>,
        state: &StoredRuntimeState,
    ) -> CliResult<String> {
        let previous_accumulator = previous.map(|anchor| anchor.accumulator_digest.as_str());
        Ok(self.digest(
            b"runtime_gc_accumulator",
            &canonical_bytes(&(
                STORE_SCHEMA_VERSION,
                &state.identity_digest,
                state.version,
                previous_accumulator,
                &state.previous_state_digest,
                &state.state_digest,
            ))?,
        ))
    }

    fn runtime_head_for_state(&self, state: &StoredRuntimeState) -> CliResult<StoredRuntimeHead> {
        let key = runtime_head_key(&state.identity_digest)?;
        let mut head = StoredRuntimeHead {
            schema_version: STORE_SCHEMA_VERSION,
            identity_digest: state.identity_digest.clone(),
            version: state.version,
            checkpoint_digest: state.checkpoint.digest.to_string(),
            state_digest: state.state_digest.clone(),
            checksum: String::new(),
        };
        head.checksum = self.runtime_head_checksum(&key, &head)?;
        Ok(head)
    }

    fn checkpoint_head_for_state(
        &self,
        state: &StoredRuntimeState,
    ) -> CliResult<StoredCheckpointHead> {
        let checkpoint_digest = state.checkpoint.digest.to_string();
        let key = runtime_checkpoint_head_key(&checkpoint_digest)?;
        let mut head = StoredCheckpointHead {
            schema_version: STORE_SCHEMA_VERSION,
            checkpoint_digest,
            identity_digest: state.identity_digest.clone(),
            version: state.version,
            status: state.status,
            state_digest: state.state_digest.clone(),
            checksum: String::new(),
        };
        head.checksum = self.checkpoint_head_checksum(&key, &head)?;
        Ok(head)
    }

    fn load_runtime_state_by_checkpoint(
        &self,
        checkpoint_digest: &str,
    ) -> CliResult<Option<LoadedRuntimeState>> {
        validate_digest(checkpoint_digest, "runtime checkpoint digest")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let checkpoint_key = runtime_checkpoint_head_key(checkpoint_digest)?;
        let Some(checkpoint_head_bytes) = snapshot
            .get(&self.runtime, &checkpoint_key)
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let checkpoint_head: StoredCheckpointHead = serde_json::from_slice(&checkpoint_head_bytes)
            .map_err(|_| integrity("production checkpoint head is invalid"))?;
        self.validate_checkpoint_head(&checkpoint_key, &checkpoint_head)?;
        let runtime_key = runtime_head_key(&checkpoint_head.identity_digest)?;
        let runtime_head_bytes = snapshot
            .get(&self.runtime, &runtime_key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production runtime head is missing"))?;
        let runtime_head: StoredRuntimeHead = serde_json::from_slice(&runtime_head_bytes)
            .map_err(|_| integrity("production runtime head is invalid"))?;
        self.validate_runtime_head(&runtime_key, &runtime_head)?;
        let state_key =
            runtime_state_key(&checkpoint_head.identity_digest, checkpoint_head.version)?;
        let state_bytes = snapshot
            .get(&self.runtime, &state_key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production checkpoint state is missing"))?;
        let state: StoredRuntimeState = serde_json::from_slice(&state_bytes)
            .map_err(|_| integrity("production checkpoint state is invalid"))?;
        self.validate_runtime_state(&state_key, &state)?;
        if checkpoint_head.checkpoint_digest != state.checkpoint.digest.to_string()
            || checkpoint_head.identity_digest != state.identity_digest
            || checkpoint_head.version != state.version
            || checkpoint_head.status != state.status
            || checkpoint_head.state_digest != state.state_digest
        {
            return Err(integrity("production checkpoint head differs from its state").into());
        }
        Ok(Some(LoadedRuntimeState {
            state,
            runtime_head,
            runtime_head_bytes,
            checkpoint_head,
            checkpoint_head_bytes,
        }))
    }

    fn load_runtime_latest(&self, identity_digest: &str) -> CliResult<Option<LoadedRuntimeState>> {
        validate_digest(identity_digest, "runtime state identity")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let runtime_key = runtime_head_key(identity_digest)?;
        let Some(runtime_head_bytes) = snapshot
            .get(&self.runtime, &runtime_key)
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let runtime_head: StoredRuntimeHead = serde_json::from_slice(&runtime_head_bytes)
            .map_err(|_| integrity("production runtime head is invalid"))?;
        self.validate_runtime_head(&runtime_key, &runtime_head)?;
        drop(snapshot);
        let loaded = self
            .load_runtime_state_by_checkpoint(&runtime_head.checkpoint_digest)?
            .ok_or_else(|| integrity("production runtime head checkpoint is missing"))?;
        if loaded.runtime_head != runtime_head {
            return Err(integrity("production runtime head changed during state load").into());
        }
        Ok(Some(loaded))
    }

    fn validate_runtime_head(&self, key: &[u8], head: &StoredRuntimeHead) -> CliResult<()> {
        let identity_digest = parse_runtime_head_key(key)?;
        if head.schema_version != STORE_SCHEMA_VERSION
            || head.identity_digest != identity_digest
            || head.version == 0
            || validate_digest(&head.checkpoint_digest, "runtime head checkpoint").is_err()
            || validate_digest(&head.state_digest, "runtime head state").is_err()
            || head.checksum != self.runtime_head_checksum(key, head)?
        {
            return Err(integrity("production runtime head failed integrity validation").into());
        }
        Ok(())
    }

    fn validate_checkpoint_head(&self, key: &[u8], head: &StoredCheckpointHead) -> CliResult<()> {
        let checkpoint_digest = parse_runtime_checkpoint_head_key(key)?;
        if head.schema_version != STORE_SCHEMA_VERSION
            || head.checkpoint_digest != checkpoint_digest
            || head.version == 0
            || validate_digest(&head.identity_digest, "checkpoint head identity").is_err()
            || validate_digest(&head.state_digest, "checkpoint head state").is_err()
            || head.checksum != self.checkpoint_head_checksum(key, head)?
        {
            return Err(integrity("production checkpoint head failed integrity validation").into());
        }
        Ok(())
    }

    fn runtime_lifecycle_receipt_checksum(
        &self,
        key: &[u8],
        receipt: &StoredRuntimeLifecycleReceipt,
    ) -> CliResult<String> {
        let mut unsigned = receipt.clone();
        unsigned.checksum.clear();
        Ok(self.digest(
            b"runtime_lifecycle_receipt_checksum",
            &canonical_bytes(&(key, unsigned))?,
        ))
    }

    fn validate_runtime_lifecycle_receipt(
        &self,
        key: &[u8],
        method: RuntimeLifecycleMethod,
        receipt: &StoredRuntimeLifecycleReceipt,
        current_generation: u64,
    ) -> CliResult<()> {
        let parsed_method = parse_runtime_lifecycle_receipt_key(key)?;
        let payload = if receipt.retired {
            None
        } else {
            let response = validate_runtime_lifecycle_response_bytes(&receipt.response_bytes)?;
            Some(
                serde_json::from_value::<RuntimeLifecyclePayloadV1>(response.payload.clone())
                    .map_err(|_| {
                        integrity("stored runtime lifecycle response payload is invalid")
                    })?,
            )
        };
        let retired_generation_valid = match (receipt.retired, receipt.retired_at_generation) {
            (false, None) => true,
            (true, Some(generation)) => {
                generation > receipt.durable_generation && generation <= current_generation
            }
            (false, Some(_)) | (true, None) => false,
        };
        if receipt.schema_version != STORE_SCHEMA_VERSION
            || receipt.method != method
            || parsed_method != method
            || validate_digest(&receipt.receipt_id, "runtime lifecycle receipt ID").is_err()
            || validate_digest(
                &receipt.request_commitment,
                "runtime lifecycle request commitment",
            )
            .is_err()
            || validate_digest(&receipt.response_digest, "runtime lifecycle response").is_err()
            || !retired_generation_valid
            || !receipt.retired
                && receipt.response_digest
                    != self.digest(b"runtime_lifecycle_response", &receipt.response_bytes)
            || receipt.retired && !receipt.response_bytes.is_empty()
            || !receipt.retired && receipt.response_bytes.is_empty()
            || receipt.response_bytes.len() > MAX_RUNTIME_LIFECYCLE_RESPONSE_BYTES
            || validate_digest(
                &receipt.state_identity_digest,
                "runtime receipt state identity",
            )
            .is_err()
            || receipt.state_version == 0
            || validate_digest(&receipt.state_digest, "runtime receipt state").is_err()
            || receipt.durable_generation == 0
            || receipt.durable_generation > current_generation
            || payload.as_ref().is_some_and(|payload| {
                payload.schema_version != STORE_SCHEMA_VERSION
                    || payload.method != method
                    || payload.receipt_id != receipt.receipt_id
                    || payload.state.version != receipt.state_version
                    || payload.state.checkpoint_digest
                        != runtime_artifact_checkpoint_digest(&payload.artifact)
                    || payload.state.checkpoint_digest.is_empty()
            })
            || receipt.checksum != self.runtime_lifecycle_receipt_checksum(key, receipt)?
        {
            return Err(integrity(
                "production runtime lifecycle receipt failed integrity validation",
            )
            .into());
        }
        Ok(())
    }

    fn commit_runtime_lifecycle(
        &self,
        key: &[u8],
        method: RuntimeLifecycleMethod,
        request_commitment: String,
        response: &RuntimeResponse,
        mutation: RuntimeLedgerMutation,
    ) -> CliResult<StoredRuntimeLifecycleReceipt> {
        if parse_runtime_lifecycle_receipt_key(key)? != method {
            return Err(integrity("runtime lifecycle receipt method differs from its key").into());
        }
        validate_digest(&request_commitment, "runtime lifecycle request commitment")?;
        self.validate_runtime_state(
            &runtime_state_key(
                &mutation.resulting_state.identity_digest,
                mutation.resulting_state.version,
            )?,
            &mutation.resulting_state,
        )?;
        let response_bytes = canonical_bytes(response)?;
        if response_bytes.is_empty() || response_bytes.len() > MAX_RUNTIME_LIFECYCLE_RESPONSE_BYTES
        {
            return Err(resource_exhausted(
                "runtime lifecycle response exceeds the 4 MiB durable limit",
                false,
            )
            .into());
        }
        let verified_response = validate_runtime_lifecycle_response_bytes(&response_bytes)?;
        if verified_response != *response {
            return Err(integrity("runtime lifecycle response is not canonical").into());
        }

        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if transaction
            .get(&self.runtime, key)
            .map_err(storage_error)?
            .is_some()
        {
            return Err(
                integrity("production runtime lifecycle idempotency changed concurrently").into(),
            );
        }
        for (expected_key, expected_value) in &mutation.expected {
            let actual = transaction
                .get(&self.runtime, expected_key)
                .map_err(storage_error)?;
            if &actual != expected_value {
                return Err(integrity("production runtime state changed concurrently").into());
            }
        }
        let rooted_count = self.non_event_receipt_count(&transaction)?;
        let actual_count = self.non_event_receipt_entries(&transaction)?;
        if usize::try_from(rooted_count).ok() != Some(actual_count) {
            return Err(integrity(
                "production non-event receipt count changed before runtime admission",
            )
            .into());
        }
        if actual_count >= MAX_NON_EVENT_RECEIPTS {
            return Err(resource_exhausted(
                "production non-event receipt limit is exhausted",
                false,
            )
            .into());
        }
        let next_count = rooted_count.checked_add(1).ok_or_else(|| {
            resource_exhausted("production non-event receipt count is exhausted", false)
        })?;
        let current = self.durable_head_from(&transaction)?;
        let durable_generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| integrity("production durable generation is exhausted"))?;
        let payload: RuntimeLifecyclePayloadV1 =
            serde_json::from_value(response.payload.clone())
                .map_err(|_| integrity("runtime lifecycle response payload is invalid"))?;
        let mut receipt = StoredRuntimeLifecycleReceipt {
            schema_version: STORE_SCHEMA_VERSION,
            method,
            receipt_id: payload.receipt_id,
            request_commitment,
            response_digest: self.digest(b"runtime_lifecycle_response", &response_bytes),
            response_bytes,
            state_identity_digest: mutation.resulting_state.identity_digest.clone(),
            state_version: mutation.resulting_state.version,
            state_digest: mutation.resulting_state.state_digest.clone(),
            durable_generation,
            retired: false,
            retired_at_generation: None,
            checksum: String::new(),
        };
        receipt.checksum = self.runtime_lifecycle_receipt_checksum(key, &receipt)?;
        let receipt_bytes = canonical_bytes(&receipt)?;
        if receipt_bytes.len() > MAX_RUNTIME_LIFECYCLE_RECEIPT_BYTES {
            return Err(resource_exhausted(
                "runtime lifecycle receipt exceeds the 4 MiB durable limit",
                false,
            )
            .into());
        }
        for (write_key, write_value) in mutation.writes {
            if classify_runtime_ledger_key(&write_key)? == RuntimeLedgerKeyKind::Receipt
                || write_value.is_empty()
                || write_value.len() > MAX_RUNTIME_LIFECYCLE_STATE_BYTES
            {
                return Err(integrity("runtime state mutation contains an invalid record").into());
            }
            transaction
                .put(&self.runtime, write_key, write_value)
                .map_err(storage_error)?;
        }
        transaction
            .put(&self.runtime, key.to_vec(), receipt_bytes)
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                NON_EVENT_RECEIPT_COUNT_KEY.to_vec(),
                next_count.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        self.verify_runtime_ledger_from(&transaction, durable_generation)?;
        let successor = self.stage_durable_successor(&mut transaction)?;
        if successor.generation != durable_generation {
            return Err(integrity("runtime lifecycle selected another durable generation").into());
        }
        let committed = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(committed.durability)?;
        Ok(receipt)
    }

    fn verify_runtime_ledger(&self, current_generation: u64) -> CliResult<BTreeSet<u64>> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.verify_runtime_ledger_from(&snapshot, current_generation)
    }

    fn verify_runtime_ledger_from(
        &self,
        snapshot: &impl ReadSnapshot,
        current_generation: u64,
    ) -> CliResult<BTreeSet<u64>> {
        let entries = snapshot
            .scan_prefix(&self.runtime, b"")
            .map_err(storage_error)?;
        if entries.len() > MAX_RUNTIME_LEDGER_RECORDS {
            return Err(integrity("production runtime ledger record cap was exceeded").into());
        }
        let mut states = BTreeMap::new();
        let mut runtime_heads = BTreeMap::new();
        let mut checkpoint_heads = BTreeMap::new();
        let mut anchors = BTreeMap::new();
        let mut receipts = Vec::new();
        let mut receipt_generations = BTreeSet::new();
        for entry in entries {
            if entry.value.is_empty() {
                return Err(integrity("production runtime ledger contains an empty record").into());
            }
            match classify_runtime_ledger_key(&entry.key)? {
                RuntimeLedgerKeyKind::State => {
                    if entry.value.len() > MAX_RUNTIME_LIFECYCLE_STATE_BYTES {
                        return Err(integrity("production runtime state exceeds its bounds").into());
                    }
                    let state: StoredRuntimeState = serde_json::from_slice(&entry.value)
                        .map_err(|_| integrity("production runtime state is invalid"))?;
                    self.validate_runtime_state(&entry.key, &state)?;
                    if states
                        .insert((state.identity_digest.clone(), state.version), state)
                        .is_some()
                    {
                        return Err(
                            integrity("production runtime state version is duplicated").into()
                        );
                    }
                }
                RuntimeLedgerKeyKind::Head => {
                    if entry.value.len() > MAX_RUNTIME_LIFECYCLE_STATE_BYTES {
                        return Err(integrity("production runtime head exceeds its bounds").into());
                    }
                    let head: StoredRuntimeHead = serde_json::from_slice(&entry.value)
                        .map_err(|_| integrity("production runtime head is invalid"))?;
                    self.validate_runtime_head(&entry.key, &head)?;
                    if runtime_heads
                        .insert(head.identity_digest.clone(), head)
                        .is_some()
                    {
                        return Err(integrity("production runtime head is duplicated").into());
                    }
                }
                RuntimeLedgerKeyKind::CheckpointHead => {
                    if entry.value.len() > MAX_RUNTIME_LIFECYCLE_STATE_BYTES {
                        return Err(
                            integrity("production checkpoint head exceeds its bounds").into()
                        );
                    }
                    let head: StoredCheckpointHead = serde_json::from_slice(&entry.value)
                        .map_err(|_| integrity("production checkpoint head is invalid"))?;
                    self.validate_checkpoint_head(&entry.key, &head)?;
                    if checkpoint_heads
                        .insert(head.checkpoint_digest.clone(), head)
                        .is_some()
                    {
                        return Err(integrity("production checkpoint head is duplicated").into());
                    }
                }
                RuntimeLedgerKeyKind::Receipt => {
                    if entry.value.len() > MAX_RUNTIME_LIFECYCLE_RECEIPT_BYTES {
                        return Err(
                            integrity("production runtime receipt exceeds its bounds").into()
                        );
                    }
                    let method = parse_runtime_lifecycle_receipt_key(&entry.key)?;
                    let receipt: StoredRuntimeLifecycleReceipt =
                        serde_json::from_slice(&entry.value).map_err(|_| {
                            integrity("production runtime lifecycle receipt is invalid")
                        })?;
                    self.validate_runtime_lifecycle_receipt(
                        &entry.key,
                        method,
                        &receipt,
                        current_generation,
                    )?;
                    if !receipt_generations.insert(receipt.durable_generation) {
                        return Err(integrity(
                            "production runtime receipts claim the same durable generation",
                        )
                        .into());
                    }
                    receipts.push(receipt);
                }
                RuntimeLedgerKeyKind::GcAnchor => {
                    if entry.value.len() > MAX_RUNTIME_LIFECYCLE_STATE_BYTES {
                        return Err(
                            integrity("production runtime GC anchor exceeds its bounds").into()
                        );
                    }
                    let anchor: StoredRuntimeGcAnchor = serde_json::from_slice(&entry.value)
                        .map_err(|_| integrity("production runtime GC anchor is invalid"))?;
                    self.validate_runtime_gc_anchor(&entry.key, &anchor, current_generation)?;
                    if anchors
                        .insert(anchor.identity_digest.clone(), anchor)
                        .is_some()
                    {
                        return Err(integrity("production runtime GC anchor is duplicated").into());
                    }
                }
            }
        }

        let state_identities = states
            .keys()
            .map(|(identity, _)| identity.clone())
            .collect::<BTreeSet<_>>();
        if state_identities != runtime_heads.keys().cloned().collect() {
            return Err(integrity("production runtime state/head identity set differs").into());
        }
        if !anchors
            .keys()
            .all(|identity| state_identities.contains(identity))
        {
            return Err(integrity("production runtime GC anchor has no retained identity").into());
        }
        let mut expected_checkpoint_heads = BTreeMap::new();
        for (identity, head) in &runtime_heads {
            let identity_states = states
                .range((identity.clone(), 0)..=(identity.clone(), u64::MAX))
                .map(|(_, state)| state)
                .collect::<Vec<_>>();
            let anchor = anchors.get(identity);
            let pruned_through = anchor.map_or(0, |anchor| anchor.pruned_through_version);
            let retained_versions = head
                .version
                .checked_sub(pruned_through)
                .ok_or_else(|| integrity("production runtime GC anchor exceeds its head"))?;
            let expected_len = usize::try_from(retained_versions).map_err(|_| {
                integrity("production retained runtime state count exceeds this platform")
            })?;
            if identity_states.len() != expected_len {
                return Err(integrity("production runtime state chain is not contiguous").into());
            }
            let mut previous = anchor.map(|anchor| anchor.terminal_state_digest.clone());
            for (offset, state) in identity_states.iter().enumerate() {
                let version = u64::try_from(offset)
                    .map_err(|_| integrity("production runtime state chain is too large"))?
                    .checked_add(pruned_through)
                    .and_then(|version| version.checked_add(1))
                    .ok_or_else(|| integrity("production runtime state version is exhausted"))?;
                if state.version != version || state.previous_state_digest != previous {
                    return Err(
                        integrity("production runtime state predecessor chain changed").into(),
                    );
                }
                previous = Some(state.state_digest.clone());
                expected_checkpoint_heads.insert(
                    state.checkpoint.digest.to_string(),
                    self.checkpoint_head_for_state(state)?,
                );
            }
            let last = identity_states
                .last()
                .ok_or_else(|| integrity("production runtime head has no state"))?;
            if head != &self.runtime_head_for_state(last)? {
                return Err(
                    integrity("production runtime head differs from the latest state").into(),
                );
            }
        }
        if checkpoint_heads != expected_checkpoint_heads {
            return Err(
                integrity("production checkpoint head set differs from runtime state").into(),
            );
        }
        for receipt in receipts {
            if receipt.retired {
                let pruned_through = anchors
                    .get(&receipt.state_identity_digest)
                    .map(|anchor| anchor.pruned_through_version)
                    .ok_or_else(|| {
                        integrity("retired runtime receipt has no authenticated GC anchor")
                    })?;
                if receipt.state_version > pruned_through {
                    return Err(
                        integrity("retired runtime receipt references an unpruned state").into(),
                    );
                }
            } else {
                let state = states
                    .get(&(receipt.state_identity_digest.clone(), receipt.state_version))
                    .ok_or_else(|| {
                        integrity("production runtime receipt references missing state")
                    })?;
                let response = validate_runtime_lifecycle_response_bytes(&receipt.response_bytes)?;
                let payload: RuntimeLifecyclePayloadV1 =
                    serde_json::from_value(response.payload)
                        .map_err(|_| integrity("stored runtime lifecycle payload is invalid"))?;
                if state.state_digest != receipt.state_digest
                    || payload.state.version != state.version
                    || payload.state.status != state.status
                    || payload.state.checkpoint_digest != state.checkpoint.digest.to_string()
                {
                    return Err(
                        integrity("production runtime receipt differs from its state").into(),
                    );
                }
            }
        }
        Ok(receipt_generations)
    }

    fn runtime_ledger_health_from(
        &self,
        snapshot: &impl ReadSnapshot,
        current_generation: u64,
    ) -> CliResult<RuntimeLedgerHealthV1> {
        self.verify_runtime_ledger_from(snapshot, current_generation)?;
        let record_count = snapshot
            .scan_prefix(&self.runtime, b"")
            .map_err(storage_error)?
            .len();
        let pressure = if record_count >= MAX_RUNTIME_LEDGER_RECORDS {
            RuntimeLedgerPressure::Exhausted
        } else if record_count >= MAX_RUNTIME_LEDGER_RECORDS.saturating_mul(9) / 10 {
            RuntimeLedgerPressure::Critical
        } else if record_count >= MAX_RUNTIME_LEDGER_RECORDS.saturating_mul(7) / 10 {
            RuntimeLedgerPressure::Elevated
        } else {
            RuntimeLedgerPressure::Nominal
        };
        Ok(RuntimeLedgerHealthV1 {
            schema_version: STORE_SCHEMA_VERSION,
            verified: true,
            bounded: true,
            pressure,
            gc_available: true,
            online_physical_checkpoint_available: false,
            manual_physical_compaction_available: false,
        })
    }

    fn plan_runtime_ledger_gc(
        &self,
        retain_state_versions: u64,
        max_record_work: u64,
        retirement_generation: u64,
    ) -> CliResult<RuntimeLedgerGcPlan> {
        if !(MIN_RUNTIME_RETAINED_STATES..=MAX_RUNTIME_RETAINED_STATES)
            .contains(&retain_state_versions)
            || max_record_work == 0
            || max_record_work > MAX_RUNTIME_GC_RECORD_WORK
        {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "runtime ledger GC bounds are outside the production contract",
                false,
            )
            .into());
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let durable = self.durable_head_from(&snapshot)?;
        if retirement_generation
            != durable
                .generation
                .checked_add(1)
                .ok_or_else(|| integrity("production durable generation is exhausted"))?
        {
            return Err(integrity("runtime GC selected another durable successor").into());
        }
        self.verify_runtime_ledger_from(&snapshot, durable.generation)?;

        let mut states = BTreeMap::<String, Vec<(Vec<u8>, StoredRuntimeState)>>::new();
        let mut receipts =
            BTreeMap::<(String, u64), Vec<(Vec<u8>, StoredRuntimeLifecycleReceipt)>>::new();
        let mut existing_anchors = BTreeMap::<String, StoredRuntimeGcAnchor>::new();
        for entry in snapshot
            .scan_prefix(&self.runtime, b"")
            .map_err(storage_error)?
        {
            match classify_runtime_ledger_key(&entry.key)? {
                RuntimeLedgerKeyKind::State => {
                    let state: StoredRuntimeState = serde_json::from_slice(&entry.value)
                        .map_err(|_| integrity("production runtime state is invalid"))?;
                    states
                        .entry(state.identity_digest.clone())
                        .or_default()
                        .push((entry.key, state));
                }
                RuntimeLedgerKeyKind::Receipt => {
                    let receipt: StoredRuntimeLifecycleReceipt =
                        serde_json::from_slice(&entry.value).map_err(|_| {
                            integrity("production runtime lifecycle receipt is invalid")
                        })?;
                    if !receipt.retired {
                        receipts
                            .entry((receipt.state_identity_digest.clone(), receipt.state_version))
                            .or_default()
                            .push((entry.key, receipt));
                    }
                }
                RuntimeLedgerKeyKind::GcAnchor => {
                    let anchor: StoredRuntimeGcAnchor = serde_json::from_slice(&entry.value)
                        .map_err(|_| integrity("production runtime GC anchor is invalid"))?;
                    existing_anchors.insert(anchor.identity_digest.clone(), anchor);
                }
                RuntimeLedgerKeyKind::Head | RuntimeLedgerKeyKind::CheckpointHead => {}
            }
        }
        for values in states.values_mut() {
            values.sort_by_key(|(_, state)| state.version);
        }

        let retain = usize::try_from(retain_state_versions)
            .map_err(|_| integrity("runtime retention bound exceeds this platform"))?;
        let mut remaining_work = max_record_work;
        let mut state_keys = BTreeSet::new();
        let mut selected_checkpoints = BTreeSet::new();
        let mut retained_checkpoints = BTreeSet::new();
        let mut retired_receipts = BTreeMap::new();
        let mut anchors = BTreeMap::new();

        for (identity, history) in &states {
            let eligible = history.len().saturating_sub(retain);
            if eligible == 0 || remaining_work < 3 {
                for (_, state) in history {
                    retained_checkpoints.insert(state.checkpoint.digest.to_string());
                }
                continue;
            }
            let mut anchor = existing_anchors.get(identity).cloned();
            let mut selected = 0_usize;
            for (key, state) in history.iter().take(eligible) {
                let related_receipts = receipts
                    .get(&(identity.clone(), state.version))
                    .map_or(0_usize, Vec::len);
                // State delete, possible checkpoint-head delete, receipt
                // rewrites, and a conservative anchor-write allowance.
                let cost = u64::try_from(related_receipts)
                    .ok()
                    .and_then(|value| value.checked_add(3))
                    .ok_or_else(|| integrity("runtime GC work estimate is exhausted"))?;
                if cost > remaining_work {
                    break;
                }
                let expected_version = anchor
                    .as_ref()
                    .map_or(1, |value| value.pruned_through_version.saturating_add(1));
                let expected_previous = anchor
                    .as_ref()
                    .map(|value| value.terminal_state_digest.clone());
                if state.version != expected_version
                    || state.previous_state_digest != expected_previous
                {
                    return Err(integrity(
                        "runtime GC source does not extend its authenticated anchor",
                    )
                    .into());
                }
                let accumulator = self.extend_runtime_gc_accumulator(anchor.as_ref(), state)?;
                let anchor_key = runtime_gc_anchor_key(identity)?;
                let mut next_anchor = StoredRuntimeGcAnchor {
                    schema_version: STORE_SCHEMA_VERSION,
                    identity_digest: identity.clone(),
                    pruned_through_version: state.version,
                    terminal_state_digest: state.state_digest.clone(),
                    accumulator_digest: accumulator,
                    updated_at_generation: retirement_generation,
                    checksum: String::new(),
                };
                next_anchor.checksum =
                    self.runtime_gc_anchor_checksum(&anchor_key, &next_anchor)?;
                anchor = Some(next_anchor);
                state_keys.insert(key.clone());
                selected_checkpoints.insert(state.checkpoint.digest.to_string());
                if let Some(values) = receipts.get(&(identity.clone(), state.version)) {
                    for (receipt_key, source) in values {
                        let mut retired = source.clone();
                        retired.response_bytes.clear();
                        retired.retired = true;
                        retired.retired_at_generation = Some(retirement_generation);
                        retired.checksum =
                            self.runtime_lifecycle_receipt_checksum(receipt_key, &retired)?;
                        retired_receipts.insert(receipt_key.clone(), retired);
                    }
                }
                selected = selected.saturating_add(1);
                remaining_work = remaining_work.saturating_sub(cost);
            }
            if let Some(anchor) = anchor.filter(|_| selected > 0) {
                anchors.insert(runtime_gc_anchor_key(identity)?, anchor);
            }
            for (_, state) in history.iter().skip(selected) {
                retained_checkpoints.insert(state.checkpoint.digest.to_string());
            }
        }

        let checkpoint_head_keys = selected_checkpoints
            .difference(&retained_checkpoints)
            .map(|digest| runtime_checkpoint_head_key(digest))
            .collect::<CliResult<BTreeSet<_>>>()?;
        let actual_work = state_keys
            .len()
            .saturating_add(checkpoint_head_keys.len())
            .saturating_add(retired_receipts.len())
            .saturating_add(anchors.len());
        if u64::try_from(actual_work).map_or(true, |work| work > max_record_work) {
            return Err(integrity("runtime GC plan exceeded its admitted work bound").into());
        }
        Ok(RuntimeLedgerGcPlan {
            state_keys,
            checkpoint_head_keys,
            retired_receipts,
            anchors,
        })
    }

    fn apply_runtime_ledger_gc(
        &self,
        plan: RuntimeLedgerGcPlan,
        expected_durable: &DurableLedgerHead,
        receipt_key: &[u8],
        request_commitment: String,
    ) -> CliResult<RuntimeLedgerGcReportV1> {
        validate_runtime_gc_receipt_key(receipt_key)?;
        validate_digest(&request_commitment, "runtime GC request commitment")?;
        let state_records_pruned = u64::try_from(plan.state_keys.len())
            .map_err(|_| integrity("runtime GC state count exceeds this platform"))?;
        let checkpoint_heads_pruned = u64::try_from(plan.checkpoint_head_keys.len())
            .map_err(|_| integrity("runtime GC checkpoint count exceeds this platform"))?;
        let receipts_retired = u64::try_from(plan.retired_receipts.len())
            .map_err(|_| integrity("runtime GC receipt count exceeds this platform"))?;
        let anchors_updated = u64::try_from(plan.anchors.len())
            .map_err(|_| integrity("runtime GC anchor count exceeds this platform"))?;
        let changed = !plan.state_keys.is_empty();
        let mut report = runtime_gc_report(
            if changed { "applied" } else { "no_op" },
            false,
            state_records_pruned,
            checkpoint_heads_pruned,
            receipts_retired,
            anchors_updated,
            changed,
        );

        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if self.durable_head_from(&transaction)? != *expected_durable {
            return Err(integrity("production state changed during runtime ledger GC").into());
        }
        if transaction
            .get(&self.idempotency, receipt_key)
            .map_err(storage_error)?
            .is_some()
        {
            return Err(integrity("production runtime GC idempotency changed concurrently").into());
        }
        let rooted_count = self.non_event_receipt_count(&transaction)?;
        let actual_count = self.non_event_receipt_entries(&transaction)?;
        if usize::try_from(rooted_count).ok() != Some(actual_count) {
            return Err(
                integrity("production non-event receipt count changed before runtime GC").into(),
            );
        }
        if actual_count >= MAX_NON_EVENT_RECEIPTS {
            return Err(resource_exhausted(
                "production non-event receipt limit is exhausted",
                false,
            )
            .into());
        }
        let next_count = rooted_count.checked_add(1).ok_or_else(|| {
            resource_exhausted("production non-event receipt count is exhausted", false)
        })?;
        let successor_generation = expected_durable
            .generation
            .checked_add(1)
            .ok_or_else(|| integrity("production durable generation is exhausted"))?;
        let receipt_id = self.digest(
            b"maintenance_runtime_gc_receipt_id",
            &canonical_bytes(&(receipt_key, &request_commitment, successor_generation))?,
        );
        report.receipt_id = Some(receipt_id.clone());
        report.durable_receipt_recorded = true;

        if !changed
            && (!plan.checkpoint_head_keys.is_empty()
                || !plan.retired_receipts.is_empty()
                || !plan.anchors.is_empty())
        {
            return Err(integrity("empty runtime GC plan contains orphan mutations").into());
        }
        for key in plan.state_keys {
            transaction
                .delete(&self.runtime, key)
                .map_err(storage_error)?;
        }
        for key in plan.checkpoint_head_keys {
            transaction
                .delete(&self.runtime, key)
                .map_err(storage_error)?;
        }
        for (key, receipt) in plan.retired_receipts {
            transaction
                .put(&self.runtime, key, canonical_bytes(&receipt)?)
                .map_err(storage_error)?;
        }
        for (key, anchor) in plan.anchors {
            transaction
                .put(&self.runtime, key, canonical_bytes(&anchor)?)
                .map_err(storage_error)?;
        }
        let response_payload = serde_json::to_value(&report)
            .map_err(|_| integrity("runtime GC report serialization failed"))?;
        let mut receipt = StoredRuntimeGcReceipt {
            schema_version: STORE_SCHEMA_VERSION,
            receipt_id,
            request_commitment,
            response_payload,
            durable_generation: successor_generation,
            checksum: String::new(),
        };
        receipt.checksum = self.runtime_gc_receipt_checksum(receipt_key, &receipt)?;
        self.validate_runtime_gc_receipt(receipt_key, &receipt, successor_generation)?;
        let receipt_bytes = canonical_bytes(&receipt)?;
        if receipt_bytes.len() > MAX_RUNTIME_GC_RECEIPT_BYTES {
            return Err(resource_exhausted(
                "runtime GC receipt exceeds the 8 KiB durable limit",
                false,
            )
            .into());
        }
        transaction
            .put(&self.idempotency, receipt_key.to_vec(), receipt_bytes)
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                NON_EVENT_RECEIPT_COUNT_KEY.to_vec(),
                next_count.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        self.verify_runtime_ledger_from(&transaction, successor_generation)?;
        let successor = self.stage_durable_successor(&mut transaction)?;
        if successor.generation != successor_generation {
            return Err(integrity("runtime GC selected another durable generation").into());
        }
        let committed = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(committed.durability)?;
        Ok(report)
    }

    fn runtime_gc_identity_digest(
        &self,
        context: &contextdb_service::AuthenticatedRequestContext,
        operation_id: &str,
    ) -> CliResult<String> {
        let header = self.header()?;
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            "maintenance_runtime_gc",
            &header.database_id,
            &context.request.workspace_id,
            &context.request.subject_id,
            &context.actor_id,
            &context.agent_id,
            &context.session_id,
            operation_id,
        ))?);
        Ok(self.digest(b"maintenance_runtime_gc_identity", &material))
    }

    fn runtime_gc_request_commitment(
        &self,
        identity_digest: &str,
        authorization_binding_digest: &str,
        canonical_payload: &[u8],
    ) -> CliResult<String> {
        validate_digest(identity_digest, "runtime GC operation identity")?;
        validate_digest(
            authorization_binding_digest,
            "runtime GC authorization binding",
        )?;
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            "maintenance_runtime_gc",
            identity_digest,
            authorization_binding_digest,
            canonical_payload,
        ))?);
        Ok(self.digest(b"maintenance_runtime_gc_request", &material))
    }

    fn runtime_gc_receipt_checksum(
        &self,
        key: &[u8],
        receipt: &StoredRuntimeGcReceipt,
    ) -> CliResult<String> {
        let mut unsigned = receipt.clone();
        unsigned.checksum.clear();
        Ok(self.digest(
            b"maintenance_runtime_gc_receipt",
            &canonical_bytes(&(key, unsigned))?,
        ))
    }

    fn validate_runtime_gc_receipt(
        &self,
        key: &[u8],
        receipt: &StoredRuntimeGcReceipt,
        current_generation: u64,
    ) -> CliResult<()> {
        validate_runtime_gc_receipt_key(key)?;
        let report: RuntimeLedgerGcReportV1 =
            serde_json::from_value(receipt.response_payload.clone())
                .map_err(|_| integrity("production runtime GC response payload is invalid"))?;
        if receipt.schema_version != STORE_SCHEMA_VERSION
            || validate_digest(&receipt.receipt_id, "runtime GC receipt ID").is_err()
            || validate_digest(&receipt.request_commitment, "runtime GC request commitment")
                .is_err()
            || receipt.durable_generation == 0
            || receipt.durable_generation > current_generation
            || report.schema_version != STORE_SCHEMA_VERSION
            || report.dry_run
            || report.replayed
            || !report.durable_receipt_recorded
            || report.receipt_id.as_deref() != Some(receipt.receipt_id.as_str())
            || !matches!(report.status.as_str(), "applied" | "no_op")
            || report.physical_bytes_reclaimed.is_some()
            || receipt.checksum != self.runtime_gc_receipt_checksum(key, receipt)?
        {
            return Err(
                integrity("production runtime GC receipt failed integrity validation").into(),
            );
        }
        Ok(())
    }

    fn runtime_gc_receipt(
        &self,
        key: &[u8],
        request_commitment: &str,
    ) -> CliResult<Option<StoredRuntimeGcReceipt>> {
        validate_runtime_gc_receipt_key(key)?;
        validate_digest(request_commitment, "runtime GC request commitment")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let Some(bytes) = snapshot
            .get(&self.idempotency, key)
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        if bytes.is_empty() || bytes.len() > MAX_RUNTIME_GC_RECEIPT_BYTES {
            return Err(integrity("production runtime GC receipt is out of bounds").into());
        }
        let receipt: StoredRuntimeGcReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("production runtime GC receipt is invalid"))?;
        let durable = self.durable_head_from(&snapshot)?;
        self.validate_runtime_gc_receipt(key, &receipt, durable.generation)?;
        if receipt.request_commitment != request_commitment {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "runtime GC operation ID was reused with different bounds or authority",
                false,
            )
            .into());
        }
        Ok(Some(receipt))
    }

    fn reindex_identity_digest(
        &self,
        context: &contextdb_service::AuthenticatedRequestContext,
        operation_id: &str,
    ) -> CliResult<String> {
        let header = self.header()?;
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            "maintenance_reindex",
            &header.database_id,
            &context.request.workspace_id,
            &context.request.subject_id,
            &context.actor_id,
            &context.agent_id,
            &context.session_id,
            operation_id,
        ))?);
        Ok(self.digest(b"maintenance_reindex_identity", &material))
    }

    fn reindex_request_commitment(
        &self,
        identity_digest: &str,
        authorization_binding_digest: &str,
        canonical_payload: &[u8],
    ) -> CliResult<String> {
        validate_digest(identity_digest, "reindex keyed operation identity")?;
        validate_digest(
            authorization_binding_digest,
            "reindex authorization binding digest",
        )?;
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            "maintenance_reindex",
            identity_digest,
            authorization_binding_digest,
            canonical_payload,
        ))?);
        Ok(self.digest(b"maintenance_reindex_request", &material))
    }

    fn reindex_source_commitment(
        &self,
        projection: &CurrentProjection,
        graph: &PolicyGraphProjection,
    ) -> CliResult<String> {
        let material = Zeroizing::new(canonical_bytes(&(
            STORE_SCHEMA_VERSION,
            "production_policy_graph_v1",
            &projection.database_id,
            projection.commit_seq,
            &projection.archive_digest,
            graph.generation,
            &graph.digest,
        ))?);
        Ok(self.digest(b"maintenance_reindex_source", &material))
    }

    fn reindex_receipt(
        &self,
        key: &[u8],
        request_commitment: &str,
    ) -> CliResult<Option<StoredReindexReceipt>> {
        validate_reindex_receipt_key(key)?;
        validate_digest(request_commitment, "reindex request commitment")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let Some(bytes) = snapshot
            .get(&self.idempotency, key)
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        if bytes.is_empty() || bytes.len() > MAX_REINDEX_RECEIPT_BYTES {
            return Err(integrity("production reindex receipt is out of bounds").into());
        }
        let receipt: StoredReindexReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("production reindex receipt is invalid"))?;
        let durable = self.durable_head_from(&snapshot)?;
        self.validate_reindex_receipt(key, &receipt, durable.generation)?;
        if receipt.request_commitment != request_commitment {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "reindex operation ID was reused with different canonical input or authority",
                false,
            )
            .into());
        }
        Ok(Some(receipt))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "explicit expected-state tuple keeps every publication recheck visible"
    )]
    fn append_reindex_receipt(
        &self,
        key: &[u8],
        request_commitment: String,
        source_commitment: String,
        expected_projection: &CurrentProjection,
        expected_graph: &PolicyGraphProjection,
        expected_durable: &DurableLedgerHead,
        candidate_bytes: &[u8],
    ) -> CliResult<StoredReindexReceipt> {
        self.append_reindex_receipt_with_limit(
            key,
            request_commitment,
            source_commitment,
            expected_projection,
            expected_graph,
            expected_durable,
            candidate_bytes,
            MAX_NON_EVENT_RECEIPTS,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test-local admission limit extends the explicit expected-state tuple"
    )]
    fn append_reindex_receipt_with_limit(
        &self,
        key: &[u8],
        request_commitment: String,
        source_commitment: String,
        expected_projection: &CurrentProjection,
        expected_graph: &PolicyGraphProjection,
        expected_durable: &DurableLedgerHead,
        candidate_bytes: &[u8],
        limit: usize,
    ) -> CliResult<StoredReindexReceipt> {
        validate_reindex_receipt_key(key)?;
        validate_digest(&request_commitment, "reindex request commitment")?;
        validate_digest(&source_commitment, "reindex source commitment")?;
        if source_commitment
            != self.reindex_source_commitment(expected_projection, expected_graph)?
        {
            return Err(integrity("production reindex source commitment changed").into());
        }
        if candidate_bytes.is_empty() || candidate_bytes.len() > MAX_REINDEX_CANDIDATE_BYTES {
            return Err(resource_exhausted(
                "production policy-graph reindex candidate exceeds the 512 MiB limit",
                false,
            )
            .into());
        }
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if transaction
            .get(&self.idempotency, key)
            .map_err(storage_error)?
            .is_some()
        {
            return Err(integrity("production reindex idempotency changed concurrently").into());
        }
        let rooted_count = self.non_event_receipt_count(&transaction)?;
        let actual_count = self.non_event_receipt_entries(&transaction)?;
        if usize::try_from(rooted_count).ok() != Some(actual_count) {
            return Err(
                integrity("production non-event receipt count changed before reindex").into(),
            );
        }
        if actual_count >= limit {
            return Err(resource_exhausted(
                "production non-event receipt limit is exhausted",
                false,
            )
            .into());
        }
        let next_count = rooted_count.checked_add(1).ok_or_else(|| {
            resource_exhausted("production non-event receipt count is exhausted", false)
        })?;

        let projection_bytes = transaction
            .get(&self.meta, CURRENT_PROJECTION_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("production current projection is missing"))?;
        let current_projection: CurrentProjection = serde_json::from_slice(&projection_bytes)
            .map_err(|_| integrity("production current projection is invalid"))?;
        validate_projection(&self.mac_key, &current_projection)?;
        if current_projection != *expected_projection
            || self.head(&transaction)? != expected_graph.generation
            || self.durable_head_from(&transaction)? != *expected_durable
        {
            return Err(integrity("production source changed during policy-graph reindex").into());
        }
        let graph_entries = transaction
            .scan_prefix(&self.graph, b"")
            .map_err(storage_error)?;
        if graph_entries.len() != 1
            || graph_entries[0].key != POLICY_GRAPH_KEY
            || graph_entries[0].value != candidate_bytes
            || canonical_bytes(expected_graph)? != candidate_bytes
        {
            return Err(integrity(
                "production policy graph changed during verified reindex publication",
            )
            .into());
        }

        // Randomness is requested only after all admission and source
        // consistency checks have passed.
        let mut receipt_random = [0_u8; 32];
        getrandom::fill(&mut receipt_random)
            .map_err(|_| unavailable("reindex receipt randomness is unavailable"))?;
        let receipt_id = blake3::Hash::from_bytes(receipt_random)
            .to_hex()
            .to_string();
        let durable_generation = expected_durable
            .generation
            .checked_add(1)
            .ok_or_else(|| integrity("production durable generation is exhausted"))?;
        let mut receipt = StoredReindexReceipt {
            schema_version: STORE_SCHEMA_VERSION,
            receipt_id,
            request_commitment,
            source_commitment,
            durable_generation,
            checksum: String::new(),
        };
        receipt.checksum = self.reindex_receipt_checksum(key, &receipt)?;
        // Replacing this exact singleton is intentional: the candidate was
        // independently rebuilt and compared byte-for-byte above.
        transaction
            .put(
                &self.graph,
                POLICY_GRAPH_KEY.to_vec(),
                candidate_bytes.to_vec(),
            )
            .map_err(storage_error)?;
        transaction
            .put(&self.idempotency, key.to_vec(), canonical_bytes(&receipt)?)
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                NON_EVENT_RECEIPT_COUNT_KEY.to_vec(),
                next_count.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        let successor = self.stage_durable_successor(&mut transaction)?;
        if successor.generation != receipt.durable_generation {
            return Err(integrity("reindex receipt selected another durable generation").into());
        }
        let committed = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(committed.durability)?;
        Ok(receipt)
    }

    fn reindex_receipt_checksum(
        &self,
        key: &[u8],
        receipt: &StoredReindexReceipt,
    ) -> CliResult<String> {
        let mut unsigned = receipt.clone();
        unsigned.checksum.clear();
        Ok(self.digest(
            b"maintenance_reindex_receipt",
            &canonical_bytes(&(key, unsigned))?,
        ))
    }

    fn validate_reindex_receipt(
        &self,
        key: &[u8],
        receipt: &StoredReindexReceipt,
        current_generation: u64,
    ) -> CliResult<()> {
        validate_reindex_receipt_key(key)?;
        if receipt.schema_version != STORE_SCHEMA_VERSION
            || validate_digest(&receipt.receipt_id, "reindex receipt ID").is_err()
            || validate_digest(&receipt.request_commitment, "reindex request commitment").is_err()
            || validate_digest(&receipt.source_commitment, "reindex source commitment").is_err()
            || receipt.durable_generation == 0
            || receipt.durable_generation > current_generation
            || receipt.checksum != self.reindex_receipt_checksum(key, receipt)?
        {
            return Err(integrity("production reindex receipt failed integrity validation").into());
        }
        Ok(())
    }

    fn stream_digest(&self, workspace_id: &str, stream_id: &str) -> CliResult<String> {
        let material = canonical_bytes(&(STREAM_SCHEMA_VERSION, workspace_id, stream_id))?;
        Ok(self.digest(b"stream_identity", &material))
    }

    fn stream_completion_idempotency_digest(&self, stream_digest: &str) -> String {
        self.digest(Operation::StreamIngest.domain(), stream_digest.as_bytes())
    }

    fn stream_states(&self) -> CliResult<Vec<StoredStreamState>> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let entries = snapshot
            .scan_prefix(&self.streams, STREAM_STATE_PREFIX)
            .map_err(storage_error)?;
        if entries.len() > MAX_OPEN_STREAMS {
            return Err(integrity("production open-stream limit was exceeded").into());
        }
        entries
            .into_iter()
            .map(|entry| {
                let stream_digest = parse_stream_state_key(&entry.key)?;
                let plaintext =
                    self.open_stream_record(b"state", &entry.key, &entry.value, 64 * 1024)?;
                let state: StoredStreamState = serde_json::from_slice(&plaintext)
                    .map_err(|_| integrity("encrypted production stream state is invalid"))?;
                self.validate_stream_state(&state, &stream_digest)?;
                Ok(state)
            })
            .collect()
    }

    fn load_stream(&self, stream_digest: &str) -> CliResult<Option<LoadedStream>> {
        validate_digest(stream_digest, "production stream digest")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let state_key = stream_state_key(stream_digest);
        let Some(state_bytes) = snapshot
            .get(&self.streams, &state_key)
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let state_plaintext =
            self.open_stream_record(b"state", &state_key, &state_bytes, 64 * 1024)?;
        let state: StoredStreamState = serde_json::from_slice(&state_plaintext)
            .map_err(|_| integrity("encrypted production stream state is invalid"))?;
        self.validate_stream_state(&state, stream_digest)?;

        let frame_prefix = stream_position_prefix(STREAM_FRAME_PREFIX, stream_digest);
        let frame_entries = snapshot
            .scan_prefix(&self.streams, &frame_prefix)
            .map_err(storage_error)?;
        let receipt_prefix = stream_position_prefix(STREAM_RECEIPT_PREFIX, stream_digest);
        let receipt_entries = snapshot
            .scan_prefix(&self.streams, &receipt_prefix)
            .map_err(storage_error)?;
        let expected_count = usize::try_from(state.next_position)
            .map_err(|_| integrity("production stream position exceeds this platform"))?;
        if frame_entries.len() != expected_count || receipt_entries.len() != expected_count {
            return Err(integrity("production stream replay records are incomplete").into());
        }

        let mut frames = BTreeMap::new();
        let mut buffered_bytes = 0_usize;
        for entry in frame_entries {
            let position =
                parse_stream_position_key(&entry.key, STREAM_FRAME_PREFIX, stream_digest)?;
            let plaintext = self.open_stream_record(
                b"frame",
                &entry.key,
                &entry.value,
                MAX_STREAM_FRAME_BYTES,
            )?;
            buffered_bytes = buffered_bytes
                .checked_add(plaintext.len())
                .filter(|bytes| *bytes <= MAX_STREAM_BUFFERED_BYTES)
                .ok_or_else(|| integrity("production stream byte limit was exceeded"))?;
            let frame: StoredStreamFrame = serde_json::from_slice(&plaintext)
                .map_err(|_| integrity("encrypted production stream frame is invalid"))?;
            validate_stored_stream_frame(&frame, stream_digest, &state, position, self)?;
            if frames.insert(position, frame).is_some() {
                return Err(integrity("production stream frame position is duplicated").into());
            }
        }
        if u64::try_from(buffered_bytes).unwrap_or(u64::MAX) != state.buffered_bytes {
            return Err(integrity("production stream byte accounting changed").into());
        }

        let mut receipts = BTreeMap::new();
        for entry in receipt_entries {
            let position =
                parse_stream_position_key(&entry.key, STREAM_RECEIPT_PREFIX, stream_digest)?;
            let plaintext = self.open_stream_record(
                b"receipt",
                &entry.key,
                &entry.value,
                MAX_STREAM_FRAME_BYTES,
            )?;
            let receipt: StoredStreamReceipt = serde_json::from_slice(&plaintext)
                .map_err(|_| integrity("encrypted production stream receipt is invalid"))?;
            if receipts.insert(position, receipt).is_some() {
                return Err(integrity("production stream receipt position is duplicated").into());
            }
        }
        validate_loaded_stream(&state, &frames, &receipts, self)?;
        Ok(Some(LoadedStream {
            state,
            frames,
            receipts,
        }))
    }

    fn load_expired_stream(&self, stream_digest: &str) -> CliResult<Option<StoredExpiredStream>> {
        validate_digest(stream_digest, "production expired stream digest")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let key = stream_expired_key(stream_digest);
        let Some(bytes) = snapshot.get(&self.streams, &key).map_err(storage_error)? else {
            return Ok(None);
        };
        let plaintext =
            self.open_stream_record(b"expired", &key, &bytes, MAX_EXPIRED_STREAM_BYTES)?;
        let expired: StoredExpiredStream = serde_json::from_slice(&plaintext)
            .map_err(|_| integrity("encrypted expired stream tombstone is invalid"))?;
        self.validate_expired_stream(&expired, stream_digest)?;
        Ok(Some(expired))
    }

    fn persist_stream_frame(
        &self,
        state: &StoredStreamState,
        frame: &StoredStreamFrame,
        receipt: &StoredStreamReceipt,
    ) -> CliResult<()> {
        let state_key = stream_state_key(&state.stream_digest);
        let frame_key =
            stream_position_key(STREAM_FRAME_PREFIX, &state.stream_digest, frame.position);
        let receipt_key =
            stream_position_key(STREAM_RECEIPT_PREFIX, &state.stream_digest, frame.position);
        let state_bytes = self.seal_stream_value(b"state", &state_key, state, 64 * 1024)?;
        let frame_bytes =
            self.seal_stream_value(b"frame", &frame_key, frame, MAX_STREAM_FRAME_BYTES)?;
        let receipt_bytes =
            self.seal_stream_value(b"receipt", &receipt_key, receipt, MAX_STREAM_FRAME_BYTES)?;
        reject_duplicate_envelope_nonces([&state_bytes, &frame_bytes, &receipt_bytes])?;

        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        self.reserve_stream_nonces(
            &mut transaction,
            [&state_bytes[..], &frame_bytes[..], &receipt_bytes[..]],
        )?;
        if transaction
            .get(&self.streams, &frame_key)
            .map_err(storage_error)?
            .is_some()
            || transaction
                .get(&self.streams, &receipt_key)
                .map_err(storage_error)?
                .is_some()
        {
            return Err(integrity("production stream position changed concurrently").into());
        }
        if frame.position == 0 {
            if transaction
                .get(&self.streams, &state_key)
                .map_err(storage_error)?
                .is_some()
            {
                return Err(integrity("production stream identity changed concurrently").into());
            }
            let states = transaction
                .scan_prefix(&self.streams, STREAM_STATE_PREFIX)
                .map_err(storage_error)?;
            if states.len() >= MAX_OPEN_STREAMS {
                return Err(
                    resource_exhausted("production open-stream limit is exhausted", true).into(),
                );
            }
            let mut workspace_open = 0_usize;
            for entry in states {
                let existing_digest = parse_stream_state_key(&entry.key)?;
                let plaintext =
                    self.open_stream_record(b"state", &entry.key, &entry.value, 64 * 1024)?;
                let existing: StoredStreamState = serde_json::from_slice(&plaintext)
                    .map_err(|_| integrity("encrypted production stream state is invalid"))?;
                self.validate_stream_state(&existing, &existing_digest)?;
                if existing.workspace_id == state.workspace_id {
                    workspace_open = workspace_open.checked_add(1).ok_or_else(|| {
                        integrity("production workspace stream count is exhausted")
                    })?;
                }
            }
            if workspace_open >= MAX_OPEN_STREAMS_PER_WORKSPACE {
                return Err(resource_exhausted(
                    "production workspace open-stream limit is exhausted",
                    true,
                )
                .into());
            }
        } else {
            let previous_bytes = transaction
                .get(&self.streams, &state_key)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("production stream state disappeared concurrently"))?;
            let previous_plaintext =
                self.open_stream_record(b"state", &state_key, &previous_bytes, 64 * 1024)?;
            let previous: StoredStreamState = serde_json::from_slice(&previous_plaintext)
                .map_err(|_| integrity("encrypted production stream state is invalid"))?;
            self.validate_stream_state(&previous, &state.stream_digest)?;
            if previous.next_position != frame.position
                || previous.workspace_id != state.workspace_id
                || previous.stream_id != state.stream_id
                || previous.authorization_digest != state.authorization_digest
                || previous.buffered_bytes >= state.buffered_bytes
                || previous.lease_expires_at_ms > state.lease_expires_at_ms
            {
                return Err(integrity("production stream state changed concurrently").into());
            }
        }
        transaction
            .put(&self.streams, state_key, state_bytes)
            .map_err(storage_error)?;
        transaction
            .put(&self.streams, frame_key, frame_bytes)
            .map_err(storage_error)?;
        transaction
            .put(&self.streams, receipt_key, receipt_bytes)
            .map_err(storage_error)?;
        self.stage_durable_successor(&mut transaction)?;
        let committed = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(committed.durability)
    }

    /// Reclaims only authenticated staging records whose host-clock lease has
    /// expired. The deletion and its new durable root are one Sync commit; the
    /// caller must reconcile the external state-head before exposing an ACK or
    /// admitting another stream.
    fn reclaim_expired_streams(&self, now_ms: u64) -> CliResult<bool> {
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        let states = transaction
            .scan_prefix(&self.streams, STREAM_STATE_PREFIX)
            .map_err(storage_error)?;
        let mut expired = Vec::new();
        for entry in states {
            let stream_digest = parse_stream_state_key(&entry.key)?;
            let plaintext =
                self.open_stream_record(b"state", &entry.key, &entry.value, 64 * 1024)?;
            let state: StoredStreamState = serde_json::from_slice(&plaintext)
                .map_err(|_| integrity("encrypted production stream state is invalid"))?;
            self.validate_stream_state(&state, &stream_digest)?;
            if state.lease_expires_at_ms == 0 || state.lease_expires_at_ms <= now_ms {
                let receipt_prefix = stream_position_prefix(STREAM_RECEIPT_PREFIX, &stream_digest);
                let receipt_entries = transaction
                    .scan_prefix(&self.streams, &receipt_prefix)
                    .map_err(storage_error)?;
                let mut request_digests = BTreeMap::new();
                for receipt_entry in receipt_entries {
                    let position = parse_stream_position_key(
                        &receipt_entry.key,
                        STREAM_RECEIPT_PREFIX,
                        &stream_digest,
                    )?;
                    let receipt_plaintext = self.open_stream_record(
                        b"receipt",
                        &receipt_entry.key,
                        &receipt_entry.value,
                        MAX_STREAM_FRAME_BYTES,
                    )?;
                    let receipt: StoredStreamReceipt = serde_json::from_slice(&receipt_plaintext)
                        .map_err(|_| {
                        integrity("encrypted production stream receipt is invalid")
                    })?;
                    validate_digest(&receipt.request_digest, "expired stream request digest")?;
                    if receipt.position != position
                        || request_digests
                            .insert(position, receipt.request_digest)
                            .is_some()
                    {
                        return Err(
                            integrity("expired stream receipt sequence is inconsistent").into()
                        );
                    }
                }
                if request_digests.len()
                    != usize::try_from(state.next_position)
                        .map_err(|_| integrity("expired stream position exceeds this platform"))?
                {
                    return Err(integrity(
                        "expired stream tombstone would omit an acknowledged frame",
                    )
                    .into());
                }
                let tombstone = StoredExpiredStream {
                    schema_version: STREAM_SCHEMA_VERSION,
                    stream_digest: stream_digest.clone(),
                    workspace_id: state.workspace_id.clone(),
                    stream_id: state.stream_id.clone(),
                    authorization_digest: state.authorization_digest.clone(),
                    // Legacy pre-lease state decoded as zero. Migrating it to
                    // the exact reclaim instant makes the new tombstone valid
                    // and fail-closed without pretending the old ACK exposed a
                    // deadline it never carried.
                    lease_expires_at_ms: if state.lease_expires_at_ms == 0 {
                        now_ms
                    } else {
                        state.lease_expires_at_ms
                    },
                    request_digests,
                };
                self.validate_expired_stream(&tombstone, &stream_digest)?;
                let tombstone_key = stream_expired_key(&stream_digest);
                let tombstone_bytes = self.seal_stream_value(
                    b"expired",
                    &tombstone_key,
                    &tombstone,
                    MAX_EXPIRED_STREAM_BYTES,
                )?;
                expired.push((entry.key, stream_digest, tombstone_key, tombstone_bytes));
            }
        }
        if expired.is_empty() {
            return Ok(false);
        }
        let existing_tombstones = transaction
            .scan_prefix(&self.streams, STREAM_EXPIRED_PREFIX)
            .map_err(storage_error)?;
        if existing_tombstones
            .len()
            .checked_add(expired.len())
            .is_none_or(|count| count > MAX_EXPIRED_STREAMS)
        {
            return Err(resource_exhausted(
                "production expired-stream reservation limit is exhausted",
                false,
            )
            .into());
        }
        for (state_key, stream_digest, tombstone_key, tombstone_bytes) in expired {
            if transaction
                .get(&self.streams, &tombstone_key)
                .map_err(storage_error)?
                .is_some()
            {
                return Err(integrity("production expired stream identity is duplicated").into());
            }
            self.reserve_stream_nonces(&mut transaction, [&tombstone_bytes[..]])?;
            transaction
                .put(&self.streams, tombstone_key, tombstone_bytes)
                .map_err(storage_error)?;
            transaction
                .delete(&self.streams, state_key)
                .map_err(storage_error)?;
            for prefix in [STREAM_FRAME_PREFIX, STREAM_RECEIPT_PREFIX] {
                let position_prefix = stream_position_prefix(prefix, &stream_digest);
                for entry in transaction
                    .scan_prefix(&self.streams, &position_prefix)
                    .map_err(storage_error)?
                {
                    transaction
                        .delete(&self.streams, entry.key)
                        .map_err(storage_error)?;
                }
            }
        }
        self.stage_durable_successor(&mut transaction)?;
        let committed = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(committed.durability)?;
        Ok(true)
    }

    fn reserve_stream_nonces<const N: usize>(
        &self,
        transaction: &mut impl WriteTransaction,
        envelopes: [&[u8]; N],
    ) -> CliResult<()> {
        let mut call_nonces = BTreeSet::new();
        for envelope in envelopes {
            let nonce = envelope_nonce(envelope)?;
            if !call_nonces.insert(nonce) {
                return Err(integrity("production stream AEAD nonce was reused").into());
            }
            let key = stream_nonce_key(&nonce);
            if transaction
                .get(&self.streams, &key)
                .map_err(storage_error)?
                .is_some()
            {
                return Err(integrity("production stream AEAD nonce was reused").into());
            }
            transaction
                .put(
                    &self.streams,
                    key,
                    self.digest(b"stream_nonce", &nonce).into_bytes(),
                )
                .map_err(storage_error)?;
        }
        Ok(())
    }

    fn validate_stream_state(
        &self,
        state: &StoredStreamState,
        expected_stream_digest: &str,
    ) -> CliResult<()> {
        validate_digest(&state.stream_digest, "production stream digest")?;
        validate_digest(
            &state.authorization_digest,
            "production stream authorization digest",
        )?;
        if state.schema_version != STREAM_SCHEMA_VERSION
            || state.stream_digest != expected_stream_digest
            || state.next_position == 0
            || state.next_position > MAX_STREAM_ITEMS.saturating_add(1)
            || state.buffered_bytes == 0
            || state.buffered_bytes > MAX_STREAM_BUFFERED_BYTES as u64
            || !bounded_identifier(&state.workspace_id, 1_024)
            || !bounded_identifier(&state.stream_id, 1_024)
            || self.stream_digest(&state.workspace_id, &state.stream_id)? != state.stream_digest
        {
            return Err(integrity("production stream state failed validation").into());
        }
        Ok(())
    }

    fn validate_expired_stream(
        &self,
        expired: &StoredExpiredStream,
        expected_stream_digest: &str,
    ) -> CliResult<()> {
        validate_digest(&expired.stream_digest, "production expired stream digest")?;
        validate_digest(
            &expired.authorization_digest,
            "production expired stream authorization digest",
        )?;
        if expired.schema_version != STREAM_SCHEMA_VERSION
            || expired.stream_digest != expected_stream_digest
            || expired.lease_expires_at_ms == 0
            || expired.request_digests.is_empty()
            || expired.request_digests.len()
                > usize::try_from(MAX_STREAM_ITEMS.saturating_add(1)).unwrap_or(usize::MAX)
            || !bounded_identifier(&expired.workspace_id, 1_024)
            || !bounded_identifier(&expired.stream_id, 1_024)
            || self.stream_digest(&expired.workspace_id, &expired.stream_id)?
                != expired.stream_digest
        {
            return Err(integrity("production expired stream tombstone failed validation").into());
        }
        for (expected_position, (position, request_digest)) in
            (0_u64..).zip(&expired.request_digests)
        {
            if *position != expected_position
                || validate_digest(request_digest, "expired stream request digest").is_err()
            {
                return Err(
                    integrity("production expired stream request sequence is invalid").into(),
                );
            }
        }
        Ok(())
    }

    fn seal_stream_value<T: Serialize>(
        &self,
        kind: &[u8],
        record_key: &[u8],
        value: &T,
        maximum_plaintext: usize,
    ) -> CliResult<Vec<u8>> {
        let plaintext = Zeroizing::new(canonical_bytes(value)?);
        if plaintext.is_empty() || plaintext.len() > maximum_plaintext {
            return Err(resource_exhausted(
                "production encrypted stream record exceeds its bound",
                false,
            )
            .into());
        }
        let mut nonce = [0_u8; STREAM_NONCE_BYTES];
        getrandom::fill(&mut nonce)
            .map_err(|_| unavailable("operating-system randomness is unavailable"))?;
        self.seal_stream_bytes_with_nonce(kind, record_key, &plaintext, nonce)
    }

    fn seal_stream_bytes_with_nonce(
        &self,
        kind: &[u8],
        record_key: &[u8],
        plaintext: &[u8],
        nonce: [u8; STREAM_NONCE_BYTES],
    ) -> CliResult<Vec<u8>> {
        let header = self.header()?;
        let associated_data = stream_associated_data(&header.database_id, kind, record_key)?;
        let cipher_key = Key::from(**self.stream_aead_key);
        let cipher = XChaCha20Poly1305::new(&cipher_key);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| integrity("production stream encryption failed"))?;
        let mut envelope = Vec::with_capacity(
            STREAM_RECORD_MAGIC
                .len()
                .saturating_add(2)
                .saturating_add(STREAM_NONCE_BYTES)
                .saturating_add(ciphertext.len()),
        );
        envelope.extend_from_slice(STREAM_RECORD_MAGIC);
        envelope.extend_from_slice(&STREAM_SCHEMA_VERSION.to_be_bytes());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    fn open_stream_record(
        &self,
        kind: &[u8],
        record_key: &[u8],
        envelope: &[u8],
        maximum_plaintext: usize,
    ) -> CliResult<Zeroizing<Vec<u8>>> {
        let overhead = STREAM_RECORD_MAGIC
            .len()
            .saturating_add(2)
            .saturating_add(STREAM_NONCE_BYTES)
            .saturating_add(STREAM_TAG_BYTES);
        if envelope.len() <= overhead
            || envelope.len() > maximum_plaintext.saturating_add(overhead)
            || envelope.get(..STREAM_RECORD_MAGIC.len()) != Some(STREAM_RECORD_MAGIC)
        {
            return Err(integrity("production encrypted stream envelope is malformed").into());
        }
        let version_start = STREAM_RECORD_MAGIC.len();
        let version_end = version_start.saturating_add(2);
        let version: [u8; 2] = envelope[version_start..version_end]
            .try_into()
            .map_err(|_| integrity("production stream envelope version is malformed"))?;
        if u16::from_be_bytes(version) != STREAM_SCHEMA_VERSION {
            return Err(integrity("production stream envelope version is unsupported").into());
        }
        let nonce_end = version_end.saturating_add(STREAM_NONCE_BYTES);
        let nonce: [u8; STREAM_NONCE_BYTES] = envelope[version_end..nonce_end]
            .try_into()
            .map_err(|_| integrity("production stream envelope nonce is malformed"))?;
        let header = self.header()?;
        let associated_data = stream_associated_data(&header.database_id, kind, record_key)?;
        let cipher_key = Key::from(**self.stream_aead_key);
        let cipher = XChaCha20Poly1305::new(&cipher_key);
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &envelope[nonce_end..],
                    aad: &associated_data,
                },
            )
            .map_err(|_| integrity("production encrypted stream record failed authentication"))?;
        if plaintext.is_empty() || plaintext.len() > maximum_plaintext {
            return Err(integrity("production encrypted stream plaintext is out of bounds").into());
        }
        Ok(Zeroizing::new(plaintext))
    }

    fn append(
        &self,
        mut event: StoredEvent,
        archive: &[u8],
        expected_previous: &DurableLedgerHead,
    ) -> CliResult<CommittedSemanticPublication> {
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if self.durable_head_from(&transaction)? != *expected_previous {
            return Err(integrity("production durable predecessor changed concurrently").into());
        }
        let head = self.head(&transaction)?;
        let sequence = head
            .checked_add(1)
            .ok_or_else(|| integrity("production sequence is exhausted"))?;
        event.sequence = sequence;
        event.previous_event_checksum = if head == 0 {
            None
        } else {
            let previous = transaction
                .get(&self.events, &event_key(head))
                .map_err(storage_error)?
                .ok_or_else(|| integrity("previous production event is missing"))?;
            let previous: StoredEvent = serde_json::from_slice(&previous)
                .map_err(|_| integrity("previous production event is invalid"))?;
            Some(previous.checksum)
        };
        event.checksum = self.record_checksum(b"production-event-v1", &event)?;
        if transaction
            .get(&self.idempotency, event.idempotency_digest.as_bytes())
            .map_err(storage_error)?
            .is_some()
        {
            return Err(integrity("production idempotency index changed concurrently").into());
        }
        let mut index = IdempotencyIndex {
            schema_version: STORE_SCHEMA_VERSION,
            sequence,
            request_digest: event.request_digest.clone(),
            checksum: String::new(),
        };
        index.checksum = self.record_checksum(b"production-idempotency-v1", &index)?;
        let identity = super::state_head::inspect_archive(archive)
            .map_err(|_| integrity("candidate production projection is invalid"))?;
        if identity.commit_seq != event.projection_commit_seq
            || identity.archive_digest != event.projection_digest
        {
            return Err(integrity("candidate production projection binding changed").into());
        }
        let mut projection = CurrentProjection {
            schema_version: STORE_SCHEMA_VERSION,
            database_id: identity.database_id.clone(),
            commit_seq: identity.commit_seq,
            archive_digest: identity.archive_digest.clone(),
            archive: archive.to_vec(),
            checksum: String::new(),
        };
        projection.checksum = self.record_checksum(b"production-projection-v1", &projection)?;
        let graph = self.build_policy_graph_projection(archive, sequence)?;
        let graph_bytes = canonical_bytes(&graph)?;
        // Build the complete request-time accelerator before Fjall commits. A
        // bounds/indexing failure therefore cannot leave a synchronized state
        // which this process is unable to publish directly.
        let verified_graph = Arc::new(VerifiedPolicyGraph::new(graph)?);
        transaction
            .put(&self.events, event_key(sequence), canonical_bytes(&event)?)
            .map_err(storage_error)?;
        transaction
            .put(
                &self.idempotency,
                event.idempotency_digest.as_bytes().to_vec(),
                canonical_bytes(&index)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                HEAD_KEY.to_vec(),
                sequence.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                CURRENT_PROJECTION_KEY.to_vec(),
                canonical_bytes(&projection)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(&self.graph, POLICY_GRAPH_KEY.to_vec(), graph_bytes)
            .map_err(storage_error)?;
        let durable = self.stage_durable_successor(&mut transaction)?;
        let receipt = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        if receipt.durability != Durability::Sync {
            return Err(unavailable("Fjall did not achieve synchronized durability").into());
        }
        Ok(CommittedSemanticPublication {
            storage_sequence: receipt.sequence,
            identity,
            durable,
            graph: verified_graph,
        })
    }

    fn append_stream_completion(
        &self,
        mut event: StoredEvent,
        archive: &[u8],
        stream: &LoadedStream,
        acknowledgement: &IngestAck,
    ) -> CliResult<()> {
        if event.operation != Operation::StreamIngest
            || event.idempotency_digest
                != self.stream_completion_idempotency_digest(&stream.state.stream_digest)
            || acknowledgement.disposition != IngestDisposition::SnapshotCommitted
        {
            return Err(integrity("production stream completion binding is invalid").into());
        }
        event.response_bytes = self.seal_stream_value(
            b"completion_ack",
            event.idempotency_digest.as_bytes(),
            acknowledgement,
            MAX_STREAM_FRAME_BYTES,
        )?;
        event.response_digest = self.digest(b"response", &event.response_bytes);

        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        self.reserve_stream_nonces(&mut transaction, [&event.response_bytes[..]])?;
        let head = self.head(&transaction)?;
        let sequence = head
            .checked_add(1)
            .ok_or_else(|| integrity("production sequence is exhausted"))?;
        event.sequence = sequence;
        event.previous_event_checksum = if head == 0 {
            None
        } else {
            let previous = transaction
                .get(&self.events, &event_key(head))
                .map_err(storage_error)?
                .ok_or_else(|| integrity("previous production event is missing"))?;
            let previous: StoredEvent = serde_json::from_slice(&previous)
                .map_err(|_| integrity("previous production event is invalid"))?;
            Some(previous.checksum)
        };
        event.checksum = self.record_checksum(b"production-event-v1", &event)?;
        if transaction
            .get(&self.idempotency, event.idempotency_digest.as_bytes())
            .map_err(storage_error)?
            .is_some()
        {
            return Err(integrity("production stream idempotency changed concurrently").into());
        }
        let mut index = IdempotencyIndex {
            schema_version: STORE_SCHEMA_VERSION,
            sequence,
            request_digest: event.request_digest.clone(),
            checksum: String::new(),
        };
        index.checksum = self.record_checksum(b"production-idempotency-v1", &index)?;
        let identity = super::state_head::inspect_archive(archive)
            .map_err(|_| integrity("candidate production projection is invalid"))?;
        if identity.commit_seq != event.projection_commit_seq
            || identity.archive_digest != event.projection_digest
            || acknowledgement.commit_seq != Some(identity.commit_seq)
        {
            return Err(integrity("candidate stream projection binding changed").into());
        }
        let mut projection = CurrentProjection {
            schema_version: STORE_SCHEMA_VERSION,
            database_id: identity.database_id,
            commit_seq: identity.commit_seq,
            archive_digest: identity.archive_digest,
            archive: archive.to_vec(),
            checksum: String::new(),
        };
        projection.checksum = self.record_checksum(b"production-projection-v1", &projection)?;
        let graph = self.build_policy_graph_projection(archive, sequence)?;

        let state_key = stream_state_key(&stream.state.stream_digest);
        if transaction
            .get(&self.streams, &state_key)
            .map_err(storage_error)?
            .is_none()
        {
            return Err(integrity("production stream state disappeared before completion").into());
        }
        let frame_prefix = stream_position_prefix(STREAM_FRAME_PREFIX, &stream.state.stream_digest);
        let frames = transaction
            .scan_prefix(&self.streams, &frame_prefix)
            .map_err(storage_error)?;
        let receipt_prefix =
            stream_position_prefix(STREAM_RECEIPT_PREFIX, &stream.state.stream_digest);
        let receipts = transaction
            .scan_prefix(&self.streams, &receipt_prefix)
            .map_err(storage_error)?;
        let expected = usize::try_from(stream.state.next_position)
            .map_err(|_| integrity("production stream position exceeds this platform"))?;
        if frames.len() != expected || receipts.len() != expected {
            return Err(integrity("production stream cleanup set changed concurrently").into());
        }
        transaction
            .delete(&self.streams, state_key)
            .map_err(storage_error)?;
        for entry in frames.into_iter().chain(receipts) {
            transaction
                .delete(&self.streams, entry.key)
                .map_err(storage_error)?;
        }

        transaction
            .put(&self.events, event_key(sequence), canonical_bytes(&event)?)
            .map_err(storage_error)?;
        transaction
            .put(
                &self.idempotency,
                event.idempotency_digest.as_bytes().to_vec(),
                canonical_bytes(&index)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                HEAD_KEY.to_vec(),
                sequence.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.meta,
                CURRENT_PROJECTION_KEY.to_vec(),
                canonical_bytes(&projection)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.graph,
                POLICY_GRAPH_KEY.to_vec(),
                canonical_bytes(&graph)?,
            )
            .map_err(storage_error)?;
        self.stage_durable_successor(&mut transaction)?;
        let committed = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(committed.durability)
    }

    fn stream_completion_ack(&self, event: &StoredEvent) -> CliResult<IngestAck> {
        if event.operation != Operation::StreamIngest {
            return Err(
                integrity("production idempotency event is not a stream completion").into(),
            );
        }
        let plaintext = self.open_stream_record(
            b"completion_ack",
            event.idempotency_digest.as_bytes(),
            &event.response_bytes,
            MAX_STREAM_FRAME_BYTES,
        )?;
        let acknowledgement: IngestAck = serde_json::from_slice(&plaintext)
            .map_err(|_| integrity("encrypted production completion receipt is invalid"))?;
        if acknowledgement.disposition != IngestDisposition::SnapshotCommitted
            || acknowledgement.commit_seq != Some(event.projection_commit_seq)
        {
            return Err(integrity("production completion receipt is inconsistent").into());
        }
        Ok(acknowledgement)
    }

    fn digest(&self, domain: &[u8], bytes: &[u8]) -> String {
        keyed_digest(&self.mac_key, domain, bytes)
    }

    fn record_checksum<T>(&self, domain: &[u8], value: &T) -> CliResult<String>
    where
        T: Clone + Serialize + ChecksumField,
    {
        record_checksum(&self.mac_key, domain, value)
    }

    fn verify(&self) -> CliResult<()> {
        self.verify_physical_keyspaces(true)?;
        self.engine
            .verify(VerifyMode::Deep)
            .map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let classified_non_event_receipt_count = self.verify_key_layout(&snapshot, false, false)?;
        if self.non_event_receipt_count(&snapshot)? != classified_non_event_receipt_count {
            return Err(integrity("production non-event receipt count changed").into());
        }
        drop(snapshot);
        let header = self.header()?;
        let events = self.events()?;
        self.verify_streams(&events)?;
        let durable = self.verify_durable_history()?;
        let runtime_generations = self.verify_runtime_ledger(durable.generation)?;
        self.verify_idempotency(&events, durable.generation, &runtime_generations)?;
        let projection = self.current_projection()?;
        if projection.database_id != header.database_id {
            return Err(integrity("production projection database identity changed").into());
        }
        match events.last() {
            Some(last)
                if last.projection_commit_seq == projection.commit_seq
                    && last.projection_digest == projection.archive_digest => {}
            None if header.base_commit_seq == projection.commit_seq
                && header.initial_archive_digest == projection.archive_digest => {}
            Some(_) | None => {
                return Err(integrity("production head is not bound to current projection").into());
            }
        }
        self.policy_graph()?;
        Ok(())
    }

    fn verify_idempotency(
        &self,
        events: &[StoredEvent],
        current_generation: u64,
        runtime_generations: &BTreeSet<u64>,
    ) -> CliResult<()> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let entries = snapshot
            .scan_prefix(&self.idempotency, b"")
            .map_err(storage_error)?;
        let mut expected_events: BTreeMap<Vec<u8>, &StoredEvent> = events
            .iter()
            .map(|event| (event.idempotency_digest.as_bytes().to_vec(), event))
            .collect();
        if expected_events.len() != events.len() {
            return Err(integrity("production event idempotency identity is duplicated").into());
        }
        let mut non_event_receipt_count = runtime_generations.len();
        let mut non_event_generations = runtime_generations.clone();
        for entry in entries {
            if entry.key.starts_with(RUNTIME_POSTFLIGHT_PREFIX) {
                non_event_receipt_count = non_event_receipt_count.saturating_add(1);
                if non_event_receipt_count > MAX_NON_EVENT_RECEIPTS
                    || entry.value.is_empty()
                    || entry.value.len() > MAX_RUNTIME_POSTFLIGHT_RECEIPT_BYTES
                {
                    return Err(integrity(
                        "production runtime postflight receipt set exceeds its bounds",
                    )
                    .into());
                }
                let receipt: StoredRuntimePostflightReceipt = serde_json::from_slice(&entry.value)
                    .map_err(|_| integrity("production runtime postflight receipt is invalid"))?;
                self.validate_runtime_postflight_receipt(&entry.key, &receipt, current_generation)?;
                if !non_event_generations.insert(receipt.durable_generation) {
                    return Err(integrity(
                        "production non-event receipts claim the same durable generation",
                    )
                    .into());
                }
                continue;
            }

            if entry.key.starts_with(REINDEX_RECEIPT_PREFIX) {
                non_event_receipt_count = non_event_receipt_count.saturating_add(1);
                if non_event_receipt_count > MAX_NON_EVENT_RECEIPTS
                    || entry.value.is_empty()
                    || entry.value.len() > MAX_REINDEX_RECEIPT_BYTES
                {
                    return Err(
                        integrity("production reindex receipt set exceeds its bounds").into(),
                    );
                }
                let receipt: StoredReindexReceipt = serde_json::from_slice(&entry.value)
                    .map_err(|_| integrity("production reindex receipt is invalid"))?;
                self.validate_reindex_receipt(&entry.key, &receipt, current_generation)?;
                if !non_event_generations.insert(receipt.durable_generation) {
                    return Err(integrity(
                        "production non-event receipts claim the same durable generation",
                    )
                    .into());
                }
                continue;
            }

            if entry.key.starts_with(RUNTIME_GC_RECEIPT_PREFIX) {
                non_event_receipt_count = non_event_receipt_count.saturating_add(1);
                if non_event_receipt_count > MAX_NON_EVENT_RECEIPTS
                    || entry.value.is_empty()
                    || entry.value.len() > MAX_RUNTIME_GC_RECEIPT_BYTES
                {
                    return Err(
                        integrity("production runtime GC receipt exceeds its bounds").into(),
                    );
                }
                let receipt: StoredRuntimeGcReceipt = serde_json::from_slice(&entry.value)
                    .map_err(|_| integrity("production runtime GC receipt is invalid"))?;
                self.validate_runtime_gc_receipt(&entry.key, &receipt, current_generation)?;
                if !non_event_generations.insert(receipt.durable_generation) {
                    return Err(integrity(
                        "production non-event receipts claim the same durable generation",
                    )
                    .into());
                }
                continue;
            }

            if entry.key.len() != 64
                || !entry
                    .key
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                return Err(integrity(
                    "production idempotency keyspace contains an unknown namespace",
                )
                .into());
            }
            let event = expected_events.remove(&entry.key).ok_or_else(|| {
                integrity("production idempotency keyspace contains an orphan event index")
            })?;
            let index: IdempotencyIndex = serde_json::from_slice(&entry.value)
                .map_err(|_| integrity("production idempotency index is invalid"))?;
            validate_index(&self.mac_key, &index, event)?;
        }
        if !expected_events.is_empty() {
            return Err(integrity("production event idempotency index is missing").into());
        }
        if u64::try_from(non_event_receipt_count).ok()
            != Some(self.non_event_receipt_count(&snapshot)?)
        {
            return Err(integrity("production non-event receipt count changed").into());
        }
        Ok(())
    }

    fn verify_streams(&self, events: &[StoredEvent]) -> CliResult<()> {
        let states = self.stream_states()?;
        let open_stream_digests = states
            .iter()
            .map(|state| state.stream_digest.as_str())
            .collect::<BTreeSet<_>>();
        let mut expected_frame_keys = BTreeSet::new();
        let mut expected_receipt_keys = BTreeSet::new();
        let mut live_nonces = BTreeSet::new();
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        for state in &states {
            let loaded = self
                .load_stream(&state.stream_digest)?
                .ok_or_else(|| integrity("production stream state vanished during verification"))?;
            for position in 0..loaded.state.next_position {
                expected_frame_keys.insert(stream_position_key(
                    STREAM_FRAME_PREFIX,
                    &state.stream_digest,
                    position,
                ));
                expected_receipt_keys.insert(stream_position_key(
                    STREAM_RECEIPT_PREFIX,
                    &state.stream_digest,
                    position,
                ));
            }
            let state_key = stream_state_key(&state.stream_digest);
            let state_value = snapshot
                .get(&self.streams, &state_key)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("production stream state vanished during verification"))?;
            insert_envelope_nonce(&mut live_nonces, &state_value)?;
        }
        let frame_entries = snapshot
            .scan_prefix(&self.streams, STREAM_FRAME_PREFIX)
            .map_err(storage_error)?;
        let receipt_entries = snapshot
            .scan_prefix(&self.streams, STREAM_RECEIPT_PREFIX)
            .map_err(storage_error)?;
        let actual_frame_keys: BTreeSet<_> = frame_entries
            .iter()
            .map(|entry| entry.key.clone())
            .collect();
        let actual_receipt_keys: BTreeSet<_> = receipt_entries
            .iter()
            .map(|entry| entry.key.clone())
            .collect();
        if actual_frame_keys != expected_frame_keys || actual_receipt_keys != expected_receipt_keys
        {
            return Err(integrity("production stream keyspace contains orphan records").into());
        }
        for entry in frame_entries.iter().chain(&receipt_entries) {
            insert_envelope_nonce(&mut live_nonces, &entry.value)?;
        }
        let completion_identities = events
            .iter()
            .filter(|event| event.operation == Operation::StreamIngest)
            .map(|event| event.idempotency_digest.as_str())
            .collect::<BTreeSet<_>>();
        let expired_entries = snapshot
            .scan_prefix(&self.streams, STREAM_EXPIRED_PREFIX)
            .map_err(storage_error)?;
        if expired_entries.len() > MAX_EXPIRED_STREAMS {
            return Err(integrity("production expired-stream limit was exceeded").into());
        }
        let mut expired_digests = BTreeSet::new();
        for entry in &expired_entries {
            let stream_digest = parse_stream_expired_key(&entry.key)?;
            let plaintext = self.open_stream_record(
                b"expired",
                &entry.key,
                &entry.value,
                MAX_EXPIRED_STREAM_BYTES,
            )?;
            let expired: StoredExpiredStream = serde_json::from_slice(&plaintext)
                .map_err(|_| integrity("encrypted expired stream tombstone is invalid"))?;
            self.validate_expired_stream(&expired, &stream_digest)?;
            if open_stream_digests.contains(stream_digest.as_str())
                || !expired_digests.insert(stream_digest.clone())
                || completion_identities.contains(
                    self.stream_completion_idempotency_digest(&stream_digest)
                        .as_str(),
                )
            {
                return Err(integrity(
                    "production expired stream conflicts with active or completed state",
                )
                .into());
            }
            insert_envelope_nonce(&mut live_nonces, &entry.value)?;
        }
        for event in events
            .iter()
            .filter(|event| event.operation == Operation::StreamIngest)
        {
            let acknowledgement = self.stream_completion_ack(event)?;
            if acknowledgement.stream_id.trim().is_empty()
                || acknowledgement.stream_id.len() > 1_024
            {
                return Err(integrity("production completion stream identity is invalid").into());
            }
            insert_envelope_nonce(&mut live_nonces, &event.response_bytes)?;
        }
        let nonce_entries = snapshot
            .scan_prefix(&self.streams, STREAM_NONCE_PREFIX)
            .map_err(storage_error)?;
        let mut reserved_nonces = BTreeSet::new();
        for entry in nonce_entries {
            let nonce = parse_stream_nonce_key(&entry.key)?;
            if entry.value != self.digest(b"stream_nonce", &nonce).as_bytes()
                || !reserved_nonces.insert(nonce)
            {
                return Err(integrity("production stream nonce registry is invalid").into());
            }
        }
        if !live_nonces.is_subset(&reserved_nonces) {
            return Err(integrity("production live stream nonce is not reserved").into());
        }
        Ok(())
    }
}

/// Official durable service composition used by persistent CLI and daemon
/// commands. Runtime/model/maintenance executors are deliberately not claimed.
pub(crate) struct ProductionService {
    state: Arc<LoadedState>,
    store: ProductionStore,
    /// Immutable graph paired with the currently published reference
    /// projection. Full store/root/history verification happens before this is
    /// replaced; ordinary reads never replay attacker-controlled disk bytes.
    published_graph: RwLock<Option<Arc<VerifiedPolicyGraph>>>,
    /// Process-local acceleration for repeated reconciliation while Fjall and
    /// the external authority remain on the exact fully verified tip.
    reconciled_tip: RwLock<Option<ReconciledTip>>,
    /// Fail-closed while a durable semantic-control successor awaits exact
    /// external-authority reconciliation and in-process publication.
    semantic_control_quarantined: AtomicBool,
    #[cfg(test)]
    full_reconciliation_passes: AtomicU64,
    #[cfg(test)]
    fast_reconciliation_passes: AtomicU64,
    #[cfg(test)]
    canonical_replay_passes: AtomicU64,
}

impl std::fmt::Debug for ProductionService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionService")
            .field("profile", &PROFILE)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "current-server")]
impl HealthProvider for ProductionService {
    fn readiness(&self) -> HealthSummary {
        // Retain the publication read guard for the complete readiness
        // snapshot. This both observes quarantine/poisoning and serializes the
        // check with in-process writers so a stale publication cannot be
        // reported ready while a mutation is being published.
        let published = self
            .state
            .inner
            .try_read()
            .ok()
            .filter(|_| !self.state.poisoned.load(Ordering::Acquire));
        let service_loaded = published.is_some();
        let tip = self
            .reconciled_tip
            .read()
            .ok()
            .and_then(|slot| slot.clone());
        let reconciled =
            service_loaded && tip.as_ref().is_some_and(|tip| self.health_tip_matches(tip));
        let publication_available = service_loaded
            && reconciled
            && !self.semantic_control_quarantined.load(Ordering::Acquire)
            && self.published_graph.read().is_ok_and(|slot| slot.is_some());
        let ready = reconciled && publication_available;
        HealthSummary {
            schema_version: 1,
            state: if ready {
                HealthState::Ready
            } else {
                HealthState::NotReady
            },
            profile: HealthProfile::ProductionFjallV1,
            checks: HealthChecks {
                service_loaded,
                fjall_verified_at_startup: tip.is_some(),
                external_head_reconciled: reconciled,
                publication_available,
            },
            capability_manifest: production_capability_manifest("production-fjall-v1"),
            reason_code: (!ready).then_some({
                if service_loaded {
                    HealthReason::PublicationReconciliationRequired
                } else {
                    HealthReason::ServicePublicationUnavailable
                }
            }),
        }
    }
}

impl ProductionService {
    /// Bounded readiness proof for an already fully verified publication.
    /// It proves that neither Fjall's global sequence nor the authenticated
    /// external authority has moved since publication. It deliberately does
    /// not deserialize the archive or graph; deep corruption detection remains
    /// the startup/explicit-verification path.
    #[cfg(feature = "current-server")]
    fn health_tip_matches(&self, tip: &ReconciledTip) -> bool {
        let Ok(before) = self.store.engine.head_sequence() else {
            return false;
        };
        if before != tip.storage_sequence {
            return false;
        }
        let Ok((current, anchored)) = self
            .state
            .authority
            .authenticated_active_identity(&self.state.key.expose_copy())
        else {
            return false;
        };
        let authority_matches = current.database_id == tip.database_id
            && current.commit_seq == tip.projection_commit_seq
            && current.archive_digest == tip.projection_digest
            && anchored.generation == tip.durable.generation
            && anchored.ledger_digest == tip.durable.digest;
        authority_matches
            && matches!(
                self.store.engine.head_sequence(),
                Ok(after) if after == before
            )
    }

    fn export_host_archive(&self, service: &ReferenceService) -> ServiceResult<ExportResponse> {
        let authority = HostArchiveAuthority::new(self.state.key.expose_copy())?;
        service.export_host_archive(&authority)
    }

    /// Materializes the already verified publication for the local host CLI.
    /// This is intentionally not part of `CognitiveMemoryService`, so network
    /// and MCP workspace requests cannot manufacture the required authority.
    pub(crate) fn export_host_archive_current(&self) -> ServiceResult<ExportResponse> {
        self.require_semantic_control_publication()?;
        let published = self.state.read()?;
        self.export_host_archive(&published)
    }

    /// Holds the lifecycle publication lock while a local host operation binds
    /// another authority to the exact verified canonical archive. This does
    /// not expose host archive authority through the public service trait and
    /// does not implement live production-store restore.
    #[cfg(feature = "mcp")]
    pub(crate) fn with_host_archive_current<T>(
        &self,
        operation: impl FnOnce(&ExportResponse) -> ServiceResult<T>,
    ) -> ServiceResult<T> {
        let mut published = self.lock()?;
        self.reconcile_locked(&mut published)?;
        let archive = self.export_host_archive(&published)?;
        operation(&archive)
    }

    pub(crate) fn initialize(path: &Path, state: Arc<LoadedState>) -> CliResult<Self> {
        let (archive, _) = state
            .authority
            .load_verified(&state.key.expose_copy())
            .map_err(CliError::from)?;
        let token_key = Zeroizing::new(state.key.expose_copy());
        let store = ProductionStore::initialize(path, &archive, &token_key)?;
        let durable = store.verify_durable_history()?;
        match state
            .authority
            .load_verified_with_ledger(&state.key.expose_copy())
        {
            Ok((anchored_archive, _, anchored)) => {
                if anchored.generation == 0
                    && anchored.ledger_digest
                        == blake3::hash(b"contextdb/empty-durable-ledger/v1")
                            .to_hex()
                            .to_string()
                    && durable.generation == 0
                    && store.head_from_latest()? == 0
                    && store.stream_states()?.is_empty()
                {
                    state
                        .authority
                        .bind_fresh_ledger_root(
                            &state.key.expose_copy(),
                            &anchored_archive,
                            &durable.digest,
                        )
                        .map_err(CliError::from)?;
                }
            }
            Err(error) if error.contains("legacy state-head authority requires explicit") => {
                if durable.generation != 0
                    || store.head_from_latest()? != 0
                    || !store.stream_states()?.is_empty()
                {
                    return Err(integrity(
                        "legacy authority can migrate only against a fresh exact-current production store",
                    )
                    .into());
                }
                state
                    .authority
                    .migrate_legacy_exact(
                        &state.key.expose_copy(),
                        &archive,
                        durable.generation,
                        &durable.digest,
                    )
                    .map_err(CliError::from)?;
            }
            Err(error) => return Err(CliError::from(error)),
        }
        let service = Self {
            state,
            store,
            published_graph: RwLock::new(None),
            reconciled_tip: RwLock::new(None),
            semantic_control_quarantined: AtomicBool::new(false),
            #[cfg(test)]
            full_reconciliation_passes: AtomicU64::new(0),
            #[cfg(test)]
            fast_reconciliation_passes: AtomicU64::new(0),
            #[cfg(test)]
            canonical_replay_passes: AtomicU64::new(0),
        };
        service.recover()?;
        Ok(service)
    }

    pub(crate) fn open(path: &Path, state: Arc<LoadedState>) -> CliResult<Self> {
        let token_key = Zeroizing::new(state.key.expose_copy());
        let service = Self {
            state,
            store: ProductionStore::open(path, &token_key)?,
            published_graph: RwLock::new(None),
            reconciled_tip: RwLock::new(None),
            semantic_control_quarantined: AtomicBool::new(false),
            #[cfg(test)]
            full_reconciliation_passes: AtomicU64::new(0),
            #[cfg(test)]
            fast_reconciliation_passes: AtomicU64::new(0),
            #[cfg(test)]
            canonical_replay_passes: AtomicU64::new(0),
        };
        service.recover()?;
        Ok(service)
    }

    fn lock(&self) -> ServiceResult<RwLockWriteGuard<'_, Arc<ReferenceService>>> {
        self.state.inner.write().map_err(|_| {
            ServiceError::new(
                ErrorCode::Unavailable,
                "production state publication lock failed",
                true,
            )
        })
    }

    fn replay(&self) -> CliResult<(Arc<ReferenceService>, Arc<VerifiedPolicyGraph>, Vec<u8>)> {
        #[cfg(test)]
        self.canonical_replay_passes.fetch_add(1, Ordering::Relaxed);
        let header = self.store.header()?;
        self.store.events()?;
        let projection = self.store.current_projection()?;
        if projection.database_id != header.database_id {
            return Err(integrity("production projection database identity changed").into());
        }
        // Rebuild and compare the complete content-free policy graph before
        // the canonical service may publish or materialize any record.
        let graph = Arc::new(VerifiedPolicyGraph::new(self.store.policy_graph()?)?);
        let service = service_from_archive(
            header.database_id,
            self.state.key.expose_copy(),
            projection.archive.clone(),
            "production-projection-replay",
        )?;
        let replayed = self.export_host_archive(&service)?;
        if replayed.bytes != projection.archive
            || replayed.digest != projection.archive_digest
            || replayed.commit_seq != projection.commit_seq
        {
            return Err(integrity("production projection replay changed canonical bytes").into());
        }
        Ok((Arc::new(service), graph, replayed.bytes))
    }

    fn fast_reconciliation_matches(&self, tip: &ReconciledTip) -> ServiceResult<bool> {
        // A malformed/missing point record is a cache miss, never a successful
        // proof. The caller responds by running the complete verifier/replay,
        // which returns the precise integrity or availability failure.
        if !matches!(self.store.reconciled_tip_matches(tip), Ok(true)) {
            return Ok(false);
        }
        let Ok((current, anchored)) = self
            .state
            .authority
            .authenticated_active_identity(&self.state.key.expose_copy())
        else {
            return Ok(false);
        };
        let authority_matches = current.database_id == tip.database_id
            && current.commit_seq == tip.projection_commit_seq
            && current.archive_digest == tip.projection_digest
            && anchored.generation == tip.durable.generation
            && anchored.ledger_digest == tip.durable.digest;
        // Close the window between the initial Fjall snapshot proof and the
        // external-authority read. Any intervening physical commit makes this
        // a cache miss and selects the full verifier at the next operation.
        Ok(authority_matches
            && matches!(
                self.store.engine.head_sequence(),
                Ok(sequence) if sequence == tip.storage_sequence
            ))
    }

    fn cached_reconciled_tip(&self) -> ServiceResult<ReconciledTip> {
        self.reconciled_tip
            .read()
            .map_err(|_| {
                ServiceError::new(
                    ErrorCode::Unavailable,
                    "production reconciliation cache lock failed",
                    true,
                )
            })?
            .clone()
            .ok_or_else(|| integrity("production reconciled tip is not published"))
    }

    fn private_candidate_from_published(
        &self,
        published: &ReferenceService,
        tip: &ReconciledTip,
    ) -> ServiceResult<ReferenceService> {
        // The published service, rather than mutable disk bytes, is the source
        // for a private clone. Its export is already paired with `tip` by the
        // publication lock and the preceding reconciliation proof.
        let source = self.export_host_archive(published)?;
        if source.commit_seq != tip.projection_commit_seq
            || source.digest != tip.projection_digest
            || blake3::hash(&source.bytes).to_hex().as_str() != tip.projection_digest
        {
            return Err(integrity(
                "published production service differs from its reconciled tip",
            ));
        }
        service_from_archive(
            tip.database_id.clone(),
            self.state.key.expose_copy(),
            source.bytes,
            "production-private-candidate",
        )
        .map_err(|error| error.0)
    }

    fn publish_committed_semantic_candidate(
        &self,
        published: &mut Arc<ReferenceService>,
        candidate: Arc<ReferenceService>,
        archive: &[u8],
        previous: &ReconciledTip,
        committed: CommittedSemanticPublication,
    ) -> ServiceResult<()> {
        let identity = super::state_head::inspect_archive(archive)
            .map_err(|_| integrity("committed production archive is invalid"))?;
        let expected_generation = previous
            .durable
            .generation
            .checked_add(1)
            .ok_or_else(|| integrity("production durable generation is exhausted"))?;
        if identity != committed.identity
            || committed.durable.generation != expected_generation
            || committed.durable.previous_digest.as_deref()
                != Some(previous.durable.digest.as_str())
            || committed.graph.database_id != identity.database_id
            || committed.graph.archive_commit_seq != identity.commit_seq
            || committed.graph.archive_digest != identity.archive_digest
        {
            return Err(integrity(
                "synchronized production publication is not the expected strict successor",
            ));
        }

        let advanced = self
            .state
            .authority
            .advance_with_ledger(
                &self.state.key.expose_copy(),
                archive,
                committed.durable.generation,
                &committed.durable.digest,
            )
            .map_err(|_| {
                durable_checkpoint_error("Fjall commit awaits state-head reconciliation")
            })?;
        if advanced != identity {
            return Err(integrity(
                "external authority advanced to another semantic projection",
            ));
        }
        let (_, reconciled, reconciled_durable) = self
            .state
            .authority
            .load_verified_with_ledger(&self.state.key.expose_copy())
            .map_err(|_| {
                durable_checkpoint_error("state-head publication could not be verified")
            })?;
        if reconciled != identity
            || reconciled_durable.generation != committed.durable.generation
            || reconciled_durable.ledger_digest != committed.durable.digest
        {
            return Err(integrity(
                "state-head publication selected another durable projection",
            ));
        }

        let tip = self
            .store
            .reconciled_tip_from_verified(&identity, &committed.durable, &committed.graph)
            .map_err(|error| error.0)?;
        if tip.storage_sequence != committed.storage_sequence {
            return Err(integrity(
                "production physical state changed before direct publication",
            ));
        }

        // Acquire every auxiliary publication lock before replacing the
        // semantic pointer. A poisoned auxiliary lock therefore withholds the
        // ACK and leaves recovery to replay the already synchronized successor.
        let mut graph_slot = self.published_graph.write().map_err(|_| {
            ServiceError::new(
                ErrorCode::Unavailable,
                "production graph publication lock failed",
                true,
            )
        })?;
        let mut tip_slot = self.reconciled_tip.write().map_err(|_| {
            ServiceError::new(
                ErrorCode::Unavailable,
                "production reconciliation cache lock failed",
                true,
            )
        })?;
        *published = candidate;
        *graph_slot = Some(committed.graph);
        *tip_slot = Some(tip);
        self.semantic_control_quarantined
            .store(false, Ordering::Release);
        Ok(())
    }

    fn reconcile_locked(&self, published: &mut Arc<ReferenceService>) -> ServiceResult<()> {
        #[cfg(test)]
        let mut full_pass_counted = false;
        let cached = self
            .reconciled_tip
            .read()
            .map_err(|_| {
                ServiceError::new(
                    ErrorCode::Unavailable,
                    "production reconciliation cache lock failed",
                    true,
                )
            })?
            .clone();
        if let Some(tip) = cached {
            if self.fast_reconciliation_matches(&tip)? {
                #[cfg(test)]
                self.fast_reconciliation_passes
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            *self.reconciled_tip.write().map_err(|_| {
                ServiceError::new(
                    ErrorCode::Unavailable,
                    "production reconciliation cache lock failed",
                    true,
                )
            })? = None;
            // Sequence, rooted point state, or external authority drifted from
            // the cached proof. Re-enter the complete closed-world verifier
            // before replaying or attempting lost-ACK reconciliation.
            #[cfg(test)]
            {
                self.full_reconciliation_passes
                    .fetch_add(1, Ordering::Relaxed);
                full_pass_counted = true;
            }
            self.store.verify().map_err(|error| error.0)?;
        }
        #[cfg(test)]
        if !full_pass_counted {
            self.full_reconciliation_passes
                .fetch_add(1, Ordering::Relaxed);
        }
        let (replayed, graph, latest) = self.replay().map_err(|error| error.0)?;
        let expected = super::state_head::inspect_archive(&latest)
            .map_err(|_| integrity("production projection identity is invalid"))?;
        let durable = self
            .store
            .verify_durable_history()
            .map_err(|error| error.0)?;
        let (_, current, anchored) = self
            .state
            .authority
            .load_verified_with_ledger(&self.state.key.expose_copy())
            .map_err(|_| durable_checkpoint_error("authenticated state reconciliation failed"))?;
        if current.database_id != expected.database_id
            || current.commit_seq > expected.commit_seq
            || anchored.generation > durable.generation
        {
            return Err(integrity(
                "external authority is ahead of or diverges from Fjall",
            ));
        }
        self.store
            .verify_durable_successor(&anchored, &durable)
            .map_err(|error| error.0)?;
        if current != expected {
            if current.commit_seq >= expected.commit_seq {
                return Err(integrity(
                    "external authority semantic archive diverges from Fjall",
                ));
            }
            self.state
                .authority
                .advance_with_ledger(
                    &self.state.key.expose_copy(),
                    &latest,
                    durable.generation,
                    &durable.digest,
                )
                .map_err(|_| {
                    durable_checkpoint_error("Fjall commit awaits state-head reconciliation")
                })?;
        } else if anchored.generation < durable.generation {
            self.state
                .authority
                .advance_ledger(
                    &self.state.key.expose_copy(),
                    &expected,
                    durable.generation,
                    &durable.digest,
                )
                .map_err(|_| {
                    durable_checkpoint_error("Fjall ledger awaits state-head reconciliation")
                })?;
        } else if anchored.ledger_digest != durable.digest {
            return Err(integrity(
                "external durable ledger digest diverges from Fjall",
            ));
        }
        let (_, reconciled, reconciled_durable) = self
            .state
            .authority
            .load_verified_with_ledger(&self.state.key.expose_copy())
            .map_err(|_| {
                durable_checkpoint_error("state-head reconciliation could not be verified")
            })?;
        if reconciled != expected
            || reconciled_durable.generation != durable.generation
            || reconciled_durable.ledger_digest != durable.digest
        {
            return Err(integrity(
                "state-head reconciliation selected another durable projection",
            ));
        }
        let tip = self
            .store
            .reconciled_tip_from_verified(&expected, &durable, &graph)
            .map_err(|error| error.0)?;
        *published = replayed;
        *self.published_graph.write().map_err(|_| {
            ServiceError::new(
                ErrorCode::Unavailable,
                "production graph publication lock failed",
                true,
            )
        })? = Some(graph);
        *self.reconciled_tip.write().map_err(|_| {
            ServiceError::new(
                ErrorCode::Unavailable,
                "production reconciliation cache lock failed",
                true,
            )
        })? = Some(tip);
        Ok(())
    }

    #[cfg(test)]
    fn reconciliation_pass_counts(&self) -> (u64, u64) {
        (
            self.full_reconciliation_passes.load(Ordering::Relaxed),
            self.fast_reconciliation_passes.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    fn canonical_replay_pass_count(&self) -> u64 {
        self.canonical_replay_passes.load(Ordering::Relaxed)
    }

    fn recover(&self) -> CliResult<()> {
        self.store.verify()?;
        let mut published = self.lock().map_err(CliError::from)?;
        self.reconcile_locked(&mut published)
            .map_err(CliError::from)
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&ReferenceService) -> ServiceResult<T>,
    ) -> ServiceResult<T> {
        self.require_semantic_control_publication()?;
        let published = self.state.read()?;
        operation(&published)
    }

    fn read_with_graph<T>(
        &self,
        operation: impl FnOnce(&ReferenceService, &VerifiedPolicyGraph) -> ServiceResult<T>,
    ) -> ServiceResult<T> {
        self.require_semantic_control_publication()?;
        let published = self.state.read()?;
        let graph = self
            .published_graph
            .read()
            .map_err(|_| {
                ServiceError::new(
                    ErrorCode::Unavailable,
                    "production graph publication lock failed",
                    true,
                )
            })?
            .clone()
            .ok_or_else(|| integrity("verified production graph is not published"))?;
        operation(&published, &graph)
    }

    fn require_semantic_control_publication(&self) -> ServiceResult<()> {
        if self.semantic_control_quarantined.load(Ordering::Acquire) {
            return Err(ServiceError::new(
                ErrorCode::Unavailable,
                "semantic-control successor awaits external-head reconciliation",
                true,
            )
            .with_context(
                Vec::new(),
                Some("semantic_control_publication".to_owned()),
                Some("retry the exact control operation or reopen the verified store".to_owned()),
                None,
            ));
        }
        Ok(())
    }

    fn mutate<Request, Response>(
        &self,
        operation: Operation,
        idempotency_material: &[u8],
        request_digest: String,
        request: Request,
        apply: impl FnOnce(&ReferenceService, Request) -> ServiceResult<Response>,
    ) -> ServiceResult<Response>
    where
        Response: DeserializeOwned + ReplayReceipt + Serialize,
    {
        let idempotency_digest = self.store.digest(operation.domain(), idempotency_material);
        let mut published = self.lock()?;
        self.reconcile_locked(&mut published)?;
        if let Some(event) = self
            .store
            .idempotent_event(&idempotency_digest, &request_digest)
            .map_err(|error| error.0)?
        {
            let mut response: Response = serde_json::from_slice(&event.response_bytes)
                .map_err(|_| integrity("stored production response is invalid"))?;
            response.mark_replayed();
            return Ok(response);
        }

        // Clone only the already verified in-process publication. A normal
        // mutation no longer rescans the event ledger, rebuilds the old graph,
        // or reimports attacker-controlled disk bytes to create its candidate.
        let previous = self.cached_reconciled_tip()?;
        let candidate = Arc::new(self.private_candidate_from_published(&published, &previous)?);
        let response = apply(&candidate, request)?;
        let response_bytes = canonical_bytes(&response).map_err(|error| error.0)?;
        let projection = self.export_host_archive(&candidate)?;
        let event = StoredEvent {
            schema_version: STORE_SCHEMA_VERSION,
            sequence: 0,
            operation,
            previous_event_checksum: None,
            idempotency_digest,
            request_digest,
            response_digest: self.store.digest(b"response", &response_bytes),
            response_bytes,
            projection_commit_seq: projection.commit_seq,
            projection_digest: projection.digest.clone(),
            checksum: String::new(),
        };
        let committed = self
            .store
            .append(event, &projection.bytes, &previous.durable)
            .map_err(|error| error.0)?;
        // Fjall is synchronized. Advance and re-read the external authority,
        // then publish the exact candidate and graph which were checked before
        // the commit. Any failure withholds the ACK; startup/retry falls back to
        // full replay and proves the durable successor chain.
        self.publish_committed_semantic_candidate(
            &mut published,
            candidate,
            &projection.bytes,
            &previous,
            committed,
        )?;
        Ok(response)
    }

    fn mutate_semantic_control(
        &self,
        operation: Operation,
        request: HighLevelControlRequest,
        apply: impl FnOnce(
            &ReferenceService,
            HighLevelControlRequest,
        ) -> ServiceResult<MutationResponse>,
    ) -> ServiceResult<MutationResponse> {
        // This check deliberately precedes target IDs and the generic JSON
        // parameters. An unauthenticated caller cannot use schema failures as
        // an oracle over protected semantic-control inputs.
        require_grant(&request.context, Capability::Correct)?;
        let (idempotency_material, request_digest) =
            semantic_control_commitments(&self.store, operation, &request)?;
        self.semantic_control_quarantined
            .store(true, Ordering::Release);
        let result = self.mutate(
            operation,
            &idempotency_material,
            request_digest,
            request,
            apply,
        );
        let reconciled = self
            .reconciled_tip
            .read()
            .ok()
            .and_then(|slot| slot.clone())
            .is_some_and(|tip| matches!(self.fast_reconciliation_matches(&tip), Ok(true)));
        if result.is_ok() || reconciled {
            self.semantic_control_quarantined
                .store(false, Ordering::Release);
        }
        result
    }

    fn prepare_runtime_seal_mutation(
        &self,
        checkpoint: PortableCheckpoint,
        source_runtime: RuntimeDescriptor,
    ) -> ServiceResult<RuntimeLedgerMutation> {
        let identity_digest = self
            .store
            .runtime_state_identity_digest(&checkpoint)
            .map_err(|error| error.0)?;
        let checkpoint_digest = checkpoint.digest.to_string();
        let source_runtime_digest =
            continuity_value_digest(&source_runtime).map_err(|error| error.0)?;
        if source_runtime_digest != checkpoint.source_runtime_digest.to_string() {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "checkpoint source runtime differs from its sealed runtime digest",
                false,
            ));
        }
        let latest = self
            .store
            .load_runtime_latest(&identity_digest)
            .map_err(|error| error.0)?;
        let mut expected = BTreeMap::new();
        let mut writes = BTreeMap::new();
        let (version, previous_state_digest) = if let Some(latest) = latest {
            if latest.state.checkpoint.digest == checkpoint.digest {
                return Err(ServiceError::new(
                    ErrorCode::InvalidArgument,
                    "checkpoint is already sealed under another runtime operation ID",
                    false,
                ));
            }
            if checkpoint.checkpoint.created_seq <= latest.state.checkpoint.checkpoint.created_seq
                || checkpoint.checkpoint.frame_snapshot.captured_at < latest.state.updated_at
            {
                return Err(ServiceError::new(
                    ErrorCode::InvalidContinuation,
                    "new runtime checkpoint does not advance the active state",
                    false,
                ));
            }
            let stale_version =
                latest.runtime_head.version.checked_add(1).ok_or_else(|| {
                    resource_exhausted("runtime state version is exhausted", false)
                })?;
            let mut stale_state = latest.state.clone();
            stale_state.version = stale_version;
            stale_state.previous_state_digest = Some(latest.state.state_digest.clone());
            stale_state.status = RuntimeCheckpointStatus::Stale;
            stale_state.updated_at = checkpoint.checkpoint.frame_snapshot.captured_at;
            let stale_state = self
                .store
                .seal_runtime_state(stale_state)
                .map_err(|error| error.0)?;
            let stale_state_key =
                runtime_state_key(&identity_digest, stale_version).map_err(|error| error.0)?;
            expected.insert(stale_state_key.clone(), None);
            writes.insert(
                stale_state_key,
                canonical_bytes(&stale_state).map_err(|error| error.0)?,
            );
            let stale_checkpoint_head = self
                .store
                .checkpoint_head_for_state(&stale_state)
                .map_err(|error| error.0)?;
            let stale_checkpoint_key =
                runtime_checkpoint_head_key(&latest.checkpoint_head.checkpoint_digest)
                    .map_err(|error| error.0)?;
            expected.insert(
                stale_checkpoint_key.clone(),
                Some(latest.checkpoint_head_bytes),
            );
            writes.insert(
                stale_checkpoint_key,
                canonical_bytes(&stale_checkpoint_head).map_err(|error| error.0)?,
            );
            let runtime_key = runtime_head_key(&identity_digest).map_err(|error| error.0)?;
            expected.insert(runtime_key, Some(latest.runtime_head_bytes));
            let next_version = stale_version
                .checked_add(1)
                .ok_or_else(|| resource_exhausted("runtime state version is exhausted", false))?;
            (next_version, Some(stale_state.state_digest))
        } else {
            expected.insert(
                runtime_head_key(&identity_digest).map_err(|error| error.0)?,
                None,
            );
            (1, None)
        };
        let checkpoint_key =
            runtime_checkpoint_head_key(&checkpoint_digest).map_err(|error| error.0)?;
        expected.insert(checkpoint_key.clone(), None);
        let mut state = StoredRuntimeState {
            schema_version: STORE_SCHEMA_VERSION,
            identity_digest,
            version,
            previous_state_digest,
            updated_at: checkpoint.checkpoint.frame_snapshot.captured_at,
            checkpoint,
            active_runtime: source_runtime,
            active_runtime_digest: source_runtime_digest,
            status: RuntimeCheckpointStatus::Sealed,
            last_bootstrap_trace_digest: None,
            last_pack_digest: None,
            handoff_count: 0,
            state_digest: String::new(),
            checksum: String::new(),
        };
        state = self
            .store
            .seal_runtime_state(state)
            .map_err(|error| error.0)?;
        let state_key =
            runtime_state_key(&state.identity_digest, state.version).map_err(|error| error.0)?;
        expected.insert(state_key.clone(), None);
        writes.insert(state_key, canonical_bytes(&state).map_err(|error| error.0)?);
        let runtime_head = self
            .store
            .runtime_head_for_state(&state)
            .map_err(|error| error.0)?;
        writes.insert(
            runtime_head_key(&state.identity_digest).map_err(|error| error.0)?,
            canonical_bytes(&runtime_head).map_err(|error| error.0)?,
        );
        let checkpoint_head = self
            .store
            .checkpoint_head_for_state(&state)
            .map_err(|error| error.0)?;
        writes.insert(
            checkpoint_key,
            canonical_bytes(&checkpoint_head).map_err(|error| error.0)?,
        );
        Ok(RuntimeLedgerMutation {
            expected,
            writes,
            resulting_state: state,
        })
    }

    fn validate_runtime_transition_source(
        &self,
        loaded: &LoadedRuntimeState,
        expected_version: u64,
        updated_at: TimestampMicros,
    ) -> ServiceResult<()> {
        if loaded.state.version != expected_version {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "runtime checkpoint version is stale",
                false,
            ));
        }
        if loaded.runtime_head.checkpoint_digest != loaded.checkpoint_head.checkpoint_digest
            || loaded.runtime_head.version != loaded.state.version
        {
            return Err(ServiceError::new(
                ErrorCode::ContinuationExpired,
                "runtime checkpoint is no longer the active state",
                false,
            ));
        }
        match loaded.state.status {
            RuntimeCheckpointStatus::Revoked => {
                return Err(ServiceError::new(
                    ErrorCode::PermissionDenied,
                    "runtime checkpoint has been revoked",
                    false,
                ));
            }
            RuntimeCheckpointStatus::Stale => {
                return Err(ServiceError::new(
                    ErrorCode::ContinuationExpired,
                    "runtime checkpoint has been superseded",
                    false,
                ));
            }
            RuntimeCheckpointStatus::Sealed
            | RuntimeCheckpointStatus::Bootstrapped
            | RuntimeCheckpointStatus::Resumed => {}
        }
        if updated_at < loaded.state.updated_at {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "runtime lifecycle timestamp predates the active state",
                false,
            ));
        }
        Ok(())
    }

    fn prepare_runtime_transition_mutation(
        &self,
        loaded: LoadedRuntimeState,
        transition: RuntimeTransition,
    ) -> ServiceResult<RuntimeLedgerMutation> {
        self.validate_runtime_transition_source(
            &loaded,
            transition.expected_version,
            transition.updated_at,
        )?;
        let version = loaded
            .state
            .version
            .checked_add(1)
            .ok_or_else(|| resource_exhausted("runtime state version is exhausted", false))?;
        let active_runtime_digest =
            continuity_value_digest(&transition.active_runtime).map_err(|error| error.0)?;
        let mut state = loaded.state.clone();
        state.version = version;
        state.previous_state_digest = Some(loaded.state.state_digest.clone());
        state.active_runtime = transition.active_runtime;
        state.active_runtime_digest = active_runtime_digest;
        state.status = transition.status;
        if let Some(value) = transition.bootstrap_trace_digest {
            state.last_bootstrap_trace_digest = Some(value);
        }
        if let Some(value) = transition.pack_digest {
            state.last_pack_digest = Some(value);
        }
        if transition.increment_handoff {
            state.handoff_count = state
                .handoff_count
                .checked_add(1)
                .ok_or_else(|| resource_exhausted("runtime handoff count is exhausted", false))?;
        }
        state.updated_at = transition.updated_at;
        state.state_digest.clear();
        state.checksum.clear();
        let state = self
            .store
            .seal_runtime_state(state)
            .map_err(|error| error.0)?;
        let state_key =
            runtime_state_key(&state.identity_digest, state.version).map_err(|error| error.0)?;
        let runtime_key = runtime_head_key(&state.identity_digest).map_err(|error| error.0)?;
        let checkpoint_key = runtime_checkpoint_head_key(&state.checkpoint.digest.to_string())
            .map_err(|error| error.0)?;
        let runtime_head = self
            .store
            .runtime_head_for_state(&state)
            .map_err(|error| error.0)?;
        let checkpoint_head = self
            .store
            .checkpoint_head_for_state(&state)
            .map_err(|error| error.0)?;
        Ok(RuntimeLedgerMutation {
            expected: BTreeMap::from([
                (runtime_key.clone(), Some(loaded.runtime_head_bytes)),
                (checkpoint_key.clone(), Some(loaded.checkpoint_head_bytes)),
                (state_key.clone(), None),
            ]),
            writes: BTreeMap::from([
                (state_key, canonical_bytes(&state).map_err(|error| error.0)?),
                (
                    runtime_key,
                    canonical_bytes(&runtime_head).map_err(|error| error.0)?,
                ),
                (
                    checkpoint_key,
                    canonical_bytes(&checkpoint_head).map_err(|error| error.0)?,
                ),
            ]),
            resulting_state: state,
        })
    }

    fn execute_compiled_bootstrap(
        &self,
        request: RuntimeRequest,
        execution: RuntimeBootstrapExecution,
        canonical_payload: &[u8],
    ) -> ServiceResult<RuntimeResponse> {
        let RuntimeBootstrapExecution {
            method,
            expected_checkpoint_version,
            request: bootstrap_request,
            target_runtime,
            provider: provider_input,
        } = execution;
        let authorization_digest = request.context.authorization_binding_digest()?;
        let identity_digest = self
            .store
            .runtime_lifecycle_identity_digest(method, &request.context, &request.operation_id)
            .map_err(|error| error.0)?;
        let receipt_key =
            runtime_lifecycle_receipt_key(method, &identity_digest).map_err(|error| error.0)?;
        let request_commitment = self
            .store
            .runtime_lifecycle_request_commitment(
                method,
                &identity_digest,
                &authorization_digest,
                canonical_payload,
            )
            .map_err(|error| error.0)?;
        let receipt_id = self
            .store
            .runtime_lifecycle_receipt_id(method, &identity_digest, &request_commitment)
            .map_err(|error| error.0)?;

        let mut published = self.lock()?;
        self.reconcile_locked(&mut published)?;
        if let Some(receipt) = self
            .store
            .runtime_lifecycle_receipt(&receipt_key, &request_commitment)
            .map_err(|error| error.0)?
        {
            return validate_runtime_lifecycle_response_bytes(&receipt.response_bytes)
                .map_err(|error| error.0);
        }

        let loaded = self
            .store
            .load_runtime_state_by_checkpoint(&bootstrap_request.checkpoint.digest.to_string())
            .map_err(|error| error.0)?
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::NotFound,
                    "runtime checkpoint is not present in the durable ledger",
                    false,
                )
            })?;
        bind_runtime_context(&request.context, &loaded.state.checkpoint)?;
        if loaded.state.checkpoint != bootstrap_request.checkpoint {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "runtime checkpoint payload differs from the durable checkpoint",
                false,
            ));
        }
        if method == RuntimeLifecycleMethod::Bootstrap
            && loaded.state.status != RuntimeCheckpointStatus::Sealed
        {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "runtime bootstrap requires a newly sealed checkpoint",
                false,
            ));
        }
        self.validate_runtime_transition_source(
            &loaded,
            expected_checkpoint_version,
            bootstrap_request.migration_at,
        )?;
        // Continuity policy, compatibility, target identity, and checkpoint
        // bindings are evaluated before the provider is constructed or read.
        bootstrap_request
            .validate(&target_runtime)
            .map_err(map_continuity_service_error)?;
        let provider = InMemoryContextProvider::new(
            bootstrap_request.snapshot.clone(),
            provider_input.candidates,
            provider_input.evidence,
        )
        .map_err(|_| {
            ServiceError::new(
                ErrorCode::InvalidArgument,
                "runtime provider source set is invalid",
                false,
            )
        })?;
        let compiler = BootstrapCompiler::new(self.store.continuity_compiler_key())
            .map_err(map_continuity_service_error)?;
        let result = compiler
            .compile(
                &bootstrap_request,
                &target_runtime,
                &provider,
                &ReferenceTokenizer,
            )
            .map_err(map_continuity_service_error)?;
        if !result.open_loops_preserved || !result.required_memory_refs_preserved {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "runtime compilation did not preserve required checkpoint state",
                false,
            ));
        }
        let artifact = runtime_bootstrap_artifact(&result);
        let status = if method == RuntimeLifecycleMethod::Bootstrap {
            RuntimeCheckpointStatus::Bootstrapped
        } else {
            RuntimeCheckpointStatus::Resumed
        };
        let mutation = self.prepare_runtime_transition_mutation(
            loaded,
            RuntimeTransition {
                expected_version: expected_checkpoint_version,
                status,
                active_runtime: target_runtime,
                updated_at: bootstrap_request.migration_at,
                bootstrap_trace_digest: Some(artifact.trace_digest.clone()),
                pack_digest: Some(artifact.compiled.canonical_digest.clone()),
                increment_handoff: false,
            },
        )?;
        let response_artifact = if method == RuntimeLifecycleMethod::Bootstrap {
            RuntimeLifecycleArtifactV1::Bootstrap {
                result: Box::new(artifact),
            }
        } else {
            RuntimeLifecycleArtifactV1::Resume {
                result: Box::new(artifact),
            }
        };
        let response = runtime_lifecycle_response(
            request.operation_id,
            method,
            receipt_id,
            &mutation.resulting_state,
            response_artifact,
        )?;
        self.store
            .commit_runtime_lifecycle(
                &receipt_key,
                method,
                request_commitment,
                &response,
                mutation,
            )
            .map_err(|error| error.0)?;
        self.reconcile_locked(&mut published)?;
        Ok(response)
    }

    fn execute_compiled_handoff(
        &self,
        request: RuntimeRequest,
        input: RuntimeHandoffInputV1,
        canonical_payload: &[u8],
    ) -> ServiceResult<RuntimeResponse> {
        let method = RuntimeLifecycleMethod::Handoff;
        let authorization_digest = request.context.authorization_binding_digest()?;
        let identity_digest = self
            .store
            .runtime_lifecycle_identity_digest(method, &request.context, &request.operation_id)
            .map_err(|error| error.0)?;
        let receipt_key =
            runtime_lifecycle_receipt_key(method, &identity_digest).map_err(|error| error.0)?;
        let request_commitment = self
            .store
            .runtime_lifecycle_request_commitment(
                method,
                &identity_digest,
                &authorization_digest,
                canonical_payload,
            )
            .map_err(|error| error.0)?;
        let receipt_id = self
            .store
            .runtime_lifecycle_receipt_id(method, &identity_digest, &request_commitment)
            .map_err(|error| error.0)?;

        let mut published = self.lock()?;
        self.reconcile_locked(&mut published)?;
        if let Some(receipt) = self
            .store
            .runtime_lifecycle_receipt(&receipt_key, &request_commitment)
            .map_err(|error| error.0)?
        {
            return validate_runtime_lifecycle_response_bytes(&receipt.response_bytes)
                .map_err(|error| error.0);
        }
        let loaded = self
            .store
            .load_runtime_state_by_checkpoint(&input.request.checkpoint.digest.to_string())
            .map_err(|error| error.0)?
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::NotFound,
                    "runtime checkpoint is not present in the durable ledger",
                    false,
                )
            })?;
        bind_runtime_context(&request.context, &loaded.state.checkpoint)?;
        if loaded.state.checkpoint != input.request.checkpoint {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "handoff checkpoint differs from the durable checkpoint",
                false,
            ));
        }
        self.validate_runtime_transition_source(
            &loaded,
            input.expected_checkpoint_version,
            input.request.issued_at,
        )?;
        // Recipient publication policy is resolved before provider creation.
        input
            .request
            .validate()
            .map_err(map_continuity_service_error)?;
        let provider = InMemoryContextProvider::new(
            input.request.compile.snapshot.clone(),
            input.provider.candidates,
            input.provider.evidence,
        )
        .map_err(|_| {
            ServiceError::new(
                ErrorCode::InvalidArgument,
                "runtime handoff provider source set is invalid",
                false,
            )
        })?;
        let compiler = HandoffCompiler::new(self.store.continuity_compiler_key())
            .map_err(map_continuity_service_error)?;
        let result = compiler
            .compile(&input.request, &provider, &ReferenceTokenizer)
            .map_err(map_continuity_service_error)?;
        let open_loops_preserved =
            handoff_preserves_open_loops(&input.request.checkpoint, &result.compiled.pack);
        if !open_loops_preserved {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "runtime handoff did not preserve checkpoint open loops",
                false,
            ));
        }
        result
            .manifest
            .validate_use(input.request.issued_at, false)
            .map_err(map_continuity_service_error)?;
        let artifact = RuntimeHandoffArtifactV1 {
            manifest: result.manifest,
            open_loops_preserved,
            compiled: runtime_compiled_context(&result.compiled),
        };
        let status = loaded.state.status;
        let active_runtime = loaded.state.active_runtime.clone();
        let mutation = self.prepare_runtime_transition_mutation(
            loaded,
            RuntimeTransition {
                expected_version: input.expected_checkpoint_version,
                status,
                active_runtime,
                updated_at: input.request.issued_at,
                bootstrap_trace_digest: None,
                pack_digest: None,
                increment_handoff: true,
            },
        )?;
        let response = runtime_lifecycle_response(
            request.operation_id,
            method,
            receipt_id,
            &mutation.resulting_state,
            RuntimeLifecycleArtifactV1::Handoff {
                result: Box::new(artifact),
            },
        )?;
        self.store
            .commit_runtime_lifecycle(
                &receipt_key,
                method,
                request_commitment,
                &response,
                mutation,
            )
            .map_err(|error| error.0)?;
        self.reconcile_locked(&mut published)?;
        Ok(response)
    }

    fn replay_open_stream(
        &self,
        stream: &LoadedStream,
        fresh_context: &contextdb_service::AuthenticatedRequestContext,
    ) -> ServiceResult<Arc<ReferenceService>> {
        let (candidate, _, _) = self.replay().map_err(|error| error.0)?;
        for position in 0..stream.state.next_position {
            let frame = stream
                .frames
                .get(&position)
                .ok_or_else(|| integrity("production stream replay frame is missing"))?;
            let receipt = stream
                .receipts
                .get(&position)
                .ok_or_else(|| integrity("production stream replay receipt is missing"))?;
            let mut acknowledgement = candidate.ingest_frame(IngestFrame {
                context: fresh_context.clone(),
                stream_id: frame.stream_id.clone(),
                position: frame.position,
                resume_cursor: frame.resume_cursor.clone(),
                value: frame.value.clone(),
            })?;
            acknowledgement.lease_expires_at_ms = receipt.acknowledgement.lease_expires_at_ms;
            if acknowledgement != receipt.acknowledgement {
                return Err(integrity(
                    "production stream replay changed a durable acknowledgement",
                ));
            }
        }
        Ok(candidate)
    }
}

impl CognitiveMemoryService for ProductionService {
    fn observe(&self, mut request: ObserveRequest) -> ServiceResult<ObserveResponse> {
        let request_digest = canonical_request_digest(&self.store, Operation::Observe, &request)?;
        let key = canonical_bytes(&(
            &request.context.workspace_id,
            &request.context.subject_id,
            &request.context.scopes,
            &request.context.purpose,
            &request.idempotency_key,
        ))
        .map_err(|error| error.0)?;
        request.idempotency_key = format!(
            "production:{}",
            self.store.digest(Operation::Observe.domain(), &key)
        );
        let response_digest = request_digest.clone();
        self.mutate(
            Operation::Observe,
            &key,
            request_digest,
            request,
            move |service, value| {
                let mut response = service.observe(value)?;
                response.request_digest = response_digest;
                Ok(response)
            },
        )
    }

    fn recall(&self, request: RecallRequest) -> ServiceResult<RecallResponse> {
        self.read(|service| service.recall(request))
    }

    fn compile_context(
        &self,
        request: CompileContextRequest,
    ) -> ServiceResult<CompileContextResponse> {
        self.read(|service| service.compile_context(request))
    }

    fn explain_recall(&self, request: ExplainRecallRequest) -> ServiceResult<RecallTrace> {
        self.read(|service| service.explain_recall(request))
    }

    fn preflight(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_grant(&request.context, Capability::Runtime)?;
        self.read(|service| service.preflight(request))
    }

    fn bootstrap(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        // Authentication/capability is resolved before operation ID, payload
        // size/depth, typed continuity data, or provider source material.
        require_grant(&request.context, Capability::Runtime)?;
        let (input, canonical_payload): (RuntimeBootstrapInputV1, _) =
            parse_runtime_lifecycle_payload(&request)?;
        if input.schema_version != STORE_SCHEMA_VERSION || input.expected_checkpoint_version == 0 {
            return Err(invalid_runtime_lifecycle_format());
        }
        validate_runtime_provider_input(&input.provider)?;
        self.execute_compiled_bootstrap(
            request,
            RuntimeBootstrapExecution {
                method: RuntimeLifecycleMethod::Bootstrap,
                expected_checkpoint_version: input.expected_checkpoint_version,
                request: input.request,
                target_runtime: input.target_runtime,
                provider: input.provider,
            },
            &canonical_payload,
        )
    }

    fn checkpoint(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_grant(&request.context, Capability::Runtime)?;
        let (input, canonical_payload): (RuntimeCheckpointInputV1, _) =
            parse_runtime_lifecycle_payload(&request)?;
        let schema_version = match &input {
            RuntimeCheckpointInputV1::Seal { schema_version, .. }
            | RuntimeCheckpointInputV1::Revoke { schema_version, .. } => *schema_version,
        };
        if schema_version != STORE_SCHEMA_VERSION {
            return Err(invalid_runtime_lifecycle_format());
        }
        let method = RuntimeLifecycleMethod::Checkpoint;
        let authorization_digest = request.context.authorization_binding_digest()?;
        let identity_digest = self
            .store
            .runtime_lifecycle_identity_digest(method, &request.context, &request.operation_id)
            .map_err(|error| error.0)?;
        let receipt_key =
            runtime_lifecycle_receipt_key(method, &identity_digest).map_err(|error| error.0)?;
        let request_commitment = self
            .store
            .runtime_lifecycle_request_commitment(
                method,
                &identity_digest,
                &authorization_digest,
                &canonical_payload,
            )
            .map_err(|error| error.0)?;
        let receipt_id = self
            .store
            .runtime_lifecycle_receipt_id(method, &identity_digest, &request_commitment)
            .map_err(|error| error.0)?;

        let mut published = self.lock()?;
        self.reconcile_locked(&mut published)?;
        if let Some(receipt) = self
            .store
            .runtime_lifecycle_receipt(&receipt_key, &request_commitment)
            .map_err(|error| error.0)?
        {
            return validate_runtime_lifecycle_response_bytes(&receipt.response_bytes)
                .map_err(|error| error.0);
        }

        let (mutation, artifact) = match input {
            RuntimeCheckpointInputV1::Seal {
                checkpoint,
                continuity_profile,
                source_runtime,
                policy,
                ..
            } => {
                let portable = PortableCheckpoint::new(
                    *checkpoint,
                    &continuity_profile,
                    &source_runtime,
                    *policy,
                )
                .map_err(map_continuity_service_error)?;
                bind_runtime_context(&request.context, &portable)?;
                let mutation =
                    self.prepare_runtime_seal_mutation(portable.clone(), *source_runtime)?;
                (
                    mutation,
                    RuntimeLifecycleArtifactV1::Checkpoint {
                        checkpoint: Box::new(portable),
                    },
                )
            }
            RuntimeCheckpointInputV1::Revoke {
                checkpoint_digest,
                expected_version,
                revoked_at,
                ..
            } => {
                validate_digest(&checkpoint_digest, "runtime checkpoint digest")
                    .map_err(|error| error.0)?;
                if expected_version == 0 {
                    return Err(invalid_runtime_lifecycle_format());
                }
                let loaded = self
                    .store
                    .load_runtime_state_by_checkpoint(&checkpoint_digest)
                    .map_err(|error| error.0)?
                    .ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::NotFound,
                            "runtime checkpoint is not present in the durable ledger",
                            false,
                        )
                    })?;
                bind_runtime_context(&request.context, &loaded.state.checkpoint)?;
                let active_runtime = loaded.state.active_runtime.clone();
                let mutation = self.prepare_runtime_transition_mutation(
                    loaded,
                    RuntimeTransition {
                        expected_version,
                        status: RuntimeCheckpointStatus::Revoked,
                        active_runtime,
                        updated_at: revoked_at,
                        bootstrap_trace_digest: None,
                        pack_digest: None,
                        increment_handoff: false,
                    },
                )?;
                (
                    mutation,
                    RuntimeLifecycleArtifactV1::CheckpointRevoked {
                        checkpoint_digest,
                        revoked_at,
                    },
                )
            }
        };
        let response = runtime_lifecycle_response(
            request.operation_id,
            method,
            receipt_id,
            &mutation.resulting_state,
            artifact,
        )?;
        self.store
            .commit_runtime_lifecycle(
                &receipt_key,
                method,
                request_commitment,
                &response,
                mutation,
            )
            .map_err(|error| error.0)?;
        self.reconcile_locked(&mut published)?;
        Ok(response)
    }

    fn resume(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_grant(&request.context, Capability::Runtime)?;
        let (input, canonical_payload): (RuntimeResumeInputV1, _) =
            parse_runtime_lifecycle_payload(&request)?;
        if input.schema_version != STORE_SCHEMA_VERSION || input.expected_checkpoint_version == 0 {
            return Err(invalid_runtime_lifecycle_format());
        }
        validate_runtime_provider_input(&input.provider)?;
        self.execute_compiled_bootstrap(
            request,
            RuntimeBootstrapExecution {
                method: RuntimeLifecycleMethod::Resume,
                expected_checkpoint_version: input.expected_checkpoint_version,
                request: input.request,
                target_runtime: input.target_runtime,
                provider: input.provider,
            },
            &canonical_payload,
        )
    }

    fn handoff(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_grant(&request.context, Capability::Runtime)?;
        let (input, canonical_payload): (RuntimeHandoffInputV1, _) =
            parse_runtime_lifecycle_payload(&request)?;
        if input.schema_version != STORE_SCHEMA_VERSION || input.expected_checkpoint_version == 0 {
            return Err(invalid_runtime_lifecycle_format());
        }
        validate_runtime_provider_input(&input.provider)?;
        self.execute_compiled_handoff(request, input, &canonical_payload)
    }

    fn postflight(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        // Authentication/capability must be resolved before the validator is
        // allowed to inspect even the routing-safe payload manifest.
        require_grant(&request.context, Capability::Runtime)?;
        let validated = validate_postflight_submission(&request)?;
        let authorization_digest = request.context.authorization_binding_digest()?;
        let identity_digest = self
            .store
            .runtime_postflight_identity_digest(&request.context, &request.operation_id)
            .map_err(|error| error.0)?;
        let storage_key = runtime_postflight_key(&identity_digest).map_err(|error| error.0)?;
        let commitment_material = Zeroizing::new(
            canonical_bytes(&(
                STORE_SCHEMA_VERSION,
                "runtime_postflight",
                &identity_digest,
                &authorization_digest,
                validated.canonical_bytes(),
            ))
            .map_err(|error| error.0)?,
        );
        let submission_commitment = self
            .store
            .digest(b"runtime_postflight_submission", &commitment_material);

        let mut published = self.lock()?;
        self.reconcile_locked(&mut published)?;
        let (receipt, replayed) = match self
            .store
            .runtime_postflight_receipt(&storage_key, &submission_commitment)
            .map_err(|error| error.0)?
        {
            Some(receipt) => (receipt, true),
            None => {
                let receipt = self
                    .store
                    .append_runtime_postflight_receipt(&storage_key, submission_commitment)
                    .map_err(|error| error.0)?;
                // The Fjall Sync is complete, but the response is withheld
                // until the same external durable authority accepts the new
                // ledger successor. A retry after a lost ACK replays above.
                self.reconcile_locked(&mut published)?;
                (receipt, false)
            }
        };
        Ok(runtime_postflight_response(
            request.operation_id,
            receipt.receipt_id,
            replayed,
        ))
    }

    fn reindex(&self, request: MaintenanceRequest) -> ServiceResult<MaintenanceResponse> {
        // The host transport already performs this check, but the production
        // composition repeats it before inspecting operation ID or payload.
        require_grant(&request.context, Capability::Maintenance)?;
        let canonical_payload = validate_reindex_request(&request)?;
        let authorization_binding_digest = request.context.authorization_binding_digest()?;

        let mut published = self.lock()?;
        self.store.verify().map_err(|error| error.0)?;
        self.reconcile_locked(&mut published)?;

        let identity_digest = self
            .store
            .reindex_identity_digest(&request.context, &request.operation_id)
            .map_err(|error| error.0)?;
        let storage_key = reindex_receipt_key(&identity_digest).map_err(|error| error.0)?;
        let request_commitment = self
            .store
            .reindex_request_commitment(
                &identity_digest,
                &authorization_binding_digest,
                &canonical_payload,
            )
            .map_err(|error| error.0)?;
        if let Some(receipt) = self
            .store
            .reindex_receipt(&storage_key, &request_commitment)
            .map_err(|error| error.0)?
        {
            // `reconcile_locked` completed an exact authority re-read before
            // this branch, including recovery after a previously lost ACK.
            return Ok(reindex_response(
                request.operation_id,
                receipt.receipt_id,
                true,
            ));
        }

        let projection = self.store.current_projection().map_err(|error| error.0)?;
        let head = self.store.head_from_latest().map_err(|error| error.0)?;
        let healthy_graph = self.store.policy_graph().map_err(|error| error.0)?;
        let candidate = self
            .store
            .build_policy_graph_projection(&projection.archive, head)
            .map_err(|error| error.0)?;
        let candidate_bytes = Zeroizing::new(canonical_bytes(&candidate).map_err(|error| error.0)?);
        if candidate_bytes.is_empty() || candidate_bytes.len() > MAX_REINDEX_CANDIDATE_BYTES {
            return Err(resource_exhausted(
                "production policy-graph reindex candidate exceeds the 512 MiB limit",
                false,
            ));
        }
        let healthy_bytes = canonical_bytes(&healthy_graph).map_err(|error| error.0)?;
        if candidate != healthy_graph || healthy_bytes.as_slice() != candidate_bytes.as_slice() {
            return Err(integrity(
                "production policy-graph reindex candidate differs from the healthy singleton",
            ));
        }
        let durable = self
            .store
            .verify_durable_history()
            .map_err(|error| error.0)?;
        let source_commitment = self
            .store
            .reindex_source_commitment(&projection, &candidate)
            .map_err(|error| error.0)?;
        let receipt = self
            .store
            .append_reindex_receipt(
                &storage_key,
                request_commitment,
                source_commitment,
                &projection,
                &candidate,
                &durable,
                &candidate_bytes,
            )
            .map_err(|error| error.0)?;

        // Fjall Sync has completed. Validate the new rooted receipt and then
        // withhold the ACK until the external authority accepts and re-reads
        // this exact durable successor.
        self.store.verify().map_err(|error| error.0)?;
        self.reconcile_locked(&mut published)?;
        Ok(reindex_response(
            request.operation_id,
            receipt.receipt_id,
            false,
        ))
    }

    fn export_archive(&self, request: ExportRequest) -> ServiceResult<ExportResponse> {
        self.read(|service| service.export_archive(request))
    }

    fn import_archive(&self, request: ImportRequest) -> ServiceResult<ImportResponse> {
        self.read(|service| service.import_archive(request))
    }

    fn verify(&self, request: VerifyRequest) -> ServiceResult<VerifyResponse> {
        self.store.verify().map_err(|error| error.0)?;
        let mut published = self.lock()?;
        self.reconcile_locked(&mut published)?;
        published.verify(request)
    }

    fn ingest_frame(&self, request: IngestFrame) -> ServiceResult<IngestAck> {
        require_grant(&request.context, Capability::StreamIngest)?;
        validate_stream_identifier(&request.stream_id)?;
        let workspace_id = request.context.request.workspace_id.clone();
        let authorization_digest = request.context.authorization_binding_digest()?;
        let stream_digest = self
            .store
            .stream_digest(&workspace_id, &request.stream_id)
            .map_err(|error| error.0)?;
        let stored_frame = StoredStreamFrame {
            schema_version: STREAM_SCHEMA_VERSION,
            stream_id: request.stream_id.clone(),
            position: request.position,
            resume_cursor: request.resume_cursor.clone(),
            value: request.value.clone(),
        };
        let frame_bytes = Zeroizing::new(canonical_bytes(&stored_frame).map_err(|error| error.0)?);
        if frame_bytes.is_empty() || frame_bytes.len() > MAX_STREAM_FRAME_BYTES {
            return Err(resource_exhausted(
                "production stream frame exceeds the 16 MiB canonical limit",
                false,
            ));
        }
        let request_digest =
            stream_request_digest(&self.store, &authorization_digest, &stored_frame)?;
        let completion_idempotency = self
            .store
            .stream_completion_idempotency_digest(&stream_digest);

        let mut published = self.lock()?;
        self.reconcile_locked(&mut published)?;
        let now_ms = unix_time_millis()?;
        if self
            .store
            .reclaim_expired_streams(now_ms)
            .map_err(|error| error.0)?
        {
            self.reconcile_locked(&mut published)?;
        }
        let lease_expires_at_ms = stream_lease_deadline(now_ms)?;

        if let Some(expired) = self
            .store
            .load_expired_stream(&stream_digest)
            .map_err(|error| error.0)?
        {
            if expired.authorization_digest != authorization_digest {
                return Err(ServiceError::new(
                    ErrorCode::Unauthorized,
                    "stream belongs to another authenticated principal",
                    false,
                ));
            }
            return match expired.request_digests.get(&request.position) {
                Some(expired_digest) if expired_digest == &request_digest => {
                    Err(stream_lease_expired_error())
                }
                Some(_) | None => Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "expired production stream identity cannot be reused",
                    false,
                )),
            };
        }

        if matches!(&request.value, IngestFrameValue::SnapshotComplete(_))
            && let Some(event) = self
                .store
                .idempotent_event(&completion_idempotency, &request_digest)
                .map_err(|error| error.0)?
        {
            return self
                .store
                .stream_completion_ack(&event)
                .map_err(|error| error.0);
        }

        let existing = self
            .store
            .load_stream(&stream_digest)
            .map_err(|error| error.0)?;
        if let IngestFrameValue::Manifest(manifest) = &request.value {
            if let Some(stream) = existing {
                if stream.state.authorization_digest != authorization_digest {
                    return Err(ServiceError::new(
                        ErrorCode::IdempotencyConflict,
                        "stream identity was reused with a different manifest or principal",
                        false,
                    ));
                }
                let receipt = stream
                    .receipts
                    .get(&0)
                    .ok_or_else(|| integrity("production manifest receipt is missing"))?;
                if receipt.request_digest != request_digest {
                    return Err(ServiceError::new(
                        ErrorCode::IdempotencyConflict,
                        "stream identity was reused with a different manifest or principal",
                        false,
                    ));
                }
                return Ok(receipt.acknowledgement.clone());
            }
            // A completed stream identity is permanently reserved by the
            // durable ledger even after all encrypted staging records vanish.
            if self
                .store
                .idempotent_event(&completion_idempotency, &request_digest)
                .map_err(|error| error.0)?
                .is_some()
            {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "completed production stream identities cannot be reused",
                    false,
                ));
            }
            if manifest.expected_items > MAX_STREAM_ITEMS {
                return Err(resource_exhausted(
                    "production snapshot exceeds the 4096-item limit",
                    false,
                ));
            }
            let (candidate, _, _) = self.replay().map_err(|error| error.0)?;
            let mut acknowledgement = candidate.ingest_frame(request.clone())?;
            if acknowledgement.disposition != IngestDisposition::Accepted
                || acknowledgement.position != 0
                || acknowledgement.commit_seq.is_some()
            {
                return Err(integrity(
                    "reference stream returned an invalid manifest acknowledgement",
                ));
            }
            acknowledgement.lease_expires_at_ms = Some(lease_expires_at_ms);
            let buffered_bytes = u64::try_from(frame_bytes.len()).map_err(|_| {
                resource_exhausted("production stream frame size exceeds this platform", false)
            })?;
            let state = StoredStreamState {
                schema_version: STREAM_SCHEMA_VERSION,
                stream_digest,
                workspace_id,
                stream_id: stored_frame.stream_id.clone(),
                authorization_digest,
                next_position: 1,
                buffered_bytes,
                lease_expires_at_ms,
            };
            let receipt = StoredStreamReceipt {
                schema_version: STREAM_SCHEMA_VERSION,
                position: 0,
                request_digest,
                acknowledgement: acknowledgement.clone(),
            };
            self.store
                .persist_stream_frame(&state, &stored_frame, &receipt)
                .map_err(|error| error.0)?;
            self.reconcile_locked(&mut published)?;
            return Ok(acknowledgement);
        }

        let stream = existing.ok_or_else(|| {
            ServiceError::new(
                ErrorCode::InvalidContinuation,
                "production stream manifest is missing or already committed",
                false,
            )
        })?;
        if stream.state.authorization_digest != authorization_digest {
            return Err(ServiceError::new(
                ErrorCode::Unauthorized,
                "stream belongs to another authenticated principal",
                false,
            ));
        }
        validate_expected_stream_cursor(&stored_frame, &stream.receipts)?;
        if request.position < stream.state.next_position {
            let receipt = stream
                .receipts
                .get(&request.position)
                .ok_or_else(|| integrity("production stream retry receipt is missing"))?;
            if receipt.request_digest != request_digest {
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "stream position was retried with different content",
                    false,
                ));
            }
            return Ok(receipt.acknowledgement.clone());
        }
        if request.position != stream.state.next_position {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "stream frame is out of order",
                false,
            ));
        }

        let candidate = self.replay_open_stream(&stream, &request.context)?;
        let mut acknowledgement = candidate.ingest_frame(request)?;
        match &stored_frame.value {
            IngestFrameValue::Manifest(_) => Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "a stream may contain exactly one opening manifest",
                false,
            )),
            IngestFrameValue::Observation(_) => {
                if acknowledgement.disposition != IngestDisposition::Accepted
                    || acknowledgement.commit_seq.is_some()
                {
                    return Err(integrity(
                        "reference stream returned an invalid frame acknowledgement",
                    ));
                }
                acknowledgement.lease_expires_at_ms = Some(lease_expires_at_ms);
                let buffered_bytes = usize::try_from(stream.state.buffered_bytes)
                    .ok()
                    .and_then(|bytes| bytes.checked_add(frame_bytes.len()))
                    .filter(|bytes| *bytes <= MAX_STREAM_BUFFERED_BYTES)
                    .ok_or_else(|| {
                        resource_exhausted(
                            "production buffered stream exceeds the 64 MiB limit",
                            false,
                        )
                    })?;
                let mut state = stream.state.clone();
                state.next_position = state.next_position.checked_add(1).ok_or_else(|| {
                    resource_exhausted("production stream position is exhausted", false)
                })?;
                state.buffered_bytes = u64::try_from(buffered_bytes).map_err(|_| {
                    resource_exhausted("production stream byte count exceeds this platform", false)
                })?;
                state.lease_expires_at_ms = lease_expires_at_ms;
                let receipt = StoredStreamReceipt {
                    schema_version: STREAM_SCHEMA_VERSION,
                    position: stored_frame.position,
                    request_digest,
                    acknowledgement: acknowledgement.clone(),
                };
                self.store
                    .persist_stream_frame(&state, &stored_frame, &receipt)
                    .map_err(|error| error.0)?;
                self.reconcile_locked(&mut published)?;
                Ok(acknowledgement)
            }
            IngestFrameValue::SnapshotComplete(_) => {
                if acknowledgement.disposition != IngestDisposition::SnapshotCommitted {
                    return Err(integrity(
                        "reference stream did not atomically commit its completion marker",
                    ));
                }
                acknowledgement.lease_expires_at_ms = None;
                let projection = self.export_host_archive(&candidate)?;
                let event = StoredEvent {
                    schema_version: STORE_SCHEMA_VERSION,
                    sequence: 0,
                    operation: Operation::StreamIngest,
                    previous_event_checksum: None,
                    idempotency_digest: completion_idempotency,
                    request_digest,
                    response_digest: String::new(),
                    response_bytes: Vec::new(),
                    projection_commit_seq: projection.commit_seq,
                    projection_digest: projection.digest.clone(),
                    checksum: String::new(),
                };
                self.store
                    .append_stream_completion(event, &projection.bytes, &stream, &acknowledgement)
                    .map_err(|error| error.0)?;
                self.reconcile_locked(&mut published)?;
                Ok(acknowledgement)
            }
        }
    }

    fn subscribe(&self, request: SubscribeRequest) -> ServiceResult<SubscriptionPage> {
        self.read(|service| service.subscribe(request))
    }

    fn publish_memory(&self, request: PublishMemoryRequest) -> ServiceResult<MutationResponse> {
        require_grant(&request.context, Capability::Correct)?;
        require_grant(&request.context, Capability::Observe)?;
        let request_digest =
            canonical_request_digest(&self.store, Operation::PublishMemory, &request)?;
        let key = authenticated_namespace(&request.context, &request.idempotency_key)?;
        self.mutate(
            Operation::PublishMemory,
            &key,
            request_digest,
            request,
            |service, value| service.publish_memory(value),
        )
    }

    fn correct(&self, request: CorrectRequest) -> ServiceResult<MutationResponse> {
        let request_digest = canonical_request_digest(&self.store, Operation::Correct, &request)?;
        let key = authenticated_namespace(&request.context, &request.idempotency_key)?;
        self.mutate(
            Operation::Correct,
            &key,
            request_digest,
            request,
            |service, value| service.correct(value),
        )
    }

    fn suppress(&self, request: HighLevelControlRequest) -> ServiceResult<MutationResponse> {
        self.mutate_semantic_control(Operation::Suppress, request, |service, value| {
            service.suppress(value)
        })
    }

    fn change_audience(&self, request: HighLevelControlRequest) -> ServiceResult<MutationResponse> {
        self.mutate_semantic_control(Operation::ChangeAudience, request, |service, value| {
            service.change_audience(value)
        })
    }

    fn publish_to_shared_memory(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        self.mutate_semantic_control(
            Operation::PublishToSharedMemory,
            request,
            |service, value| service.publish_to_shared_memory(value),
        )
    }

    fn revoke_shared_memory(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        self.mutate_semantic_control(Operation::RevokeSharedMemory, request, |service, value| {
            service.revoke_shared_memory(value)
        })
    }

    fn forget(&self, request: ForgetRequest) -> ServiceResult<MutationResponse> {
        if request.mode == ForgetMode::HardDelete {
            require_grant(&request.context, Capability::Forget)?;
            require_grant(&request.context, Capability::HardDelete)?;
            return Err(unsupported(
                "production hard deletion requires encrypted content indirection and proven physical erasure",
            ));
        }
        let request_digest = canonical_request_digest(&self.store, Operation::Forget, &request)?;
        let key = authenticated_namespace(&request.context, &request.idempotency_key)?;
        self.mutate(
            Operation::Forget,
            &key,
            request_digest,
            request,
            |service, value| service.forget(value),
        )
    }

    fn get_node(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_grant(&request.context, Capability::ReadMemory)?;
        validate_graph_record_identifier(&request.record_id)?;
        self.read_with_graph(|service, graph| {
            let commit = graph.snapshot_seq(request.at_commit)?;
            let expected = graph.authorize_record(
                &request.record_id,
                GraphRecordKind::Node,
                commit,
                &request.context.request,
                false,
            )?;
            let actual = service.get_node(request)?;
            if !graph_record_matches(expected, &actual) {
                return Err(integrity(
                    "canonical node materialization differs from the persistent policy graph",
                ));
            }
            Ok(actual)
        })
    }

    fn get_memory(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_grant(&request.context, Capability::ReadMemory)?;
        validate_graph_record_identifier(&request.record_id)?;
        self.read_with_graph(|service, graph| {
            let commit = graph.snapshot_seq(request.at_commit)?;
            let expected = graph.authorize_record(
                &request.record_id,
                GraphRecordKind::SemanticObject,
                commit,
                &request.context.request,
                false,
            )?;
            let actual = service.get_memory(request)?;
            if !graph_record_matches(expected, &actual) {
                return Err(integrity(
                    "canonical semantic memory differs from the persistent policy graph",
                ));
            }
            Ok(actual)
        })
    }

    fn traverse(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        require_grant(&request.context, Capability::Traverse)?;
        self.read_with_graph(|_service, graph| graph.traverse(&request))
    }

    fn get_timeline(&self, request: GetTimelineRequest) -> ServiceResult<TimelineResponse> {
        require_graph_record_grant(&request.context, request.expected_kind)?;
        validate_graph_record_identifier(&request.record_id)?;
        if request.max_revisions == 0 || request.max_revisions > 1_000 {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "timeline revision budget must be between 1 and 1000",
                false,
            ));
        }
        self.read_with_graph(|service, graph| {
            let commit = graph.snapshot_seq(request.at_commit)?;
            let expected = graph.authorized_history(
                &request.record_id,
                graph_kind(request.expected_kind),
                commit,
                &request.context.request,
                usize::try_from(request.max_revisions).unwrap_or(usize::MAX),
            )?;
            let expected_watermarks = graph.watermarks_at(commit);
            let actual = service.get_timeline(request)?;
            if actual.snapshot_seq != commit
                || actual.watermarks.journal != expected_watermarks.journal
                || actual.watermarks.semantic != expected_watermarks.semantic
                || actual.watermarks.lexical != expected_watermarks.lexical
                || actual.watermarks.vector != expected_watermarks.vector
                || actual.watermarks.graph != expected_watermarks.graph
                || actual.revisions.len() != expected.len()
                || actual
                    .revisions
                    .iter()
                    .zip(expected)
                    .any(|(actual, expected)| !graph_record_matches(expected, actual))
            {
                return Err(integrity(
                    "canonical timeline differs from the persistent policy graph",
                ));
            }
            Ok(actual)
        })
    }

    fn get_evidence(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_grant(&request.context, Capability::ReadEvidence)?;
        require_grant(&request.context, Capability::RawEvidence)?;
        validate_graph_record_identifier(&request.record_id)?;
        self.read_with_graph(|service, graph| {
            let commit = graph.snapshot_seq(request.at_commit)?;
            let expected = graph.authorize_record(
                &request.record_id,
                GraphRecordKind::Evidence,
                commit,
                &request.context.request,
                false,
            )?;
            let actual = service.get_evidence(request)?;
            if !graph_record_matches(expected, &actual) {
                return Err(integrity(
                    "canonical evidence materialization differs from the persistent policy graph",
                ));
            }
            Ok(actual)
        })
    }

    fn get_conflict(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_grant(&request.context, Capability::ReadConflict)?;
        validate_graph_record_identifier(&request.record_id)?;
        self.read_with_graph(|service, graph| {
            let commit = graph.snapshot_seq(request.at_commit)?;
            let expected = graph.authorize_record(
                &request.record_id,
                GraphRecordKind::Conflict,
                commit,
                &request.context.request,
                false,
            )?;
            let actual = service.get_conflict(request)?;
            if !graph_record_matches(expected, &actual) {
                return Err(integrity(
                    "canonical conflict materialization differs from the persistent policy graph",
                ));
            }
            Ok(actual)
        })
    }

    fn compact(&self, request: MaintenanceRequest) -> ServiceResult<MaintenanceResponse> {
        // Authentication is intentionally resolved before operation ID or the
        // action-specific payload can act as a format/pressure oracle.
        require_grant(&request.context, Capability::Maintenance)?;
        let payload = validate_compact_request(&request)?;
        let canonical_payload = Zeroizing::new(canonical_bytes(&payload).map_err(|error| error.0)?);
        let mut published = self.lock()?;
        self.store.verify().map_err(|error| error.0)?;
        self.reconcile_locked(&mut published)?;

        let response_payload = match payload {
            CompactPayloadV1::Physical {
                schema_version: _,
                max_bytes,
            } => {
                let before = self
                    .store
                    .engine
                    .head_sequence()
                    .map_err(storage_error)
                    .map_err(|error| error.0)?;
                let report = self
                    .store
                    .engine
                    .compact(CompactRequest { max_bytes })
                    .map_err(storage_error)
                    .map_err(|error| error.0)?;
                let after = self
                    .store
                    .engine
                    .head_sequence()
                    .map_err(storage_error)
                    .map_err(|error| error.0)?;
                if before != report.sequence || after != before {
                    return Err(integrity(
                        "physical compaction changed the logical storage sequence",
                    ));
                }
                serde_json::json!({
                    "schema_version": STORE_SCHEMA_VERSION,
                    "action": "physical",
                    "physical_sequence": report.sequence,
                    "bytes_reclaimed": report.bytes_reclaimed,
                    "logical_state_changed": false,
                    "scheduler_managed": true,
                    "manual_rewrite_claimed": false
                })
            }
            CompactPayloadV1::RuntimeLedgerGc {
                schema_version: _,
                retain_state_versions,
                max_record_work,
                dry_run,
            } => {
                let identity_digest = self
                    .store
                    .runtime_gc_identity_digest(&request.context, &request.operation_id)
                    .map_err(|error| error.0)?;
                let receipt_key =
                    runtime_gc_receipt_key(&identity_digest).map_err(|error| error.0)?;
                let authorization_digest = request.context.authorization_binding_digest()?;
                let request_commitment = self
                    .store
                    .runtime_gc_request_commitment(
                        &identity_digest,
                        &authorization_digest,
                        &canonical_payload,
                    )
                    .map_err(|error| error.0)?;
                if let Some(receipt) = self
                    .store
                    .runtime_gc_receipt(&receipt_key, &request_commitment)
                    .map_err(|error| error.0)?
                {
                    let mut report: RuntimeLedgerGcReportV1 =
                        serde_json::from_value(receipt.response_payload)
                            .map_err(|_| integrity("stored runtime GC report is not canonical"))?;
                    report.replayed = true;
                    return Ok(MaintenanceResponse {
                        operation_id: request.operation_id,
                        payload: serde_json::to_value(report)
                            .map_err(|_| integrity("runtime GC replay serialization failed"))?,
                    });
                }
                let durable = self
                    .store
                    .verify_durable_history()
                    .map_err(|error| error.0)?;
                let retirement_generation = durable
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| integrity("production durable generation is exhausted"))?;
                let plan = self
                    .store
                    .plan_runtime_ledger_gc(
                        retain_state_versions,
                        max_record_work,
                        retirement_generation,
                    )
                    .map_err(|error| error.0)?;
                let report = if dry_run {
                    runtime_gc_report(
                        if plan.state_keys.is_empty() {
                            "no_op"
                        } else {
                            "planned"
                        },
                        true,
                        u64::try_from(plan.state_keys.len()).map_err(|_| {
                            resource_exhausted(
                                "runtime GC state count exceeds this platform",
                                false,
                            )
                        })?,
                        u64::try_from(plan.checkpoint_head_keys.len()).map_err(|_| {
                            resource_exhausted(
                                "runtime GC checkpoint count exceeds this platform",
                                false,
                            )
                        })?,
                        u64::try_from(plan.retired_receipts.len()).map_err(|_| {
                            resource_exhausted(
                                "runtime GC receipt count exceeds this platform",
                                false,
                            )
                        })?,
                        u64::try_from(plan.anchors.len()).map_err(|_| {
                            resource_exhausted(
                                "runtime GC anchor count exceeds this platform",
                                false,
                            )
                        })?,
                        false,
                    )
                } else {
                    self.store
                        .apply_runtime_ledger_gc(plan, &durable, &receipt_key, request_commitment)
                        .map_err(|error| error.0)?
                };
                if report.durable_receipt_recorded {
                    self.store.verify().map_err(|error| error.0)?;
                    self.reconcile_locked(&mut published)?;
                }
                serde_json::to_value(report)
                    .map_err(|_| integrity("runtime GC report serialization failed"))?
            }
        };
        Ok(MaintenanceResponse {
            operation_id: request.operation_id,
            payload: response_payload,
        })
    }

    fn get_status(&self, request: GetStatusRequest) -> ServiceResult<StatusResponse> {
        require_grant(&request.context, Capability::Admin)?;
        let (mut status, runtime_health) = self.read_with_graph(|service, graph| {
            // Status reports the ledger health paired with the last fully
            // verified and externally reconciled publication. Ordinary reads
            // remain isolated from later unverified disk-only bytes; the
            // readiness probe detects sequence drift and explicit `verify`
            // re-enters the closed-world disk verifier.
            let runtime_health = self.cached_reconciled_tip()?.runtime_health;
            let status = service.get_status(request)?;
            if status.commit_seq != graph.archive_commit_seq
                || status.watermarks.journal != graph.watermarks.journal
                || status.watermarks.semantic != graph.watermarks.semantic
                || status.watermarks.lexical != graph.watermarks.lexical
                || status.watermarks.vector != graph.watermarks.vector
                || status.watermarks.graph != graph.watermarks.graph
            {
                return Err(integrity(
                    "canonical status differs from the persistent policy graph watermark",
                ));
            }
            Ok((status, runtime_health))
        })?;
        let pressure = match runtime_health.pressure {
            RuntimeLedgerPressure::Nominal => "nominal",
            RuntimeLedgerPressure::Elevated => "elevated",
            RuntimeLedgerPressure::Critical => "critical",
            RuntimeLedgerPressure::Exhausted => "exhausted",
        };
        status.profile = format!("{PROFILE};runtime_ledger_pressure={pressure}");
        status.capability_manifest = production_capability_manifest(&status.profile);
        Ok(status)
    }

    fn create_backup(&self, request: CreateBackupRequest) -> ServiceResult<BackupResponse> {
        require_grant(&request.context, Capability::Admin)?;
        Err(unsupported(
            "workspace authority cannot create a database-global backup; Fjall online physical checkpoints are unavailable, so use the documented quiesced host snapshot protocol",
        )
        .with_context(
            Vec::new(),
            Some("authority:host-global".to_owned()),
            Some("stop all writers and capture one quiesced recovery set".to_owned()),
            None,
        ))
    }

    fn restore_backup(
        &self,
        request: RestoreBackupRequest,
    ) -> ServiceResult<RestoreBackupResponse> {
        require_grant(&request.context, Capability::Admin)?;
        Err(unsupported(
            "live full-store restore is unavailable; restore a quiesced bundle into a new isolated path and verify it before supervisor activation",
        )
        .with_context(
            Vec::new(),
            Some("authority:host-global".to_owned()),
            Some("use the documented offline disaster-recovery boundary".to_owned()),
            None,
        ))
    }

    fn migrate_format(&self, request: MigrateFormatRequest) -> ServiceResult<StatusResponse> {
        require_grant(&request.context, Capability::Admin)?;
        if !bounded_identifier(&request.operation_id, 1_024)
            || !bounded_identifier(&request.target_format, 256)
        {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "format migration target or operation ID is not a valid bounded identifier",
                false,
            ));
        }
        if request.target_format != PRODUCTION_FORMAT_ID {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "no verified production migration path exists for the requested target format",
                false,
            )
            .with_context(
                Vec::new(),
                Some(format!("current_format:{PRODUCTION_FORMAT_ID}")),
                Some(
                    "run the side-by-side format preflight and use a registered migration executor"
                        .to_owned(),
                ),
                None,
            ));
        }
        let mut published = self.lock()?;
        self.store.verify().map_err(|error| error.0)?;
        self.reconcile_locked(&mut published)?;
        drop(published);
        // An identity target is a verified, side-effect-free preflight. It is
        // deliberately not recorded as a migration receipt because no format
        // generation is rewritten or activated.
        self.get_status(GetStatusRequest {
            context: request.context,
        })
    }
}

impl VerifiedPolicyGraph {
    fn new(projection: PolicyGraphProjection) -> CliResult<Self> {
        let adjacency = Self::build_adjacency(&projection)?;
        let semantic_commits = projection
            .journal
            .iter()
            .filter(|entry| entry.class == GraphJournalClass::SemanticPublished)
            .map(|entry| entry.commit_seq)
            .collect();
        Ok(Self {
            projection,
            adjacency,
            semantic_commits,
        })
    }

    fn build_adjacency(projection: &PolicyGraphProjection) -> CliResult<PolicyAdjacency> {
        let mut adjacency = PolicyAdjacency::new();
        let mut workspace_memberships = BTreeMap::<String, usize>::new();
        let mut estimated_adjacency_bytes = 0_usize;
        for (edge_id, history) in &projection.histories {
            for revision in history {
                if revision.record.kind != GraphRecordKind::Edge {
                    continue;
                }
                let workspace = revision.record.access.workspace.clone();
                let partition = GraphPolicyPartition::from(&revision.record.access);
                for endpoint in [
                    revision.record.links.source.as_ref(),
                    revision.record.links.target.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    let inserted = adjacency
                        .entry(workspace.clone())
                        .or_default()
                        .entry(endpoint.clone())
                        .or_default()
                        .entry(partition.clone())
                        .or_default()
                        .insert(edge_id.clone());
                    if inserted {
                        estimated_adjacency_bytes = estimated_adjacency_bytes
                            .checked_add(edge_id.len())
                            .and_then(|bytes| bytes.checked_add(endpoint.len()))
                            // Conservative map/set/key allocation overhead.
                            .and_then(|bytes| bytes.checked_add(128))
                            .filter(|bytes| *bytes <= MAX_GRAPH_ADJACENCY_BYTES)
                            .ok_or_else(|| {
                                integrity(
                                    "policy graph adjacency exceeds its 512 MiB in-memory bound",
                                )
                            })?;
                        let memberships =
                            workspace_memberships.entry(workspace.clone()).or_default();
                        *memberships = memberships
                            .checked_add(1)
                            .filter(|value| *value <= MAX_GRAPH_TRAVERSAL_WORK)
                            .ok_or_else(|| {
                                integrity(
                                    "workspace graph adjacency exceeds the bounded production traversal contract",
                                )
                            })?;
                    }
                }
            }
        }
        Ok(adjacency)
    }

    fn watermarks_at(&self, commit: u64) -> GraphWatermarks {
        let semantic_index = self
            .semantic_commits
            .partition_point(|semantic_commit| *semantic_commit <= commit);
        let semantic = semantic_index
            .checked_sub(1)
            .and_then(|index| self.semantic_commits.get(index))
            .copied()
            .unwrap_or(0);
        GraphWatermarks {
            journal: commit,
            semantic,
            lexical: semantic,
            vector: semantic,
            graph: semantic,
        }
    }

    fn validate_bounds(projection: &PolicyGraphProjection) -> CliResult<()> {
        Self::build_adjacency(projection).map(|_| ())
    }

    fn traverse(&self, request: &TraverseRequest) -> ServiceResult<TraverseResponse> {
        self.traverse_with_work_limit(request, MAX_GRAPH_TRAVERSAL_WORK)
    }

    fn traverse_with_work_limit(
        &self,
        request: &TraverseRequest,
        work_limit: usize,
    ) -> ServiceResult<TraverseResponse> {
        if request.start_ids.is_empty()
            || request.start_ids.len() > 1_000
            || request.max_hops == 0
            || request.max_hops > 32
            || request.max_nodes == 0
            || request.max_nodes > 10_000
            || request
                .start_ids
                .iter()
                .any(|id| !bounded_identifier(id, 1_024))
            || !valid_graph_set(&request.predicate_ids)
        {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "traversal roots and budgets are outside the v1 graph bounds",
                false,
            ));
        }
        let snapshot_seq = self.snapshot_seq(request.at_commit)?;
        for id in &request.start_ids {
            match self.authorize_record(
                id,
                GraphRecordKind::Node,
                snapshot_seq,
                &request.context.request,
                true,
            ) {
                Ok(_) => {}
                Err(error) if error.code == ErrorCode::NotFound => {
                    return Err(graph_permission_denied());
                }
                Err(error) => return Err(error),
            }
        }

        let maximum = usize::try_from(request.max_nodes).map_err(|_| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "graph traversal node budget exceeds this platform",
                false,
            )
        })?;
        let workspace = request.context.request.workspace_id.as_str();
        let mut work = 0_usize;
        let mut queue = VecDeque::new();
        let mut visited = request.start_ids.iter().cloned().collect::<BTreeSet<_>>();
        for id in visited.iter().cloned() {
            queue.push_back((id, 0_u8));
        }
        let mut result = Vec::new();
        let mut authorized_edges = 0_u64;
        while let Some((node, hops)) = queue.pop_front() {
            if hops >= request.max_hops {
                continue;
            }
            let mut neighbours = BTreeSet::new();
            let Some(partitions) = self
                .adjacency
                .get(workspace)
                .and_then(|by_endpoint| by_endpoint.get(&node))
            else {
                continue;
            };
            // A stable edge can move between policy partitions across
            // revisions. Union candidate IDs after policy gating so the
            // snapshot-selected revision is evaluated exactly once.
            let candidate_ids = partitions
                .iter()
                .filter(|(partition, _)| partition.allows(&request.context.request))
                .flat_map(|(_, edge_ids)| edge_ids.iter().map(String::as_str))
                .collect::<BTreeSet<_>>();
            for edge_id in &candidate_ids {
                if self.is_tombstoned_at(edge_id, snapshot_seq) {
                    continue;
                }
                if !self.current_use_policy_allows(edge_id, &request.context.request) {
                    continue;
                }
                let Some(edge) = self.revision_at(edge_id, snapshot_seq) else {
                    continue;
                };
                // The candidate partition was policy-authorized before edge
                // lookup. Re-check the selected historical revision because
                // one stable edge ID may move between policy partitions over
                // bitemporal history.
                if edge.record.lifecycle != GraphLifecycle::Active
                    || !graph_policy_allows(&edge.record.access, &request.context.request)
                {
                    continue;
                }
                if edge.record.kind != GraphRecordKind::Edge {
                    continue;
                }
                let links = &edge.record.links;
                if !request.predicate_ids.is_empty()
                    && links
                        .predicate
                        .as_ref()
                        .is_none_or(|predicate| !request.predicate_ids.contains(predicate))
                {
                    continue;
                }
                let outgoing = matches!(
                    request.direction,
                    contextdb_service::TraverseDirection::Outgoing
                        | contextdb_service::TraverseDirection::Both
                ) && links.source.as_deref() == Some(node.as_str());
                let incoming = matches!(
                    request.direction,
                    contextdb_service::TraverseDirection::Incoming
                        | contextdb_service::TraverseDirection::Both
                ) && links.target.as_deref() == Some(node.as_str());
                let neighbour = if outgoing {
                    links.target.as_ref()
                } else if incoming {
                    links.source.as_ref()
                } else {
                    None
                };
                let Some(neighbour) = neighbour else {
                    continue;
                };
                if self
                    .authorize_record(
                        neighbour,
                        GraphRecordKind::Node,
                        snapshot_seq,
                        &request.context.request,
                        true,
                    )
                    .is_ok()
                {
                    work = work.checked_add(1).ok_or_else(graph_work_exhausted)?;
                    if work > work_limit {
                        return Err(graph_work_exhausted());
                    }
                    authorized_edges = authorized_edges.saturating_add(1);
                    neighbours.insert(neighbour.clone());
                }
            }
            for neighbour in neighbours {
                if visited.insert(neighbour.clone()) {
                    result.push(neighbour.clone());
                    if result.len() >= maximum {
                        break;
                    }
                    queue.push_back((neighbour, hops.saturating_add(1)));
                }
            }
            if result.len() >= maximum {
                break;
            }
        }
        let watermarks = self.watermarks_at(snapshot_seq);
        Ok(TraverseResponse {
            node_ids: result,
            snapshot_seq,
            authorized_candidates: authorized_edges,
            watermarks: contextdb_service::Watermarks {
                journal: watermarks.journal,
                semantic: watermarks.semantic,
                lexical: watermarks.lexical,
                vector: watermarks.vector,
                graph: watermarks.graph,
            },
        })
    }
}

impl PolicyGraphProjection {
    fn snapshot_seq(&self, requested: Option<u64>) -> ServiceResult<u64> {
        let commit = requested.unwrap_or(self.archive_commit_seq);
        if commit > self.archive_commit_seq {
            return Err(ServiceError::new(
                ErrorCode::NotFound,
                "requested graph snapshot was not found",
                false,
            ));
        }
        Ok(commit)
    }

    fn revision_at<'a>(&'a self, id: &str, commit: u64) -> Option<&'a GraphRevision> {
        self.histories.get(id).and_then(|history| {
            let end = history.partition_point(|revision| revision.transaction_from <= commit);
            end.checked_sub(1)
                .and_then(|index| history.get(index))
                .filter(|revision| revision.transaction_to.is_none_or(|to| commit < to))
        })
    }

    fn is_tombstoned_at(&self, id: &str, _commit: u64) -> bool {
        // Deletion and current suppression policy are overlays on retained
        // semantic history. An old semantic snapshot is never an authority to
        // resurrect a target that is now deleted.
        self.tombstones.contains_key(id)
    }

    fn current_use_policy_allows(
        &self,
        id: &str,
        principal: &contextdb_service::RequestContext,
    ) -> bool {
        !self.tombstones.contains_key(id)
            && self
                .revision_at(id, self.archive_commit_seq)
                .is_some_and(|revision| {
                    !matches!(
                        revision.record.lifecycle,
                        GraphLifecycle::Suppressed | GraphLifecycle::Retracted
                    ) && graph_policy_allows(&revision.record.access, principal)
                })
    }

    fn authorize_record<'a>(
        &'a self,
        id: &str,
        expected: GraphRecordKind,
        commit: u64,
        principal: &contextdb_service::RequestContext,
        active_only: bool,
    ) -> ServiceResult<&'a GraphRevision> {
        if self.is_tombstoned_at(id, commit) {
            return Err(graph_not_found());
        }
        if !self.current_use_policy_allows(id, principal) {
            return Err(graph_permission_denied());
        }
        let revision = self.revision_at(id, commit).ok_or_else(graph_not_found)?;
        if active_only && revision.record.lifecycle != GraphLifecycle::Active
            || !graph_policy_allows(&revision.record.access, principal)
        {
            return Err(graph_permission_denied());
        }
        if revision.record.kind != expected {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "record family does not match the requested typed graph route",
                false,
            ));
        }
        Ok(revision)
    }

    fn authorized_history<'a>(
        &'a self,
        id: &str,
        expected: GraphRecordKind,
        commit: u64,
        principal: &contextdb_service::RequestContext,
        maximum: usize,
    ) -> ServiceResult<Vec<&'a GraphRevision>> {
        if self.is_tombstoned_at(id, commit) {
            return Err(graph_not_found());
        }
        if !self.current_use_policy_allows(id, principal) {
            return Err(graph_permission_denied());
        }
        let history = self.histories.get(id).ok_or_else(graph_not_found)?;
        let mut result = Vec::new();
        for revision in history.iter().filter(|revision| {
            revision.transaction_from <= commit
                && graph_policy_allows(&revision.record.access, principal)
        }) {
            if revision.record.kind != expected {
                return Err(ServiceError::new(
                    ErrorCode::InvalidArgument,
                    "timeline record family does not match the declared graph route",
                    false,
                ));
            }
            if result.len() < maximum {
                result.push(revision);
            }
        }
        if result.is_empty() {
            return Err(graph_permission_denied());
        }
        Ok(result)
    }
}

fn graph_policy_allows(
    policy: &GraphAccess,
    principal: &contextdb_service::RequestContext,
) -> bool {
    graph_policy_allows_parts(
        &policy.workspace,
        &policy.scopes,
        &policy.owners,
        &policy.audience,
        &policy.audience_purpose_grants,
        &policy.purposes,
        policy.sensitivity,
        policy.consent,
        policy.retrievable,
        principal,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the helper shares one explicit normalized policy contract with durable records"
)]
fn graph_policy_allows_parts(
    workspace: &str,
    scopes: &BTreeSet<String>,
    owners: &BTreeSet<String>,
    audience: &BTreeSet<String>,
    audience_purpose_grants: &BTreeMap<String, BTreeSet<String>>,
    purposes: &BTreeSet<String>,
    sensitivity: GraphSensitivity,
    consent: GraphConsent,
    retrievable: bool,
    principal: &contextdb_service::RequestContext,
) -> bool {
    if workspace != principal.workspace_id
        || consent != GraphConsent::Granted
        || !retrievable
        || sensitivity > graph_sensitivity(principal.clearance)
    {
        return false;
    }
    let is_owner = owners.contains(&principal.subject_id);
    let has_scope =
        scopes.is_empty() || scopes.iter().any(|scope| principal.scopes.contains(scope));
    let has_audience = if audience_purpose_grants.is_empty() {
        ((audience.contains(&principal.subject_id) || audience.contains("*"))
            && (purposes.is_empty() || purposes.contains(&principal.purpose)))
            || is_owner && (purposes.is_empty() || purposes.contains(&principal.purpose))
    } else {
        std::iter::once(principal.subject_id.as_str())
            .chain(std::iter::once("*"))
            .chain(is_owner.then_some("@owner"))
            .chain(principal.audiences.iter().map(String::as_str))
            .any(|audience| {
                audience_purpose_grants
                    .get(audience)
                    .is_some_and(|purposes| purposes.contains(&principal.purpose))
            })
    };
    has_scope && has_audience
}

const fn graph_sensitivity(value: contextdb_service::Sensitivity) -> GraphSensitivity {
    match value {
        contextdb_service::Sensitivity::Public => GraphSensitivity::Public,
        contextdb_service::Sensitivity::Internal => GraphSensitivity::Internal,
        contextdb_service::Sensitivity::Private => GraphSensitivity::Private,
        contextdb_service::Sensitivity::Restricted => GraphSensitivity::Restricted,
    }
}

fn graph_not_found() -> ServiceError {
    ServiceError::new(ErrorCode::NotFound, "requested object was not found", false)
}

fn graph_permission_denied() -> ServiceError {
    ServiceError::new(
        ErrorCode::PermissionDenied,
        "operation is not authorized",
        false,
    )
}

fn graph_work_exhausted() -> ServiceError {
    ServiceError::new(
        ErrorCode::ResourceExhausted,
        "policy graph traversal exceeded its deterministic work budget",
        false,
    )
}

fn validate_graph_record_identifier(value: &str) -> ServiceResult<()> {
    if !bounded_identifier(value, 1_024) {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "request contains an invalid bounded graph identifier",
            false,
        ));
    }
    Ok(())
}

fn graph_kind(value: contextdb_service::MemoryRecordKind) -> GraphRecordKind {
    match value {
        contextdb_service::MemoryRecordKind::Node => GraphRecordKind::Node,
        contextdb_service::MemoryRecordKind::Claim => GraphRecordKind::Claim,
        contextdb_service::MemoryRecordKind::Edge => GraphRecordKind::Edge,
        contextdb_service::MemoryRecordKind::Conflict => GraphRecordKind::Conflict,
        contextdb_service::MemoryRecordKind::Evidence => GraphRecordKind::Evidence,
        contextdb_service::MemoryRecordKind::Candidate => GraphRecordKind::Candidate,
        contextdb_service::MemoryRecordKind::SemanticObject => GraphRecordKind::SemanticObject,
        contextdb_service::MemoryRecordKind::RuntimeState => GraphRecordKind::RuntimeState,
        contextdb_service::MemoryRecordKind::DomainExtension => GraphRecordKind::DomainExtension,
    }
}

fn graph_record_matches(revision: &GraphRevision, actual: &MemoryRecord) -> bool {
    let document = &actual.document;
    revision.id == document.id
        && revision.revision == actual.revision
        && revision.transaction_from == actual.transaction_from
        && revision.transaction_to == actual.transaction_to
        && revision.record.kind == graph_kind(document.kind)
        && revision.record.lifecycle
            == match document.lifecycle {
                contextdb_service::MemoryLifecycle::Active => GraphLifecycle::Active,
                contextdb_service::MemoryLifecycle::Superseded => GraphLifecycle::Superseded,
                contextdb_service::MemoryLifecycle::Retracted => GraphLifecycle::Retracted,
                contextdb_service::MemoryLifecycle::Suppressed => GraphLifecycle::Suppressed,
            }
        && revision.record.valid_time.from == document.valid_time.from
        && revision.record.valid_time.to == document.valid_time.to
        && revision.record.links.subject == document.links.subject
        && revision.record.links.source == document.links.source
        && revision.record.links.target == document.links.target
        && revision.record.links.predicate == document.links.predicate
        && revision.record.links.conflict_set == document.links.conflict_set
        && revision.record.links.supersedes == document.links.supersedes
        && revision.record.links.evidence == document.links.evidence
        && revision.record.links.conflict_members == document.links.conflict_members
        && revision.record.links.single_valued == document.links.single_valued
        && graph_access_matches(&revision.record.access, &document.access)
}

fn graph_access_matches(access: &GraphAccess, actual: &contextdb_service::AccessPolicy) -> bool {
    access.workspace == actual.workspace_id
        && access.scopes == actual.scopes
        && access.owners == actual.owners
        && access.audience == actual.audience
        && access.audience_purpose_grants == actual.audience_purpose_grants
        && access.purposes == actual.purposes
        && access.sensitivity == graph_sensitivity(actual.sensitivity)
        && access.consent
            == match actual.consent {
                contextdb_service::Consent::Granted => GraphConsent::Granted,
                contextdb_service::Consent::Unknown => GraphConsent::Unknown,
                contextdb_service::Consent::Denied => GraphConsent::Denied,
            }
        && access.retrievable == actual.retrievable
}

fn project_archive_metadata(archive: &[u8], generation: u64) -> CliResult<PolicyGraphProjection> {
    let source: GraphArchiveSource = serde_json::from_slice(archive).map_err(|_| {
        integrity("canonical archive cannot be decoded for policy graph projection")
    })?;
    if source.format != "contextdb.logical.v1"
        || !bounded_identifier(&source.database_id, 1_024)
        || usize::try_from(source.head).ok() != Some(source.journal.len())
        || source.histories.len() > MAX_GRAPH_RECORDS
    {
        return Err(
            integrity("canonical archive graph metadata exceeds the production contract").into(),
        );
    }

    let mut journal = Vec::with_capacity(source.journal.len());
    let mut latest_semantic = 0_u64;
    let mut previous_record_digest = None;
    for (offset, record) in source.journal.into_iter().enumerate() {
        let commit_seq = u64::try_from(offset)
            .map_err(|_| integrity("canonical archive journal exceeds this platform"))?
            .checked_add(1)
            .ok_or_else(|| integrity("canonical archive journal sequence is exhausted"))?;
        if record.commit_seq != commit_seq
            || record.previous_digest != previous_record_digest
            || record.previous_digest.as_ref().is_some_and(|digest| {
                validate_digest(digest, "archive journal predecessor").is_err()
            })
            || validate_digest(&record.record_digest, "archive journal record digest").is_err()
        {
            return Err(integrity("canonical archive journal metadata is not contiguous").into());
        }
        let (class, affected_ids) = match record.event {
            GraphJournalEventSource::ObservationAccepted {} => {
                (GraphJournalClass::ObservationAccepted, BTreeSet::new())
            }
            GraphJournalEventSource::SemanticPublished { affected_ids } => {
                if affected_ids.len() > MAX_GRAPH_POLICY_VALUES
                    || affected_ids.iter().any(|id| !bounded_identifier(id, 1_024))
                {
                    return Err(integrity(
                        "semantic journal affected-ID set exceeds the graph projection contract",
                    )
                    .into());
                }
                latest_semantic = commit_seq;
                (GraphJournalClass::SemanticPublished, affected_ids)
            }
        };
        journal.push(GraphJournalEntry {
            commit_seq,
            previous_digest: record.previous_digest,
            record_digest: record.record_digest.clone(),
            class,
            affected_ids,
        });
        previous_record_digest = Some(record.record_digest);
    }
    let expected_watermarks = GraphWatermarks {
        journal: source.head,
        semantic: latest_semantic,
        lexical: latest_semantic,
        vector: latest_semantic,
        graph: latest_semantic,
    };
    if source.watermarks != expected_watermarks {
        return Err(integrity(
            "canonical archive watermarks disagree with its exact journal classes",
        )
        .into());
    }

    let mut histories = BTreeMap::new();
    let mut revision_count = 0_usize;
    let mut edge_revision_count = 0_usize;
    for (id, history) in source.histories {
        if !bounded_identifier(&id, 1_024) || history.is_empty() {
            return Err(integrity("canonical archive contains an invalid graph identity").into());
        }
        revision_count = revision_count
            .checked_add(history.len())
            .filter(|count| *count <= MAX_GRAPH_REVISIONS)
            .ok_or_else(|| integrity("canonical archive graph revision limit was exceeded"))?;
        let mut projected = Vec::with_capacity(history.len());
        let mut previous_to = None;
        let mut stable_kind = None;
        for (offset, revision) in history.into_iter().enumerate() {
            let expected_revision = u32::try_from(offset)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| integrity("graph revision ordinal is exhausted"))?;
            let transaction_record = revision
                .transaction_from
                .checked_sub(1)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| journal.get(index));
            if revision.id != id
                || revision.revision != expected_revision
                || revision.transaction_from == 0
                || revision.transaction_from > source.head
                || offset > 0 && previous_to != Some(revision.transaction_from)
                || revision
                    .transaction_to
                    .is_some_and(|to| to <= revision.transaction_from || to > source.head)
                || transaction_record.is_none_or(|entry| {
                    entry.class != GraphJournalClass::SemanticPublished
                        || !entry.affected_ids.contains(&id)
                })
                || !valid_graph_record_metadata(&revision.record)
                || stable_kind.is_some_and(|kind| kind != revision.record.kind)
            {
                return Err(integrity(format!(
                    "canonical archive graph revision chain is invalid for {id}"
                ))
                .into());
            }
            stable_kind = Some(revision.record.kind);
            previous_to = revision.transaction_to;
            if revision.record.kind == GraphRecordKind::Edge {
                edge_revision_count = edge_revision_count
                    .checked_add(1)
                    .ok_or_else(|| integrity("graph edge revision count is exhausted"))?;
            }
            projected.push(GraphRevision {
                id: revision.id,
                revision: revision.revision,
                transaction_from: revision.transaction_from,
                transaction_to: revision.transaction_to,
                record: revision.record,
            });
        }
        histories.insert(id, projected);
    }

    let mut tombstones = BTreeMap::new();
    for (id, tombstone) in source.tombstones {
        let publication = tombstone
            .effective_seq
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| journal.get(index));
        if !bounded_identifier(&id, 1_024)
            || tombstone.target != id
            || publication.is_none_or(|entry| {
                entry.class != GraphJournalClass::SemanticPublished
                    || !entry.affected_ids.contains(&id)
            })
        {
            return Err(integrity("canonical archive tombstone graph binding is invalid").into());
        }
        tombstones.insert(
            id,
            GraphTombstone {
                target: tombstone.target,
                effective_seq: tombstone.effective_seq,
            },
        );
    }

    Ok(PolicyGraphProjection {
        schema_version: STORE_SCHEMA_VERSION,
        database_id: source.database_id,
        generation,
        archive_commit_seq: source.head,
        archive_digest: blake3::hash(archive).to_hex().to_string(),
        watermarks: expected_watermarks,
        record_count: u64::try_from(histories.len()).unwrap_or(u64::MAX),
        revision_count: u64::try_from(revision_count).unwrap_or(u64::MAX),
        edge_revision_count: u64::try_from(edge_revision_count).unwrap_or(u64::MAX),
        histories,
        tombstones,
        journal,
        digest: String::new(),
        checksum: String::new(),
    })
}

fn valid_graph_record_metadata(record: &GraphRecordMetadata) -> bool {
    let access = &record.access;
    let links = &record.links;
    bounded_identifier(&access.workspace, 1_024)
        && !access.owners.is_empty()
        && valid_graph_set(&access.scopes)
        && valid_graph_set(&access.owners)
        && valid_graph_set(&access.audience)
        && valid_graph_set(&access.purposes)
        && access.audience_purpose_grants.len() <= MAX_GRAPH_POLICY_VALUES
        && access
            .audience_purpose_grants
            .iter()
            .all(|(audience, purposes)| {
                bounded_identifier(audience, 1_024) && valid_graph_set(purposes)
            })
        && valid_graph_optional_id(&links.subject)
        && valid_graph_optional_id(&links.source)
        && valid_graph_optional_id(&links.target)
        && valid_graph_optional_id(&links.predicate)
        && valid_graph_optional_id(&links.conflict_set)
        && valid_graph_set(&links.supersedes)
        && valid_graph_set(&links.evidence)
        && valid_graph_set(&links.conflict_members)
        && match (record.valid_time.from, record.valid_time.to) {
            (Some(from), Some(to)) => from < to,
            _ => true,
        }
}

fn valid_graph_optional_id(value: &Option<String>) -> bool {
    value
        .as_ref()
        .is_none_or(|value| bounded_identifier(value, 1_024))
}

fn valid_graph_set(values: &BTreeSet<String>) -> bool {
    values.len() <= MAX_GRAPH_POLICY_VALUES
        && values.iter().all(|value| bounded_identifier(value, 1_024))
}

fn policy_graph_digest(graph: &PolicyGraphProjection) -> CliResult<String> {
    let mut unsigned = graph.clone();
    unsigned.digest.clear();
    unsigned.checksum.clear();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb/production-policy-graph/v1");
    hasher.update(&[0]);
    hasher.update(&canonical_bytes(&unsigned)?);
    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_header(key: &[u8; 32], header: &StoreHeader) -> CliResult<()> {
    if header.schema_version != STORE_SCHEMA_VERSION
        || blake3::Hash::from_hex(&header.initial_archive_digest).is_err()
        || header.checksum != record_checksum(key, b"production-header-v1", header)?
    {
        return Err(integrity("production store header failed integrity validation").into());
    }
    Ok(())
}

fn validate_projection(key: &[u8; 32], projection: &CurrentProjection) -> CliResult<()> {
    if projection.schema_version != STORE_SCHEMA_VERSION
        || projection.archive_digest != blake3::hash(&projection.archive).to_hex().to_string()
        || projection.checksum != record_checksum(key, b"production-projection-v1", projection)?
    {
        return Err(integrity("production current projection failed integrity validation").into());
    }
    let identity = super::state_head::inspect_archive(&projection.archive)
        .map_err(|_| integrity("production current projection archive is invalid"))?;
    if identity.database_id != projection.database_id
        || identity.commit_seq != projection.commit_seq
        || identity.archive_digest != projection.archive_digest
    {
        return Err(integrity("production current projection identity is inconsistent").into());
    }
    Ok(())
}

fn validate_event(
    key: &[u8; 32],
    event: &StoredEvent,
    expected_sequence: u64,
    expected_previous_checksum: Option<&str>,
) -> CliResult<()> {
    if event.schema_version != STORE_SCHEMA_VERSION
        || event.sequence != expected_sequence
        || event.previous_event_checksum.as_deref() != expected_previous_checksum
        || blake3::Hash::from_hex(&event.idempotency_digest).is_err()
        || blake3::Hash::from_hex(&event.request_digest).is_err()
        || event.response_digest != keyed_digest(key, b"response", &event.response_bytes)
        || blake3::Hash::from_hex(&event.projection_digest).is_err()
        || event.checksum != record_checksum(key, b"production-event-v1", event)?
    {
        return Err(integrity("production event failed integrity validation").into());
    }
    Ok(())
}

fn validate_index(key: &[u8; 32], index: &IdempotencyIndex, event: &StoredEvent) -> CliResult<()> {
    if index.schema_version != STORE_SCHEMA_VERSION
        || index.sequence != event.sequence
        || index.request_digest != event.request_digest
        || index.checksum != record_checksum(key, b"production-idempotency-v1", index)?
    {
        return Err(integrity("production idempotency index failed integrity validation").into());
    }
    Ok(())
}

fn record_checksum<T>(key: &[u8; 32], domain: &[u8], value: &T) -> CliResult<String>
where
    T: Clone + Serialize + ChecksumField,
{
    let mut unsigned = value.clone();
    unsigned.clear_checksum();
    Ok(keyed_digest(key, domain, &canonical_bytes(&unsigned)?))
}

trait ChecksumField {
    fn clear_checksum(&mut self);
}

impl ChecksumField for StoreHeader {
    fn clear_checksum(&mut self) {
        self.checksum.clear();
    }
}

impl ChecksumField for CurrentProjection {
    fn clear_checksum(&mut self) {
        self.checksum.clear();
    }
}

impl ChecksumField for PolicyGraphProjection {
    fn clear_checksum(&mut self) {
        self.checksum.clear();
    }
}

impl ChecksumField for StoredEvent {
    fn clear_checksum(&mut self) {
        self.checksum.clear();
    }
}

impl ChecksumField for IdempotencyIndex {
    fn clear_checksum(&mut self) {
        self.checksum.clear();
    }
}

impl ChecksumField for DurableLedgerHead {
    fn clear_checksum(&mut self) {
        self.checksum.clear();
    }
}

fn validate_stored_stream_frame(
    frame: &StoredStreamFrame,
    stream_digest: &str,
    state: &StoredStreamState,
    expected_position: u64,
    store: &ProductionStore,
) -> CliResult<()> {
    if frame.schema_version != STREAM_SCHEMA_VERSION
        || frame.stream_id != state.stream_id
        || frame.position != expected_position
        || store.stream_digest(&state.workspace_id, &frame.stream_id)? != stream_digest
        || !bounded_identifier(&frame.stream_id, 1_024)
        || frame
            .resume_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 8_192)
    {
        return Err(integrity("production stream frame binding is invalid").into());
    }
    match (&frame.value, frame.position) {
        (IngestFrameValue::Manifest(manifest), 0) => {
            if manifest.expected_items > MAX_STREAM_ITEMS
                || manifest.compression != Compression::Identity
            {
                return Err(integrity("production stream manifest exceeds its profile").into());
            }
        }
        (IngestFrameValue::Observation(_), position) if position > 0 => {}
        (IngestFrameValue::SnapshotComplete(_), _) => {
            return Err(integrity("completed frames must not remain in stream staging").into());
        }
        (IngestFrameValue::Manifest(_), _) | (IngestFrameValue::Observation(_), _) => {
            return Err(integrity("production stream frame kind is out of order").into());
        }
    }
    Ok(())
}

fn validate_loaded_stream(
    state: &StoredStreamState,
    frames: &BTreeMap<u64, StoredStreamFrame>,
    receipts: &BTreeMap<u64, StoredStreamReceipt>,
    store: &ProductionStore,
) -> CliResult<()> {
    let manifest = match &frames
        .get(&0)
        .ok_or_else(|| integrity("production stream manifest frame is missing"))?
        .value
    {
        IngestFrameValue::Manifest(manifest) => manifest,
        IngestFrameValue::Observation(_) | IngestFrameValue::SnapshotComplete(_) => {
            return Err(integrity("production stream position zero is not a manifest").into());
        }
    };
    if state.next_position > manifest.expected_items.saturating_add(1) {
        return Err(integrity("production stream exceeds its declared item count").into());
    }
    let legacy_pre_lease = state.lease_expires_at_ms == 0;
    let mut previous_deadline = 0_u64;
    for position in 0..state.next_position {
        let frame = frames
            .get(&position)
            .ok_or_else(|| integrity("production stream frame sequence is not contiguous"))?;
        let receipt = receipts
            .get(&position)
            .ok_or_else(|| integrity("production stream receipt sequence is not contiguous"))?;
        if position == 0 {
            if frame.resume_cursor.is_some() {
                return Err(integrity("production stream manifest has a resume cursor").into());
            }
        } else {
            let previous = receipts
                .get(&position.saturating_sub(1))
                .ok_or_else(|| integrity("production stream preceding receipt is missing"))?;
            if frame.resume_cursor.as_deref()
                != Some(previous.acknowledgement.resume_cursor.as_str())
            {
                return Err(integrity("production stream cursor chain changed").into());
            }
        }
        let expected_frame_digest = canonical_value_digest(&frame.value)?;
        let expected_request_digest =
            stream_request_digest(store, &state.authorization_digest, frame)
                .map_err(CliError::from)?;
        let deadline = receipt.acknowledgement.lease_expires_at_ms.unwrap_or(0);
        if receipt.schema_version != STREAM_SCHEMA_VERSION
            || receipt.position != position
            || receipt.request_digest != expected_request_digest
            || receipt.acknowledgement.stream_id != state.stream_id
            || receipt.acknowledgement.position != position
            || receipt.acknowledgement.disposition != IngestDisposition::Accepted
            || receipt.acknowledgement.frame_digest != expected_frame_digest
            || receipt.acknowledgement.resume_cursor.is_empty()
            || receipt.acknowledgement.resume_cursor.len() > 8_192
            || receipt.acknowledgement.commit_seq.is_some()
            || !receipt.acknowledgement.partial_result_refs.is_empty()
            || if legacy_pre_lease {
                receipt.acknowledgement.lease_expires_at_ms.is_some()
            } else {
                deadline == 0
                    || deadline < previous_deadline
                    || deadline > state.lease_expires_at_ms
                    || position == state.next_position.saturating_sub(1)
                        && deadline != state.lease_expires_at_ms
            }
        {
            return Err(integrity("production stream receipt failed validation").into());
        }
        previous_deadline = deadline;
    }
    Ok(())
}

fn stream_request_digest(
    store: &ProductionStore,
    authorization_digest: &str,
    frame: &StoredStreamFrame,
) -> ServiceResult<String> {
    validate_digest(authorization_digest, "stream authorization digest")
        .map_err(|error| error.0)?;
    let material = Zeroizing::new(
        canonical_bytes(&(STREAM_SCHEMA_VERSION, authorization_digest, frame))
            .map_err(|error| error.0)?,
    );
    Ok(store.digest(b"stream_frame_request", &material))
}

fn canonical_value_digest(value: &IngestFrameValue) -> CliResult<String> {
    let bytes = Zeroizing::new(canonical_bytes(value)?);
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn validate_expected_stream_cursor(
    frame: &StoredStreamFrame,
    receipts: &BTreeMap<u64, StoredStreamReceipt>,
) -> ServiceResult<()> {
    if frame.position == 0 {
        return Err(ServiceError::new(
            ErrorCode::InvalidContinuation,
            "only a manifest may occupy stream position zero",
            false,
        ));
    }
    let previous = receipts
        .get(&frame.position.saturating_sub(1))
        .ok_or_else(|| {
            ServiceError::new(
                ErrorCode::InvalidContinuation,
                "stream cursor does not follow a durable acknowledgement",
                false,
            )
        })?;
    if frame.resume_cursor.as_deref() != Some(previous.acknowledgement.resume_cursor.as_str()) {
        return Err(ServiceError::new(
            ErrorCode::InvalidContinuation,
            "stream cursor is forged, stale, or bound to another position",
            false,
        ));
    }
    Ok(())
}

fn stream_state_key(stream_digest: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        STREAM_STATE_PREFIX
            .len()
            .saturating_add(stream_digest.len()),
    );
    key.extend_from_slice(STREAM_STATE_PREFIX);
    key.extend_from_slice(stream_digest.as_bytes());
    key
}

fn stream_expired_key(stream_digest: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        STREAM_EXPIRED_PREFIX
            .len()
            .saturating_add(stream_digest.len()),
    );
    key.extend_from_slice(STREAM_EXPIRED_PREFIX);
    key.extend_from_slice(stream_digest.as_bytes());
    key
}

fn stream_position_prefix(prefix: &[u8], stream_digest: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        prefix
            .len()
            .saturating_add(stream_digest.len())
            .saturating_add(1),
    );
    key.extend_from_slice(prefix);
    key.extend_from_slice(stream_digest.as_bytes());
    key.push(b'/');
    key
}

fn stream_position_key(prefix: &[u8], stream_digest: &str, position: u64) -> Vec<u8> {
    let mut key = stream_position_prefix(prefix, stream_digest);
    key.extend_from_slice(&position.to_be_bytes());
    key
}

fn stream_nonce_key(nonce: &[u8; STREAM_NONCE_BYTES]) -> Vec<u8> {
    let mut key = Vec::with_capacity(STREAM_NONCE_PREFIX.len().saturating_add(nonce.len()));
    key.extend_from_slice(STREAM_NONCE_PREFIX);
    key.extend_from_slice(nonce);
    key
}

fn parse_stream_nonce_key(key: &[u8]) -> CliResult<[u8; STREAM_NONCE_BYTES]> {
    if key.len() != STREAM_NONCE_PREFIX.len().saturating_add(STREAM_NONCE_BYTES)
        || !key.starts_with(STREAM_NONCE_PREFIX)
    {
        return Err(integrity("production stream nonce key is malformed").into());
    }
    key[STREAM_NONCE_PREFIX.len()..]
        .try_into()
        .map_err(|_| integrity("production stream nonce key is malformed").into())
}

fn parse_stream_state_key(key: &[u8]) -> CliResult<String> {
    if key.len() != STREAM_STATE_PREFIX.len().saturating_add(64)
        || !key.starts_with(STREAM_STATE_PREFIX)
    {
        return Err(integrity("production stream state key is malformed").into());
    }
    let digest = std::str::from_utf8(&key[STREAM_STATE_PREFIX.len()..])
        .map_err(|_| integrity("production stream state key is not UTF-8"))?
        .to_owned();
    validate_digest(&digest, "production stream state key")?;
    Ok(digest)
}

fn parse_stream_expired_key(key: &[u8]) -> CliResult<String> {
    if key.len() != STREAM_EXPIRED_PREFIX.len().saturating_add(64)
        || !key.starts_with(STREAM_EXPIRED_PREFIX)
    {
        return Err(integrity("production expired stream key is malformed").into());
    }
    let digest = std::str::from_utf8(&key[STREAM_EXPIRED_PREFIX.len()..])
        .map_err(|_| integrity("production expired stream key is not UTF-8"))?
        .to_owned();
    validate_digest(&digest, "production expired stream key")?;
    Ok(digest)
}

fn parse_stream_position_key(key: &[u8], prefix: &[u8], stream_digest: &str) -> CliResult<u64> {
    let expected_prefix = stream_position_prefix(prefix, stream_digest);
    if key.len() != expected_prefix.len().saturating_add(8) || !key.starts_with(&expected_prefix) {
        return Err(integrity("production stream position key is malformed").into());
    }
    let position: [u8; 8] = key[expected_prefix.len()..]
        .try_into()
        .map_err(|_| integrity("production stream position key is malformed"))?;
    Ok(u64::from_be_bytes(position))
}

fn stream_associated_data(database_id: &str, kind: &[u8], record_key: &[u8]) -> CliResult<Vec<u8>> {
    let mut associated_data = b"contextdb/production-stream-record/v1".to_vec();
    push_length_framed(&mut associated_data, database_id.as_bytes())?;
    push_length_framed(&mut associated_data, kind)?;
    push_length_framed(&mut associated_data, record_key)?;
    Ok(associated_data)
}

fn push_length_framed(target: &mut Vec<u8>, value: &[u8]) -> CliResult<()> {
    let length = u64::try_from(value.len())
        .map_err(|_| integrity("production stream associated data exceeds this platform"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn envelope_nonce(envelope: &[u8]) -> CliResult<[u8; STREAM_NONCE_BYTES]> {
    let nonce_start = STREAM_RECORD_MAGIC.len().saturating_add(2);
    let nonce_end = nonce_start.saturating_add(STREAM_NONCE_BYTES);
    if envelope.len() <= nonce_end.saturating_add(STREAM_TAG_BYTES)
        || envelope.get(..STREAM_RECORD_MAGIC.len()) != Some(STREAM_RECORD_MAGIC)
    {
        return Err(integrity("production encrypted stream envelope is malformed").into());
    }
    envelope[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| integrity("production stream envelope nonce is malformed").into())
}

fn insert_envelope_nonce(
    nonces: &mut BTreeSet<[u8; STREAM_NONCE_BYTES]>,
    envelope: &[u8],
) -> CliResult<()> {
    if !nonces.insert(envelope_nonce(envelope)?) {
        return Err(integrity("production stream AEAD nonce was reused").into());
    }
    Ok(())
}

fn reject_duplicate_envelope_nonces<const N: usize>(envelopes: [&[u8]; N]) -> CliResult<()> {
    let mut nonces = BTreeSet::new();
    for envelope in envelopes {
        insert_envelope_nonce(&mut nonces, envelope)?;
    }
    Ok(())
}

fn validate_digest(value: &str, label: &'static str) -> CliResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(integrity(format!("{label} is not canonical lowercase hexadecimal")).into());
    }
    Ok(())
}

fn is_canonical_digest_bytes(value: &[u8]) -> bool {
    value.len() == 64
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn decode_u64_exact(bytes: &[u8], label: &'static str) -> CliResult<u64> {
    let value: [u8; 8] = bytes
        .try_into()
        .map_err(|_| integrity(format!("{label} is malformed")))?;
    Ok(u64::from_be_bytes(value))
}

fn decode_non_event_receipt_count(bytes: &[u8]) -> CliResult<u64> {
    let count = decode_u64_exact(bytes, "production non-event receipt count")?;
    if count > u64::try_from(MAX_NON_EVENT_RECEIPTS).unwrap_or(u64::MAX) {
        return Err(integrity("production non-event receipt count exceeds its bound").into());
    }
    Ok(count)
}

fn parse_exact_sequence_key(key: &[u8], prefix: &[u8], label: &'static str) -> CliResult<u64> {
    if key.len() != prefix.len().saturating_add(8) || !key.starts_with(prefix) {
        return Err(integrity(format!("{label} key is malformed")).into());
    }
    decode_u64_exact(&key[prefix.len()..], label)
}

fn classify_stream_key(key: &[u8]) -> CliResult<()> {
    if key.starts_with(STREAM_STATE_PREFIX) {
        parse_stream_state_key(key)?;
        return Ok(());
    }
    if key.starts_with(STREAM_EXPIRED_PREFIX) {
        parse_stream_expired_key(key)?;
        return Ok(());
    }
    if key.starts_with(STREAM_NONCE_PREFIX) {
        parse_stream_nonce_key(key)?;
        return Ok(());
    }
    for prefix in [STREAM_FRAME_PREFIX, STREAM_RECEIPT_PREFIX] {
        let expected_len = prefix
            .len()
            .saturating_add(64)
            .saturating_add(1)
            .saturating_add(8);
        if key.starts_with(prefix) {
            if key.len() != expected_len
                || !is_canonical_digest_bytes(&key[prefix.len()..prefix.len() + 64])
                || key[prefix.len() + 64] != b'/'
            {
                return Err(integrity("production stream position key is malformed").into());
            }
            decode_u64_exact(&key[key.len() - 8..], "production stream position")?;
            return Ok(());
        }
    }
    Err(integrity("production stream keyspace contains an unknown namespace").into())
}

fn runtime_postflight_key(identity_digest: &str) -> CliResult<Vec<u8>> {
    validate_digest(
        identity_digest,
        "runtime postflight keyed operation identity",
    )?;
    let mut key = Vec::with_capacity(RUNTIME_POSTFLIGHT_PREFIX.len().saturating_add(64));
    key.extend_from_slice(RUNTIME_POSTFLIGHT_PREFIX);
    key.extend_from_slice(identity_digest.as_bytes());
    Ok(key)
}

fn validate_runtime_postflight_key(key: &[u8]) -> CliResult<()> {
    let Some(digest) = key.strip_prefix(RUNTIME_POSTFLIGHT_PREFIX) else {
        return Err(integrity("production runtime postflight key has another namespace").into());
    };
    if digest.len() != 64
        || !digest
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(integrity("production runtime postflight key is malformed").into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeLedgerKeyKind {
    State,
    Head,
    CheckpointHead,
    Receipt,
    GcAnchor,
}

fn runtime_state_key(identity_digest: &str, version: u64) -> CliResult<Vec<u8>> {
    validate_digest(identity_digest, "runtime state identity")?;
    if version == 0 {
        return Err(integrity("runtime state version must be positive").into());
    }
    let mut key = RUNTIME_STATE_PREFIX.to_vec();
    key.extend_from_slice(identity_digest.as_bytes());
    key.push(b'/');
    key.extend_from_slice(&version.to_be_bytes());
    Ok(key)
}

fn parse_runtime_state_key(key: &[u8]) -> CliResult<(String, u64)> {
    let suffix = key
        .strip_prefix(RUNTIME_STATE_PREFIX)
        .ok_or_else(|| integrity("production runtime state key has another namespace"))?;
    if suffix.len() != 64 + 1 + 8 || suffix[64] != b'/' || !is_canonical_digest_bytes(&suffix[..64])
    {
        return Err(integrity("production runtime state key is malformed").into());
    }
    let version = u64::from_be_bytes(
        suffix[65..]
            .try_into()
            .map_err(|_| integrity("production runtime state version is malformed"))?,
    );
    if version == 0 {
        return Err(integrity("production runtime state version is zero").into());
    }
    let identity = std::str::from_utf8(&suffix[..64])
        .map_err(|_| integrity("production runtime state identity is invalid"))?
        .to_owned();
    Ok((identity, version))
}

fn runtime_head_key(identity_digest: &str) -> CliResult<Vec<u8>> {
    validate_digest(identity_digest, "runtime state identity")?;
    let mut key = RUNTIME_HEAD_PREFIX.to_vec();
    key.extend_from_slice(identity_digest.as_bytes());
    Ok(key)
}

fn parse_runtime_head_key(key: &[u8]) -> CliResult<String> {
    let suffix = key
        .strip_prefix(RUNTIME_HEAD_PREFIX)
        .ok_or_else(|| integrity("production runtime head key has another namespace"))?;
    if !is_canonical_digest_bytes(suffix) {
        return Err(integrity("production runtime head key is malformed").into());
    }
    std::str::from_utf8(suffix)
        .map(str::to_owned)
        .map_err(|_| integrity("production runtime head identity is invalid").into())
}

fn runtime_checkpoint_head_key(checkpoint_digest: &str) -> CliResult<Vec<u8>> {
    validate_digest(checkpoint_digest, "runtime checkpoint digest")?;
    let mut key = RUNTIME_CHECKPOINT_HEAD_PREFIX.to_vec();
    key.extend_from_slice(checkpoint_digest.as_bytes());
    Ok(key)
}

fn parse_runtime_checkpoint_head_key(key: &[u8]) -> CliResult<String> {
    let suffix = key
        .strip_prefix(RUNTIME_CHECKPOINT_HEAD_PREFIX)
        .ok_or_else(|| integrity("production checkpoint head key has another namespace"))?;
    if !is_canonical_digest_bytes(suffix) {
        return Err(integrity("production checkpoint head key is malformed").into());
    }
    std::str::from_utf8(suffix)
        .map(str::to_owned)
        .map_err(|_| integrity("production checkpoint head digest is invalid").into())
}

fn runtime_lifecycle_receipt_key(
    method: RuntimeLifecycleMethod,
    identity_digest: &str,
) -> CliResult<Vec<u8>> {
    validate_digest(identity_digest, "runtime lifecycle identity")?;
    let mut key = RUNTIME_LIFECYCLE_RECEIPT_PREFIX.to_vec();
    key.extend_from_slice(method.key_name());
    key.push(b'/');
    key.extend_from_slice(identity_digest.as_bytes());
    Ok(key)
}

fn parse_runtime_lifecycle_receipt_key(key: &[u8]) -> CliResult<RuntimeLifecycleMethod> {
    let suffix = key
        .strip_prefix(RUNTIME_LIFECYCLE_RECEIPT_PREFIX)
        .ok_or_else(|| integrity("production runtime receipt key has another namespace"))?;
    for method in [
        RuntimeLifecycleMethod::Bootstrap,
        RuntimeLifecycleMethod::Checkpoint,
        RuntimeLifecycleMethod::Resume,
        RuntimeLifecycleMethod::Handoff,
    ] {
        let name = method.key_name();
        if suffix.len() == name.len() + 1 + 64
            && suffix.starts_with(name)
            && suffix[name.len()] == b'/'
            && is_canonical_digest_bytes(&suffix[name.len() + 1..])
        {
            return Ok(method);
        }
    }
    Err(integrity("production runtime receipt key is malformed").into())
}

fn runtime_gc_anchor_key(identity_digest: &str) -> CliResult<Vec<u8>> {
    validate_digest(identity_digest, "runtime GC identity")?;
    let mut key = RUNTIME_GC_ANCHOR_PREFIX.to_vec();
    key.extend_from_slice(identity_digest.as_bytes());
    Ok(key)
}

fn parse_runtime_gc_anchor_key(key: &[u8]) -> CliResult<String> {
    let suffix = key
        .strip_prefix(RUNTIME_GC_ANCHOR_PREFIX)
        .ok_or_else(|| integrity("production runtime GC anchor has another namespace"))?;
    if !is_canonical_digest_bytes(suffix) {
        return Err(integrity("production runtime GC anchor key is malformed").into());
    }
    std::str::from_utf8(suffix)
        .map(str::to_owned)
        .map_err(|_| integrity("production runtime GC anchor identity is invalid").into())
}

fn classify_runtime_ledger_key(key: &[u8]) -> CliResult<RuntimeLedgerKeyKind> {
    if key.starts_with(RUNTIME_STATE_PREFIX) {
        parse_runtime_state_key(key)?;
        Ok(RuntimeLedgerKeyKind::State)
    } else if key.starts_with(RUNTIME_HEAD_PREFIX) {
        parse_runtime_head_key(key)?;
        Ok(RuntimeLedgerKeyKind::Head)
    } else if key.starts_with(RUNTIME_CHECKPOINT_HEAD_PREFIX) {
        parse_runtime_checkpoint_head_key(key)?;
        Ok(RuntimeLedgerKeyKind::CheckpointHead)
    } else if key.starts_with(RUNTIME_LIFECYCLE_RECEIPT_PREFIX) {
        parse_runtime_lifecycle_receipt_key(key)?;
        Ok(RuntimeLedgerKeyKind::Receipt)
    } else if key.starts_with(RUNTIME_GC_ANCHOR_PREFIX) {
        parse_runtime_gc_anchor_key(key)?;
        Ok(RuntimeLedgerKeyKind::GcAnchor)
    } else {
        Err(integrity("production runtime keyspace contains an unknown namespace").into())
    }
}

fn continuity_value_digest<T: Serialize>(value: &T) -> CliResult<String> {
    Ok(blake3::hash(&canonical_bytes(value)?).to_hex().to_string())
}

fn map_continuity_service_error(error: ContinuityError) -> ServiceError {
    match error {
        ContinuityError::PolicyDenied(_) => ServiceError::new(
            ErrorCode::PermissionDenied,
            "runtime continuity policy denied the operation",
            false,
        ),
        ContinuityError::IncompatibleRuntime(_) => ServiceError::new(
            ErrorCode::ProviderUnavailable,
            "target runtime is incompatible with the continuity contract",
            false,
        ),
        ContinuityError::InvalidTransition(_) => ServiceError::new(
            ErrorCode::InvalidContinuation,
            "runtime lifecycle transition is invalid",
            false,
        ),
        ContinuityError::InvalidInput(_)
        | ContinuityError::IdentityMismatch(_)
        | ContinuityError::Serialization(_)
        | ContinuityError::Dependency(_) => ServiceError::new(
            ErrorCode::InvalidArgument,
            "runtime continuity artifact is invalid",
            false,
        ),
    }
}

fn runtime_artifact_checkpoint_digest(artifact: &RuntimeLifecycleArtifactV1) -> String {
    match artifact {
        RuntimeLifecycleArtifactV1::Checkpoint { checkpoint } => checkpoint.digest.to_string(),
        RuntimeLifecycleArtifactV1::CheckpointRevoked {
            checkpoint_digest, ..
        } => checkpoint_digest.clone(),
        RuntimeLifecycleArtifactV1::Bootstrap { result }
        | RuntimeLifecycleArtifactV1::Resume { result } => result.checkpoint_digest.clone(),
        RuntimeLifecycleArtifactV1::Handoff { result } => {
            result.manifest.checkpoint_digest.to_string()
        }
    }
}

fn validate_runtime_compiled_context(compiled: &RuntimeCompiledContextV1) -> CliResult<()> {
    compiled
        .pack
        .validate()
        .map_err(|_| integrity("stored runtime ContextPack is invalid"))?;
    let digest = CanonicalSerializer::digest(&compiled.pack)
        .map_err(|_| integrity("stored runtime ContextPack digest failed"))?;
    if compiled.canonical_digest != digest
        || compiled.rendered.profile_id != compiled.pack.compilation.model_profile
        || compiled.rendered.renderer != compiled.pack.compilation.renderer
        || compiled.rendered.control_tokens != compiled.pack.compilation.usage.control_tokens
        || compiled.rendered.data_tokens != compiled.pack.compilation.usage.data_tokens
        || compiled.rendered.total_tokens != compiled.pack.compilation.usage.rendered_tokens
    {
        return Err(integrity("stored runtime compiled context is inconsistent").into());
    }
    Ok(())
}

fn validate_runtime_lifecycle_response_bytes(bytes: &[u8]) -> CliResult<RuntimeResponse> {
    if bytes.is_empty() || bytes.len() > MAX_RUNTIME_LIFECYCLE_RESPONSE_BYTES {
        return Err(integrity("stored runtime lifecycle response is out of bounds").into());
    }
    let response: RuntimeResponse = serde_json::from_slice(bytes)
        .map_err(|_| integrity("stored runtime lifecycle response is invalid"))?;
    if canonical_bytes(&response)? != bytes {
        return Err(integrity("stored runtime lifecycle response is not canonical").into());
    }
    let payload: RuntimeLifecyclePayloadV1 = serde_json::from_value(response.payload.clone())
        .map_err(|_| integrity("stored runtime lifecycle payload is invalid"))?;
    if serde_json::to_value(&payload)
        .map_err(|_| integrity("stored runtime lifecycle payload serialization failed"))?
        != response.payload
        || payload.schema_version != STORE_SCHEMA_VERSION
        || validate_digest(&payload.receipt_id, "runtime lifecycle receipt ID").is_err()
        || validate_digest(
            &payload.state.checkpoint_digest,
            "runtime response checkpoint digest",
        )
        .is_err()
        || payload.state.version == 0
        || payload.state.checkpoint_digest != runtime_artifact_checkpoint_digest(&payload.artifact)
    {
        return Err(integrity("stored runtime lifecycle payload failed validation").into());
    }
    match (&payload.method, &payload.artifact) {
        (
            RuntimeLifecycleMethod::Checkpoint,
            RuntimeLifecycleArtifactV1::Checkpoint { checkpoint },
        ) => checkpoint
            .validate()
            .map_err(map_continuity_service_error)
            .map_err(CliError::from)?,
        (
            RuntimeLifecycleMethod::Checkpoint,
            RuntimeLifecycleArtifactV1::CheckpointRevoked {
                checkpoint_digest, ..
            },
        ) => validate_digest(checkpoint_digest, "revoked runtime checkpoint")?,
        (RuntimeLifecycleMethod::Bootstrap, RuntimeLifecycleArtifactV1::Bootstrap { result })
        | (RuntimeLifecycleMethod::Resume, RuntimeLifecycleArtifactV1::Resume { result }) => {
            if !result.open_loops_preserved
                || !result.required_memory_refs_preserved
                || validate_digest(&result.checkpoint_digest, "runtime bootstrap checkpoint")
                    .is_err()
                || validate_digest(&result.compatibility_digest, "runtime compatibility").is_err()
                || validate_digest(&result.target_runtime_digest, "runtime target").is_err()
                || validate_digest(&result.trace_digest, "runtime bootstrap trace").is_err()
            {
                return Err(integrity("stored runtime bootstrap artifact is invalid").into());
            }
            validate_runtime_compiled_context(&result.compiled)?;
        }
        (RuntimeLifecycleMethod::Handoff, RuntimeLifecycleArtifactV1::Handoff { result }) => {
            result
                .manifest
                .validate()
                .map_err(map_continuity_service_error)
                .map_err(CliError::from)?;
            if !result.open_loops_preserved
                || result.manifest.pack_digest != result.compiled.canonical_digest
            {
                return Err(integrity("stored runtime handoff artifact is invalid").into());
            }
            validate_runtime_compiled_context(&result.compiled)?;
        }
        _ => {
            return Err(integrity("runtime lifecycle method/artifact kind differs").into());
        }
    }
    Ok(response)
}

fn parse_runtime_lifecycle_payload<T>(
    request: &RuntimeRequest,
) -> ServiceResult<(T, Zeroizing<Vec<u8>>)>
where
    T: DeserializeOwned + Serialize,
{
    if !bounded_identifier(&request.operation_id, 1_024) {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "runtime operation ID is not a valid bounded identifier",
            false,
        ));
    }
    let payload_bytes = Zeroizing::new(
        serde_json::to_vec(&request.payload).map_err(|_| invalid_runtime_lifecycle_format())?,
    );
    if payload_bytes.len() > MAX_RUNTIME_LIFECYCLE_PAYLOAD_BYTES {
        return Err(resource_exhausted(
            "runtime lifecycle payload exceeds the 1 MiB canonical limit",
            false,
        ));
    }
    validate_runtime_lifecycle_json_depth(&request.payload)?;
    let typed: T =
        serde_json::from_slice(&payload_bytes).map_err(|_| invalid_runtime_lifecycle_format())?;
    let typed_value =
        serde_json::to_value(&typed).map_err(|_| invalid_runtime_lifecycle_format())?;
    if typed_value != request.payload {
        return Err(invalid_runtime_lifecycle_format());
    }
    serde_json::to_vec(&typed)
        .map(|bytes| (typed, Zeroizing::new(bytes)))
        .map_err(|_| integrity("runtime lifecycle canonical serialization failed"))
}

fn validate_runtime_lifecycle_json_depth(root: &serde_json::Value) -> ServiceResult<()> {
    let mut pending = vec![(root, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_RUNTIME_LIFECYCLE_JSON_DEPTH {
            return Err(resource_exhausted(
                "runtime lifecycle payload exceeds the JSON depth limit",
                false,
            ));
        }
        match value {
            serde_json::Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth.saturating_add(1))));
            }
            serde_json::Value::Object(values) => {
                pending.extend(
                    values
                        .values()
                        .map(|value| (value, depth.saturating_add(1))),
                );
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }
    Ok(())
}

fn invalid_runtime_lifecycle_format() -> ServiceError {
    ServiceError::new(
        ErrorCode::FormatIncompatible,
        "runtime payload does not match the exact lifecycle v1 schema",
        false,
    )
}

fn validate_runtime_provider_input(provider: &RuntimeProviderInputV1) -> ServiceResult<()> {
    if provider.candidates.len() > MAX_RUNTIME_PROVIDER_CANDIDATES
        || provider.evidence.len() > MAX_RUNTIME_PROVIDER_EVIDENCE
    {
        return Err(resource_exhausted(
            "runtime provider source set exceeds the lifecycle item limit",
            false,
        ));
    }
    Ok(())
}

fn bind_runtime_context(
    context: &contextdb_service::AuthenticatedRequestContext,
    checkpoint: &PortableCheckpoint,
) -> ServiceResult<()> {
    let required_scopes = checkpoint
        .policy
        .scopes
        .iter()
        .map(|scope| scope.id.to_string())
        .collect::<BTreeSet<_>>();
    if context.request.workspace_id != checkpoint.workspace_id.to_string()
        || context.request.subject_id != checkpoint.stable_subject.to_string()
        || context.agent_id != checkpoint.agent_id.to_string()
        || !required_scopes.is_subset(&context.request.scopes)
    {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "runtime checkpoint does not match the authenticated principal",
            false,
        ));
    }
    Ok(())
}

fn runtime_compiled_context(
    compiled: &contextdb_context::CompiledContext,
) -> RuntimeCompiledContextV1 {
    RuntimeCompiledContextV1 {
        pack: compiled.pack.clone(),
        rendered: RuntimeRenderedContextV1 {
            profile_id: compiled.rendered.profile_id.clone(),
            renderer: compiled.rendered.renderer,
            trusted_control: compiled.rendered.trusted_control.clone(),
            untrusted_data: compiled.rendered.untrusted_data.clone(),
            control_tokens: compiled.rendered.control_tokens,
            data_tokens: compiled.rendered.data_tokens,
            total_tokens: compiled.rendered.total_tokens,
        },
        canonical_digest: compiled.canonical_digest.clone(),
    }
}

fn runtime_bootstrap_artifact(
    result: &contextdb_continuity::BootstrapResult,
) -> RuntimeBootstrapArtifactV1 {
    RuntimeBootstrapArtifactV1 {
        migration_id: result.migration_id.to_string(),
        workspace_id: result.workspace_id.to_string(),
        agent_id: result.agent_id.to_string(),
        stable_subject: result.stable_subject.to_string(),
        source_profile: result.source_profile.to_string(),
        target_profile: result.target_profile.to_string(),
        checkpoint_digest: result.checkpoint_digest.to_string(),
        compatibility_digest: result.compatibility_digest.to_string(),
        target_runtime_digest: result.target_runtime_digest.to_string(),
        trace_digest: result.trace_digest.to_string(),
        open_loops_preserved: result.open_loops_preserved,
        required_memory_refs_preserved: result.required_memory_refs_preserved,
        compiled: runtime_compiled_context(&result.compiled),
    }
}

fn handoff_preserves_open_loops(checkpoint: &PortableCheckpoint, pack: &ContextPack) -> bool {
    let required = checkpoint
        .checkpoint
        .frame_snapshot
        .open_loops
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let represented = pack
        .sections
        .open_loops
        .iter()
        .flat_map(|block| &block.memory_refs)
        .filter_map(|memory| match memory {
            contextdb_core::MemoryRef::Node { id } => Some(*id),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    required.is_subset(&represented)
}

fn runtime_lifecycle_response(
    operation_id: String,
    method: RuntimeLifecycleMethod,
    receipt_id: String,
    state: &StoredRuntimeState,
    artifact: RuntimeLifecycleArtifactV1,
) -> ServiceResult<RuntimeResponse> {
    let payload = RuntimeLifecyclePayloadV1 {
        schema_version: STORE_SCHEMA_VERSION,
        method,
        receipt_id,
        state: RuntimeCheckpointStateSummaryV1 {
            checkpoint_digest: state.checkpoint.digest.to_string(),
            version: state.version,
            status: state.status,
        },
        artifact,
    };
    Ok(RuntimeResponse {
        operation_id,
        payload: serde_json::to_value(payload).map_err(|_| {
            ServiceError::new(
                ErrorCode::IntegrityFailure,
                "runtime lifecycle response serialization failed",
                false,
            )
        })?,
    })
}

fn reindex_receipt_key(identity_digest: &str) -> CliResult<Vec<u8>> {
    validate_digest(identity_digest, "reindex keyed operation identity")?;
    let mut key = Vec::with_capacity(REINDEX_RECEIPT_PREFIX.len().saturating_add(64));
    key.extend_from_slice(REINDEX_RECEIPT_PREFIX);
    key.extend_from_slice(identity_digest.as_bytes());
    Ok(key)
}

fn validate_reindex_receipt_key(key: &[u8]) -> CliResult<()> {
    let Some(digest) = key.strip_prefix(REINDEX_RECEIPT_PREFIX) else {
        return Err(integrity("production reindex key has another namespace").into());
    };
    if !is_canonical_digest_bytes(digest) {
        return Err(integrity("production reindex key is malformed").into());
    }
    Ok(())
}

fn runtime_gc_receipt_key(identity_digest: &str) -> CliResult<Vec<u8>> {
    validate_digest(identity_digest, "runtime GC operation identity")?;
    let mut key = Vec::with_capacity(RUNTIME_GC_RECEIPT_PREFIX.len().saturating_add(64));
    key.extend_from_slice(RUNTIME_GC_RECEIPT_PREFIX);
    key.extend_from_slice(identity_digest.as_bytes());
    Ok(key)
}

fn validate_runtime_gc_receipt_key(key: &[u8]) -> CliResult<()> {
    let Some(digest) = key.strip_prefix(RUNTIME_GC_RECEIPT_PREFIX) else {
        return Err(integrity("production runtime GC receipt has another namespace").into());
    };
    if !is_canonical_digest_bytes(digest) {
        return Err(integrity("production runtime GC receipt key is malformed").into());
    }
    Ok(())
}

fn bounded_identifier(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.contains('\0')
}

fn validate_stream_identifier(value: &str) -> ServiceResult<()> {
    if !bounded_identifier(value, 1_024) {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "stream ID is not a valid bounded identifier",
            false,
        ));
    }
    Ok(())
}

fn require_sync(durability: Durability) -> CliResult<()> {
    if durability != Durability::Sync {
        return Err(unavailable("Fjall did not achieve synchronized durability").into());
    }
    Ok(())
}

fn canonical_bytes<T: Serialize>(value: &T) -> CliResult<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|_| integrity("production canonical serialization failed").into())
}

fn keyed_digest(key: &[u8; 32], domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"contextdb/production-ledger/v1");
    hasher.update(&[0]);
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn event_key(sequence: u64) -> Vec<u8> {
    let mut key = EVENT_PREFIX.to_vec();
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

fn durable_history_key(generation: u64) -> Vec<u8> {
    let mut key = DURABLE_HISTORY_PREFIX.to_vec();
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

fn authenticated_namespace(
    context: &contextdb_service::AuthenticatedRequestContext,
    idempotency_key: &str,
) -> ServiceResult<Vec<u8>> {
    canonical_bytes(&(
        &context.request.workspace_id,
        &context.request.subject_id,
        &context.request.scopes,
        &context.request.purpose,
        &context.actor_id,
        &context.agent_id,
        &context.session_id,
        idempotency_key,
    ))
    .map_err(|error| error.0)
}

fn runtime_postflight_response(
    operation_id: String,
    receipt_id: String,
    replayed: bool,
) -> RuntimeResponse {
    RuntimeResponse {
        operation_id,
        payload: serde_json::json!({
            "status": "caller_assertion_recorded",
            "receipt_id": receipt_id,
            "replayed": replayed,
            "grants_authority": false,
            "semantic_mutations": 0,
            "outcome_verified_by_contextdb": false
        }),
    }
}

fn validate_reindex_request(request: &MaintenanceRequest) -> ServiceResult<Zeroizing<Vec<u8>>> {
    if !bounded_identifier(&request.operation_id, 1_024) {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "reindex operation ID is not a valid bounded identifier",
            false,
        ));
    }
    let payload_bytes =
        Zeroizing::new(serde_json::to_vec(&request.payload).map_err(|_| invalid_reindex_format())?);
    if payload_bytes.len() > MAX_REINDEX_PAYLOAD_BYTES {
        return Err(resource_exhausted(
            "reindex payload exceeds the 4 KiB canonical limit",
            false,
        ));
    }
    validate_reindex_json_depth(&request.payload)?;
    let typed: ReindexPayloadV1 =
        serde_json::from_slice(&payload_bytes).map_err(|_| invalid_reindex_format())?;
    let typed_value = serde_json::to_value(&typed).map_err(|_| invalid_reindex_format())?;
    if typed_value != request.payload
        || typed.schema_version != STORE_SCHEMA_VERSION
        || typed.projection != "production_policy_graph_v1"
    {
        return Err(invalid_reindex_format());
    }
    serde_json::to_vec(&typed)
        .map(Zeroizing::new)
        .map_err(|_| integrity("production reindex canonical serialization failed"))
}

fn validate_reindex_json_depth(root: &serde_json::Value) -> ServiceResult<()> {
    let mut pending = vec![(root, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_REINDEX_JSON_DEPTH {
            return Err(resource_exhausted(
                "reindex payload exceeds the JSON depth limit",
                false,
            ));
        }
        match value {
            serde_json::Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth.saturating_add(1))))
            }
            serde_json::Value::Object(values) => pending.extend(
                values
                    .values()
                    .map(|value| (value, depth.saturating_add(1))),
            ),
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }
    Ok(())
}

fn invalid_reindex_format() -> ServiceError {
    ServiceError::new(
        ErrorCode::FormatIncompatible,
        "reindex payload does not match the exact production policy-graph schema",
        false,
    )
}

fn reindex_response(
    operation_id: String,
    receipt_id: String,
    replayed: bool,
) -> MaintenanceResponse {
    MaintenanceResponse {
        operation_id,
        payload: serde_json::json!({
            "schema_version": 1,
            "projection": "production_policy_graph_v1",
            "status": "rebuilt_and_published",
            "receipt_id": receipt_id,
            "replayed": replayed,
            "semantic_mutations": 0,
            "primary_state_mutations": 0,
            "active_generation_changed": false,
            "external_state_head_anchored": true
        }),
    }
}

fn validate_compact_request(request: &MaintenanceRequest) -> ServiceResult<CompactPayloadV1> {
    if !bounded_identifier(&request.operation_id, 1_024) {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "compact operation ID is not a valid bounded identifier",
            false,
        ));
    }
    let payload_bytes =
        Zeroizing::new(serde_json::to_vec(&request.payload).map_err(|_| invalid_compact_format())?);
    if payload_bytes.len() > MAX_RUNTIME_GC_PAYLOAD_BYTES {
        return Err(resource_exhausted(
            "compact payload exceeds the 4 KiB canonical limit",
            false,
        ));
    }
    validate_bounded_json_depth(
        &request.payload,
        MAX_RUNTIME_GC_JSON_DEPTH,
        "compact payload exceeds the JSON depth limit",
    )?;
    let typed: CompactPayloadV1 =
        serde_json::from_slice(&payload_bytes).map_err(|_| invalid_compact_format())?;
    let typed_value = serde_json::to_value(&typed).map_err(|_| invalid_compact_format())?;
    let schema_version = match &typed {
        CompactPayloadV1::Physical { schema_version, .. }
        | CompactPayloadV1::RuntimeLedgerGc { schema_version, .. } => *schema_version,
    };
    if typed_value != request.payload || schema_version != STORE_SCHEMA_VERSION {
        return Err(invalid_compact_format());
    }
    Ok(typed)
}

fn validate_bounded_json_depth(
    root: &serde_json::Value,
    maximum: usize,
    message: &'static str,
) -> ServiceResult<()> {
    let mut pending = vec![(root, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > maximum {
            return Err(resource_exhausted(message, false));
        }
        match value {
            serde_json::Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth.saturating_add(1))));
            }
            serde_json::Value::Object(values) => {
                pending.extend(
                    values
                        .values()
                        .map(|value| (value, depth.saturating_add(1))),
                );
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }
    Ok(())
}

fn invalid_compact_format() -> ServiceError {
    ServiceError::new(
        ErrorCode::FormatIncompatible,
        "compact payload does not match an exact production maintenance schema",
        false,
    )
}

fn runtime_gc_report(
    status: &'static str,
    dry_run: bool,
    state_records_pruned: u64,
    checkpoint_heads_pruned: u64,
    receipts_retired: u64,
    anchors_updated: u64,
    logical_state_changed: bool,
) -> RuntimeLedgerGcReportV1 {
    RuntimeLedgerGcReportV1 {
        schema_version: STORE_SCHEMA_VERSION,
        status: status.to_owned(),
        dry_run,
        receipt_id: None,
        replayed: false,
        durable_receipt_recorded: false,
        state_records_pruned,
        checkpoint_heads_pruned,
        receipts_retired,
        anchors_updated,
        logical_state_changed,
        physical_bytes_reclaimed: None,
        replay_policy: "retired operation IDs return continuation_expired and never alias"
            .to_owned(),
    }
}

fn canonical_request_digest<T: Serialize>(
    store: &ProductionStore,
    operation: Operation,
    request: &T,
) -> ServiceResult<String> {
    let bytes = Zeroizing::new(canonical_bytes(request).map_err(|error| error.0)?);
    Ok(store.digest(operation.domain(), &bytes))
}

fn semantic_control_commitments(
    store: &ProductionStore,
    operation: Operation,
    request: &HighLevelControlRequest,
) -> ServiceResult<(Zeroizing<Vec<u8>>, String)> {
    const MAX_CONTROL_PARAMETERS_BYTES: usize = 64 * 1024;

    if !bounded_identifier(&request.idempotency_key, 1_024)
        || !bounded_identifier(&request.target_subject_id, 1_024)
        || !bounded_identifier(&request.target_id, 1_024)
    {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "semantic-control identity is not a valid bounded identifier",
            false,
        ));
    }
    let parameter_bytes =
        Zeroizing::new(serde_json::to_vec(&request.parameters).map_err(|_| {
            ServiceError::new(
                ErrorCode::FormatIncompatible,
                "semantic-control parameters are not canonical JSON",
                false,
            )
        })?);
    if parameter_bytes.len() > MAX_CONTROL_PARAMETERS_BYTES {
        return Err(resource_exhausted(
            "semantic-control parameters exceed the 64 KiB limit",
            false,
        ));
    }

    #[derive(Serialize)]
    struct RequestBinding<'a> {
        schema_version: u16,
        authorization_binding_digest: String,
        target_subject_id: &'a str,
        target_id: &'a str,
        parameters: &'a serde_json::Value,
    }
    let binding = Zeroizing::new(
        canonical_bytes(&RequestBinding {
            schema_version: contextdb_service::SERVICE_SCHEMA_VERSION,
            authorization_binding_digest: request.context.authorization_binding_digest()?,
            target_subject_id: &request.target_subject_id,
            target_id: &request.target_id,
            parameters: &request.parameters,
        })
        .map_err(|error| error.0)?,
    );
    let request_digest = store.digest(operation.domain(), &binding);
    let identity = Zeroizing::new(
        canonical_bytes(&(
            &request.context.request.workspace_id,
            &request.context.actor_id,
            request.idempotency_key.as_str(),
        ))
        .map_err(|error| error.0)?,
    );
    Ok((identity, request_digest))
}

fn require_grant(
    context: &contextdb_service::AuthenticatedRequestContext,
    capability: Capability,
) -> ServiceResult<()> {
    context.validate_authentication()?;
    if !context.capability_grants.contains(&capability) {
        return Err(ServiceError::new(
            ErrorCode::Unauthorized,
            "authenticated principal lacks the required capability",
            false,
        ));
    }
    Ok(())
}

fn require_graph_record_grant(
    context: &contextdb_service::AuthenticatedRequestContext,
    kind: contextdb_service::MemoryRecordKind,
) -> ServiceResult<()> {
    match kind {
        contextdb_service::MemoryRecordKind::Evidence => {
            require_grant(context, Capability::ReadEvidence)?;
            require_grant(context, Capability::RawEvidence)
        }
        contextdb_service::MemoryRecordKind::Conflict => {
            require_grant(context, Capability::ReadConflict)
        }
        contextdb_service::MemoryRecordKind::Node
        | contextdb_service::MemoryRecordKind::Claim
        | contextdb_service::MemoryRecordKind::Edge
        | contextdb_service::MemoryRecordKind::Candidate
        | contextdb_service::MemoryRecordKind::SemanticObject
        | contextdb_service::MemoryRecordKind::RuntimeState
        | contextdb_service::MemoryRecordKind::DomainExtension => {
            require_grant(context, Capability::ReadMemory)
        }
    }
}

pub(crate) fn store_path(path: &Path) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(".fjall");
    PathBuf::from(value)
}

fn storage_error(error: impl std::fmt::Display) -> CliError {
    unavailable(format!("production storage failure: {error}")).into()
}

fn integrity(message: impl Into<String>) -> ServiceError {
    ServiceError::new(ErrorCode::IntegrityFailure, message, false)
}

fn unavailable(message: impl Into<String>) -> ServiceError {
    ServiceError::new(ErrorCode::Unavailable, message, true)
}

fn resource_exhausted(message: impl Into<String>, retryable: bool) -> ServiceError {
    ServiceError::new(ErrorCode::ResourceExhausted, message, retryable)
}

fn unsupported(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::Unsupported, message, false)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Debug;
    use std::str::FromStr;

    use contextdb_context::{
        BlockId, BlockRepresentation, CandidateUsePolicy, CompressionLevel, ContentTrust,
        ContextBudgets, DisclosureRule, EvidenceHandle, EvidenceSelector, InstructionCapability,
        InstructionHierarchy as ContextInstructionHierarchy, InterpretationRule,
        ModelProfile as ContextModelProfile, PackBlockKind, PackCandidate, PackEvidence,
        PackPurpose, PositionProfile as ContextPositionProfile, ProviderCandidate,
        ProviderEvidence, SourceClass, SourceHandle, StructuredFormat as ContextStructuredFormat,
        SupportState,
    };
    use contextdb_continuity::{
        CompatibilityAnalyzer, ConditionalApprovals, ContinuityPolicyEnvelope, HandoffId,
        MemorySharingScope, MigrationId, MigrationRequirements, facets,
    };
    use contextdb_core::{
        AcceptanceState, AccessCapability, ActorId, AgentId, Audience, AudienceGrant, CheckpointId,
        CommitRange, CommitSeq, ConsentPolicy, ConsentState, ConsentStatus, ContextPackId,
        ContinuityProfileId, ConversationMode, DerivationId, DerivationKind, DerivationRef,
        EpistemicBasis, EpistemicRole, EpistemicState, IdentityClaimPolicy, LifecycleState,
        LineageNode, MemoryClass, MemoryRef, MemorySubjectId, MemoryUsePolicy, ModelProfileId,
        ModelRuntimeRef, ModificationPolicy, NodeId, NonEmptyVec, OwnershipPolicy, Perspective,
        PipelineIdentity, PolicyDecision, Purpose, RecallIntent, RetentionPolicy, RevisionNumber,
        ScopeInheritance, ScopeKind, ScopeRef, SecurityClassification, SecurityPolicy, SessionId,
        SituationFrame, TimeRange, WeightedScope, WorkspaceId,
    };
    use contextdb_model::{
        InstructionHierarchy, LanguageTag, Modality, ModelProfile, ModelRevision, PositionProfile,
        ProviderId, StructuredFormat,
    };
    use contextdb_recall::{
        AccessConsent, AccessRule, ProviderSnapshot, RecallLimits, RecallMode, RecallPrincipal,
        RecallSensitivity, RecallWatermarks,
    };
    use contextdb_service::{
        AccessPolicy, AuthenticatedRequestContext, AuthenticationEvidence, Consent,
        DomainTimeRange, MemoryDocument, MemoryLifecycle, MemoryLinks, MemoryRecordKind,
        RuntimeRequest, Sensitivity, SnapshotComplete, SourceRevisionManifest, StreamObservation,
        TraverseDirection, ordered_items_digest,
    };

    use super::*;
    use crate::{OutputFormat, TokenKey, init_state_with_key, load_state_with_key};

    fn token_key() -> TokenKey {
        TokenKey::new([0x35; 32]).expect("test key")
    }

    fn request(key: &str, id: &str) -> ObserveRequest {
        ObserveRequest {
            context: contextdb_service::RequestContext {
                request_id: format!("request:{id}"),
                workspace_id: "workspace:production".into(),
                subject_id: "subject:production".into(),
                audiences: BTreeSet::from(["subject:production".into()]),
                scopes: BTreeSet::from(["project:production".into()]),
                purpose: "assist".into(),
                clearance: Sensitivity::Private,
            },
            idempotency_key: key.into(),
            observation_id: id.into(),
            metadata: BTreeMap::new(),
            content: serde_json::json!({"text": "fjall durable projection"}),
            access: AccessPolicy {
                workspace_id: "workspace:production".into(),
                scopes: BTreeSet::from(["project:production".into()]),
                owners: BTreeSet::from(["subject:production".into()]),
                audience: BTreeSet::from(["subject:production".into()]),
                audience_purpose_grants: BTreeMap::new(),
                purposes: BTreeSet::from(["assist".into()]),
                sensitivity: Sensitivity::Private,
                consent: Consent::Granted,
                retrievable: true,
            },
        }
    }

    fn stream_context(request_id: &str, binding_byte: u8) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: contextdb_service::RequestContext {
                request_id: request_id.to_owned(),
                workspace_id: "workspace:production".to_owned(),
                subject_id: "subject:production".to_owned(),
                audiences: BTreeSet::from(["subject:production".to_owned()]),
                scopes: BTreeSet::from(["project:production".to_owned()]),
                purpose: "assist".to_owned(),
                clearance: Sensitivity::Private,
            },
            actor_id: "actor:production".to_owned(),
            agent_id: "agent:production".to_owned(),
            session_id: Some("session:production".to_owned()),
            capability_grants: BTreeSet::from([Capability::StreamIngest]),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: format!("channel:{binding_byte}"),
                peer_identity: "actor:production".to_owned(),
                binding_digest: format!("{binding_byte:02x}").repeat(32),
            },
        }
    }

    fn runtime_context(
        request_id: &str,
        workspace_id: &str,
        subject_id: &str,
    ) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: contextdb_service::RequestContext {
                request_id: request_id.to_owned(),
                workspace_id: workspace_id.to_owned(),
                subject_id: subject_id.to_owned(),
                audiences: BTreeSet::from([subject_id.to_owned()]),
                scopes: BTreeSet::from(["project:production".to_owned()]),
                purpose: "assist".to_owned(),
                clearance: Sensitivity::Private,
            },
            actor_id: format!("actor:{subject_id}"),
            agent_id: "agent:runtime-postflight".to_owned(),
            session_id: Some("session:runtime-postflight".to_owned()),
            capability_grants: BTreeSet::from([Capability::Runtime]),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: format!("channel:{request_id}"),
                peer_identity: format!("actor:{subject_id}"),
                binding_digest: "cd".repeat(32),
            },
        }
    }

    fn runtime_postflight_request(
        operation_id: &str,
        context: AuthenticatedRequestContext,
    ) -> RuntimeRequest {
        let preflight = serde_json::json!({
            "action": {
                "id": "action:content-free-postflight",
                "description": "assert completed action without persisting raw outcome",
                "requested_tool": "tool:sentinel-never-persist",
                "mutates_external_state": true,
                "argument_digest": "11".repeat(32)
            },
            "context": {
                "schema_version": "contextdb.context_pack.v1",
                "id": "00000000-0000-4000-8000-000000000101",
                "status": "no_memory",
                "snapshot": {
                    "database_id": "database:runtime-postflight",
                    "commit_seq": 0,
                    "watermarks": {
                        "journal": 0,
                        "semantic": 0,
                        "lexical": 0,
                        "vector": {},
                        "graph": 0,
                        "hierarchy": {}
                    }
                },
                "purpose": "action",
                "scope_manifest": {
                    "workspace": context.request.workspace_id,
                    "subject": context.request.subject_id,
                    "scopes": context.request.scopes,
                    "purpose": "action",
                    "temporal_view": {"kind": "current"},
                    "filter_digest": "filter:runtime-postflight"
                },
                "sections": {
                    "situation": [], "self_context": [], "participants": [],
                    "shared_history": [], "episodes": [], "facts": [],
                    "relationships": [], "preferences": [], "boundaries": [],
                    "goals": [], "decisions": [], "timeline": [],
                    "procedures": [], "constraints": [], "open_loops": [],
                    "conflicts": [], "unknowns": []
                },
                "evidence": [],
                "use_directives": [],
                "graph_manifest": {"memory_refs": [], "claim_ids": [], "conflict_sets": []},
                "freshness": {
                    "snapshot": {
                        "database_id": "database:runtime-postflight",
                        "commit_seq": 0,
                        "watermarks": {
                            "journal": 0, "semantic": 0, "lexical": 0,
                            "vector": {}, "graph": 0, "hierarchy": {}
                        }
                    },
                    "warnings": []
                },
                "provenance": {
                    "compiler_version": "contextdb.context_compiler.v1",
                    "policy_filter_digest": "filter:runtime-postflight",
                    "blocks": [],
                    "evidence_sources": {}
                },
                "continuation": null,
                "compilation": {
                    "compiler_version": "contextdb.context_compiler.v1",
                    "schema_version": "contextdb.context_pack.v1",
                    "model_profile": "model:test",
                    "tokenizer": "tokenizer:test",
                    "renderer": "canonical_json",
                    "budget": {
                        "hard_tokens": 1, "soft_tokens": 1, "max_blocks": 1,
                        "max_evidence_blocks": 1, "max_raw_evidence_tokens": 1,
                        "max_history_tokens": 1, "max_conflict_tokens": 1,
                        "max_serialized_bytes": 1048576,
                        "max_selection_evaluations": 1
                    },
                    "usage": {
                        "rendered_tokens": 0, "control_tokens": 0, "data_tokens": 0,
                        "blocks": 0, "evidence_blocks": 0, "raw_evidence_tokens": 0,
                        "history_tokens": 0, "conflict_tokens": 0,
                        "serialized_bytes": 1679, "selection_evaluations": 0
                    },
                    "soft_budget_exceeded": false,
                    "selected_blocks": [],
                    "omissions": [],
                    "sufficiency": {
                        "sufficient": false, "covered_facets": [], "missing_facets": [],
                        "unresolved_conflicts": [], "blocking_unknowns": [],
                        "unsupported_blocks": []
                    }
                },
                "no_memory": {"reason": "no_authorized_candidates", "missing_facets": []}
            },
            "host_authorization": "granted",
            "required_verifications": []
        });
        let mut provisional = RuntimeRequest {
            context,
            operation_id: operation_id.to_owned(),
            payload: serde_json::json!({
                "preflight": preflight,
                "record": {
                    "action_id": "action:content-free-postflight",
                    "preflight_digest": "44".repeat(32),
                    "host_authorization": "granted",
                    "plan_digest": "22".repeat(32),
                    "tool_results": [{
                        "tool": "tool:sentinel-never-persist",
                        "digest": "33".repeat(32),
                        "untrusted": true
                    }],
                    "outcome": {"status": "failed", "reason": "reason:sentinel-never-persist"},
                    "verification": {
                        "status": "unknown",
                        "reason": "verification:sentinel-never-persist"
                    },
                    "artifacts": [],
                    "follow_up_commitments": [],
                    "completed_at": 42,
                    "record_digest": "55".repeat(32)
                }
            }),
        };
        let report =
            contextdb_service::canonical_preflight_report(&provisional.payload["preflight"])
                .expect("preflight fixture");
        provisional.payload["record"]["preflight_digest"] = report["report_digest"].clone();
        provisional.payload["record"]["record_digest"] = serde_json::json!(
            contextdb_service::canonical_postflight_record_digest(&provisional.payload["record"])
                .expect("canonical record digest")
        );
        provisional
    }

    fn reseal_postflight_record(request: &mut RuntimeRequest) {
        request.payload["record"]["record_digest"] = serde_json::json!(
            contextdb_service::canonical_postflight_record_digest(&request.payload["record"])
                .expect("canonical postflight record digest")
        );
    }

    fn continuity_must<T, E: Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| panic!("unexpected continuity fixture error: {error:?}"))
    }

    fn continuity_parsed<T>(value: &str) -> T
    where
        T: FromStr,
        T::Err: Debug,
    {
        continuity_must(value.parse())
    }

    fn continuity_workspace() -> WorkspaceId {
        continuity_parsed("00000000-0000-4000-8000-000000000001")
    }

    fn continuity_agent() -> AgentId {
        continuity_parsed("00000000-0000-4000-8000-000000000002")
    }

    fn continuity_subject() -> MemorySubjectId {
        continuity_parsed("00000000-0000-4000-8000-000000000003")
    }

    fn continuity_recipient() -> MemorySubjectId {
        continuity_parsed("00000000-0000-4000-8000-000000000004")
    }

    fn continuity_scope() -> ScopeRef {
        ScopeRef {
            kind: ScopeKind::Project,
            id: continuity_parsed("00000000-0000-4000-8000-000000000005"),
            inheritance: ScopeInheritance::Exact,
        }
    }

    fn continuity_open_loop() -> NodeId {
        continuity_parsed("00000000-0000-4000-8000-000000000006")
    }

    fn continuity_model_id() -> ModelProfileId {
        continuity_parsed("00000000-0000-4000-8000-000000000007")
    }

    fn continuity_perspective() -> Perspective {
        Perspective {
            knower: continuity_subject(),
            experiencer: Some(continuity_subject()),
            narrator: continuity_parsed::<ActorId>("00000000-0000-4000-8000-000000000009"),
            role: EpistemicRole::Witness,
        }
    }

    fn continuity_ownership() -> OwnershipPolicy {
        OwnershipPolicy {
            owners: NonEmptyVec::new(continuity_subject()),
            audience_grants: vec![AudienceGrant {
                audience: Audience::Subject {
                    id: continuity_recipient(),
                },
                purposes: BTreeSet::from([Purpose::Export]),
                capabilities: BTreeSet::from([
                    AccessCapability::Retrieve,
                    AccessCapability::InfluenceResponse,
                    AccessCapability::Export,
                ]),
            }],
            allowed_purposes: BTreeSet::from([Purpose::Migration, Purpose::Export]),
            modification: ModificationPolicy {
                owners_may_modify: true,
                delegates_may_modify: false,
                system_may_derive: true,
            },
        }
    }

    fn continuity_consent() -> ConsentPolicy {
        ConsentPolicy {
            required: true,
            decisions: vec![ConsentState {
                subject: continuity_subject(),
                memory_class: MemoryClass::Operational,
                status: ConsentStatus::Granted,
                valid_time: TimeRange::open_ended(TimestampMicros(0)),
            }],
        }
    }

    fn continuity_use_policy() -> MemoryUsePolicy {
        MemoryUsePolicy {
            retrieve: PolicyDecision::Allow,
            influence_response: PolicyDecision::Allow,
            mention_explicitly: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Allow,
            retention: RetentionPolicy::Indefinite,
        }
    }

    fn continuity_security() -> SecurityPolicy {
        SecurityPolicy {
            classification: SecurityClassification::Internal,
            labels: BTreeSet::from(["continuity".to_owned()]),
            required_compartments: BTreeSet::new(),
            allow_external_processing: true,
        }
    }

    fn continuity_derivation() -> DerivationRef {
        DerivationRef {
            id: continuity_parsed::<DerivationId>("00000000-0000-4000-8000-000000000010"),
            kind: DerivationKind::Migration,
            actor: None,
            model_call: None,
            pipeline: PipelineIdentity {
                name: "production-runtime-fixture".to_owned(),
                version: "1".to_owned(),
                schema_version: "1".to_owned(),
            },
            inputs: vec![LineageNode::External {
                namespace: "fixture".to_owned(),
                identifier: "source".to_owned(),
            }],
        }
    }

    fn continuity_envelope() -> contextdb_core::SemanticEnvelope {
        contextdb_core::SemanticEnvelope {
            scopes: NonEmptyVec::new(continuity_scope()),
            perspective: continuity_perspective(),
            ownership: continuity_ownership(),
            consent: continuity_consent(),
            use_policy: continuity_use_policy(),
            security: continuity_security(),
            derivation: continuity_derivation(),
        }
    }

    fn continuity_policy() -> ContinuityPolicyEnvelope {
        ContinuityPolicyEnvelope {
            workspace_id: continuity_workspace(),
            scopes: NonEmptyVec::new(continuity_scope()),
            ownership: continuity_ownership(),
            consent: continuity_consent(),
            use_policy: continuity_use_policy(),
            security: continuity_security(),
        }
    }

    fn continuity_profile() -> ContinuityProfile {
        ContinuityProfile {
            id: continuity_parsed::<ContinuityProfileId>("00000000-0000-4000-8000-000000000011"),
            revision: RevisionNumber::FIRST,
            transaction_time: CommitRange::current(CommitSeq::new(10)),
            workspace_id: continuity_workspace(),
            agent_id: continuity_agent(),
            stable_subject: continuity_subject(),
            model_lineage: vec![ModelRuntimeRef {
                provider: "provider-runtime".to_owned(),
                model: continuity_model_id().to_string(),
                revision: Some("runtime.1".to_owned()),
                first_used_at: TimestampMicros(10),
                last_used_at: None,
            }],
            required_bootstrap_facets: NonEmptyVec::new(facets::AGENT_IDENTITY.to_owned()),
            migration_policy: "portable-v1".to_owned(),
            identity_claim_policy: IdentityClaimPolicy::OperationalContinuityOnly,
            envelope: continuity_envelope(),
        }
    }

    fn continuity_language(value: &str) -> LanguageTag {
        continuity_must(LanguageTag::new(value))
    }

    fn continuity_runtime() -> RuntimeDescriptor {
        RuntimeDescriptor {
            provider: continuity_must(ProviderId::new("provider-runtime")),
            model: ModelProfile {
                id: continuity_model_id(),
                family: "production-runtime-fixture".to_owned(),
                revision: continuity_must(ModelRevision::new("runtime.1")),
                tokenizer: ReferenceTokenizer::ID.to_owned(),
                max_context_tokens: 16_000,
                reserved_output_tokens: 2_000,
                preferred_structured_format: StructuredFormat::JsonSchema,
                supports_tool_results: true,
                supports_native_citations: true,
                supports_prompt_caching: false,
                position_profile: PositionProfile {
                    constraints_first: true,
                    evidence_near_claim: true,
                    summary_before_detail: true,
                    unknowns_before_actions: true,
                },
                instruction_hierarchy: InstructionHierarchy {
                    channels: vec!["system".to_owned(), "user".to_owned()],
                    isolates_tool_results: true,
                    isolates_user_content: true,
                },
                max_schema_complexity: 64,
                languages: BTreeSet::from([continuity_language("en"), continuity_language("ru")]),
                modalities: BTreeSet::from([Modality::Text, Modality::ToolResult]),
            },
            renderer: RendererKind::Compact,
            capabilities: BTreeSet::new(),
            tools: BTreeMap::new(),
            embedding_spaces: BTreeMap::new(),
            prompt_cache_namespace: None,
            external_processing: false,
        }
    }

    fn continuity_core_checkpoint(id: &str, created_seq: u64, captured_at: i64) -> Checkpoint {
        let session = continuity_parsed::<SessionId>("00000000-0000-4000-8000-000000000012");
        Checkpoint {
            id: continuity_parsed::<CheckpointId>(id),
            session_id: session,
            frame_snapshot: SituationFrame {
                session_id: session,
                conversation_mode: ConversationMode::TaskExecution,
                active_topics: Vec::new(),
                active_referents: Vec::new(),
                participant_states: Vec::new(),
                goal_stack: Vec::new(),
                active_scopes: NonEmptyVec::new(WeightedScope {
                    scope: continuity_scope(),
                    weight: 1.0,
                }),
                open_questions: Vec::new(),
                open_loops: vec![continuity_open_loop()],
                working_hypotheses: Vec::new(),
                recent_observations: Vec::new(),
                environment: Some(serde_json::json!({"device": "test"})),
                captured_at: TimestampMicros(captured_at),
                expires_at: TimestampMicros(10_000),
            },
            task_state: serde_json::json!({"selected_option": "resume"}),
            required_memory_refs: vec![MemoryRef::Node {
                id: continuity_open_loop(),
            }],
            created_seq: CommitSeq::new(created_seq),
        }
    }

    fn continuity_snapshot() -> ProviderSnapshot {
        ProviderSnapshot {
            database_id: "database:runtime-lifecycle".to_owned(),
            commit_seq: 20,
            watermarks: RecallWatermarks {
                journal: 20,
                semantic: 20,
                lexical: 20,
                vector: BTreeMap::new(),
                graph: 20,
                hierarchy: BTreeMap::new(),
            },
        }
    }

    fn continuity_access(consent: AccessConsent) -> AccessRule {
        AccessRule {
            workspace: continuity_workspace().to_string(),
            scopes: BTreeSet::from([continuity_scope().id.to_string()]),
            owners: BTreeSet::from([continuity_subject().to_string()]),
            audience_purpose_grants: BTreeMap::from([(
                "*".to_owned(),
                BTreeSet::from(["*".to_owned()]),
            )]),
            sensitivity: RecallSensitivity::Internal,
            required_compartments: BTreeSet::new(),
            consent,
            retrievable: true,
        }
    }

    fn continuity_candidate_use() -> CandidateUsePolicy {
        CandidateUsePolicy {
            influence: PolicyDecision::Allow,
            mention: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Allow,
            disclosure: DisclosureRule::MayMention,
        }
    }

    fn continuity_epistemic() -> EpistemicState {
        EpistemicState {
            basis: EpistemicBasis::Observation,
            acceptance: AcceptanceState::Accepted,
            conflict: contextdb_core::ConflictState::None,
            lifecycle: LifecycleState::Active,
        }
    }

    fn continuity_representation(summary: &str) -> BlockRepresentation {
        BlockRepresentation {
            level: CompressionLevel::L0Orientation,
            summary: summary.to_owned(),
            fields: BTreeMap::new(),
            omitted_facets: BTreeSet::new(),
        }
    }

    fn continuity_situation_candidate() -> ProviderCandidate {
        ProviderCandidate {
            access: continuity_access(AccessConsent::Granted),
            use_policy: continuity_candidate_use(),
            candidate: PackCandidate {
                id: continuity_must(BlockId::new("situation:runtime-resume")),
                kind: PackBlockKind::Situation,
                representations: vec![continuity_representation(
                    "Resume the durable runtime implementation after restart.",
                )],
                exact_fragments: Vec::new(),
                memory_refs: Vec::new(),
                claim_ids: BTreeSet::new(),
                evidence_handles: BTreeSet::new(),
                facets: BTreeSet::from([
                    facets::AGENT_IDENTITY.to_owned(),
                    facets::PARTICIPANT_IDENTITY.to_owned(),
                    facets::RELATIONSHIP_ROLE.to_owned(),
                    facets::CURRENT_CIRCUMSTANCES.to_owned(),
                    facets::RECENT_MILESTONES.to_owned(),
                    facets::IMPORTANT_CORRECTIONS.to_owned(),
                    facets::COMMUNICATION_PREFERENCES.to_owned(),
                    facets::STRICT_BOUNDARIES.to_owned(),
                    facets::SHARED_REFERENCES.to_owned(),
                    facets::INDEX_FRESHNESS.to_owned(),
                ]),
                scopes: BTreeSet::from([continuity_scope().id.to_string()]),
                valid_time: None,
                known_at_commit: 20,
                perspective: None,
                epistemic: continuity_epistemic(),
                confidence_micros: 1_000_000,
                trust: ContentTrust::TrustedSource,
                instruction_capability: InstructionCapability::None,
                source_class: SourceClass::DeterministicDerivation,
                taints: BTreeSet::new(),
                interpretation: InterpretationRule::FactualData,
                support: SupportState::Supported,
                conflict: None,
                unknown: None,
                utility_micros: 1_000_000,
                mandatory: true,
            },
        }
    }

    fn continuity_claim_id() -> contextdb_core::ClaimId {
        continuity_parsed("00000000-0000-4000-8000-000000000016")
    }

    fn continuity_evidence_handle() -> EvidenceHandle {
        continuity_must(EvidenceHandle::new("evidence:runtime-open-loop"))
    }

    fn continuity_open_loop_candidate() -> ProviderCandidate {
        ProviderCandidate {
            access: continuity_access(AccessConsent::Granted),
            use_policy: continuity_candidate_use(),
            candidate: PackCandidate {
                id: continuity_must(BlockId::new("open-loop:runtime-delivery")),
                kind: PackBlockKind::OpenLoop,
                representations: vec![continuity_representation(
                    "The durable runtime delivery remains open across restart.",
                )],
                exact_fragments: Vec::new(),
                memory_refs: vec![MemoryRef::Node {
                    id: continuity_open_loop(),
                }],
                claim_ids: BTreeSet::from([continuity_claim_id()]),
                evidence_handles: BTreeSet::from([continuity_evidence_handle()]),
                facets: BTreeSet::from([
                    facets::OPEN_LOOPS.to_owned(),
                    facets::IMPORTANT_CORRECTIONS.to_owned(),
                    facets::STRICT_BOUNDARIES.to_owned(),
                    facets::RECENT_MILESTONES.to_owned(),
                ]),
                scopes: BTreeSet::from([continuity_scope().id.to_string()]),
                valid_time: None,
                known_at_commit: 20,
                perspective: Some(continuity_perspective()),
                epistemic: continuity_epistemic(),
                confidence_micros: 950_000,
                trust: ContentTrust::TrustedSource,
                instruction_capability: InstructionCapability::None,
                source_class: SourceClass::SharedConversation,
                taints: BTreeSet::new(),
                interpretation: InterpretationRule::FactualData,
                support: SupportState::Supported,
                conflict: None,
                unknown: None,
                utility_micros: 900_000,
                mandatory: true,
            },
        }
    }

    fn continuity_private_candidate() -> ProviderCandidate {
        let mut value = continuity_situation_candidate();
        value.access.consent = AccessConsent::Denied;
        value.candidate.id = continuity_must(BlockId::new("fact:private"));
        value.candidate.representations[0].summary =
            "PRIVATE_SENTINEL_MUST_NEVER_LEAVE_PROVIDER".to_owned();
        value
    }

    fn continuity_provider_evidence() -> ProviderEvidence {
        ProviderEvidence {
            access: continuity_access(AccessConsent::Granted),
            external_model_use: PolicyDecision::Allow,
            evidence: PackEvidence {
                original_span: None,
                id: continuity_evidence_handle(),
                source: continuity_must(SourceHandle::new("source:runtime-history")),
                selector: EvidenceSelector::Whole,
                excerpt: Some("The runtime delivery is still in progress.".to_owned()),
                claim_ids: BTreeSet::from([continuity_claim_id()]),
                provenance_family: "runtime-history".to_owned(),
                primary: true,
                trust_micros: 950_000,
                source_class: SourceClass::SharedConversation,
                taints: BTreeSet::new(),
                lineage: Vec::new(),
            },
        }
    }

    fn continuity_provider(include_private: bool) -> RuntimeProviderInputV1 {
        let mut candidates = vec![
            continuity_situation_candidate(),
            continuity_open_loop_candidate(),
        ];
        if include_private {
            candidates.push(continuity_private_candidate());
        }
        RuntimeProviderInputV1 {
            candidates,
            evidence: vec![continuity_provider_evidence()],
        }
    }

    fn continuity_principal(subject: MemorySubjectId, purpose: Purpose) -> RecallPrincipal {
        RecallPrincipal::from_core(
            subject,
            continuity_workspace(),
            &[continuity_scope()],
            &purpose,
            SecurityClassification::Internal,
        )
    }

    fn continuity_budgets() -> ContextBudgets {
        ContextBudgets {
            hard_tokens: 10_000,
            soft_tokens: 9_000,
            max_blocks: 64,
            max_evidence_blocks: 64,
            max_raw_evidence_tokens: 2_000,
            max_history_tokens: 4_000,
            max_conflict_tokens: 2_000,
            max_serialized_bytes: 500_000,
            max_selection_evaluations: 128,
        }
    }

    fn continuity_portable_checkpoint(core: Checkpoint) -> PortableCheckpoint {
        continuity_must(PortableCheckpoint::new(
            core,
            &continuity_profile(),
            &continuity_runtime(),
            continuity_policy(),
        ))
    }

    fn continuity_bootstrap_request(checkpoint: PortableCheckpoint) -> BootstrapRequest {
        let runtime = continuity_runtime();
        let requirements = MigrationRequirements {
            required_capabilities: BTreeSet::new(),
            required_tools: BTreeSet::new(),
            minimum_input_tokens: 4_000,
            minimum_schema_complexity: 32,
            require_native_citations: false,
        };
        let compatibility = continuity_must(CompatibilityAnalyzer::analyze(
            continuity_must(MigrationId::new("restart:production-runtime")),
            continuity_workspace(),
            continuity_agent(),
            continuity_subject(),
            &runtime,
            &runtime,
            &requirements,
            NonEmptyVec::new(continuity_scope()),
            CommitSeq::new(20),
        ));
        BootstrapRequest {
            checkpoint,
            continuity_profile: continuity_profile(),
            source_runtime: runtime.clone(),
            compatibility,
            pack_id: continuity_parsed("00000000-0000-4000-8000-000000000017"),
            model_profile: continuity_must(runtime.context_profile()),
            snapshot: continuity_snapshot(),
            principal: continuity_principal(continuity_subject(), Purpose::Conversation),
            filter_digest: "filter:runtime-lifecycle:v1".to_owned(),
            pack_scopes: BTreeSet::from([continuity_scope().id.to_string()]),
            semantic_scopes: BTreeSet::from([continuity_scope()]),
            budgets: continuity_budgets(),
            facet_overrides: BTreeMap::new(),
            explicit_memory_request: true,
            migration_at: TimestampMicros(200),
            approvals: ConditionalApprovals::default(),
        }
    }

    fn continuity_handoff_request(checkpoint: PortableCheckpoint) -> HandoffRequest {
        HandoffRequest {
            id: continuity_must(HandoffId::new("handoff:runtime-reviewer")),
            checkpoint,
            compile: contextdb_context::CompileRequest {
                pack_id: continuity_parsed("00000000-0000-4000-8000-000000000018"),
                snapshot: continuity_snapshot(),
                principal: continuity_principal(continuity_recipient(), Purpose::Export),
                filter_digest: "filter:runtime-handoff:v1".to_owned(),
                purpose: PackPurpose::Handoff,
                scopes: BTreeSet::from([continuity_scope().id.to_string()]),
                temporal_view: contextdb_core::TemporalConstraint::Current,
                required_facets: Vec::new(),
                budgets: continuity_budgets(),
                model_profile: continuity_must(continuity_runtime().context_profile()),
                explicit_memory_request: true,
                require_primary_evidence: true,
                continuation: None,
            },
            recipient: continuity_recipient(),
            sharing_scope: MemorySharingScope::PairwiseShared,
            recipient_compartments: BTreeSet::new(),
            target_external_processing: false,
            approvals: ConditionalApprovals::default(),
            publishable_blocks: BTreeSet::from([
                continuity_must(BlockId::new("situation:runtime-resume")),
                continuity_must(BlockId::new("open-loop:runtime-delivery")),
                continuity_must(BlockId::new("fact:private")),
            ]),
            publishable_memory_refs: BTreeSet::from([MemoryRef::Node {
                id: continuity_open_loop(),
            }]),
            accepted_commitments: BTreeSet::new(),
            issued_at: TimestampMicros(300),
            expires_at: TimestampMicros(1_300),
            revocation_id: continuity_must(HandoffId::new("revoke:runtime-reviewer")),
        }
    }

    fn continuity_runtime_context(request_id: &str) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: contextdb_service::RequestContext {
                request_id: request_id.to_owned(),
                workspace_id: continuity_workspace().to_string(),
                subject_id: continuity_subject().to_string(),
                audiences: BTreeSet::from([continuity_subject().to_string()]),
                scopes: BTreeSet::from([continuity_scope().id.to_string()]),
                purpose: "migration".to_owned(),
                clearance: Sensitivity::Internal,
            },
            actor_id: continuity_subject().to_string(),
            agent_id: continuity_agent().to_string(),
            session_id: Some("session:runtime-lifecycle".to_owned()),
            capability_grants: BTreeSet::from([Capability::Runtime]),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: "channel:runtime-lifecycle".to_owned(),
                peer_identity: continuity_subject().to_string(),
                binding_digest: "ef".repeat(32),
            },
        }
    }

    fn continuity_seal_request(operation_id: &str, checkpoint: Checkpoint) -> RuntimeRequest {
        RuntimeRequest {
            context: continuity_runtime_context(&format!("request:{operation_id}")),
            operation_id: operation_id.to_owned(),
            payload: serde_json::to_value(RuntimeCheckpointInputV1::Seal {
                schema_version: STORE_SCHEMA_VERSION,
                checkpoint: Box::new(checkpoint),
                continuity_profile: Box::new(continuity_profile()),
                source_runtime: Box::new(continuity_runtime()),
                policy: Box::new(continuity_policy()),
            })
            .expect("seal payload"),
        }
    }

    fn continuity_bootstrap_runtime_request(
        operation_id: &str,
        expected_version: u64,
        checkpoint: PortableCheckpoint,
    ) -> RuntimeRequest {
        RuntimeRequest {
            context: continuity_runtime_context(&format!("request:{operation_id}")),
            operation_id: operation_id.to_owned(),
            payload: serde_json::to_value(RuntimeBootstrapInputV1 {
                schema_version: STORE_SCHEMA_VERSION,
                expected_checkpoint_version: expected_version,
                request: continuity_bootstrap_request(checkpoint),
                target_runtime: continuity_runtime(),
                provider: continuity_provider(false),
            })
            .expect("bootstrap payload"),
        }
    }

    fn continuity_resume_runtime_request(
        operation_id: &str,
        expected_version: u64,
        checkpoint: PortableCheckpoint,
    ) -> RuntimeRequest {
        RuntimeRequest {
            context: continuity_runtime_context(&format!("request:{operation_id}")),
            operation_id: operation_id.to_owned(),
            payload: serde_json::to_value(RuntimeResumeInputV1 {
                schema_version: STORE_SCHEMA_VERSION,
                expected_checkpoint_version: expected_version,
                request: continuity_bootstrap_request(checkpoint),
                target_runtime: continuity_runtime(),
                provider: continuity_provider(false),
            })
            .expect("resume payload"),
        }
    }

    fn continuity_revoke_request(
        operation_id: &str,
        checkpoint_digest: String,
        expected_version: u64,
        revoked_at: TimestampMicros,
    ) -> RuntimeRequest {
        RuntimeRequest {
            context: continuity_runtime_context(&format!("request:{operation_id}")),
            operation_id: operation_id.to_owned(),
            payload: serde_json::to_value(RuntimeCheckpointInputV1::Revoke {
                schema_version: STORE_SCHEMA_VERSION,
                checkpoint_digest,
                expected_version,
                revoked_at,
            })
            .expect("revoke payload"),
        }
    }

    fn continuity_handoff_runtime_request(
        operation_id: &str,
        expected_version: u64,
        checkpoint: PortableCheckpoint,
    ) -> RuntimeRequest {
        RuntimeRequest {
            context: continuity_runtime_context(&format!("request:{operation_id}")),
            operation_id: operation_id.to_owned(),
            payload: serde_json::to_value(RuntimeHandoffInputV1 {
                schema_version: STORE_SCHEMA_VERSION,
                expected_checkpoint_version: expected_version,
                request: continuity_handoff_request(checkpoint),
                provider: continuity_provider(true),
            })
            .expect("handoff payload"),
        }
    }

    fn graph_context(
        request_id: &str,
        subject_id: &str,
        grants: impl IntoIterator<Item = Capability>,
    ) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: contextdb_service::RequestContext {
                request_id: request_id.to_owned(),
                workspace_id: "workspace:production".to_owned(),
                subject_id: subject_id.to_owned(),
                audiences: BTreeSet::from([subject_id.to_owned()]),
                scopes: BTreeSet::from(["project:production".to_owned()]),
                purpose: "assist".to_owned(),
                clearance: Sensitivity::Private,
            },
            actor_id: subject_id.to_owned(),
            agent_id: "agent:graph-test".to_owned(),
            session_id: Some("session:graph-test".to_owned()),
            capability_grants: grants.into_iter().collect(),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: format!("channel:{request_id}"),
                peer_identity: subject_id.to_owned(),
                binding_digest: "ab".repeat(32),
            },
        }
    }

    fn semantic_control_request(
        operation: &str,
        target_id: &str,
        parameters: serde_json::Value,
    ) -> HighLevelControlRequest {
        HighLevelControlRequest {
            context: graph_context(
                &format!("request:{operation}"),
                "subject:production",
                [Capability::Correct, Capability::ReadMemory],
            ),
            idempotency_key: format!("idempotency:{operation}"),
            target_subject_id: "subject:production".to_owned(),
            target_id: target_id.to_owned(),
            parameters,
        }
    }

    fn reindex_request(operation_id: &str, request_id: &str) -> MaintenanceRequest {
        MaintenanceRequest {
            context: graph_context(request_id, "subject:production", [Capability::Maintenance]),
            operation_id: operation_id.to_owned(),
            payload: serde_json::json!({
                "schema_version": 1,
                "projection": "production_policy_graph_v1"
            }),
        }
    }

    fn runtime_gc_request(
        operation_id: &str,
        retain_state_versions: u64,
        max_record_work: u64,
        dry_run: bool,
    ) -> MaintenanceRequest {
        MaintenanceRequest {
            context: graph_context(
                &format!("request:{operation_id}"),
                "subject:production",
                [Capability::Maintenance],
            ),
            operation_id: operation_id.to_owned(),
            payload: serde_json::json!({
                "action": "runtime_ledger_gc",
                "schema_version": STORE_SCHEMA_VERSION,
                "retain_state_versions": retain_state_versions,
                "max_record_work": max_record_work,
                "dry_run": dry_run
            }),
        }
    }

    fn context_pack_plan(
        query: &str,
        at_commit: Option<u64>,
    ) -> contextdb_service::CompileContextPlan {
        contextdb_service::CompileContextPlan {
            pack_id: ContextPackId::from_str("00000000-0000-4000-8000-0000000000c1")
                .expect("stable ContextPack ID"),
            query: query.to_owned(),
            mode: RecallMode::Required,
            intent: RecallIntent::CurrentTruth,
            purpose: PackPurpose::Conversation,
            at_commit,
            now_micros: 0,
            required_facets: Vec::new(),
            recall_limits: RecallLimits {
                max_nodes_examined: 128,
                max_seed_candidates: 128,
                max_graph_hops: 2,
                max_frontier_per_hop: 128,
                max_evidence_units: 32,
                max_context_tokens: 2_048,
                deadline_micros: 5_000_000,
            },
            context_budgets: ContextBudgets {
                hard_tokens: 2_048,
                soft_tokens: 1_024,
                max_blocks: 32,
                max_evidence_blocks: 32,
                max_raw_evidence_tokens: 1_024,
                max_history_tokens: 1_024,
                max_conflict_tokens: 1_024,
                max_serialized_bytes: 256 * 1_024,
                max_selection_evaluations: 128,
            },
            model_profile: ContextModelProfile {
                id: "model:production-context-pack-test".to_owned(),
                family: "reference".to_owned(),
                tokenizer_id: ReferenceTokenizer::ID.to_owned(),
                renderer: RendererKind::Compact,
                max_context_tokens: 4_096,
                reserved_output_tokens: 1_024,
                preferred_structured_format: ContextStructuredFormat::CompactText,
                supports_tool_results: false,
                supports_native_citations: false,
                supports_prompt_caching: false,
                position_profile: ContextPositionProfile::SmallModelExplicit,
                instruction_hierarchy: ContextInstructionHierarchy::SinglePromptDelimited,
                max_schema_complexity: 32,
                external_processing: false,
            },
            explicit_memory_request: true,
            require_primary_evidence: false,
            include_evidence_quotes: false,
            permit_derived_only: true,
            max_projection_lag_commits: 0,
            allow_stale: false,
            query_vector: None,
            continuation: None,
        }
    }

    fn graph_access(subject_id: &str) -> serde_json::Value {
        let grants = BTreeMap::from([(subject_id.to_owned(), vec!["assist"])]);
        serde_json::json!({
            "workspace": "workspace:production",
            "scopes": ["project:production"],
            "owners": [subject_id],
            "audience": [subject_id],
            "audience_purpose_grants": grants,
            "purposes": [],
            "sensitivity": "private",
            "consent": "granted",
            "retrievable": true
        })
    }

    fn graph_links(
        source: Option<&str>,
        target: Option<&str>,
        predicate: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "subject": null,
            "source": source,
            "target": target,
            "predicate": predicate,
            "conflict_set": null,
            "supersedes": [],
            "evidence": [],
            "conflict_members": [],
            "single_valued": false
        })
    }

    fn canonical_reference_value(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(values) => serde_json::Value::Array(
                values.into_iter().map(canonical_reference_value).collect(),
            ),
            serde_json::Value::Object(values) => {
                let sorted = values
                    .into_iter()
                    .map(|(key, value)| (key, canonical_reference_value(value)))
                    .collect::<BTreeMap<_, _>>();
                serde_json::Value::Object(sorted.into_iter().collect())
            }
            scalar => scalar,
        }
    }

    fn reference_digest(value: &serde_json::Value) -> String {
        let bytes = serde_json::to_vec(&canonical_reference_value(value.clone()))
            .expect("canonical reference fixture");
        blake3::hash(&bytes).to_hex().to_string()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "explicit canonical archive fixture"
    )]
    fn graph_fixture_revision(
        id: &str,
        revision: u32,
        transaction_from: u64,
        transaction_to: Option<u64>,
        kind: &str,
        access_subject: &str,
        links: serde_json::Value,
        lifecycle: &str,
    ) -> (serde_json::Value, String, serde_json::Value) {
        let content = serde_json::json!({
            "value": {"fixture": id, "revision": revision},
            "search_text": format!("{id} revision {revision}"),
            "vector": null,
            "attributes": {}
        });
        let digest = reference_digest(&content);
        let content_id = format!("record:{id}:{transaction_from}:{digest}");
        (
            serde_json::json!({
                "id": id,
                "revision": revision,
                "transaction_from": transaction_from,
                "transaction_to": transaction_to,
                "record": {
                    "kind": kind,
                    "access": graph_access(access_subject),
                    "valid_time": {"from": null, "to": null},
                    "lifecycle": lifecycle,
                    "links": links
                },
                "content": {"id": content_id, "digest": digest}
            }),
            content_id,
            content,
        )
    }

    fn semantic_journal_record(
        commit_seq: u64,
        previous_digest: Option<String>,
        affected_ids: &[&str],
    ) -> (serde_json::Value, String) {
        let affected_ids: BTreeSet<_> = affected_ids.iter().map(|id| (*id).to_owned()).collect();
        let event = serde_json::json!({
            "event": "semantic_published",
            "request_digest": format!("{commit_seq:064x}"),
            "request_content": {
                "id": format!("journal-fixture:{commit_seq}"),
                "digest": "cd".repeat(32)
            },
            "affected_ids": affected_ids
        });
        let digest_input = serde_json::json!({
            "commit_seq": commit_seq,
            "previous_digest": previous_digest,
            "event": event
        });
        let record_digest = reference_digest(&digest_input);
        (
            serde_json::json!({
                "commit_seq": commit_seq,
                "previous_digest": digest_input["previous_digest"].clone(),
                "record_digest": record_digest,
                "event": digest_input["event"].clone()
            }),
            record_digest,
        )
    }

    fn semantic_graph_archive() -> Vec<u8> {
        let records = [
            (
                "node:a",
                "node",
                "subject:production",
                graph_links(None, None, None),
            ),
            (
                "node:b",
                "node",
                "subject:production",
                graph_links(None, None, None),
            ),
            (
                "node:c",
                "node",
                "subject:production",
                graph_links(None, None, None),
            ),
            (
                "edge:a-b",
                "edge",
                "subject:production",
                graph_links(Some("node:a"), Some("node:b"), Some("next")),
            ),
            (
                "edge:b-c",
                "edge",
                "subject:production",
                graph_links(Some("node:b"), Some("node:c"), Some("next")),
            ),
            // This policy-hidden edge deliberately points at a missing node.
            // Correct policy-first traversal must never inspect that linkage.
            (
                "edge:hidden-dangling",
                "edge",
                "subject:hidden",
                graph_links(Some("node:a"), Some("node:missing"), Some("next")),
            ),
        ];
        let affected: Vec<_> = records.iter().map(|(id, ..)| *id).collect();
        let (journal, _) = semantic_journal_record(1, None, &affected);
        let mut histories = serde_json::Map::new();
        let mut contents = serde_json::Map::new();
        for (id, kind, subject, links) in records {
            let (revision, content_id, content) =
                graph_fixture_revision(id, 1, 1, None, kind, subject, links, "active");
            histories.insert(id.to_owned(), serde_json::Value::Array(vec![revision]));
            contents.insert(content_id, content);
        }
        serde_json::to_vec(&serde_json::json!({
            "format": "contextdb.logical.v1",
            "database_id": "database:production-graph-fixture",
            "head": 1,
            "watermarks": {"journal": 1, "semantic": 1, "lexical": 1, "vector": 1, "graph": 1},
            "histories": histories,
            "observations": {},
            "tombstones": {},
            "journal": [journal],
            "idempotency": {},
            "contents": contents
        }))
        .expect("semantic graph archive")
    }

    fn traversal_non_influence_archive(include_irrelevant: bool) -> Vec<u8> {
        let mut records = vec![
            (
                "node:a",
                "node",
                "subject:production",
                graph_links(None, None, None),
            ),
            (
                "node:b",
                "node",
                "subject:production",
                graph_links(None, None, None),
            ),
            (
                "edge:a-b",
                "edge",
                "subject:production",
                graph_links(Some("node:a"), Some("node:b"), Some("next")),
            ),
        ];
        if include_irrelevant {
            records.extend([
                // Policy-hidden and wrong-kind records must be invisible even
                // to the observable work budget.
                (
                    "edge:hidden",
                    "edge",
                    "subject:hidden",
                    graph_links(Some("node:a"), Some("node:missing"), Some("next")),
                ),
                (
                    "record:wrong-kind",
                    "claim",
                    "subject:production",
                    graph_links(Some("node:a"), Some("node:missing"), Some("next")),
                ),
                // Authorized edges that miss the predicate or current node are
                // likewise outside this request's observable candidate set.
                (
                    "edge:predicate-miss",
                    "edge",
                    "subject:production",
                    graph_links(Some("node:a"), Some("node:missing"), Some("other")),
                ),
                (
                    "edge:unrelated",
                    "edge",
                    "subject:production",
                    graph_links(Some("node:x"), Some("node:y"), Some("next")),
                ),
                (
                    "node:hidden-target",
                    "node",
                    "subject:hidden",
                    graph_links(None, None, None),
                ),
                (
                    "edge:hidden-target",
                    "edge",
                    "subject:production",
                    graph_links(Some("node:a"), Some("node:hidden-target"), Some("next")),
                ),
            ]);
        }
        let affected: Vec<_> = records.iter().map(|(id, ..)| *id).collect();
        let (journal, _) = semantic_journal_record(1, None, &affected);
        let mut histories = serde_json::Map::new();
        let mut contents = serde_json::Map::new();
        for (id, kind, subject, links) in records {
            let (revision, content_id, content) =
                graph_fixture_revision(id, 1, 1, None, kind, subject, links, "active");
            histories.insert(id.to_owned(), serde_json::Value::Array(vec![revision]));
            contents.insert(content_id, content);
        }
        serde_json::to_vec(&serde_json::json!({
            "format": "contextdb.logical.v1",
            "database_id": "database:traversal-non-influence",
            "head": 1,
            "watermarks": {"journal": 1, "semantic": 1, "lexical": 1, "vector": 1, "graph": 1},
            "histories": histories,
            "observations": {}, "tombstones": {}, "journal": [journal],
            "idempotency": {}, "contents": contents
        }))
        .expect("traversal non-influence archive")
    }

    fn historical_policy_archive() -> Vec<u8> {
        let (first, first_content_id, first_content) = graph_fixture_revision(
            "node:policy",
            1,
            1,
            Some(2),
            "node",
            "subject:production",
            graph_links(None, None, None),
            "active",
        );
        let (second, second_content_id, second_content) = graph_fixture_revision(
            "node:policy",
            2,
            2,
            None,
            "node",
            "subject:hidden",
            graph_links(None, None, None),
            "active",
        );
        let (first_journal, first_digest) = semantic_journal_record(1, None, &["node:policy"]);
        let (second_journal, _) = semantic_journal_record(2, Some(first_digest), &["node:policy"]);
        let contents = serde_json::Map::from_iter([
            (first_content_id, first_content),
            (second_content_id, second_content),
        ]);
        serde_json::to_vec(&serde_json::json!({
            "format": "contextdb.logical.v1",
            "database_id": "database:historical-policy",
            "head": 2,
            "watermarks": {"journal": 2, "semantic": 2, "lexical": 2, "vector": 2, "graph": 2},
            "histories": {"node:policy": [first, second]},
            "observations": {},
            "tombstones": {},
            "journal": [first_journal, second_journal],
            "idempotency": {},
            "contents": contents
        }))
        .expect("historical policy archive")
    }

    fn initialized_with_archive(
        path: &Path,
        archive: &[u8],
    ) -> (TokenKey, Arc<LoadedState>, ProductionService) {
        let key = token_key();
        let authority = crate::state_head::StateHeadStore::memory(path).expect("memory authority");
        authority
            .bootstrap(&key.expose_copy(), archive)
            .expect("bootstrap fixture archive");
        let state = crate::load_state_with_authority(
            TokenKey::new(key.expose_copy()).expect("fixture key"),
            authority,
        )
        .expect("load fixture state");
        let service = ProductionService::initialize(path, state.clone())
            .expect("initialize fixture production composition");
        (key, state, service)
    }

    fn stream_observation(id: &str, text: &str) -> StreamObservation {
        StreamObservation {
            idempotency_key: format!("idempotency:{id}"),
            observation_id: id.to_owned(),
            metadata: BTreeMap::from([("source".to_owned(), serde_json::json!("test"))]),
            content: serde_json::json!({"text": text}),
            access: AccessPolicy {
                workspace_id: "workspace:production".to_owned(),
                scopes: BTreeSet::from(["project:production".to_owned()]),
                owners: BTreeSet::from(["subject:production".to_owned()]),
                audience: BTreeSet::from(["subject:production".to_owned()]),
                audience_purpose_grants: BTreeMap::new(),
                purposes: BTreeSet::from(["assist".to_owned()]),
                sensitivity: Sensitivity::Private,
                consent: Consent::Granted,
                retrievable: true,
            },
        }
    }

    fn manifest_frame(
        context: AuthenticatedRequestContext,
        stream_id: &str,
        observations: &[StreamObservation],
    ) -> IngestFrame {
        let digest = ordered_items_digest(observations).expect("ordered item digest");
        IngestFrame {
            context,
            stream_id: stream_id.to_owned(),
            position: 0,
            resume_cursor: None,
            value: IngestFrameValue::Manifest(SourceRevisionManifest {
                source_id: format!("source:{stream_id}"),
                revision_id: "revision:1".to_owned(),
                snapshot_id: format!("snapshot:{stream_id}"),
                expected_items: u64::try_from(observations.len()).expect("bounded test items"),
                ordered_items_digest: digest,
                compression: Compression::Identity,
                attributes: BTreeMap::from([("branch".to_owned(), "main".to_owned())]),
            }),
        }
    }

    fn initialized(path: &Path) -> (TokenKey, Arc<LoadedState>, ProductionService) {
        let key = token_key();
        init_state_with_key(path, false, OutputFormat::Json, &key).expect("initialize");
        let state = load_state_with_key(path, &key).expect("load state");
        let service = ProductionService::initialize(path, state.clone())
            .expect("initialize production composition");
        (key, state, service)
    }

    fn assert_integrity_failure(result: CliResult<()>) {
        let error = result.expect_err("adversarial physical state must fail closed");
        assert_eq!(error.0.code, ErrorCode::IntegrityFailure);
    }

    #[test]
    fn durable_runtime_checkpoint_bootstrap_and_resume_replay_across_restarts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-lifecycle-restart.ctxb");
        let (_key, state, service) = initialized(&path);
        let core = continuity_core_checkpoint("00000000-0000-4000-8000-000000000013", 11, 100);
        let checkpoint = continuity_portable_checkpoint(core.clone());
        let seal_request = continuity_seal_request("checkpoint:restart", core);
        let sealed = service
            .checkpoint(seal_request.clone())
            .expect("seal durable checkpoint");
        let sealed_payload: RuntimeLifecyclePayloadV1 =
            serde_json::from_value(sealed.payload.clone()).expect("sealed payload");
        assert_eq!(sealed_payload.state.version, 1);
        assert_eq!(sealed_payload.state.status, RuntimeCheckpointStatus::Sealed);
        drop(service);

        let reopened = ProductionService::open(&path, state.clone()).expect("reopen checkpoint");
        assert_eq!(
            reopened
                .checkpoint(seal_request.clone())
                .expect("exact checkpoint replay"),
            sealed
        );
        let mut changed = seal_request;
        changed.payload["checkpoint"]["task_state"] = serde_json::json!({"changed": true});
        let conflict = reopened
            .checkpoint(changed)
            .expect_err("changed checkpoint retry must conflict");
        assert_eq!(conflict.code, ErrorCode::IdempotencyConflict);

        let bootstrap_request =
            continuity_bootstrap_runtime_request("bootstrap:restart", 1, checkpoint.clone());
        let bootstrapped = reopened
            .bootstrap(bootstrap_request.clone())
            .expect("compile durable bootstrap");
        let bootstrap_payload: RuntimeLifecyclePayloadV1 =
            serde_json::from_value(bootstrapped.payload.clone()).expect("bootstrap payload");
        assert_eq!(bootstrap_payload.state.version, 2);
        assert_eq!(
            bootstrap_payload.state.status,
            RuntimeCheckpointStatus::Bootstrapped
        );
        drop(reopened);

        let reopened = ProductionService::open(&path, state.clone()).expect("reopen bootstrap");
        assert_eq!(
            reopened
                .bootstrap(bootstrap_request)
                .expect("exact bootstrap replay"),
            bootstrapped
        );
        let resume_request = continuity_resume_runtime_request("resume:restart", 2, checkpoint);
        let resumed = reopened
            .resume(resume_request.clone())
            .expect("compile durable resume");
        let resume_payload: RuntimeLifecyclePayloadV1 =
            serde_json::from_value(resumed.payload.clone()).expect("resume payload");
        assert_eq!(resume_payload.state.version, 3);
        assert_eq!(
            resume_payload.state.status,
            RuntimeCheckpointStatus::Resumed
        );
        drop(reopened);

        let reopened = ProductionService::open(&path, state).expect("reopen resumed runtime");
        assert_eq!(
            reopened
                .resume(resume_request)
                .expect("exact resume replay"),
            resumed
        );
        reopened.store.verify().expect("verified runtime ledger");
    }

    #[test]
    fn runtime_ledger_gc_is_bounded_restart_safe_and_expires_pruned_replays() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-ledger-gc.ctxb");
        let (_key, state, service) = initialized(&path);
        let first_core =
            continuity_core_checkpoint("00000000-0000-4000-8000-000000000013", 11, 100);
        let first = continuity_portable_checkpoint(first_core.clone());
        let first_seal = continuity_seal_request("checkpoint:gc:first", first_core);
        service
            .checkpoint(first_seal.clone())
            .expect("seal first checkpoint");
        service
            .bootstrap(continuity_bootstrap_runtime_request(
                "bootstrap:gc",
                1,
                first.clone(),
            ))
            .expect("bootstrap first checkpoint");
        service
            .resume(continuity_resume_runtime_request(
                "resume:gc",
                2,
                first.clone(),
            ))
            .expect("resume first checkpoint");
        service
            .handoff(continuity_handoff_runtime_request("handoff:gc", 3, first))
            .expect("handoff first checkpoint");
        let second_core =
            continuity_core_checkpoint("00000000-0000-4000-8000-000000000019", 12, 400);
        let second_seal = continuity_seal_request("checkpoint:gc:second", second_core);
        service
            .checkpoint(second_seal.clone())
            .expect("seal successor checkpoint");
        let before = service
            .store
            .verify_durable_history()
            .expect("durable before GC");

        let planned = service
            .compact(runtime_gc_request("compact:gc:plan", 2, 100, true))
            .expect("bounded GC plan");
        assert_eq!(planned.payload["status"], "planned");
        assert_eq!(planned.payload["state_records_pruned"], 4);
        assert_eq!(planned.payload["receipts_retired"], 4);
        assert_eq!(planned.payload["logical_state_changed"], false);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("dry run is inert"),
            before
        );

        let apply_request = runtime_gc_request("compact:gc:apply", 2, 100, false);
        let applied = service
            .compact(apply_request.clone())
            .expect("apply bounded GC");
        assert_eq!(applied.payload["status"], "applied");
        assert_eq!(applied.payload["state_records_pruned"], 4);
        assert_eq!(applied.payload["receipts_retired"], 4);
        assert_eq!(applied.payload["anchors_updated"], 1);
        assert_eq!(applied.payload["logical_state_changed"], true);
        let after = service
            .store
            .verify_durable_history()
            .expect("durable GC successor");
        assert_eq!(after.generation, before.generation + 1);
        assert_eq!(applied.payload["durable_receipt_recorded"], true);
        assert_eq!(applied.payload["replayed"], false);
        validate_digest(
            applied.payload["receipt_id"]
                .as_str()
                .expect("GC receipt ID"),
            "test runtime GC receipt ID",
        )
        .expect("canonical GC receipt ID");
        let replay = service
            .compact(apply_request)
            .expect("exact runtime GC retry replays its receipt");
        assert_eq!(replay.payload["receipt_id"], applied.payload["receipt_id"]);
        assert_eq!(replay.payload["replayed"], true);
        assert_eq!(replay.payload["state_records_pruned"], 4);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("GC replay is inert")
                .generation,
            after.generation
        );
        service.store.verify().expect("verified compacted ledger");
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("GC snapshot");
        assert_eq!(
            snapshot
                .scan_prefix(&service.store.runtime, RUNTIME_STATE_PREFIX)
                .expect("retained states")
                .len(),
            2
        );
        assert_eq!(
            snapshot
                .scan_prefix(&service.store.runtime, RUNTIME_GC_ANCHOR_PREFIX)
                .expect("GC anchors")
                .len(),
            1
        );
        let retired = snapshot
            .scan_prefix(&service.store.runtime, RUNTIME_LIFECYCLE_RECEIPT_PREFIX)
            .expect("runtime receipts")
            .into_iter()
            .filter(|entry| {
                serde_json::from_slice::<StoredRuntimeLifecycleReceipt>(&entry.value)
                    .is_ok_and(|receipt| receipt.retired && receipt.response_bytes.is_empty())
            })
            .count();
        assert_eq!(retired, 4);
        let gc_receipt = snapshot
            .scan_prefix(&service.store.idempotency, RUNTIME_GC_RECEIPT_PREFIX)
            .expect("runtime GC receipt")
            .into_iter()
            .next()
            .expect("one GC receipt");
        for sentinel in [
            b"compact:gc:apply".as_slice(),
            b"workspace:production".as_slice(),
            b"subject:production".as_slice(),
            b"agent:graph-test".as_slice(),
            b"session:graph-test".as_slice(),
        ] {
            assert!(
                !gc_receipt
                    .key
                    .windows(sentinel.len())
                    .chain(gc_receipt.value.windows(sentinel.len()))
                    .any(|window| window == sentinel)
            );
        }
        drop(snapshot);

        // New lifecycle work continues from the retained tail. A second GC
        // pass must extend the existing prefix accumulator rather than
        // replacing or forgetting its first boundary.
        let third_core =
            continuity_core_checkpoint("00000000-0000-4000-8000-000000000020", 13, 500);
        service
            .checkpoint(continuity_seal_request("checkpoint:gc:third", third_core))
            .expect("seal checkpoint after GC");
        let second_gc = service
            .compact(runtime_gc_request("compact:gc:second-pass", 2, 100, false))
            .expect("extend GC anchor");
        assert_eq!(second_gc.payload["state_records_pruned"], 2);
        assert_eq!(second_gc.payload["receipts_retired"], 1);
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("second GC snapshot");
        let anchor_entry = snapshot
            .scan_prefix(&service.store.runtime, RUNTIME_GC_ANCHOR_PREFIX)
            .expect("extended anchor")
            .into_iter()
            .next()
            .expect("one anchor");
        let anchor: StoredRuntimeGcAnchor =
            serde_json::from_slice(&anchor_entry.value).expect("valid anchor");
        assert_eq!(anchor.pruned_through_version, 6);
        assert_eq!(
            snapshot
                .scan_prefix(&service.store.runtime, RUNTIME_STATE_PREFIX)
                .expect("second retained tail")
                .len(),
            2
        );
        drop(snapshot);
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("restart compacted ledger");
        let expired = reopened
            .checkpoint(first_seal)
            .expect_err("pruned operation ID cannot alias or replay payload");
        assert_eq!(expired.code, ErrorCode::ContinuationExpired);
        assert_eq!(
            expired.violated_policy.as_deref(),
            Some("runtime_ledger_retention")
        );
        let second_expired = reopened
            .checkpoint(second_seal)
            .expect_err("second pruned operation ID remains reserved");
        assert_eq!(second_expired.code, ErrorCode::ContinuationExpired);
        reopened.store.verify().expect("restart verifies GC anchor");
    }

    #[test]
    fn operational_status_compaction_and_format_preflight_are_content_free_and_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("production-operations.ctxb");
        let (_key, _state, service) = initialized(&path);
        let admin = graph_context(
            "request:operations:status",
            "subject:production",
            [Capability::Admin],
        );
        let status = service
            .get_status(GetStatusRequest {
                context: admin.clone(),
            })
            .expect("verified operational status");
        assert!(status.profile.starts_with(PROFILE));
        assert!(status.profile.ends_with("runtime_ledger_pressure=nominal"));
        assert!(!status.profile.contains("workspace:production"));
        assert_eq!(status.capability_manifest.profile, status.profile);
        assert!(!status.capability_manifest.server_v1_release_ready);
        assert_eq!(
            status.capability_manifest.capability("status"),
            Some(CapabilityState::Available)
        );
        for capability in [
            "background_semantic_adjudication",
            "candidate_hierarchy_dag",
            "consolidate",
            "hard_delete",
            "live_restore",
            "observation_semantic_extraction",
            "persistent_ann_recall_projection",
            "persistent_lexical_recall_projection",
            "policy_first_candidate_recall",
            "policy_first_candidate_traversal",
            "quarantined_memory_proposals",
            "reflect",
        ] {
            assert_eq!(
                status.capability_manifest.capability(capability),
                Some(CapabilityState::Unsupported),
                "production status must not promote unwired {capability}"
            );
        }
        let backup = service
            .create_backup(CreateBackupRequest {
                context: admin.clone(),
            })
            .expect_err("online physical checkpoint is not claimed");
        assert_eq!(backup.code, ErrorCode::Unsupported);
        assert_eq!(
            backup.violated_policy.as_deref(),
            Some("authority:host-global")
        );
        let restore = service
            .restore_backup(RestoreBackupRequest {
                context: admin.clone(),
                format: "untrusted-format-must-not-be-inspected-first".to_owned(),
                bytes: b"untrusted-restore-payload".to_vec(),
                digest: "not-a-digest".to_owned(),
            })
            .expect_err("live full-store restore is not claimed");
        assert_eq!(restore.code, ErrorCode::Unsupported);
        assert_eq!(
            restore.violated_policy.as_deref(),
            Some("authority:host-global")
        );

        let before = service
            .store
            .verify_durable_history()
            .expect("durable before operations");
        let current = service
            .migrate_format(MigrateFormatRequest {
                context: admin.clone(),
                target_format: PRODUCTION_FORMAT_ID.to_owned(),
                operation_id: "migration:identity-preflight".to_owned(),
            })
            .expect("verified identity preflight");
        assert_eq!(current.commit_seq, status.commit_seq);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("identity preflight is inert"),
            before
        );
        let incompatible = service
            .migrate_format(MigrateFormatRequest {
                context: admin,
                target_format: "contextdb.production-fjall.future-v99".to_owned(),
                operation_id: "migration:future".to_owned(),
            })
            .expect_err("unknown migration target fails before mutation");
        assert_eq!(incompatible.code, ErrorCode::FormatIncompatible);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("unknown target is inert"),
            before
        );

        let physical = service
            .compact(MaintenanceRequest {
                context: graph_context(
                    "request:compact:physical",
                    "subject:production",
                    [Capability::Maintenance],
                ),
                operation_id: "compact:physical".to_owned(),
                payload: serde_json::json!({
                    "action": "physical",
                    "schema_version": STORE_SCHEMA_VERSION,
                    "max_bytes": 4096
                }),
            })
            .expect("scheduler-managed physical report");
        assert_eq!(physical.payload["logical_state_changed"], false);
        assert_eq!(physical.payload["scheduler_managed"], true);
        assert_eq!(physical.payload["manual_rewrite_claimed"], false);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("physical report is logically inert"),
            before
        );

        let mut unauthorized = runtime_gc_request("compact:unauthorized", 2, 100, false);
        unauthorized.context.capability_grants.clear();
        unauthorized.payload = serde_json::json!({"protected": "x".repeat(8 * 1024)});
        assert_eq!(
            service
                .compact(unauthorized)
                .expect_err("authorization precedes protected compact payload")
                .code,
            ErrorCode::Unauthorized
        );
        let invalid_bounds = service
            .compact(runtime_gc_request("compact:bounds", 1, 100, false))
            .expect_err("retention must preserve a bounded live tail");
        assert_eq!(invalid_bounds.code, ErrorCode::InvalidArgument);
        let mut unknown = runtime_gc_request("compact:unknown", 2, 100, false);
        unknown.payload["unknown"] = serde_json::json!(true);
        assert_eq!(
            service
                .compact(unknown)
                .expect_err("compact schema is closed")
                .code,
            ErrorCode::FormatIncompatible
        );
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("rejected maintenance is inert"),
            before
        );
    }

    #[test]
    fn production_context_pack_is_snapshot_bound_and_policy_filtered() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("production-context-pack.ctxb");
        let mut archive: serde_json::Value =
            serde_json::from_slice(&semantic_graph_archive()).expect("ContextPack fixture archive");
        for history in archive["histories"]
            .as_object_mut()
            .expect("fixture histories")
            .values_mut()
        {
            for revision in history.as_array_mut().expect("fixture revisions") {
                for purposes in revision["record"]["access"]["audience_purpose_grants"]
                    .as_object_mut()
                    .expect("fixture audience grants")
                    .values_mut()
                {
                    *purposes = serde_json::json!(["conversation"]);
                }
            }
        }
        let archive = serde_json::to_vec(&archive).expect("ContextPack fixture bytes");
        let (_key, _state, service) = initialized_with_archive(&path, &archive);

        // Advance the live archive after the retained semantic snapshot. The
        // explicit ContextPack request must remain pinned to commit 1 instead
        // of silently observing the newer publication.
        service
            .observe(request(
                "idempotency:context-pack-drift",
                "observation:context-pack-drift",
            ))
            .expect("advance live archive");
        assert_eq!(
            service
                .store
                .policy_graph()
                .expect("advanced policy graph")
                .archive_commit_seq,
            2
        );

        let mut allowed_context = graph_context(
            "request:context-pack:allowed",
            "subject:production",
            [Capability::Recall],
        );
        allowed_context.request.purpose = "conversation".to_owned();
        let allowed = service
            .compile_context(CompileContextRequest {
                context: allowed_context,
                plan: context_pack_plan("revision", Some(1)),
            })
            .expect("compile retained production ContextPack");
        allowed
            .context_pack
            .validate()
            .expect("valid production ContextPack");
        assert_eq!(allowed.trace.snapshot.commit_seq, 1);
        assert_eq!(allowed.context_pack.snapshot, allowed.trace.snapshot);
        assert!(allowed.trace.selected_blocks > 0);
        let allowed_json = serde_json::to_string(&allowed).expect("allowed ContextPack JSON");
        assert!(allowed_json.contains("edge:a-b"));
        assert!(!allowed_json.contains("edge:hidden-dangling"));

        let mut denied_context = graph_context(
            "request:context-pack:denied",
            "subject:outsider",
            [Capability::Recall],
        );
        denied_context.request.purpose = "conversation".to_owned();
        let denied = service
            .compile_context(CompileContextRequest {
                context: denied_context,
                plan: context_pack_plan("revision", Some(1)),
            })
            .expect("policy denial returns a bound no-memory ContextPack");
        assert_eq!(denied.trace.snapshot.commit_seq, 1);
        assert_eq!(denied.trace.selected_blocks, 0);
        let denied_json = serde_json::to_string(&denied).expect("denied ContextPack JSON");
        assert!(!denied_json.contains("node:a"));
        assert!(!denied_json.contains("edge:hidden-dangling"));
    }

    #[test]
    fn runtime_handoff_filters_private_sources_preserves_open_loops_and_restarts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-handoff.ctxb");
        let (_key, state, service) = initialized(&path);
        let core = continuity_core_checkpoint("00000000-0000-4000-8000-000000000013", 11, 100);
        let checkpoint = continuity_portable_checkpoint(core.clone());
        service
            .checkpoint(continuity_seal_request("checkpoint:handoff", core))
            .expect("seal handoff checkpoint");
        let handoff_request =
            continuity_handoff_runtime_request("handoff:private-filter", 1, checkpoint);
        let handoff = service
            .handoff(handoff_request.clone())
            .expect("compile handoff");
        let serialized = serde_json::to_string(&handoff).expect("serialize handoff response");
        assert!(!serialized.contains("PRIVATE_SENTINEL_MUST_NEVER_LEAVE_PROVIDER"));
        let payload: RuntimeLifecyclePayloadV1 =
            serde_json::from_value(handoff.payload.clone()).expect("handoff payload");
        assert_eq!(payload.state.version, 2);
        let RuntimeLifecycleArtifactV1::Handoff { result } = payload.artifact else {
            panic!("expected handoff artifact");
        };
        assert!(result.open_loops_preserved);
        assert_eq!(result.compiled.pack.sections.open_loops.len(), 1);
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("reopen handoff");
        assert_eq!(
            reopened
                .handoff(handoff_request)
                .expect("exact handoff replay"),
            handoff
        );
        reopened.store.verify().expect("verified handoff ledger");
    }

    #[test]
    fn runtime_stale_and_revoked_checkpoints_fail_closed_after_restart() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-stale-revoked.ctxb");
        let (_key, state, service) = initialized(&path);
        let first_core =
            continuity_core_checkpoint("00000000-0000-4000-8000-000000000013", 11, 100);
        let first = continuity_portable_checkpoint(first_core.clone());
        service
            .checkpoint(continuity_seal_request("checkpoint:first", first_core))
            .expect("seal first checkpoint");
        let second_core =
            continuity_core_checkpoint("00000000-0000-4000-8000-000000000019", 12, 200);
        let second = continuity_portable_checkpoint(second_core.clone());
        let second_response = service
            .checkpoint(continuity_seal_request("checkpoint:second", second_core))
            .expect("seal successor checkpoint");
        let second_payload: RuntimeLifecyclePayloadV1 =
            serde_json::from_value(second_response.payload).expect("second payload");
        assert_eq!(second_payload.state.version, 3);

        let stale = service
            .resume(continuity_resume_runtime_request("resume:stale", 2, first))
            .expect_err("superseded checkpoint must fail");
        assert_eq!(stale.code, ErrorCode::ContinuationExpired);
        let revoked = service
            .checkpoint(continuity_revoke_request(
                "checkpoint:revoke",
                second.digest.to_string(),
                3,
                TimestampMicros(300),
            ))
            .expect("revoke active checkpoint");
        let revoked_payload: RuntimeLifecyclePayloadV1 =
            serde_json::from_value(revoked.payload).expect("revoked payload");
        assert_eq!(revoked_payload.state.version, 4);
        assert_eq!(
            revoked_payload.state.status,
            RuntimeCheckpointStatus::Revoked
        );
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("reopen revoked runtime");
        let denied = reopened
            .resume(continuity_resume_runtime_request(
                "resume:revoked",
                4,
                second,
            ))
            .expect_err("revoked checkpoint must fail after restart");
        assert_eq!(denied.code, ErrorCode::PermissionDenied);
        reopened.store.verify().expect("verified revoked state");
    }

    #[test]
    fn runtime_auth_scope_schema_size_depth_and_tamper_are_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-adversarial.ctxb");
        let (_key, _state, service) = initialized(&path);
        let core = continuity_core_checkpoint("00000000-0000-4000-8000-000000000013", 11, 100);
        let mut unauthorized = RuntimeRequest {
            context: continuity_runtime_context("request:unauthorized"),
            operation_id: "checkpoint:unauthorized".to_owned(),
            payload: serde_json::json!({"malformed": true}),
        };
        unauthorized.context.capability_grants.clear();
        assert_eq!(
            service
                .checkpoint(unauthorized)
                .expect_err("auth must win before malformed payload")
                .code,
            ErrorCode::Unauthorized
        );

        let malformed = RuntimeRequest {
            context: continuity_runtime_context("request:malformed"),
            operation_id: "checkpoint:malformed".to_owned(),
            payload: serde_json::json!({"action": "seal", "schema_version": 1, "unknown": true}),
        };
        assert_eq!(
            service
                .checkpoint(malformed)
                .expect_err("unknown field must fail")
                .code,
            ErrorCode::FormatIncompatible
        );
        let oversized = RuntimeRequest {
            context: continuity_runtime_context("request:oversized"),
            operation_id: "checkpoint:oversized".to_owned(),
            payload: serde_json::json!({"padding": "x".repeat(MAX_RUNTIME_LIFECYCLE_PAYLOAD_BYTES + 1)}),
        };
        assert_eq!(
            service
                .checkpoint(oversized)
                .expect_err("oversized payload must fail")
                .code,
            ErrorCode::ResourceExhausted
        );
        let mut deep = serde_json::json!(null);
        for _ in 0..=MAX_RUNTIME_LIFECYCLE_JSON_DEPTH {
            deep = serde_json::json!([deep]);
        }
        let deep = RuntimeRequest {
            context: continuity_runtime_context("request:deep"),
            operation_id: "checkpoint:deep".to_owned(),
            payload: deep,
        };
        assert_eq!(
            service
                .checkpoint(deep)
                .expect_err("deep payload must fail")
                .code,
            ErrorCode::ResourceExhausted
        );

        let mut wrong_scope = continuity_seal_request("checkpoint:wrong-scope", core.clone());
        wrong_scope.context.request.scopes.clear();
        assert_eq!(
            service
                .checkpoint(wrong_scope)
                .expect_err("scope mismatch must fail")
                .code,
            ErrorCode::PermissionDenied
        );
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("runtime precommit snapshot");
        assert!(
            snapshot
                .scan_prefix(&service.store.runtime, b"")
                .expect("runtime records")
                .is_empty()
        );
        drop(snapshot);

        service
            .checkpoint(continuity_seal_request("checkpoint:tamper", core))
            .expect("seal tamper fixture");
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("runtime receipt snapshot");
        let entry = snapshot
            .scan_prefix(&service.store.runtime, RUNTIME_LIFECYCLE_RECEIPT_PREFIX)
            .expect("runtime receipts")
            .into_iter()
            .next()
            .expect("runtime receipt");
        drop(snapshot);
        let mut corrupted = entry.value;
        let corrupt_at = corrupted.len() / 2;
        corrupted[corrupt_at] ^= 1;
        let mut transaction = service.store.engine.begin_write().expect("tamper write");
        transaction
            .put(&service.store.runtime, entry.key, corrupted)
            .expect("tamper runtime receipt");
        transaction
            .commit(Durability::Sync)
            .expect("commit runtime tamper");
        assert_integrity_failure(service.store.verify());
    }

    #[test]
    fn fresh_store_materializes_exact_closed_world_keyspaces_without_marker_records() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("exact-keyspaces.ctxb");
        let (key, _state, service) = initialized(&path);
        let expected = vec![
            FJALL_INTERNAL_META_KEYSPACE.to_owned(),
            PRODUCTION_DURABLE_HISTORY_KEYSPACE.to_owned(),
            PRODUCTION_EVENTS_KEYSPACE.to_owned(),
            PRODUCTION_IDEMPOTENCY_KEYSPACE.to_owned(),
            PRODUCTION_META_KEYSPACE.to_owned(),
            PRODUCTION_GRAPH_KEYSPACE.to_owned(),
            PRODUCTION_RUNTIME_KEYSPACE.to_owned(),
            PRODUCTION_STREAMS_KEYSPACE.to_owned(),
        ];
        assert_eq!(service.store.engine.physical_keyspace_names(), expected);
        drop(service);
        let reopened =
            ProductionStore::open(&path, &key.expose_copy()).expect("reopen exact store");
        let snapshot = reopened
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("exact snapshot");
        for keyspace in [
            &reopened.meta,
            &reopened.graph,
            &reopened.events,
            &reopened.idempotency,
            &reopened.streams,
            &reopened.durable_history,
            &reopened.runtime,
        ] {
            assert_eq!(
                snapshot
                    .get(keyspace, KEYSPACE_MATERIALIZATION_KEY)
                    .expect("marker lookup"),
                None
            );
        }
        reopened.verify().expect("exact reopened verification");
    }

    #[test]
    fn unknown_physical_keyspace_internal_meta_and_nonprefix_records_fail_closed() {
        enum Fault {
            Physical,
            BackendMeta,
            ProductionMeta,
            Graph,
            Event,
            Idempotency,
            Stream,
            History,
        }
        for fault in [
            Fault::Physical,
            Fault::BackendMeta,
            Fault::ProductionMeta,
            Fault::Graph,
            Fault::Event,
            Fault::Idempotency,
            Fault::Stream,
            Fault::History,
        ] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory.path().join("unknown-layout.ctxb");
            let (token, _state, service) = initialized(&path);
            let (keyspace, key) = match fault {
                Fault::Physical => (
                    Keyspace::new("production_rogue").expect("rogue"),
                    b"key".to_vec(),
                ),
                Fault::BackendMeta => (
                    Keyspace::new(FJALL_INTERNAL_META_KEYSPACE).expect("backend meta"),
                    b"rogue".to_vec(),
                ),
                Fault::ProductionMeta => (service.store.meta.clone(), b"rogue".to_vec()),
                Fault::Graph => (service.store.graph.clone(), b"rogue".to_vec()),
                Fault::Event => (service.store.events.clone(), b"rogue".to_vec()),
                Fault::Idempotency => (service.store.idempotency.clone(), b"rogue".to_vec()),
                Fault::Stream => (service.store.streams.clone(), b"rogue".to_vec()),
                Fault::History => (service.store.durable_history.clone(), b"rogue".to_vec()),
            };
            let mut transaction = service.store.engine.begin_write().expect("fault writer");
            transaction
                .put(&keyspace, key, b"adversarial".to_vec())
                .expect("stage fault");
            transaction.commit(Durability::Sync).expect("persist fault");
            assert_integrity_failure(service.store.verify());
            drop(service);
            let error = ProductionStore::open(&path, &token.expose_copy())
                .expect_err("open must reject adversarial physical state");
            assert_eq!(error.0.code, ErrorCode::IntegrityFailure);
        }
    }

    #[test]
    fn ordinary_reads_use_the_verified_publication_and_explicit_verify_rechecks_disk() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("published-read.ctxb");
        let (_token, _state, service) = initialized(&path);
        let status_request = || GetStatusRequest {
            context: graph_context(
                "status:published",
                "subject:production",
                [Capability::Admin],
            ),
        };
        let before = service
            .get_status(status_request())
            .expect("verified published status");

        let mut transaction = service.store.engine.begin_write().expect("fault writer");
        transaction
            .put(
                &service.store.events,
                b"rogue".to_vec(),
                b"adversarial".to_vec(),
            )
            .expect("stage disk-only fault");
        transaction
            .commit(Durability::Sync)
            .expect("persist disk-only fault");

        let after = service
            .get_status(status_request())
            .expect("cached publication remains isolated from disk-only bytes");
        assert_eq!(after.commit_seq, before.commit_seq);
        assert_eq!(after.watermarks, before.watermarks);
        let error = service
            .verify(VerifyRequest {
                context: admin_context("published-read-deep-verify"),
                deep: true,
            })
            .expect_err("explicit verification must inspect persistent bytes");
        assert_eq!(error.code, ErrorCode::IntegrityFailure);
    }

    #[test]
    fn unchanged_reconciliation_uses_cached_tip_but_sequence_drift_falls_back_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cached-reconciliation.ctxb");
        let (_token, _state, service) = initialized(&path);
        let initial = service.reconciliation_pass_counts();
        assert_eq!(initial, (1, 0));

        {
            let mut published = service.lock().expect("publication lock");
            service
                .reconcile_locked(&mut published)
                .expect("unchanged exact tip");
        }
        assert_eq!(service.reconciliation_pass_counts(), (1, 1));

        // This models a second Fjall writer/tamper which advances the physical
        // sequence while changing a rooted point record. The stale cache must
        // not authorize it: mismatch selects complete verification, which
        // rejects the changed closed-world root before replay/publication.
        let mut transaction = service.store.engine.begin_write().expect("fault writer");
        transaction
            .put(
                &service.store.meta,
                HEAD_KEY.to_vec(),
                9_u64.to_be_bytes().to_vec(),
            )
            .expect("stage rooted head fault");
        transaction
            .commit(Durability::Sync)
            .expect("persist rooted head fault");

        let mut published = service.lock().expect("publication lock");
        let error = service
            .reconcile_locked(&mut published)
            .expect_err("changed physical tip must not use the cache");
        assert_eq!(error.code, ErrorCode::IntegrityFailure);
        assert_eq!(service.reconciliation_pass_counts(), (2, 1));
    }

    #[cfg(feature = "current-server")]
    #[test]
    fn unrelated_keyspace_commit_invalidates_cached_tip_and_runs_closed_world_verification() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cached-reconciliation-rogue.ctxb");
        let (_token, state, service) = initialized(&path);
        let initial_health = service.readiness();
        assert_eq!(initial_health.state, HealthState::Ready);
        assert!(initial_health.is_ready());
        state.poisoned.store(true, Ordering::Release);
        let quarantined_health = service.readiness();
        assert_eq!(quarantined_health.state, HealthState::NotReady);
        assert!(!quarantined_health.checks.service_loaded);
        assert_eq!(
            quarantined_health.reason_code,
            Some(HealthReason::ServicePublicationUnavailable)
        );
        state.poisoned.store(false, Ordering::Release);
        assert!(service.readiness().is_ready());
        let cached_sequence = service
            .reconciled_tip
            .read()
            .expect("reconciled tip lock")
            .as_ref()
            .expect("reconciled tip")
            .storage_sequence;

        // The record is unrelated to every point-read in ReconciledTip. Fjall
        // nevertheless advances its sole physical sequence in the same atomic
        // commit, so the cache cannot hide an unknown closed-world record.
        let mut transaction = service.store.engine.begin_write().expect("fault writer");
        transaction
            .put(
                &service.store.idempotency,
                b"rogue-unclassified-key".to_vec(),
                b"adversarial".to_vec(),
            )
            .expect("stage unrelated fault");
        let committed = transaction
            .commit(Durability::Sync)
            .expect("persist unrelated fault");
        assert!(committed.sequence > cached_sequence);
        let drifted_health = service.readiness();
        assert_eq!(drifted_health.state, HealthState::NotReady);
        assert!(!drifted_health.checks.external_head_reconciled);
        assert!(!drifted_health.checks.publication_available);

        let mut published = service.lock().expect("publication lock");
        let error = service
            .reconcile_locked(&mut published)
            .expect_err("unknown record must select and fail complete verification");
        assert_eq!(error.code, ErrorCode::IntegrityFailure);
        assert_eq!(service.reconciliation_pass_counts(), (2, 0));
    }

    #[test]
    fn semantic_mutation_directly_publishes_preverified_successor_without_full_replay() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("direct-semantic-publication.ctxb");
        let (_token, state, service) = initialized(&path);
        assert_eq!(service.reconciliation_pass_counts(), (1, 0));
        assert_eq!(service.canonical_replay_pass_count(), 1);

        let response = service
            .observe(request("direct-publication", "observation:direct"))
            .expect("direct semantic publication");
        assert_eq!(response.commit_seq, 1);
        // One fast predecessor proof, one full v2 root computation in append,
        // and no post-commit store verification/canonical replay.
        assert_eq!(service.reconciliation_pass_counts(), (1, 1));
        assert_eq!(service.canonical_replay_pass_count(), 1);

        let tip = service
            .reconciled_tip
            .read()
            .expect("reconciled tip lock")
            .clone()
            .expect("directly published tip");
        let (_, semantic, durable) = state
            .authority
            .load_verified_with_ledger(&state.key.expose_copy())
            .expect("external authority");
        assert_eq!(semantic.commit_seq, response.commit_seq);
        assert_eq!(semantic.archive_digest, tip.projection_digest);
        assert_eq!(durable.generation, tip.durable.generation);
        assert_eq!(durable.ledger_digest, tip.durable.digest);
    }

    fn unkeyed_legacy_digest(domain: &[u8], bytes: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"contextdb/production-ledger/v1");
        hasher.update(&[0]);
        hasher.update(domain);
        hasher.update(&[0]);
        hasher.update(bytes);
        hasher.finalize().to_hex().to_string()
    }

    #[test]
    fn encrypted_stream_survives_restart_and_completion_is_atomic() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-restart.ctxb");
        let (_key, state, service) = initialized(&path);
        let observation = stream_observation(
            "observation:encrypted-stream",
            "plaintext that must never enter Fjall",
        );
        let digest = ordered_items_digest(std::slice::from_ref(&observation)).expect("digest");
        let manifest = manifest_frame(
            stream_context("request:manifest", 0x11),
            "stream:encrypted-restart",
            std::slice::from_ref(&observation),
        );
        let manifest_ack = service
            .ingest_frame(manifest.clone())
            .expect("durable manifest");
        assert_eq!(
            service
                .ingest_frame({
                    let mut retry = manifest;
                    retry.context = stream_context("request:manifest-retry", 0x22);
                    retry
                })
                .expect("fresh-evidence manifest retry"),
            manifest_ack
        );

        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("stream snapshot");
        let frames = snapshot
            .scan_prefix(&service.store.streams, STREAM_FRAME_PREFIX)
            .expect("encrypted frames");
        assert_eq!(frames.len(), 1);
        assert!(
            !frames[0]
                .value
                .windows(b"plaintext that must never enter Fjall".len())
                .any(|window| window == b"plaintext that must never enter Fjall")
        );
        assert!(
            !frames[0]
                .value
                .windows(b"observation:encrypted-stream".len())
                .any(|window| window == b"observation:encrypted-stream")
        );
        let decrypted = service
            .store
            .open_stream_record(
                b"frame",
                &frames[0].key,
                &frames[0].value,
                MAX_STREAM_FRAME_BYTES,
            )
            .expect("test-only frame inspection");
        let minimal_json = std::str::from_utf8(&decrypted).expect("minimal frame JSON");
        assert!(!minimal_json.contains("authentication"));
        assert!(!minimal_json.contains("request_id"));
        assert!(!minimal_json.contains("capability_grants"));
        drop(snapshot);

        let item = IngestFrame {
            context: stream_context("request:item", 0x33),
            stream_id: "stream:encrypted-restart".to_owned(),
            position: 1,
            resume_cursor: Some(manifest_ack.resume_cursor.clone()),
            value: IngestFrameValue::Observation(observation),
        };
        let item_ack = service.ingest_frame(item.clone()).expect("durable item");
        {
            let published = service.state.read().expect("published stream candidate");
            assert_eq!(
                service
                    .export_host_archive(&published)
                    .expect("pre-completion export")
                    .commit_seq,
                0,
                "a staged observation must have zero partial visibility"
            );
        }
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("restart production stream");
        let mut item_retry = item;
        item_retry.context = stream_context("request:item-retry", 0x44);
        assert_eq!(
            reopened
                .ingest_frame(item_retry)
                .expect("item retry after restart"),
            item_ack
        );
        let completion = IngestFrame {
            context: stream_context("request:complete", 0x55),
            stream_id: "stream:encrypted-restart".to_owned(),
            position: 2,
            resume_cursor: Some(item_ack.resume_cursor),
            value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
                snapshot_id: "snapshot:stream:encrypted-restart".to_owned(),
                item_count: 1,
                ordered_items_digest: digest,
            }),
        };
        let completion_ack = reopened
            .ingest_frame(completion.clone())
            .expect("atomic completion");
        assert_eq!(
            completion_ack.disposition,
            IngestDisposition::SnapshotCommitted
        );
        assert_eq!(completion_ack.partial_result_refs.len(), 1);
        assert_eq!(reopened.store.events().expect("events").len(), 1);
        let snapshot = reopened
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("post-completion snapshot");
        assert!(
            snapshot
                .scan_prefix(&reopened.store.streams, STREAM_STATE_PREFIX)
                .expect("states")
                .is_empty()
        );
        assert!(
            snapshot
                .scan_prefix(&reopened.store.streams, STREAM_FRAME_PREFIX)
                .expect("frames")
                .is_empty()
        );
        assert!(
            snapshot
                .scan_prefix(&reopened.store.streams, STREAM_RECEIPT_PREFIX)
                .expect("receipts")
                .is_empty()
        );
        drop(snapshot);
        let mut completion_retry = completion;
        completion_retry.context = stream_context("request:complete-retry", 0x66);
        assert_eq!(
            reopened
                .ingest_frame(completion_retry)
                .expect("ledger completion replay"),
            completion_ack
        );
        reopened.store.verify().expect("stream store verification");
    }

    #[test]
    fn stream_completion_lost_ack_is_reconciled_without_staging_resurrection() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-lost-ack.ctxb");
        let (_key, state, service) = initialized(&path);
        let observation = stream_observation("observation:stream-lost-ack", "lost ack");
        let digest = ordered_items_digest(std::slice::from_ref(&observation)).expect("digest");
        let manifest = manifest_frame(
            stream_context("request:lost-manifest", 0x21),
            "stream:lost-ack",
            std::slice::from_ref(&observation),
        );
        let manifest_ack = service.ingest_frame(manifest).expect("manifest");
        let item_ack = service
            .ingest_frame(IngestFrame {
                context: stream_context("request:lost-item", 0x22),
                stream_id: "stream:lost-ack".to_owned(),
                position: 1,
                resume_cursor: Some(manifest_ack.resume_cursor),
                value: IngestFrameValue::Observation(observation),
            })
            .expect("item");
        let completion = IngestFrame {
            context: stream_context("request:lost-complete", 0x23),
            stream_id: "stream:lost-ack".to_owned(),
            position: 2,
            resume_cursor: Some(item_ack.resume_cursor),
            value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
                snapshot_id: "snapshot:stream:lost-ack".to_owned(),
                item_count: 1,
                ordered_items_digest: digest,
            }),
        };
        state.authority.fail_next_backend_write_for_test();
        let error = service
            .ingest_frame(completion.clone())
            .expect_err("state-head acknowledgement is lost");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
        assert_eq!(service.store.events().expect("completion event").len(), 1);
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("post-Fjall snapshot");
        assert!(
            snapshot
                .scan_prefix(&service.store.streams, STREAM_FRAME_PREFIX)
                .expect("frames")
                .is_empty()
        );
        drop(snapshot);
        let recovered = service
            .ingest_frame(completion)
            .expect("exact completion retry reconciles");
        assert_eq!(recovered.disposition, IngestDisposition::SnapshotCommitted);
        assert_eq!(service.store.events().expect("single event").len(), 1);
    }

    #[test]
    fn staged_frame_lost_authority_ack_reconciles_exact_durable_successor() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-frame-lost-ack.ctxb");
        let (key, state, service) = initialized(&path);
        let manifest = manifest_frame(
            stream_context("request:frame-lost-ack", 0x71),
            "stream:frame-lost-ack",
            &[],
        );
        state.authority.fail_next_backend_write_for_test();
        let error = service
            .ingest_frame(manifest.clone())
            .expect_err("authority acknowledgement is injected lost");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
        let persisted_deadline = service
            .store
            .load_stream(
                &service
                    .store
                    .stream_digest("workspace:production", "stream:frame-lost-ack")
                    .expect("stream digest"),
            )
            .expect("load persisted stream")
            .expect("persisted stream")
            .receipts[&0]
            .acknowledgement
            .lease_expires_at_ms;
        let durable = service
            .store
            .verify_durable_history()
            .expect("Fjall durable successor");
        assert_eq!(durable.generation, 1);
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("multi-step reconciliation");
        let mut retry = manifest;
        retry.context = stream_context("request:frame-lost-ack-retry", 0x72);
        let acknowledgement = reopened.ingest_frame(retry).expect("exact retry");
        assert_eq!(acknowledgement.disposition, IngestDisposition::Accepted);
        assert_eq!(acknowledgement.lease_expires_at_ms, persisted_deadline);
        let (_, _, anchored) = reopened
            .state
            .authority
            .load_verified_with_ledger(&key.expose_copy())
            .expect("anchored durable head");
        assert_eq!(anchored.generation, durable.generation);
        assert_eq!(anchored.ledger_digest, durable.digest);
    }

    #[test]
    fn startup_proves_multiple_durable_successors_before_advancing_authority() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("multi-successor.ctxb");
        let (_key, state, service) = initialized(&path);
        for marker in [0x81_u8, 0x82_u8] {
            let envelope = service
                .store
                .seal_stream_bytes_with_nonce(
                    b"test_history",
                    &[b'h', marker],
                    &[marker],
                    [marker; STREAM_NONCE_BYTES],
                )
                .expect("test-only nonce envelope");
            let mut transaction = service
                .store
                .engine
                .begin_write()
                .expect("durable successor writer");
            service
                .store
                .reserve_stream_nonces(&mut transaction, [&envelope])
                .expect("unique nonce reservation");
            service
                .store
                .stage_durable_successor(&mut transaction)
                .expect("durable successor");
            transaction
                .commit(Durability::Sync)
                .expect("synchronized durable successor");
        }
        let durable = service
            .store
            .verify_durable_history()
            .expect("two-step history");
        assert_eq!(durable.generation, 2);
        let (_, _, stale_anchor) = state
            .authority
            .load_verified_with_ledger(&state.key.expose_copy())
            .expect("stale external anchor");
        assert_eq!(stale_anchor.generation, 0);
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("prove both successors");
        let (_, _, reconciled) = reopened
            .state
            .authority
            .load_verified_with_ledger(&reopened.state.key.expose_copy())
            .expect("reconciled authority");
        assert_eq!(reconciled.generation, 2);
        assert_eq!(reconciled.ledger_digest, durable.digest);
    }

    #[test]
    fn rollback_to_pre_frame_snapshot_leaves_authority_ahead_and_is_quarantined() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-fjall-rollback.ctxb");
        let (key, state, service) = initialized(&path);
        let rollback_seed_path = directory.path().join("rollback-seed.ctxb");
        let initial_archive = service
            .store
            .current_projection()
            .expect("initial projection")
            .archive;
        let rollback_seed =
            ProductionStore::initialize(&rollback_seed_path, &initial_archive, &key.expose_copy())
                .expect("independent generation-zero Fjall seed");
        rollback_seed.verify().expect("generation-zero seed");
        drop(rollback_seed);
        service
            .ingest_frame(manifest_frame(
                stream_context("request:rollback-manifest", 0x73),
                "stream:rollback",
                &[],
            ))
            .expect("anchored staged frame");
        let (_, _, anchored) = state
            .authority
            .load_verified_with_ledger(&key.expose_copy())
            .expect("authority generation one");
        assert_eq!(anchored.generation, 1);
        drop(service);

        let live_store = store_path(&path);
        let initial_directory = store_path(&rollback_seed_path);
        let rolled_aside = directory.path().join("fjall-generation-one");
        std::fs::rename(&live_store, &rolled_aside).expect("preserve generation one");
        std::fs::rename(&initial_directory, &live_store).expect("replay generation zero");
        let error = ProductionService::open(&path, state)
            .expect_err("authority ahead of Fjall must quarantine");
        assert_eq!(error.0.code, ErrorCode::IntegrityFailure);
    }

    #[test]
    fn encrypted_stream_records_persist_no_request_context_or_authentication_evidence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-minimal-replay.ctxb");
        let (_key, _state, service) = initialized(&path);
        service
            .ingest_frame(manifest_frame(
                stream_context("request:must-never-persist", 0x91),
                "stream:minimal-replay",
                &[],
            ))
            .expect("anchored manifest");

        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("stream snapshot");
        let classes: [(&[u8], &[u8]); 3] = [
            (STREAM_STATE_PREFIX, b"state"),
            (STREAM_FRAME_PREFIX, b"frame"),
            (STREAM_RECEIPT_PREFIX, b"receipt"),
        ];
        let forbidden = [
            "request:must-never-persist",
            "\"request_id\"",
            "\"actor_id\"",
            "\"agent_id\"",
            "\"session_id\"",
            "\"capability_grants\"",
            "\"authentication\"",
            "\"channel_id\"",
            "\"peer_identity\"",
            "\"binding_digest\"",
            "actor:production",
            "agent:production",
            "session:production",
            "channel:145",
        ];
        for (prefix, record_kind) in classes {
            let entries = snapshot
                .scan_prefix(&service.store.streams, prefix)
                .expect("encrypted replay records");
            assert_eq!(entries.len(), 1);
            let plaintext = service
                .store
                .open_stream_record(
                    record_kind,
                    &entries[0].key,
                    &entries[0].value,
                    MAX_STREAM_FRAME_BYTES,
                )
                .expect("test-only encrypted record inspection");
            let plaintext = std::str::from_utf8(&plaintext).expect("canonical replay JSON");
            for needle in forbidden {
                assert!(
                    !plaintext.contains(needle),
                    "{record_kind:?} persisted forbidden authentication material: {needle}"
                );
            }
        }
    }

    #[test]
    fn omitted_open_stream_record_changes_the_anchored_state_root() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-omission.ctxb");
        let (_key, _state, service) = initialized(&path);
        service
            .ingest_frame(manifest_frame(
                stream_context("request:omission", 0x74),
                "stream:omission",
                &[],
            ))
            .expect("anchored manifest");
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("stream snapshot");
        let entry = snapshot
            .scan_prefix(&service.store.streams, STREAM_FRAME_PREFIX)
            .expect("frame records")
            .into_iter()
            .next()
            .expect("frame record");
        drop(snapshot);
        let mut transaction = service.store.engine.begin_write().expect("omission writer");
        transaction
            .delete(&service.store.streams, entry.key)
            .expect("omit frame");
        transaction
            .commit(Durability::Sync)
            .expect("persist omission");
        let error = service
            .verify(VerifyRequest {
                context: admin_context("stream-omission"),
                deep: true,
            })
            .expect_err("omission must fail closed");
        assert_eq!(error.code, ErrorCode::IntegrityFailure);
    }

    #[test]
    fn stream_cursor_conflicts_and_invalid_frames_leave_no_partial_record() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-conflict.ctxb");
        let (_key, _state, service) = initialized(&path);
        let observation = stream_observation("observation:stream-conflict", "original");
        let manifest = manifest_frame(
            stream_context("request:conflict-manifest", 0x31),
            "stream:conflict",
            std::slice::from_ref(&observation),
        );
        let manifest_ack = service.ingest_frame(manifest).expect("manifest");
        let mut invalid = IngestFrame {
            context: stream_context("request:invalid-item", 0x32),
            stream_id: "stream:conflict".to_owned(),
            position: 1,
            resume_cursor: Some("forged.cursor".to_owned()),
            value: IngestFrameValue::Observation(observation.clone()),
        };
        assert_eq!(
            service
                .ingest_frame(invalid.clone())
                .expect_err("forged cursor")
                .code,
            ErrorCode::InvalidContinuation
        );
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot after abort");
        assert_eq!(
            snapshot
                .scan_prefix(&service.store.streams, STREAM_FRAME_PREFIX)
                .expect("frames")
                .len(),
            1
        );
        drop(snapshot);

        invalid.resume_cursor = Some(manifest_ack.resume_cursor);
        let accepted = service.ingest_frame(invalid.clone()).expect("valid item");
        let mut conflict = invalid;
        conflict.value = IngestFrameValue::Observation(stream_observation(
            "observation:stream-conflict",
            "changed",
        ));
        assert_eq!(
            service
                .ingest_frame(conflict)
                .expect_err("changed retry")
                .code,
            ErrorCode::IdempotencyConflict
        );
        assert_eq!(
            service
                .ingest_frame({
                    let mut exact = IngestFrame {
                        context: stream_context("request:exact-retry", 0x33),
                        stream_id: "stream:conflict".to_owned(),
                        position: 1,
                        resume_cursor: None,
                        value: IngestFrameValue::Observation(observation),
                    };
                    exact.resume_cursor = service
                        .store
                        .load_stream(
                            &service
                                .store
                                .stream_digest("workspace:production", "stream:conflict")
                                .expect("stream digest"),
                        )
                        .expect("load")
                        .expect("stream")
                        .frames
                        .get(&1)
                        .expect("item")
                        .resume_cursor
                        .clone();
                    exact
                })
                .expect("exact retry"),
            accepted
        );
    }

    #[test]
    fn stream_profile_bounds_compression_and_open_registry() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-bounds.ctxb");
        let (_key, _state, service) = initialized(&path);
        let mut compressed = manifest_frame(
            stream_context("request:compressed", 0x41),
            "stream:compressed",
            &[],
        );
        let IngestFrameValue::Manifest(manifest) = &mut compressed.value else {
            panic!("manifest fixture");
        };
        manifest.compression = Compression::Gzip;
        assert_eq!(
            service
                .ingest_frame(compressed)
                .expect_err("compression is not negotiated")
                .code,
            ErrorCode::Unsupported
        );

        let mut oversized = manifest_frame(
            stream_context("request:oversized", 0x42),
            "stream:oversized",
            &[],
        );
        let IngestFrameValue::Manifest(manifest) = &mut oversized.value else {
            panic!("manifest fixture");
        };
        manifest.expected_items = MAX_STREAM_ITEMS + 1;
        assert_eq!(
            service.ingest_frame(oversized).expect_err("item cap").code,
            ErrorCode::ResourceExhausted
        );

        for index in 0..MAX_OPEN_STREAMS {
            let mut context = stream_context(&format!("request:open:{index}"), 0x43);
            context.request.workspace_id = format!("workspace:open:{}", index / 2);
            service
                .ingest_frame(manifest_frame(
                    context,
                    &format!("stream:open:{index}"),
                    &[],
                ))
                .expect("bounded open stream");
        }
        assert_eq!(service.store.stream_states().expect("states").len(), 8);
        let mut same_workspace = stream_context("request:open:workspace-overflow", 0x44);
        same_workspace.request.workspace_id = "workspace:open:0".to_owned();
        assert_eq!(
            service
                .ingest_frame(manifest_frame(
                    same_workspace,
                    "stream:open:workspace-overflow",
                    &[],
                ))
                .expect_err("third workspace stream")
                .code,
            ErrorCode::ResourceExhausted
        );
        let mut another_workspace = stream_context("request:open:overflow", 0x45);
        another_workspace.request.workspace_id = "workspace:open:overflow".to_owned();
        assert_eq!(
            service
                .ingest_frame(manifest_frame(
                    another_workspace,
                    "stream:open:overflow",
                    &[],
                ))
                .expect_err("ninth open stream")
                .code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(service.store.stream_states().expect("states").len(), 8);
    }

    #[test]
    fn expired_stream_lease_is_reclaimed_as_a_durable_successor_before_reuse() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-lease.ctxb");
        let (_key, state, service) = initialized(&path);
        let original = manifest_frame(stream_context("request:lease", 0x46), "stream:lease", &[]);
        let acknowledgement = service
            .ingest_frame(original.clone())
            .expect("open leased stream");
        assert_eq!(
            acknowledgement.lease_expires_at_ms,
            Some(service.store.stream_states().expect("lease state")[0].lease_expires_at_ms)
        );
        let leased = service.store.stream_states().expect("leased state");
        assert_eq!(leased.len(), 1);
        assert!(leased[0].lease_expires_at_ms > unix_time_millis().expect("clock"));
        let before = service
            .store
            .verify_durable_history()
            .expect("durable head before reclaim");
        assert!(
            service
                .store
                .reclaim_expired_streams(leased[0].lease_expires_at_ms)
                .expect("durable lease reclaim")
        );
        assert!(
            service
                .store
                .stream_states()
                .expect("reclaimed state")
                .is_empty()
        );
        let after = service
            .store
            .verify_durable_history()
            .expect("durable head after reclaim");
        assert_eq!(after.generation, before.generation + 1);

        let exact_expired = service
            .ingest_frame(original.clone())
            .expect_err("expired exact retry is deterministic");
        assert_eq!(exact_expired.code, ErrorCode::SnapshotExpired);
        assert_eq!(
            exact_expired.violated_policy.as_deref(),
            Some("stream_lease_expired")
        );
        let changed = service
            .ingest_frame(manifest_frame(
                stream_context("request:lease-changed", 0x46),
                "stream:lease",
                &[stream_observation("observation:changed", "changed")],
            ))
            .expect_err("expired identity cannot be repurposed");
        assert_eq!(changed.code, ErrorCode::IdempotencyConflict);

        // The authority intentionally lags this simulated lost ACK. The next
        // authenticated mutation must prove/reconcile that exact successor
        // before admitting a replacement stream.
        service
            .ingest_frame(manifest_frame(
                stream_context("request:lease-reuse", 0x47),
                "stream:lease-reuse",
                &[],
            ))
            .expect("reconcile reclaim and admit replacement");
        let (_, _, anchored) = state
            .authority
            .load_verified_with_ledger(&state.key.expose_copy())
            .expect("reconciled external authority");
        assert_eq!(
            anchored.generation,
            service
                .store
                .verify_durable_history()
                .expect("current durable head")
                .generation
        );
        drop(service);
        let reopened = ProductionService::open(&path, state).expect("reopen expired reservation");
        assert_eq!(
            reopened
                .ingest_frame(original)
                .expect_err("expired identity survives restart")
                .code,
            ErrorCode::SnapshotExpired
        );
    }

    #[test]
    fn legacy_zero_deadline_stream_migrates_to_an_expired_reservation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("legacy-zero-lease.ctxb");
        let (_key, state, service) = initialized(&path);
        let original = manifest_frame(
            stream_context("request:legacy-lease", 0x48),
            "stream:legacy-lease",
            &[],
        );
        service
            .ingest_frame(original.clone())
            .expect("open leased stream");
        let loaded = service
            .store
            .load_stream(
                &service
                    .store
                    .stream_digest("workspace:production", "stream:legacy-lease")
                    .expect("stream digest"),
            )
            .expect("load stream")
            .expect("stream exists");
        let mut legacy = loaded.state;
        legacy.lease_expires_at_ms = 0;
        let mut legacy_receipt = loaded.receipts[&0].clone();
        legacy_receipt.acknowledgement.lease_expires_at_ms = None;
        let state_key = stream_state_key(&legacy.stream_digest);
        let receipt_key = stream_position_key(STREAM_RECEIPT_PREFIX, &legacy.stream_digest, 0);
        let legacy_bytes = service
            .store
            .seal_stream_value(b"state", &state_key, &legacy, 64 * 1024)
            .expect("legacy state envelope");
        let legacy_receipt_bytes = service
            .store
            .seal_stream_value(
                b"receipt",
                &receipt_key,
                &legacy_receipt,
                MAX_STREAM_FRAME_BYTES,
            )
            .expect("legacy receipt envelope");
        let mut transaction = service.store.engine.begin_write().expect("legacy writer");
        service
            .store
            .reserve_stream_nonces(
                &mut transaction,
                [&legacy_bytes[..], &legacy_receipt_bytes[..]],
            )
            .expect("legacy nonces");
        transaction
            .put(&service.store.streams, state_key, legacy_bytes)
            .expect("legacy state put");
        transaction
            .put(&service.store.streams, receipt_key, legacy_receipt_bytes)
            .expect("legacy receipt put");
        service
            .store
            .stage_durable_successor(&mut transaction)
            .expect("legacy successor");
        transaction
            .commit(Durability::Sync)
            .expect("legacy state commit");
        drop(service);
        let reopened = ProductionService::open(&path, state).expect("pre-lease store reopens");
        assert_eq!(
            reopened
                .ingest_frame(original)
                .expect_err("legacy stream migrates to expired reservation")
                .code,
            ErrorCode::SnapshotExpired
        );
        reopened.store.verify().expect("legacy reclaim verifies");
    }

    #[test]
    fn stream_ciphertext_tamper_and_injected_nonce_reuse_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stream-crypto.ctxb");
        let (_key, _state, service) = initialized(&path);
        let envelope_a = service
            .store
            .seal_stream_bytes_with_nonce(b"test", b"record:test", b"secret", [1; 24])
            .expect("test envelope A");
        let envelope_b = service
            .store
            .seal_stream_bytes_with_nonce(b"test", b"record:test", b"secret", [2; 24])
            .expect("test envelope B");
        assert_ne!(envelope_a, envelope_b);
        assert!(reject_duplicate_envelope_nonces([&envelope_a, &envelope_a]).is_err());
        let mut transaction = service.store.engine.begin_write().expect("nonce writer");
        service
            .store
            .reserve_stream_nonces(&mut transaction, [&envelope_a])
            .expect("first nonce reservation");
        assert!(
            service
                .store
                .reserve_stream_nonces(&mut transaction, [&envelope_a])
                .is_err()
        );
        transaction.rollback().expect("nonce replay rollback");

        let manifest = manifest_frame(stream_context("request:tamper", 0x51), "stream:tamper", &[]);
        service.ingest_frame(manifest).expect("manifest");
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        let entry = snapshot
            .scan_prefix(&service.store.streams, STREAM_FRAME_PREFIX)
            .expect("frames")
            .into_iter()
            .next()
            .expect("frame");
        drop(snapshot);
        let mut tampered = entry.value;
        let last = tampered.last_mut().expect("ciphertext byte");
        *last ^= 1;
        let mut transaction = service.store.engine.begin_write().expect("tamper writer");
        transaction
            .put(&service.store.streams, entry.key, tampered)
            .expect("tamper frame");
        transaction
            .commit(Durability::Sync)
            .expect("persist tamper");
        let error = service
            .verify(VerifyRequest {
                context: admin_context("stream-tamper"),
                deep: true,
            })
            .expect_err("tamper must fail closed");
        assert_eq!(error.code, ErrorCode::IntegrityFailure);
    }

    #[test]
    fn omitted_and_tampered_frame_receipt_nonce_and_history_records_fail_closed() {
        #[derive(Clone, Copy, Debug)]
        enum RecordClass {
            Frame,
            Receipt,
            Nonce,
            History,
        }

        for record_class in [
            RecordClass::Frame,
            RecordClass::Receipt,
            RecordClass::Nonce,
            RecordClass::History,
        ] {
            for omit in [true, false] {
                let directory = tempfile::tempdir().expect("temporary directory");
                let path = directory
                    .path()
                    .join(format!("stream-mutation-{record_class:?}-{omit}.ctxb"));
                let (_key, _state, service) = initialized(&path);
                service
                    .ingest_frame(manifest_frame(
                        stream_context("request:mutation", 0x92),
                        "stream:mutation",
                        &[],
                    ))
                    .expect("anchored manifest");

                let (keyspace, prefix): (&Keyspace, &[u8]) = match record_class {
                    RecordClass::Frame => (&service.store.streams, STREAM_FRAME_PREFIX),
                    RecordClass::Receipt => (&service.store.streams, STREAM_RECEIPT_PREFIX),
                    RecordClass::Nonce => (&service.store.streams, STREAM_NONCE_PREFIX),
                    RecordClass::History => {
                        (&service.store.durable_history, DURABLE_HISTORY_PREFIX)
                    }
                };
                let snapshot = service
                    .store
                    .engine
                    .begin_read(SnapshotSelector::Latest)
                    .expect("mutation snapshot");
                let entry = snapshot
                    .scan_prefix(keyspace, prefix)
                    .expect("mutation records")
                    .into_iter()
                    .last()
                    .expect("mutation target");
                drop(snapshot);

                let mut transaction = service.store.engine.begin_write().expect("mutation writer");
                if omit {
                    transaction
                        .delete(keyspace, entry.key)
                        .expect("omit durable record");
                } else {
                    let mut value = entry.value;
                    let byte = value.last_mut().expect("non-empty durable record");
                    *byte ^= 1;
                    transaction
                        .put(keyspace, entry.key, value)
                        .expect("tamper durable record");
                }
                transaction
                    .commit(Durability::Sync)
                    .expect("persist mutation");

                let error = service
                    .verify(VerifyRequest {
                        context: admin_context("stream-mutation"),
                        deep: true,
                    })
                    .expect_err("omission or tampering must fail closed");
                assert_eq!(
                    error.code,
                    ErrorCode::IntegrityFailure,
                    "unexpected result for {record_class:?}, omit={omit}"
                );
            }
        }
    }

    #[test]
    fn observation_only_graph_lags_semantics_and_survives_restart_and_lost_ack() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("policy-graph-observation.ctxb");
        let (_key, state, service) = initialized(&path);
        let initial = service.store.policy_graph().expect("initial policy graph");
        assert_eq!(initial.generation, 0);
        assert_eq!(initial.archive_commit_seq, 0);
        assert!(initial.histories.is_empty());

        state.authority.fail_next_backend_write_for_test();
        let request = request("idempotency:graph-lost-ack", "observation:graph-lost-ack");
        let error = service
            .observe(request.clone())
            .expect_err("state-head acknowledgement is injected lost");
        assert_eq!(error.code, ErrorCode::Unavailable);
        let committed = service
            .store
            .policy_graph()
            .expect("graph commits with canonical archive");
        assert_eq!(committed.generation, 1);
        assert_eq!(committed.archive_commit_seq, 1);
        assert_eq!(committed.watermarks.journal, 1);
        assert_eq!(committed.watermarks.semantic, 0);
        assert_eq!(committed.watermarks.graph, 0);
        assert!(committed.histories.is_empty());

        let replay = service.observe(request).expect("lost ACK reconciliation");
        assert!(replay.replayed);
        assert_eq!(
            service.store.policy_graph().expect("reconciled graph"),
            committed
        );
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("restart with policy graph");
        assert_eq!(
            reopened.store.policy_graph().expect("restart graph"),
            committed
        );
        let status = reopened
            .get_status(GetStatusRequest {
                context: graph_context(
                    "status:graph-lag",
                    "subject:production",
                    [Capability::Admin],
                ),
            })
            .expect("graph-aware status");
        assert_eq!(status.commit_seq, 1);
        assert_eq!(status.watermarks.graph, 0);
        assert!(
            status
                .profile
                .contains("rebuildable-persistent-policy-graph-projection")
        );
        assert!(
            status
                .profile
                .contains("nonclaims=core-native-graph,indexed-graph")
        );
    }

    #[test]
    fn graph_key_omission_and_ciphertext_independent_tamper_change_the_durable_root() {
        for omit in [true, false] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory
                .path()
                .join(format!("policy-graph-root-{omit}.ctxb"));
            let (_key, _state, service) = initialized(&path);
            service
                .observe(request("idempotency:graph-root", "observation:graph-root"))
                .expect("commit graph root fixture");
            let snapshot = service
                .store
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("graph snapshot");
            let mut bytes = snapshot
                .get(&service.store.graph, POLICY_GRAPH_KEY)
                .expect("graph read")
                .expect("graph exists");
            drop(snapshot);
            let mut transaction = service.store.engine.begin_write().expect("graph writer");
            if omit {
                transaction
                    .delete(&service.store.graph, POLICY_GRAPH_KEY.to_vec())
                    .expect("omit graph");
            } else {
                let byte = bytes.last_mut().expect("graph byte");
                *byte ^= 1;
                transaction
                    .put(&service.store.graph, POLICY_GRAPH_KEY.to_vec(), bytes)
                    .expect("tamper graph");
            }
            transaction
                .commit(Durability::Sync)
                .expect("persist adversarial graph change");
            let error = service
                .store
                .verify()
                .expect_err("durable root rejects graph omission/tamper");
            assert_eq!(error.0.code, ErrorCode::IntegrityFailure);
        }
    }

    #[test]
    fn stale_future_and_wrong_archive_graph_manifests_fail_exact_rebuild() {
        for case in ["stale", "future", "wrong_archive"] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory
                .path()
                .join(format!("policy-graph-manifest-{case}.ctxb"));
            let (_key, _state, service) = initialized(&path);
            let stale = service.store.policy_graph().expect("generation-zero graph");
            service
                .observe(request("idempotency:manifest", "observation:manifest"))
                .expect("advance canonical projection");
            let mut graph = service.store.policy_graph().expect("current graph");
            match case {
                "stale" => graph = stale,
                "future" => graph.generation = graph.generation.saturating_add(1),
                "wrong_archive" => graph.archive_digest = "ef".repeat(32),
                _ => unreachable!(),
            }
            graph.digest = policy_graph_digest(&graph).expect("adversarial graph digest");
            graph.checksum = service
                .store
                .record_checksum(b"production-policy-graph-v1", &graph)
                .expect("adversarial graph checksum");
            let mut transaction = service.store.engine.begin_write().expect("graph writer");
            transaction
                .put(
                    &service.store.graph,
                    POLICY_GRAPH_KEY.to_vec(),
                    canonical_bytes(&graph).expect("graph bytes"),
                )
                .expect("stage graph manifest");
            transaction
                .commit(Durability::Sync)
                .expect("persist graph manifest");
            let snapshot = service
                .store
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("adversarial snapshot");
            let error = service
                .store
                .policy_graph_from(&snapshot)
                .expect_err("manifest must rebuild exactly");
            assert_eq!(error.0.code, ErrorCode::IntegrityFailure);
        }
    }

    #[test]
    fn absent_graph_migrates_only_an_exact_legacy_generation_zero_store() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("policy-graph-legacy-fresh.ctxb");
        let (_key, _state, service) = initialized(&path);
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("fresh snapshot");
        let mut legacy = service
            .store
            .durable_head_from(&snapshot)
            .expect("fresh durable head");
        legacy.state_root_version = None;
        legacy.state_root = service
            .store
            .compute_legacy_state_root(&snapshot)
            .expect("legacy state root");
        legacy.digest = service
            .store
            .durable_digest(&legacy)
            .expect("legacy durable digest");
        legacy.checksum = service
            .store
            .record_checksum(b"production-durable-head-v1", &legacy)
            .expect("legacy durable checksum");
        drop(snapshot);
        let mut transaction = service.store.engine.begin_write().expect("legacy writer");
        transaction
            .delete(&service.store.graph, POLICY_GRAPH_KEY.to_vec())
            .expect("remove new graph");
        transaction
            .delete(&service.store.meta, NON_EVENT_RECEIPT_COUNT_KEY.to_vec())
            .expect("remove v2 receipt count");
        transaction
            .put(
                &service.store.meta,
                DURABLE_HEAD_KEY.to_vec(),
                canonical_bytes(&legacy).expect("legacy head bytes"),
            )
            .expect("write legacy head");
        transaction
            .put(
                &service.store.durable_history,
                durable_history_key(0),
                canonical_bytes(&legacy).expect("legacy history bytes"),
            )
            .expect("write legacy history");
        transaction
            .commit(Durability::Sync)
            .expect("persist exact legacy fixture");
        service
            .store
            .ensure_current_format()
            .expect("exact fresh legacy graph migration");
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("migrated durable history")
                .generation,
            1
        );
        assert_eq!(
            service
                .store
                .policy_graph()
                .expect("migrated graph")
                .generation,
            0
        );

        let changed_path = directory.path().join("policy-graph-legacy-changed.ctxb");
        let (_key, _state, changed) = initialized(&changed_path);
        changed
            .observe(request("idempotency:migration", "observation:migration"))
            .expect("change production generation");
        let mut transaction = changed.store.engine.begin_write().expect("changed writer");
        transaction
            .delete(&changed.store.graph, POLICY_GRAPH_KEY.to_vec())
            .expect("remove changed graph");
        transaction
            .commit(Durability::Sync)
            .expect("persist missing changed graph");
        let error = changed
            .store
            .ensure_current_format()
            .expect_err("changed production store must not migrate implicitly");
        assert_eq!(error.0.code, ErrorCode::IntegrityFailure);

        let unknown_path = directory.path().join("policy-graph-legacy-unknown.ctxb");
        let (_key, _state, unknown) = initialized(&unknown_path);
        let snapshot = unknown
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("unknown migration snapshot");
        let mut legacy = unknown
            .store
            .durable_head_from(&snapshot)
            .expect("unknown migration head");
        legacy.state_root_version = None;
        legacy.state_root = unknown
            .store
            .compute_legacy_state_root(&snapshot)
            .expect("unknown migration legacy root");
        legacy.digest = unknown
            .store
            .durable_digest(&legacy)
            .expect("unknown migration digest");
        legacy.checksum = unknown
            .store
            .record_checksum(b"production-durable-head-v1", &legacy)
            .expect("unknown migration checksum");
        drop(snapshot);
        let mut transaction = unknown
            .store
            .engine
            .begin_write()
            .expect("unknown migration writer");
        transaction
            .delete(&unknown.store.graph, POLICY_GRAPH_KEY.to_vec())
            .expect("remove graph");
        transaction
            .delete(&unknown.store.meta, NON_EVENT_RECEIPT_COUNT_KEY.to_vec())
            .expect("remove count");
        transaction
            .put(
                &unknown.store.meta,
                DURABLE_HEAD_KEY.to_vec(),
                canonical_bytes(&legacy).expect("legacy bytes"),
            )
            .expect("legacy head");
        transaction
            .put(
                &unknown.store.durable_history,
                durable_history_key(0),
                canonical_bytes(&legacy).expect("legacy history bytes"),
            )
            .expect("legacy history");
        transaction
            .put(&unknown.store.meta, b"rogue".to_vec(), b"value".to_vec())
            .expect("inject unknown metadata");
        transaction
            .commit(Durability::Sync)
            .expect("persist unknown migration fixture");
        let error = unknown
            .store
            .ensure_current_format()
            .expect_err("unknown metadata prevents implicit migration");
        assert_eq!(error.0.code, ErrorCode::IntegrityFailure);
    }

    #[test]
    fn nonzero_legacy_root_migrates_to_v2_without_losing_event_or_runtime_receipt() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("legacy-v1-nonzero.ctxb");
        let (key, state, service) = initialized(&path);
        service
            .observe(request("idempotency:legacy-v1", "observation:legacy-v1"))
            .expect("legacy event fixture");
        let postflight_request = runtime_postflight_request(
            "postflight:legacy-v1",
            runtime_context(
                "request:postflight:legacy-v1",
                "workspace:production",
                "subject:production",
            ),
        );
        let first_receipt = service
            .postflight(postflight_request.clone())
            .expect("legacy receipt fixture");
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("current snapshot");
        let mut legacy = service
            .store
            .durable_head_from(&snapshot)
            .expect("current durable head");
        assert!(legacy.generation > 0);
        let terminal_generation = legacy.generation;
        legacy.state_root_version = None;
        drop(snapshot);

        let mut transaction = service.store.engine.begin_write().expect("legacy writer");
        transaction
            .delete(&service.store.meta, NON_EVENT_RECEIPT_COUNT_KEY.to_vec())
            .expect("remove v2 count");
        legacy.state_root = service
            .store
            .compute_state_root_v1(&transaction)
            .expect("exact prior root");
        legacy.digest = service
            .store
            .durable_digest(&legacy)
            .expect("legacy digest");
        legacy.checksum = service
            .store
            .record_checksum(b"production-durable-head-v1", &legacy)
            .expect("legacy checksum");
        transaction
            .put(
                &service.store.meta,
                DURABLE_HEAD_KEY.to_vec(),
                canonical_bytes(&legacy).expect("legacy head bytes"),
            )
            .expect("write legacy head");
        transaction
            .put(
                &service.store.durable_history,
                durable_history_key(terminal_generation),
                canonical_bytes(&legacy).expect("legacy history bytes"),
            )
            .expect("write legacy terminal history");
        transaction
            .commit(Durability::Sync)
            .expect("persist exact legacy format");
        let projection = service
            .store
            .current_projection()
            .expect("current projection");
        drop(service);
        drop(state);

        // Recreate the test authority exactly as an older deployment would
        // have anchored this authenticated legacy terminal.
        std::fs::remove_file(&path).expect("replace test archive authority");
        let authority = crate::state_head::StateHeadStore::memory(&path).expect("legacy authority");
        authority
            .bootstrap_with_ledger(
                &key.expose_copy(),
                &projection.archive,
                terminal_generation,
                &legacy.digest,
            )
            .expect("anchor exact legacy terminal");
        let reopened_state = crate::load_state_with_authority(
            TokenKey::new(key.expose_copy()).expect("reopen key"),
            authority,
        )
        .expect("load legacy authority");
        let reopened =
            ProductionService::open(&path, reopened_state).expect("migrate and reconcile v2");
        let migrated = reopened
            .store
            .verify_durable_history()
            .expect("migrated durable history");
        assert_eq!(migrated.generation, terminal_generation + 1);
        assert_eq!(migrated.state_root_version, Some(STATE_ROOT_VERSION));
        assert_eq!(reopened.store.events().expect("retained event").len(), 1);
        let replay = reopened
            .postflight(postflight_request)
            .expect("retained runtime receipt replay");
        assert_eq!(
            replay.payload["receipt_id"],
            first_receipt.payload["receipt_id"]
        );
        assert_eq!(replay.payload["replayed"], true);
        reopened
            .store
            .verify()
            .expect("fully verified v2 migration");
    }

    #[test]
    fn semantic_graph_is_policy_first_differential_and_tracks_correction_retraction() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("semantic-policy-graph.ctxb");
        let archive = semantic_graph_archive();
        let (_key, state, service) = initialized_with_archive(&path, &archive);
        let context = graph_context(
            "request:semantic-graph",
            "subject:production",
            [
                Capability::ReadMemory,
                Capability::Traverse,
                Capability::Correct,
                Capability::Forget,
            ],
        );
        let traversal_request = TraverseRequest {
            context: context.clone(),
            start_ids: vec!["node:a".to_owned()],
            direction: TraverseDirection::Outgoing,
            predicate_ids: BTreeSet::from(["next".to_owned()]),
            max_hops: 3,
            max_nodes: 10,
            at_commit: None,
        };
        let base = service
            .traverse(traversal_request.clone())
            .expect("differential graph traversal");
        assert_eq!(base.node_ids, ["node:b", "node:c"]);
        assert_eq!(base.authorized_candidates, 2);

        // A wrong-kind policy-hidden record must remain PermissionDenied;
        // neither its kind nor its dangling target may influence the result.
        let hidden = service
            .get_node(GetMemoryRequest {
                context: context.clone(),
                record_id: "edge:hidden-dangling".to_owned(),
                at_commit: None,
            })
            .expect_err("protected wrong-kind record stays hidden");
        assert_eq!(hidden.code, ErrorCode::PermissionDenied);

        let replacement = MemoryDocument {
            id: "node:a-v2".to_owned(),
            kind: MemoryRecordKind::Node,
            access: AccessPolicy {
                workspace_id: "workspace:production".to_owned(),
                scopes: BTreeSet::from(["project:production".to_owned()]),
                owners: BTreeSet::from(["subject:production".to_owned()]),
                audience: BTreeSet::from(["subject:production".to_owned()]),
                audience_purpose_grants: BTreeMap::from([(
                    "subject:production".to_owned(),
                    BTreeSet::from(["assist".to_owned()]),
                )]),
                purposes: BTreeSet::new(),
                sensitivity: Sensitivity::Private,
                consent: Consent::Granted,
                retrievable: true,
            },
            valid_time: DomainTimeRange::default(),
            lifecycle: MemoryLifecycle::Active,
            links: MemoryLinks {
                supersedes: BTreeSet::from(["node:a".to_owned()]),
                ..MemoryLinks::default()
            },
            value: serde_json::json!({"fixture": "corrected node"}),
            search_text: Some("corrected node".to_owned()),
            vector: None,
            attributes: BTreeMap::new(),
        };
        let correction = CorrectRequest {
            context: context.clone(),
            idempotency_key: "idempotency:semantic-graph-correct".to_owned(),
            target_id: "node:a".to_owned(),
            replacement,
        };
        state.authority.fail_next_backend_write_for_test();
        let error = service
            .correct(correction.clone())
            .expect_err("semantic graph Fjall commit loses authority ACK");
        assert_eq!(error.code, ErrorCode::Unavailable);
        let after_lost_ack = service
            .store
            .policy_graph()
            .expect("committed semantic graph");
        assert_eq!(after_lost_ack.generation, 1);
        assert_eq!(after_lost_ack.archive_commit_seq, 2);
        assert_eq!(after_lost_ack.watermarks.graph, 2);
        assert!(after_lost_ack.histories.contains_key("node:a-v2"));
        let replay = service
            .correct(correction)
            .expect("reconcile semantic graph ACK");
        assert!(replay.replayed);

        let target_timeline = service
            .get_timeline(GetTimelineRequest {
                context: context.clone(),
                record_id: "node:a".to_owned(),
                expected_kind: MemoryRecordKind::Node,
                at_commit: None,
                max_revisions: 10,
            })
            .expect("corrected target history");
        assert_eq!(target_timeline.revisions.len(), 2);
        assert_eq!(
            target_timeline.revisions[1].document.lifecycle,
            MemoryLifecycle::Superseded
        );

        service
            .forget(ForgetRequest {
                context: context.clone(),
                idempotency_key: "idempotency:semantic-graph-retract".to_owned(),
                target_id: "node:b".to_owned(),
                mode: ForgetMode::Retract,
                reason: String::new(),
            })
            .expect("retract graph node");
        let graph = service.store.policy_graph().expect("retracted graph");
        assert_eq!(graph.generation, 2);
        assert_eq!(graph.archive_commit_seq, 3);
        assert_eq!(graph.watermarks.graph, 3);
        assert_eq!(
            graph.histories["node:b"]
                .last()
                .expect("node b head")
                .record
                .lifecycle,
            GraphLifecycle::Retracted
        );

        let mut historical = traversal_request;
        historical.at_commit = Some(1);
        let historical = service
            .traverse(historical)
            .expect("historical graph remains exact under current lifecycle overlay");
        assert!(historical.node_ids.is_empty());
        assert_eq!(historical.snapshot_seq, 1);
        let current = service
            .traverse(TraverseRequest {
                context,
                start_ids: vec!["node:a".to_owned()],
                direction: TraverseDirection::Outgoing,
                predicate_ids: BTreeSet::new(),
                max_hops: 1,
                max_nodes: 10,
                at_commit: None,
            })
            .expect_err("superseded root is not active");
        assert_eq!(current.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn production_suppression_survives_lost_ack_reopen_and_overlays_historical_reads() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("semantic-suppression.ctxb");
        let archive = semantic_graph_archive();
        let (_key, state, service) = initialized_with_archive(&path, &archive);
        let request = semantic_control_request(
            "production-suppress",
            "node:a",
            serde_json::json!({"schema_version": 1}),
        );

        state.authority.fail_next_backend_write_for_test();
        let unavailable = service
            .suppress(request.clone())
            .expect_err("Fjall commit with lost external-head ACK");
        assert_eq!(unavailable.code, ErrorCode::Unavailable);
        let quarantined = service
            .get_node(GetMemoryRequest {
                context: graph_context(
                    "request:suppression-awaits-authority",
                    "subject:production",
                    [Capability::ReadMemory],
                ),
                record_id: "node:a".to_owned(),
                at_commit: Some(1),
            })
            .expect_err("old publication is quarantined after durable suppression");
        assert_eq!(quarantined.code, ErrorCode::Unavailable);
        assert_eq!(
            quarantined.violated_policy.as_deref(),
            Some("semantic_control_publication")
        );
        #[cfg(feature = "current-server")]
        assert_eq!(service.readiness().state, HealthState::NotReady);
        let graph = service
            .store
            .policy_graph()
            .expect("durable suppressed graph");
        assert_eq!(graph.archive_commit_seq, 2);
        assert_eq!(graph.histories["node:a"].len(), 2);
        assert_eq!(
            graph.histories["node:a"]
                .last()
                .expect("suppressed revision")
                .record
                .lifecycle,
            GraphLifecycle::Suppressed
        );

        let replay = service
            .suppress(request.clone())
            .expect("retry reconciles and replays");
        assert!(replay.replayed);
        let event = service
            .store
            .events()
            .expect("control event")
            .pop()
            .expect("one event");
        let receipt_text = String::from_utf8(event.response_bytes).expect("JSON receipt");
        assert!(!receipt_text.contains("fixture"));
        assert!(!receipt_text.contains("node:a"));

        for at_commit in [None, Some(1)] {
            let denied = service
                .get_node(GetMemoryRequest {
                    context: graph_context(
                        "request:suppressed-read",
                        "subject:production",
                        [Capability::ReadMemory],
                    ),
                    record_id: "node:a".to_owned(),
                    at_commit,
                })
                .expect_err("current suppression overlays old semantic snapshots");
            assert_eq!(denied.code, ErrorCode::PermissionDenied);
        }

        let mut changed_authority = request.clone();
        changed_authority.context.session_id = Some("session:changed-authority".to_owned());
        assert_eq!(
            service
                .suppress(changed_authority)
                .expect_err("same operation identity with changed authority conflicts")
                .code,
            ErrorCode::IdempotencyConflict
        );
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("reopen suppressed state");
        let denied = reopened
            .get_node(GetMemoryRequest {
                context: graph_context(
                    "request:suppressed-reopen",
                    "subject:production",
                    [Capability::ReadMemory],
                ),
                record_id: "node:a".to_owned(),
                at_commit: Some(1),
            })
            .expect_err("restart preserves the current suppression overlay");
        assert_eq!(denied.code, ErrorCode::PermissionDenied);
        let replay = reopened.suppress(request).expect("reopen replay");
        assert!(replay.replayed);
    }

    #[test]
    fn production_semantic_controls_authorize_before_malformed_parameters() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("semantic-control-auth.ctxb");
        let archive = semantic_graph_archive();
        let (_key, _state, service) = initialized_with_archive(&path, &archive);
        let mut request = semantic_control_request(
            "unauthorized-malformed-control",
            "node:a",
            serde_json::json!({"protected": {"malformed": true}}),
        );
        request.context.capability_grants.clear();
        assert_eq!(
            service
                .suppress(request)
                .expect_err("capability denial wins before parameters")
                .code,
            ErrorCode::Unauthorized
        );
        assert!(service.store.events().expect("no events").is_empty());
    }

    #[test]
    fn production_audience_and_shared_controls_publish_atomic_policy_revisions() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("semantic-policy-controls.ctxb");
        let archive = semantic_graph_archive();
        let (_key, _state, service) = initialized_with_archive(&path, &archive);

        let mut change = semantic_control_request(
            "change-audience-production",
            "node:a",
            serde_json::json!({
                "schema_version": 1,
                "audiences": ["subject:production", "team:one"],
                "audience_purpose_grants": {
                    "subject:production": ["assist"],
                    "team:one": ["assist"]
                }
            }),
        );
        change
            .context
            .request
            .audiences
            .insert("team:one".to_owned());
        service.change_audience(change).expect("change audience");

        let mut revoke = semantic_control_request(
            "revoke-first-team",
            "node:a",
            serde_json::json!({
                "schema_version": 1,
                "shared_audience_id": "team:one"
            }),
        );
        revoke
            .context
            .request
            .audiences
            .insert("team:one".to_owned());
        service
            .revoke_shared_memory(revoke)
            .expect("revoke first audience");

        let mut publish = semantic_control_request(
            "publish-second-team",
            "node:a",
            serde_json::json!({
                "schema_version": 1,
                "shared_audience_id": "team:two",
                "purposes": ["assist"]
            }),
        );
        publish
            .context
            .request
            .audiences
            .insert("team:two".to_owned());
        service
            .publish_to_shared_memory(publish)
            .expect("publish second audience");

        let mut revoke = semantic_control_request(
            "revoke-second-team",
            "node:a",
            serde_json::json!({
                "schema_version": 1,
                "shared_audience_id": "team:two"
            }),
        );
        revoke
            .context
            .request
            .audiences
            .insert("team:two".to_owned());
        service
            .revoke_shared_memory(revoke)
            .expect("revoke second audience");

        let graph = service.store.policy_graph().expect("policy graph");
        let history = &graph.histories["node:a"];
        assert_eq!(history.len(), 5);
        let current = &history.last().expect("current policy").record.access;
        assert_eq!(
            current.audience,
            BTreeSet::from(["subject:production".to_owned()])
        );
        assert_eq!(
            current.audience_purpose_grants,
            BTreeMap::from([(
                "subject:production".to_owned(),
                BTreeSet::from(["assist".to_owned()])
            )])
        );
        let operations: BTreeSet<_> = service
            .store
            .events()
            .expect("control events")
            .into_iter()
            .map(|event| event.operation)
            .collect();
        assert_eq!(
            operations,
            BTreeSet::from([
                Operation::ChangeAudience,
                Operation::PublishToSharedMemory,
                Operation::RevokeSharedMemory
            ])
        );
    }

    #[test]
    fn hidden_non_edge_predicate_miss_and_unrelated_records_do_not_consume_observable_work() {
        let context = graph_context(
            "request:traversal-work",
            "subject:production",
            [Capability::Traverse],
        );
        let request = TraverseRequest {
            context,
            start_ids: vec!["node:a".to_owned()],
            direction: TraverseDirection::Outgoing,
            predicate_ids: BTreeSet::from(["next".to_owned()]),
            max_hops: 1,
            max_nodes: 10,
            at_commit: Some(1),
        };
        let base = VerifiedPolicyGraph::new(
            project_archive_metadata(&traversal_non_influence_archive(false), 0)
                .expect("base graph"),
        )
        .expect("base graph index")
        .traverse_with_work_limit(&request, 1)
        .expect("one observable edge fits exact reduced budget");
        let padded = VerifiedPolicyGraph::new(
            project_archive_metadata(&traversal_non_influence_archive(true), 0)
                .expect("padded graph"),
        )
        .expect("padded graph index")
        .traverse_with_work_limit(&request, 1)
        .expect("irrelevant records remain outside work budget");
        assert_eq!(
            canonical_bytes(&base).expect("base bytes"),
            canonical_bytes(&padded).expect("padded bytes")
        );
        let indexed = VerifiedPolicyGraph::new(
            project_archive_metadata(&traversal_non_influence_archive(false), 0)
                .expect("duplicate-root graph"),
        )
        .expect("duplicate-root index");
        let mut duplicate_roots = request.clone();
        duplicate_roots.start_ids = vec!["node:a".to_owned(); 1_000];
        assert_eq!(
            indexed
                .traverse_with_work_limit(&duplicate_roots, 1)
                .expect("duplicate roots are charged once"),
            base
        );
    }

    #[test]
    fn current_and_historical_policy_both_gate_before_content_materialization() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("historical-policy-graph.ctxb");
        let archive = historical_policy_archive();
        let (_key, _state, service) = initialized_with_archive(&path, &archive);
        let owner = graph_context(
            "request:historical-owner",
            "subject:production",
            [Capability::ReadMemory],
        );
        let historical = service
            .get_node(GetMemoryRequest {
                context: owner.clone(),
                record_id: "node:policy".to_owned(),
                at_commit: Some(1),
            })
            .expect_err("current policy revokes former audience at old snapshots");
        assert_eq!(historical.code, ErrorCode::PermissionDenied);
        let historical_timeline = service
            .get_timeline(GetTimelineRequest {
                context: owner.clone(),
                record_id: "node:policy".to_owned(),
                expected_kind: MemoryRecordKind::Node,
                at_commit: Some(1),
                max_revisions: 10,
            })
            .expect_err("timeline also applies the current policy overlay");
        assert_eq!(historical_timeline.code, ErrorCode::PermissionDenied);
        let current = service
            .get_node(GetMemoryRequest {
                context: owner.clone(),
                record_id: "node:policy".to_owned(),
                at_commit: None,
            })
            .expect_err("current policy is hidden from the former audience");
        assert_eq!(current.code, ErrorCode::PermissionDenied);
        let timeline = service
            .get_timeline(GetTimelineRequest {
                context: owner,
                record_id: "node:policy".to_owned(),
                expected_kind: MemoryRecordKind::Node,
                at_commit: None,
                max_revisions: 10,
            })
            .expect_err("former audience cannot enumerate retained history");
        assert_eq!(timeline.code, ErrorCode::PermissionDenied);

        let current_owner = graph_context(
            "request:historical-current-owner",
            "subject:hidden",
            [Capability::ReadMemory],
        );
        assert_eq!(
            service
                .get_node(GetMemoryRequest {
                    context: current_owner,
                    record_id: "node:policy".to_owned(),
                    at_commit: None,
                })
                .expect("current policy owner")
                .revision,
            2
        );
    }

    #[test]
    fn current_tombstone_overlay_hides_every_retained_snapshot() {
        let mut archive: serde_json::Value =
            serde_json::from_slice(&historical_policy_archive()).expect("historical archive");
        archive["tombstones"] = serde_json::json!({
            "node:policy": {"target": "node:policy", "effective_seq": 2}
        });
        let graph = project_archive_metadata(
            &serde_json::to_vec(&archive).expect("tombstoned archive"),
            0,
        )
        .expect("tombstoned graph");
        let principal = graph_context(
            "graph:tombstone-history",
            "subject:production",
            [Capability::ReadMemory],
        );
        assert_eq!(
            graph
                .authorize_record(
                    "node:policy",
                    GraphRecordKind::Node,
                    1,
                    &principal.request,
                    true,
                )
                .expect_err("an old snapshot cannot bypass current deletion")
                .code,
            ErrorCode::NotFound
        );
        assert_eq!(
            graph
                .authorize_record(
                    "node:policy",
                    GraphRecordKind::Node,
                    2,
                    &principal.request,
                    true,
                )
                .expect_err("effective tombstone hides current snapshot")
                .code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn exact_retry_and_restart_replay_the_fjall_receipt() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("restart.ctxb");
        let (_key, state, service) = initialized(&path);
        let request = request("idempotency:restart", "observation:restart");
        let first = service.observe(request.clone()).expect("first commit");
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("ledger snapshot");
        let event_bytes = snapshot
            .get(&service.store.events, &event_key(1))
            .expect("event read")
            .expect("event exists");
        let event_text = String::from_utf8(event_bytes).expect("event metadata JSON");
        assert!(!event_text.contains("fjall durable projection"));
        assert!(!event_text.contains("observation:restart"));
        assert!(event_text.len() < 4_096);
        let event: StoredEvent = serde_json::from_str(&event_text).expect("stored event");
        let public_request = Zeroizing::new(canonical_bytes(&request).expect("canonical request"));
        assert_ne!(
            event.request_digest,
            unkeyed_legacy_digest(Operation::Observe.domain(), &public_request),
            "low-entropy request material must not reproduce the keyed digest"
        );
        assert_eq!(
            format!("{:?}", service.store),
            "ProductionStore { backend: \"fjall\", mac_key: \"[REDACTED]\", stream_aead_key: \"[REDACTED]\", .. }"
        );
        let projections = snapshot
            .scan_prefix(&service.store.meta, CURRENT_PROJECTION_KEY)
            .expect("current projection scan");
        assert_eq!(projections.len(), 1);
        drop(snapshot);
        let replay = service.observe(request.clone()).expect("exact retry");
        assert!(replay.replayed);
        assert_eq!(replay.commit_seq, first.commit_seq);
        assert_eq!(replay.request_digest, first.request_digest);
        assert_eq!(replay.watermarks, first.watermarks);
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("replay Fjall on restart");
        let restarted_replay = reopened.observe(request).expect("retry after restart");
        assert!(restarted_replay.replayed);
        assert_eq!(restarted_replay.commit_seq, first.commit_seq);
        assert_eq!(restarted_replay.request_digest, first.request_digest);
        assert_eq!(restarted_replay.watermarks, first.watermarks);
        reopened.store.verify().expect("deep Fjall verification");
    }

    #[test]
    fn changed_request_conflicts_with_the_durable_idempotency_index() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("conflict.ctxb");
        let (_key, _state, service) = initialized(&path);
        service
            .observe(request("idempotency:conflict", "observation:first"))
            .expect("first commit");
        let error = service
            .observe(request("idempotency:conflict", "observation:changed"))
            .expect_err("changed request must conflict");
        assert_eq!(error.code, ErrorCode::IdempotencyConflict);
    }

    #[test]
    fn identical_caller_keys_are_isolated_between_tenants() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("tenant-isolation.ctxb");
        let (_key, _state, service) = initialized(&path);
        let first = service
            .observe(request("shared-low-entropy-key", "observation:tenant-a"))
            .expect("tenant A commit");

        let mut second = request("shared-low-entropy-key", "observation:tenant-b");
        second.context.workspace_id = "workspace:other".into();
        second.context.subject_id = "subject:other".into();
        second.context.audiences = BTreeSet::from(["subject:other".into()]);
        second.access.workspace_id = "workspace:other".into();
        second.access.owners = BTreeSet::from(["subject:other".into()]);
        second.access.audience = BTreeSet::from(["subject:other".into()]);
        let second = service.observe(second).expect("tenant B commit");
        assert_eq!(first.commit_seq, 1);
        assert_eq!(second.commit_seq, 2);
        assert_eq!(service.store.events().expect("events").len(), 2);
    }

    #[test]
    fn fjall_commit_is_reconciled_after_lost_state_head_acknowledgement() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("lost-ack.ctxb");
        let (_key, state, service) = initialized(&path);
        let request = request("idempotency:lost-ack", "observation:lost-ack");
        state.authority.fail_next_backend_write_for_test();
        let error = service
            .observe(request.clone())
            .expect_err("authority acknowledgement is injected lost");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);

        let recovered = service
            .observe(request)
            .expect("exact retry reconciles committed Fjall projection");
        assert_eq!(recovered.commit_seq, 1);
        assert_eq!(service.store.events().expect("events").len(), 1);
    }

    #[test]
    fn corrupted_event_is_rejected_before_projection_publication() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("corrupt.ctxb");
        let (_key, _state, service) = initialized(&path);
        service
            .observe(request("idempotency:corrupt", "observation:corrupt"))
            .expect("commit");

        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        let bytes = snapshot
            .get(&service.store.events, &event_key(1))
            .expect("read")
            .expect("event");
        drop(snapshot);
        let mut event: StoredEvent = serde_json::from_slice(&bytes).expect("event fixture");
        event.projection_commit_seq = event.projection_commit_seq.saturating_add(1);
        event.checksum.clear();
        event.checksum = unkeyed_legacy_digest(
            b"production-event-v1",
            &canonical_bytes(&event).expect("unsigned tampered event"),
        );
        let bytes = canonical_bytes(&event).expect("tampered event");
        let mut transaction = service.store.engine.begin_write().expect("writer");
        transaction
            .put(&service.store.events, event_key(1), bytes)
            .expect("tamper fixture");
        transaction
            .commit(Durability::Sync)
            .expect("persist tamper fixture");

        let error = service
            .verify(VerifyRequest {
                context: admin_context("corruption-test"),
                deep: true,
            })
            .expect_err("corruption must fail closed");
        assert_eq!(error.code, ErrorCode::IntegrityFailure);
    }

    #[test]
    fn durable_postflight_receipt_is_content_free_replayable_and_semantically_inert() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-postflight.ctxb");
        let (_key, state, service) = initialized(&path);
        let before_projection = service.store.current_projection().expect("projection");
        let before_graph = service.store.policy_graph().expect("graph");
        let before_head = service.store.head_from_latest().expect("semantic head");
        let before_durable = service
            .store
            .verify_durable_history()
            .expect("durable head");
        let request = runtime_postflight_request(
            "postflight:content-free",
            runtime_context(
                "request:postflight:first",
                "workspace:production",
                "subject:production",
            ),
        );
        let raw_submission = serde_json::to_vec(&request).expect("raw sentinel request");
        let public_preflight_digest = request.payload["record"]["preflight_digest"]
            .as_str()
            .expect("preflight digest")
            .as_bytes()
            .to_vec();
        let public_record_digest = request.payload["record"]["record_digest"]
            .as_str()
            .expect("record digest")
            .as_bytes()
            .to_vec();

        let first = service.postflight(request.clone()).expect("first receipt");
        assert_eq!(first.operation_id, "postflight:content-free");
        assert_eq!(
            first
                .payload
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("caller_assertion_recorded")
        );
        assert_eq!(first.payload["replayed"], false);
        assert_eq!(first.payload["grants_authority"], false);
        assert_eq!(first.payload["semantic_mutations"], 0);
        assert_eq!(first.payload["outcome_verified_by_contextdb"], false);
        assert_eq!(
            service.store.head_from_latest().expect("semantic head"),
            before_head
        );
        assert!(service.store.events().expect("events").is_empty());
        assert_eq!(
            service.store.current_projection().expect("projection"),
            before_projection
        );
        assert_eq!(service.store.policy_graph().expect("graph"), before_graph);
        let after_durable = service
            .store
            .verify_durable_history()
            .expect("durable successor");
        assert_eq!(after_durable.generation, before_durable.generation + 1);

        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        let idempotency = snapshot
            .scan_prefix(&service.store.idempotency, b"")
            .expect("idempotency entries");
        assert_eq!(idempotency.len(), 1);
        assert!(idempotency[0].key.starts_with(RUNTIME_POSTFLIGHT_PREFIX));
        assert_eq!(
            idempotency[0].key.len(),
            RUNTIME_POSTFLIGHT_PREFIX.len() + 64
        );
        let history = snapshot
            .scan_prefix(&service.store.durable_history, DURABLE_HISTORY_PREFIX)
            .expect("durable history entries");
        let persisted_values: Vec<&[u8]> = idempotency
            .iter()
            .flat_map(|entry| [entry.key.as_slice(), entry.value.as_slice()])
            .chain(
                history
                    .iter()
                    .flat_map(|entry| [entry.key.as_slice(), entry.value.as_slice()]),
            )
            .collect();
        let dictionary_digests = ["11".repeat(32), "22".repeat(32), "33".repeat(32)];
        let sentinels: Vec<&[u8]> = vec![
            b"tool:sentinel-never-persist",
            b"reason:sentinel-never-persist",
            b"verification:sentinel-never-persist",
            b"action:content-free-postflight",
            b"subject:production",
            b"workspace:production",
            b"failed",
            dictionary_digests[0].as_bytes(),
            dictionary_digests[1].as_bytes(),
            dictionary_digests[2].as_bytes(),
            &public_preflight_digest,
            &public_record_digest,
        ];
        for sentinel in sentinels {
            assert!(
                persisted_values.iter().all(|persisted| !persisted
                    .windows(sentinel.len())
                    .any(|window| window == sentinel)),
                "raw postflight sentinel or public digest reached idempotency/history"
            );
        }
        assert!(persisted_values.iter().all(|persisted| {
            !persisted
                .windows(raw_submission.len())
                .any(|value| value == raw_submission)
        }));
        drop(snapshot);

        let replay = service
            .postflight(request.clone())
            .expect("in-process replay");
        assert_eq!(replay.payload["replayed"], true);
        assert_eq!(replay.payload["receipt_id"], first.payload["receipt_id"]);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("stable durable head")
                .generation,
            after_durable.generation
        );
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("restart");
        let restart = reopened.postflight(request).expect("restart replay");
        assert_eq!(restart.payload["replayed"], true);
        assert_eq!(restart.payload["receipt_id"], first.payload["receipt_id"]);
        assert_eq!(
            reopened.store.current_projection().expect("projection"),
            before_projection
        );
        assert_eq!(reopened.store.policy_graph().expect("graph"), before_graph);
    }

    #[test]
    fn postflight_changed_submission_or_authority_conflicts_and_tenants_are_isolated() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-postflight-conflict.ctxb");
        let (_key, _state, service) = initialized(&path);
        let context = runtime_context(
            "request:postflight:conflict",
            "workspace:production",
            "subject:production",
        );
        let first_request = runtime_postflight_request("postflight:shared", context.clone());
        let first = service
            .postflight(first_request.clone())
            .expect("first receipt");
        let generation = service
            .store
            .verify_durable_history()
            .expect("durable generation")
            .generation;

        let mut tampered = first_request.clone();
        tampered.payload["record"]["completed_at"] = serde_json::json!(43);
        let tampered_error = service
            .postflight(tampered)
            .expect_err("tampered canonical digest is rejected before persistence");
        assert_eq!(tampered_error.code, ErrorCode::InvalidArgument);

        let mut changed = first_request.clone();
        changed.payload["record"]["outcome"]["reason"] =
            serde_json::json!("reason:different-valid-assertion");
        changed.payload["record"]["record_digest"] = serde_json::json!(
            contextdb_service::canonical_postflight_record_digest(&changed.payload["record"])
                .expect("valid changed record digest")
        );
        validate_postflight_submission(&changed)
            .expect("changed submission is independently valid");
        let changed_error = service
            .postflight(changed)
            .expect_err("valid changed submission conflicts");
        assert_eq!(changed_error.code, ErrorCode::IdempotencyConflict);

        let mut changed_authority = context;
        changed_authority.request.purpose = "audit".to_owned();
        let authority_request = runtime_postflight_request("postflight:shared", changed_authority);
        let authority_error = service
            .postflight(authority_request)
            .expect_err("changed authority conflicts");
        assert_eq!(authority_error.code, ErrorCode::IdempotencyConflict);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("unchanged durable generation")
                .generation,
            generation
        );

        let other = runtime_postflight_request(
            "postflight:shared",
            runtime_context(
                "request:postflight:other-tenant",
                "workspace:tenant-bbb",
                "subject:tenant-bbb",
            ),
        );
        let other = service.postflight(other).expect("isolated tenant receipt");
        assert_ne!(other.payload["receipt_id"], first.payload["receipt_id"]);
        assert_eq!(service.store.events().expect("events").len(), 0);
        assert_eq!(service.store.head_from_latest().expect("semantic head"), 0);
    }

    #[test]
    fn postflight_receipt_cap_rejects_before_mutation_and_restart_remains_healthy() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-postflight-cap.ctxb");
        let (_key, state, service) = initialized(&path);
        let first_request = runtime_postflight_request(
            "postflight:cap:first",
            runtime_context(
                "request:postflight:cap:first",
                "workspace:production",
                "subject:production",
            ),
        );
        let first_identity = service
            .store
            .runtime_postflight_identity_digest(&first_request.context, &first_request.operation_id)
            .expect("first identity");
        let first_key = runtime_postflight_key(&first_identity).expect("first key");
        let first_commitment = "aa".repeat(32);
        service
            .store
            .append_runtime_postflight_receipt_with_limit(&first_key, first_commitment, 1)
            .expect("last allowed receipt");

        let before = service
            .store
            .verify_durable_history()
            .expect("before cap head");
        let before_snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("before cap snapshot");
        let before_count = service
            .store
            .non_event_receipt_count(&before_snapshot)
            .expect("before cap count");
        assert_eq!(before_count, 1);
        drop(before_snapshot);

        let next_request = runtime_postflight_request(
            "postflight:cap:next",
            runtime_context(
                "request:postflight:cap:next",
                "workspace:production",
                "subject:production",
            ),
        );
        let next_identity = service
            .store
            .runtime_postflight_identity_digest(&next_request.context, &next_request.operation_id)
            .expect("next identity");
        let next_key = runtime_postflight_key(&next_identity).expect("next key");
        let error = service
            .store
            .append_runtime_postflight_receipt_with_limit(&next_key, "bb".repeat(32), 1)
            .expect_err("next receipt exceeds cap");
        assert_eq!(error.0.code, ErrorCode::ResourceExhausted);

        let after = service
            .store
            .verify_durable_history()
            .expect("unchanged after cap");
        assert_eq!(after.generation, before.generation);
        assert_eq!(after.state_root, before.state_root);
        let after_snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("after cap snapshot");
        assert_eq!(
            service
                .store
                .non_event_receipt_count(&after_snapshot)
                .expect("after cap count"),
            before_count
        );
        assert_eq!(
            after_snapshot
                .get(&service.store.idempotency, &next_key)
                .expect("rejected key lookup"),
            None
        );
        drop(after_snapshot);
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("restart after cap rejection");
        reopened.store.verify().expect("restart remains healthy");
        let snapshot = reopened
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("restart snapshot");
        assert_eq!(
            reopened
                .store
                .non_event_receipt_count(&snapshot)
                .expect("restart count"),
            1
        );
    }

    #[test]
    fn postflight_capability_and_scope_fail_before_protected_payload_processing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-postflight-auth-order.ctxb");
        let (_key, _state, service) = initialized(&path);
        let mut context = runtime_context(
            "request:postflight:no-capability",
            "workspace:production",
            "subject:production",
        );
        context.capability_grants.clear();
        let call = |payload| {
            service
                .postflight(RuntimeRequest {
                    context: context.clone(),
                    operation_id: "postflight:auth-order".to_owned(),
                    payload,
                })
                .expect_err("capability required before payload")
        };
        let left = call(serde_json::json!({"protected": "tenant-a"}));
        let right = call(serde_json::json!({"protected": {"different": [1, 2, 3]}}));
        assert_eq!(left, right);
        assert_eq!(left.code, ErrorCode::Unauthorized);

        let mut mismatched = runtime_postflight_request(
            "postflight:scope-order",
            runtime_context(
                "request:postflight:scope-order",
                "workspace:production",
                "subject:production",
            ),
        );
        mismatched.payload["preflight"]["context"]["scope_manifest"]["workspace"] =
            serde_json::json!("workspace:other");
        mismatched.payload["record"]["protected"] = serde_json::json!("x".repeat(1024 * 1024));
        let mismatch = service
            .postflight(mismatched)
            .expect_err("scope mismatch wins before size/schema");
        assert_eq!(mismatch.code, ErrorCode::PermissionDenied);

        let mut unknown = runtime_postflight_request(
            "postflight:unknown-output",
            runtime_context(
                "request:postflight:unknown-output",
                "workspace:production",
                "subject:production",
            ),
        );
        unknown.payload["record"]["raw_tool_output"] =
            serde_json::json!("secret output must not be admitted");
        assert_eq!(
            service
                .postflight(unknown)
                .expect_err("arbitrary tool output is outside the exact DTO")
                .code,
            ErrorCode::FormatIncompatible
        );

        let mut oversized = runtime_postflight_request(
            "postflight:oversized",
            runtime_context(
                "request:postflight:oversized",
                "workspace:production",
                "subject:production",
            ),
        );
        oversized.payload["record"]["raw_tool_output"] = serde_json::json!("x".repeat(1024 * 1024));
        assert_eq!(
            service
                .postflight(oversized)
                .expect_err("size bound precedes typed protected parsing")
                .code,
            ErrorCode::ResourceExhausted
        );

        let mut deep = runtime_postflight_request(
            "postflight:deep",
            runtime_context(
                "request:postflight:deep",
                "workspace:production",
                "subject:production",
            ),
        );
        let mut nested = serde_json::Value::Null;
        for _ in 0..=64 {
            nested = serde_json::json!([nested]);
        }
        deep.payload["record"]["raw_tool_output"] = nested;
        assert_eq!(
            service
                .postflight(deep)
                .expect_err("depth bound precedes typed protected parsing")
                .code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("no invalid request persisted")
                .generation,
            0
        );
    }

    #[test]
    fn postflight_recomputed_preflight_linkage_rejects_valid_record_tampering() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-postflight-linkage.ctxb");
        let (_key, _state, service) = initialized(&path);
        let base = runtime_postflight_request(
            "postflight:linkage",
            runtime_context(
                "request:postflight:linkage",
                "workspace:production",
                "subject:production",
            ),
        );

        let mut cases = Vec::new();
        let mut action = base.clone();
        action.payload["record"]["action_id"] = serde_json::json!("action:other-valid");
        reseal_postflight_record(&mut action);
        cases.push(action);

        let mut report = base.clone();
        report.payload["record"]["preflight_digest"] = serde_json::json!("66".repeat(32));
        reseal_postflight_record(&mut report);
        cases.push(report);

        let mut host = base.clone();
        host.payload["record"]["host_authorization"] = serde_json::json!("denied");
        reseal_postflight_record(&mut host);
        cases.push(host);

        for request in cases {
            validate_postflight_submission(&request)
                .expect_err("valid canonical record must still match recomputed preflight");
            assert_eq!(
                service
                    .postflight(request)
                    .expect_err("production rejects linkage tampering")
                    .code,
                ErrorCode::InvalidArgument
            );
        }
        assert!(service.store.events().expect("events").is_empty());
        assert_eq!(service.store.head_from_latest().expect("semantic head"), 0);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("no durable receipt")
                .generation,
            0
        );
    }

    #[test]
    fn postflight_receipt_tamper_omission_and_relocation_fail_deep_verification() {
        for fault in ["bitflip", "omit", "relocate"] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory
                .path()
                .join(format!("runtime-postflight-{fault}.ctxb"));
            let (_key, _state, service) = initialized(&path);
            service
                .postflight(runtime_postflight_request(
                    "postflight:tamper",
                    runtime_context(
                        "request:postflight:tamper",
                        "workspace:production",
                        "subject:production",
                    ),
                ))
                .expect("receipt");
            let snapshot = service
                .store
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("snapshot");
            let entry = snapshot
                .scan_prefix(&service.store.idempotency, RUNTIME_POSTFLIGHT_PREFIX)
                .expect("runtime receipt")
                .into_iter()
                .next()
                .expect("receipt entry");
            drop(snapshot);
            let mut transaction = service.store.engine.begin_write().expect("writer");
            match fault {
                "bitflip" => {
                    let mut value = entry.value;
                    let byte = value.last_mut().expect("non-empty receipt");
                    *byte ^= 1;
                    transaction
                        .put(&service.store.idempotency, entry.key, value)
                        .expect("tamper");
                }
                "omit" => transaction
                    .delete(&service.store.idempotency, entry.key)
                    .expect("omit"),
                "relocate" => {
                    transaction
                        .delete(&service.store.idempotency, entry.key.clone())
                        .expect("delete original");
                    let mut moved = RUNTIME_POSTFLIGHT_PREFIX.to_vec();
                    moved.extend_from_slice("ab".repeat(32).as_bytes());
                    transaction
                        .put(&service.store.idempotency, moved, entry.value)
                        .expect("relocate");
                }
                _ => unreachable!(),
            }
            transaction.commit(Durability::Sync).expect("persist fault");
            let error = service
                .store
                .verify()
                .expect_err("receipt fault must fail closed");
            assert_eq!(error.0.code, ErrorCode::IntegrityFailure);
        }
    }

    #[test]
    fn lost_postflight_authority_ack_replays_the_single_fjall_successor() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime-postflight-lost-ack.ctxb");
        let (_key, state, service) = initialized(&path);
        let request = runtime_postflight_request(
            "postflight:lost-ack",
            runtime_context(
                "request:postflight:lost-ack",
                "workspace:production",
                "subject:production",
            ),
        );
        state.authority.fail_next_backend_write_for_test();
        let error = service
            .postflight(request.clone())
            .expect_err("authority ACK is lost");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("Fjall successor")
                .generation,
            1
        );
        let replay = service
            .postflight(request)
            .expect("retry reconciles durable authority");
        assert_eq!(replay.payload["replayed"], true);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("single successor")
                .generation,
            1
        );
    }

    #[test]
    fn policy_graph_reindex_is_content_free_semantically_inert_and_restart_replayable() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("policy-graph-reindex.ctxb");
        let archive = semantic_graph_archive();
        let (_key, state, service) = initialized_with_archive(&path, &archive);
        let request = reindex_request("reindex:content-free-sentinel", "request:reindex:first");
        let raw_payload = serde_json::to_vec(&request.payload).expect("payload bytes");
        let before_projection = service.store.current_projection().expect("projection");
        let before_graph = service.store.policy_graph().expect("policy graph");
        let before_durable = service
            .store
            .verify_durable_history()
            .expect("durable head");
        let before_events = service.store.events().expect("events");
        let before_head = service.store.head_from_latest().expect("semantic head");
        let before_snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("before snapshot");
        let before_graph_bytes = before_snapshot
            .get(&service.store.graph, POLICY_GRAPH_KEY)
            .expect("before graph lookup")
            .expect("before graph bytes");
        drop(before_snapshot);

        let first = service.reindex(request.clone()).expect("verified reindex");
        assert_eq!(
            first.payload,
            serde_json::json!({
                "schema_version": 1,
                "projection": "production_policy_graph_v1",
                "status": "rebuilt_and_published",
                "receipt_id": first.payload["receipt_id"].clone(),
                "replayed": false,
                "semantic_mutations": 0,
                "primary_state_mutations": 0,
                "active_generation_changed": false,
                "external_state_head_anchored": true
            })
        );
        validate_digest(
            first.payload["receipt_id"].as_str().expect("receipt ID"),
            "test reindex receipt ID",
        )
        .expect("canonical receipt ID");

        let after_durable = service
            .store
            .verify_durable_history()
            .expect("reindex successor");
        assert_eq!(after_durable.generation, before_durable.generation + 1);
        assert_eq!(
            after_durable.previous_digest.as_deref(),
            Some(before_durable.digest.as_str())
        );
        assert_ne!(after_durable.state_root, before_durable.state_root);
        assert_eq!(
            service.store.current_projection().expect("projection"),
            before_projection
        );
        assert_eq!(service.store.policy_graph().expect("graph"), before_graph);
        assert_eq!(service.store.events().expect("events"), before_events);
        assert_eq!(service.store.head_from_latest().expect("head"), before_head);
        assert_eq!(before_graph.generation, before_head);
        let (_, anchored_archive, anchored_durable) = state
            .authority
            .load_verified_with_ledger(&state.key.expose_copy())
            .expect("external authority anchor");
        assert_eq!(anchored_archive.database_id, before_projection.database_id);
        assert_eq!(anchored_archive.commit_seq, before_projection.commit_seq);
        assert_eq!(anchored_durable.generation, after_durable.generation);
        assert_eq!(anchored_durable.ledger_digest, after_durable.digest);

        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("receipt snapshot");
        assert_eq!(
            service
                .store
                .non_event_receipt_count(&snapshot)
                .expect("rooted count"),
            1
        );
        assert_eq!(
            snapshot
                .get(&service.store.graph, POLICY_GRAPH_KEY)
                .expect("after graph lookup")
                .expect("after graph bytes"),
            before_graph_bytes
        );
        let receipt_entry = snapshot
            .scan_prefix(&service.store.idempotency, REINDEX_RECEIPT_PREFIX)
            .expect("reindex receipt")
            .into_iter()
            .next()
            .expect("one reindex receipt");
        let newest_history = snapshot
            .get(
                &service.store.durable_history,
                &durable_history_key(after_durable.generation),
            )
            .expect("history lookup")
            .expect("new history");
        let persisted = [
            receipt_entry.key.as_slice(),
            receipt_entry.value.as_slice(),
            newest_history.as_slice(),
        ];
        let public_archive_digest = before_projection.archive_digest.as_bytes();
        let public_graph_digest = before_graph.digest.as_bytes();
        for sentinel in [
            b"reindex:content-free-sentinel".as_slice(),
            b"request:reindex:first".as_slice(),
            b"workspace:production".as_slice(),
            b"subject:production".as_slice(),
            b"agent:graph-test".as_slice(),
            b"session:graph-test".as_slice(),
            raw_payload.as_slice(),
            public_archive_digest,
            public_graph_digest,
        ] {
            assert!(persisted.iter().all(|value| {
                !value
                    .windows(sentinel.len())
                    .any(|window| window == sentinel)
            }));
        }
        drop(snapshot);

        let live_replay = service.reindex(request.clone()).expect("live replay");
        assert_eq!(live_replay.payload["replayed"], true);
        assert_eq!(
            live_replay.payload["receipt_id"],
            first.payload["receipt_id"]
        );
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("one successor")
                .generation,
            after_durable.generation
        );
        drop(service);

        let reopened = ProductionService::open(&path, state).expect("restart");
        let restart_replay = reopened.reindex(request).expect("restart replay");
        assert_eq!(restart_replay.payload["replayed"], true);
        assert_eq!(
            restart_replay.payload["receipt_id"],
            first.payload["receipt_id"]
        );
        assert_eq!(
            reopened.store.current_projection().expect("projection"),
            before_projection
        );
        assert_eq!(reopened.store.policy_graph().expect("graph"), before_graph);
    }

    #[test]
    fn policy_graph_reindex_preserves_observation_lag_and_rejects_changed_authority() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("policy-graph-reindex-lag.ctxb");
        let (_key, _state, service) = initialized(&path);
        service
            .observe(request(
                "idempotency:reindex-lag",
                "observation:reindex-lag",
            ))
            .expect("observation");
        let before = service.store.policy_graph().expect("lagging graph");
        assert_eq!(before.watermarks.journal, 1);
        assert_eq!(before.watermarks.semantic, 0);
        assert_eq!(before.watermarks.graph, 0);
        let request = reindex_request("reindex:authority", "request:reindex:authority");
        service.reindex(request.clone()).expect("reindex");
        assert_eq!(
            service.store.policy_graph().expect("unchanged graph"),
            before
        );
        let generation = service
            .store
            .verify_durable_history()
            .expect("generation")
            .generation;

        let identity = service
            .store
            .reindex_identity_digest(&request.context, &request.operation_id)
            .expect("identity");
        let key = reindex_receipt_key(&identity).expect("key");
        let storage_conflict = service
            .store
            .reindex_receipt(&key, &"ef".repeat(32))
            .expect_err("changed canonical input commitment conflicts");
        assert_eq!(storage_conflict.0.code, ErrorCode::IdempotencyConflict);

        let mut changed_authority = request;
        changed_authority.context.request.purpose = "audit".to_owned();
        let error = service
            .reindex(changed_authority)
            .expect_err("changed authorization binding conflicts");
        assert_eq!(error.code, ErrorCode::IdempotencyConflict);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("unchanged generation")
                .generation,
            generation
        );
    }

    #[test]
    fn policy_graph_reindex_auth_bounds_schema_and_pre_admission_cap_are_fail_closed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("policy-graph-reindex-admission.ctxb");
        let (_key, _state, service) = initialized(&path);
        let mut unauthorized = reindex_request("reindex:unauthorized", "request:unauthorized");
        unauthorized.context.capability_grants.clear();
        let mut oversized_unauthorized = unauthorized.clone();
        oversized_unauthorized.payload = serde_json::json!({"protected": "x".repeat(8 * 1024)});
        let mut deep_unauthorized = unauthorized;
        let mut deep = serde_json::Value::Null;
        for _ in 0..=MAX_REINDEX_JSON_DEPTH {
            deep = serde_json::json!([deep]);
        }
        deep_unauthorized.payload = deep.clone();
        let unauthorized_left = service
            .reindex(oversized_unauthorized)
            .expect_err("capability wins before size");
        let unauthorized_right = service
            .reindex(deep_unauthorized)
            .expect_err("capability wins before depth");
        assert_eq!(unauthorized_left, unauthorized_right);
        assert_eq!(unauthorized_left.code, ErrorCode::Unauthorized);

        let mut invalid_id = reindex_request("reindex:invalid", "request:invalid-id");
        invalid_id.operation_id = "\0".to_owned();
        invalid_id.payload = serde_json::json!({"protected": "x".repeat(8 * 1024)});
        assert_eq!(
            service.reindex(invalid_id).expect_err("ID wins").code,
            ErrorCode::InvalidArgument
        );
        let mut oversized = reindex_request("reindex:oversized", "request:oversized");
        oversized.payload = serde_json::json!({"protected": "x".repeat(8 * 1024)});
        assert_eq!(
            service
                .reindex(oversized)
                .expect_err("bounded payload")
                .code,
            ErrorCode::ResourceExhausted
        );
        let mut too_deep = reindex_request("reindex:deep", "request:deep");
        too_deep.payload = deep;
        assert_eq!(
            service.reindex(too_deep).expect_err("bounded depth").code,
            ErrorCode::ResourceExhausted
        );
        for payload in [
            serde_json::json!({
                "schema_version": 1,
                "projection": "production_policy_graph_v1",
                "unknown": true
            }),
            serde_json::json!({
                "schema_version": 2,
                "projection": "production_policy_graph_v1"
            }),
            serde_json::json!({
                "schema_version": 1,
                "projection": "vector_index"
            }),
        ] {
            let mut malformed = reindex_request("reindex:schema", "request:schema");
            malformed.payload = payload;
            assert_eq!(
                service.reindex(malformed).expect_err("exact schema").code,
                ErrorCode::FormatIncompatible
            );
        }
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("no invalid mutation")
                .generation,
            0
        );

        let first_request = reindex_request("reindex:cap:first", "request:cap:first");
        service
            .reindex(first_request)
            .expect("last admitted receipt");
        let before = service.store.verify_durable_history().expect("before cap");
        let next = reindex_request("reindex:cap:next", "request:cap:next");
        let payload = validate_reindex_request(&next).expect("canonical payload");
        let identity = service
            .store
            .reindex_identity_digest(&next.context, &next.operation_id)
            .expect("identity");
        let key = reindex_receipt_key(&identity).expect("key");
        let auth = next
            .context
            .authorization_binding_digest()
            .expect("authorization digest");
        let request_commitment = service
            .store
            .reindex_request_commitment(&identity, &auth, &payload)
            .expect("request commitment");
        let projection = service.store.current_projection().expect("projection");
        let graph = service.store.policy_graph().expect("graph");
        let source = service
            .store
            .reindex_source_commitment(&projection, &graph)
            .expect("source commitment");
        let graph_bytes = canonical_bytes(&graph).expect("graph bytes");
        let error = service
            .store
            .append_reindex_receipt_with_limit(
                &key,
                request_commitment,
                source,
                &projection,
                &graph,
                &before,
                &graph_bytes,
                1,
            )
            .expect_err("combined cap rejects before mutation");
        assert_eq!(error.0.code, ErrorCode::ResourceExhausted);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("unchanged after cap"),
            before
        );
    }

    #[test]
    fn policy_graph_reindex_receipt_faults_unknown_namespace_and_corrupt_source_fail_closed() {
        for fault in ["bitflip", "omit", "relocate", "unknown_namespace"] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory
                .path()
                .join(format!("policy-graph-reindex-{fault}.ctxb"));
            let (_key, _state, service) = initialized(&path);
            service
                .reindex(reindex_request("reindex:tamper", "request:tamper"))
                .expect("receipt");
            let snapshot = service
                .store
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("snapshot");
            let entry = snapshot
                .scan_prefix(&service.store.idempotency, REINDEX_RECEIPT_PREFIX)
                .expect("receipt")
                .into_iter()
                .next()
                .expect("receipt entry");
            drop(snapshot);
            let mut transaction = service.store.engine.begin_write().expect("writer");
            match fault {
                "bitflip" => {
                    let mut value = entry.value;
                    *value.last_mut().expect("receipt byte") ^= 1;
                    transaction
                        .put(&service.store.idempotency, entry.key, value)
                        .expect("tamper");
                }
                "omit" => transaction
                    .delete(&service.store.idempotency, entry.key)
                    .expect("omit"),
                "relocate" => {
                    transaction
                        .delete(&service.store.idempotency, entry.key)
                        .expect("delete original");
                    let mut moved = REINDEX_RECEIPT_PREFIX.to_vec();
                    moved.extend_from_slice("ab".repeat(32).as_bytes());
                    transaction
                        .put(&service.store.idempotency, moved, entry.value)
                        .expect("relocate");
                }
                "unknown_namespace" => transaction
                    .put(
                        &service.store.idempotency,
                        b"\0maintenance/reindex/v2/rogue".to_vec(),
                        entry.value,
                    )
                    .expect("unknown namespace"),
                _ => unreachable!(),
            }
            transaction.commit(Durability::Sync).expect("persist fault");
            assert_eq!(
                service.store.verify().expect_err("fail closed").0.code,
                ErrorCode::IntegrityFailure
            );
        }

        let mismatch_directory = tempfile::tempdir().expect("temporary directory");
        let mismatch_path = mismatch_directory
            .path()
            .join("policy-graph-reindex-candidate-mismatch.ctxb");
        let (_key, _state, mismatch_service) = initialized(&mismatch_path);
        let mismatch_projection = mismatch_service
            .store
            .current_projection()
            .expect("projection");
        let mut mismatched_candidate = mismatch_service.store.policy_graph().expect("graph");
        mismatched_candidate.record_count = mismatched_candidate.record_count.saturating_add(1);
        mismatched_candidate.digest =
            policy_graph_digest(&mismatched_candidate).expect("candidate digest");
        mismatched_candidate.checksum = mismatch_service
            .store
            .record_checksum(b"production-policy-graph-v1", &mismatched_candidate)
            .expect("candidate checksum");
        let mismatch_source = mismatch_service
            .store
            .reindex_source_commitment(&mismatch_projection, &mismatched_candidate)
            .expect("source commitment");
        let mismatch_durable = mismatch_service
            .store
            .verify_durable_history()
            .expect("durable head");
        let mismatch_bytes = canonical_bytes(&mismatched_candidate).expect("candidate bytes");
        let mismatch_key = reindex_receipt_key(&"ab".repeat(32)).expect("receipt key");
        let mismatch_error = mismatch_service
            .store
            .append_reindex_receipt(
                &mismatch_key,
                "cd".repeat(32),
                mismatch_source,
                &mismatch_projection,
                &mismatched_candidate,
                &mismatch_durable,
                &mismatch_bytes,
            )
            .expect_err("candidate mismatch must not become a repair");
        assert_eq!(mismatch_error.0.code, ErrorCode::IntegrityFailure);
        assert_eq!(
            mismatch_service
                .store
                .verify_durable_history()
                .expect("unchanged mismatch generation"),
            mismatch_durable
        );

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory
            .path()
            .join("policy-graph-reindex-corrupt-source.ctxb");
        let (_key, _state, service) = initialized(&path);
        let before = service
            .store
            .verify_durable_history()
            .expect("durable head");
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("graph snapshot");
        let mut graph_bytes = snapshot
            .get(&service.store.graph, POLICY_GRAPH_KEY)
            .expect("graph lookup")
            .expect("graph");
        drop(snapshot);
        *graph_bytes.last_mut().expect("graph byte") ^= 1;
        let mut transaction = service.store.engine.begin_write().expect("corrupt writer");
        transaction
            .put(&service.store.graph, POLICY_GRAPH_KEY.to_vec(), graph_bytes)
            .expect("corrupt graph");
        transaction
            .commit(Durability::Sync)
            .expect("persist corruption");
        let error = service
            .reindex(reindex_request("reindex:repair", "request:repair"))
            .expect_err("reindex is not an offline repair path");
        assert_eq!(error.code, ErrorCode::IntegrityFailure);
        assert_eq!(
            service
                .store
                .durable_head_from(
                    &service
                        .store
                        .engine
                        .begin_read(SnapshotSelector::Latest)
                        .expect("latest snapshot")
                )
                .expect("unchanged durable head"),
            before
        );
    }

    #[test]
    fn lost_reindex_authority_ack_replays_one_durable_successor() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("policy-graph-reindex-lost-ack.ctxb");
        let (_key, state, service) = initialized(&path);
        let request = reindex_request("reindex:lost-ack", "request:lost-ack");
        state.authority.fail_next_backend_write_for_test();
        let error = service
            .reindex(request.clone())
            .expect_err("authority ACK is lost");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("Fjall successor")
                .generation,
            1
        );
        let replay = service.reindex(request).expect("reconcile exact successor");
        assert_eq!(replay.payload["replayed"], true);
        assert_eq!(
            service
                .store
                .verify_durable_history()
                .expect("single successor")
                .generation,
            1
        );
        let (_, _, anchored) = state
            .authority
            .load_verified_with_ledger(&state.key.expose_copy())
            .expect("anchored authority");
        assert_eq!(anchored.generation, 1);
    }

    #[test]
    fn runtime_and_reindex_receipts_share_one_rooted_count_and_generation_set() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("mixed-non-event-receipts.ctxb");
        let (_key, _state, service) = initialized(&path);
        service
            .postflight(runtime_postflight_request(
                "postflight:mixed",
                runtime_context(
                    "request:postflight:mixed",
                    "workspace:production",
                    "subject:production",
                ),
            ))
            .expect("runtime receipt");
        service
            .reindex(reindex_request("reindex:mixed", "request:reindex:mixed"))
            .expect("reindex receipt");
        let durable = service
            .store
            .verify_durable_history()
            .expect("mixed durable history");
        assert_eq!(durable.generation, 2);
        let snapshot = service
            .store
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("mixed snapshot");
        assert_eq!(
            service
                .store
                .non_event_receipt_count(&snapshot)
                .expect("combined rooted count"),
            2
        );
        let runtime: StoredRuntimePostflightReceipt = serde_json::from_slice(
            &snapshot
                .scan_prefix(&service.store.idempotency, RUNTIME_POSTFLIGHT_PREFIX)
                .expect("runtime receipts")[0]
                .value,
        )
        .expect("runtime receipt decode");
        let reindex_entry = snapshot
            .scan_prefix(&service.store.idempotency, REINDEX_RECEIPT_PREFIX)
            .expect("reindex receipts")
            .into_iter()
            .next()
            .expect("reindex receipt");
        let mut reindex: StoredReindexReceipt =
            serde_json::from_slice(&reindex_entry.value).expect("reindex receipt decode");
        assert_eq!(runtime.durable_generation, 1);
        assert_eq!(reindex.durable_generation, 2);
        drop(snapshot);
        service.store.verify().expect("mixed receipt verification");

        // Even a validly re-MACed internal fixture cannot claim a generation
        // already used by the other receipt family.
        reindex.durable_generation = runtime.durable_generation;
        reindex.checksum = service
            .store
            .reindex_receipt_checksum(&reindex_entry.key, &reindex)
            .expect("re-MAC fixture");
        let mut transaction = service.store.engine.begin_write().expect("fixture writer");
        transaction
            .put(
                &service.store.idempotency,
                reindex_entry.key,
                canonical_bytes(&reindex).expect("receipt bytes"),
            )
            .expect("stage duplicate generation");
        transaction
            .commit(Durability::Sync)
            .expect("persist duplicate generation fixture");
        let error = service
            .store
            .verify_idempotency(&[], durable.generation, &BTreeSet::new())
            .expect_err("cross-family duplicate generation must fail closed");
        assert_eq!(error.0.code, ErrorCode::IntegrityFailure);
    }
}
