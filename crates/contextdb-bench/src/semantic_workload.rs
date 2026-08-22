//! Executable, fail-closed M17 semantic-scale development workload.
//!
//! The older semantic evaluator accepts bounded, content-addressed measurements
//! produced elsewhere. This module owns the complementary executable path: it
//! generates deterministic semantic identities, writes the real persistent graph,
//! builds and queries the current exact/HNSW vector runtime, exercises every RFC
//! BENCH-H scenario, and emits raw evidence from the operations it actually ran.
//! It cannot turn a target count into a measured count, and it deliberately blocks
//! the v1 certification shape while its remaining physical runtime and resource
//! prerequisites are insufficient.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use contextdb_core::{
    AcceptanceState, AccessCapability, ActorId, Artifact, ArtifactId, Audience, AudienceGrant,
    BitemporalRange, CommitRange, CommitSeq, ConfidenceProfile, ConsentPolicy, ContentBlockId,
    ContentDigest, DerivationId, DerivationKind, DerivationRef, Directionality, Edge, EdgeId,
    EdgeRevision, EdgeTypeId, EpistemicBasis, EpistemicRole, EpistemicState, IdentityState,
    LifecycleState, LineageNode, MemorySpace, MemorySpaceId, MemorySpaceKind, MemorySubject,
    MemorySubjectId, MemoryUsePolicy, Modality, ModificationPolicy, Node, NodeId, NodeRevision,
    NodeType, NonEmptyVec, OwnershipPolicy, PipelineIdentity, PolicyDecision, PolicyId, Purpose,
    RepresentationId, RetentionPolicy, RevisionNumber, ScopeId, ScopeInheritance, ScopeKind,
    ScopeRef, SecurityClassification, SecurityPolicy, SemanticEnvelope, SourceId, SubjectKind,
    TimeRange, TimestampMicros, VectorSpaceId, Workspace, WorkspaceId, WorkspaceState,
};
use contextdb_graph::{
    Direction, GraphMutation, GraphStore, ReadPrincipal, SEGMENT_V2_MAX_DIRECTIONAL_RECORDS,
    SegmentManifest,
};
use contextdb_index::{
    AnnAlgorithmV2, AnnBuildParametersV2, AnnGenerationVerificationV2, AnnPartitionSchemeV2,
    AnnQueryBudgetV2, AnnQueryV2, AnnRuntimeResultV2, AnnSourceImportPlanV2, AnnSourceSealV2,
    AnnSourceVerificationV2, AnnVectorRoutePageV2, AnnVectorSourceV2, IndexPolicy, IndexPrincipal,
    PersistentAnnV2, PersistentAnnVectorSourceV2, PersistentVectorStore, VectorIndex, VectorMetric,
    VectorQuery, VectorRecord, VectorSpace,
};
use contextdb_storage::{
    Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, VerifyMode,
    WriteTransaction,
};
use contextdb_storage_fjall::FjallStorage;
use contextdb_storage_redb::RedbStorage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::digest::{hex, sha256_hex};
use crate::{BenchError, Result};

/// Raw executable workload configuration schema.
pub const SEMANTIC_WORKLOAD_CONFIG_SCHEMA_VERSION: &str =
    "contextdb.bench-h-semantic-workload-config/v1";
/// Raw executable development outcome schema.
pub const SEMANTIC_EXECUTION_SCHEMA_VERSION: &str = "contextdb.bench-h-semantic-execution/v1";
/// Small index that content-addresses the execution outcome itself.
pub const SEMANTIC_EXECUTION_INDEX_SCHEMA_VERSION: &str =
    "contextdb.bench-h-semantic-execution-index/v1";

const DATASET_VERSION: &str = "contextdb-bench-h-full-stack-semantic-v1";
const ADMISSION_MODEL_VERSION: &str = "contextdb-semantic-admission-v1";
const CERTIFICATION_NODES: u64 = 10_000_000;
const CERTIFICATION_EDGES: u64 = 100_000_000;
const CERTIFICATION_VECTORS: u64 = 1_000_000;
const PRIVATE_CANARY: &str = "semantic-private-canary-never-export";
const MAX_SAMPLES: usize = 4_096;
const MAX_VECTOR_DIMENSIONS: u32 = 4_096;
const MAX_BATCH_ITEMS: u64 = 65_536;
const ANN_V2_VECTOR_SOURCE_GENERATION: u64 = 1;
const ANN_V2_ROUTE_SOURCE_GENERATION: u64 = 1;
const ANN_V2_RUNTIME_GENERATION: u64 = 1;
const ANN_SOURCE_IMPORT_PAGE_ENTRIES: usize = 1_024;

/// Named workload shape. Presets are inputs, never evidence that their target was reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticWorkloadPreset {
    /// Fast local proof that every executable hook is wired.
    Smoke,
    /// Larger but still laptop-friendly development run.
    Development,
    /// RFC BENCH-H small tier.
    Small,
    /// RFC BENCH-H medium tier.
    Medium,
    /// ERRATA E-009 lower-bound certification request.
    CertificationV1,
    /// Caller-selected counts below or between named tiers.
    Custom,
}

/// Exact configuration consumed by the executable workload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticWorkloadConfig {
    /// Configuration schema.
    pub schema_version: String,
    /// Human-readable preset label; counts below remain authoritative.
    pub preset: SemanticWorkloadPreset,
    /// Deterministic generator seed.
    pub seed: u64,
    /// Semantic node identities to commit and verify.
    pub semantic_nodes: u64,
    /// Logical directed graph edges to commit and verify.
    pub graph_edges: u64,
    /// Full-precision vectors to build, authorize, and query.
    pub vectors: u64,
    /// Dimensions in every deterministic vector.
    pub vector_dimensions: u32,
    /// Maximum nodes staged in one semantic transaction.
    pub node_batch_size: u64,
    /// Maximum edges staged in one semantic transaction.
    pub edge_batch_size: u64,
    /// Queries used by each read scenario and ANN overlap hook.
    pub queries_per_scenario: u64,
    /// Maximum raw latency samples retained per operation.
    pub maximum_samples: usize,
    /// Hard process-RSS budget checked throughout the run.
    pub process_rss_budget_bytes: u64,
    /// Sampling interval for the continuous RSS observer.
    pub rss_sample_interval_ms: u64,
    /// Capacity of the bounded pressure queue.
    pub pressure_queue_capacity: usize,
    /// Number of requests intentionally offered during pressure.
    pub pressure_requests: u64,
    /// Whether the abrupt synchronized-write crash probe is required.
    pub require_crash_probe: bool,
}

impl SemanticWorkloadConfig {
    /// Returns a deterministic named preset.
    #[must_use]
    pub fn preset(preset: SemanticWorkloadPreset) -> Self {
        let mut config = Self {
            schema_version: SEMANTIC_WORKLOAD_CONFIG_SCHEMA_VERSION.to_owned(),
            preset,
            seed: 0xC0DB_0017,
            semantic_nodes: 128,
            graph_edges: 1_024,
            vectors: 128,
            vector_dimensions: 8,
            node_batch_size: 64,
            edge_batch_size: 128,
            queries_per_scenario: 32,
            maximum_samples: 256,
            process_rss_budget_bytes: 2 * 1024 * 1024 * 1024,
            rss_sample_interval_ms: 1_000,
            pressure_queue_capacity: 8,
            pressure_requests: 256,
            require_crash_probe: true,
        };
        match preset {
            SemanticWorkloadPreset::Smoke | SemanticWorkloadPreset::Custom => {}
            SemanticWorkloadPreset::Development => {
                config.semantic_nodes = 4_096;
                config.graph_edges = 32_768;
                config.vectors = 2_048;
                config.vector_dimensions = 16;
                config.node_batch_size = 128;
                config.edge_batch_size = 256;
                config.queries_per_scenario = 64;
                config.maximum_samples = 512;
                config.process_rss_budget_bytes = 8 * 1024 * 1024 * 1024;
            }
            SemanticWorkloadPreset::Small => {
                config.semantic_nodes = 100_000;
                config.graph_edges = 1_000_000;
                config.vectors = 100_000;
                config.vector_dimensions = 32;
                config.node_batch_size = 512;
                config.edge_batch_size = 512;
                config.queries_per_scenario = 64;
                config.maximum_samples = 1_024;
                config.process_rss_budget_bytes = 24 * 1024 * 1024 * 1024;
            }
            SemanticWorkloadPreset::Medium => {
                config.semantic_nodes = 5_000_000;
                config.graph_edges = 50_000_000;
                config.vectors = 500_000;
                config.vector_dimensions = 32;
                config.node_batch_size = 1_024;
                config.edge_batch_size = 1_024;
                config.queries_per_scenario = 64;
                config.maximum_samples = 2_048;
                config.process_rss_budget_bytes = 48 * 1024 * 1024 * 1024;
            }
            SemanticWorkloadPreset::CertificationV1 => {
                config.semantic_nodes = CERTIFICATION_NODES;
                config.graph_edges = CERTIFICATION_EDGES;
                config.vectors = CERTIFICATION_VECTORS;
                config.vector_dimensions = 32;
                config.node_batch_size = 1_024;
                config.edge_batch_size = 1_024;
                config.queries_per_scenario = 64;
                config.maximum_samples = MAX_SAMPLES;
                config.process_rss_budget_bytes = 56 * 1024 * 1024 * 1024;
            }
        }
        config
    }

    /// Validates finite resource bounds before estimates or allocations.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SEMANTIC_WORKLOAD_CONFIG_SCHEMA_VERSION {
            return invalid("schema_version", "unsupported semantic workload schema");
        }
        for (field, value, minimum) in [
            ("semantic_nodes", self.semantic_nodes, 3),
            ("graph_edges", self.graph_edges, 1),
            ("vectors", self.vectors, 3),
            ("node_batch_size", self.node_batch_size, 1),
            ("edge_batch_size", self.edge_batch_size, 1),
            ("queries_per_scenario", self.queries_per_scenario, 1),
            ("process_rss_budget_bytes", self.process_rss_budget_bytes, 1),
            ("rss_sample_interval_ms", self.rss_sample_interval_ms, 50),
            ("pressure_requests", self.pressure_requests, 1),
        ] {
            if value < minimum {
                return invalid(field, format!("must be at least {minimum}"));
            }
        }
        if self.node_batch_size > MAX_BATCH_ITEMS || self.edge_batch_size > MAX_BATCH_ITEMS {
            return invalid("batch_size", "batch size exceeds the 65536-item hard bound");
        }
        if self.vector_dimensions == 0 || self.vector_dimensions > MAX_VECTOR_DIMENSIONS {
            return invalid(
                "vector_dimensions",
                format!("must be in 1..={MAX_VECTOR_DIMENSIONS}"),
            );
        }
        if self.maximum_samples == 0 || self.maximum_samples > MAX_SAMPLES {
            return invalid("maximum_samples", "must be in 1..=4096");
        }
        if self.pressure_queue_capacity == 0 || self.pressure_queue_capacity > 65_536 {
            return invalid("pressure_queue_capacity", "must be in 1..=65536");
        }
        if self.semantic_nodes > usize::MAX as u64 || self.vectors > usize::MAX as u64 {
            return invalid(
                "scale",
                "node/vector count exceeds this target's address space",
            );
        }
        Ok(())
    }

    fn requests_certification_shape(&self) -> bool {
        self.semantic_nodes >= CERTIFICATION_NODES
            && self.graph_edges >= CERTIFICATION_EDGES
            && self.vectors >= CERTIFICATION_VECTORS
    }
}

/// Capacity observed on the machine before workload admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticHostCapacity {
    /// Total physical memory, if the OS exposed it.
    pub total_memory_bytes: Option<u64>,
    /// Currently available physical memory, if the OS exposed it.
    pub available_memory_bytes: Option<u64>,
    /// Free bytes on the output volume, if the OS exposed it.
    pub available_disk_bytes: Option<u64>,
    /// Host OS family.
    pub os: String,
    /// Host architecture.
    pub architecture: String,
}

/// Why a workload cannot currently be admitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAdmissionBlocker {
    /// Stable blocker identifier.
    pub code: String,
    /// Payload-free technical explanation.
    pub detail: String,
    /// Required capacity when a numeric limit is involved.
    pub required: Option<u64>,
    /// Current hard limit or observed availability.
    pub available: Option<u64>,
}

/// Conservative deterministic estimate used only for admission and ETA planning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticResourceEstimate {
    /// Estimator revision.
    pub model_version: String,
    /// Logical directed edges expand into this many physical directional records.
    pub required_graph_directional_records: u64,
    /// Conservative bytes required on the output volume, including offline backup.
    pub estimated_disk_bytes: u64,
    /// Conservative peak process RSS for graph batches plus the in-memory vector runtime.
    pub estimated_peak_memory_bytes: u64,
    /// Lower ETA under the recorded optimistic throughput assumptions.
    pub estimated_duration_seconds_lower: u64,
    /// Upper ETA under the recorded conservative throughput assumptions.
    pub estimated_duration_seconds_upper: u64,
    /// Exact arithmetic assumptions so estimates can be reproduced.
    pub assumptions: BTreeMap<String, u64>,
}

/// Admission decision before any workload state is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticAdmissionDisposition {
    /// Safe local development shape; execution may proceed.
    Admitted,
    /// No hard blocker, but the exact admission digest must be confirmed.
    ConfirmationRequired,
    /// A current physical/runtime capacity makes the requested shape impossible.
    Blocked,
}

/// Machine-readable preflight. It contains no caller-supplied pass switch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticAdmission {
    /// Admission contract version.
    pub schema_version: String,
    /// Exact workload configuration.
    pub config: SemanticWorkloadConfig,
    /// Measured host capacity.
    pub host: SemanticHostCapacity,
    /// Deterministic resource estimate.
    pub estimate: SemanticResourceEstimate,
    /// Hard blockers derived from current contracts and host capacity.
    pub blockers: Vec<SemanticAdmissionBlocker>,
    /// Derived disposition.
    pub disposition: SemanticAdmissionDisposition,
    /// Why an otherwise runnable workload needs a digest-bound confirmation.
    pub confirmation_reasons: Vec<String>,
}

/// Derives an admission decision from exact counts, current physical caps, and host capacity.
pub fn admit_semantic_workload(
    config: SemanticWorkloadConfig,
    host: SemanticHostCapacity,
) -> Result<SemanticAdmission> {
    config.validate()?;
    let estimate = estimate_resources(&config)?;
    let mut blockers = Vec::new();
    if estimate.required_graph_directional_records > SEGMENT_V2_MAX_DIRECTIONAL_RECORDS {
        blockers.push(SemanticAdmissionBlocker {
            code: "graph_v2_directional_record_capacity".to_owned(),
            detail: format!(
                "graph-v2 stores one outgoing and one incoming physical record per directed logical edge; the current {}-record generation cap cannot represent the requested logical edge count",
                SEGMENT_V2_MAX_DIRECTIONAL_RECORDS
            ),
            required: Some(estimate.required_graph_directional_records),
            available: Some(SEGMENT_V2_MAX_DIRECTIONAL_RECORDS),
        });
    }
    if config.requests_certification_shape() {
        blockers.push(SemanticAdmissionBlocker {
            code: "persistent_ann_v2_certification_scale_unproven".to_owned(),
            detail: "no accepted reference-hardware receipt demonstrates ANN-v2 construction throughput, recall, latency, and exact-oracle quality at the requested 1M-vector floor".to_owned(),
            required: Some(config.vectors),
            available: None,
        });
    }
    if let Some(available) = host.available_disk_bytes {
        let safe = available.saturating_mul(4) / 5;
        if estimate.estimated_disk_bytes > safe {
            blockers.push(SemanticAdmissionBlocker {
                code: "insufficient_output_volume_capacity".to_owned(),
                detail: "estimated state plus offline backup exceeds 80% of currently free output-volume capacity".to_owned(),
                required: Some(estimate.estimated_disk_bytes),
                available: Some(safe),
            });
        }
    }
    if let Some(available) = host.available_memory_bytes {
        let safe = available.saturating_mul(4) / 5;
        if estimate.estimated_peak_memory_bytes > safe
            || config.process_rss_budget_bytes > host.total_memory_bytes.unwrap_or(u64::MAX)
        {
            blockers.push(SemanticAdmissionBlocker {
                code: "insufficient_memory_capacity".to_owned(),
                detail: "estimated peak or declared RSS budget exceeds the safe observed host-memory envelope".to_owned(),
                required: Some(
                    estimate
                        .estimated_peak_memory_bytes
                        .max(config.process_rss_budget_bytes),
                ),
                available: Some(safe),
            });
        }
    }

    let mut confirmation_reasons = Vec::new();
    if config.semantic_nodes >= 100_000 {
        confirmation_reasons.push("semantic node count reaches the RFC small tier".to_owned());
    }
    if config.graph_edges >= 1_000_000 {
        confirmation_reasons.push("logical edge count reaches the RFC small tier".to_owned());
    }
    if config.vectors >= 100_000 {
        confirmation_reasons
            .push("exact differential vector oracle materialization reaches 100k".to_owned());
    }
    if estimate.estimated_duration_seconds_upper >= 3_600 {
        confirmation_reasons.push("conservative ETA is at least one hour".to_owned());
    }
    if estimate.estimated_disk_bytes >= 10 * 1024 * 1024 * 1024 {
        confirmation_reasons.push("estimated output-volume use is at least 10 GiB".to_owned());
    }
    let disposition = if blockers.is_empty() {
        if confirmation_reasons.is_empty() {
            SemanticAdmissionDisposition::Admitted
        } else {
            SemanticAdmissionDisposition::ConfirmationRequired
        }
    } else {
        SemanticAdmissionDisposition::Blocked
    };
    Ok(SemanticAdmission {
        schema_version: "contextdb.bench-h-semantic-admission/v1".to_owned(),
        config,
        host,
        estimate,
        blockers,
        disposition,
        confirmation_reasons,
    })
}

fn estimate_resources(config: &SemanticWorkloadConfig) -> Result<SemanticResourceEstimate> {
    let directional = checked_mul(config.graph_edges, 2, "directional graph records")?;
    let dimensions = u64::from(config.vector_dimensions);
    let node_bytes = checked_mul(config.semantic_nodes, 2_560, "semantic node bytes")?;
    let edge_bytes = checked_mul(config.graph_edges, 2_304, "semantic edge bytes")?;
    let vector_value_bytes = checked_mul(dimensions, 4, "vector value bytes")?;
    let vector_record_bytes = vector_value_bytes
        .checked_add(768)
        .ok_or(BenchError::ArithmeticOverflow("vector record bytes"))?;
    let vector_bytes = checked_mul(config.vectors, vector_record_bytes, "vector bytes")?;
    let primary = node_bytes
        .checked_add(edge_bytes)
        .and_then(|value| value.checked_add(vector_bytes))
        .ok_or(BenchError::ArithmeticOverflow("primary semantic bytes"))?;
    let estimated_disk_bytes = checked_mul(primary, 3, "state, transient, and backup bytes")?;
    let vector_memory = checked_mul(
        config.vectors,
        vector_record_bytes.saturating_add(1_024),
        "vector runtime memory",
    )?;
    let batch_memory = checked_mul(
        config.node_batch_size.max(config.edge_batch_size),
        8_192,
        "semantic batch memory",
    )?;
    let estimated_peak_memory_bytes = vector_memory
        .checked_add(batch_memory)
        .and_then(|value| value.checked_add(512 * 1024 * 1024))
        .ok_or(BenchError::ArithmeticOverflow("semantic peak memory"))?;
    let work = config
        .semantic_nodes
        .checked_add(config.graph_edges)
        .and_then(|value| value.checked_add(config.vectors.saturating_mul(8)))
        .and_then(|value| value.checked_add(directional))
        .ok_or(BenchError::ArithmeticOverflow("semantic work units"))?;
    let optimistic_units_per_second = 40_000_u64;
    let conservative_units_per_second = 2_000_u64;
    let estimated_duration_seconds_lower = work.div_ceil(optimistic_units_per_second).max(1);
    let estimated_duration_seconds_upper = work.div_ceil(conservative_units_per_second).max(1);
    let assumptions = BTreeMap::from([
        ("semantic_node_bytes".to_owned(), 2_560),
        (
            "logical_edge_bytes_including_v2_projection".to_owned(),
            2_304,
        ),
        ("vector_runtime_overhead_bytes".to_owned(), 768 + 1_024),
        (
            "disk_replication_factor_for_transient_and_backup".to_owned(),
            3,
        ),
        (
            "optimistic_work_units_per_second".to_owned(),
            optimistic_units_per_second,
        ),
        (
            "conservative_work_units_per_second".to_owned(),
            conservative_units_per_second,
        ),
    ]);
    Ok(SemanticResourceEstimate {
        model_version: ADMISSION_MODEL_VERSION.to_owned(),
        required_graph_directional_records: directional,
        estimated_disk_bytes,
        estimated_peak_memory_bytes,
        estimated_duration_seconds_lower,
        estimated_duration_seconds_upper,
        assumptions,
    })
}

/// Writes an immutable admission file and returns its SHA-256 confirmation digest.
pub fn write_semantic_admission(root: &Path, admission: &SemanticAdmission) -> Result<String> {
    fs::create_dir_all(root)?;
    let bytes = serde_json::to_vec_pretty(admission)?;
    write_new(&root.join("semantic-admission.json"), &bytes)?;
    Ok(sha256_hex(&bytes))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionScenario {
    HotConversation,
    ColdAutobiographical,
    CurrentFact,
    HistoricalFact,
    FilteredAnn,
    HierarchyDrillDown,
    ArtifactMetadata,
    CompactionUnderLoad,
    Backup,
    Restart,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LatencySummary {
    samples: u64,
    minimum_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    maximum_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioExecution {
    scenario: ExecutionScenario,
    completed_operations: u64,
    elapsed_ns: u64,
    operations_per_second: f64,
    latency: LatencySummary,
    implementation_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseExecution {
    phase: String,
    completed_operations: u64,
    elapsed_ns: u64,
    latency: LatencySummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HookStatus {
    MeasuredPass,
    MeasuredFail,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegressionHook {
    class: String,
    status: HookStatus,
    measured_score_bps: Option<f64>,
    baseline_score_bps: Option<f64>,
    detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceSample {
    elapsed_ms: u64,
    process_rss_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceTrace {
    sample_interval_ms: u64,
    samples: Vec<ResourceSample>,
    maximum_process_rss_bytes: Option<u64>,
    process_rss_budget_bytes: u64,
    budget_exceeded: bool,
    pressure_requests: u64,
    admitted_pressure_requests: u64,
    degraded_responses: u64,
    correctness_failures: u64,
    uncontrolled_oom_events: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrashRecoveryTrace {
    required: bool,
    child_started: bool,
    child_terminated_abruptly: bool,
    synchronized_marker_recovered: bool,
    recovery_latency_ns: Option<u64>,
    marker_sha256: Option<String>,
    limitation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalFileDigest {
    path: String,
    bytes: u64,
    blake3: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalStateManifest {
    algorithm: String,
    files: Vec<PhysicalFileDigest>,
    aggregate_blake3: String,
    total_bytes: u64,
}

/// Content-addressed raw artifact used by an execution outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticExecutionArtifact {
    /// Artifact role.
    pub kind: String,
    /// Path relative to the execution root.
    pub uri: String,
    /// Exact artifact byte count.
    pub bytes: u64,
    /// SHA-256 of exact bytes.
    pub sha256: String,
}

/// Classification derived from executed checks, never accepted from the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticExecutionStatus {
    /// Every locally executable hook completed, but release prerequisites remain unavailable.
    DevelopmentComplete,
    /// At least one required executable hook failed or was unavailable.
    DevelopmentIncomplete,
}

/// Full execution outcome. Counts are populated only after exhaustive verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticExecutionOutcome {
    /// Outcome schema.
    pub schema_version: String,
    /// Deterministic dataset revision.
    pub dataset_version: String,
    /// Exact admission artifact digest confirmed before execution.
    pub admission_sha256: String,
    /// Unix milliseconds around the measured run.
    pub started_unix_ms: u64,
    /// Unix milliseconds around the measured run.
    pub finished_unix_ms: u64,
    /// Derived development status.
    pub status: SemanticExecutionStatus,
    /// Exhaustively fetched semantic nodes whose expected and actual digest matched.
    pub verified_semantic_nodes: u64,
    /// Exhaustively fetched logical edges whose expected and actual digest matched.
    pub verified_logical_graph_edges: u64,
    /// Physical directional records authenticated by graph-v2 compaction.
    pub verified_graph_directional_records: u64,
    /// Full-precision records accepted by the vector runtime and restored from its bundle.
    pub verified_vectors: u64,
    /// Whether persistent ANN-v2 builder/publication/query was exercised.
    pub persistent_ann_v2_runtime_exercised: bool,
    /// Real scenario measurements.
    scenarios: Vec<ScenarioExecution>,
    /// Real ingest/build/verify phase measurements.
    phases: Vec<PhaseExecution>,
    /// Derived correctness/privacy/social/ANN checks.
    regressions: Vec<RegressionHook>,
    /// Runtime resource/pressure trace summary.
    resource: ResourceTrace,
    /// Abrupt crash/recovery hook.
    crash_recovery: CrashRecoveryTrace,
    /// Logical semantic digest before restart.
    pub expected_logical_digest: String,
    /// Logical semantic digest reconstructed after restart.
    pub recovered_logical_digest: String,
    /// Content-addressed supporting artifacts.
    pub artifacts: Vec<SemanticExecutionArtifact>,
    /// Honest scope limitations.
    pub limitations: Vec<String>,
}

/// Self-addressing top-level pointer to one outcome file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticExecutionBundleIndex {
    /// Index schema.
    pub schema_version: String,
    /// Outcome location relative to the execution root.
    pub outcome_uri: String,
    /// Exact outcome byte count.
    pub outcome_bytes: u64,
    /// SHA-256 of exact outcome bytes.
    pub outcome_sha256: String,
}

#[derive(Clone, Debug)]
struct SemanticFixture {
    workspace: WorkspaceId,
    visible_space: MemorySpaceId,
    private_space: MemorySpaceId,
    visible_owner: MemorySubjectId,
    private_owner: MemorySubjectId,
    workspace_scope: ScopeId,
    visible_scope: ScopeId,
    private_scope: ScopeId,
    edge_type: EdgeTypeId,
    artifact: ArtifactId,
    vector_space: VectorSpaceId,
}

impl SemanticFixture {
    fn new(seed: u64) -> Result<Self> {
        let workspace = stable_id::<WorkspaceId>(seed, 1, WorkspaceId::from_uuid)?;
        let visible_space = stable_id::<MemorySpaceId>(seed, 2, MemorySpaceId::from_uuid)?;
        let private_space = stable_id::<MemorySpaceId>(seed, 3, MemorySpaceId::from_uuid)?;
        let visible_owner = stable_id::<MemorySubjectId>(seed, 4, MemorySubjectId::from_uuid)?;
        let private_owner = stable_id::<MemorySubjectId>(seed, 5, MemorySubjectId::from_uuid)?;
        Ok(Self {
            workspace,
            visible_space,
            private_space,
            visible_owner,
            private_owner,
            workspace_scope: ScopeId::from_uuid(workspace.as_uuid())
                .map_err(|error| integrity(error.to_string()))?,
            visible_scope: ScopeId::from_uuid(visible_space.as_uuid())
                .map_err(|error| integrity(error.to_string()))?,
            private_scope: ScopeId::from_uuid(private_space.as_uuid())
                .map_err(|error| integrity(error.to_string()))?,
            edge_type: stable_id::<EdgeTypeId>(seed, 6, EdgeTypeId::from_uuid)?,
            artifact: stable_id::<ArtifactId>(seed, 7, ArtifactId::from_uuid)?,
            vector_space: stable_id::<VectorSpaceId>(seed, 8, VectorSpaceId::from_uuid)?,
        })
    }

    fn node_id(&self, seed: u64, index: u64) -> Result<NodeId> {
        stable_id::<NodeId>(seed, 10_000_u64.saturating_add(index), NodeId::from_uuid)
    }

    fn edge_id(&self, seed: u64, index: u64) -> Result<EdgeId> {
        stable_id::<EdgeId>(
            seed,
            1_000_000_000_u64.saturating_add(index),
            EdgeId::from_uuid,
        )
    }

    fn representation_id(&self, seed: u64, index: u64) -> Result<RepresentationId> {
        stable_id::<RepresentationId>(
            seed,
            2_000_000_000_u64.saturating_add(index),
            RepresentationId::from_uuid,
        )
    }

    fn visible_principal(&self) -> ReadPrincipal {
        ReadPrincipal {
            subject: self.visible_owner,
            workspace_id: self.workspace,
            scopes: BTreeSet::from([self.workspace_scope, self.visible_scope]),
            memory_spaces: BTreeSet::from([self.visible_space]),
            audience_subjects: BTreeSet::new(),
            purpose: Purpose::KnowledgeRecall,
            clearance: SecurityClassification::Internal,
            compartments: BTreeSet::new(),
        }
    }

    fn private_principal(&self) -> ReadPrincipal {
        ReadPrincipal {
            subject: self.private_owner,
            workspace_id: self.workspace,
            scopes: BTreeSet::from([self.workspace_scope, self.private_scope]),
            memory_spaces: BTreeSet::from([self.private_space]),
            audience_subjects: BTreeSet::new(),
            purpose: Purpose::KnowledgeRecall,
            clearance: SecurityClassification::Restricted,
            compartments: BTreeSet::new(),
        }
    }

    fn index_principal(&self, private: bool) -> IndexPrincipal {
        let (space, owner, scope) = if private {
            (self.private_space, self.private_owner, self.private_scope)
        } else {
            (self.visible_space, self.visible_owner, self.visible_scope)
        };
        IndexPrincipal {
            workspace_id: self.workspace,
            memory_spaces: BTreeSet::from([space]),
            subjects: BTreeSet::from([owner]),
            owner_identities: BTreeSet::from([owner]),
            scopes: BTreeSet::from([scope]),
            purpose: Purpose::KnowledgeRecall,
        }
    }

    fn envelope(&self, seed: u64, private: bool, nonce: u64) -> Result<SemanticEnvelope> {
        let (space, owner, scope, classification) = if private {
            (
                self.private_space,
                self.private_owner,
                self.private_scope,
                SecurityClassification::Restricted,
            )
        } else {
            (
                self.visible_space,
                self.visible_owner,
                self.visible_scope,
                SecurityClassification::Internal,
            )
        };
        let purpose = BTreeSet::from([Purpose::KnowledgeRecall]);
        let mut scopes = NonEmptyVec::new(ScopeRef {
            kind: ScopeKind::Workspace,
            id: self.workspace_scope,
            inheritance: ScopeInheritance::Exact,
        });
        scopes.push(ScopeRef {
            kind: ScopeKind::MemorySpace,
            id: scope,
            inheritance: ScopeInheritance::Exact,
        });
        Ok(SemanticEnvelope {
            scopes,
            perspective: contextdb_core::Perspective {
                knower: owner,
                experiencer: Some(owner),
                narrator: stable_id::<ActorId>(
                    seed,
                    3_000_000_000_u64.saturating_add(nonce),
                    ActorId::from_uuid,
                )?,
                role: EpistemicRole::Verifier,
            },
            ownership: OwnershipPolicy {
                owners: NonEmptyVec::new(owner),
                audience_grants: vec![AudienceGrant {
                    audience: Audience::Owner,
                    purposes: purpose.clone(),
                    capabilities: BTreeSet::from([AccessCapability::Retrieve]),
                }],
                allowed_purposes: purpose,
                modification: ModificationPolicy {
                    owners_may_modify: true,
                    delegates_may_modify: false,
                    system_may_derive: true,
                },
            },
            consent: ConsentPolicy {
                required: false,
                decisions: Vec::new(),
            },
            use_policy: MemoryUsePolicy {
                retrieve: PolicyDecision::Allow,
                influence_response: PolicyDecision::Allow,
                mention_explicitly: PolicyDecision::Allow,
                external_model_use: PolicyDecision::Deny,
                retention: RetentionPolicy::Indefinite,
            },
            security: SecurityPolicy {
                classification,
                labels: BTreeSet::new(),
                required_compartments: BTreeSet::new(),
                allow_external_processing: false,
            },
            derivation: DerivationRef {
                id: stable_id::<DerivationId>(
                    seed,
                    4_000_000_000_u64.saturating_add(nonce),
                    DerivationId::from_uuid,
                )?,
                kind: DerivationKind::DeterministicProjector,
                actor: None,
                model_call: None,
                pipeline: PipelineIdentity {
                    name: "m17-semantic-workload".to_owned(),
                    version: "1".to_owned(),
                    schema_version: "1".to_owned(),
                },
                inputs: vec![LineageNode::External {
                    namespace: "m17-bench-h".to_owned(),
                    identifier: format!("{space}:{nonce}"),
                }],
            },
        })
    }

    fn index_policy(&self, private: bool) -> IndexPolicy {
        let (space, owner, scope, classification) = if private {
            (
                self.private_space,
                self.private_owner,
                self.private_scope,
                SecurityClassification::Restricted,
            )
        } else {
            (
                self.visible_space,
                self.visible_owner,
                self.visible_scope,
                SecurityClassification::Internal,
            )
        };
        IndexPolicy {
            workspace_id: self.workspace,
            memory_spaces: BTreeSet::from([space]),
            subjects: BTreeSet::from([owner]),
            owners: BTreeSet::from([owner]),
            scopes: BTreeSet::from([scope]),
            purposes: BTreeSet::from([Purpose::KnowledgeRecall]),
            classification,
            security_labels: BTreeSet::new(),
            required_compartments: BTreeSet::new(),
            allow_external_processing: false,
            retrieve_allowed: true,
            deleted_at: None,
        }
    }
}

struct ResourceSampler {
    stop: Arc<AtomicBool>,
    exceeded: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<ResourceSample>>>,
    join: Option<thread::JoinHandle<()>>,
    budget: u64,
    interval_ms: u64,
}

impl ResourceSampler {
    fn start(budget: u64, interval_ms: u64) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let exceeded = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = Arc::clone(&stop);
        let worker_exceeded = Arc::clone(&exceeded);
        let worker_samples = Arc::clone(&samples);
        let started = Instant::now();
        let join = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                if let Some(bytes) = process_rss_bytes() {
                    if bytes > budget {
                        worker_exceeded.store(true, Ordering::Release);
                    }
                    if let Ok(mut guard) = worker_samples.lock()
                        && guard.len() < MAX_SAMPLES
                    {
                        guard.push(ResourceSample {
                            elapsed_ms: millis(started.elapsed()),
                            process_rss_bytes: bytes,
                        });
                    }
                }
                thread::sleep(Duration::from_millis(interval_ms));
            }
        });
        Self {
            stop,
            exceeded,
            samples,
            join: Some(join),
            budget,
            interval_ms,
        }
    }

    fn checkpoint(&self) -> Result<()> {
        if self.exceeded.load(Ordering::Acquire) {
            return invalid(
                "process_rss_budget_bytes",
                "continuous observer measured RSS above the declared hard budget",
            );
        }
        Ok(())
    }

    fn finish(mut self, pressure: PressureOutcome) -> Result<ResourceTrace> {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            join.join().map_err(|_| BenchError::WorkerPanicked)?;
        }
        if let Some(bytes) = process_rss_bytes()
            && let Ok(mut guard) = self.samples.lock()
            && guard.len() < MAX_SAMPLES
        {
            let elapsed_ms = guard
                .last()
                .map_or(0, |sample| sample.elapsed_ms.saturating_add(1));
            guard.push(ResourceSample {
                elapsed_ms,
                process_rss_bytes: bytes,
            });
            if bytes > self.budget {
                self.exceeded.store(true, Ordering::Release);
            }
        }
        let samples = self
            .samples
            .lock()
            .map_err(|_| integrity("resource sample lock poisoned"))?
            .clone();
        let maximum_process_rss_bytes = samples.iter().map(|sample| sample.process_rss_bytes).max();
        Ok(ResourceTrace {
            sample_interval_ms: self.interval_ms,
            samples,
            maximum_process_rss_bytes,
            process_rss_budget_bytes: self.budget,
            budget_exceeded: self.exceeded.load(Ordering::Acquire),
            pressure_requests: pressure.requests,
            admitted_pressure_requests: pressure.admitted,
            degraded_responses: pressure.degraded,
            correctness_failures: pressure.correctness_failures,
            uncontrolled_oom_events: 0,
        })
    }
}

impl Drop for ResourceSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PressureOutcome {
    requests: u64,
    admitted: u64,
    degraded: u64,
    correctness_failures: u64,
}

#[derive(Debug)]
struct BoundedSamples {
    maximum: usize,
    seen: u64,
    values: Vec<u64>,
}

impl BoundedSamples {
    fn new(maximum: usize) -> Self {
        Self {
            maximum,
            seen: 0,
            values: Vec::with_capacity(maximum),
        }
    }

    fn push(&mut self, value: u64) {
        self.seen = self.seen.saturating_add(1);
        if self.values.len() < self.maximum {
            self.values.push(value);
            return;
        }
        let candidate = splitmix64(self.seen) % self.seen;
        if candidate < self.maximum as u64
            && let Ok(index) = usize::try_from(candidate)
        {
            self.values[index] = value;
        }
    }

    fn summary(mut self) -> Result<LatencySummary> {
        if self.values.is_empty() {
            return invalid(
                "latency_samples",
                "at least one measured sample is required",
            );
        }
        self.values.sort_unstable();
        Ok(LatencySummary {
            samples: self.seen,
            minimum_ns: self.values[0],
            p50_ns: percentile(&self.values, 50),
            p95_ns: percentile(&self.values, 95),
            p99_ns: percentile(&self.values, 99),
            maximum_ns: *self.values.last().unwrap_or(&0),
        })
    }
}

struct VectorExecution {
    index: VectorIndex,
    store_bundle: PersistentVectorStore,
    ann_v2: PersistentAnnV2ExecutionEvidence,
    build_phase: PhaseExecution,
    verified_vectors: u64,
    ann_overlap_bps: f64,
    private_isolation_passed: bool,
    filtered_ann_scenario: ScenarioExecution,
    freshness_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AnnSourceAuditSnapshot {
    route_page_reads: u64,
    vector_reads: u64,
    target_reads: u64,
    private_vector_reads: u64,
    private_target_reads: u64,
}

#[derive(Debug, Default)]
struct AnnSourceAuditState {
    route_page_reads: u64,
    vector_reads: Vec<RepresentationId>,
    target_reads: Vec<RepresentationId>,
}

#[derive(Debug)]
struct AuditedAnnSource<'a> {
    inner: &'a PersistentAnnVectorSourceV2<RedbStorage>,
    private_id: RepresentationId,
    audit: Mutex<AnnSourceAuditState>,
}

impl<'a> AuditedAnnSource<'a> {
    fn new(
        inner: &'a PersistentAnnVectorSourceV2<RedbStorage>,
        private_id: RepresentationId,
    ) -> Self {
        Self {
            inner,
            private_id,
            audit: Mutex::new(AnnSourceAuditState::default()),
        }
    }

    fn reset_audit(&self) -> Result<()> {
        *self
            .audit
            .lock()
            .map_err(|_| integrity("ANN-v2 source audit lock was poisoned"))? =
            AnnSourceAuditState::default();
        Ok(())
    }

    fn audit_snapshot(&self) -> Result<AnnSourceAuditSnapshot> {
        let audit = self
            .audit
            .lock()
            .map_err(|_| integrity("ANN-v2 source audit lock was poisoned"))?;
        Ok(AnnSourceAuditSnapshot {
            route_page_reads: audit.route_page_reads,
            vector_reads: usize_to_u64(audit.vector_reads.len()),
            target_reads: usize_to_u64(audit.target_reads.len()),
            private_vector_reads: usize_to_u64(
                audit
                    .vector_reads
                    .iter()
                    .filter(|id| **id == self.private_id)
                    .count(),
            ),
            private_target_reads: usize_to_u64(
                audit
                    .target_reads
                    .iter()
                    .filter(|id| **id == self.private_id)
                    .count(),
            ),
        })
    }
}

impl AnnVectorSourceV2 for AuditedAnnSource<'_> {
    fn source_seal(&self) -> AnnRuntimeResultV2<AnnSourceSealV2> {
        self.inner.source_seal()
    }

    fn vector_space(&self, id: VectorSpaceId) -> AnnRuntimeResultV2<VectorSpace> {
        self.inner.vector_space(id)
    }

    fn scan_routes_page(
        &self,
        start_after: Option<RepresentationId>,
        max_entries: usize,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<AnnVectorRoutePageV2> {
        let mut audit = self.audit.lock().map_err(|_| {
            contextdb_index::AnnRuntimeErrorV2::Invariant("source audit lock poisoned")
        })?;
        audit.route_page_reads = audit.route_page_reads.saturating_add(1);
        drop(audit);
        self.inner
            .scan_routes_page(start_after, max_entries, max_bytes)
    }

    fn read_vector(&self, id: RepresentationId, dimensions: usize) -> AnnRuntimeResultV2<Vec<f32>> {
        self.audit
            .lock()
            .map_err(|_| {
                contextdb_index::AnnRuntimeErrorV2::Invariant("source audit lock poisoned")
            })?
            .vector_reads
            .push(id);
        self.inner.read_vector(id, dimensions)
    }

    fn read_target(
        &self,
        id: RepresentationId,
        max_bytes: usize,
    ) -> AnnRuntimeResultV2<LineageNode> {
        self.audit
            .lock()
            .map_err(|_| {
                contextdb_index::AnnRuntimeErrorV2::Invariant("source audit lock poisoned")
            })?
            .target_reads
            .push(id);
        self.inner.read_target(id, max_bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnV2VerificationEvidence {
    generation: u64,
    manifest_digest: String,
    partition_count: u64,
    node_count: u64,
    level_row_count: u64,
    neighbour_count: u64,
    object_count: u64,
    object_bytes: u64,
}

impl From<AnnGenerationVerificationV2> for AnnV2VerificationEvidence {
    fn from(value: AnnGenerationVerificationV2) -> Self {
        Self {
            generation: value.generation(),
            manifest_digest: hex(&value.manifest_digest()),
            partition_count: value.partition_count(),
            node_count: value.node_count(),
            level_row_count: value.level_row_count(),
            neighbour_count: value.neighbour_count(),
            object_count: value.object_count(),
            object_bytes: value.object_bytes(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnV2DifferentialEvidence {
    queries: u64,
    exact_hits: u64,
    matching_id_and_score_hits: u64,
    all_queries_exact: bool,
    persistent_authorized_routes: u64,
    authorization_route_page_reads: u64,
    authorization_vector_reads: u64,
    authorization_target_reads: u64,
    query_vector_reads: u64,
    query_target_reads: u64,
    private_vector_reads: u64,
    private_target_reads: u64,
}

impl AnnV2DifferentialEvidence {
    fn passed(&self) -> bool {
        self.queries > 0
            && self.exact_hits > 0
            && self.exact_hits == self.matching_id_and_score_hits
            && self.all_queries_exact
            && self.persistent_authorized_routes > 0
            && self.authorization_route_page_reads == 0
            && self.authorization_vector_reads == 0
            && self.authorization_target_reads == 0
            && self.query_vector_reads > 0
            && self.query_target_reads > 0
            && self.private_vector_reads == 0
            && self.private_target_reads == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnV2ReopenEvidence {
    source: DurableAnnSourceEvidence,
    storage_sequence: u64,
    recovery_active_generation: u64,
    recovery_abandoned_generation: Option<u64>,
    recovery_objects_deleted: u64,
    verification: AnnV2VerificationEvidence,
    differential: AnnV2DifferentialEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableAnnSourceEvidence {
    backend: String,
    storage_sequence: u64,
    vector_store_generation: u64,
    vector_store_root: String,
    route_generation: u64,
    route_root: String,
    vector_space_registry_digest: String,
    vector_space_count: u64,
    record_count: u64,
}

impl From<AnnSourceVerificationV2> for DurableAnnSourceEvidence {
    fn from(value: AnnSourceVerificationV2) -> Self {
        Self {
            backend: "redb".to_owned(),
            storage_sequence: value.storage_sequence,
            vector_store_generation: value.seal.vector_store_generation,
            vector_store_root: hex(&value.seal.vector_store_root),
            route_generation: value.seal.route_generation,
            route_root: hex(&value.seal.route_root),
            vector_space_registry_digest: hex(&value.seal.vector_space_registry_digest),
            vector_space_count: value.vector_space_count,
            record_count: value.record_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistentAnnV2ExecutionEvidence {
    schema_version: String,
    backend: String,
    source_bridge: String,
    source: DurableAnnSourceEvidence,
    vector_store_generation: u64,
    route_generation: u64,
    publication_generation: u64,
    publication_storage_sequence: u64,
    publication_verification: AnnV2VerificationEvidence,
    immediate_storage_sequence: u64,
    immediate_verification: AnnV2VerificationEvidence,
    immediate_differential: AnnV2DifferentialEvidence,
    reopened: Option<AnnV2ReopenEvidence>,
}

impl PersistentAnnV2ExecutionEvidence {
    fn exercised(&self) -> bool {
        let Some(reopened) = &self.reopened else {
            return false;
        };
        self.schema_version == "contextdb.bench-h-persistent-ann-v2-execution/v2"
            && self.backend == "redb"
            && self.source_bridge == "redb_paged_full_precision_source_v1"
            && self.source == reopened.source
            && self.source.record_count > 0
            && self.source.vector_space_count > 0
            && self.vector_store_generation > 0
            && self.route_generation > 0
            && self.publication_generation == ANN_V2_RUNTIME_GENERATION
            && self.publication_storage_sequence > 0
            && self.immediate_storage_sequence >= self.publication_storage_sequence
            && reopened.storage_sequence >= self.publication_storage_sequence
            && self.publication_verification == self.immediate_verification
            && self.publication_verification == reopened.verification
            && reopened.recovery_active_generation == self.publication_generation
            && reopened.recovery_abandoned_generation.is_none()
            && reopened.recovery_objects_deleted == 0
            && self.immediate_differential.passed()
            && reopened.differential.passed()
    }
}

struct GraphVerification {
    digest: String,
    semantic_nodes: u64,
    logical_edges: u64,
}

/// Executes the admitted full-stack workload and writes a self-addressing evidence bundle.
///
/// `crash_child_exe` should be the current `contextdb-bench` executable. When absent, the crash
/// hook is recorded as unavailable and a required run remains development-incomplete.
pub fn run_semantic_workload(
    root: &Path,
    admission: &SemanticAdmission,
    admission_sha256: &str,
    crash_child_exe: Option<&Path>,
) -> Result<SemanticExecutionBundleIndex> {
    admission.config.validate()?;
    validate_digest("admission_sha256", admission_sha256)?;
    let canonical_admission = serde_json::to_vec_pretty(admission)?;
    if sha256_hex(&canonical_admission) != admission_sha256 {
        return Err(integrity(
            "confirmed admission digest does not bind the exact admission artifact",
        ));
    }
    if admission.disposition == SemanticAdmissionDisposition::Blocked {
        return invalid(
            "semantic_admission",
            "execution cannot proceed while the preflight is blocked",
        );
    }
    if !admission.blockers.is_empty() {
        return invalid(
            "semantic_admission.blockers",
            "an admitted workload cannot contain hard blockers",
        );
    }
    let config = &admission.config;
    let started_unix_ms = unix_millis()?;
    let state_root = root.join("semantic-state");
    let graph_root = state_root.join("graph-fjall");
    let ann_v2_path = state_root.join("ann-v2.redb");
    let ann_v2_source_path = state_root.join("ann-v2-source.redb");
    let backup_root = state_root.join("graph-backup");
    let artifacts_root = root.join("semantic-artifacts");
    if state_root.exists() || artifacts_root.exists() {
        return invalid(
            "output",
            "semantic state and artifact directories must not already exist",
        );
    }
    fs::create_dir_all(&graph_root)?;
    fs::create_dir_all(&artifacts_root)?;

    let fixture = SemanticFixture::new(config.seed)?;
    let sampler = ResourceSampler::start(
        config.process_rss_budget_bytes,
        config.rss_sample_interval_ms,
    );
    let storage = FjallStorage::open(&graph_root)?;
    let store = Arc::new(GraphStore::new(storage.clone()).map_err(graph_error)?);
    let mut phases = Vec::new();
    phases.push(ingest_semantic_nodes(&store, &fixture, config)?);
    sampler.checkpoint()?;
    phases.push(ingest_semantic_edges(&store, &fixture, config)?);
    sampler.checkpoint()?;

    let snapshot = store
        .snapshot(SnapshotSelector::Latest)
        .map_err(graph_error)?;
    let mut vector_execution = build_vectors(
        &fixture,
        config,
        snapshot.semantic_seq,
        &ann_v2_path,
        &ann_v2_source_path,
    )?;
    phases.push(vector_execution.build_phase.clone());
    sampler.checkpoint()?;

    let mut scenarios = run_read_scenarios(&store, &fixture, config, &snapshot, &vector_execution)?;
    let (compaction_scenario, compaction_manifest) =
        run_compaction_under_load(&store, &fixture, config)?;
    scenarios.push(compaction_scenario);
    sampler.checkpoint()?;
    let pressure = run_pressure(&store, &fixture, config)?;
    sampler.checkpoint()?;

    let compacted_snapshot = store
        .snapshot(SnapshotSelector::Latest)
        .map_err(graph_error)?;
    let verify_started = Instant::now();
    let verification = verify_graph(&store, &fixture, config, &compacted_snapshot)?;
    let verify_elapsed = nanos(verify_started.elapsed());
    phases.push(PhaseExecution {
        phase: "exhaustive_semantic_graph_verification".to_owned(),
        completed_operations: verification
            .semantic_nodes
            .saturating_add(verification.logical_edges),
        elapsed_ns: verify_elapsed,
        latency: single_latency(verify_elapsed)?,
    });
    let visible_principal = fixture.visible_principal();
    let private_node = fixture.node_id(config.seed, 1)?;
    let privacy_graph_passed = store
        .node(private_node, &compacted_snapshot, &visible_principal)
        .is_err()
        && store
            .node(
                private_node,
                &compacted_snapshot,
                &fixture.private_principal(),
            )
            .is_ok();
    let storage_verify = storage.verify(VerifyMode::Deep)?;

    let vector_store_bytes = vector_execution.store_bundle.payload.clone();
    let mut artifact_receipts = Vec::new();
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("vector-store.payload.json"),
        "full-precision-vector-store",
        &vector_store_bytes,
    )?);

    drop(store);
    drop(storage);
    let original_physical = physical_state_manifest(&graph_root)?;
    let backup_started = Instant::now();
    copy_directory(&graph_root, &backup_root)?;
    let backup_physical = physical_state_manifest(&backup_root)?;
    if original_physical != backup_physical {
        return Err(integrity(
            "offline backup file manifest differs from its quiescent source",
        ));
    }
    let backup_storage = FjallStorage::open(&backup_root)?;
    let backup_store = GraphStore::new(backup_storage.clone()).map_err(graph_error)?;
    let backup_snapshot = backup_store
        .snapshot(SnapshotSelector::Latest)
        .map_err(graph_error)?;
    backup_store
        .node(
            fixture.node_id(config.seed, 0)?,
            &backup_snapshot,
            &fixture.visible_principal(),
        )
        .map_err(graph_error)?;
    backup_storage.verify(VerifyMode::Deep)?;
    let backup_elapsed = nanos(backup_started.elapsed());
    scenarios.push(scenario_from_elapsed(
        ExecutionScenario::Backup,
        1,
        backup_elapsed,
        "quiescent Fjall directory copy plus manifest equality, reopen, graph read, and deep verify",
    )?);
    drop(backup_store);
    drop(backup_storage);
    sampler.checkpoint()?;

    let restart_started = Instant::now();
    let restarted_storage = FjallStorage::open(&graph_root)?;
    let restarted_store = GraphStore::new(restarted_storage.clone()).map_err(graph_error)?;
    let restarted_snapshot = restarted_store
        .snapshot(SnapshotSelector::Latest)
        .map_err(graph_error)?;
    restarted_store
        .node(
            fixture.node_id(config.seed, 0)?,
            &restarted_snapshot,
            &fixture.visible_principal(),
        )
        .map_err(graph_error)?;
    restarted_storage.verify(VerifyMode::Deep)?;
    let restart_elapsed = nanos(restart_started.elapsed());
    scenarios.push(scenario_from_elapsed(
        ExecutionScenario::Restart,
        1,
        restart_elapsed,
        "Fjall reopen, authenticated graph-v2 snapshot, semantic read, and deep physical verify",
    )?);
    let cold_scenario = measure_graph_nodes(
        ExecutionScenario::ColdAutobiographical,
        &restarted_store,
        &fixture,
        config,
        &restarted_snapshot,
        false,
        "post-reopen authorized semantic node reads without OS cache eviction",
    )?;
    scenarios.push(cold_scenario);
    let recovered = verify_graph(&restarted_store, &fixture, config, &restarted_snapshot)?;
    drop(restarted_store);
    drop(restarted_storage);
    if recovered.digest != verification.digest
        || recovered.semantic_nodes != verification.semantic_nodes
        || recovered.logical_edges != verification.logical_edges
    {
        return Err(integrity(
            "restarted graph digest or exhaustive counts differ from the pre-restart state",
        ));
    }

    let mut restored_index = VectorIndex::new();
    restored_index
        .import_store(vector_execution.store_bundle.clone())
        .map_err(index_error)?;
    verify_reopened_persistent_ann_v2(
        &ann_v2_path,
        &ann_v2_source_path,
        &restored_index,
        &fixture,
        config,
        restarted_snapshot.semantic_seq,
        &mut vector_execution.ann_v2,
    )?;
    vector_execution.index = restored_index;
    let ann_v2_evidence_bytes = serde_json::to_vec_pretty(&vector_execution.ann_v2)?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("persistent-ann-v2-execution.json"),
        "persistent-ann-v2-build-verify-reopen-differential",
        &ann_v2_evidence_bytes,
    )?);

    let crash_recovery = execute_crash_probe(
        &state_root.join("crash-probe"),
        crash_child_exe,
        config.require_crash_probe,
    )?;
    sampler.checkpoint()?;
    let resource = sampler.finish(pressure)?;

    scenarios.sort_by_key(|scenario| scenario.scenario);
    if scenarios.len() != 10 {
        return Err(integrity(format!(
            "expected ten BENCH-H scenarios, executed {}",
            scenarios.len()
        )));
    }
    let expected_directional =
        config
            .graph_edges
            .checked_mul(2)
            .ok_or(BenchError::ArithmeticOverflow(
                "expected directional graph records",
            ))?;
    let semantic_passed = verification.semantic_nodes == config.semantic_nodes
        && verification.logical_edges == config.graph_edges
        && vector_execution.verified_vectors == config.vectors
        && recovered.digest == verification.digest
        && compaction_manifest.edge_count == expected_directional;
    let ann_passed = vector_execution.ann_overlap_bps >= 9_000.0;
    let mut regressions = vec![
        RegressionHook {
            class: "semantic_quality".to_owned(),
            status: pass_status(semantic_passed),
            measured_score_bps: Some(if semantic_passed { 10_000.0 } else { 0.0 }),
            baseline_score_bps: Some(10_000.0),
            detail: "deterministic expected/recovered logical digests, exhaustive identities, and graph-v2 directional counts".to_owned(),
        },
        RegressionHook {
            class: "privacy".to_owned(),
            status: pass_status(privacy_graph_passed && vector_execution.private_isolation_passed),
            measured_score_bps: Some(if privacy_graph_passed
                && vector_execution.private_isolation_passed
            {
                10_000.0
            } else {
                0.0
            }),
            baseline_score_bps: Some(10_000.0),
            detail: "private graph/vector canary is denied to the visible principal and available only to its owner".to_owned(),
        },
        RegressionHook {
            class: "social_calibration".to_owned(),
            status: HookStatus::Unavailable,
            measured_score_bps: None,
            baseline_score_bps: None,
            detail: "the semantic-scale runner contains no model-response or human-rating path; BENCH-A social calibration remains separately required".to_owned(),
        },
        RegressionHook {
            class: "ann_exact_overlap".to_owned(),
            status: pass_status(ann_passed),
            measured_score_bps: Some(vector_execution.ann_overlap_bps),
            baseline_score_bps: Some(9_000.0),
            detail: "redb-backed persistent ANN-v2 results compared with the exact full-precision oracle across deterministic queries".to_owned(),
        },
    ];
    if resource.budget_exceeded || resource.correctness_failures > 0 {
        regressions[0].status = HookStatus::MeasuredFail;
    }

    let config_bytes = serde_json::to_vec_pretty(config)?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("workload-config.json"),
        "semantic-workload-config",
        &config_bytes,
    )?);
    let scenario_bytes = serde_json::to_vec_pretty(&scenarios)?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("scenario-trace.json"),
        "semantic-scenario-trace",
        &scenario_bytes,
    )?);
    let phase_bytes = serde_json::to_vec_pretty(&phases)?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("phase-trace.json"),
        "semantic-phase-trace",
        &phase_bytes,
    )?);
    let resource_bytes = serde_json::to_vec_pretty(&resource)?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("resource-trace.json"),
        "semantic-resource-pressure-trace",
        &resource_bytes,
    )?);
    let crash_bytes = serde_json::to_vec_pretty(&crash_recovery)?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("crash-recovery.json"),
        "semantic-crash-recovery-trace",
        &crash_bytes,
    )?);
    let physical_bytes = serde_json::to_vec_pretty(&original_physical)?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("physical-state-manifest.json"),
        "semantic-physical-state-manifest",
        &physical_bytes,
    )?);
    let storage_verify_bytes = serde_json::to_vec_pretty(&BTreeMap::from([
        ("sequence", storage_verify.sequence),
        ("keyspaces", storage_verify.keyspaces),
        ("records", storage_verify.records),
        ("index_freshness_ns", vector_execution.freshness_ns),
    ]))?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("storage-index-state.json"),
        "semantic-storage-index-state",
        &storage_verify_bytes,
    )?);

    let artifacts_private_safe = scan_artifacts_for_private_canary(root, &artifact_receipts)?;
    if !artifacts_private_safe
        && let Some(privacy) = regressions.iter_mut().find(|hook| hook.class == "privacy")
    {
        privacy.status = HookStatus::MeasuredFail;
        privacy.measured_score_bps = Some(0.0);
        privacy.detail =
            "private canary appeared in a content-addressed measurement artifact".to_owned();
    }
    let regression_bytes = serde_json::to_vec_pretty(&regressions)?;
    artifact_receipts.push(write_artifact(
        root,
        &artifacts_root.join("regression-hooks.json"),
        "semantic-quality-privacy-regression-hooks",
        &regression_bytes,
    )?);

    let crash_passed = !config.require_crash_probe
        || (crash_recovery.child_terminated_abruptly
            && crash_recovery.synchronized_marker_recovered);
    let persistent_ann_v2_runtime_exercised = vector_execution.ann_v2.exercised();
    let status = if regressions
        .iter()
        .all(|hook| hook.status == HookStatus::MeasuredPass)
        && persistent_ann_v2_runtime_exercised
        && !resource.budget_exceeded
        && resource.degraded_responses > 0
        && resource.correctness_failures == 0
        && crash_passed
    {
        SemanticExecutionStatus::DevelopmentComplete
    } else {
        SemanticExecutionStatus::DevelopmentIncomplete
    };
    let outcome = SemanticExecutionOutcome {
        schema_version: SEMANTIC_EXECUTION_SCHEMA_VERSION.to_owned(),
        dataset_version: DATASET_VERSION.to_owned(),
        admission_sha256: admission_sha256.to_owned(),
        started_unix_ms,
        finished_unix_ms: unix_millis()?,
        status,
        verified_semantic_nodes: verification.semantic_nodes,
        verified_logical_graph_edges: verification.logical_edges,
        verified_graph_directional_records: compaction_manifest.edge_count,
        verified_vectors: vector_execution.verified_vectors,
        persistent_ann_v2_runtime_exercised,
        scenarios,
        phases,
        regressions,
        resource,
        crash_recovery,
        expected_logical_digest: verification.digest,
        recovered_logical_digest: recovered.digest,
        artifacts: artifact_receipts,
        limitations: vec![
            "Development evidence only: this run is not independently witnessed, does not bind M16, and cannot emit release certification.".to_owned(),
            "ANN-v2 graph objects plus full-precision vectors, targets, vector-space definitions, and policy routes use separately verified redb stores; the exact in-memory index is retained only as the differential correctness oracle.".to_owned(),
            "The offline graph backup scenario does not copy or restore the separate ANN-v2 graph and durable-source redb files; their persistence is instead proven by closing, reopening, and exhaustively verifying both files in place.".to_owned(),
            "Persistent ANN-v2 construction and query are exercised at the selected development count only; this is not 1M-vector reference-hardware throughput, latency, or quality evidence.".to_owned(),
            "Cold autobiographical recall is measured after process-local backend reopen without operating-system page-cache eviction.".to_owned(),
            "The crash probe covers a synchronized Fjall storage write; semantic journal/outbox crash matrices remain separate M16 evidence.".to_owned(),
            "Social-calibration/model quality is unavailable in this scale runner and must be supplied by a frozen BENCH-A regression artifact.".to_owned(),
        ],
    };
    let outcome_bytes = serde_json::to_vec_pretty(&outcome)?;
    let outcome_path = root.join("semantic-execution-outcome.json");
    write_new(&outcome_path, &outcome_bytes)?;
    let index = SemanticExecutionBundleIndex {
        schema_version: SEMANTIC_EXECUTION_INDEX_SCHEMA_VERSION.to_owned(),
        outcome_uri: "semantic-execution-outcome.json".to_owned(),
        outcome_bytes: usize_to_u64(outcome_bytes.len()),
        outcome_sha256: sha256_hex(&outcome_bytes),
    };
    let index_bytes = serde_json::to_vec_pretty(&index)?;
    write_new(&root.join("semantic-execution-index.json"), &index_bytes)?;
    Ok(index)
}

fn ingest_semantic_nodes(
    store: &GraphStore<FjallStorage>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
) -> Result<PhaseExecution> {
    let phase_started = Instant::now();
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let setup_seq = CommitSeq::new(1);
    let setup_started = Instant::now();
    let visible_envelope = fixture.envelope(config.seed, false, 0)?;
    let private_envelope = fixture.envelope(config.seed, true, 1)?;
    let visible_node = make_node(fixture, config.seed, 0, setup_seq)?;
    let private_node = make_node(fixture, config.seed, 1, setup_seq)?;
    let visible_policy = visible_envelope.ownership.clone();
    let private_policy = private_envelope.ownership.clone();
    store
        .commit(
            GraphMutation {
                base_storage_seq: 0,
                workspaces: vec![Workspace {
                    id: fixture.workspace,
                    name: "M17 deterministic semantic workload".to_owned(),
                    policy_profile: stable_id::<PolicyId>(
                        config.seed,
                        5_000_000_001,
                        PolicyId::from_uuid,
                    )?,
                    ontology_profile: DATASET_VERSION.to_owned(),
                    state: WorkspaceState::Active,
                }],
                memory_spaces: vec![
                    MemorySpace {
                        id: fixture.visible_space,
                        workspace_id: fixture.workspace,
                        kind: MemorySpaceKind::UserPrivate,
                        owners: NonEmptyVec::new(fixture.visible_owner),
                        default_policy: visible_policy,
                        retention_policy: RetentionPolicy::Indefinite,
                        parent: None,
                    },
                    MemorySpace {
                        id: fixture.private_space,
                        workspace_id: fixture.workspace,
                        kind: MemorySpaceKind::UserPrivate,
                        owners: NonEmptyVec::new(fixture.private_owner),
                        default_policy: private_policy,
                        retention_policy: RetentionPolicy::Indefinite,
                        parent: None,
                    },
                ],
                memory_subjects: vec![
                    MemorySubject {
                        id: fixture.visible_owner,
                        workspace_id: fixture.workspace,
                        kind: SubjectKind::User,
                        canonical_node: visible_node.id,
                        primary_spaces: NonEmptyVec::new(fixture.visible_space),
                        continuity_policy: stable_id::<PolicyId>(
                            config.seed,
                            5_000_000_002,
                            PolicyId::from_uuid,
                        )?,
                    },
                    MemorySubject {
                        id: fixture.private_owner,
                        workspace_id: fixture.workspace,
                        kind: SubjectKind::User,
                        canonical_node: private_node.id,
                        primary_spaces: NonEmptyVec::new(fixture.private_space),
                        continuity_policy: stable_id::<PolicyId>(
                            config.seed,
                            5_000_000_003,
                            PolicyId::from_uuid,
                        )?,
                    },
                ],
                nodes: vec![visible_node, private_node],
                node_revisions: vec![
                    make_node_revision(fixture, config.seed, 0, setup_seq)?,
                    make_node_revision(fixture, config.seed, 1, setup_seq)?,
                ],
                artifacts: vec![make_artifact(fixture, config.seed, visible_envelope)?],
                ..GraphMutation::default()
            },
            Durability::Sync,
        )
        .map_err(graph_error)?;
    samples.push(nanos(setup_started.elapsed()));

    let mut next = 2_u64;
    while next < config.semantic_nodes {
        let end = next
            .saturating_add(config.node_batch_size)
            .min(config.semantic_nodes);
        let before = store
            .snapshot(SnapshotSelector::Latest)
            .map_err(graph_error)?;
        let semantic_seq =
            before
                .semantic_seq
                .checked_next()
                .ok_or(BenchError::ArithmeticOverflow(
                    "semantic node commit sequence",
                ))?;
        let capacity = usize::try_from(end - next)
            .map_err(|_| BenchError::ArithmeticOverflow("semantic node batch capacity"))?;
        let mut nodes = Vec::with_capacity(capacity);
        let mut revisions = Vec::with_capacity(capacity);
        for index in next..end {
            nodes.push(make_node(fixture, config.seed, index, semantic_seq)?);
            revisions.push(make_node_revision(
                fixture,
                config.seed,
                index,
                semantic_seq,
            )?);
        }
        let batch_started = Instant::now();
        store
            .commit(
                GraphMutation {
                    base_storage_seq: before.storage_seq,
                    nodes,
                    node_revisions: revisions,
                    ..GraphMutation::default()
                },
                Durability::Sync,
            )
            .map_err(graph_error)?;
        samples.push(nanos(batch_started.elapsed()));
        next = end;
        progress("semantic_nodes", next, config.semantic_nodes);
    }
    let elapsed = nanos(phase_started.elapsed());
    Ok(PhaseExecution {
        phase: "semantic_node_ingest".to_owned(),
        completed_operations: config.semantic_nodes,
        elapsed_ns: elapsed,
        latency: samples.summary()?,
    })
}

fn ingest_semantic_edges(
    store: &GraphStore<FjallStorage>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
) -> Result<PhaseExecution> {
    let phase_started = Instant::now();
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let mut next = 0_u64;
    while next < config.graph_edges {
        let end = next
            .saturating_add(config.edge_batch_size)
            .min(config.graph_edges);
        let before = store
            .snapshot(SnapshotSelector::Latest)
            .map_err(graph_error)?;
        let semantic_seq =
            before
                .semantic_seq
                .checked_next()
                .ok_or(BenchError::ArithmeticOverflow(
                    "semantic edge commit sequence",
                ))?;
        let capacity = usize::try_from(end - next)
            .map_err(|_| BenchError::ArithmeticOverflow("semantic edge batch capacity"))?;
        let mut edges = Vec::with_capacity(capacity);
        let mut revisions = Vec::with_capacity(capacity);
        for index in next..end {
            let (edge, revision) = make_edge(fixture, config, index, semantic_seq)?;
            edges.push(edge);
            revisions.push(revision);
        }
        let batch_started = Instant::now();
        store
            .commit(
                GraphMutation {
                    base_storage_seq: before.storage_seq,
                    edges,
                    edge_revisions: revisions,
                    ..GraphMutation::default()
                },
                Durability::Sync,
            )
            .map_err(graph_error)?;
        samples.push(nanos(batch_started.elapsed()));
        next = end;
        progress("graph_edges", next, config.graph_edges);
    }
    let elapsed = nanos(phase_started.elapsed());
    Ok(PhaseExecution {
        phase: "logical_graph_edge_ingest".to_owned(),
        completed_operations: config.graph_edges,
        elapsed_ns: elapsed,
        latency: samples.summary()?,
    })
}

fn make_node(
    fixture: &SemanticFixture,
    seed: u64,
    index: u64,
    commit_seq: CommitSeq,
) -> Result<Node> {
    let private = index == 1;
    Ok(Node {
        id: fixture.node_id(seed, index)?,
        workspace_id: fixture.workspace,
        node_type: if index.is_multiple_of(7) {
            NodeType::Event
        } else {
            NodeType::Entity
        },
        created_seq: commit_seq,
        retired_seq: None,
        identity_state: IdentityState::Canonical,
        primary_scope: ScopeRef {
            kind: ScopeKind::MemorySpace,
            id: if private {
                fixture.private_scope
            } else {
                fixture.visible_scope
            },
            inheritance: ScopeInheritance::Exact,
        },
    })
}

fn make_node_revision(
    fixture: &SemanticFixture,
    seed: u64,
    index: u64,
    commit_seq: CommitSeq,
) -> Result<NodeRevision> {
    let private = index == 1;
    Ok(NodeRevision {
        node_id: fixture.node_id(seed, index)?,
        revision: RevisionNumber::FIRST,
        temporal: BitemporalRange {
            valid_time: TimeRange::open_ended(TimestampMicros(0)),
            transaction_time: CommitRange::current(commit_seq),
        },
        canonical_name: if private {
            PRIVATE_CANARY.to_owned()
        } else {
            format!("semantic-node-{index:020}")
        },
        attributes: BTreeMap::new(),
        epistemic: epistemic(),
        confidence: confidence(),
        evidence: Vec::new(),
        envelope: fixture.envelope(seed, private, 10_000_u64.saturating_add(index))?,
    })
}

fn make_edge(
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    index: u64,
    commit_seq: CommitSeq,
) -> Result<(Edge, EdgeRevision)> {
    let visible_nodes = config.semantic_nodes.saturating_sub(1);
    let source_visible = index % visible_nodes;
    let mut target_visible = index.saturating_mul(6_361).saturating_add(1) % visible_nodes;
    if target_visible == source_visible {
        target_visible = (target_visible + 1) % visible_nodes;
    }
    let source_index = visible_ordinal_to_node(source_visible);
    let target_index = visible_ordinal_to_node(target_visible);
    let edge_id = fixture.edge_id(config.seed, index)?;
    Ok((
        Edge {
            id: edge_id,
            workspace_id: fixture.workspace,
            source: fixture.node_id(config.seed, source_index)?,
            target: fixture.node_id(config.seed, target_index)?,
            edge_type: fixture.edge_type,
            directionality: Directionality::Directed,
            created_seq: commit_seq,
            materialized_from_claim: None,
        },
        EdgeRevision {
            edge_id,
            revision: RevisionNumber::FIRST,
            temporal: BitemporalRange {
                valid_time: TimeRange::open_ended(TimestampMicros(0)),
                transaction_time: CommitRange::current(commit_seq),
            },
            weight: 1.0,
            epistemic: epistemic(),
            confidence: confidence(),
            evidence: Vec::new(),
            attributes: BTreeMap::new(),
            envelope: fixture.envelope(
                config.seed,
                false,
                100_000_000_u64.saturating_add(index),
            )?,
        },
    ))
}

fn make_artifact(
    fixture: &SemanticFixture,
    seed: u64,
    envelope: SemanticEnvelope,
) -> Result<Artifact> {
    Ok(Artifact {
        id: fixture.artifact,
        source_id: stable_id::<SourceId>(seed, 5_000_000_100, SourceId::from_uuid)?,
        modality: Modality::Structured,
        media_type: "application/vnd.contextdb.bench-h+json".to_owned(),
        native_locator: None,
        content_blocks: NonEmptyVec::new(stable_id::<ContentBlockId>(
            seed,
            5_000_000_101,
            ContentBlockId::from_uuid,
        )?),
        content_hash: ContentDigest::from_bytes(
            *blake3::hash(DATASET_VERSION.as_bytes()).as_bytes(),
        ),
        created_at: Some(TimestampMicros(0)),
        ingested_at: TimestampMicros(1),
        envelope,
    })
}

fn epistemic() -> EpistemicState {
    EpistemicState {
        // The scale fixture is synthetic and carries no durable EvidenceId objects.
        // `Hypothesis` is the only honest basis accepted without pretending a
        // benchmark-generated external lineage reference is semantic evidence.
        basis: EpistemicBasis::Hypothesis,
        acceptance: AcceptanceState::Accepted,
        conflict: contextdb_core::ConflictState::None,
        lifecycle: LifecycleState::Active,
    }
}

fn confidence() -> ConfidenceProfile {
    ConfidenceProfile {
        overall: 1.0,
        source_trust: 1.0,
        extraction_quality: 1.0,
        corroboration: 1.0,
    }
}

fn build_vectors(
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    watermark: CommitSeq,
    ann_v2_path: &Path,
    ann_v2_source_path: &Path,
) -> Result<VectorExecution> {
    let phase_started = Instant::now();
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let mut index = VectorIndex::new();
    let mut inserted_vectors = 0_u64;
    let vector_space = VectorSpace {
        id: fixture.vector_space,
        dimensions: config.vector_dimensions,
        metric: VectorMetric::DotProduct,
        model_family: "deterministic-m17-fixture".to_owned(),
        model_revision: "1".to_owned(),
        preprocessing_revision: "1".to_owned(),
        modality: Modality::Structured,
    };
    index
        .register_space(vector_space.clone())
        .map_err(index_error)?;
    let source_import = PersistentAnnVectorSourceV2::begin_import(
        RedbStorage::open(ann_v2_source_path)?,
        AnnSourceImportPlanV2 {
            vector_store_generation: ANN_V2_VECTOR_SOURCE_GENERATION,
            route_generation: ANN_V2_ROUTE_SOURCE_GENERATION,
            expected_vector_spaces: 1,
            expected_records: config.vectors,
        },
        Durability::Sync,
    )
    .map_err(index_error)?;
    source_import
        .put_vector_space(&vector_space)
        .map_err(index_error)?;
    let mut source_page = Vec::with_capacity(ANN_SOURCE_IMPORT_PAGE_ENTRIES);
    let insert_started = Instant::now();
    for vector_index in 0..config.vectors {
        let private = vector_index == 1;
        let node_index = if private {
            1
        } else {
            visible_ordinal_to_node(vector_index % config.semantic_nodes.saturating_sub(1))
        };
        let record = VectorRecord {
            id: fixture.representation_id(config.seed, vector_index)?,
            target: LineageNode::NodeRevision {
                id: fixture.node_id(config.seed, node_index)?,
                revision: RevisionNumber::FIRST,
            },
            vector_space_id: fixture.vector_space,
            values: vector_values(vector_index, config.vector_dimensions)?,
            policy: fixture.index_policy(private),
            valid_time: TimeRange::open_ended(TimestampMicros(0)),
            projected_at: watermark,
            lineage: vec![LineageNode::External {
                namespace: "m17-vector-fixture".to_owned(),
                identifier: vector_index.to_string(),
            }],
            tombstone_at: None,
        };
        index.insert(record.clone()).map_err(index_error)?;
        source_page.push(record);
        if source_page.len() == ANN_SOURCE_IMPORT_PAGE_ENTRIES {
            source_import
                .put_records_page(&source_page)
                .map_err(index_error)?;
            source_page.clear();
        }
        inserted_vectors = inserted_vectors
            .checked_add(1)
            .ok_or(BenchError::ArithmeticOverflow("inserted vectors"))?;
        if vector_index > 0 && vector_index % progress_interval(config.vectors) == 0 {
            progress("vectors", vector_index, config.vectors);
        }
    }
    if !source_page.is_empty() {
        source_import
            .put_records_page(&source_page)
            .map_err(index_error)?;
    }
    let persistent_source = source_import.finish().map_err(index_error)?;
    let source_verification = persistent_source.verification();
    if source_verification.record_count != inserted_vectors
        || source_verification.vector_space_count != 1
    {
        return Err(integrity(
            "durable ANN source verification disagrees with imported cardinality",
        ));
    }
    samples.push(nanos(insert_started.elapsed()));
    let store_bundle = index.export_store(watermark).map_err(index_error)?;
    let private_id = fixture.representation_id(config.seed, 1)?;
    let source = AuditedAnnSource::new(&persistent_source, private_id);
    let ann_storage = RedbStorage::open(ann_v2_path)?;
    let ann_storage_probe = ann_storage.clone();
    let runtime = PersistentAnnV2::open(ann_storage).map_err(index_error)?;
    let freshness_started = Instant::now();
    let publication = runtime
        .rebuild_and_publish(
            &source,
            ANN_V2_RUNTIME_GENERATION,
            watermark,
            ann_v2_build_parameters(),
            Durability::Sync,
        )
        .map_err(index_error)?;
    let immediate_verification = runtime
        .verify_active()
        .map_err(index_error)?
        .ok_or_else(|| integrity("ANN-v2 publication has no active generation"))?;
    if publication.verification != immediate_verification
        || immediate_verification.node_count() != inserted_vectors
    {
        return Err(integrity(
            "ANN-v2 publication and immediate complete verification disagree",
        ));
    }
    let immediate_storage_sequence = ann_storage_probe
        .begin_read(SnapshotSelector::Latest)?
        .sequence();
    if immediate_storage_sequence < publication.storage_sequence {
        return Err(integrity(
            "ANN-v2 verified storage sequence predates publication",
        ));
    }
    let (immediate_differential, ann_overlap_bps, filtered_ann_scenario) =
        measure_persistent_ann_v2(&runtime, &source, &index, fixture, config, watermark)?;
    let freshness_ns = nanos(freshness_started.elapsed());
    samples.push(freshness_ns);
    let (private_isolation_passed, verified_vectors) =
        verify_vector_privacy(&index, fixture, config, watermark)?;
    if verified_vectors != inserted_vectors {
        return Err(integrity(format!(
            "authorized exact-vector census found {verified_vectors} records after inserting {inserted_vectors}"
        )));
    }
    let ann_source_private_isolation = immediate_differential.private_vector_reads == 0
        && immediate_differential.private_target_reads == 0;
    let elapsed = nanos(phase_started.elapsed());
    Ok(VectorExecution {
        index,
        store_bundle,
        ann_v2: PersistentAnnV2ExecutionEvidence {
            schema_version: "contextdb.bench-h-persistent-ann-v2-execution/v2".to_owned(),
            backend: "redb".to_owned(),
            source_bridge: "redb_paged_full_precision_source_v1".to_owned(),
            source: source_verification.into(),
            vector_store_generation: ANN_V2_VECTOR_SOURCE_GENERATION,
            route_generation: ANN_V2_ROUTE_SOURCE_GENERATION,
            publication_generation: publication.generation,
            publication_storage_sequence: publication.storage_sequence,
            publication_verification: publication.verification.into(),
            immediate_storage_sequence,
            immediate_verification: immediate_verification.into(),
            immediate_differential,
            reopened: None,
        },
        build_phase: PhaseExecution {
            phase: "full_precision_vector_ingest_and_persistent_ann_v2_publish".to_owned(),
            completed_operations: inserted_vectors,
            elapsed_ns: elapsed,
            latency: samples.summary()?,
        },
        verified_vectors,
        ann_overlap_bps,
        private_isolation_passed: private_isolation_passed && ann_source_private_isolation,
        filtered_ann_scenario,
        freshness_ns,
    })
}

fn ann_v2_build_parameters() -> AnnBuildParametersV2 {
    AnnBuildParametersV2 {
        algorithm: AnnAlgorithmV2::DeterministicHnswV1,
        partition_scheme: AnnPartitionSchemeV2::ExactPolicyV1,
        max_level: 4,
        neighbours_per_level: 64,
        construction_max_visits: 512,
    }
}

fn measure_persistent_ann_v2(
    runtime: &PersistentAnnV2<RedbStorage>,
    source: &AuditedAnnSource<'_>,
    index: &VectorIndex,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    watermark: CommitSeq,
) -> Result<(AnnV2DifferentialEvidence, f64, ScenarioExecution)> {
    source.reset_audit()?;
    let universe = runtime
        .authorize(source, &fixture.index_principal(false), watermark)
        .map_err(index_error)?;
    let persistent_authorized_routes = universe.authorized_count();
    let authorization_audit = source.audit_snapshot()?;
    let exact_universe = index
        .authorize(&fixture.index_principal(false), watermark)
        .map_err(index_error)?;
    let scored = usize::try_from(config.vectors)
        .map_err(|_| BenchError::ArithmeticOverflow("vector exact score budget"))?;
    let query_count = config.queries_per_scenario.min(config.vectors.max(1));
    let mut overlap = 0_u64;
    let mut possible = 0_u64;
    let mut matching_id_and_score_hits = 0_u64;
    let mut all_queries_exact = true;
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let scenario_started = Instant::now();
    for query_index in 0..query_count {
        let visible_index = if query_index == 1 { 2 } else { query_index } % config.vectors;
        let values = vector_values(visible_index, config.vector_dimensions)?;
        let exact = index
            .search_exact(
                &exact_universe,
                VectorQuery {
                    vector_space_id: fixture.vector_space,
                    values: &values,
                    valid_at: Some(TimestampMicros(1)),
                    limit: 10,
                },
                scored.max(1),
            )
            .map_err(index_error)?;
        let started = Instant::now();
        let ann = runtime
            .search(
                source,
                &universe,
                AnnQueryV2 {
                    vector_space_id: fixture.vector_space,
                    values: &values,
                    valid_at: Some(TimestampMicros(1)),
                    limit: 10,
                },
                AnnQueryBudgetV2 {
                    max_ann_visits: scored.clamp(64, 65_536),
                    ef_search: scored.clamp(64, 512),
                    max_exact_scores: scored.clamp(1, 1_000_000),
                },
            )
            .map_err(index_error)?;
        samples.push(nanos(started.elapsed()));
        let exact_ids = exact
            .hits
            .iter()
            .map(|hit| hit.representation_id)
            .collect::<BTreeSet<_>>();
        overlap = overlap.saturating_add(
            u64::try_from(
                ann.hits
                    .iter()
                    .filter(|hit| exact_ids.contains(&hit.representation_id))
                    .count(),
            )
            .unwrap_or(u64::MAX),
        );
        possible = possible.saturating_add(u64::try_from(exact_ids.len()).unwrap_or(u64::MAX));
        let exact_query_match = ann.hits.len() == exact.hits.len()
            && ann.hits.iter().zip(&exact.hits).all(|(left, right)| {
                left.representation_id == right.representation_id
                    && left.score.to_bits() == right.score.to_bits()
            });
        all_queries_exact &= exact_query_match;
        matching_id_and_score_hits = matching_id_and_score_hits.saturating_add(
            u64::try_from(
                ann.hits
                    .iter()
                    .zip(&exact.hits)
                    .filter(|(left, right)| {
                        left.representation_id == right.representation_id
                            && left.score.to_bits() == right.score.to_bits()
                    })
                    .count(),
            )
            .unwrap_or(u64::MAX),
        );
    }
    let elapsed = nanos(scenario_started.elapsed());
    let final_audit = source.audit_snapshot()?;
    let overlap_bps = if possible == 0 {
        0.0
    } else {
        overlap as f64 * 10_000.0 / possible as f64
    };
    let differential = AnnV2DifferentialEvidence {
        queries: query_count,
        exact_hits: possible,
        matching_id_and_score_hits,
        all_queries_exact,
        persistent_authorized_routes,
        authorization_route_page_reads: authorization_audit.route_page_reads,
        authorization_vector_reads: authorization_audit.vector_reads,
        authorization_target_reads: authorization_audit.target_reads,
        query_vector_reads: final_audit
            .vector_reads
            .saturating_sub(authorization_audit.vector_reads),
        query_target_reads: final_audit
            .target_reads
            .saturating_sub(authorization_audit.target_reads),
        private_vector_reads: final_audit.private_vector_reads,
        private_target_reads: final_audit.private_target_reads,
    };
    runtime
        .release_universe(universe, Durability::Sync)
        .map_err(index_error)?;
    Ok((
        differential,
        overlap_bps,
        ScenarioExecution {
            scenario: ExecutionScenario::FilteredAnn,
            completed_operations: query_count,
            elapsed_ns: elapsed,
            operations_per_second: operations_per_second(query_count, elapsed),
            latency: samples.summary()?,
            implementation_path: "storage-backed policy universe over redb-backed persistent ANN-v2 traversal with exact full-precision reranking and exact-oracle differential".to_owned(),
        },
    ))
}

fn verify_vector_privacy(
    index: &VectorIndex,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    watermark: CommitSeq,
) -> Result<(bool, u64)> {
    let values = vector_values(1, config.vector_dimensions)?;
    let query = VectorQuery {
        vector_space_id: fixture.vector_space,
        values: &values,
        valid_at: Some(TimestampMicros(1)),
        limit: 10,
    };
    let visible = index
        .authorize(&fixture.index_principal(false), watermark)
        .map_err(index_error)?;
    let private = index
        .authorize(&fixture.index_principal(true), watermark)
        .map_err(index_error)?;
    let budget = usize::try_from(config.vectors)
        .map_err(|_| BenchError::ArithmeticOverflow("vector privacy score budget"))?
        .max(1);
    let visible_result = index
        .search_exact(&visible, query, budget)
        .map_err(index_error)?;
    let private_result = index
        .search_exact(&private, query, budget)
        .map_err(index_error)?;
    let private_id = fixture.representation_id(config.seed, 1)?;
    let private_isolation_passed = !visible_result
        .hits
        .iter()
        .any(|hit| hit.representation_id == private_id)
        && private_result
            .hits
            .iter()
            .any(|hit| hit.representation_id == private_id);
    let verified_vectors = visible_result
        .trace
        .authorized_scored
        .checked_add(private_result.trace.authorized_scored)
        .ok_or(BenchError::ArithmeticOverflow("verified vectors"))?;
    Ok((private_isolation_passed, verified_vectors))
}

fn verify_reopened_persistent_ann_v2(
    ann_v2_path: &Path,
    ann_v2_source_path: &Path,
    index: &VectorIndex,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    watermark: CommitSeq,
    evidence: &mut PersistentAnnV2ExecutionEvidence,
) -> Result<()> {
    let persistent_source =
        PersistentAnnVectorSourceV2::open(RedbStorage::open(ann_v2_source_path)?)
            .map_err(index_error)?;
    let reopened_source = DurableAnnSourceEvidence::from(persistent_source.verification());
    if reopened_source != evidence.source {
        return Err(integrity(
            "reopened durable ANN source roots or cardinality disagree with publication",
        ));
    }
    let source = AuditedAnnSource::new(
        &persistent_source,
        fixture.representation_id(config.seed, 1)?,
    );
    let storage = RedbStorage::open(ann_v2_path)?;
    let storage_probe = storage.clone();
    let runtime = PersistentAnnV2::open(storage).map_err(index_error)?;
    let recovery = runtime.recover(Durability::Sync).map_err(index_error)?;
    let verification = runtime
        .verify_active()
        .map_err(index_error)?
        .ok_or_else(|| integrity("reopened ANN-v2 runtime has no active generation"))?;
    let storage_sequence = storage_probe
        .begin_read(SnapshotSelector::Latest)?
        .sequence();
    if storage_sequence < evidence.publication_storage_sequence
        || recovery.active_generation != evidence.publication_generation
        || verification.generation() != evidence.publication_generation
    {
        return Err(integrity(
            "reopened ANN-v2 generation or storage sequence disagrees with publication",
        ));
    }
    let (differential, _, _) =
        measure_persistent_ann_v2(&runtime, &source, index, fixture, config, watermark)?;
    evidence.reopened = Some(AnnV2ReopenEvidence {
        source: reopened_source,
        storage_sequence,
        recovery_active_generation: recovery.active_generation,
        recovery_abandoned_generation: recovery.abandoned_generation,
        recovery_objects_deleted: recovery.objects_deleted,
        verification: verification.into(),
        differential,
    });
    Ok(())
}

fn vector_values(index: u64, dimensions: u32) -> Result<Vec<f32>> {
    let capacity = usize::try_from(dimensions)
        .map_err(|_| BenchError::ArithmeticOverflow("vector dimensions"))?;
    let mut values = Vec::with_capacity(capacity);
    for dimension in 0..dimensions {
        let mixed = index
            .wrapping_mul(31)
            .wrapping_add(u64::from(dimension).wrapping_mul(17))
            % 997;
        values.push((mixed.saturating_add(1)) as f32 / 997.0);
    }
    Ok(values)
}

fn run_read_scenarios(
    store: &GraphStore<FjallStorage>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    snapshot: &contextdb_graph::GraphSnapshot,
    vector: &VectorExecution,
) -> Result<Vec<ScenarioExecution>> {
    let scenarios = vec![
        measure_graph_nodes(
            ExecutionScenario::HotConversation,
            store,
            fixture,
            config,
            snapshot,
            true,
            "repeated authorized semantic node read at one stable graph snapshot",
        )?,
        measure_graph_nodes(
            ExecutionScenario::CurrentFact,
            store,
            fixture,
            config,
            snapshot,
            false,
            "rotating authorized current semantic node reads",
        )?,
        measure_historical_nodes(store, fixture, config, snapshot)?,
        measure_hierarchy(store, fixture, config, snapshot)?,
        measure_artifact(store, fixture, config, snapshot)?,
        vector.filtered_ann_scenario.clone(),
    ];
    Ok(scenarios)
}

#[allow(
    clippy::too_many_arguments,
    reason = "scenario measurement binds exact store, snapshot, fixture, and workload"
)]
fn measure_graph_nodes(
    scenario: ExecutionScenario,
    store: &GraphStore<FjallStorage>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    snapshot: &contextdb_graph::GraphSnapshot,
    hot: bool,
    path: &str,
) -> Result<ScenarioExecution> {
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let started_all = Instant::now();
    for query in 0..config.queries_per_scenario {
        let visible = if hot {
            0
        } else {
            query % config.semantic_nodes.saturating_sub(1)
        };
        let node = fixture.node_id(config.seed, visible_ordinal_to_node(visible))?;
        let started = Instant::now();
        store
            .node(node, snapshot, &fixture.visible_principal())
            .map_err(graph_error)?;
        samples.push(nanos(started.elapsed()));
    }
    let elapsed = nanos(started_all.elapsed());
    Ok(ScenarioExecution {
        scenario,
        completed_operations: config.queries_per_scenario,
        elapsed_ns: elapsed,
        operations_per_second: operations_per_second(config.queries_per_scenario, elapsed),
        latency: samples.summary()?,
        implementation_path: path.to_owned(),
    })
}

fn measure_historical_nodes(
    store: &GraphStore<FjallStorage>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    snapshot: &contextdb_graph::GraphSnapshot,
) -> Result<ScenarioExecution> {
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let started_all = Instant::now();
    for query in 0..config.queries_per_scenario {
        let visible = query % config.semantic_nodes.saturating_sub(1);
        let node = fixture.node_id(config.seed, visible_ordinal_to_node(visible))?;
        let started = Instant::now();
        store
            .node_at_valid_time(
                node,
                TimestampMicros(1),
                snapshot,
                &fixture.visible_principal(),
            )
            .map_err(graph_error)?;
        samples.push(nanos(started.elapsed()));
    }
    let elapsed = nanos(started_all.elapsed());
    Ok(ScenarioExecution {
        scenario: ExecutionScenario::HistoricalFact,
        completed_operations: config.queries_per_scenario,
        elapsed_ns: elapsed,
        operations_per_second: operations_per_second(config.queries_per_scenario, elapsed),
        latency: samples.summary()?,
        implementation_path: "bitemporal node revision lookup at an explicit valid-time instant"
            .to_owned(),
    })
}

fn measure_hierarchy(
    store: &GraphStore<FjallStorage>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    snapshot: &contextdb_graph::GraphSnapshot,
) -> Result<ScenarioExecution> {
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let started_all = Instant::now();
    let edge_types = BTreeSet::from([fixture.edge_type]);
    for query in 0..config.queries_per_scenario {
        let visible = query % config.semantic_nodes.saturating_sub(1);
        let node = fixture.node_id(config.seed, visible_ordinal_to_node(visible))?;
        let started = Instant::now();
        store
            .traverse(
                &[node],
                Direction::Outgoing,
                &edge_types,
                2,
                64,
                snapshot,
                &fixture.visible_principal(),
            )
            .map_err(graph_error)?;
        samples.push(nanos(started.elapsed()));
    }
    let elapsed = nanos(started_all.elapsed());
    Ok(ScenarioExecution {
        scenario: ExecutionScenario::HierarchyDrillDown,
        completed_operations: config.queries_per_scenario,
        elapsed_ns: elapsed,
        operations_per_second: operations_per_second(config.queries_per_scenario, elapsed),
        latency: samples.summary()?,
        implementation_path:
            "bounded two-hop typed traversal over authorized paged graph-v2 adjacency".to_owned(),
    })
}

fn measure_artifact(
    store: &GraphStore<FjallStorage>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    snapshot: &contextdb_graph::GraphSnapshot,
) -> Result<ScenarioExecution> {
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let started_all = Instant::now();
    for _ in 0..config.queries_per_scenario {
        let started = Instant::now();
        store
            .artifact(fixture.artifact, snapshot, &fixture.visible_principal())
            .map_err(graph_error)?;
        samples.push(nanos(started.elapsed()));
    }
    let elapsed = nanos(started_all.elapsed());
    Ok(ScenarioExecution {
        scenario: ExecutionScenario::ArtifactMetadata,
        completed_operations: config.queries_per_scenario,
        elapsed_ns: elapsed,
        operations_per_second: operations_per_second(config.queries_per_scenario, elapsed),
        latency: samples.summary()?,
        implementation_path:
            "policy-authorized immutable artifact metadata lookup without blob bytes".to_owned(),
    })
}

fn run_compaction_under_load(
    store: &Arc<GraphStore<FjallStorage>>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
) -> Result<(ScenarioExecution, SegmentManifest)> {
    let before = store
        .snapshot(SnapshotSelector::Latest)
        .map_err(graph_error)?;
    let query_store = Arc::clone(store);
    let compact_store = Arc::clone(store);
    let done = Arc::new(AtomicBool::new(false));
    let worker_done = Arc::clone(&done);
    let compaction_started = Instant::now();
    let worker = thread::spawn(move || {
        let result = compact_store.compact_graph(Durability::Sync);
        worker_done.store(true, Ordering::Release);
        result
    });
    let mut samples = BoundedSamples::new(config.maximum_samples);
    let mut completed = 0_u64;
    while !done.load(Ordering::Acquire) || completed == 0 {
        let visible = completed % config.semantic_nodes.saturating_sub(1);
        let node = fixture.node_id(config.seed, visible_ordinal_to_node(visible))?;
        let started = Instant::now();
        query_store
            .node(node, &before, &fixture.visible_principal())
            .map_err(graph_error)?;
        samples.push(nanos(started.elapsed()));
        completed = completed.saturating_add(1);
        if completed >= config.queries_per_scenario && done.load(Ordering::Acquire) {
            break;
        }
    }
    let manifest = worker
        .join()
        .map_err(|_| BenchError::WorkerPanicked)?
        .map_err(graph_error)?;
    let elapsed = nanos(compaction_started.elapsed());
    Ok((
        ScenarioExecution {
            scenario: ExecutionScenario::CompactionUnderLoad,
            completed_operations: completed,
            elapsed_ns: elapsed,
            operations_per_second: operations_per_second(completed, elapsed),
            latency: samples.summary()?,
            implementation_path:
                "authorized reads against a stable snapshot while graph-v2 builds and atomically switches an immutable adjacency generation"
                    .to_owned(),
        },
        manifest,
    ))
}

fn run_pressure(
    store: &Arc<GraphStore<FjallStorage>>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
) -> Result<PressureOutcome> {
    let snapshot = store
        .snapshot(SnapshotSelector::Latest)
        .map_err(graph_error)?;
    let principal = fixture.visible_principal();
    let worker_store = Arc::clone(store);
    let worker_fixture = fixture.clone();
    let seed = config.seed;
    let visible_nodes = config.semantic_nodes.saturating_sub(1);
    let (sender, receiver) = mpsc::sync_channel::<u64>(config.pressure_queue_capacity);
    let worker = thread::spawn(move || {
        let mut failures = 0_u64;
        while let Ok(request) = receiver.recv() {
            let visible = request % visible_nodes;
            let node = match worker_fixture.node_id(seed, visible_ordinal_to_node(visible)) {
                Ok(node) => node,
                Err(_) => {
                    failures = failures.saturating_add(1);
                    continue;
                }
            };
            if worker_store.node(node, &snapshot, &principal).is_err() {
                failures = failures.saturating_add(1);
            }
            thread::sleep(Duration::from_millis(1));
        }
        failures
    });
    let mut admitted = 0_u64;
    let mut degraded = 0_u64;
    for request in 0..config.pressure_requests {
        match sender.try_send(request) {
            Ok(()) => admitted = admitted.saturating_add(1),
            Err(mpsc::TrySendError::Full(_)) => degraded = degraded.saturating_add(1),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(integrity("pressure worker disconnected"));
            }
        }
    }
    drop(sender);
    let correctness_failures = worker.join().map_err(|_| BenchError::WorkerPanicked)?;
    if admitted.saturating_add(degraded) != config.pressure_requests {
        return Err(integrity("pressure request accounting is not exact"));
    }
    Ok(PressureOutcome {
        requests: config.pressure_requests,
        admitted,
        degraded,
        correctness_failures,
    })
}

fn verify_graph(
    store: &GraphStore<FjallStorage>,
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
    snapshot: &contextdb_graph::GraphSnapshot,
) -> Result<GraphVerification> {
    let principal = fixture.visible_principal();
    let private_principal = fixture.private_principal();
    let mut actual = blake3::Hasher::new();
    actual.update(b"contextdb.m17.semantic-logical-state/v1\0");
    let mut semantic_nodes = 0_u64;
    for index in 0..config.semantic_nodes {
        let node_id = fixture.node_id(config.seed, index)?;
        let state = store
            .node(
                node_id,
                snapshot,
                if index == 1 {
                    &private_principal
                } else {
                    &principal
                },
            )
            .map_err(graph_error)?;
        actual.update(state.node.id.as_uuid().as_bytes());
        actual.update(state.revision.canonical_name.as_bytes());
        semantic_nodes = semantic_nodes
            .checked_add(1)
            .ok_or(BenchError::ArithmeticOverflow("verified semantic nodes"))?;
        if index > 0 && index % progress_interval(config.semantic_nodes) == 0 {
            progress("verify_nodes", index, config.semantic_nodes);
        }
    }
    let mut logical_edges = 0_u64;
    for index in 0..config.graph_edges {
        let edge_id = fixture.edge_id(config.seed, index)?;
        let state = store
            .edge(edge_id, snapshot, &principal)
            .map_err(graph_error)?;
        actual.update(state.edge.id.as_uuid().as_bytes());
        actual.update(state.edge.source.as_uuid().as_bytes());
        actual.update(state.edge.target.as_uuid().as_bytes());
        logical_edges = logical_edges
            .checked_add(1)
            .ok_or(BenchError::ArithmeticOverflow("verified logical edges"))?;
        if index > 0 && index % progress_interval(config.graph_edges) == 0 {
            progress("verify_edges", index, config.graph_edges);
        }
    }
    let actual_digest = actual.finalize().to_hex().to_string();
    let expected_digest = expected_graph_digest(fixture, config)?;
    if actual_digest != expected_digest {
        return Err(integrity(format!(
            "semantic graph digest mismatch: expected {expected_digest}, actual {actual_digest}"
        )));
    }
    Ok(GraphVerification {
        digest: actual_digest,
        semantic_nodes,
        logical_edges,
    })
}

fn expected_graph_digest(
    fixture: &SemanticFixture,
    config: &SemanticWorkloadConfig,
) -> Result<String> {
    let mut expected = blake3::Hasher::new();
    expected.update(b"contextdb.m17.semantic-logical-state/v1\0");
    for index in 0..config.semantic_nodes {
        expected.update(fixture.node_id(config.seed, index)?.as_uuid().as_bytes());
        if index == 1 {
            expected.update(PRIVATE_CANARY.as_bytes());
        } else {
            expected.update(format!("semantic-node-{index:020}").as_bytes());
        }
    }
    for index in 0..config.graph_edges {
        let (edge, _) = make_edge(fixture, config, index, CommitSeq::GENESIS)?;
        expected.update(edge.id.as_uuid().as_bytes());
        expected.update(edge.source.as_uuid().as_bytes());
        expected.update(edge.target.as_uuid().as_bytes());
    }
    Ok(expected.finalize().to_hex().to_string())
}

fn execute_crash_probe(
    root: &Path,
    executable: Option<&Path>,
    required: bool,
) -> Result<CrashRecoveryTrace> {
    let Some(executable) = executable else {
        return Ok(CrashRecoveryTrace {
            required,
            child_started: false,
            child_terminated_abruptly: false,
            synchronized_marker_recovered: false,
            recovery_latency_ns: None,
            marker_sha256: None,
            limitation: Some("current executable path was not supplied".to_owned()),
        });
    };
    if root.exists() {
        return invalid("crash_probe", "crash-probe state must not already exist");
    }
    fs::create_dir_all(root)?;
    let state = root.join("fjall");
    let mut child = Command::new(executable)
        .arg("--semantic-crash-child")
        .arg(&state)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| integrity("crash-probe child stdout was not piped"))?;
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        let read = reader.read_line(&mut line);
        let _ = ready_sender.send(read.map(|_| line));
    });
    let ready = ready_receiver
        .recv_timeout(Duration::from_secs(30))
        .map_err(|_| integrity("crash-probe child did not acknowledge its sync marker"))??;
    if ready.trim() != "SYNCED" {
        let _ = child.kill();
        let _ = child.wait();
        return Err(integrity(
            "crash-probe child emitted an unexpected acknowledgement",
        ));
    }
    child.kill()?;
    let status = child.wait()?;
    reader.join().map_err(|_| BenchError::WorkerPanicked)?;
    let recovery_started = Instant::now();
    let storage = FjallStorage::open(&state)?;
    let snapshot = storage.begin_read(SnapshotSelector::Latest)?;
    let marker_space = Keyspace::new("m17_crash_marker")?;
    let marker = snapshot
        .get(&marker_space, b"synchronized")?
        .ok_or_else(|| integrity("synchronized crash marker was not recovered"))?;
    let expected = b"contextdb-m17-synchronized-crash-marker";
    let recovered = marker == expected;
    storage.verify(VerifyMode::Deep)?;
    let elapsed = nanos(recovery_started.elapsed());
    Ok(CrashRecoveryTrace {
        required,
        child_started: true,
        child_terminated_abruptly: !status.success(),
        synchronized_marker_recovered: recovered,
        recovery_latency_ns: Some(elapsed),
        marker_sha256: Some(sha256_hex(&marker)),
        limitation: Some(
            "probe covers one synchronized Fjall storage marker, not the complete semantic journal/outbox fault matrix"
                .to_owned(),
        ),
    })
}

/// Child-only crash probe. The caller must terminate this process after reading `SYNCED`.
pub fn run_semantic_crash_child(root: &Path) -> Result<()> {
    let storage = FjallStorage::open(root)?;
    let marker_space = Keyspace::new("m17_crash_marker")?;
    let mut transaction = storage.begin_write()?;
    transaction.put(
        &marker_space,
        b"synchronized".to_vec(),
        b"contextdb-m17-synchronized-crash-marker".to_vec(),
    )?;
    transaction.commit(Durability::Sync)?;
    println!("SYNCED");
    std::io::stdout().flush()?;
    loop {
        thread::park_timeout(Duration::from_secs(60));
    }
}

fn copy_directory(source: &Path, target: &Path) -> Result<()> {
    if target.exists() {
        return invalid("backup", "backup target must not already exist");
    }
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let destination = target.join(entry.file_name());
        if metadata.is_dir() {
            copy_directory(&entry.path(), &destination)?;
        } else if metadata.is_file() {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn physical_state_manifest(root: &Path) -> Result<PhysicalStateManifest> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();
    let mut aggregate = blake3::Hasher::new();
    aggregate.update(b"contextdb.m17.physical-state-manifest/v1\0");
    let mut total_bytes = 0_u64;
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| integrity("physical state file escaped its root"))?
            .to_string_lossy()
            .replace('\\', "/");
        let mut file = fs::File::open(&path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut bytes = 0_u64;
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            bytes = bytes.saturating_add(usize_to_u64(read));
        }
        let digest = hasher.finalize().to_hex().to_string();
        aggregate.update(relative.as_bytes());
        aggregate.update(&bytes.to_be_bytes());
        aggregate.update(digest.as_bytes());
        total_bytes = total_bytes.saturating_add(bytes);
        files.push(PhysicalFileDigest {
            path: relative,
            bytes,
            blake3: digest,
        });
    }
    Ok(PhysicalStateManifest {
        algorithm: "contextdb.m17.physical-state-manifest/v1+blake3".to_owned(),
        files,
        aggregate_blake3: aggregate.finalize().to_hex().to_string(),
        total_bytes,
    })
}

fn collect_files(root: &Path, current: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_files(root, &entry.path(), output)?;
        } else if metadata.is_file() {
            let path = entry.path();
            if !path.starts_with(root) {
                return Err(integrity("physical state file escaped its root"));
            }
            output.push(path);
        }
    }
    Ok(())
}

fn write_artifact(
    root: &Path,
    path: &Path,
    kind: &str,
    bytes: &[u8],
) -> Result<SemanticExecutionArtifact> {
    write_new(path, bytes)?;
    let uri = path
        .strip_prefix(root)
        .map_err(|_| integrity("measurement artifact escaped execution root"))?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(SemanticExecutionArtifact {
        kind: kind.to_owned(),
        uri,
        bytes: usize_to_u64(bytes.len()),
        sha256: sha256_hex(bytes),
    })
}

fn scan_artifacts_for_private_canary(
    root: &Path,
    artifacts: &[SemanticExecutionArtifact],
) -> Result<bool> {
    for artifact in artifacts {
        let path = root.join(&artifact.uri);
        let bytes = fs::read(path)?;
        if bytes
            .windows(PRIVATE_CANARY.len())
            .any(|window| window == PRIVATE_CANARY.as_bytes())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        return invalid(
            "output",
            format!("refusing to overwrite {}", path.display()),
        );
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn scenario_from_elapsed(
    scenario: ExecutionScenario,
    completed_operations: u64,
    elapsed_ns: u64,
    path: &str,
) -> Result<ScenarioExecution> {
    Ok(ScenarioExecution {
        scenario,
        completed_operations,
        elapsed_ns,
        operations_per_second: operations_per_second(completed_operations, elapsed_ns),
        latency: single_latency(elapsed_ns)?,
        implementation_path: path.to_owned(),
    })
}

fn single_latency(elapsed_ns: u64) -> Result<LatencySummary> {
    let mut samples = BoundedSamples::new(1);
    samples.push(elapsed_ns);
    samples.summary()
}

fn operations_per_second(operations: u64, elapsed_ns: u64) -> f64 {
    if elapsed_ns == 0 {
        return 0.0;
    }
    operations as f64 * 1_000_000_000.0 / elapsed_ns as f64
}

fn percentile(samples: &[u64], percentile: usize) -> u64 {
    let index = samples
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(samples.len().saturating_sub(1));
    samples[index]
}

fn pass_status(passed: bool) -> HookStatus {
    if passed {
        HookStatus::MeasuredPass
    } else {
        HookStatus::MeasuredFail
    }
}

fn visible_ordinal_to_node(ordinal: u64) -> u64 {
    if ordinal == 0 {
        0
    } else {
        ordinal.saturating_add(1)
    }
}

fn stable_id<T>(
    seed: u64,
    domain: u64,
    constructor: impl FnOnce(Uuid) -> contextdb_core::ValidationResult<T>,
) -> Result<T> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb.m17.stable-id/v1\0");
    hasher.update(&seed.to_be_bytes());
    hasher.update(&domain.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    constructor(Uuid::from_bytes(bytes)).map_err(|error| integrity(error.to_string()))
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn progress_interval(total: u64) -> u64 {
    total.div_ceil(20).max(1)
}

fn progress(phase: &str, processed: u64, total: u64) {
    if processed == total || processed.is_multiple_of(progress_interval(total)) {
        eprintln!("contextdb-bench semantic_phase={phase} processed={processed} total={total}");
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_millis() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| integrity(error.to_string()))?
            .as_millis(),
    )
    .unwrap_or(u64::MAX))
}

fn checked_mul(left: u64, right: u64, label: &'static str) -> Result<u64> {
    left.checked_mul(right)
        .ok_or(BenchError::ArithmeticOverflow(label))
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn validate_digest(field: &'static str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(field, "must be a lowercase 64-character SHA-256 digest");
    }
    Ok(())
}

fn invalid<T>(field: &'static str, reason: impl Into<String>) -> Result<T> {
    Err(BenchError::InvalidConfiguration {
        field,
        reason: reason.into(),
    })
}

fn integrity(reason: impl Into<String>) -> BenchError {
    BenchError::Integrity(reason.into())
}

fn graph_error(error: impl std::fmt::Display) -> BenchError {
    integrity(format!("semantic graph operation failed: {error}"))
}

fn index_error(error: impl std::fmt::Display) -> BenchError {
    integrity(format!("semantic index operation failed: {error}"))
}

fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
        let kilobytes = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
        kilobytes.checked_mul(1024)
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!("(Get-Process -Id {}).WorkingSet64", std::process::id());
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

/// Detects host capacity without changing the target volume.
pub fn detect_semantic_host_capacity(output: &Path) -> SemanticHostCapacity {
    let (total_memory_bytes, available_memory_bytes) = detect_memory();
    let available_disk_bytes = detect_disk(output);
    SemanticHostCapacity {
        total_memory_bytes,
        available_memory_bytes,
        available_disk_bytes,
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
    }
}

fn detect_memory() -> (Option<u64>, Option<u64>) {
    #[cfg(target_os = "linux")]
    {
        let memory = fs::read_to_string("/proc/meminfo").ok();
        let value = |label: &str| {
            memory.as_deref()?.lines().find_map(|line| {
                let suffix = line.strip_prefix(label)?;
                suffix
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()?
                    .checked_mul(1024)
            })
        };
        (value("MemTotal:"), value("MemAvailable:"))
    }
    #[cfg(target_os = "windows")]
    {
        #[derive(Deserialize)]
        struct MemoryRow {
            #[serde(rename = "TotalVisibleMemorySize")]
            total: u64,
            #[serde(rename = "FreePhysicalMemory")]
            available: u64,
        }
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress",
            ])
            .output()
            .ok();
        let row = output
            .filter(|output| output.status.success())
            .and_then(|output| serde_json::from_slice::<MemoryRow>(&output.stdout).ok());
        row.map_or((None, None), |row| {
            (row.total.checked_mul(1024), row.available.checked_mul(1024))
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        (None, None)
    }
}

fn detect_disk(output: &Path) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let existing = output
            .ancestors()
            .find(|candidate| candidate.exists())
            .unwrap_or(Path::new("."));
        let result = Command::new("df")
            .args(["-Pk", existing.to_str()?])
            .output()
            .ok()?;
        if !result.status.success() {
            return None;
        }
        let text = String::from_utf8(result.stdout).ok()?;
        text.lines()
            .last()?
            .split_whitespace()
            .nth(3)?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    }
    #[cfg(target_os = "windows")]
    {
        let absolute = if output.is_absolute() {
            output.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(output)
        };
        let path = absolute.to_string_lossy().replace('\'', "''");
        let script = format!(
            "[System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot('{path}')).AvailableFreeSpace"
        );
        let result = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .ok()?;
        if !result.status.success() {
            return None;
        }
        String::from_utf8(result.stdout)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = output;
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test fixtures use immediate failure semantics"
    )]

    use super::*;

    fn host() -> SemanticHostCapacity {
        SemanticHostCapacity {
            total_memory_bytes: Some(64 * 1024 * 1024 * 1024),
            available_memory_bytes: Some(48 * 1024 * 1024 * 1024),
            available_disk_bytes: Some(1024 * 1024 * 1024 * 1024),
            os: "test".to_owned(),
            architecture: "test".to_owned(),
        }
    }

    #[test]
    fn certification_graph_shape_fits_but_other_prerequisites_still_block() {
        let admission = admit_semantic_workload(
            SemanticWorkloadConfig::preset(SemanticWorkloadPreset::CertificationV1),
            host(),
        )
        .expect("admission");
        assert_eq!(
            admission.estimate.required_graph_directional_records,
            200_000_000
        );
        assert_eq!(admission.disposition, SemanticAdmissionDisposition::Blocked);
        assert!(
            admission.estimate.required_graph_directional_records
                <= SEGMENT_V2_MAX_DIRECTIONAL_RECORDS
        );
        assert!(
            !admission
                .blockers
                .iter()
                .any(|blocker| blocker.code == "graph_v2_directional_record_capacity")
        );
        assert!(
            !admission
                .blockers
                .iter()
                .any(|blocker| blocker.code == "persistent_ann_v2_durable_source_unavailable")
        );
        assert!(
            admission.blockers.iter().any(|blocker| {
                blocker.code == "persistent_ann_v2_certification_scale_unproven"
            })
        );
        assert!(
            !admission
                .blockers
                .iter()
                .any(|blocker| blocker.code == "persistent_ann_v2_runtime_unavailable")
        );
    }

    #[test]
    fn small_requires_digest_bound_confirmation_but_smoke_is_admitted() {
        let small = admit_semantic_workload(
            SemanticWorkloadConfig::preset(SemanticWorkloadPreset::Small),
            host(),
        )
        .expect("small admission");
        assert_eq!(
            small.disposition,
            SemanticAdmissionDisposition::ConfirmationRequired
        );
        assert!(small.blockers.is_empty());

        let smoke = admit_semantic_workload(
            SemanticWorkloadConfig::preset(SemanticWorkloadPreset::Smoke),
            host(),
        )
        .expect("smoke admission");
        assert_eq!(smoke.disposition, SemanticAdmissionDisposition::Admitted);
        assert!(smoke.blockers.is_empty());
    }

    #[test]
    fn runner_rejects_an_admission_digest_that_does_not_bind_input() {
        let directory = tempfile::tempdir().expect("tempdir");
        let admission = admit_semantic_workload(
            SemanticWorkloadConfig::preset(SemanticWorkloadPreset::Smoke),
            host(),
        )
        .expect("admission");
        let error = run_semantic_workload(directory.path(), &admission, &"0".repeat(64), None)
            .expect_err("mismatched admission digest must fail");
        assert!(error.to_string().contains("does not bind"));
    }

    #[test]
    fn bounded_samples_are_deterministic_and_capped() {
        let mut samples = BoundedSamples::new(4);
        for value in 1..=100 {
            samples.push(value);
        }
        assert_eq!(samples.seen, 100);
        assert_eq!(samples.values.len(), 4);
        let first = samples.summary().expect("summary");

        let mut repeated = BoundedSamples::new(4);
        for value in 1..=100 {
            repeated.push(value);
        }
        assert_eq!(first, repeated.summary().expect("repeated summary"));
    }

    #[test]
    fn stable_fixture_ids_and_graph_digest_are_reproducible() {
        let config = SemanticWorkloadConfig::preset(SemanticWorkloadPreset::Smoke);
        let first = SemanticFixture::new(config.seed).expect("fixture");
        let second = SemanticFixture::new(config.seed).expect("fixture");
        assert_eq!(
            first.node_id(config.seed, 42).expect("node"),
            second.node_id(config.seed, 42).expect("node")
        );
        assert_eq!(
            expected_graph_digest(&first, &config).expect("digest"),
            expected_graph_digest(&second, &config).expect("digest")
        );
    }

    #[test]
    fn persistent_ann_v2_flag_requires_publish_verify_reopen_and_exact_differential() {
        let directory = tempfile::tempdir().expect("tempdir");
        let ann_path = directory.path().join("ann-v2.redb");
        let source_path = directory.path().join("ann-v2-source.redb");
        let config = SemanticWorkloadConfig::preset(SemanticWorkloadPreset::Smoke);
        let fixture = SemanticFixture::new(config.seed).expect("fixture");
        let watermark = CommitSeq::new(7);
        let mut execution = build_vectors(&fixture, &config, watermark, &ann_path, &source_path)
            .expect("build ANN-v2");
        assert!(!execution.ann_v2.exercised());
        assert!(execution.ann_v2.immediate_differential.passed());

        let mut restored = VectorIndex::new();
        restored
            .import_store(execution.store_bundle.clone())
            .expect("restore vector source");
        verify_reopened_persistent_ann_v2(
            &ann_path,
            &source_path,
            &restored,
            &fixture,
            &config,
            watermark,
            &mut execution.ann_v2,
        )
        .expect("reopen ANN-v2");

        assert!(execution.ann_v2.exercised());
        assert_eq!(execution.ann_overlap_bps, 10_000.0);
        assert_eq!(
            execution.ann_v2.publication_verification.node_count,
            config.vectors
        );
        assert!(
            execution
                .ann_v2
                .reopened
                .as_ref()
                .expect("reopen evidence")
                .differential
                .passed()
        );
        let mut failed_differential = execution.ann_v2.clone();
        failed_differential
            .reopened
            .as_mut()
            .expect("reopen evidence")
            .differential
            .all_queries_exact = false;
        assert!(!failed_differential.exercised());

        let mut stale_reopen = execution.ann_v2.clone();
        stale_reopen
            .reopened
            .as_mut()
            .expect("reopen evidence")
            .storage_sequence = execution
            .ann_v2
            .publication_storage_sequence
            .saturating_sub(1);
        assert!(!stale_reopen.exercised());
    }
}
