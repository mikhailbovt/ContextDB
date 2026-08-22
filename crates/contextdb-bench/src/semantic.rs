//! Bounded, evidence-derived BENCH-H semantic measurement intake.
//!
//! This module evaluates a complete development target matrix. It does not execute the semantic
//! stack and intentionally has no release-certification switch. Coverage and exit-class results
//! are derived from numeric measurements whose source artifacts are content-addressed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::aggregate::{
    BenchHCoverageManifest, NativeRunMetadata, insert_coverage_parameters, version_manifest,
};
use crate::digest::sha256_hex;
use crate::report::{
    Artifact, BenchmarkFamily, BenchmarkIdentity, BenchmarkResult, ContextDbIdentity, Distribution,
    Environment, EvidenceKind, Metric, MetricDirection, MetricThreshold, QualityGate,
    ReleaseChannel, ReportStatus, RunConfiguration, ScalarValue, ThresholdOperator, ThresholdValue,
};
use crate::{BENCHMARK_RESULT_SCHEMA_VERSION, BenchError, Result};

/// Schema for raw semantic development outcomes accepted by this crate.
pub const SEMANTIC_OUTCOME_SCHEMA_VERSION: &str = "contextdb.bench-h-semantic-outcome/v1";

/// Schema for the predeclared target matrix embedded in an outcome.
pub const SEMANTIC_TARGET_MATRIX_SCHEMA_VERSION: &str =
    "contextdb.bench-h-semantic-target-matrix/v1";

const MAX_RAW_OUTCOME_BYTES: usize = 4 * 1024 * 1024;
const MAX_SAMPLES_PER_MEASUREMENT: usize = 4_096;
const MAX_EXTERNAL_ARTIFACTS: usize = 64;
const MAX_EXTERNAL_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_EXTERNAL_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_EXACT_F64_INTEGER: u64 = 9_007_199_254_740_992;

/// BENCH-H scale tier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticTier {
    /// RFC BENCH-H small tier.
    Small,
    /// RFC BENCH-H medium tier.
    Medium,
    /// ERRATA E-009 v1 certification lower-bound tier.
    CertificationV1,
}

impl SemanticTier {
    const ALL: [Self; 3] = [Self::Small, Self::Medium, Self::CertificationV1];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::CertificationV1 => "certification_v1",
        }
    }

    const fn scale_floor(self) -> (u64, u64, Option<u64>) {
        match self {
            Self::Small => (100_000, 1_000_000, None),
            Self::Medium => (5_000_000, 50_000_000, None),
            Self::CertificationV1 => (10_000_000, 100_000_000, Some(1_000_000)),
        }
    }
}

/// Exact scenario set required by RFC BENCH-H.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticScenario {
    /// Hot conversation recall.
    HotConversation,
    /// Cold autobiographical recall.
    ColdAutobiographical,
    /// Current-fact retrieval.
    CurrentFact,
    /// Historical-fact retrieval.
    HistoricalFact,
    /// Filtered approximate nearest-neighbor retrieval.
    FilteredAnn,
    /// Hierarchy drill-down.
    HierarchyDrillDown,
    /// Artifact metadata retrieval.
    ArtifactMetadata,
    /// Compaction while serving load.
    CompactionUnderLoad,
    /// Backup while preserving service semantics.
    Backup,
    /// Restart and recovery.
    Restart,
}

impl SemanticScenario {
    const ALL: [Self; 10] = [
        Self::HotConversation,
        Self::ColdAutobiographical,
        Self::CurrentFact,
        Self::HistoricalFact,
        Self::FilteredAnn,
        Self::HierarchyDrillDown,
        Self::ArtifactMetadata,
        Self::CompactionUnderLoad,
        Self::Backup,
        Self::Restart,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::HotConversation => "hot_conversation",
            Self::ColdAutobiographical => "cold_autobiographical",
            Self::CurrentFact => "current_fact",
            Self::HistoricalFact => "historical_fact",
            Self::FilteredAnn => "filtered_ann",
            Self::HierarchyDrillDown => "hierarchy_drill_down",
            Self::ArtifactMetadata => "artifact_metadata",
            Self::CompactionUnderLoad => "compaction_under_load",
            Self::Backup => "backup",
            Self::Restart => "restart",
        }
    }
}

/// Required numeric targets for one scenario at one tier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticScenarioTarget {
    /// Scenario selected by this row.
    pub scenario: SemanticScenario,
    /// Maximum p50 end-to-end latency.
    pub latency_p50_max_ns: u64,
    /// Maximum p95 end-to-end latency.
    pub latency_p95_max_ns: u64,
    /// Maximum p99 end-to-end latency.
    pub latency_p99_max_ns: u64,
    /// Minimum completed operations per second.
    pub minimum_operations_per_second: u64,
}

/// Required targets and scale floor for one tier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTierTarget {
    /// Tier selected by this row.
    pub tier: SemanticTier,
    /// Minimum semantic node/claim count.
    pub minimum_semantic_nodes: u64,
    /// Minimum typed graph-edge count.
    pub minimum_graph_edges: u64,
    /// Minimum vector count when the RFC/ERRATA defines one.
    pub minimum_vectors: Option<u64>,
    /// Exact ten-scenario target set.
    pub scenarios: Vec<SemanticScenarioTarget>,
    /// Maximum p95 recovery latency.
    pub recovery_p95_max_ns: u64,
    /// Maximum p95 index-freshness lag.
    pub index_freshness_p95_max_ns: u64,
    /// Maximum process resident set for this tier.
    pub process_rss_max_bytes: u64,
}

/// Predeclared development target matrix.
///
/// Numeric performance targets are supplied by a separately reviewable matrix and bound by its
/// SHA-256. They are not represented as frozen Beta targets by this development-only evaluator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTargetMatrix {
    /// Target-matrix schema.
    pub schema_version: String,
    /// Stable caller-assigned revision for the predeclared matrix.
    pub revision: String,
    /// Exact small, medium, and v1-certification rows.
    pub tiers: Vec<SemanticTierTarget>,
}

/// Resource, recovery, and scale measurements for one tier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTierMeasurement {
    /// Measured tier.
    pub tier: SemanticTier,
    /// Semantic nodes/claims actually loaded and traversable.
    pub semantic_nodes: u64,
    /// Typed graph edges actually loaded and traversable.
    pub graph_edges: u64,
    /// Full-precision vectors actually loaded and queryable.
    pub vectors: u64,
    /// Raw recovery latency samples.
    pub recovery_latency_ns: Vec<u64>,
    /// Raw index-freshness lag samples.
    pub index_freshness_lag_ns: Vec<u64>,
    /// Raw process RSS samples.
    pub process_rss_bytes: Vec<u64>,
    /// Requests intentionally driven into the declared pressure state.
    pub pressure_requests: u64,
    /// Pressure requests which returned an explicit partial/degraded result.
    pub degraded_responses: u64,
    /// Correctness failures observed during pressure.
    pub correctness_failures: u64,
    /// Uncontrolled out-of-memory terminations observed during pressure.
    pub uncontrolled_oom_events: u64,
    /// SHA-256 of the bound tier resource/recovery trace.
    pub artifact_sha256: String,
}

/// Raw scenario measurement from which latency and throughput are calculated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticScenarioMeasurement {
    /// Measured tier.
    pub tier: SemanticTier,
    /// Measured scenario.
    pub scenario: SemanticScenario,
    /// Raw end-to-end latency samples.
    pub latency_ns: Vec<u64>,
    /// Successfully completed operations represented by `elapsed_ns`.
    pub completed_operations: u64,
    /// Measured wall-clock interval.
    pub elapsed_ns: u64,
    /// SHA-256 of the bound scenario trace.
    pub artifact_sha256: String,
}

/// Frozen-quality class checked after an optimization.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRegressionClass {
    /// Frozen semantic quality score.
    SemanticQuality,
    /// Frozen privacy safety score.
    Privacy,
    /// Frozen social-calibration score.
    SocialCalibration,
    /// Frozen ANN/exact-overlap score.
    AnnExactOverlap,
}

impl SemanticRegressionClass {
    const ALL: [Self; 4] = [
        Self::SemanticQuality,
        Self::Privacy,
        Self::SocialCalibration,
        Self::AnnExactOverlap,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticQuality => "semantic_quality",
            Self::Privacy => "privacy",
            Self::SocialCalibration => "social_calibration",
            Self::AnnExactOverlap => "ann_exact_overlap",
        }
    }
}

/// Numeric baseline/candidate comparison for one frozen quality class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRegressionMeasurement {
    /// Regression class.
    pub class: SemanticRegressionClass,
    /// Frozen baseline score in basis points, where higher is safer/better.
    pub baseline_score_bps: f64,
    /// Candidate score measured after the optimization.
    pub candidate_score_bps: f64,
    /// SHA-256 of the bound regression report.
    pub artifact_sha256: String,
}

/// Strict raw input to the semantic development evaluator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRunOutcome {
    /// Raw-outcome schema.
    pub schema_version: String,
    /// Deterministic dataset/workload revision.
    pub dataset_version: String,
    /// Seed used to generate the semantic dataset.
    pub seed: u64,
    /// Predeclared target matrix.
    pub target_matrix: SemanticTargetMatrix,
    /// SHA-256 of compact serialization of `target_matrix`.
    pub target_matrix_sha256: String,
    /// URI assigned to the embedded target-matrix artifact.
    pub target_matrix_uri: String,
    /// SHA-256 of the bound measured-host hardware profile.
    pub reference_hardware_sha256: String,
    /// Exact three tier measurements.
    pub tier_measurements: Vec<SemanticTierMeasurement>,
    /// Exact tier-by-scenario cross product (three by ten).
    pub scenario_measurements: Vec<SemanticScenarioMeasurement>,
    /// Exact four frozen quality comparisons.
    pub regressions: Vec<SemanticRegressionMeasurement>,
}

/// Role of a raw external artifact supplied to the evaluator.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SemanticArtifactKind {
    /// Measured-host hardware profile; publication is not inferred.
    ReferenceHardwareProfile,
    /// Per-scenario timing/throughput trace.
    ScenarioTrace,
    /// Per-tier resource/recovery/freshness trace.
    TierResourceTrace,
    /// Frozen-quality regression comparison.
    RegressionReport,
}

impl SemanticArtifactKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ReferenceHardwareProfile => "reference-hardware-profile",
            Self::ScenarioTrace => "semantic-scenario-trace",
            Self::TierResourceTrace => "semantic-tier-resource-trace",
            Self::RegressionReport => "semantic-regression-report",
        }
    }
}

/// External artifact bytes whose digest is referenced by raw measured rows.
#[derive(Debug)]
pub struct MeasuredArtifact<'a> {
    /// Exact role of the artifact.
    pub kind: SemanticArtifactKind,
    /// Stable URI or relative path.
    pub uri: &'a str,
    /// Exact artifact bytes.
    pub bytes: &'a [u8],
}

#[derive(Debug)]
struct DerivedSemanticEvidence {
    coverage: BenchHCoverageManifest,
    metrics: Vec<Metric>,
    quality_gates: Vec<QualityGate>,
}

/// Returns the canonical SHA-256 binding for a target matrix.
pub fn semantic_target_matrix_sha256(matrix: &SemanticTargetMatrix) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(matrix)?))
}

/// Builds a canonical, development-only BENCH-H report from bounded raw measurements.
///
/// `raw_outcome_bytes` is parsed by this function and is itself included as a content-addressed
/// report artifact. External measurement rows are accepted only when their declared digest and
/// required artifact role match the supplied bytes.
pub fn build_semantic_development_report(
    raw_outcome_bytes: &[u8],
    raw_outcome_uri: impl Into<String>,
    metadata: NativeRunMetadata,
    external_artifacts: &[MeasuredArtifact<'_>],
) -> Result<BenchmarkResult> {
    if raw_outcome_bytes.is_empty() || raw_outcome_bytes.len() > MAX_RAW_OUTCOME_BYTES {
        return invalid(
            "semantic_outcome",
            "raw outcome must be nonempty and no larger than 4 MiB",
        );
    }
    let outcome: SemanticRunOutcome = serde_json::from_slice(raw_outcome_bytes)?;
    validate_outcome(&outcome)?;
    let artifacts = validate_and_bind_artifacts(&outcome, external_artifacts)?;
    let derived = derive_evidence(&outcome)?;

    let raw_outcome_uri = raw_outcome_uri.into();
    let target_matrix_json = serde_json::to_vec(&outcome.target_matrix)?;
    validate_identifier("raw_outcome_uri", &raw_outcome_uri)?;
    let mut report_artifacts = Vec::with_capacity(artifacts.len().saturating_add(2));
    report_artifacts.push(Artifact {
        kind: "semantic-raw-outcome".to_owned(),
        uri: raw_outcome_uri,
        sha256: sha256_hex(raw_outcome_bytes),
    });
    report_artifacts.push(Artifact {
        kind: "semantic-target-matrix".to_owned(),
        uri: outcome.target_matrix_uri.clone(),
        sha256: sha256_hex(&target_matrix_json),
    });
    report_artifacts.extend(artifacts);

    let mut safe_metadata = metadata;
    safe_metadata.release_channel = ReleaseChannel::Development;
    let contextdb = ContextDbIdentity::new(version_manifest(&safe_metadata))?;
    let mut parameters = BTreeMap::from([
        (
            "evidence_kind".to_owned(),
            ScalarValue::String(EvidenceKind::NativeMeasuredDevelopment.as_str().to_owned()),
        ),
        (
            "semantic_evaluator_mode".to_owned(),
            ScalarValue::String("development_derived_no_release_promotion".to_owned()),
        ),
        (
            "semantic_target_authority".to_owned(),
            ScalarValue::String("predeclared_development_matrix".to_owned()),
        ),
        (
            "semantic_target_matrix_sha256".to_owned(),
            ScalarValue::String(outcome.target_matrix_sha256.clone()),
        ),
        (
            "measured_hardware_profile_sha256".to_owned(),
            ScalarValue::String(outcome.reference_hardware_sha256.clone()),
        ),
        (
            "m16_deep_scan_passed".to_owned(),
            ScalarValue::Boolean(false),
        ),
        (
            "certification_node_count".to_owned(),
            ScalarValue::Unsigned(derived.coverage.semantic_nodes),
        ),
        (
            "release_certification_supported".to_owned(),
            ScalarValue::Boolean(false),
        ),
    ]);
    insert_coverage_parameters(&mut parameters, derived.coverage);
    let budgets = BTreeMap::from([
        (
            "maximum_raw_outcome_bytes".to_owned(),
            ScalarValue::Unsigned(MAX_RAW_OUTCOME_BYTES as u64),
        ),
        (
            "maximum_samples_per_measurement".to_owned(),
            ScalarValue::Unsigned(MAX_SAMPLES_PER_MEASUREMENT as u64),
        ),
        (
            "maximum_external_artifact_bytes".to_owned(),
            ScalarValue::Unsigned(MAX_EXTERNAL_ARTIFACT_BYTES as u64),
        ),
        (
            "maximum_total_external_artifact_bytes".to_owned(),
            ScalarValue::Unsigned(MAX_TOTAL_EXTERNAL_ARTIFACT_BYTES as u64),
        ),
    ]);
    let mut report = BenchmarkResult {
        schema_version: BENCHMARK_RESULT_SCHEMA_VERSION.to_owned(),
        run_id: Uuid::now_v7(),
        started_at: safe_metadata.started_at.clone(),
        finished_at: safe_metadata.finished_at.clone(),
        status: ReportStatus::ObservationOnly,
        benchmark: BenchmarkIdentity {
            id: "BENCH-0017".to_owned(),
            family: BenchmarkFamily::BenchH,
            name: "M17 semantic target-matrix development evaluation".to_owned(),
            version: crate::BENCH_H_WORKLOAD_VERSION.to_owned(),
            dataset_version: outcome.dataset_version,
            scenario: "full-semantic-target-matrix-development".to_owned(),
            tier: "small-medium-certification-v1-development".to_owned(),
        },
        contextdb,
        environment: Environment {
            os: safe_metadata.os,
            os_version: safe_metadata.os_version,
            kernel: safe_metadata.kernel,
            architecture: safe_metadata.architecture,
            cpu: safe_metadata.cpu,
            logical_cores: safe_metadata.logical_cores,
            memory_bytes: safe_metadata.memory_bytes.max(1),
            storage: safe_metadata.storage,
            filesystem: safe_metadata.filesystem,
            rustc: safe_metadata.rustc,
            cargo: safe_metadata.cargo,
            storage_backend: "externally-measured-semantic-stack".to_owned(),
            storage_backend_version: None,
            storage_configuration_digest: None,
            build_profile: safe_metadata.build_profile,
        },
        configuration: RunConfiguration {
            seed: outcome.seed,
            features: vec![
                "semantic-graph".to_owned(),
                "exact-and-ann-recall".to_owned(),
                "bounded-measurement-intake".to_owned(),
            ],
            budgets,
            parameters,
            index_watermarks: BTreeMap::new(),
        },
        metrics: derived.metrics,
        quality_gates: derived.quality_gates,
        artifacts: report_artifacts,
        limitations: vec![
            "This evaluator derives development results from supplied measured artifacts; it does not execute or independently attest the semantic stack.".to_owned(),
            "Target values are bound predeclared development targets, not frozen Beta floors.".to_owned(),
            "Artifact bytes are content-addressed, but real 10M-node/100M-edge scale and published reference hardware still require externally witnessed runs.".to_owned(),
            "There is intentionally no release-candidate input: this report remains development evidence even when every declared target passes.".to_owned(),
            "M16 deep-scan evidence is not accepted by this development evaluator.".to_owned(),
        ],
        error: None,
    };
    report.status = report.derived_status();
    report.validate()?;
    Ok(report)
}

fn validate_outcome(outcome: &SemanticRunOutcome) -> Result<()> {
    if outcome.schema_version != SEMANTIC_OUTCOME_SCHEMA_VERSION {
        return invalid("semantic_outcome.schema_version", "unsupported schema");
    }
    validate_identifier("semantic_outcome.dataset_version", &outcome.dataset_version)?;
    validate_identifier(
        "semantic_outcome.target_matrix_uri",
        &outcome.target_matrix_uri,
    )?;
    validate_digest(
        "semantic_outcome.reference_hardware_sha256",
        &outcome.reference_hardware_sha256,
    )?;
    validate_target_matrix(&outcome.target_matrix)?;
    let expected_target_digest = semantic_target_matrix_sha256(&outcome.target_matrix)?;
    if outcome.target_matrix_sha256 != expected_target_digest {
        return Err(BenchError::Integrity(
            "semantic target-matrix digest does not match the embedded matrix".to_owned(),
        ));
    }

    let tier_targets = tier_target_map(&outcome.target_matrix)?;
    if outcome.tier_measurements.len() != SemanticTier::ALL.len() {
        return invalid(
            "semantic_outcome.tier_measurements",
            "expected exactly one measurement for each tier",
        );
    }
    let mut tiers = BTreeSet::new();
    for measurement in &outcome.tier_measurements {
        if !tiers.insert(measurement.tier) {
            return invalid(
                "semantic_outcome.tier_measurements",
                "tier measurements must be unique",
            );
        }
        validate_tier_measurement(measurement)?;
        if !tier_targets.contains_key(&measurement.tier) {
            return invalid(
                "semantic_outcome.tier_measurements",
                "measurement has no matching target tier",
            );
        }
    }
    if tiers != SemanticTier::ALL.into_iter().collect() {
        return invalid(
            "semantic_outcome.tier_measurements",
            "tier measurement set is not exact",
        );
    }

    let expected_scenarios = SemanticTier::ALL
        .into_iter()
        .flat_map(|tier| {
            SemanticScenario::ALL
                .into_iter()
                .map(move |scenario| (tier, scenario))
        })
        .collect::<BTreeSet<_>>();
    if outcome.scenario_measurements.len() != expected_scenarios.len() {
        return invalid(
            "semantic_outcome.scenario_measurements",
            "expected the exact three-tier by ten-scenario matrix",
        );
    }
    let mut scenarios = BTreeSet::new();
    for measurement in &outcome.scenario_measurements {
        if !scenarios.insert((measurement.tier, measurement.scenario)) {
            return invalid(
                "semantic_outcome.scenario_measurements",
                "tier/scenario rows must be unique",
            );
        }
        validate_samples(
            "semantic_outcome.scenario_measurements.latency_ns",
            &measurement.latency_ns,
        )?;
        validate_nonzero_exact_integer(
            "semantic_outcome.scenario_measurements.completed_operations",
            measurement.completed_operations,
        )?;
        validate_nonzero_exact_integer(
            "semantic_outcome.scenario_measurements.elapsed_ns",
            measurement.elapsed_ns,
        )?;
        validate_digest(
            "semantic_outcome.scenario_measurements.artifact_sha256",
            &measurement.artifact_sha256,
        )?;
    }
    if scenarios != expected_scenarios {
        return invalid(
            "semantic_outcome.scenario_measurements",
            "tier/scenario matrix has a missing or unexpected row",
        );
    }

    if outcome.regressions.len() != SemanticRegressionClass::ALL.len() {
        return invalid(
            "semantic_outcome.regressions",
            "expected exactly four frozen-quality comparisons",
        );
    }
    let mut regressions = BTreeSet::new();
    for measurement in &outcome.regressions {
        if !regressions.insert(measurement.class) {
            return invalid(
                "semantic_outcome.regressions",
                "regression classes must be unique",
            );
        }
        if !valid_basis_points(measurement.baseline_score_bps)
            || !valid_basis_points(measurement.candidate_score_bps)
        {
            return invalid(
                "semantic_outcome.regressions.score_bps",
                "scores must be finite values from zero through 10000 basis points",
            );
        }
        validate_digest(
            "semantic_outcome.regressions.artifact_sha256",
            &measurement.artifact_sha256,
        )?;
    }
    if regressions != SemanticRegressionClass::ALL.into_iter().collect() {
        return invalid(
            "semantic_outcome.regressions",
            "regression class set is not exact",
        );
    }
    Ok(())
}

fn validate_target_matrix(matrix: &SemanticTargetMatrix) -> Result<()> {
    if matrix.schema_version != SEMANTIC_TARGET_MATRIX_SCHEMA_VERSION {
        return invalid(
            "semantic_target_matrix.schema_version",
            "unsupported schema",
        );
    }
    validate_identifier("semantic_target_matrix.revision", &matrix.revision)?;
    if matrix.tiers.len() != SemanticTier::ALL.len() {
        return invalid(
            "semantic_target_matrix.tiers",
            "expected exactly small, medium, and certification_v1",
        );
    }
    let mut tiers = BTreeSet::new();
    for tier in &matrix.tiers {
        if !tiers.insert(tier.tier) {
            return invalid(
                "semantic_target_matrix.tiers",
                "tier target rows must be unique",
            );
        }
        let (nodes, edges, vectors) = tier.tier.scale_floor();
        if (
            tier.minimum_semantic_nodes,
            tier.minimum_graph_edges,
            tier.minimum_vectors,
        ) != (nodes, edges, vectors)
        {
            return invalid(
                "semantic_target_matrix.scale_floor",
                "tier scale floors must exactly match RFC BENCH-H and ERRATA E-009",
            );
        }
        for (field, value) in [
            ("recovery_p95_max_ns", tier.recovery_p95_max_ns),
            (
                "index_freshness_p95_max_ns",
                tier.index_freshness_p95_max_ns,
            ),
            ("process_rss_max_bytes", tier.process_rss_max_bytes),
        ] {
            validate_nonzero_exact_integer(field, value)?;
        }
        if tier.scenarios.len() != SemanticScenario::ALL.len() {
            return invalid(
                "semantic_target_matrix.scenarios",
                "every tier requires exactly ten scenario targets",
            );
        }
        let mut scenarios = BTreeSet::new();
        for scenario in &tier.scenarios {
            if !scenarios.insert(scenario.scenario) {
                return invalid(
                    "semantic_target_matrix.scenarios",
                    "scenario target rows must be unique per tier",
                );
            }
            for (field, value) in [
                ("latency_p50_max_ns", scenario.latency_p50_max_ns),
                ("latency_p95_max_ns", scenario.latency_p95_max_ns),
                ("latency_p99_max_ns", scenario.latency_p99_max_ns),
                (
                    "minimum_operations_per_second",
                    scenario.minimum_operations_per_second,
                ),
            ] {
                validate_nonzero_exact_integer(field, value)?;
            }
            if scenario.latency_p50_max_ns > scenario.latency_p95_max_ns
                || scenario.latency_p95_max_ns > scenario.latency_p99_max_ns
            {
                return invalid(
                    "semantic_target_matrix.latency_percentiles",
                    "p50, p95, and p99 maxima must be nondecreasing",
                );
            }
        }
        if scenarios != SemanticScenario::ALL.into_iter().collect() {
            return invalid(
                "semantic_target_matrix.scenarios",
                "scenario target set is not exact",
            );
        }
    }
    if tiers != SemanticTier::ALL.into_iter().collect() {
        return invalid(
            "semantic_target_matrix.tiers",
            "tier target set is not exact",
        );
    }
    Ok(())
}

fn validate_tier_measurement(measurement: &SemanticTierMeasurement) -> Result<()> {
    for (field, value) in [
        ("semantic_nodes", measurement.semantic_nodes),
        ("graph_edges", measurement.graph_edges),
        ("vectors", measurement.vectors),
        ("pressure_requests", measurement.pressure_requests),
        ("degraded_responses", measurement.degraded_responses),
        ("correctness_failures", measurement.correctness_failures),
        (
            "uncontrolled_oom_events",
            measurement.uncontrolled_oom_events,
        ),
    ] {
        validate_exact_integer(field, value)?;
    }
    if measurement.degraded_responses > measurement.pressure_requests {
        return invalid(
            "semantic_outcome.tier_measurements.degraded_responses",
            "degraded responses cannot exceed pressure requests",
        );
    }
    validate_samples(
        "semantic_outcome.tier_measurements.recovery_latency_ns",
        &measurement.recovery_latency_ns,
    )?;
    validate_samples(
        "semantic_outcome.tier_measurements.index_freshness_lag_ns",
        &measurement.index_freshness_lag_ns,
    )?;
    validate_samples(
        "semantic_outcome.tier_measurements.process_rss_bytes",
        &measurement.process_rss_bytes,
    )?;
    validate_digest(
        "semantic_outcome.tier_measurements.artifact_sha256",
        &measurement.artifact_sha256,
    )
}

fn validate_samples(field: &'static str, samples: &[u64]) -> Result<()> {
    if samples.is_empty() || samples.len() > MAX_SAMPLES_PER_MEASUREMENT {
        return invalid(
            field,
            "sample set must be nonempty and contain at most 4096 values",
        );
    }
    if samples.iter().any(|sample| *sample > MAX_EXACT_F64_INTEGER) {
        return invalid(
            field,
            "sample exceeds exact integer range used by report metrics",
        );
    }
    Ok(())
}

fn validate_and_bind_artifacts(
    outcome: &SemanticRunOutcome,
    external_artifacts: &[MeasuredArtifact<'_>],
) -> Result<Vec<Artifact>> {
    if external_artifacts.is_empty() || external_artifacts.len() > MAX_EXTERNAL_ARTIFACTS {
        return invalid(
            "semantic_artifacts",
            "one through 64 external artifacts are required",
        );
    }
    let mut total_bytes = 0_usize;
    let mut by_digest = BTreeMap::new();
    let mut kind_uris = BTreeSet::new();
    let mut artifacts = Vec::with_capacity(external_artifacts.len());
    for artifact in external_artifacts {
        validate_identifier("semantic_artifact.uri", artifact.uri)?;
        if artifact.bytes.is_empty() || artifact.bytes.len() > MAX_EXTERNAL_ARTIFACT_BYTES {
            return invalid(
                "semantic_artifact.bytes",
                "artifact must be nonempty and no larger than 16 MiB",
            );
        }
        total_bytes =
            total_bytes
                .checked_add(artifact.bytes.len())
                .ok_or(BenchError::ArithmeticOverflow(
                    "semantic artifact byte total",
                ))?;
        if total_bytes > MAX_TOTAL_EXTERNAL_ARTIFACT_BYTES {
            return invalid(
                "semantic_artifacts",
                "external artifact bytes exceed the 64 MiB aggregate bound",
            );
        }
        if !kind_uris.insert((artifact.kind, artifact.uri)) {
            return invalid(
                "semantic_artifacts",
                "artifact role/URI bindings must be unique",
            );
        }
        let digest = sha256_hex(artifact.bytes);
        if by_digest.insert(digest.clone(), artifact.kind).is_some() {
            return invalid("semantic_artifacts", "artifact byte digests must be unique");
        }
        artifacts.push(Artifact {
            kind: artifact.kind.as_str().to_owned(),
            uri: artifact.uri.to_owned(),
            sha256: digest,
        });
    }
    require_artifact_role(
        &by_digest,
        &outcome.reference_hardware_sha256,
        SemanticArtifactKind::ReferenceHardwareProfile,
        "reference hardware profile",
    )?;
    let mut referenced = BTreeSet::from([outcome.reference_hardware_sha256.as_str()]);
    for measurement in &outcome.scenario_measurements {
        require_artifact_role(
            &by_digest,
            &measurement.artifact_sha256,
            SemanticArtifactKind::ScenarioTrace,
            "scenario measurement",
        )?;
        referenced.insert(measurement.artifact_sha256.as_str());
    }
    for measurement in &outcome.tier_measurements {
        require_artifact_role(
            &by_digest,
            &measurement.artifact_sha256,
            SemanticArtifactKind::TierResourceTrace,
            "tier resource measurement",
        )?;
        referenced.insert(measurement.artifact_sha256.as_str());
    }
    for measurement in &outcome.regressions {
        require_artifact_role(
            &by_digest,
            &measurement.artifact_sha256,
            SemanticArtifactKind::RegressionReport,
            "regression measurement",
        )?;
        referenced.insert(measurement.artifact_sha256.as_str());
    }
    if referenced.len() != by_digest.len()
        || by_digest
            .keys()
            .any(|digest| !referenced.contains(digest.as_str()))
    {
        return invalid(
            "semantic_artifacts",
            "every supplied artifact must be referenced by a measured row",
        );
    }
    Ok(artifacts)
}

fn require_artifact_role(
    artifacts: &BTreeMap<String, SemanticArtifactKind>,
    digest: &str,
    expected: SemanticArtifactKind,
    label: &'static str,
) -> Result<()> {
    match artifacts.get(digest) {
        Some(actual) if *actual == expected => Ok(()),
        Some(_) => Err(BenchError::Integrity(format!(
            "{label} references an artifact with the wrong role"
        ))),
        None => Err(BenchError::Integrity(format!(
            "{label} references unavailable artifact `{digest}`"
        ))),
    }
}

fn derive_evidence(outcome: &SemanticRunOutcome) -> Result<DerivedSemanticEvidence> {
    let tier_targets = tier_target_map(&outcome.target_matrix)?;
    let tiers: BTreeMap<_, _> = outcome
        .tier_measurements
        .iter()
        .map(|measurement| (measurement.tier, measurement))
        .collect();
    let scenarios: BTreeMap<_, _> = outcome
        .scenario_measurements
        .iter()
        .map(|measurement| ((measurement.tier, measurement.scenario), measurement))
        .collect();
    let regressions: BTreeMap<_, _> = outcome
        .regressions
        .iter()
        .map(|measurement| (measurement.class, measurement))
        .collect();
    let mut metrics = Vec::new();
    let mut latency_passed = true;
    let mut throughput_passed = true;
    let mut recovery_passed = true;
    let mut freshness_passed = true;
    let mut bounded_memory_passed = true;
    let mut pressure_degradation_passed = true;
    let mut pressure_correctness_passed = true;

    for tier in SemanticTier::ALL {
        let target = tier_targets.get(&tier).ok_or_else(|| {
            BenchError::Integrity(format!("missing target for tier `{}`", tier.as_str()))
        })?;
        let measurement = tiers.get(&tier).ok_or_else(|| {
            BenchError::Integrity(format!("missing measurement for tier `{}`", tier.as_str()))
        })?;
        let scenario_targets: BTreeMap<_, _> = target
            .scenarios
            .iter()
            .map(|scenario| (scenario.scenario, scenario))
            .collect();
        for scenario in SemanticScenario::ALL {
            let scenario_target = scenario_targets.get(&scenario).ok_or_else(|| {
                BenchError::Integrity(format!(
                    "missing target for `{}`/`{}`",
                    tier.as_str(),
                    scenario.as_str()
                ))
            })?;
            let measured = scenarios.get(&(tier, scenario)).ok_or_else(|| {
                BenchError::Integrity(format!(
                    "missing measurement for `{}`/`{}`",
                    tier.as_str(),
                    scenario.as_str()
                ))
            })?;
            let distribution = Distribution::from_samples(&measured.latency_ns)?;
            let prefix = format!("semantic.{}.{}", tier.as_str(), scenario.as_str());
            for (statistic, observed, threshold) in [
                ("p50", distribution.p50, scenario_target.latency_p50_max_ns),
                ("p95", distribution.p95, scenario_target.latency_p95_max_ns),
                ("p99", distribution.p99, scenario_target.latency_p99_max_ns),
            ] {
                let observed = observed.ok_or_else(|| {
                    BenchError::Integrity(format!(
                        "nonempty scenario distribution omitted {statistic}"
                    ))
                })?;
                let metric = threshold_metric(
                    format!("{prefix}.latency_{statistic}_ns"),
                    "nanoseconds",
                    MetricDirection::LowerIsBetter,
                    observed,
                    ThresholdOperator::Lte,
                    threshold as f64,
                )?;
                latency_passed &= metric.passed == Some(true);
                metrics.push(metric);
            }
            let operations_per_second =
                measured.completed_operations as f64 * 1_000_000_000.0 / measured.elapsed_ns as f64;
            let metric = threshold_metric(
                format!("{prefix}.operations_per_second"),
                "operations_per_second",
                MetricDirection::HigherIsBetter,
                operations_per_second,
                ThresholdOperator::Gte,
                scenario_target.minimum_operations_per_second as f64,
            )?;
            throughput_passed &= metric.passed == Some(true);
            metrics.push(metric);
        }

        let recovery = Distribution::from_samples(&measurement.recovery_latency_ns)?
            .p95
            .ok_or_else(|| BenchError::Integrity("recovery distribution omitted p95".to_owned()))?;
        let metric = threshold_metric(
            format!("semantic.{}.recovery_latency_p95_ns", tier.as_str()),
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            recovery,
            ThresholdOperator::Lte,
            target.recovery_p95_max_ns as f64,
        )?;
        recovery_passed &= metric.passed == Some(true);
        metrics.push(metric);

        let freshness = Distribution::from_samples(&measurement.index_freshness_lag_ns)?
            .p95
            .ok_or_else(|| {
                BenchError::Integrity("freshness distribution omitted p95".to_owned())
            })?;
        let metric = threshold_metric(
            format!("semantic.{}.index_freshness_lag_p95_ns", tier.as_str()),
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            freshness,
            ThresholdOperator::Lte,
            target.index_freshness_p95_max_ns as f64,
        )?;
        freshness_passed &= metric.passed == Some(true);
        metrics.push(metric);

        let rss_max = measurement
            .process_rss_bytes
            .iter()
            .max()
            .copied()
            .ok_or_else(|| BenchError::Integrity("RSS samples unexpectedly empty".to_owned()))?;
        let metric = threshold_metric(
            format!("semantic.{}.process_rss_max_bytes", tier.as_str()),
            "bytes",
            MetricDirection::LowerIsBetter,
            rss_max as f64,
            ThresholdOperator::Lte,
            target.process_rss_max_bytes as f64,
        )?;
        bounded_memory_passed &= metric.passed == Some(true);
        metrics.push(metric);

        let pressure_metric = threshold_metric(
            format!("semantic.{}.pressure_degraded_responses", tier.as_str()),
            "responses",
            MetricDirection::HigherIsBetter,
            measurement.degraded_responses as f64,
            ThresholdOperator::Gte,
            1.0,
        )?;
        pressure_degradation_passed &=
            measurement.pressure_requests > 0 && pressure_metric.passed == Some(true);
        metrics.push(pressure_metric);
        for (name, observed) in [
            (
                "pressure_correctness_failures",
                measurement.correctness_failures,
            ),
            (
                "pressure_uncontrolled_oom_events",
                measurement.uncontrolled_oom_events,
            ),
        ] {
            let metric = threshold_metric(
                format!("semantic.{}.{name}", tier.as_str()),
                "events",
                MetricDirection::Target,
                observed as f64,
                ThresholdOperator::Eq,
                0.0,
            )?;
            pressure_correctness_passed &= metric.passed == Some(true);
            metrics.push(metric);
        }
    }

    let mut regression_passes = BTreeMap::new();
    for class in SemanticRegressionClass::ALL {
        let measurement = regressions.get(&class).ok_or_else(|| {
            BenchError::Integrity(format!("missing regression class `{}`", class.as_str()))
        })?;
        let metric = threshold_metric(
            format!("semantic.regression.{}_candidate_score_bps", class.as_str()),
            "basis_points",
            MetricDirection::HigherIsBetter,
            measurement.candidate_score_bps,
            ThresholdOperator::Gte,
            measurement.baseline_score_bps,
        )?;
        regression_passes.insert(class, metric.passed == Some(true));
        metrics.push(metric);
    }

    let scenario_completed = |scenario| {
        SemanticTier::ALL
            .into_iter()
            .all(|tier| scenarios.contains_key(&(tier, scenario)))
    };
    let tier_completed = |tier: SemanticTier| {
        let Some(measured) = tiers.get(&tier) else {
            return false;
        };
        let (nodes, edges, vectors) = tier.scale_floor();
        measured.semantic_nodes >= nodes
            && measured.graph_edges >= edges
            && vectors.is_none_or(|minimum| measured.vectors >= minimum)
            && SemanticScenario::ALL
                .into_iter()
                .all(|scenario| scenarios.contains_key(&(tier, scenario)))
    };
    let certification = tiers
        .get(&SemanticTier::CertificationV1)
        .ok_or_else(|| BenchError::Integrity("missing certification tier".to_owned()))?;
    let coverage = BenchHCoverageManifest {
        semantic_nodes: certification.semantic_nodes,
        graph_edges: certification.graph_edges,
        vectors: certification.vectors,
        small_tier_completed: tier_completed(SemanticTier::Small),
        medium_tier_completed: tier_completed(SemanticTier::Medium),
        certification_tier_completed: tier_completed(SemanticTier::CertificationV1),
        hot_conversation_completed: scenario_completed(SemanticScenario::HotConversation),
        cold_autobiographical_completed: scenario_completed(SemanticScenario::ColdAutobiographical),
        current_fact_completed: scenario_completed(SemanticScenario::CurrentFact),
        historical_fact_completed: scenario_completed(SemanticScenario::HistoricalFact),
        filtered_ann_completed: scenario_completed(SemanticScenario::FilteredAnn),
        hierarchy_drill_down_completed: scenario_completed(SemanticScenario::HierarchyDrillDown),
        artifact_metadata_completed: scenario_completed(SemanticScenario::ArtifactMetadata),
        compaction_under_load_completed: scenario_completed(SemanticScenario::CompactionUnderLoad),
        backup_completed: scenario_completed(SemanticScenario::Backup),
        restart_completed: scenario_completed(SemanticScenario::Restart),
        e01_latency_percentiles_passed: latency_passed,
        e01_throughput_passed: throughput_passed,
        e01_recovery_passed: recovery_passed,
        e01_index_freshness_passed: freshness_passed,
        e02_bounded_memory_passed: bounded_memory_passed,
        e02_pressure_degradation_passed: pressure_degradation_passed,
        e02_no_correctness_loss_or_uncontrolled_oom_passed: pressure_correctness_passed,
        e03_semantic_regression_passed: regression_passes
            [&SemanticRegressionClass::SemanticQuality],
        e03_privacy_regression_passed: regression_passes[&SemanticRegressionClass::Privacy],
        e03_social_calibration_passed: regression_passes
            [&SemanticRegressionClass::SocialCalibration],
        e03_ann_exact_overlap_passed: regression_passes[&SemanticRegressionClass::AnnExactOverlap],
    };

    let matrix_complete = coverage.small_tier_completed
        && coverage.medium_tier_completed
        && coverage.certification_tier_completed
        && coverage.hot_conversation_completed
        && coverage.cold_autobiographical_completed
        && coverage.current_fact_completed
        && coverage.historical_fact_completed
        && coverage.filtered_ann_completed
        && coverage.hierarchy_drill_down_completed
        && coverage.artifact_metadata_completed
        && coverage.compaction_under_load_completed
        && coverage.backup_completed
        && coverage.restart_completed;
    let e01 = latency_passed && throughput_passed && recovery_passed && freshness_passed;
    let e02 = bounded_memory_passed && pressure_degradation_passed && pressure_correctness_passed;
    let e03 = regression_passes.values().all(|passed| *passed);
    for (name, passed) in [
        ("semantic.matrix.complete", matrix_complete),
        ("semantic.e01.latency_percentiles", latency_passed),
        ("semantic.e01.throughput", throughput_passed),
        ("semantic.e01.recovery", recovery_passed),
        ("semantic.e01.index_freshness", freshness_passed),
        ("semantic.e01.all_declared_targets", e01),
        ("semantic.e02.bounded_memory", bounded_memory_passed),
        (
            "semantic.e02.pressure_degradation",
            pressure_degradation_passed,
        ),
        (
            "semantic.e02.no_correctness_loss_or_uncontrolled_oom",
            pressure_correctness_passed,
        ),
        ("semantic.e02.all_declared_targets", e02),
        ("semantic.e03.no_frozen_floor_regression", e03),
    ] {
        metrics.push(exact_boolean_metric(name, passed)?);
    }
    let quality_gates = [
        ("M17-MATRIX", "semantic.matrix.complete", matrix_complete),
        ("M17-E01", "semantic.e01.all_declared_targets", e01),
        ("M17-E02", "semantic.e02.all_declared_targets", e02),
        (
            "M17-E03",
            "semantic.e03.no_frozen_floor_regression",
            e03,
        ),
    ]
    .into_iter()
    .map(|(gate_id, metric, passed)| QualityGate {
        gate_id: gate_id.to_owned(),
        metric: metric.to_owned(),
        passed,
        note: Some(
            "Development target result derived from bound numeric measurements; not release certification."
                .to_owned(),
        ),
    })
    .collect();
    Ok(DerivedSemanticEvidence {
        coverage,
        metrics,
        quality_gates,
    })
}

fn tier_target_map(
    matrix: &SemanticTargetMatrix,
) -> Result<BTreeMap<SemanticTier, &SemanticTierTarget>> {
    let targets: BTreeMap<_, _> = matrix
        .tiers
        .iter()
        .map(|target| (target.tier, target))
        .collect();
    if targets.len() != matrix.tiers.len() {
        return invalid(
            "semantic_target_matrix.tiers",
            "tier target rows must be unique",
        );
    }
    Ok(targets)
}

fn threshold_metric(
    name: String,
    unit: &'static str,
    direction: MetricDirection,
    observed: f64,
    operator: ThresholdOperator,
    threshold: f64,
) -> Result<Metric> {
    if !observed.is_finite() || !threshold.is_finite() {
        return invalid(
            "semantic_metric",
            "observed values and thresholds must be finite",
        );
    }
    Metric::scalar(name, unit, direction, observed).with_threshold(MetricThreshold {
        operator,
        value: ThresholdValue::Scalar(threshold),
    })
}

fn exact_boolean_metric(name: &'static str, passed: bool) -> Result<Metric> {
    threshold_metric(
        name.to_owned(),
        "boolean_as_integer",
        MetricDirection::Target,
        f64::from(passed),
        ThresholdOperator::Eq,
        1.0,
    )
}

fn valid_basis_points(value: f64) -> bool {
    value.is_finite() && (0.0..=10_000.0).contains(&value)
}

fn validate_identifier(field: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return invalid(
            field,
            "value must be a bounded nonempty string without controls",
        );
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(field, "expected 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_nonzero_exact_integer(field: &'static str, value: u64) -> Result<()> {
    if value == 0 {
        return invalid(field, "value must be nonzero");
    }
    validate_exact_integer(field, value)
}

fn validate_exact_integer(field: &'static str, value: u64) -> Result<()> {
    if value > MAX_EXACT_F64_INTEGER {
        return invalid(
            field,
            "value exceeds exact integer range used by report metrics",
        );
    }
    Ok(())
}

fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T> {
    Err(BenchError::InvalidConfiguration {
        field,
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "semantic contract tests use immediate failure semantics"
    )]

    use super::{
        MeasuredArtifact, SemanticArtifactKind, SemanticRegressionClass,
        SemanticRegressionMeasurement, SemanticRunOutcome, SemanticScenario,
        SemanticScenarioMeasurement, SemanticScenarioTarget, SemanticTargetMatrix, SemanticTier,
        SemanticTierMeasurement, SemanticTierTarget, build_semantic_development_report,
        semantic_target_matrix_sha256,
    };
    use crate::digest::sha256_hex;
    use crate::report::{BuildProfile, ReleaseChannel, ReportStatus, ScalarValue};
    use crate::{
        BENCH_H_WORKLOAD_VERSION, NativeRunMetadata, SEMANTIC_OUTCOME_SCHEMA_VERSION,
        SEMANTIC_TARGET_MATRIX_SCHEMA_VERSION,
    };

    const HARDWARE: &[u8] = b"synthetic hardware-profile contract fixture";
    const SCENARIO_TRACE: &[u8] = b"synthetic scenario-trace contract fixture";
    const TIER_TRACE: &[u8] = b"synthetic tier-resource contract fixture";
    const REGRESSION_TRACE: &[u8] = b"synthetic regression contract fixture";

    fn metadata() -> NativeRunMetadata {
        NativeRunMetadata {
            started_at: "2026-08-13T00:00:00Z".to_owned(),
            finished_at: "2026-08-13T00:00:01Z".to_owned(),
            git_commit: "1".repeat(40),
            dirty: false,
            release_channel: ReleaseChannel::Beta,
            build_profile: BuildProfile::Bench,
            os: "test".to_owned(),
            os_version: "test".to_owned(),
            kernel: None,
            architecture: "x86_64".to_owned(),
            cpu: "synthetic".to_owned(),
            logical_cores: 1,
            memory_bytes: 1,
            storage: "synthetic".to_owned(),
            filesystem: "synthetic".to_owned(),
            rustc: "rustc test".to_owned(),
            cargo: "cargo test".to_owned(),
            target: "x86_64-pc-windows-msvc".to_owned(),
        }
    }

    fn target_matrix() -> SemanticTargetMatrix {
        SemanticTargetMatrix {
            schema_version: SEMANTIC_TARGET_MATRIX_SCHEMA_VERSION.to_owned(),
            revision: "synthetic-development-targets-v1".to_owned(),
            tiers: SemanticTier::ALL
                .into_iter()
                .map(|tier| {
                    let (nodes, edges, vectors) = tier.scale_floor();
                    SemanticTierTarget {
                        tier,
                        minimum_semantic_nodes: nodes,
                        minimum_graph_edges: edges,
                        minimum_vectors: vectors,
                        scenarios: SemanticScenario::ALL
                            .into_iter()
                            .map(|scenario| SemanticScenarioTarget {
                                scenario,
                                latency_p50_max_ns: 100,
                                latency_p95_max_ns: 200,
                                latency_p99_max_ns: 300,
                                minimum_operations_per_second: 1,
                            })
                            .collect(),
                        recovery_p95_max_ns: 200,
                        index_freshness_p95_max_ns: 200,
                        process_rss_max_bytes: 1_000,
                    }
                })
                .collect(),
        }
    }

    fn synthetic_outcome() -> SemanticRunOutcome {
        let target_matrix = target_matrix();
        SemanticRunOutcome {
            schema_version: SEMANTIC_OUTCOME_SCHEMA_VERSION.to_owned(),
            dataset_version: BENCH_H_WORKLOAD_VERSION.to_owned(),
            seed: 17,
            target_matrix_sha256: semantic_target_matrix_sha256(&target_matrix)
                .expect("target digest"),
            target_matrix,
            target_matrix_uri: "synthetic-target-matrix.json".to_owned(),
            reference_hardware_sha256: sha256_hex(HARDWARE),
            tier_measurements: SemanticTier::ALL
                .into_iter()
                .map(|tier| {
                    let (nodes, edges, vectors) = tier.scale_floor();
                    SemanticTierMeasurement {
                        tier,
                        semantic_nodes: nodes,
                        graph_edges: edges,
                        vectors: vectors.unwrap_or(1),
                        recovery_latency_ns: vec![10, 20, 30],
                        index_freshness_lag_ns: vec![10, 20, 30],
                        process_rss_bytes: vec![500, 600],
                        pressure_requests: 2,
                        degraded_responses: 1,
                        correctness_failures: 0,
                        uncontrolled_oom_events: 0,
                        artifact_sha256: sha256_hex(TIER_TRACE),
                    }
                })
                .collect(),
            scenario_measurements: SemanticTier::ALL
                .into_iter()
                .flat_map(|tier| {
                    SemanticScenario::ALL.into_iter().map(move |scenario| {
                        SemanticScenarioMeasurement {
                            tier,
                            scenario,
                            latency_ns: vec![10, 20, 30],
                            completed_operations: 100,
                            elapsed_ns: 1_000_000_000,
                            artifact_sha256: sha256_hex(SCENARIO_TRACE),
                        }
                    })
                })
                .collect(),
            regressions: SemanticRegressionClass::ALL
                .into_iter()
                .map(|class| SemanticRegressionMeasurement {
                    class,
                    baseline_score_bps: 9_000.0,
                    candidate_score_bps: 9_000.0,
                    artifact_sha256: sha256_hex(REGRESSION_TRACE),
                })
                .collect(),
        }
    }

    fn artifacts() -> [MeasuredArtifact<'static>; 4] {
        [
            MeasuredArtifact {
                kind: SemanticArtifactKind::ReferenceHardwareProfile,
                uri: "hardware.json",
                bytes: HARDWARE,
            },
            MeasuredArtifact {
                kind: SemanticArtifactKind::ScenarioTrace,
                uri: "scenario-trace.json",
                bytes: SCENARIO_TRACE,
            },
            MeasuredArtifact {
                kind: SemanticArtifactKind::TierResourceTrace,
                uri: "tier-trace.json",
                bytes: TIER_TRACE,
            },
            MeasuredArtifact {
                kind: SemanticArtifactKind::RegressionReport,
                uri: "regression.json",
                bytes: REGRESSION_TRACE,
            },
        ]
    }

    #[test]
    fn exact_synthetic_matrix_is_derived_but_cannot_promote_to_release() {
        let raw = serde_json::to_vec(&synthetic_outcome()).expect("raw outcome");
        let report = build_semantic_development_report(
            &raw,
            "semantic-outcome.json",
            metadata(),
            &artifacts(),
        )
        .expect("semantic report");
        assert_eq!(report.status, ReportStatus::ObservationOnly);
        assert!(!report.release_eligible());
        assert_eq!(
            report.contextdb.version_manifest.release_channel,
            ReleaseChannel::Development
        );
        assert!(report.quality_gates.iter().all(|gate| gate.passed));
        assert!(matches!(
            report
                .configuration
                .parameters
                .get("bench_h_certification_tier_completed"),
            Some(ScalarValue::Boolean(true))
        ));
        assert!(matches!(
            report
                .configuration
                .parameters
                .get("release_certification_supported"),
            Some(ScalarValue::Boolean(false))
        ));
        report.validate().expect("report validates");
    }

    #[test]
    fn missing_matrix_row_and_changed_scale_floor_fail_closed() {
        let mut outcome = synthetic_outcome();
        outcome.scenario_measurements.pop();
        let raw = serde_json::to_vec(&outcome).expect("raw outcome");
        assert!(
            build_semantic_development_report(
                &raw,
                "semantic-outcome.json",
                metadata(),
                &artifacts()
            )
            .is_err()
        );

        let mut outcome = synthetic_outcome();
        outcome.target_matrix.tiers[2].minimum_graph_edges -= 1;
        outcome.target_matrix_sha256 =
            semantic_target_matrix_sha256(&outcome.target_matrix).expect("target digest");
        let raw = serde_json::to_vec(&outcome).expect("raw outcome");
        assert!(
            build_semantic_development_report(
                &raw,
                "semantic-outcome.json",
                metadata(),
                &artifacts()
            )
            .is_err()
        );
    }

    #[test]
    fn target_and_measurement_artifact_tampering_is_rejected() {
        let mut outcome = synthetic_outcome();
        outcome.target_matrix.revision.push_str("-changed");
        let raw = serde_json::to_vec(&outcome).expect("raw outcome");
        assert!(
            build_semantic_development_report(
                &raw,
                "semantic-outcome.json",
                metadata(),
                &artifacts()
            )
            .is_err()
        );

        let mut outcome = synthetic_outcome();
        outcome.scenario_measurements[0].artifact_sha256 = sha256_hex(b"missing trace");
        let raw = serde_json::to_vec(&outcome).expect("raw outcome");
        assert!(
            build_semantic_development_report(
                &raw,
                "semantic-outcome.json",
                metadata(),
                &artifacts()
            )
            .is_err()
        );
    }

    #[test]
    fn failed_numeric_target_is_a_failed_development_report() {
        let mut outcome = synthetic_outcome();
        outcome.scenario_measurements[0].latency_ns = vec![1_000];
        let raw = serde_json::to_vec(&outcome).expect("raw outcome");
        let report = build_semantic_development_report(
            &raw,
            "semantic-outcome.json",
            metadata(),
            &artifacts(),
        )
        .expect("semantic report");
        assert_eq!(report.status, ReportStatus::Failed);
        assert!(!report.release_eligible());
        assert!(
            report
                .quality_gates
                .iter()
                .any(|gate| gate.gate_id == "M17-E01" && !gate.passed)
        );
    }

    #[test]
    fn quality_gate_must_bind_an_existing_threshold_outcome() {
        let raw = serde_json::to_vec(&synthetic_outcome()).expect("raw outcome");
        let report = build_semantic_development_report(
            &raw,
            "semantic-outcome.json",
            metadata(),
            &artifacts(),
        )
        .expect("semantic report");

        let mut missing = report.clone();
        missing.quality_gates[0].metric = "semantic.missing".to_owned();
        assert!(missing.validate().is_err());

        let mut mismatched = report;
        mismatched.quality_gates[0].passed = false;
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn semantic_report_remains_nonrelease_after_all_metadata_and_parameter_flips() {
        let raw = serde_json::to_vec(&synthetic_outcome()).expect("raw outcome");
        let mut report = build_semantic_development_report(
            &raw,
            "semantic-outcome.json",
            metadata(),
            &artifacts(),
        )
        .expect("semantic report");
        report.configuration.parameters.insert(
            "evidence_kind".to_owned(),
            ScalarValue::String("release_certification".to_owned()),
        );
        report.configuration.parameters.insert(
            "m16_deep_scan_passed".to_owned(),
            ScalarValue::Boolean(true),
        );
        report.contextdb.version_manifest.release_channel = ReleaseChannel::Beta;
        report.contextdb.version_manifest.source.dirty = false;
        report.contextdb = crate::ContextDbIdentity::new(report.contextdb.version_manifest.clone())
            .expect("updated identity");
        report.environment.build_profile = BuildProfile::Bench;
        report.benchmark.scenario = "full-semantic-graph-vector-operations".to_owned();
        report.benchmark.tier = "certification-v1-full-semantic".to_owned();
        assert!(!report.release_eligible());
    }
}
