//! Canonical machine-readable benchmark result contracts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::digest::sha256_hex;
use crate::{BENCHMARK_RESULT_SCHEMA_VERSION, BenchError, Result};

/// Provenance class of a benchmark run.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Pure deterministic harness validation; never performance evidence.
    SyntheticHarnessValidation,
    /// Wall-clock measurements on a real local backend, but not release proof.
    NativeMeasuredDevelopment,
    /// Candidate release evidence, subject to every certification prerequisite.
    ReleaseCertification,
}

impl EvidenceKind {
    /// Stable value stored in canonical scalar parameters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticHarnessValidation => "synthetic_harness_validation",
            Self::NativeMeasuredDevelopment => "native_measured_development",
            Self::ReleaseCertification => "release_certification",
        }
    }
}

/// Top-level benchmark outcome defined by the canonical result schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Every declared threshold passed and release prerequisites were present.
    Passed,
    /// At least one declared correctness, privacy, or performance gate failed.
    Failed,
    /// Execution could not produce a valid measurement.
    Error,
    /// Useful measurement which is intentionally not release-gating evidence.
    ObservationOnly,
}

/// RFC benchmark family represented by this package.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BenchmarkFamily {
    /// Logical multimodal conformance and quality.
    #[serde(rename = "BENCH-E")]
    BenchE,
    /// Performance, scale, and operational behavior.
    #[serde(rename = "BENCH-H")]
    BenchH,
}

/// Stable benchmark identity and dataset tier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkIdentity {
    /// Stable four-digit benchmark ID.
    pub id: String,
    /// RFC family.
    pub family: BenchmarkFamily,
    /// Human-readable stable name.
    pub name: String,
    /// Harness version.
    pub version: String,
    /// Deterministic dataset generator version.
    pub dataset_version: String,
    /// Scenario represented by this report.
    pub scenario: String,
    /// Dataset scale tier.
    pub tier: String,
}

/// Release maturity of the measured build.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    /// Local development build.
    Development,
    /// Alpha release candidate.
    Alpha,
    /// Beta release candidate.
    Beta,
    /// Stable release.
    Stable,
}

/// Cargo profile used for the measured binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildProfile {
    /// Debug development profile.
    Dev,
    /// Test profile.
    Test,
    /// Dedicated benchmark profile.
    Bench,
    /// Optimized release profile.
    Release,
    /// Hardened optimized release profile.
    ReleaseSafe,
}

/// Source identity embedded in a version manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceManifest {
    /// Exact 40-character Git commit.
    pub git_commit: String,
    /// Whether tracked or untracked source differed from the commit.
    pub dirty: bool,
    /// Public source repository, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Normative RFC revision.
    pub rfc_revision: String,
    /// Applied errata identifiers.
    pub errata: Vec<String>,
    /// Applied architecture decision records.
    pub adrs: Vec<String>,
}

/// Compiler/build identity embedded in a version manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    /// UTC RFC3339 build timestamp.
    pub timestamp: String,
    /// Full rustc version string.
    pub rustc: String,
    /// Full cargo version string.
    pub cargo: String,
    /// Rust compilation target.
    pub target: String,
    /// Cargo profile.
    pub profile: BuildProfile,
    /// Whether this build is claimed byte-for-byte reproducible.
    pub reproducible: bool,
    /// Payload-free builder label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder: Option<String>,
}

/// One ContextDB format compatibility range.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatVersion {
    /// Writer version.
    pub writer: u32,
    /// Minimum readable version.
    pub read_min: u32,
    /// Maximum readable version.
    pub read_max: u32,
    /// Required feature names.
    pub required_features: Vec<String>,
}

/// ContextDB feature profile captured in a version manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeatureProfile {
    /// Minimal embedded engine.
    EmbeddedMinimal,
    /// Server v1 profile.
    ServerV1,
    /// Conformance profile.
    Conformance,
    /// Research/benchmark profile.
    Research,
    /// Explicit custom profile.
    Custom,
}

/// Optional physical backend identity in a version manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBackendManifest {
    /// Backend name.
    pub name: String,
    /// Backend version.
    pub version: String,
    /// SHA-256 of payload-free backend configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_digest: Option<String>,
}

/// Optional migration state in a version manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationManifest {
    /// Applied migrations.
    pub applied: Vec<String>,
    /// Whether rollback is supported.
    pub rollback_supported: bool,
}

/// Canonical ContextDB version manifest v1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionManifest {
    /// Manifest schema version.
    pub schema_version: String,
    /// ContextDB semantic version.
    pub product_version: String,
    /// Release maturity.
    pub release_channel: ReleaseChannel,
    /// Source identity.
    pub source: SourceManifest,
    /// Build identity.
    pub build: BuildManifest,
    /// Read/write format ranges.
    pub formats: BTreeMap<String, FormatVersion>,
    /// Feature profile.
    pub feature_profile: FeatureProfile,
    /// Enabled features.
    pub features: Vec<String>,
    /// Optional storage identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_backend: Option<StorageBackendManifest>,
    /// Optional migration state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migration: Option<MigrationManifest>,
}

/// Version manifest plus digest bound into the benchmark result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextDbIdentity {
    /// Full manifest.
    pub version_manifest: VersionManifest,
    /// SHA-256 of the compact canonical serialization embedded above.
    pub version_manifest_sha256: String,
}

impl ContextDbIdentity {
    /// Creates a digest-bound identity from a manifest.
    pub fn new(version_manifest: VersionManifest) -> Result<Self> {
        let bytes = serde_json::to_vec(&version_manifest)?;
        Ok(Self {
            version_manifest,
            version_manifest_sha256: sha256_hex(&bytes),
        })
    }
}

/// Hardware, operating system, and build environment for a measured run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    /// Operating system family.
    pub os: String,
    /// Operating system release.
    pub os_version: String,
    /// Optional kernel release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// CPU architecture.
    pub architecture: String,
    /// CPU model or explicit not-measured marker.
    pub cpu: String,
    /// Logical CPU count.
    pub logical_cores: u32,
    /// Physical memory, or one with an explicit limitation when unavailable.
    pub memory_bytes: u64,
    /// Storage device description.
    pub storage: String,
    /// Filesystem description.
    pub filesystem: String,
    /// rustc version.
    pub rustc: String,
    /// cargo version.
    pub cargo: String,
    /// Storage backend name.
    pub storage_backend: String,
    /// Optional backend version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_backend_version: Option<String>,
    /// Optional SHA-256 of backend settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_configuration_digest: Option<String>,
    /// Measured build profile.
    pub build_profile: BuildProfile,
}

/// Scalar configuration value allowed by the canonical result schema.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScalarValue {
    /// Unsigned integer.
    Unsigned(u64),
    /// Signed integer.
    Integer(i64),
    /// Floating-point number.
    Number(f64),
    /// String.
    String(String),
    /// Boolean.
    Boolean(bool),
    /// Explicit null, accepted only for parameters.
    Null,
}

/// Deterministic workload configuration recorded with measurements.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfiguration {
    /// Workload seed.
    pub seed: u64,
    /// Feature flags.
    pub features: Vec<String>,
    /// Predeclared resource/cardinality budgets.
    pub budgets: BTreeMap<String, ScalarValue>,
    /// Scenario parameters, including evidence classification.
    pub parameters: BTreeMap<String, ScalarValue>,
    /// Projection watermarks at measurement time.
    pub index_watermarks: BTreeMap<String, u64>,
}

/// Direction used to interpret one metric.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricDirection {
    /// Larger values are better.
    HigherIsBetter,
    /// Smaller values are better.
    LowerIsBetter,
    /// Exact or bounded target.
    Target,
    /// Observation without a pass/fail interpretation.
    Informational,
}

/// Summary distribution accepted by the canonical result schema.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Distribution {
    /// Number of samples.
    pub count: u64,
    /// Minimum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    /// Maximum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// Arithmetic mean.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean: Option<f64>,
    /// Nearest-rank median.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p50: Option<f64>,
    /// Nearest-rank p95.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95: Option<f64>,
    /// Nearest-rank p99.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p99: Option<f64>,
}

impl Distribution {
    /// Summarizes non-empty integer samples with deterministic nearest-rank percentiles.
    pub fn from_samples(samples: &[u64]) -> Result<Self> {
        if samples.is_empty() {
            return Err(BenchError::InvalidConfiguration {
                field: "samples",
                reason: "a distribution requires at least one sample".to_owned(),
            });
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let count = u64::try_from(sorted.len())
            .map_err(|_| BenchError::ArithmeticOverflow("distribution sample count"))?;
        let sum = sorted.iter().fold(0_u128, |total, value| {
            total.saturating_add(u128::from(*value))
        });
        let mean = sum as f64 / count as f64;
        Ok(Self {
            count,
            min: sorted.first().copied().map(|value| value as f64),
            max: sorted.last().copied().map(|value| value as f64),
            mean: Some(mean),
            p50: Some(nearest_rank(&sorted, 50) as f64),
            p95: Some(nearest_rank(&sorted, 95) as f64),
            p99: Some(nearest_rank(&sorted, 99) as f64),
        })
    }

    /// Extracts a named statistic for regression comparison.
    #[must_use]
    pub const fn statistic(self, statistic: DistributionStatistic) -> Option<f64> {
        match statistic {
            DistributionStatistic::Min => self.min,
            DistributionStatistic::Max => self.max,
            DistributionStatistic::Mean => self.mean,
            DistributionStatistic::P50 => self.p50,
            DistributionStatistic::P95 => self.p95,
            DistributionStatistic::P99 => self.p99,
        }
    }
}

fn nearest_rank(sorted: &[u64], percentile: usize) -> u64 {
    let numerator = sorted.len().saturating_mul(percentile).saturating_add(99);
    let rank = numerator / 100;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// Distribution field selected for a regression rule.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributionStatistic {
    /// Minimum.
    Min,
    /// Maximum.
    Max,
    /// Mean.
    Mean,
    /// Median.
    P50,
    /// p95.
    P95,
    /// p99.
    P99,
}

/// Scalar or distribution observation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetricObserved {
    /// Scalar value.
    Scalar(f64),
    /// Distribution value.
    Distribution(Distribution),
}

impl MetricObserved {
    /// Returns a scalar directly or the selected distribution statistic.
    #[must_use]
    pub fn value(&self, statistic: Option<DistributionStatistic>) -> Option<f64> {
        match (self, statistic) {
            (Self::Scalar(value), None) => Some(*value),
            (Self::Distribution(distribution), Some(statistic)) => {
                distribution.statistic(statistic)
            }
            _ => None,
        }
    }
}

/// Threshold operator from the canonical result schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdOperator {
    /// Strictly less than.
    Lt,
    /// Less than or equal.
    Lte,
    /// Equal.
    Eq,
    /// Greater than or equal.
    Gte,
    /// Strictly greater than.
    Gt,
    /// Inclusive lower and upper bound.
    BetweenInclusive,
}

/// Scalar or inclusive range threshold value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ThresholdValue {
    /// Scalar threshold.
    Scalar(f64),
    /// Two-value inclusive range.
    Range([f64; 2]),
}

/// Predeclared metric threshold.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricThreshold {
    /// Comparison operator.
    pub operator: ThresholdOperator,
    /// Scalar or range value.
    pub value: ThresholdValue,
}

impl MetricThreshold {
    /// Evaluates a scalar observation against this threshold.
    pub fn evaluate(&self, observed: f64) -> Result<bool> {
        let passed = match (self.operator, &self.value) {
            (ThresholdOperator::Lt, ThresholdValue::Scalar(value)) => observed < *value,
            (ThresholdOperator::Lte, ThresholdValue::Scalar(value)) => observed <= *value,
            (ThresholdOperator::Eq, ThresholdValue::Scalar(value)) => {
                (observed - *value).abs() <= f64::EPSILON
            }
            (ThresholdOperator::Gte, ThresholdValue::Scalar(value)) => observed >= *value,
            (ThresholdOperator::Gt, ThresholdValue::Scalar(value)) => observed > *value,
            (ThresholdOperator::BetweenInclusive, ThresholdValue::Range([lower, upper])) => {
                lower <= upper && observed >= *lower && observed <= *upper
            }
            _ => {
                return Err(BenchError::InvalidConfiguration {
                    field: "metric.threshold",
                    reason: "operator and threshold value shape disagree".to_owned(),
                });
            }
        };
        Ok(passed)
    }
}

/// One machine-readable benchmark metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metric {
    /// Stable dot-separated metric name.
    pub name: String,
    /// Unit.
    pub unit: String,
    /// Interpretation direction.
    pub direction: MetricDirection,
    /// Scalar or distribution observation.
    pub observed: MetricObserved,
    /// Predeclared threshold, when this metric is a gate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<MetricThreshold>,
    /// Threshold outcome; present exactly when a threshold is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<bool>,
}

impl Metric {
    /// Creates an informational scalar metric.
    #[must_use]
    pub fn scalar(
        name: impl Into<String>,
        unit: impl Into<String>,
        direction: MetricDirection,
        observed: f64,
    ) -> Self {
        Self {
            name: name.into(),
            unit: unit.into(),
            direction,
            observed: MetricObserved::Scalar(observed),
            threshold: None,
            passed: None,
        }
    }

    /// Creates an informational distribution metric.
    #[must_use]
    pub fn distribution(
        name: impl Into<String>,
        unit: impl Into<String>,
        direction: MetricDirection,
        observed: Distribution,
    ) -> Self {
        Self {
            name: name.into(),
            unit: unit.into(),
            direction,
            observed: MetricObserved::Distribution(observed),
            threshold: None,
            passed: None,
        }
    }

    /// Adds a scalar threshold and computes its outcome.
    pub fn with_threshold(mut self, threshold: MetricThreshold) -> Result<Self> {
        let observed =
            self.observed
                .value(None)
                .ok_or_else(|| BenchError::InvalidConfiguration {
                    field: "metric.threshold",
                    reason: "thresholds must target an emitted scalar metric".to_owned(),
                })?;
        self.passed = Some(threshold.evaluate(observed)?);
        self.threshold = Some(threshold);
        Ok(self)
    }
}

/// One named cross-metric quality gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityGate {
    /// Stable gate ID.
    pub gate_id: String,
    /// Metric used by the gate.
    pub metric: String,
    /// Gate outcome.
    pub passed: bool,
    /// Optional payload-free explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Content-addressed benchmark artifact reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Artifact kind.
    pub kind: String,
    /// URI or relative path.
    pub uri: String,
    /// SHA-256 digest.
    pub sha256: String,
}

/// Structured top-level execution failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportError {
    /// Stable code.
    pub code: String,
    /// Payload-free message.
    pub message: String,
}

/// Canonical ContextDB benchmark result v1.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkResult {
    /// Result schema version.
    pub schema_version: String,
    /// Unique run ID.
    pub run_id: Uuid,
    /// UTC RFC3339 start timestamp.
    pub started_at: String,
    /// UTC RFC3339 finish timestamp.
    pub finished_at: String,
    /// Outcome classification.
    pub status: ReportStatus,
    /// Benchmark identity.
    pub benchmark: BenchmarkIdentity,
    /// ContextDB source/build identity.
    pub contextdb: ContextDbIdentity,
    /// Native environment.
    pub environment: Environment,
    /// Deterministic configuration.
    pub configuration: RunConfiguration,
    /// Measurements.
    pub metrics: Vec<Metric>,
    /// Optional named gates.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub quality_gates: Vec<QualityGate>,
    /// Content-addressed evidence artifacts.
    pub artifacts: Vec<Artifact>,
    /// Honest known limitations.
    pub limitations: Vec<String>,
    /// Structured error, required only for error status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ReportError>,
}

impl BenchmarkResult {
    /// Validates schema shape plus M17 evidence-class invariants.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != BENCHMARK_RESULT_SCHEMA_VERSION {
            return invalid("schema_version", "unsupported result schema");
        }
        if !valid_benchmark_id(&self.benchmark.id) {
            return invalid("benchmark.id", "expected BENCH plus four digits");
        }
        if self.started_at.is_empty() || self.finished_at.is_empty() {
            return invalid("timestamps", "start and finish timestamps are required");
        }
        if self.metrics.is_empty() || self.artifacts.is_empty() {
            return invalid("report", "at least one metric and artifact are required");
        }
        if self.contextdb.version_manifest.source.git_commit.len() != 40
            || !is_lower_hex(&self.contextdb.version_manifest.source.git_commit)
        {
            return invalid("source.git_commit", "expected 40 lowercase hex characters");
        }
        let manifest_bytes = serde_json::to_vec(&self.contextdb.version_manifest)?;
        if self.contextdb.version_manifest_sha256 != sha256_hex(&manifest_bytes) {
            return Err(BenchError::Integrity(
                "version manifest digest does not match embedded manifest".to_owned(),
            ));
        }
        let mut artifact_bindings = BTreeSet::new();
        for artifact in &self.artifacts {
            if artifact.kind.trim().is_empty() || artifact.uri.trim().is_empty() {
                return invalid("artifact", "kind and URI must be non-empty");
            }
            if artifact.sha256.len() != 64 || !is_lower_hex(&artifact.sha256) {
                return invalid("artifact.sha256", "expected 64 lowercase hex characters");
            }
            if !artifact_bindings.insert((artifact.kind.as_str(), artifact.uri.as_str())) {
                return invalid("artifacts", "artifact kind/URI bindings must be unique");
            }
        }
        let mut metric_names = BTreeSet::new();
        for metric in &self.metrics {
            if !valid_metric_name(&metric.name) || metric.unit.is_empty() {
                return invalid("metric", "invalid metric name or empty unit");
            }
            if !metric_names.insert(metric.name.as_str()) {
                return invalid("metrics", "metric names must be unique");
            }
            if metric.threshold.is_some() != metric.passed.is_some() {
                return invalid(
                    "metric.threshold",
                    "threshold and passed fields must appear together",
                );
            }
            if let (MetricObserved::Scalar(observed), Some(threshold), Some(passed)) =
                (&metric.observed, &metric.threshold, metric.passed)
                && threshold.evaluate(*observed)? != passed
            {
                return Err(BenchError::Integrity(format!(
                    "metric `{}` threshold outcome is inconsistent",
                    metric.name
                )));
            }
        }
        let metrics: BTreeMap<_, _> = self
            .metrics
            .iter()
            .map(|metric| (metric.name.as_str(), metric))
            .collect();
        let mut gate_ids = BTreeSet::new();
        for gate in &self.quality_gates {
            if !gate_ids.insert(gate.gate_id.as_str()) {
                return invalid("quality_gates", "quality gate IDs must be unique");
            }
            let metric = metrics.get(gate.metric.as_str()).ok_or_else(|| {
                BenchError::InvalidConfiguration {
                    field: "quality_gate.metric",
                    reason: format!(
                        "quality gate `{}` references missing metric `{}`",
                        gate.gate_id, gate.metric
                    ),
                }
            })?;
            if metric.threshold.is_none() || metric.passed != Some(gate.passed) {
                return Err(BenchError::Integrity(format!(
                    "quality gate `{}` must match the outcome of threshold metric `{}`",
                    gate.gate_id, gate.metric
                )));
            }
        }
        if self.status == ReportStatus::Error && self.error.is_none() {
            return invalid("error", "error status requires an error object");
        }
        if self.status == ReportStatus::Passed && !self.release_eligible() {
            return invalid(
                "status",
                "passed status requires clean release evidence, M16, and complete semantic BENCH-H coverage",
            );
        }
        Ok(())
    }

    /// Returns whether this report is allowed to claim release-certification pass.
    #[must_use]
    pub fn release_eligible(&self) -> bool {
        let parameter = |name: &str| self.configuration.parameters.get(name);
        if matches!(
            parameter("release_certification_supported"),
            Some(ScalarValue::Boolean(false))
        ) {
            return false;
        }
        let unsigned_parameter = |name: &str| match parameter(name) {
            Some(ScalarValue::Unsigned(value)) => *value,
            _ => 0,
        };
        let true_parameter =
            |name: &str| matches!(parameter(name), Some(ScalarValue::Boolean(true)));
        let correct_evidence = matches!(
            parameter("evidence_kind"),
            Some(ScalarValue::String(value)) if value == EvidenceKind::ReleaseCertification.as_str()
        );
        let coverage_manifest_is_v1 = matches!(
            parameter("bench_h_coverage_manifest_version"),
            Some(ScalarValue::String(value)) if value == "contextdb.bench-h-coverage/v1"
        );
        let certification_nodes = unsigned_parameter("certification_node_count");
        let semantic_nodes = unsigned_parameter("bench_h_semantic_node_count");
        let graph_edges = unsigned_parameter("bench_h_graph_edge_count");
        let vectors = unsigned_parameter("bench_h_vector_count");
        let all_coverage_flags = [
            "bench_h_small_tier_completed",
            "bench_h_medium_tier_completed",
            "bench_h_certification_tier_completed",
            "bench_h_scenario_hot_conversation_completed",
            "bench_h_scenario_cold_autobiographical_completed",
            "bench_h_scenario_current_fact_completed",
            "bench_h_scenario_historical_fact_completed",
            "bench_h_scenario_filtered_ann_completed",
            "bench_h_scenario_hierarchy_drill_down_completed",
            "bench_h_scenario_artifact_metadata_completed",
            "bench_h_scenario_compaction_under_load_completed",
            "bench_h_scenario_backup_completed",
            "bench_h_scenario_restart_completed",
            "bench_h_e01_latency_percentiles_passed",
            "bench_h_e01_throughput_passed",
            "bench_h_e01_recovery_passed",
            "bench_h_e01_index_freshness_passed",
            "bench_h_e02_bounded_memory_passed",
            "bench_h_e02_pressure_degradation_passed",
            "bench_h_e02_no_correctness_loss_or_uncontrolled_oom_passed",
            "bench_h_e03_semantic_regression_passed",
            "bench_h_e03_privacy_regression_passed",
            "bench_h_e03_social_calibration_passed",
            "bench_h_e03_ann_exact_overlap_passed",
        ]
        .into_iter()
        .all(true_parameter);
        let mvcc_differential_bound = true_parameter("bounded_mvcc_differential_verified")
            && matches!(
                (
                    parameter("bounded_mvcc_expected_digest"),
                    parameter("bounded_mvcc_actual_digest")
                ),
                (Some(ScalarValue::String(expected)), Some(ScalarValue::String(actual)))
                    if expected.len() == 64 && expected == actual
            );
        let profile_is_qualifying = matches!(
            self.environment.build_profile,
            BuildProfile::Bench | BuildProfile::Release | BuildProfile::ReleaseSafe
        );
        let release_is_qualifying = matches!(
            self.contextdb.version_manifest.release_channel,
            ReleaseChannel::Beta | ReleaseChannel::Stable
        );
        let declared_thresholds = self.metrics.iter().any(|metric| metric.threshold.is_some());
        let all_metrics_pass = self
            .metrics
            .iter()
            .all(|metric| metric.passed != Some(false));
        let all_gates_pass =
            !self.quality_gates.is_empty() && self.quality_gates.iter().all(|gate| gate.passed);
        let required_gate_classes = [
            "M17-DIFFERENTIAL",
            "M17-SNAPSHOT",
            "M17-PRIMARY-COUNT",
            "M17-COMPACTION",
            "M17-REBUILD",
            "M17-RESTORE",
            "M17-FINAL-COUNT",
            "M17-WORKING-SET",
            "M17-TELEMETRY-PRIVACY",
            "M17-E01",
            "M17-E02",
            "M17-E03",
        ]
        .into_iter()
        .all(|required| {
            self.quality_gates
                .iter()
                .any(|gate| gate.gate_id == required && gate.passed)
        });
        let full_semantic_scenario = self.benchmark.scenario
            == "full-semantic-graph-vector-operations"
            && self.benchmark.tier == "certification-v1-full-semantic";
        correct_evidence
            && true_parameter("m16_deep_scan_passed")
            && coverage_manifest_is_v1
            && certification_nodes == semantic_nodes
            && semantic_nodes >= 10_000_000
            && graph_edges >= 100_000_000
            && vectors >= 1_000_000
            && all_coverage_flags
            && mvcc_differential_bound
            && full_semantic_scenario
            && !self.contextdb.version_manifest.source.dirty
            && profile_is_qualifying
            && release_is_qualifying
            && declared_thresholds
            && all_metrics_pass
            && all_gates_pass
            && required_gate_classes
    }

    /// Computes the only valid non-error status from evidence and gate outcomes.
    #[must_use]
    pub fn derived_status(&self) -> ReportStatus {
        if self
            .metrics
            .iter()
            .any(|metric| metric.passed == Some(false))
            || self.quality_gates.iter().any(|gate| !gate.passed)
        {
            ReportStatus::Failed
        } else if self.release_eligible() {
            ReportStatus::Passed
        } else {
            ReportStatus::ObservationOnly
        }
    }
}

fn valid_benchmark_id(value: &str) -> bool {
    value.len() == 10
        && value.starts_with("BENCH-")
        && value.as_bytes()[6..].iter().all(u8::is_ascii_digit)
}

fn valid_metric_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        reason = "benchmark contract tests use immediate failure semantics"
    )]

    use super::{
        Distribution, Metric, MetricDirection, MetricThreshold, ThresholdOperator, ThresholdValue,
    };

    #[test]
    fn distribution_uses_nearest_rank_percentiles() {
        let samples: Vec<u64> = (1..=100).collect();
        let distribution = Distribution::from_samples(&samples).expect("distribution");
        assert_eq!(distribution.p50, Some(50.0));
        assert_eq!(distribution.p95, Some(95.0));
        assert_eq!(distribution.p99, Some(99.0));
    }

    #[test]
    fn scalar_threshold_is_bound_to_outcome() {
        let metric = Metric::scalar(
            "correctness.digest_equal",
            "boolean-as-integer",
            MetricDirection::Target,
            1.0,
        )
        .with_threshold(MetricThreshold {
            operator: ThresholdOperator::Eq,
            value: ThresholdValue::Scalar(1.0),
        })
        .expect("threshold");
        assert_eq!(metric.passed, Some(true));
    }
}
