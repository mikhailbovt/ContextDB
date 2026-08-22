//! Aggregation of raw native outcomes into canonical benchmark-result v1 JSON.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::digest::sha256_hex;
use crate::report::{
    Artifact, BenchmarkFamily, BenchmarkIdentity, BenchmarkResult, BuildManifest, BuildProfile,
    ContextDbIdentity, Distribution, Environment, EvidenceKind, FeatureProfile, FormatVersion,
    Metric, MetricDirection, MetricObserved, MetricThreshold, MigrationManifest, QualityGate,
    ReleaseChannel, ReportStatus, RunConfiguration, ScalarValue, SourceManifest,
    StorageBackendManifest, ThresholdOperator, ThresholdValue, VersionManifest,
};
use crate::{BENCHMARK_RESULT_SCHEMA_VERSION, BenchError, NativeRunOutcome, Result};

/// Host/build metadata captured immediately around a native run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRunMetadata {
    /// UTC RFC3339 run start.
    pub started_at: String,
    /// UTC RFC3339 run finish.
    pub finished_at: String,
    /// Exact Git commit.
    pub git_commit: String,
    /// Dirty worktree marker.
    pub dirty: bool,
    /// Product release channel.
    pub release_channel: ReleaseChannel,
    /// Build profile.
    pub build_profile: BuildProfile,
    /// Operating system.
    pub os: String,
    /// OS version.
    pub os_version: String,
    /// Optional kernel release.
    pub kernel: Option<String>,
    /// Architecture.
    pub architecture: String,
    /// CPU model or not-measured marker.
    pub cpu: String,
    /// Logical cores.
    pub logical_cores: u32,
    /// Physical memory or one with limitation.
    pub memory_bytes: u64,
    /// Storage descriptor.
    pub storage: String,
    /// Filesystem descriptor.
    pub filesystem: String,
    /// rustc version.
    pub rustc: String,
    /// cargo version.
    pub cargo: String,
    /// Rust compilation target.
    pub target: String,
}

/// BENCH-H coverage derived by an in-crate evaluator from measured rows.
///
/// This type is deliberately crate-private. There is no public constructor which can turn caller
/// supplied booleans into release evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BenchHCoverageManifest {
    /// Canonical semantic nodes/claims exercised by the certification dataset.
    pub(crate) semantic_nodes: u64,
    /// Typed semantic graph edges exercised by the certification dataset.
    pub(crate) graph_edges: u64,
    /// Full-precision vectors exercised by exact and ANN paths.
    pub(crate) vectors: u64,
    /// RFC small tier completed on the full stack.
    pub(crate) small_tier_completed: bool,
    /// RFC medium tier completed on the full stack.
    pub(crate) medium_tier_completed: bool,
    /// ERRATA E-009 v1 certification tier completed on the full stack.
    pub(crate) certification_tier_completed: bool,
    /// Hot conversation recall scenario completed.
    pub(crate) hot_conversation_completed: bool,
    /// Cold autobiographical recall scenario completed.
    pub(crate) cold_autobiographical_completed: bool,
    /// Current-fact scenario completed.
    pub(crate) current_fact_completed: bool,
    /// Historical-fact scenario completed.
    pub(crate) historical_fact_completed: bool,
    /// Filtered ANN scenario completed.
    pub(crate) filtered_ann_completed: bool,
    /// Hierarchy drill-down scenario completed.
    pub(crate) hierarchy_drill_down_completed: bool,
    /// Artifact metadata scenario completed.
    pub(crate) artifact_metadata_completed: bool,
    /// Compaction-under-load scenario completed.
    pub(crate) compaction_under_load_completed: bool,
    /// Backup scenario completed.
    pub(crate) backup_completed: bool,
    /// Restart scenario completed.
    pub(crate) restart_completed: bool,
    /// M17-E01 latency percentiles met the bound target matrix.
    pub(crate) e01_latency_percentiles_passed: bool,
    /// M17-E01 throughput met the bound target matrix.
    pub(crate) e01_throughput_passed: bool,
    /// M17-E01 recovery met the bound target matrix.
    pub(crate) e01_recovery_passed: bool,
    /// M17-E01 index freshness met the bound target matrix.
    pub(crate) e01_index_freshness_passed: bool,
    /// M17-E02 memory stayed within the declared bound.
    pub(crate) e02_bounded_memory_passed: bool,
    /// M17-E02 pressure produced explicit partial/degraded results.
    pub(crate) e02_pressure_degradation_passed: bool,
    /// M17-E02 avoided correctness loss and uncontrolled OOM.
    pub(crate) e02_no_correctness_loss_or_uncontrolled_oom_passed: bool,
    /// M17-E03 frozen semantic floors did not regress.
    pub(crate) e03_semantic_regression_passed: bool,
    /// M17-E03 frozen privacy floors did not regress.
    pub(crate) e03_privacy_regression_passed: bool,
    /// M17-E03 frozen social-calibration floors did not regress.
    pub(crate) e03_social_calibration_passed: bool,
    /// M17-E03 frozen ANN/exact-overlap floor did not regress.
    pub(crate) e03_ann_exact_overlap_passed: bool,
}

impl BenchHCoverageManifest {
    /// Fail-closed manifest for runs which do not exercise the full semantic stack.
    #[must_use]
    pub(crate) const fn unmeasured() -> Self {
        Self {
            semantic_nodes: 0,
            graph_edges: 0,
            vectors: 0,
            small_tier_completed: false,
            medium_tier_completed: false,
            certification_tier_completed: false,
            hot_conversation_completed: false,
            cold_autobiographical_completed: false,
            current_fact_completed: false,
            historical_fact_completed: false,
            filtered_ann_completed: false,
            hierarchy_drill_down_completed: false,
            artifact_metadata_completed: false,
            compaction_under_load_completed: false,
            backup_completed: false,
            restart_completed: false,
            e01_latency_percentiles_passed: false,
            e01_throughput_passed: false,
            e01_recovery_passed: false,
            e01_index_freshness_passed: false,
            e02_bounded_memory_passed: false,
            e02_pressure_degradation_passed: false,
            e02_no_correctness_loss_or_uncontrolled_oom_passed: false,
            e03_semantic_regression_passed: false,
            e03_privacy_regression_passed: false,
            e03_social_calibration_passed: false,
            e03_ann_exact_overlap_passed: false,
        }
    }

    /// Whether derived coverage reaches the RFC/ERRATA lower bounds and every exit class.
    #[must_use]
    pub const fn is_v1_complete(self) -> bool {
        self.semantic_nodes >= 10_000_000
            && self.graph_edges >= 100_000_000
            && self.vectors >= 1_000_000
            && self.small_tier_completed
            && self.medium_tier_completed
            && self.certification_tier_completed
            && self.hot_conversation_completed
            && self.cold_autobiographical_completed
            && self.current_fact_completed
            && self.historical_fact_completed
            && self.filtered_ann_completed
            && self.hierarchy_drill_down_completed
            && self.artifact_metadata_completed
            && self.compaction_under_load_completed
            && self.backup_completed
            && self.restart_completed
            && self.e01_latency_percentiles_passed
            && self.e01_throughput_passed
            && self.e01_recovery_passed
            && self.e01_index_freshness_passed
            && self.e02_bounded_memory_passed
            && self.e02_pressure_degradation_passed
            && self.e02_no_correctness_loss_or_uncontrolled_oom_passed
            && self.e03_semantic_regression_passed
            && self.e03_privacy_regression_passed
            && self.e03_social_calibration_passed
            && self.e03_ann_exact_overlap_passed
    }
}

pub(crate) fn insert_coverage_parameters(
    parameters: &mut BTreeMap<String, ScalarValue>,
    coverage: BenchHCoverageManifest,
) {
    parameters.insert(
        "bench_h_coverage_manifest_version".to_owned(),
        ScalarValue::String("contextdb.bench-h-coverage/v1".to_owned()),
    );
    for (name, value) in [
        ("bench_h_semantic_node_count", coverage.semantic_nodes),
        ("bench_h_graph_edge_count", coverage.graph_edges),
        ("bench_h_vector_count", coverage.vectors),
    ] {
        parameters.insert(name.to_owned(), ScalarValue::Unsigned(value));
    }
    for (name, value) in [
        (
            "bench_h_small_tier_completed",
            coverage.small_tier_completed,
        ),
        (
            "bench_h_medium_tier_completed",
            coverage.medium_tier_completed,
        ),
        (
            "bench_h_certification_tier_completed",
            coverage.certification_tier_completed,
        ),
        (
            "bench_h_scenario_hot_conversation_completed",
            coverage.hot_conversation_completed,
        ),
        (
            "bench_h_scenario_cold_autobiographical_completed",
            coverage.cold_autobiographical_completed,
        ),
        (
            "bench_h_scenario_current_fact_completed",
            coverage.current_fact_completed,
        ),
        (
            "bench_h_scenario_historical_fact_completed",
            coverage.historical_fact_completed,
        ),
        (
            "bench_h_scenario_filtered_ann_completed",
            coverage.filtered_ann_completed,
        ),
        (
            "bench_h_scenario_hierarchy_drill_down_completed",
            coverage.hierarchy_drill_down_completed,
        ),
        (
            "bench_h_scenario_artifact_metadata_completed",
            coverage.artifact_metadata_completed,
        ),
        (
            "bench_h_scenario_compaction_under_load_completed",
            coverage.compaction_under_load_completed,
        ),
        (
            "bench_h_scenario_backup_completed",
            coverage.backup_completed,
        ),
        (
            "bench_h_scenario_restart_completed",
            coverage.restart_completed,
        ),
        (
            "bench_h_e01_latency_percentiles_passed",
            coverage.e01_latency_percentiles_passed,
        ),
        (
            "bench_h_e01_throughput_passed",
            coverage.e01_throughput_passed,
        ),
        ("bench_h_e01_recovery_passed", coverage.e01_recovery_passed),
        (
            "bench_h_e01_index_freshness_passed",
            coverage.e01_index_freshness_passed,
        ),
        (
            "bench_h_e02_bounded_memory_passed",
            coverage.e02_bounded_memory_passed,
        ),
        (
            "bench_h_e02_pressure_degradation_passed",
            coverage.e02_pressure_degradation_passed,
        ),
        (
            "bench_h_e02_no_correctness_loss_or_uncontrolled_oom_passed",
            coverage.e02_no_correctness_loss_or_uncontrolled_oom_passed,
        ),
        (
            "bench_h_e03_semantic_regression_passed",
            coverage.e03_semantic_regression_passed,
        ),
        (
            "bench_h_e03_privacy_regression_passed",
            coverage.e03_privacy_regression_passed,
        ),
        (
            "bench_h_e03_social_calibration_passed",
            coverage.e03_social_calibration_passed,
        ),
        (
            "bench_h_e03_ann_exact_overlap_passed",
            coverage.e03_ann_exact_overlap_passed,
        ),
    ] {
        parameters.insert(name.to_owned(), ScalarValue::Boolean(value));
    }
}

/// Aggregates a raw persistent outcome into strict canonical result DTOs.
pub fn build_native_report(
    outcome: &NativeRunOutcome,
    mut metadata: NativeRunMetadata,
    raw_artifact_uri: impl Into<String>,
    raw_artifact_bytes: &[u8],
) -> Result<BenchmarkResult> {
    if outcome.bounded_mvcc_differential_verified
        && (outcome.bounded_mvcc_expected_digest != outcome.bounded_mvcc_actual_digest
            || outcome.full_mvcc_differential_records == 0)
    {
        return Err(BenchError::Integrity(
            "verified MVCC differential has unequal digests or zero coverage".to_owned(),
        ));
    }
    metadata.release_channel = ReleaseChannel::Development;
    let contextdb = ContextDbIdentity::new(version_manifest(&metadata))?;
    let coverage = BenchHCoverageManifest::unmeasured();
    let mut parameters = BTreeMap::from([
        (
            "evidence_kind".to_owned(),
            ScalarValue::String(EvidenceKind::NativeMeasuredDevelopment.as_str().to_owned()),
        ),
        (
            "m16_deep_scan_passed".to_owned(),
            ScalarValue::Boolean(false),
        ),
        (
            "release_certification_supported".to_owned(),
            ScalarValue::Boolean(false),
        ),
        (
            "certification_node_count".to_owned(),
            ScalarValue::Unsigned(coverage.semantic_nodes),
        ),
        (
            "records".to_owned(),
            ScalarValue::Unsigned(outcome.config.records),
        ),
        (
            "oracle_mode".to_owned(),
            ScalarValue::String(outcome.oracle_mode.as_str().to_owned()),
        ),
        (
            "full_mvcc_differential_records".to_owned(),
            ScalarValue::Unsigned(outcome.full_mvcc_differential_records),
        ),
        (
            "bounded_mvcc_expected_digest".to_owned(),
            ScalarValue::String(outcome.bounded_mvcc_expected_digest.clone()),
        ),
        (
            "bounded_mvcc_actual_digest".to_owned(),
            ScalarValue::String(outcome.bounded_mvcc_actual_digest.clone()),
        ),
        (
            "bounded_mvcc_differential_verified".to_owned(),
            ScalarValue::Boolean(outcome.bounded_mvcc_differential_verified),
        ),
        (
            "full_mvcc_oracle_estimated_bytes".to_owned(),
            ScalarValue::Unsigned(outcome.full_mvcc_oracle_estimated_bytes),
        ),
        (
            "sampled_recall_queries".to_owned(),
            ScalarValue::Unsigned(outcome.sampled_recall_queries),
        ),
        (
            "batch_records".to_owned(),
            ScalarValue::Unsigned(outcome.config.batch_records),
        ),
        (
            "value_bytes".to_owned(),
            ScalarValue::Unsigned(
                u64::try_from(outcome.config.value_bytes)
                    .map_err(|_| BenchError::ArithmeticOverflow("report value bytes"))?,
            ),
        ),
        (
            "provisional_hot_conversation_p95_target_ns".to_owned(),
            ScalarValue::Unsigned(120_000_000),
        ),
        (
            "provisional_exact_graph_p95_target_ns".to_owned(),
            ScalarValue::Unsigned(150_000_000),
        ),
        (
            "provisional_hybrid_p95_target_ns".to_owned(),
            ScalarValue::Unsigned(400_000_000),
        ),
        (
            "provisional_bootstrap_p95_target_ns".to_owned(),
            ScalarValue::Unsigned(200_000_000),
        ),
        ("cold_cache_evicted".to_owned(), ScalarValue::Boolean(false)),
        (
            "real_modality_models_executed".to_owned(),
            ScalarValue::Boolean(false),
        ),
    ]);
    insert_coverage_parameters(&mut parameters, coverage);
    parameters.insert(
        "workload_manifest_sha256".to_owned(),
        ScalarValue::String(outcome.workload_manifest_sha256.clone()),
    );
    let budgets = BTreeMap::from([
        (
            "working_buffer_budget_bytes".to_owned(),
            ScalarValue::Unsigned(outcome.config.working_buffer_budget_bytes),
        ),
        (
            "estimated_peak_harness_buffer_bytes".to_owned(),
            ScalarValue::Unsigned(outcome.estimated_peak_harness_buffer_bytes),
        ),
        (
            "process_rss_budget_bytes".to_owned(),
            ScalarValue::Unsigned(outcome.config.process_rss_budget_bytes),
        ),
        (
            "telemetry_max_series".to_owned(),
            ScalarValue::Unsigned(
                u64::try_from(outcome.telemetry.max_series)
                    .map_err(|_| BenchError::ArithmeticOverflow("telemetry max series"))?,
            ),
        ),
        (
            "telemetry_max_values_per_dimension".to_owned(),
            ScalarValue::Unsigned(
                u64::try_from(outcome.telemetry.max_values_per_dimension)
                    .map_err(|_| BenchError::ArithmeticOverflow("telemetry value cardinality"))?,
            ),
        ),
        (
            "telemetry_max_samples_per_series".to_owned(),
            ScalarValue::Unsigned(
                u64::try_from(outcome.telemetry.max_samples_per_series)
                    .map_err(|_| BenchError::ArithmeticOverflow("telemetry sample retention"))?,
            ),
        ),
    ]);
    let mut metrics = native_metrics(outcome)?;
    let quality_gates = exact_quality_gates(outcome);
    let mut limitations = outcome.limitations.clone();
    if outcome.process_rss_samples_bytes.is_empty() {
        limitations.push(
            "Process RSS was unavailable on this platform; the declared RSS budget is not evaluated."
                .to_owned(),
        );
    }
    limitations.push(
        "The native storage runner is development-only and has no release-certification promotion input."
            .to_owned(),
    );
    if !coverage.is_v1_complete() {
        limitations.push(format!(
            "Full BENCH-H coverage is incomplete: semantic_nodes={}, graph_edges={}, vectors={}; every required scenario and M17-E01/E02/E03 class must also pass.",
            coverage.semantic_nodes,
            coverage.graph_edges,
            coverage.vectors
        ));
    }
    limitations.push(
        "M16 deep security scan is not bound to this development evidence; M17 release status remains open."
            .to_owned(),
    );
    let all_exact = quality_gates.iter().all(|gate| gate.passed)
        && metrics.iter().all(|metric| metric.passed != Some(false));
    let initial_status = if all_exact {
        ReportStatus::ObservationOnly
    } else {
        ReportStatus::Failed
    };
    let mut report = BenchmarkResult {
        schema_version: BENCHMARK_RESULT_SCHEMA_VERSION.to_owned(),
        run_id: Uuid::now_v7(),
        started_at: metadata.started_at.clone(),
        finished_at: metadata.finished_at.clone(),
        status: initial_status,
        benchmark: BenchmarkIdentity {
            id: "BENCH-0017".to_owned(),
            family: BenchmarkFamily::BenchH,
            name: "M17 performance scale and operations".to_owned(),
            version: crate::BENCH_H_WORKLOAD_VERSION.to_owned(),
            dataset_version: outcome.config.workload_version.clone(),
            scenario: "native-redb-storage-operations".to_owned(),
            tier: outcome.config.tier.as_str().to_owned(),
        },
        contextdb,
        environment: Environment {
            os: metadata.os,
            os_version: metadata.os_version,
            kernel: metadata.kernel,
            architecture: metadata.architecture,
            cpu: metadata.cpu,
            logical_cores: metadata.logical_cores,
            memory_bytes: metadata.memory_bytes.max(1),
            storage: metadata.storage,
            filesystem: metadata.filesystem,
            rustc: metadata.rustc,
            cargo: metadata.cargo,
            storage_backend: "redb".to_owned(),
            storage_backend_version: Some("4.1.0".to_owned()),
            storage_configuration_digest: Some(sha256_hex(b"redb-v4-sync-immediate-v1")),
            build_profile: metadata.build_profile,
        },
        configuration: RunConfiguration {
            seed: outcome.config.seed,
            features: vec![
                "exact-recall".to_owned(),
                "portable-backup".to_owned(),
                "snapshot-isolation".to_owned(),
            ],
            budgets,
            parameters,
            index_watermarks: outcome.watermarks.clone(),
        },
        metrics: std::mem::take(&mut metrics),
        quality_gates,
        artifacts: vec![Artifact {
            kind: "raw-native-outcome".to_owned(),
            uri: raw_artifact_uri.into(),
            sha256: sha256_hex(raw_artifact_bytes),
        }],
        limitations,
        error: None,
    };
    report.status = report.derived_status();
    report.validate()?;
    Ok(report)
}

pub(crate) fn version_manifest(metadata: &NativeRunMetadata) -> VersionManifest {
    let formats = BTreeMap::from([
        (
            "benchmark_result".to_owned(),
            FormatVersion {
                writer: 1,
                read_min: 1,
                read_max: 1,
                required_features: Vec::new(),
            },
        ),
        (
            "journal_backup".to_owned(),
            FormatVersion {
                writer: 1,
                read_min: 1,
                read_max: 1,
                required_features: Vec::new(),
            },
        ),
    ]);
    VersionManifest {
        schema_version: "contextdb.version-manifest/v1".to_owned(),
        product_version: env!("CARGO_PKG_VERSION").to_owned(),
        release_channel: metadata.release_channel,
        source: SourceManifest {
            git_commit: metadata.git_commit.clone(),
            dirty: metadata.dirty,
            repository: Some("https://github.com/mikhailbovt/ContextDB".to_owned()),
            rfc_revision: "RFC-0001-v0.3+ERRATA-0001".to_owned(),
            errata: vec!["ERRATA-0001".to_owned()],
            adrs: (1..=6).map(|index| format!("ADR-{index:04}")).collect(),
        },
        build: BuildManifest {
            timestamp: metadata.started_at.clone(),
            rustc: metadata.rustc.clone(),
            cargo: metadata.cargo.clone(),
            target: metadata.target.clone(),
            profile: metadata.build_profile,
            reproducible: false,
            builder: Some("contextdb-bench-native-runner".to_owned()),
        },
        formats,
        feature_profile: FeatureProfile::Research,
        features: vec![
            "m17-benchmark-harness".to_owned(),
            "portable-journal-backup".to_owned(),
            "redb".to_owned(),
        ],
        storage_backend: Some(StorageBackendManifest {
            name: "redb".to_owned(),
            version: "4.1.0".to_owned(),
            configuration_digest: Some(sha256_hex(b"redb-v4-sync-immediate-v1")),
        }),
        migration: Some(MigrationManifest {
            applied: Vec::new(),
            rollback_supported: true,
        }),
    }
}

fn native_metrics(outcome: &NativeRunOutcome) -> Result<Vec<Metric>> {
    let mut metrics = vec![
        distribution_metric(
            "ingest.commit_latency_ns",
            &outcome.ingest_latency_ns,
            MetricDirection::LowerIsBetter,
        )?,
        distribution_metric(
            "recall.cold_latency_ns",
            &outcome.cold_recall_latency_ns,
            MetricDirection::LowerIsBetter,
        )?,
        distribution_metric(
            "recall.warm_latency_ns",
            &outcome.warm_recall_latency_ns,
            MetricDirection::LowerIsBetter,
        )?,
        distribution_metric(
            "recall.filtered_latency_ns",
            &outcome.filtered_recall_latency_ns,
            MetricDirection::LowerIsBetter,
        )?,
        distribution_metric(
            "mixed.read_latency_ns",
            &outcome.mixed_read_latency_ns,
            MetricDirection::LowerIsBetter,
        )?,
        distribution_metric(
            "mixed.write_latency_ns",
            &outcome.mixed_write_latency_ns,
            MetricDirection::LowerIsBetter,
        )?,
        distribution_metric(
            "journal.ingest_latency_ns",
            &outcome.journal.ingest_latency_ns,
            MetricDirection::LowerIsBetter,
        )?,
        Metric::scalar(
            "ingest.operations_per_second",
            "operations_per_second",
            MetricDirection::HigherIsBetter,
            rate(outcome.config.records, outcome.ingest_total_ns),
        ),
        Metric::scalar(
            "ingest.bytes_per_second",
            "bytes_per_second",
            MetricDirection::HigherIsBetter,
            rate(outcome.ingested_bytes, outcome.ingest_total_ns),
        ),
        Metric::scalar(
            "compaction.foreground_latency_ns",
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            outcome.compaction_latency_ns as f64,
        ),
        Metric::scalar(
            "compaction.background_latency_ns",
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            outcome.background_compaction_ns as f64,
        ),
        Metric::scalar(
            "rebuild.latency_ns",
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            outcome.rebuild_latency_ns as f64,
        ),
        Metric::scalar(
            "backup.latency_ns",
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            outcome.journal.backup_latency_ns as f64,
        ),
        Metric::scalar(
            "restore.latency_ns",
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            outcome.journal.restore_latency_ns as f64,
        ),
        Metric::scalar(
            "recovery.reopen_latency_ns",
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            outcome.journal.reopen_latency_ns as f64,
        ),
        Metric::scalar(
            "run.total_elapsed_ns",
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            outcome.total_elapsed_ns as f64,
        ),
        exact_gate_metric(
            "correctness.oracle_digest_equal",
            outcome.oracle_logical_digest == outcome.native_logical_digest,
        )?,
        exact_gate_metric(
            "correctness.snapshot_consistent",
            outcome.snapshot_consistent,
        )?,
        exact_gate_metric(
            "correctness.primary_count_equal",
            outcome.primary_count_equal,
        )?,
        exact_gate_metric(
            "correctness.bounded_mvcc_differential_equal",
            outcome.bounded_mvcc_differential_verified,
        )?,
        exact_gate_metric("correctness.rebuild_equal", outcome.rebuild_equal)?,
        exact_gate_metric(
            "correctness.compaction_preserved",
            outcome.compaction_preserved,
        )?,
        exact_gate_metric("correctness.reopen_preserved", outcome.reopen_preserved)?,
        exact_gate_metric("correctness.restore_equal", outcome.journal.restore_equal)?,
        exact_gate_metric(
            "correctness.journal_reopen_equal",
            outcome.journal.reopen_equal,
        )?,
        exact_gate_metric(
            "correctness.restore_and_reopen_equal",
            outcome.journal.restore_equal && outcome.journal.reopen_equal,
        )?,
        exact_gate_metric(
            "correctness.final_record_count_equal",
            outcome.final_record_count_equal,
        )?,
        exact_gate_metric(
            "working_set.budget_enforced",
            outcome.working_set_budget_enforced,
        )?,
        Metric::scalar(
            "working_set.estimated_harness_buffer_bytes",
            "bytes",
            MetricDirection::LowerIsBetter,
            outcome.estimated_peak_harness_buffer_bytes as f64,
        )
        .with_threshold(MetricThreshold {
            operator: ThresholdOperator::Lte,
            value: ThresholdValue::Scalar(outcome.config.working_buffer_budget_bytes as f64),
        })?,
        Metric::scalar(
            "durability.synchronized_acknowledgement_bps",
            "basis_points",
            MetricDirection::Target,
            synchronized_acknowledgement_bps(outcome),
        )
        .with_threshold(MetricThreshold {
            operator: ThresholdOperator::Eq,
            value: ThresholdValue::Scalar(10_000.0),
        })?,
        Metric::scalar(
            "telemetry.payloads_included",
            "boolean_as_integer",
            MetricDirection::Target,
            f64::from(outcome.telemetry.payloads_included),
        )
        .with_threshold(MetricThreshold {
            operator: ThresholdOperator::Eq,
            value: ThresholdValue::Scalar(0.0),
        })?,
        Metric::scalar(
            "telemetry.series_count",
            "series",
            MetricDirection::LowerIsBetter,
            outcome.telemetry.series.len() as f64,
        )
        .with_threshold(MetricThreshold {
            operator: ThresholdOperator::Lte,
            value: ThresholdValue::Scalar(outcome.telemetry.max_series as f64),
        })?,
    ];
    if !outcome.process_rss_samples_bytes.is_empty() {
        let distribution = Distribution::from_samples(&outcome.process_rss_samples_bytes)?;
        let maximum = distribution.max.ok_or_else(|| {
            BenchError::Integrity("nonempty RSS distribution omitted maximum".to_owned())
        })?;
        metrics.push(Metric::distribution(
            "memory.phase_boundary_rss_bytes",
            "bytes",
            MetricDirection::LowerIsBetter,
            distribution,
        ));
        metrics.push(
            Metric::scalar(
                "memory.phase_boundary_rss_max_bytes",
                "bytes",
                MetricDirection::LowerIsBetter,
                maximum,
            )
            .with_threshold(MetricThreshold {
                operator: ThresholdOperator::Lte,
                value: ThresholdValue::Scalar(outcome.config.process_rss_budget_bytes as f64),
            })?,
        );
    }
    for (phase, latency) in &outcome.phase_latency_ns {
        metrics.push(Metric::scalar(
            format!("phase.{phase}.latency_ns"),
            "nanoseconds",
            MetricDirection::LowerIsBetter,
            *latency as f64,
        ));
    }
    for point in &outcome.scale_points {
        let distribution = Distribution::from_samples(&point.recall_latency_ns)?;
        metrics.push(Metric {
            name: format!("scaling.records_{}.recall_latency_ns", point.records),
            unit: "nanoseconds".to_owned(),
            direction: MetricDirection::LowerIsBetter,
            observed: MetricObserved::Distribution(distribution),
            threshold: None,
            passed: None,
        });
    }
    Ok(metrics)
}

fn exact_quality_gates(outcome: &NativeRunOutcome) -> Vec<QualityGate> {
    [
        (
            "M17-DIFFERENTIAL",
            "correctness.oracle_digest_equal",
            outcome.oracle_logical_digest == outcome.native_logical_digest,
        ),
        (
            "M17-SNAPSHOT",
            "correctness.snapshot_consistent",
            outcome.snapshot_consistent,
        ),
        (
            "M17-PRIMARY-COUNT",
            "correctness.primary_count_equal",
            outcome.primary_count_equal,
        ),
        (
            "M17-COMPACTION",
            "correctness.compaction_preserved",
            outcome.compaction_preserved,
        ),
        (
            "M17-REBUILD",
            "correctness.rebuild_equal",
            outcome.rebuild_equal,
        ),
        (
            "M17-RESTORE",
            "correctness.restore_and_reopen_equal",
            outcome.journal.restore_equal && outcome.journal.reopen_equal,
        ),
        (
            "M17-FINAL-COUNT",
            "correctness.final_record_count_equal",
            outcome.final_record_count_equal,
        ),
        (
            "M17-WORKING-SET",
            "working_set.budget_enforced",
            outcome.working_set_budget_enforced,
        ),
        (
            "M17-TELEMETRY-PRIVACY",
            "telemetry.payloads_included",
            !outcome.telemetry.payloads_included,
        ),
    ]
    .into_iter()
    .map(|(gate_id, metric, passed)| QualityGate {
        gate_id: gate_id.to_owned(),
        metric: metric.to_owned(),
        passed,
        note: None,
    })
    .collect()
}

fn exact_gate_metric(name: &'static str, passed: bool) -> Result<Metric> {
    Metric::scalar(
        name,
        "boolean_as_integer",
        MetricDirection::Target,
        f64::from(passed),
    )
    .with_threshold(MetricThreshold {
        operator: ThresholdOperator::Eq,
        value: ThresholdValue::Scalar(1.0),
    })
}

fn distribution_metric(
    name: &'static str,
    samples: &[u64],
    direction: MetricDirection,
) -> Result<Metric> {
    Ok(Metric::distribution(
        name,
        "nanoseconds",
        direction,
        Distribution::from_samples(samples)?,
    ))
}

fn rate(count: u64, elapsed_ns: u64) -> f64 {
    count as f64 * 1_000_000_000.0 / elapsed_ns.max(1) as f64
}

fn synchronized_acknowledgement_bps(outcome: &NativeRunOutcome) -> f64 {
    let total_ingest_commits = u64::try_from(outcome.ingest_latency_ns.len()).unwrap_or(u64::MAX);
    let total = total_ingest_commits.saturating_add(outcome.config.journal_observations);
    let synchronized = outcome
        .synchronized_ingest_commits
        .saturating_add(outcome.journal.synchronized_acknowledgements);
    if total == 0 {
        return 0.0;
    }
    synchronized as f64 * 10_000.0 / total as f64
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "canonical report tests use immediate failure semantics"
    )]

    use super::{NativeRunMetadata, build_native_report};
    use crate::report::{
        BuildProfile, ContextDbIdentity, EvidenceKind, ReleaseChannel, ReportStatus, ScalarValue,
    };
    use crate::runner::run_native_redb_at;
    use crate::telemetry::TelemetryBudget;
    use crate::workload::BenchConfig;

    fn metadata() -> NativeRunMetadata {
        NativeRunMetadata {
            started_at: "2026-08-12T00:00:00Z".to_owned(),
            finished_at: "2026-08-12T00:00:01Z".to_owned(),
            git_commit: "0".repeat(40),
            dirty: true,
            release_channel: ReleaseChannel::Development,
            build_profile: BuildProfile::Test,
            os: "windows".to_owned(),
            os_version: "test".to_owned(),
            kernel: None,
            architecture: "x86_64".to_owned(),
            cpu: "test".to_owned(),
            logical_cores: 1,
            memory_bytes: 1,
            storage: "temporary".to_owned(),
            filesystem: "temporary".to_owned(),
            rustc: "rustc test".to_owned(),
            cargo: "cargo test".to_owned(),
            target: "x86_64-pc-windows-msvc".to_owned(),
        }
    }

    #[test]
    fn bounded_native_report_cannot_claim_release_pass() {
        let directory = tempfile::tempdir().expect("tempdir");
        let outcome = run_native_redb_at(
            BenchConfig::smoke(),
            TelemetryBudget::default(),
            directory.path(),
        )
        .expect("native run");
        let raw = serde_json::to_vec(&outcome).expect("raw JSON");
        let report = build_native_report(&outcome, metadata(), "raw.json", &raw).expect("report");
        assert_eq!(report.status, ReportStatus::ObservationOnly);
        assert!(!report.release_eligible());
        report.validate().expect("valid report");
    }

    #[test]
    fn metadata_flips_cannot_certify_a_storage_shaped_run() {
        let directory = tempfile::tempdir().expect("tempdir");
        let outcome = run_native_redb_at(
            BenchConfig::smoke(),
            TelemetryBudget::default(),
            directory.path(),
        )
        .expect("native run");
        let raw = serde_json::to_vec(&outcome).expect("raw JSON");
        let mut report =
            build_native_report(&outcome, metadata(), "raw.json", &raw).expect("report");

        report.configuration.parameters.insert(
            "evidence_kind".to_owned(),
            ScalarValue::String(EvidenceKind::ReleaseCertification.as_str().to_owned()),
        );
        report.configuration.parameters.insert(
            "m16_deep_scan_passed".to_owned(),
            ScalarValue::Boolean(true),
        );
        report.configuration.parameters.insert(
            "certification_node_count".to_owned(),
            ScalarValue::Unsigned(10_000_000),
        );
        report.contextdb.version_manifest.source.dirty = false;
        report.contextdb.version_manifest.release_channel = ReleaseChannel::Beta;
        report.contextdb = ContextDbIdentity::new(report.contextdb.version_manifest.clone())
            .expect("updated identity");
        report.environment.build_profile = BuildProfile::Bench;
        report.benchmark.scenario = "full-semantic-graph-vector-operations".to_owned();
        report.benchmark.tier = "certification-v1-full-semantic".to_owned();

        assert!(!report.release_eligible());
        assert!(matches!(
            report
                .configuration
                .parameters
                .get("bench_h_small_tier_completed"),
            Some(ScalarValue::Boolean(false))
        ));
    }

    #[test]
    fn release_metadata_cannot_certify_the_storage_adapter() {
        let directory = tempfile::tempdir().expect("tempdir");
        let outcome = run_native_redb_at(
            BenchConfig::smoke(),
            TelemetryBudget::default(),
            directory.path(),
        )
        .expect("native run");
        let raw = serde_json::to_vec(&outcome).expect("raw JSON");
        let mut release_metadata = metadata();
        release_metadata.dirty = false;
        release_metadata.release_channel = ReleaseChannel::Beta;
        release_metadata.build_profile = BuildProfile::Bench;
        let report =
            build_native_report(&outcome, release_metadata, "raw.json", &raw).expect("report");

        assert_eq!(report.status, ReportStatus::ObservationOnly);
        assert!(!report.release_eligible());
        assert_eq!(report.benchmark.scenario, "native-redb-storage-operations");
        assert_eq!(
            report.contextdb.version_manifest.release_channel,
            ReleaseChannel::Development
        );
    }

    #[test]
    fn mvcc_gate_uses_verified_outcome_not_nonzero_record_count() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut outcome = run_native_redb_at(
            BenchConfig::smoke(),
            TelemetryBudget::default(),
            directory.path(),
        )
        .expect("native run");
        assert!(outcome.full_mvcc_differential_records > 0);
        outcome.bounded_mvcc_differential_verified = false;
        let raw = serde_json::to_vec(&outcome).expect("raw JSON");
        let report = build_native_report(&outcome, metadata(), "raw.json", &raw).expect("report");
        let gate = report
            .metrics
            .iter()
            .find(|metric| metric.name == "correctness.bounded_mvcc_differential_equal")
            .expect("MVCC gate metric");
        assert_eq!(gate.passed, Some(false));
        assert_eq!(report.status, ReportStatus::Failed);
    }
}
