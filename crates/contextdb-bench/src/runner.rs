//! Native persistent BENCH-H execution against the redb storage adapter.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::Path;
use std::thread;
use std::time::Instant;

use contextdb_storage::{
    CompactRequest, Durability, Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine,
    WriteTransaction,
};
use contextdb_storage_memory::MemoryStorage;
use contextdb_storage_redb::RedbStorage;
use serde::{Deserialize, Serialize};

use crate::digest::hex;
use crate::journal_ops::{JournalOperationsOutcome, run_journal_operations};
use crate::telemetry::{
    BackendClass, DeploymentClass, ErrorClass, IndexClass, IntentClass, OperationClass,
    OperationStatus, RecordClass, TelemetryBudget, TelemetryExport, TelemetryLabels,
    TelemetryMetric, TelemetryRecorder,
};
use crate::workload::{BenchConfig, DeterministicDataset, hash_framed};
use crate::{BenchError, Result};

const PRIMARY_SPACE: &str = "bench_primary_v1";
const DERIVED_SPACE: &str = "bench_derived_v1";
const RUNTIME_SPACE: &str = "bench_runtime_v1";
const SNAPSHOT_MARKER: &[u8] = b"snapshot/marker";
const FULL_MVCC_PROBE_RECORDS: u64 = 4_096;
const ESTIMATED_MVCC_RECORD_BYTES: u64 = 512;
const ESTIMATED_SCAN_RECORD_OVERHEAD_BYTES: u64 = 160;

/// Correctness-oracle strategy selected before any scale allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleMode {
    /// Full clone-on-write MVCC oracle fits the declared buffer budget.
    FullMvccInMemory,
    /// Full dataset digest is streamed while full MVCC is checked on a bounded probe.
    StreamingWithBoundedMvccProbe,
}

impl OracleMode {
    /// Stable report parameter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullMvccInMemory => "full_mvcc_in_memory",
            Self::StreamingWithBoundedMvccProbe => "streaming_with_bounded_mvcc_probe",
        }
    }
}

/// Allocation admission computed before opening the native database.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScaleAdmission {
    /// Oracle selected without allocating clone-on-write history.
    pub oracle_mode: OracleMode,
    /// Records covered by a full in-memory MVCC differential.
    pub full_mvcc_differential_records: u64,
    /// Clone-on-write memory estimate if a full oracle were attempted.
    pub full_mvcc_oracle_estimated_bytes: u64,
    /// Largest harness-owned streaming/batch buffer admitted for the actual path.
    pub estimated_peak_harness_buffer_bytes: u64,
}

/// One point on the deterministic scaling curve.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalePointOutcome {
    /// Logical records addressable at this point.
    pub records: u64,
    /// Exact recall latencies.
    pub recall_latency_ns: Vec<u64>,
    /// Deterministic read checksum.
    pub checksum: u64,
}

/// Raw native outcomes retained before canonical report aggregation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRunOutcome {
    /// Validated deterministic configuration.
    pub config: BenchConfig,
    /// Workload manifest identity.
    pub workload_manifest_sha256: String,
    /// Oracle strategy admitted before the run.
    pub oracle_mode: OracleMode,
    /// Records exercised by the full historical in-memory differential oracle.
    pub full_mvcc_differential_records: u64,
    /// Streaming digest expected for the bounded/full MVCC differential fixture.
    pub bounded_mvcc_expected_digest: String,
    /// Digest read back from the bounded/full in-memory MVCC oracle.
    pub bounded_mvcc_actual_digest: String,
    /// Exact digest and verified-record-count result of the MVCC differential.
    pub bounded_mvcc_differential_verified: bool,
    /// Rejected/admitted full-oracle allocation estimate.
    pub full_mvcc_oracle_estimated_bytes: u64,
    /// Deterministic exact recalls sampled from the native scale dataset.
    pub sampled_recall_queries: u64,
    /// Expected streaming/full-oracle digest.
    pub oracle_logical_digest: String,
    /// Persistent backend digest.
    pub native_logical_digest: String,
    /// Synchronized ingest batch latencies.
    pub ingest_latency_ns: Vec<u64>,
    /// Full ingest wall-clock duration.
    pub ingest_total_ns: u64,
    /// Logical payload bytes ingested.
    pub ingested_bytes: u64,
    /// Synchronized commit acknowledgements.
    pub synchronized_ingest_commits: u64,
    /// First exact reads after persistent reopen.
    pub cold_recall_latency_ns: Vec<u64>,
    /// Repeated exact reads on the same open backend.
    pub warm_recall_latency_ns: Vec<u64>,
    /// Subject-local filtered scans.
    pub filtered_recall_latency_ns: Vec<u64>,
    /// Seeded mixed read latencies while compaction is scheduled.
    pub mixed_read_latency_ns: Vec<u64>,
    /// Seeded mixed synchronized write latencies.
    pub mixed_write_latency_ns: Vec<u64>,
    /// Background physical compaction latency.
    pub background_compaction_ns: u64,
    /// Explicit post-rebuild physical compaction latency.
    pub compaction_latency_ns: u64,
    /// Derived-index rebuild latency.
    pub rebuild_latency_ns: u64,
    /// Scaling curve.
    pub scale_points: Vec<ScalePointOutcome>,
    /// Snapshot remained coherent while head advanced.
    pub snapshot_consistent: bool,
    /// Initial persistent record count matched the generated primary dataset.
    pub primary_count_equal: bool,
    /// Rebuild produced one exact derived entry per primary record.
    pub rebuild_equal: bool,
    /// Compaction preserved primary identity and logical contents.
    pub compaction_preserved: bool,
    /// Persistent reopen preserved primary identity and logical contents.
    pub reopen_preserved: bool,
    /// Final physical record count matched primary, derived, and runtime writes.
    pub final_record_count_equal: bool,
    /// Largest structurally estimated harness-owned buffer.
    pub estimated_peak_harness_buffer_bytes: u64,
    /// Structural and runtime process working-set budgets were enforced.
    pub working_set_budget_enforced: bool,
    /// Total native runner wall-clock duration.
    pub total_elapsed_ns: u64,
    /// Payload-free per-phase wall-clock durations.
    pub phase_latency_ns: BTreeMap<String, u64>,
    /// Portable journal backup/restore lifecycle.
    pub journal: JournalOperationsOutcome,
    /// Phase-boundary RSS observations; not continuous peak profiling.
    pub process_rss_samples_bytes: Vec<u64>,
    /// Payload-free aggregate telemetry.
    pub telemetry: TelemetryExport,
    /// Projection watermarks after the run.
    pub watermarks: BTreeMap<String, u64>,
    /// Honest known limitations attached to every bounded native report.
    pub limitations: Vec<String>,
}

#[derive(Debug)]
struct OracleOutcome {
    mode: OracleMode,
    full_mvcc_records: u64,
    dataset_digest: String,
    mvcc_expected_digest: String,
    mvcc_actual_digest: String,
    mvcc_verified: bool,
}

/// Computes a fail-closed working-set/oracle admission without allocating the dataset.
pub fn estimate_scale_admission(config: &BenchConfig) -> Result<ScaleAdmission> {
    config.validate()?;
    let value_bytes = u64::try_from(config.value_bytes)
        .map_err(|_| BenchError::ArithmeticOverflow("scale value bytes"))?;
    let batch_bytes = config
        .batch_records
        .checked_mul(
            value_bytes
                .checked_add(96)
                .ok_or(BenchError::ArithmeticOverflow("batch record estimate"))?,
        )
        .ok_or(BenchError::ArithmeticOverflow("batch allocation estimate"))?;
    let largest_subject_partition = config.records.div_ceil(u64::from(config.subjects));
    let filtered_scan_bytes = largest_subject_partition
        .checked_mul(
            value_bytes
                .checked_add(ESTIMATED_SCAN_RECORD_OVERHEAD_BYTES)
                .ok_or(BenchError::ArithmeticOverflow("scan record estimate"))?,
        )
        .ok_or(BenchError::ArithmeticOverflow(
            "filtered scan allocation estimate",
        ))?;
    let estimated_peak_harness_buffer_bytes = batch_bytes.max(filtered_scan_bytes);
    if estimated_peak_harness_buffer_bytes > config.working_buffer_budget_bytes {
        return Err(BenchError::InvalidConfiguration {
            field: "working_buffer_budget_bytes",
            reason: format!(
                "estimated harness buffer {estimated_peak_harness_buffer_bytes} exceeds declared budget {}",
                config.working_buffer_budget_bytes
            ),
        });
    }
    let retained_copies = retained_mvcc_record_copies(config.records, config.batch_records)?;
    let full_mvcc_oracle_estimated_bytes = retained_copies
        .checked_mul(ESTIMATED_MVCC_RECORD_BYTES)
        .ok_or(BenchError::ArithmeticOverflow("full MVCC oracle estimate"))?;
    let full_fits = full_mvcc_oracle_estimated_bytes <= config.working_buffer_budget_bytes;
    Ok(ScaleAdmission {
        oracle_mode: if full_fits {
            OracleMode::FullMvccInMemory
        } else {
            OracleMode::StreamingWithBoundedMvccProbe
        },
        full_mvcc_differential_records: if full_fits {
            config.records
        } else {
            config.records.min(FULL_MVCC_PROBE_RECORDS)
        },
        full_mvcc_oracle_estimated_bytes,
        estimated_peak_harness_buffer_bytes,
    })
}

fn retained_mvcc_record_copies(records: u64, batch_records: u64) -> Result<u64> {
    let commits = records.div_ceil(batch_records);
    let full_commits = commits.saturating_sub(1);
    let triangular = u128::from(full_commits)
        .checked_mul(u128::from(full_commits.saturating_add(1)))
        .and_then(|value| value.checked_div(2))
        .and_then(|value| value.checked_mul(u128::from(batch_records)))
        .and_then(|value| value.checked_add(u128::from(records)))
        .ok_or(BenchError::ArithmeticOverflow(
            "retained MVCC record copies",
        ))?;
    u64::try_from(triangular)
        .map_err(|_| BenchError::ArithmeticOverflow("retained MVCC record copy conversion"))
}

fn establish_oracle(dataset: &DeterministicDataset) -> Result<OracleOutcome> {
    let admission = estimate_scale_admission(dataset.config())?;
    let expected_digest = dataset.expected_logical_digest()?;
    if admission.oracle_mode == OracleMode::FullMvccInMemory {
        let storage = MemoryStorage::new();
        ingest(&storage, dataset, None)?;
        let actual = logical_digest(&storage, dataset, "full_mvcc_oracle")?;
        let verified = storage.verify(contextdb_storage::VerifyMode::Deep)?;
        let mvcc_verified =
            actual == expected_digest && verified.records == dataset.config().records;
        return Ok(OracleOutcome {
            mode: admission.oracle_mode,
            full_mvcc_records: dataset.config().records,
            dataset_digest: expected_digest.clone(),
            mvcc_expected_digest: expected_digest,
            mvcc_actual_digest: actual,
            mvcc_verified,
        });
    }

    let mut probe_config = dataset.config().clone();
    probe_config.tier = crate::ScaleTier::Development;
    let probe_records = admission.full_mvcc_differential_records;
    let probe = DeterministicDataset::new(probe_config.with_records(probe_records)?)?;
    let storage = MemoryStorage::new();
    ingest(&storage, &probe, None)?;
    let full_digest = logical_digest(&storage, &probe, "bounded_mvcc_oracle")?;
    let streaming_digest = probe.expected_logical_digest()?;
    let verified = storage.verify(contextdb_storage::VerifyMode::Deep)?;
    Ok(OracleOutcome {
        mode: admission.oracle_mode,
        full_mvcc_records: probe_records,
        dataset_digest: expected_digest,
        mvcc_expected_digest: streaming_digest.clone(),
        mvcc_actual_digest: full_digest.clone(),
        mvcc_verified: full_digest == streaming_digest && verified.records == probe_records,
    })
}

/// Runs every M17 scenario against fresh persistent files below `root`.
pub fn run_native_redb_at(
    config: BenchConfig,
    telemetry_budget: TelemetryBudget,
    root: &Path,
) -> Result<NativeRunOutcome> {
    let total_started = Instant::now();
    let mut phase_latency_ns = BTreeMap::new();
    config.validate()?;
    let admission = estimate_scale_admission(&config)?;
    let estimated_peak_harness_buffer_bytes = admission.estimated_peak_harness_buffer_bytes;
    std::fs::create_dir_all(root)?;
    let database_path = root.join("bench-primary.redb");
    let journal_source_path = root.join("bench-journal-source.redb");
    let journal_restore_path = root.join("bench-journal-restore.redb");
    if database_path.exists() || journal_source_path.exists() || journal_restore_path.exists() {
        return Err(BenchError::InvalidConfiguration {
            field: "native_run_root",
            reason: "native benchmark targets must be fresh".to_owned(),
        });
    }
    let dataset = DeterministicDataset::new(config.clone())?;
    let mut telemetry = TelemetryRecorder::new(telemetry_budget)?;
    let mut process_rss_samples_bytes = Vec::new();
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("oracle");
    let oracle = establish_oracle(&dataset)?;
    end_phase("oracle", phase_started, &mut phase_latency_ns)?;
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("native_ingest");
    let engine = RedbStorage::open(&database_path)?;
    let ingest_outcome = ingest(&engine, &dataset, Some(&mut telemetry))?;
    let initial_verify = engine.verify(contextdb_storage::VerifyMode::Deep)?;
    let primary_count_equal = initial_verify.records == config.records;
    end_phase("native_ingest", phase_started, &mut phase_latency_ns)?;
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("native_digest");
    let native_logical_digest = logical_digest(&engine, &dataset, "native_digest")?;
    end_phase("native_digest", phase_started, &mut phase_latency_ns)?;
    if oracle.dataset_digest != native_logical_digest {
        return Err(BenchError::Integrity(
            "persistent ingest differs from the admitted deterministic oracle".to_owned(),
        ));
    }

    let phase_started = begin_phase("snapshot_and_filtered_recall");
    let snapshot_consistent = check_snapshot_consistency(&engine, &mut telemetry)?;
    let filtered_recall_latency_ns = filtered_recall(&engine, &dataset, &mut telemetry)?;
    end_phase(
        "snapshot_and_filtered_recall",
        phase_started,
        &mut phase_latency_ns,
    )?;
    drop(engine);
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("cold_warm_recall");
    let reopen_started = Instant::now();
    let engine = RedbStorage::open(&database_path)?;
    telemetry.record(
        TelemetryMetric::LatencyNs,
        labels(OperationClass::Reopen, IndexClass::None),
        elapsed_ns(reopen_started)?,
    )?;
    let (cold_recall_latency_ns, cold_checksum) = exact_recall(
        &engine,
        &dataset,
        config.recall_queries,
        config.records,
        OperationClass::ColdRecall,
        &mut telemetry,
    )?;
    let (warm_recall_latency_ns, warm_checksum) = exact_recall(
        &engine,
        &dataset,
        config.recall_queries,
        config.records,
        OperationClass::WarmRecall,
        &mut telemetry,
    )?;
    if cold_checksum != warm_checksum {
        return Err(BenchError::Integrity(
            "cold and warm exact recall checksums differ".to_owned(),
        ));
    }
    end_phase("cold_warm_recall", phase_started, &mut phase_latency_ns)?;
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("scaling_curve");
    let scale_points = scaling_curve(&engine, &dataset, &mut telemetry)?;
    end_phase("scaling_curve", phase_started, &mut phase_latency_ns)?;

    let phase_started = begin_phase("mixed_under_compaction");
    let (mixed_read_latency_ns, mixed_write_latency_ns, background_compaction_ns) =
        mixed_under_compaction(&engine, &dataset, &mut telemetry)?;
    end_phase(
        "mixed_under_compaction",
        phase_started,
        &mut phase_latency_ns,
    )?;
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("derived_rebuild");
    let rebuild_started = Instant::now();
    rebuild_derived(&engine, &dataset)?;
    let rebuild_latency_ns = elapsed_ns(rebuild_started)?;
    telemetry.record(
        TelemetryMetric::LatencyNs,
        labels(OperationClass::Rebuild, IndexClass::Derived),
        rebuild_latency_ns,
    )?;
    let rebuild_equal = verify_derived(&engine, &dataset)?;
    end_phase("derived_rebuild", phase_started, &mut phase_latency_ns)?;
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("foreground_compaction");
    let before_compaction = logical_digest(&engine, &dataset, "pre_compaction_digest")?;
    let sequence_before_compaction = engine.head_sequence()?;
    let compaction_started = Instant::now();
    let compaction = engine.compact(CompactRequest {
        max_bytes: Some(config.working_buffer_budget_bytes),
    })?;
    let compaction_latency_ns = elapsed_ns(compaction_started)?;
    telemetry.record(
        TelemetryMetric::LatencyNs,
        labels(OperationClass::Compaction, IndexClass::None),
        compaction_latency_ns,
    )?;
    let after_compaction = logical_digest(&engine, &dataset, "post_compaction_digest")?;
    let compaction_preserved = before_compaction == after_compaction
        && compaction.sequence == sequence_before_compaction
        && engine.head_sequence()? == sequence_before_compaction;
    let final_sequence = engine.head_sequence()?;
    end_phase(
        "foreground_compaction",
        phase_started,
        &mut phase_latency_ns,
    )?;
    drop(engine);
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("reopen_and_verify");
    let engine = RedbStorage::open(&database_path)?;
    let reopen_preserved =
        logical_digest(&engine, &dataset, "reopen_digest")? == native_logical_digest;
    let verify_started = Instant::now();
    let physical_verify = engine.verify(contextdb_storage::VerifyMode::Deep)?;
    telemetry.record(
        TelemetryMetric::LatencyNs,
        labels(OperationClass::Verify, IndexClass::None),
        elapsed_ns(verify_started)?,
    )?;
    if physical_verify.sequence != final_sequence {
        return Err(BenchError::Integrity(
            "deep verification observed a different storage sequence".to_owned(),
        ));
    }
    let mixed_runtime_records = u64::try_from(mixed_write_latency_ns.len())
        .map_err(|_| BenchError::ArithmeticOverflow("mixed runtime record count"))?;
    let expected_final_records = config
        .records
        .checked_mul(2)
        .and_then(|records| records.checked_add(1))
        .and_then(|records| records.checked_add(mixed_runtime_records))
        .ok_or(BenchError::ArithmeticOverflow(
            "final physical record count",
        ))?;
    let final_record_count_equal = physical_verify.records == expected_final_records;
    end_phase("reopen_and_verify", phase_started, &mut phase_latency_ns)?;
    drop(engine);
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let phase_started = begin_phase("journal_backup_restore");
    let journal = run_journal_operations(
        config.journal_observations,
        config.seed,
        &journal_source_path,
        &journal_restore_path,
    )?;
    record_journal_telemetry(&journal, &mut telemetry)?;
    end_phase(
        "journal_backup_restore",
        phase_started,
        &mut phase_latency_ns,
    )?;
    sample_rss_enforced(
        &mut process_rss_samples_bytes,
        config.process_rss_budget_bytes,
    )?;

    let watermarks = BTreeMap::from([
        ("journal".to_owned(), journal.commit_seq),
        ("semantic".to_owned(), final_sequence),
        ("lexical".to_owned(), final_sequence),
        ("consolidation".to_owned(), final_sequence),
    ]);
    let mut limitations = vec![
        "Cold recall means the first read series after closing and reopening redb; the harness does not evict operating-system page cache.".to_owned(),
        "This bounded native adapter measures exact persistent storage recall, not M9 hybrid ANN/model orchestration.".to_owned(),
        "RSS is sampled at phase boundaries and is not a continuous allocator or kernel peak trace.".to_owned(),
        "The portable backup scenario exercises the production journal backup/restore boundary; the primary synthetic scale dataset is verified independently by reopen and digest.".to_owned(),
        "BENCH-E coverage in this package is a logical fixture/evaluator and does not measure real media decoders or modality models.".to_owned(),
        "M17 release certification remains blocked until the M16 deep security scan passes.".to_owned(),
    ];
    match oracle.mode {
        OracleMode::FullMvccInMemory => limitations.push(
            "The entire dataset fit the declared bounded full-MVCC differential oracle."
                .to_owned(),
        ),
        OracleMode::StreamingWithBoundedMvccProbe => limitations.push(format!(
            "The {}-record scale dataset uses a streaming expected digest/count and {} deterministic point recalls; full clone-on-write MVCC differential coverage is separately executed on {} records.",
            config.records, config.recall_queries, oracle.full_mvcc_records
        )),
    }
    if config.records >= 10_000_000 {
        limitations.push(
            "This run exercises 10000000 storage records only; the ERRATA E-009 10M semantic-node floor and required graph-edge/vector coverage remain unmeasured."
                .to_owned(),
        );
    } else {
        limitations.push(
            "The ERRATA E-009 10M-node certification floor remains unmeasured in this run."
                .to_owned(),
        );
    }
    let total_elapsed_ns = elapsed_ns(total_started)?;
    eprintln!(
        "contextdb-bench phase=complete elapsed_ns={total_elapsed_ns} records={}",
        config.records
    );
    Ok(NativeRunOutcome {
        config,
        workload_manifest_sha256: dataset.manifest_sha256().to_owned(),
        oracle_mode: oracle.mode,
        full_mvcc_differential_records: oracle.full_mvcc_records,
        bounded_mvcc_expected_digest: oracle.mvcc_expected_digest,
        bounded_mvcc_actual_digest: oracle.mvcc_actual_digest,
        bounded_mvcc_differential_verified: oracle.mvcc_verified,
        full_mvcc_oracle_estimated_bytes: admission.full_mvcc_oracle_estimated_bytes,
        sampled_recall_queries: dataset.config().recall_queries,
        oracle_logical_digest: oracle.dataset_digest,
        native_logical_digest,
        ingest_latency_ns: ingest_outcome.latencies,
        ingest_total_ns: ingest_outcome.total_ns,
        ingested_bytes: ingest_outcome.bytes,
        synchronized_ingest_commits: ingest_outcome.synchronized_commits,
        cold_recall_latency_ns,
        warm_recall_latency_ns,
        filtered_recall_latency_ns,
        mixed_read_latency_ns,
        mixed_write_latency_ns,
        background_compaction_ns,
        compaction_latency_ns,
        rebuild_latency_ns,
        scale_points,
        snapshot_consistent,
        primary_count_equal,
        rebuild_equal,
        compaction_preserved,
        reopen_preserved,
        final_record_count_equal,
        estimated_peak_harness_buffer_bytes,
        working_set_budget_enforced: true,
        total_elapsed_ns,
        phase_latency_ns,
        journal,
        process_rss_samples_bytes,
        telemetry: telemetry.export()?,
        watermarks,
        limitations,
    })
}

#[derive(Debug)]
struct IngestOutcome {
    latencies: Vec<u64>,
    total_ns: u64,
    bytes: u64,
    synchronized_commits: u64,
}

fn ingest<E: StorageEngine>(
    engine: &E,
    dataset: &DeterministicDataset,
    mut telemetry: Option<&mut TelemetryRecorder>,
) -> Result<IngestOutcome> {
    let primary = keyspace(PRIMARY_SPACE)?;
    let config = dataset.config();
    let started_total = Instant::now();
    let mut first = 0_u64;
    let mut latencies = Vec::new();
    let mut bytes = 0_u64;
    let mut synchronized_commits = 0_u64;
    let emit_progress = telemetry.is_some();
    let progress_interval = progress_interval(config.records);
    while first < config.records {
        let end = first
            .saturating_add(config.batch_records)
            .min(config.records);
        let mut transaction = engine.begin_write()?;
        for ordinal in first..end {
            let record = dataset.record(ordinal)?;
            bytes = bytes
                .checked_add(
                    u64::try_from(record.value.len())
                        .map_err(|_| BenchError::ArithmeticOverflow("ingested value bytes"))?,
                )
                .ok_or(BenchError::ArithmeticOverflow("ingested byte total"))?;
            transaction.put(&primary, record.key, record.value)?;
        }
        let started = Instant::now();
        let receipt = transaction.commit(Durability::Sync)?;
        let latency = elapsed_ns(started)?;
        latencies.push(latency);
        if receipt.durability == Durability::Sync {
            synchronized_commits = synchronized_commits.saturating_add(1);
        }
        if let Some(recorder) = telemetry.as_deref_mut() {
            recorder.record(
                TelemetryMetric::LatencyNs,
                labels(OperationClass::Ingest, IndexClass::None),
                latency,
            )?;
        }
        first = end;
        if emit_progress && (first == config.records || first.is_multiple_of(progress_interval)) {
            progress_records("native_ingest", first, config.records);
        }
    }
    Ok(IngestOutcome {
        latencies,
        total_ns: elapsed_ns(started_total)?,
        bytes,
        synchronized_commits,
    })
}

fn logical_digest<E: StorageEngine>(
    engine: &E,
    dataset: &DeterministicDataset,
    progress_phase: &'static str,
) -> Result<String> {
    let primary = keyspace(PRIMARY_SPACE)?;
    let snapshot = engine.begin_read(SnapshotSelector::Latest)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-bench-h-logical-v1\0");
    let progress_interval = progress_interval(dataset.config().records);
    for ordinal in 0..dataset.config().records {
        let record = dataset.record(ordinal)?;
        let value = snapshot
            .get(&primary, &record.key)?
            .ok_or_else(|| BenchError::Integrity(format!("primary record {ordinal} is missing")))?;
        hash_framed(&mut hasher, &record.key)?;
        hash_framed(&mut hasher, &value)?;
        if ordinal.saturating_add(1).is_multiple_of(progress_interval) {
            progress_records(
                progress_phase,
                ordinal.saturating_add(1),
                dataset.config().records,
            );
        }
    }
    Ok(hex(hasher.finalize().as_bytes()))
}

fn check_snapshot_consistency(
    engine: &RedbStorage,
    telemetry: &mut TelemetryRecorder,
) -> Result<bool> {
    let runtime = keyspace(RUNTIME_SPACE)?;
    let started = Instant::now();
    let frozen = engine.begin_read(SnapshotSelector::Latest)?;
    let frozen_sequence = frozen.sequence();
    let before = frozen.get(&runtime, SNAPSHOT_MARKER)?;
    let mut transaction = engine.begin_write()?;
    transaction.put(&runtime, SNAPSHOT_MARKER.to_vec(), b"advanced".to_vec())?;
    let receipt = transaction.commit(Durability::Sync)?;
    let frozen_after = frozen.get(&runtime, SNAPSHOT_MARKER)?;
    let latest = engine.begin_read(SnapshotSelector::Latest)?;
    let latest_value = latest.get(&runtime, SNAPSHOT_MARKER)?;
    let consistent = before.is_none()
        && frozen_after.is_none()
        && latest_value.as_deref() == Some(b"advanced".as_slice())
        && frozen.sequence() == frozen_sequence
        && receipt.sequence > frozen_sequence
        && latest.sequence() == receipt.sequence;
    telemetry.record(
        TelemetryMetric::LatencyNs,
        labels(OperationClass::Snapshot, IndexClass::None),
        elapsed_ns(started)?,
    )?;
    Ok(consistent)
}

fn exact_recall<E: StorageEngine>(
    engine: &E,
    dataset: &DeterministicDataset,
    query_count: u64,
    record_limit: u64,
    operation: OperationClass,
    telemetry: &mut TelemetryRecorder,
) -> Result<(Vec<u64>, u64)> {
    let primary = keyspace(PRIMARY_SPACE)?;
    let snapshot = engine.begin_read(SnapshotSelector::Latest)?;
    let mut latencies = Vec::with_capacity(
        usize::try_from(query_count)
            .map_err(|_| BenchError::ArithmeticOverflow("recall sample capacity"))?,
    );
    let mut checksum = 0_u64;
    for query in 0..query_count {
        let ordinal = dataset.query_ordinal(query) % record_limit;
        let record = dataset.record(ordinal)?;
        let started = Instant::now();
        let value = snapshot
            .get(&primary, &record.key)?
            .ok_or_else(|| BenchError::Integrity(format!("recall record {ordinal} is missing")))?;
        let latency = elapsed_ns(started)?;
        checksum = checksum
            .wrapping_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
            .wrapping_add(u64::from(value[0]));
        black_box(&value);
        latencies.push(latency);
        telemetry.record(
            TelemetryMetric::LatencyNs,
            TelemetryLabels {
                operation,
                status: OperationStatus::Ok,
                intent: Some(IntentClass::Current),
                record_class: RecordClass::Primary,
                index: IndexClass::Exact,
                backend: BackendClass::Redb,
                deployment: DeploymentClass::Embedded,
                error: ErrorClass::None,
            },
            latency,
        )?;
    }
    Ok((latencies, checksum))
}

fn filtered_recall(
    engine: &RedbStorage,
    dataset: &DeterministicDataset,
    telemetry: &mut TelemetryRecorder,
) -> Result<Vec<u64>> {
    let primary = keyspace(PRIMARY_SPACE)?;
    let snapshot = engine.begin_read(SnapshotSelector::Latest)?;
    let queries = u64::from(dataset.config().subjects)
        .min(dataset.config().recall_queries)
        .max(1);
    let mut latencies = Vec::with_capacity(
        usize::try_from(queries)
            .map_err(|_| BenchError::ArithmeticOverflow("filtered recall capacity"))?,
    );
    for query in 0..queries {
        let subject = u32::try_from(query % u64::from(dataset.config().subjects))
            .map_err(|_| BenchError::ArithmeticOverflow("filtered recall subject"))?;
        let prefix = dataset.subject_prefix(subject);
        let started = Instant::now();
        let values = snapshot.scan_prefix(&primary, &prefix)?;
        let latency = elapsed_ns(started)?;
        if values.is_empty() {
            return Err(BenchError::Integrity(
                "subject-filtered recall returned an empty populated partition".to_owned(),
            ));
        }
        black_box(values);
        latencies.push(latency);
        telemetry.record(
            TelemetryMetric::LatencyNs,
            TelemetryLabels {
                operation: OperationClass::FilteredRecall,
                status: OperationStatus::Ok,
                intent: Some(IntentClass::Administrative),
                record_class: RecordClass::Primary,
                index: IndexClass::Subject,
                backend: BackendClass::Redb,
                deployment: DeploymentClass::Embedded,
                error: ErrorClass::None,
            },
            latency,
        )?;
    }
    Ok(latencies)
}

fn scaling_curve(
    engine: &RedbStorage,
    dataset: &DeterministicDataset,
    telemetry: &mut TelemetryRecorder,
) -> Result<Vec<ScalePointOutcome>> {
    let mut outcomes = Vec::with_capacity(dataset.config().scale_points.len());
    let queries = dataset.config().recall_queries.clamp(1, 512);
    for point in &dataset.config().scale_points {
        let (recall_latency_ns, checksum) = exact_recall(
            engine,
            dataset,
            queries,
            *point,
            OperationClass::WarmRecall,
            telemetry,
        )?;
        outcomes.push(ScalePointOutcome {
            records: *point,
            recall_latency_ns,
            checksum,
        });
    }
    Ok(outcomes)
}

fn mixed_under_compaction(
    engine: &RedbStorage,
    dataset: &DeterministicDataset,
    telemetry: &mut TelemetryRecorder,
) -> Result<(Vec<u64>, Vec<u64>, u64)> {
    let compact_engine = engine.clone();
    let max_bytes = dataset.config().working_buffer_budget_bytes;
    let compaction = thread::spawn(move || -> Result<u64> {
        let started = Instant::now();
        loop {
            if compact_engine
                .try_compact(CompactRequest {
                    max_bytes: Some(max_bytes),
                })?
                .is_some()
            {
                break;
            }
            if started.elapsed() >= std::time::Duration::from_secs(10) {
                return Err(BenchError::Integrity(
                    "background compaction remained busy for 10 seconds".into(),
                ));
            }
            thread::sleep(std::time::Duration::from_millis(1));
        }
        elapsed_ns(started)
    });
    let primary = keyspace(PRIMARY_SPACE)?;
    let runtime = keyspace(RUNTIME_SPACE)?;
    let mut read_latencies = Vec::new();
    let mut write_latencies = Vec::new();
    for operation in 0..dataset.config().mixed_operations {
        let selector = dataset.query_ordinal(operation ^ 0x5a5a_5a5a);
        if selector % 10 < 8 {
            let ordinal = selector % dataset.config().records;
            let record = dataset.record(ordinal)?;
            let snapshot = engine.begin_read(SnapshotSelector::Latest)?;
            let started = Instant::now();
            let value = snapshot.get(&primary, &record.key)?.ok_or_else(|| {
                BenchError::Integrity("mixed read missed primary record".to_owned())
            })?;
            let latency = elapsed_ns(started)?;
            black_box(value);
            read_latencies.push(latency);
            telemetry.record(
                TelemetryMetric::LatencyNs,
                labels(OperationClass::MixedRead, IndexClass::Exact),
                latency,
            )?;
        } else {
            let key = format!("mixed/{operation:016x}").into_bytes();
            let value = selector.to_be_bytes().to_vec();
            let mut transaction = engine.begin_write()?;
            transaction.put(&runtime, key, value)?;
            let started = Instant::now();
            let receipt = transaction.commit(Durability::Sync)?;
            if receipt.durability != Durability::Sync {
                return Err(BenchError::Integrity(
                    "mixed workload acknowledged a non-synchronized write".to_owned(),
                ));
            }
            let latency = elapsed_ns(started)?;
            write_latencies.push(latency);
            telemetry.record(
                TelemetryMetric::LatencyNs,
                labels(OperationClass::MixedWrite, IndexClass::None),
                latency,
            )?;
        }
    }
    let background_compaction_ns = compaction
        .join()
        .map_err(|_| BenchError::WorkerPanicked)??;
    telemetry.record(
        TelemetryMetric::LatencyNs,
        labels(OperationClass::Compaction, IndexClass::None),
        background_compaction_ns,
    )?;
    if read_latencies.is_empty() || write_latencies.is_empty() {
        return Err(BenchError::Integrity(
            "mixed schedule did not exercise both reads and writes".to_owned(),
        ));
    }
    Ok((read_latencies, write_latencies, background_compaction_ns))
}

fn rebuild_derived<E: StorageEngine>(engine: &E, dataset: &DeterministicDataset) -> Result<()> {
    let derived = keyspace(DERIVED_SPACE)?;
    let mut first = 0_u64;
    let progress_interval = progress_interval(dataset.config().records);
    while first < dataset.config().records {
        let end = first
            .saturating_add(dataset.config().batch_records)
            .min(dataset.config().records);
        let mut transaction = engine.begin_write()?;
        for ordinal in first..end {
            let record = dataset.record(ordinal)?;
            let key = format!("subject/{:08}/{ordinal:016x}", record.subject).into_bytes();
            transaction.put(&derived, key, record.key)?;
        }
        transaction.commit(Durability::Sync)?;
        first = end;
        if first == dataset.config().records || first.is_multiple_of(progress_interval) {
            progress_records("derived_rebuild_write", first, dataset.config().records);
        }
    }
    Ok(())
}

fn verify_derived<E: StorageEngine>(engine: &E, dataset: &DeterministicDataset) -> Result<bool> {
    let derived = keyspace(DERIVED_SPACE)?;
    let snapshot = engine.begin_read(SnapshotSelector::Latest)?;
    let progress_interval = progress_interval(dataset.config().records);
    for ordinal in 0..dataset.config().records {
        let record = dataset.record(ordinal)?;
        let key = format!("subject/{:08}/{ordinal:016x}", record.subject).into_bytes();
        if snapshot.get(&derived, &key)?.as_deref() != Some(record.key.as_slice()) {
            return Ok(false);
        }
        if ordinal.saturating_add(1).is_multiple_of(progress_interval) {
            progress_records(
                "derived_rebuild_verify",
                ordinal.saturating_add(1),
                dataset.config().records,
            );
        }
    }
    Ok(true)
}

fn record_journal_telemetry(
    outcome: &JournalOperationsOutcome,
    telemetry: &mut TelemetryRecorder,
) -> Result<()> {
    for latency in &outcome.ingest_latency_ns {
        telemetry.record(
            TelemetryMetric::LatencyNs,
            TelemetryLabels {
                operation: OperationClass::Ingest,
                status: OperationStatus::Ok,
                intent: None,
                record_class: RecordClass::Journal,
                index: IndexClass::None,
                backend: BackendClass::Redb,
                deployment: DeploymentClass::Embedded,
                error: ErrorClass::None,
            },
            *latency,
        )?;
    }
    for (operation, latency) in [
        (OperationClass::Backup, outcome.backup_latency_ns),
        (OperationClass::Restore, outcome.restore_latency_ns),
        (OperationClass::Reopen, outcome.reopen_latency_ns),
    ] {
        telemetry.record(
            TelemetryMetric::LatencyNs,
            TelemetryLabels {
                operation,
                status: OperationStatus::Ok,
                intent: Some(IntentClass::Administrative),
                record_class: RecordClass::Journal,
                index: IndexClass::None,
                backend: BackendClass::Redb,
                deployment: DeploymentClass::Embedded,
                error: ErrorClass::None,
            },
            latency,
        )?;
    }
    Ok(())
}

fn labels(operation: OperationClass, index: IndexClass) -> TelemetryLabels {
    TelemetryLabels {
        operation,
        status: OperationStatus::Ok,
        intent: None,
        record_class: RecordClass::Primary,
        index,
        backend: BackendClass::Redb,
        deployment: DeploymentClass::Embedded,
        error: ErrorClass::None,
    }
}

fn keyspace(name: &'static str) -> Result<Keyspace> {
    Keyspace::new(name).map_err(BenchError::from)
}

fn elapsed_ns(started: Instant) -> Result<u64> {
    u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| BenchError::ArithmeticOverflow("native duration nanoseconds"))
}

fn begin_phase(name: &'static str) -> Instant {
    eprintln!("contextdb-bench phase={name} status=start");
    Instant::now()
}

fn end_phase(
    name: &'static str,
    started: Instant,
    timings: &mut BTreeMap<String, u64>,
) -> Result<()> {
    let elapsed = elapsed_ns(started)?;
    if timings.insert(name.to_owned(), elapsed).is_some() {
        return Err(BenchError::Integrity(format!(
            "benchmark phase {name} was recorded twice"
        )));
    }
    eprintln!("contextdb-bench phase={name} status=done elapsed_ns={elapsed}");
    Ok(())
}

fn progress_interval(records: u64) -> u64 {
    records.div_ceil(10).max(1)
}

fn progress_records(phase: &'static str, processed: u64, total: u64) {
    eprintln!(
        "contextdb-bench phase={phase} status=progress processed_records={processed} total_records={total}"
    );
}

fn sample_rss_enforced(samples: &mut Vec<u64>, budget_bytes: u64) -> Result<()> {
    if let Some(bytes) = process_rss_bytes() {
        samples.push(bytes);
        eprintln!("contextdb-bench resource=process_rss bytes={bytes} budget={budget_bytes}");
        if bytes > budget_bytes {
            return Err(BenchError::InvalidConfiguration {
                field: "process_rss_budget_bytes",
                reason: format!(
                    "observed process RSS {bytes} exceeds declared budget {budget_bytes}"
                ),
            });
        }
    }
    Ok(())
}

fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
        let kilobytes = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
        kilobytes.checked_mul(1024)
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!("(Get-Process -Id {}).WorkingSet64", std::process::id());
        let output = std::process::Command::new("powershell")
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "native benchmark tests use immediate failure semantics"
    )]

    use contextdb_storage::VerifyMode;
    use contextdb_storage_memory::MemoryStorage;

    use super::{OracleMode, estimate_scale_admission, ingest, logical_digest, run_native_redb_at};
    use crate::telemetry::TelemetryBudget;
    use crate::workload::{BenchConfig, DeterministicDataset};

    #[test]
    fn native_smoke_is_differentially_correct_and_reopenable() {
        let directory = tempfile::tempdir().expect("tempdir");
        let outcome = run_native_redb_at(
            BenchConfig::smoke(),
            TelemetryBudget::default(),
            directory.path(),
        )
        .expect("native run");
        assert_eq!(outcome.oracle_logical_digest, outcome.native_logical_digest);
        assert_eq!(
            outcome.bounded_mvcc_expected_digest,
            outcome.bounded_mvcc_actual_digest
        );
        assert!(outcome.bounded_mvcc_differential_verified);
        assert!(outcome.full_mvcc_differential_records > 0);
        assert!(outcome.snapshot_consistent);
        assert!(outcome.primary_count_equal);
        assert!(outcome.rebuild_equal);
        assert!(outcome.compaction_preserved);
        assert!(outcome.reopen_preserved);
        assert!(outcome.final_record_count_equal);
        assert!(outcome.working_set_budget_enforced);
        assert!(outcome.journal.restore_equal);
        assert!(outcome.journal.reopen_equal);
        assert!(!outcome.telemetry.payloads_included);
    }

    #[test]
    fn streaming_digest_equals_full_mvcc_oracle_on_small_fixture() {
        let dataset = DeterministicDataset::new(BenchConfig::smoke()).expect("dataset");
        let expected = dataset.expected_logical_digest().expect("streaming digest");
        let storage = MemoryStorage::new();
        ingest(&storage, &dataset, None).expect("full MVCC ingest");
        let actual = logical_digest(&storage, &dataset, "test_oracle").expect("full digest");
        let verified =
            contextdb_storage::StorageEngine::verify(&storage, VerifyMode::Deep).expect("verify");
        assert_eq!(actual, expected);
        assert_eq!(verified.records, dataset.config().records);
    }

    #[test]
    fn ten_million_admission_is_streaming_and_bounded() {
        let config = BenchConfig::development()
            .with_records(10_000_000)
            .expect("10M config");
        let admission = estimate_scale_admission(&config).expect("admission");
        assert_eq!(
            admission.oracle_mode,
            OracleMode::StreamingWithBoundedMvccProbe
        );
        assert_eq!(admission.full_mvcc_differential_records, 4_096);
        assert!(
            admission.estimated_peak_harness_buffer_bytes <= config.working_buffer_budget_bytes
        );
        assert!(admission.full_mvcc_oracle_estimated_bytes > 100_000_000_000_000);
    }

    #[test]
    fn subject_scan_must_fit_declared_working_buffer() {
        let mut config = BenchConfig::development()
            .with_records(10_000_000)
            .expect("10M config");
        config.subjects = 1;
        assert!(estimate_scale_admission(&config).is_err());
    }
}
