//! Payload-safe, fixed-dimension benchmark telemetry.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::report::Distribution;
use crate::{BenchError, Result};

/// Allowlisted operation dimension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    /// Synchronized primary ingest.
    Ingest,
    /// First recall after process reopen.
    ColdRecall,
    /// Repeated recall against a warmed backend.
    WarmRecall,
    /// Subject-filtered exact scan.
    FilteredRecall,
    /// Read leg of a seeded mixed workload.
    MixedRead,
    /// Write leg of a seeded mixed workload.
    MixedWrite,
    /// Physical compaction.
    Compaction,
    /// Derived-index rebuild.
    Rebuild,
    /// Snapshot consistency check.
    Snapshot,
    /// Portable logical backup creation.
    Backup,
    /// Portable logical restore.
    Restore,
    /// Persistent backend reopen.
    Reopen,
    /// Deep verification.
    Verify,
}

/// Allowlisted status dimension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Operation completed fully.
    Ok,
    /// Operation returned a bounded partial result.
    Partial,
    /// Operation failed.
    Error,
}

/// Allowlisted logical intent dimension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentClass {
    /// Current-state recall.
    Current,
    /// Historical recall.
    Historical,
    /// Conversational continuity.
    Continuity,
    /// Exact administrative lookup.
    Administrative,
}

/// Allowlisted record class dimension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordClass {
    /// Primary durable benchmark record.
    Primary,
    /// Rebuildable derived record.
    Derived,
    /// Immutable journal frame.
    Journal,
    /// Logical multimodal fixture item.
    ArtifactMetadata,
}

/// Allowlisted index class dimension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexClass {
    /// Exact primary key.
    Exact,
    /// Subject-local prefix.
    Subject,
    /// Rebuildable derived projection.
    Derived,
    /// No index involved.
    None,
}

/// Allowlisted backend dimension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendClass {
    /// In-memory correctness adapter.
    Memory,
    /// Native persistent redb adapter.
    Redb,
}

/// Allowlisted deployment dimension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentClass {
    /// Embedded single-process run.
    Embedded,
    /// Package-level harness validation.
    TestHarness,
}

/// Allowlisted payload-free error class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// No error.
    None,
    /// Invalid benchmark input.
    InvalidInput,
    /// Storage boundary error.
    Storage,
    /// Integrity mismatch.
    Integrity,
    /// Explicitly unsupported capability.
    Unsupported,
}

/// Fixed telemetry metric names.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TelemetryMetric {
    /// Operation latency in nanoseconds.
    LatencyNs,
    /// Bytes processed.
    Bytes,
    /// Logical operation count.
    Operations,
}

/// Privacy-safe trace sampling category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceClass {
    /// Failed operation; retained completely.
    Error,
    /// Security-relevant decision; retained completely in the protected sink.
    Security,
    /// Operation exceeding the declared slow threshold.
    Slow,
    /// Normal operation subject to deterministic adaptive sampling.
    Normal,
}

/// Sampling policy that never inspects request text or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingPolicy {
    /// Keep one normal trace out of this many using a deterministic ordinal.
    pub normal_sample_denominator: u32,
    /// Slow-operation boundary in nanoseconds.
    pub slow_threshold_ns: u64,
}

impl SamplingPolicy {
    /// Validates a bounded normal sampling rate and a nonzero slow threshold.
    pub fn validate(self) -> Result<()> {
        if self.normal_sample_denominator == 0 || self.slow_threshold_ns == 0 {
            return Err(BenchError::InvalidConfiguration {
                field: "sampling_policy",
                reason: "denominator and slow threshold must be positive".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns whether a payload-free trace class/ordinal is sampled.
    pub fn should_sample(self, class: TraceClass, operation_ordinal: u64) -> Result<bool> {
        self.validate()?;
        Ok(match class {
            TraceClass::Error | TraceClass::Security | TraceClass::Slow => true,
            TraceClass::Normal => {
                operation_ordinal.is_multiple_of(u64::from(self.normal_sample_denominator))
            }
        })
    }
}

impl TelemetryMetric {
    /// Stable metric name with no user-controlled component.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LatencyNs => "contextdb_bench_latency_ns",
            Self::Bytes => "contextdb_bench_bytes",
            Self::Operations => "contextdb_bench_operations",
        }
    }
}

/// Complete allowlisted label set. There is intentionally no ID or text field.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TelemetryLabels {
    /// Operation.
    pub operation: OperationClass,
    /// Result status.
    pub status: OperationStatus,
    /// Optional intent.
    pub intent: Option<IntentClass>,
    /// Record class.
    pub record_class: RecordClass,
    /// Index class.
    pub index: IndexClass,
    /// Backend.
    pub backend: BackendClass,
    /// Deployment shape.
    pub deployment: DeploymentClass,
    /// Payload-free error class.
    pub error: ErrorClass,
}

impl TelemetryLabels {
    fn pairs(self) -> Vec<(&'static str, &'static str)> {
        let mut pairs = vec![
            ("operation", enum_json(self.operation)),
            ("status", enum_json(self.status)),
            ("record_class", enum_json(self.record_class)),
            ("index", enum_json(self.index)),
            ("backend", enum_json(self.backend)),
            ("deployment", enum_json(self.deployment)),
            ("error", enum_json(self.error)),
        ];
        if let Some(intent) = self.intent {
            pairs.push(("intent", enum_json(intent)));
        }
        pairs
    }
}

fn enum_json<T: Serialize>(value: T) -> &'static str {
    // All enums above have a finite set. Keeping the mapping explicit avoids
    // allocating or ever accepting caller-controlled label values.
    let type_name = std::any::type_name::<T>();
    let json = serde_json::to_string(&value).unwrap_or_default();
    match (type_name.rsplit("::").next(), json.as_str()) {
        (Some("OperationClass"), "\"ingest\"") => "ingest",
        (Some("OperationClass"), "\"cold_recall\"") => "cold_recall",
        (Some("OperationClass"), "\"warm_recall\"") => "warm_recall",
        (Some("OperationClass"), "\"filtered_recall\"") => "filtered_recall",
        (Some("OperationClass"), "\"mixed_read\"") => "mixed_read",
        (Some("OperationClass"), "\"mixed_write\"") => "mixed_write",
        (Some("OperationClass"), "\"compaction\"") => "compaction",
        (Some("OperationClass"), "\"rebuild\"") => "rebuild",
        (Some("OperationClass"), "\"snapshot\"") => "snapshot",
        (Some("OperationClass"), "\"backup\"") => "backup",
        (Some("OperationClass"), "\"restore\"") => "restore",
        (Some("OperationClass"), "\"reopen\"") => "reopen",
        (Some("OperationClass"), "\"verify\"") => "verify",
        (Some("OperationStatus"), "\"ok\"") => "ok",
        (Some("OperationStatus"), "\"partial\"") => "partial",
        (Some("OperationStatus"), "\"error\"") => "error",
        (Some("IntentClass"), "\"current\"") => "current",
        (Some("IntentClass"), "\"historical\"") => "historical",
        (Some("IntentClass"), "\"continuity\"") => "continuity",
        (Some("IntentClass"), "\"administrative\"") => "administrative",
        (Some("RecordClass"), "\"primary\"") => "primary",
        (Some("RecordClass"), "\"derived\"") => "derived",
        (Some("RecordClass"), "\"journal\"") => "journal",
        (Some("RecordClass"), "\"artifact_metadata\"") => "artifact_metadata",
        (Some("IndexClass"), "\"exact\"") => "exact",
        (Some("IndexClass"), "\"subject\"") => "subject",
        (Some("IndexClass"), "\"derived\"") => "derived",
        (Some("IndexClass"), "\"none\"") => "none",
        (Some("BackendClass"), "\"memory\"") => "memory",
        (Some("BackendClass"), "\"redb\"") => "redb",
        (Some("DeploymentClass"), "\"embedded\"") => "embedded",
        (Some("DeploymentClass"), "\"test_harness\"") => "test_harness",
        (Some("ErrorClass"), "\"none\"") => "none",
        (Some("ErrorClass"), "\"invalid_input\"") => "invalid_input",
        (Some("ErrorClass"), "\"storage\"") => "storage",
        (Some("ErrorClass"), "\"integrity\"") => "integrity",
        (Some("ErrorClass"), "\"unsupported\"") => "unsupported",
        _ => "unknown",
    }
}

/// Hard cardinality and retained-sample budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryBudget {
    /// Maximum distinct metric-label series.
    pub max_series: usize,
    /// Maximum distinct values for any one label dimension.
    pub max_values_per_dimension: usize,
    /// Maximum retained samples per series.
    pub max_samples_per_series: usize,
}

impl Default for TelemetryBudget {
    fn default() -> Self {
        Self {
            max_series: 128,
            max_values_per_dimension: 16,
            max_samples_per_series: 20_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SeriesKey {
    metric: TelemetryMetric,
    labels: TelemetryLabels,
}

#[derive(Debug, Default)]
struct Samples {
    values: Vec<u64>,
    dropped: u64,
}

/// Payload-safe in-process telemetry recorder.
#[derive(Debug)]
pub struct TelemetryRecorder {
    budget: TelemetryBudget,
    series: BTreeMap<SeriesKey, Samples>,
    cardinality: BTreeMap<&'static str, BTreeSet<&'static str>>,
}

impl TelemetryRecorder {
    /// Creates a recorder. Payload export is structurally unavailable.
    pub fn new(budget: TelemetryBudget) -> Result<Self> {
        if budget.max_series == 0
            || budget.max_values_per_dimension == 0
            || budget.max_samples_per_series == 0
        {
            return Err(BenchError::InvalidConfiguration {
                field: "telemetry_budget",
                reason: "all telemetry budgets must be positive".to_owned(),
            });
        }
        Ok(Self {
            budget,
            series: BTreeMap::new(),
            cardinality: BTreeMap::new(),
        })
    }

    /// Records one integer sample after atomically checking cardinality budgets.
    pub fn record(
        &mut self,
        metric: TelemetryMetric,
        labels: TelemetryLabels,
        value: u64,
    ) -> Result<()> {
        let key = SeriesKey { metric, labels };
        if !self.series.contains_key(&key) && self.series.len() >= self.budget.max_series {
            return Err(BenchError::TelemetryBudget(
                "distinct series limit reached".to_owned(),
            ));
        }
        let pairs = labels.pairs();
        for (dimension, label_value) in &pairs {
            let existing = self.cardinality.get(dimension);
            let is_new = existing.is_none_or(|values| !values.contains(label_value));
            if is_new && existing.map_or(0, BTreeSet::len) >= self.budget.max_values_per_dimension {
                return Err(BenchError::TelemetryBudget(format!(
                    "label value budget reached for `{dimension}`"
                )));
            }
        }
        for (dimension, label_value) in pairs {
            self.cardinality
                .entry(dimension)
                .or_default()
                .insert(label_value);
        }
        let samples = self.series.entry(key).or_default();
        if samples.values.len() < self.budget.max_samples_per_series {
            samples.values.push(value);
        } else {
            samples.dropped = samples.dropped.saturating_add(1);
        }
        Ok(())
    }

    /// Exports aggregate series without record IDs, workspace IDs, query text, or payloads.
    pub fn export(&self) -> Result<TelemetryExport> {
        let mut series = Vec::with_capacity(self.series.len());
        for (key, samples) in &self.series {
            series.push(TelemetrySeries {
                metric: key.metric.as_str().to_owned(),
                labels: key
                    .labels
                    .pairs()
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value.to_owned()))
                    .collect(),
                distribution: Distribution::from_samples(&samples.values)?,
                dropped_samples: samples.dropped,
            });
        }
        Ok(TelemetryExport {
            payloads_included: false,
            max_series: self.budget.max_series,
            max_values_per_dimension: self.budget.max_values_per_dimension,
            max_samples_per_series: self.budget.max_samples_per_series,
            series,
        })
    }
}

/// One aggregate telemetry series.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySeries {
    /// Fixed metric name.
    pub metric: String,
    /// Fixed low-cardinality labels.
    pub labels: BTreeMap<String, String>,
    /// Retained sample distribution.
    pub distribution: Distribution,
    /// Samples dropped after the declared retention budget.
    pub dropped_samples: u64,
}

/// Complete payload-free telemetry export.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryExport {
    /// Always false for this harness.
    pub payloads_included: bool,
    /// Declared series budget.
    pub max_series: usize,
    /// Declared per-dimension value budget.
    pub max_values_per_dimension: usize,
    /// Declared retained-sample budget.
    pub max_samples_per_series: usize,
    /// Aggregate series.
    pub series: Vec<TelemetrySeries>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "telemetry contract tests use immediate failure semantics"
    )]

    use super::{
        BackendClass, DeploymentClass, ErrorClass, IndexClass, OperationClass, OperationStatus,
        RecordClass, SamplingPolicy, TelemetryBudget, TelemetryLabels, TelemetryMetric,
        TelemetryRecorder, TraceClass,
    };

    fn labels(operation: OperationClass) -> TelemetryLabels {
        TelemetryLabels {
            operation,
            status: OperationStatus::Ok,
            intent: None,
            record_class: RecordClass::Primary,
            index: IndexClass::Exact,
            backend: BackendClass::Redb,
            deployment: DeploymentClass::Embedded,
            error: ErrorClass::None,
        }
    }

    #[test]
    fn export_has_no_place_for_payload_or_identity() {
        let mut recorder = TelemetryRecorder::new(TelemetryBudget::default()).expect("recorder");
        recorder
            .record(
                TelemetryMetric::LatencyNs,
                labels(OperationClass::WarmRecall),
                42,
            )
            .expect("record");
        let json = serde_json::to_string(&recorder.export().expect("export")).expect("json");
        assert!(!json.contains("private-query-text"));
        assert!(!json.contains("workspace_id"));
        assert!(!json.contains("node_id"));
        assert!(json.contains("\"payloads_included\":false"));
    }

    #[test]
    fn distinct_series_budget_fails_closed() {
        let mut recorder = TelemetryRecorder::new(TelemetryBudget {
            max_series: 1,
            max_values_per_dimension: 16,
            max_samples_per_series: 8,
        })
        .expect("recorder");
        recorder
            .record(
                TelemetryMetric::LatencyNs,
                labels(OperationClass::WarmRecall),
                1,
            )
            .expect("first");
        assert!(
            recorder
                .record(
                    TelemetryMetric::LatencyNs,
                    labels(OperationClass::ColdRecall),
                    2,
                )
                .is_err()
        );
    }

    #[test]
    fn errors_security_and_slow_traces_are_never_sampled_out() {
        let policy = SamplingPolicy {
            normal_sample_denominator: 100,
            slow_threshold_ns: 120_000_000,
        };
        for class in [TraceClass::Error, TraceClass::Security, TraceClass::Slow] {
            assert!(policy.should_sample(class, 99).expect("sampling policy"));
        }
        assert!(
            policy
                .should_sample(TraceClass::Normal, 100)
                .expect("normal")
        );
        assert!(
            !policy
                .should_sample(TraceClass::Normal, 99)
                .expect("normal")
        );
    }
}
