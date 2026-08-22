//! Deterministic M17 performance, scale, and operations benchmark contracts.
//!
//! The crate keeps harness validation, bounded native measurements, and
//! release-certification evidence as distinct evidence classes. A synthetic
//! or development-tier run can therefore exercise every scenario without
//! being misrepresented as release SLO proof.

#![forbid(unsafe_code)]

mod aggregate;
mod bench_e;
mod compare;
mod digest;
mod error;
mod journal_ops;
mod report;
mod runner;
mod semantic;
mod semantic_workload;
mod telemetry;
mod workload;

pub use aggregate::{NativeRunMetadata, build_native_report};
pub use bench_e::*;
pub use compare::*;
pub use digest::{hex, sha256, sha256_hex};
pub use error::{BenchError, Result};
pub use journal_ops::JournalOperationsOutcome;
pub use report::*;
pub use runner::{
    NativeRunOutcome, OracleMode, ScaleAdmission, ScalePointOutcome, estimate_scale_admission,
    run_native_redb_at,
};
pub use semantic::{
    MeasuredArtifact, SEMANTIC_OUTCOME_SCHEMA_VERSION, SEMANTIC_TARGET_MATRIX_SCHEMA_VERSION,
    SemanticArtifactKind, SemanticRegressionClass, SemanticRegressionMeasurement,
    SemanticRunOutcome, SemanticScenario, SemanticScenarioMeasurement, SemanticScenarioTarget,
    SemanticTargetMatrix, SemanticTier, SemanticTierMeasurement, SemanticTierTarget,
    build_semantic_development_report, semantic_target_matrix_sha256,
};
pub use semantic_workload::{
    SEMANTIC_EXECUTION_INDEX_SCHEMA_VERSION, SEMANTIC_EXECUTION_SCHEMA_VERSION,
    SEMANTIC_WORKLOAD_CONFIG_SCHEMA_VERSION, SemanticAdmission, SemanticAdmissionDisposition,
    SemanticExecutionBundleIndex, SemanticExecutionOutcome, SemanticHostCapacity,
    SemanticWorkloadConfig, SemanticWorkloadPreset, admit_semantic_workload,
    detect_semantic_host_capacity, run_semantic_crash_child, run_semantic_workload,
    write_semantic_admission,
};
pub use telemetry::*;
pub use workload::{BenchConfig, BenchRecord, DeterministicDataset, ScaleTier};

/// Machine-readable benchmark result schema emitted by this package.
pub const BENCHMARK_RESULT_SCHEMA_VERSION: &str = "contextdb.benchmark-result/v1";

/// Stable workload generator version for M17 BENCH-H scenarios.
pub const BENCH_H_WORKLOAD_VERSION: &str = "contextdb-bench-h-v1";

/// Stable logical multimodal fixture version for BENCH-E conformance.
pub const BENCH_E_FIXTURE_VERSION: &str = "contextdb-bench-e-logical-v1";
