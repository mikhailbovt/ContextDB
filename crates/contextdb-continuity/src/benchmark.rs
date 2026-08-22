//! Deterministic BENCH-D cross-model continuity scoring.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{CompatibilityCode, ContinuityError, MigrationCompatibilityReport, Result};

/// BENCH-D acceptance thresholds in integer basis points and exact guards.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchDThresholds {
    /// Minimum bootstrap facet coverage.
    pub minimum_bootstrap_sufficiency_bps: u16,
    /// Minimum task/session continuity score.
    pub minimum_task_continuity_bps: u16,
    /// Minimum preference retention score.
    pub minimum_preference_retention_bps: u16,
    /// Minimum style-constraint retention score.
    pub minimum_style_constraint_bps: u16,
    /// Minimum compatibility-warning precision.
    pub minimum_warning_precision_bps: u16,
    /// Maximum allowed response-quality drop after migration.
    pub maximum_quality_drop_bps: u16,
}

impl BenchDThresholds {
    /// Validates all basis-point values.
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            (
                "minimum_bootstrap_sufficiency_bps",
                self.minimum_bootstrap_sufficiency_bps,
            ),
            (
                "minimum_task_continuity_bps",
                self.minimum_task_continuity_bps,
            ),
            (
                "minimum_preference_retention_bps",
                self.minimum_preference_retention_bps,
            ),
            (
                "minimum_style_constraint_bps",
                self.minimum_style_constraint_bps,
            ),
            (
                "minimum_warning_precision_bps",
                self.minimum_warning_precision_bps,
            ),
            ("maximum_quality_drop_bps", self.maximum_quality_drop_bps),
        ] {
            if value > 10_000 {
                return Err(ContinuityError::InvalidInput(format!(
                    "{name} exceeds 10000 basis points"
                )));
            }
        }
        Ok(())
    }
}

/// Measured outcomes for one source-to-target continuity scenario.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchDObservation {
    /// Stable memory/subject/checkpoint IDs survived.
    pub stable_ids: bool,
    /// Bootstrap required-facet coverage.
    pub bootstrap_sufficiency_bps: u16,
    /// Open-session/task continuity.
    pub task_continuity_bps: u16,
    /// Preference retention.
    pub preference_retention_bps: u16,
    /// Hard style/boundary constraint retention.
    pub style_constraint_bps: u16,
    /// Count of forbidden/private records observed in target output.
    pub private_leak_count: u64,
    /// Source-runtime task quality.
    pub source_quality_bps: u16,
    /// Target-runtime task quality.
    pub target_quality_bps: u16,
    /// Expected warning categories for the controlled scenario.
    pub expected_warning_codes: BTreeSet<CompatibilityCode>,
}

impl BenchDObservation {
    /// Validates every measured basis-point score.
    pub fn validate(&self) -> Result<()> {
        for value in [
            self.bootstrap_sufficiency_bps,
            self.task_continuity_bps,
            self.preference_retention_bps,
            self.style_constraint_bps,
            self.source_quality_bps,
            self.target_quality_bps,
        ] {
            if value > 10_000 {
                return Err(ContinuityError::InvalidInput(
                    "BENCH-D observation exceeds 10000 basis points".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Exact BENCH-D scorecard and pass/fail decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchDReport {
    /// Stable identity gate.
    pub stable_ids: bool,
    /// Bootstrap sufficiency measurement.
    pub bootstrap_sufficiency_bps: u16,
    /// Task continuity measurement.
    pub task_continuity_bps: u16,
    /// Preference retention measurement.
    pub preference_retention_bps: u16,
    /// Style/boundary constraint measurement.
    pub style_constraint_bps: u16,
    /// Exact private leak count; must be zero.
    pub private_leak_count: u64,
    /// Saturating source-minus-target quality drop.
    pub quality_drop_bps: u16,
    /// Precision of surfaced warning categories against the controlled oracle.
    pub warning_precision_bps: u16,
    /// Expected warning categories missing from the report.
    pub missing_warnings: BTreeSet<CompatibilityCode>,
    /// Unexpected warning categories surfaced by the report.
    pub unexpected_warnings: BTreeSet<CompatibilityCode>,
    /// True only when every threshold and exact privacy/identity gate passes.
    pub passed: bool,
}

/// Pure BENCH-D scorer.
#[derive(Clone, Copy, Debug, Default)]
pub struct BenchD;

impl BenchD {
    /// Scores one migration observation against an exact compatibility report.
    pub fn evaluate(
        thresholds: BenchDThresholds,
        observation: &BenchDObservation,
        compatibility: &MigrationCompatibilityReport,
    ) -> Result<BenchDReport> {
        thresholds.validate()?;
        observation.validate()?;
        compatibility.validate()?;
        let actual: BTreeSet<_> = compatibility
            .findings
            .iter()
            .filter(|finding| finding.severity != crate::FindingSeverity::Informational)
            .map(|finding| finding.code.clone())
            .collect();
        let missing_warnings: BTreeSet<CompatibilityCode> = observation
            .expected_warning_codes
            .difference(&actual)
            .cloned()
            .collect();
        let unexpected_warnings: BTreeSet<CompatibilityCode> = actual
            .difference(&observation.expected_warning_codes)
            .cloned()
            .collect();
        let true_positive = actual
            .intersection(&observation.expected_warning_codes)
            .count();
        let warning_precision_bps = if actual.is_empty() {
            if observation.expected_warning_codes.is_empty() {
                10_000
            } else {
                0
            }
        } else {
            u16::try_from(true_positive.saturating_mul(10_000) / actual.len()).unwrap_or(10_000)
        };
        let quality_drop_bps = observation
            .source_quality_bps
            .saturating_sub(observation.target_quality_bps);
        let passed = observation.stable_ids
            && observation.private_leak_count == 0
            && observation.bootstrap_sufficiency_bps
                >= thresholds.minimum_bootstrap_sufficiency_bps
            && observation.task_continuity_bps >= thresholds.minimum_task_continuity_bps
            && observation.preference_retention_bps >= thresholds.minimum_preference_retention_bps
            && observation.style_constraint_bps >= thresholds.minimum_style_constraint_bps
            && warning_precision_bps >= thresholds.minimum_warning_precision_bps
            && quality_drop_bps <= thresholds.maximum_quality_drop_bps
            && missing_warnings.is_empty();
        Ok(BenchDReport {
            stable_ids: observation.stable_ids,
            bootstrap_sufficiency_bps: observation.bootstrap_sufficiency_bps,
            task_continuity_bps: observation.task_continuity_bps,
            preference_retention_bps: observation.preference_retention_bps,
            style_constraint_bps: observation.style_constraint_bps,
            private_leak_count: observation.private_leak_count,
            quality_drop_bps,
            warning_precision_bps,
            missing_warnings,
            unexpected_warnings,
            passed,
        })
    }
}
