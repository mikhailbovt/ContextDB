//! Direction-aware baseline and regression comparison.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::report::{BenchmarkResult, DistributionStatistic};
use crate::{BenchError, Result};

/// How movement in a metric is interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegressionDirection {
    /// Larger values are better; only a decrease is regression.
    HigherIsBetter,
    /// Smaller values are better; only an increase is regression.
    LowerIsBetter,
    /// Any difference is regression; used for correctness/privacy invariants.
    Exact,
}

/// One threshold fixed before the candidate run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionRule {
    /// Stable metric name.
    pub metric: String,
    /// Distribution field, or none for a scalar.
    pub statistic: Option<DistributionStatistic>,
    /// Improvement direction.
    pub direction: RegressionDirection,
    /// Maximum relative regression in basis points.
    pub max_relative_regression_bps: u32,
    /// Maximum absolute regression in the metric's native unit.
    pub max_absolute_regression: f64,
    /// Non-waivable correctness or privacy rule.
    pub hard_gate: bool,
}

impl RegressionRule {
    fn validate(&self) -> Result<()> {
        if self.metric.is_empty()
            || !self.max_absolute_regression.is_finite()
            || self.max_absolute_regression < 0.0
        {
            return Err(BenchError::InvalidConfiguration {
                field: "regression_rule",
                reason: "metric must be non-empty and tolerance finite/nonnegative".to_owned(),
            });
        }
        if self.hard_gate
            && (self.direction != RegressionDirection::Exact
                || self.max_relative_regression_bps != 0
                || self.max_absolute_regression > f64::EPSILON)
        {
            return Err(BenchError::InvalidConfiguration {
                field: "regression_rule.hard_gate",
                reason: "hard gates must require exact equality with zero tolerance".to_owned(),
            });
        }
        Ok(())
    }
}

/// Complete predeclared comparison policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionPolicy {
    /// Stable policy version.
    pub version: String,
    /// Every metric/statistic comparison.
    pub rules: Vec<RegressionRule>,
}

impl RegressionPolicy {
    /// Validates uniqueness and non-waivable gate shapes.
    pub fn validate(&self) -> Result<()> {
        if self.version.trim().is_empty() || self.rules.is_empty() {
            return Err(BenchError::InvalidConfiguration {
                field: "regression_policy",
                reason: "version and at least one rule are required".to_owned(),
            });
        }
        let mut unique = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            if !unique.insert((rule.metric.as_str(), rule.statistic)) {
                return Err(BenchError::InvalidConfiguration {
                    field: "regression_policy.rules",
                    reason: "metric/statistic rules must be unique".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Comparison decision for one rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegressionDisposition {
    /// Candidate stayed within both tolerances.
    Passed,
    /// Candidate regressed beyond a tolerance.
    Regressed,
    /// Baseline omitted a metric required by the fixed policy.
    MissingBaseline,
    /// Candidate omitted a metric required by the fixed policy.
    MissingCandidate,
    /// Scalar/distribution shape did not match the fixed selector.
    IncompatibleMetricShape,
}

/// Detailed outcome for one regression rule.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricRegression {
    /// Metric.
    pub metric: String,
    /// Selected statistic.
    pub statistic: Option<DistributionStatistic>,
    /// Baseline value when present.
    pub baseline: Option<f64>,
    /// Candidate value when present.
    pub candidate: Option<f64>,
    /// Regression magnitude in native units.
    pub absolute_regression: Option<f64>,
    /// Regression magnitude in basis points.
    pub relative_regression_bps: Option<u32>,
    /// Decision.
    pub disposition: RegressionDisposition,
    /// Whether this is a non-waivable correctness/privacy gate.
    pub hard_gate: bool,
}

/// Complete baseline comparison report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionReport {
    /// Policy version used before the run.
    pub policy_version: String,
    /// Baseline run.
    pub baseline_run_id: uuid::Uuid,
    /// Candidate run.
    pub candidate_run_id: uuid::Uuid,
    /// True only when every rule passes.
    pub passed: bool,
    /// Detailed outcomes.
    pub metrics: Vec<MetricRegression>,
}

/// Compares a candidate to a baseline using only predeclared rules.
pub fn compare_reports(
    baseline: &BenchmarkResult,
    candidate: &BenchmarkResult,
    policy: &RegressionPolicy,
) -> Result<RegressionReport> {
    policy.validate()?;
    let baseline_metrics = unique_metrics(baseline)?;
    let candidate_metrics = unique_metrics(candidate)?;
    let mut metrics = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        let baseline_metric = baseline_metrics.get(rule.metric.as_str());
        let candidate_metric = candidate_metrics.get(rule.metric.as_str());
        let baseline_value =
            baseline_metric.and_then(|metric| metric.observed.value(rule.statistic));
        let candidate_value =
            candidate_metric.and_then(|metric| metric.observed.value(rule.statistic));
        let (absolute_regression, relative_regression_bps, disposition) = match (
            baseline_metric,
            candidate_metric,
            baseline_value,
            candidate_value,
        ) {
            (None, _, _, _) => (None, None, RegressionDisposition::MissingBaseline),
            (_, None, _, _) => (None, None, RegressionDisposition::MissingCandidate),
            (Some(_), Some(_), None, _) | (Some(_), Some(_), _, None) => {
                (None, None, RegressionDisposition::IncompatibleMetricShape)
            }
            (Some(_), Some(_), Some(base), Some(current)) => {
                let regression = regression_amount(rule.direction, base, current);
                let relative = relative_basis_points(regression, base);
                let passed = regression <= rule.max_absolute_regression
                    && relative <= rule.max_relative_regression_bps;
                (
                    Some(regression),
                    Some(relative),
                    if passed {
                        RegressionDisposition::Passed
                    } else {
                        RegressionDisposition::Regressed
                    },
                )
            }
        };
        metrics.push(MetricRegression {
            metric: rule.metric.clone(),
            statistic: rule.statistic,
            baseline: baseline_value,
            candidate: candidate_value,
            absolute_regression,
            relative_regression_bps,
            disposition,
            hard_gate: rule.hard_gate,
        });
    }
    let passed = metrics
        .iter()
        .all(|metric| metric.disposition == RegressionDisposition::Passed);
    Ok(RegressionReport {
        policy_version: policy.version.clone(),
        baseline_run_id: baseline.run_id,
        candidate_run_id: candidate.run_id,
        passed,
        metrics,
    })
}

fn unique_metrics(report: &BenchmarkResult) -> Result<BTreeMap<&str, &crate::report::Metric>> {
    let mut metrics = BTreeMap::new();
    for metric in &report.metrics {
        if metrics.insert(metric.name.as_str(), metric).is_some() {
            return Err(BenchError::InvalidConfiguration {
                field: "metrics",
                reason: format!("duplicate metric `{}`", metric.name),
            });
        }
    }
    Ok(metrics)
}

fn regression_amount(direction: RegressionDirection, baseline: f64, candidate: f64) -> f64 {
    match direction {
        RegressionDirection::HigherIsBetter => (baseline - candidate).max(0.0),
        RegressionDirection::LowerIsBetter => (candidate - baseline).max(0.0),
        RegressionDirection::Exact => (candidate - baseline).abs(),
    }
}

fn relative_basis_points(regression: f64, baseline: f64) -> u32 {
    if regression <= f64::EPSILON {
        return 0;
    }
    let denominator = baseline.abs();
    if denominator <= f64::EPSILON {
        return u32::MAX;
    }
    let scaled = (regression / denominator) * 10_000.0;
    if !scaled.is_finite() || scaled >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        scaled.ceil() as u32
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "regression comparator tests use immediate failure semantics"
    )]

    use super::{
        RegressionDirection, RegressionDisposition, RegressionPolicy, RegressionRule,
        compare_reports,
    };
    use crate::report::{BenchmarkResult, MetricObserved};

    #[test]
    fn hard_gate_cannot_hide_tolerance() {
        let rule = RegressionRule {
            metric: "privacy.leaks".to_owned(),
            statistic: None,
            direction: RegressionDirection::Exact,
            max_relative_regression_bps: 1,
            max_absolute_regression: 0.0,
            hard_gate: true,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn direction_tolerance_and_missing_candidate_are_explicit() {
        let baseline: BenchmarkResult = serde_json::from_str(include_str!(
            "../../../docs/benchmarks/examples/m0-governance-validation.json"
        ))
        .expect("canonical example");
        let mut candidate = baseline.clone();
        candidate.run_id = uuid::Uuid::now_v7();
        candidate.metrics[0].observed = MetricObserved::Scalar(1.2);
        let policy = RegressionPolicy {
            version: "predeclared-v1".to_owned(),
            rules: vec![RegressionRule {
                metric: "schema.valid".to_owned(),
                statistic: None,
                direction: RegressionDirection::LowerIsBetter,
                max_relative_regression_bps: 500,
                max_absolute_regression: 0.05,
                hard_gate: false,
            }],
        };
        let report = compare_reports(&baseline, &candidate, &policy).expect("comparison");
        assert!(!report.passed);
        assert_eq!(
            report.metrics[0].disposition,
            RegressionDisposition::Regressed
        );

        candidate.metrics.clear();
        let report = compare_reports(&baseline, &candidate, &policy).expect("comparison");
        assert_eq!(
            report.metrics[0].disposition,
            RegressionDisposition::MissingCandidate
        );
    }
}
