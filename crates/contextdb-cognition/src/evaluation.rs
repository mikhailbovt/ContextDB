//! Reference quality evaluator for labelled cognition decisions.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::NodeId;
use serde::{Deserialize, Serialize};

use crate::{
    AdjudicationOutput, CandidateDisposition, EntityResolution, PipelineStatus, ProposalKind,
    ValidationIssue,
};

/// Expected candidate outcome in a labelled write-pipeline fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedDisposition {
    Promote,
    Hypothesis,
    Summary,
    Quarantine,
    Reject,
    NoOp,
}

/// Optional expected entity resolution for one model-local mention.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExpectedEntityResolution {
    Existing { node_id: NodeId },
    CreateNew,
    Ambiguous,
}

/// Gold annotation for one proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionLabel {
    pub local_id: String,
    pub kind: ProposalKind,
    pub expected: ExpectedDisposition,
    pub hallucinated_evidence: bool,
    pub entity_resolution: BTreeMap<String, ExpectedEntityResolution>,
}

/// One evaluated output and its fixture labels.
#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationCase<'a> {
    pub case_id: &'a str,
    pub output: &'a AdjudicationOutput,
    pub labels: &'a [DecisionLabel],
    pub expected_pipeline_noop: bool,
}

/// Raw counts plus released quality metrics. Rates are deterministic ratios,
/// not model confidence estimates.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReport {
    pub labelled_candidates: u64,
    pub missing_decisions: u64,
    pub unexpected_decisions: u64,
    pub true_promotions: u64,
    pub predicted_promotions: u64,
    pub expected_promotions: u64,
    pub false_preference_promotions: u64,
    pub predicted_preference_promotions: u64,
    pub false_relationship_inferences: u64,
    pub predicted_relationship_promotions: u64,
    pub expected_corrections: u64,
    pub detected_corrections: u64,
    pub hallucinated_evidence_cases: u64,
    pub hallucinated_evidence_rejected: u64,
    pub predicted_noop_cases: u64,
    pub correct_noop_cases: u64,
    pub entity_labels: u64,
    pub correct_entity_resolutions: u64,
    pub candidate_precision: f64,
    pub candidate_recall: f64,
    pub false_preference_rate: f64,
    pub false_relationship_rate: f64,
    pub correction_recall: f64,
    pub hallucinated_evidence_rejection: f64,
    pub no_op_precision: f64,
    pub entity_resolution_accuracy: f64,
}

/// Release thresholds for M10 candidate quality.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityThresholds {
    pub min_labelled_candidates: u64,
    pub min_expected_promotions: u64,
    pub min_correction_cases: u64,
    pub min_hallucinated_evidence_cases: u64,
    pub min_predicted_noop_cases: u64,
    pub min_entity_labels: u64,
    pub min_candidate_precision: f64,
    pub min_candidate_recall: f64,
    pub max_false_preference_rate: f64,
    pub max_false_relationship_rate: f64,
    pub min_correction_recall: f64,
    pub min_hallucinated_evidence_rejection: f64,
    pub min_no_op_precision: f64,
    pub min_entity_resolution_accuracy: f64,
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            min_labelled_candidates: 1,
            min_expected_promotions: 1,
            min_correction_cases: 1,
            min_hallucinated_evidence_cases: 1,
            min_predicted_noop_cases: 1,
            min_entity_labels: 1,
            min_candidate_precision: 0.90,
            min_candidate_recall: 0.75,
            max_false_preference_rate: 0.02,
            max_false_relationship_rate: 0.01,
            min_correction_recall: 0.95,
            min_hallucinated_evidence_rejection: 1.0,
            min_no_op_precision: 0.90,
            min_entity_resolution_accuracy: 0.90,
        }
    }
}

impl EvaluationReport {
    /// Tests the report against an explicit release profile.
    #[must_use]
    pub fn meets(&self, thresholds: QualityThresholds) -> bool {
        self.labelled_candidates >= thresholds.min_labelled_candidates
            && self.expected_promotions >= thresholds.min_expected_promotions
            && self.expected_corrections >= thresholds.min_correction_cases
            && self.hallucinated_evidence_cases >= thresholds.min_hallucinated_evidence_cases
            && self.predicted_noop_cases >= thresholds.min_predicted_noop_cases
            && self.entity_labels >= thresholds.min_entity_labels
            && self.candidate_precision >= thresholds.min_candidate_precision
            && self.candidate_recall >= thresholds.min_candidate_recall
            && self.false_preference_rate <= thresholds.max_false_preference_rate
            && self.false_relationship_rate <= thresholds.max_false_relationship_rate
            && self.correction_recall >= thresholds.min_correction_recall
            && self.hallucinated_evidence_rejection
                >= thresholds.min_hallucinated_evidence_rejection
            && self.no_op_precision >= thresholds.min_no_op_precision
            && self.entity_resolution_accuracy >= thresholds.min_entity_resolution_accuracy
    }
}

/// Transparent reference evaluator for golden, adversarial, and shadow runs.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceEvaluator;

impl ReferenceEvaluator {
    /// Computes all M10 quality floors from labelled cases.
    #[must_use]
    pub fn evaluate(cases: &[EvaluationCase<'_>]) -> EvaluationReport {
        let mut report = EvaluationReport {
            labelled_candidates: 0,
            missing_decisions: 0,
            unexpected_decisions: 0,
            true_promotions: 0,
            predicted_promotions: 0,
            expected_promotions: 0,
            false_preference_promotions: 0,
            predicted_preference_promotions: 0,
            false_relationship_inferences: 0,
            predicted_relationship_promotions: 0,
            expected_corrections: 0,
            detected_corrections: 0,
            hallucinated_evidence_cases: 0,
            hallucinated_evidence_rejected: 0,
            predicted_noop_cases: 0,
            correct_noop_cases: 0,
            entity_labels: 0,
            correct_entity_resolutions: 0,
            candidate_precision: 0.0,
            candidate_recall: 0.0,
            false_preference_rate: 0.0,
            false_relationship_rate: 0.0,
            correction_recall: 0.0,
            hallucinated_evidence_rejection: 0.0,
            no_op_precision: 0.0,
            entity_resolution_accuracy: 0.0,
        };
        for case in cases {
            let decisions: BTreeMap<_, _> = case
                .output
                .decisions
                .iter()
                .map(|decision| (decision.local_id.as_str(), decision))
                .collect();
            let labels: BTreeSet<_> = case
                .labels
                .iter()
                .map(|label| label.local_id.as_str())
                .collect();
            report.unexpected_decisions = report.unexpected_decisions.saturating_add(
                decisions
                    .keys()
                    .filter(|local_id| !labels.contains(**local_id))
                    .count() as u64,
            );
            for label in case.labels {
                report.labelled_candidates = report.labelled_candidates.saturating_add(1);
                let Some(decision) = decisions.get(label.local_id.as_str()) else {
                    report.missing_decisions = report.missing_decisions.saturating_add(1);
                    continue;
                };
                let predicted_promotion = matches!(
                    decision.disposition,
                    CandidateDisposition::Promoted | CandidateDisposition::Hypothesis
                );
                let expected_promotion = matches!(
                    label.expected,
                    ExpectedDisposition::Promote | ExpectedDisposition::Hypothesis
                );
                if predicted_promotion {
                    report.predicted_promotions = report.predicted_promotions.saturating_add(1);
                }
                if expected_promotion {
                    report.expected_promotions = report.expected_promotions.saturating_add(1);
                }
                if predicted_promotion && disposition_matches(decision.disposition, label.expected)
                {
                    report.true_promotions = report.true_promotions.saturating_add(1);
                }
                if label.kind == ProposalKind::Preference && predicted_promotion {
                    report.predicted_preference_promotions =
                        report.predicted_preference_promotions.saturating_add(1);
                    if !expected_promotion {
                        report.false_preference_promotions =
                            report.false_preference_promotions.saturating_add(1);
                    }
                }
                if label.kind == ProposalKind::Relationship && predicted_promotion {
                    report.predicted_relationship_promotions =
                        report.predicted_relationship_promotions.saturating_add(1);
                    if !expected_promotion {
                        report.false_relationship_inferences =
                            report.false_relationship_inferences.saturating_add(1);
                    }
                }
                if label.kind == ProposalKind::Correction && expected_promotion {
                    report.expected_corrections = report.expected_corrections.saturating_add(1);
                    if decision.disposition == CandidateDisposition::Promoted {
                        report.detected_corrections = report.detected_corrections.saturating_add(1);
                    }
                }
                if label.hallucinated_evidence {
                    report.hallucinated_evidence_cases =
                        report.hallucinated_evidence_cases.saturating_add(1);
                    if decision.disposition == CandidateDisposition::Rejected
                        && decision.issues.iter().any(|issue| {
                            matches!(
                                issue,
                                ValidationIssue::UnknownEvidence
                                    | ValidationIssue::QuoteHashMismatch
                            )
                        })
                    {
                        report.hallucinated_evidence_rejected =
                            report.hallucinated_evidence_rejected.saturating_add(1);
                    }
                }
                for (local_ref, expected) in &label.entity_resolution {
                    report.entity_labels = report.entity_labels.saturating_add(1);
                    if decision
                        .entity_resolution
                        .iter()
                        .find(|trace| &trace.local_ref == local_ref)
                        .is_some_and(|trace| entity_matches(&trace.result, expected))
                    {
                        report.correct_entity_resolutions =
                            report.correct_entity_resolutions.saturating_add(1);
                    }
                }
            }
            let predicted_noop = case.output.status == PipelineStatus::NoOp
                || (!case.output.decisions.is_empty()
                    && case.output.decisions.iter().all(|decision| {
                        matches!(
                            decision.disposition,
                            CandidateDisposition::NoOp
                                | CandidateDisposition::Rejected
                                | CandidateDisposition::Quarantined
                        )
                    }));
            if predicted_noop {
                report.predicted_noop_cases = report.predicted_noop_cases.saturating_add(1);
                if case.expected_pipeline_noop {
                    report.correct_noop_cases = report.correct_noop_cases.saturating_add(1);
                }
            }
        }
        report.candidate_precision = ratio(report.true_promotions, report.predicted_promotions);
        report.candidate_recall = ratio(report.true_promotions, report.expected_promotions);
        report.false_preference_rate = error_ratio(
            report.false_preference_promotions,
            report.predicted_preference_promotions,
        );
        report.false_relationship_rate = error_ratio(
            report.false_relationship_inferences,
            report.predicted_relationship_promotions,
        );
        report.correction_recall = ratio(report.detected_corrections, report.expected_corrections);
        report.hallucinated_evidence_rejection = ratio(
            report.hallucinated_evidence_rejected,
            report.hallucinated_evidence_cases,
        );
        report.no_op_precision = ratio(report.correct_noop_cases, report.predicted_noop_cases);
        report.entity_resolution_accuracy =
            ratio(report.correct_entity_resolutions, report.entity_labels);
        report
    }
}

/// Candidate-level diff between an earlier run and a shadow/reprocessing run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReprocessingDiff {
    pub previous_run: String,
    pub new_run: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub unchanged: Vec<String>,
    pub new_run_would_mutate: bool,
}

impl ReprocessingDiff {
    /// Compares decisions without modifying either historical output.
    #[must_use]
    pub fn between(previous: &AdjudicationOutput, new: &AdjudicationOutput) -> Self {
        let previous_decisions: BTreeMap<_, _> = previous
            .decisions
            .iter()
            .map(|decision| (decision.local_id.clone(), decision.disposition))
            .collect();
        let new_decisions: BTreeMap<_, _> = new
            .decisions
            .iter()
            .map(|decision| (decision.local_id.clone(), decision.disposition))
            .collect();
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();
        for (local_id, disposition) in &new_decisions {
            match previous_decisions.get(local_id) {
                None => added.push(local_id.clone()),
                Some(previous) if previous != disposition => changed.push(local_id.clone()),
                Some(_) => unchanged.push(local_id.clone()),
            }
        }
        for local_id in previous_decisions.keys() {
            if !new_decisions.contains_key(local_id) {
                removed.push(local_id.clone());
            }
        }
        Self {
            previous_run: previous.processing_run.clone(),
            new_run: new.processing_run.clone(),
            added,
            removed,
            changed,
            unchanged,
            new_run_would_mutate: new
                .transaction
                .as_ref()
                .is_some_and(contextdb_core::SemanticMutationSet::has_semantic_writes)
                || !new.summaries.is_empty(),
        }
    }
}

fn disposition_matches(actual: CandidateDisposition, expected: ExpectedDisposition) -> bool {
    matches!(
        (actual, expected),
        (CandidateDisposition::Promoted, ExpectedDisposition::Promote)
            | (
                CandidateDisposition::Hypothesis,
                ExpectedDisposition::Hypothesis
            )
            | (
                CandidateDisposition::SummaryReady,
                ExpectedDisposition::Summary
            )
            | (
                CandidateDisposition::Quarantined,
                ExpectedDisposition::Quarantine
            )
            | (CandidateDisposition::Rejected, ExpectedDisposition::Reject)
            | (CandidateDisposition::NoOp, ExpectedDisposition::NoOp)
    )
}

fn entity_matches(actual: &EntityResolution, expected: &ExpectedEntityResolution) -> bool {
    match (actual, expected) {
        (
            EntityResolution::Existing {
                node_id: actual, ..
            },
            ExpectedEntityResolution::Existing { node_id: expected },
        ) => actual == expected,
        (EntityResolution::CreateNew, ExpectedEntityResolution::CreateNew)
        | (EntityResolution::Ambiguous { .. }, ExpectedEntityResolution::Ambiguous) => true,
        _ => false,
    }
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn error_ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}
