use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{CognitionError, CognitionResult, PROPOSAL_SCHEMA_V1, ProposalKind};

/// Promotion thresholds and bounded-input limits for the deterministic V1
/// reference policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitionConfig {
    pub schema_id: String,
    pub max_output_bytes: usize,
    pub max_candidates: usize,
    pub max_evidence_per_candidate: usize,
    pub max_text_chars: usize,
    pub max_summary_level: u8,
    pub auto_link_threshold: f32,
    pub ambiguous_link_threshold: f32,
    pub sensitive_auto_link_threshold: f32,
    pub promotion_thresholds: BTreeMap<ProposalKind, f32>,
    pub min_preference_source_families: usize,
    pub min_relationship_source_families: usize,
    pub min_reflection_support: usize,
    pub min_reflection_negative_examples: usize,
    pub max_lineage_depth: usize,
}

impl Default for CognitionConfig {
    fn default() -> Self {
        let promotion_thresholds = [
            (ProposalKind::Claim, 0.68),
            (ProposalKind::Preference, 0.78),
            (ProposalKind::Boundary, 0.0),
            (ProposalKind::Relationship, 0.82),
            (ProposalKind::Goal, 0.70),
            (ProposalKind::Commitment, 0.72),
            (ProposalKind::Correction, 0.0),
            (ProposalKind::Summary, 0.72),
            (ProposalKind::Reflection, 0.70),
        ]
        .into_iter()
        .collect();
        Self {
            schema_id: PROPOSAL_SCHEMA_V1.to_owned(),
            max_output_bytes: 1_048_576,
            max_candidates: 128,
            max_evidence_per_candidate: 32,
            max_text_chars: 16_384,
            max_summary_level: 3,
            auto_link_threshold: 0.92,
            ambiguous_link_threshold: 0.72,
            sensitive_auto_link_threshold: 0.97,
            promotion_thresholds,
            min_preference_source_families: 2,
            min_relationship_source_families: 2,
            min_reflection_support: 3,
            min_reflection_negative_examples: 1,
            max_lineage_depth: 8,
        }
    }
}

impl CognitionConfig {
    /// Validates limits and score thresholds before a worker starts.
    pub fn validate(&self) -> CognitionResult<()> {
        if self.schema_id.trim().is_empty() {
            return Err(CognitionError::InvalidProposal {
                field: "config.schema_id",
                reason: "must not be blank",
            });
        }
        if self.max_output_bytes == 0
            || self.max_candidates == 0
            || self.max_evidence_per_candidate == 0
            || self.max_text_chars == 0
            || self.max_lineage_depth == 0
            || self.min_preference_source_families == 0
            || self.min_relationship_source_families == 0
            || self.min_reflection_support == 0
            || self.min_reflection_negative_examples == 0
        {
            return Err(CognitionError::InvalidProposal {
                field: "config.limit",
                reason: "limits must be positive",
            });
        }
        for kind in [
            ProposalKind::Claim,
            ProposalKind::Preference,
            ProposalKind::Boundary,
            ProposalKind::Relationship,
            ProposalKind::Goal,
            ProposalKind::Commitment,
            ProposalKind::Correction,
            ProposalKind::Summary,
            ProposalKind::Reflection,
        ] {
            let Some(threshold) = self.promotion_thresholds.get(&kind) else {
                return Err(CognitionError::InvalidProposal {
                    field: "config.promotion_thresholds",
                    reason: "missing proposal kind",
                });
            };
            if !threshold.is_finite() || !(0.0..=1.0).contains(threshold) {
                return Err(CognitionError::InvalidProposal {
                    field: "config.promotion_thresholds",
                    reason: "threshold must be finite and between zero and one",
                });
            }
        }
        if [
            self.ambiguous_link_threshold,
            self.auto_link_threshold,
            self.sensitive_auto_link_threshold,
        ]
        .iter()
        .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
            || self.ambiguous_link_threshold > self.auto_link_threshold
            || self.auto_link_threshold > self.sensitive_auto_link_threshold
        {
            return Err(CognitionError::InvalidProposal {
                field: "config.entity_thresholds",
                reason: "entity thresholds are not monotonic",
            });
        }
        Ok(())
    }

    /// Returns the configured promotion threshold for a proposal class.
    #[must_use]
    pub fn promotion_threshold(&self, kind: ProposalKind) -> f32 {
        self.promotion_thresholds.get(&kind).copied().unwrap_or(1.0)
    }
}
