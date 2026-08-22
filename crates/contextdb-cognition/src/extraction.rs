//! Deterministic post-turn extraction baseline.

use contextdb_core::{
    BoundaryRule, CommitmentStatus, ContentDigest, EvidenceId, GoalHorizon, GoalStatus,
    PreferenceStrength,
};
use serde::{Deserialize, Serialize};

use crate::{
    CandidateProposal, CognitionConfig, CognitionResult, EntityMention, EvidenceCitation,
    ProposalBatch, ProposalBody, ProposalOrigin, TemporalProposal,
};

/// Speaker class retained for deterministic post-turn rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnSpeaker {
    User,
    Assistant,
    Tool,
    System,
}

/// Exact structured signal emitted by a trusted host or deterministic adapter.
/// The extractor attaches the immutable turn evidence and never accepts raw
/// graph mutations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredTurnCandidate {
    pub local_id: String,
    pub mentions: Vec<EntityMention>,
    pub body: ProposalBody,
    pub temporal: Option<TemporalProposal>,
    pub extraction_confidence: f32,
}

/// One completed conversational turn ready for asynchronous semantic
/// extraction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostTurnInput {
    pub processing_run: String,
    pub input_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub speaker: TurnSpeaker,
    /// Trusted local subject anchor, such as `user` or `agent`.
    pub speaker_subject_ref: String,
    pub text: String,
    pub evidence_id: EvidenceId,
    pub quote_hash: ContentDigest,
    pub structured: Vec<StructuredTurnCandidate>,
}

/// Conservative multilingual rule baseline. It intentionally prefers no-op
/// over turning incidental wording into a permanent trait.
#[derive(Clone, Debug)]
pub struct DeterministicPostTurnExtractor {
    config: CognitionConfig,
}

impl DeterministicPostTurnExtractor {
    /// Creates the no-model extractor.
    pub fn new(config: CognitionConfig) -> CognitionResult<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Extracts explicit high-precision signals and copies trusted structured
    /// adapter candidates. Greetings, filler, and unsupported prose yield an
    /// empty batch by design.
    pub fn extract(&self, input: &PostTurnInput) -> CognitionResult<ProposalBatch> {
        let citation = EvidenceCitation {
            evidence_id: input.evidence_id,
            quote_hash: input.quote_hash,
        };
        let mut candidates: Vec<_> = input
            .structured
            .iter()
            .map(|candidate| CandidateProposal {
                local_id: candidate.local_id.clone(),
                mentions: candidate.mentions.clone(),
                body: candidate.body.clone(),
                evidence: vec![citation],
                temporal: candidate.temporal,
                extraction_confidence: candidate.extraction_confidence,
            })
            .collect();

        if matches!(input.speaker, TurnSpeaker::User | TurnSpeaker::Assistant)
            && let Some(body) = explicit_text_signal(&input.text, &input.speaker_subject_ref)
        {
            candidates.push(CandidateProposal {
                local_id: deterministic_local_id(&input.text, candidates.len()),
                mentions: Vec::new(),
                body,
                evidence: vec![citation],
                temporal: None,
                extraction_confidence: 1.0,
            });
        }
        candidates.sort_by(|left, right| left.local_id.cmp(&right.local_id));
        let batch = ProposalBatch {
            schema_id: self.config.schema_id.clone(),
            processing_run: input.processing_run.clone(),
            origin: ProposalOrigin::Deterministic,
            input_digest: input.input_digest,
            policy_digest: input.policy_digest,
            candidates,
        };
        batch.validate_contract(
            &self.config,
            &input.processing_run,
            input.input_digest,
            input.policy_digest,
            None,
        )?;
        Ok(batch)
    }
}

fn explicit_text_signal(text: &str, subject_ref: &str) -> Option<ProposalBody> {
    let trimmed = text.trim();
    let normalized = trimmed.to_lowercase();

    for (prefix, rule) in [
        ("do not remember ", BoundaryRule::DoNotStore),
        ("don't remember ", BoundaryRule::DoNotStore),
        ("do not store ", BoundaryRule::DoNotStore),
        ("do not mention ", BoundaryRule::DoNotMention),
        ("never mention ", BoundaryRule::DoNotMention),
        ("не запоминай ", BoundaryRule::DoNotStore),
        ("не храни ", BoundaryRule::DoNotStore),
        ("не упоминай ", BoundaryRule::DoNotMention),
        ("не используй ", BoundaryRule::DoNotInfluence),
    ] {
        if normalized.starts_with(prefix) {
            let statement = trimmed.get(prefix.len()..)?.trim();
            if statement.is_empty() {
                return None;
            }
            return Some(ProposalBody::Boundary {
                subject_ref: subject_ref.to_owned(),
                rule,
                applies_to: Vec::new(),
            });
        }
    }

    for (prefix, strength) in [
        ("i prefer ", PreferenceStrength::Strong),
        ("i like ", PreferenceStrength::Moderate),
        ("я предпочитаю ", PreferenceStrength::Strong),
        ("мне нравится ", PreferenceStrength::Moderate),
    ] {
        if normalized.starts_with(prefix) {
            let value = trimmed.get(prefix.len()..)?.trim();
            if value.is_empty() {
                return None;
            }
            return Some(ProposalBody::Preference {
                subject_ref: subject_ref.to_owned(),
                domain: "general".to_owned(),
                value: serde_json::Value::String(value.to_owned()),
                strength,
            });
        }
    }

    // Test the more specific Russian forms first so punctuation is not
    // retained as part of the canonical statement.
    for prefix in ["моя цель — ", "моя цель - ", "my goal is ", "моя цель "]
    {
        if normalized.starts_with(prefix) {
            let statement = trimmed.get(prefix.len()..)?.trim();
            if statement.is_empty() {
                return None;
            }
            return Some(ProposalBody::Goal {
                owner_ref: subject_ref.to_owned(),
                statement: statement.to_owned(),
                status: GoalStatus::Active,
                horizon: GoalHorizon::Unspecified,
            });
        }
    }

    for prefix in ["i promise to ", "я обещаю "] {
        if normalized.starts_with(prefix) {
            let statement = trimmed.get(prefix.len()..)?.trim();
            if statement.is_empty() {
                return None;
            }
            return Some(ProposalBody::Commitment {
                owner_ref: subject_ref.to_owned(),
                beneficiary_ref: None,
                statement: statement.to_owned(),
                due: None,
                trigger: None,
                status: CommitmentStatus::Active,
            });
        }
    }
    None
}

fn deterministic_local_id(text: &str, ordinal: usize) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-post-turn-v1\0");
    hasher.update(text.as_bytes());
    hasher.update(&(ordinal as u64).to_be_bytes());
    format!("rule-{}", &hasher.finalize().to_hex()[..16])
}
