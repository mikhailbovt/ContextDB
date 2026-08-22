use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    BoundaryRule, CommitmentStatus, Condition, ContentDigest, EvidenceId, GoalHorizon, GoalStatus,
    ModelCallId, NodeType, PreferenceStrength, RelationshipKind, TimestampMicros,
};
use serde::{Deserialize, Serialize};

use crate::{CognitionConfig, CognitionError, CognitionResult};

/// Stable wire identifier for the initial provider-neutral proposal contract.
pub const PROPOSAL_SCHEMA_V1: &str = "contextdb://schemas/cognition/proposals/v1";

/// Provenance class for a proposal batch. Provider-specific payloads never
/// cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalOrigin {
    /// Rule-based or adapter-derived output that did not invoke a model.
    Deterministic,
    /// A schema-validated live model output.
    Model { call_id: ModelCallId },
    /// A recorded validated output used for deterministic replay.
    RecordedModel { call_id: ModelCallId },
}

impl ProposalOrigin {
    /// Returns the model call, if the batch was model-assisted.
    #[must_use]
    pub const fn model_call(&self) -> Option<ModelCallId> {
        match self {
            Self::Deterministic => None,
            Self::Model { call_id } | Self::RecordedModel { call_id } => Some(*call_id),
        }
    }
}

/// Strict, provider-neutral batch returned by extraction, summarisation, or
/// reflection compute.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalBatch {
    pub schema_id: String,
    pub processing_run: String,
    pub origin: ProposalOrigin,
    pub input_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub candidates: Vec<CandidateProposal>,
}

impl ProposalBatch {
    /// Digest of the validated provider-neutral output. This is compared with
    /// the auditable core `ModelCall.output_hash` before adjudication.
    pub fn canonical_digest(&self) -> CognitionResult<ContentDigest> {
        let encoded = serde_json::to_vec(self)
            .map_err(|error| CognitionError::Serialization(error.to_string()))?;
        Ok(ContentDigest::from_bytes(
            *blake3::hash(&encoded).as_bytes(),
        ))
    }

    /// Parses a strict JSON proposal and checks request-bound metadata before
    /// any candidate can influence resolution or mutation planning.
    pub fn from_json(
        bytes: &[u8],
        config: &CognitionConfig,
        expected_run: &str,
        expected_input: ContentDigest,
        expected_policy: ContentDigest,
        expected_model_call: Option<ModelCallId>,
    ) -> CognitionResult<Self> {
        if bytes.len() > config.max_output_bytes {
            return Err(CognitionError::OutputTooLarge);
        }
        let batch: Self = serde_json::from_slice(bytes)
            .map_err(|error| CognitionError::InvalidJson(error.to_string()))?;
        batch.validate_contract(
            config,
            expected_run,
            expected_input,
            expected_policy,
            expected_model_call,
        )?;
        Ok(batch)
    }

    /// Validates a programmatically constructed batch against the same strict
    /// contract used for JSON model output.
    pub fn validate_contract(
        &self,
        config: &CognitionConfig,
        expected_run: &str,
        expected_input: ContentDigest,
        expected_policy: ContentDigest,
        expected_model_call: Option<ModelCallId>,
    ) -> CognitionResult<()> {
        if self.schema_id != config.schema_id {
            return Err(CognitionError::SchemaMismatch {
                expected: config.schema_id.clone(),
                actual: self.schema_id.clone(),
            });
        }
        if self.processing_run != expected_run {
            return Err(CognitionError::ProcessingRunMismatch);
        }
        if self.input_digest != expected_input {
            return Err(CognitionError::InputDigestMismatch);
        }
        if self.policy_digest != expected_policy {
            return Err(CognitionError::PolicyDigestMismatch);
        }
        if self.origin.model_call() != expected_model_call {
            return Err(CognitionError::ModelCallMismatch);
        }
        if self.candidates.len() > config.max_candidates {
            return Err(CognitionError::TooManyCandidates);
        }

        let mut local_ids = BTreeSet::new();
        for candidate in &self.candidates {
            if !local_ids.insert(candidate.local_id.clone()) {
                return Err(CognitionError::DuplicateLocalIdentifier(
                    candidate.local_id.clone(),
                ));
            }
            candidate.validate_shape(config)?;
        }
        Ok(())
    }
}

/// A local mention. The model may name and describe it, but only the resolver
/// can associate it with a canonical [`contextdb_core::NodeId`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityMention {
    pub local_ref: String,
    pub surface: String,
    pub expected_type: NodeType,
    pub canonical_key: Option<String>,
    pub external_key: Option<String>,
    pub sensitive: bool,
}

/// Exact evidence reference echoed by a proposal. Both ID and quote digest are
/// checked against the authorized evidence catalogue.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCitation {
    pub evidence_id: EvidenceId,
    pub quote_hash: ContentDigest,
}

/// Proposed domain-valid time. Transaction time is assigned only by the commit
/// coordinator path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalProposal {
    pub valid_from: Option<TimestampMicros>,
    pub valid_to: Option<TimestampMicros>,
    pub change_hint: Option<ChangeHint>,
}

/// Non-authoritative model hint retained for explainability. Deterministic
/// classification may disagree with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeHint {
    Duplicate,
    Refinement,
    TemporalTransition,
    Correction,
    ScopedCoexistence,
    Contradiction,
    Independent,
}

/// One proposal with model-local identity and exact supporting evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProposal {
    pub local_id: String,
    pub mentions: Vec<EntityMention>,
    pub body: ProposalBody,
    pub evidence: Vec<EvidenceCitation>,
    pub temporal: Option<TemporalProposal>,
    /// Extraction quality only; never treated as probability of truth.
    pub extraction_confidence: f32,
}

impl CandidateProposal {
    fn validate_shape(&self, config: &CognitionConfig) -> CognitionResult<()> {
        validate_text(&self.local_id, config, "candidate.local_id")?;
        if !self.extraction_confidence.is_finite()
            || !(0.0..=1.0).contains(&self.extraction_confidence)
        {
            return Err(CognitionError::InvalidProposal {
                field: "candidate.extraction_confidence",
                reason: "must be finite and between zero and one",
            });
        }
        if self.evidence.is_empty() {
            return Err(CognitionError::InvalidProposal {
                field: "candidate.evidence",
                reason: "at least one evidence citation is required",
            });
        }
        if self.evidence.len() > config.max_evidence_per_candidate {
            return Err(CognitionError::InvalidProposal {
                field: "candidate.evidence",
                reason: "too many evidence citations",
            });
        }
        let evidence: BTreeSet<_> = self.evidence.iter().map(|item| item.evidence_id).collect();
        if evidence.len() != self.evidence.len() {
            return Err(CognitionError::InvalidProposal {
                field: "candidate.evidence",
                reason: "duplicate evidence citation",
            });
        }

        let mut mention_refs = BTreeSet::new();
        for mention in &self.mentions {
            validate_text(&mention.local_ref, config, "mention.local_ref")?;
            validate_text(&mention.surface, config, "mention.surface")?;
            if !mention_refs.insert(mention.local_ref.clone()) {
                return Err(CognitionError::InvalidProposal {
                    field: "candidate.mentions",
                    reason: "duplicate mention local reference",
                });
            }
            if let Some(value) = &mention.canonical_key {
                validate_text(value, config, "mention.canonical_key")?;
            }
            if let Some(value) = &mention.external_key {
                validate_text(value, config, "mention.external_key")?;
            }
        }
        self.body.validate_shape(config, &mention_refs)?;
        if let Some(temporal) = self.temporal
            && let (Some(start), Some(end)) = (temporal.valid_from, temporal.valid_to)
            && start >= end
        {
            return Err(CognitionError::InvalidProposal {
                field: "candidate.temporal",
                reason: "valid_from must precede valid_to",
            });
        }
        Ok(())
    }

    /// Returns the semantic proposal class used by promotion and evaluation.
    #[must_use]
    pub const fn kind(&self) -> ProposalKind {
        self.body.kind()
    }
}

/// Canonical value proposal. Node references remain local until entity
/// resolution succeeds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ProposedValue {
    Entity { mention_ref: String },
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Timestamp(TimestampMicros),
    Structured(serde_json::Value),
}

/// Strength of a relationship signal. Emotional or diagnostic claims are
/// intentionally represented explicitly so default policy can reject them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipSignal {
    ExplicitRole,
    ExplicitBoundary,
    SharedCommitment,
    RepeatedCommunicationNorm,
    SharedReference,
    SingleInteraction,
    InferredEmotion,
    PsychologicalDiagnosis,
    ConsciousnessClaim,
    JointOwnershipClaim,
}

/// Transparent V1 pattern kinds; black-box pattern mining is intentionally not
/// part of the baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    RecurringFailure,
    RecurringPreference,
    ReopenedTask,
    ReusableProcedure,
    ArchitecturalTension,
    ContradictoryPolicy,
    RepeatedUnverifiedAssumption,
    AgentBehaviourPattern,
}

/// Provider-neutral semantic proposal body. It contains no raw graph writes or
/// canonical IDs chosen by a model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposalBody {
    Claim {
        subject_ref: String,
        predicate_ref: String,
        object: ProposedValue,
    },
    Preference {
        subject_ref: String,
        domain: String,
        value: serde_json::Value,
        strength: PreferenceStrength,
    },
    Boundary {
        subject_ref: String,
        rule: BoundaryRule,
        applies_to: Vec<String>,
    },
    Relationship {
        participant_refs: Vec<String>,
        relationship_kind: RelationshipKind,
        signal: RelationshipSignal,
        roles: BTreeMap<String, String>,
        interaction_norms: Vec<String>,
    },
    Goal {
        owner_ref: String,
        statement: String,
        status: GoalStatus,
        horizon: GoalHorizon,
    },
    Commitment {
        owner_ref: String,
        beneficiary_ref: Option<String>,
        statement: String,
        due: Option<TimestampMicros>,
        trigger: Option<Condition>,
        status: CommitmentStatus,
    },
    Correction {
        target_claim_ref: String,
        replacement_subject_ref: String,
        predicate_ref: String,
        replacement: ProposedValue,
        reason: String,
        was_never_true: bool,
    },
    Summary {
        owner_ref: String,
        level: u8,
        content: serde_json::Value,
        known_omissions: Vec<String>,
    },
    Reflection {
        owner_ref: String,
        pattern_kind: PatternKind,
        label: String,
        hypothesis: String,
        negative_evidence: Vec<EvidenceCitation>,
        required_verification: Vec<String>,
        proposes_causality: bool,
        sensitive_trait: bool,
    },
}

impl ProposalBody {
    /// Returns a compact stable classification.
    #[must_use]
    pub const fn kind(&self) -> ProposalKind {
        match self {
            Self::Claim { .. } => ProposalKind::Claim,
            Self::Preference { .. } => ProposalKind::Preference,
            Self::Boundary { .. } => ProposalKind::Boundary,
            Self::Relationship { .. } => ProposalKind::Relationship,
            Self::Goal { .. } => ProposalKind::Goal,
            Self::Commitment { .. } => ProposalKind::Commitment,
            Self::Correction { .. } => ProposalKind::Correction,
            Self::Summary { .. } => ProposalKind::Summary,
            Self::Reflection { .. } => ProposalKind::Reflection,
        }
    }

    fn validate_shape(
        &self,
        config: &CognitionConfig,
        mentions: &BTreeSet<String>,
    ) -> CognitionResult<()> {
        match self {
            Self::Claim {
                subject_ref,
                predicate_ref,
                object,
            } => {
                require_mention(subject_ref, mentions)?;
                validate_text(predicate_ref, config, "claim.predicate_ref")?;
                validate_value(object, config, mentions)
            }
            Self::Preference {
                subject_ref,
                domain,
                value: _,
                strength: _,
            } => {
                validate_text(subject_ref, config, "preference.subject_ref")?;
                validate_text(domain, config, "preference.domain")
            }
            Self::Boundary {
                subject_ref,
                rule,
                applies_to,
            } => {
                validate_text(subject_ref, config, "boundary.subject_ref")?;
                if let BoundaryRule::Custom { statement } = rule {
                    validate_text(statement, config, "boundary.statement")?;
                }
                for reference in applies_to {
                    validate_text(reference, config, "boundary.applies_to")?;
                }
                Ok(())
            }
            Self::Relationship {
                participant_refs,
                relationship_kind,
                signal: _,
                roles,
                interaction_norms,
            } => {
                if participant_refs.len() < 2 {
                    return Err(CognitionError::InvalidProposal {
                        field: "relationship.participant_refs",
                        reason: "at least two participants are required",
                    });
                }
                for reference in participant_refs {
                    validate_text(reference, config, "relationship.participant_ref")?;
                }
                if let RelationshipKind::Other(label) = relationship_kind {
                    validate_text(label, config, "relationship.kind")?;
                }
                for (reference, role) in roles {
                    validate_text(reference, config, "relationship.role_ref")?;
                    validate_text(role, config, "relationship.role")?;
                }
                for norm in interaction_norms {
                    validate_text(norm, config, "relationship.interaction_norm")?;
                }
                Ok(())
            }
            Self::Goal {
                owner_ref,
                statement,
                status: _,
                horizon: _,
            } => {
                validate_text(owner_ref, config, "goal.owner_ref")?;
                validate_text(statement, config, "goal.statement")
            }
            Self::Commitment {
                owner_ref,
                beneficiary_ref,
                statement,
                due: _,
                trigger,
                status: _,
            } => {
                validate_text(owner_ref, config, "commitment.owner_ref")?;
                if let Some(reference) = beneficiary_ref {
                    validate_text(reference, config, "commitment.beneficiary_ref")?;
                }
                validate_text(statement, config, "commitment.statement")?;
                if let Some(Condition::TextCue { text }) = trigger {
                    validate_text(text, config, "commitment.trigger")?;
                }
                Ok(())
            }
            Self::Correction {
                target_claim_ref,
                replacement_subject_ref,
                predicate_ref,
                replacement,
                reason,
                was_never_true: _,
            } => {
                validate_text(target_claim_ref, config, "correction.target_claim_ref")?;
                require_mention(replacement_subject_ref, mentions)?;
                validate_text(predicate_ref, config, "correction.predicate_ref")?;
                validate_text(reason, config, "correction.reason")?;
                validate_value(replacement, config, mentions)
            }
            Self::Summary {
                owner_ref,
                level,
                content: _,
                known_omissions,
            } => {
                require_mention(owner_ref, mentions)?;
                if *level > config.max_summary_level {
                    return Err(CognitionError::InvalidProposal {
                        field: "summary.level",
                        reason: "summary abstraction level exceeds policy",
                    });
                }
                for omission in known_omissions {
                    validate_text(omission, config, "summary.known_omission")?;
                }
                Ok(())
            }
            Self::Reflection {
                owner_ref,
                pattern_kind: _,
                label,
                hypothesis,
                negative_evidence,
                required_verification,
                proposes_causality: _,
                sensitive_trait: _,
            } => {
                require_mention(owner_ref, mentions)?;
                validate_text(label, config, "reflection.label")?;
                validate_text(hypothesis, config, "reflection.hypothesis")?;
                let negative: BTreeSet<_> = negative_evidence
                    .iter()
                    .map(|item| item.evidence_id)
                    .collect();
                if negative.len() != negative_evidence.len() {
                    return Err(CognitionError::InvalidProposal {
                        field: "reflection.negative_evidence",
                        reason: "duplicate evidence citation",
                    });
                }
                for item in required_verification {
                    validate_text(item, config, "reflection.required_verification")?;
                }
                Ok(())
            }
        }
    }
}

/// Stable proposal class used in thresholds and reference evaluation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    Claim,
    Preference,
    Boundary,
    Relationship,
    Goal,
    Commitment,
    Correction,
    Summary,
    Reflection,
}

fn validate_value(
    value: &ProposedValue,
    config: &CognitionConfig,
    mentions: &BTreeSet<String>,
) -> CognitionResult<()> {
    match value {
        ProposedValue::Entity { mention_ref } => require_mention(mention_ref, mentions),
        ProposedValue::String(value) => validate_text(value, config, "value.string"),
        ProposedValue::Float(value) if !value.is_finite() => Err(CognitionError::InvalidProposal {
            field: "value.float",
            reason: "must be finite",
        }),
        ProposedValue::Structured(value) if value.is_null() => {
            Err(CognitionError::InvalidProposal {
                field: "value.structured",
                reason: "must not be null",
            })
        }
        _ => Ok(()),
    }
}

fn require_mention(reference: &str, mentions: &BTreeSet<String>) -> CognitionResult<()> {
    if mentions.contains(reference) {
        Ok(())
    } else {
        Err(CognitionError::InvalidProposal {
            field: "mention_ref",
            reason: "does not name a local mention in this candidate",
        })
    }
}

fn validate_text(
    value: &str,
    config: &CognitionConfig,
    field: &'static str,
) -> CognitionResult<()> {
    if value.trim().is_empty() {
        return Err(CognitionError::InvalidProposal {
            field,
            reason: "must not be blank",
        });
    }
    if value.chars().count() > config.max_text_chars {
        return Err(CognitionError::InvalidProposal {
            field,
            reason: "text exceeds configured character limit",
        });
    }
    Ok(())
}
