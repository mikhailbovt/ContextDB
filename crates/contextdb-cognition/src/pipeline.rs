use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    AcceptanceState, BitemporalRange, Boundary, CandidateAdjudication, CandidateId, CandidateType,
    CandidateValidationState, Claim, ClaimId, ClaimObject, ClaimRevision, CommitRange, CommitSeq,
    Commitment, ConfidenceProfile, ConflictResolution, ConflictSet, ConflictSetId,
    ConflictSetRevision, ConflictState, DerivationId, DerivationKind, DerivationRef,
    EpistemicBasis, EpistemicState, Goal, LineageNode, MemoryCandidate, MemoryRevisionHeader,
    MemorySubjectId, ModelCall, MutationId, Node, NodeId, NodeRevision, NonEmptyVec, ObservationId,
    PipelineIdentity, Preference, PromotionScore, RelationshipState, RevisionNumber,
    SemanticEnvelope, SemanticMutationSet, SnapshotRef, SummaryId, TimeRange, TimestampMicros,
    TypedMemoryMutation, Validate, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AuthorizationContext, CandidateProposal, ChangeClassification, ChangeDecision, ClaimIndex,
    CognitionConfig, CognitionError, CognitionResult, DirtyReason, DirtyRegion, EntityIndex,
    EntityResolution, EntityResolutionTrace, EvidenceCatalog, EvidenceCitation, EvidenceGate,
    ExistingClaim, PatternHypothesis, ProposalBatch, ProposalBody, ProposalKind, ProposalOrigin,
    ReferenceEntityResolver, RelationshipSignal, TemporalClass, ValidatedEvidence,
    ValidatedSummary, ValidationIssue, classify_change, classify_temporal, input_digest,
    policy_digest, predicate_for, resolve_value, summary_source_digest,
};

/// Lifecycle of a versioned extraction/consolidation profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ProcessingMode {
    Initial,
    Shadow { previous_run: String },
    Reprocess { previous_run: String },
    Replay { original_run: String },
}

impl ProcessingMode {
    const fn is_shadow(&self) -> bool {
        matches!(self, Self::Shadow { .. })
    }
}

/// Auditable processing identity. A prompt/model update creates a new value;
/// it never silently replaces the lineage of earlier revisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingRun {
    pub id: String,
    pub pipeline: PipelineIdentity,
    pub mode: ProcessingMode,
    pub model_call: Option<ModelCall>,
}

impl ProcessingRun {
    fn validate(&self) -> CognitionResult<()> {
        if self.id.trim().is_empty() {
            return Err(CognitionError::InvalidProposal {
                field: "processing_run.id",
                reason: "must not be blank",
            });
        }
        self.pipeline.validate()?;
        if let Some(model_call) = &self.model_call {
            model_call.validate()?;
            if model_call.schema_version != self.pipeline.schema_version {
                return Err(CognitionError::InvalidProposal {
                    field: "processing_run.model_call.schema_version",
                    reason: "must match pipeline schema version",
                });
            }
        }
        let invalid_ancestor = match &self.mode {
            ProcessingMode::Initial => false,
            ProcessingMode::Shadow { previous_run }
            | ProcessingMode::Reprocess { previous_run } => {
                previous_run.trim().is_empty() || previous_run == &self.id
            }
            ProcessingMode::Replay { original_run } => original_run.trim().is_empty(),
        };
        if invalid_ancestor {
            return Err(CognitionError::InvalidProposal {
                field: "processing_run.previous",
                reason: "must name a distinct non-blank run",
            });
        }
        Ok(())
    }

    /// Returns the auditable model call used by this run, if any.
    #[must_use]
    pub fn model_call_id(&self) -> Option<contextdb_core::ModelCallId> {
        self.model_call.as_ref().map(|call| call.id)
    }
}

/// Snapshot-bound input to deterministic cognition adjudication. This is the
/// narrow adapter seam for graph/recall/runtime crates.
#[derive(Clone, Debug, PartialEq)]
pub struct AdjudicationInput {
    pub workspace_id: WorkspaceId,
    pub base_snapshot: SnapshotRef,
    pub reference_time: TimestampMicros,
    pub journal_refs: NonEmptyVec<ObservationId>,
    pub run: ProcessingRun,
    pub authorization: AuthorizationContext,
    /// Trusted target policy chosen before model execution. Its derivation is
    /// replaced per target; all other fields may only narrow source policy.
    pub publication_envelope: SemanticEnvelope,
    pub evidence: EvidenceCatalog,
    pub entities: EntityIndex,
    pub claims: ClaimIndex,
    pub subject_anchors: BTreeMap<String, MemorySubjectId>,
    pub predicate_anchors: BTreeMap<String, contextdb_core::PredicateDefinition>,
    pub claim_anchors: BTreeMap<String, ClaimId>,
    pub proposals: ProposalBatch,
}

/// Final deterministic outcome for one candidate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateDisposition {
    Promoted,
    Hypothesis,
    SummaryReady,
    Quarantined,
    Rejected,
    NoOp,
    ShadowValidated,
}

/// Explainable per-candidate decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateDecision {
    pub local_id: String,
    pub candidate_id: CandidateId,
    pub kind: ProposalKind,
    pub disposition: CandidateDisposition,
    pub issues: Vec<ValidationIssue>,
    pub promotion: PromotionScore,
    pub temporal_class: Option<TemporalClass>,
    pub change: Option<ChangeDecision>,
    pub entity_resolution: Vec<EntityResolutionTrace>,
}

/// Sanitized record for a quarantine store. Unsafe proposals are represented by
/// digest and reason even when no core `MemoryCandidate` can safely reference
/// their fabricated or unauthorized evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    pub candidate_id: CandidateId,
    pub local_id: String,
    pub proposal_digest: contextdb_core::ContentDigest,
    pub disposition: CandidateDisposition,
    pub issues: Vec<ValidationIssue>,
    pub canonical_candidate: Option<MemoryCandidate>,
}

/// Counters emitted even when the correct semantic result is no-op.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineMetrics {
    pub proposed: u64,
    pub promoted: u64,
    pub hypotheses: u64,
    pub summaries_ready: u64,
    pub quarantined: u64,
    pub rejected: u64,
    pub no_op: u64,
    pub corrections_promoted: u64,
    pub hallucinated_evidence_rejected: u64,
    pub authorized_entities_examined: u64,
}

/// Overall run status, separate from individual candidate decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    SemanticPlan,
    AuditOnly,
    NoOp,
    Shadow,
}

/// Complete M10 planning result. Only `transaction` may be submitted to the
/// ordered commit coordinator, and shadow mode always leaves it empty.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdjudicationOutput {
    pub processing_run: String,
    pub status: PipelineStatus,
    pub decisions: Vec<CandidateDecision>,
    pub quarantine: Vec<QuarantineRecord>,
    pub transaction: Option<SemanticMutationSet>,
    pub dirty_regions: Vec<DirtyRegion>,
    pub summaries: Vec<ValidatedSummary>,
    pub hypotheses: Vec<PatternHypothesis>,
    pub metrics: PipelineMetrics,
}

impl AdjudicationOutput {
    /// Canonical logical digest used for recorded-output replay comparison.
    pub fn logical_digest(&self) -> CognitionResult<contextdb_core::ContentDigest> {
        let encoded = serde_json::to_vec(self)
            .map_err(|error| CognitionError::Serialization(error.to_string()))?;
        Ok(contextdb_core::ContentDigest::from_bytes(
            *blake3::hash(&encoded).as_bytes(),
        ))
    }
}

/// Deterministic, no-provider adjudication oracle.
#[derive(Clone, Debug)]
pub struct CognitionEngine {
    config: CognitionConfig,
}

impl CognitionEngine {
    /// Creates an engine after validating all thresholds and limits.
    pub fn new(config: CognitionConfig) -> CognitionResult<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Returns the immutable reference policy.
    #[must_use]
    pub const fn config(&self) -> &CognitionConfig {
        &self.config
    }

    /// Runs the complete proposal → validation → adjudication → transaction
    /// pipeline at one semantic snapshot.
    pub fn adjudicate(&self, input: &AdjudicationInput) -> CognitionResult<AdjudicationOutput> {
        self.validate_input(input)?;
        let expected_input =
            input_digest(&input.journal_refs, &input.evidence, &input.authorization);
        let expected_policy = policy_digest(&input.publication_envelope)?;
        input.proposals.validate_contract(
            &self.config,
            &input.run.id,
            expected_input,
            expected_policy,
            input.run.model_call_id(),
        )?;
        if let Some(model_call) = &input.run.model_call {
            if model_call.input_hash != expected_input
                || model_call.output_hash != input.proposals.canonical_digest()?
            {
                return Err(CognitionError::ModelCallMismatch);
            }
            let external_allowed = input
                .publication_envelope
                .security
                .allow_external_processing
                && input.publication_envelope.use_policy.external_model_use
                    == contextdb_core::PolicyDecision::Allow;
            if model_call.external_processing_allowed && !external_allowed {
                return Err(CognitionError::ModelCallMismatch);
            }
        }

        let next_seq = input
            .base_snapshot
            .commit_seq
            .checked_next()
            .ok_or(CognitionError::CommitSequenceExhausted)?;
        let ids = StableIds::new(expected_input, expected_policy, &input.run.id);
        let mut accumulator = SemanticAccumulator::default();
        let mut decisions = Vec::new();
        let mut quarantine = Vec::new();
        let mut summaries = Vec::new();
        let mut hypotheses = Vec::new();
        let mut metrics = PipelineMetrics {
            proposed: input.proposals.candidates.len() as u64,
            ..PipelineMetrics::default()
        };

        let mut ordered: Vec<_> = input.proposals.candidates.iter().collect();
        ordered.sort_by(|left, right| left.local_id.cmp(&right.local_id));
        for proposal in ordered {
            let evaluated = self.evaluate_candidate(input, proposal, next_seq, &ids)?;
            metrics.authorized_entities_examined =
                metrics.authorized_entities_examined.saturating_add(
                    evaluated
                        .decision
                        .entity_resolution
                        .iter()
                        .map(|trace| trace.authorized_examined as u64)
                        .sum::<u64>(),
                );
            update_metrics(&mut metrics, &evaluated.decision);
            if !input.run.mode.is_shadow() {
                if let Some(candidate) = evaluated.canonical_candidate.clone() {
                    accumulator.candidate_writes.push(candidate);
                }
                if matches!(
                    evaluated.decision.disposition,
                    CandidateDisposition::Promoted | CandidateDisposition::Hypothesis
                ) {
                    self.materialize(
                        input,
                        proposal,
                        &evaluated,
                        next_seq,
                        &ids,
                        &mut accumulator,
                        &mut summaries,
                        &mut hypotheses,
                    )?;
                } else if evaluated.decision.disposition == CandidateDisposition::SummaryReady {
                    self.materialize_summary(
                        input,
                        proposal,
                        &evaluated,
                        next_seq,
                        &ids,
                        &mut summaries,
                    )?;
                }
            }
            quarantine.push(QuarantineRecord {
                candidate_id: evaluated.decision.candidate_id,
                local_id: evaluated.decision.local_id.clone(),
                proposal_digest: proposal_digest(proposal)?,
                disposition: evaluated.decision.disposition,
                issues: evaluated.decision.issues.clone(),
                canonical_candidate: evaluated.canonical_candidate,
            });
            decisions.push(evaluated.decision);
        }

        let dirty_regions: Vec<DirtyRegion> = accumulator
            .dirty_region(input.base_snapshot)
            .into_iter()
            .collect();
        for region in &dirty_regions {
            accumulator.derived_work.extend(region.derived_work());
        }
        deduplicate_work(&mut accumulator.derived_work);

        let transaction = if input.run.mode.is_shadow() || accumulator.is_empty() {
            None
        } else {
            let transaction = accumulator.into_transaction(
                ids.mutation("semantic-transaction")?,
                input.base_snapshot,
                input.journal_refs.clone(),
            );
            transaction.validate()?;
            Some(transaction)
        };
        let status = if input.run.mode.is_shadow() {
            PipelineStatus::Shadow
        } else if decisions.is_empty() {
            PipelineStatus::NoOp
        } else if transaction
            .as_ref()
            .is_some_and(SemanticMutationSet::has_semantic_writes)
            || !summaries.is_empty()
        {
            PipelineStatus::SemanticPlan
        } else if transaction.is_some() {
            PipelineStatus::AuditOnly
        } else {
            PipelineStatus::NoOp
        };
        if status == PipelineStatus::NoOp && metrics.no_op == 0 {
            metrics.no_op = 1;
        }

        Ok(AdjudicationOutput {
            processing_run: input.run.id.clone(),
            status,
            decisions,
            quarantine,
            transaction,
            dirty_regions,
            summaries,
            hypotheses,
            metrics,
        })
    }

    fn validate_input(&self, input: &AdjudicationInput) -> CognitionResult<()> {
        input.run.validate()?;
        if input.workspace_id != input.authorization.workspace_id {
            return Err(CognitionError::InvalidProposal {
                field: "authorization.workspace_id",
                reason: "must match adjudication workspace",
            });
        }
        input.publication_envelope.validate()?;
        if !input
            .publication_envelope
            .ownership
            .allowed_purposes
            .contains(&input.authorization.purpose)
        {
            return Err(CognitionError::InvalidProposal {
                field: "authorization.purpose",
                reason: "publication policy does not allow the authenticated purpose",
            });
        }

        // Validate only the policy-authorized evidence projection. Prohibited
        // records cannot alter failure, timing, or scoring of this run.
        let authorized_catalog = EvidenceCatalog(
            input
                .evidence
                .0
                .iter()
                .filter(|(id, _)| input.authorization.permitted_evidence.contains(id))
                .map(|(id, record)| (*id, record.clone()))
                .collect(),
        );
        authorized_catalog.validate(&self.config)?;
        for record in input.entities.0.values().filter(|record| {
            input
                .authorization
                .permitted_nodes
                .contains(&record.node.id)
                && record.node.workspace_id == input.workspace_id
        }) {
            record.validate()?;
        }
        for claim in input.claims.0.values().filter(|claim| {
            input
                .authorization
                .permitted_claims
                .contains(&claim.claim.id)
                && claim.claim.workspace_id == input.workspace_id
        }) {
            claim.validate()?;
        }
        for predicate in input.predicate_anchors.values() {
            predicate.validate()?;
        }
        if input.run.model_call.is_some()
            != !matches!(input.proposals.origin, ProposalOrigin::Deterministic)
        {
            return Err(CognitionError::ModelCallMismatch);
        }
        Ok(())
    }

    fn evaluate_candidate(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        next_seq: CommitSeq,
        ids: &StableIds,
    ) -> CognitionResult<EvaluatedCandidate> {
        let candidate_id = ids.candidate(&proposal.local_id)?;
        let raw_inputs: Vec<_> = proposal
            .evidence
            .iter()
            .map(|citation| LineageNode::Evidence {
                id: citation.evidence_id,
            })
            .collect();
        let candidate_envelope = derive_envelope(
            &input.publication_envelope,
            &input.run,
            &input.proposals.origin,
            &raw_inputs,
            LineageNode::Candidate { id: candidate_id },
            None,
            ids,
            &format!("candidate:{}", proposal.local_id),
        )?;
        let evidence = match EvidenceGate::validate_candidate(
            proposal,
            &input.evidence,
            &input.authorization,
            &input.journal_refs,
            &candidate_envelope,
            candidate_id,
        ) {
            Ok(value) => value,
            Err(mut issues) => {
                issues.sort();
                issues.dedup();
                let promotion = zero_promotion();
                let disposition = disposition_for_issues(&issues);
                return Ok(EvaluatedCandidate {
                    decision: CandidateDecision {
                        local_id: proposal.local_id.clone(),
                        candidate_id,
                        kind: proposal.kind(),
                        disposition,
                        issues,
                        promotion,
                        temporal_class: None,
                        change: None,
                        entity_resolution: Vec::new(),
                    },
                    canonical_candidate: None,
                    evidence: None,
                    negative_evidence: Vec::new(),
                    resolved: None,
                    valid_time: None,
                });
            }
        };

        let mut negative_evidence = Vec::new();
        let mut pre_resolution_issues = Vec::new();
        if let ProposalBody::Reflection {
            negative_evidence: citations,
            ..
        } = &proposal.body
            && !citations.is_empty()
        {
            let mut negative = proposal.clone();
            negative.evidence = citations.clone();
            match EvidenceGate::validate_candidate(
                &negative,
                &input.evidence,
                &input.authorization,
                &input.journal_refs,
                &candidate_envelope,
                candidate_id,
            ) {
                Ok(validated) => negative_evidence = validated.evidence_ids,
                Err(found) => pre_resolution_issues.extend(found),
            }
        }

        let mut traces = Vec::new();
        let mut resolved_mentions = BTreeMap::new();
        let mut resolved_types = BTreeMap::new();
        let mut issues = pre_resolution_issues;
        let mut ambiguity_penalty = 0.0_f32;
        for mention in &proposal.mentions {
            let trace = ReferenceEntityResolver::resolve(
                mention,
                input.workspace_id,
                &input.publication_envelope.scopes,
                &input.entities,
                &input.authorization,
                &self.config,
            );
            match &trace.result {
                EntityResolution::Existing { node_id, .. } => {
                    let Some(record) = input.entities.0.get(node_id) else {
                        issues.push(ValidationIssue::UnknownEntityMention);
                        traces.push(trace);
                        continue;
                    };
                    if candidate_envelope
                        .validate_derived_from(&record.head.envelope)
                        .is_err()
                    {
                        issues.push(ValidationIssue::PolicyWouldBroaden);
                    } else {
                        resolved_mentions.insert(mention.local_ref.clone(), *node_id);
                        resolved_types
                            .insert(mention.local_ref.clone(), record.node.node_type.clone());
                    }
                }
                EntityResolution::CreateNew => {
                    let node_id = ids.node(&format!(
                        "mention:{}:{}",
                        proposal.local_id, mention.local_ref
                    ))?;
                    resolved_mentions.insert(mention.local_ref.clone(), node_id);
                    resolved_types.insert(mention.local_ref.clone(), mention.expected_type.clone());
                }
                EntityResolution::Ambiguous { .. } => {
                    ambiguity_penalty = 1.0;
                    issues.push(if mention.sensitive {
                        ValidationIssue::SensitiveEntityRequiresReview
                    } else {
                        ValidationIssue::EntityAmbiguous
                    });
                }
                EntityResolution::Rejected { issue } => issues.push(issue.clone()),
            }
            traces.push(trace);
        }

        let (valid_time, temporal_class) =
            match classify_temporal(proposal.temporal, &evidence, input.reference_time) {
                Ok(value) => (Some(value.0), Some(value.1)),
                Err(issue) => {
                    issues.push(issue);
                    (None, None)
                }
            };
        let resolved = self.resolve_body(
            input,
            proposal,
            &resolved_mentions,
            &resolved_types,
            &mut issues,
        );
        let change = match (&resolved, valid_time) {
            (
                Some(ResolvedBody::Claim {
                    subject,
                    predicate,
                    object,
                    ..
                }),
                Some(valid_time),
            ) => Some(classify_change(
                *subject,
                predicate,
                object,
                valid_time,
                proposal
                    .temporal
                    .and_then(|temporal| temporal.valid_from)
                    .is_some(),
                &candidate_envelope,
                &input.claims,
                &input.authorization,
            )),
            (Some(ResolvedBody::Correction { target, .. }), _) => Some(ChangeDecision {
                classification: ChangeClassification::Correction,
                compared_claim: Some(target.claim.id),
            }),
            _ => None,
        };
        if let Some(change) = &change
            && let Some(existing_id) = change.compared_claim
            && matches!(
                change.classification,
                ChangeClassification::Duplicate
                    | ChangeClassification::Refinement
                    | ChangeClassification::TemporalTransition
                    | ChangeClassification::Correction
                    | ChangeClassification::Contradiction
            )
            && let Some(existing) = input.claims.0.get(&existing_id)
            && candidate_envelope
                .validate_derived_from(&existing.head.envelope)
                .is_err()
        {
            issues.push(ValidationIssue::PolicyWouldBroaden);
        }

        let promotion = promotion_score(
            proposal.kind(),
            &evidence,
            ambiguity_penalty,
            &input.publication_envelope,
        );
        self.apply_hard_rules(
            input,
            proposal,
            resolved.as_ref(),
            &evidence,
            change.as_ref(),
            &promotion,
            &mut issues,
        );
        issues.sort();
        issues.dedup();

        let mut disposition = if issues.iter().any(ValidationIssue::is_rejection) {
            CandidateDisposition::Rejected
        } else if !issues.is_empty() {
            CandidateDisposition::Quarantined
        } else {
            match proposal.kind() {
                ProposalKind::Reflection => CandidateDisposition::Hypothesis,
                ProposalKind::Summary => CandidateDisposition::SummaryReady,
                _ => CandidateDisposition::Promoted,
            }
        };
        if change.as_ref().is_some_and(|decision| {
            decision.classification == ChangeClassification::Duplicate
                && decision.compared_claim.is_some_and(|claim_id| {
                    input.claims.0.get(&claim_id).is_some_and(|existing| {
                        evidence
                            .evidence_ids
                            .iter()
                            .all(|id| existing.head.evidence.contains(id))
                    })
                })
        }) {
            disposition = CandidateDisposition::NoOp;
            if !issues.contains(&ValidationIssue::DuplicateWithoutNewEvidence) {
                issues.push(ValidationIssue::DuplicateWithoutNewEvidence);
            }
        }
        if input.run.mode.is_shadow()
            && matches!(
                disposition,
                CandidateDisposition::Promoted
                    | CandidateDisposition::Hypothesis
                    | CandidateDisposition::SummaryReady
            )
        {
            disposition = CandidateDisposition::ShadowValidated;
            issues.push(ValidationIssue::ShadowRunCannotPublish);
        }

        let canonical_candidate = build_core_candidate(
            input,
            proposal,
            candidate_id,
            &evidence,
            candidate_envelope,
            promotion,
            disposition,
            &issues,
            next_seq,
        )?;
        Ok(EvaluatedCandidate {
            decision: CandidateDecision {
                local_id: proposal.local_id.clone(),
                candidate_id,
                kind: proposal.kind(),
                disposition,
                issues,
                promotion,
                temporal_class,
                change,
                entity_resolution: traces,
            },
            canonical_candidate: Some(canonical_candidate),
            evidence: Some(evidence),
            negative_evidence,
            resolved,
            valid_time,
        })
    }

    fn resolve_body(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        mentions: &BTreeMap<String, NodeId>,
        mention_types: &BTreeMap<String, contextdb_core::NodeType>,
        issues: &mut Vec<ValidationIssue>,
    ) -> Option<ResolvedBody> {
        let result = (|| -> Result<ResolvedBody, ValidationIssue> {
            match &proposal.body {
                ProposalBody::Claim {
                    subject_ref,
                    predicate_ref,
                    object,
                } => {
                    let subject = *mentions
                        .get(subject_ref)
                        .ok_or(ValidationIssue::UnknownEntityMention)?;
                    let subject_type = mention_types
                        .get(subject_ref)
                        .cloned()
                        .ok_or(ValidationIssue::UnknownEntityMention)?;
                    let predicate = predicate_for(predicate_ref, &input.predicate_anchors)?.clone();
                    let object = resolve_value(object, mentions)?;
                    Ok(ResolvedBody::Claim {
                        subject,
                        subject_type,
                        predicate,
                        object,
                    })
                }
                ProposalBody::Preference {
                    subject_ref,
                    domain,
                    value,
                    strength,
                } => Ok(ResolvedBody::Preference {
                    subject: subject_anchor(input, subject_ref)?,
                    domain: domain.clone(),
                    value: value.clone(),
                    strength: *strength,
                }),
                ProposalBody::Boundary {
                    subject_ref,
                    rule,
                    applies_to,
                } => {
                    let mut targets = Vec::new();
                    for reference in applies_to {
                        targets.push(subject_anchor(input, reference)?);
                    }
                    Ok(ResolvedBody::Boundary {
                        subject: subject_anchor(input, subject_ref)?,
                        rule: rule.clone(),
                        applies_to: targets,
                    })
                }
                ProposalBody::Relationship {
                    participant_refs,
                    relationship_kind,
                    signal,
                    roles,
                    interaction_norms,
                } => {
                    let mut participants = Vec::new();
                    for reference in participant_refs {
                        participants.push(subject_anchor(input, reference)?);
                    }
                    let mut resolved_roles = BTreeMap::new();
                    for (reference, role) in roles {
                        resolved_roles.insert(subject_anchor(input, reference)?, role.clone());
                    }
                    Ok(ResolvedBody::Relationship {
                        participants,
                        relationship_kind: relationship_kind.clone(),
                        signal: *signal,
                        roles: resolved_roles,
                        interaction_norms: interaction_norms.clone(),
                    })
                }
                ProposalBody::Goal {
                    owner_ref,
                    statement,
                    status,
                    horizon,
                } => Ok(ResolvedBody::Goal {
                    owner: subject_anchor(input, owner_ref)?,
                    statement: statement.clone(),
                    status: *status,
                    horizon: *horizon,
                }),
                ProposalBody::Commitment {
                    owner_ref,
                    beneficiary_ref,
                    statement,
                    due,
                    trigger,
                    status,
                } => Ok(ResolvedBody::Commitment {
                    owner: subject_anchor(input, owner_ref)?,
                    beneficiary: beneficiary_ref
                        .as_ref()
                        .map(|reference| subject_anchor(input, reference))
                        .transpose()?,
                    statement: statement.clone(),
                    due: *due,
                    trigger: trigger.clone(),
                    status: *status,
                }),
                ProposalBody::Correction {
                    target_claim_ref,
                    replacement_subject_ref,
                    predicate_ref,
                    replacement,
                    reason,
                    was_never_true,
                } => {
                    let claim_id = *input
                        .claim_anchors
                        .get(target_claim_ref)
                        .ok_or(ValidationIssue::UnknownClaimAnchor)?;
                    if !input.authorization.permitted_claims.contains(&claim_id) {
                        return Err(ValidationIssue::UnknownClaimAnchor);
                    }
                    let target = input
                        .claims
                        .0
                        .get(&claim_id)
                        .cloned()
                        .ok_or(ValidationIssue::UnknownClaimAnchor)?;
                    let subject = *mentions
                        .get(replacement_subject_ref)
                        .ok_or(ValidationIssue::UnknownEntityMention)?;
                    let subject_type = mention_types
                        .get(replacement_subject_ref)
                        .cloned()
                        .ok_or(ValidationIssue::UnknownEntityMention)?;
                    let predicate = predicate_for(predicate_ref, &input.predicate_anchors)?.clone();
                    let replacement = resolve_value(replacement, mentions)?;
                    Ok(ResolvedBody::Correction {
                        target: Box::new(target),
                        subject,
                        subject_type,
                        predicate,
                        replacement,
                        reason: reason.clone(),
                        was_never_true: *was_never_true,
                    })
                }
                ProposalBody::Summary {
                    owner_ref,
                    level,
                    content,
                    known_omissions,
                } => Ok(ResolvedBody::Summary {
                    owner: *mentions
                        .get(owner_ref)
                        .ok_or(ValidationIssue::UnknownEntityMention)?,
                    level: *level,
                    content: content.clone(),
                    known_omissions: known_omissions.clone(),
                }),
                ProposalBody::Reflection {
                    owner_ref,
                    pattern_kind,
                    label,
                    hypothesis,
                    negative_evidence,
                    required_verification,
                    proposes_causality,
                    sensitive_trait,
                } => Ok(ResolvedBody::Reflection {
                    owner: *mentions
                        .get(owner_ref)
                        .ok_or(ValidationIssue::UnknownEntityMention)?,
                    pattern_kind: *pattern_kind,
                    label: label.clone(),
                    hypothesis: hypothesis.clone(),
                    negative_evidence: negative_evidence.clone(),
                    required_verification: required_verification.clone(),
                    proposes_causality: *proposes_causality,
                    sensitive_trait: *sensitive_trait,
                }),
            }
        })();
        match result {
            Ok(value) => Some(value),
            Err(issue) => push_issue(issues, issue),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "hard rules are explicit audit inputs"
    )]
    fn apply_hard_rules(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        resolved: Option<&ResolvedBody>,
        evidence: &ValidatedEvidence,
        change: Option<&ChangeDecision>,
        promotion: &PromotionScore,
        issues: &mut Vec<ValidationIssue>,
    ) {
        let explicit_hard_rule = match resolved {
            Some(ResolvedBody::Preference { subject, .. })
            | Some(ResolvedBody::Boundary { subject, .. }) => {
                evidence.asserted_by(input.authorization.actor, *subject)
            }
            Some(ResolvedBody::Relationship { participants, .. }) => participants
                .iter()
                .any(|subject| evidence.asserted_by(input.authorization.actor, *subject)),
            Some(ResolvedBody::Correction { .. }) => evidence
                .actor_assertions
                .iter()
                .any(|(actor, _)| *actor == input.authorization.actor),
            _ => false,
        };
        if !explicit_hard_rule
            && promotion.overall < self.config.promotion_threshold(proposal.kind())
        {
            issues.push(ValidationIssue::LowPromotionScore);
        }
        match resolved {
            Some(ResolvedBody::Preference { subject, .. }) => {
                if !evidence.asserted_by(input.authorization.actor, *subject)
                    && evidence.source_families.len() < self.config.min_preference_source_families
                {
                    issues.push(ValidationIssue::PreferenceNeedsExplicitOrIndependentSupport);
                }
            }
            Some(ResolvedBody::Boundary { subject, .. }) => {
                if !evidence.asserted_by(input.authorization.actor, *subject) {
                    issues.push(ValidationIssue::BoundaryNeedsExplicitAuthority);
                }
            }
            Some(ResolvedBody::Relationship {
                participants,
                signal,
                ..
            }) => {
                if matches!(
                    signal,
                    RelationshipSignal::InferredEmotion
                        | RelationshipSignal::PsychologicalDiagnosis
                        | RelationshipSignal::ConsciousnessClaim
                        | RelationshipSignal::JointOwnershipClaim
                ) {
                    issues.push(ValidationIssue::RelationshipOverreach);
                } else {
                    let explicit = participants
                        .iter()
                        .any(|subject| evidence.asserted_by(input.authorization.actor, *subject));
                    let strong_signal = matches!(
                        signal,
                        RelationshipSignal::ExplicitRole
                            | RelationshipSignal::ExplicitBoundary
                            | RelationshipSignal::SharedCommitment
                            | RelationshipSignal::RepeatedCommunicationNorm
                            | RelationshipSignal::SharedReference
                    );
                    if !strong_signal
                        || (!explicit
                            && evidence.source_families.len()
                                < self.config.min_relationship_source_families)
                    {
                        issues.push(ValidationIssue::RelationshipNeedsStrongSupport);
                    }
                }
            }
            Some(ResolvedBody::Correction {
                target,
                subject,
                predicate,
                ..
            }) => {
                let explicit = evidence
                    .actor_assertions
                    .iter()
                    .any(|(actor, _)| *actor == input.authorization.actor);
                if !explicit {
                    issues.push(ValidationIssue::CorrectionNeedsExplicitAuthority);
                }
                if target.claim.subject != *subject || target.claim.predicate != predicate.id {
                    issues.push(ValidationIssue::CorrectionTargetMismatch);
                }
            }
            Some(ResolvedBody::Reflection {
                negative_evidence,
                required_verification,
                proposes_causality,
                sensitive_trait,
                ..
            }) => {
                if evidence.evidence_ids.len() < self.config.min_reflection_support {
                    issues.push(ValidationIssue::ReflectionInsufficientSupport);
                }
                if negative_evidence.len() < self.config.min_reflection_negative_examples {
                    issues.push(ValidationIssue::ReflectionNeedsNegativeExamples);
                }
                if *sensitive_trait {
                    issues.push(ValidationIssue::ReflectionSensitiveTraitForbidden);
                }
                if *proposes_causality && required_verification.is_empty() {
                    issues.push(ValidationIssue::ReflectionCausalityUnverified);
                }
            }
            Some(ResolvedBody::Summary { .. }) if evidence.primary_count == 0 => {
                issues.push(ValidationIssue::SummaryDerivedOnly);
            }
            _ => {}
        }
        if change.is_some_and(|decision| {
            decision.classification == ChangeClassification::Duplicate
                && decision.compared_claim.is_none()
        }) {
            issues.push(ValidationIssue::UnknownClaimAnchor);
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "materialization makes transaction inputs explicit"
    )]
    fn materialize(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        evaluated: &EvaluatedCandidate,
        next_seq: CommitSeq,
        ids: &StableIds,
        accumulator: &mut SemanticAccumulator,
        summaries: &mut Vec<ValidatedSummary>,
        hypotheses: &mut Vec<PatternHypothesis>,
    ) -> CognitionResult<()> {
        let evidence = evaluated
            .evidence
            .as_ref()
            .ok_or(CognitionError::InvalidProposal {
                field: "materialize.evidence",
                reason: "validated evidence is required",
            })?;
        let valid_time = evaluated
            .valid_time
            .ok_or(CognitionError::InvalidProposal {
                field: "materialize.valid_time",
                reason: "validated time is required",
            })?;
        let resolved = evaluated
            .resolved
            .as_ref()
            .ok_or(CognitionError::InvalidProposal {
                field: "materialize.body",
                reason: "resolved body is required",
            })?;
        self.materialize_new_mentions(
            input,
            proposal,
            evaluated,
            valid_time,
            next_seq,
            ids,
            accumulator,
        )?;
        match resolved {
            ResolvedBody::Claim {
                subject,
                subject_type,
                predicate,
                object,
            } => self.materialize_claim(
                input,
                proposal,
                evaluated,
                *subject,
                subject_type,
                predicate,
                object.clone(),
                valid_time,
                next_seq,
                ids,
                accumulator,
            )?,
            ResolvedBody::Correction {
                target,
                subject,
                subject_type,
                predicate,
                replacement,
                reason,
                was_never_true,
            } => self.materialize_correction(
                input,
                proposal,
                evaluated,
                target,
                *subject,
                subject_type,
                predicate,
                replacement.clone(),
                reason,
                *was_never_true,
                valid_time,
                next_seq,
                ids,
                accumulator,
            )?,
            ResolvedBody::Preference {
                subject,
                domain,
                value,
                strength,
            } => {
                let node_id = ids.node(&format!("preference:{}", proposal.local_id))?;
                let header = memory_header(
                    input,
                    proposal,
                    evaluated,
                    node_id,
                    valid_time,
                    next_seq,
                    ids,
                    "preference",
                )?;
                let memory = Preference {
                    header: header.clone(),
                    subject: *subject,
                    domain: domain.clone(),
                    value: value.clone(),
                    strength: *strength,
                    context: input.publication_envelope.scopes.to_vec(),
                };
                add_typed_node(
                    input,
                    node_id,
                    contextdb_core::NodeType::Preference,
                    format!("Preference: {domain}"),
                    header,
                    next_seq,
                    TypedMemoryMutation::Preference(memory),
                    accumulator,
                );
            }
            ResolvedBody::Boundary {
                subject,
                rule,
                applies_to,
            } => {
                let node_id = ids.node(&format!("boundary:{}", proposal.local_id))?;
                let header = memory_header(
                    input, proposal, evaluated, node_id, valid_time, next_seq, ids, "boundary",
                )?;
                let memory = Boundary {
                    header: header.clone(),
                    subject: *subject,
                    rule: rule.clone(),
                    applies_to: applies_to.clone(),
                    contexts: input.publication_envelope.scopes.to_vec(),
                    severity: contextdb_core::BoundarySeverity::Required,
                };
                add_typed_node(
                    input,
                    node_id,
                    contextdb_core::NodeType::Boundary,
                    "Explicit boundary".to_owned(),
                    header,
                    next_seq,
                    TypedMemoryMutation::Boundary(memory),
                    accumulator,
                );
            }
            ResolvedBody::Goal {
                owner,
                statement,
                status,
                horizon,
            } => {
                let node_id = ids.node(&format!("goal:{}", proposal.local_id))?;
                let header = memory_header(
                    input, proposal, evaluated, node_id, valid_time, next_seq, ids, "goal",
                )?;
                let memory = Goal {
                    header: header.clone(),
                    owner: *owner,
                    statement: statement.clone(),
                    status: *status,
                    horizon: *horizon,
                    related_nodes: Vec::new(),
                };
                add_typed_node(
                    input,
                    node_id,
                    contextdb_core::NodeType::Goal,
                    statement.clone(),
                    header,
                    next_seq,
                    TypedMemoryMutation::Goal(memory),
                    accumulator,
                );
            }
            ResolvedBody::Commitment {
                owner,
                beneficiary,
                statement,
                due,
                trigger,
                status,
            } => {
                let node_id = ids.node(&format!("commitment:{}", proposal.local_id))?;
                let header = memory_header(
                    input,
                    proposal,
                    evaluated,
                    node_id,
                    valid_time,
                    next_seq,
                    ids,
                    "commitment",
                )?;
                let memory = Commitment {
                    header: header.clone(),
                    owner: *owner,
                    beneficiary: *beneficiary,
                    statement: statement.clone(),
                    due: *due,
                    trigger: trigger.clone(),
                    status: *status,
                };
                add_typed_node(
                    input,
                    node_id,
                    contextdb_core::NodeType::Commitment,
                    statement.clone(),
                    header,
                    next_seq,
                    TypedMemoryMutation::Commitment(memory),
                    accumulator,
                );
            }
            ResolvedBody::Relationship {
                participants,
                relationship_kind,
                signal: _,
                roles,
                interaction_norms,
            } => {
                let node_id = ids.node(&format!("relationship:{}", proposal.local_id))?;
                let header = memory_header(
                    input,
                    proposal,
                    evaluated,
                    node_id,
                    valid_time,
                    next_seq,
                    ids,
                    "relationship",
                )?;
                let memory = RelationshipState {
                    id: ids.relationship(&proposal.local_id)?,
                    header: header.clone(),
                    participants: NonEmptyVec::try_from_vec(
                        participants.clone(),
                        "relationship.participants",
                    )?,
                    relationship_kind: relationship_kind.clone(),
                    roles: roles.clone(),
                    interaction_norms: interaction_norms.clone(),
                    boundaries: Vec::new(),
                    shared_history_root: None,
                };
                add_typed_node(
                    input,
                    node_id,
                    contextdb_core::NodeType::Relationship,
                    "Relationship state".to_owned(),
                    header,
                    next_seq,
                    TypedMemoryMutation::Relationship(memory),
                    accumulator,
                );
            }
            ResolvedBody::Reflection {
                owner,
                pattern_kind,
                label,
                hypothesis,
                negative_evidence: _,
                required_verification,
                proposes_causality: _,
                sensitive_trait: _,
            } => {
                let node_id = ids.node(&format!("reflection:{}", proposal.local_id))?;
                let target = LineageNode::NodeRevision {
                    id: node_id,
                    revision: RevisionNumber::FIRST,
                };
                let negative_inputs = evaluated
                    .negative_evidence
                    .iter()
                    .copied()
                    .map(|id| LineageNode::Evidence { id })
                    .collect();
                let envelope = semantic_envelope(
                    input,
                    proposal,
                    evaluated,
                    target,
                    EpistemicBasis::Hypothesis,
                    ids,
                    "reflection",
                    negative_inputs,
                )?;
                let epistemic = EpistemicState {
                    basis: EpistemicBasis::Hypothesis,
                    acceptance: AcceptanceState::Accepted,
                    conflict: ConflictState::None,
                    lifecycle: contextdb_core::LifecycleState::Active,
                };
                let temporal = BitemporalRange {
                    valid_time,
                    transaction_time: CommitRange::new(next_seq, None)?,
                };
                let mut attributes = BTreeMap::new();
                attributes.insert(
                    "pattern_kind".to_owned(),
                    serde_json::to_value(pattern_kind)
                        .map_err(|error| CognitionError::Serialization(error.to_string()))?,
                );
                attributes.insert(
                    "hypothesis".to_owned(),
                    serde_json::Value::String(hypothesis.clone()),
                );
                attributes.insert(
                    "required_verification".to_owned(),
                    serde_json::to_value(required_verification)
                        .map_err(|error| CognitionError::Serialization(error.to_string()))?,
                );
                accumulator.node_creates.push(Node {
                    id: node_id,
                    workspace_id: input.workspace_id,
                    node_type: contextdb_core::NodeType::Reflection,
                    created_seq: next_seq,
                    retired_seq: None,
                    identity_state: contextdb_core::IdentityState::Canonical,
                    primary_scope: input.publication_envelope.scopes.first().clone(),
                });
                accumulator.node_revisions.push(NodeRevision {
                    node_id,
                    revision: RevisionNumber::FIRST,
                    temporal,
                    canonical_name: label.clone(),
                    attributes,
                    epistemic,
                    confidence: confidence(evaluated, proposal),
                    evidence: evidence.evidence_ids.clone(),
                    envelope: envelope.clone(),
                });
                hypotheses.push(PatternHypothesis {
                    node_id,
                    label: label.clone(),
                    hypothesis: hypothesis.clone(),
                    supporting_evidence: evidence.evidence_ids.clone(),
                    negative_evidence: evaluated.negative_evidence.clone(),
                    required_verification: required_verification.clone(),
                    envelope,
                });
                accumulator.dirty_roots.insert(*owner);
                accumulator.dirty_roots.insert(node_id);
                accumulator
                    .dirty_reasons
                    .insert(DirtyReason::ReflectionCandidate);
            }
            ResolvedBody::Summary { .. } => {
                self.materialize_summary(input, proposal, evaluated, next_seq, ids, summaries)?
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "summary lineage inputs are explicit"
    )]
    fn materialize_summary(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        evaluated: &EvaluatedCandidate,
        _next_seq: CommitSeq,
        ids: &StableIds,
        summaries: &mut Vec<ValidatedSummary>,
    ) -> CognitionResult<()> {
        let Some(ResolvedBody::Summary {
            owner,
            level,
            content,
            known_omissions,
        }) = &evaluated.resolved
        else {
            return Err(CognitionError::InvalidProposal {
                field: "summary.body",
                reason: "resolved summary is required",
            });
        };
        let evidence = evaluated
            .evidence
            .as_ref()
            .ok_or(CognitionError::InvalidProposal {
                field: "summary.evidence",
                reason: "validated evidence is required",
            })?;
        let valid_time = evaluated
            .valid_time
            .ok_or(CognitionError::InvalidProposal {
                field: "summary.time",
                reason: "validated time is required",
            })?;
        let summary_id = ids.summary(&proposal.local_id)?;
        let target = LineageNode::Summary { id: summary_id };
        let envelope = semantic_envelope(
            input,
            proposal,
            evaluated,
            target,
            EpistemicBasis::ModelInference,
            ids,
            "summary",
            Vec::new(),
        )?;
        let mut sources = evidence.lineage_inputs.clone();
        if let Some(entity) = input.entities.0.get(owner) {
            sources.push(LineageNode::NodeRevision {
                id: *owner,
                revision: entity.head.revision,
            });
        }
        sources.sort();
        sources.dedup();
        let encoded_content = serde_json::to_vec(content)
            .map_err(|error| CognitionError::Serialization(error.to_string()))?;
        let content_digest =
            contextdb_core::ContentDigest::from_bytes(*blake3::hash(&encoded_content).as_bytes());
        let publication = contextdb_core::MaintenanceMutationSet {
            id: ids.mutation(&format!("summary-publication:{}", proposal.local_id))?,
            base_snapshot: input.base_snapshot,
            operation: contextdb_core::MaintenanceOperation::SummaryRevision {
                summary_id,
                revision: 1,
                content_digest,
            },
            derived_work: vec![contextdb_core::DerivedWorkItem::LexicalIndex {
                node_ids: vec![*owner],
                claim_ids: Vec::new(),
            }],
        };
        publication.validate()?;
        summaries.push(ValidatedSummary {
            id: summary_id,
            owner: *owner,
            level: *level,
            content: content.clone(),
            sources: sources.clone(),
            source_digest: summary_source_digest(&sources),
            covered_time: valid_time,
            known_omissions: known_omissions.clone(),
            envelope,
            freshness: crate::SummaryFreshness::Current,
            publication,
        });
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "claim materialization mirrors semantic contract"
    )]
    fn materialize_claim(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        evaluated: &EvaluatedCandidate,
        subject: NodeId,
        subject_type: &contextdb_core::NodeType,
        predicate: &contextdb_core::PredicateDefinition,
        object: ClaimObject,
        valid_time: TimeRange,
        next_seq: CommitSeq,
        ids: &StableIds,
        accumulator: &mut SemanticAccumulator,
    ) -> CognitionResult<()> {
        let change = evaluated
            .decision
            .change
            .as_ref()
            .ok_or(CognitionError::InvalidProposal {
                field: "claim.change",
                reason: "claim classification is required",
            })?;
        match change.classification {
            ChangeClassification::Duplicate | ChangeClassification::Refinement => {
                let existing = existing_for_change(input, change)?;
                let mut evidence = existing.head.evidence.clone();
                evidence.extend(
                    evaluated
                        .evidence
                        .as_ref()
                        .into_iter()
                        .flat_map(|value| value.evidence_ids.iter().copied()),
                );
                evidence.sort();
                evidence.dedup();
                let revision = revised_claim(
                    input,
                    proposal,
                    evaluated,
                    existing,
                    object,
                    valid_time,
                    existing.head.epistemic.conflict,
                    existing.head.epistemic.lifecycle,
                    evidence,
                    next_seq,
                    ids,
                    "claim-revision",
                )?;
                contextdb_core::validate_claim_against_predicate(
                    predicate,
                    subject_type,
                    &revision,
                )?;
                accumulator.claim_revisions.push(revision);
                accumulator.dirty_claims.insert(existing.claim.id);
            }
            ChangeClassification::TemporalTransition => {
                let existing = existing_for_change(input, change)?;
                let transition_start = valid_time.start;
                let old_valid = TimeRange::new(
                    existing.head.temporal.valid_time.start,
                    Some(transition_start),
                )?;
                let historical_evidence = combined_evidence(existing, evaluated);
                let historical = revised_claim(
                    input,
                    proposal,
                    evaluated,
                    existing,
                    existing.head.object.clone(),
                    old_valid,
                    existing.head.epistemic.conflict,
                    contextdb_core::LifecycleState::Historical,
                    historical_evidence,
                    next_seq,
                    ids,
                    "transition-close",
                )?;
                accumulator.claim_revisions.push(historical);
                self.create_claim(
                    input,
                    proposal,
                    evaluated,
                    subject,
                    subject_type,
                    predicate,
                    object,
                    valid_time,
                    ConflictState::None,
                    vec![existing.claim.id],
                    next_seq,
                    ids,
                    accumulator,
                )?;
                accumulator.dirty_reasons.insert(DirtyReason::ClaimChanged);
            }
            ChangeClassification::Contradiction => {
                let existing = existing_for_change(input, change)?;
                let conflict_id = ids.conflict(&proposal.local_id)?;
                let new_claim_id = ids.claim(&proposal.local_id)?;
                let disputed_evidence = combined_evidence(existing, evaluated);
                let disputed_old = revised_claim(
                    input,
                    proposal,
                    evaluated,
                    existing,
                    existing.head.object.clone(),
                    existing.head.temporal.valid_time,
                    ConflictState::InConflict {
                        set_id: conflict_id,
                    },
                    existing.head.epistemic.lifecycle,
                    disputed_evidence,
                    next_seq,
                    ids,
                    "conflict-old",
                )?;
                accumulator.claim_revisions.push(disputed_old);
                self.create_claim_with_id(
                    input,
                    proposal,
                    evaluated,
                    new_claim_id,
                    subject,
                    subject_type,
                    predicate,
                    object,
                    valid_time,
                    ConflictState::InConflict {
                        set_id: conflict_id,
                    },
                    Vec::new(),
                    next_seq,
                    ids,
                    accumulator,
                )?;
                self.create_conflict(
                    input,
                    proposal,
                    evaluated,
                    conflict_id,
                    subject,
                    predicate.id,
                    existing.claim.id,
                    new_claim_id,
                    ConflictResolution::Unresolved,
                    next_seq,
                    ids,
                    accumulator,
                )?;
            }
            ChangeClassification::New
            | ChangeClassification::ScopedCoexistence
            | ChangeClassification::IndependentEvidence => self.create_claim(
                input,
                proposal,
                evaluated,
                subject,
                subject_type,
                predicate,
                object,
                valid_time,
                ConflictState::None,
                Vec::new(),
                next_seq,
                ids,
                accumulator,
            )?,
            ChangeClassification::Correction => {
                return Err(CognitionError::InvalidProposal {
                    field: "claim.change",
                    reason: "correction requires the correction proposal body",
                });
            }
        }
        accumulator.dirty_roots.insert(subject);
        accumulator.dirty_reasons.insert(DirtyReason::ClaimChanged);
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "correction is one explicit atomic plan"
    )]
    fn materialize_correction(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        evaluated: &EvaluatedCandidate,
        target: &ExistingClaim,
        subject: NodeId,
        subject_type: &contextdb_core::NodeType,
        predicate: &contextdb_core::PredicateDefinition,
        replacement: ClaimObject,
        reason: &str,
        was_never_true: bool,
        valid_time: TimeRange,
        next_seq: CommitSeq,
        ids: &StableIds,
        accumulator: &mut SemanticAccumulator,
    ) -> CognitionResult<()> {
        let conflict_id = ids.conflict(&format!("correction:{}", proposal.local_id))?;
        let replacement_id = ids.claim(&format!("correction:{}", proposal.local_id))?;
        let correction_evidence = combined_evidence(target, evaluated);
        let retracted = revised_claim(
            input,
            proposal,
            evaluated,
            target,
            target.head.object.clone(),
            target.head.temporal.valid_time,
            ConflictState::Resolved {
                set_id: conflict_id,
            },
            contextdb_core::LifecycleState::Retracted,
            correction_evidence,
            next_seq,
            ids,
            "correction-retract",
        )?;
        accumulator.claim_revisions.push(retracted);
        self.create_claim_with_id(
            input,
            proposal,
            evaluated,
            replacement_id,
            subject,
            subject_type,
            predicate,
            replacement,
            valid_time,
            ConflictState::Resolved {
                set_id: conflict_id,
            },
            vec![target.claim.id],
            next_seq,
            ids,
            accumulator,
        )?;
        self.create_conflict(
            input,
            proposal,
            evaluated,
            conflict_id,
            subject,
            predicate.id,
            target.claim.id,
            replacement_id,
            ConflictResolution::Corrected {
                replacement: replacement_id,
            },
            next_seq,
            ids,
            accumulator,
        )?;
        let correction_node = ids.node(&format!("correction-record:{}", proposal.local_id))?;
        let target_lineage = LineageNode::NodeRevision {
            id: correction_node,
            revision: RevisionNumber::FIRST,
        };
        let correction_envelope = semantic_envelope(
            input,
            proposal,
            evaluated,
            target_lineage,
            semantic_basis(input, evaluated),
            ids,
            "correction-record",
            vec![
                LineageNode::ClaimRevision {
                    id: target.claim.id,
                    revision: target.head.revision,
                },
                LineageNode::ClaimRevision {
                    id: replacement_id,
                    revision: RevisionNumber::FIRST,
                },
            ],
        )?;
        let mut correction_attributes = BTreeMap::new();
        correction_attributes.insert(
            "target_claim".to_owned(),
            serde_json::Value::String(target.claim.id.to_string()),
        );
        correction_attributes.insert(
            "replacement_claim".to_owned(),
            serde_json::Value::String(replacement_id.to_string()),
        );
        correction_attributes.insert(
            "was_never_true".to_owned(),
            serde_json::Value::Bool(was_never_true),
        );
        accumulator.node_creates.push(Node {
            id: correction_node,
            workspace_id: input.workspace_id,
            node_type: contextdb_core::NodeType::Correction,
            created_seq: next_seq,
            retired_seq: None,
            identity_state: contextdb_core::IdentityState::Canonical,
            primary_scope: input.publication_envelope.scopes.first().clone(),
        });
        accumulator.node_revisions.push(NodeRevision {
            node_id: correction_node,
            revision: RevisionNumber::FIRST,
            temporal: BitemporalRange {
                valid_time,
                transaction_time: CommitRange::new(next_seq, None)?,
            },
            canonical_name: reason.to_owned(),
            attributes: correction_attributes,
            epistemic: EpistemicState {
                basis: semantic_basis(input, evaluated),
                acceptance: AcceptanceState::Accepted,
                conflict: ConflictState::None,
                lifecycle: contextdb_core::LifecycleState::Active,
            },
            confidence: confidence(evaluated, proposal),
            evidence: evaluated
                .evidence
                .as_ref()
                .map_or_else(Vec::new, |value| value.evidence_ids.clone()),
            envelope: correction_envelope,
        });
        accumulator.dirty_roots.insert(correction_node);
        accumulator.dirty_roots.insert(subject);
        accumulator.dirty_claims.insert(target.claim.id);
        accumulator.dirty_claims.insert(replacement_id);
        accumulator.dirty_reasons.insert(DirtyReason::Correction);
        accumulator
            .dirty_reasons
            .insert(DirtyReason::SummaryDependencyChanged);
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "claim creation mirrors core fields"
    )]
    fn create_claim(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        evaluated: &EvaluatedCandidate,
        subject: NodeId,
        subject_type: &contextdb_core::NodeType,
        predicate: &contextdb_core::PredicateDefinition,
        object: ClaimObject,
        valid_time: TimeRange,
        conflict: ConflictState,
        supersedes: Vec<ClaimId>,
        next_seq: CommitSeq,
        ids: &StableIds,
        accumulator: &mut SemanticAccumulator,
    ) -> CognitionResult<()> {
        let claim_id = ids.claim(&proposal.local_id)?;
        self.create_claim_with_id(
            input,
            proposal,
            evaluated,
            claim_id,
            subject,
            subject_type,
            predicate,
            object,
            valid_time,
            conflict,
            supersedes,
            next_seq,
            ids,
            accumulator,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "claim creation mirrors core fields"
    )]
    fn create_claim_with_id(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        evaluated: &EvaluatedCandidate,
        claim_id: ClaimId,
        subject: NodeId,
        subject_type: &contextdb_core::NodeType,
        predicate: &contextdb_core::PredicateDefinition,
        object: ClaimObject,
        valid_time: TimeRange,
        conflict: ConflictState,
        supersedes: Vec<ClaimId>,
        next_seq: CommitSeq,
        ids: &StableIds,
        accumulator: &mut SemanticAccumulator,
    ) -> CognitionResult<()> {
        let target = LineageNode::ClaimRevision {
            id: claim_id,
            revision: RevisionNumber::FIRST,
        };
        let mut superseded_inputs = Vec::new();
        for superseded in &supersedes {
            if let Some(existing) = input.claims.0.get(superseded) {
                superseded_inputs.push(LineageNode::ClaimRevision {
                    id: *superseded,
                    revision: existing.head.revision,
                });
            }
        }
        let envelope = semantic_envelope(
            input,
            proposal,
            evaluated,
            target,
            semantic_basis(input, evaluated),
            ids,
            "claim-create",
            superseded_inputs,
        )?;
        let evidence = evaluated
            .evidence
            .as_ref()
            .ok_or(CognitionError::InvalidProposal {
                field: "claim.evidence",
                reason: "validated evidence is required",
            })?;
        let revision = ClaimRevision {
            claim_id,
            revision: RevisionNumber::FIRST,
            object,
            temporal: BitemporalRange {
                valid_time,
                transaction_time: CommitRange::new(next_seq, None)?,
            },
            epistemic: EpistemicState {
                basis: semantic_basis(input, evaluated),
                acceptance: AcceptanceState::Accepted,
                conflict,
                lifecycle: contextdb_core::LifecycleState::Active,
            },
            confidence: confidence(evaluated, proposal),
            source_families: evidence.source_families.clone(),
            evidence: evidence.evidence_ids.clone(),
            supersedes,
            envelope,
        };
        contextdb_core::validate_claim_against_predicate(predicate, subject_type, &revision)?;
        accumulator.claim_creates.push(Claim {
            id: claim_id,
            workspace_id: input.workspace_id,
            subject,
            predicate: predicate.id,
            created_seq: next_seq,
        });
        accumulator.claim_revisions.push(revision);
        accumulator.dirty_claims.insert(claim_id);
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "conflict publication is intentionally explicit"
    )]
    fn create_conflict(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        evaluated: &EvaluatedCandidate,
        conflict_id: ConflictSetId,
        subject: NodeId,
        predicate: contextdb_core::PredicateId,
        old_claim: ClaimId,
        new_claim: ClaimId,
        resolution: ConflictResolution,
        next_seq: CommitSeq,
        ids: &StableIds,
        accumulator: &mut SemanticAccumulator,
    ) -> CognitionResult<()> {
        let target = LineageNode::ConflictRevision {
            id: conflict_id,
            revision: RevisionNumber::FIRST,
        };
        let envelope = semantic_envelope(
            input,
            proposal,
            evaluated,
            target,
            semantic_basis(input, evaluated),
            ids,
            "conflict",
            vec![
                LineageNode::ClaimRevision {
                    id: old_claim,
                    revision: input
                        .claims
                        .0
                        .get(&old_claim)
                        .map_or(RevisionNumber::FIRST, |claim| claim.head.revision),
                },
                LineageNode::ClaimRevision {
                    id: new_claim,
                    revision: RevisionNumber::FIRST,
                },
            ],
        )?;
        accumulator.conflict_creates.push(ConflictSet {
            id: conflict_id,
            workspace_id: input.workspace_id,
            subject,
            predicate,
            scopes: input.publication_envelope.scopes.clone(),
            created_seq: next_seq,
        });
        accumulator.conflict_revisions.push(ConflictSetRevision {
            conflict_set_id: conflict_id,
            revision: RevisionNumber::FIRST,
            transaction_time: CommitRange::new(next_seq, None)?,
            members: NonEmptyVec::try_from_vec(vec![old_claim, new_claim], "conflict.members")?,
            resolution,
            evidence: evaluated
                .evidence
                .as_ref()
                .map_or_else(Vec::new, |value| value.evidence_ids.clone()),
            envelope,
        });
        accumulator
            .dirty_reasons
            .insert(DirtyReason::ConflictChanged);
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "entity projection mirrors core fields"
    )]
    fn materialize_new_mentions(
        &self,
        input: &AdjudicationInput,
        proposal: &CandidateProposal,
        evaluated: &EvaluatedCandidate,
        valid_time: TimeRange,
        next_seq: CommitSeq,
        ids: &StableIds,
        accumulator: &mut SemanticAccumulator,
    ) -> CognitionResult<()> {
        for (mention, trace) in proposal
            .mentions
            .iter()
            .zip(&evaluated.decision.entity_resolution)
        {
            if !matches!(trace.result, EntityResolution::CreateNew) {
                continue;
            }
            let node_id = ids.node(&format!(
                "mention:{}:{}",
                proposal.local_id, mention.local_ref
            ))?;
            if accumulator
                .node_creates
                .iter()
                .any(|node| node.id == node_id)
            {
                continue;
            }
            let target = LineageNode::NodeRevision {
                id: node_id,
                revision: RevisionNumber::FIRST,
            };
            let envelope = semantic_envelope(
                input,
                proposal,
                evaluated,
                target,
                semantic_basis(input, evaluated),
                ids,
                "entity-create",
                Vec::new(),
            )?;
            accumulator.node_creates.push(Node {
                id: node_id,
                workspace_id: input.workspace_id,
                node_type: mention.expected_type.clone(),
                created_seq: next_seq,
                retired_seq: None,
                identity_state: contextdb_core::IdentityState::Canonical,
                primary_scope: input.publication_envelope.scopes.first().clone(),
            });
            accumulator.node_revisions.push(NodeRevision {
                node_id,
                revision: RevisionNumber::FIRST,
                temporal: BitemporalRange {
                    valid_time,
                    transaction_time: CommitRange::new(next_seq, None)?,
                },
                canonical_name: mention.surface.clone(),
                attributes: BTreeMap::new(),
                epistemic: EpistemicState {
                    basis: semantic_basis(input, evaluated),
                    acceptance: AcceptanceState::Accepted,
                    conflict: ConflictState::None,
                    lifecycle: contextdb_core::LifecycleState::Active,
                },
                confidence: confidence(evaluated, proposal),
                evidence: evaluated
                    .evidence
                    .as_ref()
                    .map_or_else(Vec::new, |value| value.evidence_ids.clone()),
                envelope,
            });
            accumulator.dirty_roots.insert(node_id);
            accumulator.dirty_reasons.insert(DirtyReason::NodeChanged);
        }
        Ok(())
    }
}

fn subject_anchor(
    input: &AdjudicationInput,
    reference: &str,
) -> Result<MemorySubjectId, ValidationIssue> {
    input
        .subject_anchors
        .get(reference)
        .copied()
        .ok_or(ValidationIssue::UnknownSubjectAnchor)
}

fn push_issue<T>(issues: &mut Vec<ValidationIssue>, issue: ValidationIssue) -> Option<T> {
    issues.push(issue);
    None
}

#[derive(Clone, Debug)]
enum ResolvedBody {
    Claim {
        subject: NodeId,
        subject_type: contextdb_core::NodeType,
        predicate: contextdb_core::PredicateDefinition,
        object: ClaimObject,
    },
    Preference {
        subject: MemorySubjectId,
        domain: String,
        value: serde_json::Value,
        strength: contextdb_core::PreferenceStrength,
    },
    Boundary {
        subject: MemorySubjectId,
        rule: contextdb_core::BoundaryRule,
        applies_to: Vec<MemorySubjectId>,
    },
    Relationship {
        participants: Vec<MemorySubjectId>,
        relationship_kind: contextdb_core::RelationshipKind,
        signal: RelationshipSignal,
        roles: BTreeMap<MemorySubjectId, String>,
        interaction_norms: Vec<String>,
    },
    Goal {
        owner: MemorySubjectId,
        statement: String,
        status: contextdb_core::GoalStatus,
        horizon: contextdb_core::GoalHorizon,
    },
    Commitment {
        owner: MemorySubjectId,
        beneficiary: Option<MemorySubjectId>,
        statement: String,
        due: Option<TimestampMicros>,
        trigger: Option<contextdb_core::Condition>,
        status: contextdb_core::CommitmentStatus,
    },
    Correction {
        target: Box<ExistingClaim>,
        subject: NodeId,
        subject_type: contextdb_core::NodeType,
        predicate: contextdb_core::PredicateDefinition,
        replacement: ClaimObject,
        reason: String,
        was_never_true: bool,
    },
    Summary {
        owner: NodeId,
        level: u8,
        content: serde_json::Value,
        known_omissions: Vec<String>,
    },
    Reflection {
        owner: NodeId,
        pattern_kind: crate::PatternKind,
        label: String,
        hypothesis: String,
        negative_evidence: Vec<EvidenceCitation>,
        required_verification: Vec<String>,
        proposes_causality: bool,
        sensitive_trait: bool,
    },
}

#[derive(Clone, Debug)]
struct EvaluatedCandidate {
    decision: CandidateDecision,
    canonical_candidate: Option<MemoryCandidate>,
    evidence: Option<ValidatedEvidence>,
    negative_evidence: Vec<contextdb_core::EvidenceId>,
    resolved: Option<ResolvedBody>,
    valid_time: Option<TimeRange>,
}

#[derive(Default)]
struct SemanticAccumulator {
    node_creates: Vec<Node>,
    node_revisions: Vec<NodeRevision>,
    claim_creates: Vec<Claim>,
    claim_revisions: Vec<ClaimRevision>,
    conflict_creates: Vec<ConflictSet>,
    conflict_revisions: Vec<ConflictSetRevision>,
    candidate_writes: Vec<MemoryCandidate>,
    typed_memory_writes: Vec<TypedMemoryMutation>,
    derived_work: Vec<contextdb_core::DerivedWorkItem>,
    dirty_roots: BTreeSet<NodeId>,
    dirty_claims: BTreeSet<ClaimId>,
    dirty_reasons: BTreeSet<DirtyReason>,
}

impl SemanticAccumulator {
    fn is_empty(&self) -> bool {
        self.node_creates.is_empty()
            && self.node_revisions.is_empty()
            && self.claim_creates.is_empty()
            && self.claim_revisions.is_empty()
            && self.conflict_creates.is_empty()
            && self.conflict_revisions.is_empty()
            && self.candidate_writes.is_empty()
            && self.typed_memory_writes.is_empty()
    }

    fn dirty_region(&self, based_on: SnapshotRef) -> Option<DirtyRegion> {
        if self.dirty_roots.is_empty() && self.dirty_claims.is_empty() {
            None
        } else {
            Some(DirtyRegion {
                based_on,
                roots: self.dirty_roots.clone(),
                claims: self.dirty_claims.clone(),
                reasons: self.dirty_reasons.clone(),
            })
        }
    }

    fn into_transaction(
        self,
        id: MutationId,
        base_snapshot: SnapshotRef,
        journal_refs: NonEmptyVec<ObservationId>,
    ) -> SemanticMutationSet {
        SemanticMutationSet {
            id,
            base_snapshot,
            journal_refs,
            observation_appends: Vec::new(),
            episode_view_writes: Vec::new(),
            node_creates: self.node_creates,
            node_revisions: self.node_revisions,
            claim_creates: self.claim_creates,
            claim_revisions: self.claim_revisions,
            edge_creates: Vec::new(),
            edge_revisions: Vec::new(),
            conflict_creates: self.conflict_creates,
            conflict_revisions: self.conflict_revisions,
            candidate_writes: self.candidate_writes,
            typed_memory_writes: self.typed_memory_writes,
            derived_work: self.derived_work,
        }
    }
}

fn zero_promotion() -> PromotionScore {
    PromotionScore {
        overall: 0.0,
        explicitness: 0.0,
        future_utility: 0.0,
        source_trust: 0.0,
        corroboration: 0.0,
        sensitivity_penalty: 0.0,
        ambiguity_penalty: 0.0,
    }
}

fn promotion_score(
    kind: ProposalKind,
    evidence: &ValidatedEvidence,
    ambiguity_penalty: f32,
    envelope: &SemanticEnvelope,
) -> PromotionScore {
    let explicitness = if !evidence.actor_assertions.is_empty() {
        1.0
    } else if evidence.primary_count > 0 {
        0.65
    } else {
        0.15
    };
    let future_utility = match kind {
        ProposalKind::Boundary | ProposalKind::Correction | ProposalKind::Commitment => 1.0,
        ProposalKind::Goal | ProposalKind::Claim => 0.8,
        ProposalKind::Preference | ProposalKind::Relationship => 0.72,
        ProposalKind::Summary => 0.65,
        ProposalKind::Reflection => 0.55,
    };
    let corroboration = match evidence.source_families.len() {
        0 => 0.0,
        1 => 0.35,
        2 => 0.75,
        _ => 1.0,
    };
    let sensitivity_penalty = match envelope.security.classification {
        contextdb_core::SecurityClassification::Public => 0.0,
        contextdb_core::SecurityClassification::Internal => 0.05,
        contextdb_core::SecurityClassification::Confidential => 0.15,
        contextdb_core::SecurityClassification::Restricted => 0.30,
    };
    let positive = 0.30 * explicitness
        + 0.20 * future_utility
        + 0.30 * evidence.source_trust
        + 0.20 * corroboration;
    PromotionScore {
        overall: (positive - 0.20 * ambiguity_penalty - 0.10 * sensitivity_penalty).clamp(0.0, 1.0),
        explicitness,
        future_utility,
        source_trust: evidence.source_trust,
        corroboration,
        sensitivity_penalty,
        ambiguity_penalty,
    }
}

fn disposition_for_issues(issues: &[ValidationIssue]) -> CandidateDisposition {
    if issues.iter().any(ValidationIssue::is_rejection) {
        CandidateDisposition::Rejected
    } else {
        CandidateDisposition::Quarantined
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "core candidate audit fields are explicit"
)]
fn build_core_candidate(
    input: &AdjudicationInput,
    proposal: &CandidateProposal,
    candidate_id: CandidateId,
    evidence: &ValidatedEvidence,
    envelope: SemanticEnvelope,
    promotion: PromotionScore,
    disposition: CandidateDisposition,
    issues: &[ValidationIssue],
    next_seq: CommitSeq,
) -> CognitionResult<MemoryCandidate> {
    let validation_state = match disposition {
        CandidateDisposition::Promoted | CandidateDisposition::Hypothesis => {
            CandidateValidationState::Promoted {
                commit_seq: next_seq,
            }
        }
        CandidateDisposition::Rejected => CandidateValidationState::Rejected {
            errors: NonEmptyVec::try_from_vec(
                issues.iter().map(|issue| issue.code().to_owned()).collect(),
                "candidate.errors",
            )?,
        },
        CandidateDisposition::Quarantined => CandidateValidationState::Quarantined,
        CandidateDisposition::NoOp
        | CandidateDisposition::SummaryReady
        | CandidateDisposition::ShadowValidated => CandidateValidationState::Validated,
    };
    let payload = serde_json::to_value(&proposal.body)
        .map_err(|error| CognitionError::Serialization(error.to_string()))?;
    let candidate = MemoryCandidate {
        id: candidate_id,
        source_observations: NonEmptyVec::try_from_vec(
            evidence.observations.clone(),
            "candidate.source_observations",
        )?,
        candidate_type: core_candidate_type(proposal.kind()),
        payload,
        evidence_spans: NonEmptyVec::try_from_vec(
            evidence.evidence_ids.clone(),
            "candidate.evidence_spans",
        )?,
        pipeline: input.run.pipeline.clone(),
        model_call: input.run.model_call_id(),
        validation_state,
        promotion,
        adjudication: CandidateAdjudication::Automatic,
        envelope,
    };
    candidate.validate()?;
    Ok(candidate)
}

fn core_candidate_type(kind: ProposalKind) -> CandidateType {
    match kind {
        ProposalKind::Claim => CandidateType::Claim,
        ProposalKind::Preference => CandidateType::Preference,
        ProposalKind::Commitment => CandidateType::Commitment,
        ProposalKind::Correction => CandidateType::Correction,
        ProposalKind::Boundary => CandidateType::Other("boundary".to_owned()),
        ProposalKind::Relationship => CandidateType::Other("relationship".to_owned()),
        ProposalKind::Goal => CandidateType::Other("goal".to_owned()),
        ProposalKind::Summary => CandidateType::Other("summary".to_owned()),
        ProposalKind::Reflection => CandidateType::Other("reflection".to_owned()),
    }
}

fn semantic_basis(input: &AdjudicationInput, evaluated: &EvaluatedCandidate) -> EpistemicBasis {
    if evaluated.decision.kind == ProposalKind::Reflection {
        EpistemicBasis::Hypothesis
    } else if evaluated
        .evidence
        .as_ref()
        .is_some_and(|evidence| !evidence.actor_assertions.is_empty())
    {
        EpistemicBasis::ActorAssertion
    } else if matches!(input.proposals.origin, ProposalOrigin::Deterministic) {
        EpistemicBasis::DeterministicDerivation
    } else {
        EpistemicBasis::ModelInference
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "semantic provenance inputs are explicit"
)]
fn semantic_envelope(
    input: &AdjudicationInput,
    proposal: &CandidateProposal,
    evaluated: &EvaluatedCandidate,
    target: LineageNode,
    basis: EpistemicBasis,
    ids: &StableIds,
    label: &str,
    mut additional_inputs: Vec<LineageNode>,
) -> CognitionResult<SemanticEnvelope> {
    let evidence = evaluated
        .evidence
        .as_ref()
        .ok_or(CognitionError::InvalidProposal {
            field: "semantic.evidence",
            reason: "validated evidence is required",
        })?;
    let mut inputs = evidence.lineage_inputs.clone();
    inputs.append(&mut additional_inputs);
    inputs.sort();
    inputs.dedup();
    derive_envelope(
        &input.publication_envelope,
        &input.run,
        &input.proposals.origin,
        &inputs,
        target,
        Some((basis, input.authorization.actor)),
        ids,
        &format!("{label}:{}", proposal.local_id),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "derivation contract is intentionally explicit"
)]
fn derive_envelope(
    base: &SemanticEnvelope,
    run: &ProcessingRun,
    origin: &ProposalOrigin,
    inputs: &[LineageNode],
    target: LineageNode,
    semantic_basis: Option<(EpistemicBasis, contextdb_core::ActorId)>,
    ids: &StableIds,
    label: &str,
) -> CognitionResult<SemanticEnvelope> {
    let (kind, actor) = match semantic_basis {
        Some((EpistemicBasis::ActorAssertion, actor)) => {
            (DerivationKind::ActorAssertion, Some(actor))
        }
        Some((EpistemicBasis::Hypothesis, _)) => (DerivationKind::Consolidation, None),
        _ if matches!(origin, ProposalOrigin::Deterministic) => {
            (DerivationKind::DeterministicProjector, None)
        }
        _ => (DerivationKind::ModelExtraction, None),
    };
    let mut envelope = base.clone();
    envelope.derivation = DerivationRef {
        id: ids.derivation(label)?,
        kind,
        actor,
        model_call: run.model_call_id(),
        pipeline: run.pipeline.clone(),
        inputs: inputs.to_vec(),
    };
    envelope.validate_for_target(&target)?;
    Ok(envelope)
}

fn confidence(evaluated: &EvaluatedCandidate, proposal: &CandidateProposal) -> ConfidenceProfile {
    ConfidenceProfile {
        overall: evaluated.decision.promotion.overall,
        source_trust: evaluated.decision.promotion.source_trust,
        extraction_quality: proposal.extraction_confidence,
        corroboration: evaluated.decision.promotion.corroboration,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "memory header mirrors core fields"
)]
fn memory_header(
    input: &AdjudicationInput,
    proposal: &CandidateProposal,
    evaluated: &EvaluatedCandidate,
    node_id: NodeId,
    valid_time: TimeRange,
    next_seq: CommitSeq,
    ids: &StableIds,
    label: &str,
) -> CognitionResult<MemoryRevisionHeader> {
    let basis = semantic_basis(input, evaluated);
    let envelope = semantic_envelope(
        input,
        proposal,
        evaluated,
        LineageNode::NodeRevision {
            id: node_id,
            revision: RevisionNumber::FIRST,
        },
        basis,
        ids,
        label,
        Vec::new(),
    )?;
    Ok(MemoryRevisionHeader {
        node_id,
        revision: RevisionNumber::FIRST,
        temporal: BitemporalRange {
            valid_time,
            transaction_time: CommitRange::new(next_seq, None)?,
        },
        epistemic: EpistemicState {
            basis,
            acceptance: AcceptanceState::Accepted,
            conflict: ConflictState::None,
            lifecycle: contextdb_core::LifecycleState::Active,
        },
        confidence: confidence(evaluated, proposal),
        evidence: evaluated
            .evidence
            .as_ref()
            .map_or_else(Vec::new, |value| value.evidence_ids.clone()),
        envelope,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "typed memory node and revision are atomic"
)]
fn add_typed_node(
    input: &AdjudicationInput,
    node_id: NodeId,
    node_type: contextdb_core::NodeType,
    canonical_name: String,
    header: MemoryRevisionHeader,
    next_seq: CommitSeq,
    memory: TypedMemoryMutation,
    accumulator: &mut SemanticAccumulator,
) {
    accumulator.node_creates.push(Node {
        id: node_id,
        workspace_id: input.workspace_id,
        node_type,
        created_seq: next_seq,
        retired_seq: None,
        identity_state: contextdb_core::IdentityState::Canonical,
        primary_scope: input.publication_envelope.scopes.first().clone(),
    });
    accumulator.node_revisions.push(NodeRevision {
        node_id,
        revision: RevisionNumber::FIRST,
        temporal: header.temporal,
        canonical_name,
        attributes: BTreeMap::new(),
        epistemic: header.epistemic,
        confidence: header.confidence,
        evidence: header.evidence.clone(),
        envelope: header.envelope.clone(),
    });
    accumulator.typed_memory_writes.push(memory);
    accumulator.dirty_roots.insert(node_id);
    accumulator
        .dirty_reasons
        .insert(DirtyReason::TypedMemoryChanged);
}

#[allow(
    clippy::too_many_arguments,
    reason = "revision update mirrors core fields"
)]
fn revised_claim(
    input: &AdjudicationInput,
    proposal: &CandidateProposal,
    evaluated: &EvaluatedCandidate,
    existing: &ExistingClaim,
    object: ClaimObject,
    valid_time: TimeRange,
    conflict: ConflictState,
    lifecycle: contextdb_core::LifecycleState,
    evidence_ids: Vec<contextdb_core::EvidenceId>,
    next_seq: CommitSeq,
    ids: &StableIds,
    label: &str,
) -> CognitionResult<ClaimRevision> {
    let revision =
        existing
            .head
            .revision
            .checked_next()
            .ok_or(CognitionError::InvalidProposal {
                field: "claim.revision",
                reason: "revision number exhausted",
            })?;
    let envelope = semantic_envelope(
        input,
        proposal,
        evaluated,
        LineageNode::ClaimRevision {
            id: existing.claim.id,
            revision,
        },
        semantic_basis(input, evaluated),
        ids,
        label,
        vec![LineageNode::ClaimRevision {
            id: existing.claim.id,
            revision: existing.head.revision,
        }],
    )?;
    let mut families = existing.head.source_families.clone();
    if let Some(evidence) = &evaluated.evidence {
        families.extend(evidence.source_families.iter().cloned());
    }
    Ok(ClaimRevision {
        claim_id: existing.claim.id,
        revision,
        object,
        temporal: BitemporalRange {
            valid_time,
            transaction_time: CommitRange::new(next_seq, None)?,
        },
        epistemic: EpistemicState {
            basis: semantic_basis(input, evaluated),
            acceptance: AcceptanceState::Accepted,
            conflict,
            lifecycle,
        },
        confidence: confidence(evaluated, proposal),
        source_families: families,
        evidence: evidence_ids,
        supersedes: existing.head.supersedes.clone(),
        envelope,
    })
}

fn existing_for_change<'a>(
    input: &'a AdjudicationInput,
    change: &ChangeDecision,
) -> CognitionResult<&'a ExistingClaim> {
    change
        .compared_claim
        .and_then(|id| input.claims.0.get(&id))
        .ok_or(CognitionError::InvalidProposal {
            field: "claim.existing",
            reason: "classified existing claim is absent",
        })
}

fn combined_evidence(
    existing: &ExistingClaim,
    evaluated: &EvaluatedCandidate,
) -> Vec<contextdb_core::EvidenceId> {
    let mut evidence = existing.head.evidence.clone();
    if let Some(validated) = &evaluated.evidence {
        evidence.extend(validated.evidence_ids.iter().copied());
    }
    evidence.sort();
    evidence.dedup();
    evidence
}

fn proposal_digest(proposal: &CandidateProposal) -> CognitionResult<contextdb_core::ContentDigest> {
    let encoded = serde_json::to_vec(proposal)
        .map_err(|error| CognitionError::Serialization(error.to_string()))?;
    Ok(contextdb_core::ContentDigest::from_bytes(
        *blake3::hash(&encoded).as_bytes(),
    ))
}

fn update_metrics(metrics: &mut PipelineMetrics, decision: &CandidateDecision) {
    match decision.disposition {
        CandidateDisposition::Promoted => metrics.promoted = metrics.promoted.saturating_add(1),
        CandidateDisposition::Hypothesis => {
            metrics.hypotheses = metrics.hypotheses.saturating_add(1)
        }
        CandidateDisposition::SummaryReady => {
            metrics.summaries_ready = metrics.summaries_ready.saturating_add(1)
        }
        CandidateDisposition::Quarantined => {
            metrics.quarantined = metrics.quarantined.saturating_add(1)
        }
        CandidateDisposition::Rejected => metrics.rejected = metrics.rejected.saturating_add(1),
        CandidateDisposition::NoOp => metrics.no_op = metrics.no_op.saturating_add(1),
        CandidateDisposition::ShadowValidated => {}
    }
    if decision.kind == ProposalKind::Correction
        && decision.disposition == CandidateDisposition::Promoted
    {
        metrics.corrections_promoted = metrics.corrections_promoted.saturating_add(1);
    }
    if decision.issues.iter().any(|issue| {
        matches!(
            issue,
            ValidationIssue::UnknownEvidence | ValidationIssue::QuoteHashMismatch
        )
    }) && decision.disposition == CandidateDisposition::Rejected
    {
        metrics.hallucinated_evidence_rejected =
            metrics.hallucinated_evidence_rejected.saturating_add(1);
    }
}

fn deduplicate_work(work: &mut Vec<contextdb_core::DerivedWorkItem>) {
    let mut encoded = BTreeSet::new();
    work.retain(|item| {
        serde_json::to_string(item)
            .map(|value| encoded.insert(value))
            .unwrap_or(false)
    });
}

struct StableIds {
    seed: [u8; 32],
}

impl StableIds {
    fn new(
        input: contextdb_core::ContentDigest,
        policy: contextdb_core::ContentDigest,
        run: &str,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"contextdb-cognition-ids-v1\0");
        hasher.update(input.as_bytes());
        hasher.update(policy.as_bytes());
        hasher.update(run.as_bytes());
        Self {
            seed: *hasher.finalize().as_bytes(),
        }
    }

    fn uuid(&self, class: &str, label: &str) -> Uuid {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.seed);
        hasher.update(class.as_bytes());
        hasher.update(&[0]);
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x50;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }

    fn candidate(&self, label: &str) -> CognitionResult<CandidateId> {
        CandidateId::from_uuid(self.uuid("candidate", label))
            .map_err(|_| CognitionError::IdentifierConstruction)
    }

    fn node(&self, label: &str) -> CognitionResult<NodeId> {
        NodeId::from_uuid(self.uuid("node", label))
            .map_err(|_| CognitionError::IdentifierConstruction)
    }

    fn claim(&self, label: &str) -> CognitionResult<ClaimId> {
        ClaimId::from_uuid(self.uuid("claim", label))
            .map_err(|_| CognitionError::IdentifierConstruction)
    }

    fn conflict(&self, label: &str) -> CognitionResult<ConflictSetId> {
        ConflictSetId::from_uuid(self.uuid("conflict", label))
            .map_err(|_| CognitionError::IdentifierConstruction)
    }

    fn relationship(&self, label: &str) -> CognitionResult<contextdb_core::RelationshipStateId> {
        contextdb_core::RelationshipStateId::from_uuid(self.uuid("relationship", label))
            .map_err(|_| CognitionError::IdentifierConstruction)
    }

    fn summary(&self, label: &str) -> CognitionResult<SummaryId> {
        SummaryId::from_uuid(self.uuid("summary", label))
            .map_err(|_| CognitionError::IdentifierConstruction)
    }

    fn mutation(&self, label: &str) -> CognitionResult<MutationId> {
        MutationId::from_uuid(self.uuid("mutation", label))
            .map_err(|_| CognitionError::IdentifierConstruction)
    }

    fn derivation(&self, label: &str) -> CognitionResult<DerivationId> {
        DerivationId::from_uuid(self.uuid("derivation", label))
            .map_err(|_| CognitionError::IdentifierConstruction)
    }
}
