use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    ActorId, CandidateId, ClaimId, ContentDigest, EvidenceId, EvidenceSpan, LineageGraph,
    LineageNode, MemorySubjectId, NodeId, NonEmptyVec, ObservationId, Purpose, SemanticEnvelope,
    SummaryId, TimestampMicros, TrustClass, Validate, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::{
    CandidateProposal, CognitionConfig, CognitionError, CognitionResult, ProposalKind,
    RelationshipSignal,
};

/// Taint discovered before model use. It remains data metadata and never grants
/// instruction or mutation authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentTaint {
    InstructionInContent,
    CredentialRequest,
    DataExfiltrationPattern,
    ToolInvocationRequest,
    PolicyOverrideAttempt,
    EncodedPayload,
    Other(String),
}

/// Trusted classification assigned by the observation gateway, not by the
/// proposal provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceAuthority {
    PrimaryObservation,
    ActorAssertion {
        actor: ActorId,
        subject: MemorySubjectId,
    },
    DeterministicSource,
    ExternalReport,
    ModelDerived,
    SummaryDerived {
        summary_id: SummaryId,
    },
    ReflectionDerived,
}

impl EvidenceAuthority {
    /// Whether this record can independently ground a factual semantic item.
    #[must_use]
    pub const fn is_primary(&self) -> bool {
        matches!(
            self,
            Self::PrimaryObservation | Self::ActorAssertion { .. } | Self::DeterministicSource
        )
    }

    /// Returns the authenticated actor assertion, if any.
    #[must_use]
    pub const fn actor_assertion(&self) -> Option<(ActorId, MemorySubjectId)> {
        match self {
            Self::ActorAssertion { actor, subject } => Some((*actor, *subject)),
            _ => None,
        }
    }
}

/// Evidence plus the trusted policy and provenance information needed by write
/// adjudication. The raw content is deliberately absent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub span: EvidenceSpan,
    pub envelope: SemanticEnvelope,
    pub source_family: String,
    pub observed_at: TimestampMicros,
    pub authority: EvidenceAuthority,
    pub taints: BTreeSet<ContentTaint>,
    /// Evidence records supporting this derived record. Primary records use an
    /// empty set.
    pub supports: Vec<EvidenceId>,
}

impl EvidenceRecord {
    fn validate(&self) -> CognitionResult<()> {
        self.span.validate()?;
        self.envelope.validate()?;
        if self.source_family.trim().is_empty() {
            return Err(CognitionError::InvalidProposal {
                field: "evidence.source_family",
                reason: "must not be blank",
            });
        }
        let unique: BTreeSet<_> = self.supports.iter().copied().collect();
        if unique.len() != self.supports.len() || unique.contains(&self.span.id) {
            return Err(CognitionError::InvalidProposal {
                field: "evidence.supports",
                reason: "support references must be unique and non-self-referential",
            });
        }
        Ok(())
    }
}

/// Deterministically ordered evidence snapshot used by one processing run.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceCatalog(pub BTreeMap<EvidenceId, EvidenceRecord>);

impl EvidenceCatalog {
    /// Validates evidence selectors, derivations, support references, cycles, and
    /// the configured derivation-depth cap.
    pub fn validate(&self, config: &CognitionConfig) -> CognitionResult<()> {
        for record in self.0.values() {
            record.validate()?;
            for support in &record.supports {
                if !self.0.contains_key(support) {
                    return Err(CognitionError::InvalidProposal {
                        field: "evidence.supports",
                        reason: "support evidence is absent from the snapshot",
                    });
                }
            }
            if let Some(derivation) = &record.span.derivation {
                let target = LineageNode::Evidence { id: record.span.id };
                derivation.validate_for(&target)?;
                let graph = LineageGraph {
                    edges: derivation
                        .inputs
                        .iter()
                        .cloned()
                        .map(|source| contextdb_core::LineageEdge {
                            derived: target.clone(),
                            source,
                        })
                        .collect(),
                };
                graph.validate()?;
            }
        }

        let mut visiting = BTreeSet::new();
        let mut visited = BTreeMap::new();
        for evidence_id in self.0.keys().copied() {
            evidence_depth(
                evidence_id,
                self,
                &mut visiting,
                &mut visited,
                config.max_lineage_depth,
            )?;
        }
        Ok(())
    }

    /// Fetches one record without materializing raw content.
    #[must_use]
    pub fn get(&self, id: &EvidenceId) -> Option<&EvidenceRecord> {
        self.0.get(id)
    }
}

fn evidence_depth(
    evidence_id: EvidenceId,
    catalog: &EvidenceCatalog,
    visiting: &mut BTreeSet<EvidenceId>,
    visited: &mut BTreeMap<EvidenceId, usize>,
    max_depth: usize,
) -> CognitionResult<usize> {
    if let Some(depth) = visited.get(&evidence_id) {
        return Ok(*depth);
    }
    if !visiting.insert(evidence_id) {
        return Err(CognitionError::CoreValidation(
            contextdb_core::ValidationError::LineageCycle,
        ));
    }
    let record = catalog
        .get(&evidence_id)
        .ok_or(CognitionError::InvalidProposal {
            field: "evidence.supports",
            reason: "support evidence is absent",
        })?;
    let mut depth = 1_usize;
    for support in &record.supports {
        depth = depth.max(
            evidence_depth(*support, catalog, visiting, visited, max_depth)?.saturating_add(1),
        );
    }
    visiting.remove(&evidence_id);
    if depth > max_depth {
        return Err(CognitionError::InvalidProposal {
            field: "evidence.lineage",
            reason: "derivation depth exceeds configured limit",
        });
    }
    visited.insert(evidence_id, depth);
    Ok(depth)
}

/// Authenticated, precomputed authorization result for a cognition run.
/// Purpose and grants come from the host policy engine, never model text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationContext {
    pub actor: ActorId,
    pub workspace_id: WorkspaceId,
    pub purpose: Purpose,
    pub may_publish: bool,
    pub permitted_evidence: BTreeSet<EvidenceId>,
    pub permitted_nodes: BTreeSet<NodeId>,
    pub permitted_claims: BTreeSet<ClaimId>,
}

/// Candidate-local validation reason recorded in quarantine/audit output.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidationIssue {
    PublicationNotAuthorized,
    UnknownEvidence,
    UnauthorizedEvidence,
    EvidenceOutsideJournal,
    QuoteHashMismatch,
    PolicyWouldBroaden,
    DerivedOnlyEvidence,
    TaintedInstructionAttempt,
    UnknownSubjectAnchor,
    UnknownPredicateAnchor,
    UnknownClaimAnchor,
    UnknownEntityMention,
    EntityAmbiguous,
    CrossWorkspaceEntity,
    SensitiveEntityRequiresReview,
    PredicateTypeMismatch,
    InvalidTemporalRange,
    DuplicateWithoutNewEvidence,
    LowPromotionScore,
    PreferenceNeedsExplicitOrIndependentSupport,
    BoundaryNeedsExplicitAuthority,
    RelationshipNeedsStrongSupport,
    RelationshipOverreach,
    CorrectionNeedsExplicitAuthority,
    CorrectionTargetMismatch,
    ReflectionInsufficientSupport,
    ReflectionNeedsNegativeExamples,
    ReflectionSensitiveTraitForbidden,
    ReflectionCausalityUnverified,
    SummaryDerivedOnly,
    SelfSupportingLineage,
    ShadowRunCannotPublish,
}

impl ValidationIssue {
    /// Stable reason code persisted in core candidate audit records.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PublicationNotAuthorized => "publication_not_authorized",
            Self::UnknownEvidence => "unknown_evidence",
            Self::UnauthorizedEvidence => "unauthorized_evidence",
            Self::EvidenceOutsideJournal => "evidence_outside_journal",
            Self::QuoteHashMismatch => "quote_hash_mismatch",
            Self::PolicyWouldBroaden => "policy_would_broaden",
            Self::DerivedOnlyEvidence => "derived_only_evidence",
            Self::TaintedInstructionAttempt => "tainted_instruction_attempt",
            Self::UnknownSubjectAnchor => "unknown_subject_anchor",
            Self::UnknownPredicateAnchor => "unknown_predicate_anchor",
            Self::UnknownClaimAnchor => "unknown_claim_anchor",
            Self::UnknownEntityMention => "unknown_entity_mention",
            Self::EntityAmbiguous => "entity_ambiguous",
            Self::CrossWorkspaceEntity => "cross_workspace_entity",
            Self::SensitiveEntityRequiresReview => "sensitive_entity_requires_review",
            Self::PredicateTypeMismatch => "predicate_type_mismatch",
            Self::InvalidTemporalRange => "invalid_temporal_range",
            Self::DuplicateWithoutNewEvidence => "duplicate_without_new_evidence",
            Self::LowPromotionScore => "low_promotion_score",
            Self::PreferenceNeedsExplicitOrIndependentSupport => {
                "preference_needs_explicit_or_independent_support"
            }
            Self::BoundaryNeedsExplicitAuthority => "boundary_needs_explicit_authority",
            Self::RelationshipNeedsStrongSupport => "relationship_needs_strong_support",
            Self::RelationshipOverreach => "relationship_overreach",
            Self::CorrectionNeedsExplicitAuthority => "correction_needs_explicit_authority",
            Self::CorrectionTargetMismatch => "correction_target_mismatch",
            Self::ReflectionInsufficientSupport => "reflection_insufficient_support",
            Self::ReflectionNeedsNegativeExamples => "reflection_needs_negative_examples",
            Self::ReflectionSensitiveTraitForbidden => "reflection_sensitive_trait_forbidden",
            Self::ReflectionCausalityUnverified => "reflection_causality_unverified",
            Self::SummaryDerivedOnly => "summary_derived_only",
            Self::SelfSupportingLineage => "self_supporting_lineage",
            Self::ShadowRunCannotPublish => "shadow_run_cannot_publish",
        }
    }

    /// Whether the violation is a hard rejection rather than a potentially
    /// reviewable quarantine state.
    #[must_use]
    pub const fn is_rejection(&self) -> bool {
        matches!(
            self,
            Self::PublicationNotAuthorized
                | Self::UnknownEvidence
                | Self::UnauthorizedEvidence
                | Self::EvidenceOutsideJournal
                | Self::QuoteHashMismatch
                | Self::PolicyWouldBroaden
                | Self::DerivedOnlyEvidence
                | Self::TaintedInstructionAttempt
                | Self::CrossWorkspaceEntity
                | Self::PredicateTypeMismatch
                | Self::BoundaryNeedsExplicitAuthority
                | Self::RelationshipOverreach
                | Self::CorrectionNeedsExplicitAuthority
                | Self::CorrectionTargetMismatch
                | Self::ReflectionSensitiveTraitForbidden
                | Self::SelfSupportingLineage
        )
    }
}

/// Evidence features computed only after every citation passes authorization.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedEvidence {
    pub evidence_ids: Vec<EvidenceId>,
    pub observations: Vec<ObservationId>,
    pub source_families: BTreeSet<String>,
    pub lineage_inputs: Vec<LineageNode>,
    pub primary_count: usize,
    pub actor_assertions: BTreeSet<(ActorId, MemorySubjectId)>,
    pub source_trust: f32,
    pub has_taint: bool,
    pub earliest_observed_at: TimestampMicros,
}

impl ValidatedEvidence {
    /// True when the authenticated actor explicitly asserted the candidate for
    /// the named subject.
    #[must_use]
    pub fn asserted_by(&self, actor: ActorId, subject: MemorySubjectId) -> bool {
        self.actor_assertions.contains(&(actor, subject))
    }
}

/// Authorization-first evidence validator.
#[derive(Clone, Copy, Debug, Default)]
pub struct EvidenceGate;

impl EvidenceGate {
    /// Validates exact citations and policy propagation. On failure, no entity
    /// or existing-claim data needs to be inspected.
    pub fn validate_candidate(
        proposal: &CandidateProposal,
        catalog: &EvidenceCatalog,
        authorization: &AuthorizationContext,
        journal_refs: &NonEmptyVec<ObservationId>,
        target_envelope: &SemanticEnvelope,
        candidate_id: CandidateId,
    ) -> Result<ValidatedEvidence, Vec<ValidationIssue>> {
        let mut issues = Vec::new();
        if !authorization.may_publish {
            issues.push(ValidationIssue::PublicationNotAuthorized);
        }

        let journal: BTreeSet<_> = journal_refs.iter().copied().collect();
        let mut records = Vec::new();
        for citation in &proposal.evidence {
            if !authorization
                .permitted_evidence
                .contains(&citation.evidence_id)
            {
                issues.push(ValidationIssue::UnauthorizedEvidence);
                continue;
            }
            let Some(record) = catalog.get(&citation.evidence_id) else {
                issues.push(ValidationIssue::UnknownEvidence);
                continue;
            };
            if citation.quote_hash != record.span.quote_hash {
                issues.push(ValidationIssue::QuoteHashMismatch);
                continue;
            }
            if !journal.contains(&record.span.observation_id) {
                issues.push(ValidationIssue::EvidenceOutsideJournal);
                continue;
            }
            if target_envelope
                .validate_derived_from(&record.envelope)
                .is_err()
            {
                issues.push(ValidationIssue::PolicyWouldBroaden);
                continue;
            }
            if record.span.derivation.as_ref().is_some_and(|derivation| {
                derivation
                    .inputs
                    .contains(&LineageNode::Candidate { id: candidate_id })
            }) {
                issues.push(ValidationIssue::SelfSupportingLineage);
                continue;
            }
            records.push(record);
        }

        if !issues.is_empty() {
            issues.sort();
            issues.dedup();
            return Err(issues);
        }

        let primary_count = records
            .iter()
            .filter(|record| record.authority.is_primary())
            .count();
        if primary_count == 0 {
            issues.push(match proposal.kind() {
                ProposalKind::Summary => ValidationIssue::SummaryDerivedOnly,
                _ => ValidationIssue::DerivedOnlyEvidence,
            });
        }
        let has_taint = records.iter().any(|record| !record.taints.is_empty());
        if has_taint && can_acquire_instruction_like_state(proposal) {
            issues.push(ValidationIssue::TaintedInstructionAttempt);
        }
        if !issues.is_empty() {
            return Err(issues);
        }

        let evidence_ids = records.iter().map(|record| record.span.id).collect();
        let observations: BTreeSet<_> = records
            .iter()
            .map(|record| record.span.observation_id)
            .collect();
        let source_families = records
            .iter()
            .map(|record| record.source_family.clone())
            .collect();
        let actor_assertions = records
            .iter()
            .filter_map(|record| record.authority.actor_assertion())
            .collect();
        let source_trust = records
            .iter()
            .map(|record| trust_score(record.span.trust))
            .fold(0.0_f32, f32::max);
        let lineage_inputs = records
            .iter()
            .map(|record| LineageNode::Evidence { id: record.span.id })
            .collect();
        let earliest_observed_at = records
            .iter()
            .map(|record| record.observed_at)
            .min()
            .unwrap_or(TimestampMicros(0));
        Ok(ValidatedEvidence {
            evidence_ids,
            observations: observations.into_iter().collect(),
            source_families,
            lineage_inputs,
            primary_count,
            actor_assertions,
            source_trust,
            has_taint,
            earliest_observed_at,
        })
    }
}

fn can_acquire_instruction_like_state(proposal: &CandidateProposal) -> bool {
    match &proposal.body {
        crate::ProposalBody::Claim { .. }
        | crate::ProposalBody::Summary { .. }
        | crate::ProposalBody::Reflection { .. } => false,
        crate::ProposalBody::Relationship { signal, .. } => !matches!(
            signal,
            RelationshipSignal::SingleInteraction | RelationshipSignal::SharedReference
        ),
        _ => true,
    }
}

fn trust_score(trust: TrustClass) -> f32 {
    match trust {
        TrustClass::Untrusted => 0.10,
        TrustClass::Unknown => 0.35,
        TrustClass::SelfAsserted => 0.70,
        TrustClass::Authenticated => 0.90,
        TrustClass::Verified => 1.0,
    }
}

/// Computes the request-bound digest over authorized evidence metadata. The
/// deterministic order prevents map insertion order from changing replay.
pub fn input_digest(
    journal_refs: &NonEmptyVec<ObservationId>,
    catalog: &EvidenceCatalog,
    authorization: &AuthorizationContext,
) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-cognition-input-v1\0");
    for observation in journal_refs.iter() {
        hasher.update(observation.as_uuid().as_bytes());
    }
    for evidence_id in &authorization.permitted_evidence {
        let Some(record) = catalog.get(evidence_id) else {
            continue;
        };
        hasher.update(evidence_id.as_uuid().as_bytes());
        hasher.update(record.span.observation_id.as_uuid().as_bytes());
        hasher.update(record.span.quote_hash.as_bytes());
        hasher.update(record.source_family.as_bytes());
    }
    ContentDigest::from_bytes(*hasher.finalize().as_bytes())
}

/// Computes a stable digest of the authenticated publication policy.
pub fn policy_digest(envelope: &SemanticEnvelope) -> CognitionResult<ContentDigest> {
    let encoded = serde_json::to_vec(envelope)
        .map_err(|error| CognitionError::Serialization(error.to_string()))?;
    Ok(ContentDigest::from_bytes(
        *blake3::hash(&encoded).as_bytes(),
    ))
}
