use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    Cardinality, Claim, ClaimId, ClaimObject, ClaimRevision, ConflictPolicy, Node, NodeId,
    NodeRevision, NodeType, PredicateDefinition, ScopeRef, SemanticEnvelope, TimeRange,
    TimestampMicros, Validate, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorizationContext, CognitionConfig, EntityMention, ProposedValue, TemporalProposal,
    ValidatedEvidence, ValidationIssue,
};

/// Authorized entity data needed by the reference resolver. Raw evidence and
/// unrelated graph neighbourhoods are not materialized here.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityRecord {
    pub node: Node,
    pub head: NodeRevision,
    pub canonical_key: Option<String>,
    pub aliases: BTreeSet<String>,
    pub external_keys: BTreeSet<String>,
    pub sensitive: bool,
    pub active_context: bool,
}

impl EntityRecord {
    /// Validates the stable/head association and canonical metadata.
    pub fn validate(&self) -> Result<(), contextdb_core::ValidationError> {
        self.node.validate()?;
        self.head.validate()?;
        if self.node.id != self.head.node_id {
            return Err(contextdb_core::ValidationError::InvalidState {
                reason: "entity head belongs to another node",
            });
        }
        Ok(())
    }
}

/// Snapshot-local deterministic entity catalogue.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityIndex(pub BTreeMap<NodeId, EntityRecord>);

/// One scored authorized resolution candidate.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityMatch {
    pub node_id: NodeId,
    pub score: f32,
}

/// Conservative entity-resolution result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EntityResolution {
    Existing { node_id: NodeId, score: f32 },
    CreateNew,
    Ambiguous { candidates: Vec<EntityMatch> },
    Rejected { issue: ValidationIssue },
}

/// Resolution trace proves how many policy-authorized records could influence
/// the decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityResolutionTrace {
    pub local_ref: String,
    pub authorized_examined: usize,
    pub result: EntityResolution,
}

/// Exact/scope-aware deterministic entity resolver used as the M10 oracle.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceEntityResolver;

impl ReferenceEntityResolver {
    /// Resolves a mention after the evidence gate has succeeded. Unauthorized
    /// records are filtered before scoring and do not affect candidate counts.
    #[must_use]
    pub fn resolve(
        mention: &EntityMention,
        workspace_id: WorkspaceId,
        scopes: &[ScopeRef],
        index: &EntityIndex,
        authorization: &AuthorizationContext,
        config: &CognitionConfig,
    ) -> EntityResolutionTrace {
        let mut matches = Vec::new();
        let mut examined = 0_usize;
        for record in index.0.values() {
            if !authorization.permitted_nodes.contains(&record.node.id) {
                continue;
            }
            if record.node.workspace_id != workspace_id {
                continue;
            }
            examined = examined.saturating_add(1);
            if record.node.node_type != mention.expected_type {
                continue;
            }
            let score = entity_score(mention, record, scopes);
            if score >= config.ambiguous_link_threshold {
                matches.push(EntityMatch {
                    node_id: record.node.id,
                    score,
                });
            }
        }
        matches.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });

        let sensitive_match = mention.sensitive
            || matches.first().is_some_and(|candidate| {
                index
                    .0
                    .get(&candidate.node_id)
                    .is_some_and(|record| record.sensitive)
            });
        let threshold = if sensitive_match {
            config.sensitive_auto_link_threshold
        } else {
            config.auto_link_threshold
        };
        let result = match matches.as_slice() {
            [] => EntityResolution::CreateNew,
            [best, rest @ ..]
                if best.score >= threshold
                    && rest
                        .first()
                        .is_none_or(|second| best.score - second.score >= 0.03) =>
            {
                EntityResolution::Existing {
                    node_id: best.node_id,
                    score: best.score,
                }
            }
            _ => EntityResolution::Ambiguous {
                candidates: matches,
            },
        };
        EntityResolutionTrace {
            local_ref: mention.local_ref.clone(),
            authorized_examined: examined,
            result,
        }
    }
}

fn entity_score(mention: &EntityMention, record: &EntityRecord, scopes: &[ScopeRef]) -> f32 {
    let surface = normalize(&mention.surface);
    let canonical_name = normalize(&record.head.canonical_name);
    let exact_external = mention.external_key.as_ref().is_some_and(|key| {
        record
            .external_keys
            .iter()
            .any(|candidate| normalize(candidate) == normalize(key))
    });
    let exact_canonical = mention.canonical_key.as_ref().is_some_and(|key| {
        record
            .canonical_key
            .as_ref()
            .is_some_and(|candidate| normalize(candidate) == normalize(key))
    });
    let exact_name = surface == canonical_name
        || record
            .aliases
            .iter()
            .any(|candidate| normalize(candidate) == surface);
    let same_scope = scopes
        .iter()
        .any(|scope| scope == &record.node.primary_scope);

    if (exact_external || exact_canonical) && same_scope {
        return 1.0;
    }

    let mut score = 0.0_f32;
    if exact_external {
        score += 0.70;
    }
    if exact_canonical {
        score += 0.55;
    }
    if exact_name {
        score += 0.70;
    } else {
        score += 0.35 * token_overlap(&surface, &canonical_name);
    }
    if same_scope {
        score += 0.15;
    }
    score += 0.10; // type compatibility was checked before scoring.
    if record.active_context {
        score += 0.05;
    }
    score.min(1.0)
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

fn token_overlap(left: &str, right: &str) -> f32 {
    let left: BTreeSet<_> = left.split_whitespace().collect();
    let right: BTreeSet<_> = right.split_whitespace().collect();
    let union = left.union(&right).count();
    if union == 0 {
        0.0
    } else {
        left.intersection(&right).count() as f32 / union as f32
    }
}

/// Existing accepted claim head supplied by a snapshot adapter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingClaim {
    pub claim: Claim,
    pub head: ClaimRevision,
    pub subject_type: NodeType,
}

impl ExistingClaim {
    /// Validates stable/head association.
    pub fn validate(&self) -> Result<(), contextdb_core::ValidationError> {
        self.claim.validate()?;
        self.head.validate()?;
        if self.claim.id != self.head.claim_id {
            return Err(contextdb_core::ValidationError::InvalidState {
                reason: "claim head belongs to another claim",
            });
        }
        Ok(())
    }
}

/// Snapshot-local current claim index. Adapters may populate it from M4/M5
/// without making cognition depend on their storage APIs.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimIndex(pub BTreeMap<ClaimId, ExistingClaim>);

/// Deterministic relationship between a proposed and existing semantic slot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeClassification {
    New,
    Duplicate,
    Refinement,
    TemporalTransition,
    Correction,
    ScopedCoexistence,
    Contradiction,
    IndependentEvidence,
}

/// Conflict classifier output and the current claim it compared, if any.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeDecision {
    pub classification: ChangeClassification,
    pub compared_claim: Option<ClaimId>,
}

/// Domain-valid temporal class used in traces and promotion policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalClass {
    Current,
    Historical,
    Future,
    BoundedCurrent,
}

/// Converts a proposal into a valid domain interval, falling back to the
/// earliest source observation rather than model wall-clock guesses.
pub fn classify_temporal(
    proposal: Option<TemporalProposal>,
    evidence: &ValidatedEvidence,
    now: TimestampMicros,
) -> Result<(TimeRange, TemporalClass), ValidationIssue> {
    let start = proposal
        .and_then(|value| value.valid_from)
        .unwrap_or(evidence.earliest_observed_at);
    let end = proposal.and_then(|value| value.valid_to);
    let range = TimeRange::new(start, end).map_err(|_| ValidationIssue::InvalidTemporalRange)?;
    let class = match end {
        Some(end) if end <= now => TemporalClass::Historical,
        Some(_) if start <= now => TemporalClass::BoundedCurrent,
        Some(_) => TemporalClass::Future,
        None if start > now => TemporalClass::Future,
        None => TemporalClass::Current,
    };
    Ok((range, class))
}

/// Resolves a model-neutral proposed value after all referenced mentions have a
/// deterministic resolution.
pub fn resolve_value(
    value: &ProposedValue,
    mentions: &BTreeMap<String, NodeId>,
) -> Result<ClaimObject, ValidationIssue> {
    Ok(match value {
        ProposedValue::Entity { mention_ref } => ClaimObject::Node(
            *mentions
                .get(mention_ref)
                .ok_or(ValidationIssue::UnknownEntityMention)?,
        ),
        ProposedValue::String(value) => ClaimObject::String(value.clone()),
        ProposedValue::Integer(value) => ClaimObject::Integer(*value),
        ProposedValue::Float(value) => ClaimObject::Float(*value),
        ProposedValue::Boolean(value) => ClaimObject::Boolean(*value),
        ProposedValue::Timestamp(value) => ClaimObject::Timestamp(*value),
        ProposedValue::Structured(value) => ClaimObject::Structured(value.clone()),
    })
}

/// Compares a proposed current claim with authorized existing heads. No
/// prohibited claim participates in this classification.
#[must_use]
#[allow(
    clippy::too_many_arguments,
    reason = "classification inputs are explicit and snapshot-bound"
)]
pub fn classify_change(
    subject: NodeId,
    predicate: &PredicateDefinition,
    object: &ClaimObject,
    valid_time: TimeRange,
    explicit_valid_start: bool,
    envelope: &SemanticEnvelope,
    claims: &ClaimIndex,
    authorization: &AuthorizationContext,
) -> ChangeDecision {
    let existing = claims
        .0
        .values()
        .filter(|item| authorization.permitted_claims.contains(&item.claim.id))
        .filter(|item| item.claim.workspace_id == authorization.workspace_id)
        .filter(|item| item.claim.subject == subject && item.claim.predicate == predicate.id)
        .filter(|item| item.head.is_current_published())
        .min_by_key(|item| item.claim.id);
    let Some(existing) = existing else {
        return ChangeDecision {
            classification: ChangeClassification::New,
            compared_claim: None,
        };
    };

    let same_scopes = same_scope_set(&existing.head.envelope.scopes, &envelope.scopes);
    let classification = if !same_scopes {
        ChangeClassification::ScopedCoexistence
    } else if existing.head.object == *object
        && existing.head.temporal.valid_time.overlaps(valid_time)
    {
        ChangeClassification::Duplicate
    } else if !existing.head.temporal.valid_time.overlaps(valid_time)
        || (explicit_valid_start
            && valid_time.start > existing.head.temporal.valid_time.start
            && existing.head.object != *object)
    {
        ChangeClassification::TemporalTransition
    } else if is_refinement(&existing.head.object, object) {
        ChangeClassification::Refinement
    } else if matches!(predicate.cardinality, Cardinality::Set | Cardinality::List)
        || predicate.conflict_policy == ConflictPolicy::AllowCoexistence
    {
        ChangeClassification::IndependentEvidence
    } else {
        ChangeClassification::Contradiction
    };
    ChangeDecision {
        classification,
        compared_claim: Some(existing.claim.id),
    }
}

fn same_scope_set(
    left: &contextdb_core::NonEmptyVec<ScopeRef>,
    right: &contextdb_core::NonEmptyVec<ScopeRef>,
) -> bool {
    let left: BTreeSet<_> = left.iter().collect();
    let right: BTreeSet<_> = right.iter().collect();
    left == right
}

fn is_refinement(existing: &ClaimObject, proposed: &ClaimObject) -> bool {
    match (existing, proposed) {
        (ClaimObject::String(old), ClaimObject::String(new)) => {
            let old = normalize(old);
            let new = normalize(new);
            new.len() > old.len() && new.contains(&old)
        }
        (ClaimObject::Structured(old), ClaimObject::Structured(new)) => {
            let (Some(old), Some(new)) = (old.as_object(), new.as_object()) else {
                return false;
            };
            new.len() > old.len() && old.iter().all(|(key, value)| new.get(key) == Some(value))
        }
        _ => false,
    }
}

/// Resolves a predicate anchor supplied by the trusted ontology adapter.
pub fn predicate_for<'a>(
    reference: &str,
    predicates: &'a BTreeMap<String, PredicateDefinition>,
) -> Result<&'a PredicateDefinition, ValidationIssue> {
    predicates
        .get(reference)
        .ok_or(ValidationIssue::UnknownPredicateAnchor)
}
