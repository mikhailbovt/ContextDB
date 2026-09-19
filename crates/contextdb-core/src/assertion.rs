//! Authority and resolution over the existing claim and bitemporal model.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    AcceptanceState, BitemporalRange, Claim, ClaimId, ClaimObject, ClaimRevision, CommitSeq,
    EpistemicBasis, EventRole, LifecycleState, NodeId, ObservationId, OriginalSourceSpan,
    PredicateId, RevisionNumber, ScopeId, ScopeInheritance, TimeRange, TimestampMicros, Validate,
    ValidationError, ValidationResult,
};

/// One exact semantic slot. Branches use different scope identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateKey {
    pub subject: NodeId,
    pub predicate: PredicateId,
    pub scope: ScopeId,
}

/// Attribution comes from the authenticated capture record, never from its text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAuthority {
    pub adapter_id: String,
    pub actor_id: String,
    pub role: EventRole,
}

/// What an assertion represents, independent of whether its text is retrievable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionStance {
    Reported,
    Proposed,
    Inferred,
    Observed,
    Decision,
}

/// An explicit schema grant, installed by the workspace authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionGrant {
    pub source: SourceAuthority,
    pub stance: AssertionStance,
}

/// Versioned rule for this predicate/scope. There is deliberately no implicit
/// last-writer-wins or confidence/embedding threshold for resolving disagreement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPolicy {
    pub key: StateKey,
    pub version: RevisionNumber,
    pub grants: Vec<AssertionGrant>,
}

impl AuthorityPolicy {
    #[must_use]
    pub fn allows(&self, source: &SourceAuthority, stance: AssertionStance) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.source == *source && grant.stance == stance)
    }
}

impl Validate for AuthorityPolicy {
    fn validate(&self) -> ValidationResult {
        if self.grants.is_empty() || self.grants.len() > 64 {
            return Err(invalid("authority policy requires 1..64 explicit grants"));
        }
        for (index, grant) in self.grants.iter().enumerate() {
            if grant.source.actor_id.trim().is_empty()
                || grant.source.adapter_id.trim().is_empty()
                || grant.source.actor_id.len() > 1024
                || grant.source.adapter_id.len() > 2048
                || self.grants[..index].contains(grant)
            {
                return Err(invalid("authority grant identity is invalid"));
            }
            let permitted = match grant.stance {
                AssertionStance::Decision => {
                    matches!(grant.source.role, EventRole::User | EventRole::Host)
                }
                AssertionStance::Observed => matches!(
                    grant.source.role,
                    EventRole::Tool | EventRole::ExternalSource
                ),
                AssertionStance::Reported => matches!(
                    grant.source.role,
                    EventRole::User | EventRole::ExternalSource | EventRole::Import
                ),
                AssertionStance::Proposed | AssertionStance::Inferred => false,
            };
            if !permitted {
                return Err(invalid(
                    "a proposal or inference cannot be granted resolution authority",
                ));
            }
        }
        Ok(())
    }
}

/// An immutable source assertion using canonical Claim/ClaimRevision identities.
/// Supersession remains the existing revision's explicit claim-ID relation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAssertion {
    pub key: StateKey,
    pub claim: Claim,
    pub revision: ClaimRevision,
    pub stance: AssertionStance,
    pub source: SourceAuthority,
    pub originating_event: ObservationId,
    pub original_evidence: Vec<OriginalSourceSpan>,
}

impl Validate for SourceAssertion {
    fn validate(&self) -> ValidationResult {
        self.claim.validate()?;
        self.revision.validate()?;
        let revision = &self.revision;
        if self.claim.id != revision.claim_id
            || self.claim.subject != self.key.subject
            || self.claim.predicate != self.key.predicate
            || revision.revision != RevisionNumber::FIRST
            || self.claim.created_seq != revision.temporal.transaction_time.start
            || revision.temporal.transaction_time.end.is_some()
            || revision.epistemic.lifecycle != LifecycleState::Active
            || !revision.envelope.scopes.iter().any(|scope| {
                scope.id == self.key.scope && scope.inheritance == ScopeInheritance::Exact
            })
            || revision.supersedes.contains(&self.claim.id)
            || revision.supersedes.len() > 64
            || revision
                .supersedes
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != revision.supersedes.len()
        {
            return Err(invalid(
                "assertion does not match its canonical claim revision",
            ));
        }
        let basis = match self.stance {
            AssertionStance::Observed => EpistemicBasis::Observation,
            AssertionStance::Inferred => EpistemicBasis::ModelInference,
            _ => EpistemicBasis::ActorAssertion,
        };
        let acceptance = match self.stance {
            AssertionStance::Proposed | AssertionStance::Inferred => AcceptanceState::Proposed,
            _ => AcceptanceState::Accepted,
        };
        if revision.epistemic.basis != basis || revision.epistemic.acceptance != acceptance {
            return Err(invalid("assertion stance and epistemic state disagree"));
        }
        if matches!(
            self.stance,
            AssertionStance::Proposed | AssertionStance::Inferred
        ) && !revision.supersedes.is_empty()
        {
            return Err(invalid(
                "a proposal or inference cannot supersede accepted state",
            ));
        }
        validate_original_support(self.originating_event, &self.original_evidence)?;
        if revision.evidence.len() != self.original_evidence.len()
            || revision
                .evidence
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != revision.evidence.len()
        {
            return Err(invalid(
                "canonical evidence IDs must map one-to-one to original spans",
            ));
        }
        Ok(())
    }
}

/// A supported negative transition. Retraction does not erase the old claim or
/// require selecting an unrelated replacement value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionRetraction {
    pub key: StateKey,
    pub target: ClaimId,
    pub temporal: BitemporalRange,
    pub source: SourceAuthority,
    pub originating_event: ObservationId,
    pub original_evidence: Vec<OriginalSourceSpan>,
}

impl Validate for AssertionRetraction {
    fn validate(&self) -> ValidationResult {
        self.temporal.validate()?;
        if self.temporal.transaction_time.end.is_some() {
            return Err(invalid(
                "accepted retraction requires an open transaction interval",
            ));
        }
        validate_original_support(self.originating_event, &self.original_evidence)
    }
}

fn validate_original_support(
    origin: ObservationId,
    evidence: &[OriginalSourceSpan],
) -> ValidationResult {
    if evidence.is_empty()
        || evidence.len() > 64
        || !evidence.iter().any(|span| span.event_id == origin)
        || evidence.iter().any(|span| span.start >= span.end)
    {
        return Err(invalid(
            "assertion requires bounded original spans including its source",
        ));
    }
    Ok(())
}

/// One value and the exact canonical assertions that support it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateAlternative {
    pub value: ClaimObject,
    pub supporting_claims: BTreeSet<ClaimId>,
}

/// Current truth is never inferred from a ranking winner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolvedState {
    Known { answer: StateAlternative },
    Conflict { alternatives: Vec<StateAlternative> },
    Unknown,
    Incomplete,
}

/// The resolver's provenance and next applicability boundary. Storage adapters
/// retain the assertions and policy that produced this deterministic result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateResolution {
    pub state: ResolvedState,
    pub retired_claims: BTreeSet<ClaimId>,
    pub valid_until: Option<TimestampMicros>,
    pub policy_version: RevisionNumber,
}

/// Resolve an already authorized, complete slot at separate knowledge and valid
/// times. All accepted negative transitions apply even when their replacement
/// was later superseded; deletion of support must not resurrect the old value.
pub fn resolve_assertions(
    policy: &AuthorityPolicy,
    assertions: &[SourceAssertion],
    retractions: &[AssertionRetraction],
    known_at: CommitSeq,
    valid_at: TimestampMicros,
    complete: bool,
) -> ValidationResult<StateResolution> {
    policy.validate()?;
    let mut retired_claims = BTreeSet::new();
    let mut boundaries = Vec::new();
    for assertion in assertions {
        assertion.validate()?;
        if assertion.key != policy.key {
            return Err(invalid(
                "resolver input crosses a predicate or branch scope",
            ));
        }
        if assertion.claim.created_seq > known_at {
            continue;
        }
        collect_boundaries(
            assertion.revision.temporal.valid_time,
            valid_at,
            &mut boundaries,
        );
        if assertion.revision.temporal.valid_time.contains(valid_at) {
            // Publication validates the original grant and explicit target. The
            // historical negative effect survives subsequent grant revocation.
            retired_claims.extend(assertion.revision.supersedes.iter().copied());
        }
    }
    for retraction in retractions {
        retraction.validate()?;
        if retraction.key != policy.key {
            return Err(invalid("retraction crosses a state slot"));
        }
        if retraction.temporal.transaction_time.start > known_at {
            continue;
        }
        collect_boundaries(retraction.temporal.valid_time, valid_at, &mut boundaries);
        if retraction.temporal.valid_time.contains(valid_at) {
            retired_claims.insert(retraction.target);
        }
    }
    let mut alternatives: Vec<StateAlternative> = Vec::new();
    for assertion in assertions {
        if assertion.claim.created_seq > known_at
            || retired_claims.contains(&assertion.claim.id)
            || !assertion.revision.temporal.valid_time.contains(valid_at)
            || !policy.allows(&assertion.source, assertion.stance)
        {
            continue;
        }
        if let Some(existing) = alternatives
            .iter_mut()
            .find(|value| value.value == assertion.revision.object)
        {
            existing.supporting_claims.insert(assertion.claim.id);
        } else {
            alternatives.push(StateAlternative {
                value: assertion.revision.object.clone(),
                supporting_claims: BTreeSet::from([assertion.claim.id]),
            });
        }
    }
    alternatives.sort_by_key(|alternative| alternative.supporting_claims.first().copied());
    let state = if !complete {
        ResolvedState::Incomplete
    } else {
        match alternatives.len() {
            0 => ResolvedState::Unknown,
            1 => ResolvedState::Known {
                answer: alternatives.remove(0),
            },
            _ => ResolvedState::Conflict { alternatives },
        }
    };
    Ok(StateResolution {
        state,
        retired_claims,
        valid_until: boundaries.into_iter().min(),
        policy_version: policy.version,
    })
}

fn collect_boundaries(
    range: TimeRange,
    now: TimestampMicros,
    boundaries: &mut Vec<TimestampMicros>,
) {
    boundaries.extend(
        std::iter::once(range.start)
            .chain(range.end)
            .filter(|time| *time > now),
    );
}

fn invalid(reason: &'static str) -> ValidationError {
    ValidationError::InvalidState { reason }
}
