//! Embedded host publication of evidence-backed assertions and interpretation coverage.

use contextdb_core::{
    AssertionRetraction, AuthorityPolicy, ContentDigest, ObservationId, PipelineIdentity, ScopeId,
    SourceAssertion, StateKey, StateResolution, TimestampMicros,
};
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};

use crate::{AuthenticatedRequestContext, CaptureReceipt, ServiceResult};

/// Accepted semantic operations share the existing canonical claim model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AssertionMutation {
    /// Install the next exact revision of a predicate's authority rule.
    Policy {
        /// Next consecutive authority revision.
        policy: AuthorityPolicy,
    },
    /// Append an immutable source assertion. Input transaction times are genesis;
    /// the publication owner assigns their actual native logical commit.
    Assert {
        /// Canonical claim and its exact original support.
        assertion: Box<SourceAssertion>,
    },
    /// Append an explicit supported negative transition.
    Retract {
        /// Supported negative applicability transition.
        retraction: AssertionRetraction,
    },
}

impl AssertionMutation {
    /// Scope/predicate identity touched by this mutation.
    pub fn key(&self) -> &StateKey {
        match self {
            Self::Policy { policy } => &policy.key,
            Self::Assert { assertion } => &assertion.key,
            Self::Retract { retraction } => &retraction.key,
        }
    }
}

/// Host interpretation result. This is a traceable pipeline claim, not a
/// statement that arbitrary natural-language understanding has been proved.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterpretationDisposition {
    /// All supported state changes from this observation are in the batch.
    Interpreted,
    /// The host pipeline found no state-changing assertion in this observation.
    NoStateChange,
    /// Interpretation remains unresolved and blocks an unqualified current value.
    Pending,
}

/// Exact observation whose semantic coverage is being reported.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventInterpretation {
    /// Immutable accepted source identity.
    pub event_id: ObservationId,
    /// Explicit pipeline result.
    pub disposition: InterpretationDisposition,
}

/// Bounded host input window; source bytes are fetched through CapturePort.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpretationInputs {
    /// Current affected-scope epoch, required unchanged at publication.
    pub scope_epoch: u64,
    /// Workspace-local raw prefix represented by this window.
    pub through: u64,
    /// Relevant accepted events, including previously unresolved observations.
    pub events: Vec<ObservationId>,
    /// More raw work exists after this bounded window.
    pub more: bool,
}

/// One atomic host transaction. This port is not a model-facing promotion tool.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishAssertionsRequest {
    /// Authenticated workspace authority; Admin is required.
    pub context: AuthenticatedRequestContext,
    /// Reuse this exact key after an uncertain acknowledgement.
    pub idempotency_key: String,
    /// Exact branch/task scope, shared by every operation.
    pub scope: ScopeId,
    /// Compare-and-publish guard from the input window.
    pub expected_scope_epoch: u64,
    /// Raw prefix actually inspected; may lag the journal head.
    pub covered_through: u64,
    /// Traceable interpreter identity/version.
    pub pipeline: PipelineIdentity,
    /// Results for all relevant sources in the bounded window.
    pub interpretations: Vec<EventInterpretation>,
    /// Typed assertions, authority policies, and explicit negative transitions.
    pub mutations: Vec<AssertionMutation>,
    /// Optional source receipt that must already be durable and authorized.
    pub after_receipt: Option<CaptureReceipt>,
}

/// Durable native semantic publication identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionReceipt {
    /// Explicit domain distinct from capture and physical storage receipts.
    pub domain: String,
    /// Native database identity.
    pub database_id: String,
    /// Workspace-local accepted semantic position.
    pub workspace_commit: u64,
    /// Digest of the complete journaled accepted mutation payload.
    pub mutation_digest: ContentDigest,
}

/// Bitemporal state lookup under current source permissions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveStateRequest {
    /// Current authenticated reader.
    pub context: AuthenticatedRequestContext,
    /// Exact subject, predicate, and branch scope.
    pub key: StateKey,
    /// Optional native logical history position; None selects current knowledge.
    pub known_at: Option<u64>,
    /// Time at which a decision or fact is to apply.
    pub valid_at: TimestampMicros,
    /// Optional read-your-capture fence.
    pub after_receipt: Option<CaptureReceipt>,
}

/// Why a current-state answer cannot yet be complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateCoverageGap {
    /// A relevant original has not been fully interpreted.
    PendingInterpretation,
    /// The bounded raw window cannot establish complete coverage. Pending IDs
    /// are an authorized subset; no claim is made about the uninspected suffix.
    PendingWindowExceeded,
    /// The producer or source observation is incomplete.
    CaptureGap,
    /// Required support is no longer available under current source policy.
    SupportUnavailable,
}

/// Attributed state plus a private principal/snapshot/epoch binding for later
/// preparation and lease checks. A returned view is not itself an action lease.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateView {
    /// Value, conflict, unknown, or explicit incompleteness.
    pub resolution: StateResolution,
    /// Exact authority rule used by the resolver.
    pub authority: AuthorityPolicy,
    /// Authorized originals' assertions, including proposals and historical values.
    pub assertions: Vec<SourceAssertion>,
    /// Authorized explicit retractions retained for explanation.
    pub retractions: Vec<AssertionRetraction>,
    /// Conservative completeness failures, without private-source counts or IDs.
    pub coverage_gaps: Vec<StateCoverageGap>,
    /// Known authorized pending originals available for bounded raw materialization.
    pub pending_events: Vec<ObservationId>,
    /// Opaque binding; not a global activity counter or physical snapshot handle.
    pub binding: String,
}

/// Narrow host boundary. Implementations share the caller's entire work/deadline
/// allowance and must keep model-proposed memory separate from publication.
pub trait AssertionPort: Send + Sync {
    /// Fetch the next bounded interpretation window for one exact scope.
    fn interpretation_inputs(
        &self,
        context: &AuthenticatedRequestContext,
        scope: ScopeId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<InterpretationInputs>;
    /// Compare and atomically publish accepted semantics, coverage, and scope epoch.
    fn publish_assertions(
        &self,
        request: PublishAssertionsRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AssertionReceipt>;
    /// Resolve separate knowledge/valid times under current evidence authorization.
    fn resolve_state(
        &self,
        request: ResolveStateRequest,
        budget: &mut QueryBudget,
    ) -> ServiceResult<StateView>;
}
