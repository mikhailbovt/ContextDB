//! Provider-neutral conversational recall boundary.

use std::collections::BTreeSet;
use std::fmt;

use contextdb_context::{CanonicalSerializer, CompiledContext, UseAction};
use contextdb_core::{
    ContextPackId, CueBundle, EvidencePolicy, FacetRequirement, Purpose, QueryContent,
    RecallBudgets, RecallIntent, RecallRequest, TemporalConstraint, TemporalContext, Validate,
};

use crate::{
    BeforeTurnRequest, ChatCaptureReceipt, ChatError, ChatSessionSnapshot,
    ConversationMemoryIntent, Result,
};

/// Deterministic, authorization-bound input to a host recall implementation.
#[derive(Clone, PartialEq)]
pub struct ConversationRecallPlan {
    /// Caller-stable pack identity derived from the acknowledged user observation.
    pub pack_id: ContextPackId,
    /// Caller-evaluated memory intent retained for an exact service-mode mapping.
    pub memory_intent: ConversationMemoryIntent,
    /// Canonical core recall request.
    pub request: RecallRequest,
    /// Workspace expected in the resulting scope manifest.
    pub workspace: String,
    /// Subject expected in the resulting scope manifest.
    pub subject: String,
    /// String form of every authorized active scope.
    pub scopes: BTreeSet<String>,
    /// Runtime rendering profile expected in the result.
    pub target_profile_id: String,
    /// Latest journal prefix visible when planning began.
    pub maximum_snapshot_seq: u64,
}

impl fmt::Debug for ConversationRecallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationRecallPlan")
            .field("pack_id", &self.pack_id)
            .field("memory_intent", &self.memory_intent)
            .field("intent", &self.request.intent)
            .field("scope_count", &self.scopes.len())
            .field("target_profile_id", &self.target_profile_id)
            .field("maximum_snapshot_seq", &self.maximum_snapshot_seq)
            .field(
                "max_latency_micros",
                &self.request.budgets.max_latency_micros,
            )
            .finish_non_exhaustive()
    }
}

impl ConversationRecallPlan {
    /// Constructs the exact query from durable state after user capture.
    pub fn from_turn(
        request: &BeforeTurnRequest,
        capture: &ChatCaptureReceipt,
        session: &ChatSessionSnapshot,
        journal_head: u64,
    ) -> Result<Self> {
        let intent = recall_intent(request.memory_intent);
        let temporal = match request.memory_intent {
            ConversationMemoryIntent::Historical => TemporalConstraint::KnownAt {
                commit_seq: capture.commit_seq,
            },
            _ => TemporalConstraint::Current,
        };
        let purpose = match request.memory_intent {
            ConversationMemoryIntent::Reflective => Purpose::Personalisation,
            ConversationMemoryIntent::Historical => Purpose::KnowledgeRecall,
            _ => Purpose::Conversation,
        };
        let active_topics = session
            .situation
            .active_topics
            .iter()
            .map(|topic| topic.node_id)
            .collect();
        let goal = session
            .situation
            .goal_stack
            .first()
            .map(|goal| goal.statement.clone());
        let core = RecallRequest {
            agent_id: session.registration.session.agent_id,
            actor_id: request.principal.actor_id,
            session_id: Some(request.session_id),
            cues: CueBundle {
                current_input: QueryContent::Text(request.message.as_str().to_owned()),
                recent_observations: session.situation.recent_observations.clone(),
                participants: session.registration.session.participants.clone(),
                active_referents: session.situation.active_referents.clone(),
                active_topics,
                temporal_context: TemporalContext {
                    now: request.occurred_at,
                    referenced_valid_time: None,
                    known_at: Some(capture.commit_seq),
                },
                location_context: None,
                conversation_mode: session.situation.conversation_mode.clone(),
                goal,
                interaction_signals: session.situation.open_loops.clone(),
            },
            intent,
            scopes: session
                .situation
                .active_scopes
                .clone()
                .into_vec()
                .into_iter()
                .map(|weighted| weighted.scope)
                .collect::<Vec<_>>()
                .try_into_non_empty("conversation_recall.scopes")?,
            temporal,
            required_facets: required_facets(request.memory_intent),
            budgets: RecallBudgets {
                max_tokens: 4_096,
                max_latency_micros: request.max_recall_micros,
                max_candidates: 256,
                max_graph_visits: 2_048,
                max_evidence_items: 64,
            },
            evidence_policy: EvidencePolicy {
                require_primary_evidence: matches!(
                    request.memory_intent,
                    ConversationMemoryIntent::Historical | ConversationMemoryIntent::ExplicitRecall
                ),
                include_quotes: false,
                permit_derived_only: false,
            },
            memory_use_policy: session.registration.memory_use_policy,
            purpose,
            target_model: None,
        };
        core.validate()?;
        let scopes = session
            .situation
            .active_scopes
            .iter()
            .map(|scope| scope.scope.id.to_string())
            .collect();
        Ok(Self {
            pack_id: ContextPackId::from_uuid(capture.observation_id.as_uuid())?,
            memory_intent: request.memory_intent,
            request: core,
            workspace: session.registration.session.workspace_id.to_string(),
            subject: request.principal.subject_id.to_string(),
            scopes,
            target_profile_id: request.target_profile_id.clone(),
            maximum_snapshot_seq: journal_head,
        })
    }

    /// Rejects stale/misbound/non-canonical output before it reaches a model.
    pub fn validate_result(&self, compiled: &CompiledContext) -> Result<()> {
        compiled.pack.validate()?;
        if compiled.pack.scope_manifest.workspace != self.workspace
            || compiled.pack.scope_manifest.subject != self.subject
            || !compiled.pack.scope_manifest.scopes.is_subset(&self.scopes)
            || compiled.pack.snapshot.commit_seq > self.maximum_snapshot_seq
            || compiled.rendered.profile_id != self.target_profile_id
            || compiled.pack.scope_manifest.purpose.core_purpose() != self.request.purpose
        {
            return Err(ChatError::Recall(
                "compiled context is outside the bound session request".to_owned(),
            ));
        }
        let canonical_json = CanonicalSerializer::to_json(&compiled.pack)?;
        let canonical_protobuf = CanonicalSerializer::to_protobuf(&compiled.pack)?;
        let canonical_digest = CanonicalSerializer::digest(&compiled.pack)?;
        if canonical_json != compiled.canonical_json
            || canonical_protobuf != compiled.canonical_protobuf
            || canonical_digest != compiled.canonical_digest
        {
            return Err(ChatError::Recall(
                "compiled context canonical bytes do not verify".to_owned(),
            ));
        }
        Ok(())
    }

    /// Counts directives which would expose memory in natural language.
    #[must_use]
    pub fn automatic_mentions(compiled: &CompiledContext) -> usize {
        compiled
            .pack
            .use_directives
            .iter()
            .filter(|directive| directive.action == UseAction::MentionNaturally)
            .count()
    }
}

/// Synchronous provider-neutral recall + context-compilation seam.
pub trait ConversationRecall: Send + Sync {
    /// Returns an already canonical, policy-safe ContextPack or an explicit
    /// no-memory result. Errors are sanitized and do not roll back capture.
    fn recall(&self, plan: &ConversationRecallPlan) -> Result<Option<CompiledContext>>;
}

/// Deterministic adapter for deployments which intentionally run without memory recall.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoMemoryRecall;

impl ConversationRecall for NoMemoryRecall {
    fn recall(&self, _plan: &ConversationRecallPlan) -> Result<Option<CompiledContext>> {
        Ok(None)
    }
}

fn recall_intent(intent: ConversationMemoryIntent) -> RecallIntent {
    match intent {
        ConversationMemoryIntent::Never | ConversationMemoryIntent::Automatic => {
            RecallIntent::Continuity
        }
        ConversationMemoryIntent::ExplicitRecall => RecallIntent::CurrentTruth,
        ConversationMemoryIntent::ImplicitContinuity => RecallIntent::Continuity,
        ConversationMemoryIntent::Historical => RecallIntent::HistoricalTruth,
        ConversationMemoryIntent::Relational => RecallIntent::Relational,
        ConversationMemoryIntent::Reflective => RecallIntent::Reflective,
        ConversationMemoryIntent::Bootstrap => RecallIntent::Bootstrap,
    }
}

fn required_facets(intent: ConversationMemoryIntent) -> Vec<FacetRequirement> {
    let name = match intent {
        ConversationMemoryIntent::Relational => "relationship",
        ConversationMemoryIntent::Reflective => "pattern",
        ConversationMemoryIntent::Historical => "historical_state",
        ConversationMemoryIntent::ImplicitContinuity => "shared_history",
        ConversationMemoryIntent::Bootstrap => "continuity",
        ConversationMemoryIntent::ExplicitRecall => "requested_memory",
        ConversationMemoryIntent::Never | ConversationMemoryIntent::Automatic => return Vec::new(),
    };
    vec![FacetRequirement {
        name: name.to_owned(),
        required: true,
        minimum_confidence: 0.5,
    }]
}

trait TryIntoNonEmpty<T> {
    fn try_into_non_empty(self, field: &'static str) -> Result<contextdb_core::NonEmptyVec<T>>;
}

impl<T> TryIntoNonEmpty<T> for Vec<T> {
    fn try_into_non_empty(self, field: &'static str) -> Result<contextdb_core::NonEmptyVec<T>> {
        Ok(contextdb_core::NonEmptyVec::try_from_vec(self, field)?)
    }
}
