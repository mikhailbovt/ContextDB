//! Provider-neutral conversational lifecycle contracts.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use contextdb_cognition::StructuredTurnCandidate;
use contextdb_core::{
    ActivatedNode, ActiveReferent, ActorId, CheckpointId, CommitSeq, ContentBlockId, ContentDigest,
    ConversationMode, EvidenceId, GoalFrame, MemoryRef, MemorySpaceId, MemorySubjectId,
    NonEmptyVec, ObservationId, OpenQuestion, PolicyId, ScopeId, SemanticEnvelope, Session,
    SessionId, SituationFrame, SourceId, StreamId, TimestampMicros, Validate, WeightedScope,
    WorkingHypothesis, WorkspaceId,
};
use contextdb_storage::Durability;
use serde::{Deserialize, Serialize};

use crate::{ChatError, Result};

const MAX_CHAT_TEXT_BYTES: usize = 1024 * 1024;
const MAX_KEY_BYTES: usize = 256;
const MAX_RUNTIME_ID_BYTES: usize = 256;

fn validate_bounded(value: &str, maximum: usize, field: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ChatError::InvalidInput(field));
    }
    Ok(())
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&part.len().to_be_bytes());
        hasher.update(part);
    }
    ContentDigest::from_bytes(*hasher.finalize().as_bytes())
}

macro_rules! text_id {
    ($name:ident, $field:literal) => {
        #[doc = concat!("Bounded stable `", stringify!($name), "`.")]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated `", stringify!($name), "`.")]
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_bounded(&value, MAX_KEY_BYTES, $field)?;
                Ok(Self(value))
            }

            /// Returns the stable string representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

text_id!(ChatInteractionId, "interaction_id");
text_id!(SemanticJobId, "semantic_job_id");
text_id!(ControlJobId, "control_job_id");

/// Bounded conversational content kept out of `Debug`, audit, and metrics.
#[derive(Clone)]
pub struct ChatText {
    value: Arc<str>,
    digest: ContentDigest,
}

impl ChatText {
    /// Creates non-blank bounded UTF-8 content.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > MAX_CHAT_TEXT_BYTES {
            return Err(ChatError::InvalidInput("chat_text"));
        }
        let digest = digest_parts(b"contextdb-chat-text-v1\0", &[value.as_bytes()]);
        Ok(Self {
            value: Arc::from(value),
            digest,
        })
    }

    /// Returns content to the explicitly selected capture/runtime boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Returns the protected content digest.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Returns the UTF-8 byte length without exposing content.
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Chat text is always non-empty after construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for ChatText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatText")
            .field("digest", &self.digest)
            .field("bytes", &self.value.len())
            .finish()
    }
}

/// Bounded idempotency key. Only its domain-separated digest is persisted by
/// chat state; the journal independently persists its own key digest.
#[derive(Clone)]
pub struct ChatIdempotencyKey {
    digest: [u8; 32],
}

impl ChatIdempotencyKey {
    /// Creates a non-blank bounded key.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_bounded(&value, MAX_KEY_BYTES, "idempotency_key")?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"contextdb-chat-idempotency-v1\0");
        hasher.update(value.as_bytes());
        Ok(Self {
            digest: *hasher.finalize().as_bytes(),
        })
    }

    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub(crate) fn journal_key_for_digest(
    digest: [u8; 32],
    suffix: &str,
) -> Result<contextdb_journal::IdempotencyKey> {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    contextdb_journal::IdempotencyKey::new(format!("chat:{encoded}:{suffix}"))
        .map_err(ChatError::from)
}

impl fmt::Debug for ChatIdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatIdempotencyKey")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Explicit session-scoped authorization input. The middleware never accepts
/// caller-selected scopes separately from this principal and registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationPrincipal {
    /// Authenticated actor.
    pub actor_id: ActorId,
    /// Actor's continuity-bearing subject.
    pub subject_id: MemorySubjectId,
    /// Memory spaces authorized before retrieval or capture.
    pub allowed_memory_spaces: BTreeSet<MemorySpaceId>,
    /// Scope IDs authorized before retrieval or capture.
    pub allowed_scopes: BTreeSet<ScopeId>,
}

impl ConversationPrincipal {
    pub(crate) fn authorizes(&self, registration: &ChatSessionRegistration) -> bool {
        self.allowed_memory_spaces
            .contains(&registration.session.memory_space)
            && registration
                .initial_frame
                .active_scopes
                .iter()
                .all(|scope| self.allowed_scopes.contains(&scope.scope.id))
    }
}

/// Durable configuration for one conversation. It binds participants, source,
/// stream, memory space, policy envelopes, and the initial working frame.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatSessionRegistration {
    /// Core session identity and lifecycle.
    pub session: Session,
    /// Stable conversation source.
    pub source_id: SourceId,
    /// Ordered source stream.
    pub stream_id: StreamId,
    /// Policy object selected by the host for conversational recall.
    pub memory_use_policy: PolicyId,
    /// Authenticated user actor.
    pub user_actor: ActorId,
    /// Authenticated assistant actor.
    pub assistant_actor: ActorId,
    /// User memory subject.
    pub user_subject: MemorySubjectId,
    /// Assistant/agent memory subject.
    pub assistant_subject: MemorySubjectId,
    /// Policy template for user evidence. Per-turn provenance is replaced.
    pub user_envelope: SemanticEnvelope,
    /// Policy template for assistant evidence. Per-turn provenance is replaced.
    pub assistant_envelope: SemanticEnvelope,
    /// Initial expiring working state.
    pub initial_frame: SituationFrame,
}

impl fmt::Debug for ChatSessionRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatSessionRegistration")
            .field("session_id", &self.session.id)
            .field("workspace_id", &self.session.workspace_id)
            .field("memory_space", &self.session.memory_space)
            .field("source_id", &self.source_id)
            .field("stream_id", &self.stream_id)
            .field("user_actor", &self.user_actor)
            .field("assistant_actor", &self.assistant_actor)
            .field("participant_count", &self.session.participants.len())
            .field(
                "active_scope_count",
                &self.initial_frame.active_scopes.len(),
            )
            .finish_non_exhaustive()
    }
}

impl ChatSessionRegistration {
    /// Validates cross-object session and policy bindings.
    pub fn validate(&self) -> Result<()> {
        self.session.validate()?;
        self.user_envelope.validate()?;
        self.assistant_envelope.validate()?;
        self.initial_frame.validate()?;
        if self.initial_frame.session_id != self.session.id
            || !self.session.participants.contains(&self.user_subject)
            || !self.session.participants.contains(&self.assistant_subject)
            || self.user_actor == self.assistant_actor
            || self.user_subject == self.assistant_subject
        {
            return Err(ChatError::InvalidInput("session_participant_binding"));
        }
        if self.user_envelope.perspective.narrator != self.user_actor
            || self.user_envelope.perspective.knower != self.user_subject
            || self.assistant_envelope.perspective.narrator != self.assistant_actor
            || self.assistant_envelope.perspective.knower != self.assistant_subject
        {
            return Err(ChatError::InvalidInput("session_perspective_binding"));
        }
        let frame_scopes: BTreeSet<_> = self
            .initial_frame
            .active_scopes
            .iter()
            .map(|scope| &scope.scope)
            .collect();
        let user_scopes: BTreeSet<_> = self.user_envelope.scopes.iter().collect();
        let assistant_scopes: BTreeSet<_> = self.assistant_envelope.scopes.iter().collect();
        if !frame_scopes.is_subset(&user_scopes) || !frame_scopes.is_subset(&assistant_scopes) {
            return Err(ChatError::InvalidInput("session_scope_binding"));
        }
        Ok(())
    }

    pub(crate) fn workspace_id(&self) -> WorkspaceId {
        self.session.workspace_id
    }
}

/// Speaker role for one separately durable evidence unit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatSpeaker {
    /// Authenticated user turn.
    User,
    /// Assistant/model output, retained as agent evidence rather than truth.
    Assistant,
}

impl ChatSpeaker {
    pub(crate) const fn actor(self, registration: &ChatSessionRegistration) -> ActorId {
        match self {
            Self::User => registration.user_actor,
            Self::Assistant => registration.assistant_actor,
        }
    }

    pub(crate) const fn subject(self, registration: &ChatSessionRegistration) -> MemorySubjectId {
        match self {
            Self::User => registration.user_subject,
            Self::Assistant => registration.assistant_subject,
        }
    }
}

/// Deterministic, caller-evaluated working-state patch. Every field remains
/// working memory until a separate cognition transaction promotes semantics.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationPatch {
    /// Updated conversation mode.
    pub conversation_mode: Option<ConversationMode>,
    /// Replaces active topics when supplied.
    pub active_topics: Option<Vec<ActivatedNode>>,
    /// Replaces active referents when supplied.
    pub active_referents: Option<Vec<ActiveReferent>>,
    /// Replaces the goal stack when supplied.
    pub goal_stack: Option<Vec<GoalFrame>>,
    /// Replaces active scopes; cannot be empty.
    pub active_scopes: Option<NonEmptyVec<WeightedScope>>,
    /// Replaces open questions.
    pub open_questions: Option<Vec<OpenQuestion>>,
    /// Replaces open-loop nodes.
    pub open_loops: Option<Vec<contextdb_core::NodeId>>,
    /// Replaces working hypotheses.
    pub working_hypotheses: Option<Vec<WorkingHypothesis>>,
    /// Replaces host environment metadata.
    pub environment: Option<serde_json::Value>,
}

impl fmt::Debug for SituationPatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SituationPatch")
            .field("has_conversation_mode", &self.conversation_mode.is_some())
            .field(
                "active_topic_count",
                &self.active_topics.as_ref().map(Vec::len),
            )
            .field(
                "active_referent_count",
                &self.active_referents.as_ref().map(Vec::len),
            )
            .field("goal_count", &self.goal_stack.as_ref().map(Vec::len))
            .field(
                "active_scope_count",
                &self.active_scopes.as_ref().map(|scopes| scopes.len()),
            )
            .field(
                "open_question_count",
                &self.open_questions.as_ref().map(Vec::len),
            )
            .field("open_loop_count", &self.open_loops.as_ref().map(Vec::len))
            .field(
                "working_hypothesis_count",
                &self.working_hypotheses.as_ref().map(Vec::len),
            )
            .field("has_environment", &self.environment.is_some())
            .finish()
    }
}

impl SituationPatch {
    pub(crate) fn validate(&self) -> Result<()> {
        for topic in self.active_topics.iter().flatten() {
            topic.validate()?;
        }
        for referent in self.active_referents.iter().flatten() {
            referent.validate()?;
        }
        for goal in self.goal_stack.iter().flatten() {
            goal.validate()?;
        }
        for scope in self.active_scopes.iter().flat_map(|scopes| scopes.iter()) {
            scope.validate()?;
        }
        for question in self.open_questions.iter().flatten() {
            question.validate()?;
        }
        for hypothesis in self.working_hypotheses.iter().flatten() {
            hypothesis.validate()?;
        }
        Ok(())
    }
}

/// Caller-evaluated recall intent. Raw natural-language classification may be
/// supplied by deterministic rules or the M9 proposal boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationMemoryIntent {
    /// Explicitly disable recall for this turn. Durable capture policy remains
    /// governed by the session envelope and typed boundary/control operations.
    Never,
    /// Run only if active state provides a deterministic reason.
    Automatic,
    /// User explicitly requested remembered information.
    ExplicitRecall,
    /// Current wording depends on a prior shared referent or open loop.
    ImplicitContinuity,
    /// Query requests earlier state rather than current truth.
    Historical,
    /// Query asks about a person or relationship.
    Relational,
    /// Query asks for a recurring pattern with hypothesis semantics.
    Reflective,
    /// Small restart/session bootstrap pack.
    Bootstrap,
}

/// Input to the synchronous pre-response hook.
#[derive(Clone)]
pub struct BeforeTurnRequest {
    /// Session to capture and recall within.
    pub session_id: SessionId,
    /// Authenticated user principal.
    pub principal: ConversationPrincipal,
    /// Links user and assistant evidence units.
    pub interaction_id: ChatInteractionId,
    /// Lost-response-safe operation key.
    pub idempotency_key: ChatIdempotencyKey,
    /// User content.
    pub message: ChatText,
    /// Event time supplied by the host.
    pub occurred_at: TimestampMicros,
    /// Evaluated working-state changes.
    pub situation: SituationPatch,
    /// Evaluated memory intent.
    pub memory_intent: ConversationMemoryIntent,
    /// Hard hot-path recall deadline.
    pub max_recall_micros: u64,
    /// Target runtime profile used by the context compiler/renderer.
    pub target_profile_id: String,
    /// Trusted structured M10 candidates, normally empty for raw chat.
    pub structured_candidates: Vec<StructuredTurnCandidate>,
}

impl fmt::Debug for BeforeTurnRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BeforeTurnRequest")
            .field("session_id", &self.session_id)
            .field("principal", &self.principal)
            .field("interaction_id", &self.interaction_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("message", &self.message)
            .field("occurred_at", &self.occurred_at)
            .field("memory_intent", &self.memory_intent)
            .field("max_recall_micros", &self.max_recall_micros)
            .field("target_profile_id", &self.target_profile_id)
            .field("structured_candidates", &self.structured_candidates.len())
            .finish_non_exhaustive()
    }
}

impl BeforeTurnRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_recall_micros == 0 {
            return Err(ChatError::InvalidInput("max_recall_micros"));
        }
        validate_bounded(
            &self.target_profile_id,
            MAX_RUNTIME_ID_BYTES,
            "target_profile_id",
        )?;
        self.situation.validate()
    }
}

/// Input to the post-response durable capture hook.
#[derive(Clone)]
pub struct AfterTurnRequest {
    /// Session to capture within.
    pub session_id: SessionId,
    /// Authenticated assistant/service principal.
    pub principal: ConversationPrincipal,
    /// Same interaction as the user turn.
    pub interaction_id: ChatInteractionId,
    /// Lost-response-safe operation key.
    pub idempotency_key: ChatIdempotencyKey,
    /// Assistant content. It remains agent evidence, not a user/world fact.
    pub response: ChatText,
    /// Event time supplied by the host.
    pub occurred_at: TimestampMicros,
    /// Evaluated working-state changes after response generation.
    pub situation: SituationPatch,
    /// Trusted structured M10 candidates, normally empty.
    pub structured_candidates: Vec<StructuredTurnCandidate>,
}

impl fmt::Debug for AfterTurnRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AfterTurnRequest")
            .field("session_id", &self.session_id)
            .field("principal", &self.principal)
            .field("interaction_id", &self.interaction_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("response", &self.response)
            .field("occurred_at", &self.occurred_at)
            .field("structured_candidates", &self.structured_candidates.len())
            .finish_non_exhaustive()
    }
}

impl AfterTurnRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        self.situation.validate()
    }
}

/// Durable capture receipt. Semantic extraction is deliberately a separate
/// status/job and cannot weaken observation acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatCaptureReceipt {
    /// Immutable observation identity.
    pub observation_id: ObservationId,
    /// Evidence identity used by M10.
    pub evidence_id: EvidenceId,
    /// Content indirection identity.
    pub content_block_id: ContentBlockId,
    /// Journal logical commit sequence.
    pub commit_seq: CommitSeq,
    /// Durability achieved before acknowledgement.
    pub durability: Durability,
    /// True for an idempotent lost-response retry.
    pub replayed: bool,
    /// Stable source stream ordinal.
    pub ordinal: u64,
    /// Durable post-turn extraction job.
    pub semantic_job_id: SemanticJobId,
}

/// Payload-free persisted turn summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatTurnSummary {
    /// Session.
    pub session_id: SessionId,
    /// Interaction linking user and assistant turns.
    pub interaction_id: ChatInteractionId,
    /// Speaker.
    pub speaker: ChatSpeaker,
    /// Observation.
    pub observation_id: ObservationId,
    /// Evidence.
    pub evidence_id: EvidenceId,
    /// Content digest, never content.
    pub content_digest: ContentDigest,
    /// Ordered stream position.
    pub ordinal: u64,
    /// Durable journal sequence.
    pub commit_seq: CommitSeq,
}

/// Stable view of a persisted conversation session.
#[derive(Clone, PartialEq)]
pub struct ChatSessionSnapshot {
    /// Core registration.
    pub registration: ChatSessionRegistration,
    /// Current working frame.
    pub situation: SituationFrame,
    /// Next reserved stream ordinal.
    pub next_ordinal: u64,
    /// Recent durable turns in order.
    pub recent_turns: Vec<ChatTurnSummary>,
    /// Most recent checkpoint, if any.
    pub latest_checkpoint: Option<CheckpointId>,
}

impl fmt::Debug for ChatSessionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatSessionSnapshot")
            .field("registration", &self.registration)
            .field("next_ordinal", &self.next_ordinal)
            .field("recent_turn_count", &self.recent_turns.len())
            .field("latest_checkpoint", &self.latest_checkpoint)
            .field("active_topic_count", &self.situation.active_topics.len())
            .field(
                "active_referent_count",
                &self.situation.active_referents.len(),
            )
            .field("goal_count", &self.situation.goal_stack.len())
            .field("open_loop_count", &self.situation.open_loops.len())
            .finish_non_exhaustive()
    }
}

/// Checkpoint request. Working/task state never becomes semantic truth merely
/// because it is persisted.
#[derive(Clone)]
pub struct CheckpointRequest {
    /// Session.
    pub session_id: SessionId,
    /// Authorized principal.
    pub principal: ConversationPrincipal,
    /// Idempotent operation identity.
    pub idempotency_key: ChatIdempotencyKey,
    /// Opaque host task state.
    pub task_state: serde_json::Value,
    /// Stable semantic/evidence references required for resume.
    pub required_memory_refs: Vec<MemoryRef>,
}

impl fmt::Debug for CheckpointRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointRequest")
            .field("session_id", &self.session_id)
            .field("principal", &self.principal)
            .field("idempotency_key", &self.idempotency_key)
            .field("required_memory_refs", &self.required_memory_refs)
            .finish_non_exhaustive()
    }
}

/// Checkpoint receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointReceipt {
    /// Durable checkpoint identity.
    pub checkpoint_id: CheckpointId,
    /// Journal snapshot represented by the checkpoint.
    pub created_seq: CommitSeq,
    /// Whether an identical request replayed.
    pub replayed: bool,
}

/// Package-level durability and bounded-state configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChatMiddlewareConfig {
    /// Required durability for content, observations, state, and jobs.
    pub durability: Durability,
    /// Maximum recent observations retained in the hot frame/session view.
    pub max_recent_turns: usize,
    /// Working-frame TTL refreshed after capture.
    pub situation_ttl_micros: u64,
    /// Maximum automatic `MentionNaturally` directives admitted per turn.
    pub max_automatic_mentions: usize,
}

impl Default for ChatMiddlewareConfig {
    fn default() -> Self {
        Self {
            durability: Durability::Sync,
            max_recent_turns: 32,
            situation_ttl_micros: 30 * 60 * 1_000_000,
            max_automatic_mentions: 1,
        }
    }
}

impl ChatMiddlewareConfig {
    pub(crate) fn validate(self) -> Result<()> {
        if self.max_recent_turns == 0
            || self.max_recent_turns > 10_000
            || self.situation_ttl_micros == 0
        {
            return Err(ChatError::InvalidInput("chat_middleware_config"));
        }
        Ok(())
    }
}
