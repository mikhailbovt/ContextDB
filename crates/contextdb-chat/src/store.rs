//! Durable conversational state store.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use contextdb_cognition::{
    EvidenceAuthority, EvidenceCatalog, EvidenceRecord, StructuredTurnCandidate,
};
use contextdb_core::{
    Checkpoint, CheckpointId, CommitSeq, ContentBlockId, ContentDigest, DerivationId,
    DerivationKind, DerivationRef, EpistemicRole, EvidenceId, EvidenceSelector, EvidenceSpan,
    LineageNode, NonEmptyVec, ObservationId, ObservationUnit, PipelineIdentity, SemanticEnvelope,
    SessionId, SituationFrame, StreamPosition, TimeRange, TimestampMicros, TrustClass, Validate,
};
use contextdb_format::RecordEnvelope;
use contextdb_journal::{
    CommitOptions, JournalCoordinator, JournalSnapshotSelector, ValidatedMutationBytes,
    ValidatedObservationBytes,
};
use contextdb_storage::{
    Keyspace, ReadSnapshot, SnapshotSelector, StorageEngine, VerifyMode, WriteTransaction,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    AfterTurnRequest, BeforeTurnRequest, ChatCaptureReceipt, ChatError, ChatIdempotencyKey,
    ChatInteractionId, ChatMiddlewareConfig, ChatSessionRegistration, ChatSessionSnapshot,
    ChatSpeaker, ChatTurnSummary, CheckpointReceipt, CheckpointRequest, ControlJobId,
    ControlJobStatus, ControlJobSummary, ConversationPrincipal, EnqueueControlRequest, Result,
    SemanticJobId, SituationPatch, StoredControlJob, journal_key_for_digest, requires_confirmation,
    summary as control_summary,
};

const SCHEMA_VERSION: u16 = 1;
const KIND_SESSION: u16 = 0x7101;
const KIND_CONTENT: u16 = 0x7102;
const KIND_CAPTURE: u16 = 0x7103;
const KIND_INTERACTION: u16 = 0x7104;
const KIND_TURN: u16 = 0x7105;
const KIND_JOB: u16 = 0x7106;
const KIND_CHECKPOINT: u16 = 0x7107;
const KIND_CHECKPOINT_KEY: u16 = 0x7108;
const KIND_CONTROL: u16 = 0x7109;

#[derive(Debug)]
struct Keyspaces {
    sessions: Keyspace,
    contents: Keyspace,
    captures: Keyspace,
    interactions: Keyspace,
    turns: Keyspace,
    jobs: Keyspace,
    checkpoints: Keyspace,
    checkpoint_keys: Keyspace,
    controls: Keyspace,
}

impl Keyspaces {
    fn new() -> Result<Self> {
        Ok(Self {
            sessions: Keyspace::new("chat_sessions_v1")?,
            contents: Keyspace::new("chat_contents_v1")?,
            captures: Keyspace::new("chat_captures_v1")?,
            interactions: Keyspace::new("chat_interactions_v1")?,
            turns: Keyspace::new("chat_turns_v1")?,
            jobs: Keyspace::new("chat_semantic_jobs_v1")?,
            checkpoints: Keyspace::new("chat_checkpoints_v1")?,
            checkpoint_keys: Keyspace::new("chat_checkpoint_keys_v1")?,
            controls: Keyspace::new("chat_controls_v1")?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredSession {
    registration: ChatSessionRegistration,
    situation: SituationFrame,
    next_ordinal: u64,
    recent_turns: Vec<ChatTurnSummary>,
    latest_checkpoint: Option<CheckpointId>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredContent {
    session_id: SessionId,
    content_block_id: ContentBlockId,
    content_digest: ContentDigest,
    text: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredInteraction {
    user: Option<ObservationId>,
    assistant: Option<ObservationId>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PreparedCapture {
    request_digest: [u8; 32],
    idempotency_digest: [u8; 32],
    session_id: SessionId,
    interaction_id: ChatInteractionId,
    speaker: ChatSpeaker,
    observation: ObservationUnit,
    evidence_id: EvidenceId,
    content_block_id: ContentBlockId,
    content_digest: ContentDigest,
    ordinal: u64,
    text: String,
    situation: SituationPatch,
    structured_candidates: Vec<StructuredTurnCandidate>,
    semantic_job_id: SemanticJobId,
    finalized: Option<ChatCaptureReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredSemanticStatus {
    Pending,
    Extracted,
    Published { commit_seq: CommitSeq },
    NoOp,
    ShadowEvaluated,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredSemanticJob {
    pub id: SemanticJobId,
    pub session_id: SessionId,
    pub workspace_id: contextdb_core::WorkspaceId,
    pub interaction_id: ChatInteractionId,
    pub speaker: ChatSpeaker,
    pub observation_id: ObservationId,
    pub evidence_id: EvidenceId,
    pub content_block_id: ContentBlockId,
    pub quote_hash: ContentDigest,
    pub actor: contextdb_core::ActorId,
    pub subject: contextdb_core::MemorySubjectId,
    pub envelope: SemanticEnvelope,
    pub observed_at: TimestampMicros,
    pub text: String,
    pub structured: Vec<StructuredTurnCandidate>,
    pub processing_run: Option<String>,
    pub proposals: Option<contextdb_cognition::ProposalBatch>,
    pub output_digest: Option<ContentDigest>,
    pub status: StoredSemanticStatus,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredCheckpointKey {
    request_digest: [u8; 32],
    checkpoint_id: CheckpointId,
}

/// Cross-check report for durable chat records and their journal references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatVerifyReport {
    /// Journal head seen by verification.
    pub journal_head: CommitSeq,
    /// Sessions decoded.
    pub sessions: u64,
    /// Turns decoded.
    pub turns: u64,
    /// Semantic jobs decoded.
    pub semantic_jobs: u64,
    /// Pending sagas which recovery can finish idempotently.
    pub pending_captures: u64,
}

/// Backend-generic durable conversation store.
///
/// Capture uses a recoverable three-step saga: content and an exact prepared
/// frame are synchronized first, the immutable journal observation is accepted
/// second, and session/job indexes are synchronized last. No receipt is
/// returned until all three steps complete. A retry or reopen resumes the same
/// prepared bytes and journal idempotency key.
pub struct ChatStore<E: StorageEngine> {
    journal: JournalCoordinator<E>,
    keyspaces: Keyspaces,
    lifecycle_lock: Mutex<()>,
    config: ChatMiddlewareConfig,
}

impl<E: StorageEngine> fmt::Debug for ChatStore<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatStore")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<E: StorageEngine> ChatStore<E> {
    /// Opens durable chat state and resumes any interrupted capture sagas.
    pub fn new(engine: E, config: ChatMiddlewareConfig) -> Result<Self> {
        config.validate()?;
        let store = Self {
            journal: JournalCoordinator::new(engine)?,
            keyspaces: Keyspaces::new()?,
            lifecycle_lock: Mutex::new(()),
            config,
        };
        store.recover_pending()?;
        Ok(store)
    }

    /// Returns immutable middleware configuration.
    #[must_use]
    pub const fn config(&self) -> ChatMiddlewareConfig {
        self.config
    }

    /// Returns the journal coordinator for read-only verification/projection.
    #[must_use]
    pub const fn journal(&self) -> &JournalCoordinator<E> {
        &self.journal
    }

    pub(crate) fn engine(&self) -> &E {
        self.journal.engine()
    }

    /// Consumes the store and returns the physical engine.
    #[must_use]
    pub fn into_engine(self) -> E {
        self.journal.into_engine()
    }

    /// Registers a durable session. Exact repeats are idempotent.
    pub fn register_session(&self, registration: ChatSessionRegistration) -> Result<()> {
        registration.validate()?;
        let _guard = self.lock()?;
        let key = session_key(registration.session.id);
        let mut transaction = self.engine().begin_write()?;
        if let Some(bytes) = transaction.get(&self.keyspaces.sessions, &key)? {
            let existing: StoredSession = decode(KIND_SESSION, &bytes)?;
            if existing.registration == registration {
                transaction.rollback()?;
                return Ok(());
            }
            return Err(ChatError::InvalidInput("duplicate_session"));
        }
        let stored = StoredSession {
            situation: registration.initial_frame.clone(),
            registration,
            next_ordinal: 0,
            recent_turns: Vec::new(),
            latest_checkpoint: None,
        };
        put_record(
            &mut transaction,
            &self.keyspaces.sessions,
            key,
            KIND_SESSION,
            &stored,
        )?;
        transaction.commit(self.config.durability)?;
        Ok(())
    }

    /// Reads a session only after checking its memory-space and scope grant.
    pub fn session_snapshot(
        &self,
        principal: &ConversationPrincipal,
        session_id: SessionId,
    ) -> Result<ChatSessionSnapshot> {
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        let stored = self.load_session(&snapshot, session_id)?;
        self.authorize_session(principal, &stored, None)?;
        Ok(ChatSessionSnapshot {
            registration: stored.registration,
            situation: stored.situation,
            next_ordinal: stored.next_ordinal,
            recent_turns: stored.recent_turns,
            latest_checkpoint: stored.latest_checkpoint,
        })
    }

    /// Bootstraps a new runtime process from durable working state. The latest
    /// checkpoint ID and recent observation window are included; semantic truth
    /// remains queryable only through the recall boundary.
    pub fn bootstrap_session(
        &self,
        principal: &ConversationPrincipal,
        session_id: SessionId,
    ) -> Result<ChatSessionSnapshot> {
        self.session_snapshot(principal, session_id)
    }

    /// Synchronizes user content, immutable observation, frame state, and an
    /// asynchronous semantic-extraction job before returning.
    pub fn capture_user(&self, request: &BeforeTurnRequest) -> Result<ChatCaptureReceipt> {
        request.validate()?;
        self.capture(
            request.session_id,
            &request.principal,
            request.interaction_id.clone(),
            &request.idempotency_key,
            &request.message,
            request.occurred_at,
            request.situation.clone(),
            request.structured_candidates.clone(),
            ChatSpeaker::User,
        )
    }

    /// Synchronizes assistant speech as distinct agent evidence. It is never
    /// promoted as user/world truth by this operation.
    pub fn capture_assistant(&self, request: &AfterTurnRequest) -> Result<ChatCaptureReceipt> {
        request.validate()?;
        self.capture(
            request.session_id,
            &request.principal,
            request.interaction_id.clone(),
            &request.idempotency_key,
            &request.response,
            request.occurred_at,
            request.situation.clone(),
            request.structured_candidates.clone(),
            ChatSpeaker::Assistant,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "capture receives the typed before/after turn projection explicitly"
    )]
    fn capture(
        &self,
        session_id: SessionId,
        principal: &ConversationPrincipal,
        interaction_id: ChatInteractionId,
        idempotency: &ChatIdempotencyKey,
        text: &crate::ChatText,
        occurred_at: TimestampMicros,
        situation: SituationPatch,
        structured_candidates: Vec<StructuredTurnCandidate>,
        speaker: ChatSpeaker,
    ) -> Result<ChatCaptureReceipt> {
        let _guard = self.lock()?;
        let request_digest = capture_digest(
            session_id,
            &interaction_id,
            idempotency.digest(),
            text.digest(),
            occurred_at,
            &situation,
            &structured_candidates,
            speaker,
        )?;
        let capture_key = idempotency.digest().to_vec();
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        if let Some(bytes) = snapshot.get(&self.keyspaces.captures, &capture_key)? {
            let prepared: PreparedCapture = decode(KIND_CAPTURE, &bytes)?;
            if prepared.request_digest != request_digest {
                return Err(ChatError::IdempotencyConflict);
            }
            return self.resume_capture(prepared, true);
        }

        let mut transaction = self.engine().begin_write()?;
        let mut session = self.load_session(&transaction, session_id)?;
        self.authorize_session(principal, &session, Some(speaker))?;
        validate_patch_scopes(principal, &session.registration, &situation)?;
        let interaction_key = interaction_key(session_id, &interaction_id);
        let interaction = match transaction.get(&self.keyspaces.interactions, &interaction_key)? {
            Some(bytes) => decode::<StoredInteraction>(KIND_INTERACTION, &bytes)?,
            None => StoredInteraction::default(),
        };
        match speaker {
            ChatSpeaker::User if interaction.user.is_some() => {
                return Err(ChatError::InvalidInput("interaction_user_already_captured"));
            }
            ChatSpeaker::Assistant
                if interaction.user.is_none() || interaction.assistant.is_some() =>
            {
                return Err(ChatError::InvalidInput("interaction_assistant_order"));
            }
            _ => {}
        }

        let ordinal = session.next_ordinal;
        session.next_ordinal = ordinal
            .checked_add(1)
            .ok_or(ChatError::ArithmeticOverflow)?;
        let observation_id = ObservationId::new();
        let evidence_id = EvidenceId::new();
        let content_block_id = ContentBlockId::new();
        let content_digest = raw_digest(text.as_str().as_bytes());
        let envelope = evidence_envelope(speaker, &session.registration, observation_id);
        let observation = ObservationUnit::try_new(ObservationUnit {
            id: observation_id,
            workspace_id: session.registration.workspace_id(),
            memory_spaces: NonEmptyVec::new(session.registration.session.memory_space),
            source_id: session.registration.source_id,
            stream_position: Some(StreamPosition {
                stream_id: session.registration.stream_id,
                ordinal,
                native_revision: None,
                wall_time: Some(occurred_at),
            }),
            participants: NonEmptyVec::new(speaker.actor(&session.registration)),
            occurred_at: TimeRange::open_ended(occurred_at),
            observed_at: occurred_at,
            recorded_at: occurred_at,
            artifact_refs: Vec::new(),
            content_block_refs: vec![content_block_id],
            content_hash: content_digest,
            envelope,
        })?;
        let semantic_job_id = SemanticJobId::new(format!("semantic:{observation_id}"))?;
        let prepared = PreparedCapture {
            request_digest,
            idempotency_digest: idempotency.digest(),
            session_id,
            interaction_id,
            speaker,
            observation,
            evidence_id,
            content_block_id,
            content_digest,
            ordinal,
            text: text.as_str().to_owned(),
            situation,
            structured_candidates,
            semantic_job_id,
            finalized: None,
        };
        let content = StoredContent {
            session_id,
            content_block_id,
            content_digest,
            text: text.as_str().to_owned(),
        };
        put_record(
            &mut transaction,
            &self.keyspaces.sessions,
            session_key(session_id),
            KIND_SESSION,
            &session,
        )?;
        put_record(
            &mut transaction,
            &self.keyspaces.contents,
            content_key(content_block_id),
            KIND_CONTENT,
            &content,
        )?;
        put_record(
            &mut transaction,
            &self.keyspaces.captures,
            capture_key,
            KIND_CAPTURE,
            &prepared,
        )?;
        transaction.commit(self.config.durability)?;
        self.resume_capture(prepared, false)
    }

    fn resume_capture(
        &self,
        prepared: PreparedCapture,
        replay_request: bool,
    ) -> Result<ChatCaptureReceipt> {
        if let Some(mut receipt) = prepared.finalized.clone() {
            receipt.replayed = true;
            return Ok(receipt);
        }
        let validated = ValidatedObservationBytes::from_observation(&prepared.observation)?;
        let journal_key = journal_key_for_digest(prepared.idempotency_digest, "observation")?;
        let journal_receipt = self.journal.accept_observation(
            &journal_key,
            &validated,
            CommitOptions {
                durability: self.config.durability,
                fail_at: None,
            },
        )?;
        let mut receipt = ChatCaptureReceipt {
            observation_id: prepared.observation.id,
            evidence_id: prepared.evidence_id,
            content_block_id: prepared.content_block_id,
            commit_seq: journal_receipt.commit_seq,
            durability: journal_receipt.durability,
            replayed: replay_request || journal_receipt.replayed,
            ordinal: prepared.ordinal,
            semantic_job_id: prepared.semantic_job_id.clone(),
        };
        self.finalize_capture(prepared, &receipt)?;
        if replay_request {
            receipt.replayed = true;
        }
        Ok(receipt)
    }

    fn finalize_capture(
        &self,
        mut prepared: PreparedCapture,
        receipt: &ChatCaptureReceipt,
    ) -> Result<()> {
        let mut transaction = self.engine().begin_write()?;
        let key = prepared.idempotency_digest.to_vec();
        if let Some(bytes) = transaction.get(&self.keyspaces.captures, &key)? {
            let existing: PreparedCapture = decode(KIND_CAPTURE, &bytes)?;
            if existing.request_digest != prepared.request_digest {
                return Err(ChatError::IdempotencyConflict);
            }
            if existing.finalized.is_some() {
                transaction.rollback()?;
                return Ok(());
            }
        } else {
            return Err(ChatError::Corrupt(
                "prepared capture disappeared".to_owned(),
            ));
        }
        let mut session = self.load_session(&transaction, prepared.session_id)?;
        let interaction_key = interaction_key(prepared.session_id, &prepared.interaction_id);
        let mut interaction =
            match transaction.get(&self.keyspaces.interactions, &interaction_key)? {
                Some(bytes) => decode::<StoredInteraction>(KIND_INTERACTION, &bytes)?,
                None => StoredInteraction::default(),
            };
        let slot = match prepared.speaker {
            ChatSpeaker::User => &mut interaction.user,
            ChatSpeaker::Assistant => &mut interaction.assistant,
        };
        if slot.is_some_and(|id| id != prepared.observation.id) {
            return Err(ChatError::Corrupt("interaction slot collision".to_owned()));
        }
        *slot = Some(prepared.observation.id);
        let summary = ChatTurnSummary {
            session_id: prepared.session_id,
            interaction_id: prepared.interaction_id.clone(),
            speaker: prepared.speaker,
            observation_id: prepared.observation.id,
            evidence_id: prepared.evidence_id,
            content_digest: prepared.content_digest,
            ordinal: prepared.ordinal,
            commit_seq: receipt.commit_seq,
        };
        apply_situation(
            &mut session.situation,
            &prepared.situation,
            prepared.observation.id,
            prepared.observation.observed_at,
            self.config,
        )?;
        session.recent_turns.push(summary.clone());
        session
            .recent_turns
            .sort_by_key(|turn| (turn.ordinal, turn.observation_id));
        if session.recent_turns.len() > self.config.max_recent_turns {
            let excess = session.recent_turns.len() - self.config.max_recent_turns;
            session.recent_turns.drain(..excess);
        }
        let job = StoredSemanticJob {
            id: prepared.semantic_job_id.clone(),
            session_id: prepared.session_id,
            workspace_id: session.registration.workspace_id(),
            interaction_id: prepared.interaction_id.clone(),
            speaker: prepared.speaker,
            observation_id: prepared.observation.id,
            evidence_id: prepared.evidence_id,
            content_block_id: prepared.content_block_id,
            quote_hash: prepared.content_digest,
            actor: prepared.speaker.actor(&session.registration),
            subject: prepared.speaker.subject(&session.registration),
            envelope: prepared.observation.envelope.clone(),
            observed_at: prepared.observation.observed_at,
            text: prepared.text.clone(),
            structured: prepared.structured_candidates.clone(),
            processing_run: None,
            proposals: None,
            output_digest: None,
            status: StoredSemanticStatus::Pending,
        };
        let mut stored_receipt = receipt.clone();
        stored_receipt.replayed = false;
        prepared.finalized = Some(stored_receipt);
        put_record(
            &mut transaction,
            &self.keyspaces.sessions,
            session_key(prepared.session_id),
            KIND_SESSION,
            &session,
        )?;
        put_record(
            &mut transaction,
            &self.keyspaces.interactions,
            interaction_key,
            KIND_INTERACTION,
            &interaction,
        )?;
        put_record(
            &mut transaction,
            &self.keyspaces.turns,
            turn_key(prepared.session_id, prepared.ordinal),
            KIND_TURN,
            &summary,
        )?;
        put_record(
            &mut transaction,
            &self.keyspaces.jobs,
            job_key(&prepared.semantic_job_id),
            KIND_JOB,
            &job,
        )?;
        put_record(
            &mut transaction,
            &self.keyspaces.captures,
            key,
            KIND_CAPTURE,
            &prepared,
        )?;
        transaction.commit(self.config.durability)?;
        Ok(())
    }

    /// Loads protected turn content for an authorized session principal.
    pub fn turn_content(
        &self,
        principal: &ConversationPrincipal,
        session_id: SessionId,
        content_block_id: ContentBlockId,
    ) -> Result<crate::ChatText> {
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        let session = self.load_session(&snapshot, session_id)?;
        self.authorize_session(principal, &session, None)?;
        let bytes = snapshot
            .get(&self.keyspaces.contents, &content_key(content_block_id))?
            .ok_or(ChatError::NotFound("content"))?;
        let content: StoredContent = decode(KIND_CONTENT, &bytes)?;
        if content.session_id != session_id {
            return Err(ChatError::Unauthorized);
        }
        if content.content_block_id != content_block_id
            || raw_digest(content.text.as_bytes()) != content.content_digest
        {
            return Err(ChatError::Corrupt("content digest mismatch".to_owned()));
        }
        crate::ChatText::new(content.text)
    }

    /// Creates a durable session checkpoint bound to the current journal head.
    pub fn checkpoint(&self, request: &CheckpointRequest) -> Result<CheckpointReceipt> {
        let _guard = self.lock()?;
        let request_digest = hash_json(
            b"contextdb-chat-checkpoint-v1\0",
            &(
                request.session_id,
                &request.task_state,
                &request.required_memory_refs,
            ),
        )?;
        let key = request.idempotency_key.digest().to_vec();
        let head = self
            .journal
            .snapshot(JournalSnapshotSelector::Latest)?
            .commit_seq;
        let mut transaction = self.engine().begin_write()?;
        let session = self.load_session(&transaction, request.session_id)?;
        self.authorize_session(&request.principal, &session, None)?;
        if let Some(bytes) = transaction.get(&self.keyspaces.checkpoint_keys, &key)? {
            let existing: StoredCheckpointKey = decode(KIND_CHECKPOINT_KEY, &bytes)?;
            if existing.request_digest != request_digest {
                return Err(ChatError::IdempotencyConflict);
            }
            transaction.rollback()?;
            let checkpoint = self.load_checkpoint_record(existing.checkpoint_id)?;
            return Ok(CheckpointReceipt {
                checkpoint_id: checkpoint.id,
                created_seq: checkpoint.created_seq,
                replayed: true,
            });
        }
        let mut session = session;
        let checkpoint = Checkpoint {
            id: CheckpointId::new(),
            session_id: request.session_id,
            frame_snapshot: session.situation.clone(),
            task_state: request.task_state.clone(),
            required_memory_refs: request.required_memory_refs.clone(),
            created_seq: head,
        };
        checkpoint.validate()?;
        session.latest_checkpoint = Some(checkpoint.id);
        put_record(
            &mut transaction,
            &self.keyspaces.checkpoints,
            checkpoint_key(checkpoint.id),
            KIND_CHECKPOINT,
            &checkpoint,
        )?;
        put_record(
            &mut transaction,
            &self.keyspaces.checkpoint_keys,
            key,
            KIND_CHECKPOINT_KEY,
            &StoredCheckpointKey {
                request_digest,
                checkpoint_id: checkpoint.id,
            },
        )?;
        put_record(
            &mut transaction,
            &self.keyspaces.sessions,
            session_key(request.session_id),
            KIND_SESSION,
            &session,
        )?;
        transaction.commit(self.config.durability)?;
        Ok(CheckpointReceipt {
            checkpoint_id: checkpoint.id,
            created_seq: checkpoint.created_seq,
            replayed: false,
        })
    }

    /// Loads a validated durable checkpoint.
    pub fn load_checkpoint(
        &self,
        principal: &ConversationPrincipal,
        checkpoint_id: CheckpointId,
    ) -> Result<Checkpoint> {
        let checkpoint = self.load_checkpoint_record(checkpoint_id)?;
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        let session = self.load_session(&snapshot, checkpoint.session_id)?;
        self.authorize_session(principal, &session, None)?;
        Ok(checkpoint)
    }

    fn load_checkpoint_record(&self, checkpoint_id: CheckpointId) -> Result<Checkpoint> {
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        let bytes = snapshot
            .get(&self.keyspaces.checkpoints, &checkpoint_key(checkpoint_id))?
            .ok_or(ChatError::NotFound("checkpoint"))?;
        let checkpoint: Checkpoint = decode(KIND_CHECKPOINT, &bytes)?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    /// Restores working state from a checkpoint without changing semantic truth.
    pub fn resume_checkpoint(
        &self,
        principal: &ConversationPrincipal,
        checkpoint_id: CheckpointId,
        resumed_at: TimestampMicros,
    ) -> Result<ChatSessionSnapshot> {
        let _guard = self.lock()?;
        let checkpoint = self.load_checkpoint_record(checkpoint_id)?;
        let mut transaction = self.engine().begin_write()?;
        let mut session = self.load_session(&transaction, checkpoint.session_id)?;
        self.authorize_session(principal, &session, None)?;
        session.situation = checkpoint.frame_snapshot;
        session.situation.captured_at = resumed_at;
        session.situation.expires_at = add_micros(resumed_at, self.config.situation_ttl_micros)?;
        session.situation.validate()?;
        put_record(
            &mut transaction,
            &self.keyspaces.sessions,
            session_key(checkpoint.session_id),
            KIND_SESSION,
            &session,
        )?;
        transaction.commit(self.config.durability)?;
        Ok(ChatSessionSnapshot {
            registration: session.registration,
            situation: session.situation,
            next_ordinal: session.next_ordinal,
            recent_turns: session.recent_turns,
            latest_checkpoint: session.latest_checkpoint,
        })
    }

    /// Durably queues a typed user control. Operations which delete, correct,
    /// privatize, or broaden sharing require a separate confirmation call.
    pub fn enqueue_control(&self, request: &EnqueueControlRequest) -> Result<ControlJobSummary> {
        let _guard = self.lock()?;
        let request_digest = hash_json(
            b"contextdb-chat-control-v1\0",
            &(request.session_id, &request.directive, request.requested_at),
        )?;
        let key = request.idempotency_key.digest().to_vec();
        let mut transaction = self.engine().begin_write()?;
        if let Some(bytes) = transaction.get(&self.keyspaces.controls, &key)? {
            let existing: StoredControlJob = decode(KIND_CONTROL, &bytes)?;
            if existing.request_digest != request_digest {
                return Err(ChatError::IdempotencyConflict);
            }
            transaction.rollback()?;
            return Ok(control_summary(&existing, true));
        }
        let session = self.load_session(&transaction, request.session_id)?;
        self.authorize_session(&request.principal, &session, Some(ChatSpeaker::User))?;
        let job = StoredControlJob {
            id: ControlJobId::new(format!(
                "control:{}",
                digest_hex(request.idempotency_key.digest())
            ))?,
            session_id: request.session_id,
            request_digest,
            directive: request.directive.clone(),
            requested_at: request.requested_at,
            status: if requires_confirmation(&request.directive) {
                ControlJobStatus::AwaitingConfirmation
            } else {
                ControlJobStatus::PendingExecution
            },
            executor_receipt_digest: None,
        };
        put_record(
            &mut transaction,
            &self.keyspaces.controls,
            key,
            KIND_CONTROL,
            &job,
        )?;
        transaction.commit(self.config.durability)?;
        Ok(control_summary(&job, false))
    }

    /// Explicitly confirms a queued destructive or sharing operation.
    pub fn confirm_control(
        &self,
        principal: &ConversationPrincipal,
        idempotency_key: &ChatIdempotencyKey,
    ) -> Result<ControlJobSummary> {
        let _guard = self.lock()?;
        let key = idempotency_key.digest().to_vec();
        let mut transaction = self.engine().begin_write()?;
        let bytes = transaction
            .get(&self.keyspaces.controls, &key)?
            .ok_or(ChatError::NotFound("control_job"))?;
        let mut job: StoredControlJob = decode(KIND_CONTROL, &bytes)?;
        let session = self.load_session(&transaction, job.session_id)?;
        self.authorize_session(principal, &session, Some(ChatSpeaker::User))?;
        match job.status {
            ControlJobStatus::AwaitingConfirmation => {
                job.status = ControlJobStatus::PendingExecution;
                put_record(
                    &mut transaction,
                    &self.keyspaces.controls,
                    key,
                    KIND_CONTROL,
                    &job,
                )?;
                transaction.commit(self.config.durability)?;
                Ok(control_summary(&job, false))
            }
            ControlJobStatus::PendingExecution
            | ControlJobStatus::Applied
            | ControlJobStatus::Rejected => {
                transaction.rollback()?;
                Ok(control_summary(&job, true))
            }
        }
    }

    /// Records a host executor result. The chat crate never claims a control
    /// was applied merely because it was requested or confirmed.
    pub fn finish_control(
        &self,
        principal: &ConversationPrincipal,
        idempotency_key: &ChatIdempotencyKey,
        applied: bool,
        executor_receipt_digest: ContentDigest,
    ) -> Result<ControlJobSummary> {
        let _guard = self.lock()?;
        let key = idempotency_key.digest().to_vec();
        let mut transaction = self.engine().begin_write()?;
        let bytes = transaction
            .get(&self.keyspaces.controls, &key)?
            .ok_or(ChatError::NotFound("control_job"))?;
        let mut job: StoredControlJob = decode(KIND_CONTROL, &bytes)?;
        let session = self.load_session(&transaction, job.session_id)?;
        self.authorize_session(principal, &session, Some(ChatSpeaker::User))?;
        match job.status {
            ControlJobStatus::AwaitingConfirmation => {
                Err(ChatError::InvalidInput("control_confirmation_required"))
            }
            ControlJobStatus::PendingExecution => {
                job.status = if applied {
                    ControlJobStatus::Applied
                } else {
                    ControlJobStatus::Rejected
                };
                job.executor_receipt_digest = Some(executor_receipt_digest);
                put_record(
                    &mut transaction,
                    &self.keyspaces.controls,
                    key,
                    KIND_CONTROL,
                    &job,
                )?;
                transaction.commit(self.config.durability)?;
                Ok(control_summary(&job, false))
            }
            ControlJobStatus::Applied | ControlJobStatus::Rejected => {
                if job.executor_receipt_digest != Some(executor_receipt_digest)
                    || (job.status == ControlJobStatus::Applied) != applied
                {
                    return Err(ChatError::IdempotencyConflict);
                }
                transaction.rollback()?;
                Ok(control_summary(&job, true))
            }
        }
    }

    /// Deeply checks record envelopes, digests, and chat-to-journal references.
    pub fn verify(&self) -> Result<ChatVerifyReport> {
        let journal = self.journal.verify(VerifyMode::Deep)?;
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        let observation_sequences: BTreeMap<_, _> = self
            .journal
            .snapshot(JournalSnapshotSelector::Latest)?
            .events
            .into_iter()
            .filter_map(|event| match event {
                contextdb_journal::JournalEvent::ObservationAccepted {
                    commit_seq,
                    observation_id,
                    ..
                } => Some((observation_id, commit_seq)),
                _ => None,
            })
            .collect();
        let sessions = snapshot.scan_prefix(&self.keyspaces.sessions, b"")?;
        for entry in &sessions {
            let session: StoredSession = decode(KIND_SESSION, &entry.value)?;
            session.registration.validate()?;
            session.situation.validate()?;
        }
        let turns = snapshot.scan_prefix(&self.keyspaces.turns, b"")?;
        for entry in &turns {
            let turn: ChatTurnSummary = decode(KIND_TURN, &entry.value)?;
            if observation_sequences.get(&turn.observation_id) != Some(&turn.commit_seq) {
                return Err(ChatError::Corrupt(
                    "turn points outside the accepted journal prefix".to_owned(),
                ));
            }
        }
        let jobs = snapshot.scan_prefix(&self.keyspaces.jobs, b"")?;
        for entry in &jobs {
            let job: StoredSemanticJob = decode(KIND_JOB, &entry.value)?;
            if !observation_sequences.contains_key(&job.observation_id) {
                return Err(ChatError::Corrupt(
                    "semantic job lacks accepted observation".to_owned(),
                ));
            }
            let content_bytes = snapshot
                .get(&self.keyspaces.contents, &content_key(job.content_block_id))?
                .ok_or_else(|| ChatError::Corrupt("semantic job content absent".to_owned()))?;
            let content: StoredContent = decode(KIND_CONTENT, &content_bytes)?;
            if content.session_id != job.session_id
                || content.content_digest != job.quote_hash
                || raw_digest(content.text.as_bytes()) != job.quote_hash
            {
                return Err(ChatError::Corrupt(
                    "semantic job content mismatch".to_owned(),
                ));
            }
        }
        let captures = snapshot.scan_prefix(&self.keyspaces.captures, b"")?;
        let pending_captures = captures
            .iter()
            .map(|entry| decode::<PreparedCapture>(KIND_CAPTURE, &entry.value))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .filter(|capture| capture.finalized.is_none())
            .count();
        Ok(ChatVerifyReport {
            journal_head: journal.commit_seq,
            sessions: u64::try_from(sessions.len()).map_err(|_| ChatError::ArithmeticOverflow)?,
            turns: u64::try_from(turns.len()).map_err(|_| ChatError::ArithmeticOverflow)?,
            semantic_jobs: u64::try_from(jobs.len()).map_err(|_| ChatError::ArithmeticOverflow)?,
            pending_captures: u64::try_from(pending_captures)
                .map_err(|_| ChatError::ArithmeticOverflow)?,
        })
    }

    pub(crate) fn load_semantic_job(&self, id: &SemanticJobId) -> Result<StoredSemanticJob> {
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        let bytes = snapshot
            .get(&self.keyspaces.jobs, &job_key(id))?
            .ok_or(ChatError::NotFound("semantic_job"))?;
        decode(KIND_JOB, &bytes)
    }

    pub(crate) fn store_semantic_job(&self, job: &StoredSemanticJob) -> Result<()> {
        let mut transaction = self.engine().begin_write()?;
        put_record(
            &mut transaction,
            &self.keyspaces.jobs,
            job_key(&job.id),
            KIND_JOB,
            job,
        )?;
        transaction.commit(self.config.durability)?;
        Ok(())
    }

    pub(crate) fn semantic_job_entries(&self) -> Result<Vec<StoredSemanticJob>> {
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        snapshot
            .scan_prefix(&self.keyspaces.jobs, b"")?
            .into_iter()
            .map(|entry| decode(KIND_JOB, &entry.value))
            .collect()
    }

    pub(crate) fn authorize_job(
        &self,
        principal: &ConversationPrincipal,
        job: &StoredSemanticJob,
    ) -> Result<()> {
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        let session = self.load_session(&snapshot, job.session_id)?;
        self.authorize_session(principal, &session, None)
    }

    pub(crate) fn evidence_catalog(job: &StoredSemanticJob) -> EvidenceCatalog {
        let span = EvidenceSpan {
            id: job.evidence_id,
            observation_id: job.observation_id,
            artifact_id: None,
            content_block_id: job.content_block_id,
            selector: EvidenceSelector::Whole,
            quote_hash: job.quote_hash,
            extracted_text: None,
            trust: TrustClass::SelfAsserted,
            derivation: None,
        };
        EvidenceCatalog(BTreeMap::from([(
            job.evidence_id,
            EvidenceRecord {
                span,
                envelope: job.envelope.clone(),
                source_family: "conversation".to_owned(),
                observed_at: job.observed_at,
                authority: EvidenceAuthority::ActorAssertion {
                    actor: job.actor,
                    subject: job.subject,
                },
                taints: Default::default(),
                supports: Vec::new(),
            },
        )]))
    }

    pub(crate) fn publish_job_mutation(
        &self,
        job: &StoredSemanticJob,
        mutation: &contextdb_core::SemanticMutationSet,
    ) -> Result<contextdb_journal::PublicationReceipt> {
        let validated = ValidatedMutationBytes::from_mutation(mutation)?;
        let key_digest = raw_digest(job.id.as_str().as_bytes());
        let key = journal_key_for_digest(*key_digest.as_bytes(), "semantic")?;
        Ok(self.journal.publish_semantic(
            &key,
            &validated,
            CommitOptions {
                durability: self.config.durability,
                fail_at: None,
            },
        )?)
    }

    fn recover_pending(&self) -> Result<()> {
        let snapshot = self.engine().begin_read(SnapshotSelector::Latest)?;
        let captures = snapshot.scan_prefix(&self.keyspaces.captures, b"")?;
        drop(snapshot);
        for entry in captures {
            let prepared: PreparedCapture = decode(KIND_CAPTURE, &entry.value)?;
            if prepared.finalized.is_none() {
                let _ = self.resume_capture(prepared, true)?;
            }
        }
        Ok(())
    }

    fn load_session<S: ReadSnapshot>(&self, snapshot: &S, id: SessionId) -> Result<StoredSession> {
        let bytes = snapshot
            .get(&self.keyspaces.sessions, &session_key(id))?
            .ok_or(ChatError::NotFound("session"))?;
        decode(KIND_SESSION, &bytes)
    }

    fn authorize_session(
        &self,
        principal: &ConversationPrincipal,
        session: &StoredSession,
        speaker: Option<ChatSpeaker>,
    ) -> Result<()> {
        let participant = (principal.actor_id == session.registration.user_actor
            && principal.subject_id == session.registration.user_subject)
            || (principal.actor_id == session.registration.assistant_actor
                && principal.subject_id == session.registration.assistant_subject);
        if !participant
            || !principal.authorizes(&session.registration)
            || !session
                .situation
                .active_scopes
                .iter()
                .all(|scope| principal.allowed_scopes.contains(&scope.scope.id))
        {
            return Err(ChatError::Unauthorized);
        }
        if let Some(speaker) = speaker
            && (principal.actor_id != speaker.actor(&session.registration)
                || principal.subject_id != speaker.subject(&session.registration))
        {
            return Err(ChatError::Unauthorized);
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>> {
        self.lifecycle_lock
            .lock()
            .map_err(|_| ChatError::LockPoisoned)
    }
}

fn digest_hex(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn validate_patch_scopes(
    principal: &ConversationPrincipal,
    registration: &ChatSessionRegistration,
    patch: &SituationPatch,
) -> Result<()> {
    if let Some(scopes) = &patch.active_scopes {
        let user = registration
            .user_envelope
            .scopes
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let assistant = registration
            .assistant_envelope
            .scopes
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if scopes.iter().any(|scope| {
            !principal.allowed_scopes.contains(&scope.scope.id)
                || !user.contains(&scope.scope)
                || !assistant.contains(&scope.scope)
        }) {
            return Err(ChatError::Unauthorized);
        }
    }
    Ok(())
}

fn evidence_envelope(
    speaker: ChatSpeaker,
    registration: &ChatSessionRegistration,
    observation_id: ObservationId,
) -> SemanticEnvelope {
    let mut envelope = match speaker {
        ChatSpeaker::User => registration.user_envelope.clone(),
        ChatSpeaker::Assistant => registration.assistant_envelope.clone(),
    };
    envelope.perspective.narrator = speaker.actor(registration);
    envelope.perspective.knower = speaker.subject(registration);
    envelope.perspective.experiencer = Some(speaker.subject(registration));
    envelope.perspective.role = EpistemicRole::Asserter;
    envelope.derivation = DerivationRef {
        id: DerivationId::new(),
        kind: DerivationKind::ActorAssertion,
        actor: Some(speaker.actor(registration)),
        model_call: None,
        pipeline: PipelineIdentity {
            name: "contextdb-chat-capture".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: crate::FORMAT_VERSION.to_string(),
        },
        inputs: vec![LineageNode::External {
            namespace: "conversation-interaction".to_owned(),
            identifier: observation_id.to_string(),
        }],
    };
    envelope
}

fn apply_situation(
    frame: &mut SituationFrame,
    patch: &SituationPatch,
    observation: ObservationId,
    captured_at: TimestampMicros,
    config: ChatMiddlewareConfig,
) -> Result<()> {
    if let Some(value) = &patch.conversation_mode {
        frame.conversation_mode = value.clone();
    }
    if let Some(value) = &patch.active_topics {
        frame.active_topics.clone_from(value);
    }
    if let Some(value) = &patch.active_referents {
        frame.active_referents.clone_from(value);
    }
    if let Some(value) = &patch.goal_stack {
        frame.goal_stack.clone_from(value);
    }
    if let Some(value) = &patch.active_scopes {
        frame.active_scopes.clone_from(value);
    }
    if let Some(value) = &patch.open_questions {
        frame.open_questions.clone_from(value);
    }
    if let Some(value) = &patch.open_loops {
        frame.open_loops.clone_from(value);
    }
    if let Some(value) = &patch.working_hypotheses {
        frame.working_hypotheses.clone_from(value);
    }
    if let Some(value) = &patch.environment {
        frame.environment = Some(value.clone());
    }
    frame.recent_observations.push(observation);
    if frame.recent_observations.len() > config.max_recent_turns {
        let excess = frame.recent_observations.len() - config.max_recent_turns;
        frame.recent_observations.drain(..excess);
    }
    frame.captured_at = captured_at;
    frame.expires_at = add_micros(captured_at, config.situation_ttl_micros)?;
    frame.validate()?;
    Ok(())
}

fn add_micros(timestamp: TimestampMicros, delta: u64) -> Result<TimestampMicros> {
    let delta = i64::try_from(delta).map_err(|_| ChatError::ArithmeticOverflow)?;
    Ok(TimestampMicros(
        timestamp
            .0
            .checked_add(delta)
            .ok_or(ChatError::ArithmeticOverflow)?,
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "every logical capture field is bound into the idempotency digest"
)]
fn capture_digest(
    session_id: SessionId,
    interaction_id: &ChatInteractionId,
    idempotency_digest: [u8; 32],
    text_digest: ContentDigest,
    occurred_at: TimestampMicros,
    patch: &SituationPatch,
    structured: &[StructuredTurnCandidate],
    speaker: ChatSpeaker,
) -> Result<[u8; 32]> {
    hash_json(
        b"contextdb-chat-capture-request-v1\0",
        &(
            session_id,
            interaction_id,
            idempotency_digest,
            text_digest,
            occurred_at,
            patch,
            structured,
            speaker,
        ),
    )
}

fn raw_digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn hash_json<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn encode<T: Serialize>(kind: u16, sequence: u64, value: &T) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(value)?;
    Ok(RecordEnvelope::encode(
        kind,
        SCHEMA_VERSION,
        0,
        sequence,
        &payload,
    )?)
}

fn decode<T: DeserializeOwned>(kind: u16, bytes: &[u8]) -> Result<T> {
    let record = RecordEnvelope::decode(bytes)?;
    if record.envelope.record_kind != kind || record.envelope.schema_version != SCHEMA_VERSION {
        return Err(ChatError::Corrupt("unexpected chat record type".to_owned()));
    }
    Ok(serde_json::from_slice(record.payload)?)
}

fn put_record<T: Serialize, W: WriteTransaction>(
    transaction: &mut W,
    keyspace: &Keyspace,
    key: Vec<u8>,
    kind: u16,
    value: &T,
) -> Result<()> {
    let sequence = transaction
        .sequence()
        .checked_add(1)
        .ok_or(ChatError::ArithmeticOverflow)?;
    transaction.put(keyspace, key, encode(kind, sequence, value)?)?;
    Ok(())
}

fn session_key(id: SessionId) -> Vec<u8> {
    id.to_string().into_bytes()
}

fn content_key(id: ContentBlockId) -> Vec<u8> {
    id.to_string().into_bytes()
}

fn checkpoint_key(id: CheckpointId) -> Vec<u8> {
    id.to_string().into_bytes()
}

fn job_key(id: &SemanticJobId) -> Vec<u8> {
    id.as_str().as_bytes().to_vec()
}

fn interaction_key(session: SessionId, interaction: &ChatInteractionId) -> Vec<u8> {
    format!("{session}:{}", interaction.as_str()).into_bytes()
}

fn turn_key(session: SessionId, ordinal: u64) -> Vec<u8> {
    format!("{session}:{ordinal:020}").into_bytes()
}
