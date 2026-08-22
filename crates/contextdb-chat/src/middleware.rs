//! Synchronous before-turn and durable after-turn middleware.

use std::fmt;

use contextdb_context::CompiledContext;
use contextdb_storage::StorageEngine;

use crate::{
    AfterTurnRequest, BeforeTurnRequest, ChatCaptureReceipt, ChatClock, ChatStore,
    ConversationMemoryIntent, ConversationRecall, ConversationRecallPlan, Result,
};

/// Synchronous recall result without leaking retrieved content into metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallDisposition {
    /// Memory use was explicitly disabled or had no deterministic trigger.
    Skipped,
    /// Provider completed successfully with an explicit empty result.
    NoMemory,
    /// A validated canonical ContextPack is available.
    Ready,
    /// Provider returned a sanitized failure; response generation may continue.
    Degraded,
    /// Provider completed after the hard hot-path budget; output was discarded.
    TimedOut,
    /// Provider result violated scope, snapshot, profile, or canonical-byte binding.
    Rejected,
}

/// Complete pre-response hook result. Capture always precedes recall.
pub struct BeforeTurnOutcome {
    /// Durable immutable user observation receipt.
    pub capture: ChatCaptureReceipt,
    /// Recall lifecycle outcome.
    pub recall: RecallDisposition,
    /// Runtime-safe compiled context only when `recall == Ready`.
    pub context: Option<CompiledContext>,
    /// Monotonic elapsed recall time.
    pub recall_elapsed_micros: u64,
}

impl fmt::Debug for BeforeTurnOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BeforeTurnOutcome")
            .field("capture", &self.capture)
            .field("recall", &self.recall)
            .field("has_context", &self.context.is_some())
            .field("recall_elapsed_micros", &self.recall_elapsed_micros)
            .finish()
    }
}

/// Provider-neutral conversational lifecycle orchestrator.
#[derive(Debug)]
pub struct ConversationMiddleware<E, R, C>
where
    E: StorageEngine,
    R: ConversationRecall,
    C: ChatClock,
{
    store: ChatStore<E>,
    recall: R,
    clock: C,
}

impl<E, R, C> ConversationMiddleware<E, R, C>
where
    E: StorageEngine,
    R: ConversationRecall,
    C: ChatClock,
{
    /// Composes a durable store, recall implementation, and monotonic clock.
    #[must_use]
    pub const fn new(store: ChatStore<E>, recall: R, clock: C) -> Self {
        Self {
            store,
            recall,
            clock,
        }
    }

    /// Returns the durable store.
    #[must_use]
    pub const fn store(&self) -> &ChatStore<E> {
        &self.store
    }

    /// Captures user evidence synchronously, then performs bounded recall. A
    /// recall outage or invalid result cannot erase or fail the capture.
    pub fn before_turn(&self, request: &BeforeTurnRequest) -> Result<BeforeTurnOutcome> {
        let capture = self.store.capture_user(request)?;
        let session = self
            .store
            .session_snapshot(&request.principal, request.session_id)?;
        if should_skip(request.memory_intent, &session.situation) {
            return Ok(BeforeTurnOutcome {
                capture,
                recall: RecallDisposition::Skipped,
                context: None,
                recall_elapsed_micros: 0,
            });
        }
        let journal_head = self
            .store
            .journal()
            .snapshot(contextdb_journal::JournalSnapshotSelector::Latest)?
            .commit_seq
            .get();
        let plan = ConversationRecallPlan::from_turn(request, &capture, &session, journal_head)?;
        let start = self.clock.now_micros();
        let recalled = self.recall.recall(&plan);
        let elapsed = self.clock.now_micros().saturating_sub(start);
        if elapsed > request.max_recall_micros {
            return Ok(BeforeTurnOutcome {
                capture,
                recall: RecallDisposition::TimedOut,
                context: None,
                recall_elapsed_micros: elapsed,
            });
        }
        let (recall, context) = match recalled {
            Err(_) => (RecallDisposition::Degraded, None),
            Ok(None) => (RecallDisposition::NoMemory, None),
            Ok(Some(compiled)) => {
                if plan.validate_result(&compiled).is_err()
                    || ConversationRecallPlan::automatic_mentions(&compiled)
                        > self.store.config().max_automatic_mentions
                {
                    (RecallDisposition::Rejected, None)
                } else {
                    (RecallDisposition::Ready, Some(compiled))
                }
            }
        };
        Ok(BeforeTurnOutcome {
            capture,
            recall,
            context,
            recall_elapsed_micros: elapsed,
        })
    }

    /// Captures assistant output and enqueues post-turn cognition. This method
    /// does not wait for extraction or semantic publication.
    pub fn after_turn(&self, request: &AfterTurnRequest) -> Result<ChatCaptureReceipt> {
        self.store.capture_assistant(request)
    }

    /// Consumes middleware and returns its store, useful across runtime restart tests.
    #[must_use]
    pub fn into_store(self) -> ChatStore<E> {
        self.store
    }
}

fn should_skip(intent: ConversationMemoryIntent, frame: &contextdb_core::SituationFrame) -> bool {
    match intent {
        ConversationMemoryIntent::Never => true,
        ConversationMemoryIntent::Automatic => {
            frame.active_referents.is_empty()
                && frame.open_loops.is_empty()
                && frame.goal_stack.is_empty()
                && frame.open_questions.is_empty()
        }
        ConversationMemoryIntent::ExplicitRecall
        | ConversationMemoryIntent::ImplicitContinuity
        | ConversationMemoryIntent::Historical
        | ConversationMemoryIntent::Relational
        | ConversationMemoryIntent::Reflective
        | ConversationMemoryIntent::Bootstrap => false,
    }
}
