//! Provider-neutral re-embedding job planning and state transitions.

use std::collections::BTreeSet;

use contextdb_core::{
    CommitSeq, ContentDigest, NonEmptyVec, ScopeRef, TimestampMicros, Validate, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::{
    ContinuityError, EmbeddingSpaceDescriptor, MigrationId, Result, canonical_digest,
    ensure_digest_nonzero, validate_text,
};

/// Immutable specification for rebuilding one representation space.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReembeddingJobSpec {
    /// Stable content-derived job identity.
    pub id: ContentDigest,
    /// Migration that requested the rebuild.
    pub migration_id: MigrationId,
    /// Workspace and snapshot from which source records are read.
    pub workspace_id: WorkspaceId,
    /// Fixed semantic snapshot. Jobs must never mix source commits.
    pub snapshot_commit: CommitSeq,
    /// Explicit scopes eligible for representation rebuild.
    pub scopes: NonEmptyVec<ScopeRef>,
    /// Existing immutable source space.
    pub source: EmbeddingSpaceDescriptor,
    /// New immutable target space.
    pub target: EmbeddingSpaceDescriptor,
}

impl ReembeddingJobSpec {
    /// Creates a deterministic job and derives its ID from the complete contract.
    pub fn new(
        migration_id: MigrationId,
        workspace_id: WorkspaceId,
        snapshot_commit: CommitSeq,
        scopes: NonEmptyVec<ScopeRef>,
        source: EmbeddingSpaceDescriptor,
        target: EmbeddingSpaceDescriptor,
    ) -> Result<Self> {
        let id = canonical_digest(&(
            &migration_id,
            workspace_id,
            snapshot_commit,
            &scopes,
            &source,
            &target,
        ))?;
        let value = Self {
            id,
            migration_id,
            workspace_id,
            snapshot_commit,
            scopes,
            source,
            target,
        };
        value.validate()?;
        Ok(value)
    }

    /// Rejects space reuse, cross-modality rebuilds, and non-canonical scopes.
    pub fn validate(&self) -> Result<()> {
        self.source.validate()?;
        self.target.validate()?;
        ensure_digest_nonzero(self.id, "re-embedding job ID")?;
        if self.source.id == self.target.id {
            return Err(ContinuityError::InvalidInput(
                "re-embedding must use a new vector-space ID".to_owned(),
            ));
        }
        if self.source.modality != self.target.modality {
            return Err(ContinuityError::InvalidInput(
                "re-embedding cannot change modality".to_owned(),
            ));
        }
        if self.source.fingerprint == self.target.fingerprint
            && self.source.dimensions == self.target.dimensions
            && self.source.normalized == self.target.normalized
        {
            return Err(ContinuityError::InvalidInput(
                "compatible vector spaces do not require a rebuild".to_owned(),
            ));
        }
        let mut distinct = BTreeSet::new();
        for scope in &self.scopes {
            scope
                .validate()
                .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
            if !distinct.insert(scope) {
                return Err(ContinuityError::InvalidInput(
                    "re-embedding job repeats a scope".to_owned(),
                ));
            }
        }
        if self.compute_id()? != self.id {
            return Err(ContinuityError::InvalidInput(
                "re-embedding job ID differs from its immutable contract".to_owned(),
            ));
        }
        Ok(())
    }

    fn compute_id(&self) -> Result<ContentDigest> {
        canonical_digest(&(
            &self.migration_id,
            self.workspace_id,
            self.snapshot_commit,
            &self.scopes,
            &self.source,
            &self.target,
        ))
    }
}

/// Durable state of a re-embedding job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ReembeddingJobState {
    /// Awaiting a worker.
    Queued,
    /// One bounded attempt is active.
    Running {
        /// One-based attempt number.
        attempt: u32,
        /// Deterministic host-supplied start timestamp.
        started_at: TimestampMicros,
    },
    /// Target-space publication completed atomically.
    Succeeded {
        /// Attempt that published the target space.
        attempt: u32,
        /// Start of the successful attempt.
        started_at: TimestampMicros,
        /// Number of source records represented.
        indexed_items: u64,
        /// Manifest digest of the published target-space records.
        output_digest: ContentDigest,
        /// Completion timestamp.
        completed_at: TimestampMicros,
    },
    /// Attempt failed without publishing partial target state.
    Failed {
        /// Attempt that failed.
        attempt: u32,
        /// Start of the failed attempt.
        started_at: TimestampMicros,
        /// Whether policy permits another bounded attempt.
        retryable: bool,
        /// Non-secret stable failure category/detail.
        reason: String,
        /// Failure timestamp.
        failed_at: TimestampMicros,
    },
    /// Explicitly cancelled before publication.
    Cancelled {
        /// Cancellation timestamp.
        cancelled_at: TimestampMicros,
        /// Non-secret reason.
        reason: String,
    },
}

/// Pure lifecycle wrapper for one re-embedding specification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReembeddingJob {
    /// Immutable job specification.
    pub spec: ReembeddingJobSpec,
    /// Current state.
    pub state: ReembeddingJobState,
}

impl ReembeddingJob {
    /// Creates a queued job.
    pub fn queued(spec: ReembeddingJobSpec) -> Result<Self> {
        spec.validate()?;
        let value = Self {
            spec,
            state: ReembeddingJobState::Queued,
        };
        value.validate()?;
        Ok(value)
    }

    /// Starts or retries one bounded attempt.
    pub fn start(&mut self, at: TimestampMicros) -> Result<()> {
        self.validate()?;
        let attempt = match &self.state {
            ReembeddingJobState::Queued => 1,
            ReembeddingJobState::Failed {
                attempt,
                retryable: true,
                failed_at,
                ..
            } => {
                if at < *failed_at {
                    return Err(ContinuityError::InvalidTransition(
                        "re-embedding retry started before the prior failure".to_owned(),
                    ));
                }
                attempt.checked_add(1).ok_or_else(|| {
                    ContinuityError::InvalidTransition(
                        "re-embedding attempt counter overflow".to_owned(),
                    )
                })?
            }
            _ => {
                return Err(ContinuityError::InvalidTransition(
                    "only queued or retryable failed jobs may start".to_owned(),
                ));
            }
        };
        self.state = ReembeddingJobState::Running {
            attempt,
            started_at: at,
        };
        self.validate()
    }

    /// Atomically marks a running attempt successful.
    pub fn succeed(
        &mut self,
        indexed_items: u64,
        output_digest: ContentDigest,
        at: TimestampMicros,
    ) -> Result<()> {
        self.validate()?;
        ensure_digest_nonzero(output_digest, "re-embedding output digest")?;
        let (attempt, started_at) = match &self.state {
            ReembeddingJobState::Running {
                attempt,
                started_at,
            } => (*attempt, *started_at),
            _ => {
                return Err(ContinuityError::InvalidTransition(
                    "only a running re-embedding job may succeed".to_owned(),
                ));
            }
        };
        if at < started_at {
            return Err(ContinuityError::InvalidTransition(
                "re-embedding completed before it started".to_owned(),
            ));
        }
        self.state = ReembeddingJobState::Succeeded {
            attempt,
            started_at,
            indexed_items,
            output_digest,
            completed_at: at,
        };
        self.validate()
    }

    /// Records a failed running attempt without exposing partial target state.
    pub fn fail(
        &mut self,
        retryable: bool,
        reason: impl Into<String>,
        at: TimestampMicros,
    ) -> Result<()> {
        self.validate()?;
        let reason = reason.into();
        validate_text(&reason, "re-embedding failure reason", 1024)?;
        let (attempt, started_at) = match &self.state {
            ReembeddingJobState::Running {
                attempt,
                started_at,
            } => (*attempt, *started_at),
            _ => {
                return Err(ContinuityError::InvalidTransition(
                    "only a running re-embedding job may fail".to_owned(),
                ));
            }
        };
        if at < started_at {
            return Err(ContinuityError::InvalidTransition(
                "re-embedding failed before it started".to_owned(),
            ));
        }
        self.state = ReembeddingJobState::Failed {
            attempt,
            started_at,
            retryable,
            reason,
            failed_at: at,
        };
        self.validate()
    }

    /// Cancels a queued or failed job before any target publication.
    pub fn cancel(&mut self, reason: impl Into<String>, at: TimestampMicros) -> Result<()> {
        self.validate()?;
        let reason = reason.into();
        validate_text(&reason, "re-embedding cancellation reason", 1024)?;
        if let ReembeddingJobState::Failed { failed_at, .. } = &self.state
            && at < *failed_at
        {
            return Err(ContinuityError::InvalidTransition(
                "re-embedding cancellation predates the prior failure".to_owned(),
            ));
        }
        if !matches!(
            &self.state,
            ReembeddingJobState::Queued | ReembeddingJobState::Failed { .. }
        ) {
            return Err(ContinuityError::InvalidTransition(
                "running or terminal successful jobs cannot be cancelled".to_owned(),
            ));
        }
        self.state = ReembeddingJobState::Cancelled {
            cancelled_at: at,
            reason,
        };
        self.validate()
    }

    /// Validates the immutable specification and the complete current-state invariants.
    pub fn validate(&self) -> Result<()> {
        self.spec.validate()?;
        match &self.state {
            ReembeddingJobState::Queued => Ok(()),
            ReembeddingJobState::Running { attempt, .. } if *attempt > 0 => Ok(()),
            ReembeddingJobState::Succeeded {
                attempt,
                started_at,
                output_digest,
                completed_at,
                ..
            } if *attempt > 0 && completed_at >= started_at => {
                ensure_digest_nonzero(*output_digest, "re-embedding output digest")
            }
            ReembeddingJobState::Failed {
                attempt,
                started_at,
                reason,
                failed_at,
                ..
            } if *attempt > 0 && failed_at >= started_at => {
                validate_text(reason, "re-embedding failure reason", 1024)
            }
            ReembeddingJobState::Cancelled { reason, .. } => {
                validate_text(reason, "re-embedding cancellation reason", 1024)
            }
            _ => Err(ContinuityError::InvalidInput(
                "re-embedding state has an invalid attempt or timestamp".to_owned(),
            )),
        }
    }

    /// Returns true only after an atomic target-space publication.
    #[must_use]
    pub const fn is_succeeded(&self) -> bool {
        matches!(&self.state, ReembeddingJobState::Succeeded { .. })
    }
}
