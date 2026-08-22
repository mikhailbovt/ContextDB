//! Deterministic migration lifecycle coordinator.

use contextdb_core::{
    AgentId, ContentDigest, MemorySubjectId, ModelProfileId, TimestampMicros, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::{
    BootstrapResult, ContinuityError, MigrationCompatibilityReport, MigrationId,
    PortableCheckpoint, ReembeddingJob, Result, canonical_digest, validate_text,
};

/// Deterministic cross-model migration phase.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    /// Stable identities and target were declared.
    Planned,
    /// A portable checkpoint was sealed.
    CheckpointSealed,
    /// Compatibility report was accepted.
    CompatibilityAnalyzed,
    /// Required representation-space rebuilds are in progress.
    Reembedding,
    /// No blocking findings remain and all rebuilds succeeded.
    ReadyForBootstrap,
    /// Target-specific bootstrap pack was compiled.
    Bootstrapped,
    /// Operational continuity was verified by the host/evaluation layer.
    Completed,
    /// Terminal failure; reason is non-secret.
    Failed,
}

/// Append-only payload-free migration transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationEvent {
    /// One-based event sequence.
    pub sequence: u32,
    /// Phase entered by this event.
    pub phase: MigrationPhase,
    /// Host-supplied timestamp.
    pub at: TimestampMicros,
    /// Digest of the checkpoint/report/pack or failure category driving the transition.
    pub artifact_digest: ContentDigest,
}

/// Pure state machine coordinating checkpoint, compatibility, rebuild, and bootstrap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationLifecycle {
    /// Stable migration identity.
    pub id: MigrationId,
    /// Workspace binding.
    pub workspace_id: WorkspaceId,
    /// Stable agent identity, distinct from models.
    pub agent_id: AgentId,
    /// Stable memory subject that must never change.
    pub stable_subject: MemorySubjectId,
    /// Source model profile.
    pub source_profile: ModelProfileId,
    /// Target model profile.
    pub target_profile: ModelProfileId,
    /// Current phase.
    pub phase: MigrationPhase,
    /// Checkpoint digest, after sealing.
    pub checkpoint_digest: Option<ContentDigest>,
    /// Exact source runtime copied from the checkpoint binding.
    pub source_runtime_digest: Option<ContentDigest>,
    /// Exact continuity profile copied from the checkpoint binding.
    pub continuity_profile_digest: Option<ContentDigest>,
    /// Compatibility report digest, after analysis.
    pub compatibility_digest: Option<ContentDigest>,
    /// Exact target runtime descriptor accepted by compatibility analysis.
    pub target_runtime_digest: Option<ContentDigest>,
    /// Canonical target ContextPack digest, after bootstrap.
    pub bootstrap_pack_digest: Option<String>,
    /// Append-only canonical transition trace.
    pub events: Vec<MigrationEvent>,
    /// Terminal non-secret failure reason.
    pub failure_reason: Option<String>,
}

impl MigrationLifecycle {
    /// Creates a planned lifecycle with no artifacts loaded.
    pub fn new(
        id: MigrationId,
        workspace_id: WorkspaceId,
        agent_id: AgentId,
        stable_subject: MemorySubjectId,
        source_profile: ModelProfileId,
        target_profile: ModelProfileId,
    ) -> Result<Self> {
        Ok(Self {
            id,
            workspace_id,
            agent_id,
            stable_subject,
            source_profile,
            target_profile,
            phase: MigrationPhase::Planned,
            checkpoint_digest: None,
            source_runtime_digest: None,
            continuity_profile_digest: None,
            compatibility_digest: None,
            target_runtime_digest: None,
            bootstrap_pack_digest: None,
            events: Vec::new(),
            failure_reason: None,
        })
    }

    /// Binds the portable checkpoint before compatibility analysis.
    pub fn seal_checkpoint(
        &mut self,
        checkpoint: &PortableCheckpoint,
        at: TimestampMicros,
    ) -> Result<()> {
        self.validate()?;
        self.require_phase(MigrationPhase::Planned)?;
        self.validate_time(at)?;
        checkpoint.validate()?;
        if checkpoint.workspace_id != self.workspace_id
            || checkpoint.agent_id != self.agent_id
            || checkpoint.stable_subject != self.stable_subject
            || checkpoint.source_model_profile != self.source_profile
        {
            return Err(ContinuityError::IdentityMismatch(
                "portable checkpoint belongs to another migration identity".to_owned(),
            ));
        }
        self.checkpoint_digest = Some(checkpoint.digest);
        self.source_runtime_digest = Some(checkpoint.source_runtime_digest);
        self.continuity_profile_digest = Some(checkpoint.continuity_profile_digest);
        self.transition(MigrationPhase::CheckpointSealed, at, checkpoint.digest)
    }

    /// Binds an exact compatibility report and chooses rebuild/ready phase.
    pub fn accept_compatibility(
        &mut self,
        report: &MigrationCompatibilityReport,
        at: TimestampMicros,
    ) -> Result<()> {
        self.validate()?;
        self.require_phase(MigrationPhase::CheckpointSealed)?;
        self.validate_time(at)?;
        report.validate()?;
        if report.migration_id != self.id
            || report.workspace_id != self.workspace_id
            || report.agent_id != self.agent_id
            || report.stable_subject != self.stable_subject
            || report.source_profile != self.source_profile
            || report.target_profile != self.target_profile
            || Some(report.source_runtime_digest) != self.source_runtime_digest
        {
            return Err(ContinuityError::IdentityMismatch(
                "compatibility report belongs to another migration".to_owned(),
            ));
        }
        if !report.compatible {
            return Err(ContinuityError::IncompatibleRuntime(
                "compatibility report contains blocking findings".to_owned(),
            ));
        }
        self.compatibility_digest = Some(report.report_digest);
        self.target_runtime_digest = Some(report.target_runtime_digest);
        self.transition(
            MigrationPhase::CompatibilityAnalyzed,
            at,
            report.report_digest,
        )?;
        let next = if report.reembedding_jobs.is_empty() {
            MigrationPhase::ReadyForBootstrap
        } else {
            MigrationPhase::Reembedding
        };
        self.transition(next, at, report.report_digest)
    }

    /// Verifies all planned rebuilds before bootstrap.
    pub fn finish_reembedding(
        &mut self,
        report: &MigrationCompatibilityReport,
        jobs: &[ReembeddingJob],
        at: TimestampMicros,
    ) -> Result<()> {
        self.validate()?;
        self.require_phase(MigrationPhase::Reembedding)?;
        self.validate_time(at)?;
        report.validate()?;
        if self.compatibility_digest != Some(report.report_digest) {
            return Err(ContinuityError::IdentityMismatch(
                "re-embedding report differs from the accepted compatibility report".to_owned(),
            ));
        }
        if jobs.len() != report.reembedding_jobs.len() {
            return Err(ContinuityError::InvalidInput(
                "re-embedding job result set is incomplete".to_owned(),
            ));
        }
        let mut job_by_id = std::collections::BTreeMap::new();
        for job in jobs {
            job.validate()?;
            if job_by_id.insert(job.spec.id, job).is_some() {
                return Err(ContinuityError::InvalidInput(
                    "re-embedding result set repeats a job identity".to_owned(),
                ));
            }
        }
        let mut canonical_states = Vec::with_capacity(report.reembedding_jobs.len());
        for spec in &report.reembedding_jobs {
            let job = job_by_id.get(&spec.id).copied().ok_or_else(|| {
                ContinuityError::InvalidInput("required re-embedding job is missing".to_owned())
            })?;
            if &job.spec != spec || !job.is_succeeded() {
                return Err(ContinuityError::InvalidTransition(
                    "required re-embedding job has not published successfully".to_owned(),
                ));
            }
            canonical_states.push((&job.spec.id, &job.state));
        }
        let digest = canonical_digest(&canonical_states)?;
        self.transition(MigrationPhase::ReadyForBootstrap, at, digest)
    }

    /// Records target-specific bootstrap only when checkpoint open loops survived.
    pub fn record_bootstrap(
        &mut self,
        bootstrap: &BootstrapResult,
        at: TimestampMicros,
    ) -> Result<()> {
        self.validate()?;
        self.require_phase(MigrationPhase::ReadyForBootstrap)?;
        self.validate_time(at)?;
        bootstrap.validate()?;
        if bootstrap.migration_id != self.id
            || bootstrap.workspace_id != self.workspace_id
            || bootstrap.agent_id != self.agent_id
            || bootstrap.stable_subject != self.stable_subject
            || bootstrap.source_profile != self.source_profile
            || bootstrap.target_profile != self.target_profile
            || Some(bootstrap.checkpoint_digest) != self.checkpoint_digest
            || Some(bootstrap.compatibility_digest) != self.compatibility_digest
            || Some(bootstrap.target_runtime_digest) != self.target_runtime_digest
        {
            return Err(ContinuityError::IdentityMismatch(
                "bootstrap result belongs to another migration artifact chain".to_owned(),
            ));
        }
        if !bootstrap.open_loops_preserved {
            return Err(ContinuityError::InvalidTransition(
                "bootstrap did not preserve every checkpoint open loop".to_owned(),
            ));
        }
        if !bootstrap.required_memory_refs_preserved {
            return Err(ContinuityError::InvalidTransition(
                "bootstrap did not preserve every checkpoint-required memory source".to_owned(),
            ));
        }
        if bootstrap.compiled.pack.status != contextdb_context::PackStatus::Sufficient {
            return Err(ContinuityError::InvalidTransition(
                "bootstrap did not satisfy every required continuity facet".to_owned(),
            ));
        }
        self.bootstrap_pack_digest = Some(bootstrap.compiled.canonical_digest.clone());
        self.transition(MigrationPhase::Bootstrapped, at, bootstrap.trace_digest)
    }

    /// Completes migration after the host/evaluation layer verifies operational resume.
    pub fn complete(
        &mut self,
        verification_digest: ContentDigest,
        at: TimestampMicros,
    ) -> Result<()> {
        self.validate()?;
        self.require_phase(MigrationPhase::Bootstrapped)?;
        self.validate_time(at)?;
        crate::ensure_digest_nonzero(verification_digest, "migration verification digest")?;
        self.transition(MigrationPhase::Completed, at, verification_digest)
    }

    /// Marks any non-terminal migration failed without copying sensitive payloads.
    pub fn fail(&mut self, reason: impl Into<String>, at: TimestampMicros) -> Result<()> {
        self.validate()?;
        if matches!(
            self.phase,
            MigrationPhase::Completed | MigrationPhase::Failed
        ) {
            return Err(ContinuityError::InvalidTransition(
                "terminal migration cannot fail again".to_owned(),
            ));
        }
        let reason = reason.into();
        validate_text(&reason, "migration failure reason", 1024)?;
        self.validate_time(at)?;
        let digest = canonical_digest(&reason)?;
        self.failure_reason = Some(reason);
        self.transition(MigrationPhase::Failed, at, digest)
    }

    /// Validates the trace and artifact/phase consistency.
    pub fn validate(&self) -> Result<()> {
        for (index, event) in self.events.iter().enumerate() {
            let expected = u32::try_from(index + 1).map_err(|_| {
                ContinuityError::InvalidInput("migration event sequence overflow".to_owned())
            })?;
            if event.sequence != expected || index > 0 && event.at < self.events[index - 1].at {
                return Err(ContinuityError::InvalidInput(
                    "migration event trace is not canonical/monotonic".to_owned(),
                ));
            }
            crate::ensure_digest_nonzero(event.artifact_digest, "migration event digest")?;
            let previous = index
                .checked_sub(1)
                .map(|previous| self.events[previous].phase);
            if !valid_event_transition(previous, event.phase) {
                return Err(ContinuityError::InvalidInput(
                    "migration event trace contains an invalid phase transition".to_owned(),
                ));
            }
        }
        if self.phase == MigrationPhase::Planned && !self.events.is_empty() {
            return Err(ContinuityError::InvalidInput(
                "planned migration unexpectedly contains lifecycle events".to_owned(),
            ));
        }
        if self.phase != MigrationPhase::Planned && self.events.is_empty() {
            return Err(ContinuityError::InvalidInput(
                "non-planned migration has no lifecycle events".to_owned(),
            ));
        }
        if self
            .events
            .last()
            .is_some_and(|event| event.phase != self.phase)
        {
            return Err(ContinuityError::InvalidInput(
                "migration phase differs from its final event".to_owned(),
            ));
        }
        if (self.phase == MigrationPhase::Failed) != self.failure_reason.is_some() {
            return Err(ContinuityError::InvalidInput(
                "migration failure phase/reason disagree".to_owned(),
            ));
        }
        let reached_checkpoint = self
            .events
            .iter()
            .any(|event| event.phase == MigrationPhase::CheckpointSealed);
        if reached_checkpoint != self.checkpoint_digest.is_some()
            || reached_checkpoint != self.source_runtime_digest.is_some()
            || reached_checkpoint != self.continuity_profile_digest.is_some()
        {
            return Err(ContinuityError::InvalidInput(
                "migration checkpoint/profile/runtime bindings disagree with the trace".to_owned(),
            ));
        }
        if let Some(digest) = self.source_runtime_digest {
            crate::ensure_digest_nonzero(digest, "lifecycle source runtime digest")?;
        }
        if let Some(digest) = self.continuity_profile_digest {
            crate::ensure_digest_nonzero(digest, "lifecycle continuity profile digest")?;
        }
        if let Some(digest) = self.checkpoint_digest {
            let event = self
                .events
                .iter()
                .find(|event| event.phase == MigrationPhase::CheckpointSealed)
                .ok_or_else(|| {
                    ContinuityError::InvalidInput(
                        "checkpoint digest has no sealing event".to_owned(),
                    )
                })?;
            if event.artifact_digest != digest {
                return Err(ContinuityError::InvalidInput(
                    "checkpoint event digest differs from lifecycle binding".to_owned(),
                ));
            }
        }
        let reached_compatibility = self
            .events
            .iter()
            .any(|event| event.phase == MigrationPhase::CompatibilityAnalyzed);
        if reached_compatibility != self.compatibility_digest.is_some()
            || reached_compatibility != self.target_runtime_digest.is_some()
        {
            return Err(ContinuityError::InvalidInput(
                "migration compatibility binding disagrees with the trace".to_owned(),
            ));
        }
        if let Some(digest) = self.compatibility_digest {
            let event = self
                .events
                .iter()
                .find(|event| event.phase == MigrationPhase::CompatibilityAnalyzed)
                .ok_or_else(|| {
                    ContinuityError::InvalidInput(
                        "compatibility digest has no analysis event".to_owned(),
                    )
                })?;
            if event.artifact_digest != digest {
                return Err(ContinuityError::InvalidInput(
                    "compatibility event digest differs from lifecycle binding".to_owned(),
                ));
            }
        }
        if let Some(digest) = self.target_runtime_digest {
            crate::ensure_digest_nonzero(digest, "lifecycle target runtime digest")?;
        }
        let reached_bootstrap = self
            .events
            .iter()
            .any(|event| event.phase == MigrationPhase::Bootstrapped);
        if reached_bootstrap != self.bootstrap_pack_digest.is_some() {
            return Err(ContinuityError::InvalidInput(
                "migration bootstrap binding disagrees with the trace".to_owned(),
            ));
        }
        if let Some(digest) = &self.bootstrap_pack_digest
            && (digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        {
            return Err(ContinuityError::InvalidInput(
                "migration bootstrap pack digest is not canonical hexadecimal".to_owned(),
            ));
        }
        if let Some(reason) = &self.failure_reason {
            validate_text(reason, "migration failure reason", 1024)?;
            let expected = canonical_digest(reason)?;
            if self
                .events
                .last()
                .is_none_or(|event| event.artifact_digest != expected)
            {
                return Err(ContinuityError::InvalidInput(
                    "migration failure reason differs from its event digest".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Emits compact canonical JSON after validating the complete transition trace.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| ContinuityError::Serialization(error.to_string()))
    }

    /// Parses canonical JSON and rejects invalid transitions, tampering, or alternate encoding.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ContinuityError::Serialization(error.to_string()))?;
        value.validate()?;
        if value.to_json()? != bytes {
            return Err(ContinuityError::Serialization(
                "migration lifecycle JSON is not canonical".to_owned(),
            ));
        }
        Ok(value)
    }

    fn require_phase(&self, expected: MigrationPhase) -> Result<()> {
        if self.phase != expected {
            return Err(ContinuityError::InvalidTransition(format!(
                "expected {expected:?}, found {:?}",
                self.phase
            )));
        }
        Ok(())
    }

    fn validate_time(&self, at: TimestampMicros) -> Result<()> {
        if self.events.last().is_some_and(|event| at < event.at) {
            return Err(ContinuityError::InvalidTransition(
                "migration timestamp moved backwards".to_owned(),
            ));
        }
        Ok(())
    }

    fn transition(
        &mut self,
        phase: MigrationPhase,
        at: TimestampMicros,
        artifact_digest: ContentDigest,
    ) -> Result<()> {
        if self.events.last().is_some_and(|event| at < event.at) {
            return Err(ContinuityError::InvalidTransition(
                "migration timestamp moved backwards".to_owned(),
            ));
        }
        crate::ensure_digest_nonzero(artifact_digest, "migration transition digest")?;
        let sequence = u32::try_from(self.events.len() + 1).map_err(|_| {
            ContinuityError::InvalidTransition("migration event sequence overflow".to_owned())
        })?;
        self.phase = phase;
        self.events.push(MigrationEvent {
            sequence,
            phase,
            at,
            artifact_digest,
        });
        self.validate()
    }
}

fn valid_event_transition(previous: Option<MigrationPhase>, next: MigrationPhase) -> bool {
    matches!(
        (previous, next),
        (
            None,
            MigrationPhase::CheckpointSealed | MigrationPhase::Failed
        ) | (
            Some(MigrationPhase::CheckpointSealed),
            MigrationPhase::CompatibilityAnalyzed | MigrationPhase::Failed
        ) | (
            Some(MigrationPhase::CompatibilityAnalyzed),
            MigrationPhase::Reembedding
                | MigrationPhase::ReadyForBootstrap
                | MigrationPhase::Failed
        ) | (
            Some(MigrationPhase::Reembedding),
            MigrationPhase::ReadyForBootstrap | MigrationPhase::Failed
        ) | (
            Some(MigrationPhase::ReadyForBootstrap),
            MigrationPhase::Bootstrapped | MigrationPhase::Failed
        ) | (
            Some(MigrationPhase::Bootstrapped),
            MigrationPhase::Completed | MigrationPhase::Failed
        )
    )
}
