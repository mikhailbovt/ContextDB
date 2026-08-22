//! Durable asynchronous post-turn cognition jobs.

use std::fmt;

use contextdb_cognition::{
    AdjudicationOutput, AuthorizationContext, DeterministicPostTurnExtractor, EvidenceCatalog,
    PostTurnInput, ProcessingRun, ProposalBatch, input_digest, policy_digest,
};
use contextdb_core::{
    CommitSeq, ContentDigest, NonEmptyVec, ObservationId, SemanticEnvelope, Validate,
};
use contextdb_storage::StorageEngine;

use crate::{
    ChatError, ChatStore, ConversationPrincipal, Result, SemanticJobId, StoredSemanticJob,
    StoredSemanticStatus,
};

/// Public lifecycle of a durable post-turn semantic job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticJobStatus {
    /// Captured and waiting for extraction.
    Pending,
    /// Proposal batch is durable and awaits host-supplied graph adjudication.
    Extracted,
    /// Semantic mutation and atomic derived-work outbox were published.
    Published,
    /// Deterministic adjudication correctly produced no mutation.
    NoOp,
    /// A shadow run was evaluated without publication authority.
    ShadowEvaluated,
}

/// Payload-free semantic-job status for queues and observability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticJobSummary {
    /// Stable job identity.
    pub id: SemanticJobId,
    /// Immutable journal evidence.
    pub observation_id: ObservationId,
    /// Current lifecycle status.
    pub status: SemanticJobStatus,
    /// Published journal sequence, when applicable.
    pub publication_seq: Option<CommitSeq>,
    /// Bound processing run after extraction.
    pub processing_run: Option<String>,
}

/// Trusted inputs which bind extraction to the later M10 adjudication run.
#[derive(Clone, Debug)]
pub struct SemanticExtractionRequest {
    /// Job whose protected text may be opened.
    pub job_id: SemanticJobId,
    /// Session-authorized caller.
    pub principal: ConversationPrincipal,
    /// Immutable M10 processing identity.
    pub run: ProcessingRun,
    /// Host policy-engine result.
    pub authorization: AuthorizationContext,
    /// Target semantic envelope. It may narrow, never broaden, capture policy.
    pub publication_envelope: SemanticEnvelope,
}

/// Exact extraction artifacts needed to construct an M10 `AdjudicationInput`.
#[derive(Clone)]
pub struct ExtractedSemanticJob {
    /// Payload-free status.
    pub summary: SemanticJobSummary,
    /// Immutable journal references for the transaction.
    pub journal_refs: NonEmptyVec<ObservationId>,
    /// Validated evidence catalog without raw conversational content.
    pub evidence: EvidenceCatalog,
    /// Auditable processing run.
    pub run: ProcessingRun,
    /// Precomputed host authorization.
    pub authorization: AuthorizationContext,
    /// Target policy used to bind proposal hashes.
    pub publication_envelope: SemanticEnvelope,
    /// Deterministic proposal batch; it has no mutation authority.
    pub proposals: ProposalBatch,
}

impl fmt::Debug for ExtractedSemanticJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtractedSemanticJob")
            .field("summary", &self.summary)
            .field("journal_ref_count", &self.journal_refs.len())
            .field("evidence_count", &self.evidence.0.len())
            .field("processing_run", &self.run.id)
            .field("proposal_count", &self.proposals.candidates.len())
            .finish_non_exhaustive()
    }
}

/// Publication/no-op result for an extracted job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticJobOutcome {
    /// Job identity.
    pub job_id: SemanticJobId,
    /// Final lifecycle state.
    pub status: SemanticJobStatus,
    /// Journal publication sequence for a semantic mutation.
    pub publication_seq: Option<CommitSeq>,
    /// Logical output digest, including no-op and shadow decisions.
    pub output_digest: ContentDigest,
    /// True when a previously finalized status was returned.
    pub replayed: bool,
}

impl<E: StorageEngine> ChatStore<E> {
    /// Lists authorized jobs without exposing their text or proposal payload.
    pub fn semantic_jobs(
        &self,
        principal: &ConversationPrincipal,
    ) -> Result<Vec<SemanticJobSummary>> {
        let mut jobs = self
            .semantic_job_entries()?
            .into_iter()
            .filter(|job| self.authorize_job(principal, job).is_ok())
            .map(|job| semantic_summary(&job))
            .collect::<Vec<_>>();
        jobs.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(jobs)
    }

    /// Runs the deterministic no-model M10 extractor and durably stores only
    /// proposals. It cannot publish semantic mutations.
    pub fn extract_semantic_job(
        &self,
        request: &SemanticExtractionRequest,
        extractor: &DeterministicPostTurnExtractor,
    ) -> Result<ExtractedSemanticJob> {
        let mut job = self.load_semantic_job(&request.job_id)?;
        self.authorize_job(&request.principal, &job)?;
        if request.authorization.workspace_id != job.workspace_id
            || !request
                .authorization
                .permitted_evidence
                .contains(&job.evidence_id)
        {
            return Err(ChatError::Unauthorized);
        }
        request.publication_envelope.validate()?;
        request
            .publication_envelope
            .validate_derived_from(&job.envelope)?;
        let evidence = Self::evidence_catalog(&job);
        let journal_refs = NonEmptyVec::new(job.observation_id);
        let expected_input = input_digest(&journal_refs, &evidence, &request.authorization);
        let expected_policy = policy_digest(&request.publication_envelope)?;

        let proposals = if let (Some(existing_run), Some(existing)) =
            (&job.processing_run, &job.proposals)
        {
            if existing_run != &request.run.id {
                return Err(ChatError::IdempotencyConflict);
            }
            existing.clone()
        } else {
            let input = PostTurnInput {
                processing_run: request.run.id.clone(),
                input_digest: expected_input,
                policy_digest: expected_policy,
                speaker: match job.speaker {
                    crate::ChatSpeaker::User => contextdb_cognition::TurnSpeaker::User,
                    crate::ChatSpeaker::Assistant => contextdb_cognition::TurnSpeaker::Assistant,
                },
                speaker_subject_ref: match job.speaker {
                    crate::ChatSpeaker::User => "user",
                    crate::ChatSpeaker::Assistant => "assistant",
                }
                .to_owned(),
                text: job.text.clone(),
                evidence_id: job.evidence_id,
                quote_hash: job.quote_hash,
                structured: job.structured.clone(),
            };
            let proposals = extractor.extract(&input)?;
            job.processing_run = Some(request.run.id.clone());
            job.proposals = Some(proposals.clone());
            job.status = StoredSemanticStatus::Extracted;
            self.store_semantic_job(&job)?;
            proposals
        };
        Ok(ExtractedSemanticJob {
            summary: semantic_summary(&job),
            journal_refs,
            evidence,
            run: request.run.clone(),
            authorization: request.authorization.clone(),
            publication_envelope: request.publication_envelope.clone(),
            proposals,
        })
    }

    /// Publishes only the validated mutation emitted by M10 adjudication, or
    /// records an explicit no-op/shadow result. Journal publication atomically
    /// includes its derived-work outbox.
    pub fn finish_semantic_job(
        &self,
        principal: &ConversationPrincipal,
        job_id: &SemanticJobId,
        output: &AdjudicationOutput,
    ) -> Result<SemanticJobOutcome> {
        let mut job = self.load_semantic_job(job_id)?;
        self.authorize_job(principal, &job)?;
        let expected_run = job
            .processing_run
            .as_deref()
            .ok_or(ChatError::InvalidInput("semantic_job_not_extracted"))?;
        if output.processing_run != expected_run {
            return Err(ChatError::IdempotencyConflict);
        }
        let output_digest = output.logical_digest()?;
        if let Some(existing) = job.output_digest {
            if existing != output_digest {
                return Err(ChatError::IdempotencyConflict);
            }
            let summary = semantic_summary(&job);
            return Ok(SemanticJobOutcome {
                job_id: job.id,
                status: summary.status,
                publication_seq: summary.publication_seq,
                output_digest,
                replayed: true,
            });
        }

        let (status, publication_seq) = if let Some(mutation) = &output.transaction {
            if matches!(output.status, contextdb_cognition::PipelineStatus::Shadow)
                || !mutation.journal_refs.contains(&job.observation_id)
            {
                return Err(ChatError::InvalidInput("semantic_publication_binding"));
            }
            let receipt = self.publish_job_mutation(&job, mutation)?;
            (
                StoredSemanticStatus::Published {
                    commit_seq: receipt.commit_seq,
                },
                Some(receipt.commit_seq),
            )
        } else if matches!(output.status, contextdb_cognition::PipelineStatus::Shadow) {
            (StoredSemanticStatus::ShadowEvaluated, None)
        } else {
            (StoredSemanticStatus::NoOp, None)
        };
        job.status = status;
        job.output_digest = Some(output_digest);
        self.store_semantic_job(&job)?;
        Ok(SemanticJobOutcome {
            job_id: job.id,
            status: semantic_status(&job.status),
            publication_seq,
            output_digest,
            replayed: false,
        })
    }
}

fn semantic_summary(job: &StoredSemanticJob) -> SemanticJobSummary {
    let publication_seq = match job.status {
        StoredSemanticStatus::Published { commit_seq } => Some(commit_seq),
        _ => None,
    };
    SemanticJobSummary {
        id: job.id.clone(),
        observation_id: job.observation_id,
        status: semantic_status(&job.status),
        publication_seq,
        processing_run: job.processing_run.clone(),
    }
}

const fn semantic_status(status: &StoredSemanticStatus) -> SemanticJobStatus {
    match status {
        StoredSemanticStatus::Pending => SemanticJobStatus::Pending,
        StoredSemanticStatus::Extracted => SemanticJobStatus::Extracted,
        StoredSemanticStatus::Published { .. } => SemanticJobStatus::Published,
        StoredSemanticStatus::NoOp => SemanticJobStatus::NoOp,
        StoredSemanticStatus::ShadowEvaluated => SemanticJobStatus::ShadowEvaluated,
    }
}
