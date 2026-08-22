//! Deterministic in-memory source and knowledge ledger.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    AcceptanceState, BitemporalRange, Cardinality, Claim, ClaimId, ClaimObject, ClaimRevision,
    CommitRange, CommitSeq, ConfidenceProfile, ConflictPolicy, ConflictResolution, ConflictSet,
    ConflictSetId, ConflictSetRecord, ConflictSetRevision, ConflictState, DerivationId,
    DerivationKind, DerivedWorkItem, EpistemicBasis, EpistemicState, EvidenceId, EvidenceSpan,
    IdentityState, LifecycleState, LineageNode, MutationId, Node, NodeId, NodeRecord, NodeRevision,
    NodeType, NonEmptyVec, PredicateDefinition, PredicateId, RevisionNumber, SecurityPropagation,
    SemanticEnvelope, SemanticMutationSet, SnapshotRef, SourceId, TemporalMode, Transitivity,
    Validate,
};
use contextdb_recall::RecallPrincipal;

use crate::adapter::deterministic_uuid;
use crate::{
    AdaptedDocument, DocumentRevisionKind, KnowledgeAlternative, KnowledgeAnswerState,
    KnowledgeChangeReason, KnowledgeCitation, KnowledgeError, KnowledgeExport, KnowledgeHypothesis,
    KnowledgeOpenQuestion, KnowledgeProposalAction, KnowledgePublication, KnowledgeQuery,
    KnowledgeQueryResult, KnowledgeTimelineEntry, PublicationStatus, Result, SourceClaimRecord,
    SourceClaimRevisionReason, SourceConstraint, SourceRevision, StatementEpistemic, UnknownReason,
};

/// In-memory correctness baseline for accumulating source knowledge.
#[derive(Clone, Debug, Default)]
pub struct KnowledgeLedger {
    workspace_id: Option<contextdb_core::WorkspaceId>,
    commit_seq: CommitSeq,
    sources: BTreeMap<SourceId, Vec<SourceRevision>>,
    source_keys: BTreeMap<String, SourceId>,
    nodes: BTreeMap<String, NodeRecord>,
    predicates: BTreeMap<String, PredicateDefinition>,
    claims: BTreeMap<ClaimId, SourceClaimRecord>,
    claim_keys: BTreeMap<crate::SourceStatementRef, ClaimId>,
    conflicts: BTreeMap<String, ConflictSetRecord>,
    hypotheses: Vec<KnowledgeHypothesis>,
    open_questions: Vec<KnowledgeOpenQuestion>,
    evidence: BTreeMap<EvidenceId, EvidenceSpan>,
    evidence_sources: BTreeMap<EvidenceId, SourceId>,
    slot_watermarks: BTreeMap<String, CommitSeq>,
}

impl KnowledgeLedger {
    /// Current coherent semantic snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotRef {
        SnapshotRef {
            commit_seq: self.commit_seq,
        }
    }

    /// Publishes one complete adapted source revision atomically. Validation is
    /// performed against a clone and `self` changes only after every core
    /// invariant has passed.
    pub fn publish(&mut self, document: AdaptedDocument) -> Result<KnowledgePublication> {
        let mut staged = self.clone();
        let publication = staged.apply(document)?;
        *self = staged;
        Ok(publication)
    }

    /// Executes authorization before inspecting source/claim/evidence payload.
    pub fn query(&self, query: &KnowledgeQuery) -> Result<KnowledgeQueryResult> {
        validate_query(query)?;
        if query.known_at.commit_seq > self.commit_seq {
            return Err(KnowledgeError::FutureSnapshot);
        }

        let authorized_sources: BTreeSet<_> = self
            .sources
            .iter()
            .filter_map(|(source_id, revisions)| {
                revisions
                    .iter()
                    .rev()
                    .find(|revision| revision.published_at.commit_seq <= query.known_at.commit_seq)
                    .filter(|revision| principal_allows(&query.principal, revision))
                    .filter(|revision| source_matches(&query.source, revision))
                    .map(|_| *source_id)
            })
            .collect();
        let mut active = Vec::new();
        let mut history = Vec::new();
        let mut had_retracted_match = false;
        for record in self.claims.values() {
            if !authorized_sources.contains(&record.source_id) {
                continue;
            }
            let has_authorized_revision = record.revisions.iter().any(|revision| {
                revision.temporal.transaction_time.start <= query.known_at.commit_seq
                    && principal_allows_envelope(
                        &query.principal,
                        record.claim.workspace_id,
                        &revision.envelope,
                    )
            });
            if !has_authorized_revision
                || record.subject_key != query.subject_key
                || record.predicate_key != query.predicate_key
            {
                continue;
            }
            let revisions: Vec<_> = record
                .revisions
                .iter()
                .zip(&record.revision_reasons)
                .filter(|(revision, _)| {
                    revision.temporal.transaction_time.start <= query.known_at.commit_seq
                        && revision.temporal.valid_time.contains(query.valid_at)
                        && principal_allows_envelope(
                            &query.principal,
                            record.claim.workspace_id,
                            &revision.envelope,
                        )
                })
                .collect();
            if let Some((revision, _)) = revisions.last() {
                if revision.epistemic.lifecycle == LifecycleState::Retracted {
                    had_retracted_match = true;
                }
                if revision.epistemic.acceptance.is_published()
                    && revision.epistemic.lifecycle == LifecycleState::Active
                {
                    active.push((record, *revision));
                }
            }
            if query.include_history {
                for (revision, reason) in record.revisions.iter().zip(&record.revision_reasons) {
                    if revision.temporal.transaction_time.start <= query.known_at.commit_seq
                        && principal_allows_envelope(
                            &query.principal,
                            record.claim.workspace_id,
                            &revision.envelope,
                        )
                    {
                        history.push(self.timeline_entry(record, revision, *reason, query)?);
                    }
                }
            }
        }
        history.sort_by_key(|entry| (entry.system_start, entry.claim_id, entry.revision));

        let mut searched_sources: Vec<_> = authorized_sources.iter().copied().collect();
        searched_sources.sort();
        let mut relevant_questions: Vec<_> = self
            .open_questions
            .iter()
            .filter(|question| {
                authorized_sources.contains(&question.source_id)
                    && self.workspace_id.is_some_and(|workspace| {
                        principal_allows_envelope(&query.principal, workspace, &question.envelope)
                    })
                    && question.subject_key == query.subject_key
                    && question.predicate_key == query.predicate_key
                    && question.published_at.commit_seq <= query.known_at.commit_seq
            })
            .map(|question| question.question.clone())
            .collect();
        relevant_questions.sort();
        relevant_questions.dedup();
        let mut hypotheses: Vec<_> = self
            .hypotheses
            .iter()
            .filter(|hypothesis| {
                authorized_sources.contains(&hypothesis.source_id)
                    && self.workspace_id.is_some_and(|workspace| {
                        principal_allows_envelope(&query.principal, workspace, &hypothesis.envelope)
                    })
                    && hypothesis.subject_key == query.subject_key
                    && hypothesis.predicate_key == query.predicate_key
                    && hypothesis.published_at.commit_seq <= query.known_at.commit_seq
            })
            .cloned()
            .collect();
        hypotheses.sort_by_key(|hypothesis| {
            (
                hypothesis.source_id,
                hypothesis.statement_key.clone(),
                hypothesis.published_at.commit_seq,
            )
        });

        let state = if active.is_empty() {
            let reason = if authorized_sources.is_empty() {
                UnknownReason::NoAuthorizedSource
            } else if !relevant_questions.is_empty() {
                UnknownReason::OpenQuestion
            } else if !hypotheses.is_empty() {
                UnknownReason::OnlyDerivedHypotheses
            } else if had_retracted_match {
                UnknownReason::AllSupportRetracted
            } else {
                UnknownReason::NoMatchingClaim
            };
            KnowledgeAnswerState::Unknown {
                reason,
                searched_sources,
                open_questions: relevant_questions,
            }
        } else {
            let alternatives = self.alternatives(&active, query)?;
            if alternatives.len() == 1 {
                KnowledgeAnswerState::Supported {
                    answer: alternatives.into_iter().next().ok_or(
                        KnowledgeError::InvalidInput {
                            field: "knowledge.alternatives",
                            reason: "supported answer lost its alternative",
                        },
                    )?,
                }
            } else if query.disclose_conflicts {
                let canonical_conflict = self.conflict_for_active(&active, query)?;
                let conflict_set_id =
                    canonical_conflict.unwrap_or_else(|| answer_conflict_id(&alternatives));
                KnowledgeAnswerState::Disputed {
                    conflict_set_id,
                    canonical_conflict: canonical_conflict.is_some(),
                    alternatives,
                }
            } else {
                KnowledgeAnswerState::Unknown {
                    reason: UnknownReason::NoMatchingClaim,
                    searched_sources,
                    open_questions: vec![
                        "authorized sources disagree and conflict disclosure was disabled"
                            .to_owned(),
                    ],
                }
            }
        };

        let source_revision_watermark = self.authorized_slot_watermark(
            &authorized_sources,
            &query.subject_key,
            &query.predicate_key,
            query.known_at.commit_seq,
            &query.principal,
        );

        Ok(KnowledgeQueryResult {
            snapshot: query.known_at,
            valid_at: query.valid_at,
            subject_key: query.subject_key.clone(),
            predicate_key: query.predicate_key.clone(),
            state,
            history,
            hypotheses,
            source_revision_watermark,
        })
    }

    fn authorized_slot_watermark(
        &self,
        authorized_sources: &BTreeSet<SourceId>,
        subject_key: &str,
        predicate_key: &str,
        known_at: CommitSeq,
        principal: &RecallPrincipal,
    ) -> CommitSeq {
        let claim_commits = self
            .claims
            .values()
            .filter(|record| authorized_sources.contains(&record.source_id))
            .flat_map(|record| {
                record
                    .revisions
                    .iter()
                    .filter(|revision| {
                        principal_allows_envelope(
                            principal,
                            record.claim.workspace_id,
                            &revision.envelope,
                        )
                    })
                    .filter(|_| {
                        record.subject_key == subject_key && record.predicate_key == predicate_key
                    })
                    .map(|revision| revision.temporal.transaction_time.start)
            });
        let question_commits = self
            .open_questions
            .iter()
            .filter(|question| {
                authorized_sources.contains(&question.source_id)
                    && self.workspace_id.is_some_and(|workspace| {
                        principal_allows_envelope(principal, workspace, &question.envelope)
                    })
                    && question.subject_key == subject_key
                    && question.predicate_key == predicate_key
            })
            .map(|question| question.published_at.commit_seq);
        let hypothesis_commits = self
            .hypotheses
            .iter()
            .filter(|hypothesis| {
                authorized_sources.contains(&hypothesis.source_id)
                    && self.workspace_id.is_some_and(|workspace| {
                        principal_allows_envelope(principal, workspace, &hypothesis.envelope)
                    })
                    && hypothesis.subject_key == subject_key
                    && hypothesis.predicate_key == predicate_key
            })
            .map(|hypothesis| hypothesis.published_at.commit_seq);
        claim_commits
            .chain(question_commits)
            .chain(hypothesis_commits)
            .filter(|commit| *commit <= known_at)
            .max()
            .unwrap_or(CommitSeq::GENESIS)
    }

    fn conflict_for_active(
        &self,
        active: &[(&SourceClaimRecord, &ClaimRevision)],
        query: &KnowledgeQuery,
    ) -> Result<Option<ConflictSetId>> {
        let signatures: BTreeSet<_> = active
            .iter()
            .map(|(_, revision)| policy_signature(&revision.envelope))
            .collect::<Result<_>>()?;
        let Some(signature) = signatures.iter().next() else {
            return Ok(None);
        };
        if signatures.len() != 1 {
            return Ok(None);
        }
        let key = format!(
            "{}\0{signature}",
            slot_key(&query.subject_key, &query.predicate_key)
        );
        let active_claims: BTreeSet<_> = active.iter().map(|(record, _)| record.claim.id).collect();
        Ok(self.conflicts.get(&key).and_then(|record| {
            record
                .revisions
                .iter()
                .rev()
                .find(|revision| revision.transaction_time.start <= query.known_at.commit_seq)
                .filter(|revision| {
                    revision.resolution == ConflictResolution::Unresolved
                        && active_claims
                            .iter()
                            .all(|claim| revision.members.contains(claim))
                })
                .map(|_| record.conflict.id)
        }))
    }

    /// Canonical logical export independent of a storage backend.
    #[must_use]
    pub fn export(&self) -> KnowledgeExport {
        KnowledgeExport {
            workspace_id: self.workspace_id,
            snapshot: self.snapshot(),
            sources: self.sources.clone(),
            nodes: self.nodes.clone(),
            predicates: self.predicates.clone(),
            claims: self.claims.clone(),
            conflicts: self.conflicts.clone(),
            hypotheses: self.hypotheses.clone(),
            open_questions: self.open_questions.clone(),
            slot_watermarks: self.slot_watermarks.clone(),
        }
    }

    /// Restores and validates a canonical logical export.
    pub fn import(export: KnowledgeExport) -> Result<Self> {
        let mut ledger = Self {
            workspace_id: export.workspace_id,
            commit_seq: export.snapshot.commit_seq,
            sources: export.sources,
            source_keys: BTreeMap::new(),
            nodes: export.nodes,
            predicates: export.predicates,
            claims: export.claims,
            claim_keys: BTreeMap::new(),
            conflicts: export.conflicts,
            hypotheses: export.hypotheses,
            open_questions: export.open_questions,
            evidence: BTreeMap::new(),
            evidence_sources: BTreeMap::new(),
            slot_watermarks: export.slot_watermarks,
        };
        let mut artifact_ids = BTreeSet::new();
        let mut content_block_ids = BTreeSet::new();
        let mut evidence_ids = BTreeSet::new();
        for (source_id, revisions) in &ledger.sources {
            if revisions.is_empty() {
                return Err(KnowledgeError::InvalidInput {
                    field: "knowledge_export.sources",
                    reason: "source revision chain must not be empty",
                });
            }
            for (index, revision) in revisions.iter().enumerate() {
                validate_source_revision(revision)?;
                let expected_revision =
                    RevisionNumber::new(u32::try_from(index + 1).map_err(|_| {
                        KnowledgeError::InvalidInput {
                            field: "knowledge_export.sources",
                            reason: "source revision count exceeds u32",
                        }
                    })?)?;
                let expected_parent = index
                    .checked_sub(1)
                    .and_then(|previous| revisions.get(previous))
                    .map(|previous| previous.artifact.id);
                if revision.revision != expected_revision
                    || revision.supersedes != expected_parent
                    || revision.published_at.commit_seq > ledger.commit_seq
                    || index.checked_sub(1).is_some_and(|previous| {
                        revisions[previous].published_at.commit_seq
                            >= revision.published_at.commit_seq
                    })
                {
                    return Err(KnowledgeError::InvalidInput {
                        field: "knowledge_export.sources",
                        reason: "source revision chain is not monotonic and contiguous",
                    });
                }
                if revisions.first().is_some_and(|first| {
                    first.source_key != revision.source_key
                        || first.source_family != revision.source_family
                }) {
                    return Err(KnowledgeError::InvalidInput {
                        field: "knowledge_export.sources",
                        reason: "source key and dependence family must remain stable",
                    });
                }
                if ledger
                    .workspace_id
                    .is_some_and(|workspace| workspace != revision.source.workspace_id)
                {
                    return Err(KnowledgeError::InvalidInput {
                        field: "knowledge_export.workspace_id",
                        reason: "source revision belongs to another workspace",
                    });
                }
                ledger
                    .workspace_id
                    .get_or_insert(revision.source.workspace_id);
                if revision.source.id != *source_id {
                    return Err(KnowledgeError::InvalidInput {
                        field: "knowledge_export.sources",
                        reason: "source map key differs from revision source ID",
                    });
                }
                if ledger
                    .source_keys
                    .insert(revision.source_key.clone(), *source_id)
                    .is_some_and(|existing| existing != *source_id)
                {
                    return Err(KnowledgeError::InvalidInput {
                        field: "knowledge_export.source_keys",
                        reason: "one stable source key maps to multiple source IDs",
                    });
                }
                if !artifact_ids.insert(revision.artifact.id)
                    || revision
                        .content_blocks
                        .iter()
                        .any(|content| !content_block_ids.insert(content.id))
                {
                    return Err(KnowledgeError::InvalidInput {
                        field: "knowledge_export.artifacts",
                        reason: "artifact and content block IDs must be globally unique",
                    });
                }
                for evidence in &revision.evidence {
                    if !evidence_ids.insert(evidence.id)
                        || ledger
                            .evidence
                            .insert(evidence.id, evidence.clone())
                            .is_some()
                    {
                        return Err(KnowledgeError::InvalidInput {
                            field: "knowledge_export.evidence",
                            reason: "evidence IDs must be globally unique",
                        });
                    }
                    ledger.evidence_sources.insert(evidence.id, *source_id);
                }
            }
        }
        let mut node_ids = BTreeSet::new();
        for record in ledger.nodes.values() {
            record.validate()?;
            if !node_ids.insert(record.node.id)
                || ledger
                    .workspace_id
                    .is_some_and(|workspace| workspace != record.node.workspace_id)
            {
                return Err(KnowledgeError::InvalidInput {
                    field: "knowledge_export.nodes",
                    reason: "node IDs must be unique and belong to the export workspace",
                });
            }
        }
        for predicate in ledger.predicates.values() {
            predicate.validate()?;
        }
        for (claim_id, record) in &ledger.claims {
            validate_claim_record(record)?;
            let source_head = ledger
                .sources
                .get(&record.source_id)
                .and_then(|revisions| revisions.last())
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge_export.claim.source",
                    reason: "claim refers to an absent source",
                })?;
            if record.claim.id != *claim_id
                || record.source_key != source_head.source_key
                || record.source_family != source_head.source_family
                || record.revisions.iter().any(|revision| {
                    revision.temporal.transaction_time.start > ledger.commit_seq
                        || revision.evidence.iter().any(|evidence| {
                            ledger.evidence_sources.get(evidence) != Some(&record.source_id)
                        })
                })
            {
                return Err(KnowledgeError::InvalidInput {
                    field: "knowledge_export.claim",
                    reason: "claim identity, source lineage, or commit range is inconsistent",
                });
            }
            let key = crate::SourceStatementRef {
                source_key: record.source_key.clone(),
                statement_key: record.statement_key.clone(),
            };
            if ledger.claim_keys.insert(key, record.claim.id).is_some() {
                return Err(KnowledgeError::InvalidInput {
                    field: "knowledge_export.claim_keys",
                    reason: "duplicate source statement claim",
                });
            }
        }
        for conflict in ledger.conflicts.values() {
            conflict.validate()?;
            if conflict
                .revisions
                .iter()
                .flat_map(|revision| revision.members.iter())
                .any(|member| !ledger.claims.contains_key(member))
            {
                return Err(KnowledgeError::InvalidInput {
                    field: "knowledge_export.conflicts",
                    reason: "conflict set refers to an absent source claim",
                });
            }
        }
        for hypothesis in &ledger.hypotheses {
            hypothesis.envelope.validate()?;
        }
        for question in &ledger.open_questions {
            question.envelope.validate()?;
        }
        if ledger
            .slot_watermarks
            .values()
            .any(|watermark| *watermark > ledger.commit_seq)
            || ledger.hypotheses.iter().any(|hypothesis| {
                hypothesis.published_at.commit_seq > ledger.commit_seq
                    || !ledger.sources.contains_key(&hypothesis.source_id)
                    || hypothesis
                        .evidence
                        .iter()
                        .chain(&hypothesis.supporting_evidence)
                        .any(|evidence| !ledger.evidence.contains_key(evidence))
                    || hypothesis.supporting_evidence.iter().any(|evidence| {
                        ledger.evidence_sources.get(evidence) == Some(&hypothesis.source_id)
                    })
            })
            || ledger.open_questions.iter().any(|question| {
                question.published_at.commit_seq > ledger.commit_seq
                    || !ledger.sources.contains_key(&question.source_id)
                    || ledger.evidence_sources.get(&question.evidence_id)
                        != Some(&question.source_id)
            })
        {
            return Err(KnowledgeError::InvalidInput {
                field: "knowledge_export.derived_state",
                reason: "watermark or derived source lineage exceeds the exported snapshot",
            });
        }
        Ok(ledger)
    }

    pub(crate) fn source_revision_at(
        &self,
        id: SourceId,
        snapshot: SnapshotRef,
    ) -> Option<&SourceRevision> {
        self.sources.get(&id).and_then(|revisions| {
            revisions
                .iter()
                .rev()
                .find(|revision| revision.published_at.commit_seq <= snapshot.commit_seq)
        })
    }

    pub(crate) fn source_revision_for_artifact(
        &self,
        id: SourceId,
        artifact: contextdb_core::ArtifactId,
    ) -> Option<&SourceRevision> {
        self.sources.get(&id).and_then(|revisions| {
            revisions
                .iter()
                .find(|revision| revision.artifact.id == artifact)
        })
    }

    pub(crate) fn source_revisions_through(
        &self,
        id: SourceId,
        snapshot: SnapshotRef,
    ) -> Vec<&SourceRevision> {
        self.sources
            .get(&id)
            .map(|revisions| {
                revisions
                    .iter()
                    .filter(|revision| revision.published_at.commit_seq <= snapshot.commit_seq)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn apply(&mut self, document: AdaptedDocument) -> Result<KnowledgePublication> {
        validate_source_revision(&document.source_revision)?;
        let source_id = document.source_revision.source.id;
        let artifact_id = document.source_revision.artifact.id;
        if self
            .workspace_id
            .is_some_and(|workspace| workspace != document.source_revision.source.workspace_id)
        {
            return Err(KnowledgeError::InvalidInput {
                field: "document.workspace_id",
                reason: "one knowledge ledger serves exactly one workspace",
            });
        }
        if let Some(existing_id) = self.source_keys.get(&document.source_revision.source_key)
            && *existing_id != source_id
        {
            return Err(KnowledgeError::InvalidInput {
                field: "document.source_key",
                reason: "stable source key maps to a different source ID",
            });
        }
        if let Some(existing) = self.sources.get(&source_id).and_then(|revisions| {
            revisions.iter().find(|revision| {
                revision.native_revision == document.source_revision.native_revision
            })
        }) {
            if existing.logical_digest != document.source_revision.logical_digest {
                return Err(KnowledgeError::RevisionDigestConflict {
                    native_revision: document.source_revision.native_revision,
                });
            }
            return Ok(KnowledgePublication {
                status: PublicationStatus::AlreadyPublished,
                snapshot: existing.published_at,
                source_id,
                artifact_id,
                created_claims: Vec::new(),
                revised_claims: Vec::new(),
                retracted_claims: Vec::new(),
                hypotheses_retained: 0,
                open_questions_retained: 0,
                semantic_transaction: None,
            });
        }
        if let Some(head) = self
            .sources
            .get(&source_id)
            .and_then(|revisions| revisions.last())
        {
            if document.source_revision.supersedes != Some(head.artifact.id) {
                return Err(KnowledgeError::SourceRevisionFork);
            }
            if document.source_revision.source_key != head.source_key
                || document.source_revision.source_family != head.source_family
            {
                return Err(KnowledgeError::InvalidInput {
                    field: "document.source_identity",
                    reason: "source key and dependence family are immutable",
                });
            }
        } else if document.source_revision.supersedes.is_some() {
            return Err(KnowledgeError::SourceRevisionFork);
        }

        let next = self
            .commit_seq
            .checked_next()
            .ok_or(KnowledgeError::CommitSequenceExhausted)?;
        let base_snapshot = self.snapshot();
        let mut source_revision = document.source_revision;
        source_revision.revision = RevisionNumber::new(
            u32::try_from(
                self.sources
                    .get(&source_id)
                    .map_or(1, |values| values.len() + 1),
            )
            .map_err(|_| KnowledgeError::InvalidInput {
                field: "source_revision.revision",
                reason: "source revision count exceeds u32",
            })?,
        )?;
        source_revision.published_at = SnapshotRef { commit_seq: next };
        if let Some(position) = &mut source_revision.observation.stream_position {
            position.ordinal = u64::from(source_revision.revision.get());
        }
        for entry in &mut source_revision.hierarchy {
            if entry.kind == crate::SourceHierarchyKind::Revision {
                entry.order_key = u64::from(source_revision.revision.get());
            }
        }
        validate_source_revision(&source_revision)?;
        let mut semantic = MutationBuilder::new(
            source_revision.source.workspace_id,
            base_snapshot,
            source_revision.observation.id,
        );
        let mut created_claims = Vec::new();
        let mut revised_claims = Vec::new();
        let mut retracted_claims = Vec::new();
        let mut touched_slots = BTreeSet::new();
        let mut hypotheses_retained = 0_usize;
        let mut open_questions_retained = 0_usize;

        for evidence in &source_revision.evidence {
            self.evidence.insert(evidence.id, evidence.clone());
            self.evidence_sources.insert(evidence.id, source_id);
        }
        semantic
            .transaction
            .observation_appends
            .push(source_revision.observation.clone());

        for proposal in document.proposals {
            match proposal.action {
                KnowledgeProposalAction::Assert {
                    subject_key,
                    subject_label,
                    predicate_key,
                    object,
                    valid_time,
                    epistemic,
                    cognition_candidate: _,
                } => match epistemic {
                    StatementEpistemic::SourceAssertion => {
                        let subject = self.ensure_subject(
                            &subject_key,
                            &subject_label,
                            next,
                            proposal.evidence_id,
                            &source_revision,
                            &mut semantic,
                        )?;
                        let predicate = self.ensure_predicate(&predicate_key, &object)?;
                        let claim_id = claim_id(source_id, &proposal.statement_key);
                        let key = crate::SourceStatementRef {
                            source_key: source_revision.source_key.clone(),
                            statement_key: proposal.statement_key.clone(),
                        };
                        if let Some(existing_id) = self.claim_keys.get(&key).copied() {
                            self.append_source_update(
                                existing_id,
                                object,
                                valid_time,
                                proposal.evidence_id,
                                next,
                                &source_revision,
                                &mut semantic,
                            )?;
                            revised_claims.push(existing_id);
                        } else {
                            self.create_source_claim(
                                claim_id,
                                source_id,
                                source_revision.source_key.clone(),
                                source_revision.source_family.clone(),
                                proposal.statement_key.clone(),
                                subject_key.clone(),
                                predicate_key.clone(),
                                subject,
                                &predicate,
                                object,
                                valid_time,
                                proposal.evidence_id,
                                next,
                                source_revision.source.trust,
                                &source_revision.envelope,
                                &mut semantic,
                            )?;
                            self.claim_keys.insert(key, claim_id);
                            created_claims.push(claim_id);
                        }
                        touched_slots.insert(slot_key(&subject_key, &predicate_key));
                    }
                    StatementEpistemic::DerivedHypothesis {
                        supporting_evidence,
                    } => {
                        if supporting_evidence
                            .iter()
                            .any(|evidence| !self.evidence.contains_key(evidence))
                        {
                            return Err(KnowledgeError::InvalidInput {
                                field: "knowledge.hypothesis.supporting_evidence",
                                reason: "hypothesis cites evidence absent from the immutable ledger",
                            });
                        }
                        if supporting_evidence.contains(&proposal.evidence_id)
                            || supporting_evidence.iter().any(|evidence| {
                                self.evidence_sources.get(evidence) == Some(&source_id)
                            })
                        {
                            return Err(KnowledgeError::InvalidInput {
                                field: "knowledge.hypothesis.supporting_evidence",
                                reason: "hypothesis support must be independent and non-circular",
                            });
                        }
                        self.hypotheses.push(KnowledgeHypothesis {
                            source_id,
                            statement_key: proposal.statement_key,
                            subject_key: subject_key.clone(),
                            predicate_key: predicate_key.clone(),
                            object,
                            evidence: vec![proposal.evidence_id],
                            supporting_evidence,
                            published_at: SnapshotRef { commit_seq: next },
                            envelope: source_revision.envelope.clone(),
                        });
                        touched_slots.insert(slot_key(&subject_key, &predicate_key));
                        hypotheses_retained += 1;
                    }
                },
                KnowledgeProposalAction::Retract { target, reason: _ } => {
                    let Some(claim_id) = self.claim_keys.get(&target).copied() else {
                        return Err(KnowledgeError::UnknownRetractionTarget {
                            source_key: target.source_key,
                            statement_key: target.statement_key,
                        });
                    };
                    let record =
                        self.claims
                            .get(&claim_id)
                            .ok_or(KnowledgeError::InvalidInput {
                                field: "knowledge.claim_index",
                                reason: "claim key points at a missing record",
                            })?;
                    if record.source_id != source_id
                        || record.source_family != source_revision.source_family
                    {
                        return Err(KnowledgeError::CrossFamilyRetraction);
                    }
                    let slot = slot_key(&record.subject_key, &record.predicate_key);
                    self.retract_claim(
                        claim_id,
                        proposal.evidence_id,
                        next,
                        &source_revision.envelope,
                        &mut semantic,
                    )?;
                    touched_slots.insert(slot);
                    retracted_claims.push(claim_id);
                }
                KnowledgeProposalAction::OpenQuestion {
                    subject_key,
                    predicate_key,
                    question,
                    reason,
                } => {
                    self.open_questions.push(KnowledgeOpenQuestion {
                        source_id,
                        statement_key: proposal.statement_key,
                        subject_key: subject_key.clone(),
                        predicate_key: predicate_key.clone(),
                        question,
                        reason,
                        evidence_id: proposal.evidence_id,
                        published_at: SnapshotRef { commit_seq: next },
                        envelope: source_revision.envelope.clone(),
                    });
                    touched_slots.insert(slot_key(&subject_key, &predicate_key));
                    open_questions_retained += 1;
                }
            }
        }

        if source_revision.revision_kind == DocumentRevisionKind::RetractDocument {
            let current_claims: Vec<_> = self
                .claims
                .values()
                .filter(|record| record.source_id == source_id)
                .filter_map(|record| {
                    record
                        .revisions
                        .last()
                        .filter(|revision| revision.epistemic.lifecycle == LifecycleState::Active)
                        .map(|_| record.claim.id)
                })
                .collect();
            let document_retraction_evidence = source_revision
                .evidence
                .first()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "document.retraction",
                    reason: "document retraction requires evidence",
                })?
                .id;
            for claim_id in current_claims {
                let record = self
                    .claims
                    .get(&claim_id)
                    .ok_or(KnowledgeError::InvalidInput {
                        field: "knowledge.claim_index",
                        reason: "document claim disappeared during retraction",
                    })?;
                let slot = slot_key(&record.subject_key, &record.predicate_key);
                self.retract_claim(
                    claim_id,
                    document_retraction_evidence,
                    next,
                    &source_revision.envelope,
                    &mut semantic,
                )?;
                touched_slots.insert(slot);
                retracted_claims.push(claim_id);
            }
        }

        for slot in &touched_slots {
            self.rebuild_conflict(slot, next, &source_revision.envelope, &mut semantic)?;
            self.slot_watermarks.insert(slot.clone(), next);
        }
        semantic.add_work();
        semantic.transaction.validate()?;
        self.source_keys
            .insert(source_revision.source_key.clone(), source_id);
        self.sources
            .entry(source_id)
            .or_default()
            .push(source_revision);
        self.workspace_id = Some(semantic.workspace);
        self.commit_seq = next;

        created_claims.sort();
        revised_claims.sort();
        revised_claims.dedup();
        retracted_claims.sort();
        retracted_claims.dedup();
        Ok(KnowledgePublication {
            status: PublicationStatus::Published,
            snapshot: SnapshotRef { commit_seq: next },
            source_id,
            artifact_id,
            created_claims,
            revised_claims,
            retracted_claims,
            hypotheses_retained,
            open_questions_retained,
            semantic_transaction: Some(semantic.transaction),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "canonical source claim construction mirrors the core schema"
    )]
    fn create_source_claim(
        &mut self,
        claim_id: ClaimId,
        source_id: SourceId,
        source_key: String,
        source_family: String,
        statement_key: String,
        subject_key: String,
        predicate_key: String,
        subject: NodeId,
        predicate: &PredicateDefinition,
        object: ClaimObject,
        valid_time: contextdb_core::TimeRange,
        evidence_id: EvidenceId,
        commit: CommitSeq,
        source_trust: contextdb_core::TrustClass,
        source_envelope: &SemanticEnvelope,
        semantic: &mut MutationBuilder,
    ) -> Result<()> {
        let claim = Claim {
            id: claim_id,
            workspace_id: semantic.workspace,
            subject,
            predicate: predicate.id,
            created_seq: commit,
        };
        let envelope = derived_envelope(
            source_envelope,
            LineageNode::ClaimRevision {
                id: claim_id,
                revision: RevisionNumber::FIRST,
            },
            vec![LineageNode::Evidence { id: evidence_id }],
            "claim-create",
        )?;
        let revision = ClaimRevision {
            claim_id,
            revision: RevisionNumber::FIRST,
            object,
            temporal: BitemporalRange {
                valid_time,
                transaction_time: CommitRange::current(commit),
            },
            epistemic: accepted_source_extraction(ConflictState::None, LifecycleState::Active),
            confidence: confidence(1, source_trust),
            source_families: BTreeSet::from([source_family.clone()]),
            evidence: vec![evidence_id],
            supersedes: Vec::new(),
            envelope,
        };
        revision.validate()?;
        contextdb_core::validate_claim_against_predicate(predicate, &NodeType::Concept, &revision)?;
        semantic.transaction.claim_creates.push(claim.clone());
        semantic.transaction.claim_revisions.push(revision.clone());
        semantic.dirty_nodes.insert(subject);
        semantic.dirty_claims.insert(claim_id);
        self.claims.insert(
            claim_id,
            SourceClaimRecord {
                claim,
                source_id,
                source_key,
                source_family,
                statement_key,
                subject_key,
                predicate_key,
                revisions: NonEmptyVec::new(revision),
                revision_reasons: vec![SourceClaimRevisionReason::SourceAdded],
            },
        );
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "source update retains explicit bitemporal inputs"
    )]
    fn append_source_update(
        &mut self,
        claim_id: ClaimId,
        object: ClaimObject,
        valid_time: contextdb_core::TimeRange,
        evidence_id: EvidenceId,
        commit: CommitSeq,
        source_revision: &SourceRevision,
        semantic: &mut MutationBuilder,
    ) -> Result<()> {
        let record = self
            .claims
            .get_mut(&claim_id)
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.claim",
                reason: "source update target disappeared",
            })?;
        let previous = record
            .revisions
            .last()
            .cloned()
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.claim.revisions",
                reason: "claim has no revision",
            })?;
        let next_revision =
            previous
                .revision
                .checked_next()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.claim.revision",
                    reason: "revision sequence exhausted",
                })?;
        close_transaction_head(record, commit)?;
        let temporal_transition =
            previous.object != object && previous.temporal.valid_time.end == Some(valid_time.start);
        let envelope = derived_envelope(
            &source_revision.envelope,
            LineageNode::ClaimRevision {
                id: claim_id,
                revision: next_revision,
            },
            vec![
                LineageNode::Evidence { id: evidence_id },
                LineageNode::ClaimRevision {
                    id: claim_id,
                    revision: previous.revision,
                },
            ],
            "claim-update",
        )?;
        let mut evidence = previous.evidence.clone();
        if !evidence.contains(&evidence_id) {
            evidence.push(evidence_id);
            evidence.sort();
        }
        let revision = ClaimRevision {
            claim_id,
            revision: next_revision,
            object,
            temporal: BitemporalRange {
                valid_time,
                transaction_time: CommitRange::current(commit),
            },
            epistemic: accepted_source_extraction(ConflictState::None, LifecycleState::Active),
            confidence: confidence(1, source_revision.source.trust),
            source_families: BTreeSet::from([record.source_family.clone()]),
            evidence,
            supersedes: Vec::new(),
            envelope,
        };
        revision.validate()?;
        semantic.transaction.claim_revisions.push(revision.clone());
        semantic.dirty_nodes.insert(record.claim.subject);
        semantic.dirty_claims.insert(claim_id);
        record.revisions.push(revision);
        record.revision_reasons.push(if temporal_transition {
            SourceClaimRevisionReason::ExplicitTemporalTransition
        } else {
            SourceClaimRevisionReason::SourceUpdated
        });
        Ok(())
    }

    fn retract_claim(
        &mut self,
        claim_id: ClaimId,
        evidence_id: EvidenceId,
        commit: CommitSeq,
        source_envelope: &SemanticEnvelope,
        semantic: &mut MutationBuilder,
    ) -> Result<()> {
        let record = self
            .claims
            .get_mut(&claim_id)
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.claim",
                reason: "retraction target disappeared",
            })?;
        let previous = record
            .revisions
            .last()
            .cloned()
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.claim.revisions",
                reason: "claim has no revision",
            })?;
        if previous.epistemic.lifecycle == LifecycleState::Retracted {
            return Ok(());
        }
        let next_revision =
            previous
                .revision
                .checked_next()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.claim.revision",
                    reason: "revision sequence exhausted",
                })?;
        close_transaction_head(record, commit)?;
        let envelope = derived_envelope(
            source_envelope,
            LineageNode::ClaimRevision {
                id: claim_id,
                revision: next_revision,
            },
            vec![
                LineageNode::Evidence { id: evidence_id },
                LineageNode::ClaimRevision {
                    id: claim_id,
                    revision: previous.revision,
                },
            ],
            "claim-retract",
        )?;
        let mut evidence = previous.evidence.clone();
        if !evidence.contains(&evidence_id) {
            evidence.push(evidence_id);
            evidence.sort();
        }
        let revision = ClaimRevision {
            claim_id,
            revision: next_revision,
            object: previous.object,
            temporal: BitemporalRange {
                valid_time: previous.temporal.valid_time,
                transaction_time: CommitRange::current(commit),
            },
            epistemic: accepted_source_extraction(ConflictState::None, LifecycleState::Retracted),
            confidence: previous.confidence,
            source_families: previous.source_families,
            evidence,
            supersedes: previous.supersedes,
            envelope,
        };
        revision.validate()?;
        semantic.transaction.claim_revisions.push(revision.clone());
        semantic.dirty_nodes.insert(record.claim.subject);
        semantic.dirty_claims.insert(claim_id);
        record.revisions.push(revision);
        record
            .revision_reasons
            .push(SourceClaimRevisionReason::SourceRetracted);
        Ok(())
    }

    fn ensure_subject(
        &mut self,
        key: &str,
        label: &str,
        commit: CommitSeq,
        evidence_id: EvidenceId,
        source_revision: &SourceRevision,
        semantic: &mut MutationBuilder,
    ) -> Result<NodeId> {
        if let Some(record) = self.nodes.get(key) {
            return Ok(record.node.id);
        }
        let node_id = node_id(semantic.workspace, key);
        let node = Node {
            id: node_id,
            workspace_id: semantic.workspace,
            node_type: NodeType::Concept,
            created_seq: commit,
            retired_seq: None,
            identity_state: IdentityState::Canonical,
            primary_scope: source_revision.envelope.scopes.first().clone(),
        };
        let envelope = derived_envelope(
            &source_revision.envelope,
            LineageNode::NodeRevision {
                id: node_id,
                revision: RevisionNumber::FIRST,
            },
            vec![LineageNode::Evidence { id: evidence_id }],
            "subject-create",
        )?;
        let revision = NodeRevision {
            node_id,
            revision: RevisionNumber::FIRST,
            temporal: BitemporalRange {
                valid_time: contextdb_core::TimeRange::open_ended(contextdb_core::TimestampMicros(
                    0,
                )),
                transaction_time: CommitRange::current(commit),
            },
            canonical_name: label.to_owned(),
            attributes: BTreeMap::from([(
                "knowledge_key".to_owned(),
                serde_json::Value::String(key.to_owned()),
            )]),
            epistemic: EpistemicState {
                basis: EpistemicBasis::DeterministicDerivation,
                acceptance: AcceptanceState::Accepted,
                conflict: ConflictState::None,
                lifecycle: LifecycleState::Active,
            },
            confidence: confidence(1, source_revision.source.trust),
            evidence: vec![evidence_id],
            envelope,
        };
        node.validate()?;
        revision.validate()?;
        semantic.transaction.node_creates.push(node.clone());
        semantic.transaction.node_revisions.push(revision.clone());
        semantic.dirty_nodes.insert(node_id);
        self.nodes.insert(
            key.to_owned(),
            NodeRecord {
                node,
                revisions: NonEmptyVec::new(revision),
            },
        );
        Ok(node_id)
    }

    fn ensure_predicate(&mut self, key: &str, object: &ClaimObject) -> Result<PredicateDefinition> {
        if let Some(predicate) = self.predicates.get(key) {
            if predicate.range != object.value_type() {
                return Err(KnowledgeError::InvalidInput {
                    field: "knowledge.predicate.range",
                    reason: "source claim object differs from registered predicate range",
                });
            }
            return Ok(predicate.clone());
        }
        let predicate = PredicateDefinition {
            id: predicate_id(key),
            name: key.to_owned(),
            domain: BTreeSet::from([NodeType::Concept]),
            range: object.value_type(),
            cardinality: Cardinality::OptionalSingle,
            temporal_mode: TemporalMode::Bitemporal,
            inverse: None,
            transitivity: Transitivity::None,
            conflict_policy: ConflictPolicy::RequireConflictSet,
            default_traversal_weight: 0.5,
            security_propagation: SecurityPropagation::InheritStrictest,
            version: RevisionNumber::FIRST,
        };
        predicate.validate()?;
        self.predicates.insert(key.to_owned(), predicate.clone());
        Ok(predicate)
    }

    fn rebuild_conflict(
        &mut self,
        slot: &str,
        commit: CommitSeq,
        source_envelope: &SemanticEnvelope,
        semantic: &mut MutationBuilder,
    ) -> Result<()> {
        let policy_signature = policy_signature(source_envelope)?;
        let conflict_key = format!("{slot}\0{policy_signature}");
        let candidates: Vec<_> = self
            .claims
            .values()
            .filter(|record| slot_key(&record.subject_key, &record.predicate_key) == slot)
            .filter_map(|record| {
                record
                    .revisions
                    .last()
                    .filter(|revision| {
                        policy_signature_matches(&revision.envelope, &policy_signature)
                    })
                    .filter(|revision| revision.epistemic.lifecycle == LifecycleState::Active)
                    .map(|revision| {
                        (
                            record.claim.id,
                            revision.object.clone(),
                            revision.evidence.clone(),
                            revision.temporal.valid_time,
                        )
                    })
            })
            .collect();
        let mut conflicting_members = BTreeSet::new();
        for (index, left) in candidates.iter().enumerate() {
            for right in &candidates[index + 1..] {
                if left.1 != right.1 && left.3.overlaps(right.3) {
                    conflicting_members.insert(left.0);
                    conflicting_members.insert(right.0);
                }
            }
        }
        let current: Vec<_> = candidates
            .iter()
            .filter(|(claim, _, _, _)| conflicting_members.contains(claim))
            .map(|(claim, object, evidence, _)| (*claim, object.clone(), evidence.clone()))
            .collect();
        let distinct: BTreeSet<_> = current
            .iter()
            .map(|(_, object, _)| object_key(object))
            .collect();
        if distinct.len() < 2 {
            let previous_members: BTreeSet<_> = self
                .conflicts
                .get(&conflict_key)
                .and_then(|record| record.revisions.last())
                .map(|revision| revision.members.iter().copied().collect())
                .unwrap_or_default();
            let remaining: Vec<_> = candidates
                .into_iter()
                .filter(|(claim, _, _, _)| previous_members.contains(claim))
                .collect();
            self.resolve_conflict(&conflict_key, &remaining, commit, source_envelope, semantic)?;
            return Ok(());
        }
        let members: Vec<_> = current.iter().map(|(claim, _, _)| *claim).collect();
        let evidence: BTreeSet<_> = current
            .iter()
            .flat_map(|(_, _, evidence)| evidence.iter().copied())
            .collect();
        let first_record = self
            .claims
            .get(&members[0])
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.conflict",
                reason: "conflict member disappeared",
            })?;
        let id = conflict_id(
            &first_record.subject_key,
            &first_record.predicate_key,
            &policy_signature,
        );
        if let Some(existing) = self.conflicts.get_mut(&conflict_key) {
            let previous =
                existing
                    .revisions
                    .last()
                    .cloned()
                    .ok_or(KnowledgeError::InvalidInput {
                        field: "knowledge.conflict.revisions",
                        reason: "conflict set has no revision",
                    })?;
            close_conflict_head(existing, commit)?;
            let revision_number =
                previous
                    .revision
                    .checked_next()
                    .ok_or(KnowledgeError::InvalidInput {
                        field: "knowledge.conflict.revision",
                        reason: "revision sequence exhausted",
                    })?;
            let envelope = derived_envelope(
                source_envelope,
                LineageNode::ConflictRevision {
                    id,
                    revision: revision_number,
                },
                members
                    .iter()
                    .map(|member| LineageNode::ClaimRevision {
                        id: *member,
                        revision: self
                            .claims
                            .get(member)
                            .and_then(|record| record.revisions.last())
                            .map_or(RevisionNumber::FIRST, |revision| revision.revision),
                    })
                    .collect(),
                "conflict-update",
            )?;
            let revision = ConflictSetRevision {
                conflict_set_id: id,
                revision: revision_number,
                transaction_time: CommitRange::current(commit),
                members: NonEmptyVec::try_from_vec(members.clone(), "knowledge.conflict.members")?,
                resolution: ConflictResolution::Unresolved,
                evidence: evidence.into_iter().collect(),
                envelope,
            };
            revision.validate()?;
            existing.revisions.push(revision.clone());
            semantic.transaction.conflict_revisions.push(revision);
        } else {
            let conflict = ConflictSet {
                id,
                workspace_id: first_record.claim.workspace_id,
                subject: first_record.claim.subject,
                predicate: first_record.claim.predicate,
                scopes: source_envelope.scopes.clone(),
                created_seq: commit,
            };
            let envelope = derived_envelope(
                source_envelope,
                LineageNode::ConflictRevision {
                    id,
                    revision: RevisionNumber::FIRST,
                },
                members
                    .iter()
                    .map(|member| LineageNode::ClaimRevision {
                        id: *member,
                        revision: self
                            .claims
                            .get(member)
                            .and_then(|record| record.revisions.last())
                            .map_or(RevisionNumber::FIRST, |revision| revision.revision),
                    })
                    .collect(),
                "conflict-create",
            )?;
            let revision = ConflictSetRevision {
                conflict_set_id: id,
                revision: RevisionNumber::FIRST,
                transaction_time: CommitRange::current(commit),
                members: NonEmptyVec::try_from_vec(members.clone(), "knowledge.conflict.members")?,
                resolution: ConflictResolution::Unresolved,
                evidence: evidence.into_iter().collect(),
                envelope,
            };
            conflict.validate()?;
            revision.validate()?;
            semantic.transaction.conflict_creates.push(conflict.clone());
            semantic
                .transaction
                .conflict_revisions
                .push(revision.clone());
            self.conflicts.insert(
                conflict_key,
                ConflictSetRecord {
                    conflict,
                    revisions: NonEmptyVec::new(revision),
                },
            );
        }
        for claim_id in members {
            self.mark_claim_conflicted(claim_id, id, commit, semantic)?;
        }
        Ok(())
    }

    fn resolve_conflict(
        &mut self,
        conflict_key: &str,
        current: &[(
            ClaimId,
            ClaimObject,
            Vec<EvidenceId>,
            contextdb_core::TimeRange,
        )],
        commit: CommitSeq,
        source_envelope: &SemanticEnvelope,
        semantic: &mut MutationBuilder,
    ) -> Result<()> {
        let Some(existing_snapshot) = self.conflicts.get(conflict_key).cloned() else {
            return Ok(());
        };
        let previous =
            existing_snapshot
                .revisions
                .last()
                .cloned()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.conflict.revisions",
                    reason: "conflict set has no revision",
                })?;
        let Some(winner) = current.iter().map(|(claim, _, _, _)| *claim).min() else {
            // Core has no automatic "all support retracted" resolution kind.
            // Preserve the historical unresolved record rather than falsely
            // attributing a human adjudication that never happened.
            return Ok(());
        };
        let distinct_objects: BTreeSet<_> = current
            .iter()
            .map(|(_, object, _, _)| object_key(object))
            .collect();
        let resolution = if distinct_objects.len() > 1 {
            ConflictResolution::TemporalTransition
        } else {
            ConflictResolution::WinnerWithDissent { winner }
        };
        let resolved_claims: Vec<_> = if resolution == ConflictResolution::TemporalTransition {
            current.iter().map(|(claim, _, _, _)| *claim).collect()
        } else {
            vec![winner]
        };
        if previous.resolution == resolution {
            return Ok(());
        }
        let revision_number =
            previous
                .revision
                .checked_next()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.conflict.revision",
                    reason: "revision sequence exhausted",
                })?;
        let mut members: Vec<_> = previous.members.iter().copied().collect();
        members.extend(current.iter().map(|(claim, _, _, _)| *claim));
        members.sort();
        members.dedup();
        let mut evidence: BTreeSet<_> = previous.evidence.iter().copied().collect();
        evidence.extend(
            current
                .iter()
                .flat_map(|(_, _, evidence, _)| evidence.iter().copied()),
        );
        let envelope = derived_envelope(
            source_envelope,
            LineageNode::ConflictRevision {
                id: existing_snapshot.conflict.id,
                revision: revision_number,
            },
            members
                .iter()
                .filter_map(|member| {
                    self.claims.get(member).and_then(|record| {
                        record
                            .revisions
                            .last()
                            .map(|revision| LineageNode::ClaimRevision {
                                id: *member,
                                revision: revision.revision,
                            })
                    })
                })
                .collect(),
            "conflict-resolve",
        )?;
        let revision = ConflictSetRevision {
            conflict_set_id: existing_snapshot.conflict.id,
            revision: revision_number,
            transaction_time: CommitRange::current(commit),
            members: NonEmptyVec::try_from_vec(members, "knowledge.conflict.members")?,
            resolution,
            evidence: evidence.into_iter().collect(),
            envelope,
        };
        revision.validate()?;
        let existing =
            self.conflicts
                .get_mut(conflict_key)
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.conflict",
                    reason: "conflict disappeared during resolution",
                })?;
        close_conflict_head(existing, commit)?;
        existing.revisions.push(revision.clone());
        semantic.transaction.conflict_revisions.push(revision);
        for claim in resolved_claims {
            self.mark_claim_resolved(claim, existing_snapshot.conflict.id, commit, semantic)?;
        }
        Ok(())
    }

    fn mark_claim_resolved(
        &mut self,
        claim_id: ClaimId,
        conflict_id: ConflictSetId,
        commit: CommitSeq,
        semantic: &mut MutationBuilder,
    ) -> Result<()> {
        let record = self
            .claims
            .get_mut(&claim_id)
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.conflict.winner",
                reason: "winner claim disappeared",
            })?;
        let previous = record
            .revisions
            .last()
            .cloned()
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.claim.revisions",
                reason: "claim has no revision",
            })?;
        let resolved = ConflictState::Resolved {
            set_id: conflict_id,
        };
        if previous.epistemic.conflict == resolved {
            return Ok(());
        }
        if previous.temporal.transaction_time.start == commit {
            let current = record
                .revisions
                .last_mut()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.claim.revisions",
                    reason: "claim has no revision",
                })?;
            current.epistemic.conflict = resolved;
            let pending = semantic
                .transaction
                .claim_revisions
                .iter_mut()
                .find(|revision| {
                    revision.claim_id == claim_id && revision.revision == current.revision
                })
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.semantic_transaction",
                    reason: "same-commit winner revision is absent",
                })?;
            pending.epistemic.conflict = resolved;
            current.validate()?;
            return Ok(());
        }
        let revision_number =
            previous
                .revision
                .checked_next()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.claim.revision",
                    reason: "revision sequence exhausted",
                })?;
        close_transaction_head(record, commit)?;
        let mut revision = previous;
        revision.revision = revision_number;
        revision.temporal.transaction_time = CommitRange::current(commit);
        revision.epistemic.conflict = resolved;
        revision.envelope = derived_envelope(
            &revision.envelope,
            LineageNode::ClaimRevision {
                id: claim_id,
                revision: revision_number,
            },
            vec![LineageNode::ConflictRevision {
                id: conflict_id,
                revision: self
                    .conflicts
                    .values()
                    .find(|conflict| conflict.conflict.id == conflict_id)
                    .and_then(|conflict| conflict.revisions.last())
                    .map_or(RevisionNumber::FIRST, |revision| revision.revision),
            }],
            "claim-conflict-resolved",
        )?;
        revision.validate()?;
        semantic.transaction.claim_revisions.push(revision.clone());
        semantic.dirty_claims.insert(claim_id);
        record.revisions.push(revision);
        record
            .revision_reasons
            .push(SourceClaimRevisionReason::ConflictResolved);
        Ok(())
    }

    fn mark_claim_conflicted(
        &mut self,
        claim_id: ClaimId,
        conflict_id: ConflictSetId,
        commit: CommitSeq,
        semantic: &mut MutationBuilder,
    ) -> Result<()> {
        let record = self
            .claims
            .get_mut(&claim_id)
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.conflict.member",
                reason: "claim member disappeared",
            })?;
        let previous = record
            .revisions
            .last()
            .cloned()
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.claim.revisions",
                reason: "claim has no revision",
            })?;
        if previous.epistemic.conflict
            == (ConflictState::InConflict {
                set_id: conflict_id,
            })
        {
            return Ok(());
        }
        if previous.temporal.transaction_time.start == commit {
            let current = record
                .revisions
                .last_mut()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.claim.revisions",
                    reason: "claim has no revision",
                })?;
            current.epistemic.conflict = ConflictState::InConflict {
                set_id: conflict_id,
            };
            let pending = semantic
                .transaction
                .claim_revisions
                .iter_mut()
                .find(|revision| {
                    revision.claim_id == claim_id && revision.revision == current.revision
                })
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.semantic_transaction",
                    reason: "same-commit claim revision is absent",
                })?;
            pending.epistemic.conflict = current.epistemic.conflict;
            current.validate()?;
            return Ok(());
        }
        let revision_number =
            previous
                .revision
                .checked_next()
                .ok_or(KnowledgeError::InvalidInput {
                    field: "knowledge.claim.revision",
                    reason: "revision sequence exhausted",
                })?;
        close_transaction_head(record, commit)?;
        let mut revision = previous;
        revision.revision = revision_number;
        revision.temporal.transaction_time = CommitRange::current(commit);
        revision.epistemic.conflict = ConflictState::InConflict {
            set_id: conflict_id,
        };
        revision.envelope = derived_envelope(
            &revision.envelope,
            LineageNode::ClaimRevision {
                id: claim_id,
                revision: revision_number,
            },
            vec![LineageNode::ConflictRevision {
                id: conflict_id,
                revision: self
                    .conflicts
                    .values()
                    .find(|conflict| conflict.conflict.id == conflict_id)
                    .and_then(|conflict| conflict.revisions.last())
                    .map_or(RevisionNumber::FIRST, |revision| revision.revision),
            }],
            "claim-conflict",
        )?;
        revision.validate()?;
        semantic.transaction.claim_revisions.push(revision.clone());
        semantic.dirty_claims.insert(claim_id);
        record.revisions.push(revision);
        record
            .revision_reasons
            .push(SourceClaimRevisionReason::ConflictDetected);
        Ok(())
    }

    fn alternatives(
        &self,
        active: &[(&SourceClaimRecord, &ClaimRevision)],
        query: &KnowledgeQuery,
    ) -> Result<Vec<KnowledgeAlternative>> {
        let mut grouped: BTreeMap<String, Vec<(&SourceClaimRecord, &ClaimRevision)>> =
            BTreeMap::new();
        for (record, revision) in active {
            grouped
                .entry(object_key(&revision.object))
                .or_default()
                .push((*record, *revision));
        }
        let mut alternatives = Vec::new();
        for values in grouped.values() {
            let object = values[0].1.object.clone();
            let valid_time = intersect_ranges(
                values
                    .iter()
                    .map(|(_, revision)| revision.temporal.valid_time),
            )?;
            let claim_ids: BTreeSet<_> = values.iter().map(|(record, _)| record.claim.id).collect();
            let independent_source_families: BTreeSet<_> = values
                .iter()
                .map(|(record, _)| record.source_family.clone())
                .collect();
            let mut citations = Vec::new();
            let mut family_support = BTreeMap::<String, u32>::new();
            for (record, revision) in values {
                family_support
                    .entry(record.source_family.clone())
                    .and_modify(|score| {
                        *score = (*score).max(confidence_micros(revision.confidence));
                    })
                    .or_insert_with(|| confidence_micros(revision.confidence));
                for evidence in &revision.evidence {
                    citations.push(self.citation(
                        record.claim.id,
                        record.source_id,
                        *evidence,
                        query.include_excerpts,
                    )?);
                }
            }
            citations.sort_by_key(|citation| (citation.source_id, citation.evidence_id));
            citations.dedup_by_key(|citation| citation.evidence_id);
            alternatives.push(KnowledgeAlternative {
                object,
                valid_time,
                claim_ids,
                independent_source_families,
                citations,
                confidence_micros: combine_independent_support(family_support.values().copied()),
            });
        }
        alternatives.sort_by_key(|alternative| object_key(&alternative.object));
        Ok(alternatives)
    }

    fn citation(
        &self,
        claim_id: ClaimId,
        source_id: SourceId,
        evidence_id: EvidenceId,
        include_excerpt: bool,
    ) -> Result<KnowledgeCitation> {
        let evidence = self
            .evidence
            .get(&evidence_id)
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.evidence",
                reason: "claim cites unknown evidence",
            })?;
        let revisions = self
            .sources
            .get(&source_id)
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.source",
                reason: "citation source is unknown",
            })?;
        let revision = evidence
            .artifact_id
            .and_then(|artifact| {
                revisions
                    .iter()
                    .find(|revision| revision.artifact.id == artifact)
            })
            .ok_or(KnowledgeError::InvalidInput {
                field: "knowledge.evidence.artifact",
                reason: "evidence artifact is absent from source history",
            })?;
        let revision_lineage = source_lineage(revisions, revision.artifact.id)?;
        Ok(KnowledgeCitation {
            claim_id,
            source_id,
            artifact_id: revision.artifact.id,
            native_locator: revision.source.native_locator.clone(),
            native_revision: revision.native_revision.clone(),
            source_family: revision.source_family.clone(),
            evidence_id,
            selector: evidence.selector.clone(),
            quote_hash: evidence.quote_hash,
            excerpt: include_excerpt
                .then(|| evidence.extracted_text.clone())
                .flatten(),
            trust: evidence.trust,
            revision_lineage,
        })
    }

    fn timeline_entry(
        &self,
        record: &SourceClaimRecord,
        revision: &ClaimRevision,
        reason: SourceClaimRevisionReason,
        query: &KnowledgeQuery,
    ) -> Result<KnowledgeTimelineEntry> {
        let mut citations = revision
            .evidence
            .iter()
            .map(|evidence| {
                self.citation(
                    record.claim.id,
                    record.source_id,
                    *evidence,
                    query.include_excerpts,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        citations.sort_by_key(|citation| (citation.source_id, citation.evidence_id));
        citations.dedup_by_key(|citation| citation.evidence_id);
        Ok(KnowledgeTimelineEntry {
            claim_id: record.claim.id,
            revision: revision.revision,
            object: revision.object.clone(),
            valid_time: revision.temporal.valid_time,
            system_start: revision.temporal.transaction_time.start,
            system_end: revision.temporal.transaction_time.end,
            lifecycle: revision.epistemic.lifecycle,
            reason: match reason {
                SourceClaimRevisionReason::SourceAdded => KnowledgeChangeReason::SourceAdded,
                SourceClaimRevisionReason::SourceUpdated => KnowledgeChangeReason::SourceUpdated,
                SourceClaimRevisionReason::ExplicitTemporalTransition => {
                    KnowledgeChangeReason::ExplicitTemporalTransition
                }
                SourceClaimRevisionReason::SourceRetracted => {
                    KnowledgeChangeReason::SourceRetracted
                }
                SourceClaimRevisionReason::ConflictDetected => {
                    KnowledgeChangeReason::ConflictDetected
                }
                SourceClaimRevisionReason::ConflictResolved => {
                    KnowledgeChangeReason::ConflictResolved
                }
            },
            citations,
        })
    }
}

#[derive(Debug)]
struct MutationBuilder {
    transaction: SemanticMutationSet,
    workspace: contextdb_core::WorkspaceId,
    dirty_nodes: BTreeSet<NodeId>,
    dirty_claims: BTreeSet<ClaimId>,
}

impl MutationBuilder {
    fn new(
        workspace: contextdb_core::WorkspaceId,
        base_snapshot: SnapshotRef,
        observation: contextdb_core::ObservationId,
    ) -> Self {
        Self {
            transaction: SemanticMutationSet {
                id: mutation_id(observation),
                base_snapshot,
                journal_refs: NonEmptyVec::new(observation),
                observation_appends: Vec::new(),
                episode_view_writes: Vec::new(),
                node_creates: Vec::new(),
                node_revisions: Vec::new(),
                claim_creates: Vec::new(),
                claim_revisions: Vec::new(),
                edge_creates: Vec::new(),
                edge_revisions: Vec::new(),
                conflict_creates: Vec::new(),
                conflict_revisions: Vec::new(),
                candidate_writes: Vec::new(),
                typed_memory_writes: Vec::new(),
                derived_work: Vec::new(),
            },
            workspace,
            dirty_nodes: BTreeSet::new(),
            dirty_claims: BTreeSet::new(),
        }
    }

    fn add_work(&mut self) {
        if !self.dirty_nodes.is_empty() || !self.dirty_claims.is_empty() {
            let nodes: Vec<_> = self.dirty_nodes.iter().copied().collect();
            let claims: Vec<_> = self.dirty_claims.iter().copied().collect();
            self.transaction.derived_work = vec![
                DerivedWorkItem::LexicalIndex {
                    node_ids: nodes.clone(),
                    claim_ids: claims,
                },
                DerivedWorkItem::Vectorize {
                    nodes: nodes.clone(),
                },
                DerivedWorkItem::DirtyHierarchyRegion {
                    roots: nodes.clone(),
                },
                DerivedWorkItem::InvalidateSummaries {
                    nodes: nodes.clone(),
                },
                DerivedWorkItem::Consolidate { roots: nodes },
            ];
        }
    }
}

fn intersect_ranges(
    ranges: impl IntoIterator<Item = contextdb_core::TimeRange>,
) -> Result<contextdb_core::TimeRange> {
    let mut ranges = ranges.into_iter();
    let mut intersection = ranges.next().ok_or(KnowledgeError::InvalidInput {
        field: "knowledge.alternative.valid_time",
        reason: "an answer alternative requires at least one temporal support",
    })?;
    for range in ranges {
        intersection.start = intersection.start.max(range.start);
        intersection.end = match (intersection.end, range.end) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None,
        };
    }
    intersection.validate()?;
    Ok(intersection)
}

fn validate_source_revision(revision: &SourceRevision) -> Result<()> {
    revision.source.validate()?;
    revision.artifact.validate()?;
    revision.observation.validate()?;
    revision.envelope.validate()?;
    let content_ids: Vec<_> = revision
        .content_blocks
        .iter()
        .map(|content| content.id)
        .collect();
    if revision.source.id != revision.artifact.source_id
        || revision.source.id != revision.observation.source_id
        || revision.observation.artifact_refs != vec![revision.artifact.id]
        || revision
            .artifact
            .content_blocks
            .iter()
            .copied()
            .collect::<Vec<_>>()
            != content_ids
        || revision.observation.content_block_refs != content_ids
        || revision.artifact.content_hash != revision.content_digest
        || revision.observation.content_hash != revision.content_digest
        || revision.source.content_fingerprint != Some(revision.content_digest)
        || revision.artifact.envelope != revision.envelope
        || revision.observation.envelope != revision.envelope
        || revision
            .observation
            .stream_position
            .as_ref()
            .is_none_or(|position| position.ordinal != u64::from(revision.revision.get()))
    {
        return Err(KnowledgeError::InvalidInput {
            field: "source_revision.identity",
            reason: "source, artifact, observation, envelope, or content identities disagree",
        });
    }
    if revision.content_blocks.is_empty()
        || revision.sections.len() != revision.content_blocks.len()
        || revision
            .hierarchy
            .iter()
            .filter(|entry| entry.kind == crate::SourceHierarchyKind::Corpus)
            .count()
            != 1
        || revision
            .hierarchy
            .iter()
            .filter(|entry| entry.kind == crate::SourceHierarchyKind::Document)
            .count()
            != 1
        || revision
            .hierarchy
            .iter()
            .filter(|entry| entry.kind == crate::SourceHierarchyKind::Revision)
            .count()
            != 1
        || revision
            .hierarchy
            .iter()
            .filter(|entry| entry.kind == crate::SourceHierarchyKind::Section)
            .count()
            != revision.sections.len()
    {
        return Err(KnowledgeError::InvalidInput {
            field: "source_revision.structure",
            reason: "source hierarchy and immutable content blocks are incomplete",
        });
    }
    let mut hierarchy_ids = BTreeSet::new();
    if revision
        .hierarchy
        .iter()
        .any(|entry| !hierarchy_ids.insert(entry.id))
    {
        return Err(KnowledgeError::InvalidInput {
            field: "source_revision.hierarchy",
            reason: "hierarchy IDs must be unique",
        });
    }
    let corpus = revision
        .hierarchy
        .iter()
        .find(|entry| entry.kind == crate::SourceHierarchyKind::Corpus)
        .ok_or(KnowledgeError::InvalidInput {
            field: "source_revision.hierarchy",
            reason: "corpus hierarchy entry is absent",
        })?;
    let document = revision
        .hierarchy
        .iter()
        .find(|entry| entry.kind == crate::SourceHierarchyKind::Document)
        .ok_or(KnowledgeError::InvalidInput {
            field: "source_revision.hierarchy",
            reason: "document hierarchy entry is absent",
        })?;
    let revision_entry = revision
        .hierarchy
        .iter()
        .find(|entry| entry.kind == crate::SourceHierarchyKind::Revision)
        .ok_or(KnowledgeError::InvalidInput {
            field: "source_revision.hierarchy",
            reason: "revision hierarchy entry is absent",
        })?;
    if corpus.parent.is_some()
        || corpus.source_id.is_some()
        || corpus.artifact_id.is_some()
        || document.parent != Some(corpus.id)
        || document.source_id != Some(revision.source.id)
        || document.artifact_id.is_some()
        || revision_entry.parent != Some(document.id)
        || revision_entry.source_id != Some(revision.source.id)
        || revision_entry.artifact_id != Some(revision.artifact.id)
        || revision
            .hierarchy
            .iter()
            .any(|entry| entry.label.trim().is_empty())
        || revision.sections.iter().any(|section| {
            !revision.hierarchy.iter().any(|entry| {
                entry.id == section.id
                    && entry.kind == crate::SourceHierarchyKind::Section
                    && entry.parent == Some(revision_entry.id)
                    && entry.source_id == Some(revision.source.id)
                    && entry.artifact_id == Some(revision.artifact.id)
            })
        })
    {
        return Err(KnowledgeError::InvalidInput {
            field: "source_revision.hierarchy",
            reason: "corpus, document, revision, and section parentage is inconsistent",
        });
    }
    if revision
        .hierarchy
        .iter()
        .filter(|entry| entry.kind == crate::SourceHierarchyKind::Revision)
        .any(|entry| entry.order_key != u64::from(revision.revision.get()))
    {
        return Err(KnowledgeError::InvalidInput {
            field: "source_revision.hierarchy",
            reason: "revision hierarchy order differs from the published source sequence",
        });
    }
    for content in &revision.content_blocks {
        content.validate()?;
    }
    let mut section_ordinals = BTreeSet::new();
    let mut section_paths = BTreeSet::new();
    for section in &revision.sections {
        let Some(content) = revision
            .content_blocks
            .iter()
            .find(|content| content.id == section.content_block_id)
        else {
            return Err(KnowledgeError::InvalidInput {
                field: "source_revision.sections",
                reason: "section refers to an absent content block",
            });
        };
        if !section_ordinals.insert(section.ordinal)
            || !section_paths.insert(section.path.clone())
            || section.path.is_empty()
            || section
                .path
                .iter()
                .any(|component| component.trim().is_empty())
            || section.content_hash != content.content_hash
            || section.content_hash != crate::adapter::digest_bytes(section.content.as_bytes())
            || content.byte_length != section.content.len() as u64
        {
            return Err(KnowledgeError::InvalidInput {
                field: "source_revision.sections",
                reason: "section ordering, path, bytes, or content hash is inconsistent",
            });
        }
    }
    if revision_content_digest(&revision.sections) != revision.content_digest {
        return Err(KnowledgeError::InvalidInput {
            field: "source_revision.content_digest",
            reason: "aggregate content digest differs from immutable section bytes",
        });
    }
    for evidence in &revision.evidence {
        evidence.validate()?;
        let source_section = revision
            .sections
            .iter()
            .find(|section| section.content_block_id == evidence.content_block_id);
        let exact_quote_matches = match (
            source_section,
            &evidence.selector,
            evidence.extracted_text.as_deref(),
        ) {
            (
                Some(section),
                contextdb_core::EvidenceSelector::ByteRange { start, end },
                Some(excerpt),
            ) => usize::try_from(*start)
                .ok()
                .zip(usize::try_from(*end).ok())
                .and_then(|(start, end)| section.content.as_bytes().get(start..end))
                .is_some_and(|bytes| bytes == excerpt.as_bytes()),
            _ => false,
        };
        if evidence.artifact_id != Some(revision.artifact.id)
            || evidence.observation_id != revision.observation.id
            || !content_ids.contains(&evidence.content_block_id)
            || !exact_quote_matches
            || evidence.extracted_text.as_ref().is_some_and(|text| {
                crate::adapter::digest_bytes(text.as_bytes()) != evidence.quote_hash
            })
        {
            return Err(KnowledgeError::InvalidInput {
                field: "source_revision.evidence",
                reason: "evidence lineage or exact quote hash is inconsistent",
            });
        }
    }
    Ok(())
}

fn revision_content_digest(sections: &[crate::DocumentSection]) -> contextdb_core::ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-document-content-v1\0");
    for section in sections {
        for component in &section.path {
            hasher.update(&(component.len() as u64).to_be_bytes());
            hasher.update(component.as_bytes());
        }
        hasher.update(&(section.content.len() as u64).to_be_bytes());
        hasher.update(section.content.as_bytes());
    }
    contextdb_core::ContentDigest::from_bytes(*hasher.finalize().as_bytes())
}

fn validate_claim_record(record: &SourceClaimRecord) -> Result<()> {
    record.claim.validate()?;
    if record.revisions.len() != record.revision_reasons.len() {
        return Err(KnowledgeError::InvalidInput {
            field: "knowledge_export.claim.reasons",
            reason: "revision reason count differs from revision count",
        });
    }
    if record
        .revisions
        .iter()
        .any(|revision| revision.claim_id != record.claim.id)
    {
        return Err(KnowledgeError::InvalidInput {
            field: "knowledge_export.claim.revisions",
            reason: "revision belongs to another claim",
        });
    }
    contextdb_core::validate_revision_chain(&record.revisions)?;
    Ok(())
}

fn validate_query(query: &KnowledgeQuery) -> Result<()> {
    if query.subject_key.trim().is_empty()
        || query.predicate_key.trim().is_empty()
        || query.subject_key.contains('\0')
        || query.predicate_key.contains('\0')
    {
        return Err(KnowledgeError::InvalidInput {
            field: "knowledge_query.slot",
            reason: "subject and predicate keys must not be blank or contain NUL",
        });
    }
    if let SourceConstraint::Family { family } = &query.source
        && (family.trim().is_empty() || family.contains('\0'))
    {
        return Err(KnowledgeError::InvalidInput {
            field: "knowledge_query.source.family",
            reason: "must not be blank or contain NUL",
        });
    }
    query.principal.validate()?;
    Ok(())
}

fn source_matches(constraint: &SourceConstraint, revision: &SourceRevision) -> bool {
    match constraint {
        SourceConstraint::AnyAuthorized => true,
        SourceConstraint::Source { id } => id == &revision.source.id,
        SourceConstraint::Family { family } => family == &revision.source_family,
    }
}

fn principal_allows(principal: &RecallPrincipal, revision: &SourceRevision) -> bool {
    principal_allows_envelope(principal, revision.source.workspace_id, &revision.envelope)
}

fn principal_allows_envelope(
    principal: &RecallPrincipal,
    workspace: contextdb_core::WorkspaceId,
    envelope: &SemanticEnvelope,
) -> bool {
    let access = access_rule(workspace, envelope);
    principal.allows(&access)
}

fn access_rule(
    workspace: contextdb_core::WorkspaceId,
    envelope: &SemanticEnvelope,
) -> contextdb_recall::AccessRule {
    let owners: BTreeSet<_> = envelope
        .ownership
        .owners
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut grants: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for grant in &envelope.ownership.audience_grants {
        if !grant
            .capabilities
            .contains(&contextdb_core::AccessCapability::Retrieve)
        {
            continue;
        }
        let key = match &grant.audience {
            contextdb_core::Audience::Public => "*".to_owned(),
            contextdb_core::Audience::Owner => "@owner".to_owned(),
            contextdb_core::Audience::Subject { id } | contextdb_core::Audience::Group { id } => {
                id.to_string()
            }
            contextdb_core::Audience::MemorySpace { id } => id.to_string(),
        };
        grants
            .entry(key)
            .or_default()
            .extend(grant.purposes.iter().map(contextdb_recall::purpose_key));
    }
    let consent = if !envelope.consent.required
        || envelope
            .consent
            .decisions
            .iter()
            .all(|decision| decision.status == contextdb_core::ConsentStatus::Granted)
    {
        contextdb_recall::AccessConsent::Granted
    } else if envelope
        .consent
        .decisions
        .iter()
        .any(|decision| decision.status == contextdb_core::ConsentStatus::Denied)
    {
        contextdb_recall::AccessConsent::Denied
    } else {
        contextdb_recall::AccessConsent::Unknown
    };
    contextdb_recall::AccessRule {
        workspace: workspace.to_string(),
        scopes: envelope
            .scopes
            .iter()
            .map(|scope| scope.id.to_string())
            .collect(),
        owners,
        audience_purpose_grants: grants,
        sensitivity: envelope.security.classification.into(),
        required_compartments: envelope
            .security
            .required_compartments
            .iter()
            .map(ToString::to_string)
            .collect(),
        consent,
        retrievable: envelope.use_policy.retrieve == contextdb_core::PolicyDecision::Allow,
    }
}

fn close_transaction_head(record: &mut SourceClaimRecord, at: CommitSeq) -> Result<()> {
    let current = record
        .revisions
        .last_mut()
        .ok_or(KnowledgeError::InvalidInput {
            field: "knowledge.claim.revisions",
            reason: "claim has no revision",
        })?;
    current.temporal.transaction_time.end = Some(at);
    current.temporal.transaction_time.validate()?;
    Ok(())
}

fn close_conflict_head(record: &mut ConflictSetRecord, at: CommitSeq) -> Result<()> {
    let current = record
        .revisions
        .last_mut()
        .ok_or(KnowledgeError::InvalidInput {
            field: "knowledge.conflict.revisions",
            reason: "conflict has no revision",
        })?;
    current.transaction_time.end = Some(at);
    current.transaction_time.validate()?;
    Ok(())
}

fn accepted_source_extraction(
    conflict: ConflictState,
    lifecycle: LifecycleState,
) -> EpistemicState {
    EpistemicState {
        // The source is an assertion, but this canonical claim is a deterministic
        // projection of an immutable document span. Calling it an actor assertion
        // would incorrectly require the projector itself to be the asserting actor.
        basis: EpistemicBasis::DeterministicDerivation,
        acceptance: AcceptanceState::Accepted,
        conflict,
        lifecycle,
    }
}

fn confidence(
    independent_families: usize,
    source_trust: contextdb_core::TrustClass,
) -> ConfidenceProfile {
    let trust = match source_trust {
        contextdb_core::TrustClass::Untrusted => 0.20,
        contextdb_core::TrustClass::Unknown => 0.35,
        contextdb_core::TrustClass::SelfAsserted => 0.55,
        contextdb_core::TrustClass::Authenticated => 0.75,
        contextdb_core::TrustClass::Verified => 0.90,
    };
    let corroboration = match independent_families {
        0 | 1 => 0.35,
        2 => 0.70,
        _ => 0.85,
    };
    ConfidenceProfile {
        overall: (0.45_f32 * trust + 0.30 + 0.25 * corroboration).min(0.99),
        source_trust: trust,
        extraction_quality: 1.0,
        corroboration,
    }
}

fn confidence_micros(confidence: ConfidenceProfile) -> u32 {
    (f64::from(confidence.overall) * 1_000_000.0).round() as u32
}

fn combine_independent_support(scores: impl IntoIterator<Item = u32>) -> u32 {
    let mut remaining = 1_000_000_u64;
    for score in scores {
        remaining =
            remaining.saturating_mul(1_000_000_u64.saturating_sub(u64::from(score))) / 1_000_000;
    }
    u32::try_from(1_000_000_u64.saturating_sub(remaining).min(999_999)).unwrap_or(999_999)
}

fn derived_envelope(
    source: &SemanticEnvelope,
    target: LineageNode,
    inputs: Vec<LineageNode>,
    stage: &str,
) -> Result<SemanticEnvelope> {
    let mut envelope = source.clone();
    envelope.derivation = contextdb_core::DerivationRef {
        id: DerivationId::from_uuid(deterministic_uuid(&[
            b"knowledge-derivation",
            stage.as_bytes(),
            serde_json::to_string(&target)
                .map_err(|error| KnowledgeError::Serialization(error.to_string()))?
                .as_bytes(),
        ]))?,
        kind: DerivationKind::DeterministicProjector,
        actor: None,
        model_call: None,
        pipeline: contextdb_core::PipelineIdentity {
            name: "contextdb-knowledge".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            schema_version: "1".to_owned(),
        },
        inputs,
    };
    envelope.validate_derived_from(source)?;
    envelope.validate_for_target(&target)?;
    Ok(envelope)
}

fn source_lineage(
    revisions: &[SourceRevision],
    target: contextdb_core::ArtifactId,
) -> Result<Vec<contextdb_core::ArtifactId>> {
    let by_id: BTreeMap<_, _> = revisions
        .iter()
        .map(|revision| (revision.artifact.id, revision))
        .collect();
    let mut lineage = Vec::new();
    let mut cursor = Some(target);
    let mut seen = BTreeSet::new();
    while let Some(artifact) = cursor {
        if !seen.insert(artifact) {
            return Err(KnowledgeError::InvalidInput {
                field: "source_revision.lineage",
                reason: "artifact ancestry contains a cycle",
            });
        }
        lineage.push(artifact);
        cursor = by_id
            .get(&artifact)
            .and_then(|revision| revision.supersedes);
    }
    lineage.reverse();
    Ok(lineage)
}

fn slot_key(subject: &str, predicate: &str) -> String {
    format!("{subject}\0{predicate}")
}

fn object_key(object: &ClaimObject) -> String {
    serde_json::to_string(object).unwrap_or_else(|_| "<unserializable>".to_owned())
}

fn node_id(workspace: contextdb_core::WorkspaceId, key: &str) -> NodeId {
    NodeId::from_uuid(deterministic_uuid(&[
        b"knowledge-node",
        workspace.as_uuid().as_bytes(),
        key.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn predicate_id(key: &str) -> PredicateId {
    PredicateId::from_uuid(deterministic_uuid(&[
        b"knowledge-predicate",
        key.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn claim_id(source: SourceId, statement: &str) -> ClaimId {
    ClaimId::from_uuid(deterministic_uuid(&[
        b"knowledge-claim",
        source.as_uuid().as_bytes(),
        statement.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn conflict_id(subject: &str, predicate: &str, policy_signature: &str) -> ConflictSetId {
    ConflictSetId::from_uuid(deterministic_uuid(&[
        b"knowledge-conflict",
        subject.as_bytes(),
        predicate.as_bytes(),
        policy_signature.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn answer_conflict_id(alternatives: &[KnowledgeAlternative]) -> ConflictSetId {
    let mut claim_ids: Vec<_> = alternatives
        .iter()
        .flat_map(|alternative| alternative.claim_ids.iter().copied())
        .collect();
    claim_ids.sort();
    claim_ids.dedup();
    let encoded: Vec<_> = claim_ids
        .iter()
        .flat_map(|claim| claim.as_uuid().as_bytes().to_vec())
        .collect();
    ConflictSetId::from_uuid(deterministic_uuid(&[
        b"knowledge-answer-conflict",
        &encoded,
    ]))
    .expect("deterministic UUID is non-nil")
}

fn policy_signature(envelope: &SemanticEnvelope) -> Result<String> {
    let value = serde_json::json!({
        "scopes": envelope.scopes,
        "ownership": envelope.ownership,
        "consent": envelope.consent,
        "use_policy": envelope.use_policy,
        "security": envelope.security,
    });
    let bytes = serde_json::to_vec(&value)
        .map_err(|error| KnowledgeError::Serialization(error.to_string()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn policy_signature_matches(envelope: &SemanticEnvelope, expected: &str) -> bool {
    policy_signature(envelope).is_ok_and(|actual| actual == expected)
}

fn mutation_id(observation: contextdb_core::ObservationId) -> MutationId {
    MutationId::from_uuid(deterministic_uuid(&[
        b"knowledge-mutation",
        observation.as_uuid().as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}
