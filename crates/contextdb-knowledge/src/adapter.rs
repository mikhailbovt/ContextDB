//! Generic document adapter with exact evidence alignment.

use std::collections::BTreeSet;

use contextdb_cognition::{
    CandidateProposal, EntityMention, EvidenceCitation, ProposalBody, ProposedValue,
    TemporalProposal,
};
use contextdb_core::{
    Artifact, ArtifactId, BlobLocator, Compression, ContentBlock, ContentBlockId, ContentDigest,
    ContentEncoding, DerivationId, DerivationKind, EvidenceId, EvidenceSelector, EvidenceSpan,
    LineageNode, Modality, NodeId, NodeType, NonEmptyVec, ObservationId, ObservationUnit,
    RevisionNumber, Source, SourceId, SourceKind, StreamId, StreamPosition, Validate,
};
use uuid::Uuid;

use crate::{
    AdaptedDocument, DocumentFormat, DocumentRevisionInput, DocumentRevisionKind,
    DocumentStatementAction, KnowledgeError, KnowledgeProposal, KnowledgeProposalAction, Result,
    SourceHierarchyEntry, SourceHierarchyKind, SourceRevision, StatementEpistemic,
};

/// Bounded generic adapter limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DocumentAdapterConfig {
    pub max_sections: usize,
    pub max_statements: usize,
    pub max_section_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for DocumentAdapterConfig {
    fn default() -> Self {
        Self {
            max_sections: 4_096,
            max_statements: 16_384,
            max_section_bytes: 4 * 1_024 * 1_024,
            max_total_bytes: 128 * 1_024 * 1_024,
        }
    }
}

impl DocumentAdapterConfig {
    /// Rejects unbounded or nonsensical adapter configurations.
    pub fn validate(self) -> Result<Self> {
        if self.max_sections == 0
            || self.max_statements == 0
            || self.max_section_bytes == 0
            || self.max_total_bytes == 0
            || self.max_section_bytes > self.max_total_bytes
        {
            return Err(KnowledgeError::InvalidInput {
                field: "document_adapter.config",
                reason: "limits must be positive and internally consistent",
            });
        }
        Ok(self)
    }
}

/// Deterministic adapter. It creates immutable source material and strict M10
/// proposals but never publishes semantic truth itself.
#[derive(Clone, Debug)]
pub struct GenericDocumentAdapter {
    config: DocumentAdapterConfig,
}

impl GenericDocumentAdapter {
    /// Creates an adapter after validating bounded-input limits.
    pub fn new(config: DocumentAdapterConfig) -> Result<Self> {
        Ok(Self {
            config: config.validate()?,
        })
    }

    /// Converts one generic revision into an immutable artifact and exact
    /// evidence-backed semantic proposals.
    pub fn adapt(&self, input: &DocumentRevisionInput) -> Result<AdaptedDocument> {
        validate_input(input, self.config)?;
        let logical_digest = logical_digest(input)?;
        let source_id = source_id(input.workspace_id, &input.source_key);
        let artifact_id = source_artifact_id(source_id, &input.native_revision);
        let observation_id = observation_id(artifact_id);
        let stream_id = stream_id(source_id);
        // The adapter cannot know the ledger-local sequence. Publication
        // replaces this provisional first revision atomically.
        let revision = RevisionNumber::FIRST;
        let content_digest = content_digest(input);
        if input
            .expected_content_hash
            .is_some_and(|expected| expected != content_digest)
        {
            return Err(KnowledgeError::InvalidInput {
                field: "document.expected_content_hash",
                reason: "expected digest does not match normalized section content",
            });
        }

        let source = Source {
            id: source_id,
            workspace_id: input.workspace_id,
            kind: SourceKind::Document,
            native_locator: input.native_locator.clone(),
            owner_actor: Some(input.actor_id),
            owner_subject: Some(input.envelope.ownership.owners.first().to_owned()),
            trust: input.trust,
            ingestion_policy: input.ingestion_policy,
            content_fingerprint: Some(content_digest),
        };
        source.validate()?;

        let mut content_blocks = Vec::new();
        let mut sections = Vec::new();
        let mut evidence = Vec::new();
        let mut proposals = Vec::new();
        let mut content_block_ids = Vec::new();
        let mut statement_keys = BTreeSet::new();
        let corpus_node = hierarchy_id(input.workspace_id, "corpus", &input.corpus_key, "stable");
        let document_node =
            hierarchy_id(input.workspace_id, "document", &input.source_key, "stable");
        let revision_node = hierarchy_id(
            input.workspace_id,
            "revision",
            &input.source_key,
            &input.native_revision,
        );
        let mut hierarchy = vec![
            SourceHierarchyEntry {
                id: corpus_node,
                parent: None,
                kind: SourceHierarchyKind::Corpus,
                order_key: 0,
                label: input.corpus_key.clone(),
                source_id: None,
                artifact_id: None,
            },
            SourceHierarchyEntry {
                id: document_node,
                parent: Some(corpus_node),
                kind: SourceHierarchyKind::Document,
                order_key: 0,
                label: input.title.clone(),
                source_id: Some(source_id),
                artifact_id: None,
            },
            SourceHierarchyEntry {
                id: revision_node,
                parent: Some(document_node),
                kind: SourceHierarchyKind::Revision,
                order_key: u64::from(revision.get()),
                label: input.native_revision.clone(),
                source_id: Some(source_id),
                artifact_id: Some(artifact_id),
            },
        ];

        for (section_index, section) in input.sections.iter().enumerate() {
            let ordinal =
                u32::try_from(section_index + 1).map_err(|_| KnowledgeError::InvalidInput {
                    field: "document.sections",
                    reason: "section ordinal exceeds u32",
                })?;
            let content_hash = digest_bytes(section.content.as_bytes());
            let block_id = content_block_id(artifact_id, ordinal);
            let section_id = hierarchy_id(
                input.workspace_id,
                "section",
                &input.source_key,
                &format!("{}:{ordinal}", input.native_revision),
            );
            content_block_ids.push(block_id);
            let content_block = ContentBlock {
                id: block_id,
                media_type: media_type(input.format.clone()).to_owned(),
                encoding: ContentEncoding::Utf8,
                compression: Compression::None,
                byte_length: section.content.len() as u64,
                blob_locator: BlobLocator(format!(
                    "contextdb://source/{source_id}/artifact/{artifact_id}/section/{ordinal}"
                )),
                content_hash,
            };
            content_block.validate()?;
            content_blocks.push(content_block);
            sections.push(crate::DocumentSection {
                id: section_id,
                ordinal,
                path: section.path.clone(),
                content: section.content.clone(),
                content_block_id: block_id,
                content_hash,
            });
            hierarchy.push(SourceHierarchyEntry {
                id: section_id,
                parent: Some(revision_node),
                kind: SourceHierarchyKind::Section,
                order_key: u64::from(ordinal),
                label: section_label(section, ordinal),
                source_id: Some(source_id),
                artifact_id: Some(artifact_id),
            });

            for statement in &section.statements {
                if !statement_keys.insert(statement.statement_key.clone()) {
                    return Err(KnowledgeError::InvalidInput {
                        field: "document.statement_key",
                        reason: "statement keys must be unique within a source revision",
                    });
                }
                let (start, end) = unique_quote_range(&section.content, &statement.quote)
                    .ok_or_else(|| KnowledgeError::HallucinatedCitation {
                        statement: statement.statement_key.clone(),
                        section: section_label(section, ordinal),
                    })?;
                let evidence_id = evidence_id(artifact_id, &statement.statement_key);
                let mut evidence_derivation = input.envelope.derivation.clone();
                evidence_derivation.id = derivation_id(evidence_id, "evidence");
                evidence_derivation.kind = DerivationKind::DeterministicProjector;
                evidence_derivation.model_call = None;
                evidence_derivation.inputs = vec![LineageNode::Artifact { id: artifact_id }];
                let span = EvidenceSpan {
                    id: evidence_id,
                    observation_id,
                    artifact_id: Some(artifact_id),
                    content_block_id: block_id,
                    selector: EvidenceSelector::ByteRange {
                        start: start as u64,
                        end: end as u64,
                    },
                    quote_hash: digest_bytes(statement.quote.as_bytes()),
                    extracted_text: Some(statement.quote.clone()),
                    trust: input.trust,
                    derivation: Some(evidence_derivation),
                };
                span.validate()?;
                evidence.push(span);
                let action = proposal_action(statement, evidence_id)?;
                proposals.push(KnowledgeProposal {
                    local_id: format!("{}:{}", input.source_key, statement.statement_key),
                    statement_key: statement.statement_key.clone(),
                    section_id,
                    evidence_id,
                    action,
                });
            }
        }

        let artifact = Artifact {
            id: artifact_id,
            source_id,
            modality: Modality::Text,
            media_type: media_type(input.format.clone()).to_owned(),
            native_locator: Some(input.native_locator.clone()),
            content_blocks: NonEmptyVec::try_from_vec(
                content_block_ids.clone(),
                "document.content_blocks",
            )?,
            content_hash: content_digest,
            created_at: input.created_at,
            ingested_at: input.recorded_at,
            envelope: input.envelope.clone(),
        };
        artifact.validate()?;
        let observation = ObservationUnit {
            id: observation_id,
            workspace_id: input.workspace_id,
            memory_spaces: NonEmptyVec::new(input.memory_space_id),
            source_id,
            stream_position: Some(StreamPosition {
                stream_id,
                ordinal: u64::from(revision.get()),
                native_revision: Some(input.native_revision.clone()),
                wall_time: Some(input.observed_at),
            }),
            participants: NonEmptyVec::new(input.actor_id),
            occurred_at: contextdb_core::TimeRange::open_ended(input.effective_at),
            observed_at: input.observed_at,
            recorded_at: input.recorded_at,
            artifact_refs: vec![artifact_id],
            content_block_refs: content_block_ids,
            content_hash: content_digest,
            envelope: input.envelope.clone(),
        };
        observation.validate()?;
        hierarchy.sort_by_key(|entry| (entry.kind, entry.order_key, entry.id));
        proposals.sort_by(|left, right| left.local_id.cmp(&right.local_id));

        Ok(AdaptedDocument {
            source_revision: SourceRevision {
                published_at: contextdb_core::SnapshotRef {
                    commit_seq: contextdb_core::CommitSeq::GENESIS,
                },
                source,
                source_key: input.source_key.clone(),
                corpus_key: input.corpus_key.clone(),
                source_family: input.source_family.clone(),
                revision,
                native_revision: input.native_revision.clone(),
                supersedes: input
                    .supersedes_native_revision
                    .as_ref()
                    .map(|parent| source_artifact_id(source_id, parent)),
                content_digest,
                logical_digest,
                artifact,
                content_blocks,
                observation,
                sections,
                evidence,
                hierarchy,
                envelope: input.envelope.clone(),
                revision_kind: input.revision_kind,
            },
            proposals,
        })
    }
}

fn validate_input(input: &DocumentRevisionInput, config: DocumentAdapterConfig) -> Result<()> {
    for (field, value) in [
        ("document.corpus_key", input.corpus_key.as_str()),
        ("document.source_key", input.source_key.as_str()),
        ("document.source_family", input.source_family.as_str()),
        ("document.native_locator", input.native_locator.as_str()),
        ("document.native_revision", input.native_revision.as_str()),
        ("document.title", input.title.as_str()),
    ] {
        if value.trim().is_empty() || value.contains('\0') {
            return Err(KnowledgeError::InvalidInput {
                field,
                reason: "must not be blank or contain NUL",
            });
        }
    }
    if matches!(&input.format, DocumentFormat::Other(label) if label.trim().is_empty())
        || input
            .supersedes_native_revision
            .as_ref()
            .is_some_and(|parent| parent.trim().is_empty() || parent == &input.native_revision)
    {
        return Err(KnowledgeError::InvalidInput {
            field: "document.revision_metadata",
            reason: "custom format and parent revision metadata must be non-blank and acyclic",
        });
    }
    if input.observed_at > input.recorded_at
        || input
            .created_at
            .is_some_and(|created| created > input.recorded_at)
    {
        return Err(KnowledgeError::InvalidInput {
            field: "document.timestamps",
            reason: "observation and creation cannot occur after recording",
        });
    }
    input.envelope.validate()?;
    if input.sections.is_empty() || input.sections.len() > config.max_sections {
        return Err(KnowledgeError::InvalidInput {
            field: "document.sections",
            reason: "section count is outside configured bounds",
        });
    }
    let mut total_bytes = 0_usize;
    let mut total_statements = 0_usize;
    let mut paths = BTreeSet::new();
    for section in &input.sections {
        if section.path.is_empty()
            || section
                .path
                .iter()
                .any(|part| part.trim().is_empty() || part.contains('\0'))
            || section.content.is_empty()
        {
            return Err(KnowledgeError::InvalidInput {
                field: "document.section",
                reason: "path and content must be non-empty",
            });
        }
        if !paths.insert(section.path.clone()) {
            return Err(KnowledgeError::InvalidInput {
                field: "document.section.path",
                reason: "section paths must be unique within a revision",
            });
        }
        if section.content.len() > config.max_section_bytes {
            return Err(KnowledgeError::InvalidInput {
                field: "document.section.content",
                reason: "section exceeds configured byte limit",
            });
        }
        total_bytes = total_bytes.saturating_add(section.content.len());
        total_statements = total_statements.saturating_add(section.statements.len());
        for statement in &section.statements {
            for (field, value) in [
                ("statement.key", statement.statement_key.as_str()),
                ("statement.subject_key", statement.subject_key.as_str()),
                ("statement.subject_label", statement.subject_label.as_str()),
                ("statement.predicate_key", statement.predicate_key.as_str()),
                ("statement.quote", statement.quote.as_str()),
            ] {
                if value.trim().is_empty() || value.contains('\0') {
                    return Err(KnowledgeError::InvalidInput {
                        field,
                        reason: "must not be blank or contain NUL",
                    });
                }
            }
        }
    }
    if total_bytes > config.max_total_bytes || total_statements > config.max_statements {
        return Err(KnowledgeError::InvalidInput {
            field: "document",
            reason: "document exceeds configured aggregate bounds",
        });
    }
    if input.revision_kind == DocumentRevisionKind::RetractDocument
        && (total_statements == 0
            || input.sections.iter().any(|section| {
                section.statements.iter().any(|statement| {
                    !matches!(statement.action, DocumentStatementAction::Retract { .. })
                })
            }))
    {
        return Err(KnowledgeError::InvalidInput {
            field: "document.revision_kind",
            reason: "a document retraction may only carry explicit retraction statements",
        });
    }
    Ok(())
}

fn proposal_action(
    statement: &crate::DocumentStatementInput,
    evidence_id: EvidenceId,
) -> Result<KnowledgeProposalAction> {
    let citation = EvidenceCitation {
        evidence_id,
        quote_hash: digest_bytes(statement.quote.as_bytes()),
    };
    Ok(match &statement.action {
        DocumentStatementAction::Assert {
            object,
            valid_time,
            epistemic,
        } => {
            object.validate()?;
            valid_time.validate()?;
            if let StatementEpistemic::DerivedHypothesis {
                supporting_evidence,
            } = epistemic
                && (supporting_evidence.is_empty()
                    || supporting_evidence.iter().collect::<BTreeSet<_>>().len()
                        != supporting_evidence.len())
            {
                return Err(KnowledgeError::InvalidInput {
                    field: "statement.epistemic.supporting_evidence",
                    reason: "a hypothesis requires unique independent support references",
                });
            }
            let mention = EntityMention {
                local_ref: "subject".to_owned(),
                surface: statement.subject_label.clone(),
                expected_type: NodeType::Concept,
                canonical_key: Some(statement.subject_key.clone()),
                external_key: None,
                sensitive: false,
            };
            let cognition_candidate = CandidateProposal {
                local_id: statement.statement_key.clone(),
                mentions: vec![mention],
                body: ProposalBody::Claim {
                    subject_ref: "subject".to_owned(),
                    predicate_ref: statement.predicate_key.clone(),
                    object: proposed_value(object)?,
                },
                evidence: vec![citation],
                temporal: Some(TemporalProposal {
                    valid_from: Some(valid_time.start),
                    valid_to: valid_time.end,
                    change_hint: None,
                }),
                extraction_confidence: if matches!(epistemic, StatementEpistemic::SourceAssertion) {
                    1.0
                } else {
                    0.5
                },
            };
            KnowledgeProposalAction::Assert {
                subject_key: statement.subject_key.clone(),
                subject_label: statement.subject_label.clone(),
                predicate_key: statement.predicate_key.clone(),
                object: object.clone(),
                valid_time: *valid_time,
                epistemic: epistemic.clone(),
                cognition_candidate: Box::new(cognition_candidate),
            }
        }
        DocumentStatementAction::Retract { target, reason } => {
            if reason.trim().is_empty()
                || target.source_key.trim().is_empty()
                || target.statement_key.trim().is_empty()
                || target.source_key.contains('\0')
                || target.statement_key.contains('\0')
            {
                return Err(KnowledgeError::InvalidInput {
                    field: "statement.retraction",
                    reason: "target and reason must be non-blank and contain no NUL",
                });
            }
            KnowledgeProposalAction::Retract {
                target: target.clone(),
                reason: reason.clone(),
            }
        }
        DocumentStatementAction::OpenQuestion { question, reason } => {
            if question.trim().is_empty() || reason.trim().is_empty() {
                return Err(KnowledgeError::InvalidInput {
                    field: "statement.open_question",
                    reason: "question and reason must not be blank",
                });
            }
            KnowledgeProposalAction::OpenQuestion {
                subject_key: statement.subject_key.clone(),
                predicate_key: statement.predicate_key.clone(),
                question: question.clone(),
                reason: reason.clone(),
            }
        }
    })
}

fn proposed_value(value: &contextdb_core::ClaimObject) -> Result<ProposedValue> {
    Ok(match value {
        contextdb_core::ClaimObject::String(value) => ProposedValue::String(value.clone()),
        contextdb_core::ClaimObject::Integer(value) => ProposedValue::Integer(*value),
        contextdb_core::ClaimObject::Float(value) => ProposedValue::Float(*value),
        contextdb_core::ClaimObject::Boolean(value) => ProposedValue::Boolean(*value),
        contextdb_core::ClaimObject::Timestamp(value) => ProposedValue::Timestamp(*value),
        contextdb_core::ClaimObject::Structured(value) => ProposedValue::Structured(value.clone()),
        contextdb_core::ClaimObject::Uri(value) => ProposedValue::String(value.clone()),
        contextdb_core::ClaimObject::Quantity { value, unit } => {
            ProposedValue::Structured(serde_json::json!({ "value": value, "unit": unit }))
        }
        contextdb_core::ClaimObject::TimeRange(value) => ProposedValue::Structured(
            serde_json::to_value(value)
                .map_err(|error| KnowledgeError::Serialization(error.to_string()))?,
        ),
        contextdb_core::ClaimObject::Node(_) | contextdb_core::ClaimObject::CodeLocation { .. } => {
            return Err(KnowledgeError::InvalidInput {
                field: "statement.object",
                reason: "generic document claim objects cannot contain canonical node/code IDs",
            });
        }
    })
}

fn content_digest(input: &DocumentRevisionInput) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-document-content-v1\0");
    for section in &input.sections {
        for component in &section.path {
            update_part(&mut hasher, component.as_bytes());
        }
        update_part(&mut hasher, section.content.as_bytes());
    }
    ContentDigest::from_bytes(*hasher.finalize().as_bytes())
}

fn logical_digest(input: &DocumentRevisionInput) -> Result<ContentDigest> {
    let bytes = serde_json::to_vec(input)
        .map_err(|error| KnowledgeError::Serialization(error.to_string()))?;
    Ok(digest_bytes(&bytes))
}

fn unique_quote_range(content: &str, quote: &str) -> Option<(usize, usize)> {
    let mut matches = content.match_indices(quote);
    let (start, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some((start, start + quote.len()))
}

fn section_label(section: &crate::DocumentSectionInput, ordinal: u32) -> String {
    section
        .path
        .last()
        .cloned()
        .unwrap_or_else(|| format!("section-{ordinal}"))
}

fn media_type(format: DocumentFormat) -> &'static str {
    match format {
        DocumentFormat::PlainText => "text/plain",
        DocumentFormat::Markdown => "text/markdown",
        DocumentFormat::PdfExtractedText => "application/pdf+text",
        DocumentFormat::HtmlExtractedText => "text/html+extracted",
        DocumentFormat::Json => "application/json",
        DocumentFormat::Csv => "text/csv",
        DocumentFormat::Other(_) => "application/octet-stream",
    }
}

fn source_id(workspace: contextdb_core::WorkspaceId, source_key: &str) -> SourceId {
    SourceId::from_uuid(deterministic_uuid(&[
        b"source",
        workspace.as_uuid().as_bytes(),
        source_key.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn source_artifact_id(source: SourceId, native_revision: &str) -> ArtifactId {
    ArtifactId::from_uuid(deterministic_uuid(&[
        b"artifact",
        source.as_uuid().as_bytes(),
        native_revision.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn content_block_id(artifact: ArtifactId, ordinal: u32) -> ContentBlockId {
    ContentBlockId::from_uuid(deterministic_uuid(&[
        b"content-block",
        artifact.as_uuid().as_bytes(),
        &ordinal.to_be_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn observation_id(artifact: ArtifactId) -> ObservationId {
    ObservationId::from_uuid(deterministic_uuid(&[
        b"observation",
        artifact.as_uuid().as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn stream_id(source: SourceId) -> StreamId {
    StreamId::from_uuid(deterministic_uuid(&[
        b"stream",
        source.as_uuid().as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn evidence_id(artifact: ArtifactId, statement_key: &str) -> EvidenceId {
    EvidenceId::from_uuid(deterministic_uuid(&[
        b"evidence",
        artifact.as_uuid().as_bytes(),
        statement_key.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn derivation_id(evidence: EvidenceId, label: &str) -> DerivationId {
    DerivationId::from_uuid(deterministic_uuid(&[
        b"derivation",
        evidence.as_uuid().as_bytes(),
        label.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

fn hierarchy_id(
    workspace: contextdb_core::WorkspaceId,
    kind: &str,
    source_key: &str,
    local_key: &str,
) -> NodeId {
    NodeId::from_uuid(deterministic_uuid(&[
        b"knowledge-hierarchy",
        workspace.as_uuid().as_bytes(),
        kind.as_bytes(),
        source_key.as_bytes(),
        local_key.as_bytes(),
    ]))
    .expect("deterministic UUID is non-nil")
}

pub(crate) fn deterministic_uuid(parts: &[&[u8]]) -> Uuid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-knowledge-id-v1\0");
    for part in parts {
        update_part(&mut hasher, part);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    if bytes == [0_u8; 16] {
        bytes[15] = 1;
    }
    Uuid::from_bytes(bytes)
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn update_part(hasher: &mut blake3::Hasher, part: &[u8]) {
    hasher.update(&(part.len() as u64).to_be_bytes());
    hasher.update(part);
}
