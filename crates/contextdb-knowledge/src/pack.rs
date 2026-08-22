//! Model-neutral knowledge ContextPack adapter.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::{
    BlockId, BlockRepresentation, CandidateUsePolicy, CompressionLevel, ConflictDescriptor,
    ConflictResolution, ContentTaint, ContentTrust, DisclosureRule, EvidenceHandle,
    EvidenceSelector, InMemoryContextProvider, InstructionCapability, InterpretationRule,
    PackBlockKind, PackCandidate, PackEvidence, ProviderCandidate, ProviderEvidence, SourceClass,
    SourceHandle, SupportState, UnknownDescriptor,
};
use contextdb_core::{
    AcceptanceState, ConflictState, EpistemicBasis, EpistemicState, LifecycleState, MemoryRef,
    PolicyDecision, TrustClass, Validate,
};
use contextdb_recall::{
    AccessConsent, AccessRule, ProviderSnapshot, RecallPrincipal, RecallWatermarks,
};

use crate::{
    KnowledgeAnswerState, KnowledgeCitation, KnowledgeLedger, KnowledgeQuery, KnowledgeQueryResult,
    Result,
};

/// Query result paired with a policy-first provider suitable for
/// `contextdb_context::ContextCompiler` using the same principal and snapshot.
#[derive(Clone, Debug)]
pub struct KnowledgeContextMaterial {
    pub result: KnowledgeQueryResult,
    pub provider: InMemoryContextProvider,
}

/// Deterministic knowledge-to-ContextPack boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct KnowledgeContextAdapter;

impl KnowledgeContextAdapter {
    /// Executes the authorized temporal query first, then exposes only that
    /// result through a provider locked to the same principal.
    pub fn prepare(
        ledger: &KnowledgeLedger,
        query: &KnowledgeQuery,
    ) -> Result<KnowledgeContextMaterial> {
        let result = ledger.query(query)?;
        let snapshot = provider_snapshot(&result);
        let access = bound_access(&query.principal);
        let mut candidates = vec![situation_candidate(&result, &access)?];
        let mut evidence = BTreeMap::<EvidenceHandle, ProviderEvidence>::new();

        match &result.state {
            KnowledgeAnswerState::Supported { answer } => {
                candidates.push(fact_candidate(
                    &result,
                    answer,
                    None,
                    &access,
                    ledger,
                    &mut evidence,
                )?);
            }
            KnowledgeAnswerState::Disputed {
                conflict_set_id,
                canonical_conflict,
                alternatives,
            } => {
                for alternative in alternatives {
                    candidates.push(fact_candidate(
                        &result,
                        alternative,
                        Some(*conflict_set_id),
                        &access,
                        ledger,
                        &mut evidence,
                    )?);
                }
                candidates.push(conflict_candidate(
                    &result,
                    *conflict_set_id,
                    *canonical_conflict,
                    alternatives,
                    &access,
                    ledger,
                    &mut evidence,
                )?);
            }
            KnowledgeAnswerState::Unknown {
                reason,
                searched_sources,
                open_questions,
            } => candidates.push(unknown_candidate(
                &result,
                *reason,
                searched_sources,
                open_questions,
                &access,
                ledger,
            )?),
        }

        for entry in &result.history {
            candidates.push(history_candidate(
                &result,
                entry,
                &access,
                ledger,
                &mut evidence,
            )?);
        }
        candidates.sort_by(|left, right| left.candidate.id.cmp(&right.candidate.id));
        let provider =
            InMemoryContextProvider::new(snapshot, candidates, evidence.into_values().collect())?;
        Ok(KnowledgeContextMaterial { result, provider })
    }
}

fn situation_candidate(
    result: &KnowledgeQueryResult,
    access: &AccessRule,
) -> Result<ProviderCandidate> {
    Ok(ProviderCandidate {
        access: access.clone(),
        use_policy: CandidateUsePolicy {
            influence: PolicyDecision::Allow,
            mention: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Allow,
            disclosure: DisclosureRule::MayMention,
        },
        candidate: PackCandidate {
            id: BlockId::new(format!(
                "knowledge:situation:{}:{}:{}:{}",
                result.subject_key,
                result.predicate_key,
                result.valid_at.0,
                result.snapshot.commit_seq.get()
            ))?,
            kind: PackBlockKind::Situation,
            representations: vec![BlockRepresentation {
                level: CompressionLevel::L0Orientation,
                summary: format!(
                    "Resolve {} {} at valid time {} using knowledge available at commit {}",
                    result.subject_key,
                    result.predicate_key,
                    result.valid_at.0,
                    result.snapshot.commit_seq
                ),
                fields: BTreeMap::from([
                    ("subject".to_owned(), result.subject_key.clone()),
                    ("predicate".to_owned(), result.predicate_key.clone()),
                    ("valid_at".to_owned(), result.valid_at.0.to_string()),
                    (
                        "known_at".to_owned(),
                        result.snapshot.commit_seq.to_string(),
                    ),
                ]),
                omitted_facets: BTreeSet::new(),
            }],
            exact_fragments: Vec::new(),
            memory_refs: Vec::new(),
            claim_ids: BTreeSet::new(),
            evidence_handles: BTreeSet::new(),
            facets: BTreeSet::from([
                result.subject_key.clone(),
                result.predicate_key.clone(),
                "knowledge_query".to_owned(),
            ]),
            scopes: access.scopes.clone(),
            valid_time: None,
            known_at_commit: result.snapshot.commit_seq.get(),
            perspective: None,
            epistemic: EpistemicState {
                basis: EpistemicBasis::DeterministicDerivation,
                acceptance: AcceptanceState::Validated,
                conflict: ConflictState::None,
                lifecycle: LifecycleState::Active,
            },
            confidence_micros: 1_000_000,
            trust: ContentTrust::TrustedSource,
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::DeterministicDerivation,
            taints: BTreeSet::new(),
            interpretation: InterpretationRule::FactualData,
            support: SupportState::Supported,
            conflict: None,
            unknown: None,
            utility_micros: 1_000_000,
            mandatory: true,
        },
    })
}

fn fact_candidate(
    result: &KnowledgeQueryResult,
    alternative: &crate::KnowledgeAlternative,
    conflict: Option<contextdb_core::ConflictSetId>,
    access: &AccessRule,
    ledger: &KnowledgeLedger,
    evidence: &mut BTreeMap<EvidenceHandle, ProviderEvidence>,
) -> Result<ProviderCandidate> {
    add_evidence(
        &alternative.citations,
        result.snapshot,
        access,
        ledger,
        evidence,
    )?;
    let evidence_handles = evidence_handles(&alternative.citations)?;
    let perspective = perspective_for(&alternative.citations, ledger);
    let mut fields = BTreeMap::from([
        ("subject".to_owned(), result.subject_key.clone()),
        ("predicate".to_owned(), result.predicate_key.clone()),
        ("object".to_owned(), object_text(&alternative.object)?),
        (
            "independent_source_families".to_owned(),
            alternative.independent_source_families.len().to_string(),
        ),
    ]);
    if conflict.is_some() {
        fields.insert("status".to_owned(), "disputed".to_owned());
    }
    Ok(ProviderCandidate {
        access: access.clone(),
        use_policy: use_policy(&alternative.citations, result.snapshot, ledger),
        candidate: PackCandidate {
            id: BlockId::new(format!(
                "knowledge:fact:{}:{}:{}",
                result.subject_key,
                result.predicate_key,
                stable_object_digest(&alternative.object)?
            ))?,
            kind: PackBlockKind::Fact,
            representations: vec![BlockRepresentation {
                level: CompressionLevel::L2Structured,
                summary: format!(
                    "{} {} {}",
                    result.subject_key,
                    result.predicate_key,
                    object_text(&alternative.object)?
                ),
                fields,
                omitted_facets: BTreeSet::new(),
            }],
            exact_fragments: Vec::new(),
            memory_refs: alternative
                .claim_ids
                .iter()
                .map(|id| MemoryRef::Claim { id: *id })
                .collect(),
            claim_ids: alternative.claim_ids.clone(),
            evidence_handles,
            facets: BTreeSet::from([
                result.subject_key.clone(),
                result.predicate_key.clone(),
                "current_knowledge".to_owned(),
            ]),
            scopes: access.scopes.clone(),
            valid_time: Some(alternative.valid_time),
            known_at_commit: result.snapshot.commit_seq.get(),
            perspective,
            epistemic: EpistemicState {
                basis: EpistemicBasis::DeterministicDerivation,
                acceptance: AcceptanceState::Accepted,
                conflict: conflict.map_or(ConflictState::None, |set_id| {
                    ConflictState::InConflict { set_id }
                }),
                lifecycle: LifecycleState::Active,
            },
            confidence_micros: alternative.confidence_micros,
            trust: aggregate_trust(&alternative.citations),
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::ExternalDocument,
            taints: document_taints(),
            interpretation: InterpretationRule::FactualData,
            support: SupportState::Supported,
            conflict: None,
            unknown: None,
            utility_micros: 900_000,
            mandatory: true,
        },
    })
}

fn conflict_candidate(
    result: &KnowledgeQueryResult,
    conflict_set_id: contextdb_core::ConflictSetId,
    canonical_conflict: bool,
    alternatives: &[crate::KnowledgeAlternative],
    access: &AccessRule,
    ledger: &KnowledgeLedger,
    evidence: &mut BTreeMap<EvidenceHandle, ProviderEvidence>,
) -> Result<ProviderCandidate> {
    let citations: Vec<_> = alternatives
        .iter()
        .flat_map(|alternative| alternative.citations.iter().cloned())
        .collect();
    add_evidence(&citations, result.snapshot, access, ledger, evidence)?;
    let claim_ids: BTreeSet<_> = alternatives
        .iter()
        .flat_map(|alternative| alternative.claim_ids.iter().copied())
        .collect();
    let values = alternatives
        .iter()
        .map(|alternative| object_text(&alternative.object))
        .collect::<Result<Vec<_>>>()?;
    Ok(ProviderCandidate {
        access: access.clone(),
        use_policy: use_policy(&citations, result.snapshot, ledger),
        candidate: PackCandidate {
            id: BlockId::new(format!("knowledge:conflict:{conflict_set_id}"))?,
            kind: PackBlockKind::Conflict,
            representations: vec![BlockRepresentation {
                level: CompressionLevel::L2Structured,
                summary: format!(
                    "Authorized sources disagree about {} {}",
                    result.subject_key, result.predicate_key
                ),
                fields: BTreeMap::from([
                    ("status".to_owned(), "unresolved".to_owned()),
                    ("alternatives".to_owned(), values.join(" | ")),
                ]),
                omitted_facets: BTreeSet::new(),
            }],
            exact_fragments: Vec::new(),
            memory_refs: if canonical_conflict {
                std::iter::once(MemoryRef::ConflictSet {
                    id: conflict_set_id,
                })
                .chain(claim_ids.iter().map(|id| MemoryRef::Claim { id: *id }))
                .collect()
            } else {
                claim_ids
                    .iter()
                    .map(|id| MemoryRef::Claim { id: *id })
                    .collect()
            },
            claim_ids: claim_ids.clone(),
            evidence_handles: evidence_handles(&citations)?,
            facets: BTreeSet::from([
                result.subject_key.clone(),
                result.predicate_key.clone(),
                "source_disagreement".to_owned(),
            ]),
            scopes: access.scopes.clone(),
            valid_time: Some(intersect_alternative_ranges(alternatives)?),
            known_at_commit: result.snapshot.commit_seq.get(),
            perspective: perspective_for(&citations, ledger),
            epistemic: EpistemicState {
                basis: EpistemicBasis::DeterministicDerivation,
                acceptance: AcceptanceState::Accepted,
                conflict: ConflictState::InConflict {
                    set_id: conflict_set_id,
                },
                lifecycle: LifecycleState::Active,
            },
            confidence_micros: alternatives
                .iter()
                .map(|alternative| alternative.confidence_micros)
                .min()
                .unwrap_or(0),
            trust: aggregate_trust(&citations),
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::ExternalDocument,
            taints: document_taints(),
            interpretation: InterpretationRule::ConflictAlternatives,
            support: SupportState::Supported,
            conflict: Some(ConflictDescriptor {
                set_id: conflict_set_id,
                alternatives: claim_ids,
                resolution: ConflictResolution::Unresolved,
                blocking: true,
            }),
            unknown: None,
            utility_micros: 1_000_000,
            mandatory: true,
        },
    })
}

fn intersect_alternative_ranges(
    alternatives: &[crate::KnowledgeAlternative],
) -> Result<contextdb_core::TimeRange> {
    let mut alternatives = alternatives.iter();
    let mut intersection = alternatives
        .next()
        .ok_or(crate::KnowledgeError::InvalidInput {
            field: "knowledge_context.conflict",
            reason: "a conflict requires at least one alternative",
        })?
        .valid_time;
    for alternative in alternatives {
        intersection.start = intersection.start.max(alternative.valid_time.start);
        intersection.end = match (intersection.end, alternative.valid_time.end) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None,
        };
    }
    intersection.validate()?;
    Ok(intersection)
}

fn unknown_candidate(
    result: &KnowledgeQueryResult,
    reason: crate::UnknownReason,
    searched_sources: &[contextdb_core::SourceId],
    open_questions: &[String],
    access: &AccessRule,
    ledger: &KnowledgeLedger,
) -> Result<ProviderCandidate> {
    let reason_text = format!("{reason:?}").to_lowercase();
    Ok(ProviderCandidate {
        access: access.clone(),
        use_policy: use_policy_for_sources(searched_sources, result.snapshot, ledger),
        candidate: PackCandidate {
            id: BlockId::new(format!(
                "knowledge:unknown:{}:{}",
                result.subject_key, result.predicate_key
            ))?,
            kind: PackBlockKind::Unknown,
            representations: vec![BlockRepresentation {
                level: CompressionLevel::L1Summary,
                summary: format!(
                    "Unknown: {} {} ({reason_text})",
                    result.subject_key, result.predicate_key
                ),
                fields: BTreeMap::from([
                    ("reason".to_owned(), reason_text.clone()),
                    (
                        "searched_source_count".to_owned(),
                        searched_sources.len().to_string(),
                    ),
                ]),
                omitted_facets: BTreeSet::new(),
            }],
            exact_fragments: Vec::new(),
            memory_refs: Vec::new(),
            claim_ids: BTreeSet::new(),
            evidence_handles: BTreeSet::new(),
            facets: BTreeSet::from([
                result.subject_key.clone(),
                result.predicate_key.clone(),
                "unknown".to_owned(),
            ]),
            scopes: access.scopes.clone(),
            valid_time: None,
            known_at_commit: result.snapshot.commit_seq.get(),
            perspective: None,
            epistemic: EpistemicState {
                // ContextPack's unsupported-state contract deliberately models
                // an unknown marker as hypothesis-shaped, never as accepted fact.
                basis: EpistemicBasis::Hypothesis,
                acceptance: AcceptanceState::Validated,
                conflict: ConflictState::None,
                lifecycle: LifecycleState::Active,
            },
            confidence_micros: 1_000_000,
            trust: ContentTrust::TrustedSource,
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::DeterministicDerivation,
            taints: BTreeSet::new(),
            interpretation: InterpretationRule::UnknownMarker,
            support: SupportState::Unsupported {
                reason: reason_text.clone(),
            },
            conflict: None,
            unknown: Some(UnknownDescriptor {
                question: open_questions.first().cloned().unwrap_or_else(|| {
                    format!("What is {} {}?", result.subject_key, result.predicate_key)
                }),
                reason: reason_text,
                blocking: true,
            }),
            utility_micros: 1_000_000,
            mandatory: true,
        },
    })
}

fn history_candidate(
    result: &KnowledgeQueryResult,
    entry: &crate::KnowledgeTimelineEntry,
    access: &AccessRule,
    ledger: &KnowledgeLedger,
    evidence: &mut BTreeMap<EvidenceHandle, ProviderEvidence>,
) -> Result<ProviderCandidate> {
    add_evidence(&entry.citations, result.snapshot, access, ledger, evidence)?;
    Ok(ProviderCandidate {
        access: access.clone(),
        use_policy: use_policy(&entry.citations, result.snapshot, ledger),
        candidate: PackCandidate {
            id: BlockId::new(format!(
                "knowledge:history:{}:{}",
                entry.claim_id,
                entry.revision.get()
            ))?,
            kind: PackBlockKind::Timeline,
            representations: vec![BlockRepresentation {
                level: CompressionLevel::L2Structured,
                summary: format!(
                    "Historical source state: {} {} {}",
                    result.subject_key,
                    result.predicate_key,
                    object_text(&entry.object)?
                ),
                fields: BTreeMap::from([
                    (
                        "change".to_owned(),
                        format!("{:?}", entry.reason).to_lowercase(),
                    ),
                    (
                        "source_lifecycle".to_owned(),
                        format!("{:?}", entry.lifecycle).to_lowercase(),
                    ),
                    ("system_start".to_owned(), entry.system_start.to_string()),
                ]),
                omitted_facets: BTreeSet::new(),
            }],
            exact_fragments: Vec::new(),
            memory_refs: vec![MemoryRef::Claim { id: entry.claim_id }],
            claim_ids: BTreeSet::from([entry.claim_id]),
            evidence_handles: evidence_handles(&entry.citations)?,
            facets: BTreeSet::from([
                result.subject_key.clone(),
                result.predicate_key.clone(),
                "knowledge_history".to_owned(),
            ]),
            scopes: access.scopes.clone(),
            valid_time: Some(entry.valid_time),
            known_at_commit: entry.system_start.get(),
            perspective: perspective_for(&entry.citations, ledger),
            epistemic: EpistemicState {
                basis: EpistemicBasis::DeterministicDerivation,
                acceptance: AcceptanceState::Accepted,
                conflict: ConflictState::None,
                lifecycle: LifecycleState::Historical,
            },
            confidence_micros: 800_000,
            trust: aggregate_trust(&entry.citations),
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::ExternalDocument,
            taints: document_taints(),
            interpretation: InterpretationRule::HistoricalData,
            support: SupportState::Supported,
            conflict: None,
            unknown: None,
            utility_micros: 700_000,
            mandatory: true,
        },
    })
}

fn add_evidence(
    citations: &[KnowledgeCitation],
    snapshot: contextdb_core::SnapshotRef,
    access: &AccessRule,
    ledger: &KnowledgeLedger,
    output: &mut BTreeMap<EvidenceHandle, ProviderEvidence>,
) -> Result<()> {
    for citation in citations {
        let handle = evidence_handle(citation.evidence_id)?;
        if output.contains_key(&handle) {
            continue;
        }
        let source_policy = ledger
            .source_revision_at(citation.source_id, snapshot)
            .ok_or(crate::KnowledgeError::InvalidInput {
                field: "knowledge_context.source",
                reason: "citation source has no policy at the query snapshot",
            })?;
        let artifact_policy = ledger
            .source_revision_for_artifact(citation.source_id, citation.artifact_id)
            .ok_or(crate::KnowledgeError::InvalidInput {
                field: "knowledge_context.source",
                reason: "citation artifact has no immutable source revision",
            })?;
        let source = source_handle(citation.artifact_id)?;
        let lineage = citation
            .revision_lineage
            .iter()
            .copied()
            .filter(|artifact| artifact != &citation.artifact_id)
            .map(source_handle)
            .collect::<Result<Vec<_>>>()?;
        output.insert(
            handle.clone(),
            ProviderEvidence {
                access: access.clone(),
                external_model_use: strictest_decision([
                    external_decision(artifact_policy),
                    external_decision(source_policy),
                ]),
                evidence: PackEvidence {
                    id: handle,
                    source,
                    selector: selector(&citation.selector),
                    excerpt: citation.excerpt.clone(),
                    claim_ids: BTreeSet::from([citation.claim_id]),
                    provenance_family: citation.source_family.clone(),
                    primary: true,
                    trust_micros: trust_micros(citation.trust),
                    source_class: SourceClass::ExternalDocument,
                    taints: document_taints(),
                    lineage,
                },
            },
        );
    }
    Ok(())
}

fn evidence_handles(citations: &[KnowledgeCitation]) -> Result<BTreeSet<EvidenceHandle>> {
    citations
        .iter()
        .map(|citation| evidence_handle(citation.evidence_id))
        .collect()
}

fn evidence_handle(id: contextdb_core::EvidenceId) -> Result<EvidenceHandle> {
    Ok(EvidenceHandle::new(format!("evidence:{id}"))?)
}

fn source_handle(id: contextdb_core::ArtifactId) -> Result<SourceHandle> {
    Ok(SourceHandle::new(format!("artifact:{id}"))?)
}

fn perspective_for(
    citations: &[KnowledgeCitation],
    ledger: &KnowledgeLedger,
) -> Option<contextdb_core::Perspective> {
    citations
        .first()
        .and_then(|citation| {
            ledger.source_revision_for_artifact(citation.source_id, citation.artifact_id)
        })
        .map(|revision| revision.envelope.perspective.clone())
}

fn use_policy(
    citations: &[KnowledgeCitation],
    snapshot: contextdb_core::SnapshotRef,
    ledger: &KnowledgeLedger,
) -> CandidateUsePolicy {
    let mut revisions = Vec::new();
    for citation in citations {
        if let Some(revision) =
            ledger.source_revision_for_artifact(citation.source_id, citation.artifact_id)
        {
            revisions.push(revision);
        }
        if let Some(revision) = ledger.source_revision_at(citation.source_id, snapshot) {
            revisions.push(revision);
        }
    }
    aggregate_use_policy(&revisions)
}

fn use_policy_for_sources(
    sources: &[contextdb_core::SourceId],
    snapshot: contextdb_core::SnapshotRef,
    ledger: &KnowledgeLedger,
) -> CandidateUsePolicy {
    let revisions: Vec<_> = sources
        .iter()
        .flat_map(|source| ledger.source_revisions_through(*source, snapshot))
        .collect();
    aggregate_use_policy(&revisions)
}

fn aggregate_use_policy(revisions: &[&crate::SourceRevision]) -> CandidateUsePolicy {
    let influence = strictest_decision(
        revisions
            .iter()
            .map(|revision| revision.envelope.use_policy.influence_response),
    );
    let mention = strictest_decision(
        revisions
            .iter()
            .map(|revision| revision.envelope.use_policy.mention_explicitly),
    );
    let external_model_use =
        strictest_decision(revisions.iter().map(|revision| external_decision(revision)));
    CandidateUsePolicy {
        influence,
        mention,
        external_model_use,
        disclosure: match mention {
            PolicyDecision::Allow => DisclosureRule::MayMention,
            PolicyDecision::Conditional => DisclosureRule::MentionOnlyWhenExplicit,
            PolicyDecision::Deny => DisclosureRule::DoNotDisclose,
        },
    }
}

fn strictest_decision(decisions: impl IntoIterator<Item = PolicyDecision>) -> PolicyDecision {
    let mut saw_any = false;
    let mut result = PolicyDecision::Allow;
    for decision in decisions {
        saw_any = true;
        match decision {
            PolicyDecision::Deny => return PolicyDecision::Deny,
            PolicyDecision::Conditional => result = PolicyDecision::Conditional,
            PolicyDecision::Allow => {}
        }
    }
    if saw_any {
        result
    } else {
        PolicyDecision::Allow
    }
}

fn external_decision(revision: &crate::SourceRevision) -> PolicyDecision {
    if revision.envelope.security.allow_external_processing {
        revision.envelope.use_policy.external_model_use
    } else {
        PolicyDecision::Deny
    }
}

fn selector(selector: &contextdb_core::EvidenceSelector) -> EvidenceSelector {
    match selector {
        contextdb_core::EvidenceSelector::ByteRange { start, end }
        | contextdb_core::EvidenceSelector::CharacterRange { start, end } => {
            EvidenceSelector::TextBytes {
                start: *start,
                end: *end,
            }
        }
        contextdb_core::EvidenceSelector::LineRange {
            start_line,
            end_line,
            ..
        } => EvidenceSelector::Lines {
            start: u64::from(*start_line),
            end: u64::from(*end_line),
        },
        contextdb_core::EvidenceSelector::JsonPointer { pointer }
        | contextdb_core::EvidenceSelector::ToolResultField {
            json_pointer: pointer,
        } => EvidenceSelector::JsonPointer {
            pointer: pointer.clone(),
        },
        contextdb_core::EvidenceSelector::MediaTimeRange {
            start_millis,
            end_millis,
        }
        | contextdb_core::EvidenceSelector::SpeakerSegment {
            start_millis,
            end_millis,
            ..
        } => EvidenceSelector::TimeMicros {
            start: start_millis.saturating_mul(1_000),
            end: end_millis.saturating_mul(1_000),
        },
        contextdb_core::EvidenceSelector::Whole
        | contextdb_core::EvidenceSelector::DocumentHeading { .. }
        | contextdb_core::EvidenceSelector::AstNode { .. }
        | contextdb_core::EvidenceSelector::GitDiffHunk { .. }
        | contextdb_core::EvidenceSelector::ImageRegion { .. }
        | contextdb_core::EvidenceSelector::SensorInterval { .. } => EvidenceSelector::Whole,
    }
}

fn aggregate_trust(citations: &[KnowledgeCitation]) -> ContentTrust {
    if citations
        .iter()
        .all(|citation| citation.trust >= TrustClass::Authenticated)
    {
        ContentTrust::TrustedSource
    } else if citations
        .iter()
        .any(|citation| citation.trust == TrustClass::Untrusted)
    {
        ContentTrust::Untrusted
    } else {
        ContentTrust::Mixed
    }
}

const fn trust_micros(trust: TrustClass) -> u32 {
    match trust {
        TrustClass::Untrusted => 100_000,
        TrustClass::Unknown => 300_000,
        TrustClass::SelfAsserted => 550_000,
        TrustClass::Authenticated => 800_000,
        TrustClass::Verified => 950_000,
    }
}

fn document_taints() -> BTreeSet<ContentTaint> {
    BTreeSet::from([
        ContentTaint::ExternalContent,
        ContentTaint::UntrustedInstructions,
    ])
}

fn bound_access(principal: &RecallPrincipal) -> AccessRule {
    AccessRule {
        workspace: principal.workspace.clone(),
        scopes: principal.scopes.clone(),
        owners: BTreeSet::from([principal.subject.clone()]),
        audience_purpose_grants: BTreeMap::from([(
            principal.subject.clone(),
            BTreeSet::from([principal.purpose.clone()]),
        )]),
        sensitivity: principal.clearance,
        required_compartments: BTreeSet::new(),
        consent: AccessConsent::Granted,
        retrievable: true,
    }
}

fn provider_snapshot(result: &KnowledgeQueryResult) -> ProviderSnapshot {
    let commit = result.snapshot.commit_seq.get();
    ProviderSnapshot {
        database_id: "contextdb:knowledge".to_owned(),
        commit_seq: commit,
        watermarks: RecallWatermarks {
            journal: commit,
            semantic: commit,
            lexical: 0,
            vector: BTreeMap::new(),
            graph: 0,
            hierarchy: BTreeMap::from([("knowledge-source".to_owned(), commit)]),
        },
    }
}

fn object_text(object: &contextdb_core::ClaimObject) -> Result<String> {
    serde_json::to_string(object)
        .map_err(|error| crate::KnowledgeError::Serialization(error.to_string()))
}

fn stable_object_digest(object: &contextdb_core::ClaimObject) -> Result<String> {
    Ok(blake3::hash(object_text(object)?.as_bytes())
        .to_hex()
        .to_string())
}
