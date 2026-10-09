//! Fixed public originals. Evaluation never crosses into the provider/scorer.

use super::*;
use contextdb_core::{
    AcceptanceState, ActorId, ClaimId, ConflictSetId, ConflictState, ContextPackId, EpistemicBasis,
    EpistemicRole, EpistemicState, LifecycleState, MemorySubjectId, OriginalSourceSpan,
    Perspective, PolicyDecision, TemporalConstraint,
};
use contextdb_recall::{
    AccessConsent, AccessRule, ProviderSnapshot, RecallPrincipal, RecallSensitivity,
    RecallWatermarks,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Scenario {
    EarlyCode,
    CorrectedCode,
    LocalConstraint,
    Complement,
    MultiMemory,
    NoMemory,
    EnglishCode,
    ResidentCode,
    HardAlternative,
    MandatoryConflictUnknown,
    ToolIndirect,
    PartialResident,
}
pub(super) const SCENARIOS: [Scenario; 12] = [
    Scenario::EarlyCode,
    Scenario::CorrectedCode,
    Scenario::LocalConstraint,
    Scenario::Complement,
    Scenario::MultiMemory,
    Scenario::NoMemory,
    Scenario::EnglishCode,
    Scenario::ResidentCode,
    Scenario::HardAlternative,
    Scenario::MandatoryConflictUnknown,
    Scenario::ToolIndirect,
    Scenario::PartialResident,
];

pub(super) struct Original {
    pub(super) span: OriginalSourceSpan,
    pub(super) text: String,
    pub(super) known_at: u64,
}
pub(super) struct Case {
    pub(super) id: String,
    pub(super) domain: String,
    pub(super) known_at: u64,
    pub(super) request: CompileAssemblyRequest,
    pub(super) provider: Provider,
    pub(super) oracle: targets::Oracle,
    pub(super) exploration: collector::Exploration,
    pub(super) originals: BTreeMap<ObservationId, Original>,
    #[cfg(test)]
    pub(super) source_ids: BTreeMap<String, BlockId>,
}

pub(super) fn domain(group: u32) -> String {
    format!("synthetic:conditional-domain:{group}")
}

pub(super) fn build_case(group: u32, scenario: Scenario, budget: &mut QueryBudget) -> Result<Case> {
    if group >= 4 {
        return Err(invalid());
    }
    let id = format!("group-{group}-{scenario:?}");
    let domain = domain(group);
    let offset = u64::from(group) * 100;
    let at = match scenario {
        Scenario::CorrectedCode
        | Scenario::LocalConstraint
        | Scenario::MandatoryConflictUnknown => 4,
        Scenario::ToolIndirect => 5,
        _ => 3,
    };
    let known_at = offset + at;
    let entity = ["Atlas", "Boreal", "Cygnus", "Delta"][group as usize];
    let code = (7319 + group * 37).to_string();
    let corrected = (8426 + group * 41).to_string();
    let query = match scenario {
        Scenario::EarlyCode => "Какой код Atlas?",
        Scenario::CorrectedCode => "Какой код Atlas сейчас?",
        Scenario::LocalConstraint => "Можно ли хранить Atlas в облаке?",
        Scenario::Complement | Scenario::MultiMemory | Scenario::HardAlternative => {
            "Назови исходный код Atlas и правило хранения."
        }
        Scenario::NoMemory => "Напиши слово: привет.",
        Scenario::EnglishCode => "What was the original Atlas safe code?",
        Scenario::ResidentCode | Scenario::PartialResident => {
            "Повтори исходный код Atlas из текущего окна."
        }
        Scenario::MandatoryConflictUnknown => {
            "Какой из противоречащих кодов Atlas подтверждён владельцем?"
        }
        Scenario::ToolIndirect => "Продолжи настройку Atlas с учётом результата проверки.",
    }
    .replace("Atlas", entity);
    let scope = format!("synthetic:conditional-scope:{group}");
    let access = AccessRule {
        workspace: format!("synthetic:conditional-workspace:{group}"),
        scopes: BTreeSet::from([scope.clone()]),
        owners: BTreeSet::from(["synthetic:owner".into()]),
        audience_purpose_grants: BTreeMap::from([(
            "@owner".into(),
            BTreeSet::from(["conversation".into()]),
        )]),
        sensitivity: RecallSensitivity::Internal,
        required_compartments: BTreeSet::new(),
        consent: AccessConsent::Granted,
        retrievable: true,
    };
    let mut candidates = vec![wrap(
        &access,
        marker(
            &scope,
            "situation",
            known_at,
            PackBlockKind::Situation,
            "Current conversation task.",
            "question",
            &query,
        )?,
    )];
    let mut evidence = Vec::new();
    let mut originals = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut source_ids = BTreeMap::new();
    let mut hot = Vec::new();
    for event in crate::continuous_history(0)
        .events
        .into_iter()
        .filter(|event| event.known_at <= at)
    {
        let text = event
            .text
            .replace("Atlas", entity)
            .replace("7319", &code)
            .replace("8426", &corrected);
        let source = source(
            &domain,
            &access,
            &event.id,
            &text,
            offset + event.known_at,
            budget,
        )?;
        let original = source
            .evidence
            .original_span
            .as_ref()
            .ok_or_else(invalid)?
            .clone();
        originals.insert(
            original.event_id,
            Original {
                span: original.clone(),
                text: text.clone(),
                known_at: offset + event.known_at,
            },
        );
        if event.speaker == "assistant" {
            // A fixed source-class frontier, not gold-driven candidate pruning.
            // The observed proposal remains in the actual host context.
            hot.push(message(
                &format!("hot:{}", event.id),
                &original,
                &text,
                OutgoingZone::HotHistory,
                OutgoingRole::Assistant,
            )?);
        } else {
            let mut candidate = marker(
                &scope,
                &unit_key(&domain, &event.id),
                offset + event.known_at,
                PackBlockKind::RawObservation,
                "Original source occurrence.",
                "speaker",
                "user",
            )?;
            candidate.mandatory = false;
            candidate.trust = ContentTrust::Untrusted;
            candidate.source_class = SourceClass::UserStatement;
            candidate.interpretation = InterpretationRule::HistoricalData;
            candidate
                .evidence_handles
                .insert(source.evidence.id.clone());
            source_ids.insert(event.id.clone(), candidate.id.clone());
            candidates.push(wrap(&access, candidate));
            evidence.push(source.clone());
        }
        sources.insert(event.id, source);
    }
    let initial = sources
        .get("atlas-code")
        .ok_or_else(invalid)?
        .evidence
        .original_span
        .as_ref()
        .ok_or_else(invalid)?
        .clone();
    let local = sources
        .get("atlas-local")
        .ok_or_else(invalid)?
        .evidence
        .original_span
        .as_ref()
        .ok_or_else(invalid)?
        .clone();
    if matches!(scenario, Scenario::ResidentCode | Scenario::PartialResident) {
        let original = originals.get(&initial.event_id).ok_or_else(invalid)?;
        let mut resident = initial.clone();
        if scenario == Scenario::PartialResident {
            resident.end = "Код сейфа ".len() as u64;
            resident.span_digest = ContentDigest::from_bytes(
                *blake3::hash(&original.text.as_bytes()[..resident.end as usize]).as_bytes(),
            );
        }
        let text = original
            .text
            .get(resident.start as usize..resident.end as usize)
            .ok_or_else(invalid)?;
        hot.push(message(
            "resident-original",
            &resident,
            text,
            OutgoingZone::HotHistory,
            OutgoingRole::User,
        )?);
    }
    let mut dependencies = BTreeMap::new();
    // Every optional pair is proposed from the query-time inventory, including
    // irrelevant candidates. No evaluator-derived bundle enters this graph.
    for id in source_ids.values() {
        dependencies.insert(
            id.clone(),
            EvidenceDependencies {
                complements: source_ids
                    .values()
                    .filter(|other| *other != id)
                    .cloned()
                    .collect(),
                ..Default::default()
            },
        );
    }
    let mut sufficient_sets = vec![vec![interval(&initial)]];
    let rule = match scenario {
        Scenario::Complement => targets::Rule::SufficientUnionOnly,
        Scenario::MandatoryConflictUnknown => targets::Rule::UnresolvedTask,
        _ => targets::Rule::Additive,
    };
    match scenario {
        Scenario::CorrectedCode => {
            let corrected = sources
                .get("atlas-correction")
                .ok_or_else(invalid)?
                .evidence
                .original_span
                .as_ref()
                .ok_or_else(invalid)?;
            sufficient_sets = vec![vec![interval(corrected)]];
        }
        Scenario::LocalConstraint | Scenario::ToolIndirect => {
            sufficient_sets = vec![vec![interval(&local)]]
        }
        Scenario::Complement | Scenario::MultiMemory => {
            sufficient_sets = vec![vec![interval(&initial), interval(&local)]]
        }
        Scenario::NoMemory => sufficient_sets.clear(),
        Scenario::HardAlternative => {
            let text = format!("The original {entity} code is {code}. {}", "Its retained attribution confirms the same original code and applies only to the local vault. ".repeat(12));
            let alternative = source(
                &domain,
                &access,
                "equivalent-attribution",
                &text,
                offset + 2,
                budget,
            )?;
            let alternative_span = alternative
                .evidence
                .original_span
                .as_ref()
                .ok_or_else(invalid)?
                .clone();
            originals.insert(
                alternative_span.event_id,
                Original {
                    span: alternative_span.clone(),
                    text,
                    known_at: offset + 2,
                },
            );
            let initial_id = source_ids.get("atlas-code").ok_or_else(invalid)?;
            let candidate = candidates
                .iter_mut()
                .find(|item| &item.candidate.id == initial_id)
                .ok_or_else(invalid)?;
            candidate
                .candidate
                .evidence_handles
                .insert(alternative.evidence.id.clone());
            let dependency = dependencies.get_mut(initial_id).ok_or_else(invalid)?;
            dependency
                .hard
                .insert(source_ids.get("atlas-local").ok_or_else(invalid)?.clone());
            dependency.supports = vec![
                BTreeSet::from([alternative.evidence.id.clone()]),
                BTreeSet::from([sources
                    .get("atlas-code")
                    .ok_or_else(invalid)?
                    .evidence
                    .id
                    .clone()]),
            ];
            sufficient_sets = vec![
                vec![interval(&initial), interval(&local)],
                vec![interval(&alternative_span), interval(&local)],
            ];
            evidence.push(alternative);
        }
        Scenario::MandatoryConflictUnknown => {
            add_mandatory_state(
                &mut candidates,
                &mut evidence,
                &access,
                &scope,
                known_at,
                &domain,
                &sources,
            )?;
        }
        _ => {}
    }
    let working_text = format!(
        "Active task: continue configuring the {entity} vault; unresolved steps remain open."
    );
    let working = source(
        &domain,
        &access,
        &format!("working:{id}"),
        &working_text,
        known_at,
        budget,
    )?;
    let working_span = working
        .evidence
        .original_span
        .as_ref()
        .ok_or_else(invalid)?
        .clone();
    originals.insert(
        working_span.event_id,
        Original {
            span: working_span.clone(),
            text: working_text.clone(),
            known_at,
        },
    );
    let query_source = source(
        &domain,
        &access,
        &format!("query:{id}"),
        &query,
        known_at,
        budget,
    )?;
    let query_span = query_source
        .evidence
        .original_span
        .as_ref()
        .ok_or_else(invalid)?
        .clone();
    originals.insert(
        query_span.event_id,
        Original {
            span: query_span.clone(),
            text: query.clone(),
            known_at,
        },
    );
    let mut current = vec![message(
        "current-query",
        &query_span,
        &query,
        OutgoingZone::CurrentTurn,
        OutgoingRole::User,
    )?];
    let mut control = vec![OutgoingMessage {
        id: BlockId::new("control").map_err(|_| invalid())?, zone: OutgoingZone::Control, role: OutgoingRole::System,
        text: "Answer from attributed conversation data; preserve unresolved conflicts and missing information.".into(),
        originals: Vec::new(), tool_calls: Vec::new(), tool_result: None,
    }];
    if scenario == Scenario::ToolIndirect {
        control.push(OutgoingMessage {
            id: BlockId::new("tool-definition").map_err(|_| invalid())?,
            zone: OutgoingZone::ToolDefinitions,
            role: OutgoingRole::System,
            text: "Available tool: inspect_storage.".into(),
            originals: Vec::new(),
            tool_calls: Vec::new(),
            tool_result: None,
        });
        let text = "Inspecting the configured storage before the next action.";
        let call = source(
            &domain,
            &access,
            &format!("tool-call:{id}"),
            text,
            known_at,
            budget,
        )?;
        let call_span = call
            .evidence
            .original_span
            .as_ref()
            .ok_or_else(invalid)?
            .clone();
        originals.insert(
            call_span.event_id,
            Original {
                span: call_span.clone(),
                text: text.into(),
                known_at,
            },
        );
        let mut call_message = message(
            "tool-call",
            &call_span,
            text,
            OutgoingZone::HotHistory,
            OutgoingRole::Assistant,
        )?;
        call_message.tool_calls.push("inspect-call".into());
        hot.push(call_message);
        let text = "Storage check: the network destination is unavailable; select the permitted offline path.";
        let tool = source(
            &domain,
            &access,
            &format!("tool-result:{id}"),
            text,
            known_at,
            budget,
        )?;
        let tool_span = tool
            .evidence
            .original_span
            .as_ref()
            .ok_or_else(invalid)?
            .clone();
        originals.insert(
            tool_span.event_id,
            Original {
                span: tool_span.clone(),
                text: text.into(),
                known_at,
            },
        );
        let mut tool_message = message(
            "tool-result",
            &tool_span,
            text,
            OutgoingZone::CurrentTurn,
            OutgoingRole::Tool,
        )?;
        tool_message.tool_result = Some("inspect-call".into());
        current.insert(0, tool_message);
    }
    let snapshot = ProviderSnapshot {
        database_id: domain.clone(),
        commit_seq: known_at,
        watermarks: RecallWatermarks {
            journal: known_at,
            semantic: known_at,
            lexical: known_at,
            vector: BTreeMap::new(),
            graph: known_at,
            hierarchy: BTreeMap::new(),
        },
    };
    charge(
        budget,
        1,
        originals.values().map(|item| item.text.len() as u64).sum(),
    )?;
    let provider = Provider {
        data: InMemoryContextProvider::new(snapshot.clone(), candidates, evidence)
            .map_err(|_| invalid())?,
        originals: originals
            .iter()
            .map(|(id, source)| (*id, source.text.as_bytes().to_vec()))
            .collect(),
        dependencies,
        scope: scope.clone(),
        binding: AssemblyBinding {
            snapshot: format!("conditional:{group}:{known_at}"),
            authorization: format!("synthetic:owner:{group}"),
            state: format!("synthetic:state:{group}"),
            valid_until: None,
        },
    };
    let request = CompileAssemblyRequest {
        context: CompileRequest {
            pack_id: ContextPackId::from_uuid(stable_uuid(&id)).map_err(|_| invalid())?,
            snapshot,
            principal: RecallPrincipal {
                subject: "synthetic:owner".into(),
                audiences: BTreeSet::new(),
                workspace: access.workspace,
                scopes: BTreeSet::from([scope.clone()]),
                purpose: "conversation".into(),
                clearance: RecallSensitivity::Confidential,
            },
            filter_digest: "synthetic:conditional-source-class-frontier.v1".into(),
            purpose: PackPurpose::Conversation,
            scopes: BTreeSet::from([scope]),
            temporal_view: TemporalConstraint::Current,
            required_facets: Vec::new(),
            budgets: ContextBudgets {
                hard_tokens: 12000,
                soft_tokens: 10000,
                max_blocks: 16,
                max_evidence_blocks: 16,
                max_raw_evidence_tokens: 6000,
                max_history_tokens: 6000,
                max_conflict_tokens: 6000,
                max_serialized_bytes: 2 * 1024 * 1024,
                max_selection_evaluations: 64,
            },
            model_profile: ModelProfile {
                id: "synthetic-conditional-reference".into(),
                family: "synthetic".into(),
                tokenizer_id: ReferenceTokenizer::ID.into(),
                renderer: RendererKind::Compact,
                max_context_tokens: 32000,
                reserved_output_tokens: 4000,
                preferred_structured_format: StructuredFormat::CompactText,
                supports_tool_results: true,
                supports_native_citations: false,
                supports_prompt_caching: false,
                position_profile: PositionProfile::SmallModelExplicit,
                instruction_hierarchy: InstructionHierarchy::SinglePromptDelimited,
                max_schema_complexity: 64,
                external_processing: false,
            },
            explicit_memory_request: true,
            require_primary_evidence: true,
            continuation: None,
        },
        base: OutgoingBase {
            control,
            working: vec![message(
                "working",
                &working_span,
                &working_text,
                OutgoingZone::WorkingState,
                OutgoingRole::User,
            )?],
            hot,
            current,
        },
        budget: OutgoingBudget {
            max_input_tokens: 27000,
            safety_tokens: 1000,
            max_wire_bytes: 2 * 1024 * 1024,
        },
    };
    Ok(Case {
        id,
        domain,
        known_at,
        request,
        provider,
        originals,
        #[cfg(test)]
        source_ids,
        oracle: targets::Oracle {
            rule,
            sufficient_sets,
        },
        exploration: if matches!(
            scenario,
            Scenario::NoMemory | Scenario::MandatoryConflictUnknown
        ) {
            collector::Exploration::AlwaysStop
        } else {
            collector::Exploration::ConstantPositive
        },
    })
}

fn interval(span: &OriginalSourceSpan) -> SourceInterval {
    SourceInterval {
        event_id: span.event_id,
        payload_digest: span.payload_digest,
        start: span.start,
        end: span.end,
    }
}
fn unit_key(domain: &str, source: &str) -> String {
    format!(
        "unit:{}",
        &blake3::hash(format!("{domain}/{source}").as_bytes()).to_hex()[..16]
    )
}
fn stable_uuid(key: &str) -> uuid::Uuid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&blake3::hash(key.as_bytes()).as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}
fn marker(
    scope: &str,
    id: &str,
    known_at: u64,
    kind: PackBlockKind,
    summary: &str,
    key: &str,
    value: &str,
) -> Result<PackCandidate> {
    Ok(PackCandidate {
        id: BlockId::new(id).map_err(|_| invalid())?,
        kind,
        representations: vec![BlockRepresentation {
            level: CompressionLevel::L0Orientation,
            summary: summary.into(),
            fields: BTreeMap::from([(key.into(), value.into())]),
            omitted_facets: BTreeSet::new(),
        }],
        exact_fragments: Vec::new(),
        memory_refs: Vec::new(),
        claim_ids: BTreeSet::new(),
        evidence_handles: BTreeSet::new(),
        facets: BTreeSet::new(),
        scopes: BTreeSet::from([scope.into()]),
        valid_time: None,
        known_at_commit: known_at,
        perspective: None,
        epistemic: EpistemicState {
            basis: EpistemicBasis::Observation,
            acceptance: AcceptanceState::Accepted,
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
    })
}
fn wrap(access: &AccessRule, candidate: PackCandidate) -> ProviderCandidate {
    ProviderCandidate {
        access: access.clone(),
        candidate,
        use_policy: CandidateUsePolicy {
            influence: PolicyDecision::Allow,
            mention: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Allow,
            disclosure: DisclosureRule::MayMention,
        },
    }
}
fn source(
    domain: &str,
    access: &AccessRule,
    id: &str,
    text: &str,
    _: u64,
    budget: &mut QueryBudget,
) -> Result<ProviderEvidence> {
    charge(budget, 1, (text.len() as u64).saturating_mul(4))?;
    let digest = ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes());
    let span = OriginalSourceSpan {
        event_id: ObservationId::from_uuid(stable_uuid(&format!("{domain}/{id}")))
            .map_err(|_| invalid())?,
        payload_digest: digest,
        start: 0,
        end: text.len() as u64,
        span_digest: digest,
    };
    Ok(ProviderEvidence {
        access: access.clone(),
        external_model_use: PolicyDecision::Allow,
        evidence: PackEvidence {
            id: EvidenceHandle::new(format!(
                "evidence:{}",
                stable_uuid(&format!("{domain}/{id}"))
            ))
            .map_err(|_| invalid())?,
            source: SourceHandle::new(format!("{domain}/{id}")).map_err(|_| invalid())?,
            selector: EvidenceSelector::TextBytes {
                start: 0,
                end: text.len() as u64,
            },
            excerpt: Some(text.into()),
            claim_ids: BTreeSet::new(),
            provenance_family: format!("{domain}/{id}"),
            primary: true,
            trust_micros: 1_000_000,
            source_class: SourceClass::UserStatement,
            taints: BTreeSet::from([ContentTaint::UserControlled]),
            lineage: Vec::new(),
            original_span: Some(span),
        },
    })
}
fn message(
    id: &str,
    span: &OriginalSourceSpan,
    text: &str,
    zone: OutgoingZone,
    role: OutgoingRole,
) -> Result<OutgoingMessage> {
    Ok(OutgoingMessage {
        id: BlockId::new(id).map_err(|_| invalid())?,
        zone,
        role,
        text: text.into(),
        originals: vec![VisibleOriginal {
            span: span.clone(),
            text_start: 0,
            text_end: text.len() as u64,
        }],
        tool_calls: Vec::new(),
        tool_result: None,
    })
}
fn add_mandatory_state(
    candidates: &mut Vec<ProviderCandidate>,
    evidence: &mut [ProviderEvidence],
    access: &AccessRule,
    scope: &str,
    known_at: u64,
    domain: &str,
    sources: &BTreeMap<String, ProviderEvidence>,
) -> Result<()> {
    let mut unknown = marker(
        scope,
        "unknown-confirmation",
        known_at,
        PackBlockKind::Unknown,
        "Owner confirmation is missing.",
        "question",
        "Which conflicting code did the owner confirm?",
    )?;
    unknown.epistemic.basis = EpistemicBasis::Hypothesis;
    unknown.interpretation = InterpretationRule::UnknownMarker;
    unknown.unknown = Some(UnknownDescriptor {
        question: "Which conflicting code did the owner confirm?".into(),
        reason: "No owner confirmation exists in the permitted originals.".into(),
        blocking: true,
    });
    candidates.push(wrap(access, unknown));
    let claims = [
        ClaimId::from_uuid(stable_uuid(&format!("{domain}/initial-claim")))
            .map_err(|_| invalid())?,
        ClaimId::from_uuid(stable_uuid(&format!("{domain}/corrected-claim")))
            .map_err(|_| invalid())?,
    ];
    let set_id = ConflictSetId::from_uuid(stable_uuid(&format!("{domain}/conflict")))
        .map_err(|_| invalid())?;
    for (index, source_id) in ["atlas-code", "atlas-correction"].into_iter().enumerate() {
        let handle = &sources.get(source_id).ok_or_else(invalid)?.evidence.id;
        let support = evidence
            .iter_mut()
            .find(|item| &item.evidence.id == handle)
            .ok_or_else(invalid)?;
        support.evidence.claim_ids.insert(claims[index]);
    }
    let mut conflict = marker(
        scope,
        "blocking-conflict",
        known_at,
        PackBlockKind::Conflict,
        "Two observed codes remain unresolved.",
        "reason",
        "Owner confirmation is required before choosing an alternative.",
    )?;
    conflict.claim_ids = claims.into_iter().collect();
    conflict.evidence_handles = ["atlas-code", "atlas-correction"]
        .into_iter()
        .map(|id| {
            sources
                .get(id)
                .map(|item| item.evidence.id.clone())
                .ok_or_else(invalid)
        })
        .collect::<Result<_>>()?;
    conflict.perspective = Some(Perspective {
        knower: MemorySubjectId::from_uuid(stable_uuid(&format!("{domain}/owner")))
            .map_err(|_| invalid())?,
        experiencer: None,
        narrator: ActorId::from_uuid(stable_uuid(&format!("{domain}/actor")))
            .map_err(|_| invalid())?,
        role: EpistemicRole::Witness,
    });
    conflict.epistemic.conflict = ConflictState::InConflict { set_id };
    conflict.interpretation = InterpretationRule::ConflictAlternatives;
    conflict.conflict = Some(ConflictDescriptor {
        set_id,
        alternatives: claims.into_iter().collect(),
        resolution: ConflictResolution::Unresolved,
        blocking: true,
    });
    candidates.push(wrap(access, conflict));
    Ok(())
}

pub(super) fn lineage(case: &Case) -> Result<(Vec<RouterLineageRef>, Vec<RouterLineageNode>)> {
    let mut nodes = Vec::new();
    let mut parents = Vec::new();
    for kind in [
        RouterLineageKind::Workspace,
        RouterLineageKind::Project,
        RouterLineageKind::Entity,
        RouterLineageKind::Session,
        RouterLineageKind::Run,
    ] {
        let reference = RouterLineageRef {
            kind,
            domain: case.domain.clone(),
            id: format!("{}:{kind:?}", case.domain),
            version: None,
        };
        nodes.push(RouterLineageNode {
            reference: reference.clone(),
            available_at: case.known_at / 100 * 100 + 1,
            parents: Vec::new(),
        });
        parents.push(reference);
    }
    parents.sort();
    let mut roots = Vec::new();
    for original in case.originals.values() {
        if original.known_at > case.known_at {
            return Err(invalid());
        }
        let reference = RouterLineageRef {
            kind: RouterLineageKind::SourceVersion,
            domain: case.domain.clone(),
            id: original.span.event_id.to_string(),
            version: Some(original.span.payload_digest.to_string()),
        };
        nodes.push(RouterLineageNode {
            reference: reference.clone(),
            available_at: original.known_at,
            parents: parents.clone(),
        });
        roots.push(reference);
    }
    roots.sort();
    Ok((roots, nodes))
}

pub(super) struct Provider {
    data: InMemoryContextProvider,
    originals: BTreeMap<ObservationId, Vec<u8>>,
    pub(super) dependencies: BTreeMap<BlockId, EvidenceDependencies>,
    scope: String,
    binding: AssemblyBinding,
}
impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConditionalSyntheticProvider")
            .field("originals", &self.originals.len())
            .finish_non_exhaustive()
    }
}
impl ContextProvider for Provider {
    fn snapshot(&self) -> contextdb_context::Result<ProviderSnapshot> {
        self.data.snapshot()
    }
    fn candidate_labels(&self) -> contextdb_context::Result<Vec<CandidatePolicyLabel>> {
        self.data.candidate_labels()
    }
    fn materialize_candidate(&self, id: &BlockId) -> contextdb_context::Result<PackCandidate> {
        self.data.materialize_candidate(id)
    }
    fn evidence_labels(
        &self,
        ids: &[EvidenceHandle],
    ) -> contextdb_context::Result<Vec<EvidencePolicyLabel>> {
        self.data.evidence_labels(ids)
    }
    fn materialize_evidence(&self, id: &EvidenceHandle) -> contextdb_context::Result<PackEvidence> {
        self.data.materialize_evidence(id)
    }
}
impl AssemblyProvider for Provider {
    fn binding(&self) -> contextdb_context::Result<AssemblyBinding> {
        Ok(self.binding.clone())
    }
    fn dependencies(&self, id: &BlockId) -> contextdb_context::Result<EvidenceDependencies> {
        Ok(self.dependencies.get(id).cloned().unwrap_or_default())
    }
    fn verify_original(
        &self,
        span: &OriginalSourceSpan,
        data: &[u8],
        budget: &mut QueryBudget,
    ) -> contextdb_context::Result<()> {
        budget
            .charge(1, data.len() as u64)
            .map_err(|_| ContextError::BudgetExceeded("conditional source allowance".into()))?;
        let original = self.originals.get(&span.event_id).ok_or_else(|| {
            ContextError::Authorization("conditional original unavailable".into())
        })?;
        if span.payload_digest.as_bytes() != blake3::hash(original).as_bytes()
            || original.get(span.start as usize..span.end as usize) != Some(data)
        {
            return Err(ContextError::Provider(
                "conditional original version/range mismatch".into(),
            ));
        }
        Ok(())
    }
    fn validate_read_set(
        &self,
        read: &AssemblyReadSet,
        budget: &mut QueryBudget,
    ) -> contextdb_context::Result<()> {
        budget
            .charge(1, 0)
            .map_err(|_| ContextError::BudgetExceeded("conditional read-set allowance".into()))?;
        if read.binding != self.binding || read.scopes != BTreeSet::from([self.scope.clone()]) {
            return Err(ContextError::Authorization(
                "conditional read-set mismatch".into(),
            ));
        }
        Ok(())
    }
}
