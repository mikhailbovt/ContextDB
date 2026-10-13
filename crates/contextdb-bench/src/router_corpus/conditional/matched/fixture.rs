//! Query seeds construct the full inventory before interval annotations exist.

use super::super::fixture::{
    self as common, Original, Provider, interval, marker, message, stable_uuid, unit_key, wrap,
};
use super::*;
use contextdb_core::{
    ActorId, ClaimId, ConflictSetId, ConflictState, ContextPackId, EpistemicBasis, EpistemicRole,
    MemorySubjectId, OriginalSourceSpan, Perspective, TemporalConstraint,
};
use contextdb_recall::{
    AccessConsent, AccessRule, ProviderSnapshot, RecallPrincipal, RecallSensitivity,
    RecallWatermarks,
};

pub(super) struct Case {
    pub(super) id: String,
    pub(super) domain: String,
    request: CompileAssemblyRequest,
    provider: Provider,
    exploration: collector::Exploration,
    originals: BTreeMap<ObservationId, Original>,
    sources: BTreeMap<String, ProviderEvidence>,
    source_ids: BTreeMap<String, BlockId>,
}
impl Case {
    pub(super) fn compiler_input(&self) -> collector::CompileCase<'_> {
        collector::CompileCase {
            id: &self.id,
            domain: &self.domain,
            known_at: 6,
            request: &self.request,
            provider: &self.provider,
            exploration: &self.exploration,
        }
    }
}

fn role(value: &str) -> Result<(OutgoingRole, SourceClass, ContentTaint)> {
    match value {
        "user" => Ok((
            OutgoingRole::User,
            SourceClass::UserStatement,
            ContentTaint::UserControlled,
        )),
        "assistant" => Ok((
            OutgoingRole::Assistant,
            SourceClass::ModelGenerated,
            ContentTaint::Generated,
        )),
        "tool" => Ok((
            OutgoingRole::Tool,
            SourceClass::ToolOutput,
            ContentTaint::ExternalContent,
        )),
        _ => Err(invalid()),
    }
}

fn source(
    domain: &str,
    access: &AccessRule,
    id: &str,
    text: &str,
    source_role: &str,
    budget: &mut QueryBudget,
) -> Result<ProviderEvidence> {
    let (_, class, taint) = role(source_role)?;
    let mut source = common::source(
        domain,
        access,
        &stable_uuid(id).to_string(),
        text,
        0,
        budget,
    )?;
    source.evidence.source_class = class;
    source.evidence.taints = BTreeSet::from([taint]);
    Ok(source)
}

fn retain(
    originals: &mut BTreeMap<ObservationId, Original>,
    source: &ProviderEvidence,
    text: &str,
    known_at: u64,
) -> Result<OriginalSourceSpan> {
    let span = source
        .evidence
        .original_span
        .as_ref()
        .ok_or_else(invalid)?
        .clone();
    if originals
        .insert(
            span.event_id,
            Original {
                span: span.clone(),
                text: text.into(),
                known_at,
            },
        )
        .is_some()
    {
        return Err(invalid());
    }
    Ok(span)
}

pub(super) fn build(history: &History, probe: Probe, budget: &mut QueryBudget) -> Result<Case> {
    let id = probe.id(history);
    let domain = history.domain();
    let scope = format!("{domain}:scope");
    let access = AccessRule {
        workspace: format!("{domain}:workspace"),
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
    let query = if probe == Probe::Unresolved {
        history.unresolved_query.as_deref().ok_or_else(invalid)?
    } else {
        &history.query
    };
    let mut candidates = vec![wrap(
        &access,
        marker(
            &scope,
            "situation",
            6,
            PackBlockKind::Situation,
            "Current conversation task.",
            "question",
            query,
        )?,
    )];
    let mut evidence = Vec::new();
    let mut originals = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut source_ids = BTreeMap::new();
    let mut hot = Vec::new();
    // Candidate inventory comes from all four chronological originals. Neither
    // sufficient proofs nor utility targets choose candidates or dependencies.
    for (index, (name, speaker, text)) in history.events.iter().enumerate() {
        let known_at = index as u64 + 1;
        let source = source(&domain, &access, name, text, speaker, budget)?;
        let span = retain(&mut originals, &source, text, known_at)?;
        let (outgoing_role, source_class, taint) = role(speaker)?;
        let mut candidate = marker(
            &scope,
            &unit_key(&domain, name),
            known_at,
            PackBlockKind::RawObservation,
            "Original source occurrence.",
            "speaker",
            speaker,
        )?;
        candidate.mandatory = false;
        candidate.trust = ContentTrust::Untrusted;
        candidate.source_class = source_class;
        candidate.taints.insert(taint);
        candidate.interpretation = InterpretationRule::HistoricalData;
        candidate
            .evidence_handles
            .insert(source.evidence.id.clone());
        source_ids.insert(name.clone(), candidate.id.clone());
        candidates.push(wrap(&access, candidate));
        evidence.push(source.clone());
        let is_current_tool = history
            .base_tool_exchange
            .as_ref()
            .is_some_and(|exchange| exchange.result_source_id == *name);
        if probe == Probe::Resident && history.resident.contains(name) && !is_current_tool {
            if outgoing_role == OutgoingRole::Tool {
                return Err(invalid());
            }
            hot.push(message(
                &format!("resident:{index}"),
                &span,
                text,
                OutgoingZone::HotHistory,
                outgoing_role,
            )?);
        }
        sources.insert(name.clone(), source);
    }
    let dependencies = source_ids
        .values()
        .map(|id| {
            (
                id.clone(),
                EvidenceDependencies {
                    complements: source_ids
                        .values()
                        .filter(|other| *other != id)
                        .cloned()
                        .collect(),
                    ..Default::default()
                },
            )
        })
        .collect();
    if probe == Probe::Unresolved {
        mandatory(
            history,
            query,
            &scope,
            &access,
            &sources,
            &mut candidates,
            &mut evidence,
        )?;
    }
    let working = source(
        &domain,
        &access,
        "working",
        &history.working,
        "user",
        budget,
    )?;
    let working_span = retain(&mut originals, &working, &history.working, 6)?;
    let query_source = source(
        &domain,
        &access,
        if probe == Probe::Unresolved {
            "unresolved-query"
        } else {
            "query"
        },
        query,
        "user",
        budget,
    )?;
    let query_span = retain(&mut originals, &query_source, query, 6)?;
    let mut current = vec![message(
        "current-query",
        &query_span,
        query,
        OutgoingZone::CurrentTurn,
        OutgoingRole::User,
    )?];
    let mut control = vec![OutgoingMessage {
        id: BlockId::new("control").map_err(|_| invalid())?, zone: OutgoingZone::Control, role: OutgoingRole::System,
        text: "Answer from attributed conversation data; preserve unresolved conflicts and missing information.".into(),
        originals: Vec::new(), tool_calls: Vec::new(), tool_result: None,
    }];
    if let Some(exchange) = history
        .base_tool_exchange
        .as_ref()
        .filter(|_| probe != Probe::Unresolved)
    {
        control.push(OutgoingMessage {
            id: BlockId::new("tool-definition").map_err(|_| invalid())?,
            zone: OutgoingZone::ToolDefinitions,
            role: OutgoingRole::System,
            text: "Available tool: inspect_original.".into(),
            originals: Vec::new(),
            tool_calls: Vec::new(),
            tool_result: None,
        });
        let result_index = history
            .events
            .iter()
            .position(|event| event.0 == exchange.result_source_id)
            .ok_or_else(invalid)?;
        let (_, result_role, result_text) = &history.events[result_index];
        if result_role != "tool" {
            return Err(invalid());
        }
        let call = source(
            &domain,
            &access,
            "tool-call",
            &exchange.call_text,
            "assistant",
            budget,
        )?;
        let call_span = retain(
            &mut originals,
            &call,
            &exchange.call_text,
            result_index as u64,
        )?;
        let mut call_message = message(
            "tool-call",
            &call_span,
            &exchange.call_text,
            OutgoingZone::HotHistory,
            OutgoingRole::Assistant,
        )?;
        call_message.tool_calls.push("inspect-call".into());
        hot.push(call_message);
        let result = sources
            .get(&exchange.result_source_id)
            .ok_or_else(invalid)?;
        let result_span = result.evidence.original_span.as_ref().ok_or_else(invalid)?;
        let mut result_message = message(
            "tool-result",
            result_span,
            result_text,
            OutgoingZone::CurrentTurn,
            OutgoingRole::Tool,
        )?;
        result_message.tool_result = Some("inspect-call".into());
        current.insert(0, result_message);
    }
    let snapshot = ProviderSnapshot {
        database_id: domain.clone(),
        commit_seq: 6,
        watermarks: RecallWatermarks {
            journal: 6,
            semantic: 6,
            lexical: 6,
            vector: BTreeMap::new(),
            graph: 6,
            hierarchy: BTreeMap::new(),
        },
    };
    charge(
        budget,
        1,
        originals
            .values()
            .map(|original| original.text.len() as u64)
            .sum(),
    )?;
    let provider = Provider {
        data: InMemoryContextProvider::new(snapshot.clone(), candidates, evidence)
            .map_err(|_| invalid())?,
        originals: originals
            .iter()
            .map(|(id, original)| (*id, original.text.as_bytes().to_vec()))
            .collect(),
        dependencies,
        scope: scope.clone(),
        binding: AssemblyBinding {
            snapshot: format!("{domain}:6"),
            authorization: format!("{domain}:owner"),
            state: format!("{domain}:state"),
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
            filter_digest: "synthetic:matched-full-source-frontier.v2".into(),
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
                max_serialized_bytes: MAX_CONDITIONAL_INPUT_BYTES as u32,
                max_selection_evaluations: 64,
            },
            model_profile: ModelProfile {
                id: "synthetic-matched-reference-v2".into(),
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
                &history.working,
                OutgoingZone::WorkingState,
                OutgoingRole::User,
            )?],
            hot,
            current,
        },
        budget: OutgoingBudget {
            max_input_tokens: 27000,
            safety_tokens: 1000,
            max_wire_bytes: MAX_CONDITIONAL_INPUT_BYTES as u32,
        },
    };
    let exploration = if probe == Probe::Unresolved {
        collector::Exploration::UnresolvedStopV2
    } else {
        collector::Exploration::FirstInventorySingleThenStop(
            source_ids
                .get(&history.events[0].0)
                .ok_or_else(invalid)?
                .clone(),
        )
    };
    Ok(Case {
        id,
        domain,
        request,
        provider,
        exploration,
        originals,
        sources,
        source_ids,
    })
}

fn mandatory(
    history: &History,
    query: &str,
    scope: &str,
    access: &AccessRule,
    sources: &BTreeMap<String, ProviderEvidence>,
    candidates: &mut Vec<ProviderCandidate>,
    evidence: &mut [ProviderEvidence],
) -> Result<()> {
    let domain = history.domain();
    let mut unknown = marker(
        scope,
        "unknown-confirmation",
        6,
        PackBlockKind::Unknown,
        "Owner confirmation is missing.",
        "question",
        query,
    )?;
    unknown.epistemic.basis = EpistemicBasis::Hypothesis;
    unknown.interpretation = InterpretationRule::UnknownMarker;
    unknown.unknown = Some(UnknownDescriptor {
        question: query.into(),
        reason: "No owner confirmation exists in these permitted originals.".into(),
        blocking: true,
    });
    candidates.push(wrap(access, unknown));
    let claims = [0, 1]
        .map(|index| {
            ClaimId::from_uuid(stable_uuid(&format!("{domain}/claim:{index}")))
                .map_err(|_| invalid())
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let set_id = ConflictSetId::from_uuid(stable_uuid(&format!("{domain}/conflict")))
        .map_err(|_| invalid())?;
    let mut handles = BTreeSet::new();
    for (name, claim) in history.conflict_sources.iter().zip(&claims) {
        let source = sources.get(name).ok_or_else(invalid)?;
        let support = evidence
            .iter_mut()
            .find(|item| item.evidence.id == source.evidence.id)
            .ok_or_else(invalid)?;
        if support.evidence.source_class != SourceClass::ModelGenerated {
            return Err(invalid());
        }
        support.evidence.claim_ids.insert(*claim);
        handles.insert(source.evidence.id.clone());
    }
    let mut conflict = marker(
        scope,
        "blocking-conflict",
        6,
        PackBlockKind::Conflict,
        "Two attributed proposals remain unresolved.",
        "reason",
        "Owner confirmation is required before choosing an alternative.",
    )?;
    conflict.claim_ids = claims.iter().copied().collect();
    conflict.evidence_handles = handles;
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

pub(super) fn oracle(history: &History, probe: Probe, case: &Case) -> Result<targets::Oracle> {
    let rule = if probe == Probe::Unresolved {
        targets::Rule::UnresolvedTask
    } else {
        match history.rule.as_str() {
            "additive" => targets::Rule::Additive,
            "sufficient_union_only" => targets::Rule::SufficientUnionOnly,
            _ => return Err(invalid()),
        }
    };
    let sufficient_sets = if probe == Probe::Unresolved {
        Vec::new()
    } else {
        history
            .proofs
            .iter()
            .map(|set| {
                set.iter()
                    .map(|id| {
                        let source = case.sources.get(id).ok_or_else(invalid)?;
                        Ok(interval(
                            source.evidence.original_span.as_ref().ok_or_else(invalid)?,
                        ))
                    })
                    .collect::<Result<_>>()
            })
            .collect::<Result<_>>()?
    };
    Ok(targets::Oracle {
        rule,
        sufficient_sets,
    })
}

pub(super) fn lineage(
    history: &History,
    case: &Case,
) -> Result<(Vec<RouterLineageRef>, Vec<RouterLineageNode>)> {
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
            version: Some(format!("seed:{}:v2", history.seed_sha256)),
        };
        nodes.push(RouterLineageNode {
            reference: reference.clone(),
            available_at: 1,
            parents: Vec::new(),
        });
        parents.push(reference);
    }
    parents.sort();
    let mut roots = Vec::new();
    for original in case.originals.values() {
        if original.known_at == 0 || original.known_at > 6 {
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

pub(super) fn validate_exploration(
    case: &Case,
    probe: Probe,
    rows: &[Observation],
    budget: &mut QueryBudget,
) -> Result<()> {
    let inventory: BTreeSet<_> = case.source_ids.values().cloned().collect();
    let first = match &case.exploration {
        collector::Exploration::FirstInventorySingleThenStop(id) => Some(id),
        collector::Exploration::UnresolvedStopV2 => None,
        _ => return Err(invalid()),
    };
    let mut groups = BTreeMap::<BTreeSet<BlockId>, BTreeSet<BTreeSet<BlockId>>>::new();
    for row in rows {
        charge(budget, 1, 0)?;
        let selected: BTreeSet<_> = row
            .selected
            .pack
            .sections
            .iter()
            .filter(|block| inventory.contains(&block.id))
            .map(|block| block.id.clone())
            .collect();
        if !row.outgoing_fits
            || row.seed_ids.is_empty()
            || row.seed_ids.len() > 2
            || !row.seed_ids.is_subset(&inventory)
            || !selected.is_disjoint(&row.seed_ids)
            || !groups
                .entry(selected)
                .or_default()
                .insert(row.seed_ids.clone())
        {
            return Err(invalid());
        }
        if probe == Probe::Unresolved
            && [PackBlockKind::Conflict, PackBlockKind::Unknown]
                .iter()
                .any(|kind| {
                    !row.selected
                        .pack
                        .sections
                        .iter()
                        .any(|block| &block.kind == kind)
                })
        {
            return Err(invalid());
        }
    }
    let expected_bases = if let Some(id) = first {
        vec![BTreeSet::new(), BTreeSet::from([id.clone()])]
    } else {
        vec![BTreeSet::new()]
    };
    if groups.len() != expected_bases.len() {
        return Err(invalid());
    }
    for selected in expected_bases {
        let available: Vec<_> = inventory.difference(&selected).cloned().collect();
        let mut expected = BTreeSet::new();
        for (index, id) in available.iter().enumerate() {
            expected.insert(BTreeSet::from([id.clone()]));
            for other in available.iter().skip(index + 1) {
                expected.insert(BTreeSet::from([id.clone(), other.clone()]));
            }
        }
        if groups.get(&selected) != Some(&expected) {
            return Err(invalid());
        }
    }
    Ok(())
}
