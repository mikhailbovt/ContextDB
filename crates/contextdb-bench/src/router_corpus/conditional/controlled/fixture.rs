//! Materialize exact originals, explicit residents and complete candidate graph.

use super::super::fixture::{
    self as common, Original, Provider, interval, marker, message, stable_uuid, unit_key, wrap,
};
use super::*;
use contextdb_core::{ContextPackId, OriginalSourceSpan, TemporalConstraint};
use contextdb_recall::{
    AccessConsent, AccessRule, ProviderSnapshot, RecallPrincipal, RecallSensitivity,
    RecallWatermarks,
};

pub(super) struct Case {
    pub(super) id: String,
    pub(super) domain: String,
    cutoff: u64,
    request: CompileAssemblyRequest,
    provider: Provider,
    originals: BTreeMap<ObservationId, Original>,
    sources: BTreeMap<String, ProviderEvidence>,
    source_ids: BTreeMap<String, BlockId>,
}
impl Case {
    pub(super) fn compiler_input(&self) -> collector::CompileCase<'_> {
        collector::CompileCase {
            id: &self.id,
            domain: &self.domain,
            known_at: self.cutoff,
            request: &self.request,
            provider: &self.provider,
            exploration: &collector::Exploration::ControlledStopV4,
        }
    }
    pub(super) fn intervals(&self) -> Result<BTreeMap<String, SourceInterval>> {
        self.sources
            .iter()
            .map(|(id, source)| {
                Ok((
                    id.clone(),
                    interval(source.evidence.original_span.as_ref().ok_or_else(invalid)?),
                ))
            })
            .collect()
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
    seed: &OriginalSeed,
    budget: &mut QueryBudget,
) -> Result<ProviderEvidence> {
    let (_, class, taint) = role(&seed.role)?;
    let mut source = common::source(
        domain,
        access,
        &stable_uuid(&seed.id).to_string(),
        &seed.text,
        seed.known_at,
        budget,
    )?;
    source.evidence.source_class = class;
    source.evidence.taints = BTreeSet::from([taint]);
    Ok(source)
}

fn retain(
    originals: &mut BTreeMap<ObservationId, Original>,
    source: &ProviderEvidence,
    seed: &OriginalSeed,
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
                text: seed.text.clone(),
                known_at: seed.known_at,
            },
        )
        .is_some()
    {
        return Err(invalid());
    }
    Ok(span)
}

pub(super) fn build(history: &History, probe: &Probe, budget: &mut QueryBudget) -> Result<Case> {
    let id = history.case_id(probe);
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
    let mut candidates = vec![wrap(
        &access,
        marker(
            &scope,
            "situation",
            history.cutoff,
            PackBlockKind::Situation,
            "Current conversation task.",
            "question",
            &history.query,
        )?,
    )];
    let mut originals = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for seed in &history.originals {
        let source = source(&domain, &access, seed, budget)?;
        retain(&mut originals, &source, seed)?;
        sources.insert(seed.id.clone(), source);
    }
    let mut evidence = Vec::new();
    let mut source_ids = BTreeMap::new();
    for name in &history.candidate_source_ids {
        let seed = history.original(name)?;
        let source = sources.get(name).ok_or_else(invalid)?;
        let (_, class, taint) = role(&seed.role)?;
        let mut candidate = marker(
            &scope,
            &unit_key(&domain, name),
            seed.known_at,
            PackBlockKind::RawObservation,
            "Original source occurrence.",
            "speaker",
            &seed.role,
        )?;
        candidate.mandatory = false;
        candidate.trust = ContentTrust::Untrusted;
        candidate.source_class = class;
        candidate.taints.insert(taint);
        candidate.interpretation = InterpretationRule::HistoricalData;
        candidate
            .evidence_handles
            .insert(source.evidence.id.clone());
        source_ids.insert(name.clone(), candidate.id.clone());
        candidates.push(wrap(&access, candidate));
        evidence.push(source.clone());
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
    let mut resident: BTreeSet<_> = probe
        .resident_source_ids
        .iter()
        .map(String::as_str)
        .collect();
    for binding in &history.tool_bindings {
        if resident.contains(binding.result_source_id.as_str()) {
            resident.insert(&binding.call_source_id);
        }
    }
    let mut hot = Vec::new();
    for seed in history
        .originals
        .iter()
        .filter(|seed| resident.contains(seed.id.as_str()))
    {
        let source = sources.get(&seed.id).ok_or_else(invalid)?;
        let span = source.evidence.original_span.as_ref().ok_or_else(invalid)?;
        let mut item = message(
            &format!("resident:{}", stable_uuid(&seed.id)),
            span,
            &seed.text,
            OutgoingZone::HotHistory,
            role(&seed.role)?.0,
        )?;
        for binding in &history.tool_bindings {
            if binding.call_source_id == seed.id {
                item.tool_calls.push(binding.tool_call_id.clone());
            }
            if binding.result_source_id == seed.id {
                item.tool_result = Some(binding.tool_call_id.clone());
            }
        }
        hot.push(item);
    }
    let mut current_sources = Vec::new();
    for (id, text) in [("working", &history.working), ("query", &history.query)] {
        let seed = OriginalSeed {
            id: id.into(),
            role: "user".into(),
            text: text.clone(),
            known_at: history.cutoff,
        };
        let source = source(&domain, &access, &seed, budget)?;
        current_sources.push(retain(&mut originals, &source, &seed)?);
    }
    let mut control = vec![OutgoingMessage { id: BlockId::new("control").map_err(|_| invalid())?,
        zone: OutgoingZone::Control, role: OutgoingRole::System,
        text: "Answer from attributed conversation data; preserve unresolved conflicts and missing information.".into(),
        originals: Vec::new(), tool_calls: Vec::new(), tool_result: None }];
    if !history.tool_bindings.is_empty() {
        control.push(OutgoingMessage {
            id: BlockId::new("tool-definition").map_err(|_| invalid())?,
            zone: OutgoingZone::ToolDefinitions,
            role: OutgoingRole::System,
            text: "Available tool: inspect_original.".into(),
            originals: Vec::new(),
            tool_calls: Vec::new(),
            tool_result: None,
        });
    }
    let snapshot = ProviderSnapshot {
        database_id: domain.clone(),
        commit_seq: history.cutoff,
        watermarks: RecallWatermarks {
            journal: history.cutoff,
            semantic: history.cutoff,
            lexical: history.cutoff,
            vector: BTreeMap::new(),
            graph: history.cutoff,
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
            snapshot: format!("{domain}:{}", history.cutoff),
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
            filter_digest: "synthetic:controlled-full-source-frontier.v4".into(),
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
                id: "synthetic-controlled-reference-v4".into(),
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
                &current_sources[0],
                &history.working,
                OutgoingZone::WorkingState,
                OutgoingRole::User,
            )?],
            hot,
            current: vec![message(
                "current-query",
                &current_sources[1],
                &history.query,
                OutgoingZone::CurrentTurn,
                OutgoingRole::User,
            )?],
        },
        budget: OutgoingBudget {
            max_input_tokens: 27000,
            safety_tokens: 1000,
            max_wire_bytes: MAX_CONDITIONAL_INPUT_BYTES as u32,
        },
    };
    Ok(Case {
        id,
        domain,
        cutoff: history.cutoff,
        request,
        provider,
        originals,
        sources,
        source_ids,
    })
}

pub(super) fn lineage(
    history: &History,
    case: &Case,
    seed_sha256: &str,
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
            version: Some(format!("seed:{seed_sha256}:v4")),
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
        if original.known_at == 0 || original.known_at > history.cutoff {
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
    rows: &[Observation],
    budget: &mut QueryBudget,
) -> Result<()> {
    let inventory: BTreeSet<_> = case.source_ids.values().cloned().collect();
    let mut expected = BTreeSet::new();
    let ids: Vec<_> = inventory.iter().cloned().collect();
    for (index, id) in ids.iter().enumerate() {
        expected.insert(BTreeSet::from([id.clone()]));
        for other in ids.iter().skip(index + 1) {
            expected.insert(BTreeSet::from([id.clone(), other.clone()]));
        }
    }
    let mut seen = BTreeSet::new();
    let mut bases = BTreeSet::new();
    for row in rows {
        charge(budget, 1, 0)?;
        if !row.outgoing_fits
            || !expected.contains(&row.seed_ids)
            || !seen.insert(row.seed_ids.clone())
            || row.closure_ids != row.seed_ids
            || row
                .selected
                .pack
                .sections
                .iter()
                .any(|block| inventory.contains(&block.id))
        {
            return Err(invalid());
        }
        bases.insert(row.selected_base_digest);
    }
    if seen != expected || rows.len() != 10 || bases.len() != 1 {
        return Err(invalid());
    }
    Ok(())
}
