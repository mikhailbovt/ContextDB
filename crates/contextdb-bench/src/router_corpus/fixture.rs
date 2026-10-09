//! Built-in synthetic originals; this is not an intake path for private traces.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::router::RoutedAssembly;
use contextdb_context::*;
use contextdb_core::{
    AcceptanceState, ConflictState, ContentDigest, ContextPackId, EpistemicBasis, EpistemicState,
    LifecycleState, ObservationId, OriginalSourceSpan, PolicyDecision, TemporalConstraint,
};
use contextdb_recall::{
    AccessConsent, AccessRule, ProviderSnapshot, QueryBudget, RecallPrincipal, RecallSensitivity,
    RecallWatermarks,
};

use super::RouterQuerySpec;
use crate::{ContinuousTarget, continuous_history};

pub(crate) const GENERATOR: &str = "contextdb.router-synthetic.v1";

#[derive(Clone, Copy, Debug)]
pub(crate) enum Scenario {
    EarlyCode,
    CorrectedCode,
    LocalConstraint,
    Complement,
    MultiMemory,
    NoMemory,
    EnglishCode,
    ResidentCode,
}

pub(crate) const SCENARIOS: [Scenario; 8] = [
    Scenario::EarlyCode,
    Scenario::CorrectedCode,
    Scenario::LocalConstraint,
    Scenario::Complement,
    Scenario::MultiMemory,
    Scenario::NoMemory,
    Scenario::EnglishCode,
    Scenario::ResidentCode,
];

/// Evaluation stays separate from the query projection used by the provider.
pub(crate) struct BuiltinRouterCase {
    pub(crate) query: RouterQuerySpec,
    pub(crate) routed: RoutedAssembly,
    pub(crate) base: OutgoingBase,
    pub(crate) evaluation: ContinuousTarget,
    pub(crate) originals: BTreeMap<ObservationId, (String, u64)>,
    pub(crate) fixture_id: String,
}

pub(crate) fn build_case(
    group: u32,
    scenario: Scenario,
    budget: &mut QueryBudget,
) -> crate::Result<BuiltinRouterCase> {
    if group >= 4 {
        return Err(crate::BenchError::InvalidConfiguration {
            field: "router corpus groups",
            reason: "at most four built-in groups".into(),
        });
    }
    budget.charge(1, 0).map_err(|_| invalid())?;
    let history = continuous_history(0);
    let offset = u64::from(group) * 100;
    let scope = format!("synthetic:atlas:{group}");
    let domain = format!("synthetic:router-domain:{group}");
    let fixture_id = format!("group-{group}-{scenario:?}");
    let entity = ["Atlas", "Boreal", "Cygnus", "Delta"][group as usize];
    let initial_code = (7319 + group * 37).to_string();
    let corrected_code = (8426 + group * 41).to_string();
    let (query_text, at, evidence_ids, answer) = match scenario {
        Scenario::EarlyCode => ("Какой код Atlas?", 3, vec!["atlas-code"], "7319"),
        Scenario::CorrectedCode => (
            "Какой код Atlas сейчас?",
            4,
            vec!["atlas-correction"],
            "8426",
        ),
        Scenario::LocalConstraint => (
            "Можно ли хранить Atlas в облаке?",
            4,
            vec!["atlas-local"],
            "только локально",
        ),
        Scenario::Complement | Scenario::MultiMemory => (
            "Назови исходный код Atlas и правило хранения.",
            3,
            vec!["atlas-code", "atlas-local"],
            "7319; только локально",
        ),
        Scenario::NoMemory => ("Напиши слово: привет.", 3, vec![], "привет"),
        Scenario::EnglishCode => (
            "What was the original Atlas safe code?",
            3,
            vec!["atlas-code"],
            "7319",
        ),
        Scenario::ResidentCode => (
            "Повтори исходный код Atlas из текущего окна.",
            3,
            vec!["atlas-code"],
            "7319",
        ),
    };
    let query_text = query_text.replace("Atlas", entity);
    let answer = answer
        .replace("7319", &initial_code)
        .replace("8426", &corrected_code);
    let evaluation = ContinuousTarget {
        id: fixture_id.clone(),
        query: query_text.clone(),
        scope: scope.clone(),
        known_at: offset + at,
        evidence_ids: evidence_ids.into_iter().map(str::to_owned).collect(),
        answer,
    };
    // Only this query-only projection crosses into the compiler/provider input.
    let query = RouterQuerySpec::from_target(&evaluation, &domain, budget)?;
    let access = AccessRule {
        workspace: format!("synthetic:workspace:{group}"),
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
    let mut candidates = vec![situation(&access, query.known_at, &query_text)?];
    let mut evidence = Vec::new();
    let mut originals = BTreeMap::new();
    let mut original_labels = BTreeMap::new();
    let mut resident = Vec::new();
    for event in history
        .events
        .iter()
        .filter(|event| event.scope == "atlas" && event.known_at <= at)
    {
        budget
            .charge(1, event.text.len() as u64)
            .map_err(|_| invalid())?;
        let event_text = event
            .text
            .replace("Atlas", entity)
            .replace("7319", &initial_code)
            .replace("8426", &corrected_code);
        let mut source = source(&domain, &access, &event.id, &event_text)?;
        if event.speaker == "assistant" {
            source.evidence.source_class = SourceClass::ModelGenerated;
            source.evidence.taints = BTreeSet::from([ContentTaint::Generated]);
        }
        let span = source.evidence.original_span.as_ref().ok_or_else(invalid)?;
        originals.insert(span.event_id, event_text.as_bytes().to_vec());
        original_labels.insert(span.event_id, (event.id.clone(), offset + event.known_at));
        if matches!(scenario, Scenario::ResidentCode) {
            resident.push(OutgoingMessage {
                id: BlockId::new(format!("hot:{}", event.id)).map_err(|_| invalid())?,
                zone: OutgoingZone::HotHistory,
                role: if event.speaker == "assistant" {
                    OutgoingRole::Assistant
                } else {
                    OutgoingRole::User
                },
                text: event_text.clone(),
                originals: vec![VisibleOriginal {
                    span: span.clone(),
                    text_start: 0,
                    text_end: event_text.len() as u64,
                }],
                tool_calls: Vec::new(),
                tool_result: None,
            });
        }
        let mut candidate = raw_candidate(
            &access,
            &event.id,
            offset + event.known_at,
            &source.evidence,
        )?;
        candidate.candidate.representations[0]
            .fields
            .insert("speaker".into(), event.speaker.clone());
        candidates.push(candidate);
        evidence.push(source);
    }
    let query_source_id = format!("query:{fixture_id}");
    let query_source = source(&domain, &access, &query_source_id, &query.query)?;
    let query_span = query_source.evidence.original_span.ok_or_else(invalid)?;
    originals.insert(query_span.event_id, query.query.as_bytes().to_vec());
    original_labels.insert(query_span.event_id, (query_source_id, query.known_at));
    let snapshot = ProviderSnapshot {
        database_id: domain,
        commit_seq: query.known_at,
        watermarks: RecallWatermarks {
            journal: query.known_at,
            semantic: query.known_at,
            lexical: query.known_at,
            vector: BTreeMap::new(),
            graph: query.known_at,
            hierarchy: BTreeMap::new(),
        },
    };
    let provider = SyntheticProvider {
        data: InMemoryContextProvider::new(snapshot.clone(), candidates, evidence)
            .map_err(|_| invalid())?,
        originals,
        scope: scope.clone(),
        binding: AssemblyBinding {
            snapshot: format!("synthetic:{group}:{}", query.known_at),
            authorization: format!("synthetic:owner:{group}"),
            state: format!("synthetic:scope:{group}"),
            valid_until: None,
        },
    };
    let base = OutgoingBase {
        control: vec![OutgoingMessage {
            id: BlockId::new("control").map_err(|_| invalid())?,
            zone: OutgoingZone::Control,
            role: OutgoingRole::System,
            text: "Answer using source-backed conversation data.".into(),
            originals: Vec::new(),
            tool_calls: Vec::new(),
            tool_result: None,
        }],
        working: Vec::new(),
        hot: resident,
        current: vec![OutgoingMessage {
            id: BlockId::new("current-query").map_err(|_| invalid())?,
            zone: OutgoingZone::CurrentTurn,
            role: OutgoingRole::User,
            text: query_text.clone(),
            originals: vec![VisibleOriginal {
                span: query_span,
                text_start: 0,
                text_end: query_text.len() as u64,
            }],
            tool_calls: Vec::new(),
            tool_result: None,
        }],
    };
    let request = CompileAssemblyRequest {
        context: CompileRequest {
            pack_id: ContextPackId::from_uuid(stable_uuid(&fixture_id)).map_err(|_| invalid())?,
            snapshot,
            principal: RecallPrincipal {
                subject: "synthetic:owner".into(),
                audiences: BTreeSet::new(),
                workspace: access.workspace.clone(),
                scopes: BTreeSet::from([scope.clone()]),
                purpose: "conversation".into(),
                clearance: RecallSensitivity::Confidential,
            },
            filter_digest: "synthetic:permitted-originals:v1".into(),
            purpose: PackPurpose::Conversation,
            scopes: BTreeSet::from([scope]),
            temporal_view: TemporalConstraint::Current,
            required_facets: Vec::new(),
            budgets: ContextBudgets {
                hard_tokens: 12000,
                soft_tokens: 10000,
                max_blocks: 32,
                max_evidence_blocks: 32,
                max_raw_evidence_tokens: 6000,
                max_history_tokens: 6000,
                max_conflict_tokens: 6000,
                max_serialized_bytes: 2 * 1024 * 1024,
                max_selection_evaluations: 128,
            },
            model_profile: profile(),
            explicit_memory_request: true,
            require_primary_evidence: true,
            continuation: None,
        },
        base: base.clone(),
        budget: OutgoingBudget {
            max_input_tokens: 27000,
            safety_tokens: 1000,
            max_wire_bytes: 2 * 1024 * 1024,
        },
    };
    let routed = ContextCompiler::new([7; 32])
        .map_err(|_| invalid())?
        .compile_assembly_with_router(
            &request,
            &provider,
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &R0Scorer,
            budget,
        )
        .map_err(|_| invalid())?;
    Ok(BuiltinRouterCase {
        query,
        routed,
        base,
        evaluation,
        originals: original_labels,
        fixture_id,
    })
}

fn profile() -> ModelProfile {
    ModelProfile {
        id: "synthetic-reference".into(),
        family: "synthetic".into(),
        tokenizer_id: ReferenceTokenizer::ID.into(),
        renderer: RendererKind::Compact,
        max_context_tokens: 32000,
        reserved_output_tokens: 4000,
        preferred_structured_format: StructuredFormat::CompactText,
        supports_tool_results: false,
        supports_native_citations: false,
        supports_prompt_caching: false,
        position_profile: PositionProfile::SmallModelExplicit,
        instruction_hierarchy: InstructionHierarchy::SinglePromptDelimited,
        max_schema_complexity: 64,
        external_processing: false,
    }
}

fn epistemic() -> EpistemicState {
    EpistemicState {
        basis: EpistemicBasis::Observation,
        acceptance: AcceptanceState::Accepted,
        conflict: ConflictState::None,
        lifecycle: LifecycleState::Active,
    }
}

fn situation(access: &AccessRule, known: u64, query: &str) -> crate::Result<ProviderCandidate> {
    let candidate = PackCandidate {
        id: BlockId::new("situation").map_err(|_| invalid())?,
        kind: PackBlockKind::Situation,
        representations: vec![BlockRepresentation {
            level: CompressionLevel::L0Orientation,
            summary: "A synthetic conversation memory query.".into(),
            fields: BTreeMap::from([("intent".into(), query.into())]),
            omitted_facets: BTreeSet::new(),
        }],
        exact_fragments: Vec::new(),
        memory_refs: Vec::new(),
        claim_ids: BTreeSet::new(),
        evidence_handles: BTreeSet::new(),
        facets: BTreeSet::new(),
        scopes: access.scopes.clone(),
        valid_time: None,
        known_at_commit: known,
        perspective: None,
        epistemic: epistemic(),
        confidence_micros: 1000000,
        trust: ContentTrust::TrustedSource,
        instruction_capability: InstructionCapability::None,
        source_class: SourceClass::DeterministicDerivation,
        taints: BTreeSet::new(),
        interpretation: InterpretationRule::FactualData,
        support: SupportState::Supported,
        conflict: None,
        unknown: None,
        utility_micros: 1000000,
        mandatory: true,
    };
    Ok(provider_candidate(access, candidate))
}

fn raw_candidate(
    access: &AccessRule,
    id: &str,
    known: u64,
    evidence: &PackEvidence,
) -> crate::Result<ProviderCandidate> {
    let candidate = PackCandidate {
        id: BlockId::new(format!("raw:{id}")).map_err(|_| invalid())?,
        kind: PackBlockKind::RawObservation,
        representations: vec![BlockRepresentation {
            level: CompressionLevel::L0Orientation,
            summary: format!("Original conversation occurrence: {id}"),
            fields: BTreeMap::new(),
            omitted_facets: BTreeSet::new(),
        }],
        exact_fragments: Vec::new(),
        memory_refs: Vec::new(),
        claim_ids: BTreeSet::new(),
        evidence_handles: BTreeSet::from([evidence.id.clone()]),
        facets: BTreeSet::new(),
        scopes: access.scopes.clone(),
        valid_time: None,
        known_at_commit: known,
        perspective: None,
        epistemic: epistemic(),
        confidence_micros: 1000000,
        trust: ContentTrust::Untrusted,
        instruction_capability: InstructionCapability::None,
        source_class: evidence.source_class.clone(),
        taints: evidence.taints.clone(),
        interpretation: InterpretationRule::HistoricalData,
        support: SupportState::Supported,
        conflict: None,
        unknown: None,
        utility_micros: 850000,
        mandatory: false,
    };
    Ok(provider_candidate(access, candidate))
}

fn provider_candidate(access: &AccessRule, candidate: PackCandidate) -> ProviderCandidate {
    ProviderCandidate {
        access: access.clone(),
        use_policy: CandidateUsePolicy {
            influence: PolicyDecision::Allow,
            mention: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Allow,
            disclosure: DisclosureRule::MayMention,
        },
        candidate,
    }
}

fn source(
    domain: &str,
    access: &AccessRule,
    id: &str,
    text: &str,
) -> crate::Result<ProviderEvidence> {
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
            id: EvidenceHandle::new(format!("evidence:{id}")).map_err(|_| invalid())?,
            source: SourceHandle::new(format!("{domain}/{id}")).map_err(|_| invalid())?,
            selector: EvidenceSelector::TextBytes {
                start: 0,
                end: text.len() as u64,
            },
            excerpt: Some(text.into()),
            claim_ids: BTreeSet::new(),
            provenance_family: format!("{domain}/{id}"),
            primary: true,
            trust_micros: 1000000,
            source_class: SourceClass::UserStatement,
            taints: BTreeSet::from([ContentTaint::UserControlled]),
            lineage: Vec::new(),
            original_span: Some(span),
        },
    })
}

fn stable_uuid(key: &str) -> uuid::Uuid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&blake3::hash(key.as_bytes()).as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

struct SyntheticProvider {
    data: InMemoryContextProvider,
    originals: BTreeMap<ObservationId, Vec<u8>>,
    scope: String,
    binding: AssemblyBinding,
}
impl ContextProvider for SyntheticProvider {
    fn snapshot(&self) -> Result<ProviderSnapshot> {
        self.data.snapshot()
    }
    fn candidate_labels(&self) -> Result<Vec<CandidatePolicyLabel>> {
        self.data.candidate_labels()
    }
    fn materialize_candidate(&self, id: &BlockId) -> Result<PackCandidate> {
        self.data.materialize_candidate(id)
    }
    fn evidence_labels(&self, ids: &[EvidenceHandle]) -> Result<Vec<EvidencePolicyLabel>> {
        self.data.evidence_labels(ids)
    }
    fn materialize_evidence(&self, id: &EvidenceHandle) -> Result<PackEvidence> {
        self.data.materialize_evidence(id)
    }
}
impl std::fmt::Debug for SyntheticProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyntheticProvider")
            .field("originals", &self.originals.len())
            .finish_non_exhaustive()
    }
}
impl AssemblyProvider for SyntheticProvider {
    fn binding(&self) -> Result<AssemblyBinding> {
        Ok(self.binding.clone())
    }
    fn dependencies(&self, _: &BlockId) -> Result<EvidenceDependencies> {
        Ok(EvidenceDependencies::default())
    }
    fn verify_original(
        &self,
        span: &OriginalSourceSpan,
        bytes: &[u8],
        budget: &mut QueryBudget,
    ) -> Result<()> {
        budget
            .charge(1, bytes.len() as u64)
            .map_err(|_| ContextError::BudgetExceeded("synthetic original allowance".into()))?;
        let original = self
            .originals
            .get(&span.event_id)
            .ok_or_else(|| ContextError::Authorization("synthetic original unavailable".into()))?;
        if blake3::hash(original).as_bytes() != span.payload_digest.as_bytes()
            || original.get(span.start as usize..span.end as usize) != Some(bytes)
        {
            return Err(ContextError::Provider("synthetic original mismatch".into()));
        }
        Ok(())
    }
    fn validate_read_set(
        &self,
        read_set: &AssemblyReadSet,
        budget: &mut QueryBudget,
    ) -> Result<()> {
        budget
            .charge(1, 0)
            .map_err(|_| ContextError::BudgetExceeded("synthetic read-set allowance".into()))?;
        if read_set.binding != self.binding
            || read_set.scopes != BTreeSet::from([self.scope.clone()])
        {
            return Err(ContextError::Authorization(
                "synthetic read-set mismatch".into(),
            ));
        }
        Ok(())
    }
}

fn invalid() -> crate::BenchError {
    crate::BenchError::Integrity("built-in router fixture rejected".into())
}
