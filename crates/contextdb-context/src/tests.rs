use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    str::FromStr,
};

use contextdb_core::{
    AcceptanceState, ActorId, ClaimId, ConflictSetId, ConflictState, ContextPackId, EpistemicBasis,
    EpistemicRole, EpistemicState, LifecycleState, MemoryRef, MemorySubjectId, Perspective,
    PolicyDecision, TemporalConstraint,
};
use contextdb_recall::{
    AccessConsent, AccessRule, ProviderSnapshot, RecallPrincipal, RecallSensitivity,
    RecallWatermarks,
};
use proptest::prelude::*;
use serde::Serialize;

use crate::*;

mod continuous;

const WORKSPACE: &str = "ws:test";
const SUBJECT: &str = "subject:alice";
const SCOPE: &str = "project:japan-bar";

fn must<T, E: Debug>(result: std::result::Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn claim(value: u128) -> ClaimId {
    must(ClaimId::from_str(&format!(
        "00000000-0000-4000-8000-{value:012x}"
    )))
}

fn conflict(value: u128) -> ConflictSetId {
    must(ConflictSetId::from_str(&format!(
        "00000000-0000-4000-8001-{value:012x}"
    )))
}

fn pack_id() -> ContextPackId {
    must(ContextPackId::from_str(
        "00000000-0000-4000-8002-000000000001",
    ))
}

fn perspective() -> Perspective {
    Perspective {
        knower: must(MemorySubjectId::from_str(
            "00000000-0000-4000-8003-000000000001",
        )),
        experiencer: None,
        narrator: must(ActorId::from_str("00000000-0000-4000-8004-000000000001")),
        role: EpistemicRole::Asserter,
    }
}

fn snapshot() -> ProviderSnapshot {
    ProviderSnapshot {
        database_id: "db:test".to_owned(),
        commit_seq: 42,
        watermarks: RecallWatermarks {
            journal: 42,
            semantic: 42,
            lexical: 41,
            vector: BTreeMap::from([("text:v1".to_owned(), 40)]),
            graph: 42,
            hierarchy: BTreeMap::new(),
        },
    }
}

fn access(consent: AccessConsent) -> AccessRule {
    AccessRule {
        workspace: WORKSPACE.to_owned(),
        scopes: BTreeSet::from([SCOPE.to_owned()]),
        owners: BTreeSet::from([SUBJECT.to_owned()]),
        audience_purpose_grants: BTreeMap::from([(
            "*".to_owned(),
            BTreeSet::from(["*".to_owned()]),
        )]),
        sensitivity: RecallSensitivity::Internal,
        required_compartments: BTreeSet::new(),
        consent,
        retrievable: true,
    }
}

fn use_policy(disclosure: DisclosureRule) -> CandidateUsePolicy {
    CandidateUsePolicy {
        influence: PolicyDecision::Allow,
        mention: PolicyDecision::Allow,
        external_model_use: PolicyDecision::Allow,
        disclosure,
    }
}

fn purpose_key(purpose: PackPurpose) -> String {
    contextdb_recall::purpose_key(&purpose.core_purpose())
}

fn principal(purpose: PackPurpose) -> RecallPrincipal {
    RecallPrincipal {
        subject: SUBJECT.to_owned(),
        audiences: BTreeSet::new(),
        workspace: WORKSPACE.to_owned(),
        scopes: BTreeSet::from([SCOPE.to_owned()]),
        purpose: purpose_key(purpose),
        clearance: RecallSensitivity::Confidential,
    }
}

fn budgets() -> ContextBudgets {
    ContextBudgets {
        hard_tokens: 20_000,
        soft_tokens: 16_000,
        max_blocks: 64,
        max_evidence_blocks: 64,
        max_raw_evidence_tokens: 4_000,
        max_history_tokens: 8_000,
        max_conflict_tokens: 4_000,
        max_serialized_bytes: 1_000_000,
        max_selection_evaluations: 128,
    }
}

fn profile(renderer: RendererKind) -> ModelProfile {
    let preferred_structured_format = match renderer {
        RendererKind::Compact => StructuredFormat::CompactText,
        RendererKind::HostedStructured => StructuredFormat::ToolResult,
        RendererKind::Chat | RendererKind::Coding => StructuredFormat::Markdown,
        RendererKind::CanonicalJson => StructuredFormat::Json,
    };
    ModelProfile {
        id: format!("profile:{renderer:?}"),
        family: format!("test:{renderer:?}"),
        tokenizer_id: ReferenceTokenizer::ID.to_owned(),
        renderer,
        max_context_tokens: 32_000,
        reserved_output_tokens: 4_000,
        preferred_structured_format,
        supports_tool_results: renderer == RendererKind::HostedStructured,
        supports_native_citations: renderer == RendererKind::HostedStructured,
        supports_prompt_caching: renderer != RendererKind::Compact,
        position_profile: if renderer == RendererKind::Compact {
            PositionProfile::SmallModelExplicit
        } else {
            PositionProfile::EvidenceAdjacent
        },
        instruction_hierarchy: if renderer == RendererKind::Compact {
            InstructionHierarchy::SinglePromptDelimited
        } else {
            InstructionHierarchy::SeparatedChannels
        },
        max_schema_complexity: 64,
        external_processing: false,
    }
}

fn request(purpose: PackPurpose, renderer: RendererKind) -> CompileRequest {
    CompileRequest {
        pack_id: pack_id(),
        snapshot: snapshot(),
        principal: principal(purpose),
        filter_digest: "policy-filter:test:v1".to_owned(),
        purpose,
        scopes: BTreeSet::from([SCOPE.to_owned()]),
        temporal_view: TemporalConstraint::Current,
        required_facets: vec![
            PackFacetRequirement {
                name: "referent".to_owned(),
                minimum_confidence_micros: 900_000,
                require_evidence: false,
            },
            PackFacetRequirement {
                name: "business_status".to_owned(),
                minimum_confidence_micros: 800_000,
                require_evidence: true,
            },
            PackFacetRequirement {
                name: "constraints".to_owned(),
                minimum_confidence_micros: 800_000,
                require_evidence: true,
            },
        ],
        budgets: budgets(),
        model_profile: profile(renderer),
        explicit_memory_request: false,
        require_primary_evidence: true,
        continuation: None,
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

fn representation(
    level: CompressionLevel,
    summary: &str,
    fields: &[(&str, &str)],
) -> BlockRepresentation {
    BlockRepresentation {
        level,
        summary: summary.to_owned(),
        fields: fields
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
        omitted_facets: BTreeSet::new(),
    }
}

fn situation_candidate() -> ProviderCandidate {
    ProviderCandidate {
        access: access(AccessConsent::Granted),
        use_policy: use_policy(DisclosureRule::MayMention),
        candidate: PackCandidate {
            id: must(BlockId::new("situation:japan-bar")),
            kind: PackBlockKind::Situation,
            representations: vec![representation(
                CompressionLevel::L0Orientation,
                "The current question refers to the previously discussed Japan bar concept.",
                &[("intent", "evaluate whether opening it is worthwhile")],
            )],
            exact_fragments: Vec::new(),
            memory_refs: Vec::new(),
            claim_ids: BTreeSet::new(),
            evidence_handles: BTreeSet::new(),
            facets: BTreeSet::from(["referent".to_owned(), "intent".to_owned()]),
            scopes: BTreeSet::from([SCOPE.to_owned()]),
            valid_time: None,
            known_at_commit: 42,
            perspective: None,
            epistemic: epistemic(),
            confidence_micros: 980_000,
            trust: ContentTrust::TrustedSource,
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::DeterministicDerivation,
            taints: BTreeSet::new(),
            interpretation: InterpretationRule::FactualData,
            support: SupportState::Supported,
            conflict: None,
            unknown: None,
            utility_micros: 980_000,
            mandatory: true,
        },
    }
}

fn evidence_for(id: &str, claims: BTreeSet<ClaimId>, excerpt: &str) -> ProviderEvidence {
    ProviderEvidence {
        access: access(AccessConsent::Granted),
        external_model_use: PolicyDecision::Allow,
        evidence: PackEvidence {
            original_span: None,
            id: must(EvidenceHandle::new(id)),
            source: must(SourceHandle::new(format!("source:{id}"))),
            selector: EvidenceSelector::TextBytes {
                start: 0,
                end: u64::try_from(excerpt.len()).unwrap_or(u64::MAX),
            },
            excerpt: Some(excerpt.to_owned()),
            claim_ids: claims,
            provenance_family: format!("family:{id}"),
            primary: true,
            trust_micros: 950_000,
            source_class: SourceClass::UserStatement,
            taints: BTreeSet::from([ContentTaint::UserControlled]),
            lineage: Vec::new(),
        },
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "test fixture builder exposes semantic axes"
)]
fn factual_candidate(
    id: &str,
    kind: PackBlockKind,
    claim_id: ClaimId,
    evidence_id: &str,
    summary: &str,
    facets: &[&str],
    interpretation: InterpretationRule,
    mandatory: bool,
    disclosure: DisclosureRule,
) -> ProviderCandidate {
    ProviderCandidate {
        access: access(AccessConsent::Granted),
        use_policy: use_policy(disclosure),
        candidate: PackCandidate {
            id: must(BlockId::new(id)),
            kind,
            representations: vec![
                representation(
                    CompressionLevel::L2Structured,
                    summary,
                    &[("status", summary)],
                ),
                representation(CompressionLevel::L0Orientation, summary, &[]),
            ],
            exact_fragments: Vec::new(),
            memory_refs: vec![MemoryRef::Claim { id: claim_id }],
            claim_ids: BTreeSet::from([claim_id]),
            evidence_handles: BTreeSet::from([must(EvidenceHandle::new(evidence_id))]),
            facets: facets.iter().map(|value| (*value).to_owned()).collect(),
            scopes: BTreeSet::from([SCOPE.to_owned()]),
            valid_time: None,
            known_at_commit: 42,
            perspective: Some(perspective()),
            epistemic: epistemic(),
            confidence_micros: 910_000,
            trust: ContentTrust::TrustedSource,
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::UserStatement,
            taints: BTreeSet::from([ContentTaint::UserControlled]),
            interpretation,
            support: SupportState::Supported,
            conflict: None,
            unknown: None,
            utility_micros: 850_000,
            mandatory,
        },
    }
}

fn explicit_unknown(id: &str, question: &str, facet: &str) -> ProviderCandidate {
    ProviderCandidate {
        access: access(AccessConsent::Granted),
        use_policy: use_policy(DisclosureRule::MayMention),
        candidate: PackCandidate {
            id: must(BlockId::new(id)),
            kind: PackBlockKind::Unknown,
            representations: vec![representation(
                CompressionLevel::L0Orientation,
                "This input remains unknown.",
                &[("question", question)],
            )],
            exact_fragments: Vec::new(),
            memory_refs: Vec::new(),
            claim_ids: BTreeSet::new(),
            evidence_handles: BTreeSet::new(),
            facets: BTreeSet::from([facet.to_owned()]),
            scopes: BTreeSet::from([SCOPE.to_owned()]),
            valid_time: None,
            known_at_commit: 42,
            perspective: None,
            epistemic: EpistemicState {
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
            support: SupportState::Supported,
            conflict: None,
            unknown: Some(UnknownDescriptor {
                question: question.to_owned(),
                reason: "not established in authorized memory".to_owned(),
                blocking: false,
            }),
            utility_micros: 500_000,
            mandatory: true,
        },
    }
}

fn japan_fixture() -> (Vec<ProviderCandidate>, Vec<ProviderEvidence>) {
    let status = claim(1);
    let boundary = claim(2);
    let preference = claim(3);
    let candidates = vec![
        situation_candidate(),
        factual_candidate(
            "fact:hypothetical",
            PackBlockKind::Fact,
            status,
            "evidence:status",
            "The bar is a hypothetical concept; no opening is established.",
            &["business_status"],
            InterpretationRule::FactualData,
            false,
            DisclosureRule::MayMention,
        ),
        factual_candidate(
            "boundary:short-menu",
            PackBlockKind::Boundary,
            boundary,
            "evidence:boundary",
            "Keep the menu intentionally short.",
            &["constraints"],
            InterpretationRule::ConstraintData,
            true,
            DisclosureRule::UseSilently,
        ),
        factual_candidate(
            "preference:atmosphere",
            PackBlockKind::Preference,
            preference,
            "evidence:preference",
            "Prefer an intimate neighborhood atmosphere over a tourist theme park.",
            &["preferences"],
            InterpretationRule::StyleSignal,
            false,
            DisclosureRule::UseSilently,
        ),
        explicit_unknown("unknown:budget", "What is the available budget?", "budget"),
        explicit_unknown("unknown:location", "Which Japanese city?", "location"),
    ];
    let evidence = vec![
        evidence_for(
            "evidence:status",
            BTreeSet::from([status]),
            "We are only discussing a possible bar in Japan; it is not open.",
        ),
        evidence_for(
            "evidence:boundary",
            BTreeSet::from([boundary]),
            "The menu should stay short rather than trying to serve everything.",
        ),
        evidence_for(
            "evidence:preference",
            BTreeSet::from([preference]),
            "The desired atmosphere is intimate and local, not a tourist attraction.",
        ),
    ];
    (candidates, evidence)
}

fn compile_fixture(
    request: &CompileRequest,
    candidates: Vec<ProviderCandidate>,
    evidence: Vec<ProviderEvidence>,
) -> CompiledContext {
    let provider = must(InMemoryContextProvider::new(
        request.snapshot.clone(),
        candidates,
        evidence,
    ));
    let compiler = must(ContextCompiler::new([7_u8; 32]));
    must(compiler.compile(request, &provider, &ReferenceTokenizer))
}

#[derive(Serialize)]
struct GoldenView<'a> {
    status: PackStatus,
    selected: &'a [BlockId],
    section_counts: [usize; 17],
    evidence: Vec<&'a str>,
    directives: Vec<(&'a str, UseAction)>,
    missing_facets: &'a BTreeSet<String>,
    unresolved_conflicts: usize,
    rendered_tokens: u32,
    canonical_digest: &'a str,
}

#[derive(Serialize)]
struct RendererGolden {
    semantic_ids: Vec<String>,
    rows: Vec<RendererGoldenRow>,
}

#[derive(Serialize)]
struct RendererGoldenRow {
    renderer: RendererKind,
    control_tokens: u32,
    data_tokens: u32,
    total_tokens: u32,
    control_digest: String,
    data_digest: String,
}

fn golden_view(compiled: &CompiledContext) -> GoldenView<'_> {
    let sections = &compiled.pack.sections;
    GoldenView {
        status: compiled.pack.status,
        selected: &compiled.pack.compilation.selected_blocks,
        section_counts: [
            sections.situation.len(),
            sections.self_context.len(),
            sections.participants.len(),
            sections.shared_history.len(),
            sections.episodes.len(),
            sections.facts.len(),
            sections.relationships.len(),
            sections.preferences.len(),
            sections.boundaries.len(),
            sections.goals.len(),
            sections.decisions.len(),
            sections.timeline.len(),
            sections.procedures.len(),
            sections.constraints.len(),
            sections.open_loops.len(),
            sections.conflicts.len(),
            sections.unknowns.len(),
        ],
        evidence: compiled
            .pack
            .evidence
            .iter()
            .map(|item| item.id.as_str())
            .collect(),
        directives: compiled
            .pack
            .use_directives
            .iter()
            .map(|item| (item.block_id.as_str(), item.action))
            .collect(),
        missing_facets: &compiled.pack.compilation.sufficiency.missing_facets,
        unresolved_conflicts: compiled
            .pack
            .compilation
            .sufficiency
            .unresolved_conflicts
            .len(),
        rendered_tokens: compiled.pack.compilation.usage.rendered_tokens,
        canonical_digest: &compiled.canonical_digest,
    }
}

#[test]
fn japan_bar_implicit_question_compiles_to_deterministic_golden() {
    let request = request(PackPurpose::Conversation, RendererKind::Chat);
    let (candidates, evidence) = japan_fixture();
    let first = compile_fixture(&request, candidates.clone(), evidence.clone());
    let mut reversed_candidates = candidates;
    reversed_candidates.reverse();
    let mut reversed_evidence = evidence;
    reversed_evidence.reverse();
    let second = compile_fixture(&request, reversed_candidates, reversed_evidence);
    assert_eq!(first, second);

    let actual = must(serde_json::to_string_pretty(&golden_view(&first)));
    let expected = include_str!("../tests/fixtures/japan_bar_golden.json").replace("\r\n", "\n");
    let expected = expected.trim();
    assert_eq!(actual, expected);
}

#[test]
fn canonical_json_and_protobuf_round_trip_without_semantic_drift() {
    let request = request(PackPurpose::Conversation, RendererKind::CanonicalJson);
    let (candidates, evidence) = japan_fixture();
    let compiled = compile_fixture(&request, candidates, evidence);
    assert_eq!(
        must(CanonicalSerializer::from_json(&compiled.canonical_json)),
        compiled.pack
    );
    assert_eq!(
        must(CanonicalSerializer::from_protobuf(
            &compiled.canonical_protobuf
        )),
        compiled.pack
    );
    assert_eq!(
        must(CanonicalSerializer::digest(&compiled.pack)),
        compiled.canonical_digest
    );
}

#[test]
fn recall_adapter_materializes_only_the_selected_snapshot_bound_subgraph() {
    let mut request = request(PackPurpose::Conversation, RendererKind::Compact);
    request.required_facets.truncate(1);
    let selected = situation_candidate();
    let selected_document = must(contextdb_recall::DocumentId::new(
        selected.candidate.id.as_str(),
    ));
    let optional_claim = claim(77);
    let unselected = factual_candidate(
        "fact:unselected",
        PackBlockKind::Fact,
        optional_claim,
        "evidence:unselected",
        "This relevant-looking memory was not selected by recall.",
        &["referent"],
        InterpretationRule::FactualData,
        true,
        DisclosureRule::MayMention,
    );
    let provider = must(InMemoryContextProvider::new(
        request.snapshot.clone(),
        vec![selected, unselected],
        vec![evidence_for(
            "evidence:unselected",
            BTreeSet::from([optional_claim]),
            "unselected",
        )],
    ));
    let recall = contextdb_recall::DeterministicRecallResult {
        status: contextdb_recall::RecallStatus::Complete,
        snapshot: Some(request.snapshot.clone()),
        gate: contextdb_recall::MemoryGateDecision {
            run_recall: true,
            depth: contextdb_recall::RecallDepth::Hot,
            reasons: vec![contextdb_recall::GateReason::ActiveReferent],
            mandatory_facets: BTreeSet::from(["referent".to_owned()]),
            preferred_routes: vec![contextdb_recall::RecallRoute::ActiveContext],
        },
        items: vec![contextdb_recall::RecallItem {
            document_id: selected_document,
            kind: contextdb_recall::RecallDocumentKind::Observation,
            content: Some("authorized marker".to_owned()),
            score: contextdb_recall::ScoreBreakdown {
                rrf_micros: 1,
                activation_micros: 1,
                modifier_micros: 1,
                final_micros: 3,
                routes: Vec::new(),
            },
            covered_facets: BTreeSet::from(["referent".to_owned()]),
            use_decision: contextdb_recall::MemoryUseDecision::IncludeSilently,
            estimated_tokens: 8,
        }],
        evidence: Vec::new(),
        sufficiency: contextdb_recall::SufficiencyReport {
            sufficient: true,
            covered_facets: BTreeSet::from(["referent".to_owned()]),
            missing_facets: BTreeSet::new(),
            unresolved_conflicts: BTreeSet::new(),
            unsupported_documents: BTreeSet::new(),
            confidence_micros: 990_000,
        },
        stop_reason: contextdb_recall::StopReason::Sufficient,
        usage: contextdb_recall::BudgetUsage::default(),
        trace: contextdb_recall::RecallTrace {
            plan_version: contextdb_recall::PLAN_VERSION.to_owned(),
            filter_digest: request.filter_digest.clone(),
            snapshot: Some(request.snapshot.clone()),
            steps: Vec::new(),
        },
        continuation: None,
        freshness_warnings: Vec::new(),
    };
    let binding = must(RecallContextBinding::identity(&recall));
    let compiler = must(ContextCompiler::new([3_u8; 32]));
    let compiled =
        must(compiler.compile_recall(&request, &recall, &binding, &provider, &ReferenceTokenizer));
    assert_eq!(compiled.pack.sections.situation.len(), 1);
    assert!(compiled.pack.sections.facts.is_empty());
    assert_eq!(
        compiled.pack.use_directives[0].action,
        UseAction::UseSilently
    );

    let mut changed_filter = request;
    changed_filter.filter_digest = "other-policy".to_owned();
    assert!(matches!(
        compiler.compile_recall(
            &changed_filter,
            &recall,
            &binding,
            &provider,
            &ReferenceTokenizer,
        ),
        Err(ContextError::Authorization(_))
    ));
}

#[derive(Debug)]
struct PolicyProbeProvider {
    snapshot: ProviderSnapshot,
    allowed: ProviderCandidate,
    denied: ProviderCandidate,
    allowed_evidence: ProviderEvidence,
    denied_materializations: Cell<u32>,
}

impl ContextProvider for PolicyProbeProvider {
    fn snapshot(&self) -> Result<ProviderSnapshot> {
        Ok(self.snapshot.clone())
    }

    fn candidate_labels(&self) -> Result<Vec<CandidatePolicyLabel>> {
        Ok(vec![
            CandidatePolicyLabel {
                id: self.allowed.candidate.id.clone(),
                access: self.allowed.access.clone(),
                use_policy: self.allowed.use_policy,
            },
            CandidatePolicyLabel {
                id: self.denied.candidate.id.clone(),
                access: self.denied.access.clone(),
                use_policy: self.denied.use_policy,
            },
        ])
    }

    fn materialize_candidate(&self, id: &BlockId) -> Result<PackCandidate> {
        if id == &self.denied.candidate.id {
            self.denied_materializations
                .set(self.denied_materializations.get().saturating_add(1));
            return Err(ContextError::Provider(
                "forbidden payload was materialized".to_owned(),
            ));
        }
        Ok(self.allowed.candidate.clone())
    }

    fn evidence_labels(&self, requested: &[EvidenceHandle]) -> Result<Vec<EvidencePolicyLabel>> {
        Ok(requested
            .iter()
            .map(|id| EvidencePolicyLabel {
                id: id.clone(),
                access: self.allowed_evidence.access.clone(),
                external_model_use: PolicyDecision::Allow,
            })
            .collect())
    }

    fn materialize_evidence(&self, _: &EvidenceHandle) -> Result<PackEvidence> {
        Ok(self.allowed_evidence.evidence.clone())
    }
}

#[test]
fn authorization_precedes_payload_and_forbidden_candidate_is_output_invariant() {
    let mut request = request(PackPurpose::Conversation, RendererKind::Compact);
    request.required_facets.truncate(1);
    let allowed = situation_candidate();
    let denied = ProviderCandidate {
        access: access(AccessConsent::Denied),
        use_policy: use_policy(DisclosureRule::MayMention),
        candidate: PackCandidate {
            id: must(BlockId::new("forbidden:malformed")),
            kind: PackBlockKind::Fact,
            representations: vec![representation(
                CompressionLevel::L4Raw,
                &"TOP SECRET ".repeat(10_000),
                &[],
            )],
            exact_fragments: Vec::new(),
            memory_refs: Vec::new(),
            claim_ids: BTreeSet::new(),
            evidence_handles: BTreeSet::new(),
            facets: BTreeSet::new(),
            scopes: BTreeSet::new(),
            valid_time: None,
            known_at_commit: u64::MAX,
            perspective: None,
            epistemic: epistemic(),
            confidence_micros: u32::MAX,
            trust: ContentTrust::TrustedSource,
            instruction_capability: InstructionCapability::HostTrusted,
            source_class: SourceClass::UserStatement,
            taints: BTreeSet::new(),
            interpretation: InterpretationRule::FactualData,
            support: SupportState::Supported,
            conflict: None,
            unknown: None,
            utility_micros: u64::MAX,
            mandatory: true,
        },
    };
    let dummy_claim = claim(88);
    let probe = PolicyProbeProvider {
        snapshot: request.snapshot.clone(),
        allowed: allowed.clone(),
        denied,
        allowed_evidence: evidence_for("evidence:unused", BTreeSet::from([dummy_claim]), "unused"),
        denied_materializations: Cell::new(0),
    };
    let compiler = must(ContextCompiler::new([9_u8; 32]));
    let with_forbidden = must(compiler.compile(&request, &probe, &ReferenceTokenizer));
    assert_eq!(probe.denied_materializations.get(), 0);
    let baseline = compile_fixture(&request, vec![allowed], Vec::new());
    assert_eq!(with_forbidden.pack, baseline.pack);
    assert_eq!(with_forbidden.rendered, baseline.rendered);
    assert_eq!(with_forbidden.canonical_digest, baseline.canonical_digest);
}

#[test]
fn independently_forbidden_evidence_cannot_affect_pack_or_trace() {
    let mut request = request(PackPurpose::Conversation, RendererKind::Compact);
    request.required_facets = vec![PackFacetRequirement {
        name: "business_status".to_owned(),
        minimum_confidence_micros: 800_000,
        require_evidence: true,
    }];
    let status = claim(1);
    let candidate = factual_candidate(
        "fact:hypothetical",
        PackBlockKind::Fact,
        status,
        "evidence:status",
        "The bar remains hypothetical.",
        &["business_status"],
        InterpretationRule::FactualData,
        true,
        DisclosureRule::MayMention,
    );
    let mut denied = evidence_for(
        "evidence:status",
        BTreeSet::new(),
        &"forbidden evidence payload ".repeat(5_000),
    );
    denied.access.consent = AccessConsent::Denied;
    denied.evidence.trust_micros = u32::MAX;
    let with_denied = compile_fixture(&request, vec![candidate.clone()], vec![denied]);
    let without_evidence = compile_fixture(&request, vec![candidate], Vec::new());
    assert_eq!(with_denied, without_evidence);
    assert!(with_denied.pack.sections.facts.is_empty());
    assert_eq!(with_denied.pack.status, PackStatus::NoMemory);
}

#[test]
fn unresolved_conflict_and_unknown_remain_first_class_and_block_sufficiency() {
    let mut request = request(PackPurpose::Knowledge, RendererKind::HostedStructured);
    request.required_facets = vec![PackFacetRequirement {
        name: "database".to_owned(),
        minimum_confidence_micros: 800_000,
        require_evidence: true,
    }];
    let postgres = claim(10);
    let redis = claim(11);
    let set_id = conflict(1);
    let evidence_id = "evidence:db-conflict";
    let mut fact = factual_candidate(
        "fact:postgres",
        PackBlockKind::Fact,
        postgres,
        evidence_id,
        "The current database may be PostgreSQL.",
        &["database"],
        InterpretationRule::HypothesisOnly,
        false,
        DisclosureRule::MayMention,
    );
    fact.candidate.epistemic.conflict = ConflictState::InConflict { set_id };
    let conflict_candidate = ProviderCandidate {
        access: access(AccessConsent::Granted),
        use_policy: use_policy(DisclosureRule::MayMention),
        candidate: PackCandidate {
            id: must(BlockId::new("conflict:database")),
            kind: PackBlockKind::Conflict,
            representations: vec![representation(
                CompressionLevel::L2Structured,
                "PostgreSQL and Redis remain competing historical/current interpretations.",
                &[("resolution", "unresolved")],
            )],
            exact_fragments: Vec::new(),
            memory_refs: vec![
                MemoryRef::Claim { id: postgres },
                MemoryRef::Claim { id: redis },
            ],
            claim_ids: BTreeSet::from([postgres, redis]),
            evidence_handles: BTreeSet::from([must(EvidenceHandle::new(evidence_id))]),
            facets: BTreeSet::from(["database".to_owned()]),
            scopes: BTreeSet::from([SCOPE.to_owned()]),
            valid_time: None,
            known_at_commit: 42,
            perspective: Some(perspective()),
            epistemic: epistemic(),
            confidence_micros: 900_000,
            trust: ContentTrust::Mixed,
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::SharedConversation,
            taints: BTreeSet::new(),
            interpretation: InterpretationRule::ConflictAlternatives,
            support: SupportState::Supported,
            conflict: Some(ConflictDescriptor {
                set_id,
                alternatives: BTreeSet::from([postgres, redis]),
                resolution: ConflictResolution::Unresolved,
                blocking: true,
            }),
            unknown: None,
            utility_micros: 990_000,
            mandatory: true,
        },
    };
    let evidence = evidence_for(
        evidence_id,
        BTreeSet::from([postgres, redis]),
        "One source says PostgreSQL while another retained Redis history.",
    );
    let compiled = compile_fixture(
        &request,
        vec![situation_candidate(), fact, conflict_candidate],
        vec![evidence],
    );
    assert_eq!(compiled.pack.sections.conflicts.len(), 1);
    assert_eq!(
        compiled.pack.compilation.sufficiency.unresolved_conflicts,
        BTreeSet::from([set_id])
    );
    assert!(!compiled.pack.compilation.sufficiency.sufficient);
    assert_eq!(compiled.pack.status, PackStatus::Partial);
}

#[test]
fn missing_required_facet_emits_explicit_unknown_not_a_guess() {
    let mut request = request(PackPurpose::Knowledge, RendererKind::Compact);
    request.required_facets = vec![PackFacetRequirement {
        name: "visa_requirements".to_owned(),
        minimum_confidence_micros: 900_000,
        require_evidence: true,
    }];
    let compiled = compile_fixture(&request, Vec::new(), Vec::new());
    assert_eq!(compiled.pack.status, PackStatus::NoMemory);
    assert_eq!(compiled.pack.sections.unknowns.len(), 1);
    assert_eq!(
        compiled.pack.compilation.sufficiency.missing_facets,
        BTreeSet::from(["visa_requirements".to_owned()])
    );
    assert!(
        compiled
            .pack
            .compilation
            .sufficiency
            .blocking_unknowns
            .len()
            == 1
    );
}

#[test]
fn hard_token_budget_fails_closed_without_mid_block_truncation() {
    let mut request = request(PackPurpose::Conversation, RendererKind::Compact);
    request.budgets.hard_tokens = 8;
    request.budgets.soft_tokens = 8;
    let (candidates, evidence) = japan_fixture();
    let provider = must(InMemoryContextProvider::new(
        request.snapshot.clone(),
        candidates,
        evidence,
    ));
    let compiler = must(ContextCompiler::new([7_u8; 32]));
    let error = compiler.compile(&request, &provider, &ReferenceTokenizer);
    assert!(matches!(error, Err(ContextError::BudgetExceeded(_))));
}

#[test]
fn exact_fragments_survive_structural_compression_verbatim() {
    let mut request = request(PackPurpose::Action, RendererKind::Coding);
    request.required_facets = vec![PackFacetRequirement {
        name: "command".to_owned(),
        minimum_confidence_micros: 800_000,
        require_evidence: true,
    }];
    let command_claim = claim(20);
    let mut command = factual_candidate(
        "procedure:migrate",
        PackBlockKind::Procedure,
        command_claim,
        "evidence:command",
        "Run the exact verified migration command.",
        &["command"],
        InterpretationRule::ConstraintData,
        true,
        DisclosureRule::UseSilently,
    );
    command.candidate.exact_fragments = vec![ExactFragment {
        label: "command".to_owned(),
        value: "cargo run -- migrate --check-only".to_owned(),
    }];
    let compiled = compile_fixture(
        &request,
        vec![situation_candidate(), command],
        vec![evidence_for(
            "evidence:command",
            BTreeSet::from([command_claim]),
            "Verified command: cargo run -- migrate --check-only",
        )],
    );
    let block = &compiled.pack.sections.procedures[0];
    assert_eq!(block.representation.level, CompressionLevel::L0Orientation);
    assert_eq!(
        block.exact_fragments[0].value,
        "cargo run -- migrate --check-only"
    );
    assert!(
        compiled
            .rendered
            .untrusted_data
            .contains("cargo run -- migrate --check-only")
    );
}

#[test]
fn instruction_data_separation_is_enforced_in_every_renderer() {
    let renderers = [
        RendererKind::Compact,
        RendererKind::HostedStructured,
        RendererKind::Chat,
        RendererKind::Coding,
        RendererKind::CanonicalJson,
    ];
    for renderer in renderers {
        let request = request(PackPurpose::Conversation, renderer);
        let (candidates, evidence) = japan_fixture();
        let compiled = compile_fixture(&request, candidates, evidence);
        assert!(
            compiled
                .rendered
                .trusted_control
                .contains("instruction_capability")
        );
        assert!(
            !compiled
                .rendered
                .trusted_control
                .contains("tourist theme park")
        );
        for block in compiled.pack.sections.iter() {
            assert_eq!(block.instruction_capability, InstructionCapability::None);
            assert!(compiled.rendered.untrusted_data.contains(block.id.as_str()));
        }
        assert!(
            compiled.pack.compilation.usage.rendered_tokens
                <= compiled.pack.compilation.budget.hard_tokens
        );
    }
}

#[test]
fn exact_evidence_is_adjacent_to_the_block_it_supports() {
    let request = request(PackPurpose::Conversation, RendererKind::Chat);
    let (candidates, evidence) = japan_fixture();
    let compiled = compile_fixture(&request, candidates, evidence);
    for renderer in [
        RendererKind::Compact,
        RendererKind::HostedStructured,
        RendererKind::Chat,
        RendererKind::Coding,
    ] {
        let rendered = must(ContextRenderer::render(
            &compiled.pack,
            &profile(renderer),
            &ReferenceTokenizer,
        ));
        let lines: Vec<_> = rendered.untrusted_data.lines().collect();
        for block in compiled
            .pack
            .sections
            .iter()
            .filter(|block| !block.evidence_handles.is_empty())
        {
            let block_json_id = format!("\"id\":\"{}\"", block.id);
            let block_line = lines
                .iter()
                .position(|line| line.contains(&block_json_id))
                .unwrap_or_else(|| panic!("renderer {renderer:?} omitted block {}", block.id));
            let evidence_marker = format!("evidence@{}", block.id).to_ascii_lowercase();
            let evidence_lines: Vec<_> = lines
                .iter()
                .enumerate()
                .filter(|(_, line)| line.to_ascii_lowercase().contains(&evidence_marker))
                .map(|(index, _)| index)
                .collect();
            assert_eq!(
                evidence_lines.len(),
                block.evidence_handles.len(),
                "renderer {renderer:?} lost or duplicated adjacent evidence for {}",
                block.id
            );
            assert_eq!(
                evidence_lines.first().copied(),
                Some(block_line + 1),
                "renderer {renderer:?} separated evidence from {}",
                block.id
            );
        }
    }
}

#[test]
fn one_canonical_pack_renders_across_model_profiles_without_semantic_drift() {
    let request = request(PackPurpose::Conversation, RendererKind::Chat);
    let (candidates, evidence) = japan_fixture();
    let compiled = compile_fixture(&request, candidates, evidence);
    let original = compiled.pack.clone();
    let semantic_ids: Vec<_> = original
        .sections
        .iter()
        .map(|block| block.id.to_string())
        .collect();
    let mut rows = Vec::new();
    for renderer in [
        RendererKind::Compact,
        RendererKind::HostedStructured,
        RendererKind::Chat,
        RendererKind::Coding,
        RendererKind::CanonicalJson,
    ] {
        let rendered = must(ContextRenderer::render(
            &compiled.pack,
            &profile(renderer),
            &ReferenceTokenizer,
        ));
        assert_eq!(compiled.pack, original);
        for id in &semantic_ids {
            assert!(
                rendered.untrusted_data.contains(id),
                "renderer {renderer:?} omitted semantic identity {id}"
            );
        }
        rows.push(RendererGoldenRow {
            renderer,
            control_tokens: rendered.control_tokens,
            data_tokens: rendered.data_tokens,
            total_tokens: rendered.total_tokens,
            control_digest: blake3::hash(rendered.trusted_control.as_bytes())
                .to_hex()
                .to_string(),
            data_digest: blake3::hash(rendered.untrusted_data.as_bytes())
                .to_hex()
                .to_string(),
        });
    }
    let actual = must(serde_json::to_string_pretty(&RendererGolden {
        semantic_ids,
        rows,
    }));
    let expected =
        include_str!("../tests/fixtures/model_renderers_golden.json").replace("\r\n", "\n");
    assert_eq!(format!("{actual}\n"), expected);
}

#[test]
fn model_profile_reserves_output_and_rejects_format_mismatch() {
    let mut request = request(PackPurpose::Conversation, RendererKind::Chat);
    request.model_profile.max_context_tokens = 22_000;
    request.model_profile.reserved_output_tokens = 4_000;
    assert!(matches!(
        request.validate(),
        Err(ContextError::InvalidRequest(message))
            if message.contains("after reserved output")
    ));

    let mut invalid = profile(RendererKind::Chat);
    invalid.preferred_structured_format = StructuredFormat::Json;
    assert!(matches!(
        invalid.validate(),
        Err(ContextError::InvalidRequest(message))
            if message.contains("structured format")
    ));
}

#[test]
fn all_v1_acceptance_pack_purposes_compile() {
    let purposes = [
        PackPurpose::Conversation,
        PackPurpose::Knowledge,
        PackPurpose::Historical,
        PackPurpose::Reflective,
        PackPurpose::Action,
    ];
    for purpose in purposes {
        let request = request(purpose, RendererKind::Compact);
        let (candidates, evidence) = japan_fixture();
        let compiled = compile_fixture(&request, candidates, evidence);
        assert_eq!(compiled.pack.purpose, purpose);
        assert!(!compiled.pack.sections.is_empty());
    }
}

#[test]
fn disclosure_rules_distinguish_silent_use_from_total_withholding() {
    let mut request = request(PackPurpose::Conversation, RendererKind::Compact);
    request.required_facets.truncate(1);
    let mut silent = situation_candidate();
    silent.candidate.id = must(BlockId::new("situation:silent"));
    silent.use_policy.disclosure = DisclosureRule::UseSilently;
    let mut withheld = situation_candidate();
    withheld.candidate.id = must(BlockId::new("situation:withheld"));
    withheld.candidate.mandatory = false;
    withheld.use_policy.disclosure = DisclosureRule::DoNotDisclose;
    let compiled = compile_fixture(&request, vec![silent, withheld], Vec::new());
    assert_eq!(compiled.pack.sections.situation.len(), 1);
    assert_eq!(
        compiled.pack.use_directives[0].action,
        UseAction::UseSilently
    );
    assert!(
        !compiled
            .canonical_json
            .windows("withheld".len())
            .any(|window| window == b"withheld")
    );
}

#[test]
fn continuation_is_authenticated_and_bound_to_snapshot_filter_profile_and_budgets() {
    let mut request = request(PackPurpose::Conversation, RendererKind::Compact);
    request.required_facets.truncate(1);
    request.budgets.soft_tokens = 1;
    let (mut candidates, evidence) = japan_fixture();
    candidates.retain(|candidate| candidate.candidate.kind != PackBlockKind::Unknown);
    let provider = must(InMemoryContextProvider::new(
        request.snapshot.clone(),
        candidates,
        evidence,
    ));
    let compiler = must(ContextCompiler::new([4_u8; 32]));
    let first = must(compiler.compile(&request, &provider, &ReferenceTokenizer));
    let token = match first.pack.continuation.clone() {
        Some(value) => value,
        None => panic!("expected progressive continuation"),
    };
    let mut next_request = request.clone();
    next_request.continuation = Some(token.clone());
    let second = must(compiler.compile(&next_request, &provider, &ReferenceTokenizer));
    assert!(second.pack.sections.len() > first.pack.sections.len());
    assert!(second.pack.compilation.usage.rendered_tokens <= request.budgets.hard_tokens);

    let mut changed_filter = next_request.clone();
    changed_filter.filter_digest = "different-policy".to_owned();
    assert!(matches!(
        compiler.compile(&changed_filter, &provider, &ReferenceTokenizer),
        Err(ContextError::InvalidContinuation(_))
    ));

    let mut changed_budget = next_request.clone();
    changed_budget.budgets.max_blocks -= 1;
    assert!(matches!(
        compiler.compile(&changed_budget, &provider, &ReferenceTokenizer),
        Err(ContextError::InvalidContinuation(_))
    ));

    let mut tampered = token;
    tampered.opaque.replace_range(20..21, "f");
    let mut tampered_request = request;
    tampered_request.continuation = Some(tampered);
    assert!(matches!(
        compiler.compile(&tampered_request, &provider, &ReferenceTokenizer),
        Err(ContextError::InvalidContinuation(_))
    ));
}

#[test]
fn secret_like_payloads_fail_closed_before_rendering() {
    let mut request = request(PackPurpose::Conversation, RendererKind::Chat);
    request.required_facets.truncate(1);
    let mut secret = situation_candidate();
    secret.candidate.id = must(BlockId::new("secret:api-key"));
    secret.candidate.mandatory = false;
    secret.candidate.taints.insert(ContentTaint::SecretLike);
    secret.candidate.representations[0].summary = "sk-live-secret-value".to_owned();
    let compiled = compile_fixture(&request, vec![situation_candidate(), secret], Vec::new());
    assert!(
        !compiled
            .rendered
            .untrusted_data
            .contains("sk-live-secret-value")
    );
    assert!(
        !compiled
            .canonical_json
            .windows(20)
            .any(|window| window == b"sk-live-secret-value")
    );
}

proptest! {
    #[test]
    fn property_forbidden_payload_never_changes_result(secret in ".{0,256}") {
        let mut request = request(PackPurpose::Conversation, RendererKind::Compact);
        request.required_facets.truncate(1);
        let baseline = compile_fixture(&request, vec![situation_candidate()], Vec::new());
        let mut forbidden = situation_candidate();
        forbidden.access.consent = AccessConsent::Denied;
        forbidden.candidate.id = must(BlockId::new("forbidden:property"));
        forbidden.candidate.representations[0].summary = secret;
        forbidden.candidate.utility_micros = u64::MAX;
        forbidden.candidate.mandatory = true;
        let actual = compile_fixture(
            &request,
            vec![forbidden, situation_candidate()],
            Vec::new(),
        );
        prop_assert_eq!(actual, baseline);
    }

    #[test]
    fn property_every_successful_pack_respects_hard_budget(hard in 64_u32..20_000) {
        let mut request = request(PackPurpose::Conversation, RendererKind::Compact);
        request.budgets.hard_tokens = hard;
        request.budgets.soft_tokens = hard.min(2_000);
        let (candidates, evidence) = japan_fixture();
        let provider = must(InMemoryContextProvider::new(
            request.snapshot.clone(),
            candidates,
            evidence,
        ));
        let compiler = must(ContextCompiler::new([7_u8; 32]));
        if let Ok(compiled) = compiler.compile(&request, &provider, &ReferenceTokenizer) {
            prop_assert!(compiled.pack.compilation.usage.rendered_tokens <= hard);
            prop_assert!(compiled.pack.compilation.usage.blocks <= request.budgets.max_blocks);
            prop_assert!(compiled.pack.compilation.usage.serialized_bytes <= request.budgets.max_serialized_bytes);
        }
    }
}
