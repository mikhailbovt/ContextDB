use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    str::FromStr,
};

use contextdb_context::{
    BlockId, BlockRepresentation, CandidateUsePolicy, CompressionLevel, ContentTrust,
    ContextBudgets, ContextCompiler, DisclosureRule, EvidenceHandle, EvidenceSelector,
    InMemoryContextProvider, InstructionCapability, InterpretationRule, PackBlockKind,
    PackCandidate, PackEvidence, PackPurpose, ProviderCandidate, ProviderEvidence,
    ReferenceTokenizer, RendererKind, SourceClass, SourceHandle, SupportState, TokenCounter,
};
use contextdb_core::{
    AcceptanceState, AccessCapability, ActorId, AgentId, Audience, AudienceGrant, Checkpoint,
    CheckpointId, CommitRange, CommitSeq, ConsentPolicy, ConsentState, ConsentStatus,
    ContentDigest, ContinuityProfile, ContinuityProfileId, ConversationMode, DerivationId,
    DerivationKind, DerivationRef, EpistemicBasis, EpistemicRole, EpistemicState,
    IdentityClaimPolicy, LifecycleState, LineageNode, MemoryClass, MemoryRef, MemorySubjectId,
    MemoryUsePolicy, ModelProfileId, ModelRuntimeRef, ModificationPolicy, NodeId, NonEmptyVec,
    OwnershipPolicy, Perspective, PipelineIdentity, PolicyDecision, Purpose, RetentionPolicy,
    RevisionNumber, ScopeInheritance, ScopeKind, ScopeRef, SecurityClassification, SecurityPolicy,
    SemanticEnvelope, SessionId, SituationFrame, TimeRange, TimestampMicros, VectorSpaceId,
    WeightedScope, WorkspaceId,
};
use contextdb_model::{
    InstructionHierarchy, LanguageTag, Modality, ModelCapability, ModelProfile, ModelRevision,
    PositionProfile, ProviderId, StructuredFormat,
};
use contextdb_recall::{
    AccessConsent, AccessRule, ProviderSnapshot, RecallPrincipal, RecallSensitivity,
    RecallWatermarks,
};
use proptest::prelude::*;

use crate::*;

fn must<T, E: Debug>(value: std::result::Result<T, E>) -> T {
    match value {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    must(value.parse())
}

fn workspace() -> WorkspaceId {
    parsed("00000000-0000-4000-8000-000000000001")
}

fn agent() -> AgentId {
    parsed("00000000-0000-4000-8000-000000000002")
}

fn subject() -> MemorySubjectId {
    parsed("00000000-0000-4000-8000-000000000003")
}

fn recipient() -> MemorySubjectId {
    parsed("00000000-0000-4000-8000-000000000004")
}

fn scope() -> ScopeRef {
    ScopeRef {
        kind: ScopeKind::Project,
        id: parsed("00000000-0000-4000-8000-000000000005"),
        inheritance: ScopeInheritance::Exact,
    }
}

fn open_loop() -> NodeId {
    parsed("00000000-0000-4000-8000-000000000006")
}

fn source_profile_id() -> ModelProfileId {
    parsed("00000000-0000-4000-8000-000000000007")
}

fn target_profile_id() -> ModelProfileId {
    parsed("00000000-0000-4000-8000-000000000008")
}

fn perspective() -> Perspective {
    Perspective {
        knower: subject(),
        experiencer: Some(subject()),
        narrator: parsed::<ActorId>("00000000-0000-4000-8000-000000000009"),
        role: EpistemicRole::Witness,
    }
}

fn derivation() -> DerivationRef {
    DerivationRef {
        id: parsed::<DerivationId>("00000000-0000-4000-8000-000000000010"),
        kind: DerivationKind::Migration,
        actor: None,
        model_call: None,
        pipeline: PipelineIdentity {
            name: "continuity-fixture".to_owned(),
            version: "1".to_owned(),
            schema_version: "1".to_owned(),
        },
        inputs: vec![LineageNode::External {
            namespace: "fixture".to_owned(),
            identifier: "source".to_owned(),
        }],
    }
}

fn ownership() -> OwnershipPolicy {
    OwnershipPolicy {
        owners: NonEmptyVec::new(subject()),
        audience_grants: vec![AudienceGrant {
            audience: Audience::Subject { id: recipient() },
            purposes: BTreeSet::from([Purpose::Export]),
            capabilities: BTreeSet::from([
                AccessCapability::Retrieve,
                AccessCapability::InfluenceResponse,
                AccessCapability::Export,
            ]),
        }],
        allowed_purposes: BTreeSet::from([Purpose::Migration, Purpose::Export]),
        modification: ModificationPolicy {
            owners_may_modify: true,
            delegates_may_modify: false,
            system_may_derive: true,
        },
    }
}

fn consent() -> ConsentPolicy {
    ConsentPolicy {
        required: true,
        decisions: vec![ConsentState {
            subject: subject(),
            memory_class: MemoryClass::Operational,
            status: ConsentStatus::Granted,
            valid_time: TimeRange::open_ended(TimestampMicros(0)),
        }],
    }
}

fn use_policy() -> MemoryUsePolicy {
    MemoryUsePolicy {
        retrieve: PolicyDecision::Allow,
        influence_response: PolicyDecision::Allow,
        mention_explicitly: PolicyDecision::Allow,
        external_model_use: PolicyDecision::Allow,
        retention: RetentionPolicy::Indefinite,
    }
}

fn security() -> SecurityPolicy {
    SecurityPolicy {
        classification: SecurityClassification::Internal,
        labels: BTreeSet::from(["continuity".to_owned()]),
        required_compartments: BTreeSet::new(),
        allow_external_processing: true,
    }
}

fn semantic_envelope() -> SemanticEnvelope {
    SemanticEnvelope {
        scopes: NonEmptyVec::new(scope()),
        perspective: perspective(),
        ownership: ownership(),
        consent: consent(),
        use_policy: use_policy(),
        security: security(),
        derivation: derivation(),
    }
}

fn profile_policy() -> ContinuityPolicyEnvelope {
    ContinuityPolicyEnvelope {
        workspace_id: workspace(),
        scopes: NonEmptyVec::new(scope()),
        ownership: ownership(),
        consent: consent(),
        use_policy: use_policy(),
        security: security(),
    }
}

fn continuity_profile() -> ContinuityProfile {
    ContinuityProfile {
        id: parsed::<ContinuityProfileId>("00000000-0000-4000-8000-000000000011"),
        revision: RevisionNumber::FIRST,
        transaction_time: CommitRange::current(CommitSeq::new(10)),
        workspace_id: workspace(),
        agent_id: agent(),
        stable_subject: subject(),
        model_lineage: vec![ModelRuntimeRef {
            provider: "provider-a".to_owned(),
            model: source_profile_id().to_string(),
            revision: Some("model-a.1".to_owned()),
            first_used_at: TimestampMicros(10),
            last_used_at: None,
        }],
        required_bootstrap_facets: NonEmptyVec::new(facets::AGENT_IDENTITY.to_owned()),
        migration_policy: "portable-v1".to_owned(),
        identity_claim_policy: IdentityClaimPolicy::OperationalContinuityOnly,
        envelope: semantic_envelope(),
    }
}

fn core_checkpoint() -> Checkpoint {
    let session = parsed::<SessionId>("00000000-0000-4000-8000-000000000012");
    Checkpoint {
        id: parsed::<CheckpointId>("00000000-0000-4000-8000-000000000013"),
        session_id: session,
        frame_snapshot: SituationFrame {
            session_id: session,
            conversation_mode: ConversationMode::TaskExecution,
            active_topics: Vec::new(),
            active_referents: Vec::new(),
            participant_states: Vec::new(),
            goal_stack: Vec::new(),
            active_scopes: NonEmptyVec::new(WeightedScope {
                scope: scope(),
                weight: 1.0,
            }),
            open_questions: Vec::new(),
            open_loops: vec![open_loop()],
            working_hypotheses: Vec::new(),
            recent_observations: Vec::new(),
            environment: Some(serde_json::json!({"device": "test"})),
            captured_at: TimestampMicros(100),
            expires_at: TimestampMicros(10_000),
        },
        task_state: serde_json::json!({"selected_option": "resume"}),
        required_memory_refs: vec![MemoryRef::Node { id: open_loop() }],
        created_seq: CommitSeq::new(11),
    }
}

fn portable_checkpoint() -> PortableCheckpoint {
    must(PortableCheckpoint::new(
        core_checkpoint(),
        &continuity_profile(),
        &source_runtime(),
        profile_policy(),
    ))
}

fn language(value: &str) -> LanguageTag {
    must(LanguageTag::new(value))
}

fn runtime_model(
    id: ModelProfileId,
    revision: &str,
    tokenizer: &str,
    max_context_tokens: u32,
    native_citations: bool,
    cache: bool,
) -> ModelProfile {
    ModelProfile {
        id,
        family: "fixture-family".to_owned(),
        revision: must(ModelRevision::new(revision)),
        tokenizer: tokenizer.to_owned(),
        max_context_tokens,
        reserved_output_tokens: 2_000,
        preferred_structured_format: StructuredFormat::JsonSchema,
        supports_tool_results: true,
        supports_native_citations: native_citations,
        supports_prompt_caching: cache,
        position_profile: PositionProfile {
            constraints_first: max_context_tokens < 20_000,
            evidence_near_claim: true,
            summary_before_detail: true,
            unknowns_before_actions: max_context_tokens < 20_000,
        },
        instruction_hierarchy: InstructionHierarchy {
            channels: vec!["system".to_owned(), "user".to_owned()],
            isolates_tool_results: true,
            isolates_user_content: true,
        },
        max_schema_complexity: 64,
        languages: BTreeSet::from([language("en"), language("ru")]),
        modalities: BTreeSet::from([Modality::Text, Modality::Code, Modality::ToolResult]),
    }
}

fn source_space() -> EmbeddingSpaceDescriptor {
    EmbeddingSpaceDescriptor {
        id: parsed::<VectorSpaceId>("00000000-0000-4000-8000-000000000014"),
        modality: Modality::Text,
        encoder_family: "embed-a".to_owned(),
        encoder_revision: must(ModelRevision::new("embed-a.1")),
        dimensions: 768,
        normalized: true,
        fingerprint: ContentDigest::from_bytes([1_u8; 32]),
    }
}

fn target_space() -> EmbeddingSpaceDescriptor {
    EmbeddingSpaceDescriptor {
        id: parsed::<VectorSpaceId>("00000000-0000-4000-8000-000000000015"),
        modality: Modality::Text,
        encoder_family: "embed-b".to_owned(),
        encoder_revision: must(ModelRevision::new("embed-b.1")),
        dimensions: 1_024,
        normalized: true,
        fingerprint: ContentDigest::from_bytes([2_u8; 32]),
    }
}

fn source_runtime() -> RuntimeDescriptor {
    let tool = must(ToolId::new("tool:legacy-search"));
    RuntimeDescriptor {
        provider: must(ProviderId::new("provider-a")),
        model: runtime_model(
            source_profile_id(),
            "model-a.1",
            "tokenizer:a",
            32_000,
            true,
            true,
        ),
        renderer: RendererKind::Chat,
        capabilities: BTreeSet::from([ModelCapability::ExtractMemoryCandidates]),
        tools: BTreeMap::from([(
            tool.clone(),
            ToolDescriptor {
                id: tool,
                revision: "1".to_owned(),
                operations: BTreeSet::from(["search".to_owned()]),
            },
        )]),
        embedding_spaces: BTreeMap::from([(source_space().id, source_space())]),
        prompt_cache_namespace: Some(must(PromptCacheNamespace::new("cache:model-a"))),
        external_processing: false,
    }
}

fn target_runtime() -> RuntimeDescriptor {
    RuntimeDescriptor {
        provider: must(ProviderId::new("provider-b")),
        model: runtime_model(
            target_profile_id(),
            "model-b.1",
            ReferenceTokenizer::ID,
            16_000,
            false,
            true,
        ),
        renderer: RendererKind::Compact,
        capabilities: BTreeSet::new(),
        tools: BTreeMap::new(),
        embedding_spaces: BTreeMap::from([(target_space().id, target_space())]),
        prompt_cache_namespace: Some(must(PromptCacheNamespace::new("cache:model-b"))),
        external_processing: false,
    }
}

fn requirements(required_tool: bool) -> MigrationRequirements {
    MigrationRequirements {
        required_capabilities: BTreeSet::new(),
        required_tools: if required_tool {
            BTreeSet::from([must(ToolId::new("tool:legacy-search"))])
        } else {
            BTreeSet::new()
        },
        minimum_input_tokens: 4_000,
        minimum_schema_complexity: 32,
        require_native_citations: false,
    }
}

fn migration_report(required_tool: bool) -> MigrationCompatibilityReport {
    must(CompatibilityAnalyzer::analyze(
        must(MigrationId::new("migration:a-to-b")),
        workspace(),
        agent(),
        subject(),
        &source_runtime(),
        &target_runtime(),
        &requirements(required_tool),
        NonEmptyVec::new(scope()),
        CommitSeq::new(20),
    ))
}

fn snapshot() -> ProviderSnapshot {
    ProviderSnapshot {
        database_id: "db:m12".to_owned(),
        commit_seq: 20,
        watermarks: RecallWatermarks {
            journal: 20,
            semantic: 20,
            lexical: 20,
            vector: BTreeMap::from([("text:v1".to_owned(), 20)]),
            graph: 20,
            hierarchy: BTreeMap::new(),
        },
    }
}

fn access(consent: AccessConsent) -> AccessRule {
    AccessRule {
        workspace: workspace().to_string(),
        scopes: BTreeSet::from([scope().id.to_string()]),
        owners: BTreeSet::from([subject().to_string()]),
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

fn candidate_use() -> CandidateUsePolicy {
    CandidateUsePolicy {
        influence: PolicyDecision::Allow,
        mention: PolicyDecision::Allow,
        external_model_use: PolicyDecision::Allow,
        disclosure: DisclosureRule::MayMention,
    }
}

fn epistemic() -> EpistemicState {
    EpistemicState {
        basis: EpistemicBasis::Observation,
        acceptance: AcceptanceState::Accepted,
        conflict: contextdb_core::ConflictState::None,
        lifecycle: LifecycleState::Active,
    }
}

fn representation(
    summary: impl Into<String>,
    fields: BTreeMap<String, String>,
) -> BlockRepresentation {
    BlockRepresentation {
        level: CompressionLevel::L0Orientation,
        summary: summary.into(),
        fields,
        omitted_facets: BTreeSet::new(),
    }
}

fn situation_candidate() -> ProviderCandidate {
    ProviderCandidate {
        access: access(AccessConsent::Granted),
        use_policy: candidate_use(),
        candidate: PackCandidate {
            id: must(BlockId::new("situation:migration-resume")),
            kind: PackBlockKind::Situation,
            representations: vec![representation(
                "Resume the existing job-application work after model migration.",
                BTreeMap::new(),
            )],
            exact_fragments: Vec::new(),
            memory_refs: Vec::new(),
            claim_ids: BTreeSet::new(),
            evidence_handles: BTreeSet::new(),
            facets: BTreeSet::from([
                facets::AGENT_IDENTITY.to_owned(),
                facets::PARTICIPANT_IDENTITY.to_owned(),
                facets::RELATIONSHIP_ROLE.to_owned(),
                facets::CURRENT_CIRCUMSTANCES.to_owned(),
                facets::RECENT_MILESTONES.to_owned(),
                facets::IMPORTANT_CORRECTIONS.to_owned(),
                facets::COMMUNICATION_PREFERENCES.to_owned(),
                facets::STRICT_BOUNDARIES.to_owned(),
                facets::SHARED_REFERENCES.to_owned(),
                facets::INDEX_FRESHNESS.to_owned(),
            ]),
            scopes: BTreeSet::from([scope().id.to_string()]),
            valid_time: None,
            known_at_commit: 20,
            perspective: None,
            epistemic: epistemic(),
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
    }
}

fn open_loop_claim() -> contextdb_core::ClaimId {
    parsed("00000000-0000-4000-8000-000000000016")
}

fn open_loop_evidence() -> EvidenceHandle {
    must(EvidenceHandle::new("evidence:application-open-loop"))
}

fn open_loop_candidate() -> ProviderCandidate {
    ProviderCandidate {
        access: access(AccessConsent::Granted),
        use_policy: candidate_use(),
        candidate: PackCandidate {
            id: must(BlockId::new("open-loop:job-application")),
            kind: PackBlockKind::OpenLoop,
            representations: vec![representation(
                "The job application is still awaiting an outcome.",
                BTreeMap::from([("status".to_owned(), "open".to_owned())]),
            )],
            exact_fragments: Vec::new(),
            memory_refs: vec![MemoryRef::Node { id: open_loop() }],
            claim_ids: BTreeSet::from([open_loop_claim()]),
            evidence_handles: BTreeSet::from([open_loop_evidence()]),
            facets: BTreeSet::from([
                facets::OPEN_LOOPS.to_owned(),
                facets::IMPORTANT_CORRECTIONS.to_owned(),
                facets::STRICT_BOUNDARIES.to_owned(),
                facets::RECENT_MILESTONES.to_owned(),
            ]),
            scopes: BTreeSet::from([scope().id.to_string()]),
            valid_time: None,
            known_at_commit: 20,
            perspective: Some(perspective()),
            epistemic: epistemic(),
            confidence_micros: 950_000,
            trust: ContentTrust::TrustedSource,
            instruction_capability: InstructionCapability::None,
            source_class: SourceClass::SharedConversation,
            taints: BTreeSet::new(),
            interpretation: InterpretationRule::FactualData,
            support: SupportState::Supported,
            conflict: None,
            unknown: None,
            utility_micros: 900_000,
            mandatory: true,
        },
    }
}

fn evidence() -> ProviderEvidence {
    ProviderEvidence {
        access: access(AccessConsent::Granted),
        external_model_use: PolicyDecision::Allow,
        evidence: PackEvidence {
            original_span: None,
            id: open_loop_evidence(),
            source: must(SourceHandle::new("source:shared-history")),
            selector: EvidenceSelector::Whole,
            excerpt: Some("We are waiting for an update on the submitted application.".to_owned()),
            claim_ids: BTreeSet::from([open_loop_claim()]),
            provenance_family: "shared-conversation".to_owned(),
            primary: true,
            trust_micros: 950_000,
            source_class: SourceClass::SharedConversation,
            taints: BTreeSet::new(),
            lineage: Vec::new(),
        },
    }
}

fn provider(candidates: Vec<ProviderCandidate>) -> InMemoryContextProvider {
    provider_with_evidence(candidates, vec![evidence()])
}

fn provider_with_evidence(
    candidates: Vec<ProviderCandidate>,
    evidence: Vec<ProviderEvidence>,
) -> InMemoryContextProvider {
    must(InMemoryContextProvider::new(
        snapshot(),
        candidates,
        evidence,
    ))
}

fn principal(subject_id: MemorySubjectId, purpose: Purpose) -> RecallPrincipal {
    RecallPrincipal::from_core(
        subject_id,
        workspace(),
        &[scope()],
        &purpose,
        SecurityClassification::Internal,
    )
}

fn budgets() -> ContextBudgets {
    ContextBudgets {
        hard_tokens: 10_000,
        soft_tokens: 9_000,
        max_blocks: 64,
        max_evidence_blocks: 64,
        max_raw_evidence_tokens: 2_000,
        max_history_tokens: 4_000,
        max_conflict_tokens: 2_000,
        max_serialized_bytes: 500_000,
        max_selection_evaluations: 128,
    }
}

#[derive(Debug)]
struct TokenizerA;

impl TokenCounter for TokenizerA {
    fn id(&self) -> &str {
        "tokenizer:a"
    }

    fn count_tokens(&self, input: &str) -> contextdb_context::Result<u32> {
        ReferenceTokenizer.count_tokens(input)
    }
}

fn compile_request(
    pack_id: contextdb_core::ContextPackId,
    purpose: PackPurpose,
    principal: RecallPrincipal,
) -> contextdb_context::CompileRequest {
    contextdb_context::CompileRequest {
        pack_id,
        snapshot: snapshot(),
        principal,
        filter_digest: "filter:m12:v1".to_owned(),
        purpose,
        scopes: BTreeSet::from([scope().id.to_string()]),
        temporal_view: contextdb_core::TemporalConstraint::Current,
        required_facets: Vec::new(),
        budgets: budgets(),
        model_profile: must(target_runtime().context_profile()),
        explicit_memory_request: true,
        require_primary_evidence: true,
        continuation: None,
    }
}

#[test]
fn compatibility_reports_budget_tokenizer_tool_citation_and_reembedding() {
    let report = migration_report(false);
    assert!(report.compatible);
    for code in [
        CompatibilityCode::ContextBudgetReduced,
        CompatibilityCode::TokenizerChanged,
        CompatibilityCode::ToolUnavailable,
        CompatibilityCode::NativeCitationsUnavailable,
        CompatibilityCode::EmbeddingRebuildRequired,
        CompatibilityCode::BehavioralContinuityNotGuaranteed,
    ] {
        assert!(report.findings.iter().any(|finding| finding.code == code));
    }
    assert_eq!(report.reembedding_jobs.len(), 1);
    assert_ne!(
        report.reembedding_jobs[0].source.id,
        report.reembedding_jobs[0].target.id
    );
    let json = must(report.to_json());
    assert_eq!(must(MigrationCompatibilityReport::from_json(&json)), report);
    let mut noncanonical = json.clone();
    noncanonical.push(b'\n');
    assert!(matches!(
        MigrationCompatibilityReport::from_json(&noncanonical),
        Err(ContinuityError::Serialization(_))
    ));
}

#[test]
fn vector_space_id_collision_is_a_hard_compatibility_failure() {
    let source = source_runtime();
    let mut target = target_runtime();
    let mut collided = target_space();
    collided.id = source_space().id;
    target.embedding_spaces = BTreeMap::from([(collided.id, collided)]);
    let report = must(CompatibilityAnalyzer::analyze(
        must(MigrationId::new("migration:collision")),
        workspace(),
        agent(),
        subject(),
        &source,
        &target,
        &requirements(false),
        NonEmptyVec::new(scope()),
        CommitSeq::new(20),
    ));
    assert!(!report.compatible);
    assert!(report.findings.iter().any(|finding| {
        finding.code == CompatibilityCode::EmbeddingSpaceIdCollision
            && finding.severity == FindingSeverity::Blocking
    }));
    assert!(report.reembedding_jobs.is_empty());
}

#[test]
fn identical_vector_semantics_cannot_be_aliased_to_a_new_space_id() {
    let source = source_runtime();
    let mut target = target_runtime();
    let mut alias = source_space();
    alias.id = target_space().id;
    target.embedding_spaces = BTreeMap::from([(alias.id, alias)]);
    let report = must(CompatibilityAnalyzer::analyze(
        must(MigrationId::new("migration:vector-alias")),
        workspace(),
        agent(),
        subject(),
        &source,
        &target,
        &requirements(false),
        NonEmptyVec::new(scope()),
        CommitSeq::new(20),
    ));
    assert!(!report.compatible);
    assert!(report.findings.iter().any(|finding| {
        finding.code == CompatibilityCode::EmbeddingSpaceSemanticAlias
            && finding.severity == FindingSeverity::Blocking
    }));
    assert!(report.reembedding_jobs.is_empty());
}

#[test]
fn target_must_meet_absolute_budget_citation_and_tool_contract_requirements() {
    let mut source = source_runtime();
    source.model.max_context_tokens = 6_000;
    source.model.supports_native_citations = false;
    let mut target = target_runtime();
    target.model.max_context_tokens = 7_000;
    target.model.supports_native_citations = false;
    let tool_id = must(ToolId::new("tool:legacy-search"));
    target.tools.insert(
        tool_id.clone(),
        ToolDescriptor {
            id: tool_id.clone(),
            revision: "2".to_owned(),
            operations: BTreeSet::from(["lookup".to_owned()]),
        },
    );
    let requirements = MigrationRequirements {
        required_capabilities: BTreeSet::new(),
        required_tools: BTreeSet::from([tool_id]),
        minimum_input_tokens: 6_000,
        minimum_schema_complexity: 32,
        require_native_citations: true,
    };
    let report = must(CompatibilityAnalyzer::analyze(
        must(MigrationId::new("migration:absolute-requirements")),
        workspace(),
        agent(),
        subject(),
        &source,
        &target,
        &requirements,
        NonEmptyVec::new(scope()),
        CommitSeq::new(20),
    ));
    assert!(!report.compatible);
    for code in [
        CompatibilityCode::ContextBudgetInsufficient,
        CompatibilityCode::NativeCitationsUnavailable,
        CompatibilityCode::ToolContractChanged,
    ] {
        assert!(report.findings.iter().any(|finding| {
            finding.code == code && finding.severity == FindingSeverity::Blocking
        }));
    }
}

#[test]
fn required_missing_tool_blocks_migration_without_partial_lifecycle_state() {
    let report = migration_report(true);
    assert!(!report.compatible);
    assert!(report.findings.iter().any(|finding| {
        finding.code == CompatibilityCode::ToolUnavailable
            && finding.severity == FindingSeverity::Blocking
    }));
    let mut lifecycle = must(MigrationLifecycle::new(
        report.migration_id.clone(),
        workspace(),
        agent(),
        subject(),
        source_profile_id(),
        target_profile_id(),
    ));
    let checkpoint = portable_checkpoint();
    must(lifecycle.seal_checkpoint(&checkpoint, TimestampMicros(200)));
    let before = lifecycle.clone();
    assert!(matches!(
        lifecycle.accept_compatibility(&report, TimestampMicros(201)),
        Err(ContinuityError::IncompatibleRuntime(_))
    ));
    assert_eq!(lifecycle, before);
}

#[test]
fn portable_checkpoint_round_trips_and_rejects_tampering() {
    let checkpoint = portable_checkpoint();
    let bytes = must(checkpoint.to_json());
    assert_eq!(must(PortableCheckpoint::from_json(&bytes)), checkpoint);
    let mut tampered = checkpoint;
    tampered.checkpoint.task_state = serde_json::json!({"selected_option": "secretly changed"});
    assert!(matches!(
        tampered.validate(),
        Err(ContinuityError::InvalidInput(message)) if message.contains("digest")
    ));
}

#[test]
fn portable_checkpoint_rejects_policy_weakening_and_runtime_aliasing() {
    let profile = continuity_profile();
    let source = source_runtime();
    let mut broader = profile_policy();
    broader.security.classification = SecurityClassification::Public;
    assert!(matches!(
        PortableCheckpoint::new(core_checkpoint(), &profile, &source, broader),
        Err(ContinuityError::PolicyDenied(_))
    ));

    let checkpoint = portable_checkpoint();
    let mut aliased_runtime = source;
    aliased_runtime.model.tokenizer = "tokenizer:substituted".to_owned();
    assert!(matches!(
        checkpoint.validate_against(&profile, &aliased_runtime),
        Err(ContinuityError::IdentityMismatch(_))
    ));
}

#[test]
fn conditional_migration_gates_require_explicit_approvals() {
    let mut policy = profile_policy();
    policy.use_policy.retrieve = PolicyDecision::Conditional;
    policy.use_policy.influence_response = PolicyDecision::Conditional;
    policy.use_policy.external_model_use = PolicyDecision::Conditional;
    assert!(matches!(
        policy.authorize_migration(
            subject(),
            TimestampMicros(200),
            true,
            ConditionalApprovals::default(),
        ),
        Err(ContinuityError::PolicyDenied(_))
    ));
    must(policy.authorize_migration(
        subject(),
        TimestampMicros(200),
        true,
        ConditionalApprovals {
            memory_use: true,
            external_processing: true,
        },
    ));
}

#[test]
fn model_lineage_preserves_stable_identity_and_closes_source_runtime() {
    let previous = continuity_profile();
    let next = must(append_model_lineage(
        &previous,
        ModelRuntimeRef {
            provider: "provider-b".to_owned(),
            model: "model-b".to_owned(),
            revision: Some("b.1".to_owned()),
            first_used_at: TimestampMicros(500),
            last_used_at: None,
        },
        must(RevisionNumber::new(2)),
        CommitRange::current(CommitSeq::new(21)),
        semantic_envelope(),
    ));
    assert_eq!(next.id, previous.id);
    assert_eq!(next.agent_id, previous.agent_id);
    assert_eq!(next.stable_subject, previous.stable_subject);
    assert_eq!(next.model_lineage.len(), 2);
    assert_eq!(
        next.model_lineage[0].last_used_at,
        Some(TimestampMicros(500))
    );
    assert_eq!(
        next.identity_claim_policy,
        IdentityClaimPolicy::OperationalContinuityOnly
    );
}

#[test]
fn model_lineage_rejects_policy_weakening() {
    let previous = continuity_profile();
    let mut weakened = semantic_envelope();
    weakened.security.classification = SecurityClassification::Public;
    assert!(matches!(
        append_model_lineage(
            &previous,
            ModelRuntimeRef {
                provider: "provider-b".to_owned(),
                model: "model-b".to_owned(),
                revision: Some("b.1".to_owned()),
                first_used_at: TimestampMicros(500),
                last_used_at: None,
            },
            must(RevisionNumber::new(2)),
            CommitRange::current(CommitSeq::new(21)),
            weakened,
        ),
        Err(ContinuityError::PolicyDenied(_))
    ));
}

#[test]
fn reembedding_jobs_are_new_space_atomic_and_retryable() {
    let spec = migration_report(false).reembedding_jobs[0].clone();
    let mut job = must(ReembeddingJob::queued(spec));
    must(job.start(TimestampMicros(300)));
    must(job.fail(true, "transient worker outage", TimestampMicros(301)));
    must(job.start(TimestampMicros(302)));
    must(job.succeed(
        123,
        ContentDigest::from_bytes([9_u8; 32]),
        TimestampMicros(303),
    ));
    assert!(job.is_succeeded());
    assert!(matches!(
        job.start(TimestampMicros(304)),
        Err(ContinuityError::InvalidTransition(_))
    ));
}

#[test]
fn model_a_to_b_bootstrap_preserves_open_loop_and_completes_lifecycle() {
    let checkpoint = portable_checkpoint();
    let report = migration_report(false);
    let target = target_runtime();
    let request = BootstrapRequest {
        checkpoint: checkpoint.clone(),
        continuity_profile: continuity_profile(),
        source_runtime: source_runtime(),
        compatibility: report.clone(),
        pack_id: parsed("00000000-0000-4000-8000-000000000017"),
        model_profile: must(target.context_profile()),
        snapshot: snapshot(),
        principal: principal(subject(), Purpose::Conversation),
        filter_digest: "filter:m12:v1".to_owned(),
        pack_scopes: BTreeSet::from([scope().id.to_string()]),
        semantic_scopes: BTreeSet::from([scope()]),
        budgets: budgets(),
        facet_overrides: BTreeMap::new(),
        explicit_memory_request: true,
        migration_at: TimestampMicros(200),
        approvals: ConditionalApprovals::default(),
    };
    let provider = provider(vec![situation_candidate(), open_loop_candidate()]);
    let bootstrap = must(must(BootstrapCompiler::new([3_u8; 32])).compile(
        &request,
        &target,
        &provider,
        &ReferenceTokenizer,
    ));
    assert!(bootstrap.open_loops_preserved);
    assert_eq!(bootstrap.stable_subject, subject());
    assert_eq!(bootstrap.compiled.pack.purpose, PackPurpose::Bootstrap);
    assert_eq!(bootstrap.compiled.pack.sections.open_loops.len(), 1);

    let mut jobs: Vec<_> = report
        .reembedding_jobs
        .iter()
        .cloned()
        .map(ReembeddingJob::queued)
        .map(must)
        .collect();
    for job in &mut jobs {
        must(job.start(TimestampMicros(220)));
        must(job.succeed(
            1,
            ContentDigest::from_bytes([8_u8; 32]),
            TimestampMicros(221),
        ));
    }
    let mut lifecycle = must(MigrationLifecycle::new(
        report.migration_id.clone(),
        workspace(),
        agent(),
        subject(),
        source_profile_id(),
        target_profile_id(),
    ));
    must(lifecycle.seal_checkpoint(&checkpoint, TimestampMicros(200)));
    must(lifecycle.accept_compatibility(&report, TimestampMicros(201)));
    must(lifecycle.finish_reembedding(&report, &jobs, TimestampMicros(222)));
    let other_report = must(CompatibilityAnalyzer::analyze(
        must(MigrationId::new("migration:other")),
        workspace(),
        agent(),
        subject(),
        &source_runtime(),
        &target,
        &requirements(false),
        NonEmptyVec::new(scope()),
        CommitSeq::new(20),
    ));
    let mut other_request = request.clone();
    other_request.compatibility = other_report;
    let other_bootstrap = must(must(BootstrapCompiler::new([3_u8; 32])).compile(
        &other_request,
        &target,
        &provider,
        &ReferenceTokenizer,
    ));
    let before_wrong_bootstrap = lifecycle.clone();
    assert!(matches!(
        lifecycle.record_bootstrap(&other_bootstrap, TimestampMicros(223)),
        Err(ContinuityError::IdentityMismatch(_))
    ));
    assert_eq!(lifecycle, before_wrong_bootstrap);
    must(lifecycle.record_bootstrap(&bootstrap, TimestampMicros(223)));
    must(lifecycle.complete(ContentDigest::from_bytes([7_u8; 32]), TimestampMicros(224)));
    assert_eq!(lifecycle.phase, MigrationPhase::Completed);
    must(lifecycle.validate());
    let bytes = must(lifecycle.to_json());
    assert_eq!(must(MigrationLifecycle::from_json(&bytes)), lifecycle);
    let mut tampered = lifecycle;
    tampered.events[0].artifact_digest = ContentDigest::from_bytes([6_u8; 32]);
    assert!(matches!(
        tampered.validate(),
        Err(ContinuityError::InvalidInput(_))
    ));
}

#[test]
fn process_restart_resumes_with_the_same_runtime_and_stable_subject() {
    let checkpoint = portable_checkpoint();
    let runtime = source_runtime();
    let report = must(CompatibilityAnalyzer::analyze(
        must(MigrationId::new("restart:model-a")),
        workspace(),
        agent(),
        subject(),
        &runtime,
        &runtime,
        &requirements(false),
        NonEmptyVec::new(scope()),
        CommitSeq::new(20),
    ));
    assert!(report.compatible);
    assert!(report.reembedding_jobs.is_empty());
    let request = BootstrapRequest {
        checkpoint: checkpoint.clone(),
        continuity_profile: continuity_profile(),
        source_runtime: runtime.clone(),
        compatibility: report.clone(),
        pack_id: parsed("00000000-0000-4000-8000-000000000024"),
        model_profile: must(runtime.context_profile()),
        snapshot: snapshot(),
        principal: principal(subject(), Purpose::Conversation),
        filter_digest: "filter:restart:v1".to_owned(),
        pack_scopes: BTreeSet::from([scope().id.to_string()]),
        semantic_scopes: BTreeSet::from([scope()]),
        budgets: budgets(),
        facet_overrides: BTreeMap::new(),
        explicit_memory_request: true,
        migration_at: TimestampMicros(200),
        approvals: ConditionalApprovals::default(),
    };
    let bootstrap = must(must(BootstrapCompiler::new([11_u8; 32])).compile(
        &request,
        &runtime,
        &provider(vec![situation_candidate(), open_loop_candidate()]),
        &TokenizerA,
    ));
    assert_eq!(bootstrap.stable_subject, subject());
    assert!(bootstrap.open_loops_preserved);

    let mut lifecycle = must(MigrationLifecycle::new(
        report.migration_id.clone(),
        workspace(),
        agent(),
        subject(),
        source_profile_id(),
        source_profile_id(),
    ));
    must(lifecycle.seal_checkpoint(&checkpoint, TimestampMicros(200)));
    must(lifecycle.accept_compatibility(&report, TimestampMicros(201)));
    assert_eq!(lifecycle.phase, MigrationPhase::ReadyForBootstrap);
    must(lifecycle.record_bootstrap(&bootstrap, TimestampMicros(202)));
    must(lifecycle.complete(ContentDigest::from_bytes([5_u8; 32]), TimestampMicros(203)));
    assert_eq!(lifecycle.phase, MigrationPhase::Completed);
}

#[test]
fn model_a_to_b_migration_matches_deterministic_golden() {
    let checkpoint = portable_checkpoint();
    let report = migration_report(false);
    let target = target_runtime();
    let request = BootstrapRequest {
        checkpoint: checkpoint.clone(),
        continuity_profile: continuity_profile(),
        source_runtime: source_runtime(),
        compatibility: report.clone(),
        pack_id: parsed("00000000-0000-4000-8000-000000000017"),
        model_profile: must(target.context_profile()),
        snapshot: snapshot(),
        principal: principal(subject(), Purpose::Conversation),
        filter_digest: "filter:m12:v1".to_owned(),
        pack_scopes: BTreeSet::from([scope().id.to_string()]),
        semantic_scopes: BTreeSet::from([scope()]),
        budgets: budgets(),
        facet_overrides: BTreeMap::new(),
        explicit_memory_request: true,
        migration_at: TimestampMicros(200),
        approvals: ConditionalApprovals::default(),
    };
    let bootstrap = must(must(BootstrapCompiler::new([3_u8; 32])).compile(
        &request,
        &target,
        &provider(vec![situation_candidate(), open_loop_candidate()]),
        &ReferenceTokenizer,
    ));
    let findings: Vec<_> = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "code": finding.code,
                "severity": finding.severity,
                "subject": finding.subject,
            })
        })
        .collect();
    let jobs: Vec<_> = report
        .reembedding_jobs
        .iter()
        .map(|job| {
            serde_json::json!({
                "id": job.id,
                "source_space": job.source.id,
                "target_space": job.target.id,
                "snapshot_commit": job.snapshot_commit,
            })
        })
        .collect();
    let selected_blocks: Vec<_> = bootstrap
        .compiled
        .pack
        .compilation
        .selected_blocks
        .iter()
        .map(ToString::to_string)
        .collect();
    let golden = serde_json::json!({
        "format_version": CONTINUITY_FORMAT_VERSION,
        "migration_id": report.migration_id,
        "stable": {
            "workspace_id": report.workspace_id,
            "agent_id": report.agent_id,
            "memory_subject_id": report.stable_subject,
            "checkpoint_id": checkpoint.checkpoint.id,
            "open_loop_id": open_loop(),
        },
        "runtime": {
            "source_profile": report.source_profile,
            "target_profile": report.target_profile,
            "source_runtime_digest": report.source_runtime_digest,
            "target_runtime_digest": report.target_runtime_digest,
            "source_renderer": report.source_renderer,
            "target_renderer": report.target_renderer,
        },
        "compatibility": {
            "compatible": report.compatible,
            "findings": findings,
            "reembedding": jobs,
            "report_digest": report.report_digest,
        },
        "bootstrap": {
            "status": bootstrap.compiled.pack.status,
            "profile_id": bootstrap.compiled.rendered.profile_id,
            "renderer": bootstrap.compiled.rendered.renderer,
            "selected_blocks": selected_blocks,
            "pack_digest": bootstrap.compiled.canonical_digest,
            "trace_digest": bootstrap.trace_digest,
            "open_loops_preserved": bootstrap.open_loops_preserved,
        },
    });
    let actual = format!("{}\n", must(serde_json::to_string_pretty(&golden)));
    let expected = include_str!("../tests/fixtures/model_a_to_b_golden.json").replace("\r\n", "\n");
    assert_eq!(actual, expected);
}

fn handoff_request() -> HandoffRequest {
    HandoffRequest {
        id: must(HandoffId::new("handoff:reviewer")),
        checkpoint: portable_checkpoint(),
        compile: compile_request(
            parsed("00000000-0000-4000-8000-000000000018"),
            PackPurpose::Handoff,
            principal(recipient(), Purpose::Export),
        ),
        recipient: recipient(),
        sharing_scope: MemorySharingScope::PairwiseShared,
        recipient_compartments: BTreeSet::new(),
        target_external_processing: false,
        approvals: ConditionalApprovals::default(),
        publishable_blocks: BTreeSet::from([
            must(BlockId::new("situation:migration-resume")),
            must(BlockId::new("open-loop:job-application")),
            must(BlockId::new("fact:private")),
        ]),
        publishable_memory_refs: BTreeSet::from([MemoryRef::Node { id: open_loop() }]),
        accepted_commitments: BTreeSet::new(),
        issued_at: TimestampMicros(400),
        expires_at: TimestampMicros(1_400),
        revocation_id: must(HandoffId::new("revoke:reviewer")),
    }
}

fn private_candidate(secret: String) -> ProviderCandidate {
    let mut value = situation_candidate();
    value.access.consent = AccessConsent::Denied;
    value.candidate.id = must(BlockId::new("fact:private"));
    value.candidate.mandatory = true;
    value.candidate.utility_micros = u64::MAX;
    value.candidate.representations[0].summary = secret;
    value
}

fn private_evidence(secret: String) -> ProviderEvidence {
    let mut value = evidence();
    value.access.consent = AccessConsent::Denied;
    value.evidence.excerpt = Some(secret);
    value
}

#[test]
fn handoff_rebuilds_from_recipient_authorized_sources_and_has_expiry_manifest() {
    let request = handoff_request();
    let baseline_provider = provider(vec![situation_candidate(), open_loop_candidate()]);
    let with_private_provider = provider(vec![
        situation_candidate(),
        open_loop_candidate(),
        private_candidate("private user history".to_owned()),
    ]);
    let compiler = must(HandoffCompiler::new([4_u8; 32]));
    let baseline = must(compiler.compile(&request, &baseline_provider, &ReferenceTokenizer));
    let actual = must(compiler.compile(&request, &with_private_provider, &ReferenceTokenizer));
    assert_eq!(actual, baseline);
    assert!(
        !actual
            .compiled
            .canonical_json
            .windows(7)
            .any(|w| w == b"private")
    );
    assert_eq!(actual.manifest.expires_at, TimestampMicros(1_400));
    assert_eq!(actual.manifest.recipient, recipient());
    must(actual.manifest.validate());
    must(actual.manifest.validate_use(TimestampMicros(500), false));
    assert!(matches!(
        actual.manifest.validate_use(TimestampMicros(1_400), false),
        Err(ContinuityError::PolicyDenied(_))
    ));
    assert!(matches!(
        actual.manifest.validate_use(TimestampMicros(500), true),
        Err(ContinuityError::PolicyDenied(_))
    ));
    assert_eq!(
        must(HandoffManifest::from_json(&must(actual.manifest.to_json()))),
        actual.manifest
    );
}

#[test]
fn recipient_denied_raw_evidence_cannot_affect_handoff_output() {
    let request = handoff_request();
    let mut durable_situation = situation_candidate();
    durable_situation.candidate.memory_refs = vec![MemoryRef::Node { id: open_loop() }];
    let candidates = vec![durable_situation, open_loop_candidate()];
    let without_evidence = provider_with_evidence(candidates.clone(), Vec::new());
    let with_denied_evidence = provider_with_evidence(
        candidates,
        vec![private_evidence("recipient-private evidence".to_owned())],
    );
    let compiler = must(HandoffCompiler::new([10_u8; 32]));
    let baseline = must(compiler.compile(&request, &without_evidence, &ReferenceTokenizer));
    let actual = must(compiler.compile(&request, &with_denied_evidence, &ReferenceTokenizer));
    assert_eq!(actual, baseline);
    assert!(
        !actual
            .manifest
            .evidence_handles
            .contains(&open_loop_evidence())
    );
}

#[derive(Debug)]
struct NeverReadProvider {
    labels_read: Cell<bool>,
}

impl contextdb_context::ContextProvider for NeverReadProvider {
    fn snapshot(&self) -> contextdb_context::Result<ProviderSnapshot> {
        self.labels_read.set(true);
        Ok(snapshot())
    }

    fn candidate_labels(
        &self,
    ) -> contextdb_context::Result<Vec<contextdb_context::CandidatePolicyLabel>> {
        self.labels_read.set(true);
        Ok(Vec::new())
    }

    fn materialize_candidate(&self, _: &BlockId) -> contextdb_context::Result<PackCandidate> {
        panic!("payload must not be read")
    }

    fn evidence_labels(
        &self,
        _: &[EvidenceHandle],
    ) -> contextdb_context::Result<Vec<contextdb_context::EvidencePolicyLabel>> {
        panic!("evidence must not be read")
    }

    fn materialize_evidence(&self, _: &EvidenceHandle) -> contextdb_context::Result<PackEvidence> {
        panic!("evidence payload must not be read")
    }
}

#[test]
fn handoff_policy_denial_happens_before_any_provider_access() {
    let mut request = handoff_request();
    request.recipient = parsed("00000000-0000-4000-8000-000000000099");
    request.compile.principal.subject = request.recipient.to_string();
    let provider = NeverReadProvider {
        labels_read: Cell::new(false),
    };
    assert!(matches!(
        must(HandoffCompiler::new([5_u8; 32])).compile(&request, &provider, &ReferenceTokenizer),
        Err(ContinuityError::PolicyDenied(_))
    ));
    assert!(!provider.labels_read.get());
}

#[test]
fn agent_private_handoff_is_rejected_before_any_provider_access() {
    let mut request = handoff_request();
    request.sharing_scope = MemorySharingScope::AgentPrivate;
    let provider = NeverReadProvider {
        labels_read: Cell::new(false),
    };
    assert!(matches!(
        must(HandoffCompiler::new([5_u8; 32])).compile(&request, &provider, &ReferenceTokenizer),
        Err(ContinuityError::PolicyDenied(_))
    ));
    assert!(!provider.labels_read.get());
}

#[test]
fn bootstrap_policy_denial_happens_before_any_provider_access() {
    let mut denied_policy = profile_policy();
    denied_policy.use_policy.retrieve = PolicyDecision::Deny;
    let checkpoint = must(PortableCheckpoint::new(
        core_checkpoint(),
        &continuity_profile(),
        &source_runtime(),
        denied_policy,
    ));
    let report = migration_report(false);
    let target = target_runtime();
    let request = BootstrapRequest {
        checkpoint,
        continuity_profile: continuity_profile(),
        source_runtime: source_runtime(),
        compatibility: report,
        pack_id: parsed("00000000-0000-4000-8000-000000000022"),
        model_profile: must(target.context_profile()),
        snapshot: snapshot(),
        principal: principal(subject(), Purpose::Conversation),
        filter_digest: "filter:m12:v1".to_owned(),
        pack_scopes: BTreeSet::from([scope().id.to_string()]),
        semantic_scopes: BTreeSet::from([scope()]),
        budgets: budgets(),
        facet_overrides: BTreeMap::new(),
        explicit_memory_request: false,
        migration_at: TimestampMicros(200),
        approvals: ConditionalApprovals::default(),
    };
    let provider = NeverReadProvider {
        labels_read: Cell::new(false),
    };
    assert!(matches!(
        must(BootstrapCompiler::new([5_u8; 32])).compile(
            &request,
            &target,
            &provider,
            &ReferenceTokenizer
        ),
        Err(ContinuityError::PolicyDenied(_))
    ));
    assert!(!provider.labels_read.get());
}

#[test]
fn bootstrap_rejects_runtime_substitution_before_provider_access() {
    let report = migration_report(false);
    let mut target = target_runtime();
    target.model.tokenizer = "tokenizer:substituted".to_owned();
    let request = BootstrapRequest {
        checkpoint: portable_checkpoint(),
        continuity_profile: continuity_profile(),
        source_runtime: source_runtime(),
        compatibility: report,
        pack_id: parsed("00000000-0000-4000-8000-000000000023"),
        model_profile: must(target.context_profile()),
        snapshot: snapshot(),
        principal: principal(subject(), Purpose::Conversation),
        filter_digest: "filter:m12:v1".to_owned(),
        pack_scopes: BTreeSet::from([scope().id.to_string()]),
        semantic_scopes: BTreeSet::from([scope()]),
        budgets: budgets(),
        facet_overrides: BTreeMap::new(),
        explicit_memory_request: false,
        migration_at: TimestampMicros(200),
        approvals: ConditionalApprovals::default(),
    };
    let provider = NeverReadProvider {
        labels_read: Cell::new(false),
    };
    assert!(matches!(
        must(BootstrapCompiler::new([5_u8; 32])).compile(
            &request,
            &target,
            &provider,
            &ReferenceTokenizer
        ),
        Err(ContinuityError::IdentityMismatch(_))
    ));
    assert!(!provider.labels_read.get());
}

#[test]
fn bootstrap_facet_baselines_cannot_be_weakened_before_provider_access() {
    let report = migration_report(false);
    let target = target_runtime();
    let request = BootstrapRequest {
        checkpoint: portable_checkpoint(),
        continuity_profile: continuity_profile(),
        source_runtime: source_runtime(),
        compatibility: report,
        pack_id: parsed("00000000-0000-4000-8000-000000000025"),
        model_profile: must(target.context_profile()),
        snapshot: snapshot(),
        principal: principal(subject(), Purpose::Conversation),
        filter_digest: "filter:m12:v1".to_owned(),
        pack_scopes: BTreeSet::from([scope().id.to_string()]),
        semantic_scopes: BTreeSet::from([scope()]),
        budgets: budgets(),
        facet_overrides: BTreeMap::from([(
            facets::STRICT_BOUNDARIES.to_owned(),
            contextdb_context::PackFacetRequirement {
                name: facets::STRICT_BOUNDARIES.to_owned(),
                minimum_confidence_micros: 1,
                require_evidence: false,
            },
        )]),
        explicit_memory_request: false,
        migration_at: TimestampMicros(200),
        approvals: ConditionalApprovals::default(),
    };
    let provider = NeverReadProvider {
        labels_read: Cell::new(false),
    };
    assert!(matches!(
        must(BootstrapCompiler::new([5_u8; 32])).compile(
            &request,
            &target,
            &provider,
            &ReferenceTokenizer
        ),
        Err(ContinuityError::InvalidInput(_))
    ));
    assert!(!provider.labels_read.get());
}

fn action_pack() -> contextdb_context::ContextPack {
    let constraint_claim = parsed("00000000-0000-4000-8000-000000000019");
    let evidence_id = must(EvidenceHandle::new("evidence:action-boundary"));
    let mut constraint = open_loop_candidate();
    constraint.candidate.id = must(BlockId::new("constraint:no-delete"));
    constraint.candidate.kind = PackBlockKind::Constraint;
    constraint.candidate.memory_refs = vec![MemoryRef::Node {
        id: parsed("00000000-0000-4000-8000-000000000020"),
    }];
    constraint.candidate.claim_ids = BTreeSet::from([constraint_claim]);
    constraint.candidate.evidence_handles = BTreeSet::from([evidence_id.clone()]);
    constraint.candidate.facets = BTreeSet::from(["constraint".to_owned()]);
    constraint.candidate.representations = vec![representation(
        "Never delete the production database.",
        BTreeMap::from([("decision".to_owned(), "deny".to_owned())]),
    )];
    constraint.candidate.interpretation = InterpretationRule::ConstraintData;
    let boundary_evidence = ProviderEvidence {
        access: access(AccessConsent::Granted),
        external_model_use: PolicyDecision::Allow,
        evidence: PackEvidence {
            original_span: None,
            id: evidence_id,
            source: must(SourceHandle::new("source:boundary")),
            selector: EvidenceSelector::Whole,
            excerpt: Some("Explicit boundary: do not delete production.".to_owned()),
            claim_ids: BTreeSet::from([constraint_claim]),
            provenance_family: "boundary".to_owned(),
            primary: true,
            trust_micros: 1_000_000,
            source_class: SourceClass::UserStatement,
            taints: BTreeSet::new(),
            lineage: Vec::new(),
        },
    };
    let provider = must(InMemoryContextProvider::new(
        snapshot(),
        vec![situation_candidate(), constraint],
        vec![boundary_evidence],
    ));
    must(must(ContextCompiler::new([6_u8; 32])).compile(
        &compile_request(
            parsed("00000000-0000-4000-8000-000000000021"),
            PackPurpose::Action,
            principal(subject(), Purpose::TaskExecution),
        ),
        &provider,
        &ReferenceTokenizer,
    ))
    .pack
}

#[test]
fn preflight_can_block_but_never_grants_authority() {
    let report = must(PreflightEvaluator::evaluate(&PreflightRequest {
        action: ActionIntent {
            id: must(ActionId::new("action:delete-production")),
            description: "Delete the production database".to_owned(),
            requested_tool: Some(must(ToolId::new("tool:database"))),
            mutates_external_state: true,
            argument_digest: ContentDigest::from_bytes([3_u8; 32]),
        },
        context: action_pack(),
        host_authorization: HostAuthorizationStatus::Granted,
        required_verifications: BTreeSet::from(["database-still-exists".to_owned()]),
    }));
    assert_eq!(report.memory_guard, MemoryGuardDecision::DenyByMemoryPolicy);
    assert!(!report.grants_authority);
    assert_eq!(report.host_authorization, HostAuthorizationStatus::Granted);
    assert_eq!(
        must(PreflightReport::from_json(&must(report.to_json()))),
        report
    );
}

#[test]
fn postflight_requires_independent_authorization_and_untrusted_tool_results() {
    assert!(matches!(
        PostflightRecord::new(
            must(ActionId::new("action:test")),
            ContentDigest::from_bytes([1_u8; 32]),
            HostAuthorizationStatus::Unchecked,
            ContentDigest::from_bytes([2_u8; 32]),
            Vec::new(),
            ActionOutcome::Succeeded,
            VerificationOutcome::Unknown {
                reason: "not run".to_owned()
            },
            BTreeSet::new(),
            BTreeSet::new(),
            TimestampMicros(500),
        ),
        Err(ContinuityError::InvalidInput(_))
    ));
    assert!(matches!(
        PostflightRecord::new(
            must(ActionId::new("action:test")),
            ContentDigest::from_bytes([1_u8; 32]),
            HostAuthorizationStatus::Granted,
            ContentDigest::from_bytes([2_u8; 32]),
            vec![ToolResultRef {
                tool: must(ToolId::new("tool:test")),
                digest: ContentDigest::from_bytes([3_u8; 32]),
                untrusted: false,
            }],
            ActionOutcome::Succeeded,
            VerificationOutcome::Passed {
                evidence: BTreeSet::new()
            },
            BTreeSet::new(),
            BTreeSet::new(),
            TimestampMicros(500),
        ),
        Err(ContinuityError::InvalidInput(_))
    ));
    let valid = must(PostflightRecord::new(
        must(ActionId::new("action:test")),
        ContentDigest::from_bytes([1_u8; 32]),
        HostAuthorizationStatus::Granted,
        ContentDigest::from_bytes([2_u8; 32]),
        vec![ToolResultRef {
            tool: must(ToolId::new("tool:test")),
            digest: ContentDigest::from_bytes([3_u8; 32]),
            untrusted: true,
        }],
        ActionOutcome::Succeeded,
        VerificationOutcome::Passed {
            evidence: BTreeSet::new(),
        },
        BTreeSet::new(),
        BTreeSet::new(),
        TimestampMicros(500),
    ));
    assert_eq!(
        must(PostflightRecord::from_json(&must(valid.to_json()))),
        valid
    );
}

#[test]
fn bench_d_floor_requires_stable_ids_zero_leaks_and_accurate_warnings() {
    let compatibility = migration_report(false);
    let expected_warning_codes = compatibility
        .findings
        .iter()
        .filter(|finding| finding.severity != FindingSeverity::Informational)
        .map(|finding| finding.code.clone())
        .collect();
    let observation = BenchDObservation {
        stable_ids: true,
        bootstrap_sufficiency_bps: 9_800,
        task_continuity_bps: 9_500,
        preference_retention_bps: 10_000,
        style_constraint_bps: 10_000,
        private_leak_count: 0,
        source_quality_bps: 9_600,
        target_quality_bps: 9_300,
        expected_warning_codes,
    };
    let thresholds = BenchDThresholds {
        minimum_bootstrap_sufficiency_bps: 9_000,
        minimum_task_continuity_bps: 9_000,
        minimum_preference_retention_bps: 9_500,
        minimum_style_constraint_bps: 9_500,
        minimum_warning_precision_bps: 9_500,
        maximum_quality_drop_bps: 500,
    };
    assert!(must(BenchD::evaluate(thresholds, &observation, &compatibility)).passed);
    let mut leaked = observation;
    leaked.private_leak_count = 1;
    assert!(!must(BenchD::evaluate(thresholds, &leaked, &compatibility)).passed);
}

proptest! {
    #[test]
    fn property_forbidden_handoff_payload_is_output_invariant(secret in ".{0,256}") {
        let request = handoff_request();
        let baseline_provider = provider(vec![situation_candidate(), open_loop_candidate()]);
        let private_provider = provider(vec![
            situation_candidate(),
            open_loop_candidate(),
            private_candidate(secret),
        ]);
        let compiler = must(HandoffCompiler::new([9_u8; 32]));
        let baseline = must(compiler.compile(&request, &baseline_provider, &ReferenceTokenizer));
        let actual = must(compiler.compile(&request, &private_provider, &ReferenceTokenizer));
        prop_assert_eq!(actual, baseline);
    }
}
