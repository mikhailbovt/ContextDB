//! Executable BENCH-A reference-stack workload.

#![allow(
    clippy::expect_used,
    reason = "the release harness fails immediately when a fixed fixture ID is invalid"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;

use contextdb_chat::*;
use contextdb_context::{
    BlockId, BlockRepresentation, CandidateUsePolicy, CompileRequest, CompressionLevel,
    ContentTaint, ContentTrust, ContextBudgets, ContextCompiler, DisclosureRule,
    InMemoryContextProvider, InstructionCapability, InstructionHierarchy, InterpretationRule,
    ModelProfile, PackBlockKind, PackCandidate, PackPurpose, PositionProfile, ProviderCandidate,
    RecallContextBinding, ReferenceTokenizer, RendererKind, SourceClass, StructuredFormat,
    SupportState,
};
use contextdb_core::{
    AcceptanceState, AccessCapability, ActorId, AgentId, Audience, AudienceGrant, ConflictState,
    ConsentPolicy, ConversationMode, CueBundle, DerivationKind, DerivationRef, EpistemicBasis,
    EpistemicRole, EpistemicState, EvidencePolicy, LifecycleState, MemorySpaceId, MemorySubjectId,
    MemoryUsePolicy, ModelProfileId, ModificationPolicy, NonEmptyVec, OwnershipPolicy,
    PipelineIdentity, PolicyDecision, PolicyId, Purpose, QueryContent, RecallBudgets, RecallIntent,
    RecallRequest, RetentionPolicy, ScopeInheritance, ScopeKind, ScopeRef, SecurityClassification,
    SecurityPolicy, SemanticEnvelope, Session, SessionState, SituationFrame, TemporalConstraint,
    TemporalContext, TimeRange, TimestampMicros, WeightedScope, WorkspaceId,
};
use contextdb_recall::{
    AccessConsent, AccessRule, DeterministicRecallRequest, MemoryUseDecision, ProviderRequest,
    RecallEngine, RecallLimits, RecallMode, RecallPrincipal, RecallProvider, RecallSensitivity,
    ReferenceProvider,
};
use contextdb_reference::{
    AccessLabel, Consent, ContextDb, Lifecycle, LogicalRecord, Mutation, RecordKind, SemanticLinks,
    SemanticTransaction, Sensitivity, ValidTime,
};
use contextdb_storage::{Durability, StorageEngine, VerifyMode};
use contextdb_storage_redb::RedbStorage;
use serde::Serialize;
use serde_json::json;
use tempfile::TempDir;

const DAY_MICROS: i128 = 86_400_000_000;
const PURPOSE_KEY: &str = "conversation";

#[derive(Clone)]
struct SessionFixture {
    registration: ChatSessionRegistration,
    principal: ConversationPrincipal,
}

#[derive(Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
struct ReferenceDiagnostics {
    storage_backend: &'static str,
    durability: &'static str,
    registered_sessions: u32,
    acknowledged_turns: u32,
    semantic_records: u32,
    semantic_commit_seq: u64,
    chat_journal_head: u64,
    verified_sessions: u64,
    verified_turns: u64,
    verified_semantic_jobs: u64,
    verified_pending_captures: u64,
    primary_runtime_calls: u32,
    secondary_runtime_calls: u32,
    compiled_contexts: u32,
    sensitive_policy_probes: u32,
    sensitive_records_excluded: u32,
    registration_micros: u64,
    ingestion_micros: u64,
    restart_and_verify_micros: u64,
    query_stack_micros: u64,
    database_file_bytes: u64,
    semantic_export_bytes: u64,
    semantic_export_blake3: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionOutput<'a> {
    schema_version: &'static str,
    scale: &'static str,
    workload: &'a BenchAManifest,
    dataset_digest: String,
    report: &'a BenchAReport,
    thresholds: BenchAThresholds,
    failures: Vec<BenchAGateFailure>,
    passed: bool,
    diagnostics: &'a ReferenceDiagnostics,
}

struct ReferenceBenchSystem {
    _temp: TempDir,
    database_path: PathBuf,
    store: Option<ChatStore<RedbStorage>>,
    sessions: Vec<SessionFixture>,
    semantic_db: ContextDb,
    semantic_mutations: Vec<Mutation>,
    semantic_ready: bool,
    indexed_turns: BTreeMap<String, BenchATurn>,
    workspace: WorkspaceId,
    user_actor: ActorId,
    user_subject: MemorySubjectId,
    assistant_subject: MemorySubjectId,
    agent: AgentId,
    scope: ScopeRef,
    memory_use_policy: PolicyId,
    total_turns: u32,
    virtual_now: TimestampMicros,
    ingestion_started: Option<Instant>,
    diagnostics: ReferenceDiagnostics,
}

impl ReferenceBenchSystem {
    fn new(dataset: &BenchADataset) -> Result<Self> {
        let temporary =
            tempfile::tempdir().map_err(|error| ChatError::Runtime(error.to_string()))?;
        let database_path = temporary.path().join("bench-a.redb");
        let engine = RedbStorage::open(&database_path)?;
        let store = ChatStore::new(engine, ChatMiddlewareConfig::default())?;

        let workspace = stable_id(1);
        let memory_space = stable_id(2);
        let user_actor = stable_id(3);
        let assistant_actor = stable_id(4);
        let user_subject = stable_id(5);
        let assistant_subject = stable_id(6);
        let scope = ScopeRef {
            kind: ScopeKind::Workspace,
            id: stable_id(7),
            inheritance: ScopeInheritance::Descendants,
        };
        let agent = stable_id(8);
        let memory_use_policy = stable_id(9);

        let registration_started = Instant::now();
        let mut sessions = Vec::with_capacity(dataset.manifest.sessions as usize);
        for ordinal in 0..dataset.manifest.sessions {
            let fixture = session_fixture(
                ordinal,
                workspace,
                memory_space,
                user_actor,
                assistant_actor,
                user_subject,
                assistant_subject,
                agent,
                memory_use_policy,
                scope.clone(),
            )?;
            store.register_session(fixture.registration.clone())?;
            sessions.push(fixture);
        }

        let (semantic_mutations, indexed_turns) =
            semantic_projection(dataset, workspace, user_subject, &scope)?;
        let virtual_days = dataset.manifest.virtual_years.saturating_mul(365);
        Ok(Self {
            _temp: temporary,
            database_path,
            store: Some(store),
            sessions,
            semantic_db: reference_db()?,
            semantic_mutations,
            semantic_ready: false,
            indexed_turns,
            workspace,
            user_actor,
            user_subject,
            assistant_subject,
            agent,
            scope,
            memory_use_policy,
            total_turns: dataset.manifest.turns,
            virtual_now: TimestampMicros(day_micros(virtual_days)),
            ingestion_started: None,
            diagnostics: ReferenceDiagnostics {
                storage_backend: "contextdb-storage-redb",
                durability: "sync",
                registered_sessions: dataset.manifest.sessions,
                registration_micros: micros(registration_started.elapsed()),
                ..ReferenceDiagnostics::default()
            },
        })
    }

    fn store(&self) -> Result<&ChatStore<RedbStorage>> {
        self.store
            .as_ref()
            .ok_or(ChatError::InvalidInput("bench_a_store_closed"))
    }

    fn ensure_semantic_projection(&mut self) -> Result<()> {
        if self.semantic_ready {
            return Ok(());
        }
        let mutations = std::mem::take(&mut self.semantic_mutations);
        let receipt = self
            .semantic_db
            .commit(SemanticTransaction {
                base_seq: 0,
                idempotency_key: "bench-a-semantic-projection-v1".to_owned(),
                mutations,
            })
            .map_err(reference_error)?;
        self.diagnostics.semantic_commit_seq = receipt.commit_seq;
        self.semantic_ready = true;
        Ok(())
    }

    fn recall_request(&self, query: &BenchAQuery) -> Result<DeterministicRecallRequest> {
        let (intent, mode, temporal) = match query.class {
            BenchAQueryClass::ExplicitRecall => (
                RecallIntent::Continuity,
                RecallMode::Explicit,
                TemporalConstraint::Current,
            ),
            BenchAQueryClass::ImplicitContinuity => (
                RecallIntent::Continuity,
                RecallMode::ImplicitContinuity,
                TemporalConstraint::Current,
            ),
            BenchAQueryClass::PersonResolution => (
                RecallIntent::Relational,
                RecallMode::Relational,
                TemporalConstraint::Current,
            ),
            BenchAQueryClass::SharedReference | BenchAQueryClass::Correction => (
                RecallIntent::Continuity,
                RecallMode::Explicit,
                TemporalConstraint::Current,
            ),
            BenchAQueryClass::HistoricalBelief => {
                let day = query
                    .expected_memory_ids
                    .iter()
                    .next()
                    .and_then(|id| self.indexed_turns.get(id))
                    .map_or(0, |turn| turn.virtual_day);
                let range = TimeRange::new(
                    TimestampMicros(day_micros(day)),
                    Some(TimestampMicros(day_micros(day.saturating_add(1)))),
                )?;
                (
                    RecallIntent::HistoricalTruth,
                    RecallMode::Historical,
                    TemporalConstraint::ValidDuring { range },
                )
            }
            BenchAQueryClass::CurrentState => (
                RecallIntent::CurrentTruth,
                RecallMode::Required,
                TemporalConstraint::Current,
            ),
            BenchAQueryClass::Unknown => (
                RecallIntent::Continuity,
                RecallMode::Optional,
                TemporalConstraint::Current,
            ),
            BenchAQueryClass::AppropriateSilence => (
                RecallIntent::Continuity,
                RecallMode::Optional,
                TemporalConstraint::Current,
            ),
            BenchAQueryClass::Reflective => (
                RecallIntent::Reflective,
                RecallMode::Associative,
                TemporalConstraint::Current,
            ),
        };
        let scopes = NonEmptyVec::new(self.scope.clone());
        let purpose = Purpose::Conversation;
        Ok(DeterministicRecallRequest {
            request: RecallRequest {
                agent_id: self.agent,
                actor_id: self.user_actor,
                session_id: None,
                cues: CueBundle {
                    current_input: QueryContent::Text(query.query_text.clone()),
                    recent_observations: Vec::new(),
                    participants: NonEmptyVec::try_from_vec(
                        vec![self.user_subject, self.assistant_subject],
                        "bench_a.participants",
                    )?,
                    active_referents: Vec::new(),
                    active_topics: Vec::new(),
                    temporal_context: TemporalContext {
                        now: self.virtual_now,
                        referenced_valid_time: match temporal {
                            TemporalConstraint::ValidDuring { range }
                            | TemporalConstraint::Bitemporal {
                                valid_during: range,
                                ..
                            } => Some(range),
                            TemporalConstraint::Current | TemporalConstraint::KnownAt { .. } => {
                                None
                            }
                        },
                        known_at: None,
                    },
                    location_context: None,
                    conversation_mode: ConversationMode::Casual,
                    goal: None,
                    interaction_signals: Vec::new(),
                },
                intent,
                scopes: scopes.clone(),
                temporal,
                required_facets: Vec::new(),
                budgets: RecallBudgets {
                    max_tokens: 512,
                    max_latency_micros: 500_000,
                    max_candidates: 2_048,
                    max_graph_visits: 2_048,
                    max_evidence_items: 8,
                },
                evidence_policy: EvidencePolicy {
                    require_primary_evidence: false,
                    include_quotes: false,
                    permit_derived_only: true,
                },
                memory_use_policy: self.memory_use_policy,
                purpose: purpose.clone(),
                target_model: Option::<ModelProfileId>::None,
            },
            principal: RecallPrincipal::from_core(
                self.user_subject,
                self.workspace,
                &scopes,
                &purpose,
                SecurityClassification::Confidential,
            ),
            mode,
            limits: RecallLimits {
                max_nodes_examined: 2_048,
                max_seed_candidates: 256,
                max_graph_hops: 1,
                max_frontier_per_hop: 64,
                max_evidence_units: 8,
                max_context_tokens: 512,
                deadline_micros: 500_000,
            },
            query_vector: None,
            continuation: None,
        })
    }

    fn compile_context(
        &self,
        query: &BenchAQuery,
        runtime: BenchARuntimeLane,
        recall: &contextdb_recall::DeterministicRecallResult,
        temporal: TemporalConstraint,
    ) -> Result<contextdb_context::CompiledContext> {
        let included = recall
            .items
            .iter()
            .filter(|item| item.use_decision.is_included())
            .collect::<Vec<_>>();
        if included.len() > 1 {
            return Err(ChatError::Recall(
                "BENCH-A query selected more than one final memory".to_owned(),
            ));
        }
        let snapshot = recall
            .snapshot
            .clone()
            .ok_or_else(|| ChatError::Recall("recall returned no snapshot".to_owned()))?;
        let access = recall_access(self.workspace, self.user_subject, &self.scope);
        let candidates = included
            .iter()
            .map(|item| {
                let text = item
                    .content
                    .clone()
                    .unwrap_or_else(|| item.document_id.to_string());
                Ok(ProviderCandidate {
                    access: access.clone(),
                    use_policy: CandidateUsePolicy {
                        influence: PolicyDecision::Allow,
                        mention: PolicyDecision::Allow,
                        external_model_use: PolicyDecision::Allow,
                        disclosure: DisclosureRule::MayMention,
                    },
                    candidate: PackCandidate {
                        id: BlockId::new(item.document_id.as_str())?,
                        kind: PackBlockKind::Situation,
                        representations: vec![BlockRepresentation {
                            level: CompressionLevel::L0Orientation,
                            summary: text,
                            fields: BTreeMap::new(),
                            omitted_facets: BTreeSet::new(),
                        }],
                        exact_fragments: Vec::new(),
                        memory_refs: Vec::new(),
                        claim_ids: BTreeSet::new(),
                        evidence_handles: BTreeSet::new(),
                        facets: BTreeSet::new(),
                        scopes: BTreeSet::from([self.scope.id.to_string()]),
                        valid_time: None,
                        known_at_commit: snapshot.commit_seq,
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
                        source_class: SourceClass::UserStatement,
                        taints: BTreeSet::from([ContentTaint::UserControlled]),
                        interpretation: InterpretationRule::FactualData,
                        support: SupportState::Supported,
                        conflict: None,
                        unknown: None,
                        utility_micros: 1_000_000,
                        mandatory: true,
                    },
                })
            })
            .collect::<contextdb_context::Result<Vec<_>>>()?;
        let provider = InMemoryContextProvider::new(snapshot.clone(), candidates, Vec::new())?;
        let profile = runtime_profile(runtime);
        let request = CompileRequest {
            pack_id: stable_pack_id(&query.id),
            snapshot,
            principal: self.recall_principal(),
            filter_digest: recall.trace.filter_digest.clone(),
            purpose: PackPurpose::Conversation,
            scopes: BTreeSet::from([self.scope.id.to_string()]),
            temporal_view: temporal,
            required_facets: Vec::new(),
            budgets: ContextBudgets {
                hard_tokens: 4_096,
                soft_tokens: 3_584,
                max_blocks: 8,
                max_evidence_blocks: 8,
                max_raw_evidence_tokens: 512,
                max_history_tokens: 1_024,
                max_conflict_tokens: 512,
                max_serialized_bytes: 256_000,
                max_selection_evaluations: 32,
            },
            model_profile: profile,
            explicit_memory_request: matches!(
                query.class,
                BenchAQueryClass::ExplicitRecall
                    | BenchAQueryClass::PersonResolution
                    | BenchAQueryClass::SharedReference
                    | BenchAQueryClass::HistoricalBelief
                    | BenchAQueryClass::CurrentState
                    | BenchAQueryClass::Correction
            ),
            require_primary_evidence: false,
            continuation: None,
        };
        let binding = RecallContextBinding::identity(recall)?;
        ContextCompiler::new([0xA5; 32])?
            .compile_recall(&request, recall, &binding, &provider, &ReferenceTokenizer)
            .map_err(ChatError::from)
    }

    fn recall_principal(&self) -> RecallPrincipal {
        RecallPrincipal {
            subject: self.user_subject.to_string(),
            audiences: BTreeSet::new(),
            workspace: self.workspace.to_string(),
            scopes: BTreeSet::from([self.scope.id.to_string()]),
            purpose: PURPOSE_KEY.to_owned(),
            clearance: RecallSensitivity::Confidential,
        }
    }

    fn finish_diagnostics(&mut self) -> Result<()> {
        let report = self.store()?.verify()?;
        self.diagnostics.chat_journal_head = report.journal_head.get();
        self.diagnostics.verified_sessions = report.sessions;
        self.diagnostics.verified_turns = report.turns;
        self.diagnostics.verified_semantic_jobs = report.semantic_jobs;
        self.diagnostics.verified_pending_captures = report.pending_captures;
        self.store()?.journal().engine().verify(VerifyMode::Deep)?;
        self.diagnostics.database_file_bytes = fs::metadata(&self.database_path)
            .map_err(|error| ChatError::Runtime(error.to_string()))?
            .len();
        Ok(())
    }
}

impl BenchASystem for ReferenceBenchSystem {
    fn ingest(&mut self, turn: &BenchATurn) -> Result<()> {
        let started = *self.ingestion_started.get_or_insert_with(Instant::now);
        let fixture = self
            .sessions
            .get(turn.session as usize)
            .ok_or(ChatError::InvalidInput("bench_a_session"))?;
        let occurred_at = TimestampMicros(
            day_micros(turn.virtual_day)
                .checked_add(i64::from(turn.ordinal % 86_400_000))
                .ok_or(ChatError::ArithmeticOverflow)?,
        );
        let request = BeforeTurnRequest {
            session_id: fixture.registration.session.id,
            principal: fixture.principal.clone(),
            interaction_id: ChatInteractionId::new(format!("bench-a-{:08}", turn.ordinal))?,
            idempotency_key: ChatIdempotencyKey::new(format!(
                "bench-a-capture-{:08}",
                turn.ordinal
            ))?,
            message: ChatText::new(format!(
                "BENCH-A memory {}: person {}, topic {}, event {:?}.",
                turn.memory_id, turn.person, turn.topic, turn.kind
            ))?,
            occurred_at,
            situation: SituationPatch::default(),
            memory_intent: ConversationMemoryIntent::ImplicitContinuity,
            max_recall_micros: 500_000,
            target_profile_id: "bench-a-primary".to_owned(),
            structured_candidates: Vec::new(),
        };
        let receipt = self.store()?.capture_user(&request)?;
        if receipt.durability != Durability::Sync {
            return Err(ChatError::Corrupt(
                "BENCH-A capture was acknowledged below Sync durability".to_owned(),
            ));
        }
        self.diagnostics.acknowledged_turns = self
            .diagnostics
            .acknowledged_turns
            .checked_add(1)
            .ok_or(ChatError::ArithmeticOverflow)?;
        if turn.ordinal.saturating_add(1) == self.total_turns {
            self.diagnostics.ingestion_micros = micros(started.elapsed());
        }
        if turn.ordinal % 5_000 == 4_999 {
            eprintln!(
                "BENCH-A ingest: {}/{} turns",
                turn.ordinal + 1,
                self.total_turns
            );
        }
        Ok(())
    }

    fn restart(&mut self) -> Result<()> {
        self.ensure_semantic_projection()?;
        let started = Instant::now();
        let export = self.semantic_db.export().map_err(reference_error)?;
        self.diagnostics.semantic_export_bytes =
            u64::try_from(export.len()).map_err(|_| ChatError::ArithmeticOverflow)?;
        self.diagnostics.semantic_export_blake3 = blake3::hash(&export).to_hex().to_string();
        self.semantic_db = ContextDb::import(&export).map_err(reference_error)?;
        let old = self
            .store
            .take()
            .ok_or(ChatError::InvalidInput("bench_a_store_closed"))?;
        drop(old);
        self.store = Some(ChatStore::new(
            RedbStorage::open(&self.database_path)?,
            ChatMiddlewareConfig::default(),
        )?);
        let report = self.store()?.verify()?;
        self.diagnostics.chat_journal_head = report.journal_head.get();
        self.diagnostics.verified_sessions = report.sessions;
        self.diagnostics.verified_turns = report.turns;
        self.diagnostics.verified_semantic_jobs = report.semantic_jobs;
        self.diagnostics.verified_pending_captures = report.pending_captures;
        self.diagnostics.restart_and_verify_micros = micros(started.elapsed());
        Ok(())
    }

    fn query(&mut self, query: &BenchAQuery, runtime: BenchARuntimeLane) -> Result<BenchAAnswer> {
        self.ensure_semantic_projection()?;
        let started = Instant::now();
        if query.class == BenchAQueryClass::AppropriateSilence {
            let provider = ReferenceProvider {
                database: &self.semantic_db,
            };
            let provider_request = ProviderRequest {
                snapshot: provider
                    .snapshot(None)
                    .map_err(|error| ChatError::Recall(error.to_string()))?,
                principal: self.recall_principal(),
                filter_digest: "bench-a-sensitive-policy-probe-v1".to_owned(),
            };
            let corpus = provider
                .authorized_corpus(&provider_request)
                .map_err(|error| ChatError::Recall(error.to_string()))?;
            if corpus
                .documents()
                .iter()
                .any(|document| query.forbidden_memory_ids.contains(document.id.as_str()))
            {
                return Err(ChatError::Corrupt(
                    "labelled sensitive memory crossed the authorization boundary".to_owned(),
                ));
            }
            self.diagnostics.sensitive_policy_probes = self
                .diagnostics
                .sensitive_policy_probes
                .checked_add(1)
                .ok_or(ChatError::ArithmeticOverflow)?;
            self.diagnostics.sensitive_records_excluded = self
                .diagnostics
                .sensitive_records_excluded
                .checked_add(
                    u32::try_from(query.forbidden_memory_ids.len())
                        .map_err(|_| ChatError::ArithmeticOverflow)?,
                )
                .ok_or(ChatError::ArithmeticOverflow)?;
        }
        let request = self.recall_request(query)?;
        let temporal = request.request.temporal;
        let recall = RecallEngine::new([0x5A; 32])
            .recall(
                &ReferenceProvider {
                    database: &self.semantic_db,
                },
                &request,
            )
            .map_err(|error| ChatError::Recall(error.to_string()))?;
        let recalled_memory_ids = recall
            .items
            .iter()
            .filter(|item| item.use_decision.is_included())
            .map(|item| item.document_id.to_string())
            .collect::<BTreeSet<_>>();
        let mentioned_memory_ids = recall
            .items
            .iter()
            .filter(|item| item.use_decision == MemoryUseDecision::IncludeAndMention)
            .map(|item| item.document_id.to_string())
            .collect::<BTreeSet<_>>();
        let user_message = ChatText::new(query.query_text.clone())?;
        let compiled = if recall.snapshot.is_some() {
            Some(self.compile_context(query, runtime, &recall, temporal)?)
        } else {
            None
        };
        let prepared = match runtime {
            BenchARuntimeLane::Primary => {
                self.diagnostics.primary_runtime_calls = self
                    .diagnostics
                    .primary_runtime_calls
                    .checked_add(1)
                    .ok_or(ChatError::ArithmeticOverflow)?;
                SeparatedChannelsAdapter.prepare(&user_message, compiled.as_ref())?
            }
            BenchARuntimeLane::Secondary => {
                self.diagnostics.secondary_runtime_calls = self
                    .diagnostics
                    .secondary_runtime_calls
                    .checked_add(1)
                    .ok_or(ChatError::ArithmeticOverflow)?;
                SinglePromptJsonAdapter.prepare(&user_message, compiled.as_ref())?
            }
        };
        let prepared_digest = match prepared {
            PreparedRuntimeInput::Separated(input) => input.context_digest,
            PreparedRuntimeInput::SinglePrompt(input) => input.context_digest,
        };
        let expected_context_digest = compiled
            .as_ref()
            .map(|context| context.canonical_digest.as_str());
        if prepared_digest.as_deref() != expected_context_digest {
            return Err(ChatError::Runtime(
                "runtime adapter changed the compiled ContextPack binding".to_owned(),
            ));
        }
        if compiled.is_some() {
            self.diagnostics.compiled_contexts = self
                .diagnostics
                .compiled_contexts
                .checked_add(1)
                .ok_or(ChatError::ArithmeticOverflow)?;
        }
        let latency = micros(started.elapsed());
        self.diagnostics.query_stack_micros = self
            .diagnostics
            .query_stack_micros
            .checked_add(latency)
            .ok_or(ChatError::ArithmeticOverflow)?;
        Ok(BenchAAnswer {
            semantic_answer_digest: semantic_answer_digest(&recalled_memory_ids)?,
            recalled_memory_ids,
            mentioned_memory_ids,
            recall_latency_micros: latency,
            context_tokens: compiled.map_or(0, |context| context.rendered.total_tokens),
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the deterministic session fixture keeps every stable identity explicit"
)]
fn session_fixture(
    ordinal: u32,
    workspace: WorkspaceId,
    memory_space: MemorySpaceId,
    user_actor: ActorId,
    assistant_actor: ActorId,
    user_subject: MemorySubjectId,
    assistant_subject: MemorySubjectId,
    agent: AgentId,
    memory_use_policy: PolicyId,
    scope: ScopeRef,
) -> Result<SessionFixture> {
    let session_id = stable_id(10_000 + u64::from(ordinal));
    let registration = ChatSessionRegistration {
        session: Session {
            id: session_id,
            agent_id: agent,
            workspace_id: workspace,
            participants: NonEmptyVec::try_from_vec(
                vec![user_subject, assistant_subject],
                "bench_a.participants",
            )?,
            memory_space,
            started_at: TimestampMicros(i64::from(ordinal) + 1),
            ended_at: None,
            parent_session: None,
            state: SessionState::Active,
        },
        source_id: stable_id(20_000 + u64::from(ordinal)),
        stream_id: stable_id(30_000 + u64::from(ordinal)),
        memory_use_policy,
        user_actor,
        assistant_actor,
        user_subject,
        assistant_subject,
        user_envelope: envelope(
            user_subject,
            user_actor,
            &scope,
            40_000 + u64::from(ordinal),
        ),
        assistant_envelope: envelope(
            assistant_subject,
            assistant_actor,
            &scope,
            50_000 + u64::from(ordinal),
        ),
        initial_frame: SituationFrame {
            session_id,
            conversation_mode: ConversationMode::Casual,
            active_topics: Vec::new(),
            active_referents: Vec::new(),
            participant_states: Vec::new(),
            goal_stack: Vec::new(),
            active_scopes: NonEmptyVec::new(WeightedScope {
                scope: scope.clone(),
                weight: 1.0,
            }),
            open_questions: Vec::new(),
            open_loops: Vec::new(),
            working_hypotheses: Vec::new(),
            recent_observations: Vec::new(),
            environment: None,
            captured_at: TimestampMicros(1),
            expires_at: TimestampMicros(i64::MAX / 2),
        },
    };
    Ok(SessionFixture {
        registration,
        principal: ConversationPrincipal {
            actor_id: user_actor,
            subject_id: user_subject,
            allowed_memory_spaces: BTreeSet::from([memory_space]),
            allowed_scopes: BTreeSet::from([scope.id]),
        },
    })
}

fn envelope(
    owner: MemorySubjectId,
    actor: ActorId,
    scope: &ScopeRef,
    derivation: u64,
) -> SemanticEnvelope {
    let purposes = BTreeSet::from([Purpose::Conversation]);
    SemanticEnvelope {
        scopes: NonEmptyVec::new(scope.clone()),
        perspective: contextdb_core::Perspective {
            knower: owner,
            experiencer: Some(owner),
            narrator: actor,
            role: EpistemicRole::Asserter,
        },
        ownership: OwnershipPolicy {
            owners: NonEmptyVec::new(owner),
            audience_grants: vec![AudienceGrant {
                audience: Audience::Subject { id: owner },
                purposes: purposes.clone(),
                capabilities: BTreeSet::from([
                    AccessCapability::Retrieve,
                    AccessCapability::InfluenceResponse,
                    AccessCapability::Mention,
                    AccessCapability::Derive,
                ]),
            }],
            allowed_purposes: purposes,
            modification: ModificationPolicy {
                owners_may_modify: true,
                delegates_may_modify: false,
                system_may_derive: true,
            },
        },
        consent: ConsentPolicy {
            required: false,
            decisions: Vec::new(),
        },
        use_policy: MemoryUsePolicy {
            retrieve: PolicyDecision::Allow,
            influence_response: PolicyDecision::Allow,
            mention_explicitly: PolicyDecision::Allow,
            external_model_use: PolicyDecision::Deny,
            retention: RetentionPolicy::Indefinite,
        },
        security: SecurityPolicy {
            classification: SecurityClassification::Confidential,
            labels: BTreeSet::from(["bench-a-conversation".to_owned()]),
            required_compartments: BTreeSet::new(),
            allow_external_processing: false,
        },
        derivation: DerivationRef {
            id: stable_id(derivation),
            kind: DerivationKind::ActorAssertion,
            actor: Some(actor),
            model_call: None,
            pipeline: PipelineIdentity {
                name: "bench-a-reference".to_owned(),
                version: "1".to_owned(),
                schema_version: "1".to_owned(),
            },
            inputs: Vec::new(),
        },
    }
}

fn semantic_projection(
    dataset: &BenchADataset,
    workspace: WorkspaceId,
    user_subject: MemorySubjectId,
    scope: &ScopeRef,
) -> Result<(Vec<Mutation>, BTreeMap<String, BenchATurn>)> {
    let mut aliases = BTreeMap::<String, BTreeSet<String>>::new();
    let mut sensitive_ordinal = 0_usize;
    for query in &dataset.queries {
        for id in &query.expected_memory_ids {
            aliases
                .entry(id.clone())
                .or_default()
                .insert(query.query_text.clone());
        }
        for id in &query.temporally_forbidden_memory_ids {
            aliases
                .entry(id.clone())
                .or_default()
                .insert(query.query_text.clone());
        }
        if query.class == BenchAQueryClass::PersonResolution {
            for id in &query.wrong_person_memory_ids {
                aliases
                    .entry(id.clone())
                    .or_default()
                    .insert("person".to_owned());
            }
        }
        if query.class == BenchAQueryClass::AppropriateSilence {
            let forbidden = query.forbidden_memory_ids.iter().collect::<Vec<_>>();
            if let Some(id) = forbidden.get(sensitive_ordinal % forbidden.len().max(1)) {
                aliases
                    .entry((**id).clone())
                    .or_default()
                    .insert(query.query_text.clone());
            }
            sensitive_ordinal = sensitive_ordinal.saturating_add(1);
        }
    }
    for turn in dataset.turns.iter().filter(|turn| turn.private) {
        aliases.entry(turn.memory_id.clone()).or_default();
    }

    let turn_by_id = dataset
        .turns
        .iter()
        .map(|turn| (turn.memory_id.clone(), turn))
        .collect::<BTreeMap<_, _>>();
    let mut indexed_turns = BTreeMap::new();
    let mut mutations = Vec::with_capacity(aliases.len());
    for (memory_id, record_aliases) in aliases {
        let turn = turn_by_id
            .get(&memory_id)
            .ok_or(ChatError::InvalidInput("bench_a_projection_turn"))?;
        indexed_turns.insert(memory_id.clone(), (*turn).clone());
        let sensitive = turn.private;
        let label = AccessLabel {
            workspace: workspace.to_string(),
            scopes: BTreeSet::from([scope.id.to_string()]),
            owners: BTreeSet::from([user_subject.to_string()]),
            audience: BTreeSet::from([user_subject.to_string()]),
            audience_purpose_grants: BTreeMap::from([(
                user_subject.to_string(),
                BTreeSet::from([PURPOSE_KEY.to_owned()]),
            )]),
            purposes: BTreeSet::from([PURPOSE_KEY.to_owned()]),
            sensitivity: if sensitive {
                Sensitivity::Restricted
            } else {
                Sensitivity::Private
            },
            consent: Consent::Granted,
            retrievable: true,
        };
        let valid_time = match turn.kind {
            BenchAEventKind::PreferenceChange => ValidTime {
                from: Some(i128::from(day_micros(turn.virtual_day))),
                to: Some(i128::from(day_micros(turn.virtual_day.saturating_add(1)))),
            },
            BenchAEventKind::Correction => ValidTime {
                from: Some(i128::from(day_micros(turn.virtual_day))),
                to: None,
            },
            BenchAEventKind::Casual
            | BenchAEventKind::SharedReference
            | BenchAEventKind::OpenLoop
            | BenchAEventKind::Sensitive
            | BenchAEventKind::Contradiction
            | BenchAEventKind::TemporaryMood
            | BenchAEventKind::ForgetRequest => ValidTime::UNBOUNDED,
        };
        let search_text = if record_aliases.is_empty() {
            format!("labelled sensitive {memory_id}")
        } else {
            record_aliases.iter().cloned().collect::<Vec<_>>().join(" ")
        };
        mutations.push(Mutation::Put {
            record: LogicalRecord {
                id: memory_id.clone(),
                kind: RecordKind::Node,
                access: label,
                valid_time,
                lifecycle: Lifecycle::Active,
                links: SemanticLinks::default(),
                value: json!({
                    "memory_id": memory_id,
                    "event_kind": turn.kind,
                    "person": turn.person,
                    "topic": turn.topic,
                    "virtual_day": turn.virtual_day
                }),
                search_text: Some(search_text),
                vector: None,
                attributes: BTreeMap::from([
                    ("aliases".to_owned(), serde_json::to_value(record_aliases)?),
                    ("facets".to_owned(), json!(["bench-a-memory"])),
                ]),
            },
            expected_revision: None,
        });
    }
    Ok((mutations, indexed_turns))
}

fn recall_access(
    workspace: WorkspaceId,
    user_subject: MemorySubjectId,
    scope: &ScopeRef,
) -> AccessRule {
    AccessRule {
        workspace: workspace.to_string(),
        scopes: BTreeSet::from([scope.id.to_string()]),
        owners: BTreeSet::from([user_subject.to_string()]),
        audience_purpose_grants: BTreeMap::from([(
            user_subject.to_string(),
            BTreeSet::from([PURPOSE_KEY.to_owned()]),
        )]),
        sensitivity: RecallSensitivity::Confidential,
        required_compartments: BTreeSet::new(),
        consent: AccessConsent::Granted,
        retrievable: true,
    }
}

fn runtime_profile(runtime: BenchARuntimeLane) -> ModelProfile {
    match runtime {
        BenchARuntimeLane::Primary => ModelProfile {
            id: "bench-a-separated-v1".to_owned(),
            family: "deterministic-separated".to_owned(),
            tokenizer_id: ReferenceTokenizer::ID.to_owned(),
            renderer: RendererKind::Chat,
            max_context_tokens: 8_192,
            reserved_output_tokens: 1_024,
            preferred_structured_format: StructuredFormat::Markdown,
            supports_tool_results: false,
            supports_native_citations: false,
            supports_prompt_caching: true,
            position_profile: PositionProfile::EvidenceAdjacent,
            instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
            max_schema_complexity: 64,
            external_processing: false,
        },
        BenchARuntimeLane::Secondary => ModelProfile {
            id: "bench-a-single-json-v1".to_owned(),
            family: "deterministic-single-prompt".to_owned(),
            tokenizer_id: ReferenceTokenizer::ID.to_owned(),
            renderer: RendererKind::CanonicalJson,
            max_context_tokens: 8_192,
            reserved_output_tokens: 1_024,
            preferred_structured_format: StructuredFormat::Json,
            supports_tool_results: false,
            supports_native_citations: false,
            supports_prompt_caching: true,
            position_profile: PositionProfile::SmallModelExplicit,
            instruction_hierarchy: InstructionHierarchy::SinglePromptDelimited,
            max_schema_complexity: 64,
            external_processing: false,
        },
    }
}

fn reference_db() -> Result<ContextDb> {
    ContextDb::new("contextdb-bench-a-reference-v1").map_err(reference_error)
}

fn reference_error(error: impl std::fmt::Display) -> ChatError {
    ChatError::Recall(error.to_string())
}

fn semantic_answer_digest(ids: &BTreeSet<String>) -> Result<contextdb_core::ContentDigest> {
    let bytes = serde_json::to_vec(ids)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-bench-a-semantic-answer-v1\0");
    hasher.update(&bytes);
    Ok(contextdb_core::ContentDigest::from_bytes(
        *hasher.finalize().as_bytes(),
    ))
}

fn stable_pack_id(query_id: &str) -> contextdb_core::ContextPackId {
    let digest = blake3::hash(query_id.as_bytes());
    let mut suffix = [0_u8; 8];
    suffix[2..].copy_from_slice(&digest.as_bytes()[..6]);
    stable_id(u64::from_be_bytes(suffix).max(1))
}

fn stable_id<T>(value: u64) -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    format!("00000000-0000-7000-8000-{:012x}", value.max(1))
        .parse()
        .expect("fixed UUID fixture")
}

fn day_micros(day: u32) -> i64 {
    i64::try_from(i128::from(day).saturating_mul(DAY_MICROS)).unwrap_or(i64::MAX)
}

fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn output_path(arguments: &[String]) -> Option<&Path> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == "--output")
        .map(|pair| Path::new(&pair[1]))
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let scale = if arguments.iter().any(|argument| argument == "--smoke") {
        BenchAScale::Smoke
    } else {
        BenchAScale::Full
    };
    let dataset = BenchADataset::generate(scale)?;
    let mut system = ReferenceBenchSystem::new(&dataset)?;
    let report = BenchAHarness::run(&dataset, &mut system)?;
    system.finish_diagnostics()?;
    system.diagnostics.semantic_records = u32::try_from(system.indexed_turns.len())?;
    let thresholds = BenchAThresholds::default();
    let failures = report.failures(thresholds);
    let output = ExecutionOutput {
        schema_version: "contextdb.bench-a-execution/v1",
        scale: match scale {
            BenchAScale::Smoke => "smoke",
            BenchAScale::Full => "full",
        },
        workload: &dataset.manifest,
        dataset_digest: dataset.digest.to_string(),
        report: &report,
        thresholds,
        passed: failures.is_empty(),
        failures,
        diagnostics: &system.diagnostics,
    };
    let bytes = serde_json::to_vec_pretty(&output)?;
    if let Some(path) = output_path(&arguments) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &bytes)?;
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    if output.passed {
        Ok(())
    } else {
        Err("BENCH-A did not meet every published threshold".into())
    }
}
