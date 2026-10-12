//! Shared owner-contract fixture; its reader never measures learned answer quality.

use super::*;
use contextdb_capture::{
    ExternalTool, ToolAction, ToolObservation, ToolOutcome, ToolReconciliation, ToolReplaySafety,
};
use contextdb_context::Result as ContextResult;
use contextdb_continuity::OwnedRunIdentity;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

pub(super) const COPPER: &str = "ARCHIVE_COPPER seal belongs to the amber expedition.";
pub(super) const SILVER: &str = "ARCHIVE_SILVER spare lantern is stored beside the north entrance.";
pub(super) const OPERATION: &str = "fixture.hybrid_registry";
pub(super) const DATABASE: &str = "owned-hybrid-vertical";

pub(super) fn budget() -> QueryBudget {
    QueryBudget::new(
        50_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}
pub(super) fn now() -> TimestampMicros {
    TimestampMicros(1_000_000)
}
fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}

#[derive(Debug)]
enum Backend {
    Controlled,
    Real(Box<OwnedLocalEmbedding>),
}

#[derive(Debug)]
pub(super) struct Encoder {
    backend: Backend,
    pub profile: TextEmbeddingProfile,
    pub source_forwards: AtomicUsize,
    pub measurements: AtomicUsize,
    pub query_forwards: AtomicUsize,
    pub query_texts: Mutex<Vec<String>>,
    pub revoke_after_measure: AtomicBool,
    pub revocation: Mutex<
        Option<(
            Arc<NativeService>,
            AuthenticatedRequestContext,
            ObservationId,
        )>,
    >,
}
impl Encoder {
    fn new() -> Self {
        Self::with_backend(
            Backend::Controlled,
            TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(
                b"controlled owned-hybrid fixture backend",
            )),
        )
    }
    pub(super) fn real(backend: OwnedLocalEmbedding) -> Self {
        let profile = backend.profile().clone();
        Self::with_backend(Backend::Real(Box::new(backend)), profile)
    }
    fn with_backend(backend: Backend, profile: TextEmbeddingProfile) -> Self {
        Self {
            backend,
            profile,
            source_forwards: AtomicUsize::new(0),
            measurements: AtomicUsize::new(0),
            query_forwards: AtomicUsize::new(0),
            query_texts: Mutex::new(vec![]),
            revoke_after_measure: AtomicBool::new(false),
            revocation: Mutex::new(None),
        }
    }
    pub(super) fn controlled(&self) -> bool {
        matches!(&self.backend, Backend::Controlled)
    }
    pub(super) fn budget(&self) -> QueryBudget {
        if self.controlled() {
            budget()
        } else {
            // Real source maintenance shares the same parent as each step/drive.
            QueryBudget::new(
                50_000_000,
                512 * 1024 * 1024,
                Duration::from_secs(180),
                Default::default(),
            )
        }
    }
    pub(super) fn shutdown(&mut self, parent: &mut QueryBudget) -> ServiceResult<()> {
        match &mut self.backend {
            Backend::Controlled => Ok(()),
            Backend::Real(backend) => backend.shutdown(parent),
        }
    }
    fn measured(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<TokenizedText> {
        parent
            .charge(text.len() as u64 + 1, text.len() as u64 * 2 + 16384)
            .map_err(budget_error)?;
        let input = self.profile.input_text(kind, text)?;
        let mut tokens = blake3::Hasher::new();
        for token in [1_i32, 2, 3, 4] {
            tokens.update(&token.to_le_bytes());
        }
        Ok(TokenizedText {
            profile_digest: self.profile.digest()?,
            kind,
            text_digest: digest(text.as_bytes()),
            input_digest: digest(input.as_bytes()),
            tokens_digest: ContentDigest::from_bytes(*tokens.finalize().as_bytes()),
            token_count: 4,
        })
    }
}
impl TextEmbeddingAdapter for Encoder {
    fn profile(&self) -> &TextEmbeddingProfile {
        &self.profile
    }
    fn measure_tokens(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<TokenizedText> {
        let observed = match &self.backend {
            Backend::Controlled => self.measured(kind, text, parent)?,
            Backend::Real(backend) => backend.measure_tokens(kind, text, parent)?,
        };
        assert_eq!(
            kind,
            EmbeddingTextKind::Query,
            "source projection does not use query preflight"
        );
        self.measurements.fetch_add(1, Ordering::SeqCst);
        if self.revoke_after_measure.swap(false, Ordering::SeqCst) {
            let (native, context, event) = self
                .revocation
                .lock()
                .expect("revocation fixture")
                .clone()
                .expect("declared revocation");
            native.revoke_original(
                &context,
                event,
                "hybrid-revoke-between-tokenize-and-forward",
                parent,
            )?;
        }
        Ok(observed)
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        let embedded = match &self.backend {
            Backend::Controlled => {
                let observed = self.measured(kind, text, parent)?;
                parent.charge(1024, 4096).map_err(budget_error)?;
                // Deliberately constant: no hash/oracle encoding or semantic claim.
                let mut values = vec![0_f32; 1024];
                values[0] = 1.;
                let mut hash = blake3::Hasher::new();
                for value in &values {
                    hash.update(&value.to_le_bytes());
                }
                EmbeddedText {
                    profile_digest: observed.profile_digest,
                    kind,
                    text_digest: observed.text_digest,
                    input_digest: observed.input_digest,
                    tokens_digest: observed.tokens_digest,
                    token_count: observed.token_count,
                    values,
                    vector_digest: ContentDigest::from_bytes(*hash.finalize().as_bytes()),
                }
            }
            Backend::Real(backend) => backend.embed(kind, text, parent)?,
        };
        match kind {
            EmbeddingTextKind::Source => {
                self.source_forwards.fetch_add(1, Ordering::SeqCst);
            }
            EmbeddingTextKind::Query => {
                self.query_forwards.fetch_add(1, Ordering::SeqCst);
                self.query_texts
                    .lock()
                    .expect("query texts")
                    .push(text.to_owned());
            }
        }
        Ok(embedded)
    }
}

#[derive(Debug)]
pub(super) struct Preparation {
    pub native: Arc<NativeService>,
    pub encoder: Arc<Encoder>,
}
impl PreparationHook for Preparation {
    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for scope in &context.request.scopes {
            let scope = scope.parse().expect("fixture scope");
            let input = self.native.interpretation_inputs(context, scope, parent)?;
            self.native.publish_assertions(
                PublishAssertionsRequest {
                    context: context.clone(),
                    idempotency_key: format!("hybrid-contract/{scope}/{}", input.scope_epoch),
                    scope,
                    expected_scope_epoch: input.scope_epoch,
                    covered_through: input.through,
                    pipeline: PipelineIdentity {
                        name: "controlled-no-state-corpus".into(),
                        version: "1".into(),
                        schema_version: "1".into(),
                    },
                    interpretations: input
                        .events
                        .into_iter()
                        .map(|event_id| EventInterpretation {
                            event_id,
                            disposition: InterpretationDisposition::NoStateChange,
                        })
                        .collect(),
                    mutations: vec![],
                    after_receipt: None,
                },
                parent,
            )?;
        }
        loop {
            if self
                .native
                .project_originals_bm25(context, false, 64, parent)?
                .caught_up
            {
                break;
            }
        }
        loop {
            if self
                .native
                .project_original_spans(context, self.encoder.as_ref(), 64, parent)?
                .caught_up
            {
                break;
            }
        }
        // Maintenance advances only source rows; never rebuild the frozen graph.
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct Reader {
    pub calls: AtomicUsize,
    pub wires: Mutex<Vec<Vec<OutgoingMessage>>>,
    pub call: ToolCallId,
}

// A registry's reference to an archive key is not the archived fact. Copy only
// a marker at the beginning of an actual delivered original-content line.
fn original_marker_line<'a>(messages: &'a [OutgoingMessage], marker: &str) -> Option<&'a str> {
    messages
        .iter()
        .filter(|message| message.zone == OutgoingZone::Evidence)
        .flat_map(|message| {
            message.originals.iter().filter_map(move |original| {
                let start = usize::try_from(original.text_start).ok()?;
                let end = usize::try_from(original.text_end).ok()?;
                message.text.get(start..end)
            })
        })
        .flat_map(str::lines)
        .find(|line| {
            line.strip_prefix(marker)
                .is_some_and(|suffix| suffix.starts_with(' '))
        })
}

mod reader_tests;

impl Reader {
    pub fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            wires: Mutex::new(vec![]),
            call: ToolCallId::new(),
        }
    }
}
impl OutgoingEncoder for Reader {
    fn id(&self) -> &str {
        "contextdb.reference-request-json.v1"
    }
    fn tokenizer_id(&self) -> &str {
        ReferenceTokenizer::ID
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        parent: &mut QueryBudget,
    ) -> ContextResult<EncodedOutgoing> {
        ReferenceOutgoingEncoder(&ReferenceTokenizer).encode(messages, parent)
    }
}
impl ReaderAdapter for Reader {
    fn profile(&self) -> ModelProfile {
        ModelProfile {
            id: "owned-hybrid-controlled-reader".into(),
            family: "controlled-contract-fixture".into(),
            tokenizer_id: ReferenceTokenizer::ID.into(),
            renderer: RendererKind::Compact,
            max_context_tokens: 64000,
            reserved_output_tokens: 4000,
            preferred_structured_format: StructuredFormat::CompactText,
            supports_tool_results: true,
            supports_native_citations: false,
            supports_prompt_caching: false,
            position_profile: PositionProfile::CriticalFirst,
            instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
            max_schema_complexity: 64,
            external_processing: false,
        }
    }
    fn capabilities(&self) -> ReaderCapabilities {
        ReaderCapabilities {
            history: ReaderHistory::Stateless,
            history_contract: "controlled reader copies actual delivered evidence".into(),
            can_reconcile: false,
        }
    }
    fn tokenizer(&self) -> &dyn TokenCounter {
        &ReferenceTokenizer
    }
    fn capture_manifest(
        &self,
        call: ModelCallId,
        messages: &[OutgoingMessage],
        wire: &EncodedOutgoing,
        parent: &mut QueryBudget,
    ) -> ServiceResult<ModelRequestManifest> {
        ReferenceOutgoingEncoder(&ReferenceTokenizer)
            .capture_manifest(call, messages, wire, parent)
            .map_err(|_| invalid("fixture request manifest"))
    }
    fn complete(&self, _: ModelCallId, wire: &EncodedOutgoing) -> ServiceResult<ReaderOutcome> {
        let messages: Vec<OutgoingMessage> =
            serde_json::from_slice(&wire.wire).expect("actual outgoing wire");
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        let cue = if index == 0 {
            "ARCHIVE_COPPER"
        } else {
            "ARCHIVE_SILVER"
        };
        let text = original_marker_line(&messages, cue)
            .map(str::to_owned)
            .unwrap_or_else(|| "No attributable fixture evidence was delivered.".into());
        self.wires
            .lock()
            .expect("actual reader wires")
            .push(messages);
        let tool_calls = if index == 0 {
            vec![RequestedTool {
                call_id: self.call,
                action: ToolAction {
                    operation: OPERATION.into(),
                    input: vec![],
                    expected_target_version: None,
                },
            }]
        } else {
            vec![]
        };
        Ok(ReaderOutcome::Completed(ReaderReply { text, tool_calls }))
    }
    fn reconcile(&self, _: ModelCallId, _: ContentDigest) -> ServiceResult<ModelReconciliation> {
        Ok(ModelReconciliation::Unknown)
    }
}

#[derive(Debug)]
pub(super) struct Registry {
    pub tool: Arc<CueTool>,
}
impl RuntimeToolRegistry for Registry {
    fn resolve(&self, operation: &str) -> Option<Arc<dyn ExternalTool>> {
        if operation == OPERATION {
            Some(Arc::clone(&self.tool) as Arc<dyn ExternalTool>)
        } else {
            None
        }
    }
}
#[derive(Debug)]
pub(super) struct CueTool {
    pub calls: AtomicUsize,
}
impl ExternalTool for CueTool {
    fn replay_safety(&self) -> ToolReplaySafety {
        ToolReplaySafety::NoAutomaticReplay
    }
    fn execute(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        action: &ToolAction,
    ) -> ServiceResult<ToolObservation> {
        assert_eq!(action.operation, OPERATION);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ToolObservation { outcome: ToolOutcome::Completed,
            bytes: Some(b"The actual registry result requests ARCHIVE_SILVER and identifies the north entrance.".to_vec()),
            media_type: "text/plain".into(), upstream_truncated: false })
    }
    fn reconcile(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        _: ContentDigest,
    ) -> ServiceResult<ToolReconciliation> {
        Ok(ToolReconciliation::Unknown)
    }
}

pub(super) fn settings(encoder: Arc<Encoder>) -> RuntimeSettings {
    // This 64K scripted-reader fixture budgets for the complete <=20-source
    // fusion shortlist. Constant controlled vectors provide no relevance
    // utility; neither backend proves a main-LLM semantic selection benefit.
    RuntimeSettings {
        control: vec![],
        purpose: PackPurpose::Conversation,
        memory_budget: ContextBudgets {
            hard_tokens: 52000,
            soft_tokens: 48000,
            max_blocks: 64,
            max_evidence_blocks: 128,
            max_raw_evidence_tokens: 40000,
            max_history_tokens: 40000,
            max_conflict_tokens: 40000,
            max_serialized_bytes: 2 * 1024 * 1024,
            max_selection_evaluations: 128,
        },
        outgoing_budget: OutgoingBudget {
            max_input_tokens: 59000,
            safety_tokens: 1000,
            max_wire_bytes: 2 * 1024 * 1024,
        },
        rolling: RollingPolicy {
            high_tokens: 3200,
            low_tokens: 2100,
            keep_complete_groups: 1,
            chunk_groups: 2,
            max_prepare_attempts: 3,
        },
        cache_residency: None,
        automatic_recall_filter: RawFilter::default(),
        automatic_bm25: None,
        automatic_hybrid: Some(OwnedHybridSettings {
            query_encoder: encoder,
            limits: OwnedHybridLimits {
                sources: 20,
                ..OwnedHybridLimits::default()
            },
        }),
        router_trace_profile: RouterTraceProfile::RequiredReplayV2,
    }
}

pub(super) struct Fixture {
    pub native: Arc<NativeService>,
    pub context: AuthenticatedRequestContext,
    pub identity: OwnedRunIdentity,
    pub root: tempfile::TempDir,
    pub ledger: Arc<crate::NativeSuppressionLedger>,
    pub keys: Arc<crate::NativeCustodyKeys>,
    pub _ledger: tempfile::TempDir,
    pub _keys: tempfile::TempDir,
    pub encoder: Arc<Encoder>,
    pub copper: ObservationId,
    pub silver: ObservationId,
    pub graph_nodes: u64,
}
pub(super) fn fixture() -> Fixture {
    fixture_with_encoder(Arc::new(Encoder::new()))
}
pub(super) fn fixture_with_encoder(encoder: Arc<Encoder>) -> Fixture {
    let root = tempfile::tempdir().expect("owned hybrid directory");
    let (ld, ledger) = crate::suppression::tests::authority(DATABASE);
    let (kd, keys) = crate::encryption::tests::authority(DATABASE);
    let native = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            DATABASE,
            [29; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("encrypted owner"),
    );
    let seed = crate::capture::tests::request(1, COPPER);
    let mut context = seed.context.clone();
    context.request.purpose = "conversation".into();
    context.capability_grants.extend([
        Capability::Runtime,
        Capability::ReadMemory,
        Capability::ReadConflict,
        Capability::Maintenance,
        Capability::ModelProcessing,
    ]);
    let session = SessionId::new();
    context.session_id = Some(session.to_string());
    let identity = OwnedRunIdentity {
        workspace_id: seed.event.workspace_id,
        session_id: session,
        run_id: AgentRunId::new(),
        actor_id: context.actor_id.clone(),
        agent_id: context.agent_id.clone(),
        subject_id: context.request.subject_id.clone(),
        scopes: seed.event.scope_ids.clone(),
    };
    let mut copper = seed.event.event_id;
    let mut silver = seed.event.event_id;
    for sequence in 1..=24 {
        let body = match sequence {
            1 => COPPER.to_owned(),
            2 => SILVER.to_owned(),
            _ => format!("Weather bulletin {sequence}: cloudy conditions."),
        };
        let mut original = crate::capture::tests::request(sequence, &body);
        original.context = context.clone();
        original.event.session_id = Some(session);
        if sequence == 1 {
            copper = original.event.event_id;
        }
        if sequence == 2 {
            silver = original.event.event_id;
        }
        native
            .append_event(original)
            .expect("accepted archive fixture");
    }
    native
        .initialize_state_catalog(&context, &mut budget())
        .expect("state catalog");
    let hook = Preparation {
        native: Arc::clone(&native),
        encoder: Arc::clone(&encoder),
    };
    hook.before_prepare(&context, &mut encoder.budget())
        .expect("actual source projection");
    let graph = native
        .publish_original_span_graph(&context, &mut encoder.budget())
        .expect("actual native graph publication");
    assert_eq!(graph.manifest.nodes, 24);
    assert_eq!(encoder.source_forwards.load(Ordering::SeqCst), 24);
    // This structural integration test does not measure wall-clock latency.
    // Keep the real 30-second lease rules independent of parallel CI load.
    native
        .set_lease_test_clock(
            native.preparation_wall_time().expect("fixture wall time"),
            0,
        )
        .expect("instance-owned controlled lease time");
    Fixture {
        native,
        context,
        identity,
        root,
        ledger,
        keys,
        _ledger: ld,
        _keys: kd,
        encoder,
        copper,
        silver,
        graph_nodes: graph.manifest.nodes,
    }
}
