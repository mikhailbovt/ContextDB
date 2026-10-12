//! Actual owned automatic discovery before a model call and again after a tool.

use super::*;
use contextdb_agent_runtime::*;
use contextdb_capture::{
    ExternalTool, ToolAction, ToolObservation, ToolOutcome, ToolReconciliation, ToolReplaySafety,
};
use contextdb_context::{Result as ContextResult, *};
use contextdb_continuity::OwnedRunIdentity;
use contextdb_core::*;
use contextdb_service::{Capability, *};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn now() -> TimestampMicros {
    TimestampMicros(1_000_000)
}

#[derive(Debug)]
struct Reader {
    phase: AtomicUsize,
    wires: Mutex<Vec<Vec<OutgoingMessage>>>,
    call: ToolCallId,
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
        budget: &mut QueryBudget,
    ) -> ContextResult<EncodedOutgoing> {
        ReferenceOutgoingEncoder(&ReferenceTokenizer).encode(messages, budget)
    }
}
impl ReaderAdapter for Reader {
    fn profile(&self) -> ModelProfile {
        ModelProfile {
            id: "native-bm25-wire-fixture".into(),
            family: "deterministic-fixture".into(),
            tokenizer_id: ReferenceTokenizer::ID.into(),
            renderer: RendererKind::Compact,
            max_context_tokens: 32000,
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
            history_contract: "fixture reads only actual complete wire".into(),
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
        budget: &mut QueryBudget,
    ) -> ServiceResult<ModelRequestManifest> {
        ReferenceOutgoingEncoder(&ReferenceTokenizer)
            .capture_manifest(call, messages, wire, budget)
            .map_err(|_| crate::invalid("fixture manifest failed"))
    }
    fn complete(&self, _: ModelCallId, wire: &EncodedOutgoing) -> ServiceResult<ReaderOutcome> {
        let messages: Vec<OutgoingMessage> = serde_json::from_slice(&wire.wire).expect("real wire");
        self.wires.lock().expect("wires").push(messages);
        let phase = self.phase.load(Ordering::SeqCst);
        let reply = if phase == 1 {
            self.phase.store(2, Ordering::SeqCst);
            ReaderReply {
                text: "Observe the registered fixture.".into(),
                tool_calls: vec![RequestedTool {
                    call_id: self.call,
                    action: ToolAction {
                        operation: "fixture.bm25_cues".into(),
                        input: vec![],
                        expected_target_version: None,
                    },
                }],
            }
        } else {
            ReaderReply::text("This fixture exchange is complete.")
        };
        Ok(ReaderOutcome::Completed(reply))
    }
    fn reconcile(&self, _: ModelCallId, _: ContentDigest) -> ServiceResult<ModelReconciliation> {
        Ok(ModelReconciliation::Unknown)
    }
}

#[derive(Debug)]
struct Preparation(Arc<NativeService>);
impl PreparationHook for Preparation {
    fn before_prepare(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for scope in &context.request.scopes {
            let scope = scope.parse().expect("scope");
            let input = self.0.interpretation_inputs(context, scope, budget)?;
            self.0.publish_assertions(
                PublishAssertionsRequest {
                    context: context.clone(),
                    idempotency_key: format!("bm25-fixture/{scope}/{}", input.scope_epoch),
                    scope,
                    expected_scope_epoch: input.scope_epoch,
                    covered_through: input.through,
                    pipeline: PipelineIdentity {
                        name: "synthetic-bm25-no-state-corpus".into(),
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
                budget,
            )?;
        }
        loop {
            if self
                .0
                .project_originals_bm25(context, false, 256, budget)?
                .caught_up
            {
                break;
            }
        }
        Ok(())
    }
}
struct CueTool;
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
        assert_eq!(action.operation, "fixture.bm25_cues");
        Ok(ToolObservation { outcome: ToolOutcome::Completed, bytes: Some(format!("For this task the observed registry names are ZEPPELIN7341 and CHRONOMETER6182. {}", "v ".repeat(5000)).into_bytes()), media_type: "text/plain".into(), upstream_truncated: false })
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
fn settings() -> RuntimeSettings {
    RuntimeSettings {
        control: vec![],
        purpose: PackPurpose::Conversation,
        memory_budget: ContextBudgets {
            hard_tokens: 14000,
            soft_tokens: 12000,
            max_blocks: 64,
            max_evidence_blocks: 128,
            max_raw_evidence_tokens: 10000,
            max_history_tokens: 10000,
            max_conflict_tokens: 10000,
            max_serialized_bytes: 2 * 1024 * 1024,
            max_selection_evaluations: 128,
        },
        outgoing_budget: OutgoingBudget {
            max_input_tokens: 27000,
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
        automatic_bm25: Some(64),
        automatic_hybrid: None,
        router_trace_profile: RouterTraceProfile::Off,
    }
}
fn evidence_sources(messages: &[OutgoingMessage]) -> BTreeSet<ObservationId> {
    messages
        .iter()
        .filter(|message| message.zone == OutgoingZone::Evidence)
        .flat_map(|message| {
            message
                .originals
                .iter()
                .map(|original| original.span.event_id)
        })
        .collect()
}

#[test]
fn cold_owned_bm25_automatically_recalls_complementary_history_then_fresh_tool_cues() {
    let directory = tempfile::tempdir().expect("directory");
    let (_keys_dir, keys) = crate::encryption::tests::authority("automatic-bm25");
    let (_ledger_dir, ledger) = crate::suppression::tests::authority("automatic-bm25");
    let path = directory.path().join("native");
    let owner = Arc::new(
        NativeService::open_encrypted(
            &path,
            "automatic-bm25",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("owner"),
    );
    let fixture = crate::capture::tests::request(1, "unused metadata");
    let mut context = fixture.context;
    context.request.purpose = "conversation".into();
    context.capability_grants.extend([
        Capability::Runtime,
        Capability::ReadMemory,
        Capability::ReadConflict,
        Capability::Maintenance,
    ]);
    let session = SessionId::new();
    context.session_id = Some(session.to_string());
    let identity = OwnedRunIdentity {
        workspace_id: fixture.event.workspace_id,
        session_id: session,
        run_id: AgentRunId::new(),
        actor_id: context.actor_id.clone(),
        agent_id: context.agent_id.clone(),
        subject_id: context.request.subject_id.clone(),
        scopes: fixture.event.scope_ids,
    };
    owner
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let reader = Reader {
        phase: AtomicUsize::new(0),
        wires: Mutex::new(vec![]),
        call: ToolCallId::new(),
    };
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&owner),
        context.clone(),
        StartRun {
            identity: identity.clone(),
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    let fence = OwnerDispatchFence::new(Arc::clone(&owner));
    let hook = Preparation(Arc::clone(&owner));
    let mut original_ids = Vec::new();
    for text in [
        "ASTROLABE4312 stores launch_code red.",
        "HYDROFOIL9821 stores recovery_code blue.",
        "ZEPPELIN7341 stores service_key copper.",
        "CHRONOMETER6182 stores service_key silver.",
    ] {
        runtime
            .accept_user(text.into(), now(), &mut budget())
            .expect("history input");
        original_ids.push(
            runtime
                .checkpoint()
                .groups
                .last()
                .expect("group")
                .messages
                .last()
                .expect("input")
                .source
                .event_id,
        );
        runtime
            .step(&reader, &fence, &hook, &[], now(), &mut budget())
            .expect("closed real exchange");
    }
    for index in 0..8 {
        runtime
            .accept_user(
                format!(
                    "Weather exchange {index}. {}",
                    "Ordinary clouds rain temperature incidental chatter. ".repeat(50)
                ),
                now(),
                &mut budget(),
            )
            .expect("chatter");
        runtime
            .step(&reader, &fence, &hook, &[], now(), &mut budget())
            .expect("actual owned eviction");
    }
    assert!(
        runtime
            .checkpoint()
            .groups
            .iter()
            .flat_map(|group| &group.messages)
            .all(|message| !original_ids.contains(&message.source.event_id))
    );
    drop(runtime);
    drop(fence);
    drop(hook);
    drop(owner);
    let owner = Arc::new(
        NativeService::open_encrypted(&path, "automatic-bm25", [8; 32], ledger, keys)
            .expect("cold owner"),
    );
    let mut runtime = OwnedAgentRuntime::resume(
        Arc::clone(&owner),
        context.clone(),
        identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("cold run");
    let fence = OwnerDispatchFence::new(Arc::clone(&owner));
    let hook = Preparation(Arc::clone(&owner));
    runtime
        .accept_user(
            "Retrieve ASTROLABE4312 and HYDROFOIL9821, then observe the registered fixture.".into(),
            now(),
            &mut budget(),
        )
        .expect("current query");
    reader.phase.store(1, Ordering::SeqCst);
    let before = runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("automatic OR before model");
    let page = before
        .prepared
        .bm25_discovery
        .as_ref()
        .expect("actual BM25 report");
    assert_eq!(page.profile_status, RawBm25ProfileStatus::Supported);
    assert!(
        before.prepared.discovery.is_empty(),
        "opt-in did not execute eight legacy routes"
    );
    assert!(
        page.hits
            .iter()
            .any(|hit| hit.source.event_id == original_ids[0])
    );
    assert!(
        page.hits
            .iter()
            .any(|hit| hit.source.event_id == original_ids[1])
    );
    let first_wire = reader
        .wires
        .lock()
        .expect("wires")
        .last()
        .expect("actual wire")
        .clone();
    let shown = evidence_sources(&first_wire);
    assert!(
        shown.contains(&original_ids[0]) && shown.contains(&original_ids[1]),
        "actual delivered sources={shown:?}; expected={:?}",
        &original_ids[..2]
    );
    assert!(!shown.contains(&original_ids[2]) && !shown.contains(&original_ids[3]));
    assert!(
        first_wire
            .iter()
            .any(|message| message.zone == OutgoingZone::Evidence
                && message.text.contains("launch_code red."))
    );
    assert!(
        first_wire
            .iter()
            .any(|message| message.zone == OutgoingZone::Evidence
                && message.text.contains("recovery_code blue."))
    );
    assert_eq!(
        runtime
            .execute_next_tool("fixture.bm25_cues", &CueTool, &fence, now(), &mut budget())
            .expect("actual source-producing tool"),
        ToolOutcome::Completed
    );
    let after = runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("automatic fresh tool recall");
    assert!(after.prepared.discovery.is_empty());
    let frontier = after
        .prepared
        .bm25_discovery
        .as_ref()
        .expect("after-tool frontier");
    let frontier_sources = frontier
        .hits
        .iter()
        .map(|hit| hit.source.event_id)
        .collect::<BTreeSet<_>>();
    assert!(
        frontier_sources.contains(&original_ids[2]) && frontier_sources.contains(&original_ids[3]),
        "after-tool candidate ceiling={frontier_sources:?}; status={:?}; expected={:?}",
        frontier.profile_status,
        &original_ids[2..]
    );
    let second_wire = reader
        .wires
        .lock()
        .expect("wires")
        .last()
        .expect("actual wire")
        .clone();
    let shown = evidence_sources(&second_wire);
    assert!(
        shown.contains(&original_ids[2]) && shown.contains(&original_ids[3]),
        "after-tool delivered={shown:?}; expected={:?}; terms={:?}; ranks={:?}; selected={:?}; evidence={:?}",
        &original_ids[2..],
        frontier.terms,
        frontier
            .hits
            .iter()
            .map(|hit| (hit.source.event_id, hit.source.role, hit.score))
            .collect::<Vec<_>>(),
        after
            .prepared
            .context_pack
            .sections
            .iter()
            .map(|block| &block.id)
            .collect::<Vec<_>>(),
        after
            .prepared
            .context_pack
            .evidence
            .iter()
            .filter_map(|item| item.original_span.as_ref().map(|span| span.event_id))
            .collect::<Vec<_>>()
    );
    assert!(second_wire.iter().any(|message| message.tool_result.as_deref() == Some(reader.call.to_string().as_str())));
    let mut limited_settings = settings();
    limited_settings
        .automatic_recall_filter
        .include_request_occurrences = true;
    let mut other_identity = identity.clone();
    other_identity.run_id = AgentRunId::new();
    let mut limited = OwnedAgentRuntime::start(
        Arc::clone(&owner),
        context.clone(),
        StartRun {
            identity: other_identity,
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        limited_settings,
        &mut budget(),
    )
    .expect("unsupported-profile run");
    reader.phase.store(0, Ordering::SeqCst);
    limited
        .accept_user("Retrieve ASTROLABE4312.".into(), now(), &mut budget())
        .expect("limited query");
    let limited = limited
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("explicit incomplete profile");
    assert_eq!(
        limited
            .prepared
            .bm25_discovery
            .as_ref()
            .expect("process report")
            .profile_status,
        RawBm25ProfileStatus::UnsupportedFilter
    );
    assert!(limited.prepared.discovery.is_empty());
    assert!(
        reader
            .wires
            .lock()
            .expect("wires")
            .last()
            .expect("real limited wire")
            .iter()
            .any(
                |message| message.id.as_str() == "contextdb.bm25-discovery-status.v1"
                    && message.text.contains("memory-search unknown")
            )
    );
    hook.before_prepare(&context, &mut budget())
        .expect("publish latest fixture observations");
    let settings = settings();
    let mut text_profile = reader.profile();
    text_profile.supports_tool_results = false;
    let text_only = owner
        .prepare_context(
            PrepareContextRequest {
                context: context.clone(),
                pack_id: ContextPackId::new(),
                purpose: settings.purpose,
                known_at: None,
                valid_at: None,
                after_receipt: None,
                raw_queries: vec![],
                memory_query: None,
                bm25_query: Some(query("ZEPPELIN7341")),
                required_facets: vec![],
                memory_budget: settings.memory_budget,
                model_profile: text_profile,
                base: OutgoingBase {
                    control: vec![],
                    working: vec![],
                    hot: vec![],
                    current: vec![],
                },
                outgoing_budget: settings.outgoing_budget,
                explicit_memory_request: false,
                router_trace_profile: RouterTraceProfile::Off,
            },
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &mut budget(),
        )
        .expect("text-only authenticated partial memory");
    assert!(
        text_only.original_page_recall,
        "data locator and visible spans remain owner bound"
    );
    assert!(
        text_only
            .messages
            .iter()
            .all(|message| message.zone != OutgoingZone::ToolDefinitions)
    );
    assert!(
        text_only
            .messages
            .iter()
            .any(|message| message.text.contains("original_page")
                && !message.text.contains("original_page_operation"))
    );
    owner
        .verify_native(true)
        .expect("captured actual protocol, current source and projection bindings");
}
