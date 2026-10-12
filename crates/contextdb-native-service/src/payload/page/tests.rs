//! Native archive, actual reader wire, local page tool and cold continuation.

mod recall;

use super::*;
use contextdb_agent_runtime::*;
use contextdb_capture::{
    CaptureHost, ExternalTool, ToolAction, ToolObservation, ToolOutcome, ToolOutcomeSlot,
    ToolReconciliation, ToolReplaySafety,
};
use contextdb_context::Result as ContextResult;
use contextdb_context::*;
use contextdb_continuity::*;
use contextdb_core::*;
use contextdb_recall::QueryBudget;
use contextdb_service::{Capability, *};
use contextdb_storage::WriteTransaction;
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn budget() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}
fn now() -> TimestampMicros {
    TimestampMicros(1_000_000)
}

#[derive(Debug)]
struct FixturePreparation(Arc<NativeService>);
impl PreparationHook for FixturePreparation {
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
                    idempotency_key: format!("page-fixture/{scope}/{}", input.scope_epoch),
                    scope,
                    expected_scope_epoch: input.scope_epoch,
                    covered_through: input.through,
                    pipeline: PipelineIdentity {
                        name: "synthetic-page-no-state-corpus".into(),
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
        self.0.project_originals(context, false, 256, budget)?;
        Ok(())
    }
}

struct LargeTool {
    body: Vec<u8>,
    executions: AtomicUsize,
}
impl ExternalTool for LargeTool {
    fn replay_safety(&self) -> ToolReplaySafety {
        ToolReplaySafety::NoAutomaticReplay
    }
    fn execute(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        action: &ToolAction,
    ) -> ServiceResult<ToolObservation> {
        assert_eq!(action.operation, "fixture.large_result");
        self.executions.fetch_add(1, Ordering::SeqCst);
        Ok(ToolObservation {
            outcome: ToolOutcome::Completed,
            bytes: Some(self.body.clone()),
            media_type: "text/plain".into(),
            upstream_truncated: false,
        })
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

#[derive(Debug)]
struct PageReader {
    first_call: ToolCallId,
    page_call: ToolCallId,
    calls: AtomicUsize,
    requests: Mutex<Vec<Vec<OutgoingMessage>>>,
}
impl PageReader {
    fn new(first_call: ToolCallId, page_call: ToolCallId, phase: usize) -> Self {
        Self {
            first_call,
            page_call,
            calls: AtomicUsize::new(phase),
            requests: Mutex::new(vec![]),
        }
    }
}
impl OutgoingEncoder for PageReader {
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
impl ReaderAdapter for PageReader {
    fn profile(&self) -> ModelProfile {
        ModelProfile {
            id: "native-page-fixture".into(),
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
            history_contract: "fixture inspects only the supplied complete JSON wire".into(),
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
            .map_err(|_| invalid("fixture manifest failed"))
    }
    fn complete(&self, _: ModelCallId, wire: &EncodedOutgoing) -> ServiceResult<ReaderOutcome> {
        let messages: Vec<OutgoingMessage> =
            serde_json::from_slice(&wire.wire).expect("actual wire");
        self.requests
            .lock()
            .expect("requests")
            .push(messages.clone());
        let phase = self.calls.fetch_add(1, Ordering::SeqCst);
        let reply = if phase == 0 {
            ReaderReply {
                text: "Read the original.".into(),
                tool_calls: vec![RequestedTool {
                    call_id: self.first_call,
                    action: ToolAction {
                        operation: "fixture.large_result".into(),
                        input: vec![],
                        expected_target_version: None,
                    },
                }],
            }
        } else if phase == 1 {
            let result = messages
                .iter()
                .find(|message| {
                    message.tool_result.as_deref() == Some(self.first_call.to_string().as_str())
                })
                .expect("real first call result");
            assert!(result.text.contains("view: partial"));
            assert!(
                result
                    .originals
                    .iter()
                    .all(|original| original.span.end - original.span.start <= 4096)
            );
            let handle: OriginalPageHandle = serde_json::from_str(
                result
                    .text
                    .lines()
                    .find_map(|line| line.strip_prefix("handle="))
                    .expect("usable full locator"),
            )
            .expect("handle");
            assert!(handle.byte_length > 1024 * 1024);
            assert!(
                messages
                    .iter()
                    .any(|message| message.zone == OutgoingZone::ToolDefinitions
                        && message.text.contains(ORIGINAL_PAGE_OPERATION))
            );
            ReaderReply {
                text: "Read the late original range.".into(),
                tool_calls: vec![RequestedTool {
                    call_id: self.page_call,
                    action: ToolAction {
                        operation: ORIGINAL_PAGE_OPERATION.into(),
                        input: serde_json::to_vec(&OriginalPageArguments {
                            start: handle.byte_length - 64,
                            handle,
                            max_bytes: 64,
                        })
                        .expect("selector"),
                        expected_target_version: None,
                    },
                }],
            }
        } else {
            let result = messages
                .iter()
                .find(|message| {
                    message.tool_result.as_deref() == Some(self.page_call.to_string().as_str())
                })
                .expect("real page call result");
            assert!(
                result.text.contains("late_original_sentinel_7391"),
                "late-page tool result: {}",
                result.text
            );
            assert_eq!(
                result.originals.len(),
                2,
                "metadata anchor and original page remain separate sources"
            );
            assert_ne!(
                result.originals[0].span.event_id,
                result.originals[1].span.event_id
            );
            ReaderReply::text("Late original is present in this fresh request.")
        };
        Ok(ReaderOutcome::Completed(reply))
    }
    fn reconcile(&self, _: ModelCallId, _: ContentDigest) -> ServiceResult<ModelReconciliation> {
        Ok(ModelReconciliation::Unknown)
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
        router_trace_profile: RouterTraceProfile::Off,
    }
}

#[test]
fn large_tool_original_pages_reopen_with_real_protocol_and_current_authorization() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_key_directory, keys) = crate::encryption::tests::authority("tool-pages");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("tool-pages");
    let path = directory.path().join("native");
    let owner = Arc::new(
        NativeService::open_encrypted(&path, "tool-pages", [7; 32], ledger.clone(), keys.clone())
            .expect("encrypted owner"),
    );
    let fixture = crate::capture::tests::request(1, "unused fixture metadata");
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
    let body = format!(
        "{}🙂{} late_original_sentinel_7391",
        "a".repeat(4095),
        "z ".repeat(1024 * 1024)
    );
    assert!(
        ReferenceTokenizer
            .count_tokens(&body)
            .expect("exact reference count")
            > 32000,
        "the complete original must exceed the declared reader window"
    );
    let target = LargeTool {
        body: body.as_bytes().to_vec(),
        executions: AtomicUsize::new(0),
    };
    let first_call = ToolCallId::new();
    let page_call = ToolCallId::new();
    let reader = PageReader::new(first_call, page_call, 0);
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
    runtime
        .accept_user(
            "Read the large fixture original and its late range.".into(),
            now(),
            &mut budget(),
        )
        .expect("input");
    let fence = OwnerDispatchFence::new(Arc::clone(&owner));
    let hook = FixturePreparation(Arc::clone(&owner));
    runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("source-bound proposal");
    let snapshot = owner
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        !owner
            .raw_manifest(&snapshot)
            .expect("ordinary manifest")
            .features
            .contains(crate::owned::TOOL_PAGES_FEATURE),
        "ordinary checkpoints do not add the paging format"
    );
    drop(snapshot);
    assert_eq!(
        runtime
            .execute_next_tool(
                "fixture.large_result",
                &target,
                &fence,
                now(),
                &mut budget()
            )
            .expect("complete capture"),
        ToolOutcome::Completed
    );
    assert_eq!(target.executions.load(Ordering::SeqCst), 1);
    let first = runtime
        .checkpoint()
        .groups
        .last()
        .expect("group")
        .messages
        .last()
        .expect("first result")
        .clone();
    let view = first.tool_page.clone().expect("explicit partial view");
    assert_eq!(
        view.preview.end, 4095,
        "page ends before a bisected UTF-8 character"
    );
    assert_ne!(
        view.preview.span_digest, view.handle.payload_digest,
        "prefix is never assigned the complete digest"
    );
    assert_eq!(first.tool_result, Some(first_call.to_string()));
    let mut checkpoint_bytes = QueryBudget::new(
        100_000,
        64 * 1024,
        Duration::from_secs(30),
        Default::default(),
    );
    assert_eq!(
        owner
            .load_run_checkpoint(&context, identity.run_id, &mut checkpoint_bytes)
            .expect_err("reopening a small page still budgets its authenticated storage chunk")
            .code,
        ErrorCode::BudgetExhausted
    );
    let original = owner
        .read_original(ReadOriginalRequest {
            context: context.clone(),
            event_id: view.handle.event_id,
            after_receipt: None,
        })
        .expect("durable original");
    assert_eq!(original.receipt.database_id, view.handle.database_id);
    assert!(matches!(
        original.event.payload,
        EventPayload::Staged { .. }
    ));
    assert_eq!(original.event.coverage, EventCoverage::CompleteObservation);
    assert!(!original.event.upstream_truncated);
    // Verify every archived byte in existing bounded spans; production paging
    // does not materialize this complete plaintext buffer.
    let mut archived = Vec::new();
    for (ordinal, chunk) in body.as_bytes().chunks(1024 * 1024).enumerate() {
        let start = (ordinal * 1024 * 1024) as u64;
        archived.extend(
            owner
                .read_original_span(
                    &context,
                    &OriginalSourceSpan {
                        event_id: view.handle.event_id,
                        payload_digest: view.handle.payload_digest,
                        start,
                        end: start + chunk.len() as u64,
                        span_digest: ContentDigest::from_bytes(*blake3::hash(chunk).as_bytes()),
                    },
                )
                .expect("bounded archive segment"),
        );
    }
    assert_eq!(archived, target.body);
    assert_eq!(
        ContentDigest::from_bytes(*blake3::hash(&archived).as_bytes()),
        view.handle.payload_digest
    );
    let request = ReadOriginalPageRequest {
        context: context.clone(),
        handle: view.handle.clone(),
        start: 4096,
        max_bytes: 64,
        external_processing: false,
    };
    let mut remaining = budget();
    let before = remaining.remaining_bytes();
    let page = owner
        .read_original_page(request.clone(), &mut remaining)
        .expect("UTF-8 start inside character");
    assert_eq!(page.view.preview.start, 4099);
    assert!(remaining.remaining_bytes() < before);
    assert_eq!(
        page.view.preview.span_digest,
        ContentDigest::from_bytes(*blake3::hash(&page.bytes).as_bytes())
    );
    let mut tiny = QueryBudget::new(100_000, 64, Duration::from_secs(30), Default::default());
    assert_eq!(
        owner
            .read_original_page(request.clone(), &mut tiny)
            .expect_err("parent byte budget constrains authenticated chunk IO")
            .code,
        ErrorCode::BudgetExhausted
    );
    let mut remote = request.clone();
    remote.external_processing = true;
    assert_eq!(
        owner
            .read_original_page(remote, &mut budget())
            .expect_err("no model-processing grant")
            .code,
        ErrorCode::Unauthorized
    );
    for kind in ["database", "digest", "length"] {
        let mut changed = request.clone();
        match kind {
            "database" => changed.handle.database_id = "other".into(),
            "digest" => changed.handle.payload_digest = ContentDigest::from_bytes([9; 32]),
            _ => changed.handle.byte_length += 1,
        }
        assert!(
            owner.read_original_page(changed, &mut budget()).is_err(),
            "{kind} does not retarget an original"
        );
    }
    runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("actual first-page wire and page proposal");
    let checkpoint = runtime.checkpoint().clone();
    assert!(
        runtime
            .next_tool(&mut budget())
            .expect("queued page")
            .is_some()
    );
    drop(runtime);
    drop(hook);
    drop(fence);
    drop(owner);
    let owner = Arc::new(
        NativeService::open_encrypted(&path, "tool-pages", [8; 32], ledger, keys)
            .expect("cold native reopen"),
    );
    let mut runtime = OwnedAgentRuntime::resume(
        Arc::clone(&owner),
        context.clone(),
        identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("reopen exact locator and protocol");
    assert_eq!(runtime.checkpoint(), &checkpoint);
    let fresh_reader = PageReader::new(first_call, page_call, 2);
    let fence = OwnerDispatchFence::new(Arc::clone(&owner));
    let hook = FixturePreparation(Arc::clone(&owner));
    let answer = runtime
        .drive(
            &ExecutionAdapters {
                reader: &fresh_reader,
                model_fence: &fence,
                tool_fence: &fence,
                preparation: &hook,
                tools: &NoExternalTools,
            },
            1,
            now(),
            &mut budget(),
        )
        .expect("reserved page tool and actual fresh reader");
    assert!(answer.reply().tool_calls.is_empty());
    assert_eq!(
        target.executions.load(Ordering::SeqCst),
        1,
        "cold continuation did not repeat external execution"
    );
    let page_result = runtime
        .checkpoint()
        .groups
        .last()
        .expect("group")
        .messages
        .iter()
        .find(|message| message.tool_result.as_deref() == Some(page_call.to_string().as_str()))
        .expect("actual page result");
    let late = page_result.tool_page.as_ref().expect("late original view");
    assert_eq!(late.handle, view.handle);
    assert_ne!(page_result.source.event_id, late.preview.event_id);
    assert!(
        runtime
            .checkpoint()
            .required_sources()
            .any(|source| source == &late.preview)
    );
    let closure = owner
        .inspect_original_deletion(
            &context,
            &BTreeSet::from([view.handle.event_id]),
            &mut budget(),
        )
        .expect("original custody descendants");
    assert!(
        closure
            .sources
            .iter()
            .any(|source| source.receipt.event_id == page_result.source.event_id)
    );
    let saved = owner
        .load_run_checkpoint(&context, identity.run_id, &mut budget())
        .expect("current checkpoint")
        .expect("saved head");
    let snapshot = owner
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let manifest = owner.raw_manifest(&snapshot).expect("paging manifest");
    assert!(manifest.features.contains(crate::owned::TOOL_PAGES_FEATURE));
    let (_, recovery) = owner
        .capture_recovery_metadata(&snapshot, saved.receipt.event_id, &mut budget())
        .expect("retained metadata");
    assert_eq!(
        serde_json::to_value(recovery.expect("recovery marker")).expect("metadata")["checkpoint"]["tool_pages"],
        serde_json::Value::Bool(true),
        "the format requirement survives checkpoint-body pruning"
    );
    drop(snapshot);
    let mut orphaned = manifest.clone();
    orphaned.features.remove(crate::owned::OWNED_FEATURE);
    orphaned.checksum = manifest_checksum(&orphaned).expect("checksum");
    assert_eq!(
        crate::validate_manifest(&orphaned, "tool-pages")
            .expect_err("paging requires the owned checkpoint format")
            .code,
        ErrorCode::FormatIncompatible
    );
    let mut stripped = manifest.clone();
    stripped.features.remove(crate::owned::TOOL_PAGES_FEATURE);
    stripped.checksum = manifest_checksum(&stripped).expect("checksum");
    let mut tx = owner.engine.begin_write().expect("fault transaction");
    tx.put(
        &owner.keyspaces.meta,
        META_MANIFEST_KEY.to_vec(),
        encode(&stripped).expect("manifest"),
    )
    .expect("strip required flag");
    tx.commit(Durability::Sync).expect("fault commit");
    assert!(
        owner
            .load_run_checkpoint(&context, identity.run_id, &mut budget())
            .is_err()
    );
    let snapshot = owner
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert!(
        owner
            .capture_recovery_metadata(&snapshot, saved.receipt.event_id, &mut budget())
            .is_err(),
        "retained metadata refuses a missing paging flag without reading the checkpoint body"
    );
    drop(snapshot);
    assert!(
        owner.verify_native(true).is_err(),
        "historical page records require the flag"
    );
    let mut tx = owner.engine.begin_write().expect("restore transaction");
    tx.put(
        &owner.keyspaces.meta,
        META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest"),
    )
    .expect("restore exact manifest");
    tx.commit(Durability::Sync).expect("restore commit");
    owner
        .verify_native(true)
        .expect("native archive and protocol closure");
    owner
        .revoke_original(
            &context,
            view.handle.event_id,
            "revoke-page-original",
            &mut budget(),
        )
        .expect("actual source revocation");
    assert_eq!(
        owner
            .read_original_page(request, &mut budget())
            .expect_err("saved handle cannot revive revoked original")
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(
        owner
            .load_run_checkpoint(&context, identity.run_id, &mut budget())
            .is_err(),
        "cold checkpoint admission also fails under current custody"
    );
}

#[test]
fn malformed_original_and_oversized_selectors_are_refused_without_cropping() {
    let directory = tempfile::tempdir().expect("directory");
    let owner =
        Arc::new(NativeService::open(directory.path(), "malformed-pages", [7; 32]).expect("owner"));
    let request = crate::capture::tests::request(1, "request");
    let context = request.context.clone();
    let target = LargeTool {
        body: vec![b'a', 0xff, b'b'],
        executions: AtomicUsize::new(0),
    };
    let result = CaptureHost::new(Arc::clone(&owner))
        .run_tool(
            request,
            ToolCallId::new(),
            &ToolAction {
                operation: "fixture.large_result".into(),
                input: vec![],
                expected_target_version: None,
            },
            ToolOutcomeSlot {
                event_id: ObservationId::new(),
                producer_sequence: 2,
                recorded_at: now(),
                idempotency_key: "malformed-result".into(),
            },
            &target,
        )
        .expect("exact observed bytes");
    let receipt = result.observed.expect("actual outcome receipt");
    let original = owner
        .read_original(ReadOriginalRequest {
            context: context.clone(),
            event_id: receipt.event_id,
            after_receipt: Some(receipt.clone()),
        })
        .expect("original");
    let page = ReadOriginalPageRequest {
        context,
        handle: OriginalPageHandle {
            database_id: receipt.database_id,
            event_id: receipt.event_id,
            payload_digest: original.event.payload.digest().expect("digest"),
            byte_length: 3,
        },
        start: 0,
        max_bytes: 3,
        external_processing: false,
    };
    assert_eq!(
        owner
            .read_original_page(page.clone(), &mut budget())
            .expect_err("malformed text is not repaired")
            .code,
        ErrorCode::InvalidArgument
    );
    for (start, max_bytes) in [(0, 0), (0, TOOL_RESULT_PAGE_BYTES + 1), (3, 1)] {
        let mut changed = page.clone();
        changed.start = start;
        changed.max_bytes = max_bytes;
        assert_eq!(
            owner
                .read_original_page(changed, &mut budget())
                .expect_err("declared selector bound")
                .code,
            ErrorCode::InvalidArgument
        );
    }
    let selector = OriginalPageArguments {
        handle: page.handle,
        start: 0,
        max_bytes: 3,
    };
    let valid = ToolAction {
        operation: ORIGINAL_PAGE_OPERATION.into(),
        input: serde_json::to_vec(&selector).expect("selector"),
        expected_target_version: None,
    };
    let bytes = serde_json::to_vec(&valid).expect("action");
    let digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
    assert_eq!(
        crate::owned::captured_original_page_arguments(&bytes, digest)
            .expect("fixed page classification"),
        selector
    );
    assert!(
        crate::owned::captured_original_page_arguments(&bytes, ContentDigest::from_bytes([9; 32]))
            .is_err()
    );
    for change in [
        "expansion_alias",
        "external_alias",
        "precondition",
        "model_grant",
        "range_cap",
    ] {
        let mut action = valid.clone();
        match change {
            "expansion_alias" => action.operation = "contextdb.memory.expand".into(),
            "external_alias" => action.operation = "fixture.large_result".into(),
            "precondition" => action.expected_target_version = Some("model-version".into()),
            "model_grant" => {
                let mut value = serde_json::to_value(&selector).expect("selector value");
                value["external_processing"] = serde_json::Value::Bool(true);
                action.input = serde_json::to_vec(&value).expect("forged grant");
            }
            _ => {
                let mut changed = selector.clone();
                changed.max_bytes = TOOL_RESULT_PAGE_BYTES + 1;
                action.input = serde_json::to_vec(&changed).expect("oversized selector");
            }
        }
        let bytes = serde_json::to_vec(&action).expect("changed action");
        let digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
        assert!(
            crate::owned::captured_original_page_arguments(&bytes, digest).is_err(),
            "{change} cannot gain the pure page class"
        );
    }
}
