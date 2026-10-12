//! Evicted originals return through actual automatic discovery and captured wire.

use super::*;

#[derive(Debug)]
struct RecallReader {
    inner: PageReader,
    proposed_handle: Option<OriginalPageHandle>,
}
impl RecallReader {
    fn new(phase: usize, proposed_handle: Option<OriginalPageHandle>) -> Self {
        Self {
            inner: PageReader::new(ToolCallId::new(), ToolCallId::new(), phase),
            proposed_handle,
        }
    }
}
impl OutgoingEncoder for RecallReader {
    fn id(&self) -> &str {
        OutgoingEncoder::id(&self.inner)
    }
    fn tokenizer_id(&self) -> &str {
        OutgoingEncoder::tokenizer_id(&self.inner)
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> ContextResult<EncodedOutgoing> {
        self.inner.encode(messages, budget)
    }
}
impl ReaderAdapter for RecallReader {
    fn profile(&self) -> ModelProfile {
        self.inner.profile()
    }
    fn capabilities(&self) -> ReaderCapabilities {
        self.inner.capabilities()
    }
    fn tokenizer(&self) -> &dyn TokenCounter {
        self.inner.tokenizer()
    }
    fn capture_manifest(
        &self,
        call: ModelCallId,
        messages: &[OutgoingMessage],
        wire: &EncodedOutgoing,
        budget: &mut QueryBudget,
    ) -> ServiceResult<ModelRequestManifest> {
        self.inner.capture_manifest(call, messages, wire, budget)
    }
    fn complete(&self, _: ModelCallId, wire: &EncodedOutgoing) -> ServiceResult<ReaderOutcome> {
        let messages: Vec<OutgoingMessage> =
            serde_json::from_slice(&wire.wire).expect("actual complete wire");
        self.inner
            .requests
            .lock()
            .expect("requests")
            .push(messages.clone());
        let phase = self.inner.calls.load(Ordering::SeqCst);
        if phase != 2 {
            self.inner.calls.fetch_add(1, Ordering::SeqCst);
        }
        let reply = match phase {
            0 => ReaderReply {
                text: "Observe the fixture.".into(),
                tool_calls: vec![RequestedTool {
                    call_id: self.inner.first_call,
                    action: ToolAction {
                        operation: "fixture.large_result".into(),
                        input: vec![],
                        expected_target_version: None,
                    },
                }],
            },
            1 => ReaderReply::text("The observation is archived."),
            2 => ReaderReply::text("The unrelated exchange is complete."),
            3 => {
                let shown: OriginalPageHandle = messages
                    .iter()
                    .filter(|message| message.zone == OutgoingZone::Memory)
                    .find_map(|message| {
                        let block: serde_json::Value = serde_json::from_str(&message.text).ok()?;
                        let handle = block["representation"]["fields"]["original_page"].as_str()?;
                        serde_json::from_str(handle).ok()
                    })
                    .expect("full locator shown with the automatically recalled historical source");
                assert!(
                    messages
                        .iter()
                        .any(|message| message.zone == OutgoingZone::ToolDefinitions
                            && message.text == ORIGINAL_PAGE_DEFINITION)
                );
                assert!(
                    messages
                        .iter()
                        .flat_map(|message| &message.originals)
                        .any(|original| original.span.event_id == shown.event_id
                            && original.span.end - original.span.start <= 4096)
                );
                assert!(wire.input_tokens <= 27000 && wire.wire.len() < 2 * 1024 * 1024);
                let handle = self.proposed_handle.clone().unwrap_or(shown);
                ReaderReply {
                    text: "Read the late range of the disclosed original.".into(),
                    tool_calls: vec![RequestedTool {
                        call_id: self.inner.page_call,
                        action: ToolAction {
                            operation: ORIGINAL_PAGE_OPERATION.into(),
                            expected_target_version: None,
                            input: serde_json::to_vec(&OriginalPageArguments {
                                start: handle.byte_length - 64,
                                handle,
                                max_bytes: 64,
                            })
                            .expect("page selector"),
                        },
                    }],
                }
            }
            _ => {
                let page = messages
                    .iter()
                    .find(|message| {
                        message.tool_result.as_deref()
                            == Some(self.inner.page_call.to_string().as_str())
                    })
                    .expect("real local page result");
                assert!(page.text.contains("late_original_sentinel_7391"));
                assert_eq!(page.originals.len(), 2);
                assert_ne!(
                    page.originals[0].span.event_id,
                    page.originals[1].span.event_id
                );
                ReaderReply::text("The late historical source is present.")
            }
        };
        Ok(ReaderOutcome::Completed(reply))
    }
    fn reconcile(&self, _: ModelCallId, _: ContentDigest) -> ServiceResult<ModelReconciliation> {
        Ok(ModelReconciliation::Unknown)
    }
}

fn start(
    owner: &Arc<NativeService>,
    context: &AuthenticatedRequestContext,
    identity: OwnedRunIdentity,
    reader: &RecallReader,
) -> OwnedAgentRuntime<NativeService> {
    OwnedAgentRuntime::start(
        Arc::clone(owner),
        context.clone(),
        StartRun {
            identity,
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("owned run")
}
fn fixture_tool(
    owner: &Arc<NativeService>,
    context: &AuthenticatedRequestContext,
    identity: OwnedRunIdentity,
    target: &LargeTool,
) -> (
    OwnedAgentRuntime<NativeService>,
    RecallReader,
    OriginalPageHandle,
) {
    let reader = RecallReader::new(0, None);
    let mut runtime = start(owner, context, identity, &reader);
    runtime
        .accept_user(
            "Archive the fixture observation.".into(),
            now(),
            &mut budget(),
        )
        .expect("input");
    let fence = OwnerDispatchFence::new(Arc::clone(owner));
    let hook = FixturePreparation(Arc::clone(owner));
    runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("real proposal");
    assert_eq!(
        runtime
            .execute_next_tool("fixture.large_result", target, &fence, now(), &mut budget())
            .expect("real tool"),
        ToolOutcome::Completed
    );
    let handle = runtime
        .checkpoint()
        .groups
        .last()
        .expect("group")
        .messages
        .iter()
        .find_map(|message| message.tool_page.as_ref().map(|page| page.handle.clone()))
        .expect("original handle");
    runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("close source exchange");
    (runtime, reader, handle)
}

#[test]
fn evicted_tool_locator_is_automatically_disclosed_and_pages_after_cold_reopen() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_key_directory, keys) = crate::encryption::tests::authority("page-recall");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("page-recall");
    let path = directory.path().join("native");
    let owner = Arc::new(
        NativeService::open_encrypted(&path, "page-recall", [7; 32], ledger.clone(), keys.clone())
            .expect("encrypted owner"),
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
    let body = format!(
        "ARCHIVEKITE9143 {} late_original_sentinel_7391",
        "z ".repeat(1024 * 1024)
    );
    assert!(
        ReferenceTokenizer
            .count_tokens(&body)
            .expect("full original count")
            > 32000
    );
    let target = LargeTool {
        body: body.into_bytes(),
        executions: AtomicUsize::new(0),
    };
    let (mut old, reader, original) = fixture_tool(&owner, &context, identity.clone(), &target);
    let fence = OwnerDispatchFence::new(Arc::clone(&owner));
    let hook = FixturePreparation(Arc::clone(&owner));
    for index in 0..8 {
        old.accept_user(
            format!(
                "Unrelated weather exchange {index}. {}",
                "Ordinary clouds rain temperature and incidental chatter. ".repeat(50)
            ),
            now(),
            &mut budget(),
        )
        .expect("chatter");
        old.step(&reader, &fence, &hook, &[], now(), &mut budget())
            .expect("actual rolling eviction");
    }
    assert!(
        !old.checkpoint()
            .groups
            .iter()
            .flat_map(|group| &group.messages)
            .any(|message| message
                .tool_page
                .as_ref()
                .is_some_and(|page| page.handle == original))
    );
    let mut other_identity = identity.clone();
    other_identity.run_id = AgentRunId::new();
    let other_target = LargeTool {
        body: format!("UNDISCLOSEDOTHER728 {}", "v ".repeat(4096)).into_bytes(),
        executions: AtomicUsize::new(0),
    };
    let (_, _, undisclosed) = fixture_tool(&owner, &context, other_identity, &other_target);
    owner
        .read_original_page(
            ReadOriginalPageRequest {
                context: context.clone(),
                handle: undisclosed.clone(),
                start: 0,
                max_bytes: 64,
                external_processing: false,
            },
            &mut budget(),
        )
        .expect("other original is currently accessible");
    drop(old);
    drop(reader);
    drop(fence);
    drop(hook);
    drop(owner);
    let owner = Arc::new(
        NativeService::open_encrypted(&path, "page-recall", [8; 32], ledger.clone(), keys.clone())
            .expect("cold source archive"),
    );
    let restored = OwnedAgentRuntime::resume(
        Arc::clone(&owner),
        context.clone(),
        identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("evicted run reopens");
    assert!(
        !restored
            .checkpoint()
            .groups
            .iter()
            .flat_map(|group| &group.messages)
            .any(|message| message.source.event_id == original.event_id)
    );
    drop(restored);
    let fence = OwnerDispatchFence::new(Arc::clone(&owner));
    let hook = FixturePreparation(Arc::clone(&owner));
    // The main model can guess a true authorized locator, but the host still
    // requires that exact original to be a source in its actual parent request.
    let mut bad_identity = identity.clone();
    bad_identity.run_id = AgentRunId::new();
    let bad_reader = RecallReader::new(3, Some(undisclosed));
    let mut bad = start(&owner, &context, bad_identity, &bad_reader);
    bad.accept_user(
        "Retrieve ARCHIVEKITE9143 from previous history.".into(),
        now(),
        &mut budget(),
    )
    .expect("bad query");
    let bad_turn = bad
        .step(&bad_reader, &fence, &hook, &[], now(), &mut budget())
        .expect("captured guessed proposal");
    assert!(bad_turn.prepared.original_page_recall);
    assert_eq!(
        bad.execute_next_original_page(&fence, now(), &mut budget())
            .expect_err("undisclosed handle is not selectable")
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(
        bad.checkpoint().pending_tool.is_none(),
        "no dispatch intent exists before disclosure admission"
    );
    drop(bad);
    // A new owned run intentionally recalls the evicted original from an older
    // run. The source remains historical, while proposal/result anchors are new.
    let mut current_identity = identity.clone();
    current_identity.run_id = AgentRunId::new();
    let reader = RecallReader::new(3, None);
    let mut runtime = start(&owner, &context, current_identity.clone(), &reader);
    runtime
        .accept_user(
            "Retrieve ARCHIVEKITE9143 from previous history.".into(),
            now(),
            &mut budget(),
        )
        .expect("recall query");
    let turn = runtime
        .step(&reader, &fence, &hook, &[], now(), &mut budget())
        .expect("automatic source discovery without extra routes");
    assert!(turn.prepared.original_page_recall);
    let mut stripped_prepared = turn.prepared.clone();
    stripped_prepared.original_page_recall = false;
    assert!(
        owner
            .register_context_lease(&context, &stripped_prepared, &mut budget())
            .is_err(),
        "a stripped prepared encoding differs from the owner seal"
    );
    let queued = runtime
        .next_tool(&mut budget())
        .expect("page proposal")
        .expect("queued page");
    let selector =
        OriginalPageArguments::from_json(&queued.requested.action.input).expect("selector");
    assert_eq!(selector.handle, original);
    let saved = owner
        .load_run_checkpoint(&context, current_identity.run_id, &mut budget())
        .expect("saved current run")
        .expect("head");
    let snapshot = owner
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let proposal = owner
        .load_captured_original_with_budget(&snapshot, queued.proposal.event_id, &mut budget())
        .expect("proposal metadata");
    let Some(EventProvenance::ModelOutput {
        request_event_id, ..
    }) = proposal.event.provenance
    else {
        panic!("actual model parent")
    };
    let request = owner
        .load_captured_original_with_budget(&snapshot, request_event_id, &mut budget())
        .expect("captured request");
    let EventPayload::Assembly {
        manifest: request_manifest,
    } = &request.event.payload
    else {
        panic!("actual request")
    };
    assert!(request_manifest.original_page_recall);
    assert!(request_manifest.parts.iter().any(|part| matches!(part, RequestPart::Source { span } | RequestPart::JsonStringSource { span, .. }
        if span.event_id == original.event_id && span.end - span.start <= 4096)));
    let mut swapped_manifest = request_manifest.clone();
    drop(snapshot);
    // B did not exist when the A-only request was rendered. Its identical page
    // bytes and different full tail cannot replace A's sealed source identity.
    let mut duplicate_identity = identity.clone();
    duplicate_identity.run_id = AgentRunId::new();
    let mut duplicate_bytes = target.body[..4096].to_vec();
    duplicate_bytes.extend_from_slice(b" a different full original tail ");
    let duplicate_target = LargeTool {
        body: duplicate_bytes,
        executions: AtomicUsize::new(0),
    };
    let (_, _, duplicate) = fixture_tool(&owner, &context, duplicate_identity, &duplicate_target);
    assert_ne!(duplicate.payload_digest, original.payload_digest);
    let mut substitutions = 0;
    for part in &mut swapped_manifest.parts {
        if let RequestPart::Source { span } | RequestPart::JsonStringSource { span, .. } = part
            && span.event_id == original.event_id
        {
            assert!(span.end <= 4096);
            span.event_id = duplicate.event_id;
            span.payload_digest = duplicate.payload_digest;
            substitutions += 1;
        }
    }
    assert!(substitutions > 0);
    let snapshot = owner
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("source-swap snapshot");
    assert_eq!(
        owner
            .assemble_request_with_budget(&snapshot, &context, &swapped_manifest, &mut budget())
            .expect("authorized equal bytes preserve the exact wire"),
        turn.prepared.outgoing.wire
    );
    drop(snapshot);
    let mut swapped_request = CaptureRequest {
        context: context.clone(),
        idempotency_key: "equal-page-source-swap-v1".into(),
        event: request.event.clone(),
    };
    swapped_request.event.event_id = ObservationId::new();
    swapped_request.event.payload = EventPayload::Assembly {
        manifest: swapped_manifest,
    };
    let error = owner
        .capture_prepared_model_request(
            swapped_request,
            &turn.prepared,
            Some(&saved.receipt),
            &mut budget(),
        )
        .expect_err("byte-equivalent B is not the owner-rendered A source");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(
        error.message.contains("captured source identities differ"),
        "source identity refusal: {error}"
    );
    let snapshot = owner
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("retained request snapshot");
    let (_, recovery) = owner
        .capture_recovery_metadata(&snapshot, request_event_id, &mut budget())
        .expect("retained request metadata");
    assert_eq!(
        serde_json::to_value(recovery.expect("request marker")).expect("metadata")["original_page_recall"],
        serde_json::Value::Bool(true)
    );
    let manifest = owner.raw_manifest(&snapshot).expect("feature manifest");
    drop(snapshot);
    let mut tiny = QueryBudget::new(
        2_000_000,
        64 * 1024,
        Duration::from_secs(30),
        Default::default(),
    );
    assert_eq!(
        owner
            .validate_original_page_disclosure(
                &context,
                &saved.receipt,
                &queued.proposal,
                queued.requested.call_id,
                &selector,
                &mut tiny
            )
            .expect_err("disclosure budgets authenticated storage chunks")
            .code,
        ErrorCode::BudgetExhausted
    );
    let mut stripped = manifest.clone();
    stripped.features.remove(crate::owned::PAGE_RECALL_FEATURE);
    stripped.checksum = manifest_checksum(&stripped).expect("checksum");
    let mut tx = owner.engine.begin_write().expect("fault transaction");
    tx.put(
        &owner.keyspaces.meta,
        META_MANIFEST_KEY.to_vec(),
        encode(&stripped).expect("manifest"),
    )
    .expect("strip feature");
    tx.commit(Durability::Sync).expect("fault commit");
    assert!(
        owner
            .validate_original_page_disclosure(
                &context,
                &saved.receipt,
                &queued.proposal,
                queued.requested.call_id,
                &selector,
                &mut budget()
            )
            .is_err()
    );
    let snapshot = owner
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault snapshot");
    assert!(
        owner
            .capture_recovery_metadata(&snapshot, request_event_id, &mut budget())
            .is_err(),
        "retained metadata alone requires the feature"
    );
    drop(snapshot);
    assert!(
        owner.verify_native(true).is_err(),
        "historical disclosure format cannot be silently ignored"
    );
    let mut tx = owner.engine.begin_write().expect("restore transaction");
    tx.put(
        &owner.keyspaces.meta,
        META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest"),
    )
    .expect("restore feature");
    tx.commit(Durability::Sync).expect("restore commit");
    let page_call = reader.inner.page_call;
    drop(runtime);
    drop(reader);
    drop(fence);
    drop(hook);
    drop(owner);
    let owner = Arc::new(
        NativeService::open_encrypted(&path, "page-recall", [9; 32], ledger, keys)
            .expect("cold captured proposal"),
    );
    let mut runtime = OwnedAgentRuntime::resume(
        Arc::clone(&owner),
        context.clone(),
        current_identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("page continuation");
    let mut reader = RecallReader::new(4, None);
    reader.inner.page_call = page_call;
    let fence = OwnerDispatchFence::new(Arc::clone(&owner));
    let hook = FixturePreparation(Arc::clone(&owner));
    let answer = runtime
        .drive(
            &ExecutionAdapters {
                reader: &reader,
                model_fence: &fence,
                tool_fence: &fence,
                preparation: &hook,
                tools: &NoExternalTools,
            },
            1,
            now(),
            &mut budget(),
        )
        .expect("real local page and fresh reader");
    assert!(answer.reply().tool_calls.is_empty());
    assert_eq!(target.executions.load(Ordering::SeqCst), 1);
    assert_eq!(other_target.executions.load(Ordering::SeqCst), 1);
    assert_eq!(duplicate_target.executions.load(Ordering::SeqCst), 1);
    let page = runtime
        .checkpoint()
        .groups
        .last()
        .expect("current group")
        .messages
        .iter()
        .find(|message| message.tool_result.as_deref() == Some(page_call.to_string().as_str()))
        .expect("current page anchor");
    assert_ne!(page.source.event_id, original.event_id);
    assert_eq!(
        page.tool_page
            .as_ref()
            .expect("separate original page")
            .handle,
        original
    );
    owner
        .verify_native(true)
        .expect("native source and cross-run current protocol closure");
    owner
        .revoke_original(
            &context,
            original.event_id,
            "revoke-recalled-original",
            &mut budget(),
        )
        .expect("source revocation");
    assert!(
        owner
            .load_run_checkpoint(&context, current_identity.run_id, &mut budget())
            .is_err(),
        "current anchor cannot revive a revoked historical original"
    );
    assert_eq!(
        owner
            .read_original_page(
                ReadOriginalPageRequest {
                    context,
                    handle: original,
                    start: 0,
                    max_bytes: 64,
                    external_processing: false,
                },
                &mut budget()
            )
            .expect_err("revoked source")
            .code,
        ErrorCode::PermissionDenied
    );
}
