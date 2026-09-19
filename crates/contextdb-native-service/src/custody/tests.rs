use super::*;
use contextdb_core::{
    AgentRunId, EventRole, ModelCallId, ModelOutputFormat, ModelRequestManifest,
    OriginalSourceSpan, RawFilter, RawTextQuery, ScopeId, SessionId, ToolCallId,
};
use contextdb_recall::{IndexedQuery, IndexedRecallProvider, IndexedSelection};
use contextdb_service::{
    CapturePort, CaptureRequest, CapturedOriginal, CognitiveMemoryService, CreateBackupRequest,
    ReadOriginalRequest, RestoreBackupRequest,
};
use std::time::Duration;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

fn read(service: &NativeService, input: &CaptureRequest) -> ServiceResult<CapturedOriginal> {
    service.read_original(ReadOriginalRequest {
        context: input.context.clone(),
        event_id: input.event.event_id,
        after_receipt: None,
    })
}

fn span(event: &EventEnvelope) -> OriginalSourceSpan {
    let bytes = event
        .payload
        .original_bytes()
        .expect("independent original");
    OriginalSourceSpan {
        event_id: event.event_id,
        payload_digest: event.payload.digest().expect("digest"),
        start: 0,
        end: bytes.len() as u64,
        span_digest: ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()),
    }
}

fn model_pair(
    service: &NativeService,
    sequence: u64,
    parent: &CaptureRequest,
    scope: ScopeId,
) -> CaptureRequest {
    let mut request = crate::capture::tests::request(sequence, "wire");
    request.context = parent.context.clone();
    request
        .context
        .capability_grants
        .insert(Capability::Runtime);
    request.context.request.scopes.insert(scope.to_string());
    request.event.scope_ids = BTreeSet::from([scope]);
    request.event.kind = EventKind::ModelRequested;
    request.event.role = EventRole::Host;
    request.event.run_id = Some(AgentRunId::from_uuid(uuid::Uuid::from_u128(50)).expect("run"));
    request.event.session_id =
        Some(SessionId::from_uuid(uuid::Uuid::from_u128(51)).expect("session"));
    let source = span(&parent.event);
    let call = ModelCallId::new();
    request.event.payload = EventPayload::Assembly {
        manifest: ModelRequestManifest {
            model_call_id: call,
            renderer: "custody-test/v1".into(),
            wire_digest: source.span_digest,
            byte_length: source.end,
            parts: vec![RequestPart::Source { span: source }],
        },
    };
    request.event.provenance = Some(EventProvenance::ModelRequest {
        model_call_id: call,
    });
    service
        .append_event(request.clone())
        .expect("captured request");
    let mut output = crate::capture::tests::request(sequence + 1, "derived secret 7319");
    output.context = request.context.clone();
    output.event.scope_ids = request.event.scope_ids.clone();
    output.event.kind = EventKind::ModelResponseCompleted;
    output.event.role = EventRole::Assistant;
    output.event.run_id = request.event.run_id;
    output.event.session_id = request.event.session_id;
    output.event.parent_event_ids.insert(request.event.event_id);
    output.event.provenance = Some(EventProvenance::ModelOutput {
        model_call_id: call,
        request_event_id: request.event.event_id,
        format: ModelOutputFormat::PlainText,
        tool_calls: vec![],
    });
    service
        .append_event(output.clone())
        .expect("captured response");
    output
}

fn repair(service: &NativeService, context: &AuthenticatedRequestContext) {
    for _ in 0..100 {
        if service
            .maintain_custody(context, 64, &mut budget())
            .expect("bounded repair")
            .caught_up
        {
            return;
        }
    }
    panic!("fixture custody did not catch up");
}

#[test]
fn model_and_tool_derivations_keep_private_input_restrictions_after_reopen_and_revocation() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "custody", [7; 32]).expect("open");
    let original = crate::capture::tests::request(1, "private secret 7319");
    service.append_event(original.clone()).expect("source");
    let scope = ScopeId::new();
    let output = model_pair(&service, 2, &original, scope);
    let mut tool = crate::capture::tests::request(4, "tool arguments 7319");
    tool.context = output.context.clone();
    tool.event.scope_ids = BTreeSet::from([scope]);
    tool.event.kind = EventKind::ToolRequested;
    tool.event.role = EventRole::Host;
    tool.event.parent_event_ids.insert(output.event.event_id);
    tool.event.run_id = output.event.run_id;
    tool.event.provenance = Some(EventProvenance::Tool {
        call_id: ToolCallId::new(),
        request_event_id: tool.event.event_id,
        action_digest: tool.event.payload.digest().expect("action"),
    });
    service.append_event(tool.clone()).expect("tool intent");
    let mut result = crate::capture::tests::request(5, "tool result 7319");
    result.context = tool.context.clone();
    result.event.scope_ids = tool.event.scope_ids.clone();
    result.event.kind = EventKind::ToolCompleted;
    result.event.role = EventRole::Tool;
    result.event.run_id = tool.event.run_id;
    result.event.parent_event_ids.insert(tool.event.event_id);
    result.event.provenance = tool.event.provenance.clone();
    service.append_event(result.clone()).expect("tool result");
    let mut allowed = crate::capture::tests::request(6, "independent 7319");
    allowed.context = output.context.clone();
    allowed.event.scope_ids = BTreeSet::from([scope]);
    let through = service
        .append_event(allowed.clone())
        .expect("independent")
        .workspace_commit;
    let mut revision = crate::capture::tests::request(7, "edited source still contains 7319");
    revision.context = output.context.clone();
    revision.event.scope_ids = BTreeSet::from([scope]);
    revision.event.kind = EventKind::MessageEdited;
    revision.event.supersedes_event_id = Some(original.event.event_id);
    service
        .append_event(revision.clone())
        .expect("attributed revision");
    let mut narrow = output.clone();
    narrow.context.request.scopes = BTreeSet::from([scope.to_string()]);
    assert_eq!(
        read(&service, &narrow)
            .expect_err("output cannot broaden source grants")
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(read(&service, &output).is_ok());
    service
        .project_originals(&output.context, false, 64, &mut budget())
        .expect("index");
    service
        .verify_native(true)
        .expect("materialized provenance closure");
    service
        .revoke_original(
            &original.context,
            original.event.event_id,
            "revoke",
            &mut budget(),
        )
        .expect("revoke");
    assert_eq!(
        read(&service, &result)
            .expect_err("barrier before derived payload")
            .code,
        ErrorCode::IndexTooStale
    );
    let first = service
        .maintain_custody(&output.context, 1, &mut budget())
        .expect("one capture");
    assert_eq!(first.processed, 1);
    assert!(!first.caught_up);
    assert_eq!(
        read(&service, &allowed)
            .expect_err("workspace barrier stays closed")
            .code,
        ErrorCode::IndexTooStale
    );
    service
        .verify_native(true)
        .expect("valid unfinished propagation");
    drop(service);
    let service = NativeService::open(directory.path(), "custody", [7; 32]).expect("reopen");
    assert!(
        read(&service, &result).is_err(),
        "restart cannot clear admission barrier"
    );
    let backup = service
        .create_backup(CreateBackupRequest {
            context: output.context.clone(),
        })
        .expect("backup while propagation is incomplete");
    let restored_directory = tempfile::tempdir().expect("restore directory");
    let restored =
        NativeService::open(restored_directory.path(), "custody", [9; 32]).expect("restore owner");
    restored
        .restore_backup(RestoreBackupRequest {
            context: output.context.clone(),
            bytes: backup.bytes,
            format: backup.format,
            digest: backup.digest,
        })
        .expect("restore retains closed workspace");
    drop(service);
    let service = restored;
    assert_eq!(
        read(&service, &result)
            .expect_err("restore cannot clear admission barrier")
            .code,
        ErrorCode::IndexTooStale
    );
    repair(&service, &output.context);
    for derived in [&output, &tool, &result, &revision] {
        assert_eq!(
            read(&service, derived)
                .expect_err("transitive revocation")
                .code,
            ErrorCode::PermissionDenied
        );
    }
    assert!(
        read(&service, &allowed).is_ok(),
        "independent roots recover after the pass"
    );
    service
        .project_originals(&output.context, true, 64, &mut budget())
        .expect("current index");
    let provider = service.indexed_recall_provider(&output.context);
    let view = provider
        .open_view(Some(through), &mut budget())
        .expect("historical content view");
    let page = provider
        .candidates(
            &view,
            &IndexedQuery {
                filter: RawFilter::default(),
                text: Some(RawTextQuery::AllTerms("7319".into())),
                neighbor_of: None,
                selection: IndexedSelection::TopK { limit: 20 },
            },
            &mut budget(),
        )
        .expect("current restrictions before search");
    assert_eq!(page.hits.len(), 1);
    assert_eq!(page.hits[0].source.event_id, allowed.event.event_id);
    service
        .verify_native(true)
        .expect("revocation and index closure");
}

#[test]
fn conversation_depth_does_not_grow_the_read_time_policy_closure() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "custody", [7; 32]).expect("open");
    let original = crate::capture::tests::request(1, "original secret");
    service.append_event(original.clone()).expect("source");
    let mut previous = original.clone();
    let scope = ScopeId::new();
    // 520 dependency edges, exceeding the request-part bound of 512. Only two
    // distinct policies exist; conversation ancestry is never a query budget.
    for turn in 0..260 {
        previous = model_pair(&service, 2 + turn * 2, &previous, scope);
    }
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    let record = service
        .custody_record(&snapshot, previous.event.event_id)
        .expect("latest custody");
    assert_eq!(record.policies.len(), 2);
    assert_eq!(record.inputs.sources.len(), 1);
    assert_eq!(
        read(&service, &previous)
            .expect("bounded current authorization")
            .event,
        previous.event
    );
    service
        .revoke_original(
            &original.context,
            original.event.event_id,
            "deep-root",
            &mut budget(),
        )
        .expect("deep revocation");
    repair(&service, &previous.context);
    assert_eq!(
        read(&service, &previous)
            .expect_err("last descendant revoked")
            .code,
        ErrorCode::PermissionDenied
    );
    service
        .verify_native(true)
        .expect("long closure reconstruction");
}

#[test]
fn legacy_captures_require_explicit_bounded_migration_and_a_new_index_generation() {
    let directory = tempfile::tempdir().expect("directory");
    let service = NativeService::open(directory.path(), "custody", [7; 32]).expect("open");
    let original = crate::capture::tests::request(1, "private secret");
    service.append_event(original.clone()).expect("source");
    let output = model_pair(&service, 2, &original, ScopeId::new());
    service
        .project_originals(&output.context, false, 64, &mut budget())
        .expect("old index");
    // Synthetic pre-feature format: immutable event/journal bodies are retained.
    let mut tx = service.engine.begin_write().expect("legacy fixture");
    for entry in tx
        .scan_prefix(&service.keyspaces.continuous, b"custody/")
        .expect("custody rows")
    {
        tx.delete(&service.keyspaces.continuous, entry.key)
            .expect("legacy lacks custody");
    }
    for entry in tx
        .scan_prefix(&service.keyspaces.continuous, b"receipt/")
        .expect("receipts")
    {
        let text = String::from_utf8(entry.value).expect("receipt JSON");
        let text = text.replace(",\"custody_version\":1", "");
        tx.put(&service.keyspaces.continuous, entry.key, text.into_bytes())
            .expect("legacy receipt");
    }
    let workspace = digest_bytes(output.context.request.workspace_id.as_bytes());
    let key = crate::raw_index::generation_key(&workspace, 1);
    let bytes = tx
        .get(&service.keyspaces.continuous, &key)
        .expect("index manifest")
        .expect("present");
    let text = String::from_utf8(bytes).expect("index JSON");
    let text = text.replace("\"custody_version\":1,", "");
    tx.put(&service.keyspaces.continuous, key, text.into_bytes())
        .expect("legacy generation");
    let mut manifest: crate::Manifest = decode(
        &tx.get(&service.keyspaces.meta, crate::META_MANIFEST_KEY)
            .expect("manifest")
            .expect("present"),
        "manifest",
    )
    .expect("decode");
    manifest.features.remove(CUSTODY_FEATURE);
    manifest.checksum = crate::manifest_checksum(&manifest).expect("checksum");
    tx.put(
        &service.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("encode"),
    )
    .expect("legacy format");
    tx.commit(Durability::Sync).expect("legacy fixture commit");
    service
        .verify_native(true)
        .expect("legacy remains an administratively valid archive");
    assert_eq!(
        read(&service, &output)
            .expect_err("no implicit unsafe authorization")
            .code,
        ErrorCode::IndexTooStale
    );
    assert!(
        service
            .indexed_recall_provider(&output.context)
            .open_view(None, &mut budget())
            .is_err()
    );
    let independent = crate::capture::tests::request(4, "capture continues during migration");
    service
        .append_event(independent.clone())
        .expect("independent capture remains available");
    assert!(
        !service
            .maintain_custody(&output.context, 1, &mut budget())
            .expect("first page")
            .caught_up
    );
    service
        .verify_native(true)
        .expect("partial migration prefix");
    repair(&service, &output.context);
    assert!(read(&service, &output).is_ok());
    assert!(
        service
            .indexed_recall_provider(&output.context)
            .open_view(None, &mut budget())
            .is_err(),
        "legacy index domains cannot become trusted because custody finished"
    );
    service
        .project_originals(&output.context, true, 64, &mut budget())
        .expect("new generation");
    assert!(
        service
            .indexed_recall_provider(&output.context)
            .open_view(None, &mut budget())
            .is_ok()
    );
    service.verify_native(true).expect("completed migration");
    let mut tx = service.engine.begin_write().expect("corruption fixture");
    let mut record = service
        .custody_record(&tx, output.event.event_id)
        .expect("output custody");
    record.policies.retain(|policy| {
        policy.scopes
            == output
                .event
                .scope_ids
                .iter()
                .map(ToString::to_string)
                .collect()
    });
    service
        .put_custody_record(&mut tx, &record)
        .expect("forged permissive closure");
    tx.commit(Durability::Sync).expect("fault");
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("deep reconstruction detects removed restriction")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn repair_admission_rechecks_concurrent_capture_revocation_and_cancellation() {
    use std::sync::{Arc, Barrier};
    let directory = tempfile::tempdir().expect("directory");
    let service =
        Arc::new(NativeService::open(directory.path(), "custody", [7; 32]).expect("open"));
    let first = crate::capture::tests::request(1, "first source");
    service.append_event(first.clone()).expect("first");
    let second = crate::capture::tests::request(2, "independent second source");
    service.append_event(second.clone()).expect("second");
    service
        .revoke_original(
            &second.context,
            second.event.event_id,
            "revoke-second",
            &mut budget(),
        )
        .expect("initial revocation");
    let paused = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let spawn_repair = || {
        let owner = Arc::clone(&service);
        let context = first.context.clone();
        let paused = Arc::clone(&paused);
        let resume = Arc::clone(&resume);
        std::thread::spawn(move || {
            BEFORE_PUBLISH.with(|hook| {
                hook.replace(Some(Box::new(move || {
                    paused.wait();
                    resume.wait();
                })))
            });
            owner.maintain_custody(&context, 64, &mut budget())
        })
    };
    let worker = spawn_repair();
    paused.wait();
    let third = crate::capture::tests::request(3, "new capture while repair analyzed");
    service
        .append_event(third.clone())
        .expect("capture is not held by repair analysis");
    resume.wait();
    let progress = worker
        .join()
        .expect("repair worker")
        .expect("publish first page");
    assert_eq!(progress.processed, 1);
    assert!(
        !progress.caught_up,
        "concurrent capture must be inside the next admission fence"
    );
    let worker = spawn_repair();
    paused.wait();
    let revocation = service
        .revoke_original(
            &first.context,
            first.event.event_id,
            "revoke-first",
            &mut budget(),
        )
        .expect("older source revoked during analysis");
    resume.wait();
    assert_eq!(
        worker
            .join()
            .expect("repair worker")
            .expect_err("stale complete attempt rejected")
            .code,
        ErrorCode::IndexTooStale
    );
    let workspace = digest_bytes(first.context.request.workspace_id.as_bytes());
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    let state = service
        .custody_state(&snapshot, &workspace)
        .expect("state")
        .expect("exists");
    assert_eq!(
        state.through, 0,
        "earlier revocation rewinds the checked prefix"
    );
    assert_eq!(state.authorization_epoch, revocation.authorization_epoch);
    let head = service.global_head(&snapshot).expect("accepted head");
    let mut tiny = QueryBudget::new(1, 1, Duration::from_secs(5), Default::default());
    assert_eq!(
        service
            .maintain_custody(&first.context, 64, &mut tiny)
            .expect_err("analysis honors byte/work budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    let current = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current view");
    assert_eq!(service.global_head(&current).expect("current head"), head);
    assert_eq!(
        service
            .custody_state(&current, &workspace)
            .expect("current custody"),
        Some(state)
    );
    repair(&service, &first.context);
    assert!(read(&service, &third).is_ok());
    assert_eq!(
        read(&service, &first).expect_err("first revoked").code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        read(&service, &second).expect_err("second revoked").code,
        ErrorCode::PermissionDenied
    );
    service.verify_native(true).expect("concurrent closure");
}
