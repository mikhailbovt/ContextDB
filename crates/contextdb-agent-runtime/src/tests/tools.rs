use std::{io::Write, path::PathBuf};

use contextdb_capture::{
    ExternalTool, ToolAction, ToolObservation, ToolOutcome, ToolReconciliation, ToolReplaySafety,
};

use super::*;

struct FileTarget {
    path: PathBuf,
    action: ToolAction,
    effects: AtomicUsize,
    lose_response: AtomicBool,
}
impl FileTarget {
    fn observation() -> ToolObservation {
        ToolObservation {
            outcome: ToolOutcome::Completed,
            bytes: Some(b"Artifact was created at version 1.".to_vec()),
            media_type: "text/plain".into(),
            upstream_truncated: false,
        }
    }
}
impl ExternalTool for FileTarget {
    fn replay_safety(&self) -> ToolReplaySafety {
        ToolReplaySafety::VersionCompareAndSwap
    }
    fn execute(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        action: &ToolAction,
    ) -> ServiceResult<ToolObservation> {
        if action != &self.action || action.expected_target_version.as_deref() != Some("missing") {
            return Err(invalid("fixture action differs"));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)
            .map_err(|_| invalid("target version no longer matches missing"))?;
        file.write_all(&action.input)
            .map_err(|_| invalid("fixture write failed"))?;
        file.sync_all()
            .map_err(|_| invalid("fixture sync failed"))?;
        self.effects.fetch_add(1, Ordering::SeqCst);
        if self.lose_response.swap(false, Ordering::SeqCst) {
            return Err(ServiceError::new(
                ErrorCode::Unavailable,
                "simulated lost external reply after real file effect",
                false,
            ));
        }
        Ok(Self::observation())
    }
    fn reconcile(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        action_digest: ContentDigest,
    ) -> ServiceResult<ToolReconciliation> {
        let expected = ContentDigest::from_bytes(
            *blake3::hash(&serde_json::to_vec(&self.action).expect("action")).as_bytes(),
        );
        if expected != action_digest {
            return Err(invalid("reconciliation action differs"));
        }
        match std::fs::read(&self.path) {
            Ok(bytes) if bytes == self.action.input => Ok(ToolReconciliation::Observed {
                action_digest,
                observation: Self::observation(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ToolReconciliation::NotApplied {
                    current_target_version: Some("missing".into()),
                })
            }
            _ => Ok(ToolReconciliation::Unknown),
        }
    }
}

fn target(directory: &std::path::Path, lose_response: bool) -> FileTarget {
    FileTarget {
        path: directory.join("external-artifact.txt"),
        action: ToolAction {
            operation: "fixture.create_artifact".into(),
            input: b"Exact durable external effect".to_vec(),
            expected_target_version: Some("missing".into()),
        },
        effects: AtomicUsize::new(0),
        lose_response: AtomicBool::new(lose_response),
    }
}
fn reader(target: &FileTarget) -> ScriptedReader {
    ScriptedReader {
        tool_proposal: Some(RequestedTool {
            call_id: ToolCallId::new(),
            action: target.action.clone(),
        }),
        ..Default::default()
    }
}

#[test]
fn cancellation_releases_unexecuted_proposals_without_inventing_tool_results() {
    let directory = tempfile::tempdir().expect("directory");
    let owner = Arc::new(
        NativeService::open(directory.path().join("native"), "runtime", [7; 32]).expect("open"),
    );
    let (context, identity) = identity();
    owner
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let target = target(directory.path(), false);
    let reader = reader(&target);
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
            "Propose the action before dispatch.".into(),
            now(),
            &mut budget(),
        )
        .expect("input");
    let proposal = runtime
        .step(
            &reader,
            &FixtureFence,
            &FixturePreparation(Arc::clone(&owner)),
            &[],
            now(),
            &mut budget(),
        )
        .expect("proposal")
        .output_receipt;
    assert!(runtime.next_tool(&mut budget()).expect("queued").is_some());
    runtime
        .finish(OwnedRunStatus::Cancelled, now(), &mut budget())
        .expect("cancel before effect");
    assert_eq!(target.effects.load(Ordering::SeqCst), 0);
    assert!(!target.path.exists());
    assert!(runtime.checkpoint().required_sources().next().is_none());
    owner
        .read_original(ReadOriginalRequest {
            context: context.clone(),
            event_id: proposal.event_id,
            after_receipt: Some(proposal),
        })
        .expect("proposal remains auditable");
    drop(runtime);
    let mut resumed = OwnedAgentRuntime::resume(
        owner,
        context,
        identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("terminal checkpoint");
    assert_eq!(resumed.checkpoint().status, OwnedRunStatus::Cancelled);
    assert!(
        resumed
            .accept_user("Cannot resume execution.".into(), now(), &mut budget())
            .is_err()
    );
}

#[test]
fn owned_tool_recovery_after_real_effect_keeps_protocol_and_does_not_execute_again() {
    let directory = tempfile::tempdir().expect("directory");
    let database = directory.path().join("native");
    let owner = Arc::new(NativeService::open(&database, "runtime", [7; 32]).expect("open"));
    let (context, identity) = identity();
    owner
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let target = target(directory.path(), true);
    let reader = reader(&target);
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
            "Create this exact fixture artifact once.".into(),
            now(),
            &mut budget(),
        )
        .expect("input");
    runtime
        .step(
            &reader,
            &FixtureFence,
            &FixturePreparation(Arc::clone(&owner)),
            &[],
            now(),
            &mut budget(),
        )
        .expect("captured model tool proposal");
    assert!(!runtime.checkpoint().groups.last().expect("group").complete);
    assert!(
        runtime
            .step(
                &reader,
                &FixtureFence,
                &KeepUninterpreted,
                &[],
                now(),
                &mut budget()
            )
            .is_err(),
        "pending tool group cannot reach a model"
    );
    assert_eq!(
        runtime
            .execute_next_tool(
                "fixture.create_artifact",
                &target,
                &FixtureFence,
                now(),
                &mut budget()
            )
            .expect("unknown observed outcome"),
        ToolOutcome::Unknown
    );
    assert_eq!(
        std::fs::read(&target.path).expect("actual effect"),
        target.action.input
    );
    drop(runtime);
    drop(owner);
    let owner = Arc::new(NativeService::open(&database, "runtime", [7; 32]).expect("reopen"));
    let mut runtime = OwnedAgentRuntime::resume(
        Arc::clone(&owner),
        context.clone(),
        identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("resume uncertain tool");
    assert_eq!(
        runtime
            .execute_next_tool(
                "fixture.create_artifact",
                &target,
                &FixtureFence,
                now(),
                &mut budget()
            )
            .expect("reconcile"),
        ToolOutcome::Completed
    );
    assert_eq!(target.effects.load(Ordering::SeqCst), 1);
    assert!(
        runtime
            .next_tool(&mut budget())
            .expect("no queued action")
            .is_none()
    );
    let answer = runtime
        .step(
            &reader,
            &FixtureFence,
            &FixturePreparation(Arc::clone(&owner)),
            &[],
            now(),
            &mut budget(),
        )
        .expect("next protocol-valid model call");
    assert!(
        answer
            .prepared
            .messages
            .iter()
            .any(|message| message.role == OutgoingRole::Tool
                && message.text == "Artifact was created at version 1.")
    );
    assert!(runtime.checkpoint().groups.last().expect("group").complete);
    owner
        .verify(VerifyRequest {
            context: context.request,
            deep: true,
        })
        .expect("all captured protocol origins");
}

#[test]
fn lost_tool_output_acknowledgement_retries_only_capture() {
    let directory = tempfile::tempdir().expect("directory");
    let native = Arc::new(
        NativeService::open(directory.path().join("native"), "runtime", [7; 32]).expect("open"),
    );
    let owner = Arc::new(LostOutputAcknowledgement {
        owner: Arc::clone(&native),
        lose_once: AtomicBool::new(true),
        output_kind: EventKind::ToolCompleted,
    });
    let (context, identity) = identity();
    native
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let target = target(directory.path(), false);
    let reader = reader(&target);
    let mut runtime = OwnedAgentRuntime::start(
        owner,
        context,
        StartRun {
            identity,
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    runtime
        .accept_user(
            "Persist this tool result before continuing.".into(),
            now(),
            &mut budget(),
        )
        .expect("input");
    runtime
        .step(
            &reader,
            &FixtureFence,
            &FixturePreparation(native),
            &[],
            now(),
            &mut budget(),
        )
        .expect("tool proposal");
    assert!(
        runtime
            .execute_next_tool(
                "fixture.create_artifact",
                &target,
                &FixtureFence,
                now(),
                &mut budget()
            )
            .is_err()
    );
    assert_eq!(target.effects.load(Ordering::SeqCst), 1);
    assert!(
        runtime
            .execute_next_tool(
                "fixture.create_artifact",
                &target,
                &FixtureFence,
                now(),
                &mut budget()
            )
            .is_err(),
        "pending result capture freezes execution"
    );
    runtime
        .retry_persistence(now(), &mut budget())
        .expect("retry native acknowledgement");
    assert_eq!(target.effects.load(Ordering::SeqCst), 1);
    assert!(
        runtime
            .next_tool(&mut budget())
            .expect("protocol")
            .is_none()
    );
}

#[test]
fn model_requested_expansion_drives_original_into_next_wire_without_manual_memory_search() {
    use contextdb_recall::{IndexedQuery, IndexedSelection};
    let directory = tempfile::tempdir().expect("directory");
    let owner = Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
    let (context, identity) = identity();
    let old_id = ObservationId::new();
    let original =
        "Микроволновка решила изучать этикет: теперь разогревает только светские беседы.";
    owner
        .append_event(CaptureRequest {
            context: context.clone(),
            idempotency_key: "old-incidental-original".into(),
            event: EventEnvelope {
                version: EVENT_ENVELOPE_VERSION,
                event_id: old_id,
                workspace_id: identity.workspace_id,
                scope_ids: identity.scopes.clone(),
                producer_id: StreamId::new(),
                producer_sequence: 1,
                kind: EventKind::MessageCreated,
                recorded_at: now(),
                observed_at: None,
                source_id: SourceId::new(),
                source_version: None,
                adapter_id: "fixture-history".into(),
                role: EventRole::User,
                session_id: Some(identity.session_id),
                run_id: Some(AgentRunId::new()),
                task_id: None,
                parent_event_ids: BTreeSet::new(),
                supersedes_event_id: None,
                payload: EventPayload::InlineUtf8 {
                    text: original.into(),
                    digest: ContentDigest::from_bytes(
                        *blake3::hash(original.as_bytes()).as_bytes(),
                    ),
                },
                coverage: EventCoverage::CompleteObservation,
                upstream_truncated: false,
                gap_reason: None,
                response_stream: None,
                provenance: None,
            },
        })
        .expect("old original");
    owner
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let queries = vec![IndexedQuery {
        filter: RawFilter {
            event_ids: BTreeSet::from([old_id]),
            ..Default::default()
        },
        text: None,
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 4 },
    }];
    let reader = ScriptedReader {
        tool_proposal: Some(RequestedTool {
            call_id: ToolCallId::new(),
            action: ToolAction {
                operation: MEMORY_EXPAND_OPERATION.into(),
                input: serde_json::to_vec(&queries).expect("queries"),
                expected_target_version: None,
            },
        }),
        ..Default::default()
    };
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&owner),
        context.clone(),
        StartRun {
            identity,
            model_profile: reader.profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    runtime
        .accept_user("Need more detail.".into(), now(), &mut budget())
        .expect("input");
    let hook = FixturePreparation(Arc::clone(&owner));
    let adapters = ExecutionAdapters {
        reader: &reader,
        model_fence: &FixtureFence,
        tool_fence: &FixtureFence,
        preparation: &hook,
        tools: &NoExternalTools,
    };
    let answer = runtime
        .drive(&adapters, 2, now(), &mut budget())
        .expect("automatic expansion cycle");
    assert!(answer.reply().tool_calls.is_empty());
    let requests = reader.requests.lock().expect("requests");
    assert_eq!(requests.len(), 2);
    assert!(
        !requests[0]
            .iter()
            .any(|message| message.text.contains(original)),
        "initial lexical route did not magically find the source"
    );
    assert!(
        requests[1]
            .iter()
            .any(|message| message.text.contains(original)
                && message
                    .originals
                    .iter()
                    .any(|span| span.span.event_id == old_id)),
        "requested original reaches the actual next wire"
    );
    drop(requests);
    assert!(matches!(
        runtime
            .drive(&adapters, 2, now(), &mut budget())
            .expect("idempotent answer recovery"),
        InteractionAnswer::Recovered(_)
    ));
    assert_eq!(reader.calls.load(Ordering::SeqCst), 2);
    owner
        .verify(VerifyRequest {
            context: context.request,
            deep: true,
        })
        .expect("expansion and protocol source closure");
}
