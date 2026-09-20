use std::{
    sync::{Arc, Barrier},
    time::Duration,
};

use contextdb_context::*;
use contextdb_continuity::{CapturedMessage, InteractionGroup, ObligationStatus, ScopedObligation};
use contextdb_core::{OriginalSourceSpan, SessionId};
use contextdb_service::{CapturePort, ReadOriginalRequest};

use super::*;

fn budget() -> QueryBudget {
    QueryBudget::new(
        100_000,
        64 * 1024 * 1024,
        Duration::from_secs(20),
        Default::default(),
    )
}
fn fixture(service: &NativeService) -> SaveRunCheckpointRequest {
    let mut input =
        crate::capture::tests::request(1, "Та самая шутка, которую пересказ уже испортит.");
    let session = SessionId::new();
    let run = AgentRunId::new();
    input.context.capability_grants.insert(Capability::Runtime);
    input.context.session_id = Some(session.to_string());
    input.event.session_id = Some(session);
    input.event.run_id = Some(run);
    service.append_event(input.clone()).expect("original");
    let bytes = input
        .event
        .payload
        .original_bytes()
        .expect("original bytes");
    let source = OriginalSourceSpan {
        event_id: input.event.event_id,
        payload_digest: input.event.payload.digest().expect("digest"),
        start: 0,
        end: bytes.len() as u64,
        span_digest: input.event.payload.digest().expect("digest"),
    };
    SaveRunCheckpointRequest {
        context: input.context.clone(),
        idempotency_key: "checkpoint/1".into(),
        event_id: contextdb_core::ObservationId::new(),
        expected_revision: 0,
        checkpoint: OwnedRunCheckpoint {
            version: 1,
            identity: OwnedRunIdentity {
                workspace_id: input.event.workspace_id,
                session_id: session,
                run_id: run,
                actor_id: input.context.actor_id,
                agent_id: input.context.agent_id,
                subject_id: input.context.request.subject_id,
                scopes: input.event.scope_ids.clone(),
            },
            revision: 1,
            producer_id: input.event.producer_id,
            next_sequence: 3,
            recorded_at: input.event.recorded_at,
            model_profile: ModelProfile {
                id: "reference-reader".into(),
                family: "reference".into(),
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
            },
            groups: vec![InteractionGroup {
                sequence: 1,
                complete: true,
                messages: vec![CapturedMessage {
                    id: BlockId::new("dialogue/1").expect("block"),
                    source: source.clone(),
                    role: OutgoingRole::User,
                    tool_calls: vec![],
                    tool_result: None,
                }],
            }],
            obligations: vec![ScopedObligation {
                id: "remember-context".into(),
                scope: *input.event.scope_ids.first().expect("scope"),
                source,
                status: ObligationStatus::Open,
            }],
            pending_model: None,
            pending_tool: None,
            last_model_output: None,
            status: OwnedRunStatus::Active,
        },
    }
}

#[test]
fn checkpoint_reopens_exact_state_and_concurrent_publication_has_one_winner() {
    let dir = tempfile::tempdir().expect("directory");
    let (_key_directory, keys) = crate::encryption::tests::authority("owned");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("owned");
    let service =
        NativeService::open_encrypted(dir.path(), "owned", [7; 32], ledger.clone(), keys.clone())
            .expect("open");
    let mut request = fixture(&service);
    request.checkpoint.model_profile.id = "checkpoint_sentinel_profile_14873".into();
    request.checkpoint.obligations[0].id = "checkpoint_sentinel_obligation_25874".into();
    let saved = service
        .save_run_checkpoint(request.clone(), &mut budget())
        .expect("checkpoint");
    assert_eq!(
        saved.receipt,
        service
            .save_run_checkpoint(request.clone(), &mut budget())
            .expect("retry")
            .receipt
    );
    service
        .verify_native(true)
        .expect("atomic checkpoint and head");
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let stored: serde_json::Value = decode(
        &snapshot
            .get(
                &service.keyspaces.continuous,
                format!("receipt/{}", saved.receipt.event_id).as_bytes(),
            )
            .expect("capture record")
            .expect("present"),
        "capture record",
    )
    .expect("JSON");
    let metadata = stored["recovery"].to_string();
    assert!(stored["recovery"]["checkpoint"].is_object());
    assert!(!metadata.contains("checkpoint_sentinel"));
    assert!(!metadata.contains("Та самая шутка"));
    drop(snapshot);
    drop(service);
    let service = Arc::new(
        NativeService::open_encrypted(dir.path(), "owned", [8; 32], ledger, keys).expect("reopen"),
    );
    assert_eq!(
        service
            .load_run_checkpoint(
                &request.context,
                request.checkpoint.identity.run_id,
                &mut budget()
            )
            .expect("load")
            .expect("head")
            .checkpoint,
        request.checkpoint
    );
    let barrier = Arc::new(Barrier::new(2));
    let threads = (0..2)
        .map(|index| {
            let service = Arc::clone(&service);
            let barrier = Arc::clone(&barrier);
            let mut next = request.clone();
            next.event_id = contextdb_core::ObservationId::new();
            next.idempotency_key = format!("checkpoint/2/{index}");
            next.expected_revision = 1;
            next.checkpoint.revision = 2;
            next.checkpoint.next_sequence = 4;
            next.checkpoint.model_profile.id = format!("reader-{index}");
            std::thread::spawn(move || {
                barrier.wait();
                service.save_run_checkpoint(next, &mut budget())
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().expect("join"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .find_map(|result| result.as_ref().err())
            .expect("loser")
            .code,
        ErrorCode::IndexTooStale
    );
    service
        .verify_native(true)
        .expect("nonforked checkpoint history");
    // An old acknowledgement may be replayed but must never reset the head.
    service
        .save_run_checkpoint(request.clone(), &mut budget())
        .expect("old exact retry");
    assert_eq!(
        service
            .load_run_checkpoint(
                &request.context,
                request.checkpoint.identity.run_id,
                &mut budget()
            )
            .expect("load")
            .expect("head")
            .checkpoint
            .revision,
        2
    );
}

#[test]
fn checkpoint_rejects_role_forgery_and_detects_total_run_head_loss() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "owned", [7; 32]).expect("open");
    let mut request = fixture(&service);
    request.checkpoint.groups[0].messages[0].role = OutgoingRole::Assistant;
    assert_eq!(
        service
            .save_run_checkpoint(request.clone(), &mut budget())
            .expect_err("forgery")
            .code,
        ErrorCode::InvalidArgument
    );
    request.checkpoint.groups[0].messages[0].role = OutgoingRole::User;
    let saved = service
        .save_run_checkpoint(request.clone(), &mut budget())
        .expect("checkpoint");
    let original = service
        .read_original(ReadOriginalRequest {
            context: request.context.clone(),
            event_id: saved.receipt.event_id,
            after_receipt: None,
        })
        .expect("checkpoint original");
    let mut forged = CaptureRequest {
        context: request.context.clone(),
        event: original.event,
        idempotency_key: "forged-generic-capture".into(),
    };
    forged.event.event_id = contextdb_core::ObservationId::new();
    assert_eq!(
        service
            .append_event(forged)
            .expect_err("generic capture cannot publish a head")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut tx = service.engine.begin_write().expect("write");
    tx.delete(
        &service.keyspaces.continuous,
        head_key(
            &request.context.request.workspace_id,
            request.checkpoint.identity.run_id,
        ),
    )
    .expect("fault injection");
    tx.commit(contextdb_storage::Durability::Sync)
        .expect("fault commit");
    assert!(
        service.verify_native(true).is_err(),
        "missing entire head family must fail deep reconstruction"
    );
}

#[test]
fn recovery_control_rejects_checkpoint_owner_and_state_projection_tampering() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "owned", [7; 32]).expect("open");
    let request = fixture(&service);
    service
        .save_run_checkpoint(request.clone(), &mut budget())
        .expect("checkpoint");
    let key = head_key(
        &request.context.request.workspace_id,
        request.checkpoint.identity.run_id,
    );
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let original: RunHead = decode(
        &snapshot
            .get(&service.keyspaces.continuous, &key)
            .expect("head")
            .expect("present"),
        "head",
    )
    .expect("decode");
    for damage in ["owner", "state", "revision", "status", "producer"] {
        let mut changed = original.clone();
        match damage {
            "owner" => changed.identity.subject_id = "a-different-owner".into(),
            "state" => changed.state_digest = ContentDigest::from_bytes([1; 32]),
            "revision" => changed.revision += 1,
            "status" => changed.status = OwnedRunStatus::Completed,
            _ => changed.producer_id = contextdb_core::StreamId::new(),
        }
        let mut tx = service.engine.begin_write().expect("write");
        tx.put(
            &service.keyspaces.continuous,
            key.clone(),
            encode(&changed).expect("head"),
        )
        .expect("tamper");
        tx.commit(contextdb_storage::Durability::Sync)
            .expect("commit");
        assert_eq!(
            service.verify_native(true).expect_err(damage).code,
            ErrorCode::IntegrityFailure,
            "{damage}"
        );
    }
}

#[test]
fn terminal_obligation_releases_pin_but_revoked_hot_history_cannot_be_checkpointed() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "owned", [7; 32]).expect("open");
    let mut request = fixture(&service);
    service
        .save_run_checkpoint(request.clone(), &mut budget())
        .expect("checkpoint");
    let span = request.checkpoint.groups[0].messages[0].source.clone();
    service
        .revoke_original(
            &request.context,
            span.event_id,
            "revoke-source",
            &mut budget(),
        )
        .expect("revoke original");
    request.expected_revision = 1;
    request.checkpoint.revision = 2;
    request.checkpoint.next_sequence = 4;
    request.event_id = contextdb_core::ObservationId::new();
    request.idempotency_key = "checkpoint/2".into();
    assert_eq!(
        service
            .save_run_checkpoint(request.clone(), &mut budget())
            .expect_err("old body ACL still applies")
            .code,
        ErrorCode::PermissionDenied
    );
    request.checkpoint.groups.clear();
    request
        .checkpoint
        .close_obligation("remember-context", ObligationStatus::Completed)
        .expect("close");
    request.checkpoint.status = OwnedRunStatus::Completed;
    service
        .save_run_checkpoint(request.clone(), &mut budget())
        .expect("terminal source locator is no longer pinned");
    assert_eq!(request.checkpoint.required_sources().count(), 0);
    service
        .verify_native(true)
        .expect("revoked source remains an attributed historical reference");
}

#[test]
fn captured_message_after_checkpoint_is_recoverable_in_producer_order() {
    let dir = tempfile::tempdir().expect("directory");
    let service = NativeService::open(dir.path(), "owned", [7; 32]).expect("open");
    let checkpoint = fixture(&service);
    let saved = service
        .save_run_checkpoint(checkpoint.clone(), &mut budget())
        .expect("checkpoint");
    let mut message =
        crate::capture::tests::request(3, "А эту деталь записали за миг до падения процесса.");
    message.context = checkpoint.context.clone();
    message.event.session_id = Some(checkpoint.checkpoint.identity.session_id);
    message.event.run_id = Some(checkpoint.checkpoint.identity.run_id);
    let receipt = service
        .append_event(message)
        .expect("capture without later checkpoint");
    drop(service);
    let service = NativeService::open(dir.path(), "owned", [7; 32]).expect("reopen");
    let tail = service
        .read_run_tail(&checkpoint.context, &saved.receipt, &mut budget())
        .expect("recover");
    assert!(!tail.more);
    assert_eq!(tail.events.len(), 1);
    assert_eq!(tail.events[0].receipt, receipt);
}
