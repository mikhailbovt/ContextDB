//! Accepted replay material survives encrypted restore and retains removal controls.

use std::sync::Arc;

use contextdb_continuity::CapturedMessage;
use contextdb_core::{
    ContentDigest, EventKind, EventPayload, EventProvenance, EventRole, ModelOutputFormat,
    ObservationId, OriginalSourceSpan, ROUTER_REPLAY_TRACE_VERSION,
};
use contextdb_service::{
    AcceptedRouterTracePort, AcceptedRouterTraceRead, AcceptedRouterTraceReadResult,
    AuthenticatedRequestContext, BackupResponse, CreateBackupRequest, OwnedRunPort,
    ReadAcceptedRouterTraceRequest, ReadOriginalRequest, RestoreBackupRequest,
    SaveRunCheckpointRequest,
};
use contextdb_storage::ReadSnapshot;

use super::*;
use crate::{
    META_MANIFEST_KEY, Manifest, NativeCustodyKeys, NativeSuppressionLedger, decode, digest_bytes,
    manifest_checksum,
};

struct Fixture {
    service: Arc<NativeService>,
    ledger: Arc<NativeSuppressionLedger>,
    keys: Arc<NativeCustodyKeys>,
    root: tempfile::TempDir,
    _ledger_directory: tempfile::TempDir,
    _key_directory: tempfile::TempDir,
    database: &'static str,
}

fn fixture(database: &'static str) -> Fixture {
    let root = tempfile::tempdir().expect("encrypted lifecycle root");
    let (ledger_directory, ledger) = crate::suppression::tests::authority(database);
    let (key_directory, keys) = crate::encryption::tests::authority(database);
    let service = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            database,
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("actual encrypted owner"),
    );
    Fixture {
        service,
        ledger,
        keys,
        root,
        _ledger_directory: ledger_directory,
        _key_directory: key_directory,
        database,
    }
}

fn restore(
    fixture: &Fixture,
    name: &str,
    backup: &BackupResponse,
    context: &AuthenticatedRequestContext,
) -> NativeService {
    let restored = NativeService::open_encrypted(
        fixture.root.path().join(name),
        fixture.database,
        [9; 32],
        fixture.ledger.clone(),
        fixture.keys.clone(),
    )
    .expect("fresh encrypted owner");
    restored
        .restore_backup(RestoreBackupRequest {
            context: context.clone(),
            bytes: backup.bytes.clone(),
            format: backup.format.clone(),
            digest: backup.digest.clone(),
        })
        .expect("actual encrypted restore");
    restored.verify_native(true).expect("cold accepted history");
    restored
}

fn accepted_read(
    service: &NativeService,
    accepted: &capture::TraceCaptureFixture,
) -> Box<AcceptedRouterTraceRead> {
    match service
        .read_accepted_router_trace(
            ReadAcceptedRouterTraceRequest {
                context: accepted.context.clone(),
                receipt: accepted.acceptance.receipt.clone(),
            },
            &mut budget(),
        )
        .expect("current authorized accepted material")
    {
        AcceptedRouterTraceReadResult::Complete(read) => read,
        AcceptedRouterTraceReadResult::Unavailable(reason) => {
            panic!("accepted replay material unavailable: {reason:?}")
        }
    }
}

fn set_replay_feature(service: &NativeService, present: bool) {
    let mut tx = service
        .engine
        .begin_write()
        .expect("feature fault transaction");
    let mut manifest: Manifest = decode(
        &tx.get(&service.keyspaces.meta, META_MANIFEST_KEY)
            .expect("manifest row")
            .expect("manifest present"),
        "fixture manifest",
    )
    .expect("valid ordinary manifest");
    if present {
        assert!(manifest.features.insert(TRACE_REPLAY_FEATURE.into()));
    } else {
        assert!(manifest.features.remove(TRACE_REPLAY_FEATURE));
    }
    manifest.checksum = manifest_checksum(&manifest).expect("ordinary checksum");
    tx.put(
        &service.keyspaces.meta,
        META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest bytes"),
    )
    .expect("replace only feature declaration");
    tx.commit(Durability::Sync).expect("fixture fault Sync");
}

#[test]
fn encrypted_v2_cold_restore_is_exact_and_marker_requires_an_accepted_v2_witness() {
    let f = fixture("trace-v2-cold");
    let (accepted, discarded) = capture::accepted_unselected_replay_fixture(&f.service);
    let read = accepted_read(&f.service, &accepted);
    assert_eq!(read.header.version, ROUTER_REPLAY_TRACE_VERSION);
    assert!(
        read.material
            .prepared_policy
            .as_ref()
            .and_then(|policy| policy.replay.as_ref())
            .is_some()
    );
    assert!(read.replay_observation.is_some());
    assert!(read.lineage.originals.contains(&discarded));
    assert!(
        !read
            .manifest
            .assembly
            .read_set
            .originals
            .iter()
            .any(|span| span.event_id == discarded)
    );
    f.service
        .verify_native(true)
        .expect("actual accepted replay history");
    let backup = f
        .service
        .create_backup(CreateBackupRequest {
            context: accepted.context.clone(),
        })
        .expect("verified encrypted backup");
    assert_eq!(backup.format, crate::NATIVE_ENCRYPTED_BACKUP_FORMAT);
    let protected = accepted.prepared.router_trace.as_ref().expect("sealed v2");
    assert!(
        !backup
            .bytes
            .windows(protected.canonical_json.len())
            .any(|bytes| bytes == protected.canonical_json.as_bytes())
    );
    let restored = restore(&f, "cold", &backup, &accepted.context);
    let cold = accepted_read(&restored, &accepted);
    assert_eq!(
        serde_json::to_vec(&*cold).expect("cold projection"),
        serde_json::to_vec(&*read).expect("accepted projection")
    );
    let original = restored
        .read_original(ReadOriginalRequest {
            context: accepted.context.clone(),
            event_id: accepted.request.event.event_id,
            after_receipt: Some(accepted.acceptance.receipt.clone()),
        })
        .expect("exact accepted occurrence");
    assert_eq!(original.event, accepted.request.event);
    assert_eq!(original.receipt, accepted.acceptance.receipt);

    // A checksum-valid marker cannot silently upgrade existing v1 history.
    let legacy = fixture("trace-v2-false-marker");
    let v1 = capture::accepted_fixture(&legacy.service);
    assert_eq!(
        accepted_read(&legacy.service, &v1).header.version,
        contextdb_core::ROUTER_TRACE_VERSION
    );
    legacy
        .service
        .verify_native(true)
        .expect("valid v1 baseline");
    set_replay_feature(&legacy.service, true);
    let error = legacy
        .service
        .verify_native(true)
        .expect_err("marker needs a real v2 receipt");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert_eq!(
        error.message,
        "router replay format lacks an accepted v2 capture"
    );
}

#[test]
fn pruned_v2_retains_header_and_all_descendants_and_refuses_feature_or_header_downgrade() {
    let f = fixture("trace-v2-pruning");
    let (accepted, discarded) = capture::accepted_unselected_replay_fixture(&f.service);
    let mut independent = source(4, "Independent original survives replay trace removal.");
    independent.context = accepted.context.clone();
    f.service
        .append_event(independent.clone())
        .expect("independent original");
    let mut output = accepted.request.clone();
    output.idempotency_key = "replay-lifecycle-output".into();
    output.event.event_id = ObservationId::new();
    output.event.producer_sequence += 1;
    output.event.kind = EventKind::ModelResponseCompleted;
    output.event.role = EventRole::Assistant;
    let text = "Actual output inherits the discarded replay origin.";
    let digest = ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes());
    output.event.payload = EventPayload::InlineUtf8 {
        text: text.into(),
        digest,
    };
    output.event.parent_event_ids = BTreeSet::from([accepted.request.event.event_id]);
    output.event.provenance = Some(EventProvenance::ModelOutput {
        model_call_id: accepted
            .checkpoint
            .checkpoint
            .pending_model
            .as_ref()
            .expect("owned attempt")
            .call_id,
        request_event_id: accepted.request.event.event_id,
        format: ModelOutputFormat::PlainText,
        tool_calls: Vec::new(),
    });
    f.service
        .append_event(output.clone())
        .expect("actual derived output");
    let mut state = accepted.checkpoint.checkpoint.clone();
    state.revision += 1;
    state.next_sequence = output.event.producer_sequence + 2;
    state.pending_model = None;
    state.last_model_output = Some(output.event.event_id);
    let group = state.groups.last_mut().expect("interaction");
    group.complete = true;
    group.messages.push(CapturedMessage {
        id: BlockId::new("replay-lifecycle-output").expect("message identity"),
        source: OriginalSourceSpan {
            event_id: output.event.event_id,
            payload_digest: digest,
            start: 0,
            end: text.len() as u64,
            span_digest: digest,
        },
        role: OutgoingRole::Assistant,
        tool_calls: Vec::new(),
        tool_result: None,
    });
    let checkpoint = f
        .service
        .save_run_checkpoint(
            SaveRunCheckpointRequest {
                context: accepted.context.clone(),
                idempotency_key: "replay-lifecycle-output-checkpoint".into(),
                event_id: ObservationId::new(),
                expected_revision: accepted.checkpoint.checkpoint.revision,
                checkpoint: state,
            },
            &mut budget(),
        )
        .expect("actual derived checkpoint");
    f.service
        .verify_native(true)
        .expect("valid complete lifecycle baseline");
    let roots = BTreeSet::from([discarded]);
    let lineage = f
        .service
        .inspect_original_deletion(&accepted.context, &roots, &mut budget())
        .expect("discarded-origin closure");
    let targets: BTreeSet<_> = lineage
        .sources
        .iter()
        .map(|source| source.receipt.event_id)
        .collect();
    for id in [
        discarded,
        accepted.request.event.event_id,
        output.event.event_id,
        checkpoint.receipt.event_id,
    ] {
        assert!(
            targets.contains(&id),
            "replay custody retains descendant {id}"
        );
    }
    assert!(!targets.contains(&independent.event.event_id));
    let original_archive = f
        .service
        .create_backup(CreateBackupRequest {
            context: accepted.context.clone(),
        })
        .expect("verified pre-removal archive");
    let removal = f
        .service
        .request_original_removal(
            &accepted.context,
            &roots,
            "remove-discarded-replay-origin",
            &mut budget(),
        )
        .expect("retained removal request");
    f.service
        .prepare_original_removal_sources(&accepted.context, &removal, &targets, &mut budget())
        .expect("prepare exact affected originals");
    assert!(
        f.service
            .maintain_custody(&accepted.context, 256, &mut budget())
            .expect("propagate current denial")
            .caught_up
    );
    f.service
        .project_originals(&accepted.context, true, 256, &mut budget())
        .expect("new raw projection");
    let mut reclaimed = false;
    for _ in 0..16 {
        let progress = f
            .service
            .reclaim_raw_generations(&accepted.context, 1024, &mut budget())
            .expect("bounded obsolete raw-copy reclamation");
        if progress.finished && progress.retained_generations == 1 {
            reclaimed = true;
            break;
        }
    }
    assert!(
        reclaimed,
        "obsolete raw generations were actually reclaimed"
    );
    assert_eq!(
        f.service
            .prune_original_sources(&accepted.context, &removal, &targets, &mut budget())
            .expect("actual primary pruning")
            .sources,
        targets
    );
    f.service
        .verify_native(true)
        .expect("pruned replay metadata remains valid");
    let replacement = f
        .service
        .create_removal_backup(
            &accepted.context,
            &removal,
            &original_archive,
            &mut budget(),
        )
        .expect("request-bound encrypted replacement");
    let restored = restore(&f, "pruned-cold", &replacement.backup, &accepted.context);
    let snapshot = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("pruned cold snapshot");
    for id in &targets {
        assert!(
            snapshot
                .get(
                    &restored.keyspaces.observations_content,
                    digest_bytes(id.to_string().as_bytes()).as_bytes()
                )
                .expect("primary row")
                .is_none()
        );
    }
    assert_eq!(
        restored
            .load_captured_original(&snapshot, independent.event.event_id)
            .expect("independent administrative original")
            .event,
        independent.event
    );
    let retained = restored
        .verified_capture_control(&snapshot, accepted.request.event.event_id, &mut budget())
        .expect("retained pruned authority");
    assert!(retained.original.is_none());
    let EventPayload::Assembly { manifest } = &accepted.request.event.payload else {
        panic!("assembly");
    };
    assert_eq!(
        retained.recovery.router_trace.as_ref(),
        Some(&manifest.router_trace.as_ref().expect("accepted v2").header)
    );
    assert_eq!(
        retained
            .recovery
            .router_trace
            .as_ref()
            .expect("header2")
            .version,
        ROUTER_REPLAY_TRACE_VERSION
    );
    assert!(
        retained
            .recovery
            .inputs
            .trace_controls
            .as_ref()
            .expect("complete controls")
            .originals
            .contains(&discarded)
    );
    drop(snapshot);
    assert_eq!(
        restored
            .read_accepted_router_trace(
                ReadAcceptedRouterTraceRequest {
                    context: accepted.context.clone(),
                    receipt: accepted.acceptance.receipt.clone(),
                },
                &mut budget()
            )
            .expect_err("removal remains a current disclosure barrier")
            .code,
        ErrorCode::IndexTooStale
    );

    for fault in ["missing-marker", "downgraded-header"] {
        let service = restore(&f, fault, &replacement.backup, &accepted.context);
        if fault == "missing-marker" {
            set_replay_feature(&service, false);
        } else {
            let mut tx = service
                .engine
                .begin_write()
                .expect("header fault transaction");
            let key = format!("receipt/{}", accepted.request.event.event_id).into_bytes();
            let mut control: serde_json::Value = decode(
                &tx.get(&service.keyspaces.continuous, &key)
                    .expect("retained control row")
                    .expect("present"),
                "fixture recovery",
            )
            .expect("retained control");
            assert_eq!(control["recovery"]["router_trace"]["version"], 2);
            control["recovery"]["router_trace"]["version"] = serde_json::json!(1);
            tx.put(
                &service.keyspaces.continuous,
                key,
                encode(&control).expect("downgraded control"),
            )
            .expect("replace retained header only");
            tx.commit(Durability::Sync).expect("fault Sync");
        }
        let error = service
            .verify_native(true)
            .expect_err("pruned v2 cannot downgrade");
        assert_eq!(error.code, ErrorCode::IntegrityFailure, "{fault}");
        if fault == "missing-marker" {
            assert_eq!(
                error.message,
                "capture recovery router replay feature is absent"
            );
        }
        assert_eq!(
            service
                .create_backup(CreateBackupRequest {
                    context: accepted.context.clone()
                })
                .expect_err("invalid pruned history cannot be issued")
                .code,
            ErrorCode::IntegrityFailure
        );
    }
}
