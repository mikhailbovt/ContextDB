//! Actual encrypted archives and explicit primary-body removal retain controls.

use std::sync::Arc;

use contextdb_continuity::CapturedMessage;
use contextdb_core::{
    ContentDigest, EventKind, EventPayload, EventProvenance, EventRole, ModelOutputFormat,
    ObservationId, OriginalSourceSpan,
};
use contextdb_service::{
    AuthenticatedRequestContext, BackupResponse, CreateBackupRequest, OwnedRunPort,
    ReadOriginalRequest, RestoreBackupRequest, SaveRunCheckpointRequest, ServiceResult,
};
use contextdb_storage::ReadSnapshot;

use super::*;
use crate::{
    META_MANIFEST_KEY, Manifest, NativeCustodyKeys, NativeSuppressionLedger,
    StoredObservationContent, StoredObservationPolicy, canonical_digest, decode, digest_bytes,
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
    let root = tempfile::tempdir().expect("native fixture root");
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
        .expect("actual encrypted native owner"),
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
    .expect("fresh encrypted restore owner");
    restored
        .restore_backup(RestoreBackupRequest {
            context: context.clone(),
            bytes: backup.bytes.clone(),
            format: backup.format.clone(),
            digest: backup.digest.clone(),
        })
        .expect("actual encrypted archive restore");
    restored
        .verify_native(true)
        .expect("complete restored replay");
    restored
}

fn read(
    service: &NativeService,
    context: &AuthenticatedRequestContext,
    id: ObservationId,
) -> ServiceResult<contextdb_service::CapturedOriginal> {
    service.read_original(ReadOriginalRequest {
        context: context.clone(),
        event_id: id,
        after_receipt: None,
    })
}

#[test]
fn encrypted_archive_restores_exact_trace_and_rejects_feature_page_and_control_stripping() {
    let f = fixture("trace-archive-lifecycle");
    let (accepted, discarded) = capture::accepted_unselected_fixture(&f.service);
    let backup = f
        .service
        .create_backup(CreateBackupRequest {
            context: accepted.context.clone(),
        })
        .expect("actual verified encrypted archive");
    assert_eq!(backup.format, crate::NATIVE_ENCRYPTED_BACKUP_FORMAT);
    let protected = accepted.prepared.router_trace.as_ref().expect("trace");
    assert!(
        !backup
            .bytes
            .windows(protected.canonical_json.len())
            .any(|bytes| bytes == protected.canonical_json.as_bytes()),
        "archive stores protected material through native encryption"
    );
    let restored = restore(&f, "restored", &backup, &accepted.context);
    let original = read(
        &restored,
        &accepted.context,
        accepted.request.event.event_id,
    )
    .expect("complete restored request");
    assert_eq!(original.event, accepted.request.event);
    assert_eq!(original.receipt, accepted.acceptance.receipt);
    let EventPayload::Assembly { manifest } = &original.event.payload else {
        panic!("restored model request");
    };
    let trace = manifest.router_trace.as_ref().expect("restored trace");
    assert_eq!(
        trace.canonical_json().expect("exact pages"),
        protected.canonical_json
    );
    assert_eq!(
        trace.header.origin_closure_digest,
        protected.origin_closure_digest
    );

    for fault in ["feature", "page", "control"] {
        let service = restore(&f, fault, &backup, &accepted.context);
        let mut tx = service.engine.begin_write().expect("archive fixture fault");
        match fault {
            "feature" => {
                let mut manifest: Manifest = decode(
                    &tx.get(&service.keyspaces.meta, META_MANIFEST_KEY)
                        .expect("manifest")
                        .expect("present"),
                    "fixture manifest",
                )
                .expect("native manifest");
                assert!(manifest.features.remove(TRACE_FEATURE));
                manifest.checksum = manifest_checksum(&manifest).expect("valid ordinary checksum");
                tx.put(
                    &service.keyspaces.meta,
                    META_MANIFEST_KEY.to_vec(),
                    encode(&manifest).expect("manifest bytes"),
                )
                .expect("strip declared trace feature");
            }
            "page" => {
                let key = digest_bytes(accepted.request.event.event_id.to_string().as_bytes());
                let mut content: StoredObservationContent = decode(
                    &tx.get(&service.keyspaces.observations_content, key.as_bytes())
                        .expect("original")
                        .expect("present"),
                    "fixture original",
                )
                .expect("original wrapper");
                let page =
                    &mut content.content["payload"]["manifest"]["router_trace"]["pages"][0]["text"];
                *page = serde_json::Value::String(format!(
                    "{} ",
                    page.as_str().expect("protected page")
                ));
                // Repair the ordinary observation wrapper. The page commitment,
                // rather than an unrelated wrapper hash, must reject this fault.
                content.digest = canonical_digest(&(
                    &content.observation_id,
                    &content.metadata,
                    &content.content,
                ))
                .expect("ordinary wrapper digest");
                let mut policy: StoredObservationPolicy = decode(
                    &tx.get(&service.keyspaces.observations_policy, key.as_bytes())
                        .expect("policy")
                        .expect("present"),
                    "fixture policy",
                )
                .expect("policy wrapper");
                policy.content_digest = content.digest.clone();
                tx.put(
                    &service.keyspaces.observations_content,
                    key.as_bytes().to_vec(),
                    encode(&content).expect("rehashed original"),
                )
                .expect("replace page");
                tx.put(
                    &service.keyspaces.observations_policy,
                    key.as_bytes().to_vec(),
                    encode(&policy).expect("rehashed policy"),
                )
                .expect("repair wrapper binding");
            }
            "control" => {
                let key = format!("receipt/{}", accepted.request.event.event_id).into_bytes();
                let mut record: serde_json::Value = decode(
                    &tx.get(&service.keyspaces.continuous, &key)
                        .expect("capture metadata")
                        .expect("present"),
                    "fixture capture control",
                )
                .expect("capture metadata");
                let originals = record["recovery"]["inputs"]["trace_controls"]["originals"]
                    .as_array_mut()
                    .expect("complete origin control");
                let before = originals.len();
                originals.retain(|id| id != &serde_json::json!(discarded));
                assert_eq!(originals.len(), before - 1);
                tx.put(
                    &service.keyspaces.continuous,
                    key,
                    encode(&record).expect("stripped control bytes"),
                )
                .expect("strip discarded origin from retained controls");
                // Repair the ordinary derived outbox commitment so this fault
                // reaches the independent protected origin-closure check.
                let work = service
                    .capture_work_for_receipt(&tx, &accepted.acceptance.receipt)
                    .expect("derived work for altered recovery metadata");
                let outboxes: Vec<_> = tx
                    .scan_prefix(&service.keyspaces.continuous, b"outbox/")
                    .expect("capture outbox rows")
                    .into_iter()
                    .filter(|row| {
                        let existing: crate::capture::CaptureWork =
                            decode(&row.value, "fixture capture outbox").expect("outbox work");
                        existing.event_id == accepted.request.event.event_id
                    })
                    .collect();
                assert_eq!(outboxes.len(), 1);
                tx.put(
                    &service.keyspaces.continuous,
                    outboxes[0].key.clone(),
                    encode(&work).expect("repaired ordinary outbox commitment"),
                )
                .expect("repair ordinary outbox binding");
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("fixture fault Sync");
        if fault == "page" {
            assert_eq!(
                read(&service, &accepted.context, accepted.request.event.event_id)
                    .expect_err("page integrity closes original disclosure")
                    .message,
                "captured envelope invariant failed"
            );
        }
        let error = service
            .verify_native(true)
            .expect_err("protected archive fault");
        assert_eq!(error.code, ErrorCode::IntegrityFailure, "{fault}");
        if fault == "control" {
            assert_eq!(
                error.message,
                "capture recovery router trace origins changed"
            );
        }
        let before = f
            .keys
            .backup_catalog_page(0, None, 256)
            .expect("issuance catalog")
            .revision;
        assert_eq!(
            service
                .create_backup(CreateBackupRequest {
                    context: accepted.context.clone()
                })
                .expect_err("invalid protected history cannot be issued")
                .code,
            ErrorCode::IntegrityFailure,
        );
        assert_eq!(
            f.keys
                .backup_catalog_page(0, None, 256)
                .expect("unchanged issuance")
                .revision,
            before
        );
    }
}

#[test]
fn discarded_origin_removal_reaches_trace_output_and_checkpoint_and_preserves_independent_original()
{
    let f = fixture("trace-removal-lifecycle");
    let (accepted, discarded) = capture::accepted_unselected_fixture(&f.service);
    assert!(
        !accepted
            .prepared
            .assembly
            .read_set
            .originals
            .iter()
            .any(|span| span.event_id == discarded)
    );
    let mut independent = source(
        4,
        "Independent primary original survives protected trace removal.",
    );
    independent.context = accepted.context.clone();
    f.service
        .append_event(independent.clone())
        .expect("independent original");
    let mut output = accepted.request.clone();
    output.idempotency_key = "protected-lifecycle-output".into();
    output.event.event_id = ObservationId::new();
    output.event.producer_sequence += 1;
    output.event.kind = EventKind::ModelResponseCompleted;
    output.event.role = EventRole::Assistant;
    let text = "Derived output retains all inspected origins.";
    output.event.payload = EventPayload::InlineUtf8 {
        text: text.into(),
        digest: ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes()),
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
        .expect("actual derived model output");
    let mut state = accepted.checkpoint.checkpoint.clone();
    state.revision += 1;
    state.next_sequence = output.event.producer_sequence + 2;
    state.pending_model = None;
    state.last_model_output = Some(output.event.event_id);
    let group = state.groups.last_mut().expect("owned interaction");
    group.complete = true;
    let digest = output.event.payload.digest().expect("output digest");
    group.messages.push(CapturedMessage {
        id: BlockId::new("protected-lifecycle-output").expect("message identity"),
        source: OriginalSourceSpan {
            event_id: output.event.event_id,
            payload_digest: digest,
            start: 0,
            end: output
                .event
                .payload
                .original_bytes()
                .expect("output bytes")
                .len() as u64,
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
                idempotency_key: "protected-lifecycle-output-checkpoint".into(),
                event_id: ObservationId::new(),
                expected_revision: accepted.checkpoint.checkpoint.revision,
                checkpoint: state,
            },
            &mut budget(),
        )
        .expect("actual derived owned checkpoint");
    f.service
        .verify_native(true)
        .expect("complete pre-removal lifecycle");
    let roots = BTreeSet::from([discarded]);
    let lineage = f
        .service
        .inspect_original_deletion(&accepted.context, &roots, &mut budget())
        .expect("actual discarded-candidate closure");
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
            "complete trace custody retains descendant {id}"
        );
    }
    assert!(!targets.contains(&independent.event.event_id));
    let snapshot = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before removal");
    let receipt_key = format!("receipt/{}", accepted.request.event.event_id).into_bytes();
    let trace_control = snapshot
        .get(&f.service.keyspaces.continuous, &receipt_key)
        .expect("trace control")
        .expect("retained metadata");
    drop(snapshot);
    let original_archive = f
        .service
        .create_backup(CreateBackupRequest {
            context: accepted.context.clone(),
        })
        .expect("actual pre-removal archive");
    let removal = f
        .service
        .request_original_removal(
            &accepted.context,
            &roots,
            "remove-discarded-trace-origin",
            &mut budget(),
        )
        .expect("retained explicit removal request");
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
        .expect("new raw projection without denied origins");
    let mut reclaimed = false;
    for _ in 0..16 {
        let progress = f
            .service
            .reclaim_raw_generations(&accepted.context, 1024, &mut budget())
            .expect("bounded old raw-copy reclamation");
        if progress.finished && progress.retained_generations == 1 {
            reclaimed = true;
            break;
        }
    }
    assert!(reclaimed, "fixture removed its obsolete raw generations");
    let pruned = f
        .service
        .prune_original_sources(&accepted.context, &removal, &targets, &mut budget())
        .expect("actual affected primary-body pruning");
    assert_eq!(pruned.sources, targets);
    f.service
        .verify_native(true)
        .expect("pruned protected trace remains replayable");
    // The retained removal request keeps the workspace disclosure barrier
    // closed after local pruning. Byte preservation below is administrative;
    // it does not claim completion of the separate removal protocol.
    for id in [
        independent.event.event_id,
        accepted.request.event.event_id,
        output.event.event_id,
        checkpoint.receipt.event_id,
    ] {
        let error = read(&f.service, &accepted.context, id)
            .expect_err("retained removal closes public workspace disclosure");
        assert_eq!(error.code, ErrorCode::IndexTooStale);
        assert_eq!(
            error.message,
            "current retention removal must finish before disclosure"
        );
    }
    let snapshot = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after removal");
    assert_eq!(
        f.service
            .load_captured_original(&snapshot, independent.event.event_id)
            .expect("administrative independent exact original")
            .event,
        independent.event
    );
    for id in &targets {
        assert!(
            snapshot
                .get(
                    &f.service.keyspaces.observations_content,
                    digest_bytes(id.to_string().as_bytes()).as_bytes(),
                )
                .expect("affected primary body row")
                .is_none(),
            "removed primary body remains absent for {id}"
        );
    }
    assert_eq!(
        snapshot
            .get(&f.service.keyspaces.continuous, &receipt_key)
            .expect("retained control"),
        Some(trace_control)
    );
    let retained = f
        .service
        .verified_capture_control(&snapshot, accepted.request.event.event_id, &mut budget())
        .expect("independently verified pruned control");
    assert!(retained.original.is_none());
    assert_eq!(
        retained
            .recovery
            .router_trace
            .as_ref()
            .expect("retained trace header")
            .origin_closure_digest,
        accepted
            .prepared
            .router_trace
            .as_ref()
            .expect("original trace")
            .origin_closure_digest
    );
    drop(snapshot);
    let replacement = f
        .service
        .create_removal_backup(
            &accepted.context,
            &removal,
            &original_archive,
            &mut budget(),
        )
        .expect("actual request-bound encrypted replacement");
    assert_eq!(replacement.replacement.pruning.sources, 1);
    let restored = restore(
        &f,
        "pruned-restored",
        &replacement.backup,
        &accepted.context,
    );
    assert_eq!(
        read(&restored, &accepted.context, independent.event.event_id)
            .expect_err("restore retains the removal disclosure barrier")
            .code,
        ErrorCode::IndexTooStale,
    );
    let snapshot = restored
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("restored pruned metadata");
    assert_eq!(
        restored
            .load_captured_original(&snapshot, independent.event.event_id)
            .expect("administrative independent restored exact original")
            .event,
        independent.event
    );
    for id in &targets {
        assert!(
            snapshot
                .get(
                    &restored.keyspaces.observations_content,
                    digest_bytes(id.to_string().as_bytes()).as_bytes(),
                )
                .expect("restored affected primary body row")
                .is_none(),
            "restored primary body remains absent for {id}"
        );
    }
    let retained = restored
        .verified_capture_control(&snapshot, accepted.request.event.event_id, &mut budget())
        .expect("restored header and complete origin controls");
    assert!(retained.original.is_none());
    assert!(
        retained
            .recovery
            .inputs
            .trace_controls
            .as_ref()
            .expect("retained origin union")
            .originals
            .contains(&discarded)
    );
}
