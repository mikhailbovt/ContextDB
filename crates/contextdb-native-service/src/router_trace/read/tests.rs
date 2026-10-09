//! Encrypted accepted reads and current-rights failures through the actual port.

use std::sync::Arc;
use std::time::Duration;

use contextdb_context::router::{RouterMaterialStatus, RouterMaterialUnavailableReason};
use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::{
    CapturePort, CognitiveMemoryService, CreateBackupRequest, ForgetMode, ForgetRequest,
    PrepareContextRequest, ReadOriginalRequest, RestoreBackupRequest,
};
use contextdb_storage::{
    Durability, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};

use super::*;
use crate::history_key;
use crate::router_trace::tests::{budget, capture, envelope, memory_query, publication, source};
use crate::{NativeCustodyKeys, NativeSuppressionLedger};

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
    let root = tempfile::tempdir().expect("encrypted read fixture root");
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

fn read_request(fixture: &capture::TraceCaptureFixture) -> ReadAcceptedRouterTraceRequest {
    ReadAcceptedRouterTraceRequest {
        context: fixture.context.clone(),
        receipt: fixture.acceptance.receipt.clone(),
    }
}

fn complete(
    service: &NativeService,
    request: ReadAcceptedRouterTraceRequest,
) -> Box<AcceptedRouterTraceRead> {
    match service
        .read_accepted_router_trace(request, &mut budget())
        .expect("actual accepted trace read")
    {
        AcceptedRouterTraceReadResult::Complete(read) => read,
        AcceptedRouterTraceReadResult::Unavailable(reason) => {
            panic!("accepted protected material unavailable: {reason:?}")
        }
    }
}

fn sequence(service: &NativeService) -> contextdb_storage::StorageSequence {
    service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current snapshot")
        .sequence()
}

fn poison_original(service: &NativeService, event_id: contextdb_core::ObservationId) {
    let mut tx = service
        .engine
        .begin_write()
        .expect("body corruption fixture");
    tx.put(
        &service.keyspaces.observations_content,
        digest_bytes(event_id.to_string().as_bytes()).into_bytes(),
        b"poisoned protected original body".to_vec(),
    )
    .expect("fixture body fault");
    tx.commit(Durability::Sync).expect("body fault Sync");
}

#[test]
fn encrypted_accepted_material_cold_read_preserves_all_candidates_without_writes_or_replay_claims()
{
    let f = fixture("accepted-router-cold-read");
    let (accepted, discarded) = capture::accepted_unselected_fixture(&f.service);
    let expected = envelope(&accepted.prepared);
    let before = sequence(&f.service);
    let read = complete(&f.service, read_request(&accepted));
    assert_eq!(
        sequence(&f.service),
        before,
        "embedded read writes no head, index, lease or checkpoint"
    );
    assert_eq!(read.receipt, accepted.acceptance.receipt);
    assert_eq!(
        read.header.trace_digest,
        accepted
            .prepared
            .router_trace
            .as_ref()
            .expect("trace")
            .trace_digest
    );
    assert_eq!(
        serde_json::to_vec(&read.request).expect("request bytes"),
        serde_json::to_vec(&expected.request).expect("frozen request")
    );
    assert_eq!(
        serde_json::to_vec(&read.plan).expect("plan bytes"),
        serde_json::to_vec(&expected.plan).expect("frozen plan")
    );
    assert_eq!(
        serde_json::to_vec(&read.manifest).expect("manifest bytes"),
        serde_json::to_vec(&expected.manifest).expect("frozen manifest")
    );
    assert_eq!(
        serde_json::to_vec(&read.base).expect("base bytes"),
        serde_json::to_vec(&expected.base).expect("frozen base")
    );
    assert_eq!(
        serde_json::to_vec(&read.material).expect("material bytes"),
        serde_json::to_vec(&expected.materials).expect("complete frozen material")
    );
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
    assert_eq!(
        read.verification.support_material,
        RouterMaterialStatus::Verified
    );
    assert_eq!(
        read.verification.unit_semantics,
        RouterMaterialStatus::Verified
    );
    for status in [
        &read.verification.candidate_commitment,
        &read.verification.historical_selection,
    ] {
        assert_eq!(
            status,
            &RouterMaterialStatus::Unavailable(
                RouterMaterialUnavailableReason::MissingPreparedPolicy
            )
        );
    }
    let debug = format!("{read:?}");
    for text in [
        "Current original remains",
        "Independent optional original",
        "amber",
        "cobalt",
    ] {
        assert!(!debug.contains(text), "Debug redacts source bytes");
    }
    let backup = f
        .service
        .create_backup(CreateBackupRequest {
            context: accepted.context.clone(),
        })
        .expect("verified encrypted archive");
    let restored = NativeService::open_encrypted(
        f.root.path().join("cold-restored"),
        f.database,
        [9; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("fresh encrypted owner");
    restored
        .restore_backup(RestoreBackupRequest {
            context: accepted.context.clone(),
            bytes: backup.bytes,
            format: backup.format,
            digest: backup.digest,
        })
        .expect("cold restore does not require a historical physical snapshot");
    let before = sequence(&restored);
    let cold = complete(&restored, read_request(&accepted));
    assert_eq!(sequence(&restored), before);
    assert_eq!(
        serde_json::to_vec(&*cold).expect("cold projection"),
        serde_json::to_vec(&*read).expect("original projection")
    );
}

fn generic_setup(
    service: &NativeService,
    source: &contextdb_service::CaptureRequest,
    plan: &mut PrepareContextRequest,
) {
    for id in ["match", "unrelated-archive-item"] {
        service
            .publish_memory_from_sources(
                publication(&source.context, id),
                &BTreeSet::from([source.event.event_id]),
                &mut budget(),
            )
            .expect("actual registered generic control publication");
    }
    plan.memory_query = Some(memory_query());
}

fn generic_replay_setup(
    service: &NativeService,
    source: &contextdb_service::CaptureRequest,
    plan: &mut PrepareContextRequest,
) {
    generic_setup(service, source, plan);
    capture::replay_profile(service, source, plan);
}

#[test]
fn actual_unselected_generic_retraction_preserves_history_and_current_head_denial_precedes_body() {
    for setup in [generic_setup as capture::FixtureSetup, generic_replay_setup] {
        generic_head_for_setup(setup);
    }
}

fn generic_head_for_setup(setup: capture::FixtureSetup) {
    let f = fixture("accepted-router-generic-read-denial");
    let accepted = capture::accepted_fixture_with_setup(&f.service, setup);
    let frozen = envelope(&accepted.prepared);
    assert_eq!(frozen.retrieval_origins.records.len(), 2);
    assert_eq!(
        frozen
            .materials
            .candidates
            .iter()
            .filter(|candidate| candidate.id.as_str().starts_with("native:"))
            .count(),
        1
    );
    assert_eq!(
        complete(&f.service, read_request(&accepted))
            .lineage
            .record_versions
            .len(),
        2
    );
    let snapshot = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("registered generic head");
    let historical = f
        .service
        .load_head(&snapshot, "unrelated-archive-item")
        .expect("head lookup")
        .expect("actual inspected unselected record");
    drop(snapshot);
    f.service
        .retract_from_sources(
            ForgetRequest {
                context: accepted.context.clone(),
                idempotency_key: "retract-unselected-reader-record".into(),
                target_id: "unrelated-archive-item".into(),
                mode: ForgetMode::Retract,
                reason: "current-reader-use-denied".into(),
            },
            &frozen.retrieval_origins.originals,
            &mut budget(),
        )
        .expect("actual current generic head retraction");
    // Reversible retraction keeps historical access; it is not an ACL update.
    complete(&f.service, read_request(&accepted));
    let snapshot = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual retracted current head");
    let mut denied = f
        .service
        .load_head(&snapshot, "unrelated-archive-item")
        .expect("retracted head lookup")
        .expect("real new source-aware revision");
    assert!(denied.revision > historical.revision);
    drop(snapshot);
    denied.access.retrievable = false;
    let mut tx = f
        .service
        .engine
        .begin_write()
        .expect("poison bodies behind denial");
    // Explicit current-policy fault fixture: no public ACL-change API is
    // inferred from Retract. The owner must consult this current head before
    // either historical generic material or protected trace pages.
    tx.put(
        &f.service.keyspaces.policy_head,
        denied.record_digest.as_bytes().to_vec(),
        crate::encode(&denied).expect("denied current metadata"),
    )
    .expect("fixture current-head ACL denial");
    tx.put(
        &f.service.keyspaces.content_history,
        history_key(&historical.record_digest, historical.revision),
        b"poisoned old generic body".to_vec(),
    )
    .expect("historical body fault");
    tx.put(
        &f.service.keyspaces.observations_content,
        digest_bytes(accepted.request.event.event_id.to_string().as_bytes()).into_bytes(),
        b"poisoned protected original body".to_vec(),
    )
    .expect("trace body fault");
    tx.commit(Durability::Sync)
        .expect("denied bodies fixture Sync");
    let before = sequence(&f.service);
    assert_eq!(
        f.service
            .read_accepted_router_trace(read_request(&accepted), &mut budget())
            .expect_err(
                "current unselected generic denial precedes both historical record and trace bodies"
            )
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(sequence(&f.service), before);
    let root = *frozen
        .retrieval_origins
        .originals
        .first()
        .expect("actual raw source root");
    f.service
        .read_original(ReadOriginalRequest {
            context: accepted.context,
            event_id: root,
            after_receipt: None,
        })
        .expect("raw root remains independently permitted");
}

#[test]
fn accepted_reader_requires_existing_capabilities_exact_receipt_and_shared_budget_before_body() {
    let f = fixture("accepted-router-read-fences");
    let (accepted, discarded) = capture::accepted_unselected_fixture(&f.service);
    assert!(
        envelope(&accepted.prepared)
            .origins
            .originals
            .contains(&discarded)
    );
    let mut off = source(4, "Explicitly trace-disabled captured original.");
    off.context = accepted.context.clone();
    let receipt = f.service.append_event(off).expect("actual Off occurrence");
    assert!(matches!(
        f.service
            .read_accepted_router_trace(
                ReadAcceptedRouterTraceRequest {
                    context: accepted.context.clone(),
                    receipt,
                },
                &mut budget()
            )
            .expect("authorized Off read"),
        AcceptedRouterTraceReadResult::Unavailable(AcceptedRouterTraceUnavailable::LegacyOff)
    ));

    // A corrupt protected body makes the ordering observable: these failures
    // must remain authentication/receipt/budget failures, never payload parsing.
    poison_original(&f.service, accepted.request.event.event_id);
    let before = sequence(&f.service);
    let mut admin_only = read_request(&accepted);
    admin_only.context.capability_grants = BTreeSet::from([Capability::Admin]);
    assert_eq!(
        f.service
            .read_accepted_router_trace(admin_only, &mut budget())
            .expect_err("Admin is no read grant")
            .code,
        ErrorCode::Unauthorized
    );
    let mut wrong_domain = read_request(&accepted);
    wrong_domain.receipt.domain = "unaccepted.synthetic-router".into();
    assert_eq!(
        f.service
            .read_accepted_router_trace(wrong_domain, &mut budget())
            .expect_err("wrong domain")
            .code,
        ErrorCode::FormatIncompatible
    );
    let mut forged = read_request(&accepted);
    forged.receipt.token.push('0');
    assert_eq!(
        f.service
            .read_accepted_router_trace(forged, &mut budget())
            .expect_err("receipt-shaped JSON is not acceptance")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut oversized = read_request(&accepted);
    oversized.receipt.token = "0".repeat(MAX_REQUEST_BYTES + 1);
    assert_eq!(
        f.service
            .read_accepted_router_trace(oversized, &mut budget())
            .expect_err("incoming receipt bounds precede native body reads")
            .code,
        ErrorCode::ResourceExhausted
    );
    let mut limited = QueryBudget::new(
        1_000_000,
        1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    );
    assert_eq!(
        f.service
            .read_accepted_router_trace(read_request(&accepted), &mut limited)
            .expect_err("one enclosing byte allowance")
            .code,
        ErrorCode::BudgetExhausted
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    assert_eq!(
        f.service
            .read_accepted_router_trace(read_request(&accepted), &mut cancelled)
            .expect_err("cancelled before protected body")
            .message,
        "indexed query cancelled"
    );
    assert_eq!(
        f.service
            .read_accepted_router_trace(read_request(&accepted), &mut budget())
            .expect_err("actually corrupt accepted body")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(
        sequence(&f.service),
        before,
        "failed reads publish no state"
    );
    let mut tx = f
        .service
        .engine
        .begin_write()
        .expect("custody truncation fixture");
    let key = format!("custody/source/{}", accepted.request.event.event_id).into_bytes();
    let mut custody: serde_json::Value = decode(
        &tx.get(&f.service.keyspaces.continuous, &key)
            .expect("custody row")
            .expect("protected custody"),
        "fixture custody",
    )
    .expect("stored custody metadata");
    for pointer in [
        "/inputs/trace_controls/originals",
        "/trace_controls/originals",
    ] {
        let originals = custody
            .pointer_mut(pointer)
            .expect("origin control vector")
            .as_array_mut()
            .expect("captured original IDs");
        assert!(!originals.is_empty());
        originals.clear();
    }
    tx.put(
        &f.service.keyspaces.continuous,
        key,
        crate::encode(&custody).expect("stripped custody metadata"),
    )
    .expect("fixture custody fault");
    tx.commit(Durability::Sync).expect("custody fault Sync");
    let before = sequence(&f.service);
    assert_eq!(
        f.service
            .read_accepted_router_trace(read_request(&accepted), &mut budget())
            .expect_err(
                "capture recovery prevents a truncated derived cache from authorizing body reads"
            )
            .message,
        "accepted trace custody inputs differ from recovery"
    );
    assert_eq!(sequence(&f.service), before);
}

#[test]
fn retained_removal_barrier_is_an_error_before_any_pruned_or_complete_read_result() {
    let f = fixture("accepted-router-retention-barrier");
    let (accepted, discarded) = capture::accepted_unselected_fixture(&f.service);
    complete(&f.service, read_request(&accepted));
    f.service
        .request_original_removal(
            &accepted.context,
            &BTreeSet::from([discarded]),
            "read-port-retained-removal",
            &mut budget(),
        )
        .expect("actual retained removal request");
    poison_original(&f.service, accepted.request.event.event_id);
    let before = sequence(&f.service);
    let error = f
        .service
        .read_accepted_router_trace(read_request(&accepted), &mut budget())
        .expect_err("retained workspace removal is not an authorized unavailable disclosure");
    assert_eq!(error.code, ErrorCode::IndexTooStale);
    assert_eq!(
        error.message,
        "current retention removal must finish before disclosure"
    );
    assert_eq!(sequence(&f.service), before);
}

#[test]
fn discarded_current_source_and_actual_purpose_denials_precede_poisoned_protected_body() {
    let f = fixture("accepted-router-read-revocation");
    let (accepted, discarded) = capture::accepted_unselected_fixture(&f.service);
    complete(&f.service, read_request(&accepted));
    let mut training = read_request(&accepted);
    training.context.request.purpose = "personalisation".into();
    assert_eq!(
        f.service
            .read_accepted_router_trace(training, &mut budget())
            .expect_err("ordinary purpose does not grant personalisation")
            .code,
        ErrorCode::PermissionDenied
    );
    f.service
        .revoke_original(
            &accepted.context,
            discarded,
            "revoke-discarded-read-origin",
            &mut budget(),
        )
        .expect("actual current source revocation");
    let mut caught_up = false;
    for _ in 0..16 {
        if f.service
            .maintain_custody(&accepted.context, 64, &mut budget())
            .expect("bounded actual custody propagation")
            .caught_up
        {
            caught_up = true;
            break;
        }
    }
    assert!(caught_up);
    poison_original(&f.service, accepted.request.event.event_id);
    let before = sequence(&f.service);
    let error = f
        .service
        .read_accepted_router_trace(read_request(&accepted), &mut budget())
        .expect_err("discarded origin closes the complete trace before body decode");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(!format!("{error:?}").contains("amber"));
    assert!(!format!("{error:?}").contains("cobalt"));
    assert_eq!(sequence(&f.service), before);
    // An independent original remains under the ordinary read path.
    let snapshot = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current raw source rights");
    let still_permitted = accepted
        .prepared
        .assembly
        .read_set
        .originals
        .iter()
        .find(|span| span.event_id != discarded)
        .expect("actual selected original")
        .event_id;
    f.service
        .authorized_capture_policy(&snapshot, &accepted.context, still_permitted)
        .expect("unrelated selected root remains permitted");
    drop(snapshot);
    f.service
        .read_original(ReadOriginalRequest {
            context: accepted.context,
            event_id: still_permitted,
            after_receipt: None,
        })
        .expect("independent original remains readable");
}
