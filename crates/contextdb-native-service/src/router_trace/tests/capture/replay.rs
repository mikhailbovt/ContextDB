//! Real owner-issued replay v2 captures, cold reads and version admission gates.

use std::time::Duration;

use contextdb_context::router::{
    RouterHistoricalReplayResult, RouterMaterialStatus, RouterMaterialUnavailableReason,
};
use contextdb_recall::QueryCancellation;
use contextdb_service::{
    AcceptedRouterTracePort, AcceptedRouterTraceRead, AcceptedRouterTraceReadResult,
    ReadAcceptedRouterTraceRequest,
};
use contextdb_storage::ReadSnapshot;

use super::*;

fn replay_budget() -> QueryBudget {
    // The parent must admit reconstruction plus the original live selector
    // allowance; replay reserves that allowance without minting a fresh budget.
    QueryBudget::new(
        2_000_000,
        1024 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}

fn read_request(fixture: &TraceCaptureFixture) -> ReadAcceptedRouterTraceRequest {
    ReadAcceptedRouterTraceRequest {
        context: fixture.context.clone(),
        receipt: fixture.acceptance.receipt.clone(),
    }
}

fn complete_read(
    service: &NativeService,
    fixture: &TraceCaptureFixture,
    allowance: &mut QueryBudget,
) -> Box<AcceptedRouterTraceRead> {
    match service
        .read_accepted_router_trace(read_request(fixture), allowance)
        .expect("owner authorizes the accepted complete v2 material")
    {
        AcceptedRouterTraceReadResult::Complete(read) => read,
        AcceptedRouterTraceReadResult::Unavailable(reason) => {
            panic!("actual accepted v2 material is unavailable: {reason:?}")
        }
    }
}

fn sequence(service: &NativeService) -> contextdb_storage::StorageSequence {
    service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("native sequence")
        .sequence()
}

fn verify_replay(
    read: &AcceptedRouterTraceRead,
    fixture: &TraceCaptureFixture,
    allowance: &mut QueryBudget,
) {
    let result = ContextCompiler::replay_router_r0(
        &read.request,
        &read.plan,
        &read.manifest,
        &read.base,
        &read.material,
        read.replay_observation
            .as_ref()
            .expect("separate accepted observation"),
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        allowance,
    )
    .expect("the actual shared R0 selector executes from accepted retained state");
    let RouterHistoricalReplayResult::Complete(replayed) = result else {
        panic!("actual pinned R0 replay should be complete");
    };
    assert_eq!(replayed.score_selection, RouterMaterialStatus::Verified);
    assert_eq!(replayed.material_wire, RouterMaterialStatus::Verified);
    assert_eq!(replayed.token_count, RouterMaterialStatus::Verified);
    assert_eq!(
        replayed.assembly.outgoing.wire,
        fixture.prepared.outgoing.wire
    );
    assert_eq!(
        replayed.assembly.context.canonical_protobuf,
        fixture.prepared.canonical_bytes
    );
    assert_eq!(replayed.assembly.manifest, fixture.prepared.assembly);
    assert_eq!(
        serde_json::to_vec(&replayed.assembly.context.pack).expect("replayed pack"),
        serde_json::to_vec(&fixture.prepared.context_pack).expect("accepted pack"),
    );
}

#[test]
fn accepted_v2_cold_read_executes_real_r0_separately_with_discarded_origins_and_shared_allowance() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_keys_directory, keys) = crate::encryption::tests::authority("native-replay-cold");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("native-replay-cold");
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "native-replay-cold",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("encrypted native owner"),
    );
    let (fixture, discarded) = accepted_unselected_replay_fixture(&service);
    let trace = fixture
        .prepared
        .router_trace
        .as_ref()
        .expect("explicit v2 preparation");
    assert_eq!(trace.version, contextdb_core::ROUTER_REPLAY_TRACE_VERSION);
    assert_eq!(envelope(&fixture.prepared).format, REPLAY_FORMAT);
    let before = sequence(&service);
    let mut allowance = replay_budget();
    let read = complete_read(&service, &fixture, &mut allowance);
    assert_eq!(
        read.header.version,
        contextdb_core::ROUTER_REPLAY_TRACE_VERSION
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
        read.verification.candidate_commitment,
        RouterMaterialStatus::Verified
    );
    assert_eq!(
        read.verification.historical_selection,
        RouterMaterialStatus::Unavailable(
            RouterMaterialUnavailableReason::HistoricalReplayNotExecuted
        )
    );
    verify_replay(&read, &fixture, &mut allowance);
    assert_eq!(
        sequence(&service),
        before,
        "read and detached replay write no native state"
    );
    let serialized = serde_json::to_vec(&read).expect("protected test-only projection roundtrip");
    let detached: AcceptedRouterTraceRead =
        serde_json::from_slice(&serialized).expect("cold typed projection");
    verify_replay(&detached, &fixture, &mut replay_budget());
    service
        .verify_native(true)
        .expect("actual accepted v2 journal and custody");
    drop(service);
    let reopened = NativeService::open_encrypted(
        directory.path(),
        "native-replay-cold",
        [7; 32],
        ledger,
        keys,
    )
    .expect("cold encrypted owner");
    let before = sequence(&reopened);
    let mut allowance = replay_budget();
    let cold = complete_read(&reopened, &fixture, &mut allowance);
    assert_eq!(serde_json::to_vec(&cold).expect("cold read"), serialized);
    verify_replay(&cold, &fixture, &mut allowance);
    assert_eq!(sequence(&reopened), before);
}

fn replace_envelope(prepared: &mut PreparedContext, changed: &RouterEnvelope) {
    let trace = prepared.router_trace.as_mut().expect("prepared trace");
    let bytes = canonical_bytes(changed, &mut budget()).expect("bounded canonical fault fixture");
    trace.trace_digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
    trace.canonical_json = String::from_utf8(bytes).expect("UTF-8 envelope");
    // The genuine native seal is never manufactured or replaced.
}

#[test]
fn v2_profile_refuses_missing_replay_mixed_versions_and_rehashed_unsealed_downgrade_atomically() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_keys_directory, keys) =
        crate::encryption::tests::authority("native-replay-profile-gates");
    let (_ledger_directory, ledger) =
        crate::suppression::tests::authority("native-replay-profile-gates");
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "native-replay-profile-gates",
            [7; 32],
            ledger,
            keys,
        )
        .expect("encrypted native owner"),
    );
    let fixture = planned_fixture_with_setup(&service, false, Some(replay_profile));
    let original = envelope(&fixture.prepared);
    let before = sequence(&service);
    type EnvelopeFault = (&'static str, fn(&mut RouterEnvelope));
    let faults: [EnvelopeFault; 6] = [
        ("v1 format cannot contain replay", |trace| {
            trace.format = FORMAT.into()
        }),
        ("policy removed", |trace| {
            trace.materials.prepared_policy = None
        }),
        ("preparation removed", |trace| {
            trace
                .materials
                .prepared_policy
                .as_mut()
                .expect("v2 prepared policy")
                .replay = None
        }),
        ("observation removed", |trace| {
            trace.replay_observation = None
        }),
        ("observation digest changed", |trace| {
            trace
                .replay_observation
                .as_mut()
                .expect("v2 attempt observation")
                .preparation_digest = ContentDigest::from_bytes([99; 32])
        }),
        ("observation format changed", |trace| {
            trace
                .replay_observation
                .as_mut()
                .expect("v2 attempt observation")
                .format = "unsupported-replay-observation".into()
        }),
    ];
    for (label, mutate) in faults {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_eq!(
            changed.validate(&mut budget()).expect_err(label).code,
            ErrorCode::IntegrityFailure
        );
        let mut prepared = fixture.prepared.clone();
        replace_envelope(&mut prepared, &changed);
        assert_eq!(
            prepared_envelope(
                prepared.router_trace.as_ref().expect("prepared v2 trace"),
                &mut budget()
            )
            .err()
            .expect(label)
            .code,
            ErrorCode::IntegrityFailure
        );
        let request = capture_request(&fixture.source, &fixture.checkpoint, &prepared);
        assert_eq!(
            decode_envelope(&request.event, &mut budget())
                .err()
                .expect(label)
                .code,
            ErrorCode::IntegrityFailure
        );
        assert_eq!(
            service
                .capture_prepared_model_request(
                    request,
                    &prepared,
                    Some(&fixture.checkpoint.receipt),
                    &mut budget()
                )
                .expect_err(label)
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            sequence(&service),
            before,
            "refusal cannot activate features or publish rows"
        );
    }
    let mut version_only = fixture.prepared.clone();
    version_only
        .router_trace
        .as_mut()
        .expect("prepared v2 trace")
        .version = contextdb_core::ROUTER_TRACE_VERSION;
    assert_eq!(
        prepared_envelope(
            version_only
                .router_trace
                .as_ref()
                .expect("prepared v2 trace"),
            &mut budget()
        )
        .err()
        .expect("prepared version must match explicit envelope format")
        .code,
        ErrorCode::IntegrityFailure
    );
    let mut downgraded_request = fixture.request.clone();
    let EventPayload::Assembly { manifest } = &mut downgraded_request.event.payload else {
        panic!("model request");
    };
    manifest
        .router_trace
        .as_mut()
        .expect("accepted v2 attachment")
        .header
        .version = contextdb_core::ROUTER_TRACE_VERSION;
    assert_eq!(
        decode_envelope(&downgraded_request.event, &mut budget())
            .err()
            .expect("page header must match explicit envelope version")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(
        service
            .capture_prepared_model_request(
                downgraded_request,
                &fixture.prepared,
                Some(&fixture.checkpoint.receipt),
                &mut budget()
            )
            .expect_err("attachment version must match the genuine owner preparation")
            .code,
        ErrorCode::InvalidArgument
    );

    // Even a locally coherent v1 envelope with all extensions removed cannot
    // inherit the owner-issued v2 seal. This is a seal boundary, not an ACL grant.
    let mut stripped = original.clone();
    stripped.format = FORMAT.into();
    stripped.materials.prepared_policy = None;
    stripped.replay_observation = None;
    let mut prepared = fixture.prepared.clone();
    replace_envelope(&mut prepared, &stripped);
    prepared
        .router_trace
        .as_mut()
        .expect("prepared v2 trace")
        .version = contextdb_core::ROUTER_TRACE_VERSION;
    let request = capture_request(&fixture.source, &fixture.checkpoint, &prepared);
    assert_eq!(
        service
            .capture_prepared_model_request(
                request,
                &prepared,
                Some(&fixture.checkpoint.receipt),
                &mut budget()
            )
            .expect_err("stripped rehashed v1 bytes retain no v2 owner authority")
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(sequence(&service), before);
    publish(&service, &fixture);
    service
        .verify_native(true)
        .expect("only the real v2 capture is accepted");
}

#[test]
fn v2_existing_capabilities_cancellation_and_parent_budget_precede_protected_body() {
    let directory = tempfile::tempdir().expect("native directory");
    let (_keys_directory, keys) =
        crate::encryption::tests::authority("native-replay-read-allowance");
    let (_ledger_directory, ledger) =
        crate::suppression::tests::authority("native-replay-read-allowance");
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "native-replay-read-allowance",
            [7; 32],
            ledger,
            keys,
        )
        .expect("encrypted native owner"),
    );
    let fixture = accepted_fixture_with_setup(&service, replay_profile);
    let mut tx = service
        .engine
        .begin_write()
        .expect("explicit protected body fault");
    tx.put(
        &service.keyspaces.observations_content,
        crate::digest_bytes(fixture.request.event.event_id.to_string().as_bytes()).into_bytes(),
        b"poisoned v2 protected original body".to_vec(),
    )
    .expect("body fault");
    tx.commit(Durability::Sync).expect("fault fixture Sync");
    let before = sequence(&service);
    let mut admin = read_request(&fixture);
    admin.context.capability_grants = BTreeSet::from([Capability::Admin]);
    assert_eq!(
        service
            .read_accepted_router_trace(admin, &mut budget())
            .expect_err("Admin alone does not supply existing raw read capabilities")
            .code,
        ErrorCode::Unauthorized
    );
    let mut empty = QueryBudget::new(0, 0, Duration::from_secs(30), QueryCancellation::default());
    assert_eq!(
        service
            .read_accepted_router_trace(read_request(&fixture), &mut empty)
            .expect_err("caller exhaustion precedes poisoned protected bytes")
            .code,
        ErrorCode::BudgetExhausted
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        2_000_000,
        1024 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    assert_eq!(
        service
            .read_accepted_router_trace(read_request(&fixture), &mut cancelled)
            .expect_err("caller cancellation precedes poisoned protected bytes")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(sequence(&service), before);
}
