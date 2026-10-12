//! Encrypted owner-certificate guards. Synthetic certificates are not publications.
use super::*;
use contextdb_service::{CapturePort, ErrorCode};
use contextdb_storage::{Durability, SnapshotSelector, StorageEngine, WriteTransaction};
use std::{sync::Arc, time::Duration};

const DATABASE: &str = "prefix-root-certificate-fixture";
struct Fixture {
    native: NativeService,
    root: tempfile::TempDir,
    ledger: Arc<crate::NativeSuppressionLedger>,
    keys: Arc<crate::NativeCustodyKeys>,
    _ledger: tempfile::TempDir,
    _keys: tempfile::TempDir,
    workspace: String,
}
fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("prefix roots directory");
    let (ld, ledger) = crate::suppression::tests::authority(DATABASE);
    let (kd, keys) = crate::encryption::tests::authority(DATABASE);
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        DATABASE,
        [41; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted native owner");
    let request = crate::capture::tests::request(1, "actual capture before any prefix roots");
    let workspace = request.context.request.workspace_id.clone();
    native
        .append_event(request)
        .expect("accepted actual original");
    Fixture {
        native,
        root,
        ledger,
        keys,
        _ledger: ld,
        _keys: kd,
        workspace,
    }
}
fn budget() -> QueryBudget {
    QueryBudget::new(
        100_000,
        32 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}
fn current(native: &NativeService, workspace: &str) -> ServiceResult<WorkspaceState> {
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(storage_error)?;
    native.current_prefix_bases(&snapshot, workspace, &mut budget())
}
fn certificate(native: &NativeService, workspace: &str) -> WorkspaceState {
    let _guard = native.lock_writes().expect("owner certificate lock");
    let mut tx = native.engine.begin_write().expect("owner transaction");
    let mut frame = native
        .begin_frame(&tx, workspace, false)
        .expect("actual owner frame");
    for feature in [
        crate::raw_index::INDEX_FEATURE,
        crate::raw_index::bm25::FEATURE,
        crate::raw_index::dense::FEATURE,
        FEATURE,
    ] {
        native
            .enable_capture_extension(&mut tx, feature)
            .expect("test-only format declaration");
    }
    // Empty is sufficient to prove durable non-downgrade/signature behavior;
    // this operation intentionally has no accepted prefix graph or locator.
    frame.state.prefix_bases = Some(BTreeMap::new());
    let request = crate::canonical_digest(&(frame.global_commit, "prefix certificate fixture"))
        .expect("fixture request digest");
    native
        .finish_frame(
            &mut tx,
            &frame,
            "prefix_root_certificate_fixture",
            request.as_bytes(),
            &request,
            &(frame.global_commit, "certificate primitive only"),
        )
        .expect("owner-signed frame");
    crate::require_sync(tx.commit(Durability::Sync).expect("owner Sync").durability).expect("Sync");
    frame.state
}
fn put_state_and_map(native: &NativeService, state: &WorkspaceState) {
    let mut tx = native.engine.begin_write().expect("fault transaction");
    tx.put(
        &native.keyspaces.workspace,
        state.workspace_digest.as_bytes().to_vec(),
        encode(state).expect("state"),
    )
    .expect("fault state");
    tx.put(
        &native.keyspaces.workspace_map,
        workspace_map_key(&state.workspace_digest, state.watermarks.journal),
        encode(&CommitMap {
            schema_version: SCHEMA_VERSION,
            global_commit: state.latest_global_commit,
            state: state.clone(),
        })
        .expect("map"),
    )
    .expect("fault map");
    tx.commit(Durability::Sync).expect("fault Sync");
}
fn strip_feature(native: &NativeService) {
    let mut tx = native
        .engine
        .begin_write()
        .expect("feature fault transaction");
    let mut manifest: Manifest = decode(
        &tx.get(&native.keyspaces.meta, crate::META_MANIFEST_KEY)
            .expect("actual manifest")
            .expect("present"),
        "manifest",
    )
    .expect("typed manifest");
    manifest.features.remove(FEATURE);
    manifest.checksum = crate::manifest_checksum(&manifest).expect("unkeyed checksum");
    tx.put(
        &native.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest"),
    )
    .expect("fault manifest");
    tx.commit(Durability::Sync).expect("feature fault Sync");
}
fn deny_capture(native: &NativeService, sequence: u64) {
    let before = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before");
    let head = native.global_head(&before).expect("actual global head");
    drop(before);
    assert_eq!(
        native
            .append_event(crate::capture::tests::request(
                sequence,
                "must not sign another frame from the corrupted predecessor"
            ))
            .expect_err("every writer checks its predecessor")
            .code,
        ErrorCode::IntegrityFailure
    );
    let after = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after");
    assert_eq!(
        native.global_head(&after).expect("unchanged global head"),
        head
    );
}

#[test]
fn prefix_none_keeps_exact_legacy_bytes_and_authenticates_budgeted_absence() {
    let f = fixture();
    let workspace = digest_bytes(f.workspace.as_bytes());
    let genesis = WorkspaceState::genesis(workspace.clone());
    let expected = format!(
        "{{\"schema_version\":1,\"workspace_digest\":\"{workspace}\",\"latest_global_commit\":0,\"watermarks\":{{\"journal\":0,\"semantic\":0,\"lexical\":0,\"vector\":0,\"graph\":0}}}}"
    );
    assert_eq!(
        encode(&genesis).expect("legacy genesis"),
        expected.as_bytes()
    );
    let state = current(&f.native, &f.workspace).expect("authentic current None");
    assert!(state.prefix_bases.is_none());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let bytes = snapshot
        .get(
            &f.native.keyspaces.events,
            &state.latest_global_commit.to_be_bytes(),
        )
        .expect("actual event")
        .expect("present");
    let event: StoredEvent = decode(&bytes, "actual legacy event").expect("event");
    assert!(
        !std::str::from_utf8(&bytes)
            .expect("event JSON")
            .contains("prefix_bases")
    );
    assert!(event.prefix_bases.is_none());
    assert_eq!(
        f.native
            .prefix_base_stamp(&state, &event)
            .expect("legacy stamp"),
        None
    );
    let mut tiny = QueryBudget::new(0, 0, Duration::from_secs(60), Default::default());
    assert_eq!(
        f.native
            .current_prefix_bases(&snapshot, &f.workspace, &mut tiny)
            .expect_err("parent before metadata IO")
            .code,
        ErrorCode::BudgetExhausted
    );
}

#[test]
fn prefix_some_empty_propagates_through_capture_and_cold_but_does_not_prove_publication() {
    let f = fixture();
    certificate(&f.native, &f.workspace);
    let capture = f
        .native
        .append_event(crate::capture::tests::request(
            2,
            "actual original after prefix certificate",
        ))
        .expect("actual capture");
    let state = current(&f.native, &f.workspace).expect("authenticated Some empty");
    assert_eq!(state.prefix_bases, Some(BTreeMap::new()));
    assert!(
        state.segment_heads.is_none(),
        "prefix format does not activate v1 directories"
    );
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let event: StoredEvent = decode(
        &snapshot
            .get(
                &f.native.keyspaces.events,
                &state.latest_global_commit.to_be_bytes(),
            )
            .expect("actual event")
            .expect("present"),
        "event",
    )
    .expect("typed event");
    assert_eq!(
        event
            .accepted_original
            .as_ref()
            .expect("actual capture work")
            .event_id,
        capture.event_id
    );
    assert!(event.prefix_bases.is_some());
    assert!(event.segment_heads.is_none());
    f.native
        .verify_prefix_heads_inner(&snapshot, &mut budget(), false)
        .expect("owner certificate replay only");
    assert_eq!(
        f.native
            .verify_prefix_bases_records(&snapshot, &mut budget())
            .expect_err("synthetic certificate is not accepted prefix publication")
            .code,
        ErrorCode::IntegrityFailure
    );
    drop(snapshot);
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        DATABASE,
        [41; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold owner certificate");
    assert_eq!(
        current(&cold, &f.workspace).expect("cold exact owner root"),
        state
    );
    cold.append_event(crate::capture::tests::request(
        3,
        "actual original after cold Some empty",
    ))
    .expect("cold source capture");
    assert_eq!(
        current(&cold, &f.workspace)
            .expect("empty remains activated")
            .prefix_bases,
        Some(BTreeMap::new())
    );
}

#[test]
fn joint_none_strip_and_authentic_old_none_replay_cannot_mint_a_new_owner_frame() {
    let f = fixture();
    let legacy = current(&f.native, &f.workspace).expect("old authentic None");
    certificate(&f.native, &f.workspace);
    let accepted = current(&f.native, &f.workspace).expect("accepted certificate");
    let mut stripped = accepted.clone();
    stripped.prefix_bases = None;
    put_state_and_map(&f.native, &stripped);
    assert_eq!(
        current(&f.native, &f.workspace)
            .expect_err("event still has its real owner stamp")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture(&f.native, 2);
    put_state_and_map(&f.native, &accepted);
    f.native
        .append_event(crate::capture::tests::request(
            2,
            "actual later committed source",
        ))
        .expect("later source capture");
    // Replay the real preactivation state/map; later accepted maps remain.
    put_state_and_map(&f.native, &legacy);
    assert_eq!(
        current(&f.native, &f.workspace)
            .expect_err("old None has an accepted successor")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture(&f.native, 3);
    strip_feature(&f.native);
    assert_eq!(
        current(&f.native, &f.workspace)
            .expect_err("surviving successor defeats format stripping")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture(&f.native, 3);
}

#[test]
fn surviving_prefix_stamp_closes_the_missing_map_legacy_exception_even_without_feature() {
    let f = fixture();
    let accepted = certificate(&f.native, &f.workspace);
    let mut stripped = accepted.clone();
    stripped.prefix_bases = None;
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("joint fault transaction");
    tx.put(
        &f.native.keyspaces.workspace,
        stripped.workspace_digest.as_bytes().to_vec(),
        encode(&stripped).expect("stripped world"),
    )
    .expect("fault world");
    tx.delete(
        &f.native.keyspaces.workspace_map,
        workspace_map_key(&accepted.workspace_digest, accepted.watermarks.journal),
    )
    .expect("delete exact current map");
    tx.commit(Durability::Sync).expect("fault Sync");
    strip_feature(&f.native);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("surviving event snapshot");
    let event: StoredEvent = decode(
        &snapshot
            .get(
                &f.native.keyspaces.events,
                &accepted.latest_global_commit.to_be_bytes(),
            )
            .expect("actual event")
            .expect("present"),
        "event",
    )
    .expect("typed surviving certificate");
    assert!(
        event.prefix_bases.is_some(),
        "real owner certificate remains in the journal"
    );
    drop(snapshot);
    deny_capture(&f.native, 2);
}

#[test]
fn prefix_root_decoder_refuses_duplicate_or_excess_generations_before_value_growth() {
    let f = fixture();
    let mut state = serde_json::to_value(current(&f.native, &f.workspace).expect("current None"))
        .expect("state wire");
    let reference = PrefixBaseRefV2 {
        global_commit: 1,
        request_digest: "a".repeat(64),
        response_digest: "b".repeat(64),
        receipt_digest: ContentDigest::from_bytes([1; 32]),
        content_digest: ContentDigest::from_bytes([2; 32]),
    };
    let wire = serde_json::to_string(&reference).expect("bounded shape");
    state["prefix_bases"] =
        serde_json::json!({"1":reference,"2":reference,"3":reference,"4":reference});
    assert!(serde_json::from_value::<WorkspaceState>(state).is_err());
    let base =
        serde_json::to_string(&current(&f.native, &f.workspace).expect("None")).expect("state");
    let duplicated = format!(
        "{},\"prefix_bases\":{{\"1\":{wire},\"1\":{wire}}}}}",
        base.strip_suffix('}').expect("object")
    );
    assert!(serde_json::from_str::<WorkspaceState>(&duplicated).is_err());
}
