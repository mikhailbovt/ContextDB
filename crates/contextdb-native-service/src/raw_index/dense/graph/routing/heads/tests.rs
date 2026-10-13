//! Encrypted frame-certificate proofs; synthetic empty maps are not publications.
use super::*;
use crate::storage_error;
use contextdb_service::{CapturePort, ErrorCode};
use contextdb_storage::{Durability, SnapshotSelector, StorageEngine, WriteTransaction};
use std::{sync::Arc, time::Duration};

const DATABASE: &str = "directory-router-head-certificate";
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
    let root = tempfile::tempdir().expect("certificate directory");
    let (ld, ledger) = crate::suppression::tests::authority(DATABASE);
    let (kd, keys) = crate::encryption::tests::authority(DATABASE);
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        DATABASE,
        [43; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted owner");
    let request = crate::capture::tests::request(1, "actual original before head activation");
    let workspace = request.context.request.workspace_id.clone();
    native
        .append_event(request)
        .expect("accepted actual capture");
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
        1_000_000,
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
    native.current_directory_router_heads(&snapshot, workspace, &mut budget())
}
fn certificate(native: &NativeService, workspace: &str) -> WorkspaceState {
    let _guard = native.lock_writes().expect("owner lock");
    let mut tx = native.engine.begin_write().expect("owner transaction");
    let mut frame = native
        .begin_frame(&tx, workspace, false)
        .expect("actual owner frame");
    for feature in [
        crate::raw_index::INDEX_FEATURE,
        crate::raw_index::bm25::FEATURE,
        crate::raw_index::dense::FEATURE,
        super::super::super::prefix_v2::types::FEATURE,
        FEATURE,
    ] {
        native
            .enable_capture_extension(&mut tx, feature)
            .expect("test format declaration");
    }
    // Two independent empty maps test certificates/domain separation only.
    // This intentionally is not an accepted prefix or router publication.
    frame.state.prefix_bases = Some(BTreeMap::new());
    frame.state.directory_routers = Some(BTreeMap::new());
    let request = crate::canonical_digest(&(frame.global_commit, "head certificate only"))
        .expect("fixture request");
    native
        .finish_frame(
            &mut tx,
            &frame,
            "directory_router_certificate_fixture",
            request.as_bytes(),
            &request,
            &(frame.global_commit, "no accepted publication"),
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
        encode(state).expect("fault state"),
    )
    .expect("put state");
    tx.put(
        &native.keyspaces.workspace_map,
        workspace_map_key(&state.workspace_digest, state.watermarks.journal),
        encode(&CommitMap {
            schema_version: SCHEMA_VERSION,
            global_commit: state.latest_global_commit,
            state: state.clone(),
        })
        .expect("fault map"),
    )
    .expect("put map");
    tx.commit(Durability::Sync).expect("fault Sync");
}
fn deny_capture(native: &NativeService, sequence: u64) {
    let before = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before");
    let head = native.global_head(&before).expect("actual head");
    drop(before);
    assert_eq!(
        native
            .append_event(crate::capture::tests::request(
                sequence,
                "corrupted predecessor must not mint another signed frame"
            ))
            .expect_err("predecessor must refuse")
            .code,
        ErrorCode::IntegrityFailure
    );
    let after = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after");
    assert_eq!(native.global_head(&after).expect("unchanged head"), head);
}

#[test]
fn none_bytes_and_zero_parent_admit_no_new_head_or_metadata_read() {
    let f = fixture();
    let workspace = digest_bytes(f.workspace.as_bytes());
    let genesis = WorkspaceState::genesis(workspace.clone());
    let expected = format!(
        "{{\"schema_version\":1,\"workspace_digest\":\"{workspace}\",\"latest_global_commit\":0,\"watermarks\":{{\"journal\":0,\"semantic\":0,\"lexical\":0,\"vector\":0,\"graph\":0}}}}"
    );
    assert_eq!(encode(&genesis).expect("old bytes"), expected.as_bytes());
    let state = current(&f.native, &f.workspace).expect("authentic None");
    assert!(state.directory_routers.is_none());
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
        .expect("event")
        .expect("present");
    assert!(
        !std::str::from_utf8(&bytes)
            .expect("JSON")
            .contains("directory_routers")
    );
    let event: StoredEvent = decode(&bytes, "legacy event").expect("typed event");
    assert_eq!(
        f.native
            .directory_router_head_stamp(&state, &event)
            .expect("None"),
        None
    );
    let mut zero = QueryBudget::new(0, 0, Duration::from_secs(60), Default::default());
    assert_eq!(
        f.native
            .current_directory_router_heads(&snapshot, &f.workspace, &mut zero)
            .expect_err("refuse before metadata")
            .code,
        ErrorCode::BudgetExhausted
    );
}

#[test]
fn independent_empty_stamps_survive_actual_capture_and_cold_without_faking_acceptance() {
    let f = fixture();
    certificate(&f.native, &f.workspace);
    let capture = f
        .native
        .append_event(crate::capture::tests::request(
            2,
            "actual source after independent certificates",
        ))
        .expect("actual capture");
    let state = current(&f.native, &f.workspace).expect("strict current head");
    assert_eq!(state.directory_routers, Some(BTreeMap::new()));
    assert!(state.segment_heads.is_none(), "no v1 activation");
    assert!(
        state.prefix_segment_heads.is_none(),
        "base-only certificate has no segment activation"
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
            .expect("event")
            .expect("present"),
        "event",
    )
    .expect("typed event");
    assert_eq!(
        event
            .accepted_original
            .as_ref()
            .expect("accepted capture")
            .event_id,
        capture.event_id
    );
    let stamp = event.directory_routers.as_ref().expect("new stamp");
    let prefix = event.prefix_bases.as_ref().expect("prefix stamp");
    assert_eq!(
        stamp.map_digest, prefix.map_digest,
        "same empty-map content"
    );
    assert_ne!(stamp.token, prefix.token, "distinct owner domains");
    let mut changed_sibling = state.clone();
    changed_sibling.prefix_segment_heads = Some(BTreeMap::new());
    assert_ne!(
        f.native
            .directory_router_head_stamp(&changed_sibling, &event)
            .expect("same router map, different sibling map"),
        event.directory_routers,
        "new signature commits sibling None versus Some(empty)"
    );
    assert_eq!(
        f.native
            .current_prefix_bases(&snapshot, &f.workspace, &mut budget())
            .expect("cross-family prefix check"),
        state
    );
    assert_eq!(
        f.native
            .current_segment_heads(&snapshot, &f.workspace, &mut budget())
            .expect("cross-family segment check"),
        state
    );
    f.native
        .verify_directory_router_heads_inner(&snapshot, &mut budget(), false)
        .expect("certificate primitive replay");
    assert_eq!(
        f.native
            .verify_directory_router_heads_records(&snapshot, &mut budget())
            .expect_err("synthetic certificate is not accepted router publication")
            .code,
        ErrorCode::IntegrityFailure
    );
    drop(snapshot);
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        DATABASE,
        [43; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("cold owner");
    assert_eq!(
        current(&cold, &f.workspace).expect("cold authenticated map"),
        state
    );
    cold.append_event(crate::capture::tests::request(3, "actual cold source"))
        .expect("actual owner continuation");
    assert_eq!(
        current(&cold, &f.workspace)
            .expect("cold continuation")
            .directory_routers,
        Some(BTreeMap::new())
    );
}

#[test]
fn cross_family_map_strip_and_real_old_none_successor_refuse_before_capture() {
    let f = fixture();
    let legacy = current(&f.native, &f.workspace).expect("real old None");
    let accepted = certificate(&f.native, &f.workspace);
    let mut stripped = accepted.clone();
    stripped.directory_routers = None;
    put_state_and_map(&f.native, &stripped);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault snapshot");
    assert_eq!(
        f.native
            .current_prefix_bases(&snapshot, &f.workspace, &mut budget())
            .expect_err("old prefix map matches, new event stamp does not")
            .code,
        ErrorCode::IntegrityFailure
    );
    drop(snapshot);
    assert_eq!(
        current(&f.native, &f.workspace)
            .expect_err("new map stripped")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture(&f.native, 2);
    put_state_and_map(&f.native, &accepted);
    f.native
        .append_event(crate::capture::tests::request(
            2,
            "later real accepted capture",
        ))
        .expect("later capture");
    put_state_and_map(&f.native, &legacy);
    assert_eq!(
        current(&f.native, &f.workspace)
            .expect_err("real old None has successor")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture(&f.native, 3);
}

#[test]
fn bounded_decoder_rejects_extra_and_duplicate_keys_before_values_grow() {
    let f = fixture();
    let reference = DirectoryRouterRefV1 {
        serial: 1,
        global_commit: 1,
        request_digest: "a".repeat(64),
        response_digest: "b".repeat(64),
        receipt_digest: ContentDigest::from_bytes([1; 32]),
        content_digest: ContentDigest::from_bytes([2; 32]),
    };
    let mut state =
        serde_json::to_value(current(&f.native, &f.workspace).expect("None")).expect("state JSON");
    state["directory_routers"] =
        serde_json::json!({"1":reference,"2":reference,"3":reference,"4":reference});
    assert!(serde_json::from_value::<WorkspaceState>(state).is_err());
    let wire = serde_json::to_string(&reference).expect("shape");
    let base =
        serde_json::to_string(&current(&f.native, &f.workspace).expect("None")).expect("state");
    let duplicate = format!(
        "{},\"directory_routers\":{{\"1\":{wire},\"1\":{wire}}}}}",
        base.strip_suffix('}').expect("object")
    );
    assert!(serde_json::from_str::<WorkspaceState>(&duplicate).is_err());
}

#[test]
fn four_full_max_width_root_maps_fit_the_existing_eight_kibibyte_head_bound() {
    // A shape-bound proof, not a synthetic publication or accepted source census.
    let mut state = WorkspaceState::genesis("a".repeat(64));
    state.latest_global_commit = u64::MAX;
    state.watermarks.journal = u64::MAX;
    state.watermarks.semantic = u64::MAX;
    state.watermarks.lexical = u64::MAX;
    state.watermarks.vector = u64::MAX;
    state.watermarks.graph = u64::MAX;
    let mut legacy = BTreeMap::new();
    let mut bases = BTreeMap::new();
    let mut segments = BTreeMap::new();
    let mut routers = BTreeMap::new();
    for generation in [u64::MAX - 2, u64::MAX - 1, u64::MAX] {
        legacy.insert(
            generation,
            crate::raw_index::dense::graph::segments::types::DirectoryRef {
                count: u64::MAX,
                global_commit: u64::MAX,
                request_digest: "b".repeat(64),
                response_digest: "c".repeat(64),
                content_digest: ContentDigest::from_bytes([3; 32]),
            },
        );
        bases.insert(
            generation,
            crate::raw_index::dense::graph::prefix_v2::types::PrefixBaseRefV2 {
                global_commit: u64::MAX,
                request_digest: "b".repeat(64),
                response_digest: "c".repeat(64),
                receipt_digest: ContentDigest::from_bytes([2; 32]),
                content_digest: ContentDigest::from_bytes([3; 32]),
            },
        );
        segments.insert(generation, crate::raw_index::dense::graph::prefix_segments_v2::types::PrefixSegmentDirectoryRefV2 {
            count: u64::MAX, global_commit: u64::MAX,
            request_digest: "b".repeat(64), response_digest: "c".repeat(64),
            content_digest: ContentDigest::from_bytes([3; 32]),
        });
        routers.insert(
            generation,
            DirectoryRouterRefV1 {
                serial: u64::MAX,
                global_commit: u64::MAX,
                request_digest: "b".repeat(64),
                response_digest: "c".repeat(64),
                receipt_digest: ContentDigest::from_bytes([2; 32]),
                content_digest: ContentDigest::from_bytes([3; 32]),
            },
        );
    }
    state.segment_heads = Some(legacy);
    state.prefix_bases = Some(bases);
    state.prefix_segment_heads = Some(segments);
    state.directory_routers = Some(routers);
    validate_workspace_state(&state, &state.workspace_digest).expect("max-width bounded map shape");
    let state_bytes = encode(&state).expect("canonical state");
    assert!(
        state_bytes.len() <= HEAD_BYTES,
        "all four maps must fit the frozen head cap"
    );
    let mapping = CommitMap {
        schema_version: SCHEMA_VERSION,
        global_commit: u64::MAX,
        state,
    };
    let map_bytes = encode(&mapping).expect("canonical commit map");
    assert!(
        map_bytes.len() <= HEAD_BYTES,
        "commit envelope must also fit the same cap"
    );
    assert_eq!(
        decode::<CommitMap>(&map_bytes, "four-map roundtrip").expect("typed map"),
        mapping
    );
}
