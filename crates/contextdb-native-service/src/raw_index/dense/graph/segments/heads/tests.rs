//! Head-certificate primitives, not accepted segment append/GC evidence.
use super::*;
use contextdb_service::{CapturePort, ErrorCode};
use contextdb_storage::{Durability, SnapshotSelector, StorageEngine, WriteTransaction};
use std::{sync::Arc, time::Duration};

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
    let root = tempfile::tempdir().expect("heads directory");
    let (ld, ledger) = crate::suppression::tests::authority("segment-heads-fixture");
    let (kd, keys) = crate::encryption::tests::authority("segment-heads-fixture");
    let native = NativeService::open_encrypted(
        root.path().join("native"),
        "segment-heads-fixture",
        [37; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted owner");
    let request = crate::capture::tests::request(1, "actual original before head activation");
    let workspace = request.context.request.workspace_id.clone();
    native.append_event(request).expect("original capture");
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
        16 * 1024 * 1024,
        Duration::from_secs(60),
        Default::default(),
    )
}
fn current(native: &NativeService, workspace: &str) -> ServiceResult<WorkspaceState> {
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .map_err(storage_error)?;
    native.current_segment_heads(&snapshot, workspace, &mut budget())
}
// These declarations are intentionally synthetic certificate inputs. There is
// no segment publication operation, vector receipt, or serving activation here.
fn publish_certificate(native: &NativeService, workspace: &str, empty: bool) -> WorkspaceState {
    let _guard = native.lock_writes().expect("owner lock");
    let mut tx = native.engine.begin_write().expect("owner tx");
    let mut frame = native
        .begin_frame(&tx, workspace, false)
        .expect("owner frame");
    for feature in [
        crate::raw_index::INDEX_FEATURE,
        crate::raw_index::bm25::FEATURE,
        crate::raw_index::dense::FEATURE,
        crate::raw_index::dense::graph::FEATURE,
        FEATURE,
    ] {
        native
            .enable_capture_extension(&mut tx, feature)
            .expect("test-only format declaration");
    }
    frame.state.segment_heads = Some(if empty {
        BTreeMap::new()
    } else {
        BTreeMap::from([(
            1,
            DirectoryRef {
                count: 1,
                global_commit: frame.global_commit,
                request_digest: digest_bytes(b"synthetic certificate request"),
                response_digest: digest_bytes(b"synthetic certificate response"),
                content_digest: ContentDigest::from_bytes(
                    *blake3::hash(b"synthetic certificate directory").as_bytes(),
                ),
            },
        )])
    });
    let request = crate::canonical_digest(&(frame.global_commit, &frame.state.segment_heads))
        .expect("fixture request");
    native
        .finish_frame(
            &mut tx,
            &frame,
            "segment_head_certificate_fixture",
            request.as_bytes(),
            &request,
            &(frame.global_commit, "certificate fixture"),
        )
        .expect("owner-signed frame");
    crate::require_sync(tx.commit(Durability::Sync).expect("owner sync").durability)
        .expect("sync durability");
    frame.state
}
fn put_state_and_map(native: &NativeService, state: &WorkspaceState) {
    let mut tx = native.engine.begin_write().expect("fault tx");
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
    tx.commit(Durability::Sync).expect("fault sync");
}
fn deny_capture_without_frame(native: &NativeService, sequence: u64) {
    let before = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("before snapshot");
    let head = native.global_head(&before).expect("before global head");
    drop(before);
    assert_eq!(
        native
            .append_event(crate::capture::tests::request(
                sequence,
                "must not be accepted under a replayed head"
            ))
            .expect_err("writer refuses predecessor")
            .code,
        ErrorCode::IntegrityFailure
    );
    let after = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("after snapshot");
    assert_eq!(native.global_head(&after).expect("after global head"), head);
}

#[test]
fn legacy_none_bytes_and_owner_capture_propagate_cold_head_certificate() {
    let f = fixture();
    let workspace_digest = digest_bytes(f.workspace.as_bytes());
    let genesis = WorkspaceState::genesis(workspace_digest.clone());
    let expected = format!(
        "{{\"schema_version\":1,\"workspace_digest\":\"{workspace_digest}\",\"latest_global_commit\":0,\"watermarks\":{{\"journal\":0,\"semantic\":0,\"lexical\":0,\"vector\":0,\"graph\":0}}}}"
    );
    assert_eq!(encode(&genesis).expect("legacy bytes"), expected.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("legacy snapshot");
    let event_bytes = snapshot
        .get(&f.native.keyspaces.events, &1_u64.to_be_bytes())
        .expect("legacy event")
        .expect("stored");
    let event: StoredEvent = decode(&event_bytes, "legacy event").expect("event");
    assert!(event.segment_heads.is_none());
    assert!(
        !std::str::from_utf8(&event_bytes)
            .expect("JSON")
            .contains("segment_heads")
    );
    assert_eq!(
        f.native
            .segment_head_stamp(&current(&f.native, &f.workspace).expect("None"), &event)
            .expect("legacy stamp"),
        None
    );
    drop(snapshot);
    let activation = publish_certificate(&f.native, &f.workspace, false);
    let capture = f
        .native
        .append_event(crate::capture::tests::request(
            2,
            "actual source after certificate",
        ))
        .expect("ordinary source capture");
    let state = current(&f.native, &f.workspace).expect("current owner head");
    assert_eq!(state.segment_heads, activation.segment_heads);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("latest");
    let map: CommitMap = decode(
        &snapshot
            .get(
                &f.native.keyspaces.workspace_map,
                &workspace_map_key(&workspace_digest, state.watermarks.journal),
            )
            .expect("commit map")
            .expect("present"),
        "map",
    )
    .expect("typed map");
    assert_eq!(map.state, state);
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
    assert_eq!(event.operation, "capture");
    assert_eq!(
        event
            .accepted_original
            .as_ref()
            .expect("actual accepted source")
            .event_id,
        capture.event_id
    );
    assert!(event.segment_heads.is_some());
    f.native
        .verify_segment_head_certificates(&snapshot, &mut budget())
        .expect("certificate history");
    assert_eq!(
        f.native
            .verify_segment_heads_records(&snapshot, &mut budget())
            .expect_err("certificate shape alone is not an accepted segment append")
            .code,
        ErrorCode::IntegrityFailure
    );
    drop(snapshot);
    let Fixture {
        native,
        root,
        ledger,
        keys,
        _ledger,
        _keys,
        workspace,
    } = f;
    drop(native);
    let cold = NativeService::open_encrypted(
        root.path().join("native"),
        "segment-heads-fixture",
        [37; 32],
        ledger,
        keys,
    )
    .expect("cold owner");
    assert_eq!(current(&cold, &workspace).expect("cold current"), state);
    let empty = publish_certificate(&cold, &workspace, true);
    assert_eq!(empty.segment_heads, Some(BTreeMap::new()));
    cold.append_event(crate::capture::tests::request(
        3,
        "source after empty certificate",
    ))
    .expect("capture with empty map");
    assert_eq!(
        current(&cold, &workspace)
            .expect("empty remains activated")
            .segment_heads,
        Some(BTreeMap::new())
    );
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cold snapshot");
    cold.verify_segment_head_certificates(&snapshot, &mut budget())
        .expect("Some empty remains stamped");
}

#[test]
fn current_head_refuses_joint_map_retarget_and_old_valid_map_successor() {
    let f = fixture();
    let old = publish_certificate(&f.native, &f.workspace, false);
    f.native
        .append_event(crate::capture::tests::request(2, "later actual source"))
        .expect("later capture");
    let current_state = current(&f.native, &f.workspace).expect("current head");
    let mut forged = current_state.clone();
    forged
        .segment_heads
        .as_mut()
        .expect("map")
        .get_mut(&1)
        .expect("head")
        .count = 2;
    put_state_and_map(&f.native, &forged);
    assert_eq!(
        current(&f.native, &f.workspace)
            .expect_err("joint map change lacks owner MAC")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture_without_frame(&f.native, 3);
    put_state_and_map(&f.native, &current_state);
    // The older exact map and its stamp are authentic; a committed successor
    // still makes it invalid as the current head.
    put_state_and_map(&f.native, &old);
    assert_eq!(
        current(&f.native, &f.workspace)
            .expect_err("old valid current-map replay")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture_without_frame(&f.native, 3);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("rollback snapshot");
    assert_eq!(
        f.native
            .verify_segment_head_certificates(&snapshot, &mut budget())
            .expect_err("deep current rollback")
            .code,
        ErrorCode::IntegrityFailure
    );
    drop(snapshot);
    put_state_and_map(&f.native, &current_state);
    current(&f.native, &f.workspace).expect("restored exact current head");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("budget snapshot");
    let mut zero = QueryBudget::new(0, 0, Duration::from_secs(60), Default::default());
    assert_eq!(
        f.native
            .current_segment_heads(&snapshot, &f.workspace, &mut zero)
            .expect_err("same parent zero allowance")
            .code,
        ErrorCode::BudgetExhausted
    );
}

#[test]
fn cold_owner_mac_refuses_rehashed_journal_stamp_and_retained_feature_strip() {
    let f = fixture();
    publish_certificate(&f.native, &f.workspace, false);
    f.native
        .append_event(crate::capture::tests::request(2, "last actual capture"))
        .expect("last capture");
    let state = current(&f.native, &f.workspace).expect("head");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("event snapshot");
    let bytes = snapshot
        .get(
            &f.native.keyspaces.events,
            &state.latest_global_commit.to_be_bytes(),
        )
        .expect("event")
        .expect("present");
    let mut event: StoredEvent = decode(&bytes, "event").expect("typed event");
    event.segment_heads.as_mut().expect("stamp").token = digest_bytes(b"not the owner MAC");
    // Rehashing the unkeyed envelope is deliberately insufficient authority.
    event.event_digest = event_digest(&event).expect("rehashed event");
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("fault tx");
    tx.put(
        &f.native.keyspaces.events,
        state.latest_global_commit.to_be_bytes().to_vec(),
        encode(&event).expect("event bytes"),
    )
    .expect("fault event");
    tx.put(
        &f.native.keyspaces.meta,
        crate::META_EVENT_DIGEST_KEY.to_vec(),
        event.event_digest.as_bytes().to_vec(),
    )
    .expect("fault terminal digest");
    tx.commit(Durability::Sync).expect("fault sync");
    let Fixture {
        native,
        root,
        ledger,
        keys,
        _ledger,
        _keys,
        workspace,
    } = f;
    drop(native);
    let cold = NativeService::open_encrypted(
        root.path().join("native"),
        "segment-heads-fixture",
        [37; 32],
        ledger,
        keys,
    )
    .expect("unkeyed chain remains structurally valid");
    assert_eq!(
        current(&cold, &workspace)
            .expect_err("cold owner stamp authentication")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture_without_frame(&cold, 3);
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cold snapshot");
    assert_eq!(
        cold.verify_segment_head_certificates(&snapshot, &mut budget())
            .expect_err("deep MAC authentication")
            .code,
        ErrorCode::IntegrityFailure
    );
    drop(snapshot);
    // An independent feature-stripping fixture has authentic stamps and maps.
    let g = fixture();
    publish_certificate(&g.native, &g.workspace, true);
    let mut tx = g.native.engine.begin_write().expect("feature fault tx");
    let mut manifest = g.native.raw_manifest(&tx).expect("manifest");
    manifest.features.remove(FEATURE);
    manifest.checksum = crate::manifest_checksum(&manifest).expect("manifest checksum");
    tx.put(
        &g.native.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest bytes"),
    )
    .expect("feature strip");
    tx.commit(Durability::Sync).expect("feature sync");
    assert_eq!(
        current(&g.native, &g.workspace)
            .expect_err("empty head feature remains required")
            .code,
        ErrorCode::IntegrityFailure
    );
    deny_capture_without_frame(&g.native, 2);
    let snapshot = g
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("feature snapshot");
    assert_eq!(
        g.native
            .verify_segment_head_certificates(&snapshot, &mut budget())
            .expect_err("retained head history feature")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn every_owner_frame_rejects_none_rollback_even_after_feature_strip() {
    let f = fixture();
    let legacy = current(&f.native, &f.workspace).expect("authentic preactivation None");
    assert!(legacy.segment_heads.is_none());
    publish_certificate(&f.native, &f.workspace, false);
    f.native
        .append_event(crate::capture::tests::request(2, "later accepted source"))
        .expect("postactivation capture");
    put_state_and_map(&f.native, &legacy);
    deny_capture_without_frame(&f.native, 3);
    let mut tx = f.native.engine.begin_write().expect("feature fault tx");
    let mut manifest = f.native.raw_manifest(&tx).expect("manifest");
    manifest.features.remove(FEATURE);
    manifest.checksum = crate::manifest_checksum(&manifest).expect("checksum");
    tx.put(
        &f.native.keyspaces.meta,
        crate::META_MANIFEST_KEY.to_vec(),
        encode(&manifest).expect("manifest"),
    )
    .expect("feature strip");
    tx.commit(Durability::Sync).expect("feature fault sync");
    deny_capture_without_frame(&f.native, 3);

    // Legitimate None-only writers still tolerate unavailable historical maps
    // when the segment format was never introduced. No segment frame is signed.
    let g = fixture();
    let state = current(&g.native, &g.workspace).expect("legacy current");
    let mut tx = g.native.engine.begin_write().expect("legacy expiry tx");
    tx.delete(
        &g.native.keyspaces.workspace_map,
        workspace_map_key(&state.workspace_digest, state.watermarks.journal),
    )
    .expect("expire old legacy mapping");
    tx.commit(Durability::Sync).expect("legacy expiry sync");
    g.native
        .append_event(crate::capture::tests::request(
            2,
            "legitimate legacy capture",
        ))
        .expect("legacy None capture after expired mapping");
    assert!(
        current(&g.native, &g.workspace)
            .expect("legacy None stays None")
            .segment_heads
            .is_none()
    );
}

#[test]
fn segment_head_decoder_refuses_excess_and_duplicate_generation_keys() {
    let f = fixture();
    let state = publish_certificate(&f.native, &f.workspace, false);
    let mut value = serde_json::to_value(&state).expect("state JSON");
    let entry = value["segment_heads"]["1"].clone();
    for generation in 2..=4 {
        value["segment_heads"][generation.to_string()] = entry.clone();
    }
    assert!(serde_json::from_value::<WorkspaceState>(value).is_err());
    let ref_bytes = String::from_utf8(
        encode(&state.segment_heads.as_ref().expect("map")[&1]).expect("reference"),
    )
    .expect("JSON");
    let duplicate = format!("{{\"1\":{ref_bytes},\"1\":{ref_bytes}}}");
    let canonical_map =
        String::from_utf8(encode(state.segment_heads.as_ref().expect("map")).expect("map bytes"))
            .expect("map JSON");
    let duplicate_state = String::from_utf8(encode(&state).expect("state bytes"))
        .expect("state JSON")
        .replace(&canonical_map, &duplicate);
    assert!(serde_json::from_str::<WorkspaceState>(&duplicate_state).is_err());
}
