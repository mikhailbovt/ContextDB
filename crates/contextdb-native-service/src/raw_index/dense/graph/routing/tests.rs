//! Actual encrypted maintenance/cold/retirement evidence, not semantic recall.

use super::super::prefix_segments_v2::types::PrefixSegmentSealRequestV2;
use super::super::prefix_v2::inputs::tests::{
    DATABASE, Fixture, TOKEN_KEY, budget, fixture, read_generation,
};
use super::super::prefix_v2::types::DensePrefixBaseRequestV2;
use super::*;
use contextdb_service::{
    CapturePort, EmbeddedText, EmbeddingTextKind, ErrorCode, TextEmbeddingAdapter,
    TextEmbeddingProfile,
};

fn base(f: &Fixture) {
    f.native
        .publish_original_span_prefix_base(
            &f.context,
            &DensePrefixBaseRequestV2 {
                generation: 1,
                target: f.target.clone(),
            },
            &mut budget(),
        )
        .expect("genuine partial prefix over complete prerecorded raw archive");
}

fn seal(f: &Fixture) {
    let previous = f
        .native
        .original_span_prefix_segment_head(&f.context, 1, &mut budget())
        .expect("fine predecessor");
    let target = f
        .native
        .project_original_spans(&f.context, &f.encoder, 64, &mut budget())
        .expect("genuine dense progress");
    f.native
        .seal_original_span_prefix_segment(
            &f.context,
            &PrefixSegmentSealRequestV2 {
                generation: 1,
                previous,
                target,
            },
            &mut budget(),
        )
        .expect("complete genuine fine interval");
}

#[test]
fn encrypted_base_only_then_interval_router_keeps_old_retry_and_cold_current_owner() {
    let f = fixture();
    base(&f);
    let first_request = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("base-only target");
    assert!(first_request.previous.is_none() && first_request.coverage.directory.is_none());
    let first = f
        .native
        .publish_original_span_directory_router(&f.context, &first_request, &mut budget())
        .expect("actual complete base-only router");
    assert_eq!(first.manifest.coverage_count, 1);
    assert_eq!(first.manifest.representatives, 1);
    assert_eq!(first.manifest.raw.projected_sources, 3);
    assert_eq!(first.manifest.covered.sources, 2);
    assert_ne!(
        first.manifest.source_space_id,
        first.manifest.coarse_space_id
    );
    assert!(
        f.native
            .verify_native(true)
            .expect("deep base-only reconstruction")
            .valid
    );
    seal(&f);
    let second_request = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("stale prior root is metadata for rebuild");
    assert_eq!(
        second_request.previous.as_ref().expect("first root").serial,
        1
    );
    assert_eq!(
        second_request
            .coverage
            .directory
            .as_ref()
            .expect("fine directory")
            .count,
        1
    );
    let second = f
        .native
        .publish_original_span_directory_router(&f.context, &second_request, &mut budget())
        .expect("complete independent second router");
    assert_eq!(second.manifest.serial, 2);
    assert_eq!(second.manifest.coverage_count, 2);
    assert_eq!(second.manifest.representatives, 2);
    assert_eq!(second.manifest.covered.sources, 3);
    let latest = read_generation(&f.native, &f.context, &mut budget())
        .dense_directory_router
        .expect("current router root");
    assert_eq!(
        f.native
            .publish_original_span_directory_router(&f.context, &first_request, &mut budget())
            .expect("exact historical retry"),
        first
    );
    assert_eq!(
        read_generation(&f.native, &f.context, &mut budget()).dense_directory_router,
        Some(latest.clone())
    );
    assert!(
        f.native
            .verify_native(true)
            .expect("all immutable routers reconstruct without overwriting latest head")
            .valid
    );
    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        DATABASE,
        TOKEN_KEY,
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual encrypted cold open");
    assert_eq!(
        cold.publish_original_span_directory_router(&f.context, &first_request, &mut budget())
            .expect("cold old retry"),
        first
    );
    assert_eq!(
        cold.publish_original_span_directory_router(&f.context, &second_request, &mut budget())
            .expect("cold latest retry"),
        second
    );
    assert_eq!(
        read_generation(&cold, &f.context, &mut budget()).dense_directory_router,
        Some(latest)
    );
    assert!(
        cold.verify_native(true)
            .expect("cold complete router acceptance")
            .valid
    );
}

#[test]
fn encrypted_router_limits_permissions_missing_fine_row_and_same_cutoff_corruption_refuse() {
    let f = fixture();
    base(&f);
    let request = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("target");
    let before = f
        .native
        .global_head(
            &f.native
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("head view"),
        )
        .expect("head");
    let mut denied = f.context.clone();
    denied
        .capability_grants
        .remove(&Capability::ModelProcessing);
    assert_eq!(
        f.native
            .publish_original_span_directory_router(&denied, &request, &mut budget())
            .expect_err("all operator capabilities precede reads")
            .code,
        ErrorCode::Unauthorized
    );
    let cancel = contextdb_recall::QueryCancellation::default();
    cancel.cancel();
    let mut cancelled = QueryBudget::new(
        20_000_000,
        1024 * 1024 * 1024,
        std::time::Duration::from_secs(60),
        cancel,
    );
    assert!(
        f.native
            .publish_original_span_directory_router(&f.context, &request, &mut cancelled)
            .is_err()
    );
    let mut tiny = QueryBudget::new(
        1,
        1,
        std::time::Duration::from_secs(60),
        contextdb_recall::QueryCancellation::default(),
    );
    assert!(
        f.native
            .publish_original_span_directory_router(&f.context, &request, &mut tiny)
            .is_err()
    );
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fine rows");
    let rows = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            &prefix_v2::types::prefix_key(&workspace, 1).expect("prefix"),
        )
        .expect("fine census");
    let missing = rows
        .iter()
        .find(|row| String::from_utf8_lossy(&row.key).contains("/node/"))
        .expect("actual fine node")
        .clone();
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("fault writer");
    tx.delete(&f.native.keyspaces.continuous, missing.key.clone())
        .expect("remove genuine fine node");
    tx.commit(Durability::Sync).expect("fault Sync");
    assert_eq!(
        f.native
            .publish_original_span_directory_router(&f.context, &request, &mut budget())
            .expect_err("incomplete fine topology cannot become router")
            .code,
        ErrorCode::IntegrityFailure
    );
    let mut tx = f.native.engine.begin_write().expect("restore writer");
    tx.put(&f.native.keyspaces.continuous, missing.key, missing.value)
        .expect("exact restore");
    tx.commit(Durability::Sync).expect("restore Sync");
    assert_eq!(
        f.native
            .global_head(
                &f.native
                    .engine
                    .begin_read(SnapshotSelector::Latest)
                    .expect("unchanged view")
            )
            .expect("unchanged head"),
        before
    );
    let receipt = f
        .native
        .publish_original_span_directory_router(&f.context, &request, &mut budget())
        .expect("whole fine path restored");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("binding view");
    let mut wrong = read_generation(&f.native, &f.context, &mut budget());
    assert_eq!(
        wrong.dense.as_ref().expect("dense").through,
        receipt.manifest.covered.through
    );
    wrong.dense.as_mut().expect("dense").commitment = ContentDigest::from_bytes([73; 32]);
    assert_eq!(
        f.native
            .check_directory_router_generation_binding(
                &snapshot,
                &workspace,
                &wrong,
                &receipt,
                &mut budget()
            )
            .expect_err("equal cutoff requires full manifest equality")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn encrypted_one_row_gc_keeps_router_root_and_shared_copy_acceptance_after_full_retirement() {
    let f = fixture();
    base(&f);
    seal(&f);
    let request = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("complete target");
    let receipt = f
        .native
        .publish_original_span_directory_router(&f.context, &request, &mut budget())
        .expect("real router acceptance");
    let old = read_generation(&f.native, &f.context, &mut budget());
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("saved copies");
    let all = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            generation_prefix(&workspace, 1).as_bytes(),
        )
        .expect("real generation rows");
    let saved: Vec<_> = all
        .iter()
        .filter(|row| {
            let key = String::from_utf8_lossy(&row.key);
            key.contains("/dense/directory-router-v1/")
                || key.ends_with("/dense/directory-routers-v1/head")
        })
        .cloned()
        .collect();
    assert!(!saved.is_empty());
    for row in &saved {
        f.native
            .verify_dense_directory_router_copy(
                &snapshot,
                &old,
                &row.key,
                &row.value,
                &mut budget(),
            )
            .expect("all router copies are authentic shared rows");
    }
    assert!(
        f.native
            .has_dense_graph_rows(&snapshot, &workspace, 1, &mut budget())
            .expect("derived rows block pruning")
    );
    drop(snapshot);
    let next = f
        .native
        .project_originals_bm25(&f.context, true, 64, &mut budget())
        .expect("real new generation");
    assert!(next.caught_up && next.generation == 2);
    let mut finished = false;
    let mut sibling_loss_seen = false;
    for _ in 0..=all.len() {
        let progress = f
            .native
            .reclaim_raw_generations(&f.context, 1, &mut budget())
            .expect("one-row actual copy-witness GC");
        assert!(progress.removed_rows <= 1 && progress.copies.is_some());
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("GC snapshot");
        let world = f
            .native
            .current_directory_router_heads(
                &snapshot,
                &f.context.request.workspace_id,
                &mut budget(),
            )
            .expect("current four-map owner");
        assert_eq!(
            world
                .directory_routers
                .as_ref()
                .expect("Some persists")
                .contains_key(&1),
            !progress.finished
        );
        let live = saved
            .iter()
            .filter(|row| {
                snapshot
                    .get(&f.native.keyspaces.continuous, &row.key)
                    .expect("point")
                    .is_some()
            })
            .count();
        sibling_loss_seen |= live > 0 && live < saved.len();
        // Production GC authenticates each removed row. All row kinds are also
        // checked before and after full GC; one saved copy suffices per partial
        // page to prove that missing live siblings do not become dependencies.
        let row = &saved[0];
        f.native
            .verify_dense_directory_router_copy(
                &snapshot,
                &old,
                &row.key,
                &row.value,
                &mut budget(),
            )
            .expect("saved shared copy needs no physical sibling");
        drop(snapshot);
        if progress.finished {
            finished = true;
            break;
        }
    }
    assert!(finished && sibling_loss_seen);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("full GC");
    for row in &saved {
        assert!(
            snapshot
                .get(&f.native.keyspaces.continuous, &row.key)
                .expect("removed row")
                .is_none()
        );
        f.native
            .verify_dense_directory_router_copy(
                &snapshot,
                &old,
                &row.key,
                &row.value,
                &mut budget(),
            )
            .expect("full GC retained shared copy acceptance");
    }
    assert!(
        !f.native
            .has_dense_graph_rows(&snapshot, &workspace, 1, &mut budget())
            .expect("all derived live rows gone")
    );
    drop(snapshot);
    assert_eq!(
        f.native
            .publish_original_span_directory_router(&f.context, &request, &mut budget())
            .expect("historical exact retry after full generation GC"),
        receipt
    );
    assert!(
        f.native
            .verify_native(true)
            .expect("all retained router declarations survive full GC")
            .valid
    );
}

#[derive(Debug)]
struct DirectionalEncoder<'a>(&'a prefix_v2::inputs::tests::Encoder);
impl TextEmbeddingAdapter for DirectionalEncoder<'_> {
    fn profile(&self) -> &TextEmbeddingProfile {
        self.0.profile()
    }
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText> {
        let mut result = self.0.embed(kind, text, parent)?;
        if text.contains("negative cancellation") {
            result.values[0] = -1.;
            parent
                .charge(result.values.len() as u64 + 1, 256)
                .map_err(budget_error)?;
            let mut hash = blake3::Hasher::new();
            for value in &result.values {
                hash.update(&value.to_le_bytes());
            }
            result.vector_digest = ContentDigest::from_bytes(*hash.finalize().as_bytes());
        }
        Ok(result)
    }
}

#[test]
fn genuine_controlled_vectors_mean_and_exact_zero_fallback_stay_shared_routing() {
    let f = fixture();
    base(&f);
    seal(&f);
    for (sequence, text) in [(90, "positive cancellation"), (91, "negative cancellation")] {
        let mut capture = crate::capture::tests::request(sequence, text);
        capture.context = f.context.clone();
        capture.event.source_version = Some(format!("actual-directional-control-{sequence}"));
        f.native
            .append_event(capture)
            .expect("actual permitted original");
    }
    f.native
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("real raw progress");
    let target = f
        .native
        .project_original_spans(
            &f.context,
            &DirectionalEncoder(&f.encoder),
            64,
            &mut budget(),
        )
        .expect("actual controlled positive/negative vector receipts");
    let previous = f
        .native
        .original_span_prefix_segment_head(&f.context, 1, &mut budget())
        .expect("previous fine head");
    f.native
        .seal_original_span_prefix_segment(
            &f.context,
            &PrefixSegmentSealRequestV2 {
                generation: 1,
                previous,
                target,
            },
            &mut budget(),
        )
        .expect("two genuine vectors in one fine cohort");
    let request = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("complete target");
    let receipt = f
        .native
        .publish_original_span_directory_router(&f.context, &request, &mut budget())
        .expect("actual mean and exact-zero fallback publication");
    assert_eq!(receipt.manifest.coverage_count, 3);
    assert_eq!(receipt.manifest.representatives, 3);
    assert_eq!(receipt.manifest.covered.spans, 4);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let generation = read_generation(&f.native, &f.context, &mut budget());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual router rows");
    let rows = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            &router_prefix(&workspace, 1, receipt.manifest.serial).expect("router prefix"),
        )
        .expect("actual canonical router rows");
    let mut means = 0;
    let mut fallbacks = 0;
    let mut count = 0;
    for row in &rows {
        f.native
            .verify_dense_directory_router_copy(
                &snapshot,
                &generation,
                &row.key,
                &row.value,
                &mut budget(),
            )
            .expect("routing rows have shared retained native proof");
        if !String::from_utf8_lossy(&row.key).contains("/member/") {
            continue;
        }
        let member: DirectoryRouterMemberV1 =
            decode(&row.value, "actual routing member").expect("member");
        count += member.contributors;
        match member.mode {
            DirectoryRouterCentroidModeV1::Mean => means += 1,
            DirectoryRouterCentroidModeV1::FirstContributor { .. } => {
                fallbacks += 1;
                assert_eq!(member.path.ordinal(), 2);
                assert_eq!(member.contributors, 2);
            }
        }
    }
    assert_eq!((means, fallbacks, count), (2, 1, 4));
    drop(snapshot);
    assert!(
        f.native
            .verify_native(true)
            .expect("actual zero-mean recipe independently reconstructs")
            .valid
    );
}

#[test]
fn complete_router_stream_includes_zero_node_intervals_and_ordinal_sixty_five() {
    let f = fixture();
    base(&f);
    seal(&f);
    let omitted = "x".repeat(64 * 1024 + 1);
    for ordinal in 2..=65_u64 {
        let text = if ordinal == 65 {
            "actual late original beyond the first sixty-four intervals"
        } else {
            &omitted
        };
        let mut capture = crate::capture::tests::request(200 + ordinal, text);
        capture.context = f.context.clone();
        capture.event.source_version = Some(format!("actual-router-ordinal-{ordinal}"));
        f.native
            .append_event(capture)
            .expect("real next original capture");
        f.native
            .project_originals_bm25(&f.context, false, 64, &mut budget())
            .expect("actual complete raw progress");
        seal(&f);
    }
    let request = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("all accepted ordinals target");
    assert_eq!(
        request
            .coverage
            .directory
            .as_ref()
            .expect("directory")
            .count,
        65
    );
    // Explicit finite OFFLINE test construction allowance; production query limits
    // and caller-owned maintenance budgets are unchanged.
    let mut complete = QueryBudget::new(
        250_000_000,
        8 * 1024 * 1024 * 1024,
        std::time::Duration::from_secs(180),
        contextdb_recall::QueryCancellation::default(),
    );
    let receipt = f
        .native
        .publish_original_span_directory_router(&f.context, &request, &mut complete)
        .expect("complete ALL directory or refusal; no ordinal prefix");
    assert_eq!(receipt.manifest.coverage_count, 66);
    assert_eq!(receipt.manifest.covered.sources, 67);
    assert_eq!(receipt.manifest.covered.spans, 3);
    assert_eq!(receipt.manifest.representatives, 3);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("complete coarse rows");
    let rows = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            &router_prefix(&workspace, 1, receipt.manifest.serial).expect("router namespace"),
        )
        .expect("actual built routing rows");
    let mut late = false;
    for row in rows {
        if String::from_utf8_lossy(&row.key).contains("/member/") {
            let member: DirectoryRouterMemberV1 =
                decode(&row.value, "actual complete member").expect("member");
            late |= member.path.ordinal() == 65;
            assert!(
                member.path.ordinal() == 0
                    || member.path.ordinal() == 1
                    || member.path.ordinal() == 65
            );
        }
    }
    assert!(
        late,
        "real later path represented; zero-node intervals only contribute coverage"
    );
}

#[test]
fn terminal_native_event_loss_and_router_only_rows_never_become_absence_evidence() {
    let f = fixture();
    base(&f);
    let request = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("base-only target");
    let receipt = f
        .native
        .publish_original_span_directory_router(&f.context, &request, &mut budget())
        .expect("actual router");
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault originals");
    let event_key = receipt.global_commit.to_be_bytes();
    let event = snapshot
        .get(&f.native.keyspaces.events, &event_key)
        .expect("event read")
        .expect("actual terminal event");
    let locator_key = retained_locator_key(&workspace, 1, 1).expect("retained locator key");
    let locator = snapshot
        .get(&f.native.keyspaces.idempotency, &locator_key)
        .expect("locator read")
        .expect("actual locator");
    let fine = snapshot
        .scan_prefix(
            &f.native.keyspaces.continuous,
            &prefix_v2::types::prefix_key(&workspace, 1).expect("fine prefix"),
        )
        .expect("actual fine rows");
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("fault transaction");
    tx.delete(&f.native.keyspaces.events, event_key.to_vec())
        .expect("remove terminal declaration");
    tx.delete(&f.native.keyspaces.idempotency, locator_key.clone())
        .expect("remove its locator");
    tx.commit(Durability::Sync).expect("fault Sync");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("terminal fault view");
    let error = f
        .native
        .directory_router_declarations(&snapshot, &mut budget())
        .expect_err("scanned prefix cannot hide actual higher global head");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
    assert!(error.message.contains("terminal native global event"));
    assert_eq!(
        f.native
            .global_head(&snapshot)
            .expect("unchanged global head"),
        receipt.global_commit
    );
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("exact restore");
    tx.put(&f.native.keyspaces.events, event_key.to_vec(), event)
        .expect("restore event");
    tx.put(&f.native.keyspaces.idempotency, locator_key, locator)
        .expect("restore locator");
    for row in &fine {
        tx.delete(&f.native.keyspaces.continuous, row.key.clone())
            .expect("temporarily leave router-derived rows only");
    }
    tx.commit(Durability::Sync)
        .expect("restore terminal and isolate router rows");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("only shared router topology remains");
    assert!(
        f.native
            .has_dense_graph_rows(&snapshot, &workspace, 1, &mut budget())
            .expect("router-only namespace prevents pruning")
    );
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("restore fine rows");
    for row in fine {
        tx.put(&f.native.keyspaces.continuous, row.key, row.value)
            .expect("exact fine restore");
    }
    tx.commit(Durability::Sync).expect("fine restore Sync");
    assert!(
        f.native
            .verify_native(true)
            .expect("whole native archive restored exactly")
            .valid
    );
}
