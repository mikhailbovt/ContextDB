//! Real encrypted target observations; no model or retrieval-quality fixture.

use super::*;
use crate::raw_index::dense::graph::prefix_v2::inputs::tests::{
    DATABASE, Fixture, TOKEN_KEY, budget, fixture, read_generation,
};
use crate::raw_index::dense::{
    document_key as source_document_key, vector_key as source_vector_key,
};
use contextdb_recall::QueryCancellation;
use contextdb_service::ErrorCode;
use contextdb_storage::{Durability, WriteTransaction};
use std::time::Duration;

fn status(f: &Fixture) -> NativeRoutedMaintenanceTarget {
    f.native
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("actual authenticated current target")
}

fn base(f: &Fixture) -> prefix_types::DensePrefixBaseReceiptV2 {
    f.native
        .publish_original_span_prefix_base(
            &f.context,
            &prefix_types::DensePrefixBaseRequestV2 {
                generation: f.target.generation,
                target: f.target.clone(),
            },
            &mut budget(),
        )
        .expect("actual accepted partial base")
}

fn router(f: &Fixture) -> DirectoryRouterReceiptV1 {
    let target = f
        .native
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("actual complete fine target");
    f.native
        .publish_original_span_directory_router(&f.context, &target, &mut budget())
        .expect("accepted current router")
}

#[test]
fn raw_only_and_partial_dense_targets_do_not_invent_a_base() {
    let f = fixture();
    let first = status(&f);
    assert_eq!(first.generation, 1);
    assert_eq!(first.raw_sources, 3);
    assert_eq!(first.dense, Some(f.target.clone()));
    assert!(first.dense_matches_raw);
    assert!(first.base.is_none() && first.directory.is_none());
    assert!(first.covered.is_none() && first.router.is_none());
    assert!(!first.router_matches_directory);

    let raw = f
        .native
        .project_originals_bm25(&f.context, true, 64, &mut budget())
        .expect("actual replacement raw generation, with no Dense projection");
    assert!(raw.caught_up && raw.generation == 2);
    let current = status(&f);
    assert_eq!(current.generation, raw.generation);
    assert_eq!(current.raw_through, raw.through);
    assert_eq!(current.raw_sources, raw.projected_sources);
    assert!(current.dense.is_none() && current.base.is_none());
    assert!(current.directory.is_none() && current.directory_ref.is_none());
    assert!(current.covered.is_none() && current.router.is_none());
    assert!(!current.dense_matches_raw && !current.router_matches_directory);
    let encoded = serde_json::to_value(&current).expect("bounded response");
    for field in [
        "dense",
        "base",
        "directory",
        "directory_ref",
        "covered",
        "router",
    ] {
        assert!(
            encoded.get(field).is_none(),
            "{field} absence stays omitted"
        );
    }
}

#[test]
fn accepted_base_fresh_progress_stale_router_and_cold_current_directory_are_distinct() {
    let f = fixture();
    let accepted_base = base(&f);
    let before_router = status(&f);
    assert_eq!(before_router.base, Some(accepted_base.clone()));
    assert_eq!(before_router.covered, Some(f.target.clone()));
    assert!(!before_router.router_matches_directory);

    let first_router = router(&f);
    let base_only = status(&f);
    assert_eq!(base_only.router, Some(first_router.clone()));
    assert!(base_only.router_matches_directory);
    assert!(base_only.directory_ref.is_none());

    let target = f
        .native
        .project_original_spans(&f.context, &f.encoder, 4, &mut budget())
        .expect("accepted genuine fresh whole source");
    let pending = status(&f);
    assert_eq!(pending.dense, Some(target.clone()));
    assert_eq!(pending.covered, Some(f.target.clone()));
    assert_eq!(pending.router, Some(first_router.clone()));
    assert!(pending.router_matches_directory);
    assert!(
        pending.dense.as_ref().expect("Dense").sources
            > pending.covered.as_ref().expect("covered").sources
    );
    let interval = f
        .native
        .seal_original_span_prefix_segment(
            &f.context,
            &interval_types::PrefixSegmentSealRequestV2 {
                generation: 1,
                previous: pending.directory_ref,
                target: target.clone(),
            },
            &mut budget(),
        )
        .expect("actual pending interval sealed without another projection");
    let stale = status(&f);
    assert_eq!(stale.directory, Some(interval.directory.clone()));
    assert!(stale.directory_ref.is_some());
    assert_eq!(stale.covered, Some(target.clone()));
    assert_eq!(stale.router, Some(first_router));
    assert!(!stale.router_matches_directory);
    let second_router = router(&f);
    let current = status(&f);
    assert_eq!(current.router, Some(second_router));
    assert!(current.router_matches_directory);

    drop(f.native);
    let cold = NativeService::open_encrypted(
        f.root.path().join("native"),
        DATABASE,
        TOKEN_KEY,
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual cold native owner");
    assert_eq!(
        cold.original_span_routed_maintenance_target(&f.context, &mut budget())
            .expect("cold accepted targets"),
        current
    );
}

#[test]
fn tracked_missing_base_and_stripped_root_refuse_instead_of_reporting_absence() {
    for strip_root in [false, true] {
        let f = fixture();
        base(&f);
        let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
        let mut tx = f.native.engine.begin_write().expect("fault transaction");
        if strip_root {
            let mut generation = read_generation(&f.native, &f.context, &mut budget());
            generation.dense_prefix_base = None;
            tx.put(
                &f.native.keyspaces.continuous,
                generation_key(&workspace, 1),
                encode(&generation).expect("observed generation fault"),
            )
            .expect("strip tracked generation root");
        } else {
            tx.delete(
                &f.native.keyspaces.continuous,
                prefix_types::receipt_key(&workspace, 1).expect("canonical base key"),
            )
            .expect("remove tracked live base");
        }
        tx.commit(Durability::Sync).expect("durable fault");
        assert_eq!(
            f.native
                .original_span_routed_maintenance_target(&f.context, &mut budget())
                .expect_err("accepted target cannot disappear")
                .code,
            ErrorCode::IntegrityFailure
        );
    }
}

#[test]
fn coherent_old_generation_and_dense_receipt_replay_fails_native_recency() {
    let f = fixture();
    base(&f);
    router(&f);
    let old_generation = read_generation(&f.native, &f.context, &mut budget());
    let old_receipt = f.target.clone();
    let latest = f
        .native
        .project_original_spans(&f.context, &f.encoder, 4, &mut budget())
        .expect("new legitimate Dense acceptance");
    assert!(latest.sources > old_receipt.sources);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let mut tx = f.native.engine.begin_write().expect("replay transaction");
    tx.put(
        &f.native.keyspaces.continuous,
        generation_key(&workspace, 1),
        encode(&old_generation).expect("actual saved old generation"),
    )
    .expect("coherent old generation replay");
    tx.put(
        &f.native.keyspaces.continuous,
        dense::receipt_key(&workspace, 1),
        encode(&old_receipt).expect("actual old receipt"),
    )
    .expect("coherent valid old live receipt replay");
    tx.commit(Durability::Sync).expect("durable replay");
    assert_eq!(
        f.native
            .original_span_routed_maintenance_target(&f.context, &mut budget())
            .expect_err("current suffix contains the newer accepted Dense")
            .code,
        ErrorCode::IndexTooStale
    );
}

#[test]
fn status_reads_control_targets_without_dense_document_or_vector_rows() {
    let f = fixture();
    base(&f);
    router(&f);
    let before = status(&f);
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let mut tx = f
        .native
        .engine
        .begin_write()
        .expect("source-row fault transaction");
    tx.delete(
        &f.native.keyspaces.continuous,
        source_document_key(&workspace, 1, f.sources[0]),
    )
    .expect("remove current Dense document control");
    tx.delete(
        &f.native.keyspaces.continuous,
        source_vector_key(&workspace, 1, f.sources[0], 0),
    )
    .expect("remove actual source vector");
    tx.commit(Durability::Sync)
        .expect("durable missing source rows");
    // Coverage matches metadata; this observation intentionally makes no claim
    // that the original/vector rows exist or that a serving read will succeed.
    assert_eq!(status(&f), before);
}

#[test]
fn stale_router_ending_requires_its_own_real_capture_acceptance() {
    use contextdb_service::CapturePort;

    let f = fixture();
    let accepted_base = base(&f);
    let first = f
        .native
        .project_original_spans(&f.context, &f.encoder, 4, &mut budget())
        .expect("project the genuine original after the base");
    let mut interval = f
        .native
        .seal_original_span_prefix_segment(
            &f.context,
            &interval_types::PrefixSegmentSealRequestV2 {
                generation: 1,
                previous: None,
                target: first,
            },
            &mut budget(),
        )
        .expect("first actual fine interval");
    let old_router = router(&f);
    for sequence in 4..=5 {
        let mut request = crate::capture::tests::request(sequence, "later real fine endpoint");
        request.context = f.context.clone();
        request.event.source_version = Some(format!("status-ending-original-{sequence}"));
        f.native
            .append_event(request)
            .expect("actual later capture");
        f.native
            .project_originals_bm25(&f.context, false, 64, &mut budget())
            .expect("actual full raw progress");
        let target = f
            .native
            .project_original_spans(&f.context, &f.encoder, 4, &mut budget())
            .expect("actual later Dense target");
        let previous = f
            .native
            .original_span_prefix_segment_head(&f.context, 1, &mut budget())
            .expect("actual current fine predecessor");
        interval = f
            .native
            .seal_original_span_prefix_segment(
                &f.context,
                &interval_types::PrefixSegmentSealRequestV2 {
                    generation: 1,
                    previous,
                    target,
                },
                &mut budget(),
            )
            .expect("actual next fine interval");
    }
    let before = status(&f);
    assert!(!before.router_matches_directory);
    assert_eq!(before.router.as_ref(), Some(&old_router));
    assert_eq!(before.directory.as_ref(), Some(&interval.directory));
    let old_ending = &old_router.manifest.ending;
    assert_ne!(old_ending, &interval.delta.manifest.start);
    assert_ne!(old_ending, &interval.directory.head.ending);
    assert!(old_ending.work.workspace_commit > accepted_base.manifest.prefix.through);
    assert_eq!(old_ending.work.event_id, f.sources[2]);

    let key = old_ending.global_commit.to_be_bytes();
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("exact actual old endpoint event");
    let original = snapshot
        .get(&f.native.keyspaces.events, &key)
        .expect("read accepted event")
        .expect("accepted endpoint remains present");
    drop(snapshot);
    let mut tx = f.native.engine.begin_write().expect("endpoint fault");
    tx.delete(&f.native.keyspaces.events, key.to_vec())
        .expect("remove only the actual old endpoint event");
    tx.commit(Durability::Sync).expect("durable endpoint fault");
    let outcome = f
        .native
        .original_span_routed_maintenance_target(&f.context, &mut budget());

    let mut tx = f.native.engine.begin_write().expect("restore endpoint");
    tx.put(&f.native.keyspaces.events, key.to_vec(), original)
        .expect("restore exact accepted bytes");
    tx.commit(Durability::Sync).expect("durable restoration");
    assert_eq!(
        outcome
            .expect_err("a current ending proof cannot admit a stale router endpoint")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(status(&f), before);
    f.native
        .verify_native(true)
        .expect("restored native deep proof");
}

#[test]
fn status_requires_operator_processing_capability_and_the_same_parent() {
    let f = fixture();
    let mut denied = f.context.clone();
    denied
        .capability_grants
        .remove(&Capability::ModelProcessing);
    denied
        .validate_authentication()
        .expect("fixture channel remains authenticated");
    let error = f
        .native
        .original_span_routed_maintenance_target(&denied, &mut budget())
        .expect_err("authenticated channel still requires a processing grant");
    assert_eq!(error.code, ErrorCode::Unauthorized);
    assert!(error.message.contains("required capability is absent"));

    let mut tiny = QueryBudget::new(1, 1, Duration::from_secs(30), QueryCancellation::default());
    assert_eq!(
        f.native
            .original_span_routed_maintenance_target(&f.context, &mut tiny)
            .expect_err("no replacement allowance")
            .code,
        ErrorCode::BudgetExhausted
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        20_000_000,
        1024 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    let error = f
        .native
        .original_span_routed_maintenance_target(&f.context, &mut cancelled)
        .expect_err("sticky cancellation");
    assert_eq!(error.code, ErrorCode::BudgetExhausted);
    assert!(error.message.contains("cancelled"));
}
