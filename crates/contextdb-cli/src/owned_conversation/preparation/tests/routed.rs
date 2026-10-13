//! Genuine prefix/router controls precede any automatic source callback.
use super::*;
use contextdb_native_service::{DensePrefixBaseRequestV2, PrefixSegmentSealRequestV2};
use contextdb_service::OwnedRoutedLimits;

fn limits() -> OwnedHybridLimits {
    OwnedHybridLimits {
        routed: Some(OwnedRoutedLimits {
            max_fine_paths: 8,
            coarse_node_reads: 64,
            coarse_vector_reads: 64,
            coarse_discovered: 64,
            coarse_ef_search: 32,
        }),
        ..Default::default()
    }
}
fn ready() -> (Fixture, Arc<ControlledEncoder>) {
    let f = fixture();
    capture(&f, &f.owner, 1);
    capture(&f, &f.owner, 2);
    f.owner
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("actual full raw archive");
    let encoder = Arc::new(ControlledEncoder::new(b"controlled-routed-hook-profile"));
    let target = f
        .owner
        .project_original_spans(&f.context, encoder.as_ref(), 1, &mut budget())
        .expect("genuine partial dense receipt");
    assert!(!target.caught_up);
    f.owner
        .publish_original_span_prefix_base(
            &f.context,
            &DensePrefixBaseRequestV2 {
                generation: target.generation,
                target,
            },
            &mut budget(),
        )
        .expect("actual prefix base");
    let request = f
        .owner
        .original_span_directory_router_target(&f.context, 1, &mut budget())
        .expect("actual base-only target");
    f.owner
        .publish_original_span_directory_router(&f.context, &request, &mut budget())
        .expect("actual complete router");
    (f, encoder)
}

#[test]
fn routed_hook_projects_one_capacity_bounded_batch_and_keeps_all_graph_roots() {
    let (f, encoder) = ready();
    let before = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("authenticated current status");
    let hook = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), limits());
    let mut production_parent = crate::owned_conversation::budget(Duration::from_secs(60));
    let outcome = hook.before_prepare(&f.context, &mut production_parent);
    eprintln!(
        "routed_hook_production_cost work={} bytes={} error={:?}",
        2_000_000_u64.saturating_sub(production_parent.remaining_work()),
        (512_u64 * 1024 * 1024).saturating_sub(production_parent.remaining_bytes()),
        outcome.as_ref().err().map(|error| error.code)
    );
    outcome.expect("one genuine source batch under the ACTUAL2M/512MiB CLI step allowance");
    let after = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("current accepted status");
    assert!(after.dense_matches_raw && after.dense.as_ref().expect("dense").caught_up);
    assert_eq!(encoder.calls.load(Ordering::SeqCst), 2);
    assert_eq!(after.base, before.base);
    assert_eq!(after.directory_ref, before.directory_ref);
    assert_eq!(after.router, before.router);
    assert_eq!(after.covered, before.covered);
    hook.before_prepare(&f.context, &mut budget())
        .expect("caught-up status is checked without repeat inference");
    assert_eq!(encoder.calls.load(Ordering::SeqCst), 2);
    capture(&f, &f.owner, 3);
    hook.before_prepare(&f.context, &mut budget())
        .expect("later source advances only the fresh prefix");
    assert_eq!(encoder.calls.load(Ordering::SeqCst), 3);
    verify(&f);
}

#[test]
fn routed_hook_refuses_missing_base_zero_capacity_stale_router_and_changed_profile() {
    let f = fixture();
    capture(&f, &f.owner, 1);
    let encoder = Arc::new(ControlledEncoder::new(b"controlled-routed-hook-profile"));
    let missing = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), limits());
    assert_eq!(
        missing
            .before_prepare(&f.context, &mut budget())
            .expect_err("explicit base/router maintenance required")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(encoder.calls.load(Ordering::SeqCst), 0);
    verify(&f);
    let (f, encoder) = ready();
    let baseline = encoder.calls.load(Ordering::SeqCst);
    let mut small = limits();
    small.tail_vectors = 63;
    let no_capacity = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), small);
    assert_eq!(
        no_capacity
            .before_prepare(&f.context, &mut budget())
            .expect_err("one complete source could require64 spans")
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(encoder.calls.load(Ordering::SeqCst), baseline);
    let changed = Arc::new(ControlledEncoder::new(b"another-real-controlled-profile"));
    let wrong = NativePreparation::with_routed(f.owner.clone(), changed.clone(), limits());
    assert_eq!(
        wrong
            .before_prepare(&f.context, &mut budget())
            .expect_err("full encoder profile must match before any source forwarding")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(changed.calls.load(Ordering::SeqCst), 0);
    let target = f
        .owner
        .project_original_spans(&f.context, encoder.as_ref(), 64, &mut budget())
        .expect("explicit actual dense progress");
    let previous = f
        .owner
        .original_span_prefix_segment_head(&f.context, 1, &mut budget())
        .expect("genuine predecessor");
    f.owner
        .seal_original_span_prefix_segment(
            &f.context,
            &PrefixSegmentSealRequestV2 {
                generation: 1,
                previous,
                target,
            },
            &mut budget(),
        )
        .expect("explicit accepted fine append");
    let status = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("legitimate stale router remains observable");
    assert!(!status.router_matches_directory);
    let calls = encoder.calls.load(Ordering::SeqCst);
    let stale = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), limits());
    assert_eq!(
        stale
            .before_prepare(&f.context, &mut budget())
            .expect_err("caught-up dense never bypasses stale router")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(encoder.calls.load(Ordering::SeqCst), calls);
    verify(&f);
}

#[test]
fn routed_hook_partial_single_batch_and_cancelled_parent_do_not_reset_allowances() {
    let (f, encoder) = ready();
    for sequence in 3..=6 {
        capture(&f, &f.owner, sequence);
    }
    let mut tight = limits();
    tight.tail_vectors = 64;
    let hook = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), tight);
    assert_eq!(
        hook.before_prepare(&f.context, &mut budget())
            .expect_err("single admitted source batch leaves explicit remaining lag")
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        2,
        "one new source callback, no 64-event loop"
    );
    let status = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("actual durable partial progress");
    assert!(
        !status
            .dense
            .as_ref()
            .expect("actual partial receipt")
            .caught_up
            && status.dense_matches_raw
    );
    let calls = encoder.calls.load(Ordering::SeqCst);
    let cancel = contextdb_recall::QueryCancellation::default();
    cancel.cancel();
    let mut parent = QueryBudget::new(
        20_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(60),
        cancel,
    );
    assert_eq!(
        hook.before_prepare(&f.context, &mut parent)
            .expect_err("parent cancellation remains shared")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(encoder.calls.load(Ordering::SeqCst), calls);
    verify(&f);
}
