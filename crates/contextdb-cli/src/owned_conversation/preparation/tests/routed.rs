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
    let earlier = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("actual unchanged partial target");
    assert_eq!(
        super::super::routed::check_progress(&earlier, &earlier, &mut budget())
            .expect_err("identical genuine target cannot count as batch progress")
            .code,
        ErrorCode::ResourceExhausted
    );
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
    assert_eq!(
        super::super::routed::check_progress(&earlier, &status, &mut budget())
            .expect_err("genuine operator change cannot be adopted mid-hook")
            .code,
        ErrorCode::IntegrityFailure
    );
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
fn routed_hook_capacity_and_cancelled_parent_do_not_reset_allowances() {
    let (f, encoder) = ready();
    for sequence in 3..=6 {
        capture(&f, &f.owner, sequence);
    }
    let mut tight = limits();
    tight.tail_vectors = 64;
    let hook = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), tight);
    assert_eq!(
        hook.before_prepare(&f.context, &mut budget())
            .expect_err("remaining capacity cannot admit another worst-case whole source")
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

fn captured_work(f: &Fixture, sequence: u64, kind: EventKind, role: EventRole, text: String) {
    f.owner
        .append_event(CaptureRequest {
            context: f.context.clone(),
            idempotency_key: format!("routed/work/{sequence}"),
            event: EventEnvelope {
                version: EVENT_ENVELOPE_VERSION,
                event_id: ObservationId::new(),
                workspace_id: f.workspace,
                scope_ids: BTreeSet::from([f.scope]),
                producer_id: f.producer,
                producer_sequence: sequence,
                kind,
                recorded_at: TimestampMicros(1_000_000 + sequence as i64),
                observed_at: None,
                source_id: SourceId::new(),
                source_version: None,
                adapter_id: "observed-routed-hook-work".into(),
                role,
                session_id: None,
                run_id: None,
                task_id: None,
                parent_event_ids: BTreeSet::new(),
                supersedes_event_id: None,
                payload: EventPayload::InlineUtf8 {
                    digest: digest(text.as_bytes()),
                    text,
                },
                coverage: EventCoverage::CompleteObservation,
                upstream_truncated: false,
                gap_reason: None,
                response_stream: None,
                provenance: None,
            },
        })
        .expect("actual accepted observation, without invented owned-checkpoint authority");
}

#[test]
fn routed_hook_crosses_zero_vector_controls_with_the_actual_cli_parent() {
    let (f, encoder) = ready();
    for sequence in 3..=9 {
        captured_work(
            &f,
            sequence,
            EventKind::RunCancelled,
            EventRole::Host,
            format!("Observed cancellation control {sequence}"),
        );
    }
    capture(&f, &f.owner, 10);
    let before = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("genuine immutable graph controls before the pending work");
    let hook = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), limits());
    let mut parent = crate::owned_conversation::budget(Duration::from_secs(60));
    let outcome = hook.before_prepare(&f.context, &mut parent);
    eprintln!(
        "routed_hook_controls_production_cost work={} bytes={} error={:?}",
        2_000_000_u64.saturating_sub(parent.remaining_work()),
        (512_u64 * 1024 * 1024).saturating_sub(parent.remaining_bytes()),
        outcome.as_ref().err().map(|error| error.code)
    );
    outcome.expect("multiple <=4-work batches share the unchanged actual CLI allowance");
    let after = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("actual accepted progress after all control work");
    let dense = after.dense.as_ref().expect("actual current projection");
    assert!(dense.caught_up && after.dense_matches_raw);
    assert_eq!(dense.sources, 10);
    assert_eq!(dense.embedded_sources, 3);
    assert_eq!(dense.omitted_sources, 7);
    assert_eq!(encoder.calls.load(Ordering::SeqCst), 3);
    assert!(
        dense.global_commit
            >= before
                .dense
                .as_ref()
                .expect("earlier receipt")
                .global_commit
                + 3
    );
    assert_eq!(after.base, before.base);
    assert_eq!(after.directory_ref, before.directory_ref);
    assert_eq!(after.router, before.router);
    assert_eq!(after.covered, before.covered);
    verify(&f);
}

#[test]
fn routed_hook_high_span_tail_and_batch_count_refuse_without_extra_source_forwards() {
    let (f, encoder) = ready();
    captured_work(
        &f,
        3,
        EventKind::MessageCreated,
        EventRole::User,
        "a".repeat(32 * 1024),
    );
    f.owner
        .project_originals_bm25(&f.context, false, 64, &mut budget())
        .expect("genuine large source raw progress");
    let dense = f
        .owner
        .project_original_spans(&f.context, encoder.as_ref(), 64, &mut budget())
        .expect("explicit actual multi-span source projection");
    assert!(dense.spans > 16);
    capture(&f, &f.owner, 4);
    let calls = encoder.calls.load(Ordering::SeqCst);
    let mut tight = limits();
    tight.tail_vectors = 32;
    let hook = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), tight);
    assert_eq!(
        hook.before_prepare(&f.context, &mut budget())
            .expect_err("actual existing spans leave less than one64-span source allowance")
            .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(encoder.calls.load(Ordering::SeqCst), calls);
    verify(&f);

    let (f, encoder) = ready();
    for sequence in 3..=36 {
        captured_work(
            &f,
            sequence,
            EventKind::RunCancelled,
            EventRole::Host,
            format!("Observed bounded cancellation control {sequence}"),
        );
    }
    let hook = NativePreparation::with_routed(f.owner.clone(), encoder.clone(), limits());
    let mut parent = budget();
    let before = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("initial accepted projection");
    assert_eq!(
        hook.before_prepare(&f.context, &mut parent)
            .expect_err(
                "remaining control work requires explicit continuation after at most8 batches"
            )
            .code,
        ErrorCode::ResourceExhausted
    );
    let after = f
        .owner
        .original_span_routed_maintenance_target(&f.context, &mut budget())
        .expect("genuine accepted partial progress")
        .dense
        .expect("actual dense");
    assert!(!after.caught_up);
    assert_eq!(
        after.global_commit,
        before.known_at + 1 + u64::from(ROUTED_MAX_BATCHES),
        "this single-workspace fixture accepts one raw frame then at most8 dense frames"
    );
    assert_eq!(
        after.sources, 26,
        "four initial work rows then seven batches of3 after one actual vector"
    );
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        2,
        "no ninth batch or control-vector invention"
    );
    verify(&f);
}
