use super::*;

fn usage(total: u64, cached: u64) -> ReaderUsage {
    ReaderUsage {
        input_tokens: Some(total),
        uncached_input_tokens: Some(total - cached),
        cache_read_tokens: Some(cached),
        cache_write_tokens: Some(0),
        output_tokens: Some(200),
        reasoning_tokens: Some(150),
        prefill_micros: None,
    }
}

#[test]
fn disjoint_usage_prices_failed_attempts_without_double_counting_reasoning() {
    let tariff = ReaderTariff {
        currency: "fixture-micro-units".into(),
        request_micros: 7,
        uncached_per_million_micros: 1_000_000,
        cache_write_per_million_micros: 2_000_000,
        cache_read_per_million_micros: 100_000,
        output_per_million_micros: 3_000_000,
    };
    assert_eq!(tariff.charge_micros(&ReaderUsage::default()), None);
    assert_eq!(tariff.charge_micros(&usage(1000, 900)), Some(797));
    let mut missing = usage(1000, 900);
    missing.cache_write_tokens = None;
    assert_eq!(tariff.charge_micros(&missing), None);
    let mut overlapping = usage(1000, 900);
    overlapping.uncached_input_tokens = Some(1000);
    assert!(overlapping.validate().is_err());
    assert_eq!(tariff.charge_micros(&overlapping), None);
    let mut excessive = usage(1000, 900);
    excessive.reasoning_tokens = Some(201);
    assert!(excessive.validate().is_err());
    let mut overflow = usage(u64::MAX, 0);
    overflow.cache_write_tokens = Some(u64::MAX);
    assert!(overflow.validate().is_err());
    // A smaller cold request can cost more than a larger cached summary request.
    assert!(
        tariff.charge_micros(&usage(8000, 0)).expect("cold")
            > tariff.charge_micros(&usage(30000, 27000)).expect("cached")
    );
}

#[test]
fn measured_residency_adapts_with_hysteresis_and_unknown_usage_resets_it() {
    let base = settings().rolling;
    let policy = CacheResidencyPolicy {
        high_tokens: 6000,
        enter_hit_bps: 8000,
        leave_hit_bps: 5000,
        min_observations: 2,
    };
    let adaptive = Some(policy);
    let mut controller = CacheResidencyController::default();
    assert_eq!(
        controller.select(base, adaptive, 27000).expect("initial").1,
        ResidencyReason::Unmeasured
    );
    controller.observe(&usage(1000, 950));
    controller.observe(&usage(1000, 900));
    let (sticky, reason) = controller.select(base, adaptive, 27000).expect("measured");
    assert_eq!(reason, ResidencyReason::MeasuredReuse);
    assert_eq!(sticky.high_tokens, 6000);
    assert_eq!(sticky.low_tokens, base.low_tokens);
    for _ in 0..4 {
        controller.observe(&usage(1000, 100));
    }
    assert_eq!(
        controller.select(base, adaptive, 27000).expect("miss").1,
        ResidencyReason::MeasuredMiss
    );
    controller.observe(&ReaderUsage::default());
    assert_eq!(
        controller.select(base, adaptive, 27000).expect("unknown").0,
        base
    );
    let invalid = Some(CacheResidencyPolicy {
        high_tokens: 27000,
        ..policy
    });
    assert!(controller.select(base, invalid, 27000).is_err());
}

#[test]
fn bounded_trace_reports_loss_and_never_turns_prefix_similarity_into_usage() {
    let mut telemetry = telemetry::Telemetry::resumed();
    let mut first = StepMeasurement::default();
    telemetry.wire(&vec![b'a'; 700], &mut first);
    assert_eq!(first.matching_prefix_floor_bytes, None);
    let mut changed = vec![b'a'; 700];
    changed[600] = b'b';
    let mut second = StepMeasurement::default();
    telemetry.wire(&changed, &mut second);
    assert_eq!(second.matching_prefix_floor_bytes, Some(512));
    assert_eq!(second.usage.cache_read_tokens, None);
    for _ in 0..70 {
        telemetry.push(second.clone());
    }
    let batch = telemetry.drain();
    assert_eq!(batch.steps.len(), 64);
    assert_eq!(batch.dropped_steps, 6);
    assert!(batch.prior_process_unmeasured);
    assert_eq!(telemetry.drain().dropped_steps, 6);
}
