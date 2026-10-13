//! The host composite is explicit; configuration comparison grants no authority.
use super::*;
use contextdb_core::ModelCallId;
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
fn intent() -> OwnedHybridIntent {
    OwnedHybridIntent {
        call_id: ModelCallId::new(),
        request_event: ObservationId::new(),
        interaction_sequence: 1,
        attempt: 0,
        limits: limits(),
    }
}

#[test]
fn composite_selection_preserves_legacy_and_requires_installed_limits_and_full_profile() {
    let f = fixture();
    let installed = Arc::new(ControlledEncoder::new(b"installed-routed-profile"));
    assert!(
        NativePreparation::new(f.owner.clone())
            .owned_hybrid_preparer()
            .is_none()
    );
    assert!(
        NativePreparation::with_hybrid(f.owner.clone(), installed.clone())
            .owned_hybrid_preparer()
            .is_none()
    );
    let hook = NativePreparation::with_routed(f.owner.clone(), installed.clone(), limits());
    assert!(hook.owned_hybrid_preparer().is_some());
    hook.admit_composite_configuration(&intent(), installed.as_ref(), &mut budget())
        .expect("same installed configuration is eligible, without claiming source admission");
    let mut changed = intent();
    changed.limits.tail_vectors -= 1;
    assert_eq!(
        hook.admit_composite_configuration(&changed, installed.as_ref(), &mut budget())
            .expect_err("per-attempt limits cannot switch the installed profile")
            .code,
        ErrorCode::IntegrityFailure
    );
    let changed_profile = ControlledEncoder::new(b"different-runtime-artifacts");
    assert_eq!(
        hook.admit_composite_configuration(&intent(), &changed_profile, &mut budget())
            .expect_err("equal dimensions and family do not replace full profile equality")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(
        hook.admit_composite_configuration(
            &intent(),
            installed.as_ref(),
            &mut QueryBudget::new(0, 0, Duration::from_secs(10), Default::default()),
        )
        .expect_err("configuration proof cannot reset the caller allowance")
        .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(installed.calls.load(Ordering::SeqCst), 0);
    assert_eq!(changed_profile.calls.load(Ordering::SeqCst), 0);
}
