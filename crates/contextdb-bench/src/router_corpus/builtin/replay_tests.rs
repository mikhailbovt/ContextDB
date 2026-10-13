use super::*;
use contextdb_context::router::{RouterHistoricalReplayResult, RouterReplayUnavailableReason};
use contextdb_context::{ReferenceOutgoingEncoder, ReferenceTokenizer};
use std::time::Duration;

fn allowance() -> QueryBudget {
    QueryBudget::new(
        20_000_000,
        2 * 1024 * 1024 * 1024,
        Duration::from_secs(40),
        Default::default(),
    )
}

#[test]
fn cold_replay_profile_runs_actual_r0_preserves_retry_and_feature_isolation() {
    let temp = tempfile::tempdir().expect("owned public synthetic fixture");
    let parent = fs::canonicalize(temp.path()).expect("canonical owned parent");
    let root = parent.join("replay");
    let built = write_builtin_router_replay_corpus(&root, &mut allowance())
        .expect("live preparation then detached R0 replay");
    assert_eq!(built.examples, 32);
    assert_eq!(built.known_labels, 104);
    assert_eq!(
        (built.train, built.validation, built.test, built.quarantined),
        (8, 8, 8, 8)
    );
    assert!(built.historical_selection.starts_with("verified:"));
    assert!(!built.trained_router);
    assert!(built.current_source_wire.starts_with("unavailable:"));
    let manifest = fs::read(root.join(MANIFEST)).expect("completion bytes");
    assert_eq!(
        built,
        verify_builtin_router_replay_corpus(&root, &mut allowance()).expect("cold R0 execution")
    );
    assert_eq!(
        built,
        write_builtin_router_replay_corpus(&root, &mut allowance()).expect("completed retry")
    );
    assert_eq!(
        manifest,
        fs::read(root.join(MANIFEST)).expect("unchanged manifest")
    );
    assert!(verify_builtin_router_corpus(&root, &mut allowance()).is_err());

    let inputs: Vec<RouterQueryTimeRecord> = decode(
        &fs::read(root.join(FILES[0])).expect("query-time"),
        MAX_ROUTER_EXAMPLE_BYTES,
        &mut allowance(),
    )
    .expect("canonical frozen preparation");
    let mut behavior: Vec<RouterBehaviorRecord> = decode(
        &fs::read(root.join(FILES[2])).expect("behavior"),
        MAX_ROUTER_EXAMPLE_BYTES,
        &mut allowance(),
    )
    .expect("canonical observed attempts");
    let features = build_router_features(&inputs[0], &mut allowance()).expect("features");
    behavior[0]
        .replay_observation
        .as_mut()
        .expect("actual observation")
        .attempts
        .clear();
    assert_eq!(
        features,
        build_router_features(&inputs[0], &mut allowance()).expect("independent features")
    );
    assert!(
        replay_router_behavior(
            &inputs[0],
            &behavior[0],
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &mut allowance(),
        )
        .is_err()
    );
    behavior[0].replay_observation = None;
    assert!(matches!(
        replay_router_behavior(
            &inputs[0],
            &behavior[0],
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &mut allowance(),
        )
        .expect("truthful missing observation"),
        RouterHistoricalReplayResult::Unavailable(
            RouterReplayUnavailableReason::MissingReplayObservation
        )
    ));
}
