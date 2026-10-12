use super::*;
use contextdb_core::{ContentDigest, OriginalSourceSpan};
use contextdb_recall::QueryCancellation;
use contextdb_service::ErrorCode;
use std::time::Duration;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        32 * 1024 * 1024,
        Duration::from_secs(5),
        Default::default(),
    )
}
fn hit(sequence: u64, start: u64) -> IndexedHit {
    let source = RawSource::from(&crate::assertions::tests::capture(sequence, "0123456789").event);
    IndexedHit {
        matches: vec![OriginalSourceSpan {
            event_id: source.event_id,
            payload_digest: source.payload_digest.expect("digest"),
            start,
            end: start + 1,
            span_digest: ContentDigest::from_bytes([1; 32]),
        }],
        source,
    }
}
fn route(route: SourceRoute, hits: Vec<IndexedHit>) -> SourceRouteInput {
    let admitted_sources = hits
        .iter()
        .map(|hit| (hit.source.event_id, hit.source.clone()))
        .collect();
    SourceRouteInput {
        route,
        hits,
        admitted_sources,
    }
}

#[test]
fn repeated_ranges_receive_one_source_vote_and_keep_complementary_matches() {
    let first = hit(1, 0);
    let late = hit(1, 8);
    let second = hit(2, 1);
    let result = fuse_sources(
        vec![
            route(
                SourceRoute::Bm25,
                vec![first.clone(), late.clone(), second.clone()],
            ),
            route(SourceRoute::Dense, vec![second.clone(), late.clone()]),
        ],
        20,
        &mut budget(),
    )
    .expect("fusion");
    assert_eq!(result.revision, SOURCE_RRF_REVISION);
    assert_eq!(result.selected.len(), 2);
    let one = result
        .selected
        .iter()
        .find(|x| x.hit.source.event_id == first.source.event_id)
        .expect("first");
    assert_eq!(one.routing_micros, 1_000_000 / 61 + 1_000_000 / 62);
    assert_eq!(
        one.hit.matches,
        vec![first.matches[0].clone(), late.matches[0].clone()]
    );
    let two = result
        .selected
        .iter()
        .find(|x| x.hit.source.event_id == second.source.event_id)
        .expect("second");
    assert_eq!(two.routing_micros, one.routing_micros);
    assert_eq!(
        two.route_ranks,
        vec![
            SourceRouteRank {
                route: SourceRoute::Bm25,
                rank: 2
            },
            SourceRouteRank {
                route: SourceRoute::Dense,
                rank: 1
            }
        ]
    );
    let expected_first = first.source.event_id.min(second.source.event_id);
    assert_eq!(result.selected[0].hit.source.event_id, expected_first);
}

#[test]
fn complementary_routes_beat_single_route_and_preserve_unranked_frontier() {
    let isolated = hit(1, 0);
    let both = hit(2, 1);
    let omitted = hit(3, 2).source;
    let mut lexical = route(SourceRoute::Bm25, vec![isolated, both.clone()]);
    lexical
        .admitted_sources
        .insert(omitted.event_id, omitted.clone());
    let result = fuse_sources(
        vec![lexical, route(SourceRoute::Dense, vec![both.clone()])],
        20,
        &mut budget(),
    )
    .expect("fusion");
    assert_eq!(result.selected[0].hit.source.event_id, both.source.event_id);
    assert_eq!(
        result.admitted_sources.get(&omitted.event_id),
        Some(&omitted)
    );
}

#[test]
fn final_cap_does_not_remove_inspected_sources_or_make_input_order_a_tie_breaker() {
    let hits: Vec<_> = (1..=25).map(|id| hit(id, 0)).collect();
    let first = fuse_sources(
        vec![
            route(SourceRoute::Bm25, hits.clone()),
            route(SourceRoute::Causal, hits.iter().rev().cloned().collect()),
        ],
        20,
        &mut budget(),
    )
    .expect("first");
    let second = fuse_sources(
        vec![
            route(SourceRoute::Causal, hits.iter().rev().cloned().collect()),
            route(SourceRoute::Bm25, hits),
        ],
        20,
        &mut budget(),
    )
    .expect("second");
    assert!(first.ranked_out);
    assert_eq!(first.selected.len(), 20);
    assert_eq!(first.admitted_sources.len(), 25);
    assert_eq!(
        first
            .selected
            .iter()
            .map(|x| x.hit.source.event_id)
            .collect::<Vec<_>>(),
        second
            .selected
            .iter()
            .map(|x| x.hit.source.event_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn version_span_and_admission_collisions_refuse_fusion() {
    let first = hit(1, 0);
    let mut changed = first.clone();
    changed.source.source_version = Some("another version".into());
    assert_eq!(
        fuse_sources(
            vec![
                route(SourceRoute::Bm25, vec![first.clone()]),
                route(SourceRoute::Dense, vec![changed])
            ],
            20,
            &mut budget()
        )
        .expect_err("version")
        .code,
        ErrorCode::IntegrityFailure
    );
    let mut changed = first.clone();
    changed.matches[0].span_digest = ContentDigest::from_bytes([2; 32]);
    assert_eq!(
        fuse_sources(
            vec![
                route(SourceRoute::Bm25, vec![first.clone()]),
                route(SourceRoute::Dense, vec![changed])
            ],
            20,
            &mut budget()
        )
        .expect_err("range")
        .code,
        ErrorCode::IntegrityFailure
    );
    let mut absent = route(SourceRoute::Bm25, vec![first]);
    absent.admitted_sources.clear();
    assert_eq!(
        fuse_sources(vec![absent], 20, &mut budget())
            .expect_err("admission")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn route_bounds_cancellation_and_parent_allocation_allowance_are_not_reset() {
    assert_eq!(
        fuse_sources(Vec::new(), 19, &mut budget())
            .expect_err("limit")
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        fuse_sources(
            vec![
                route(SourceRoute::Bm25, Vec::new()),
                route(SourceRoute::Bm25, Vec::new())
            ],
            20,
            &mut budget()
        )
        .expect_err("duplicate route")
        .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        fuse_sources(
            vec![route(
                SourceRoute::Bm25,
                (1..=257).map(|id| hit(id, 0)).collect()
            )],
            20,
            &mut budget()
        )
        .expect_err("ceiling")
        .code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        fuse_sources(
            vec![
                route(SourceRoute::Bm25, (1..=256).map(|id| hit(id, 0)).collect()),
                route(
                    SourceRoute::Dense,
                    (257..=512).map(|id| hit(id, 0)).collect()
                )
            ],
            20,
            &mut budget()
        )
        .expect_err("full frontier cap precedes second route votes")
        .code,
        ErrorCode::ResourceExhausted
    );
    let mut no_bytes = QueryBudget::new(1000, 0, Duration::from_secs(5), Default::default());
    assert_eq!(
        fuse_sources(
            vec![route(SourceRoute::Bm25, vec![hit(1, 0)])],
            20,
            &mut no_bytes
        )
        .expect_err("bytes")
        .code,
        ErrorCode::BudgetExhausted
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(1000, 1024, Duration::from_secs(5), cancellation);
    assert_eq!(
        fuse_sources(Vec::new(), 20, &mut cancelled)
            .expect_err("cancelled")
            .code,
        ErrorCode::BudgetExhausted
    );
}
