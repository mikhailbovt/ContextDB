use super::*;
use std::time::Duration;

fn budget() -> QueryBudget {
    QueryBudget::new(
        100_000,
        16 * 1024 * 1024,
        Duration::from_secs(5),
        Default::default(),
    )
}
fn hit(sequence: u64, start: u64) -> IndexedHit {
    let source = RawSource::from(&crate::assertions::tests::capture(sequence, "0123456789").event);
    let span = OriginalSourceSpan {
        event_id: source.event_id,
        payload_digest: source.payload_digest.expect("original digest"),
        start,
        end: start + 1,
        span_digest: ContentDigest::from_bytes([1; 32]),
    };
    IndexedHit {
        source,
        matches: vec![span],
    }
}

#[test]
fn repeated_source_preserves_both_route_ranges_and_deduplicates_exact_bytes() {
    let first = hit(1, 0);
    let mut other_range = first.clone();
    other_range.matches[0].start = 8;
    other_range.matches[0].end = 9;
    let second = hit(2, 2);
    let result = union_raw_hits(
        vec![
            vec![first.clone(), second.clone()],
            vec![other_range.clone(), first.clone()],
        ],
        &mut budget(),
    )
    .expect("union");
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].source, first.source);
    assert_eq!(
        result[0].matches,
        vec![first.matches[0].clone(), other_range.matches[0].clone()]
    );
    assert_eq!(result[1], second);
}

#[test]
fn conflicting_version_or_range_digest_discards_the_whole_frontier() {
    let first = hit(1, 0);
    let mut changed = first.clone();
    changed.source.source_version = Some("unaccepted replacement".into());
    assert_eq!(
        union_raw_hits(vec![vec![first.clone()], vec![changed]], &mut budget())
            .expect_err("version collision")
            .code,
        contextdb_service::ErrorCode::IntegrityFailure
    );
    let mut changed = first.clone();
    changed.matches[0].span_digest = ContentDigest::from_bytes([2; 32]);
    assert_eq!(
        union_raw_hits(vec![vec![first], vec![changed]], &mut budget())
            .expect_err("range collision")
            .code,
        contextdb_service::ErrorCode::IntegrityFailure
    );
}

#[test]
fn union_refuses_source_overflow_and_preserves_the_parent_allowance() {
    let inputs = (1..=257).map(|sequence| hit(sequence, 0)).collect();
    assert_eq!(
        union_raw_hits(vec![inputs], &mut budget())
            .expect_err("source bound")
            .code,
        contextdb_service::ErrorCode::ResourceExhausted
    );
    let mut allowance = QueryBudget::new(100_000, 0, Duration::from_secs(5), Default::default());
    assert_eq!(
        union_raw_hits(vec![vec![hit(1, 0)]], &mut allowance)
            .expect_err("no insertion allowance")
            .code,
        contextdb_service::ErrorCode::BudgetExhausted
    );
}
