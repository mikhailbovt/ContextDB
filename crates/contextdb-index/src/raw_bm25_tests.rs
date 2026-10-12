use super::*;

#[test]
fn frequencies_preserve_legacy_unicode_spans_and_repeated_original_words() {
    let bytes = "🙂 İD=7319; id 7319 НЕ не cloud_data".as_bytes();
    let digest = ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes());
    let id = ObservationId::new();
    let analysis = analyze_raw_bm25_original(id, digest, bytes, |_, _| Ok(()))
        .expect("analysis")
        .expect("text");
    assert_eq!(
        analysis.lexical,
        RawLexicalDocument::from_original(id, digest, bytes)
            .expect("legacy")
            .expect("text")
    );
    assert_eq!(analysis.token_count, 7);
    assert_eq!(analysis.term_frequencies["7319"], 2);
    assert_eq!(analysis.term_frequencies["не"], 2);
    assert_eq!(analysis.term_frequencies["i\u{307}d"], 1);
    assert_eq!(
        analysis.term_frequencies.keys().collect::<Vec<_>>(),
        analysis.lexical.first_terms.keys().collect::<Vec<_>>()
    );
}

#[test]
fn allocation_refusal_never_returns_partial_frequency_statistics() {
    let bytes = "shared ".repeat(2000).into_bytes();
    let digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
    let mut calls = 0;
    let result = analyze_raw_bm25_original(ObservationId::new(), digest, &bytes, |_, _| {
        calls += 1;
        if calls == 3 {
            Err(IndexError::InvalidBudget)
        } else {
            Ok(())
        }
    });
    assert!(matches!(result, Err(IndexError::InvalidBudget)));
    assert_eq!(calls, 3);
}

#[test]
fn cooperative_work_refusal_stops_the_scan_before_full_source_analysis() {
    let bytes = "shared ".repeat(2000).into_bytes();
    let digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
    let mut remaining = bytes.len() as u64 + 1000;
    let mut admitted = 0;
    let result = analyze_raw_bm25_original(ObservationId::new(), digest, &bytes, |work, _| {
        remaining = remaining
            .checked_sub(work)
            .ok_or(IndexError::InvalidBudget)?;
        admitted += work;
        Ok(())
    });
    assert!(matches!(result, Err(IndexError::InvalidBudget)));
    assert!(admitted < (2 * bytes.len()) as u64);
}

#[test]
fn binary_and_changed_digest_never_become_frequency_statistics() {
    let bytes = [0xff, 0xfe];
    let digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
    assert!(
        analyze_raw_bm25_original(ObservationId::new(), digest, &bytes, |_, _| Ok(()))
            .expect("binary")
            .is_none()
    );
    assert!(
        analyze_raw_bm25_original(ObservationId::new(), digest, b"different", |_, _| Ok(()))
            .is_err()
    );
}

#[test]
fn repeated_tokens_do_not_reserve_map_nodes_for_every_occurrence() {
    let bytes = "alpha ".repeat(4096).into_bytes();
    let digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
    let ceiling = (bytes.len() * 6 + 4096) as u64;
    let mut reserved = 0_u64;
    let analysis =
        analyze_raw_bm25_original(ObservationId::new(), digest, &bytes, |_, allocation| {
            reserved += allocation;
            if reserved > ceiling {
                Err(IndexError::InvalidBudget)
            } else {
                Ok(())
            }
        })
        .expect("bounded temporary normalization and two map nodes")
        .expect("text");
    assert_eq!(analysis.token_count, 4096);
    assert_eq!(analysis.term_frequencies["alpha"], 4096);
    assert_eq!(analysis.lexical.first_terms.len(), 1);
}
