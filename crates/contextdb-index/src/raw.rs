//! Deterministic original-text analyzer shared by raw recall and its projections.

use std::collections::BTreeMap;

use contextdb_core::{ContentDigest, ObservationId, OriginalSourceSpan, RawTextQuery};
use serde::{Deserialize, Serialize};

use crate::{IndexError, Result};

/// Analyzer identity. Original bytes are never normalized or rewritten.
pub const RAW_ANALYZER: &str = "unicode-alnum-underscore-lowercase-v1";
/// Maximum encoded query before analysis.
pub const MAX_RAW_QUERY_BYTES: usize = 4096;
/// Maximum unique query terms.
pub const MAX_RAW_QUERY_TERMS: usize = 64;

/// One original UTF-8 byte range, before lowercase expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTokenSpan {
    pub start: u64,
    pub end: u64,
}

/// Ordered normalized terms with their first occurrence in one source.
///
/// This is a rebuildable representation, never the original or a fact. Keeping
/// one occurrence per term bounds repetitive-text amplification. Exact phrase
/// matching always checks the original bytes, not this projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLexicalDocument {
    pub analyzer: String,
    pub event_id: ObservationId,
    pub payload_digest: ContentDigest,
    pub byte_length: u64,
    pub first_terms: BTreeMap<String, RawTokenSpan>,
}

impl RawLexicalDocument {
    /// Build only after the caller has checked source authorization and byte budget.
    pub fn from_original(
        event_id: ObservationId,
        payload_digest: ContentDigest,
        bytes: &[u8],
    ) -> Result<Option<Self>> {
        if ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()) != payload_digest {
            return Err(IndexError::Invalid("raw original digest mismatch"));
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Ok(None);
        };
        let mut first_terms = BTreeMap::new();
        visit_tokens(text, |term, span| {
            first_terms.entry(term).or_insert(span);
        });
        Ok(Some(Self {
            analyzer: RAW_ANALYZER.into(),
            event_id,
            payload_digest,
            byte_length: bytes.len() as u64,
            first_terms,
        }))
    }
}

/// Validates query bounds and returns unique terms for a persistent posting route.
pub fn raw_query_terms(query: &RawTextQuery) -> Result<Vec<String>> {
    let text = match query {
        RawTextQuery::AllTerms(text) | RawTextQuery::ExactPhrase(text) => text,
    };
    if text.is_empty() || text.len() > MAX_RAW_QUERY_BYTES {
        return Err(IndexError::Invalid(
            "raw query is empty or exceeds its byte limit",
        ));
    }
    let mut terms = BTreeMap::new();
    visit_tokens(text, |term, _| {
        terms.insert(term, ());
    });
    if terms.len() > MAX_RAW_QUERY_TERMS
        || (terms.is_empty() && matches!(query, RawTextQuery::AllTerms(_)))
    {
        return Err(IndexError::Invalid("raw query term budget is invalid"));
    }
    Ok(terms.into_keys().collect())
}

/// Exact oracle. Returns at most one bound span per requested term, or one phrase.
pub fn match_raw_original(
    event_id: ObservationId,
    payload_digest: ContentDigest,
    bytes: &[u8],
    query: &RawTextQuery,
) -> Result<Option<Vec<OriginalSourceSpan>>> {
    let terms = raw_query_terms(query)?;
    if ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes()) != payload_digest {
        return Err(IndexError::Invalid("raw original digest mismatch"));
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(None);
    };
    let ranges = match query {
        RawTextQuery::ExactPhrase(phrase) => {
            let Some(start) = text.find(phrase.as_str()) else {
                return Ok(None);
            };
            vec![RawTokenSpan {
                start: start as u64,
                end: (start + phrase.len()) as u64,
            }]
        }
        RawTextQuery::AllTerms(_) => {
            let mut remaining = terms
                .into_iter()
                .map(|term| (term, None))
                .collect::<BTreeMap<_, _>>();
            visit_tokens(text, |term, span| {
                if let Some(found) = remaining.get_mut(&term) {
                    found.get_or_insert(span);
                }
            });
            let Some(ranges) = remaining.into_values().collect::<Option<Vec<_>>>() else {
                return Ok(None);
            };
            ranges
        }
    };
    let mut spans = ranges
        .into_iter()
        .map(|range| OriginalSourceSpan {
            event_id,
            payload_digest,
            start: range.start,
            end: range.end,
            span_digest: ContentDigest::from_bytes(
                *blake3::hash(&bytes[range.start as usize..range.end as usize]).as_bytes(),
            ),
        })
        .collect::<Vec<_>>();
    spans.sort_by_key(|span| (span.start, span.end));
    Ok(Some(spans))
}

fn visit_tokens(text: &str, mut visit: impl FnMut(String, RawTokenSpan)) {
    let mut start = None;
    for (offset, ch) in text
        .char_indices()
        .chain(std::iter::once((text.len(), '\0')))
    {
        if ch.is_alphanumeric() || ch == '_' {
            start.get_or_insert(offset);
        } else if let Some(from) = start.take() {
            visit(
                text[from..offset].to_lowercase(),
                RawTokenSpan {
                    start: from as u64,
                    end: offset as u64,
                },
            );
        }
    }
}

/// A whole interior token is a safe posting anchor for an exact substring.
/// Partial edge tokens are deliberately excluded; punctuation-only phrases use
/// a bounded metadata/range route instead of a false-negative word restriction.
#[must_use]
pub fn raw_phrase_anchor(phrase: &str) -> Option<String> {
    let mut anchor = None;
    visit_tokens(phrase, |term, span| {
        if anchor.is_none() && span.start > 0 && span.end < phrase.len() as u64 {
            anchor = Some(term);
        }
    });
    anchor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzer_keeps_original_unicode_offsets_and_exact_punctuation() {
        let bytes = "🙂 Не загружать cloud_data; İD=7319. e\u{301} / é".as_bytes();
        let digest = ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes());
        let id = ObservationId::new();
        let spans = match_raw_original(
            id,
            digest,
            bytes,
            &RawTextQuery::AllTerms("НЕ cloud_data İD 7319".into()),
        )
        .expect("match")
        .expect("found");
        let quotes = spans
            .iter()
            .map(|span| {
                std::str::from_utf8(&bytes[span.start as usize..span.end as usize]).expect("UTF-8")
            })
            .collect::<Vec<_>>();
        assert_eq!(quotes, ["Не", "cloud_data", "İD", "7319"]);
        let exact = match_raw_original(
            id,
            digest,
            bytes,
            &RawTextQuery::ExactPhrase("e\u{301} / é".into()),
        )
        .expect("exact")
        .expect("found");
        assert_eq!(
            &bytes[exact[0].start as usize..exact[0].end as usize],
            "e\u{301} / é".as_bytes()
        );
        assert!(
            match_raw_original(id, digest, bytes, &RawTextQuery::ExactPhrase("не".into()))
                .expect("case")
                .is_none()
        );
        let document = RawLexicalDocument::from_original(id, digest, bytes)
            .expect("projection")
            .expect("text");
        assert_eq!(document.first_terms["7319"].start, spans[3].start);
    }

    #[test]
    fn binary_omissions_and_invalid_queries_are_not_fabricated_text() {
        let bytes = [0xff, 0xfe];
        let digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
        assert!(
            RawLexicalDocument::from_original(ObservationId::new(), digest, &bytes)
                .expect("binary")
                .is_none()
        );
        assert!(raw_query_terms(&RawTextQuery::AllTerms("---".into())).is_err());
        assert!(
            raw_query_terms(&RawTextQuery::ExactPhrase("---".into()))
                .expect("punctuation")
                .is_empty()
        );
    }
}
