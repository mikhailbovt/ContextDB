//! Union discovery ranges before materializing an immutable original.

use super::*;
use contextdb_recall::IndexedHit;

const MAX_SOURCES: usize = 256;
const MAX_SOURCE_MATCHES: usize = 64;
const MAX_MATCHES: usize = 2048;

/// Route order preserves the existing routing prior. Another route cannot hide
/// a useful range by naming a source that an earlier route already discovered.
pub(super) fn union_raw_hits(
    batches: Vec<Vec<IndexedHit>>,
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<IndexedHit>> {
    let mut positions = BTreeMap::<contextdb_core::ObservationId, usize>::new();
    let mut hits: Vec<IndexedHit> = Vec::new();
    let mut match_count = 0_usize;
    for batch in batches {
        for mut hit in batch {
            budget.charge(1, 0).map_err(budget_error)?;
            if hit.matches.len() > MAX_SOURCE_MATCHES {
                return Err(super::super::exhausted(
                    "raw source match frontier exceeds its bound",
                ));
            }
            for span in &hit.matches {
                budget.charge(1, 0).map_err(budget_error)?;
                if span.event_id != hit.source.event_id
                    || Some(span.payload_digest) != hit.source.payload_digest
                    || span.start >= span.end
                    || hit
                        .source
                        .byte_length
                        .is_none_or(|length| span.end > length)
                    || span.span_digest == ContentDigest::from_bytes([0; 32])
                {
                    return Err(super::super::integrity(
                        "raw match differs from its immutable source",
                    ));
                }
            }
            let index = if let Some(index) = positions.get(&hit.source.event_id).copied() {
                if hits[index].source != hit.source {
                    return Err(super::super::integrity(
                        "discovery routes disagree on original version",
                    ));
                }
                index
            } else {
                if hits.len() == MAX_SOURCES {
                    return Err(super::super::exhausted(
                        "raw preparation frontier exceeds its limit",
                    ));
                }
                budget
                    .charge(
                        1,
                        (size_of::<IndexedHit>()
                            + size_of::<(contextdb_core::ObservationId, usize)>()
                            + 256) as u64,
                    )
                    .map_err(budget_error)?;
                let index = hits.len();
                positions.insert(hit.source.event_id, index);
                hits.push(IndexedHit {
                    source: hit.source,
                    matches: Vec::new(),
                });
                index
            };
            for span in hit.matches.drain(..) {
                let matches = &mut hits[index].matches;
                budget
                    .charge(matches.len() as u64 + 1, 0)
                    .map_err(budget_error)?;
                if let Some(existing) = matches
                    .iter()
                    .find(|existing| existing.start == span.start && existing.end == span.end)
                {
                    if existing != &span {
                        return Err(super::super::integrity(
                            "discovery routes disagree on exact original range",
                        ));
                    }
                    continue;
                }
                if matches.len() == MAX_SOURCE_MATCHES || match_count == MAX_MATCHES {
                    return Err(super::super::exhausted(
                        "raw preparation match frontier exceeds its bound",
                    ));
                }
                budget
                    .charge(1, size_of::<OriginalSourceSpan>() as u64 * 2)
                    .map_err(budget_error)?;
                matches.push(span);
                match_count += 1;
            }
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests;
