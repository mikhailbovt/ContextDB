//! Bounded source context around lexical matches, retaining exact byte identity.

use super::*;
use contextdb_recall::IndexedHit;
use contextdb_service::OriginalRenderOmission;

pub(super) struct PreparedRawSpan {
    pub span: OriginalSourceSpan,
    pub page: Option<contextdb_service::OriginalPage>,
}

impl NativeService {
    pub(super) fn prepare_raw_spans(
        &self,
        snapshot: &impl ReadSnapshot,
        context: &AuthenticatedRequestContext,
        hit: &IndexedHit,
        external_processing: bool,
        budget: &mut QueryBudget,
    ) -> ServiceResult<std::result::Result<Vec<PreparedRawSpan>, OriginalRenderOmission>> {
        const WHOLE_LIMIT: u64 = 32 * 1024;
        const CONTEXT: u64 = 1024;
        let Some(length) = hit.source.byte_length.filter(|length| *length > 0) else {
            return Ok(Err(OriginalRenderOmission::Unavailable));
        };
        if hit.source.role == EventRole::Tool
            && matches!(
                hit.source.kind,
                EventKind::ToolCompleted | EventKind::ToolFailed
            )
            && length > u64::from(contextdb_continuity::TOOL_RESULT_PAGE_BYTES)
        {
            let handle = contextdb_continuity::OriginalPageHandle {
                database_id: self.database_id.clone(),
                event_id: hit.source.event_id,
                payload_digest: hit
                    .source
                    .payload_digest
                    .ok_or_else(|| super::super::integrity("tool payload digest absent"))?,
                byte_length: length,
            };
            let original = self.validate_tool_page_original(snapshot, context, &handle, budget)?;
            if RawSource::from(&original.event) != hit.source {
                return Err(super::super::integrity(
                    "indexed tool source differs from its captured original",
                ));
            }
            if let contextdb_core::EventPayload::InlineBytes { media_type, .. }
            | contextdb_core::EventPayload::Staged { media_type, .. } = &original.event.payload
                && !media_type.starts_with("text/")
                && !matches!(media_type.as_str(), "application/json" | "application/xml")
            {
                return Ok(Err(OriginalRenderOmission::NonText));
            }
            let starts = if hit.matches.is_empty() {
                vec![0]
            } else {
                hit.matches
                    .iter()
                    .take(8)
                    .map(|span| span.start.saturating_sub(CONTEXT))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            };
            let mut spans = Vec::new();
            for start in starts {
                let page = self.read_tool_original_page_at(
                    snapshot,
                    contextdb_service::ReadOriginalPageRequest {
                        context: context.clone(),
                        handle: handle.clone(),
                        start,
                        max_bytes: contextdb_continuity::TOOL_RESULT_PAGE_BYTES,
                        external_processing,
                    },
                    budget,
                )?;
                spans.push(PreparedRawSpan {
                    span: page.view.preview.clone(),
                    page: Some(page),
                });
            }
            return Ok(Ok(spans));
        }
        let ranges = if length <= WHOLE_LIMIT {
            vec![(0, length)]
        } else if hit.matches.is_empty() {
            return Ok(Err(OriginalRenderOmission::RangeRequired));
        } else {
            let mut ranges: Vec<(u64, u64)> = hit
                .matches
                .iter()
                .take(8)
                .map(|span| {
                    (
                        span.start.saturating_sub(CONTEXT),
                        span.end.saturating_add(CONTEXT).min(length),
                    )
                })
                .collect();
            ranges.sort_unstable();
            let mut merged: Vec<(u64, u64)> = Vec::new();
            for (start, end) in ranges {
                if let Some(previous) = merged.last_mut()
                    && start <= previous.1
                {
                    previous.1 = previous.1.max(end);
                } else {
                    merged.push((start, end));
                }
            }
            merged
        };
        let original = self.load_captured_original(snapshot, hit.source.event_id)?;
        if let contextdb_core::EventPayload::InlineBytes { media_type, .. }
        | contextdb_core::EventPayload::Staged { media_type, .. } = &original.event.payload
            && !media_type.starts_with("text/")
            && !matches!(media_type.as_str(), "application/json" | "application/xml")
        {
            return Ok(Err(OriginalRenderOmission::NonText));
        }
        let payload_digest = hit
            .source
            .payload_digest
            .ok_or_else(|| super::super::integrity("raw payload digest absent"))?;
        let mut spans = Vec::new();
        for (start, end) in ranges {
            let size = end
                .checked_sub(start)
                .filter(|size| *size <= WHOLE_LIMIT)
                .ok_or_else(|| super::super::exhausted("raw context range exceeds its limit"))?;
            budget.charge(1, size).map_err(budget_error)?;
            let bytes = self.original_range(snapshot, context, &original.event, start, end)?;
            // A query byte window may bisect a UTF-8 code point. Trim only its
            // incomplete boundary bytes; malformed content itself is not repaired.
            let skip = if start == 0 {
                0
            } else {
                bytes
                    .iter()
                    .take(3)
                    .take_while(|byte| **byte & 0xc0 == 0x80)
                    .count()
            };
            let bytes = &bytes[skip..];
            let text = match std::str::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) if end < length && error.error_len().is_none() => {
                    std::str::from_utf8(&bytes[..error.valid_up_to()])
                        .map_err(|_| super::super::integrity("UTF-8 boundary changed"))?
                }
                Err(_) => return Ok(Err(OriginalRenderOmission::NonText)),
            };
            if text.is_empty() {
                return Ok(Err(OriginalRenderOmission::NonText));
            }
            let start = start + skip as u64;
            spans.push(PreparedRawSpan {
                span: OriginalSourceSpan {
                    event_id: hit.source.event_id,
                    payload_digest,
                    start,
                    end: start + text.len() as u64,
                    span_digest: ContentDigest::from_bytes(
                        *blake3::hash(text.as_bytes()).as_bytes(),
                    ),
                },
                page: None,
            });
        }
        Ok(Ok(spans))
    }
}
