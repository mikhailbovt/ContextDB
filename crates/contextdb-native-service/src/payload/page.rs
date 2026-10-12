//! Current-authorized bounded pages of a fully retained tool original.

use super::*;
use contextdb_continuity::{OriginalPageHandle, TOOL_RESULT_PAGE_BYTES, ToolResultPageView};
use contextdb_core::{EventRole, RawSource};

impl NativeService {
    pub(crate) fn validate_tool_page_original<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        handle: &OriginalPageHandle,
        budget: &mut PayloadBudget,
    ) -> ServiceResult<contextdb_service::CapturedOriginal> {
        handle
            .validate()
            .map_err(|_| invalid("invalid full-original page handle"))?;
        if handle.database_id != self.database_id {
            return Err(invalid("page handle belongs to another database"));
        }
        self.authorized_capture_policy_with_budget(snapshot, context, handle.event_id, budget)?;
        self.authorize_derived_custody_with_budget(snapshot, context, handle.event_id, budget)?;
        let original =
            self.load_captured_original_with_budget(snapshot, handle.event_id, budget)?;
        check_original(&original.event, handle)?;
        Ok(original)
    }

    pub(super) fn read_tool_original_page(
        &self,
        request: ReadOriginalPageRequest,
        budget: &mut PayloadBudget,
    ) -> ServiceResult<OriginalPage> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.read_tool_original_page_at(&snapshot, request, budget)
    }

    pub(crate) fn read_tool_original_page_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        request: ReadOriginalPageRequest,
        budget: &mut PayloadBudget,
    ) -> ServiceResult<OriginalPage> {
        require_capability(&request.context, Capability::ReadEvidence)?;
        require_capability(&request.context, Capability::RawEvidence)?;
        if request.external_processing || self.preparation_scorer.is_some() {
            require_capability(&request.context, Capability::ModelProcessing)?;
        }
        request
            .handle
            .validate()
            .map_err(|_| invalid("invalid full-original page handle"))?;
        if request.handle.database_id != self.database_id
            || request.max_bytes == 0
            || request.max_bytes > TOOL_RESULT_PAGE_BYTES
            || request.start >= request.handle.byte_length
        {
            return Err(invalid(
                "original page selector exceeds its declared profile",
            ));
        }
        budget
            .charge(1, u64::from(request.max_bytes))
            .map_err(super::super::raw_index::budget_error)?;
        self.authorized_capture_policy_with_budget(
            snapshot,
            &request.context,
            request.handle.event_id,
            budget,
        )?;
        self.authorize_derived_custody_with_budget(
            snapshot,
            &request.context,
            request.handle.event_id,
            budget,
        )?;
        let original =
            self.load_captured_original_with_budget(snapshot, request.handle.event_id, budget)?;
        check_original(&original.event, &request.handle)?;
        let end = request
            .start
            .saturating_add(u64::from(request.max_bytes))
            .min(request.handle.byte_length);
        let bytes = match &original.event.payload {
            EventPayload::InlineUtf8 { text, .. } => {
                text.as_bytes()[source_range(request.start, end, text.len())?].to_vec()
            }
            EventPayload::InlineBytes {
                bytes, media_type, ..
            } => {
                require_text(media_type)?;
                bytes[source_range(request.start, end, bytes.len())?].to_vec()
            }
            EventPayload::Staged {
                reference,
                media_type,
            } => {
                require_text(media_type)?;
                let header = self.checked_payload_header_inner(
                    snapshot,
                    Some(&request.context),
                    reference,
                    Some(budget),
                )?;
                self.payload_range_inner(snapshot, &header, request.start, end, Some(budget))?
            }
            _ => return Err(invalid("original page requires an observed text payload")),
        };
        let skip = if request.start == 0 {
            0
        } else {
            bytes
                .iter()
                .take(3)
                .take_while(|byte| **byte & 0xc0 == 0x80)
                .count()
        };
        let selected = &bytes[skip..];
        let text = match std::str::from_utf8(selected) {
            Ok(text) => text,
            Err(error) if end < request.handle.byte_length && error.error_len().is_none() => {
                std::str::from_utf8(&selected[..error.valid_up_to()])
                    .map_err(|_| invalid("malformed original UTF-8 page"))?
            }
            Err(_) => return Err(invalid("malformed original UTF-8 page")),
        };
        if text.is_empty() {
            return Err(invalid(
                "original page contains no complete UTF-8 character",
            ));
        }
        let start = request.start + skip as u64;
        let page = OriginalPage {
            view: ToolResultPageView {
                handle: request.handle.clone(),
                preview: OriginalSourceSpan {
                    event_id: request.handle.event_id,
                    payload_digest: request.handle.payload_digest,
                    start,
                    end: start + text.len() as u64,
                    span_digest: ContentDigest::from_bytes(
                        *blake3::hash(text.as_bytes()).as_bytes(),
                    ),
                },
            },
            bytes: text.as_bytes().to_vec(),
        };
        budget
            .check()
            .map_err(super::super::raw_index::budget_error)?;
        Ok(page)
    }
}

fn check_original(event: &EventEnvelope, handle: &OriginalPageHandle) -> ServiceResult<()> {
    if event.role != EventRole::Tool
        || !matches!(event.kind, EventKind::ToolCompleted | EventKind::ToolFailed)
        || event.payload.digest() != Some(handle.payload_digest)
        || RawSource::from(event).byte_length != Some(handle.byte_length)
    {
        return Err(invalid(
            "page handle differs from its complete tool original",
        ));
    }
    Ok(())
}
fn require_text(media: &str) -> ServiceResult<()> {
    if media.starts_with("text/") || matches!(media, "application/json" | "application/xml") {
        Ok(())
    } else {
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "original page requires a declared text media type",
            false,
        ))
    }
}

#[cfg(test)]
mod tests;
