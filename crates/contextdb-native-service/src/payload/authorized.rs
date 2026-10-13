//! Same-snapshot range access to a genuine already admitted original.

use super::*;
use contextdb_core::ObservationId;
use contextdb_service::CapturedOriginal;

/// Only the native admission below constructs this capability. Its borrowed
/// owner, snapshot and principal cannot be exchanged for another range read.
pub(crate) struct AuthorizedCapturedOriginal<'a, S> {
    service: &'a NativeService,
    snapshot: &'a S,
    context: &'a AuthenticatedRequestContext,
    original: CapturedOriginal,
}

impl<S> AuthorizedCapturedOriginal<'_, S> {
    pub(crate) fn original(&self) -> &CapturedOriginal {
        &self.original
    }
}

impl NativeService {
    pub(crate) fn admit_captured_original<'a, S: ReadSnapshot>(
        &'a self,
        snapshot: &'a S,
        context: &'a AuthenticatedRequestContext,
        event_id: ObservationId,
        budget: &mut PayloadBudget,
    ) -> ServiceResult<AuthorizedCapturedOriginal<'a, S>> {
        budget
            .charge(1, size_of::<AuthorizedCapturedOriginal<'_, S>>() as u64)
            .map_err(crate::raw_index::budget_error)?;
        self.authorized_capture_policy_with_budget(snapshot, context, event_id, budget)?;
        self.authorize_derived_custody_with_budget(snapshot, context, event_id, budget)?;
        let original = self.load_captured_original_with_budget(snapshot, event_id, budget)?;
        Ok(AuthorizedCapturedOriginal {
            service: self,
            snapshot,
            context,
            original,
        })
    }

    pub(crate) fn source_span_from_authorized_original<S: ReadSnapshot>(
        &self,
        admitted: &AuthorizedCapturedOriginal<'_, S>,
        span: &OriginalSourceSpan,
        independent_root: bool,
        budget: &mut PayloadBudget,
    ) -> ServiceResult<Vec<u8>> {
        budget
            .charge(1, 0)
            .map_err(crate::raw_index::budget_error)?;
        if !std::ptr::eq(self, admitted.service) {
            return Err(invalid(
                "authorized original belongs to another native owner",
            ));
        }
        let event = &admitted.original.event;
        if event.event_id != span.event_id {
            return Err(invalid("source event differs from its admitted original"));
        }
        // External suppression can advance without changing this snapshot. The
        // capability reuses attribution, never current disclosure permission.
        self.authorized_capture_policy_with_budget(
            admitted.snapshot,
            admitted.context,
            event.event_id,
            budget,
        )?;
        self.authorize_derived_custody_with_budget(
            admitted.snapshot,
            admitted.context,
            event.event_id,
            budget,
        )?;
        span.end
            .checked_sub(span.start)
            .ok_or_else(|| invalid("source range is reversed"))?;
        if independent_root
            && (event.kind == EventKind::ModelRequested
                || matches!(event.payload, EventPayload::Assembly { .. }))
        {
            return Err(invalid(
                "model request echo cannot become an independent source root",
            ));
        }
        if matches!(event.payload, EventPayload::Omitted { .. }) {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "original source bytes are explicitly unavailable",
                false,
            ));
        }
        if event.payload.digest() != Some(span.payload_digest) {
            return Err(invalid("source payload digest mismatch"));
        }
        // This context-bearing primitive prepays the selected buffer and retains
        // staged header/chunk authentication and recursive Assembly source checks.
        let selected = self.original_range_with_budget(
            admitted.snapshot,
            admitted.context,
            event,
            span.start,
            span.end,
            budget,
        )?;
        budget
            .charge(selected.len() as u64 + 1, 0)
            .map_err(crate::raw_index::budget_error)?;
        if raw_digest(&selected) != span.span_digest {
            return Err(invalid("source span digest mismatch"));
        }
        budget.check().map_err(crate::raw_index::budget_error)?;
        Ok(selected)
    }
}
