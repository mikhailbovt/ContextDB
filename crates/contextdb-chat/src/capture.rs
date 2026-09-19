//! Native conversation capture, independent of recall and extraction gates.

use std::{collections::BTreeSet, sync::Arc};

use contextdb_core::{EventEnvelope, EventKind, EventRole};
use contextdb_service::{
    Capability, CapturePort, CaptureReceipt, CaptureRequest, ErrorCode, ServiceError, ServiceResult,
};

use crate::{
    ConversationAuthorityBinding, ConversationServiceAuthority, service_adapter::validate_authority,
};

/// Host adapter to the sole native capture owner.
///
/// The caller retains the original and the same idempotency key until this
/// operation returns a synchronized receipt. Any failure pauses strict capture;
/// it must not advance the conversation or evict the unacknowledged original.
/// This adapter never writes the legacy `ChatStore` or runs an extractor.
pub struct NativeConversationCapture<S: ?Sized, A> {
    service: Arc<S>,
    authority: A,
}

impl<S: ?Sized, A> std::fmt::Debug for NativeConversationCapture<S, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeConversationCapture")
            .finish_non_exhaustive()
    }
}

impl<S: CapturePort + ?Sized, A: ConversationServiceAuthority> NativeConversationCapture<S, A> {
    /// Bind an embedded capture owner and a content-independent host authority.
    #[must_use]
    pub const fn new(service: Arc<S>, authority: A) -> Self {
        Self { service, authority }
    }

    /// Capture one immutable user/assistant observation or explicit capture gap.
    ///
    /// `binding` and the observed role come from the host's registered session,
    /// not from model text. The native owner verifies payload digests, stream
    /// ordering, edits, producer gaps and exact retry identity atomically.
    pub fn capture(
        &self,
        binding: &ConversationAuthorityBinding,
        event: EventEnvelope,
        idempotency_key: String,
    ) -> ServiceResult<CaptureReceipt> {
        let mut binding = binding.clone();
        binding.required_capabilities = BTreeSet::from([Capability::Observe]);
        // Authenticate before inspecting the supplied content or provenance.
        let context = self.authority.authorize(&binding)?;
        validate_authority(&binding, &context).map_err(|_| {
            ServiceError::new(
                ErrorCode::PermissionDenied,
                "capture authority differs from the registered conversation",
                false,
            )
        })?;
        if event.workspace_id.to_string() != binding.workspace_id
            || event
                .scope_ids
                .iter()
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>()
                != binding.scopes
            || event.session_id.map(|id| id.to_string()) != binding.session_id
        {
            return Err(ServiceError::new(
                ErrorCode::PermissionDenied,
                "capture event differs from the registered conversation",
                false,
            ));
        }
        let allowed_role = match event.kind {
            EventKind::MessageCreated | EventKind::MessageEdited | EventKind::MessageDeleted => {
                matches!(event.role, EventRole::User | EventRole::Assistant)
            }
            EventKind::ModelResponseChunk
            | EventKind::ModelResponseCompleted
            | EventKind::ModelResponseAborted => event.role == EventRole::Assistant,
            EventKind::CaptureGap => event.role == EventRole::Host,
            _ => false,
        };
        if !allowed_role {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "event kind or role is not a conversation observation",
                false,
            ));
        }
        self.service.append_event(CaptureRequest {
            context,
            event,
            idempotency_key,
        })
    }
}
