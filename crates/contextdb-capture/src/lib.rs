//! Host-owned original capture adapters; no extraction or model authority.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod artifact;
mod tool;

pub use artifact::*;
pub use tool::*;

use std::sync::Arc;

use contextdb_core::{
    ContentBlockId, ContentDigest, EventKind, EventPayload, EventRole, ModelRequestManifest,
};
use contextdb_service::{
    CaptureAcceptance, CaptureRequest, ErrorCode, PayloadPort, ServiceError, ServiceResult,
    StagePayloadRequest,
};

/// Native inline profile shared by the host adapters.
const INLINE_BYTES: usize = 256 * 1024;

/// Shared host adapter over one native publication owner.
pub struct CaptureHost<S: ?Sized> {
    owner: Arc<S>,
}

impl<S: ?Sized> std::fmt::Debug for CaptureHost<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureHost").finish_non_exhaustive()
    }
}

impl<S: PayloadPort + ?Sized> CaptureHost<S> {
    /// Use the same owner as conversation capture and the owned runtime.
    #[must_use]
    pub const fn new(owner: Arc<S>) -> Self {
        Self { owner }
    }

    /// Preserve complete observed bytes, staging large originals before publication.
    ///
    /// Failures retain the same event, producer position and retry key. The caller
    /// pauses until acknowledgement; staging alone is not an event receipt.
    pub fn capture_bytes(
        &self,
        mut request: CaptureRequest,
        bytes: Vec<u8>,
        media_type: String,
    ) -> ServiceResult<CaptureAcceptance> {
        request.context.validate_authentication()?;
        request.event.payload = if bytes.len() <= INLINE_BYTES {
            EventPayload::InlineBytes {
                digest: digest(&bytes),
                bytes,
                media_type,
            }
        } else {
            let key = serde_json::to_vec(&(request.event.producer_id, &request.idempotency_key))
                .map_err(|_| invalid("payload retry identity cannot be encoded"))?;
            let staged = self.owner.stage_payload(StagePayloadRequest {
                context: request.context.clone(),
                idempotency_key: format!("payload/{}", blake3::hash(&key)),
                block_id: ContentBlockId::from_uuid(request.event.event_id.as_uuid())
                    .map_err(|_| invalid("payload identity is invalid"))?,
                bytes,
            })?;
            EventPayload::Staged {
                reference: staged.reference,
                media_type,
            }
        };
        self.owner.append_event_with_status(request)
    }

    /// Record exact ordered model input without indexing retrieved echoes as new roots.
    pub fn capture_model_request(
        &self,
        mut request: CaptureRequest,
        manifest: ModelRequestManifest,
    ) -> ServiceResult<CaptureAcceptance> {
        request.event.kind = EventKind::ModelRequested;
        request.event.role = EventRole::Host;
        request.event.payload = EventPayload::Assembly { manifest };
        self.owner.append_event_with_status(request)
    }
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn invalid(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false)
}
