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
    RequestPart,
};
use contextdb_service::{
    CaptureAcceptance, CaptureReceipt, CaptureRequest, ErrorCode, PayloadPort, PrepareContextPort,
    PreparedContext, ServiceError, ServiceResult, StagePayloadRequest,
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
        request: CaptureRequest,
        manifest: ModelRequestManifest,
    ) -> ServiceResult<CaptureAcceptance> {
        if manifest.router_trace.is_some() {
            return Err(invalid("router trace requires prepared owner capture"));
        }
        self.stage_model_request(request, manifest, |request| {
            self.owner.append_event_with_status(request)
        })
    }

    fn stage_model_request(
        &self,
        mut request: CaptureRequest,
        mut manifest: ModelRequestManifest,
        publish: impl FnOnce(CaptureRequest) -> ServiceResult<CaptureAcceptance>,
    ) -> ServiceResult<CaptureAcceptance> {
        request.context.validate_authentication()?;
        let novel_bytes = manifest
            .parts
            .iter()
            .filter_map(|part| match part {
                RequestPart::Novel { bytes } => Some(bytes.len()),
                _ => None,
            })
            .sum::<usize>();
        if novel_bytes > INLINE_BYTES {
            for (index, part) in manifest.parts.iter_mut().enumerate() {
                if let RequestPart::Novel { bytes } = part {
                    let key =
                        serde_json::to_vec(&("request-novel/v1", request.event.event_id, index))
                            .map_err(|_| invalid("request part identity cannot be encoded"))?;
                    let hash = blake3::hash(&key);
                    let mut id = [0_u8; 16];
                    id.copy_from_slice(&hash.as_bytes()[..16]);
                    let staged = self.owner.stage_payload(StagePayloadRequest {
                        context: request.context.clone(),
                        idempotency_key: format!("request-payload/{hash}"),
                        block_id: ContentBlockId::from_uuid(uuid::Uuid::from_bytes(id))
                            .map_err(|_| invalid("request part identity is invalid"))?,
                        bytes: bytes.clone(),
                    })?;
                    *part = RequestPart::StoredNovel {
                        payload: staged.reference,
                    };
                }
            }
        }
        request.event.kind = EventKind::ModelRequested;
        request.event.role = EventRole::Host;
        request.event.provenance = Some(contextdb_core::EventProvenance::ModelRequest {
            model_call_id: manifest.model_call_id,
        });
        request.event.payload = EventPayload::Assembly { manifest };
        publish(request)
    }
}

impl<S: PayloadPort + PrepareContextPort + ?Sized> CaptureHost<S> {
    /// Capture an owner-prepared protected trace outside the reader's wire.
    pub fn capture_prepared_model_request(
        &self,
        mut request: CaptureRequest,
        manifest: ModelRequestManifest,
        prepared: &PreparedContext,
        current_checkpoint: Option<&CaptureReceipt>,
        budget: &mut contextdb_recall::QueryBudget,
    ) -> ServiceResult<CaptureAcceptance> {
        request.context.validate_authentication()?;
        if manifest
            .parts
            .iter()
            .try_fold(0_usize, |total, part| {
                total.checked_add(match part {
                    RequestPart::Novel { bytes } => bytes.len(),
                    _ => 0,
                })
            })
            .is_none_or(|total| total > INLINE_BYTES)
            || manifest
                .parts
                .iter()
                .any(|part| matches!(part, RequestPart::StoredNovel { .. }))
        {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "protected requests require bounded inline novel material",
                false,
            ));
        }
        let trace = prepared
            .router_trace
            .as_ref()
            .ok_or_else(|| invalid("protected request has no prepared trace"))?;
        let expected = trace.attach(manifest.model_call_id, budget)?;
        if manifest.router_trace.as_deref() != Some(&expected)
            || manifest.wire_digest != prepared.assembly.wire_digest
            || manifest.byte_length != prepared.outgoing.wire.len() as u64
        {
            return Err(invalid("protected request differs from prepared trace"));
        }
        // Consume the final event without cloning a caller's discarded payload.
        // This profile has already excluded staging and StoredNovel.
        request.event.kind = EventKind::ModelRequested;
        request.event.role = EventRole::Host;
        request.event.provenance = Some(contextdb_core::EventProvenance::ModelRequest {
            model_call_id: manifest.model_call_id,
        });
        request.event.payload = EventPayload::Assembly { manifest };
        let mut encoded = EventSize(0);
        serde_json::to_writer(&mut encoded, &request.event).map_err(|_| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "protected request exceeds the native event profile",
                false,
            )
        })?;
        budget.charge(1, encoded.0 as u64).map_err(|_| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "protected request exhausted the shared allowance",
                false,
            )
        })?;
        self.owner
            .capture_prepared_model_request(request, prepared, current_checkpoint, budget)
    }
}

struct EventSize(usize);
impl std::io::Write for EventSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        if self.0 > 8 * 1024 * 1024 {
            return Err(std::io::Error::other(
                "protected event exceeds byte ceiling",
            ));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn invalid(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false)
}
