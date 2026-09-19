use contextdb_core::{
    ArtifactId, EventCoverage, EventKind, EventPayload, EventProvenance, EventRole, PayloadOmission,
};
use contextdb_service::{
    CaptureAcceptance, CaptureReceipt, CaptureRequest, PayloadPort, ServiceResult,
};

use crate::{CaptureHost, digest};

/// Complete observed source version; watcher gaps remain explicit.
#[derive(Clone)]
pub struct ArtifactObservation {
    /// Stable artifact identity across source versions.
    pub artifact_id: ArtifactId,
    /// Predecessor receipt, including its original digest.
    pub previous: Option<CaptureReceipt>,
    /// Complete observed bytes; `None` means an observed source deletion.
    pub bytes: Option<Vec<u8>>,
    /// Original media type.
    pub media_type: String,
    /// Fresh snapshot after missing watcher events; never a reconstructed diff.
    pub rescan_after_gap: bool,
}

impl std::fmt::Debug for ArtifactObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactObservation")
            .field("artifact_id", &self.artifact_id)
            .field("byte_length", &self.bytes.as_ref().map(Vec::len))
            .field("rescan_after_gap", &self.rescan_after_gap)
            .finish_non_exhaustive()
    }
}

impl<S: PayloadPort + ?Sized> CaptureHost<S> {
    /// Capture a full source version or deletion, bound to its observed predecessor.
    pub fn capture_artifact(
        &self,
        mut request: CaptureRequest,
        observation: ArtifactObservation,
    ) -> ServiceResult<CaptureAcceptance> {
        request.context.validate_authentication()?;
        if let Some(previous) = &observation.previous {
            self.owner
                .resolve_capture_receipt(&request.context, previous)?;
        }
        request.event.kind = if observation.bytes.is_none() {
            EventKind::ArtifactDeleted
        } else if observation.previous.is_some() {
            EventKind::ArtifactChanged
        } else {
            EventKind::ArtifactObserved
        };
        request.event.role = EventRole::ExternalSource;
        request.event.supersedes_event_id = observation
            .previous
            .as_ref()
            .map(|receipt| receipt.event_id);
        request.event.provenance = Some(EventProvenance::Artifact {
            artifact_id: observation.artifact_id,
            base_digest: observation
                .previous
                .as_ref()
                .and_then(|receipt| receipt.payload_digest),
            new_digest: observation.bytes.as_ref().map(|bytes| digest(bytes)),
            rescan_after_gap: observation.rescan_after_gap,
        });
        if observation.rescan_after_gap {
            request.event.coverage = EventCoverage::PartialObservation;
        }
        match observation.bytes {
            Some(bytes) => self.capture_bytes(request, bytes, observation.media_type),
            None => {
                request.event.payload = EventPayload::Omitted {
                    reason: PayloadOmission::SourceDeleted,
                };
                request.event.coverage = EventCoverage::PartialObservation;
                self.owner.append_event_with_status(request)
            }
        }
    }
}
