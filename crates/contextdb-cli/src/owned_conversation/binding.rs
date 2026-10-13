//! One accepted source pins this reference host's immutable run configuration.

use std::sync::Arc;

use contextdb_capture::CaptureHost;
use contextdb_continuity::OwnedRunIdentity;
use contextdb_core::{
    ContentDigest, EVENT_ENVELOPE_VERSION, EventCoverage, EventEnvelope, EventKind, EventPayload,
    EventRole, ObservationId, SourceId, StreamId, TimestampMicros,
};
use contextdb_native_service::NativeService;
use contextdb_service::{
    AuthenticatedRequestContext, CapturePort, CaptureReceipt, CaptureRequest, ErrorCode,
    ReadOriginalRequest,
};
use serde::Serialize;

use super::{invalid, now};
use crate::CliResult;

const BINDING_ADAPTER: &str = "contextdb.cli-owned-host-binding.v1";

#[derive(Serialize)]
struct ConfigurationBinding<'a> {
    profile: &'a str,
    config_digest: &'a str,
}

pub(super) struct AcceptedBinding {
    pub(super) receipt: CaptureReceipt,
    pub(super) recorded_at: TimestampMicros,
}

/// Binding and runtime use separate producers. Interrupted start can reuse the
/// accepted binding and its timestamp, but resume never creates a missing one.
pub(super) fn require_binding(
    owner: &Arc<NativeService>,
    context: &AuthenticatedRequestContext,
    identity: &OwnedRunIdentity,
    digest: &str,
    start: bool,
) -> CliResult<AcceptedBinding> {
    let name = format!("contextdb/cli-owned-host-binding/v1/{}", identity.run_id);
    let hash = blake3::hash(name.as_bytes()).to_hex();
    let event_id: ObservationId = hash[..32]
        .parse()
        .map_err(|_| invalid("conversation binding identity cannot be created"))?;
    let producer_id = StreamId::from_uuid(event_id.as_uuid())
        .map_err(|_| invalid("conversation binding producer cannot be created"))?;
    let bytes = serde_json::to_vec(&ConfigurationBinding {
        profile: BINDING_ADAPTER,
        config_digest: digest,
    })
    .map_err(|_| invalid("conversation configuration cannot be bound"))?;
    match owner.read_original(ReadOriginalRequest {
        context: context.clone(),
        event_id,
        after_receipt: None,
    }) {
        Ok(original) => {
            let event = &original.event;
            if event.event_id != event_id
                || event.workspace_id != identity.workspace_id
                || event.scope_ids != identity.scopes
                || event.session_id != Some(identity.session_id)
                || event.run_id != Some(identity.run_id)
                || event.producer_id != producer_id
                || event.producer_sequence != 1
                || event.kind != EventKind::RunStarted
                || event.role != EventRole::Host
                || event.adapter_id != BINDING_ADAPTER
                || event.payload.original_bytes() != Some(bytes.as_slice())
            {
                return Err(invalid(
                    "run configuration differs from its accepted host binding",
                ));
            }
            owner.resolve_capture_receipt(context, &original.receipt)?;
            Ok(AcceptedBinding {
                receipt: original.receipt,
                recorded_at: event.recorded_at,
            })
        }
        Err(error) if start && error.code == ErrorCode::NotFound => {
            let recorded_at = now()?;
            let event = EventEnvelope {
                version: EVENT_ENVELOPE_VERSION,
                event_id,
                workspace_id: identity.workspace_id,
                scope_ids: identity.scopes.clone(),
                producer_id,
                producer_sequence: 1,
                kind: EventKind::RunStarted,
                recorded_at,
                observed_at: None,
                source_id: SourceId::from_uuid(event_id.as_uuid())
                    .map_err(|_| invalid("conversation binding source cannot be created"))?,
                source_version: Some("1".into()),
                adapter_id: BINDING_ADAPTER.into(),
                role: EventRole::Host,
                session_id: Some(identity.session_id),
                run_id: Some(identity.run_id),
                task_id: None,
                parent_event_ids: Default::default(),
                supersedes_event_id: None,
                payload: EventPayload::InlineBytes {
                    digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
                    bytes: bytes.clone(),
                    media_type: "application/json".into(),
                },
                coverage: EventCoverage::CompleteObservation,
                upstream_truncated: false,
                gap_reason: None,
                response_stream: None,
                provenance: None,
            };
            let accepted = CaptureHost::new(owner.clone()).capture_bytes(
                CaptureRequest {
                    context: context.clone(),
                    idempotency_key: format!("owned-host-binding/{}", identity.run_id),
                    event,
                },
                bytes,
                "application/json".into(),
            )?;
            Ok(AcceptedBinding {
                receipt: accepted.receipt,
                recorded_at,
            })
        }
        Err(error) => Err(error.into()),
    }
}
