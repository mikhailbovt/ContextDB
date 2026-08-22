//! Lossless conversion between generated Protobuf types and the canonical
//! application-service types.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_proto::v1 as wire;
use contextdb_service as domain;

fn invalid(message: &'static str) -> domain::ServiceError {
    domain::ServiceError::new(domain::ErrorCode::InvalidArgument, message, false)
}

fn required<T>(value: Option<T>, message: &'static str) -> domain::ServiceResult<T> {
    value.ok_or_else(|| invalid(message))
}

fn set(values: Vec<String>) -> domain::ServiceResult<BTreeSet<String>> {
    let input_len = values.len();
    let result: BTreeSet<_> = values.into_iter().collect();
    if result.len() != input_len {
        return Err(invalid("repeated set contains a duplicate"));
    }
    Ok(result)
}

fn sensitivity(value: i32) -> domain::ServiceResult<domain::Sensitivity> {
    match wire::Sensitivity::try_from(value).ok() {
        Some(wire::Sensitivity::Public) => Ok(domain::Sensitivity::Public),
        Some(wire::Sensitivity::Internal) => Ok(domain::Sensitivity::Internal),
        Some(wire::Sensitivity::Private) => Ok(domain::Sensitivity::Private),
        Some(wire::Sensitivity::Restricted) => Ok(domain::Sensitivity::Restricted),
        Some(wire::Sensitivity::Unspecified) | None => {
            Err(invalid("sensitivity must be specified"))
        }
    }
}

fn consent(value: i32) -> domain::ServiceResult<domain::Consent> {
    match wire::Consent::try_from(value).ok() {
        Some(wire::Consent::Granted) => Ok(domain::Consent::Granted),
        Some(wire::Consent::Unknown) => Ok(domain::Consent::Unknown),
        Some(wire::Consent::Denied) => Ok(domain::Consent::Denied),
        Some(wire::Consent::Unspecified) | None => Err(invalid("consent must be specified")),
    }
}

fn sensitivity_to_proto(value: domain::Sensitivity) -> i32 {
    match value {
        domain::Sensitivity::Public => wire::Sensitivity::Public as i32,
        domain::Sensitivity::Internal => wire::Sensitivity::Internal as i32,
        domain::Sensitivity::Private => wire::Sensitivity::Private as i32,
        domain::Sensitivity::Restricted => wire::Sensitivity::Restricted as i32,
    }
}

fn consent_to_proto(value: domain::Consent) -> i32 {
    match value {
        domain::Consent::Granted => wire::Consent::Granted as i32,
        domain::Consent::Unknown => wire::Consent::Unknown as i32,
        domain::Consent::Denied => wire::Consent::Denied as i32,
    }
}

/// Converts a wire request context, rejecting missing enum values and duplicate
/// set members before the application service sees the request.
pub fn request_context_from_proto(
    value: wire::RequestContext,
) -> domain::ServiceResult<domain::RequestContext> {
    Ok(domain::RequestContext {
        request_id: value.request_id,
        workspace_id: value.workspace_id,
        subject_id: value.subject_id,
        audiences: set(value.audiences)?,
        scopes: set(value.scopes)?,
        purpose: value.purpose,
        clearance: sensitivity(value.clearance)?,
    })
}

/// Converts a canonical request context to its wire representation.
#[must_use]
pub fn request_context_to_proto(value: domain::RequestContext) -> wire::RequestContext {
    wire::RequestContext {
        request_id: value.request_id,
        workspace_id: value.workspace_id,
        subject_id: value.subject_id,
        audiences: value.audiences.into_iter().collect(),
        scopes: value.scopes.into_iter().collect(),
        purpose: value.purpose,
        clearance: sensitivity_to_proto(value.clearance),
        actor_id: None,
        agent_id: None,
        session_id: None,
        capability_grants: Vec::new(),
        authentication: None,
    }
}

fn capability(value: i32) -> domain::ServiceResult<domain::Capability> {
    match wire::Capability::try_from(value).ok() {
        Some(wire::Capability::Observe) => Ok(domain::Capability::Observe),
        Some(wire::Capability::StreamIngest) => Ok(domain::Capability::StreamIngest),
        Some(wire::Capability::Recall) => Ok(domain::Capability::Recall),
        Some(wire::Capability::Correct) => Ok(domain::Capability::Correct),
        Some(wire::Capability::Forget) => Ok(domain::Capability::Forget),
        Some(wire::Capability::HardDelete) => Ok(domain::Capability::HardDelete),
        Some(wire::Capability::ReadMemory) => Ok(domain::Capability::ReadMemory),
        Some(wire::Capability::Traverse) => Ok(domain::Capability::Traverse),
        Some(wire::Capability::ReadEvidence) => Ok(domain::Capability::ReadEvidence),
        Some(wire::Capability::ReadConflict) => Ok(domain::Capability::ReadConflict),
        Some(wire::Capability::Subscribe) => Ok(domain::Capability::Subscribe),
        Some(wire::Capability::Runtime) => Ok(domain::Capability::Runtime),
        Some(wire::Capability::Maintenance) => Ok(domain::Capability::Maintenance),
        Some(wire::Capability::Admin) => Ok(domain::Capability::Admin),
        Some(wire::Capability::RawEvidence) => Ok(domain::Capability::RawEvidence),
        Some(wire::Capability::ModelProcessing) => Ok(domain::Capability::ModelProcessing),
        Some(wire::Capability::Unspecified) | None => {
            Err(invalid("capability grant must be specified"))
        }
    }
}

fn capability_to_proto(value: domain::Capability) -> i32 {
    (match value {
        domain::Capability::Observe => wire::Capability::Observe,
        domain::Capability::StreamIngest => wire::Capability::StreamIngest,
        domain::Capability::Recall => wire::Capability::Recall,
        domain::Capability::Correct => wire::Capability::Correct,
        domain::Capability::Forget => wire::Capability::Forget,
        domain::Capability::HardDelete => wire::Capability::HardDelete,
        domain::Capability::ReadMemory => wire::Capability::ReadMemory,
        domain::Capability::Traverse => wire::Capability::Traverse,
        domain::Capability::ReadEvidence => wire::Capability::ReadEvidence,
        domain::Capability::ReadConflict => wire::Capability::ReadConflict,
        domain::Capability::Subscribe => wire::Capability::Subscribe,
        domain::Capability::Runtime => wire::Capability::Runtime,
        domain::Capability::Maintenance => wire::Capability::Maintenance,
        domain::Capability::Admin => wire::Capability::Admin,
        domain::Capability::RawEvidence => wire::Capability::RawEvidence,
        domain::Capability::ModelProcessing => wire::Capability::ModelProcessing,
    }) as i32
}

/// Converts the additive authenticated v1 request-context fields.
pub fn authenticated_context_from_proto(
    value: wire::RequestContext,
) -> domain::ServiceResult<domain::AuthenticatedRequestContext> {
    let actor_id = required(value.actor_id.clone(), "actor ID is required")?;
    let agent_id = required(value.agent_id.clone(), "agent ID is required")?;
    let session_id = value.session_id.clone();
    let mut grants = BTreeSet::new();
    for value in &value.capability_grants {
        if !grants.insert(capability(*value)?) {
            return Err(invalid("capability grant appears more than once"));
        }
    }
    let authentication = match required(
        value.authentication.clone(),
        "authentication evidence is required",
    )?
    .evidence
    .ok_or_else(|| invalid("authentication evidence is required"))?
    {
        wire::authentication_evidence::Evidence::AuthenticatedChannel(channel) => {
            domain::AuthenticationEvidence::AuthenticatedChannel {
                channel_id: channel.channel_id,
                peer_identity: channel.peer_identity,
                binding_digest: channel.binding_digest,
            }
        }
        wire::authentication_evidence::Evidence::RequestSignature(signature) => {
            domain::AuthenticationEvidence::RequestSignature {
                algorithm: signature.algorithm,
                key_id: signature.key_id,
                signature: signature.signature,
                signed_context_digest: signature.signed_context_digest,
            }
        }
    };
    let result = domain::AuthenticatedRequestContext {
        request: request_context_from_proto(value)?,
        actor_id,
        agent_id,
        session_id,
        capability_grants: grants,
        authentication,
    };
    result.validate_authentication()?;
    Ok(result)
}

/// Converts a fully authenticated context to additive v1 Protobuf fields.
#[must_use]
pub fn authenticated_context_to_proto(
    value: domain::AuthenticatedRequestContext,
) -> wire::RequestContext {
    let mut result = request_context_to_proto(value.request);
    result.actor_id = Some(value.actor_id);
    result.agent_id = Some(value.agent_id);
    result.session_id = value.session_id;
    result.capability_grants = value
        .capability_grants
        .into_iter()
        .map(capability_to_proto)
        .collect();
    result.authentication = Some(wire::AuthenticationEvidence {
        evidence: Some(match value.authentication {
            domain::AuthenticationEvidence::AuthenticatedChannel {
                channel_id,
                peer_identity,
                binding_digest,
            } => wire::authentication_evidence::Evidence::AuthenticatedChannel(
                wire::AuthenticatedChannelEvidence {
                    channel_id,
                    peer_identity,
                    binding_digest,
                },
            ),
            domain::AuthenticationEvidence::RequestSignature {
                algorithm,
                key_id,
                signature,
                signed_context_digest,
            } => wire::authentication_evidence::Evidence::RequestSignature(
                wire::RequestSignatureEvidence {
                    algorithm,
                    key_id,
                    signature,
                    signed_context_digest,
                },
            ),
        }),
    });
    result
}

fn access_from_proto(value: wire::AccessPolicy) -> domain::ServiceResult<domain::AccessPolicy> {
    let mut grants = BTreeMap::new();
    for grant in value.audience_purpose_grants {
        if grants
            .insert(grant.audience, set(grant.purposes)?)
            .is_some()
        {
            return Err(invalid("audience grant appears more than once"));
        }
    }
    Ok(domain::AccessPolicy {
        workspace_id: value.workspace_id,
        scopes: set(value.scopes)?,
        owners: set(value.owners)?,
        audience: set(value.audience)?,
        audience_purpose_grants: grants,
        purposes: set(value.purposes)?,
        sensitivity: sensitivity(value.sensitivity)?,
        consent: consent(value.consent)?,
        retrievable: value.retrievable,
    })
}

fn access_to_proto(value: domain::AccessPolicy) -> wire::AccessPolicy {
    wire::AccessPolicy {
        workspace_id: value.workspace_id,
        scopes: value.scopes.into_iter().collect(),
        owners: value.owners.into_iter().collect(),
        audience: value.audience.into_iter().collect(),
        audience_purpose_grants: value
            .audience_purpose_grants
            .into_iter()
            .map(|(audience, purposes)| wire::AudiencePurposeGrant {
                audience,
                purposes: purposes.into_iter().collect(),
            })
            .collect(),
        purposes: value.purposes.into_iter().collect(),
        sensitivity: sensitivity_to_proto(value.sensitivity),
        consent: consent_to_proto(value.consent),
        retrievable: value.retrievable,
    }
}

fn canonical_json(bytes: &[u8]) -> domain::ServiceResult<serde_json::Value> {
    if bytes.len() > crate::MAX_WIRE_BYTES {
        return Err(domain::ServiceError::new(
            domain::ErrorCode::ResourceExhausted,
            "canonical JSON exceeds the wire limit",
            false,
        ));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("canonical JSON is malformed"))?;
    let encoded =
        serde_json::to_vec(&value).map_err(|_| invalid("canonical JSON cannot be serialized"))?;
    if encoded != bytes {
        return Err(invalid("JSON bytes are not in canonical form"));
    }
    Ok(value)
}

/// Converts and validates one canonical Protobuf observe request.
pub fn observe_request_from_proto(
    value: wire::ObserveRequest,
) -> domain::ServiceResult<domain::ObserveRequest> {
    let mut metadata = BTreeMap::new();
    for entry in value.metadata {
        let parsed = canonical_json(&entry.canonical_json)?;
        if metadata.insert(entry.key, parsed).is_some() {
            return Err(invalid("metadata key appears more than once"));
        }
    }
    Ok(domain::ObserveRequest {
        context: request_context_from_proto(required(value.context, "context is required")?)?,
        idempotency_key: value.idempotency_key,
        observation_id: value.observation_id,
        metadata,
        content: canonical_json(&value.content_json)?,
        access: access_from_proto(required(value.access, "access policy is required")?)?,
    })
}

/// Converts an embedded observe request to canonical Protobuf.
pub fn observe_request_to_proto(
    value: domain::ObserveRequest,
) -> domain::ServiceResult<wire::ObserveRequest> {
    let metadata = value
        .metadata
        .into_iter()
        .map(|(key, value)| {
            serde_json::to_vec(&value)
                .map(|canonical_json| wire::JsonEntry {
                    key,
                    canonical_json,
                })
                .map_err(|_| invalid("metadata JSON cannot be serialized"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let content_json = serde_json::to_vec(&value.content)
        .map_err(|_| invalid("content JSON cannot be serialized"))?;
    Ok(wire::ObserveRequest {
        context: Some(request_context_to_proto(value.context)),
        idempotency_key: value.idempotency_key,
        observation_id: value.observation_id,
        metadata,
        content_json,
        access: Some(access_to_proto(value.access)),
        gateway_attestation: None,
    })
}

fn compression(value: i32) -> domain::ServiceResult<domain::Compression> {
    match wire::Compression::try_from(value).ok() {
        Some(wire::Compression::Identity) => Ok(domain::Compression::Identity),
        Some(wire::Compression::Gzip) => Ok(domain::Compression::Gzip),
        Some(wire::Compression::Zstd) => Ok(domain::Compression::Zstd),
        Some(wire::Compression::Unspecified) | None => {
            Err(invalid("source compression must be specified"))
        }
    }
}

fn compression_to_proto(value: domain::Compression) -> i32 {
    (match value {
        domain::Compression::Identity => wire::Compression::Identity,
        domain::Compression::Gzip => wire::Compression::Gzip,
        domain::Compression::Zstd => wire::Compression::Zstd,
    }) as i32
}

fn stream_observation_from_proto(
    value: wire::StreamObservation,
) -> domain::ServiceResult<domain::StreamObservation> {
    let mut metadata = BTreeMap::new();
    for entry in value.metadata {
        let parsed = canonical_json(&entry.canonical_json)?;
        if metadata.insert(entry.key, parsed).is_some() {
            return Err(invalid("stream metadata key appears more than once"));
        }
    }
    Ok(domain::StreamObservation {
        idempotency_key: value.idempotency_key,
        observation_id: value.observation_id,
        metadata,
        content: canonical_json(&value.content_json)?,
        access: access_from_proto(required(value.access, "access policy is required")?)?,
    })
}

fn stream_observation_to_proto(
    value: domain::StreamObservation,
) -> domain::ServiceResult<wire::StreamObservation> {
    Ok(wire::StreamObservation {
        idempotency_key: value.idempotency_key,
        observation_id: value.observation_id,
        metadata: value
            .metadata
            .into_iter()
            .map(|(key, value)| {
                serde_json::to_vec(&value)
                    .map(|canonical_json| wire::JsonEntry {
                        key,
                        canonical_json,
                    })
                    .map_err(|_| invalid("stream metadata JSON cannot be serialized"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        content_json: serde_json::to_vec(&value.content)
            .map_err(|_| invalid("stream content JSON cannot be serialized"))?,
        access: Some(access_to_proto(value.access)),
    })
}

/// Converts one authenticated streaming-ingestion frame. Authentication
/// metadata is converted before any canonical content JSON is inspected.
pub fn ingest_frame_from_proto(
    value: wire::IngestFrame,
) -> domain::ServiceResult<domain::IngestFrame> {
    let context =
        authenticated_context_from_proto(required(value.context, "context is required")?)?;
    let frame_value = match required(value.value, "ingest frame value is required")? {
        wire::ingest_frame::Value::Manifest(manifest) => {
            let mut attributes = BTreeMap::new();
            for entry in manifest.attributes {
                if attributes.insert(entry.key, entry.value).is_some() {
                    return Err(invalid("source manifest attribute appears more than once"));
                }
            }
            domain::IngestFrameValue::Manifest(domain::SourceRevisionManifest {
                source_id: manifest.source_id,
                revision_id: manifest.revision_id,
                snapshot_id: manifest.snapshot_id,
                expected_items: manifest.expected_items,
                ordered_items_digest: manifest.ordered_items_digest,
                compression: compression(manifest.compression)?,
                attributes,
            })
        }
        wire::ingest_frame::Value::Observation(observation) => {
            domain::IngestFrameValue::Observation(stream_observation_from_proto(observation)?)
        }
        wire::ingest_frame::Value::SnapshotComplete(marker) => {
            domain::IngestFrameValue::SnapshotComplete(domain::SnapshotComplete {
                snapshot_id: marker.snapshot_id,
                item_count: marker.item_count,
                ordered_items_digest: marker.ordered_items_digest,
            })
        }
    };
    Ok(domain::IngestFrame {
        context,
        stream_id: value.stream_id,
        position: value.position,
        resume_cursor: value.resume_cursor,
        value: frame_value,
    })
}

/// Converts an embedded ingestion frame to canonical Protobuf.
pub fn ingest_frame_to_proto(
    value: domain::IngestFrame,
) -> domain::ServiceResult<wire::IngestFrame> {
    let frame_value = match value.value {
        domain::IngestFrameValue::Manifest(manifest) => {
            wire::ingest_frame::Value::Manifest(wire::SourceRevisionManifest {
                source_id: manifest.source_id,
                revision_id: manifest.revision_id,
                snapshot_id: manifest.snapshot_id,
                expected_items: manifest.expected_items,
                ordered_items_digest: manifest.ordered_items_digest,
                compression: compression_to_proto(manifest.compression),
                attributes: manifest
                    .attributes
                    .into_iter()
                    .map(|(key, value)| wire::SourceAttribute { key, value })
                    .collect(),
            })
        }
        domain::IngestFrameValue::Observation(observation) => {
            wire::ingest_frame::Value::Observation(stream_observation_to_proto(observation)?)
        }
        domain::IngestFrameValue::SnapshotComplete(marker) => {
            wire::ingest_frame::Value::SnapshotComplete(wire::SnapshotComplete {
                snapshot_id: marker.snapshot_id,
                item_count: marker.item_count,
                ordered_items_digest: marker.ordered_items_digest,
            })
        }
    };
    Ok(wire::IngestFrame {
        context: Some(authenticated_context_to_proto(value.context)),
        stream_id: value.stream_id,
        position: value.position,
        resume_cursor: value.resume_cursor,
        value: Some(frame_value),
        gateway_attestation: None,
    })
}

/// Converts a per-frame ingestion acknowledgement to Protobuf.
#[must_use]
pub fn ingest_ack_to_proto(value: domain::IngestAck) -> wire::IngestAck {
    wire::IngestAck {
        stream_id: value.stream_id,
        position: value.position,
        disposition: match value.disposition {
            domain::IngestDisposition::Accepted => wire::IngestDisposition::Accepted,
            domain::IngestDisposition::Replayed => wire::IngestDisposition::Replayed,
            domain::IngestDisposition::SnapshotCommitted => {
                wire::IngestDisposition::SnapshotCommitted
            }
        } as i32,
        frame_digest: value.frame_digest,
        resume_cursor: value.resume_cursor,
        commit_seq: value.commit_seq,
        partial_result_refs: value.partial_result_refs,
        lease_expires_at_ms: value.lease_expires_at_ms,
    }
}

fn memory_event_kind(value: i32) -> domain::ServiceResult<domain::MemoryEventKind> {
    match wire::MemoryEventKind::try_from(value).ok() {
        Some(wire::MemoryEventKind::NodeChanged) => Ok(domain::MemoryEventKind::NodeChanged),
        Some(wire::MemoryEventKind::ClaimChanged) => Ok(domain::MemoryEventKind::ClaimChanged),
        Some(wire::MemoryEventKind::OpenLoopTriggered) => {
            Ok(domain::MemoryEventKind::OpenLoopTriggered)
        }
        Some(wire::MemoryEventKind::IndexWatermarkAdvanced) => {
            Ok(domain::MemoryEventKind::IndexWatermarkAdvanced)
        }
        Some(wire::MemoryEventKind::ConflictResolved) => {
            Ok(domain::MemoryEventKind::ConflictResolved)
        }
        Some(wire::MemoryEventKind::SourceInvalidated) => {
            Ok(domain::MemoryEventKind::SourceInvalidated)
        }
        Some(wire::MemoryEventKind::OperationProgress) => {
            Ok(domain::MemoryEventKind::OperationProgress)
        }
        Some(wire::MemoryEventKind::SecurityEvent) => Ok(domain::MemoryEventKind::SecurityEvent),
        Some(wire::MemoryEventKind::ObservationAccepted) => {
            Ok(domain::MemoryEventKind::ObservationAccepted)
        }
        Some(wire::MemoryEventKind::RecordChanged) => Ok(domain::MemoryEventKind::RecordChanged),
        Some(wire::MemoryEventKind::Unspecified) | None => {
            Err(invalid("subscription event filter must be specified"))
        }
    }
}

fn memory_event_kind_to_proto(value: domain::MemoryEventKind) -> i32 {
    (match value {
        domain::MemoryEventKind::NodeChanged => wire::MemoryEventKind::NodeChanged,
        domain::MemoryEventKind::ClaimChanged => wire::MemoryEventKind::ClaimChanged,
        domain::MemoryEventKind::OpenLoopTriggered => wire::MemoryEventKind::OpenLoopTriggered,
        domain::MemoryEventKind::IndexWatermarkAdvanced => {
            wire::MemoryEventKind::IndexWatermarkAdvanced
        }
        domain::MemoryEventKind::ConflictResolved => wire::MemoryEventKind::ConflictResolved,
        domain::MemoryEventKind::SourceInvalidated => wire::MemoryEventKind::SourceInvalidated,
        domain::MemoryEventKind::OperationProgress => wire::MemoryEventKind::OperationProgress,
        domain::MemoryEventKind::SecurityEvent => wire::MemoryEventKind::SecurityEvent,
        domain::MemoryEventKind::ObservationAccepted => wire::MemoryEventKind::ObservationAccepted,
        domain::MemoryEventKind::RecordChanged => wire::MemoryEventKind::RecordChanged,
    }) as i32
}

/// Converts a subscription request to the authenticated domain contract.
pub fn subscribe_request_from_proto(
    value: wire::SubscribeRequest,
) -> domain::ServiceResult<domain::SubscribeRequest> {
    let context =
        authenticated_context_from_proto(required(value.context, "context is required")?)?;
    let mut filters = BTreeSet::new();
    for value in value.filters {
        if !filters.insert(memory_event_kind(value)?) {
            return Err(invalid("subscription filter appears more than once"));
        }
    }
    Ok(domain::SubscribeRequest {
        context,
        filters,
        resume_cursor: value.resume_cursor,
        max_events: value.max_events,
    })
}

/// Converts one finite subscription page into ordered event deliveries followed
/// by an explicit cursor checkpoint. Every event delivery therefore has a
/// stable non-empty event ID; checkpoints are never disguised as events.
#[must_use]
pub fn subscription_page_to_proto(
    value: domain::SubscriptionPage,
) -> Vec<wire::SubscriptionDelivery> {
    let mut deliveries: Vec<_> = value
        .events
        .into_iter()
        .map(|event| wire::SubscriptionDelivery {
            value: Some(wire::subscription_delivery::Value::Event(
                wire::MemoryEvent {
                    event_id: event.event_id,
                    commit_seq: event.commit_seq,
                    ordinal: event.ordinal,
                    kind: memory_event_kind_to_proto(event.kind),
                    object_refs: event.object_refs,
                    attributes: event
                        .attributes
                        .into_iter()
                        .map(|(key, value)| wire::StringEntry { key, value })
                        .collect(),
                },
            )),
        })
        .collect();
    deliveries.push(wire::SubscriptionDelivery {
        value: Some(wire::subscription_delivery::Value::Checkpoint(
            wire::SubscriptionCheckpoint {
                resume_cursor: value.resume_cursor,
                caught_up: value.caught_up,
            },
        )),
    });
    deliveries
}

fn memory_record_kind(value: i32) -> domain::ServiceResult<domain::MemoryRecordKind> {
    match wire::MemoryRecordKind::try_from(value).ok() {
        Some(wire::MemoryRecordKind::Node) => Ok(domain::MemoryRecordKind::Node),
        Some(wire::MemoryRecordKind::Claim) => Ok(domain::MemoryRecordKind::Claim),
        Some(wire::MemoryRecordKind::Edge) => Ok(domain::MemoryRecordKind::Edge),
        Some(wire::MemoryRecordKind::Conflict) => Ok(domain::MemoryRecordKind::Conflict),
        Some(wire::MemoryRecordKind::Evidence) => Ok(domain::MemoryRecordKind::Evidence),
        Some(wire::MemoryRecordKind::Candidate) => Ok(domain::MemoryRecordKind::Candidate),
        Some(wire::MemoryRecordKind::SemanticObject) => {
            Ok(domain::MemoryRecordKind::SemanticObject)
        }
        Some(wire::MemoryRecordKind::RuntimeState) => Ok(domain::MemoryRecordKind::RuntimeState),
        Some(wire::MemoryRecordKind::DomainExtension) => {
            Ok(domain::MemoryRecordKind::DomainExtension)
        }
        Some(wire::MemoryRecordKind::Unspecified) | None => {
            Err(invalid("memory record kind must be specified"))
        }
    }
}

fn memory_record_kind_to_proto(value: domain::MemoryRecordKind) -> i32 {
    (match value {
        domain::MemoryRecordKind::Node => wire::MemoryRecordKind::Node,
        domain::MemoryRecordKind::Claim => wire::MemoryRecordKind::Claim,
        domain::MemoryRecordKind::Edge => wire::MemoryRecordKind::Edge,
        domain::MemoryRecordKind::Conflict => wire::MemoryRecordKind::Conflict,
        domain::MemoryRecordKind::Evidence => wire::MemoryRecordKind::Evidence,
        domain::MemoryRecordKind::Candidate => wire::MemoryRecordKind::Candidate,
        domain::MemoryRecordKind::SemanticObject => wire::MemoryRecordKind::SemanticObject,
        domain::MemoryRecordKind::RuntimeState => wire::MemoryRecordKind::RuntimeState,
        domain::MemoryRecordKind::DomainExtension => wire::MemoryRecordKind::DomainExtension,
    }) as i32
}

fn memory_lifecycle(value: i32) -> domain::ServiceResult<domain::MemoryLifecycle> {
    match wire::MemoryLifecycle::try_from(value).ok() {
        Some(wire::MemoryLifecycle::Active) => Ok(domain::MemoryLifecycle::Active),
        Some(wire::MemoryLifecycle::Superseded) => Ok(domain::MemoryLifecycle::Superseded),
        Some(wire::MemoryLifecycle::Retracted) => Ok(domain::MemoryLifecycle::Retracted),
        Some(wire::MemoryLifecycle::Suppressed) => Ok(domain::MemoryLifecycle::Suppressed),
        Some(wire::MemoryLifecycle::Unspecified) | None => {
            Err(invalid("memory lifecycle must be specified"))
        }
    }
}

fn memory_lifecycle_to_proto(value: domain::MemoryLifecycle) -> i32 {
    (match value {
        domain::MemoryLifecycle::Active => wire::MemoryLifecycle::Active,
        domain::MemoryLifecycle::Superseded => wire::MemoryLifecycle::Superseded,
        domain::MemoryLifecycle::Retracted => wire::MemoryLifecycle::Retracted,
        domain::MemoryLifecycle::Suppressed => wire::MemoryLifecycle::Suppressed,
    }) as i32
}

fn parse_i128(value: Option<String>) -> domain::ServiceResult<Option<i128>> {
    value
        .map(|value| {
            value
                .parse::<i128>()
                .map_err(|_| invalid("domain time is not a canonical signed integer"))
        })
        .transpose()
}

fn memory_document_from_proto(
    value: wire::MemoryDocument,
) -> domain::ServiceResult<domain::MemoryDocument> {
    let valid_time = required(value.valid_time, "domain-time range is required")?;
    let links = required(value.links, "memory links are required")?;
    let mut attributes = BTreeMap::new();
    for entry in value.attributes {
        if attributes
            .insert(entry.key, canonical_json(&entry.canonical_json)?)
            .is_some()
        {
            return Err(invalid("memory attribute appears more than once"));
        }
    }
    Ok(domain::MemoryDocument {
        id: value.id,
        kind: memory_record_kind(value.kind)?,
        access: access_from_proto(required(value.access, "access policy is required")?)?,
        valid_time: domain::DomainTimeRange {
            from: parse_i128(valid_time.from_unix_nanos)?,
            to: parse_i128(valid_time.to_unix_nanos)?,
        },
        lifecycle: memory_lifecycle(value.lifecycle)?,
        links: domain::MemoryLinks {
            subject: links.subject,
            source: links.source,
            target: links.target,
            predicate: links.predicate,
            conflict_set: links.conflict_set,
            supersedes: set(links.supersedes)?,
            evidence: set(links.evidence)?,
            conflict_members: set(links.conflict_members)?,
            single_valued: links.single_valued,
        },
        value: canonical_json(&value.value_json)?,
        search_text: value.search_text,
        vector: (!value.vector.is_empty()).then_some(value.vector),
        attributes,
    })
}

/// Converts a complete typed memory document to Protobuf.
pub fn memory_document_to_proto(
    value: domain::MemoryDocument,
) -> domain::ServiceResult<wire::MemoryDocument> {
    Ok(wire::MemoryDocument {
        id: value.id,
        kind: memory_record_kind_to_proto(value.kind),
        access: Some(access_to_proto(value.access)),
        valid_time: Some(wire::DomainTimeRange {
            from_unix_nanos: value.valid_time.from.map(|value| value.to_string()),
            to_unix_nanos: value.valid_time.to.map(|value| value.to_string()),
        }),
        lifecycle: memory_lifecycle_to_proto(value.lifecycle),
        links: Some(wire::MemoryLinks {
            subject: value.links.subject,
            source: value.links.source,
            target: value.links.target,
            predicate: value.links.predicate,
            conflict_set: value.links.conflict_set,
            supersedes: value.links.supersedes.into_iter().collect(),
            evidence: value.links.evidence.into_iter().collect(),
            conflict_members: value.links.conflict_members.into_iter().collect(),
            single_valued: value.links.single_valued,
        }),
        value_json: serde_json::to_vec(&value.value)
            .map_err(|_| invalid("memory value cannot be serialized"))?,
        search_text: value.search_text,
        vector: value.vector.unwrap_or_default(),
        attributes: value
            .attributes
            .into_iter()
            .map(|(key, value)| {
                serde_json::to_vec(&value)
                    .map(|canonical_json| wire::JsonEntry {
                        key,
                        canonical_json,
                    })
                    .map_err(|_| invalid("memory attribute cannot be serialized"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Converts a typed correction request, authenticating context before content.
pub fn correct_request_from_proto(
    value: wire::CorrectRequest,
) -> domain::ServiceResult<domain::CorrectRequest> {
    let context =
        authenticated_context_from_proto(required(value.context, "context is required")?)?;
    Ok(domain::CorrectRequest {
        context,
        idempotency_key: value.idempotency_key,
        target_id: value.target_id,
        replacement: memory_document_from_proto(required(
            value.replacement,
            "replacement document is required",
        )?)?,
    })
}

/// Converts a typed correction request to Protobuf.
pub fn correct_request_to_proto(
    value: domain::CorrectRequest,
) -> domain::ServiceResult<wire::CorrectRequest> {
    Ok(wire::CorrectRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        idempotency_key: value.idempotency_key,
        target_id: value.target_id,
        replacement: Some(memory_document_to_proto(value.replacement)?),
    })
}

/// Converts a typed forget request.
pub fn forget_request_from_proto(
    value: wire::ForgetRequest,
) -> domain::ServiceResult<domain::ForgetRequest> {
    let context =
        authenticated_context_from_proto(required(value.context, "context is required")?)?;
    let mode = match wire::ForgetMode::try_from(value.mode).ok() {
        Some(wire::ForgetMode::Retract) => domain::ForgetMode::Retract,
        Some(wire::ForgetMode::HardDelete) => domain::ForgetMode::HardDelete,
        Some(wire::ForgetMode::Unspecified) | None => {
            return Err(invalid("forget mode must be specified"));
        }
    };
    Ok(domain::ForgetRequest {
        context,
        idempotency_key: value.idempotency_key,
        target_id: value.target_id,
        mode,
        reason: value.reason,
    })
}

/// Converts a typed forget request to Protobuf.
#[must_use]
pub fn forget_request_to_proto(value: domain::ForgetRequest) -> wire::ForgetRequest {
    wire::ForgetRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        idempotency_key: value.idempotency_key,
        target_id: value.target_id,
        mode: match value.mode {
            domain::ForgetMode::Retract => wire::ForgetMode::Retract,
            domain::ForgetMode::HardDelete => wire::ForgetMode::HardDelete,
        } as i32,
        reason: value.reason,
    }
}

/// Converts a semantic mutation receipt to Protobuf.
#[must_use]
pub fn mutation_response_to_proto(value: domain::MutationResponse) -> wire::MutationResponse {
    wire::MutationResponse {
        commit_seq: value.commit_seq,
        replayed: value.replayed,
        request_digest: value.request_digest,
        watermarks: Some(watermarks_to_proto(value.watermarks)),
    }
}

/// Converts a typed point lookup request.
pub fn get_memory_request_from_proto(
    value: wire::GetMemoryRequest,
) -> domain::ServiceResult<domain::GetMemoryRequest> {
    Ok(domain::GetMemoryRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
        record_id: value.record_id,
        at_commit: value.at_commit,
    })
}

/// Converts a typed point lookup request to Protobuf.
#[must_use]
pub fn get_memory_request_to_proto(value: domain::GetMemoryRequest) -> wire::GetMemoryRequest {
    wire::GetMemoryRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        record_id: value.record_id,
        at_commit: value.at_commit,
    }
}

/// Converts a typed timeline request.
pub fn get_timeline_request_from_proto(
    value: wire::GetTimelineRequest,
) -> domain::ServiceResult<domain::GetTimelineRequest> {
    Ok(domain::GetTimelineRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
        record_id: value.record_id,
        expected_kind: memory_record_kind(value.expected_kind)?,
        at_commit: value.at_commit,
        max_revisions: value.max_revisions,
    })
}

/// Converts a typed timeline request to Protobuf.
#[must_use]
pub fn get_timeline_request_to_proto(
    value: domain::GetTimelineRequest,
) -> wire::GetTimelineRequest {
    wire::GetTimelineRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        record_id: value.record_id,
        expected_kind: memory_record_kind_to_proto(value.expected_kind),
        at_commit: value.at_commit,
        max_revisions: value.max_revisions,
    }
}

/// Converts a bounded traversal request.
pub fn traverse_request_from_proto(
    value: wire::TraverseRequest,
) -> domain::ServiceResult<domain::TraverseRequest> {
    let context =
        authenticated_context_from_proto(required(value.context, "context is required")?)?;
    let direction = match wire::TraverseDirection::try_from(value.direction).ok() {
        Some(wire::TraverseDirection::Outgoing) => domain::TraverseDirection::Outgoing,
        Some(wire::TraverseDirection::Incoming) => domain::TraverseDirection::Incoming,
        Some(wire::TraverseDirection::Both) => domain::TraverseDirection::Both,
        Some(wire::TraverseDirection::Unspecified) | None => {
            return Err(invalid("traversal direction must be specified"));
        }
    };
    let max_hops =
        u8::try_from(value.max_hops).map_err(|_| invalid("traversal hop budget exceeds uint8"))?;
    Ok(domain::TraverseRequest {
        context,
        start_ids: value.start_ids,
        direction,
        predicate_ids: set(value.predicate_ids)?,
        max_hops,
        max_nodes: value.max_nodes,
        at_commit: value.at_commit,
    })
}

/// Converts a bounded traversal request to Protobuf.
#[must_use]
pub fn traverse_request_to_proto(value: domain::TraverseRequest) -> wire::TraverseRequest {
    wire::TraverseRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        start_ids: value.start_ids,
        direction: match value.direction {
            domain::TraverseDirection::Outgoing => wire::TraverseDirection::Outgoing,
            domain::TraverseDirection::Incoming => wire::TraverseDirection::Incoming,
            domain::TraverseDirection::Both => wire::TraverseDirection::Both,
        } as i32,
        predicate_ids: value.predicate_ids.into_iter().collect(),
        max_hops: u32::from(value.max_hops),
        max_nodes: value.max_nodes,
        at_commit: value.at_commit,
    }
}

/// Converts one authorized memory record to Protobuf.
pub fn memory_record_to_proto(
    value: domain::MemoryRecord,
) -> domain::ServiceResult<wire::MemoryRecord> {
    Ok(wire::MemoryRecord {
        document: Some(memory_document_to_proto(value.document)?),
        revision: value.revision,
        transaction_from: value.transaction_from,
        transaction_to: value.transaction_to,
    })
}

/// Converts a typed timeline response to Protobuf.
pub fn timeline_response_to_proto(
    value: domain::TimelineResponse,
) -> domain::ServiceResult<wire::TimelineResponse> {
    Ok(wire::TimelineResponse {
        revisions: value
            .revisions
            .into_iter()
            .map(memory_record_to_proto)
            .collect::<Result<Vec<_>, _>>()?,
        snapshot_seq: value.snapshot_seq,
        watermarks: Some(watermarks_to_proto(value.watermarks)),
    })
}

/// Converts a graph traversal response to Protobuf.
#[must_use]
pub fn traverse_response_to_proto(value: domain::TraverseResponse) -> wire::TraverseResponse {
    wire::TraverseResponse {
        node_ids: value.node_ids,
        snapshot_seq: value.snapshot_seq,
        authorized_candidates: value.authorized_candidates,
        watermarks: Some(watermarks_to_proto(value.watermarks)),
    }
}

/// Converts one method-specific runtime request after its authenticated context.
pub fn runtime_request_from_proto(
    value: wire::RuntimeRequest,
) -> domain::ServiceResult<domain::RuntimeRequest> {
    let context =
        authenticated_context_from_proto(required(value.context, "context is required")?)?;
    Ok(domain::RuntimeRequest {
        context,
        operation_id: value.operation_id,
        payload: canonical_json(&value.payload_json)?,
    })
}

/// Converts one runtime response to Protobuf.
pub fn runtime_response_to_proto(
    value: domain::RuntimeResponse,
) -> domain::ServiceResult<wire::RuntimeResponse> {
    Ok(wire::RuntimeResponse {
        operation_id: value.operation_id,
        payload_json: serde_json::to_vec(&value.payload)
            .map_err(|_| invalid("runtime response cannot be serialized"))?,
    })
}

/// Converts one method-specific maintenance request.
pub fn maintenance_request_from_proto(
    value: wire::MaintenanceRequest,
) -> domain::ServiceResult<domain::MaintenanceRequest> {
    let context =
        authenticated_context_from_proto(required(value.context, "context is required")?)?;
    Ok(domain::MaintenanceRequest {
        context,
        operation_id: value.operation_id,
        payload: canonical_json(&value.payload_json)?,
    })
}

/// Converts one maintenance response to Protobuf.
pub fn maintenance_response_to_proto(
    value: domain::MaintenanceResponse,
) -> domain::ServiceResult<wire::MaintenanceResponse> {
    Ok(wire::MaintenanceResponse {
        operation_id: value.operation_id,
        payload_json: serde_json::to_vec(&value.payload)
            .map_err(|_| invalid("maintenance response cannot be serialized"))?,
    })
}

/// Converts an authenticated status request.
pub fn status_request_from_proto(
    value: wire::GetStatusRequest,
) -> domain::ServiceResult<domain::GetStatusRequest> {
    Ok(domain::GetStatusRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
    })
}

/// Converts an authenticated status request to Protobuf.
#[must_use]
pub fn status_request_to_proto(value: domain::GetStatusRequest) -> wire::GetStatusRequest {
    wire::GetStatusRequest {
        context: Some(authenticated_context_to_proto(value.context)),
    }
}

/// Converts administrative status to Protobuf.
#[must_use]
pub fn status_response_to_proto(value: domain::StatusResponse) -> wire::StatusResponse {
    wire::StatusResponse {
        schema_version: u32::from(value.schema_version),
        profile: value.profile,
        commit_seq: value.commit_seq,
        watermarks: Some(watermarks_to_proto(value.watermarks)),
        capability_manifest: Some(capability_manifest_to_proto(value.capability_manifest)),
    }
}

fn capability_manifest_to_proto(value: domain::CapabilityManifestV1) -> wire::CapabilityManifestV1 {
    wire::CapabilityManifestV1 {
        schema_version: u32::from(value.schema_version),
        profile: value.profile,
        server_v1_release_ready: value.server_v1_release_ready,
        capabilities: value
            .capabilities
            .into_iter()
            .map(|(capability, state)| {
                let state = match state {
                    domain::CapabilityState::Available => wire::RuntimeCapabilityState::Available,
                    domain::CapabilityState::CompiledOnly => {
                        wire::RuntimeCapabilityState::CompiledOnly
                    }
                    domain::CapabilityState::Unsupported => {
                        wire::RuntimeCapabilityState::Unsupported
                    }
                };
                (capability, state as i32)
            })
            .collect(),
    }
}

/// Converts an authenticated backup request.
pub fn backup_request_from_proto(
    value: wire::CreateBackupRequest,
) -> domain::ServiceResult<domain::CreateBackupRequest> {
    Ok(domain::CreateBackupRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
    })
}

/// Converts an authenticated backup request to Protobuf.
#[must_use]
pub fn backup_request_to_proto(value: domain::CreateBackupRequest) -> wire::CreateBackupRequest {
    wire::CreateBackupRequest {
        context: Some(authenticated_context_to_proto(value.context)),
    }
}

/// Converts a canonical logical backup to Protobuf.
#[must_use]
pub fn backup_response_to_proto(value: domain::BackupResponse) -> wire::BackupResponse {
    wire::BackupResponse {
        format: value.format,
        archive: value.bytes,
        digest: value.digest,
        commit_seq: value.commit_seq,
    }
}

/// Converts an authenticated restore request.
pub fn restore_request_from_proto(
    value: wire::RestoreBackupRequest,
) -> domain::ServiceResult<domain::RestoreBackupRequest> {
    if value.archive.len() > crate::MAX_WIRE_BYTES {
        return Err(domain::ServiceError::new(
            domain::ErrorCode::ResourceExhausted,
            "backup exceeds the wire limit",
            false,
        ));
    }
    Ok(domain::RestoreBackupRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
        format: value.format,
        bytes: value.archive,
        digest: value.digest,
    })
}

/// Converts a restore receipt to Protobuf.
#[must_use]
pub fn restore_response_to_proto(
    value: domain::RestoreBackupResponse,
) -> wire::RestoreBackupResponse {
    wire::RestoreBackupResponse {
        commit_seq: value.commit_seq,
        watermarks: Some(watermarks_to_proto(value.watermarks)),
    }
}

/// Converts an authenticated format-migration request.
pub fn migrate_request_from_proto(
    value: wire::MigrateFormatRequest,
) -> domain::ServiceResult<domain::MigrateFormatRequest> {
    Ok(domain::MigrateFormatRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
        target_format: value.target_format,
        operation_id: value.operation_id,
    })
}

/// Converts a Protobuf recall request.
pub fn recall_request_from_proto(
    value: wire::RecallRequest,
) -> domain::ServiceResult<domain::RecallRequest> {
    Ok(domain::RecallRequest {
        context: request_context_from_proto(required(value.context, "context is required")?)?,
        query: value.query,
        page_size: value.page_size,
        at_commit: value.at_commit,
        continuation: value.continuation,
    })
}

/// Converts an embedded recall request to Protobuf.
#[must_use]
pub fn recall_request_to_proto(value: domain::RecallRequest) -> wire::RecallRequest {
    wire::RecallRequest {
        context: Some(request_context_to_proto(value.context)),
        query: value.query,
        page_size: value.page_size,
        at_commit: value.at_commit,
        continuation: value.continuation,
    }
}

/// Converts a first-class ContextPack request, authenticating its context
/// before decoding any query, vector, or model-profile content.
pub fn compile_context_request_from_proto(
    value: wire::CompileContextRequest,
) -> domain::ServiceResult<domain::CompileContextRequest> {
    let context =
        authenticated_context_from_proto(required(value.context, "context is required")?)?;
    let plan = serde_json::from_value(canonical_json(&value.plan_json)?)
        .map_err(|_| invalid("ContextPack plan violates the typed contract"))?;
    Ok(domain::CompileContextRequest { context, plan })
}

/// Converts a typed ContextPack request into its canonical gRPC envelope.
pub fn compile_context_request_to_proto(
    value: domain::CompileContextRequest,
) -> domain::ServiceResult<wire::CompileContextRequest> {
    let plan = serde_json::to_value(value.plan)
        .map_err(|_| invalid("ContextPack plan cannot be serialized"))?;
    Ok(wire::CompileContextRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        plan_json: serde_json::to_vec(&plan)
            .map_err(|_| invalid("ContextPack plan cannot be serialized"))?,
    })
}

fn serialized_enum_name<T: serde::Serialize>(value: T) -> domain::ServiceResult<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| {
            domain::ServiceError::new(
                domain::ErrorCode::IntegrityFailure,
                "ContextPack enum cannot be serialized",
                false,
            )
        })
}

/// Converts the canonical ContextPack result and its privacy-safe trace to the
/// public gRPC response without flattening trusted and untrusted rendering.
pub fn compile_context_response_to_proto(
    value: domain::CompileContextResponse,
) -> domain::ServiceResult<wire::CompileContextResponse> {
    value.context_pack.validate().map_err(|_| {
        domain::ServiceError::new(
            domain::ErrorCode::IntegrityFailure,
            "ContextPack violates canonical invariants",
            false,
        )
    })?;
    let context_pack_json = serde_json::to_vec(&value.context_pack).map_err(|_| {
        domain::ServiceError::new(
            domain::ErrorCode::IntegrityFailure,
            "ContextPack cannot be canonically serialized",
            false,
        )
    })?;
    let renderer = serialized_enum_name(value.rendered.renderer)?;
    let recall_status = serialized_enum_name(value.trace.recall_status)?;
    let stop_reason = serialized_enum_name(value.trace.stop_reason)?;
    let pack_status = serialized_enum_name(value.trace.pack_status)?;
    Ok(wire::CompileContextResponse {
        context_pack_json,
        canonical_digest: value.canonical_digest,
        rendered: Some(wire::RenderedContextPayload {
            profile_id: value.rendered.profile_id,
            renderer,
            trusted_control: value.rendered.trusted_control,
            untrusted_data: value.rendered.untrusted_data,
            control_tokens: value.rendered.control_tokens,
            data_tokens: value.rendered.data_tokens,
            total_tokens: value.rendered.total_tokens,
        }),
        continuation: value.continuation,
        trace: Some(wire::ContextPackTrace {
            trace_id: value.trace.trace_id,
            database_id: value.trace.snapshot.database_id,
            snapshot_seq: value.trace.snapshot.commit_seq,
            filter_digest: value.trace.filter_digest,
            recall_status,
            stop_reason,
            recall_usage: Some(wire::RecallBudgetUsage {
                nodes_examined: value.trace.recall_usage.nodes_examined,
                graph_edges_examined: value.trace.recall_usage.graph_edges_examined,
                max_hop_reached: u32::from(value.trace.recall_usage.max_hop_reached),
                evidence_units: value.trace.recall_usage.evidence_units,
                context_tokens: value.trace.recall_usage.context_tokens,
            }),
            pack_status,
            pack_usage: Some(wire::ContextBudgetUsage {
                rendered_tokens: value.trace.pack_usage.rendered_tokens,
                control_tokens: value.trace.pack_usage.control_tokens,
                data_tokens: value.trace.pack_usage.data_tokens,
                blocks: value.trace.pack_usage.blocks,
                evidence_blocks: value.trace.pack_usage.evidence_blocks,
                raw_evidence_tokens: value.trace.pack_usage.raw_evidence_tokens,
                history_tokens: value.trace.pack_usage.history_tokens,
                conflict_tokens: value.trace.pack_usage.conflict_tokens,
                serialized_bytes: value.trace.pack_usage.serialized_bytes,
                selection_evaluations: value.trace.pack_usage.selection_evaluations,
            }),
            selected_blocks: value.trace.selected_blocks,
            evidence_blocks: value.trace.evidence_blocks,
            max_projection_lag_commits: value.trace.max_projection_lag_commits,
            stale: value.trace.stale,
            freshness_warnings: value.trace.freshness_warnings,
        }),
        canonical_bytes: value.canonical_bytes,
        canonical_encoding: value.canonical_encoding,
        canonical_digest_algorithm: value.canonical_digest_algorithm,
    })
}

/// Converts an explain request.
pub fn explain_request_from_proto(
    value: wire::ExplainRecallRequest,
) -> domain::ServiceResult<domain::ExplainRecallRequest> {
    Ok(domain::ExplainRecallRequest {
        context: request_context_from_proto(required(value.context, "context is required")?)?,
        trace: trace_from_proto(required(value.trace, "recall trace is required")?)?,
    })
}

/// Converts an export request.
pub fn export_request_from_proto(
    value: wire::ExportRequest,
) -> domain::ServiceResult<domain::ExportRequest> {
    Ok(domain::ExportRequest {
        context: request_context_from_proto(required(value.context, "context is required")?)?,
    })
}

/// Converts an import request.
pub fn import_request_from_proto(
    value: wire::ImportRequest,
) -> domain::ServiceResult<domain::ImportRequest> {
    if value.archive.len() > crate::MAX_WIRE_BYTES {
        return Err(domain::ServiceError::new(
            domain::ErrorCode::ResourceExhausted,
            "archive exceeds the wire limit",
            false,
        ));
    }
    Ok(domain::ImportRequest {
        context: request_context_from_proto(required(value.context, "context is required")?)?,
        format: value.format,
        bytes: value.archive,
        digest: value.digest,
    })
}

/// Converts a verify request.
pub fn verify_request_from_proto(
    value: wire::VerifyRequest,
) -> domain::ServiceResult<domain::VerifyRequest> {
    Ok(domain::VerifyRequest {
        context: request_context_from_proto(required(value.context, "context is required")?)?,
        deep: value.deep,
    })
}

fn watermarks_to_proto(value: domain::Watermarks) -> wire::Watermarks {
    wire::Watermarks {
        journal: value.journal,
        semantic: value.semantic,
        lexical: value.lexical,
        vector: value.vector,
        graph: value.graph,
    }
}

fn watermarks_from_proto(value: wire::Watermarks) -> domain::Watermarks {
    domain::Watermarks {
        journal: value.journal,
        semantic: value.semantic,
        lexical: value.lexical,
        vector: value.vector,
        graph: value.graph,
    }
}

/// Converts an observe response to Protobuf.
#[must_use]
pub fn observe_response_to_proto(value: domain::ObserveResponse) -> wire::ObserveResponse {
    wire::ObserveResponse {
        commit_seq: value.commit_seq,
        replayed: value.replayed,
        request_digest: value.request_digest,
        watermarks: Some(watermarks_to_proto(value.watermarks)),
    }
}

/// Converts a Protobuf observe response to the embedded type.
pub fn observe_response_from_proto(
    value: wire::ObserveResponse,
) -> domain::ServiceResult<domain::ObserveResponse> {
    Ok(domain::ObserveResponse {
        commit_seq: value.commit_seq,
        replayed: value.replayed,
        request_digest: value.request_digest,
        watermarks: watermarks_from_proto(required(value.watermarks, "watermarks are required")?),
    })
}

fn trace_to_proto(value: domain::RecallTrace) -> wire::RecallTrace {
    wire::RecallTrace {
        trace_id: value.trace_id,
        snapshot_seq: value.snapshot_seq,
        operation: value.operation,
        authorized_candidates: value.authorized_candidates,
        selected_ids: value.selected_ids,
        watermarks: Some(watermarks_to_proto(value.watermarks)),
    }
}

fn trace_from_proto(value: wire::RecallTrace) -> domain::ServiceResult<domain::RecallTrace> {
    Ok(domain::RecallTrace {
        trace_id: value.trace_id,
        snapshot_seq: value.snapshot_seq,
        operation: value.operation,
        authorized_candidates: value.authorized_candidates,
        selected_ids: value.selected_ids,
        watermarks: watermarks_from_proto(required(value.watermarks, "watermarks are required")?),
    })
}

/// Converts a recall response to Protobuf.
#[must_use]
pub fn recall_response_to_proto(value: domain::RecallResponse) -> wire::RecallResponse {
    wire::RecallResponse {
        hits: value
            .hits
            .into_iter()
            .map(|hit| wire::RecallHit {
                id: hit.id,
                score: hit.score,
            })
            .collect(),
        trace: Some(trace_to_proto(value.trace)),
        continuation: value.continuation,
    }
}

/// Converts a Protobuf recall response to the embedded type.
pub fn recall_response_from_proto(
    value: wire::RecallResponse,
) -> domain::ServiceResult<domain::RecallResponse> {
    Ok(domain::RecallResponse {
        hits: value
            .hits
            .into_iter()
            .map(|hit| domain::RecallHit {
                id: hit.id,
                score: hit.score,
            })
            .collect(),
        trace: trace_from_proto(required(value.trace, "recall trace is required")?)?,
        continuation: value.continuation,
    })
}

/// Converts one authenticated high-level write request after transport auth.
pub fn high_level_write_request_from_proto(
    value: wire::HighLevelWriteRequest,
) -> domain::ServiceResult<domain::HighLevelWriteRequest> {
    Ok(domain::HighLevelWriteRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
        idempotency_key: value.idempotency_key,
        target_subject_id: value.target_subject_id,
        session_id: value.session_id,
        logical_id: value.logical_id,
        access: access_from_proto(required(value.access, "access policy is required")?)?,
        payload: canonical_json(&value.payload_json)?,
        references: set(value.references)?,
    })
}

/// Converts one high-level write request to canonical Protobuf.
pub fn high_level_write_request_to_proto(
    value: domain::HighLevelWriteRequest,
) -> domain::ServiceResult<wire::HighLevelWriteRequest> {
    Ok(wire::HighLevelWriteRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        idempotency_key: value.idempotency_key,
        target_subject_id: value.target_subject_id,
        session_id: value.session_id,
        logical_id: value.logical_id,
        access: Some(access_to_proto(value.access)),
        payload_json: serde_json::to_vec(&value.payload)
            .map_err(|_| invalid("high-level payload cannot be serialized"))?,
        references: value.references.into_iter().collect(),
    })
}

/// Converts one authenticated high-level query after transport auth.
pub fn high_level_query_request_from_proto(
    value: wire::HighLevelQueryRequest,
) -> domain::ServiceResult<domain::HighLevelQueryRequest> {
    Ok(domain::HighLevelQueryRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
        target_subject_id: value.target_subject_id,
        cue: value.cue,
        page_size: value.page_size,
        at_commit: value.at_commit,
        continuation: value.continuation,
    })
}

/// Converts one high-level query request to canonical Protobuf.
#[must_use]
pub fn high_level_query_request_to_proto(
    value: domain::HighLevelQueryRequest,
) -> wire::HighLevelQueryRequest {
    wire::HighLevelQueryRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        target_subject_id: value.target_subject_id,
        cue: value.cue,
        page_size: value.page_size,
        at_commit: value.at_commit,
        continuation: value.continuation,
    }
}

/// Converts one authenticated high-level control after transport auth.
pub fn high_level_control_request_from_proto(
    value: wire::HighLevelControlRequest,
) -> domain::ServiceResult<domain::HighLevelControlRequest> {
    Ok(domain::HighLevelControlRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
        idempotency_key: value.idempotency_key,
        target_subject_id: value.target_subject_id,
        target_id: value.target_id,
        parameters: canonical_json(&value.parameters_json)?,
    })
}

/// Converts one high-level control request to canonical Protobuf.
pub fn high_level_control_request_to_proto(
    value: domain::HighLevelControlRequest,
) -> domain::ServiceResult<wire::HighLevelControlRequest> {
    Ok(wire::HighLevelControlRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        idempotency_key: value.idempotency_key,
        target_subject_id: value.target_subject_id,
        target_id: value.target_id,
        parameters_json: serde_json::to_vec(&value.parameters)
            .map_err(|_| invalid("high-level parameters cannot be serialized"))?,
    })
}

/// Converts one authenticated subject transfer after transport auth.
pub fn high_level_transfer_request_from_proto(
    value: wire::HighLevelTransferRequest,
) -> domain::ServiceResult<domain::HighLevelTransferRequest> {
    if value.archive.len() > crate::MAX_WIRE_BYTES {
        return Err(domain::ServiceError::new(
            domain::ErrorCode::ResourceExhausted,
            "subject archive exceeds the wire limit",
            false,
        ));
    }
    Ok(domain::HighLevelTransferRequest {
        context: authenticated_context_from_proto(required(value.context, "context is required")?)?,
        idempotency_key: value.idempotency_key,
        target_subject_id: value.target_subject_id,
        format: value.format,
        bytes: value.archive,
        digest: value.digest,
    })
}

/// Converts one subject transfer request to canonical Protobuf.
#[must_use]
pub fn high_level_transfer_request_to_proto(
    value: domain::HighLevelTransferRequest,
) -> wire::HighLevelTransferRequest {
    wire::HighLevelTransferRequest {
        context: Some(authenticated_context_to_proto(value.context)),
        idempotency_key: value.idempotency_key,
        target_subject_id: value.target_subject_id,
        format: value.format,
        archive: value.bytes,
        digest: value.digest,
    }
}

/// Converts a durable high-level mutation receipt to canonical Protobuf.
#[must_use]
pub fn high_level_mutation_response_to_proto(
    value: domain::HighLevelMutationResponse,
) -> wire::HighLevelMutationResponse {
    wire::HighLevelMutationResponse {
        operation: value.operation,
        logical_id: value.logical_id,
        policy_result: match value.policy_result {
            domain::HighLevelPolicyResult::Accepted => wire::HighLevelPolicyResult::Accepted,
        } as i32,
        semantic_status: match value.semantic_status {
            domain::HighLevelSemanticStatus::Pending => wire::HighLevelSemanticStatus::Pending,
        } as i32,
        receipt: Some(observe_response_to_proto(value.receipt)),
    }
}

/// Converts a trace to Protobuf.
#[must_use]
pub fn recall_trace_to_proto(value: domain::RecallTrace) -> wire::RecallTrace {
    trace_to_proto(value)
}

/// Converts an export response to Protobuf.
#[must_use]
pub fn export_response_to_proto(value: domain::ExportResponse) -> wire::ExportResponse {
    wire::ExportResponse {
        format: value.format,
        archive: value.bytes,
        digest: value.digest,
        commit_seq: value.commit_seq,
    }
}

/// Converts an import response to Protobuf.
#[must_use]
pub fn import_response_to_proto(value: domain::ImportResponse) -> wire::ImportResponse {
    wire::ImportResponse {
        commit_seq: value.commit_seq,
        watermarks: Some(watermarks_to_proto(value.watermarks)),
    }
}

/// Converts a verify response to Protobuf.
#[must_use]
pub fn verify_response_to_proto(value: domain::VerifyResponse) -> wire::VerifyResponse {
    wire::VerifyResponse {
        valid: value.valid,
        commit_seq: value.commit_seq,
        archive_digest: value.archive_digest,
    }
}

/// Converts a canonical service error to a typed Protobuf stream status.
#[must_use]
pub fn error_to_proto(value: domain::ServiceError) -> wire::ErrorStatus {
    let code = match value.code {
        domain::ErrorCode::InvalidScope => wire::ErrorCode::InvalidScope,
        domain::ErrorCode::Unauthorized => wire::ErrorCode::Unauthorized,
        domain::ErrorCode::AmbiguousIdentity => wire::ErrorCode::AmbiguousIdentity,
        domain::ErrorCode::SnapshotExpired => wire::ErrorCode::SnapshotExpired,
        domain::ErrorCode::IndexTooStale => wire::ErrorCode::IndexTooStale,
        domain::ErrorCode::EvidenceRequired => wire::ErrorCode::EvidenceRequired,
        domain::ErrorCode::ConflictUnresolved => wire::ErrorCode::ConflictUnresolved,
        domain::ErrorCode::BudgetExhausted => wire::ErrorCode::BudgetExhausted,
        domain::ErrorCode::ContinuationExpired => wire::ErrorCode::ContinuationExpired,
        domain::ErrorCode::FormatIncompatible => wire::ErrorCode::FormatIncompatible,
        domain::ErrorCode::ProviderUnavailable => wire::ErrorCode::ProviderUnavailable,
        domain::ErrorCode::DegradedMode => wire::ErrorCode::DegradedMode,
        domain::ErrorCode::InvalidArgument => wire::ErrorCode::InvalidArgument,
        domain::ErrorCode::PermissionDenied => wire::ErrorCode::PermissionDenied,
        domain::ErrorCode::NotFound => wire::ErrorCode::NotFound,
        domain::ErrorCode::IdempotencyConflict => wire::ErrorCode::IdempotencyConflict,
        domain::ErrorCode::InvalidContinuation => wire::ErrorCode::InvalidContinuation,
        domain::ErrorCode::IntegrityFailure => wire::ErrorCode::IntegrityFailure,
        domain::ErrorCode::Unavailable => wire::ErrorCode::Unavailable,
        domain::ErrorCode::ResourceExhausted => wire::ErrorCode::ResourceExhausted,
        domain::ErrorCode::Unsupported => wire::ErrorCode::Unsupported,
    };
    wire::ErrorStatus {
        code: code as i32,
        message: value.message,
        retryable: value.retryable,
        partial_result_refs: value.partial_result_refs.into_vec(),
        violated_policy: value.violated_policy.map(Into::into),
        safe_next_action: value.safe_next_action.map(Into::into),
        trace_id: value.trace_id.map(Into::into),
    }
}
