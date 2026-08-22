use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use contextdb_proto::v1 as wire;
use contextdb_server::{
    Blake3GatewayAuthenticator, GATEWAY_ATTESTATION_HEADER, GATEWAY_ID_HEADER,
    GatewayAuthenticator, GatewayTransport, authenticated_context_to_proto, ingest_frame_to_proto,
    observe_request_to_proto, recall_request_to_proto,
};
use contextdb_service::{
    AuthenticatedRequestContext, AuthenticationEvidence, Capability as ServiceCapability,
    CognitiveMemoryService, Compression, ErrorCode, IngestFrame, IngestFrameValue, RequestContext,
    SnapshotComplete, SourceRevisionManifest, StreamObservation, ordered_items_digest,
};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{ConformanceError, ConformanceFixture, ConformanceResult};

const GATEWAY_KEY: [u8; 32] = [0x72; 32];
const GRPC_OBSERVE_STREAM: &str = "contextdb.v1.ObservationService/ObserveStream";
const GRPC_INGEST_SNAPSHOT: &str = "contextdb.v1.ObservationService/IngestSnapshot";
const GRPC_RECALL_STREAM: &str = "contextdb.v1.RecallService/RecallStream";
const GRPC_SUBSCRIBE: &str = "contextdb.v1.SubscriptionService/Subscribe";
static NEXT_GATEWAY_NONCE: AtomicU64 = AtomicU64::new(1);

fn unique_gateway_nonce() -> [u8; 16] {
    let mut nonce = [0_u8; 16];
    nonce[..8].copy_from_slice(
        &NEXT_GATEWAY_NONCE
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    nonce
}

/// Typed outcome of one observation-stream acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "code", rename_all = "snake_case")]
pub enum StreamAckOutcome {
    /// Observation committed or replayed.
    Success {
        /// True for exact idempotent replay.
        replayed: bool,
        /// Durable commit sequence.
        commit_seq: u64,
    },
    /// Per-item canonical failure; later items may still be acknowledged.
    Error(ErrorCode),
}

/// Evidence collected across real HTTP/2 gRPC streams.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcStreamingProof {
    /// Production acknowledgement channel window.
    pub configured_ack_window: usize,
    /// Positions returned by the server.
    pub observe_positions: Vec<u64>,
    /// Per-position success/error outcomes.
    pub observe_outcomes: Vec<StreamAckOutcome>,
    /// Ordered recall event kind names.
    pub recall_events: Vec<String>,
    /// True when one failed item did not suppress the later success ack.
    pub partial_acknowledgement: bool,
    /// True when positions are strictly 1-based and contiguous.
    pub per_stream_order: bool,
    /// True when recall emitted started, page, completed exactly once in order.
    pub recall_event_order: bool,
    /// Positions acknowledged by resumable source-snapshot ingestion.
    pub ingest_positions: Vec<u64>,
    /// Exact retry returned the same partial acknowledgement.
    pub ingest_partial_ack_idempotent: bool,
    /// Every non-manifest frame carried the preceding authenticated cursor.
    pub ingest_resume_bound: bool,
    /// Unsupported declared compression was negotiated fail-closed and the
    /// identity stream subsequently succeeded.
    pub compression_validated: bool,
    /// Source observations remained unpublished until the explicit marker.
    pub completion_gated: bool,
    /// Completion produced an explicit snapshot-committed acknowledgement.
    pub snapshot_complete: bool,
    /// Repeating an unacknowledged subscription delivery retained event IDs.
    pub subscription_event_ids_stable: bool,
    /// Resume cursor eliminated already acknowledged events.
    pub subscription_resume_dedup: bool,
    /// Event-family filters were enforced.
    pub subscription_filtering: bool,
    /// A different subject could not observe the source event.
    pub subscription_policy_first: bool,
    /// Missing authenticated-channel metadata was rejected before service use.
    pub transport_authentication_required: bool,
}

impl GrpcStreamingProof {
    /// True only when every streaming invariant was observed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.configured_ack_window > 0
            && self.partial_acknowledgement
            && self.per_stream_order
            && self.recall_event_order
            && self.ingest_positions == [0, 1, 1, 2]
            && self.ingest_partial_ack_idempotent
            && self.ingest_resume_bound
            && self.compression_validated
            && self.completion_gated
            && self.snapshot_complete
            && self.subscription_event_ids_stable
            && self.subscription_resume_dedup
            && self.subscription_filtering
            && self.subscription_policy_first
            && self.transport_authentication_required
    }
}

/// Starts the production gRPC server on an ephemeral loopback socket and proves
/// ordered partial acknowledgements plus recall event ordering over real HTTP/2.
/// The service may already contain the deterministic semantic fixture.
pub async fn prove_grpc_network_streaming(
    service: Arc<dyn CognitiveMemoryService>,
    fixture: &ConformanceFixture,
) -> ConformanceResult<GrpcStreamingProof> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
    let address = listener
        .local_addr()
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:conformance", GATEWAY_KEY)
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
    );
    let server_gateway: Arc<dyn GatewayAuthenticator> = gateway.clone();
    let server = tokio::spawn(
        contextdb_server::serve_grpc_listener_with_shutdown_and_gateway(
            listener,
            service,
            server_gateway,
            async move {
                let _ = shutdown_receiver.await;
            },
        ),
    );
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    let channel = endpoint
        .connect()
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;

    let requests = vec![
        observe_request_to_proto(fixture.visible_a.clone())
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        observe_request_to_proto(fixture.visible_a.clone())
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        observe_request_to_proto(fixture.policy_omission())
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        observe_request_to_proto(fixture.visible_b.clone())
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
    ]
    .into_iter()
    .map(|frame| attest_observe_stream_frame(gateway.as_ref(), frame))
    .collect::<ConformanceResult<Vec<_>>>()?;
    let mut observation_client =
        wire::observation_service_client::ObservationServiceClient::new(channel.clone());
    let observe_stream_request = tonic::Request::new(tokio_stream::iter(requests));
    let mut acknowledgements = observation_client
        .observe_stream(observe_stream_request)
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
        .into_inner();
    let mut positions = Vec::new();
    let mut outcomes = Vec::new();
    while let Some(acknowledgement) = acknowledgements
        .message()
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
    {
        positions.push(acknowledgement.stream_position);
        let outcome = match acknowledgement.outcome {
            Some(wire::observe_ack::Outcome::Response(response)) => StreamAckOutcome::Success {
                replayed: response.replayed,
                commit_seq: response.commit_seq,
            },
            Some(wire::observe_ack::Outcome::Error(error)) => {
                StreamAckOutcome::Error(error_code(error.code).ok_or_else(|| {
                    ConformanceError::Protocol("stream error code is unspecified".to_owned())
                })?)
            }
            None => {
                return Err(ConformanceError::Protocol(
                    "stream acknowledgement outcome is missing".to_owned(),
                ));
            }
        };
        outcomes.push(outcome);
    }

    let binding = "22".repeat(32);
    let authenticated = authenticated_context(
        fixture.caller.clone(),
        &[
            ServiceCapability::StreamIngest,
            ServiceCapability::Subscribe,
        ],
        &binding,
    );
    let stream_observation = StreamObservation {
        idempotency_key: "conformance:source-item".to_owned(),
        observation_id: "observation:source-snapshot".to_owned(),
        metadata: fixture.visible_a.metadata.clone(),
        content: serde_json::json!({"text": "authenticated resumable source snapshot"}),
        access: fixture.visible_a.access.clone(),
    };
    let source_digest = ordered_items_digest(std::slice::from_ref(&stream_observation))
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    let compressed_manifest = IngestFrame {
        context: authenticated.clone(),
        stream_id: "stream:conformance:unsupported-compression".to_owned(),
        position: 0,
        resume_cursor: None,
        value: IngestFrameValue::Manifest(SourceRevisionManifest {
            source_id: "source:conformance:unsupported-compression".to_owned(),
            revision_id: "revision:compressed".to_owned(),
            snapshot_id: "snapshot:compressed".to_owned(),
            expected_items: 1,
            ordered_items_digest: source_digest.clone(),
            compression: Compression::Gzip,
            attributes: std::collections::BTreeMap::new(),
        }),
    };
    let compressed_wire = attest_ingest_frame(
        gateway.as_ref(),
        ingest_frame_to_proto(compressed_manifest)
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
    )?;
    let compressed_request = tonic::Request::new(tokio_stream::iter([compressed_wire]));
    let mut compressed_stream = observation_client
        .ingest_snapshot(compressed_request)
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
        .into_inner();
    let compression_fail_closed = compressed_stream
        .message()
        .await
        .is_err_and(|status| status.code() == tonic::Code::Unimplemented);

    let manifest_frame = IngestFrame {
        context: authenticated.clone(),
        stream_id: "stream:conformance:source".to_owned(),
        position: 0,
        resume_cursor: None,
        value: IngestFrameValue::Manifest(SourceRevisionManifest {
            source_id: "source:conformance".to_owned(),
            revision_id: "revision:2026-08-12".to_owned(),
            snapshot_id: "snapshot:conformance".to_owned(),
            expected_items: 1,
            ordered_items_digest: source_digest.clone(),
            compression: Compression::Identity,
            attributes: std::collections::BTreeMap::new(),
        }),
    };
    let (ingest_sender, ingest_receiver) = tokio::sync::mpsc::channel(4);
    ingest_sender
        .send(attest_ingest_frame(
            gateway.as_ref(),
            ingest_frame_to_proto(manifest_frame)
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        )?)
        .await
        .map_err(|_| ConformanceError::Protocol("ingest request channel closed".to_owned()))?;
    let ingest_request =
        tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(ingest_receiver));
    let mut ingest = observation_client
        .ingest_snapshot(ingest_request)
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
        .into_inner();
    let manifest_ack = next_ingest_ack(&mut ingest).await?;
    let item_frame = IngestFrame {
        context: authenticated.clone(),
        stream_id: "stream:conformance:source".to_owned(),
        position: 1,
        resume_cursor: Some(manifest_ack.resume_cursor.clone()),
        value: IngestFrameValue::Observation(stream_observation),
    };
    let item_wire = ingest_frame_to_proto(item_frame)
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    ingest_sender
        .send(attest_ingest_frame(gateway.as_ref(), item_wire.clone())?)
        .await
        .map_err(|_| ConformanceError::Protocol("ingest request channel closed".to_owned()))?;
    let item_ack = next_ingest_ack(&mut ingest).await?;
    ingest_sender
        .send(attest_ingest_frame(gateway.as_ref(), item_wire)?)
        .await
        .map_err(|_| ConformanceError::Protocol("ingest request channel closed".to_owned()))?;
    let replay_ack = next_ingest_ack(&mut ingest).await?;

    let before_completion = collect_subscription(
        channel.clone(),
        authenticated.clone(),
        vec![wire::MemoryEventKind::ObservationAccepted as i32],
        None,
        gateway.as_ref(),
        true,
    )
    .await
    .map_err(|error| {
        ConformanceError::Protocol(format!("pre-completion subscription failed: {error}"))
    })?;
    let completion_gated = !before_completion.events.iter().any(|event| {
        event
            .object_refs
            .iter()
            .any(|value| value == "observation:source-snapshot")
    });

    let complete_frame = IngestFrame {
        context: authenticated.clone(),
        stream_id: "stream:conformance:source".to_owned(),
        position: 2,
        resume_cursor: Some(item_ack.resume_cursor.clone()),
        value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
            snapshot_id: "snapshot:conformance".to_owned(),
            item_count: 1,
            ordered_items_digest: source_digest,
        }),
    };
    ingest_sender
        .send(attest_ingest_frame(
            gateway.as_ref(),
            ingest_frame_to_proto(complete_frame)
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        )?)
        .await
        .map_err(|_| ConformanceError::Protocol("ingest request channel closed".to_owned()))?;
    let complete_ack = next_ingest_ack(&mut ingest).await?;
    drop(ingest_sender);
    let ingest_positions = vec![
        manifest_ack.position,
        item_ack.position,
        replay_ack.position,
        complete_ack.position,
    ];
    let ingest_partial_ack_idempotent = item_ack == replay_ack;
    let ingest_resume_bound = !manifest_ack.resume_cursor.is_empty()
        && !item_ack.resume_cursor.is_empty()
        && manifest_ack.resume_cursor != item_ack.resume_cursor;
    let compression_validated = compression_fail_closed
        && manifest_ack.disposition == wire::IngestDisposition::Accepted as i32;
    let snapshot_complete = complete_ack.disposition
        == wire::IngestDisposition::SnapshotCommitted as i32
        && complete_ack.commit_seq.is_some();

    let after_completion = collect_subscription(
        channel.clone(),
        authenticated.clone(),
        vec![wire::MemoryEventKind::ObservationAccepted as i32],
        None,
        gateway.as_ref(),
        true,
    )
    .await?;
    let duplicate_delivery = collect_subscription(
        channel.clone(),
        authenticated.clone(),
        vec![wire::MemoryEventKind::ObservationAccepted as i32],
        None,
        gateway.as_ref(),
        true,
    )
    .await?;
    let source_event = after_completion.events.iter().find(|event| {
        event
            .object_refs
            .iter()
            .any(|value| value == "observation:source-snapshot")
    });
    let duplicate_source_event = duplicate_delivery.events.iter().find(|event| {
        event
            .object_refs
            .iter()
            .any(|value| value == "observation:source-snapshot")
    });
    let subscription_event_ids_stable = source_event
        .zip(duplicate_source_event)
        .is_some_and(|(left, right)| !left.event_id.is_empty() && left.event_id == right.event_id);
    let resume_cursor = Some(after_completion.resume_cursor.clone());
    let mut resume_context = authenticated.clone();
    resume_context.request.request_id = "request:subscription:reconnect".to_owned();
    let resumed = collect_subscription(
        channel.clone(),
        resume_context,
        vec![wire::MemoryEventKind::ObservationAccepted as i32],
        resume_cursor,
        gateway.as_ref(),
        true,
    )
    .await?;
    let subscription_resume_dedup = resumed.events.is_empty() && resumed.caught_up;
    let filtered = collect_subscription(
        channel.clone(),
        authenticated.clone(),
        vec![wire::MemoryEventKind::NodeChanged as i32],
        None,
        gateway.as_ref(),
        true,
    )
    .await?;
    let subscription_filtering = filtered.events.is_empty() && filtered.caught_up;
    let other_binding = "33".repeat(32);
    let other = authenticated_context(
        fixture.other_principal.clone(),
        &[ServiceCapability::Subscribe],
        &other_binding,
    );
    let other_events = collect_subscription(
        channel.clone(),
        other,
        vec![wire::MemoryEventKind::ObservationAccepted as i32],
        None,
        gateway.as_ref(),
        true,
    )
    .await?;
    let subscription_policy_first = !other_events.events.iter().any(|event| {
        event
            .object_refs
            .iter()
            .any(|value| value == "observation:source-snapshot")
    });
    let missing_transport_auth = collect_subscription(
        channel.clone(),
        authenticated,
        vec![wire::MemoryEventKind::ObservationAccepted as i32],
        None,
        gateway.as_ref(),
        false,
    )
    .await;
    let transport_authentication_required = matches!(
        missing_transport_auth,
        Err(ConformanceError::Protocol(ref message)) if message.contains("PermissionDenied")
    );

    let mut recall_client = wire::recall_service_client::RecallServiceClient::new(channel);
    let recall_stream_request = exact_grpc_request(
        recall_request_to_proto(fixture.recall(10)),
        GRPC_RECALL_STREAM,
        gateway.as_ref(),
    )?;
    let mut recall = recall_client
        .recall_stream(recall_stream_request)
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
        .into_inner();
    let mut recall_events = Vec::new();
    while let Some(event) = recall
        .message()
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
    {
        let kind = wire::RecallEventKind::try_from(event.kind)
            .map_err(|_| ConformanceError::Protocol("unknown recall event kind".to_owned()))?;
        recall_events.push(
            match kind {
                wire::RecallEventKind::Unspecified => "unspecified",
                wire::RecallEventKind::Started => "started",
                wire::RecallEventKind::Page => "page",
                wire::RecallEventKind::Completed => "completed",
            }
            .to_owned(),
        );
    }

    let _ = shutdown_sender.send(());
    server
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;

    let per_stream_order = positions == vec![1, 2, 3, 4];
    let partial_acknowledgement = matches!(
        outcomes.as_slice(),
        [
            StreamAckOutcome::Success {
                replayed: false,
                ..
            },
            StreamAckOutcome::Success { replayed: true, .. },
            StreamAckOutcome::Error(ErrorCode::InvalidArgument),
            StreamAckOutcome::Success {
                replayed: false,
                ..
            }
        ]
    ) && matches!(
        outcomes.as_slice(),
        [
            StreamAckOutcome::Success { commit_seq: first, .. },
            StreamAckOutcome::Success { commit_seq: replay, .. },
            _,
            _
        ] if first == replay
    );
    let recall_event_order = recall_events == ["started", "page", "completed"];
    Ok(GrpcStreamingProof {
        configured_ack_window: 32,
        observe_positions: positions,
        observe_outcomes: outcomes,
        recall_events,
        partial_acknowledgement,
        per_stream_order,
        recall_event_order,
        ingest_positions,
        ingest_partial_ack_idempotent,
        ingest_resume_bound,
        compression_validated,
        completion_gated,
        snapshot_complete,
        subscription_event_ids_stable,
        subscription_resume_dedup,
        subscription_filtering,
        subscription_policy_first,
        transport_authentication_required,
    })
}

fn authenticated_context(
    request: RequestContext,
    grants: &[ServiceCapability],
    binding: &str,
) -> AuthenticatedRequestContext {
    let actor_id = request.subject_id.clone();
    AuthenticatedRequestContext {
        request,
        actor_id: actor_id.clone(),
        agent_id: "agent:conformance".to_owned(),
        session_id: Some("session:conformance".to_owned()),
        capability_grants: grants.iter().copied().collect(),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "channel:conformance".to_owned(),
            peer_identity: actor_id,
            binding_digest: binding.to_owned(),
        },
    }
}

fn attest_observe_stream_frame(
    gateway: &Blake3GatewayAuthenticator,
    mut frame: wire::ObserveRequest,
) -> ConformanceResult<wire::ObserveRequest> {
    frame.gateway_attestation = None;
    let token = gateway
        .attest_exact_request(
            GatewayTransport::Grpc,
            GRPC_OBSERVE_STREAM,
            &frame.encode_to_vec(),
            unique_gateway_nonce(),
        )
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    frame.gateway_attestation = Some(wire::GatewayFrameAttestation {
        gateway_id: gateway.gateway_id().to_owned(),
        token,
    });
    Ok(frame)
}

fn attest_ingest_frame(
    gateway: &Blake3GatewayAuthenticator,
    mut frame: wire::IngestFrame,
) -> ConformanceResult<wire::IngestFrame> {
    frame.gateway_attestation = None;
    let token = gateway
        .attest_exact_request(
            GatewayTransport::Grpc,
            GRPC_INGEST_SNAPSHOT,
            &frame.encode_to_vec(),
            unique_gateway_nonce(),
        )
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    frame.gateway_attestation = Some(wire::GatewayFrameAttestation {
        gateway_id: gateway.gateway_id().to_owned(),
        token,
    });
    Ok(frame)
}

fn exact_grpc_request<T: Message>(
    message: T,
    operation: &'static str,
    gateway: &Blake3GatewayAuthenticator,
) -> ConformanceResult<tonic::Request<T>> {
    let token = gateway
        .attest_exact_request(
            GatewayTransport::Grpc,
            operation,
            &message.encode_to_vec(),
            unique_gateway_nonce(),
        )
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    let mut request = tonic::Request::new(message);
    let (service, method) = operation.split_once('/').ok_or_else(|| {
        ConformanceError::Protocol("canonical gRPC operation is invalid".to_owned())
    })?;
    request
        .extensions_mut()
        .insert(tonic::GrpcMethod::new(service, method));
    request.metadata_mut().insert(
        GATEWAY_ID_HEADER,
        gateway.gateway_id().parse().map_err(|error| {
            ConformanceError::Protocol(format!("invalid gateway metadata: {error}"))
        })?,
    );
    request.metadata_mut().insert(
        GATEWAY_ATTESTATION_HEADER,
        token.parse().map_err(|error| {
            ConformanceError::Protocol(format!("invalid attestation metadata: {error}"))
        })?,
    );
    Ok(request)
}

async fn next_ingest_ack(
    stream: &mut tonic::Streaming<wire::IngestAck>,
) -> ConformanceResult<wire::IngestAck> {
    stream
        .message()
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
        .ok_or_else(|| ConformanceError::Protocol("ingest stream ended before ack".to_owned()))
}

async fn collect_subscription(
    channel: tonic::transport::Channel,
    context: AuthenticatedRequestContext,
    filters: Vec<i32>,
    resume_cursor: Option<String>,
    gateway: &Blake3GatewayAuthenticator,
    include_transport_auth: bool,
) -> ConformanceResult<CollectedSubscription> {
    let mut client = wire::subscription_service_client::SubscriptionServiceClient::new(channel);
    let message = wire::SubscribeRequest {
        context: Some(authenticated_context_to_proto(context)),
        filters,
        resume_cursor,
        max_events: 100,
    };
    let request = if include_transport_auth {
        exact_grpc_request(message, GRPC_SUBSCRIBE, gateway)?
    } else {
        tonic::Request::new(message)
    };
    let mut stream = client
        .subscribe(request)
        .await
        .map_err(|error| ConformanceError::Protocol(format!("{error:?}")))?
        .into_inner();
    let mut events = Vec::new();
    let mut checkpoint = None;
    while let Some(delivery) = stream
        .message()
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?
    {
        match delivery.value {
            Some(wire::subscription_delivery::Value::Event(event)) => {
                if checkpoint.is_some() {
                    return Err(ConformanceError::Protocol(
                        "subscription event followed its terminal checkpoint".to_owned(),
                    ));
                }
                if event.event_id.is_empty() {
                    return Err(ConformanceError::Protocol(
                        "subscription event ID is empty".to_owned(),
                    ));
                }
                events.push(event);
            }
            Some(wire::subscription_delivery::Value::Checkpoint(value)) => {
                if value.resume_cursor.is_empty() || checkpoint.replace(value).is_some() {
                    return Err(ConformanceError::Protocol(
                        "subscription checkpoint is empty or duplicated".to_owned(),
                    ));
                }
            }
            None => {
                return Err(ConformanceError::Protocol(
                    "subscription delivery value is absent".to_owned(),
                ));
            }
        }
    }
    let checkpoint = checkpoint.ok_or_else(|| {
        ConformanceError::Protocol("subscription stream omitted its checkpoint".to_owned())
    })?;
    Ok(CollectedSubscription {
        events,
        resume_cursor: checkpoint.resume_cursor,
        caught_up: checkpoint.caught_up,
    })
}

struct CollectedSubscription {
    events: Vec<wire::MemoryEvent>,
    resume_cursor: String,
    caught_up: bool,
}

fn error_code(value: i32) -> Option<ErrorCode> {
    match wire::ErrorCode::try_from(value).ok()? {
        wire::ErrorCode::Unspecified => None,
        wire::ErrorCode::InvalidScope => Some(ErrorCode::InvalidScope),
        wire::ErrorCode::Unauthorized => Some(ErrorCode::Unauthorized),
        wire::ErrorCode::AmbiguousIdentity => Some(ErrorCode::AmbiguousIdentity),
        wire::ErrorCode::SnapshotExpired => Some(ErrorCode::SnapshotExpired),
        wire::ErrorCode::IndexTooStale => Some(ErrorCode::IndexTooStale),
        wire::ErrorCode::EvidenceRequired => Some(ErrorCode::EvidenceRequired),
        wire::ErrorCode::ConflictUnresolved => Some(ErrorCode::ConflictUnresolved),
        wire::ErrorCode::BudgetExhausted => Some(ErrorCode::BudgetExhausted),
        wire::ErrorCode::ContinuationExpired => Some(ErrorCode::ContinuationExpired),
        wire::ErrorCode::FormatIncompatible => Some(ErrorCode::FormatIncompatible),
        wire::ErrorCode::ProviderUnavailable => Some(ErrorCode::ProviderUnavailable),
        wire::ErrorCode::DegradedMode => Some(ErrorCode::DegradedMode),
        wire::ErrorCode::InvalidArgument => Some(ErrorCode::InvalidArgument),
        wire::ErrorCode::PermissionDenied => Some(ErrorCode::PermissionDenied),
        wire::ErrorCode::NotFound => Some(ErrorCode::NotFound),
        wire::ErrorCode::IdempotencyConflict => Some(ErrorCode::IdempotencyConflict),
        wire::ErrorCode::InvalidContinuation => Some(ErrorCode::InvalidContinuation),
        wire::ErrorCode::IntegrityFailure => Some(ErrorCode::IntegrityFailure),
        wire::ErrorCode::Unavailable => Some(ErrorCode::Unavailable),
        wire::ErrorCode::ResourceExhausted => Some(ErrorCode::ResourceExhausted),
        wire::ErrorCode::Unsupported => Some(ErrorCode::Unsupported),
    }
}
