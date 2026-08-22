use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use contextdb_proto::v1 as wire;
use contextdb_proto::v1::admin_service_server::AdminService;
use contextdb_proto::v1::agent_runtime_service_server::AgentRuntimeService;
use contextdb_proto::v1::archive_service_server::ArchiveService;
use contextdb_proto::v1::artifact_service_server::ArtifactService;
use contextdb_proto::v1::conversation_service_server::ConversationService;
use contextdb_proto::v1::maintenance_service_server::MaintenanceService;
use contextdb_proto::v1::memory_control_service_server::MemoryControlService;
use contextdb_proto::v1::memory_service_server::MemoryService;
use contextdb_proto::v1::observation_service_server::ObservationService;
use contextdb_proto::v1::recall_service_server::RecallService;
use contextdb_proto::v1::subject_relationship_service_server::SubjectRelationshipService;
use contextdb_proto::v1::subscription_service_server::SubscriptionService;
use contextdb_service::{
    AuthenticatedRequestContext, CognitiveMemoryService, ErrorCode, ServiceError,
};
use prost::Message;
use tokio::sync::Semaphore;
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};

use crate::{
    ExecutionAdmission, ExecutionClass, GATEWAY_ATTESTATION_HEADER, GATEWAY_ID_HEADER,
    GatewayAuthenticator, GatewayTransport, LegacyNetworkOperation, MAX_GATEWAY_ATTESTATION_BYTES,
    MAX_GATEWAY_ID_BYTES, MAX_WIRE_BYTES, RejectingGatewayAuthenticator, SharedExecutionAdmission,
    SharedGatewayAuthenticator, authenticated_context_from_proto, backup_request_from_proto,
    backup_response_to_proto, compile_context_request_from_proto,
    compile_context_response_to_proto, correct_request_from_proto, error_to_proto,
    explain_request_from_proto, export_request_from_proto, export_response_to_proto,
    forget_request_from_proto, get_memory_request_from_proto, get_timeline_request_from_proto,
    high_level_control_request_from_proto, high_level_mutation_response_to_proto,
    high_level_query_request_from_proto, high_level_transfer_request_from_proto,
    high_level_write_request_from_proto, import_request_from_proto, import_response_to_proto,
    ingest_ack_to_proto, ingest_frame_from_proto, maintenance_request_from_proto,
    maintenance_response_to_proto, memory_record_to_proto, migrate_request_from_proto,
    mutation_response_to_proto, observe_request_from_proto, observe_response_to_proto,
    recall_request_from_proto, recall_response_to_proto, recall_trace_to_proto,
    request_context_from_proto, restore_request_from_proto, restore_response_to_proto,
    runtime_request_from_proto, runtime_response_to_proto, status_request_from_proto,
    status_response_to_proto, subscribe_request_from_proto, subscription_page_to_proto,
    timeline_response_to_proto, traverse_request_from_proto, traverse_response_to_proto,
    verify_request_from_proto, verify_response_to_proto,
};

type WireStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

const MAX_PENDING_STREAM_OPENINGS: usize = 32;
const MAX_CONCURRENT_REQUESTS_PER_CONNECTION: usize = 64;
const MAX_GRPC_HEADER_LIST_BYTES: u32 = 16 * 1024;
const STREAM_OPENING_TIMEOUT: Duration = Duration::from_secs(1);

/// Tonic adapter over the canonical service contract.
#[derive(Clone)]
pub struct GrpcAdapter {
    service: Arc<dyn CognitiveMemoryService>,
    stream_window: usize,
    pending_stream_openings: Arc<Semaphore>,
    gateway_authenticator: SharedGatewayAuthenticator,
    execution_admission: SharedExecutionAdmission,
}

impl std::fmt::Debug for GrpcAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrpcAdapter")
            .field("stream_window", &self.stream_window)
            .finish_non_exhaustive()
    }
}

impl GrpcAdapter {
    /// Creates an adapter with bounded stream acknowledgement buffering and a
    /// fail-closed gateway policy. Protected v1 methods require
    /// [`Self::with_gateway_authenticator`].
    #[must_use]
    pub fn new(service: Arc<dyn CognitiveMemoryService>, stream_window: usize) -> Self {
        Self::with_gateway_authenticator(
            service,
            stream_window,
            Arc::new(RejectingGatewayAuthenticator),
        )
    }

    /// Creates an adapter with bounded streams and an explicit trusted gateway
    /// verifier for authenticated v1 methods.
    #[must_use]
    pub fn with_gateway_authenticator(
        service: Arc<dyn CognitiveMemoryService>,
        stream_window: usize,
        gateway_authenticator: SharedGatewayAuthenticator,
    ) -> Self {
        Self::with_gateway_authenticator_and_admission(
            service,
            stream_window,
            gateway_authenticator,
            Arc::new(ExecutionAdmission::default()),
        )
    }

    /// Creates an adapter with bounded streams, trusted gateway verification,
    /// and a shared blocking-execution admission authority.
    #[must_use]
    pub fn with_gateway_authenticator_and_admission(
        service: Arc<dyn CognitiveMemoryService>,
        stream_window: usize,
        gateway_authenticator: SharedGatewayAuthenticator,
        execution_admission: SharedExecutionAdmission,
    ) -> Self {
        Self {
            service,
            stream_window: stream_window.clamp(1, 1_024),
            pending_stream_openings: Arc::new(Semaphore::new(MAX_PENDING_STREAM_OPENINGS)),
            gateway_authenticator,
            execution_admission,
        }
    }
}

async fn receive_bounded_stream_opening<T>(
    pending_stream_openings: &Arc<Semaphore>,
    inbound: &mut tonic::Streaming<T>,
) -> Result<T, Status> {
    let _permit = Arc::clone(pending_stream_openings)
        .try_acquire_owned()
        .map_err(|_| {
            Status::resource_exhausted(
                "ResourceExhausted: too many pending unauthenticated stream openings",
            )
        })?;
    match tokio::time::timeout(STREAM_OPENING_TIMEOUT, inbound.next()).await {
        Ok(Some(Ok(frame))) => Ok(frame),
        Ok(Some(Err(status))) => Err(status),
        Ok(None) => Err(Status::permission_denied(
            "PermissionDenied: first authenticated stream frame is required",
        )),
        Err(_) => Err(Status::deadline_exceeded(
            "DeadlineExceeded: authenticated first stream frame deadline exceeded",
        )),
    }
}

pub(crate) fn grpc_status(error: ServiceError) -> Status {
    let code = match error.code {
        ErrorCode::InvalidScope
        | ErrorCode::AmbiguousIdentity
        | ErrorCode::EvidenceRequired
        | ErrorCode::InvalidArgument => tonic::Code::InvalidArgument,
        ErrorCode::Unauthorized | ErrorCode::PermissionDenied => tonic::Code::PermissionDenied,
        ErrorCode::SnapshotExpired | ErrorCode::ContinuationExpired => tonic::Code::OutOfRange,
        ErrorCode::IndexTooStale | ErrorCode::ConflictUnresolved => tonic::Code::FailedPrecondition,
        ErrorCode::BudgetExhausted | ErrorCode::ResourceExhausted => tonic::Code::ResourceExhausted,
        ErrorCode::FormatIncompatible => tonic::Code::FailedPrecondition,
        ErrorCode::ProviderUnavailable | ErrorCode::Unavailable => tonic::Code::Unavailable,
        ErrorCode::DegradedMode => tonic::Code::FailedPrecondition,
        ErrorCode::NotFound => tonic::Code::NotFound,
        ErrorCode::IdempotencyConflict => tonic::Code::AlreadyExists,
        ErrorCode::InvalidContinuation => tonic::Code::FailedPrecondition,
        ErrorCode::IntegrityFailure => tonic::Code::DataLoss,
        ErrorCode::Unsupported => tonic::Code::Unimplemented,
    };
    let message = format!("{:?}: {}", error.code, error.message);
    let details = error_to_proto(error).encode_to_vec().into();
    Status::with_details(code, message, details)
}

async fn run_blocking<T, F>(
    admission: SharedExecutionAdmission,
    class: ExecutionClass,
    operation: F,
) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ServiceError> + Send + 'static,
{
    admission
        .execute(class, operation)
        .await
        .map_err(grpc_status)
}

fn validate_transport_authentication<M: Message>(
    gateway_authenticator: &dyn GatewayAuthenticator,
    request: &Request<M>,
    context: Option<&wire::RequestContext>,
    expected_operation: &'static str,
) -> Result<AuthenticatedRequestContext, Status> {
    verify_grpc_exact_request(gateway_authenticator, request, expected_operation)?;
    let context = context.ok_or_else(|| {
        grpc_status(ServiceError::new(
            ErrorCode::InvalidArgument,
            "authenticated request context is required",
            false,
        ))
    })?;
    let context = authenticated_context_from_proto(context.clone()).map_err(grpc_status)?;
    Ok(context)
}

fn validate_high_level_transport_authentication<M: Message>(
    gateway_authenticator: &dyn GatewayAuthenticator,
    request: &Request<M>,
    context: Option<&wire::RequestContext>,
    expected_operation: &'static str,
    capabilities: &[contextdb_service::Capability],
) -> Result<AuthenticatedRequestContext, Status> {
    let context = validate_transport_authentication(
        gateway_authenticator,
        request,
        context,
        expected_operation,
    )?;
    for capability in capabilities {
        contextdb_service::authorize_capability(&context, *capability).map_err(grpc_status)?;
    }
    Ok(context)
}

fn validate_legacy_transport_authentication<M: Message>(
    gateway_authenticator: &dyn GatewayAuthenticator,
    request: &Request<M>,
    context: Option<&wire::RequestContext>,
    operation: LegacyNetworkOperation,
) -> Result<(), Status> {
    verify_grpc_exact_request(gateway_authenticator, request, operation.canonical_id())?;
    let context = context.ok_or_else(|| {
        grpc_status(ServiceError::new(
            ErrorCode::InvalidArgument,
            "legacy request context is required",
            false,
        ))
    })?;
    request_context_from_proto(context.clone()).map_err(grpc_status)?;
    Ok(())
}

fn verify_grpc_exact_request<M: Message>(
    gateway_authenticator: &dyn GatewayAuthenticator,
    request: &Request<M>,
    expected_operation: &'static str,
) -> Result<(), Status> {
    let gateway_id =
        exact_metadata_value(request.metadata(), GATEWAY_ID_HEADER, MAX_GATEWAY_ID_BYTES)?;
    let attestation = exact_metadata_value(
        request.metadata(),
        GATEWAY_ATTESTATION_HEADER,
        MAX_GATEWAY_ATTESTATION_BYTES,
    )?;
    // Tonic's generated client records `GrpcMethod` as a local extension, but
    // that extension is not serialized and therefore is absent on requests
    // received by a real generated server. The service implementation already
    // knows its exact canonical method; use that as the authority and treat a
    // locally supplied extension as an additional consistency check only.
    if let Some(method) = request.extensions().get::<tonic::GrpcMethod<'static>>() {
        let operation = format!("{}/{}", method.service(), method.method());
        if expected_operation != operation {
            return Err(invalid_gateway_metadata());
        }
    }
    let canonical_body = request.get_ref().encode_to_vec();
    gateway_authenticator
        .verify_exact_request(
            Some(gateway_id),
            Some(attestation),
            GatewayTransport::Grpc,
            expected_operation,
            &canonical_body,
        )
        .map_err(grpc_status)
}

fn exact_metadata_value<'a>(
    metadata: &'a tonic::metadata::MetadataMap,
    name: &'static str,
    max_bytes: usize,
) -> Result<&'a str, Status> {
    let value = metadata.get(name).ok_or_else(invalid_gateway_metadata)?;
    let value = value.to_str().map_err(|_| invalid_gateway_metadata())?;
    if value.len() > max_bytes {
        return Err(invalid_gateway_metadata());
    }
    Ok(value)
}

fn invalid_gateway_metadata() -> Status {
    grpc_status(ServiceError::new(
        ErrorCode::Unauthorized,
        "trusted gateway exact-request attestation is missing or malformed",
        false,
    ))
}

fn validate_legacy_stream_frame(
    gateway_authenticator: &dyn GatewayAuthenticator,
    frame: &mut wire::ObserveRequest,
) -> Result<(), Status> {
    let attestation = frame
        .gateway_attestation
        .take()
        .ok_or_else(invalid_gateway_metadata)?;
    verify_grpc_stream_frame(
        gateway_authenticator,
        &attestation,
        LegacyNetworkOperation::GrpcObserveStream.canonical_id(),
        frame,
    )?;
    let context = frame.context.as_ref().ok_or_else(|| {
        grpc_status(ServiceError::new(
            ErrorCode::InvalidArgument,
            "legacy request context is required",
            false,
        ))
    })?;
    request_context_from_proto(context.clone()).map_err(grpc_status)?;
    Ok(())
}

fn validate_ingest_stream_frame(
    gateway_authenticator: &dyn GatewayAuthenticator,
    frame: &mut wire::IngestFrame,
) -> Result<(), Status> {
    let attestation = frame
        .gateway_attestation
        .take()
        .ok_or_else(invalid_gateway_metadata)?;
    verify_grpc_stream_frame(
        gateway_authenticator,
        &attestation,
        "contextdb.v1.ObservationService/IngestSnapshot",
        frame,
    )?;
    let context = frame.context.as_ref().ok_or_else(|| {
        grpc_status(ServiceError::new(
            ErrorCode::InvalidArgument,
            "authenticated request context is required",
            false,
        ))
    })?;
    let context = authenticated_context_from_proto(context.clone()).map_err(grpc_status)?;
    contextdb_service::authorize_capability(&context, contextdb_service::Capability::StreamIngest)
        .map_err(grpc_status)
}

fn verify_grpc_stream_frame<M: Message>(
    gateway_authenticator: &dyn GatewayAuthenticator,
    attestation: &wire::GatewayFrameAttestation,
    operation: &str,
    frame_without_attestation: &M,
) -> Result<(), Status> {
    if attestation.gateway_id.len() > MAX_GATEWAY_ID_BYTES
        || attestation.token.len() > MAX_GATEWAY_ATTESTATION_BYTES
    {
        return Err(invalid_gateway_metadata());
    }
    let canonical_body = frame_without_attestation.encode_to_vec();
    gateway_authenticator
        .verify_exact_request(
            Some(&attestation.gateway_id),
            Some(&attestation.token),
            GatewayTransport::Grpc,
            operation,
            &canonical_body,
        )
        .map_err(grpc_status)
}

#[tonic::async_trait]
impl ObservationService for GrpcAdapter {
    async fn observe(
        &self,
        request: Request<wire::ObserveRequest>,
    ) -> Result<Response<wire::ObserveResponse>, Status> {
        validate_legacy_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            LegacyNetworkOperation::GrpcObserve,
        )?;
        let request = observe_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.observe(request),
        )
        .await?;
        Ok(Response::new(observe_response_to_proto(response)))
    }

    type ObserveStreamStream = WireStream<wire::ObserveAck>;

    async fn observe_stream(
        &self,
        request: Request<tonic::Streaming<wire::ObserveRequest>>,
    ) -> Result<Response<Self::ObserveStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let mut first =
            receive_bounded_stream_opening(&self.pending_stream_openings, &mut inbound).await?;
        validate_legacy_stream_frame(self.gateway_authenticator.as_ref(), &mut first)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(self.stream_window);
        let service = Arc::clone(&self.service);
        let gateway_authenticator = Arc::clone(&self.gateway_authenticator);
        let execution_admission = Arc::clone(&self.execution_admission);

        tokio::spawn(async move {
            let mut position = 0_u64;
            let mut first = Some(first);
            loop {
                let already_authenticated = first.is_some();
                let item = match first.take() {
                    Some(frame) => Some(Ok(frame)),
                    None => inbound.next().await,
                };
                let Some(item) = item else {
                    break;
                };
                position = position.saturating_add(1);
                let outcome = match item {
                    Ok(mut value) => {
                        if !already_authenticated
                            && let Err(status) = validate_legacy_stream_frame(
                                gateway_authenticator.as_ref(),
                                &mut value,
                            )
                        {
                            let _ = sender.send(Err(status)).await;
                            break;
                        }
                        match observe_request_from_proto(value) {
                            Ok(request) => {
                                let service = Arc::clone(&service);
                                match execution_admission
                                    .execute(ExecutionClass::Interactive, move || {
                                        service.observe(request)
                                    })
                                    .await
                                {
                                    Ok(response) => Some(wire::observe_ack::Outcome::Response(
                                        observe_response_to_proto(response),
                                    )),
                                    Err(error) => Some(wire::observe_ack::Outcome::Error(
                                        error_to_proto(error),
                                    )),
                                }
                            }
                            Err(error) => {
                                Some(wire::observe_ack::Outcome::Error(error_to_proto(error)))
                            }
                        }
                    }
                    Err(status) => {
                        let _ = sender.send(Err(status)).await;
                        break;
                    }
                };
                if sender
                    .send(Ok(wire::ObserveAck {
                        stream_position: position,
                        outcome,
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    type IngestSnapshotStream = WireStream<wire::IngestAck>;

    async fn ingest_snapshot(
        &self,
        request: Request<tonic::Streaming<wire::IngestFrame>>,
    ) -> Result<Response<Self::IngestSnapshotStream>, Status> {
        let mut inbound = request.into_inner();
        let mut first =
            receive_bounded_stream_opening(&self.pending_stream_openings, &mut inbound).await?;
        validate_ingest_stream_frame(self.gateway_authenticator.as_ref(), &mut first)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(self.stream_window);
        let service = Arc::clone(&self.service);
        let execution_admission = Arc::clone(&self.execution_admission);
        let gateway_authenticator = Arc::clone(&self.gateway_authenticator);
        tokio::spawn(async move {
            let mut first = Some(first);
            loop {
                let already_authenticated = first.is_some();
                let item = match first.take() {
                    Some(frame) => Some(Ok(frame)),
                    None => inbound.next().await,
                };
                let Some(item) = item else {
                    break;
                };
                let mut wire_frame = match item {
                    Ok(value) => value,
                    Err(status) => {
                        let _ = sender.send(Err(status)).await;
                        break;
                    }
                };
                if !already_authenticated
                    && let Err(status) = validate_ingest_stream_frame(
                        gateway_authenticator.as_ref(),
                        &mut wire_frame,
                    )
                {
                    let _ = sender.send(Err(status)).await;
                    break;
                }
                let frame = match ingest_frame_from_proto(wire_frame) {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sender.send(Err(grpc_status(error))).await;
                        break;
                    }
                };
                let service = Arc::clone(&service);
                match run_blocking(
                    Arc::clone(&execution_admission),
                    ExecutionClass::Interactive,
                    move || service.ingest_frame(frame),
                )
                .await
                {
                    Ok(ack) => {
                        if sender.send(Ok(ingest_ack_to_proto(ack))).await.is_err() {
                            break;
                        }
                    }
                    Err(status) => {
                        let _ = sender.send(Err(status)).await;
                        break;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn correct(
        &self,
        request: Request<wire::CorrectRequest>,
    ) -> Result<Response<wire::MutationResponse>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.ObservationService/Correct",
            &[contextdb_service::Capability::Correct],
        )?;
        let request = correct_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.correct(request),
        )
        .await?;
        Ok(Response::new(mutation_response_to_proto(response)))
    }

    async fn forget(
        &self,
        request: Request<wire::ForgetRequest>,
    ) -> Result<Response<wire::MutationResponse>, Status> {
        let authenticated_context = validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.ObservationService/Forget",
            &[contextdb_service::Capability::Forget],
        )?;
        if request.get_ref().mode == wire::ForgetMode::HardDelete as i32 {
            contextdb_service::authorize_capability(
                &authenticated_context,
                contextdb_service::Capability::HardDelete,
            )
            .map_err(grpc_status)?;
        }
        let request = forget_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.forget(request),
        )
        .await?;
        Ok(Response::new(mutation_response_to_proto(response)))
    }
}

#[tonic::async_trait]
impl SubscriptionService for GrpcAdapter {
    type SubscribeStream = WireStream<wire::SubscriptionDelivery>;

    async fn subscribe(
        &self,
        request: Request<wire::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.SubscriptionService/Subscribe",
            &[contextdb_service::Capability::Subscribe],
        )?;
        let request = subscribe_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let page = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.subscribe(request),
        )
        .await?;
        let events = subscription_page_to_proto(page)
            .into_iter()
            .map(Ok::<_, Status>);
        Ok(Response::new(Box::pin(tokio_stream::iter(events))))
    }
}

#[tonic::async_trait]
impl MemoryService for GrpcAdapter {
    async fn get_node(
        &self,
        request: Request<wire::GetMemoryRequest>,
    ) -> Result<Response<wire::MemoryRecord>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.MemoryService/GetNode",
            &[contextdb_service::Capability::ReadMemory],
        )?;
        let request = get_memory_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.get_node(request),
        )
        .await?;
        Ok(Response::new(
            memory_record_to_proto(response).map_err(grpc_status)?,
        ))
    }

    async fn traverse(
        &self,
        request: Request<wire::TraverseRequest>,
    ) -> Result<Response<wire::TraverseResponse>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.MemoryService/Traverse",
            &[contextdb_service::Capability::Traverse],
        )?;
        let request = traverse_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.traverse(request),
        )
        .await?;
        Ok(Response::new(traverse_response_to_proto(response)))
    }

    async fn get_timeline(
        &self,
        request: Request<wire::GetTimelineRequest>,
    ) -> Result<Response<wire::TimelineResponse>, Status> {
        let authenticated_context = validate_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.MemoryService/GetTimeline",
        )?;
        let timeline_capabilities: &[contextdb_service::Capability] =
            match wire::MemoryRecordKind::try_from(request.get_ref().expected_kind).map_err(
                |_| {
                    grpc_status(ServiceError::new(
                        ErrorCode::InvalidArgument,
                        "unknown timeline record kind",
                        false,
                    ))
                },
            )? {
                wire::MemoryRecordKind::Evidence => &[
                    contextdb_service::Capability::ReadEvidence,
                    contextdb_service::Capability::RawEvidence,
                ],
                wire::MemoryRecordKind::Conflict => &[contextdb_service::Capability::ReadConflict],
                _ => &[contextdb_service::Capability::ReadMemory],
            };
        for capability in timeline_capabilities {
            contextdb_service::authorize_capability(&authenticated_context, *capability)
                .map_err(grpc_status)?;
        }
        let request = get_timeline_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.get_timeline(request),
        )
        .await?;
        Ok(Response::new(
            timeline_response_to_proto(response).map_err(grpc_status)?,
        ))
    }

    async fn get_evidence(
        &self,
        request: Request<wire::GetMemoryRequest>,
    ) -> Result<Response<wire::MemoryRecord>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.MemoryService/GetEvidence",
            &[
                contextdb_service::Capability::ReadEvidence,
                contextdb_service::Capability::RawEvidence,
            ],
        )?;
        let request = get_memory_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.get_evidence(request),
        )
        .await?;
        Ok(Response::new(
            memory_record_to_proto(response).map_err(grpc_status)?,
        ))
    }

    async fn get_conflict(
        &self,
        request: Request<wire::GetMemoryRequest>,
    ) -> Result<Response<wire::MemoryRecord>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.MemoryService/GetConflict",
            &[contextdb_service::Capability::ReadConflict],
        )?;
        let request = get_memory_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.get_conflict(request),
        )
        .await?;
        Ok(Response::new(
            memory_record_to_proto(response).map_err(grpc_status)?,
        ))
    }
}

#[derive(Clone, Copy)]
enum RuntimeCall {
    Bootstrap,
    Preflight,
    Postflight,
    Checkpoint,
    Resume,
    Handoff,
}

impl RuntimeCall {
    const fn canonical_operation(self) -> &'static str {
        match self {
            Self::Bootstrap => "contextdb.v1.AgentRuntimeService/Bootstrap",
            Self::Preflight => "contextdb.v1.AgentRuntimeService/Preflight",
            Self::Postflight => "contextdb.v1.AgentRuntimeService/Postflight",
            Self::Checkpoint => "contextdb.v1.AgentRuntimeService/Checkpoint",
            Self::Resume => "contextdb.v1.AgentRuntimeService/Resume",
            Self::Handoff => "contextdb.v1.AgentRuntimeService/Handoff",
        }
    }
}

async fn runtime_once(
    service: &Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: &dyn GatewayAuthenticator,
    execution_admission: &SharedExecutionAdmission,
    request: Request<wire::RuntimeRequest>,
    call: RuntimeCall,
) -> Result<Response<wire::RuntimeResponse>, Status> {
    validate_high_level_transport_authentication(
        gateway_authenticator,
        &request,
        request.get_ref().context.as_ref(),
        call.canonical_operation(),
        &[contextdb_service::Capability::Runtime],
    )?;
    let request = runtime_request_from_proto(request.into_inner()).map_err(grpc_status)?;
    let service = Arc::clone(service);
    let response = run_blocking(
        Arc::clone(execution_admission),
        ExecutionClass::Interactive,
        move || match call {
            RuntimeCall::Bootstrap => service.bootstrap(request),
            RuntimeCall::Preflight => service.preflight(request),
            RuntimeCall::Postflight => service.postflight(request),
            RuntimeCall::Checkpoint => service.checkpoint(request),
            RuntimeCall::Resume => service.resume(request),
            RuntimeCall::Handoff => service.handoff(request),
        },
    )
    .await?;
    Ok(Response::new(
        runtime_response_to_proto(response).map_err(grpc_status)?,
    ))
}

#[tonic::async_trait]
impl AgentRuntimeService for GrpcAdapter {
    async fn bootstrap(
        &self,
        request: Request<wire::RuntimeRequest>,
    ) -> Result<Response<wire::RuntimeResponse>, Status> {
        runtime_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            RuntimeCall::Bootstrap,
        )
        .await
    }

    async fn preflight(
        &self,
        request: Request<wire::RuntimeRequest>,
    ) -> Result<Response<wire::RuntimeResponse>, Status> {
        runtime_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            RuntimeCall::Preflight,
        )
        .await
    }

    async fn postflight(
        &self,
        request: Request<wire::RuntimeRequest>,
    ) -> Result<Response<wire::RuntimeResponse>, Status> {
        runtime_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            RuntimeCall::Postflight,
        )
        .await
    }

    async fn checkpoint(
        &self,
        request: Request<wire::RuntimeRequest>,
    ) -> Result<Response<wire::RuntimeResponse>, Status> {
        runtime_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            RuntimeCall::Checkpoint,
        )
        .await
    }

    async fn resume(
        &self,
        request: Request<wire::RuntimeRequest>,
    ) -> Result<Response<wire::RuntimeResponse>, Status> {
        runtime_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            RuntimeCall::Resume,
        )
        .await
    }

    async fn handoff(
        &self,
        request: Request<wire::RuntimeRequest>,
    ) -> Result<Response<wire::RuntimeResponse>, Status> {
        runtime_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            RuntimeCall::Handoff,
        )
        .await
    }
}

#[tonic::async_trait]
impl RecallService for GrpcAdapter {
    async fn compile_context(
        &self,
        request: Request<wire::CompileContextRequest>,
    ) -> Result<Response<wire::CompileContextResponse>, Status> {
        let authenticated = validate_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.RecallService/CompileContext",
        )?;
        contextdb_service::authorize_capability(
            &authenticated,
            contextdb_service::Capability::Recall,
        )
        .map_err(grpc_status)?;
        let request =
            compile_context_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.compile_context(request),
        )
        .await?;
        Ok(Response::new(
            compile_context_response_to_proto(response).map_err(grpc_status)?,
        ))
    }

    async fn recall(
        &self,
        request: Request<wire::RecallRequest>,
    ) -> Result<Response<wire::RecallResponse>, Status> {
        recall_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            LegacyNetworkOperation::GrpcRecall,
        )
        .await
    }

    type RecallStreamStream = WireStream<wire::RecallEvent>;

    async fn recall_stream(
        &self,
        request: Request<wire::RecallRequest>,
    ) -> Result<Response<Self::RecallStreamStream>, Status> {
        validate_legacy_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            LegacyNetworkOperation::GrpcRecallStream,
        )?;
        let request = recall_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let execution_permit = self
            .execution_admission
            .try_acquire(ExecutionClass::Interactive)
            .map_err(grpc_status)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(3);
        let service = Arc::clone(&self.service);
        tokio::spawn(async move {
            if sender
                .send(Ok(wire::RecallEvent {
                    kind: wire::RecallEventKind::Started as i32,
                    page: None,
                    trace_id: None,
                }))
                .await
                .is_err()
            {
                return;
            }
            let result = ExecutionAdmission::execute_admitted(execution_permit, move || {
                service.recall(request)
            })
            .await
            .map_err(grpc_status);
            match result {
                Ok(response) => {
                    let trace_id = response.trace.trace_id.clone();
                    if sender
                        .send(Ok(wire::RecallEvent {
                            kind: wire::RecallEventKind::Page as i32,
                            page: Some(recall_response_to_proto(response)),
                            trace_id: None,
                        }))
                        .await
                        .is_ok()
                    {
                        let _ = sender
                            .send(Ok(wire::RecallEvent {
                                kind: wire::RecallEventKind::Completed as i32,
                                page: None,
                                trace_id: Some(trace_id),
                            }))
                            .await;
                    }
                }
                Err(status) => {
                    let _ = sender.send(Err(status)).await;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn continue_recall(
        &self,
        request: Request<wire::RecallRequest>,
    ) -> Result<Response<wire::RecallResponse>, Status> {
        recall_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            LegacyNetworkOperation::GrpcContinueRecall,
        )
        .await
    }

    async fn explain_recall(
        &self,
        request: Request<wire::ExplainRecallRequest>,
    ) -> Result<Response<wire::RecallTrace>, Status> {
        validate_legacy_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            LegacyNetworkOperation::GrpcExplainRecall,
        )?;
        let request = explain_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.explain_recall(request),
        )
        .await?;
        Ok(Response::new(recall_trace_to_proto(response)))
    }
}

async fn recall_once(
    service: &Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: &dyn GatewayAuthenticator,
    execution_admission: &SharedExecutionAdmission,
    request: Request<wire::RecallRequest>,
    operation: LegacyNetworkOperation,
) -> Result<Response<wire::RecallResponse>, Status> {
    validate_legacy_transport_authentication(
        gateway_authenticator,
        &request,
        request.get_ref().context.as_ref(),
        operation,
    )?;
    let request = recall_request_from_proto(request.into_inner()).map_err(grpc_status)?;
    let service = Arc::clone(service);
    let response = run_blocking(
        Arc::clone(execution_admission),
        ExecutionClass::Interactive,
        move || service.recall(request),
    )
    .await?;
    Ok(Response::new(recall_response_to_proto(response)))
}

#[tonic::async_trait]
impl ArchiveService for GrpcAdapter {
    async fn export(
        &self,
        request: Request<wire::ExportRequest>,
    ) -> Result<Response<wire::ExportResponse>, Status> {
        validate_legacy_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            LegacyNetworkOperation::GrpcArchiveExport,
        )?;
        let request = export_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::BulkTransfer,
            move || service.export_archive(request),
        )
        .await?;
        Ok(Response::new(export_response_to_proto(response)))
    }

    async fn import(
        &self,
        request: Request<wire::ImportRequest>,
    ) -> Result<Response<wire::ImportResponse>, Status> {
        validate_legacy_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            LegacyNetworkOperation::GrpcArchiveImport,
        )?;
        let request = import_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::BulkTransfer,
            move || service.import_archive(request),
        )
        .await?;
        Ok(Response::new(import_response_to_proto(response)))
    }
}

#[tonic::async_trait]
impl MaintenanceService for GrpcAdapter {
    async fn consolidate(
        &self,
        request: Request<wire::MaintenanceRequest>,
    ) -> Result<Response<wire::MaintenanceResponse>, Status> {
        maintenance_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            MaintenanceCall::Consolidate,
        )
        .await
    }

    async fn reflect(
        &self,
        request: Request<wire::MaintenanceRequest>,
    ) -> Result<Response<wire::MaintenanceResponse>, Status> {
        maintenance_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            MaintenanceCall::Reflect,
        )
        .await
    }

    async fn reindex(
        &self,
        request: Request<wire::MaintenanceRequest>,
    ) -> Result<Response<wire::MaintenanceResponse>, Status> {
        maintenance_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            MaintenanceCall::Reindex,
        )
        .await
    }

    async fn compact(
        &self,
        request: Request<wire::MaintenanceRequest>,
    ) -> Result<Response<wire::MaintenanceResponse>, Status> {
        maintenance_once(
            &self.service,
            self.gateway_authenticator.as_ref(),
            &self.execution_admission,
            request,
            MaintenanceCall::Compact,
        )
        .await
    }

    async fn verify(
        &self,
        request: Request<wire::VerifyRequest>,
    ) -> Result<Response<wire::VerifyResponse>, Status> {
        validate_legacy_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            LegacyNetworkOperation::GrpcMaintenanceVerify,
        )?;
        let request = verify_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Maintenance,
            move || service.verify(request),
        )
        .await?;
        Ok(Response::new(verify_response_to_proto(response)))
    }
}

#[derive(Clone, Copy)]
enum MaintenanceCall {
    Consolidate,
    Reflect,
    Reindex,
    Compact,
}

impl MaintenanceCall {
    const fn canonical_operation(self) -> &'static str {
        match self {
            Self::Consolidate => "contextdb.v1.MaintenanceService/Consolidate",
            Self::Reflect => "contextdb.v1.MaintenanceService/Reflect",
            Self::Reindex => "contextdb.v1.MaintenanceService/Reindex",
            Self::Compact => "contextdb.v1.MaintenanceService/Compact",
        }
    }
}

async fn maintenance_once(
    service: &Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: &dyn GatewayAuthenticator,
    execution_admission: &SharedExecutionAdmission,
    request: Request<wire::MaintenanceRequest>,
    call: MaintenanceCall,
) -> Result<Response<wire::MaintenanceResponse>, Status> {
    validate_high_level_transport_authentication(
        gateway_authenticator,
        &request,
        request.get_ref().context.as_ref(),
        call.canonical_operation(),
        &[contextdb_service::Capability::Maintenance],
    )?;
    let request = maintenance_request_from_proto(request.into_inner()).map_err(grpc_status)?;
    let service = Arc::clone(service);
    let response = run_blocking(
        Arc::clone(execution_admission),
        ExecutionClass::Maintenance,
        move || match call {
            MaintenanceCall::Consolidate => service.consolidate(request),
            MaintenanceCall::Reflect => service.reflect(request),
            MaintenanceCall::Reindex => service.reindex(request),
            MaintenanceCall::Compact => service.compact(request),
        },
    )
    .await?;
    Ok(Response::new(
        maintenance_response_to_proto(response).map_err(grpc_status)?,
    ))
}

#[tonic::async_trait]
impl AdminService for GrpcAdapter {
    async fn get_status(
        &self,
        request: Request<wire::GetStatusRequest>,
    ) -> Result<Response<wire::StatusResponse>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.AdminService/GetStatus",
            &[contextdb_service::Capability::Admin],
        )?;
        let request = status_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Interactive,
            move || service.get_status(request),
        )
        .await?;
        Ok(Response::new(status_response_to_proto(response)))
    }

    async fn create_backup(
        &self,
        request: Request<wire::CreateBackupRequest>,
    ) -> Result<Response<wire::BackupResponse>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.AdminService/CreateBackup",
            &[contextdb_service::Capability::Admin],
        )?;
        let request = backup_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::BulkTransfer,
            move || service.create_backup(request),
        )
        .await?;
        Ok(Response::new(backup_response_to_proto(response)))
    }

    async fn restore_backup(
        &self,
        request: Request<wire::RestoreBackupRequest>,
    ) -> Result<Response<wire::RestoreBackupResponse>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.AdminService/RestoreBackup",
            &[contextdb_service::Capability::Admin],
        )?;
        let request = restore_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::BulkTransfer,
            move || service.restore_backup(request),
        )
        .await?;
        Ok(Response::new(restore_response_to_proto(response)))
    }

    async fn migrate_format(
        &self,
        request: Request<wire::MigrateFormatRequest>,
    ) -> Result<Response<wire::StatusResponse>, Status> {
        validate_high_level_transport_authentication(
            self.gateway_authenticator.as_ref(),
            &request,
            request.get_ref().context.as_ref(),
            "contextdb.v1.AdminService/MigrateFormat",
            &[contextdb_service::Capability::Admin],
        )?;
        let request = migrate_request_from_proto(request.into_inner()).map_err(grpc_status)?;
        let service = Arc::clone(&self.service);
        let response = run_blocking(
            Arc::clone(&self.execution_admission),
            ExecutionClass::Maintenance,
            move || service.migrate_format(request),
        )
        .await?;
        Ok(Response::new(status_response_to_proto(response)))
    }
}

#[derive(Clone, Copy)]
enum HighLevelWriteCall {
    BeginSession,
    AfterTurn,
    EndSession,
    BootstrapSubject,
    Remember,
    CreateMemorySubject,
    CreateRelationshipSpace,
    IngestArtifact,
    AttachArtifactToEpisode,
    AddDerivedRepresentation,
    AddEvidenceSelector,
}

impl HighLevelWriteCall {
    const fn canonical_operation(self) -> &'static str {
        match self {
            Self::BeginSession => "contextdb.v1.ConversationService/BeginSession",
            Self::AfterTurn => "contextdb.v1.ConversationService/AfterTurn",
            Self::EndSession => "contextdb.v1.ConversationService/EndSession",
            Self::BootstrapSubject => "contextdb.v1.ConversationService/BootstrapSubject",
            Self::Remember => "contextdb.v1.MemoryControlService/Remember",
            Self::CreateMemorySubject => {
                "contextdb.v1.SubjectRelationshipService/CreateMemorySubject"
            }
            Self::CreateRelationshipSpace => {
                "contextdb.v1.SubjectRelationshipService/CreateRelationshipSpace"
            }
            Self::IngestArtifact => "contextdb.v1.ArtifactService/IngestArtifact",
            Self::AttachArtifactToEpisode => "contextdb.v1.ArtifactService/AttachArtifactToEpisode",
            Self::AddDerivedRepresentation => {
                "contextdb.v1.ArtifactService/AddDerivedRepresentation"
            }
            Self::AddEvidenceSelector => "contextdb.v1.ArtifactService/AddEvidenceSelector",
        }
    }
}

async fn high_level_write_once(
    service: &Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: &dyn GatewayAuthenticator,
    execution_admission: &SharedExecutionAdmission,
    request: Request<wire::HighLevelWriteRequest>,
    call: HighLevelWriteCall,
) -> Result<Response<wire::HighLevelMutationResponse>, Status> {
    validate_high_level_transport_authentication(
        gateway_authenticator,
        &request,
        request.get_ref().context.as_ref(),
        call.canonical_operation(),
        &[contextdb_service::Capability::Observe],
    )?;
    let request = high_level_write_request_from_proto(request.into_inner()).map_err(grpc_status)?;
    let service = Arc::clone(service);
    let response = run_blocking(
        Arc::clone(execution_admission),
        ExecutionClass::Interactive,
        move || match call {
            HighLevelWriteCall::BeginSession => service.begin_session(request),
            HighLevelWriteCall::AfterTurn => service.after_turn(request),
            HighLevelWriteCall::EndSession => service.end_session(request),
            HighLevelWriteCall::BootstrapSubject => service.bootstrap_subject(request),
            HighLevelWriteCall::Remember => service.remember(request),
            HighLevelWriteCall::CreateMemorySubject => service.create_memory_subject(request),
            HighLevelWriteCall::CreateRelationshipSpace => {
                service.create_relationship_space(request)
            }
            HighLevelWriteCall::IngestArtifact => service.ingest_artifact(request),
            HighLevelWriteCall::AttachArtifactToEpisode => {
                service.attach_artifact_to_episode(request)
            }
            HighLevelWriteCall::AddDerivedRepresentation => {
                service.add_derived_representation(request)
            }
            HighLevelWriteCall::AddEvidenceSelector => service.add_evidence_selector(request),
        },
    )
    .await?;
    Ok(Response::new(high_level_mutation_response_to_proto(
        response,
    )))
}

#[derive(Clone, Copy)]
enum HighLevelQueryCall {
    BeforeTurn,
    ResolveReferent,
    RecallSharedHistory,
    ExplainMemory,
    ListSubjectMemories,
    GetContinuityProfile,
    GetArtifactMetadata,
}

impl HighLevelQueryCall {
    const fn canonical_operation(self) -> &'static str {
        match self {
            Self::BeforeTurn => "contextdb.v1.ConversationService/BeforeTurn",
            Self::ResolveReferent => "contextdb.v1.ConversationService/ResolveReferent",
            Self::RecallSharedHistory => "contextdb.v1.ConversationService/RecallSharedHistory",
            Self::ExplainMemory => "contextdb.v1.MemoryControlService/ExplainMemory",
            Self::ListSubjectMemories => "contextdb.v1.MemoryControlService/ListSubjectMemories",
            Self::GetContinuityProfile => {
                "contextdb.v1.SubjectRelationshipService/GetContinuityProfile"
            }
            Self::GetArtifactMetadata => "contextdb.v1.ArtifactService/GetArtifactMetadata",
        }
    }
}

async fn high_level_query_once(
    service: &Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: &dyn GatewayAuthenticator,
    execution_admission: &SharedExecutionAdmission,
    request: Request<wire::HighLevelQueryRequest>,
    call: HighLevelQueryCall,
) -> Result<Response<wire::RecallResponse>, Status> {
    validate_high_level_transport_authentication(
        gateway_authenticator,
        &request,
        request.get_ref().context.as_ref(),
        call.canonical_operation(),
        &[contextdb_service::Capability::Recall],
    )?;
    let request = high_level_query_request_from_proto(request.into_inner()).map_err(grpc_status)?;
    let service = Arc::clone(service);
    let response = run_blocking(
        Arc::clone(execution_admission),
        ExecutionClass::Interactive,
        move || match call {
            HighLevelQueryCall::BeforeTurn => service.before_turn(request),
            HighLevelQueryCall::ResolveReferent => service.resolve_referent(request),
            HighLevelQueryCall::RecallSharedHistory => service.recall_shared_history(request),
            HighLevelQueryCall::ExplainMemory => service.explain_memory(request),
            HighLevelQueryCall::ListSubjectMemories => service.list_subject_memories(request),
            HighLevelQueryCall::GetContinuityProfile => service.get_continuity_profile(request),
            HighLevelQueryCall::GetArtifactMetadata => service.get_artifact_metadata(request),
        },
    )
    .await?;
    Ok(Response::new(recall_response_to_proto(response)))
}

#[derive(Clone, Copy)]
enum HighLevelControlCall {
    Pin,
    Suppress,
    ChangeAudience,
    ChangeRetention,
    UpdateConfiguredRole,
    MigrateAgentRuntime,
    PublishToSharedMemory,
    RevokeSharedMemory,
    DeleteArtifactLineage,
}

impl HighLevelControlCall {
    const fn canonical_operation(self) -> &'static str {
        match self {
            Self::Pin => "contextdb.v1.MemoryControlService/Pin",
            Self::Suppress => "contextdb.v1.MemoryControlService/Suppress",
            Self::ChangeAudience => "contextdb.v1.MemoryControlService/ChangeAudience",
            Self::ChangeRetention => "contextdb.v1.MemoryControlService/ChangeRetention",
            Self::UpdateConfiguredRole => {
                "contextdb.v1.SubjectRelationshipService/UpdateConfiguredRole"
            }
            Self::MigrateAgentRuntime => {
                "contextdb.v1.SubjectRelationshipService/MigrateAgentRuntime"
            }
            Self::PublishToSharedMemory => {
                "contextdb.v1.SubjectRelationshipService/PublishToSharedMemory"
            }
            Self::RevokeSharedMemory => {
                "contextdb.v1.SubjectRelationshipService/RevokeSharedMemory"
            }
            Self::DeleteArtifactLineage => "contextdb.v1.ArtifactService/DeleteArtifactLineage",
        }
    }

    fn required_capabilities(self) -> &'static [contextdb_service::Capability] {
        use contextdb_service::Capability::{Correct, Forget, HardDelete, Runtime};
        match self {
            Self::Pin
            | Self::Suppress
            | Self::ChangeAudience
            | Self::ChangeRetention
            | Self::PublishToSharedMemory
            | Self::RevokeSharedMemory => &[Correct],
            Self::UpdateConfiguredRole | Self::MigrateAgentRuntime => &[Runtime],
            Self::DeleteArtifactLineage => &[Forget, HardDelete],
        }
    }
}

async fn high_level_control_once(
    service: &Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: &dyn GatewayAuthenticator,
    execution_admission: &SharedExecutionAdmission,
    request: Request<wire::HighLevelControlRequest>,
    call: HighLevelControlCall,
) -> Result<Response<wire::MutationResponse>, Status> {
    validate_high_level_transport_authentication(
        gateway_authenticator,
        &request,
        request.get_ref().context.as_ref(),
        call.canonical_operation(),
        call.required_capabilities(),
    )?;
    let request =
        high_level_control_request_from_proto(request.into_inner()).map_err(grpc_status)?;
    let service = Arc::clone(service);
    let response = run_blocking(
        Arc::clone(execution_admission),
        ExecutionClass::Interactive,
        move || match call {
            HighLevelControlCall::Pin => service.pin(request),
            HighLevelControlCall::Suppress => service.suppress(request),
            HighLevelControlCall::ChangeAudience => service.change_audience(request),
            HighLevelControlCall::ChangeRetention => service.change_retention(request),
            HighLevelControlCall::UpdateConfiguredRole => service.update_configured_role(request),
            HighLevelControlCall::MigrateAgentRuntime => service.migrate_agent_runtime(request),
            HighLevelControlCall::PublishToSharedMemory => {
                service.publish_to_shared_memory(request)
            }
            HighLevelControlCall::RevokeSharedMemory => service.revoke_shared_memory(request),
            HighLevelControlCall::DeleteArtifactLineage => service.delete_artifact_lineage(request),
        },
    )
    .await?;
    Ok(Response::new(mutation_response_to_proto(response)))
}

macro_rules! impl_high_level_service {
    (
        $service:path;
        writes { $( $write_name:ident => $write_call:ident ),* $(,)? }
        queries { $( $query_name:ident => $query_call:ident ),* $(,)? }
        controls { $( $control_name:ident => $control_call:ident ),* $(,)? }
        extra { $( $extra:item )* }
    ) => {
        #[tonic::async_trait]
        impl $service for GrpcAdapter {
            $(
                async fn $write_name(
                    &self,
                    request: Request<wire::HighLevelWriteRequest>,
                ) -> Result<Response<wire::HighLevelMutationResponse>, Status> {
                    high_level_write_once(
                        &self.service,
                        self.gateway_authenticator.as_ref(),
                        &self.execution_admission,
                        request,
                        HighLevelWriteCall::$write_call,
                    )
                    .await
                }
            )*
            $(
                async fn $query_name(
                    &self,
                    request: Request<wire::HighLevelQueryRequest>,
                ) -> Result<Response<wire::RecallResponse>, Status> {
                    high_level_query_once(
                        &self.service,
                        self.gateway_authenticator.as_ref(),
                        &self.execution_admission,
                        request,
                        HighLevelQueryCall::$query_call,
                    )
                    .await
                }
            )*
            $(
                async fn $control_name(
                    &self,
                    request: Request<wire::HighLevelControlRequest>,
                ) -> Result<Response<wire::MutationResponse>, Status> {
                    high_level_control_once(
                        &self.service,
                        self.gateway_authenticator.as_ref(),
                        &self.execution_admission,
                        request,
                        HighLevelControlCall::$control_call,
                    )
                    .await
                }
            )*
            $( $extra )*
        }
    };
}

impl_high_level_service! {
    ConversationService;
    writes {
        begin_session => BeginSession,
        after_turn => AfterTurn,
        end_session => EndSession,
        bootstrap_subject => BootstrapSubject,
    }
    queries {
        before_turn => BeforeTurn,
        resolve_referent => ResolveReferent,
        recall_shared_history => RecallSharedHistory,
    }
    controls {}
    extra {}
}

impl_high_level_service! {
    MemoryControlService;
    writes { remember => Remember }
    queries {
        explain_memory => ExplainMemory,
        list_subject_memories => ListSubjectMemories,
    }
    controls {
        pin => Pin,
        suppress => Suppress,
        change_audience => ChangeAudience,
        change_retention => ChangeRetention,
    }
    extra {
        async fn export_subject(
            &self,
            request: Request<wire::HighLevelTransferRequest>,
        ) -> Result<Response<wire::ExportResponse>, Status> {
            validate_high_level_transport_authentication(
                self.gateway_authenticator.as_ref(),
                &request,
                request.get_ref().context.as_ref(),
                "contextdb.v1.MemoryControlService/ExportSubject",
                &[contextdb_service::Capability::ReadMemory],
            )?;
            let request = high_level_transfer_request_from_proto(request.into_inner())
                .map_err(grpc_status)?;
            let service = Arc::clone(&self.service);
            let response = run_blocking(
                Arc::clone(&self.execution_admission),
                ExecutionClass::BulkTransfer,
                move || service.export_subject(request),
            ).await?;
            Ok(Response::new(export_response_to_proto(response)))
        }

        async fn import_subject(
            &self,
            request: Request<wire::HighLevelTransferRequest>,
        ) -> Result<Response<wire::ImportResponse>, Status> {
            validate_high_level_transport_authentication(
                self.gateway_authenticator.as_ref(),
                &request,
                request.get_ref().context.as_ref(),
                "contextdb.v1.MemoryControlService/ImportSubject",
                &[
                    contextdb_service::Capability::Observe,
                    contextdb_service::Capability::Admin,
                ],
            )?;
            let request = high_level_transfer_request_from_proto(request.into_inner())
                .map_err(grpc_status)?;
            let service = Arc::clone(&self.service);
            let response = run_blocking(
                Arc::clone(&self.execution_admission),
                ExecutionClass::BulkTransfer,
                move || service.import_subject(request),
            ).await?;
            Ok(Response::new(import_response_to_proto(response)))
        }
    }
}

impl_high_level_service! {
    SubjectRelationshipService;
    writes {
        create_memory_subject => CreateMemorySubject,
        create_relationship_space => CreateRelationshipSpace,
    }
    queries { get_continuity_profile => GetContinuityProfile }
    controls {
        update_configured_role => UpdateConfiguredRole,
        migrate_agent_runtime => MigrateAgentRuntime,
        publish_to_shared_memory => PublishToSharedMemory,
        revoke_shared_memory => RevokeSharedMemory,
    }
    extra {}
}

impl_high_level_service! {
    ArtifactService;
    writes {
        ingest_artifact => IngestArtifact,
        attach_artifact_to_episode => AttachArtifactToEpisode,
        add_derived_representation => AddDerivedRepresentation,
        add_evidence_selector => AddEvidenceSelector,
    }
    queries { get_artifact_metadata => GetArtifactMetadata }
    controls { delete_artifact_lineage => DeleteArtifactLineage }
    extra {}
}

/// Serves all canonical gRPC domain services until the server exits.
pub async fn serve_grpc(
    address: SocketAddr,
    service: Arc<dyn CognitiveMemoryService>,
) -> Result<(), tonic::transport::Error> {
    serve_grpc_with_shutdown(address, service, std::future::pending()).await
}

/// Serves all gRPC services with an explicitly configured trusted gateway.
pub async fn serve_grpc_with_gateway_authenticator(
    address: SocketAddr,
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
) -> Result<(), tonic::transport::Error> {
    serve_grpc_with_shutdown_and_gateway(
        address,
        service,
        gateway_authenticator,
        std::future::pending(),
    )
    .await
}

/// Serves all canonical gRPC services with graceful shutdown.
pub async fn serve_grpc_with_shutdown<F>(
    address: SocketAddr,
    service: Arc<dyn CognitiveMemoryService>,
    signal: F,
) -> Result<(), tonic::transport::Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_grpc_with_shutdown_and_gateway(
        address,
        service,
        Arc::new(RejectingGatewayAuthenticator),
        signal,
    )
    .await
}

/// Serves all gRPC services with trusted gateway verification and graceful
/// shutdown.
pub async fn serve_grpc_with_shutdown_and_gateway<F>(
    address: SocketAddr,
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    signal: F,
) -> Result<(), tonic::transport::Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    let adapter = GrpcAdapter::with_gateway_authenticator(service, 32, gateway_authenticator);
    tonic::transport::Server::builder()
        .concurrency_limit_per_connection(MAX_CONCURRENT_REQUESTS_PER_CONNECTION)
        .http2_max_header_list_size(MAX_GRPC_HEADER_LIST_BYTES)
        .add_service(
            wire::observation_service_server::ObservationServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::subscription_service_server::SubscriptionServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::agent_runtime_service_server::AgentRuntimeServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::memory_service_server::MemoryServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::recall_service_server::RecallServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::archive_service_server::ArchiveServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::maintenance_service_server::MaintenanceServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::admin_service_server::AdminServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::conversation_service_server::ConversationServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::memory_control_service_server::MemoryControlServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::subject_relationship_service_server::SubjectRelationshipServiceServer::new(
                adapter.clone(),
            )
            .max_decoding_message_size(MAX_WIRE_BYTES)
            .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::artifact_service_server::ArtifactServiceServer::new(adapter)
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .serve_with_shutdown(address, signal)
        .await
}

/// Serves all canonical gRPC services on an already-bound listener. This is
/// useful for supervisors that bind sockets before privilege dropping and for
/// race-free conformance tests.
pub async fn serve_grpc_listener_with_shutdown<F>(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
    signal: F,
) -> Result<(), tonic::transport::Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_grpc_listener_with_shutdown_and_gateway(
        listener,
        service,
        Arc::new(RejectingGatewayAuthenticator),
        signal,
    )
    .await
}

/// Serves all gRPC services on a pre-bound listener with an explicitly
/// configured trusted gateway and graceful shutdown.
pub async fn serve_grpc_listener_with_shutdown_and_gateway<F>(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    signal: F,
) -> Result<(), tonic::transport::Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_grpc_listener_with_shutdown_gateway_and_admission(
        listener,
        service,
        gateway_authenticator,
        Arc::new(ExecutionAdmission::default()),
        signal,
    )
    .await
}

/// Serves all gRPC services on a pre-bound listener with trusted gateway,
/// shared blocking-execution admission, and graceful shutdown.
pub async fn serve_grpc_listener_with_shutdown_gateway_and_admission<F>(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    execution_admission: SharedExecutionAdmission,
    signal: F,
) -> Result<(), tonic::transport::Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    let adapter = GrpcAdapter::with_gateway_authenticator_and_admission(
        service,
        32,
        gateway_authenticator,
        execution_admission,
    );
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .concurrency_limit_per_connection(MAX_CONCURRENT_REQUESTS_PER_CONNECTION)
        .http2_max_header_list_size(MAX_GRPC_HEADER_LIST_BYTES)
        .add_service(
            wire::observation_service_server::ObservationServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::subscription_service_server::SubscriptionServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::agent_runtime_service_server::AgentRuntimeServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::memory_service_server::MemoryServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::recall_service_server::RecallServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::archive_service_server::ArchiveServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::maintenance_service_server::MaintenanceServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::admin_service_server::AdminServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::conversation_service_server::ConversationServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::memory_control_service_server::MemoryControlServiceServer::new(adapter.clone())
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::subject_relationship_service_server::SubjectRelationshipServiceServer::new(
                adapter.clone(),
            )
            .max_decoding_message_size(MAX_WIRE_BYTES)
            .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .add_service(
            wire::artifact_service_server::ArtifactServiceServer::new(adapter)
                .max_decoding_message_size(MAX_WIRE_BYTES)
                .max_encoding_message_size(MAX_WIRE_BYTES),
        )
        .serve_with_incoming_shutdown(incoming, signal)
        .await
}
