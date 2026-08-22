use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use contextdb_proto::v1 as wire;
use contextdb_proto::v1::archive_service_server::ArchiveService;
use contextdb_proto::v1::maintenance_service_server::MaintenanceService;
use contextdb_proto::v1::observation_service_server::ObservationService;
use contextdb_proto::v1::recall_service_server::RecallService;
use contextdb_server::{
    Blake3GatewayAuthenticator, GATEWAY_ATTESTATION_HEADER, GATEWAY_ID_HEADER, GatewayTransport,
    GrpcAdapter as ServerGrpcAdapter, LegacyNetworkOperation, observe_request_to_proto,
    observe_response_from_proto, recall_request_to_proto, recall_response_from_proto,
    recall_trace_to_proto, request_context_to_proto,
};
use contextdb_service::{
    CognitiveMemoryService, ErrorCode, ExportResponse, ImportResponse, RecallTrace, RequestContext,
    VerifyResponse, Watermarks,
};
use prost::Message;
use tonic::{Request, Status};

use super::{AdapterFuture, ConformanceAdapter};
use crate::{
    CanonicalError, CanonicalOperation, CanonicalResponse, CapabilityManifest, ConformanceError,
    InterfaceKind, grpc_manifest,
};

/// In-process invocation of the generated gRPC service traits. Requests and
/// responses cross the real Protobuf conversion layer; network framing and
/// streaming are covered by `GrpcStreamingProbe`.
#[derive(Clone, Debug)]
pub struct GrpcAdapter {
    server: ServerGrpcAdapter,
    gateway: Arc<Blake3GatewayAuthenticator>,
}

const GATEWAY_KEY: [u8; 32] = [0x72; 32];
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

const fn grpc_operation_id(operation: LegacyNetworkOperation) -> Option<&'static str> {
    match operation {
        LegacyNetworkOperation::GrpcObserve => Some("contextdb.v1.ObservationService/Observe"),
        LegacyNetworkOperation::GrpcObserveStream => {
            Some("contextdb.v1.ObservationService/ObserveStream")
        }
        LegacyNetworkOperation::GrpcRecall => Some("contextdb.v1.RecallService/Recall"),
        LegacyNetworkOperation::GrpcRecallStream => Some("contextdb.v1.RecallService/RecallStream"),
        LegacyNetworkOperation::GrpcContinueRecall => {
            Some("contextdb.v1.RecallService/ContinueRecall")
        }
        LegacyNetworkOperation::GrpcExplainRecall => {
            Some("contextdb.v1.RecallService/ExplainRecall")
        }
        LegacyNetworkOperation::GrpcArchiveExport => Some("contextdb.v1.ArchiveService/Export"),
        LegacyNetworkOperation::GrpcArchiveImport => Some("contextdb.v1.ArchiveService/Import"),
        LegacyNetworkOperation::GrpcMaintenanceVerify => {
            Some("contextdb.v1.MaintenanceService/Verify")
        }
        LegacyNetworkOperation::HttpObserve
        | LegacyNetworkOperation::HttpRecall
        | LegacyNetworkOperation::HttpExplainRecall
        | LegacyNetworkOperation::HttpExport
        | LegacyNetworkOperation::HttpImport
        | LegacyNetworkOperation::HttpVerify => None,
    }
}

impl GrpcAdapter {
    /// Creates a gRPC adapter with the production stream window.
    #[must_use]
    pub fn new(service: Arc<dyn CognitiveMemoryService>) -> Self {
        let gateway = Arc::new(
            Blake3GatewayAuthenticator::new("gateway:conformance-grpc", GATEWAY_KEY)
                .expect("static conformance gateway configuration is valid"),
        );
        Self {
            server: ServerGrpcAdapter::with_gateway_authenticator(service, 32, gateway.clone()),
            gateway,
        }
    }
}

impl ConformanceAdapter for GrpcAdapter {
    fn interface(&self) -> InterfaceKind {
        InterfaceKind::Grpc
    }

    fn manifest(&self) -> CapabilityManifest {
        grpc_manifest()
    }

    fn invoke(&mut self, operation: CanonicalOperation) -> AdapterFuture<'_> {
        let server = self.server.clone();
        let gateway = Arc::clone(&self.gateway);
        Box::pin(async move {
            let response = match operation {
                CanonicalOperation::Observe(request) => {
                    let context = request.context.clone();
                    let request = observe_request_to_proto(request)
                        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
                    ObservationService::observe(
                        &server,
                        legacy_request(
                            request,
                            LegacyNetworkOperation::GrpcObserve,
                            &context,
                            &gateway,
                        )?,
                    )
                    .await
                    .map(|response| response.into_inner())
                    .map_err(status_error)
                    .and_then(|response| observe_response_from_proto(response).map_err(Into::into))
                    .map(CanonicalResponse::Observe)
                }
                CanonicalOperation::Recall(request) => {
                    let context = request.context.clone();
                    RecallService::recall(
                        &server,
                        legacy_request(
                            recall_request_to_proto(request),
                            LegacyNetworkOperation::GrpcRecall,
                            &context,
                            &gateway,
                        )?,
                    )
                    .await
                    .map(|response| response.into_inner())
                    .map_err(status_error)
                    .and_then(|response| recall_response_from_proto(response).map_err(Into::into))
                    .map(CanonicalResponse::Recall)
                }
                CanonicalOperation::ExplainRecall(request) => {
                    let context = request.context.clone();
                    let request = wire::ExplainRecallRequest {
                        context: Some(request_context_to_proto(request.context)),
                        trace: Some(recall_trace_to_proto(request.trace)),
                    };
                    RecallService::explain_recall(
                        &server,
                        legacy_request(
                            request,
                            LegacyNetworkOperation::GrpcExplainRecall,
                            &context,
                            &gateway,
                        )?,
                    )
                    .await
                    .map(|response| trace_from_proto(response.into_inner()))
                    .map_err(status_error)
                    .and_then(|response| response)
                    .map(CanonicalResponse::ExplainRecall)
                }
                CanonicalOperation::Export(request) => {
                    let context = request.context.clone();
                    let request = wire::ExportRequest {
                        context: Some(request_context_to_proto(request.context)),
                    };
                    ArchiveService::export(
                        &server,
                        legacy_request(
                            request,
                            LegacyNetworkOperation::GrpcArchiveExport,
                            &context,
                            &gateway,
                        )?,
                    )
                    .await
                    .map(|response| {
                        let response = response.into_inner();
                        ExportResponse {
                            format: response.format,
                            bytes: response.archive,
                            digest: response.digest,
                            commit_seq: response.commit_seq,
                        }
                    })
                    .map_err(status_error)
                    .map(CanonicalResponse::Export)
                }
                CanonicalOperation::Import(request) => {
                    let context = request.context.clone();
                    let request = wire::ImportRequest {
                        context: Some(request_context_to_proto(request.context)),
                        format: request.format,
                        archive: request.bytes,
                        digest: request.digest,
                    };
                    ArchiveService::import(
                        &server,
                        legacy_request(
                            request,
                            LegacyNetworkOperation::GrpcArchiveImport,
                            &context,
                            &gateway,
                        )?,
                    )
                    .await
                    .map(|response| response.into_inner())
                    .map_err(status_error)
                    .and_then(import_from_proto)
                    .map(CanonicalResponse::Import)
                }
                CanonicalOperation::Verify(request) => {
                    let context = request.context.clone();
                    let request = wire::VerifyRequest {
                        context: Some(request_context_to_proto(request.context)),
                        deep: request.deep,
                    };
                    MaintenanceService::verify(
                        &server,
                        legacy_request(
                            request,
                            LegacyNetworkOperation::GrpcMaintenanceVerify,
                            &context,
                            &gateway,
                        )?,
                    )
                    .await
                    .map(|response| {
                        let response = response.into_inner();
                        VerifyResponse {
                            valid: response.valid,
                            commit_seq: response.commit_seq,
                            archive_digest: response.archive_digest,
                        }
                    })
                    .map_err(status_error)
                    .map(CanonicalResponse::Verify)
                }
            };
            Ok(response)
        })
    }
}

fn legacy_request<T: Message>(
    message: T,
    operation: LegacyNetworkOperation,
    _context: &RequestContext,
    gateway: &Blake3GatewayAuthenticator,
) -> Result<Request<T>, ConformanceError> {
    let operation = grpc_operation_id(operation).ok_or_else(|| {
        ConformanceError::Protocol("HTTP operation used for a gRPC request".to_owned())
    })?;
    let body = message.encode_to_vec();
    let token = gateway
        .attest_exact_request(
            GatewayTransport::Grpc,
            operation,
            &body,
            unique_gateway_nonce(),
        )
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    let mut request = Request::new(message);
    let (service, method) = operation.split_once('/').ok_or_else(|| {
        ConformanceError::Protocol("canonical gRPC operation is invalid".to_owned())
    })?;
    request
        .extensions_mut()
        .insert(tonic::GrpcMethod::new(service, method));
    request.metadata_mut().insert(
        GATEWAY_ID_HEADER,
        gateway
            .gateway_id()
            .parse()
            .map_err(|error| ConformanceError::Protocol(format!("gateway metadata: {error}")))?,
    );
    request.metadata_mut().insert(
        GATEWAY_ATTESTATION_HEADER,
        token.parse().map_err(|error| {
            ConformanceError::Protocol(format!("gateway attestation metadata: {error}"))
        })?,
    );
    Ok(request)
}

fn watermarks_from_proto(value: Option<wire::Watermarks>) -> Result<Watermarks, CanonicalError> {
    value
        .map(|value| Watermarks {
            journal: value.journal,
            semantic: value.semantic,
            lexical: value.lexical,
            vector: value.vector,
            graph: value.graph,
        })
        .ok_or_else(|| CanonicalError {
            code: ErrorCode::FormatIncompatible,
            message: "required Protobuf watermarks are missing".to_owned(),
            retryable: false,
            partial_result_refs: Box::default(),
            violated_policy: None,
            safe_next_action: None,
            trace_id: None,
        })
}

fn trace_from_proto(value: wire::RecallTrace) -> Result<RecallTrace, CanonicalError> {
    Ok(RecallTrace {
        trace_id: value.trace_id,
        snapshot_seq: value.snapshot_seq,
        operation: value.operation,
        authorized_candidates: value.authorized_candidates,
        selected_ids: value.selected_ids,
        watermarks: watermarks_from_proto(value.watermarks)?,
    })
}

fn import_from_proto(value: wire::ImportResponse) -> Result<ImportResponse, CanonicalError> {
    Ok(ImportResponse {
        commit_seq: value.commit_seq,
        watermarks: watermarks_from_proto(value.watermarks)?,
    })
}

fn status_error(status: Status) -> CanonicalError {
    if let Ok(details) = wire::ErrorStatus::decode(status.details())
        && let Some(code) = wire_error_code(details.code)
    {
        return CanonicalError {
            code,
            message: details.message,
            retryable: details.retryable,
            partial_result_refs: details.partial_result_refs.into_boxed_slice(),
            violated_policy: details.violated_policy.map(String::into_boxed_str),
            safe_next_action: details.safe_next_action.map(String::into_boxed_str),
            trace_id: details.trace_id.map(String::into_boxed_str),
        };
    }
    let text = status.message();
    let (name, message) = text.split_once(": ").unwrap_or(("", text));
    let code = parse_error_code(name).unwrap_or_else(|| match status.code() {
        tonic::Code::InvalidArgument => ErrorCode::InvalidArgument,
        tonic::Code::PermissionDenied => ErrorCode::PermissionDenied,
        tonic::Code::NotFound => ErrorCode::NotFound,
        tonic::Code::AlreadyExists => ErrorCode::IdempotencyConflict,
        tonic::Code::ResourceExhausted => ErrorCode::ResourceExhausted,
        tonic::Code::Unavailable => ErrorCode::Unavailable,
        tonic::Code::Unimplemented => ErrorCode::Unsupported,
        tonic::Code::DataLoss => ErrorCode::IntegrityFailure,
        _ => ErrorCode::FormatIncompatible,
    });
    CanonicalError {
        code,
        message: message.to_owned(),
        retryable: matches!(
            code,
            ErrorCode::Unavailable | ErrorCode::ProviderUnavailable | ErrorCode::IndexTooStale
        ),
        partial_result_refs: Box::default(),
        violated_policy: None,
        safe_next_action: None,
        trace_id: None,
    }
}

fn wire_error_code(value: i32) -> Option<ErrorCode> {
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

fn parse_error_code(value: &str) -> Option<ErrorCode> {
    let codes = [
        ("InvalidScope", ErrorCode::InvalidScope),
        ("Unauthorized", ErrorCode::Unauthorized),
        ("AmbiguousIdentity", ErrorCode::AmbiguousIdentity),
        ("SnapshotExpired", ErrorCode::SnapshotExpired),
        ("IndexTooStale", ErrorCode::IndexTooStale),
        ("EvidenceRequired", ErrorCode::EvidenceRequired),
        ("ConflictUnresolved", ErrorCode::ConflictUnresolved),
        ("BudgetExhausted", ErrorCode::BudgetExhausted),
        ("ContinuationExpired", ErrorCode::ContinuationExpired),
        ("FormatIncompatible", ErrorCode::FormatIncompatible),
        ("ProviderUnavailable", ErrorCode::ProviderUnavailable),
        ("DegradedMode", ErrorCode::DegradedMode),
        ("InvalidArgument", ErrorCode::InvalidArgument),
        ("PermissionDenied", ErrorCode::PermissionDenied),
        ("NotFound", ErrorCode::NotFound),
        ("IdempotencyConflict", ErrorCode::IdempotencyConflict),
        ("InvalidContinuation", ErrorCode::InvalidContinuation),
        ("IntegrityFailure", ErrorCode::IntegrityFailure),
        ("Unavailable", ErrorCode::Unavailable),
        ("ResourceExhausted", ErrorCode::ResourceExhausted),
        ("Unsupported", ErrorCode::Unsupported),
    ];
    codes
        .into_iter()
        .find_map(|(name, code)| (name == value).then_some(code))
}
