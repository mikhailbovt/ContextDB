use axum::body::{Body, to_bytes};
use axum::http::{Method, Request};
use contextdb_server::{
    Blake3GatewayAuthenticator, GATEWAY_ATTESTATION_HEADER, GATEWAY_ID_HEADER, GatewayTransport,
    HttpErrorBody, LegacyNetworkOperation, MAX_WIRE_BYTES, http_router_with_gateway_authenticator,
};
use contextdb_service::CognitiveMemoryService;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

use super::{AdapterFuture, ConformanceAdapter};
use crate::{
    CanonicalError, CanonicalOperation, CanonicalResponse, CapabilityManifest, ConformanceError,
    InterfaceKind, http_manifest,
};

#[derive(Clone, Copy, Debug)]
enum ResponseKind {
    Observe,
    Recall,
    Explain,
    Export,
    Import,
    Verify,
}

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

/// In-process HTTP adapter which still traverses the real Axum router, JSON
/// codec, body limit, status mapping, and error envelope.
#[derive(Clone, Debug)]
pub struct HttpAdapter {
    router: axum::Router,
    gateway: Arc<Blake3GatewayAuthenticator>,
}

const GATEWAY_KEY: [u8; 32] = [0x71; 32];

/// Evidence that framework-level HTTP failures use the canonical typed error
/// plane rather than Axum's default plaintext rejection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProtocolProof {
    /// Malformed JSON maps to 400 / InvalidArgument.
    pub malformed_json: bool,
    /// Structurally incompatible JSON maps to 422 / FormatIncompatible.
    pub incompatible_schema: bool,
    /// Payload over the fixed wire limit maps to 413 / ResourceExhausted.
    pub oversized_body: bool,
}

impl HttpProtocolProof {
    /// True only when all framework-level mappings passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.malformed_json && self.incompatible_schema && self.oversized_body
    }
}

impl HttpAdapter {
    /// Creates an adapter over the canonical HTTP router.
    #[must_use]
    pub fn new(service: Arc<dyn CognitiveMemoryService>) -> Self {
        let gateway = Arc::new(
            Blake3GatewayAuthenticator::new("gateway:conformance-http", GATEWAY_KEY)
                .expect("static conformance gateway configuration is valid"),
        );
        Self {
            router: http_router_with_gateway_authenticator(service, gateway.clone()),
            gateway,
        }
    }
}

/// Exercises raw HTTP bodies which never reach the canonical service method.
pub async fn prove_http_protocol_errors(
    service: Arc<dyn CognitiveMemoryService>,
) -> Result<HttpProtocolProof, ConformanceError> {
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:conformance-http-errors", GATEWAY_KEY)
            .expect("static conformance gateway configuration is valid"),
    );
    let router = http_router_with_gateway_authenticator(service, gateway.clone());
    let malformed = raw_error(router.clone(), gateway.as_ref(), b"{".to_vec()).await?;
    let incompatible = raw_error(router.clone(), gateway.as_ref(), b"{}".to_vec()).await?;
    let oversized = raw_error(
        router,
        gateway.as_ref(),
        vec![b'x'; MAX_WIRE_BYTES.saturating_add(1)],
    )
    .await?;
    Ok(HttpProtocolProof {
        malformed_json: malformed.0 == axum::http::StatusCode::BAD_REQUEST
            && malformed.1.code == contextdb_service::ErrorCode::InvalidArgument,
        incompatible_schema: incompatible.0 == axum::http::StatusCode::UNPROCESSABLE_ENTITY
            && incompatible.1.code == contextdb_service::ErrorCode::FormatIncompatible,
        oversized_body: oversized.0 == axum::http::StatusCode::PAYLOAD_TOO_LARGE
            && oversized.1.code == contextdb_service::ErrorCode::ResourceExhausted,
    })
}

async fn raw_error(
    router: axum::Router,
    gateway: &Blake3GatewayAuthenticator,
    body: Vec<u8>,
) -> Result<(axum::http::StatusCode, HttpErrorBody), ConformanceError> {
    const PATH: &str = "/v1/observations";
    let attestation = gateway
        .attest_exact_request(
            GatewayTransport::Http,
            "POST:/v1/observations",
            &body,
            unique_gateway_nonce(),
        )
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(PATH)
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(GATEWAY_ATTESTATION_HEADER, attestation)
        .body(Body::from(body))
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    let response = router
        .oneshot(request)
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), MAX_WIRE_BYTES.saturating_add(1))
        .await
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    Ok((status, decode(&bytes)?))
}

impl ConformanceAdapter for HttpAdapter {
    fn interface(&self) -> InterfaceKind {
        InterfaceKind::Http
    }

    fn manifest(&self) -> CapabilityManifest {
        http_manifest()
    }

    fn invoke(&mut self, operation: CanonicalOperation) -> AdapterFuture<'_> {
        let router = self.router.clone();
        let gateway = Arc::clone(&self.gateway);
        Box::pin(async move {
            let (path, body, kind, _legacy_operation, _context) = encode_operation(&operation)?;
            let attestation = gateway
                .attest_exact_request(
                    GatewayTransport::Http,
                    &format!("POST:{path}"),
                    &body,
                    unique_gateway_nonce(),
                )
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
            let request = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("content-type", "application/json")
                .header(GATEWAY_ID_HEADER, gateway.gateway_id())
                .header(GATEWAY_ATTESTATION_HEADER, attestation)
                .body(Body::from(body))
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
            let response = router
                .oneshot(request)
                .await
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
            let status = response.status();
            let bytes = to_bytes(response.into_body(), MAX_WIRE_BYTES.saturating_add(1))
                .await
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
            if status == axum::http::StatusCode::OK {
                Ok(Ok(decode_success(kind, &bytes)?))
            } else {
                let error: HttpErrorBody = decode(&bytes)?;
                Ok(Err(CanonicalError {
                    code: error.code,
                    message: error.message,
                    retryable: error.retryable,
                    partial_result_refs: error.partial_result_refs.into_boxed_slice(),
                    violated_policy: error.violated_policy.map(String::into_boxed_str),
                    safe_next_action: error.safe_next_action.map(String::into_boxed_str),
                    trace_id: error.trace_id.map(String::into_boxed_str),
                }))
            }
        })
    }
}

fn encode_operation(
    operation: &CanonicalOperation,
) -> Result<
    (
        &'static str,
        Vec<u8>,
        ResponseKind,
        LegacyNetworkOperation,
        &contextdb_service::RequestContext,
    ),
    ConformanceError,
> {
    let (path, value, kind, legacy_operation, context) = match operation {
        CanonicalOperation::Observe(request) => (
            "/v1/observations",
            serde_json::to_value(request),
            ResponseKind::Observe,
            LegacyNetworkOperation::HttpObserve,
            &request.context,
        ),
        CanonicalOperation::Recall(request) => (
            "/v1/recall",
            serde_json::to_value(request),
            ResponseKind::Recall,
            LegacyNetworkOperation::HttpRecall,
            &request.context,
        ),
        CanonicalOperation::ExplainRecall(request) => (
            "/v1/recall/explain",
            serde_json::to_value(request),
            ResponseKind::Explain,
            LegacyNetworkOperation::HttpExplainRecall,
            &request.context,
        ),
        CanonicalOperation::Export(request) => (
            "/v1/archive/export",
            serde_json::to_value(request),
            ResponseKind::Export,
            LegacyNetworkOperation::HttpExport,
            &request.context,
        ),
        CanonicalOperation::Import(request) => (
            "/v1/archive/import",
            serde_json::to_value(request),
            ResponseKind::Import,
            LegacyNetworkOperation::HttpImport,
            &request.context,
        ),
        CanonicalOperation::Verify(request) => (
            "/v1/verify",
            serde_json::to_value(request),
            ResponseKind::Verify,
            LegacyNetworkOperation::HttpVerify,
            &request.context,
        ),
    };
    let value = value.map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    let body = serde_json::to_vec(&value)
        .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    Ok((path, body, kind, legacy_operation, context))
}

fn decode_success(kind: ResponseKind, bytes: &[u8]) -> Result<CanonicalResponse, ConformanceError> {
    match kind {
        ResponseKind::Observe => decode(bytes).map(CanonicalResponse::Observe),
        ResponseKind::Recall => decode(bytes).map(CanonicalResponse::Recall),
        ResponseKind::Explain => decode(bytes).map(CanonicalResponse::ExplainRecall),
        ResponseKind::Export => decode(bytes).map(CanonicalResponse::Export),
        ResponseKind::Import => decode(bytes).map(CanonicalResponse::Import),
        ResponseKind::Verify => decode(bytes).map(CanonicalResponse::Verify),
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ConformanceError> {
    serde_json::from_slice(bytes).map_err(|error| ConformanceError::Protocol(error.to_string()))
}
