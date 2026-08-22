use std::future::Future;
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRef, FromRequest, Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use contextdb_service::{
    AuthenticatedRequestContext, CognitiveMemoryService, CompileContextRequest, CorrectRequest,
    CreateBackupRequest, ErrorCode, ExplainRecallRequest, ExportRequest, ForgetRequest,
    GetMemoryRequest, GetStatusRequest, GetTimelineRequest, HighLevelControlRequest,
    HighLevelQueryRequest, HighLevelTransferRequest, HighLevelWriteRequest, ImportRequest,
    IngestFrame, MaintenanceRequest, MigrateFormatRequest, ObserveRequest, RecallRequest,
    RestoreBackupRequest, RuntimeRequest, ServiceError, SubscribeRequest, TraverseRequest,
    VerifyRequest,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::{
    ExecutionAdmission, ExecutionClass, FixedHealthProvider, GATEWAY_ATTESTATION_HEADER,
    GATEWAY_ID_HEADER, GatewayTransport, HealthSummary, LegacyNetworkOperation,
    MAX_GATEWAY_ATTESTATION_BYTES, MAX_GATEWAY_ID_BYTES, MAX_WIRE_BYTES,
    RejectingGatewayAuthenticator, SharedExecutionAdmission, SharedGatewayAuthenticator,
    SharedHealthProvider,
};

#[derive(Clone)]
struct HttpState {
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    health_provider: SharedHealthProvider,
    health_slots: Arc<tokio::sync::Semaphore>,
    execution_admission: SharedExecutionAdmission,
}

/// Stable payload-free HTTP error envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpErrorBody {
    /// Stable canonical error code.
    pub code: ErrorCode,
    /// Safe bounded message.
    pub message: String,
    /// Whether exact retry may succeed.
    pub retryable: bool,
    /// Safe references to partial results.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_result_refs: Vec<String>,
    /// Stable violated-policy identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violated_policy: Option<String>,
    /// Content-free remediation guidance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_next_action: Option<String>,
    /// Privacy-safe trace handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

struct HttpError(ServiceError);

impl From<ServiceError> for HttpError {
    fn from(value: ServiceError) -> Self {
        Self(value)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = match self.0.code {
            ErrorCode::InvalidScope
            | ErrorCode::AmbiguousIdentity
            | ErrorCode::EvidenceRequired
            | ErrorCode::InvalidArgument
            | ErrorCode::InvalidContinuation => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized | ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
            ErrorCode::SnapshotExpired | ErrorCode::ContinuationExpired => StatusCode::GONE,
            ErrorCode::IndexTooStale | ErrorCode::ConflictUnresolved => StatusCode::CONFLICT,
            ErrorCode::BudgetExhausted | ErrorCode::ResourceExhausted => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            ErrorCode::FormatIncompatible => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::ProviderUnavailable | ErrorCode::Unavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            ErrorCode::DegradedMode => StatusCode::PARTIAL_CONTENT,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::IdempotencyConflict => StatusCode::CONFLICT,
            ErrorCode::IntegrityFailure => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::Unsupported => StatusCode::NOT_IMPLEMENTED,
        };
        (
            status,
            Json(HttpErrorBody {
                code: self.0.code,
                message: self.0.message,
                retryable: self.0.retryable,
                partial_result_refs: self.0.partial_result_refs.into_vec(),
                violated_policy: self.0.violated_policy.map(Into::into),
                safe_next_action: self.0.safe_next_action.map(Into::into),
                trace_id: self.0.trace_id.map(Into::into),
            }),
        )
            .into_response()
    }
}

/// Constructs the canonical HTTP/JSON adapter router with a fail-closed gateway
/// policy. Protected v1 methods require
/// [`http_router_with_gateway_authenticator`].
pub fn http_router(service: Arc<dyn CognitiveMemoryService>) -> axum::Router {
    http_router_with_gateway_authenticator(service, Arc::new(RejectingGatewayAuthenticator))
}

/// Constructs a fail-closed application router with an explicit health source.
pub fn http_router_with_health_provider(
    service: Arc<dyn CognitiveMemoryService>,
    health_provider: SharedHealthProvider,
) -> axum::Router {
    http_router_with_gateway_authenticator_and_health(
        service,
        Arc::new(RejectingGatewayAuthenticator),
        health_provider,
    )
}

/// Constructs an HTTP/JSON adapter with an explicit trusted gateway verifier.
///
/// Protected methods authenticate the exact route and original bounded body
/// bytes before parsing any JSON or allocating request-controlled collections.
pub fn http_router_with_gateway_authenticator(
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
) -> axum::Router {
    http_router_with_gateway_authenticator_and_health(
        service,
        gateway_authenticator,
        Arc::new(FixedHealthProvider::not_configured()),
    )
}

/// Constructs the HTTP adapter with explicit gateway and health authorities.
pub fn http_router_with_gateway_authenticator_and_health(
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    health_provider: SharedHealthProvider,
) -> axum::Router {
    http_router_with_gateway_authenticator_health_and_admission(
        service,
        gateway_authenticator,
        health_provider,
        Arc::new(ExecutionAdmission::default()),
    )
}

/// Constructs the HTTP adapter with explicit gateway, health, and shared
/// blocking-execution admission authorities.
pub fn http_router_with_gateway_authenticator_health_and_admission(
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    health_provider: SharedHealthProvider,
    execution_admission: SharedExecutionAdmission,
) -> axum::Router {
    axum::Router::new()
        .route("/health/live", get(live_health))
        .route("/health/ready", get(ready_health))
        .route("/v1/observations", post(observe))
        .route("/v1/observations/ingest-frame", post(ingest_frame))
        .route("/v1/observations/correct", post(correct))
        .route("/v1/observations/forget", post(forget))
        .route("/v1/recall", post(recall))
        .route("/v1/recall/explain", post(explain))
        .route("/v1/context-pack", post(compile_context))
        .route("/v1/subscriptions/page", post(subscribe))
        .route("/v1/memory/node", post(get_node))
        .route("/v1/memory/traverse", post(traverse))
        .route("/v1/memory/timeline", post(get_timeline))
        .route("/v1/memory/evidence", post(get_evidence))
        .route("/v1/memory/conflict", post(get_conflict))
        .route("/v1/runtime/bootstrap", post(bootstrap))
        .route("/v1/runtime/preflight", post(preflight))
        .route("/v1/runtime/postflight", post(postflight))
        .route("/v1/runtime/checkpoint", post(checkpoint))
        .route("/v1/runtime/resume", post(resume))
        .route("/v1/runtime/handoff", post(handoff))
        .route("/v1/maintenance/consolidate", post(consolidate))
        .route("/v1/maintenance/reflect", post(reflect))
        .route("/v1/maintenance/reindex", post(reindex))
        .route("/v1/maintenance/compact", post(compact))
        .route("/v1/admin/status", post(get_status))
        .route("/v1/admin/backup", post(create_backup))
        .route("/v1/admin/restore", post(restore_backup))
        .route("/v1/admin/migrate", post(migrate_format))
        .route("/v1/archive/export", post(export))
        .route("/v1/archive/import", post(import))
        .route("/v1/verify", post(verify))
        .route("/v1/conversation/begin-session", post(begin_session))
        .route("/v1/conversation/before-turn", post(before_turn))
        .route("/v1/conversation/after-turn", post(after_turn))
        .route("/v1/conversation/resolve-referent", post(resolve_referent))
        .route(
            "/v1/conversation/recall-shared-history",
            post(recall_shared_history),
        )
        .route("/v1/conversation/end-session", post(end_session))
        .route(
            "/v1/conversation/bootstrap-subject",
            post(bootstrap_subject),
        )
        .route("/v1/memory/remember", post(remember))
        .route("/v1/memory/pin", post(pin))
        .route("/v1/memory/suppress", post(suppress))
        .route("/v1/memory/change-audience", post(change_audience))
        .route("/v1/memory/change-retention", post(change_retention))
        .route("/v1/memory/explain", post(explain_memory))
        .route("/v1/memory/list-subject", post(list_subject_memories))
        .route("/v1/memory/export-subject", post(export_subject))
        .route("/v1/memory/import-subject", post(import_subject))
        .route("/v1/subjects/create", post(create_memory_subject))
        .route(
            "/v1/relationship-spaces/create",
            post(create_relationship_space),
        )
        .route(
            "/v1/subjects/continuity-profile",
            post(get_continuity_profile),
        )
        .route(
            "/v1/subjects/configured-role/update",
            post(update_configured_role),
        )
        .route(
            "/v1/subjects/agent-runtime/migrate",
            post(migrate_agent_runtime),
        )
        .route("/v1/shared-memory/publish", post(publish_to_shared_memory))
        .route("/v1/shared-memory/revoke", post(revoke_shared_memory))
        .route("/v1/artifacts/ingest", post(ingest_artifact))
        .route(
            "/v1/artifacts/attach-to-episode",
            post(attach_artifact_to_episode),
        )
        .route(
            "/v1/artifacts/derived-representations",
            post(add_derived_representation),
        )
        .route(
            "/v1/artifacts/evidence-selectors",
            post(add_evidence_selector),
        )
        .route("/v1/artifacts/metadata", post(get_artifact_metadata))
        .route(
            "/v1/artifacts/delete-lineage",
            post(delete_artifact_lineage),
        )
        .layer(DefaultBodyLimit::max(MAX_WIRE_BYTES))
        .with_state(HttpState {
            service,
            gateway_authenticator,
            health_provider,
            health_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            execution_admission,
        })
}

async fn live_health() -> Response {
    health_response(StatusCode::OK, HealthSummary::live())
}

async fn ready_health(State(state): State<HttpState>) -> Response {
    let Ok(permit) = Arc::clone(&state.health_slots).try_acquire_owned() else {
        return health_response(
            StatusCode::SERVICE_UNAVAILABLE,
            HealthSummary::health_check_busy(),
        );
    };
    let provider = Arc::clone(&state.health_provider);
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        provider.readiness()
    });
    let summary = match tokio::time::timeout(std::time::Duration::from_secs(1), task).await {
        Ok(Ok(summary)) => summary.sanitized(),
        Ok(Err(_)) => HealthSummary::invalid_provider(),
        Err(_) => HealthSummary::health_check_busy(),
    };
    let status = if summary.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    health_response(status, summary)
}

fn health_response(status: StatusCode, summary: HealthSummary) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(summary),
    )
        .into_response()
}

struct AuthenticatedBody {
    bytes: Bytes,
    context: AuthenticatedRequestContext,
}

struct LegacyAuthenticatedJson<T>(T);

trait LegacyHttpRequest: DeserializeOwned {
    const OPERATION: LegacyNetworkOperation;
}

impl LegacyHttpRequest for ObserveRequest {
    const OPERATION: LegacyNetworkOperation = LegacyNetworkOperation::HttpObserve;
}

impl LegacyHttpRequest for RecallRequest {
    const OPERATION: LegacyNetworkOperation = LegacyNetworkOperation::HttpRecall;
}

impl LegacyHttpRequest for ExplainRecallRequest {
    const OPERATION: LegacyNetworkOperation = LegacyNetworkOperation::HttpExplainRecall;
}

impl LegacyHttpRequest for ExportRequest {
    const OPERATION: LegacyNetworkOperation = LegacyNetworkOperation::HttpExport;
}

impl LegacyHttpRequest for ImportRequest {
    const OPERATION: LegacyNetworkOperation = LegacyNetworkOperation::HttpImport;
}

impl LegacyHttpRequest for VerifyRequest {
    const OPERATION: LegacyNetworkOperation = LegacyNetworkOperation::HttpVerify;
}

#[derive(Deserialize)]
struct RawAuthenticationEnvelope<'a> {
    #[serde(borrow)]
    context: &'a RawValue,
}

impl<S> FromRequest<S> for AuthenticatedBody
where
    S: Send + Sync,
    HttpState: FromRef<S>,
{
    type Rejection = HttpError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let http_state = HttpState::from_ref(state);
        validate_json_content_type(request.headers())?;
        let (gateway_id, attestation) = exact_request_headers(request.headers())?;
        let operation = format!("{}:{}", request.method(), request.uri().path());
        let bytes = read_bounded_body(request, state).await?;
        http_state.gateway_authenticator.verify_exact_request(
            Some(gateway_id.to_str().map_err(|_| invalid_gateway_headers())?),
            Some(
                attestation
                    .to_str()
                    .map_err(|_| invalid_gateway_headers())?,
            ),
            GatewayTransport::Http,
            &operation,
            &bytes,
        )?;
        let envelope: RawAuthenticationEnvelope<'_> =
            serde_json::from_slice(&bytes).map_err(authentication_envelope_error)?;
        let context: AuthenticatedRequestContext =
            serde_json::from_str(envelope.context.get()).map_err(authentication_envelope_error)?;
        context.validate_authentication()?;
        Ok(Self { bytes, context })
    }
}

fn decode_authenticated<T: DeserializeOwned>(
    body: AuthenticatedBody,
    capabilities: &[contextdb_service::Capability],
) -> Result<T, HttpError> {
    for capability in capabilities {
        contextdb_service::authorize_capability(&body.context, *capability)?;
    }
    serde_json::from_slice(&body.bytes).map_err(full_json_error)
}

#[derive(Deserialize)]
struct ForgetAuthorizationEnvelope {
    mode: contextdb_service::ForgetMode,
}

fn decode_forget(body: AuthenticatedBody) -> Result<ForgetRequest, HttpError> {
    contextdb_service::authorize_capability(&body.context, contextdb_service::Capability::Forget)?;
    let envelope: ForgetAuthorizationEnvelope =
        serde_json::from_slice(&body.bytes).map_err(full_json_error)?;
    if envelope.mode == contextdb_service::ForgetMode::HardDelete {
        contextdb_service::authorize_capability(
            &body.context,
            contextdb_service::Capability::HardDelete,
        )?;
    }
    serde_json::from_slice(&body.bytes).map_err(full_json_error)
}

#[derive(Deserialize)]
struct TimelineAuthorizationEnvelope {
    expected_kind: contextdb_service::MemoryRecordKind,
}

fn decode_timeline(body: AuthenticatedBody) -> Result<GetTimelineRequest, HttpError> {
    let envelope: TimelineAuthorizationEnvelope =
        serde_json::from_slice(&body.bytes).map_err(full_json_error)?;
    match envelope.expected_kind {
        contextdb_service::MemoryRecordKind::Evidence => {
            contextdb_service::authorize_capability(
                &body.context,
                contextdb_service::Capability::ReadEvidence,
            )?;
            contextdb_service::authorize_capability(
                &body.context,
                contextdb_service::Capability::RawEvidence,
            )?;
        }
        contextdb_service::MemoryRecordKind::Conflict => {
            contextdb_service::authorize_capability(
                &body.context,
                contextdb_service::Capability::ReadConflict,
            )?;
        }
        _ => contextdb_service::authorize_capability(
            &body.context,
            contextdb_service::Capability::ReadMemory,
        )?,
    }
    serde_json::from_slice(&body.bytes).map_err(full_json_error)
}

impl<S, T> FromRequest<S> for LegacyAuthenticatedJson<T>
where
    S: Send + Sync,
    HttpState: FromRef<S>,
    T: LegacyHttpRequest,
{
    type Rejection = HttpError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let http_state = HttpState::from_ref(state);
        validate_json_content_type(request.headers())?;
        let (gateway_id, attestation) = exact_request_headers(request.headers())?;
        let bytes = read_bounded_body(request, state).await?;
        http_state.gateway_authenticator.verify_exact_request(
            Some(gateway_id.to_str().map_err(|_| invalid_gateway_headers())?),
            Some(
                attestation
                    .to_str()
                    .map_err(|_| invalid_gateway_headers())?,
            ),
            GatewayTransport::Http,
            T::OPERATION.canonical_id(),
            &bytes,
        )?;

        let value = serde_json::from_slice(&bytes).map_err(full_json_error)?;
        Ok(Self(value))
    }
}

fn exact_request_headers(
    headers: &axum::http::HeaderMap,
) -> Result<(axum::http::HeaderValue, axum::http::HeaderValue), HttpError> {
    let gateway_id = headers
        .get(GATEWAY_ID_HEADER)
        .ok_or_else(invalid_gateway_headers)?;
    let attestation = headers
        .get(GATEWAY_ATTESTATION_HEADER)
        .ok_or_else(invalid_gateway_headers)?;
    if gateway_id.as_bytes().len() > MAX_GATEWAY_ID_BYTES
        || attestation.as_bytes().len() > MAX_GATEWAY_ATTESTATION_BYTES
        || gateway_id.to_str().is_err()
        || attestation.to_str().is_err()
    {
        return Err(invalid_gateway_headers());
    }
    Ok((gateway_id.clone(), attestation.clone()))
}

fn invalid_gateway_headers() -> HttpError {
    HttpError(ServiceError::new(
        ErrorCode::Unauthorized,
        "trusted gateway exact-request attestation is missing or malformed",
        false,
    ))
}

async fn read_bounded_body<S>(request: Request, state: &S) -> Result<Bytes, HttpError>
where
    S: Send + Sync,
{
    Bytes::from_request(request, state)
        .await
        .map_err(|rejection| {
            let response = rejection.into_response();
            if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
                HttpError(ServiceError::new(
                    ErrorCode::ResourceExhausted,
                    "request body exceeds the 16 MiB wire limit",
                    false,
                ))
            } else {
                HttpError(ServiceError::new(
                    ErrorCode::InvalidArgument,
                    "request body could not be read",
                    false,
                ))
            }
        })
}

async fn ingest_frame(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::IngestAck>, HttpError> {
    let request: IngestFrame =
        decode_authenticated(body, &[contextdb_service::Capability::StreamIngest])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.ingest_frame(request),
        )
        .await?,
    ))
}

async fn correct(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MutationResponse>, HttpError> {
    let request: CorrectRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Correct])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.correct(request),
        )
        .await?,
    ))
}

async fn forget(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MutationResponse>, HttpError> {
    let request = decode_forget(body)?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.forget(request),
        )
        .await?,
    ))
}

async fn subscribe(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::SubscriptionPage>, HttpError> {
    let request: SubscribeRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Subscribe])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.subscribe(request),
        )
        .await?,
    ))
}

async fn get_node(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MemoryRecord>, HttpError> {
    let request: GetMemoryRequest =
        decode_authenticated(body, &[contextdb_service::Capability::ReadMemory])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.get_node(request),
        )
        .await?,
    ))
}

async fn traverse(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::TraverseResponse>, HttpError> {
    let request: TraverseRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Traverse])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.traverse(request),
        )
        .await?,
    ))
}

async fn get_timeline(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::TimelineResponse>, HttpError> {
    let request = decode_timeline(body)?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.get_timeline(request),
        )
        .await?,
    ))
}

async fn get_evidence(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MemoryRecord>, HttpError> {
    let request: GetMemoryRequest = decode_authenticated(
        body,
        &[
            contextdb_service::Capability::ReadEvidence,
            contextdb_service::Capability::RawEvidence,
        ],
    )?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.get_evidence(request),
        )
        .await?,
    ))
}

async fn get_conflict(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MemoryRecord>, HttpError> {
    let request: GetMemoryRequest =
        decode_authenticated(body, &[contextdb_service::Capability::ReadConflict])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Interactive,
            move || state.service.get_conflict(request),
        )
        .await?,
    ))
}

macro_rules! high_level_write_handler {
    ($name:ident, $method:ident, [$($capability:expr),+ $(,)?]) => {
        async fn $name(
            State(state): State<HttpState>,
            body: AuthenticatedBody,
        ) -> Result<Json<contextdb_service::HighLevelMutationResponse>, HttpError> {
            let request: HighLevelWriteRequest = decode_authenticated(body, &[$($capability),+])?;
            Ok(Json(run(
                Arc::clone(&state.execution_admission),
                ExecutionClass::Interactive,
                move || state.service.$method(request),
            ).await?))
        }
    };
}

macro_rules! high_level_query_handler {
    ($name:ident, $method:ident, [$($capability:expr),+ $(,)?]) => {
        async fn $name(
            State(state): State<HttpState>,
            body: AuthenticatedBody,
        ) -> Result<Json<contextdb_service::RecallResponse>, HttpError> {
            let request: HighLevelQueryRequest = decode_authenticated(body, &[$($capability),+])?;
            Ok(Json(run(
                Arc::clone(&state.execution_admission),
                ExecutionClass::Interactive,
                move || state.service.$method(request),
            ).await?))
        }
    };
}

macro_rules! high_level_control_handler {
    ($name:ident, $method:ident, [$($capability:expr),+ $(,)?]) => {
        async fn $name(
            State(state): State<HttpState>,
            body: AuthenticatedBody,
        ) -> Result<Json<contextdb_service::MutationResponse>, HttpError> {
            let request: HighLevelControlRequest = decode_authenticated(body, &[$($capability),+])?;
            Ok(Json(run(
                Arc::clone(&state.execution_admission),
                ExecutionClass::Interactive,
                move || state.service.$method(request),
            ).await?))
        }
    };
}

high_level_write_handler!(
    begin_session,
    begin_session,
    [contextdb_service::Capability::Observe]
);
high_level_query_handler!(
    before_turn,
    before_turn,
    [contextdb_service::Capability::Recall]
);
high_level_write_handler!(
    after_turn,
    after_turn,
    [contextdb_service::Capability::Observe]
);
high_level_query_handler!(
    resolve_referent,
    resolve_referent,
    [contextdb_service::Capability::Recall]
);
high_level_query_handler!(
    recall_shared_history,
    recall_shared_history,
    [contextdb_service::Capability::Recall]
);
high_level_write_handler!(
    end_session,
    end_session,
    [contextdb_service::Capability::Observe]
);
high_level_write_handler!(
    bootstrap_subject,
    bootstrap_subject,
    [contextdb_service::Capability::Observe]
);
high_level_write_handler!(remember, remember, [contextdb_service::Capability::Observe]);
high_level_control_handler!(pin, pin, [contextdb_service::Capability::Correct]);
high_level_control_handler!(suppress, suppress, [contextdb_service::Capability::Correct]);
high_level_control_handler!(
    change_audience,
    change_audience,
    [contextdb_service::Capability::Correct]
);
high_level_control_handler!(
    change_retention,
    change_retention,
    [contextdb_service::Capability::Correct]
);
high_level_query_handler!(
    explain_memory,
    explain_memory,
    [contextdb_service::Capability::Recall]
);
high_level_query_handler!(
    list_subject_memories,
    list_subject_memories,
    [contextdb_service::Capability::Recall]
);
high_level_write_handler!(
    create_memory_subject,
    create_memory_subject,
    [contextdb_service::Capability::Observe]
);
high_level_write_handler!(
    create_relationship_space,
    create_relationship_space,
    [contextdb_service::Capability::Observe]
);
high_level_query_handler!(
    get_continuity_profile,
    get_continuity_profile,
    [contextdb_service::Capability::Recall]
);
high_level_control_handler!(
    update_configured_role,
    update_configured_role,
    [contextdb_service::Capability::Runtime]
);
high_level_control_handler!(
    migrate_agent_runtime,
    migrate_agent_runtime,
    [contextdb_service::Capability::Runtime]
);
high_level_control_handler!(
    publish_to_shared_memory,
    publish_to_shared_memory,
    [contextdb_service::Capability::Correct]
);
high_level_control_handler!(
    revoke_shared_memory,
    revoke_shared_memory,
    [contextdb_service::Capability::Correct]
);
high_level_write_handler!(
    ingest_artifact,
    ingest_artifact,
    [contextdb_service::Capability::Observe]
);
high_level_write_handler!(
    attach_artifact_to_episode,
    attach_artifact_to_episode,
    [contextdb_service::Capability::Observe]
);
high_level_write_handler!(
    add_derived_representation,
    add_derived_representation,
    [contextdb_service::Capability::Observe]
);
high_level_write_handler!(
    add_evidence_selector,
    add_evidence_selector,
    [contextdb_service::Capability::Observe]
);
high_level_query_handler!(
    get_artifact_metadata,
    get_artifact_metadata,
    [contextdb_service::Capability::Recall]
);
high_level_control_handler!(
    delete_artifact_lineage,
    delete_artifact_lineage,
    [
        contextdb_service::Capability::Forget,
        contextdb_service::Capability::HardDelete
    ]
);

async fn export_subject(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::ExportResponse>, HttpError> {
    let request: HighLevelTransferRequest =
        decode_authenticated(body, &[contextdb_service::Capability::ReadMemory])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::BulkTransfer,
            move || state.service.export_subject(request),
        )
        .await?,
    ))
}

async fn import_subject(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::ImportResponse>, HttpError> {
    let request: HighLevelTransferRequest = decode_authenticated(
        body,
        &[
            contextdb_service::Capability::Observe,
            contextdb_service::Capability::Admin,
        ],
    )?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::BulkTransfer,
            move || state.service.import_subject(request),
        )
        .await?,
    ))
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

async fn runtime_call(
    state: HttpState,
    request: RuntimeRequest,
    call: RuntimeCall,
) -> Result<Json<contextdb_service::RuntimeResponse>, HttpError> {
    let service = Arc::clone(&state.service);
    let response = run(
        Arc::clone(&state.execution_admission),
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
    Ok(Json(response))
}

async fn bootstrap(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::RuntimeResponse>, HttpError> {
    let request: RuntimeRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Runtime])?;
    runtime_call(state, request, RuntimeCall::Bootstrap).await
}

async fn preflight(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::RuntimeResponse>, HttpError> {
    let request: RuntimeRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Runtime])?;
    runtime_call(state, request, RuntimeCall::Preflight).await
}

async fn postflight(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::RuntimeResponse>, HttpError> {
    let request: RuntimeRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Runtime])?;
    runtime_call(state, request, RuntimeCall::Postflight).await
}

async fn checkpoint(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::RuntimeResponse>, HttpError> {
    let request: RuntimeRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Runtime])?;
    runtime_call(state, request, RuntimeCall::Checkpoint).await
}

async fn resume(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::RuntimeResponse>, HttpError> {
    let request: RuntimeRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Runtime])?;
    runtime_call(state, request, RuntimeCall::Resume).await
}

async fn handoff(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::RuntimeResponse>, HttpError> {
    let request: RuntimeRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Runtime])?;
    runtime_call(state, request, RuntimeCall::Handoff).await
}

#[derive(Clone, Copy)]
enum MaintenanceCall {
    Consolidate,
    Reflect,
    Reindex,
    Compact,
}

async fn maintenance_call(
    state: HttpState,
    request: MaintenanceRequest,
    call: MaintenanceCall,
) -> Result<Json<contextdb_service::MaintenanceResponse>, HttpError> {
    let service = Arc::clone(&state.service);
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::Maintenance,
        move || match call {
            MaintenanceCall::Consolidate => service.consolidate(request),
            MaintenanceCall::Reflect => service.reflect(request),
            MaintenanceCall::Reindex => service.reindex(request),
            MaintenanceCall::Compact => service.compact(request),
        },
    )
    .await?;
    Ok(Json(response))
}

async fn consolidate(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MaintenanceResponse>, HttpError> {
    let request: MaintenanceRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Maintenance])?;
    maintenance_call(state, request, MaintenanceCall::Consolidate).await
}

async fn reflect(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MaintenanceResponse>, HttpError> {
    let request: MaintenanceRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Maintenance])?;
    maintenance_call(state, request, MaintenanceCall::Reflect).await
}

async fn reindex(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MaintenanceResponse>, HttpError> {
    let request: MaintenanceRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Maintenance])?;
    maintenance_call(state, request, MaintenanceCall::Reindex).await
}

async fn compact(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::MaintenanceResponse>, HttpError> {
    let request: MaintenanceRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Maintenance])?;
    maintenance_call(state, request, MaintenanceCall::Compact).await
}

async fn get_status(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::StatusResponse>, HttpError> {
    let request: GetStatusRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Admin])?;
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::Interactive,
        move || state.service.get_status(request),
    )
    .await?;
    Ok(Json(response))
}

async fn create_backup(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::BackupResponse>, HttpError> {
    let request: CreateBackupRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Admin])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::BulkTransfer,
            move || state.service.create_backup(request),
        )
        .await?,
    ))
}

async fn restore_backup(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::RestoreBackupResponse>, HttpError> {
    let request: RestoreBackupRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Admin])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::BulkTransfer,
            move || state.service.restore_backup(request),
        )
        .await?,
    ))
}

async fn migrate_format(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::StatusResponse>, HttpError> {
    let request: MigrateFormatRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Admin])?;
    Ok(Json(
        run(
            Arc::clone(&state.execution_admission),
            ExecutionClass::Maintenance,
            move || state.service.migrate_format(request),
        )
        .await?,
    ))
}

async fn observe(
    State(state): State<HttpState>,
    LegacyAuthenticatedJson(request): LegacyAuthenticatedJson<ObserveRequest>,
) -> Result<Json<contextdb_service::ObserveResponse>, HttpError> {
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::Interactive,
        move || state.service.observe(request),
    )
    .await?;
    Ok(Json(response))
}

async fn recall(
    State(state): State<HttpState>,
    LegacyAuthenticatedJson(request): LegacyAuthenticatedJson<RecallRequest>,
) -> Result<Json<contextdb_service::RecallResponse>, HttpError> {
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::Interactive,
        move || state.service.recall(request),
    )
    .await?;
    Ok(Json(response))
}

async fn compile_context(
    State(state): State<HttpState>,
    body: AuthenticatedBody,
) -> Result<Json<contextdb_service::CompileContextResponse>, HttpError> {
    let request: CompileContextRequest =
        decode_authenticated(body, &[contextdb_service::Capability::Recall])?;
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::Interactive,
        move || state.service.compile_context(request),
    )
    .await?;
    Ok(Json(response))
}

async fn explain(
    State(state): State<HttpState>,
    LegacyAuthenticatedJson(request): LegacyAuthenticatedJson<ExplainRecallRequest>,
) -> Result<Json<contextdb_service::RecallTrace>, HttpError> {
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::Interactive,
        move || state.service.explain_recall(request),
    )
    .await?;
    Ok(Json(response))
}

async fn export(
    State(state): State<HttpState>,
    LegacyAuthenticatedJson(request): LegacyAuthenticatedJson<ExportRequest>,
) -> Result<Json<contextdb_service::ExportResponse>, HttpError> {
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::BulkTransfer,
        move || state.service.export_archive(request),
    )
    .await?;
    Ok(Json(response))
}

async fn import(
    State(state): State<HttpState>,
    LegacyAuthenticatedJson(request): LegacyAuthenticatedJson<ImportRequest>,
) -> Result<Json<contextdb_service::ImportResponse>, HttpError> {
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::BulkTransfer,
        move || state.service.import_archive(request),
    )
    .await?;
    Ok(Json(response))
}

async fn verify(
    State(state): State<HttpState>,
    LegacyAuthenticatedJson(request): LegacyAuthenticatedJson<VerifyRequest>,
) -> Result<Json<contextdb_service::VerifyResponse>, HttpError> {
    let response = run(
        Arc::clone(&state.execution_admission),
        ExecutionClass::Maintenance,
        move || state.service.verify(request),
    )
    .await?;
    Ok(Json(response))
}

fn validate_json_content_type(headers: &axum::http::HeaderMap) -> Result<(), HttpError> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(HttpError(ServiceError::new(
            ErrorCode::FormatIncompatible,
            "request must use the canonical application/json schema",
            false,
        )));
    }
    Ok(())
}

fn authentication_envelope_error(error: serde_json::Error) -> HttpError {
    let (code, message) = if error.is_syntax() || error.is_eof() {
        (
            ErrorCode::InvalidArgument,
            "request authentication envelope is not canonical JSON",
        )
    } else {
        (
            ErrorCode::FormatIncompatible,
            "request authentication context is missing or incompatible",
        )
    };
    HttpError(ServiceError::new(code, message, false))
}

fn full_json_error(error: serde_json::Error) -> HttpError {
    let (code, message) = if error.is_syntax() || error.is_eof() {
        (
            ErrorCode::InvalidArgument,
            "request body is not canonical JSON",
        )
    } else {
        (
            ErrorCode::FormatIncompatible,
            "request does not match the canonical application/json schema",
        )
    };
    HttpError(ServiceError::new(code, message, false))
}

async fn run<T, F>(
    admission: SharedExecutionAdmission,
    class: ExecutionClass,
    operation: F,
) -> Result<T, HttpError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ServiceError> + Send + 'static,
{
    admission.execute(class, operation).await.map_err(HttpError)
}

/// Serves the HTTP adapter on an already-bound listener.
pub async fn serve_http(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
) -> std::io::Result<()> {
    axum::serve(listener, http_router(service)).await
}

/// Serves the HTTP adapter with an explicitly configured trusted gateway.
pub async fn serve_http_with_gateway_authenticator(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        http_router_with_gateway_authenticator(service, gateway_authenticator),
    )
    .await
}

/// Serves the HTTP adapter with graceful shutdown.
pub async fn serve_http_with_shutdown<F>(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
    signal: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, http_router(service))
        .with_graceful_shutdown(signal)
        .await
}

/// Serves the HTTP adapter with both trusted gateway verification and graceful
/// shutdown.
pub async fn serve_http_with_shutdown_and_gateway<F>(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    signal: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        http_router_with_gateway_authenticator(service, gateway_authenticator),
    )
    .with_graceful_shutdown(signal)
    .await
}

/// Serves the HTTP adapter with explicit gateway and health authorities plus
/// graceful shutdown.
pub async fn serve_http_with_shutdown_gateway_and_health<F>(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    health_provider: SharedHealthProvider,
    signal: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_http_with_shutdown_gateway_health_and_admission(
        listener,
        service,
        gateway_authenticator,
        health_provider,
        Arc::new(ExecutionAdmission::default()),
        signal,
    )
    .await
}

/// Serves the HTTP adapter with explicit gateway, health, shared admission,
/// and graceful-shutdown authorities.
pub async fn serve_http_with_shutdown_gateway_health_and_admission<F>(
    listener: tokio::net::TcpListener,
    service: Arc<dyn CognitiveMemoryService>,
    gateway_authenticator: SharedGatewayAuthenticator,
    health_provider: SharedHealthProvider,
    execution_admission: SharedExecutionAdmission,
    signal: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        http_router_with_gateway_authenticator_health_and_admission(
            service,
            gateway_authenticator,
            health_provider,
            execution_admission,
        ),
    )
    .with_graceful_shutdown(signal)
    .await
}
