use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use contextdb_proto::v1 as wire;
use contextdb_proto::v1::agent_runtime_service_server::AgentRuntimeService;
use contextdb_proto::v1::archive_service_server::ArchiveService;
use contextdb_proto::v1::maintenance_service_client::MaintenanceServiceClient;
use contextdb_proto::v1::maintenance_service_server::MaintenanceService;
use contextdb_proto::v1::memory_control_service_server::MemoryControlService;
use contextdb_proto::v1::memory_service_server::MemoryService;
use contextdb_proto::v1::observation_service_client::ObservationServiceClient;
use contextdb_proto::v1::observation_service_server::ObservationService;
use contextdb_proto::v1::observe_ack::Outcome;
use contextdb_proto::v1::recall_service_server::RecallService;
use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, AuthenticationEvidence, Capability,
    CognitiveMemoryService, CompileContextRequest, Consent, ExplainRecallRequest, ExportRequest,
    GetStatusRequest, HighLevelControlRequest, HighLevelWriteRequest, HostArchiveAuthority,
    ImportRequest, ObserveRequest, RecallRequest, ReferenceService, RequestContext, Sensitivity,
    VerifyRequest,
};
use prost::Message;
use tower::ServiceExt;

use crate::{
    Blake3GatewayAuthenticator, ExecutionAdmission, ExecutionAdmissionConfig, ExecutionClass,
    FixedHealthProvider, GATEWAY_ATTESTATION_HEADER, GATEWAY_ID_HEADER, GatewayAuthenticator,
    GatewayTransport, GrpcAdapter, HealthChecks, HealthProfile, HealthProvider, HealthReason,
    HealthState, HealthSummary, LegacyNetworkOperation, MAX_WIRE_BYTES,
    compile_context_request_to_proto, http_router, http_router_with_gateway_authenticator,
    http_router_with_gateway_authenticator_health_and_admission, http_router_with_health_provider,
    observe_request_to_proto, observe_response_from_proto, recall_request_to_proto,
    recall_trace_to_proto, request_context_to_proto, serve_grpc_listener_with_shutdown_and_gateway,
    serve_grpc_listener_with_shutdown_gateway_and_admission,
};

const GATEWAY_KEY: [u8; 32] = [0x61; 32];
static NEXT_GATEWAY_NONCE: AtomicUsize = AtomicUsize::new(1);

#[derive(Default)]
struct CountingGatewayAuthenticator {
    modern_calls: AtomicUsize,
}

impl GatewayAuthenticator for CountingGatewayAuthenticator {
    fn verify_exact_request(
        &self,
        _gateway_id: Option<&str>,
        _attestation: Option<&str>,
        _transport: GatewayTransport,
        _operation: &str,
        _canonical_body: &[u8],
    ) -> contextdb_service::ServiceResult<()> {
        self.modern_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn unique_gateway_nonce() -> [u8; 16] {
    let mut nonce = [0_u8; 16];
    nonce[..8].copy_from_slice(
        &(NEXT_GATEWAY_NONCE.fetch_add(1, Ordering::Relaxed) as u64).to_le_bytes(),
    );
    nonce
}

fn exact_http_attestation(gateway: &Blake3GatewayAuthenticator, path: &str, body: &[u8]) -> String {
    gateway
        .attest_exact_request(
            GatewayTransport::Http,
            &format!("POST:{path}"),
            body,
            unique_gateway_nonce(),
        )
        .expect("HTTP exact-request attestation")
}

fn attest_observe_stream_frame(
    gateway: &Blake3GatewayAuthenticator,
    mut frame: wire::ObserveRequest,
) -> wire::ObserveRequest {
    frame.gateway_attestation = None;
    let token = gateway
        .attest_exact_request(
            GatewayTransport::Grpc,
            LegacyNetworkOperation::GrpcObserveStream.canonical_id(),
            &frame.encode_to_vec(),
            unique_gateway_nonce(),
        )
        .expect("stream-frame attestation");
    frame.gateway_attestation = Some(wire::GatewayFrameAttestation {
        gateway_id: gateway.gateway_id().to_owned(),
        token,
    });
    frame
}

fn context(request_id: &str) -> RequestContext {
    RequestContext {
        request_id: request_id.into(),
        workspace_id: "workspace:test".into(),
        subject_id: "subject:alice".into(),
        audiences: BTreeSet::from(["subject:alice".into()]),
        scopes: BTreeSet::from(["project:test".into()]),
        purpose: "assist".into(),
        clearance: Sensitivity::Private,
    }
}

fn admin_context(request_id: &str) -> RequestContext {
    RequestContext {
        request_id: request_id.into(),
        workspace_id: "workspace:test".into(),
        subject_id: "subject:admin".into(),
        audiences: BTreeSet::from(["subject:admin".into()]),
        scopes: BTreeSet::from(["project:test".into()]),
        purpose: "contextdb:admin".into(),
        clearance: Sensitivity::Restricted,
    }
}

fn observe_request(id: &str, key: &str) -> ObserveRequest {
    ObserveRequest {
        context: context("request:observe"),
        idempotency_key: key.into(),
        observation_id: id.into(),
        metadata: BTreeMap::from([("kind".into(), serde_json::json!("chat"))]),
        content: serde_json::json!({"text": "The bar in Japan was quiet."}),
        access: AccessPolicy {
            workspace_id: "workspace:test".into(),
            scopes: BTreeSet::from(["project:test".into()]),
            owners: BTreeSet::from(["subject:alice".into()]),
            audience: BTreeSet::from(["subject:alice".into()]),
            audience_purpose_grants: BTreeMap::new(),
            purposes: BTreeSet::from(["assist".into()]),
            sensitivity: Sensitivity::Private,
            consent: Consent::Granted,
            retrievable: true,
        },
    }
}

fn authenticated(request_id: &str, grants: &[Capability]) -> AuthenticatedRequestContext {
    AuthenticatedRequestContext {
        request: context(request_id),
        actor_id: "subject:alice".to_owned(),
        agent_id: "agent:test".to_owned(),
        session_id: Some("session:test".to_owned()),
        capability_grants: grants.iter().copied().collect(),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "channel:test".to_owned(),
            peer_identity: "subject:alice".to_owned(),
            binding_digest: "55".repeat(32),
        },
    }
}

fn context_pack_request(request_id: &str) -> CompileContextRequest {
    let mut context = authenticated(request_id, &[Capability::Recall]);
    context.request.purpose = "conversation".to_owned();
    serde_json::from_value(serde_json::json!({
        "context": context,
        "plan": {
            "pack_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "query": "bounded empty reference query",
            "mode": "required",
            "intent": "current_truth",
            "purpose": "conversation",
            "at_commit": null,
            "now_micros": 0,
            "required_facets": [],
            "recall_limits": {
                "max_nodes_examined": 128,
                "max_seed_candidates": 128,
                "max_graph_hops": 2,
                "max_frontier_per_hop": 128,
                "max_evidence_units": 32,
                "max_context_tokens": 2048,
                "deadline_micros": 5000000
            },
            "context_budgets": {
                "hard_tokens": 2048,
                "soft_tokens": 1024,
                "max_blocks": 32,
                "max_evidence_blocks": 32,
                "max_raw_evidence_tokens": 1024,
                "max_history_tokens": 1024,
                "max_conflict_tokens": 1024,
                "max_serialized_bytes": 262144,
                "max_selection_evaluations": 128
            },
            "model_profile": {
                "id": "model:server-local",
                "family": "reference",
                "tokenizer_id": "contextdb.reference_unicode_tokens.v1",
                "renderer": "compact",
                "max_context_tokens": 4096,
                "reserved_output_tokens": 1024,
                "preferred_structured_format": "compact_text",
                "supports_tool_results": false,
                "supports_native_citations": false,
                "supports_prompt_caching": false,
                "position_profile": "small_model_explicit",
                "instruction_hierarchy": "single_prompt_delimited",
                "max_schema_complexity": 32,
                "external_processing": false
            },
            "explicit_memory_request": false,
            "require_primary_evidence": false,
            "include_evidence_quotes": false,
            "permit_derived_only": true,
            "max_projection_lag_commits": 0,
            "allow_stale": false,
            "query_vector": null,
            "continuation": null
        }
    }))
    .expect("typed ContextPack request")
}

fn high_level_write_request(request_id: &str) -> HighLevelWriteRequest {
    HighLevelWriteRequest {
        context: authenticated(request_id, &[Capability::Observe]),
        idempotency_key: format!("idempotency:{request_id}"),
        target_subject_id: "subject:alice".to_owned(),
        session_id: Some("session:test".to_owned()),
        logical_id: format!("logical:{request_id}"),
        access: observe_request("observation:policy", "idempotency:policy").access,
        payload: serde_json::json!({"text": "high-level content"}),
        references: BTreeSet::from(["episode:test".to_owned()]),
    }
}

fn legacy_http_request<T: serde::Serialize>(
    path: &str,
    operation: LegacyNetworkOperation,
    _context: &RequestContext,
    value: &T,
    gateway: &Blake3GatewayAuthenticator,
) -> Request<Body> {
    let body = serde_json::to_vec(value).expect("json");
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(
            GATEWAY_ATTESTATION_HEADER,
            gateway
                .attest_exact_request(
                    GatewayTransport::Http,
                    operation.canonical_id(),
                    &body,
                    unique_gateway_nonce(),
                )
                .expect("legacy attestation"),
        )
        .body(Body::from(body))
        .expect("request")
}

fn legacy_grpc_request<T: Message>(
    value: T,
    operation: LegacyNetworkOperation,
    _context: &RequestContext,
    gateway: &Blake3GatewayAuthenticator,
) -> tonic::Request<T> {
    let token = gateway
        .attest_exact_request(
            GatewayTransport::Grpc,
            operation.canonical_id(),
            &value.encode_to_vec(),
            unique_gateway_nonce(),
        )
        .expect("legacy attestation");
    let mut request = tonic::Request::new(value);
    let (service, method) = operation
        .canonical_id()
        .split_once('/')
        .expect("canonical gRPC operation");
    request
        .extensions_mut()
        .insert(tonic::GrpcMethod::new(service, method));
    request.metadata_mut().insert(
        GATEWAY_ID_HEADER,
        gateway.gateway_id().parse().expect("gateway metadata"),
    );
    request.metadata_mut().insert(
        GATEWAY_ATTESTATION_HEADER,
        token.parse().expect("attestation metadata"),
    );
    request
}

fn authenticated_grpc_request<T: Message>(
    value: T,
    _context: &AuthenticatedRequestContext,
    operation: &'static str,
    gateway: &Blake3GatewayAuthenticator,
) -> tonic::Request<T> {
    let token = gateway
        .attest_exact_request(
            GatewayTransport::Grpc,
            operation,
            &value.encode_to_vec(),
            unique_gateway_nonce(),
        )
        .expect("attestation");
    let mut request = tonic::Request::new(value);
    let (service, method) = operation.split_once('/').expect("canonical gRPC operation");
    request
        .extensions_mut()
        .insert(tonic::GrpcMethod::new(service, method));
    request.metadata_mut().insert(
        GATEWAY_ID_HEADER,
        gateway.gateway_id().parse().expect("gateway metadata"),
    );
    request.metadata_mut().insert(
        GATEWAY_ATTESTATION_HEADER,
        token.parse().expect("attestation metadata"),
    );
    request
}

fn counted_grpc_request<T>(value: T, operation: &'static str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(value);
    let (service, method) = operation.split_once('/').expect("canonical gRPC operation");
    request
        .extensions_mut()
        .insert(tonic::GrpcMethod::new(service, method));
    request.metadata_mut().insert(
        GATEWAY_ID_HEADER,
        "gateway:test".parse().expect("gateway metadata"),
    );
    request.metadata_mut().insert(
        GATEWAY_ATTESTATION_HEADER,
        "counted-test-token".parse().expect("attestation metadata"),
    );
    request
}

fn assert_grpc_permission_denied<T>(
    result: Result<tonic::Response<T>, tonic::Status>,
    label: &str,
) {
    match result {
        Ok(_) => panic!("{label} unexpectedly bypassed gateway authentication"),
        Err(status) => assert_eq!(status.code(), tonic::Code::PermissionDenied, "{label}"),
    }
}

#[derive(Clone, Copy)]
enum MaintenanceTestCall {
    Consolidate,
    Reflect,
    Reindex,
    Compact,
}

impl MaintenanceTestCall {
    const ALL: [Self; 4] = [
        Self::Consolidate,
        Self::Reflect,
        Self::Reindex,
        Self::Compact,
    ];

    const fn http_path(self) -> &'static str {
        match self {
            Self::Consolidate => "/v1/maintenance/consolidate",
            Self::Reflect => "/v1/maintenance/reflect",
            Self::Reindex => "/v1/maintenance/reindex",
            Self::Compact => "/v1/maintenance/compact",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Consolidate => "consolidate",
            Self::Reflect => "reflect",
            Self::Reindex => "reindex",
            Self::Compact => "compact",
        }
    }

    const fn grpc_operation(self) -> &'static str {
        match self {
            Self::Consolidate => "contextdb.v1.MaintenanceService/Consolidate",
            Self::Reflect => "contextdb.v1.MaintenanceService/Reflect",
            Self::Reindex => "contextdb.v1.MaintenanceService/Reindex",
            Self::Compact => "contextdb.v1.MaintenanceService/Compact",
        }
    }
}

async fn call_grpc_maintenance(
    adapter: &GrpcAdapter,
    call: MaintenanceTestCall,
    request: tonic::Request<wire::MaintenanceRequest>,
) -> Result<tonic::Response<wire::MaintenanceResponse>, tonic::Status> {
    match call {
        MaintenanceTestCall::Consolidate => MaintenanceService::consolidate(adapter, request).await,
        MaintenanceTestCall::Reflect => MaintenanceService::reflect(adapter, request).await,
        MaintenanceTestCall::Reindex => MaintenanceService::reindex(adapter, request).await,
        MaintenanceTestCall::Compact => MaintenanceService::compact(adapter, request).await,
    }
}

async fn http_error_response(
    router: axum::Router,
    request: Request<Body>,
) -> (StatusCode, crate::HttpErrorBody) {
    let response = router.oneshot(request).await.expect("HTTP response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("HTTP error body");
    let error = serde_json::from_slice(&bytes).expect("canonical HTTP error envelope");
    (status, error)
}

#[tokio::test]
async fn grpc_unary_matches_embedded_contract() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("grpc-test", [7; 32]).expect("valid key"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let adapter = GrpcAdapter::with_gateway_authenticator(Arc::clone(&service), 4, gateway.clone());
    let request = observe_request("observation:grpc", "idempotency:grpc");
    let expected = service.observe(request.clone()).expect("embedded observe");
    let context = request.context.clone();
    let wire = adapter
        .observe(legacy_grpc_request(
            observe_request_to_proto(request).expect("wire request"),
            LegacyNetworkOperation::GrpcObserve,
            &context,
            &gateway,
        ))
        .await
        .expect("grpc observe")
        .into_inner();
    let actual = observe_response_from_proto(wire).expect("wire response");

    assert_eq!(actual.commit_seq, expected.commit_seq);
    assert_eq!(actual.request_digest, expected.request_digest);
    assert!(actual.replayed);
}

#[tokio::test]
async fn legacy_grpc_authentication_precedes_sensitive_operation_conversion() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("grpc-legacy-two-phase", [24; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let adapter = GrpcAdapter::with_gateway_authenticator(service, 4, gateway.clone());
    let request = observe_request("observation:grpc-two-phase", "idempotency:grpc-two-phase");
    let context = request.context.clone();
    let mut wire = observe_request_to_proto(request).expect("wire request");
    wire.content_json = b"sensitive malformed JSON".to_vec();

    let status = ObservationService::observe(&adapter, tonic::Request::new(wire.clone()))
        .await
        .expect_err("missing authentication must win");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    let status = ObservationService::observe(
        &adapter,
        legacy_grpc_request(
            wire,
            LegacyNetworkOperation::GrpcObserve,
            &context,
            &gateway,
        ),
    )
    .await
    .expect_err("authenticated malformed operation must reach conversion");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn every_legacy_grpc_unary_and_recall_stream_requires_exact_attestation() {
    let reference = Arc::new(ReferenceService::new("grpc-legacy-auth", [23; 32]).expect("service"));
    let service: Arc<dyn CognitiveMemoryService> = reference.clone();
    let observation = observe_request("observation:grpc-auth", "idempotency:grpc-auth");
    service
        .observe(observation.clone())
        .expect("seed observation");
    let recall = RecallRequest {
        context: context("request:grpc-auth:recall"),
        query: "Japan quiet bar".into(),
        page_size: 20,
        at_commit: None,
        continuation: None,
    };
    let trace = service.recall(recall.clone()).expect("seed recall").trace;
    let admin = admin_context("request:grpc-auth:admin");
    let archive = reference
        .export_host_archive(&HostArchiveAuthority::new([23; 32]).expect("host authority"))
        .expect("archive fixture");
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let adapter = GrpcAdapter::with_gateway_authenticator(Arc::clone(&service), 4, gateway.clone());

    let observe_wire = observe_request_to_proto(observation.clone()).expect("wire observe");
    assert_grpc_permission_denied(
        ObservationService::observe(&adapter, tonic::Request::new(observe_wire.clone())).await,
        "ObservationService/Observe",
    );
    ObservationService::observe(
        &adapter,
        legacy_grpc_request(
            observe_wire,
            LegacyNetworkOperation::GrpcObserve,
            &observation.context,
            &gateway,
        ),
    )
    .await
    .expect("attested observe");

    let recall_wire = recall_request_to_proto(recall.clone());
    assert_grpc_permission_denied(
        RecallService::recall(&adapter, tonic::Request::new(recall_wire.clone())).await,
        "RecallService/Recall",
    );
    RecallService::recall(
        &adapter,
        legacy_grpc_request(
            recall_wire.clone(),
            LegacyNetworkOperation::GrpcRecall,
            &recall.context,
            &gateway,
        ),
    )
    .await
    .expect("attested recall");

    assert_grpc_permission_denied(
        RecallService::continue_recall(&adapter, tonic::Request::new(recall_wire.clone())).await,
        "RecallService/ContinueRecall",
    );
    RecallService::continue_recall(
        &adapter,
        legacy_grpc_request(
            recall_wire.clone(),
            LegacyNetworkOperation::GrpcContinueRecall,
            &recall.context,
            &gateway,
        ),
    )
    .await
    .expect("attested continue recall");

    assert_grpc_permission_denied(
        RecallService::recall_stream(&adapter, tonic::Request::new(recall_wire.clone())).await,
        "RecallService/RecallStream",
    );
    let mut recall_stream = RecallService::recall_stream(
        &adapter,
        legacy_grpc_request(
            recall_wire,
            LegacyNetworkOperation::GrpcRecallStream,
            &recall.context,
            &gateway,
        ),
    )
    .await
    .expect("attested recall stream")
    .into_inner();
    let mut event_count = 0;
    while let Some(event) = tokio_stream::StreamExt::next(&mut recall_stream).await {
        event.expect("recall event");
        event_count += 1;
    }
    assert_eq!(event_count, 3);

    let explain_wire = wire::ExplainRecallRequest {
        context: Some(request_context_to_proto(recall.context.clone())),
        trace: Some(recall_trace_to_proto(trace)),
    };
    assert_grpc_permission_denied(
        RecallService::explain_recall(&adapter, tonic::Request::new(explain_wire.clone())).await,
        "RecallService/ExplainRecall",
    );
    RecallService::explain_recall(
        &adapter,
        legacy_grpc_request(
            explain_wire,
            LegacyNetworkOperation::GrpcExplainRecall,
            &recall.context,
            &gateway,
        ),
    )
    .await
    .expect("attested explain recall");

    let export_wire = wire::ExportRequest {
        context: Some(request_context_to_proto(admin.clone())),
    };
    assert_grpc_permission_denied(
        ArchiveService::export(&adapter, tonic::Request::new(export_wire.clone())).await,
        "ArchiveService/Export",
    );
    let status = ArchiveService::export(
        &adapter,
        legacy_grpc_request(
            export_wire,
            LegacyNetworkOperation::GrpcArchiveExport,
            &admin,
            &gateway,
        ),
    )
    .await
    .expect_err("attested workspace export must remain unavailable");
    assert_eq!(status.code(), tonic::Code::Unimplemented);

    let import_wire = wire::ImportRequest {
        context: Some(request_context_to_proto(admin.clone())),
        format: archive.format,
        archive: archive.bytes,
        digest: archive.digest,
    };
    assert_grpc_permission_denied(
        ArchiveService::import(&adapter, tonic::Request::new(import_wire.clone())).await,
        "ArchiveService/Import",
    );
    let status = ArchiveService::import(
        &adapter,
        legacy_grpc_request(
            import_wire,
            LegacyNetworkOperation::GrpcArchiveImport,
            &admin,
            &gateway,
        ),
    )
    .await
    .expect_err("attested workspace import must remain unavailable");
    assert_eq!(status.code(), tonic::Code::Unimplemented);

    let verify_wire = wire::VerifyRequest {
        context: Some(request_context_to_proto(admin.clone())),
        deep: true,
    };
    assert_grpc_permission_denied(
        MaintenanceService::verify(&adapter, tonic::Request::new(verify_wire.clone())).await,
        "MaintenanceService/Verify",
    );
    MaintenanceService::verify(
        &adapter,
        legacy_grpc_request(
            verify_wire,
            LegacyNetworkOperation::GrpcMaintenanceVerify,
            &admin,
            &gateway,
        ),
    )
    .await
    .expect("attested verify");

    let default_adapter = GrpcAdapter::new(service, 4);
    assert_grpc_permission_denied(
        ObservationService::observe(
            &default_adapter,
            tonic::Request::new(
                observe_request_to_proto(observation).expect("default adapter observe"),
            ),
        )
        .await,
        "default rejecting adapter",
    );
}

#[tokio::test]
async fn context_pack_http_and_grpc_share_the_typed_snapshot_bound_contract() {
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        ReferenceService::new("context-pack-transports", [0x71; 32]).expect("reference service"),
    );
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:context-pack", GATEWAY_KEY)
            .expect("gateway verifier"),
    );
    let request = context_pack_request("request:context-pack-http");
    let body = serde_json::to_vec(&request).expect("ContextPack JSON");
    let http_request = Request::builder()
        .method("POST")
        .uri("/v1/context-pack")
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(
            GATEWAY_ATTESTATION_HEADER,
            exact_http_attestation(&gateway, "/v1/context-pack", &body),
        )
        .body(Body::from(body))
        .expect("HTTP request");
    let response = http_router_with_gateway_authenticator(Arc::clone(&service), gateway.clone())
        .oneshot(http_request)
        .await
        .expect("HTTP response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("HTTP response body");
    let http: contextdb_service::CompileContextResponse =
        serde_json::from_slice(&bytes).expect("typed HTTP response");
    assert_eq!(http.trace.snapshot, http.context_pack.snapshot);
    assert_eq!(
        http.trace.filter_digest,
        http.context_pack.scope_manifest.filter_digest
    );

    let grpc_request = context_pack_request("request:context-pack-grpc");
    let authenticated = grpc_request.context.clone();
    let wire = compile_context_request_to_proto(grpc_request).expect("gRPC request conversion");
    let adapter = GrpcAdapter::with_gateway_authenticator(service, 4, gateway.clone());
    let response = RecallService::compile_context(
        &adapter,
        authenticated_grpc_request(
            wire,
            &authenticated,
            "contextdb.v1.RecallService/CompileContext",
            &gateway,
        ),
    )
    .await
    .expect("gRPC ContextPack response")
    .into_inner();
    let trace = response.trace.as_ref().expect("privacy-safe trace");
    let pack: serde_json::Value =
        serde_json::from_slice(&response.context_pack_json).expect("canonical ContextPack JSON");
    assert_eq!(trace.snapshot_seq, pack["snapshot"]["commit_seq"]);
    assert_eq!(trace.filter_digest, pack["scope_manifest"]["filter_digest"]);
    assert_eq!(
        response.canonical_encoding,
        "contextdb.context_pack.protobuf.v1"
    );
    assert_eq!(response.canonical_digest_algorithm, "blake3-256");
    assert_eq!(
        blake3::hash(&response.canonical_bytes).to_hex().as_str(),
        response.canonical_digest
    );
    let canonical = wire::CanonicalContextPackV1::decode(response.canonical_bytes.as_slice())
        .expect("public canonical ContextPack Protobuf");
    assert_eq!(canonical.schema_version, pack["schema_version"]);
    assert_eq!(canonical.id, pack["id"]);
    assert!(response.rendered.is_some());
}

#[tokio::test]
async fn http_json_matches_embedded_recall_and_structured_errors() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-test", [8; 32]).expect("valid key"));
    service
        .observe(observe_request("observation:http", "idempotency:http"))
        .expect("observe");
    let recall = RecallRequest {
        context: context("request:recall"),
        query: "Japan quiet bar".into(),
        page_size: 20,
        at_commit: None,
        continuation: None,
    };
    let expected = service.recall(recall.clone()).expect("embedded recall");
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let request = legacy_http_request(
        "/v1/recall",
        LegacyNetworkOperation::HttpRecall,
        &recall.context,
        &recall,
        &gateway,
    );
    let response = http_router_with_gateway_authenticator(Arc::clone(&service), gateway.clone())
        .oneshot(request)
        .await
        .expect("http response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let actual: contextdb_service::RecallResponse =
        serde_json::from_slice(&bytes).expect("recall response");
    assert_eq!(actual, expected);

    let malformed_body = br#"{"query":"missing context"}"#.to_vec();
    let malformed = Request::builder()
        .method("POST")
        .uri("/v1/recall")
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(
            GATEWAY_ATTESTATION_HEADER,
            exact_http_attestation(&gateway, "/v1/recall", &malformed_body),
        )
        .body(Body::from(malformed_body))
        .expect("request");
    let response = http_router_with_gateway_authenticator(service, gateway)
        .oneshot(malformed)
        .await
        .expect("http response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("error body");
    let error: crate::HttpErrorBody = serde_json::from_slice(&bytes).expect("error envelope");
    assert_eq!(error.code, contextdb_service::ErrorCode::FormatIncompatible);
    assert!(!error.retryable);
    assert!(error.partial_result_refs.is_empty());
}

#[tokio::test]
async fn every_legacy_http_route_requires_its_exact_gateway_attestation() {
    let reference = Arc::new(ReferenceService::new("http-legacy-auth", [21; 32]).expect("service"));
    let service: Arc<dyn CognitiveMemoryService> = reference.clone();
    let observation = observe_request("observation:http-auth", "idempotency:http-auth");
    service
        .observe(observation.clone())
        .expect("seed observation");
    let recall = RecallRequest {
        context: context("request:http-auth:recall"),
        query: "Japan quiet bar".into(),
        page_size: 20,
        at_commit: None,
        continuation: None,
    };
    let trace = service.recall(recall.clone()).expect("seed recall").trace;
    let explain = ExplainRecallRequest {
        context: recall.context.clone(),
        trace,
    };
    let admin = admin_context("request:http-auth:admin");
    let archive = reference
        .export_host_archive(&HostArchiveAuthority::new([21; 32]).expect("host authority"))
        .expect("export fixture");
    let export = ExportRequest {
        context: admin.clone(),
    };
    let import = ImportRequest {
        context: admin.clone(),
        format: archive.format,
        bytes: archive.bytes,
        digest: archive.digest,
    };
    let verify = VerifyRequest {
        context: admin,
        deep: true,
    };
    let cases = [
        (
            "/v1/observations",
            LegacyNetworkOperation::HttpObserve,
            observation.context.clone(),
            serde_json::to_value(observation).expect("observe JSON"),
            StatusCode::OK,
        ),
        (
            "/v1/recall",
            LegacyNetworkOperation::HttpRecall,
            recall.context.clone(),
            serde_json::to_value(recall).expect("recall JSON"),
            StatusCode::OK,
        ),
        (
            "/v1/recall/explain",
            LegacyNetworkOperation::HttpExplainRecall,
            explain.context.clone(),
            serde_json::to_value(explain).expect("explain JSON"),
            StatusCode::OK,
        ),
        (
            "/v1/archive/export",
            LegacyNetworkOperation::HttpExport,
            export.context.clone(),
            serde_json::to_value(export).expect("export JSON"),
            StatusCode::NOT_IMPLEMENTED,
        ),
        (
            "/v1/archive/import",
            LegacyNetworkOperation::HttpImport,
            import.context.clone(),
            serde_json::to_value(import).expect("import JSON"),
            StatusCode::NOT_IMPLEMENTED,
        ),
        (
            "/v1/verify",
            LegacyNetworkOperation::HttpVerify,
            verify.context.clone(),
            serde_json::to_value(verify).expect("verify JSON"),
            StatusCode::OK,
        ),
    ];
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let router = http_router_with_gateway_authenticator(service, gateway.clone());

    for (path, operation, context, value, expected_status) in cases {
        let missing = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&value).expect("request JSON"),
            ))
            .expect("missing-auth request");
        let response = router.clone().oneshot(missing).await.expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");

        let bound = legacy_http_request(path, operation, &context, &value, &gateway);
        let response = router.clone().oneshot(bound).await.expect("response");
        assert_eq!(response.status(), expected_status, "{path}");
        if expected_status == StatusCode::NOT_IMPLEMENTED {
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("error body");
            let error: crate::HttpErrorBody =
                serde_json::from_slice(&bytes).expect("typed unsupported error");
            assert_eq!(error.code, contextdb_service::ErrorCode::Unsupported);
        }
    }
}

#[tokio::test]
async fn legacy_http_authentication_precedes_full_sensitive_schema_decode() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-legacy-two-phase", [22; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let legacy_context = context("request:legacy-two-phase");
    let body = serde_json::to_vec(&serde_json::json!({
        "context": legacy_context,
        "idempotency_key": "idempotency:legacy-two-phase",
        "observation_id": "observation:legacy-two-phase",
        "metadata": "sensitive incompatible operation payload",
        "content": {"secret": "must not reach full decoder before authentication"},
        "access": {}
    }))
    .expect("JSON");
    let router = http_router_with_gateway_authenticator(service, gateway.clone());
    let missing = Request::builder()
        .method("POST")
        .uri("/v1/observations")
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .expect("request");
    let response = router.clone().oneshot(missing).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let attestation = exact_http_attestation(&gateway, "/v1/observations", &body);
    let bound = Request::builder()
        .method("POST")
        .uri("/v1/observations")
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(GATEWAY_ATTESTATION_HEADER, attestation)
        .body(Body::from(body))
        .expect("request");
    let response = router.oneshot(bound).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn http_rejects_before_materializing_large_auth_context_collections() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-pre-auth-collection", [0x92; 32]).expect("service"));
    let gateway = Arc::new(CountingGatewayAuthenticator::default());
    let audiences: Vec<String> = (0..20_000)
        .map(|index| format!("subject:attacker:{index}"))
        .collect();
    let body = serde_json::to_vec(&serde_json::json!({
        "context": {
            "request_id": "request:large-context",
            "workspace_id": "workspace:test",
            "subject_id": "subject:alice",
            "audiences": audiences,
            "scopes": ["project:test"],
            "purpose": "assist",
            "clearance": "private"
        },
        "query": "must remain opaque",
        "page_size": 1
    }))
    .expect("large request JSON");
    assert!(body.len() < MAX_WIRE_BYTES);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/recall")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("request");
    let response = http_router_with_gateway_authenticator(service, gateway.clone())
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(gateway.modern_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http_extractor_failures_use_the_canonical_error_envelope() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-limits", [8; 32]).expect("valid key"));

    let missing_content_type = Request::builder()
        .method("POST")
        .uri("/v1/recall")
        .body(Body::from("{}"))
        .expect("request");
    let response = http_router(Arc::clone(&service))
        .oneshot(missing_content_type)
        .await
        .expect("http response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("error body");
    let error: crate::HttpErrorBody = serde_json::from_slice(&bytes).expect("error envelope");
    assert_eq!(error.code, contextdb_service::ErrorCode::FormatIncompatible);

    let oversized = Request::builder()
        .method("POST")
        .uri("/v1/recall")
        .header("content-type", "application/json")
        .body(Body::from(vec![b' '; MAX_WIRE_BYTES + 1]))
        .expect("request");
    let response = http_router(service)
        .oneshot(oversized)
        .await
        .expect("http response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("error body");
    let error: crate::HttpErrorBody = serde_json::from_slice(&bytes).expect("error envelope");
    assert_eq!(error.code, contextdb_service::ErrorCode::Unauthorized);
    assert!(!error.retryable);
}

#[test]
fn protobuf_conversion_rejects_noncanonical_json_and_unspecified_labels() {
    let mut request =
        observe_request_to_proto(observe_request("observation:bad", "idempotency:bad"))
            .expect("wire request");
    request.content_json = br#"{ "text": "not canonical" }"#.to_vec();
    assert!(crate::observe_request_from_proto(request.clone()).is_err());

    request.content_json = br#"{"text":"not canonical"}"#.to_vec();
    request.access.as_mut().expect("access").sensitivity = 0;
    assert!(crate::observe_request_from_proto(request).is_err());

    let high_level = high_level_write_request("request:proto-high-level");
    let wire = crate::high_level_write_request_to_proto(high_level.clone())
        .expect("high-level wire request");
    assert_eq!(
        crate::high_level_write_request_from_proto(wire).expect("high-level round trip"),
        high_level
    );

    let mut noncanonical =
        crate::high_level_write_request_to_proto(high_level).expect("high-level wire request");
    noncanonical.payload_json = br#"{ "text": "not canonical" }"#.to_vec();
    assert!(crate::high_level_write_request_from_proto(noncanonical).is_err());
}

#[test]
fn grpc_status_preserves_the_typed_safe_error_details() {
    let status = crate::grpc::grpc_status(
        contextdb_service::ServiceError::new(
            contextdb_service::ErrorCode::Unauthorized,
            "policy denied",
            false,
        )
        .with_context(
            vec!["partial:1".into()],
            Some("policy:no-share".into()),
            Some("request a narrower scope".into()),
            Some("trace:safe".into()),
        ),
    );
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    let details =
        contextdb_proto::v1::ErrorStatus::decode(status.details()).expect("typed error details");
    assert_eq!(
        details.code,
        contextdb_proto::v1::ErrorCode::Unauthorized as i32
    );
    assert_eq!(details.partial_result_refs, ["partial:1"]);
    assert_eq!(details.violated_policy.as_deref(), Some("policy:no-share"));
    assert_eq!(details.trace_id.as_deref(), Some("trace:safe"));

    let expired = crate::grpc::grpc_status(contextdb_service::stream_lease_expired_error());
    assert_eq!(expired.code(), tonic::Code::OutOfRange);
    let details =
        contextdb_proto::v1::ErrorStatus::decode(expired.details()).expect("typed expiry details");
    assert_eq!(
        details.code,
        contextdb_proto::v1::ErrorCode::SnapshotExpired as i32
    );
    assert!(!details.retryable);
    assert!(details.partial_result_refs.is_empty());
    assert_eq!(
        details.violated_policy.as_deref(),
        Some("stream_lease_expired")
    );
}

#[test]
fn ingest_ack_conversion_preserves_the_optional_lease_deadline() {
    let ack = contextdb_service::IngestAck {
        stream_id: "stream:leased".to_owned(),
        position: 2,
        disposition: contextdb_service::IngestDisposition::Accepted,
        frame_digest: "digest".to_owned(),
        resume_cursor: "cursor".to_owned(),
        commit_seq: None,
        partial_result_refs: Vec::new(),
        lease_expires_at_ms: Some(1_750_000_000_000),
    };
    let wire = crate::ingest_ack_to_proto(ack);
    assert_eq!(wire.lease_expires_at_ms, Some(1_750_000_000_000));
}

#[tokio::test]
async fn grpc_wire_prewalk_rejects_allocation_amplification_before_auth_handler() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("wire-prewalk", [0x91; 32]).expect("service"));
    let gateway = Arc::new(CountingGatewayAuthenticator::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_grpc_listener_with_shutdown_and_gateway(
        listener,
        service,
        gateway.clone(),
        async move {
            let _ = shutdown_receiver.await;
        },
    ));

    let request = wire::ObserveRequest {
        metadata: (0..=4_096)
            .map(|_| wire::JsonEntry {
                key: String::new(),
                canonical_json: Vec::new(),
            })
            .collect(),
        ..Default::default()
    };
    let mut client = ObservationServiceClient::connect(format!("http://{address}"))
        .await
        .expect("connect");
    let status = client
        .observe(request)
        .await
        .expect_err("allocation-amplifying repeated fields must fail at decode admission");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    assert_eq!(gateway.modern_calls.load(Ordering::SeqCst), 0);

    let _ = shutdown_sender.send(());
    server.await.expect("server task").expect("server result");
}

#[tokio::test]
async fn grpc_network_stream_is_ordered_bounded_and_partially_acknowledged() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("stream-test", [9; 32]).expect("valid key"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let server = tokio::spawn(serve_grpc_listener_with_shutdown_and_gateway(
        listener,
        service,
        gateway.clone(),
        async move {
            let _ = shutdown_receiver.await;
        },
    ));

    let mut first = observe_request("observation:stream:1", "idempotency:stream:1");
    let mut conflicting = first.clone();
    conflicting.content = serde_json::json!({"text": "different retry payload"});
    let second = observe_request("observation:stream:2", "idempotency:stream:2");
    first.context.request_id = "request:stream:1".into();
    conflicting.context.request_id = "request:stream:1".into();
    let mut second = second;
    second.context.request_id = "request:stream:1".into();
    let requests = vec![
        observe_request_to_proto(first).expect("first"),
        observe_request_to_proto(conflicting).expect("conflict"),
        observe_request_to_proto(second).expect("second"),
    ];
    let endpoint = format!("http://{address}");
    let mut client = ObservationServiceClient::connect(endpoint)
        .await
        .expect("connect");
    let rejected = client
        .observe_stream(tokio_stream::iter([requests[0].clone()]))
        .await
        .expect_err("first unauthenticated frame must reject the stream opening");
    assert_eq!(rejected.code(), tonic::Code::PermissionDenied);

    let first_attested = attest_observe_stream_frame(&gateway, requests[0].clone());
    let mut changed_context = first_attested.clone();
    changed_context
        .context
        .as_mut()
        .expect("stream context")
        .purpose = "changed-after-attestation".to_owned();
    let mixed_request = tonic::Request::new(tokio_stream::iter([first_attested, changed_context]));
    let mut mixed = client
        .observe_stream(mixed_request)
        .await
        .expect("mixed stream response")
        .into_inner();
    let first_mixed = mixed
        .message()
        .await
        .expect("first mixed frame")
        .expect("first mixed acknowledgement");
    assert!(matches!(first_mixed.outcome, Some(Outcome::Response(_))));
    let status = mixed
        .message()
        .await
        .expect_err("changed per-frame context must terminate the stream");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    let signing_gateway = Arc::clone(&gateway);
    let requests = requests
        .into_iter()
        .map(move |frame| attest_observe_stream_frame(&signing_gateway, frame));
    let request = tonic::Request::new(tokio_stream::iter(requests));
    let mut response = client
        .observe_stream(request)
        .await
        .expect("stream call")
        .into_inner();
    let mut acknowledgements = Vec::new();
    while let Some(value) = response.message().await.expect("stream response") {
        acknowledgements.push(value);
    }

    assert_eq!(acknowledgements.len(), 3);
    assert_eq!(
        acknowledgements
            .iter()
            .map(|ack| ack.stream_position)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(matches!(
        acknowledgements[0].outcome,
        Some(Outcome::Response(_))
    ));
    assert!(matches!(
        acknowledgements[1].outcome,
        Some(Outcome::Error(_))
    ));
    assert!(matches!(
        acknowledgements[2].outcome,
        Some(Outcome::Response(_))
    ));

    let _ = shutdown_sender.send(());
    server.await.expect("server task").expect("server result");
}

#[tokio::test]
async fn health_routes_are_content_free_and_independent_of_gateway_authentication() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("health-default", [0x41; 32]).expect("service"));
    let router = http_router(Arc::clone(&service));

    let live = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/live")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("live response");
    assert_eq!(live.status(), StatusCode::OK);
    assert_eq!(live.headers()["cache-control"], "no-store");
    assert_eq!(live.headers()["pragma"], "no-cache");
    let live: HealthSummary =
        serde_json::from_slice(&to_bytes(live.into_body(), 4096).await.expect("live body"))
            .expect("live JSON");
    assert_eq!(live.state, HealthState::Live);
    assert_eq!(live.profile, HealthProfile::Transport);
    assert_eq!(live.capability_manifest.profile, "transport-http-v1");
    assert!(!live.capability_manifest.server_v1_release_ready);
    assert_eq!(
        live.capability_manifest.capability("http_transport"),
        Some(contextdb_service::CapabilityState::Available)
    );
    assert!(!live.is_ready());

    let default_ready = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("ready response");
    assert_eq!(default_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(default_ready.headers()["cache-control"], "no-store");
    let default_ready: HealthSummary = serde_json::from_slice(
        &to_bytes(default_ready.into_body(), 4096)
            .await
            .expect("ready body"),
    )
    .expect("ready JSON");
    assert_eq!(default_ready.state, HealthState::NotReady);
    assert_eq!(
        default_ready.reason_code,
        Some(HealthReason::HealthProviderNotConfigured)
    );

    let ready = HealthSummary::new(
        HealthState::Ready,
        HealthProfile::ProductionFjallV1,
        HealthChecks {
            service_loaded: true,
            fjall_verified_at_startup: true,
            external_head_reconciled: true,
            publication_available: true,
        },
        None,
    )
    .expect("valid health");
    let configured = http_router_with_health_provider(
        service,
        Arc::new(FixedHealthProvider::new(ready.clone())),
    );
    let response = configured
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("configured response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let actual: HealthSummary = serde_json::from_slice(
        &to_bytes(response.into_body(), 4096)
            .await
            .expect("configured body"),
    )
    .expect("configured JSON");
    assert_eq!(actual, ready);
    assert_eq!(actual.capability_manifest.profile, "production-fjall-v1");
    assert_eq!(
        actual
            .capability_manifest
            .capability("persistent_ann_recall_projection"),
        Some(contextdb_service::CapabilityState::Unsupported)
    );

    let mut extension_leak = actual.clone();
    extension_leak.capability_manifest.capabilities.insert(
        "workspace:should-never-be-public".to_owned(),
        contextdb_service::CapabilityState::Available,
    );
    let sanitized = FixedHealthProvider::new(extension_leak).readiness();
    assert_eq!(sanitized.profile, HealthProfile::Transport);
    assert_eq!(
        sanitized.reason_code,
        Some(HealthReason::InvalidProviderResponse)
    );

    let invalid = HealthSummary {
        schema_version: 1,
        state: HealthState::Ready,
        profile: HealthProfile::ProductionFjallV1,
        checks: HealthChecks {
            service_loaded: false,
            fjall_verified_at_startup: false,
            external_head_reconciled: false,
            publication_available: false,
        },
        capability_manifest: contextdb_service::service_capability_manifest_v1(
            "production-fjall-v1",
            &["http_transport"],
            &[],
        ),
        reason_code: None,
    };
    let invalid_provider = http_router_with_health_provider(
        Arc::new(ReferenceService::new("health-invalid", [0x2c; 32]).expect("valid key")),
        Arc::new(FixedHealthProvider::new(invalid)),
    );
    let response = invalid_provider
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("invalid-provider response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let summary: HealthSummary = serde_json::from_slice(
        &to_bytes(response.into_body(), 4096)
            .await
            .expect("invalid-provider body"),
    )
    .expect("invalid-provider JSON");
    assert_eq!(summary.profile, HealthProfile::Transport);
    assert_eq!(
        summary.reason_code,
        Some(HealthReason::InvalidProviderResponse)
    );
}

#[tokio::test]
async fn grpc_idle_unauthenticated_streams_are_rejected_during_opening() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("idle-stream-test", [0x2d; 32]).expect("valid key"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let server = tokio::spawn(serve_grpc_listener_with_shutdown_and_gateway(
        listener,
        service,
        gateway,
        async move {
            let _ = shutdown_receiver.await;
        },
    ));

    let endpoint = format!("http://{address}");
    let mut client = ObservationServiceClient::connect(endpoint)
        .await
        .expect("connect");
    let (_idle_sender, idle_receiver) = tokio::sync::mpsc::channel::<wire::ObserveRequest>(1);
    let idle_stream = tokio_stream::wrappers::ReceiverStream::new(idle_receiver);
    let result = tokio::time::timeout(Duration::from_secs(3), client.observe_stream(idle_stream))
        .await
        .expect("the application must bound an idle stream opening")
        .expect_err("an idle stream without an authenticated first frame must be rejected");
    assert_eq!(result.code(), tonic::Code::DeadlineExceeded);

    let (_idle_sender, idle_receiver) = tokio::sync::mpsc::channel::<wire::IngestFrame>(1);
    let idle_stream = tokio_stream::wrappers::ReceiverStream::new(idle_receiver);
    let result = tokio::time::timeout(Duration::from_secs(3), client.ingest_snapshot(idle_stream))
        .await
        .expect("the application must bound an idle ingest opening")
        .expect_err("an idle ingest without an authenticated first frame must be rejected");
    assert_eq!(result.code(), tonic::Code::DeadlineExceeded);

    let _ = shutdown_sender.send(());
    server.await.expect("server task").expect("server result");
}

#[test]
fn authenticated_proto_context_rejects_unknown_capability_and_bad_auth_before_content() {
    let valid = authenticated("request:authenticated", &[Capability::Admin]);
    let mut wire = crate::authenticated_context_to_proto(valid.clone());
    wire.capability_grants.push(0);
    assert_eq!(
        crate::authenticated_context_from_proto(wire)
            .expect_err("unspecified capability")
            .code,
        contextdb_service::ErrorCode::InvalidArgument
    );

    let mut bad = valid;
    bad.authentication = AuthenticationEvidence::AuthenticatedChannel {
        channel_id: "channel:test".to_owned(),
        peer_identity: "subject:mallory".to_owned(),
        binding_digest: "55".repeat(32),
    };
    assert_eq!(
        crate::authenticated_context_from_proto(crate::authenticated_context_to_proto(bad))
            .expect_err("principal mismatch")
            .code,
        contextdb_service::ErrorCode::Unauthorized
    );
}

#[tokio::test]
async fn http_authenticated_routes_require_transport_binding() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-auth", [12; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let request = GetStatusRequest {
        context: authenticated("request:status", &[Capability::Admin]),
    };
    let body = serde_json::to_vec(&request).expect("json");
    let attestation = exact_http_attestation(&gateway, "/v1/admin/status", &body);

    let missing = Request::builder()
        .method("POST")
        .uri("/v1/admin/status")
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .expect("request");
    let response = http_router_with_gateway_authenticator(Arc::clone(&service), gateway.clone())
        .oneshot(missing)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let bound = Request::builder()
        .method("POST")
        .uri("/v1/admin/status")
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(GATEWAY_ATTESTATION_HEADER, attestation)
        .body(Body::from(body))
        .expect("request");
    let response = http_router_with_gateway_authenticator(service, gateway)
        .oneshot(bound)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn high_level_http_routes_require_full_gateway_auth_and_preserve_typed_gaps() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-high-level", [0x73; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let request = high_level_write_request("request:begin-session");
    let body = serde_json::to_vec(&request).expect("JSON");
    let router = http_router_with_gateway_authenticator(service, gateway.clone());

    let missing = Request::builder()
        .method("POST")
        .uri("/v1/conversation/begin-session")
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .expect("request");
    let response = router.clone().oneshot(missing).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let attestation = exact_http_attestation(&gateway, "/v1/conversation/begin-session", &body);
    let bound = Request::builder()
        .method("POST")
        .uri("/v1/conversation/begin-session")
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(GATEWAY_ATTESTATION_HEADER, attestation)
        .body(Body::from(body))
        .expect("request");
    let response = router.clone().oneshot(bound).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let control = HighLevelControlRequest {
        context: authenticated("request:pin", &[Capability::Correct]),
        idempotency_key: "idempotency:pin".to_owned(),
        target_subject_id: "subject:alice".to_owned(),
        target_id: "memory:one".to_owned(),
        parameters: serde_json::json!({"secret": "bounded"}),
    };
    let control_body = serde_json::to_vec(&control).expect("JSON");
    let attestation = exact_http_attestation(&gateway, "/v1/memory/pin", &control_body);
    let bound = Request::builder()
        .method("POST")
        .uri("/v1/memory/pin")
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(GATEWAY_ATTESTATION_HEADER, attestation)
        .body(Body::from(control_body))
        .expect("request");
    let response = router.oneshot(bound).await.expect("response");
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let error: crate::HttpErrorBody = serde_json::from_slice(&bytes).expect("error");
    assert_eq!(error.code, contextdb_service::ErrorCode::Unsupported);
}

#[tokio::test]
async fn high_level_http_authentication_precedes_sensitive_payload_decode() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-high-level-two-phase", [0x74; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let context = authenticated("request:two-phase-high-level", &[Capability::Observe]);
    let body = serde_json::to_vec(&serde_json::json!({
        "context": context,
        "idempotency_key": "idempotency:two-phase",
        "target_subject_id": "subject:alice",
        "session_id": "session:test",
        "logical_id": "logical:two-phase",
        "access": 42,
        "payload": {"secret": "must not reach the full decoder before auth"},
        "references": []
    }))
    .expect("JSON");
    let router = http_router_with_gateway_authenticator(service, gateway.clone());
    let missing = Request::builder()
        .method("POST")
        .uri("/v1/conversation/begin-session")
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .expect("request");
    assert_eq!(
        router
            .clone()
            .oneshot(missing)
            .await
            .expect("response")
            .status(),
        StatusCode::FORBIDDEN
    );

    let bound = Request::builder()
        .method("POST")
        .uri("/v1/conversation/begin-session")
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(
            GATEWAY_ATTESTATION_HEADER,
            exact_http_attestation(&gateway, "/v1/conversation/begin-session", &body),
        )
        .body(Body::from(body))
        .expect("request");
    assert_eq!(
        router.oneshot(bound).await.expect("response").status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn every_high_level_http_route_checks_gateway_and_capability_before_content() {
    const ROUTES: [&str; 29] = [
        "/v1/conversation/begin-session",
        "/v1/conversation/before-turn",
        "/v1/conversation/after-turn",
        "/v1/conversation/resolve-referent",
        "/v1/conversation/recall-shared-history",
        "/v1/conversation/end-session",
        "/v1/conversation/bootstrap-subject",
        "/v1/memory/remember",
        "/v1/memory/pin",
        "/v1/memory/suppress",
        "/v1/memory/change-audience",
        "/v1/memory/change-retention",
        "/v1/memory/explain",
        "/v1/memory/list-subject",
        "/v1/memory/export-subject",
        "/v1/memory/import-subject",
        "/v1/subjects/create",
        "/v1/relationship-spaces/create",
        "/v1/subjects/continuity-profile",
        "/v1/subjects/configured-role/update",
        "/v1/subjects/agent-runtime/migrate",
        "/v1/shared-memory/publish",
        "/v1/shared-memory/revoke",
        "/v1/artifacts/ingest",
        "/v1/artifacts/attach-to-episode",
        "/v1/artifacts/derived-representations",
        "/v1/artifacts/evidence-selectors",
        "/v1/artifacts/metadata",
        "/v1/artifacts/delete-lineage",
    ];
    const ALL_GRANTS: [Capability; 8] = [
        Capability::Observe,
        Capability::Recall,
        Capability::Correct,
        Capability::ReadMemory,
        Capability::Runtime,
        Capability::Forget,
        Capability::HardDelete,
        Capability::Admin,
    ];

    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-all-high-level-auth", [0x76; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let router = http_router_with_gateway_authenticator(service, gateway.clone());

    for (index, path) in ROUTES.into_iter().enumerate() {
        let request_id = format!("request:all-high-level:{index}");
        let no_grants = authenticated(&request_id, &[]);
        let invalid_body = serde_json::to_vec(&serde_json::json!({
            "context": no_grants,
            "idempotency_key": 42,
            "payload": {"secret": "must remain opaque before capability"}
        }))
        .expect("JSON");
        let missing_gateway = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(invalid_body.clone()))
            .expect("request");
        assert_eq!(
            router
                .clone()
                .oneshot(missing_gateway)
                .await
                .expect("response")
                .status(),
            StatusCode::FORBIDDEN,
            "gateway must precede content for {path}"
        );

        let capability_denied = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(GATEWAY_ID_HEADER, gateway.gateway_id())
            .header(
                GATEWAY_ATTESTATION_HEADER,
                exact_http_attestation(&gateway, path, &invalid_body),
            )
            .body(Body::from(invalid_body))
            .expect("request");
        assert_eq!(
            router
                .clone()
                .oneshot(capability_denied)
                .await
                .expect("response")
                .status(),
            StatusCode::FORBIDDEN,
            "capability must precede content for {path}"
        );

        let all_grants = authenticated(&request_id, &ALL_GRANTS);
        let invalid_body = serde_json::to_vec(&serde_json::json!({
            "context": all_grants,
            "idempotency_key": 42,
            "payload": {"secret": "now full schema validation may run"}
        }))
        .expect("JSON");
        let schema_denied = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(GATEWAY_ID_HEADER, gateway.gateway_id())
            .header(
                GATEWAY_ATTESTATION_HEADER,
                exact_http_attestation(&gateway, path, &invalid_body),
            )
            .body(Body::from(invalid_body))
            .expect("request");
        assert_eq!(
            router
                .clone()
                .oneshot(schema_denied)
                .await
                .expect("response")
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "full schema validation must follow authorization for {path}"
        );
    }
}

#[tokio::test]
async fn high_level_grpc_checks_gateway_and_capability_before_json_materialization() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("grpc-high-level-auth", [0x77; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let adapter = GrpcAdapter::with_gateway_authenticator(service, 4, gateway.clone());

    let no_grants = authenticated("request:grpc-high-level", &[]);
    let wire_request = wire::HighLevelControlRequest {
        context: Some(crate::authenticated_context_to_proto(no_grants.clone())),
        idempotency_key: "idempotency:grpc-high-level".to_owned(),
        target_subject_id: "subject:alice".to_owned(),
        target_id: "memory:one".to_owned(),
        parameters_json: b"not-json-and-must-not-be-materialized".to_vec(),
    };
    let status = MemoryControlService::pin(
        &adapter,
        authenticated_grpc_request(
            wire_request,
            &no_grants,
            "contextdb.v1.MemoryControlService/Pin",
            &gateway,
        ),
    )
    .await
    .expect_err("capability denied before content");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    let allowed = authenticated("request:grpc-high-level", &[Capability::Correct]);
    let wire_request = wire::HighLevelControlRequest {
        context: Some(crate::authenticated_context_to_proto(allowed.clone())),
        idempotency_key: "idempotency:grpc-high-level".to_owned(),
        target_subject_id: "subject:alice".to_owned(),
        target_id: "memory:one".to_owned(),
        parameters_json: b"not-json-and-now-schema-validation-runs".to_vec(),
    };
    let status = MemoryControlService::pin(
        &adapter,
        authenticated_grpc_request(
            wire_request,
            &allowed,
            "contextdb.v1.MemoryControlService/Pin",
            &gateway,
        ),
    )
    .await
    .expect_err("malformed JSON after capability");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn http_authenticates_raw_context_before_materializing_operation_payload() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-two-phase", [13; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let context = authenticated("request:two-phase", &[Capability::Runtime]);
    let body = serde_json::to_vec(&serde_json::json!({
        "context": context,
        "operation_id": 42,
        "payload": {"secret": "must-not-reach-domain-decoder"}
    }))
    .expect("json");
    let unauthenticated = Request::builder()
        .method("POST")
        .uri("/v1/runtime/preflight")
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .expect("request");
    let response = http_router_with_gateway_authenticator(
        Arc::clone(&service),
        Arc::clone(&gateway) as Arc<dyn GatewayAuthenticator>,
    )
    .oneshot(unauthenticated)
    .await
    .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let _context = authenticated("request:two-phase", &[Capability::Runtime]);
    let attestation = exact_http_attestation(&gateway, "/v1/runtime/preflight", &body);
    let authenticated = Request::builder()
        .method("POST")
        .uri("/v1/runtime/preflight")
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(GATEWAY_ATTESTATION_HEADER, attestation)
        .body(Body::from(body))
        .expect("request");
    let response = http_router_with_gateway_authenticator(service, gateway)
        .oneshot(authenticated)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn maintenance_http_authorization_precedes_full_payload_decode_on_every_route() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("http-maintenance-two-phase", [0x78; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let router = http_router_with_gateway_authenticator(service, gateway.clone());

    for (index, call) in MaintenanceTestCall::ALL.into_iter().enumerate() {
        let request_id = format!("request:http-maintenance:{index}");
        let no_grants = authenticated(&request_id, &[]);
        let allowed = authenticated(&request_id, &[Capability::Maintenance]);
        let valid_body = |context: &AuthenticatedRequestContext| {
            serde_json::to_vec(&serde_json::json!({
                "context": context,
                "operation_id": format!("operation:{}", call.label()),
                "payload": {"mode": "bounded"}
            }))
            .expect("maintenance JSON")
        };
        // The outer JSON and authentication envelope remain valid, while the
        // operation id is deliberately incompatible with the full DTO.
        let malformed_body = |context: &AuthenticatedRequestContext| {
            serde_json::to_vec(&serde_json::json!({
                "context": context,
                "operation_id": 42,
                "payload": {"secret": "must remain opaque before authorization"}
            }))
            .expect("schema-incompatible maintenance JSON")
        };
        let request = |body: Vec<u8>, context: Option<&AuthenticatedRequestContext>| {
            let mut builder = Request::builder()
                .method("POST")
                .uri(call.http_path())
                .header("content-type", "application/json");
            if let Some(_context) = context {
                builder = builder
                    .header(GATEWAY_ID_HEADER, gateway.gateway_id())
                    .header(
                        GATEWAY_ATTESTATION_HEADER,
                        exact_http_attestation(&gateway, call.http_path(), &body),
                    );
            }
            builder.body(Body::from(body)).expect("maintenance request")
        };

        let missing_gateway_valid =
            http_error_response(router.clone(), request(valid_body(&no_grants), None)).await;
        let missing_gateway_malformed =
            http_error_response(router.clone(), request(malformed_body(&no_grants), None)).await;
        assert_eq!(missing_gateway_valid.0, StatusCode::FORBIDDEN);
        assert_eq!(missing_gateway_valid, missing_gateway_malformed);

        let missing_capability_valid = http_error_response(
            router.clone(),
            request(valid_body(&no_grants), Some(&no_grants)),
        )
        .await;
        let missing_capability_malformed = http_error_response(
            router.clone(),
            request(malformed_body(&no_grants), Some(&no_grants)),
        )
        .await;
        assert_eq!(missing_capability_valid.0, StatusCode::FORBIDDEN);
        assert_eq!(missing_capability_valid, missing_capability_malformed);
        assert_eq!(
            missing_capability_valid.1.code,
            contextdb_service::ErrorCode::Unauthorized
        );

        let authorized_malformed = http_error_response(
            router.clone(),
            request(malformed_body(&allowed), Some(&allowed)),
        )
        .await;
        assert_eq!(authorized_malformed.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            authorized_malformed.1.code,
            contextdb_service::ErrorCode::FormatIncompatible
        );

        let authorized_valid = http_error_response(
            router.clone(),
            request(valid_body(&allowed), Some(&allowed)),
        )
        .await;
        assert_eq!(authorized_valid.0, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            authorized_valid.1.code,
            contextdb_service::ErrorCode::Unsupported
        );
    }
}

#[tokio::test]
async fn maintenance_http_auth_envelope_and_wire_limit_both_fail_early() {
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        ReferenceService::new("http-maintenance-wire-limit", [0x79; 32]).expect("service"),
    );
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let router = http_router_with_gateway_authenticator(service, gateway.clone());
    let context = authenticated(
        "request:http-maintenance:oversized",
        &[Capability::Maintenance],
    );
    let body = serde_json::to_vec(&serde_json::json!({
        "context": context,
        "operation_id": "operation:reindex:oversized",
        "payload": {"padding": "x".repeat(MAX_WIRE_BYTES)}
    }))
    .expect("oversized maintenance JSON");
    assert!(body.len() > MAX_WIRE_BYTES);

    let request = |authenticated: bool| {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/maintenance/reindex")
            .header("content-type", "application/json");
        if authenticated {
            builder = builder
                .header(GATEWAY_ID_HEADER, gateway.gateway_id())
                .header(
                    GATEWAY_ATTESTATION_HEADER,
                    exact_http_attestation(&gateway, "/v1/maintenance/reindex", &body),
                );
        }
        builder
            .body(Body::from(body.clone()))
            .expect("oversized maintenance request")
    };

    let missing_gateway = http_error_response(router.clone(), request(false)).await;
    let authenticated = http_error_response(router, request(true)).await;
    assert_eq!(missing_gateway.0, StatusCode::FORBIDDEN);
    assert_eq!(
        missing_gateway.1.code,
        contextdb_service::ErrorCode::Unauthorized
    );
    assert_eq!(authenticated.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        authenticated.1.code,
        contextdb_service::ErrorCode::ResourceExhausted
    );
}

#[tokio::test]
async fn maintenance_grpc_authorization_precedes_payload_json_on_every_method() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("grpc-maintenance-two-phase", [0x7a; 32]).expect("service"));
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let adapter = GrpcAdapter::with_gateway_authenticator(service, 4, gateway.clone());

    for (index, call) in MaintenanceTestCall::ALL.into_iter().enumerate() {
        let request_id = format!("request:grpc-maintenance:{index}");
        let no_grants = authenticated(&request_id, &[]);
        let allowed = authenticated(&request_id, &[Capability::Maintenance]);
        let wire_request =
            |context: &AuthenticatedRequestContext, payload_json: &[u8]| wire::MaintenanceRequest {
                context: Some(crate::authenticated_context_to_proto(context.clone())),
                operation_id: format!("operation:{}", call.label()),
                payload_json: payload_json.to_vec(),
            };

        let missing_gateway_valid = call_grpc_maintenance(
            &adapter,
            call,
            tonic::Request::new(wire_request(&no_grants, b"{}")),
        )
        .await
        .expect_err("missing gateway must be denied");
        let missing_gateway_malformed = call_grpc_maintenance(
            &adapter,
            call,
            tonic::Request::new(wire_request(&no_grants, b"not-json")),
        )
        .await
        .expect_err("missing gateway must precede malformed JSON");
        assert_eq!(missing_gateway_valid.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            missing_gateway_valid.code(),
            missing_gateway_malformed.code()
        );
        assert_eq!(
            missing_gateway_valid.message(),
            missing_gateway_malformed.message()
        );
        assert_eq!(
            missing_gateway_valid.details(),
            missing_gateway_malformed.details()
        );

        let missing_capability_valid = call_grpc_maintenance(
            &adapter,
            call,
            authenticated_grpc_request(
                wire_request(&no_grants, b"{}"),
                &no_grants,
                call.grpc_operation(),
                &gateway,
            ),
        )
        .await
        .expect_err("missing maintenance capability must be denied");
        let missing_capability_malformed = call_grpc_maintenance(
            &adapter,
            call,
            authenticated_grpc_request(
                wire_request(&no_grants, b"not-json"),
                &no_grants,
                call.grpc_operation(),
                &gateway,
            ),
        )
        .await
        .expect_err("capability denial must precede malformed JSON");
        assert_eq!(
            missing_capability_valid.code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            missing_capability_valid.code(),
            missing_capability_malformed.code()
        );
        assert_eq!(
            missing_capability_valid.message(),
            missing_capability_malformed.message()
        );
        assert_eq!(
            missing_capability_valid.details(),
            missing_capability_malformed.details()
        );

        let authorized_malformed = call_grpc_maintenance(
            &adapter,
            call,
            authenticated_grpc_request(
                wire_request(&allowed, b"not-json"),
                &allowed,
                call.grpc_operation(),
                &gateway,
            ),
        )
        .await
        .expect_err("authorized malformed JSON must reach conversion");
        assert_eq!(authorized_malformed.code(), tonic::Code::InvalidArgument);

        let authorized_valid = call_grpc_maintenance(
            &adapter,
            call,
            authenticated_grpc_request(
                wire_request(&allowed, b"{}"),
                &allowed,
                call.grpc_operation(),
                &gateway,
            ),
        )
        .await
        .expect_err("reference profile keeps maintenance unsupported");
        assert_eq!(authorized_valid.code(), tonic::Code::Unimplemented);
    }
}

#[tokio::test]
async fn maintenance_grpc_wire_limit_precedes_application_authentication() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("listener address");
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        ReferenceService::new("grpc-maintenance-wire-limit", [0x7b; 32]).expect("service"),
    );
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway verifier"),
    );
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_grpc_listener_with_shutdown_and_gateway(
        listener,
        service,
        gateway.clone(),
        async move {
            let _ = shutdown_receiver.await;
        },
    ));
    let endpoint = format!("http://{address}");
    let mut client = MaintenanceServiceClient::connect(endpoint)
        .await
        .expect("connect")
        .max_encoding_message_size(MAX_WIRE_BYTES * 2);
    let context = authenticated(
        "request:grpc-maintenance:oversized",
        &[Capability::Maintenance],
    );
    let wire_request = wire::MaintenanceRequest {
        context: Some(crate::authenticated_context_to_proto(context.clone())),
        operation_id: "operation:reindex:oversized".to_owned(),
        payload_json: vec![b'x'; MAX_WIRE_BYTES],
    };
    assert!(wire_request.encoded_len() > MAX_WIRE_BYTES);

    let missing_gateway = client
        .reindex(tonic::Request::new(wire_request.clone()))
        .await
        .expect_err("oversized frame must be rejected before gateway auth");
    let authenticated = client
        .reindex(authenticated_grpc_request(
            wire_request,
            &context,
            "contextdb.v1.MaintenanceService/Reindex",
            &gateway,
        ))
        .await
        .expect_err("oversized frame must be rejected before application decoding");
    // Tonic's configured unary message-size guard reports an oversized
    // decoded frame as OUT_OF_RANGE before dispatching the application RPC.
    assert_eq!(missing_gateway.code(), tonic::Code::OutOfRange);
    assert_eq!(missing_gateway.code(), authenticated.code());

    let _ = shutdown_sender.send(());
    server.await.expect("server task").expect("server result");
}

#[tokio::test]
async fn shared_http_grpc_admission_rejects_before_service_execution() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("shared-admission", [0x81; 32]).expect("service"));
    let gateway =
        Arc::new(Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway"));
    let admission = Arc::new(ExecutionAdmission::new(
        ExecutionAdmissionConfig::new(1, 1, 1).expect("admission config"),
    ));
    let held = admission
        .try_acquire(ExecutionClass::Interactive)
        .expect("hold interactive slot");
    let router = http_router_with_gateway_authenticator_health_and_admission(
        Arc::clone(&service),
        gateway.clone(),
        Arc::new(FixedHealthProvider::not_configured()),
        Arc::clone(&admission),
    );
    let request = observe_request("observation:admission:http", "idempotency:admission:http");
    let response = router
        .oneshot(legacy_http_request(
            "/v1/observations",
            LegacyNetworkOperation::HttpObserve,
            &request.context,
            &request,
            &gateway,
        ))
        .await
        .expect("HTTP response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: crate::HttpErrorBody = serde_json::from_slice(
        &to_bytes(response.into_body(), 4096)
            .await
            .expect("bounded overload body"),
    )
    .expect("typed overload body");
    assert_eq!(body.code, contextdb_service::ErrorCode::ResourceExhausted);
    assert!(body.retryable);

    let adapter = GrpcAdapter::with_gateway_authenticator_and_admission(
        Arc::clone(&service),
        8,
        gateway.clone(),
        Arc::clone(&admission),
    );
    let grpc_request = observe_request("observation:admission:grpc", "idempotency:admission:grpc");
    let proto = observe_request_to_proto(grpc_request.clone()).expect("proto request");
    let error = ObservationService::observe(
        &adapter,
        legacy_grpc_request(
            proto,
            LegacyNetworkOperation::GrpcObserve,
            &grpc_request.context,
            &gateway,
        ),
    )
    .await
    .expect_err("gRPC shares exhausted HTTP capacity");
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);

    drop(held);
    let proto = observe_request_to_proto(grpc_request.clone()).expect("retry proto");
    let response = ObservationService::observe(
        &adapter,
        legacy_grpc_request(
            proto,
            LegacyNetworkOperation::GrpcObserve,
            &grpc_request.context,
            &gateway,
        ),
    )
    .await
    .expect("capacity release permits execution")
    .into_inner();
    assert_eq!(
        response.commit_seq, 1,
        "rejected calls never reached service"
    );
}

#[tokio::test]
async fn workload_classes_are_isolated_and_health_bypasses_work_admission() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("class-admission", [0x82; 32]).expect("service"));
    let gateway =
        Arc::new(Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway"));
    let admission = Arc::new(ExecutionAdmission::new(
        ExecutionAdmissionConfig::new(1, 1, 1).expect("admission config"),
    ));
    let _maintenance = admission
        .try_acquire(ExecutionClass::Maintenance)
        .expect("hold maintenance slot");
    let router = http_router_with_gateway_authenticator_health_and_admission(
        service,
        gateway.clone(),
        Arc::new(FixedHealthProvider::not_configured()),
        Arc::clone(&admission),
    );

    let live = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/live")
                .body(Body::empty())
                .expect("live request"),
        )
        .await
        .expect("live response");
    assert_eq!(live.status(), StatusCode::OK);

    let request = observe_request("observation:class", "idempotency:class");
    let response = router
        .oneshot(legacy_http_request(
            "/v1/observations",
            LegacyNetworkOperation::HttpObserve,
            &request.context,
            &request,
            &gateway,
        ))
        .await
        .expect("interactive response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn grpc_stream_frames_are_individually_fail_fast_admitted() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("stream-admission", [0x83; 32]).expect("service"));
    let gateway =
        Arc::new(Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway"));
    let admission = Arc::new(ExecutionAdmission::new(
        ExecutionAdmissionConfig::new(1, 1, 1).expect("admission config"),
    ));
    let held = admission
        .try_acquire(ExecutionClass::Interactive)
        .expect("hold interactive slot");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_grpc_listener_with_shutdown_gateway_and_admission(
        listener,
        service,
        gateway.clone(),
        admission,
        async move {
            let _ = shutdown_receiver.await;
        },
    ));

    let request = observe_request(
        "observation:stream:admission",
        "idempotency:stream:admission",
    );
    let proto = attest_observe_stream_frame(
        &gateway,
        observe_request_to_proto(request).expect("proto request"),
    );
    let mut client = ObservationServiceClient::connect(format!("http://{address}"))
        .await
        .expect("connect");
    let response = client
        .observe_stream(tonic::Request::new(tokio_stream::iter([proto])))
        .await
        .expect("stream opens")
        .into_inner()
        .message()
        .await
        .expect("stream response")
        .expect("one acknowledgement");
    let Some(Outcome::Error(error)) = response.outcome else {
        panic!("exhausted stream frame must return one typed error outcome");
    };
    assert_eq!(
        error.code,
        contextdb_proto::v1::ErrorCode::ResourceExhausted as i32
    );
    assert!(error.retryable);

    drop(held);
    let _ = shutdown_sender.send(());
    server.await.expect("server task").expect("server result");
}

#[tokio::test]
async fn typed_capability_denial_precedes_full_decode_and_exhausted_admission() {
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        ReferenceService::new("capability-before-admission", [0x84; 32]).expect("service"),
    );
    let gateway =
        Arc::new(Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway"));
    let admission = Arc::new(ExecutionAdmission::new(
        ExecutionAdmissionConfig::new(1, 1, 1).expect("admission config"),
    ));
    let _held = admission
        .try_acquire(ExecutionClass::Interactive)
        .expect("hold interactive slot");
    let router = http_router_with_gateway_authenticator_health_and_admission(
        Arc::clone(&service),
        gateway.clone(),
        Arc::new(FixedHealthProvider::not_configured()),
        Arc::clone(&admission),
    );

    let request = |path: &str, _context: &AuthenticatedRequestContext, body: serde_json::Value| {
        let body = serde_json::to_vec(&body).expect("JSON");
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(GATEWAY_ID_HEADER, gateway.gateway_id())
            .header(
                GATEWAY_ATTESTATION_HEADER,
                exact_http_attestation(&gateway, path, &body),
            )
            .body(Body::from(body))
            .expect("request")
    };

    let no_grants = authenticated("request:denied-runtime", &[]);
    let runtime = router
        .clone()
        .oneshot(request(
            "/v1/runtime/preflight",
            &no_grants,
            serde_json::json!({
                "context": no_grants.clone(),
                "operation_id": {"malformed": true},
                "payload": "sensitive malformed payload"
            }),
        ))
        .await
        .expect("runtime response");
    assert_eq!(runtime.status(), StatusCode::FORBIDDEN);

    let forget_only = authenticated("request:denied-hard-delete", &[Capability::Forget]);
    let hard_delete = router
        .clone()
        .oneshot(request(
            "/v1/observations/forget",
            &forget_only,
            serde_json::json!({
                "context": forget_only.clone(),
                "idempotency_key": {"malformed": true},
                "target_id": ["malformed"],
                "mode": "hard_delete",
                "reason": {"sensitive": "not decoded"}
            }),
        ))
        .await
        .expect("hard-delete response");
    assert_eq!(hard_delete.status(), StatusCode::FORBIDDEN);

    let timeline_context = authenticated("request:denied-timeline", &[]);
    let timeline = router
        .oneshot(request(
            "/v1/memory/timeline",
            &timeline_context,
            serde_json::json!({
                "context": timeline_context.clone(),
                "record_id": {"malformed": true},
                "expected_kind": "evidence",
                "max_revisions": "malformed"
            }),
        ))
        .await
        .expect("timeline response");
    assert_eq!(timeline.status(), StatusCode::FORBIDDEN);

    let grpc_context = authenticated("request:denied-grpc-runtime", &[]);
    let adapter = GrpcAdapter::with_gateway_authenticator_and_admission(
        service,
        8,
        gateway.clone(),
        admission,
    );
    let grpc_request = wire::RuntimeRequest {
        context: Some(crate::authenticated_context_to_proto(grpc_context.clone())),
        operation_id: "operation:denied".to_owned(),
        payload_json: b"sensitive malformed JSON".to_vec(),
    };
    let error = AgentRuntimeService::preflight(
        &adapter,
        authenticated_grpc_request(
            grpc_request,
            &grpc_context,
            "contextdb.v1.AgentRuntimeService/Preflight",
            &gateway,
        ),
    )
    .await
    .expect_err("capability denial must precede conversion and admission");
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn grpc_policy_discriminators_verify_gateway_exactly_once_per_request() {
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        ReferenceService::new("single-gateway-verification", [0x86; 32]).expect("service"),
    );
    let gateway = Arc::new(CountingGatewayAuthenticator::default());
    let adapter = GrpcAdapter::with_gateway_authenticator(service, 8, gateway.clone());

    let hard_delete = contextdb_service::ForgetRequest {
        context: authenticated(
            "request:single-verify-hard-delete",
            &[Capability::Forget, Capability::HardDelete],
        ),
        idempotency_key: "idempotency:single-verify-hard-delete".to_owned(),
        target_id: "memory:missing".to_owned(),
        mode: contextdb_service::ForgetMode::HardDelete,
        reason: "user_requested".to_owned(),
    };
    let result = ObservationService::forget(
        &adapter,
        counted_grpc_request(
            crate::forget_request_to_proto(hard_delete),
            "contextdb.v1.ObservationService/Forget",
        ),
    )
    .await;
    let _ = result;
    assert_eq!(gateway.modern_calls.load(Ordering::SeqCst), 1);

    let timeline = contextdb_service::GetTimelineRequest {
        context: authenticated("request:single-verify-timeline", &[Capability::ReadMemory]),
        record_id: "memory:missing".to_owned(),
        expected_kind: contextdb_service::MemoryRecordKind::Node,
        at_commit: None,
        max_revisions: 8,
    };
    let result = MemoryService::get_timeline(
        &adapter,
        counted_grpc_request(
            crate::get_timeline_request_to_proto(timeline),
            "contextdb.v1.MemoryService/GetTimeline",
        ),
    )
    .await;
    let _ = result;
    assert_eq!(gateway.modern_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn recall_stream_rejects_overload_before_emitting_started() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("recall-stream-admission", [0x85; 32]).expect("service"));
    let gateway =
        Arc::new(Blake3GatewayAuthenticator::new("gateway:test", GATEWAY_KEY).expect("gateway"));
    let admission = Arc::new(ExecutionAdmission::new(
        ExecutionAdmissionConfig::new(1, 1, 1).expect("admission config"),
    ));
    let _held = admission
        .try_acquire(ExecutionClass::Interactive)
        .expect("hold interactive slot");
    let adapter = GrpcAdapter::with_gateway_authenticator_and_admission(
        service,
        8,
        gateway.clone(),
        admission,
    );
    let request = RecallRequest {
        context: context("request:recall-stream-overload"),
        query: "bounded recall".to_owned(),
        page_size: 4,
        at_commit: None,
        continuation: None,
    };
    let result = RecallService::recall_stream(
        &adapter,
        legacy_grpc_request(
            recall_request_to_proto(request.clone()),
            LegacyNetworkOperation::GrpcRecallStream,
            &request.context,
            &gateway,
        ),
    )
    .await;
    let Err(error) = result else {
        panic!("overloaded recall stream must fail before returning a stream");
    };
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
}
