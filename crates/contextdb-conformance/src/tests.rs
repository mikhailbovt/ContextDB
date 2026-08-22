#![allow(
    clippy::expect_used,
    reason = "conformance tests use immediate failure semantics"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::Request as HttpRequest;
use contextdb_proto::v1::admin_service_server::AdminService;
use contextdb_proto::v1::conversation_service_server::ConversationService;
use contextdb_proto::v1::memory_service_server::MemoryService;
use contextdb_proto::v1::observation_service_server::ObservationService;
use contextdb_reference::{
    AccessLabel, Consent as ReferenceConsent, ContextDb, Lifecycle, LogicalRecord, Mutation,
    RecordKind, SemanticLinks, SemanticTransaction, Sensitivity as ReferenceSensitivity, ValidTime,
};
use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, AuthenticationEvidence,
    Capability as ServiceCapability, CognitiveMemoryService, Consent, CorrectRequest,
    CreateBackupRequest, DomainTimeRange, ErrorCode, ExplainRecallRequest, ExportRequest,
    ForgetMode, ForgetRequest, GetMemoryRequest, GetStatusRequest, GetTimelineRequest,
    HighLevelMutationResponse, HighLevelQueryRequest, HighLevelWriteRequest, HostArchiveAuthority,
    ImportRequest, MemoryDocument, MemoryLifecycle, MemoryLinks, MemoryRecord, MemoryRecordKind,
    MutationResponse, ObserveRequest, ObserveResponse, RecallRequest, RecallResponse, RecallTrace,
    ReferenceService, Sensitivity, ServiceError, ServiceResult, StatusResponse, TimelineResponse,
    TraverseDirection, TraverseRequest, TraverseResponse, VerifyRequest, VerifyResponse,
};
use proptest::prelude::*;
use prost::Message;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use contextdb_server::{
    Blake3GatewayAuthenticator, GATEWAY_ATTESTATION_HEADER, GATEWAY_ID_HEADER, GatewayTransport,
    GrpcAdapter as ServerGrpcAdapter, backup_request_to_proto, correct_request_to_proto,
    forget_request_to_proto, get_memory_request_to_proto, get_timeline_request_to_proto,
    high_level_mutation_response_to_proto, high_level_query_request_to_proto,
    high_level_write_request_to_proto, http_router_with_gateway_authenticator,
    memory_record_to_proto, mutation_response_to_proto, status_request_to_proto,
    status_response_to_proto, timeline_response_to_proto, traverse_request_to_proto,
    traverse_response_to_proto,
};

use crate::adapters::{
    CliProcessAdapter, ConformanceAdapter, EmbeddedAdapter, GrpcAdapter, HttpAdapter, McpAdapter,
    prove_http_protocol_errors,
};
use crate::{
    CanonicalOperation, Capability, ConformanceFixture, SchemaManifest, Support,
    compare_schema_compatibility, current_schema_manifest, parse_proto_schema,
    prove_grpc_network_streaming, run_archive_round_trip, run_conformance_suite,
};

const KEY: [u8; 32] = [0x51; 32];
const DOMAIN_GATEWAY_KEY: [u8; 32] = [0x73; 32];
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
const ERROR_CODES: [ErrorCode; 21] = [
    ErrorCode::InvalidScope,
    ErrorCode::Unauthorized,
    ErrorCode::AmbiguousIdentity,
    ErrorCode::SnapshotExpired,
    ErrorCode::IndexTooStale,
    ErrorCode::EvidenceRequired,
    ErrorCode::ConflictUnresolved,
    ErrorCode::BudgetExhausted,
    ErrorCode::ContinuationExpired,
    ErrorCode::FormatIncompatible,
    ErrorCode::ProviderUnavailable,
    ErrorCode::DegradedMode,
    ErrorCode::InvalidArgument,
    ErrorCode::PermissionDenied,
    ErrorCode::NotFound,
    ErrorCode::IdempotencyConflict,
    ErrorCode::InvalidContinuation,
    ErrorCode::IntegrityFailure,
    ErrorCode::Unavailable,
    ErrorCode::ResourceExhausted,
    ErrorCode::Unsupported,
];

fn empty_service(database_id: &str) -> Arc<dyn CognitiveMemoryService> {
    Arc::new(ReferenceService::new(database_id, KEY).expect("reference service"))
}

fn seeded_service(database_id: &str) -> Arc<ReferenceService> {
    let database = ContextDb::new(database_id).expect("database");
    let records = [
        (
            "semantic:visible-a",
            "Japan jazz bar beside station",
            "subject:alice",
        ),
        (
            "semantic:visible-b",
            "Japan jazz bar quiet blue entrance",
            "subject:alice",
        ),
        (
            "semantic:forbidden",
            "Japan Japan jazz bar secret dossier",
            "subject:bob",
        ),
    ];
    let mutations = records
        .into_iter()
        .map(|(id, text, audience)| Mutation::Put {
            record: LogicalRecord {
                id: id.to_owned(),
                kind: RecordKind::SemanticObject,
                access: AccessLabel {
                    workspace: "workspace:conformance".to_owned(),
                    scopes: BTreeSet::from(["project:conformance".to_owned()]),
                    owners: BTreeSet::from([audience.to_owned()]),
                    audience: BTreeSet::from([audience.to_owned()]),
                    audience_purpose_grants: BTreeMap::from([(
                        audience.to_owned(),
                        BTreeSet::from(["assist".to_owned()]),
                    )]),
                    purposes: BTreeSet::new(),
                    sensitivity: ReferenceSensitivity::Private,
                    consent: ReferenceConsent::Granted,
                    retrievable: true,
                },
                valid_time: ValidTime::UNBOUNDED,
                lifecycle: Lifecycle::Active,
                links: SemanticLinks::default(),
                value: serde_json::json!({"fact": text}),
                search_text: Some(text.to_owned()),
                vector: None,
                attributes: BTreeMap::new(),
            },
            expected_revision: None,
        })
        .collect();
    database
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "m15-semantic-seed".to_owned(),
            mutations,
        })
        .expect("seed commit");
    Arc::new(ReferenceService::from_database(database, KEY).expect("seeded reference service"))
}

fn authenticated(
    request: contextdb_service::RequestContext,
    grants: &[ServiceCapability],
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
            binding_digest: "44".repeat(32),
        },
    }
}

fn mcp_adapter(
    service: Arc<dyn CognitiveMemoryService>,
    request: contextdb_service::RequestContext,
    grants: &[ServiceCapability],
) -> McpAdapter {
    McpAdapter::with_fixed_session_authority(service, authenticated(request, grants))
        .expect("fixed MCP host session")
}

fn domain_service() -> Arc<dyn CognitiveMemoryService> {
    let database = ContextDb::new("m15-domain-transcript").expect("database");
    let access = AccessLabel {
        workspace: "workspace:conformance".to_owned(),
        scopes: BTreeSet::from(["project:conformance".to_owned()]),
        owners: BTreeSet::from(["subject:alice".to_owned()]),
        audience: BTreeSet::from(["subject:alice".to_owned()]),
        audience_purpose_grants: BTreeMap::from([(
            "subject:alice".to_owned(),
            BTreeSet::from(["assist".to_owned()]),
        )]),
        purposes: BTreeSet::new(),
        sensitivity: ReferenceSensitivity::Private,
        consent: ReferenceConsent::Granted,
        retrievable: true,
    };
    let record = |id: &str, kind: RecordKind, value: serde_json::Value| LogicalRecord {
        id: id.to_owned(),
        kind,
        access: access.clone(),
        valid_time: ValidTime::UNBOUNDED,
        lifecycle: Lifecycle::Active,
        links: SemanticLinks::default(),
        value,
        search_text: None,
        vector: None,
        attributes: BTreeMap::new(),
    };
    let node_a = record("node:a", RecordKind::Node, serde_json::json!({"name": "A"}));
    let node_b = record("node:b", RecordKind::Node, serde_json::json!({"name": "B"}));
    let mut edge = record(
        "edge:a:b",
        RecordKind::Edge,
        serde_json::json!({"relationship": "next"}),
    );
    edge.links.source = Some("node:a".to_owned());
    edge.links.target = Some("node:b".to_owned());
    edge.links.predicate = Some("rel:next".to_owned());
    let mut claim = record(
        "claim:a",
        RecordKind::Claim,
        serde_json::json!({"status": "old"}),
    );
    claim.links.subject = Some("node:a".to_owned());
    claim.links.predicate = Some("status".to_owned());
    database
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "m15-domain-seed".to_owned(),
            mutations: [node_a, node_b, edge, claim]
                .into_iter()
                .map(|record| Mutation::Put {
                    record,
                    expected_revision: None,
                })
                .collect(),
        })
        .expect("domain seed");
    Arc::new(ReferenceService::from_database(database, KEY).expect("domain service"))
}

fn domain_context() -> AuthenticatedRequestContext {
    authenticated(
        ConformanceFixture::standard().caller,
        &[
            ServiceCapability::Correct,
            ServiceCapability::Forget,
            ServiceCapability::ReadMemory,
            ServiceCapability::Traverse,
            ServiceCapability::Admin,
        ],
    )
}

fn domain_policy() -> AccessPolicy {
    AccessPolicy {
        workspace_id: "workspace:conformance".to_owned(),
        scopes: BTreeSet::from(["project:conformance".to_owned()]),
        owners: BTreeSet::from(["subject:alice".to_owned()]),
        audience: BTreeSet::from(["subject:alice".to_owned()]),
        audience_purpose_grants: BTreeMap::from([(
            "subject:alice".to_owned(),
            BTreeSet::from(["assist".to_owned()]),
        )]),
        purposes: BTreeSet::new(),
        sensitivity: Sensitivity::Private,
        consent: Consent::Granted,
        retrievable: true,
    }
}

fn trusted_legacy_observe_policy() -> AccessPolicy {
    AccessPolicy {
        workspace_id: "workspace:conformance".to_owned(),
        scopes: BTreeSet::from(["project:conformance".to_owned()]),
        owners: BTreeSet::from(["subject:alice".to_owned()]),
        audience: BTreeSet::from(["subject:alice".to_owned()]),
        audience_purpose_grants: BTreeMap::new(),
        purposes: BTreeSet::from(["assist".to_owned()]),
        sensitivity: Sensitivity::Private,
        consent: Consent::Granted,
        retrievable: true,
    }
}

fn correction_request(context: AuthenticatedRequestContext) -> CorrectRequest {
    CorrectRequest {
        context,
        idempotency_key: "m15-domain-correct".to_owned(),
        target_id: "claim:a".to_owned(),
        replacement: MemoryDocument {
            id: "claim:a:v2".to_owned(),
            kind: MemoryRecordKind::Claim,
            access: domain_policy(),
            valid_time: DomainTimeRange::default(),
            lifecycle: MemoryLifecycle::Active,
            links: MemoryLinks {
                subject: Some("node:a".to_owned()),
                predicate: Some("status".to_owned()),
                supersedes: BTreeSet::from(["claim:a".to_owned()]),
                ..MemoryLinks::default()
            },
            value: serde_json::json!({"status": "corrected"}),
            search_text: Some("corrected status".to_owned()),
            vector: None,
            attributes: BTreeMap::new(),
        },
    }
}

async fn http_domain_call<T, R>(
    router: &axum::Router,
    gateway: &Blake3GatewayAuthenticator,
    path: &str,
    _context: &AuthenticatedRequestContext,
    request: &T,
) -> R
where
    T: Serialize,
    R: DeserializeOwned,
{
    let body = serde_json::to_vec(request).expect("request JSON");
    let attestation = gateway
        .attest_exact_request(
            GatewayTransport::Http,
            &format!("POST:{path}"),
            &body,
            unique_gateway_nonce(),
        )
        .expect("gateway attestation");
    let request = HttpRequest::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(GATEWAY_ATTESTATION_HEADER, attestation)
        .body(Body::from(body))
        .expect("HTTP request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("HTTP response");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = to_bytes(response.into_body(), contextdb_server::MAX_WIRE_BYTES)
        .await
        .expect("HTTP body");
    serde_json::from_slice(&bytes).expect("typed HTTP response")
}

async fn http_domain_error<T>(
    router: &axum::Router,
    gateway: &Blake3GatewayAuthenticator,
    path: &str,
    _context: &AuthenticatedRequestContext,
    request: &T,
) -> ServiceError
where
    T: Serialize,
{
    let body = serde_json::to_vec(request).expect("request JSON");
    let attestation = gateway
        .attest_exact_request(
            GatewayTransport::Http,
            &format!("POST:{path}"),
            &body,
            unique_gateway_nonce(),
        )
        .expect("gateway attestation");
    let request = HttpRequest::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header(GATEWAY_ID_HEADER, gateway.gateway_id())
        .header(GATEWAY_ATTESTATION_HEADER, attestation)
        .body(Body::from(body))
        .expect("HTTP request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("HTTP response");
    assert!(!response.status().is_success());
    let bytes = to_bytes(response.into_body(), contextdb_server::MAX_WIRE_BYTES)
        .await
        .expect("HTTP body");
    serde_json::from_slice(&bytes).expect("typed HTTP error")
}

fn grpc_domain_request<T: Message>(
    message: T,
    _context: &AuthenticatedRequestContext,
    operation: &'static str,
    gateway: &Blake3GatewayAuthenticator,
) -> tonic::Request<T> {
    let token = gateway
        .attest_exact_request(
            GatewayTransport::Grpc,
            operation,
            &message.encode_to_vec(),
            unique_gateway_nonce(),
        )
        .expect("gateway attestation");
    let mut request = tonic::Request::new(message);
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

#[tokio::test]
async fn embedded_http_grpc_and_mcp_share_one_semantic_transcript() {
    let fixture = ConformanceFixture::standard();
    let mut embedded = EmbeddedAdapter::new(seeded_service("conformance-parity"));
    let mut http = HttpAdapter::new(seeded_service("conformance-parity"));
    let mut grpc = GrpcAdapter::new(seeded_service("conformance-parity"));
    let mut mcp = mcp_adapter(
        seeded_service("conformance-parity"),
        fixture.caller.clone(),
        &[ServiceCapability::Observe, ServiceCapability::Recall],
    );

    let embedded_report = run_conformance_suite(&mut embedded, &fixture)
        .await
        .expect("embedded report");
    let http_report = run_conformance_suite(&mut http, &fixture)
        .await
        .expect("HTTP report");
    let grpc_report = run_conformance_suite(&mut grpc, &fixture)
        .await
        .expect("gRPC report");
    let mcp_report = run_conformance_suite(&mut mcp, &fixture)
        .await
        .expect("MCP report");
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/embedded_report_golden.json"
    ))
    .expect("embedded golden");

    assert!(
        embedded_report.semantic_checks_passed(),
        "{embedded_report:#?}"
    );
    assert!(http_report.semantic_checks_passed(), "{http_report:#?}");
    assert!(grpc_report.semantic_checks_passed(), "{grpc_report:#?}");
    assert!(mcp_report.semantic_checks_passed(), "{mcp_report:#?}");
    assert_eq!(embedded_report.semantic_digest, http_report.semantic_digest);
    assert_eq!(embedded_report.semantic_digest, grpc_report.semantic_digest);
    assert_ne!(
        embedded_report.semantic_digest, mcp_report.semantic_digest,
        "a fixed MCP principal rejects the cross-principal trace at the host boundary"
    );
    assert_eq!(
        golden
            .get("semantic_digest")
            .and_then(serde_json::Value::as_str),
        Some(embedded_report.semantic_digest.as_str())
    );
    assert_eq!(
        golden
            .get("report_digest")
            .and_then(serde_json::Value::as_str),
        Some(embedded_report.report_digest.as_str())
    );
    for report in [&embedded_report, &http_report, &grpc_report, &mcp_report] {
        assert!(report.manifest.unclassified().is_empty());
        assert!(!report.strictly_passed());
        assert!(matches!(
            report
                .manifest
                .capabilities
                .get(&Capability::RuntimeLifecycle),
            Some(Support::ProfileGap { .. })
        ));
    }
}

#[test]
fn runtime_profiles_separate_reference_gaps_from_unexercised_production_lifecycle() {
    for manifest in [
        crate::embedded_manifest(),
        crate::http_manifest(),
        crate::grpc_manifest(),
        crate::mcp_manifest(),
    ] {
        assert!(matches!(
            manifest.capabilities.get(&Capability::RuntimePreflight),
            Some(Support::Exercised)
        ));
        assert!(matches!(
            manifest.capabilities.get(&Capability::RuntimeLifecycle),
            Some(Support::ProfileGap { .. })
        ));
        assert!(matches!(
            manifest
                .capabilities
                .get(&Capability::RuntimePostflightReceipt),
            Some(Support::ProfileGap { .. })
        ));
        assert!(!manifest.is_strictly_satisfied());
    }

    let available_cli = crate::cli_manifest(true);
    assert!(matches!(
        available_cli
            .capabilities
            .get(&Capability::RuntimePreflight),
        Some(Support::Exercised)
    ));
    assert!(matches!(
        available_cli
            .capabilities
            .get(&Capability::RuntimePostflightReceipt),
        Some(Support::Exercised)
    ));
    assert!(matches!(
        available_cli
            .capabilities
            .get(&Capability::RuntimeLifecycle),
        Some(Support::ExternalProofRequired { .. })
    ));
    assert!(matches!(
        available_cli
            .capabilities
            .get(&Capability::RuntimeCapabilityManifest),
        Some(Support::Exercised)
    ));

    let unavailable_cli = crate::cli_manifest(false);
    assert!(matches!(
        unavailable_cli
            .capabilities
            .get(&Capability::RuntimePreflight),
        Some(Support::ExternalProofRequired { .. })
    ));
    assert!(matches!(
        unavailable_cli
            .capabilities
            .get(&Capability::RuntimeLifecycle),
        Some(Support::ExternalProofRequired { .. })
    ));
    assert!(matches!(
        unavailable_cli
            .capabilities
            .get(&Capability::RuntimePostflightReceipt),
        Some(Support::ExternalProofRequired { .. })
    ));
}

#[test]
fn production_policy_graph_reindex_does_not_claim_full_maintenance_admin() {
    for manifest in [
        crate::embedded_manifest(),
        crate::http_manifest(),
        crate::grpc_manifest(),
    ] {
        let Some(Support::ProfileGap { reason }) =
            manifest.capabilities.get(&Capability::MaintenanceAdmin)
        else {
            panic!("reference-backed adapter must keep maintenance/admin as a profile gap");
        };
        assert!(reason.contains("backup"));
        assert!(reason.contains("maintenance"));
        assert!(!manifest.is_strictly_satisfied());
    }

    let cli = crate::cli_manifest(true);
    let Some(Support::ProfileGap { reason }) = cli.capabilities.get(&Capability::MaintenanceAdmin)
    else {
        panic!("one production-only reindex projection must not satisfy maintenance/admin");
    };
    for exact_boundary in [
        "policy-graph reindex",
        "physical compact observation",
        "runtime-ledger GC",
        "consolidation",
        "reflection",
        "live restore",
        "format rewrite",
        "offline repair",
        "lexical/vector/HNSW",
        "SLO",
    ] {
        assert!(
            reason.contains(exact_boundary),
            "maintenance/admin gap omitted boundary {exact_boundary:?}: {reason}"
        );
    }
    assert!(!cli.is_strictly_satisfied());
}

#[test]
fn http_contract_keeps_health_outside_the_protected_sdk_surface() {
    #[derive(serde::Deserialize)]
    struct RouteSpec {
        method: String,
        path: String,
        profile: String,
    }

    #[derive(serde::Deserialize)]
    struct HealthBoundary {
        sdk_exposed: bool,
        gateway_attestation_required: bool,
        content_free: bool,
        rfc_31_15_complete: bool,
        server_v1_profile_proven: bool,
    }

    #[derive(serde::Deserialize)]
    struct HttpContract {
        candidate_runtime_capability_ids_v1: Vec<String>,
        routes: BTreeMap<String, String>,
        unauthenticated_non_sdk_routes: BTreeMap<String, RouteSpec>,
        health_boundary: HealthBoundary,
    }

    let contract: HttpContract =
        serde_json::from_str(include_str!("../../../sdk/fixtures/http_v1_contract.json"))
            .expect("HTTP contract fixture");
    assert_eq!(contract.routes.len(), 59);
    assert_eq!(
        contract.candidate_runtime_capability_ids_v1,
        contextdb_proto::CANDIDATE_RUNTIME_CAPABILITY_IDS_V1
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert!(
        contract
            .routes
            .values()
            .all(|path| path.starts_with("/v1/"))
    );
    assert_eq!(contract.unauthenticated_non_sdk_routes.len(), 2);
    assert_eq!(
        contract.routes.get("compile_context").map(String::as_str),
        Some("/v1/context-pack")
    );
    assert_eq!(
        contract
            .unauthenticated_non_sdk_routes
            .values()
            .map(|route| (
                route.method.as_str(),
                route.path.as_str(),
                route.profile.as_str()
            ))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ("GET", "/health/live", "current-server"),
            ("GET", "/health/ready", "current-server"),
        ])
    );
    assert!(!contract.health_boundary.sdk_exposed);
    assert!(!contract.health_boundary.gateway_attestation_required);
    assert!(contract.health_boundary.content_free);
    assert!(!contract.health_boundary.rfc_31_15_complete);
    assert!(!contract.health_boundary.server_v1_profile_proven);
}

#[tokio::test]
async fn authenticated_domain_methods_share_embedded_http_and_grpc_transcript() {
    let embedded = domain_service();
    let http_service = domain_service();
    let grpc_service = domain_service();
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:domain-transcript", DOMAIN_GATEWAY_KEY)
            .expect("gateway verifier"),
    );
    let http = http_router_with_gateway_authenticator(http_service, gateway.clone());
    let grpc = ServerGrpcAdapter::with_gateway_authenticator(grpc_service, 32, gateway.clone());
    let context = domain_context();

    let get_node = GetMemoryRequest {
        context: context.clone(),
        record_id: "node:a".to_owned(),
        at_commit: None,
    };
    let traverse = TraverseRequest {
        context: context.clone(),
        start_ids: vec!["node:a".to_owned()],
        direction: TraverseDirection::Outgoing,
        predicate_ids: BTreeSet::from(["rel:next".to_owned()]),
        max_hops: 1,
        max_nodes: 10,
        at_commit: None,
    };
    let correction = correction_request(context.clone());
    let timeline = GetTimelineRequest {
        context: context.clone(),
        record_id: "claim:a:v2".to_owned(),
        expected_kind: MemoryRecordKind::Claim,
        at_commit: None,
        max_revisions: 10,
    };
    let forget = ForgetRequest {
        context: context.clone(),
        idempotency_key: "m15-domain-forget".to_owned(),
        target_id: "claim:a:v2".to_owned(),
        mode: ForgetMode::Retract,
        reason: String::new(),
    };
    let status = GetStatusRequest {
        context: context.clone(),
    };
    let backup = CreateBackupRequest {
        context: context.clone(),
    };

    let embedded_node = embedded.get_node(get_node.clone()).expect("embedded node");
    let embedded_traverse = embedded
        .traverse(traverse.clone())
        .expect("embedded traverse");
    let embedded_correct = embedded
        .correct(correction.clone())
        .expect("embedded correct");
    let embedded_timeline = embedded
        .get_timeline(timeline.clone())
        .expect("embedded timeline");
    let embedded_forget = embedded.forget(forget.clone()).expect("embedded forget");
    let embedded_status = embedded
        .get_status(status.clone())
        .expect("embedded status");
    let embedded_backup = embedded
        .create_backup(backup.clone())
        .expect_err("workspace backup must be unavailable");

    let http_node: MemoryRecord = http_domain_call(
        &http,
        gateway.as_ref(),
        "/v1/memory/node",
        &context,
        &get_node,
    )
    .await;
    let http_traverse: TraverseResponse = http_domain_call(
        &http,
        gateway.as_ref(),
        "/v1/memory/traverse",
        &context,
        &traverse,
    )
    .await;
    let http_correct: MutationResponse = http_domain_call(
        &http,
        gateway.as_ref(),
        "/v1/observations/correct",
        &context,
        &correction,
    )
    .await;
    let http_timeline: TimelineResponse = http_domain_call(
        &http,
        gateway.as_ref(),
        "/v1/memory/timeline",
        &context,
        &timeline,
    )
    .await;
    let http_forget: MutationResponse = http_domain_call(
        &http,
        gateway.as_ref(),
        "/v1/observations/forget",
        &context,
        &forget,
    )
    .await;
    let http_status: StatusResponse = http_domain_call(
        &http,
        gateway.as_ref(),
        "/v1/admin/status",
        &context,
        &status,
    )
    .await;
    let http_backup = http_domain_error(
        &http,
        gateway.as_ref(),
        "/v1/admin/backup",
        &context,
        &backup,
    )
    .await;
    assert_eq!(http_node, embedded_node);
    assert_eq!(http_traverse, embedded_traverse);
    assert_eq!(http_correct, embedded_correct);
    assert_eq!(http_timeline, embedded_timeline);
    assert_eq!(http_forget, embedded_forget);
    assert_eq!(http_status, embedded_status);
    assert_eq!(http_backup.code, ErrorCode::Unsupported);
    assert_eq!(http_backup, embedded_backup);

    let grpc_node = MemoryService::get_node(
        &grpc,
        grpc_domain_request(
            get_memory_request_to_proto(get_node),
            &context,
            "contextdb.v1.MemoryService/GetNode",
            gateway.as_ref(),
        ),
    )
    .await
    .expect("gRPC node")
    .into_inner();
    assert_eq!(
        grpc_node,
        memory_record_to_proto(embedded_node).expect("node wire")
    );
    let grpc_traverse = MemoryService::traverse(
        &grpc,
        grpc_domain_request(
            traverse_request_to_proto(traverse),
            &context,
            "contextdb.v1.MemoryService/Traverse",
            gateway.as_ref(),
        ),
    )
    .await
    .expect("gRPC traverse")
    .into_inner();
    assert_eq!(grpc_traverse, traverse_response_to_proto(embedded_traverse));
    let grpc_correct = ObservationService::correct(
        &grpc,
        grpc_domain_request(
            correct_request_to_proto(correction).expect("correct wire"),
            &context,
            "contextdb.v1.ObservationService/Correct",
            gateway.as_ref(),
        ),
    )
    .await
    .expect("gRPC correct")
    .into_inner();
    assert_eq!(grpc_correct, mutation_response_to_proto(embedded_correct));
    let grpc_timeline = MemoryService::get_timeline(
        &grpc,
        grpc_domain_request(
            get_timeline_request_to_proto(timeline),
            &context,
            "contextdb.v1.MemoryService/GetTimeline",
            gateway.as_ref(),
        ),
    )
    .await
    .expect("gRPC timeline")
    .into_inner();
    assert_eq!(
        grpc_timeline,
        timeline_response_to_proto(embedded_timeline).expect("timeline wire")
    );
    let grpc_forget = ObservationService::forget(
        &grpc,
        grpc_domain_request(
            forget_request_to_proto(forget),
            &context,
            "contextdb.v1.ObservationService/Forget",
            gateway.as_ref(),
        ),
    )
    .await
    .expect("gRPC forget")
    .into_inner();
    assert_eq!(grpc_forget, mutation_response_to_proto(embedded_forget));
    let grpc_status = AdminService::get_status(
        &grpc,
        grpc_domain_request(
            status_request_to_proto(status),
            &context,
            "contextdb.v1.AdminService/GetStatus",
            gateway.as_ref(),
        ),
    )
    .await
    .expect("gRPC status")
    .into_inner();
    assert_eq!(grpc_status, status_response_to_proto(embedded_status));
    let grpc_backup = AdminService::create_backup(
        &grpc,
        grpc_domain_request(
            backup_request_to_proto(backup),
            &context,
            "contextdb.v1.AdminService/CreateBackup",
            gateway.as_ref(),
        ),
    )
    .await
    .expect_err("gRPC workspace backup must be unavailable");
    let grpc_backup = contextdb_proto::v1::ErrorStatus::decode(grpc_backup.details())
        .expect("typed gRPC backup error");
    assert_eq!(
        grpc_backup.code,
        contextdb_proto::v1::ErrorCode::Unsupported as i32
    );
}

#[tokio::test]
async fn high_level_conversation_capture_and_recall_match_embedded_http_and_grpc() {
    let embedded = empty_service("high-level-conversation");
    let http_service = empty_service("high-level-conversation");
    let grpc_service = empty_service("high-level-conversation");
    let gateway = Arc::new(
        Blake3GatewayAuthenticator::new("gateway:high-level", DOMAIN_GATEWAY_KEY)
            .expect("gateway verifier"),
    );
    let http = http_router_with_gateway_authenticator(http_service, gateway.clone());
    let grpc = ServerGrpcAdapter::with_gateway_authenticator(grpc_service, 32, gateway.clone());
    let context = authenticated(
        ConformanceFixture::standard().caller,
        &[ServiceCapability::Observe, ServiceCapability::Recall],
    );
    let begin = HighLevelWriteRequest {
        context: context.clone(),
        idempotency_key: "high-level-begin".to_owned(),
        target_subject_id: context.request.subject_id.clone(),
        session_id: context.session_id.clone(),
        logical_id: "session:conformance".to_owned(),
        access: trusted_legacy_observe_policy(),
        payload: serde_json::json!({"channel": "chat"}),
        references: BTreeSet::new(),
    };
    let before = HighLevelQueryRequest {
        context: context.clone(),
        target_subject_id: context.request.subject_id.clone(),
        cue: "Japan bar".to_owned(),
        page_size: 10,
        at_commit: None,
        continuation: None,
    };

    let embedded_begin = embedded
        .begin_session(begin.clone())
        .expect("embedded begin");
    let embedded_before = embedded
        .before_turn(before.clone())
        .expect("embedded before turn");
    let http_begin: HighLevelMutationResponse = http_domain_call(
        &http,
        gateway.as_ref(),
        "/v1/conversation/begin-session",
        &context,
        &begin,
    )
    .await;
    let http_before: RecallResponse = http_domain_call(
        &http,
        gateway.as_ref(),
        "/v1/conversation/before-turn",
        &context,
        &before,
    )
    .await;
    assert_eq!(http_begin, embedded_begin);
    assert_eq!(http_before, embedded_before);

    let grpc_begin = ConversationService::begin_session(
        &grpc,
        grpc_domain_request(
            high_level_write_request_to_proto(begin).expect("begin wire"),
            &context,
            "contextdb.v1.ConversationService/BeginSession",
            gateway.as_ref(),
        ),
    )
    .await
    .expect("gRPC begin")
    .into_inner();
    assert_eq!(
        grpc_begin,
        high_level_mutation_response_to_proto(embedded_begin)
    );
    let grpc_before = ConversationService::before_turn(
        &grpc,
        grpc_domain_request(
            high_level_query_request_to_proto(before),
            &context,
            "contextdb.v1.ConversationService/BeforeTurn",
            gateway.as_ref(),
        ),
    )
    .await
    .expect("gRPC before turn")
    .into_inner();
    assert_eq!(
        grpc_before,
        contextdb_server::recall_response_to_proto(embedded_before)
    );
}

#[tokio::test]
async fn database_global_archive_is_absent_from_every_workspace_interface() {
    let fixture = ConformanceFixture::standard();
    let export = CanonicalOperation::Export(ExportRequest {
        context: fixture.administrator.clone(),
    });
    let mut embedded = EmbeddedAdapter::new(seeded_service("archive-embedded"));
    let mut http = HttpAdapter::new(seeded_service("archive-http"));
    let mut grpc = GrpcAdapter::new(seeded_service("archive-grpc"));
    for adapter in [
        &mut embedded as &mut dyn ConformanceAdapter,
        &mut http,
        &mut grpc,
    ] {
        let error = adapter
            .invoke(export.clone())
            .await
            .expect("adapter invocation")
            .expect_err("workspace export must be unavailable");
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    let mut mcp = McpAdapter::new(seeded_service("archive-mcp"));
    assert!(matches!(
        mcp.manifest()
            .capabilities
            .get(&Capability::PortableArchive),
        Some(Support::NotApplicable { .. })
    ));
    assert!(
        mcp.invoke(export).await.is_err(),
        "MCP archive tool is absent"
    );
}

#[test]
fn host_archive_round_trip_is_exact_and_corruption_leaves_target_unchanged() {
    let fixture = ConformanceFixture::standard();
    let source = ReferenceService::new("host-archive-source", KEY).expect("source");
    source.observe(fixture.visible_a).expect("seed source");
    let authority = HostArchiveAuthority::new(KEY).expect("host authority");
    let archive = source.export_host_archive(&authority).expect("host export");
    let target = ReferenceService::new("host-archive-target", KEY).expect("target");
    let before = target
        .export_host_archive(&authority)
        .expect("empty target");
    let mut corrupted = archive.bytes.clone();
    corrupted[0] ^= 1;
    assert_eq!(
        target
            .import_host_archive(&authority, &archive.format, &corrupted, &archive.digest)
            .expect_err("corrupt import")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(
        target
            .export_host_archive(&authority)
            .expect("unchanged target"),
        before
    );
    let receipt = target
        .import_host_archive(&authority, &archive.format, &archive.bytes, &archive.digest)
        .expect("host import");
    assert_eq!(receipt.commit_seq, archive.commit_seq);
    assert_eq!(
        target
            .export_host_archive(&authority)
            .expect("host re-export"),
        archive
    );
}

#[tokio::test]
async fn http_framework_errors_and_grpc_network_streams_are_typed_and_ordered() {
    let http = prove_http_protocol_errors(empty_service("http-protocol"))
        .await
        .expect("HTTP protocol proof");
    assert!(http.passed(), "{http:?}");

    let stream = prove_grpc_network_streaming(
        seeded_service("grpc-stream"),
        &ConformanceFixture::standard(),
    )
    .await
    .expect("gRPC stream proof");
    assert!(stream.passed(), "{stream:?}");
}

#[test]
fn authenticated_domain_surface_delegates_safe_subset_and_reports_exact_executor_gaps() {
    let service = seeded_service("domain-surface");
    let fixture = ConformanceFixture::standard();
    let context = authenticated(
        fixture.caller.clone(),
        &[
            ServiceCapability::Correct,
            ServiceCapability::Forget,
            ServiceCapability::HardDelete,
            ServiceCapability::ReadMemory,
            ServiceCapability::ReadEvidence,
            ServiceCapability::RawEvidence,
            ServiceCapability::ReadConflict,
            ServiceCapability::Traverse,
            ServiceCapability::Runtime,
            ServiceCapability::Maintenance,
        ],
    );
    let replacement = MemoryDocument {
        id: "semantic:visible-a:v2".to_owned(),
        kind: MemoryRecordKind::SemanticObject,
        access: domain_policy(),
        valid_time: DomainTimeRange::default(),
        lifecycle: MemoryLifecycle::Active,
        links: MemoryLinks {
            supersedes: BTreeSet::from(["semantic:visible-a".to_owned()]),
            ..MemoryLinks::default()
        },
        value: serde_json::json!({"fact": "corrected Japan bar"}),
        search_text: Some("corrected Japan bar".to_owned()),
        vector: None,
        attributes: BTreeMap::new(),
    };
    let corrected = service
        .correct(CorrectRequest {
            context: context.clone(),
            idempotency_key: "correct:conformance".to_owned(),
            target_id: "semantic:visible-a".to_owned(),
            replacement: replacement.clone(),
        })
        .expect("correct delegated");
    assert_eq!(corrected.commit_seq, 2);
    let timeline = service
        .get_timeline(GetTimelineRequest {
            context: context.clone(),
            record_id: replacement.id.clone(),
            expected_kind: MemoryRecordKind::SemanticObject,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("timeline delegated");
    assert_eq!(timeline.revisions[0].document.id, replacement.id);

    for operation in [
        service.get_node(GetMemoryRequest {
            context: context.clone(),
            record_id: replacement.id.clone(),
            at_commit: None,
        }),
        service.get_evidence(GetMemoryRequest {
            context: context.clone(),
            record_id: replacement.id.clone(),
            at_commit: None,
        }),
        service.get_conflict(GetMemoryRequest {
            context: context.clone(),
            record_id: replacement.id.clone(),
            at_commit: None,
        }),
    ] {
        assert_eq!(
            operation.expect_err("wrong typed route").code,
            ErrorCode::PermissionDenied
        );
    }

    let runtime = service
        .bootstrap(contextdb_service::RuntimeRequest {
            context: context.clone(),
            operation_id: "runtime:conformance".to_owned(),
            payload: serde_json::json!({}),
        })
        .expect_err("runtime executor gap");
    assert_eq!(runtime.code, ErrorCode::Unsupported);
    assert!(runtime.message.contains("lifecycle executor"));
    let maintenance = service
        .consolidate(contextdb_service::MaintenanceRequest {
            context: context.clone(),
            operation_id: "maintenance:conformance".to_owned(),
            payload: serde_json::json!({}),
        })
        .expect_err("maintenance executor gap");
    assert_eq!(maintenance.code, ErrorCode::Unsupported);
    assert!(maintenance.message.contains("maintenance executor"));

    let deleted = service
        .forget(ForgetRequest {
            context,
            idempotency_key: "delete:conformance".to_owned(),
            target_id: replacement.id,
            mode: ForgetMode::HardDelete,
            reason: "subject_request".to_owned(),
        })
        .expect("hard delete delegated");
    assert_eq!(deleted.commit_seq, 3);
}

#[test]
fn authenticated_workspace_admin_status_executes_but_global_backup_is_unavailable() {
    let service = seeded_service("admin-surface");
    let fixture = ConformanceFixture::standard();
    let context = authenticated(fixture.administrator, &[ServiceCapability::Admin]);
    let status = service
        .get_status(GetStatusRequest {
            context: context.clone(),
        })
        .expect("status delegated");
    assert_eq!(status.commit_seq, 1);
    assert_eq!(status.capability_manifest.schema_version, 1);
    assert_eq!(status.capability_manifest.profile, status.profile);
    assert!(!status.capability_manifest.server_v1_release_ready);
    assert_eq!(
        status.capability_manifest.capability("status"),
        Some(contextdb_service::CapabilityState::Available)
    );
    assert_eq!(
        status
            .capability_manifest
            .capability("persistent_ann_recall_projection"),
        Some(contextdb_service::CapabilityState::Unsupported)
    );
    for capability in contextdb_proto::CANDIDATE_RUNTIME_CAPABILITY_IDS_V1 {
        assert!(
            contextdb_service::SERVICE_CAPABILITY_IDS_V1.contains(&capability),
            "service vocabulary omits canonical candidate capability {capability}"
        );
        assert_eq!(
            status.capability_manifest.capability(capability),
            Some(contextdb_service::CapabilityState::Unsupported),
            "reference service must not advertise native-only {capability}"
        );
    }
    let backup = service
        .create_backup(CreateBackupRequest { context })
        .expect_err("workspace backup must not materialize global state");
    assert_eq!(backup.code, ErrorCode::Unsupported);
    assert_eq!(
        backup.violated_policy.as_deref(),
        Some("authority:host-global")
    );
}

#[test]
fn mcp_r19_keeps_strict_stateless_metadata_and_supports_standard_initialize() {
    let mut adapter = McpAdapter::new(empty_service("mcp-r19"));
    let proof = adapter.prove_r19();
    assert!(proof.passed(), "{proof:?}");
}

#[tokio::test]
async fn extended_error_details_survive_every_general_purpose_adapter() {
    let expected = ServiceError::new(ErrorCode::ConflictUnresolved, "safe conflict", false)
        .with_context(
            vec!["claim:partial".to_owned()],
            Some("policy:resolve-conflict".to_owned()),
            Some("request explicit perspective".to_owned()),
            Some("trace:safe".to_owned()),
        );
    let fixture = ConformanceFixture::standard();
    let operation = CanonicalOperation::Recall(fixture.recall(1));

    let mut embedded = EmbeddedAdapter::new(Arc::new(AlwaysError(expected.clone())));
    let mut http = HttpAdapter::new(Arc::new(AlwaysError(expected.clone())));
    let mut grpc = GrpcAdapter::new(Arc::new(AlwaysError(expected.clone())));
    let mut mcp = mcp_adapter(
        Arc::new(AlwaysError(expected.clone())),
        fixture.caller.clone(),
        &[ServiceCapability::Recall],
    );

    for adapter in [
        &mut embedded as &mut dyn ConformanceAdapter,
        &mut http,
        &mut grpc,
    ] {
        let actual = adapter
            .invoke(operation.clone())
            .await
            .expect("adapter invocation")
            .expect_err("canonical error");
        assert_eq!(actual, expected.clone().into());
    }
    let mcp_error = mcp
        .invoke(operation)
        .await
        .expect("MCP invocation")
        .expect_err("MCP tool error");
    assert_eq!(mcp_error, expected.into());
    assert!(matches!(
        mcp.manifest()
            .capabilities
            .get(&Capability::ExtendedErrorDetails),
        Some(Support::Exercised)
    ));
}

#[tokio::test]
async fn every_stable_error_code_survives_all_general_purpose_adapters() {
    let fixture = ConformanceFixture::standard();
    let operation = CanonicalOperation::Recall(fixture.recall(1));
    for code in ERROR_CODES {
        let retryable = matches!(
            code,
            ErrorCode::Unavailable | ErrorCode::ProviderUnavailable | ErrorCode::IndexTooStale
        );
        let expected = ServiceError::new(code, "safe error", retryable);
        let mut embedded = EmbeddedAdapter::new(Arc::new(AlwaysError(expected.clone())));
        let mut http = HttpAdapter::new(Arc::new(AlwaysError(expected.clone())));
        let mut grpc = GrpcAdapter::new(Arc::new(AlwaysError(expected.clone())));
        let mut mcp = mcp_adapter(
            Arc::new(AlwaysError(expected.clone())),
            fixture.caller.clone(),
            &[ServiceCapability::Recall],
        );
        for adapter in [
            &mut embedded as &mut dyn ConformanceAdapter,
            &mut http,
            &mut grpc,
            &mut mcp,
        ] {
            let actual = adapter
                .invoke(operation.clone())
                .await
                .expect("adapter invocation")
                .expect_err("canonical error");
            assert_eq!(actual, expected.clone().into(), "{code:?}");
        }
    }
}

#[test]
fn cli_binary_absence_is_explicit_and_never_a_synthetic_pass() {
    let directory = tempfile::tempdir().expect("temporary directory");
    if let Some(mut adapter) = CliProcessAdapter::from_env(
        directory.path().join("state.cdb"),
        directory.path().join("scratch"),
    )
    .expect("CLI environment")
    {
        assert!(
            adapter.initialize(true).is_err(),
            "anchored CLI conformance must never force-replace state"
        );
        let fixture = ConformanceFixture::standard();
        let source = seeded_service("cli-conformance-seed");
        let archive = source
            .export_host_archive(&HostArchiveAuthority::new(KEY).expect("host authority"))
            .expect("seed archive");
        adapter
            .install_archive(&archive.bytes)
            .expect("CLI archive installation");
        let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
        let report = runtime
            .block_on(run_conformance_suite(&mut adapter, &fixture))
            .expect("CLI conformance report");
        assert!(report.semantic_checks_passed(), "{report:#?}");
        assert!(!report.strictly_passed(), "{report:#?}");
        let mut target = CliProcessAdapter::from_env(
            directory.path().join("target-state.cdb"),
            directory.path().join("target-scratch"),
        )
        .expect("target CLI environment")
        .expect("target CLI executable");
        assert!(
            runtime
                .block_on(run_archive_round_trip(
                    &mut adapter,
                    &mut target,
                    &fixture.administrator,
                ))
                .expect("CLI archive round trip")
        );
        let proof = adapter
            .prove_external_surface()
            .expect("CLI external proof");
        assert!(proof.passed(), "{proof:?}");
        adapter
            .cleanup_authority()
            .expect("source CLI authority cleanup");
        target
            .cleanup_authority()
            .expect("target CLI authority cleanup");

        let initialized = CliProcessAdapter::from_env(
            directory.path().join("initialized-state.cdb"),
            directory.path().join("initialized-scratch"),
        )
        .expect("initialized CLI environment")
        .expect("initialized CLI executable");
        initialized
            .initialize(false)
            .expect("fresh anchored CLI initialization");
        initialized
            .cleanup_authority()
            .expect("initialized CLI authority cleanup");

        let mut corrupt = archive.bytes;
        corrupt[0] ^= 0x01;
        let mut rejected_target = CliProcessAdapter::from_env(
            directory.path().join("rejected-state.cdb"),
            directory.path().join("rejected-scratch"),
        )
        .expect("rejected target CLI environment")
        .expect("rejected target CLI executable");
        assert!(rejected_target.install_archive(&corrupt).is_err());
        rejected_target
            .initialize(false)
            .expect("failed clone import left target empty and unanchored");
        rejected_target
            .cleanup_authority()
            .expect("rejected target CLI authority cleanup");
    } else {
        let manifest = crate::cli_manifest(false);
        assert!(matches!(
            manifest.capabilities.get(&Capability::ObserveUnary),
            Some(Support::ExternalProofRequired { .. })
        ));
        assert!(!manifest.is_strictly_satisfied());
    }
}

#[test]
fn released_schema_golden_is_exact_and_additive_comparison_is_directional() {
    let current = current_schema_manifest().expect("current schema");
    let baseline: SchemaManifest = parse_proto_schema(include_str!(
        "../tests/fixtures/contextdb_v1_released.proto"
    ))
    .expect("released schema fixture");
    let compatibility = compare_schema_compatibility(&baseline, &current);
    assert!(
        compatibility.compatible,
        "current schema must preserve every released v1 identity: {compatibility:?}"
    );
    assert!(
        compatibility.additive_items > 0,
        "RFC 21.22-21.25 surfaces are an explicit additive evolution"
    );

    let additive = parse_proto_schema(
        "syntax = \"proto3\";\npackage p;\nmessage A {\n string id = 1;\n optional string note = 2;\n}\n",
    )
    .expect("additive schema");
    let original =
        parse_proto_schema("syntax = \"proto3\";\npackage p;\nmessage A {\n string id = 1;\n}\n")
            .expect("original schema");
    let report = compare_schema_compatibility(&original, &additive);
    assert!(report.compatible);
    assert_eq!(report.additive_items, 1);
    let reverse = compare_schema_compatibility(&additive, &original);
    assert!(!reverse.compatible);
}

#[test]
fn high_level_surface_fixture_matches_the_additive_proto_services() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        compatibility: String,
        baseline: String,
        authentication: String,
        http_routes: BTreeMap<String, HttpRoute>,
        services: BTreeMap<String, Vec<String>>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HttpRoute {
        operation: String,
        request: String,
        response: String,
        capabilities: Vec<String>,
        reference_semantics: String,
    }

    let fixture: Fixture =
        serde_json::from_str(include_str!("../tests/fixtures/high_level_v1_surface.json"))
            .expect("high-level surface fixture");
    assert_eq!(fixture.compatibility, "additive");
    assert_eq!(fixture.baseline, "contextdb_v1_released.proto");
    assert_eq!(
        fixture.authentication,
        "full_authenticated_request_context_gateway_before_content"
    );
    assert_eq!(fixture.http_routes.len(), 29);
    let route_operations = fixture
        .http_routes
        .iter()
        .map(|(path, route)| {
            assert!(path.starts_with("/v1/"));
            assert!(
                matches!(
                    route.request.as_str(),
                    "high_level_write"
                        | "high_level_query"
                        | "high_level_control"
                        | "high_level_transfer"
                ),
                "unknown request mapping for {path}"
            );
            assert!(
                matches!(
                    route.response.as_str(),
                    "high_level_mutation" | "recall" | "mutation" | "export" | "import"
                ),
                "unknown response mapping for {path}"
            );
            assert!(!route.capabilities.is_empty());
            assert!(route.capabilities.iter().all(|capability| matches!(
                capability.as_str(),
                "observe"
                    | "recall"
                    | "correct"
                    | "read_memory"
                    | "runtime"
                    | "forget"
                    | "hard_delete"
                    | "admin"
            )));
            assert!(matches!(
                route.reference_semantics.as_str(),
                "durable_capture_pending"
                    | "bounded_recall"
                    | "atomic_policy_revision"
                    | "unsupported"
            ));
            route.operation.clone()
        })
        .collect::<BTreeSet<_>>();
    let service_operations = fixture
        .services
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(route_operations, service_operations);
    let current = current_schema_manifest().expect("current schema");
    let baseline = parse_proto_schema(include_str!(
        "../tests/fixtures/contextdb_v1_released.proto"
    ))
    .expect("released baseline");
    let compatibility = compare_schema_compatibility(&baseline, &current);
    assert!(compatibility.compatible);
    assert!(compatibility.additive_items > 0);

    for (service, expected_methods) in fixture.services {
        let actual = current
            .services
            .get(&service)
            .unwrap_or_else(|| panic!("missing additive service {service}"));
        assert_eq!(
            actual.keys().cloned().collect::<Vec<_>>(),
            expected_methods,
            "method surface drifted for {service}"
        );
        for signature in actual.values() {
            assert!(!signature.client_streaming);
            assert!(!signature.server_streaming);
            assert!(signature.request.starts_with("HighLevel"));
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_new_field_numbers_are_additive(number in 2_u32..536_870_911_u32) {
        let baseline = parse_proto_schema(
            "syntax = \"proto3\";\npackage p;\nmessage A {\n string id = 1;\n}\n",
        ).expect("baseline");
        let candidate = parse_proto_schema(&format!(
            "syntax = \"proto3\";\npackage p;\nmessage A {{\n string id = 1;\n optional bytes extension = {number};\n}}\n"
        )).expect("candidate");
        prop_assert!(compare_schema_compatibility(&baseline, &candidate).compatible);
    }

    #[test]
    fn renaming_a_released_field_is_always_rejected(name in "[a-z]{1,16}") {
        prop_assume!(name != "id");
        let baseline = parse_proto_schema(
            "syntax = \"proto3\";\npackage p;\nmessage A {\n string id = 1;\n}\n",
        ).expect("baseline");
        let candidate = parse_proto_schema(&format!(
            "syntax = \"proto3\";\npackage p;\nmessage A {{\n string {name} = 1;\n}}\n"
        )).expect("candidate");
        prop_assert!(!compare_schema_compatibility(&baseline, &candidate).compatible);
    }
}

#[derive(Clone, Debug)]
struct AlwaysError(ServiceError);

impl CognitiveMemoryService for AlwaysError {
    fn observe(&self, _request: ObserveRequest) -> ServiceResult<ObserveResponse> {
        Err(self.0.clone())
    }

    fn recall(&self, _request: RecallRequest) -> ServiceResult<RecallResponse> {
        Err(self.0.clone())
    }

    fn explain_recall(&self, _request: ExplainRecallRequest) -> ServiceResult<RecallTrace> {
        Err(self.0.clone())
    }

    fn export_archive(
        &self,
        _request: ExportRequest,
    ) -> ServiceResult<contextdb_service::ExportResponse> {
        Err(self.0.clone())
    }

    fn import_archive(
        &self,
        _request: ImportRequest,
    ) -> ServiceResult<contextdb_service::ImportResponse> {
        Err(self.0.clone())
    }

    fn verify(&self, _request: VerifyRequest) -> ServiceResult<VerifyResponse> {
        Err(self.0.clone())
    }
}
