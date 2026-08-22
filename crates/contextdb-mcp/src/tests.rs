use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::Arc;

use contextdb_native_service::NativeService;
use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, AuthenticationEvidence, Capability,
    CognitiveMemoryService, Consent, ErrorCode, ObserveRequest, ObserveResponse,
    PublishMemoryRequest, RecallRequest, RecallResponse, ReferenceService, RequestContext,
    RuntimeRequest, Sensitivity, ServiceError, ServiceResult,
};

use crate::{JsonRpcRequest, McpServer, serve_stdio};

fn authorized_server(service: Arc<dyn CognitiveMemoryService>, grants: &[Capability]) -> McpServer {
    McpServer::with_fixed_session_authority(service, authenticated("host:session", grants))
        .expect("fixed host session authority")
}

fn meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": crate::MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

fn request(id: i64, method: &str, mut params: serde_json::Value) -> JsonRpcRequest {
    params
        .as_object_mut()
        .expect("object parameters")
        .insert("_meta".into(), meta());
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(id),
        method: method.into(),
        params: Some(params),
    }
}

fn context(request_id: &str) -> RequestContext {
    RequestContext {
        request_id: request_id.into(),
        workspace_id: "workspace:mcp".into(),
        subject_id: "subject:alice".into(),
        audiences: BTreeSet::from(["subject:alice".into()]),
        scopes: BTreeSet::from(["project:mcp".into()]),
        purpose: "conversation".into(),
        clearance: Sensitivity::Private,
    }
}

fn observation() -> ObserveRequest {
    ObserveRequest {
        context: context("request:observe"),
        idempotency_key: "idempotency:mcp".into(),
        observation_id: "observation:mcp".into(),
        metadata: BTreeMap::new(),
        content: serde_json::json!({"text": "Japan bar served yuzu tea"}),
        access: AccessPolicy {
            workspace_id: "workspace:mcp".into(),
            scopes: BTreeSet::from(["project:mcp".into()]),
            owners: BTreeSet::from(["subject:alice".into()]),
            audience: BTreeSet::from(["subject:alice".into()]),
            audience_purpose_grants: BTreeMap::new(),
            purposes: BTreeSet::from(["conversation".into()]),
            sensitivity: Sensitivity::Private,
            consent: Consent::Granted,
            retrievable: true,
        },
    }
}

fn authenticated(request_id: &str, capabilities: &[Capability]) -> AuthenticatedRequestContext {
    AuthenticatedRequestContext {
        request: context(request_id),
        actor_id: "actor:alice".into(),
        agent_id: "agent:test".into(),
        session_id: Some("session:mcp".into()),
        capability_grants: capabilities.iter().copied().collect(),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "channel:test".into(),
            peer_identity: "actor:alice".into(),
            binding_digest: "11".repeat(32),
        },
    }
}

fn call(name: &str, arguments: serde_json::Value, id: i64) -> JsonRpcRequest {
    request(
        id,
        "tools/call",
        serde_json::json!({"name": name, "arguments": arguments}),
    )
}

#[test]
fn stateless_discovery_tools_and_authenticated_trace_resource_conform() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("mcp-test", [11; 32]).expect("reference service"));
    let mut server = authorized_server(
        Arc::clone(&service),
        &[Capability::Observe, Capability::Recall],
    );

    let missing_meta = server.handle(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(1),
        method: "tools/list".into(),
        params: Some(serde_json::json!({})),
    });
    assert_eq!(missing_meta.error.expect("error").code, -32602);
    let discover = server.handle(request(2, "server/discover", serde_json::json!({})));
    let discovered = discover.result.expect("discover result");
    assert_eq!(
        discovered["supportedVersions"][0],
        crate::MCP_PROTOCOL_VERSION
    );
    assert_eq!(discovered["resultType"], "complete");
    assert_eq!(discovered["cacheScope"], "public");
    assert!(discovered["_meta"]["io.modelcontextprotocol/serverInfo"].is_object());

    let tools = server
        .handle(request(3, "tools/list", serde_json::json!({})))
        .result
        .expect("tools result");
    assert_eq!(tools["tools"].as_array().map(Vec::len), Some(16));
    assert_eq!(tools["ttlMs"], 300_000);
    assert_eq!(tools["tools"][0]["name"], "contextdb_session");
    assert_eq!(
        tools["tools"][0]["inputSchema"]["additionalProperties"],
        false
    );

    let session = server
        .handle(call("contextdb_session", serde_json::json!({}), 30))
        .result
        .expect("fixed session result");
    assert_eq!(session["isError"], false);
    assert_eq!(
        session["structuredContent"]["context_template"]["workspace_id"],
        "workspace:mcp"
    );
    assert_eq!(
        session["structuredContent"]["context_template"]["request_id"],
        "host:session"
    );
    assert_eq!(session["structuredContent"]["actor_id"], "actor:alice");
    assert_eq!(session["structuredContent"]["agent_id"], "agent:test");
    assert_eq!(
        session["structuredContent"]["context_plan_template"]["model_profile"]["renderer"],
        "coding"
    );
    assert_eq!(
        session["structuredContent"]["context_plan_template"]["model_profile"]["preferred_structured_format"],
        "markdown"
    );
    assert_eq!(
        session["structuredContent"]["context_plan_template"]["model_profile"]["external_processing"],
        true
    );
    assert!(session["structuredContent"].get("authentication").is_none());
    assert!(
        session["structuredContent"]["capabilities"]
            .as_array()
            .is_some_and(|capabilities| capabilities.iter().any(|value| value == "recall"))
    );

    let observed = server
        .handle(call(
            "contextdb_observe",
            serde_json::to_value(observation()).expect("request JSON"),
            4,
        ))
        .result
        .expect("observe result");
    assert_eq!(observed["isError"], false);

    let recall = RecallRequest {
        context: context("request:recall"),
        query: "yuzu Japan".into(),
        page_size: 10,
        at_commit: None,
        continuation: None,
    };
    let recalled = server
        .handle(call(
            "contextdb_recall",
            serde_json::to_value(recall).expect("request JSON"),
            5,
        ))
        .result
        .expect("recall result");
    assert_eq!(recalled["isError"], false);
    assert_eq!(recalled["resultType"], "complete");
    let trace_id = recalled["structuredContent"]["trace"]["trace_id"]
        .as_str()
        .expect("trace ID");
    let uri = format!("contextdb://recall/{trace_id}/trace");

    let resource = server.handle(request(
        6,
        "resources/read",
        serde_json::json!({"uri": uri}),
    ));
    assert!(resource.error.is_none());
    let resource = resource.result.expect("resource result");
    assert_eq!(resource["contents"][0]["mimeType"], "application/json");
    assert_eq!(resource["ttlMs"], 0);
    assert_eq!(resource["cacheScope"], "private");

    let mut fresh_adapter = McpServer::new(service);
    let unavailable = fresh_adapter
        .handle(call("contextdb_session", serde_json::json!({}), 7))
        .result
        .expect("typed session result");
    assert_eq!(unavailable["isError"], true);
    assert_eq!(unavailable["structuredContent"]["code"], "unsupported");
    let denied = fresh_adapter.handle(request(
        8,
        "resources/read",
        serde_json::json!({"uri": uri}),
    ));
    assert_eq!(denied.error.expect("not found").code, -32602);
}

#[test]
fn legacy_assist_authority_gets_a_conversation_plan_without_partition_drift() {
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        ReferenceService::new("mcp-legacy-assist", [0x31; 32]).expect("reference service"),
    );
    let mut authority = authenticated("host:legacy-assist", &[Capability::Recall]);
    authority.request.purpose = "assist".to_owned();
    let mut server = McpServer::with_fixed_session_authority(service, authority)
        .expect("legacy assist host authority");

    let session = server
        .handle(call("contextdb_session", serde_json::json!({}), 31))
        .result
        .expect("session result");
    assert_eq!(
        session["structuredContent"]["context_template"]["purpose"],
        "assist"
    );
    assert_eq!(
        session["structuredContent"]["context_plan_template"]["purpose"],
        "conversation"
    );
    assert_eq!(
        session["structuredContent"]["context_plan_template"]["model_profile"]["external_processing"],
        true
    );
}

#[test]
fn native_candidate_hierarchy_and_session_context_template_flow() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        NativeService::open(directory.path(), "mcp-native-hierarchy", [0x6a; 32])
            .expect("native service"),
    );
    let mut server = authorized_server(
        service,
        &[
            Capability::Observe,
            Capability::ReadMemory,
            Capability::Recall,
            Capability::Traverse,
            Capability::ModelProcessing,
        ],
    );

    let session = server
        .handle(call("contextdb_session", serde_json::json!({}), 100))
        .result
        .expect("session result");
    let mut plan = session["structuredContent"]["context_plan_template"].clone();
    plan["pack_id"] = serde_json::json!("00000000-0000-4000-8000-000000000101");
    plan["query"] = serde_json::json!("durable MCP hierarchy decision");
    plan["now_micros"] = serde_json::json!(1_900_000_000_000_000_i64);

    let root = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("structured-root"),
                "identity_key": "project|repo=d:/develop/contextdb-mcp-test",
                "semantic_kind": "project",
                "value": {"text": "durable MCP project root"},
                "search_text": "durable MCP project root",
                "parent_candidate_ids": [],
                "supersedes_candidate_ids": []
            }),
            101,
        ))
        .result
        .expect("root result");
    assert_eq!(root["isError"], false);
    assert_eq!(
        root["structuredContent"]["candidate_edge_ids"],
        serde_json::json!([])
    );
    assert_eq!(root["structuredContent"]["proposal_state"], "quarantined");
    assert_eq!(root["structuredContent"]["canonical"], false);
    let root_id = root["structuredContent"]["candidate_id"]
        .as_str()
        .expect("root candidate ID")
        .to_owned();

    let topic = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("structured-topic"),
                "identity_key": format!("topic|project={root_id}|key=durable-hierarchy"),
                "semantic_kind": "topic",
                "value": {"text": "durable MCP hierarchy topic"},
                "search_text": "durable MCP hierarchy topic",
                "parent_candidate_ids": [root_id.clone()],
                "supersedes_candidate_ids": []
            }),
            102,
        ))
        .result
        .expect("topic result");
    assert_eq!(topic["isError"], false, "{topic:#}");
    let topic_id = topic["structuredContent"]["candidate_id"]
        .as_str()
        .expect("topic candidate ID")
        .to_owned();

    let mut decision_parents = vec![root_id.clone(), topic_id.clone()];
    decision_parents.sort();
    let child = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("structured-child"),
                "identity_key": format!(
                    "memory|kind=decision|parents={}|subject=durable-hierarchy|revision=00000001",
                    decision_parents.join(",")
                ),
                "semantic_kind": "decision",
                "value": {"text": "durable MCP hierarchy decision"},
                "search_text": "durable MCP hierarchy decision",
                "parent_candidate_ids": decision_parents,
                "supersedes_candidate_ids": []
            }),
            103,
        ))
        .result
        .expect("child result");
    assert_eq!(child["isError"], false);
    assert_eq!(child["structuredContent"]["proposal_state"], "quarantined");
    assert_eq!(child["structuredContent"]["canonical"], false);
    assert_eq!(
        child["structuredContent"]["candidate_edge_ids"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let child_id = child["structuredContent"]["candidate_id"]
        .as_str()
        .expect("child candidate ID")
        .to_owned();

    let traversed = server
        .handle(call(
            "contextdb_traverse_candidates",
            serde_json::json!({
                "context": context("traverse-hierarchy"),
                "start_ids": [root_id.clone()],
                "direction": "outgoing",
                "predicate_ids": ["contextdb.candidate_hierarchy.parent"],
                "max_hops": 2,
                "max_nodes": 16,
                "at_commit": null
            }),
            104,
        ))
        .result
        .expect("traverse result");
    assert_eq!(traversed["isError"], false);
    let traversed_ids = traversed["structuredContent"]["node_ids"]
        .as_array()
        .expect("traversed node IDs")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        traversed_ids,
        BTreeSet::from([root_id.as_str(), topic_id.as_str(), child_id.as_str()])
    );

    let recalled = server
        .handle(call(
            "contextdb_recall_candidates",
            serde_json::json!({
                "context": context("recall-candidates"),
                "query": "durable hierarchy decision",
                "semantic_kinds": ["decision"],
                "page_size": 10,
                "at_commit": null
            }),
            105,
        ))
        .result
        .expect("candidate recall result");
    assert_eq!(recalled["isError"], false);
    assert_eq!(
        recalled["structuredContent"]["hits"][0]["candidate_id"],
        child_id
    );

    let materialized = server
        .handle(call(
            "contextdb_get_candidate",
            serde_json::json!({
                "context": context("get-candidate"),
                "record_id": child_id,
                "at_commit": null
            }),
            106,
        ))
        .result
        .expect("candidate materialization result");
    assert_eq!(materialized["isError"], false);
    assert_eq!(
        materialized["structuredContent"]["document"]["attributes"]["contextdb.proposal.state"],
        "quarantined"
    );

    let compiled = server
        .handle(call(
            "contextdb_context",
            serde_json::json!({
                "context": context("compile-template"),
                "plan": plan
            }),
            107,
        ))
        .result
        .expect("context result");
    assert_eq!(compiled["isError"], false, "{compiled:#}");
    assert_eq!(
        compiled["structuredContent"]["rendered"]["renderer"],
        "coding"
    );
    assert_eq!(
        compiled["structuredContent"]["canonical_digest_algorithm"],
        "blake3-256"
    );
    assert!(
        !serde_json::to_string(&compiled["structuredContent"])
            .expect("compiled ContextPack JSON")
            .contains("durable MCP hierarchy decision"),
        "quarantined candidates must never enter ordinary ContextPack output"
    );
}

#[test]
fn candidate_identity_host_rejects_live_malformed_shapes_and_parent_role_mismatch() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        NativeService::open(directory.path(), "mcp-candidate-contract", [0x2d; 32])
            .expect("native service"),
    );
    let mut server = authorized_server(service, &[Capability::Observe, Capability::ReadMemory]);

    for (index, identity_key, semantic_kind) in [
        (201, "project:contextdb", "project"),
        (202, "topic:contextdb:automatic-memory", "topic"),
        (203, "decision:automatic-memory", "decision"),
    ] {
        let rejected = server
            .handle(call(
                "contextdb_ensure_candidate",
                serde_json::json!({
                    "context": context(&format!("malformed-candidate-{index}")),
                    "identity_key": identity_key,
                    "semantic_kind": semantic_kind,
                    "value": {"summary": "must not persist"},
                    "search_text": "must not persist",
                    "parent_candidate_ids": [],
                    "supersedes_candidate_ids": []
                }),
                index,
            ))
            .result
            .expect("malformed contract result");
        assert_eq!(rejected["isError"], true, "{rejected:#}");
        assert_eq!(
            rejected["structuredContent"]["code"], "invalid_argument",
            "{rejected:#}"
        );
        assert_eq!(
            rejected["structuredContent"]["partial_result_refs"],
            serde_json::json!([]),
            "contract failures must not disclose candidate existence"
        );
    }

    let project = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("contract-project"),
                "identity_key": "project|repo=d:/develop/contextdb-contract-test",
                "semantic_kind": "project",
                "value": {"summary": "contract project"},
                "search_text": "contract project",
                "parent_candidate_ids": [],
                "supersedes_candidate_ids": []
            }),
            204,
        ))
        .result
        .expect("project result");
    assert_eq!(project["isError"], false, "{project:#}");
    let project_id = project["structuredContent"]["candidate_id"]
        .as_str()
        .expect("project ID")
        .to_owned();

    let topic = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("contract-topic"),
                "identity_key": format!("topic|project={project_id}|key=host-contract"),
                "semantic_kind": "topic",
                "value": {"summary": "contract topic"},
                "search_text": "contract topic",
                "parent_candidate_ids": [project_id.clone()],
                "supersedes_candidate_ids": []
            }),
            205,
        ))
        .result
        .expect("topic result");
    assert_eq!(topic["isError"], false, "{topic:#}");
    let topic_id = topic["structuredContent"]["candidate_id"]
        .as_str()
        .expect("topic ID")
        .to_owned();

    let wrong_topic_parent = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("contract-topic-role-mismatch"),
                "identity_key": format!("topic|project={topic_id}|key=wrong-parent-role"),
                "semantic_kind": "topic",
                "value": {"summary": "must not persist"},
                "search_text": "must not persist",
                "parent_candidate_ids": [topic_id.clone()],
                "supersedes_candidate_ids": []
            }),
            206,
        ))
        .result
        .expect("topic role mismatch result");
    assert_eq!(
        wrong_topic_parent["isError"], true,
        "{wrong_topic_parent:#}"
    );
    assert_eq!(
        wrong_topic_parent["structuredContent"]["code"],
        "invalid_argument"
    );
    assert_eq!(
        wrong_topic_parent["structuredContent"]["message"],
        "candidate hierarchy does not match the active authorized Candidate identity v1 parent-role contract"
    );
    assert_eq!(
        wrong_topic_parent["structuredContent"]["partial_result_refs"],
        serde_json::json!([])
    );

    let mut decision_parents = vec![project_id, topic_id];
    decision_parents.sort();
    let decision = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("contract-decision"),
                "identity_key": format!(
                    "memory|kind=decision|parents={}|subject=host-contract|revision=00000001",
                    decision_parents.join(",")
                ),
                "semantic_kind": "decision",
                "value": {"summary": "accepted multi-parent decision"},
                "search_text": "accepted multi-parent decision",
                "parent_candidate_ids": decision_parents,
                "supersedes_candidate_ids": []
            }),
            207,
        ))
        .result
        .expect("decision result");
    assert_eq!(decision["isError"], false, "{decision:#}");
    assert_eq!(
        decision["structuredContent"]["candidate_edge_ids"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let decision_id = decision["structuredContent"]["candidate_id"]
        .as_str()
        .expect("decision ID")
        .to_owned();

    let unanchored = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("contract-unanchored-fact"),
                "identity_key": format!(
                    "memory|kind=fact|parents={decision_id}|subject=unanchored-fact|revision=00000001"
                ),
                "semantic_kind": "fact",
                "value": {"summary": "must not persist"},
                "search_text": "must not persist",
                "parent_candidate_ids": [decision_id],
                "supersedes_candidate_ids": []
            }),
            208,
        ))
        .result
        .expect("unanchored role result");
    assert_eq!(unanchored["isError"], true, "{unanchored:#}");
    assert_eq!(unanchored["structuredContent"]["code"], "invalid_argument");
    assert_eq!(
        unanchored["structuredContent"]["message"],
        wrong_topic_parent["structuredContent"]["message"],
        "role failures must use one non-oracular error"
    );
}

#[test]
fn deterministic_candidate_ensure_deduplicates_across_fresh_sessions_without_overwrite() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        NativeService::open(directory.path(), "mcp-native-identity", [0x73; 32])
            .expect("native service"),
    );
    let grants = [Capability::Observe, Capability::ReadMemory];
    let mut first = authorized_server(Arc::clone(&service), &grants);
    let created = first
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("ensure-first"),
                "identity_key": "  PROJECT|REPO=D:/Develop/ＣＯＮＴＥＸＴＤＢ \n",
                "semantic_kind": "project",
                "value": {"summary": "first durable project anchor"},
                "search_text": "first durable project anchor",
                "parent_candidate_ids": []
            }),
            107,
        ))
        .result
        .expect("created ensure result");
    assert_eq!(created["isError"], false, "{created:#}");
    assert_eq!(created["structuredContent"]["outcome"], "created");
    assert_eq!(created["structuredContent"]["created"], true);
    assert_eq!(created["structuredContent"]["input_applied"], true);
    assert_eq!(created["structuredContent"]["canonical"], false);
    assert_eq!(
        created["structuredContent"]["identity_contract"],
        "contextdb.candidate_identity.nfkc_lower_whitespace.v1"
    );
    let candidate_id = created["structuredContent"]["candidate_id"]
        .as_str()
        .expect("candidate ID")
        .to_owned();
    drop(first);

    let mut second_authority = authenticated("host:session-2", &grants);
    second_authority.session_id = Some("session:mcp-second-process".to_owned());
    let mut second = McpServer::with_fixed_session_authority(service, second_authority)
        .expect("fresh fixed authority");
    let reused = second
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("ensure-second"),
                "identity_key": "project|repo=d:/develop/contextdb",
                "semantic_kind": "project",
                "value": {"summary": "attempted overwrite must be ignored"},
                "search_text": "attempted overwrite must be ignored",
                "parent_candidate_ids": [],
                "supersedes_candidate_ids": []
            }),
            108,
        ))
        .result
        .expect("reused ensure result");
    assert_eq!(reused["isError"], false, "{reused:#}");
    assert_eq!(reused["structuredContent"]["outcome"], "existing_candidate");
    assert_eq!(reused["structuredContent"]["created"], false);
    assert_eq!(reused["structuredContent"]["input_applied"], false);
    assert_eq!(reused["structuredContent"]["candidate_id"], candidate_id);
    assert_eq!(
        reused["structuredContent"]["materialize_before_change"],
        true
    );
    assert!(reused["structuredContent"]["mutation"].is_null());

    let materialized = second
        .handle(call(
            "contextdb_get_candidate",
            serde_json::json!({
                "context": context("ensure-materialize"),
                "record_id": candidate_id,
                "at_commit": null
            }),
            109,
        ))
        .result
        .expect("materialized ensure result");
    assert_eq!(materialized["isError"], false, "{materialized:#}");
    assert_eq!(
        materialized["structuredContent"]["document"]["value"]["summary"],
        "first durable project anchor"
    );
}

#[test]
fn model_has_no_direct_canonical_write_or_model_chosen_candidate_identity_route() {
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        ReferenceService::new("mcp-explicit-memory", [0x5a; 32]).expect("reference service"),
    );
    let mut server = authorized_server(service, &[Capability::Observe, Capability::Correct]);
    for (index, forbidden) in [
        "contextdb_remember",
        "contextdb_remember_structured",
        "contextdb_propose_memory",
        "contextdb_correct",
    ]
    .into_iter()
    .enumerate()
    {
        let response = server.handle(call(
            forbidden,
            serde_json::json!({"context": context("forbidden-canonical-write")}),
            10 + i64::try_from(index).expect("small index"),
        ));
        assert_eq!(response.error.expect("unknown tool").code, -32602);
    }
}

#[test]
fn context_tool_compiles_one_policy_bound_model_ready_pack() {
    let service =
        Arc::new(ReferenceService::new("mcp-context-pack", [0x6d; 32]).expect("reference service"));
    service
        .publish_memory(PublishMemoryRequest {
            context: authenticated(
                "host:publish-context-pack",
                &[Capability::Observe, Capability::Correct],
            ),
            idempotency_key: "idempotency:context-pack".into(),
            memory_id: "memory:context-pack".into(),
            value: serde_json::json!({"text": "The local launch word is espresso"}),
            search_text: "local launch word espresso".into(),
        })
        .expect("trusted host publishes canonical test fixture");
    let mut authority = authenticated("host:context-pack", &[Capability::Recall]);
    authority.request.purpose = "conversation".to_owned();
    let mut server = McpServer::with_fixed_session_authority(service, authority)
        .expect("fixed ContextPack authority");

    let mut compile_context = context("request:context-compile");
    compile_context.purpose = "conversation".to_owned();
    let compiled = server
        .handle(call(
            "contextdb_context",
            serde_json::json!({
                "context": compile_context,
                "plan": {
                    "pack_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "query": "What is the local launch word?",
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
                        "id": "model:mcp-local",
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
            }),
            16,
        ))
        .result
        .expect("ContextPack result");
    assert_eq!(compiled["isError"], false, "{compiled:#}");
    assert_eq!(
        compiled["structuredContent"]["trace"]["snapshot"],
        compiled["structuredContent"]["context_pack"]["snapshot"]
    );
    assert_eq!(
        compiled["structuredContent"]["trace"]["filter_digest"],
        compiled["structuredContent"]["context_pack"]["scope_manifest"]["filter_digest"]
    );
    assert!(
        compiled["structuredContent"]["rendered"]["untrusted_data"]
            .as_str()
            .is_some_and(|text| text.contains("espresso"))
    );
    assert!(compiled["structuredContent"]["canonical_digest"].is_string());
    assert_eq!(
        compiled["structuredContent"]["canonical_encoding"],
        "contextdb.context_pack.protobuf.v1"
    );
    assert_eq!(
        compiled["structuredContent"]["canonical_digest_algorithm"],
        "blake3-256"
    );
    assert!(compiled["structuredContent"]["canonical_bytes"].is_array());
}

#[test]
fn model_facing_tools_are_discoverable_strict_and_fail_closed() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("mcp-v1-tools", [14; 32]).expect("reference service"));
    let mut server = authorized_server(
        Arc::clone(&service),
        &[
            Capability::Runtime,
            Capability::Observe,
            Capability::Recall,
            Capability::ReadMemory,
            Capability::Traverse,
        ],
    );
    let listed = server
        .handle(request(20, "tools/list", serde_json::json!({})))
        .result
        .expect("tools")
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .expect("tool array");
    let names = listed
        .iter()
        .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    assert!(names.contains("contextdb_session"));
    let session_schema = listed
        .iter()
        .find(|tool| tool["name"] == "contextdb_session")
        .map(|tool| &tool["inputSchema"])
        .expect("session schema");
    assert_eq!(session_schema["additionalProperties"], false);
    assert_eq!(
        session_schema["properties"]
            .as_object()
            .map(serde_json::Map::len),
        Some(0)
    );
    for expected in [
        "contextdb_observe",
        "contextdb_recall",
        "contextdb_context",
        "contextdb_ensure_candidate",
        "contextdb_recall_candidates",
        "contextdb_get_candidate",
        "contextdb_traverse_candidates",
        "contextdb_get_memory",
        "contextdb_explain",
        "contextdb_verify",
        "contextdb_preflight",
        "contextdb_postflight",
        "contextdb_checkpoint",
        "contextdb_resume",
        "contextdb_handoff",
    ] {
        assert!(names.contains(expected), "missing {expected}");
        let schema = listed
            .iter()
            .find(|tool| tool["name"] == expected)
            .map(|tool| &tool["inputSchema"])
            .expect("schema");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["context"]["additionalProperties"],
            false
        );
        assert!(
            schema["properties"]["context"]["properties"]
                .get("authentication")
                .is_none()
        );
        assert!(
            schema["properties"]["context"]["properties"]
                .get("capability_grants")
                .is_none()
        );
        if expected == "contextdb_context" {
            assert_eq!(schema["properties"]["plan"]["additionalProperties"], false);
            assert_eq!(
                schema["properties"]["plan"]["properties"]["query"]["maxLength"],
                32768
            );
        }
        if expected == "contextdb_ensure_candidate" {
            assert_eq!(schema["properties"]["identity_key"]["maxLength"], 4096);
            assert!(
                schema["properties"]["identity_key"]["description"]
                    .as_str()
                    .is_some_and(|description| description.contains("project|repo="))
            );
            assert!(schema["properties"].get("candidate_id").is_none());
            assert!(schema["properties"].get("idempotency_key").is_none());
            assert_eq!(schema["properties"]["value"]["type"], "object");
            assert_eq!(schema["properties"]["parent_candidate_ids"]["maxItems"], 16);
            assert!(schema.get("allOf").is_none());
            assert_eq!(
                schema["properties"]["supersedes_candidate_ids"]["maxItems"],
                16
            );
            assert!(
                schema["required"]
                    .as_array()
                    .is_some_and(|required| required
                        .iter()
                        .all(|field| { field.as_str() != Some("supersedes_candidate_ids") })),
                "supersedes_candidate_ids must remain a documented optional property"
            );
            assert_eq!(
                schema["properties"]["semantic_kind"]["enum"]
                    .as_array()
                    .map(Vec::len),
                Some(10)
            );
        }
        if expected == "contextdb_traverse_candidates" {
            assert_eq!(schema["properties"]["max_hops"]["maximum"], 32);
            assert_eq!(schema["properties"]["max_nodes"]["maximum"], 10_000);
        }
    }
    for forbidden in [
        "contextdb_remember",
        "contextdb_remember_structured",
        "contextdb_propose_memory",
        "contextdb_correct",
    ] {
        assert!(
            !names.contains(forbidden),
            "forbidden model tool {forbidden}"
        );
    }

    let runtime = RuntimeRequest {
        context: authenticated("request:preflight", &[Capability::Runtime]),
        operation_id: "operation:preflight".into(),
        payload: serde_json::json!({"turn": 1}),
    };
    let runtime_arguments = serde_json::json!({
        "context": runtime.context.request,
        "operation_id": runtime.operation_id,
        "payload": runtime.payload
    });
    let malformed_preflight = server
        .handle(call("contextdb_preflight", runtime_arguments, 21))
        .result
        .expect("tool result");
    assert_eq!(malformed_preflight["isError"], true);
    assert_eq!(
        malformed_preflight["structuredContent"]["code"],
        "format_incompatible"
    );

    let denied = RuntimeRequest {
        context: authenticated("request:denied", &[]),
        operation_id: "operation:denied".into(),
        payload: serde_json::json!({}),
    };
    let denied_arguments = serde_json::json!({
        "context": denied.context.request,
        "operation_id": denied.operation_id,
        "payload": denied.payload
    });
    let mut denied_server = McpServer::new(service);
    let denied = denied_server
        .handle(call("contextdb_checkpoint", denied_arguments, 22))
        .result
        .expect("tool result");
    assert_eq!(denied["isError"], true);
    assert_eq!(denied["structuredContent"]["code"], "unauthorized");

    let proposed = server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("request:proposal-unsupported"),
                "identity_key": "project|repo=d:/develop/unsupported-service",
                "semantic_kind": "project",
                "value": {"text": "untrusted proposal"},
                "search_text": "untrusted proposal",
                "parent_candidate_ids": [],
                "supersedes_candidate_ids": []
            }),
            23,
        ))
        .result
        .expect("tool result");
    assert_eq!(proposed["isError"], true);
    assert_eq!(proposed["structuredContent"]["code"], "unsupported");

    let invalid = server.handle(call(
        "contextdb_resume",
        serde_json::json!({
            "context": context("request:invalid"),
            "operation_id": "operation:invalid",
            "payload": {},
            "unexpected": true
        }),
        24,
    ));
    assert_eq!(invalid.error.expect("protocol error").code, -32602);

    for (index, tool) in [
        "contextdb_preflight",
        "contextdb_postflight",
        "contextdb_checkpoint",
        "contextdb_resume",
        "contextdb_handoff",
    ]
    .into_iter()
    .enumerate()
    {
        let denied_before_payload = denied_server
            .handle(call(
                tool,
                serde_json::json!({
                    "context": context("request:auth-first"),
                    "operation_id": "",
                    "payload": {},
                    "invalid_payload_field": true
                }),
                30 + i64::try_from(index).expect("small index"),
            ))
            .result
            .expect("typed authentication result");
        assert_eq!(denied_before_payload["isError"], true, "{tool}");
        assert_eq!(
            denied_before_payload["structuredContent"]["code"], "unauthorized",
            "{tool} must authorize before decoding the complete payload"
        );
    }
    let proposal_denied_before_payload = denied_server
        .handle(call(
            "contextdb_ensure_candidate",
            serde_json::json!({
                "context": context("request:proposal-auth-first"),
                "identity_key": "",
                "semantic_kind": "not-a-kind",
                "value": {},
                "search_text": "",
                "parent_candidate_ids": "not-an-array",
                "supersedes_candidate_ids": [],
                "invalid_payload_field": true
            }),
            35,
        ))
        .result
        .expect("typed authentication result");
    assert_eq!(proposal_denied_before_payload["isError"], true);
    assert_eq!(
        proposal_denied_before_payload["structuredContent"]["code"],
        "unauthorized"
    );
    let context_denied_before_payload = denied_server
        .handle(call(
            "contextdb_context",
            serde_json::json!({
                "context": context("request:context-auth-first"),
                "plan": "not-a-plan",
                "invalid_payload_field": true
            }),
            36,
        ))
        .result
        .expect("typed authentication result");
    assert_eq!(context_denied_before_payload["isError"], true);
    assert_eq!(
        context_denied_before_payload["structuredContent"]["code"],
        "unauthorized"
    );
}

#[test]
fn stdio_is_stateless_newline_delimited_json_rpc_only() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("stdio-test", [12; 32]).expect("reference service"));
    let mut server = McpServer::new(service);
    let discover =
        serde_json::to_string(&request(1, "server/discover", serde_json::json!({}))).expect("JSON");
    let tools =
        serde_json::to_string(&request(2, "tools/list", serde_json::json!({}))).expect("JSON");
    let input = format!("\u{feff}{discover}\n{tools}\nnot-json\n");
    let mut output = Vec::new();
    serve_stdio(&mut server, Cursor::new(input.as_bytes()), &mut output).expect("stdio");
    let lines = String::from_utf8(output)
        .expect("UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSON response"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["id"], 2);
    assert_eq!(lines[2]["error"]["code"], -32700);
}

#[test]
fn codex_standard_handshake_allows_metadata_free_list_and_call_without_notification_response() {
    let service: Arc<dyn CognitiveMemoryService> = Arc::new(
        ReferenceService::new("stdio-codex-handshake", [0x5c; 32]).expect("reference service"),
    );
    let mut server = authorized_server(service, &[Capability::Recall]);
    let initialize = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 41,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "codex", "version": "0.148.0"}
        }
    });
    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    let tools = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/list",
        "params": {}
    });
    let session = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 43,
        "method": "tools/call",
        "params": {"name": "contextdb_session", "arguments": {}}
    });
    let input = [initialize, initialized, tools, session]
        .into_iter()
        .map(|message| serde_json::to_string(&message).expect("wire JSON"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let mut output = Vec::new();
    serve_stdio(&mut server, Cursor::new(input.as_bytes()), &mut output).expect("stdio");
    let lines = String::from_utf8(output)
        .expect("UTF-8")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSON response"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 3, "initialized notification has no response");
    assert_eq!(lines[0]["id"], 41);
    assert_eq!(lines[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "contextdb");
    assert_eq!(lines[1]["id"], 42);
    assert_eq!(
        lines[1]["result"]["tools"].as_array().map(Vec::len),
        Some(16)
    );
    assert_eq!(lines[2]["id"], 43);
    assert_eq!(lines[2]["result"]["isError"], false);
    assert_eq!(
        lines[2]["result"]["structuredContent"]["context_template"]["workspace_id"],
        "workspace:mcp"
    );
}

#[test]
fn unsupported_version_and_service_failures_use_correct_error_planes() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("failure-test", [13; 32]).expect("reference service"));
    let mut server = authorized_server(service, &[Capability::Recall]);
    let mut wrong_meta = meta();
    wrong_meta["io.modelcontextprotocol/protocolVersion"] = serde_json::json!("2025-11-25");
    let unsupported = server.handle(JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(8),
        method: "tools/list".into(),
        params: Some(serde_json::json!({"_meta": wrong_meta})),
    });
    assert_eq!(unsupported.error.expect("error").code, -32022);

    let recall = RecallRequest {
        context: context("request:invalid"),
        query: String::new(),
        page_size: 0,
        at_commit: None,
        continuation: None,
    };
    let response = server.handle(call(
        "contextdb_recall",
        serde_json::to_value(recall).expect("JSON"),
        9,
    ));
    assert!(response.error.is_none());
    let result = response.result.expect("tool result");
    assert_eq!(result["isError"], true);
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["structuredContent"]["code"], "invalid_argument");
}

#[test]
fn tool_business_error_preserves_safe_remediation_context() {
    #[derive(Debug)]
    struct RichErrorService;

    impl CognitiveMemoryService for RichErrorService {
        fn observe(&self, _: ObserveRequest) -> ServiceResult<ObserveResponse> {
            Err(
                ServiceError::new(ErrorCode::Unauthorized, "policy denied", false).with_context(
                    vec!["partial:1".to_owned()],
                    Some("policy:no-share".to_owned()),
                    Some("request a narrower scope".to_owned()),
                    Some("trace:safe".to_owned()),
                ),
            )
        }

        fn recall(&self, _: RecallRequest) -> ServiceResult<RecallResponse> {
            unreachable!("not used")
        }

        fn explain_recall(
            &self,
            _: contextdb_service::ExplainRecallRequest,
        ) -> ServiceResult<contextdb_service::RecallTrace> {
            unreachable!("not used")
        }

        fn export_archive(
            &self,
            _: contextdb_service::ExportRequest,
        ) -> ServiceResult<contextdb_service::ExportResponse> {
            unreachable!("not used")
        }

        fn import_archive(
            &self,
            _: contextdb_service::ImportRequest,
        ) -> ServiceResult<contextdb_service::ImportResponse> {
            unreachable!("not used")
        }

        fn verify(
            &self,
            _: contextdb_service::VerifyRequest,
        ) -> ServiceResult<contextdb_service::VerifyResponse> {
            unreachable!("not used")
        }
    }

    let mut server = authorized_server(Arc::new(RichErrorService), &[Capability::Observe]);
    let response = server.handle(call(
        "contextdb_observe",
        serde_json::to_value(observation()).expect("request"),
        7,
    ));
    assert!(response.error.is_none());
    let result = response.result.expect("tool result");
    assert_eq!(result["isError"], true);
    assert_eq!(
        result["structuredContent"]["partial_result_refs"],
        serde_json::json!(["partial:1"])
    );
    assert_eq!(
        result["structuredContent"]["violated_policy"],
        "policy:no-share"
    );
    assert_eq!(result["structuredContent"]["trace_id"], "trace:safe");
}

#[test]
fn model_controlled_context_and_grants_cannot_authorize_mcp_tools() {
    let service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("mcp-host-authority", [15; 32]).expect("service"));
    let mut fail_closed = McpServer::new(Arc::clone(&service));
    let forged_observe = fail_closed
        .handle(call(
            "contextdb_observe",
            serde_json::to_value(observation()).expect("observation"),
            50,
        ))
        .result
        .expect("typed authorization error");
    assert_eq!(forged_observe["isError"], true);
    assert_eq!(forged_observe["structuredContent"]["code"], "unauthorized");

    let mut host_authorized = authorized_server(service, &[Capability::Observe]);
    let accepted = host_authorized
        .handle(call(
            "contextdb_observe",
            serde_json::to_value(observation()).expect("observation"),
            51,
        ))
        .result
        .expect("authorized result");
    assert_eq!(accepted["isError"], false);

    let mut cross_workspace = observation();
    cross_workspace.context.workspace_id = "workspace:other".to_owned();
    cross_workspace.access.workspace_id = "workspace:other".to_owned();
    let denied = host_authorized
        .handle(call(
            "contextdb_observe",
            serde_json::to_value(cross_workspace).expect("observation"),
            52,
        ))
        .result
        .expect("typed authorization error");
    assert_eq!(denied["isError"], true);
    assert_eq!(denied["structuredContent"]["code"], "unauthorized");

    let admin_service: Arc<dyn CognitiveMemoryService> =
        Arc::new(ReferenceService::new("mcp-no-archive", [16; 32]).expect("service"));
    let mut admin_authority = authenticated("host:admin", &[Capability::Admin]);
    admin_authority.request.purpose = "contextdb:admin".to_owned();
    admin_authority.request.clearance = Sensitivity::Restricted;
    let mut admin_request = admin_authority.request.clone();
    admin_request.request_id = "request:verify".to_owned();
    let mut admin_authorized =
        McpServer::with_fixed_session_authority(admin_service, admin_authority)
            .expect("fixed host admin authority");
    let verified = admin_authorized
        .handle(call(
            "contextdb_verify",
            serde_json::json!({"context": admin_request, "deep": false}),
            53,
        ))
        .result
        .expect("authorized verify result");
    assert_eq!(verified["isError"], false);
    assert_eq!(verified["structuredContent"]["valid"], true);

    for (id, tool) in [(54, "contextdb_export"), (55, "contextdb_import")] {
        let response = admin_authorized.handle(call(
            tool,
            serde_json::json!({"context": context("request:archive")}),
            id,
        ));
        assert_eq!(
            response.error.expect("archive tool must be absent").code,
            -32602
        );
    }
    let tools = admin_authorized
        .handle(request(56, "tools/list", serde_json::json!({})))
        .result
        .expect("tool list")["tools"]
        .as_array()
        .cloned()
        .expect("tools");
    assert!(tools.iter().all(|tool| {
        !matches!(
            tool["name"].as_str(),
            Some("contextdb_export" | "contextdb_import")
        )
    }));
}
