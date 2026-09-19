use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier};
use std::thread;

use contextdb_context::{
    ContextBudgets, InstructionHierarchy, ModelProfile, PackPurpose, PositionProfile,
    ReferenceTokenizer, RendererKind, StructuredFormat,
};
use contextdb_core::{ContextPackId, RecallIntent};
use contextdb_recall::{
    ProviderRequest, RecallLimits, RecallMode, RecallPrincipal, RecallProvider, RecallSensitivity,
};
use contextdb_service::{
    AuthenticationEvidence, CompileContextPlan, CompileContextRequest, DomainTimeRange, ForgetMode,
    MemoryLinks, PublishMemoryRequest,
};

use super::*;

fn request_context(request_id: &str, workspace: &str, subject: &str) -> RequestContext {
    RequestContext {
        request_id: request_id.to_owned(),
        workspace_id: workspace.to_owned(),
        subject_id: subject.to_owned(),
        audiences: BTreeSet::from([subject.to_owned()]),
        scopes: BTreeSet::from(["project".to_owned()]),
        purpose: "assist".to_owned(),
        clearance: Sensitivity::Private,
    }
}

pub(super) fn authenticated(
    request_id: &str,
    workspace: &str,
    subject: &str,
    capabilities: impl IntoIterator<Item = Capability>,
) -> AuthenticatedRequestContext {
    AuthenticatedRequestContext {
        request: request_context(request_id, workspace, subject),
        actor_id: "human-owner".to_owned(),
        agent_id: "codex-agent".to_owned(),
        session_id: Some("session-1".to_owned()),
        capability_grants: capabilities.into_iter().collect(),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "local-channel".to_owned(),
            peer_identity: "human-owner".to_owned(),
            binding_digest: "aa".repeat(32),
        },
    }
}

fn publish_request(
    request_id: &str,
    workspace: &str,
    subject: &str,
    idempotency_key: &str,
    memory_id: &str,
    text: &str,
) -> PublishMemoryRequest {
    PublishMemoryRequest {
        context: authenticated(
            request_id,
            workspace,
            subject,
            [Capability::Correct, Capability::Observe],
        ),
        idempotency_key: idempotency_key.to_owned(),
        memory_id: memory_id.to_owned(),
        value: serde_json::json!({"text": text}),
        search_text: text.to_owned(),
    }
}

fn proposal_request(
    request_id: &str,
    idempotency_key: &str,
    memory_id: &str,
    semantic_kind: StructuredMemoryKind,
    text: &str,
    parent_ids: impl IntoIterator<Item = &'static str>,
) -> ProposeMemoryRequest {
    let mut context = authenticated(
        request_id,
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Observe],
    );
    context.request.purpose = "conversation".to_owned();
    ProposeMemoryRequest {
        context,
        idempotency_key: idempotency_key.to_owned(),
        candidate_id: memory_id.to_owned(),
        semantic_kind,
        value: serde_json::json!({"text": text}),
        search_text: text.to_owned(),
        parent_candidate_ids: parent_ids.into_iter().map(ToOwned::to_owned).collect(),
        supersedes_candidate_ids: BTreeSet::new(),
    }
}

fn candidate_traverse(
    request_id: &str,
    start_ids: impl IntoIterator<Item = &'static str>,
    direction: TraverseDirection,
    max_hops: u8,
) -> TraverseRequest {
    let mut context = authenticated(
        request_id,
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Traverse],
    );
    context.request.purpose = "conversation".to_owned();
    TraverseRequest {
        context,
        start_ids: start_ids.into_iter().map(ToOwned::to_owned).collect(),
        direction,
        predicate_ids: BTreeSet::from([CANDIDATE_HIERARCHY_PARENT_PREDICATE.to_owned()]),
        max_hops,
        max_nodes: 128,
        at_commit: None,
    }
}

fn recall_request(
    request_id: &str,
    workspace: &str,
    subject: &str,
    query: &str,
    page_size: u32,
) -> RecallRequest {
    RecallRequest {
        context: request_context(request_id, workspace, subject),
        query: query.to_owned(),
        page_size,
        at_commit: None,
        continuation: None,
    }
}

fn get_request(
    request_id: &str,
    workspace: &str,
    subject: &str,
    memory_id: &str,
    at_commit: Option<u64>,
) -> GetMemoryRequest {
    GetMemoryRequest {
        context: authenticated(request_id, workspace, subject, [Capability::ReadMemory]),
        record_id: memory_id.to_owned(),
        at_commit,
    }
}

fn compile_plan(query: &str) -> CompileContextPlan {
    CompileContextPlan {
        pack_id: ContextPackId::from_uuid(uuid::Uuid::from_u128(0x1234)).expect("context pack ID"),
        query: query.to_owned(),
        mode: RecallMode::Required,
        intent: RecallIntent::CurrentTruth,
        purpose: PackPurpose::Conversation,
        at_commit: None,
        now_micros: 0,
        required_facets: Vec::new(),
        recall_limits: RecallLimits {
            max_nodes_examined: 128,
            max_seed_candidates: 128,
            max_graph_hops: 2,
            max_frontier_per_hop: 128,
            max_evidence_units: 32,
            max_context_tokens: 2_048,
            deadline_micros: 5_000_000,
        },
        context_budgets: ContextBudgets {
            hard_tokens: 2_048,
            soft_tokens: 1_024,
            max_blocks: 32,
            max_evidence_blocks: 32,
            max_raw_evidence_tokens: 1_024,
            max_history_tokens: 1_024,
            max_conflict_tokens: 1_024,
            max_serialized_bytes: 256 * 1_024,
            max_selection_evaluations: 128,
        },
        model_profile: ModelProfile {
            id: "model:local-test".to_owned(),
            family: "native".to_owned(),
            tokenizer_id: ReferenceTokenizer::ID.to_owned(),
            renderer: RendererKind::Compact,
            max_context_tokens: 4_096,
            reserved_output_tokens: 1_024,
            preferred_structured_format: StructuredFormat::CompactText,
            supports_tool_results: false,
            supports_native_citations: false,
            supports_prompt_caching: false,
            position_profile: PositionProfile::SmallModelExplicit,
            instruction_hierarchy: InstructionHierarchy::SinglePromptDelimited,
            max_schema_complexity: 32,
            external_processing: false,
        },
        explicit_memory_request: true,
        require_primary_evidence: false,
        include_evidence_quotes: false,
        permit_derived_only: true,
        max_projection_lag_commits: 0,
        allow_stale: false,
        query_vector: None,
        continuation: None,
    }
}

#[test]
fn publish_recall_get_restart_and_idempotency_are_durable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("native");
    let key = [7_u8; 32];
    let service = NativeService::open(&path, "db-native", key).expect("open native");
    assert_eq!(service.engine.head_sequence().expect("head"), 1);

    let request = publish_request(
        "request-1",
        "workspace-a",
        "subject-a",
        "publish-1",
        "memory-amber",
        "the durable color is amber",
    );
    let first = service
        .publish_memory(request.clone())
        .expect("publish memory");
    assert_eq!(first.commit_seq, 1);
    assert!(!first.replayed);
    assert_eq!(first.watermarks.semantic, 1);
    assert_eq!(first.watermarks.lexical, 1);
    assert_eq!(first.watermarks.vector, 0);
    assert_eq!(first.watermarks.graph, 0);
    assert_eq!(service.engine.head_sequence().expect("head"), 2);

    let mut retry = request;
    retry.context.request.request_id = "fresh-request-id".to_owned();
    let replay = service.publish_memory(retry).expect("idempotent replay");
    assert!(replay.replayed);
    assert_eq!(replay.commit_seq, first.commit_seq);
    assert_eq!(service.engine.head_sequence().expect("head"), 2);

    let recall = service
        .recall(recall_request(
            "recall-1",
            "workspace-a",
            "subject-a",
            "amber",
            10,
        ))
        .expect("recall");
    assert_eq!(recall.hits.len(), 1);
    assert_eq!(recall.hits[0].id, "memory-amber");
    assert_eq!(recall.trace.authorized_candidates, 1);
    service
        .explain_recall(ExplainRecallRequest {
            context: request_context("explain-1", "workspace-a", "subject-a"),
            trace: recall.trace,
        })
        .expect("explain trace");

    let memory = service
        .get_memory(get_request(
            "get-1",
            "workspace-a",
            "subject-a",
            "memory-amber",
            None,
        ))
        .expect("get memory");
    assert_eq!(memory.document.value["text"], "the durable color is amber");
    service.verify_native(true).expect("deep verify");
    drop(service);

    let reopened = NativeService::open(&path, "db-native", key).expect("reopen native");
    let recalled = reopened
        .recall(recall_request(
            "recall-after-restart",
            "workspace-a",
            "subject-a",
            "amber",
            10,
        ))
        .expect("recall after restart");
    assert_eq!(recalled.hits[0].id, "memory-amber");
    assert_eq!(reopened.engine.head_sequence().expect("head"), 2);
}

#[test]
fn native_provider_compiles_one_policy_bound_context_pack() {
    let directory = tempfile::tempdir().expect("tempdir");
    let key = [31_u8; 32];
    let service = NativeService::open(directory.path(), "db-context-pack", key).expect("open");
    let mut allowed = publish_request(
        "remember-allowed",
        "workspace-a",
        "subject-a",
        "allowed-key",
        "memory-allowed",
        "The project codename is Espresso",
    );
    allowed.context.request.purpose = "conversation".to_owned();
    service.publish_memory(allowed).expect("publish allowed");
    let mut denied = publish_request(
        "remember-denied",
        "workspace-a",
        "subject-b",
        "denied-key",
        "memory-denied",
        "FORBIDDEN-CONTEXT-CANARY",
    );
    denied.context.request.purpose = "conversation".to_owned();
    service.publish_memory(denied).expect("publish denied");

    let mut context = authenticated("compile", "workspace-a", "subject-a", [Capability::Recall]);
    context.request.purpose = "conversation".to_owned();
    let response = service
        .compile_context(CompileContextRequest {
            context,
            plan: compile_plan("remember the Espresso project codename"),
        })
        .expect("compile native ContextPack");
    response.context_pack.validate().expect("valid ContextPack");
    assert_eq!(response.context_pack.snapshot, response.trace.snapshot);
    assert!(!response.trace.stale);
    assert_eq!(response.trace.max_projection_lag_commits, 0);
    let encoded = serde_json::to_string(&response).expect("response JSON");
    assert!(encoded.contains("Espresso"));
    assert!(!encoded.contains("FORBIDDEN-CONTEXT-CANARY"));
    let trace = serde_json::to_string(&response.trace).expect("trace JSON");
    assert!(!trace.contains("Espresso"));

    drop(service);
    let reopened = NativeService::open(directory.path(), "db-context-pack", key).expect("reopen");
    let mut context = authenticated(
        "compile-after-restart",
        "workspace-a",
        "subject-a",
        [Capability::Recall],
    );
    context.request.purpose = "conversation".to_owned();
    let restarted = reopened
        .compile_context(CompileContextRequest {
            context,
            plan: compile_plan("Espresso"),
        })
        .expect("compile after restart");
    let encoded = serde_json::to_string(&restarted).expect("restarted response JSON");
    assert!(encoded.contains("Espresso"));
    assert!(!encoded.contains("FORBIDDEN-CONTEXT-CANARY"));
}

#[test]
fn candidate_hierarchy_is_atomic_durable_idempotent_and_canonically_isolated() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("native");
    let key = [0x41_u8; 32];
    let service = NativeService::open(&path, "db-hierarchy", key).expect("open");

    service
        .propose_memory(proposal_request(
            "project",
            "structured-project",
            "memory:project",
            StructuredMemoryKind::Project,
            "ContextDB project root",
            [],
        ))
        .expect("publish project");
    service
        .propose_memory(proposal_request(
            "topic-a",
            "structured-topic-a",
            "memory:topic-a",
            StructuredMemoryKind::Topic,
            "hierarchical capture topic alpha",
            ["memory:project"],
        ))
        .expect("publish topic a");
    service
        .propose_memory(proposal_request(
            "topic-b",
            "structured-topic-b",
            "memory:topic-b",
            StructuredMemoryKind::Topic,
            "hierarchical capture topic beta",
            ["memory:project"],
        ))
        .expect("publish topic b");
    let decision_request = proposal_request(
        "decision",
        "structured-decision",
        "memory:decision",
        StructuredMemoryKind::Decision,
        "use true typed hierarchy edges",
        ["memory:topic-a", "memory:topic-b"],
    );
    let decision = service
        .propose_memory(decision_request.clone())
        .expect("publish multi-parent decision");
    assert_eq!(decision.mutation.commit_seq, 4);
    assert_eq!(decision.mutation.watermarks.semantic, 0);
    assert_eq!(decision.mutation.watermarks.graph, 0);
    assert_eq!(
        decision.proposal_state,
        contextdb_service::CandidateProposalState::Quarantined
    );
    assert!(!decision.canonical);
    assert_eq!(decision.candidate_edge_ids.len(), 2);
    assert_eq!(
        decision.candidate_edge_ids,
        vec![
            candidate_hierarchy_edge_id("memory:topic-a", "memory:decision").expect("edge id"),
            candidate_hierarchy_edge_id("memory:topic-b", "memory:decision").expect("edge id"),
        ]
    );

    let mut retry = decision_request;
    retry.context.request.request_id = "decision-retry".to_owned();
    let replay = service
        .propose_memory(retry)
        .expect("structured idempotent replay");
    assert!(replay.mutation.replayed);
    assert_eq!(replay.candidate_edge_ids, decision.candidate_edge_ids);

    let outgoing = service
        .traverse_candidates(candidate_traverse(
            "traverse-outgoing",
            ["memory:project"],
            TraverseDirection::Outgoing,
            2,
        ))
        .expect("multi-parent outgoing traversal");
    assert_eq!(
        outgoing.node_ids,
        [
            "memory:project",
            "memory:topic-a",
            "memory:topic-b",
            "memory:decision",
        ]
    );
    let incoming = service
        .traverse_candidates(candidate_traverse(
            "traverse-incoming",
            ["memory:decision"],
            TraverseDirection::Incoming,
            2,
        ))
        .expect("multi-parent incoming traversal");
    assert_eq!(
        incoming.node_ids,
        [
            "memory:decision",
            "memory:topic-a",
            "memory:topic-b",
            "memory:project",
        ]
    );

    let mut get = get_request(
        "get-decision",
        "workspace-hierarchy",
        "subject-owner",
        "memory:decision",
        None,
    );
    get.context.request.purpose = "conversation".to_owned();
    let stored = service.get_candidate(get).expect("quarantined candidate");
    assert_eq!(stored.document.kind, MemoryRecordKind::Candidate);
    assert_eq!(
        stored.document.attributes["contextdb.proposal.state"],
        "quarantined"
    );
    assert_eq!(
        stored.document.attributes["contextdb.proposal.promotion_eligible"],
        false
    );
    assert_eq!(
        stored.document.attributes["contextdb.semantic_kind"],
        "decision"
    );
    assert_eq!(
        stored.document.attributes["facets"][0],
        "contextdb.semantic_kind:decision"
    );

    let mut compile_context = authenticated(
        "compile-hierarchy",
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Recall],
    );
    compile_context.request.purpose = "conversation".to_owned();
    let packed = service
        .compile_context(CompileContextRequest {
            context: compile_context,
            plan: compile_plan("true typed hierarchy edges"),
        })
        .expect("compile hierarchy ContextPack");
    let encoded = serde_json::to_string(&packed).expect("packed JSON");
    assert!(!encoded.contains("memory:decision"));
    let mut canonical_request = recall_request(
        "canonical-recall",
        "workspace-hierarchy",
        "subject-owner",
        "true typed hierarchy edges",
        10,
    );
    canonical_request.context.purpose = "conversation".to_owned();
    let canonical = service
        .recall(canonical_request)
        .expect("canonical recall excludes candidates");
    assert!(canonical.hits.is_empty());
    assert_eq!(canonical.trace.authorized_candidates, 0);
    let mut candidate_context = authenticated(
        "candidate-recall",
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Recall],
    );
    candidate_context.request.purpose = "conversation".to_owned();
    let candidates = service
        .recall_candidates(RecallCandidatesRequest {
            context: candidate_context,
            query: "true typed hierarchy edges".to_owned(),
            semantic_kinds: BTreeSet::from([StructuredMemoryKind::Decision]),
            page_size: 10,
            at_commit: None,
        })
        .expect("candidate recall");
    assert_eq!(candidates.hits.len(), 1);
    assert_eq!(candidates.hits[0].candidate_id, "memory:decision");
    let provider = NativeRecallProvider::new(&service, "workspace-hierarchy");
    let provider_snapshot = provider.snapshot(None).expect("provider snapshot");
    let corpus = provider
        .authorized_corpus(&ProviderRequest {
            snapshot: provider_snapshot,
            principal: RecallPrincipal {
                subject: "subject-owner".to_owned(),
                audiences: BTreeSet::from(["subject-owner".to_owned()]),
                workspace: "workspace-hierarchy".to_owned(),
                scopes: BTreeSet::from(["project".to_owned()]),
                purpose: "conversation".to_owned(),
                clearance: RecallSensitivity::Confidential,
            },
            filter_digest: "hierarchy-provider-test".to_owned(),
        })
        .expect("authorized provider corpus");
    assert!(corpus.documents().is_empty());
    assert!(corpus.relations().is_empty());
    service.verify_native(true).expect("deep verify hierarchy");
    drop(service);

    let reopened = NativeService::open(&path, "db-hierarchy", key).expect("reopen hierarchy");
    let restarted = reopened
        .traverse_candidates(candidate_traverse(
            "traverse-restart",
            ["memory:project"],
            TraverseDirection::Outgoing,
            2,
        ))
        .expect("restart traversal");
    assert_eq!(restarted.node_ids, outgoing.node_ids);
    reopened.verify_native(true).expect("restart deep verify");
}

#[test]
fn candidate_hierarchy_rejects_invalid_parents_and_cycles_without_partial_writes() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service =
        NativeService::open(directory.path(), "db-hierarchy-reject", [0x42_u8; 32]).expect("open");
    service
        .propose_memory(proposal_request(
            "parent",
            "parent-key",
            "memory:parent",
            StructuredMemoryKind::Project,
            "authorized hierarchy parent",
            [],
        ))
        .expect("publish parent");

    let baseline = service.verify_native(false).expect("baseline").commit_seq;
    let unknown = service
        .propose_memory(proposal_request(
            "unknown",
            "unknown-key",
            "memory:unknown-child",
            StructuredMemoryKind::Topic,
            "unknown parent child",
            ["memory:absent"],
        ))
        .expect_err("unknown parent rejected");
    assert_eq!(unknown.code, ErrorCode::NotFound);
    assert_eq!(
        service
            .verify_native(false)
            .expect("after unknown")
            .commit_seq,
        baseline
    );

    let mut cross_policy = proposal_request(
        "cross-policy",
        "cross-policy-key",
        "memory:cross-policy-child",
        StructuredMemoryKind::Topic,
        "cross policy child",
        ["memory:parent"],
    );
    cross_policy
        .context
        .request
        .scopes
        .insert("project:additional".to_owned());
    let cross_policy = service
        .propose_memory(cross_policy)
        .expect_err("cross-policy parent rejected");
    assert_eq!(cross_policy.code, ErrorCode::PermissionDenied);
    assert_eq!(
        service
            .verify_native(false)
            .expect("after cross policy")
            .commit_seq,
        baseline
    );

    let mut unauthorized_parent = proposal_request(
        "other-parent",
        "other-parent-key",
        "memory:other-parent",
        StructuredMemoryKind::Project,
        "other subject parent",
        [],
    );
    unauthorized_parent.context.request.subject_id = "subject-other".to_owned();
    unauthorized_parent.context.request.audiences = BTreeSet::from(["subject-other".to_owned()]);
    service
        .propose_memory(unauthorized_parent)
        .expect("publish other parent");
    let before_unauthorized = service.verify_native(false).expect("head").commit_seq;
    let unauthorized = service
        .propose_memory(proposal_request(
            "unauthorized",
            "unauthorized-key",
            "memory:unauthorized-child",
            StructuredMemoryKind::Topic,
            "unauthorized parent child",
            ["memory:other-parent"],
        ))
        .expect_err("unauthorized parent rejected");
    assert_eq!(unauthorized.code, ErrorCode::PermissionDenied);
    assert_eq!(
        service
            .verify_native(false)
            .expect("after unauthorized")
            .commit_seq,
        before_unauthorized
    );

    let before_cycle = service
        .verify_native(false)
        .expect("before cycle")
        .commit_seq;
    let cycle = service
        .propose_memory(proposal_request(
            "cycle",
            "cycle-key",
            "memory:self-cycle",
            StructuredMemoryKind::Topic,
            "self cycle",
            ["memory:self-cycle"],
        ))
        .expect_err("self cycle rejected");
    assert_eq!(cycle.code, ErrorCode::InvalidArgument);
    assert_eq!(
        service
            .verify_native(false)
            .expect("after cycle")
            .commit_seq,
        before_cycle
    );
    service
        .verify_native(true)
        .expect("deep verify rejected writes");
}

#[test]
fn deep_verify_rejects_an_injected_multi_node_candidate_cycle() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service =
        NativeService::open(directory.path(), "db-hierarchy-cycle", [0x44_u8; 32]).expect("open");
    service
        .propose_memory(proposal_request(
            "cycle-a",
            "cycle-a-key",
            "memory:cycle-a",
            StructuredMemoryKind::Topic,
            "cycle node a",
            [],
        ))
        .expect("publish cycle node a");
    service
        .propose_memory(proposal_request(
            "cycle-b",
            "cycle-b-key",
            "memory:cycle-b",
            StructuredMemoryKind::Topic,
            "cycle node b",
            ["memory:cycle-a"],
        ))
        .expect("publish cycle node b");
    let mut get = get_request(
        "cycle-policy",
        "workspace-hierarchy",
        "subject-owner",
        "memory:cycle-a",
        None,
    );
    get.context.request.purpose = "conversation".to_owned();
    let access = service
        .get_candidate(get)
        .expect("cycle node")
        .document
        .access;
    let provenance = authenticated(
        "injected-cycle",
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Observe],
    );
    let mut transaction = service.engine.begin_write().expect("write transaction");
    let global_head = service.global_head(&transaction).expect("global head");
    let edge = MemoryRecord {
        document: MemoryDocument {
            id: candidate_hierarchy_edge_id("memory:cycle-b", "memory:cycle-a")
                .expect("candidate edge ID"),
            kind: MemoryRecordKind::Candidate,
            access,
            valid_time: DomainTimeRange::default(),
            lifecycle: MemoryLifecycle::Active,
            links: MemoryLinks {
                source: Some("memory:cycle-b".to_owned()),
                target: Some("memory:cycle-a".to_owned()),
                predicate: Some(CANDIDATE_HIERARCHY_PARENT_PREDICATE.to_owned()),
                ..MemoryLinks::default()
            },
            value: serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "proposal_state": "quarantined"
            }),
            search_text: None,
            vector: None,
            attributes: candidate_provenance_attributes(
                &provenance,
                &"bb".repeat(32),
                CANDIDATE_EDGE_ROLE,
            ),
        },
        revision: 1,
        transaction_from: global_head,
        transaction_to: None,
    };
    let policy = policy_for(&edge).expect("edge policy");
    service
        .put_record(&mut transaction, &policy, &edge)
        .expect("inject corrupt edge");
    transaction
        .commit(Durability::Sync)
        .expect("commit corrupt fixture");

    let error = service
        .verify_native(true)
        .expect_err("deep verify rejects the injected cycle");
    assert_eq!(error.code, ErrorCode::IntegrityFailure);
}

#[test]
fn candidate_retraction_closes_incident_links_and_preserves_canonical_watermarks() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("native");
    let key = [0x45_u8; 32];
    let service = NativeService::open(&path, "db-candidate-retract", key).expect("open");
    service
        .propose_memory(proposal_request(
            "retract-root",
            "retract-root-key",
            "memory:retract-root",
            StructuredMemoryKind::Project,
            "candidate root to retract",
            [],
        ))
        .expect("publish root");
    service
        .propose_memory(proposal_request(
            "retract-child",
            "retract-child-key",
            "memory:retract-child",
            StructuredMemoryKind::Topic,
            "candidate child remains active",
            ["memory:retract-root"],
        ))
        .expect("publish child");

    let mut root_get = get_request(
        "correct-candidate-get",
        "workspace-hierarchy",
        "subject-owner",
        "memory:retract-root",
        None,
    );
    root_get.context.request.purpose = "conversation".to_owned();
    let mut forbidden_successor = service
        .get_candidate(root_get)
        .expect("candidate root")
        .document;
    forbidden_successor.id = "memory:retract-root-v2".to_owned();
    forbidden_successor
        .links
        .supersedes
        .insert("memory:retract-root".to_owned());
    let mut correction_context = authenticated(
        "generic-candidate-correct",
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Correct],
    );
    correction_context.request.purpose = "conversation".to_owned();
    let generic_correction = service
        .correct(CorrectRequest {
            context: correction_context,
            idempotency_key: "generic-candidate-correct-key".to_owned(),
            target_id: "memory:retract-root".to_owned(),
            replacement: forbidden_successor,
        })
        .expect_err("generic correction cannot bypass candidate supersession");
    assert_eq!(generic_correction.code, ErrorCode::InvalidArgument);

    let mut forget_context = authenticated(
        "retract-candidate",
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Forget],
    );
    forget_context.request.purpose = "conversation".to_owned();
    let receipt = service
        .forget(ForgetRequest {
            context: forget_context,
            idempotency_key: "retract-candidate-key".to_owned(),
            target_id: "memory:retract-root".to_owned(),
            mode: ForgetMode::Retract,
            reason: "owner_requested".to_owned(),
        })
        .expect("retract candidate root");
    assert_eq!(receipt.watermarks.semantic, 0);
    assert_eq!(receipt.watermarks.graph, 0);
    let incoming = service
        .traverse_candidates(candidate_traverse(
            "traverse-after-retract",
            ["memory:retract-child"],
            TraverseDirection::Incoming,
            2,
        ))
        .expect("traverse remaining candidate");
    assert_eq!(incoming.node_ids, ["memory:retract-child"]);
    service
        .verify_native(true)
        .expect("deep verify after candidate retraction");
    drop(service);

    let reopened =
        NativeService::open(&path, "db-candidate-retract", key).expect("restart service");
    let restarted = reopened
        .traverse_candidates(candidate_traverse(
            "traverse-retracted-restart",
            ["memory:retract-child"],
            TraverseDirection::Incoming,
            2,
        ))
        .expect("restart traversal");
    assert_eq!(restarted.node_ids, ["memory:retract-child"]);
    reopened
        .verify_native(true)
        .expect("restart deep verify after retraction");
}

#[test]
fn candidate_policy_preserves_exact_restricted_sensitivity() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(directory.path(), "db-candidate-restricted", [0x46_u8; 32])
        .expect("open");
    let mut request = proposal_request(
        "restricted-candidate",
        "restricted-candidate-key",
        "memory:restricted-candidate",
        StructuredMemoryKind::Constraint,
        "restricted candidate policy",
        [],
    );
    request.context.request.clearance = Sensitivity::Restricted;
    service
        .propose_memory(request)
        .expect("publish restricted candidate");
    let mut get = get_request(
        "get-restricted-candidate",
        "workspace-hierarchy",
        "subject-owner",
        "memory:restricted-candidate",
        None,
    );
    get.context.request.purpose = "conversation".to_owned();
    get.context.request.clearance = Sensitivity::Restricted;
    let stored = service
        .get_candidate(get)
        .expect("read restricted candidate");
    assert_eq!(stored.document.access.sensitivity, Sensitivity::Restricted);
    service
        .verify_native(true)
        .expect("deep verify restricted candidate");
}

#[test]
fn candidate_supersession_closes_contradictions_and_incident_links_across_restart() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("native");
    let key = [0x43_u8; 32];
    let service = NativeService::open(&path, "db-hierarchy-lifecycle", key).expect("open");
    service
        .propose_memory(proposal_request(
            "project",
            "lifecycle-project",
            "memory:lifecycle-project",
            StructuredMemoryKind::Project,
            "hierarchy lifecycle project",
            [],
        ))
        .expect("project");
    service
        .propose_memory(proposal_request(
            "topic",
            "lifecycle-topic",
            "memory:lifecycle-topic-v1",
            StructuredMemoryKind::Topic,
            "hierarchy lifecycle topic version one",
            ["memory:lifecycle-project"],
        ))
        .expect("topic");
    service
        .propose_memory(proposal_request(
            "decision",
            "lifecycle-decision",
            "memory:lifecycle-decision-v1",
            StructuredMemoryKind::Decision,
            "hierarchy lifecycle decision version one",
            ["memory:lifecycle-topic-v1"],
        ))
        .expect("decision");

    let mut child_correction = proposal_request(
        "correct-child",
        "correct-child-key",
        "memory:lifecycle-decision-v2",
        StructuredMemoryKind::Decision,
        "hierarchy lifecycle decision version two",
        ["memory:lifecycle-topic-v1"],
    );
    child_correction
        .supersedes_candidate_ids
        .insert("memory:lifecycle-decision-v1".to_owned());
    let child_receipt = service
        .propose_memory(child_correction)
        .expect("supersede child candidate");
    assert!(!child_receipt.canonical);
    let after_child = service
        .traverse_candidates(candidate_traverse(
            "after-child",
            ["memory:lifecycle-project"],
            TraverseDirection::Outgoing,
            3,
        ))
        .expect("traverse corrected child");
    assert_eq!(
        after_child.node_ids,
        [
            "memory:lifecycle-project",
            "memory:lifecycle-topic-v1",
            "memory:lifecycle-decision-v2",
        ]
    );

    let mut parent_correction = proposal_request(
        "correct-parent",
        "correct-parent-key",
        "memory:lifecycle-topic-v2",
        StructuredMemoryKind::Topic,
        "hierarchy lifecycle topic version two",
        ["memory:lifecycle-project"],
    );
    parent_correction
        .supersedes_candidate_ids
        .insert("memory:lifecycle-topic-v1".to_owned());
    let parent_receipt = service
        .propose_memory(parent_correction)
        .expect("supersede parent candidate");
    assert!(!parent_receipt.canonical);
    let after_parent = service
        .traverse_candidates(candidate_traverse(
            "after-parent",
            ["memory:lifecycle-project"],
            TraverseDirection::Outgoing,
            3,
        ))
        .expect("traverse corrected parent");
    assert_eq!(
        after_parent.node_ids,
        ["memory:lifecycle-project", "memory:lifecycle-topic-v2",]
    );
    let mut compile_context = authenticated(
        "compile-rewired",
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Recall],
    );
    compile_context.request.purpose = "conversation".to_owned();
    service
        .compile_context(CompileContextRequest {
            context: compile_context,
            plan: compile_plan("hierarchy lifecycle decision version two"),
        })
        .expect("ContextPack after edge rewire");
    service
        .verify_native(true)
        .expect("deep verify rewired graph");
    drop(service);

    let reopened = NativeService::open(&path, "db-hierarchy-lifecycle", key).expect("reopen");
    let restarted = reopened
        .traverse_candidates(candidate_traverse(
            "restarted",
            ["memory:lifecycle-project"],
            TraverseDirection::Outgoing,
            3,
        ))
        .expect("restart traversal");
    assert_eq!(restarted.node_ids, after_parent.node_ids);
    let mut old_get = get_request(
        "get-superseded",
        "workspace-hierarchy",
        "subject-owner",
        "memory:lifecycle-topic-v1",
        None,
    );
    old_get.context.request.purpose = "conversation".to_owned();
    assert_eq!(
        reopened
            .get_candidate(old_get)
            .expect("superseded candidate remains auditable")
            .document
            .lifecycle,
        MemoryLifecycle::Superseded
    );
    let mut recall_context = authenticated(
        "recall-active-candidates",
        "workspace-hierarchy",
        "subject-owner",
        [Capability::Recall],
    );
    recall_context.request.purpose = "conversation".to_owned();
    let active = reopened
        .recall_candidates(RecallCandidatesRequest {
            context: recall_context,
            query: "hierarchy lifecycle".to_owned(),
            semantic_kinds: BTreeSet::new(),
            page_size: 32,
            at_commit: None,
        })
        .expect("recall active successors");
    let ids = active
        .hits
        .iter()
        .map(|hit| hit.candidate_id.as_str())
        .collect::<BTreeSet<_>>();
    assert!(ids.contains("memory:lifecycle-topic-v2"));
    assert!(ids.contains("memory:lifecycle-decision-v2"));
    assert!(!ids.contains("memory:lifecycle-topic-v1"));
    assert!(!ids.contains("memory:lifecycle-decision-v1"));
    let provider = NativeRecallProvider::new(&reopened, "workspace-hierarchy");
    let corpus = provider
        .authorized_corpus(&ProviderRequest {
            snapshot: provider.snapshot(None).expect("snapshot"),
            principal: RecallPrincipal {
                subject: "subject-owner".to_owned(),
                audiences: BTreeSet::from(["subject-owner".to_owned()]),
                workspace: "workspace-hierarchy".to_owned(),
                scopes: BTreeSet::from(["project".to_owned()]),
                purpose: "conversation".to_owned(),
                clearance: RecallSensitivity::Confidential,
            },
            filter_digest: "post-supersession-provider-test".to_owned(),
        })
        .expect("canonical provider excludes all proposals");
    assert!(corpus.documents().is_empty());
    assert!(corpus.relations().is_empty());
    reopened
        .verify_native(true)
        .expect("deep verify after candidate supersession");
}

#[test]
fn correction_has_snapshot_bound_successor_semantics_across_restart() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("native");
    let key = [9_u8; 32];
    let service = NativeService::open(&path, "db-correction", key).expect("open");
    service
        .publish_memory(publish_request(
            "publish",
            "workspace-a",
            "subject-a",
            "publish-v1",
            "memory-v1",
            "the durable color is amber",
        ))
        .expect("publish v1");
    let old = service
        .get_memory(get_request(
            "get-old",
            "workspace-a",
            "subject-a",
            "memory-v1",
            None,
        ))
        .expect("old memory");
    let mut successor = old.document.clone();
    successor.id = "memory-v2".to_owned();
    successor.value = serde_json::json!({"text": "the durable color is cobalt"});
    successor.search_text = Some("the durable color is cobalt".to_owned());
    successor.links.supersedes.insert("memory-v1".to_owned());
    let correction = service
        .correct(CorrectRequest {
            context: authenticated("correct", "workspace-a", "subject-a", [Capability::Correct]),
            idempotency_key: "correct-v2".to_owned(),
            target_id: "memory-v1".to_owned(),
            replacement: successor,
        })
        .expect("correct memory");
    assert_eq!(correction.commit_seq, 2);

    let current_old = service
        .recall(recall_request(
            "recall-old-current",
            "workspace-a",
            "subject-a",
            "amber",
            10,
        ))
        .expect("current old recall");
    assert!(current_old.hits.is_empty());
    let current_new = service
        .recall(recall_request(
            "recall-new-current",
            "workspace-a",
            "subject-a",
            "cobalt",
            10,
        ))
        .expect("current new recall");
    assert_eq!(current_new.hits[0].id, "memory-v2");
    assert_eq!(
        service
            .get_memory(get_request(
                "get-v1-current",
                "workspace-a",
                "subject-a",
                "memory-v1",
                None,
            ))
            .expect_err("superseded ID is absent from current ordinary lookup")
            .code,
        ErrorCode::NotFound
    );

    let mut historical = recall_request(
        "recall-old-historical",
        "workspace-a",
        "subject-a",
        "amber",
        10,
    );
    historical.at_commit = Some(1);
    let historical = service.recall(historical).expect("historical recall");
    assert_eq!(historical.hits[0].id, "memory-v1");
    assert_eq!(historical.trace.snapshot_seq, 1);
    assert_eq!(
        service
            .get_memory(get_request(
                "get-v1-historical",
                "workspace-a",
                "subject-a",
                "memory-v1",
                Some(1),
            ))
            .expect("historical v1")
            .document
            .value["text"],
        "the durable color is amber"
    );
    drop(service);

    let reopened = NativeService::open(&path, "db-correction", key).expect("reopen");
    let recalled = reopened
        .recall(recall_request(
            "restarted-v2",
            "workspace-a",
            "subject-a",
            "cobalt",
            10,
        ))
        .expect("restarted recall");
    assert_eq!(recalled.hits[0].id, "memory-v2");
    reopened.verify_native(true).expect("deep verify");
}

#[test]
fn authorization_precedes_corrupt_content_materialization() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(directory.path(), "db-policy", [11_u8; 32]).expect("open");
    service
        .publish_memory(publish_request(
            "publish",
            "workspace-a",
            "subject-a",
            "publish-secret",
            "memory-secret",
            "classified canary phrase",
        ))
        .expect("publish");

    let digest = digest_bytes(b"memory-secret");
    let mut transaction = service.engine.begin_write().expect("transaction");
    transaction
        .put(
            &service.keyspaces.content_history,
            history_key(&digest, 1),
            b"not-json-and-must-stay-inert".to_vec(),
        )
        .expect("stage corruption");
    transaction
        .commit(Durability::Sync)
        .expect("commit test corruption");

    let denied = service
        .recall(recall_request(
            "denied-recall",
            "workspace-b",
            "subject-b",
            "classified",
            10,
        ))
        .expect("forbidden corrupt content remains inert");
    assert!(denied.hits.is_empty());
    assert_eq!(denied.trace.authorized_candidates, 0);
    assert_eq!(
        service
            .recall(recall_request(
                "authorized-recall",
                "workspace-a",
                "subject-a",
                "classified",
                10,
            ))
            .expect_err("authorized materialization detects corruption")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("deep verification detects corruption")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn continuations_are_snapshot_and_authority_bound() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(directory.path(), "db-pages", [13_u8; 32]).expect("open");
    for index in 0..3 {
        service
            .publish_memory(publish_request(
                &format!("publish-{index}"),
                "workspace-a",
                "subject-a",
                &format!("key-{index}"),
                &format!("memory-{index}"),
                &format!("shared durable token item {index}"),
            ))
            .expect("publish page item");
    }
    let first_request = recall_request(
        "recall-page-1",
        "workspace-a",
        "subject-a",
        "shared durable token",
        1,
    );
    let first = service.recall(first_request.clone()).expect("first page");
    let continuation = first.continuation.expect("continuation");

    let mut second_request = first_request.clone();
    second_request.context.request_id = "recall-page-2".to_owned();
    second_request.continuation = Some(continuation.clone());
    let second = service.recall(second_request).expect("second page");
    assert_ne!(first.hits[0].id, second.hits[0].id);

    let mut rebound = first_request.clone();
    rebound.context.subject_id = "subject-b".to_owned();
    rebound.context.audiences = BTreeSet::from(["subject-b".to_owned()]);
    rebound.continuation = Some(continuation.clone());
    assert_eq!(
        service
            .recall(rebound)
            .expect_err("authority rebind rejected")
            .code,
        ErrorCode::InvalidContinuation
    );
    let mut tampered = first_request;
    tampered.continuation = Some(format!("x{continuation}"));
    assert_eq!(
        service
            .recall(tampered)
            .expect_err("tampered continuation rejected")
            .code,
        ErrorCode::InvalidContinuation
    );
}

#[test]
fn retraction_is_versioned_and_hard_delete_remains_explicitly_deferred() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(directory.path(), "db-retract", [15_u8; 32]).expect("open");
    service
        .publish_memory(publish_request(
            "publish",
            "workspace-a",
            "subject-a",
            "publish-1",
            "memory-1",
            "removable durable token",
        ))
        .expect("publish");
    let retracted = service
        .forget(ForgetRequest {
            context: authenticated("retract", "workspace-a", "subject-a", [Capability::Forget]),
            idempotency_key: "retract-1".to_owned(),
            target_id: "memory-1".to_owned(),
            mode: ForgetMode::Retract,
            reason: "user-request".to_owned(),
        })
        .expect("retract");
    assert_eq!(retracted.commit_seq, 2);
    assert!(
        service
            .recall(recall_request(
                "recall",
                "workspace-a",
                "subject-a",
                "removable",
                10,
            ))
            .expect("recall after retract")
            .hits
            .is_empty()
    );
    let explicit = service
        .get_memory(get_request(
            "get",
            "workspace-a",
            "subject-a",
            "memory-1",
            None,
        ))
        .expect("explicit lookup retains retracted history");
    assert_eq!(explicit.document.lifecycle, MemoryLifecycle::Retracted);

    let hard_delete = service
        .forget(ForgetRequest {
            context: authenticated(
                "hard-delete",
                "workspace-a",
                "subject-a",
                [Capability::Forget, Capability::HardDelete],
            ),
            idempotency_key: "delete-1".to_owned(),
            target_id: "memory-1".to_owned(),
            mode: ForgetMode::HardDelete,
            reason: "user-request".to_owned(),
        })
        .expect_err("hard delete deferred");
    assert_eq!(hard_delete.code, ErrorCode::Unsupported);
}

#[test]
fn concurrent_exact_retries_commit_once() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service = Arc::new(
        NativeService::open(directory.path(), "db-concurrent", [17_u8; 32]).expect("open"),
    );
    let request = publish_request(
        "publish",
        "workspace-a",
        "subject-a",
        "same-key",
        "memory-1",
        "concurrent durable token",
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let service = Arc::clone(&service);
        let request = request.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            service.publish_memory(request).expect("concurrent publish")
        }));
    }
    barrier.wait();
    let responses = workers
        .into_iter()
        .map(|worker| worker.join().expect("join"))
        .collect::<Vec<_>>();
    assert_eq!(responses.iter().filter(|value| value.replayed).count(), 1);
    assert_eq!(responses[0].commit_seq, responses[1].commit_seq);
    assert_eq!(service.engine.head_sequence().expect("head"), 2);
}

#[test]
fn writes_have_linear_fixed_record_growth_without_whole_archive_blobs() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(directory.path(), "db-scale", [19_u8; 32]).expect("open");
    for index in 0..64 {
        service
            .publish_memory(publish_request(
                &format!("request-{index}"),
                "workspace-a",
                "subject-a",
                &format!("key-{index}"),
                &format!("memory-{index}"),
                &format!("bounded incremental payload {index}"),
            ))
            .expect("publish incremental record");
    }
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        snapshot
            .scan_prefix(&service.keyspaces.content_history, b"")
            .expect("contents")
            .len(),
        64
    );
    assert_eq!(
        snapshot
            .scan_prefix(&service.keyspaces.events, b"")
            .expect("events")
            .len(),
        64
    );
    for keyspace in service.keyspaces.all() {
        for entry in snapshot.scan_prefix(keyspace, b"").expect("scan") {
            assert!(entry.value.len() < 64 * 1024);
            assert!(
                !entry
                    .value
                    .windows(b"contextdb.logical.v1".len())
                    .any(|window| window == b"contextdb.logical.v1")
            );
        }
    }
    assert_eq!(service.engine.head_sequence().expect("head"), 65);
    service.verify_native(true).expect("deep verify");
}

#[test]
fn workspace_sequences_are_isolated_from_global_commit_order() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(directory.path(), "db-tenants", [21_u8; 32]).expect("open");
    let a1 = service
        .publish_memory(publish_request(
            "a1",
            "workspace-a",
            "subject-a",
            "a1",
            "memory-a1",
            "alpha one",
        ))
        .expect("a1");
    let b1 = service
        .publish_memory(publish_request(
            "b1",
            "workspace-b",
            "subject-b",
            "b1",
            "memory-b1",
            "beta one",
        ))
        .expect("b1");
    let a2 = service
        .publish_memory(publish_request(
            "a2",
            "workspace-a",
            "subject-a",
            "a2",
            "memory-a2",
            "alpha two",
        ))
        .expect("a2");
    assert_eq!((a1.commit_seq, b1.commit_seq, a2.commit_seq), (1, 1, 2));
    assert_eq!(service.verify_native(true).expect("verify").commit_seq, 3);
    let mut historical_a = recall_request("historical-a", "workspace-a", "subject-a", "alpha", 10);
    historical_a.at_commit = Some(1);
    let result = service.recall(historical_a).expect("historical a");
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].id, "memory-a1");
    let tenant_b = service
        .recall(recall_request(
            "current-b",
            "workspace-b",
            "subject-b",
            "beta",
            10,
        ))
        .expect("current b");
    assert_eq!(tenant_b.trace.authorized_candidates, 1);
    assert_eq!(tenant_b.hits.len(), 1);
    assert_eq!(tenant_b.hits[0].id, "memory-b1");
}

#[test]
fn observe_is_durable_but_not_semantically_recallable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let service = NativeService::open(directory.path(), "db-observe", [23_u8; 32]).expect("open");
    let context = request_context("observe", "workspace-a", "subject-a");
    let response = service
        .observe(ObserveRequest {
            context: context.clone(),
            idempotency_key: "observe-key".to_owned(),
            observation_id: "observation-1".to_owned(),
            metadata: BTreeMap::from([("source".to_owned(), serde_json::json!("chat"))]),
            content: serde_json::json!({"text": "raw evidence only"}),
            access: trusted_legacy_policy(&context),
        })
        .expect("observe");
    assert_eq!(response.commit_seq, 1);
    assert_eq!(response.watermarks.journal, 1);
    assert_eq!(response.watermarks.semantic, 0);
    assert!(
        service
            .recall(recall_request(
                "recall",
                "workspace-a",
                "subject-a",
                "raw evidence",
                10,
            ))
            .expect("recall")
            .hits
            .is_empty()
    );
    service.verify_native(true).expect("deep verify");
}

#[test]
fn document_validation_rejects_policy_or_vector_widening() {
    let access = trusted_explicit_policy(&request_context("request", "workspace-a", "subject-a"));
    let mut document = MemoryDocument {
        id: "memory".to_owned(),
        kind: MemoryRecordKind::SemanticObject,
        access,
        valid_time: DomainTimeRange::default(),
        lifecycle: MemoryLifecycle::Active,
        links: MemoryLinks::default(),
        value: serde_json::json!({"text": "value"}),
        search_text: Some("value".to_owned()),
        vector: Some(vec![f32::NAN]),
        attributes: BTreeMap::new(),
    };
    assert_eq!(
        validate_memory_document(&document)
            .expect_err("nonfinite vector")
            .code,
        ErrorCode::InvalidArgument
    );
    document.vector = None;
    document.access.owners.clear();
    assert_eq!(
        validate_memory_document(&document)
            .expect_err("ownerless policy")
            .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn admin_backup_restores_all_native_keyspaces_into_a_pristine_target_and_reopens() {
    let source_directory = tempfile::tempdir().expect("source tempdir");
    let source = NativeService::open(source_directory.path(), "db-backup", [41_u8; 32])
        .expect("open source");
    source
        .publish_memory(publish_request(
            "publish-a",
            "workspace-a",
            "subject-a",
            "publish-a",
            "memory-a",
            "backup roundtrip amber sentinel",
        ))
        .expect("publish workspace a");
    source
        .publish_memory(publish_request(
            "publish-b",
            "workspace-b",
            "subject-b",
            "publish-b",
            "memory-b",
            "backup roundtrip cobalt sentinel",
        ))
        .expect("publish workspace b");
    let observation_context = request_context("observe", "workspace-a", "subject-a");
    source
        .observe(ObserveRequest {
            context: observation_context.clone(),
            idempotency_key: "observe-backup".to_owned(),
            observation_id: "observation-backup".to_owned(),
            metadata: BTreeMap::from([("source".to_owned(), serde_json::json!("test"))]),
            content: serde_json::json!({"private": "raw observation sentinel"}),
            access: trusted_legacy_policy(&observation_context),
        })
        .expect("observe raw evidence");

    let unauthorized = source
        .create_backup(CreateBackupRequest {
            context: authenticated("backup-denied", "workspace-a", "subject-a", []),
        })
        .expect_err("backup requires admin");
    assert_eq!(unauthorized.code, ErrorCode::Unauthorized);

    let admin = authenticated(
        "backup-create",
        "workspace-a",
        "subject-a",
        [Capability::Admin],
    );
    let status = source
        .get_status(GetStatusRequest {
            context: admin.clone(),
        })
        .expect("native status");
    assert_eq!(status.capability_manifest.profile, status.profile);
    assert!(!status.capability_manifest.server_v1_release_ready);
    assert_eq!(
        status
            .capability_manifest
            .capability("admin_native_logical_backup"),
        Some(contextdb_service::CapabilityState::Available)
    );
    assert_eq!(
        status
            .capability_manifest
            .capability("admin_native_pristine_restore"),
        Some(contextdb_service::CapabilityState::Available)
    );
    assert_eq!(
        status.capability_manifest.capability("archive_export"),
        Some(contextdb_service::CapabilityState::Unsupported)
    );
    assert_eq!(
        status.capability_manifest.capability("live_restore"),
        Some(contextdb_service::CapabilityState::Unsupported)
    );
    for capability in [
        "candidate_hierarchy_dag",
        "policy_first_candidate_recall",
        "policy_first_candidate_traversal",
        "quarantined_memory_proposals",
    ] {
        assert_eq!(
            status.capability_manifest.capability(capability),
            Some(contextdb_service::CapabilityState::Available),
            "native candidate executor must advertise {capability}"
        );
    }
    for capability in [
        "background_semantic_adjudication",
        "consolidate",
        "native_graph_store",
        "observation_semantic_extraction",
        "reflect",
    ] {
        assert_eq!(
            status.capability_manifest.capability(capability),
            Some(contextdb_service::CapabilityState::Unsupported),
            "candidate-only execution must not overclaim {capability}"
        );
    }
    let backup = source
        .create_backup(CreateBackupRequest {
            context: admin.clone(),
        })
        .expect("create native backup");
    assert_eq!(backup.format, backup::native_backup_format());
    assert_eq!(backup.digest, digest_bytes(&backup.bytes));
    assert_eq!(backup.commit_seq, 3);
    assert!(backup.bytes.len() < backup::maximum_native_backup_bytes());
    let repeated = source
        .create_backup(CreateBackupRequest {
            context: admin.clone(),
        })
        .expect("repeat exact backup");
    assert_eq!(repeated, backup);

    let target_directory = tempfile::tempdir().expect("target tempdir");
    let target_path = target_directory.path().join("native");
    let target =
        NativeService::open(&target_path, "db-backup", [41_u8; 32]).expect("open pristine target");
    let restored = target
        .restore_backup(RestoreBackupRequest {
            context: authenticated(
                "backup-restore",
                "workspace-a",
                "subject-a",
                [Capability::Admin],
            ),
            format: backup.format.clone(),
            bytes: backup.bytes.clone(),
            digest: backup.digest.clone(),
        })
        .expect("restore native backup");
    assert_eq!(restored.commit_seq, 3);
    assert_eq!(restored.watermarks.journal, 2);
    assert_eq!(
        target
            .recall(recall_request(
                "recall-restored-a",
                "workspace-a",
                "subject-a",
                "amber",
                10,
            ))
            .expect("recall workspace a")
            .hits[0]
            .id,
        "memory-a"
    );
    assert_eq!(
        target
            .recall(recall_request(
                "recall-restored-b",
                "workspace-b",
                "subject-b",
                "cobalt",
                10,
            ))
            .expect("recall workspace b")
            .hits[0]
            .id,
        "memory-b"
    );
    let restored_digest = target
        .verify_native(true)
        .expect("verify restored target")
        .archive_digest;
    drop(target);

    let reopened = NativeService::open(&target_path, "db-backup", [41_u8; 32])
        .expect("reopen restored target");
    assert_eq!(
        reopened
            .verify_native(true)
            .expect("verify reopened target")
            .archive_digest,
        restored_digest
    );
    assert_eq!(
        reopened
            .recall(recall_request(
                "recall-after-reopen",
                "workspace-a",
                "subject-a",
                "amber",
                10,
            ))
            .expect("recall after reopen")
            .hits[0]
            .id,
        "memory-a"
    );
}

#[test]
fn restore_tamper_identity_and_non_pristine_fail_before_native_mutation() {
    let source_directory = tempfile::tempdir().expect("source tempdir");
    let source = NativeService::open(source_directory.path(), "db-backup-guard", [43_u8; 32])
        .expect("open source");
    source
        .publish_memory(publish_request(
            "publish-source",
            "workspace-a",
            "subject-a",
            "publish-source",
            "memory-source",
            "source backup sentinel",
        ))
        .expect("publish source");
    let backup = source
        .create_backup(CreateBackupRequest {
            context: authenticated(
                "backup-create",
                "workspace-a",
                "subject-a",
                [Capability::Admin],
            ),
        })
        .expect("create backup");

    let target_directory = tempfile::tempdir().expect("target tempdir");
    let target = NativeService::open(target_directory.path(), "db-backup-guard", [43_u8; 32])
        .expect("open target");
    let baseline = target.verify_native(true).expect("pristine baseline");
    let denied_malformed = target
        .restore_backup(RestoreBackupRequest {
            context: authenticated("restore-denied-malformed", "workspace-a", "subject-a", []),
            format: "attacker-controlled-format".to_owned(),
            bytes: b"attacker-controlled-content".to_vec(),
            digest: "attacker-controlled-digest".to_owned(),
        })
        .expect_err("authorization precedes restore parsing");
    let denied_valid = target
        .restore_backup(RestoreBackupRequest {
            context: authenticated("restore-denied-valid", "workspace-a", "subject-a", []),
            format: backup.format.clone(),
            bytes: backup.bytes.clone(),
            digest: backup.digest.clone(),
        })
        .expect_err("authorization also precedes valid archive inspection");
    assert_eq!(denied_malformed, denied_valid);
    assert_eq!(denied_valid.code, ErrorCode::Unauthorized);
    assert_eq!(
        target.verify_native(true).expect("unchanged after denial"),
        baseline
    );

    let mut tampered_bytes = backup.bytes.clone();
    let tamper_index = tampered_bytes.len() / 2;
    tampered_bytes[tamper_index] ^= 1;
    let tampered = target
        .restore_backup(RestoreBackupRequest {
            context: authenticated(
                "restore-tampered",
                "workspace-a",
                "subject-a",
                [Capability::Admin],
            ),
            format: backup.format.clone(),
            digest: digest_bytes(&tampered_bytes),
            bytes: tampered_bytes,
        })
        .expect_err("internal footer rejects recomputed outer digest");
    assert_eq!(tampered.code, ErrorCode::IntegrityFailure);
    assert_eq!(
        target.verify_native(true).expect("unchanged after tamper"),
        baseline
    );

    let wrong_identity_directory = tempfile::tempdir().expect("wrong identity tempdir");
    let wrong_identity = NativeService::open(
        wrong_identity_directory.path(),
        "db-another-identity",
        [43_u8; 32],
    )
    .expect("open wrong identity target");
    let wrong_baseline = wrong_identity
        .verify_native(true)
        .expect("wrong identity baseline");
    let identity_error = wrong_identity
        .restore_backup(RestoreBackupRequest {
            context: authenticated(
                "restore-wrong-identity",
                "workspace-a",
                "subject-a",
                [Capability::Admin],
            ),
            format: backup.format.clone(),
            bytes: backup.bytes.clone(),
            digest: backup.digest.clone(),
        })
        .expect_err("database identity mismatch rejected");
    assert_eq!(identity_error.code, ErrorCode::FormatIncompatible);
    assert_eq!(
        wrong_identity
            .verify_native(true)
            .expect("wrong identity unchanged"),
        wrong_baseline
    );

    target
        .publish_memory(publish_request(
            "publish-target",
            "workspace-a",
            "subject-a",
            "publish-target",
            "memory-target",
            "non-pristine target sentinel",
        ))
        .expect("advance target");
    let occupied_baseline = target
        .verify_native(true)
        .expect("occupied target baseline");
    let occupied = target
        .restore_backup(RestoreBackupRequest {
            context: authenticated(
                "restore-occupied",
                "workspace-a",
                "subject-a",
                [Capability::Admin],
            ),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect_err("live replacement is forbidden");
    assert_eq!(occupied.code, ErrorCode::Unsupported);
    assert_eq!(
        occupied.violated_policy.as_deref(),
        Some("restore:pristine-target-only")
    );
    assert_eq!(
        target
            .verify_native(true)
            .expect("occupied target unchanged"),
        occupied_baseline
    );
    assert_eq!(
        target
            .recall(recall_request(
                "recall-target",
                "workspace-a",
                "subject-a",
                "non-pristine",
                10,
            ))
            .expect("target data retained")
            .hits[0]
            .id,
        "memory-target"
    );
}
