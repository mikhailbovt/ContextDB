#![allow(
    clippy::expect_used,
    reason = "test fixtures use immediate failure semantics"
)]

use std::collections::{BTreeMap, BTreeSet};

use contextdb_reference::{
    AccessLabel, Consent as ReferenceConsent, ContextDb, Lifecycle, LogicalRecord, Mutation,
    RecordKind, SemanticLinks, SemanticTransaction, Sensitivity as ReferenceSensitivity, ValidTime,
};
use serde_json::json;

use crate::{
    AccessPolicy, AuthenticatedRequestContext, AuthenticationEvidence, Capability,
    CognitiveMemoryService, Compression, Consent, CorrectRequest, CreateBackupRequest,
    DomainTimeRange, ErrorCode, ExplainRecallRequest, ExportRequest, ForgetMode, ForgetRequest,
    GetMemoryRequest, GetTimelineRequest, HighLevelControlRequest, HighLevelSemanticStatus,
    HighLevelWriteRequest, HostArchiveAuthority, ImportRequest, IngestDisposition, IngestFrame,
    IngestFrameValue, MemoryDocument, MemoryEventKind, MemoryLifecycle, MemoryLinks,
    MemoryRecordKind, ObserveRequest, PublishMemoryRequest, RecallRequest, ReferenceService,
    RequestContext, RestoreBackupRequest, Sensitivity, SnapshotComplete, SourceRevisionManifest,
    StreamObservation, SubscribeRequest, TraverseDirection, TraverseRequest, VerifyRequest,
    Watermarks, ordered_items_digest,
};

fn context(subject: &str, purpose: &str, clearance: Sensitivity) -> RequestContext {
    RequestContext {
        request_id: format!("request-{subject}-{purpose}"),
        workspace_id: "workspace-a".to_owned(),
        subject_id: subject.to_owned(),
        audiences: BTreeSet::from([subject.to_owned()]),
        scopes: BTreeSet::from(["scope-a".to_owned()]),
        purpose: purpose.to_owned(),
        clearance,
    }
}

fn authenticated(subject: &str, grants: &[Capability]) -> AuthenticatedRequestContext {
    AuthenticatedRequestContext {
        request: context(subject, "recall", Sensitivity::Restricted),
        actor_id: subject.to_owned(),
        agent_id: "agent:test".to_owned(),
        session_id: Some("session:test".to_owned()),
        capability_grants: grants.iter().copied().collect(),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "channel:test".to_owned(),
            peer_identity: subject.to_owned(),
            binding_digest: "11".repeat(32),
        },
    }
}

fn policy(owner: &str, audience: &str, retrievable: bool) -> AccessPolicy {
    AccessPolicy {
        workspace_id: "workspace-a".to_owned(),
        scopes: BTreeSet::from(["scope-a".to_owned()]),
        owners: BTreeSet::from([owner.to_owned()]),
        audience: BTreeSet::from([audience.to_owned()]),
        audience_purpose_grants: BTreeMap::new(),
        purposes: BTreeSet::from(["recall".to_owned()]),
        sensitivity: Sensitivity::Private,
        consent: Consent::Granted,
        retrievable,
    }
}

fn high_level_write(operation: &str, grants: &[Capability]) -> HighLevelWriteRequest {
    let mut context = authenticated("alice", grants);
    context.session_id = Some("session:high-level".to_owned());
    HighLevelWriteRequest {
        context,
        idempotency_key: format!("idempotency:{operation}"),
        target_subject_id: "alice".to_owned(),
        session_id: Some("session:high-level".to_owned()),
        logical_id: format!("logical:{operation}"),
        access: policy("alice", "alice", true),
        payload: json!({"text": "bounded high-level content"}),
        references: BTreeSet::from(["episode:one".to_owned()]),
    }
}

#[test]
fn high_level_conversation_and_memory_writes_are_durable_idempotent_and_session_bound() {
    let service = ReferenceService::new("high-level-write", [0x71; 32]).expect("service");
    let request = high_level_write("begin-session", &[Capability::Observe]);
    let first = service
        .begin_session(request.clone())
        .expect("durable begin session");
    let replay = service.begin_session(request).expect("exact replay");
    assert_eq!(first.operation, "BeginSession");
    assert_eq!(first.semantic_status, HighLevelSemanticStatus::Pending);
    assert!(!first.receipt.replayed);
    assert!(replay.receipt.replayed);
    assert_eq!(first.receipt.request_digest, replay.receipt.request_digest);

    let mut wrong_session = high_level_write("after-turn", &[Capability::Observe]);
    wrong_session.session_id = Some("session:other".to_owned());
    assert_eq!(
        service
            .after_turn(wrong_session)
            .expect_err("session binding")
            .code,
        ErrorCode::PermissionDenied
    );
}

#[test]
fn high_level_controls_authenticate_and_authorize_before_typed_profile_gap() {
    let service = ReferenceService::new("high-level-control", [0x72; 32]).expect("service");
    let request = HighLevelControlRequest {
        context: authenticated("alice", &[]),
        idempotency_key: "idempotency:pin".to_owned(),
        target_subject_id: "alice".to_owned(),
        target_id: "memory:one".to_owned(),
        parameters: json!({"secret": "not materialized by the reference profile"}),
    };
    assert_eq!(
        service
            .pin(request.clone())
            .expect_err("missing capability")
            .code,
        ErrorCode::Unauthorized
    );
    let mut allowed = request;
    allowed
        .context
        .capability_grants
        .insert(Capability::Correct);
    assert_eq!(
        service.pin(allowed).expect_err("typed profile gap").code,
        ErrorCode::Unsupported
    );
}

fn semantic_control(operation: &str, parameters: serde_json::Value) -> HighLevelControlRequest {
    HighLevelControlRequest {
        context: authenticated("owner", &[Capability::Correct, Capability::ReadMemory]),
        idempotency_key: format!("idempotency:{operation}"),
        target_subject_id: "owner".to_owned(),
        target_id: "allowed-a".to_owned(),
        parameters,
    }
}

#[test]
fn suppression_is_atomic_idempotent_and_current_policy_hides_historical_snapshots() {
    let service = seeded_service();
    let historical_commit = service
        .get_timeline(GetTimelineRequest {
            context: authenticated("alice", &[Capability::ReadMemory]),
            record_id: "allowed-a".to_owned(),
            expected_kind: MemoryRecordKind::SemanticObject,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("seed timeline")
        .snapshot_seq;
    let request = semantic_control("suppress", json!({"schema_version": 1}));
    let first = service.suppress(request.clone()).expect("suppress");
    let mut retry = request.clone();
    retry.context.request.request_id = "request:suppress-retry".to_owned();
    retry.context.authentication = AuthenticationEvidence::AuthenticatedChannel {
        channel_id: "channel:suppress-retry".to_owned(),
        peer_identity: "owner".to_owned(),
        binding_digest: "44".repeat(32),
    };
    let replay = service.suppress(retry).expect("suppress replay");
    assert_eq!(first.commit_seq, replay.commit_seq);
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.request_digest, replay.request_digest);

    for at_commit in [None, Some(historical_commit)] {
        let denied = service
            .get_timeline(GetTimelineRequest {
                context: authenticated("alice", &[Capability::ReadMemory]),
                record_id: "allowed-a".to_owned(),
                expected_kind: MemoryRecordKind::SemanticObject,
                at_commit,
                max_revisions: 10,
            })
            .expect_err("current suppression overlays every snapshot");
        assert_eq!(denied.code, ErrorCode::PermissionDenied);
        let recall = service
            .recall(RecallRequest {
                context: context("alice", "recall", Sensitivity::Restricted),
                query: "Japan jazz bar".to_owned(),
                page_size: 10,
                at_commit,
                continuation: None,
            })
            .expect("suppressed recall is a valid empty/filtered result");
        assert!(!recall.hits.iter().any(|hit| hit.id == "allowed-a"));
    }

    let mut changed = request;
    changed.context.session_id = Some("session:changed-authority".to_owned());
    assert_eq!(
        service
            .suppress(changed)
            .expect_err("changed replay authority conflicts")
            .code,
        ErrorCode::IdempotencyConflict
    );
}

#[test]
fn suppression_overlay_blocks_historical_vector_and_graph_routes() {
    let service = typed_memory_service();
    let context = authenticated(
        "owner",
        &[
            Capability::Correct,
            Capability::ReadMemory,
            Capability::Traverse,
        ],
    );
    let historical_commit = service
        .get_timeline(GetTimelineRequest {
            context: authenticated("alice", &[Capability::ReadMemory]),
            record_id: "node-a".to_owned(),
            expected_kind: MemoryRecordKind::Node,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("seed graph")
        .snapshot_seq;
    service
        .suppress(HighLevelControlRequest {
            context,
            idempotency_key: "idempotency:suppress-edge".to_owned(),
            target_subject_id: "owner".to_owned(),
            target_id: "edge-a-b".to_owned(),
            parameters: json!({"schema_version": 1}),
        })
        .expect("suppress edge");
    let traversal = service
        .traverse(TraverseRequest {
            context: authenticated("alice", &[Capability::Traverse]),
            start_ids: vec!["node-a".to_owned()],
            direction: TraverseDirection::Outgoing,
            predicate_ids: BTreeSet::new(),
            max_hops: 2,
            max_nodes: 10,
            at_commit: Some(historical_commit),
        })
        .expect("suppressed edge is filtered, not materialized");
    assert!(traversal.node_ids.is_empty());

    let database = ContextDb::new("vector-suppression").expect("database");
    database
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "seed-vector".to_owned(),
            mutations: vec![Mutation::Put {
                record: LogicalRecord {
                    id: "vector-memory".to_owned(),
                    kind: RecordKind::SemanticObject,
                    access: reference_access("alice"),
                    valid_time: ValidTime::UNBOUNDED,
                    lifecycle: Lifecycle::Active,
                    links: SemanticLinks::default(),
                    value: json!({"fact": "vector sentinel"}),
                    search_text: None,
                    vector: Some(vec![1.0, 0.0]),
                    attributes: BTreeMap::new(),
                },
                expected_revision: None,
            }],
        })
        .expect("seed vector");
    let old_snapshot = database.snapshot().expect("old snapshot");
    database
        .commit(SemanticTransaction {
            base_seq: old_snapshot.commit_seq,
            idempotency_key: "suppress-vector".to_owned(),
            mutations: vec![Mutation::Put {
                record: LogicalRecord {
                    id: "vector-memory".to_owned(),
                    kind: RecordKind::SemanticObject,
                    access: reference_access("alice"),
                    valid_time: ValidTime::UNBOUNDED,
                    lifecycle: Lifecycle::Suppressed,
                    links: SemanticLinks::default(),
                    value: json!({"fact": "vector sentinel"}),
                    search_text: None,
                    vector: Some(vec![1.0, 0.0]),
                    attributes: BTreeMap::new(),
                },
                expected_revision: Some(1),
            }],
        })
        .expect("suppress vector");
    let vector = database
        .vector_search(
            &[1.0, 0.0],
            10,
            &old_snapshot,
            &contextdb_reference::Principal {
                subject: "alice".to_owned(),
                audiences: BTreeSet::from(["alice".to_owned()]),
                workspace: "workspace-a".to_owned(),
                scopes: BTreeSet::from(["scope-a".to_owned()]),
                purpose: "recall".to_owned(),
                clearance: ReferenceSensitivity::Restricted,
            },
        )
        .expect("historical vector query");
    assert!(vector.value.is_empty());
    assert_eq!(vector.trace.authorized_candidates, 0);
}

#[test]
fn semantic_controls_authorize_before_malformed_parameters_and_preserve_payload_history() {
    let service = seeded_service();
    let mut unauthorized = semantic_control("unauthorized-suppress", json!({"secret": [1, 2, 3]}));
    unauthorized.context.capability_grants.clear();
    assert_eq!(
        service
            .suppress(unauthorized)
            .expect_err("authorization precedes parameter schema")
            .code,
        ErrorCode::Unauthorized
    );

    let before = service
        .get_timeline(GetTimelineRequest {
            context: authenticated("alice", &[Capability::ReadMemory]),
            record_id: "allowed-a".to_owned(),
            expected_kind: MemoryRecordKind::SemanticObject,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("before policy revision");
    let original = before.revisions[0].document.clone();
    let mut change = semantic_control(
        "change-audience",
        json!({
            "schema_version": 1,
            "audiences": ["alice", "team:one"],
            "audience_purpose_grants": {
                "@owner": ["recall"],
                "alice": ["recall"],
                "team:one": ["recall"]
            }
        }),
    );
    change
        .context
        .request
        .audiences
        .insert("team:one".to_owned());
    service.change_audience(change).expect("audience revision");
    let after = service
        .get_timeline(GetTimelineRequest {
            context: authenticated("alice", &[Capability::ReadMemory]),
            record_id: "allowed-a".to_owned(),
            expected_kind: MemoryRecordKind::SemanticObject,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("policy history");
    assert_eq!(after.revisions.len(), 2);
    assert_eq!(after.revisions[0].document, original);
    let revised = &after.revisions[1].document;
    assert_eq!(revised.value, original.value);
    assert_eq!(revised.search_text, original.search_text);
    assert_eq!(revised.vector, original.vector);
    assert_eq!(revised.attributes, original.attributes);
    assert!(revised.access.audience.contains("team:one"));
}

#[test]
fn shared_memory_publish_and_revoke_are_exact_policy_revisions() {
    let service = seeded_service();
    let mut install_exact = semantic_control(
        "install-exact-audience",
        json!({
            "schema_version": 1,
            "audiences": ["alice"],
            "audience_purpose_grants": {"@owner": ["recall"], "alice": ["recall"]}
        }),
    );
    service
        .change_audience(install_exact.clone())
        .expect("install exact policy");
    install_exact.idempotency_key = "idempotency:publish-team".to_owned();
    install_exact
        .context
        .request
        .audiences
        .insert("team:one".to_owned());
    install_exact.parameters = json!({
        "schema_version": 1,
        "shared_audience_id": "team:one",
        "purposes": ["recall"]
    });
    service
        .publish_to_shared_memory(install_exact.clone())
        .expect("publish shared policy");

    install_exact.idempotency_key = "idempotency:revoke-team".to_owned();
    install_exact.parameters = json!({
        "schema_version": 1,
        "shared_audience_id": "team:one"
    });
    service
        .revoke_shared_memory(install_exact)
        .expect("revoke shared policy");
    let timeline = service
        .get_timeline(GetTimelineRequest {
            context: authenticated("alice", &[Capability::ReadMemory]),
            record_id: "allowed-a".to_owned(),
            expected_kind: MemoryRecordKind::SemanticObject,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("shared policy timeline");
    assert_eq!(timeline.revisions.len(), 4);
    assert!(
        !timeline
            .revisions
            .last()
            .expect("current policy")
            .document
            .access
            .audience
            .contains("team:one")
    );
}

#[test]
fn high_level_identity_and_idempotency_are_isolated_across_tenants() {
    let service = ReferenceService::new("high-level-tenants", [0x75; 32]).expect("service");
    let first = high_level_write("same-logical-id", &[Capability::Observe]);
    let mut second = first.clone();
    second.context.request.request_id = "request:tenant-b".to_owned();
    second.context.request.workspace_id = "workspace-b".to_owned();
    second.context.request.subject_id = "bob".to_owned();
    second.context.request.audiences = BTreeSet::from(["bob".to_owned()]);
    second.context.request.scopes = BTreeSet::from(["scope-b".to_owned()]);
    second.context.actor_id = "bob".to_owned();
    second.context.authentication = AuthenticationEvidence::AuthenticatedChannel {
        channel_id: "channel:tenant-b".to_owned(),
        peer_identity: "bob".to_owned(),
        binding_digest: "22".repeat(32),
    };
    second.target_subject_id = "bob".to_owned();
    second.access.workspace_id = "workspace-b".to_owned();
    second.access.scopes = BTreeSet::from(["scope-b".to_owned()]);
    second.access.owners = BTreeSet::from(["bob".to_owned()]);
    second.access.audience = BTreeSet::from(["bob".to_owned()]);

    let first = service.remember(first).expect("tenant A capture");
    let second = service.remember(second).expect("tenant B capture");
    assert_eq!(first.logical_id, second.logical_id);
    assert!(!first.receipt.replayed);
    assert!(!second.receipt.replayed);
    assert_ne!(first.receipt.commit_seq, second.receipt.commit_seq);
    assert_ne!(first.receipt.request_digest, second.receipt.request_digest);
}

fn reference_access(audience: &str) -> AccessLabel {
    AccessLabel {
        workspace: "workspace-a".to_owned(),
        scopes: BTreeSet::from(["scope-a".to_owned()]),
        owners: BTreeSet::from(["owner".to_owned()]),
        audience: BTreeSet::from([audience.to_owned()]),
        audience_purpose_grants: BTreeMap::new(),
        purposes: BTreeSet::from(["recall".to_owned()]),
        sensitivity: ReferenceSensitivity::Private,
        consent: ReferenceConsent::Granted,
        retrievable: true,
    }
}

fn seeded_service() -> ReferenceService {
    let database = ContextDb::new("service-test").expect("database");
    let records = [
        ("allowed-a", "Japan jazz bar", "alice"),
        ("allowed-b", "Japan jazz night", "alice"),
        (
            "denied-super-score",
            "Japan Japan Japan jazz bar",
            "mallory",
        ),
    ];
    let mutations = records
        .into_iter()
        .map(|(id, text, audience)| Mutation::Put {
            record: LogicalRecord {
                id: id.to_owned(),
                kind: RecordKind::SemanticObject,
                access: reference_access(audience),
                valid_time: ValidTime::UNBOUNDED,
                lifecycle: Lifecycle::Active,
                links: SemanticLinks::default(),
                value: json!({"fact": text}),
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
            idempotency_key: "seed-records".to_owned(),
            mutations,
        })
        .expect("seed commit");
    ReferenceService::from_database(database, [7; 32]).expect("service")
}

fn typed_memory_service() -> ReferenceService {
    fn record(id: &str, kind: RecordKind, value: serde_json::Value) -> LogicalRecord {
        LogicalRecord {
            id: id.to_owned(),
            kind,
            access: reference_access("alice"),
            valid_time: ValidTime::UNBOUNDED,
            lifecycle: Lifecycle::Active,
            links: SemanticLinks::default(),
            value,
            search_text: None,
            vector: None,
            attributes: BTreeMap::new(),
        }
    }

    let database = ContextDb::new("typed-memory-service").expect("database");
    let node_a = record("node-a", RecordKind::Node, json!({"name": "A"}));
    let node_b = record("node-b", RecordKind::Node, json!({"name": "B"}));
    let node_private = record(
        "node-private",
        RecordKind::Node,
        json!({"name": "authorized node behind denied edge"}),
    );
    let evidence = record(
        "evidence-a",
        RecordKind::Evidence,
        json!({"selector": "line:1"}),
    );
    let mut edge = record("edge-a-b", RecordKind::Edge, json!({"kind": "next"}));
    edge.links.source = Some("node-a".to_owned());
    edge.links.target = Some("node-b".to_owned());
    edge.links.predicate = Some("next".to_owned());
    let mut denied_edge = record(
        "edge-a-private",
        RecordKind::Edge,
        json!({"secret": "must not influence traversal"}),
    );
    denied_edge.access = reference_access("mallory");
    denied_edge.links.source = Some("node-a".to_owned());
    denied_edge.links.target = Some("node-private".to_owned());
    denied_edge.links.predicate = Some("next".to_owned());
    let mut claim_a = record("claim-a", RecordKind::Claim, json!("A"));
    claim_a.links.subject = Some("node-a".to_owned());
    claim_a.links.predicate = Some("status".to_owned());
    claim_a.links.single_valued = true;
    claim_a.links.conflict_set = Some("conflict-a".to_owned());
    claim_a.links.evidence.insert("evidence-a".to_owned());
    let mut claim_b = record("claim-b", RecordKind::Claim, json!("B"));
    claim_b.links = claim_a.links.clone();
    let mut conflict = record(
        "conflict-a",
        RecordKind::Conflict,
        json!({"resolution": "open"}),
    );
    conflict.links.conflict_members = BTreeSet::from(["claim-a".to_owned(), "claim-b".to_owned()]);
    let mutations = [
        node_a,
        node_b,
        node_private,
        evidence,
        edge,
        denied_edge,
        claim_a,
        claim_b,
        conflict,
    ]
    .into_iter()
    .map(|record| Mutation::Put {
        record,
        expected_revision: None,
    })
    .collect();
    database
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "typed-memory-seed".to_owned(),
            mutations,
        })
        .expect("typed memory seed");
    ReferenceService::from_database(database, [13; 32]).expect("service")
}

#[test]
fn observe_replay_and_conflict_have_the_same_contract_at_the_embedded_boundary() {
    let service = ReferenceService::new("observe-test", [3; 32]).expect("service");
    let request = ObserveRequest {
        context: context("alice", "recall", Sensitivity::Private),
        idempotency_key: "observe-key".to_owned(),
        observation_id: "observation-a".to_owned(),
        metadata: BTreeMap::from([("stream".to_owned(), json!("chat"))]),
        content: json!({"text": "hello"}),
        access: policy("alice", "alice", true),
    };
    let first = service.observe(request.clone()).expect("first observe");
    let replay = service.observe(request.clone()).expect("replay observe");
    assert_eq!(first.commit_seq, replay.commit_seq);
    assert!(!first.replayed);
    assert!(replay.replayed);
    let mut conflict = request;
    conflict.content = json!({"text": "different"});
    assert_eq!(
        service.observe(conflict).expect_err("conflict").code,
        ErrorCode::IdempotencyConflict
    );
}

#[test]
fn legacy_observe_policy_is_minted_from_trusted_context_for_unary_and_stream_paths() {
    let service = ReferenceService::new("trusted-observe-policy", [0x3a; 32]).expect("service");
    let valid = ObserveRequest {
        context: context("alice", "recall", Sensitivity::Restricted),
        idempotency_key: "trusted-policy-valid".to_owned(),
        observation_id: "observation:trusted-valid".to_owned(),
        metadata: BTreeMap::new(),
        content: json!({"text": "same-subject legacy content"}),
        access: policy("alice", "alice", true),
    };
    let mut forged = valid.clone();
    forged.idempotency_key = "trusted-policy-forged".to_owned();
    forged.observation_id = "observation:trusted-forged".to_owned();
    forged.access.owners = BTreeSet::from(["mallory".to_owned()]);
    forged.access.audience = BTreeSet::from(["mallory".to_owned(), "*".to_owned()]);
    forged.access.scopes.insert("scope:forged".to_owned());
    forged.access.sensitivity = Sensitivity::Public;
    assert_eq!(
        service
            .observe(forged.clone())
            .expect_err("caller-authored policy must be rejected")
            .code,
        ErrorCode::PermissionDenied
    );
    service
        .observe(valid)
        .expect("trusted template remains usable");

    let stream_context = authenticated("alice", &[Capability::StreamIngest]);
    let streamed = StreamObservation {
        idempotency_key: forged.idempotency_key,
        observation_id: forged.observation_id,
        metadata: forged.metadata,
        content: forged.content,
        access: forged.access,
    };
    let digest = ordered_items_digest(std::slice::from_ref(&streamed)).expect("stream digest");
    let manifest = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:trusted-policy".to_owned(),
            position: 0,
            resume_cursor: None,
            value: IngestFrameValue::Manifest(SourceRevisionManifest {
                source_id: "source:trusted-policy".to_owned(),
                revision_id: "revision:trusted-policy".to_owned(),
                snapshot_id: "snapshot:trusted-policy".to_owned(),
                expected_items: 1,
                ordered_items_digest: digest,
                compression: Compression::Identity,
                attributes: BTreeMap::new(),
            }),
        })
        .expect("manifest");
    let stream_error = service
        .ingest_frame(IngestFrame {
            context: stream_context,
            stream_id: "stream:trusted-policy".to_owned(),
            position: 1,
            resume_cursor: Some(manifest.resume_cursor),
            value: IngestFrameValue::Observation(streamed),
        })
        .expect_err("stream cannot bypass trusted policy minting");
    assert_eq!(stream_error.code, ErrorCode::PermissionDenied);
}

#[test]
fn typed_reads_collapse_private_misses_and_enforce_the_stored_family() {
    let service = typed_memory_service();
    let ordinary = authenticated("alice", &[Capability::ReadMemory]);
    let absent = service
        .get_node(GetMemoryRequest {
            context: ordinary.clone(),
            record_id: "node:absent".to_owned(),
            at_commit: None,
        })
        .expect_err("absent");
    let wrong_family = service
        .get_node(GetMemoryRequest {
            context: ordinary.clone(),
            record_id: "evidence-a".to_owned(),
            at_commit: None,
        })
        .expect_err("wrong family");
    let denied = service
        .get_node(GetMemoryRequest {
            context: authenticated("mallory", &[Capability::ReadMemory]),
            record_id: "node-a".to_owned(),
            at_commit: None,
        })
        .expect_err("policy denied");
    let missing_exact_capability = service
        .get_timeline(GetTimelineRequest {
            context: ordinary,
            record_id: "evidence-a".to_owned(),
            expected_kind: MemoryRecordKind::Evidence,
            at_commit: None,
            max_revisions: 10,
        })
        .expect_err("stored evidence family requires exact grants");

    service
        .forget(ForgetRequest {
            context: authenticated("alice", &[Capability::Forget, Capability::HardDelete]),
            idempotency_key: "delete:uniform-private-miss".to_owned(),
            target_id: "node-b".to_owned(),
            mode: ForgetMode::HardDelete,
            reason: "privacy-test".to_owned(),
        })
        .expect("delete node");
    let tombstoned = service
        .get_node(GetMemoryRequest {
            context: authenticated("alice", &[Capability::ReadMemory]),
            record_id: "node-b".to_owned(),
            at_commit: None,
        })
        .expect_err("tombstoned");

    assert_eq!(absent, wrong_family);
    assert_eq!(absent, denied);
    assert_eq!(absent, missing_exact_capability);
    assert_eq!(absent, tombstoned);
    assert_eq!(absent.code, ErrorCode::PermissionDenied);
    assert!(absent.partial_result_refs.is_empty());
    assert!(absent.violated_policy.is_none());
}

#[test]
fn workspace_local_snapshots_watermarks_and_events_ignore_other_tenants() {
    let service = ReferenceService::new("tenant-local-sequences", [0x3b; 32]).expect("service");
    let alice_observe = ObserveRequest {
        context: context("alice", "recall", Sensitivity::Restricted),
        idempotency_key: "tenant-a:observe".to_owned(),
        observation_id: "tenant-a:observation".to_owned(),
        metadata: BTreeMap::new(),
        content: json!({"text": "tenant A observation only"}),
        access: policy("alice", "alice", true),
    };
    service.observe(alice_observe).expect("tenant A observe");
    let alice_recall = RecallRequest {
        context: context("alice", "recall", Sensitivity::Restricted),
        query: "no semantic publication".to_owned(),
        page_size: 10,
        at_commit: None,
        continuation: None,
    };
    let before = service.recall(alice_recall.clone()).expect("before recall");
    assert_eq!(before.trace.snapshot_seq, 1);
    assert_eq!(before.trace.watermarks.journal, 1);
    assert_eq!(before.trace.watermarks.semantic, 0);

    for index in 0..64 {
        let mut bob_context = context("bob", "recall", Sensitivity::Restricted);
        bob_context.workspace_id = "workspace-b".to_owned();
        bob_context.scopes = BTreeSet::from(["scope-b".to_owned()]);
        let mut bob_access = policy("bob", "bob", true);
        bob_access.workspace_id = "workspace-b".to_owned();
        bob_access.scopes = BTreeSet::from(["scope-b".to_owned()]);
        service
            .observe(ObserveRequest {
                context: bob_context,
                idempotency_key: format!("tenant-b:{index}"),
                observation_id: format!("tenant-b:observation:{index}"),
                metadata: BTreeMap::new(),
                content: json!({"text": "forbidden tenant activity", "index": index}),
                access: bob_access,
            })
            .expect("tenant B observe");
    }
    let after = service.recall(alice_recall.clone()).expect("after recall");
    assert_eq!(after, before);

    let mut historical = alice_recall.clone();
    historical.at_commit = Some(before.trace.snapshot_seq);
    assert_eq!(
        service
            .recall(historical)
            .expect("local ordinal round-trip"),
        before
    );
    let mut out_of_range = alice_recall;
    out_of_range.at_commit = Some(2);
    assert_eq!(
        service
            .recall(out_of_range)
            .expect_err("other tenant cannot advance Alice local head")
            .code,
        ErrorCode::NotFound
    );

    let mut subscribe_context = authenticated("alice", &[Capability::Subscribe]);
    subscribe_context.request.workspace_id = "workspace-a".to_owned();
    let page = service
        .subscribe(SubscribeRequest {
            context: subscribe_context,
            filters: BTreeSet::from([MemoryEventKind::ObservationAccepted]),
            resume_cursor: None,
            max_events: 1,
        })
        .expect("tenant A subscription");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].object_refs, ["tenant-a:observation"]);
    assert_eq!(page.events[0].commit_seq, 1);
    assert!(page.caught_up);

    let mut charlie = context("charlie", "recall", Sensitivity::Restricted);
    charlie.workspace_id = "workspace-c".to_owned();
    charlie.scopes = BTreeSet::from(["scope-c".to_owned()]);
    let genesis = service
        .recall(RecallRequest {
            context: charlie.clone(),
            query: "empty workspace".to_owned(),
            page_size: 10,
            at_commit: None,
            continuation: None,
        })
        .expect("workspace genesis");
    assert_eq!(genesis.trace.snapshot_seq, 0);
    assert_eq!(genesis.trace.watermarks, Watermarks::default());
    let explicit_genesis = service
        .recall(RecallRequest {
            context: charlie,
            query: "empty workspace".to_owned(),
            page_size: 10,
            at_commit: Some(0),
            continuation: None,
        })
        .expect("explicit workspace genesis");
    assert_eq!(explicit_genesis, genesis);
}

#[test]
fn recall_pagination_trace_and_unauthorized_non_influence_are_authenticated() {
    let service = seeded_service();
    let caller = context("alice", "recall", Sensitivity::Private);
    let request = RecallRequest {
        context: caller.clone(),
        query: "Japan jazz".to_owned(),
        page_size: 1,
        at_commit: None,
        continuation: None,
    };
    let first = service.recall(request.clone()).expect("first page");
    assert_eq!(first.hits.len(), 1);
    assert!(
        !first
            .trace
            .selected_ids
            .contains(&"denied-super-score".to_owned())
    );
    assert_eq!(first.trace.authorized_candidates, 2);
    let mut second_request = request.clone();
    second_request.continuation = first.continuation.clone();
    let second = service.recall(second_request).expect("second page");
    assert_eq!(second.hits.len(), 1);
    assert_ne!(first.hits[0].id, second.hits[0].id);
    assert!(second.continuation.is_none());

    assert_eq!(
        service
            .explain_recall(ExplainRecallRequest {
                context: caller.clone(),
                trace: first.trace.clone(),
            })
            .expect("explain"),
        first.trace
    );
    let mut other_context = caller;
    other_context.subject_id = "mallory".to_owned();
    assert_eq!(
        service
            .explain_recall(ExplainRecallRequest {
                context: other_context,
                trace: first.trace.clone(),
            })
            .expect_err("cross-principal trace")
            .code,
        ErrorCode::PermissionDenied
    );
    let mut forged = first.continuation.expect("continuation");
    forged.replace_range(0..1, if &forged[0..1] == "0" { "1" } else { "0" });
    let mut forged_request = request;
    forged_request.continuation = Some(forged);
    assert_eq!(
        service
            .recall(forged_request)
            .expect_err("forged continuation")
            .code,
        ErrorCode::InvalidContinuation
    );
}

#[test]
fn workspace_admin_archive_is_disabled_while_host_archive_remains_byte_stable() {
    let service = seeded_service();
    let admin = context("admin", "contextdb:admin", Sensitivity::Restricted);
    assert_eq!(
        service
            .export_archive(ExportRequest {
                context: admin.clone(),
            })
            .expect_err("workspace authority must not export global state")
            .code,
        ErrorCode::Unsupported
    );

    let mut authenticated_admin = authenticated("admin", &[Capability::Admin]);
    authenticated_admin.request.purpose = "contextdb:admin".to_owned();
    assert_eq!(
        service
            .create_backup(CreateBackupRequest {
                context: authenticated_admin,
            })
            .expect_err("workspace authority must not back up global state")
            .code,
        ErrorCode::Unsupported
    );

    let export = service
        .export_host_archive(&HostArchiveAuthority::new([7; 32]).expect("host authority"))
        .expect("host export");
    assert_eq!(
        service
            .export_host_archive(&HostArchiveAuthority::new([8; 32]).expect("other host authority"))
            .expect_err("authority from another host key")
            .code,
        ErrorCode::Unauthorized
    );

    let verify = service
        .verify(VerifyRequest {
            context: admin.clone(),
            deep: true,
        })
        .expect("verify");
    assert!(verify.valid);
    assert_eq!(
        verify.archive_digest.as_deref(),
        Some(export.digest.as_str())
    );

    assert_eq!(
        service
            .import_archive(ImportRequest {
                context: admin.clone(),
                format: export.format.clone(),
                bytes: export.bytes.clone(),
                digest: export.digest.clone(),
            })
            .expect_err("workspace authority must not replace global state")
            .code,
        ErrorCode::Unsupported
    );
    let mut restore_context = authenticated("admin", &[Capability::Admin]);
    restore_context.request.purpose = "contextdb:admin".to_owned();
    assert_eq!(
        service
            .restore_backup(RestoreBackupRequest {
                context: restore_context,
                format: export.format.clone(),
                bytes: export.bytes.clone(),
                digest: export.digest.clone(),
            })
            .expect_err("workspace authority must not restore global state")
            .code,
        ErrorCode::Unsupported
    );
    let restored = ReferenceService::new("empty", [9; 32]).expect("isolated restored service");
    let restore_authority = HostArchiveAuthority::new([9; 32]).expect("restore authority");
    let before = restored
        .export_host_archive(&restore_authority)
        .expect("empty host export");
    let mut corrupted = export.bytes.clone();
    corrupted[0] ^= 1;
    assert_eq!(
        restored
            .import_host_archive(
                &restore_authority,
                &export.format,
                &corrupted,
                &export.digest,
            )
            .expect_err("corrupt host archive")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(
        restored
            .export_host_archive(&restore_authority)
            .expect("unchanged empty export"),
        before
    );
    let receipt = restored
        .import_host_archive(
            &restore_authority,
            &export.format,
            &export.bytes,
            &export.digest,
        )
        .expect("host import");
    assert_eq!(receipt.commit_seq, export.commit_seq);
    let reexport = restored
        .export_host_archive(&restore_authority)
        .expect("host re-export");
    assert_eq!(reexport.commit_seq, export.commit_seq);
    assert_eq!(reexport.bytes, export.bytes);
    assert_eq!(reexport.digest, export.digest);

    let denied = context("alice", "recall", Sensitivity::Restricted);
    assert_eq!(
        service
            .export_archive(ExportRequest { context: denied })
            .expect_err("non-admin export")
            .code,
        ErrorCode::PermissionDenied
    );
    let denied_import = context("alice", "recall", Sensitivity::Restricted);
    assert_eq!(
        service
            .import_archive(ImportRequest {
                context: denied_import,
                format: export.format,
                bytes: export.bytes,
                digest: export.digest,
            })
            .expect_err("non-admin import")
            .code,
        ErrorCode::PermissionDenied
    );
}

#[test]
fn resumable_source_snapshot_is_ordered_idempotent_and_completion_gated() {
    let service = ReferenceService::new("stream-reference", [4; 32]).expect("service");
    let context = authenticated("alice", &[Capability::StreamIngest, Capability::Subscribe]);
    let observation = StreamObservation {
        idempotency_key: "item-key".to_owned(),
        observation_id: "observation:streamed".to_owned(),
        metadata: BTreeMap::from([("source".to_owned(), json!("repository"))]),
        content: json!({"text": "snapshot item"}),
        access: policy("alice", "alice", true),
    };
    let digest = ordered_items_digest(std::slice::from_ref(&observation)).expect("digest");
    let manifest = IngestFrame {
        context: context.clone(),
        stream_id: "stream:revision-1".to_owned(),
        position: 0,
        resume_cursor: None,
        value: IngestFrameValue::Manifest(SourceRevisionManifest {
            source_id: "source:repository".to_owned(),
            revision_id: "revision:1".to_owned(),
            snapshot_id: "snapshot:1".to_owned(),
            expected_items: 1,
            ordered_items_digest: digest.clone(),
            compression: Compression::Identity,
            attributes: BTreeMap::from([("branch".to_owned(), "main".to_owned())]),
        }),
    };
    let manifest_ack = service.ingest_frame(manifest.clone()).expect("manifest");
    assert_eq!(manifest_ack.disposition, IngestDisposition::Accepted);
    assert_eq!(
        service.ingest_frame(manifest).expect("manifest replay"),
        manifest_ack
    );

    let before = service
        .subscribe(SubscribeRequest {
            context: context.clone(),
            filters: BTreeSet::from([MemoryEventKind::ObservationAccepted]),
            resume_cursor: None,
            max_events: 10,
        })
        .expect("subscription before completion");
    assert!(before.events.is_empty());

    let mut resumed_context = context.clone();
    resumed_context.request.request_id = "request-stream-resume".to_owned();
    resumed_context.authentication = AuthenticationEvidence::AuthenticatedChannel {
        channel_id: "channel:resume".to_owned(),
        peer_identity: "alice".to_owned(),
        binding_digest: "44".repeat(32),
    };
    let item = IngestFrame {
        context: resumed_context.clone(),
        stream_id: "stream:revision-1".to_owned(),
        position: 1,
        resume_cursor: Some(manifest_ack.resume_cursor.clone()),
        value: IngestFrameValue::Observation(observation),
    };
    let item_ack = service.ingest_frame(item.clone()).expect("item");
    assert_eq!(service.ingest_frame(item).expect("item replay"), item_ack);

    let skipped = IngestFrame {
        context: resumed_context.clone(),
        stream_id: "stream:revision-1".to_owned(),
        position: 3,
        resume_cursor: Some(item_ack.resume_cursor.clone()),
        value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
            snapshot_id: "snapshot:1".to_owned(),
            item_count: 1,
            ordered_items_digest: digest.clone(),
        }),
    };
    assert_eq!(
        service
            .ingest_frame(skipped)
            .expect_err("out of order")
            .code,
        ErrorCode::InvalidContinuation
    );

    let complete = IngestFrame {
        context: resumed_context,
        stream_id: "stream:revision-1".to_owned(),
        position: 2,
        resume_cursor: Some(item_ack.resume_cursor),
        value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
            snapshot_id: "snapshot:1".to_owned(),
            item_count: 1,
            ordered_items_digest: digest,
        }),
    };
    let complete_ack = service.ingest_frame(complete.clone()).expect("complete");
    assert_eq!(
        complete_ack.disposition,
        IngestDisposition::SnapshotCommitted
    );
    assert_eq!(complete_ack.partial_result_refs, ["observation:streamed"]);
    assert_eq!(
        service.ingest_frame(complete).expect("completion replay"),
        complete_ack
    );

    let after = service
        .subscribe(SubscribeRequest {
            context,
            filters: BTreeSet::from([MemoryEventKind::ObservationAccepted]),
            resume_cursor: None,
            max_events: 10,
        })
        .expect("subscription after completion");
    assert_eq!(after.events.len(), 1);
    assert_eq!(after.events[0].object_refs, ["observation:streamed"]);
}

#[test]
fn authorization_precedes_stream_content_validation_and_subscription_is_stable() {
    let service = ReferenceService::new("stream-auth", [5; 32]).expect("service");
    let denied_context = authenticated("alice", &[]);
    let request = IngestFrame {
        context: denied_context,
        stream_id: "stream:denied".to_owned(),
        position: 0,
        resume_cursor: None,
        value: IngestFrameValue::Manifest(SourceRevisionManifest {
            source_id: String::new(),
            revision_id: String::new(),
            snapshot_id: String::new(),
            expected_items: u64::MAX,
            ordered_items_digest: "not-a-digest".to_owned(),
            compression: Compression::Identity,
            attributes: BTreeMap::new(),
        }),
    };
    assert_eq!(
        service
            .ingest_frame(request)
            .expect_err("capability first")
            .code,
        ErrorCode::Unauthorized
    );

    let observe = ObserveRequest {
        context: context("alice", "recall", Sensitivity::Private),
        idempotency_key: "subscription-observe".to_owned(),
        observation_id: "observation:subscription".to_owned(),
        metadata: BTreeMap::new(),
        content: json!({"text": "visible only to alice"}),
        access: policy("alice", "alice", true),
    };
    service.observe(observe).expect("observe");
    let request = SubscribeRequest {
        context: authenticated("alice", &[Capability::Subscribe]),
        filters: BTreeSet::new(),
        resume_cursor: None,
        max_events: 1,
    };
    let first = service.subscribe(request.clone()).expect("first delivery");
    let duplicate = service.subscribe(request).expect("at least once retry");
    assert_eq!(first.events[0].event_id, duplicate.events[0].event_id);

    let mut resumed_context = authenticated("alice", &[Capability::Subscribe]);
    resumed_context.request.request_id = "request-subscription-resume".to_owned();
    resumed_context.authentication = AuthenticationEvidence::AuthenticatedChannel {
        channel_id: "channel:subscription-resume".to_owned(),
        peer_identity: "alice".to_owned(),
        binding_digest: "66".repeat(32),
    };
    let resumed = service
        .subscribe(SubscribeRequest {
            context: resumed_context.clone(),
            filters: BTreeSet::new(),
            resume_cursor: Some(first.resume_cursor.clone()),
            max_events: 10,
        })
        .expect("fresh request evidence resumes the same authority");
    assert!(resumed.events.is_empty());
    resumed_context
        .request
        .scopes
        .insert("scope:expanded".to_owned());
    assert_eq!(
        service
            .subscribe(SubscribeRequest {
                context: resumed_context,
                filters: BTreeSet::new(),
                resume_cursor: Some(first.resume_cursor),
                max_events: 10,
            })
            .expect_err("cursor cannot cross an authorization scope change")
            .code,
        ErrorCode::InvalidContinuation
    );

    let denied = service
        .subscribe(SubscribeRequest {
            context: authenticated("mallory", &[Capability::Subscribe]),
            filters: BTreeSet::new(),
            resume_cursor: None,
            max_events: 10,
        })
        .expect("unauthorized records are omitted");
    assert!(denied.events.is_empty());
}

#[test]
fn unsupported_runtime_is_typed_only_after_authentication_and_capability() {
    let service = ReferenceService::new("runtime-gap", [6; 32]).expect("service");
    let denied = service
        .bootstrap(crate::RuntimeRequest {
            context: authenticated("alice", &[]),
            operation_id: "runtime:1".to_owned(),
            payload: json!({"session": "secret"}),
        })
        .expect_err("capability denied before unsupported");
    assert_eq!(denied.code, ErrorCode::Unauthorized);

    let unsupported = service
        .bootstrap(crate::RuntimeRequest {
            context: authenticated("alice", &[Capability::Runtime]),
            operation_id: "runtime:1".to_owned(),
            payload: json!({"session": "secret"}),
        })
        .expect_err("reference runtime executor is absent");
    assert_eq!(unsupported.code, ErrorCode::Unsupported);
    assert!(unsupported.safe_next_action.is_some());
}

#[test]
fn compression_is_negotiated_fail_closed_when_reference_transport_cannot_execute_it() {
    let service = ReferenceService::new("compression", [10; 32]).expect("service");
    for (index, compression) in [Compression::Gzip, Compression::Zstd]
        .into_iter()
        .enumerate()
    {
        let observations = Vec::new();
        let digest = ordered_items_digest(&observations).expect("digest");
        let stream_id = format!("stream:compression:{index}");
        let context = authenticated("alice", &[Capability::StreamIngest]);
        let error = service
            .ingest_frame(IngestFrame {
                context,
                stream_id,
                position: 0,
                resume_cursor: None,
                value: IngestFrameValue::Manifest(SourceRevisionManifest {
                    source_id: format!("source:{index}"),
                    revision_id: "revision:1".to_owned(),
                    snapshot_id: format!("snapshot:{index}"),
                    expected_items: 0,
                    ordered_items_digest: digest.clone(),
                    compression,
                    attributes: BTreeMap::new(),
                }),
            })
            .expect_err("unsupported compression must fail closed");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert_eq!(
            error.violated_policy.as_deref(),
            Some("compression_not_negotiated")
        );
    }
}

#[test]
fn incomplete_stream_registry_is_strictly_bounded() {
    let service = ReferenceService::new("stream-open-bound", [25; 32]).expect("service");
    let stream_context = authenticated("alice", &[Capability::StreamIngest]);
    let digest = ordered_items_digest(&[]).expect("digest");
    for index in 0..8 {
        service
            .ingest_frame(IngestFrame {
                context: stream_context.clone(),
                stream_id: format!("stream:open:{index}"),
                position: 0,
                resume_cursor: None,
                value: IngestFrameValue::Manifest(SourceRevisionManifest {
                    source_id: format!("source:open:{index}"),
                    revision_id: "revision:open".to_owned(),
                    snapshot_id: format!("snapshot:open:{index}"),
                    expected_items: 0,
                    ordered_items_digest: digest.clone(),
                    compression: Compression::Identity,
                    attributes: BTreeMap::new(),
                }),
            })
            .expect("bounded open stream");
    }
    let error = service
        .ingest_frame(IngestFrame {
            context: stream_context,
            stream_id: "stream:open:overflow".to_owned(),
            position: 0,
            resume_cursor: None,
            value: IngestFrameValue::Manifest(SourceRevisionManifest {
                source_id: "source:open:overflow".to_owned(),
                revision_id: "revision:open".to_owned(),
                snapshot_id: "snapshot:open:overflow".to_owned(),
                expected_items: 0,
                ordered_items_digest: digest,
                compression: Compression::Identity,
                attributes: BTreeMap::new(),
            }),
        })
        .expect_err("ninth incomplete stream must fail closed");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(error.retryable);
}

#[test]
fn multi_item_snapshot_completion_is_atomic_on_late_item_failure() {
    let service = ReferenceService::new("stream-atomic", [21; 32]).expect("service");
    service
        .observe(ObserveRequest {
            context: context("alice", "recall", Sensitivity::Private),
            idempotency_key: "existing-key".to_owned(),
            observation_id: "observation:collision".to_owned(),
            metadata: BTreeMap::new(),
            content: json!({"text": "existing unrelated value"}),
            access: policy("alice", "alice", true),
        })
        .expect("existing observation");
    let stream_context = authenticated("alice", &[Capability::StreamIngest, Capability::Subscribe]);
    let observations = vec![
        StreamObservation {
            idempotency_key: "atomic-first-key".to_owned(),
            observation_id: "observation:atomic-first".to_owned(),
            metadata: BTreeMap::new(),
            content: json!({"text": "atomic unpublished sentinel"}),
            access: policy("alice", "alice", true),
        },
        StreamObservation {
            idempotency_key: "atomic-collision-key".to_owned(),
            observation_id: "observation:collision".to_owned(),
            metadata: BTreeMap::new(),
            content: json!({"text": "would collide at the second staged item"}),
            access: policy("alice", "alice", true),
        },
    ];
    let digest = ordered_items_digest(&observations).expect("digest");
    let manifest = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:atomic".to_owned(),
            position: 0,
            resume_cursor: None,
            value: IngestFrameValue::Manifest(SourceRevisionManifest {
                source_id: "source:atomic".to_owned(),
                revision_id: "revision:atomic".to_owned(),
                snapshot_id: "snapshot:atomic".to_owned(),
                expected_items: 2,
                ordered_items_digest: digest.clone(),
                compression: Compression::Identity,
                attributes: BTreeMap::new(),
            }),
        })
        .expect("manifest");
    let first = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:atomic".to_owned(),
            position: 1,
            resume_cursor: Some(manifest.resume_cursor),
            value: IngestFrameValue::Observation(observations[0].clone()),
        })
        .expect("first item");
    let second = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:atomic".to_owned(),
            position: 2,
            resume_cursor: Some(first.resume_cursor),
            value: IngestFrameValue::Observation(observations[1].clone()),
        })
        .expect("second item buffered");
    let error = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:atomic".to_owned(),
            position: 3,
            resume_cursor: Some(second.resume_cursor),
            value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
                snapshot_id: "snapshot:atomic".to_owned(),
                item_count: 2,
                ordered_items_digest: digest,
            }),
        })
        .expect_err("late staged collision must abort the entire publication");
    assert!(error.partial_result_refs.is_empty());
    let events = service
        .subscribe(SubscribeRequest {
            context: stream_context,
            filters: BTreeSet::from([MemoryEventKind::ObservationAccepted]),
            resume_cursor: None,
            max_events: 10,
        })
        .expect("events after aborted completion");
    assert_eq!(events.events.len(), 1);
    assert_eq!(events.events[0].object_refs, ["observation:collision"]);

    let recall = service
        .recall(RecallRequest {
            context: context("alice", "recall", Sensitivity::Private),
            query: "atomic unpublished sentinel".to_owned(),
            page_size: 10,
            at_commit: None,
            continuation: None,
        })
        .expect("recall after aborted completion");
    assert!(recall.hits.is_empty());
    assert_eq!(recall.trace.snapshot_seq, 1);
}

#[test]
fn successful_multi_item_snapshot_becomes_visible_as_one_completed_revision() {
    let service = ReferenceService::new("stream-atomic-success", [24; 32]).expect("service");
    let stream_context = authenticated("alice", &[Capability::StreamIngest, Capability::Subscribe]);
    let observations = [
        StreamObservation {
            idempotency_key: "success-a".to_owned(),
            observation_id: "observation:success-a".to_owned(),
            metadata: BTreeMap::new(),
            content: json!({"text": "atomic success alpha"}),
            access: policy("alice", "alice", true),
        },
        StreamObservation {
            idempotency_key: "success-b".to_owned(),
            observation_id: "observation:success-b".to_owned(),
            metadata: BTreeMap::new(),
            content: json!({"text": "atomic success beta"}),
            access: policy("alice", "alice", true),
        },
    ];
    let digest = ordered_items_digest(&observations).expect("digest");
    let manifest = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:atomic-success".to_owned(),
            position: 0,
            resume_cursor: None,
            value: IngestFrameValue::Manifest(SourceRevisionManifest {
                source_id: "source:atomic-success".to_owned(),
                revision_id: "revision:atomic-success".to_owned(),
                snapshot_id: "snapshot:atomic-success".to_owned(),
                expected_items: 2,
                ordered_items_digest: digest.clone(),
                compression: Compression::Identity,
                attributes: BTreeMap::new(),
            }),
        })
        .expect("manifest");
    let first = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:atomic-success".to_owned(),
            position: 1,
            resume_cursor: Some(manifest.resume_cursor),
            value: IngestFrameValue::Observation(observations[0].clone()),
        })
        .expect("first item");
    let second = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:atomic-success".to_owned(),
            position: 2,
            resume_cursor: Some(first.resume_cursor),
            value: IngestFrameValue::Observation(observations[1].clone()),
        })
        .expect("second item");
    let before = service
        .subscribe(SubscribeRequest {
            context: stream_context.clone(),
            filters: BTreeSet::from([MemoryEventKind::ObservationAccepted]),
            resume_cursor: None,
            max_events: 10,
        })
        .expect("pre-completion subscription");
    assert!(before.events.is_empty());

    let complete = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:atomic-success".to_owned(),
            position: 3,
            resume_cursor: Some(second.resume_cursor),
            value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
                snapshot_id: "snapshot:atomic-success".to_owned(),
                item_count: 2,
                ordered_items_digest: digest,
            }),
        })
        .expect("atomic completion");
    assert_eq!(complete.commit_seq, Some(2));
    assert_eq!(
        complete.partial_result_refs,
        ["observation:success-a", "observation:success-b"]
    );
    let after = service
        .subscribe(SubscribeRequest {
            context: stream_context,
            filters: BTreeSet::from([MemoryEventKind::ObservationAccepted]),
            resume_cursor: None,
            max_events: 10,
        })
        .expect("post-completion subscription");
    assert_eq!(after.events.len(), 2);
    assert_eq!(after.events[0].object_refs, ["observation:success-a"]);
    assert_eq!(after.events[1].object_refs, ["observation:success-b"]);
}

#[test]
fn replacing_source_head_produces_retained_deduplicable_invalidation_event() {
    let service = ReferenceService::new("source-events", [22; 32]).expect("service");
    let stream_context = authenticated("alice", &[Capability::StreamIngest, Capability::Subscribe]);
    let digest = ordered_items_digest(&[]).expect("empty digest");
    for revision in ["one", "two"] {
        let stream_id = format!("stream:{revision}");
        let manifest = service
            .ingest_frame(IngestFrame {
                context: stream_context.clone(),
                stream_id: stream_id.clone(),
                position: 0,
                resume_cursor: None,
                value: IngestFrameValue::Manifest(SourceRevisionManifest {
                    source_id: "source:replaceable".to_owned(),
                    revision_id: format!("revision:{revision}"),
                    snapshot_id: format!("snapshot:{revision}"),
                    expected_items: 0,
                    ordered_items_digest: digest.clone(),
                    compression: Compression::Identity,
                    attributes: BTreeMap::new(),
                }),
            })
            .expect("manifest");
        service
            .ingest_frame(IngestFrame {
                context: stream_context.clone(),
                stream_id,
                position: 1,
                resume_cursor: Some(manifest.resume_cursor),
                value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
                    snapshot_id: format!("snapshot:{revision}"),
                    item_count: 0,
                    ordered_items_digest: digest.clone(),
                }),
            })
            .expect("completion");
    }

    let request = SubscribeRequest {
        context: stream_context.clone(),
        filters: BTreeSet::from([MemoryEventKind::SourceInvalidated]),
        resume_cursor: None,
        max_events: 10,
    };
    let first = service.subscribe(request.clone()).expect("source event");
    let replay = service.subscribe(request).expect("at-least-once replay");
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.events, replay.events);
    assert_eq!(
        first.events[0].object_refs,
        ["source:replaceable", "revision:one", "revision:two"]
    );

    let third_manifest = service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:three".to_owned(),
            position: 0,
            resume_cursor: None,
            value: IngestFrameValue::Manifest(SourceRevisionManifest {
                source_id: "source:replaceable".to_owned(),
                revision_id: "revision:three".to_owned(),
                snapshot_id: "snapshot:three".to_owned(),
                expected_items: 0,
                ordered_items_digest: digest.clone(),
                compression: Compression::Identity,
                attributes: BTreeMap::new(),
            }),
        })
        .expect("third manifest");
    service
        .ingest_frame(IngestFrame {
            context: stream_context.clone(),
            stream_id: "stream:three".to_owned(),
            position: 1,
            resume_cursor: Some(third_manifest.resume_cursor),
            value: IngestFrameValue::SnapshotComplete(SnapshotComplete {
                snapshot_id: "snapshot:three".to_owned(),
                item_count: 0,
                ordered_items_digest: digest,
            }),
        })
        .expect("third completion");
    let resumed = service
        .subscribe(SubscribeRequest {
            context: stream_context,
            filters: BTreeSet::from([MemoryEventKind::SourceInvalidated]),
            resume_cursor: Some(first.resume_cursor),
            max_events: 10,
        })
        .expect("same-commit retained resume");
    assert_eq!(resumed.events.len(), 1);
    assert_eq!(
        resumed.events[0].object_refs,
        ["source:replaceable", "revision:two", "revision:three"]
    );
}

#[test]
fn semantic_subscription_produces_index_and_explicit_open_loop_events() {
    let database = ContextDb::new("subscription-producers").expect("database");
    let mut runtime = LogicalRecord {
        id: "runtime:open-loop".to_owned(),
        kind: RecordKind::RuntimeState,
        access: reference_access("alice"),
        valid_time: ValidTime::UNBOUNDED,
        lifecycle: Lifecycle::Active,
        links: SemanticLinks::default(),
        value: json!({"trigger": "commitment overdue"}),
        search_text: None,
        vector: None,
        attributes: BTreeMap::new(),
    };
    runtime
        .attributes
        .insert("contextdb.open_loop_trigger".to_owned(), json!(true));
    database
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "subscription-producers".to_owned(),
            mutations: vec![Mutation::Put {
                record: runtime,
                expected_revision: None,
            }],
        })
        .expect("semantic commit");
    let service = ReferenceService::from_database(database, [23; 32]).expect("service");
    let subscription_context = authenticated("alice", &[Capability::Subscribe]);
    let filters = BTreeSet::from([
        MemoryEventKind::OpenLoopTriggered,
        MemoryEventKind::IndexWatermarkAdvanced,
    ]);
    let first = service
        .subscribe(SubscribeRequest {
            context: subscription_context.clone(),
            filters: filters.clone(),
            resume_cursor: None,
            max_events: 1,
        })
        .expect("first subscription page");
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.events[0].kind, MemoryEventKind::OpenLoopTriggered);
    assert!(!first.caught_up);
    let resumed = service
        .subscribe(SubscribeRequest {
            context: subscription_context,
            filters,
            resume_cursor: Some(first.resume_cursor),
            max_events: 1,
        })
        .expect("resumed subscription page");
    assert_eq!(resumed.events.len(), 1);
    assert_eq!(
        resumed.events[0].kind,
        MemoryEventKind::IndexWatermarkAdvanced
    );
    assert!(resumed.caught_up);
}

#[test]
fn reference_service_debug_never_exposes_continuation_key_or_database_content() {
    let service = ReferenceService::new("debug-redaction", [81; 32]).expect("service");
    let rendered = format!("{service:?}");
    assert!(!rendered.contains("81"));
    assert!(!rendered.contains("continuation_key"));
    assert!(!rendered.contains("database"));
}

#[test]
fn typed_memory_reads_and_traversal_are_executable_and_policy_first() {
    let service = typed_memory_service();
    let context = authenticated(
        "alice",
        &[
            Capability::ReadMemory,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ReadConflict,
            Capability::Traverse,
        ],
    );
    let node = service
        .get_node(GetMemoryRequest {
            context: context.clone(),
            record_id: "node-a".to_owned(),
            at_commit: None,
        })
        .expect("node read");
    assert_eq!(node.document.kind, MemoryRecordKind::Node);
    let evidence = service
        .get_evidence(GetMemoryRequest {
            context: context.clone(),
            record_id: "evidence-a".to_owned(),
            at_commit: None,
        })
        .expect("evidence read");
    assert_eq!(evidence.document.kind, MemoryRecordKind::Evidence);
    let conflict = service
        .get_conflict(GetMemoryRequest {
            context: context.clone(),
            record_id: "conflict-a".to_owned(),
            at_commit: None,
        })
        .expect("conflict read");
    assert_eq!(conflict.document.kind, MemoryRecordKind::Conflict);
    let history = service
        .get_timeline(GetTimelineRequest {
            context: context.clone(),
            record_id: "claim-a".to_owned(),
            expected_kind: MemoryRecordKind::Claim,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("claim timeline");
    assert_eq!(history.revisions.len(), 1);
    let traversal = service
        .traverse(TraverseRequest {
            context: context.clone(),
            start_ids: vec!["node-a".to_owned()],
            direction: TraverseDirection::Outgoing,
            predicate_ids: BTreeSet::from(["next".to_owned()]),
            max_hops: 2,
            max_nodes: 10,
            at_commit: None,
        })
        .expect("graph traversal");
    assert_eq!(traversal.node_ids, ["node-b"]);
    assert_eq!(traversal.authorized_candidates, 1);

    let without_raw_evidence = authenticated("alice", &[Capability::ReadEvidence]);
    assert_eq!(
        service
            .get_evidence(GetMemoryRequest {
                context: without_raw_evidence,
                record_id: "evidence-a".to_owned(),
                at_commit: None,
            })
            .expect_err("raw evidence requires its independent grant")
            .code,
        ErrorCode::Unauthorized
    );
    let other_subject = authenticated("mallory", &[Capability::ReadMemory]);
    assert_eq!(
        service
            .get_node(GetMemoryRequest {
                context: other_subject,
                record_id: "node-a".to_owned(),
                at_commit: None,
            })
            .expect_err("policy-hidden node")
            .code,
        ErrorCode::PermissionDenied
    );
}

#[test]
fn historical_timeline_returns_snapshot_bound_watermarks() {
    let database = ContextDb::new("historical-timeline-watermarks").expect("database");
    database
        .commit(SemanticTransaction {
            base_seq: 0,
            idempotency_key: "timeline:create".to_owned(),
            mutations: vec![Mutation::Put {
                record: LogicalRecord {
                    id: "claim:timeline".to_owned(),
                    kind: RecordKind::SemanticObject,
                    access: reference_access("alice"),
                    valid_time: ValidTime::UNBOUNDED,
                    lifecycle: Lifecycle::Active,
                    links: SemanticLinks::default(),
                    value: json!({"version": 1}),
                    search_text: None,
                    vector: None,
                    attributes: BTreeMap::new(),
                },
                expected_revision: None,
            }],
        })
        .expect("initial timeline revision");
    let historical_commit = database.snapshot().expect("historical snapshot").commit_seq;
    database
        .commit(SemanticTransaction {
            base_seq: historical_commit,
            idempotency_key: "timeline:revise".to_owned(),
            mutations: vec![Mutation::Put {
                record: LogicalRecord {
                    id: "claim:timeline".to_owned(),
                    kind: RecordKind::SemanticObject,
                    access: reference_access("alice"),
                    valid_time: ValidTime::UNBOUNDED,
                    lifecycle: Lifecycle::Active,
                    links: SemanticLinks::default(),
                    value: json!({"version": 2}),
                    search_text: None,
                    vector: None,
                    attributes: BTreeMap::new(),
                },
                expected_revision: Some(1),
            }],
        })
        .expect("current timeline revision");
    let current_commit = database.snapshot().expect("current snapshot").commit_seq;
    let service = ReferenceService::from_database(database, [0x42; 32]).expect("service");

    let historical = service
        .get_timeline(GetTimelineRequest {
            context: authenticated("alice", &[Capability::ReadMemory]),
            record_id: "claim:timeline".to_owned(),
            expected_kind: MemoryRecordKind::SemanticObject,
            at_commit: Some(historical_commit),
            max_revisions: 10,
        })
        .expect("historical timeline");
    assert_eq!(historical.snapshot_seq, historical_commit);
    assert_eq!(historical.watermarks.journal, historical_commit);
    assert_eq!(historical.watermarks.semantic, historical_commit);
    assert_eq!(historical.revisions.len(), 1);

    let current = service
        .get_timeline(GetTimelineRequest {
            context: authenticated("alice", &[Capability::ReadMemory]),
            record_id: "claim:timeline".to_owned(),
            expected_kind: MemoryRecordKind::SemanticObject,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("current timeline");
    assert_eq!(current.snapshot_seq, current_commit);
    assert_eq!(current.watermarks.journal, current_commit);
    assert_eq!(current.watermarks.semantic, current_commit);
    assert_eq!(current.revisions.len(), 2);
}

#[test]
fn correction_and_forgetting_are_actor_scoped_policy_preserving_and_idempotent() {
    let service = seeded_service();
    let context = authenticated(
        "alice",
        &[
            Capability::Correct,
            Capability::Forget,
            Capability::HardDelete,
            Capability::ReadMemory,
        ],
    );
    let replacement = MemoryDocument {
        id: "allowed-a-v2".to_owned(),
        kind: MemoryRecordKind::SemanticObject,
        access: policy("owner", "alice", true),
        valid_time: DomainTimeRange::default(),
        lifecycle: MemoryLifecycle::Active,
        links: MemoryLinks {
            supersedes: BTreeSet::from(["allowed-a".to_owned()]),
            ..MemoryLinks::default()
        },
        value: json!({"fact": "Japan jazz bar corrected"}),
        search_text: Some("Japan jazz bar corrected".to_owned()),
        vector: None,
        attributes: BTreeMap::new(),
    };
    let correct = CorrectRequest {
        context: context.clone(),
        idempotency_key: "correction:key".to_owned(),
        target_id: "allowed-a".to_owned(),
        replacement: replacement.clone(),
    };
    let first = service.correct(correct.clone()).expect("correct");
    let mut retry = correct.clone();
    retry.context.request.request_id = "request-retry-correction".to_owned();
    retry.context.authentication = AuthenticationEvidence::AuthenticatedChannel {
        channel_id: "channel:retry".to_owned(),
        peer_identity: "alice".to_owned(),
        binding_digest: "22".repeat(32),
    };
    let replay = service.correct(retry).expect("correction replay");
    assert_eq!(first.commit_seq, replay.commit_seq);
    assert!(!first.replayed);
    assert!(replay.replayed);

    let mut weakening = correct;
    weakening.idempotency_key = "correction:weaken".to_owned();
    weakening.replacement.id = "allowed-a-v3".to_owned();
    weakening.replacement.access.audience = BTreeSet::from(["*".to_owned()]);
    assert_eq!(
        service
            .correct(weakening)
            .expect_err("policy weakening")
            .code,
        ErrorCode::PermissionDenied
    );

    let timeline = service
        .get_timeline(GetTimelineRequest {
            context: context.clone(),
            record_id: replacement.id.clone(),
            expected_kind: MemoryRecordKind::SemanticObject,
            at_commit: None,
            max_revisions: 10,
        })
        .expect("successor timeline");
    assert_eq!(timeline.revisions[0].document.id, replacement.id);

    let denied_delete = ForgetRequest {
        context: authenticated("alice", &[Capability::Forget]),
        idempotency_key: "delete:denied".to_owned(),
        target_id: replacement.id.clone(),
        mode: ForgetMode::HardDelete,
        reason: "subject_request".to_owned(),
    };
    assert_eq!(
        service
            .forget(denied_delete)
            .expect_err("hard-delete grant")
            .code,
        ErrorCode::Unauthorized
    );

    let delete = ForgetRequest {
        context,
        idempotency_key: "delete:allowed".to_owned(),
        target_id: replacement.id.clone(),
        mode: ForgetMode::HardDelete,
        reason: "subject_request".to_owned(),
    };
    let deleted = service.forget(delete.clone()).expect("hard delete");
    let mut retry = delete;
    retry.context.request.request_id = "request-retry-delete".to_owned();
    retry.context.authentication = AuthenticationEvidence::AuthenticatedChannel {
        channel_id: "channel:retry".to_owned(),
        peer_identity: "alice".to_owned(),
        binding_digest: "33".repeat(32),
    };
    let replay = service.forget(retry).expect("hard delete replay");
    assert_eq!(deleted.commit_seq, replay.commit_seq);
    assert!(replay.replayed);
}

#[test]
fn explicit_memory_publication_is_policy_derived_recallable_and_readable() {
    let service = ReferenceService::new("explicit-memory", [0x79; 32]).expect("service");
    let context = authenticated(
        "alice",
        &[
            Capability::Observe,
            Capability::Correct,
            Capability::Recall,
            Capability::ReadMemory,
        ],
    );
    let request = PublishMemoryRequest {
        context: context.clone(),
        idempotency_key: "explicit:key".to_owned(),
        memory_id: "memory:explicit-v1".to_owned(),
        value: json!({"text": "ContextDB uses Fjall for the production composition"}),
        search_text: "ContextDB production composition Fjall".to_owned(),
    };

    let first = service
        .publish_memory(request.clone())
        .expect("publish explicit memory");
    let replay = service
        .publish_memory(request)
        .expect("replay explicit memory");
    assert_eq!(first.commit_seq, replay.commit_seq);
    assert!(!first.replayed);
    assert!(replay.replayed);

    let recalled = service
        .recall(RecallRequest {
            context: context.request.clone(),
            query: "production Fjall".to_owned(),
            page_size: 10,
            at_commit: None,
            continuation: None,
        })
        .expect("recall explicit memory");
    assert_eq!(recalled.hits.len(), 1);
    assert_eq!(recalled.hits[0].id, "memory:explicit-v1");

    let memory = service
        .get_memory(GetMemoryRequest {
            context,
            record_id: "memory:explicit-v1".to_owned(),
            at_commit: None,
        })
        .expect("materialize explicit memory");
    assert_eq!(
        memory.document.value["text"],
        "ContextDB uses Fjall for the production composition"
    );
    assert_eq!(memory.document.access, policy("alice", "alice", true));
}
