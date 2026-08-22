#![allow(
    clippy::unwrap_used,
    reason = "test fixtures use immediate failure semantics"
)]

use std::collections::{BTreeMap, BTreeSet};

use contextdb_reference::{
    AccessLabel, Consent, ContextDb, Direction, Failpoint, JournalEvent, Lifecycle, LogicalExport,
    LogicalRecord, Mutation, ObservationInput, Principal, RecordKind, ReferenceError,
    SemanticLinks, SemanticTransaction, Sensitivity, ValidTime,
};
use serde_json::{Value, json};

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(ToString::to_string).collect()
}

fn access(subject: &str) -> AccessLabel {
    AccessLabel {
        workspace: "ws".to_owned(),
        scopes: set(&["shared"]),
        owners: set(&[subject]),
        audience: set(&[subject]),
        audience_purpose_grants: BTreeMap::new(),
        purposes: set(&["recall"]),
        sensitivity: Sensitivity::Internal,
        consent: Consent::Granted,
        retrievable: true,
    }
}

fn principal(subject: &str) -> Principal {
    Principal {
        subject: subject.to_owned(),
        audiences: BTreeSet::new(),
        workspace: "ws".to_owned(),
        scopes: set(&["shared"]),
        purpose: "recall".to_owned(),
        clearance: Sensitivity::Private,
    }
}

fn record(id: &str, kind: RecordKind, value: Value) -> LogicalRecord {
    LogicalRecord {
        id: id.to_owned(),
        kind,
        access: access("alice"),
        valid_time: ValidTime::UNBOUNDED,
        lifecycle: Lifecycle::Active,
        links: SemanticLinks::default(),
        value,
        search_text: Some(id.replace('-', " ")),
        vector: None,
        attributes: BTreeMap::new(),
    }
}

fn transaction(
    db: &ContextDb,
    key: impl Into<String>,
    mutations: Vec<Mutation>,
) -> SemanticTransaction {
    SemanticTransaction {
        base_seq: db.snapshot().expect("snapshot").commit_seq,
        idempotency_key: key.into(),
        mutations,
    }
}

fn put(record: LogicalRecord) -> Mutation {
    Mutation::Put {
        record,
        expected_revision: None,
    }
}

#[test]
fn snapshots_separate_current_state_from_history() {
    let db = ContextDb::new("history-db").expect("database");
    db.commit(transaction(
        &db,
        "create",
        vec![put(record(
            "node",
            RecordKind::Node,
            json!({"name": "old"}),
        ))],
    ))
    .expect("create");
    let old_snapshot = db.snapshot().expect("old snapshot");

    let mut revised = record("node", RecordKind::Node, json!({"name": "current"}));
    revised.search_text = Some("current name".to_owned());
    db.commit(SemanticTransaction {
        base_seq: old_snapshot.commit_seq,
        idempotency_key: "revise".to_owned(),
        mutations: vec![Mutation::Put {
            record: revised,
            expected_revision: Some(1),
        }],
    })
    .expect("revise");
    let current_snapshot = db.snapshot().expect("current snapshot");

    assert_eq!(
        db.get("node", &old_snapshot, &principal("alice"))
            .expect("old record")
            .content
            .value,
        json!({"name": "old"})
    );
    assert_eq!(
        db.get("node", &current_snapshot, &principal("alice"))
            .expect("current record")
            .content
            .value,
        json!({"name": "current"})
    );
    let history = db
        .history("node", &current_snapshot, &principal("alice"))
        .expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].revision.transaction_to, Some(2));
    assert_eq!(history[1].revision.transaction_from, 2);

    let historical_watermarks = db
        .watermarks_for(&old_snapshot)
        .expect("historical watermarks");
    let current_watermarks = db
        .watermarks_for(&current_snapshot)
        .expect("current watermarks");
    assert_eq!(historical_watermarks.journal, old_snapshot.commit_seq);
    assert_eq!(historical_watermarks.semantic, old_snapshot.commit_seq);
    assert_eq!(current_watermarks.journal, current_snapshot.commit_seq);
    assert_eq!(current_watermarks.semantic, current_snapshot.commit_seq);
}

#[test]
fn stale_precondition_is_atomic_and_does_not_advance_head() {
    let db = ContextDb::new("atomic-db").expect("database");
    let stale = db.snapshot().expect("snapshot");
    db.commit(transaction(
        &db,
        "winner",
        vec![put(record("winner", RecordKind::Node, json!(1)))],
    ))
    .expect("winner");
    let error = db
        .commit(SemanticTransaction {
            base_seq: stale.commit_seq,
            idempotency_key: "stale".to_owned(),
            mutations: vec![put(record("must-not-exist", RecordKind::Node, json!(2)))],
        })
        .expect_err("stale transaction must fail");
    assert!(matches!(error, ReferenceError::SnapshotConflict { .. }));
    assert_eq!(db.snapshot().expect("snapshot").commit_seq, 1);
    assert!(matches!(
        db.get(
            "must-not-exist",
            &db.snapshot().expect("snapshot"),
            &principal("alice")
        ),
        Err(ReferenceError::NotFound { .. })
    ));
}

#[test]
fn idempotency_replays_exact_request_and_rejects_key_reuse() {
    let db = ContextDb::new("idempotency-db").expect("database");
    let request = transaction(
        &db,
        "stable-key",
        vec![put(record("node", RecordKind::Node, json!(1)))],
    );
    let first = db.commit(request.clone()).expect("first commit");
    let replay = db.commit(request).expect("replay");
    assert_eq!(first.commit_seq, replay.commit_seq);
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(db.snapshot().expect("snapshot").commit_seq, 1);

    let error = db
        .commit(SemanticTransaction {
            base_seq: 1,
            idempotency_key: "stable-key".to_owned(),
            mutations: vec![put(record("other", RecordKind::Node, json!(2)))],
        })
        .expect_err("key reuse must fail");
    assert!(matches!(error, ReferenceError::IdempotencyConflict { .. }));
    assert_eq!(db.snapshot().expect("snapshot").commit_seq, 1);
}

#[test]
fn failpoints_model_pre_publish_rollback_and_lost_ack_replay() {
    let before_db = ContextDb::new("before-crash").expect("database");
    let before_request = transaction(
        &before_db,
        "before",
        vec![put(record("node", RecordKind::Node, json!(1)))],
    );
    assert!(matches!(
        before_db.commit_with_failpoint(before_request.clone(), Failpoint::BeforePublish),
        Err(ReferenceError::InjectedCrash("before_publish"))
    ));
    assert_eq!(before_db.snapshot().expect("snapshot").commit_seq, 0);
    let committed = before_db.commit(before_request).expect("retry commits");
    assert_eq!(committed.commit_seq, 1);
    assert!(!committed.replayed);

    let after_db = ContextDb::new("after-crash").expect("database");
    let after_request = transaction(
        &after_db,
        "after",
        vec![put(record("node", RecordKind::Node, json!(1)))],
    );
    assert!(matches!(
        after_db.commit_with_failpoint(after_request.clone(), Failpoint::AfterPublish),
        Err(ReferenceError::InjectedCrash("after_publish"))
    ));
    assert_eq!(after_db.snapshot().expect("snapshot").commit_seq, 1);
    let replay = after_db.commit(after_request).expect("lost ack replay");
    assert_eq!(replay.commit_seq, 1);
    assert!(replay.replayed);
}

#[test]
fn observation_and_semantic_publication_are_distinct_journal_events() {
    let db = ContextDb::new("journal-db").expect("database");
    let observation = ObservationInput {
        idempotency_key: "observe-1".to_owned(),
        observation_id: "observation-1".to_owned(),
        access: access("alice"),
        metadata: BTreeMap::from([("source".to_owned(), json!("chat"))]),
        content: json!({"raw": "the user said this"}),
    };
    let observed = db.observe(observation).expect("observe");
    assert_eq!(observed.watermarks.journal, 1);
    assert_eq!(observed.watermarks.semantic, 0);
    let observation_snapshot = db.snapshot().expect("observation snapshot");
    assert_eq!(
        db.get_observation("observation-1", &observation_snapshot, &principal("alice"))
            .expect("materialized observation")
            .content,
        json!({"raw": "the user said this"})
    );
    assert!(matches!(
        db.get_observation("observation-1", &observation_snapshot, &principal("bob")),
        Err(ReferenceError::Unauthorized)
    ));
    let published = db
        .commit(transaction(
            &db,
            "publish-1",
            vec![put(record("fact", RecordKind::SemanticObject, json!(true)))],
        ))
        .expect("publish");
    assert_eq!(published.commit_seq, 2);
    assert_eq!(published.watermarks.semantic, 2);
    let journal = db.journal().expect("journal");
    assert!(matches!(
        journal[0].event,
        JournalEvent::ObservationAccepted { .. }
    ));
    assert!(matches!(
        journal[1].event,
        JournalEvent::SemanticPublished { .. }
    ));
    assert_eq!(
        journal[1].previous_digest,
        Some(journal[0].record_digest.clone())
    );
}

#[test]
fn correction_supersedes_history_without_rewriting_it() {
    let db = ContextDb::new("correction-db").expect("database");
    let subject = record("person", RecordKind::Node, json!({"name": "Alice"}));
    let mut old_claim = record("claim-old", RecordKind::Claim, json!("red"));
    old_claim.links.subject = Some("person".to_owned());
    old_claim.links.predicate = Some("favorite-color".to_owned());
    old_claim.links.single_valued = true;
    db.commit(transaction(
        &db,
        "initial",
        vec![put(subject), put(old_claim)],
    ))
    .expect("initial state");
    let historical = db.snapshot().expect("historical snapshot");

    let mut corrected = record("claim-current", RecordKind::Claim, json!("blue"));
    corrected.links.subject = Some("person".to_owned());
    corrected.links.predicate = Some("favorite-color".to_owned());
    corrected.links.single_valued = true;
    corrected.links.supersedes.insert("claim-old".to_owned());
    db.commit(transaction(
        &db,
        "correction",
        vec![Mutation::Correct {
            target: "claim-old".to_owned(),
            replacement: corrected,
        }],
    ))
    .expect("correction");

    let current = db.snapshot().expect("current snapshot");
    assert_eq!(
        db.get("claim-old", &historical, &principal("alice"))
            .expect("historical claim")
            .revision
            .record
            .lifecycle,
        Lifecycle::Active
    );
    assert_eq!(
        db.get("claim-old", &current, &principal("alice"))
            .expect("superseded claim")
            .revision
            .record
            .lifecycle,
        Lifecycle::Superseded
    );
    assert_eq!(
        db.get("claim-current", &current, &principal("alice"))
            .expect("replacement")
            .content
            .value,
        json!("blue")
    );
}

#[test]
fn single_value_conflicts_require_a_revisioned_conflict_set() {
    let db = ContextDb::new("conflict-db").expect("database");
    db.commit(transaction(
        &db,
        "subject",
        vec![put(record("person", RecordKind::Node, json!("Alice")))],
    ))
    .expect("subject");
    let mut first = record("claim-a", RecordKind::Claim, json!("A"));
    first.links.subject = Some("person".to_owned());
    first.links.predicate = Some("status".to_owned());
    first.links.single_valued = true;
    db.commit(transaction(&db, "first", vec![put(first.clone())]))
        .expect("first claim");

    let mut second = record("claim-b", RecordKind::Claim, json!("B"));
    second.links = first.links.clone();
    assert!(matches!(
        db.commit(transaction(
            &db,
            "invalid-second",
            vec![put(second.clone())]
        )),
        Err(ReferenceError::Invariant(_))
    ));
    assert_eq!(db.snapshot().expect("snapshot").commit_seq, 2);

    first.links.conflict_set = Some("conflict".to_owned());
    second.links.conflict_set = Some("conflict".to_owned());
    let mut conflict = record(
        "conflict",
        RecordKind::Conflict,
        json!({"resolution": "open"}),
    );
    conflict.links.conflict_members = set(&["claim-a", "claim-b"]);
    db.commit(SemanticTransaction {
        base_seq: 2,
        idempotency_key: "publish-conflict".to_owned(),
        mutations: vec![
            Mutation::Put {
                record: first,
                expected_revision: Some(1),
            },
            put(second),
            put(conflict),
        ],
    })
    .expect("explicit conflict");
    let snapshot = db.snapshot().expect("snapshot");
    assert_eq!(
        db.get("conflict", &snapshot, &principal("alice"))
            .expect("conflict")
            .revision
            .record
            .links
            .conflict_members,
        set(&["claim-a", "claim-b"])
    );
}

#[test]
fn hard_delete_erases_content_from_current_and_retained_snapshots() {
    let db = ContextDb::new("deletion-db").expect("database");
    let node_a = record(
        "node-a",
        RecordKind::Node,
        json!({"secret": "ERASE-ME-493"}),
    );
    let node_b = record("node-b", RecordKind::Node, json!({"name": "safe"}));
    let mut edge = record(
        "edge-a-b",
        RecordKind::Edge,
        json!({"note": "ERASE-EDGE-493"}),
    );
    edge.links.source = Some("node-a".to_owned());
    edge.links.target = Some("node-b".to_owned());
    edge.links.predicate = Some("related-to".to_owned());
    db.commit(transaction(
        &db,
        "graph",
        vec![put(node_a), put(node_b), put(edge)],
    ))
    .expect("graph");
    let retained = db.snapshot().expect("retained snapshot");

    db.commit(transaction(
        &db,
        "delete-a",
        vec![Mutation::Delete {
            target: "node-a".to_owned(),
            requested_by: "alice".to_owned(),
            reason: "explicit_forget".to_owned(),
        }],
    ))
    .expect("delete");
    assert!(matches!(
        db.get("node-a", &retained, &principal("alice")),
        Err(ReferenceError::NotFound { .. })
    ));
    assert!(matches!(
        db.get("edge-a-b", &retained, &principal("alice")),
        Err(ReferenceError::NotFound { .. })
    ));
    assert_eq!(
        db.get("node-b", &retained, &principal("alice"))
            .expect("unrelated content")
            .content
            .value,
        json!({"name": "safe"})
    );
    let export = String::from_utf8(db.export().expect("export")).expect("utf8");
    assert!(!export.contains("ERASE-ME-493"));
    assert!(!export.contains("ERASE-EDGE-493"));
    assert!(db.tombstone("node-a").expect("tombstone").is_some());
    assert!(db.tombstone("edge-a-b").expect("tombstone").is_some());
}

#[test]
fn unauthorized_content_does_not_change_candidates_scores_or_trace_counts() {
    fn build(secret_value: &str, secret_vector: Vec<f32>) -> ContextDb {
        let db = ContextDb::new("policy-db").expect("database");
        let mut visible = record("visible", RecordKind::SemanticObject, json!("japan bar"));
        visible.search_text = Some("japan bar".to_owned());
        visible.vector = Some(vec![1.0, 0.0]);
        db.commit(transaction(&db, "visible", vec![put(visible)]))
            .expect("visible");
        let mut secret = record("secret", RecordKind::SemanticObject, json!(secret_value));
        secret.access = access("bob");
        secret.search_text = Some(format!("japan bar {secret_value}"));
        secret.vector = Some(secret_vector);
        db.commit(transaction(&db, "secret", vec![put(secret)]))
            .expect("secret");
        db
    }
    let left = build("LEFT-SECRET", vec![10_000.0, 0.0]);
    let right = build("RIGHT-SECRET-DIFFERENT", vec![-10_000.0, 0.0]);
    let left_snapshot = left.snapshot().expect("snapshot");
    let right_snapshot = right.snapshot().expect("snapshot");
    let actor = principal("alice");
    assert_eq!(
        left.lexical_search("japan bar", 10, &left_snapshot, &actor)
            .expect("left lexical"),
        right
            .lexical_search("japan bar", 10, &right_snapshot, &actor)
            .expect("right lexical")
    );
    assert_eq!(
        left.vector_search(&[1.0, 0.0], 10, &left_snapshot, &actor)
            .expect("left vector"),
        right
            .vector_search(&[1.0, 0.0], 10, &right_snapshot, &actor)
            .expect("right vector")
    );
    assert!(matches!(
        left.get("secret", &left_snapshot, &actor),
        Err(ReferenceError::Unauthorized)
    ));
}

#[test]
fn exact_graph_traversal_is_bounded_authorized_and_stably_ordered() {
    let db = ContextDb::new("graph-db").expect("database");
    let nodes = ["a", "b", "c", "private"]
        .into_iter()
        .map(|id| put(record(id, RecordKind::Node, json!(id))))
        .collect::<Vec<_>>();
    db.commit(transaction(&db, "nodes", nodes)).expect("nodes");
    let mut edges = Vec::new();
    for (id, source, target) in [("e1", "a", "b"), ("e2", "b", "c")] {
        let mut edge = record(id, RecordKind::Edge, json!(id));
        edge.links.source = Some(source.to_owned());
        edge.links.target = Some(target.to_owned());
        edge.links.predicate = Some("next".to_owned());
        edges.push(put(edge));
    }
    let mut private_edge = record("e-private", RecordKind::Edge, json!("hidden"));
    private_edge.access = access("bob");
    private_edge.links.source = Some("a".to_owned());
    private_edge.links.target = Some("private".to_owned());
    private_edge.links.predicate = Some("next".to_owned());
    edges.push(put(private_edge));
    db.commit(transaction(&db, "edges", edges)).expect("edges");
    let snapshot = db.snapshot().expect("snapshot");
    let result = db
        .traverse(
            &["a".to_owned()],
            Direction::Outgoing,
            &set(&["next"]),
            2,
            10,
            &snapshot,
            &principal("alice"),
        )
        .expect("traverse");
    assert_eq!(result.value, vec!["b", "c"]);
    assert!(!result.trace.selected_ids.contains(&"private".to_owned()));
}

#[test]
fn exact_vector_ties_use_stable_id_order_and_reads_include_new_delta() {
    let db = ContextDb::new("vector-db").expect("database");
    let mut z = record("z", RecordKind::SemanticObject, json!("z"));
    z.vector = Some(vec![1.0, 1.0]);
    let mut a = record("a", RecordKind::SemanticObject, json!("a"));
    a.vector = Some(vec![1.0, 1.0]);
    db.commit(transaction(&db, "vectors", vec![put(z), put(a)]))
        .expect("vectors");
    let snapshot = db.snapshot().expect("snapshot");
    let result = db
        .vector_search(&[1.0, 0.0], 10, &snapshot, &principal("alice"))
        .expect("search");
    assert_eq!(result.value[0].id, "a");
    assert_eq!(result.value[1].id, "z");
    assert_eq!(result.trace.watermarks.vector, snapshot.commit_seq);
}

#[test]
fn export_is_canonical_importable_and_preserves_idempotency() {
    let db = ContextDb::new("export-db").expect("database");
    let request = transaction(
        &db,
        "create",
        vec![put(record(
            "node",
            RecordKind::Node,
            json!({"b": 2, "a": 1}),
        ))],
    );
    db.commit(request.clone()).expect("commit");
    let first = db.export().expect("first export");
    let second = db.export().expect("second export");
    assert_eq!(first, second);

    let restored = ContextDb::import(&first).expect("import");
    assert_eq!(first, restored.export().expect("round-trip export"));
    let receipt = restored.commit(request).expect("idempotent replay");
    assert!(receipt.replayed);
    assert_eq!(receipt.commit_seq, 1);

    let mut corrupt: LogicalExport = serde_json::from_slice(&first).expect("decode export");
    corrupt.journal[0].record_digest = "wrong".to_owned();
    let corrupt_bytes = serde_json::to_vec(&corrupt).expect("encode corrupt export");
    assert!(matches!(
        ContextDb::import(&corrupt_bytes),
        Err(ReferenceError::InvalidImport(_))
    ));
}

#[test]
fn exact_validated_transaction_is_available_for_replay_until_policy_deletes_it() {
    let db = ContextDb::new("replay-db").expect("database");
    let request = transaction(
        &db,
        "create",
        vec![put(record(
            "node",
            RecordKind::Node,
            json!({"exact": true}),
        ))],
    );
    db.commit(request.clone()).expect("commit");
    let export: LogicalExport =
        serde_json::from_slice(&db.export().expect("export")).expect("decode export");
    let JournalEvent::SemanticPublished {
        request_content, ..
    } = &export.journal[0].event
    else {
        panic!("expected semantic publication");
    };
    assert_eq!(
        export.contents.get(&request_content.id),
        Some(&serde_json::to_value(request).expect("request value"))
    );
}

#[test]
fn multimodal_selectors_round_trip_without_text_only_assumptions() {
    let db = ContextDb::new("artifact-db").expect("database");
    let selector = json!({
        "original_artifact": "artifact-1",
        "selectors": [
            {"kind": "image_region", "x": 10, "y": 20, "width": 30, "height": 40},
            {"kind": "audio_time_range", "start_ms": 1200, "end_ms": 2400}
        ],
        "derived": {"caption": "not canonical", "transcript": "not canonical"}
    });
    db.commit(transaction(
        &db,
        "artifact",
        vec![put(record(
            "evidence",
            RecordKind::Evidence,
            selector.clone(),
        ))],
    ))
    .expect("evidence");
    let restored = ContextDb::import(&db.export().expect("export")).expect("import");
    let snapshot = restored.snapshot().expect("snapshot");
    assert_eq!(
        restored
            .get("evidence", &snapshot, &principal("alice"))
            .expect("evidence")
            .content
            .value,
        selector
    );
}

#[test]
fn deterministic_state_machine_executes_more_than_ten_thousand_operations() {
    let db = ContextDb::new("state-machine-db").expect("database");
    let mut seed = 0x4d59_5df4_d0f3_3173_u64;
    let mut revisions = [0_u32; 8];
    for operation in 0..10_240_u32 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let slot = usize::try_from(seed % 8).expect("bounded slot");
        if operation % 20 == 0 {
            let id = format!("state-{slot}");
            let next_revision = revisions[slot].saturating_add(1);
            let record = record(
                &id,
                RecordKind::SemanticObject,
                json!({"operation": operation, "seed": seed}),
            );
            db.commit(SemanticTransaction {
                base_seq: db.snapshot().expect("snapshot").commit_seq,
                idempotency_key: format!("operation-{operation}"),
                mutations: vec![Mutation::Put {
                    record,
                    expected_revision: Some(revisions[slot]),
                }],
            })
            .expect("state mutation");
            revisions[slot] = next_revision;
        } else {
            let snapshot = db.snapshot().expect("snapshot");
            let scan = db
                .scan_kind(RecordKind::SemanticObject, &snapshot, &principal("alice"))
                .expect("state read");
            assert!(scan.value.len() <= 8);
            assert_eq!(scan.trace.snapshot_seq, snapshot.commit_seq);
        }
    }
    let export = db.export().expect("deterministic final export");
    assert_eq!(
        export,
        ContextDb::import(&export)
            .expect("state import")
            .export()
            .expect("state re-export")
    );
}
