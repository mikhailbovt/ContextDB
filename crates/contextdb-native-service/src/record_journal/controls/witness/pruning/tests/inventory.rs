use super::*;
use crate::record_sources::tests::input;
use contextdb_service::CapturePort;

#[test]
fn primary_pruning_requires_explicit_origins_for_legacy_generic_records() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("unclassified-copy");
    let native =
        NativeService::open_with_suppression(root.path(), "unclassified-copy", [7; 32], ledger)
            .expect("native");
    let captured = input(1, "legacy source");
    native.append_event(captured.clone()).expect("capture");
    native
        .publish_memory(publication(&captured.context, "legacy-record"))
        .expect("legacy publication");
    let targets = BTreeSet::from([captured.event.event_id]);
    let removal = native
        .request_original_removal(&captured.context, &targets, "remove", &mut budget())
        .expect("removal");
    assert_eq!(
        native
            .prune_original_sources(&captured.context, &removal, &targets, &mut budget())
            .expect_err("unknown origin is not independence")
            .code,
        ErrorCode::EvidenceRequired
    );
    native
        .verify_native(true)
        .expect("denied cleanup leaves original state intact");
}

#[test]
fn primary_pruning_inventory_rejects_lost_history_and_orphan_generic_bodies() {
    let f = fixture();
    let edge = candidate_hierarchy_edge_id("PRIVATE-PARENT", "PRIVATE-CHILD").expect("edge");
    for (record, revision) in [
        ("private-record", 1),
        ("private-record", 2),
        ("PRIVATE-PARENT", 1),
        ("PRIVATE-CHILD", 1),
        (edge.as_str(), 1),
    ] {
        f.service
            .prune_record_revision(
                &f.context,
                &prepare(&f, record, revision).expect("witness"),
                &mut budget(),
            )
            .expect("prune");
    }
    let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
    let targets = BTreeSet::from([f.source]);
    let key = history_key(&digest_bytes(b"independent-record"), 1);
    for mutation in [
        "policy",
        "birth-reference",
        "orphan-content",
        "orphan-mutation",
    ] {
        let mut tx = f.service.engine.begin_write().expect("transaction");
        f.service
            .require_record_copies_pruned(&tx, &workspace, &targets, &mut budget())
            .expect("baseline");
        let stored: StoredContent = decode(
            &tx.get(&f.service.keyspaces.content_history, &key)
                .expect("content")
                .expect("body"),
            "test content",
        )
        .expect("decode");
        match mutation {
            "policy" => {
                tx.delete(&f.service.keyspaces.policy_history, key.clone())
                    .expect("delete policy");
            }
            "birth-reference" => {
                let global = stored.record.transaction_from;
                let mut event = f
                    .service
                    .recovery_global_event(&tx, global, &mut budget())
                    .expect("event");
                event.accepted_records.clear();
                tx.put(
                    &f.service.keyspaces.events,
                    global.to_be_bytes().to_vec(),
                    encode(&event).expect("event"),
                )
                .expect("replace event");
                preparation::tests::rehash(&f.service, &mut tx);
            }
            "orphan-content" => {
                let mut orphan = stored;
                orphan.record.document.id = "unaccepted-copy".into();
                tx.put(
                    &f.service.keyspaces.content_history,
                    history_key(&digest_bytes(b"unaccepted-copy"), 1),
                    encode(&orphan).expect("content"),
                )
                .expect("orphan");
            }
            "orphan-mutation" => {
                let mut orphan = stored.record;
                let global = f.service.global_head(&tx).expect("head") + 1;
                orphan.transaction_to = Some(global);
                tx.put(
                    &f.service.keyspaces.continuous,
                    mutation_address(global, &digest_bytes(b"independent-record"), 1),
                    encode(&orphan).expect("mutation"),
                )
                .expect("orphan");
            }
            _ => unreachable!(),
        }
        assert_eq!(
            f.service
                .require_record_copies_pruned(&tx, &workspace, &targets, &mut budget())
                .expect_err(mutation)
                .code,
            ErrorCode::IntegrityFailure
        );
        assert!(
            tx.get(
                &f.service.keyspaces.observations_content,
                digest_bytes(f.source.to_string().as_bytes()).as_bytes()
            )
            .expect("original")
            .is_some()
        );
    }
}
