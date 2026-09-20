use super::*;
use crate::assertions::tests::{assertion, capture, change, key, policy, publication, publish};
use contextdb_core::{
    AssertionRetraction, BitemporalRange, CommitRange, PredicateId, TimestampMicros,
};
use contextdb_service::{
    CaptureRequest, CognitiveMemoryService, CreateBackupRequest, ReadOriginalRequest,
    RestoreBackupRequest,
};
use std::sync::Arc;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        512 * 1024 * 1024,
        std::time::Duration::from_secs(60),
        Default::default(),
    )
}
fn remove(
    native: &NativeService,
    input: &CaptureRequest,
    name: &str,
) -> crate::NativeRemovalRequestReceipt {
    native
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            name,
            &mut budget(),
        )
        .expect("request removal")
}
fn prepare(
    native: &NativeService,
    input: &CaptureRequest,
    removal: &crate::NativeRemovalRequestReceipt,
) {
    native
        .prepare_original_removal_sources(
            &input.context,
            removal,
            &BTreeSet::from([input.event.event_id]),
            &mut budget(),
        )
        .expect("prepare");
    native
        .maintain_custody(&input.context, 256, &mut budget())
        .expect("custody");
    native
        .project_originals(&input.context, true, 256, &mut budget())
        .expect("project");
    for _ in 0..10 {
        let progress = native
            .reclaim_raw_generations(&input.context, 1024, &mut budget())
            .expect("reclaim");
        if progress.finished && progress.retained_generations == 1 {
            break;
        }
    }
}
fn mixed(
    native: &NativeService,
    first: &CaptureRequest,
    second: &CaptureRequest,
) -> (PublishAssertionsRequest, ClaimId, ClaimId) {
    native.append_event(first.clone()).expect("first original");
    native
        .append_event(second.clone())
        .expect("second original");
    let mut selected = assertion(first, "semanticremovalsentinel", 0, None, vec![]);
    selected
        .revision
        .envelope
        .security
        .labels
        .insert("removed-envelope-sentinel".into());
    let mut independent = assertion(second, "independent-semantic-value", 0, None, vec![]);
    independent.key.predicate = PredicateId::from_uuid(uuid::Uuid::from_u128(222)).expect("id");
    independent.claim.predicate = independent.key.predicate;
    let mut independent_policy = policy(second);
    independent_policy.key = independent.key.clone();
    let ids = (selected.claim.id, independent.claim.id);
    let request = publication(
        native,
        first,
        "mixed batch",
        vec![
            AssertionMutation::Policy {
                policy: policy(first),
            },
            change(selected),
            AssertionMutation::Policy {
                policy: independent_policy,
            },
            change(independent),
        ],
    );
    (request, ids.0, ids.1)
}
fn row(native: &NativeService, key: &[u8]) -> Option<Vec<u8>> {
    native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot")
        .get(&native.keyspaces.continuous, key)
        .expect("row")
}
fn put(native: &NativeService, key: Vec<u8>, value: Option<Vec<u8>>) {
    let mut tx = native.engine.begin_write().expect("tx");
    if let Some(value) = value {
        tx.put(&native.keyspaces.continuous, key, value)
            .expect("put");
    } else {
        tx.delete(&native.keyspaces.continuous, key)
            .expect("delete");
    }
    tx.commit(Durability::Sync).expect("sync");
}

#[test]
fn mixed_assertions_prune_without_changing_independent_mutations_or_old_receipts() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = crate::suppression::tests::authority("semantic-prune");
    let (_keys_dir, keys) = crate::encryption::tests::authority("semantic-prune");
    let path = root.path().join("native");
    let native = NativeService::open_encrypted(
        &path,
        "semantic-prune",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("native");
    let first = capture(1, "rawpruningsentinel");
    let second = capture(2, "independent source");
    let (request, first_id, independent_id) = mixed(&native, &first, &second);
    let accepted = native
        .publish_assertions(request.clone(), &mut budget())
        .expect("mixed publication");
    let independent_bytes = row(&native, &claim_key(independent_id)).expect("independent bytes");
    native
        .initialize_state_catalog(&first.context, &mut budget())
        .expect("catalog");
    let later = capture(3, "later independent choice");
    native.append_event(later.clone()).expect("later capture");
    let successor = assertion(&later, "replacement-value", 0, None, vec![first_id]);
    let successor_id = successor.claim.id;
    publish(&native, &later, "supersession", vec![change(successor)]);
    let negative = capture(4, "negative transition source");
    native
        .append_event(negative.clone())
        .expect("negative original");
    let support = assertion(&negative, "unused", 0, None, vec![]);
    let negative_receipt = publish(
        &native,
        &negative,
        "negative",
        vec![AssertionMutation::Retract {
            retraction: AssertionRetraction {
                key: key(&negative),
                target: first_id,
                temporal: BitemporalRange {
                    transaction_time: CommitRange {
                        start: CommitSeq::GENESIS,
                        end: None,
                    },
                    valid_time: TimeRange {
                        start: TimestampMicros(0),
                        end: None,
                    },
                },
                source: support.source,
                originating_event: negative.event.event_id,
                original_evidence: support.original_evidence,
            },
        }],
    );
    let old = native
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("old archive");
    let removal = remove(&native, &first, "remove first");
    assert_eq!(
        native
            .prune_source_assertions(
                &first.context,
                &removal,
                accepted.workspace_commit,
                &mut budget()
            )
            .expect_err("unprepared")
            .code,
        ErrorCode::IndexTooStale
    );
    prepare(&native, &first, &removal);
    assert_eq!(
        native
            .prune_original_sources(
                &first.context,
                &removal,
                &BTreeSet::from([first.event.event_id]),
                &mut budget()
            )
            .expect_err("semantic bytes still required")
            .code,
        ErrorCode::Unsupported
    );
    let pruned = native
        .prune_source_assertions(
            &first.context,
            &removal,
            accepted.workspace_commit,
            &mut budget(),
        )
        .expect("prune selected assertion");
    assert_eq!(pruned.mutations, BTreeSet::from([1]));
    assert_eq!(
        row(&native, &claim_key(independent_id)),
        Some(independent_bytes.clone())
    );
    assert!(row(&native, &claim_key(first_id)).is_none());
    assert!(row(&native, &claim_key(successor_id)).is_some());
    assert_eq!(
        native
            .publish_assertions(request.clone(), &mut budget())
            .expect("original retry"),
        accepted
    );
    native
        .verify_native(true)
        .expect("mixed and dependent target replay");
    let partial = native
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("partial archive");
    drop(native);
    let native = NativeService::open_encrypted(
        &path,
        "semantic-prune",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("reopen");
    assert_eq!(
        native
            .prune_source_assertions(
                &first.context,
                &removal,
                accepted.workspace_commit,
                &mut budget()
            )
            .expect("pruning retry"),
        pruned
    );
    native
        .prune_original_sources(
            &first.context,
            &removal,
            &BTreeSet::from([first.event.event_id]),
            &mut budget(),
        )
        .expect("primary after semantic cleanup");
    let snapshot = native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    for keyspace in native.keyspaces.all() {
        for row in snapshot.scan_prefix(keyspace, b"").expect("logical rows") {
            let text = String::from_utf8_lossy(&row.value);
            for removed in [
                "rawpruningsentinel",
                "semanticremovalsentinel",
                "removed-envelope-sentinel",
            ] {
                assert!(
                    !text.contains(removed),
                    "private content survived in {}",
                    String::from_utf8_lossy(&row.key)
                );
            }
        }
    }
    drop(snapshot);
    let second_removal = remove(&native, &second, "remove second later");
    prepare(&native, &second, &second_removal);
    let second_pruned = native
        .prune_source_assertions(
            &second.context,
            &second_removal,
            accepted.workspace_commit,
            &mut budget(),
        )
        .expect("second mixed mutation");
    assert_eq!(second_pruned.mutations, BTreeSet::from([3]));
    let batch_key = retained_key(&workspace(&first.context), accepted.workspace_commit);
    let retained: RetainedAssertions =
        decode(&row(&native, &batch_key).expect("retained"), "retained").expect("decode");
    assert!(
        matches!(retained.mutations[1], RetainedMutation::Removed { at, .. } if at == pruned.workspace_commit)
    );
    native
        .prune_original_sources(
            &second.context,
            &second_removal,
            &BTreeSet::from([second.event.event_id]),
            &mut budget(),
        )
        .expect("second primary");
    let negative_removal = remove(&native, &negative, "remove negative support");
    prepare(&native, &negative, &negative_removal);
    native
        .prune_source_assertions(
            &negative.context,
            &negative_removal,
            negative_receipt.workspace_commit,
            &mut budget(),
        )
        .expect("prune retraction body");
    native
        .prune_original_sources(
            &negative.context,
            &negative_removal,
            &BTreeSet::from([negative.event.event_id]),
            &mut budget(),
        )
        .expect("negative primary");
    native
        .verify_native(true)
        .expect("pruned negative and superseded targets verify");
    let clean = native
        .create_backup(CreateBackupRequest {
            context: first.context.clone(),
        })
        .expect("clean archive");
    for (name, archive) in [("old", old), ("partial", partial), ("clean", clean)] {
        let restored = NativeService::open_encrypted(
            root.path().join(name),
            "semantic-prune",
            [9; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: first.context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("restore");
        restored
            .verify_native(true)
            .expect("restored semantic closure");
        assert!(row(&restored, &claim_key(successor_id)).is_some());
        assert_eq!(
            restored
                .read_original(ReadOriginalRequest {
                    context: first.context.clone(),
                    event_id: first.event.event_id,
                    after_receipt: None
                })
                .expect_err("removal barrier retained")
                .code,
            ErrorCode::IndexTooStale
        );
        if name == "partial" {
            restored
                .prune_original_sources(
                    &first.context,
                    &removal,
                    &BTreeSet::from([first.event.event_id]),
                    &mut budget(),
                )
                .expect("resume partial primary");
            assert_eq!(
                row(&restored, &claim_key(independent_id)),
                Some(independent_bytes.clone())
            );
        }
        if name != "old" {
            assert_eq!(
                restored
                    .prune_source_assertions(
                        &first.context,
                        &removal,
                        accepted.workspace_commit,
                        &mut budget()
                    )
                    .expect("restored exact pruning retry"),
                pruned
            );
        }
    }
}

#[test]
fn semantic_pruning_rejects_changed_controls_resurrection_and_concurrent_publication() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = crate::suppression::tests::authority("semantic-damage");
    let native = Arc::new(
        NativeService::open_with_suppression(root.path(), "semantic-damage", [7; 32], ledger)
            .expect("native"),
    );
    let first = capture(1, "first source");
    let second = capture(2, "second source");
    let (request, first_id, second_id) = mixed(&native, &first, &second);
    let accepted = native
        .publish_assertions(request, &mut budget())
        .expect("publish");
    let full_key = journal_key(&workspace(&first.context), accepted.workspace_commit);
    let original_batch = row(&native, &full_key).expect("full batch");
    let removal = remove(&native, &first, "remove");
    prepare(&native, &first, &removal);
    let mut empty = QueryBudget::new(0, 0, std::time::Duration::from_secs(10), Default::default());
    assert!(
        native
            .prune_source_assertions(
                &first.context,
                &removal,
                accepted.workspace_commit,
                &mut empty
            )
            .is_err()
    );
    assert!(row(&native, &claim_key(first_id)).is_some());
    let concurrent = native.clone();
    BEFORE_PUBLICATION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            concurrent
                .append_event(capture(3, "concurrent independent source"))
                .expect("concurrent capture");
        }))
    });
    assert_eq!(
        native
            .prune_source_assertions(
                &first.context,
                &removal,
                accepted.workspace_commit,
                &mut budget()
            )
            .expect_err("changed workspace")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(row(&native, &full_key), Some(original_batch.clone()));
    let pruned = native
        .prune_source_assertions(
            &first.context,
            &removal,
            accepted.workspace_commit,
            &mut budget(),
        )
        .expect("retry prune");
    let pruned_key = retained_key(&workspace(&first.context), accepted.workspace_commit);
    let good = row(&native, &pruned_key).expect("pruned batch");
    let corrupt = |value: Option<Vec<u8>>| {
        put(&native, pruned_key.clone(), value);
        assert_eq!(
            native
                .verify_native(true)
                .expect_err("invalid retained control")
                .code,
            ErrorCode::IntegrityFailure
        );
        assert_eq!(
            native
                .prune_source_assertions(
                    &first.context,
                    &removal,
                    accepted.workspace_commit,
                    &mut budget()
                )
                .expect_err("retry must validate loss")
                .code,
            ErrorCode::IntegrityFailure
        );
        put(&native, pruned_key.clone(), Some(good.clone()));
    };
    corrupt(None);
    let mut changed: RetainedAssertions = decode(&good, "good").expect("decode");
    if let RetainedMutation::Removed { at, .. } = &mut changed.mutations[1] {
        *at += 1;
    }
    corrupt(Some(encode(&changed).expect("encode")));
    let mut changed: RetainedAssertions = decode(&good, "good").expect("decode");
    changed.control.pipeline_digest = "0".repeat(64);
    corrupt(Some(encode(&changed).expect("encode")));
    let mut changed: RetainedAssertions = decode(&good, "good").expect("decode");
    changed.mutations.swap(1, 3);
    corrupt(Some(encode(&changed).expect("encode")));
    put(&native, full_key.clone(), Some(original_batch));
    assert_eq!(
        native.verify_native(true).expect_err("resurrection").code,
        ErrorCode::IntegrityFailure
    );
    put(&native, full_key, None);
    let independent = row(&native, &claim_key(second_id)).expect("independent");
    put(&native, claim_key(second_id), None);
    assert_eq!(
        native
            .verify_native(true)
            .expect_err("unexplained independent hole")
            .code,
        ErrorCode::IntegrityFailure
    );
    put(&native, claim_key(second_id), Some(independent));
    native.verify_native(true).expect("repaired closure");
    assert_eq!(
        native
            .prune_source_assertions(
                &first.context,
                &removal,
                accepted.workspace_commit,
                &mut budget()
            )
            .expect("exact accepted progress"),
        pruned
    );
}
