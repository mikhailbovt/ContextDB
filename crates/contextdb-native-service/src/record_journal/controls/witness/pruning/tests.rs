use super::*;
use crate::record_journal::controls::witness::tests::{fixture, prepare};
use crate::record_sources::tests::{budget, publication};
use contextdb_service::CognitiveMemoryService;

mod failures;
mod inventory;

#[test]
fn record_pruning_erases_complete_revision_families_and_preserves_graph_history_and_receipts() {
    let f = fixture();
    let mut archives = vec![
        f.service
            .create_backup(CreateBackupRequest {
                context: f.context.clone(),
            })
            .expect("full archive"),
    ];
    let mut first_witness = None;
    let before = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let independent_key = history_key(&digest_bytes(b"independent-record"), 1);
    let independent = before
        .get(&f.service.keyspaces.content_history, &independent_key)
        .expect("independent");
    let original = f
        .service
        .publish_memory_from_sources(
            publication(&f.context, "private-record"),
            &BTreeSet::from([f.source]),
            &mut budget(),
        )
        .expect("original receipt");
    assert_eq!(
        f.service
            .prune_original_sources(
                &f.context,
                &f.removal,
                &BTreeSet::from([f.source]),
                &mut budget()
            )
            .expect_err("generic copies still need cleanup")
            .code,
        ErrorCode::Unsupported
    );
    let edge = candidate_hierarchy_edge_id("PRIVATE-PARENT", "PRIVATE-CHILD").expect("edge");
    for (record, revision) in [
        ("private-record", 1),
        ("private-record", 2),
        ("PRIVATE-PARENT", 1),
        ("PRIVATE-CHILD", 1),
        (edge.as_str(), 1),
    ] {
        let witness = prepare(&f, record, revision).expect("witness");
        first_witness.get_or_insert_with(|| witness.clone());
        let receipt = f
            .service
            .prune_record_revision(&f.context, &witness, &mut budget())
            .expect("prune revision");
        assert_eq!(
            f.service
                .prune_record_revision(&f.context, &witness, &mut budget())
                .expect("exact retry"),
            receipt
        );
        assert_eq!(
            prepare(&f, record, revision).expect("witness retry without bodies"),
            witness
        );
        let snapshot = f
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("snapshot");
        let digest = digest_bytes(record.as_bytes());
        assert!(
            snapshot
                .get(
                    &f.service.keyspaces.content_history,
                    &history_key(&digest, revision)
                )
                .expect("content")
                .is_none()
        );
        let pruned = f
            .service
            .pruned_record(&snapshot, &digest, revision, &mut budget())
            .expect("marker")
            .expect("pruned");
        for control in pruned.witness.controls() {
            let global = control
                .policy
                .transaction_to
                .unwrap_or(control.policy.transaction_from);
            assert!(
                snapshot
                    .get(
                        &f.service.keyspaces.continuous,
                        &mutation_address(global, &digest, revision)
                    )
                    .expect("mutation")
                    .is_none()
            );
        }
        f.service
            .verify_native(true)
            .expect("mixed graph and history verify after each revision");
        if record == "private-record" && revision == 1 {
            archives.push(
                f.service
                    .create_backup(CreateBackupRequest {
                        context: f.context.clone(),
                    })
                    .expect("partial archive"),
            );
        }
    }
    let after = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    assert_eq!(
        after
            .get(&f.service.keyspaces.content_history, &independent_key)
            .expect("independent"),
        independent
    );
    assert_eq!(
        f.service
            .publish_memory_from_sources(
                publication(&f.context, "private-record"),
                &BTreeSet::from([f.source]),
                &mut budget()
            )
            .expect("original receipt after erasure"),
        original
    );
    f.service
        .prepare_original_removal_sources(
            &f.context,
            &f.removal,
            &BTreeSet::from([f.source]),
            &mut budget(),
        )
        .expect("prepare primary original");
    f.service
        .maintain_custody(&f.context, 256, &mut budget())
        .expect("revoked custody");
    f.service
        .project_originals(&f.context, true, 256, &mut budget())
        .expect("index without removed source");
    let mut reclaimed = false;
    for _ in 0..10 {
        let progress = f
            .service
            .reclaim_raw_generations(&f.context, 1024, &mut budget())
            .expect("reclaim raw copies");
        if progress.finished && progress.retained_generations == 1 {
            reclaimed = true;
            break;
        }
    }
    assert!(reclaimed, "bounded raw cleanup completes");
    let primary = f
        .service
        .prune_original_sources(
            &f.context,
            &f.removal,
            &BTreeSet::from([f.source]),
            &mut budget(),
        )
        .expect("all affected generic copies are pruned");
    assert_eq!(
        f.service
            .prune_original_sources(
                &f.context,
                &f.removal,
                &BTreeSet::from([f.source]),
                &mut budget()
            )
            .expect("primary retry"),
        primary
    );
    f.service
        .verify_native(true)
        .expect("generic provenance survives primary pruning");
    let cleaned = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cleaned snapshot");
    assert!(
        cleaned
            .get(
                &f.service.keyspaces.observations_content,
                digest_bytes(f.source.to_string().as_bytes()).as_bytes()
            )
            .expect("primary content")
            .is_none()
    );
    assert_eq!(
        cleaned
            .get(&f.service.keyspaces.content_history, &independent_key)
            .expect("independent content"),
        independent
    );
    assert_eq!(
        cleaned
            .get(
                &f.service.keyspaces.observations_content,
                digest_bytes(f.independent.to_string().as_bytes()).as_bytes()
            )
            .expect("independent source"),
        before
            .get(
                &f.service.keyspaces.observations_content,
                digest_bytes(f.independent.to_string().as_bytes()).as_bytes()
            )
            .expect("original independent source")
    );
    archives.push(
        f.service
            .create_backup(CreateBackupRequest {
                context: f.context.clone(),
            })
            .expect("cleaned archive"),
    );
    drop((before, after, cleaned));
    drop(f.service);
    let reopened = NativeService::open_with_suppression(
        f.root.path().join("native"),
        "record-witness",
        [7; 32],
        f.ledger.clone(),
    )
    .expect("reopen cleaned owner");
    reopened
        .verify_native(true)
        .expect("actual reopen after body erasure");
    for (index, archive) in archives.into_iter().enumerate() {
        let restored = NativeService::open_with_suppression(
            f.root.path().join(format!("restore-{index}")),
            "record-witness",
            [7; 32],
            f.ledger.clone(),
        )
        .expect("restore target");
        restored
            .restore_backup(RestoreBackupRequest {
                context: f.context.clone(),
                format: archive.format,
                bytes: archive.bytes,
                digest: archive.digest,
            })
            .expect("mixed/full/cleaned restore");
        restored
            .prune_record_revision(
                &f.context,
                first_witness.as_ref().expect("witness"),
                &mut budget(),
            )
            .expect("restored pruning or original receipt");
        restored
            .verify_native(true)
            .expect("restored history remains verifiable");
        assert!(
            restored
                .get_memory(GetMemoryRequest {
                    context: f.context.clone(),
                    record_id: "private-record".into(),
                    at_commit: None
                })
                .is_err()
        );
    }
}
