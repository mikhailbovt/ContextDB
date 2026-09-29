use super::*;
use crate::retention::keys::witness::tests::{Fixture, budget};
use crate::{NativeRemovalBackup, NativeService, NativeSuppressionLedger};
use contextdb_core::ContentBlockId;
use contextdb_service::{
    Capability, CapturePort, CognitiveMemoryService, CreateBackupRequest, PayloadPort,
    RestoreBackupRequest, StagePayloadRequest,
};

mod crashes;

fn prepared(large: bool) -> (Fixture, BackupResponse, NativeRemovalBackup) {
    let root = tempfile::tempdir().expect("root");
    let keys = NativeCustodyKeys::create(root.path().join("keys"), "primary-decisions", master())
        .expect("keys");
    let ledger = NativeSuppressionLedger::create(root.path().join("ledger"), "primary-decisions")
        .expect("ledger");
    let native = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            "primary-decisions",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native"),
    );
    let input = crate::capture::tests::request(1, "selected original");
    native.append_event(input.clone()).expect("capture");
    native
        .append_event(crate::capture::tests::request(2, "independent original"))
        .expect("capture");
    if large {
        let mut input = crate::capture::tests::request(3, "independent large original");
        let staged = native
            .stage_payload(StagePayloadRequest {
                context: input.context.clone(),
                idempotency_key: "artifact-independent-payload".into(),
                block_id: ContentBlockId::new(),
                bytes: vec![37; 700 * 1024],
            })
            .expect("stage independent bytes");
        input.event.payload = contextdb_core::EventPayload::Staged {
            reference: staged.reference,
            media_type: "application/octet-stream".into(),
        };
        native
            .append_event(input)
            .expect("capture independent payload");
    }
    let removal = native
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "remove",
            &mut budget(),
        )
        .expect("removal");
    let witness = native
        .retain_original_key_removal(&input.context, &removal, &mut budget())
        .expect("witness");
    let f = Fixture {
        root,
        native,
        keys,
        ledger,
        input,
        removal,
        witness,
    };
    let old = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("original archive");
    f.native
        .prepare_original_removal_sources(
            &f.input.context,
            &f.removal,
            &f.removal.roots,
            &mut budget(),
        )
        .expect("prepare");
    f.native
        .maintain_custody(&f.input.context, 256, &mut budget())
        .expect("custody");
    f.native
        .prune_original_sources(
            &f.input.context,
            &f.removal,
            &f.removal.roots,
            &mut budget(),
        )
        .expect("prune");
    let result = f
        .native
        .create_removal_backup(&f.input.context, &f.removal, &old, &mut budget())
        .expect("verified replacement");
    (f, old, result)
}

fn retain(
    f: &Fixture,
    result: &NativeRemovalBackup,
    from: u32,
    count: u32,
) -> ServiceResult<NativeBackupArtifactProgress> {
    f.native.retain_removal_backup(
        &f.input.context,
        &f.removal,
        result,
        from,
        count,
        &mut budget(),
    )
}

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master")
}

#[test]
fn archive_artifact_resumes_exact_bytes_across_cold_reopen_and_old_native_restore() {
    let (f, old, result) = prepared(true);
    let before = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("before");
    assert!(
        f.keys
            .backup_artifact(&result.backup.digest, &mut budget())
            .expect("unknown")
            .is_none()
    );
    let first = retain(&f, &result, 0, 1).expect("first portion");
    assert!(!first.complete);
    assert!(first.total_pages > 2);
    assert_eq!(first.stored_pages, 1);
    assert_eq!(first.stored_bytes, CHUNK_BYTES as u64);
    let head = f.keys.engine.head_sequence().expect("head");
    assert_eq!(retain(&f, &result, 0, 1).expect("exact retry"), first);
    assert_eq!(
        f.keys.engine.head_sequence().expect("no duplicate Sync"),
        head
    );
    assert_eq!(
        retain(&f, &result, 0, 2).expect_err("changed limit").code,
        ErrorCode::IdempotencyConflict
    );
    assert!(retain(&f, &result, 2, 1).is_err(), "cannot skip a page");
    assert_eq!(
        f.native
            .read_retained_removal_backup(
                &f.input.context,
                &f.removal,
                &result.replacement.receipt,
                &first.receipt,
                &mut budget(),
            )
            .expect_err("partial bytes are unavailable")
            .code,
        ErrorCode::IndexTooStale
    );
    let mut progress = first.clone();
    while !progress.complete {
        progress = retain(&f, &result, progress.stored_pages, 16).expect("next bounded portion");
    }
    assert_eq!(progress.stored_bytes, result.backup.bytes.len() as u64);
    assert_eq!(
        f.native
            .read_retained_removal_backup(
                &f.input.context,
                &f.removal,
                &result.replacement.receipt,
                &progress.receipt,
                &mut budget(),
            )
            .expect("complete bytes"),
        result.backup
    );
    assert_eq!(
        f.native
            .read_retained_removal_backup(
                &f.input.context,
                &f.removal,
                &result.replacement.receipt,
                &first.receipt,
                &mut budget(),
            )
            .expect_err("old partial receipt stays partial")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        retain(&f, &result, 0, 1).expect("old retry stays exact"),
        first
    );
    let after = f
        .keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("after");
    assert_eq!(
        before.frontier.issued_sequence,
        after.frontier.issued_sequence
    );
    assert_eq!(before.frontier.contents, after.frontier.contents);
    assert_eq!(before.frontier.replacements, after.frontier.replacements);
    assert_ne!(before.frontier.artifacts, after.frontier.artifacts);
    assert_eq!(
        f.keys
            .require_backup_frontier(&before.frontier, &mut budget())
            .expect_err("byte publication invalidates custody decision")
            .code,
        ErrorCode::IndexTooStale
    );
    assert_eq!(
        after.archives.last().expect("target").artifact,
        Some(progress.clone())
    );
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_id,
        master(),
    )
    .expect("cold keys reopen");
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "primary-decisions", ledger_id)
            .expect("cold ledger reopen");
    for (name, backup) in [
        ("old-restore", old),
        ("clean-restore", result.backup.clone()),
    ] {
        let native = NativeService::open_encrypted(
            f.root.path().join(name),
            "primary-decisions",
            [8; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native");
        native
            .restore_backup(RestoreBackupRequest {
                context: f.input.context.clone(),
                bytes: backup.bytes,
                format: backup.format,
                digest: backup.digest,
            })
            .expect("actual restore");
        native.verify_native(true).expect("native replay");
        assert_eq!(
            native
                .read_retained_removal_backup(
                    &f.input.context,
                    &f.removal,
                    &result.replacement.receipt,
                    &progress.receipt,
                    &mut budget(),
                )
                .expect("independent artifact survives restore"),
            result.backup
        );
        assert_eq!(
            keys.backup_artifact(&result.backup.digest, &mut budget())
                .expect("availability"),
            Some(progress.clone())
        );
    }
}

#[test]
fn archive_artifact_interleaves_archives_and_preserves_anchor_on_new_issuance() {
    let (f, old, first) = prepared(true);
    let first_page = retain(&f, &first, 0, 1).expect("first");
    f.native
        .append_event(crate::capture::tests::request(
            4,
            "another independent original",
        ))
        .expect("append");
    let second = f
        .native
        .create_removal_backup(&f.input.context, &f.removal, &old, &mut budget())
        .expect("later replacement");
    assert_eq!(
        f.keys
            .backup_artifact(&first.backup.digest, &mut budget())
            .expect("anchor retained"),
        Some(first_page)
    );
    let second_page = retain(&f, &second, 0, 1).expect("second");
    assert_eq!(second_page.receipt.sequence, 2);
    for result in [&first, &second] {
        let done = retain(&f, result, 1, 16).expect("interleaved completion");
        assert!(done.complete);
        assert_eq!(
            f.native
                .read_retained_removal_backup(
                    &f.input.context,
                    &f.removal,
                    &result.replacement.receipt,
                    &done.receipt,
                    &mut budget(),
                )
                .expect("right archive bytes"),
            result.backup
        );
    }
    f.keys.verify().expect("both artifact chains close");
}

#[test]
fn archive_artifact_policy_request_and_budget_precede_byte_access() {
    let (f, _, result) = prepared(false);
    let before = f.keys.engine.head_sequence().expect("before");
    for bound in [0, 17] {
        assert!(retain(&f, &result, 0, bound).is_err());
    }
    let mut changed = result.clone();
    changed.backup.bytes[0] ^= 1;
    assert!(retain(&f, &changed, 0, 1).is_err());
    changed = result.clone();
    changed.replacement.pruning.sources += 1;
    assert!(retain(&f, &changed, 0, 1).is_err());
    let mut empty = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert_eq!(
        f.native
            .retain_removal_backup(&f.input.context, &f.removal, &result, 0, 1, &mut empty,)
            .expect_err("empty budget")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        f.keys.engine.head_sequence().expect("no partial state"),
        before
    );
    let done = retain(&f, &result, 0, 16).expect("complete");
    assert!(done.complete);
    let other = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([crate::capture::tests::request(2, "independent original")
                .event
                .event_id]),
            "other-removal",
            &mut budget(),
        )
        .expect("another valid request");
    let mut tx = f.keys.engine.begin_write().expect("damage");
    tx.put(&f.keys.rows, chunk_key(&result.backup.digest, 0), vec![1])
        .expect("damaged ciphertext");
    tx.commit(Durability::Sync).expect("damage Sync");
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .read_retained_removal_backup(
                &f.input.context,
                &other,
                &result.replacement.receipt,
                &done.receipt,
                &mut budget(),
            )
            .expect_err("exact request before corrupt bytes")
            .message,
        "retained archive replacement belongs to another request"
    );
    assert_eq!(
        f.native
            .retain_removal_backup(&denied, &f.removal, &result, 0, 16, &mut budget(),)
            .expect_err("auth before corrupt bytes")
            .code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        f.native
            .read_retained_removal_backup(
                &denied,
                &f.removal,
                &result.replacement.receipt,
                &done.receipt,
                &mut budget(),
            )
            .expect_err("auth before corrupt bytes")
            .code,
        ErrorCode::Unauthorized
    );
    let mut foreign = f.input.context.clone();
    foreign.request.workspace_id = "other-workspace".into();
    assert!(
        f.native
            .read_retained_removal_backup(
                &foreign,
                &f.removal,
                &result.replacement.receipt,
                &done.receipt,
                &mut budget(),
            )
            .is_err()
    );
}

#[test]
fn archive_artifact_staging_failure_and_lost_response_publish_at_most_once() {
    let (f, _, result) = prepared(false);
    let before = f.keys.engine.head_sequence().expect("before");
    BEFORE_ARTIFACT_SYNC
        .with(|hook| hook.replace(Some(Box::new(|| Err(crate::exhausted("before Sync"))))));
    assert!(retain(&f, &result, 0, 16).is_err());
    assert_eq!(f.keys.engine.head_sequence().expect("rolled back"), before);
    assert!(
        f.keys
            .backup_artifact(&result.backup.digest, &mut budget())
            .expect("absent")
            .is_none()
    );
    AFTER_ARTIFACT_SYNC
        .with(|hook| hook.replace(Some(Box::new(|| Err(crate::exhausted("lost response"))))));
    assert!(retain(&f, &result, 0, 16).is_err());
    let durable = f
        .keys
        .backup_artifact(&result.backup.digest, &mut budget())
        .expect("durable")
        .expect("receipt");
    assert!(durable.complete);
    assert_eq!(
        retain(&f, &result, 0, 16).expect("recover exact acceptance"),
        durable
    );
    assert_eq!(
        f.keys.engine.head_sequence().expect("only one Sync"),
        before + 1
    );
    f.keys.verify().expect("closure");
}

fn rewrite_event(f: &Fixture, event: &mut ArtifactEvent, bytes: &[u8]) {
    let mut tx = f.keys.engine.begin_write().expect("tx");
    let chunk = chunk_key(&event.contents.registration.archive_digest, 0);
    tx.put(
        &f.keys.rows,
        chunk.clone(),
        seal(
            &f.keys.master.0,
            &f.keys.backup_aad(&chunk).expect("aad"),
            bytes,
        )
        .expect("seal"),
    )
    .expect("changed chunk");
    event.chain =
        append_chunk(&genesis(&event.contents).expect("genesis"), 0, bytes).expect("chain");
    event.digest = event.commitment().expect("commitment");
    let receipt = event.receipt();
    let key = event_key(event.sequence);
    tx.put(
        &f.keys.rows,
        key.clone(),
        f.keys.seal_backup_record(&key, event).expect("seal"),
    )
    .expect("event");
    for key in [
        index_key(&receipt.archive_digest, 0),
        latest_key(&receipt.archive_digest),
    ] {
        tx.put(
            &f.keys.rows,
            key.clone(),
            f.keys.seal_backup_record(&key, &receipt).expect("seal"),
        )
        .expect("locator");
    }
    let mut head = f.keys.backup_head(&tx).expect("head");
    head.artifacts = Some(receipt);
    tx.put(
        &f.keys.rows,
        HEAD.to_vec(),
        f.keys.seal_backup_record(HEAD, &head).expect("seal"),
    )
    .expect("head");
    tx.commit(Durability::Sync).expect("resealed fixture");
}

fn accepted_event(f: &Fixture, receipt: &NativeBackupArtifactReceipt) -> ArtifactEvent {
    let snapshot = f
        .keys
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    f.keys
        .read_artifact_record(&snapshot, &event_key(receipt.sequence), &mut budget())
        .expect("event")
}

#[test]
fn archive_artifact_missing_extra_or_rehashed_data_cannot_claim_availability() {
    for fault in [
        "chunk", "event", "index", "latest", "orphan", "head", "rehashed",
    ] {
        let (f, _, result) = prepared(false);
        let done = retain(&f, &result, 0, 16).expect("complete");
        assert_eq!(done.total_pages, 1, "single-page corruption fixture");
        if fault == "rehashed" {
            let mut bytes = result.backup.bytes.clone();
            bytes[0] ^= 1;
            rewrite_event(&f, &mut accepted_event(&f, &done.receipt), &bytes);
        } else {
            let mut tx = f.keys.engine.begin_write().expect("tx");
            match fault {
                "chunk" => tx
                    .delete(&f.keys.rows, chunk_key(&result.backup.digest, 0))
                    .expect("loss"),
                "event" => tx
                    .delete(&f.keys.rows, event_key(done.receipt.sequence))
                    .expect("loss"),
                "index" => tx
                    .delete(&f.keys.rows, index_key(&result.backup.digest, 0))
                    .expect("loss"),
                "latest" => tx
                    .delete(&f.keys.rows, latest_key(&result.backup.digest))
                    .expect("loss"),
                "orphan" => tx
                    .put(&f.keys.rows, chunk_key(&result.backup.digest, 1), vec![1])
                    .expect("extra chunk"),
                "head" => {
                    let mut head = f.keys.backup_head(&tx).expect("head");
                    head.artifacts = None;
                    tx.put(
                        &f.keys.rows,
                        HEAD.to_vec(),
                        f.keys.seal_backup_record(HEAD, &head).expect("seal"),
                    )
                    .expect("head rollback");
                }
                _ => unreachable!(),
            }
            tx.commit(Durability::Sync).expect("damage");
        }
        let before = f.keys.engine.head_sequence().expect("head");
        assert!(f.keys.verify().is_err(), "{fault}");
        assert!(
            f.keys
                .backup_artifact(&result.backup.digest, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.native
                .read_retained_removal_backup(
                    &f.input.context,
                    &f.removal,
                    &result.replacement.receipt,
                    &done.receipt,
                    &mut budget(),
                )
                .is_err(),
            "{fault}"
        );
        assert!(retain(&f, &result, 0, 16).is_err(), "{fault}");
        assert_eq!(
            f.keys.engine.head_sequence().expect("no acceptance"),
            before
        );
        let id = f.keys.authority_id();
        drop((f.native, f.keys, f.ledger));
        assert!(
            NativeCustodyKeys::open(
                f.root.path().join("keys"),
                "primary-decisions",
                id,
                master()
            )
            .is_err(),
            "cold reopen {fault}"
        );
    }
}

#[test]
fn archive_artifact_rehashed_partial_prefix_cannot_be_completed_from_valid_input() {
    let (f, _, result) = prepared(true);
    let first = retain(&f, &result, 0, 1).expect("partial");
    let mut bytes = result.backup.bytes[..CHUNK_BYTES].to_vec();
    bytes[0] ^= 1;
    rewrite_event(&f, &mut accepted_event(&f, &first.receipt), &bytes);
    // A partial prefix cannot yet be compared to the complete archive digest.
    f.keys.verify().expect("self-consistent partial metadata");
    assert!(
        !f.keys
            .backup_artifact(&result.backup.digest, &mut budget())
            .expect("partial")
            .expect("receipt")
            .complete
    );
    let before = f.keys.engine.head_sequence().expect("before");
    assert!(
        retain(&f, &result, 0, 1).is_err(),
        "cannot acknowledge false prefix"
    );
    assert!(
        retain(&f, &result, 1, 16).is_err(),
        "cannot complete a different prefix"
    );
    assert_eq!(
        f.keys.engine.head_sequence().expect("no acceptance"),
        before
    );
}
