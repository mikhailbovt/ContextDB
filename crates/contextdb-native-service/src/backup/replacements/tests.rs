use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use crate::{CustodyMasterKey, NativeCustodyKeys, NativeSuppressionLedger};
use contextdb_service::{CapturePort, CognitiveMemoryService};
use zeroize::Zeroizing;

fn archive(f: &Fixture) -> BackupResponse {
    f.native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("archive")
}

fn prune(
    service: &NativeService,
    context: &AuthenticatedRequestContext,
    removal: &NativeRemovalRequestReceipt,
) {
    service
        .prepare_original_removal_sources(context, removal, &removal.roots, &mut budget())
        .expect("prepare");
    service
        .maintain_custody(context, 256, &mut budget())
        .expect("custody");
    service
        .prune_original_sources(context, removal, &removal.roots, &mut budget())
        .expect("prune");
}

fn replace(f: &Fixture, old: &BackupResponse) -> ServiceResult<NativeRemovalBackup> {
    f.native
        .create_removal_backup(&f.input.context, &f.removal, old, &mut budget())
}

#[test]
fn archive_replacement_preserves_independent_bytes_retries_and_both_authorities() {
    let f = fixture();
    let old = archive(&f);
    let source = decode_backup(&old.bytes, "primary-decisions").expect("source");
    let before = f
        .native
        .engine
        .decode_snapshot(BackupSnapshot::new(&source));
    let independent = before
        .scan_prefix(&f.native.keyspaces.observations_content, b"")
        .expect("originals")
        .into_iter()
        .find(|row| {
            row.key != digest_bytes(f.input.event.event_id.to_string().as_bytes()).as_bytes()
        })
        .expect("independent original");
    prune(&f.native, &f.input.context, &f.removal);
    let native_head = f.native.engine.head_sequence().expect("native head");
    let key_head = f
        .keys
        .backup_catalog_page(0, None, 256)
        .expect("catalog")
        .revision;
    let result = replace(&f, &old).expect("replacement");
    assert_eq!(
        f.keys
            .backup_catalog_page(0, None, 256)
            .expect("catalog")
            .revision,
        key_head + 1
    );
    assert_eq!(result.replacement.pruning.sources, 1);
    assert_eq!(result.replacement.pruning.total(), Some(1));
    assert_eq!(
        result.replacement.source.registration.archive_digest,
        old.digest
    );
    assert_eq!(
        result.replacement.target.registration.archive_digest,
        result.backup.digest
    );
    assert_eq!(result.replacement.receipt.sequence, 1);
    assert_eq!(replace(&f, &old).expect("exact retry"), result);
    assert_eq!(
        f.keys
            .backup_catalog_page(0, None, 256)
            .expect("catalog")
            .revision,
        key_head + 1
    );
    assert_eq!(
        f.native.engine.head_sequence().expect("native unchanged"),
        native_head
    );
    assert_eq!(
        f.keys
            .backup_replacement(&result.replacement.receipt, &mut budget())
            .expect("retained proof"),
        result.replacement
    );
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop(before);
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_id,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master"),
    )
    .expect("cold key reopen");
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "primary-decisions", ledger_id)
            .expect("cold ledger reopen");
    for (name, backup) in [
        ("full", old.clone()),
        ("replacement", result.backup.clone()),
    ] {
        let native = NativeService::open_encrypted(
            f.root.path().join(name),
            "primary-decisions",
            [9; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("restore owner");
        native
            .restore_backup(RestoreBackupRequest {
                context: f.input.context.clone(),
                bytes: backup.bytes,
                format: backup.format,
                digest: backup.digest,
            })
            .expect("actual restore");
        native.verify_native(true).expect("full native replay");
        let view = native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("view");
        assert_eq!(
            view.get(&native.keyspaces.observations_content, &independent.key)
                .expect("independent"),
            Some(independent.value.clone())
        );
        assert_eq!(
            view.get(
                &native.keyspaces.observations_content,
                digest_bytes(f.input.event.event_id.to_string().as_bytes()).as_bytes()
            )
            .expect("selected")
            .is_none(),
            name == "replacement"
        );
        assert_eq!(
            keys.backup_replacement(&result.replacement.receipt, &mut budget())
                .expect("proof survives old native restore"),
            result.replacement
        );
        drop(view);
        if name == "replacement" {
            assert_eq!(
                native
                    .create_removal_backup(&f.input.context, &f.removal, &old, &mut budget())
                    .expect("retry from replacement restore"),
                result
            );
        }
    }
}

#[test]
fn archive_replacement_requires_authorization_verified_bytes_and_actual_pruning() {
    let f = fixture();
    let old = archive(&f);
    assert!(
        replace(&f, &old).is_err(),
        "unchanged history is not cleanup"
    );
    f.native
        .append_event(request(3, "new independent original"))
        .expect("addition");
    assert!(
        replace(&f, &old).is_err(),
        "ordinary history growth is not cleanup"
    );
    let (_, unissued) = f
        .native
        .build_native_backup()
        .expect("verified but unissued");
    prune(&f.native, &f.input.context, &f.removal);
    let key_head = f
        .keys
        .backup_catalog_page(0, None, 256)
        .expect("catalog")
        .revision;
    assert!(
        replace(&f, &unissued).is_err(),
        "cannot invent original issuance"
    );
    let mut malformed = old.clone();
    malformed.bytes.clear();
    let mut denied = f.input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.native
            .create_removal_backup(&denied, &f.removal, &malformed, &mut budget())
            .expect_err("auth first")
            .code,
        ErrorCode::Unauthorized
    );
    assert!(replace(&f, &malformed).is_err());
    let mut foreign = f.input.context.clone();
    foreign.request.workspace_id = "another-workspace".into();
    assert!(
        f.native
            .create_removal_backup(&foreign, &f.removal, &old, &mut budget())
            .is_err()
    );
    let mut wrong = f.removal.clone();
    wrong.digest = "ab".repeat(32);
    assert!(
        f.native
            .create_removal_backup(&f.input.context, &wrong, &old, &mut budget())
            .is_err()
    );
    let mut empty = QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert_eq!(
        f.native
            .create_removal_backup(&f.input.context, &f.removal, &old, &mut empty)
            .expect_err("bounded")
            .code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        f.keys
            .backup_catalog_page(0, None, 256)
            .expect("catalog")
            .revision,
        key_head
    );
    replace(&f, &old).expect("valid input still accepted");
}

#[test]
fn archive_replacement_rejects_divergent_issued_history_even_with_later_commit() {
    let f = fixture();
    let old = archive(&f);
    let fork = NativeService::open_encrypted(
        f.root.path().join("fork"),
        "primary-decisions",
        [9; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("fork");
    fork.restore_backup(RestoreBackupRequest {
        context: f.input.context.clone(),
        bytes: old.bytes.clone(),
        format: old.format.clone(),
        digest: old.digest.clone(),
    })
    .expect("fork restore");
    fork.append_event(request(3, "independent fork-only source"))
        .expect("fork mutation");
    let divergent = fork
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("issued divergent archive");
    f.native
        .append_event(request(3, "different independent main source"))
        .expect("main mutation");
    prune(&f.native, &f.input.context, &f.removal);
    assert!(
        f.native
            .verify_native(true)
            .expect("valid current history")
            .commit_seq
            > divergent.commit_seq
    );
    let key_head = f
        .keys
        .backup_catalog_page(0, None, 256)
        .expect("catalog")
        .revision;
    assert!(
        replace(&f, &divergent).is_err(),
        "sequence order does not prove ancestry"
    );
    assert_eq!(
        f.keys
            .backup_catalog_page(0, None, 256)
            .expect("catalog")
            .revision,
        key_head
    );
    replace(&f, &old).expect("common ancestor is valid");
}

#[test]
fn archive_replacement_rejects_cleanup_bound_to_another_request() {
    let f = fixture();
    let old = archive(&f);
    let source = f
        .native
        .read_original_removal_inventory(&f.input.context, &f.removal, &mut budget())
        .expect("first lineage");
    let view = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    let independent = view
        .scan_prefix(&f.native.keyspaces.events, b"")
        .expect("history")
        .into_iter()
        .map(|row| decode::<StoredEvent>(&row.value, "event").expect("event"))
        .filter_map(|event| event.accepted_original.map(|original| original.event_id))
        .find(|id| !source.roots.contains(id))
        .expect("independent source");
    drop(view);
    let second = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([independent]),
            "second-removal",
            &mut budget(),
        )
        .expect("second request");
    prune(&f.native, &f.input.context, &second);
    assert!(
        replace(&f, &old).is_err(),
        "another request cannot authorize this removal"
    );
    let valid = f
        .native
        .create_removal_backup(&f.input.context, &second, &old, &mut budget())
        .expect("actual request");
    assert_eq!(valid.replacement.request, second);
    assert_eq!(valid.replacement.pruning.sources, 1);
}

#[test]
fn archive_replacement_tracks_partial_chunks_without_losing_an_independent_payload() {
    use contextdb_service::{PayloadPort, StagePayloadRequest};
    let f = crate::retention::keys::owned::tests::fixture();
    let independent = f
        .native
        .stage_payload(StagePayloadRequest {
            context: f.input.context.clone(),
            idempotency_key: "independent-payload".into(),
            block_id: contextdb_core::ContentBlockId::new(),
            bytes: b"independent-payload-sentinel".to_vec(),
        })
        .expect("independent payload");
    let old = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("full archive");
    prune(&f.native, &f.input.context, &f.removal);
    let partial = f
        .native
        .prune_original_payload(
            &f.input.context,
            &f.removal,
            f.payload.block_id,
            1,
            &mut budget(),
        )
        .expect("first chunk");
    assert!(!partial.complete);
    let replacement = f
        .native
        .create_removal_backup(&f.input.context, &f.removal, &old, &mut budget())
        .expect("partial replacement");
    assert_eq!(replacement.replacement.pruning.sources, 1);
    assert_eq!(replacement.replacement.pruning.payloads, 1);
    assert!(
        f.native
            .prune_original_payload(
                &f.input.context,
                &f.removal,
                f.payload.block_id,
                1,
                &mut budget()
            )
            .expect("last chunk")
            .complete
    );
    let final_result = f
        .native
        .create_removal_backup(
            &f.input.context,
            &f.removal,
            &replacement.backup,
            &mut budget(),
        )
        .expect("replacement of a partial archive");
    assert_eq!(final_result.replacement.receipt.sequence, 2);
    assert_eq!(final_result.replacement.pruning.sources, 0);
    assert_eq!(final_result.replacement.pruning.payloads, 1);
    let mut chunk_key = format!("payload/chunk/{}/", independent.reference.block_id).into_bytes();
    chunk_key.extend_from_slice(&0_u32.to_be_bytes());
    for (name, backup) in [
        ("partial", replacement.backup),
        ("final", final_result.backup),
    ] {
        let native = NativeService::open_encrypted(
            f.root.path().join(name),
            "owned-decisions",
            [9; 32],
            f.ledger.clone(),
            f.keys.clone(),
        )
        .expect("restore owner");
        native
            .restore_backup(RestoreBackupRequest {
                context: f.input.context.clone(),
                bytes: backup.bytes,
                format: backup.format,
                digest: backup.digest,
            })
            .expect("actual restore");
        native.verify_native(true).expect("chunk replay");
        let view = native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("view");
        assert_eq!(
            view.get(&native.keyspaces.continuous, &chunk_key)
                .expect("independent bytes"),
            Some(b"independent-payload-sentinel".to_vec())
        );
        let selected = format!("payload/chunk/{}/", f.payload.block_id);
        assert_eq!(
            view.scan_prefix(&native.keyspaces.continuous, selected.as_bytes())
                .expect("selected chunks")
                .len(),
            usize::from(name == "partial")
        );
    }
}

#[test]
fn archive_replacement_accepts_generic_revision_cleanup_and_preserves_independent_records() {
    use crate::record_journal::controls::witness::tests::{fixture_with_keys, prepare};
    let (_directory, keys) = crate::encryption::tests::authority("record-witness");
    let f = fixture_with_keys(Some(keys));
    let old = f
        .service
        .create_backup(CreateBackupRequest {
            context: f.context.clone(),
        })
        .expect("full record archive");
    let key = history_key(&digest_bytes(b"independent-record"), 1);
    let view = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view");
    let independent = view
        .get(&f.service.keyspaces.content_history, &key)
        .expect("record")
        .expect("body");
    drop(view);
    let witness = prepare(&f, "private-record", 1).expect("closed revision witness");
    f.service
        .prune_record_revision(&f.context, &witness, &mut budget())
        .expect("prune birth and closure");
    let result = f
        .service
        .create_removal_backup(&f.context, &f.removal, &old, &mut budget())
        .expect("replacement");
    assert_eq!(result.replacement.pruning.records, 1);
    assert_eq!(result.replacement.pruning.total(), Some(1));
    let target = decode_backup(&result.backup.bytes, "record-witness").expect("archive");
    let after = f
        .service
        .engine
        .decode_snapshot(BackupSnapshot::new(&target));
    assert_eq!(
        after
            .get(&f.service.keyspaces.content_history, &key)
            .expect("independent record"),
        Some(independent)
    );
    f.service
        .verify_backup_snapshot(&after)
        .expect("complete graph and history");
}

#[test]
fn archive_replacement_preserves_independent_mutations_in_a_mixed_assertion_batch() {
    let f = crate::assertions::retention::witness::tests::fixture();
    let old = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.first.context.clone(),
        })
        .expect("mixed archive");
    f.native
        .prepare_original_removal_sources(
            &f.first.context,
            &f.removal,
            &f.removal.roots,
            &mut budget(),
        )
        .expect("prepare selected source");
    f.native
        .maintain_custody(&f.first.context, 256, &mut budget())
        .expect("current custody");
    let pruned = f
        .native
        .prune_source_assertions(
            &f.first.context,
            &f.removal,
            f.accepted.workspace_commit,
            &mut budget(),
        )
        .expect("selected mutation");
    assert_eq!(pruned.mutations, BTreeSet::from([1]));
    let result = f
        .native
        .create_removal_backup(&f.first.context, &f.removal, &old, &mut budget())
        .expect("mixed replacement");
    assert_eq!(result.replacement.pruning.assertions, 1);
    assert_eq!(result.replacement.pruning.total(), Some(1));
    let target = decode_backup(&result.backup.bytes, "assertion-witness").expect("archive");
    let after = f
        .native
        .engine
        .decode_snapshot(BackupSnapshot::new(&target));
    f.native
        .verify_backup_snapshot(&after)
        .expect("all independent mutation bodies and policies remain replayable");
    let values = f
        .native
        .read_assertion_key_inventory(&f.first.context, &f.witness, &mut budget())
        .expect("preservation evidence")
        .value_ownership
        .expect("classified values");
    assert!(values.addresses.values().flatten().any(|entry| matches!(
        &entry.disposition, crate::NativeAssertionValueDisposition::PreserveIndependent { mutations } if mutations == &BTreeSet::from([0, 2, 3])
    )));
}
