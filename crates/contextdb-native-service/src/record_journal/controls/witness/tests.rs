use contextdb_recall::QueryCancellation;
use contextdb_service::{CapturePort, CognitiveMemoryService, StructuredMemoryKind};
use std::sync::Arc;

use super::*;
use crate::record_sources::tests::{budget, input, publication};

mod key_inventory;
mod legacy;
mod nonretrievable;

pub(crate) struct Fixture {
    pub(crate) root: tempfile::TempDir,
    pub(crate) ledger_directory: tempfile::TempDir,
    pub(crate) ledger: Arc<NativeSuppressionLedger>,
    pub(crate) service: Arc<NativeService>,
    pub(crate) context: AuthenticatedRequestContext,
    pub(crate) source: ObservationId,
    pub(crate) independent: ObservationId,
    pub(crate) removal: NativeRemovalRequestReceipt,
    original: MutationResponse,
}

pub(crate) fn fixture() -> Fixture {
    fixture_with_keys(None)
}

pub(crate) fn fixture_with_keys(keys: Option<Arc<NativeCustodyKeys>>) -> Fixture {
    let root = tempfile::tempdir().expect("root");
    let (ledger_directory, ledger) = suppression::tests::authority("record-witness");
    let service = Arc::new(
        match keys {
            Some(keys) => NativeService::open_encrypted(
                root.path().join("native"),
                "record-witness",
                [7; 32],
                ledger.clone(),
                keys,
            ),
            None => NativeService::open_with_suppression(
                root.path().join("native"),
                "record-witness",
                [7; 32],
                ledger.clone(),
            ),
        }
        .expect("native"),
    );
    let first = input(1, "PRIVATE-WITNESS-ORIGINAL");
    let second = input(2, "independent original");
    service.append_event(first.clone()).expect("capture");
    service.append_event(second.clone()).expect("capture");
    let context = first.context;
    let source = first.event.event_id;
    let independent = second.event.event_id;
    let original = service
        .publish_memory_from_sources(
            publication(&context, "private-record"),
            &BTreeSet::from([source]),
            &mut budget(),
        )
        .expect("original record");
    service
        .retract_from_sources(
            ForgetRequest {
                context: context.clone(),
                idempotency_key: "retract-record".into(),
                target_id: "private-record".into(),
                mode: ForgetMode::Retract,
                reason: "requested".into(),
            },
            &BTreeSet::from([independent]),
            &mut budget(),
        )
        .expect("closure and copied revision");
    service
        .publish_memory_from_sources(
            publication(&context, "independent-record"),
            &BTreeSet::from([independent]),
            &mut budget(),
        )
        .expect("independent record");
    for (id, parents) in [
        ("PRIVATE-PARENT", vec![]),
        ("PRIVATE-CHILD", vec!["PRIVATE-PARENT".into()]),
    ] {
        service
            .propose_memory_from_sources(
                ProposeMemoryRequest {
                    context: context.clone(),
                    idempotency_key: format!("proposal-{id}"),
                    candidate_id: id.into(),
                    semantic_kind: StructuredMemoryKind::Fact,
                    value: serde_json::json!({"secret": "PRIVATE-PROPOSAL-BODY"}),
                    search_text: "PRIVATE-PROPOSAL-TEXT".into(),
                    parent_candidate_ids: parents.into_iter().collect(),
                    supersedes_candidate_ids: BTreeSet::new(),
                },
                &BTreeSet::from([source]),
                &mut budget(),
            )
            .expect("candidate graph");
    }
    let removal = service
        .request_original_removal(
            &context,
            &BTreeSet::from([source]),
            "remove-source",
            &mut budget(),
        )
        .expect("retained removal");
    Fixture {
        root,
        ledger_directory,
        ledger,
        service,
        context,
        source,
        independent,
        removal,
        original,
    }
}

pub(crate) fn prepare(
    f: &Fixture,
    record: &str,
    revision: u32,
) -> ServiceResult<NativeRecordRemovalWitnessReceipt> {
    f.service.prepare_record_removal(
        &f.context,
        &f.removal,
        record,
        revision,
        f.source,
        &mut budget(),
    )
}

#[test]
fn independently_retained_record_witnesses_preserve_native_bytes_across_old_restore() {
    let f = fixture();
    let archive = f
        .service
        .create_backup(CreateBackupRequest {
            context: f.context.clone(),
        })
        .expect("old archive");
    let before = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let mut receipts = Vec::new();
    let edge = candidate_hierarchy_edge_id("PRIVATE-PARENT", "PRIVATE-CHILD").expect("edge");
    for (record, revision) in [
        ("private-record", 1),
        ("private-record", 2),
        ("PRIVATE-PARENT", 1),
        ("PRIVATE-CHILD", 1),
        (edge.as_str(), 1),
    ] {
        let receipt = prepare(&f, record, revision).expect("retain witness");
        assert_eq!(prepare(&f, record, revision).expect("exact retry"), receipt);
        receipts.push((record.to_owned(), revision, receipt));
    }
    let after = f
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    for space in f.service.keyspaces.all() {
        assert_eq!(
            before.scan_prefix(space, b"").expect("before"),
            after.scan_prefix(space, b"").expect("after"),
            "{}",
            space.as_str()
        );
    }
    assert_eq!(
        f.ledger
            .current_removal(&digest_bytes(f.context.request.workspace_id.as_bytes()))
            .expect("retention"),
        Some(RemovalCheckpoint {
            sequence: f.removal.sequence,
            digest: f.removal.digest.clone()
        })
    );
    f.service
        .verify_native(true)
        .expect("native graph and history unchanged");
    let restored = NativeService::open_with_suppression(
        f.root.path().join("restored"),
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
        .expect("old native restore");
    for (record, revision, receipt) in receipts {
        assert_eq!(
            restored
                .prepare_record_removal(
                    &f.context,
                    &f.removal,
                    &record,
                    revision,
                    f.source,
                    &mut budget()
                )
                .expect("retained receipt after old restore"),
            receipt
        );
    }
    let mut original = f.original.clone();
    original.replayed = true;
    assert_eq!(
        restored
            .publish_memory_from_sources(
                publication(&f.context, "private-record"),
                &BTreeSet::from([f.source]),
                &mut budget()
            )
            .expect("original receipt"),
        original
    );
    assert!(
        restored
            .get_memory(GetMemoryRequest {
                context: f.context.clone(),
                record_id: "private-record".into(),
                at_commit: None
            })
            .is_err()
    );
    restored
        .verify_native(true)
        .expect("restored full bodies remain valid");
}

#[test]
fn record_witness_authority_budget_cas_and_lost_ack_do_not_erase_bodies() {
    let f = fixture();
    let mut denied = f.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        f.service
            .prepare_record_removal(
                &denied,
                &f.removal,
                "private-record",
                1,
                f.source,
                &mut budget()
            )
            .expect_err("admin")
            .code,
        ErrorCode::Unauthorized
    );
    denied = f.context.clone();
    denied.request.scopes = BTreeSet::from(["outside".into()]);
    assert_eq!(
        f.service
            .prepare_record_removal(
                &denied,
                &f.removal,
                "private-record",
                1,
                f.source,
                &mut budget()
            )
            .expect_err("policy")
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(prepare(&f, "independent-record", 1).is_err());
    let mut limited =
        QueryBudget::new(0, 0, std::time::Duration::from_secs(30), Default::default());
    assert!(
        f.service
            .prepare_record_removal(
                &f.context,
                &f.removal,
                "private-record",
                1,
                f.source,
                &mut limited
            )
            .is_err()
    );
    let service = f.service.clone();
    BEFORE_PUBLICATION.with(|hook| {
        hook.replace(Some(Box::new(move || {
            service
                .append_event(input(3, "concurrent capture"))
                .expect("concurrent native write");
        })))
    });
    assert_eq!(
        prepare(&f, "private-record", 1)
            .expect_err("workspace CAS")
            .code,
        ErrorCode::IndexTooStale
    );
    let cancellation = QueryCancellation::default();
    let cancel = cancellation.clone();
    AFTER_AUTHORITY_SYNC.with(|hook| hook.replace(Some(Box::new(move || cancel.cancel()))));
    let mut interrupted = QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        std::time::Duration::from_secs(30),
        cancellation,
    );
    assert!(
        f.service
            .prepare_record_removal(
                &f.context,
                &f.removal,
                "private-record",
                1,
                f.source,
                &mut interrupted
            )
            .is_err()
    );
    let accepted = prepare(&f, "private-record", 1).expect("recover uncertain acknowledgement");
    assert_eq!(prepare(&f, "private-record", 1).expect("repeat"), accepted);
    f.service.verify_native(true).expect("no body erased");
}

#[test]
fn record_witness_rejects_a_rehashed_mutation_with_an_invalid_owner() {
    let f = fixture();
    let mut tx = f.service.engine.begin_write().expect("transaction");
    let origin = f
        .ledger
        .retained_record_sources(
            &digest_bytes(f.context.request.workspace_id.as_bytes()),
            &digest_bytes(b"private-record"),
            1,
        )
        .expect("origin")
        .expect("classified");
    let global = origin.record_control().expect("control").transaction_from;
    let mut event = f
        .service
        .recovery_global_event(&tx, global, &mut budget())
        .expect("event");
    event.operation = "capture".into();
    tx.put(
        &f.service.keyspaces.events,
        global.to_be_bytes().to_vec(),
        encode(&event).expect("event"),
    )
    .expect("wrong owner");
    preparation::tests::rehash(&f.service, &mut tx);
    tx.commit(Durability::Sync).expect("rehash native history");
    assert_eq!(
        prepare(&f, "private-record", 1)
            .expect_err("wrong publication owner")
            .code,
        ErrorCode::IntegrityFailure
    );
}
