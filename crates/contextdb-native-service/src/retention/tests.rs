use super::*;
use crate::capture::tests::request;
use contextdb_service::{CapturePort, ReadOriginalRequest};
use std::{process::Command, sync::Arc, time::Duration};

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        128 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

#[test]
fn accepted_removal_closes_disclosure_across_reopen_and_old_encrypted_restore() {
    let root = tempfile::tempdir().expect("root");
    let (_key_dir, keys) = encryption::tests::authority("retention");
    let (_ledger_dir, ledger) = suppression::tests::authority("retention");
    let input = request(1, "retain until explicit removal, then stop disclosure");
    let source = NativeService::open_encrypted(
        root.path().join("source"),
        "retention",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("open");
    source.append_event(input.clone()).expect("source");
    let backup = source
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("old encrypted archive");
    let mut child = request(2, "derived bytes accepted after the archive");
    child.event.supersedes_event_id = Some(input.event.event_id);
    source
        .append_event(child.clone())
        .expect("later descendant");
    let independent = request(3, "derived bytes accepted after the archive");
    source
        .append_event(independent.clone())
        .expect("independent identical bytes");
    let roots = BTreeSet::from([input.event.event_id]);
    let receipt = source
        .request_original_removal(&input.context, &roots, "remove", &mut budget())
        .expect("durable request");
    assert_eq!(
        source
            .request_original_removal(&input.context, &roots, "remove", &mut budget())
            .expect("exact retry"),
        receipt
    );
    let key_inventory = source
        .read_original_key_inventory(&input.context, &receipt, &mut budget())
        .expect("source keys selected through retained lineage");
    assert_eq!(
        key_inventory
            .sources
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([input.event.event_id, child.event.event_id])
    );
    assert!(key_inventory.sources.values().all(|keys| keys.len() == 1));
    let usage = key_inventory.native_use.as_ref().expect("v4 source use");
    assert_eq!(usage.addresses.len(), 2);
    for key in key_inventory.sources.values().flatten() {
        let history = &usage.addresses[&key.address_digest];
        assert_eq!(history.transitions.len(), 1);
        assert_eq!(
            history.transitions[0]
                .after
                .as_ref()
                .expect("accepted original")
                .key_id,
            key.key_id
        );
        assert_eq!(history.acknowledged.len(), 1);
    }
    assert!(
        !key_inventory
            .sources
            .contains_key(&independent.event.event_id)
    );
    let before_keys = keys
        .key_catalog_page(None, 1, &mut budget())
        .expect("key head before inventory denials")
        .revision;
    let mut denied = input.context.clone();
    denied.capability_grants.remove(&Capability::Admin);
    assert_eq!(
        source
            .read_original_key_inventory(&denied, &receipt, &mut budget())
            .expect_err("admin required")
            .code,
        ErrorCode::Unauthorized
    );
    let mut forged = receipt.clone();
    forged.inspected_workspace_commit += 1;
    assert!(
        source
            .read_original_key_inventory(&input.context, &forged, &mut budget())
            .is_err()
    );
    assert_eq!(
        keys.key_catalog_page(None, 1, &mut budget())
            .expect("no key mutation")
            .revision,
        before_keys
    );
    drop(source);
    let reopened = NativeService::open_encrypted(
        root.path().join("source"),
        "retention",
        [8; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("reopen");
    let restored = NativeService::open_encrypted(
        root.path().join("restored"),
        "retention",
        [9; 32],
        ledger,
        keys,
    )
    .expect("restore target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: input.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("install archive");
    for service in [&reopened, &restored] {
        let current = service
            .read_original_key_inventory(&input.context, &receipt, &mut budget())
            .expect("primary keys survive older restore, including an absent later descendant");
        assert_eq!(current.sources, key_inventory.sources);
        let usage = current
            .native_use
            .as_ref()
            .expect("retained tracked copies");
        let original_address = &current.sources[&input.event.event_id][0].address_digest;
        let child_address = &current.sources[&child.event.event_id][0].address_digest;
        assert_eq!(
            usage.addresses[original_address].acknowledged.len(),
            2,
            "original was also imported into the older replica"
        );
        assert_eq!(
            usage.addresses[child_address].acknowledged.len(),
            1,
            "later descendant remains only in the newer instance"
        );
        let inventory = service
            .read_original_removal_inventory(&input.context, &receipt, &mut budget())
            .expect("full inventory survives an older native archive");
        assert_eq!(inventory.workspace_commit, 3);
        assert_eq!(
            inventory
                .sources
                .iter()
                .map(|source| source.receipt.event_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([input.event.event_id, child.event.event_id])
        );
        let workspace = digest_bytes(input.context.request.workspace_id.as_bytes());
        assert_eq!(
            service
                .require_unsuppressed_identity(&workspace, child.event.event_id)
                .expect_err("descendant ID remains denied even when absent from archive")
                .code,
            ErrorCode::PermissionDenied
        );
        service
            .require_unsuppressed_identity(&workspace, independent.event.event_id)
            .expect("same bytes alone are not deletion lineage");
        assert_eq!(
            service
                .read_original(ReadOriginalRequest {
                    context: input.context.clone(),
                    event_id: input.event.event_id,
                    after_receipt: None
                })
                .expect_err("pending deletion must gate old bytes")
                .code,
            ErrorCode::IndexTooStale
        );
        assert!(
            service
                .maintain_suppression(&input.context, 64, &mut budget())
                .expect("ordinary revocation maintenance")
                .caught_up
        );
        assert_eq!(
            service
                .read_original(ReadOriginalRequest {
                    context: input.context.clone(),
                    event_id: input.event.event_id,
                    after_receipt: None
                })
                .expect_err("ordinary maintenance cannot complete deletion")
                .code,
            ErrorCode::IndexTooStale
        );
        assert_eq!(
            service
                .request_original_removal(&input.context, &roots, "remove", &mut budget())
                .expect("lost receipt retry"),
            receipt
        );
        service
            .verify_native(true)
            .expect("intent does not yet remove bodies");
    }
    let other_roots = BTreeSet::from([ObservationId::new()]);
    let mut other_workspace = input.context.clone();
    other_workspace.request.workspace_id = contextdb_core::WorkspaceId::new().to_string();
    assert_eq!(
        reopened
            .read_original_removal_inventory(&other_workspace, &receipt, &mut budget())
            .expect_err("cannot read another workspace inventory")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        reopened
            .request_original_removal(&input.context, &other_roots, "remove", &mut budget())
            .expect_err("retry conflict before inspection")
            .code,
        ErrorCode::IdempotencyConflict
    );
}

#[test]
fn competing_replica_retry_returns_the_accepted_intent_instead_of_local_inspection() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_dir, ledger) = suppression::tests::authority("retention");
    let first = NativeService::open_with_suppression(
        root.path().join("first"),
        "retention",
        [7; 32],
        ledger.clone(),
    )
    .expect("first");
    let second = Arc::new(
        NativeService::open_with_suppression(
            root.path().join("second"),
            "retention",
            [7; 32],
            ledger,
        )
        .expect("second"),
    );
    let input = request(1, "same accepted root");
    first.append_event(input.clone()).expect("first capture");
    second.append_event(input.clone()).expect("second capture");
    second
        .append_event(request(2, "independent replica tail"))
        .expect("newer prefix");
    let roots = BTreeSet::from([input.event.event_id]);
    let concurrent = Arc::clone(&second);
    let concurrent_context = input.context.clone();
    let concurrent_roots = roots.clone();
    BEFORE_INTENT_SYNC.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            concurrent
                .request_original_removal(
                    &concurrent_context,
                    &concurrent_roots,
                    "same-key",
                    &mut budget(),
                )
                .expect("other replica wins");
        }))
    });
    let actual = first
        .request_original_removal(&input.context, &roots, "same-key", &mut budget())
        .expect("racing exact retry");
    let accepted = second
        .request_original_removal(&input.context, &roots, "same-key", &mut budget())
        .expect("accepted receipt");
    assert_eq!(actual, accepted);
    assert_eq!(actual.inspected_workspace_commit, 2);
}

#[derive(Serialize, Deserialize)]
struct CrashFixture {
    native: std::path::PathBuf,
    ledger: std::path::PathBuf,
    authority: uuid::Uuid,
}

#[test]
fn removal_intent_crash_child() {
    let Ok(path) = std::env::var("CONTEXTDB_REMOVAL_CRASH_FIXTURE") else {
        return;
    };
    let fixture: CrashFixture =
        serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("JSON");
    let ledger = NativeSuppressionLedger::open(&fixture.ledger, "retention", fixture.authority)
        .expect("ledger");
    let service =
        NativeService::open_with_suppression(&fixture.native, "retention", [7; 32], ledger)
            .expect("native");
    let input = request(1, "process crash must not reopen this original");
    AFTER_INTENT_SYNC.with(|hook| *hook.borrow_mut() = Some(Box::new(|| std::process::exit(76))));
    service
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "crash-removal",
            &mut budget(),
        )
        .expect("request");
    panic!("crash injection did not run");
}

#[test]
fn crash_after_external_intent_sync_preserves_the_gate_and_the_lost_receipt() {
    let root = tempfile::tempdir().expect("root");
    let ledger_path = root.path().join("ledger");
    let native_path = root.path().join("native");
    let input = request(1, "process crash must not reopen this original");
    let authority = {
        let ledger = NativeSuppressionLedger::create(&ledger_path, "retention").expect("ledger");
        let authority = ledger.authority_id();
        let service =
            NativeService::open_with_suppression(&native_path, "retention", [7; 32], ledger)
                .expect("native");
        service.append_event(input.clone()).expect("original");
        let mut child = request(2, "crash must retain the full source inventory");
        child.event.supersedes_event_id = Some(input.event.event_id);
        service.append_event(child).expect("derived original");
        authority
    };
    let fixture_path = root.path().join("fixture.json");
    std::fs::write(
        &fixture_path,
        serde_json::to_vec(&CrashFixture {
            native: native_path.clone(),
            ledger: ledger_path.clone(),
            authority,
        })
        .expect("JSON"),
    )
    .expect("fixture");
    let status = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "retention::tests::removal_intent_crash_child",
            "--nocapture",
        ])
        .env("CONTEXTDB_REMOVAL_CRASH_FIXTURE", fixture_path)
        .status()
        .expect("subprocess");
    assert_eq!(status.code(), Some(76));
    let ledger = NativeSuppressionLedger::open(ledger_path, "retention", authority)
        .expect("retained authority");
    let service = NativeService::open_with_suppression(native_path, "retention", [8; 32], ledger)
        .expect("recover native");
    assert_eq!(
        service
            .read_original(ReadOriginalRequest {
                context: input.context.clone(),
                event_id: input.event.event_id,
                after_receipt: None
            })
            .expect_err("persisted barrier")
            .code,
        ErrorCode::IndexTooStale
    );
    let roots = BTreeSet::from([input.event.event_id]);
    let receipt = service
        .request_original_removal(&input.context, &roots, "crash-removal", &mut budget())
        .expect("recover lost acknowledgement");
    assert_eq!(receipt.sequence, 2); // Workspace registration, then removal intent.
    service
        .require_unsuppressed_identity(
            &digest_bytes(input.context.request.workspace_id.as_bytes()),
            request(2, "crash must retain the full source inventory")
                .event
                .event_id,
        )
        .expect_err("descendant deny and inventory were synced with the request");
    assert_eq!(
        service
            .request_original_removal(&input.context, &roots, "crash-removal", &mut budget())
            .expect("exact retry"),
        receipt
    );
}
