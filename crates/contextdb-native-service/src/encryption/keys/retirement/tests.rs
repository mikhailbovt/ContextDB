use super::*;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use crate::{NativeService, NativeSuppressionLedger};
use contextdb_service::AuthenticatedRequestContext;

type Cipher = (Keyspace, Vec<u8>, Vec<u8>);

fn master() -> CustodyMasterKey {
    CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master")
}

fn pruned() -> (Fixture, Cipher) {
    let f = fixture();
    let space = f.native.keyspaces.observations_content.clone();
    let key = crate::digest_bytes(f.input.event.event_id.to_string().as_bytes()).into_bytes();
    let ciphertext = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("view")
        .inner
        .get(&space, &key)
        .expect("ciphertext")
        .expect("present");
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
    (f, (space, key, ciphertext))
}

fn ids(f: &Fixture) -> BTreeSet<Uuid> {
    f.witness
        .dispositions
        .values()
        .flatten()
        .map(|key| key.allocation.key_id)
        .collect()
}

fn retire(f: &Fixture) -> ServiceResult<NativeKeyRetirement> {
    f.native.retire_removal_keys(
        &f.input.context,
        &f.removal,
        &NativeRemovalKeySelection::Originals,
        &ids(f),
        &mut budget(),
    )
}

#[test]
fn retirement_sync_boundaries_keep_uncertain_keys_closed_and_recover_lost_reply() {
    let (f, cipher) = pruned();
    BEFORE_RETIREMENT_SYNC.with(|hook| {
        hook.replace(Some(Box::new(|| {
            Err(integrity("injected pre-Sync failure"))
        })))
    });
    assert!(retire(&f).is_err());
    assert!(
        f.keys
            .retirement_frontier()
            .expect("not accepted")
            .is_none()
    );
    f.keys
        .open_value(&cipher.0, &cipher.1, &cipher.2, None)
        .expect("no premature refusal");
    AFTER_RETIREMENT_SYNC
        .with(|hook| hook.replace(Some(Box::new(|| Err(integrity("injected lost response"))))));
    assert!(retire(&f).is_err());
    let frontier = f
        .keys
        .retirement_frontier()
        .expect("accepted current state")
        .expect("retired");
    assert!(
        f.keys
            .open_value(&cipher.0, &cipher.1, &cipher.2, None)
            .is_err()
    );
    assert_eq!(
        retire(&f).expect("recover accepted retry").receipt,
        frontier
    );

    let (f, cipher) = pruned();
    // Inject an ambiguous return at the real durable boundary, before installing
    // current state. The separate subprocess test exits at this same boundary.
    AFTER_RETIREMENT_DURABLE.with(|hook| {
        hook.replace(Some(Box::new(|| {
            Err(integrity("injected ambiguous Sync result"))
        })))
    });
    assert!(retire(&f).is_err());
    assert!(
        f.keys.retirement_frontier().is_err(),
        "uncertain state is not active"
    );
    assert!(
        f.keys
            .open_value(&cipher.0, &cipher.1, &cipher.2, None)
            .is_err()
    );
    assert!(
        f.native.verify_native(true).is_err(),
        "ordinary key use stays closed until recovery"
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
    .expect("recover durable journal");
    assert!(keys.retirement_frontier().expect("known state").is_some());
    assert!(
        keys.open_value(&cipher.0, &cipher.1, &cipher.2, None)
            .is_err()
    );
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "primary-decisions", ledger_id)
            .expect("ledger");
    let native = NativeService::open_encrypted(
        f.root.path().join("native"),
        "primary-decisions",
        [9; 32],
        ledger,
        keys,
    )
    .expect("recovered native owner");
    native
        .verify_native(true)
        .expect("independent data remains valid");
}

fn seal_row<T: Serialize>(keys: &NativeCustodyKeys, row: &[u8], value: &T) -> Vec<u8> {
    seal(
        &keys.master.0,
        &keys.retirement_aad(row).expect("AAD"),
        &encode(value).expect("encode"),
    )
    .expect("seal")
}

#[test]
fn retirement_missing_or_rehashed_history_cannot_reactivate_or_duplicate_a_key() {
    for fault in [
        "event",
        "index",
        "anchor",
        "index-rehash",
        "false-allocation",
    ] {
        let (f, cipher) = pruned();
        let accepted = retire(&f).expect("retire");
        let mut tx = f.keys.engine.begin_write().expect("fixture transaction");
        let mut event: Event = f
            .keys
            .read_retirement_row(&tx, &event_key(accepted.receipt.sequence), &mut budget())
            .expect("event");
        let locator = index_key(&event.intent().expect("intent"));
        match fault {
            "event" => tx.delete(&f.keys.rows, event_key(1)).expect("remove event"),
            "index" => tx.delete(&f.keys.rows, locator).expect("remove index"),
            "anchor" => {
                let mut head = f.keys.key_version_head(&tx).expect("head");
                head.retirements = None;
                tx.put(
                    &f.keys.rows,
                    versions::HEAD.to_vec(),
                    f.keys
                        .seal_key_log(versions::HEAD, &encode(&head).expect("head"))
                        .expect("seal head"),
                )
                .expect("drop anchor only");
            }
            "index-rehash" => {
                let mut wrong = accepted.receipt.clone();
                wrong.digest = "ab".repeat(32);
                tx.put(
                    &f.keys.rows,
                    locator.clone(),
                    seal_row(&f.keys, &locator, &wrong),
                )
                .expect("false index");
            }
            "false-allocation" => {
                event.value.keys[0].address_digest = "cd".repeat(32);
                event.value.receipt.digest = event.commitment().expect("rehashed event");
                let row = event_key(1);
                tx.put(&f.keys.rows, row.clone(), seal_row(&f.keys, &row, &event))
                    .expect("false allocation");
                tx.put(
                    &f.keys.rows,
                    locator.clone(),
                    seal_row(&f.keys, &locator, &event.value.receipt),
                )
                .expect("matching false index");
                let mut head = f.keys.key_version_head(&tx).expect("head");
                head.retirements = Some(event.value.receipt.clone());
                tx.put(
                    &f.keys.rows,
                    versions::HEAD.to_vec(),
                    f.keys
                        .seal_key_log(versions::HEAD, &encode(&head).expect("head"))
                        .expect("seal head"),
                )
                .expect("matching false anchor");
            }
            _ => unreachable!(),
        }
        tx.commit(Durability::Sync).expect("fixture corruption");
        let before = f.keys.engine.head_sequence().expect("before failed retry");
        assert!(f.keys.verify().is_err(), "{fault}");
        assert!(
            f.keys
                .key_retirement(&accepted.receipt, &mut budget())
                .is_err(),
            "{fault}"
        );
        assert!(
            f.keys
                .open_value(&cipher.0, &cipher.1, &cipher.2, None)
                .is_err(),
            "current refusal survives {fault}"
        );
        assert!(
            retire(&f).is_err(),
            "cannot create another acceptance: {fault}"
        );
        assert_eq!(f.keys.engine.head_sequence().expect("unchanged"), before);
        let authority = f.keys.authority_id();
        drop((f.native, f.keys, f.ledger));
        assert!(
            NativeCustodyKeys::open(
                f.root.path().join("keys"),
                "primary-decisions",
                authority,
                master()
            )
            .is_err(),
            "reopen {fault}"
        );
    }
}

#[derive(Serialize, Deserialize)]
struct CrashInput {
    keys: Uuid,
    ledger: Uuid,
    context: AuthenticatedRequestContext,
    request: NativeRemovalRequestReceipt,
    selected: BTreeSet<Uuid>,
}

#[test]
fn retirement_crash_child() {
    let Some(root) = std::env::var_os("CONTEXTDB_KEY_RETIREMENT_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let input: CrashInput =
        serde_json::from_slice(&std::fs::read(root.join("retirement-input.json")).expect("input"))
            .expect("input JSON");
    let keys =
        NativeCustodyKeys::open(root.join("keys"), "primary-decisions", input.keys, master())
            .expect("keys");
    let ledger =
        NativeSuppressionLedger::open(root.join("ledger"), "primary-decisions", input.ledger)
            .expect("ledger");
    let native = NativeService::open_encrypted(
        root.join("native"),
        "primary-decisions",
        [9; 32],
        ledger,
        keys,
    )
    .expect("native");
    if std::env::var("CONTEXTDB_KEY_RETIREMENT_CRASH_STAGE").expect("stage") == "before" {
        BEFORE_RETIREMENT_SYNC.with(|hook| hook.replace(Some(Box::new(|| std::process::exit(81)))));
    } else {
        AFTER_RETIREMENT_DURABLE
            .with(|hook| hook.replace(Some(Box::new(|| std::process::exit(82)))));
    }
    native
        .retire_removal_keys(
            &input.context,
            &input.request,
            &NativeRemovalKeySelection::Originals,
            &input.selected,
            &mut budget(),
        )
        .expect("retirement");
    panic!("crash hook did not run");
}

#[test]
fn retirement_actual_process_exit_recovers_only_the_accepted_terminal() {
    for stage in ["before", "after"] {
        let (f, cipher) = pruned();
        let input = CrashInput {
            keys: f.keys.authority_id(),
            ledger: f.ledger.authority_id(),
            context: f.input.context.clone(),
            request: f.removal.clone(),
            selected: ids(&f),
        };
        std::fs::write(
            f.root.path().join("retirement-input.json"),
            serde_json::to_vec(&input).expect("input JSON"),
        )
        .expect("fixture input");
        drop((f.native, f.keys, f.ledger));
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "encryption::keys::retirement::tests::retirement_crash_child",
                "--nocapture",
            ])
            .env("CONTEXTDB_KEY_RETIREMENT_CRASH_ROOT", f.root.path())
            .env("CONTEXTDB_KEY_RETIREMENT_CRASH_STAGE", stage)
            .status()
            .expect("subprocess");
        assert_eq!(status.code(), Some(if stage == "before" { 81 } else { 82 }));
        let keys = NativeCustodyKeys::open(
            f.root.path().join("keys"),
            "primary-decisions",
            input.keys,
            master(),
        )
        .expect("cold recovery");
        assert_eq!(
            keys.retirement_frontier()
                .expect("known terminal")
                .is_some(),
            stage == "after"
        );
        assert_eq!(
            keys.open_value(&cipher.0, &cipher.1, &cipher.2, None)
                .is_err(),
            stage == "after"
        );
        let ledger = NativeSuppressionLedger::open(
            f.root.path().join("ledger"),
            "primary-decisions",
            input.ledger,
        )
        .expect("ledger");
        let native = NativeService::open_encrypted(
            f.root.path().join("native"),
            "primary-decisions",
            [9; 32],
            ledger,
            keys.clone(),
        )
        .expect("native");
        let accepted = native
            .retire_removal_keys(
                &input.context,
                &input.request,
                &NativeRemovalKeySelection::Originals,
                &input.selected,
                &mut budget(),
            )
            .expect("resume or retrieve");
        assert_eq!(accepted.receipt.sequence, 1);
        assert_eq!(
            keys.key_retirement(&accepted.receipt, &mut budget())
                .expect("exact retained acceptance"),
            accepted
        );
        native
            .verify_native(true)
            .expect("independent native history");
    }
}
