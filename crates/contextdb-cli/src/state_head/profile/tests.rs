use super::*;
use serde_json::json;

const KEY: [u8; 32] = [7; 32];

fn archive(head: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "format": "contextdb.logical.v1", "database_id": "profile-test", "head": head
    }))
    .expect("actual archive bytes")
}

fn fixture() -> (tempfile::TempDir, StateHeadStore) {
    let directory = tempfile::tempdir().expect("owned archive directory");
    let store = StateHeadStore::memory(&directory.path().join("profile.ctxb"))
        .expect("independent authority");
    store
        .bootstrap(&KEY, &archive(0))
        .expect("actual bootstrap");
    (directory, store)
}

#[test]
fn native_profile_opt_in_keeps_schema2_bytes_and_survives_lifecycle_publication() {
    let (_directory, store) = fixture();
    let old = store.raw_authority().expect("read").expect("exists");
    let old_value: serde_json::Value = serde_json::from_slice(&old).expect("authority JSON");
    assert_eq!(old_value["schema_version"], 2);
    assert!(old_value.get("native_profile_digest").is_none());
    assert!(old_value.get("native_restore_pending").is_none());
    assert_eq!(
        store.native_profile_digest(&KEY).expect("plain profile"),
        None
    );
    store
        .load_verified(&KEY)
        .expect("legacy current head remains valid");
    assert_eq!(store.raw_authority().expect("read"), Some(old));

    let digest = "a".repeat(64);
    store
        .pin_native_profile(&KEY, &digest)
        .expect("explicit opt-in");
    let pinned = store.raw_authority().expect("read").expect("exists");
    store
        .pin_native_profile(&KEY, &digest)
        .expect("exact retry");
    assert_eq!(store.raw_authority().expect("read"), Some(pinned));
    assert!(store.pin_native_profile(&KEY, &"b".repeat(64)).is_err());
    store
        .advance(&KEY, &archive(1))
        .expect("actual archive advance");
    let (_, identity, ledger) = store
        .load_verified_with_ledger(&KEY)
        .expect("current archive");
    store
        .advance_ledger(&KEY, &identity, ledger.generation + 1, &"c".repeat(64))
        .expect("actual receipt-only publication");
    assert_eq!(
        store.native_profile_digest(&KEY).expect("retained"),
        Some(digest)
    );
    let current: serde_json::Value =
        serde_json::from_slice(&store.raw_authority().expect("read").expect("exists"))
            .expect("authority JSON");
    assert_eq!(current["schema_version"], 3);
}

#[test]
fn native_restore_fence_survives_actual_lifecycle_recovery_and_requires_exact_profile() {
    let (_directory, store) = fixture();
    let digest = "f".repeat(64);
    assert!(store.begin_native_restore(&KEY, &digest).is_err());
    store.pin_native_profile(&KEY, &digest).expect("pin");
    assert!(store.finish_native_restore(&KEY, &digest).is_err());
    let ready = store.raw_authority().expect("read");
    assert!(store.begin_native_restore(&KEY, &"a".repeat(64)).is_err());
    assert_eq!(store.raw_authority().expect("read"), ready);

    store
        .begin_native_restore(&KEY, &digest)
        .expect("accepted restore intent");
    assert!(store.require_native_restore_ready(&KEY).is_err());
    assert!(store.begin_native_restore(&KEY, &digest).is_err());
    assert_eq!(
        store.native_profile_digest(&KEY).expect("shutdown binding"),
        Some(digest.clone())
    );
    store.fail_final_activation_for_test();
    assert!(store.advance(&KEY, &archive(1)).is_err());
    let pending = store.raw_authority().expect("read");
    assert!(store.require_native_restore_ready(&KEY).is_err());
    assert_eq!(store.raw_authority().expect("read"), pending);
    store.load_verified(&KEY).expect("lifecycle recovery");
    assert!(store.require_native_restore_ready(&KEY).is_err());
    let (_, identity, ledger) = store.load_verified_with_ledger(&KEY).expect("archive");
    store
        .advance_ledger(&KEY, &identity, ledger.generation + 1, &"b".repeat(64))
        .expect("receipt publication retains native fence");
    let retained = store.raw_authority().expect("read");
    assert!(store.finish_native_restore(&KEY, &"a".repeat(64)).is_err());
    assert!(store.finish_native_restore(&[8; 32], &digest).is_err());
    assert_eq!(store.raw_authority().expect("read"), retained);

    store
        .finish_native_restore(&KEY, &digest)
        .expect("verified operator completion");
    store.require_native_restore_ready(&KEY).expect("ready");
    assert_eq!(
        store.native_profile_digest(&KEY).expect("unchanged pin"),
        Some(digest)
    );
    let final_envelope: serde_json::Value =
        serde_json::from_slice(&store.raw_authority().expect("read").expect("exists"))
            .expect("authority JSON");
    assert!(final_envelope.get("native_restore_pending").is_none());
}

#[test]
fn native_profile_commitment_survives_lost_activation_without_read_side_recovery() {
    let (_directory, store) = fixture();
    let digest = "d".repeat(64);
    store.pin_native_profile(&KEY, &digest).expect("pin");
    store.fail_final_activation_for_test();
    assert!(store.advance(&KEY, &archive(1)).is_err());
    let pending = store.raw_authority().expect("read").expect("exists");
    assert_eq!(
        store.native_profile_digest(&KEY).expect("configuration"),
        Some(digest.clone())
    );
    assert_eq!(store.raw_authority().expect("read"), Some(pending));
    assert!(store.pin_native_profile(&KEY, &digest).is_err());
    store.load_verified(&KEY).expect("explicit normal recovery");
    assert_eq!(
        store.native_profile_digest(&KEY).expect("retained"),
        Some(digest)
    );
}

#[test]
fn native_profile_schema_and_authenticated_binding_cannot_be_erased_or_forged() {
    let (_directory, store) = fixture();
    store
        .pin_native_profile(&KEY, &"e".repeat(64))
        .expect("pin");
    let original = store.raw_authority().expect("read").expect("exists");
    let mut erased: AuthorityEnvelope = serde_json::from_slice(&original).expect("envelope");
    erased.native_profile_digest = None;
    erased.mac = authority_mac(&erased, &KEY).expect("fully rehashed invalid structure");
    store
        .replace_raw_authority(Some(serde_json::to_vec(&erased).expect("encode")))
        .expect("owned corruption fixture");
    assert!(store.native_profile_digest(&KEY).is_err());
    let mut downgraded: AuthorityEnvelope = serde_json::from_slice(&original).expect("envelope");
    downgraded.schema_version = 2;
    downgraded.mac = authority_mac(&downgraded, &KEY).expect("fully rehashed false version");
    store
        .replace_raw_authority(Some(serde_json::to_vec(&downgraded).expect("encode")))
        .expect("owned corruption fixture");
    assert!(store.native_profile_digest(&KEY).is_err());
    store
        .replace_raw_authority(Some(original))
        .expect("restore owned fixture");
    assert!(store.native_profile_digest(&[8; 32]).is_err());
    fs::remove_file(store.archive_path()).expect("owned archive loss");
    assert_eq!(
        store
            .native_profile_digest(&KEY)
            .expect("independent commitment"),
        Some("e".repeat(64))
    );
    assert!(store.pin_native_profile(&KEY, &"e".repeat(64)).is_err());
}
