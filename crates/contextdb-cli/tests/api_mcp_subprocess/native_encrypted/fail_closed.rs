use super::*;

fn hold_active_path(original: &Path, held: &Path) -> bool {
    match std::fs::rename(original, held) {
        Ok(()) => true,
        Err(error) if cfg!(windows) && error.kind() == std::io::ErrorKind::PermissionDenied => {
            // Windows may prevent relocation of a live Fjall owner entirely.
            assert!(original.exists() && !held.exists());
            false
        }
        Err(error) => panic!("preserve active owned fixture: {error}"),
    }
}

#[test]
fn encrypted_native_active_owner_refuses_replaced_authorities_and_lost_native_controls() {
    let f = Fixture::new();
    f.provision();
    let mut broker = f.broker();
    let candidate = f.call("contextdb_ensure_candidate", proposal())["candidate_id"]
        .as_str()
        .expect("candidate")
        .to_owned();
    let request = rpc("contextdb_session", serde_json::json!({}));
    let mut admitted = Vec::new();
    let mut probes = 0;
    for authority in ["keys", "suppression"] {
        let original = f.custody.join(authority);
        let held = f.directory.path().join(format!("live-held-{authority}"));
        if !hold_active_path(&original, &held) {
            continue;
        }
        std::fs::create_dir(&original).expect("empty authority replacement");
        let output = f.mcp(&request, Some(MASTER));
        no_key_disclosure(&output);
        let entries = std::fs::read_dir(&original)
            .expect("replacement remains inspectable")
            .count();
        std::fs::remove_dir(&original).expect("only empty owned replacement is removed");
        std::fs::rename(&held, &original).expect("restore exact active authority");
        assert_eq!(entries, 0, "a joining proxy must never initialize custody");
        probes += 1;
        if output.status.success() {
            admitted.push(format!("empty {authority} replacement"));
        }
    }
    for (label, directory) in [
        ("keys", f.custody.join("keys")),
        ("suppression", f.custody.join("suppression")),
        ("native", f.native()),
    ] {
        for control in ["version", "lock"] {
            let original = directory.join(control);
            let held = f
                .directory
                .path()
                .join(format!("live-held-{label}-{control}"));
            if !hold_active_path(&original, &held) {
                continue;
            }
            let output = f.mcp(&request, Some(MASTER));
            no_key_disclosure(&output);
            let recreated = original.exists();
            std::fs::rename(&held, &original).expect("restore exact active physical control");
            assert!(!recreated, "joining must not bootstrap a partial store");
            probes += 1;
            if output.status.success() {
                admitted.push(format!("missing {label} {control}"));
            }
        }
    }
    recall(&f, &candidate);
    f.stop(&mut broker);
    assert!(
        probes > 0,
        "physical loss must be exercised before acceptance"
    );
    assert!(
        admitted.is_empty(),
        "live broker admitted unavailable state: {admitted:?}"
    );
}

fn string_range(bytes: &[u8], cursor: &mut usize) -> std::ops::Range<usize> {
    let length = u16::from_be_bytes(
        bytes[*cursor..*cursor + 2]
            .try_into()
            .expect("issued string length"),
    ) as usize;
    *cursor += 2;
    let range = *cursor..*cursor + length;
    *cursor = range.end;
    range
}

fn corrupt_inner_footer(mut bytes: Vec<u8>) -> Vec<u8> {
    let magic = b"contextdb/codex-composite-backup/v2\0";
    assert!(bytes.starts_with(magic));
    assert_eq!(&bytes[magic.len()..magic.len() + 2], &[0, 2]);
    let outer_footer = bytes.len() - 32;
    assert_eq!(
        &bytes[outer_footer..],
        blake3::hash(&bytes[..outer_footer]).as_bytes()
    );
    let mut cursor = magic.len() + 2;
    for _ in 0..4 {
        string_range(&bytes, &mut cursor);
    }
    for component in 0..2 {
        let format = string_range(&bytes, &mut cursor);
        let digest = string_range(&bytes, &mut cursor);
        cursor += 8;
        let length = u64::from_be_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .expect("issued component length"),
        );
        cursor += 8;
        let inner = cursor..cursor + usize::try_from(length).expect("fixture component size");
        cursor = inner.end;
        if component == 1 {
            assert_eq!(
                &bytes[format],
                b"contextdb.native-fjall.encrypted-backup.v3"
            );
            assert!(inner.len() > 32 && inner.end == outer_footer);
            bytes[inner.end - 1] ^= 1;
            let replacement = blake3::hash(&bytes[inner]).to_hex().to_string();
            bytes[digest].copy_from_slice(replacement.as_bytes());
        }
    }
    assert_eq!(cursor, outer_footer);
    let footer = *blake3::hash(&bytes[..outer_footer]).as_bytes();
    bytes[outer_footer..].copy_from_slice(&footer);
    bytes
}

fn assert_exact_authorities(f: &Fixture, descriptor: &serde_json::Value) {
    use contextdb_native_service::{CustodyMasterKey, NativeCustodyKeys, NativeSuppressionLedger};
    let identity = &descriptor["identity"];
    let database = identity["database_id"].as_str().expect("pinned database");
    let key_id: contextdb_core::ObservationId =
        serde_json::from_value(identity["custody_authority"].clone())
            .expect("pinned key authority");
    let suppression_id: contextdb_core::ObservationId =
        serde_json::from_value(identity["suppression_authority"].clone())
            .expect("pinned suppression authority");
    let keys = NativeCustodyKeys::open(
        f.custody.join("keys"),
        database,
        key_id.as_uuid(),
        CustodyMasterKey::from_zeroizing(zeroize::Zeroizing::new([0x59; 32]))
            .expect("fixture master"),
    )
    .expect("same retained key authority is healthy");
    let suppression = NativeSuppressionLedger::open(
        f.custody.join("suppression"),
        database,
        suppression_id.as_uuid(),
    )
    .expect("same retained suppression authority is healthy");
    assert_eq!(keys.authority_id(), key_id.as_uuid());
    assert_eq!(keys.format_version(), 4);
    assert_eq!(suppression.authority_id(), suppression_id.as_uuid());
    assert_eq!(suppression.format_version(), 3);
}

#[test]
fn encrypted_native_corrupt_inner_restore_stays_fenced_after_ready_profile_replay() {
    let f = Fixture::new();
    let initialized = f.provision();
    let ready = std::fs::read(f.profile()).expect("retained ready profile");
    let ready_value: serde_json::Value = serde_json::from_slice(&ready).expect("ready JSON");
    let mut broker = f.broker();
    f.call("contextdb_ensure_candidate", proposal());
    f.stop(&mut broker);
    let (backup, output) = f.backup("valid-before-inner-corruption.backup");
    success(&output);
    let corrupt = f.directory.path().join("canonical-corrupt-inner.backup");
    std::fs::write(
        &corrupt,
        corrupt_inner_footer(std::fs::read(&backup).expect("issued backup")),
    )
    .expect("owned corrupt fixture");
    std::fs::rename(
        f.native(),
        f.directory
            .path()
            .join("retained-native-before-corrupt-restore"),
    )
    .expect("preserve populated original");
    let restored = f.run(
        &["--json", "codex-restore", path(&f.archive), path(&corrupt)],
        Some(MASTER),
    );
    refused(&restored);
    assert!(
        String::from_utf8_lossy(&restored.stderr)
            .contains("native backup footer digest is invalid")
    );
    let pending = std::fs::read(f.profile()).expect("signed pending profile");
    let pending_value: serde_json::Value = serde_json::from_slice(&pending).expect("pending JSON");
    assert_eq!(pending_value["descriptor"], ready_value["descriptor"]);
    assert_eq!(
        pending_value["master_key_tag"],
        ready_value["master_key_tag"]
    );
    assert_eq!(pending_value["state"], "restore_pending");
    let retained_head = head_bytes(&f);
    let head: serde_json::Value = serde_json::from_slice(&retained_head).expect("external intent");
    assert_eq!(head["native_profile_digest"], initialized["profile_digest"]);
    assert_eq!(head["native_restore_pending"], true);
    assert_exact_authorities(&f, &ready_value["descriptor"]);
    let request = rpc("contextdb_session", serde_json::json!({}));
    refused(&f.mcp(&request, Some(MASTER)));
    std::fs::write(f.profile(), &ready).expect("replay locally valid old Ready descriptor");
    refused(&f.mcp(&request, Some(MASTER)));
    assert_eq!(head_bytes(&f), retained_head);
    std::fs::write(f.profile(), &pending).expect("retain exact incomplete restore profile");
    let (destination, output) = f.backup("pending-must-not-export-blank.backup");
    refused(&output);
    assert!(!destination.exists());
}
