#![no_main]

use std::collections::BTreeSet;

use contextdb_security::{
    BackupEncryptionKey, BackupSigningKey, EncryptedBackup, EncryptedRestrictedField,
    RestoreAuthorization, RestrictedFieldKey, decrypt_restricted_field, restore_backup, scan_secrets,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = scan_secrets(text, data.len().max(1));
    }
    if let Ok(backup) = serde_json::from_slice::<EncryptedBackup>(data) {
        let encryption = BackupEncryptionKey::new("fuzz-encryption-key", [7; 32]);
        let signing = BackupSigningKey::new("fuzz-signing-key", [9; 32]);
        if let (Ok(encryption), Ok(signing)) = (encryption, signing) {
            let authorization = RestoreAuthorization {
                now_micros: 1,
                expected_database_id: "fuzz-database".to_owned(),
                expected_workspace_id: "fuzz-workspace".to_owned(),
                expected_policy_digest:
                    "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
                expected_manifest_digest:
                    "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
                minimum_encryption_key_generation: 1,
                minimum_signing_key_generation: 1,
                allowed_scopes: BTreeSet::from(["fuzz-scope".to_owned()]),
                restore_capability: true,
            };
            let _ = restore_backup(
                &backup,
                &encryption,
                &signing.verifying_key(),
                &authorization,
            );
        }
    }
    if let Ok(field) = serde_json::from_slice::<EncryptedRestrictedField>(data)
        && let Ok(key) = RestrictedFieldKey::new("fuzz-field-key", 1, [11; 32])
    {
        let metadata = field.header.metadata.clone();
        let _ = decrypt_restricted_field(&field, &metadata, &key, true);
    }
});
