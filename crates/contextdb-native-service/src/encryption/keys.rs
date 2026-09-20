use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use contextdb_storage::{
    Durability, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};
use contextdb_storage_fjall::{FJALL_INTERNAL_META_KEYSPACE, FjallStorage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::*;

mod backups;
mod versions;
pub use backups::{NativeBackupCatalogPage, NativeBackupRegistration};

const MAX_PENDING_KEYS: usize = 16_384;
const KEYSPACE: &str = "contextdb_native_custody_keys";

/// Long-lived encryption key supplied by host custody, separate from token keys.
/// It is zeroized on drop and has no serialization or cloning implementation.
pub struct CustodyMasterKey(Zeroizing<[u8; 32]>);

impl CustodyMasterKey {
    /// Accept host-provisioned entropy. The caller must independently retain the
    /// key for restart; native backups never contain it.
    pub fn from_zeroizing(key: Zeroizing<[u8; 32]>) -> contextdb_service::ServiceResult<Self> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(crate::invalid("custody master key must not be all zero"));
        }
        Ok(Self(key))
    }
}

impl fmt::Debug for CustodyMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustodyMasterKey([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u16,
    authority: Uuid,
    database: String,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRecord {
    id: Uuid,
    wrapped: Vec<u8>,
}

pub(super) struct PendingKey {
    record: KeyRecord,
    bytes: Zeroizing<[u8; 32]>,
}

pub(super) type PendingKeys = BTreeMap<String, PendingKey>;

/// Independently retained incremental custody-key inventory.
///
/// Version 3 allocates a random key per value address per native transaction.
/// Versions 1 and 2 retain their original reusable-address keys. The inventory contains
/// wrapped keys, never source bytes. Hosts retain its current directory,
/// authority identity and master key outside native backup/restore.
pub struct NativeCustodyKeys {
    engine: FjallStorage,
    rows: Keyspace,
    identity: Identity,
    master: CustodyMasterKey,
    pub(crate) path: PathBuf,
    writes: crate::publication::PublicationQueue,
}

impl fmt::Debug for NativeCustodyKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCustodyKeys").finish_non_exhaustive()
    }
}

impl NativeCustodyKeys {
    /// Create a new key authority in a new independently retained directory.
    pub fn create(
        path: impl AsRef<Path>,
        database_id: &str,
        master: CustodyMasterKey,
    ) -> contextdb_service::ServiceResult<Arc<Self>> {
        Self::create_version(path.as_ref(), database_id, master, 3)
    }

    pub(super) fn create_version(
        path: &Path,
        database_id: &str,
        master: CustodyMasterKey,
        version: u16,
    ) -> contextdb_service::ServiceResult<Arc<Self>> {
        if !matches!(version, 1..=3) {
            return Err(crate::integrity("unsupported custody authority version"));
        }
        crate::validate_identifier(database_id, "custody database ID")?;
        std::fs::create_dir(path)
            .map_err(|_| crate::integrity("custody authority requires a new directory"))?;
        let engine = FjallStorage::open(path).map_err(crate::storage_error)?;
        let rows = Keyspace::new(KEYSPACE).map_err(crate::storage_error)?;
        let identity = Identity {
            version,
            authority: contextdb_core::ObservationId::new().as_uuid(),
            database: crate::digest_bytes(database_id.as_bytes()),
        };
        let proof = seal(
            &master.0,
            &encode(&identity).map_err(crate::storage_error)?,
            b"contextdb/native-custody-authority/v1",
        )
        .map_err(crate::storage_error)?;
        let mut tx = engine.begin_write().map_err(crate::storage_error)?;
        tx.put(
            &rows,
            b"identity".to_vec(),
            encode(&identity).map_err(crate::storage_error)?,
        )
        .map_err(crate::storage_error)?;
        tx.put(&rows, b"proof".to_vec(), proof)
            .map_err(crate::storage_error)?;
        if version >= 2 {
            tx.put(
                &rows,
                backups::HEAD.to_vec(),
                backups::genesis(&identity, &master).map_err(crate::storage_error)?,
            )
            .map_err(crate::storage_error)?;
        }
        if version == 3 {
            tx.put(
                &rows,
                versions::HEAD.to_vec(),
                versions::genesis(&identity, &master).map_err(crate::storage_error)?,
            )
            .map_err(crate::storage_error)?;
        }
        crate::require_sync(
            tx.commit(Durability::Sync)
                .map_err(crate::storage_error)?
                .durability,
        )?;
        Self::finish_open(engine, rows, identity, master, path)
    }

    /// Open the exact retained inventory. Missing authority or wrong master key
    /// fails; there is no empty-catalog or plaintext fallback.
    pub fn open(
        path: impl AsRef<Path>,
        database_id: &str,
        authority: Uuid,
        master: CustodyMasterKey,
    ) -> contextdb_service::ServiceResult<Arc<Self>> {
        if !path.as_ref().is_dir() {
            return Err(crate::integrity(
                "current custody key authority is unavailable",
            ));
        }
        let engine = FjallStorage::open(path.as_ref()).map_err(crate::storage_error)?;
        let rows = Keyspace::new(KEYSPACE).map_err(crate::storage_error)?;
        let snapshot = engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        let identity: Identity = decode(
            &snapshot
                .get(&rows, b"identity")
                .map_err(crate::storage_error)?
                .ok_or_else(|| crate::integrity("custody identity is missing"))?,
        )
        .map_err(crate::storage_error)?;
        if !matches!(identity.version, 1..=3)
            || identity.authority != authority
            || identity.database != crate::digest_bytes(database_id.as_bytes())
        {
            return Err(crate::integrity("custody authority binding differs"));
        }
        drop(snapshot);
        Self::finish_open(engine, rows, identity, master, path.as_ref())
    }

    fn finish_open(
        engine: FjallStorage,
        rows: Keyspace,
        identity: Identity,
        master: CustodyMasterKey,
        path: &Path,
    ) -> contextdb_service::ServiceResult<Arc<Self>> {
        let keys = Self {
            engine,
            rows,
            identity,
            master,
            path: path
                .canonicalize()
                .map_err(|_| crate::integrity("custody path is unavailable"))?,
            writes: Default::default(),
        };
        keys.verify().map_err(crate::storage_error)?;
        Ok(Arc::new(keys))
    }

    /// Opaque identity required when reopening the external key inventory.
    #[must_use]
    pub fn authority_id(&self) -> Uuid {
        self.identity.authority
    }

    pub(crate) fn require_database(&self, database: &str) -> contextdb_service::ServiceResult<()> {
        if self.identity.database != crate::digest_bytes(database.as_bytes()) {
            return Err(crate::integrity(
                "custody key authority belongs to another database",
            ));
        }
        Ok(())
    }

    fn key_aad(&self, address: &str, id: Uuid) -> contextdb_storage::Result<Vec<u8>> {
        encode(&(
            "contextdb/native-wrapped-key/v1",
            &self.identity,
            address,
            id,
        ))
    }

    fn value_aad(&self, address: &str, id: Uuid) -> contextdb_storage::Result<Vec<u8>> {
        encode(&(
            "contextdb/native-sealed-value/v1",
            &self.identity,
            address,
            id,
        ))
    }

    fn unwrap(
        &self,
        address: &str,
        record: &KeyRecord,
    ) -> contextdb_storage::Result<Zeroizing<[u8; 32]>> {
        if record.id.is_nil() || record.wrapped.len() != NONCE_BYTES + 32 + TAG_BYTES {
            return Err(failure("wrapped custody key shape is invalid"));
        }
        let plaintext = open(
            &self.master.0,
            &self.key_aad(address, record.id)?,
            &record.wrapped,
        )?;
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&plaintext);
        Ok(key)
    }

    fn record(&self, address: &str) -> contextdb_storage::Result<Option<KeyRecord>> {
        #[cfg(test)]
        KEY_LOOKUPS.with(|count| count.set(count.get() + 1));
        let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
        snapshot
            .get(&self.rows, &row_key(address))?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    pub(super) fn seal_value(
        &self,
        space: &Keyspace,
        key: &[u8],
        plaintext: &[u8],
        pending: &mut PendingKeys,
    ) -> contextdb_storage::Result<Vec<u8>> {
        let address = address(space, key);
        if let Some(entry) = pending.get(&address) {
            return self.value_envelope(&address, entry.record.id, &entry.bytes, plaintext);
        }
        if self.identity.version < 3
            && let Some(record) = self.record(&address)?
        {
            let bytes = self.unwrap(&address, &record)?;
            return self.value_envelope(&address, record.id, &bytes, plaintext);
        }
        if pending.len() >= MAX_PENDING_KEYS {
            return Err(failure("native custody key batch exceeds 16384 entries"));
        }
        let bytes = random_key()?;
        let id = contextdb_core::ObservationId::new().as_uuid();
        let record = KeyRecord {
            id,
            wrapped: seal(
                &self.master.0,
                &self.key_aad(&address, id)?,
                bytes.as_slice(),
            )?,
        };
        let value = self.value_envelope(&address, id, &bytes, plaintext)?;
        pending.insert(address, PendingKey { record, bytes });
        Ok(value)
    }

    fn value_envelope(
        &self,
        address: &str,
        id: Uuid,
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> contextdb_storage::Result<Vec<u8>> {
        let ciphertext = seal(key, &self.value_aad(address, id)?, plaintext)?;
        Ok([VALUE_MAGIC, id.as_bytes(), ciphertext.as_slice()].concat())
    }

    pub(super) fn open_value(
        &self,
        space: &Keyspace,
        key: &[u8],
        value: &[u8],
        pending: Option<&PendingKeys>,
    ) -> contextdb_storage::Result<Vec<u8>> {
        let header = VALUE_MAGIC.len() + 16;
        if value.len() < header || !value.starts_with(VALUE_MAGIC) {
            return Err(failure("native value lacks its custody envelope"));
        }
        let id = Uuid::from_slice(&value[VALUE_MAGIC.len()..header])
            .map_err(|_| failure("native custody key identity is invalid"))?;
        let address = address(space, key);
        let aad = self.value_aad(&address, id)?;
        let plaintext = if let Some(entry) = pending.and_then(|keys| keys.get(&address)) {
            if entry.record.id != id {
                return Err(failure("pending custody key identity differs"));
            }
            open(&entry.bytes, &aad, &value[header..])?
        } else {
            let record = if self.identity.version == 3 {
                self.version_record(&address, id)?
            } else {
                self.record(&address)?
            }
            .ok_or_else(|| failure("current custody key is unavailable"))?;
            if record.id != id {
                return Err(failure("current custody key identity differs"));
            }
            let bytes = self.unwrap(&address, &record)?;
            open(&bytes, &aad, &value[header..])?
        };
        Ok(plaintext.to_vec())
    }

    // One key-store Sync per native transaction, before publishing ciphertext.
    // Legacy address-allocation races publish neither mixed keys nor native rows.
    pub(super) fn publish(&self, pending: &PendingKeys) -> contextdb_storage::Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let _guard = self
            .writes
            .enter(|| Ok(()))
            .map_err(|_| failure("custody publication admission unavailable"))?;
        let mut tx = self.engine.begin_write()?;
        if self.identity.version == 3 {
            self.publish_key_versions(&mut tx, pending)?;
            let receipt = tx.commit(Durability::Sync)?;
            if receipt.durability != Durability::Sync {
                return Err(failure("custody key versions were not synchronized"));
            }
            return Ok(());
        }
        for address in pending.keys() {
            if tx.get(&self.rows, &row_key(address))?.is_some() {
                return Err(failure(
                    "custody key allocation changed; retry native publication",
                ));
            }
        }
        for (address, entry) in pending {
            tx.put(&self.rows, row_key(address), encode(&entry.record)?)?;
        }
        let receipt = tx.commit(Durability::Sync)?;
        if receipt.durability != Durability::Sync {
            return Err(failure("custody keys were not synchronized"));
        }
        Ok(())
    }

    fn verify(&self) -> contextdb_storage::Result<()> {
        #[cfg(test)]
        CATALOG_VERIFICATIONS.with(|count| count.set(count.get() + 1));
        if self
            .engine
            .physical_keyspace_names()
            .iter()
            .any(|name| ![KEYSPACE, FJALL_INTERNAL_META_KEYSPACE].contains(&name.as_str()))
        {
            return Err(failure("custody inventory contains an unknown keyspace"));
        }
        let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
        let proof = snapshot
            .get(&self.rows, b"proof")?
            .ok_or_else(|| failure("custody master-key proof is absent"))?;
        if open(&self.master.0, &encode(&self.identity)?, &proof)?.as_slice()
            != b"contextdb/native-custody-authority/v1"
        {
            return Err(failure("custody master-key proof differs"));
        }
        for row in snapshot.scan_prefix(&self.rows, b"")? {
            if row.key == b"identity" || row.key == b"proof" {
                continue;
            }
            if row.key.starts_with(b"backup/") {
                continue; // Verified as an exact ordered registry below.
            }
            if self.identity.version == 3
                && (row.key.starts_with(b"key/") || row.key.starts_with(b"key-log/"))
            {
                continue; // The immutable allocation journal closes both families.
            }
            let address = row
                .key
                .strip_prefix(b"key/")
                .and_then(|suffix| std::str::from_utf8(suffix).ok())
                .ok_or_else(|| failure("unknown custody inventory row"))?;
            if blake3::Hash::from_hex(address).is_err() {
                return Err(failure("custody value address is invalid"));
            }
            self.unwrap(address, &decode(&row.value)?)?;
        }
        if self.identity.version == 3 {
            self.verify_key_versions(&snapshot)?;
        }
        self.verify_backup_catalog(&snapshot)?;
        Ok(())
    }
}

fn row_key(address: &str) -> Vec<u8> {
    format!("key/{address}").into_bytes()
}

#[cfg(test)]
thread_local! {
    pub(super) static KEY_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static CATALOG_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
