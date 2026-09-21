//! Current, independently retained record of archives that may have left custody.
//! A registration proves issuance, never deletion or absence of external copies.

use contextdb_storage::ScanPageRequest;

use super::*;

mod contents;
pub use contents::{
    NativeBackupContentsInventory, NativeBackupContentsPage, NativeBackupContentsReceipt,
    NativeBackupFrontier, NativeBackupKeyArchive, NativeBackupKeyCopy, NativeBackupKeyInventory,
};

#[cfg(test)]
mod tests;

pub(super) const HEAD: &[u8] = b"backup/head";
const ISSUED: &[u8] = b"backup/issued/";

/// Content-free registration of a verified encrypted archive before issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupRegistration {
    /// Monotonic position in this authority's archive registry.
    pub sequence: u64,
    /// Exact authority required for archive decryption.
    pub authority_id: Uuid,
    /// BLAKE3 digest of the complete canonical ciphertext archive.
    pub archive_digest: String,
    /// Native logical journal prefix, not a physical storage sequence.
    pub native_commit: u64,
    /// Logical closure verified before this registration was synchronized.
    pub logical_digest: String,
    /// Size of the complete encoded archive.
    pub encoded_bytes: u64,
    /// Previous issued archive in this registry; absent at position one.
    pub previous_archive_digest: Option<String>,
}

/// Bounded registry page. Continue with the same revision or restart if stale.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBackupCatalogPage {
    /// Registry revision checked for this page, independent of unrelated keys.
    pub revision: u64,
    /// At most the requested number of content-free registrations.
    pub entries: Vec<NativeBackupRegistration>,
    /// Last returned sequence if more registrations exist at this revision.
    pub next_after: Option<u64>,
}

#[derive(Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    sequence: u64,
    digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contents: Option<NativeBackupContentsReceipt>,
}

impl NativeCustodyKeys {
    pub(crate) fn require_backup_registry(&self) -> contextdb_service::ServiceResult<()> {
        if self.identity.version < 2 {
            return Err(contextdb_service::ServiceError::new(
                contextdb_service::ErrorCode::FormatIncompatible,
                "version 1 custody authority requires explicit backup-registry migration",
                false,
            ));
        }
        Ok(())
    }

    /// Read an issued-archive registration by exact ciphertext digest. A missing
    /// entry does not prove that an external copy never existed.
    pub fn backup_registration(
        &self,
        digest: &str,
    ) -> contextdb_service::ServiceResult<Option<NativeBackupRegistration>> {
        self.require_backup_registry()?;
        valid_digest(digest).map_err(crate::storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        self.find_backup(&snapshot, digest)
            .map_err(crate::storage_error)
    }

    /// Enumerate 1..256 issued archives. Pass the first page's revision to every
    /// continuation; concurrent issuance rejects it without returning mixed pages.
    pub fn backup_catalog_page(
        &self,
        after: u64,
        expected_revision: Option<u64>,
        limit: u32,
    ) -> contextdb_service::ServiceResult<NativeBackupCatalogPage> {
        self.require_backup_registry()?;
        if !(1..=256).contains(&limit) || (after != 0 && expected_revision.is_none()) {
            return Err(crate::invalid(
                "backup page requires 1..256 entries and a continuation revision",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(crate::storage_error)?;
        let head = self.backup_head(&snapshot).map_err(crate::storage_error)?;
        if expected_revision.is_some_and(|revision| revision != head.sequence)
            || after > head.sequence
        {
            return Err(contextdb_service::ServiceError::new(
                contextdb_service::ErrorCode::IndexTooStale,
                "issued backup registry changed; restart enumeration",
                true,
            ));
        }
        let after_key = issued_key(after);
        let page = snapshot
            .scan_prefix_page(
                &self.rows,
                ScanPageRequest {
                    prefix: ISSUED,
                    start_after: Some(&after_key),
                    max_entries: limit as usize,
                    max_bytes: 512 * 1024,
                },
            )
            .map_err(crate::storage_error)?;
        let mut entries = Vec::with_capacity(page.entries.len());
        let mut through = after;
        for row in page.entries {
            let entry = self
                .decode_registration(&row.key, &row.value)
                .map_err(crate::storage_error)?;
            through = through
                .checked_add(1)
                .ok_or_else(|| crate::integrity("backup sequence overflow"))?;
            if entry.sequence != through || through > head.sequence {
                return Err(crate::integrity("issued backup registry has a gap"));
            }
            entries.push(entry);
        }
        if page.continuation.is_none() != (through == head.sequence) {
            return Err(crate::integrity(
                "issued backup registry ended before its head",
            ));
        }
        Ok(NativeBackupCatalogPage {
            revision: head.sequence,
            entries,
            next_after: (through < head.sequence).then_some(through),
        })
    }

    pub(crate) fn register_backup(
        &self,
        digest: &str,
        commit: u64,
        logical_digest: &str,
        encoded_bytes: u64,
    ) -> contextdb_storage::Result<()> {
        if self.identity.version < 2 {
            return Err(failure(
                "issued backups require a version 2 or later custody authority",
            ));
        }
        valid_digest(digest)?;
        valid_digest(logical_digest)?;
        let _guard = self
            .writes
            .enter(|| Ok(()))
            .map_err(|_| failure("backup custody admission unavailable"))?;
        let mut tx = self.engine.begin_write()?;
        if !self
            .stage_backup_registration(&mut tx, digest, commit, logical_digest, encoded_bytes)?
            .1
        {
            return Ok(());
        }
        if tx.commit(Durability::Sync)?.durability != Durability::Sync {
            return Err(failure("issued archive registration was not synchronized"));
        }
        Ok(())
    }

    fn stage_backup_registration<T: WriteTransaction>(
        &self,
        tx: &mut T,
        digest: &str,
        commit: u64,
        logical_digest: &str,
        encoded_bytes: u64,
    ) -> contextdb_storage::Result<(NativeBackupRegistration, bool)> {
        if let Some(previous) = self.find_backup(tx, digest)? {
            if previous.native_commit != commit
                || previous.logical_digest != logical_digest
                || previous.encoded_bytes != encoded_bytes
            {
                return Err(failure("issued archive metadata changed"));
            }
            return Ok((previous, false));
        }
        let head = self.backup_head(tx)?;
        let sequence = head
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure("backup registry overflow"))?;
        let entry = NativeBackupRegistration {
            sequence,
            authority_id: self.authority_id(),
            archive_digest: digest.into(),
            native_commit: commit,
            logical_digest: logical_digest.into(),
            encoded_bytes,
            previous_archive_digest: head.digest,
        };
        let key = issued_key(sequence);
        tx.put(
            &self.rows,
            key.clone(),
            self.seal_backup_record(&key, &entry)?,
        )?;
        let index = index_key(digest);
        tx.put(
            &self.rows,
            index.clone(),
            self.seal_backup_record(&index, &sequence)?,
        )?;
        tx.put(
            &self.rows,
            HEAD.to_vec(),
            self.seal_backup_record(
                HEAD,
                &Head {
                    sequence,
                    digest: Some(digest.into()),
                    contents: head.contents,
                },
            )?,
        )?;
        Ok((entry, true))
    }

    fn backup_aad(&self, key: &[u8]) -> contextdb_storage::Result<Vec<u8>> {
        encode(&("contextdb/native-issued-backup/v1", &self.identity, key))
    }

    fn seal_backup_record<T: Serialize>(
        &self,
        key: &[u8],
        value: &T,
    ) -> contextdb_storage::Result<Vec<u8>> {
        seal(&self.master.0, &self.backup_aad(key)?, &encode(value)?)
    }

    fn open_backup_record<T: serde::de::DeserializeOwned>(
        &self,
        key: &[u8],
        value: &[u8],
    ) -> contextdb_storage::Result<T> {
        decode(&open(&self.master.0, &self.backup_aad(key)?, value)?)
    }

    fn backup_head<S: ReadSnapshot>(&self, snapshot: &S) -> contextdb_storage::Result<Head> {
        let head: Head = self.open_backup_record(
            HEAD,
            &snapshot
                .get(&self.rows, HEAD)?
                .ok_or_else(|| failure("issued backup registry head is missing"))?,
        )?;
        if (head.sequence == 0) != head.digest.is_none() {
            return Err(failure("issued backup registry head is invalid"));
        }
        if let Some(digest) = &head.digest {
            valid_digest(digest)?;
        }
        if let Some(contents) = &head.contents {
            contents.validate(self)?;
        }
        Ok(head)
    }

    fn decode_registration(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> contextdb_storage::Result<NativeBackupRegistration> {
        let entry: NativeBackupRegistration = self.open_backup_record(key, bytes)?;
        valid_digest(&entry.archive_digest)?;
        valid_digest(&entry.logical_digest)?;
        if let Some(previous) = &entry.previous_archive_digest {
            valid_digest(previous)?;
        }
        if entry.authority_id != self.authority_id()
            || entry.sequence == 0
            || key != issued_key(entry.sequence)
            || entry.encoded_bytes == 0
            || (entry.sequence == 1) != entry.previous_archive_digest.is_none()
        {
            return Err(failure("issued backup registration binding is invalid"));
        }
        Ok(entry)
    }

    fn find_backup<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        digest: &str,
    ) -> contextdb_storage::Result<Option<NativeBackupRegistration>> {
        let index = index_key(digest);
        let Some(bytes) = snapshot.get(&self.rows, &index)? else {
            return Ok(None);
        };
        let sequence: u64 = self.open_backup_record(&index, &bytes)?;
        let key = issued_key(sequence);
        let bytes = snapshot
            .get(&self.rows, &key)?
            .ok_or_else(|| failure("issued backup registration is missing"))?;
        let entry = self.decode_registration(&key, &bytes)?;
        let head = self.backup_head(snapshot)?;
        if entry.archive_digest != digest || entry.sequence > head.sequence {
            return Err(failure("issued backup lookup binding differs"));
        }
        Ok(Some(entry))
    }

    pub(super) fn verify_backup_catalog<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> contextdb_storage::Result<()> {
        let rows = snapshot.scan_prefix(&self.rows, b"backup/")?;
        if self.identity.version == 1 {
            return if rows.is_empty() {
                Ok(())
            } else {
                Err(failure(
                    "legacy custody authority contains undeclared backup data",
                ))
            };
        }
        let head = self.backup_head(snapshot)?;
        let mut reconstructed = Head::default();
        let mut expected = std::collections::BTreeSet::from([HEAD.to_vec()]);
        for row in rows.iter().filter(|row| row.key.starts_with(ISSUED)) {
            let entry = self.decode_registration(&row.key, &row.value)?;
            if entry.sequence != reconstructed.sequence + 1
                || entry.previous_archive_digest != reconstructed.digest
                || self.find_backup(snapshot, &entry.archive_digest)?.as_ref() != Some(&entry)
            {
                return Err(failure("issued backup registry chain differs"));
            }
            expected.insert(row.key.clone());
            expected.insert(index_key(&entry.archive_digest));
            reconstructed = Head {
                sequence: entry.sequence,
                digest: Some(entry.archive_digest),
                contents: None,
            };
        }
        self.verify_backup_contents(snapshot, &head, &mut expected)?;
        reconstructed.contents = head.contents.clone();
        if reconstructed != head
            || rows.len() != expected.len()
            || rows.iter().any(|row| !expected.contains(&row.key))
        {
            return Err(failure("issued backup registry closure differs"));
        }
        Ok(())
    }
}

fn valid_digest(digest: &str) -> contextdb_storage::Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(failure("issued backup digest is not canonical"));
    }
    Ok(())
}
fn issued_key(sequence: u64) -> Vec<u8> {
    format!("backup/issued/{sequence:020}").into_bytes()
}
fn index_key(digest: &str) -> Vec<u8> {
    format!("backup/index/{digest}").into_bytes()
}

pub(super) fn genesis(
    identity: &Identity,
    master: &CustodyMasterKey,
) -> contextdb_storage::Result<Vec<u8>> {
    seal(
        &master.0,
        &encode(&("contextdb/native-issued-backup/v1", identity, HEAD))?,
        &encode(&Head::default())?,
    )
}
