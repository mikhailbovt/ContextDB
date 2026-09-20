//! Immutable ciphertext-version keys. The mandatory authenticated allocation
//! journal detects missing families. This profile retains old versions; key
//! retirement requires a separate independently verified deletion transition.

use std::collections::BTreeSet;

use super::*;

mod catalog;
pub use catalog::{NativeKeyAllocation, NativeKeyCatalogPage};

#[cfg(test)]
mod tests;

pub(super) const HEAD: &[u8] = b"key-log/head";
const BATCHES: &[u8] = b"key-log/batch/";
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const REFERENCES_PER_BATCH: usize = 256;

#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    sequence: u64,
    digest: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyReference {
    address: String,
    id: Uuid,
    record_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    sequence: u64,
    previous_digest: Option<String>,
    keys: Vec<KeyReference>,
}

impl NativeCustodyKeys {
    pub(super) fn version_record(
        &self,
        address: &str,
        id: Uuid,
    ) -> contextdb_storage::Result<Option<KeyRecord>> {
        #[cfg(test)]
        KEY_LOOKUPS.with(|count| count.set(count.get() + 1));
        let snapshot = self.engine.begin_read(SnapshotSelector::Latest)?;
        snapshot
            .get(&self.rows, &version_key(address, id))?
            .map(|bytes| {
                let record: KeyRecord = decode(&bytes)?;
                if record.id != id {
                    return Err(failure("ciphertext key version identity differs"));
                }
                Ok(record)
            })
            .transpose()
    }

    pub(super) fn publish_key_versions<T: WriteTransaction>(
        &self,
        tx: &mut T,
        pending: &PendingKeys,
    ) -> contextdb_storage::Result<()> {
        let mut head = self.key_version_head(tx)?;
        if !tx
            .scan_prefix_page(
                &self.rows,
                contextdb_storage::ScanPageRequest {
                    prefix: BATCHES,
                    start_after: Some(&batch_key(head.sequence)),
                    max_entries: 1,
                    max_bytes: MAX_BATCH_BYTES + NONCE_BYTES + TAG_BYTES,
                },
            )?
            .entries
            .is_empty()
        {
            return Err(failure("key version head is behind its accepted journal"));
        }
        if head.sequence == 0
            && !tx
                .scan_prefix_page(
                    &self.rows,
                    contextdb_storage::ScanPageRequest {
                        prefix: b"key/",
                        start_after: None,
                        max_entries: 1,
                        max_bytes: MAX_BATCH_BYTES,
                    },
                )?
                .entries
                .is_empty()
        {
            return Err(failure("empty key journal has existing key versions"));
        }
        let mut references = Vec::with_capacity(pending.len());
        for (address, entry) in pending {
            let key = version_key(address, entry.record.id);
            if tx.get(&self.rows, &key)?.is_some() {
                return Err(failure("ciphertext key identity was already allocated"));
            }
            let bytes = encode(&entry.record)?;
            references.push(KeyReference {
                address: address.clone(),
                id: entry.record.id,
                record_digest: crate::digest_bytes(&bytes),
            });
            tx.put(&self.rows, key, bytes)?;
        }
        // Bound new journal records so paging a large native transaction does
        // not repeatedly decode its entire allocation set. Historical larger
        // batches remain readable. All records and the head share one Sync.
        for references in references.chunks(REFERENCES_PER_BATCH) {
            let sequence = head
                .sequence
                .checked_add(1)
                .ok_or_else(|| failure("key version journal exhausted"))?;
            let batch = Batch {
                sequence,
                previous_digest: head.digest,
                keys: references.to_vec(),
            };
            let bytes = encode(&batch)?;
            if bytes.len() > MAX_BATCH_BYTES {
                return Err(failure("key version journal batch exceeds its bound"));
            }
            head = Head {
                sequence,
                digest: Some(crate::digest_bytes(&bytes)),
            };
            let key = batch_key(sequence);
            tx.put(&self.rows, key.clone(), self.seal_key_log(&key, &bytes)?)?;
        }
        tx.put(
            &self.rows,
            HEAD.to_vec(),
            self.seal_key_log(HEAD, &encode(&head)?)?,
        )?;
        Ok(())
    }

    fn key_version_head<S: ReadSnapshot>(&self, snapshot: &S) -> contextdb_storage::Result<Head> {
        let bytes = snapshot
            .get(&self.rows, HEAD)?
            .ok_or_else(|| failure("key version journal head is absent"))?;
        let head: Head = decode(&self.open_key_log(HEAD, &bytes)?)?;
        if (head.sequence == 0) != head.digest.is_none()
            || head
                .digest
                .as_ref()
                .is_some_and(|value| blake3::Hash::from_hex(value).is_err())
        {
            return Err(failure("key version journal head is invalid"));
        }
        // Even a new allocation must not overwrite a missing/changed terminal.
        if let Some(digest) = &head.digest {
            let key = batch_key(head.sequence);
            let bytes = snapshot
                .get(&self.rows, &key)?
                .ok_or_else(|| failure("key version journal terminal is absent"))?;
            if crate::digest_bytes(&self.open_key_log(&key, &bytes)?) != *digest {
                return Err(failure("key version journal terminal differs"));
            }
        }
        Ok(head)
    }

    pub(super) fn verify_key_versions<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> contextdb_storage::Result<()> {
        let head = self.key_version_head(snapshot)?;
        let mut reconstructed = Head::default();
        let mut expected = BTreeMap::new();
        let rows = snapshot.scan_prefix(&self.rows, BATCHES)?;
        for row in &rows {
            let bytes = self.open_key_log(&row.key, &row.value)?;
            let batch: Batch = decode(&bytes)?;
            let next = reconstructed
                .sequence
                .checked_add(1)
                .ok_or_else(|| failure("key version verification exhausted"))?;
            if batch.sequence != next
                || row.key != batch_key(next)
                || batch.previous_digest != reconstructed.digest
                || !(1..=MAX_PENDING_KEYS).contains(&batch.keys.len())
            {
                return Err(failure("key version journal is discontinuous or invalid"));
            }
            let mut addresses = BTreeSet::new();
            for reference in batch.keys {
                if reference.id.is_nil()
                    || blake3::Hash::from_hex(&reference.address).is_err()
                    || blake3::Hash::from_hex(&reference.record_digest).is_err()
                    || !addresses.insert(reference.address.clone())
                {
                    return Err(failure("key version reference is invalid"));
                }
                let key = version_key(&reference.address, reference.id);
                let bytes = snapshot
                    .get(&self.rows, &key)?
                    .ok_or_else(|| failure("accepted key version is absent"))?;
                let record: KeyRecord = decode(&bytes)?;
                if record.id != reference.id
                    || crate::digest_bytes(&bytes) != reference.record_digest
                    || expected.insert(key, reference.record_digest).is_some()
                {
                    return Err(failure("accepted key version changed or repeats"));
                }
                self.unwrap(&reference.address, &record)?;
            }
            reconstructed = Head {
                sequence: next,
                digest: Some(crate::digest_bytes(&bytes)),
            };
        }
        let actual = snapshot.scan_prefix(&self.rows, b"key/")?;
        let metadata = snapshot.scan_prefix(&self.rows, b"key-log/")?;
        if reconstructed != head
            || actual.len() != expected.len()
            || actual
                .iter()
                .any(|row| expected.get(&row.key) != Some(&crate::digest_bytes(&row.value)))
            || metadata.len() != rows.len() + 1
            || metadata
                .iter()
                .any(|row| row.key != HEAD && !row.key.starts_with(BATCHES))
        {
            return Err(failure("key versions differ from their accepted journal"));
        }
        Ok(())
    }

    fn seal_key_log(&self, key: &[u8], bytes: &[u8]) -> contextdb_storage::Result<Vec<u8>> {
        seal(&self.master.0, &log_aad(&self.identity, key)?, bytes)
    }

    fn open_key_log(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> contextdb_storage::Result<Zeroizing<Vec<u8>>> {
        if bytes.len() > MAX_BATCH_BYTES + NONCE_BYTES + TAG_BYTES {
            return Err(failure("key version metadata exceeds its bound"));
        }
        open(&self.master.0, &log_aad(&self.identity, key)?, bytes)
    }
}

pub(super) fn genesis(
    identity: &Identity,
    master: &CustodyMasterKey,
) -> contextdb_storage::Result<Vec<u8>> {
    seal(
        &master.0,
        &log_aad(identity, HEAD)?,
        &encode(&Head::default())?,
    )
}

fn log_aad(identity: &Identity, key: &[u8]) -> contextdb_storage::Result<Vec<u8>> {
    encode(&("contextdb/native-key-log/v1", identity, key))
}

fn version_key(address: &str, id: Uuid) -> Vec<u8> {
    format!("key/{address}/{id}").into_bytes()
}

fn batch_key(sequence: u64) -> Vec<u8> {
    format!("key-log/batch/{sequence:020}").into_bytes()
}
