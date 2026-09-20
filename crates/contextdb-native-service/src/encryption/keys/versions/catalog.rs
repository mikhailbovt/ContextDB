//! Bounded enumeration of accepted key allocations, not proof of native use,
//! physical-copy absence or permission to disable a key.

use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};
use contextdb_storage::ScanPageRequest;

use crate::{integrity, invalid, raw_index::budget_error, storage_error};

use super::*;

#[cfg(test)]
mod tests;

const MAX_CURSOR_BYTES: usize = 2048;

/// One exact descriptor committed by the independent allocation journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyAllocation {
    /// Domain-separated hash of the native keyspace and value address.
    pub address_digest: String,
    /// Immutable key UUID named by the corresponding ciphertext envelope.
    pub key_id: Uuid,
    /// Ordered allocation batch, independent of native workspace commits.
    pub allocation_sequence: u64,
    /// Commitment to the wrapped descriptor; no key material is returned.
    pub descriptor_digest: String,
}

/// A revision-bound page of accepted allocations. Unused allocations can remain
/// after interrupted native publication; this is not a native-copy inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyCatalogPage {
    /// Exact independently retained authority supplying these descriptors.
    pub authority_id: Uuid,
    /// Last accepted allocation batch for this entire enumeration.
    pub revision: u64,
    /// Authenticated chain commitment at that revision; absent only at genesis.
    pub revision_digest: Option<String>,
    /// At most the requested number of descriptors, in allocation order.
    pub entries: Vec<NativeKeyAllocation>,
    /// Opaque authenticated continuation, bound to this authority and revision.
    /// None means this enumeration reached its committed terminal batch.
    pub continuation: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    head: Head,
    sequence: u64,
    offset: usize,
    previous_digest: Option<String>,
    batch_digest: Option<String>,
}

impl NativeCustodyKeys {
    /// Enumerate 1..256 accepted descriptors without exposing wrapped or raw keys.
    /// Pass the returned continuation unchanged; allocation changes require a new
    /// enumeration. Backup registration alone does not invalidate it. Cursors
    /// survive reopening the same retained authority with the same master key.
    ///
    /// Each page checks its exact descriptors and journal chain. A partial page
    /// does not establish complete coverage; completion must reach the authenticated
    /// terminal. Full reverse inventory verification remains an authority-open
    /// check. Key use, physical copies and deletion authorization are separate.
    /// Work/bytes/time are budgeted, including decoding allocation batches of up
    /// to 8 MiB. This administrative API is not used by ordinary value reads.
    pub fn key_catalog_page(
        &self,
        continuation: Option<&[u8]>,
        limit: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeKeyCatalogPage> {
        if self.identity.version != 3 {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "key allocation enumeration requires explicit version 3 custody migration",
                false,
            ));
        }
        if !(1..=256).contains(&limit)
            || continuation.is_some_and(|bytes| bytes.len() > MAX_CURSOR_BYTES)
        {
            return Err(invalid(
                "key catalog requires 1..256 entries and a bounded cursor",
            ));
        }
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head_bytes = self.catalog_row(&snapshot, HEAD, budget)?;
        if head_bytes.len() > MAX_CURSOR_BYTES {
            return Err(integrity("key catalog head exceeds its bound"));
        }
        let head: Head = decode(
            &self
                .open_key_log(HEAD, &head_bytes)
                .map_err(storage_error)?,
        )
        .map_err(storage_error)?;
        if (head.sequence == 0) != head.digest.is_none()
            || head
                .digest
                .as_ref()
                .is_some_and(|value| blake3::Hash::from_hex(value).is_err())
        {
            return Err(integrity("key catalog head is invalid"));
        }
        self.catalog_frontier(&snapshot, &head, budget)?;
        let mut cursor = match continuation {
            Some(bytes) => {
                budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
                let cursor: Cursor = decode(
                    &open(&self.master.0, &self.catalog_aad()?, bytes).map_err(storage_error)?,
                )
                .map_err(storage_error)?;
                if cursor.head != head {
                    return Err(ServiceError::new(
                        ErrorCode::IndexTooStale,
                        "key allocations changed; restart enumeration",
                        true,
                    ));
                }
                if cursor.sequence == 0
                    || cursor.sequence > head.sequence
                    || cursor.offset >= MAX_LEGACY_BATCH_KEYS
                    || (cursor.offset == 0) != cursor.batch_digest.is_none()
                    || (cursor.sequence == 1) != cursor.previous_digest.is_none()
                {
                    return Err(integrity("key catalog continuation is invalid"));
                }
                cursor
            }
            None => Cursor {
                head: head.clone(),
                sequence: 1,
                offset: 0,
                previous_digest: None,
                batch_digest: None,
            },
        };
        let mut complete = head.sequence == 0;
        let mut entries = Vec::with_capacity(limit as usize);
        while !complete && entries.len() < limit as usize {
            let bytes = self.catalog_row(&snapshot, &batch_key(cursor.sequence), budget)?;
            let bytes = self
                .open_key_log(&batch_key(cursor.sequence), &bytes)
                .map_err(storage_error)?;
            let digest = crate::digest_bytes(&bytes);
            let batch: Batch = decode(&bytes).map_err(storage_error)?;
            budget
                .charge(batch.keys.len() as u64, 0)
                .map_err(budget_error)?;
            if batch.sequence != cursor.sequence
                || batch.previous_digest != cursor.previous_digest
                || !(1..=MAX_LEGACY_BATCH_KEYS).contains(&batch.keys.len())
                || cursor.offset >= batch.keys.len()
                || cursor
                    .batch_digest
                    .as_ref()
                    .is_some_and(|expected| expected != &digest)
                || (batch.sequence == head.sequence && head.digest.as_ref() != Some(&digest))
                || batch
                    .keys
                    .windows(2)
                    .any(|pair| pair[0].address >= pair[1].address)
                || batch.keys.iter().any(|reference| {
                    reference.id.is_nil()
                        || blake3::Hash::from_hex(&reference.address).is_err()
                        || blake3::Hash::from_hex(&reference.record_digest).is_err()
                })
            {
                return Err(integrity("key catalog allocation chain differs"));
            }
            while cursor.offset < batch.keys.len() && entries.len() < limit as usize {
                let reference = &batch.keys[cursor.offset];
                let bytes = self.catalog_row(
                    &snapshot,
                    &version_key(&reference.address, reference.id),
                    budget,
                )?;
                let record: KeyRecord = decode(&bytes).map_err(storage_error)?;
                if record.id != reference.id
                    || crate::digest_bytes(&bytes) != reference.record_digest
                {
                    return Err(integrity(
                        "key catalog descriptor differs from its allocation",
                    ));
                }
                self.unwrap(&reference.address, &record)
                    .map_err(storage_error)?;
                entries.push(NativeKeyAllocation {
                    address_digest: reference.address.clone(),
                    key_id: reference.id,
                    allocation_sequence: batch.sequence,
                    descriptor_digest: reference.record_digest.clone(),
                });
                cursor.offset += 1;
            }
            if cursor.offset == batch.keys.len() {
                complete = cursor.sequence == head.sequence;
                if !complete {
                    cursor.sequence = cursor
                        .sequence
                        .checked_add(1)
                        .ok_or_else(|| integrity("key catalog sequence exhausted"))?;
                    cursor.offset = 0;
                    cursor.previous_digest = Some(digest);
                    cursor.batch_digest = None;
                }
            } else {
                cursor.batch_digest = Some(digest);
            }
        }
        budget.check().map_err(budget_error)?;
        let continuation = if complete {
            None
        } else {
            let bytes = seal(
                &self.master.0,
                &self.catalog_aad()?,
                &encode(&cursor).map_err(storage_error)?,
            )
            .map_err(storage_error)?;
            if bytes.len() > MAX_CURSOR_BYTES {
                return Err(integrity("key catalog continuation exceeds its bound"));
            }
            Some(bytes)
        };
        let page = NativeKeyCatalogPage {
            authority_id: self.identity.authority,
            revision: head.sequence,
            revision_digest: head.digest,
            entries,
            continuation,
        };
        budget
            .charge(0, encode(&page).map_err(storage_error)?.len() as u64)
            .map_err(budget_error)?;
        Ok(page)
    }

    fn catalog_aad(&self) -> ServiceResult<Vec<u8>> {
        encode(&("contextdb/native-key-catalog/v1", &self.identity)).map_err(storage_error)
    }

    fn catalog_row<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        key: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<u8>> {
        budget.check().map_err(budget_error)?;
        let bytes = snapshot
            .get(&self.rows, key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("accepted key catalog row is absent"))?;
        budget
            .charge(1, (key.len() + bytes.len()) as u64)
            .map_err(budget_error)?;
        Ok(bytes)
    }

    fn catalog_frontier<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        head: &Head,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let after = batch_key(head.sequence);
        for (prefix, start_after) in [(BATCHES, Some(after.as_slice()))]
            .into_iter()
            .chain((head.sequence == 0).then_some((b"key/".as_slice(), None)))
        {
            budget.check().map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.rows,
                    ScanPageRequest {
                        prefix,
                        start_after,
                        max_entries: 1,
                        max_bytes: MAX_BATCH_BYTES + NONCE_BYTES + TAG_BYTES,
                    },
                )
                .map_err(storage_error)?;
            budget
                .charge(
                    1,
                    page.entries
                        .iter()
                        .map(|row| (row.key.len() + row.value.len()) as u64)
                        .sum(),
                )
                .map_err(budget_error)?;
            if !page.entries.is_empty() || page.continuation.is_some() {
                return Err(integrity("key catalog head is behind retained allocations"));
            }
        }
        Ok(())
    }
}
