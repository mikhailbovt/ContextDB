//! Independently retained encrypted archive bytes, published in bounded portions.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_recall::QueryBudget;
use contextdb_service::{BackupResponse, ErrorCode, ServiceError, ServiceResult};

use super::*;
use crate::{integrity, invalid, raw_index::budget_error, storage_error};

mod publication;
mod verification;

#[cfg(test)]
mod tests;

const CHUNK_BYTES: usize = 256 * 1024;
const MAX_BATCH_PAGES: u32 = 16;
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Immutable acceptance of one portion of an encrypted archive, outside native restore.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupArtifactReceipt {
    /// Independent authority retaining the actual ciphertext archive.
    pub authority_id: Uuid,
    /// Position in this authority's archive-byte journal.
    pub sequence: u64,
    /// Complete issued archive's digest, including portions not yet retained.
    pub archive_digest: String,
    /// Exact accepted progress and predecessor commitments.
    pub digest: String,
}

impl NativeBackupArtifactReceipt {
    pub(super) fn validate(&self, keys: &NativeCustodyKeys) -> contextdb_storage::Result<()> {
        if keys.identity.version < 4
            || self.authority_id != keys.authority_id()
            || self.sequence == 0
        {
            return Err(failure("archive artifact authority or sequence differs"));
        }
        valid_digest(&self.archive_digest)?;
        valid_digest(&self.digest)
    }
}

/// Durable byte coverage of one issued archive. Complete applies only to this
/// artifact; it never means removal completion, key retirement or external erasure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupArtifactProgress {
    /// Exact accepted progress, recoverable after a lost response.
    pub receipt: NativeBackupArtifactReceipt,
    /// Independently retained issuance and complete logical membership.
    pub contents: NativeBackupContentsInventory,
    /// Contiguous retained page prefix. Continue from this ordinal.
    pub stored_pages: u32,
    /// Pages required for this exact archive, each at most 256 KiB.
    pub total_pages: u32,
    /// Exact archive bytes durably retained at this progress.
    pub stored_bytes: u64,
    /// Every byte is retained and the complete original digest was verified.
    pub complete: bool,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEvent {
    sequence: u64,
    previous: Option<String>,
    prior: Option<NativeBackupArtifactReceipt>,
    contents: NativeBackupContentsInventory,
    from: u32,
    through: u32,
    requested_pages: u32,
    chain: String,
    digest: String,
}

impl ArtifactEvent {
    fn commitment(&self) -> ServiceResult<String> {
        crate::canonical_digest(&(
            "contextdb/native-backup-artifact/v1",
            self.sequence,
            &self.previous,
            &self.prior,
            &self.contents,
            self.from,
            self.through,
            self.requested_pages,
            &self.chain,
        ))
    }

    fn receipt(&self) -> NativeBackupArtifactReceipt {
        NativeBackupArtifactReceipt {
            authority_id: self.contents.registration.authority_id,
            sequence: self.sequence,
            archive_digest: self.contents.registration.archive_digest.clone(),
            digest: self.digest.clone(),
        }
    }

    fn progress(&self) -> NativeBackupArtifactProgress {
        let bytes = self.contents.registration.encoded_bytes;
        let total_pages = bytes.div_ceil(CHUNK_BYTES as u64) as u32;
        NativeBackupArtifactProgress {
            receipt: self.receipt(),
            contents: self.contents.clone(),
            stored_pages: self.through,
            total_pages,
            stored_bytes: (u64::from(self.through) * CHUNK_BYTES as u64).min(bytes),
            complete: self.through == total_pages,
        }
    }
}

pub(super) struct ArtifactState {
    pub(super) progress: NativeBackupArtifactProgress,
    chain: String,
    hash: blake3::Hasher,
}

impl NativeCustodyKeys {
    // Used only inside a catalog walk that already verifies all artifact events.
    pub(super) fn artifact_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        receipt: &NativeBackupArtifactReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupArtifactProgress> {
        let event: ArtifactEvent =
            self.read_artifact_record(snapshot, &event_key(receipt.sequence), budget)?;
        if event.receipt() != *receipt {
            return Err(integrity("archive job artifact receipt differs"));
        }
        Ok(event.progress())
    }

    /// Latest verified byte availability. Absence and incomplete progress must not
    /// be used as proof that the archive has a recoverable replacement.
    pub fn backup_artifact(
        &self,
        archive_digest: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<NativeBackupArtifactProgress>> {
        self.require_backup_contents()?;
        valid_digest(archive_digest).map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        Ok(self
            .selected_backup_keys_at(&snapshot, &BTreeMap::new(), budget)?
            .archives
            .into_iter()
            .find(|archive| archive.registration.archive_digest == archive_digest)
            .and_then(|archive| archive.artifact))
    }

    pub(crate) fn read_archive_artifact(
        &self,
        receipt: &NativeBackupArtifactReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BackupResponse> {
        self.require_backup_contents()?;
        receipt.validate(self).map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.selected_backup_keys_at(&snapshot, &BTreeMap::new(), budget)?;
        let event: ArtifactEvent =
            self.read_artifact_record(&snapshot, &event_key(receipt.sequence), budget)?;
        if event.receipt() != *receipt {
            return Err(integrity("archive artifact receipt differs"));
        }
        let progress = event.progress();
        if !progress.complete {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "archive artifact is incomplete",
                true,
            ));
        }
        budget
            .charge(0, progress.stored_bytes)
            .map_err(budget_error)?;
        let mut bytes = Vec::with_capacity(progress.stored_bytes as usize);
        for page in 0..progress.total_pages {
            bytes.extend_from_slice(&self.read_artifact_chunk(
                &snapshot,
                &event.contents,
                page,
                budget,
            )?);
        }
        if crate::digest_bytes(&bytes) != receipt.archive_digest {
            return Err(integrity("retained archive full digest differs"));
        }
        budget.check().map_err(budget_error)?;
        Ok(BackupResponse {
            format: crate::NATIVE_ENCRYPTED_BACKUP_FORMAT.into(),
            bytes,
            digest: receipt.archive_digest.clone(),
            commit_seq: event.contents.registration.native_commit,
        })
    }
}

fn event_key(sequence: u64) -> Vec<u8> {
    format!("backup/artifact/event/{sequence:020}").into_bytes()
}
fn index_key(archive: &str, from: u32) -> Vec<u8> {
    format!("backup/artifact/index/{archive}/{from:08}").into_bytes()
}
fn latest_key(archive: &str) -> Vec<u8> {
    format!("backup/artifact/latest/{archive}").into_bytes()
}
fn chunk_key(archive: &str, page: u32) -> Vec<u8> {
    format!("backup/artifact/chunk/{archive}/{page:08}").into_bytes()
}
fn genesis(contents: &NativeBackupContentsInventory) -> ServiceResult<String> {
    crate::canonical_digest(&("contextdb/native-backup-artifact-genesis/v1", contents))
}
fn append_chunk(previous: &str, page: u32, bytes: &[u8]) -> ServiceResult<String> {
    crate::canonical_digest(&(
        "contextdb/native-backup-artifact-chunk/v1",
        previous,
        page,
        bytes.len(),
        crate::digest_bytes(bytes),
    ))
}

#[cfg(test)]
type PublicationHook = Box<dyn FnOnce() -> ServiceResult<()>>;

#[cfg(test)]
thread_local! {
    static BEFORE_ARTIFACT_SYNC: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
    static AFTER_ARTIFACT_SYNC: std::cell::RefCell<Option<PublicationHook>> = const { std::cell::RefCell::new(None) };
}
