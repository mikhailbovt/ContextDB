//! Immutable archive membership, independently retained without archive bytes.

use contextdb_recall::QueryBudget;
use contextdb_service::{ErrorCode, ServiceError, ServiceResult};

use super::*;
use crate::{integrity, invalid, raw_index::budget_error, storage_error};

mod publication;
mod selection;
pub use selection::{NativeBackupFrontier, NativeBackupKeyArchive, NativeBackupKeyInventory};
#[cfg(test)]
mod tests;
mod verification;

const EVENTS: &[u8] = b"backup/contents/event/";
const PAGE_ROWS: usize = 256;
const MAX_PAGE_BYTES: usize = 256 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Exact observed archive copy. Repeated issuance is not a physical-copy count.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupKeyCopy {
    /// Domain-separated hash of the native keyspace and row address.
    pub address_digest: String,
    /// Authenticated ciphertext and decoded-value commitments, without their bytes.
    pub version: NativeKeyUseVersion,
}

impl NativeBackupKeyCopy {
    fn validate(&self) -> contextdb_storage::Result<()> {
        NativeKeyUseChange {
            address_digest: self.address_digest.clone(),
            before: None,
            after: Some(self.version.clone()),
        }
        .validate()
    }
}

/// Immutable acceptance of the complete membership of one issued archive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupContentsReceipt {
    /// Independently retained custody authority, outside native restore.
    pub authority_id: Uuid,
    /// Contents journal position, distinct from issuance and native sequences.
    pub sequence: u64,
    /// Exact complete ciphertext archive to which this membership belongs.
    pub archive_digest: String,
    /// Commitment to the accepted registration and complete page-chain terminal.
    pub digest: String,
}

impl NativeBackupContentsReceipt {
    pub(super) fn validate(&self, keys: &NativeCustodyKeys) -> contextdb_storage::Result<()> {
        if keys.identity.version < 4
            || self.authority_id != keys.authority_id()
            || self.sequence == 0
        {
            return Err(failure("archive contents authority or sequence differs"));
        }
        valid_digest(&self.archive_digest)?;
        valid_digest(&self.digest)
    }
}

/// Complete membership declaration. Reading its pages is required to inspect copies.
/// This does not retain the archive, identify its original native instance or prove erasure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupContentsInventory {
    /// Original issuance metadata, unchanged by later membership backfill.
    pub registration: NativeBackupRegistration,
    /// Exact acceptance of all declared pages.
    pub receipt: NativeBackupContentsReceipt,
    /// Every ciphertext-bearing row in the verified logical archive.
    pub rows: u64,
    /// Number of pages, each containing at most 256 rows.
    pub pages: u32,
    /// Terminal digest of the ordered membership pages.
    pub contents_digest: String,
}

/// One immutable membership page. Native and issuance growth do not change its target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupContentsPage {
    /// The complete accepted declaration; all pages share this identity.
    pub inventory: NativeBackupContentsInventory,
    /// Zero-based ordinal within this exact inventory.
    pub page: u32,
    /// At most 256 exact archive copies, including shared and control rows.
    pub copies: Vec<NativeBackupKeyCopy>,
    /// Next page, absent only after the declared terminal.
    pub next_page: Option<u32>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentsEvent {
    sequence: u64,
    previous: Option<String>,
    registration: NativeBackupRegistration,
    rows: u64,
    pages: u32,
    contents_digest: String,
    digest: String,
}

impl ContentsEvent {
    fn commitment(&self) -> contextdb_storage::Result<String> {
        crate::canonical_digest(&(
            "contextdb/native-backup-contents/v1",
            self.sequence,
            &self.previous,
            &self.registration,
            self.rows,
            self.pages,
            &self.contents_digest,
        ))
        .map_err(|_| failure("archive contents commitment cannot be encoded"))
    }

    fn receipt(&self) -> NativeBackupContentsReceipt {
        NativeBackupContentsReceipt {
            authority_id: self.registration.authority_id,
            sequence: self.sequence,
            archive_digest: self.registration.archive_digest.clone(),
            digest: self.digest.clone(),
        }
    }

    fn inventory(&self) -> NativeBackupContentsInventory {
        NativeBackupContentsInventory {
            registration: self.registration.clone(),
            receipt: self.receipt(),
            rows: self.rows,
            pages: self.pages,
            contents_digest: self.contents_digest.clone(),
        }
    }
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyPage {
    previous: String,
    digest: String,
    copies: Vec<NativeBackupKeyCopy>,
}

impl CopyPage {
    fn commitment(&self, page: u32) -> contextdb_storage::Result<String> {
        crate::canonical_digest(&(
            "contextdb/native-backup-copy-page/v1",
            page,
            &self.previous,
            &self.copies,
        ))
        .map_err(|_| failure("archive copy page cannot be encoded"))
    }
}

impl NativeCustodyKeys {
    pub(crate) fn supports_backup_contents(&self) -> bool {
        self.identity.version >= 4
    }

    /// Resolve membership by exact issued archive digest. None is legacy or missing
    /// coverage, never an empty archive or proof of external-copy absence.
    pub fn backup_contents(
        &self,
        digest: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<NativeBackupContentsInventory>> {
        self.require_backup_contents()?;
        valid_digest(digest).map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        Ok(self
            .find_contents(&snapshot, digest, budget)?
            .map(|event| event.inventory()))
    }

    /// Read one receipt-bound page under a shared budget. Complete consumers must
    /// read every page. Reopen and later native/issuance changes preserve the target.
    pub fn backup_contents_page(
        &self,
        receipt: &NativeBackupContentsReceipt,
        page: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupContentsPage> {
        self.require_backup_contents()?;
        receipt.validate(self).map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let event = self
            .find_contents(&snapshot, &receipt.archive_digest, budget)?
            .ok_or_else(|| integrity("archive contents acceptance is absent"))?;
        if event.receipt() != *receipt {
            return Err(integrity("archive contents receipt differs"));
        }
        if page >= event.pages {
            return Err(invalid("archive contents page is outside its receipt"));
        }
        let stored = self.read_copy_page(&snapshot, &event, page, budget)?;
        let previous = if page == 0 {
            contents_genesis(&event.registration).map_err(storage_error)?
        } else {
            self.read_copy_page(&snapshot, &event, page - 1, budget)?
                .digest
        };
        if stored.previous != previous {
            return Err(integrity("archive contents page chain differs"));
        }
        Ok(NativeBackupContentsPage {
            inventory: event.inventory(),
            page,
            copies: stored.copies,
            next_page: (page + 1 < event.pages).then_some(page + 1),
        })
    }

    pub(crate) fn require_backup_contents(&self) -> ServiceResult<()> {
        if !self.supports_backup_contents() {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "archive contents require v4 custody; older authorities need explicit migration",
                false,
            ));
        }
        Ok(())
    }
}

fn contents_genesis(registration: &NativeBackupRegistration) -> contextdb_storage::Result<String> {
    crate::canonical_digest(&("contextdb/native-backup-copy-genesis/v1", registration))
        .map_err(|_| failure("archive copy genesis cannot be encoded"))
}
fn event_key(sequence: u64) -> Vec<u8> {
    format!("backup/contents/event/{sequence:020}").into_bytes()
}
fn index_key(digest: &str) -> Vec<u8> {
    format!("backup/contents/index/{digest}").into_bytes()
}
fn page_key(sequence: u64, page: u32) -> Vec<u8> {
    format!("backup/contents/page/{sequence:020}/{page:08}").into_bytes()
}
