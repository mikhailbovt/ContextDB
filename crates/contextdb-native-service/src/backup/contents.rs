//! Complete archive observations before issuance or explicit legacy backfill.

use contextdb_recall::QueryBudget;
use contextdb_service::AuthenticatedRequestContext;

use super::*;
use crate::{NativeBackupContentsInventory, NativeBackupKeyCopy, raw_index::budget_error};

impl NativeService {
    /// Backfill exact key membership from an already issued encrypted archive.
    /// Admin authorization precedes byte inspection. The entire archive is verified;
    /// its original registration and bytes remain unchanged. No native restore or
    /// key retirement occurs, and the original native instance is not inferred.
    pub fn retain_backup_contents(
        &self,
        context: &AuthenticatedRequestContext,
        backup: &BackupResponse,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupContentsInventory> {
        require_capability(context, Capability::Admin)?;
        let archive = self.verify_encrypted_archive(backup, budget)?;
        self.retain_verified_backup_contents(&archive, backup, false, budget)
    }

    pub(super) fn verify_encrypted_archive(
        &self,
        backup: &BackupResponse,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackup> {
        let keys = self.engine.keys.as_ref().ok_or_else(|| {
            super::super::unsupported("archive contents require encrypted custody")
        })?;
        keys.require_backup_contents()?;
        budget
            .charge(1, backup.bytes.len() as u64)
            .map_err(budget_error)?;
        if backup.format != NATIVE_ENCRYPTED_BACKUP_FORMAT {
            return Err(invalid_archive());
        }
        if backup.bytes.len() > MAX_BACKUP_BYTES {
            return Err(exhausted("native archive exceeds the 256 MiB limit"));
        }
        if backup.digest != digest_bytes(&backup.bytes) {
            return Err(integrity("archive contents input digest differs"));
        }
        let archive = decode_backup(&backup.bytes, &self.database_id)?;
        budget
            .charge(
                archive
                    .keyspaces
                    .iter()
                    .map(|space| space.entries.len() as u64)
                    .sum(),
                0,
            )
            .map_err(budget_error)?;
        if archive.format != backup.format
            || archive.commit_seq != backup.commit_seq
            || archive.custody_authority != Some(keys.authority_id())
        {
            return Err(integrity("archive contents input identity differs"));
        }
        let snapshot = self.engine.decode_snapshot(BackupSnapshot::new(&archive));
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("archive contents manifest is absent"))?,
            "archive contents manifest",
        )?;
        self.verify_suppression_binding(&manifest)?;
        self.verify_encryption_binding(&manifest)?;
        let (commit, digest) = self.verify_backup_snapshot(&snapshot)?;
        if commit != archive.commit_seq || digest != archive.deep_digest {
            return Err(integrity("archive contents differ from verified replay"));
        }
        budget.check().map_err(budget_error)?;
        Ok(archive)
    }

    pub(super) fn retain_verified_backup_contents(
        &self,
        archive: &NativeBackup,
        response: &BackupResponse,
        allow_issue: bool,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupContentsInventory> {
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive contents custody is absent"))?;
        keys.accept_backup_contents(
            response,
            &archive.deep_digest,
            self.archive_copies(archive)?,
            allow_issue,
            budget,
        )
    }
    pub(super) fn archive_copies<'a>(
        &'a self,
        archive: &'a NativeBackup,
    ) -> ServiceResult<impl Iterator<Item = ServiceResult<NativeBackupKeyCopy>> + 'a> {
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive contents custody is absent"))?;
        Ok(archive.keyspaces.iter().flat_map(move |space| {
            let target = self
                .keyspaces
                .all()
                .into_iter()
                .find(|keyspace| keyspace.as_str() == space.name);
            space.entries.iter().map(move |entry| {
                let target =
                    target.ok_or_else(|| integrity("archive contents keyspace is not admitted"))?;
                Ok(NativeBackupKeyCopy {
                    address_digest: crate::encryption::address(target, &entry.key),
                    version: keys
                        .observe_archived_version(target, &entry.key, &entry.value)
                        .map_err(storage_error)?,
                })
            })
        }))
    }
}

pub(super) fn issuance_budget() -> QueryBudget {
    QueryBudget::new(
        (MAX_BACKUP_ENTRIES as u64) * 4 + 4096,
        (MAX_BACKUP_BYTES as u64) * 4,
        std::time::Duration::from_secs(60),
        Default::default(),
    )
}

fn invalid_archive() -> ServiceError {
    ServiceError::new(
        ErrorCode::FormatIncompatible,
        "archive contents require a bounded encrypted native v3 archive",
        false,
    )
}
