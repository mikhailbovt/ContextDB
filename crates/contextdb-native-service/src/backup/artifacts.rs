//! Administrative durability of verified issued archives and replacements.

use contextdb_recall::QueryBudget;
use contextdb_service::AuthenticatedRequestContext;

use super::*;
use crate::{
    NativeBackupArtifactProgress, NativeBackupArtifactReceipt, NativeBackupReplacement,
    NativeBackupReplacementReceipt, NativeRemovalRequestReceipt,
};

impl NativeService {
    /// Retain 1..16 pages of an already issued encrypted archive, including an
    /// original needed for later automatic cleanup. Admin and full native replay
    /// are checked before byte publication. Complete membership must already be
    /// retained; use `retain_backup_contents` for explicit legacy backfill.
    /// Retry the same page and limit after an uncertain response. This creates no
    /// issuance, replacement proof, native instance or deletion-completion receipt.
    pub fn retain_issued_backup(
        &self,
        context: &AuthenticatedRequestContext,
        backup: &BackupResponse,
        from_page: u32,
        max_pages: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupArtifactProgress> {
        require_capability(context, Capability::Admin)?;
        self.verify_encrypted_archive(backup, budget)?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody is absent"))?;
        let contents = keys
            .backup_contents(&backup.digest, budget)?
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::EvidenceRequired,
                    "archive retention requires complete issued membership",
                    false,
                )
            })?;
        keys.retain_archive_artifact(backup, &contents, from_page, max_pages, budget)
    }

    /// Retain 1..16 pages (at most 4 MiB) of a verified replacement archive in its
    /// independent custody authority. Start at zero, then use returned stored_pages.
    /// Retry the same starting page and limit after an uncertain response; the exact
    /// previous receipt is returned without another Sync. Complete describes only
    /// this artifact's bytes, not deletion or the availability of external copies.
    pub fn retain_removal_backup(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        replacement: &NativeRemovalBackup,
        from_page: u32,
        max_pages: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupArtifactProgress> {
        let accepted = self.require_removal_backup_artifact(
            context,
            request,
            &replacement.replacement.receipt,
            budget,
        )?;
        if accepted != replacement.replacement {
            return Err(integrity("archive replacement proof fields differ"));
        }
        self.verify_encrypted_archive(&replacement.backup, budget)?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody is absent"))?;
        keys.retain_archive_artifact(
            &replacement.backup,
            &accepted.target,
            from_page,
            max_pages,
            budget,
        )
    }

    /// Recover actual complete encrypted replacement bytes after restart or old
    /// native restore. Authorization and exact request/provenance binding precede
    /// archive access. The complete byte digest and native replay are verified;
    /// partial, unavailable or damaged artifacts return an error.
    pub fn read_retained_removal_backup(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        replacement: &NativeBackupReplacementReceipt,
        artifact: &NativeBackupArtifactReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BackupResponse> {
        let accepted =
            self.require_removal_backup_artifact(context, request, replacement, budget)?;
        if artifact.archive_digest != accepted.target.registration.archive_digest {
            return Err(integrity(
                "retained artifact belongs to another replacement",
            ));
        }
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody is absent"))?;
        let backup = keys.read_archive_artifact(artifact, budget)?;
        self.verify_encrypted_archive(&backup, budget)?;
        Ok(backup)
    }

    fn require_removal_backup_artifact(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        receipt: &NativeBackupReplacementReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupReplacement> {
        self.read_original_removal_inventory(context, request, budget)?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody is absent"))?;
        keys.backup_replacement_for_request(
            receipt,
            &digest_bytes(context.request.workspace_id.as_bytes()),
            request,
            budget,
        )
    }
}
