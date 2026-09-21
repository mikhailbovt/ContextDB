//! Continue from verified replacement ancestry without decrypting refused origins.

use super::*;
use crate::{NativeBackupContentsReceipt, NativeBackupReplacementReceipt};

impl NativeService {
    /// Read the usable end of 1..256 exact, ordered replacement acceptances.
    /// Admin and the current removal request are checked first; every earlier
    /// request must also be independently retained in this workspace/authority.
    /// The path starts at `original` and each complete target is the next source.
    /// Its intermediate archives need not remain decryptable.
    ///
    /// The terminal artifact must be complete and pass current-key/native replay
    /// verification. Restore it into a pristine isolated owner to continue cleanup.
    /// This preserves prior authorized removals; it does not establish that the
    /// current request is complete or grant permission to retire any keys.
    pub fn read_removal_backup_successor(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &NativeBackupContentsReceipt,
        path: &[NativeBackupReplacementReceipt],
        budget: &mut QueryBudget,
    ) -> ServiceResult<BackupResponse> {
        self.read_original_removal_inventory(context, request, budget)?;
        if !(1..=256).contains(&path.len()) {
            return Err(crate::invalid(
                "archive successor requires 1..256 replacement receipts",
            ));
        }
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        let (catalog, replacements) = keys.selected_backup_keys_for_request(
            &BTreeMap::new(),
            &digest_bytes(context.request.workspace_id.as_bytes()),
            request,
            budget,
        )?;
        let by_sequence: BTreeMap<_, _> = replacements
            .iter()
            .map(|proof| (proof.receipt.sequence, proof))
            .collect();
        let mut verified = Vec::<NativeBackupReplacement>::new();
        for receipt in path {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            let proof = by_sequence
                .get(&receipt.sequence)
                .filter(|proof| proof.receipt == *receipt)
                .ok_or_else(|| {
                    integrity("archive successor proof differs or belongs to another scope")
                })?;
            let connected = match verified.last() {
                Some(previous) => previous.target == proof.source,
                None => proof.source.receipt == *original,
            };
            if !connected {
                return Err(integrity(
                    "archive successor path has different source ancestry",
                ));
            }
            verified.push((*proof).clone());
        }
        self.verify_backup_replacement_requests(context, request, &verified, budget)?;
        let terminal = &verified
            .last()
            .ok_or_else(|| integrity("empty successor path"))?
            .target;
        let archive = catalog
            .archives
            .iter()
            .find(|archive| archive.contents.as_ref() == Some(terminal))
            .ok_or_else(|| integrity("archive successor contents absent"))?;
        let artifact = archive
            .artifact
            .as_ref()
            .filter(|artifact| artifact.complete && artifact.contents == *terminal)
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::EvidenceRequired,
                    "archive successor requires complete retained bytes",
                    false,
                )
            })?;
        if !archive.keys_available {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "archive successor keys are unavailable; supply a usable accepted successor",
                false,
            ));
        }
        let backup = keys.read_archive_artifact(&artifact.receipt, budget)?;
        self.verify_encrypted_archive(&backup, budget)?;
        keys.require_backup_frontier(&catalog.frontier, budget)?;
        Ok(backup)
    }

    /// Advance cleanup using an accepted successor of an original archive.
    /// First read that same path with `read_removal_backup_successor` and restore
    /// the result into a pristine isolated owner. Reuse the path across restarts.
    /// Ordinary coordinator ancestry checks reject an unrelated active history.
    /// New replacement proofs start at the successor, retaining each earlier
    /// request's separate authority instead of reassigning its pruning history.
    pub fn advance_removal_backup_from_replacement(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &NativeBackupContentsReceipt,
        path: &[NativeBackupReplacementReceipt],
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupProgress> {
        let successor =
            self.read_removal_backup_successor(context, request, original, path, budget)?;
        self.advance_removal_backup(context, request, &successor, budget)
    }
}
