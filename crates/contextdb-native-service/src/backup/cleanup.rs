//! Resume logical cleanup of one exact restored archive using existing native receipts.

use super::*;
use crate::{NativeBackupArtifactProgress, NativeBackupReplacement, NativeRemovalRequestReceipt};
use contextdb_recall::QueryBudget;
use contextdb_service::AuthenticatedRequestContext;
use serde::{Deserialize, Serialize};

mod index;
mod successor;

#[cfg(test)]
mod tests;

/// Work accepted by one archive-cleanup advance. These are local logical-copy
/// stages, never deletion completion or permission to discard keys/other archives.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeBackupCleanupStage {
    /// Imported the fixed input into its job's pristine registered worker.
    Restored,
    /// Completed or caught up retained record-origin declarations.
    RecordOrigins,
    /// Prepared immutable source controls before removing their bodies.
    SourceControls,
    /// Rebuilt current source restrictions.
    Custody,
    /// Advanced an index rebuild or reclaimed an obsolete generation.
    RawIndex,
    /// Removed selected mutations from one semantic assertion batch.
    Assertions,
    /// Prepared controls or removed one classified generic revision.
    Records,
    /// Removed a bounded set of selected original bodies.
    Originals,
    /// Removed a bounded portion of an exclusively owned staged payload.
    Payload,
    /// Retained a prefix of the verified replacement's encrypted bytes.
    Artifact,
    /// This archive's logical cleanup and independently retained replacement are ready.
    Available,
    /// No new pruning was required. This is not replacement or deletion evidence.
    Unchanged,
}

/// Restartable progress for one original archive and one retained removal request.
/// Resume by supplying that same original and request to the same restored owner.
/// Durable journals determine the next operation; no caller-provided stage is trusted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupCleanupProgress {
    /// Operation just accepted, or the terminal local-archive state.
    pub stage: NativeBackupCleanupStage,
    /// Observed native workspace commit. At artifact publication this identifies
    /// the verified target; later writes do not change the immutable receipt.
    pub workspace_commit: u64,
    /// Verified source-to-target preservation, present at artifact publication.
    pub replacement: Option<NativeBackupReplacement>,
    /// Actual retained byte prefix; complete only when stage is Available.
    pub artifact: Option<NativeBackupArtifactProgress>,
}

impl NativeService {
    /// Advance one bounded maintenance operation on an exact restored archive.
    /// Open a separate encrypted owner with the retained authorities and restore
    /// `original` through the pristine-only restore API before the first call.
    /// A divergent active history is rejected before any cleanup; histories are
    /// never merged or substituted. Repeat after restart or an uncertain response.
    ///
    /// Admin, exact request, original issuance, native replay and ancestry are
    /// checked before work. Unknown origins, new unretained descendants and legacy
    /// hash-only mutations require explicit reconciliation/migration. Each existing
    /// operation keeps its own bounds and durable receipts under the shared budget.
    /// Available covers this archive's logical families and retained replacement;
    /// keys, physical/external copies and global deletion admission remain unchanged.
    pub fn advance_removal_backup(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &BackupResponse,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupCleanupProgress> {
        self.advance_removal_backup_for_job(context, request, original, budget)
            .map(|(progress, _)| progress)
    }

    pub(super) fn advance_removal_backup_for_job(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &BackupResponse,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(NativeBackupCleanupProgress, Option<String>)> {
        let retained = self.read_original_removal_inventory(context, request, budget)?;
        let source = self.verify_encrypted_archive(original, budget)?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody is absent"))?;
        if keys.backup_registration(&original.digest)?.is_none() {
            return Err(crate::invalid("archive cleanup requires original issuance"));
        }
        let (pruning, admitted_sequence, admitted_workspace_commit, admitted_digest) = {
            let _guard = self.lock_index_publication(budget)?;
            let (current, bytes) = self.build_native_backup()?;
            budget
                .charge(
                    current
                        .keyspaces
                        .iter()
                        .map(|space| space.entries.len() as u64)
                        .sum(),
                    bytes.bytes.len() as u64,
                )
                .map_err(crate::raw_index::budget_error)?;
            if current.commit_seq < source.commit_seq {
                return Err(integrity("archive cleanup owner predates its original"));
            }
            let before = self.engine.decode_snapshot(BackupSnapshot::new(&source));
            let after = self.engine.decode_snapshot(BackupSnapshot::new(&current));
            let pruning = self.verify_replacement_history(
                &before,
                &after,
                source.commit_seq,
                &retained,
                request,
                budget,
            )?;
            (
                pruning,
                self.engine.head_sequence().map_err(storage_error)?,
                self.workspace_state(&after, &context.request.workspace_id)?
                    .watermarks
                    .journal,
                bytes.digest,
            )
        };
        let local = self.read_original_removal_local_inventory(context, request, budget)?;
        let selected: BTreeSet<_> = local
            .sources
            .iter()
            .map(|source| source.receipt.event_id)
            .collect();
        let mut cursor = None;
        loop {
            let page =
                self.pending_record_source_writes(context, cursor.as_deref(), 256, budget)?;
            if let Some(commit) = page.pending.first() {
                self.resume_record_source_write(context, *commit, budget)?;
                return self
                    .backup_cleanup_progress(context, NativeBackupCleanupStage::RecordOrigins);
            }
            if page.caught_up {
                break;
            }
            cursor = Some(page.continuation);
        }
        let origins = self.maintain_record_sources(context, 256, budget)?;
        if origins.processed != 0 {
            return self.backup_cleanup_progress(context, NativeBackupCleanupStage::RecordOrigins);
        }
        if !origins.caught_up {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "record origins changed during archive cleanup; repeat the advance",
                true,
            ));
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        let mut prepare = BTreeSet::new();
        for id in &selected {
            if !self.source_prepared_at(
                &snapshot,
                &workspace,
                *id,
                Some(world.watermarks.journal),
                budget,
            )? {
                prepare.insert(*id);
                if prepare.len() == 256 {
                    break;
                }
            }
        }
        drop(snapshot);
        if !prepare.is_empty() {
            self.prepare_original_removal_sources(context, request, &prepare, budget)?;
            return self.backup_cleanup_progress(context, NativeBackupCleanupStage::SourceControls);
        }
        self.maintain_custody(context, 256, budget)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let latest = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        if latest != world {
            return self.backup_cleanup_progress(context, NativeBackupCleanupStage::Custody);
        }
        drop(snapshot);
        if self.advance_backup_index_cleanup(context, &local.sources, budget)? {
            return self.backup_cleanup_progress(context, NativeBackupCleanupStage::RawIndex);
        }
        if let Some(commit) = self.next_removal_assertion(context, &selected, budget)? {
            self.prune_source_assertions(context, request, commit, budget)?;
            return self.backup_cleanup_progress(context, NativeBackupCleanupStage::Assertions);
        }
        if self.advance_removal_record(context, request, &selected, budget)? {
            return self.backup_cleanup_progress(context, NativeBackupCleanupStage::Records);
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let mut originals = BTreeSet::new();
        for id in &selected {
            if self.verify_pruned_source(&snapshot, *id, budget)?.is_none() {
                originals.insert(*id);
                if originals.len() == 256 {
                    break;
                }
            }
        }
        drop(snapshot);
        if !originals.is_empty() {
            self.prune_original_sources(context, request, &originals, budget)?;
            return self.backup_cleanup_progress(context, NativeBackupCleanupStage::Originals);
        }
        for payload in &local.payloads {
            if !self.removal_payload_complete(payload.block_id, budget)? {
                self.prune_original_payload(context, request, payload.block_id, 32, budget)?;
                return self.backup_cleanup_progress(context, NativeBackupCleanupStage::Payload);
            }
        }
        #[cfg(test)]
        BEFORE_COMPLETION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        if pruning.total() == Some(0) {
            let _guard = self.lock_index_publication(budget)?;
            if self.engine.head_sequence().map_err(storage_error)? != admitted_sequence {
                return Err(ServiceError::new(
                    ErrorCode::IndexTooStale,
                    "archive changed during cleanup verification; repeat the advance",
                    true,
                ));
            }
            return self
                .backup_cleanup_progress(context, NativeBackupCleanupStage::Unchanged)
                .map(|(progress, _)| (progress, Some(admitted_digest)));
        }
        let replacement = self.create_removal_backup_at(
            context,
            request,
            original,
            Some(admitted_sequence),
            budget,
        )?;
        let existing = keys.backup_artifact(&replacement.backup.digest, budget)?;
        let artifact = match existing {
            Some(complete) if complete.complete => complete,
            partial => self.retain_removal_backup(
                context,
                request,
                &replacement,
                partial.map_or(0, |progress| progress.stored_pages),
                16,
                budget,
            )?,
        };
        let terminal_digest = artifact.complete.then_some(replacement.backup.digest);
        Ok((
            NativeBackupCleanupProgress {
                stage: if artifact.complete {
                    NativeBackupCleanupStage::Available
                } else {
                    NativeBackupCleanupStage::Artifact
                },
                workspace_commit: admitted_workspace_commit,
                replacement: Some(replacement.replacement),
                artifact: Some(artifact),
            },
            terminal_digest,
        ))
    }

    fn backup_cleanup_progress(
        &self,
        context: &AuthenticatedRequestContext,
        stage: NativeBackupCleanupStage,
    ) -> ServiceResult<(NativeBackupCleanupProgress, Option<String>)> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        Ok((
            NativeBackupCleanupProgress {
                stage,
                workspace_commit: self
                    .workspace_state(&snapshot, &context.request.workspace_id)?
                    .watermarks
                    .journal,
                replacement: None,
                artifact: None,
            },
            None,
        ))
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_COMPLETION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
