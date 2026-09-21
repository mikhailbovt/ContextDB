//! Exact accepted-history preservation before issuing a request-bound replacement.

use contextdb_recall::QueryBudget;
use contextdb_service::AuthenticatedRequestContext;
use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    NativeBackupContentsInventory, NativeBackupPruningCounts, NativeBackupReplacement,
    NativeDeletionLineage, NativeRemovalRequestReceipt, raw_index::budget_error,
    suppression::RemovalCheckpoint,
};

#[cfg(test)]
mod tests;

/// Actual encrypted replacement bytes and independently retained preservation proof.
/// Use `retain_removal_backup` to store the returned bytes in independent custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRemovalBackup {
    /// Restorable archive with the same native format and exact ciphertext rows.
    pub backup: BackupResponse,
    /// Source-to-target provenance. This is not a deletion completion receipt.
    pub replacement: NativeBackupReplacement,
}

pub(crate) struct ReplacementProof {
    pub(crate) workspace_digest: String,
    pub(crate) request: NativeRemovalRequestReceipt,
    pub(crate) source: NativeBackupContentsInventory,
    pub(crate) pruning: NativeBackupPruningCounts,
}

impl NativeService {
    /// Issue the current cleaned history as a verified replacement of an already
    /// issued archive. Admin and exact retained request authorization come first.
    /// Existing cleanup operations must have published at least one pruning event.
    ///
    /// The current history must extend the original byte-exact journal and preserve
    /// original receipts, staged manifests and independent originals. Every new
    /// pruning publication must belong to this request and workspace. Hash-only
    /// legacy record history requires migration. Divergent archives require their
    /// own restored cleanup instance; a later commit number is insufficient.
    ///
    /// Target issuance, complete membership and provenance share one custody Sync.
    /// Exact retries reuse that acceptance. Verified source membership may be
    /// backfilled separately. No original archive, key or disclosure gate changes;
    /// partial cleanup and other copy classes still require further work.
    pub fn create_removal_backup(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &BackupResponse,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRemovalBackup> {
        self.create_removal_backup_at(context, request, original, None, budget)
    }

    pub(super) fn create_removal_backup_at(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &BackupResponse,
        expected_storage_sequence: Option<u64>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRemovalBackup> {
        require_capability(context, Capability::Admin)?;
        let lineage = self.read_original_removal_inventory(context, request, budget)?;
        let source = self.verify_encrypted_archive(original, budget)?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive replacement custody is absent"))?;
        if keys.backup_registration(&original.digest)?.is_none() {
            return Err(crate::invalid(
                "archive replacement requires original issuance",
            ));
        }
        let _guard = self.lock_index_publication(budget)?;
        if let Some(expected) = expected_storage_sequence
            && self.engine.head_sequence().map_err(storage_error)? != expected
        {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "archive changed during cleanup verification; repeat the advance",
                true,
            ));
        }
        let (target, backup) = self.build_native_backup()?;
        budget
            .charge(
                target
                    .keyspaces
                    .iter()
                    .map(|space| space.entries.len() as u64)
                    .sum(),
                backup.bytes.len() as u64,
            )
            .map_err(budget_error)?;
        if target.commit_seq <= source.commit_seq {
            return Err(crate::invalid(
                "replacement must extend the original native history",
            ));
        }
        let before = self.engine.decode_snapshot(BackupSnapshot::new(&source));
        let after = self.engine.decode_snapshot(BackupSnapshot::new(&target));
        let pruning = self.verify_replacement_history(
            &before,
            &after,
            source.commit_seq,
            &lineage,
            request,
            budget,
        )?;
        if pruning.total().is_none_or(|total| total == 0) {
            return Err(crate::invalid(
                "archive replacement requires accepted pruning progress",
            ));
        }
        let source = self.retain_verified_backup_contents(&source, original, false, budget)?;
        let replacement = keys.accept_backup_replacement(
            &backup,
            &target.deep_digest,
            self.archive_copies(&target)?,
            ReplacementProof {
                workspace_digest: digest_bytes(context.request.workspace_id.as_bytes()),
                request: request.clone(),
                source,
                pruning,
            },
            budget,
        )?;
        #[cfg(test)]
        AFTER_REGISTRATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        Ok(NativeRemovalBackup {
            backup,
            replacement,
        })
    }

    pub(super) fn verify_replacement_history<S: ReadSnapshot, T: ReadSnapshot>(
        &self,
        before: &S,
        after: &T,
        original_commit: u64,
        lineage: &NativeDeletionLineage,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupPruningCounts> {
        let workspace = digest_bytes(lineage.workspace_id.as_bytes());
        let expected = RemovalCheckpoint {
            sequence: request.sequence,
            digest: request.digest.clone(),
        };
        let mut pruning = NativeBackupPruningCounts::default();
        for row in after
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            budget
                .charge(1, (row.key.len() + row.value.len()) as u64)
                .map_err(budget_error)?;
            let event: StoredEvent = decode(&row.value, "replacement journal")?;
            if crate::record_journal::owns_record_mutations(&event.operation)
                && event.accepted_records.is_empty()
            {
                return Err(crate::unsupported(
                    "archive replacement requires replayable record history; migrate hash-only legacy mutations",
                ));
            }
            if event.global_commit <= original_commit {
                if before
                    .get(&self.keyspaces.events, &row.key)
                    .map_err(storage_error)?
                    .as_ref()
                    != Some(&row.value)
                {
                    return Err(integrity(
                        "replacement history diverges from the original archive",
                    ));
                }
                continue;
            }
            for (checkpoint, count) in [
                (
                    event
                        .accepted_source_pruning
                        .as_ref()
                        .map(|value| value.removal_request()),
                    &mut pruning.sources,
                ),
                (
                    event
                        .accepted_payload_pruning
                        .as_ref()
                        .map(|value| value.removal_request()),
                    &mut pruning.payloads,
                ),
                (
                    event
                        .accepted_assertion_pruning
                        .as_ref()
                        .map(|value| value.removal_request()),
                    &mut pruning.assertions,
                ),
            ] {
                if let Some(checkpoint) = checkpoint {
                    if event.workspace_digest != workspace || checkpoint != &expected {
                        return Err(integrity(
                            "replacement contains pruning from another removal request",
                        ));
                    }
                    *count += 1;
                }
            }
            if let Some(publication) = &event.accepted_record_pruning {
                if event.workspace_digest != workspace || !publication.belongs_to_removal(request) {
                    return Err(integrity(
                        "replacement contains revision pruning from another request",
                    ));
                }
                pruning.records += 1;
            }
        }
        // Native replay verifies accepted bodies and all derived rows. Also retain
        // receipts and original payload manifests exactly, without relying on the
        // completeness of a target-only verifier to prove preservation of old rows.
        for (space, prefix) in [
            (&self.keyspaces.idempotency, b"".as_slice()),
            (&self.keyspaces.continuous, b"payload/header/".as_slice()),
        ] {
            for row in before.scan_prefix(space, prefix).map_err(storage_error)? {
                budget
                    .charge(1, (row.key.len() + row.value.len()) as u64)
                    .map_err(budget_error)?;
                if after.get(space, &row.key).map_err(storage_error)?.as_ref() != Some(&row.value) {
                    return Err(integrity(
                        "replacement changes an original receipt or payload manifest",
                    ));
                }
            }
        }
        let selected: BTreeMap<_, _> = lineage
            .sources
            .iter()
            .map(|source| {
                (
                    digest_bytes(source.receipt.event_id.to_string().as_bytes()).into_bytes(),
                    source.receipt.event_id,
                )
            })
            .collect();
        // Covers legacy observations too, even when no capture event referenced
        // their full body. Every permitted difference must be verified pruning.
        for row in before
            .scan_prefix(&self.keyspaces.observations_content, b"")
            .map_err(storage_error)?
        {
            budget
                .charge(1, (row.key.len() + row.value.len()) as u64)
                .map_err(budget_error)?;
            if after
                .get(&self.keyspaces.observations_content, &row.key)
                .map_err(storage_error)?
                .as_ref()
                == Some(&row.value)
            {
                continue;
            }
            let id = selected
                .get(&row.key)
                .ok_or_else(|| integrity("replacement loses an independent original"))?;
            if self.verify_pruned_source(after, *id, budget)?.is_none() {
                return Err(integrity(
                    "replacement changes an original without verified pruning",
                ));
            }
        }
        budget.check().map_err(budget_error)?;
        Ok(pruning)
    }
}
