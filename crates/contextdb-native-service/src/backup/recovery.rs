//! Available inputs for cleanup, without claiming that a readable archive is clean.

use super::*;
use crate::{
    NativeBackupArtifactReceipt, NativeBackupContentsInventory, NativeBackupFrontier,
    NativeBackupRegistration, NativeBackupReplacementReceipt, NativeRemovalRequestReceipt,
};
use contextdb_recall::QueryBudget;
use contextdb_service::AuthenticatedRequestContext;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Readable input availability, independent of deletion or preservation completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeBackupRecoveryState {
    /// The issued original has no complete retained membership.
    UnknownContents,
    /// No authorized route reaches an archive whose keys are currently usable.
    KeysUnavailable,
    /// An eligible input exists, but no complete readable artifact is retained.
    AwaitingArtifact {
        /// Exact input whose bytes can be retained through `retain_issued_backup`.
        target: NativeBackupContentsInventory,
        /// Separately authorized edges; empty when the original is the target.
        path: NativeBackupPreservationPath,
    },
    /// Complete readable input bytes exist. They may still require cleanup.
    Available {
        /// Exact input membership, never an assertion of complete deletion.
        target: NativeBackupContentsInventory,
        /// Separately authorized edges; empty for a directly retained original.
        path: NativeBackupPreservationPath,
        /// Complete independently retained byte acceptance.
        artifact: NativeBackupArtifactReceipt,
    },
}

/// One original issuance and its current recovery-input disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupRecovery {
    /// Exact original issuance, including archives with unknown membership.
    pub original: NativeBackupRegistration,
    /// Availability only; a partial-cleanup replacement remains a valid input.
    pub state: NativeBackupRecoveryState,
}

/// Complete issued-archive input coverage at a single current custody frontier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupRecoveryInventory {
    /// Exact independently retained request authorizing this inspection.
    pub request: NativeRemovalRequestReceipt,
    /// Issuance, membership, replacement, artifact and key-refusal frontier.
    pub frontier: NativeBackupFrontier,
    /// Every issued archive in issuance order, including unavailable inputs.
    pub archives: Vec<NativeBackupRecovery>,
}

/// Actual verified input selected automatically from one original's ancestry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupRecoveryInput {
    /// Original archive whose permitted history this input preserves.
    pub original: NativeBackupRegistration,
    /// Exact returned source membership; keep this baseline for a cleanup job.
    pub target: NativeBackupContentsInventory,
    /// Accepted source-to-target edges, empty for a directly retained original.
    pub replacements: Vec<NativeBackupReplacementReceipt>,
    /// Complete artifact from which the returned bytes were read.
    pub artifact: NativeBackupArtifactReceipt,
    /// Full-digest and native-replay verified encrypted archive bytes.
    pub backup: BackupResponse,
}

impl NativeService {
    /// Find an available original or authorized successor for every issued archive.
    /// Admin and the exact request precede catalog access. Each earlier request is
    /// independently verified in this workspace and authority. Prefer complete
    /// readable artifacts over targets awaiting bytes; unknown membership and key
    /// refusal stay explicit. Work and the complete report share a bounded budget.
    ///
    /// Unlike key-preservation inspection, inputs need not be clean: the full
    /// archive coordinator must still reconcile and prune their local history.
    pub fn read_removal_backup_recovery(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupRecoveryInventory> {
        self.read_original_removal_inventory(context, request, budget)?;
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody is absent"))?;
        let (catalog, replacements) = keys.selected_backup_keys_for_request(
            &BTreeMap::new(),
            &digest_bytes(context.request.workspace_id.as_bytes()),
            request,
            budget,
        )?;
        self.verify_backup_replacement_requests(context, request, &replacements, budget)?;
        let archives = recovery_from_inventory(&catalog, &replacements, budget)?;
        let report = NativeBackupRecoveryInventory {
            request: request.clone(),
            frontier: catalog.frontier,
            archives,
        };
        crate::retention::keys::charge_report(&report, budget)?;
        #[cfg(test)]
        BEFORE_RECOVERY_FENCE.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = keys.lock_backup_frontier(&report.frontier, budget)?;
        Ok(report)
    }

    /// Read an automatically selected complete, currently decryptable input.
    /// The original registration must match independent issuance exactly. All
    /// edges and requests are checked before bytes are returned; no caller path
    /// or serialized availability report is accepted as authority. Preserve the
    /// returned baseline when resuming an existing isolated cleanup worker.
    pub fn read_removal_backup_input(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        original: &NativeBackupRegistration,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeBackupRecoveryInput> {
        let inventory = self.read_removal_backup_recovery(context, request, budget)?;
        let entry = inventory
            .archives
            .iter()
            .find(|archive| archive.original == *original)
            .ok_or_else(|| integrity("archive recovery requires the exact issued original"))?;
        let NativeBackupRecoveryState::Available {
            target,
            path,
            artifact,
        } = &entry.state
        else {
            return Err(ServiceError::new(
                ErrorCode::EvidenceRequired,
                "archive recovery requires known membership and complete readable bytes",
                false,
            ));
        };
        let keys = self
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody is absent"))?;
        let backup = keys.read_archive_artifact(artifact, budget)?;
        self.verify_encrypted_archive(&backup, budget)?;
        let _guard = keys.lock_backup_frontier(&inventory.frontier, budget)?;
        Ok(NativeBackupRecoveryInput {
            original: original.clone(),
            target: target.clone(),
            replacements: path.replacements.clone(),
            artifact: artifact.clone(),
            backup,
        })
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_RECOVERY_FENCE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

// Both inputs have already passed request and complete custody verification.
pub(super) fn recovery_from_inventory(
    catalog: &crate::NativeBackupKeyInventory,
    replacements: &[crate::NativeBackupReplacement],
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<NativeBackupRecovery>> {
    let routes = routing::ArchiveRoutes::new(catalog, replacements, |_| true, budget)?;
    let by_sequence: BTreeMap<_, _> = catalog
        .archives
        .iter()
        .map(|archive| (archive.registration.sequence, archive))
        .collect();
    let mut archives = Vec::new();
    let mut report_bytes = 0;
    for archive in &catalog.archives {
        let state = if archive.contents.is_none() {
            NativeBackupRecoveryState::UnknownContents
        } else if let Some(route) =
            routes.best(archive.registration.sequence, &mut report_bytes, budget)?
        {
            let target = by_sequence[&route.path.target_sequence]
                .contents
                .as_ref()
                .ok_or_else(|| integrity("archive recovery target contents disappeared"))?
                .clone();
            if let Some(artifact) = route.artifact {
                NativeBackupRecoveryState::Available {
                    target,
                    path: route.path,
                    artifact,
                }
            } else {
                NativeBackupRecoveryState::AwaitingArtifact {
                    target,
                    path: route.path,
                }
            }
        } else {
            NativeBackupRecoveryState::KeysUnavailable
        };
        let entry = NativeBackupRecovery {
            original: archive.registration.clone(),
            state,
        };
        routing::reserve(&entry, &mut report_bytes, budget)?;
        archives.push(entry);
    }
    Ok(archives)
}
