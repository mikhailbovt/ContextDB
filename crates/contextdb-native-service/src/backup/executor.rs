//! Owned bounded execution of independently retained archive cleanup obligations.

use super::*;
use crate::{
    NativeBackupCleanupJob, NativeBackupCleanupJobProgress, NativeBackupCleanupJobReceipt,
    NativeBackupFrontier, NativeBackupRegistration, NativeRemovalRequestReceipt,
};
use contextdb_recall::QueryBudget;
use contextdb_service::AuthenticatedRequestContext;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod coverage;
mod paths;
mod plan;
#[cfg(test)]
mod tests;

/// Request-scoped logical work. These states never authorize physical disposal,
/// retiring keys or global removal admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeArchiveCleanupState {
    /// An exact completed job and authorized ancestry reach a readable clean input.
    Covered {
        /// Independently accepted terminal job anchoring this request's cleanup.
        job: NativeBackupCleanupJobReceipt,
        /// Exact source-to-clean-target ancestry, empty for the endpoint itself.
        path: NativeBackupPreservationPath,
        /// Exact ancestry from the job's clean result to the same readable target.
        /// Empty when the job itself produced the target; later edges carry its
        /// cleanup forward without claiming that the job inspected those outputs.
        clean_path: NativeBackupPreservationPath,
        /// Complete currently readable artifact at the enclosing frontier.
        artifact: crate::NativeBackupArtifactReceipt,
    },
    /// A new job can be admitted using the indicated input.
    Ready {
        /// Complete input, possibly from the last job on the same worker.
        input: NativeBackupRecoveryState,
    },
    /// Continue this fixed job on its registered worker.
    Running {
        /// Current accepted job state.
        job: NativeBackupCleanupJobReceipt,
        /// Exact required instance; missing storage cannot create a replacement.
        worker_instance: uuid::Uuid,
    },
    /// Unknown contents, unavailable keys or incomplete input bytes need recovery.
    AwaitingInput {
        /// Explicit current availability failure, not an empty successful scan.
        input: NativeBackupRecoveryState,
    },
    /// Local cleanup finished, but no proven clean artifact is currently readable.
    CompletedUnavailable {
        /// Historical terminal acceptance; this does not supply usable preservation.
        job: NativeBackupCleanupJobReceipt,
    },
    /// This original's worker has another unfinished request. Reassignment is forbidden.
    WorkerBusy,
    /// Reusing this original's worker requires a separately authorized workspace transfer.
    WorkerScopeRequired,
    /// The verified path exceeds the currently admitted 256-edge job input bound.
    AncestryLimit,
    /// An accepted input/output belongs to another original's existing worker.
    /// That owner must finish before this archive's final coverage can be assessed.
    WaitingForOwner {
        /// Issuance sequence of the owning original in the same inventory.
        original_sequence: u64,
    },
}

/// One issued archive, including unavailable originals and generated successors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArchiveCleanupEntry {
    /// Original exact issuance.
    pub original: NativeBackupRegistration,
    /// Verified current logical work or preservation, independent of local paths.
    pub state: NativeArchiveCleanupState,
}

/// Complete logical scheduling inventory at one custody frontier. Worker directory
/// availability is checked on advance; coverage does not certify other copy classes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArchiveCleanupInventory {
    /// Exact retained request authorizing inspection.
    pub request: NativeRemovalRequestReceipt,
    /// Freshness boundary; publication requires reinspection.
    pub frontier: NativeBackupFrontier,
    /// Every independently issued archive, including blocked work.
    pub archives: Vec<NativeArchiveCleanupEntry>,
}

/// One bounded accepted operation or an explicit missing-worker obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeArchiveCleanupAction {
    /// Reserved the verified input and worker; import occurs on a later advance.
    Started {
        /// Durable new or recovered job binding.
        job: Box<NativeBackupCleanupJob>,
    },
    /// Imported once or accepted one existing coordinator operation.
    Advanced {
        /// Exact job and resulting operation.
        result: Box<NativeBackupCleanupJobProgress>,
    },
    /// Known history exists but its native directory is missing; no new instance was created.
    AwaitingWorker {
        /// Original whose registered worker must be recovered.
        original: NativeBackupRegistration,
        /// Required native instance.
        worker_instance: uuid::Uuid,
    },
    /// This instance is permanently fenced. Its retained copies still exist and
    /// further work requires a separately verified replacement, not an empty path.
    WorkerSealed {
        /// Original whose worker can no longer accept work.
        original: NativeBackupRegistration,
        /// Independently retained publication fence.
        seal: crate::NativeBackupWorkerSeal,
    },
}

/// The inspected frontier precedes the action. Reinspect to assess new coverage;
/// no eligible action can also mean that every remaining archive is blocked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArchiveCleanupAdvance {
    /// Complete scheduling evidence used before this attempt.
    pub before: NativeArchiveCleanupInventory,
    /// Accepted work, missing-worker obligation, or no eligible action.
    pub action: Option<NativeArchiveCleanupAction>,
}

/// Host-owned archive executor with a stable directory per authority and original.
/// Keeps one worker open, advances round-robin and never disposes an instance.
/// Recreate the controller with the same root after restart. Paths are locators;
/// independently retained jobs and native-use records remain authoritative.
#[derive(Debug)]
pub struct NativeArchiveCleanup<'a> {
    owner: &'a NativeService,
    root: PathBuf,
    after: u64,
    worker: Option<(PathBuf, NativeService)>,
}

impl<'a> NativeArchiveCleanup<'a> {
    /// Configure execution without creating directories or touching storage.
    /// Supply an absolute root separate from the primary and both authorities.
    pub fn new(owner: &'a NativeService, worker_root: impl Into<PathBuf>) -> ServiceResult<Self> {
        let keys =
            owner.engine.keys.as_ref().ok_or_else(|| {
                crate::unsupported("archive execution requires encrypted custody")
            })?;
        keys.require_backup_contents()?;
        if owner.suppression.is_none() {
            return Err(crate::unsupported(
                "archive execution requires version 4 encrypted custody",
            ));
        }
        let root = worker_root.into();
        if !root.is_absolute()
            || root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(crate::invalid(
                "archive worker root must be an absolute path without parent traversal",
            ));
        }
        Ok(Self {
            owner,
            root,
            after: 0,
            worker: None,
        })
    }

    /// Inspect all issuance at a current frontier under Admin/exact request authority.
    /// Known clean successor aliases share coverage instead of creating more workers.
    pub fn inspect(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveCleanupInventory> {
        plan::inventory(self.owner, context, request, budget)
    }

    /// Select and advance one eligible archive, reusing its registered worker.
    /// A failed attempt advances the in-memory round-robin cursor so other eligible
    /// archives can proceed. Restart progress comes from jobs and native journals.
    /// Missing directories with accepted native history remain explicit obligations.
    pub fn advance(
        &mut self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveCleanupAdvance> {
        let before = self.inspect(context, request, budget)?;
        let eligible: Vec<_> = before
            .archives
            .iter()
            .filter(|archive| {
                matches!(
                    archive.state,
                    NativeArchiveCleanupState::Ready { .. }
                        | NativeArchiveCleanupState::Running { .. }
                )
            })
            .collect();
        let Some(selected) = eligible
            .iter()
            .find(|entry| entry.original.sequence > self.after)
            .or_else(|| eligible.first())
            .copied()
        else {
            return advance_response(before, None, budget);
        };
        let selected = selected.clone();
        self.after = selected.original.sequence;
        let keys = self
            .owner
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        // Do not hold custody publication while opening native storage: its own
        // registration/import path acquires the same queue and rechecks authority.
        drop(keys.lock_backup_frontier(&before.frontier, budget)?);
        let (catalog, _) = keys.selected_backup_keys_for_request(
            &BTreeMap::new(),
            &digest_bytes(context.request.workspace_id.as_bytes()),
            request,
            budget,
        )?;
        if catalog.frontier != before.frontier {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "archive schedule changed; repeat the advance",
                true,
            ));
        }
        let previous = catalog
            .jobs
            .iter()
            .rev()
            .find(|job| job.binding.original == selected.original);
        let instance = previous.map_or_else(
            || managed_instance(keys.authority_id(), &selected.original.archive_digest),
            |job| job.binding.worker_instance,
        );
        let state = keys.managed_instance_state(instance, budget)?;
        if state == crate::encryption::ManagedInstanceState::Sealed {
            return advance_response(
                before,
                Some(NativeArchiveCleanupAction::WorkerSealed {
                    original: selected.original,
                    seal: keys
                        .backup_worker_seal(instance, budget)?
                        .ok_or_else(|| integrity("sealed archive worker lost its receipt"))?,
                }),
                budget,
            );
        }
        let path = self.worker_path(&selected.original, budget)?;
        if !path.is_dir()
            && (previous.is_some() || state == crate::encryption::ManagedInstanceState::Active)
        {
            return advance_response(
                before,
                Some(NativeArchiveCleanupAction::AwaitingWorker {
                    original: selected.original,
                    worker_instance: instance,
                }),
                budget,
            );
        }
        self.require_worker_path(&path)?;
        if self
            .worker
            .as_ref()
            .is_none_or(|(opened, _)| *opened != path)
        {
            self.worker = None;
            let engine = crate::encryption::NativeStorage::open_managed_archive(
                &path,
                keys.clone(),
                instance,
                budget,
            )?;
            let worker = NativeService::finish_open(
                &path,
                self.owner.database_id.clone(),
                *self.owner.token_key,
                self.owner.suppression.clone(),
                engine,
            )?;
            self.worker = Some((path.clone(), worker));
        }
        let worker = &self
            .worker
            .as_ref()
            .ok_or_else(|| integrity("archive worker absent"))?
            .1;
        #[cfg(test)]
        BEFORE_MANAGED_JOB.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        let action = match selected.state {
            NativeArchiveCleanupState::Ready { .. } => NativeArchiveCleanupAction::Started {
                job: Box::new(worker.start_removal_backup_job(
                    context,
                    request,
                    &selected.original,
                    budget,
                )?),
            },
            NativeArchiveCleanupState::Running { job, .. } => {
                NativeArchiveCleanupAction::Advanced {
                    result: Box::new(
                        worker.advance_removal_backup_job(context, request, &job, budget)?,
                    ),
                }
            }
            _ => return Err(integrity("archive scheduling selected ineligible work")),
        };
        advance_response(before, Some(action), budget)
    }
}

fn advance_response(
    before: NativeArchiveCleanupInventory,
    action: Option<NativeArchiveCleanupAction>,
    budget: &mut QueryBudget,
) -> ServiceResult<NativeArchiveCleanupAdvance> {
    let result = NativeArchiveCleanupAdvance { before, action };
    crate::retention::keys::charge_report(&result, budget)?;
    Ok(result)
}

#[cfg(test)]
type ManagedJobHook = Box<dyn FnOnce() -> ServiceResult<()>>;
#[cfg(test)]
thread_local! {
    static BEFORE_MANAGED_JOB: std::cell::RefCell<Option<ManagedJobHook>> = const { std::cell::RefCell::new(None) };
}

fn managed_instance(authority: uuid::Uuid, archive: &str) -> uuid::Uuid {
    let mut hash = blake3::Hasher::new();
    hash.update(b"contextdb/managed-archive-worker/v1\0");
    hash.update(authority.as_bytes());
    hash.update(archive.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}
