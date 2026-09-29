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
mod disposal;
pub use disposal::NativeArchiveWorkerDisposalProgress;
pub(crate) use disposal::VerifiedWorkerDisposal;
mod paths;
mod plan;
#[cfg(test)]
mod scheduling;
#[cfg(test)]
pub(crate) mod tests;

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
    /// Continued an already accepted disposal intent; no new intent is inferred.
    DisposalAdvanced {
        /// Original whose sealed generation is being disposed.
        original: NativeBackupRegistration,
        /// Actual exclusion, bounded unlink or namespace-absence observation.
        progress: Box<NativeArchiveWorkerDisposalProgress>,
    },
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

/// Host-owned archive executor with stable directories per original and generation.
/// Keeps one worker open and advances round-robin. Explicit disposal intent is
/// required before advance can resume bounded removal of a sealed generation.
/// Recreate the controller with the same root after restart. Paths are locators;
/// independently retained jobs and native-use records remain authoritative.
#[derive(Debug)]
pub struct NativeArchiveCleanup<'a> {
    owner: &'a NativeService,
    root: PathBuf,
    // Entries require actual eligible work and leave when that request is idle.
    // Exhaustion is explicit; evicting an active cursor would restore starvation.
    schedules: BTreeMap<(uuid::Uuid, u64), RequestSchedule>,
    worker: Option<(PathBuf, NativeService)>,
}

#[derive(Debug, Default)]
struct RequestSchedule {
    archive_after: u64,
    disposal_after: u64,
    prefer_archive: bool,
}

// Each entry contains a fixed-size key and three scalars, never an inventory.
const MAX_REQUEST_SCHEDULES: usize = 65_536;

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
            schedules: BTreeMap::new(),
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

    /// Inspect mixed-workspace ancestry using only fresh host authentication.
    pub fn inspect_with_scope_authority(
        &self,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        resolver: &NativeArchiveScopeResolver<'_>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveCleanupInventory> {
        let scopes = self
            .owner
            .archive_available_scope_frame(resolver, workspace, request, budget)?;
        let context = scopes.context_for(&digest_bytes(workspace.as_bytes()), request)?;
        plan::inventory_authorized(self.owner, context, request, Some(&scopes), budget)
    }

    /// Select one eligible archive or resume one already accepted disposal intent.
    /// Alternate these classes within each request when both have work. Neither a
    /// seal nor logical coverage creates intent; resumed disposal removes at most 16 entries.
    /// A failed attempt advances the in-memory round-robin cursor so other eligible
    /// archives can proceed. Restart progress comes from jobs and native journals.
    /// Missing directories with accepted native history remain explicit obligations.
    /// Up to 65,536 active request cursors are retained; reaching that limit fails
    /// explicitly. Advancing an idle request releases its cursor without eviction.
    pub fn advance(
        &mut self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveCleanupAdvance> {
        self.advance_authorized(context, request, None, budget)
    }

    /// Continue one host-authorized archive across workspace requests. A change
    /// seals the actual completed worker before admitting a pristine successor.
    pub fn advance_with_scope_authority(
        &mut self,
        workspace: &str,
        request: &NativeRemovalRequestReceipt,
        resolver: &NativeArchiveScopeResolver<'_>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveCleanupAdvance> {
        let scopes = self
            .owner
            .archive_available_scope_frame(resolver, workspace, request, budget)?;
        let context = scopes.context_for(&digest_bytes(workspace.as_bytes()), request)?;
        self.advance_authorized(context, request, Some((resolver, &scopes)), budget)
    }

    fn advance_authorized(
        &mut self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        scoped: Option<(
            &NativeArchiveScopeResolver<'_>,
            &scopes::VerifiedArchiveScopes,
        )>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeArchiveCleanupAdvance> {
        let before = plan::inventory_authorized(
            self.owner,
            context,
            request,
            scoped.map(|(_, scopes)| scopes),
            budget,
        )?;
        // inspect authenticated the exact retained request; sequence is unique
        // within its authority and its retained binding already covers workspace.
        let request_key = (request.authority_id, request.sequence);
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
        let pending = self.pending_worker_disposals(context, request, budget)?;
        if eligible.is_empty() && pending.is_empty() {
            self.schedules.remove(&request_key);
            return advance_response(before, None, budget);
        }
        if !self.schedules.contains_key(&request_key)
            && self.schedules.len() >= MAX_REQUEST_SCHEDULES
        {
            return Err(exhausted(
                "archive execution exceeds 65,536 active request cursors",
            ));
        }
        let schedule = self.schedules.entry(request_key).or_default();
        if !pending.is_empty() && (!schedule.prefer_archive || eligible.is_empty()) {
            let action = self.resume_worker_disposal(
                context,
                request,
                pending,
                scoped.map(|(resolver, _)| resolver),
                budget,
            )?;
            return advance_response(before, Some(action), budget);
        }
        let Some(selected) = eligible
            .iter()
            .find(|entry| entry.original.sequence > schedule.archive_after)
            .or_else(|| eligible.first())
            .copied()
        else {
            return Err(integrity("archive scheduling lost its eligible work"));
        };
        let selected = selected.clone();
        schedule.prefer_archive = false;
        schedule.archive_after = selected.original.sequence;
        let keys = self
            .owner
            .engine
            .keys
            .as_ref()
            .ok_or_else(|| integrity("archive custody absent"))?;
        // Do not hold custody publication while opening native storage: its own
        // registration/import path acquires the same queue and rechecks authority.
        drop(keys.lock_backup_frontier(&before.frontier, budget)?);
        let (catalog, _) = if scoped.is_some() {
            keys.selected_backup_keys_for_authority(&BTreeMap::new(), request, budget)?
        } else {
            keys.selected_backup_keys_for_request(
                &BTreeMap::new(),
                &digest_bytes(context.request.workspace_id.as_bytes()),
                request,
                budget,
            )?
        };
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
        let mut instance = previous.map_or_else(
            || managed_instance(keys.authority_id(), &selected.original.archive_digest),
            |job| job.binding.worker_instance,
        );
        let mut state = keys.managed_instance_state(instance, budget)?;
        if let Some((_, scopes)) = scoped {
            scopes.require_frontier(self.owner, budget)?;
        }
        // A mixed-scope transfer cannot relabel a live worker. Open and seal its
        // exact terminal bytes under the predecessor's freshly verified grants.
        if let (Some(previous), Some((resolver, scopes))) = (previous, scoped)
            && previous.binding.workspace_digest
                != digest_bytes(context.request.workspace_id.as_bytes())
            && state != crate::encryption::ManagedInstanceState::Sealed
        {
            let prior_context = scopes.context_for(
                &previous.binding.workspace_digest,
                &previous.binding.request,
            )?;
            let generation = catalog
                .jobs
                .iter()
                .any(|job| {
                    job.binding.worker_instance == instance && job.binding.worker_seal.is_some()
                })
                .then_some(instance);
            let path = self.worker_path(&selected.original, generation, budget)?;
            if !path.is_dir() {
                return advance_response(
                    before,
                    Some(NativeArchiveCleanupAction::AwaitingWorker {
                        original: selected.original,
                        worker_instance: instance,
                    }),
                    budget,
                );
            }
            self.open_worker(&path, instance, budget)?;
            let worker = &self
                .worker
                .as_ref()
                .ok_or_else(|| integrity("archive worker absent"))?
                .1;
            let seal = worker.seal_removal_backup_worker_with_scope_authority(
                &prior_context.request.workspace_id,
                &previous.binding.request,
                &previous.receipt,
                resolver,
                budget,
            )?;
            self.worker = None;
            return advance_response(
                before,
                Some(NativeArchiveCleanupAction::WorkerSealed {
                    original: selected.original,
                    seal,
                }),
                budget,
            );
        }
        let mut replacement = false;
        if let Some(previous) = previous
            && state == crate::encryption::ManagedInstanceState::Sealed
            && matches!(selected.state, NativeArchiveCleanupState::Ready { .. })
        {
            let seal = keys
                .backup_worker_seal(instance, budget)?
                .ok_or_else(|| integrity("sealed archive worker lost its receipt"))?;
            if seal.job != previous.receipt {
                return Err(integrity(
                    "archive replacement requires the latest sealed job",
                ));
            }
            instance = managed_replacement_instance(&seal);
            state = keys.managed_instance_state(instance, budget)?;
            replacement = true;
        }
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
        let bound = catalog
            .jobs
            .iter()
            .any(|job| job.binding.worker_instance == instance);
        let generation = (replacement
            || catalog.jobs.iter().any(|job| {
                job.binding.worker_instance == instance && job.binding.worker_seal.is_some()
            }))
        .then_some(instance);
        let path = self.worker_path(&selected.original, generation, budget)?;
        if !path.is_dir() && (bound || state == crate::encryption::ManagedInstanceState::Active) {
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
        self.open_worker(&path, instance, budget)?;
        let worker = &self
            .worker
            .as_ref()
            .ok_or_else(|| integrity("archive worker absent"))?
            .1;
        #[cfg(test)]
        BEFORE_MANAGED_JOB.with(|hook| hook.take().map_or(Ok(()), |hook| hook()))?;
        let action = match selected.state {
            NativeArchiveCleanupState::Ready { .. } => NativeArchiveCleanupAction::Started {
                job: Box::new(if let Some((resolver, _)) = scoped {
                    worker.start_removal_backup_job_with_scope_authority(
                        &context.request.workspace_id,
                        request,
                        &selected.original,
                        resolver,
                        budget,
                    )?
                } else {
                    worker.start_removal_backup_job(context, request, &selected.original, budget)?
                }),
            },
            NativeArchiveCleanupState::Running { job, .. } => {
                NativeArchiveCleanupAction::Advanced {
                    result: Box::new(if let Some((resolver, _)) = scoped {
                        worker.advance_removal_backup_job_with_scope_authority(
                            &context.request.workspace_id,
                            request,
                            &job,
                            resolver,
                            budget,
                        )?
                    } else {
                        worker.advance_removal_backup_job(context, request, &job, budget)?
                    }),
                }
            }
            _ => return Err(integrity("archive scheduling selected ineligible work")),
        };
        advance_response(before, Some(action), budget)
    }

    fn open_worker(
        &mut self,
        path: &Path,
        instance: uuid::Uuid,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.require_worker_path(path)?;
        if self
            .worker
            .as_ref()
            .is_none_or(|(opened, _)| opened != path)
        {
            self.worker = None;
            let keys = self
                .owner
                .engine
                .keys
                .as_ref()
                .ok_or_else(|| integrity("archive custody absent"))?;
            let engine = crate::encryption::NativeStorage::open_managed_archive(
                path,
                keys.clone(),
                instance,
                budget,
            )?;
            let worker = NativeService::finish_open(
                path,
                self.owner.database_id.clone(),
                *self.owner.token_key,
                self.owner.suppression.clone(),
                engine,
            )?;
            self.worker = Some((path.to_path_buf(), worker));
        }
        Ok(())
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

fn managed_replacement_instance(seal: &crate::NativeBackupWorkerSeal) -> uuid::Uuid {
    let mut hash = blake3::Hasher::new();
    hash.update(b"contextdb/managed-archive-replacement/v1\0");
    hash.update(seal.authority_id.as_bytes());
    hash.update(seal.digest.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}
