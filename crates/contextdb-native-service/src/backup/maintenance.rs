//! Owned background host work; runtime/model contexts never supply its authority.

use super::*;
use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::AuthenticatedRequestContext;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    thread::JoinHandle,
    time::Duration,
};

#[cfg(test)]
mod tests;
mod worker;

/// Host authentication for one exact configured workspace on each tick.
/// Implementations must honor the cooperative budget/cancellation and obtain
/// current grants. No saved runtime context or model text can mint Admin here.
pub trait NativeArchiveMaintenanceAuthority: std::fmt::Debug + Send + Sync + 'static {
    /// Return current host authentication; the service checks Admin and workspace.
    fn context(
        &self,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AuthenticatedRequestContext>;
}

/// One administrative operation per tick, sharing these limits from authentication
/// through discovery and publication. This is cooperative work, not a hard OS timer.
#[derive(Clone, Debug)]
pub struct NativeArchiveMaintenanceOptions {
    /// Delay after each tick, including failures; ten milliseconds to one hour.
    pub interval: Duration,
    /// Fresh whole-tick deadline, at most sixty seconds.
    pub timeout: Duration,
    /// Maximum charged work per tick; must be nonzero.
    pub work: u64,
    /// Maximum charged bytes per tick; must be nonzero.
    pub bytes: u64,
}

impl Default for NativeArchiveMaintenanceOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(10),
            work: 2_000_000,
            bytes: 512 * 1024 * 1024,
        }
    }
}

/// Counts at the archive frontier before the attempted operation, for one request.
/// They are neither post-action coverage nor global removal completion.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArchiveMaintenanceBacklog {
    /// Readable cleanup coverage at inspection.
    pub covered: u64,
    /// Ready or running jobs eligible for this request.
    pub runnable: u64,
    /// Unknown membership, unavailable keys or missing complete bytes.
    pub awaiting_input: u64,
    /// Completed historical jobs without currently readable clean preservation.
    pub unavailable: u64,
    /// Workers occupied by another unfinished request.
    pub worker_busy: u64,
    /// Existing workers need a separately verified workspace reassignment.
    pub worker_scope_required: u64,
    /// Input ancestry exceeds the supported job bound.
    pub ancestry_limit: u64,
    /// Input/output aliases still depend on another original's owner.
    pub waiting_owner: u64,
}

/// Compact accepted work or a missing worker, without duplicating full inventories.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeArchiveMaintenanceOperation {
    /// A durable job was admitted or its start response recovered.
    Started {
        /// Exact original issuance.
        original_sequence: u64,
        /// Registered worker required after restart.
        worker_instance: uuid::Uuid,
    },
    /// One coordinator operation or accepted terminal response.
    Advanced {
        /// Exact original issuance.
        original_sequence: u64,
        /// Same registered worker.
        worker_instance: uuid::Uuid,
        /// Actual logical operation, never physical disposal.
        stage: NativeBackupCleanupStage,
    },
    /// The original worker directory must be recovered.
    AwaitingWorker {
        /// Exact original issuance.
        original_sequence: u64,
        /// Identity that cannot be replaced by an empty directory.
        worker_instance: uuid::Uuid,
    },
}

/// Latest bounded observation for a workspace. One request is inspected per tick;
/// these summaries cannot stand in for a complete multi-request deletion report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeArchiveMaintenanceOutcome {
    /// Configured but not yet inspected.
    Pending,
    /// No request existed at this independently verified journal frontier.
    NoRequests {
        /// Global removal journal position.
        sequence: u64,
        /// Exact journal commitment.
        digest: String,
    },
    /// An exact request was inspected and optionally advanced.
    Inspected {
        /// Number of requests discovered for this workspace.
        requests: u64,
        /// Global removal discovery position, preceding archive inspection.
        sequence: u64,
        /// Exact removal discovery commitment.
        digest: String,
        /// Exact selected request position in the retained removal authority.
        request_sequence: u64,
        /// Archive custody frontier before the operation.
        archive_frontier: Box<crate::NativeBackupFrontier>,
        /// Explicit remaining conditions at that frontier.
        backlog: NativeArchiveMaintenanceBacklog,
        /// Accepted operation or missing-worker obligation; absence can mean blocked.
        operation: Option<NativeArchiveMaintenanceOperation>,
    },
    /// Authentication, discovery or work failed. Earlier progress remains durable.
    /// Provider messages and credentials are never copied into shared status.
    Failed {
        /// Canonical failure code.
        code: ErrorCode,
        /// Whether the operation reported that an exact retry may succeed.
        retryable: bool,
    },
}

/// An observation's position in this process's host loop, not a durable receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArchiveMaintenanceObservation {
    /// Host tick that produced the observation; zero means not yet inspected.
    pub tick: u64,
    /// Actual success, explicit backlog or failure from this tick.
    pub outcome: NativeArchiveMaintenanceOutcome,
}

/// Bounded operational status for at most 64 configured workspaces. Not persisted:
/// native and independent journals, never this status, determine restart progress.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArchiveMaintenanceStatus {
    /// Completed host ticks in this process, including failed attempts.
    pub ticks: u64,
    /// Whether the owned thread is still running, including timer waits.
    pub running: bool,
    /// An unexpected terminal loop error; ordinary tick errors remain per workspace.
    pub terminal_error: Option<ErrorCode>,
    /// Latest observation per exact configured workspace.
    pub workspaces: BTreeMap<String, NativeArchiveMaintenanceObservation>,
}

struct Shared {
    status: Mutex<NativeArchiveMaintenanceStatus>,
    wake: Condvar,
    cancellation: QueryCancellation,
}

/// Explicitly enabled host service. It discovers retained requests itself and
/// owns a separate worker thread, so capture does not call this maintenance loop.
/// Keep one handle per worker root; reuse that root and both authorities on restart.
/// Dropping or shutting down joins cooperative work without deleting any storage.
pub struct NativeArchiveMaintenance {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for NativeArchiveMaintenance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeArchiveMaintenance")
            .finish_non_exhaustive()
    }
}

impl NativeArchiveMaintenance {
    /// Start one background host loop. Configuration alone supplies no grants;
    /// denied authentication appears in status and creates no worker directory.
    /// Unencrypted/legacy custody is rejected rather than silently downgraded.
    pub fn start(
        owner: Arc<NativeService>,
        root: impl Into<PathBuf>,
        workspaces: Vec<String>,
        authority: Arc<dyn NativeArchiveMaintenanceAuthority>,
        options: NativeArchiveMaintenanceOptions,
    ) -> ServiceResult<Self> {
        let root = root.into();
        NativeArchiveCleanup::new(&owner, &root)?;
        if workspaces.is_empty()
            || workspaces.len() > 64
            || workspaces.iter().collect::<BTreeSet<_>>().len() != workspaces.len()
            || options.interval < Duration::from_millis(10)
            || options.interval > Duration::from_secs(3600)
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(60)
            || options.work == 0
            || options.bytes == 0
        {
            return Err(crate::invalid(
                "archive maintenance configuration is outside its bounds",
            ));
        }
        for workspace in &workspaces {
            crate::validate_identifier(workspace, "maintenance workspace")?;
        }
        let shared = Arc::new(Shared {
            status: Mutex::new(NativeArchiveMaintenanceStatus {
                ticks: 0,
                running: true,
                terminal_error: None,
                workspaces: workspaces
                    .iter()
                    .map(|workspace| {
                        (
                            workspace.clone(),
                            NativeArchiveMaintenanceObservation {
                                tick: 0,
                                outcome: NativeArchiveMaintenanceOutcome::Pending,
                            },
                        )
                    })
                    .collect(),
            }),
            wake: Condvar::new(),
            cancellation: QueryCancellation::default(),
        });
        let state = shared.clone();
        let thread = std::thread::Builder::new()
            .name("contextdb-archive-maintenance".into())
            .spawn(move || {
                let _completion = worker::Completion(state.clone());
                if let Err(error) = worker::run(
                    &owner,
                    root,
                    &workspaces,
                    authority.as_ref(),
                    &options,
                    &state,
                ) && let Ok(mut status) = state.status.lock()
                {
                    status.terminal_error = Some(error.code);
                }
            })
            .map_err(|_| unavailable())?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    /// Read bounded operational evidence, without requesting or authorizing work.
    pub fn status(&self) -> ServiceResult<NativeArchiveMaintenanceStatus> {
        Ok(self
            .shared
            .status
            .lock()
            .map_err(|_| unavailable())?
            .clone())
    }

    /// Wait for a newer host tick or termination, at most sixty seconds. A timeout
    /// returns the same status and never starts another worker or another job.
    pub fn wait_for_change(
        &self,
        after_tick: u64,
        timeout: Duration,
    ) -> ServiceResult<NativeArchiveMaintenanceStatus> {
        if timeout > Duration::from_secs(60) {
            return Err(crate::invalid(
                "maintenance observation wait exceeds sixty seconds",
            ));
        }
        let status = self.shared.status.lock().map_err(|_| unavailable())?;
        let (status, _) = self
            .shared
            .wake
            .wait_timeout_while(status, timeout, |status| {
                status.running && status.ticks <= after_tick
            })
            .map_err(|_| unavailable())?;
        Ok(status.clone())
    }

    /// Cancel cooperative work and wake the timer. Call shutdown to join it.
    pub fn request_stop(&self) {
        self.shared.cancellation.cancel();
        // Pair notification with the waiter's mutex: cancellation between its
        // predicate check and parking must not lose the wakeup for a long timer.
        let _guard = self
            .shared
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.shared.wake.notify_all();
    }

    /// Stop and join the actual worker; all accepted jobs/directories are retained.
    pub fn shutdown(mut self) -> ServiceResult<NativeArchiveMaintenanceStatus> {
        self.request_stop();
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| unavailable())?;
        }
        self.status()
    }
}

impl Drop for NativeArchiveMaintenance {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn unavailable() -> ServiceError {
    ServiceError::new(
        ErrorCode::Unavailable,
        "archive maintenance worker unavailable",
        false,
    )
}
