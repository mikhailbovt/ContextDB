use super::*;

pub(super) struct Completion(pub Arc<Shared>);

impl Drop for Completion {
    fn drop(&mut self) {
        let mut status = self
            .0
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.running = false;
        if std::thread::panicking() {
            status.terminal_error = Some(ErrorCode::Unavailable);
        }
        self.0.wake.notify_all();
    }
}

pub(super) fn run(
    owner: &NativeService,
    root: PathBuf,
    workspaces: &[String],
    authority: &dyn NativeArchiveMaintenanceAuthority,
    options: &NativeArchiveMaintenanceOptions,
    shared: &Shared,
) -> ServiceResult<()> {
    let mut executor = NativeArchiveCleanup::new(owner, root)?;
    let mut cursors = vec![0; workspaces.len()];
    let mut next = 0;
    while !shared.cancellation.is_cancelled() {
        let workspace = &workspaces[next];
        let mut budget = QueryBudget::new(
            options.work,
            options.bytes,
            options.timeout,
            shared.cancellation.clone(),
        );
        let outcome = match tick(
            owner,
            &mut executor,
            workspace,
            authority,
            &mut cursors[next],
            &mut budget,
        ) {
            Ok(outcome) => outcome,
            Err(error) => NativeArchiveMaintenanceOutcome::Failed {
                code: error.code,
                retryable: error.retryable,
            },
        };
        next = (next + 1) % workspaces.len();
        let mut status = shared.status.lock().map_err(|_| unavailable())?;
        status.ticks = status
            .ticks
            .checked_add(1)
            .ok_or_else(|| exhausted("maintenance tick overflow"))?;
        let tick = status.ticks;
        status.workspaces.insert(
            workspace.clone(),
            NativeArchiveMaintenanceObservation { tick, outcome },
        );
        shared.wake.notify_all();
        // The lock is released while sleeping. Capture never enters this mutex.
        let _wait = shared
            .wake
            .wait_timeout_while(status, options.interval, |_| {
                !shared.cancellation.is_cancelled()
            })
            .map_err(|_| unavailable())?;
    }
    Ok(())
}

fn tick(
    owner: &NativeService,
    executor: &mut NativeArchiveCleanup<'_>,
    workspace: &str,
    authority: &dyn NativeArchiveMaintenanceAuthority,
    after: &mut u64,
    budget: &mut QueryBudget,
) -> ServiceResult<NativeArchiveMaintenanceOutcome> {
    budget.check().map_err(crate::raw_index::budget_error)?;
    let context = authority.context(workspace, budget)?;
    budget.check().map_err(crate::raw_index::budget_error)?;
    if context.request.workspace_id != workspace {
        return Err(crate::permission_denied());
    }
    let catalog = owner.read_original_removal_requests(&context, budget)?;
    let Some(request) = catalog
        .requests
        .iter()
        .find(|request| request.sequence > *after)
        .or_else(|| catalog.requests.first())
    else {
        return Ok(NativeArchiveMaintenanceOutcome::NoRequests {
            sequence: catalog.sequence,
            digest: catalog.digest,
        });
    };
    // An unavailable request must not starve another accepted request or workspace.
    *after = request.sequence;
    let advanced = executor.advance(&context, request, budget)?;
    let mut backlog = NativeArchiveMaintenanceBacklog::default();
    for entry in &advanced.before.archives {
        match entry.state {
            NativeArchiveCleanupState::Covered { .. } => backlog.covered += 1,
            NativeArchiveCleanupState::Ready { .. } | NativeArchiveCleanupState::Running { .. } => {
                backlog.runnable += 1
            }
            NativeArchiveCleanupState::AwaitingInput { .. } => backlog.awaiting_input += 1,
            NativeArchiveCleanupState::CompletedUnavailable { .. } => backlog.unavailable += 1,
            NativeArchiveCleanupState::WorkerBusy => backlog.worker_busy += 1,
            NativeArchiveCleanupState::WorkerScopeRequired => backlog.worker_scope_required += 1,
            NativeArchiveCleanupState::AncestryLimit => backlog.ancestry_limit += 1,
            NativeArchiveCleanupState::WaitingForOwner { .. } => backlog.waiting_owner += 1,
        }
    }
    let operation = advanced.action.map(|action| match action {
        NativeArchiveCleanupAction::Started { job } => NativeArchiveMaintenanceOperation::Started {
            original_sequence: job.binding.original.sequence,
            worker_instance: job.binding.worker_instance,
        },
        NativeArchiveCleanupAction::Advanced { result } => {
            NativeArchiveMaintenanceOperation::Advanced {
                original_sequence: result.job.binding.original.sequence,
                worker_instance: result.job.binding.worker_instance,
                stage: result.progress.stage,
            }
        }
        NativeArchiveCleanupAction::AwaitingWorker {
            original,
            worker_instance,
        } => NativeArchiveMaintenanceOperation::AwaitingWorker {
            original_sequence: original.sequence,
            worker_instance,
        },
    });
    Ok(NativeArchiveMaintenanceOutcome::Inspected {
        requests: catalog.requests.len() as u64,
        sequence: catalog.sequence,
        digest: catalog.digest,
        request_sequence: request.sequence,
        archive_frontier: Box::new(advanced.before.frontier),
        backlog,
        operation,
    })
}
