use super::*;
use crate::capture::tests::request;
use crate::retention::keys::witness::tests::{Fixture, budget, fixture};
use crate::{CustodyMasterKey, NativeCustodyKeys, NativeSuppressionLedger};
use contextdb_service::{CapturePort, CognitiveMemoryService};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

#[derive(Debug)]
struct Authority {
    context: Mutex<AuthenticatedRequestContext>,
    calls: AtomicUsize,
}

impl NativeArchiveMaintenanceAuthority for Authority {
    fn context(
        &self,
        _: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AuthenticatedRequestContext> {
        budget.check().map_err(crate::raw_index::budget_error)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.context.lock().expect("test authority").clone())
    }
}

fn authority(f: &Fixture) -> Arc<Authority> {
    Arc::new(Authority {
        context: Mutex::new(f.input.context.clone()),
        calls: AtomicUsize::new(0),
    })
}

fn start(
    f: &Fixture,
    authority: Arc<dyn NativeArchiveMaintenanceAuthority>,
) -> NativeArchiveMaintenance {
    NativeArchiveMaintenance::start(
        f.native.clone(),
        f.root.path().join("workers"),
        vec![f.input.context.request.workspace_id.clone()],
        authority,
        NativeArchiveMaintenanceOptions {
            interval: Duration::from_millis(10),
            timeout: Duration::from_secs(30),
            work: 2_000_000,
            bytes: 512 * 1024 * 1024,
        },
    )
    .expect("host starts")
}

fn issued(f: &Fixture, retain: bool) -> BackupResponse {
    let backup = f
        .native
        .create_backup(CreateBackupRequest {
            context: f.input.context.clone(),
        })
        .expect("archive");
    if retain {
        assert!(
            f.native
                .retain_issued_backup(&f.input.context, &backup, 0, 16, &mut budget())
                .expect("bytes")
                .complete
        );
    }
    backup
}

fn wait(
    host: &NativeArchiveMaintenance,
    predicate: impl Fn(&NativeArchiveMaintenanceStatus) -> bool,
) -> NativeArchiveMaintenanceStatus {
    let deadline = Instant::now() + Duration::from_secs(55);
    let mut status = host.status().expect("status");
    loop {
        if predicate(&status) {
            return status;
        }
        assert!(
            status.running && Instant::now() < deadline,
            "maintenance did not reach expected evidence: {status:?}"
        );
        status = host
            .wait_for_change(status.ticks, Duration::from_millis(500))
            .expect("observe actual loop");
    }
}

fn is_covered(status: &NativeArchiveMaintenanceStatus, request: u64) -> bool {
    status.workspaces.values().any(|entry| matches!(&entry.outcome,
        NativeArchiveMaintenanceOutcome::Inspected { request_sequence, backlog, operation: None, .. }
        if *request_sequence == request && backlog.covered > 0 && backlog == &NativeArchiveMaintenanceBacklog { covered: backlog.covered, ..Default::default() }
    ))
}

fn cold(f: Fixture) -> Fixture {
    let key_id = f.keys.authority_id();
    let ledger_id = f.ledger.authority_id();
    drop((f.native, f.keys, f.ledger));
    let keys = NativeCustodyKeys::open(
        f.root.path().join("keys"),
        "primary-decisions",
        key_id,
        CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master"),
    )
    .expect("cold keys");
    let ledger =
        NativeSuppressionLedger::open(f.root.path().join("ledger"), "primary-decisions", ledger_id)
            .expect("cold ledger");
    let native = Arc::new(
        NativeService::open_encrypted(
            f.root.path().join("native"),
            "primary-decisions",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("cold native"),
    );
    Fixture {
        root: f.root,
        native,
        keys,
        ledger,
        input: f.input,
        removal: f.removal,
        witness: f.witness,
    }
}

#[test]
fn archive_maintenance_automatically_resumes_and_discovers_later_requests_on_the_same_worker() {
    let f = fixture();
    let original = issued(&f, true);
    let auth = authority(&f);
    let host = start(&f, auth.clone());
    let started = wait(&host, |status| {
        status.workspaces.values().any(|entry| {
            matches!(
                entry.outcome,
                NativeArchiveMaintenanceOutcome::Inspected {
                    operation: Some(NativeArchiveMaintenanceOperation::Started { .. }),
                    ..
                }
            )
        })
    });
    assert!(auth.calls.load(Ordering::SeqCst) as u64 >= started.ticks);
    assert!(!host.shutdown().expect("joined").running);
    drop(auth);
    let f = cold(f);
    let host = start(&f, authority(&f));
    wait(&host, |status| is_covered(status, f.removal.sequence));
    // No enqueue, per-request command, or foreground advance drives this host.
    let next = f
        .native
        .request_original_removal(
            &f.input.context,
            &BTreeSet::from([request(2, "").event.event_id]),
            "later-live-request",
            &mut budget(),
        )
        .expect("request while host runs");
    wait(&host, |status| is_covered(status, next.sequence));
    let older = wait(&host, |status| is_covered(status, f.removal.sequence));
    assert!(
        older
            .workspaces
            .values()
            .any(|entry| matches!(&entry.outcome,
        NativeArchiveMaintenanceOutcome::Inspected { backlog, .. } if backlog.covered == 3))
    );
    assert!(!host.shutdown().expect("joined after work").running);
    let f = cold(f);
    let (catalog, _) = f
        .keys
        .selected_backup_keys_for_request(
            &BTreeMap::new(),
            &digest_bytes(f.input.context.request.workspace_id.as_bytes()),
            &next,
            &mut budget(),
        )
        .expect("actual job journal");
    assert_eq!(catalog.jobs.len(), 2);
    assert!(catalog.jobs.iter().all(|job| job.terminal.is_some()));
    assert_eq!(
        catalog.jobs[0].binding.worker_instance,
        catalog.jobs[1].binding.worker_instance
    );
    let worker = NativeService::open_encrypted(
        f.root
            .path()
            .join("workers")
            .join(f.keys.authority_id().to_string())
            .join(original.digest),
        "primary-decisions",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("same actual worker");
    worker.verify_native(true).expect("final replay");
    let snapshot = worker
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("worker contents");
    for root in f.removal.roots.iter().chain(&next.roots) {
        assert!(
            snapshot
                .get(
                    &worker.keyspaces.observations_content,
                    digest_bytes(root.to_string().as_bytes()).as_bytes()
                )
                .expect("source body")
                .is_none()
        );
    }
}

#[test]
fn archive_maintenance_fresh_authority_and_missing_inputs_remain_explicit_while_capture_continues()
{
    let f = fixture();
    let original = issued(&f, false);
    let auth = authority(&f);
    auth.context.lock().expect("context").request.workspace_id = "wrong-workspace".into();
    let host = start(&f, auth.clone());
    wait(&host, |status| {
        status.workspaces.values().any(|entry| {
            matches!(
                entry.outcome,
                NativeArchiveMaintenanceOutcome::Failed {
                    code: ErrorCode::PermissionDenied,
                    ..
                }
            )
        })
    });
    assert!(!f.root.path().join("workers").exists());
    *auth.context.lock().expect("correct workspace") = f.input.context.clone();
    wait(&host, |status| {
        status.workspaces.values().any(|entry| matches!(&entry.outcome,
        NativeArchiveMaintenanceOutcome::Inspected { backlog, operation: None, .. } if backlog.awaiting_input == 1))
    });
    assert!(!f.root.path().join("workers").exists());
    auth.context
        .lock()
        .expect("revoke grant")
        .capability_grants
        .remove(&Capability::Admin);
    wait(&host, |status| {
        status.workspaces.values().any(|entry| {
            matches!(
                entry.outcome,
                NativeArchiveMaintenanceOutcome::Failed {
                    code: ErrorCode::Unauthorized,
                    ..
                }
            )
        })
    });
    f.native
        .append_event(request(3, "new capture during maintenance failure"))
        .expect("capture remains independent");
    assert!(
        f.native
            .retain_issued_backup(&f.input.context, &original, 0, 16, &mut budget())
            .expect("restore input availability")
            .complete
    );
    *auth.context.lock().expect("current host grant") = f.input.context.clone();
    wait(&host, |status| is_covered(status, f.removal.sequence));
    host.shutdown().expect("joined");
    f.native
        .verify_native(true)
        .expect("primary capture preserved");
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("primary");
    assert!(
        snapshot
            .get(
                &f.native.keyspaces.observations_content,
                digest_bytes(request(3, "").event.event_id.to_string().as_bytes()).as_bytes()
            )
            .expect("independent current capture")
            .is_some()
    );
}

#[derive(Debug)]
struct WaitingAuthority(std::sync::mpsc::SyncSender<()>);

impl NativeArchiveMaintenanceAuthority for WaitingAuthority {
    fn context(
        &self,
        _: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AuthenticatedRequestContext> {
        let _ = self.0.try_send(());
        loop {
            budget.check().map_err(crate::raw_index::budget_error)?;
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn archive_maintenance_shutdown_cancels_actual_background_authentication_without_blocking_capture()
{
    let f = fixture();
    issued(&f, true);
    let (entered, live) = std::sync::mpsc::sync_channel(1);
    let host = start(&f, Arc::new(WaitingAuthority(entered)));
    live.recv_timeout(Duration::from_secs(5))
        .expect("actual background call is live");
    f.native
        .append_event(request(3, "capture while background provider waits"))
        .expect("capture is not in the maintenance loop");
    let started = Instant::now();
    let status = host.shutdown().expect("cancelled and joined");
    assert!(!status.running);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(status.terminal_error, None);
    assert!(!f.root.path().join("workers").exists());
    assert!(status.workspaces.values().any(|entry| matches!(
        entry.outcome,
        NativeArchiveMaintenanceOutcome::Failed {
            code: ErrorCode::BudgetExhausted,
            ..
        }
    )));
    let sleeping = NativeArchiveMaintenance::start(
        f.native.clone(),
        f.root.path().join("workers"),
        vec![f.input.context.request.workspace_id.clone()],
        authority(&f),
        NativeArchiveMaintenanceOptions {
            interval: Duration::from_secs(3600),
            ..Default::default()
        },
    )
    .expect("long timer host");
    wait(&sleeping, |status| status.ticks > 0);
    let started = Instant::now();
    assert!(!sleeping.shutdown().expect("timer wake and join").running);
    assert!(started.elapsed() < Duration::from_secs(5));
}
