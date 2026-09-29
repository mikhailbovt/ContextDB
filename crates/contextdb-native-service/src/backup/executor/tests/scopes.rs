use super::*;
use crate::{
    NativeArchiveMaintenance, NativeArchiveMaintenanceAuthority, NativeArchiveMaintenanceOptions,
    NativeArchiveMaintenanceOutcome, NativeArchiveMaintenanceStatus, NativeArchiveScopeResolver,
    NativeArchiveWorkerDisposalProgress, NativeRemovalKeySelection,
};
use contextdb_core::WorkspaceId;
use contextdb_service::{CaptureReceipt, CaptureRequest};
use std::{sync::Mutex, time::Duration, time::Instant};

#[derive(Debug)]
struct Authority {
    contexts: Mutex<BTreeMap<String, AuthenticatedRequestContext>>,
    calls: Mutex<Vec<String>>,
}

impl NativeArchiveMaintenanceAuthority for Authority {
    fn context(
        &self,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AuthenticatedRequestContext> {
        budget.check().map_err(crate::raw_index::budget_error)?;
        self.calls.lock().expect("calls").push(workspace.to_owned());
        self.contexts
            .lock()
            .expect("contexts")
            .get(workspace)
            .cloned()
            .ok_or_else(crate::permission_denied)
    }
}

fn scoped_capture(sequence: u64, workspace: u128, text: &str) -> CaptureRequest {
    let mut input = request(sequence, text);
    input.event.workspace_id =
        WorkspaceId::from_uuid(uuid::Uuid::from_u128(workspace)).expect("workspace");
    let mut context = crate::tests::authenticated(
        &format!("capture-{workspace}"),
        &input.event.workspace_id.to_string(),
        &format!("owner-{workspace}"),
        [
            Capability::Observe,
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::Admin,
        ],
    );
    context.request.scopes = input
        .event
        .scope_ids
        .iter()
        .map(ToString::to_string)
        .collect();
    input.context = context;
    input
}

fn scoped_fixture(
    archive_before_a: bool,
) -> (
    Fixture,
    CaptureRequest,
    CaptureRequest,
    CaptureReceipt,
    Option<NativeBackupRegistration>,
) {
    let root = tempfile::tempdir().expect("owned native fixture");
    let keys = NativeCustodyKeys::create(
        root.path().join("keys"),
        "primary-decisions",
        CustodyMasterKey::from_zeroizing(Zeroizing::new([83; 32])).expect("master"),
    )
    .expect("keys");
    let ledger = NativeSuppressionLedger::create(root.path().join("ledger"), "primary-decisions")
        .expect("ledger");
    let native = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            "primary-decisions",
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("native"),
    );
    let input = scoped_capture(1, 1, "selected original A");
    let b = scoped_capture(2, 11, "selected original B");
    let c = scoped_capture(3, 21, "  independent C\r\nТочная цитата: 7319\0\t");
    native.append_event(b.clone()).expect("capture B");
    let c_receipt = native.append_event(c.clone()).expect("capture C");
    let early_archive = archive_before_a.then(|| {
        let backup = native
            .create_backup(CreateBackupRequest {
                context: input.context.clone(),
            })
            .expect("archive contains B and C before A capture");
        let retained = native
            .retain_issued_backup(&input.context, &backup, 0, 16, &mut budget())
            .expect("retained early archive");
        assert!(retained.complete);
        retained.contents.registration
    });
    native.append_event(input.clone()).expect("capture A");
    let removal = native
        .request_original_removal(
            &input.context,
            &BTreeSet::from([input.event.event_id]),
            "remove-A",
            &mut budget(),
        )
        .expect("A retained request");
    let witness = native
        .retain_original_key_removal(&input.context, &removal, &mut budget())
        .expect("A witness");
    (
        Fixture {
            root,
            native,
            keys,
            ledger,
            input,
            removal,
            witness,
        },
        b,
        c,
        c_receipt,
        early_archive,
    )
}

fn authority(f: &Fixture, b: &CaptureRequest) -> Arc<Authority> {
    Arc::new(Authority {
        contexts: Mutex::new(BTreeMap::from([
            (
                f.input.context.request.workspace_id.clone(),
                f.input.context.clone(),
            ),
            (b.context.request.workspace_id.clone(), b.context.clone()),
        ])),
        calls: Mutex::new(Vec::new()),
    })
}

fn configured(f: &Fixture, b: &CaptureRequest) -> Vec<String> {
    vec![
        f.input.context.request.workspace_id.clone(),
        b.context.request.workspace_id.clone(),
    ]
}

fn rows(service: &NativeService, input: &CaptureRequest) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual native view");
    (
        snapshot
            .get(
                &service.keyspaces.observations_content,
                digest_bytes(input.event.event_id.to_string().as_bytes()).as_bytes(),
            )
            .expect("original body"),
        snapshot
            .get(
                &service.keyspaces.continuous,
                format!("receipt/{}", input.event.event_id).as_bytes(),
            )
            .expect("capture record"),
    )
}

fn assert_c(
    service: &NativeService,
    c: &CaptureRequest,
    receipt: &CaptureReceipt,
    expected: &(Option<Vec<u8>>, Option<Vec<u8>>),
) {
    assert!(expected.0.is_some() && expected.1.is_some());
    assert_eq!(&rows(service, c), expected);
    let snapshot = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("actual native view");
    let original = service
        .load_captured_original(&snapshot, c.event.event_id)
        .expect("full original and retained receipt");
    assert_eq!(original.event, c.event);
    assert_eq!(&original.receipt, receipt);
}

fn latest(f: &Fixture, original: &NativeBackupRegistration) -> NativeBackupCleanupJob {
    f.keys
        .selected_backup_keys(&BTreeMap::new(), &mut budget())
        .expect("complete custody replay")
        .jobs
        .into_iter()
        .rev()
        .find(|job| job.binding.original == *original)
        .expect("latest exact original job")
}

fn finish_scoped(
    executor: &mut NativeArchiveCleanup<'_>,
    workspace: &str,
    request: &NativeRemovalRequestReceipt,
    resolver: &NativeArchiveScopeResolver<'_>,
) -> NativeArchiveCleanupInventory {
    for _ in 0..96 {
        let step = executor
            .advance_with_scope_authority(workspace, request, resolver, &mut budget())
            .expect("fresh host-authorized native advance");
        if step.action.is_none() {
            assert!(
                step.before
                    .archives
                    .iter()
                    .all(|entry| matches!(entry.state, NativeArchiveCleanupState::Covered { .. })),
                "{step:?}"
            );
            return step.before;
        }
        assert!(!matches!(
            step.action,
            Some(NativeArchiveCleanupAction::AwaitingWorker { .. })
        ));
    }
    panic!("cross-workspace native archive did not settle");
}

fn remove_primary(
    f: &Fixture,
    context: &AuthenticatedRequestContext,
    request: &NativeRemovalRequestReceipt,
) {
    f.native
        .prepare_original_removal_sources(context, request, &request.roots, &mut budget())
        .expect("prepare exact primary roots");
    f.native
        .maintain_custody(context, 256, &mut budget())
        .expect("acknowledge current primary state");
    f.native
        .prune_original_sources(context, request, &request.roots, &mut budget())
        .expect("prune selected primary");
}

fn assert_scope_blocked(step: &NativeArchiveCleanupAdvance, original: &NativeBackupRegistration) {
    assert!(step.action.is_none(), "{step:?}");
    assert!(matches!(
        step.before
            .archives
            .iter()
            .find(|entry| entry.original == *original)
            .expect("blocked original")
            .state,
        NativeArchiveCleanupState::WorkerScopeRequired
    ));
}

#[test]
fn archive_scopes_resume_exact_input_and_retire_disposed_dependencies_preserving_c() {
    let (f, b, c, c_receipt, _) = scoped_fixture(false);
    let a_workspace = f.input.context.request.workspace_id.clone();
    let b_workspace = b.context.request.workspace_id.clone();
    let permitted = rows(&f.native, &c);
    let original = issued(&f, true);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    let first = latest(&f, &original);
    let next = f
        .native
        .request_original_removal(
            &b.context,
            &BTreeSet::from([b.event.event_id]),
            "remove-B",
            &mut budget(),
        )
        .expect("B retained request");
    assert_ne!(
        first.binding.workspace_digest,
        digest_bytes(b_workspace.as_bytes())
    );
    let auth = authority(&f, &b);
    let workspaces = configured(&f, &b);
    let resolver =
        NativeArchiveScopeResolver::new(&workspaces, auth.as_ref()).expect("host scopes");
    let single = executor
        .inspect(&b.context, &next, &mut budget())
        .expect("single scope plan");
    assert!(matches!(
        single
            .archives
            .iter()
            .find(|entry| entry.original == original)
            .expect("original")
            .state,
        NativeArchiveCleanupState::WorkerScopeRequired
    ));
    assert!(
        executor
            .advance(&b.context, &next, &mut budget())
            .expect("single context refusal")
            .action
            .is_none()
    );

    let use_before = f
        .keys
        .native_use_catalog_page(None, 1, &mut budget())
        .expect("frontier")
        .revision;
    auth.contexts
        .lock()
        .expect("revoke A")
        .get_mut(&a_workspace)
        .expect("A")
        .capability_grants
        .remove(&Capability::Admin);
    assert_scope_blocked(
        &executor
            .advance_with_scope_authority(&b_workspace, &next, &resolver, &mut budget())
            .expect("foreign Admin revoked before worker action"),
        &original,
    );
    assert_eq!(
        executor
            .worker
            .as_ref()
            .expect("original A worker")
            .1
            .start_removal_backup_job_with_scope_authority(
                &b_workspace,
                &next,
                &original,
                &resolver,
                &mut budget()
            )
            .expect_err("strict admission still requires foreign A grant")
            .code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        f.keys
            .native_use_catalog_page(None, 1, &mut budget())
            .expect("unchanged use")
            .revision,
        use_before
    );
    assert_eq!(
        std::fs::read_dir(root.join(f.keys.authority_id().to_string()))
            .expect("generations")
            .count(),
        1
    );
    auth.contexts
        .lock()
        .expect("restore A")
        .insert(a_workspace.clone(), f.input.context.clone());
    auth.contexts
        .lock()
        .expect("wrong callback workspace")
        .insert(a_workspace.clone(), b.context.clone());
    assert_eq!(
        executor
            .worker
            .as_ref()
            .expect("unchanged A worker")
            .1
            .start_removal_backup_job_with_scope_authority(
                &b_workspace,
                &next,
                &original,
                &resolver,
                &mut budget()
            )
            .expect_err("A lookup returned authenticated B")
            .code,
        ErrorCode::PermissionDenied
    );
    auth.contexts
        .lock()
        .expect("correct A")
        .insert(a_workspace.clone(), f.input.context.clone());
    let mut substituted = next.clone();
    substituted.roots = f.removal.roots.clone();
    assert!(
        executor
            .advance_with_scope_authority(&b_workspace, &substituted, &resolver, &mut budget())
            .is_err()
    );
    assert_eq!(
        f.keys
            .native_use_catalog_page(None, 1, &mut budget())
            .expect("no failed publication")
            .revision,
        use_before
    );

    crate::encryption::AFTER_SEAL_SYNC.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|| {
            Err(integrity("lost cross-scope seal acknowledgement"))
        }))
    });
    assert!(
        executor
            .advance_with_scope_authority(&b_workspace, &next, &resolver, &mut budget())
            .is_err()
    );
    let seal = f
        .keys
        .backup_worker_seal(first.binding.worker_instance, &mut budget())
        .expect("accepted exact seal")
        .expect("retained despite lost acknowledgement");
    assert_eq!(seal.job, first.receipt);
    drop(executor);
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    let Some(NativeArchiveCleanupAction::Started { job: start }) = executor
        .advance_with_scope_authority(&b_workspace, &next, &resolver, &mut budget())
        .expect("recover seal and admit pristine B")
        .action
    else {
        panic!("B must start once")
    };
    assert_eq!(start.binding.worker_seal, Some(seal.clone()));
    assert_eq!(
        start.binding.worker_instance,
        managed_replacement_instance(&seal)
    );
    assert!(start.binding.scope_continuation.is_some());
    let (source, path, artifact) = first.next_source().expect("exact A result");
    assert_eq!(start.binding.source, source);
    assert_eq!(start.binding.source_path, path);
    assert_eq!(start.binding.source_artifact, artifact);
    let pristine_head = executor
        .worker
        .as_ref()
        .expect("B generation")
        .1
        .engine
        .head_sequence()
        .expect("physical head");
    assert_eq!(start.binding.restore_at, Some(pristine_head));
    auth.contexts
        .lock()
        .expect("revoke A on resume")
        .get_mut(&a_workspace)
        .expect("A")
        .capability_grants
        .remove(&Capability::Admin);
    assert_eq!(
        executor
            .worker
            .as_ref()
            .expect("same B generation")
            .1
            .advance_removal_backup_job_with_scope_authority(
                &b_workspace,
                &next,
                &start.receipt,
                &resolver,
                &mut budget()
            )
            .expect_err("saved binding cannot authenticate A during import")
            .code,
        ErrorCode::Unauthorized
    );
    assert_eq!(
        executor
            .worker
            .as_ref()
            .expect("same B generation")
            .1
            .engine
            .head_sequence()
            .expect("no import"),
        pristine_head
    );
    assert!(!latest(&f, &original).initialized);
    auth.contexts
        .lock()
        .expect("regrant A")
        .insert(a_workspace.clone(), f.input.context.clone());
    let imported = executor
        .advance_with_scope_authority(&b_workspace, &next, &resolver, &mut budget())
        .expect("one exact import");
    assert!(
        matches!(imported.action, Some(NativeArchiveCleanupAction::Advanced { result })
        if result.progress.stage == NativeBackupCleanupStage::Restored && result.job.initialized)
    );
    assert_eq!(
        executor
            .worker
            .as_ref()
            .expect("B generation")
            .1
            .engine
            .head_sequence()
            .expect("one physical import"),
        pristine_head + 1
    );
    drop(executor);
    let f = cold(f);
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold import retry");
    let retry = executor
        .advance_with_scope_authority(&b_workspace, &next, &resolver, &mut budget())
        .expect("lost import response resumes without reimport");
    assert!(
        !matches!(retry.action, Some(NativeArchiveCleanupAction::Advanced { result })
        if result.progress.stage == NativeBackupCleanupStage::Restored)
    );
    finish_scoped(&mut executor, &b_workspace, &next, &resolver);
    let second = latest(&f, &original);
    let worker = &executor.worker.as_ref().expect("actual B worker").1;
    assert!(rows(worker, &f.input).0.is_none());
    assert!(rows(worker, &b).0.is_none());
    assert_c(worker, &c, &c_receipt, &permitted);
    worker
        .verify_native(true)
        .expect("actual mixed native replay");
    assert_eq!(
        f.keys
            .selected_backup_keys(&BTreeMap::new(), &mut budget())
            .expect("jobs")
            .jobs
            .len(),
        2
    );
    assert_eq!(
        std::fs::read_dir(root.join(f.keys.authority_id().to_string()))
            .expect("generations")
            .count(),
        2
    );

    remove_primary(&f, &f.input.context, &f.removal);
    remove_primary(&f, &b.context, &next);
    let selected: BTreeSet<_> = f
        .native
        .read_original_key_inventory(&b.context, &next, &mut budget())
        .expect("B key ownership")
        .sources
        .into_values()
        .flatten()
        .map(|allocation| allocation.key_id)
        .collect();
    let retire_b = || {
        f.native.retire_removal_keys_with_scope_authority(
            &b_workspace,
            &next,
            &NativeRemovalKeySelection::Originals,
            &selected,
            &resolver,
            &mut budget(),
        )
    };
    assert!(
        retire_b().is_err(),
        "A seal retains B's current managed-copy dependency"
    );
    let before = f
        .native
        .read_original_key_inventory(&b.context, &next, &mut budget())
        .expect("B tracked native copies")
        .native_use
        .expect("v4 tracking");
    assert!(before.disposed_workers.is_empty());
    assert_eq!(before.managed_disposition_version, Some(1));
    assert!(
        before
            .addresses
            .values()
            .any(|address| address.acknowledged.contains_key(&seal.worker_instance))
    );
    let intent = executor
        .dispose_worker_with_scope_authority(
            &a_workspace,
            &f.removal,
            &first.receipt,
            &resolver,
            1,
            &mut budget(),
        )
        .expect("cross-scope disposal intent");
    let NativeArchiveWorkerDisposalProgress::Prepared { disposal } = intent else {
        panic!("intent before unlink")
    };
    assert_eq!(
        disposal.binding.preservation_artifact,
        second.next_source().expect("B clean target").2
    );
    assert!(
        retire_b().is_err(),
        "pending disposal still preserves its current dependency and keys"
    );
    let mut disposed = false;
    for _ in 0..32 {
        if matches!(
            executor
                .dispose_worker_with_scope_authority(
                    &a_workspace,
                    &f.removal,
                    &first.receipt,
                    &resolver,
                    16,
                    &mut budget()
                )
                .expect("bounded controlled disposal"),
            NativeArchiveWorkerDisposalProgress::DirectoryAbsent { .. }
        ) {
            disposed = true;
            break;
        }
    }
    assert!(disposed);
    let after = f
        .native
        .read_original_key_inventory(&b.context, &next, &mut budget())
        .expect("verified disposed obligation")
        .native_use
        .expect("v4 tracking");
    assert_eq!(
        after.addresses, before.addresses,
        "historical acknowledgements survive disposal"
    );
    assert_eq!(after.managed_disposition_version, Some(1));
    assert_eq!(
        after.disposed_workers[&seal.worker_instance].binding.seal,
        seal
    );
    let refused_b = retire_b().expect("completed verified disposal permits B key refusal");
    assert_eq!(
        refused_b
            .keys
            .iter()
            .map(|allocation| allocation.key_id)
            .collect::<BTreeSet<_>>(),
        selected
    );
    let selected_a: BTreeSet<_> = f
        .native
        .read_original_key_inventory(&f.input.context, &f.removal, &mut budget())
        .expect("A key ownership")
        .sources
        .into_values()
        .flatten()
        .map(|allocation| allocation.key_id)
        .collect();
    f.native
        .retire_removal_keys_with_scope_authority(
            &a_workspace,
            &f.removal,
            &NativeRemovalKeySelection::Originals,
            &selected_a,
            &resolver,
            &mut budget(),
        )
        .expect("A current key refusal through B preservation");
    assert_c(&f.native, &c, &c_receipt, &permitted);
    assert_c(
        &executor.worker.as_ref().expect("B survives disposal").1,
        &c,
        &c_receipt,
        &permitted,
    );
    drop(executor);
    let f = cold(f);
    let executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold final controller");
    let (target, _, artifact) = second.next_source().expect("latest retained clean result");
    for (workspace, request, anchor) in [
        (&a_workspace, &f.removal, &first),
        (&b_workspace, &next, &second),
    ] {
        let report = executor
            .inspect_with_scope_authority(workspace, request, &resolver, &mut budget())
            .expect("cold coverage with original selected keys refused");
        assert!(
            report
                .archives
                .iter()
                .all(|entry| matches!(entry.state, NativeArchiveCleanupState::Covered { .. })),
            "{report:?}"
        );
        let endpoint = report
            .archives
            .iter()
            .find(|entry| entry.original == target.registration)
            .expect("latest endpoint");
        let NativeArchiveCleanupState::Covered {
            job,
            clean_path,
            artifact: readable,
            ..
        } = &endpoint.state
        else {
            panic!("covered endpoint")
        };
        assert_eq!(job, &anchor.receipt);
        assert_eq!(readable, &artifact);
        assert_eq!(
            clean_path.replacements.len(),
            usize::from(workspace == &a_workspace)
        );
        let input = f
            .native
            .read_removal_backup_input_with_scope_authority(
                workspace,
                request,
                &original,
                &resolver,
                &mut budget(),
            )
            .expect("actual latest bytes remain readable");
        assert_eq!(input.target, target);
        assert_eq!(input.artifact, artifact);
        assert_eq!(input.replacements.len(), 2);
    }
    f.native
        .verify_native(true)
        .expect("cold primary and independent C after refusal");
    let calls = auth.calls.lock().expect("fresh calls");
    assert!(
        calls
            .iter()
            .filter(|workspace| *workspace == &a_workspace)
            .count()
            > 8
    );
    assert!(
        calls
            .iter()
            .filter(|workspace| *workspace == &b_workspace)
            .count()
            > 8
    );
    assert!(
        calls
            .iter()
            .all(|workspace| workspace == &a_workspace || workspace == &b_workspace)
    );
    assert_eq!(
        auth.contexts
            .lock()
            .expect("unmodified independent grants")
            .get(&a_workspace),
        Some(&f.input.context)
    );
    assert_eq!(
        auth.contexts
            .lock()
            .expect("unmodified independent grants")
            .get(&b_workspace),
        Some(&b.context)
    );
}

fn covered(status: &NativeArchiveMaintenanceStatus, workspace: &str, request: u64) -> bool {
    status.workspaces.get(workspace).is_some_and(|entry| matches!(&entry.outcome,
        NativeArchiveMaintenanceOutcome::Inspected { request_sequence, backlog, operation: None, .. }
        if *request_sequence == request && backlog.covered > 0
            && backlog.runnable == 0 && backlog.awaiting_input == 0 && backlog.unavailable == 0
            && backlog.worker_busy == 0 && backlog.worker_scope_required == 0
            && backlog.ancestry_limit == 0 && backlog.waiting_owner == 0))
}

fn wait_covered(host: &NativeArchiveMaintenance, workspace: &str, request: u64) {
    let deadline = Instant::now() + Duration::from_secs(55);
    let mut status = host.status().expect("actual owned loop status");
    while !covered(&status, workspace, request) {
        assert!(
            status.running && Instant::now() < deadline,
            "owned mixed-scope maintenance stalled: {status:?}"
        );
        status = host
            .wait_for_change(status.ticks, Duration::from_millis(500))
            .expect("owned loop progress");
    }
}

#[test]
fn archive_scopes_owned_background_discovers_b_seals_a_and_preserves_independent_c() {
    let (f, b, c, c_receipt, _) = scoped_fixture(false);
    let permitted = rows(&f.native, &c);
    let original = issued(&f, true);
    let auth = authority(&f, &b);
    let workspaces = configured(&f, &b);
    let root = f.root.path().join("workers");
    let start = |f: &Fixture| {
        NativeArchiveMaintenance::start(
            f.native.clone(),
            &root,
            workspaces.clone(),
            auth.clone(),
            NativeArchiveMaintenanceOptions {
                interval: Duration::from_millis(10),
                timeout: Duration::from_secs(30),
                work: 2_000_000,
                bytes: 512 * 1024 * 1024,
            },
        )
        .expect("actual host starts")
    };
    let host = start(&f);
    wait_covered(&host, &workspaces[0], f.removal.sequence);
    host.shutdown().expect("joined A worker");
    let first = latest(&f, &original);
    let next = f
        .native
        .request_original_removal(
            &b.context,
            &BTreeSet::from([b.event.event_id]),
            "background-remove-B",
            &mut budget(),
        )
        .expect("retained B request without enqueue");
    let f = cold(f);
    let host = start(&f);
    wait_covered(&host, &workspaces[1], next.sequence);
    wait_covered(&host, &workspaces[0], f.removal.sequence);
    host.shutdown()
        .expect("joined after automatic cross-scope work");
    let f = cold(f);
    let second = latest(&f, &original);
    let seal = second
        .binding
        .worker_seal
        .as_ref()
        .expect("host automatically sealed predecessor");
    assert_eq!(seal.worker_instance, first.binding.worker_instance);
    assert_eq!(seal.job, first.receipt);
    assert_eq!(
        second.binding.worker_instance,
        managed_replacement_instance(seal)
    );
    assert_ne!(
        second.binding.worker_instance,
        first.binding.worker_instance
    );
    assert_eq!(
        f.keys
            .selected_backup_keys(&BTreeMap::new(), &mut budget())
            .expect("cold job journal")
            .jobs
            .len(),
        2
    );
    let path = root.join(original.authority_id.to_string()).join(format!(
        "{}.{}",
        original.archive_digest, second.binding.worker_instance
    ));
    let worker = NativeService::open_encrypted(
        path,
        "primary-decisions",
        [7; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("actual automatically continued generation");
    assert!(rows(&worker, &f.input).0.is_none());
    assert!(rows(&worker, &b).0.is_none());
    assert_c(&worker, &c, &c_receipt, &permitted);
    worker
        .verify_native(true)
        .expect("full cold replay of actual background result");
    assert_eq!(
        std::fs::read_dir(
            worker_path(&root, &original)
                .parent()
                .expect("worker namespace")
        )
        .expect("two generations")
        .count(),
        2
    );
    assert!(
        auth.calls
            .lock()
            .expect("fresh scope calls")
            .iter()
            .all(|workspace| workspaces.contains(workspace))
    );
}

#[test]
fn archive_scopes_unchanged_predecessor_cannot_bypass_foreign_authority_with_empty_path() {
    let (f, b, c, c_receipt, early) = scoped_fixture(true);
    let original = early.expect("archive predates selected A");
    let permitted = rows(&f.native, &c);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    let first = latest(&f, &original);
    assert_eq!(
        first.terminal.as_ref().expect("A terminal").stage,
        NativeBackupCleanupStage::Unchanged
    );
    assert!(first.next_source().expect("unchanged input").1.is_empty());
    let next = f
        .native
        .request_original_removal(
            &b.context,
            &BTreeSet::from([b.event.event_id]),
            "B-after-unchanged-A",
            &mut budget(),
        )
        .expect("B retained request");
    let a_workspace = f.input.context.request.workspace_id.clone();
    let b_workspace = b.context.request.workspace_id.clone();
    let auth = authority(&f, &b);
    let workspaces = configured(&f, &b);
    let resolver =
        NativeArchiveScopeResolver::new(&workspaces, auth.as_ref()).expect("host scopes");
    assert!(matches!(
        executor
            .advance_with_scope_authority(&b_workspace, &next, &resolver, &mut budget())
            .expect("automatic A seal")
            .action,
        Some(NativeArchiveCleanupAction::WorkerSealed { .. })
    ));
    let Some(NativeArchiveCleanupAction::Started { job }) = executor
        .advance_with_scope_authority(&b_workspace, &next, &resolver, &mut budget())
        .expect("mixed B start")
        .action
    else {
        panic!("B start")
    };
    assert!(job.binding.source_path.is_empty());
    let provenance = job
        .binding
        .scope_continuation
        .as_ref()
        .expect("scope bound without path edges");
    assert_eq!(provenance.previous_job, Some(first.receipt.clone()));
    assert_eq!(
        provenance
            .requests
            .iter()
            .map(|scope| (scope.workspace_digest.clone(), scope.request.clone()))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([
            (digest_bytes(a_workspace.as_bytes()), f.removal.clone()),
            (digest_bytes(b_workspace.as_bytes()), next.clone()),
        ])
    );
    let worker = &executor.worker.as_ref().expect("pristine B generation").1;
    let before = worker.engine.head_sequence().expect("physical head");
    assert_eq!(
        worker
            .advance_removal_backup_job(&b.context, &next, &job.receipt, &mut budget())
            .expect_err("empty ancestry cannot remove immutable A requirement")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert_eq!(
        worker
            .start_removal_backup_job(&b.context, &next, &original, &mut budget())
            .expect_err("old API cannot recover mixed start without A")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert_eq!(worker.engine.head_sequence().expect("no import"), before);
    auth.contexts
        .lock()
        .expect("revoke A")
        .get_mut(&a_workspace)
        .expect("A")
        .capability_grants
        .remove(&Capability::Admin);
    assert_eq!(
        worker
            .advance_removal_backup_job_with_scope_authority(
                &b_workspace,
                &next,
                &job.receipt,
                &resolver,
                &mut budget()
            )
            .expect_err("fresh A still required despite zero edges")
            .code,
        ErrorCode::Unauthorized
    );
    auth.contexts
        .lock()
        .expect("regrant A")
        .insert(a_workspace.clone(), f.input.context.clone());
    finish_scoped(&mut executor, &b_workspace, &next, &resolver);
    let terminal = latest(&f, &original);
    let worker = &executor.worker.as_ref().expect("actual completed B").1;
    assert_eq!(
        worker
            .advance_removal_backup_job(&b.context, &next, &job.receipt, &mut budget())
            .expect_err("historical terminal response is still scoped")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert_eq!(
        worker
            .seal_removal_backup_worker(&b.context, &next, &terminal.receipt, &mut budget())
            .expect_err("old seal API cannot bypass retained A provenance")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert!(
        f.keys
            .backup_worker_seal(terminal.binding.worker_instance, &mut budget())
            .expect("no seal")
            .is_none()
    );
    assert_c(worker, &c, &c_receipt, &permitted);
    worker
        .seal_removal_backup_worker_with_scope_authority(
            &b_workspace,
            &next,
            &terminal.receipt,
            &resolver,
            &mut budget(),
        )
        .expect("fresh scoped seal of mixed result");
    assert_eq!(
        executor
            .dispose_worker(&b.context, &next, &terminal.receipt, 1, &mut budget())
            .expect_err("old disposal API cannot bypass A with empty original input path")
            .code,
        ErrorCode::EvidenceRequired
    );
    assert!(
        f.keys
            .backup_worker_disposal(terminal.binding.worker_instance, &mut budget())
            .expect("no disposal intent")
            .is_none()
    );
    assert!(matches!(
        executor
            .dispose_worker_with_scope_authority(
                &b_workspace,
                &next,
                &terminal.receipt,
                &resolver,
                1,
                &mut budget()
            )
            .expect("fresh host scopes admit controlled disposal intent"),
        NativeArchiveWorkerDisposalProgress::Prepared { .. }
    ));
}

#[test]
fn archive_scopes_revoked_foreign_branch_does_not_starve_an_independent_native_archive() {
    let (f, b, c, c_receipt, _) = scoped_fixture(false);
    let permitted = rows(&f.native, &c);
    let first_original = issued(&f, true);
    let root = f.root.path().join("workers");
    let mut executor = NativeArchiveCleanup::new(&f.native, &root).expect("controller");
    finish(&f, &mut executor, &f.removal);
    let first = latest(&f, &first_original);
    f.native
        .append_event(scoped_capture(4, 21, "independent later C capture"))
        .expect("new unrelated primary archive branch");
    let independent = issued(&f, true);
    assert_ne!(independent.archive_digest, first_original.archive_digest);
    let next = f
        .native
        .request_original_removal(
            &b.context,
            &BTreeSet::from([b.event.event_id]),
            "B-independent-branch",
            &mut budget(),
        )
        .expect("B retained request");
    let workspaces = configured(&f, &b);
    let auth = authority(&f, &b);
    auth.contexts
        .lock()
        .expect("deny A")
        .get_mut(&workspaces[0])
        .expect("A")
        .capability_grants
        .remove(&Capability::Admin);
    let resolver =
        NativeArchiveScopeResolver::new(&workspaces, auth.as_ref()).expect("host scopes");
    let mut terminal = None;
    for iteration in 0..64 {
        let step = executor
            .advance_with_scope_authority(&workspaces[1], &next, &resolver, &mut budget())
            .unwrap_or_else(|error| panic!("independent B step {iteration} failed: {error:?}"));
        assert!(matches!(
            step.before
                .archives
                .iter()
                .find(|entry| entry.original == first_original)
                .expect("first original stays blocked")
                .state,
            NativeArchiveCleanupState::WorkerScopeRequired
        ));
        match step.action {
            Some(NativeArchiveCleanupAction::Started { job }) => {
                assert_eq!(job.binding.original, independent)
            }
            Some(NativeArchiveCleanupAction::Advanced { result }) => {
                assert_eq!(result.job.binding.original, independent);
                if result.job.terminal.is_some() {
                    terminal = Some(result.job);
                    break;
                }
            }
            other => panic!("independent branch should remain runnable: {other:?}"),
        }
    }
    let terminal = terminal.expect("actual independent B cleanup finished");
    assert!(terminal.binding.scope_continuation.is_none());
    assert!(
        f.keys
            .backup_worker_seal(first.binding.worker_instance, &mut budget())
            .expect("foreign generation unchanged")
            .is_none()
    );
    assert_eq!(
        f.keys
            .selected_backup_keys(&BTreeMap::new(), &mut budget())
            .expect("only actual owners")
            .jobs
            .len(),
        2
    );
    let worker = &executor
        .worker
        .as_ref()
        .expect("independent actual B worker")
        .1;
    assert!(rows(worker, &b).0.is_none());
    assert_c(worker, &c, &c_receipt, &permitted);
    worker
        .verify_native(true)
        .expect("independent full native replay");
    drop(executor);
    let f = cold(f);
    let executor = NativeArchiveCleanup::new(&f.native, &root).expect("cold controller");
    let report = executor
        .inspect_with_scope_authority(&workspaces[1], &next, &resolver, &mut budget())
        .expect("cold mixed report keeps denied branch explicit");
    assert!(matches!(
        report
            .archives
            .iter()
            .find(|entry| entry.original == first_original)
            .expect("denied branch")
            .state,
        NativeArchiveCleanupState::WorkerScopeRequired
    ));
    assert!(matches!(
        report
            .archives
            .iter()
            .find(|entry| entry.original == independent)
            .expect("independent branch")
            .state,
        NativeArchiveCleanupState::Covered { .. }
    ));
    let clean = terminal
        .next_source()
        .expect("accepted independent result")
        .0;
    let input = f
        .native
        .read_removal_backup_input_with_scope_authority(
            &workspaces[1],
            &next,
            &clean.registration,
            &resolver,
            &mut budget(),
        )
        .expect("strict independent input does not acquire unrelated A grant");
    assert_eq!(input.target, clean);
}
