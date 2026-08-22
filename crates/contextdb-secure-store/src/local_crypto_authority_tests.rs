//! Real local-crypto authority, recovery, and suppression tests.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, RwLock};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::test_support::InMemoryHeadMacAuthorityV2;
use crate::*;

const CHILD_PHASE: &str = "CONTEXTDB_LOCAL_CRYPTO_CHILD_PHASE";
const CHILD_DATABASE: &str = "CONTEXTDB_LOCAL_CRYPTO_CHILD_DATABASE";
const PROCESS_KILL_PLAINTEXT: &[u8] =
    b"contextdb-local-process-kill-plaintext-sentinel-6da66345261f";
const LIFECYCLE_SENTINEL: &str = "contextdb-local-lifecycle-plaintext-sentinel-341d72902d67";

fn root(label: &str) -> StateRootV2 {
    StateRootV2::commit("local-crypto-test", label.as_bytes()).expect("state root")
}

fn namespace() -> StateNamespaceV2 {
    StateNamespaceV2::new("local-authority", "db", "ws", "primary").expect("namespace")
}

fn context(owner: &str) -> ContentSecurityContextV2 {
    ContentSecurityContextV2::new("db", "ws", "memory.lifecycle", owner, root("policy"), 1)
        .expect("content context")
}

fn managed(label: &str) -> ManagedCopyCatalogCommitmentsV2 {
    ManagedCopyCatalogCommitmentsV2::try_new(vec![
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::ProviderCopy,
            1,
            root(&format!("provider-{label}")),
        )
        .expect("provider"),
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::Export,
            1,
            root(&format!("export-{label}")),
        )
        .expect("export"),
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::Backup,
            1,
            root(&format!("backup-{label}")),
        )
        .expect("backup"),
    ])
    .expect("managed commitments")
}

fn lifecycle(subject: &str) -> LifecyclePayloadV1 {
    LifecyclePayloadV1::new(
        LifecycleContentClassV1::ToolObservation,
        "ws",
        LIFECYCLE_SENTINEL,
        subject,
        vec!["owner".to_owned(), "workspace-members".to_owned()],
        vec!["memory.read".to_owned(), "memory.write".to_owned()],
        "default-profile",
        Some("contextdb-test-tool".to_owned()),
        vec![
            LifecycleProvenanceV1::new(
                "test-tool",
                "opaque-test-reference",
                Some("run-1".to_owned()),
            )
            .expect("provenance"),
        ],
    )
    .expect("lifecycle")
}

fn request(label: &str) -> LocalObjectSealRequestV1 {
    let subject = format!("subject-{label}");
    LocalObjectSealRequestV1::from_durable_intent(
        DurableObjectCreateIntentV2::preallocate(namespace(), context(&subject), managed(label))
            .expect("durable intent"),
        lifecycle(&subject),
    )
    .expect("local request")
}

fn master() -> LocalMasterKeyV1 {
    LocalMasterKeyV1::from_zeroizing(Zeroizing::new([0x5a; 32]))
}

fn open_authority(
    path: &Path,
    expected_anchor: Option<&LocalAuthorityAnchorV1>,
) -> RedbLocalCryptoAuthorityV1 {
    RedbLocalCryptoAuthorityV1::open(path, namespace(), master(), expected_anchor)
        .expect("open local authority")
}

struct StaticOverlay {
    decision: LiveSuppressionDecisionV2,
    calls: AtomicUsize,
}

impl LiveSuppressionOverlayV2 for StaticOverlay {
    fn check_content(
        &self,
        _namespace: &StateNamespaceV2,
        _overlay_root: &StateRootV2,
        _content_handle: &ContentHandleV2,
    ) -> Result<LiveSuppressionDecisionV2> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.decision)
    }
}

struct TestOpenEpochState {
    publication_head_commitment: StateRootV2,
    suppressed: bool,
}

struct TestOpenEpoch {
    state: RwLock<TestOpenEpochState>,
    entered: Option<Arc<Barrier>>,
    release: Option<Arc<Barrier>>,
}

impl TestOpenEpoch {
    fn current(head: &CompositeStateHeadV2) -> Self {
        Self {
            state: RwLock::new(TestOpenEpochState {
                publication_head_commitment: head.commitment().expect("head commitment"),
                suppressed: false,
            }),
            entered: None,
            release: None,
        }
    }

    fn blocking(head: &CompositeStateHeadV2, entered: Arc<Barrier>, release: Arc<Barrier>) -> Self {
        Self {
            state: RwLock::new(TestOpenEpochState {
                publication_head_commitment: head.commitment().expect("head commitment"),
                suppressed: false,
            }),
            entered: Some(entered),
            release: Some(release),
        }
    }

    fn publish(&self, head: &CompositeStateHeadV2, suppressed: bool) {
        let mut state = self.state.write().expect("epoch write lock");
        state.publication_head_commitment = head.commitment().expect("head commitment");
        state.suppressed = suppressed;
    }
}

impl LocalOpenAuthorizationEpochV1 for TestOpenEpoch {
    fn with_current_authorization(
        &self,
        observed_namespace: &StateNamespaceV2,
        publication_head_commitment: &StateRootV2,
        _content_handle: &ContentHandleV2,
        open: &mut dyn FnMut() -> Result<()>,
    ) -> Result<LiveSuppressionDecisionV2> {
        if observed_namespace != &namespace() {
            return Err(SecureStoreError::Integrity(
                "test epoch namespace mismatch".to_owned(),
            ));
        }
        let state = self.state.read().map_err(|_| {
            SecureStoreError::StateConflict("test epoch lock is poisoned".to_owned())
        })?;
        if &state.publication_head_commitment != publication_head_commitment {
            return Err(SecureStoreError::StateConflict(
                "permit publication epoch is no longer current".to_owned(),
            ));
        }
        if state.suppressed {
            return Ok(LiveSuppressionDecisionV2::Suppressed);
        }
        if let Some(entered) = &self.entered {
            entered.wait();
        }
        if let Some(release) = &self.release {
            release.wait();
        }
        open()?;
        Ok(LiveSuppressionDecisionV2::Allow)
    }
}

struct ForgedAllowEpoch;

impl LocalOpenAuthorizationEpochV1 for ForgedAllowEpoch {
    fn with_current_authorization(
        &self,
        _namespace: &StateNamespaceV2,
        _publication_head_commitment: &StateRootV2,
        _content_handle: &ContentHandleV2,
        _open: &mut dyn FnMut() -> Result<()>,
    ) -> Result<LiveSuppressionDecisionV2> {
        Ok(LiveSuppressionDecisionV2::Allow)
    }
}

fn head(
    authority: &RedbLocalCryptoAuthorityV1,
    mac: &InMemoryHeadMacAuthorityV2,
    suppression: SuppressionBindingV2,
) -> CompositeStateHeadV2 {
    let workflow_root = match &suppression {
        SuppressionBindingV2::Clear => root("clear-workflow"),
        SuppressionBindingV2::Pending { overlay_root, .. }
        | SuppressionBindingV2::Enforced { overlay_root } => overlay_root.clone(),
    };
    CompositeStateHeadV2::initial(
        namespace(),
        CompositeHeadPayloadV2 {
            projection_root: root("projection"),
            policy_root: root("policy"),
            key_catalog_root: authority.current_catalog_root().expect("catalog root"),
            deletion_workflow_root: workflow_root,
            suppression,
        },
        mac,
    )
    .expect("composite head")
}

#[test]
fn lifecycle_payload_rejects_hidden_reasoning_and_unknown_fields() {
    assert!(
        LifecyclePayloadV1::new(
            LifecycleContentClassV1::ModelHiddenReasoning,
            "ws",
            "agent",
            "subject",
            vec!["owner".to_owned()],
            vec!["memory.read".to_owned()],
            "profile",
            None,
            vec![LifecycleProvenanceV1::new("model", "ref", None).expect("provenance")],
        )
        .is_err()
    );
    let valid = lifecycle("subject");
    let mut json = serde_json::to_value(&valid).expect("lifecycle JSON");
    json.as_object_mut().expect("object").insert(
        "hidden_reasoning".to_owned(),
        serde_json::json!("forbidden"),
    );
    assert!(
        LifecyclePayloadV1::from_json_bounded(
            &serde_json::to_vec(&json).expect("malformed lifecycle JSON")
        )
        .is_err()
    );
    let debug = format!("{valid:?}");
    assert!(!debug.contains(LIFECYCLE_SENTINEL));
    assert!(!debug.contains("opaque-test-reference"));
}

#[test]
fn create_reopen_and_retry_are_exact_without_plaintext_staging() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("local.redb");
    let request = request("reopen");
    let plaintext = b"durable local encrypted memory";
    let authority = open_authority(&path, None);
    let initial = authority.current_anchor().expect("initial anchor");
    let first = authority
        .create_and_seal_or_get(&request, plaintext)
        .expect("create");
    assert!(matches!(first, LocalCreateOutcomeV1::Applied(_)));
    let final_anchor = authority.current_anchor().expect("final anchor");
    assert!(final_anchor.generation() >= initial.generation() + 2);
    let report = authority.deep_verify(None).expect("verify");
    assert_eq!(report.object_count(), 1);
    assert_eq!(report.staged_source_count(), 0);
    drop(authority);

    let authority = open_authority(&path, Some(&final_anchor));
    let replay = authority
        .create_and_seal_or_get(&request, plaintext)
        .expect("replay");
    assert!(matches!(replay, LocalCreateOutcomeV1::AlreadyApplied(_)));
    assert!(
        authority
            .create_and_seal_or_get(&request, b"substituted plaintext")
            .is_err()
    );
    let mut changed_payload = serde_json::to_value(&request).expect("request JSON");
    changed_payload["lifecycle"]["profile_id"] = serde_json::json!("changed-profile");
    let changed_payload = LocalObjectSealRequestV1::from_json_bounded(
        &serde_json::to_vec(&changed_payload).expect("changed payload JSON"),
    )
    .expect("changed payload request");
    assert!(
        authority
            .create_and_seal_or_get(&changed_payload, plaintext)
            .is_err()
    );
    let mut changed_scope = serde_json::to_value(&request).expect("request JSON");
    changed_scope["intent"]["security_context"]["record_kind"] =
        serde_json::json!("memory.changed-scope");
    let changed_scope = LocalObjectSealRequestV1::from_json_bounded(
        &serde_json::to_vec(&changed_scope).expect("changed scope JSON"),
    )
    .expect("changed scope request");
    assert!(
        authority
            .create_and_seal_or_get(&changed_scope, plaintext)
            .is_err()
    );
    let description = authority
        .describe_strongly_consistent(
            replay.object().initial_key().key_handle(),
            replay.object().initial_key().scope(),
            1,
        )
        .expect("describe");
    assert_eq!(description.descriptor(), replay.object().initial_key());

    let authority_debug = format!("{authority:?}");
    drop(authority);
    let bytes = std::fs::read(&path).expect("database bytes");
    assert!(
        !bytes
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );
    assert!(
        !bytes
            .windows(LIFECYCLE_SENTINEL.len())
            .any(|window| window == LIFECYCLE_SENTINEL.as_bytes()),
        "lifecycle metadata reached redb in plaintext"
    );
    assert!(
        !bytes.windows(32).any(|window| window == [0x5a; 32]),
        "master key bytes reached redb"
    );
    assert!(!authority_debug.contains("5a5a5a5a"));
    assert!(!format!("{master:?}", master = master()).contains("5a5a5a5a"));
}

#[test]
fn suppression_precedes_open_and_destroy_revokes_existing_permit() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("suppression.redb");
    let request = request("suppression");
    let plaintext = b"suppression-gated local plaintext";
    let authority = open_authority(&path, None);
    let object = authority
        .create_and_seal_or_get(&request, plaintext)
        .expect("create")
        .object()
        .clone();
    let mac = InMemoryHeadMacAuthorityV2::random("local-suppression-mac").expect("MAC");
    let overlay_root = root("overlay");
    let pending_overlay = StaticOverlay {
        decision: LiveSuppressionDecisionV2::Allow,
        calls: AtomicUsize::new(0),
    };
    let pending = head(
        &authority,
        &mac,
        SuppressionBindingV2::Pending {
            overlay_root: overlay_root.clone(),
            pending_workflow_count: 1,
        },
    );
    assert!(
        authority
            .authorize_open_after_suppression(
                &pending,
                object.content_handle(),
                request.intent().security_context(),
                &mac,
                &pending_overlay,
            )
            .is_err()
    );
    assert_eq!(pending_overlay.calls.load(Ordering::SeqCst), 0);

    let suppressing_overlay = StaticOverlay {
        decision: LiveSuppressionDecisionV2::Suppressed,
        calls: AtomicUsize::new(0),
    };
    let enforced = head(
        &authority,
        &mac,
        SuppressionBindingV2::Enforced {
            overlay_root: overlay_root.clone(),
        },
    );
    assert!(matches!(
        authority
            .authorize_open_after_suppression(
                &enforced,
                object.content_handle(),
                request.intent().security_context(),
                &mac,
                &suppressing_overlay,
            )
            .expect("suppressed authorization"),
        LocalOpenAuthorizationV1::Suppressed
    ));
    assert_eq!(suppressing_overlay.calls.load(Ordering::SeqCst), 1);

    let divergent_head = CompositeStateHeadV2::initial(
        namespace(),
        CompositeHeadPayloadV2 {
            projection_root: root("projection"),
            policy_root: root("policy"),
            key_catalog_root: root("foreign-catalog"),
            deletion_workflow_root: overlay_root.clone(),
            suppression: SuppressionBindingV2::Enforced {
                overlay_root: overlay_root.clone(),
            },
        },
        &mac,
    )
    .expect("divergent head");
    assert!(
        authority
            .authorize_open_after_suppression(
                &divergent_head,
                object.content_handle(),
                request.intent().security_context(),
                &mac,
                &StaticOverlay {
                    decision: LiveSuppressionDecisionV2::Allow,
                    calls: AtomicUsize::new(0),
                },
            )
            .is_err()
    );

    let allowing_overlay = StaticOverlay {
        decision: LiveSuppressionDecisionV2::Allow,
        calls: AtomicUsize::new(0),
    };
    let authorization = authority
        .authorize_open_after_suppression(
            &enforced,
            object.content_handle(),
            request.intent().security_context(),
            &mac,
            &allowing_overlay,
        )
        .expect("allowed authorization");
    let LocalOpenAuthorizationV1::Permitted(permit) = authorization else {
        panic!("expected permit");
    };
    let second_permit = match authority
        .authorize_open_after_suppression(
            &enforced,
            object.content_handle(),
            request.intent().security_context(),
            &mac,
            &allowing_overlay,
        )
        .expect("second authorization")
    {
        LocalOpenAuthorizationV1::Permitted(value) => value,
        _ => panic!("expected second permit"),
    };
    let restart_permit = match authority
        .authorize_open_after_suppression(
            &enforced,
            object.content_handle(),
            request.intent().security_context(),
            &mac,
            &allowing_overlay,
        )
        .expect("restart permit authorization")
    {
        LocalOpenAuthorizationV1::Permitted(value) => value,
        _ => panic!("expected restart permit"),
    };
    let forged_epoch_permit = match authority
        .authorize_open_after_suppression(
            &enforced,
            object.content_handle(),
            request.intent().security_context(),
            &mac,
            &allowing_overlay,
        )
        .expect("forged-epoch permit authorization")
    {
        LocalOpenAuthorizationV1::Permitted(value) => value,
        _ => panic!("expected forged-epoch permit"),
    };
    assert!(
        authority
            .open_with_permit(*forged_epoch_permit, &ForgedAllowEpoch)
            .is_err(),
        "an epoch authority cannot claim allow without running the bound open"
    );
    let open_epoch = TestOpenEpoch::current(&enforced);
    assert_eq!(
        authority
            .open_with_permit(*second_permit, &open_epoch)
            .expect("open")
            .plaintext(),
        Some(plaintext.as_slice())
    );
    let destroy = LocalDestroyRequestV1::new(
        OperationRequestIdV2::generate().expect("destroy request ID"),
        namespace(),
        object.initial_key().clone(),
    )
    .expect("destroy request");
    let outcome = authority.destroy(&destroy).expect("destroy");
    assert_eq!(
        outcome.receipt().descriptor().lifecycle(),
        KeyLifecycleV2::Destroyed
    );
    assert!(authority.open_with_permit(*permit, &open_epoch).is_err());
    assert!(matches!(
        authority.destroy(&destroy).expect("destroy replay"),
        LocalDestroyOutcomeV1::AlreadyApplied(_)
    ));
    assert!(
        authority
            .describe_strongly_consistent(
                object.initial_key().key_handle(),
                object.initial_key().scope(),
                3,
            )
            .is_ok()
    );
    let anchor = authority.current_anchor().expect("destroy anchor");
    drop(authority);
    let authority = open_authority(&path, Some(&anchor));
    assert!(
        authority
            .open_with_permit(*restart_permit, &open_epoch)
            .is_err()
    );
    assert!(
        authority
            .describe_strongly_consistent(
                object.initial_key().key_handle(),
                object.initial_key().scope(),
                3,
            )
            .is_ok()
    );
}

#[test]
fn permit_consumption_is_linearized_with_suppression_and_restart() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("suppression-linearization.redb");
    let request = request("suppression-linearization");
    let plaintext = b"linearized suppression plaintext";
    let authority = Arc::new(open_authority(&path, None));
    let object = authority
        .create_and_seal_or_get(&request, plaintext)
        .expect("create")
        .object()
        .clone();
    let mac = InMemoryHeadMacAuthorityV2::random("linearized-suppression-mac").expect("MAC");
    let allowed_root = root("linearized-allow-overlay");
    let allowed_head = head(
        &authority,
        &mac,
        SuppressionBindingV2::Enforced {
            overlay_root: allowed_root,
        },
    );
    let allowing_overlay = StaticOverlay {
        decision: LiveSuppressionDecisionV2::Allow,
        calls: AtomicUsize::new(0),
    };
    let issue_permit = || match authority
        .authorize_open_after_suppression(
            &allowed_head,
            object.content_handle(),
            request.intent().security_context(),
            &mac,
            &allowing_overlay,
        )
        .expect("issue pre-suppression permit")
    {
        LocalOpenAuthorizationV1::Permitted(permit) => *permit,
        LocalOpenAuthorizationV1::Missing | LocalOpenAuthorizationV1::Suppressed => {
            panic!("expected pre-suppression permit")
        }
    };
    let read_first_permit = issue_permit();
    let write_first_permit = issue_permit();
    let restart_permit = issue_permit();

    let suppressed_head = head(
        &authority,
        &mac,
        SuppressionBindingV2::Enforced {
            overlay_root: root("linearized-suppressed-overlay"),
        },
    );
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let epoch = Arc::new(TestOpenEpoch::blocking(
        &allowed_head,
        Arc::clone(&entered),
        Arc::clone(&release),
    ));

    let reader_authority = Arc::clone(&authority);
    let reader_epoch = Arc::clone(&epoch);
    let reader = std::thread::spawn(move || {
        reader_authority.open_with_permit(read_first_permit, reader_epoch.as_ref())
    });
    entered.wait();

    let writer_epoch = Arc::clone(&epoch);
    let (writer_started_tx, writer_started_rx) = mpsc::channel();
    let (writer_done_tx, writer_done_rx) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        writer_started_tx.send(()).expect("signal writer start");
        writer_epoch.publish(&suppressed_head, true);
        writer_done_tx.send(()).expect("signal writer completion");
    });
    writer_started_rx.recv().expect("writer started");
    assert!(
        writer_done_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "suppression committed while the read held its shared authorization lease"
    );

    release.wait();
    let read_first = reader.join().expect("reader thread").expect("read first");
    assert_eq!(read_first.plaintext(), Some(plaintext.as_slice()));
    writer_done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("suppression commits after read lease release");
    writer.join().expect("writer thread");

    assert!(
        authority
            .open_with_permit(write_first_permit, epoch.as_ref())
            .is_err(),
        "a permit consumed after suppression must not decrypt"
    );

    let anchor = authority.current_anchor().expect("restart anchor");
    drop(authority);
    let reopened = open_authority(&path, Some(&anchor));
    assert!(
        reopened
            .open_with_permit(restart_permit, epoch.as_ref())
            .is_err(),
        "restart must not make a pre-suppression permit current again"
    );
}

#[test]
fn wrong_master_and_rollback_are_rejected() {
    let directory = tempfile::tempdir().expect("tempdir");
    let current_path = directory.path().join("current.redb");
    let rollback_path = directory.path().join("rollback.redb");
    let authority = open_authority(&current_path, None);
    let initial = authority.current_anchor().expect("initial anchor");
    drop(authority);
    std::fs::copy(&current_path, &rollback_path).expect("copy rollback snapshot");

    let authority = open_authority(&current_path, Some(&initial));
    authority
        .create_and_seal_or_get(&request("rollback"), b"rollback protected plaintext")
        .expect("create");
    let latest = authority.current_anchor().expect("latest anchor");
    drop(authority);
    assert!(
        RedbLocalCryptoAuthorityV1::open(&rollback_path, namespace(), master(), Some(&latest))
            .is_err()
    );
    let wrong_key_error = RedbLocalCryptoAuthorityV1::open(
        &current_path,
        namespace(),
        LocalMasterKeyV1::from_zeroizing(Zeroizing::new([0xa5; 32])),
        None,
    )
    .expect_err("wrong key must fail");
    assert!(
        !format!("{wrong_key_error:?}").contains("a5a5a5a5"),
        "error exposed master-key bytes"
    );
}

#[test]
fn encrypted_record_tamper_fails_closed_on_deep_verify_and_reopen() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("tamper.redb");
    let authority = open_authority(&path, None);
    authority
        .create_and_seal_or_get(&request("tamper"), b"tamper protected plaintext")
        .expect("create");
    authority
        .corrupt_first_object_value_for_test()
        .expect("corrupt object");
    assert!(authority.deep_verify(None).is_err());
    drop(authority);
    assert!(RedbLocalCryptoAuthorityV1::open(&path, namespace(), master(), None).is_err());
}

#[test]
fn idempotent_create_resumes_exact_encrypted_stage_and_rejects_changed_source() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("stage-retry.redb");
    let request = request("stage-retry");
    let authority = open_authority(&path, None);
    authority
        .stage_only_for_process_kill_test(&request, b"exact staged source")
        .expect("stage source");
    assert!(
        authority
            .create_and_seal_or_get(&request, b"changed staged source")
            .is_err()
    );
    assert!(matches!(
        authority
            .create_and_seal_or_get(&request, b"exact staged source")
            .expect("resume create"),
        LocalCreateOutcomeV1::Applied(_)
    ));
    assert_eq!(
        authority
            .deep_verify(None)
            .expect("deep verify")
            .staged_source_count(),
        0
    );
}

#[test]
fn local_process_kill_after_dek_allocation_recovers_encrypted_stage() {
    if std::env::var(CHILD_PHASE).is_ok() {
        run_process_kill_child();
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    let database_path = directory.path().join("crash.redb");
    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "local_crypto_authority_tests::local_process_kill_after_dek_allocation_recovers_encrypted_stage",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_PHASE, "allocated-uncommitted")
        .env(CHILD_DATABASE, &database_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn crash child");
    let stdout = child.stdout.take().expect("child stdout");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let ready = BufReader::new(stdout)
            .lines()
            .map_while(std::result::Result::ok)
            .any(|line| line.contains("CONTEXTDB_LOCAL_DEK_ALLOCATED_UNCOMMITTED"));
        let _ = sender.send(ready);
    });
    let ready = receiver
        .recv_timeout(Duration::from_secs(30))
        .unwrap_or(false);
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child exited or timed out before DEK allocation marker");
    }
    child.kill().expect("kill child");
    let status = child.wait().expect("wait child");
    assert!(!status.success());

    let database_bytes = std::fs::read(&database_path).expect("database bytes");
    assert!(
        !database_bytes
            .windows(PROCESS_KILL_PLAINTEXT.len())
            .any(|window| window == PROCESS_KILL_PLAINTEXT),
        "source plaintext reached the redb file"
    );
    let authority = open_authority(&database_path, None);
    let before = authority.deep_verify(None).expect("verify after kill");
    assert_eq!(before.object_count(), 0);
    assert_eq!(before.staged_source_count(), 1);
    let page = authority
        .recovery_page(None, None, 16, 64 * 1024)
        .expect("recovery page");
    assert_eq!(page.items().len(), 1);
    let source_material_handle = page.items()[0].source_material_handle().clone();
    let content_handle = page.items()[0].content_handle().clone();
    authority
        .resume_staged(&source_material_handle)
        .expect("resume stage");
    let after = authority.deep_verify(None).expect("verify after recovery");
    assert_eq!(after.object_count(), 1);
    assert_eq!(after.staged_source_count(), 0);
    let mac = InMemoryHeadMacAuthorityV2::random("crash-recovery-mac").expect("MAC");
    let overlay = StaticOverlay {
        decision: LiveSuppressionDecisionV2::Allow,
        calls: AtomicUsize::new(0),
    };
    let clear_head = head(&authority, &mac, SuppressionBindingV2::Clear);
    let open_epoch = TestOpenEpoch::current(&clear_head);
    let opened = authority
        .open_after_suppression(
            &clear_head,
            &content_handle,
            &context("subject-process-kill"),
            &mac,
            &overlay,
            &open_epoch,
        )
        .expect("open recovered object");
    assert_eq!(opened.plaintext(), Some(PROCESS_KILL_PLAINTEXT));
}

fn run_process_kill_child() {
    let database_path = std::env::var_os(CHILD_DATABASE).expect("child database path");
    let request = request("process-kill");
    let authority = open_authority(Path::new(&database_path), None);
    authority
        .stage_only_for_process_kill_test(&request, PROCESS_KILL_PLAINTEXT)
        .expect("stage source");
    authority
        .hold_after_key_allocation_for_process_kill_test(request.intent().source_material_handle())
        .expect("hold after DEK allocation");
}
