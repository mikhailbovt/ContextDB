//! P5 durable-adapter, recovery, and suppression-gate tests.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::test_support::{
    AcceptAllDeletionEvidenceV2, InMemoryHeadMacAuthorityV2, InMemoryKeyAuthorityV2,
    NonProductionCompositeHeadRepositoryV2, NonProductionManagedCopyDeletionAdapterV2,
};
use crate::*;

const CHILD_PHASE: &str = "CONTEXTDB_P5_CHILD_PHASE";
const CHILD_DATABASE: &str = "CONTEXTDB_P5_CHILD_DATABASE";
const CHILD_INTENT: &str = "CONTEXTDB_P5_CHILD_INTENT";

fn root(label: &str) -> StateRootV2 {
    StateRootV2::commit("p5-test", label.as_bytes()).expect("state root")
}

fn namespace() -> StateNamespaceV2 {
    StateNamespaceV2::new("p5-authority", "db", "ws", "primary").expect("namespace")
}

fn context(owner: &str) -> ContentSecurityContextV2 {
    ContentSecurityContextV2::new("db", "ws", "observation.raw", owner, root("policy"), 1)
        .expect("content context")
}

fn managed(label: &str) -> ManagedCopyCatalogCommitmentsV2 {
    ManagedCopyCatalogCommitmentsV2::try_new(vec![
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::ProviderCopy,
            3,
            root(&format!("provider-{label}")),
        )
        .expect("provider commitment"),
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::Export,
            5,
            root(&format!("export-{label}")),
        )
        .expect("export commitment"),
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::Backup,
            7,
            root(&format!("backup-{label}")),
        )
        .expect("backup commitment"),
    ])
    .expect("managed commitments")
}

fn repository_provenance() -> AuthorityProvenanceV2 {
    AuthorityProvenanceV2::non_production(
        AuthorityRoleV2::CompositeHeadRepository,
        "p5-repository",
        "p5-test-deployment",
    )
    .expect("repository provenance")
}

fn open_catalog(
    path: &Path,
    mac: Arc<InMemoryHeadMacAuthorityV2>,
    expected_anchor: Option<&DurableCatalogAnchorV2>,
) -> RedbDurableEncryptedObjectCatalogV2 {
    RedbDurableEncryptedObjectCatalogV2::open(
        path,
        namespace(),
        repository_provenance(),
        mac,
        expected_anchor,
    )
    .expect("open durable catalog")
}

fn applied(outcome: DurableObjectMutationOutcomeV2) -> DurableObjectMutationV2 {
    match outcome {
        DurableObjectMutationOutcomeV2::Applied(value) => value,
        other => panic!("expected applied mutation, got {other:?}"),
    }
}

fn found(
    outcome: DurableObjectLoadOutcomeV2,
) -> (
    DurableObjectCatalogEntryV2,
    Option<EncryptedContentV2>,
    DurableObjectCatalogSnapshotV2,
) {
    match outcome {
        DurableObjectLoadOutcomeV2::Found {
            entry,
            encrypted_object,
            snapshot,
        } => (*entry, encrypted_object.map(|value| *value), snapshot),
        other => panic!("expected found object, got {other:?}"),
    }
}

fn payload(key_catalog_root: StateRootV2) -> CompositeHeadPayloadV2 {
    CompositeHeadPayloadV2 {
        projection_root: root("projection"),
        policy_root: root("policy"),
        key_catalog_root,
        deletion_workflow_root: root("deletion"),
        suppression: SuppressionBindingV2::Clear,
    }
}

#[test]
fn redb_catalog_reopens_every_creation_boundary_and_rejects_wrong_provenance() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("secure-catalog.redb");
    let mac = Arc::new(InMemoryHeadMacAuthorityV2::random("p5-head-key").expect("MAC"));
    let intent =
        DurableObjectCreateIntentV2::preallocate(namespace(), context("owner"), managed("durable"))
            .expect("preallocate");
    let load = DurableObjectLoadRequestV2::new(namespace(), intent.content_handle().clone());
    let mut key_authority = InMemoryKeyAuthorityV2::default();

    let catalog = open_catalog(&path, mac.clone(), None);
    let reserved = applied(catalog.reserve(&intent).expect("reserve"));
    let reserved_anchor = catalog.current_anchor().expect("reserved anchor");
    drop(catalog);

    let catalog = open_catalog(&path, mac.clone(), Some(&reserved_anchor));
    let (recovered_reserved, no_ciphertext, _) =
        found(catalog.load(&load).expect("load reservation"));
    assert_eq!(recovered_reserved, *reserved.entry());
    assert_eq!(no_ciphertext, None);
    let key = key_authority
        .create_random_dek(
            intent
                .key_create_request()
                .expect("key request")
                .scope()
                .clone(),
        )
        .expect("create key");
    let key_record = DurableObjectKeyCreatedRequestV2::new(&recovered_reserved, key.clone())
        .expect("key record");
    let key_created = applied(catalog.record_key_created(&key_record).expect("record key"));
    let key_anchor = catalog.current_anchor().expect("key-created anchor");
    drop(catalog);

    let catalog = open_catalog(&path, mac.clone(), Some(&key_anchor));
    let (recovered_key_created, no_ciphertext, _) =
        found(catalog.load(&load).expect("load key-created entry"));
    assert_eq!(recovered_key_created, *key_created.entry());
    assert_eq!(no_ciphertext, None);
    let encrypted = EncryptedContentV2::seal_existing(
        &key_authority,
        key,
        b"durable P5 ciphertext, never persisted as plaintext",
    )
    .expect("seal");
    let object_request =
        DurableEncryptedObjectCreateRequestV2::new(&recovered_key_created, encrypted)
            .expect("object request");
    let stored = applied(
        catalog
            .create_or_get_object(&object_request)
            .expect("store object"),
    );
    let stored_anchor = catalog.current_anchor().expect("catalog anchor");
    drop(catalog);

    let catalog = open_catalog(&path, mac.clone(), Some(&stored_anchor));
    let report = catalog
        .deep_verify(Some(&stored_anchor))
        .expect("deep verify");
    assert_eq!(report.entry_count(), 1);
    assert_eq!(report.encrypted_object_count(), 1);
    assert_eq!(report.request_binding_count(), 3);
    let (recovered_stored, recovered_ciphertext, snapshot) =
        found(catalog.load(&load).expect("load after reopen"));
    assert_eq!(recovered_stored, *stored.entry());
    assert_eq!(
        recovered_ciphertext,
        Some(object_request.encrypted_object().clone())
    );

    let repository = NonProductionCompositeHeadRepositoryV2::random(
        "p5-repository",
        "p5-test-deployment",
        mac.clone(),
    )
    .expect("repository");
    assert_eq!(repository.provenance(), &repository_provenance());
    let head = CompositeStateHeadV2::initial(
        namespace(),
        payload(snapshot.publication_root().expect("publication root")),
        mac.as_ref(),
    )
    .expect("head");
    let cas = CompositeHeadCasRequestV2::new(intent.head_publish_request_id().clone(), None, head)
        .expect("CAS");
    let publication = DurableObjectHeadPublishRequestV2::new(
        &recovered_stored,
        snapshot,
        repository.provenance().clone(),
        cas,
        mac.as_ref(),
    )
    .expect("publication intent");
    applied(
        catalog
            .prepare_head_publication(&publication)
            .expect("prepare publication"),
    );
    let pending_anchor = catalog.current_anchor().expect("pending anchor");
    drop(catalog);

    let wrong_provenance = AuthorityProvenanceV2::non_production(
        AuthorityRoleV2::CompositeHeadRepository,
        "wrong-repository",
        "p5-test-deployment",
    )
    .expect("wrong provenance");
    assert!(
        RedbDurableEncryptedObjectCatalogV2::open(
            &path,
            namespace(),
            wrong_provenance,
            mac.clone(),
            Some(&pending_anchor),
        )
        .is_err(),
        "pending publication recovered under substituted provenance"
    );

    let catalog = open_catalog(&path, mac.clone(), Some(&stored_anchor));
    let (pending, _, _) = found(catalog.load(&load).expect("load pending"));
    assert_eq!(
        pending.stage(),
        DurableObjectCatalogStageV2::PublicationPending
    );
    let outcome = repository
        .compare_and_swap(publication.repository_request())
        .expect("repository CAS");
    let published = DurableObjectPublishedRequestV2::from_repository_outcome(
        &pending,
        &outcome,
        2,
        &repository,
    )
    .expect("published record");
    applied(
        catalog
            .record_head_published(&published)
            .expect("record head"),
    );
    let final_anchor = catalog.current_anchor().expect("final anchor");
    drop(catalog);

    let catalog = open_catalog(&path, mac, Some(&pending_anchor));
    let (complete, _, final_snapshot) = found(catalog.load(&load).expect("load complete"));
    assert_eq!(complete.stage(), DurableObjectCatalogStageV2::Published);
    assert!(matches!(
        plan_durable_object_recovery_v2(&complete, &final_snapshot).expect("recovery plan"),
        DurableObjectRecoveryActionV2::Complete(_)
    ));
    assert_eq!(
        catalog.current_anchor().expect("current anchor"),
        final_anchor
    );
}

#[test]
fn redb_catalog_external_anchor_detects_a_rolled_back_database_copy() {
    let directory = tempfile::tempdir().expect("tempdir");
    let live_path = directory.path().join("live.redb");
    let rollback_path = directory.path().join("rollback.redb");
    let mac = Arc::new(InMemoryHeadMacAuthorityV2::random("p5-rollback-key").expect("MAC"));
    let catalog = open_catalog(&live_path, mac.clone(), None);
    drop(catalog);
    std::fs::copy(&live_path, &rollback_path).expect("copy old catalog");

    let catalog = open_catalog(&live_path, mac.clone(), None);
    let intent = DurableObjectCreateIntentV2::preallocate(
        namespace(),
        context("rollback-owner"),
        managed("rollback"),
    )
    .expect("intent");
    applied(catalog.reserve(&intent).expect("reserve"));
    let new_anchor = catalog.current_anchor().expect("new anchor");
    let anchor_json = serde_json::to_vec(&new_anchor).expect("anchor JSON");
    let new_anchor = DurableCatalogAnchorV2::from_json_bounded(&anchor_json, &namespace())
        .expect("recover caller-custodied anchor");
    drop(catalog);

    assert!(
        RedbDurableEncryptedObjectCatalogV2::open(
            &rollback_path,
            namespace(),
            repository_provenance(),
            mac,
            Some(&new_anchor),
        )
        .is_err(),
        "rolled-back database satisfied a newer caller-custodied anchor"
    );
    assert!(
        DurableCatalogAnchorV2::from_json_bounded(
            &vec![b' '; MAX_DURABLE_CATALOG_ANCHOR_JSON_BYTES_V2 + 1],
            &namespace(),
        )
        .is_err(),
        "oversized external anchor reached JSON parsing"
    );
}

#[test]
fn redb_catalog_anchor_binds_same_generation_nonpublic_state() {
    let directory = tempfile::tempdir().expect("tempdir");
    let first_path = directory.path().join("first.redb");
    let second_path = directory.path().join("second.redb");
    let mac = Arc::new(InMemoryHeadMacAuthorityV2::random("p5-divergence-key").expect("MAC"));

    let first = open_catalog(&first_path, mac.clone(), None);
    let first_intent = DurableObjectCreateIntentV2::preallocate(
        namespace(),
        context("first-reservation"),
        managed("first-reservation"),
    )
    .expect("first intent");
    let first_mutation = applied(first.reserve(&first_intent).expect("first reserve"));
    let first_anchor = first.current_anchor().expect("first anchor");
    drop(first);

    let second = open_catalog(&second_path, mac.clone(), None);
    let second_intent = DurableObjectCreateIntentV2::preallocate(
        namespace(),
        context("second-reservation"),
        managed("second-reservation"),
    )
    .expect("second intent");
    let second_mutation = applied(second.reserve(&second_intent).expect("second reserve"));
    let second_anchor = second.current_anchor().expect("second anchor");
    drop(second);

    assert_eq!(first_anchor.generation(), second_anchor.generation());
    assert_eq!(
        first_mutation
            .snapshot()
            .publication_root()
            .expect("first root"),
        second_mutation
            .snapshot()
            .publication_root()
            .expect("second root"),
        "reserved-only entries intentionally do not alter the public key/object roots"
    );
    assert_ne!(
        first_anchor, second_anchor,
        "external anchor must bind reservations and request identities too"
    );
    assert!(
        RedbDurableEncryptedObjectCatalogV2::open(
            &second_path,
            namespace(),
            repository_provenance(),
            mac,
            Some(&first_anchor),
        )
        .is_err(),
        "same-generation durable-state divergence satisfied a foreign anchor"
    );
}

#[test]
fn redb_process_kill_recovers_committed_and_discards_uncommitted() {
    if let Ok(phase) = std::env::var(CHILD_PHASE) {
        run_process_kill_child(&phase);
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    for (phase, expected_found, marker) in [
        ("uncommitted", false, "CONTEXTDB_P5_UNCOMMITTED_READY"),
        ("committed", true, "CONTEXTDB_P5_COMMITTED_READY"),
    ] {
        let database_path = directory.path().join(format!("{phase}.redb"));
        let intent_path = directory.path().join(format!("{phase}-intent.json"));
        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .args([
                "--exact",
                "p5_tests::redb_process_kill_recovers_committed_and_discards_uncommitted",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_PHASE, phase)
            .env(CHILD_DATABASE, &database_path)
            .env(CHILD_INTENT, &intent_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn crash child");
        let stdout = child.stdout.take().expect("child stdout");
        let (sender, receiver) = mpsc::channel();
        let expected_marker = marker.to_owned();
        std::thread::spawn(move || {
            let ready = BufReader::new(stdout)
                .lines()
                .map_while(std::result::Result::ok)
                .any(|line| line.contains(&expected_marker));
            let _ = sender.send(ready);
        });
        let ready = receiver
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or(false);
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child exited or timed out before durability marker for {phase}");
        }
        child.kill().expect("kill child at durability boundary");
        let status = child.wait().expect("wait killed child");
        assert!(!status.success(), "killed child unexpectedly succeeded");

        let intent_bytes = std::fs::read(&intent_path).expect("read child intent");
        let intent =
            DurableObjectCreateIntentV2::from_json_bounded(&intent_bytes).expect("decode intent");
        let mac = Arc::new(
            InMemoryHeadMacAuthorityV2::random(format!("p5-child-{phase}-mac")).expect("MAC"),
        );
        let catalog = open_catalog(&database_path, mac, None);
        let load = DurableObjectLoadRequestV2::new(namespace(), intent.content_handle().clone());
        assert_eq!(
            matches!(
                catalog.load(&load).expect("load after kill"),
                DurableObjectLoadOutcomeV2::Found { .. }
            ),
            expected_found,
            "wrong recovery outcome after {phase} process kill"
        );
        catalog.deep_verify(None).expect("post-kill deep verify");
    }
}

fn run_process_kill_child(phase: &str) {
    let database_path = std::env::var_os(CHILD_DATABASE).expect("child database path");
    let intent_path = std::env::var_os(CHILD_INTENT).expect("child intent path");
    let mac =
        Arc::new(InMemoryHeadMacAuthorityV2::random(format!("p5-child-{phase}-mac")).expect("MAC"));
    let catalog = open_catalog(Path::new(&database_path), mac, None);
    let intent = DurableObjectCreateIntentV2::preallocate(
        namespace(),
        context(&format!("child-{phase}")),
        managed(phase),
    )
    .expect("child intent");
    let bytes = serde_json::to_vec(&intent).expect("intent JSON");
    let mut intent_file = std::fs::File::create(intent_path).expect("create child intent");
    intent_file.write_all(&bytes).expect("write child intent");
    intent_file.sync_all().expect("sync child intent");
    match phase {
        "uncommitted" => catalog
            .hold_uncommitted_reservation_for_process_kill_test(&intent)
            .expect("hold uncommitted transaction"),
        "committed" => {
            applied(catalog.reserve(&intent).expect("committed reserve"));
            println!("CONTEXTDB_P5_COMMITTED_READY");
            std::io::stdout().flush().expect("flush child marker");
            loop {
                std::thread::park();
            }
        }
        _ => panic!("unknown child phase"),
    }
}

struct CountingKeyAuthorityV2 {
    delegate: InMemoryKeyAuthorityV2,
    read_calls: AtomicUsize,
}

impl Default for CountingKeyAuthorityV2 {
    fn default() -> Self {
        Self {
            delegate: InMemoryKeyAuthorityV2::default(),
            read_calls: AtomicUsize::new(0),
        }
    }
}

impl KeyAuthorityV2 for CountingKeyAuthorityV2 {
    fn create_random_dek(&mut self, scope: DekScopeV2) -> Result<KeyDescriptorV2> {
        self.delegate.create_random_dek(scope)
    }

    fn descriptor(&self, key_handle: &KeyHandleV2) -> Result<KeyDescriptorV2> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        self.delegate.descriptor(key_handle)
    }

    fn seal(
        &self,
        key: &KeyDescriptorV2,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedPayloadV2> {
        self.delegate.seal(key, plaintext, associated_data)
    }

    fn open(
        &self,
        key: &KeyDescriptorV2,
        payload: &SealedPayloadV2,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        self.delegate.open(key, payload, associated_data)
    }

    fn request_destroy(
        &mut self,
        key_handle: &KeyHandleV2,
        expected_generation: u64,
    ) -> Result<KeyDescriptorV2> {
        self.delegate
            .request_destroy(key_handle, expected_generation)
    }

    fn confirm_destroy(
        &mut self,
        key_handle: &KeyHandleV2,
        expected_generation: u64,
        authority_evidence: EvidenceHandleV2,
    ) -> Result<KeyDescriptorV2> {
        self.delegate
            .confirm_destroy(key_handle, expected_generation, authority_evidence)
    }
}

struct StaticOverlayV2 {
    decision: LiveSuppressionDecisionV2,
    calls: AtomicUsize,
}

impl LiveSuppressionOverlayV2 for StaticOverlayV2 {
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

#[test]
fn suppression_is_evaluated_before_any_key_authority_read() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("suppression.redb");
    let ns = namespace();
    let content_context = context("suppression-owner");
    let mut keys = CountingKeyAuthorityV2::default();
    let intent = DurableObjectCreateIntentV2::preallocate(
        ns.clone(),
        content_context.clone(),
        managed("suppression"),
    )
    .expect("intent");
    let key = keys
        .create_random_dek(
            intent
                .key_create_request()
                .expect("key request")
                .scope()
                .clone(),
        )
        .expect("key");
    let encrypted =
        EncryptedContentV2::seal_existing(&keys, key.clone(), b"suppression-before-decrypt")
            .expect("encrypt");
    let mac = Arc::new(InMemoryHeadMacAuthorityV2::random("suppression-head-key").expect("MAC"));
    let catalog = open_catalog(&path, mac.clone(), None);
    let reserved = applied(catalog.reserve(&intent).expect("reserve"));
    let key_record =
        DurableObjectKeyCreatedRequestV2::new(reserved.entry(), key).expect("key-created request");
    let key_created = applied(
        catalog
            .record_key_created(&key_record)
            .expect("record key created"),
    );
    let object_request = DurableEncryptedObjectCreateRequestV2::new(key_created.entry(), encrypted)
        .expect("object request");
    let stored = applied(
        catalog
            .create_or_get_object(&object_request)
            .expect("store ciphertext"),
    );
    let load = DurableObjectLoadRequestV2::new(ns.clone(), intent.content_handle().clone());
    keys.read_calls.store(0, Ordering::SeqCst);
    let publication_root = stored
        .snapshot()
        .publication_root()
        .expect("publication root");
    let overlay_root = root("live-overlay");
    let overlay = StaticOverlayV2 {
        decision: LiveSuppressionDecisionV2::Suppressed,
        calls: AtomicUsize::new(0),
    };
    let pending = CompositeStateHeadV2::initial(
        ns.clone(),
        CompositeHeadPayloadV2 {
            projection_root: root("projection"),
            policy_root: root("policy"),
            key_catalog_root: publication_root.clone(),
            deletion_workflow_root: overlay_root.clone(),
            suppression: SuppressionBindingV2::Pending {
                overlay_root: overlay_root.clone(),
                pending_workflow_count: 1,
            },
        },
        mac.as_ref(),
    )
    .expect("pending head");
    assert!(
        decrypt_after_suppression_v2(
            &pending,
            &load,
            mac.as_ref(),
            &content_context,
            &catalog,
            &overlay,
            &keys,
        )
        .is_err()
    );
    assert_eq!(keys.read_calls.load(Ordering::SeqCst), 0);
    assert_eq!(overlay.calls.load(Ordering::SeqCst), 0);

    let enforced = CompositeStateHeadV2::initial(
        ns.clone(),
        CompositeHeadPayloadV2 {
            projection_root: root("projection"),
            policy_root: root("policy"),
            key_catalog_root: publication_root.clone(),
            deletion_workflow_root: overlay_root.clone(),
            suppression: SuppressionBindingV2::Enforced { overlay_root },
        },
        mac.as_ref(),
    )
    .expect("enforced head");
    assert!(matches!(
        decrypt_after_suppression_v2(
            &enforced,
            &load,
            mac.as_ref(),
            &content_context,
            &catalog,
            &overlay,
            &keys,
        )
        .expect("suppressed read"),
        SuppressionAwareReadV2::Suppressed
    ));
    assert_eq!(keys.read_calls.load(Ordering::SeqCst), 0);
    assert_eq!(overlay.calls.load(Ordering::SeqCst), 1);

    let clear = CompositeStateHeadV2::initial(
        ns.clone(),
        CompositeHeadPayloadV2 {
            projection_root: root("projection"),
            policy_root: root("policy"),
            key_catalog_root: publication_root,
            deletion_workflow_root: root("clear-deletion"),
            suppression: SuppressionBindingV2::Clear,
        },
        mac.as_ref(),
    )
    .expect("clear head");
    let result = decrypt_after_suppression_v2(
        &clear,
        &load,
        mac.as_ref(),
        &content_context,
        &catalog,
        &overlay,
        &keys,
    )
    .expect("clear read");
    assert_eq!(
        result.plaintext(),
        Some(b"suppression-before-decrypt".as_slice())
    );
    assert_eq!(keys.read_calls.load(Ordering::SeqCst), 2);
}

fn managed_inventory(target: DeletionTargetHandleV2) -> DeletionClosureInventoryV2 {
    let classes = ALL_DELETION_CLOSURE_CLASSES_V2
        .into_iter()
        .map(|class| {
            if class == DeletionClosureClassV2::ProviderCopy {
                ClassInventoryV2::new(class, BTreeSet::from([target.clone()]), None)
            } else {
                ClassInventoryV2::new(
                    class,
                    BTreeSet::new(),
                    Some(EvidenceHandleV2::generate().expect("absence evidence")),
                )
            }
        })
        .collect::<Result<Vec<_>>>()
        .expect("managed inventory classes");
    DeletionClosureInventoryV2::try_new(classes).expect("managed inventory")
}

struct AcceptPersistedTicketV2 {
    request_evidence: EvidenceHandleV2,
    ticket_evidence: EvidenceHandleV2,
}

impl AcceptPersistedTicketV2 {
    fn new() -> Self {
        Self {
            request_evidence: EvidenceHandleV2::generate().expect("request persistence evidence"),
            ticket_evidence: EvidenceHandleV2::generate().expect("ticket persistence evidence"),
        }
    }
}

impl ManagedCopyRequestPersistenceVerifierV2 for AcceptPersistedTicketV2 {
    fn verify_persisted_request(
        &self,
        _request: &ManagedCopyDeleteRequestV2,
        _evaluated_at_micros: u64,
    ) -> Result<EvidenceHandleV2> {
        Ok(self.request_evidence.clone())
    }
}

impl ManagedCopyTicketPersistenceVerifierV2 for AcceptPersistedTicketV2 {
    fn verify_persisted_ticket(
        &self,
        _ticket: &ManagedCopyDeleteTicketV2,
        _evaluated_at_micros: u64,
    ) -> Result<EvidenceHandleV2> {
        Ok(self.ticket_evidence.clone())
    }
}

fn purging_workflow(target: DeletionTargetHandleV2) -> DeletionWorkflowV2 {
    let verifier = AcceptAllDeletionEvidenceV2;
    let mut workflow =
        DeletionWorkflowV2::prepare(namespace(), managed_inventory(target), 1).expect("workflow");
    workflow
        .begin_suppression(workflow.revision(), 2)
        .expect("begin suppression");
    workflow
        .confirm_suppressed(workflow.revision(), 3, root("suppression"), &verifier)
        .expect("confirm suppression");
    workflow
        .begin_purging(workflow.revision(), 4)
        .expect("begin purge");
    workflow
}

#[test]
fn managed_copy_bridge_binds_inventory_and_keeps_outside_control_incomplete() {
    for (terminal_disposition, should_verify) in [
        (ManagedCopyTerminalDispositionV2::Deleted, true),
        (ManagedCopyTerminalDispositionV2::OutsideControl, false),
    ] {
        let target = DeletionTargetHandleV2::generate().expect("target");
        let mut workflow = purging_workflow(target.clone());
        let persistence = AcceptPersistedTicketV2::new();
        let persisted_request = prepare_persisted_managed_copy_delete_request_v2(
            &workflow,
            target,
            OperationRequestIdV2::generate().expect("request"),
            &managed("workflow"),
            5,
            &persistence,
        )
        .expect("managed request");
        let request = persisted_request.request();
        assert_eq!(request.copy_generation(), 3);
        assert_eq!(request.inventory_commitment(), &root("provider-workflow"));
        let adapter =
            NonProductionManagedCopyDeletionAdapterV2::random("p5-provider", "p5-test-deployment")
                .expect("adapter");
        let ticket = match adapter.request_delete(request).expect("request delete") {
            AuthorityOperationOutcomeV2::Applied(ticket) => ticket,
            other => panic!("expected accepted ticket, got {other:?}"),
        };
        let revision = workflow.revision();
        record_persisted_managed_copy_ticket_v2(
            &mut workflow,
            revision,
            5,
            &persisted_request,
            &ticket,
            5,
            &persistence,
        )
        .expect("record persisted ticket");
        assert!(
            workflow
                .record_disposition(
                    workflow.revision(),
                    5,
                    request.target().clone(),
                    DeletionTargetDispositionV2::Managed(
                        ManagedCopyDispositionV2::DeletionRequested {
                            request: EvidenceHandleV2::generate()
                                .expect("substituted request evidence"),
                        },
                    ),
                )
                .is_err(),
            "same-rank request evidence substitution must remain forbidden"
        );
        let terminal = adapter
            .mark_terminal_for_test(ticket.ticket_handle(), terminal_disposition, 6)
            .expect("terminal evidence");
        let mismatch_revision = workflow.revision();
        assert!(
            record_managed_copy_terminal_evidence_v2(
                &mut workflow,
                mismatch_revision,
                6,
                &terminal,
                6,
                &AcceptPersistedTicketV2::new(),
                &adapter,
            )
            .is_err(),
            "terminal evidence crossed a substituted durable-ticket proof"
        );
        let revision = workflow.revision();
        record_managed_copy_terminal_evidence_v2(
            &mut workflow,
            revision,
            6,
            &terminal,
            6,
            &persistence,
            &adapter,
        )
        .expect("record terminal evidence");
        assert_eq!(
            workflow.dispositions().get(request.target()),
            Some(&DeletionTargetDispositionV2::Managed(
                terminal.workflow_disposition()
            ))
        );
        let terminal_revision = workflow.revision();
        record_managed_copy_terminal_evidence_v2(
            &mut workflow,
            terminal_revision,
            7,
            &terminal,
            7,
            &persistence,
            &adapter,
        )
        .expect("exact terminal replay is idempotent");
        assert_eq!(workflow.revision(), terminal_revision);
        if terminal_disposition == ManagedCopyTerminalDispositionV2::OutsideControl {
            assert!(
                workflow
                    .record_disposition(
                        workflow.revision(),
                        7,
                        request.target().clone(),
                        DeletionTargetDispositionV2::Managed(
                            ManagedCopyDispositionV2::DeletionRequested {
                                request: EvidenceHandleV2::generate()
                                    .expect("substituted request evidence"),
                            },
                        ),
                    )
                    .is_err(),
                "OutsideControl must not regress to another same-rank state"
            );
        }
        let revision = workflow.revision();
        workflow
            .await_external(revision, 8)
            .expect("await external");
        let revision = workflow.revision();
        let authoritative = workflow.inventory().clone();
        assert_eq!(
            workflow
                .verify_closure(revision, 9, &authoritative, &AcceptAllDeletionEvidenceV2)
                .is_ok(),
            should_verify,
            "OutsideControl must remain terminal but incomplete"
        );
    }
}
