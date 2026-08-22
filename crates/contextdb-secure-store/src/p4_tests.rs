use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::test_support::{
    InMemoryHeadMacAuthorityV2, InMemoryKeyAuthorityV2, NonProductionCompositeHeadRepositoryV2,
};
use crate::*;

fn root(label: &str) -> StateRootV2 {
    StateRootV2::commit("p4-test", label.as_bytes()).expect("state root")
}

fn namespace() -> StateNamespaceV2 {
    StateNamespaceV2::new("p4-authority", "db", "ws", "primary").expect("namespace")
}

fn context(owner: &str) -> ContentSecurityContextV2 {
    ContentSecurityContextV2::new("db", "ws", "observation.raw", owner, root("policy"), 1)
        .expect("security context")
}

fn managed(label: &str) -> ManagedCopyCatalogCommitmentsV2 {
    ManagedCopyCatalogCommitmentsV2::try_new(vec![
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::ProviderCopy,
            1,
            root(&format!("provider-{label}")),
        )
        .expect("provider commitment"),
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::Export,
            1,
            root(&format!("export-{label}")),
        )
        .expect("export commitment"),
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::Backup,
            1,
            root(&format!("backup-{label}")),
        )
        .expect("backup commitment"),
    ])
    .expect("managed commitments")
}

#[derive(Default)]
struct RecoverableTestKms {
    authority: InMemoryKeyAuthorityV2,
    requests: BTreeMap<OperationRequestIdV2, (StateRootV2, KeyDescriptorV2)>,
    scopes: BTreeMap<DekScopeV2, KeyDescriptorV2>,
}

impl RecoverableTestKms {
    fn create_or_get(&mut self, request: &ProductionKeyCreateRequestV2) -> Result<KeyDescriptorV2> {
        let commitment = request.intent_commitment()?;
        if let Some((existing, descriptor)) = self.requests.get(request.request_id()) {
            if existing == &commitment {
                return Ok(descriptor.clone());
            }
            return Err(SecureStoreError::StateConflict(
                "test KMS request ID has another intent".to_owned(),
            ));
        }
        let descriptor = if let Some(existing) = self.scopes.get(request.scope()) {
            existing.clone()
        } else {
            let created = self.authority.create_random_dek(request.scope().clone())?;
            self.scopes.insert(request.scope().clone(), created.clone());
            created
        };
        request.validate_response(&descriptor)?;
        self.requests.insert(
            request.request_id().clone(),
            (commitment, descriptor.clone()),
        );
        Ok(descriptor)
    }

    fn seal(&self, key: KeyDescriptorV2, plaintext: &[u8]) -> Result<EncryptedContentV2> {
        EncryptedContentV2::seal_existing(&self.authority, key, plaintext)
    }
}

#[derive(Clone, Default)]
struct TestCatalogState {
    generation: u64,
    entries: BTreeMap<ContentHandleV2, DurableObjectCatalogEntryV2>,
    objects: BTreeMap<ContentHandleV2, EncryptedContentV2>,
    request_intents: BTreeMap<OperationRequestIdV2, StateRootV2>,
}

#[derive(Default)]
struct CrashRecoverableTestCatalog {
    state: Mutex<TestCatalogState>,
}

impl CrashRecoverableTestCatalog {
    fn restart(&self) -> Self {
        Self {
            state: Mutex::new(self.state.lock().expect("catalog lock").clone()),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, TestCatalogState>> {
        self.state
            .lock()
            .map_err(|_| SecureStoreError::StateConflict("test catalog lock poisoned".to_owned()))
    }

    fn snapshot(
        state: &TestCatalogState,
        ns: &StateNamespaceV2,
    ) -> Result<DurableObjectCatalogSnapshotV2> {
        let keys = state
            .entries
            .values()
            .filter_map(|entry| entry.key().cloned())
            .collect::<Vec<_>>();
        let key_catalog_root = KeyCatalogSnapshotV2::try_new(keys)?.root()?;
        let stored = state
            .entries
            .values()
            .filter_map(|entry| entry.stored().cloned())
            .collect::<Vec<_>>();
        let encrypted_object_catalog_root = StateRootV2::commit(
            "p4-test-encrypted-object-catalog",
            &canonical_json(&stored)?,
        )?;
        DurableObjectCatalogSnapshotV2::new(
            ns.clone(),
            state.generation.max(1),
            key_catalog_root,
            encrypted_object_catalog_root,
        )
    }

    fn mutation(
        state: &TestCatalogState,
        entry: DurableObjectCatalogEntryV2,
    ) -> Result<DurableObjectMutationV2> {
        DurableObjectMutationV2::new(
            entry.clone(),
            Self::snapshot(state, entry.intent().namespace())?,
        )
    }

    fn bind_request(
        state: &mut TestCatalogState,
        request_id: &OperationRequestIdV2,
        commitment: &StateRootV2,
    ) -> Result<bool> {
        if let Some(existing) = state.request_intents.get(request_id) {
            if existing == commitment {
                return Ok(false);
            }
            return Err(SecureStoreError::StateConflict(
                "test catalog request ID has another intent".to_owned(),
            ));
        }
        state
            .request_intents
            .insert(request_id.clone(), commitment.clone());
        Ok(true)
    }
}

impl DurableEncryptedObjectCatalogV2 for CrashRecoverableTestCatalog {
    fn reserve(
        &self,
        intent: &DurableObjectCreateIntentV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let commitment = intent.commitment()?;
        let mut state = self.lock()?;
        if let Some(existing) = state.entries.get(intent.content_handle()) {
            return if existing.intent() == intent {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    Self::mutation(&state, existing.clone())?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: existing.root()?,
                })
            };
        }
        if Self::bind_request(&mut state, intent.reservation_request_id(), &commitment).is_err() {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: state
                    .request_intents
                    .get(intent.reservation_request_id())
                    .cloned()
                    .unwrap_or(commitment),
            });
        }
        let entry = DurableObjectCatalogEntryV2::reserved(intent.clone())?;
        state
            .entries
            .insert(intent.content_handle().clone(), entry.clone());
        state.generation = state.generation.saturating_add(1);
        Ok(DurableObjectMutationOutcomeV2::Applied(Self::mutation(
            &state, entry,
        )?))
    }

    fn record_key_created(
        &self,
        request: &DurableObjectKeyCreatedRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let mut state = self.lock()?;
        let current = state
            .entries
            .get(request.content_handle())
            .cloned()
            .ok_or_else(|| SecureStoreError::StateConflict("reservation missing".to_owned()))?;
        if current.stage() >= DurableObjectCatalogStageV2::KeyCreated {
            return if current.key() == Some(request.descriptor()) {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    Self::mutation(&state, current)?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: current.root()?,
                })
            };
        }
        if current.revision() != request.expected_catalog_revision()
            || current.intent().key_create_request_id() != request.key_create_request_id()
            || current.intent().key_create_request()?.intent_commitment()?
                != *request.key_create_intent_commitment()
        {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: current.root()?,
            });
        }
        let next = current.record_key_created(request.descriptor().clone())?;
        state
            .entries
            .insert(request.content_handle().clone(), next.clone());
        state.generation = state.generation.saturating_add(1);
        Ok(DurableObjectMutationOutcomeV2::Applied(Self::mutation(
            &state, next,
        )?))
    }

    fn create_or_get_object(
        &self,
        request: &DurableEncryptedObjectCreateRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let mut state = self.lock()?;
        let current = state
            .entries
            .get(request.intent().content_handle())
            .cloned()
            .ok_or_else(|| SecureStoreError::StateConflict("reservation missing".to_owned()))?;
        if current.stage() >= DurableObjectCatalogStageV2::ObjectStored {
            let same = current.stored() == Some(request.descriptor())
                && state.objects.get(request.intent().content_handle())
                    == Some(request.encrypted_object());
            return if same {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    Self::mutation(&state, current)?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: current.root()?,
                })
            };
        }
        let commitment = request.request_intent_commitment().clone();
        if Self::bind_request(&mut state, request.request_id(), &commitment).is_err() {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: state
                    .request_intents
                    .get(request.request_id())
                    .cloned()
                    .unwrap_or(commitment),
            });
        }
        let next = current.record_object_stored(request)?;
        state.objects.insert(
            request.intent().content_handle().clone(),
            request.encrypted_object().clone(),
        );
        state
            .entries
            .insert(request.intent().content_handle().clone(), next.clone());
        state.generation = state.generation.saturating_add(1);
        Ok(DurableObjectMutationOutcomeV2::Applied(Self::mutation(
            &state, next,
        )?))
    }

    fn prepare_head_publication(
        &self,
        request: &DurableObjectHeadPublishRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let mut state = self.lock()?;
        let current = state
            .entries
            .get(request.content_handle())
            .cloned()
            .ok_or_else(|| SecureStoreError::StateConflict("object missing".to_owned()))?;
        if current.stage() >= DurableObjectCatalogStageV2::PublicationPending {
            return if current.pending_publication() == Some(request) {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    Self::mutation(&state, current)?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: current.root()?,
                })
            };
        }
        if Self::snapshot(&state, current.intent().namespace())? != *request.catalog_snapshot() {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: current.root()?,
            });
        }
        let commitment = request.intent_commitment()?;
        if Self::bind_request(
            &mut state,
            request.repository_request().request_id(),
            &commitment,
        )
        .is_err()
        {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: state
                    .request_intents
                    .get(request.repository_request().request_id())
                    .cloned()
                    .unwrap_or(commitment),
            });
        }
        let next = current.record_publication_pending(request)?;
        state
            .entries
            .insert(request.content_handle().clone(), next.clone());
        state.generation = state.generation.saturating_add(1);
        Ok(DurableObjectMutationOutcomeV2::Applied(Self::mutation(
            &state, next,
        )?))
    }

    fn record_head_published(
        &self,
        request: &DurableObjectPublishedRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let mut state = self.lock()?;
        let current = state
            .entries
            .get(request.content_handle())
            .cloned()
            .ok_or_else(|| SecureStoreError::StateConflict("object missing".to_owned()))?;
        if current.stage() == DurableObjectCatalogStageV2::Published {
            return if current.published_anchor() == Some(request.anchored_head().anchor()) {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    Self::mutation(&state, current)?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: current.root()?,
                })
            };
        }
        let next = current.record_published_request(request)?;
        state
            .entries
            .insert(request.content_handle().clone(), next.clone());
        state.generation = state.generation.saturating_add(1);
        Ok(DurableObjectMutationOutcomeV2::Applied(Self::mutation(
            &state, next,
        )?))
    }

    fn load(&self, request: &DurableObjectLoadRequestV2) -> Result<DurableObjectLoadOutcomeV2> {
        let state = self.lock()?;
        let Some(entry) = state.entries.get(request.content_handle()).cloned() else {
            return Ok(DurableObjectLoadOutcomeV2::Missing);
        };
        if entry.intent().namespace() != request.namespace() {
            return Err(SecureStoreError::Integrity(
                "test catalog namespace mismatch".to_owned(),
            ));
        }
        let encrypted_object = state
            .objects
            .get(request.content_handle())
            .cloned()
            .map(Box::new);
        let outcome = DurableObjectLoadOutcomeV2::Found {
            snapshot: Self::snapshot(&state, request.namespace())?,
            entry: Box::new(entry),
            encrypted_object,
        };
        outcome.validate_for(request)?;
        Ok(outcome)
    }

    fn scan_page(
        &self,
        request: &DurableObjectCatalogPageRequestV2,
    ) -> Result<DurableObjectCatalogPageOutcomeV2> {
        let state = self.lock()?;
        let snapshot = Self::snapshot(&state, request.namespace())?;
        if request
            .expected_generation()
            .is_some_and(|expected| expected != snapshot.generation())
        {
            return Ok(DurableObjectCatalogPageOutcomeV2::GenerationChanged {
                current_generation: snapshot.generation(),
            });
        }
        let mut candidates = state
            .entries
            .values()
            .filter(|entry| entry.intent().namespace() == request.namespace())
            .filter(|entry| {
                request
                    .after()
                    .is_none_or(|after| entry.intent().content_handle() > after)
            })
            .map(DurableObjectCatalogSummaryV2::from_entry)
            .collect::<Result<Vec<_>>>()?;
        candidates.sort_by(|left, right| left.content_handle().cmp(right.content_handle()));
        let has_more = candidates.len() > request.max_items();
        candidates.truncate(request.max_items());
        let page = DurableObjectCatalogPageV2::new(request, snapshot, candidates, has_more)?;
        Ok(DurableObjectCatalogPageOutcomeV2::Page(page))
    }
}

fn applied(outcome: DurableObjectMutationOutcomeV2) -> DurableObjectMutationV2 {
    match outcome {
        DurableObjectMutationOutcomeV2::Applied(value) => value,
        other => panic!("expected applied mutation, got {other:?}"),
    }
}

fn found(
    outcome: DurableObjectLoadOutcomeV2,
) -> (DurableObjectCatalogEntryV2, DurableObjectCatalogSnapshotV2) {
    match outcome {
        DurableObjectLoadOutcomeV2::Found {
            entry, snapshot, ..
        } => (*entry, snapshot),
        other => panic!("expected found object, got {other:?}"),
    }
}

fn head_payload(key_catalog_root: StateRootV2) -> CompositeHeadPayloadV2 {
    CompositeHeadPayloadV2 {
        projection_root: root("projection"),
        policy_root: root("policy"),
        key_catalog_root,
        deletion_workflow_root: root("deletion"),
        suppression: SuppressionBindingV2::Clear,
    }
}

#[test]
fn crash_recovery_converges_across_kms_store_and_head_failpoints() {
    let intent =
        DurableObjectCreateIntentV2::preallocate(namespace(), context("owner"), managed("a"))
            .expect("preallocate");
    let mut catalog = CrashRecoverableTestCatalog::default();
    let mut kms = RecoverableTestKms::default();

    applied(catalog.reserve(&intent).expect("reserve"));
    let key = kms
        .create_or_get(&intent.key_create_request().expect("key request"))
        .expect("KMS create");

    catalog = catalog.restart();
    let load = DurableObjectLoadRequestV2::new(namespace(), intent.content_handle().clone());
    let (reserved, reserved_snapshot) = found(catalog.load(&load).expect("load reservation"));
    match plan_durable_object_recovery_v2(&reserved, &reserved_snapshot).expect("plan") {
        DurableObjectRecoveryActionV2::RetryKeyCreate(request) => {
            assert_eq!(
                kms.create_or_get(&request).expect("idempotent KMS retry"),
                key
            );
        }
        other => panic!("expected KMS retry, got {other:?}"),
    }

    let key_record =
        DurableObjectKeyCreatedRequestV2::new(&reserved, key.clone()).expect("key-created request");
    applied(
        catalog
            .record_key_created(&key_record)
            .expect("record KMS result"),
    );
    catalog = catalog.restart();
    let (key_created, key_snapshot) = found(catalog.load(&load).expect("load key-created"));
    match plan_durable_object_recovery_v2(&key_created, &key_snapshot).expect("plan") {
        DurableObjectRecoveryActionV2::SealAndStore {
            source_material_handle,
            key: recovered_key,
            expected_catalog_revision: 2,
        } => {
            assert_eq!(&source_material_handle, intent.source_material_handle());
            assert_eq!(recovered_key, key);
        }
        other => panic!("expected seal-and-store, got {other:?}"),
    }

    let encrypted = kms
        .seal(key, b"durable source survives until publication")
        .expect("seal");
    let create =
        DurableEncryptedObjectCreateRequestV2::new(&key_created, encrypted).expect("object create");
    applied(catalog.create_or_get_object(&create).expect("store object"));
    catalog = catalog.restart();
    let (stored, stored_snapshot) = found(catalog.load(&load).expect("load stored"));
    assert!(matches!(
        plan_durable_object_recovery_v2(&stored, &stored_snapshot).expect("plan"),
        DurableObjectRecoveryActionV2::PrepareHeadPublication(_)
    ));

    let mac = Arc::new(InMemoryHeadMacAuthorityV2::random("p4-head-key").expect("MAC"));
    let repository = NonProductionCompositeHeadRepositoryV2::random(
        "p4-head-repository",
        "test-process",
        mac.clone(),
    )
    .expect("repository");
    let head = CompositeStateHeadV2::initial(
        namespace(),
        head_payload(
            stored_snapshot
                .publication_root()
                .expect("publication root"),
        ),
        mac.as_ref(),
    )
    .expect("initial head");
    let repository_request =
        CompositeHeadCasRequestV2::new(intent.head_publish_request_id().clone(), None, head)
            .expect("repository request");
    let publication = DurableObjectHeadPublishRequestV2::new(
        &stored,
        stored_snapshot,
        repository.provenance().clone(),
        repository_request,
        mac.as_ref(),
    )
    .expect("publication intent");
    applied(
        catalog
            .prepare_head_publication(&publication)
            .expect("persist head intent"),
    );
    let first_outcome = repository
        .compare_and_swap(publication.repository_request())
        .expect("repository CAS");
    assert!(matches!(
        first_outcome,
        CompositeHeadCasOutcomeV2::Applied(_)
    ));

    catalog = catalog.restart();
    let (pending, pending_snapshot) = found(catalog.load(&load).expect("load pending"));
    let retry = match plan_durable_object_recovery_v2(&pending, &pending_snapshot).expect("plan") {
        DurableObjectRecoveryActionV2::RetryHeadPublication(request) => request,
        other => panic!("expected repository retry, got {other:?}"),
    };
    let replayed = repository
        .compare_and_swap(&retry)
        .expect("repository retry");
    assert!(matches!(
        replayed,
        CompositeHeadCasOutcomeV2::AlreadyAnchored(_)
    ));
    let published = DurableObjectPublishedRequestV2::from_repository_outcome(
        &pending,
        &replayed,
        2,
        &repository,
    )
    .expect("published request");
    applied(
        catalog
            .record_head_published(&published)
            .expect("record published"),
    );
    catalog = catalog.restart();
    let (complete, snapshot) = found(catalog.load(&load).expect("load published"));
    assert!(matches!(
        plan_durable_object_recovery_v2(&complete, &snapshot).expect("plan"),
        DurableObjectRecoveryActionV2::Complete(_)
    ));
}

#[test]
fn preallocation_and_managed_copy_inventory_are_bounded_exact_and_plaintext_free() {
    let ns = namespace();
    let commitments = managed("exact");
    let intent =
        DurableObjectCreateIntentV2::preallocate(ns, context("sensitive-owner"), commitments)
            .expect("intent");
    let bytes = serde_json::to_vec(&intent).expect("intent JSON");
    assert_eq!(
        DurableObjectCreateIntentV2::from_json_bounded(&bytes).expect("recover"),
        intent
    );
    assert!(
        DurableObjectCreateIntentV2::from_json_bounded(&vec![
            b' ';
            MAX_DURABLE_OBJECT_INTENT_JSON_BYTES_V2
                + 1
        ])
        .is_err()
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("plaintext"));
    let debug = format!("{intent:?}");
    assert!(!debug.contains(intent.content_handle().as_str()));
    assert!(!debug.contains(intent.source_material_handle().as_str()));

    assert!(ManagedCopyCatalogCommitmentsV2::try_new(vec![]).is_err());
    assert!(
        ManagedCopyCatalogCommitmentsV2::try_new(vec![
            ManagedCopyCatalogCommitmentV2::new(
                DeletionClosureClassV2::ProviderCopy,
                1,
                root("p"),
            )
            .expect("provider");
            3
        ])
        .is_err()
    );
    assert!(
        ManagedCopyCatalogCommitmentV2::new(
            DeletionClosureClassV2::PrimaryContent,
            1,
            root("wrong"),
        )
        .is_err()
    );
}

#[test]
fn reservation_and_ciphertext_retries_never_rebind_an_idempotency_identity() {
    let catalog = CrashRecoverableTestCatalog::default();
    let first =
        DurableObjectCreateIntentV2::preallocate(namespace(), context("one"), managed("one"))
            .expect("first intent");
    applied(catalog.reserve(&first).expect("reserve first"));
    assert!(matches!(
        catalog.reserve(&first).expect("replay"),
        DurableObjectMutationOutcomeV2::AlreadyApplied(_)
    ));

    let conflicting = DurableObjectCreateIntentV2::new_preallocated(
        first.reservation_request_id().clone(),
        OperationRequestIdV2::generate().expect("request"),
        OperationRequestIdV2::generate().expect("request"),
        OperationRequestIdV2::generate().expect("request"),
        namespace(),
        SourceMaterialHandleV2::generate().expect("source"),
        managed("other"),
        ContentHandleV2::generate().expect("content"),
        ErasureDomainV2::generate().expect("domain"),
        context("other"),
    )
    .expect("conflicting intent");
    assert!(matches!(
        catalog.reserve(&conflicting).expect("conflict"),
        DurableObjectMutationOutcomeV2::Conflict { .. }
    ));

    let mut kms = RecoverableTestKms::default();
    let load = DurableObjectLoadRequestV2::new(namespace(), first.content_handle().clone());
    let (entry, _) = found(catalog.load(&load).expect("load"));
    let key = kms
        .create_or_get(&first.key_create_request().expect("KMS request"))
        .expect("key");
    let key_record = DurableObjectKeyCreatedRequestV2::new(&entry, key.clone()).expect("record");
    applied(
        catalog
            .record_key_created(&key_record)
            .expect("persist key"),
    );
    let (key_created, _) = found(catalog.load(&load).expect("load key"));
    let first_ciphertext = kms.seal(key.clone(), b"same source").expect("seal first");
    let first_create = DurableEncryptedObjectCreateRequestV2::new(&key_created, first_ciphertext)
        .expect("first create");
    applied(
        catalog
            .create_or_get_object(&first_create)
            .expect("store first"),
    );
    let second_ciphertext = kms.seal(key, b"same source").expect("seal retry");
    let second_create = DurableEncryptedObjectCreateRequestV2::new(&key_created, second_ciphertext)
        .expect("second create shape");
    assert!(matches!(
        catalog
            .create_or_get_object(&second_create)
            .expect("conflicting ciphertext"),
        DurableObjectMutationOutcomeV2::Conflict { .. }
    ));
}

#[test]
fn catalog_pages_are_stable_exclusive_and_count_bounded() {
    let catalog = CrashRecoverableTestCatalog::default();
    for owner in ["a", "b", "c"] {
        let intent =
            DurableObjectCreateIntentV2::preallocate(namespace(), context(owner), managed(owner))
                .expect("intent");
        applied(catalog.reserve(&intent).expect("reserve"));
    }
    let first_request = DurableObjectCatalogPageRequestV2::new(
        namespace(),
        None,
        None,
        2,
        MAX_DURABLE_OBJECT_CATALOG_PAGE_BYTES_V2,
    )
    .expect("page request");
    let first = match catalog.scan_page(&first_request).expect("first page") {
        DurableObjectCatalogPageOutcomeV2::Page(page) => page,
        other => panic!("expected page, got {other:?}"),
    };
    assert_eq!(first.items().len(), 2);
    let cursor = first.next_after().cloned().expect("next cursor");
    let second_request = DurableObjectCatalogPageRequestV2::new(
        namespace(),
        Some(first.snapshot().generation()),
        Some(cursor.clone()),
        2,
        MAX_DURABLE_OBJECT_CATALOG_PAGE_BYTES_V2,
    )
    .expect("second request");
    let second = match catalog.scan_page(&second_request).expect("second page") {
        DurableObjectCatalogPageOutcomeV2::Page(page) => page,
        other => panic!("expected page, got {other:?}"),
    };
    assert_eq!(second.items().len(), 1);
    assert!(second.items()[0].content_handle() > &cursor);
    assert!(second.next_after().is_none());

    let extra = DurableObjectCreateIntentV2::preallocate(namespace(), context("d"), managed("d"))
        .expect("extra intent");
    applied(catalog.reserve(&extra).expect("reserve extra"));
    assert!(matches!(
        catalog
            .scan_page(&second_request)
            .expect("generation check"),
        DurableObjectCatalogPageOutcomeV2::GenerationChanged { .. }
    ));
    assert!(DurableObjectCatalogPageRequestV2::new(namespace(), None, None, 0, 1).is_err());
    assert!(
        DurableObjectCatalogPageRequestV2::new(
            namespace(),
            None,
            None,
            1,
            MAX_DURABLE_OBJECT_CATALOG_PAGE_BYTES_V2 + 1,
        )
        .is_err()
    );
    let tiny_bytes = DurableObjectCatalogPageRequestV2::new(namespace(), None, None, 1, 1)
        .expect("tiny bounded request");
    assert!(catalog.scan_page(&tiny_bytes).is_err());
}

#[test]
fn head_publication_rejects_wrong_catalog_root_and_nonanchored_outcomes() {
    let catalog = CrashRecoverableTestCatalog::default();
    let mut kms = RecoverableTestKms::default();
    let intent =
        DurableObjectCreateIntentV2::preallocate(namespace(), context("owner"), managed("x"))
            .expect("intent");
    let reserved = applied(catalog.reserve(&intent).expect("reserve"));
    let key = kms
        .create_or_get(&intent.key_create_request().expect("request"))
        .expect("key");
    let key_request =
        DurableObjectKeyCreatedRequestV2::new(reserved.entry(), key.clone()).expect("key record");
    let key_created = applied(
        catalog
            .record_key_created(&key_request)
            .expect("record key"),
    );
    let encrypted = kms.seal(key, b"payload").expect("seal");
    let object_request = DurableEncryptedObjectCreateRequestV2::new(key_created.entry(), encrypted)
        .expect("object request");
    let stored = applied(
        catalog
            .create_or_get_object(&object_request)
            .expect("store"),
    );
    let mac = Arc::new(InMemoryHeadMacAuthorityV2::random("p4-wrong-root").expect("MAC"));
    let repository = NonProductionCompositeHeadRepositoryV2::random(
        "p4-wrong-root-repository",
        "test-process",
        mac.clone(),
    )
    .expect("repository");
    let wrong_head = CompositeStateHeadV2::initial(
        namespace(),
        head_payload(root("wrong-catalog")),
        mac.as_ref(),
    )
    .expect("wrong head");
    let wrong_request =
        CompositeHeadCasRequestV2::new(intent.head_publish_request_id().clone(), None, wrong_head)
            .expect("wrong request");
    assert!(
        DurableObjectHeadPublishRequestV2::new(
            stored.entry(),
            stored.snapshot().clone(),
            repository.provenance().clone(),
            wrong_request,
            mac.as_ref(),
        )
        .is_err()
    );

    let exact_head = CompositeStateHeadV2::initial(
        namespace(),
        head_payload(stored.snapshot().publication_root().expect("root")),
        mac.as_ref(),
    )
    .expect("exact head");
    let exact_request =
        CompositeHeadCasRequestV2::new(intent.head_publish_request_id().clone(), None, exact_head)
            .expect("exact request");
    let pending_request = DurableObjectHeadPublishRequestV2::new(
        stored.entry(),
        stored.snapshot().clone(),
        repository.provenance().clone(),
        exact_request,
        mac.as_ref(),
    )
    .expect("pending request");
    let pending = applied(
        catalog
            .prepare_head_publication(&pending_request)
            .expect("prepare"),
    );
    assert!(
        DurableObjectPublishedRequestV2::from_repository_outcome(
            pending.entry(),
            &CompositeHeadCasOutcomeV2::Unavailable,
            2,
            &repository,
        )
        .is_err()
    );
    assert!(
        DurableObjectPublishedRequestV2::from_repository_outcome(
            pending.entry(),
            &CompositeHeadCasOutcomeV2::Conflict { current: None },
            2,
            &repository,
        )
        .is_err()
    );
    let other_repository = NonProductionCompositeHeadRepositoryV2::random(
        "another-p4-repository",
        "test-process",
        mac,
    )
    .expect("other repository");
    let substituted = other_repository
        .compare_and_swap(pending_request.repository_request())
        .expect("substituted repository outcome");
    assert!(
        DurableObjectPublishedRequestV2::from_repository_outcome(
            pending.entry(),
            &substituted,
            2,
            &other_repository,
        )
        .is_err()
    );
}
