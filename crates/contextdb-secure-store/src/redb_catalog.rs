use std::collections::BTreeMap;
use std::fmt;
#[cfg(test)]
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use redb::{
    Database, Durability as RedbDurability, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityProvenanceV2, AuthorityRoleV2, ContentHandleV2, DurableEncryptedObjectCatalogV2,
    DurableEncryptedObjectCreateRequestV2, DurableObjectCatalogEntryV2,
    DurableObjectCatalogPageOutcomeV2, DurableObjectCatalogPageRequestV2,
    DurableObjectCatalogPageV2, DurableObjectCatalogSnapshotV2, DurableObjectCatalogSummaryV2,
    DurableObjectHeadPublishRequestV2, DurableObjectKeyCreatedRequestV2,
    DurableObjectLoadOutcomeV2, DurableObjectLoadRequestV2, DurableObjectMutationOutcomeV2,
    DurableObjectMutationV2, DurableObjectPublishedRequestV2, EncryptedContentV2,
    HeadMacAuthorityV2, KeyCatalogSnapshotV2, OperationRequestIdV2, Result, SecureStoreError,
    StateNamespaceV2, StateRootV2, canonical_json, object_create_intent_commitment, require_role,
};

const META_BYTES: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("secure_catalog_meta_bytes_v2");
const META_U64: TableDefinition<'static, &'static [u8], u64> =
    TableDefinition::new("secure_catalog_meta_u64_v2");
const ENTRIES: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("secure_catalog_entries_v2");
const OBJECTS: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("secure_catalog_objects_v2");
const REQUESTS: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("secure_catalog_requests_v2");
const GENERATIONS: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("secure_catalog_generations_v2");

const META_NAMESPACE: &[u8] = b"namespace";
const META_GENERATION: &[u8] = b"generation";
const INITIAL_CATALOG_GENERATION: u64 = 1;
const MAX_REDB_NAMESPACE_JSON_BYTES_V2: usize = 64 * 1024;
const MAX_REDB_OPAQUE_TEXT_BYTES_V2: usize = 256;

/// Maximum JSON bytes accepted for one persisted encrypted object.
///
/// Ciphertext is serialized as a JSON byte sequence by the P4 envelope, so the
/// wire bound is deliberately larger than the 16 MiB ciphertext bound.
pub const MAX_REDB_ENCRYPTED_OBJECT_JSON_BYTES_V2: usize = 96 * 1024 * 1024;
/// Maximum bytes accepted for one catalog generation-chain record.
pub const MAX_REDB_CATALOG_GENERATION_JSON_BYTES_V2: usize = 256 * 1024;
/// Maximum bytes accepted when recovering one caller-custodied rollback anchor.
pub const MAX_DURABLE_CATALOG_ANCHOR_JSON_BYTES_V2: usize = 64 * 1024;

/// Caller-custodied anti-rollback anchor for the durable catalog hash chain.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct DurableCatalogAnchorV2 {
    namespace: StateNamespaceV2,
    generation: u64,
    chain_root: StateRootV2,
}

impl DurableCatalogAnchorV2 {
    /// Recovers an externally retained anchor from a bounded buffer and binds
    /// it to the exact configured namespace.
    pub fn from_json_bounded(bytes: &[u8], namespace: &StateNamespaceV2) -> Result<Self> {
        if bytes.len() > MAX_DURABLE_CATALOG_ANCHOR_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "durable catalog anchor exceeds recovery byte limit".to_owned(),
            ));
        }
        let wire: DurableCatalogAnchorWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        if &wire.namespace != namespace || wire.generation == 0 {
            return Err(SecureStoreError::Integrity(
                "durable catalog anchor namespace or generation is invalid".to_owned(),
            ));
        }
        Ok(Self {
            namespace: wire.namespace,
            generation: wire.generation,
            chain_root: wire.chain_root,
        })
    }

    /// Returns the exact single-namespace catalog identity.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the monotonic local durability generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the chained commitment that must be held outside the database file.
    #[must_use]
    pub fn chain_root(&self) -> &StateRootV2 {
        &self.chain_root
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableCatalogAnchorWireV2 {
    namespace: StateNamespaceV2,
    generation: u64,
    chain_root: StateRootV2,
}

impl fmt::Debug for DurableCatalogAnchorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableCatalogAnchorV2")
            .field("namespace", &self.namespace)
            .field("generation", &self.generation)
            .field("chain_root", &"[COMMITMENT]")
            .finish()
    }
}

/// Result of recomputing the durable catalog from real redb table contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableCatalogDeepVerifyReportV2 {
    snapshot: DurableObjectCatalogSnapshotV2,
    anchor: DurableCatalogAnchorV2,
    entry_count: u64,
    encrypted_object_count: u64,
    request_binding_count: u64,
}

impl DurableCatalogDeepVerifyReportV2 {
    /// Returns roots recomputed from every persisted entry and ciphertext descriptor.
    #[must_use]
    pub fn snapshot(&self) -> &DurableObjectCatalogSnapshotV2 {
        &self.snapshot
    }

    /// Returns the current caller-custody anti-rollback anchor.
    #[must_use]
    pub fn anchor(&self) -> &DurableCatalogAnchorV2 {
        &self.anchor
    }

    /// Returns validated durable entry count.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns authenticated ciphertext-body count.
    #[must_use]
    pub const fn encrypted_object_count(&self) -> u64 {
        self.encrypted_object_count
    }

    /// Returns exact idempotency-binding count.
    #[must_use]
    pub const fn request_binding_count(&self) -> u64 {
        self.request_binding_count
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogGenerationRecordV2 {
    namespace: StateNamespaceV2,
    generation: u64,
    snapshot: DurableObjectCatalogSnapshotV2,
    durable_state_root: StateRootV2,
    previous_chain_root: Option<StateRootV2>,
    chain_root: StateRootV2,
}

impl CatalogGenerationRecordV2 {
    fn new(
        namespace: StateNamespaceV2,
        generation: u64,
        snapshot: DurableObjectCatalogSnapshotV2,
        durable_state_root: StateRootV2,
        previous_chain_root: Option<StateRootV2>,
    ) -> Result<Self> {
        let chain_root = catalog_chain_root(
            &namespace,
            generation,
            &snapshot,
            &durable_state_root,
            previous_chain_root.as_ref(),
        )?;
        Ok(Self {
            namespace,
            generation,
            snapshot,
            durable_state_root,
            previous_chain_root,
            chain_root,
        })
    }

    fn validate(
        &self,
        expected_namespace: &StateNamespaceV2,
        expected_generation: u64,
        expected_previous: Option<&StateRootV2>,
    ) -> Result<()> {
        if &self.namespace != expected_namespace
            || self.generation != expected_generation
            || self.snapshot.namespace() != expected_namespace
            || self.snapshot.generation() != expected_generation
            || self.previous_chain_root.as_ref() != expected_previous
            || self.chain_root
                != catalog_chain_root(
                    &self.namespace,
                    self.generation,
                    &self.snapshot,
                    &self.durable_state_root,
                    self.previous_chain_root.as_ref(),
                )?
        {
            return Err(SecureStoreError::Integrity(
                "durable catalog generation chain is missing, forked, or corrupt".to_owned(),
            ));
        }
        Ok(())
    }

    fn anchor(&self) -> DurableCatalogAnchorV2 {
        DurableCatalogAnchorV2 {
            namespace: self.namespace.clone(),
            generation: self.generation,
            chain_root: self.chain_root.clone(),
        }
    }
}

struct VerifiedCatalogStateV2 {
    entries: BTreeMap<ContentHandleV2, DurableObjectCatalogEntryV2>,
    objects: BTreeMap<ContentHandleV2, EncryptedContentV2>,
    requests: BTreeMap<OperationRequestIdV2, StateRootV2>,
    snapshot: DurableObjectCatalogSnapshotV2,
    anchor: DurableCatalogAnchorV2,
}

/// redb-backed, single-namespace implementation of the P4 durable catalog.
///
/// Every `Applied` mutation is one redb transaction committed with immediate
/// durability. The transaction atomically writes entry state, ciphertext when
/// present, exact request binding, the next deep-root snapshot, and a chained
/// generation record. This adapter provides real disk durability and recovery,
/// but it is not by itself a production hard-delete capability: KMS/HSM,
/// provider evidence, physical purge, and an independently custodied anchor are
/// separate required authorities.
pub struct RedbDurableEncryptedObjectCatalogV2 {
    database: Mutex<Database>,
    namespace: StateNamespaceV2,
    expected_repository_provenance: AuthorityProvenanceV2,
    mac_authority: Arc<dyn HeadMacAuthorityV2 + Send + Sync>,
}

impl RedbDurableEncryptedObjectCatalogV2 {
    /// Opens or creates a durable single-namespace catalog and performs a full
    /// recovery/deep-verify pass before returning.
    ///
    /// When `expected_anchor` is supplied, rollback, same-generation
    /// divergence, missing successor records, and chain forks fail closed. The
    /// host must retain that anchor outside this database file for the check to
    /// provide rollback resistance.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: StateNamespaceV2,
        expected_repository_provenance: AuthorityProvenanceV2,
        mac_authority: Arc<dyn HeadMacAuthorityV2 + Send + Sync>,
        expected_anchor: Option<&DurableCatalogAnchorV2>,
    ) -> Result<Self> {
        require_role(
            &expected_repository_provenance,
            AuthorityRoleV2::CompositeHeadRepository,
        )?;
        let database = Database::create(path).map_err(redb_unavailable)?;
        let catalog = Self {
            database: Mutex::new(database),
            namespace,
            expected_repository_provenance,
            mac_authority,
        };
        catalog.initialize_if_empty()?;
        catalog.deep_verify(expected_anchor)?;
        Ok(catalog)
    }

    /// Recomputes catalog roots, validates every ciphertext and idempotency
    /// binding, verifies the complete generation chain, and checks an optional
    /// caller-custodied anti-rollback anchor.
    pub fn deep_verify(
        &self,
        expected_anchor: Option<&DurableCatalogAnchorV2>,
    ) -> Result<DurableCatalogDeepVerifyReportV2> {
        let database = self.lock_database()?;
        let state = self.verify_database(&database, expected_anchor)?;
        Ok(DurableCatalogDeepVerifyReportV2 {
            snapshot: state.snapshot,
            anchor: state.anchor,
            entry_count: state.entries.len() as u64,
            encrypted_object_count: state.objects.len() as u64,
            request_binding_count: state.requests.len() as u64,
        })
    }

    /// Returns the current external-custody anchor after a full deep verify.
    pub fn current_anchor(&self) -> Result<DurableCatalogAnchorV2> {
        self.deep_verify(None).map(|report| report.anchor)
    }

    fn lock_database(&self) -> Result<MutexGuard<'_, Database>> {
        self.database.lock().map_err(|_| {
            SecureStoreError::StateConflict("durable catalog lock is poisoned".to_owned())
        })
    }

    fn initialize_if_empty(&self) -> Result<()> {
        let database = self.lock_database()?;
        let mut transaction = database.begin_write().map_err(redb_unavailable)?;
        let existing_namespace = {
            let table = transaction
                .open_table(META_BYTES)
                .map_err(redb_unavailable)?;
            table
                .get(META_NAMESPACE)
                .map_err(redb_unavailable)?
                .map(|value| bounded_copy(value.value(), MAX_REDB_NAMESPACE_JSON_BYTES_V2))
                .transpose()?
        };
        if let Some(bytes) = existing_namespace {
            let stored: StateNamespaceV2 =
                serde_json::from_slice(&bytes).map_err(|_| SecureStoreError::Serialization)?;
            if stored != self.namespace {
                return Err(SecureStoreError::Integrity(
                    "durable catalog namespace differs from configured namespace".to_owned(),
                ));
            }
            transaction.abort().map_err(redb_unavailable)?;
            return Ok(());
        }
        {
            let entries = transaction.open_table(ENTRIES).map_err(redb_unavailable)?;
            let objects = transaction.open_table(OBJECTS).map_err(redb_unavailable)?;
            let requests = transaction.open_table(REQUESTS).map_err(redb_unavailable)?;
            let generations = transaction
                .open_table(GENERATIONS)
                .map_err(redb_unavailable)?;
            if entries.len().map_err(redb_unavailable)? != 0
                || objects.len().map_err(redb_unavailable)? != 0
                || requests.len().map_err(redb_unavailable)? != 0
                || generations.len().map_err(redb_unavailable)? != 0
            {
                return Err(SecureStoreError::Integrity(
                    "uninitialized durable catalog contains orphan state".to_owned(),
                ));
            }
        }
        let snapshot = snapshot_from_entries(
            &self.namespace,
            INITIAL_CATALOG_GENERATION,
            &BTreeMap::new(),
        )?;
        let record = CatalogGenerationRecordV2::new(
            self.namespace.clone(),
            INITIAL_CATALOG_GENERATION,
            snapshot,
            durable_state_root(&BTreeMap::new(), &BTreeMap::new())?,
            None,
        )?;
        let namespace_bytes =
            serde_json::to_vec(&self.namespace).map_err(|_| SecureStoreError::Serialization)?;
        let record_bytes = encode_generation_record(&record)?;
        {
            let mut table = transaction
                .open_table(META_BYTES)
                .map_err(redb_unavailable)?;
            table
                .insert(META_NAMESPACE, namespace_bytes.as_slice())
                .map_err(redb_unavailable)?;
        }
        {
            let mut table = transaction.open_table(META_U64).map_err(redb_unavailable)?;
            table
                .insert(META_GENERATION, INITIAL_CATALOG_GENERATION)
                .map_err(redb_unavailable)?;
        }
        {
            let mut table = transaction
                .open_table(GENERATIONS)
                .map_err(redb_unavailable)?;
            table
                .insert(INITIAL_CATALOG_GENERATION, record_bytes.as_slice())
                .map_err(redb_unavailable)?;
        }
        transaction
            .set_durability(RedbDurability::Immediate)
            .map_err(redb_unavailable)?;
        transaction.commit().map_err(redb_unavailable)
    }

    fn verify_database(
        &self,
        database: &Database,
        expected_anchor: Option<&DurableCatalogAnchorV2>,
    ) -> Result<VerifiedCatalogStateV2> {
        let transaction = database.begin_read().map_err(redb_unavailable)?;
        let stored_namespace = {
            let table = transaction
                .open_table(META_BYTES)
                .map_err(redb_unavailable)?;
            table
                .get(META_NAMESPACE)
                .map_err(redb_unavailable)?
                .map(|value| bounded_copy(value.value(), MAX_REDB_NAMESPACE_JSON_BYTES_V2))
                .transpose()?
                .ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "durable catalog namespace metadata is missing".to_owned(),
                    )
                })?
        };
        let stored_namespace: StateNamespaceV2 = serde_json::from_slice(&stored_namespace)
            .map_err(|_| SecureStoreError::Serialization)?;
        if stored_namespace != self.namespace {
            return Err(SecureStoreError::Integrity(
                "durable catalog namespace metadata changed".to_owned(),
            ));
        }
        let generation = {
            let table = transaction.open_table(META_U64).map_err(redb_unavailable)?;
            table
                .get(META_GENERATION)
                .map_err(redb_unavailable)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "durable catalog generation metadata is missing".to_owned(),
                    )
                })?
        };
        if generation == 0 {
            return Err(SecureStoreError::Integrity(
                "durable catalog generation is invalid".to_owned(),
            ));
        }
        let entries = {
            let table = transaction.open_table(ENTRIES).map_err(redb_unavailable)?;
            collect_entries(
                &table,
                &self.expected_repository_provenance,
                self.mac_authority.as_ref(),
                &self.namespace,
            )?
        };
        let objects = {
            let table = transaction.open_table(OBJECTS).map_err(redb_unavailable)?;
            collect_objects(&table)?
        };
        validate_object_inventory(&entries, &objects)?;
        let requests = {
            let table = transaction.open_table(REQUESTS).map_err(redb_unavailable)?;
            collect_request_bindings(&table)?
        };
        let expected_requests = expected_request_bindings(&entries)?;
        if requests != expected_requests {
            return Err(SecureStoreError::Integrity(
                "durable catalog idempotency bindings are missing or orphaned".to_owned(),
            ));
        }
        let snapshot = snapshot_from_entries(&self.namespace, generation, &entries)?;
        let current_record = {
            let table = transaction
                .open_table(GENERATIONS)
                .map_err(redb_unavailable)?;
            if table.len().map_err(redb_unavailable)? != generation {
                return Err(SecureStoreError::Integrity(
                    "durable catalog generation history has gaps or extra records".to_owned(),
                ));
            }
            let mut previous: Option<StateRootV2> = None;
            let mut current: Option<CatalogGenerationRecordV2> = None;
            for sequence in 1..=generation {
                let value = table
                    .get(sequence)
                    .map_err(redb_unavailable)?
                    .ok_or_else(|| {
                        SecureStoreError::Integrity(
                            "durable catalog generation history has a gap".to_owned(),
                        )
                    })?;
                let record = decode_generation_record(value.value())?;
                record.validate(&self.namespace, sequence, previous.as_ref())?;
                previous = Some(record.chain_root.clone());
                current = Some(record);
            }
            current.ok_or_else(|| {
                SecureStoreError::Integrity(
                    "durable catalog current generation record is missing".to_owned(),
                )
            })?
        };
        if current_record.snapshot != snapshot
            || current_record.durable_state_root != durable_state_root(&entries, &requests)?
        {
            return Err(SecureStoreError::Integrity(
                "durable catalog roots differ from recomputed table state".to_owned(),
            ));
        }
        let anchor = current_record.anchor();
        verify_expected_anchor(expected_anchor, &anchor, &transaction)?;
        Ok(VerifiedCatalogStateV2 {
            entries,
            objects,
            requests,
            snapshot,
            anchor,
        })
    }

    fn verified_state_locked(&self, database: &Database) -> Result<VerifiedCatalogStateV2> {
        self.verify_database(database, None)
    }

    #[cfg(test)]
    pub(crate) fn hold_uncommitted_reservation_for_process_kill_test(
        &self,
        intent: &crate::DurableObjectCreateIntentV2,
    ) -> Result<()> {
        if intent.namespace() != &self.namespace {
            return Err(SecureStoreError::Integrity(
                "test reservation belongs to another namespace".to_owned(),
            ));
        }
        let database = self.lock_database()?;
        let state = self.verified_state_locked(&database)?;
        if state.entries.contains_key(intent.content_handle()) {
            return Err(SecureStoreError::StateConflict(
                "test reservation already exists".to_owned(),
            ));
        }
        let entry = DurableObjectCatalogEntryV2::reserved(intent.clone())?;
        let entry_bytes = encode_entry(&entry)?;
        let transaction = database.begin_write().map_err(redb_unavailable)?;
        {
            let mut table = transaction.open_table(ENTRIES).map_err(redb_unavailable)?;
            table
                .insert(
                    intent.content_handle().as_str().as_bytes(),
                    entry_bytes.as_slice(),
                )
                .map_err(redb_unavailable)?;
        }
        {
            let mut table = transaction.open_table(REQUESTS).map_err(redb_unavailable)?;
            table
                .insert(
                    intent.reservation_request_id().as_str().as_bytes(),
                    intent.commitment()?.as_str().as_bytes(),
                )
                .map_err(redb_unavailable)?;
        }
        println!("CONTEXTDB_P5_UNCOMMITTED_READY");
        std::io::stdout().flush().map_err(|_| {
            SecureStoreError::StateConflict("test process stdout is unavailable".to_owned())
        })?;
        loop {
            std::thread::park();
        }
    }

    fn commit_entry_update(
        &self,
        database: &Database,
        state: &VerifiedCatalogStateV2,
        entry: DurableObjectCatalogEntryV2,
        encrypted_object: Option<&EncryptedContentV2>,
        request_binding: Option<(&OperationRequestIdV2, &StateRootV2)>,
    ) -> Result<DurableObjectMutationV2> {
        let next_generation = state.snapshot.generation().checked_add(1).ok_or_else(|| {
            SecureStoreError::StateConflict("durable catalog generation exhausted".to_owned())
        })?;
        let mut entries = state.entries.clone();
        entries.insert(entry.intent().content_handle().clone(), entry.clone());
        let mut requests = state.requests.clone();
        if let Some((request_id, commitment)) = request_binding {
            requests.insert(request_id.clone(), commitment.clone());
        }
        let snapshot = snapshot_from_entries(&self.namespace, next_generation, &entries)?;
        let record = CatalogGenerationRecordV2::new(
            self.namespace.clone(),
            next_generation,
            snapshot.clone(),
            durable_state_root(&entries, &requests)?,
            Some(state.anchor.chain_root.clone()),
        )?;
        let entry_bytes = encode_entry(&entry)?;
        let object_bytes = encrypted_object.map(encode_object).transpose()?;
        let record_bytes = encode_generation_record(&record)?;

        let mut transaction = database.begin_write().map_err(redb_unavailable)?;
        let observed_generation = {
            let table = transaction.open_table(META_U64).map_err(redb_unavailable)?;
            table
                .get(META_GENERATION)
                .map_err(redb_unavailable)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "durable catalog generation vanished before mutation".to_owned(),
                    )
                })?
        };
        if observed_generation != state.snapshot.generation() {
            return Err(SecureStoreError::StateConflict(
                "durable catalog generation changed during mutation".to_owned(),
            ));
        }
        let handle_key = entry.intent().content_handle().as_str().as_bytes();
        {
            let mut table = transaction.open_table(ENTRIES).map_err(redb_unavailable)?;
            table
                .insert(handle_key, entry_bytes.as_slice())
                .map_err(redb_unavailable)?;
        }
        if let Some(bytes) = object_bytes.as_ref() {
            let mut table = transaction.open_table(OBJECTS).map_err(redb_unavailable)?;
            table
                .insert(handle_key, bytes.as_slice())
                .map_err(redb_unavailable)?;
        }
        if let Some((request_id, commitment)) = request_binding {
            let mut table = transaction.open_table(REQUESTS).map_err(redb_unavailable)?;
            table
                .insert(
                    request_id.as_str().as_bytes(),
                    commitment.as_str().as_bytes(),
                )
                .map_err(redb_unavailable)?;
        }
        {
            let mut table = transaction
                .open_table(GENERATIONS)
                .map_err(redb_unavailable)?;
            table
                .insert(next_generation, record_bytes.as_slice())
                .map_err(redb_unavailable)?;
        }
        {
            let mut table = transaction.open_table(META_U64).map_err(redb_unavailable)?;
            table
                .insert(META_GENERATION, next_generation)
                .map_err(redb_unavailable)?;
        }
        transaction
            .set_durability(RedbDurability::Immediate)
            .map_err(redb_unavailable)?;
        transaction.commit().map_err(redb_unavailable)?;
        DurableObjectMutationV2::new(entry, snapshot)
    }
}

impl fmt::Debug for RedbDurableEncryptedObjectCatalogV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedbDurableEncryptedObjectCatalogV2")
            .field("namespace", &self.namespace)
            .field(
                "expected_repository_provenance",
                &self.expected_repository_provenance,
            )
            .finish_non_exhaustive()
    }
}

impl DurableEncryptedObjectCatalogV2 for RedbDurableEncryptedObjectCatalogV2 {
    fn reserve(
        &self,
        intent: &crate::DurableObjectCreateIntentV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        if intent.namespace() != &self.namespace {
            return Err(SecureStoreError::Integrity(
                "reservation belongs to another durable catalog namespace".to_owned(),
            ));
        }
        let database = self.lock_database()?;
        let state = self.verified_state_locked(&database)?;
        if let Some(existing) = state.entries.get(intent.content_handle()) {
            return if existing.intent() == intent {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    DurableObjectMutationV2::new(existing.clone(), state.snapshot)?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: existing.root()?,
                })
            };
        }
        let commitment = intent.commitment()?;
        if let Some(existing) = state.requests.get(intent.reservation_request_id()) {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: existing.clone(),
            });
        }
        let entry = DurableObjectCatalogEntryV2::reserved(intent.clone())?;
        let mutation = self.commit_entry_update(
            &database,
            &state,
            entry,
            None,
            Some((intent.reservation_request_id(), &commitment)),
        )?;
        Ok(DurableObjectMutationOutcomeV2::Applied(mutation))
    }

    fn record_key_created(
        &self,
        request: &DurableObjectKeyCreatedRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let database = self.lock_database()?;
        let state = self.verified_state_locked(&database)?;
        let current = state.entries.get(request.content_handle()).ok_or_else(|| {
            SecureStoreError::StateConflict("durable reservation is missing".to_owned())
        })?;
        if current.stage() >= crate::DurableObjectCatalogStageV2::KeyCreated {
            return if current.key() == Some(request.descriptor()) {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    DurableObjectMutationV2::new(current.clone(), state.snapshot)?,
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
        if let Some(existing) = state.requests.get(request.key_create_request_id()) {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: existing.clone(),
            });
        }
        let next = current.record_key_created(request.descriptor().clone())?;
        let mutation = self.commit_entry_update(
            &database,
            &state,
            next,
            None,
            Some((
                request.key_create_request_id(),
                request.key_create_intent_commitment(),
            )),
        )?;
        Ok(DurableObjectMutationOutcomeV2::Applied(mutation))
    }

    fn create_or_get_object(
        &self,
        request: &DurableEncryptedObjectCreateRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let database = self.lock_database()?;
        let state = self.verified_state_locked(&database)?;
        let handle = request.intent().content_handle();
        let current = state.entries.get(handle).ok_or_else(|| {
            SecureStoreError::StateConflict("durable reservation is missing".to_owned())
        })?;
        if current.stage() >= crate::DurableObjectCatalogStageV2::ObjectStored {
            let exact = current.stored() == Some(request.descriptor())
                && state.objects.get(handle) == Some(request.encrypted_object());
            return if exact {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    DurableObjectMutationV2::new(current.clone(), state.snapshot)?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: current.root()?,
                })
            };
        }
        if let Some(existing) = state.requests.get(request.request_id()) {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: existing.clone(),
            });
        }
        let next = current.record_object_stored(request)?;
        let mutation = self.commit_entry_update(
            &database,
            &state,
            next,
            Some(request.encrypted_object()),
            Some((request.request_id(), request.request_intent_commitment())),
        )?;
        Ok(DurableObjectMutationOutcomeV2::Applied(mutation))
    }

    fn prepare_head_publication(
        &self,
        request: &DurableObjectHeadPublishRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let database = self.lock_database()?;
        let state = self.verified_state_locked(&database)?;
        let current = state.entries.get(request.content_handle()).ok_or_else(|| {
            SecureStoreError::StateConflict("durable object is missing".to_owned())
        })?;
        if current.stage() >= crate::DurableObjectCatalogStageV2::PublicationPending {
            return if current.pending_publication() == Some(request) {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    DurableObjectMutationV2::new(current.clone(), state.snapshot)?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: current.root()?,
                })
            };
        }
        if state.snapshot != *request.catalog_snapshot()
            || request.expected_repository_provenance() != &self.expected_repository_provenance
        {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: current.root()?,
            });
        }
        let commitment = request.intent_commitment()?;
        let request_id = request.repository_request().request_id();
        if let Some(existing) = state.requests.get(request_id) {
            return Ok(DurableObjectMutationOutcomeV2::Conflict {
                existing_commitment: existing.clone(),
            });
        }
        let next = current.record_publication_pending(request)?;
        let mutation = self.commit_entry_update(
            &database,
            &state,
            next,
            None,
            Some((request_id, &commitment)),
        )?;
        Ok(DurableObjectMutationOutcomeV2::Applied(mutation))
    }

    fn record_head_published(
        &self,
        request: &DurableObjectPublishedRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2> {
        let database = self.lock_database()?;
        let state = self.verified_state_locked(&database)?;
        let current = state.entries.get(request.content_handle()).ok_or_else(|| {
            SecureStoreError::StateConflict("durable object is missing".to_owned())
        })?;
        if current.stage() == crate::DurableObjectCatalogStageV2::Published {
            return if current.published_anchor() == Some(request.anchored_head().anchor()) {
                Ok(DurableObjectMutationOutcomeV2::AlreadyApplied(
                    DurableObjectMutationV2::new(current.clone(), state.snapshot)?,
                ))
            } else {
                Ok(DurableObjectMutationOutcomeV2::Conflict {
                    existing_commitment: current.root()?,
                })
            };
        }
        let next = current.record_published_request(request)?;
        let mutation = self.commit_entry_update(&database, &state, next, None, None)?;
        Ok(DurableObjectMutationOutcomeV2::Applied(mutation))
    }

    fn load(&self, request: &DurableObjectLoadRequestV2) -> Result<DurableObjectLoadOutcomeV2> {
        if request.namespace() != &self.namespace {
            return Err(SecureStoreError::Integrity(
                "durable catalog point read targets another namespace".to_owned(),
            ));
        }
        let database = self.lock_database()?;
        let state = self.verified_state_locked(&database)?;
        let Some(entry) = state.entries.get(request.content_handle()).cloned() else {
            return Ok(DurableObjectLoadOutcomeV2::Missing);
        };
        let outcome = DurableObjectLoadOutcomeV2::Found {
            encrypted_object: state
                .objects
                .get(request.content_handle())
                .cloned()
                .map(Box::new),
            entry: Box::new(entry),
            snapshot: state.snapshot,
        };
        outcome.validate_for(request)?;
        Ok(outcome)
    }

    fn scan_page(
        &self,
        request: &DurableObjectCatalogPageRequestV2,
    ) -> Result<DurableObjectCatalogPageOutcomeV2> {
        if request.namespace() != &self.namespace {
            return Err(SecureStoreError::Integrity(
                "durable catalog scan targets another namespace".to_owned(),
            ));
        }
        let database = self.lock_database()?;
        let state = self.verified_state_locked(&database)?;
        if request
            .expected_generation()
            .is_some_and(|expected| expected != state.snapshot.generation())
        {
            return Ok(DurableObjectCatalogPageOutcomeV2::GenerationChanged {
                current_generation: state.snapshot.generation(),
            });
        }
        let mut candidates = state
            .entries
            .values()
            .filter(|entry| {
                request
                    .after()
                    .is_none_or(|after| entry.intent().content_handle() > after)
            })
            .map(DurableObjectCatalogSummaryV2::from_entry)
            .collect::<Result<Vec<_>>>()?;
        let has_more = candidates.len() > request.max_items();
        candidates.truncate(request.max_items());
        let page = DurableObjectCatalogPageV2::new(request, state.snapshot, candidates, has_more)?;
        Ok(DurableObjectCatalogPageOutcomeV2::Page(page))
    }
}

fn collect_entries<T>(
    table: &T,
    provenance: &AuthorityProvenanceV2,
    mac_authority: &dyn HeadMacAuthorityV2,
    namespace: &StateNamespaceV2,
) -> Result<BTreeMap<ContentHandleV2, DurableObjectCatalogEntryV2>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut entries = BTreeMap::new();
    for item in table.iter().map_err(redb_unavailable)? {
        let (key, value) = item.map_err(redb_unavailable)?;
        if key.value().len() > MAX_REDB_OPAQUE_TEXT_BYTES_V2 {
            return Err(SecureStoreError::Integrity(
                "durable catalog entry key exceeds its recovery bound".to_owned(),
            ));
        }
        let handle = ContentHandleV2::parse(
            std::str::from_utf8(key.value())
                .map_err(|_| {
                    SecureStoreError::Integrity(
                        "durable catalog entry key is not canonical UTF-8".to_owned(),
                    )
                })?
                .to_owned(),
        )?;
        let entry = DurableObjectCatalogEntryV2::from_json_bounded(
            value.value(),
            provenance,
            mac_authority,
        )?;
        if entry.intent().namespace() != namespace
            || entry.intent().content_handle() != &handle
            || entries.insert(handle, entry).is_some()
        {
            return Err(SecureStoreError::Integrity(
                "durable catalog entry key, namespace, or uniqueness is invalid".to_owned(),
            ));
        }
    }
    Ok(entries)
}

fn collect_objects<T>(table: &T) -> Result<BTreeMap<ContentHandleV2, EncryptedContentV2>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut objects = BTreeMap::new();
    for item in table.iter().map_err(redb_unavailable)? {
        let (key, value) = item.map_err(redb_unavailable)?;
        if key.value().len() > MAX_REDB_OPAQUE_TEXT_BYTES_V2 {
            return Err(SecureStoreError::Integrity(
                "durable ciphertext key exceeds its recovery bound".to_owned(),
            ));
        }
        let handle = ContentHandleV2::parse(
            std::str::from_utf8(key.value())
                .map_err(|_| {
                    SecureStoreError::Integrity(
                        "durable ciphertext key is not canonical UTF-8".to_owned(),
                    )
                })?
                .to_owned(),
        )?;
        let encrypted = decode_object(value.value())?;
        if encrypted.header().content_handle() != &handle
            || objects.insert(handle, encrypted).is_some()
        {
            return Err(SecureStoreError::Integrity(
                "durable ciphertext key or uniqueness is invalid".to_owned(),
            ));
        }
    }
    Ok(objects)
}

fn collect_request_bindings<T>(table: &T) -> Result<BTreeMap<OperationRequestIdV2, StateRootV2>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut requests = BTreeMap::new();
    for item in table.iter().map_err(redb_unavailable)? {
        let (key, value) = item.map_err(redb_unavailable)?;
        if key.value().len() > MAX_REDB_OPAQUE_TEXT_BYTES_V2
            || value.value().len() > MAX_REDB_OPAQUE_TEXT_BYTES_V2
        {
            return Err(SecureStoreError::Integrity(
                "durable request binding exceeds its recovery bound".to_owned(),
            ));
        }
        let request = OperationRequestIdV2::parse(
            std::str::from_utf8(key.value())
                .map_err(|_| {
                    SecureStoreError::Integrity(
                        "durable request key is not canonical UTF-8".to_owned(),
                    )
                })?
                .to_owned(),
        )?;
        let root = StateRootV2::parse(
            std::str::from_utf8(value.value())
                .map_err(|_| {
                    SecureStoreError::Integrity(
                        "durable request commitment is not canonical UTF-8".to_owned(),
                    )
                })?
                .to_owned(),
        )?;
        if requests.insert(request, root).is_some() {
            return Err(SecureStoreError::Integrity(
                "durable request binding is duplicated".to_owned(),
            ));
        }
    }
    Ok(requests)
}

fn expected_request_bindings(
    entries: &BTreeMap<ContentHandleV2, DurableObjectCatalogEntryV2>,
) -> Result<BTreeMap<OperationRequestIdV2, StateRootV2>> {
    let mut expected = BTreeMap::new();
    for entry in entries.values() {
        insert_expected_request(
            &mut expected,
            entry.intent().reservation_request_id(),
            entry.intent().commitment()?,
        )?;
        if entry.key().is_some() {
            insert_expected_request(
                &mut expected,
                entry.intent().key_create_request_id(),
                entry.intent().key_create_request()?.intent_commitment()?,
            )?;
        }
        if let Some(stored) = entry.stored() {
            insert_expected_request(
                &mut expected,
                entry.intent().object_create_request_id(),
                object_create_intent_commitment(entry.intent(), stored)?,
            )?;
        }
        if let Some(pending) = entry.pending_publication() {
            insert_expected_request(
                &mut expected,
                entry.intent().head_publish_request_id(),
                pending.intent_commitment()?,
            )?;
        }
    }
    Ok(expected)
}

fn insert_expected_request(
    expected: &mut BTreeMap<OperationRequestIdV2, StateRootV2>,
    request: &OperationRequestIdV2,
    root: StateRootV2,
) -> Result<()> {
    if expected.insert(request.clone(), root).is_some() {
        return Err(SecureStoreError::Integrity(
            "durable catalog reuses an idempotency identity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_object_inventory(
    entries: &BTreeMap<ContentHandleV2, DurableObjectCatalogEntryV2>,
    objects: &BTreeMap<ContentHandleV2, EncryptedContentV2>,
) -> Result<()> {
    for (handle, entry) in entries {
        match (entry.stored(), objects.get(handle)) {
            (None, None) => {}
            (Some(descriptor), Some(encrypted)) => {
                descriptor.validate_encrypted_object(encrypted)?;
            }
            _ => {
                return Err(SecureStoreError::Integrity(
                    "durable ciphertext body is missing or orphaned".to_owned(),
                ));
            }
        }
    }
    if objects.len()
        != entries
            .values()
            .filter(|entry| entry.stored().is_some())
            .count()
    {
        return Err(SecureStoreError::Integrity(
            "durable ciphertext table contains orphan objects".to_owned(),
        ));
    }
    Ok(())
}

fn snapshot_from_entries(
    namespace: &StateNamespaceV2,
    generation: u64,
    entries: &BTreeMap<ContentHandleV2, DurableObjectCatalogEntryV2>,
) -> Result<DurableObjectCatalogSnapshotV2> {
    let keys = entries
        .values()
        .filter_map(|entry| entry.key().cloned())
        .collect::<Vec<_>>();
    let key_catalog_root = KeyCatalogSnapshotV2::try_new(keys)?.root()?;
    let stored = entries
        .values()
        .filter_map(|entry| entry.stored().cloned())
        .collect::<Vec<_>>();
    let encrypted_object_catalog_root = StateRootV2::commit(
        "redb-encrypted-object-catalog-v2",
        &canonical_json(&stored)?,
    )?;
    DurableObjectCatalogSnapshotV2::new(
        namespace.clone(),
        generation,
        key_catalog_root,
        encrypted_object_catalog_root,
    )
}

fn verify_expected_anchor(
    expected: Option<&DurableCatalogAnchorV2>,
    current: &DurableCatalogAnchorV2,
    transaction: &redb::ReadTransaction,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.namespace != current.namespace {
        return Err(SecureStoreError::Integrity(
            "durable catalog rollback anchor belongs to another namespace".to_owned(),
        ));
    }
    if current.generation < expected.generation {
        return Err(SecureStoreError::StateConflict(
            "durable catalog rollback detected".to_owned(),
        ));
    }
    let table = transaction
        .open_table(GENERATIONS)
        .map_err(redb_unavailable)?;
    let value = table
        .get(expected.generation)
        .map_err(redb_unavailable)?
        .ok_or_else(|| {
            SecureStoreError::Integrity(
                "durable catalog expected anchor generation is missing".to_owned(),
            )
        })?;
    let record = decode_generation_record(value.value())?;
    if record.chain_root != expected.chain_root {
        return Err(SecureStoreError::Integrity(
            "durable catalog diverged from the caller-custodied anchor".to_owned(),
        ));
    }
    Ok(())
}

fn catalog_chain_root(
    namespace: &StateNamespaceV2,
    generation: u64,
    snapshot: &DurableObjectCatalogSnapshotV2,
    durable_state_root: &StateRootV2,
    previous_chain_root: Option<&StateRootV2>,
) -> Result<StateRootV2> {
    #[derive(Serialize)]
    struct ChainPayload<'a> {
        namespace: &'a StateNamespaceV2,
        generation: u64,
        snapshot: &'a DurableObjectCatalogSnapshotV2,
        durable_state_root: &'a StateRootV2,
        previous_chain_root: Option<&'a StateRootV2>,
    }
    StateRootV2::commit(
        "redb-durable-catalog-generation-chain-v2",
        &canonical_json(&ChainPayload {
            namespace,
            generation,
            snapshot,
            durable_state_root,
            previous_chain_root,
        })?,
    )
}

fn durable_state_root(
    entries: &BTreeMap<ContentHandleV2, DurableObjectCatalogEntryV2>,
    requests: &BTreeMap<OperationRequestIdV2, StateRootV2>,
) -> Result<StateRootV2> {
    #[derive(Serialize)]
    struct DurableState<'a> {
        entries: &'a BTreeMap<ContentHandleV2, DurableObjectCatalogEntryV2>,
        request_bindings: &'a BTreeMap<OperationRequestIdV2, StateRootV2>,
    }
    StateRootV2::commit(
        "redb-durable-catalog-state-v2",
        &canonical_json(&DurableState {
            entries,
            request_bindings: requests,
        })?,
    )
}

fn encode_entry(entry: &DurableObjectCatalogEntryV2) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(entry).map_err(|_| SecureStoreError::Serialization)?;
    if bytes.len() > crate::MAX_DURABLE_OBJECT_ENTRY_JSON_BYTES_V2 {
        return Err(SecureStoreError::InvalidInput(
            "durable object entry exceeds storage byte limit".to_owned(),
        ));
    }
    Ok(bytes)
}

fn encode_object(object: &EncryptedContentV2) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(object).map_err(|_| SecureStoreError::Serialization)?;
    if bytes.len() > MAX_REDB_ENCRYPTED_OBJECT_JSON_BYTES_V2 {
        return Err(SecureStoreError::InvalidInput(
            "durable encrypted object exceeds storage byte limit".to_owned(),
        ));
    }
    Ok(bytes)
}

fn decode_object(bytes: &[u8]) -> Result<EncryptedContentV2> {
    if bytes.len() > MAX_REDB_ENCRYPTED_OBJECT_JSON_BYTES_V2 {
        return Err(SecureStoreError::InvalidInput(
            "durable encrypted object exceeds recovery byte limit".to_owned(),
        ));
    }
    serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)
}

fn encode_generation_record(record: &CatalogGenerationRecordV2) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(record).map_err(|_| SecureStoreError::Serialization)?;
    if bytes.len() > MAX_REDB_CATALOG_GENERATION_JSON_BYTES_V2 {
        return Err(SecureStoreError::InvalidInput(
            "durable catalog generation record exceeds storage byte limit".to_owned(),
        ));
    }
    Ok(bytes)
}

fn decode_generation_record(bytes: &[u8]) -> Result<CatalogGenerationRecordV2> {
    if bytes.len() > MAX_REDB_CATALOG_GENERATION_JSON_BYTES_V2 {
        return Err(SecureStoreError::InvalidInput(
            "durable catalog generation record exceeds recovery byte limit".to_owned(),
        ));
    }
    serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)
}

fn bounded_copy(bytes: &[u8], maximum: usize) -> Result<Vec<u8>> {
    if bytes.len() > maximum {
        return Err(SecureStoreError::InvalidInput(
            "durable redb metadata exceeds its recovery byte limit".to_owned(),
        ));
    }
    Ok(bytes.to_vec())
}

fn redb_unavailable(error: impl fmt::Display) -> SecureStoreError {
    SecureStoreError::StateConflict(format!("durable redb catalog unavailable: {error}"))
}
