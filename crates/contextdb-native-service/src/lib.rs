//! Incremental durable application service for ContextDB.
//!
//! The reference engine is intentionally clone-on-write and the original CLI
//! composition persists a complete logical archive after each semantic write.
//! This crate provides the complementary production-shaped path: policy labels,
//! revision content, idempotency receipts, workspace sequence mappings, and the
//! content-free event chain are updated in one synchronized Fjall transaction.
//! Authorization is evaluated from the label keyspace before record content is
//! materialized.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(test)]
mod adapter_tests;
mod assertions;
pub use assertions::{
    NativeAssertionBatchKind, NativeAssertionCopyKind, NativeAssertionKeyInventory,
    NativeAssertionPruningReceipt, NativeAssertionRemovalWitnessReceipt,
    NativeAssertionValueDisposition, NativeAssertionValueInventory,
    NativeAssertionValueWitnessReceipt, NativeAssertionVersionOwnership,
};
mod backup;
mod capture;
mod custody;
mod deletion;
mod encryption;
mod indexed_provider;
mod lease;
mod owned;
mod payload;
mod prepare;
mod provider;
mod publication;
mod raw;
mod raw_index;
mod record_journal;
pub use record_journal::NativeRecordControlPreparationReceipt;
pub use record_journal::controls::witness::pruning::NativeRecordPruningReceipt;
pub use record_journal::controls::witness::{
    NativeRecordBodyKind, NativeRecordKeyInventory, NativeRecordRemovalWitnessReceipt,
};
mod record_sources;
pub use record_sources::{
    NativePendingRecordWrites, NativeRecordSourceProgress, NativeRecordSourceReceipt,
    NativeRecordSourceWorkspaceReceipt, NativeRecordWriteReceipt,
    NativeRecordWriteRecoveryProgress,
};
mod retention;
mod suppression;

pub use backup::{
    NATIVE_BACKUP_FORMAT, NATIVE_CONTINUOUS_BACKUP_FORMAT, NATIVE_ENCRYPTED_BACKUP_FORMAT,
};
pub use capture::{CAPTURE_MAX_INLINE_BYTES, CAPTURE_MAX_PRODUCER_GAPS};
pub use custody::CustodyProgress;
pub use deletion::{NativeDeletionLineage, NativeDeletionSource};
pub use encryption::{
    CustodyMasterKey, NativeBackupCatalogPage, NativeBackupRegistration, NativeCustodyKeys,
    NativeKeyAllocation, NativeKeyCatalogPage, NativeKeyUseAddressInventory,
    NativeKeyUseCatalogPage, NativeKeyUseChange, NativeKeyUseChangesPage, NativeKeyUseInventory,
    NativeKeyUseOutcome, NativeKeyUseReceipt, NativeKeyUseTransaction, NativeKeyUseTransition,
    NativeKeyUseVersion,
};
pub use indexed_provider::{NativeIndexedRecallProvider, NativeIndexedView};
pub use payload::{
    CAPTURE_MAX_PAYLOAD_BYTES, CAPTURE_MAX_REQUEST_PARTS, NativePayloadKeyInventory,
    NativePayloadPruningProgress,
};
pub use raw_index::{
    NativeRawCopyKind, NativeRawCopyObservation, NativeRawCopyReceipt, NativeRawCopyWitness,
    NativeRawSourceControl, NativeRawValueVersion, OriginalRevocationReceipt,
    RawProjectionProgress, RawReclaimProgress,
};
pub use raw_index::{
    NativeRawGenerationRole, NativeRawIndexGeneration, NativeRawIndexInventoryPage,
    NativeRawIndexInventoryReceipt, NativeRawIndexInventoryWitness, NativeRawIndexKeyInventory,
    NativeRawIndexSnapshot,
};
pub use raw_index::{
    NativeRawKeyFamily, NativeRawKeyInventory, NativeRawRemovalCopy, NativeRawRemovalCopyPage,
};
pub use retention::{
    NativePrimaryKeyAction, NativePrimaryKeyDisposition, NativePrimaryKeyInventory,
    NativePrimaryKeyRemovalReceipt, NativePrimaryKeyRemovalWitness,
    NativeRemovalPreparationReceipt, NativeRemovalRequestReceipt, NativeSourcePruningReceipt,
};
pub use suppression::{NativeSuppressionLedger, SuppressionProgress};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::mem::size_of;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use contextdb_service::{
    AccessPolicy, AuthenticatedRequestContext, BackupResponse, Capability, CognitiveMemoryService,
    CompileContextRequest, CompileContextResponse, Consent, CorrectRequest, CreateBackupRequest,
    ErrorCode, ExplainRecallRequest, ExportRequest, ExportResponse, ForgetMode, ForgetRequest,
    GetMemoryRequest, GetStatusRequest, GetTimelineRequest, ImportRequest, ImportResponse,
    MaintenanceRequest, MaintenanceResponse, MemoryDocument, MemoryLifecycle, MemoryRecord,
    MemoryRecordKind, MutationResponse, ObserveRequest, ObserveResponse, ProposeMemoryRequest,
    ProposeMemoryResponse, PublishMemoryRequest, RecallCandidatesRequest, RecallCandidatesResponse,
    RecallHit, RecallRequest, RecallResponse, RecallTrace, RequestContext, RestoreBackupRequest,
    RestoreBackupResponse, Sensitivity, ServiceError, ServiceResult, StatusResponse,
    StructuredMemoryKind, TimelineResponse, TraverseDirection, TraverseRequest, TraverseResponse,
    VerifyRequest, VerifyResponse, Watermarks, service_capability_manifest_v1,
};
use contextdb_storage::{
    CompactRequest, Durability, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector,
    StorageEngine, VerifyMode, WriteTransaction,
};
use encryption::NativeStorage;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use provider::NativeRecallProvider;

const SCHEMA_VERSION: u16 = 1;
const FORMAT_NAME: &str = "contextdb.native-service.v1";
const PROFILE: &str = "native-fjall-incremental-v1";
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUERY_BYTES: usize = 32 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_POLICY_VALUES: usize = 4_096;
const MAX_AUTHORIZED_CANDIDATES: usize = 100_000;
const MAX_HIERARCHY_PARENTS: usize = 16;
const HIERARCHY_PARENT_PREDICATE: &str = "contextdb.hierarchy.parent";
const CANDIDATE_HIERARCHY_PARENT_PREDICATE: &str = "contextdb.candidate_hierarchy.parent";
const CANDIDATE_ROLE_ATTRIBUTE: &str = "contextdb.candidate_role";
const CANDIDATE_MEMORY_ROLE: &str = "memory_proposal";
const CANDIDATE_EDGE_ROLE: &str = "hierarchy_edge_proposal";
const SCAN_PAGE_ENTRIES: usize = 4_096;
const SCAN_PAGE_BYTES: usize = 8 * 1024 * 1024;
const META_MANIFEST_KEY: &[u8] = b"manifest/v1";
const META_GLOBAL_HEAD_KEY: &[u8] = b"global-head/v1";
const META_EVENT_DIGEST_KEY: &[u8] = b"event-digest/v1";

fn native_capability_manifest(
    external_suppression: bool,
    encrypted: bool,
) -> contextdb_service::CapabilityManifestV1 {
    let mut available = vec![
        "admin_native_logical_backup",
        "admin_native_pristine_restore",
        "bounded_publication_admission",
        "candidate_hierarchy_dag",
        "capture_custody_migration",
        "capture_custody_propagation",
        "compact",
        "context_pack_recall",
        "durable_fjall_storage",
        "native_service_executor",
        "policy_first_candidate_recall",
        "policy_first_candidate_traversal",
        "quarantined_memory_proposals",
        "raw_index_generation_gc",
        "restart_verification",
        "status",
        "verify",
    ];
    if external_suppression {
        available.push("restore_current_suppression_ledger");
    }
    if encrypted {
        available.push("encrypted_custody_domains");
    }
    service_capability_manifest_v1(PROFILE, &available, &[])
}

#[derive(Clone, Debug)]
struct Keyspaces {
    meta: Keyspace,
    workspace: Keyspace,
    workspace_map: Keyspace,
    policy_head: Keyspace,
    policy_history: Keyspace,
    policy_route: Keyspace,
    content_history: Keyspace,
    observations_policy: Keyspace,
    observations_content: Keyspace,
    idempotency: Keyspace,
    events: Keyspace,
    continuous: Keyspace,
}

impl Keyspaces {
    fn new() -> ServiceResult<Self> {
        Ok(Self {
            meta: keyspace("contextdb_native_meta")?,
            workspace: keyspace("contextdb_native_workspace")?,
            workspace_map: keyspace("contextdb_native_workspace_map")?,
            policy_head: keyspace("contextdb_native_policy_head")?,
            policy_history: keyspace("contextdb_native_policy_history")?,
            policy_route: keyspace("contextdb_native_policy_route")?,
            content_history: keyspace("contextdb_native_content_history")?,
            observations_policy: keyspace("contextdb_native_observation_policy")?,
            observations_content: keyspace("contextdb_native_observation_content")?,
            idempotency: keyspace("contextdb_native_idempotency")?,
            events: keyspace("contextdb_native_events")?,
            continuous: keyspace("contextdb_native_continuous")?,
        })
    }

    fn all(&self) -> [&Keyspace; 12] {
        [
            &self.meta,
            &self.workspace,
            &self.workspace_map,
            &self.policy_head,
            &self.policy_history,
            &self.policy_route,
            &self.content_history,
            &self.observations_policy,
            &self.observations_content,
            &self.idempotency,
            &self.events,
            &self.continuous,
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u16,
    format: String,
    database_id: String,
    checksum: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    features: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    state_catalogs: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    suppression_authority: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody_authority: Option<uuid::Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceState {
    schema_version: u16,
    workspace_digest: String,
    latest_global_commit: u64,
    watermarks: Watermarks,
}

impl WorkspaceState {
    fn genesis(workspace_digest: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            workspace_digest,
            latest_global_commit: 0,
            watermarks: Watermarks::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitMap {
    schema_version: u16,
    global_commit: u64,
    state: WorkspaceState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPolicy {
    schema_version: u16,
    record_digest: String,
    revision: u32,
    kind: MemoryRecordKind,
    access: AccessPolicy,
    lifecycle: MemoryLifecycle,
    transaction_from: u64,
    transaction_to: Option<u64>,
    content_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizedPolicyFamily {
    Canonical,
    Candidate,
}

impl AuthorizedPolicyFamily {
    fn accepts(self, kind: MemoryRecordKind) -> bool {
        match self {
            Self::Canonical => kind != MemoryRecordKind::Candidate,
            Self::Candidate => kind == MemoryRecordKind::Candidate,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredContent {
    schema_version: u16,
    record_digest: String,
    record: MemoryRecord,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredObservationPolicy {
    schema_version: u16,
    observation_digest: String,
    accepted_global_commit: u64,
    access: AccessPolicy,
    content_digest: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredObservationContent {
    schema_version: u16,
    observation_id: String,
    metadata: BTreeMap<String, serde_json::Value>,
    content: serde_json::Value,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdempotency {
    schema_version: u16,
    operation: String,
    request_digest: String,
    response_digest: String,
    response_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEvent {
    schema_version: u16,
    global_commit: u64,
    workspace_digest: String,
    workspace_commit: u64,
    operation: String,
    request_digest: String,
    response_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_original: Option<capture::CaptureWork>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_payload: Option<contextdb_core::OriginalPayloadRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_original_revocation: Option<OriginalRevocationReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_raw_reclamation: Option<RawReclaimProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_assertions: Option<contextdb_service::AssertionReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    accepted_records: Vec<record_journal::RecordMutationRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_suppression: Option<suppression::SuppressionPublication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_removal_preparation: Option<retention::RemovalPreparationPublication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_source_pruning: Option<retention::SourcePruningPublication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_payload_pruning: Option<payload::PayloadPruningPublication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_assertion_pruning: Option<assertions::AssertionPruningPublication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_record_sources: Option<record_sources::RecordSourcesPublication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_record_write: Option<record_sources::writes::RecordWriteRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_record_write_completion: Option<record_sources::writes::RecordWriteCompletion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_record_control_preparation:
        Option<record_journal::controls::preparation::ControlPreparation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_record_pruning:
        Option<record_journal::controls::witness::pruning::RecordPruningPublication>,
    previous_event_digest: Option<String>,
    event_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecallCursor {
    schema_version: u16,
    request_digest: String,
    authorization_digest: String,
    global_commit: u64,
    workspace_commit: u64,
    offset: u64,
}

#[derive(Clone, Debug)]
struct CommitFrame {
    global_commit: u64,
    workspace_digest: String,
    state: WorkspaceState,
    previous_event_digest: Option<String>,
}

#[derive(Clone, Debug)]
struct HierarchyRewire {
    old_policy: StoredPolicy,
    old_record: MemoryRecord,
    new_edge_id: String,
    new_source: String,
    new_target: String,
}

/// Incremental Fjall-backed implementation of the canonical application service.
pub struct NativeService {
    engine: NativeStorage,
    keyspaces: Keyspaces,
    database_id: String,
    token_key: Zeroizing<[u8; 32]>,
    writes: publication::PublicationQueue,
    index_views: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    leases: Mutex<lease::LeaseRegistry>,
    lease_started: std::time::Instant,
    lease_instance: uuid::Uuid,
    suppression: Option<std::sync::Arc<NativeSuppressionLedger>>,
    record_write_recovery: Mutex<record_sources::writes::RecoveryCache>,
}

impl fmt::Debug for NativeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeService")
            .field("profile", &PROFILE)
            .field("database_id", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl NativeService {
    /// Opens an existing native database or initializes an empty one.
    /// Continuous archives created without an external suppression authority are
    /// archival only; restoring them requires explicit authority migration.
    pub fn open(
        path: impl AsRef<Path>,
        database_id: impl Into<String>,
        token_key: [u8; 32],
    ) -> ServiceResult<Self> {
        Self::open_internal(path, database_id.into(), token_key, None, None)
    }

    fn open_internal(
        path: impl AsRef<Path>,
        database_id: String,
        token_key: [u8; 32],
        suppression: Option<std::sync::Arc<NativeSuppressionLedger>>,
        keys: Option<std::sync::Arc<NativeCustodyKeys>>,
    ) -> ServiceResult<Self> {
        validate_identifier(&database_id, "database ID")?;
        if token_key.iter().all(|byte| *byte == 0) {
            return Err(invalid("native service token key must not be all zero"));
        }
        if let Some(ledger) = &suppression {
            ledger.require_database(&database_id)?;
        }
        if let Some(keys) = &keys {
            keys.require_database(&database_id)?;
            if suppression.is_none() {
                return Err(invalid(
                    "encrypted native storage requires current suppression",
                ));
            }
        }
        let engine = NativeStorage::open(path.as_ref(), keys).map_err(storage_error)?;
        if let Some(ledger) = &suppression {
            let native_path = path
                .as_ref()
                .canonicalize()
                .map_err(|_| integrity("native path is unavailable"))?;
            if native_path.starts_with(&ledger.path) || ledger.path.starts_with(&native_path) {
                return Err(invalid(
                    "suppression and native authorities require separate directory trees",
                ));
            }
        }
        if let Some(keys) = &engine.keys {
            let native_path = path
                .as_ref()
                .canonicalize()
                .map_err(|_| integrity("native path is unavailable"))?;
            if native_path.starts_with(&keys.path)
                || keys.path.starts_with(&native_path)
                || suppression.as_ref().is_some_and(|ledger| {
                    ledger.path.starts_with(&keys.path) || keys.path.starts_with(&ledger.path)
                })
            {
                return Err(invalid(
                    "native, suppression and custody-key authorities require separate directory trees",
                ));
            }
        }
        let keyspaces = Keyspaces::new()?;
        let service = Self {
            engine,
            keyspaces,
            database_id,
            token_key: Zeroizing::new(token_key),
            writes: publication::PublicationQueue::default(),
            index_views: std::sync::Arc::default(),
            leases: Mutex::new(lease::LeaseRegistry::default()),
            lease_started: std::time::Instant::now(),
            lease_instance: contextdb_core::ObservationId::new().as_uuid(),
            suppression,
            record_write_recovery: Mutex::default(),
        };
        service.install_or_verify_manifest()?;
        service.verify_native(false)?;
        Ok(service)
    }

    /// Stable native profile name used by status and host capability manifests.
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        PROFILE
    }

    fn install_or_verify_manifest(&self) -> ServiceResult<()> {
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if let Some(bytes) = snapshot
            .get(&self.keyspaces.meta, META_MANIFEST_KEY)
            .map_err(storage_error)?
        {
            let manifest: Manifest = decode(&bytes, "native manifest")?;
            validate_manifest(&manifest, &self.database_id)?;
            self.verify_suppression_binding(&manifest)?;
            self.verify_encryption_binding(&manifest)?;
            return Ok(());
        }
        if snapshot.sequence() != 0 && !self.engine.is_protocol_genesis().map_err(storage_error)? {
            return Err(integrity(
                "native manifest is absent from a non-empty physical store",
            ));
        }
        drop(snapshot);
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        let mut manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            format: FORMAT_NAME.to_owned(),
            database_id: self.database_id.clone(),
            checksum: String::new(),
            features: BTreeSet::new(),
            state_catalogs: BTreeSet::new(),
            suppression_authority: self
                .suppression
                .as_ref()
                .map(|ledger| ledger.authority_id()),
            custody_authority: self.engine.keys.as_ref().map(|keys| keys.authority_id()),
        };
        if manifest.suppression_authority.is_some() {
            manifest
                .features
                .insert(suppression::SUPPRESSION_FEATURE.into());
        }
        if self
            .suppression
            .as_ref()
            .is_some_and(|ledger| ledger.supports_removal())
        {
            manifest
                .features
                .insert(retention::RETENTION_FEATURE.into());
        }
        if manifest.custody_authority.is_some() {
            manifest
                .features
                .insert(encryption::ENCRYPTION_FEATURE.into());
        }
        manifest.checksum = manifest_checksum(&manifest)?;
        transaction
            .put(
                &self.keyspaces.meta,
                META_MANIFEST_KEY.to_vec(),
                encode(&manifest)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.meta,
                META_GLOBAL_HEAD_KEY.to_vec(),
                0_u64.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        let receipt = transaction
            .commit(Durability::Sync)
            .map_err(storage_error)?;
        require_sync(receipt.durability)
    }

    fn lock_writes(&self) -> ServiceResult<publication::PublicationGuard<'_>> {
        self.writes.enter(|| Ok(()))
    }

    fn global_head<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<u64> {
        let bytes = snapshot
            .get(&self.keyspaces.meta, META_GLOBAL_HEAD_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("native global head is absent"))?;
        decode_u64(&bytes, "native global head")
    }

    fn workspace_state<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
    ) -> ServiceResult<WorkspaceState> {
        let workspace_digest = digest_bytes(workspace_id.as_bytes());
        let Some(bytes) = snapshot
            .get(&self.keyspaces.workspace, workspace_digest.as_bytes())
            .map_err(storage_error)?
        else {
            return Ok(WorkspaceState::genesis(workspace_digest));
        };
        let state: WorkspaceState = decode(&bytes, "native workspace state")?;
        validate_workspace_state(&state, &workspace_digest)?;
        Ok(state)
    }

    fn select_snapshot<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        at_commit: Option<u64>,
    ) -> ServiceResult<(u64, WorkspaceState)> {
        let current = self.workspace_state(snapshot, workspace_id)?;
        let Some(requested) = at_commit else {
            return Ok((self.global_head(snapshot)?, current));
        };
        if requested == 0 {
            return Ok((0, WorkspaceState::genesis(current.workspace_digest.clone())));
        }
        if requested > current.watermarks.journal {
            return Err(ServiceError::new(
                ErrorCode::NotFound,
                "requested workspace snapshot does not exist",
                false,
            ));
        }
        let key = workspace_map_key(&current.workspace_digest, requested);
        let bytes = snapshot
            .get(&self.keyspaces.workspace_map, &key)
            .map_err(storage_error)?
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::SnapshotExpired,
                    "requested workspace snapshot mapping is unavailable",
                    false,
                )
            })?;
        let mapping: CommitMap = decode(&bytes, "native workspace commit map")?;
        if mapping.schema_version != SCHEMA_VERSION
            || mapping.state.workspace_digest != current.workspace_digest
            || mapping.state.watermarks.journal != requested
            || mapping.global_commit == 0
        {
            return Err(integrity("native workspace commit mapping is invalid"));
        }
        Ok((mapping.global_commit, mapping.state))
    }

    fn begin_frame<T: WriteTransaction>(
        &self,
        transaction: &T,
        workspace_id: &str,
        semantic: bool,
    ) -> ServiceResult<CommitFrame> {
        if let Some(ledger) = &self.suppression {
            ledger.register_removal_workspace(&digest_bytes(workspace_id.as_bytes()))?;
        }
        let global_commit = self
            .global_head(transaction)?
            .checked_add(1)
            .ok_or_else(|| exhausted("native global commit sequence is exhausted"))?;
        let mut state = self.workspace_state(transaction, workspace_id)?;
        let workspace_commit = state
            .watermarks
            .journal
            .checked_add(1)
            .ok_or_else(|| exhausted("native workspace commit sequence is exhausted"))?;
        state.latest_global_commit = global_commit;
        state.watermarks.journal = workspace_commit;
        if semantic {
            state.watermarks.semantic = workspace_commit;
            state.watermarks.lexical = workspace_commit;
        }
        let previous_event_digest = transaction
            .get(&self.keyspaces.meta, META_EVENT_DIGEST_KEY)
            .map_err(storage_error)?
            .map(|bytes| String::from_utf8(bytes).map_err(|_| integrity("event digest is invalid")))
            .transpose()?;
        Ok(CommitFrame {
            global_commit,
            workspace_digest: state.workspace_digest.clone(),
            state,
            previous_event_digest,
        })
    }

    fn finish_frame<T: WriteTransaction, R: Serialize>(
        &self,
        transaction: &mut T,
        frame: &CommitFrame,
        operation: &'static str,
        idempotency_key: &[u8],
        request_digest: &str,
        response: &R,
    ) -> ServiceResult<()> {
        let response_bytes = encode(response)?;
        let response_digest = digest_bytes(&response_bytes);
        let accepted_records = self.accepted_record_mutations(transaction, frame)?;
        let accepted_record_write = self.accepted_record_write(
            transaction,
            frame,
            operation,
            request_digest,
            idempotency_key,
            &accepted_records,
        )?;
        let mut event = StoredEvent {
            schema_version: SCHEMA_VERSION,
            global_commit: frame.global_commit,
            workspace_digest: frame.workspace_digest.clone(),
            workspace_commit: frame.state.watermarks.journal,
            operation: operation.to_owned(),
            request_digest: request_digest.to_owned(),
            response_digest: response_digest.clone(),
            accepted_original: if operation == "capture" {
                let receipt: contextdb_service::CaptureReceipt =
                    decode(&response_bytes, "capture response")?;
                Some(self.capture_work_for_receipt(transaction, &receipt)?)
            } else {
                None
            },
            previous_event_digest: frame.previous_event_digest.clone(),
            accepted_payload: if operation == "stage_payload" {
                Some(
                    decode::<contextdb_service::PayloadReceipt>(
                        &response_bytes,
                        "payload response",
                    )?
                    .reference,
                )
            } else {
                None
            },
            event_digest: String::new(),
            accepted_original_revocation: if operation == "original_revocation" {
                Some(decode(&response_bytes, "original revocation receipt")?)
            } else {
                None
            },
            accepted_raw_reclamation: if operation == "raw_reclamation_with_copies" {
                Some(decode(&response_bytes, "raw reclamation progress")?)
            } else {
                None
            },
            accepted_assertions: if operation == "assertions" {
                Some(decode(&response_bytes, "assertion receipt")?)
            } else {
                None
            },
            accepted_records,
            accepted_record_write,
            accepted_record_write_completion: if operation == "record_write_complete" {
                Some(decode(&response_bytes, "record write completion")?)
            } else {
                None
            },
            accepted_record_control_preparation: if operation == "record_controls_prepare" {
                Some(decode(&response_bytes, "record control preparation")?)
            } else {
                None
            },
            accepted_suppression: if operation == "suppression_reconcile" {
                Some(decode(&response_bytes, "suppression publication")?)
            } else {
                None
            },
            accepted_removal_preparation: if operation == "removal_prepare" {
                Some(decode(&response_bytes, "removal preparation publication")?)
            } else {
                None
            },
            accepted_source_pruning: if operation == "source_prune" {
                Some(decode(&response_bytes, "source pruning publication")?)
            } else {
                None
            },
            accepted_payload_pruning: if operation == "payload_prune" {
                Some(decode(&response_bytes, "payload pruning publication")?)
            } else {
                None
            },
            accepted_assertion_pruning: if operation == "assertion_prune" {
                Some(decode(&response_bytes, "assertion pruning publication")?)
            } else {
                None
            },
            accepted_record_sources: if operation == "record_sources_reconcile" {
                Some(decode(&response_bytes, "record source application")?)
            } else {
                None
            },
            accepted_record_pruning: if operation == "record_prune" {
                Some(decode(&response_bytes, "record pruning publication")?)
            } else {
                None
            },
        };
        event.event_digest = event_digest(&event)?;
        let idempotency = StoredIdempotency {
            schema_version: SCHEMA_VERSION,
            operation: operation.to_owned(),
            request_digest: request_digest.to_owned(),
            response_digest,
            response_bytes,
        };
        transaction
            .put(
                &self.keyspaces.idempotency,
                idempotency_key.to_vec(),
                encode(&idempotency)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.events,
                frame.global_commit.to_be_bytes().to_vec(),
                encode(&event)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.workspace,
                frame.workspace_digest.as_bytes().to_vec(),
                encode(&frame.state)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.workspace_map,
                workspace_map_key(&frame.workspace_digest, frame.state.watermarks.journal),
                encode(&CommitMap {
                    schema_version: SCHEMA_VERSION,
                    global_commit: frame.global_commit,
                    state: frame.state.clone(),
                })?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.meta,
                META_GLOBAL_HEAD_KEY.to_vec(),
                frame.global_commit.to_be_bytes().to_vec(),
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.meta,
                META_EVENT_DIGEST_KEY.to_vec(),
                event.event_digest.as_bytes().to_vec(),
            )
            .map_err(storage_error)
    }

    fn replay<R: DeserializeOwned, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        idempotency_key: &[u8],
        operation: &'static str,
        request_digest: &str,
    ) -> ServiceResult<Option<R>> {
        let Some(bytes) = snapshot
            .get(&self.keyspaces.idempotency, idempotency_key)
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let stored: StoredIdempotency = decode(&bytes, "native idempotency receipt")?;
        if stored.schema_version != SCHEMA_VERSION
            || stored.operation != operation
            || stored.request_digest != request_digest
            || stored.response_digest != digest_bytes(&stored.response_bytes)
        {
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "idempotency key was reused with different canonical input",
                false,
            ));
        }
        decode(&stored.response_bytes, "native idempotency response").map(Some)
    }

    fn put_record<T: WriteTransaction>(
        &self,
        transaction: &mut T,
        policy: &StoredPolicy,
        record: &MemoryRecord,
    ) -> ServiceResult<()> {
        validate_stored_policy(policy)?;
        let record_digest = digest_bytes(&encode(record)?);
        if record_digest != policy.content_digest
            || digest_bytes(record.document.id.as_bytes()) != policy.record_digest
            || record.revision != policy.revision
            || record.document.kind != policy.kind
            || record.document.access != policy.access
            || record.document.lifecycle != policy.lifecycle
            || record.transaction_from != policy.transaction_from
            || record.transaction_to != policy.transaction_to
        {
            return Err(integrity("native policy/content binding is invalid"));
        }
        let stored = StoredContent {
            schema_version: SCHEMA_VERSION,
            record_digest: policy.record_digest.clone(),
            record: record.clone(),
            digest: record_digest,
        };
        self.journal_record(transaction, record)?;
        let key = history_key(&policy.record_digest, policy.revision);
        transaction
            .put(&self.keyspaces.policy_history, key.clone(), encode(policy)?)
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.policy_route,
                policy_route_key(
                    &policy.access.workspace_id,
                    &policy.record_digest,
                    policy.revision,
                ),
                encode(policy)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(&self.keyspaces.content_history, key, encode(&stored)?)
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.policy_head,
                policy.record_digest.as_bytes().to_vec(),
                encode(policy)?,
            )
            .map_err(storage_error)
    }

    fn load_head<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        record_id: &str,
    ) -> ServiceResult<Option<StoredPolicy>> {
        let record_digest = digest_bytes(record_id.as_bytes());
        snapshot
            .get(&self.keyspaces.policy_head, record_digest.as_bytes())
            .map_err(storage_error)?
            .map(|bytes| {
                let policy: StoredPolicy = decode(&bytes, "native head policy")?;
                validate_stored_policy(&policy)?;
                if policy.record_digest != record_digest {
                    return Err(integrity("native head policy key binding is invalid"));
                }
                Ok(policy)
            })
            .transpose()
    }

    fn load_content<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
    ) -> ServiceResult<MemoryRecord> {
        let key = history_key(&policy.record_digest, policy.revision);
        let bytes = snapshot
            .get(&self.keyspaces.content_history, &key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("native authorized record content is absent"))?;
        self.decode_content(&bytes, policy)
    }

    fn decode_content(&self, bytes: &[u8], policy: &StoredPolicy) -> ServiceResult<MemoryRecord> {
        let stored: StoredContent = decode(bytes, "native record content")?;
        if stored.schema_version != SCHEMA_VERSION
            || stored.record_digest != policy.record_digest
            || stored.digest != policy.content_digest
            || stored.digest != digest_bytes(&encode(&stored.record)?)
            || stored.record.revision != policy.revision
            || stored.record.document.access != policy.access
            || stored.record.document.kind != policy.kind
            || stored.record.document.lifecycle != policy.lifecycle
            || stored.record.transaction_from != policy.transaction_from
            || stored.record.transaction_to != policy.transaction_to
        {
            return Err(integrity(
                "native authorized policy/content binding changed",
            ));
        }
        if let Some(ledger) = &self.suppression
            && let Some(binding) = ledger.retained_record_sources(
                &digest_bytes(policy.access.workspace_id.as_bytes()),
                &policy.record_digest,
                policy.revision,
            )?
            && (binding.record_control()?.transaction_from != policy.transaction_from
                || binding.record_control()?.document_digest
                    != canonical_digest(&stored.record.document)?)
        {
            return Err(integrity(
                "record body differs from retained source provenance",
            ));
        }
        Ok(stored.record)
    }

    fn policy_at<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        record_id: &str,
        global_commit: u64,
    ) -> ServiceResult<Option<StoredPolicy>> {
        let record_digest = digest_bytes(record_id.as_bytes());
        let prefix = history_prefix(&record_digest);
        let entries = snapshot
            .scan_prefix(&self.keyspaces.policy_history, &prefix)
            .map_err(storage_error)?;
        if entries.len() > 100_000 {
            return Err(exhausted(
                "native record revision history exceeds the limit",
            ));
        }
        let mut selected = None;
        for entry in entries {
            let policy: StoredPolicy = decode(&entry.value, "native historical policy")?;
            validate_stored_policy(&policy)?;
            if policy.record_digest != record_digest {
                return Err(integrity(
                    "native historical policy prefix binding is invalid",
                ));
            }
            if visible_at(&policy, global_commit)
                && selected
                    .as_ref()
                    .is_none_or(|current: &StoredPolicy| current.revision < policy.revision)
            {
                selected = Some(policy);
            }
        }
        Ok(selected)
    }

    fn authenticated_record(
        &self,
        request: &GetMemoryRequest,
        expected_kind: Option<MemoryRecordKind>,
    ) -> ServiceResult<MemoryRecord> {
        require_capability(&request.context, Capability::ReadMemory)?;
        validate_identifier(&request.record_id, "memory record ID")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.require_suppression_current(
            &snapshot,
            &digest_bytes(request.context.request.workspace_id.as_bytes()),
        )?;
        let (global_commit, _) = self.select_snapshot(
            &snapshot,
            &request.context.request.workspace_id,
            request.at_commit,
        )?;
        let policy = self
            .policy_at(&snapshot, &request.record_id, global_commit)?
            .ok_or_else(not_found)?;
        if expected_kind.is_some_and(|kind| kind != policy.kind) {
            return Err(not_found());
        }
        if !policy_allows(&request.context.request, &policy.access) {
            return Err(permission_denied());
        }
        self.authorize_record_sources(&snapshot, &request.context.request, &policy)?;
        self.load_content(&snapshot, &policy)
    }

    fn verify_native(&self, deep: bool) -> ServiceResult<VerifyResponse> {
        let backend = self
            .engine
            .verify(if deep {
                VerifyMode::Deep
            } else {
                VerifyMode::Quick
            })
            .map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let manifest_bytes = snapshot
            .get(&self.keyspaces.meta, META_MANIFEST_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("native manifest is absent"))?;
        let manifest: Manifest = decode(&manifest_bytes, "native manifest")?;
        validate_manifest(&manifest, &self.database_id)?;
        let global_head = self.global_head(&snapshot)?;
        self.verify_event_chain(&snapshot, global_head)?;
        let digest = if deep {
            Some(self.verify_all_records(&snapshot)?)
        } else {
            None
        };
        if backend.sequence != snapshot.sequence() {
            return Err(integrity("native backend verification changed snapshots"));
        }
        Ok(VerifyResponse {
            valid: true,
            commit_seq: global_head,
            archive_digest: digest,
        })
    }

    fn verify_event_chain<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        global_head: u64,
    ) -> ServiceResult<()> {
        let entries = snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?;
        if u64::try_from(entries.len()).unwrap_or(u64::MAX) != global_head {
            return Err(integrity(
                "native event chain length disagrees with its head",
            ));
        }
        let mut previous: Option<String> = None;
        for (offset, entry) in entries.into_iter().enumerate() {
            let expected = u64::try_from(offset)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| exhausted("native event chain exceeds u64"))?;
            if entry.key != expected.to_be_bytes() || entry.value.len() > MAX_JSON_BYTES {
                return Err(integrity("native event chain ordering is invalid"));
            }
            let event: StoredEvent = decode(&entry.value, "native event")?;
            if event.schema_version != SCHEMA_VERSION
                || event.global_commit != expected
                || event.previous_event_digest != previous
                || event.event_digest != event_digest(&event)?
            {
                return Err(integrity("native event chain digest is invalid"));
            }
            previous = Some(event.event_digest);
        }
        let stored = snapshot
            .get(&self.keyspaces.meta, META_EVENT_DIGEST_KEY)
            .map_err(storage_error)?
            .map(|bytes| String::from_utf8(bytes).map_err(|_| integrity("event digest is invalid")))
            .transpose()?;
        if stored != previous {
            return Err(integrity("native event chain terminal digest is invalid"));
        }
        Ok(())
    }

    fn raw_manifest<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<Manifest> {
        decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )
    }

    fn verify_all_records<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<String> {
        for entry in snapshot
            .scan_prefix(&self.keyspaces.policy_history, b"")
            .map_err(storage_error)?
        {
            let policy: StoredPolicy = decode(&entry.value, "native historical policy")?;
            validate_stored_policy(&policy)?;
            if entry.key != history_key(&policy.record_digest, policy.revision) {
                return Err(integrity("native historical policy key is invalid"));
            }
            if self
                .pruned_record(
                    snapshot,
                    &policy.record_digest,
                    policy.revision,
                    &mut retention::audit_budget(),
                )?
                .is_none()
            {
                let _ = self.load_content(snapshot, &policy)?;
            }
        }
        for entry in snapshot
            .scan_prefix(&self.keyspaces.policy_head, b"")
            .map_err(storage_error)?
        {
            let policy: StoredPolicy = decode(&entry.value, "native head policy")?;
            validate_stored_policy(&policy)?;
            if entry.key != policy.record_digest.as_bytes()
                || snapshot
                    .get(
                        &self.keyspaces.policy_history,
                        &history_key(&policy.record_digest, policy.revision),
                    )
                    .map_err(storage_error)?
                    .as_deref()
                    != Some(entry.value.as_slice())
            {
                return Err(integrity(
                    "native head policy is not an exact history member",
                ));
            }
        }
        for entry in snapshot
            .scan_prefix(&self.keyspaces.policy_route, b"")
            .map_err(storage_error)?
        {
            let policy: StoredPolicy = decode(&entry.value, "native routed policy")?;
            validate_stored_policy(&policy)?;
            if entry.key
                != policy_route_key(
                    &policy.access.workspace_id,
                    &policy.record_digest,
                    policy.revision,
                )
                || snapshot
                    .get(
                        &self.keyspaces.policy_history,
                        &history_key(&policy.record_digest, policy.revision),
                    )
                    .map_err(storage_error)?
                    .as_deref()
                    != Some(entry.value.as_slice())
            {
                return Err(integrity(
                    "native routed policy is not an exact history member",
                ));
            }
        }
        for entry in snapshot
            .scan_prefix(&self.keyspaces.observations_policy, b"")
            .map_err(storage_error)?
        {
            let policy: StoredObservationPolicy =
                decode(&entry.value, "native observation policy")?;
            validate_access(&policy.access)?;
            if policy.schema_version != SCHEMA_VERSION
                || policy.accepted_global_commit == 0
                || entry.key != policy.observation_digest.as_bytes()
            {
                return Err(integrity("native observation policy is invalid"));
            }
            let bytes = snapshot
                .get(
                    &self.keyspaces.observations_content,
                    policy.observation_digest.as_bytes(),
                )
                .map_err(storage_error)?;
            let Some(bytes) = bytes else {
                self.verify_pruned_observation(snapshot, &policy)?;
                continue;
            };
            let content: StoredObservationContent = decode(&bytes, "native observation content")?;
            if content.metadata.get("capture_format")
                == Some(&serde_json::json!(contextdb_service::NATIVE_CAPTURE_DOMAIN))
                && snapshot
                    .get(
                        &self.keyspaces.continuous,
                        format!("receipt/{}", content.observation_id).as_bytes(),
                    )
                    .map_err(storage_error)?
                    .is_none()
            {
                return Err(integrity("captured observation lacks its native receipt"));
            }
            if content.schema_version != SCHEMA_VERSION
                || digest_bytes(content.observation_id.as_bytes()) != policy.observation_digest
                || content.digest != policy.content_digest
                || content.digest
                    != canonical_digest(&(
                        &content.observation_id,
                        &content.metadata,
                        &content.content,
                    ))?
            {
                return Err(integrity(
                    "native observation policy/content binding is invalid",
                ));
            }
        }
        for entry in snapshot
            .scan_prefix(&self.keyspaces.idempotency, b"")
            .map_err(storage_error)?
        {
            let receipt: StoredIdempotency = decode(&entry.value, "native idempotency receipt")?;
            if receipt.schema_version != SCHEMA_VERSION
                || receipt.operation.trim().is_empty()
                || receipt.request_digest.len() != 64
                || receipt.response_digest != digest_bytes(&receipt.response_bytes)
            {
                return Err(integrity("native idempotency receipt is invalid"));
            }
        }
        for entry in snapshot
            .scan_prefix(&self.keyspaces.workspace, b"")
            .map_err(storage_error)?
        {
            let state: WorkspaceState = decode(&entry.value, "native workspace state")?;
            let digest = std::str::from_utf8(&entry.key)
                .map_err(|_| integrity("native workspace key is invalid"))?;
            validate_workspace_state(&state, digest)?;
        }
        self.verify_active_graph_invariants(snapshot)?;
        self.verify_capture_records(snapshot)?;
        self.verify_custody_records(snapshot)?;
        self.verify_suppression_records(snapshot)?;
        self.verify_removal_preparations(snapshot)?;
        self.verify_source_pruning(snapshot)?;
        self.verify_payload_records(snapshot)?;
        self.verify_raw_index_records(snapshot)?;
        self.verify_assertion_records(snapshot)?;
        self.verify_record_mutations(snapshot)?;
        self.verify_record_pruning(snapshot)?;
        self.verify_record_source_progress(snapshot)?;
        self.verify_record_writes(snapshot)?;
        for entry in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&entry.value, "native journal reference")?;
            self.verify_capture_journal_reference(snapshot, &event)?;
            self.verify_payload_journal_reference(snapshot, &event)?;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"contextdb/native-service/deep-verification/v1\0");
        for keyspace in self.keyspaces.all() {
            let entries = snapshot.scan_prefix(keyspace, b"").map_err(storage_error)?;
            // Empty optional extensions retain the exact legacy verification digest.
            if keyspace == &self.keyspaces.continuous && entries.is_empty() {
                continue;
            }
            hasher.update(keyspace.as_str().as_bytes());
            hasher.update(&[0]);
            for entry in entries {
                hasher.update(&(entry.key.len() as u64).to_be_bytes());
                hasher.update(&entry.key);
                hasher.update(&(entry.value.len() as u64).to_be_bytes());
                hasher.update(&entry.value);
            }
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn verify_active_graph_invariants<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<()> {
        self.verify_record_graph(snapshot)
    }
}

impl CognitiveMemoryService for NativeService {
    fn observe(&self, request: ObserveRequest) -> ServiceResult<ObserveResponse> {
        validate_observe(&request)?;
        let request_digest = canonical_digest(&(
            "observe-v1",
            &request.context.workspace_id,
            &request.context.subject_id,
            &request.context.audiences,
            &request.context.scopes,
            &request.context.purpose,
            request.context.clearance,
            &request.observation_id,
            &request.metadata,
            &request.content,
            &request.access,
        ))?;
        let idempotency_key =
            legacy_idempotency_key("observe", &request.context, &request.idempotency_key)?;
        let _guard = self.lock_writes()?;
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if let Some(mut replay) = self.replay::<ObserveResponse, _>(
            &transaction,
            &idempotency_key,
            "observe",
            &request_digest,
        )? {
            replay.replayed = true;
            return Ok(replay);
        }
        let observation_digest = digest_bytes(request.observation_id.as_bytes());
        if transaction
            .get(
                &self.keyspaces.observations_policy,
                observation_digest.as_bytes(),
            )
            .map_err(storage_error)?
            .is_some()
        {
            return Err(invalid("observation ID has already been used"));
        }
        let frame = self.begin_frame(&transaction, &request.context.workspace_id, false)?;
        let content_digest =
            canonical_digest(&(&request.observation_id, &request.metadata, &request.content))?;
        let policy = StoredObservationPolicy {
            schema_version: SCHEMA_VERSION,
            observation_digest: observation_digest.clone(),
            accepted_global_commit: frame.global_commit,
            access: request.access,
            content_digest: content_digest.clone(),
        };
        let content = StoredObservationContent {
            schema_version: SCHEMA_VERSION,
            observation_id: request.observation_id,
            metadata: request.metadata,
            content: request.content,
            digest: content_digest,
        };
        transaction
            .put(
                &self.keyspaces.observations_policy,
                observation_digest.as_bytes().to_vec(),
                encode(&policy)?,
            )
            .map_err(storage_error)?;
        transaction
            .put(
                &self.keyspaces.observations_content,
                observation_digest.as_bytes().to_vec(),
                encode(&content)?,
            )
            .map_err(storage_error)?;
        let response = ObserveResponse {
            commit_seq: frame.state.watermarks.journal,
            replayed: false,
            request_digest: request_digest.clone(),
            watermarks: frame.state.watermarks.clone(),
        };
        self.finish_frame(
            &mut transaction,
            &frame,
            "observe",
            &idempotency_key,
            &request_digest,
            &response,
        )?;
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(response)
    }

    fn recall(&self, request: RecallRequest) -> ServiceResult<RecallResponse> {
        self.recall_page(request)
    }

    fn compile_context(
        &self,
        request: CompileContextRequest,
    ) -> ServiceResult<CompileContextResponse> {
        let workspace_id = request.context.request.workspace_id.clone();
        let provider = NativeRecallProvider::new(self, &workspace_id);
        contextdb_service::compile_provider_context(&provider, &self.token_key, request)
    }

    fn explain_recall(&self, request: ExplainRecallRequest) -> ServiceResult<RecallTrace> {
        validate_request_context(&request.context)?;
        let expected = trace_id(&self.token_key, &request.context, &request.trace)?;
        if expected != request.trace.trace_id {
            return Err(ServiceError::new(
                ErrorCode::PermissionDenied,
                "recall trace is not bound to this caller",
                false,
            ));
        }
        Ok(request.trace)
    }

    fn export_archive(&self, request: ExportRequest) -> ServiceResult<ExportResponse> {
        validate_request_context(&request.context)?;
        Err(unsupported(
            "native subject-safe export requires a filtered closure executor",
        ))
    }

    fn import_archive(&self, request: ImportRequest) -> ServiceResult<ImportResponse> {
        validate_request_context(&request.context)?;
        Err(unsupported(
            "native live import requires an isolated restore executor",
        ))
    }

    fn verify(&self, request: VerifyRequest) -> ServiceResult<VerifyResponse> {
        validate_request_context(&request.context)?;
        self.verify_native(request.deep)
    }

    fn publish_memory(&self, request: PublishMemoryRequest) -> ServiceResult<MutationResponse> {
        self.publish_explicit_memory(request)
    }

    fn propose_memory(
        &self,
        request: ProposeMemoryRequest,
    ) -> ServiceResult<ProposeMemoryResponse> {
        self.propose_memory_atomic(request)
    }

    fn recall_candidates(
        &self,
        request: RecallCandidatesRequest,
    ) -> ServiceResult<RecallCandidatesResponse> {
        self.recall_candidate_page(request)
    }

    fn get_candidate(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        self.authenticated_record(&request, Some(MemoryRecordKind::Candidate))
            .and_then(|record| {
                if candidate_role(&record.document) == Some(CANDIDATE_MEMORY_ROLE) {
                    Ok(record)
                } else {
                    Err(not_found())
                }
            })
    }

    fn traverse_candidates(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        self.traverse_candidate_graph(request)
    }

    fn correct(&self, request: CorrectRequest) -> ServiceResult<MutationResponse> {
        self.correct_memory(request)
    }

    fn forget(&self, request: ForgetRequest) -> ServiceResult<MutationResponse> {
        self.retract_memory(request)
    }

    fn get_node(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        self.authenticated_record(&request, Some(MemoryRecordKind::Node))
    }

    fn get_memory(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        self.authenticated_record(&request, Some(MemoryRecordKind::SemanticObject))
    }

    fn traverse(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        self.traverse_graph(request)
    }

    fn get_timeline(&self, request: GetTimelineRequest) -> ServiceResult<TimelineResponse> {
        self.timeline(request)
    }

    fn get_status(&self, request: GetStatusRequest) -> ServiceResult<StatusResponse> {
        require_capability(&request.context, Capability::Admin)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let state = self.workspace_state(&snapshot, &request.context.request.workspace_id)?;
        Ok(StatusResponse {
            schema_version: SCHEMA_VERSION,
            profile: PROFILE.to_owned(),
            commit_seq: state.watermarks.journal,
            watermarks: state.watermarks,
            capability_manifest: native_capability_manifest(
                self.suppression.is_some(),
                self.engine.is_encrypted(),
            ),
        })
    }

    fn compact(&self, request: MaintenanceRequest) -> ServiceResult<MaintenanceResponse> {
        require_capability(&request.context, Capability::Maintenance)?;
        validate_identifier(&request.operation_id, "maintenance operation ID")?;
        let payload: CompactPayload = serde_json::from_value(request.payload)
            .map_err(|_| invalid("native compact payload is invalid"))?;
        if payload.schema_version != SCHEMA_VERSION {
            return Err(invalid("native compact schema version is unsupported"));
        }
        let report = self
            .engine
            .compact(CompactRequest {
                max_bytes: payload.max_bytes,
            })
            .map_err(storage_error)?;
        Ok(MaintenanceResponse {
            operation_id: request.operation_id,
            payload: serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "physical_sequence": report.sequence,
                "bytes_reclaimed": report.bytes_reclaimed,
                "logical_state_changed": false,
            }),
        })
    }

    fn create_backup(&self, request: CreateBackupRequest) -> ServiceResult<BackupResponse> {
        self.create_native_backup(request)
    }

    fn restore_backup(
        &self,
        request: RestoreBackupRequest,
    ) -> ServiceResult<RestoreBackupResponse> {
        self.restore_native_backup(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactPayload {
    schema_version: u16,
    max_bytes: Option<u64>,
}

impl NativeService {
    fn publish_explicit_memory(
        &self,
        request: PublishMemoryRequest,
    ) -> ServiceResult<MutationResponse> {
        self.publish_explicit_memory_inner(request, None)
    }

    fn publish_explicit_memory_inner(
        &self,
        request: PublishMemoryRequest,
        mut inputs: Option<(
            &BTreeSet<contextdb_core::ObservationId>,
            &mut contextdb_recall::QueryBudget,
        )>,
    ) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Correct)?;
        require_capability(&request.context, Capability::Observe)?;
        validate_identifier(&request.idempotency_key, "idempotency key")?;
        validate_identifier(&request.memory_id, "memory ID")?;
        validate_text(&request.search_text, "memory search text", MAX_QUERY_BYTES)?;
        validate_json(&request.value, "memory value")?;
        if request.context.request.clearance < Sensitivity::Private {
            return Err(permission_denied());
        }
        let authorization_digest = request.context.authorization_binding_digest()?;
        let mut request_digest = canonical_digest(&(
            "publish-memory-v1",
            &authorization_digest,
            &request.memory_id,
            &request.value,
            &request.search_text,
        ))?;
        let operation = if let Some((sources, _)) = &inputs {
            request_digest = canonical_digest(&(
                record_sources::writes::WRITE_FEATURE,
                "publish_memory_from_sources",
                &request_digest,
                sources,
            ))?;
            "publish_memory_from_sources"
        } else {
            "publish_memory"
        };
        let idempotency_key =
            authenticated_idempotency_key(operation, &request.context, &request.idempotency_key)?;
        // Accepted retries repair the original handoff even if its source has
        // since been revoked. They never re-evaluate it as a new publication.
        let prepared = if let Some((sources, budget)) = inputs.as_mut() {
            let snapshot = self
                .engine
                .begin_read(SnapshotSelector::Latest)
                .map_err(storage_error)?;
            if let Some(mut replay) = self.replay::<MutationResponse, _>(
                &snapshot,
                &idempotency_key,
                operation,
                &request_digest,
            )? {
                replay.replayed = true;
                return Ok(replay);
            }
            Some(self.prepare_record_write(&request.context, sources, budget)?)
        } else {
            None
        };
        #[cfg(test)]
        if prepared.is_some() {
            record_sources::writes::before_publication();
        }
        let _guard = if let Some((_, budget)) = &inputs {
            self.lock_index_publication(budget)?
        } else {
            self.lock_writes()?
        };
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if let Some(mut replay) = self.replay::<MutationResponse, _>(
            &transaction,
            &idempotency_key,
            operation,
            &request_digest,
        )? {
            replay.replayed = true;
            return Ok(replay);
        }
        if let Some(prepared) = &prepared {
            self.check_record_write_preparation(&transaction, &request.context, prepared)?;
        } else {
            self.require_legacy_record_writer(&transaction, &request.context.request.workspace_id)?;
        }
        if self.load_head(&transaction, &request.memory_id)?.is_some() {
            return Err(invalid("memory ID has already been used"));
        }
        let frame = self.begin_frame(&transaction, &request.context.request.workspace_id, true)?;
        let document = MemoryDocument {
            id: request.memory_id,
            kind: MemoryRecordKind::SemanticObject,
            access: trusted_explicit_policy(&request.context.request),
            valid_time: Default::default(),
            lifecycle: MemoryLifecycle::Active,
            links: Default::default(),
            value: request.value,
            search_text: Some(request.search_text),
            vector: None,
            attributes: BTreeMap::from([(
                "contextdb.explicit_memory.schema_version".to_owned(),
                serde_json::json!(SCHEMA_VERSION),
            )]),
        };
        validate_memory_document(&document)?;
        let record = MemoryRecord {
            document,
            revision: 1,
            transaction_from: frame.global_commit,
            transaction_to: None,
        };
        let policy = policy_for(&record)?;
        self.put_record(&mut transaction, &policy, &record)?;
        let response = MutationResponse {
            commit_seq: frame.state.watermarks.journal,
            replayed: false,
            request_digest: request_digest.clone(),
            watermarks: frame.state.watermarks.clone(),
        };
        if let Some(prepared) = prepared {
            self.stage_record_write(
                &mut transaction,
                &frame,
                (&request_digest, &idempotency_key),
                prepared,
                &record,
                inputs.as_mut().expect("prepared source write").1,
            )?;
        }
        self.finish_frame(
            &mut transaction,
            &frame,
            operation,
            &idempotency_key,
            &request_digest,
            &response,
        )?;
        if let Some((_, budget)) = &inputs {
            budget.check().map_err(raw_index::budget_error)?;
        }
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(response)
    }

    fn propose_memory_atomic(
        &self,
        request: ProposeMemoryRequest,
    ) -> ServiceResult<ProposeMemoryResponse> {
        self.propose_memory_atomic_inner(request, None)
    }

    fn propose_memory_atomic_inner(
        &self,
        request: ProposeMemoryRequest,
        mut inputs: Option<record_sources::writes::Inputs<'_>>,
    ) -> ServiceResult<ProposeMemoryResponse> {
        require_capability(&request.context, Capability::Observe)?;
        validate_identifier(&request.idempotency_key, "idempotency key")?;
        validate_identifier(&request.candidate_id, "candidate ID")?;
        validate_text(
            &request.search_text,
            "candidate search text",
            MAX_QUERY_BYTES,
        )?;
        validate_json(&request.value, "candidate value")?;
        if request.parent_candidate_ids.len() > MAX_HIERARCHY_PARENTS
            || request.supersedes_candidate_ids.len() > MAX_HIERARCHY_PARENTS
        {
            return Err(exhausted(
                "candidate proposal exceeds the 16-link hierarchy limit",
            ));
        }
        for parent_id in &request.parent_candidate_ids {
            validate_identifier(parent_id, "candidate parent ID")?;
            if parent_id == &request.candidate_id {
                return Err(invalid("candidate cannot be its own parent"));
            }
        }
        for predecessor_id in &request.supersedes_candidate_ids {
            validate_identifier(predecessor_id, "candidate predecessor ID")?;
            if predecessor_id == &request.candidate_id
                || request.parent_candidate_ids.contains(predecessor_id)
            {
                return Err(invalid(
                    "candidate predecessor cannot also be the proposal or its parent",
                ));
            }
        }
        if request.context.request.clearance < Sensitivity::Private {
            return Err(permission_denied());
        }

        let authorization_digest = request.context.authorization_binding_digest()?;
        let input_digest = canonical_digest(&(
            "candidate-proposal-input-v1",
            &request.candidate_id,
            request.semantic_kind,
            &request.value,
            &request.search_text,
            &request.parent_candidate_ids,
            &request.supersedes_candidate_ids,
        ))?;
        let mut request_digest =
            canonical_digest(&("propose-memory-v1", &authorization_digest, &input_digest))?;
        let operation = if inputs.is_some() {
            record_sources::writes::PROPOSE
        } else {
            "propose_memory"
        };
        if let Some((sources, _)) = &inputs {
            request_digest = canonical_digest(&(
                record_sources::writes::GROUP_FEATURE,
                operation,
                &request_digest,
                sources,
            ))?;
        }
        let idempotency_key =
            authenticated_idempotency_key(operation, &request.context, &request.idempotency_key)?;
        let (prepared, replay) = self.prepare_record_write_or_replay::<ProposeMemoryResponse>(
            &request.context,
            operation,
            &idempotency_key,
            &request_digest,
            &mut inputs,
        )?;
        if let Some(replay) = replay {
            return Ok(replay);
        }
        #[cfg(test)]
        if prepared.is_some() {
            record_sources::writes::before_publication();
        }
        let _guard = if let Some((_, budget)) = &inputs {
            self.lock_index_publication(budget)?
        } else {
            self.lock_writes()?
        };
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if let Some(mut replay) = self.replay::<ProposeMemoryResponse, _>(
            &transaction,
            &idempotency_key,
            operation,
            &request_digest,
        )? {
            replay.mutation.replayed = true;
            return Ok(replay);
        }
        if let Some(prepared) = &prepared {
            self.check_record_write_preparation(&transaction, &request.context, prepared)?;
        } else {
            self.require_legacy_record_writer(&transaction, &request.context.request.workspace_id)?;
        }
        if self
            .load_head(&transaction, &request.candidate_id)?
            .is_some()
        {
            return Err(invalid("candidate ID has already been used"));
        }

        let candidate_access = trusted_structured_policy(&request.context.request);
        for parent_id in &request.parent_candidate_ids {
            let parent_policy = self
                .load_head(&transaction, parent_id)?
                .filter(|policy| policy.transaction_to.is_none())
                .ok_or_else(not_found)?;
            if parent_policy.lifecycle != MemoryLifecycle::Active {
                return Err(not_found());
            }
            if !policy_allows(&request.context.request, &parent_policy.access) {
                return Err(permission_denied());
            }
            if parent_policy.kind != MemoryRecordKind::Candidate
                || parent_policy.access != candidate_access
            {
                return Err(permission_denied());
            }
            self.authorize_record_sources(&transaction, &request.context.request, &parent_policy)?;
            if let Some((_, budget)) = inputs.as_mut() {
                self.charge_source_record_body(&transaction, &parent_policy, budget)?;
            }
            let parent = self.load_content(&transaction, &parent_policy)?;
            if parent.document.lifecycle != MemoryLifecycle::Active
                || candidate_role(&parent.document) != Some(CANDIDATE_MEMORY_ROLE)
            {
                return Err(not_found());
            }
        }
        let mut predecessors = Vec::new();
        for predecessor_id in &request.supersedes_candidate_ids {
            let predecessor_policy = self
                .load_head(&transaction, predecessor_id)?
                .filter(|policy| policy.transaction_to.is_none())
                .ok_or_else(not_found)?;
            if !policy_allows(&request.context.request, &predecessor_policy.access) {
                return Err(permission_denied());
            }
            if predecessor_policy.kind != MemoryRecordKind::Candidate
                || predecessor_policy.lifecycle != MemoryLifecycle::Active
                || predecessor_policy.access != candidate_access
            {
                return Err(permission_denied());
            }
            self.authorize_record_sources(
                &transaction,
                &request.context.request,
                &predecessor_policy,
            )?;
            if let Some((_, budget)) = inputs.as_mut() {
                self.charge_source_record_body(&transaction, &predecessor_policy, budget)?;
            }
            let predecessor = self.load_content(&transaction, &predecessor_policy)?;
            if candidate_role(&predecessor.document) != Some(CANDIDATE_MEMORY_ROLE) {
                return Err(not_found());
            }
            predecessors.push((predecessor_policy, predecessor));
        }

        let candidate_edge_ids = request
            .parent_candidate_ids
            .iter()
            .map(|parent_id| candidate_hierarchy_edge_id(parent_id, &request.candidate_id))
            .collect::<ServiceResult<Vec<_>>>()?;
        for edge_id in &candidate_edge_ids {
            if self.load_head(&transaction, edge_id)?.is_some() {
                return Err(invalid(
                    "deterministic candidate-link ID has already been used",
                ));
            }
        }
        let global_head = self.global_head(&transaction)?;
        let active_edges = self.active_candidate_hierarchy_edges(
            &transaction,
            &request.context.request,
            global_head,
            &candidate_access,
            inputs.as_mut().map(|(_, budget)| &mut **budget),
        )?;
        reject_candidate_hierarchy_cycle(
            &active_edges,
            &request.candidate_id,
            &request.parent_candidate_ids,
        )?;

        let frame = self.begin_frame(&transaction, &request.context.request.workspace_id, false)?;
        for (predecessor_policy, mut predecessor) in predecessors {
            predecessor.transaction_to = Some(frame.global_commit);
            let closed_policy = policy_for(&predecessor)?;
            if closed_policy.record_digest != predecessor_policy.record_digest {
                return Err(integrity(
                    "candidate predecessor changed before supersession",
                ));
            }
            self.put_record(&mut transaction, &closed_policy, &predecessor)?;
            let mut superseded_document = predecessor.document;
            superseded_document.lifecycle = MemoryLifecycle::Superseded;
            let superseded = MemoryRecord {
                document: superseded_document,
                revision: predecessor
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| exhausted("candidate revision sequence is exhausted"))?,
                transaction_from: frame.global_commit,
                transaction_to: None,
            };
            let superseded_policy = policy_for(&superseded)?;
            self.put_record(&mut transaction, &superseded_policy, &superseded)?;
        }
        self.close_candidate_edges_for_superseded(
            &mut transaction,
            &frame,
            active_edges,
            &request.supersedes_candidate_ids,
        )?;

        let semantic_kind = structured_kind_name(request.semantic_kind);
        let mut proposal_attributes =
            candidate_provenance_attributes(&request.context, &input_digest, CANDIDATE_MEMORY_ROLE);
        proposal_attributes.insert(
            "contextdb.semantic_kind".to_owned(),
            serde_json::json!(semantic_kind),
        );
        proposal_attributes.insert(
            "facets".to_owned(),
            serde_json::json!([format!("contextdb.semantic_kind:{semantic_kind}")]),
        );
        let document = MemoryDocument {
            id: request.candidate_id.clone(),
            kind: MemoryRecordKind::Candidate,
            access: candidate_access.clone(),
            valid_time: Default::default(),
            lifecycle: MemoryLifecycle::Active,
            links: contextdb_service::MemoryLinks {
                supersedes: request.supersedes_candidate_ids.clone(),
                ..Default::default()
            },
            value: request.value,
            search_text: Some(request.search_text),
            vector: None,
            attributes: proposal_attributes,
        };
        validate_memory_document(&document)?;
        let child = MemoryRecord {
            document,
            revision: 1,
            transaction_from: frame.global_commit,
            transaction_to: None,
        };
        let child_policy = policy_for(&child)?;
        self.put_record(&mut transaction, &child_policy, &child)?;

        for (parent_id, edge_id) in request.parent_candidate_ids.iter().zip(&candidate_edge_ids) {
            let edge = MemoryRecord {
                document: MemoryDocument {
                    id: edge_id.clone(),
                    kind: MemoryRecordKind::Candidate,
                    access: candidate_access.clone(),
                    valid_time: Default::default(),
                    lifecycle: MemoryLifecycle::Active,
                    links: contextdb_service::MemoryLinks {
                        source: Some(parent_id.clone()),
                        target: Some(request.candidate_id.clone()),
                        predicate: Some(CANDIDATE_HIERARCHY_PARENT_PREDICATE.to_owned()),
                        ..Default::default()
                    },
                    value: serde_json::json!({
                        "schema_version": SCHEMA_VERSION,
                        "proposal_state": "quarantined",
                    }),
                    search_text: None,
                    vector: None,
                    attributes: candidate_provenance_attributes(
                        &request.context,
                        &input_digest,
                        CANDIDATE_EDGE_ROLE,
                    ),
                },
                revision: 1,
                transaction_from: frame.global_commit,
                transaction_to: None,
            };
            let edge_policy = policy_for(&edge)?;
            self.put_record(&mut transaction, &edge_policy, &edge)?;
        }

        let mutation = MutationResponse {
            commit_seq: frame.state.watermarks.journal,
            replayed: false,
            request_digest: request_digest.clone(),
            watermarks: frame.state.watermarks.clone(),
        };
        let response = ProposeMemoryResponse {
            mutation,
            candidate_id: request.candidate_id,
            candidate_edge_ids,
            proposal_state: contextdb_service::CandidateProposalState::Quarantined,
            canonical: false,
        };
        if let Some(prepared) = prepared {
            self.stage_record_group(
                &mut transaction,
                &frame,
                record_sources::writes::GroupRequest::new(
                    operation,
                    &request_digest,
                    &idempotency_key,
                    &response.candidate_id,
                ),
                prepared,
                inputs.as_mut().expect("prepared source group").1,
            )?;
        }
        self.finish_frame(
            &mut transaction,
            &frame,
            operation,
            &idempotency_key,
            &request_digest,
            &response,
        )?;
        if let Some((_, budget)) = &inputs {
            budget.check().map_err(raw_index::budget_error)?;
        }
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(response)
    }

    fn active_candidate_hierarchy_edges<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        principal: &RequestContext,
        global_commit: u64,
        exact_access: &AccessPolicy,
        mut budget: Option<&mut contextdb_recall::QueryBudget>,
    ) -> ServiceResult<Vec<(StoredPolicy, MemoryRecord)>> {
        let policies = if let Some(budget) = budget.as_deref_mut() {
            self.source_graph_policies(
                snapshot,
                principal,
                global_commit,
                exact_access,
                AuthorizedPolicyFamily::Candidate,
                budget,
            )?
        } else {
            self.authorized_policies(
                snapshot,
                principal,
                global_commit,
                MemoryLifecycle::Active,
                AuthorizedPolicyFamily::Candidate,
            )?
        };
        let mut edges = Vec::new();
        for policy in policies.into_values() {
            if policy.kind != MemoryRecordKind::Candidate || policy.access != *exact_access {
                continue;
            }
            if let Some(budget) = budget.as_deref_mut() {
                self.charge_source_record_body(snapshot, &policy, budget)?;
            }
            let record = self.load_content(snapshot, &policy)?;
            if candidate_role(&record.document) == Some(CANDIDATE_EDGE_ROLE) {
                if record.document.links.predicate.as_deref()
                    != Some(CANDIDATE_HIERARCHY_PARENT_PREDICATE)
                    || record.document.links.source.is_none()
                    || record.document.links.target.is_none()
                {
                    return Err(integrity("candidate hierarchy link is malformed"));
                }
                edges.push((policy, record));
            }
        }
        edges.sort_by(|left, right| left.1.document.id.cmp(&right.1.document.id));
        Ok(edges)
    }

    fn close_candidate_edges_for_superseded<T: WriteTransaction>(
        &self,
        transaction: &mut T,
        frame: &CommitFrame,
        edges: Vec<(StoredPolicy, MemoryRecord)>,
        superseded_ids: &BTreeSet<String>,
    ) -> ServiceResult<()> {
        for (policy, mut record) in edges {
            if !record
                .document
                .links
                .source
                .as_ref()
                .is_some_and(|id| superseded_ids.contains(id))
                && !record
                    .document
                    .links
                    .target
                    .as_ref()
                    .is_some_and(|id| superseded_ids.contains(id))
            {
                continue;
            }
            record.transaction_to = Some(frame.global_commit);
            let closed_policy = policy_for(&record)?;
            if closed_policy.record_digest != policy.record_digest
                || closed_policy.revision != policy.revision
            {
                return Err(integrity(
                    "candidate hierarchy link changed before supersession",
                ));
            }
            self.put_record(transaction, &closed_policy, &record)?;
        }
        Ok(())
    }

    fn active_hierarchy_edges<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        principal: &RequestContext,
        global_commit: u64,
        exact_access: &AccessPolicy,
        mut budget: Option<&mut contextdb_recall::QueryBudget>,
    ) -> ServiceResult<Vec<(StoredPolicy, MemoryRecord)>> {
        let policies = if let Some(budget) = budget.as_deref_mut() {
            self.source_graph_policies(
                snapshot,
                principal,
                global_commit,
                exact_access,
                AuthorizedPolicyFamily::Canonical,
                budget,
            )?
        } else {
            self.authorized_policies(
                snapshot,
                principal,
                global_commit,
                MemoryLifecycle::Active,
                AuthorizedPolicyFamily::Canonical,
            )?
        };
        let mut edges = Vec::new();
        for policy in policies.into_values() {
            if policy.kind != MemoryRecordKind::Edge || policy.access != *exact_access {
                continue;
            }
            if let Some(budget) = budget.as_deref_mut() {
                self.charge_source_record_body(snapshot, &policy, budget)?;
            }
            let record = self.load_content(snapshot, &policy)?;
            if record.document.links.predicate.as_deref() == Some(HIERARCHY_PARENT_PREDICATE) {
                let (Some(_), Some(_)) = (
                    record.document.links.source.as_ref(),
                    record.document.links.target.as_ref(),
                ) else {
                    return Err(integrity("hierarchy edge endpoints are absent"));
                };
                edges.push((policy, record));
            }
        }
        edges.sort_by(|left, right| left.1.document.id.cmp(&right.1.document.id));
        Ok(edges)
    }

    fn prepare_hierarchy_rewire<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        edges: &[(StoredPolicy, MemoryRecord)],
        target_id: &str,
        replacement_id: &str,
    ) -> ServiceResult<Vec<HierarchyRewire>> {
        let mut rewires = Vec::new();
        let mut new_ids = BTreeSet::new();
        for (policy, record) in edges {
            let source = record
                .document
                .links
                .source
                .as_ref()
                .ok_or_else(|| integrity("hierarchy edge source is absent"))?;
            let target = record
                .document
                .links
                .target
                .as_ref()
                .ok_or_else(|| integrity("hierarchy edge target is absent"))?;
            if source != target_id && target != target_id {
                continue;
            }
            let new_source = if source == target_id {
                replacement_id.to_owned()
            } else {
                source.clone()
            };
            let new_target = if target == target_id {
                replacement_id.to_owned()
            } else {
                target.clone()
            };
            if new_source == new_target {
                return Err(invalid("hierarchy correction would create a self edge"));
            }
            let new_edge_id = hierarchy_edge_id(&new_source, &new_target)?;
            if !new_ids.insert(new_edge_id.clone()) {
                return Err(integrity(
                    "hierarchy correction collapses distinct edges onto one identity",
                ));
            }
            if self.load_head(snapshot, &new_edge_id)?.is_some() {
                return Err(invalid(
                    "rewired deterministic hierarchy edge ID has already been used",
                ));
            }
            rewires.push(HierarchyRewire {
                old_policy: policy.clone(),
                old_record: record.clone(),
                new_edge_id,
                new_source,
                new_target,
            });
        }
        if !rewires.is_empty() {
            reject_rewired_hierarchy_cycle(edges, target_id, replacement_id)?;
        }
        Ok(rewires)
    }

    fn put_hierarchy_rewire<T: WriteTransaction>(
        &self,
        transaction: &mut T,
        frame: &CommitFrame,
        rewire: HierarchyRewire,
    ) -> ServiceResult<()> {
        let successor = MemoryRecord {
            document: hierarchy_rewire_document(
                &rewire.old_record.document,
                &rewire.new_source,
                &rewire.new_target,
            )?,
            revision: 1,
            transaction_from: frame.global_commit,
            transaction_to: None,
        };
        if successor.document.id != rewire.new_edge_id {
            return Err(integrity(
                "hierarchy successor identity differs from its plan",
            ));
        }
        let mut old_record = rewire.old_record;
        old_record.transaction_to = Some(frame.global_commit);
        let closed_policy = policy_for(&old_record)?;
        if closed_policy.record_digest != rewire.old_policy.record_digest
            || closed_policy.revision != rewire.old_policy.revision
        {
            return Err(integrity("hierarchy edge changed before correction"));
        }
        self.put_record(transaction, &closed_policy, &old_record)?;

        let successor_policy = policy_for(&successor)?;
        self.put_record(transaction, &successor_policy, &successor)
    }

    fn close_incident_hierarchy_edges<T: WriteTransaction>(
        &self,
        transaction: &mut T,
        frame: &CommitFrame,
        edges: Vec<(StoredPolicy, MemoryRecord)>,
        target_id: &str,
    ) -> ServiceResult<usize> {
        let mut closed = 0_usize;
        for (policy, mut record) in edges {
            if record.document.links.source.as_deref() != Some(target_id)
                && record.document.links.target.as_deref() != Some(target_id)
            {
                continue;
            }
            record.transaction_to = Some(frame.global_commit);
            let closed_policy = policy_for(&record)?;
            if closed_policy.record_digest != policy.record_digest
                || closed_policy.revision != policy.revision
            {
                return Err(integrity("hierarchy edge changed before retraction"));
            }
            self.put_record(transaction, &closed_policy, &record)?;
            closed = closed
                .checked_add(1)
                .ok_or_else(|| exhausted("incident hierarchy edge count is exhausted"))?;
        }
        Ok(closed)
    }

    fn traverse_graph(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        require_capability(&request.context, Capability::Traverse)?;
        if request.start_ids.is_empty()
            || request.start_ids.len() > 1_000
            || request.max_hops == 0
            || request.max_hops > 32
            || request.max_nodes == 0
            || request.max_nodes > 10_000
        {
            return Err(invalid(
                "traversal roots and budgets are outside the v1 bounds",
            ));
        }
        for start_id in &request.start_ids {
            validate_identifier(start_id, "traversal root")?;
        }
        validate_string_set(&request.predicate_ids, "traversal predicate")?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (global_commit, state) = self.select_snapshot(
            &snapshot,
            &request.context.request.workspace_id,
            request.at_commit,
        )?;
        let policies = self.authorized_policies(
            &snapshot,
            &request.context.request,
            global_commit,
            MemoryLifecycle::Active,
            AuthorizedPolicyFamily::Canonical,
        )?;
        let authorized_candidates = u64::try_from(policies.len()).unwrap_or(u64::MAX);
        let mut node_ids = BTreeSet::new();
        let mut edges = Vec::new();
        for policy in policies.values() {
            if policy.kind == MemoryRecordKind::Candidate {
                continue;
            }
            let record = self.load_content(&snapshot, policy)?;
            if record.document.kind == MemoryRecordKind::Edge {
                let (Some(source), Some(target), Some(predicate)) = (
                    record.document.links.source,
                    record.document.links.target,
                    record.document.links.predicate,
                ) else {
                    continue;
                };
                edges.push((source, target, predicate));
            } else {
                node_ids.insert(record.document.id);
            }
        }
        for start_id in &request.start_ids {
            if !node_ids.contains(start_id) {
                return Err(not_found());
            }
        }
        edges.retain(|(source, target, predicate)| {
            node_ids.contains(source)
                && node_ids.contains(target)
                && (request.predicate_ids.is_empty() || request.predicate_ids.contains(predicate))
        });
        edges.sort();
        let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
        let mut incoming = BTreeMap::<String, BTreeSet<String>>::new();
        for (source, target, _) in edges {
            outgoing
                .entry(source.clone())
                .or_default()
                .insert(target.clone());
            incoming.entry(target).or_default().insert(source);
        }

        let max_nodes = usize::try_from(request.max_nodes)
            .map_err(|_| exhausted("traversal node budget exceeds this platform"))?;
        let mut visited = BTreeSet::new();
        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        for start_id in &request.start_ids {
            if visited.insert(start_id.clone()) {
                result.push(start_id.clone());
                queue.push_back((start_id.clone(), 0_u8));
                if result.len() == max_nodes {
                    break;
                }
            }
        }
        while result.len() < max_nodes {
            let Some((current, depth)) = queue.pop_front() else {
                break;
            };
            if depth >= request.max_hops {
                continue;
            }
            let mut neighbors = BTreeSet::new();
            if request.direction != TraverseDirection::Incoming
                && let Some(targets) = outgoing.get(&current)
            {
                neighbors.extend(targets.iter().cloned());
            }
            if request.direction != TraverseDirection::Outgoing
                && let Some(sources) = incoming.get(&current)
            {
                neighbors.extend(sources.iter().cloned());
            }
            for neighbor in neighbors {
                if visited.insert(neighbor.clone()) {
                    result.push(neighbor.clone());
                    if result.len() == max_nodes {
                        break;
                    }
                    queue.push_back((neighbor, depth + 1));
                }
            }
        }
        Ok(TraverseResponse {
            node_ids: result,
            snapshot_seq: state.watermarks.journal,
            authorized_candidates,
            watermarks: state.watermarks,
        })
    }

    fn recall_candidate_page(
        &self,
        request: RecallCandidatesRequest,
    ) -> ServiceResult<RecallCandidatesResponse> {
        require_capability(&request.context, Capability::Recall)?;
        validate_text(&request.query, "candidate recall query", MAX_QUERY_BYTES)?;
        if request.page_size == 0 || request.page_size > 1_000 {
            return Err(invalid(
                "candidate recall page size must be between 1 and 1000",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (global_commit, state) = self.select_snapshot(
            &snapshot,
            &request.context.request.workspace_id,
            request.at_commit,
        )?;
        let policies = self.authorized_policies(
            &snapshot,
            &request.context.request,
            global_commit,
            MemoryLifecycle::Active,
            AuthorizedPolicyFamily::Candidate,
        )?;
        let mut authorized_candidates = 0_u64;
        let mut hits = Vec::new();
        for policy in policies.values() {
            if policy.kind != MemoryRecordKind::Candidate {
                continue;
            }
            let record = self.load_content(&snapshot, policy)?;
            if candidate_role(&record.document) != Some(CANDIDATE_MEMORY_ROLE) {
                continue;
            }
            authorized_candidates = authorized_candidates
                .checked_add(1)
                .ok_or_else(|| exhausted("candidate recall count is exhausted"))?;
            let semantic_kind = structured_kind_from_document(&record.document)
                .ok_or_else(|| integrity("candidate semantic kind is invalid"))?;
            if !request.semantic_kinds.is_empty()
                && !request.semantic_kinds.contains(&semantic_kind)
            {
                continue;
            }
            if let Some(score) = lexical_score(&request.query, &record.document) {
                hits.push(contextdb_service::CandidateRecallHit {
                    candidate_id: record.document.id,
                    semantic_kind,
                    score,
                });
            }
        }
        hits.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.candidate_id.cmp(&right.candidate_id))
        });
        hits.truncate(request.page_size as usize);
        Ok(RecallCandidatesResponse {
            hits,
            snapshot_seq: state.watermarks.journal,
            authorized_candidates,
            watermarks: state.watermarks,
        })
    }

    fn traverse_candidate_graph(
        &self,
        request: TraverseRequest,
    ) -> ServiceResult<TraverseResponse> {
        require_capability(&request.context, Capability::Traverse)?;
        if request.start_ids.is_empty()
            || request.start_ids.len() > 1_000
            || request.max_hops == 0
            || request.max_hops > 32
            || request.max_nodes == 0
            || request.max_nodes > 10_000
        {
            return Err(invalid(
                "candidate traversal roots and budgets are outside the v1 bounds",
            ));
        }
        for start_id in &request.start_ids {
            validate_identifier(start_id, "candidate traversal root")?;
        }
        validate_string_set(&request.predicate_ids, "candidate traversal predicate")?;
        if request
            .predicate_ids
            .iter()
            .any(|predicate| predicate != CANDIDATE_HIERARCHY_PARENT_PREDICATE)
        {
            return Err(invalid(
                "candidate traversal supports only the candidate hierarchy predicate",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (global_commit, state) = self.select_snapshot(
            &snapshot,
            &request.context.request.workspace_id,
            request.at_commit,
        )?;
        let policies = self.authorized_policies(
            &snapshot,
            &request.context.request,
            global_commit,
            MemoryLifecycle::Active,
            AuthorizedPolicyFamily::Candidate,
        )?;
        let mut nodes = BTreeSet::new();
        let mut edges = Vec::new();
        let mut authorized_candidates = 0_u64;
        for policy in policies.values() {
            if policy.kind != MemoryRecordKind::Candidate {
                continue;
            }
            let record = self.load_content(&snapshot, policy)?;
            match candidate_role(&record.document) {
                Some(CANDIDATE_MEMORY_ROLE) => {
                    structured_kind_from_document(&record.document)
                        .ok_or_else(|| integrity("candidate semantic kind is invalid"))?;
                    nodes.insert(record.document.id);
                    authorized_candidates = authorized_candidates
                        .checked_add(1)
                        .ok_or_else(|| exhausted("candidate traversal count is exhausted"))?;
                }
                Some(CANDIDATE_EDGE_ROLE) => {
                    let (Some(source), Some(target), Some(predicate)) = (
                        record.document.links.source,
                        record.document.links.target,
                        record.document.links.predicate,
                    ) else {
                        return Err(integrity("candidate hierarchy link is malformed"));
                    };
                    if predicate != CANDIDATE_HIERARCHY_PARENT_PREDICATE {
                        return Err(integrity("candidate hierarchy predicate is invalid"));
                    }
                    edges.push((source, target));
                    authorized_candidates = authorized_candidates
                        .checked_add(1)
                        .ok_or_else(|| exhausted("candidate traversal count is exhausted"))?;
                }
                Some(_) => return Err(integrity("candidate role is invalid")),
                None => {}
            }
        }
        for start_id in &request.start_ids {
            if !nodes.contains(start_id) {
                return Err(not_found());
            }
        }
        let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
        let mut incoming = BTreeMap::<String, BTreeSet<String>>::new();
        for (source, target) in edges {
            if !nodes.contains(&source) || !nodes.contains(&target) {
                return Err(integrity(
                    "active candidate hierarchy link has no active endpoint",
                ));
            }
            outgoing
                .entry(source.clone())
                .or_default()
                .insert(target.clone());
            incoming.entry(target).or_default().insert(source);
        }
        let result = bounded_bfs(
            &request.start_ids,
            request.direction,
            request.max_hops,
            request.max_nodes,
            &outgoing,
            &incoming,
        )?;
        Ok(TraverseResponse {
            node_ids: result,
            snapshot_seq: state.watermarks.journal,
            authorized_candidates,
            watermarks: state.watermarks,
        })
    }

    fn correct_memory(&self, request: CorrectRequest) -> ServiceResult<MutationResponse> {
        self.correct_memory_inner(request, None)
    }

    fn correct_memory_inner(
        &self,
        request: CorrectRequest,
        mut inputs: Option<record_sources::writes::Inputs<'_>>,
    ) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Correct)?;
        validate_identifier(&request.idempotency_key, "idempotency key")?;
        validate_identifier(&request.target_id, "correction target")?;
        validate_memory_document(&request.replacement)?;
        if request.target_id == request.replacement.id {
            return Err(invalid(
                "correction successor must use a distinct memory ID",
            ));
        }
        if !request
            .replacement
            .links
            .supersedes
            .contains(&request.target_id)
        {
            return Err(invalid(
                "correction successor must explicitly supersede its target",
            ));
        }
        let authorization_digest = request.context.authorization_binding_digest()?;
        let mut request_digest = canonical_digest(&(
            "correct-memory-v1",
            &authorization_digest,
            &request.target_id,
            &request.replacement,
        ))?;
        let operation = if inputs.is_some() {
            record_sources::writes::CORRECT
        } else {
            "correct"
        };
        if let Some((sources, _)) = &inputs {
            request_digest = canonical_digest(&(
                record_sources::writes::CORRECTION_FEATURE,
                operation,
                &request_digest,
                sources,
            ))?;
        }
        let idempotency_key =
            authenticated_idempotency_key(operation, &request.context, &request.idempotency_key)?;
        let (prepared, replay) = self.prepare_record_write_or_replay::<MutationResponse>(
            &request.context,
            operation,
            &idempotency_key,
            &request_digest,
            &mut inputs,
        )?;
        if let Some(replay) = replay {
            return Ok(replay);
        }
        #[cfg(test)]
        if prepared.is_some() {
            record_sources::writes::before_publication();
        }
        let _guard = if let Some((_, budget)) = &inputs {
            self.lock_index_publication(budget)?
        } else {
            self.lock_writes()?
        };
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if let Some(mut replay) = self.replay::<MutationResponse, _>(
            &transaction,
            &idempotency_key,
            operation,
            &request_digest,
        )? {
            replay.replayed = true;
            return Ok(replay);
        }
        if let Some(prepared) = &prepared {
            self.check_record_write_preparation(&transaction, &request.context, prepared)?;
        } else {
            self.require_legacy_record_writer(&transaction, &request.context.request.workspace_id)?;
        }
        let target_policy = self
            .load_head(&transaction, &request.target_id)?
            .filter(|policy| policy.transaction_to.is_none())
            .ok_or_else(not_found)?;
        if target_policy.lifecycle != MemoryLifecycle::Active {
            return Err(invalid("correction target is not active"));
        }
        if !policy_allows(&request.context.request, &target_policy.access)
            || !target_policy
                .access
                .owners
                .contains(&request.context.request.subject_id)
        {
            return Err(permission_denied());
        }
        self.authorize_record_sources(&transaction, &request.context.request, &target_policy)?;
        if let Some((_, budget)) = inputs.as_mut() {
            self.charge_source_record_body(&transaction, &target_policy, budget)?;
        }
        let mut target = self.load_content(&transaction, &target_policy)?;
        if target.document.kind == MemoryRecordKind::Candidate {
            return Err(invalid(
                "candidate proposals can change only through typed proposal supersession",
            ));
        }
        if request.replacement.access != target.document.access {
            return Err(permission_denied());
        }
        if request.replacement.kind != target.document.kind
            || request.replacement.lifecycle != MemoryLifecycle::Active
        {
            return Err(invalid(
                "correction successor must preserve the record kind and be active",
            ));
        }
        if target.document.kind == MemoryRecordKind::Edge
            && target.document.links.predicate.as_deref() == Some(HIERARCHY_PARENT_PREDICATE)
        {
            return Err(invalid(
                "managed hierarchy edges can change only through vertex correction",
            ));
        }
        validate_structured_successor(&target.document, &request.replacement)?;
        if self
            .load_head(&transaction, &request.replacement.id)?
            .is_some()
        {
            return Err(invalid("correction successor ID has already been used"));
        }
        let global_head = self.global_head(&transaction)?;
        let hierarchy_edges = self.active_hierarchy_edges(
            &transaction,
            &request.context.request,
            global_head,
            &target.document.access,
            inputs.as_mut().map(|(_, budget)| &mut **budget),
        )?;
        let rewires = self.prepare_hierarchy_rewire(
            &transaction,
            &hierarchy_edges,
            &request.target_id,
            &request.replacement.id,
        )?;
        let replacement_id = request.replacement.id.clone();
        let group_request = record_sources::writes::GroupRequest::new(
            operation,
            &request_digest,
            &idempotency_key,
            &replacement_id,
        )
        .correcting(&target_policy, &rewires);
        if !rewires.is_empty()
            && (target.document.kind == MemoryRecordKind::Edge
                || request.replacement.kind != target.document.kind)
        {
            return Err(invalid(
                "a hierarchy vertex correction must preserve its record kind",
            ));
        }
        let mut frame =
            self.begin_frame(&transaction, &request.context.request.workspace_id, true)?;
        if !rewires.is_empty() {
            frame.state.watermarks.graph = frame.state.watermarks.journal;
        }
        target.transaction_to = Some(frame.global_commit);
        let closed_policy = policy_for(&target)?;
        self.put_record(&mut transaction, &closed_policy, &target)?;

        let successor = MemoryRecord {
            document: request.replacement,
            revision: 1,
            transaction_from: frame.global_commit,
            transaction_to: None,
        };
        let successor_policy = policy_for(&successor)?;
        self.put_record(&mut transaction, &successor_policy, &successor)?;
        for rewire in rewires {
            self.put_hierarchy_rewire(&mut transaction, &frame, rewire)?;
        }
        let response = MutationResponse {
            commit_seq: frame.state.watermarks.journal,
            replayed: false,
            request_digest: request_digest.clone(),
            watermarks: frame.state.watermarks.clone(),
        };
        if let Some(prepared) = prepared {
            self.stage_record_group(
                &mut transaction,
                &frame,
                group_request,
                prepared,
                inputs.as_mut().expect("prepared source group").1,
            )?;
        }
        self.finish_frame(
            &mut transaction,
            &frame,
            operation,
            &idempotency_key,
            &request_digest,
            &response,
        )?;
        if let Some((_, budget)) = &inputs {
            budget.check().map_err(raw_index::budget_error)?;
        }
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(response)
    }

    fn retract_memory(&self, request: ForgetRequest) -> ServiceResult<MutationResponse> {
        self.retract_memory_inner(request, None)
    }

    fn retract_memory_inner(
        &self,
        request: ForgetRequest,
        mut inputs: Option<record_sources::writes::Inputs<'_>>,
    ) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Forget)?;
        if request.mode == ForgetMode::HardDelete {
            require_capability(&request.context, Capability::HardDelete)?;
            return Err(unsupported(
                "native hard delete remains deferred with the security workstream",
            ));
        }
        validate_identifier(&request.idempotency_key, "idempotency key")?;
        validate_identifier(&request.target_id, "retraction target")?;
        let authorization_digest = request.context.authorization_binding_digest()?;
        let mut request_digest = canonical_digest(&(
            "retract-memory-v1",
            &authorization_digest,
            &request.target_id,
            request.mode,
            &request.reason,
        ))?;
        let operation = if inputs.is_some() {
            record_sources::writes::RETRACT
        } else {
            "retract"
        };
        if let Some((sources, _)) = &inputs {
            request_digest = canonical_digest(&(
                record_sources::writes::GROUP_FEATURE,
                operation,
                &request_digest,
                sources,
            ))?;
        }
        let idempotency_key =
            authenticated_idempotency_key(operation, &request.context, &request.idempotency_key)?;
        let (prepared, replay) = self.prepare_record_write_or_replay::<MutationResponse>(
            &request.context,
            operation,
            &idempotency_key,
            &request_digest,
            &mut inputs,
        )?;
        if let Some(replay) = replay {
            return Ok(replay);
        }
        #[cfg(test)]
        if prepared.is_some() {
            record_sources::writes::before_publication();
        }
        let _guard = if let Some((_, budget)) = &inputs {
            self.lock_index_publication(budget)?
        } else {
            self.lock_writes()?
        };
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        if let Some(mut replay) = self.replay::<MutationResponse, _>(
            &transaction,
            &idempotency_key,
            operation,
            &request_digest,
        )? {
            replay.replayed = true;
            return Ok(replay);
        }
        if let Some(prepared) = &prepared {
            self.check_record_write_preparation(&transaction, &request.context, prepared)?;
        } else {
            self.require_legacy_record_writer(&transaction, &request.context.request.workspace_id)?;
        }
        let target_policy = self
            .load_head(&transaction, &request.target_id)?
            .filter(|policy| policy.transaction_to.is_none())
            .ok_or_else(not_found)?;
        if !policy_allows(&request.context.request, &target_policy.access)
            || !target_policy
                .access
                .owners
                .contains(&request.context.request.subject_id)
        {
            return Err(permission_denied());
        }
        self.authorize_record_sources(&transaction, &request.context.request, &target_policy)?;
        if let Some((_, budget)) = inputs.as_mut() {
            self.charge_source_record_body(&transaction, &target_policy, budget)?;
        }
        let mut target = self.load_content(&transaction, &target_policy)?;
        if target.document.lifecycle != MemoryLifecycle::Active {
            return Err(invalid("retraction target is not active"));
        }
        let global_head = self.global_head(&transaction)?;
        let hierarchy_edges = self.active_hierarchy_edges(
            &transaction,
            &request.context.request,
            global_head,
            &target.document.access,
            inputs.as_mut().map(|(_, budget)| &mut **budget),
        )?;
        let has_incident_hierarchy_edges = hierarchy_edges.iter().any(|(_, record)| {
            record.document.links.source.as_deref() == Some(&request.target_id)
                || record.document.links.target.as_deref() == Some(&request.target_id)
        });
        let candidate_hierarchy_edges = if target.document.kind == MemoryRecordKind::Candidate
            && candidate_role(&target.document) == Some(CANDIDATE_MEMORY_ROLE)
        {
            self.active_candidate_hierarchy_edges(
                &transaction,
                &request.context.request,
                global_head,
                &target.document.access,
                inputs.as_mut().map(|(_, budget)| &mut **budget),
            )?
        } else {
            Vec::new()
        };
        let semantic = target.document.kind != MemoryRecordKind::Candidate;
        let mut frame = self.begin_frame(
            &transaction,
            &request.context.request.workspace_id,
            semantic,
        )?;
        if has_incident_hierarchy_edges {
            frame.state.watermarks.graph = frame.state.watermarks.journal;
        }
        target.transaction_to = Some(frame.global_commit);
        let closed_policy = policy_for(&target)?;
        self.put_record(&mut transaction, &closed_policy, &target)?;

        let mut retracted_document = target.document;
        retracted_document.lifecycle = MemoryLifecycle::Retracted;
        let retracted = MemoryRecord {
            document: retracted_document,
            revision: target
                .revision
                .checked_add(1)
                .ok_or_else(|| exhausted("memory revision sequence is exhausted"))?,
            transaction_from: frame.global_commit,
            transaction_to: None,
        };
        let retracted_policy = policy_for(&retracted)?;
        self.put_record(&mut transaction, &retracted_policy, &retracted)?;
        self.close_incident_hierarchy_edges(
            &mut transaction,
            &frame,
            hierarchy_edges,
            &request.target_id,
        )?;
        self.close_candidate_edges_for_superseded(
            &mut transaction,
            &frame,
            candidate_hierarchy_edges,
            &BTreeSet::from([request.target_id.clone()]),
        )?;
        let response = MutationResponse {
            commit_seq: frame.state.watermarks.journal,
            replayed: false,
            request_digest: request_digest.clone(),
            watermarks: frame.state.watermarks.clone(),
        };
        if let Some(prepared) = prepared {
            self.stage_record_group(
                &mut transaction,
                &frame,
                record_sources::writes::GroupRequest::new(
                    operation,
                    &request_digest,
                    &idempotency_key,
                    &request.target_id,
                ),
                prepared,
                inputs.as_mut().expect("prepared source group").1,
            )?;
        }
        self.finish_frame(
            &mut transaction,
            &frame,
            operation,
            &idempotency_key,
            &request_digest,
            &response,
        )?;
        if let Some((_, budget)) = &inputs {
            budget.check().map_err(raw_index::budget_error)?;
        }
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(response)
    }

    fn timeline(&self, request: GetTimelineRequest) -> ServiceResult<TimelineResponse> {
        require_timeline_capabilities(&request)?;
        validate_identifier(&request.record_id, "timeline record ID")?;
        if request.max_revisions == 0 || request.max_revisions > 1_000 {
            return Err(invalid(
                "timeline revision limit must be between 1 and 1000",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.require_suppression_current(
            &snapshot,
            &digest_bytes(request.context.request.workspace_id.as_bytes()),
        )?;
        let (global_commit, state) = self.select_snapshot(
            &snapshot,
            &request.context.request.workspace_id,
            request.at_commit,
        )?;
        let record_digest = digest_bytes(request.record_id.as_bytes());
        let entries = snapshot
            .scan_prefix(
                &self.keyspaces.policy_history,
                &history_prefix(&record_digest),
            )
            .map_err(storage_error)?;
        if entries.len() > 100_000 {
            return Err(exhausted("timeline history exceeds the service limit"));
        }
        let mut revisions = Vec::new();
        for entry in entries {
            let policy: StoredPolicy = decode(&entry.value, "native timeline policy")?;
            validate_stored_policy(&policy)?;
            if policy.record_digest != record_digest
                || policy.kind != request.expected_kind
                || policy.transaction_from > global_commit
                || !policy_allows(&request.context.request, &policy.access)
            {
                continue;
            }
            match self.authorize_record_sources(&snapshot, &request.context.request, &policy) {
                Ok(()) => {}
                Err(error) if record_sources::source_unavailable(&error) => continue,
                Err(error) => return Err(error),
            }
            let mut record = self.load_content(&snapshot, &policy)?;
            if record.transaction_to.is_some_and(|to| to > global_commit) {
                record.transaction_to = None;
            }
            revisions.push(record);
        }
        revisions.sort_by_key(|record| record.revision);
        revisions.truncate(request.max_revisions as usize);
        if revisions.is_empty() {
            return Err(not_found());
        }
        Ok(TimelineResponse {
            revisions,
            snapshot_seq: state.watermarks.journal,
            watermarks: state.watermarks,
        })
    }

    fn recall_page(&self, request: RecallRequest) -> ServiceResult<RecallResponse> {
        validate_request_context(&request.context)?;
        validate_text(&request.query, "recall query", MAX_QUERY_BYTES)?;
        if request.page_size == 0 || request.page_size > 1_000 {
            return Err(invalid("recall page size must be between 1 and 1000"));
        }
        let request_digest = canonical_digest(&(
            "native-recall-v1",
            &request.context.workspace_id,
            &request.context.subject_id,
            &request.context.audiences,
            &request.context.scopes,
            &request.context.purpose,
            request.context.clearance,
            &request.query,
            request.page_size,
            request.at_commit,
        ))?;
        let authorization_digest = request_context_binding(&request.context)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let (global_commit, state) =
            self.select_snapshot(&snapshot, &request.context.workspace_id, request.at_commit)?;
        let offset = match &request.continuation {
            None => 0,
            Some(token) => {
                let cursor = decode_cursor(&self.token_key, token)?;
                if cursor.schema_version != SCHEMA_VERSION
                    || cursor.request_digest != request_digest
                    || cursor.authorization_digest != authorization_digest
                    || cursor.global_commit != global_commit
                    || cursor.workspace_commit != state.watermarks.journal
                {
                    return Err(ServiceError::new(
                        ErrorCode::InvalidContinuation,
                        "recall continuation is bound to another request or snapshot",
                        false,
                    ));
                }
                usize::try_from(cursor.offset)
                    .map_err(|_| exhausted("recall continuation offset exceeds this platform"))?
            }
        };
        let policies = self.authorized_policies(
            &snapshot,
            &request.context,
            global_commit,
            MemoryLifecycle::Active,
            AuthorizedPolicyFamily::Canonical,
        )?;
        let authorized_candidates = u64::try_from(policies.len()).unwrap_or(u64::MAX);
        let mut scored = Vec::new();
        for policy in policies.values() {
            if policy.kind == MemoryRecordKind::Candidate {
                continue;
            }
            let record = self.load_content(&snapshot, policy)?;
            if let Some(score) = lexical_score(&request.query, &record.document) {
                scored.push(RecallHit {
                    id: record.document.id,
                    score,
                });
            }
        }
        scored.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.id.cmp(&right.id))
        });
        if offset > scored.len() {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "recall continuation offset is outside the result set",
                false,
            ));
        }
        let page_size = request.page_size as usize;
        let end = offset.saturating_add(page_size).min(scored.len());
        let hits = scored[offset..end].to_vec();
        let continuation = if end < scored.len() {
            Some(encode_cursor(
                &self.token_key,
                &RecallCursor {
                    schema_version: SCHEMA_VERSION,
                    request_digest: request_digest.clone(),
                    authorization_digest,
                    global_commit,
                    workspace_commit: state.watermarks.journal,
                    offset: u64::try_from(end)
                        .map_err(|_| exhausted("recall result offset exceeds u64"))?,
                },
            )?)
        } else {
            None
        };
        let mut trace = RecallTrace {
            trace_id: String::new(),
            snapshot_seq: state.watermarks.journal,
            operation: "native_policy_first_lexical_v1".to_owned(),
            authorized_candidates,
            selected_ids: hits.iter().map(|hit| hit.id.clone()).collect(),
            watermarks: state.watermarks,
        };
        trace.trace_id = trace_id(&self.token_key, &request.context, &trace)?;
        Ok(RecallResponse {
            hits,
            trace,
            continuation,
        })
    }

    fn authorized_policies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        principal: &RequestContext,
        global_commit: u64,
        lifecycle: MemoryLifecycle,
        family: AuthorizedPolicyFamily,
    ) -> ServiceResult<BTreeMap<String, StoredPolicy>> {
        self.require_suppression_current(
            snapshot,
            &digest_bytes(principal.workspace_id.as_bytes()),
        )?;
        let mut selected = BTreeMap::<String, StoredPolicy>::new();
        let route_prefix = policy_route_prefix(&principal.workspace_id);
        let mut continuation: Option<Vec<u8>> = None;
        let mut scanned = 0_usize;
        loop {
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.policy_route,
                    ScanPageRequest {
                        prefix: &route_prefix,
                        start_after: continuation.as_deref(),
                        max_entries: SCAN_PAGE_ENTRIES,
                        max_bytes: SCAN_PAGE_BYTES,
                    },
                )
                .map_err(storage_error)?;
            scanned = scanned
                .checked_add(page.entries.len())
                .ok_or_else(|| exhausted("native policy scan counter is exhausted"))?;
            if scanned > 1_000_000 {
                return Err(exhausted(
                    "native policy scan exceeds the one-million-label cap",
                ));
            }
            for entry in page.entries {
                let policy: StoredPolicy = decode(&entry.value, "native recall policy")?;
                validate_stored_policy(&policy)?;
                if visible_at(&policy, global_commit)
                    && policy.lifecycle == lifecycle
                    && policy_allows(principal, &policy.access)
                    && family.accepts(policy.kind)
                {
                    match self.authorize_record_sources(snapshot, principal, &policy) {
                        Ok(()) => {}
                        Err(error) if record_sources::source_unavailable(&error) => continue,
                        Err(error) => return Err(error),
                    }
                    selected.insert(policy.record_digest.clone(), policy);
                    if selected.len() > MAX_AUTHORIZED_CANDIDATES {
                        return Err(exhausted(
                            "authorized recall candidate set exceeds the service limit",
                        ));
                    }
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if continuation
                .as_ref()
                .is_some_and(|previous| &next <= previous)
            {
                return Err(integrity("native policy scan continuation did not advance"));
            }
            continuation = Some(next);
        }
        Ok(selected)
    }
}

fn keyspace(name: &'static str) -> ServiceResult<Keyspace> {
    Keyspace::new(name).map_err(storage_error)
}

fn encode<T: Serialize>(value: &T) -> ServiceResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| integrity("native canonical serialization failed"))
}

fn decode<T: DeserializeOwned>(bytes: &[u8], label: &'static str) -> ServiceResult<T> {
    serde_json::from_slice(bytes).map_err(|_| integrity(format!("{label} is invalid")))
}

fn digest_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn manifest_checksum(manifest: &Manifest) -> ServiceResult<String> {
    let mut unsigned = manifest.clone();
    unsigned.checksum.clear();
    encode(&unsigned).map(|bytes| digest_bytes(&bytes))
}

fn validate_manifest(manifest: &Manifest, database_id: &str) -> ServiceResult<()> {
    if manifest.schema_version != SCHEMA_VERSION
        || manifest.format != FORMAT_NAME
        || manifest.database_id != database_id
        || manifest.features.iter().any(|feature| {
            feature != capture::CAPTURE_FEATURE
                && feature != capture::IMPACT_FEATURE
                && feature != capture::RECOVERY_FEATURE
                && feature != custody::CUSTODY_FEATURE
                && feature != owned::OWNED_FEATURE
                && feature != payload::SOURCE_FEATURE
                && feature != payload::MODEL_PROTOCOL_FEATURE
                && feature != payload::REQUEST_TRANSFORM_FEATURE
                && feature != raw_index::INDEX_FEATURE
                && feature != raw_index::GC_FEATURE
                && feature != raw_index::COPY_FEATURE
                && feature != raw_index::REMOVAL_FEATURE
                && feature != assertions::STATE_FEATURE
                && feature != assertions::PRUNING_FEATURE
                && feature != assertions::CATALOG_FEATURE
                && feature != record_journal::RECORD_FEATURE
                && feature != record_journal::CONTROL_FEATURE
                && feature != record_journal::controls::preparation::FEATURE
                && feature != record_journal::controls::witness::pruning::FEATURE
                && feature != record_sources::FEATURE
                && feature != record_sources::writes::WRITE_FEATURE
                && feature != record_sources::writes::GROUP_FEATURE
                && feature != record_sources::writes::CORRECTION_FEATURE
                && feature != suppression::SUPPRESSION_FEATURE
                && feature != retention::RETENTION_FEATURE
                && feature != retention::PRUNING_FEATURE
                && feature != payload::PAYLOAD_PRUNING_FEATURE
                && feature != encryption::ENCRYPTION_FEATURE
        })
        || manifest.features.contains(suppression::SUPPRESSION_FEATURE)
            != manifest.suppression_authority.is_some()
        || manifest.suppression_authority.is_some_and(|id| id.is_nil())
        || ((manifest.features.contains(record_journal::CONTROL_FEATURE)
            || manifest
                .features
                .contains(record_journal::controls::preparation::FEATURE))
            && !manifest.features.contains(record_journal::RECORD_FEATURE))
        || (manifest
            .features
            .contains(record_sources::writes::CORRECTION_FEATURE)
            && !manifest
                .features
                .contains(record_sources::writes::GROUP_FEATURE))
        || (manifest
            .features
            .contains(record_sources::writes::GROUP_FEATURE)
            && !manifest
                .features
                .contains(record_sources::writes::WRITE_FEATURE))
        || (manifest
            .features
            .contains(record_sources::writes::WRITE_FEATURE)
            && (!manifest.features.contains(record_sources::FEATURE)
                || !manifest.features.contains(record_journal::RECORD_FEATURE)
                || manifest.suppression_authority.is_none()))
        || (manifest.features.contains(retention::RETENTION_FEATURE)
            && manifest.suppression_authority.is_none())
        || (manifest
            .features
            .contains(record_journal::controls::witness::pruning::FEATURE)
            && (!manifest.features.contains(record_journal::RECORD_FEATURE)
                || !manifest.features.contains(retention::RETENTION_FEATURE)))
        || (manifest.features.contains(raw_index::REMOVAL_FEATURE)
            && !manifest.features.contains(retention::RETENTION_FEATURE))
        || (manifest.features.contains(retention::PRUNING_FEATURE)
            && !manifest.features.contains(retention::RETENTION_FEATURE))
        || (manifest.features.contains(assertions::PRUNING_FEATURE)
            && (!manifest.features.contains(retention::RETENTION_FEATURE)
                || !manifest.features.contains(assertions::STATE_FEATURE)))
        || (manifest.features.contains(payload::PAYLOAD_PRUNING_FEATURE)
            && (!manifest.features.contains(retention::PRUNING_FEATURE)
                || !manifest.features.contains(payload::SOURCE_FEATURE)))
        || manifest.features.contains(encryption::ENCRYPTION_FEATURE)
            != manifest.custody_authority.is_some()
        || manifest.custody_authority.is_some_and(|id| id.is_nil())
        || (manifest.custody_authority.is_some() && manifest.suppression_authority.is_none())
        || manifest.state_catalogs.len() > 1024
        || manifest
            .state_catalogs
            .iter()
            .any(|workspace| workspace.len() != 64 || blake3::Hash::from_hex(workspace).is_err())
        || manifest.features.contains(assertions::CATALOG_FEATURE)
            == manifest.state_catalogs.is_empty()
        || manifest.checksum != manifest_checksum(manifest)?
    {
        return Err(ServiceError::new(
            ErrorCode::FormatIncompatible,
            "native database manifest is incompatible",
            false,
        ));
    }
    Ok(())
}

fn validate_workspace_state(state: &WorkspaceState, digest: &str) -> ServiceResult<()> {
    let watermarks = &state.watermarks;
    if state.schema_version != SCHEMA_VERSION
        || state.workspace_digest != digest
        || watermarks.semantic > watermarks.journal
        || watermarks.lexical > watermarks.journal
        || watermarks.vector > watermarks.journal
        || watermarks.graph > watermarks.journal
        || (watermarks.journal == 0) != (state.latest_global_commit == 0)
    {
        return Err(integrity("native workspace state is invalid"));
    }
    Ok(())
}

fn decode_u64(bytes: &[u8], label: &'static str) -> ServiceResult<u64> {
    let exact: [u8; 8] = bytes
        .try_into()
        .map_err(|_| integrity(format!("{label} has invalid length")))?;
    Ok(u64::from_be_bytes(exact))
}

fn workspace_map_key(workspace_digest: &str, workspace_commit: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(workspace_digest.len() + 1 + 8);
    key.extend_from_slice(workspace_digest.as_bytes());
    key.push(b'/');
    key.extend_from_slice(&workspace_commit.to_be_bytes());
    key
}

fn policy_route_prefix(workspace_id: &str) -> Vec<u8> {
    let workspace_digest = digest_bytes(workspace_id.as_bytes());
    let mut key = Vec::with_capacity(workspace_digest.len() + 1);
    key.extend_from_slice(workspace_digest.as_bytes());
    key.push(b'/');
    key
}

fn policy_route_key(workspace_id: &str, record_digest: &str, revision: u32) -> Vec<u8> {
    let mut key = policy_route_prefix(workspace_id);
    key.reserve(record_digest.len() + 1 + size_of::<u32>());
    key.extend_from_slice(record_digest.as_bytes());
    key.push(b'/');
    key.extend_from_slice(&revision.to_be_bytes());
    key
}

fn history_prefix(record_digest: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(record_digest.len() + 1);
    key.extend_from_slice(record_digest.as_bytes());
    key.push(b'/');
    key
}

fn history_key(record_digest: &str, revision: u32) -> Vec<u8> {
    let mut key = history_prefix(record_digest);
    key.extend_from_slice(&revision.to_be_bytes());
    key
}

fn event_digest(event: &StoredEvent) -> ServiceResult<String> {
    let mut unsigned = event.clone();
    unsigned.event_digest.clear();
    encode(&unsigned).map(|bytes| digest_bytes(&bytes))
}

fn canonical_digest<T: Serialize>(value: &T) -> ServiceResult<String> {
    encode(value).map(|bytes| digest_bytes(&bytes))
}

fn validate_text(value: &str, label: &'static str, maximum: usize) -> ServiceResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(invalid(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_string_set(values: &BTreeSet<String>, label: &'static str) -> ServiceResult<()> {
    if values.len() > MAX_POLICY_VALUES {
        return Err(exhausted(format!("{label} exceeds the service limit")));
    }
    for value in values {
        validate_identifier(value, label)?;
    }
    Ok(())
}

fn validate_request_context(context: &RequestContext) -> ServiceResult<()> {
    validate_identifier(&context.request_id, "request ID")?;
    validate_identifier(&context.workspace_id, "workspace ID")?;
    validate_identifier(&context.subject_id, "subject ID")?;
    validate_identifier(&context.purpose, "purpose")?;
    validate_string_set(&context.audiences, "audience")?;
    validate_string_set(&context.scopes, "scope")
}

fn require_capability(
    context: &AuthenticatedRequestContext,
    capability: Capability,
) -> ServiceResult<()> {
    context.validate_authentication()?;
    if context.capability_grants.contains(&capability) {
        Ok(())
    } else {
        Err(ServiceError::new(
            ErrorCode::Unauthorized,
            "required capability is absent",
            false,
        ))
    }
}

fn validate_access(access: &AccessPolicy) -> ServiceResult<()> {
    validate_identifier(&access.workspace_id, "policy workspace")?;
    validate_string_set(&access.scopes, "policy scope")?;
    validate_string_set(&access.owners, "policy owner")?;
    validate_string_set(&access.audience, "policy audience")?;
    validate_string_set(&access.purposes, "policy purpose")?;
    if access.owners.is_empty() {
        return Err(invalid("memory policy requires at least one owner"));
    }
    if access.audience_purpose_grants.len() > MAX_POLICY_VALUES {
        return Err(exhausted(
            "audience-purpose grant map exceeds the service limit",
        ));
    }
    for (audience, purposes) in &access.audience_purpose_grants {
        validate_identifier(audience, "policy audience grant")?;
        validate_string_set(purposes, "policy purpose grant")?;
    }
    Ok(())
}

fn trusted_legacy_policy(context: &RequestContext) -> AccessPolicy {
    AccessPolicy {
        workspace_id: context.workspace_id.clone(),
        scopes: context.scopes.clone(),
        owners: BTreeSet::from([context.subject_id.clone()]),
        audience: BTreeSet::from([context.subject_id.clone()]),
        audience_purpose_grants: BTreeMap::new(),
        purposes: BTreeSet::from([context.purpose.clone()]),
        sensitivity: Sensitivity::Private,
        consent: Consent::Granted,
        retrievable: true,
    }
}

fn trusted_explicit_policy(context: &RequestContext) -> AccessPolicy {
    trusted_legacy_policy(context)
}

fn trusted_structured_policy(context: &RequestContext) -> AccessPolicy {
    let mut policy = trusted_legacy_policy(context);
    policy.sensitivity = context.clearance;
    policy
}

fn candidate_role(document: &MemoryDocument) -> Option<&str> {
    document
        .attributes
        .get(CANDIDATE_ROLE_ATTRIBUTE)
        .and_then(serde_json::Value::as_str)
}

fn candidate_provenance_attributes(
    context: &AuthenticatedRequestContext,
    input_digest: &str,
    role: &str,
) -> BTreeMap<String, serde_json::Value> {
    BTreeMap::from([
        (
            "contextdb.proposal.schema_version".to_owned(),
            serde_json::json!(SCHEMA_VERSION),
        ),
        (
            "contextdb.proposal.state".to_owned(),
            serde_json::json!("quarantined"),
        ),
        (
            "contextdb.proposal.input_digest".to_owned(),
            serde_json::json!(input_digest),
        ),
        (
            "contextdb.proposal.actor_id".to_owned(),
            serde_json::json!(context.actor_id),
        ),
        (
            "contextdb.proposal.agent_id".to_owned(),
            serde_json::json!(context.agent_id),
        ),
        (
            "contextdb.proposal.session_id".to_owned(),
            serde_json::json!(context.session_id),
        ),
        (
            "contextdb.proposal.request_id".to_owned(),
            serde_json::json!(context.request.request_id),
        ),
        (
            "contextdb.proposal.schema_id".to_owned(),
            serde_json::json!("contextdb.mcp.propose_memory.v1"),
        ),
        (
            "contextdb.proposal.evidence_ids".to_owned(),
            serde_json::json!([]),
        ),
        (
            "contextdb.proposal.promotion_eligible".to_owned(),
            serde_json::json!(false),
        ),
        (CANDIDATE_ROLE_ATTRIBUTE.to_owned(), serde_json::json!(role)),
    ])
}

fn structured_kind_from_document(document: &MemoryDocument) -> Option<StructuredMemoryKind> {
    match document
        .attributes
        .get("contextdb.semantic_kind")?
        .as_str()?
    {
        "project" => Some(StructuredMemoryKind::Project),
        "topic" => Some(StructuredMemoryKind::Topic),
        "decision" => Some(StructuredMemoryKind::Decision),
        "constraint" => Some(StructuredMemoryKind::Constraint),
        "goal" => Some(StructuredMemoryKind::Goal),
        "open_loop" => Some(StructuredMemoryKind::OpenLoop),
        "milestone" => Some(StructuredMemoryKind::Milestone),
        "preference" => Some(StructuredMemoryKind::Preference),
        "fact" => Some(StructuredMemoryKind::Fact),
        "evidence_summary" => Some(StructuredMemoryKind::EvidenceSummary),
        _ => None,
    }
}

fn validate_candidate_provenance_attributes(document: &MemoryDocument) -> ServiceResult<()> {
    if document
        .attributes
        .get("contextdb.proposal.schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(SCHEMA_VERSION))
        || document
            .attributes
            .get("contextdb.proposal.state")
            .and_then(serde_json::Value::as_str)
            != Some("quarantined")
        || document
            .attributes
            .get("contextdb.proposal.schema_id")
            .and_then(serde_json::Value::as_str)
            != Some("contextdb.mcp.propose_memory.v1")
        || document
            .attributes
            .get("contextdb.proposal.promotion_eligible")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(integrity(
            "active candidate quarantine provenance is invalid",
        ));
    }
    for attribute in [
        "contextdb.proposal.actor_id",
        "contextdb.proposal.agent_id",
        "contextdb.proposal.request_id",
    ] {
        if document
            .attributes
            .get(attribute)
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(integrity("active candidate provenance is incomplete"));
        }
    }
    let input_digest = document
        .attributes
        .get("contextdb.proposal.input_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| integrity("active candidate input digest is absent"))?;
    if input_digest.len() != 64 || blake3::Hash::from_hex(input_digest).is_err() {
        return Err(integrity("active candidate input digest is invalid"));
    }
    if !document
        .attributes
        .get("contextdb.proposal.session_id")
        .is_some_and(|session| {
            session.is_null()
                || session
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty())
        })
        || !document
            .attributes
            .get("contextdb.proposal.evidence_ids")
            .is_some_and(serde_json::Value::is_array)
    {
        return Err(integrity(
            "active candidate session or evidence provenance is invalid",
        ));
    }
    Ok(())
}

fn validate_candidate_proposal_document(document: &MemoryDocument) -> ServiceResult<()> {
    validate_candidate_provenance_attributes(document)?;
    if document.links.source.is_some()
        || document.links.target.is_some()
        || document.links.predicate.is_some()
        || document.search_text.as_deref().is_none_or(str::is_empty)
        || document
            .attributes
            .get("contextdb.proposal.schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(SCHEMA_VERSION))
        || document
            .attributes
            .get("contextdb.proposal.state")
            .and_then(serde_json::Value::as_str)
            != Some("quarantined")
        || document
            .attributes
            .get("contextdb.proposal.schema_id")
            .and_then(serde_json::Value::as_str)
            != Some("contextdb.mcp.propose_memory.v1")
        || document
            .attributes
            .get("contextdb.proposal.promotion_eligible")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Err(integrity(
            "active candidate proposal quarantine contract is invalid",
        ));
    }
    for attribute in [
        "contextdb.proposal.actor_id",
        "contextdb.proposal.agent_id",
        "contextdb.proposal.request_id",
    ] {
        if document
            .attributes
            .get(attribute)
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(integrity(
                "active candidate proposal provenance is incomplete",
            ));
        }
    }
    let input_digest = document
        .attributes
        .get("contextdb.proposal.input_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| integrity("active candidate proposal input digest is absent"))?;
    if input_digest.len() != 64 || blake3::Hash::from_hex(input_digest).is_err() {
        return Err(integrity(
            "active candidate proposal input digest is invalid",
        ));
    }
    if !document
        .attributes
        .get("contextdb.proposal.session_id")
        .is_some_and(|session| {
            session.is_null()
                || session
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty())
        })
        || !document
            .attributes
            .get("contextdb.proposal.evidence_ids")
            .is_some_and(serde_json::Value::is_array)
    {
        return Err(integrity(
            "active candidate proposal session or evidence provenance is invalid",
        ));
    }
    let kind = structured_kind_from_document(document)
        .ok_or_else(|| integrity("active candidate proposal semantic kind is invalid"))?;
    let kind = structured_kind_name(kind);
    let expected_facet = format!("contextdb.semantic_kind:{kind}");
    if !document
        .attributes
        .get("facets")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|facets| {
            facets
                .iter()
                .any(|facet| facet.as_str() == Some(expected_facet.as_str()))
        })
    {
        return Err(integrity(
            "active candidate proposal semantic facet is invalid",
        ));
    }
    Ok(())
}

fn verify_acyclic_graph(label: &str, edges: &[(String, String)]) -> ServiceResult<()> {
    let mut nodes = BTreeSet::new();
    let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
    let mut indegree = BTreeMap::<String, usize>::new();
    for (source, target) in edges {
        if source == target {
            return Err(integrity(format!("active {label} contains a self-cycle")));
        }
        nodes.insert(source.clone());
        nodes.insert(target.clone());
        if outgoing
            .entry(source.clone())
            .or_default()
            .insert(target.clone())
        {
            let degree = indegree.entry(target.clone()).or_default();
            *degree = degree
                .checked_add(1)
                .ok_or_else(|| exhausted(format!("{label} indegree is exhausted")))?;
        }
        indegree.entry(source.clone()).or_default();
    }
    let mut queue = VecDeque::from_iter(
        nodes
            .iter()
            .filter(|node| indegree.get(*node).copied().unwrap_or_default() == 0)
            .cloned(),
    );
    let mut visited = 0_usize;
    while let Some(node) = queue.pop_front() {
        visited = visited
            .checked_add(1)
            .ok_or_else(|| exhausted(format!("{label} verification is exhausted")))?;
        if let Some(targets) = outgoing.get(&node) {
            for target in targets {
                let degree = indegree
                    .get_mut(target)
                    .ok_or_else(|| integrity(format!("active {label} indegree is absent")))?;
                *degree = degree
                    .checked_sub(1)
                    .ok_or_else(|| integrity(format!("active {label} indegree underflow")))?;
                if *degree == 0 {
                    queue.push_back(target.clone());
                }
            }
        }
    }
    if visited != nodes.len() {
        return Err(integrity(format!("active {label} contains a cycle")));
    }
    Ok(())
}

fn bounded_bfs(
    start_ids: &[String],
    direction: TraverseDirection,
    max_hops: u8,
    max_nodes: u32,
    outgoing: &BTreeMap<String, BTreeSet<String>>,
    incoming: &BTreeMap<String, BTreeSet<String>>,
) -> ServiceResult<Vec<String>> {
    let max_nodes = usize::try_from(max_nodes)
        .map_err(|_| exhausted("traversal node budget exceeds this platform"))?;
    let mut visited = BTreeSet::new();
    let mut result = Vec::new();
    let mut queue = VecDeque::new();
    for start_id in start_ids {
        if visited.insert(start_id.clone()) {
            result.push(start_id.clone());
            queue.push_back((start_id.clone(), 0_u8));
            if result.len() == max_nodes {
                break;
            }
        }
    }
    while result.len() < max_nodes {
        let Some((current, depth)) = queue.pop_front() else {
            break;
        };
        if depth >= max_hops {
            continue;
        }
        let mut neighbors = BTreeSet::new();
        if direction != TraverseDirection::Incoming
            && let Some(targets) = outgoing.get(&current)
        {
            neighbors.extend(targets.iter().cloned());
        }
        if direction != TraverseDirection::Outgoing
            && let Some(sources) = incoming.get(&current)
        {
            neighbors.extend(sources.iter().cloned());
        }
        for neighbor in neighbors {
            if visited.insert(neighbor.clone()) {
                result.push(neighbor.clone());
                if result.len() == max_nodes {
                    break;
                }
                queue.push_back((neighbor, depth + 1));
            }
        }
    }
    Ok(result)
}

fn candidate_hierarchy_edge_id(parent_id: &str, child_id: &str) -> ServiceResult<String> {
    canonical_digest(&(
        "contextdb-candidate-hierarchy-edge-v1",
        CANDIDATE_HIERARCHY_PARENT_PREDICATE,
        parent_id,
        child_id,
    ))
    .map(|digest| format!("candidate-hierarchy-edge:{digest}"))
}

fn reject_candidate_hierarchy_cycle(
    edges: &[(StoredPolicy, MemoryRecord)],
    child_id: &str,
    parent_ids: &BTreeSet<String>,
) -> ServiceResult<()> {
    if parent_ids.is_empty() {
        return Ok(());
    }
    let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
    for (_, record) in edges {
        let source = record
            .document
            .links
            .source
            .as_ref()
            .ok_or_else(|| integrity("candidate hierarchy source is absent"))?;
        let target = record
            .document
            .links
            .target
            .as_ref()
            .ok_or_else(|| integrity("candidate hierarchy target is absent"))?;
        outgoing
            .entry(source.clone())
            .or_default()
            .insert(target.clone());
    }
    let mut queue = VecDeque::from([child_id.to_owned()]);
    let mut visited = BTreeSet::new();
    while let Some(current) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        if visited.len() > MAX_AUTHORIZED_CANDIDATES {
            return Err(exhausted(
                "candidate hierarchy cycle check exceeds the service limit",
            ));
        }
        if parent_ids.contains(&current) {
            return Err(invalid("candidate hierarchy proposal would create a cycle"));
        }
        if let Some(targets) = outgoing.get(&current) {
            queue.extend(targets.iter().cloned());
        }
    }
    Ok(())
}

fn hierarchy_rewire_document(
    old: &MemoryDocument,
    source: &str,
    target: &str,
) -> ServiceResult<MemoryDocument> {
    let mut links = old.links.clone();
    links.source = Some(source.into());
    links.target = Some(target.into());
    links.supersedes.insert(old.id.clone());
    Ok(MemoryDocument {
        id: hierarchy_edge_id(source, target)?,
        kind: MemoryRecordKind::Edge,
        access: old.access.clone(),
        valid_time: old.valid_time,
        lifecycle: MemoryLifecycle::Active,
        links,
        value: serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "relation": "parent",
            "parent_id": source,
            "child_id": target,
        }),
        search_text: None,
        vector: None,
        attributes: old.attributes.clone(),
    })
}

fn hierarchy_edge_id(parent_id: &str, child_id: &str) -> ServiceResult<String> {
    canonical_digest(&(
        "contextdb-hierarchy-edge-v1",
        HIERARCHY_PARENT_PREDICATE,
        parent_id,
        child_id,
    ))
    .map(|digest| format!("hierarchy-edge:{digest}"))
}

const fn structured_kind_name(kind: StructuredMemoryKind) -> &'static str {
    match kind {
        StructuredMemoryKind::Project => "project",
        StructuredMemoryKind::Topic => "topic",
        StructuredMemoryKind::Decision => "decision",
        StructuredMemoryKind::Constraint => "constraint",
        StructuredMemoryKind::Goal => "goal",
        StructuredMemoryKind::OpenLoop => "open_loop",
        StructuredMemoryKind::Milestone => "milestone",
        StructuredMemoryKind::Preference => "preference",
        StructuredMemoryKind::Fact => "fact",
        StructuredMemoryKind::EvidenceSummary => "evidence_summary",
    }
}

fn validate_structured_successor(
    target: &MemoryDocument,
    replacement: &MemoryDocument,
) -> ServiceResult<()> {
    let structured = target
        .attributes
        .get("contextdb.structured_memory.schema_version")
        .and_then(serde_json::Value::as_u64)
        == Some(u64::from(SCHEMA_VERSION));
    if !structured {
        return Ok(());
    }
    if replacement.kind != MemoryRecordKind::SemanticObject
        || replacement
            .attributes
            .get("contextdb.structured_memory.schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(SCHEMA_VERSION))
        || replacement.links.source.is_some()
        || replacement.links.target.is_some()
        || replacement.links.predicate.is_some()
    {
        return Err(invalid(
            "structured correction must preserve the typed semantic-object contract",
        ));
    }
    let Some(kind) = replacement
        .attributes
        .get("contextdb.semantic_kind")
        .and_then(serde_json::Value::as_str)
    else {
        return Err(invalid(
            "structured correction requires a semantic kind attribute",
        ));
    };
    if !is_structured_kind_name(kind)
        || !replacement
            .attributes
            .get("facets")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|facets| {
                let expected = format!("contextdb.semantic_kind:{kind}");
                facets
                    .iter()
                    .any(|facet| facet.as_str() == Some(expected.as_str()))
            })
    {
        return Err(invalid(
            "structured correction semantic kind and facet are inconsistent",
        ));
    }
    Ok(())
}

fn is_structured_kind_name(kind: &str) -> bool {
    matches!(
        kind,
        "project"
            | "topic"
            | "decision"
            | "constraint"
            | "goal"
            | "open_loop"
            | "milestone"
            | "preference"
            | "fact"
            | "evidence_summary"
    )
}

fn reject_rewired_hierarchy_cycle(
    edges: &[(StoredPolicy, MemoryRecord)],
    target_id: &str,
    replacement_id: &str,
) -> ServiceResult<()> {
    let mut nodes = BTreeSet::new();
    let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();
    let mut indegree = BTreeMap::<String, usize>::new();
    for (_, record) in edges {
        let source = record
            .document
            .links
            .source
            .as_ref()
            .ok_or_else(|| integrity("hierarchy edge source is absent"))?;
        let target = record
            .document
            .links
            .target
            .as_ref()
            .ok_or_else(|| integrity("hierarchy edge target is absent"))?;
        let source = if source == target_id {
            replacement_id
        } else {
            source
        };
        let target = if target == target_id {
            replacement_id
        } else {
            target
        };
        if source == target {
            return Err(invalid("hierarchy correction would create a self edge"));
        }
        nodes.insert(source.to_owned());
        nodes.insert(target.to_owned());
        if nodes.len() > MAX_AUTHORIZED_CANDIDATES {
            return Err(exhausted(
                "hierarchy correction graph exceeds the service limit",
            ));
        }
        if outgoing
            .entry(source.to_owned())
            .or_default()
            .insert(target.to_owned())
        {
            let value = indegree.entry(target.to_owned()).or_default();
            *value = value
                .checked_add(1)
                .ok_or_else(|| exhausted("hierarchy indegree is exhausted"))?;
        }
        indegree.entry(source.to_owned()).or_default();
    }

    let mut ready = BTreeSet::new();
    for node in &nodes {
        if indegree.get(node).copied().unwrap_or_default() == 0 {
            ready.insert(node.clone());
        }
    }
    let mut visited = 0_usize;
    while let Some(node) = ready.pop_first() {
        visited = visited
            .checked_add(1)
            .ok_or_else(|| exhausted("hierarchy traversal count is exhausted"))?;
        if let Some(targets) = outgoing.get(&node) {
            for target in targets {
                let degree = indegree
                    .get_mut(target)
                    .ok_or_else(|| integrity("hierarchy indegree entry is absent"))?;
                *degree = degree
                    .checked_sub(1)
                    .ok_or_else(|| integrity("hierarchy indegree underflow"))?;
                if *degree == 0 {
                    ready.insert(target.clone());
                }
            }
        }
    }
    if visited != nodes.len() {
        return Err(invalid("hierarchy correction would create a cycle"));
    }
    Ok(())
}

fn validate_observe(request: &ObserveRequest) -> ServiceResult<()> {
    validate_request_context(&request.context)?;
    validate_identifier(&request.idempotency_key, "idempotency key")?;
    validate_identifier(&request.observation_id, "observation ID")?;
    validate_access(&request.access)?;
    validate_json(&request.metadata, "observation metadata")?;
    validate_json(&request.content, "observation content")?;
    if request.access != trusted_legacy_policy(&request.context) {
        return Err(permission_denied());
    }
    Ok(())
}

fn validate_json<T: Serialize>(value: &T, label: &'static str) -> ServiceResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid(format!("{label} is invalid")))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(exhausted(format!("{label} exceeds the 8 MiB limit")));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| invalid(format!("{label} is invalid")))?;
    validate_json_depth(&value, 0, label)
}

fn validate_json_depth(
    value: &serde_json::Value,
    depth: usize,
    label: &'static str,
) -> ServiceResult<()> {
    if depth > 64 {
        return Err(exhausted(format!("{label} exceeds the JSON depth limit")));
    }
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                validate_json_depth(value, depth + 1, label)?;
            }
        }
        serde_json::Value::Object(values) => {
            if values.len() > MAX_POLICY_VALUES {
                return Err(exhausted(format!("{label} object exceeds the field limit")));
            }
            for value in values.values() {
                validate_json_depth(value, depth + 1, label)?;
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
    Ok(())
}

fn validate_memory_document(document: &MemoryDocument) -> ServiceResult<()> {
    validate_identifier(&document.id, "memory ID")?;
    validate_access(&document.access)?;
    validate_json(&document.value, "memory value")?;
    validate_json(&document.attributes, "memory attributes")?;
    if let Some(search_text) = &document.search_text {
        validate_text(search_text, "memory search text", MAX_QUERY_BYTES)?;
    }
    if document.vector.as_ref().is_some_and(|vector| {
        vector.is_empty() || vector.len() > 4_096 || vector.iter().any(|value| !value.is_finite())
    }) {
        return Err(invalid("memory vector is invalid"));
    }
    if document
        .valid_time
        .to
        .is_some_and(|to| document.valid_time.from.is_some_and(|from| from >= to))
    {
        return Err(invalid("memory valid-time range is invalid"));
    }
    for value in document
        .links
        .subject
        .iter()
        .chain(document.links.source.iter())
        .chain(document.links.target.iter())
        .chain(document.links.predicate.iter())
        .chain(document.links.conflict_set.iter())
        .chain(&document.links.supersedes)
        .chain(&document.links.evidence)
        .chain(&document.links.conflict_members)
    {
        validate_identifier(value, "memory link")?;
    }
    Ok(())
}

fn policy_for(record: &MemoryRecord) -> ServiceResult<StoredPolicy> {
    validate_memory_document(&record.document)?;
    if record.revision == 0
        || record
            .transaction_to
            .is_some_and(|to| record.transaction_from >= to)
    {
        return Err(invalid("memory transaction-time revision is invalid"));
    }
    Ok(StoredPolicy {
        schema_version: SCHEMA_VERSION,
        record_digest: digest_bytes(record.document.id.as_bytes()),
        revision: record.revision,
        kind: record.document.kind,
        access: record.document.access.clone(),
        lifecycle: record.document.lifecycle,
        transaction_from: record.transaction_from,
        transaction_to: record.transaction_to,
        content_digest: canonical_digest(record)?,
    })
}

fn validate_stored_policy(policy: &StoredPolicy) -> ServiceResult<()> {
    validate_access(&policy.access)?;
    if policy.schema_version != SCHEMA_VERSION
        || policy.record_digest.len() != 64
        || blake3::Hash::from_hex(&policy.record_digest).is_err()
        || policy.revision == 0
        || policy.transaction_from == 0
        || policy
            .transaction_to
            .is_some_and(|to| policy.transaction_from >= to)
        || policy.content_digest.len() != 64
        || blake3::Hash::from_hex(&policy.content_digest).is_err()
    {
        return Err(integrity("native stored policy is invalid"));
    }
    Ok(())
}

fn visible_at(policy: &StoredPolicy, global_commit: u64) -> bool {
    policy.transaction_from <= global_commit
        && policy
            .transaction_to
            .is_none_or(|transaction_to| global_commit < transaction_to)
}

fn policy_allows(principal: &RequestContext, policy: &AccessPolicy) -> bool {
    if policy.workspace_id != principal.workspace_id
        || policy.consent != Consent::Granted
        || !policy.retrievable
        || policy.sensitivity > principal.clearance
        || (!policy.scopes.is_empty()
            && !policy
                .scopes
                .iter()
                .any(|scope| principal.scopes.contains(scope)))
    {
        return false;
    }
    let owner = policy.owners.contains(&principal.subject_id);
    if policy.audience_purpose_grants.is_empty() {
        let audience = owner
            || policy.audience.contains(&principal.subject_id)
            || policy.audience.contains("*")
            || principal
                .audiences
                .iter()
                .any(|audience| policy.audience.contains(audience));
        let purpose = policy.purposes.is_empty() || policy.purposes.contains(&principal.purpose);
        audience && purpose
    } else {
        std::iter::once(principal.subject_id.as_str())
            .chain(std::iter::once("*"))
            .chain(owner.then_some("@owner"))
            .chain(principal.audiences.iter().map(String::as_str))
            .any(|audience| {
                policy
                    .audience_purpose_grants
                    .get(audience)
                    .is_some_and(|purposes| purposes.contains(&principal.purpose))
            })
    }
}

fn legacy_idempotency_key(
    operation: &'static str,
    context: &RequestContext,
    idempotency_key: &str,
) -> ServiceResult<Vec<u8>> {
    encode(&(
        "contextdb-native-idempotency-v1",
        operation,
        &context.workspace_id,
        &context.subject_id,
        idempotency_key,
    ))
    .map(|bytes| digest_bytes(&bytes).into_bytes())
}

fn authenticated_idempotency_key(
    operation: &'static str,
    context: &AuthenticatedRequestContext,
    idempotency_key: &str,
) -> ServiceResult<Vec<u8>> {
    encode(&(
        "contextdb-native-authenticated-idempotency-v1",
        operation,
        &context.request.workspace_id,
        &context.request.subject_id,
        &context.actor_id,
        &context.agent_id,
        idempotency_key,
    ))
    .map(|bytes| digest_bytes(&bytes).into_bytes())
}

fn request_context_binding(context: &RequestContext) -> ServiceResult<String> {
    canonical_digest(&(
        "contextdb-native-request-binding-v1",
        &context.workspace_id,
        &context.subject_id,
        &context.audiences,
        &context.scopes,
        &context.purpose,
        context.clearance,
    ))
}

fn lexical_terms(text: &str) -> BTreeSet<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .filter(|term| term.len() <= 256)
        .collect()
}

fn lexical_score(query: &str, document: &MemoryDocument) -> Option<f32> {
    let query_terms = lexical_terms(query);
    if query_terms.is_empty() {
        return None;
    }
    let text = document
        .search_text
        .clone()
        .unwrap_or_else(|| serde_json::to_string(&document.value).unwrap_or_default());
    let document_terms = lexical_terms(&text);
    let overlap = query_terms.intersection(&document_terms).count();
    if overlap == 0 {
        return None;
    }
    let denominator = query_terms.len().max(1) as f32;
    let mut score = overlap as f32 / denominator;
    if text.to_lowercase().contains(&query.to_lowercase()) {
        score += 1.0;
    }
    score.is_finite().then_some(score)
}

fn require_timeline_capabilities(request: &GetTimelineRequest) -> ServiceResult<()> {
    match request.expected_kind {
        MemoryRecordKind::Evidence => {
            require_capability(&request.context, Capability::ReadEvidence)?;
            require_capability(&request.context, Capability::RawEvidence)
        }
        MemoryRecordKind::Conflict => {
            require_capability(&request.context, Capability::ReadConflict)
        }
        MemoryRecordKind::Node
        | MemoryRecordKind::Claim
        | MemoryRecordKind::Edge
        | MemoryRecordKind::Candidate
        | MemoryRecordKind::SemanticObject
        | MemoryRecordKind::RuntimeState
        | MemoryRecordKind::DomainExtension => {
            require_capability(&request.context, Capability::ReadMemory)
        }
    }
}

fn keyed_token(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(domain.len().saturating_add(payload.len()));
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(payload);
    blake3::keyed_hash(key, &bytes).to_hex().to_string()
}

fn encode_cursor(key: &[u8; 32], cursor: &RecallCursor) -> ServiceResult<String> {
    let bytes = encode(cursor)?;
    let payload = encode_hex(&bytes);
    let mac = keyed_token(
        key,
        b"contextdb/native-recall-cursor/v1\0",
        payload.as_bytes(),
    );
    Ok(format!("{payload}.{mac}"))
}

fn decode_cursor(key: &[u8; 32], token: &str) -> ServiceResult<RecallCursor> {
    if token.len() > 32 * 1024 {
        return Err(ServiceError::new(
            ErrorCode::InvalidContinuation,
            "recall continuation exceeds the service limit",
            false,
        ));
    }
    let (payload, mac) = token.rsplit_once('.').ok_or_else(|| {
        ServiceError::new(
            ErrorCode::InvalidContinuation,
            "recall continuation is malformed",
            false,
        )
    })?;
    let expected = keyed_token(
        key,
        b"contextdb/native-recall-cursor/v1\0",
        payload.as_bytes(),
    );
    if mac != expected {
        return Err(ServiceError::new(
            ErrorCode::InvalidContinuation,
            "recall continuation authentication failed",
            false,
        ));
    }
    let bytes = decode_hex(payload).ok_or_else(|| {
        ServiceError::new(
            ErrorCode::InvalidContinuation,
            "recall continuation encoding is invalid",
            false,
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        ServiceError::new(
            ErrorCode::InvalidContinuation,
            "recall continuation payload is invalid",
            false,
        )
    })
}

fn trace_id(
    key: &[u8; 32],
    context: &RequestContext,
    trace: &RecallTrace,
) -> ServiceResult<String> {
    let mut unsigned = trace.clone();
    unsigned.trace_id.clear();
    let bytes = encode(&(
        "contextdb-native-recall-trace-v1",
        request_context_binding(context)?,
        unsigned,
    ))?;
    Ok(keyed_token(
        key,
        b"contextdb/native-recall-trace/v1\0",
        &bytes,
    ))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Some(output)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn require_sync(durability: Durability) -> ServiceResult<()> {
    if durability == Durability::Sync {
        Ok(())
    } else {
        Err(unavailable(
            "native Fjall commit did not reach synchronized durability",
            true,
        ))
    }
}

fn storage_error(error: impl fmt::Display) -> ServiceError {
    ServiceError::new(
        ErrorCode::Unavailable,
        format!("native storage operation failed: {error}"),
        true,
    )
}

fn invalid(message: impl Into<String>) -> ServiceError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false)
}

fn integrity(message: impl Into<String>) -> ServiceError {
    ServiceError::new(ErrorCode::IntegrityFailure, message, false)
}

fn unavailable(message: impl Into<String>, retryable: bool) -> ServiceError {
    ServiceError::new(ErrorCode::Unavailable, message, retryable)
}

fn exhausted(message: impl Into<String>) -> ServiceError {
    ServiceError::new(ErrorCode::ResourceExhausted, message, false)
}

fn not_found() -> ServiceError {
    ServiceError::new(ErrorCode::NotFound, "memory record was not found", false)
}

fn permission_denied() -> ServiceError {
    ServiceError::new(
        ErrorCode::PermissionDenied,
        "memory policy denied the operation",
        false,
    )
}

fn unsupported(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::Unsupported, message, false)
}

fn validate_identifier(value: &str, label: &'static str) -> ServiceResult<()> {
    if value.trim().is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.contains('\0') {
        return Err(invalid(format!("{label} is invalid")));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
