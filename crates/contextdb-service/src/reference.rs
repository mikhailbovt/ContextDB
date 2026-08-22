use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use contextdb_reference::{
    AccessLabel, ContextDb, Direction, Lifecycle, LogicalRecord, MaterializedRecord, Mutation,
    ObservationInput, Principal, RecordKind, ReferenceError, SemanticLinks, SemanticTransaction,
    Sensitivity as ReferenceSensitivity, ValidTime, WorkspaceEventCandidateKind,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    AccessPolicy, AuthenticatedRequestContext, BackupResponse, Capability, CognitiveMemoryService,
    CompileContextRequest, CompileContextResponse, Compression, Consent, CorrectRequest,
    CreateBackupRequest, DomainTimeRange, ErrorCode, ExplainRecallRequest, ExportRequest,
    ExportResponse, ForgetMode, ForgetRequest, GetMemoryRequest, GetStatusRequest,
    GetTimelineRequest, HighLevelControlRequest, ImportRequest, ImportResponse, IngestAck,
    IngestDisposition, IngestFrame, IngestFrameValue, MemoryDocument, MemoryEvent, MemoryEventKind,
    MemoryLifecycle, MemoryLinks, MemoryRecord, MemoryRecordKind, MigrateFormatRequest,
    MutationResponse, ObserveRequest, ObserveResponse, PublishMemoryRequest, RecallHit,
    RecallRequest, RecallResponse, RecallTrace, RequestContext, RestoreBackupRequest,
    RestoreBackupResponse, RuntimeRequest, RuntimeResponse, Sensitivity, ServiceError,
    ServiceResult, SnapshotComplete, SourceRevisionManifest, StreamObservation, SubscribeRequest,
    SubscriptionPage, TimelineResponse, TraverseDirection, TraverseRequest, TraverseResponse,
    VerifyRequest, VerifyResponse, Watermarks, continuation, ordered_items_digest,
};

const ARCHIVE_FORMAT: &str = "contextdb.logical.v1";
const RETAINED_SERVICE_EVENTS: usize = 10_000;
const SUBSCRIPTION_SCAN_BUDGET: usize = 4_096;
const SUBSCRIPTION_CURSOR_DOMAIN: &str = "workspace_event_v1";
// The reference index fails closed above 100,000 affected records per
// workspace/publication, leaving a disjoint ordinal range for service events.
const SERVICE_EVENT_ORDINAL_BASE: u32 = 1_000_000;
const RETAINED_STREAM_STATES: usize = 64;
const MAX_OPEN_STREAMS: usize = 8;
const MAX_STREAM_ITEM_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUFFERED_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const HOST_ARCHIVE_AUTHORITY_CONTEXT: &str = "contextdb/service/host-archive-authority/v1";

/// Opaque authority for database-global archive materialization.
///
/// This value is constructed only from the deployment's external 32-byte host
/// key. It is deliberately non-serializable and has no model- or transport-
/// facing DTO representation. A workspace [`Capability::Admin`] grant is not a
/// substitute for this authority.
pub struct HostArchiveAuthority {
    proof: Zeroizing<[u8; 32]>,
}

impl HostArchiveAuthority {
    /// Derives database-global archive authority from an external host key.
    pub fn new(host_key: [u8; 32]) -> ServiceResult<Self> {
        let host_key = Zeroizing::new(host_key);
        if host_key.iter().all(|byte| *byte == 0) {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "host archive authority key must not be all zero",
                false,
            ));
        }
        Ok(Self {
            proof: Zeroizing::new(blake3::derive_key(
                HOST_ARCHIVE_AUTHORITY_CONTEXT,
                host_key.as_ref(),
            )),
        })
    }
}

impl std::fmt::Debug for HostArchiveAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostArchiveAuthority")
            .finish_non_exhaustive()
    }
}

/// Canonical service backed by the deterministic reference engine.
pub struct ReferenceService {
    database: RwLock<ContextDb>,
    continuation_key: Zeroizing<[u8; 32]>,
    streams: RwLock<StreamRegistry>,
    mutation_replays: RwLock<BTreeMap<String, MutationReplay>>,
}

#[derive(Clone, Debug)]
struct IngestState {
    context_digest: String,
    manifest: SourceRevisionManifest,
    frame_digests: BTreeMap<u64, String>,
    acknowledgements: BTreeMap<u64, IngestAck>,
    observations: Vec<StreamObservation>,
    buffered_bytes: usize,
    next_position: u64,
    complete: bool,
}

#[derive(Debug, Default)]
struct StreamRegistry {
    streams: BTreeMap<(String, String), IngestState>,
    completed_streams: VecDeque<(String, String)>,
    source_heads: BTreeMap<(String, String), SourceHead>,
    service_events: BTreeMap<String, VecDeque<MemoryEvent>>,
    dropped_before: BTreeMap<String, (u64, u32, String)>,
    next_service_ordinal: BTreeMap<(String, u64), u32>,
}

#[derive(Clone, Debug)]
struct SourceHead {
    stream_id: String,
    revision_id: String,
    authorization_digest: String,
}

#[derive(Debug)]
struct AuthorizedEventScan {
    events: Vec<MemoryEvent>,
    checkpoint: (u64, u32),
    authorized_commit: Option<u64>,
    has_more: bool,
}

#[derive(Clone, Debug)]
struct MutationReplay {
    request_digest: String,
    response: MutationResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", content = "parameters", rename_all = "snake_case")]
enum SemanticControlIntent {
    Suppress(crate::high_level::SuppressParametersV1),
    ChangeAudience(crate::high_level::ChangeAudienceParametersV1),
    PublishToSharedMemory(crate::high_level::PublishSharedParametersV1),
    RevokeSharedMemory(crate::high_level::RevokeSharedParametersV1),
}

impl SemanticControlIntent {
    const fn operation(&self) -> &'static str {
        match self {
            Self::Suppress(_) => "suppress",
            Self::ChangeAudience(_) => "change_audience",
            Self::PublishToSharedMemory(_) => "publish_to_shared_memory",
            Self::RevokeSharedMemory(_) => "revoke_shared_memory",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IngestCursor {
    schema_version: u16,
    workspace_id: String,
    actor_id: String,
    agent_id: String,
    authorization_digest: String,
    stream_id: String,
    manifest_digest: String,
    next_position: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionCursor {
    schema_version: u16,
    sequence_domain: String,
    binding_digest: String,
    after_commit: u64,
    after_ordinal: u32,
    after_event_id: String,
    authorized_commit: Option<u64>,
}

impl ReferenceService {
    /// Creates an empty canonical service. A non-zero deployment secret is
    /// required for continuation and explain-handle authentication.
    pub fn new(database_id: impl Into<String>, continuation_key: [u8; 32]) -> ServiceResult<Self> {
        if continuation_key.iter().all(|byte| *byte == 0) {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "continuation key must not be all zero",
                false,
            ));
        }
        let database = ContextDb::new(database_id).map_err(map_reference_error)?;
        Ok(Self {
            database: RwLock::new(database),
            continuation_key: Zeroizing::new(continuation_key),
            streams: RwLock::new(StreamRegistry::default()),
            mutation_replays: RwLock::new(BTreeMap::new()),
        })
    }

    /// Wraps an existing validated reference database. This is the embedded
    /// adapter seam used by imports, examples, and differential tests.
    pub fn from_database(database: ContextDb, continuation_key: [u8; 32]) -> ServiceResult<Self> {
        if continuation_key.iter().all(|byte| *byte == 0) {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "continuation key must not be all zero",
                false,
            ));
        }
        database.snapshot().map_err(map_reference_error)?;
        Ok(Self {
            database: RwLock::new(database),
            continuation_key: Zeroizing::new(continuation_key),
            streams: RwLock::new(StreamRegistry::default()),
            mutation_replays: RwLock::new(BTreeMap::new()),
        })
    }

    /// Exports the complete logical database for a trusted local host
    /// persistence or operator boundary.
    ///
    /// This is intentionally separate from [`CognitiveMemoryService`]: its
    /// opaque authority cannot be supplied by a workspace request, wire DTO,
    /// or MCP tool argument.
    pub fn export_host_archive(
        &self,
        authority: &HostArchiveAuthority,
    ) -> ServiceResult<ExportResponse> {
        self.validate_host_archive_authority(authority)?;
        let database = self.read()?;
        let snapshot = database.snapshot().map_err(map_reference_error)?;
        let bytes = database.export().map_err(map_reference_error)?;
        let digest = blake3::hash(&bytes).to_hex().to_string();
        Ok(ExportResponse {
            format: ARCHIVE_FORMAT.to_owned(),
            bytes,
            digest,
            commit_seq: snapshot.commit_seq,
        })
    }

    /// Replaces this isolated service from a complete host-verified logical
    /// archive.
    ///
    /// Callers must provide the opaque authority derived from the same
    /// external key used to construct this service. This seam is for local
    /// clone/recovery orchestration; public workspace requests cannot invoke
    /// it through [`CognitiveMemoryService`].
    pub fn import_host_archive(
        &self,
        authority: &HostArchiveAuthority,
        format: &str,
        bytes: &[u8],
        digest: &str,
    ) -> ServiceResult<ImportResponse> {
        self.validate_host_archive_authority(authority)?;
        let actual_digest = blake3::hash(bytes).to_hex().to_string();
        if format != ARCHIVE_FORMAT || actual_digest != digest {
            return Err(ServiceError::new(
                ErrorCode::IntegrityFailure,
                "archive format or digest is invalid",
                false,
            ));
        }
        let imported = ContextDb::import(bytes).map_err(map_reference_error)?;
        let snapshot = imported.snapshot().map_err(map_reference_error)?;
        let watermarks = imported.watermarks().map_err(map_reference_error)?;
        *self.write()? = imported;
        *self.streams.write().map_err(|_| lock_error())? = StreamRegistry::default();
        self.mutation_replays
            .write()
            .map_err(|_| lock_error())?
            .clear();
        Ok(ImportResponse {
            commit_seq: snapshot.commit_seq,
            watermarks: map_watermarks(watermarks),
        })
    }

    fn validate_host_archive_authority(
        &self,
        authority: &HostArchiveAuthority,
    ) -> ServiceResult<()> {
        let expected = Zeroizing::new(blake3::derive_key(
            HOST_ARCHIVE_AUTHORITY_CONTEXT,
            self.continuation_key.as_ref(),
        ));
        if !constant_time_equal(authority.proof.as_ref(), expected.as_ref()) {
            return Err(ServiceError::new(
                ErrorCode::Unauthorized,
                "host archive authority does not match this service",
                false,
            ));
        }
        Ok(())
    }

    fn read(&self) -> ServiceResult<RwLockReadGuard<'_, ContextDb>> {
        self.database.read().map_err(|_| {
            ServiceError::new(ErrorCode::Unavailable, "service lock was poisoned", true)
        })
    }

    fn write(&self) -> ServiceResult<RwLockWriteGuard<'_, ContextDb>> {
        self.database.write().map_err(|_| {
            ServiceError::new(ErrorCode::Unavailable, "service lock was poisoned", true)
        })
    }
}

impl std::fmt::Debug for ReferenceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReferenceService")
            .field("profile", &"reference-in-memory")
            .finish_non_exhaustive()
    }
}

impl ReferenceService {
    fn apply_semantic_control(
        &self,
        request: HighLevelControlRequest,
        intent: SemanticControlIntent,
    ) -> ServiceResult<MutationResponse> {
        let request_digest = semantic_control_digest(&request, &intent)?;
        let cache_key = scoped_idempotency_key(
            &request.context,
            intent.operation(),
            &request.idempotency_key,
        )?;
        let mut replay_cache = self.mutation_replays.write().map_err(|_| lock_error())?;
        if let Some(cached) = replay_cache.get(&cache_key) {
            return replay_mutation(cached, &request_digest);
        }

        let database = self.read()?;
        let snapshot = database.snapshot().map_err(map_reference_error)?;
        let principal = to_principal(&request.context.request);
        let target = database
            .get(&request.target_id, &snapshot, &principal)
            .map_err(map_reference_error)?;
        if !target
            .revision
            .record
            .access
            .owners
            .contains(&request.target_subject_id)
        {
            return Err(ServiceError::new(
                ErrorCode::PermissionDenied,
                "semantic controls require current target ownership",
                false,
            )
            .with_context(
                Vec::new(),
                Some("semantic_control_owner".to_owned()),
                Some("authenticate as a current owner of the target memory".to_owned()),
                None,
            ));
        }
        if target.revision.record.lifecycle != Lifecycle::Active {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "semantic controls require an active target revision",
                false,
            ));
        }

        let expected_revision = target.revision.revision;
        let mut record = to_logical_record(map_memory_record(target).document);
        apply_control_intent(&request, &intent, &mut record)?;
        let receipt = database
            .commit(SemanticTransaction {
                base_seq: snapshot.commit_seq,
                idempotency_key: cache_key.clone(),
                mutations: vec![Mutation::Put {
                    record,
                    expected_revision: Some(expected_revision),
                }],
            })
            .map_err(map_reference_error)?;
        let mut response = mutation_response(receipt);
        // The public receipt binds only caller identity, target identity, and
        // the exact content-free control DTO. The replacement record's raw
        // payload never enters this response or the service replay cache.
        response.request_digest.clone_from(&request_digest);
        replay_cache.insert(
            cache_key,
            MutationReplay {
                request_digest,
                response: response.clone(),
            },
        );
        Ok(response)
    }
}

impl CognitiveMemoryService for ReferenceService {
    fn observe(&self, request: ObserveRequest) -> ServiceResult<ObserveResponse> {
        validate_observe_request(&request)?;
        let receipt = self
            .read()?
            .observe(ObservationInput {
                idempotency_key: request.idempotency_key,
                observation_id: request.observation_id,
                access: to_access(request.access),
                metadata: request.metadata,
                content: request.content,
            })
            .map_err(map_reference_error)?;
        Ok(ObserveResponse {
            commit_seq: receipt.commit_seq,
            replayed: receipt.replayed,
            request_digest: receipt.request_digest,
            watermarks: map_watermarks(receipt.watermarks),
        })
    }

    fn recall(&self, request: RecallRequest) -> ServiceResult<RecallResponse> {
        validate_context(&request.context)?;
        validate_identifier(&request.query, "recall query", 32_768)?;
        if request.page_size == 0 || request.page_size > 1_000 {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "page size must be between 1 and 1000",
                false,
            ));
        }
        let digest = continuation::request_digest(&request)?;
        let (snapshot_seq, offset) = match &request.continuation {
            Some(token) => {
                let cursor = continuation::decode(&self.continuation_key, token)?;
                let requested_snapshot = request
                    .at_commit
                    .map(|workspace_seq| {
                        self.read()?
                            .snapshot_for_workspace(&request.context.workspace_id, workspace_seq)
                            .map_err(map_reference_error)
                    })
                    .transpose()?;
                if cursor.request_digest != digest
                    || requested_snapshot
                        .is_some_and(|snapshot| snapshot.commit_seq != cursor.snapshot_seq)
                {
                    return Err(ServiceError::new(
                        ErrorCode::InvalidContinuation,
                        "continuation is invalid or bound to another request",
                        false,
                    ));
                }
                (cursor.snapshot_seq, cursor.offset)
            }
            None => {
                let database = self.read()?;
                let snapshot = match request.at_commit {
                    Some(commit) => database
                        .snapshot_for_workspace(&request.context.workspace_id, commit)
                        .map_err(map_reference_error)?,
                    None => database.snapshot().map_err(map_reference_error)?,
                };
                (snapshot.commit_seq, 0)
            }
        };
        let page_size = usize::try_from(request.page_size).map_err(|_| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "page size is too large",
                false,
            )
        })?;
        let offset = usize::try_from(offset).map_err(|_| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "continuation offset is too large",
                false,
            )
        })?;
        let fetch_limit = offset
            .checked_add(page_size)
            .and_then(|value| value.checked_add(1))
            .filter(|value| *value <= 100_001)
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::ResourceExhausted,
                    "recall pagination budget exceeded",
                    false,
                )
            })?;
        let database = self.read()?;
        let snapshot = database
            .snapshot_at(snapshot_seq)
            .map_err(map_reference_error)?;
        let principal = to_principal(&request.context);
        let result = database
            .lexical_search(&request.query, fetch_limit, &snapshot, &principal)
            .map_err(map_reference_error)?;
        let has_more = result.value.len() > offset.saturating_add(page_size);
        let hits: Vec<_> = result
            .value
            .into_iter()
            .skip(offset)
            .take(page_size)
            .map(|hit| RecallHit {
                id: hit.id,
                score: hit.score,
            })
            .collect();
        let watermarks = map_watermarks(result.trace.watermarks);
        let public_snapshot_seq = result.trace.snapshot_seq;
        let selected_ids: Vec<_> = hits.iter().map(|hit| hit.id.clone()).collect();
        let authorized_candidates =
            u64::try_from(result.trace.authorized_candidates).unwrap_or(u64::MAX);
        let trace_id = trace_id(
            &self.continuation_key,
            &request.context,
            public_snapshot_seq,
            &result.trace.operation,
            authorized_candidates,
            &selected_ids,
            &watermarks,
        )?;
        let trace = RecallTrace {
            trace_id,
            snapshot_seq: public_snapshot_seq,
            operation: result.trace.operation,
            authorized_candidates,
            selected_ids,
            watermarks,
        };
        let continuation = if has_more {
            Some(continuation::encode(
                &self.continuation_key,
                digest,
                snapshot_seq,
                u64::try_from(offset.saturating_add(page_size)).map_err(|_| {
                    ServiceError::new(
                        ErrorCode::ResourceExhausted,
                        "continuation offset is too large",
                        false,
                    )
                })?,
            )?)
        } else {
            None
        };
        Ok(RecallResponse {
            hits,
            trace,
            continuation,
        })
    }

    fn compile_context(
        &self,
        request: CompileContextRequest,
    ) -> ServiceResult<CompileContextResponse> {
        let database = self.read()?;
        crate::context_pack::compile_reference_context(&database, &self.continuation_key, request)
    }

    fn explain_recall(&self, request: ExplainRecallRequest) -> ServiceResult<RecallTrace> {
        validate_context(&request.context)?;
        let expected = trace_id(
            &self.continuation_key,
            &request.context,
            request.trace.snapshot_seq,
            &request.trace.operation,
            request.trace.authorized_candidates,
            &request.trace.selected_ids,
            &request.trace.watermarks,
        )?;
        if expected != request.trace.trace_id {
            return Err(ServiceError::new(
                ErrorCode::PermissionDenied,
                "recall trace is invalid or belongs to another principal",
                false,
            ));
        }
        self.read()?
            .snapshot_for_workspace(&request.context.workspace_id, request.trace.snapshot_seq)
            .map_err(map_reference_error)?;
        Ok(request.trace)
    }

    fn preflight(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Runtime)?;
        crate::runtime::execute_preflight(request)
    }

    fn export_archive(&self, request: ExportRequest) -> ServiceResult<ExportResponse> {
        require_admin(&request.context)?;
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "workspace requests cannot materialize a database-global archive",
            false,
        )
        .with_context(
            Vec::new(),
            Some("authority:host-global".to_owned()),
            Some("use the local host archive boundary with explicit host authority".to_owned()),
            None,
        ))
    }

    fn import_archive(&self, request: ImportRequest) -> ServiceResult<ImportResponse> {
        require_admin(&request.context)?;
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "workspace requests cannot replace a database-global archive",
            false,
        )
        .with_context(
            Vec::new(),
            Some("authority:host-global".to_owned()),
            Some("construct a new isolated service from a host-verified archive".to_owned()),
            None,
        ))
    }

    fn verify(&self, request: VerifyRequest) -> ServiceResult<VerifyResponse> {
        require_admin(&request.context)?;
        let database = self.read()?;
        let snapshot = database.snapshot().map_err(map_reference_error)?;
        if !request.deep {
            database.journal().map_err(map_reference_error)?;
            return Ok(VerifyResponse {
                valid: true,
                commit_seq: snapshot.commit_seq,
                archive_digest: None,
            });
        }
        let bytes = database.export().map_err(map_reference_error)?;
        let imported = ContextDb::import(&bytes).map_err(map_reference_error)?;
        let replayed = imported.export().map_err(map_reference_error)?;
        if replayed != bytes {
            return Err(ServiceError::new(
                ErrorCode::IntegrityFailure,
                "deep archive replay changed canonical bytes",
                false,
            ));
        }
        Ok(VerifyResponse {
            valid: true,
            commit_seq: snapshot.commit_seq,
            archive_digest: Some(blake3::hash(&bytes).to_hex().to_string()),
        })
    }

    fn ingest_frame(&self, request: IngestFrame) -> ServiceResult<IngestAck> {
        crate::authenticated::require_capability(&request.context, Capability::StreamIngest)?;
        validate_identifier(&request.stream_id, "stream ID", 1_024)?;
        let context_digest = request.context.authorization_binding_digest()?;
        let frame_digest = continuation::digest_value(&request.value)?;
        let workspace_id = request.context.request.workspace_id.clone();
        let stream_id = request.stream_id.clone();
        let key = (workspace_id.clone(), stream_id.clone());

        if let IngestFrameValue::Manifest(manifest) = &request.value {
            if request.position != 0 || request.resume_cursor.is_some() {
                return Err(ServiceError::new(
                    ErrorCode::InvalidContinuation,
                    "a manifest must open a new stream at position zero",
                    false,
                ));
            }
            validate_manifest(manifest)?;
            let mut registry = self.streams.write().map_err(|_| lock_error())?;
            if let Some(existing) = registry.streams.get(&key) {
                if existing.context_digest == context_digest
                    && existing.frame_digests.get(&0) == Some(&frame_digest)
                {
                    return existing.acknowledgements.get(&0).cloned().ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::IntegrityFailure,
                            "stream replay state is incomplete",
                            false,
                        )
                    });
                }
                return Err(ServiceError::new(
                    ErrorCode::IdempotencyConflict,
                    "stream identity was reused with a different manifest or principal",
                    false,
                ));
            }
            while registry.streams.len() >= RETAINED_STREAM_STATES {
                let Some(completed) = registry.completed_streams.pop_front() else {
                    break;
                };
                if registry
                    .streams
                    .get(&completed)
                    .is_some_and(|state| state.complete)
                {
                    registry.streams.remove(&completed);
                }
            }
            if registry.streams.len() >= RETAINED_STREAM_STATES
                || registry
                    .streams
                    .values()
                    .filter(|state| !state.complete)
                    .count()
                    >= MAX_OPEN_STREAMS
            {
                return Err(ServiceError::new(
                    ErrorCode::ResourceExhausted,
                    "reference stream retention or open-stream limit is exhausted",
                    true,
                )
                .with_context(
                    Vec::new(),
                    Some("stream_retention_limit".to_owned()),
                    Some("complete or resume an existing source stream".to_owned()),
                    None,
                ));
            }
            let cursor = encode_ingest_cursor(
                &self.continuation_key,
                &request.context,
                &stream_id,
                &frame_digest,
                1,
            )?;
            let ack = IngestAck {
                stream_id,
                position: 0,
                disposition: IngestDisposition::Accepted,
                frame_digest: frame_digest.clone(),
                resume_cursor: cursor,
                commit_seq: None,
                partial_result_refs: Vec::new(),
                lease_expires_at_ms: None,
            };
            registry.streams.insert(
                key,
                IngestState {
                    context_digest,
                    manifest: manifest.clone(),
                    frame_digests: BTreeMap::from([(0, frame_digest)]),
                    acknowledgements: BTreeMap::from([(0, ack.clone())]),
                    observations: Vec::new(),
                    buffered_bytes: 0,
                    next_position: 1,
                    complete: false,
                },
            );
            return Ok(ack);
        }

        let mut registry = self.streams.write().map_err(|_| lock_error())?;
        let state = registry.streams.get_mut(&key).ok_or_else(|| {
            ServiceError::new(
                ErrorCode::InvalidContinuation,
                "stream manifest is missing or no longer retained",
                false,
            )
        })?;
        if state.context_digest != context_digest {
            return Err(ServiceError::new(
                ErrorCode::Unauthorized,
                "stream belongs to another authenticated principal",
                false,
            ));
        }
        validate_ingest_cursor(
            &self.continuation_key,
            request.resume_cursor.as_deref(),
            &request.context,
            &request.stream_id,
            state.frame_digests.get(&0).ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::IntegrityFailure,
                    "stream manifest digest is missing",
                    false,
                )
            })?,
            request.position,
        )?;

        if request.position < state.next_position {
            if state.frame_digests.get(&request.position) == Some(&frame_digest) {
                return state
                    .acknowledgements
                    .get(&request.position)
                    .cloned()
                    .ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::IntegrityFailure,
                            "stream acknowledgement state is incomplete",
                            false,
                        )
                    });
            }
            return Err(ServiceError::new(
                ErrorCode::IdempotencyConflict,
                "stream position was retried with different content",
                false,
            ));
        }
        if request.position != state.next_position || state.complete {
            return Err(ServiceError::new(
                ErrorCode::InvalidContinuation,
                "stream frame is out of order or follows completion",
                false,
            ));
        }

        match request.value {
            IngestFrameValue::Manifest(_) => Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "a stream may contain exactly one opening manifest",
                false,
            )),
            IngestFrameValue::Observation(observation) => {
                let expected_position = u64::try_from(state.observations.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1);
                if request.position != expected_position
                    || request.position > state.manifest.expected_items
                {
                    return Err(ServiceError::new(
                        ErrorCode::InvalidArgument,
                        "observation position exceeds the declared source manifest",
                        false,
                    ));
                }
                validate_stream_observation(&request.context, &observation)?;
                let observation_bytes = serde_json::to_vec(&observation)
                    .map_err(|_| {
                        ServiceError::new(
                            ErrorCode::IntegrityFailure,
                            "stream observation serialization failed",
                            false,
                        )
                    })?
                    .len();
                if observation_bytes > MAX_STREAM_ITEM_BYTES {
                    return Err(ServiceError::new(
                        ErrorCode::ResourceExhausted,
                        "stream observation exceeds the 16 MiB item limit",
                        false,
                    ));
                }
                let buffered_bytes = state
                    .buffered_bytes
                    .checked_add(observation_bytes)
                    .filter(|bytes| *bytes <= MAX_BUFFERED_SNAPSHOT_BYTES)
                    .ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::ResourceExhausted,
                            "buffered source snapshot exceeds the 64 MiB reference limit",
                            false,
                        )
                    })?;
                let next_position = request.position.saturating_add(1);
                let cursor = encode_ingest_cursor(
                    &self.continuation_key,
                    &request.context,
                    &request.stream_id,
                    state.frame_digests.get(&0).ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::IntegrityFailure,
                            "stream manifest digest is missing",
                            false,
                        )
                    })?,
                    next_position,
                )?;
                let ack = IngestAck {
                    stream_id: request.stream_id,
                    position: request.position,
                    disposition: IngestDisposition::Accepted,
                    frame_digest: frame_digest.clone(),
                    resume_cursor: cursor,
                    commit_seq: None,
                    partial_result_refs: Vec::new(),
                    lease_expires_at_ms: None,
                };
                state.observations.push(observation);
                state.buffered_bytes = buffered_bytes;
                state.frame_digests.insert(request.position, frame_digest);
                state.acknowledgements.insert(request.position, ack.clone());
                state.next_position = next_position;
                Ok(ack)
            }
            IngestFrameValue::SnapshotComplete(marker) => {
                validate_snapshot_complete(&state.manifest, &state.observations, &marker)?;
                let expected_position = state.manifest.expected_items.saturating_add(1);
                if request.position != expected_position {
                    return Err(ServiceError::new(
                        ErrorCode::InvalidArgument,
                        "snapshot completion marker is not at the declared final position",
                        false,
                    ));
                }
                // Build the complete revision against a private imported
                // snapshot. No observation becomes visible until every item
                // has validated and committed successfully in this staging
                // database and the outer database handle is replaced once.
                let (base_seq, archive) = {
                    let database = self.read()?;
                    let snapshot = database.snapshot().map_err(map_reference_error)?;
                    let archive = database.export().map_err(map_reference_error)?;
                    (snapshot.commit_seq, archive)
                };
                let staged = ContextDb::import(&archive).map_err(map_reference_error)?;
                let mut partial_result_refs = Vec::new();
                let mut commit_seq = base_seq;
                for observation in &state.observations {
                    let idempotency_key = scoped_idempotency_key(
                        &request.context,
                        "stream_ingest",
                        &observation.idempotency_key,
                    )?;
                    let input = ObservationInput {
                        idempotency_key,
                        observation_id: observation.observation_id.clone(),
                        access: to_access(observation.access.clone()),
                        metadata: observation.metadata.clone(),
                        content: observation.content.clone(),
                    };
                    match staged.observe(input) {
                        Ok(response) => {
                            commit_seq = commit_seq.max(response.commit_seq);
                            partial_result_refs.push(observation.observation_id.clone());
                        }
                        Err(error) => {
                            let mut error = map_reference_error(error);
                            // These references exist only in discarded staging
                            // state, therefore atomic failure exposes no partial
                            // durable results.
                            error.partial_result_refs = Box::default();
                            return Err(error);
                        }
                    }
                }
                let mut database = self.write()?;
                let current_seq = database.snapshot().map_err(map_reference_error)?.commit_seq;
                if current_seq != base_seq {
                    return Err(ServiceError::new(
                        ErrorCode::Unavailable,
                        "source snapshot publication raced with another commit",
                        true,
                    )
                    .with_context(
                        Vec::new(),
                        Some("snapshot_head_changed".to_owned()),
                        Some("retry completion with the same stream cursor".to_owned()),
                        None,
                    ));
                }
                *database = staged;
                drop(database);
                let next_position = request.position.saturating_add(1);
                let cursor = encode_ingest_cursor(
                    &self.continuation_key,
                    &request.context,
                    &request.stream_id,
                    state.frame_digests.get(&0).ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::IntegrityFailure,
                            "stream manifest digest is missing",
                            false,
                        )
                    })?,
                    next_position,
                )?;
                let ack = IngestAck {
                    stream_id: request.stream_id.clone(),
                    position: request.position,
                    disposition: IngestDisposition::SnapshotCommitted,
                    frame_digest: frame_digest.clone(),
                    resume_cursor: cursor,
                    commit_seq: Some(commit_seq),
                    partial_result_refs,
                    lease_expires_at_ms: None,
                };
                let source_id = state.manifest.source_id.clone();
                let revision_id = state.manifest.revision_id.clone();
                state.frame_digests.insert(request.position, frame_digest);
                state.acknowledgements.insert(request.position, ack.clone());
                state.next_position = next_position;
                state.complete = true;
                state.observations.clear();
                state.buffered_bytes = 0;
                let source_key = (
                    request.context.request.workspace_id.clone(),
                    source_id.clone(),
                );
                let previous_head = registry.source_heads.get(&source_key).cloned();
                let new_head = SourceHead {
                    stream_id: request.stream_id.clone(),
                    revision_id,
                    authorization_digest: context_digest.clone(),
                };
                registry.source_heads.insert(source_key, new_head.clone());
                registry.completed_streams.push_back(key);
                if let Some(previous) = previous_head
                    && previous.stream_id != new_head.stream_id
                {
                    let workspace_seq = {
                        let database = self.read()?;
                        let snapshot = database
                            .snapshot_at(commit_seq)
                            .map_err(map_reference_error)?;
                        database
                            .watermarks_for_workspace(
                                &snapshot,
                                &request.context.request.workspace_id,
                            )
                            .map_err(map_reference_error)?
                            .journal
                    };
                    retain_source_invalidation(
                        &mut registry,
                        &request.context.request.workspace_id,
                        &source_id,
                        &previous,
                        &new_head,
                        workspace_seq,
                    )?;
                }
                Ok(ack)
            }
        }
    }

    fn subscribe(&self, request: SubscribeRequest) -> ServiceResult<SubscriptionPage> {
        crate::authenticated::require_capability(&request.context, Capability::Subscribe)?;
        if request.max_events == 0 || request.max_events > 1_000 {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "subscription page size must be between 1 and 1000",
                false,
            ));
        }
        let binding_digest = subscription_binding_digest(&request)?;
        let authorization_digest = request.context.authorization_binding_digest()?;
        let limit = usize::try_from(request.max_events).map_err(|_| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "subscription page size exceeds this platform",
                false,
            )
        })?;
        let cursor = match request.resume_cursor.as_deref() {
            Some(token) => {
                let cursor: SubscriptionCursor =
                    continuation::decode_value(&self.continuation_key, token)?;
                if cursor.schema_version != crate::SERVICE_SCHEMA_VERSION
                    || cursor.sequence_domain != SUBSCRIPTION_CURSOR_DOMAIN
                    || cursor.binding_digest != binding_digest
                    || cursor
                        .authorized_commit
                        .is_some_and(|commit| commit != cursor.after_commit)
                {
                    return Err(ServiceError::new(
                        ErrorCode::InvalidContinuation,
                        "subscription cursor is bound to another principal or filter",
                        false,
                    ));
                }
                cursor
            }
            None => SubscriptionCursor {
                schema_version: crate::SERVICE_SCHEMA_VERSION,
                sequence_domain: SUBSCRIPTION_CURSOR_DOMAIN.to_owned(),
                binding_digest: binding_digest.clone(),
                after_commit: 0,
                after_ordinal: 0,
                after_event_id: String::new(),
                authorized_commit: None,
            },
        };
        let registry = self.streams.read().map_err(|_| lock_error())?;
        if let Some(dropped) = registry.dropped_before.get(&authorization_digest)
            && !cursor.after_event_id.is_empty()
            && (
                cursor.after_commit,
                cursor.after_ordinal,
                cursor.after_event_id.as_str(),
            ) <= (dropped.0, dropped.1, dropped.2.as_str())
        {
            return Err(ServiceError::new(
                ErrorCode::ContinuationExpired,
                "subscription cursor predates retained service events",
                false,
            )
            .with_context(
                Vec::new(),
                Some("subscription_retention".to_owned()),
                Some("resubscribe from the current retained head".to_owned()),
                None,
            ));
        }
        let mut service_events: Vec<_> = registry
            .service_events
            .get(&authorization_digest)
            .into_iter()
            .flatten()
            .filter(|event| {
                event_position(event)
                    > (
                        cursor.after_commit,
                        cursor.after_ordinal,
                        cursor.after_event_id.as_str(),
                    )
                    && (request.filters.is_empty() || request.filters.contains(&event.kind))
            })
            .take(limit.saturating_add(1))
            .cloned()
            .collect();
        let service_has_more = service_events.len() > limit;
        drop(registry);
        let database = self.read()?;
        if cursor.after_commit > 0 {
            match database
                .snapshot_for_workspace(&request.context.request.workspace_id, cursor.after_commit)
            {
                Ok(_) => {}
                Err(ReferenceError::SnapshotNotFound { .. }) => {
                    return Err(ServiceError::new(
                        ErrorCode::InvalidContinuation,
                        "subscription cursor is outside the workspace event sequence",
                        false,
                    ));
                }
                Err(error) => return Err(map_reference_error(error)),
            }
        }
        let principal = to_principal(&request.context.request);
        let journal = database
            .workspace_event_page(
                &request.context.request.workspace_id,
                cursor.after_commit,
                cursor.after_ordinal,
                SUBSCRIPTION_SCAN_BUDGET,
            )
            .map_err(map_reference_error)?;
        let scan = authorized_events(
            &database,
            &principal,
            &request.context.request.workspace_id,
            journal,
            &cursor,
            limit.saturating_add(1),
        )?;
        let mut events = scan.events;
        events.append(&mut service_events);
        events.retain(|event| {
            (request.filters.is_empty() || request.filters.contains(&event.kind))
                && event_position(event)
                    > (
                        cursor.after_commit,
                        cursor.after_ordinal,
                        cursor.after_event_id.as_str(),
                    )
        });
        events.sort_by(|left, right| event_position(left).cmp(&event_position(right)));
        events.dedup_by(|left, right| left.event_id == right.event_id);
        let output_has_more = events.len() > limit;
        events.truncate(limit);
        let caught_up = !output_has_more && !service_has_more && !scan.has_more;
        let last_event_authorizes_commit = events.last().is_some_and(|event| {
            matches!(
                event.kind,
                MemoryEventKind::NodeChanged
                    | MemoryEventKind::ClaimChanged
                    | MemoryEventKind::ConflictResolved
                    | MemoryEventKind::RecordChanged
                    | MemoryEventKind::OpenLoopTriggered
            )
        });
        let last_event_position = events
            .last()
            .map(|event| (event.commit_seq, event.ordinal, event.event_id.clone()));
        let checkpoint_advances = !output_has_more
            && (scan.checkpoint.0, scan.checkpoint.1) > (cursor.after_commit, cursor.after_ordinal)
            && last_event_position
                .as_ref()
                .is_none_or(|position| (position.0, position.1) <= scan.checkpoint);
        let (after_commit, after_ordinal, after_event_id) = if checkpoint_advances {
            (scan.checkpoint.0, scan.checkpoint.1, String::new())
        } else if let Some(last) = last_event_position {
            last
        } else {
            (
                cursor.after_commit,
                cursor.after_ordinal,
                cursor.after_event_id.clone(),
            )
        };
        let authorized_commit = if last_event_authorizes_commit {
            Some(after_commit)
        } else if scan.checkpoint.0 == after_commit
            && (scan.checkpoint.0, scan.checkpoint.1) >= (after_commit, after_ordinal)
        {
            scan.authorized_commit
        } else if cursor.after_commit == after_commit {
            cursor.authorized_commit
        } else {
            None
        };
        let resume_cursor = continuation::encode_value(
            &self.continuation_key,
            &SubscriptionCursor {
                schema_version: crate::SERVICE_SCHEMA_VERSION,
                sequence_domain: SUBSCRIPTION_CURSOR_DOMAIN.to_owned(),
                binding_digest,
                after_commit,
                after_ordinal,
                after_event_id,
                authorized_commit,
            },
        )?;
        Ok(SubscriptionPage {
            events,
            resume_cursor,
            caught_up,
        })
    }

    fn publish_memory(&self, request: PublishMemoryRequest) -> ServiceResult<MutationResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Correct)?;
        crate::authenticated::require_capability(&request.context, Capability::Observe)?;
        validate_identifier(&request.idempotency_key, "idempotency key", 1_024)?;
        validate_identifier(&request.memory_id, "memory ID", 1_024)?;
        validate_identifier(&request.search_text, "memory search text", 32_768)?;
        let value_bytes = serde_json::to_vec(&request.value).map_err(|_| {
            ServiceError::new(
                ErrorCode::InvalidArgument,
                "explicit memory value is not canonical JSON",
                false,
            )
        })?;
        if value_bytes.len() > 8 * 1024 * 1024 {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "explicit memory value exceeds the 8 MiB limit",
                false,
            ));
        }
        if request.context.request.clearance < Sensitivity::Private {
            return Err(ServiceError::new(
                ErrorCode::PermissionDenied,
                "explicit semantic memory requires private clearance",
                false,
            ));
        }

        let request_digest = publish_memory_digest(&request)?;
        let cache_key =
            scoped_idempotency_key(&request.context, "publish_memory", &request.idempotency_key)?;
        let mut replay_cache = self.mutation_replays.write().map_err(|_| lock_error())?;
        if let Some(cached) = replay_cache.get(&cache_key) {
            return replay_mutation(cached, &request_digest);
        }
        let database = self.read()?;
        let snapshot = database.snapshot().map_err(map_reference_error)?;
        let record = LogicalRecord {
            id: request.memory_id,
            kind: RecordKind::SemanticObject,
            access: to_access(trusted_explicit_memory_policy(&request.context)),
            valid_time: ValidTime::default(),
            lifecycle: Lifecycle::Active,
            links: SemanticLinks::default(),
            value: request.value,
            search_text: Some(request.search_text),
            vector: None,
            attributes: BTreeMap::from([(
                "contextdb.explicit_memory.schema_version".to_owned(),
                serde_json::json!(1),
            )]),
        };
        let receipt = database
            .commit(SemanticTransaction {
                base_seq: snapshot.commit_seq,
                idempotency_key: cache_key.clone(),
                mutations: vec![Mutation::Put {
                    record,
                    expected_revision: Some(0),
                }],
            })
            .map_err(map_reference_error)?;
        let mut response = mutation_response(receipt);
        response.request_digest.clone_from(&request_digest);
        replay_cache.insert(
            cache_key,
            MutationReplay {
                request_digest,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    fn correct(&self, request: CorrectRequest) -> ServiceResult<MutationResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Correct)?;
        validate_identifier(&request.idempotency_key, "idempotency key", 1_024)?;
        validate_identifier(&request.target_id, "correction target", 1_024)?;
        validate_memory_document_metadata(&request.replacement)?;
        let request_digest = correction_digest(&request)?;
        let cache_key =
            scoped_idempotency_key(&request.context, "correct", &request.idempotency_key)?;
        let mut replay_cache = self.mutation_replays.write().map_err(|_| lock_error())?;
        if let Some(cached) = replay_cache.get(&cache_key) {
            return replay_mutation(cached, &request_digest);
        }
        let database = self.read()?;
        let snapshot = database.snapshot().map_err(map_reference_error)?;
        let principal = to_principal(&request.context.request);
        let target = database
            .get(&request.target_id, &snapshot, &principal)
            .map_err(map_reference_error)?;
        let replacement_access = to_access(request.replacement.access.clone());
        if target.revision.record.access != replacement_access {
            return Err(ServiceError::new(
                ErrorCode::PermissionDenied,
                "correction policy must exactly preserve the target policy envelope",
                false,
            ));
        }
        if !request
            .replacement
            .links
            .supersedes
            .contains(&request.target_id)
        {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "correction successor must explicitly supersede its target",
                false,
            ));
        }
        let receipt = database
            .commit(SemanticTransaction {
                base_seq: snapshot.commit_seq,
                idempotency_key: cache_key.clone(),
                mutations: vec![Mutation::Correct {
                    target: request.target_id,
                    replacement: to_logical_record(request.replacement),
                }],
            })
            .map_err(map_reference_error)?;
        let response = mutation_response(receipt);
        replay_cache.insert(
            cache_key,
            MutationReplay {
                request_digest,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    fn suppress(&self, request: HighLevelControlRequest) -> ServiceResult<MutationResponse> {
        crate::high_level::authorize_control_envelope(&request, Capability::Correct)?;
        let parameters = crate::high_level::parse_suppress_parameters(&request.parameters)?;
        self.apply_semantic_control(request, SemanticControlIntent::Suppress(parameters))
    }

    fn change_audience(&self, request: HighLevelControlRequest) -> ServiceResult<MutationResponse> {
        crate::high_level::authorize_control_envelope(&request, Capability::Correct)?;
        let parameters = crate::high_level::parse_change_audience_parameters(&request.parameters)?;
        self.apply_semantic_control(request, SemanticControlIntent::ChangeAudience(parameters))
    }

    fn publish_to_shared_memory(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        crate::high_level::authorize_control_envelope(&request, Capability::Correct)?;
        let parameters = crate::high_level::parse_publish_shared_parameters(&request.parameters)?;
        self.apply_semantic_control(
            request,
            SemanticControlIntent::PublishToSharedMemory(parameters),
        )
    }

    fn revoke_shared_memory(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        crate::high_level::authorize_control_envelope(&request, Capability::Correct)?;
        let parameters = crate::high_level::parse_revoke_shared_parameters(&request.parameters)?;
        self.apply_semantic_control(
            request,
            SemanticControlIntent::RevokeSharedMemory(parameters),
        )
    }

    fn forget(&self, request: ForgetRequest) -> ServiceResult<MutationResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Forget)?;
        if request.mode == ForgetMode::HardDelete {
            crate::authenticated::require_capability(&request.context, Capability::HardDelete)?;
        }
        validate_identifier(&request.idempotency_key, "idempotency key", 1_024)?;
        validate_identifier(&request.target_id, "forget target", 1_024)?;
        if request.mode == ForgetMode::HardDelete {
            validate_identifier(&request.reason, "deletion reason", 1_024)?;
        }
        let request_digest = forget_digest(&request)?;
        let operation = match request.mode {
            ForgetMode::Retract => "retract",
            ForgetMode::HardDelete => "hard_delete",
        };
        let cache_key =
            scoped_idempotency_key(&request.context, operation, &request.idempotency_key)?;
        let mut replay_cache = self.mutation_replays.write().map_err(|_| lock_error())?;
        if let Some(cached) = replay_cache.get(&cache_key) {
            return replay_mutation(cached, &request_digest);
        }
        let database = self.read()?;
        let snapshot = database.snapshot().map_err(map_reference_error)?;
        let principal = to_principal(&request.context.request);
        database
            .get(&request.target_id, &snapshot, &principal)
            .map_err(map_reference_error)?;
        let mutation = match request.mode {
            ForgetMode::Retract => Mutation::Retract {
                target: request.target_id,
            },
            ForgetMode::HardDelete => Mutation::Delete {
                target: request.target_id,
                requested_by: request.context.actor_id,
                reason: request.reason,
            },
        };
        let receipt = database
            .commit(SemanticTransaction {
                base_seq: snapshot.commit_seq,
                idempotency_key: cache_key.clone(),
                mutations: vec![mutation],
            })
            .map_err(map_reference_error)?;
        let response = mutation_response(receipt);
        replay_cache.insert(
            cache_key,
            MutationReplay {
                request_digest,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    fn get_node(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        crate::authenticated::require_capability(&request.context, Capability::ReadMemory)?;
        self.get_typed_record(request, MemoryRecordKind::Node)
    }

    fn get_memory(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        crate::authenticated::require_capability(&request.context, Capability::ReadMemory)?;
        self.get_typed_record(request, MemoryRecordKind::SemanticObject)
    }

    fn traverse(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Traverse)?;
        if request.start_ids.is_empty()
            || request.start_ids.len() > 1_000
            || request.max_hops == 0
            || request.max_hops > 32
            || request.max_nodes == 0
            || request.max_nodes > 10_000
        {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "traversal roots and budgets are outside the v1 bounds",
                false,
            ));
        }
        for value in &request.start_ids {
            validate_identifier(value, "traversal root", 1_024)?;
        }
        validate_set(&request.predicate_ids, "traversal predicate")?;
        let database = self.read()?;
        let snapshot = select_snapshot(
            &database,
            request.at_commit,
            &request.context.request.workspace_id,
        )?;
        let principal = to_principal(&request.context.request);
        let result = database
            .traverse(
                &request.start_ids,
                match request.direction {
                    TraverseDirection::Outgoing => Direction::Outgoing,
                    TraverseDirection::Incoming => Direction::Incoming,
                    TraverseDirection::Both => Direction::Both,
                },
                &request.predicate_ids,
                request.max_hops,
                usize::try_from(request.max_nodes).map_err(|_| {
                    ServiceError::new(
                        ErrorCode::ResourceExhausted,
                        "traversal node budget exceeds this platform",
                        false,
                    )
                })?,
                &snapshot,
                &principal,
            )
            .map_err(map_reference_error)?;
        Ok(TraverseResponse {
            node_ids: result.value,
            snapshot_seq: result.trace.snapshot_seq,
            authorized_candidates: u64::try_from(result.trace.authorized_candidates)
                .unwrap_or(u64::MAX),
            watermarks: map_watermarks(result.trace.watermarks),
        })
    }

    fn get_timeline(&self, request: GetTimelineRequest) -> ServiceResult<TimelineResponse> {
        request.context.validate_authentication()?;
        validate_identifier(&request.record_id, "timeline record", 1_024)?;
        if request.max_revisions == 0 || request.max_revisions > 1_000 {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "timeline revision budget must be between 1 and 1000",
                false,
            ));
        }
        let database = self.read()?;
        let snapshot = select_snapshot(
            &database,
            request.at_commit,
            &request.context.request.workspace_id,
        )?;
        let principal = to_principal(&request.context.request);
        let metadata = database
            .authorized_record_metadata(&request.record_id, &snapshot, &principal)
            .map_err(map_private_record_error)?;
        let actual_kind = map_record_kind(metadata.kind);
        if actual_kind != request.expected_kind {
            return Err(private_record_denied());
        }
        require_record_capability_private(&request.context, actual_kind)?;
        let mut history = database
            .history_typed(&request.record_id, metadata.kind, &snapshot, &principal)
            .map_err(map_private_record_error)?;
        history.truncate(usize::try_from(request.max_revisions).unwrap_or(usize::MAX));
        let watermarks = database
            .watermarks_for_workspace(&snapshot, &request.context.request.workspace_id)
            .map_err(map_reference_error)?;
        let snapshot_seq = watermarks.journal;
        Ok(TimelineResponse {
            revisions: history.into_iter().map(map_memory_record).collect(),
            snapshot_seq,
            watermarks: map_watermarks(watermarks),
        })
    }

    fn get_evidence(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        crate::authenticated::require_capability(&request.context, Capability::ReadEvidence)?;
        crate::authenticated::require_capability(&request.context, Capability::RawEvidence)?;
        self.get_typed_record(request, MemoryRecordKind::Evidence)
    }

    fn get_conflict(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        crate::authenticated::require_capability(&request.context, Capability::ReadConflict)?;
        self.get_typed_record(request, MemoryRecordKind::Conflict)
    }

    fn get_status(&self, request: GetStatusRequest) -> ServiceResult<crate::StatusResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Admin)?;
        let database = self.read()?;
        let snapshot = database.snapshot().map_err(map_reference_error)?;
        let watermarks = database.watermarks().map_err(map_reference_error)?;
        Ok(crate::StatusResponse {
            schema_version: crate::SERVICE_SCHEMA_VERSION,
            profile: "reference-in-memory".to_owned(),
            commit_seq: snapshot.commit_seq,
            watermarks: map_watermarks(watermarks),
            capability_manifest: crate::reference_capability_manifest_v1(),
        })
    }

    fn create_backup(&self, request: CreateBackupRequest) -> ServiceResult<BackupResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Admin)?;
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "reference backup requires host-global authority unavailable to a workspace request",
            false,
        )
        .with_context(
            Vec::new(),
            Some("authority:host-global".to_owned()),
            Some(
                "use a deployment backup boundary with explicit host-global authorization"
                    .to_owned(),
            ),
            None,
        ))
    }

    fn restore_backup(
        &self,
        request: RestoreBackupRequest,
    ) -> ServiceResult<RestoreBackupResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Admin)?;
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "workspace requests cannot replace state from a database-global backup",
            false,
        )
        .with_context(
            Vec::new(),
            Some("authority:host-global".to_owned()),
            Some("restore into a new isolated service through the local host boundary".to_owned()),
            None,
        ))
    }

    fn migrate_format(
        &self,
        request: MigrateFormatRequest,
    ) -> ServiceResult<crate::StatusResponse> {
        crate::authenticated::require_capability(&request.context, Capability::Admin)?;
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "the in-memory reference engine has no physical format migration executor",
            false,
        )
        .with_context(
            Vec::new(),
            None,
            Some("run migration through a durable storage backend".to_owned()),
            None,
        ))
    }
}

impl ReferenceService {
    fn get_typed_record(
        &self,
        request: GetMemoryRequest,
        expected: MemoryRecordKind,
    ) -> ServiceResult<MemoryRecord> {
        validate_identifier(&request.record_id, "memory record", 1_024)?;
        let database = self.read()?;
        let snapshot = select_snapshot(
            &database,
            request.at_commit,
            &request.context.request.workspace_id,
        )?;
        let principal = to_principal(&request.context.request);
        let record = database
            .get_typed(
                &request.record_id,
                to_record_kind(expected),
                &snapshot,
                &principal,
            )
            .map_err(map_private_record_error)?;
        Ok(map_memory_record(record))
    }
}

fn validate_observe_request(request: &ObserveRequest) -> ServiceResult<()> {
    validate_context(&request.context)?;
    validate_identifier(&request.idempotency_key, "idempotency key", 1_024)?;
    validate_identifier(&request.observation_id, "observation ID", 1_024)?;
    validate_access(&request.access)?;
    if request.access != trusted_legacy_observe_policy(&request.context) {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "observation policy does not match the trusted legacy policy template",
            false,
        )
        .with_context(
            Vec::new(),
            Some("trusted_legacy_observe_policy".to_owned()),
            Some(
                "use the authenticated subject, workspace, scopes, and current purpose".to_owned(),
            ),
            None,
        ));
    }
    Ok(())
}

fn trusted_legacy_observe_policy(context: &RequestContext) -> AccessPolicy {
    AccessPolicy {
        workspace_id: context.workspace_id.clone(),
        scopes: context.scopes.clone(),
        owners: BTreeSet::from([context.subject_id.clone()]),
        audience: BTreeSet::from([context.subject_id.clone()]),
        audience_purpose_grants: BTreeMap::new(),
        purposes: BTreeSet::from([context.purpose.clone()]),
        // Legacy Observe has no authenticated classification authority. A
        // fixed private template avoids caller-controlled downgrades while
        // preserving the established same-subject legacy profile.
        sensitivity: Sensitivity::Private,
        consent: Consent::Granted,
        retrievable: true,
    }
}

fn trusted_explicit_memory_policy(context: &AuthenticatedRequestContext) -> AccessPolicy {
    trusted_legacy_observe_policy(&context.request)
}

fn validate_manifest(manifest: &SourceRevisionManifest) -> ServiceResult<()> {
    validate_identifier(&manifest.source_id, "source ID", 1_024)?;
    validate_identifier(&manifest.revision_id, "source revision", 1_024)?;
    validate_identifier(&manifest.snapshot_id, "source snapshot", 1_024)?;
    if manifest.expected_items > 10_000 {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "source snapshot exceeds the 10000-item reference limit",
            false,
        ));
    }
    validate_digest(&manifest.ordered_items_digest)?;
    if manifest.compression != Compression::Identity {
        return Err(ServiceError::new(
            ErrorCode::Unsupported,
            "the structured v1 reference stream does not execute gzip or zstd decompression",
            false,
        )
        .with_context(
            Vec::new(),
            Some("compression_not_negotiated".to_owned()),
            Some("decompress at a bounded trusted adapter and declare identity".to_owned()),
            None,
        ));
    }
    if manifest.attributes.len() > 4_096 {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "source manifest attribute limit exceeded",
            false,
        ));
    }
    for (key, value) in &manifest.attributes {
        validate_identifier(key, "manifest attribute key", 1_024)?;
        validate_identifier(value, "manifest attribute value", 4_096)?;
    }
    Ok(())
}

fn validate_stream_observation(
    context: &AuthenticatedRequestContext,
    observation: &StreamObservation,
) -> ServiceResult<()> {
    validate_observe_request(&stream_observe_request(context, observation.clone()))
}

fn stream_observe_request(
    context: &AuthenticatedRequestContext,
    observation: StreamObservation,
) -> ObserveRequest {
    ObserveRequest {
        context: context.request.clone(),
        idempotency_key: observation.idempotency_key,
        observation_id: observation.observation_id,
        metadata: observation.metadata,
        content: observation.content,
        access: observation.access,
    }
}

fn validate_snapshot_complete(
    manifest: &SourceRevisionManifest,
    observations: &[StreamObservation],
    marker: &SnapshotComplete,
) -> ServiceResult<()> {
    validate_identifier(&marker.snapshot_id, "source snapshot", 1_024)?;
    validate_digest(&marker.ordered_items_digest)?;
    let item_count = u64::try_from(observations.len()).map_err(|_| {
        ServiceError::new(
            ErrorCode::ResourceExhausted,
            "source snapshot item count exceeds this platform",
            false,
        )
    })?;
    let computed = ordered_items_digest(observations)?;
    if marker.snapshot_id != manifest.snapshot_id
        || marker.item_count != manifest.expected_items
        || marker.item_count != item_count
        || marker.ordered_items_digest != manifest.ordered_items_digest
        || marker.ordered_items_digest != computed
    {
        return Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "snapshot completion does not match the declared source revision manifest",
            false,
        ));
    }
    Ok(())
}

fn encode_ingest_cursor(
    key: &[u8; 32],
    context: &AuthenticatedRequestContext,
    stream_id: &str,
    manifest_digest: &str,
    next_position: u64,
) -> ServiceResult<String> {
    continuation::encode_value(
        key,
        &IngestCursor {
            schema_version: crate::SERVICE_SCHEMA_VERSION,
            workspace_id: context.request.workspace_id.clone(),
            actor_id: context.actor_id.clone(),
            agent_id: context.agent_id.clone(),
            authorization_digest: context.authorization_binding_digest()?,
            stream_id: stream_id.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            next_position,
        },
    )
}

fn validate_ingest_cursor(
    key: &[u8; 32],
    token: Option<&str>,
    context: &AuthenticatedRequestContext,
    stream_id: &str,
    manifest_digest: &str,
    position: u64,
) -> ServiceResult<()> {
    let token = token.ok_or_else(|| {
        ServiceError::new(
            ErrorCode::InvalidContinuation,
            "a resumable stream frame requires the preceding acknowledgement cursor",
            false,
        )
    })?;
    let cursor: IngestCursor = continuation::decode_value(key, token)?;
    if cursor.schema_version != crate::SERVICE_SCHEMA_VERSION
        || cursor.workspace_id != context.request.workspace_id
        || cursor.actor_id != context.actor_id
        || cursor.agent_id != context.agent_id
        || cursor.authorization_digest != context.authorization_binding_digest()?
        || cursor.stream_id != stream_id
        || cursor.manifest_digest != manifest_digest
        || cursor.next_position != position
    {
        return Err(ServiceError::new(
            ErrorCode::InvalidContinuation,
            "stream cursor is forged, stale, or bound to another stream",
            false,
        ));
    }
    Ok(())
}

fn subscription_binding_digest(request: &SubscribeRequest) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct Binding<'a> {
        schema_version: u16,
        context_digest: String,
        filters: &'a BTreeSet<MemoryEventKind>,
    }

    continuation::digest_value(&Binding {
        schema_version: crate::SERVICE_SCHEMA_VERSION,
        context_digest: request.context.authorization_binding_digest()?,
        filters: &request.filters,
    })
}

fn authorized_events(
    database: &ContextDb,
    principal: &Principal,
    workspace_id: &str,
    journal: contextdb_reference::WorkspaceEventPage,
    cursor: &SubscriptionCursor,
    max_events: usize,
) -> ServiceResult<AuthorizedEventScan> {
    let mut events = Vec::new();
    let mut scanned_candidates = 0_usize;
    let mut checkpoint = (cursor.after_commit, cursor.after_ordinal);
    let mut authorized_commit = cursor.authorized_commit;
    let mut current_commit = cursor.after_commit;
    let mut has_more = journal.has_more;
    for candidate in journal.candidates {
        let position = (candidate.workspace_seq, candidate.ordinal);
        if position <= (cursor.after_commit, cursor.after_ordinal) {
            continue;
        }
        if scanned_candidates >= SUBSCRIPTION_SCAN_BUDGET {
            has_more = true;
            break;
        }
        scanned_candidates = scanned_candidates.saturating_add(1);
        checkpoint = position;
        if candidate.workspace_seq != current_commit {
            current_commit = candidate.workspace_seq;
            authorized_commit = None;
        }
        let snapshot = database
            .snapshot_at(candidate.commit_seq)
            .map_err(map_reference_error)?;
        match candidate.kind {
            WorkspaceEventCandidateKind::ObservationAccepted { observation_id } => {
                match database.authorize_observation(&observation_id, &snapshot, principal) {
                    Ok(_) => events.push(memory_event(
                        workspace_id,
                        &candidate.record_digest,
                        candidate.workspace_seq,
                        candidate.ordinal,
                        MemoryEventKind::ObservationAccepted,
                        vec![observation_id],
                        BTreeMap::new(),
                    )?),
                    Err(ReferenceError::Unauthorized | ReferenceError::NotFound { .. }) => {}
                    Err(error) => return Err(map_reference_error(error)),
                }
            }
            WorkspaceEventCandidateKind::SemanticRecordChanged { record_id } => {
                match database.authorized_record_metadata(&record_id, &snapshot, principal) {
                    Ok(metadata) => {
                        authorized_commit = Some(candidate.workspace_seq);
                        let kind = match metadata.kind {
                            RecordKind::Node => MemoryEventKind::NodeChanged,
                            RecordKind::Claim => MemoryEventKind::ClaimChanged,
                            RecordKind::Conflict => MemoryEventKind::ConflictResolved,
                            RecordKind::RuntimeState => database
                                .get_typed(
                                    &record_id,
                                    RecordKind::RuntimeState,
                                    &snapshot,
                                    principal,
                                )
                                .map_err(map_private_record_error)
                                .map(|value| {
                                    if value
                                        .content
                                        .attributes
                                        .get("contextdb.open_loop_trigger")
                                        .and_then(serde_json::Value::as_bool)
                                        == Some(true)
                                    {
                                        MemoryEventKind::OpenLoopTriggered
                                    } else {
                                        MemoryEventKind::RecordChanged
                                    }
                                })?,
                            _ => MemoryEventKind::RecordChanged,
                        };
                        events.push(memory_event(
                            workspace_id,
                            &candidate.record_digest,
                            candidate.workspace_seq,
                            candidate.ordinal,
                            kind,
                            vec![record_id],
                            BTreeMap::from([(
                                "record_kind".to_owned(),
                                record_kind_name(metadata.kind).to_owned(),
                            )]),
                        )?);
                    }
                    Err(ReferenceError::Unauthorized | ReferenceError::NotFound { .. }) => {}
                    Err(error) => return Err(map_reference_error(error)),
                }
            }
            WorkspaceEventCandidateKind::SemanticWatermark => {
                if authorized_commit == Some(candidate.workspace_seq) {
                    events.push(memory_event(
                        workspace_id,
                        &candidate.record_digest,
                        candidate.workspace_seq,
                        candidate.ordinal,
                        MemoryEventKind::IndexWatermarkAdvanced,
                        vec!["index:lexical".to_owned(), "index:graph".to_owned()],
                        BTreeMap::from([(
                            "watermark".to_owned(),
                            candidate.workspace_seq.to_string(),
                        )]),
                    )?);
                }
                authorized_commit = None;
            }
        }
        if events.len() >= max_events {
            has_more = true;
            break;
        }
    }
    events.sort_by(|left, right| event_position(left).cmp(&event_position(right)));
    Ok(AuthorizedEventScan {
        events,
        checkpoint,
        authorized_commit,
        has_more,
    })
}

fn retain_source_invalidation(
    registry: &mut StreamRegistry,
    workspace_id: &str,
    source_id: &str,
    previous: &SourceHead,
    current: &SourceHead,
    workspace_seq: u64,
) -> ServiceResult<()> {
    let journal_digest = continuation::digest_value(&(
        "source_invalidation",
        workspace_id,
        source_id,
        &previous.stream_id,
        &previous.revision_id,
        &current.stream_id,
        &current.revision_id,
    ))?;
    let mut bindings = BTreeSet::from([current.authorization_digest.clone()]);
    bindings.insert(previous.authorization_digest.clone());
    for authorization_digest in bindings {
        let ordinal = registry
            .next_service_ordinal
            .entry((authorization_digest.clone(), workspace_seq))
            .or_insert(SERVICE_EVENT_ORDINAL_BASE);
        let event_ordinal = *ordinal;
        *ordinal = ordinal.checked_add(1).ok_or_else(|| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "service event ordinal is exhausted",
                false,
            )
        })?;
        let event = memory_event(
            workspace_id,
            &journal_digest,
            workspace_seq,
            event_ordinal,
            MemoryEventKind::SourceInvalidated,
            vec![
                source_id.to_owned(),
                previous.revision_id.clone(),
                current.revision_id.clone(),
            ],
            BTreeMap::from([
                ("previous_stream_id".to_owned(), previous.stream_id.clone()),
                ("current_stream_id".to_owned(), current.stream_id.clone()),
            ]),
        )?;
        let retained = registry
            .service_events
            .entry(authorization_digest.clone())
            .or_default();
        retained.push_back(event);
        while retained.len() > RETAINED_SERVICE_EVENTS {
            let Some(dropped) = retained.pop_front() else {
                break;
            };
            let position = (dropped.commit_seq, dropped.ordinal, dropped.event_id);
            let dropped_before = registry
                .dropped_before
                .entry(authorization_digest.clone())
                .or_insert_with(|| position.clone());
            if (
                dropped_before.0,
                dropped_before.1,
                dropped_before.2.as_str(),
            ) < (position.0, position.1, position.2.as_str())
            {
                *dropped_before = position;
            }
        }
        let minimum_retained = retained
            .front()
            .map(|event| event.commit_seq)
            .unwrap_or(workspace_seq);
        registry
            .next_service_ordinal
            .retain(|(binding, commit), _| {
                binding != &authorization_digest || *commit >= minimum_retained
            });
    }
    Ok(())
}

fn memory_event(
    workspace_id: &str,
    journal_digest: &str,
    commit_seq: u64,
    ordinal: u32,
    kind: MemoryEventKind,
    object_refs: Vec<String>,
    attributes: BTreeMap<String, String>,
) -> ServiceResult<MemoryEvent> {
    #[derive(Serialize)]
    struct EventIdentity<'a> {
        schema_version: u16,
        workspace_id: &'a str,
        journal_digest: &'a str,
        commit_seq: u64,
        ordinal: u32,
        kind: MemoryEventKind,
        object_refs: &'a [String],
    }
    let identity = serde_json::to_vec(&EventIdentity {
        schema_version: crate::SERVICE_SCHEMA_VERSION,
        workspace_id,
        journal_digest,
        commit_seq,
        ordinal,
        kind,
        object_refs: &object_refs,
    })
    .map_err(|_| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "subscription event identity serialization failed",
            false,
        )
    })?;
    Ok(MemoryEvent {
        event_id: blake3::hash(&identity).to_hex().to_string(),
        commit_seq,
        ordinal,
        kind,
        object_refs,
        attributes,
    })
}

fn event_position(event: &MemoryEvent) -> (u64, u32, &str) {
    (event.commit_seq, event.ordinal, event.event_id.as_str())
}

fn scoped_idempotency_key(
    context: &AuthenticatedRequestContext,
    operation: &str,
    caller_key: &str,
) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct Scope<'a> {
        workspace_id: &'a str,
        actor_id: &'a str,
        operation: &'a str,
        caller_key: &'a str,
    }
    let digest = continuation::digest_value(&Scope {
        workspace_id: &context.request.workspace_id,
        actor_id: &context.actor_id,
        operation,
        caller_key,
    })?;
    Ok(format!("service-v1:{operation}:{digest}"))
}

fn semantic_control_digest(
    request: &HighLevelControlRequest,
    intent: &SemanticControlIntent,
) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct ControlInput<'a> {
        schema_version: u16,
        authorization_binding_digest: String,
        target_subject_id: &'a str,
        target_id: &'a str,
        intent: &'a SemanticControlIntent,
    }

    continuation::digest_value(&ControlInput {
        schema_version: crate::SERVICE_SCHEMA_VERSION,
        authorization_binding_digest: request.context.authorization_binding_digest()?,
        target_subject_id: &request.target_subject_id,
        target_id: &request.target_id,
        intent,
    })
}

fn apply_control_intent(
    request: &HighLevelControlRequest,
    intent: &SemanticControlIntent,
    record: &mut LogicalRecord,
) -> ServiceResult<()> {
    match intent {
        SemanticControlIntent::Suppress(_) => {
            record.lifecycle = Lifecycle::Suppressed;
        }
        SemanticControlIntent::ChangeAudience(parameters) => {
            validate_audience_revision(request, &record.access, parameters)?;
            record.access.audience.clone_from(&parameters.audiences);
            record
                .access
                .audience_purpose_grants
                .clone_from(&parameters.audience_purpose_grants);
            require_resulting_owner_access(request, &record.access)?;
        }
        SemanticControlIntent::PublishToSharedMemory(parameters) => {
            validate_shared_audience(request, &record.access, &parameters.shared_audience_id)?;
            if record.access.audience_purpose_grants.is_empty() {
                return Err(ServiceError::new(
                    ErrorCode::Unsupported,
                    "shared publication cannot losslessly revise a legacy wildcard purpose policy",
                    false,
                )
                .with_context(
                    Vec::new(),
                    Some("exact_audience_purpose_policy".to_owned()),
                    Some(
                        "first install an exact audience-purpose policy with ChangeAudience"
                            .to_owned(),
                    ),
                    None,
                ));
            }
            if parameters
                .purposes
                .iter()
                .any(|purpose| purpose != &request.context.request.purpose)
            {
                return Err(policy_widening_error());
            }
            let existing = record
                .access
                .audience_purpose_grants
                .entry(parameters.shared_audience_id.clone())
                .or_default();
            let changed = parameters
                .purposes
                .iter()
                .any(|purpose| !existing.contains(purpose));
            if !changed {
                return Err(no_policy_change_error());
            }
            existing.extend(parameters.purposes.iter().cloned());
            record
                .access
                .audience
                .insert(parameters.shared_audience_id.clone());
            require_resulting_owner_access(request, &record.access)?;
        }
        SemanticControlIntent::RevokeSharedMemory(parameters) => {
            if record
                .access
                .owners
                .contains(&parameters.shared_audience_id)
                || parameters.shared_audience_id == "@owner"
            {
                return Err(ServiceError::new(
                    ErrorCode::InvalidArgument,
                    "shared-memory revocation cannot remove target ownership",
                    false,
                ));
            }
            let audience_removed = record
                .access
                .audience
                .remove(&parameters.shared_audience_id);
            let grant_removed = record
                .access
                .audience_purpose_grants
                .remove(&parameters.shared_audience_id)
                .is_some();
            if !audience_removed && !grant_removed {
                return Err(no_policy_change_error());
            }
            require_resulting_owner_access(request, &record.access)?;
        }
    }
    Ok(())
}

fn validate_audience_revision(
    request: &HighLevelControlRequest,
    current: &AccessLabel,
    parameters: &crate::high_level::ChangeAudienceParametersV1,
) -> ServiceResult<()> {
    if parameters.audiences.contains("@owner") {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "@owner is a policy grant key, not an audience identity",
            false,
        ));
    }
    for key in parameters.audience_purpose_grants.keys() {
        if key != "@owner" && !parameters.audiences.contains(key) {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "audience-purpose grants must exactly name a proposed audience or @owner",
                false,
            ));
        }
    }
    if !parameters.audience_purpose_grants.is_empty()
        && parameters
            .audiences
            .iter()
            .any(|audience| !parameters.audience_purpose_grants.contains_key(audience))
    {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "every exact audience requires an explicit purpose grant",
            false,
        ));
    }
    let newly_added: BTreeSet<_> = parameters
        .audiences
        .difference(&current.audience)
        .cloned()
        .collect();
    if parameters.audience_purpose_grants.is_empty() && !newly_added.is_empty() {
        return Err(ServiceError::new(
            ErrorCode::Unsupported,
            "adding an audience requires exact purpose grants",
            false,
        ));
    }
    for (audience, purposes) in &parameters.audience_purpose_grants {
        for purpose in purposes {
            if policy_pair_allowed(current, audience, purpose) {
                continue;
            }
            let authenticated_audience =
                audience == "@owner" || request.context.request.audiences.contains(audience);
            if !authenticated_audience || purpose != &request.context.request.purpose {
                return Err(policy_widening_error());
            }
        }
    }
    Ok(())
}

fn validate_shared_audience(
    request: &HighLevelControlRequest,
    current: &AccessLabel,
    audience: &str,
) -> ServiceResult<()> {
    if audience == "@owner"
        || audience == "*"
        || current.owners.contains(audience)
        || !request.context.request.audiences.contains(audience)
    {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "shared audience is not an authenticated non-owner audience",
            false,
        )
        .with_context(
            Vec::new(),
            Some("shared_audience_binding".to_owned()),
            Some("use a resolved shared audience from the authenticated context".to_owned()),
            None,
        ));
    }
    Ok(())
}

fn policy_pair_allowed(current: &AccessLabel, audience: &str, purpose: &str) -> bool {
    if current.audience_purpose_grants.is_empty() {
        let audience_allowed = audience == "@owner"
            || current.owners.contains(audience)
            || current.audience.contains(audience);
        audience_allowed && (current.purposes.is_empty() || current.purposes.contains(purpose))
    } else {
        current
            .audience_purpose_grants
            .get(audience)
            .is_some_and(|purposes| purposes.contains(purpose))
    }
}

fn require_resulting_owner_access(
    request: &HighLevelControlRequest,
    access: &AccessLabel,
) -> ServiceResult<()> {
    if !to_principal(&request.context.request).allows(access) {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "policy revision would remove the authenticated owner's current access",
            false,
        )
        .with_context(
            Vec::new(),
            Some("owner_access_preservation".to_owned()),
            Some("retain an owner or @owner grant for the current purpose".to_owned()),
            None,
        ));
    }
    Ok(())
}

fn policy_widening_error() -> ServiceError {
    ServiceError::new(
        ErrorCode::PermissionDenied,
        "policy revision exceeds the authenticated audience or purpose grant",
        false,
    )
    .with_context(
        Vec::new(),
        Some("semantic_control_policy_widening".to_owned()),
        Some("request only an authenticated audience and the current purpose".to_owned()),
        None,
    )
}

fn no_policy_change_error() -> ServiceError {
    ServiceError::new(
        ErrorCode::InvalidArgument,
        "semantic control would not change the target policy",
        false,
    )
}

fn publish_memory_digest(request: &PublishMemoryRequest) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct MutationInput<'a> {
        schema_version: u16,
        authorization_binding_digest: String,
        memory_id: &'a str,
        value: &'a serde_json::Value,
        search_text: &'a str,
    }

    continuation::digest_value(&MutationInput {
        schema_version: crate::SERVICE_SCHEMA_VERSION,
        authorization_binding_digest: request.context.authorization_binding_digest()?,
        memory_id: &request.memory_id,
        value: &request.value,
        search_text: &request.search_text,
    })
}

fn correction_digest(request: &CorrectRequest) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct MutationInput<'a> {
        schema_version: u16,
        target_id: &'a str,
        replacement: &'a MemoryDocument,
    }

    continuation::digest_value(&MutationInput {
        schema_version: crate::SERVICE_SCHEMA_VERSION,
        target_id: &request.target_id,
        replacement: &request.replacement,
    })
}

fn forget_digest(request: &ForgetRequest) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct MutationInput<'a> {
        schema_version: u16,
        target_id: &'a str,
        mode: ForgetMode,
        reason: &'a str,
    }

    continuation::digest_value(&MutationInput {
        schema_version: crate::SERVICE_SCHEMA_VERSION,
        target_id: &request.target_id,
        mode: request.mode,
        reason: &request.reason,
    })
}

fn replay_mutation(
    cached: &MutationReplay,
    request_digest: &str,
) -> ServiceResult<MutationResponse> {
    if cached.request_digest != request_digest {
        return Err(ServiceError::new(
            ErrorCode::IdempotencyConflict,
            "actor-scoped idempotency key was reused with different input",
            false,
        ));
    }
    let mut response = cached.response.clone();
    response.replayed = true;
    Ok(response)
}

fn mutation_response(receipt: contextdb_reference::CommitReceipt) -> MutationResponse {
    MutationResponse {
        commit_seq: receipt.commit_seq,
        replayed: receipt.replayed,
        request_digest: receipt.request_digest,
        watermarks: map_watermarks(receipt.watermarks),
    }
}

fn validate_memory_document_metadata(document: &MemoryDocument) -> ServiceResult<()> {
    validate_identifier(&document.id, "memory document ID", 1_024)?;
    validate_access(&document.access)?;
    if !(ValidTime {
        from: document.valid_time.from,
        to: document.valid_time.to,
    })
    .is_valid()
    {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "memory document has an invalid domain-time interval",
            false,
        ));
    }
    for value in document
        .links
        .supersedes
        .iter()
        .chain(document.links.evidence.iter())
        .chain(document.links.conflict_members.iter())
    {
        validate_identifier(value, "memory link", 1_024)?;
    }
    for value in [
        &document.links.subject,
        &document.links.source,
        &document.links.target,
        &document.links.predicate,
        &document.links.conflict_set,
    ]
    .into_iter()
    .flatten()
    {
        validate_identifier(value, "memory link", 1_024)?;
    }
    if document.vector.as_ref().is_some_and(|vector| {
        vector.len() > 65_536 || vector.iter().any(|value| !value.is_finite())
    }) {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "memory vector is non-finite or exceeds the dimension limit",
            false,
        ));
    }
    Ok(())
}

fn require_record_capability_private(
    context: &AuthenticatedRequestContext,
    kind: MemoryRecordKind,
) -> ServiceResult<()> {
    let grants = &context.capability_grants;
    let allowed = match kind {
        MemoryRecordKind::Evidence => {
            grants.contains(&Capability::ReadEvidence) && grants.contains(&Capability::RawEvidence)
        }
        MemoryRecordKind::Conflict => grants.contains(&Capability::ReadConflict),
        _ => grants.contains(&Capability::ReadMemory),
    };
    if !allowed {
        return Err(private_record_denied());
    }
    Ok(())
}

fn select_snapshot(
    database: &ContextDb,
    at_commit: Option<u64>,
    workspace_id: &str,
) -> ServiceResult<contextdb_reference::Snapshot> {
    match at_commit {
        Some(commit) => database
            .snapshot_for_workspace(workspace_id, commit)
            .map_err(map_reference_error),
        None => database.snapshot().map_err(map_reference_error),
    }
}

fn to_logical_record(document: MemoryDocument) -> LogicalRecord {
    LogicalRecord {
        id: document.id,
        kind: to_record_kind(document.kind),
        access: to_access(document.access),
        valid_time: ValidTime {
            from: document.valid_time.from,
            to: document.valid_time.to,
        },
        lifecycle: to_lifecycle(document.lifecycle),
        links: SemanticLinks {
            subject: document.links.subject,
            source: document.links.source,
            target: document.links.target,
            predicate: document.links.predicate,
            conflict_set: document.links.conflict_set,
            supersedes: document.links.supersedes,
            evidence: document.links.evidence,
            conflict_members: document.links.conflict_members,
            single_valued: document.links.single_valued,
        },
        value: document.value,
        search_text: document.search_text,
        vector: document.vector,
        attributes: document.attributes,
    }
}

fn map_memory_record(record: MaterializedRecord) -> MemoryRecord {
    let metadata = record.revision.record;
    MemoryRecord {
        document: MemoryDocument {
            id: record.revision.id,
            kind: map_record_kind(metadata.kind),
            access: map_access(metadata.access),
            valid_time: DomainTimeRange {
                from: metadata.valid_time.from,
                to: metadata.valid_time.to,
            },
            lifecycle: map_lifecycle(metadata.lifecycle),
            links: MemoryLinks {
                subject: metadata.links.subject,
                source: metadata.links.source,
                target: metadata.links.target,
                predicate: metadata.links.predicate,
                conflict_set: metadata.links.conflict_set,
                supersedes: metadata.links.supersedes,
                evidence: metadata.links.evidence,
                conflict_members: metadata.links.conflict_members,
                single_valued: metadata.links.single_valued,
            },
            value: record.content.value,
            search_text: record.content.search_text,
            vector: record.content.vector,
            attributes: record.content.attributes,
        },
        revision: record.revision.revision,
        transaction_from: record.revision.transaction_from,
        transaction_to: record.revision.transaction_to,
    }
}

const fn map_record_kind(kind: RecordKind) -> MemoryRecordKind {
    match kind {
        RecordKind::Node => MemoryRecordKind::Node,
        RecordKind::Claim => MemoryRecordKind::Claim,
        RecordKind::Edge => MemoryRecordKind::Edge,
        RecordKind::Conflict => MemoryRecordKind::Conflict,
        RecordKind::Evidence => MemoryRecordKind::Evidence,
        RecordKind::Candidate => MemoryRecordKind::Candidate,
        RecordKind::SemanticObject => MemoryRecordKind::SemanticObject,
        RecordKind::RuntimeState => MemoryRecordKind::RuntimeState,
        RecordKind::DomainExtension => MemoryRecordKind::DomainExtension,
    }
}

const fn to_record_kind(kind: MemoryRecordKind) -> RecordKind {
    match kind {
        MemoryRecordKind::Node => RecordKind::Node,
        MemoryRecordKind::Claim => RecordKind::Claim,
        MemoryRecordKind::Edge => RecordKind::Edge,
        MemoryRecordKind::Conflict => RecordKind::Conflict,
        MemoryRecordKind::Evidence => RecordKind::Evidence,
        MemoryRecordKind::Candidate => RecordKind::Candidate,
        MemoryRecordKind::SemanticObject => RecordKind::SemanticObject,
        MemoryRecordKind::RuntimeState => RecordKind::RuntimeState,
        MemoryRecordKind::DomainExtension => RecordKind::DomainExtension,
    }
}

const fn map_lifecycle(value: Lifecycle) -> MemoryLifecycle {
    match value {
        Lifecycle::Active => MemoryLifecycle::Active,
        Lifecycle::Superseded => MemoryLifecycle::Superseded,
        Lifecycle::Retracted => MemoryLifecycle::Retracted,
        Lifecycle::Suppressed => MemoryLifecycle::Suppressed,
    }
}

const fn to_lifecycle(value: MemoryLifecycle) -> Lifecycle {
    match value {
        MemoryLifecycle::Active => Lifecycle::Active,
        MemoryLifecycle::Superseded => Lifecycle::Superseded,
        MemoryLifecycle::Retracted => Lifecycle::Retracted,
        MemoryLifecycle::Suppressed => Lifecycle::Suppressed,
    }
}

fn map_access(access: AccessLabel) -> AccessPolicy {
    AccessPolicy {
        workspace_id: access.workspace,
        scopes: access.scopes,
        owners: access.owners,
        audience: access.audience,
        audience_purpose_grants: access.audience_purpose_grants,
        purposes: access.purposes,
        sensitivity: map_sensitivity(access.sensitivity),
        consent: match access.consent {
            contextdb_reference::Consent::Granted => Consent::Granted,
            contextdb_reference::Consent::Unknown => Consent::Unknown,
            contextdb_reference::Consent::Denied => Consent::Denied,
        },
        retrievable: access.retrievable,
    }
}

const fn map_sensitivity(value: ReferenceSensitivity) -> Sensitivity {
    match value {
        ReferenceSensitivity::Public => Sensitivity::Public,
        ReferenceSensitivity::Internal => Sensitivity::Internal,
        ReferenceSensitivity::Private => Sensitivity::Private,
        ReferenceSensitivity::Restricted => Sensitivity::Restricted,
    }
}

const fn record_kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Node => "node",
        RecordKind::Claim => "claim",
        RecordKind::Edge => "edge",
        RecordKind::Conflict => "conflict",
        RecordKind::Evidence => "evidence",
        RecordKind::Candidate => "candidate",
        RecordKind::SemanticObject => "semantic_object",
        RecordKind::RuntimeState => "runtime_state",
        RecordKind::DomainExtension => "domain_extension",
    }
}

fn validate_digest(value: &str) -> ServiceResult<()> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "digest must be canonical lowercase BLAKE3 hexadecimal",
            false,
        ));
    }
    Ok(())
}

fn lock_error() -> ServiceError {
    ServiceError::new(ErrorCode::Unavailable, "service lock was poisoned", true)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn validate_context(context: &RequestContext) -> ServiceResult<()> {
    crate::authenticated::validate_legacy_context(context)
}

fn validate_access(access: &AccessPolicy) -> ServiceResult<()> {
    validate_identifier(&access.workspace_id, "policy workspace", 1_024)?;
    validate_set(&access.scopes, "policy scope")?;
    validate_set(&access.owners, "policy owner")?;
    validate_set(&access.audience, "policy audience")?;
    validate_set(&access.purposes, "policy purpose")?;
    for (audience, purposes) in &access.audience_purpose_grants {
        validate_identifier(audience, "grant audience", 1_024)?;
        validate_set(purposes, "grant purpose")?;
    }
    if access.owners.is_empty() {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "observation policy requires an owner",
            false,
        ));
    }
    Ok(())
}

fn validate_set(values: &BTreeSet<String>, field: &'static str) -> ServiceResult<()> {
    if values.len() > 4_096 {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "request set exceeds the service limit",
            false,
        ));
    }
    for value in values {
        validate_identifier(value, field, 1_024)?;
    }
    Ok(())
}

fn validate_identifier(value: &str, _field: &'static str, max: usize) -> ServiceResult<()> {
    if value.trim().is_empty() || value.len() > max || value.contains('\0') {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "request contains an invalid bounded string",
            false,
        ));
    }
    Ok(())
}

fn require_admin(context: &RequestContext) -> ServiceResult<()> {
    validate_context(context)?;
    if context.purpose != "contextdb:admin" || context.clearance != Sensitivity::Restricted {
        return Err(ServiceError::new(
            ErrorCode::PermissionDenied,
            "administrative capability is required",
            false,
        ));
    }
    Ok(())
}

fn to_principal(context: &RequestContext) -> Principal {
    Principal {
        subject: context.subject_id.clone(),
        audiences: context.audiences.clone(),
        workspace: context.workspace_id.clone(),
        scopes: context.scopes.clone(),
        purpose: context.purpose.clone(),
        clearance: to_sensitivity(context.clearance),
    }
}

fn to_access(access: AccessPolicy) -> AccessLabel {
    AccessLabel {
        workspace: access.workspace_id,
        scopes: access.scopes,
        owners: access.owners,
        audience: access.audience,
        audience_purpose_grants: access.audience_purpose_grants,
        purposes: access.purposes,
        sensitivity: to_sensitivity(access.sensitivity),
        consent: match access.consent {
            Consent::Granted => contextdb_reference::Consent::Granted,
            Consent::Unknown => contextdb_reference::Consent::Unknown,
            Consent::Denied => contextdb_reference::Consent::Denied,
        },
        retrievable: access.retrievable,
    }
}

const fn to_sensitivity(value: Sensitivity) -> ReferenceSensitivity {
    match value {
        Sensitivity::Public => ReferenceSensitivity::Public,
        Sensitivity::Internal => ReferenceSensitivity::Internal,
        Sensitivity::Private => ReferenceSensitivity::Private,
        Sensitivity::Restricted => ReferenceSensitivity::Restricted,
    }
}

fn map_watermarks(value: contextdb_reference::Watermarks) -> Watermarks {
    Watermarks {
        journal: value.journal,
        semantic: value.semantic,
        lexical: value.lexical,
        vector: value.vector,
        graph: value.graph,
    }
}

fn trace_id(
    key: &[u8; 32],
    context: &RequestContext,
    snapshot_seq: u64,
    operation: &str,
    authorized_candidates: u64,
    selected_ids: &[String],
    watermarks: &Watermarks,
) -> ServiceResult<String> {
    #[derive(serde::Serialize)]
    struct TraceBinding<'a> {
        schema_version: u16,
        workspace_id: &'a str,
        subject_id: &'a str,
        audiences: &'a BTreeSet<String>,
        scopes: &'a BTreeSet<String>,
        purpose: &'a str,
        clearance: Sensitivity,
        snapshot_seq: u64,
        operation: &'a str,
        authorized_candidates: u64,
        selected_ids: &'a [String],
        watermarks: &'a Watermarks,
    }
    continuation::trace_id(
        key,
        &TraceBinding {
            schema_version: crate::SERVICE_SCHEMA_VERSION,
            workspace_id: &context.workspace_id,
            subject_id: &context.subject_id,
            audiences: &context.audiences,
            scopes: &context.scopes,
            purpose: &context.purpose,
            clearance: context.clearance,
            snapshot_seq,
            operation,
            authorized_candidates,
            selected_ids,
            watermarks,
        },
    )
}

fn map_reference_error(error: ReferenceError) -> ServiceError {
    match error {
        ReferenceError::Unauthorized => ServiceError::new(
            ErrorCode::PermissionDenied,
            "operation is not authorized",
            false,
        ),
        ReferenceError::NotFound { .. } | ReferenceError::SnapshotNotFound { .. } => {
            ServiceError::new(ErrorCode::NotFound, "requested object was not found", false)
        }
        ReferenceError::IdempotencyConflict { .. } => ServiceError::new(
            ErrorCode::IdempotencyConflict,
            "idempotency key was reused with different input",
            false,
        ),
        ReferenceError::LockPoisoned | ReferenceError::InjectedCrash(_) => {
            ServiceError::new(ErrorCode::Unavailable, "service is unavailable", true)
        }
        ReferenceError::ResourceExhausted => ServiceError::new(
            ErrorCode::ResourceExhausted,
            "tenant-scoped reference work budget was exhausted",
            true,
        ),
        ReferenceError::SnapshotConflict { .. }
        | ReferenceError::Invariant(_)
        | ReferenceError::CoreValidation(_) => ServiceError::new(
            ErrorCode::InvalidArgument,
            "request violates a canonical service invariant",
            false,
        ),
        ReferenceError::InvalidImport(_) | ReferenceError::Serialization(_) => ServiceError::new(
            ErrorCode::IntegrityFailure,
            "canonical archive or serialization integrity failed",
            false,
        ),
    }
}

fn private_record_denied() -> ServiceError {
    ServiceError::new(
        ErrorCode::PermissionDenied,
        "memory record is unavailable to this caller",
        false,
    )
}

fn map_private_record_error(error: ReferenceError) -> ServiceError {
    match error {
        ReferenceError::Unauthorized
        | ReferenceError::NotFound { .. }
        | ReferenceError::SnapshotNotFound { .. } => private_record_denied(),
        other => map_reference_error(other),
    }
}

#[cfg(test)]
mod retention_tests {
    #![allow(
        clippy::expect_used,
        reason = "retention tests use immediate failure semantics"
    )]

    use crate::{AuthenticationEvidence, Capability};

    use super::*;

    fn subscriber_context() -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: RequestContext {
                request_id: "request:retention".to_owned(),
                workspace_id: "workspace:retention".to_owned(),
                subject_id: "actor:retention".to_owned(),
                audiences: BTreeSet::from(["actor:retention".to_owned()]),
                scopes: BTreeSet::new(),
                purpose: "retention-test".to_owned(),
                clearance: Sensitivity::Private,
            },
            actor_id: "actor:retention".to_owned(),
            agent_id: "agent:retention".to_owned(),
            session_id: Some("session:retention".to_owned()),
            capability_grants: BTreeSet::from([Capability::Subscribe]),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: "channel:retention".to_owned(),
                peer_identity: "actor:retention".to_owned(),
                binding_digest: "31".repeat(32),
            },
        }
    }

    #[test]
    fn service_event_retention_is_bounded_and_expires_the_evicted_cursor() {
        let service = ReferenceService::new("retention-test", [0x61; 32]).expect("service");
        let context = subscriber_context();
        let authorization_digest = context
            .authorization_binding_digest()
            .expect("authorization digest");
        let mut request = SubscribeRequest {
            context,
            filters: BTreeSet::from([MemoryEventKind::SourceInvalidated]),
            resume_cursor: None,
            max_events: 1,
        };
        let binding_digest = subscription_binding_digest(&request).expect("subscription binding");
        let mut registry = StreamRegistry::default();
        let mut previous = SourceHead {
            stream_id: "stream:before-retention-window".to_owned(),
            revision_id: "revision:before-retention-window".to_owned(),
            authorization_digest: authorization_digest.clone(),
        };
        let mut first_position = None;

        for index in 0..=RETAINED_SERVICE_EVENTS {
            let current = SourceHead {
                stream_id: format!("stream:retention:{index}"),
                revision_id: format!("revision:retention:{index}"),
                authorization_digest: authorization_digest.clone(),
            };
            retain_source_invalidation(
                &mut registry,
                "workspace:retention",
                "source:retention",
                &previous,
                &current,
                0,
            )
            .expect("retained invalidation");
            if first_position.is_none() {
                let event = registry
                    .service_events
                    .get(&authorization_digest)
                    .and_then(VecDeque::back)
                    .expect("first event");
                first_position = Some((event.commit_seq, event.ordinal, event.event_id.clone()));
            }
            previous = current;
        }

        assert_eq!(
            registry
                .service_events
                .get(&authorization_digest)
                .map(VecDeque::len),
            Some(RETAINED_SERVICE_EVENTS)
        );
        let first_position = first_position.expect("first position");
        assert_eq!(
            registry.dropped_before.get(&authorization_digest),
            Some(&first_position)
        );
        *service.streams.write().expect("stream registry") = registry;
        request.resume_cursor = Some(
            continuation::encode_value(
                &service.continuation_key,
                &SubscriptionCursor {
                    schema_version: crate::SERVICE_SCHEMA_VERSION,
                    sequence_domain: SUBSCRIPTION_CURSOR_DOMAIN.to_owned(),
                    binding_digest,
                    after_commit: first_position.0,
                    after_ordinal: first_position.1,
                    after_event_id: first_position.2,
                    authorized_commit: None,
                },
            )
            .expect("expired cursor"),
        );

        let error = service
            .subscribe(request)
            .expect_err("evicted cursor must expire");
        assert_eq!(error.code, ErrorCode::ContinuationExpired);
        assert_eq!(
            error.violated_policy.as_deref(),
            Some("subscription_retention")
        );
    }

    #[test]
    fn sparse_subscription_scan_stops_at_budget_and_resumes_after_checkpoint() {
        let database = ContextDb::new("sparse-subscription-budget").expect("database");
        let context = subscriber_context();
        let principal = to_principal(&context.request);
        let first_cursor = SubscriptionCursor {
            schema_version: crate::SERVICE_SCHEMA_VERSION,
            sequence_domain: SUBSCRIPTION_CURSOR_DOMAIN.to_owned(),
            binding_digest: "binding".to_owned(),
            after_commit: 0,
            after_ordinal: 0,
            after_event_id: String::new(),
            authorized_commit: None,
        };
        let candidates = (0..SUBSCRIPTION_SCAN_BUDGET)
            .map(|index| contextdb_reference::WorkspaceEventCandidate {
                workspace_seq: 1,
                ordinal: u32::try_from(index).expect("ordinal"),
                commit_seq: 0,
                record_digest: "content-free-test-journal-digest".to_owned(),
                kind: WorkspaceEventCandidateKind::SemanticRecordChanged {
                    record_id: format!("denied:{index:05}"),
                },
            })
            .collect();
        let first = authorized_events(
            &database,
            &principal,
            &context.request.workspace_id,
            contextdb_reference::WorkspaceEventPage {
                candidates,
                scanned_through: (
                    1,
                    u32::try_from(SUBSCRIPTION_SCAN_BUDGET - 1).expect("ordinal"),
                ),
                has_more: true,
            },
            &first_cursor,
            1,
        )
        .expect("first bounded scan");
        assert!(first.events.is_empty());
        assert!(first.has_more);
        assert_eq!(
            first.checkpoint,
            (
                1,
                u32::try_from(SUBSCRIPTION_SCAN_BUDGET - 1).expect("ordinal")
            )
        );

        let resumed_cursor = SubscriptionCursor {
            after_commit: first.checkpoint.0,
            after_ordinal: first.checkpoint.1,
            ..first_cursor
        };
        let resumed = authorized_events(
            &database,
            &principal,
            &context.request.workspace_id,
            contextdb_reference::WorkspaceEventPage {
                candidates: vec![
                    contextdb_reference::WorkspaceEventCandidate {
                        workspace_seq: 1,
                        ordinal: u32::try_from(SUBSCRIPTION_SCAN_BUDGET).expect("ordinal"),
                        commit_seq: 0,
                        record_digest: "content-free-test-journal-digest".to_owned(),
                        kind: WorkspaceEventCandidateKind::SemanticRecordChanged {
                            record_id: "denied:04096".to_owned(),
                        },
                    },
                    contextdb_reference::WorkspaceEventCandidate {
                        workspace_seq: 1,
                        ordinal: u32::try_from(SUBSCRIPTION_SCAN_BUDGET + 1)
                            .expect("watermark ordinal"),
                        commit_seq: 0,
                        record_digest: "content-free-test-journal-digest".to_owned(),
                        kind: WorkspaceEventCandidateKind::SemanticWatermark,
                    },
                ],
                scanned_through: (
                    1,
                    u32::try_from(SUBSCRIPTION_SCAN_BUDGET + 1).expect("watermark ordinal"),
                ),
                has_more: false,
            },
            &resumed_cursor,
            1,
        )
        .expect("resumed bounded scan");
        assert!(resumed.events.is_empty());
        assert!(!resumed.has_more);
        assert_eq!(
            resumed.checkpoint,
            (
                1,
                u32::try_from(SUBSCRIPTION_SCAN_BUDGET + 1).expect("watermark ordinal")
            )
        );
    }
}
