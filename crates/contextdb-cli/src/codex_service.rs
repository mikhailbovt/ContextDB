//! Hybrid host used by the local Codex MCP adapter.
//!
//! New memory traffic uses the incremental native Fjall service. The existing
//! externally anchored production composition remains the lifecycle executor
//! while its checkpoint/bootstrap/handoff state is migrated into the reusable
//! runtime. This keeps the Codex integration functional without routing each
//! `remember` or `correct` through a complete logical-archive rewrite.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use contextdb_native_service::{NATIVE_BACKUP_FORMAT, NativeService};
use contextdb_service::{
    BackupResponse, Capability, CapabilityState, CognitiveMemoryService, CompileContextRequest,
    CompileContextResponse, CorrectRequest, CreateBackupRequest, ErrorCode, ExplainRecallRequest,
    ExportRequest, ExportResponse, ForgetRequest, GetMemoryRequest, GetStatusRequest,
    GetTimelineRequest, ImportRequest, ImportResponse, IngestAck, IngestFrame, MaintenanceRequest,
    MaintenanceResponse, MemoryRecord, MigrateFormatRequest, MutationResponse, ObserveRequest,
    ObserveResponse, ProposeMemoryRequest, ProposeMemoryResponse, PublishMemoryRequest,
    RecallCandidatesRequest, RecallCandidatesResponse, RecallRequest, RecallResponse, RecallTrace,
    RestoreBackupRequest, RestoreBackupResponse, RuntimeRequest, RuntimeResponse, ServiceError,
    ServiceResult, StatusResponse, SubscribeRequest, SubscriptionPage, TimelineResponse,
    TraverseRequest, TraverseResponse, VerifyRequest, VerifyResponse, authorize_capability,
    service_capability_manifest_v1,
};

use crate::production::ProductionService;
use crate::{CliResult, LoadedState, durable_checkpoint_error};

const HYBRID_PROFILE: &str = "codex-local-hybrid-v1";
pub(crate) const CODEX_BACKUP_FORMAT: &str = "contextdb.codex-composite-backup.v1";
pub(crate) const CODEX_BACKUP_RESTORE_POLICY: &str =
    "lifecycle-exact-match+native-pristine-target-only";
const CODEX_BACKUP_MAGIC: &[u8] = b"contextdb/codex-composite-backup/v1\0";
const CODEX_BACKUP_SCHEMA_VERSION: u16 = 1;
const CODEX_BACKUP_FOOTER_BYTES: usize = 32;
const MAX_LIFECYCLE_COMPONENT_BYTES: usize = 512 * 1024 * 1024;
const MAX_NATIVE_COMPONENT_BYTES: usize = 256 * 1024 * 1024;
pub(crate) const MAX_CODEX_BACKUP_BYTES: usize =
    MAX_LIFECYCLE_COMPONENT_BYTES + MAX_NATIVE_COMPONENT_BYTES + 64 * 1024;
const CODEX_AVAILABLE_CAPABILITIES: &[&str] = &[
    "bootstrap",
    "candidate_hierarchy_dag",
    "checkpoint",
    "codex_composite_backup",
    "codex_composite_restore_pristine_native_only",
    "compact",
    "context_pack_recall",
    "durable_fjall_storage",
    "durable_postflight_receipt",
    "handoff",
    "mcp_transport",
    "native_service_executor",
    "policy_first_candidate_recall",
    "policy_first_candidate_traversal",
    "quarantined_memory_proposals",
    "restart_verification",
    "resume",
    "runtime_state",
    "status",
    "verify",
];

/// Combined incremental-memory and durable-lifecycle service for Codex MCP.
pub(crate) struct CodexService {
    native: NativeService,
    lifecycle: Arc<ProductionService>,
}

impl std::fmt::Debug for CodexService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodexService")
            .field("memory_profile", &self.native.profile())
            .field("lifecycle", &self.lifecycle)
            .finish_non_exhaustive()
    }
}

impl CodexService {
    /// Opens both authorities from one already authenticated CLI state.
    pub(crate) fn open(path: &Path, state: Arc<LoadedState>) -> CliResult<Self> {
        let key = state.key.expose_copy();
        let (_, identity) = state
            .authority
            .load_verified(&key)
            .map_err(|_| durable_checkpoint_error("authenticated Codex state preflight failed"))?;
        let native = NativeService::open(native_store_path(path), identity.database_id, key)?;
        let lifecycle = Arc::new(ProductionService::open(path, state)?);
        Ok(Self { native, lifecycle })
    }
}

impl CognitiveMemoryService for CodexService {
    fn observe(&self, request: ObserveRequest) -> ServiceResult<ObserveResponse> {
        self.native.observe(request)
    }

    fn recall(&self, request: RecallRequest) -> ServiceResult<RecallResponse> {
        self.native.recall(request)
    }

    fn compile_context(
        &self,
        request: CompileContextRequest,
    ) -> ServiceResult<CompileContextResponse> {
        self.native.compile_context(request)
    }

    fn explain_recall(&self, request: ExplainRecallRequest) -> ServiceResult<RecallTrace> {
        self.native.explain_recall(request)
    }

    fn export_archive(&self, request: ExportRequest) -> ServiceResult<ExportResponse> {
        // A native-only archive would omit the independently anchored lifecycle
        // database, so retain the native profile's explicit Unsupported result.
        self.native.export_archive(request)
    }

    fn import_archive(&self, request: ImportRequest) -> ServiceResult<ImportResponse> {
        // Live import cannot atomically replace both hybrid authorities.
        self.native.import_archive(request)
    }

    fn verify(&self, request: VerifyRequest) -> ServiceResult<VerifyResponse> {
        // The lifecycle authority is the anti-rollback boundary and is checked
        // first. Only a healthy lifecycle publication may expose the native
        // semantic verification receipt.
        self.lifecycle.verify(request.clone())?;
        self.native.verify(request)
    }

    fn ingest_frame(&self, request: IngestFrame) -> ServiceResult<IngestAck> {
        self.lifecycle.ingest_frame(request)
    }

    fn subscribe(&self, request: SubscribeRequest) -> ServiceResult<SubscriptionPage> {
        self.lifecycle.subscribe(request)
    }

    fn publish_memory(&self, request: PublishMemoryRequest) -> ServiceResult<MutationResponse> {
        self.native.publish_memory(request)
    }

    fn propose_memory(
        &self,
        request: ProposeMemoryRequest,
    ) -> ServiceResult<ProposeMemoryResponse> {
        self.native.propose_memory(request)
    }

    fn recall_candidates(
        &self,
        request: RecallCandidatesRequest,
    ) -> ServiceResult<RecallCandidatesResponse> {
        self.native.recall_candidates(request)
    }

    fn get_candidate(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        self.native.get_candidate(request)
    }

    fn correct(&self, request: CorrectRequest) -> ServiceResult<MutationResponse> {
        self.native.correct(request)
    }

    fn forget(&self, request: ForgetRequest) -> ServiceResult<MutationResponse> {
        self.native.forget(request)
    }

    fn get_node(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        self.native.get_node(request)
    }

    fn get_memory(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        self.native.get_memory(request)
    }

    fn traverse(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        self.native.traverse(request)
    }

    fn traverse_candidates(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        self.native.traverse_candidates(request)
    }

    fn get_timeline(&self, request: GetTimelineRequest) -> ServiceResult<TimelineResponse> {
        self.native.get_timeline(request)
    }

    fn bootstrap(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        self.lifecycle.bootstrap(request)
    }

    fn preflight(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        self.lifecycle.preflight(request)
    }

    fn postflight(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        self.lifecycle.postflight(request)
    }

    fn checkpoint(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        self.lifecycle.checkpoint(request)
    }

    fn resume(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        self.lifecycle.resume(request)
    }

    fn handoff(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        self.lifecycle.handoff(request)
    }

    fn get_status(&self, request: GetStatusRequest) -> ServiceResult<StatusResponse> {
        let lifecycle = self.lifecycle.get_status(request.clone())?;
        let mut memory = self.native.get_status(request)?;
        memory.profile = format!(
            "{HYBRID_PROFILE}+memory({})+lifecycle({})",
            memory.profile, lifecycle.profile
        );
        memory.capability_manifest = codex_capability_manifest(&memory.profile);
        Ok(memory)
    }

    fn compact(&self, request: MaintenanceRequest) -> ServiceResult<MaintenanceResponse> {
        // Authenticate before even the top-level discriminator can act as a
        // profile/schema oracle. Routing is exact and never retries another
        // authority after a format or execution failure.
        authorize_capability(&request.context, Capability::Maintenance)?;
        match compact_route(&request.payload)? {
            CompactRoute::Lifecycle => self.lifecycle.compact(request),
            CompactRoute::Native => self.native.compact(request),
        }
    }

    fn create_backup(&self, request: CreateBackupRequest) -> ServiceResult<BackupResponse> {
        authorize_capability(&request.context, Capability::Admin)?;
        self.lifecycle.with_host_archive_current(|lifecycle| {
            let lifecycle_identity = crate::state_head::inspect_archive(&lifecycle.bytes)
                .map_err(|_| integrity_backup("verified lifecycle archive is invalid"))?;
            if lifecycle_identity.commit_seq != lifecycle.commit_seq
                || lifecycle_identity.archive_digest != lifecycle.digest
            {
                return Err(integrity_backup(
                    "verified lifecycle archive identity diverged",
                ));
            }
            let native = self.native.create_backup(request)?;
            if native.format != NATIVE_BACKUP_FORMAT {
                return Err(integrity_backup("native backup format diverged"));
            }
            let native_commit_seq = native.commit_seq;
            let envelope = CodexBackupEnvelope {
                database_id: lifecycle_identity.database_id,
                lifecycle: BackupComponent::from_export(lifecycle.clone()),
                native: BackupComponent::from_response(native),
            };
            let bytes = encode_codex_backup(&envelope)?;
            Ok(BackupResponse {
                format: CODEX_BACKUP_FORMAT.to_owned(),
                digest: blake3::hash(&bytes).to_hex().to_string(),
                bytes,
                commit_seq: native_commit_seq,
            })
        })
    }

    fn restore_backup(
        &self,
        request: RestoreBackupRequest,
    ) -> ServiceResult<RestoreBackupResponse> {
        // Authentication precedes all envelope parsing and lifecycle identity
        // comparison. Restore never becomes a content or format oracle.
        authorize_capability(&request.context, Capability::Admin)?;
        if request.format != CODEX_BACKUP_FORMAT {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "Codex composite backup format is incompatible",
                false,
            ));
        }
        if request.bytes.len() > MAX_CODEX_BACKUP_BYTES {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "Codex composite backup exceeds its bounded size",
                false,
            ));
        }
        if request.digest != blake3::hash(&request.bytes).to_hex().to_string() {
            return Err(integrity_backup("Codex composite backup digest is invalid"));
        }
        let RestoreBackupRequest { context, bytes, .. } = request;
        let envelope = decode_codex_backup(&bytes)?;
        drop(bytes);
        self.lifecycle.with_host_archive_current(|current| {
            let current_identity = crate::state_head::inspect_archive(&current.bytes)
                .map_err(|_| integrity_backup("verified lifecycle archive is invalid"))?;
            if current_identity.database_id != envelope.database_id
                || !envelope.lifecycle.matches_export(current)
            {
                return Err(lifecycle_restore_mismatch());
            }
            self.native.restore_backup(RestoreBackupRequest {
                context,
                format: envelope.native.format,
                bytes: envelope.native.bytes,
                digest: envelope.native.digest,
            })
        })
    }

    fn migrate_format(&self, request: MigrateFormatRequest) -> ServiceResult<StatusResponse> {
        self.lifecycle.migrate_format(request)
    }
}

fn codex_capability_manifest(profile: &str) -> contextdb_service::CapabilityManifestV1 {
    // This is an explicit adapter dispatch/host-property whitelist. It must
    // never be produced by merging the two underlying service manifests:
    // several lifecycle methods are intentionally not routed by CodexService.
    let mut manifest = service_capability_manifest_v1(profile, CODEX_AVAILABLE_CAPABILITIES, &[]);
    if cfg!(feature = "server-v1") {
        for capability in [
            "ann_hnsw_runtime",
            "compression_zstd",
            "lexical_tantivy",
            "native_graph_store",
        ] {
            manifest
                .capabilities
                .insert(capability.to_owned(), CapabilityState::CompiledOnly);
        }
    }
    for capability in [
        "archive_export",
        "archive_import",
        "hard_delete",
        "live_restore",
        "persistent_ann_recall_projection",
        "persistent_lexical_recall_projection",
    ] {
        manifest
            .capabilities
            .insert(capability.to_owned(), CapabilityState::Unsupported);
    }
    manifest.server_v1_release_ready = false;
    manifest
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompactRoute {
    Lifecycle,
    Native,
}

fn compact_route(payload: &serde_json::Value) -> ServiceResult<CompactRoute> {
    let Some(object) = payload.as_object() else {
        return Err(invalid_hybrid_compact_format());
    };
    if object.contains_key("action") {
        return Ok(CompactRoute::Lifecycle);
    }
    if object.len() == 2
        && object.contains_key("schema_version")
        && object.contains_key("max_bytes")
    {
        return Ok(CompactRoute::Native);
    }
    Err(invalid_hybrid_compact_format())
}

fn invalid_hybrid_compact_format() -> ServiceError {
    ServiceError::new(
        ErrorCode::FormatIncompatible,
        "hybrid compact payload must match exactly one advertised authority schema",
        false,
    )
    .with_context(
        Vec::new(),
        Some("hybrid_compact_route".to_owned()),
        Some(
            "use a production payload with action, or native {schema_version,max_bytes}".to_owned(),
        ),
        None,
    )
}

pub(crate) fn native_store_path(path: &Path) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(".native-fjall");
    PathBuf::from(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackupComponent {
    format: String,
    digest: String,
    commit_seq: u64,
    bytes: Vec<u8>,
}

impl BackupComponent {
    fn from_response(response: BackupResponse) -> Self {
        Self {
            format: response.format,
            digest: response.digest,
            commit_seq: response.commit_seq,
            bytes: response.bytes,
        }
    }

    fn from_export(response: ExportResponse) -> Self {
        Self {
            format: response.format,
            digest: response.digest,
            commit_seq: response.commit_seq,
            bytes: response.bytes,
        }
    }

    fn matches_export(&self, response: &ExportResponse) -> bool {
        self.format == response.format
            && self.digest == response.digest
            && self.commit_seq == response.commit_seq
            && self.bytes == response.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CodexBackupEnvelope {
    database_id: String,
    lifecycle: BackupComponent,
    native: BackupComponent,
}

fn encode_codex_backup(envelope: &CodexBackupEnvelope) -> ServiceResult<Vec<u8>> {
    validate_codex_component(
        &envelope.lifecycle,
        "contextdb.logical.v1",
        MAX_LIFECYCLE_COMPONENT_BYTES,
    )?;
    validate_codex_component(
        &envelope.native,
        NATIVE_BACKUP_FORMAT,
        MAX_NATIVE_COMPONENT_BYTES,
    )?;
    let identity = crate::state_head::inspect_archive(&envelope.lifecycle.bytes)
        .map_err(|_| integrity_backup("lifecycle backup component is invalid"))?;
    if identity.database_id != envelope.database_id
        || identity.commit_seq != envelope.lifecycle.commit_seq
        || identity.archive_digest != envelope.lifecycle.digest
    {
        return Err(integrity_backup(
            "lifecycle backup component identity diverged",
        ));
    }

    let mut output = Vec::new();
    push_codex_bytes(&mut output, CODEX_BACKUP_MAGIC)?;
    push_codex_u16(&mut output, CODEX_BACKUP_SCHEMA_VERSION)?;
    push_codex_string(&mut output, CODEX_BACKUP_FORMAT)?;
    push_codex_string(&mut output, CODEX_BACKUP_RESTORE_POLICY)?;
    push_codex_string(&mut output, &envelope.database_id)?;
    push_codex_component(&mut output, &envelope.lifecycle)?;
    push_codex_component(&mut output, &envelope.native)?;
    let footer = *blake3::hash(&output).as_bytes();
    push_codex_bytes(&mut output, &footer)?;
    Ok(output)
}

fn decode_codex_backup(bytes: &[u8]) -> ServiceResult<CodexBackupEnvelope> {
    if bytes.len() > MAX_CODEX_BACKUP_BYTES
        || bytes.len() < CODEX_BACKUP_MAGIC.len() + CODEX_BACKUP_FOOTER_BYTES
    {
        return Err(integrity_backup("Codex composite backup length is invalid"));
    }
    let body_len = bytes
        .len()
        .checked_sub(CODEX_BACKUP_FOOTER_BYTES)
        .ok_or_else(|| integrity_backup("Codex composite backup footer is absent"))?;
    let (body, footer) = bytes.split_at(body_len);
    if footer != blake3::hash(body).as_bytes() {
        return Err(integrity_backup(
            "Codex composite backup footer digest is invalid",
        ));
    }
    let mut reader = CodexBackupReader::new(body);
    if reader.take(CODEX_BACKUP_MAGIC.len())? != CODEX_BACKUP_MAGIC
        || reader.read_u16()? != CODEX_BACKUP_SCHEMA_VERSION
        || reader.read_string(128)? != CODEX_BACKUP_FORMAT
        || reader.read_string(128)? != CODEX_BACKUP_RESTORE_POLICY
    {
        return Err(ServiceError::new(
            ErrorCode::FormatIncompatible,
            "Codex composite backup header is incompatible",
            false,
        ));
    }
    let database_id = reader.read_string(1_024)?;
    let lifecycle = reader.read_component(MAX_LIFECYCLE_COMPONENT_BYTES)?;
    let native = reader.read_component(MAX_NATIVE_COMPONENT_BYTES)?;
    if !reader.is_finished() {
        return Err(integrity_backup(
            "Codex composite backup contains trailing body bytes",
        ));
    }
    let envelope = CodexBackupEnvelope {
        database_id,
        lifecycle,
        native,
    };
    validate_codex_component(
        &envelope.lifecycle,
        "contextdb.logical.v1",
        MAX_LIFECYCLE_COMPONENT_BYTES,
    )?;
    validate_codex_component(
        &envelope.native,
        NATIVE_BACKUP_FORMAT,
        MAX_NATIVE_COMPONENT_BYTES,
    )?;
    let identity = crate::state_head::inspect_archive(&envelope.lifecycle.bytes)
        .map_err(|_| integrity_backup("lifecycle backup component is invalid"))?;
    if identity.database_id != envelope.database_id
        || identity.commit_seq != envelope.lifecycle.commit_seq
        || identity.archive_digest != envelope.lifecycle.digest
    {
        return Err(integrity_backup(
            "lifecycle backup component identity diverged",
        ));
    }
    if encode_codex_backup(&envelope)? != bytes {
        return Err(integrity_backup(
            "Codex composite backup encoding is non-canonical",
        ));
    }
    Ok(envelope)
}

fn validate_codex_component(
    component: &BackupComponent,
    expected_format: &str,
    maximum: usize,
) -> ServiceResult<()> {
    if component.format != expected_format {
        return Err(ServiceError::new(
            ErrorCode::FormatIncompatible,
            "Codex backup component format is incompatible",
            false,
        ));
    }
    if component.bytes.len() > maximum {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "Codex backup component exceeds its bounded size",
            false,
        ));
    }
    if component.digest.len() != 64
        || blake3::Hash::from_hex(&component.digest).is_err()
        || component.digest != blake3::hash(&component.bytes).to_hex().to_string()
    {
        return Err(integrity_backup("Codex backup component digest is invalid"));
    }
    Ok(())
}

fn push_codex_component(output: &mut Vec<u8>, component: &BackupComponent) -> ServiceResult<()> {
    push_codex_string(output, &component.format)?;
    push_codex_string(output, &component.digest)?;
    push_codex_u64(output, component.commit_seq)?;
    let length = u64::try_from(component.bytes.len()).map_err(|_| {
        ServiceError::new(
            ErrorCode::ResourceExhausted,
            "Codex backup component length exceeds u64",
            false,
        )
    })?;
    push_codex_u64(output, length)?;
    push_codex_bytes(output, &component.bytes)
}

fn push_codex_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> ServiceResult<()> {
    let required = output.len().checked_add(bytes.len()).ok_or_else(|| {
        ServiceError::new(
            ErrorCode::ResourceExhausted,
            "Codex composite backup length overflowed",
            false,
        )
    })?;
    if required > MAX_CODEX_BACKUP_BYTES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "Codex composite backup exceeds its bounded size",
            false,
        ));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn push_codex_u16(output: &mut Vec<u8>, value: u16) -> ServiceResult<()> {
    push_codex_bytes(output, &value.to_be_bytes())
}

fn push_codex_u64(output: &mut Vec<u8>, value: u64) -> ServiceResult<()> {
    push_codex_bytes(output, &value.to_be_bytes())
}

fn push_codex_string(output: &mut Vec<u8>, value: &str) -> ServiceResult<()> {
    let length = u16::try_from(value.len()).map_err(|_| {
        ServiceError::new(
            ErrorCode::ResourceExhausted,
            "Codex backup string exceeds u16",
            false,
        )
    })?;
    if length == 0 {
        return Err(integrity_backup("Codex backup string is empty"));
    }
    push_codex_u16(output, length)?;
    push_codex_bytes(output, value.as_bytes())
}

struct CodexBackupReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> CodexBackupReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, count: usize) -> ServiceResult<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| integrity_backup("Codex composite backup is truncated"))?;
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> ServiceResult<u16> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| integrity_backup("Codex backup u16 is truncated"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> ServiceResult<u64> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| integrity_backup("Codex backup u64 is truncated"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_string(&mut self, maximum: usize) -> ServiceResult<String> {
        let length = usize::from(self.read_u16()?);
        if length == 0 || length > maximum {
            return Err(integrity_backup("Codex backup string length is invalid"));
        }
        std::str::from_utf8(self.take(length)?)
            .map(ToOwned::to_owned)
            .map_err(|_| integrity_backup("Codex backup string is not UTF-8"))
    }

    fn read_component(&mut self, maximum: usize) -> ServiceResult<BackupComponent> {
        let format = self.read_string(128)?;
        let digest = self.read_string(64)?;
        let commit_seq = self.read_u64()?;
        let length = usize::try_from(self.read_u64()?).map_err(|_| {
            ServiceError::new(
                ErrorCode::ResourceExhausted,
                "Codex backup component length exceeds this platform",
                false,
            )
        })?;
        if length > maximum {
            return Err(ServiceError::new(
                ErrorCode::ResourceExhausted,
                "Codex backup component exceeds its bounded size",
                false,
            ));
        }
        Ok(BackupComponent {
            format,
            digest,
            commit_seq,
            bytes: self.take(length)?.to_vec(),
        })
    }

    const fn is_finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

fn integrity_backup(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::IntegrityFailure, message, false)
}

fn lifecycle_restore_mismatch() -> ServiceError {
    ServiceError::new(
        ErrorCode::Unsupported,
        "Codex composite restore requires the exact current lifecycle authority",
        false,
    )
    .with_context(
        Vec::new(),
        Some("restore:lifecycle-exact-match-required".to_owned()),
        Some("use the quiesced full production recovery protocol".to_owned()),
        None,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use contextdb_service::{
        AccessPolicy, AuthenticatedRequestContext, AuthenticationEvidence, Consent, RequestContext,
        Sensitivity,
    };

    use super::*;
    use crate::{OutputFormat, TokenKey, init_state_with_key, load_state_with_key};

    fn fixture() -> (tempfile::TempDir, Arc<LoadedState>, CodexService) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("codex-hybrid.ctxb");
        let key = TokenKey::new([0x6a; 32]).expect("test token key");
        init_state_with_key(&path, false, OutputFormat::Json, &key)
            .expect("initialize hybrid lifecycle store");
        let state = load_state_with_key(&path, &key).expect("load hybrid state");
        drop(
            ProductionService::initialize(&path, state.clone())
                .expect("bind test authority to initialized lifecycle store"),
        );
        let service = CodexService::open(&path, state.clone()).expect("open hybrid service");
        (directory, state, service)
    }

    fn legacy_context(request_id: &str) -> RequestContext {
        RequestContext {
            request_id: request_id.to_owned(),
            workspace_id: "workspace:codex-hybrid".to_owned(),
            subject_id: "subject:codex-hybrid".to_owned(),
            audiences: BTreeSet::from(["subject:codex-hybrid".to_owned()]),
            scopes: BTreeSet::from(["project:codex-hybrid".to_owned()]),
            purpose: "assist".to_owned(),
            clearance: Sensitivity::Private,
        }
    }

    fn legacy_admin_context(request_id: &str) -> RequestContext {
        let mut context = legacy_context(request_id);
        context.purpose = "contextdb:admin".to_owned();
        context.clearance = Sensitivity::Restricted;
        context
    }

    fn authenticated(
        request_id: &str,
        grants: impl IntoIterator<Item = Capability>,
    ) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: legacy_context(request_id),
            actor_id: "actor:codex-hybrid".to_owned(),
            agent_id: "agent:codex-hybrid".to_owned(),
            session_id: Some("session:codex-hybrid".to_owned()),
            capability_grants: grants.into_iter().collect(),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: "channel:codex-hybrid".to_owned(),
                peer_identity: "actor:codex-hybrid".to_owned(),
                binding_digest: "6a".repeat(32),
            },
        }
    }

    fn observe_request() -> ObserveRequest {
        ObserveRequest {
            context: legacy_context("request:hybrid-observe"),
            idempotency_key: "idempotency:hybrid-observe".to_owned(),
            observation_id: "observation:hybrid-native".to_owned(),
            metadata: BTreeMap::new(),
            content: serde_json::json!({"text": "native memory authority sentinel"}),
            access: AccessPolicy {
                workspace_id: "workspace:codex-hybrid".to_owned(),
                scopes: BTreeSet::from(["project:codex-hybrid".to_owned()]),
                owners: BTreeSet::from(["subject:codex-hybrid".to_owned()]),
                audience: BTreeSet::from(["subject:codex-hybrid".to_owned()]),
                audience_purpose_grants: BTreeMap::new(),
                purposes: BTreeSet::from(["assist".to_owned()]),
                sensitivity: Sensitivity::Private,
                consent: Consent::Granted,
                retrievable: true,
            },
        }
    }

    fn recall_request(request_id: &str) -> RecallRequest {
        RecallRequest {
            context: legacy_context(request_id),
            query: "native memory authority sentinel".to_owned(),
            page_size: 10,
            at_commit: None,
            continuation: None,
        }
    }

    fn publish_request(request_id: &str) -> PublishMemoryRequest {
        PublishMemoryRequest {
            context: authenticated(request_id, [Capability::Observe, Capability::Correct]),
            idempotency_key: format!("idempotency:{request_id}"),
            memory_id: "memory:hybrid-native".to_owned(),
            value: serde_json::json!({"text": "native memory authority sentinel"}),
            search_text: "native memory authority sentinel".to_owned(),
        }
    }

    #[test]
    fn capability_manifest_is_the_exact_codex_dispatch_whitelist() {
        let (_directory, _state, service) = fixture();
        let status = service
            .get_status(GetStatusRequest {
                context: authenticated("request:manifest", [Capability::Admin]),
            })
            .expect("hybrid status");
        let available = status
            .capability_manifest
            .capabilities
            .iter()
            .filter_map(|(capability, state)| {
                (*state == CapabilityState::Available).then_some(capability.as_str())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            available,
            CODEX_AVAILABLE_CAPABILITIES.iter().copied().collect()
        );
        assert!(!status.capability_manifest.server_v1_release_ready);
        for capability in [
            "archive_export",
            "archive_import",
            "background_semantic_adjudication",
            "consolidate",
            "hard_delete",
            "live_restore",
            "observation_semantic_extraction",
            "persistent_ann_recall_projection",
            "persistent_lexical_recall_projection",
            "reflect",
        ] {
            assert_eq!(
                status.capability_manifest.capability(capability),
                Some(CapabilityState::Unsupported),
                "CodexService has no advertised route for {capability}"
            );
        }
    }

    #[test]
    fn composite_backup_restores_only_a_pristine_native_authority_and_reopens() {
        let (directory, state, service) = fixture();
        let path = directory.path().join("codex-hybrid.ctxb");
        service
            .publish_memory(publish_request("request:seed-backup"))
            .expect("seed native authority");
        let backup = service
            .create_backup(CreateBackupRequest {
                context: authenticated("request:backup", [Capability::Admin]),
            })
            .expect("create composite backup");
        assert_eq!(backup.format, CODEX_BACKUP_FORMAT);
        assert_eq!(
            backup.digest,
            blake3::hash(&backup.bytes).to_hex().to_string()
        );
        assert!(backup.bytes.len() <= MAX_CODEX_BACKUP_BYTES);
        let denied_malformed = service
            .restore_backup(RestoreBackupRequest {
                context: authenticated("request:restore-denied-malformed", []),
                format: "attacker-controlled-format".to_owned(),
                bytes: b"attacker-controlled-content".to_vec(),
                digest: "attacker-controlled-digest".to_owned(),
            })
            .expect_err("authorization precedes composite parsing");
        let denied_valid = service
            .restore_backup(RestoreBackupRequest {
                context: authenticated("request:restore-denied-valid", []),
                format: backup.format.clone(),
                bytes: backup.bytes.clone(),
                digest: backup.digest.clone(),
            })
            .expect_err("authorization also precedes valid composite inspection");
        assert_eq!(denied_malformed, denied_valid);
        assert_eq!(denied_valid.code, ErrorCode::Unauthorized);

        drop(service);
        let native_path = native_store_path(&path);
        fs::rename(&native_path, directory.path().join("source-native-fjall"))
            .expect("quarantine source native authority");
        let target = CodexService::open(&path, state.clone()).expect("open pristine target");

        let before = target
            .native
            .verify(VerifyRequest {
                context: legacy_admin_context("request:before-tamper"),
                deep: true,
            })
            .expect("verify pristine target");
        let mut tampered = backup.clone();
        *tampered.bytes.last_mut().expect("non-empty composite") ^= 1;
        tampered.digest = blake3::hash(&tampered.bytes).to_hex().to_string();
        let tamper_error = target
            .restore_backup(RestoreBackupRequest {
                context: authenticated("request:tampered-restore", [Capability::Admin]),
                format: tampered.format,
                bytes: tampered.bytes,
                digest: tampered.digest,
            })
            .expect_err("footer tamper must fail before mutation");
        assert_eq!(tamper_error.code, ErrorCode::IntegrityFailure);
        assert_eq!(
            target
                .native
                .verify(VerifyRequest {
                    context: legacy_admin_context("request:after-tamper"),
                    deep: true,
                })
                .expect("target remains pristine"),
            before
        );

        let restored = target
            .restore_backup(RestoreBackupRequest {
                context: authenticated("request:restore", [Capability::Admin]),
                format: backup.format.clone(),
                bytes: backup.bytes.clone(),
                digest: backup.digest.clone(),
            })
            .expect("restore composite backup");
        assert_eq!(restored.commit_seq, backup.commit_seq);
        let recalled = target
            .recall(recall_request("request:restored-recall"))
            .expect("recall restored native memory");
        assert_eq!(recalled.hits.len(), 1);
        assert_eq!(recalled.hits[0].id, "memory:hybrid-native");

        let second_restore = target
            .restore_backup(RestoreBackupRequest {
                context: authenticated("request:second-restore", [Capability::Admin]),
                format: backup.format.clone(),
                bytes: backup.bytes.clone(),
                digest: backup.digest.clone(),
            })
            .expect_err("non-pristine native target must be rejected");
        assert_eq!(second_restore.code, ErrorCode::Unsupported);
        assert_eq!(
            second_restore.violated_policy.as_deref(),
            Some("restore:pristine-target-only")
        );
        assert_eq!(
            target
                .recall(recall_request("request:after-second-restore"))
                .expect("failed restore leaves memory unchanged")
                .hits,
            recalled.hits
        );

        drop(target);
        let reopened = CodexService::open(&path, state).expect("reopen restored authorities");
        assert_eq!(
            reopened
                .recall(recall_request("request:reopened-recall"))
                .expect("restored memory survives restart")
                .hits,
            recalled.hits
        );
    }

    #[test]
    fn composite_restore_rejects_lifecycle_drift_before_native_mutation() {
        let (directory, state, service) = fixture();
        let path = directory.path().join("codex-hybrid.ctxb");
        service
            .publish_memory(publish_request("request:seed-drift"))
            .expect("seed native authority");
        let backup = service
            .create_backup(CreateBackupRequest {
                context: authenticated("request:drift-backup", [Capability::Admin]),
            })
            .expect("create composite backup");

        service
            .lifecycle
            .observe(observe_request())
            .expect("advance lifecycle authority after backup");
        drop(service);
        let native_path = native_store_path(&path);
        fs::rename(
            &native_path,
            directory.path().join("drift-source-native-fjall"),
        )
        .expect("quarantine source native authority");
        let target = CodexService::open(&path, state).expect("open pristine target");
        let before = target
            .native
            .verify(VerifyRequest {
                context: legacy_admin_context("request:drift-before"),
                deep: true,
            })
            .expect("verify pristine native target");
        let error = target
            .restore_backup(RestoreBackupRequest {
                context: authenticated("request:drift-restore", [Capability::Admin]),
                format: backup.format,
                bytes: backup.bytes,
                digest: backup.digest,
            })
            .expect_err("lifecycle drift must fail before native restore");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert_eq!(
            error.violated_policy.as_deref(),
            Some("restore:lifecycle-exact-match-required")
        );
        assert_eq!(
            target
                .native
                .verify(VerifyRequest {
                    context: legacy_admin_context("request:drift-after"),
                    deep: true,
                })
                .expect("mismatch leaves native target pristine"),
            before
        );
    }

    #[test]
    fn verify_and_status_require_lifecycle_then_publish_native_memory_receipts() {
        let (_directory, state, service) = fixture();
        service
            .observe(observe_request())
            .expect("advance only the native memory authority");

        let verify_request = VerifyRequest {
            context: legacy_admin_context("request:hybrid-verify"),
            deep: true,
        };
        let lifecycle_receipt = service
            .lifecycle
            .verify(verify_request.clone())
            .expect("lifecycle verification");
        let native_receipt = service
            .native
            .verify(verify_request.clone())
            .expect("native verification");
        let hybrid_receipt = service
            .verify(verify_request.clone())
            .expect("dual hybrid verification");
        assert_eq!(hybrid_receipt, native_receipt);
        assert_ne!(hybrid_receipt, lifecycle_receipt);
        assert_eq!(hybrid_receipt.commit_seq, 1);

        let status_request = GetStatusRequest {
            context: authenticated("request:hybrid-status", [Capability::Admin]),
        };
        let lifecycle_status = service
            .lifecycle
            .get_status(status_request.clone())
            .expect("lifecycle status");
        let native_status = service
            .native
            .get_status(status_request.clone())
            .expect("native status");
        let hybrid_status = service.get_status(status_request).expect("hybrid status");
        assert_eq!(hybrid_status.commit_seq, native_status.commit_seq);
        assert_eq!(hybrid_status.watermarks, native_status.watermarks);
        assert_eq!(hybrid_status.commit_seq, 1);
        assert!(hybrid_status.profile.starts_with(HYBRID_PROFILE));
        assert!(hybrid_status.profile.contains(service.native.profile()));
        assert!(hybrid_status.profile.contains(&lifecycle_status.profile));
        assert!(hybrid_status.profile.contains("runtime_ledger_pressure="));
        assert!(!hybrid_status.profile.contains("workspace:codex-hybrid"));

        let original_authority = state
            .authority
            .raw_authority()
            .expect("read lifecycle authority")
            .expect("initialized lifecycle authority");
        let mut tampered_authority = original_authority.clone();
        *tampered_authority.last_mut().expect("non-empty authority") ^= 1;
        state
            .authority
            .replace_raw_authority(Some(tampered_authority))
            .expect("tamper lifecycle authority");
        let error = service
            .verify(verify_request.clone())
            .expect_err("hybrid verification must fail on lifecycle authority corruption");
        assert!(matches!(
            error.code,
            ErrorCode::IntegrityFailure | ErrorCode::Unavailable
        ));
        assert_eq!(
            service
                .native
                .verify(verify_request)
                .expect("native authority remains healthy"),
            native_receipt
        );
        state
            .authority
            .replace_raw_authority(Some(original_authority))
            .expect("restore lifecycle authority fixture");
    }

    #[test]
    fn compact_and_operational_methods_route_to_exact_hybrid_authorities() {
        let (_directory, _state, service) = fixture();
        let maintenance = authenticated("request:hybrid-compact", [Capability::Maintenance]);
        let lifecycle = service
            .compact(MaintenanceRequest {
                context: maintenance.clone(),
                operation_id: "compact:hybrid:lifecycle".to_owned(),
                payload: serde_json::json!({
                    "action": "physical",
                    "schema_version": 1,
                    "max_bytes": 4096
                }),
            })
            .expect("route tagged compact to lifecycle authority");
        assert_eq!(lifecycle.payload["scheduler_managed"], true);

        let native = service
            .compact(MaintenanceRequest {
                context: maintenance.clone(),
                operation_id: "compact:hybrid:native".to_owned(),
                payload: serde_json::json!({
                    "schema_version": 1,
                    "max_bytes": 4096
                }),
            })
            .expect("route exact untagged compact to native authority");
        assert_eq!(native.payload["logical_state_changed"], false);
        assert!(native.payload.get("scheduler_managed").is_none());

        let ambiguous = service
            .compact(MaintenanceRequest {
                context: maintenance.clone(),
                operation_id: "compact:hybrid:ambiguous".to_owned(),
                payload: serde_json::json!({
                    "action": "physical",
                    "schema_version": 1,
                    "max_bytes": 4096,
                    "native_extra": true
                }),
            })
            .expect_err("tagged payload never falls back to native parsing");
        assert_eq!(ambiguous.code, ErrorCode::FormatIncompatible);

        let unknown = service
            .compact(MaintenanceRequest {
                context: maintenance,
                operation_id: "compact:hybrid:unknown".to_owned(),
                payload: serde_json::json!({"schema_version": 1}),
            })
            .expect_err("untagged payload must match the exact native shape");
        assert_eq!(unknown.code, ErrorCode::FormatIncompatible);
        assert_eq!(
            unknown.violated_policy.as_deref(),
            Some("hybrid_compact_route")
        );

        let mut unauthorized = MaintenanceRequest {
            context: authenticated("request:hybrid-compact-unauthorized", []),
            operation_id: "compact:hybrid:unauthorized".to_owned(),
            payload: serde_json::json!({"protected": "x".repeat(16 * 1024)}),
        };
        assert_eq!(
            service
                .compact(unauthorized.clone())
                .expect_err("authorization precedes route inspection")
                .code,
            ErrorCode::Unauthorized
        );
        unauthorized.payload = serde_json::json!({"action": "physical"});
        assert_eq!(
            service
                .compact(unauthorized)
                .expect_err("tagged route is also authorization-first")
                .code,
            ErrorCode::Unauthorized
        );

        let admin = authenticated("request:hybrid-admin", [Capability::Admin]);
        let migration = service
            .migrate_format(MigrateFormatRequest {
                context: admin.clone(),
                target_format: "contextdb.production-fjall.state-root-v2.runtime-ledger-v1"
                    .to_owned(),
                operation_id: "migration:hybrid:preflight".to_owned(),
            })
            .expect("delegate exact identity preflight to lifecycle authority");
        assert!(migration.profile.starts_with("production-fjall-v1"));

        let export = service
            .export_archive(ExportRequest {
                context: legacy_context("request:hybrid-export"),
            })
            .expect_err("hybrid export cannot omit lifecycle authority");
        assert_eq!(export.code, ErrorCode::Unsupported);
        assert!(export.message.contains("native"));
        let import = service
            .import_archive(ImportRequest {
                context: legacy_context("request:hybrid-import"),
                format: "contextdb.logical.v1".to_owned(),
                bytes: Vec::new(),
                digest: "00".repeat(32),
            })
            .expect_err("hybrid import cannot atomically replace both authorities");
        assert_eq!(import.code, ErrorCode::Unsupported);
        assert!(import.message.contains("native"));
    }
}
