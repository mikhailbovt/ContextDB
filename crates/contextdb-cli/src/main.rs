//! Headless command-line, daemon, and MCP entry point for ContextDB.

#![forbid(unsafe_code)]

#[cfg(feature = "mcp")]
mod codex_service;
#[cfg(feature = "mcp")]
mod mcp_broker;
mod production;
mod state_head;

#[cfg(feature = "mcp")]
use std::collections::BTreeSet;
#[cfg(feature = "current-server")]
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
#[cfg(feature = "current-server")]
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLockReadGuard;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "current-server")]
use contextdb_server::{
    Blake3GatewayAuthenticator, ExecutionAdmission, ExecutionAdmissionConfig, FixedHealthProvider,
    GatewayAuthenticator, HealthChecks, HealthProfile, HealthProvider, HealthReason, HealthState,
    HealthSummary, serve_grpc_listener_with_shutdown_gateway_and_admission,
    serve_http_with_shutdown_gateway_health_and_admission,
};
use contextdb_server::{
    error_to_proto, export_response_to_proto, import_response_to_proto, observe_response_to_proto,
    recall_response_to_proto, recall_trace_to_proto, verify_response_to_proto,
};
#[cfg(feature = "mcp")]
use contextdb_service::{
    AuthenticatedRequestContext, AuthenticationEvidence, Capability as ServiceCapability,
};
use contextdb_service::{
    BackupResponse, CognitiveMemoryService, CompileContextRequest, CompileContextResponse,
    CorrectRequest, CreateBackupRequest, ErrorCode, ExplainRecallRequest, ExportResponse,
    ForgetRequest, GetMemoryRequest, GetStatusRequest, GetTimelineRequest, HighLevelControlRequest,
    HighLevelMutationResponse, HighLevelQueryRequest, HighLevelTransferRequest,
    HighLevelWriteRequest, HostArchiveAuthority, ImportResponse, IngestAck, IngestFrame,
    MaintenanceRequest, MaintenanceResponse, MemoryRecord, MigrateFormatRequest, MutationResponse,
    ObserveRequest, RecallRequest, RecallResponse, ReferenceService, RequestContext,
    RestoreBackupRequest, RestoreBackupResponse, RuntimeRequest, RuntimeResponse, Sensitivity,
    ServiceError, ServiceResult, StatusResponse, SubscribeRequest, SubscriptionPage,
    TimelineResponse, TraverseRequest, TraverseResponse, VerifyRequest,
};
#[cfg(any(feature = "current-server", feature = "mcp", test))]
use contextdb_service::{ExportRequest, ImportRequest};
#[cfg(any(feature = "current-server", feature = "mcp", test))]
use contextdb_service::{ObserveResponse, RecallTrace, VerifyResponse};
use prost::Message;
#[cfg(feature = "mcp")]
use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroizing;

#[cfg(feature = "mcp")]
use crate::codex_service::{
    CODEX_BACKUP_FORMAT, CODEX_BACKUP_RESTORE_POLICY, CodexService, MAX_CODEX_BACKUP_BYTES,
};
use crate::production::ProductionService;
use crate::state_head::StateHeadStore;

const ARCHIVE_FORMAT: &str = "contextdb.logical.v1";
const TOKEN_KEY_HEX_ENV: &str = "CONTEXTDB_TOKEN_KEY_HEX";
const TOKEN_KEY_FILE_ENV: &str = "CONTEXTDB_TOKEN_KEY_FILE";
#[cfg(feature = "current-server")]
const GATEWAY_ID_ENV: &str = "CONTEXTDB_GATEWAY_ID";
#[cfg(feature = "current-server")]
const GATEWAY_KEY_HEX_ENV: &str = "CONTEXTDB_GATEWAY_KEY_HEX";
const TOKEN_KEY_BYTES: usize = 32;
const MAX_CUSTODY_SNAPSHOT_FJALL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_CUSTODY_SNAPSHOT_ENTRIES: u64 = 1_000_000;
const MAX_CUSTODY_SNAPSHOT_DEPTH: usize = 128;

#[derive(Debug, Parser)]
#[command(name = "contextdb", version, about)]
struct Cli {
    /// Emit compact JSON instead of human-readable JSON.
    #[arg(long, global = true, conflicts_with = "protobuf")]
    json: bool,
    /// Emit the canonical Protobuf response bytes to stdout.
    #[arg(long, global = true)]
    protobuf: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print independently versioned ContextDB components.
    Version,
    /// Create an empty portable logical database using an external token key.
    Init {
        /// Archive path. Omit only for the legacy in-memory smoke demo.
        path: Option<PathBuf>,
        /// Use the deterministic in-memory reference smoke demo.
        #[arg(long)]
        in_memory: bool,
        /// Compatibility flag; anchored state refuses replacement.
        #[arg(long)]
        force: bool,
    },
    /// Print the current logical head after shallow verification.
    Status {
        /// Portable logical archive.
        path: PathBuf,
    },
    /// Capture one JSON-encoded canonical observation request.
    Observe {
        /// Portable logical archive.
        path: PathBuf,
        /// Request JSON path, or `-` for stdin.
        #[arg(long)]
        request: PathBuf,
    },
    /// Run one JSON-encoded canonical recall request.
    Recall {
        /// Portable logical archive.
        path: PathBuf,
        /// Request JSON path, or `-` for stdin.
        #[arg(long)]
        request: PathBuf,
    },
    /// Validate and return one JSON-encoded recall trace request.
    Explain {
        /// Portable logical archive.
        path: PathBuf,
        /// Request JSON path, or `-` for stdin.
        #[arg(long)]
        request: PathBuf,
    },
    /// Invoke one authenticated v1 domain, runtime, maintenance, or high-level method.
    Api {
        /// Portable logical archive.
        path: PathBuf,
        /// Stable RFC method name in kebab-case.
        #[arg(value_enum)]
        operation: ApiOperation,
        /// Request JSON path, or `-` for stdin.
        #[arg(long)]
        request: PathBuf,
    },
    #[cfg(feature = "mcp")]
    /// Create a bounded composite backup for the local Codex authorities.
    CodexBackup {
        /// Current portable lifecycle archive.
        path: PathBuf,
        /// New destination for the sensitive composite backup.
        output: PathBuf,
    },
    #[cfg(feature = "mcp")]
    /// Restore a local Codex composite backup into a pristine native sidecar.
    CodexRestore {
        /// Unchanged portable lifecycle archive associated with the backup.
        path: PathBuf,
        /// Source composite backup.
        input: PathBuf,
    },
    /// Copy a verified canonical logical archive.
    Export {
        /// Current portable logical archive.
        path: PathBuf,
        /// Destination archive.
        output: PathBuf,
    },
    #[command(hide = true)]
    /// Export a quiesced source-bound custody snapshot through a detached verifier.
    CustodySnapshotExport {
        /// Current portable logical archive whose external authority is locked.
        path: PathBuf,
        /// New canonical logical archive destination.
        output: PathBuf,
    },
    /// Validate and clone a canonical logical archive into a new empty path.
    Import {
        /// Destination state path.
        path: PathBuf,
        /// Source canonical archive.
        input: PathBuf,
        /// Compatibility flag; anchored state refuses replacement.
        #[arg(long)]
        force: bool,
    },
    /// Run logical verification.
    Verify {
        /// Portable logical archive.
        path: PathBuf,
        /// Include canonical export/import replay.
        #[arg(long)]
        deep: bool,
    },
    /// Run deep verification (operator-friendly alias).
    Doctor {
        /// Portable logical archive.
        path: PathBuf,
    },
    #[cfg(feature = "current-server")]
    /// Probe the local daemon's content-free readiness endpoint.
    Probe {
        /// Loopback HTTP address of the current-server daemon.
        #[arg(long, default_value = "127.0.0.1:7733")]
        address: SocketAddr,
    },
    #[cfg(feature = "current-server")]
    /// Serve HTTP/JSON and gRPC until Ctrl-C, then atomically checkpoint.
    Serve {
        /// Portable logical archive.
        path: PathBuf,
        /// HTTP/JSON listen address.
        #[arg(long, default_value = "127.0.0.1:7733")]
        http_listen: SocketAddr,
        /// Canonical gRPC listen address.
        #[arg(long, default_value = "127.0.0.1:7734")]
        grpc_listen: SocketAddr,
        /// Development-only archive service without the Fjall production ledger.
        #[arg(long)]
        reference: bool,
    },
    #[cfg(feature = "mcp")]
    /// Run the external MCP stdio adapter, then checkpoint on EOF.
    Mcp {
        /// Portable logical archive.
        path: PathBuf,
        /// Development-only archive service without the Fjall production ledger.
        #[arg(long)]
        reference: bool,
        /// Host-authenticated actor fixed for this MCP process.
        #[arg(long)]
        actor_id: String,
        /// Host-authenticated agent fixed for this MCP process.
        #[arg(long)]
        agent_id: String,
        /// Authorized workspace fixed for this MCP process.
        #[arg(long)]
        workspace_id: String,
        /// Authorized subject fixed for this MCP process.
        #[arg(long)]
        subject_id: String,
        /// Authorized purpose fixed for this MCP process.
        #[arg(long)]
        purpose: String,
        /// Optional fixed host session identifier.
        #[arg(long)]
        session_id: Option<String>,
        /// Authorized audience. Repeat for each audience.
        #[arg(long = "audience", required = true)]
        audiences: Vec<String>,
        /// Authorized semantic scope. Repeat for each scope.
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        /// Host-granted MCP operation capability. Repeat as needed.
        #[arg(long = "capability", value_enum, required = true)]
        capabilities: Vec<McpCapabilityArg>,
        /// Maximum sensitivity materializable by this MCP process.
        #[arg(long, value_enum)]
        clearance: McpClearanceArg,
    },
    #[cfg(feature = "mcp")]
    #[command(hide = true)]
    /// Own the local durable authorities and multiplex authenticated MCP sessions.
    McpBroker {
        /// Portable logical archive.
        path: PathBuf,
        /// Development-only archive service without the Fjall production ledger.
        #[arg(long)]
        reference: bool,
    },
    #[cfg(feature = "mcp")]
    #[command(hide = true)]
    /// Quiesce and stop the authenticated local MCP broker for operator work.
    McpBrokerStop {
        /// Portable logical archive.
        path: PathBuf,
    },
}

#[cfg(feature = "mcp")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
enum McpCapabilityArg {
    Observe,
    Recall,
    ReadMemory,
    Correct,
    Traverse,
    ModelProcessing,
    Runtime,
    Admin,
}

#[cfg(feature = "mcp")]
impl From<McpCapabilityArg> for ServiceCapability {
    fn from(value: McpCapabilityArg) -> Self {
        match value {
            McpCapabilityArg::Observe => Self::Observe,
            McpCapabilityArg::Recall => Self::Recall,
            McpCapabilityArg::ReadMemory => Self::ReadMemory,
            McpCapabilityArg::Correct => Self::Correct,
            McpCapabilityArg::Traverse => Self::Traverse,
            McpCapabilityArg::ModelProcessing => Self::ModelProcessing,
            McpCapabilityArg::Runtime => Self::Runtime,
            McpCapabilityArg::Admin => Self::Admin,
        }
    }
}

#[cfg(feature = "mcp")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
enum McpClearanceArg {
    Public,
    Internal,
    Private,
    Restricted,
}

#[cfg(feature = "mcp")]
impl From<McpClearanceArg> for Sensitivity {
    fn from(value: McpClearanceArg) -> Self {
        match value {
            McpClearanceArg::Public => Self::Public,
            McpClearanceArg::Internal => Self::Internal,
            McpClearanceArg::Private => Self::Private,
            McpClearanceArg::Restricted => Self::Restricted,
        }
    }
}

/// Bounded canonical v1 operation vocabulary exposed by `contextdb api`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, ValueEnum)]
enum ApiOperation {
    IngestFrame,
    Subscribe,
    Correct,
    Forget,
    GetNode,
    Traverse,
    GetTimeline,
    GetEvidence,
    GetConflict,
    CompileContext,
    Bootstrap,
    Preflight,
    Postflight,
    Checkpoint,
    Resume,
    Handoff,
    Consolidate,
    Reflect,
    Reindex,
    Compact,
    GetStatus,
    CreateBackup,
    RestoreBackup,
    MigrateFormat,
    BeginSession,
    BeforeTurn,
    AfterTurn,
    ResolveReferent,
    RecallSharedHistory,
    EndSession,
    BootstrapSubject,
    Remember,
    Pin,
    Suppress,
    ChangeAudience,
    ChangeRetention,
    ExplainMemory,
    ListSubjectMemories,
    ExportSubject,
    ImportSubject,
    CreateMemorySubject,
    CreateRelationshipSpace,
    GetContinuityProfile,
    UpdateConfiguredRole,
    MigrateAgentRuntime,
    PublishToSharedMemory,
    RevokeSharedMemory,
    IngestArtifact,
    AttachArtifactToEpisode,
    AddDerivedRepresentation,
    AddEvidenceSelector,
    GetArtifactMetadata,
    DeleteArtifactLineage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Human,
    Json,
    Protobuf,
}

#[derive(Debug, Serialize)]
struct StateReceipt<'a> {
    operation: &'a str,
    path: String,
    commit_seq: u64,
}

#[cfg(feature = "mcp")]
#[derive(Debug, Serialize)]
struct CodexBackupReceipt<'a> {
    operation: &'a str,
    state_path: String,
    backup_path: String,
    format: &'a str,
    digest: &'a str,
    commit_seq: u64,
    bytes: usize,
    restore_policy: &'a str,
}

#[cfg(feature = "mcp")]
#[derive(Debug, Serialize)]
struct CodexRestoreReceipt<'a> {
    operation: &'a str,
    state_path: String,
    backup_path: String,
    format: &'a str,
    digest: &'a str,
    restore_policy: &'a str,
    response: RestoreBackupResponse,
}

#[derive(Debug)]
struct CliError(ServiceError);

struct TokenKey {
    bytes: Zeroizing<[u8; TOKEN_KEY_BYTES]>,
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl TokenKey {
    fn new(bytes: [u8; TOKEN_KEY_BYTES]) -> CliResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err("token key cannot be all zero".to_owned().into());
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    fn expose_copy(&self) -> [u8; TOKEN_KEY_BYTES] {
        *self.bytes
    }
}

#[cfg(feature = "mcp")]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct McpAuthorityConfig {
    actor_id: String,
    agent_id: String,
    workspace_id: String,
    subject_id: String,
    purpose: String,
    session_id: Option<String>,
    audiences: Vec<String>,
    scopes: Vec<String>,
    capabilities: Vec<McpCapabilityArg>,
    clearance: McpClearanceArg,
}

#[cfg(feature = "mcp")]
fn mcp_session_authority(
    token_key: &TokenKey,
    config: McpAuthorityConfig,
) -> CliResult<AuthenticatedRequestContext> {
    let capabilities = config
        .capabilities
        .into_iter()
        .map(ServiceCapability::from)
        .collect::<BTreeSet<_>>();
    let request = RequestContext {
        request_id: "mcp:launch-authority".to_owned(),
        workspace_id: config.workspace_id,
        subject_id: config.subject_id,
        audiences: config.audiences.into_iter().collect(),
        scopes: config.scopes.into_iter().collect(),
        purpose: config.purpose,
        clearance: config.clearance.into(),
    };
    let actor_id = config.actor_id;
    let context = AuthenticatedRequestContext {
        request,
        actor_id: actor_id.clone(),
        agent_id: config.agent_id,
        session_id: config.session_id,
        capability_grants: capabilities,
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "mcp:protected-local-stdio".to_owned(),
            peer_identity: actor_id,
            binding_digest: blake3::keyed_hash(
                &blake3::derive_key(
                    "contextdb/cli/mcp-session-binding/v1",
                    &token_key.expose_copy(),
                ),
                b"mcp:protected-local-stdio",
            )
            .to_hex()
            .to_string(),
        },
    };
    context.validate_authentication()?;
    Ok(context)
}

#[cfg(feature = "mcp")]
fn codex_operator_authority(
    token_key: &TokenKey,
    operation: &str,
) -> CliResult<AuthenticatedRequestContext> {
    let actor_id = "operator:contextdb-local-host".to_owned();
    let channel_id = "cli:codex-operator-recovery".to_owned();
    let context = AuthenticatedRequestContext {
        request: RequestContext {
            request_id: format!("cli:{operation}"),
            workspace_id: "workspace:local-admin".to_owned(),
            subject_id: "subject:local-admin".to_owned(),
            audiences: BTreeSet::from(["subject:local-admin".to_owned()]),
            scopes: BTreeSet::from(["host:local-recovery".to_owned()]),
            purpose: "contextdb:admin".to_owned(),
            clearance: Sensitivity::Restricted,
        },
        actor_id: actor_id.clone(),
        agent_id: "agent:contextdb-cli".to_owned(),
        session_id: None,
        capability_grants: BTreeSet::from([ServiceCapability::Admin]),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: channel_id.clone(),
            peer_identity: actor_id,
            binding_digest: blake3::keyed_hash(
                &blake3::derive_key(
                    "contextdb/cli/codex-operator-binding/v1",
                    &token_key.expose_copy(),
                ),
                format!("{channel_id}:{operation}").as_bytes(),
            )
            .to_hex()
            .to_string(),
        },
    };
    context.validate_authentication()?;
    Ok(context)
}

type CliResult<T> = Result<T, CliError>;

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<String> for CliError {
    fn from(error: String) -> Self {
        Self(ServiceError::new(ErrorCode::InvalidArgument, error, false))
    }
}

impl From<ServiceError> for CliError {
    fn from(error: ServiceError) -> Self {
        Self(error)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self(ServiceError::new(
            ErrorCode::Unavailable,
            error.to_string(),
            true,
        ))
    }
}

#[cfg(any(feature = "current-server", feature = "mcp", test))]
struct DurableService {
    state: Arc<LoadedState>,
}

#[cfg(any(feature = "current-server", feature = "mcp", test))]
impl std::fmt::Debug for DurableService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableService")
            .field("path", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[cfg(any(feature = "current-server", feature = "mcp", test))]
impl DurableService {
    fn new(state: Arc<LoadedState>) -> Self {
        Self { state }
    }
}

struct LoadedState {
    inner: RwLock<Arc<ReferenceService>>,
    key: TokenKey,
    authority: StateHeadStore,
    poisoned: AtomicBool,
}

impl std::fmt::Debug for LoadedState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoadedState")
            .field("inner", &self.inner)
            .field("key", &self.key)
            .field("authority", &self.authority)
            .finish()
    }
}

impl LoadedState {
    fn read(&self) -> ServiceResult<RwLockReadGuard<'_, Arc<ReferenceService>>> {
        let service = self.inner.read().map_err(|_| {
            ServiceError::new(
                ErrorCode::Unavailable,
                "durable state publication lock failed",
                true,
            )
        })?;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(durable_checkpoint_error(
                "durable state is quarantined after an ambiguous checkpoint; restart after repairing the external authority",
            ));
        }
        Ok(service)
    }
}

#[cfg(any(feature = "current-server", feature = "mcp", test))]
impl LoadedState {
    fn with_service<T>(
        &self,
        operation: impl FnOnce(&ReferenceService) -> ServiceResult<T>,
    ) -> ServiceResult<T> {
        let service = self.read()?;
        operation(&service)
    }

    /// Builds the mutation against a private service loaded from the current
    /// authenticated archive. Readers retain the old service until the new
    /// archive and its state head have both committed successfully.
    fn transact<T>(
        &self,
        operation: impl FnOnce(&ReferenceService) -> ServiceResult<T>,
    ) -> ServiceResult<T> {
        let mut published = self.inner.write().map_err(|_| {
            ServiceError::new(
                ErrorCode::Unavailable,
                "durable state publication lock failed",
                true,
            )
        })?;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(durable_checkpoint_error(
                "durable state is quarantined after an ambiguous checkpoint; restart after repairing the external authority",
            ));
        }
        let (trusted_bytes, trusted_identity) = self
            .authority
            .load_verified(&self.key.expose_copy())
            .map_err(|_| durable_checkpoint_error("authenticated state preflight failed"))?;
        let candidate = Arc::new(
            service_from_archive(
                trusted_identity.database_id.clone(),
                self.key.expose_copy(),
                trusted_bytes,
                "durable-transaction",
            )
            .map_err(|_| durable_checkpoint_error("trusted state reconstruction failed"))?,
        );
        let response = operation(&candidate)?;
        let host_authority = HostArchiveAuthority::new(self.key.expose_copy())?;
        let archive = candidate
            .export_host_archive(&host_authority)
            .map_err(|_| durable_checkpoint_error("candidate export failed"))?;
        let candidate_identity = state_head::inspect_archive(&archive.bytes)
            .map_err(|_| durable_checkpoint_error("candidate identity validation failed"))?;
        if self
            .authority
            .advance(&self.key.expose_copy(), &archive.bytes)
            .is_err()
        {
            match self.authority.load_verified(&self.key.expose_copy()) {
                Ok((_bytes, recovered)) if recovered == candidate_identity => {
                    // The exact pending candidate reached the atomic archive
                    // replacement and is therefore the committed candidate. Treat
                    // final active-head reconciliation as successful recovery.
                }
                Ok((_bytes, recovered)) if recovered == trusted_identity => {
                    return Err(durable_checkpoint_error(
                        "authenticated checkpoint commit failed before publication",
                    ));
                }
                Ok(_) | Err(_) => {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(durable_checkpoint_error(
                        "authenticated checkpoint outcome is ambiguous; state quarantined",
                    ));
                }
            }
        }
        *published = candidate;
        Ok(response)
    }
}

fn durable_checkpoint_error(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::Unavailable, message, true)
}

#[cfg(any(feature = "current-server", feature = "mcp", test))]
impl CognitiveMemoryService for DurableService {
    fn observe(&self, request: ObserveRequest) -> ServiceResult<ObserveResponse> {
        self.state.transact(|service| service.observe(request))
    }

    fn recall(&self, request: RecallRequest) -> ServiceResult<RecallResponse> {
        self.state.with_service(|service| service.recall(request))
    }

    fn compile_context(
        &self,
        request: CompileContextRequest,
    ) -> ServiceResult<CompileContextResponse> {
        self.state
            .with_service(|service| service.compile_context(request))
    }

    fn explain_recall(&self, request: ExplainRecallRequest) -> ServiceResult<RecallTrace> {
        self.state
            .with_service(|service| service.explain_recall(request))
    }

    fn export_archive(&self, request: ExportRequest) -> ServiceResult<ExportResponse> {
        self.state
            .with_service(|service| service.export_archive(request))
    }

    fn import_archive(&self, request: ImportRequest) -> ServiceResult<ImportResponse> {
        self.state
            .with_service(|service| service.import_archive(request))
    }

    fn verify(&self, request: VerifyRequest) -> ServiceResult<VerifyResponse> {
        self.state.with_service(|service| service.verify(request))
    }
}

fn main() {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let requested_format = if arguments.iter().any(|argument| argument == "--protobuf") {
        OutputFormat::Protobuf
    } else if arguments.iter().any(|argument| argument == "--json") {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    };
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return;
        }
        Err(_) => {
            emit_cli_error(
                &CliError(ServiceError::new(
                    ErrorCode::InvalidArgument,
                    "invalid command line",
                    false,
                )),
                requested_format,
            );
            std::process::exit(2);
        }
    };
    let format = if cli.protobuf {
        OutputFormat::Protobuf
    } else if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    };
    if let Err(error) = run(cli) {
        emit_cli_error(&error, format);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> CliResult<()> {
    let format = if cli.protobuf {
        OutputFormat::Protobuf
    } else if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    };
    match cli.command {
        Command::Version => print_version(),
        Command::Init {
            path: _,
            in_memory: true,
            force: _,
        } => {
            let service = ReferenceService::new("contextdb-m0-demo", [1; 32])?;
            let response = service.verify(VerifyRequest {
                context: admin_context("init-smoke"),
                deep: false,
            })?;
            emit_state(
                "initialized_in_memory",
                Path::new("<memory>"),
                response.commit_seq,
                format,
            )?;
        }
        Command::Init {
            path: Some(path),
            in_memory: false,
            force,
        } => init_state(&path, force, format)?,
        Command::Init {
            path: None,
            in_memory: false,
            force: _,
        } => {
            return Err("init requires a state path or --in-memory"
                .to_owned()
                .into());
        }
        Command::Status { path } => {
            let service = load_production(&path)?;
            let response = service.verify(VerifyRequest {
                context: admin_context("status"),
                deep: false,
            })?;
            emit_proto(
                &response,
                verify_response_to_proto(response.clone()),
                format,
            )?;
        }
        Command::Observe { path, request } => {
            let request: ObserveRequest = read_json(&request)?;
            let service = load_production(&path)?;
            let response = service.observe(request)?;
            emit_proto(
                &response,
                observe_response_to_proto(response.clone()),
                format,
            )?;
        }
        Command::Recall { path, request } => {
            let request: RecallRequest = read_json(&request)?;
            let response = load_production(&path)?.recall(request)?;
            emit_proto(
                &response,
                recall_response_to_proto(response.clone()),
                format,
            )?;
        }
        Command::Explain { path, request } => {
            let request: ExplainRecallRequest = read_json(&request)?;
            let response = load_production(&path)?.explain_recall(request)?;
            emit_proto(&response, recall_trace_to_proto(response.clone()), format)?;
        }
        Command::Api {
            path,
            operation,
            request,
        } => {
            let service = load_production(&path)?;
            dispatch_api(service.as_ref(), operation, &request, format)?;
        }
        #[cfg(feature = "mcp")]
        Command::CodexBackup { path, output } => {
            create_codex_backup(&path, &output, format)?;
        }
        #[cfg(feature = "mcp")]
        Command::CodexRestore { path, input } => {
            restore_codex_backup(&path, &input, format)?;
        }
        Command::Export { path, output } => {
            let response = load_production(&path)?.export_host_archive_current()?;
            atomic_write(&output, &response.bytes, false)?;
            emit_proto(
                &response,
                export_response_to_proto(response.clone()),
                format,
            )?;
        }
        Command::CustodySnapshotExport { path, output } => {
            custody_snapshot_export(&path, &output, format)?;
        }
        Command::Import { path, input, force } => {
            import_state(&path, &input, force, format)?;
        }
        Command::Verify { path, deep } => {
            verify_state(&path, deep, format)?;
        }
        Command::Doctor { path } => verify_state(&path, true, format)?,
        #[cfg(feature = "current-server")]
        Command::Probe { address } => probe_readiness(address, format)?,
        #[cfg(feature = "current-server")]
        Command::Serve {
            path,
            http_listen,
            grpc_listen,
            reference,
        } => run_current_server(&path, http_listen, grpc_listen, reference)?,
        #[cfg(feature = "mcp")]
        Command::Mcp {
            path,
            reference,
            actor_id,
            agent_id,
            workspace_id,
            subject_id,
            purpose,
            session_id,
            audiences,
            scopes,
            capabilities,
            clearance,
        } => {
            let config = McpAuthorityConfig {
                actor_id,
                agent_id,
                workspace_id,
                subject_id,
                purpose,
                session_id,
                audiences,
                scopes,
                capabilities,
                clearance,
            };
            mcp_broker::run_proxy(&path, reference, config)?;
        }
        #[cfg(feature = "mcp")]
        Command::McpBroker { path, reference } => {
            mcp_broker::run_broker(&path, reference)?;
        }
        #[cfg(feature = "mcp")]
        Command::McpBrokerStop { path } => {
            mcp_broker::stop_broker(&path)?;
        }
    }
    Ok(())
}

fn dispatch_api(
    service: &dyn CognitiveMemoryService,
    operation: ApiOperation,
    request_path: &Path,
    format: OutputFormat,
) -> CliResult<()> {
    if format == OutputFormat::Protobuf {
        return Err(ServiceError::new(
            ErrorCode::Unsupported,
            "the grouped API surface emits canonical JSON; use the named Protobuf commands or gRPC for Protobuf output",
            false,
        )
        .into());
    }

    macro_rules! invoke {
        ($request:ty, $method:ident, $response:ty) => {{
            let request: $request = read_json(request_path)?;
            let response: $response = service.$method(request)?;
            emit_json(&response, format)
        }};
    }

    match operation {
        ApiOperation::IngestFrame => invoke!(IngestFrame, ingest_frame, IngestAck),
        ApiOperation::Subscribe => invoke!(SubscribeRequest, subscribe, SubscriptionPage),
        ApiOperation::Correct => invoke!(CorrectRequest, correct, MutationResponse),
        ApiOperation::Forget => invoke!(ForgetRequest, forget, MutationResponse),
        ApiOperation::GetNode => invoke!(GetMemoryRequest, get_node, MemoryRecord),
        ApiOperation::Traverse => invoke!(TraverseRequest, traverse, TraverseResponse),
        ApiOperation::GetTimeline => {
            invoke!(GetTimelineRequest, get_timeline, TimelineResponse)
        }
        ApiOperation::GetEvidence => invoke!(GetMemoryRequest, get_evidence, MemoryRecord),
        ApiOperation::GetConflict => invoke!(GetMemoryRequest, get_conflict, MemoryRecord),
        ApiOperation::CompileContext => {
            invoke!(
                CompileContextRequest,
                compile_context,
                CompileContextResponse
            )
        }
        ApiOperation::Bootstrap => invoke!(RuntimeRequest, bootstrap, RuntimeResponse),
        ApiOperation::Preflight => invoke!(RuntimeRequest, preflight, RuntimeResponse),
        ApiOperation::Postflight => invoke!(RuntimeRequest, postflight, RuntimeResponse),
        ApiOperation::Checkpoint => invoke!(RuntimeRequest, checkpoint, RuntimeResponse),
        ApiOperation::Resume => invoke!(RuntimeRequest, resume, RuntimeResponse),
        ApiOperation::Handoff => invoke!(RuntimeRequest, handoff, RuntimeResponse),
        ApiOperation::Consolidate => {
            invoke!(MaintenanceRequest, consolidate, MaintenanceResponse)
        }
        ApiOperation::Reflect => invoke!(MaintenanceRequest, reflect, MaintenanceResponse),
        ApiOperation::Reindex => invoke!(MaintenanceRequest, reindex, MaintenanceResponse),
        ApiOperation::Compact => invoke!(MaintenanceRequest, compact, MaintenanceResponse),
        ApiOperation::GetStatus => invoke!(GetStatusRequest, get_status, StatusResponse),
        ApiOperation::CreateBackup => {
            invoke!(CreateBackupRequest, create_backup, BackupResponse)
        }
        ApiOperation::RestoreBackup => {
            invoke!(RestoreBackupRequest, restore_backup, RestoreBackupResponse)
        }
        ApiOperation::MigrateFormat => {
            invoke!(MigrateFormatRequest, migrate_format, StatusResponse)
        }
        ApiOperation::BeginSession => {
            invoke!(
                HighLevelWriteRequest,
                begin_session,
                HighLevelMutationResponse
            )
        }
        ApiOperation::BeforeTurn => invoke!(HighLevelQueryRequest, before_turn, RecallResponse),
        ApiOperation::AfterTurn => {
            invoke!(HighLevelWriteRequest, after_turn, HighLevelMutationResponse)
        }
        ApiOperation::ResolveReferent => {
            invoke!(HighLevelQueryRequest, resolve_referent, RecallResponse)
        }
        ApiOperation::RecallSharedHistory => {
            invoke!(HighLevelQueryRequest, recall_shared_history, RecallResponse)
        }
        ApiOperation::EndSession => {
            invoke!(
                HighLevelWriteRequest,
                end_session,
                HighLevelMutationResponse
            )
        }
        ApiOperation::BootstrapSubject => {
            invoke!(
                HighLevelWriteRequest,
                bootstrap_subject,
                HighLevelMutationResponse
            )
        }
        ApiOperation::Remember => {
            invoke!(HighLevelWriteRequest, remember, HighLevelMutationResponse)
        }
        ApiOperation::Pin => invoke!(HighLevelControlRequest, pin, MutationResponse),
        ApiOperation::Suppress => invoke!(HighLevelControlRequest, suppress, MutationResponse),
        ApiOperation::ChangeAudience => {
            invoke!(HighLevelControlRequest, change_audience, MutationResponse)
        }
        ApiOperation::ChangeRetention => {
            invoke!(HighLevelControlRequest, change_retention, MutationResponse)
        }
        ApiOperation::ExplainMemory => {
            invoke!(HighLevelQueryRequest, explain_memory, RecallResponse)
        }
        ApiOperation::ListSubjectMemories => {
            invoke!(HighLevelQueryRequest, list_subject_memories, RecallResponse)
        }
        ApiOperation::ExportSubject => {
            invoke!(HighLevelTransferRequest, export_subject, ExportResponse)
        }
        ApiOperation::ImportSubject => {
            invoke!(HighLevelTransferRequest, import_subject, ImportResponse)
        }
        ApiOperation::CreateMemorySubject => invoke!(
            HighLevelWriteRequest,
            create_memory_subject,
            HighLevelMutationResponse
        ),
        ApiOperation::CreateRelationshipSpace => invoke!(
            HighLevelWriteRequest,
            create_relationship_space,
            HighLevelMutationResponse
        ),
        ApiOperation::GetContinuityProfile => {
            invoke!(
                HighLevelQueryRequest,
                get_continuity_profile,
                RecallResponse
            )
        }
        ApiOperation::UpdateConfiguredRole => {
            invoke!(
                HighLevelControlRequest,
                update_configured_role,
                MutationResponse
            )
        }
        ApiOperation::MigrateAgentRuntime => {
            invoke!(
                HighLevelControlRequest,
                migrate_agent_runtime,
                MutationResponse
            )
        }
        ApiOperation::PublishToSharedMemory => invoke!(
            HighLevelControlRequest,
            publish_to_shared_memory,
            MutationResponse
        ),
        ApiOperation::RevokeSharedMemory => invoke!(
            HighLevelControlRequest,
            revoke_shared_memory,
            MutationResponse
        ),
        ApiOperation::IngestArtifact => invoke!(
            HighLevelWriteRequest,
            ingest_artifact,
            HighLevelMutationResponse
        ),
        ApiOperation::AttachArtifactToEpisode => invoke!(
            HighLevelWriteRequest,
            attach_artifact_to_episode,
            HighLevelMutationResponse
        ),
        ApiOperation::AddDerivedRepresentation => invoke!(
            HighLevelWriteRequest,
            add_derived_representation,
            HighLevelMutationResponse
        ),
        ApiOperation::AddEvidenceSelector => invoke!(
            HighLevelWriteRequest,
            add_evidence_selector,
            HighLevelMutationResponse
        ),
        ApiOperation::GetArtifactMetadata => {
            invoke!(HighLevelQueryRequest, get_artifact_metadata, RecallResponse)
        }
        ApiOperation::DeleteArtifactLineage => invoke!(
            HighLevelControlRequest,
            delete_artifact_lineage,
            MutationResponse
        ),
    }
}

fn init_state(path: &Path, force: bool, format: OutputFormat) -> CliResult<()> {
    if force {
        return Err(
            "--force is disabled for anchored state; initialize a new empty path instead"
                .to_owned()
                .into(),
        );
    }
    ensure_archive_parent(path)?;
    let key = read_external_key(path)?;
    let authority = StateHeadStore::open(path).map_err(CliError::from)?;
    init_state_with_authority(path, format, &key, &authority)
}

#[cfg(test)]
fn init_state_with_key(
    path: &Path,
    force: bool,
    format: OutputFormat,
    key: &TokenKey,
) -> CliResult<()> {
    if force {
        return Err("anchored state cannot be force-replaced".to_owned().into());
    }
    let authority = StateHeadStore::memory(path).map_err(CliError::from)?;
    init_state_with_authority(path, format, key, &authority)
}

fn init_state_with_authority(
    path: &Path,
    format: OutputFormat,
    key: &TokenKey,
    authority: &StateHeadStore,
) -> CliResult<()> {
    let service = ReferenceService::new(database_id(path), key.expose_copy())?;
    let host_authority = HostArchiveAuthority::new(key.expose_copy())?;
    let archive = service.export_host_archive(&host_authority)?;
    let receipt = authority
        .bootstrap(&key.expose_copy(), &archive.bytes)
        .map_err(CliError::from)?;
    let state = load_state_with_authority(TokenKey::new(key.expose_copy())?, authority.clone())?;
    ProductionService::initialize(path, state)?;
    emit_state("initialized", path, receipt.commit_seq, format)
}

fn import_state(path: &Path, input: &Path, force: bool, format: OutputFormat) -> CliResult<()> {
    if force {
        return Err(
            "--force is disabled: raw logical import may only clone into a new empty anchored path"
                .to_owned()
                .into(),
        );
    }
    if path.exists() {
        return Err("destination exists; raw import cannot overwrite live state"
            .to_owned()
            .into());
    }
    ensure_archive_parent(path)?;
    let bytes = state_head::read_archive_bounded(input).map_err(CliError::from)?;
    let key = read_external_key(path)?;
    let service = ReferenceService::new(database_id(path), key.expose_copy())?;
    let host_authority = HostArchiveAuthority::new(key.expose_copy())?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    let response = service.import_host_archive(&host_authority, ARCHIVE_FORMAT, &bytes, &digest)?;
    let canonical = service.export_host_archive(&host_authority)?;
    let authority = StateHeadStore::open(path).map_err(CliError::from)?;
    let staged = authority
        .bootstrap(&key.expose_copy(), &canonical.bytes)
        .map_err(CliError::from)?;
    if staged.commit_seq != response.commit_seq {
        return Err("staged import receipt changed commit head"
            .to_owned()
            .into());
    }
    let state = load_state_with_authority(TokenKey::new(key.expose_copy())?, authority.clone())?;
    ProductionService::initialize(path, state)?;
    emit_proto(
        &response,
        import_response_to_proto(response.clone()),
        format,
    )
}

fn verify_state(path: &Path, deep: bool, format: OutputFormat) -> CliResult<()> {
    let response = load_production(path)?.verify(VerifyRequest {
        context: admin_context("verify"),
        deep,
    })?;
    emit_proto(
        &response,
        verify_response_to_proto(response.clone()),
        format,
    )
}

fn custody_snapshot_export(path: &Path, output: &Path, format: OutputFormat) -> CliResult<()> {
    reject_existing_custody_output(output)?;
    reject_custody_path_links(path, "source archive path")?;
    let key = read_external_key(path)?;

    // This exact external-authority lock is the quiescence boundary for every
    // supported ContextDB writer. It remains held until the detached snapshot
    // has been verified, exported, and atomically installed.
    let source_authority = StateHeadStore::open(path).map_err(CliError::from)?;
    let source_archive = source_authority.archive_path().to_path_buf();
    let source_fjall = production::store_path(&source_archive);
    let canonical_source_fjall = canonical_custody_directory(&source_fjall, "production Fjall")?;
    reject_native_custody_sidecar(&source_archive)?;
    let canonical_output =
        canonical_custody_output(output, &source_archive, &canonical_source_fjall)?;

    let temporary = tempfile::tempdir()
        .map_err(|error| format!("cannot create detached custody directory: {error}"))?;
    let detached_archive = temporary.path().join("detached-source.ctxb");
    let detached_authority = source_authority
        .detached_snapshot(&detached_archive, &key.expose_copy())
        .map_err(CliError::from)?;

    let archive_bytes =
        state_head::read_archive_bounded(&source_archive).map_err(CliError::from)?;
    atomic_write(&detached_archive, &archive_bytes, false)?;
    let detached_fjall = production::store_path(&detached_archive);
    copy_custody_tree(&canonical_source_fjall, &detached_fjall)?;
    ensure_detached_fjall_lock(&detached_fjall)?;

    let response = {
        let detached_state =
            load_state_with_authority(TokenKey::new(key.expose_copy())?, detached_authority)?;
        let service = ProductionService::open(&detached_archive, detached_state)?;
        service.verify(VerifyRequest {
            context: admin_context("custody-snapshot-export"),
            deep: true,
        })?;
        service.export_host_archive_current()?
    };
    atomic_write(&canonical_output, &response.bytes, false)?;
    emit_proto(
        &response,
        export_response_to_proto(response.clone()),
        format,
    )
}

fn reject_existing_custody_output(output: &Path) -> CliResult<()> {
    match fs::symlink_metadata(output) {
        Ok(_) => Err(format!("destination already exists: {}", output.display()).into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect custody destination: {error}").into()),
    }
}

fn canonical_custody_output(
    output: &Path,
    source_archive: &Path,
    source_fjall: &Path,
) -> CliResult<PathBuf> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect custody destination directory: {error}"))?;
    reject_custody_path_links(parent, "custody destination directory")?;
    reject_custody_link_or_reparse(&metadata, "custody destination directory")?;
    if !metadata.is_dir() {
        return Err("custody destination parent is not a directory"
            .to_owned()
            .into());
    }
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| format!("cannot resolve custody destination directory: {error}"))?;
    let name = output
        .file_name()
        .ok_or_else(|| CliError::from("custody destination must name a file".to_owned()))?;
    let canonical_output = canonical_parent.join(name);
    if canonical_output == source_archive || canonical_output.starts_with(source_fjall) {
        return Err("custody destination aliases protected source state"
            .to_owned()
            .into());
    }
    Ok(canonical_output)
}

fn reject_native_custody_sidecar(source_archive: &Path) -> CliResult<()> {
    let mut native = source_archive.as_os_str().to_os_string();
    native.push(".native-fjall");
    let native = PathBuf::from(native);
    match fs::symlink_metadata(&native) {
        Ok(_) => Err(format!(
            "native sidecar exists and cannot be omitted from custody migration: {}",
            native.display()
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect native custody sidecar: {error}").into()),
    }
}

fn canonical_custody_directory(path: &Path, label: &str) -> CliResult<PathBuf> {
    reject_custody_path_links(path, label)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("cannot inspect {label}: {error}"))?;
    reject_custody_link_or_reparse(&metadata, label)?;
    if !metadata.is_dir() {
        return Err(format!("{label} is not a directory").into());
    }
    fs::canonicalize(path).map_err(|error| format!("cannot resolve {label}: {error}").into())
}

fn reject_custody_path_links(path: &Path, label: &str) -> CliResult<()> {
    let mut ancestors = path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        reject_custody_link_or_reparse(&metadata, label)?;
    }
    Ok(())
}

fn copy_custody_tree(source: &Path, destination: &Path) -> CliResult<()> {
    if fs::symlink_metadata(destination).is_ok() {
        return Err("detached custody destination already exists"
            .to_owned()
            .into());
    }
    let source = canonical_custody_directory(source, "production Fjall")?;
    fs::create_dir(destination)
        .map_err(|error| format!("cannot create detached Fjall directory: {error}"))?;

    let mut stack = vec![(source, destination.to_path_buf(), 0_usize)];
    let mut entries_seen = 0_u64;
    let mut bytes_seen = 0_u64;
    while let Some((source_directory, destination_directory, depth)) = stack.pop() {
        let mut entries = fs::read_dir(&source_directory)
            .map_err(|error| format!("cannot enumerate production Fjall: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate production Fjall: {error}"))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            entries_seen = entries_seen
                .checked_add(1)
                .ok_or_else(|| CliError::from("custody entry count overflow".to_owned()))?;
            if entries_seen > MAX_CUSTODY_SNAPSHOT_ENTRIES {
                return Err("production Fjall exceeds the custody entry limit"
                    .to_owned()
                    .into());
            }

            let source_entry = entry.path();
            let destination_entry = destination_directory.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_entry)
                .map_err(|error| format!("cannot inspect production Fjall entry: {error}"))?;
            reject_custody_link_or_reparse(&metadata, "production Fjall entry")?;
            if metadata.is_dir() {
                let next_depth = depth
                    .checked_add(1)
                    .ok_or_else(|| CliError::from("custody directory depth overflow".to_owned()))?;
                if next_depth > MAX_CUSTODY_SNAPSHOT_DEPTH {
                    return Err("production Fjall exceeds the custody directory depth limit"
                        .to_owned()
                        .into());
                }
                fs::create_dir(&destination_entry).map_err(|error| {
                    format!("cannot create detached Fjall subdirectory: {error}")
                })?;
                stack.push((source_entry, destination_entry, next_depth));
            } else if metadata.is_file() {
                bytes_seen = bytes_seen
                    .checked_add(metadata.len())
                    .ok_or_else(|| CliError::from("custody byte count overflow".to_owned()))?;
                if bytes_seen > MAX_CUSTODY_SNAPSHOT_FJALL_BYTES {
                    return Err("production Fjall exceeds the 64 GiB custody snapshot limit"
                        .to_owned()
                        .into());
                }
                copy_custody_file(&source_entry, &destination_entry, metadata.len())?;
            } else {
                return Err("production Fjall contains a non-regular filesystem entry"
                    .to_owned()
                    .into());
            }
        }
    }
    Ok(())
}

fn ensure_detached_fjall_lock(detached_fjall: &Path) -> CliResult<()> {
    let lock = detached_fjall.join("lock");
    match fs::symlink_metadata(&lock) {
        Ok(metadata) => {
            reject_custody_link_or_reparse(&metadata, "detached Fjall lock")?;
            if !metadata.is_file() {
                return Err("detached Fjall lock is not a regular file"
                    .to_owned()
                    .into());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("cannot create detached Fjall lock: {error}").into()),
        Err(error) => Err(format!("cannot inspect detached Fjall lock: {error}").into()),
    }
}

fn copy_custody_file(source: &Path, destination: &Path, expected_len: u64) -> CliResult<()> {
    let reader = fs::File::open(source)
        .map_err(|error| format!("cannot open production Fjall entry: {error}"))?;
    let opened = reader
        .metadata()
        .map_err(|error| format!("cannot inspect open production Fjall entry: {error}"))?;
    reject_custody_link_or_reparse(&opened, "open production Fjall entry")?;
    if !opened.is_file() || opened.len() != expected_len {
        return Err(
            "production Fjall changed while custody snapshot was captured"
                .to_owned()
                .into(),
        );
    }
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("cannot create detached Fjall entry: {error}"))?;
    let mut limited = reader.take(expected_len.saturating_add(1));
    let copied = std::io::copy(&mut limited, &mut writer)
        .map_err(|error| format!("cannot copy production Fjall entry: {error}"))?;
    if copied != expected_len {
        return Err(
            "production Fjall changed while custody snapshot was captured"
                .to_owned()
                .into(),
        );
    }
    writer
        .flush()
        .and_then(|()| writer.sync_all())
        .map_err(|error| format!("cannot sync detached Fjall entry: {error}"))?;
    let after = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot re-inspect production Fjall entry: {error}"))?;
    reject_custody_link_or_reparse(&after, "production Fjall entry")?;
    if !after.is_file() || after.len() != expected_len {
        return Err(
            "production Fjall changed while custody snapshot was captured"
                .to_owned()
                .into(),
        );
    }
    Ok(())
}

fn reject_custody_link_or_reparse(metadata: &fs::Metadata, label: &str) -> CliResult<()> {
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} cannot be a symbolic link").into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{label} cannot be a reparse point").into());
        }
    }
    Ok(())
}

#[cfg(feature = "current-server")]
fn probe_readiness(address: SocketAddr, format: OutputFormat) -> CliResult<()> {
    let summary = readiness_snapshot(address)?;
    emit_json(&summary, format)
}

#[cfg(feature = "current-server")]
fn readiness_snapshot(address: SocketAddr) -> CliResult<HealthSummary> {
    readiness_snapshot_with_timeout(address, std::time::Duration::from_secs(2))
}

#[cfg(feature = "current-server")]
fn readiness_snapshot_with_timeout(
    address: SocketAddr,
    timeout: std::time::Duration,
) -> CliResult<HealthSummary> {
    use std::net::{IpAddr, TcpStream};
    use std::time::Instant;

    const MAX_HEALTH_RESPONSE_BYTES: usize = 16 * 1024;
    if !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback())
        && !matches!(address.ip(), IpAddr::V6(ip) if ip.is_loopback())
    {
        return Err("readiness probe address must be loopback".to_owned().into());
    }
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("readiness probe connection failed: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("cannot bound readiness probe read: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("cannot bound readiness probe write: {error}"))?;
    stream
        .write_all(
            b"GET /health/ready HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
        )
        .map_err(|error| format!("readiness probe request failed: {error}"))?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CliError::from("readiness probe timeout is invalid".to_owned()))?;
    let mut response = Vec::new();
    let (header_end, content_length) = loop {
        if response.len() > MAX_HEALTH_RESPONSE_BYTES {
            return Err("readiness probe response exceeds 16 KiB".to_owned().into());
        }
        if let Some(header_end) = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        {
            let content_length = parse_health_headers(&response[..header_end])?;
            let total = header_end.checked_add(content_length).ok_or_else(|| {
                CliError::from("readiness probe response size overflow".to_owned())
            })?;
            if total > MAX_HEALTH_RESPONSE_BYTES {
                return Err("readiness probe response exceeds 16 KiB".to_owned().into());
            }
            if response.len() > total {
                return Err("readiness probe HTTP response has trailing bytes"
                    .to_owned()
                    .into());
            }
            if response.len() == total {
                break (header_end, content_length);
            }
        }

        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| CliError::from("readiness probe response timed out".to_owned()))?;
        if remaining.is_zero() {
            return Err("readiness probe response timed out".to_owned().into());
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| format!("cannot update readiness probe deadline: {error}"))?;
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                "readiness probe response timed out".to_owned()
            } else {
                format!("readiness probe response failed: {error}")
            }
        })?;
        if read == 0 {
            return Err("readiness probe HTTP response ended early"
                .to_owned()
                .into());
        }
        response.extend_from_slice(&buffer[..read]);
    };
    let body = &response[header_end..header_end + content_length];
    let summary: HealthSummary = serde_json::from_slice(body)
        .map_err(|_| "readiness probe body is not canonical health JSON".to_owned())?;
    summary
        .validate()
        .map_err(|_| "readiness probe body violates the health contract".to_owned())?;
    if !summary.is_ready() {
        return Err("readiness probe body does not attest ready state"
            .to_owned()
            .into());
    }
    Ok(summary)
}

#[cfg(feature = "current-server")]
fn parse_health_headers(headers: &[u8]) -> CliResult<usize> {
    let headers = std::str::from_utf8(headers)
        .map_err(|_| "readiness probe HTTP headers are not UTF-8".to_owned())?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status != "HTTP/1.1 200 OK" && status != "HTTP/1.0 200 OK" {
        return Err(format!("readiness probe returned non-ready status: {status}").into());
    }
    let mut content_length = None;
    let mut content_type = false;
    let mut content_type_seen = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err("readiness probe HTTP header is malformed".to_owned().into());
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("readiness probe has duplicate content length"
                    .to_owned()
                    .into());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "readiness probe content length is invalid".to_owned())?,
            );
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type_seen {
                return Err("readiness probe has duplicate content type"
                    .to_owned()
                    .into());
            }
            content_type_seen = true;
            content_type = value
                .trim()
                .split(';')
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case("application/json"));
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("readiness probe does not accept transfer encoding"
                .to_owned()
                .into());
        }
    }
    let Some(content_length) = content_length else {
        return Err("readiness probe content length is missing"
            .to_owned()
            .into());
    };
    if !content_type {
        return Err("readiness probe HTTP framing is invalid".to_owned().into());
    }
    Ok(content_length)
}

#[cfg(feature = "current-server")]
fn run_current_server(
    path: &Path,
    http_address: SocketAddr,
    grpc_address: SocketAddr,
    reference: bool,
) -> CliResult<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot create server runtime: {error}"))?
        .block_on(serve(path, http_address, grpc_address, reference))
}

#[cfg(feature = "current-server")]
async fn serve(
    path: &Path,
    http_address: SocketAddr,
    grpc_address: SocketAddr,
    reference: bool,
) -> CliResult<()> {
    // Resolve the complete trust configuration before opening any listener.
    // A daemon that cannot authenticate its gateway must never become reachable.
    let gateway = read_gateway_authenticator()?;
    let state = load_state(path)?;
    let http_listener = tokio::net::TcpListener::bind(http_address)
        .await
        .map_err(|error| format!("cannot bind HTTP listener: {error}"))?;
    let grpc_listener = tokio::net::TcpListener::bind(grpc_address)
        .await
        .map_err(|error| format!("cannot bind gRPC listener: {error}"))?;
    let (http_shutdown, http_signal) = tokio::sync::oneshot::channel();
    let (grpc_shutdown, grpc_signal) = tokio::sync::oneshot::channel();
    let (service, health_provider): (Arc<dyn CognitiveMemoryService>, Arc<dyn HealthProvider>) =
        if reference {
            eprintln!("ContextDB development reference profile explicitly selected");
            let service: Arc<dyn CognitiveMemoryService> = Arc::new(DurableService::new(state));
            let summary = HealthSummary::new(
                HealthState::NotReady,
                HealthProfile::DevelopmentReference,
                HealthChecks {
                    service_loaded: true,
                    fjall_verified_at_startup: false,
                    external_head_reconciled: false,
                    publication_available: true,
                },
                Some(HealthReason::DevelopmentReferenceNonproduction),
            )
            .map_err(|error| format!("invalid development health profile: {error}"))?;
            (service, Arc::new(FixedHealthProvider::new(summary)))
        } else {
            let production = Arc::new(ProductionService::open(path, state)?);
            let service: Arc<dyn CognitiveMemoryService> = production.clone();
            let health: Arc<dyn HealthProvider> = production;
            (service, health)
        };
    let http_service = service.clone();
    let grpc_service = service;
    let execution_admission =
        Arc::new(ExecutionAdmission::new(ExecutionAdmissionConfig::default()));
    eprintln!("ContextDB HTTP listening on {http_address}");
    eprintln!("ContextDB gRPC listening on {grpc_address}");
    let http_gateway: Arc<dyn GatewayAuthenticator> = gateway.clone();
    let grpc_gateway: Arc<dyn GatewayAuthenticator> = gateway;
    let http_admission = Arc::clone(&execution_admission);
    let grpc_admission = execution_admission;
    let mut http_task = tokio::spawn(async move {
        serve_http_with_shutdown_gateway_health_and_admission(
            http_listener,
            http_service,
            http_gateway,
            health_provider,
            http_admission,
            async move {
                let _ = http_signal.await;
            },
        )
        .await
        .map_err(|error| CliError::from(format!("HTTP server failed: {error}")))
    });
    let mut grpc_task = tokio::spawn(async move {
        serve_grpc_listener_with_shutdown_gateway_and_admission(
            grpc_listener,
            grpc_service,
            grpc_gateway,
            grpc_admission,
            async move {
                let _ = grpc_signal.await;
            },
        )
        .await
        .map_err(|error| CliError::from(format!("gRPC server failed: {error}")))
    });
    enum Exit {
        Signal(Result<(), std::io::Error>),
        Http(Result<CliResult<()>, tokio::task::JoinError>),
        Grpc(Result<CliResult<()>, tokio::task::JoinError>),
    }
    let exit = tokio::select! {
        signal = tokio::signal::ctrl_c() => Exit::Signal(signal),
        result = &mut http_task => Exit::Http(result),
        result = &mut grpc_task => Exit::Grpc(result),
    };
    let _ = http_shutdown.send(());
    let _ = grpc_shutdown.send(());
    match exit {
        Exit::Signal(result) => {
            result.map_err(|error| format!("cannot listen for shutdown: {error}"))?;
            http_task
                .await
                .map_err(|error| format!("HTTP task failed: {error}"))??;
            grpc_task
                .await
                .map_err(|error| format!("gRPC task failed: {error}"))??;
            Ok(())
        }
        Exit::Http(result) => {
            grpc_task.abort();
            result
                .map_err(|error| format!("HTTP task failed: {error}"))?
                .map_err(|error| format!("HTTP server exited: {error}"))?;
            Err("HTTP server exited unexpectedly".to_owned().into())
        }
        Exit::Grpc(result) => {
            http_task.abort();
            result
                .map_err(|error| format!("gRPC task failed: {error}"))?
                .map_err(|error| format!("gRPC server exited: {error}"))?;
            Err("gRPC server exited unexpectedly".to_owned().into())
        }
    }
}

fn load_production(path: &Path) -> CliResult<Arc<ProductionService>> {
    let state = load_state(path)?;
    ProductionService::open(path, state).map(Arc::new)
}

#[cfg(feature = "current-server")]
fn read_gateway_authenticator() -> CliResult<Arc<Blake3GatewayAuthenticator>> {
    gateway_authenticator_from_values(
        std::env::var_os(GATEWAY_ID_ENV),
        std::env::var_os(GATEWAY_KEY_HEX_ENV),
    )
}

#[cfg(feature = "current-server")]
fn gateway_authenticator_from_values(
    gateway_id: Option<OsString>,
    key_hex: Option<OsString>,
) -> CliResult<Arc<Blake3GatewayAuthenticator>> {
    let gateway_id = gateway_id.ok_or_else(|| {
        CliError::from(format!(
            "a trusted gateway identity is required through {GATEWAY_ID_ENV}"
        ))
    })?;
    let gateway_id = gateway_id
        .into_string()
        .map_err(|_| format!("{GATEWAY_ID_ENV} must be valid Unicode"))?;
    let key_hex = key_hex.ok_or_else(|| {
        CliError::from(format!(
            "a gateway attestation key is required through {GATEWAY_KEY_HEX_ENV}"
        ))
    })?;
    let key_hex = key_hex.into_string().map_err(|_| {
        format!("{GATEWAY_KEY_HEX_ENV} must contain exactly 64 hexadecimal characters")
    })?;
    let key_hex = Zeroizing::new(key_hex);
    let key = parse_token_key_hex(key_hex.as_bytes(), GATEWAY_KEY_HEX_ENV)?;
    Blake3GatewayAuthenticator::new(gateway_id, key.expose_copy())
        .map(Arc::new)
        .map_err(CliError::from)
}

fn load_state(path: &Path) -> CliResult<Arc<LoadedState>> {
    let key = read_external_key(path)?;
    let authority = StateHeadStore::open(path).map_err(CliError::from)?;
    load_state_with_authority(key, authority)
}

#[cfg(test)]
fn load_service_with_key(path: &Path, key: &TokenKey) -> CliResult<Arc<ReferenceService>> {
    let state = load_state_with_key(path, key)?;
    state
        .read()
        .map(|service| service.clone())
        .map_err(CliError::from)
}

#[cfg(test)]
fn load_state_with_key(path: &Path, key: &TokenKey) -> CliResult<Arc<LoadedState>> {
    let authority = StateHeadStore::memory(path).map_err(CliError::from)?;
    let bytes = state_head::read_archive_bounded(path).map_err(CliError::from)?;
    authority
        .adopt_existing_for_test(&key.expose_copy(), &bytes)
        .map_err(CliError::from)?;
    load_state_with_authority(TokenKey::new(key.expose_copy())?, authority)
}

fn load_state_with_authority(
    key: TokenKey,
    authority: StateHeadStore,
) -> CliResult<Arc<LoadedState>> {
    let (bytes, identity) = authority
        .load_verified(&key.expose_copy())
        .map_err(CliError::from)?;
    let service = Arc::new(service_from_archive(
        identity.database_id,
        key.expose_copy(),
        bytes,
        "open",
    )?);
    Ok(Arc::new(LoadedState {
        inner: RwLock::new(service),
        key,
        authority,
        poisoned: AtomicBool::new(false),
    }))
}

fn service_from_archive(
    database_id: String,
    key: [u8; TOKEN_KEY_BYTES],
    bytes: Vec<u8>,
    operation: &str,
) -> CliResult<ReferenceService> {
    let service = ReferenceService::new(database_id, key)?;
    let authority = HostArchiveAuthority::new(key)?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    service
        .import_host_archive(&authority, ARCHIVE_FORMAT, &bytes, &digest)
        .map_err(|error| {
            ServiceError::new(
                error.code,
                format!("{operation}: {}", error.message),
                error.retryable,
            )
        })?;
    Ok(service)
}

fn read_external_key(archive_path: &Path) -> CliResult<TokenKey> {
    let key_hex = std::env::var_os(TOKEN_KEY_HEX_ENV);
    let key_file = std::env::var_os(TOKEN_KEY_FILE_ENV);
    match (key_hex, key_file) {
        (Some(_), Some(_)) => {
            Err(format!("set exactly one of {TOKEN_KEY_HEX_ENV} or {TOKEN_KEY_FILE_ENV}").into())
        }
        (None, None) => Err(format!(
            "an external token key is required through {TOKEN_KEY_HEX_ENV} or {TOKEN_KEY_FILE_ENV}"
        )
        .into()),
        (Some(value), None) => {
            let value = value.into_string().map_err(|_| {
                format!("{TOKEN_KEY_HEX_ENV} must contain exactly 64 hexadecimal characters")
            })?;
            let value = Zeroizing::new(value);
            parse_token_key_hex(value.as_bytes(), TOKEN_KEY_HEX_ENV)
        }
        (None, Some(value)) => read_external_key_file(archive_path, PathBuf::from(value)),
    }
}

fn read_external_key_file(archive_path: &Path, key_path: PathBuf) -> CliResult<TokenKey> {
    #[cfg(windows)]
    {
        let _ = archive_path;
        let _ = key_path;
        Err(format!(
            "{TOKEN_KEY_FILE_ENV} is disabled on Windows because safe DACL and reparse-point custody cannot be proven; inject {TOKEN_KEY_HEX_ENV} from an OS secret store"
        )
        .into())
    }

    #[cfg(unix)]
    {
        if !key_path.is_absolute() {
            return Err(format!("{TOKEN_KEY_FILE_ENV} must be an absolute path").into());
        }
        let supplied_metadata = fs::symlink_metadata(&key_path)
            .map_err(|error| format!("cannot inspect external token key file: {error}"))?;
        if supplied_metadata.file_type().is_symlink() {
            return Err(format!("{TOKEN_KEY_FILE_ENV} cannot name a symbolic link").into());
        }
        let archive_parent = archive_path.parent().unwrap_or_else(|| Path::new("."));
        let data_directory = fs::canonicalize(archive_parent)
            .map_err(|error| format!("cannot resolve state directory: {error}"))?;
        let canonical_key_path = fs::canonicalize(&key_path)
            .map_err(|error| format!("cannot resolve external token key file: {error}"))?;
        if canonical_key_path.starts_with(&data_directory) {
            return Err(format!(
                "{TOKEN_KEY_FILE_ENV} must be outside the ContextDB archive directory"
            )
            .into());
        }
        let bytes = Zeroizing::new(read_unix_key_file_bounded(&canonical_key_path)?);
        let encoded = strip_one_line_ending(bytes.as_slice());
        parse_token_key_hex(encoded, TOKEN_KEY_FILE_ENV)
    }
}

fn ensure_archive_parent(path: &Path) -> CliResult<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create state directory: {error}"))?;
    Ok(())
}

#[cfg(unix)]
fn read_unix_key_file_bounded(path: &Path) -> CliResult<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;

    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("cannot open external token key file: {error}"))?;
    let file = fs::File::from(descriptor);
    let handle_metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect external token key handle: {error}"))?;
    if !handle_metadata.is_file()
        || handle_metadata.nlink() != 1
        || handle_metadata.uid() != rustix::process::geteuid().as_raw()
        || handle_metadata.mode() & 0o077 != 0
        || handle_metadata.len() > 66
    {
        return Err(format!(
            "{TOKEN_KEY_FILE_ENV} must be an owner-only regular file with one link and at most 66 bytes"
        )
        .into());
    }
    let path_metadata = fs::metadata(path)
        .map_err(|error| format!("cannot re-inspect external token key file: {error}"))?;
    if path_metadata.dev() != handle_metadata.dev() || path_metadata.ino() != handle_metadata.ino()
    {
        return Err(format!("{TOKEN_KEY_FILE_ENV} changed identity during validation").into());
    }
    let mut bytes = Vec::with_capacity(66);
    file.take(67)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read external token key file: {error}"))?;
    if bytes.len() > 66 {
        return Err(format!("{TOKEN_KEY_FILE_ENV} exceeds 66 bytes").into());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn strip_one_line_ending(bytes: &[u8]) -> &[u8] {
    if let Some(value) = bytes.strip_suffix(b"\r\n") {
        value
    } else if let Some(value) = bytes.strip_suffix(b"\n") {
        value
    } else {
        bytes
    }
}

fn parse_token_key_hex(bytes: &[u8], source: &str) -> CliResult<TokenKey> {
    if bytes.len() != TOKEN_KEY_BYTES * 2 {
        return Err(format!("{source} must contain exactly 64 hexadecimal characters").into());
    }
    let mut decoded = Zeroizing::new([0_u8; TOKEN_KEY_BYTES]);
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])
            .ok_or_else(|| format!("{source} contains a non-hexadecimal character"))?;
        let low = decode_hex_nibble(pair[1])
            .ok_or_else(|| format!("{source} contains a non-hexadecimal character"))?;
        decoded[index] = (high << 4) | low;
    }
    TokenKey::new(*decoded)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn database_id(path: &Path) -> String {
    format!("contextdb-cli:{}", path.display())
}

fn admin_context(operation: &str) -> RequestContext {
    RequestContext {
        request_id: format!("cli:{operation}"),
        workspace_id: "workspace:local-admin".to_owned(),
        subject_id: "subject:local-admin".to_owned(),
        audiences: Default::default(),
        scopes: Default::default(),
        purpose: "contextdb:admin".to_owned(),
        clearance: Sensitivity::Restricted,
    }
}

#[cfg(feature = "mcp")]
fn create_codex_backup(path: &Path, output: &Path, format: OutputFormat) -> CliResult<()> {
    require_codex_operator_output(format)?;
    if output.exists() {
        return Err(format!("destination already exists: {}", output.display()).into());
    }

    // Loading the externally anchored state and constructing its fixed host
    // authority precede every read from either protected authority.
    let state = load_state(path)?;
    let context = codex_operator_authority(&state.key, "codex-backup")?;
    let service = CodexService::open(path, state)?;
    let response = service.create_backup(CreateBackupRequest { context })?;
    atomic_write(output, &response.bytes, false)?;
    emit_json(
        &CodexBackupReceipt {
            operation: "codex_backup_created",
            state_path: path.display().to_string(),
            backup_path: output.display().to_string(),
            format: &response.format,
            digest: &response.digest,
            commit_seq: response.commit_seq,
            bytes: response.bytes.len(),
            restore_policy: CODEX_BACKUP_RESTORE_POLICY,
        },
        format,
    )
}

#[cfg(feature = "mcp")]
fn restore_codex_backup(path: &Path, input: &Path, format: OutputFormat) -> CliResult<()> {
    require_codex_operator_output(format)?;

    // Authenticate the local host against the anchored lifecycle authority
    // before the untrusted backup file becomes an input or format oracle.
    let state = load_state(path)?;
    let context = codex_operator_authority(&state.key, "codex-restore")?;
    let service = CodexService::open(path, state)?;
    let bytes = read_codex_backup(input)?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    let response = service.restore_backup(RestoreBackupRequest {
        context,
        format: CODEX_BACKUP_FORMAT.to_owned(),
        bytes,
        digest: digest.clone(),
    })?;
    emit_json(
        &CodexRestoreReceipt {
            operation: "codex_backup_restored",
            state_path: path.display().to_string(),
            backup_path: input.display().to_string(),
            format: CODEX_BACKUP_FORMAT,
            digest: &digest,
            restore_policy: CODEX_BACKUP_RESTORE_POLICY,
            response,
        },
        format,
    )
}

#[cfg(feature = "mcp")]
fn require_codex_operator_output(format: OutputFormat) -> CliResult<()> {
    if format == OutputFormat::Protobuf {
        return Err(ServiceError::new(
            ErrorCode::Unsupported,
            "Codex operator recovery receipts have no Protobuf message",
            false,
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "mcp")]
fn read_codex_backup(path: &Path) -> CliResult<Vec<u8>> {
    let file = fs::File::open(path)
        .map_err(|error| format!("cannot open Codex composite backup: {error}"))?;
    let mut bytes = Vec::new();
    file.take((MAX_CODEX_BACKUP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read Codex composite backup: {error}"))?;
    if bytes.len() > MAX_CODEX_BACKUP_BYTES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "Codex composite backup exceeds its bounded size",
            false,
        )
        .into());
    }
    Ok(bytes)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> CliResult<T> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        std::io::stdin()
            .take((contextdb_server::MAX_WIRE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read stdin: {error}"))?;
    } else {
        bytes = fs::read(path).map_err(|error| format!("cannot read request: {error}"))?;
    }
    if bytes.len() > contextdb_server::MAX_WIRE_BYTES {
        return Err("request exceeds the wire size limit".to_owned().into());
    }
    Ok(serde_json::from_slice(&bytes).map_err(|error| format!("invalid request JSON: {error}"))?)
}

fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> CliResult<()> {
    if !replace && path.exists() {
        return Err(format!("destination already exists: {}", path.display()).into());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create state directory: {error}"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create temporary state: {error}"))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| format!("cannot sync temporary state: {error}"))?;
    if replace {
        temporary
            .persist(path)
            .map_err(|error| format!("cannot replace state atomically: {}", error.error))?;
    } else {
        temporary
            .persist_noclobber(path)
            .map_err(|error| format!("cannot install state atomically: {}", error.error))?;
    }
    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync state directory: {error}"))?;
    Ok(())
}

fn emit_state(
    operation: &str,
    path: &Path,
    commit_seq: u64,
    format: OutputFormat,
) -> CliResult<()> {
    if format == OutputFormat::Protobuf {
        return Err("this administrative receipt has no Protobuf message"
            .to_owned()
            .into());
    }
    emit_json(
        &StateReceipt {
            operation,
            path: path.display().to_string(),
            commit_seq,
        },
        format,
    )
}

fn emit_proto<T: Serialize, P: Message>(
    value: &T,
    proto: P,
    format: OutputFormat,
) -> CliResult<()> {
    if format == OutputFormat::Protobuf {
        std::io::stdout()
            .write_all(&proto.encode_to_vec())
            .map_err(|error| format!("cannot write Protobuf response: {error}"))?;
        Ok(())
    } else {
        emit_json(value, format)
    }
}

fn emit_json<T: Serialize>(value: &T, format: OutputFormat) -> CliResult<()> {
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    if format == OutputFormat::Human {
        serde_json::to_writer_pretty(&mut writer, value)
    } else {
        serde_json::to_writer(&mut writer, value)
    }
    .map_err(|error| format!("cannot serialize response: {error}"))?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("cannot write response: {error}"))?;
    Ok(())
}

fn emit_cli_error(error: &CliError, format: OutputFormat) {
    let stderr = std::io::stderr();
    let mut writer = stderr.lock();
    match format {
        OutputFormat::Protobuf => {
            let _ = writer.write_all(&error_to_proto(error.0.clone()).encode_to_vec());
        }
        OutputFormat::Json => {
            let _ = serde_json::to_writer(&mut writer, &error.0);
            let _ = writer.write_all(b"\n");
        }
        OutputFormat::Human => {
            let _ = writeln!(writer, "contextdb: {error}");
        }
    }
}

fn print_version() {
    println!("contextdb {}", env!("CARGO_PKG_VERSION"));
    #[cfg(all(feature = "local-mcp", not(feature = "current-server")))]
    println!("build_profile local-mcp");
    #[cfg(all(feature = "local-mcp", not(feature = "current-server")))]
    println!("network_listeners disabled");
    #[cfg(all(feature = "local-mcp", feature = "current-server"))]
    println!("build_profile mixed-local-mcp-current-server");
    #[cfg(all(feature = "local-mcp", feature = "current-server"))]
    println!("network_listeners enabled");
    println!("wire_schema 1");
    println!("semantic_schema 1");
    println!("storage_format 1");
    println!("context_pack_schema 1");
    #[cfg(feature = "mcp")]
    println!("mcp_protocol {}", contextdb_mcp::MCP_PROTOCOL_VERSION);
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    #[cfg(feature = "current-server")]
    use std::io::{Read as _, Write as _};
    #[cfg(feature = "current-server")]
    use std::net::TcpListener;
    #[cfg(all(feature = "current-server", feature = "mcp"))]
    use std::process::Stdio;
    use std::sync::Arc;

    use clap::{Parser, ValueEnum};
    use contextdb_service::{
        AccessPolicy, CognitiveMemoryService, Consent, ObserveRequest, RequestContext, Sensitivity,
        VerifyRequest,
    };
    #[cfg(all(feature = "current-server", feature = "mcp"))]
    use contextdb_service::{ErrorCode, ServiceError};

    use super::{
        ApiOperation, Cli, Command, DurableService, OutputFormat, TokenKey, init_state_with_key,
        load_service_with_key, load_state_with_key, parse_token_key_hex, read_external_key_file,
    };
    #[cfg(all(feature = "current-server", feature = "mcp"))]
    use super::{GATEWAY_ID_ENV, TOKEN_KEY_FILE_ENV, TOKEN_KEY_HEX_ENV};
    #[cfg(feature = "current-server")]
    use super::{
        GATEWAY_KEY_HEX_ENV, gateway_authenticator_from_values, readiness_snapshot,
        readiness_snapshot_with_timeout,
    };

    const TEST_TOKEN_KEY_HEX: &str =
        "0707070707070707070707070707070707070707070707070707070707070707";

    fn test_token_key() -> TokenKey {
        parse_token_key_hex(TEST_TOKEN_KEY_HEX.as_bytes(), "test token key").expect("test key")
    }

    fn test_observe_request(idempotency_key: &str, observation_id: &str) -> ObserveRequest {
        let context = RequestContext {
            request_id: format!("request:{observation_id}"),
            workspace_id: "workspace:cli".into(),
            subject_id: "subject:alice".into(),
            audiences: BTreeSet::from(["subject:alice".into()]),
            scopes: BTreeSet::from(["project:cli".into()]),
            purpose: "assist".into(),
            clearance: Sensitivity::Private,
        };
        ObserveRequest {
            context,
            idempotency_key: idempotency_key.into(),
            observation_id: observation_id.into(),
            metadata: BTreeMap::new(),
            content: serde_json::json!({"text": "durable yuzu memory"}),
            access: AccessPolicy {
                workspace_id: "workspace:cli".into(),
                scopes: BTreeSet::from(["project:cli".into()]),
                owners: BTreeSet::from(["subject:alice".into()]),
                audience: BTreeSet::from(["subject:alice".into()]),
                audience_purpose_grants: BTreeMap::new(),
                purposes: BTreeSet::from(["assist".into()]),
                sensitivity: Sensitivity::Private,
                consent: Consent::Granted,
                retrievable: true,
            },
        }
    }

    #[test]
    fn parses_version_legacy_demo_and_public_commands() {
        assert!(matches!(
            Cli::try_parse_from(["contextdb", "version"]),
            Ok(Cli {
                command: Command::Version,
                ..
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["contextdb", "init", "--in-memory"]),
            Ok(Cli {
                command: Command::Init {
                    in_memory: true,
                    ..
                },
                ..
            })
        ));
        assert!(
            Cli::try_parse_from([
                "contextdb",
                "--json",
                "recall",
                "memory.ctxb",
                "--request",
                "recall.json"
            ])
            .is_ok()
        );
        #[cfg(feature = "current-server")]
        assert!(matches!(
            Cli::try_parse_from(["contextdb", "probe"]),
            Ok(Cli {
                command: Command::Probe { .. },
                ..
            })
        ));
        assert!(
            Cli::try_parse_from([
                "contextdb",
                "--json",
                "api",
                "memory.ctxb",
                "before-turn",
                "--request",
                "before-turn.json"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "contextdb",
                "api",
                "memory.ctxb",
                "delete-artifact-lineage",
                "--request",
                "delete.json"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "contextdb",
                "api",
                "memory.ctxb",
                "arbitrary-storage-patch",
                "--request",
                "patch.json"
            ])
            .is_err()
        );
        #[cfg(feature = "current-server")]
        assert!(
            Cli::try_parse_from([
                "contextdb",
                "serve",
                "memory.ctxb",
                "--http-listen",
                "127.0.0.1:8000"
            ])
            .is_ok()
        );
        #[cfg(not(feature = "current-server"))]
        assert!(Cli::try_parse_from(["contextdb", "serve", "memory.ctxb"]).is_err());
        #[cfg(feature = "mcp")]
        {
            assert!(Cli::try_parse_from(["contextdb", "mcp", "memory.ctxb"]).is_err());
            assert!(
                Cli::try_parse_from([
                    "contextdb",
                    "mcp",
                    "memory.ctxb",
                    "--actor-id",
                    "actor:alice",
                    "--agent-id",
                    "agent:test",
                    "--workspace-id",
                    "workspace:cli",
                    "--subject-id",
                    "subject:alice",
                    "--purpose",
                    "assist",
                    "--session-id",
                    "session:test",
                    "--audience",
                    "subject:alice",
                    "--scope",
                    "project:cli",
                    "--capability",
                    "runtime",
                    "--capability",
                    "traverse",
                    "--capability",
                    "model-processing",
                    "--clearance",
                    "private"
                ])
                .is_ok()
            );
        }
        #[cfg(not(feature = "mcp"))]
        assert!(Cli::try_parse_from(["contextdb", "mcp", "memory.ctxb"]).is_err());
    }

    #[test]
    fn canonical_high_level_fixture_maps_exactly_to_cli_operations() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../contextdb-conformance/tests/fixtures/high_level_v1_surface.json"
        ))
        .expect("canonical high-level fixture");
        assert_eq!(
            fixture["authentication"],
            "full_authenticated_request_context_gateway_before_content"
        );
        let routes = fixture["http_routes"].as_object().expect("route map");
        assert_eq!(routes.len(), 29);
        let mut mapped = BTreeSet::new();
        for route in routes.values() {
            let operation = route["operation"].as_str().expect("operation");
            let mut kebab = String::new();
            for (index, character) in operation.chars().enumerate() {
                if character.is_ascii_uppercase() && index != 0 {
                    kebab.push('-');
                }
                kebab.push(character.to_ascii_lowercase());
            }
            let parsed = ApiOperation::from_str(&kebab, true)
                .unwrap_or_else(|_| panic!("fixture operation is absent from CLI: {operation}"));
            assert!(
                mapped.insert(parsed),
                "duplicate CLI mapping for {operation}"
            );
        }
        assert_eq!(mapped.len(), 29);
        let expected = BTreeSet::from([
            ApiOperation::BeginSession,
            ApiOperation::BeforeTurn,
            ApiOperation::AfterTurn,
            ApiOperation::ResolveReferent,
            ApiOperation::RecallSharedHistory,
            ApiOperation::EndSession,
            ApiOperation::BootstrapSubject,
            ApiOperation::Remember,
            ApiOperation::Pin,
            ApiOperation::Suppress,
            ApiOperation::ChangeAudience,
            ApiOperation::ChangeRetention,
            ApiOperation::ExplainMemory,
            ApiOperation::ListSubjectMemories,
            ApiOperation::ExportSubject,
            ApiOperation::ImportSubject,
            ApiOperation::CreateMemorySubject,
            ApiOperation::CreateRelationshipSpace,
            ApiOperation::GetContinuityProfile,
            ApiOperation::UpdateConfiguredRole,
            ApiOperation::MigrateAgentRuntime,
            ApiOperation::PublishToSharedMemory,
            ApiOperation::RevokeSharedMemory,
            ApiOperation::IngestArtifact,
            ApiOperation::AttachArtifactToEpisode,
            ApiOperation::AddDerivedRepresentation,
            ApiOperation::AddEvidenceSelector,
            ApiOperation::GetArtifactMetadata,
            ApiOperation::DeleteArtifactLineage,
        ]);
        assert_eq!(mapped, expected);
    }

    #[test]
    fn grouped_api_has_exactly_53_unique_exhaustively_dispatched_names() {
        let variants = ApiOperation::value_variants();
        assert_eq!(variants.len(), 53);
        let names = variants
            .iter()
            .map(|operation| {
                operation
                    .to_possible_value()
                    .expect("API operation name")
                    .get_name()
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), variants.len());
        assert!(names.contains("ingest-frame"));
        assert!(names.contains("migrate-format"));
        assert!(names.contains("compile-context"));
        assert!(names.contains("delete-artifact-lineage"));
    }

    #[test]
    fn acknowledged_cli_service_write_survives_archive_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("memory.ctxb");
        let key = test_token_key();
        init_state_with_key(&path, false, OutputFormat::Json, &key).expect("initialize");
        let state = load_state_with_key(&path, &key).expect("load");
        let service: Arc<dyn CognitiveMemoryService> = Arc::new(DurableService::new(state));
        let request = test_observe_request("idempotency:cli", "observation:cli");
        let first = service
            .observe(request.clone())
            .expect("durable acknowledgement");
        drop(service);

        let reopened = load_service_with_key(&path, &key).expect("reopen");
        let replayed = reopened.observe(request).expect("idempotent replay");
        assert!(replayed.replayed);
        assert_eq!(replayed.commit_seq, first.commit_seq);
        assert_eq!(replayed.request_digest, first.request_digest);
    }

    #[test]
    fn failed_checkpoint_never_publishes_candidate_in_process() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("failpoint.ctxb");
        let key = test_token_key();
        init_state_with_key(&path, false, OutputFormat::Json, &key).expect("initialize");
        let state = load_state_with_key(&path, &key).expect("load");
        state.authority.fail_next_backend_write_for_test();
        let service = DurableService::new(state.clone());
        let request = test_observe_request("idempotency:failpoint", "observation:failpoint");

        assert!(service.observe(request.clone()).is_err());
        let after_failure = service
            .verify(VerifyRequest {
                context: super::admin_context("failpoint-check"),
                deep: false,
            })
            .expect("published service remains readable");
        assert_eq!(after_failure.commit_seq, 0);
        let (disk_bytes, disk_identity) = state
            .authority
            .load_verified(&key.expose_copy())
            .expect("authority remains on trusted pre-image");
        assert_eq!(disk_identity.commit_seq, 0);
        assert_eq!(
            blake3::hash(&disk_bytes).to_hex().to_string(),
            disk_identity.archive_digest
        );

        let retried = service.observe(request).expect("clean retry commits");
        assert_eq!(retried.commit_seq, 1);
        let after_retry = service
            .verify(VerifyRequest {
                context: super::admin_context("failpoint-retry-check"),
                deep: false,
            })
            .expect("committed candidate is published");
        assert_eq!(after_retry.commit_seq, 1);
    }

    #[test]
    fn exact_pending_candidate_is_reconciled_before_acknowledgement() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("pending-recovery.ctxb");
        let key = test_token_key();
        init_state_with_key(&path, false, OutputFormat::Json, &key).expect("initialize");
        let state = load_state_with_key(&path, &key).expect("load");
        state.authority.fail_final_activation_for_test();
        let service = DurableService::new(state.clone());
        let response = service
            .observe(test_observe_request(
                "idempotency:pending-recovery",
                "observation:pending-recovery",
            ))
            .expect("exact pending candidate is a recoverable durable commit");
        assert_eq!(response.commit_seq, 1);
        let current = service
            .verify(VerifyRequest {
                context: super::admin_context("pending-recovery-check"),
                deep: false,
            })
            .expect("recovered candidate is published after authority reconciliation");
        assert_eq!(current.commit_seq, 1);
        let (_, identity) = state
            .authority
            .load_verified(&key.expose_copy())
            .expect("reconciled authority remains valid");
        assert_eq!(identity.commit_seq, 1);
    }

    #[cfg(all(feature = "current-server", feature = "mcp"))]
    #[test]
    fn cli_binary_round_trips_portable_archive_across_processes() {
        let Some(executable) = option_env!("CARGO_BIN_EXE_contextdb") else {
            return;
        };
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("process.ctxb");
        #[cfg(windows)]
        let authority_id = format!(
            "contextdb-cli-test-{}-{}",
            std::process::id(),
            blake3::hash(path.to_string_lossy().as_bytes()).to_hex()
        );
        #[cfg(windows)]
        super::state_head::delete_test_registry_authority(&authority_id)
            .expect("clean stale test authority");
        #[cfg(unix)]
        let authority_directory = tempfile::tempdir().expect("authority directory");
        #[cfg(unix)]
        let authority_path = authority_directory.path().join("process.head");

        let mut init_command = std::process::Command::new(executable);
        init_command
            .args(["--json", "init"])
            .arg(&path)
            .env(TOKEN_KEY_HEX_ENV, TEST_TOKEN_KEY_HEX)
            .env_remove(TOKEN_KEY_FILE_ENV);
        #[cfg(windows)]
        init_command
            .env(super::state_head::STATE_HEAD_ID_ENV, &authority_id)
            .env_remove(super::state_head::STATE_HEAD_FILE_ENV);
        #[cfg(unix)]
        init_command
            .env(super::state_head::STATE_HEAD_FILE_ENV, &authority_path)
            .env_remove(super::state_head::STATE_HEAD_ID_ENV);
        let init = init_command.output().expect("run init");
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let initialized: serde_json::Value =
            serde_json::from_slice(&init.stdout).expect("init JSON");
        assert_eq!(initialized["operation"], "initialized");

        let mut verify_command = std::process::Command::new(executable);
        verify_command
            .args(["--json", "verify"])
            .arg(&path)
            .arg("--deep")
            .env(TOKEN_KEY_HEX_ENV, TEST_TOKEN_KEY_HEX)
            .env_remove(TOKEN_KEY_FILE_ENV);
        #[cfg(windows)]
        verify_command
            .env(super::state_head::STATE_HEAD_ID_ENV, &authority_id)
            .env_remove(super::state_head::STATE_HEAD_FILE_ENV);
        #[cfg(unix)]
        verify_command
            .env(super::state_head::STATE_HEAD_FILE_ENV, &authority_path)
            .env_remove(super::state_head::STATE_HEAD_ID_ENV);
        let verify = verify_command.output().expect("run verify");
        assert!(
            verify.status.success(),
            "{}",
            String::from_utf8_lossy(&verify.stderr)
        );
        let verified: serde_json::Value =
            serde_json::from_slice(&verify.stdout).expect("verify JSON");
        assert_eq!(verified["valid"], true);
        assert!(verified["archive_digest"].as_str().is_some());
        assert!(!path.with_extension("ctxb.key").exists());

        let authenticated = serde_json::json!({
            "request": {
                "request_id": "request:cli-api",
                "workspace_id": "workspace:cli",
                "subject_id": "subject:alice",
                "audiences": ["subject:alice"],
                "scopes": ["project:cli"],
                "purpose": "assist",
                "clearance": "private"
            },
            "actor_id": "actor:alice",
            "agent_id": "agent:cli-test",
            "session_id": "session:cli-test",
            "capability_grants": ["admin"],
            "authentication": {
                "kind": "authenticated_channel",
                "channel_id": "channel:cli-test",
                "peer_identity": "actor:alice",
                "binding_digest": "11".repeat(32)
            }
        });
        let status_request = directory.path().join("status.json");
        std::fs::write(
            &status_request,
            serde_json::to_vec(&serde_json::json!({"context": authenticated.clone()}))
                .expect("status JSON"),
        )
        .expect("status request");
        let mut status_command = std::process::Command::new(executable);
        status_command
            .args(["--json", "api"])
            .arg(&path)
            .args(["get-status", "--request"])
            .arg(&status_request)
            .env(TOKEN_KEY_HEX_ENV, TEST_TOKEN_KEY_HEX)
            .env_remove(TOKEN_KEY_FILE_ENV);
        #[cfg(windows)]
        status_command
            .env(super::state_head::STATE_HEAD_ID_ENV, &authority_id)
            .env_remove(super::state_head::STATE_HEAD_FILE_ENV);
        #[cfg(unix)]
        status_command
            .env(super::state_head::STATE_HEAD_FILE_ENV, &authority_path)
            .env_remove(super::state_head::STATE_HEAD_ID_ENV);
        let status = status_command.output().expect("run authenticated API");
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        let status: serde_json::Value =
            serde_json::from_slice(&status.stdout).expect("status JSON");
        assert_eq!(status["schema_version"], 1);
        assert!(
            status["profile"]
                .as_str()
                .is_some_and(|profile| profile.starts_with("production-fjall-v1"))
        );

        let run_api = |operation: &str, name: &str, request: serde_json::Value| {
            let request_path = directory.path().join(format!("{name}.json"));
            std::fs::write(
                &request_path,
                serde_json::to_vec(&request).expect("API request JSON"),
            )
            .expect("API request file");
            let mut command = std::process::Command::new(executable);
            command
                .args(["--json", "api"])
                .arg(&path)
                .arg(operation)
                .arg("--request")
                .arg(&request_path)
                .env(TOKEN_KEY_HEX_ENV, TEST_TOKEN_KEY_HEX)
                .env_remove(TOKEN_KEY_FILE_ENV);
            #[cfg(windows)]
            command
                .env(super::state_head::STATE_HEAD_ID_ENV, &authority_id)
                .env_remove(super::state_head::STATE_HEAD_FILE_ENV);
            #[cfg(unix)]
            command
                .env(super::state_head::STATE_HEAD_FILE_ENV, &authority_path)
                .env_remove(super::state_head::STATE_HEAD_ID_ENV);
            command.output().expect("run grouped API")
        };

        let mut begin_context = authenticated.clone();
        begin_context["request"]["request_id"] = serde_json::json!("request:begin-session");
        begin_context["capability_grants"] = serde_json::json!(["observe"]);
        let begin = run_api(
            "begin-session",
            "begin-session",
            serde_json::json!({
                "context": begin_context,
                "idempotency_key": "idempotency:begin-session",
                "target_subject_id": "subject:alice",
                "session_id": "session:cli-test",
                "logical_id": "session:cli-test",
                "access": {
                    "workspace_id": "workspace:cli",
                    "scopes": ["project:cli"],
                    "owners": ["subject:alice"],
                    "audience": ["subject:alice"],
                    "audience_purpose_grants": {"subject:alice": ["assist"]},
                    "purposes": [],
                    "sensitivity": "private",
                    "consent": "granted",
                    "retrievable": true
                },
                "payload": {"channel": "test"},
                "references": []
            }),
        );
        assert!(
            begin.status.success(),
            "{}",
            String::from_utf8_lossy(&begin.stderr)
        );
        let begin_json: serde_json::Value =
            serde_json::from_slice(&begin.stdout).expect("begin response JSON");
        assert_eq!(begin_json["operation"], "BeginSession");
        assert_eq!(begin_json["semantic_status"], "pending");

        let mut pin_context = authenticated.clone();
        pin_context["request"]["request_id"] = serde_json::json!("request:pin");
        pin_context["capability_grants"] = serde_json::json!(["correct"]);
        let pin = run_api(
            "pin",
            "pin",
            serde_json::json!({
                "context": pin_context,
                "idempotency_key": "idempotency:pin",
                "target_subject_id": "subject:alice",
                "target_id": "memory:missing",
                "parameters": {}
            }),
        );
        assert!(!pin.status.success());
        let pin_error: ServiceError = serde_json::from_slice(&pin.stderr).expect("typed pin error");
        assert_eq!(pin_error.code, ErrorCode::Unsupported);

        let mut runtime_context = authenticated.clone();
        runtime_context["request"]["request_id"] = serde_json::json!("request:preflight");
        runtime_context["capability_grants"] = serde_json::json!(["runtime"]);
        let preflight = run_api(
            "preflight",
            "preflight",
            serde_json::json!({
                "context": runtime_context,
                "operation_id": "operation:preflight",
                "payload": {"turn": 1}
            }),
        );
        assert!(!preflight.status.success());
        let preflight_error: ServiceError =
            serde_json::from_slice(&preflight.stderr).expect("typed preflight error");
        assert_eq!(preflight_error.code, ErrorCode::FormatIncompatible);
        for bytes in [
            begin.stdout.as_slice(),
            begin.stderr.as_slice(),
            pin.stdout.as_slice(),
            pin.stderr.as_slice(),
            preflight.stdout.as_slice(),
            preflight.stderr.as_slice(),
        ] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(TEST_TOKEN_KEY_HEX));
            assert!(!text.contains(&"11".repeat(32)));
            assert!(!text.contains("binding_digest"));
            assert!(!text.contains("authentication"));
        }

        let meta = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": contextdb_mcp::MCP_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {"name": "cli-test", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        let mut mcp_command = std::process::Command::new(executable);
        mcp_command
            .arg("mcp")
            .arg(&path)
            .args([
                "--actor-id",
                "actor:alice",
                "--agent-id",
                "agent:cli-test",
                "--workspace-id",
                "workspace:cli",
                "--subject-id",
                "subject:alice",
                "--purpose",
                "assist",
                "--session-id",
                "session:cli-test",
                "--audience",
                "subject:alice",
                "--scope",
                "project:cli",
                "--capability",
                "runtime",
                "--clearance",
                "private",
            ])
            .env(TOKEN_KEY_HEX_ENV, TEST_TOKEN_KEY_HEX)
            .env_remove(TOKEN_KEY_FILE_ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        mcp_command
            .env(super::state_head::STATE_HEAD_ID_ENV, &authority_id)
            .env_remove(super::state_head::STATE_HEAD_FILE_ENV);
        #[cfg(unix)]
        mcp_command
            .env(super::state_head::STATE_HEAD_FILE_ENV, &authority_path)
            .env_remove(super::state_head::STATE_HEAD_ID_ENV);
        let mut mcp = mcp_command.spawn().expect("spawn MCP child");
        let mut mcp_stdin = mcp.stdin.take().expect("MCP stdin");
        for request in [
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/list",
                "params": {"_meta": meta}
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "contextdb_preflight",
                    "arguments": {
                        "context": {
                            "request_id": "request:mcp-preflight",
                            "workspace_id": "workspace:cli",
                            "subject_id": "subject:alice",
                            "audiences": ["subject:alice"],
                            "scopes": ["project:cli"],
                            "purpose": "assist",
                            "clearance": "private"
                        },
                        "operation_id": "operation:mcp-preflight",
                        "payload": {"turn": 1}
                    },
                    "_meta": meta
                }
            }),
        ] {
            serde_json::to_writer(&mut mcp_stdin, &request).expect("write MCP JSON");
            mcp_stdin.write_all(b"\n").expect("write MCP newline");
        }
        drop(mcp_stdin);
        let mcp = mcp.wait_with_output().expect("wait for MCP child");
        assert!(
            mcp.status.success(),
            "{}",
            String::from_utf8_lossy(&mcp.stderr)
        );
        let responses = mcp
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<serde_json::Value>(line).expect("MCP response"))
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        let names = responses[0]["result"]["tools"]
            .as_array()
            .expect("MCP tools")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<BTreeSet<_>>();
        assert!(names.contains("contextdb_preflight"));
        assert!(names.contains("contextdb_correct"));
        assert_eq!(responses[1]["result"]["isError"], true);
        assert_eq!(
            responses[1]["result"]["structuredContent"]["code"],
            "format_incompatible"
        );

        let mut missing_gateway = std::process::Command::new(executable);
        missing_gateway
            .arg("serve")
            .arg(&path)
            .args([
                "--http-listen",
                "127.0.0.1:0",
                "--grpc-listen",
                "127.0.0.1:0",
            ])
            .env(TOKEN_KEY_HEX_ENV, TEST_TOKEN_KEY_HEX)
            .env_remove(GATEWAY_ID_ENV)
            .env_remove(GATEWAY_KEY_HEX_ENV);
        #[cfg(windows)]
        missing_gateway.env(super::state_head::STATE_HEAD_ID_ENV, &authority_id);
        #[cfg(unix)]
        missing_gateway.env(super::state_head::STATE_HEAD_FILE_ENV, &authority_path);
        let missing_gateway = missing_gateway.output().expect("run serve without gateway");
        assert!(!missing_gateway.status.success());
        assert!(
            String::from_utf8_lossy(&missing_gateway.stderr).contains(GATEWAY_ID_ENV),
            "{}",
            String::from_utf8_lossy(&missing_gateway.stderr)
        );

        let malformed_gateway = std::process::Command::new(executable)
            .arg("serve")
            .arg(&path)
            .args([
                "--http-listen",
                "127.0.0.1:0",
                "--grpc-listen",
                "127.0.0.1:0",
            ])
            .env(GATEWAY_ID_ENV, "gateway:test")
            .env(GATEWAY_KEY_HEX_ENV, "07")
            .output()
            .expect("run serve with malformed gateway key");
        assert!(!malformed_gateway.status.success());
        assert!(
            String::from_utf8_lossy(&malformed_gateway.stderr).contains(GATEWAY_KEY_HEX_ENV),
            "{}",
            String::from_utf8_lossy(&malformed_gateway.stderr)
        );
        #[cfg(windows)]
        super::state_head::delete_test_registry_authority(&authority_id)
            .expect("remove temporary test authority");
    }

    #[test]
    fn token_key_parser_is_strict_and_redacted() {
        let key = test_token_key();
        assert_eq!(key.expose_copy(), [7; 32]);
        assert!(!format!("{key:?}").contains(TEST_TOKEN_KEY_HEX));
        assert!(parse_token_key_hex(b"07", "test token key").is_err());
        assert!(parse_token_key_hex(&[b'g'; 64], "test token key").is_err());
        assert!(parse_token_key_hex(&[b'0'; 64], "test token key").is_err());
    }

    #[cfg(feature = "current-server")]
    #[test]
    fn gateway_configuration_is_mandatory_strict_and_redacted() {
        assert!(gateway_authenticator_from_values(None, None).is_err());
        assert!(gateway_authenticator_from_values(Some("gateway:test".into()), None).is_err());
        assert!(
            gateway_authenticator_from_values(Some("gateway:test".into()), Some("07".into()))
                .is_err()
        );

        let gateway = gateway_authenticator_from_values(
            Some("gateway:test".into()),
            Some(TEST_TOKEN_KEY_HEX.into()),
        )
        .expect("valid gateway configuration");
        assert_eq!(gateway.gateway_id(), "gateway:test");
        let debug = format!("{gateway:?}");
        assert!(!debug.contains(TEST_TOKEN_KEY_HEX));
        assert!(!debug.contains(GATEWAY_KEY_HEX_ENV));
    }

    #[cfg(unix)]
    #[test]
    fn key_file_must_be_external_and_uses_hex_encoding() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().expect("temporary directory");
        let state_dir = directory.path().join("state");
        std::fs::create_dir_all(&state_dir).expect("state directory");
        let archive = state_dir.join("memory.ctxb");
        let external = directory.path().join("token-key.hex");
        std::fs::write(&external, format!("{TEST_TOKEN_KEY_HEX}\n")).expect("external key");
        std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o600))
            .expect("protect external key");
        let key = read_external_key_file(&archive, external).expect("external key accepted");
        assert_eq!(key.expose_copy(), [7; 32]);

        let forbidden = state_dir.join("token-key.hex");
        std::fs::write(&forbidden, TEST_TOKEN_KEY_HEX).expect("forbidden key fixture");
        std::fs::set_permissions(&forbidden, std::fs::Permissions::from_mode(0o600))
            .expect("protect forbidden key");
        assert!(read_external_key_file(&archive, forbidden).is_err());

        let oversized = directory.path().join("oversized-key.hex");
        std::fs::write(&oversized, vec![b'0'; 67]).expect("oversized key fixture");
        std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600))
            .expect("protect oversized key");
        assert!(read_external_key_file(&archive, oversized).is_err());

        let link = directory.path().join("key-link.hex");
        symlink(directory.path().join("token-key.hex"), &link).expect("key symlink");
        assert!(read_external_key_file(&archive, link).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn key_file_mode_is_unconditionally_disabled_on_windows() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = directory.path().join("memory.ctxb");
        let key_path = directory.path().join("token-key.hex");
        std::fs::write(&key_path, TEST_TOKEN_KEY_HEX).expect("key fixture");
        let error = read_external_key_file(&archive, key_path)
            .expect_err("Windows file-backed keys must fail closed");
        assert!(error.to_string().contains("disabled on Windows"));
    }

    #[cfg(feature = "current-server")]
    #[test]
    fn loopback_probe_requires_exact_bounded_ready_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let expected = contextdb_server::HealthSummary::new(
            contextdb_server::HealthState::Ready,
            contextdb_server::HealthProfile::ProductionFjallV1,
            contextdb_server::HealthChecks {
                service_loaded: true,
                fjall_verified_at_startup: true,
                external_head_reconciled: true,
                publication_available: true,
            },
            None,
        )
        .expect("health summary");
        let body = serde_json::to_vec(&expected).expect("health JSON");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept probe");
            let mut request = [0_u8; 512];
            let read = stream.read(&mut request).expect("read probe");
            assert!(request[..read].starts_with(b"GET /health/ready HTTP/1.1\r\n"));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write headers");
            stream.write_all(&body).expect("write body");
        });
        assert_eq!(readiness_snapshot(address).expect("ready probe"), expected);
        server.join().expect("server thread");

        let duplicate_listener = TcpListener::bind("127.0.0.1:0").expect("duplicate listener");
        let duplicate_address = duplicate_listener.local_addr().expect("duplicate address");
        let duplicate_body = serde_json::to_vec(&expected).expect("duplicate health JSON");
        let duplicate_server = std::thread::spawn(move || {
            let (mut stream, _) = duplicate_listener.accept().expect("accept duplicate probe");
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).expect("read duplicate probe");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                duplicate_body.len(),
                duplicate_body.len()
            )
            .expect("write duplicate headers");
            stream
                .write_all(&duplicate_body)
                .expect("write duplicate body");
        });
        let duplicate_error = readiness_snapshot_with_timeout(
            duplicate_address,
            std::time::Duration::from_millis(250),
        )
        .expect_err("ambiguous duplicate framing must fail");
        assert!(
            duplicate_error
                .to_string()
                .contains("duplicate content length")
        );
        duplicate_server.join().expect("duplicate server thread");

        let drip_listener = TcpListener::bind("127.0.0.1:0").expect("drip listener");
        let drip_address = drip_listener.local_addr().expect("drip address");
        let drip_server = std::thread::spawn(move || {
            let (mut stream, _) = drip_listener.accept().expect("accept drip probe");
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).expect("read drip probe");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n")
                .expect("write drip prefix");
            std::thread::sleep(std::time::Duration::from_millis(100));
            let _ = stream.write_all(b"Content-Type: application/json\r\n");
        });
        let started = std::time::Instant::now();
        let drip_error =
            readiness_snapshot_with_timeout(drip_address, std::time::Duration::from_millis(25))
                .expect_err("slow-drip response must hit one absolute deadline");
        assert!(drip_error.to_string().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_millis(250));
        drip_server.join().expect("drip server thread");

        let non_loopback = "0.0.0.0:7733".parse().expect("address");
        assert!(readiness_snapshot(non_loopback).is_err());
    }
}
