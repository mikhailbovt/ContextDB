use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use contextdb_proto::v1 as wire;
use contextdb_service::{
    CapabilityState, ErrorCode, ExportResponse, StatusResponse, VerifyResponse,
};
use prost::Message;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{AdapterFuture, ConformanceAdapter};
use crate::{
    CanonicalError, CanonicalOperation, CanonicalResponse, CapabilityManifest, ConformanceError,
    InterfaceKind, cli_manifest,
};

/// External CLI proof which cannot be inferred merely from source presence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliExternalProof {
    /// Executable exercised by the proof.
    pub executable: String,
    /// Compact JSON output decoded successfully.
    pub json_decoded: bool,
    /// Protobuf output decoded as the canonical v1 message.
    pub protobuf_decoded: bool,
    /// JSON stderr decoded as the canonical error envelope.
    pub json_error_decoded: bool,
    /// Protobuf stderr decoded as `contextdb.v1.ErrorStatus`.
    pub protobuf_error_decoded: bool,
    /// Exported file bytes match the response digest and payload.
    pub archive_copy_exact: bool,
    /// Authenticated v1 administrative request succeeds through `contextdb api`.
    pub authenticated_api_decoded: bool,
    /// One canonical high-level capture executes through the real subprocess.
    pub high_level_capture_decoded: bool,
    /// A missing high-level policy executor remains a typed business gap.
    pub high_level_gap_typed: bool,
    /// Malformed continuity preflight is returned as a canonical typed format error.
    pub runtime_gap_typed: bool,
    /// The real `contextdb mcp` child advertises the stateless R19 tool surface.
    pub mcp_discovery_decoded: bool,
    /// A real MCP child call preserves the canonical typed preflight format error.
    pub mcp_call_typed: bool,
}

impl CliExternalProof {
    /// True only when every subprocess assertion passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.json_decoded
            && self.protobuf_decoded
            && self.json_error_decoded
            && self.protobuf_error_decoded
            && self.archive_copy_exact
            && self.authenticated_api_decoded
            && self.high_level_capture_decoded
            && self.high_level_gap_typed
            && self.runtime_gap_typed
            && self.mcp_discovery_decoded
            && self.mcp_call_typed
    }
}

/// Black-box CLI adapter. The caller supplies an explicit executable and
/// isolated state/scratch paths; no shell or ambient working directory is used.
#[derive(Clone)]
pub struct CliProcessAdapter {
    executable: PathBuf,
    state_path: PathBuf,
    scratch_dir: PathBuf,
    child_environment: Arc<ChildEnvironment>,
    next_file: u64,
}

impl std::fmt::Debug for CliProcessAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CliProcessAdapter")
            .field("executable", &self.executable)
            .field("state_path", &self.state_path)
            .field("scratch_dir", &self.scratch_dir)
            .field("child_environment", &"[REDACTED]")
            .field("next_file", &self.next_file)
            .finish()
    }
}

impl CliProcessAdapter {
    /// Creates a black-box adapter. This does not initialize state.
    pub fn new(
        executable: impl Into<PathBuf>,
        state_path: impl Into<PathBuf>,
        scratch_dir: impl Into<PathBuf>,
    ) -> Result<Self, ConformanceError> {
        let executable = executable.into();
        let state_path = state_path.into();
        let scratch_dir = scratch_dir.into();
        if !executable.is_file() {
            return Err(ConformanceError::NotExercised(format!(
                "CLI executable does not exist: {}",
                executable.display()
            )));
        }
        std::fs::create_dir_all(&scratch_dir)
            .map_err(|error| ConformanceError::Io(error.to_string()))?;
        let child_environment = Arc::new(ChildEnvironment::new(&state_path)?);
        Ok(Self {
            executable,
            state_path,
            scratch_dir,
            child_environment,
            next_file: 1,
        })
    }

    /// Resolves an executable from `CONTEXTDB_CONFORMANCE_CLI`. Missing env is
    /// represented as `Ok(None)` and must remain visible in the final report.
    pub fn from_env(
        state_path: impl Into<PathBuf>,
        scratch_dir: impl Into<PathBuf>,
    ) -> Result<Option<Self>, ConformanceError> {
        let Some(executable) = std::env::var_os("CONTEXTDB_CONFORMANCE_CLI") else {
            return Ok(None);
        };
        Self::new(PathBuf::from(executable), state_path, scratch_dir).map(Some)
    }

    /// Removes this adapter's exact external authority and lock. Callers that
    /// need cleanup evidence should use this instead of relying on best-effort
    /// process teardown; remaining clones make cleanup fail closed.
    pub fn cleanup_authority(self) -> Result<(), ConformanceError> {
        let environment = Arc::try_unwrap(self.child_environment).map_err(|_| {
            ConformanceError::Io(
                "cannot clean CLI authority while adapter clones still exist".to_owned(),
            )
        })?;
        environment.cleanup()
    }

    /// Initializes an isolated portable database.
    pub fn initialize(&self, force: bool) -> Result<(), ConformanceError> {
        if force {
            return Err(ConformanceError::Protocol(
                "anchored CLI state cannot be force-initialized".to_owned(),
            ));
        }
        let args = vec![
            OsString::from("--json"),
            OsString::from("init"),
            self.state_path.as_os_str().to_owned(),
        ];
        let output = run(&self.executable, &args, &self.child_environment)?;
        ensure_success(output)
            .map(|_| ())
            .map_err(ConformanceError::Protocol)
    }

    /// Installs verified canonical archive bytes through the real CLI import
    /// command. This is the deterministic way to preload semantic fixtures
    /// which cannot be created by the observation gateway alone.
    pub fn install_archive(&mut self, bytes: &[u8]) -> Result<(), ConformanceError> {
        let input = self.next_path("archive-import", "cdb");
        std::fs::write(&input, bytes).map_err(|error| ConformanceError::Io(error.to_string()))?;
        let output = run(
            &self.executable,
            &[
                OsString::from("--json"),
                OsString::from("import"),
                self.state_path.as_os_str().to_owned(),
                input.as_os_str().to_owned(),
            ],
            &self.child_environment,
        )?;
        let _ = std::fs::remove_file(input);
        ensure_success(output)
            .map(|_| ())
            .map_err(ConformanceError::Protocol)
    }

    /// Exercises JSON, Protobuf, and exact archive-copy behavior against the
    /// current state.
    pub fn prove_external_surface(&mut self) -> Result<CliExternalProof, ConformanceError> {
        let json = run(
            &self.executable,
            &[
                OsString::from("--json"),
                OsString::from("verify"),
                self.state_path.as_os_str().to_owned(),
                OsString::from("--deep"),
            ],
            &self.child_environment,
        )?;
        let json_decoded = ensure_success(json)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<VerifyResponse>(&bytes).ok())
            .is_some_and(|response| response.valid);

        let protobuf = run(
            &self.executable,
            &[
                OsString::from("--protobuf"),
                OsString::from("verify"),
                self.state_path.as_os_str().to_owned(),
                OsString::from("--deep"),
            ],
            &self.child_environment,
        )?;
        let protobuf_decoded = ensure_success(protobuf)
            .ok()
            .and_then(|bytes| wire::VerifyResponse::decode(bytes.as_slice()).ok())
            .is_some_and(|response| response.valid);

        let invalid_request = self.next_path("invalid-recall", "json");
        let invalid_json = serde_json::json!({
            "context": {
                "request_id": "request:cli-invalid",
                "workspace_id": "workspace:conformance",
                "subject_id": "subject:alice",
                "audiences": ["subject:alice"],
                "scopes": ["project:conformance"],
                "purpose": "assist",
                "clearance": "private"
            },
            "query": "",
            "page_size": 0,
            "at_commit": null,
            "continuation": null
        });
        std::fs::write(
            &invalid_request,
            serde_json::to_vec(&invalid_json)
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        )
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
        let json_error = run(
            &self.executable,
            &[
                OsString::from("--json"),
                OsString::from("recall"),
                self.state_path.as_os_str().to_owned(),
                OsString::from("--request"),
                invalid_request.as_os_str().to_owned(),
            ],
            &self.child_environment,
        )?;
        let json_error_decoded = !json_error.status.success()
            && serde_json::from_slice::<CanonicalError>(&json_error.stderr)
                .is_ok_and(|error| error.code == ErrorCode::InvalidArgument);
        let protobuf_error = run(
            &self.executable,
            &[
                OsString::from("--protobuf"),
                OsString::from("recall"),
                self.state_path.as_os_str().to_owned(),
                OsString::from("--request"),
                invalid_request.as_os_str().to_owned(),
            ],
            &self.child_environment,
        )?;
        let protobuf_error_decoded = !protobuf_error.status.success()
            && wire::ErrorStatus::decode(protobuf_error.stderr.as_slice())
                .is_ok_and(|error| error.code == wire::ErrorCode::InvalidArgument as i32);
        let _ = std::fs::remove_file(invalid_request);

        let output_path = self.next_path("archive-export", "cdb");
        let export = run(
            &self.executable,
            &[
                OsString::from("--json"),
                OsString::from("export"),
                self.state_path.as_os_str().to_owned(),
                output_path.as_os_str().to_owned(),
            ],
            &self.child_environment,
        )?;
        let response = ensure_success(export)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ExportResponse>(&bytes).ok());
        let archive_copy_exact =
            response
                .zip(std::fs::read(&output_path).ok())
                .is_some_and(|(response, file)| {
                    file == response.bytes
                        && blake3::hash(&file).to_hex().to_string() == response.digest
                });
        let _ = std::fs::remove_file(output_path);

        let status_request = self.next_path("authenticated-status", "json");
        let authenticated_context = serde_json::json!({
            "request": {
                "request_id": "request:cli-status",
                "workspace_id": "workspace:conformance",
                "subject_id": "subject:alice",
                "audiences": ["subject:alice"],
                "scopes": ["project:conformance"],
                "purpose": "assist",
                "clearance": "private"
            },
            "actor_id": "actor:alice",
            "agent_id": "agent:conformance",
            "session_id": "session:conformance",
            "capability_grants": ["admin"],
            "authentication": {
                "kind": "authenticated_channel",
                "channel_id": "channel:conformance",
                "peer_identity": "actor:alice",
                "binding_digest": "11".repeat(32)
            }
        });
        std::fs::write(
            &status_request,
            serde_json::to_vec(&serde_json::json!({"context": authenticated_context}))
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        )
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
        let authenticated_status = run(
            &self.executable,
            &[
                OsString::from("--json"),
                OsString::from("api"),
                self.state_path.as_os_str().to_owned(),
                OsString::from("get-status"),
                OsString::from("--request"),
                status_request.as_os_str().to_owned(),
            ],
            &self.child_environment,
        )?;
        let authenticated_api_decoded = ensure_success(authenticated_status)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<StatusResponse>(&bytes).ok())
            .is_some_and(|status| {
                status.profile.starts_with("production-fjall-v1")
                    && status.schema_version == 1
                    && status.capability_manifest.profile == status.profile
                    && !status.capability_manifest.server_v1_release_ready
                    && status.capability_manifest.capability("status")
                        == Some(CapabilityState::Available)
                    && status
                        .capability_manifest
                        .capability("persistent_ann_recall_projection")
                        == Some(CapabilityState::Unsupported)
            });
        let _ = std::fs::remove_file(status_request);

        let begin_request = self.next_path("begin-session", "json");
        let mut begin_context = authenticated_context.clone();
        begin_context["request"]["request_id"] = serde_json::json!("request:cli-begin");
        begin_context["capability_grants"] = serde_json::json!(["observe"]);
        std::fs::write(
            &begin_request,
            serde_json::to_vec(&serde_json::json!({
                "context": begin_context,
                "idempotency_key": "idempotency:cli-begin",
                "target_subject_id": "subject:alice",
                "session_id": "session:conformance",
                "logical_id": "session:conformance",
                "access": {
                    "workspace_id": "workspace:conformance",
                    "scopes": ["project:conformance"],
                    "owners": ["subject:alice"],
                    "audience": ["subject:alice"],
                    "audience_purpose_grants": {},
                    "purposes": ["assist"],
                    "sensitivity": "private",
                    "consent": "granted",
                    "retrievable": true
                },
                "payload": {"channel": "conformance"},
                "references": []
            }))
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        )
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
        let begin = run(
            &self.executable,
            &[
                OsString::from("--json"),
                OsString::from("api"),
                self.state_path.as_os_str().to_owned(),
                OsString::from("begin-session"),
                OsString::from("--request"),
                begin_request.as_os_str().to_owned(),
            ],
            &self.child_environment,
        )?;
        let high_level_capture_decoded = ensure_success(begin)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|value| {
                value["operation"] == "BeginSession" && value["semantic_status"] == "pending"
            });
        let _ = std::fs::remove_file(begin_request);

        let pin_request = self.next_path("pin-gap", "json");
        let mut pin_context = authenticated_context.clone();
        pin_context["request"]["request_id"] = serde_json::json!("request:cli-pin");
        pin_context["capability_grants"] = serde_json::json!(["correct"]);
        std::fs::write(
            &pin_request,
            serde_json::to_vec(&serde_json::json!({
                "context": pin_context,
                "idempotency_key": "idempotency:cli-pin",
                "target_subject_id": "subject:alice",
                "target_id": "memory:missing",
                "parameters": {}
            }))
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        )
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
        let pin = run(
            &self.executable,
            &[
                OsString::from("--json"),
                OsString::from("api"),
                self.state_path.as_os_str().to_owned(),
                OsString::from("pin"),
                OsString::from("--request"),
                pin_request.as_os_str().to_owned(),
            ],
            &self.child_environment,
        )?;
        let high_level_gap_typed = !pin.status.success()
            && serde_json::from_slice::<CanonicalError>(&pin.stderr)
                .is_ok_and(|error| error.code == ErrorCode::Unsupported)
            && !String::from_utf8_lossy(&pin.stderr).contains("binding_digest")
            && !String::from_utf8_lossy(&pin.stderr).contains("authentication");
        let _ = std::fs::remove_file(pin_request);

        let runtime_request = self.next_path("runtime-gap", "json");
        let mut runtime_context = authenticated_context;
        runtime_context["request"]["request_id"] = serde_json::json!("request:cli-preflight");
        runtime_context["capability_grants"] = serde_json::json!(["runtime"]);
        std::fs::write(
            &runtime_request,
            serde_json::to_vec(&serde_json::json!({
                "context": runtime_context,
                "operation_id": "operation:cli-preflight",
                "payload": {"turn": 1}
            }))
            .map_err(|error| ConformanceError::Protocol(error.to_string()))?,
        )
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
        let runtime = run(
            &self.executable,
            &[
                OsString::from("--json"),
                OsString::from("api"),
                self.state_path.as_os_str().to_owned(),
                OsString::from("preflight"),
                OsString::from("--request"),
                runtime_request.as_os_str().to_owned(),
            ],
            &self.child_environment,
        )?;
        let runtime_gap_typed = !runtime.status.success()
            && serde_json::from_slice::<CanonicalError>(&runtime.stderr)
                .is_ok_and(|error| error.code == ErrorCode::FormatIncompatible);
        let _ = std::fs::remove_file(runtime_request);

        let mcp_meta = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": contextdb_mcp::MCP_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "contextdb-conformance-subprocess",
                "version": env!("CARGO_PKG_VERSION")
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        let discovery = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": mcp_meta}
        });
        let mcp_context = serde_json::json!({
            "request_id": "request:mcp-preflight",
            "workspace_id": "workspace:conformance",
            "subject_id": "subject:alice",
            "audiences": ["subject:alice"],
            "scopes": ["project:conformance"],
            "purpose": "assist",
            "clearance": "private"
        });
        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "contextdb_preflight",
                "arguments": {
                    "context": mcp_context,
                    "operation_id": "operation:mcp-preflight",
                    "payload": {"turn": 1}
                },
                "_meta": mcp_meta
            }
        });
        let initialize = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": contextdb_mcp::MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "contextdb-conformance-subprocess",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        });
        let initialized = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });
        let mcp_output = run_mcp(
            &self.executable,
            &self.state_path,
            &self.child_environment,
            &[initialize, initialized, discovery, mcp_call],
        )?;
        let responses = mcp_output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .collect::<Vec<_>>();
        let discovered = responses
            .iter()
            .find(|response| response["id"] == 1)
            .cloned()
            .unwrap_or_default();
        let called = responses
            .iter()
            .find(|response| response["id"] == 2)
            .cloned()
            .unwrap_or_default();
        let tool_names = discovered["result"]["tools"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect::<std::collections::BTreeSet<_>>();
        let mcp_discovery_decoded = mcp_output.status.success()
            && discovered["result"]["resultType"] == "complete"
            && [
                "contextdb_preflight",
                "contextdb_postflight",
                "contextdb_checkpoint",
                "contextdb_resume",
                "contextdb_handoff",
                "contextdb_ensure_candidate",
            ]
            .into_iter()
            .all(|name| tool_names.contains(name));
        let mcp_call_typed = called["result"]["isError"] == true
            && called["result"]["structuredContent"]["code"] == "format_incompatible"
            && called["result"]["resultType"] == "complete";

        Ok(CliExternalProof {
            executable: self.executable.display().to_string(),
            json_decoded,
            protobuf_decoded,
            json_error_decoded,
            protobuf_error_decoded,
            archive_copy_exact,
            authenticated_api_decoded,
            high_level_capture_decoded,
            high_level_gap_typed,
            runtime_gap_typed,
            mcp_discovery_decoded,
            mcp_call_typed,
        })
    }

    fn next_path(&mut self, stem: &str, extension: &str) -> PathBuf {
        let sequence = self.next_file;
        self.next_file = self.next_file.saturating_add(1);
        self.scratch_dir
            .join(format!("{stem}-{sequence}.{extension}"))
    }
}

fn run_mcp(
    executable: &Path,
    state_path: &Path,
    environment: &ChildEnvironment,
    requests: &[serde_json::Value],
) -> Result<Output, ConformanceError> {
    let mut command = Command::new(executable);
    command
        .arg("mcp")
        .arg(state_path)
        .args([
            "--actor-id",
            "actor:alice",
            "--agent-id",
            "agent:conformance",
            "--workspace-id",
            "workspace:conformance",
            "--subject-id",
            "subject:alice",
            "--purpose",
            "assist",
            "--audience",
            "subject:alice",
            "--scope",
            "project:conformance",
            "--capability",
            "observe",
            "--capability",
            "recall",
            "--capability",
            "read-memory",
            "--capability",
            "correct",
            "--capability",
            "traverse",
            "--capability",
            "model-processing",
            "--capability",
            "runtime",
            "--capability",
            "admin",
            "--clearance",
            "private",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    environment.configure(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
    let cleanup = McpBrokerCleanup::new(executable, state_path, environment);
    let request_result = (|| {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            ConformanceError::Io("MCP subprocess stdin was not created".to_owned())
        })?;
        for request in requests {
            serde_json::to_writer(&mut stdin, request)
                .map_err(|error| ConformanceError::Protocol(error.to_string()))?;
            stdin
                .write_all(b"\n")
                .map_err(|error| ConformanceError::Io(error.to_string()))?;
        }
        Ok::<(), ConformanceError>(())
    })();
    if let Err(error) = request_result {
        let _ = child.wait_with_output();
        return Err(error);
    }
    let output = child
        .wait_with_output()
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
    cleanup.stop_verified()?;
    Ok(output)
}

struct McpBrokerCleanup<'a> {
    executable: &'a Path,
    state_path: &'a Path,
    environment: &'a ChildEnvironment,
    armed: bool,
}

impl<'a> McpBrokerCleanup<'a> {
    fn new(executable: &'a Path, state_path: &'a Path, environment: &'a ChildEnvironment) -> Self {
        Self {
            executable,
            state_path,
            environment,
            armed: cfg!(windows),
        }
    }

    fn stop_verified(mut self) -> Result<(), ConformanceError> {
        let result = stop_mcp_broker(self.executable, self.state_path, self.environment);
        self.armed = result.is_err();
        result
    }
}

impl Drop for McpBrokerCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = stop_mcp_broker(self.executable, self.state_path, self.environment);
        }
    }
}

#[cfg(windows)]
fn stop_mcp_broker(
    executable: &Path,
    state_path: &Path,
    environment: &ChildEnvironment,
) -> Result<(), ConformanceError> {
    let mut command = Command::new(executable);
    command
        .arg("mcp-broker-stop")
        .arg(state_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    environment.configure(&mut command);
    let status = command
        .status()
        .map_err(|error| ConformanceError::Io(error.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(ConformanceError::Protocol(format!(
            "authenticated MCP broker stop exited with {status}"
        )))
    }
}

#[cfg(not(windows))]
fn stop_mcp_broker(
    _executable: &Path,
    _state_path: &Path,
    _environment: &ChildEnvironment,
) -> Result<(), ConformanceError> {
    Ok(())
}

impl ConformanceAdapter for CliProcessAdapter {
    fn interface(&self) -> InterfaceKind {
        InterfaceKind::Cli
    }

    fn manifest(&self) -> CapabilityManifest {
        cli_manifest(true)
    }

    fn invoke(&mut self, operation: CanonicalOperation) -> AdapterFuture<'_> {
        let executable = self.executable.clone();
        let child_environment = Arc::clone(&self.child_environment);
        let state_path = self.state_path.clone();
        let request_path = self.next_path("request", "json");
        let prepared = prepare(&state_path, &request_path, operation);
        Box::pin(async move {
            let (args, kind) = prepared?;
            let output =
                tokio::task::spawn_blocking(move || run(&executable, &args, &child_environment))
                    .await
                    .map_err(|error| ConformanceError::Io(error.to_string()))??;
            let _ = std::fs::remove_file(&request_path);
            match ensure_success(output) {
                Ok(bytes) => Ok(Ok(decode_success(kind, &bytes)?)),
                Err(error) => match parse_cli_error(&error) {
                    Some(error) => Ok(Err(error)),
                    None => Err(ConformanceError::Protocol(error)),
                },
            }
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum ResponseKind {
    Observe,
    Recall,
    Explain,
    Export,
    Import,
    Verify,
}

fn prepare(
    state_path: &Path,
    request_path: &Path,
    operation: CanonicalOperation,
) -> Result<(Vec<OsString>, ResponseKind), ConformanceError> {
    let (command, request, kind) = match operation {
        CanonicalOperation::Observe(request) => (
            "observe",
            serde_json::to_vec(&request),
            ResponseKind::Observe,
        ),
        CanonicalOperation::Recall(request) => {
            ("recall", serde_json::to_vec(&request), ResponseKind::Recall)
        }
        CanonicalOperation::ExplainRecall(request) => (
            "explain",
            serde_json::to_vec(&request),
            ResponseKind::Explain,
        ),
        CanonicalOperation::Verify(request) => {
            let mut args = vec![
                OsString::from("--json"),
                OsString::from("verify"),
                state_path.as_os_str().to_owned(),
            ];
            if request.deep {
                args.push(OsString::from("--deep"));
            }
            return Ok((args, ResponseKind::Verify));
        }
        CanonicalOperation::Export(_) => {
            return Ok((
                vec![
                    OsString::from("--json"),
                    OsString::from("export"),
                    state_path.as_os_str().to_owned(),
                    request_path.as_os_str().to_owned(),
                ],
                ResponseKind::Export,
            ));
        }
        CanonicalOperation::Import(request) => {
            std::fs::write(request_path, request.bytes)
                .map_err(|error| ConformanceError::Io(error.to_string()))?;
            return Ok((
                vec![
                    OsString::from("--json"),
                    OsString::from("import"),
                    state_path.as_os_str().to_owned(),
                    request_path.as_os_str().to_owned(),
                ],
                ResponseKind::Import,
            ));
        }
    };
    let bytes = request.map_err(|error| ConformanceError::Protocol(error.to_string()))?;
    std::fs::write(request_path, bytes).map_err(|error| ConformanceError::Io(error.to_string()))?;
    Ok((
        vec![
            OsString::from("--json"),
            OsString::from(command),
            state_path.as_os_str().to_owned(),
            OsString::from("--request"),
            request_path.as_os_str().to_owned(),
        ],
        kind,
    ))
}

const STATE_HEAD_FILE_ENV: &str = "CONTEXTDB_STATE_HEAD_FILE";
const STATE_HEAD_ID_ENV: &str = "CONTEXTDB_STATE_HEAD_ID";
const TOKEN_KEY_FILE_ENV: &str = "CONTEXTDB_TOKEN_KEY_FILE";
const TOKEN_KEY_HEX_ENV: &str = "CONTEXTDB_TOKEN_KEY_HEX";
static NEXT_AUTHORITY: AtomicU64 = AtomicU64::new(1);

struct ChildEnvironment {
    custody: AuthorityCustody,
}

impl std::fmt::Debug for ChildEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChildEnvironment")
            .field("custody", &"[REDACTED]")
            .finish()
    }
}

enum AuthorityCustody {
    #[cfg(windows)]
    Windows { selector: String },
    #[cfg(unix)]
    Unix { directory: PathBuf, head: PathBuf },
}

impl ChildEnvironment {
    fn new(state_path: &Path) -> Result<Self, ConformanceError> {
        let unique = unique_authority_name(state_path);
        #[cfg(windows)]
        {
            return Ok(Self {
                custody: AuthorityCustody::Windows {
                    selector: format!("conformance-{unique}"),
                },
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            let state_parent = state_path.parent().ok_or_else(|| {
                ConformanceError::Io("CLI state path must have a parent directory".to_owned())
            })?;
            let state_parent = std::fs::canonicalize(state_parent)
                .map_err(|error| ConformanceError::Io(error.to_string()))?;
            let directory =
                std::env::temp_dir().join(format!(".contextdb-conformance-authority-{unique}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|error| ConformanceError::Io(error.to_string()))?;
            if directory.starts_with(&state_parent) {
                let _ = std::fs::remove_dir(&directory);
                return Err(ConformanceError::Io(
                    "cannot place CLI state-head custody outside the archive directory".to_owned(),
                ));
            }
            return Ok(Self {
                custody: AuthorityCustody::Unix {
                    head: directory.join("state-head.json"),
                    directory,
                },
            });
        }
        #[allow(unreachable_code, reason = "ContextDB supports Windows and Unix hosts")]
        Err(ConformanceError::NotExercised(
            "CLI state-head custody is unavailable on this platform".to_owned(),
        ))
    }

    fn configure(&self, command: &mut Command) {
        command
            .env_remove(TOKEN_KEY_FILE_ENV)
            .env_remove(STATE_HEAD_FILE_ENV)
            .env_remove(STATE_HEAD_ID_ENV)
            .env(TOKEN_KEY_HEX_ENV, "51".repeat(32));
        match &self.custody {
            #[cfg(windows)]
            AuthorityCustody::Windows { selector } => {
                command.env(STATE_HEAD_ID_ENV, selector);
            }
            #[cfg(unix)]
            AuthorityCustody::Unix { head, .. } => {
                command.env(STATE_HEAD_FILE_ENV, head);
            }
        }
    }

    fn cleanup(mut self) -> Result<(), ConformanceError> {
        self.custody.cleanup().map_err(ConformanceError::Io)?;
        Ok(())
    }
}

impl Drop for AuthorityCustody {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl AuthorityCustody {
    fn cleanup(&mut self) -> Result<(), String> {
        match self {
            #[cfg(windows)]
            Self::Windows { selector } => cleanup_windows_authority(selector)?,
            #[cfg(unix)]
            Self::Unix { directory, head } => {
                let lock = directory.join(".state-head.json.lock");
                remove_if_present(head)?;
                remove_if_present(&lock)?;
                match std::fs::remove_dir(directory) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("cannot remove authority directory: {error}"));
                    }
                }
            }
        }
        Ok(())
    }
}

fn unique_authority_name(state_path: &Path) -> String {
    let sequence = NEXT_AUTHORITY.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let material = format!(
        "{}:{}:{timestamp}:{sequence}",
        std::process::id(),
        state_path.display()
    );
    blake3::hash(material.as_bytes()).to_hex()[..32].to_owned()
}

#[cfg(windows)]
fn cleanup_windows_authority(selector: &str) -> Result<(), String> {
    let digest = blake3::hash(selector.as_bytes()).to_hex().to_string();
    let key_path = format!("Software\\ContextDB\\StateHeads\\{digest}");
    match winreg::HKCU.delete_subkey_all(key_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot remove exact HKCU authority: {error}")),
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        remove_if_present(
            &PathBuf::from(local)
                .join("ContextDB")
                .join("authority-locks")
                .join(format!("{digest}.lock")),
        )?;
    }
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot remove exact authority artifact: {error}")),
    }
}

fn run(
    executable: &Path,
    args: &[OsString],
    child_environment: &ChildEnvironment,
) -> Result<Output, ConformanceError> {
    let mut command = Command::new(executable);
    command.args(args);
    child_environment.configure(&mut command);
    command
        // The subprocess oracle uses one explicit, deterministic, non-secret
        // fixture key in the child only. It neither depends on nor mutates the
        // caller environment. State-head custody is likewise explicit and
        // external to the portable archive and scratch paths.
        .output()
        .map_err(|error| ConformanceError::Io(error.to_string()))
}

fn ensure_success(output: Output) -> Result<Vec<u8>, String> {
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

fn decode_success(kind: ResponseKind, bytes: &[u8]) -> Result<CanonicalResponse, ConformanceError> {
    match kind {
        ResponseKind::Observe => decode(bytes).map(CanonicalResponse::Observe),
        ResponseKind::Recall => decode(bytes).map(CanonicalResponse::Recall),
        ResponseKind::Explain => decode(bytes).map(CanonicalResponse::ExplainRecall),
        ResponseKind::Export => decode(bytes).map(CanonicalResponse::Export),
        ResponseKind::Import => decode(bytes).map(CanonicalResponse::Import),
        ResponseKind::Verify => decode(bytes).map(CanonicalResponse::Verify),
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ConformanceError> {
    serde_json::from_slice(bytes).map_err(|error| ConformanceError::Protocol(error.to_string()))
}

fn parse_cli_error(stderr: &str) -> Option<CanonicalError> {
    if let Ok(error) = serde_json::from_str::<CanonicalError>(stderr) {
        return Some(error);
    }
    let text = stderr.strip_prefix("contextdb: ").unwrap_or(stderr);
    let (name, message) = text.split_once(": ")?;
    let code = match name {
        "InvalidScope" => ErrorCode::InvalidScope,
        "Unauthorized" => ErrorCode::Unauthorized,
        "AmbiguousIdentity" => ErrorCode::AmbiguousIdentity,
        "SnapshotExpired" => ErrorCode::SnapshotExpired,
        "IndexTooStale" => ErrorCode::IndexTooStale,
        "EvidenceRequired" => ErrorCode::EvidenceRequired,
        "ConflictUnresolved" => ErrorCode::ConflictUnresolved,
        "BudgetExhausted" => ErrorCode::BudgetExhausted,
        "ContinuationExpired" => ErrorCode::ContinuationExpired,
        "FormatIncompatible" => ErrorCode::FormatIncompatible,
        "ProviderUnavailable" => ErrorCode::ProviderUnavailable,
        "DegradedMode" => ErrorCode::DegradedMode,
        "InvalidArgument" => ErrorCode::InvalidArgument,
        "PermissionDenied" => ErrorCode::PermissionDenied,
        "NotFound" => ErrorCode::NotFound,
        "IdempotencyConflict" => ErrorCode::IdempotencyConflict,
        "InvalidContinuation" => ErrorCode::InvalidContinuation,
        "IntegrityFailure" => ErrorCode::IntegrityFailure,
        "Unavailable" => ErrorCode::Unavailable,
        "ResourceExhausted" => ErrorCode::ResourceExhausted,
        "Unsupported" => ErrorCode::Unsupported,
        _ => return None,
    };
    Some(CanonicalError {
        code,
        message: message.to_owned(),
        retryable: matches!(
            code,
            ErrorCode::Unavailable | ErrorCode::ProviderUnavailable | ErrorCode::IndexTooStale
        ),
        partial_result_refs: Box::default(),
        violated_policy: None,
        safe_next_action: None,
        trace_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{AuthorityCustody, ChildEnvironment};

    #[test]
    fn child_environment_debug_redacts_authority() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let environment =
            ChildEnvironment::new(&directory.path().join("state.cdb")).expect("child custody");
        assert_eq!(
            format!("{environment:?}"),
            "ChildEnvironment { custody: \"[REDACTED]\" }"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_custody_drop_removes_only_its_exact_authority_and_lock() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let environment =
            ChildEnvironment::new(&directory.path().join("state.cdb")).expect("child custody");
        let AuthorityCustody::Windows { selector } = &environment.custody;
        let digest = blake3::hash(selector.as_bytes()).to_hex().to_string();
        let key_path = format!("Software\\ContextDB\\StateHeads\\{digest}");
        let (key, _) = winreg::HKCU
            .create_subkey(&key_path)
            .expect("exact test authority");
        key.set_value("authority", &"test-only")
            .expect("test authority value");
        drop(key);

        let local = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA");
        let lock = std::path::PathBuf::from(local)
            .join("ContextDB")
            .join("authority-locks")
            .join(format!("{digest}.lock"));
        std::fs::create_dir_all(lock.parent().expect("lock parent")).expect("lock directory");
        std::fs::write(&lock, b"").expect("test lock");

        environment.cleanup().expect("explicit exact cleanup");
        assert!(winreg::HKCU.open_subkey(&key_path).is_err());
        assert!(!lock.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_custody_is_external_owner_only_and_removed_on_drop() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary state directory");
        let environment =
            ChildEnvironment::new(&directory.path().join("state.cdb")).expect("child custody");
        let AuthorityCustody::Unix {
            directory: authority,
            ..
        } = &environment.custody;
        let authority = authority.clone();
        let metadata = std::fs::metadata(&authority).expect("authority metadata");
        assert_eq!(metadata.permissions().mode() & 0o077, 0);
        assert_eq!(
            metadata.uid(),
            std::fs::metadata(directory.path())
                .expect("state directory metadata")
                .uid()
        );
        assert!(!authority.starts_with(directory.path()));
        environment.cleanup().expect("explicit exact cleanup");
        assert!(!authority.exists());
    }
}
