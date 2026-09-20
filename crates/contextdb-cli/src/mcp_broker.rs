//! Platform-local single-owner broker for concurrent Codex MCP processes.
//!
//! The broker is the only process that opens the state-head and Fjall
//! authorities. Every `contextdb mcp` invocation remains a short-lived stdio
//! adapter and connects to the broker through a local-only Windows named pipe
//! or an owner-only Unix-domain socket. This preserves the exclusive
//! durable-custody locks while allowing independent Codex tasks to share one
//! archive safely.

use std::collections::{BTreeSet, VecDeque};
#[cfg(unix)]
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use contextdb_mcp::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, MAX_MCP_LINE_BYTES, McpServer};
use contextdb_service::{CognitiveMemoryService, ErrorCode, ServiceError};
use serde::{Deserialize, Serialize};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt,
    BufReader as AsyncBufReader,
};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, watch};

use crate::codex_service::CodexService;
use crate::{
    CliError, CliResult, DurableService, McpAuthorityConfig, TokenKey, load_state,
    mcp_session_authority, read_external_key, state_head,
};

#[cfg(unix)]
mod unix_endpoint;
#[cfg(unix)]
use unix_endpoint::EndpointOwner;

const BROKER_SCHEMA_VERSION: u16 = 1;
#[cfg(windows)]
const BROKER_PIPE_PREFIX: &str = r"\\.\pipe\contextdb-mcp-broker-v1-";
const BROKER_HANDSHAKE_CONTEXT: &str = "contextdb/cli/mcp-broker-handshake/v1";
const BROKER_ACK_CONTEXT: &str = "contextdb/cli/mcp-broker-ack/v1";
const MAX_BROKER_HANDSHAKE_BYTES: usize = 64 * 1024;
const MAX_BROKER_ACK_BYTES: usize = 4 * 1024;
const MAX_BROKER_NONCES: usize = 4_096;
const BROKER_START_TIMEOUT: Duration = Duration::from_secs(15);
const BROKER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const BROKER_RETRY_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(unix)]
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;

#[cfg(windows)]
type BrokerListener = NamedPipeServer;
#[cfg(unix)]
type BrokerListener = UnixListener;
#[cfg(windows)]
type BrokerClient = NamedPipeClient;
#[cfg(unix)]
type BrokerClient = UnixStream;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerHandshakePayload {
    schema_version: u16,
    pipe_id: String,
    operation: BrokerOperation,
    reference: bool,
    nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<McpAuthorityConfig>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BrokerOperation {
    Session,
    Shutdown,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerHandshake {
    payload: BrokerHandshakePayload,
    mac: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerAckPayload {
    schema_version: u16,
    accepted: bool,
    handshake_nonce: String,
    pipe_id: String,
    operation: BrokerOperation,
    reference: bool,
    broker_pid: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerAck {
    payload: BrokerAckPayload,
    mac: String,
}

#[derive(Debug, Default)]
struct NonceCache {
    entries: BTreeSet<String>,
    order: VecDeque<String>,
}

impl NonceCache {
    fn admit(&mut self, nonce: &str) -> bool {
        if self.entries.contains(nonce) {
            return false;
        }
        if self.order.len() == MAX_BROKER_NONCES
            && let Some(expired) = self.order.pop_front()
        {
            self.entries.remove(&expired);
        }
        let nonce = nonce.to_owned();
        self.entries.insert(nonce.clone());
        self.order.push_back(nonce);
        true
    }
}

struct BrokerShared {
    pipe_id: String,
    reference: bool,
    key: Arc<TokenKey>,
    service: Arc<dyn CognitiveMemoryService>,
    request_gate: Arc<Mutex<()>>,
    nonce_cache: Arc<Mutex<NonceCache>>,
    shutting_down: Arc<AtomicBool>,
    shutdown_sender: watch::Sender<bool>,
}

/// Runs the persistent single-owner broker. This command is intentionally
/// hidden from normal CLI help and is launched by [`run_proxy`].
pub(crate) fn run_broker(path: &Path, reference: bool) -> CliResult<()> {
    let canonical_path = state_head::canonical_archive_path(path).map_err(CliError::from)?;
    let pipe_id = state_head::path_digest(&canonical_path);
    let pipe_name = endpoint_name(&canonical_path, &pipe_id)?;
    // bind(2) publishes a Unix socket before listen(2) can accept connections.
    // Claim ownership first so another starter cannot mistake that interval
    // for a stale endpoint, unlink it, and connect clients to a losing owner.
    #[cfg(unix)]
    let endpoint_owner = EndpointOwner::claim(&pipe_name).map_err(CliError::from)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::from)?;

    // Claim the deterministic endpoint before opening either durable
    // authority. Racing auto-starts therefore choose one winner without ever
    // contending on the state-head or Fjall locks.
    let first_server = {
        let _runtime = runtime.enter();
        #[cfg(windows)]
        let server = create_server(&pipe_name, true);
        #[cfg(unix)]
        let server = create_server(&pipe_name, &endpoint_owner);
        server.map_err(CliError::from)?
    };
    #[cfg(unix)]
    let socket_cleanup = UnixSocketGuard::new(&pipe_name).map_err(CliError::from)?;
    let state = load_state(&canonical_path)?;
    let handshake_key = Arc::new(TokenKey::new(state.key.expose_copy())?);
    let service: Arc<dyn CognitiveMemoryService> = if reference {
        Arc::new(DurableService::new(state))
    } else {
        Arc::new(CodexService::open(&canonical_path, state)?)
    };

    eprintln!("contextdb MCP broker ready");
    let result = runtime
        .block_on(serve_broker(
            first_server,
            pipe_name,
            pipe_id,
            reference,
            handshake_key,
            service.clone(),
        ))
        .map_err(CliError::from);
    // Quiesce every connection and unlink the endpoint while the durable
    // authority is still held. stop_broker's lock acquisition must not race
    // the socket guard's destructor after an authenticated shutdown.
    drop(runtime);
    #[cfg(unix)]
    drop(socket_cleanup);
    // A successful stop's state-head probe must also imply that a new broker
    // can claim the endpoint. Release its guard before the durable authority.
    #[cfg(unix)]
    drop(endpoint_owner);
    drop(service);
    result
}

/// Connects one stdio MCP session to the persistent broker, starting the
/// broker in a hidden process when no owner is currently available.
pub(crate) fn run_proxy(
    path: &Path,
    reference: bool,
    authority: McpAuthorityConfig,
) -> CliResult<()> {
    let canonical_path = state_head::canonical_archive_path(path).map_err(CliError::from)?;
    let pipe_id = state_head::path_digest(&canonical_path);
    let pipe_name = endpoint_name(&canonical_path, &pipe_id)?;
    let key = read_external_key(&canonical_path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::from)?;

    let client = runtime.block_on(connect_broker(
        &pipe_name,
        Some(|| spawn_hidden_broker(&canonical_path, reference)),
    ))?;
    let handshake = build_handshake(
        &pipe_id,
        BrokerOperation::Session,
        reference,
        Some(authority),
        &key,
    )?;
    runtime.block_on(proxy_session(client, handshake, &key))
}

/// Stops an existing broker after authenticating with the same external token
/// key. An absent broker is already quiesced and is therefore a successful
/// no-op.
pub(crate) fn stop_broker(path: &Path) -> CliResult<()> {
    let canonical_path = state_head::canonical_archive_path(path).map_err(CliError::from)?;
    let pipe_id = state_head::path_digest(&canonical_path);
    let pipe_name = endpoint_name(&canonical_path, &pipe_id)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::from)?;
    let client = match runtime.block_on(open_client(&pipe_name)) {
        Ok(client) => client,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        #[cfg(unix)]
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            if remove_owned_stale_socket(&pipe_name).map_err(CliError::from)? {
                // A crashed owner can leave the filesystem endpoint behind.
                // Removing that exact stale inode is not sufficient evidence
                // for maintenance: also prove that no process still owns the
                // durable state-head authority.
                drop(crate::StateHeadStore::open(&canonical_path).map_err(|_| {
                    unavailable("MCP broker did not quiesce its durable authorities", true)
                })?);
                return Ok(());
            }
            runtime.block_on(wait_for_broker(&pipe_name))?
        }
        Err(_) => runtime.block_on(wait_for_broker(&pipe_name))?,
    };
    let key = read_external_key(&canonical_path)?;
    let handshake = build_handshake(&pipe_id, BrokerOperation::Shutdown, false, None, &key)?;
    runtime.block_on(stop_session(client, handshake, &key))?;
    // Do not return merely because the shutdown acknowledgement was flushed.
    // Successfully taking and releasing the exact state-head lock proves the
    // owner process dropped both hybrid authorities before operator work
    // continues.
    drop(
        crate::StateHeadStore::open(&canonical_path)
            .map_err(|_| unavailable("MCP broker did not quiesce its durable authorities", true))?,
    );
    Ok(())
}

#[cfg(windows)]
async fn serve_broker(
    mut listener: BrokerListener,
    pipe_name: String,
    pipe_id: String,
    reference: bool,
    key: Arc<TokenKey>,
    service: Arc<dyn CognitiveMemoryService>,
) -> io::Result<()> {
    let (shared, mut shutdown_receiver) = broker_shared(pipe_id, reference, key, service);
    loop {
        tokio::select! {
            changed = shutdown_receiver.changed() => {
                if changed.is_err() || *shutdown_receiver.borrow() {
                    return Ok(());
                }
                continue;
            }
            connected = listener.connect() => connected?,
        }
        let connected = listener;
        // Keep a listening instance available before dispatching the accepted
        // client, as required by Windows named-pipe connection semantics.
        listener = create_server(&pipe_name, false)?;
        let connection_shared = shared.clone();
        tokio::spawn(async move {
            let _ = serve_connection(connected, connection_shared).await;
        });
    }
}

#[cfg(unix)]
async fn serve_broker(
    listener: BrokerListener,
    _pipe_name: String,
    pipe_id: String,
    reference: bool,
    key: Arc<TokenKey>,
    service: Arc<dyn CognitiveMemoryService>,
) -> io::Result<()> {
    let (shared, mut shutdown_receiver) = broker_shared(pipe_id, reference, key, service);
    loop {
        tokio::select! {
            changed = shutdown_receiver.changed() => {
                if changed.is_err() || *shutdown_receiver.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (connection, _) = accepted?;
                let connection_shared = shared.clone();
                tokio::spawn(async move {
                    let _ = serve_connection(connection, connection_shared).await;
                });
            }
        }
    }
}

fn broker_shared(
    pipe_id: String,
    reference: bool,
    key: Arc<TokenKey>,
    service: Arc<dyn CognitiveMemoryService>,
) -> (Arc<BrokerShared>, watch::Receiver<bool>) {
    let request_gate = Arc::new(Mutex::new(()));
    let nonce_cache = Arc::new(Mutex::new(NonceCache::default()));
    let shutting_down = Arc::new(AtomicBool::new(false));
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let shared = Arc::new(BrokerShared {
        pipe_id,
        reference,
        key,
        service,
        request_gate,
        nonce_cache,
        shutting_down,
        shutdown_sender,
    });
    (shared, shutdown_receiver)
}

async fn serve_connection<S>(pipe: S, shared: Arc<BrokerShared>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = AsyncBufReader::new(reader);
    let Some(frame) = read_broker_control_frame(&mut reader, MAX_BROKER_HANDSHAKE_BYTES).await?
    else {
        return Ok(());
    };
    let handshake = frame
        .ok()
        .and_then(|bytes| serde_json::from_slice::<BrokerHandshake>(&bytes).ok());
    let Some(handshake) = handshake else {
        return Ok(());
    };
    if !verify_handshake(&handshake, &shared.pipe_id, shared.reference, &shared.key) {
        return Ok(());
    }
    if !shared
        .nonce_cache
        .lock()
        .await
        .admit(&handshake.payload.nonce)
    {
        return Ok(());
    }
    if handshake.payload.operation == BrokerOperation::Shutdown {
        let _serial = shared.request_gate.lock().await;
        shared.shutting_down.store(true, Ordering::Release);
        write_ack(&mut writer, &handshake.payload, true, &shared.key).await?;
        let _ = shared.shutdown_sender.send(true);
        return Ok(());
    }
    let Some(authority_config) = handshake.payload.authority.clone() else {
        write_ack(&mut writer, &handshake.payload, false, &shared.key).await?;
        return Ok(());
    };
    let authority = match mcp_session_authority(&shared.key, authority_config) {
        Ok(authority) => authority,
        Err(_) => {
            write_ack(&mut writer, &handshake.payload, false, &shared.key).await?;
            return Ok(());
        }
    };
    let mut server =
        match McpServer::with_fixed_session_authority(shared.service.clone(), authority) {
            Ok(server) => server,
            Err(_) => {
                write_ack(&mut writer, &handshake.payload, false, &shared.key).await?;
                return Ok(());
            }
        };
    write_ack(&mut writer, &handshake.payload, true, &shared.key).await?;

    while let Some(frame) = read_async_frame(&mut reader, MAX_MCP_LINE_BYTES).await? {
        let response = {
            // Tokio's mutex is FIFO. Holding one gate across decode + handle
            // gives every client one global JSON-RPC execution order while
            // each connection retains its own MCP trace cache and authority.
            let _serial = shared.request_gate.lock().await;
            if shared.shutting_down.load(Ordering::Acquire) {
                return Ok(());
            }
            match frame {
                Ok(bytes) => match serde_json::from_slice::<JsonRpcRequest>(strip_utf8_bom(&bytes))
                {
                    Ok(request) if request.is_notification() => None,
                    Ok(request) => Some(server.handle(request)),
                    Err(_) => Some(protocol_error(-32700, "invalid JSON-RPC JSON")),
                },
                Err(()) => Some(protocol_error(-32600, "MCP frame exceeds size limit")),
            }
        };
        if let Some(response) = response {
            write_response(&mut writer, response).await?;
        }
    }
    Ok(())
}

async fn stop_session(
    client: BrokerClient,
    handshake: BrokerHandshake,
    key: &TokenKey,
) -> CliResult<()> {
    let (reader, mut writer) = tokio::io::split(client);
    let mut reader = AsyncBufReader::new(reader);
    let bytes = serde_json::to_vec(&handshake)
        .map_err(|_| unavailable("cannot encode the bounded MCP broker handshake", false))?;
    if bytes.len() > MAX_BROKER_HANDSHAKE_BYTES {
        return Err(unavailable(
            "MCP broker handshake exceeds its size limit",
            false,
        ));
    }
    writer.write_all(&bytes).await.map_err(CliError::from)?;
    writer.write_all(b"\n").await.map_err(CliError::from)?;
    writer.flush().await.map_err(CliError::from)?;
    let ack = read_broker_control_frame(&mut reader, MAX_BROKER_ACK_BYTES)
        .await
        .map_err(CliError::from)?
        .and_then(Result::ok)
        .and_then(|frame| serde_json::from_slice::<BrokerAck>(&frame).ok())
        .ok_or_else(|| unavailable("MCP broker rejected the shutdown request", false))?;
    if !verify_ack(&ack, &handshake.payload, key) || !ack.payload.accepted {
        return Err(unavailable(
            "MCP broker failed mutual authentication for shutdown",
            false,
        ));
    }
    Ok(())
}

async fn proxy_session(
    client: BrokerClient,
    handshake: BrokerHandshake,
    key: &TokenKey,
) -> CliResult<()> {
    let (reader, mut writer) = tokio::io::split(client);
    let mut reader = AsyncBufReader::new(reader);
    let handshake_bytes = serde_json::to_vec(&handshake)
        .map_err(|_| unavailable("cannot encode the bounded MCP broker handshake", false))?;
    if handshake_bytes.len() > MAX_BROKER_HANDSHAKE_BYTES {
        return Err(unavailable(
            "MCP broker handshake exceeds its size limit",
            false,
        ));
    }
    writer
        .write_all(&handshake_bytes)
        .await
        .map_err(CliError::from)?;
    writer.write_all(b"\n").await.map_err(CliError::from)?;
    writer.flush().await.map_err(CliError::from)?;

    let ack = read_broker_control_frame(&mut reader, MAX_BROKER_ACK_BYTES)
        .await
        .map_err(CliError::from)?
        .and_then(Result::ok)
        .and_then(|bytes| serde_json::from_slice::<BrokerAck>(&bytes).ok())
        .ok_or_else(|| unavailable("MCP broker rejected the authenticated session", false))?;
    if !verify_ack(&ack, &handshake.payload, key) || !ack.payload.accepted {
        return Err(unavailable(
            "MCP broker failed mutual authentication",
            false,
        ));
    }
    let _broker_pid = ack.payload.broker_pid;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();
    while let Some(frame) = read_sync_frame(&mut stdin, MAX_MCP_LINE_BYTES)? {
        let bytes = match frame {
            Ok(bytes) => bytes,
            Err(()) => {
                write_sync_response(
                    &mut stdout,
                    &protocol_error(-32600, "MCP frame exceeds size limit"),
                )?;
                continue;
            }
        };
        let bytes = strip_utf8_bom(&bytes);
        if serde_json::from_slice::<JsonRpcRequest>(bytes)
            .is_ok_and(|request| request.is_notification())
        {
            continue;
        }
        writer.write_all(bytes).await.map_err(CliError::from)?;
        writer.write_all(b"\n").await.map_err(CliError::from)?;
        writer.flush().await.map_err(CliError::from)?;
        let response = read_async_frame(&mut reader, MAX_MCP_LINE_BYTES)
            .await
            .map_err(CliError::from)?
            .ok_or_else(|| unavailable("MCP broker disconnected before responding", true))?
            .map_err(|()| unavailable("MCP broker response exceeds its size limit", false))?;
        stdout.write_all(&response).map_err(CliError::from)?;
        stdout.write_all(b"\n").map_err(CliError::from)?;
        stdout.flush().map_err(CliError::from)?;
    }
    Ok(())
}

fn build_handshake(
    pipe_id: &str,
    operation: BrokerOperation,
    reference: bool,
    authority: Option<McpAuthorityConfig>,
    key: &TokenKey,
) -> CliResult<BrokerHandshake> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random)
        .map_err(|_| unavailable("cannot generate an MCP broker session nonce", true))?;
    let payload = BrokerHandshakePayload {
        schema_version: BROKER_SCHEMA_VERSION,
        pipe_id: pipe_id.to_owned(),
        operation,
        reference,
        nonce: blake3::hash(&random).to_hex().to_string(),
        authority,
    };
    let mac = handshake_mac(&payload, key)?;
    Ok(BrokerHandshake { payload, mac })
}

fn verify_handshake(
    handshake: &BrokerHandshake,
    pipe_id: &str,
    reference: bool,
    key: &TokenKey,
) -> bool {
    if handshake.payload.schema_version != BROKER_SCHEMA_VERSION
        || handshake.payload.pipe_id != pipe_id
        || handshake.payload.nonce.len() != 64
        || blake3::Hash::from_hex(&handshake.payload.nonce).is_err()
        || (handshake.payload.operation == BrokerOperation::Session
            && (handshake.payload.reference != reference || handshake.payload.authority.is_none()))
        || (handshake.payload.operation == BrokerOperation::Shutdown
            && handshake.payload.authority.is_some())
    {
        return false;
    }
    let Ok(expected) = handshake_mac(&handshake.payload, key) else {
        return false;
    };
    let (Ok(expected), Ok(candidate)) = (
        blake3::Hash::from_hex(expected),
        blake3::Hash::from_hex(&handshake.mac),
    ) else {
        return false;
    };
    expected == candidate
}

fn handshake_mac(payload: &BrokerHandshakePayload, key: &TokenKey) -> CliResult<String> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|_| unavailable("cannot encode the MCP broker handshake payload", false))?;
    if bytes.len() > MAX_BROKER_HANDSHAKE_BYTES {
        return Err(unavailable(
            "MCP broker handshake exceeds its size limit",
            false,
        ));
    }
    let mac_key = blake3::derive_key(BROKER_HANDSHAKE_CONTEXT, &key.expose_copy());
    Ok(blake3::keyed_hash(&mac_key, &bytes).to_hex().to_string())
}

async fn write_ack<W: AsyncWrite + Unpin>(
    writer: &mut W,
    handshake: &BrokerHandshakePayload,
    accepted: bool,
    key: &TokenKey,
) -> io::Result<()> {
    let payload = BrokerAckPayload {
        schema_version: BROKER_SCHEMA_VERSION,
        accepted,
        handshake_nonce: handshake.nonce.clone(),
        pipe_id: handshake.pipe_id.clone(),
        operation: handshake.operation,
        reference: handshake.reference,
        broker_pid: std::process::id(),
    };
    let mac = ack_mac(&payload, key).map_err(|_| io::Error::other("cannot authenticate ACK"))?;
    let ack = BrokerAck { payload, mac };
    let bytes = serde_json::to_vec(&ack).map_err(io::Error::other)?;
    writer.write_all(&bytes).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

fn ack_mac(payload: &BrokerAckPayload, key: &TokenKey) -> CliResult<String> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|_| unavailable("cannot encode the MCP broker ACK payload", false))?;
    if bytes.len() > MAX_BROKER_ACK_BYTES {
        return Err(unavailable("MCP broker ACK exceeds its size limit", false));
    }
    let mac_key = blake3::derive_key(BROKER_ACK_CONTEXT, &key.expose_copy());
    Ok(blake3::keyed_hash(&mac_key, &bytes).to_hex().to_string())
}

fn verify_ack(ack: &BrokerAck, handshake: &BrokerHandshakePayload, key: &TokenKey) -> bool {
    if ack.payload.schema_version != BROKER_SCHEMA_VERSION
        || ack.payload.handshake_nonce != handshake.nonce
        || ack.payload.pipe_id != handshake.pipe_id
        || ack.payload.operation != handshake.operation
        || ack.payload.reference != handshake.reference
        || ack.payload.broker_pid == 0
    {
        return false;
    }
    let Ok(expected) = ack_mac(&ack.payload, key) else {
        return false;
    };
    let (Ok(expected), Ok(candidate)) = (
        blake3::Hash::from_hex(expected),
        blake3::Hash::from_hex(&ack.mac),
    ) else {
        return false;
    };
    expected == candidate
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut response: JsonRpcResponse,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
    if bytes.len() > MAX_MCP_LINE_BYTES {
        response = JsonRpcResponse {
            jsonrpc: "2.0".to_owned(),
            id: response.id,
            result: None,
            error: Some(JsonRpcError {
                code: -32603,
                message: "MCP response exceeds size limit".to_owned(),
            }),
        };
        bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
    }
    writer.write_all(&bytes).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

fn write_sync_response(writer: &mut impl Write, response: &JsonRpcResponse) -> CliResult<()> {
    serde_json::to_writer(&mut *writer, response)
        .map_err(|error| unavailable(format!("cannot encode MCP response: {error}"), false))?;
    writer.write_all(b"\n").map_err(CliError::from)?;
    writer.flush().map_err(CliError::from)
}

fn protocol_error(code: i32, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_owned(),
        id: serde_json::Value::Null,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_owned(),
        }),
    }
}

#[cfg(windows)]
fn create_server(pipe_name: &str, first: bool) -> io::Result<BrokerListener> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    options.create(pipe_name)
}

#[cfg(unix)]
fn create_server(socket_name: &str, _owner: &EndpointOwner) -> io::Result<BrokerListener> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    match fs::symlink_metadata(socket_name) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "MCP broker socket path is occupied by an untrusted entry",
                ));
            }
            match std::os::unix::net::UnixStream::connect(socket_name) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "an MCP broker already owns the Unix-domain socket",
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    fs::remove_file(socket_name)?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let listener = UnixListener::bind(socket_name)?;
    if let Err(error) = fs::set_permissions(socket_name, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(socket_name);
        return Err(error);
    }
    Ok(listener)
}

#[cfg(windows)]
async fn open_client(pipe_name: &str) -> io::Result<BrokerClient> {
    ClientOptions::new().open(pipe_name)
}

#[cfg(unix)]
async fn open_client(socket_name: &str) -> io::Result<BrokerClient> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = fs::symlink_metadata(socket_name)?;
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "MCP broker socket must be owned by the current user and owner-only",
        ));
    }
    // bind creates the entry before create_server can chmod it. Wait without
    // connecting until the current owner has finished restricting its socket.
    if metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "MCP broker socket is awaiting owner-only permissions",
        ));
    }
    UnixStream::connect(socket_name).await
}

#[cfg(unix)]
fn remove_owned_stale_socket(socket_name: &str) -> io::Result<bool> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let _owner = match EndpointOwner::claim(socket_name) {
        Ok(owner) => owner,
        // A live owner may be between bind/listen or listener drop/unlink.
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(error) => return Err(error),
    };
    let original = match fs::symlink_metadata(socket_name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error),
    };
    if !original.file_type().is_socket()
        || original.uid() != rustix::process::geteuid().as_raw()
        || original.mode() & 0o077 != 0
        || original.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stale MCP broker endpoint must be an owner-only, singly linked Unix socket",
        ));
    }
    let device = original.dev();
    let inode = original.ino();

    match std::os::unix::net::UnixStream::connect(socket_name) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(error),
    }

    let current = match fs::symlink_metadata(socket_name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error),
    };
    if !current.file_type().is_socket()
        || current.uid() != rustix::process::geteuid().as_raw()
        || current.mode() & 0o077 != 0
        || current.nlink() != 1
        || current.dev() != device
        || current.ino() != inode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stale MCP broker endpoint changed identity during guarded cleanup",
        ));
    }
    fs::remove_file(socket_name)?;
    Ok(true)
}

async fn connect_broker<F>(pipe_name: &str, mut start: Option<F>) -> CliResult<BrokerClient>
where
    F: FnOnce() -> CliResult<()>,
{
    let started = Instant::now();
    loop {
        let error = match open_client(pipe_name).await {
            Ok(client) => return Ok(client),
            Err(error) => error,
        };
        let absent = error.kind() == io::ErrorKind::NotFound
            || (cfg!(unix) && error.kind() == io::ErrorKind::ConnectionRefused);
        // ERROR_PIPE_BUSY means a live owner has no available instance yet.
        // Starting another process here can leave a delayed contender that
        // claims the endpoint after the original owner's authenticated stop.
        let busy = error.kind() == io::ErrorKind::WouldBlock
            || (cfg!(windows) && error.raw_os_error() == Some(231));
        if !absent && !busy && error.kind() != io::ErrorKind::Interrupted {
            return Err(CliError::from(error));
        }
        if absent && let Some(start) = start.take() {
            start()?;
        }
        if started.elapsed() >= BROKER_START_TIMEOUT {
            return Err(unavailable(
                "MCP broker did not become ready before the startup deadline",
                true,
            ));
        }
        tokio::time::sleep(BROKER_RETRY_INTERVAL).await;
    }
}

async fn wait_for_broker(pipe_name: &str) -> CliResult<BrokerClient> {
    connect_broker::<fn() -> CliResult<()>>(pipe_name, None).await
}

#[cfg(windows)]
fn spawn_hidden_broker(path: &Path, reference: bool) -> CliResult<()> {
    use std::os::windows::process::CommandExt;

    let executable = std::env::current_exe()
        .map_err(|_| unavailable("cannot resolve the ContextDB executable", false))?;
    // A directly spawned persistent grandchild inherits any inheritable stdio
    // handles that the MCP proxy itself received from Codex. That keeps the
    // proxy's captured stdout pipe open forever after the proxy exits. Use the
    // Windows shell's detached Start-Process path through a short-lived hidden
    // launcher, wait for that launcher, and pass trusted paths only through
    // task-specific environment variables rather than interpolated script.
    const START_SCRIPT: &str = concat!(
        "$ErrorActionPreference='Stop';",
        "$brokerExecutable=$env:CONTEXTDB_BROKER_EXECUTABLE_PATH;",
        "$brokerArchive=$env:CONTEXTDB_BROKER_ARCHIVE_PATH;",
        "$brokerReference=$env:CONTEXTDB_BROKER_REFERENCE_MODE;",
        "Remove-Item Env:CONTEXTDB_BROKER_EXECUTABLE_PATH -ErrorAction SilentlyContinue;",
        "Remove-Item Env:CONTEXTDB_BROKER_ARCHIVE_PATH -ErrorAction SilentlyContinue;",
        "Remove-Item Env:CONTEXTDB_BROKER_REFERENCE_MODE -ErrorAction SilentlyContinue;",
        "$quotedArchive='\"'+$brokerArchive+'\"';",
        "$brokerArgs=@('mcp-broker',$quotedArchive);",
        "if($brokerReference -eq '1'){$brokerArgs+='--reference'};",
        "Start-Process -FilePath $brokerExecutable ",
        "-ArgumentList $brokerArgs -WindowStyle Hidden | Out-Null"
    );
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            START_SCRIPT,
        ])
        .env("CONTEXTDB_BROKER_EXECUTABLE_PATH", executable)
        .env("CONTEXTDB_BROKER_ARCHIVE_PATH", path)
        .env(
            "CONTEXTDB_BROKER_REFERENCE_MODE",
            if reference { "1" } else { "0" },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    let status = command
        .status()
        .map_err(|_| unavailable("cannot run the hidden MCP broker launcher", true))?;
    if !status.success() {
        return Err(unavailable(
            "hidden MCP broker launcher exited unsuccessfully",
            true,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn spawn_hidden_broker(path: &Path, reference: bool) -> CliResult<()> {
    let executable = std::env::current_exe()
        .map_err(|_| unavailable("cannot resolve the ContextDB executable", false))?;
    let mut command = Command::new(executable);
    command
        .arg("mcp-broker")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if reference {
        command.arg("--reference");
    }
    command
        .spawn()
        .map_err(|_| unavailable("cannot start the local Unix MCP broker", true))?;
    Ok(())
}

#[cfg(windows)]
fn endpoint_name(_archive_path: &Path, pipe_id: &str) -> CliResult<String> {
    Ok(format!("{BROKER_PIPE_PREFIX}{pipe_id}"))
}

#[cfg(unix)]
fn endpoint_name(archive_path: &Path, pipe_id: &str) -> CliResult<String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let authority = std::env::var_os(state_head::STATE_HEAD_FILE_ENV).ok_or_else(|| {
        unavailable(
            "an external state-head authority is required for the local Unix MCP broker",
            false,
        )
    })?;
    let authority = Path::new(&authority);
    if !authority.is_absolute() {
        return Err(unavailable(
            "Unix MCP broker requires an absolute external state-head authority path",
            false,
        ));
    }
    let parent = authority.parent().ok_or_else(|| {
        unavailable(
            "Unix MCP broker state-head authority must have a parent directory",
            false,
        )
    })?;
    let parent = fs::canonicalize(parent).map_err(CliError::from)?;
    let metadata = fs::metadata(&parent).map_err(CliError::from)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(unavailable(
            "Unix MCP broker authority directory must be owned by the current user and not group/world writable",
            false,
        ));
    }
    if archive_path
        .parent()
        .is_some_and(|directory| parent == directory)
    {
        return Err(unavailable(
            "Unix MCP broker socket directory must remain outside the archive directory",
            false,
        ));
    }
    let broker_directory = unix_broker_directory(pipe_id)?;
    if archive_path.parent().is_some_and(|directory| {
        broker_directory.starts_with(directory) || directory.starts_with(&broker_directory)
    }) {
        return Err(unavailable(
            "Unix MCP broker runtime directory must remain outside the archive directory",
            false,
        ));
    }
    let socket = broker_directory.join(format!("{}.sock", &pipe_id[..24]));
    if socket.as_os_str().as_bytes().len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(unavailable(
            "Unix MCP broker socket path exceeds the platform limit in the protected runtime directory",
            false,
        ));
    }
    socket
        .into_os_string()
        .into_string()
        .map_err(|_| unavailable("Unix MCP broker socket path must be valid UTF-8", false))
}

#[cfg(unix)]
fn unix_broker_directory(pipe_id: &str) -> CliResult<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let socket_name = format!("{}.sock", &pipe_id[..24]);
    if let Some(runtime_root) = std::env::var_os("XDG_RUNTIME_DIR")
        .as_deref()
        .and_then(validated_owner_runtime_root)
    {
        let broker_directory = runtime_root.join("contextdb-mcp");
        let socket = broker_directory.join(&socket_name);
        if socket.as_os_str().as_bytes().len() <= MAX_UNIX_SOCKET_PATH_BYTES
            && socket.to_str().is_some()
        {
            ensure_owner_only_directory(&broker_directory)?;
            return Ok(broker_directory);
        }
    }

    let temporary_root = validated_shared_temporary_root()?;
    let broker_directory = temporary_root.join(format!(
        "contextdb-mcp-{}",
        rustix::process::geteuid().as_raw()
    ));
    let socket = broker_directory.join(socket_name);
    if socket.as_os_str().as_bytes().len() > MAX_UNIX_SOCKET_PATH_BYTES || socket.to_str().is_none()
    {
        return Err(unavailable(
            "Unix MCP broker cannot create a bounded UTF-8 socket path in the protected runtime directory",
            false,
        ));
    }
    ensure_owner_only_directory(&broker_directory)?;
    Ok(broker_directory)
}

#[cfg(unix)]
fn validated_owner_runtime_root(path: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let path = Path::new(path);
    if !path.is_absolute() {
        return None;
    }
    let configured_metadata = fs::symlink_metadata(path).ok()?;
    if configured_metadata.file_type().is_symlink() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    let metadata = fs::symlink_metadata(&canonical).ok()?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return None;
    }
    Some(canonical)
}

#[cfg(unix)]
fn validated_shared_temporary_root() -> CliResult<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let root = fs::canonicalize("/tmp").map_err(CliError::from)?;
    let metadata = fs::symlink_metadata(&root).map_err(CliError::from)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o1000 == 0
        || metadata.mode() & 0o002 == 0
    {
        return Err(unavailable(
            "Unix MCP broker fallback requires a root-owned sticky shared temporary directory",
            false,
        ));
    }
    Ok(root)
}

#[cfg(unix)]
fn ensure_owner_only_directory(path: &Path) -> CliResult<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(unavailable(
                    "Unix MCP broker directory must be owner-only and must not be a symbolic link",
                    false,
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(CliError::from(error)),
            }
            let metadata = fs::symlink_metadata(path).map_err(CliError::from)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(unavailable(
                    "Unix MCP broker directory could not be protected as owner-only",
                    false,
                ));
            }
        }
        Err(error) => return Err(CliError::from(error)),
    }
    Ok(())
}

#[cfg(unix)]
struct UnixSocketGuard {
    path: String,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl UnixSocketGuard {
    fn new(path: &str) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn unavailable(message: impl Into<String>, retryable: bool) -> CliError {
    ServiceError::new(ErrorCode::Unavailable, message, retryable).into()
}

fn read_sync_frame<R: BufRead>(
    reader: &mut R,
    maximum: usize,
) -> io::Result<Option<Result<Vec<u8>, ()>>> {
    let mut frame = Vec::new();
    let mut overflow = false;
    let mut saw_any = false;
    loop {
        let (consume, reached_newline, bytes) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if !saw_any {
                    return Ok(None);
                }
                while frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                return Ok(Some(if overflow { Err(()) } else { Ok(frame) }));
            }
            saw_any = true;
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consume = newline.map_or(available.len(), |position| position + 1);
            let data_end = newline.unwrap_or(available.len());
            (consume, newline.is_some(), available[..data_end].to_vec())
        };
        reader.consume(consume);
        if !overflow {
            if frame.len().saturating_add(bytes.len()) > maximum {
                overflow = true;
                frame.clear();
            } else {
                frame.extend_from_slice(&bytes);
            }
        }
        if reached_newline {
            while frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(if overflow { Err(()) } else { Ok(frame) }));
        }
    }
}

async fn read_async_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> io::Result<Option<Result<Vec<u8>, ()>>> {
    let mut frame = Vec::new();
    let mut overflow = false;
    let mut saw_any = false;
    loop {
        let (consume, reached_newline, bytes) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                if !saw_any {
                    return Ok(None);
                }
                while frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                return Ok(Some(if overflow { Err(()) } else { Ok(frame) }));
            }
            saw_any = true;
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consume = newline.map_or(available.len(), |position| position + 1);
            let data_end = newline.unwrap_or(available.len());
            (consume, newline.is_some(), available[..data_end].to_vec())
        };
        reader.consume(consume);
        if !overflow {
            if frame.len().saturating_add(bytes.len()) > maximum {
                overflow = true;
                frame.clear();
            } else {
                frame.extend_from_slice(&bytes);
            }
        }
        if reached_newline {
            while frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(Some(if overflow { Err(()) } else { Ok(frame) }));
        }
    }
}

async fn read_broker_control_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> io::Result<Option<Result<Vec<u8>, ()>>> {
    tokio::time::timeout(BROKER_HANDSHAKE_TIMEOUT, read_async_frame(reader, maximum))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MCP broker handshake timed out"))?
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{McpCapabilityArg, McpClearanceArg};

    #[cfg(windows)]
    #[test]
    fn windows_busy_pipe_waits_for_its_owner_without_autostart() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let name = format!("{BROKER_PIPE_PREFIX}busy-test-{}", std::process::id());
            let first = create_server(&name, true).expect("first instance");
            let occupied = open_client(&name).await.expect("occupy first instance");
            first.connect().await.expect("connected");
            assert_eq!(
                open_client(&name)
                    .await
                    .expect_err("all instances occupied")
                    .raw_os_error(),
                Some(231)
            );

            let starts = std::cell::Cell::new(0);
            let mut connecting = Box::pin(connect_broker(
                &name,
                Some(|| {
                    starts.set(starts.get() + 1);
                    Ok(())
                }),
            ));
            std::future::poll_fn(|cx| {
                assert!(Future::poll(connecting.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert_eq!(
                starts.get(),
                0,
                "backpressure must not queue a replacement broker"
            );

            let available = create_server(&name, false).expect("same owner opens next instance");
            let client = tokio::time::timeout(Duration::from_secs(5), &mut connecting)
                .await
                .expect("retry bounded")
                .expect("connect to existing owner");
            available.connect().await.expect("next instance connected");
            assert_eq!(starts.get(), 0);
            drop((client, available, occupied, first));
        });
    }

    #[cfg(windows)]
    #[test]
    fn windows_missing_pipe_starts_once_and_access_denial_never_starts_an_owner() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let name = format!("{BROKER_PIPE_PREFIX}missing-test-{}", std::process::id());
            let starts = std::cell::Cell::new(0);
            let listener = std::cell::RefCell::new(None);
            let client = connect_broker(
                &name,
                Some(|| {
                    starts.set(starts.get() + 1);
                    *listener.borrow_mut() = Some(create_server(&name, true).expect("new owner"));
                    Ok(())
                }),
            )
            .await
            .expect("absent endpoint starts");
            assert_eq!(starts.get(), 1);
            let server = listener.into_inner().expect("started server");
            server.connect().await.expect("new owner connected");
            drop((client, server));

            let name = format!("{BROKER_PIPE_PREFIX}denied-test-{}", std::process::id());
            let server = ServerOptions::new()
                .first_pipe_instance(true)
                .access_outbound(false)
                .reject_remote_clients(true)
                .create(&name)
                .expect("inbound-only server");
            assert_eq!(
                open_client(&name)
                    .await
                    .expect_err("duplex access denied")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            connect_broker(
                &name,
                Some(|| {
                    starts.set(starts.get() + 1);
                    Ok(())
                }),
            )
            .await
            .expect_err("denial is not absence");
            assert_eq!(starts.get(), 1);
            drop(server);
        });
    }

    #[cfg(unix)]
    #[test]
    fn unix_connect_waits_for_owner_only_socket_permissions_without_autostart() {
        use std::os::unix::fs::PermissionsExt;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let directory = tempfile::tempdir().expect("private directory");
        let path = directory.path().join("starting.sock");
        let name = path.to_str().expect("socket path");
        runtime.block_on(async {
            let listener = UnixListener::bind(&path).expect("bound before chmod");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("startup window");
            assert_eq!(
                open_client(name).await.expect_err("not ready").kind(),
                io::ErrorKind::WouldBlock
            );
            let starts = std::cell::Cell::new(0);
            let mut connecting = Box::pin(connect_broker(
                name,
                Some(|| {
                    starts.set(starts.get() + 1);
                    Ok(())
                }),
            ));
            std::future::poll_fn(|cx| {
                assert!(Future::poll(connecting.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert_eq!(starts.get(), 0);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("owner hardens socket");
            let client = tokio::time::timeout(Duration::from_secs(5), &mut connecting)
                .await
                .expect("bounded retry")
                .expect("ready owner");
            let (server, _) = listener.accept().await.expect("accepted");
            assert_eq!(starts.get(), 0);
            drop((client, server, listener));
            fs::remove_file(&path).expect("remove socket");
            fs::write(&path, "not a socket").expect("untrusted endpoint type");
            connect_broker(
                name,
                Some(|| {
                    starts.set(starts.get() + 1);
                    Ok(())
                }),
            )
            .await
            .expect_err("wrong file type is permanent denial");
            assert_eq!(starts.get(), 0);
        });
    }

    #[cfg(unix)]
    #[test]
    fn live_endpoint_ownership_prevents_stale_cleanup_during_listener_gaps() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir_in("/tmp").expect("short private fixture path");
        let socket = directory.path().join("broker.sock");
        let socket_name = socket.to_str().expect("socket path");
        let owner = EndpointOwner::claim(socket_name).expect("first owner");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("listener");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).expect("socket mode");
        let inode = fs::symlink_metadata(&socket).expect("socket inode").ino();
        // Dropping the listener before cleanup leaves the same refused-connect
        // state as a socket whose owner has bound it but has not listened yet.
        drop(listener);
        assert!(!remove_owned_stale_socket(socket_name).expect("live owner"));
        assert_eq!(
            fs::symlink_metadata(&socket).expect("same socket").ino(),
            inode
        );

        drop(owner);
        assert!(remove_owned_stale_socket(socket_name).expect("crashed owner cleanup"));
        assert!(!socket.exists());
        EndpointOwner::claim(socket_name).expect("next owner can start");
    }

    fn test_key(byte: u8) -> TokenKey {
        TokenKey::new([byte; 32]).expect("test token key")
    }

    #[test]
    fn windows_powershell_utf8_bom_is_not_forwarded_to_json_rpc() {
        let frame = b"\xef\xbb\xbf{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        let stripped = strip_utf8_bom(frame);
        let request = serde_json::from_slice::<JsonRpcRequest>(stripped).expect("JSON-RPC request");
        assert_eq!(request.id, serde_json::json!(1));
        assert_eq!(request.method, "tools/list");
    }

    fn authority() -> McpAuthorityConfig {
        McpAuthorityConfig {
            actor_id: "actor:test".to_owned(),
            agent_id: "agent:test".to_owned(),
            workspace_id: "workspace:test".to_owned(),
            subject_id: "subject:test".to_owned(),
            purpose: "conversation".to_owned(),
            session_id: Some("session:test".to_owned()),
            audiences: vec!["subject:test".to_owned()],
            scopes: vec!["project:test".to_owned()],
            capabilities: vec![McpCapabilityArg::Recall],
            clearance: McpClearanceArg::Private,
        }
    }

    fn signed_ack(handshake: &BrokerHandshakePayload, accepted: bool, key: &TokenKey) -> BrokerAck {
        let payload = BrokerAckPayload {
            schema_version: BROKER_SCHEMA_VERSION,
            accepted,
            handshake_nonce: handshake.nonce.clone(),
            pipe_id: handshake.pipe_id.clone(),
            operation: handshake.operation,
            reference: handshake.reference,
            broker_pid: 42,
        };
        let mac = ack_mac(&payload, key).expect("ACK MAC");
        BrokerAck { payload, mac }
    }

    #[test]
    fn broker_ack_is_mutually_authenticated_and_bound_to_the_handshake() {
        let key = test_key(7);
        let handshake = build_handshake(
            "pipe:test",
            BrokerOperation::Session,
            false,
            Some(authority()),
            &key,
        )
        .expect("handshake");
        let mut ack = signed_ack(&handshake.payload, true, &key);
        assert!(verify_ack(&ack, &handshake.payload, &key));

        ack.payload.broker_pid += 1;
        assert!(!verify_ack(&ack, &handshake.payload, &key));
        ack = signed_ack(&handshake.payload, true, &key);
        ack.payload.handshake_nonce = "11".repeat(32);
        assert!(!verify_ack(&ack, &handshake.payload, &key));
        ack = signed_ack(&handshake.payload, true, &key);
        ack.payload.operation = BrokerOperation::Shutdown;
        assert!(!verify_ack(&ack, &handshake.payload, &key));
    }

    #[test]
    fn pipe_squatter_cannot_forge_an_accepted_ack() {
        let key = test_key(8);
        let handshake = build_handshake(
            "pipe:test",
            BrokerOperation::Session,
            false,
            Some(authority()),
            &key,
        )
        .expect("handshake");
        let mut forged = signed_ack(&handshake.payload, true, &key);
        forged.mac = "00".repeat(32);
        assert!(!verify_ack(&forged, &handshake.payload, &key));
        let wrong_key = test_key(9);
        assert!(!verify_ack(&forged, &handshake.payload, &wrong_key));
    }

    #[test]
    fn handshake_tampering_and_process_lifetime_replay_are_rejected() {
        let key = test_key(10);
        let mut handshake = build_handshake(
            "pipe:test",
            BrokerOperation::Session,
            false,
            Some(authority()),
            &key,
        )
        .expect("handshake");
        assert!(verify_handshake(&handshake, "pipe:test", false, &key));
        handshake.payload.reference = true;
        assert!(!verify_handshake(&handshake, "pipe:test", false, &key));

        let mut cache = NonceCache::default();
        assert!(cache.admit("first"));
        assert!(!cache.admit("first"));
        for index in 1..MAX_BROKER_NONCES {
            assert!(cache.admit(&format!("nonce:{index}")));
        }
        assert_eq!(cache.entries.len(), MAX_BROKER_NONCES);
        assert!(cache.admit("after-capacity"));
        assert_eq!(cache.entries.len(), MAX_BROKER_NONCES);
        assert!(
            cache.admit("first"),
            "oldest nonce must be evicted at the cap"
        );
    }
}
