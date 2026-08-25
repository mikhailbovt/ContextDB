use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN: &str = "3737373737373737373737373737373737373737373737373737373737373737";

struct TestAuthority {
    #[cfg(windows)]
    selector: String,
    archive_directory: PathBuf,
    #[cfg(unix)]
    head: PathBuf,
    #[cfg(unix)]
    _directory: tempfile::TempDir,
}

impl TestAuthority {
    fn new(archive_directory: &Path) -> Self {
        #[cfg(windows)]
        {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos();
            Self {
                selector: format!("cli-api-integration-{}-{nonce}", std::process::id()),
                archive_directory: archive_directory.to_path_buf(),
            }
        }
        #[cfg(unix)]
        {
            let authority_directory = tempfile::tempdir().expect("authority directory");
            Self {
                head: authority_directory.path().join("state-head.json"),
                _directory: authority_directory,
                archive_directory: archive_directory.to_path_buf(),
            }
        }
    }

    fn configure(&self, command: &mut Command) {
        command
            .env("CONTEXTDB_TOKEN_KEY_HEX", TOKEN)
            .env_remove("CONTEXTDB_TOKEN_KEY_FILE");
        #[cfg(windows)]
        command
            .env("CONTEXTDB_STATE_HEAD_ID", &self.selector)
            .env_remove("CONTEXTDB_STATE_HEAD_FILE");
        #[cfg(unix)]
        command
            .env("CONTEXTDB_STATE_HEAD_FILE", &self.head)
            .env_remove("CONTEXTDB_STATE_HEAD_ID");
    }
}

impl Drop for TestAuthority {
    fn drop(&mut self) {
        #[cfg(windows)]
        use winreg::RegKey;
        #[cfg(windows)]
        use winreg::enums::HKEY_CURRENT_USER;

        // A failed assertion must not leave a detached broker holding the
        // temporary Fjall directory while TempDir unwinds. Best-effort
        // authenticated shutdown runs before deleting this test's authority.
        if let Ok(entries) = std::fs::read_dir(&self.archive_directory) {
            for archive in entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "ctxb")
                })
            {
                let mut command = Command::new(env!("CARGO_BIN_EXE_contextdb"));
                command
                    .arg("mcp-broker-stop")
                    .arg(archive)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                self.configure(&mut command);
                let _ = command.status();
            }
        }

        #[cfg(windows)]
        {
            let digest = blake3::hash(self.selector.as_bytes()).to_hex();
            let parent = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
                "Software\\ContextDB\\StateHeads",
                winreg::enums::KEY_WRITE,
            );
            if let Ok(parent) = parent {
                let _ = parent.delete_subkey_all(digest.to_string());
            }
        }
    }
}

fn run(binary: &str, authority: &TestAuthority, arguments: &[&str]) -> Output {
    let mut command = Command::new(binary);
    command.args(arguments);
    authority.configure(&mut command);
    command.output().expect("run contextdb")
}

fn authenticated(capability: &str, request_id: &str) -> serde_json::Value {
    serde_json::json!({
        "request": {
            "request_id": request_id,
            "workspace_id": "workspace:subprocess",
            "subject_id": "subject:alice",
            "audiences": ["subject:alice"],
            "scopes": ["project:subprocess"],
            "purpose": "assist",
            "clearance": "private"
        },
        "actor_id": "actor:alice",
        "agent_id": "agent:subprocess",
        "session_id": "session:subprocess",
        "capability_grants": [capability],
        "authentication": {
            "kind": "authenticated_channel",
            "channel_id": "channel:subprocess",
            "peer_identity": "actor:alice",
            "binding_digest": "44".repeat(32)
        }
    })
}

fn mcp_semantic_context(request_id: &str) -> serde_json::Value {
    authenticated("model-must-not-grant-capabilities", request_id)["request"].clone()
}

fn mcp_admin_semantic_context(request_id: &str) -> serde_json::Value {
    let mut context = mcp_semantic_context(request_id);
    context["purpose"] = serde_json::json!("contextdb:admin");
    context["clearance"] = serde_json::json!("restricted");
    context
}

fn write_json(directory: &Path, name: &str, value: serde_json::Value) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, serde_json::to_vec(&value).expect("request JSON")).expect("request file");
    path
}

fn invoke_memory_mcp(
    binary: &str,
    authority: &TestAuthority,
    archive: &Path,
    request: &serde_json::Value,
) -> serde_json::Value {
    let mut command = Command::new(binary);
    command
        .arg("mcp")
        .arg(archive)
        .args([
            "--actor-id",
            "actor:alice",
            "--agent-id",
            "agent:memory-subprocess",
            "--workspace-id",
            "workspace:memory-subprocess",
            "--subject-id",
            "subject:alice",
            "--purpose",
            "conversation",
            "--session-id",
            "session:memory-subprocess",
            "--audience",
            "subject:alice",
            "--scope",
            "project:memory-subprocess",
            "--capability",
            "observe",
            "--capability",
            "recall",
            "--capability",
            "read-memory",
            "--capability",
            "traverse",
            "--capability",
            "model-processing",
            "--clearance",
            "private",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    authority.configure(&mut command);
    let mut child = command.spawn().expect("spawn memory MCP child");
    let mut stdin = child.stdin.take().expect("memory MCP stdin");
    serde_json::to_writer(&mut stdin, request).expect("memory MCP JSON");
    stdin.write_all(b"\n").expect("memory MCP newline");
    drop(stdin);
    let output = child.wait_with_output().expect("memory MCP output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    serde_json::from_slice(
        output
            .stdout
            .strip_suffix(b"\n")
            .expect("newline-delimited memory response"),
    )
    .expect("memory MCP response")
}

fn stop_memory_mcp(binary: &str, authority: &TestAuthority, archive: &Path) {
    let stopped = run(
        binary,
        authority,
        &["mcp-broker-stop", archive.to_str().expect("archive path")],
    );
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
}

fn memory_semantic_context(request_id: &str) -> serde_json::Value {
    serde_json::json!({
        "request_id": request_id,
        "workspace_id": "workspace:memory-subprocess",
        "subject_id": "subject:alice",
        "audiences": ["subject:alice"],
        "scopes": ["project:memory-subprocess"],
        "purpose": "conversation",
        "clearance": "private"
    })
}

fn mcp_meta() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": contextdb_mcp::MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "integration", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

struct BrokerChild(Child);

impl BrokerChild {
    fn wait_for_exit(&mut self) {
        let status = self.0.wait().expect("wait for MCP broker");
        assert!(
            status.success(),
            "MCP broker exited unsuccessfully: {status}"
        );
    }
}

impl Drop for BrokerChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_mcp_broker(binary: &str, authority: &TestAuthority, archive: &Path) -> BrokerChild {
    let mut command = Command::new(binary);
    command
        .arg("mcp-broker")
        .arg(archive)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    authority.configure(&mut command);
    let mut child = command.spawn().expect("spawn MCP broker");
    let stderr = child.stderr.take().expect("MCP broker stderr");
    let mut reader = BufReader::new(stderr);
    let mut readiness = String::new();
    reader
        .read_line(&mut readiness)
        .expect("read MCP broker readiness");
    assert_eq!(
        readiness.trim(),
        "contextdb MCP broker ready",
        "{readiness}"
    );
    BrokerChild(child)
}

fn spawn_memory_mcp(binary: &str, authority: &TestAuthority, archive: &Path) -> Child {
    let mut command = Command::new(binary);
    command
        .arg("mcp")
        .arg(archive)
        .args([
            "--actor-id",
            "actor:alice",
            "--agent-id",
            "agent:memory-subprocess",
            "--workspace-id",
            "workspace:memory-subprocess",
            "--subject-id",
            "subject:alice",
            "--purpose",
            "conversation",
            "--session-id",
            "session:memory-subprocess",
            "--audience",
            "subject:alice",
            "--scope",
            "project:memory-subprocess",
            "--capability",
            "observe",
            "--capability",
            "recall",
            "--capability",
            "read-memory",
            "--capability",
            "traverse",
            "--capability",
            "model-processing",
            "--clearance",
            "private",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    authority.configure(&mut command);
    command.spawn().expect("spawn brokered MCP proxy")
}

fn send_one_mcp_request(mut child: Child, request: &serde_json::Value) -> Output {
    let mut stdin = child.stdin.take().expect("brokered MCP stdin");
    serde_json::to_writer(&mut stdin, request).expect("brokered MCP JSON");
    stdin.write_all(b"\n").expect("brokered MCP newline");
    drop(stdin);
    child.wait_with_output().expect("brokered MCP output")
}

fn decoded_mcp_output(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(TOKEN));
    serde_json::from_slice(
        output
            .stdout
            .strip_suffix(b"\n")
            .expect("newline-delimited brokered response"),
    )
    .expect("brokered MCP response")
}

#[test]
fn mcp_broker_serializes_concurrent_writes_and_reopens_after_restart() {
    let binary = env!("CARGO_BIN_EXE_contextdb");
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = directory.path().join("brokered-memory.ctxb");
    let authority = TestAuthority::new(directory.path());
    let initialized = run(
        binary,
        &authority,
        &["--json", "init", archive.to_str().expect("archive path")],
    );
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let mut broker = start_mcp_broker(binary, &authority, &archive);
    let meta = mcp_meta();
    let request = |id: u64, suffix: &str| {
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {
                "name": "contextdb_ensure_candidate",
                "arguments": {
                    "context": memory_semantic_context(&format!("request:broker:{suffix}")),
                    "identity_key": format!("project|repo=d:/develop/contextdb-broker-{suffix}"),
                    "semantic_kind": "project",
                    "value": {"text": format!("Concurrent broker project {suffix}")},
                    "search_text": format!("concurrent broker project {suffix}"),
                    "parent_candidate_ids": [],
                    "supersedes_candidate_ids": []
                },
                "_meta": meta
            }
        })
    };
    let first = spawn_memory_mcp(binary, &authority, &archive);
    let second = spawn_memory_mcp(binary, &authority, &archive);
    let first_request = request(1, "alpha");
    let second_request = request(2, "beta");
    let first_thread = std::thread::spawn(move || send_one_mcp_request(first, &first_request));
    let second_thread = std::thread::spawn(move || send_one_mcp_request(second, &second_request));
    let first_output = first_thread.join().expect("first MCP proxy thread");
    let second_output = second_thread.join().expect("second MCP proxy thread");
    let first_response = decoded_mcp_output(&first_output);
    let second_response = decoded_mcp_output(&second_output);
    for response in [&first_response, &second_response] {
        assert!(response["error"].is_null(), "{response:#}");
        assert_eq!(response["result"]["isError"], false, "{response:#}");
        assert_eq!(
            response["result"]["structuredContent"]["proposal_state"],
            "quarantined"
        );
    }
    let first_commit = first_response["result"]["structuredContent"]["mutation"]["commit_seq"]
        .as_u64()
        .expect("first commit sequence");
    let second_commit = second_response["result"]["structuredContent"]["mutation"]["commit_seq"]
        .as_u64()
        .expect("second commit sequence");
    assert_ne!(first_commit, second_commit);
    assert_eq!(first_commit.abs_diff(second_commit), 1);
    let first_candidate_id = first_response["result"]["structuredContent"]["candidate_id"]
        .as_str()
        .expect("first derived candidate ID")
        .to_owned();
    let second_candidate_id = second_response["result"]["structuredContent"]["candidate_id"]
        .as_str()
        .expect("second derived candidate ID")
        .to_owned();
    assert_ne!(first_candidate_id, second_candidate_id);

    stop_memory_mcp(binary, &authority, &archive);
    broker.wait_for_exit();
    let mut reopened_broker = start_mcp_broker(binary, &authority, &archive);
    for (id, candidate_id) in [(3, first_candidate_id), (4, second_candidate_id)] {
        let materialized = invoke_memory_mcp(
            binary,
            &authority,
            &archive,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {
                    "name": "contextdb_get_candidate",
                    "arguments": {
                        "context": memory_semantic_context(&format!("request:broker:get:{id}")),
                        "record_id": candidate_id.clone(),
                        "at_commit": null
                    },
                    "_meta": mcp_meta()
                }
            }),
        );
        assert!(materialized["error"].is_null(), "{materialized:#}");
        assert_eq!(materialized["result"]["isError"], false, "{materialized:#}");
        assert_eq!(
            materialized["result"]["structuredContent"]["document"]["id"],
            candidate_id
        );
    }
    stop_memory_mcp(binary, &authority, &archive);
    reopened_broker.wait_for_exit();
}

#[cfg(unix)]
#[test]
fn unix_mcp_broker_socket_is_owner_only_and_removed_after_shutdown() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let binary = env!("CARGO_BIN_EXE_contextdb");
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = directory.path().join("owner-only-broker.ctxb");
    let authority = TestAuthority::new(directory.path());
    let initialized = run(
        binary,
        &authority,
        &["--json", "init", archive.to_str().expect("archive path")],
    );
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let mut broker = start_mcp_broker(binary, &authority, &archive);
    let broker_directory = authority
        .head
        .parent()
        .expect("state-head parent")
        .join("brokers");
    let directory_metadata =
        std::fs::symlink_metadata(&broker_directory).expect("owner-only broker directory metadata");
    assert!(directory_metadata.is_dir());
    assert_eq!(directory_metadata.mode() & 0o777, 0o700);
    assert_eq!(
        directory_metadata.uid(),
        rustix::process::geteuid().as_raw()
    );

    let sockets = std::fs::read_dir(&broker_directory)
        .expect("broker directory")
        .map(|entry| entry.expect("broker directory entry").path())
        .collect::<Vec<_>>();
    assert_eq!(sockets.len(), 1);
    let socket = sockets.into_iter().next().expect("broker socket");
    let metadata = std::fs::symlink_metadata(&socket).expect("broker socket metadata");
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());

    stop_memory_mcp(binary, &authority, &archive);
    broker.wait_for_exit();
    assert!(!socket.exists(), "broker shutdown must unlink its socket");
}

#[cfg(unix)]
#[test]
fn unix_mcp_broker_rejects_symbolic_link_socket_directory() {
    use std::os::unix::fs::symlink;

    let binary = env!("CARGO_BIN_EXE_contextdb");
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = directory.path().join("symlink-broker.ctxb");
    let authority = TestAuthority::new(directory.path());
    let initialized = run(
        binary,
        &authority,
        &["--json", "init", archive.to_str().expect("archive path")],
    );
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let untrusted_directory = tempfile::tempdir().expect("untrusted broker directory");
    let socket_directory = authority
        .head
        .parent()
        .expect("state-head parent")
        .join("brokers");
    symlink(untrusted_directory.path(), &socket_directory).expect("broker directory symlink");
    let rejected = run(
        binary,
        &authority,
        &["mcp-broker", archive.to_str().expect("archive path")],
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("symbolic link"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
}

#[cfg(unix)]
#[test]
fn unix_mcp_broker_concurrent_autostarts_share_one_authenticated_owner() {
    use std::sync::{Arc, Barrier};

    const SESSIONS: usize = 8;

    let binary = env!("CARGO_BIN_EXE_contextdb");
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = directory.path().join("concurrent-autostart.ctxb");
    let authority = TestAuthority::new(directory.path());
    let initialized = run(
        binary,
        &authority,
        &["--json", "init", archive.to_str().expect("archive path")],
    );
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let gate = Arc::new(Barrier::new(SESSIONS));
    let threads = std::thread::scope(|scope| {
        (0..SESSIONS)
            .map(|index| {
                let gate = gate.clone();
                let authority = &authority;
                let archive = &archive;
                scope.spawn(move || {
                    gate.wait();
                    let child = spawn_memory_mcp(binary, authority, archive);
                    let request = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": index,
                        "method": "tools/list",
                        "params": {"_meta": mcp_meta()}
                    });
                    decoded_mcp_output(&send_one_mcp_request(child, &request))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().expect("concurrent MCP session"))
            .collect::<Vec<_>>()
    });
    for response in threads {
        assert!(response["error"].is_null(), "{response:#}");
        assert_eq!(
            response["result"]["tools"]
                .as_array()
                .expect("MCP tool inventory")
                .len(),
            16
        );
    }

    let broker_directory = authority
        .head
        .parent()
        .expect("state-head parent")
        .join("brokers");
    assert_eq!(
        std::fs::read_dir(broker_directory)
            .expect("broker directory")
            .count(),
        1,
        "simultaneous autostarts must converge on exactly one socket owner"
    );
    stop_memory_mcp(binary, &authority, &archive);
}

#[test]
fn production_mcp_persists_candidates_and_keeps_them_out_of_context_after_restart() {
    let binary = env!("CARGO_BIN_EXE_contextdb");
    let directory = tempfile::tempdir().expect("temporary directory");
    // Exercise the constant-script/env-only Windows launcher with characters
    // that would be shell metacharacters if a path were interpolated.
    let archive = directory.path().join("memory with spaces & symbols.ctxb");
    let authority = TestAuthority::new(directory.path());
    let initialized = run(
        binary,
        &authority,
        &["--json", "init", archive.to_str().expect("archive path")],
    );
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let meta = mcp_meta();
    let proposed = invoke_memory_mcp(
        binary,
        &authority,
        &archive,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "contextdb_ensure_candidate",
                "arguments": {
                    "context": memory_semantic_context("request:propose"),
                    "identity_key": "project|repo=d:/develop/contextdb-espresso-test",
                    "semantic_kind": "project",
                    "value": {"text": "The project codename is Espresso."},
                    "search_text": "project codename Espresso",
                    "parent_candidate_ids": [],
                    "supersedes_candidate_ids": []
                },
                "_meta": meta
            }
        }),
    );
    assert!(proposed["error"].is_null(), "{proposed:#}");
    assert_eq!(proposed["result"]["isError"], false, "{proposed:#}");
    assert_eq!(
        proposed["result"]["structuredContent"]["proposal_state"],
        "quarantined"
    );
    assert_eq!(proposed["result"]["structuredContent"]["canonical"], false);
    let proposed_candidate_id = proposed["result"]["structuredContent"]["candidate_id"]
        .as_str()
        .expect("derived candidate ID")
        .to_owned();

    let native_path = PathBuf::from(format!("{}.native-fjall", archive.display()));
    assert!(native_path.is_dir(), "native sidecar was not created");

    // A second process proves that both the native semantic state and its
    // ContextPack provider survive the process boundary.
    let recalled = invoke_memory_mcp(
        binary,
        &authority,
        &archive,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "contextdb_recall_candidates",
                "arguments": {
                    "context": memory_semantic_context("request:recall-candidate"),
                    "query": "project codename Espresso",
                    "semantic_kinds": ["project"],
                    "page_size": 10,
                    "at_commit": null
                },
                "_meta": meta
            }
        }),
    );
    assert!(recalled["error"].is_null(), "{recalled:#}");
    assert_eq!(recalled["result"]["isError"], false, "{recalled:#}");
    assert_eq!(
        recalled["result"]["structuredContent"]["hits"][0]["candidate_id"],
        proposed_candidate_id
    );

    let compiled = invoke_memory_mcp(
        binary,
        &authority,
        &archive,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "contextdb_context",
                "arguments": {
                    "context": memory_semantic_context("request:context"),
                    "plan": {
                        "pack_id": "00000000-0000-0000-0000-000000000123",
                        "query": "remember the Espresso project codename",
                        "mode": "auto",
                        "intent": "current_truth",
                        "purpose": "conversation",
                        "at_commit": null,
                        "now_micros": 0,
                        "required_facets": [],
                        "recall_limits": {
                            "max_nodes_examined": 128,
                            "max_seed_candidates": 128,
                            "max_graph_hops": 2,
                            "max_frontier_per_hop": 128,
                            "max_evidence_units": 32,
                            "max_context_tokens": 2048,
                            "deadline_micros": 5000000
                        },
                        "context_budgets": {
                            "hard_tokens": 2048,
                            "soft_tokens": 1024,
                            "max_blocks": 32,
                            "max_evidence_blocks": 32,
                            "max_raw_evidence_tokens": 1024,
                            "max_history_tokens": 1024,
                            "max_conflict_tokens": 1024,
                            "max_serialized_bytes": 262144,
                            "max_selection_evaluations": 128
                        },
                        "model_profile": {
                            "id": "model:local-test",
                            "family": "native",
                            "tokenizer_id": "contextdb.reference_unicode_tokens.v1",
                            "renderer": "compact",
                            "max_context_tokens": 4096,
                            "reserved_output_tokens": 1024,
                            "preferred_structured_format": "compact_text",
                            "supports_tool_results": false,
                            "supports_native_citations": false,
                            "supports_prompt_caching": false,
                            "position_profile": "small_model_explicit",
                            "instruction_hierarchy": "single_prompt_delimited",
                            "max_schema_complexity": 32,
                            "external_processing": false
                        },
                        "explicit_memory_request": false,
                        "require_primary_evidence": false,
                        "include_evidence_quotes": false,
                        "permit_derived_only": true,
                        "max_projection_lag_commits": 0,
                        "allow_stale": false,
                        "query_vector": null,
                        "continuation": null
                    }
                },
                "_meta": meta
            }
        }),
    );
    assert!(compiled["error"].is_null(), "{compiled:#}");
    assert_eq!(compiled["result"]["isError"], false, "{compiled:#}");
    let encoded = serde_json::to_string(&compiled).expect("compiled response JSON");
    assert!(
        !encoded.contains("Espresso"),
        "quarantined candidate leaked into canonical ContextPack: {compiled:#}"
    );
    assert_eq!(
        compiled["result"]["structuredContent"]["trace"]["stale"],
        false
    );
    stop_memory_mcp(binary, &authority, &archive);
}

#[test]
fn operator_cli_composite_backup_roundtrips_and_fails_closed() {
    let binary = env!("CARGO_BIN_EXE_contextdb");
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = directory.path().join("operator-recovery.ctxb");
    let backup = directory.path().join("operator-recovery.cdb-backup");
    let authority = TestAuthority::new(directory.path());
    let initialized = run(
        binary,
        &authority,
        &["--json", "init", archive.to_str().expect("archive path")],
    );
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let proposed = invoke_memory_mcp(
        binary,
        &authority,
        &archive,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "contextdb_ensure_candidate",
                "arguments": {
                    "context": memory_semantic_context("request:operator-propose"),
                    "identity_key": "project|repo=d:/develop/contextdb-operator-recovery",
                    "semantic_kind": "project",
                    "value": {"text": "The operator recovery codename is Espresso."},
                    "search_text": "operator recovery codename Espresso",
                    "parent_candidate_ids": [],
                    "supersedes_candidate_ids": []
                },
                "_meta": mcp_meta()
            }
        }),
    );
    assert!(proposed["error"].is_null(), "{proposed:#}");
    assert_eq!(proposed["result"]["isError"], false, "{proposed:#}");
    let proposed_candidate_id = proposed["result"]["structuredContent"]["candidate_id"]
        .as_str()
        .expect("derived operator candidate ID")
        .to_owned();
    stop_memory_mcp(binary, &authority, &archive);

    let created = run(
        binary,
        &authority,
        &[
            "--json",
            "codex-backup",
            archive.to_str().expect("archive path"),
            backup.to_str().expect("backup path"),
        ],
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&created.stdout).expect("backup receipt");
    assert_eq!(receipt["operation"], "codex_backup_created");
    assert_eq!(receipt["format"], "contextdb.codex-composite-backup.v1");
    assert_eq!(
        receipt["restore_policy"],
        "lifecycle-exact-match+native-pristine-target-only"
    );
    assert_eq!(
        receipt["bytes"].as_u64(),
        Some(std::fs::metadata(&backup).expect("backup metadata").len())
    );
    for bytes in [&created.stdout, &created.stderr] {
        let output = String::from_utf8_lossy(bytes);
        assert!(!output.contains("Espresso"));
        assert!(!output.contains(TOKEN));
    }
    let installed_backup = std::fs::read(&backup).expect("installed backup");
    let rejected_clobber = run(
        binary,
        &authority,
        &[
            "--json",
            "codex-backup",
            archive.to_str().expect("archive path"),
            backup.to_str().expect("backup path"),
        ],
    );
    assert!(!rejected_clobber.status.success());
    assert_eq!(
        std::fs::read(&backup).expect("backup after no-clobber rejection"),
        installed_backup
    );

    let native_path = PathBuf::from(format!("{}.native-fjall", archive.display()));
    let source_native_path = directory.path().join("source-native-fjall");
    std::fs::rename(&native_path, &source_native_path)
        .expect("quarantine original native authority");

    let tampered_path = directory.path().join("tampered.cdb-backup");
    let mut tampered = std::fs::read(&backup).expect("read backup fixture");
    *tampered.last_mut().expect("non-empty backup") ^= 1;
    std::fs::write(&tampered_path, tampered).expect("write tampered backup fixture");
    let rejected_tamper = run(
        binary,
        &authority,
        &[
            "--json",
            "codex-restore",
            archive.to_str().expect("archive path"),
            tampered_path.to_str().expect("tampered path"),
        ],
    );
    assert!(!rejected_tamper.status.success());
    let tamper_error: serde_json::Value =
        serde_json::from_slice(&rejected_tamper.stderr).expect("tamper error");
    assert_eq!(tamper_error["code"], "integrity_failure");

    let restored = run(
        binary,
        &authority,
        &[
            "--json",
            "codex-restore",
            archive.to_str().expect("archive path"),
            backup.to_str().expect("backup path"),
        ],
    );
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let restore_receipt: serde_json::Value =
        serde_json::from_slice(&restored.stdout).expect("restore receipt");
    assert_eq!(restore_receipt["operation"], "codex_backup_restored");
    assert_eq!(restore_receipt["response"]["commit_seq"], 1);

    let recalled = invoke_memory_mcp(
        binary,
        &authority,
        &archive,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "contextdb_recall_candidates",
                "arguments": {
                    "context": memory_semantic_context("request:operator-recall"),
                    "query": "recovery codename Espresso",
                    "semantic_kinds": ["project"],
                    "page_size": 10,
                    "at_commit": null
                },
                "_meta": mcp_meta()
            }
        }),
    );
    assert!(recalled["error"].is_null(), "{recalled:#}");
    assert_eq!(recalled["result"]["isError"], false, "{recalled:#}");
    assert_eq!(
        recalled["result"]["structuredContent"]["hits"][0]["candidate_id"],
        proposed_candidate_id
    );
    stop_memory_mcp(binary, &authority, &archive);

    let rejected_non_pristine = run(
        binary,
        &authority,
        &[
            "--json",
            "codex-restore",
            archive.to_str().expect("archive path"),
            backup.to_str().expect("backup path"),
        ],
    );
    assert!(!rejected_non_pristine.status.success());
    let non_pristine_error: serde_json::Value =
        serde_json::from_slice(&rejected_non_pristine.stderr).expect("non-pristine error");
    assert_eq!(non_pristine_error["code"], "unsupported");
    assert_eq!(
        non_pristine_error["violated_policy"],
        "restore:pristine-target-only"
    );

    let recalled_after_failure = invoke_memory_mcp(
        binary,
        &authority,
        &archive,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "contextdb_recall_candidates",
                "arguments": {
                    "context": memory_semantic_context("request:operator-recall-after-failure"),
                    "query": "recovery codename Espresso",
                    "semantic_kinds": ["project"],
                    "page_size": 10,
                    "at_commit": null
                },
                "_meta": mcp_meta()
            }
        }),
    );
    assert_eq!(
        recalled_after_failure["result"]["structuredContent"]["hits"][0]["candidate_id"],
        proposed_candidate_id
    );
    stop_memory_mcp(binary, &authority, &archive);
}

#[test]
fn real_binary_exposes_authenticated_high_level_runtime_and_mcp_surfaces() {
    let binary = env!("CARGO_BIN_EXE_contextdb");
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive = directory.path().join("memory.ctxb");
    let authority = TestAuthority::new(directory.path());
    let initialized = run(
        binary,
        &authority,
        &["--json", "init", archive.to_str().expect("archive path")],
    );
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let begin = write_json(
        directory.path(),
        "begin.json",
        serde_json::json!({
            "context": authenticated("observe", "request:begin"),
            "idempotency_key": "idempotency:begin",
            "target_subject_id": "subject:alice",
            "session_id": "session:subprocess",
            "logical_id": "session:subprocess",
            "access": {
                "workspace_id": "workspace:subprocess",
                "scopes": ["project:subprocess"],
                "owners": ["subject:alice"],
                "audience": ["subject:alice"],
                "audience_purpose_grants": {},
                "purposes": ["assist"],
                "sensitivity": "private",
                "consent": "granted",
                "retrievable": true
            },
            "payload": {"channel": "integration"},
            "references": []
        }),
    );
    let begun = run(
        binary,
        &authority,
        &[
            "--json",
            "api",
            archive.to_str().expect("archive path"),
            "begin-session",
            "--request",
            begin.to_str().expect("request path"),
        ],
    );
    assert!(
        begun.status.success(),
        "{}",
        String::from_utf8_lossy(&begun.stderr)
    );
    let begun_json: serde_json::Value =
        serde_json::from_slice(&begun.stdout).expect("begin response");
    assert_eq!(begun_json["operation"], "BeginSession");
    assert_eq!(begun_json["semantic_status"], "pending");

    let pin = write_json(
        directory.path(),
        "pin.json",
        serde_json::json!({
            "context": authenticated("correct", "request:pin"),
            "idempotency_key": "idempotency:pin",
            "target_subject_id": "subject:alice",
            "target_id": "memory:missing",
            "parameters": {}
        }),
    );
    let pinned = run(
        binary,
        &authority,
        &[
            "--json",
            "api",
            archive.to_str().expect("archive path"),
            "pin",
            "--request",
            pin.to_str().expect("request path"),
        ],
    );
    assert!(!pinned.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&pinned.stderr).expect("pin error")["code"],
        "unsupported"
    );

    let preflight = write_json(
        directory.path(),
        "preflight.json",
        serde_json::json!({
            "context": authenticated("runtime", "request:preflight"),
            "operation_id": "operation:preflight",
            "payload": {"turn": 1}
        }),
    );
    let preflighted = run(
        binary,
        &authority,
        &[
            "--json",
            "api",
            archive.to_str().expect("archive path"),
            "preflight",
            "--request",
            preflight.to_str().expect("request path"),
        ],
    );
    assert!(!preflighted.status.success());
    let preflight_error =
        serde_json::from_slice::<serde_json::Value>(&preflighted.stderr).expect("preflight error");
    assert_eq!(
        preflight_error["code"], "format_incompatible",
        "{preflight_error:#}"
    );

    let meta = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": contextdb_mcp::MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "integration", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut command = Command::new(binary);
    command
        .arg("mcp")
        .arg(&archive)
        .args([
            "--actor-id",
            "actor:alice",
            "--agent-id",
            "agent:subprocess",
            "--workspace-id",
            "workspace:subprocess",
            "--subject-id",
            "subject:alice",
            "--purpose",
            "assist",
            "--session-id",
            "session:subprocess",
            "--audience",
            "subject:alice",
            "--scope",
            "project:subprocess",
            "--capability",
            "runtime",
            "--clearance",
            "private",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    authority.configure(&mut command);
    let mut child = command.spawn().expect("spawn MCP child");
    let mut stdin = child.stdin.take().expect("MCP stdin");
    for request in [
        serde_json::json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "codex-integration", "version": "1"}
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/initialized",
            "params": {}
        }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {}
        }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "contextdb_preflight",
                "arguments": {
                    "context": mcp_semantic_context("request:mcp-preflight"),
                    "operation_id": "operation:mcp-preflight",
                    "payload": {}
                }
            }
        }),
    ] {
        serde_json::to_writer(&mut stdin, &request).expect("MCP JSON");
        stdin.write_all(b"\n").expect("MCP newline");
    }
    drop(stdin);
    let output = child.wait_with_output().expect("MCP output");
    assert!(output.status.success());
    let responses = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).expect("MCP response"))
        .collect::<Vec<_>>();
    assert_eq!(
        responses.len(),
        3,
        "initialized notification has no response"
    );
    assert_eq!(responses[0]["result"]["protocolVersion"], "2025-06-18");
    let tools = responses[1]["result"]["tools"]
        .as_array()
        .expect("tool array");
    assert_eq!(tools.len(), 16);
    let names = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(names.contains("contextdb_session"));
    assert!(names.contains("contextdb_preflight"));
    assert!(names.contains("contextdb_context"));
    assert!(names.contains("contextdb_ensure_candidate"));
    assert!(names.contains("contextdb_recall_candidates"));
    assert!(names.contains("contextdb_get_candidate"));
    assert!(names.contains("contextdb_traverse_candidates"));
    assert!(!names.contains("contextdb_remember"));
    assert!(!names.contains("contextdb_remember_structured"));
    assert!(!names.contains("contextdb_correct"));
    assert!(!names.contains("contextdb_propose_memory"));
    assert!(!names.contains("contextdb_export"));
    assert!(!names.contains("contextdb_import"));
    assert!(
        names
            .iter()
            .all(|name| !name.contains("backup") && !name.contains("restore")),
        "database-global operator recovery must never be an MCP tool"
    );
    assert!(responses[2]["error"].is_null(), "{:#}", responses[2]);
    assert_eq!(
        responses[2]["result"]["structuredContent"]["code"],
        "format_incompatible"
    );

    let mut admin_command = Command::new(binary);
    admin_command
        .arg("mcp")
        .arg(&archive)
        .args([
            "--actor-id",
            "actor:alice",
            "--agent-id",
            "agent:subprocess",
            "--workspace-id",
            "workspace:subprocess",
            "--subject-id",
            "subject:alice",
            "--purpose",
            "contextdb:admin",
            "--session-id",
            "session:subprocess-admin",
            "--audience",
            "subject:alice",
            "--scope",
            "project:subprocess",
            "--capability",
            "admin",
            "--clearance",
            "restricted",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    authority.configure(&mut admin_command);
    let mut admin_child = admin_command.spawn().expect("spawn admin MCP child");
    let mut admin_stdin = admin_child.stdin.take().expect("admin MCP stdin");
    let verify = serde_json::json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "contextdb_verify",
            "arguments": {
                "context": mcp_admin_semantic_context("request:mcp-verify"),
                "deep": false
            },
            "_meta": meta
        }
    });
    serde_json::to_writer(&mut admin_stdin, &verify).expect("admin MCP JSON");
    admin_stdin.write_all(b"\n").expect("admin MCP newline");
    drop(admin_stdin);
    let admin_output = admin_child.wait_with_output().expect("admin MCP output");
    assert!(admin_output.status.success());
    let admin_response: serde_json::Value = serde_json::from_slice(
        admin_output
            .stdout
            .strip_suffix(b"\n")
            .expect("newline-delimited admin response"),
    )
    .expect("admin MCP response");
    assert!(admin_response["error"].is_null(), "{admin_response:#}");
    assert_eq!(admin_response["result"]["isError"], false);
    assert_eq!(admin_response["result"]["structuredContent"]["valid"], true);

    for output in [begun, pinned, preflighted, output, admin_output] {
        for bytes in [output.stdout, output.stderr] {
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(TOKEN));
            assert!(!text.contains(&"44".repeat(32)));
            assert!(!text.contains("x-contextdb-gateway"));
        }
    }
    stop_memory_mcp(binary, &authority, &archive);
}
