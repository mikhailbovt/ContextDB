use super::*;

#[path = "native_encrypted/fail_closed.rs"]
mod fail_closed;

const MASTER: &str = "5959595959595959595959595959595959595959595959595959595959595959";
const WRONG_MASTER: &str = "6161616161616161616161616161616161616161616161616161616161616161";
const SECRET: &str = "encrypted-native-private-bluebird-7319";

struct Fixture {
    authority: TestAuthority,
    archive: PathBuf,
    custody: PathBuf,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("isolated operator fixture");
        let host = directory.path().join("host");
        std::fs::create_dir(&host).expect("host directory");
        let fixture = Self {
            authority: TestAuthority::new(&host),
            archive: host.join("encrypted.ctxb"),
            custody: directory.path().join("custody"),
            directory,
        };
        success(&fixture.run(&["--json", "init", path(&fixture.archive)], None));
        fixture
    }

    fn command(&self, arguments: &[&str], master: Option<&str>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_contextdb"));
        command.args(arguments);
        self.authority.configure(&mut command);
        command.env_remove("CONTEXTDB_NATIVE_MASTER_KEY_HEX");
        if let Some(master) = master {
            command.env("CONTEXTDB_NATIVE_MASTER_KEY_HEX", master);
        }
        command
    }

    fn run(&self, arguments: &[&str], master: Option<&str>) -> Output {
        self.command(arguments, master)
            .output()
            .expect("actual operator CLI")
    }

    fn provision(&self) -> serde_json::Value {
        success(&self.run(
            &[
                "--json",
                "codex-native-init",
                path(&self.archive),
                "--custody-root",
                path(&self.custody),
            ],
            Some(MASTER),
        ))
    }

    fn native(&self) -> PathBuf {
        PathBuf::from(format!("{}.native-fjall", self.archive.display()))
    }

    fn profile(&self) -> PathBuf {
        PathBuf::from(format!("{}.native-profile.json", self.archive.display()))
    }

    fn mcp(&self, request: &serde_json::Value, master: Option<&str>) -> Output {
        self.mcp_mode(request, master, false)
    }

    fn mcp_mode(
        &self,
        request: &serde_json::Value,
        master: Option<&str>,
        reference: bool,
    ) -> Output {
        let mut command = self.command(
            &[
                "mcp",
                path(&self.archive),
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
            ],
            master,
        );
        if reference {
            command.arg("--reference");
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        send_one_mcp_request(command.spawn().expect("normal MCP subprocess"), request)
    }

    fn call(&self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        let output = self.mcp(&rpc(name, arguments), Some(MASTER));
        no_key_disclosure(&output);
        let response = decoded_mcp_output(&output);
        assert!(response["error"].is_null(), "{response:#}");
        assert_eq!(response["result"]["isError"], false, "{response:#}");
        response["result"]["structuredContent"].clone()
    }

    fn broker(&self) -> BrokerChild {
        let mut command = self.command(&["mcp-broker", path(&self.archive)], Some(MASTER));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = BrokerChild(command.spawn().expect("owned encrypted broker subprocess"));
        let mut reader = BufReader::new(child.0.stderr.take().expect("broker readiness"));
        let mut readiness = String::new();
        reader
            .read_line(&mut readiness)
            .expect("actual broker readiness");
        assert_eq!(
            readiness.trim(),
            "contextdb MCP broker ready",
            "{readiness}"
        );
        child
    }

    fn stop(&self, broker: &mut BrokerChild) {
        let output = self.run(&["mcp-broker-stop", path(&self.archive)], Some(MASTER));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        broker.wait_for_exit();
    }

    fn backup(&self, name: &str) -> (PathBuf, Output) {
        let destination = self.directory.path().join(name);
        let output = self.run(
            &[
                "--json",
                "codex-backup",
                path(&self.archive),
                path(&destination),
            ],
            Some(MASTER),
        );
        (destination, output)
    }
}

fn path(path: &Path) -> &str {
    path.to_str().expect("fixture path")
}

fn no_key_disclosure(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(TOKEN) && !text.contains(MASTER) && !text.contains(WRONG_MASTER));
    }
}

fn success(output: &Output) -> serde_json::Value {
    no_key_disclosure(output);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("operator JSON response")
}

fn refused(output: &Output) {
    no_key_disclosure(output);
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn rpc(name: &str, arguments: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":name,"arguments":arguments,"_meta":mcp_meta()}})
}

fn proposal() -> serde_json::Value {
    serde_json::json!({"context":memory_semantic_context("encrypted-proposal"),
        "identity_key":"project|repo=d:/develop/contextdb-encrypted-acceptance",
        "semantic_kind":"project","value":{"text":SECRET},"search_text":SECRET,
        "parent_candidate_ids":[],"supersedes_candidate_ids":[]})
}

fn observation() -> serde_json::Value {
    serde_json::json!({"context":memory_semantic_context("encrypted-observation"),
        "idempotency_key":"encrypted-observation","observation_id":"observation:encrypted-native",
        "metadata":{"source":"actual-cli-acceptance"},"content":{"text":SECRET},
        "access":{"workspace_id":"workspace:memory-subprocess","scopes":["project:memory-subprocess"],
            "owners":["subject:alice"],"audience":["subject:alice"],"audience_purpose_grants":{},
            "purposes":["conversation"],"sensitivity":"private","consent":"granted","retrievable":true}})
}

fn recall(fixture: &Fixture, candidate: &str) {
    let recalled = fixture.call(
        "contextdb_recall_candidates",
        serde_json::json!({
        "context":memory_semantic_context("encrypted-recall"),"query":SECRET,
        "semantic_kinds":["project"],"page_size":5,"at_commit":null}),
    );
    assert_eq!(recalled["hits"][0]["candidate_id"], candidate);
    let read = fixture.call("contextdb_get_candidate", serde_json::json!({
        "context":memory_semantic_context("encrypted-read"),"record_id":candidate,"at_commit":null}));
    assert!(
        serde_json::to_string(&read)
            .expect("candidate JSON")
            .contains(SECRET)
    );
}

fn assert_no_plaintext(directory: &Path) {
    for entry in std::fs::read_dir(directory).expect("owned native directory") {
        let entry = entry.expect("native entry");
        if entry.file_type().expect("native type").is_dir() {
            assert_no_plaintext(&entry.path());
        } else {
            let bytes = std::fs::read(entry.path()).expect("native fixture bytes");
            assert!(
                !bytes
                    .windows(SECRET.len())
                    .any(|window| window == SECRET.as_bytes())
            );
        }
    }
}

fn head_bytes(f: &Fixture) -> Vec<u8> {
    #[cfg(windows)]
    {
        let name = format!(
            "Software\\ContextDB\\StateHeads\\{}",
            blake3::hash(f.authority.selector.as_bytes()).to_hex()
        );
        let key = winreg::HKCU
            .open_subkey(name)
            .expect("isolated test authority");
        key.get_value::<String, _>("authority")
            .expect("authority envelope")
            .into_bytes()
    }
    #[cfg(unix)]
    std::fs::read(&f.authority.head).expect("isolated test authority")
}

fn write_head(f: &Fixture, bytes: &[u8]) {
    #[cfg(windows)]
    {
        let name = format!(
            "Software\\ContextDB\\StateHeads\\{}",
            blake3::hash(f.authority.selector.as_bytes()).to_hex()
        );
        let key = winreg::HKCU
            .open_subkey_with_flags(name, winreg::enums::KEY_WRITE)
            .expect("isolated test authority");
        key.set_value(
            "authority",
            &std::str::from_utf8(bytes).expect("authority JSON"),
        )
        .expect("test envelope update");
    }
    #[cfg(unix)]
    std::fs::write(&f.authority.head, bytes).expect("test envelope update");
}

#[test]
fn encrypted_native_actual_mcp_reopens_and_composite_restore_preserves_memory() {
    let f = Fixture::new();
    let initialized = f.provision();
    assert_eq!(initialized["operation"], "codex_native_initialized");
    assert_eq!(initialized["profile"], "codex-native-encrypted-custody-v1");
    let head: serde_json::Value =
        serde_json::from_slice(&head_bytes(&f)).expect("external authority JSON");
    assert_eq!(head["schema_version"], 3);
    assert_eq!(head["native_profile_digest"], initialized["profile_digest"]);
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.profile()).expect("signed profile"))
            .expect("profile JSON");
    assert_eq!(profile["state"], "ready");
    assert_eq!(profile["descriptor"]["identity"]["custody_format"], 4);
    assert_eq!(profile["descriptor"]["identity"]["suppression_format"], 3);
    assert_eq!(
        profile["descriptor"]["identity"]["custody_authority"],
        initialized["custody_authority"]
    );
    assert_eq!(
        profile["descriptor"]["identity"]["suppression_authority"],
        initialized["suppression_authority"]
    );
    assert!(f.profile().is_file() && f.native().is_dir());
    assert!(f.custody.join("keys").is_dir() && f.custody.join("suppression").is_dir());
    let mut broker = f.broker();
    let observed = f.call("contextdb_observe", observation());
    assert_eq!(observed["replayed"], false);
    let proposed = f.call("contextdb_ensure_candidate", proposal());
    let candidate = proposed["candidate_id"]
        .as_str()
        .expect("actual candidate")
        .to_owned();
    recall(&f, &candidate);
    f.stop(&mut broker);
    let mut broker = f.broker();
    recall(&f, &candidate);
    let replayed = f.call("contextdb_observe", observation());
    assert_eq!(replayed["replayed"], true);
    assert_eq!(replayed["request_digest"], observed["request_digest"]);
    f.stop(&mut broker);
    assert_no_plaintext(&f.native());
    let status_request = write_json(
        f.directory.path(),
        "status.json",
        serde_json::json!({"context":authenticated("admin", "encrypted-status")}),
    );
    let status = success(&f.run(
        &[
            "--json",
            "api",
            path(&f.archive),
            "get-status",
            "--request",
            path(&status_request),
        ],
        Some(MASTER),
    ));
    assert!(status["profile"].is_string());
    let (backup, output) = f.backup("encrypted.cdb-backup");
    let receipt = success(&output);
    assert_eq!(receipt["format"], "contextdb.codex-composite-backup.v2");
    assert!(
        !std::fs::read(&backup)
            .expect("encrypted backup")
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes())
    );
    let foreign = Fixture::new();
    foreign.provision();
    let foreign_profile = std::fs::read(foreign.profile()).expect("foreign exact profile");
    refused(&foreign.run(
        &[
            "--json",
            "codex-restore",
            path(&foreign.archive),
            path(&backup),
        ],
        Some(MASTER),
    ));
    assert_eq!(
        std::fs::read(foreign.profile()).expect("foreign profile preserved"),
        foreign_profile
    );
    success(&foreign.backup("foreign-still-pristine.backup").1);
    let profile = std::fs::read(f.profile()).expect("immutable profile");
    let held = f.directory.path().join("retained-original-native");
    std::fs::rename(f.native(), &held).expect("preserve original fixture before explicit restore");
    let restored = success(&f.run(
        &["--json", "codex-restore", path(&f.archive), path(&backup)],
        Some(MASTER),
    ));
    assert_eq!(restored["format"], "contextdb.codex-composite-backup.v2");
    assert_eq!(
        std::fs::read(f.profile()).expect("profile preserved"),
        profile
    );
    let mut broker = f.broker();
    recall(&f, &candidate);
    assert_eq!(f.call("contextdb_observe", observation())["replayed"], true);
    f.stop(&mut broker);
    refused(&f.run(
        &["--json", "codex-restore", path(&f.archive), path(&backup)],
        Some(MASTER),
    ));
    assert_no_plaintext(&f.native());
}

#[test]
fn encrypted_native_running_broker_requires_current_master_and_exact_profile() {
    let f = Fixture::new();
    f.provision();
    let mut broker = f.broker();
    let candidate = f.call("contextdb_ensure_candidate", proposal())["candidate_id"]
        .as_str()
        .expect("candidate")
        .to_owned();
    let request = rpc("contextdb_session", serde_json::json!({}));
    refused(&f.mcp(&request, None));
    refused(&f.mcp(&request, Some(WRONG_MASTER)));
    refused(&f.mcp_mode(&request, Some(MASTER), true));
    let profile = std::fs::read(f.profile()).expect("profile bytes");
    let mut tampered: serde_json::Value = serde_json::from_slice(&profile).expect("profile JSON");
    tampered["token_mac"] = serde_json::json!("00".repeat(32));
    std::fs::write(
        f.profile(),
        serde_json::to_vec(&tampered).expect("tampered profile"),
    )
    .expect("tamper owned profile");
    refused(&f.mcp(&request, Some(MASTER)));
    std::fs::write(f.profile(), &profile).expect("restore owned fixture profile");
    let held = f.directory.path().join("profile-held.json");
    std::fs::rename(f.profile(), &held).expect("temporarily missing profile");
    refused(&f.mcp(&request, Some(MASTER)));
    assert!(!f.profile().exists());
    let shutdown = f.run(&["mcp-broker-stop", path(&f.archive)], None);
    no_key_disclosure(&shutdown);
    assert!(
        shutdown.status.success(),
        "token authority can quiesce a lost-profile owner"
    );
    broker.wait_for_exit();
    std::fs::rename(&held, f.profile()).expect("restore exact profile");
    let mut broker = f.broker();
    recall(&f, &candidate);
    f.stop(&mut broker);
    assert_eq!(std::fs::read(f.profile()).expect("same profile"), profile);
}

#[test]
fn encrypted_native_profile_and_authority_loss_never_bootstrap_plaintext() {
    let f = Fixture::new();
    f.provision();
    let profile = std::fs::read(f.profile()).expect("profile");
    let head = head_bytes(&f);
    let mut tampered: serde_json::Value = serde_json::from_slice(&head).expect("authority JSON");
    tampered["mac"] = serde_json::json!("00".repeat(32));
    write_head(
        &f,
        &serde_json::to_vec(&tampered).expect("tampered fixture authority"),
    );
    let (destination, output) = f.backup("tampered-authority.backup");
    refused(&output);
    assert!(!destination.exists());
    write_head(&f, &head);
    for authority in ["keys", "suppression"] {
        let original = f.custody.join(authority);
        let held = f.directory.path().join(format!("held-{authority}"));
        std::fs::rename(&original, &held).expect("temporarily missing exact custody authority");
        let (destination, output) = f.backup(&format!("missing-{authority}.backup"));
        refused(&output);
        assert!(!original.exists() && !destination.exists());
        std::fs::rename(&held, &original).expect("restore exact authority");
    }
    let held_profile = f.directory.path().join("held-profile.json");
    let held_native = f.directory.path().join("held-native");
    std::fs::rename(f.profile(), &held_profile).expect("preserve profile");
    std::fs::rename(f.native(), &held_native).expect("preserve native fixture");
    refused(&f.mcp(
        &rpc("contextdb_session", serde_json::json!({})),
        Some(MASTER),
    ));
    assert!(
        !f.profile().exists() && !f.native().exists(),
        "external pin must reject loss of both local artifacts"
    );
    std::fs::rename(&held_profile, f.profile()).expect("restore profile");
    std::fs::rename(&held_native, f.native()).expect("restore original native");
    assert_eq!(
        std::fs::read(f.profile()).expect("unchanged profile"),
        profile
    );
    success(&f.backup("after-recovery.backup").1);

    let plain = Fixture::new();
    let mut command = plain.command(&["mcp-broker", path(&plain.archive)], None);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut broker = BrokerChild(command.spawn().expect("legacy plaintext broker"));
    let mut reader = BufReader::new(broker.0.stderr.take().expect("legacy readiness"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("legacy readiness");
    assert_eq!(line.trim(), "contextdb MCP broker ready");
    let output = plain.mcp(&rpc("contextdb_ensure_candidate", proposal()), None);
    let proposed = decoded_mcp_output(&output);
    assert_eq!(proposed["result"]["isError"], false);
    let stopped = plain.run(&["mcp-broker-stop", path(&plain.archive)], None);
    assert!(stopped.status.success());
    broker.wait_for_exit();
    let (backup, output) = plain.backup("plain-compatible.backup");
    assert_eq!(
        success(&output)["format"],
        "contextdb.codex-composite-backup.v1"
    );
    assert!(backup.is_file());
    refused(&plain.run(
        &[
            "--json",
            "codex-native-init",
            path(&plain.archive),
            "--custody-root",
            path(&plain.custody),
        ],
        Some(MASTER),
    ));
    assert!(
        !plain.profile().exists() && !plain.custody.exists(),
        "existing plaintext needs explicit migration, not profile relabelling"
    );
}
