use super::*;
use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use contextdb_core::{AgentRunId, EventPayload, EventProvenance, OriginalSourceSpan};
use contextdb_native_service::{
    CustodyMasterKey, NativeCustodyKeys, NativeService, NativeSuppressionLedger,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, CapturePort, CaptureReceipt, OwnedRunPort, PayloadPort,
    ReadOriginalRequest,
};

#[path = "owned_conversation/peer.rs"]
mod peer;
use peer::Peer;

#[path = "owned_conversation/protected_trace.rs"]
mod protected_trace;

const ORIGINAL: &str = "An incidental launch note: the satellite nickname was BLUEBIRD-7319 after a maintenance meeting.";

fn config(f: &Fixture, peer: &Peer) -> (PathBuf, serde_json::Value) {
    let value = serde_json::json!({"schema_version":1,
        "identity":{"workspace_id":"10000000-0000-4000-8000-000000000001",
            "session_id":"10000000-0000-4000-8000-000000000002",
            "run_id":"10000000-0000-4000-8000-000000000003",
            "actor_id":"10000000-0000-4000-8000-000000000004",
            "agent_id":"10000000-0000-4000-8000-000000000005",
            "subject_id":"10000000-0000-4000-8000-000000000006",
            "scopes":["10000000-0000-4000-8000-000000000007"]},
        "control":"Use captured conversation context. Reply in plain visible text.",
        "input_tokens":2048,"reader":peer.config()});
    let root = std::fs::canonicalize(f.directory.path()).expect("canonical owned fixture root");
    (write_json(&root, "owned.json", value.clone()), value)
}

fn input(lines: &[serde_json::Value]) -> Vec<u8> {
    lines
        .iter()
        .flat_map(|line| {
            let mut bytes = serde_json::to_vec(line).expect("host input");
            bytes.push(b'\n');
            bytes
        })
        .collect()
}

struct HostDeadline {
    hard: Instant,
    last_answer: Instant,
    idle: Duration,
    completed: usize,
    commands: usize,
}

impl HostDeadline {
    fn new(started: Instant, idle: Duration, turn: Duration, commands: usize) -> Self {
        Self {
            hard: started + idle + turn * commands as u32,
            last_answer: started,
            idle,
            completed: 0,
            commands,
        }
    }

    fn answer(&mut self, observed: Instant) {
        if self.completed < self.commands
            && observed < self.hard
            && observed.saturating_duration_since(self.last_answer) < self.idle
        {
            self.completed += 1;
            self.last_answer = self.last_answer.max(observed);
        }
    }

    fn expired(&self, now: Instant) -> Option<&'static str> {
        if now >= self.hard {
            Some("absolute batch deadline")
        } else if now.saturating_duration_since(self.last_answer) >= self.idle {
            Some("no completed answer progress")
        } else {
            None
        }
    }
}

fn wait_host(
    child: &mut BrokerChild,
    progress: &mpsc::Receiver<Instant>,
    deadline: &mut HostDeadline,
) -> (std::process::ExitStatus, Option<&'static str>) {
    loop {
        if let Some(status) = child.0.try_wait().expect("host progress") {
            return (status, None);
        }
        for observed in progress.try_iter() {
            deadline.answer(observed);
        }
        if let Some(reason) = deadline.expired(Instant::now()) {
            // Reap before joining the pipe collectors or input writer.
            let _ = child.0.kill();
            return (child.0.wait().expect("reap timed-out host"), Some(reason));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum CompletedHostRecord {
    #[serde(rename = "answer")]
    Answer {
        output_receipt: CaptureReceipt,
        checkpoint_receipt: CaptureReceipt,
    },
}

fn host(f: &Fixture, config: &Path, resume: bool, bytes: Vec<u8>) -> Output {
    let commands = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .count();
    assert!(
        commands <= 32,
        "owned fixture batch exceeds its command bound"
    );
    let mut command = f.command(
        &[
            "--json",
            "owned-conversation",
            path(&f.archive),
            "--config",
            path(config),
            if resume { "--resume" } else { "--start" },
        ],
        Some(MASTER),
    );
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = BrokerChild(command.spawn().expect("actual owned CLI host"));
    let stdout = child.0.stdout.take().expect("host output");
    let stderr = child.0.stderr.take().expect("host error");
    let mut stdin = child.0.stdin.take().expect("host input");
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
    });
    let (progress_sender, progress) = mpsc::channel();
    let stdout = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout.take(8 * 1024 * 1024));
        let mut bytes = vec![];
        let mut answers = BTreeSet::new();
        loop {
            let start = bytes.len();
            if reader
                .read_until(b'\n', &mut bytes)
                .expect("bounded host output")
                == 0
            {
                break;
            }
            if answers.len() < commands
                && bytes.last() == Some(&b'\n')
                && let Ok(CompletedHostRecord::Answer {
                    output_receipt,
                    checkpoint_receipt,
                }) = serde_json::from_slice(&bytes[start..])
                && output_receipt.domain == contextdb_service::NATIVE_CAPTURE_DOMAIN
                && checkpoint_receipt.domain == contextdb_service::NATIVE_CAPTURE_DOMAIN
                && output_receipt.workspace_commit > 0
                && checkpoint_receipt.workspace_commit > output_receipt.workspace_commit
                && answers.insert(output_receipt.event_id)
            {
                // Only complete, distinct answer records advance the guard.
                // The exact wire and owner receipts are still checked below.
                let _ = progress_sender.send(Instant::now());
            }
        }
        bytes
    });
    let stderr = std::thread::spawn(move || {
        let mut bytes = vec![];
        stderr
            .take(8 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .expect("bounded host error");
        bytes
    });
    // A batch has separately bounded turns. Completed answers may renew the
    // inactivity guard, but never its finite command-derived absolute ceiling.
    let started = Instant::now();
    let mut deadline = HostDeadline::new(
        started,
        Duration::from_secs(180),
        Duration::from_secs(30),
        commands,
    );
    let (status, timeout) = wait_host(&mut child, &progress, &mut deadline);
    writer.join().expect("host input writer");
    let output = Output {
        status,
        stdout: stdout.join().expect("host stdout"),
        stderr: stderr.join().expect("host stderr"),
    };
    for observed in progress.try_iter() {
        deadline.answer(observed);
    }
    eprintln!(
        "owned host: resume={resume}, elapsed_ms={}, status={}, completed_answers={}",
        started.elapsed().as_millis(),
        output.status,
        deadline.completed
    );
    no_key_disclosure(&output);
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains("BLUEBIRD-7319") && !text.contains("bridge-private-sentinel-7319"),
            "private source/protocol bytes must not be dumped into host diagnostics"
        );
    }
    assert!(
        timeout.is_none(),
        "owned CLI timeout: reason={}, completed_answers={}, commands={}, elapsed_ms={}",
        timeout.unwrap_or("none"),
        deadline.completed,
        commands,
        started.elapsed().as_millis()
    );
    output
}

fn records(output: &Output) -> Vec<serde_json::Value> {
    String::from_utf8(output.stdout.clone())
        .expect("JSONL host output")
        .lines()
        .map(|line| serde_json::from_str(line).expect("host emits only compact JSONL"))
        .collect()
}

fn require_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn owned_host_guard_bounds_progress_and_reaps_a_stalled_process() {
    let started = Instant::now();
    let mut deadline = HostDeadline::new(
        started,
        Duration::from_secs(180),
        Duration::from_secs(30),
        2,
    );
    deadline.answer(started + Duration::from_secs(170));
    deadline.answer(started + Duration::from_secs(200));
    assert_eq!(deadline.completed, 2);
    assert_eq!(deadline.expired(started + Duration::from_secs(220)), None);
    let last = deadline.last_answer;
    deadline.answer(started + Duration::from_secs(239));
    assert_eq!(
        deadline.last_answer, last,
        "excess answers cannot renew the guard"
    );
    assert_eq!(
        deadline.expired(started + Duration::from_secs(240)),
        Some("absolute batch deadline")
    );
    let idle = HostDeadline::new(
        started,
        Duration::from_secs(180),
        Duration::from_secs(30),
        2,
    );
    assert_eq!(
        idle.expired(started + Duration::from_secs(180)),
        Some("no completed answer progress")
    );
    for record in [
        br#"{"type":"ready"}"#.as_slice(),
        br#"{"type":"accepted"}"#.as_slice(),
        br#"{"type":"answer","output_receipt":{}}"#.as_slice(),
    ] {
        assert!(serde_json::from_slice::<CompletedHostRecord>(record).is_err());
    }

    // Exercise the real wait/kill/wait path, including an open stdout pipe.
    // This child is only a lifecycle fixture and never acts as a reader.
    let fixture = Fixture::new();
    let peer = Peer::new(&fixture, "reply");
    let mut child = BrokerChild(
        Command::new(&peer.python)
            .args([
                "-I",
                "-u",
                "-c",
                "import os, time; os.write(1, b'guard-ready\\n'); time.sleep(60)",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("stalled lifecycle child"),
    );
    let stdout = child.0.stdout.take().expect("lifecycle pipe");
    let (ready_sender, ready) = mpsc::channel();
    let collector = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout.take(64));
        let mut bytes = vec![];
        reader
            .read_until(b'\n', &mut bytes)
            .expect("lifecycle ready");
        ready_sender.send(()).expect("lifecycle readiness");
        reader
            .read_to_end(&mut bytes)
            .expect("closed lifecycle pipe");
        bytes
    });
    ready
        .recv_timeout(Duration::from_secs(5))
        .expect("child entered its stall");
    let (_sender, progress) = mpsc::channel();
    let before = Instant::now();
    let mut stalled = HostDeadline::new(
        before,
        Duration::from_millis(100),
        Duration::from_millis(100),
        2,
    );
    let (status, timeout) = wait_host(&mut child, &progress, &mut stalled);
    assert_eq!(timeout, Some("no completed answer progress"));
    assert!(!status.success());
    assert!(
        child
            .0
            .try_wait()
            .expect("reaped lifecycle child")
            .is_some()
    );
    assert_eq!(
        collector.join().expect("lifecycle collector"),
        b"guard-ready\n"
    );
    assert!(before.elapsed() < Duration::from_secs(5));
}

fn context(config: &serde_json::Value) -> AuthenticatedRequestContext {
    let identity = &config["identity"];
    serde_json::from_value(serde_json::json!({"request":{"request_id":"owned-subprocess-audit",
        "workspace_id":identity["workspace_id"],"subject_id":identity["subject_id"],
        "audiences":[identity["subject_id"]],"scopes":identity["scopes"],"purpose":"conversation","clearance":"private"},
        "actor_id":identity["actor_id"],"agent_id":identity["agent_id"],"session_id":identity["session_id"],
        "capability_grants":["runtime","admin","observe","recall","read_evidence","raw_evidence","read_memory","read_conflict","maintenance"],
        "authentication":{"kind":"authenticated_channel","channel_id":"owned-subprocess-audit",
            "peer_identity":identity["actor_id"],"binding_digest":"aa".repeat(32)}})).expect("owned fixture audit grant")
}

fn native(f: &Fixture) -> Arc<NativeService> {
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.profile()).expect("pinned profile"))
            .expect("profile JSON");
    let identity = &profile["descriptor"]["identity"];
    let database = identity["database_id"].as_str().expect("native database");
    let key_id: contextdb_core::ObservationId =
        serde_json::from_value(identity["custody_authority"].clone()).expect("key id");
    let suppression_id: contextdb_core::ObservationId =
        serde_json::from_value(identity["suppression_authority"].clone()).expect("ledger id");
    let keys = NativeCustodyKeys::open(
        f.custody.join("keys"),
        database,
        key_id.as_uuid(),
        CustodyMasterKey::from_zeroizing(zeroize::Zeroizing::new([0x59; 32]))
            .expect("fixture master"),
    )
    .expect("retained keys");
    let suppression = NativeSuppressionLedger::open(
        f.custody.join("suppression"),
        database,
        suppression_id.as_uuid(),
    )
    .expect("retained ledger");
    Arc::new(
        NativeService::open_encrypted_existing(f.native(), database, [0x37; 32], suppression, keys)
            .expect("cold native audit"),
    )
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}

fn checkpoint(
    owner: &NativeService,
    config: &serde_json::Value,
) -> contextdb_service::SavedRunCheckpoint {
    let run: AgentRunId =
        serde_json::from_value(config["identity"]["run_id"].clone()).expect("run id");
    owner
        .load_run_checkpoint(&context(config), run, &mut budget())
        .expect("read current checkpoint")
        .expect("durable owned run")
}

fn verify_answer(
    owner: &NativeService,
    config: &serde_json::Value,
    answer: &serde_json::Value,
    sends: &[serde_json::Value],
) -> contextdb_core::ModelRequestManifest {
    let ctx = context(config);
    let output: CaptureReceipt =
        serde_json::from_value(answer["output_receipt"].clone()).expect("output receipt");
    owner
        .resolve_capture_receipt(&ctx, &output)
        .expect("actual output receipt");
    let original = owner
        .read_original(ReadOriginalRequest {
            context: ctx.clone(),
            event_id: output.event_id,
            after_receipt: Some(output),
        })
        .expect("captured model output");
    assert_eq!(
        original.event.payload.original_bytes(),
        Some(b"Visible deterministic reply.".as_slice())
    );
    let Some(EventProvenance::ModelOutput {
        model_call_id,
        request_event_id,
        ..
    }) = original.event.provenance
    else {
        panic!("visible response must retain exact request occurrence");
    };
    let request = owner
        .read_original(ReadOriginalRequest {
            context: ctx.clone(),
            event_id: request_event_id,
            after_receipt: None,
        })
        .expect("captured request manifest");
    let EventPayload::Assembly { manifest } = request.event.payload else {
        panic!("exact request manifest");
    };
    assert_eq!(manifest.model_call_id, model_call_id);
    let replayed = owner
        .read_original_span(
            &ctx,
            &OriginalSourceSpan {
                event_id: request_event_id,
                payload_digest: manifest.wire_digest,
                start: 0,
                end: manifest.byte_length,
                span_digest: manifest.wire_digest,
            },
        )
        .expect("reconstruct captured wire from original source parts");
    let sent = sends
        .iter()
        .find(|sent| sent["request"]["call"] == serde_json::json!(model_call_id))
        .expect("actual dispatch");
    let wire: Vec<u8> = serde_json::from_value(sent["request"]["outgoing"]["wire"].clone())
        .expect("observed sent bytes");
    assert_eq!(replayed, wire);
    assert_eq!(
        manifest.wire_digest.as_bytes(),
        blake3::hash(&wire).as_bytes()
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&wire).expect("actual ChatML JSON wire");
    use contextdb_context::TokenCounter;
    assert_eq!(
        contextdb_context::ReferenceTokenizer
            .count_tokens(payload["prompt"].as_str().expect("full prompt"))
            .expect("exact fixture count"),
        sent["request"]["outgoing"]["input_tokens"]
            .as_u64()
            .expect("input count") as u32
    );
    manifest
}

#[test]
fn owned_conversation_actual_rolling_cold_resume_replays_original_and_exact_wire() {
    let f = Fixture::new();
    f.provision();
    let peer = Peer::new(&f, "reply");
    let (config_path, config) = config(&f, &peer);
    let mut lines = vec![serde_json::json!({"type":"user","text":ORIGINAL})];
    for index in 0..20 {
        lines.push(
            serde_json::json!({"type":"user","text":format!("Routine shift {index}. {}",
            "Valves stable; pressure nominal; maintenance scheduling unchanged. ".repeat(25))}),
        );
    }
    let first = host(&f, &config_path, false, input(&lines));
    require_success(&first);
    let first_records = records(&first);
    let first_receipt: CaptureReceipt = serde_json::from_value(
        first_records
            .iter()
            .find(|item| item["type"] == "accepted")
            .expect("first user captured")["source_receipt"]
            .clone(),
    )
    .expect("first source receipt");
    assert_eq!(peer.sends().len(), 21);
    let rotations = first_records
        .iter()
        .filter(|item| item["type"] == "answer")
        .flat_map(|item| {
            item["measurements"]["steps"]
                .as_array()
                .expect("measured steps")
        })
        .filter(|step| step["evicted_groups"].as_u64().unwrap_or(0) > 0)
        .count();
    assert!(rotations > 0);
    {
        let owner = native(&f);
        let original = owner
            .read_original(ReadOriginalRequest {
                context: context(&config),
                event_id: first_receipt.event_id,
                after_receipt: Some(first_receipt.clone()),
            })
            .expect("first durable original");
        assert_eq!(
            original.event.payload.original_bytes(),
            Some(ORIGINAL.as_bytes())
        );
        let saved = checkpoint(&owner, &config);
        assert!(
            !saved
                .checkpoint
                .groups
                .iter()
                .flat_map(|group| &group.messages)
                .any(|message| message.source.event_id == first_receipt.event_id),
            "first original must leave resident history"
        );
        for answer in first_records.iter().filter(|item| item["type"] == "answer") {
            verify_answer(&owner, &config, answer, &peer.sends());
        }
    }
    let resumed = host(
        &f,
        &config_path,
        true,
        input(&[
            serde_json::json!({"type":"user","text":"Which satellite nickname came up near the start of our conversation?"}),
            serde_json::json!({"type":"finish"}),
        ]),
    );
    require_success(&resumed);
    let answers = records(&resumed);
    assert_eq!(peer.sends().len(), 22);
    let sent = peer.sends();
    let wire: Vec<u8> = serde_json::from_value(
        sent.last().expect("last request")["request"]["outgoing"]["wire"].clone(),
    )
    .expect("sent wire");
    let payload: serde_json::Value = serde_json::from_slice(&wire).expect("last wire JSON");
    if let Some(directory) = std::env::var_os("CONTEXTDB_TEST_EVIDENCE_DIR") {
        std::fs::write(PathBuf::from(directory).join("owned-last-wire.json"), &wire)
            .expect("requested fixture wire evidence");
    }
    let owner = native(&f);
    let answer = answers
        .iter()
        .find(|item| item["type"] == "answer")
        .expect("resumed answer");
    let manifest = verify_answer(&owner, &config, answer, &sent);
    let original_parts: Vec<_> = manifest
        .parts
        .iter()
        .filter_map(|part| match part {
            contextdb_core::RequestPart::Source { span }
            | contextdb_core::RequestPart::JsonStringSource { span, .. }
                if span.event_id == first_receipt.event_id =>
            {
                Some((span.start, span.end))
            }
            _ => None,
        })
        .collect();
    let nickname_present = payload["prompt"]
        .as_str()
        .expect("sent full prompt")
        .contains("BLUEBIRD-7319");
    eprintln!(
        "owned fixture: rotations={rotations}, sends={}, nickname_present={nickname_present}, first_source_spans={original_parts:?}",
        sent.len()
    );
    peer.assert_reaped();
    if (!nickname_present || original_parts.is_empty())
        && let Some(directory) = std::env::var_os("CONTEXTDB_TEST_EVIDENCE_DIR")
    {
        let retained = f.directory.keep();
        std::fs::write(
            PathBuf::from(directory).join("owned-last-fixture-path.txt"),
            retained.to_string_lossy().as_bytes(),
        )
        .expect("retain requested source-omission diagnostic fixture");
    }
    assert!(
        nickname_present,
        "old incidental nickname must reach the actual sent wire"
    );
    assert!(manifest.parts.iter().any(|part| matches!(part,
        contextdb_core::RequestPart::Source {span} | contextdb_core::RequestPart::JsonStringSource {span,..}
            if span.event_id == first_receipt.event_id)),"archive original must reach captured outgoing manifest");
    let saved = checkpoint(&owner, &config);
    assert_eq!(
        saved.checkpoint.status,
        contextdb_continuity::OwnedRunStatus::Completed
    );
    assert_eq!(
        serde_json::json!(saved.receipt),
        answers.last().expect("finished checkpoint")["checkpoint_receipt"]
    );
    assert_eq!(answer["measurements"]["prior_process_unmeasured"], true);
    assert!(
        rotations >= 3,
        "require three automatic rotation occurrences, observed {rotations}"
    );
    for record in peer
        .records()
        .iter()
        .filter(|record| record["request"]["op"] == "process_environment")
    {
        assert_eq!(record["request"]["contains_token"], false);
        assert_eq!(record["request"]["contains_master"], false);
    }
    peer.assert_reaped();
}

#[test]
fn owned_conversation_unknown_send_never_repeats_on_cold_resume_and_children_end() {
    for mode in ["lost", "large", "deadline", "invalid_partial"] {
        let f = Fixture::new();
        f.provision();
        let peer = Peer::new(&f, mode);
        let (config_path, config) = config(&f, &peer);
        let before = Instant::now();
        let failed = host(
            &f,
            &config_path,
            false,
            input(&[serde_json::json!({"type":"user","text":"A fresh visible request."})]),
        );
        assert!(
            !failed.status.success(),
            "uncertain reader response cannot become a complete turn"
        );
        assert!(
            before.elapsed() < Duration::from_secs(15),
            "bounded private reader termination in {mode}"
        );
        assert_eq!(
            peer.sends().len(),
            1,
            "one actual dispatch before uncertainty in {mode}"
        );
        assert!(records(&failed).iter().all(|item| item["type"] != "answer"));
        peer.assert_reaped();
        {
            let owner = native(&f);
            let saved = checkpoint(&owner, &config);
            let pending = saved
                .checkpoint
                .pending_model
                .expect("exact uncertain attempt remains durable");
            assert!(pending.wire_digest.is_some());
            if matches!(mode, "large" | "invalid_partial") {
                let original = owner
                    .read_original(ReadOriginalRequest {
                        context: context(&config),
                        event_id: pending
                            .interrupted_output
                            .expect("available protocol prefix retained"),
                        after_receipt: None,
                    })
                    .expect("aborted original");
                assert_eq!(
                    original.event.kind,
                    contextdb_core::EventKind::ModelResponseAborted
                );
                owner
                    .resolve_capture_receipt(&context(&config), &original.receipt)
                    .expect("aborted bytes have an actual source receipt");
                assert!(
                    original
                        .event
                        .payload
                        .original_bytes()
                        .expect("actual partial bytes")
                        .len()
                        <= 256 * 1024
                );
                if mode == "invalid_partial" {
                    let protocol: serde_json::Value = serde_json::from_slice(
                        original
                            .event
                            .payload
                            .original_bytes()
                            .expect("actual private response"),
                    )
                    .expect("observed invalid private response retained without execution");
                    assert_eq!(
                        protocol["text"],
                        "bridge-private-sentinel-7319 visible observed bytes"
                    );
                    assert_eq!(protocol["partial"]["media_type"], "unsupported");
                }
            }
        }
        let resumed = host(
            &f,
            &config_path,
            true,
            input(&[serde_json::json!({"type":"continue"})]),
        );
        assert!(
            !resumed.status.success(),
            "unknown provider outcome remains stopped"
        );
        assert_eq!(records(&resumed)[0]["model_outcome_unknown"], true);
        assert_eq!(
            peer.sends().len(),
            1,
            "cold continuation must never dispatch the uncertain wire again"
        );
        peer.assert_reaped();
    }
}

#[test]
fn owned_conversation_authority_loss_and_real_restore_pending_send_nothing() {
    let f = Fixture::new();
    f.provision();
    let peer = Peer::new(&f, "reply");
    let (config_path, _) = config(&f, &peer);
    let user =
        input(&[serde_json::json!({"type":"user","text":"Must stay within current custody."})]);
    for authority in ["keys", "suppression"] {
        let original = f.custody.join(authority);
        let held = f.directory.path().join(format!("held-owned-{authority}"));
        std::fs::rename(&original, &held).expect("preserve exact authority");
        let refused = host(&f, &config_path, false, user.clone());
        std::fs::rename(&held, &original).expect("restore exact authority");
        assert!(!refused.status.success());
        assert!(
            peer.records().is_empty(),
            "host custody must be verified before reader process start"
        );
    }
    let (good, output) = f.backup("before-owned-pending.backup");
    success(&output);
    let bad = f.directory.path().join("owned-corrupt-inner.backup");
    std::fs::write(
        &bad,
        fail_closed::corrupt_inner_footer(std::fs::read(&good).expect("native backup")),
    )
    .expect("owned corruption fixture");
    std::fs::rename(f.native(), f.directory.path().join("owned-retained-native"))
        .expect("preserve original native");
    refused(&f.run(
        &["--json", "codex-restore", path(&f.archive), path(&bad)],
        Some(MASTER),
    ));
    let output = host(&f, &config_path, false, user);
    assert!(!output.status.success());
    assert!(
        peer.records().is_empty(),
        "external incomplete restore must reject before any reader invocation"
    );
}

#[test]
fn owned_conversation_bounded_stdin_refuses_without_model_disclosure() {
    let f = Fixture::new();
    f.provision();
    let peer = Peer::new(&f, "reply");
    let (config_path, config) = config(&f, &peer);
    let injected = host(
        &f,
        &config_path,
        false,
        input(&[
            serde_json::json!({"type":"user","text":"BLUEBIRD-7319 private input",
        "config":{"reader":{"program":"untrusted-input-program"}},"capability_grants":["admin"],"checkpoint":{"revision":999}}),
        ]),
    );
    assert!(!injected.status.success());
    assert!(
        records(&injected)
            .iter()
            .all(|item| item["type"] != "accepted")
    );
    assert!(
        peer.sends().is_empty(),
        "conversation input cannot inject host configuration or authority"
    );
    let mut bytes = b"{\"type\":\"user\",\"text\":\"BLUEBIRD-7319 ".to_vec();
    bytes.extend(std::iter::repeat_n(b'x', 3 * 1024 * 1024));
    bytes.extend_from_slice(b"\"}\n");
    let output = host(&f, &config_path, true, bytes);
    assert!(!output.status.success());
    assert!(peer.sends().is_empty());
    assert!(output.stdout.len() + output.stderr.len() < 64 * 1024);
    let owner = native(&f);
    assert!(checkpoint(&owner, &config).checkpoint.groups.is_empty());
    peer.assert_reaped();
}
