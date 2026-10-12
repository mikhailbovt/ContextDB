//! Actual host/encoder lifecycle proof with a constant scripted reader, not an eval.

use super::*;
use contextdb_agent_runtime::{LocalEmbeddingConfig, embedding_backend_artifacts_digest};
use contextdb_core::{
    ContentDigest, EVENT_ENVELOPE_VERSION, EventCoverage, EventEnvelope, EventKind, EventRole,
    ObservationId, ROUTER_REPLAY_TRACE_VERSION, RequestPart, SessionId, SourceId, StreamId,
    TimestampMicros, WorkspaceId,
};
use contextdb_service::{
    AcceptedRouterTracePort, AcceptedRouterTraceReadResult, CaptureRequest, CognitiveMemoryService,
    ErrorCode, OwnedHybridLimits, ReadAcceptedRouterTraceRequest, ServiceError,
    TextEmbeddingProfile, VerifyRequest,
};
use std::net::{Ipv4Addr, TcpListener};

fn encoder_config() -> LocalEmbeddingConfig {
    let path = std::env::var_os("CONTEXTDB_DENSE_ENCODER_CONFIG")
        .expect("explicit provisioned encoder configuration");
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .expect("pinned host encoder configuration")
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .expect("bounded encoder configuration read");
    assert!(bytes.len() <= 64 * 1024);
    let config: LocalEmbeddingConfig =
        serde_json::from_slice(&bytes).expect("trusted encoder configuration");
    assert_eq!(config.port, 18768, "dedicated provisioned proof endpoint");
    config
}

fn endpoint_released(port: u16) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .expect("owned encoder endpoint must be released when CLI exits");
    drop(listener);
}

fn capture_archive(f: &Fixture, config: &serde_json::Value) -> CaptureReceipt {
    let owner = native(f);
    let ctx = context(config);
    let event = EventEnvelope {
        version: EVENT_ENVELOPE_VERSION,
        event_id: ObservationId::new(),
        workspace_id: ctx
            .request
            .workspace_id
            .parse::<WorkspaceId>()
            .expect("workspace"),
        scope_ids: ctx
            .request
            .scopes
            .iter()
            .map(|scope| scope.parse().expect("scope"))
            .collect(),
        producer_id: StreamId::new(),
        producer_sequence: 1,
        kind: EventKind::MessageCreated,
        recorded_at: TimestampMicros(1_000_000),
        observed_at: None,
        source_id: SourceId::new(),
        source_version: None,
        adapter_id: "owned-cli-hybrid-source-fixture".into(),
        role: EventRole::User,
        session_id: Some(
            ctx.session_id
                .as_ref()
                .expect("session")
                .parse::<SessionId>()
                .expect("session"),
        ),
        run_id: None,
        task_id: None,
        parent_event_ids: BTreeSet::new(),
        supersedes_event_id: None,
        payload: EventPayload::InlineUtf8 {
            text: ORIGINAL.into(),
            digest: ContentDigest::from_bytes(*blake3::hash(ORIGINAL.as_bytes()).as_bytes()),
        },
        coverage: EventCoverage::CompleteObservation,
        upstream_truncated: false,
        gap_reason: None,
        response_stream: None,
        provenance: None,
    };
    let receipt = owner
        .append_event(CaptureRequest {
            context: ctx.clone(),
            idempotency_key: "owned-cli-hybrid-archived-original".into(),
            event,
        })
        .expect("same encrypted owner's actual archived original");
    let captured = owner
        .read_original(ReadOriginalRequest {
            context: ctx,
            event_id: receipt.event_id,
            after_receipt: Some(receipt.clone()),
        })
        .expect("archive receipt and current policy");
    assert_eq!(
        captured.event.payload.original_bytes(),
        Some(ORIGINAL.as_bytes())
    );
    owner
        .verify(VerifyRequest {
            context: context(config).request,
            deep: true,
        })
        .expect("seeded encrypted source integrity");
    receipt
}

fn index(f: &Fixture, config: &Path, bootstrap: bool) -> Output {
    let mut command = f.command(
        &[
            "--json",
            "owned-hybrid-index",
            path(&f.archive),
            "--config",
            path(config),
            if bootstrap {
                "--bootstrap"
            } else {
                "--continue"
            },
        ],
        Some(MASTER),
    );
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = BrokerChild(command.spawn().expect("actual owned index CLI"));
    let stdout = child.0.stdout.take().expect("index stdout");
    let stderr = child.0.stderr.take().expect("index stderr");
    let stdout = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .expect("bounded index output");
        bytes
    });
    let stderr = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .expect("bounded index error");
        bytes
    });
    let (_sender, progress) = mpsc::channel();
    // Startup120s, operation60s, shutdown10s plus finite scheduler headroom.
    let mut deadline =
        HostDeadline::new(Instant::now(), Duration::from_secs(210), Duration::ZERO, 0);
    let (status, timeout) = wait_host(&mut child, &progress, &mut deadline);
    let output = Output {
        status,
        stdout: stdout.join().expect("index stdout collector"),
        stderr: stderr.join().expect("index stderr collector"),
    };
    assert!(
        timeout.is_none(),
        "index CLI exceeded its finite process guard"
    );
    assert!(output.stdout.len() <= 1024 * 1024 && output.stderr.len() <= 1024 * 1024);
    no_key_disclosure(&output);
    output
}

fn verify_hybrid(
    owner: &NativeService,
    config: &serde_json::Value,
    answer: &serde_json::Value,
    sends: &[serde_json::Value],
    archive: &CaptureReceipt,
    profile: &TextEmbeddingProfile,
    graph_digest: &serde_json::Value,
) -> serde_json::Value {
    let manifest = verify_answer(owner, config, answer, sends);
    assert!(
        manifest.parts.iter().any(|part| matches!(part,
        RequestPart::Source { span } | RequestPart::JsonStringSource { span, .. }
            if span.event_id == archive.event_id)),
        "archived original reaches the exact sent wire"
    );
    let trace = manifest
        .router_trace
        .as_ref()
        .expect("actual protected replay attachment");
    assert_eq!(trace.header.version, ROUTER_REPLAY_TRACE_VERSION);
    trace
        .validate_for_model_request(&manifest)
        .expect("protected call and wire binding");
    let retained: serde_json::Value =
        serde_json::from_str(&trace.canonical_json().expect("complete protected pages"))
            .expect("actual accepted envelope");
    assert_eq!(retained["format"], "contextdb.native_router_trace.v2");
    let observation = &retained["owned_hybrid"];
    assert_eq!(observation["embedding_profile"], serde_json::json!(profile));
    assert_eq!(
        observation["profile_digest"],
        serde_json::json!(profile.digest().expect("profile digest"))
    );
    assert_eq!(
        observation["vector"]["profile_digest"],
        observation["profile_digest"]
    );
    assert_eq!(observation["vector"]["kind"], "query");
    let preflights = observation["preflights"]
        .as_array()
        .expect("observed preflights");
    assert!(!preflights.is_empty() && preflights.len() <= 4);
    let final_tokens = &preflights.last().expect("final admitted sample")["tokens"];
    assert_eq!(
        final_tokens["token_count"],
        observation["vector"]["token_count"]
    );
    assert_eq!(
        final_tokens["tokens_digest"],
        observation["vector"]["tokens_digest"]
    );
    assert!(
        final_tokens["token_count"]
            .as_u64()
            .is_some_and(|count| count > 0 && count <= 2048)
    );
    let origins = retained["retrieval_origins"]["originals"]
        .as_array()
        .expect("protected frontier");
    assert!(origins.contains(&serde_json::json!(archive.event_id)));
    let routes = observation["routes"]
        .as_array()
        .expect("actual native routes");
    assert_eq!(routes.len(), 3);
    for route in routes {
        assert!(
            route["admitted_sources"]
                .as_array()
                .expect("admitted sources")
                .iter()
                .all(|source| origins.contains(source))
        );
    }
    let dense = routes
        .iter()
        .find(|route| route["route"] == "dense")
        .expect("actual dense route");
    assert_eq!(&dense["dense_witness"]["graph_digest"], graph_digest);
    assert_eq!(dense["tail_witness_complete"], true);

    let ctx = context(config);
    let output: CaptureReceipt =
        serde_json::from_value(answer["output_receipt"].clone()).expect("output");
    let output = owner
        .read_original(ReadOriginalRequest {
            context: ctx.clone(),
            event_id: output.event_id,
            after_receipt: Some(output),
        })
        .expect("captured output provenance");
    let Some(EventProvenance::ModelOutput {
        request_event_id, ..
    }) = output.event.provenance
    else {
        panic!("actual output must name its accepted request");
    };
    let requested = owner
        .read_original(ReadOriginalRequest {
            context: ctx.clone(),
            event_id: request_event_id,
            after_receipt: None,
        })
        .expect("exact captured protected request");
    assert_eq!(
        observation["intent"]["request_event"],
        serde_json::json!(request_event_id)
    );
    let read = owner
        .read_accepted_router_trace(
            ReadAcceptedRouterTraceRequest {
                context: ctx,
                receipt: requested.receipt,
            },
            &mut budget(),
        )
        .expect("cold current-authorized protected read");
    let AcceptedRouterTraceReadResult::Complete(read) = read else {
        panic!("retained protected material required");
    };
    assert_eq!(read.header, trace.header);
    assert!(read.lineage.originals.contains(&archive.event_id));
    assert!(
        read.material.evidence.iter().any(|evidence| {
            evidence
                .original_span
                .as_ref()
                .is_some_and(|span| span.event_id == archive.event_id)
                && evidence
                    .excerpt
                    .as_deref()
                    .is_some_and(|text| text.contains(ORIGINAL))
        }),
        "attributable recalled source, independently of the scripted reader reply"
    );
    for message in read
        .base
        .current
        .iter()
        .chain(&read.base.hot)
        .chain(&read.base.working)
    {
        assert!(!message.text.contains("BLUEBIRD-7319"));
        assert!(
            message
                .originals
                .iter()
                .all(|original| original.span.event_id != archive.event_id)
        );
    }
    let sent = sends
        .iter()
        .find(|sent| sent["request"]["call"] == serde_json::json!(manifest.model_call_id))
        .expect("actual reader dispatch");
    let wire: Vec<u8> =
        serde_json::from_value(sent["request"]["outgoing"]["wire"].clone()).expect("sent bytes");
    let wire: serde_json::Value = serde_json::from_slice(&wire).expect("actual ChatML wire");
    assert!(
        wire["prompt"]
            .as_str()
            .expect("full actual prompt")
            .contains(ORIGINAL)
    );
    observation.clone()
}

#[test]
#[ignore = "requires explicitly provisioned pinned GPU encoder and Python peer"]
fn owned_hybrid_real_encoder_cli_bootstrap_resume_and_strict_stale_cleanup() {
    let encoder = encoder_config();
    let profile = TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(
        embedding_backend_artifacts_digest(&encoder.runtime_artifacts)
            .expect("complete pinned backend"),
    );
    let fixture = Fixture::new();
    fixture.provision();
    let peer = Peer::new(&fixture, "reply");
    let (config_path, mut configured) = config(&fixture, &peer);
    configured["router_trace_profile"] = serde_json::json!("required_replay_v2");
    configured["automatic_hybrid"] = serde_json::json!({
        "encoder": encoder,
        "limits": OwnedHybridLimits { sources: 20, ..OwnedHybridLimits::default() },
    });
    std::fs::write(
        &config_path,
        serde_json::to_vec(&configured).expect("exact pinned hybrid config"),
    )
    .expect("trusted opt-in config");
    let archive = capture_archive(&fixture, &configured);
    let first_index = success(&index(&fixture, &config_path, true));
    endpoint_released(18768);
    assert_eq!(first_index["type"], "hybrid_index");
    assert_eq!(first_index["progress"]["graph_ready"], true);
    assert_eq!(first_index["progress"]["raw"]["caught_up"], true);
    assert_eq!(first_index["progress"]["dense"]["caught_up"], true);
    assert_eq!(first_index["progress"]["dense"]["spans"], 1);
    assert_eq!(
        first_index["progress"]["dense"]["profile"],
        serde_json::json!(profile)
    );
    let graph = first_index["progress"]["graph"].clone();
    let exact_retry = success(&index(&fixture, &config_path, false));
    endpoint_released(18768);
    assert_eq!(
        exact_retry["progress"]["graph"], graph,
        "exact retry retains one accepted immutable graph"
    );

    let started = host(
        &fixture,
        &config_path,
        false,
        input(&[
            serde_json::json!({"type":"user","text":"Recall the incidental satellite nickname from the launch maintenance meeting."}),
        ]),
    );
    require_success(&started);
    endpoint_released(18768);
    let first_records = records(&started);
    assert_eq!(first_records.last().expect("EOF pause")["type"], "paused");
    let first = first_records
        .iter()
        .find(|record| record["type"] == "answer")
        .expect("first answer");
    let first_observation = {
        let owner = native(&fixture);
        let saved = checkpoint(&owner, &configured);
        assert!(saved.checkpoint.pending_model.is_none());
        assert!(
            !saved
                .checkpoint
                .groups
                .iter()
                .flat_map(|group| &group.messages)
                .any(|message| message.source.event_id == archive.event_id)
        );
        verify_hybrid(
            &owner,
            &configured,
            first,
            &peer.sends(),
            &archive,
            &profile,
            &graph["manifest"]["content_digest"],
        )
    };
    peer.assert_reaped();
    let resumed = host(
        &fixture,
        &config_path,
        true,
        input(&[
            serde_json::json!({"type":"user","text":"Check again: which nickname did that incidental satellite launch note record after the maintenance meeting?"}),
        ]),
    );
    require_success(&resumed);
    endpoint_released(18768);
    let second_records = records(&resumed);
    assert_eq!(
        second_records.first().expect("cold ready")["model_outcome_unknown"],
        false
    );
    assert_eq!(
        second_records.last().expect("resumed EOF pause")["type"],
        "paused"
    );
    assert_eq!(
        first_records[0]["config_receipt"],
        second_records[0]["config_receipt"]
    );
    assert_eq!(peer.sends().len(), 2);
    peer.assert_reaped();

    // A real post-launch failure must clean up its encoder and must never replace
    // the frozen base after runtime source advancement. Do not retry bootstrap.
    let stale = index(&fixture, &config_path, false);
    no_key_disclosure(&stale);
    assert!(!stale.status.success());
    let error: ServiceError =
        serde_json::from_slice(&stale.stderr).expect("typed operator failure");
    assert_eq!(error.code, ErrorCode::IndexTooStale);
    endpoint_released(18768);

    let owner = native(&fixture);
    let second = second_records
        .iter()
        .find(|record| record["type"] == "answer")
        .expect("resumed answer");
    let second_observation = verify_hybrid(
        &owner,
        &configured,
        second,
        &peer.sends(),
        &archive,
        &profile,
        &graph["manifest"]["content_digest"],
    );
    let retained_first = verify_hybrid(
        &owner,
        &configured,
        first,
        &peer.sends(),
        &archive,
        &profile,
        &graph["manifest"]["content_digest"],
    );
    assert_eq!(
        retained_first, first_observation,
        "cold protected observation remains exact"
    );
    assert_ne!(
        first_observation["intent"]["call_id"],
        second_observation["intent"]["call_id"]
    );
    let saved = checkpoint(&owner, &configured);
    let output: CaptureReceipt =
        serde_json::from_value(second["output_receipt"].clone()).expect("last output");
    assert_eq!(saved.checkpoint.last_model_output, Some(output.event_id));
    assert!(saved.checkpoint.pending_model.is_none());
    owner
        .verify(VerifyRequest {
            context: context(&configured).request,
            deep: true,
        })
        .expect("cold encrypted source/graph/trace integrity");
    println!(
        "{}",
        serde_json::json!({
            "proof":"owned-hybrid-real-cli-subprocess-v1", "real_encoder":true,
            "profile_digest":profile.digest().expect("actual profile"),
            "graph_digest":graph["manifest"]["content_digest"],
            "graph_exact_retry":true, "accepted_query_vectors":2, "cold_accepted_traces":2,
            "resumed_followup":true, "archive_wire_attribution":true,
            "stale_continue_refused":true, "encoder_endpoint_released":true,
            "reader_children_reaped":true, "reader":"constant-scripted-protocol-fixture",
            "model_benefit_measured":false, "semantic_recall_measured":false, "benchmark_score":null,
        })
    );
}
