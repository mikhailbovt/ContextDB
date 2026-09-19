//! Real-reader one-step replay: native capture, R0 compiler, owned send and output.
//! The parent process supplies query-time originals only, never evaluation labels.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use contextdb_agent_runtime::*;
use contextdb_context::*;
use contextdb_continuity::*;
use contextdb_core::*;
use contextdb_native_service::NativeService;
use contextdb_recall::QueryBudget;
use contextdb_service::{Capability, *};
use serde::Deserialize;
use serde_json::json;

#[path = "continuous_reader/bridge.rs"]
mod bridge;
use bridge::{Bridge, LocalReader};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    id: String,
    role: String,
    scope: String,
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    id: String,
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    events: Vec<Original>,
    queries: Vec<Query>,
    control: String,
    model: String,
    hot_events: usize,
    input_tokens: u32,
    output_tokens: u32,
    seed: u32,
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        4_000_000,
        512 * 1024 * 1024,
        Duration::from_secs(120),
        Default::default(),
    )
}
fn now() -> TimestampMicros {
    TimestampMicros(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_micros() as i64,
    )
}
fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_micros() as u64
}

fn fixture_id(domain: &str, index: usize) -> uuid::Uuid {
    let digest = blake3::hash(format!("contextdb.reader-replay/v1/{domain}/{index}").as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

fn project(owner: &NativeService, context: &AuthenticatedRequestContext) -> ServiceResult<()> {
    let mut work = budget();
    while !owner
        .project_originals(context, false, 256, &mut work)?
        .caught_up
    {}
    Ok(())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let replay: Replay = serde_json::from_str(&line)?;
    if replay.events.len() > 4096
        || replay.queries.len() > 64
        || replay.hot_events > 32
        || !(1024..=15000).contains(&replay.input_tokens)
        || !(16..=1024).contains(&replay.output_tokens)
    {
        return Err("replay exceeds the bounded text benchmark profile".into());
    }
    let started = Instant::now();
    let bridge = Arc::new(Bridge::default());
    let directory = tempfile::tempdir()?;
    let owner = Arc::new(NativeService::open(
        directory.path(),
        "continuous-reader-bench",
        [37; 32],
    )?);
    let identity = OwnedRunIdentity {
        workspace_id: WorkspaceId::from_uuid(fixture_id("workspace", 0))?,
        session_id: SessionId::from_uuid(fixture_id("session", 0))?,
        run_id: AgentRunId::from_uuid(fixture_id("run", 0))?,
        actor_id: "benchmark-host".into(),
        agent_id: "benchmark-agent".into(),
        subject_id: MemorySubjectId::from_uuid(fixture_id("subject", 0))?.to_string(),
        scopes: BTreeSet::from([ScopeId::from_uuid(fixture_id("scope", 0))?]),
    };
    let context = AuthenticatedRequestContext {
        request: RequestContext {
            request_id: "continuous-reader-bench".into(),
            workspace_id: identity.workspace_id.to_string(),
            subject_id: identity.subject_id.clone(),
            audiences: BTreeSet::from([identity.subject_id.clone()]),
            scopes: identity.scopes.iter().map(ToString::to_string).collect(),
            purpose: "conversation".into(),
            clearance: Sensitivity::Private,
        },
        actor_id: identity.actor_id.clone(),
        agent_id: identity.agent_id.clone(),
        session_id: Some(identity.session_id.to_string()),
        capability_grants: BTreeSet::from([
            Capability::Observe,
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ReadMemory,
            Capability::ReadConflict,
            Capability::Runtime,
            Capability::Admin,
            Capability::Maintenance,
        ]),
        authentication: AuthenticationEvidence::AuthenticatedChannel {
            channel_id: "synthetic-local-stdio".into(),
            peer_identity: identity.actor_id.clone(),
            binding_digest: "aa".repeat(32),
        },
    };
    owner.initialize_state_catalog(&context, &mut budget())?;
    let producer = StreamId::from_uuid(fixture_id("producer", 0))?;
    let mut original_ids = BTreeMap::new();
    let mut captured = Vec::new();
    let foreign_scope = ScopeId::from_uuid(fixture_id("scope", 1))?;
    for (index, original) in replay.events.iter().enumerate() {
        let (role, kind, outgoing_role) = match original.role.as_str() {
            "user" => (
                EventRole::User,
                EventKind::MessageCreated,
                OutgoingRole::User,
            ),
            "assistant" => (
                EventRole::Assistant,
                EventKind::MessageCreated,
                OutgoingRole::Assistant,
            ),
            _ => return Err("unsupported replay role".into()),
        };
        let id = ObservationId::from_uuid(fixture_id("event", index))?;
        let digest = ContentDigest::from_bytes(*blake3::hash(original.text.as_bytes()).as_bytes());
        let mut capture_context = context.clone();
        let scopes = if original.scope == "main" {
            identity.scopes.clone()
        } else {
            capture_context.request.scopes = BTreeSet::from([foreign_scope.to_string()]);
            BTreeSet::from([foreign_scope])
        };
        let event = EventEnvelope {
            version: EVENT_ENVELOPE_VERSION,
            event_id: id,
            workspace_id: identity.workspace_id,
            scope_ids: scopes,
            producer_id: producer,
            producer_sequence: index as u64 + 1,
            kind,
            role,
            recorded_at: TimestampMicros(1_789_833_600_000_000 + index as i64),
            observed_at: None,
            source_id: SourceId::from_uuid(fixture_id("source", index))?,
            source_version: None,
            adapter_id: "contextdb.synthetic-replay.v1".into(),
            session_id: Some(identity.session_id),
            run_id: Some(identity.run_id),
            task_id: None,
            parent_event_ids: BTreeSet::new(),
            supersedes_event_id: None,
            payload: EventPayload::InlineUtf8 {
                text: original.text.clone(),
                digest,
            },
            coverage: EventCoverage::CompleteObservation,
            upstream_truncated: false,
            gap_reason: None,
            response_stream: None,
            provenance: None,
        };
        owner.append_event(CaptureRequest {
            context: capture_context,
            idempotency_key: format!("synthetic/{index}"),
            event,
        })?;
        original_ids.insert(id, (original.id.clone(), original.text.len() as u64));
        if original.scope != "main" {
            continue;
        }
        captured.push(CapturedMessage {
            id: BlockId::new(format!("history:{index}"))?,
            source: OriginalSourceSpan {
                event_id: id,
                payload_digest: digest,
                start: 0,
                end: original.text.len() as u64,
                span_digest: digest,
            },
            role: outgoing_role,
            tool_calls: vec![],
            tool_result: None,
        });
    }
    project(&owner, &context)?;
    let profile = ModelProfile {
        id: replay.model.clone(),
        family: "Qwen3-8B-GGUF".into(),
        tokenizer_id: format!("llama.cpp-b10964:{}", replay.model),
        renderer: RendererKind::Compact,
        max_context_tokens: 16384,
        reserved_output_tokens: replay.output_tokens,
        preferred_structured_format: StructuredFormat::CompactText,
        supports_tool_results: false,
        supports_native_citations: false,
        supports_prompt_caching: true,
        position_profile: PositionProfile::CriticalFirst,
        instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
        max_schema_complexity: 64,
        external_processing: false,
    };
    let settings = RuntimeSettings {
        control: vec![OutgoingMessage {
            id: BlockId::new("control")?,
            zone: OutgoingZone::Control,
            role: OutgoingRole::System,
            text: replay.control,
            originals: vec![],
            tool_calls: vec![],
            tool_result: None,
        }],
        purpose: PackPurpose::Conversation,
        memory_budget: ContextBudgets {
            hard_tokens: replay.input_tokens / 2,
            soft_tokens: replay.input_tokens / 2,
            max_blocks: 48,
            max_evidence_blocks: 64,
            max_raw_evidence_tokens: replay.input_tokens / 2,
            max_history_tokens: replay.input_tokens / 2,
            max_conflict_tokens: replay.input_tokens / 2,
            max_serialized_bytes: 2 * 1024 * 1024,
            max_selection_evaluations: 96,
        },
        outgoing_budget: OutgoingBudget {
            max_input_tokens: replay.input_tokens,
            safety_tokens: 128,
            max_wire_bytes: 2 * 1024 * 1024,
        },
        rolling: RollingPolicy {
            high_tokens: replay.input_tokens * 3 / 4,
            low_tokens: replay.input_tokens / 2,
            keep_complete_groups: 1,
            chunk_groups: 2,
            max_prepare_attempts: 3,
        },
        cache_residency: None,
        // Original query-time history only: prior replay answers are retained for
        // audit but must never leak into another independent evaluation question.
        automatic_recall_filter: RawFilter {
            recorded_range: Some(TimeRange::new(
                TimestampMicros(1_789_833_600_000_000),
                Some(TimestampMicros(
                    1_789_833_600_000_000 + replay.events.len() as i64,
                )),
            )?),
            ..Default::default()
        },
    };
    let runtime = OwnedAgentRuntime::start(
        Arc::clone(&owner),
        context.clone(),
        StartRun {
            identity: identity.clone(),
            model_profile: profile.clone(),
            recorded_at: now(),
        },
        settings.clone(),
        &mut budget(),
    )?;
    drop(runtime);
    let seed_groups = captured
        .into_iter()
        .rev()
        .take(replay.hot_events)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .enumerate()
        .map(|(index, message)| InteractionGroup {
            sequence: index as u64 + 1,
            messages: vec![message],
            complete: true,
        })
        .collect::<Vec<_>>();
    bridge.exchange(&json!({"op":"setup", "elapsed_micros":elapsed(started), "captured_events":replay.events.len()}))?;
    let reader = LocalReader::new(Arc::clone(&bridge), profile, replay.seed);
    for query in replay.queries {
        let started = Instant::now();
        bridge.exchange(&json!({"op":"query_start", "id":query.id}))?;
        // One-step replay restores the same authorized H* for every treatment.
        // This benchmark does not claim a multi-step task rollout or legacy migration.
        let mut head = owner
            .load_run_checkpoint(&context, identity.run_id, &mut budget())?
            .ok_or("run head absent")?
            .checkpoint;
        let revision = head.revision;
        head.revision += 1;
        head.next_sequence += 1;
        head.recorded_at = now();
        head.groups = seed_groups.clone();
        head.last_model_output = None;
        owner.save_run_checkpoint(
            SaveRunCheckpointRequest {
                context: context.clone(),
                event_id: ObservationId::new(),
                idempotency_key: format!("replay/{}", head.revision),
                expected_revision: revision,
                checkpoint: head,
            },
            &mut budget(),
        )?;
        let mut runtime = OwnedAgentRuntime::resume(
            Arc::clone(&owner),
            context.clone(),
            identity.run_id,
            settings.clone(),
            now(),
            &mut budget(),
        )?;
        let current = runtime.accept_user(query.text, now(), &mut budget())?;
        project(&owner, &context)?;
        let result = runtime.step(
            &reader,
            &OwnerDispatchFence::new(Arc::clone(&owner)),
            &KeepUninterpreted,
            &[],
            now(),
            &mut budget(),
        );
        let measurements = runtime.drain_measurements();
        match result {
            Ok(turn) => {
                if turn
                    .prepared
                    .assembly
                    .read_set
                    .originals
                    .iter()
                    .any(|span| {
                        !original_ids.contains_key(&span.event_id)
                            && span.event_id != current.event_id
                    })
                {
                    return Err("replay exposed a source outside the query-time partition".into());
                }
                let visible = turn
                    .prepared
                    .assembly
                    .read_set
                    .originals
                    .iter()
                    .filter_map(|span| {
                        original_ids
                            .get(&span.event_id)
                            .filter(|(_, size)| span.start == 0 && span.end == *size)
                            .map(|(id, _)| id)
                    })
                    .collect::<BTreeSet<_>>();
                bridge.exchange(&json!({"op":"answer","id":query.id,"text":turn.reply.text,"visible_events":visible,
                    "elapsed_micros":elapsed(started),"measurements":measurements,"input_tokens":turn.prepared.outgoing.input_tokens,
                    "discovery":turn.prepared.discovery,"compilation":turn.prepared.context_pack.compilation}))?;
            }
            Err(error) => {
                bridge.exchange(&json!({"op":"answer","id":query.id,"error":error.code,"elapsed_micros":elapsed(started),"measurements":measurements}))?;
                if runtime.model_outcome_unknown() {
                    break;
                }
            }
        }
    }
    owner.verify(VerifyRequest {
        context: context.request,
        deep: true,
    })?;
    bridge.exchange(&json!({"op":"finished", "native_verified":true}))?;
    Ok(())
}
