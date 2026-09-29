use std::sync::Arc;

use contextdb_agent_runtime::{OwnedAgentRuntime, RollingPolicy, RuntimeSettings, StartRun};
use contextdb_context::{
    ContextBudgets, InstructionHierarchy, ModelProfile, OutgoingBudget, PackPurpose,
    PositionProfile, ReferenceTokenizer, RendererKind, StructuredFormat,
};
use contextdb_continuity::OwnedRunIdentity;
use contextdb_core::{AgentRunId, RawFilter, SessionId, TimestampMicros};

use super::*;

fn profile() -> ModelProfile {
    ModelProfile {
        id: "recovery-fixture".into(),
        family: "no-model-call".into(),
        tokenizer_id: ReferenceTokenizer::ID.into(),
        renderer: RendererKind::Compact,
        max_context_tokens: 32000,
        reserved_output_tokens: 4000,
        preferred_structured_format: StructuredFormat::CompactText,
        supports_tool_results: false,
        supports_native_citations: false,
        supports_prompt_caching: false,
        position_profile: PositionProfile::CriticalFirst,
        instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
        max_schema_complexity: 64,
        external_processing: false,
    }
}

fn settings() -> RuntimeSettings {
    RuntimeSettings {
        control: vec![],
        purpose: PackPurpose::Conversation,
        memory_budget: ContextBudgets {
            hard_tokens: 14000,
            soft_tokens: 12000,
            max_blocks: 64,
            max_evidence_blocks: 128,
            max_raw_evidence_tokens: 10000,
            max_history_tokens: 10000,
            max_conflict_tokens: 10000,
            max_serialized_bytes: 2 * 1024 * 1024,
            max_selection_evaluations: 128,
        },
        outgoing_budget: OutgoingBudget {
            max_input_tokens: 27000,
            safety_tokens: 1000,
            max_wire_bytes: 2 * 1024 * 1024,
        },
        rolling: RollingPolicy {
            high_tokens: 3200,
            low_tokens: 2100,
            keep_complete_groups: 1,
            chunk_groups: 2,
            max_prepare_attempts: 3,
        },
        cache_residency: None,
        automatic_recall_filter: RawFilter::default(),
    }
}

#[test]
fn runtime_start_and_reopen_resume_repair_accepted_memory_without_a_user_command() {
    let root = tempfile::tempdir().expect("root");
    let (_authority, ledger) = suppression::tests::authority("runtime-record-recovery");
    let path = root.path().join("native");
    let service = Arc::new(
        NativeService::open_with_suppression(
            &path,
            "runtime-record-recovery",
            [7; 32],
            ledger.clone(),
        )
        .expect("native"),
    );
    let source = input(1, "earlier permitted conversation");
    service.append_event(source.clone()).expect("capture");
    let identity = OwnedRunIdentity {
        workspace_id: source.event.workspace_id,
        session_id: SessionId::new(),
        run_id: AgentRunId::new(),
        actor_id: source.context.actor_id.clone(),
        agent_id: source.context.agent_id.clone(),
        subject_id: source.context.request.subject_id.clone(),
        scopes: source.event.scope_ids.clone(),
    };
    let mut context = source.context;
    context.session_id = Some(identity.session_id.to_string());
    context.capability_grants.extend([
        Capability::Runtime,
        Capability::ReadEvidence,
        Capability::RawEvidence,
    ]);
    pending_write(&service, &context, source.event.event_id, "before-start");
    assert_eq!(
        get(&service, &context, "before-start")
            .expect_err("accepted but incomplete")
            .code,
        ErrorCode::IndexTooStale
    );
    let runtime = OwnedAgentRuntime::start(
        service.clone(),
        context.clone(),
        StartRun {
            identity: identity.clone(),
            model_profile: profile(),
            recorded_at: TimestampMicros(1_000_000),
        },
        settings(),
        &mut budget(),
    )
    .expect("start performs recovery");
    get(&service, &context, "before-start").expect("start opened the completed group");
    pending_write(&service, &context, source.event.event_id, "before-resume");
    drop(runtime);
    drop(service);
    let service = Arc::new(
        NativeService::open_with_suppression(path, "runtime-record-recovery", [7; 32], ledger)
            .expect("reopen"),
    );
    let runtime = OwnedAgentRuntime::resume(
        service.clone(),
        context.clone(),
        identity.run_id,
        settings(),
        TimestampMicros(2_000_000),
        &mut budget(),
    )
    .expect("resume performs recovery");
    assert_eq!(runtime.checkpoint().identity, identity);
    get(&service, &context, "before-resume").expect("resumed group is available");
    service
        .verify_native(true)
        .expect("real runtime and native recovery agree");
}
