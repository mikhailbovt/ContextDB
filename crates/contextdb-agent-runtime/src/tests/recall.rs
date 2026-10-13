use contextdb_capture::{
    ExternalTool, ToolAction, ToolObservation, ToolOutcome, ToolReconciliation, ToolReplaySafety,
};
use contextdb_recall::QueryCancellation;

use super::*;

fn message(role: OutgoingRole, zone: OutgoingZone, text: &str) -> OutgoingMessage {
    OutgoingMessage {
        id: BlockId::new("cue-fixture").expect("id"),
        role,
        zone,
        text: text.into(),
        originals: vec![],
        tool_calls: vec![],
        tool_result: None,
    }
}

#[test]
fn bounded_cues_preserve_channel_fairness_utf8_and_shared_cancellation() {
    let mut base = OutgoingBase {
        control: vec![message(
            OutgoingRole::System,
            OutgoingZone::Control,
            "control_only",
        )],
        working: vec![message(
            OutgoingRole::User,
            OutgoingZone::WorkingState,
            "open_obligation",
        )],
        hot: vec![message(
            OutgoingRole::User,
            OutgoingZone::HotHistory,
            "resident_only",
        )],
        current: vec![
            message(
                OutgoingRole::User,
                OutgoingZone::CurrentTurn,
                "current_request",
            ),
            message(
                OutgoingRole::Tool,
                OutgoingZone::CurrentTurn,
                &format!(
                    "tool_observation {} tail_observation",
                    "длинное_наблюдение ".repeat(4000)
                ),
            ),
            message(
                OutgoingRole::Assistant,
                OutgoingZone::CurrentTurn,
                "assistant_proposal",
            ),
        ],
    };
    let cues = current_step_routes(&base, &mut budget()).expect("bounded cues");
    let terms = cues
        .routes
        .iter()
        .filter_map(|route| match &route.text {
            Some(RawTextQuery::AllTerms(term)) => Some(term.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "current_request",
        "tool_observation",
        "open_obligation",
        "assistant_proposal",
    ] {
        assert!(terms.contains(required), "missing channel: {required}");
    }
    assert!(!terms.contains("control_only") && !terms.contains("resident_only"));
    assert!(cues.routes.len() <= 8 && cues.inspected_bytes <= 64 * 1024);
    assert_eq!(
        cues.inspected_bytes + cues.omitted_bytes,
        base.current
            .iter()
            .chain(&base.working)
            .map(|item| item.text.len() as u64)
            .sum::<u64>()
    );
    assert!(cues.omitted_bytes > 100_000);
    // A word spanning either crop boundary must never become a new search key.
    base.current = vec![message(
        OutgoingRole::Tool,
        OutgoingZone::CurrentTurn,
        &"x".repeat(4097),
    )];
    base.working.clear();
    assert!(
        current_step_routes(&base, &mut budget())
            .expect("clipped word")
            .routes
            .is_empty()
    );
    let mut zero = QueryBudget::new(0, 0, Duration::from_secs(1), Default::default());
    assert_eq!(
        current_step_routes(&base, &mut zero)
            .err()
            .expect("shared exhaustion")
            .code,
        ErrorCode::BudgetExhausted
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled =
        QueryBudget::new(1_000_000, 1_000_000, Duration::from_secs(1), cancellation);
    assert_eq!(
        current_step_routes(&base, &mut cancelled)
            .err()
            .expect("shared cancel")
            .code,
        ErrorCode::BudgetExhausted
    );
}

struct ObservedTool;
impl ExternalTool for ObservedTool {
    fn replay_safety(&self) -> ToolReplaySafety {
        ToolReplaySafety::NoAutomaticReplay
    }
    fn execute(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        _: &ToolAction,
    ) -> ServiceResult<ToolObservation> {
        Ok(ToolObservation {
            outcome: ToolOutcome::Completed,
            bytes: Some(b"KESTREL742".to_vec()),
            media_type: "text/plain".into(),
            upstream_truncated: false,
        })
    }
    fn reconcile(
        &self,
        _: &AuthenticatedRequestContext,
        _: ToolCallId,
        _: ContentDigest,
    ) -> ServiceResult<ToolReconciliation> {
        Ok(ToolReconciliation::Unknown)
    }
}

#[test]
fn captured_tool_result_automatically_recalls_an_evicted_original_on_the_next_call() {
    let directory = tempfile::tempdir().expect("directory");
    let owner = Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
    let (context, identity) = identity();
    owner
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let first = ScriptedReader::default();
    let hook = FixturePreparation(Arc::clone(&owner));
    let mut runtime = OwnedAgentRuntime::start(
        Arc::clone(&owner),
        context.clone(),
        StartRun {
            identity,
            model_profile: first.profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    let old = "KESTREL742: the exact archived calibration offset is 19.25 millimeters.";
    runtime
        .accept_user(old.into(), now(), &mut budget())
        .expect("old original");
    let old_event = runtime.checkpoint().groups[0].messages[0].source.event_id;
    runtime
        .step(&first, &FixtureFence, &hook, &[], now(), &mut budget())
        .expect("old turn");
    for index in 0..8 {
        runtime
            .accept_user(
                format!(
                    "Unrelated conversation {index}. {}",
                    "Ordinary weather discussion and incidental chatter. ".repeat(50)
                ),
                now(),
                &mut budget(),
            )
            .expect("input");
        runtime
            .step(&first, &FixtureFence, &hook, &[], now(), &mut budget())
            .expect("rotate");
    }
    assert!(
        !runtime
            .checkpoint()
            .groups
            .iter()
            .flat_map(|g| &g.messages)
            .any(|m| m.source.event_id == old_event)
    );
    let reader = ScriptedReader {
        model_id: Some("scripted-tool-reader"),
        tool_proposal: Some(RequestedTool {
            call_id: ToolCallId::new(),
            action: ToolAction {
                operation: "fixture.observe".into(),
                input: vec![],
                expected_target_version: None,
            },
        }),
        ..Default::default()
    };
    runtime
        .switch_reader(&reader, settings(), now(), &mut budget())
        .expect("tool reader");
    runtime
        .accept_user(
            "Instrument inspection proceed.".into(),
            now(),
            &mut budget(),
        )
        .expect("new query");
    let before = runtime
        .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
        .expect("proposal");
    assert!(
        !before
            .prepared
            .messages
            .iter()
            .any(|m| m.originals.iter().any(|o| o.span.event_id == old_event)),
        "query itself does not name the old entity"
    );
    runtime
        .execute_next_tool(
            "fixture.observe",
            &ObservedTool,
            &FixtureFence,
            now(),
            &mut budget(),
        )
        .expect("capture result");
    let after = runtime
        .step(&reader, &FixtureFence, &hook, &[], now(), &mut budget())
        .expect("automatic refresh");
    assert!(
        after
            .prepared
            .messages
            .iter()
            .any(|m| m.text.contains(old)
                && m.originals.iter().any(|o| o.span.event_id == old_event)),
        "actual next reader wire carries exact old original"
    );
    assert!(
        after
            .prepared
            .messages
            .iter()
            .any(|m| m.role == OutgoingRole::Tool && m.text.contains("KESTREL742"))
    );
    assert_eq!(reader.calls.load(Ordering::SeqCst), 2);
    assert!(
        runtime
            .drain_measurements()
            .steps
            .last()
            .expect("measurement")
            .automatic_recall_inspected_bytes
            > 0
    );
    owner
        .verify(VerifyRequest {
            context: context.request,
            deep: true,
        })
        .expect("native integrity");
}
