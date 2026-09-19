use super::*;

#[test]
fn interrupted_protocol_survives_lost_ack_restart_and_contradictory_reconciliation() {
    let directory = tempfile::tempdir().expect("directory");
    let native = Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
    let owner = Arc::new(LostOutputAcknowledgement {
        owner: Arc::clone(&native),
        lose_once: AtomicBool::new(true),
        output_kind: EventKind::ModelResponseAborted,
    });
    let (context, identity) = identity();
    native
        .initialize_state_catalog(&context, &mut budget())
        .expect("catalog");
    let mut runtime = OwnedAgentRuntime::start(
        owner,
        context.clone(),
        StartRun {
            identity: identity.clone(),
            model_profile: profile(),
            recorded_at: now(),
        },
        settings(),
        &mut budget(),
    )
    .expect("start");
    runtime
        .accept_user(
            "An interrupted action proposal is only an observation.".into(),
            now(),
            &mut budget(),
        )
        .expect("input");
    let partial = b"{\"text\":\"observed\",\"tool_calls\":[\xff".to_vec();
    let reader = ScriptedReader {
        partial: Some(partial.clone()),
        ..Default::default()
    };
    assert_eq!(
        runtime
            .step(
                &reader,
                &FixtureFence,
                &FixturePreparation(Arc::clone(&native)),
                &[],
                now(),
                &mut budget()
            )
            .expect_err("lost abort receipt")
            .code,
        ErrorCode::Unavailable
    );
    drop(runtime);
    drop(native);
    let native =
        Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("reopen"));
    let mut runtime = OwnedAgentRuntime::resume(
        Arc::clone(&native),
        context.clone(),
        identity.run_id,
        settings(),
        now(),
        &mut budget(),
    )
    .expect("recover uncheckpointed abort");
    assert!(runtime.model_outcome_unknown());
    assert!(
        runtime
            .next_tool(&mut budget())
            .expect("no executable proposal")
            .is_none()
    );
    let id = runtime
        .checkpoint()
        .pending_model
        .as_ref()
        .expect("attempt")
        .interrupted_output
        .expect("captured partial");
    let original = native
        .read_original(ReadOriginalRequest {
            context: context.clone(),
            event_id: id,
            after_receipt: None,
        })
        .expect("partial original");
    assert_eq!(
        original.event.payload.original_bytes(),
        Some(partial.as_slice())
    );
    assert_eq!(original.event.coverage, EventCoverage::PartialObservation);
    reader.deny_acceptance.store(true, Ordering::SeqCst);
    assert_eq!(
        runtime
            .reconcile_model(&reader, now(), &mut budget())
            .expect_err("cannot deny exposed output")
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(runtime.model_outcome_unknown());
    reader.deny_acceptance.store(false, Ordering::SeqCst);
    runtime
        .reconcile_model(&reader, now(), &mut budget())
        .expect("recover full answer")
        .expect("complete result");
    assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    assert!(runtime.checkpoint().groups.last().expect("group").complete);
    assert_eq!(
        native
            .read_original(ReadOriginalRequest {
                context: context.clone(),
                event_id: id,
                after_receipt: None,
            })
            .expect("original preserved")
            .event,
        original.event
    );
    native
        .verify(VerifyRequest {
            context: context.request,
            deep: true,
        })
        .expect("deep closure");
}
