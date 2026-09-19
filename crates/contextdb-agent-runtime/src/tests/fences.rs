use super::*;

#[derive(Debug)]
struct ChangingFence {
    owner: Arc<NativeService>,
    seed: EventEnvelope,
    attempts: AtomicUsize,
    continuous: bool,
}
impl ModelDispatchFence for ChangingFence {
    fn before_model(
        &self,
        context: &AuthenticatedRequestContext,
        checkpoint: &CaptureReceipt,
        call: ModelCallId,
        request: &CaptureReceipt,
        prepared: &PreparedContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 || self.continuous {
            let mut event = self.seed.clone();
            event.event_id = ObservationId::new();
            event.source_id = SourceId::new();
            event.producer_id = StreamId::new();
            event.producer_sequence = 1;
            event.run_id = None;
            // This synthetic source is explicitly not a new semantic constraint.
            let text = "Another fixture observation arrived during preparation.".to_owned();
            event.payload = EventPayload::InlineUtf8 {
                digest: ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes()),
                text,
            };
            self.owner.append_event(CaptureRequest {
                context: context.clone(),
                idempotency_key: format!("concurrent-fixture-{attempt}"),
                event,
            })?;
        }
        OwnerDispatchFence::new(Arc::clone(&self.owner))
            .before_model(context, checkpoint, call, request, prepared, budget)
    }
}

#[test]
fn disclosure_replans_before_send_and_stops_after_bounded_continuous_invalidation() {
    for continuous in [false, true] {
        let directory = tempfile::tempdir().expect("directory");
        let owner =
            Arc::new(NativeService::open(directory.path(), "runtime", [7; 32]).expect("open"));
        let (context, identity) = identity();
        owner
            .initialize_state_catalog(&context, &mut budget())
            .expect("catalog");
        let mut runtime = OwnedAgentRuntime::start(
            Arc::clone(&owner),
            context.clone(),
            StartRun {
                identity,
                model_profile: profile(),
                recorded_at: now(),
            },
            settings(),
            &mut budget(),
        )
        .expect("start");
        let input = runtime
            .accept_user(
                "Continue this fixture conversation.".into(),
                now(),
                &mut budget(),
            )
            .expect("input");
        let seed = owner
            .read_original(ReadOriginalRequest {
                context: context.clone(),
                event_id: input.event_id,
                after_receipt: Some(input),
            })
            .expect("seed")
            .event;
        let fence = ChangingFence {
            owner: Arc::clone(&owner),
            seed,
            attempts: AtomicUsize::new(0),
            continuous,
        };
        let reader = ScriptedReader::default();
        let result = runtime.drive(
            &ExecutionAdapters {
                reader: &reader,
                model_fence: &fence,
                tool_fence: &OwnerDispatchFence::new(Arc::clone(&owner)),
                preparation: &FixturePreparation(Arc::clone(&owner)),
                tools: &NoExternalTools,
            },
            2,
            now(),
            &mut budget(),
        );
        assert_eq!(fence.attempts.load(Ordering::SeqCst), 2);
        let measurements = runtime.drain_measurements();
        assert_eq!(measurements.steps.len(), 2);
        assert!(!measurements.steps[0].dispatched);
        assert!(measurements.steps[0].error.is_some());
        assert_eq!(measurements.steps[1].dispatched, !continuous);
        assert_eq!(measurements.dropped_steps, 0);
        assert!(
            measurements
                .steps
                .iter()
                .all(|step| step.usage.input_tokens.is_none())
        );
        let serialized = serde_json::to_string(&measurements).expect("measurement JSON");
        assert!(!serialized.contains("Continue this fixture conversation"));
        if continuous {
            assert_eq!(
                result.expect_err("bounded refresh cap").code,
                ErrorCode::IndexTooStale
            );
            assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
            assert!(
                !runtime.model_outcome_unknown(),
                "both requests were rejected before handoff"
            );
        } else {
            result.expect("fresh preparation sent once");
            assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
        }
        owner
            .verify(VerifyRequest {
                context: context.request,
                deep: true,
            })
            .expect("native closure");
    }
}
