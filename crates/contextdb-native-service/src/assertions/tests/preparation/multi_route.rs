//! Two independent discoveries of one long original must both reach the reader.
use super::*;

fn check(service: &NativeService, input: &CaptureRequest, source: &CaptureRequest) {
    let mut plan = request(input);
    plan.router_trace_profile = contextdb_service::RouterTraceProfile::RequiredReplayV2;
    for phrase in ["first_marker", "second_marker"] {
        plan.raw_queries.push(IndexedQuery {
            filter: RawFilter {
                event_ids: BTreeSet::from([source.event.event_id]),
                ..Default::default()
            },
            text: Some(RawTextQuery::ExactPhrase(phrase.into())),
            neighbor_of: None,
            selection: IndexedSelection::TopK { limit: 4 },
        });
    }
    let prepared = prepare(service, plan).expect("all matching ranges prepared");
    assert_eq!(prepared.context_pack.sections.raw_observations.len(), 1);
    for phrase in ["first_marker", "second_marker"] {
        assert!(
            prepared
                .messages
                .iter()
                .any(|message| message.text.contains(phrase)),
            "reader lost {phrase}"
        );
        assert!(
            prepared
                .context_pack
                .evidence
                .iter()
                .any(|evidence| evidence
                    .original_span
                    .as_ref()
                    .is_some_and(|span| span.event_id == source.event.event_id)
                    && evidence
                        .excerpt
                        .as_ref()
                        .is_some_and(|text| text.contains(phrase))),
            "attributed original lost {phrase}"
        );
    }
    assert_eq!(
        prepared
            .context_pack
            .evidence
            .iter()
            .filter(|evidence| evidence
                .original_span
                .as_ref()
                .is_some_and(|span| span.event_id == source.event.event_id))
            .count(),
        2
    );
}

#[test]
fn two_routes_union_distant_original_spans_before_rendering_and_after_cold_reopen() {
    let directory = tempfile::tempdir().expect("fixture");
    let (_ledger_directory, ledger) = crate::suppression::tests::authority("prepare-union");
    let (_keys_directory, keys) = crate::encryption::tests::authority("prepare-union");
    let service = NativeService::open_encrypted(
        directory.path(),
        "prepare-union",
        [7; 32],
        ledger.clone(),
        keys.clone(),
    )
    .expect("encrypted open");
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let text = "a ".repeat(10_000)
        + "first_marker"
        + &" b".repeat(10_000)
        + "second_marker"
        + &" c".repeat(10_000);
    let mut source = capture(2, &text);
    source.context.request.purpose = "conversation".into();
    service
        .append_event(source.clone())
        .expect("long original capture");
    publish(&service, &source, "coverage-union", Vec::new());
    check(&service, &input, &source);
    service.verify_native(true).expect("deep source closure");
    drop(service);
    let service =
        NativeService::open_encrypted(directory.path(), "prepare-union", [7; 32], ledger, keys)
            .expect("encrypted cold reopen");
    check(&service, &input, &source);
}
