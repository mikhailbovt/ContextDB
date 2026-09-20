use super::*;
use crate::record_journal::controls::preparation::tests::strip_controls;

#[test]
fn legacy_record_witness_requires_prepared_birth_and_closure_without_rewriting_history() {
    let root = tempfile::tempdir().expect("root");
    let (_ledger_directory, ledger) = suppression::tests::authority("legacy-witness");
    let service = NativeService::open_with_suppression(
        root.path().join("native"),
        "legacy-witness",
        [7; 32],
        ledger,
    )
    .expect("native");
    let captured = input(1, "legacy original");
    service.append_event(captured.clone()).expect("capture");
    let context = captured.context;
    let source = captured.event.event_id;
    let original = service
        .publish_memory(publication(&context, "legacy-record"))
        .expect("unclassified original");
    let closed = service
        .forget(ForgetRequest {
            context: context.clone(),
            idempotency_key: "legacy-retract".into(),
            target_id: "legacy-record".into(),
            mode: ForgetMode::Retract,
            reason: "requested".into(),
        })
        .expect("closure");
    // Synthetic pre-control encoding, not an archive attributed to an old binary.
    strip_controls(&service);
    for revision in [1, 2] {
        service
            .bind_record_sources(
                &context,
                "legacy-record",
                revision,
                &BTreeSet::from([source]),
                &mut budget(),
            )
            .expect("explicit origin classification");
    }
    let removal = service
        .request_original_removal(&context, &BTreeSet::from([source]), "remove", &mut budget())
        .expect("removal request");
    let prepare = |revision| {
        service.prepare_record_removal(
            &context,
            &removal,
            "legacy-record",
            revision,
            source,
            &mut budget(),
        )
    };
    assert_eq!(
        prepare(1).expect_err("unprepared birth").code,
        ErrorCode::IntegrityFailure
    );
    let before = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    let events = before
        .scan_prefix(&service.keyspaces.events, b"")
        .expect("events");
    service
        .prepare_record_controls(&context, original.commit_seq, &mut budget())
        .expect("prepare birth group");
    assert_eq!(
        prepare(1).expect_err("unprepared closure").code,
        ErrorCode::IntegrityFailure
    );
    service
        .prepare_record_controls(&context, closed.commit_seq, &mut budget())
        .expect("prepare closure group");
    for revision in [1, 2] {
        let accepted = prepare(revision).expect("prepared witness");
        assert_eq!(prepare(revision).expect("exact retry"), accepted);
    }
    let after = service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("snapshot");
    for event in events {
        assert_eq!(
            after
                .get(&service.keyspaces.events, &event.key)
                .expect("read event"),
            Some(event.value)
        );
    }
    let mut expected = original;
    expected.replayed = true;
    assert_eq!(
        service
            .publish_memory(publication(&context, "legacy-record"))
            .expect("original receipt"),
        expected
    );
    service
        .verify_native(true)
        .expect("mixed accepted preparation and witness");
}
