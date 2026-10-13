//! Actual encrypted bounded dense prefixes under a larger REAL raw census.
//! The inherited constant encoder proves protocol wiring, not retrieval quality.

use super::*;

#[test]
fn encrypted_lagged_dense_batches_seal_in_order_without_faking_raw_census() {
    let f = fixture();
    // 140 actual captures exceed the 128-work delta allowance. One text in each
    // dense batch gives a real whole vector plan; binaries retain honest omitted
    // documents and make the fixture cheap without manufacturing work counters.
    for sequence in 3..=142 {
        let request = if [3, 67, 131].contains(&sequence) {
            let mut request = crate::capture::tests::request(
                sequence,
                &format!("actual independent bounded-prefix text {sequence}"),
            );
            request.event.source_version = Some(format!("actual-lag-text-version-{sequence}"));
            request
        } else {
            small_binary(sequence)
        };
        f.native
            .append_event(request)
            .expect("actual full archive capture");
    }
    let mut parent = budget();
    let mut raw = None;
    for _ in 0..3 {
        let progress = f
            .native
            .project_originals_bm25(&f.context, false, 64, &mut parent)
            .expect("bounded real raw-census batch");
        assert_eq!(progress.generation, 1);
        let complete = progress.caught_up;
        raw = Some(progress);
        if complete {
            break;
        }
    }
    let raw = raw.expect("actual raw progress");
    assert!(
        raw.caught_up,
        "the raw index catches up BEFORE bounded dense projection"
    );
    let full = generation(&f.native, &f.context);
    assert_eq!(full.projected_sources, 142);
    assert!(full.dense_segments.is_none());
    let real_raw_through = full.through;
    let forwards_before = f.encoder.forwards.load(Ordering::SeqCst);
    assert_eq!(
        forwards_before, 2,
        "only accepted base texts were forwarded yet"
    );

    let mut first_request = None;
    let mut first_publication = None;
    let mut previous = f.base.manifest.dense.clone();
    for (index, (sources, work, caught_up)) in
        [(66_u64, 64_u32, false), (130, 64, false), (142, 12, true)]
            .into_iter()
            .enumerate()
    {
        let target = f
            .native
            .project_original_spans(&f.context, &f.encoder, 64, &mut parent)
            .expect("one bounded accepted dense batch");
        assert_eq!(target.generation, 1);
        assert_eq!(target.raw_through, real_raw_through);
        assert_eq!(target.raw_sources, 142);
        assert_eq!(target.sources, sources);
        assert_eq!(target.caught_up, caught_up);
        assert_eq!(target.caught_up, target.through == target.raw_through);
        assert_eq!(
            f.encoder.forwards.load(Ordering::SeqCst),
            forwards_before + index + 1
        );
        let request = seal_request(&f, target);
        request
            .validate()
            .expect("honest lagged or complete target");
        let mut false_claim = request.clone();
        false_claim.target.caught_up = !caught_up;
        assert!(
            false_claim.validate().is_err(),
            "caught_up describes the real cutoff equality"
        );

        let publication = f
            .native
            .seal_original_span_segment(&f.context, &request, &mut parent)
            .expect("accepted bounded dense prefix is sealable while raw is larger");
        let delta = &publication.delta.manifest;
        assert_eq!(delta.ordinal, index as u64 + 1);
        assert_eq!(delta.work_items, work);
        assert_eq!(
            delta.nodes, 1,
            "the entire one-span text plan accompanies real omitted documents"
        );
        assert_eq!(delta.before, previous);
        assert_eq!(delta.binding.raw_through, real_raw_through);
        assert_eq!(
            delta.binding.raw_sources, 142,
            "partial dense totals never impersonate the raw census"
        );
        assert_eq!(delta.after.sources, sources);
        assert_eq!(delta.after.through, request.target.through);
        assert_eq!(publication.directory.head.covered, delta.after);
        assert_eq!(delta.after.through == delta.binding.raw_through, caught_up);
        assert_base_unchanged(&f.native, &f.base);
        previous = delta.after.clone();
        if index == 0 {
            first_request = Some(request);
            first_publication = Some(publication);
        }
    }
    let first_request = first_request.expect("accepted first lagged request");
    let first_publication = first_publication.expect("accepted first lagged publication");
    assert!(!first_request.target.caught_up);
    let final_generation = generation(&f.native, &f.context);
    assert_eq!(final_generation.number, 1);
    assert_eq!(final_generation.projected_sources, 142);
    assert_eq!(final_generation.through, real_raw_through);
    assert_eq!(
        final_generation
            .dense_segments
            .as_ref()
            .expect("final directory")
            .count,
        3
    );
    let global = latest_global(&f.native);
    assert_eq!(
        f.native
            .seal_original_span_segment(&f.context, &first_request, &mut parent)
            .expect("old exact lagged retry"),
        first_publication
    );
    assert_eq!(
        latest_global(&f.native),
        global,
        "retry never publishes or rewinds a head"
    );
    assert_eq!(generation(&f.native, &f.context), final_generation);
    let snapshot = f
        .native
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("final source snapshot");
    f.native
        .verify_segment_heads_records(&snapshot, &mut parent)
        .expect("accepted partial-to-complete directory transitions");
    f.native
        .verify_raw_index_records(&snapshot)
        .expect("all lagged manifests reconstruct with REAL raw binding");
    drop(snapshot);

    let Fixture {
        native,
        context,
        source: _,
        root,
        ledger,
        keys,
        _ledger,
        _keys,
        encoder,
        base,
    } = f;
    drop(native);
    let cold = NativeService::open_encrypted(
        root.path().join("native"),
        "span-ann-segment-fixture",
        [31; 32],
        ledger,
        keys,
    )
    .expect("cold encrypted owner");
    let snapshot = cold
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("cold source snapshot");
    cold.verify_segment_heads_records(&snapshot, &mut budget())
        .expect("cold accepted head replay");
    cold.verify_raw_index_records(&snapshot)
        .expect("cold exact partial prefix reconstruction");
    drop(snapshot);
    assert_eq!(
        cold.seal_original_span_segment(&context, &first_request, &mut budget())
            .expect("cold old lagged retry"),
        first_publication
    );
    assert_eq!(generation(&cold, &context), final_generation);
    assert_base_unchanged(&cold, &base);
    assert_eq!(
        encoder.forwards.load(Ordering::SeqCst),
        5,
        "seals, retries and cold reconstruction perform no extra model forwards"
    );
}
