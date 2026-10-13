//! Pure format fixtures do not grant native acceptance or retrieval permission.
use super::*;
use contextdb_core::ObservationId;
use contextdb_service::TextEmbeddingProfile;

fn d(byte: u8) -> ContentDigest {
    ContentDigest::from_bytes([byte; 32])
}
fn publication(at: u64) -> AcceptedPublicationRef {
    AcceptedPublicationRef {
        global_commit: at,
        event_digest: "11".repeat(32),
        request_digest: "22".repeat(32),
        response_digest: "33".repeat(32),
    }
}
fn boundary(commit: u64, global: u64) -> CaptureBoundaryRefV2 {
    CaptureBoundaryRefV2 {
        work: CaptureWork {
            event_id: format!("00000000-0000-4000-8000-{commit:012x}")
                .parse::<ObservationId>()
                .expect("fixture id"),
            workspace_commit: commit,
            event_digest: d(6),
            recovery_digest: Some(d(7)),
        },
        global_commit: global,
        event_digest: "44".repeat(32),
        receipt_digest: d(8),
        control_digest: d(9),
    }
}
fn manifest() -> PrefixDeltaManifestV2 {
    let profile = TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(d(1));
    let before = DenseManifest {
        profile_digest: profile.digest().expect("profile"),
        vector_space_id: profile.vector_space_id().expect("space"),
        profile,
        through: 300,
        sources: 200,
        embedded_sources: 150,
        spans: 160,
        omitted_sources: 50,
        commitment: d(2),
    };
    let mut after = before.clone();
    after.through = 305;
    after.sources = 202;
    after.embedded_sources = 151;
    after.spans = 162;
    after.omitted_sources = 51;
    after.commitment = d(3);
    PrefixDeltaManifestV2 {
        revision: 2,
        raw: PrefixRawBindingV2 {
            generation: 1,
            custody_version: crate::custody::CUSTODY_VERSION,
            analyzer: contextdb_index::RAW_ANALYZER.into(),
            bm25: crate::raw_index::bm25::Bm25Profile::fixed(),
            authorization_epoch: 0,
            removal_through: None,
            through: 1000,
            projected_sources: 600,
        },
        admitted_known_at: 1001,
        admitted_global_commit: 1002,
        ordinal: 1,
        base: PrefixSegmentBaseRefV2 {
            publication: publication(650),
            receipt_digest: d(10),
            content_digest: d(11),
        },
        before,
        after,
        before_dense: publication(600),
        target_dense: publication(700),
        // Both capture boundaries precede BOTH publications. Their actual positions,
        // rather than either publication position, define the complete range.
        start: boundary(299, 400),
        end: boundary(304, 405),
        interval: PrefixIntervalV2 {
            work_items: 2,
            digest: d(12),
        },
        nodes: 2,
        cohorts: vec![GraphCohortSummary {
            policy_domain: "55".repeat(32),
            partition_digest: d(13),
            nodes: 2,
        }],
        builder_revision: ANN_PARTITION_BUILD_REVISION_V2.into(),
        content_digest: d(14),
    }
}

#[test]
fn total_history_exceeds_128_while_real_raw_census_and_interval_remain_separate() {
    let m = manifest();
    m.validate().expect("actual small interval shape");
    assert!(m.before.sources > u64::from(MAX_WORK));
    assert!(m.raw.projected_sources > m.after.sources);
    assert!(m.end.global_commit < m.before_dense.global_commit);
    let bytes = crate::encode(&m).expect("canonical");
    let restored: PrefixDeltaManifestV2 =
        crate::decode(&bytes, "pure format").expect("bounded decode");
    assert_eq!(m, restored);
    assert_eq!(bytes, crate::encode(&restored).expect("canonical again"));
    let mut unknown = serde_json::to_value(m).expect("value");
    unknown
        .as_object_mut()
        .expect("object")
        .insert("graph_digest".into(), serde_json::json!("legacy"));
    assert!(serde_json::from_value::<PrefixDeltaManifestV2>(unknown).is_err());
}

#[test]
fn genuine_omission_interval_has_no_nodes_but_requires_work_and_advance() {
    let mut m = manifest();
    m.after.embedded_sources = m.before.embedded_sources;
    m.after.spans = m.before.spans;
    m.after.sources = m.before.sources + 1;
    m.after.omitted_sources = m.before.omitted_sources + 1;
    m.interval.work_items = 1;
    m.nodes = 0;
    m.cohorts.clear();
    m.validate().expect("zero-node genuine omission");
    m.interval.work_items = 0;
    assert!(m.validate().is_err());
    m.interval.work_items = 1;
    m.after = m.before.clone();
    assert!(m.validate().is_err());
}

#[test]
fn interval_caps_profiles_counters_and_capture_boundaries_fail_closed() {
    for change in 0..7 {
        let mut m = manifest();
        match change {
            0 => m.interval.work_items = MAX_WORK + 1,
            1 => m.after.profile.dimensions = 512,
            2 => m.after.sources = m.before.sources - 1,
            3 => m.end.work.workspace_commit = m.before.through,
            4 => m.start.global_commit = m.before_dense.global_commit + 1,
            5 => m.raw.projected_sources = m.after.sources - 1,
            _ => m.admitted_global_commit = m.target_dense.global_commit - 1,
        }
        assert!(m.validate().is_err(), "invalid interval {change}");
    }
    let mut exact = manifest();
    exact.after.through = 600;
    exact.end.work.workspace_commit = 599;
    exact.end.global_commit = 650;
    exact.interval.work_items = MAX_WORK;
    exact.validate().expect("128 works not total history");
    exact.interval.work_items += 1;
    assert!(exact.validate().is_err());
}

#[test]
fn scalable_directory_and_cycle_free_current_ref_preserve_full_retained_acceptance() {
    let m = manifest();
    let reference = PrefixSegmentDirectoryRefV2 {
        count: 999,
        global_commit: 1002,
        request_digest: "66".repeat(32),
        response_digest: "77".repeat(32),
        content_digest: d(15),
    };
    reference
        .validate()
        .expect("bounded-size ref for many ordinals");
    let value = serde_json::to_value(&reference).expect("value");
    assert!(value.get("event_digest").is_none());
    assert!(value.get("publication").is_none());
    let mut head = PrefixSegmentDirectoryHeadV2 {
        revision: 2,
        generation: 1,
        base: m.base,
        count: 1000,
        latest: PrefixSegmentRefV2 {
            ordinal: 1000,
            global_commit: 1003,
            manifest_digest: d(14),
            receipt_digest: d(16),
        },
        covered: m.after,
        covered_dense: m.target_dense,
        ending: m.end,
        previous: Some(reference),
        content_digest: d(17),
    };
    head.validate()
        .expect("directory has no all-history vector or one-delta cap");
    head.previous.as_mut().expect("previous").count = u64::MAX;
    assert!(head.validate().is_err(), "checked predecessor arithmetic");
    let locator = RetainedPrefixSegmentLocatorV2 {
        revision: 2,
        workspace_digest: "88".repeat(32),
        generation: 1,
        ordinal: 1000,
        publication: publication(1003),
        token: "99".repeat(32),
    };
    locator.validate().expect("retained actual event reference");
    assert!(
        serde_json::to_value(locator).expect("value")["publication"]
            .get("event_digest")
            .is_some()
    );
}

#[test]
fn new_addresses_and_domains_cannot_alias_legacy_graph_or_prefix_base() {
    let workspace = "ab".repeat(32);
    let prefix = segment_prefix(&workspace, 1, 1).expect("prefix");
    assert!(!prefix.starts_with(&crate::raw_index::dense::graph::graph_prefix(&workspace, 1)));
    assert!(!prefix.starts_with(
        &super::super::super::prefix_v2::types::prefix_key(&workspace, 1).expect("base prefix")
    ));
    assert!(
        delta_receipt_key(&workspace, 1, 1)
            .expect("receipt")
            .starts_with(&prefix)
    );
    assert!(
        !retained_locator_key(&workspace, 1, 1)
            .expect("locator")
            .starts_with(crate::raw_index::generation_prefix(&workspace, 1).as_bytes())
    );
    assert!(segment_prefix(&workspace.to_uppercase(), 1, 1).is_err());
    assert!(segment_prefix(&workspace, 0, 1).is_err());
    assert!(segment_prefix(&workspace, 1, 0).is_err());
    assert!(segment_cohort_key(&workspace, 1, 1, "bad").is_err());
    assert_ne!(
        WORKSPACE_HEADS_MAC,
        super::super::super::prefix_v2::types::WORKSPACE_HEADS_MAC
    );
    assert_ne!(
        DELTA_RECEIPT_MAC,
        super::super::super::segments::types::DELTA_RECEIPT_MAC
    );
}

#[test]
fn bounded_cohort_decoder_and_v2_stamp_reject_overflow_and_old_revision() {
    let m = manifest();
    let mut value = serde_json::to_value(&m).expect("value");
    value["cohorts"] = serde_json::to_value(vec![m.cohorts[0].clone(); MAX_COHORTS + 1])
        .expect("oversized fixture");
    assert!(serde_json::from_value::<PrefixDeltaManifestV2>(value).is_err());
    let mut stamp = PrefixSegmentHeadStampV2 {
        revision: 2,
        map_digest: d(18),
        token: "aa".repeat(32),
    };
    stamp.validate().expect("v2 stamp");
    stamp.revision = 1;
    assert!(stamp.validate().is_err());
}
