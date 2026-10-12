//! Pure format tests. These fixtures confer no native publication authority.
use super::*;
use contextdb_service::TextEmbeddingProfile;

fn d(byte: u8) -> ContentDigest {
    ContentDigest::from_bytes([byte; 32])
}
fn manifest() -> DensePrefixBaseManifestV2 {
    let profile = TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(d(1));
    DensePrefixBaseManifestV2 {
        revision: 2,
        raw: PrefixRawBindingV2 {
            generation: 1,
            custody_version: crate::custody::CUSTODY_VERSION,
            analyzer: RAW_ANALYZER.into(),
            bm25: Bm25Profile::fixed(),
            authorization_epoch: 0,
            removal_through: None,
            through: 1000,
            projected_sources: 600,
        },
        admitted_known_at: 1001,
        admitted_global_commit: 1002,
        target: AcceptedPublicationRef {
            global_commit: 1002,
            event_digest: "11".repeat(32),
            request_digest: "22".repeat(32),
            response_digest: "33".repeat(32),
        },
        prefix: DenseManifest {
            profile_digest: profile.digest().expect("fixed profile"),
            vector_space_id: profile.vector_space_id().expect("fixed space"),
            profile,
            through: 3,
            sources: 2,
            embedded_sources: 1,
            spans: 1,
            omitted_sources: 1,
            commitment: d(2),
        },
        interval: PrefixIntervalV2 {
            work_items: 2,
            digest: d(3),
        },
        nodes: 1,
        cohorts: vec![GraphCohortSummary {
            policy_domain: "44".repeat(32),
            partition_digest: d(4),
            nodes: 1,
        }],
        builder_revision: ANN_PARTITION_BUILD_REVISION_V2.into(),
        content_digest: d(5),
    }
}

#[test]
fn full_raw_census_and_small_real_prefix_have_separate_canonical_fields() {
    let m = manifest();
    m.validate().expect("partial prefix shape");
    assert!(m.raw.through > m.prefix.through);
    assert!(m.raw.projected_sources > m.prefix.sources);
    let bytes = crate::encode(&m).expect("canonical bytes");
    let restored: DensePrefixBaseManifestV2 =
        crate::decode(&bytes, "format fixture").expect("bounded decode");
    assert_eq!(restored, m);
    assert_eq!(crate::encode(&restored).expect("canonical again"), bytes);
    let mut value = serde_json::to_value(m).expect("typed value");
    value
        .as_object_mut()
        .expect("object")
        .insert("source_generation".into(), serde_json::json!([]));
    assert!(
        serde_json::from_value::<DensePrefixBaseManifestV2>(value).is_err(),
        "no fake v1 envelope field"
    );
}

#[test]
fn prefix_shape_refuses_empty_partial_and_wrong_admission_bindings() {
    for change in 0..5 {
        let mut m = manifest();
        match change {
            0 => {
                m.nodes = 0;
                m.prefix.spans = 0;
                m.prefix.embedded_sources = 0;
                m.prefix.omitted_sources = 2;
                m.cohorts.clear();
            }
            1 => m.interval.work_items = MAX_WORK + 1,
            2 => m.admitted_global_commit = m.target.global_commit - 1,
            3 => m.prefix.profile.dimensions = 512,
            _ => m.raw.projected_sources = 1,
        }
        assert!(m.validate().is_err(), "invalid shape {change}");
    }
}

#[test]
fn current_ref_avoids_same_event_digest_cycle_and_retained_locator_keeps_it() {
    let reference = PrefixBaseRefV2 {
        global_commit: 1003,
        request_digest: "22".repeat(32),
        response_digest: "33".repeat(32),
        receipt_digest: d(6),
        content_digest: d(5),
    };
    reference.validate().expect("cycle-free map reference");
    let value = serde_json::to_value(reference).expect("value");
    assert!(value.get("event_digest").is_none());
    assert!(value.get("publication").is_none());
    let locator = RetainedPrefixBaseLocatorV2 {
        revision: 2,
        workspace_digest: "55".repeat(32),
        generation: 1,
        publication: manifest().target,
        token: "66".repeat(32),
    };
    locator
        .validate()
        .expect("retained full accepted ref shape");
    assert!(
        serde_json::to_value(locator).expect("value")["publication"]
            .get("event_digest")
            .is_some()
    );
}

#[test]
fn prefix_keys_stay_outside_old_graph_and_locator_stays_outside_generation_gc() {
    let workspace = "ab".repeat(32);
    let prefix = prefix_key(&workspace, 1).expect("prefix");
    assert!(!prefix.starts_with(&crate::raw_index::dense::graph::graph_prefix(&workspace, 1)));
    let receipt = receipt_key(&workspace, 1).expect("receipt");
    assert!(receipt.starts_with(&prefix));
    let locator = retained_locator_key(&workspace, 1).expect("locator");
    assert!(!locator.starts_with(crate::raw_index::generation_prefix(&workspace, 1).as_bytes()));
    assert!(prefix_key(&workspace.to_uppercase(), 1).is_err());
    assert!(prefix_key(&workspace, 0).is_err());
    assert!(cohort_key(&workspace, 1, "bad").is_err());
}

#[test]
fn bounded_cohort_decode_rejects_overflow_before_allocating_caller_size_hint() {
    let m = manifest();
    let mut value = serde_json::to_value(&m).expect("value");
    value["cohorts"] = serde_json::to_value(vec![m.cohorts[0].clone(); MAX_COHORTS + 1])
        .expect("oversized fixture");
    assert!(serde_json::from_value::<DensePrefixBaseManifestV2>(value).is_err());
    let mut stamp = PrefixBaseStampV2 {
        revision: 2,
        map_digest: d(9),
        token: "88".repeat(32),
    };
    stamp.validate().expect("v2 stamp shape");
    stamp.revision = 1;
    assert!(stamp.validate().is_err());
}
