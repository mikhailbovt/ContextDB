//! Format/refusal tests; synthetic digests are not owner-issued publications.

use super::*;
use contextdb_service::TextEmbeddingProfile;

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::from_bytes([byte; 32])
}
fn publication(global_commit: u64) -> AcceptedPublicationRef {
    AcceptedPublicationRef {
        global_commit,
        event_digest: "11".repeat(32),
        request_digest: "22".repeat(32),
        response_digest: "33".repeat(32),
    }
}
fn manifest() -> DenseDeltaManifest {
    let profile = TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(digest(1));
    let before = DenseManifest {
        profile: profile.clone(),
        profile_digest: profile.digest().expect("profile"),
        vector_space_id: profile.vector_space_id().expect("space"),
        through: 10,
        sources: 1,
        embedded_sources: 1,
        spans: 1,
        omitted_sources: 0,
        commitment: digest(2),
    };
    let mut after = before.clone();
    after.through = 20;
    after.sources = 2;
    after.embedded_sources = 2;
    after.spans = 2;
    after.commitment = digest(3);
    DenseDeltaManifest {
        revision: 1,
        binding: DeltaGenerationBinding {
            generation: 1,
            custody_version: crate::custody::CUSTODY_VERSION,
            analyzer: RAW_ANALYZER.into(),
            bm25: Bm25Profile::fixed(),
            authorization_epoch: 0,
            removal_through: Some(0),
            raw_through: 20,
            raw_sources: 2,
        },
        ordinal: 1,
        base: BaseRef {
            publication: publication(11),
            receipt_digest: digest(4),
            graph_digest: digest(5),
        },
        before,
        after,
        target_dense: publication(21),
        interval_digest: digest(6),
        work_items: 1,
        nodes: 1,
        cohorts: vec![GraphCohortSummary {
            policy_domain: "aa".repeat(32),
            partition_digest: digest(7),
            nodes: 1,
        }],
        builder_revision: ANN_PARTITION_BUILD_REVISION_V2.into(),
        content_digest: digest(8),
    }
}
fn head() -> DenseSegmentDirectoryHead {
    let m = manifest();
    DenseSegmentDirectoryHead {
        revision: 1,
        generation: 1,
        base: m.base,
        count: 1,
        latest: SegmentRef {
            ordinal: 1,
            global_commit: 22,
            manifest_digest: m.content_digest,
            receipt_digest: digest(9),
        },
        covered: m.after,
        previous: None,
        content_digest: digest(10),
    }
}

#[test]
fn canonical_delta_roundtrip_unknown_fields_and_legacy_none_stay_explicit() {
    let m = manifest();
    m.validate().expect("bounded shape");
    let bytes = crate::encode(&m).expect("canonical encoding");
    let restored: DenseDeltaManifest = crate::decode(&bytes, "shape fixture").expect("decode");
    assert_eq!(crate::encode(&restored).expect("re-encode"), bytes);
    let mut unexpected = serde_json::to_value(&m).expect("value");
    unexpected["caller_can_authorize"] = serde_json::json!(true);
    assert!(serde_json::from_value::<DenseDeltaManifest>(unexpected).is_err());

    let legacy = format!(
        "{{\"number\":1,\"custody_version\":1,\"analyzer\":{},\"through\":10,\"authorization_epoch\":0,\"projected_sources\":1}}",
        serde_json::to_string(RAW_ANALYZER).expect("analyzer JSON"),
    );
    let generation: crate::raw_index::Generation =
        crate::decode(legacy.as_bytes(), "old raw generation")
            .expect("new omitted fields default to None");
    assert_eq!(
        crate::encode(&generation)
            .expect("same old encoding")
            .as_slice(),
        legacy.as_bytes()
    );
}

#[test]
fn coverage_only_delta_has_no_invented_vectors() {
    let mut m = manifest();
    m.after.embedded_sources = m.before.embedded_sources;
    m.after.spans = m.before.spans;
    m.after.omitted_sources = 1;
    m.nodes = 0;
    m.cohorts.clear();
    m.validate()
        .expect("complete omission/control interval shape");
    m.nodes = 1;
    assert!(
        m.validate().is_err(),
        "omitted-only interval cannot manufacture a node"
    );
}

#[test]
fn delta_rejects_profile_counter_and_placeholder_changes() {
    let mut stale = manifest();
    stale.after.profile.backend_artifacts_digest = digest(15);
    stale.after.profile_digest = stale.after.profile.digest().expect("other valid profile");
    stale.after.vector_space_id = stale
        .after
        .profile
        .vector_space_id()
        .expect("other valid space");
    assert!(
        stale.validate().is_err(),
        "equal dimensions do not admit another encoder"
    );
    let mut backwards = manifest();
    backwards.after.through = backwards.before.through;
    backwards.binding.raw_through = backwards.after.through;
    assert!(backwards.validate().is_err());
    let mut oversized = manifest();
    oversized.work_items = MAX_WORK + 1;
    assert!(oversized.validate().is_err());
    let mut placeholder = manifest();
    placeholder.content_digest = digest(0);
    assert!(placeholder.validate().is_err());
    let mut overflow = manifest();
    overflow.cohorts[0].nodes = u64::MAX;
    overflow.cohorts.push(overflow.cohorts[0].clone());
    assert!(
        overflow.validate().is_err(),
        "cohort sum is checked rather than wrapping"
    );
}

#[test]
fn directory_supports_many_appends_without_unbounded_history_or_wrap() {
    let mut h = head();
    h.count = 10_000;
    h.latest.ordinal = h.count;
    h.latest.global_commit = 50_001;
    h.covered.through = 50_000;
    h.covered.sources = 20_000;
    h.covered.embedded_sources = 1;
    h.covered.spans = 1;
    h.covered.omitted_sources = 19_999;
    h.previous = Some(DirectoryRef {
        count: 9_999,
        global_commit: 49_999,
        request_digest: "44".repeat(32),
        response_digest: "55".repeat(32),
        content_digest: digest(12),
    });
    h.validate().expect("no one-delta format ceiling");
    assert!(crate::encode(&h).expect("fixed head").len() < 4096);
    h.previous.as_mut().expect("previous").count = u64::MAX;
    assert!(h.validate().is_err(), "checked next ordinal refuses wrap");
    let mut wrong = head();
    wrong.latest.ordinal = 2;
    assert!(wrong.validate().is_err());
}

#[test]
fn bounded_cohort_and_node_decoders_refuse_the_extra_entry() {
    let m = manifest();
    let mut value = serde_json::to_value(&m).expect("manifest value");
    value["cohorts"] = serde_json::Value::Array(
        std::iter::repeat_n(value["cohorts"][0].clone(), MAX_COHORTS + 1).collect(),
    );
    assert!(serde_json::from_value::<DenseDeltaManifest>(value).is_err());
    let node = serde_json::json!({ "segment_ordinal":1,
        "representation_id":RepresentationId::new(), "policy_domain":"aa".repeat(32),
        "canonical_node":vec![0_u8; ANN_V2_MAX_NODE_BYTES + 1],
        "segment_digest":digest(8), "token":"66".repeat(32) });
    assert!(serde_json::from_value::<SegNode>(node).is_err());
}

#[test]
fn segment_keys_are_canonical_disjoint_and_reject_path_injection() {
    let workspace = "11".repeat(32);
    let first = delta_receipt_key(&workspace, 1, 1).expect("first");
    let second = delta_receipt_key(&workspace, 1, 2).expect("second");
    assert_ne!(first, second);
    assert!(first.ends_with(b"segment/0000000000000001/receipt"));
    let retained = retained_locator_key(&workspace, 1, 1).expect("retained");
    assert!(
        !retained.starts_with(&graph_prefix(&workspace, 1)),
        "locator survives live-row GC"
    );
    assert!(first.len() as u64 <= KEY_BYTES && retained.len() as u64 <= KEY_BYTES);
    assert!(segment_prefix("../workspace", 1, 1).is_err());
    assert!(segment_prefix(&"AA".repeat(32), 1, 1).is_err());
    assert!(segment_prefix(&workspace, 0, 1).is_err());
    assert!(segment_prefix(&workspace, 1, 0).is_err());
    assert!(segment_cohort_key(&workspace, 1, 1, "domain/escape").is_err());
}

#[test]
fn workspace_stamp_and_combined_publication_reject_different_heads() {
    let stamp = SegmentHeadStamp {
        revision: 1,
        map_digest: digest(2),
        token: "77".repeat(32),
    };
    stamp.validate().expect("stamp shape, not a MAC check");
    let bad = SegmentHeadStamp {
        map_digest: digest(0),
        ..stamp
    };
    assert!(bad.validate().is_err());
    let mut p = DenseSegmentPublication {
        delta: DenseDeltaReceipt {
            database_id: "shape-fixture".into(),
            workspace_id: "workspace".into(),
            manifest: manifest(),
            global_commit: 22,
            token: "88".repeat(32),
        },
        directory: DenseSegmentDirectoryReceipt {
            database_id: "shape-fixture".into(),
            workspace_id: "workspace".into(),
            head: head(),
            global_commit: 22,
            token: "99".repeat(32),
        },
    };
    p.directory.head.latest.receipt_digest = ContentDigest::from_bytes(
        *blake3::hash(&crate::encode(&p.delta).expect("signed shape bytes")).as_bytes(),
    );
    p.validate().expect("combined structural join");
    p.directory.head.covered.commitment = digest(14);
    assert!(
        p.validate().is_err(),
        "directory cannot cover a different accepted prefix"
    );
}
