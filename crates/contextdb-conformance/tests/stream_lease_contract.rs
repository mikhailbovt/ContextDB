use contextdb_conformance::{
    compare_schema_compatibility, current_schema_manifest, parse_proto_schema,
};
use contextdb_proto::v1 as wire;
use contextdb_service::{ErrorCode, IngestAck, IngestDisposition, stream_lease_expired_error};
use prost::Message;

#[derive(Clone, PartialEq, Message)]
struct ReleasedIngestAck {
    #[prost(string, tag = "1")]
    stream_id: String,
    #[prost(uint64, tag = "2")]
    position: u64,
    #[prost(enumeration = "wire::IngestDisposition", tag = "3")]
    disposition: i32,
    #[prost(string, tag = "4")]
    frame_digest: String,
    #[prost(string, tag = "5")]
    resume_cursor: String,
    #[prost(uint64, optional, tag = "6")]
    commit_seq: Option<u64>,
    #[prost(string, repeated, tag = "7")]
    partial_result_refs: Vec<String>,
}

fn released_ack() -> ReleasedIngestAck {
    ReleasedIngestAck {
        stream_id: "stream:lease".to_owned(),
        position: 4,
        disposition: wire::IngestDisposition::Accepted as i32,
        frame_digest: "digest".to_owned(),
        resume_cursor: "cursor".to_owned(),
        commit_seq: None,
        partial_result_refs: Vec::new(),
    }
}

#[test]
fn lease_deadline_is_additive_and_protobuf_bidirectionally_compatible() {
    let baseline = parse_proto_schema(include_str!("fixtures/contextdb_v1_released.proto"))
        .expect("released schema");
    let current = current_schema_manifest().expect("current schema");
    let compatibility = compare_schema_compatibility(&baseline, &current);
    assert!(compatibility.compatible, "{compatibility:?}");
    let lease_field = current
        .messages
        .get("IngestAck")
        .and_then(|fields| fields.get(&8))
        .expect("lease field 8");
    assert_eq!(lease_field.name, "lease_expires_at_ms");
    assert_eq!(lease_field.type_name, "uint64");
    assert_eq!(lease_field.cardinality, "optional");

    let released = released_ack();
    let upgraded = wire::IngestAck::decode(released.encode_to_vec().as_slice())
        .expect("new reader accepts released bytes");
    assert_eq!(upgraded.lease_expires_at_ms, None);

    let mut leased = upgraded;
    leased.lease_expires_at_ms = Some(1_750_000_000_000);
    let downgraded = ReleasedIngestAck::decode(leased.encode_to_vec().as_slice())
        .expect("released reader ignores additive field");
    assert_eq!(downgraded, released);
}

#[test]
fn json_deadline_is_visible_but_legacy_payloads_default_to_no_lease() {
    let legacy = r#"{
        "stream_id":"stream:lease",
        "position":0,
        "disposition":"accepted",
        "frame_digest":"digest",
        "resume_cursor":"cursor",
        "commit_seq":null,
        "partial_result_refs":[]
    }"#;
    let mut ack: IngestAck = serde_json::from_str(legacy).expect("legacy JSON acknowledgement");
    assert_eq!(ack.lease_expires_at_ms, None);
    assert!(
        !serde_json::to_string(&ack)
            .expect("unleased JSON")
            .contains("lease_expires_at_ms")
    );

    ack.lease_expires_at_ms = Some(1_750_000_000_000);
    let json = serde_json::to_value(&ack).expect("leased JSON acknowledgement");
    assert_eq!(json["lease_expires_at_ms"], 1_750_000_000_000_u64);
}

#[test]
fn expired_stream_outcome_is_stable_non_retryable_and_payload_free() {
    let error = stream_lease_expired_error();
    assert_eq!(error.code, ErrorCode::SnapshotExpired);
    assert!(!error.retryable);
    assert!(error.partial_result_refs.is_empty());
    assert_eq!(
        error.violated_policy.as_deref(),
        Some("stream_lease_expired")
    );
    assert_eq!(
        error.safe_next_action.as_deref(),
        Some("open a new source stream with a new stream ID")
    );

    let completed = IngestAck {
        stream_id: "stream:lease".to_owned(),
        position: 1,
        disposition: IngestDisposition::SnapshotCommitted,
        frame_digest: "digest".to_owned(),
        resume_cursor: "cursor".to_owned(),
        commit_seq: Some(7),
        partial_result_refs: Vec::new(),
        lease_expires_at_ms: None,
    };
    assert_eq!(completed.lease_expires_at_ms, None);
}
