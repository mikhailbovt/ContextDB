//! Local transport/version gates; native owner tests establish seal admission.

use super::*;
use contextdb_recall::QueryCancellation;
use std::time::Duration;

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn legacy_json() -> String {
    let body = "{\"query\":\"protected-version-fixture\"}";
    format!(
        "{{\"pack_id\":\"{}\",\"wire_digest\":\"{}\",\"wire_byte_length\":10,\"router_request_digest\":\"{}\",\"router_plan_digest\":\"{}\",\"router_manifest_digest\":\"{}\",\"origin_closure_digest\":\"{}\",\"trace_digest\":\"{}\",\"canonical_json\":{},\"seal\":\"opaque-native-seal-fixture\"}}",
        ContextPackId::new(),
        digest(b"model-wire"),
        digest(b"request"),
        digest(b"plan"),
        digest(b"manifest"),
        digest(b"origins"),
        digest(body.as_bytes()),
        serde_json::to_string(body).expect("bounded JSON text"),
    )
}

fn budget() -> QueryBudget {
    QueryBudget::new(
        1000,
        16 * 1024 * 1024,
        Duration::from_secs(5),
        QueryCancellation::default(),
    )
}

#[test]
fn prepared_trace_versions_keep_legacy_transport_and_copy_exact_attachment_version() {
    let encoded = legacy_json();
    let legacy: PreparedRouterTrace = serde_json::from_str(&encoded).expect("old owner DTO");
    assert_eq!(legacy.version, ROUTER_TRACE_VERSION);
    legacy.validate().expect("local transport consistency");
    assert_eq!(
        serde_json::to_string(&legacy).expect("old owner bytes"),
        encoded
    );
    let call = ModelCallId::new();
    let old_attachment = legacy.attach(call, &mut budget()).expect("v1 pages");
    assert_eq!(old_attachment.header.version, ROUTER_TRACE_VERSION);
    let mut replay = legacy.clone();
    replay.version = ROUTER_REPLAY_TRACE_VERSION;
    let attachment = replay.attach(call, &mut budget()).expect("v2 pages");
    assert_eq!(attachment.header.version, ROUTER_REPLAY_TRACE_VERSION);
    assert_eq!(attachment.pages, old_attachment.pages);
    assert_eq!(
        attachment.header.wire_digest,
        old_attachment.header.wire_digest
    );
    let value = serde_json::to_value(&replay).expect("v2 DTO");
    assert_eq!(value["version"], serde_json::json!(2));
    let cold: PreparedRouterTrace = serde_json::from_value(value).expect("v2 cold DTO");
    assert_eq!(cold, replay);
    assert!(!format!("{cold:?}").contains("protected-version-fixture"));
    for version in [0, 3, u16::MAX] {
        let mut unsupported = replay.clone();
        unsupported.version = version;
        assert!(unsupported.validate().is_err());
        assert!(unsupported.attach(call, &mut budget()).is_err());
    }
}

#[test]
fn replay_profile_is_explicit_and_legacy_profiles_keep_their_contracts() {
    for (text, profile, version) in [
        ("off", RouterTraceProfile::Off, None),
        ("required", RouterTraceProfile::Required, Some(1)),
        (
            "required_replay_v2",
            RouterTraceProfile::RequiredReplayV2,
            Some(2),
        ),
    ] {
        let encoded = format!("\"{text}\"");
        assert_eq!(
            serde_json::from_str::<RouterTraceProfile>(&encoded).expect("explicit profile"),
            profile
        );
        assert_eq!(
            serde_json::to_string(&profile).expect("profile bytes"),
            encoded
        );
        assert_eq!(profile.version(), version);
        assert_eq!(profile.is_off(), version.is_none());
    }
    assert_eq!(RouterTraceProfile::default(), RouterTraceProfile::Off);
    assert!(serde_json::from_str::<RouterTraceProfile>("\"required_replay_v3\"").is_err());
}
