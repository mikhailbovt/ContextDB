use super::*;
use crate::{EventPayload, RequestPart};

fn trace(text: &str) -> RouterTraceAttachment {
    RouterTraceAttachment::new(
        ModelCallId::new(),
        ContextPackId::new(),
        hash(b"exact-model-wire"),
        16,
        hash(b"request"),
        hash(b"plan"),
        hash(b"manifest"),
        hash(b"all-origins"),
        text,
    )
    .expect("bounded trace")
}

fn manifest(trace: Option<RouterTraceAttachment>) -> ModelRequestManifest {
    let call = trace
        .as_ref()
        .map_or_else(ModelCallId::new, |value| value.header.model_call_id);
    ModelRequestManifest {
        model_call_id: call,
        renderer: "test-exact-wire-v1".into(),
        wire_digest: hash(b"exact-model-wire"),
        byte_length: 16,
        parts: vec![RequestPart::Novel {
            bytes: b"exact-model-wire".to_vec(),
        }],
        router_trace: trace.map(Box::new),
    }
}

#[test]
fn protected_utf8_pages_reject_tampering_without_changing_model_wire() {
    let text = format!(
        "{}Ж🙂private-query-material",
        "x".repeat(MAX_ROUTER_TRACE_PAGE_BYTES - 1)
    );
    let observed = trace(&text);
    assert_eq!(observed.pages.len(), 2);
    assert_eq!(
        observed.pages[0].text.len(),
        MAX_ROUTER_TRACE_PAGE_BYTES - 1
    );
    assert_eq!(observed.canonical_json().expect("verified pages"), text);
    let request = manifest(Some(observed.clone()));
    observed
        .validate_for_model_request(&request)
        .expect("same call and wire");
    assert_eq!(
        EventPayload::Assembly {
            manifest: request.clone()
        }
        .digest(),
        Some(request.wire_digest)
    );
    for mutation in [
        (|value: &mut RouterTraceAttachment| value.pages[1].text.push('!'))
            as fn(&mut RouterTraceAttachment),
        |value: &mut RouterTraceAttachment| value.pages.swap(0, 1),
        |value: &mut RouterTraceAttachment| value.header.pages[1].index = 0,
        |value: &mut RouterTraceAttachment| value.header.byte_length += 1,
        |value: &mut RouterTraceAttachment| value.header.trace_digest = hash(b"different trace"),
        |value: &mut RouterTraceAttachment| {
            value.pages.remove(0);
        },
    ] {
        let mut changed = observed.clone();
        mutation(&mut changed);
        assert!(changed.validate().is_err());
    }
    for mutation in [
        (|value: &mut RouterTraceAttachment| value.header.model_call_id = ModelCallId::new())
            as fn(&mut RouterTraceAttachment),
        |value: &mut RouterTraceAttachment| value.header.wire_digest = hash(b"different wire"),
        |value: &mut RouterTraceAttachment| value.header.wire_byte_length += 1,
    ] {
        let mut transplanted = observed.clone();
        mutation(&mut transplanted);
        assert!(transplanted.validate_for_model_request(&request).is_err());
    }
    assert!(!format!("{observed:?}").contains("private-query-material"));
    assert!(!format!("{:?}", observed.pages[1]).contains("private-query-material"));
}

#[test]
fn trace_ceiling_and_strict_page_transport_refuse_excess_or_duplicate_metadata() {
    let observed = trace("{\"query\":\"private-query-material\"}");
    assert!(
        RouterTraceAttachment::new(
            observed.header.model_call_id,
            observed.header.pack_id,
            observed.header.wire_digest,
            observed.header.wire_byte_length,
            observed.header.router_request_digest,
            observed.header.router_plan_digest,
            observed.header.router_manifest_digest,
            observed.header.origin_closure_digest,
            &"x".repeat(MAX_ROUTER_TRACE_BYTES + 1),
        )
        .is_err()
    );
    let mut extra = serde_json::to_value(&observed).expect("trace serialization");
    extra["pages"] = serde_json::json!(vec![&observed.pages[0]; MAX_ROUTER_TRACE_PAGES + 1]);
    assert!(serde_json::from_value::<RouterTraceAttachment>(extra).is_err());
    let mut oversized = serde_json::to_value(&observed).expect("trace serialization");
    oversized["pages"][0]["text"] = serde_json::json!("x".repeat(MAX_ROUTER_TRACE_PAGE_BYTES + 1));
    assert!(serde_json::from_value::<RouterTraceAttachment>(oversized).is_err());
    let encoded = serde_json::to_string(&observed).expect("trace serialization");
    let duplicated = encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(serde_json::from_str::<RouterTraceAttachment>(&duplicated).is_err());
    let mut extra = serde_json::to_value(&observed).expect("trace serialization");
    extra["header"]["grant"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RouterTraceAttachment>(extra).is_err());
}

#[test]
fn absent_trace_preserves_legacy_manifest_json_exactly() {
    let request = manifest(None);
    let expected = format!(
        "{{\"model_call_id\":\"{}\",\"renderer\":\"test-exact-wire-v1\",\"wire_digest\":\"{}\",\"byte_length\":16,\"parts\":[{{\"kind\":\"novel\",\"bytes\":{:?}}}]}}",
        request.model_call_id, request.wire_digest, b"exact-model-wire"
    ).replace(", ", ",");
    assert_eq!(
        serde_json::to_string(&request).expect("legacy serialization"),
        expected
    );
    let decoded: ModelRequestManifest = serde_json::from_str(&expected).expect("legacy manifest");
    assert!(decoded.router_trace.is_none());
    assert_eq!(decoded, request);
}

#[test]
fn explicit_replay_version_preserves_pages_and_legacy_constructor_bytes() {
    let text = format!(
        "{}Ж🙂protected-replay",
        "x".repeat(MAX_ROUTER_TRACE_PAGE_BYTES - 1)
    );
    let legacy = trace(&text);
    let header = &legacy.header;
    let make = |version| {
        RouterTraceAttachment::new_with_version(
            version,
            header.model_call_id,
            header.pack_id,
            header.wire_digest,
            header.wire_byte_length,
            header.router_request_digest,
            header.router_plan_digest,
            header.router_manifest_digest,
            header.origin_closure_digest,
            &text,
        )
    };
    let explicit_v1 = make(ROUTER_TRACE_VERSION).expect("explicit legacy contract");
    assert_eq!(
        serde_json::to_vec(&explicit_v1).expect("v1 bytes"),
        serde_json::to_vec(&legacy).expect("legacy bytes")
    );
    let replay = make(ROUTER_REPLAY_TRACE_VERSION).expect("explicit replay pages");
    assert_eq!(replay.header.version, 2);
    assert_eq!(replay.pages, legacy.pages);
    assert_eq!(replay.header.pages, legacy.header.pages);
    assert_eq!(replay.header.trace_digest, legacy.header.trace_digest);
    assert_eq!(replay.canonical_json().expect("complete UTF-8"), text);
    replay
        .validate_for_model_request(&manifest(Some(replay.clone())))
        .expect("same model wire");
    let encoded = serde_json::to_vec(&replay).expect("replay transport");
    let decoded: RouterTraceAttachment =
        serde_json::from_slice(&encoded).expect("cold replay pages");
    assert_eq!(decoded, replay);
    assert!(!format!("{replay:?}").contains("protected-replay"));
    for version in [0, 3, u16::MAX] {
        assert!(make(version).is_err());
        let mut changed = replay.clone();
        changed.header.version = version;
        assert!(changed.validate().is_err());
    }
}
