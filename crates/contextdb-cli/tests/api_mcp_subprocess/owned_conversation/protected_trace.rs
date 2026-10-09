//! One real encrypted public-host turn, including its retained configuration.

use super::*;
use contextdb_service::{CognitiveMemoryService, VerifyRequest};

#[test]
fn owned_conversation_required_trace_survives_cold_resume_and_refuses_profile_switch_before_peer_launch()
 {
    let fixture = Fixture::new();
    fixture.provision();
    let peer = Peer::new(&fixture, "reply");
    let (config_path, mut config) = config(&fixture, &peer);
    config["router_trace_profile"] = serde_json::json!("required");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&config).expect("Required config"),
    )
    .expect("trusted Required opt-in");
    let output = host(
        &fixture,
        &config_path,
        false,
        input(&[
            serde_json::json!({"type":"user","text":"Current protected CLI original: avocado 7391."}),
        ]),
    );
    require_success(&output);
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("avocado 7391")
            && !String::from_utf8_lossy(&output.stderr).contains("avocado 7391"),
        "protected current material stays outside public host diagnostics"
    );
    let records = records(&output);
    let accepted = records
        .iter()
        .find(|record| record["type"] == "accepted")
        .expect("actual user capture");
    let original: CaptureReceipt = serde_json::from_value(accepted["source_receipt"].clone())
        .expect("actual original receipt");
    let answer = records
        .iter()
        .find(|record| record["type"] == "answer")
        .expect("actual deterministic completed turn");
    let sends = peer.sends();
    assert_eq!(
        sends.len(),
        1,
        "one actual dispatch in the bounded Required fixture"
    );
    {
        let owner = native(&fixture);
        let manifest = verify_answer(&owner, &config, answer, &sends);
        let trace = manifest
            .router_trace
            .as_ref()
            .expect("native retained Required attachment");
        trace
            .validate_for_model_request(&manifest)
            .expect("real call and wire commitments");
        let retained: serde_json::Value = serde_json::from_str(
            &trace
                .canonical_json()
                .expect("verified complete protected pages"),
        )
        .expect("actual native envelope");
        assert_eq!(retained["format"], "contextdb.native_router_trace.v1");
        assert!(
            retained["origins"]["originals"]
                .as_array()
                .expect("actual captured origins")
                .contains(&serde_json::json!(original.event_id))
        );
        assert!(
            retained["base_origins"]["originals"]
                .as_array()
                .expect("actual current input roots")
                .contains(&serde_json::json!(original.event_id))
        );
        let wire: Vec<u8> = serde_json::from_value(sends[0]["request"]["outgoing"]["wire"].clone())
            .expect("actual observed reader wire");
        let wire_text = std::str::from_utf8(&wire).expect("actual ChatML JSON");
        assert!(wire_text.contains("avocado 7391"));
        assert!(!wire_text.contains("contextdb.native_router_trace.v1"));
        assert!(
            sends[0]["request"].get("router_trace").is_none(),
            "protected envelope is not a reader protocol argument"
        );
        let saved = checkpoint(&owner, &config);
        assert!(saved.checkpoint.pending_model.is_none());
        assert_eq!(
            saved.checkpoint.last_model_output,
            Some(
                serde_json::from_value::<CaptureReceipt>(answer["output_receipt"].clone())
                    .expect("actual output receipt")
                    .event_id
            )
        );
        owner
            .verify(VerifyRequest {
                context: context(&config).request,
                deep: true,
            })
            .expect("cold encrypted native trace and custody audit");
    }
    peer.assert_reaped();
    let peer_records_before_switch = peer.records().len();
    let mut off = config.clone();
    off["router_trace_profile"] = serde_json::json!("off");
    let off_path = write_json(fixture.directory.path(), "owned-off.json", off);
    let refused = host(&fixture, &off_path, true, Vec::new());
    assert!(
        !refused.status.success(),
        "accepted Required binding refuses a cold Off switch"
    );
    assert_eq!(
        peer.records().len(),
        peer_records_before_switch,
        "configuration refusal precedes even the reader handshake"
    );
    let resumed = host(&fixture, &config_path, true, Vec::new());
    require_success(&resumed);
    let resumed_records = super::records(&resumed);
    assert_eq!(
        resumed_records.first().expect("actual cold ready")["type"],
        "ready"
    );
    assert_eq!(
        resumed_records.first().expect("actual cold outcome")["model_outcome_unknown"],
        false
    );
    assert_eq!(
        peer.sends().len(),
        1,
        "cold inspection cannot resend a completed request"
    );
    peer.assert_reaped();
    let owner = native(&fixture);
    verify_answer(&owner, &config, answer, &peer.sends());
    owner
        .verify(VerifyRequest {
            context: context(&config).request,
            deep: true,
        })
        .expect("Required history survives actual subprocess cold resume");
}
