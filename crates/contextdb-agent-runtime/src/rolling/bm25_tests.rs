use super::*;
use contextdb_core::{ContentDigest, ObservationId};
use std::time::Duration;

#[test]
fn bm25_cues_use_visible_tool_bytes_and_preserve_unicode_for_one_native_analysis() {
    let body = "ZEPPELIN7341 CHRONOMETER6182 İSTANBUL";
    let prefix =
        "[source locator protocol metadata identifier_012345678901234567890123456789]\n".repeat(64);
    let digest = ContentDigest::from_bytes(*blake3::hash(body.as_bytes()).as_bytes());
    let message = OutgoingMessage {
        id: BlockId::new("visible-tool-data").expect("block"),
        zone: OutgoingZone::CurrentTurn,
        role: OutgoingRole::Tool,
        text: prefix.clone() + body,
        originals: vec![VisibleOriginal {
            span: OriginalSourceSpan {
                event_id: ObservationId::new(),
                payload_digest: digest,
                start: 0,
                end: body.len() as u64,
                span_digest: digest,
            },
            text_start: prefix.len() as u64,
            text_end: (prefix.len() + body.len()) as u64,
        }],
        tool_calls: vec![],
        tool_result: Some("fixture-call".into()),
    };
    let base = OutgoingBase {
        current: vec![message],
        control: vec![],
        working: vec![],
        hot: vec![],
    };
    let mut budget = QueryBudget::new(
        1_000_000,
        4 * 1024 * 1024,
        Duration::from_secs(10),
        Default::default(),
    );
    let cues = bm25_step_routes(&base, &mut budget).expect("actual data cues");
    let query = bm25_step_query(&cues, &RawFilter::default(), 64, &mut budget)
        .expect("bounded query")
        .expect("nonempty query");
    assert!(query.text.contains("ZEPPELIN7341"));
    assert!(query.text.contains("CHRONOMETER6182"));
    assert!(query.text.contains("İSTANBUL"));
    assert!(!query.text.contains("identifier_"));
    assert!(query.text.len() <= 4096);
    assert!(cues.routes.len() <= 64);
    assert_eq!(cues.inspected_bytes, body.len() as u64);
}
