//! A controlled reader copies delivered source bytes, never an embedded key reference.

use super::*;
use contextdb_context::{BlockId, VisibleOriginal};

fn evidence(name: &str, header: &str, body: &str) -> OutgoingMessage {
    let text = format!("{header}\n{body}");
    let start = (header.len() + 1) as u64;
    OutgoingMessage {
        id: BlockId::new(name).expect("fixture block"),
        zone: OutgoingZone::Evidence,
        role: OutgoingRole::User,
        text,
        originals: vec![VisibleOriginal {
            span: OriginalSourceSpan {
                event_id: ObservationId::new(),
                payload_digest: digest(body.as_bytes()),
                start: 0,
                end: body.len() as u64,
                span_digest: digest(body.as_bytes()),
            },
            text_start: start,
            text_end: start + body.len() as u64,
        }],
        tool_calls: vec![],
        tool_result: None,
    }
}

fn reply(reader: &Reader, messages: &[OutgoingMessage]) -> ReaderReply {
    let wire = reader
        .encode(messages, &mut budget())
        .expect("actual reader wire");
    let ReaderOutcome::Completed(reply) = reader
        .complete(ModelCallId::new(), &wire)
        .expect("controlled reader completion")
    else {
        panic!("controlled reader must complete");
    };
    reply
}

#[test]
fn embedded_tool_reference_and_metadata_do_not_replace_delivered_archived_fact() {
    let reader = Reader::new();
    reader.calls.store(1, Ordering::SeqCst);
    let distractor = evidence(
        "tool-reference",
        "ARCHIVE_SILVER locator-only metadata",
        "The actual registry result requests ARCHIVE_SILVER and identifies the north entrance.",
    );
    let archive = evidence("archive-original", "Source attribution", SILVER);
    let messages = vec![distractor, archive];
    assert_eq!(reply(&reader, &messages).text, SILVER);
    assert_eq!(
        reply(&reader, &messages[..1]).text,
        "No attributable fixture evidence was delivered.",
        "a tool reference or a marker in metadata cannot supply the archived answer"
    );
    let other_key = evidence(
        "different-key",
        "Source attribution",
        "ARCHIVE_SILVERY is another archive key.",
    );
    assert_eq!(
        reply(&reader, &[other_key]).text,
        "No attributable fixture evidence was delivered.",
        "the source key boundary must match exactly"
    );
}
