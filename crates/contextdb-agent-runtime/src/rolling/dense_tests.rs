use super::*;
use contextdb_continuity::OriginalPageHandle;
use contextdb_core::ObservationId;
use contextdb_recall::QueryCancellation;
use std::time::Duration;

fn budget() -> QueryBudget {
    QueryBudget::new(
        1_000_000,
        16 * 1024 * 1024,
        Duration::from_secs(10),
        Default::default(),
    )
}
fn observed(id: &str, role: OutgoingRole, body: &str, prefix: &str) -> OutgoingMessage {
    let digest = ContentDigest::from_bytes(*blake3::hash(body.as_bytes()).as_bytes());
    OutgoingMessage {
        id: BlockId::new(id).expect("block"),
        zone: OutgoingZone::CurrentTurn,
        role,
        text: prefix.to_owned() + body,
        originals: vec![VisibleOriginal {
            span: OriginalSourceSpan {
                event_id: ObservationId::new(),
                payload_digest: digest,
                start: 17,
                end: 17 + body.len() as u64,
                span_digest: digest,
            },
            text_start: prefix.len() as u64,
            text_end: (prefix.len() + body.len()) as u64,
        }],
        tool_calls: vec![],
        tool_result: (role == OutgoingRole::Tool).then(|| "fixture-call".into()),
    }
}
fn base(current: Vec<OutgoingMessage>) -> OutgoingBase {
    OutgoingBase {
        control: vec![],
        working: vec![],
        hot: vec![],
        current,
    }
}

#[test]
fn dense_cues_preserve_paraphrase_and_new_tool_correction_without_headers() {
    let old = "Could you first look at the earlier arrangement?";
    let paraphrase = "Where was the spare we kept for the colder months?";
    let correction = "Correction: It is now beside the front entrance, not in the basement.";
    let header = format!(
        "handle={}\nsource_digest=012345678901234567890\n",
        "opaque_locator_".repeat(128)
    );
    let mut input = base(vec![
        observed("old-user", OutgoingRole::User, old, ""),
        observed("new-user", OutgoingRole::User, paraphrase, ""),
        observed("new-tool", OutgoingRole::Tool, correction, &header),
    ]);
    input.control.push(observed(
        "control",
        OutgoingRole::User,
        "CONTROL_SENTINEL",
        "",
    ));
    input.hot.push(observed(
        "history",
        OutgoingRole::User,
        "OLD_HISTORY_SENTINEL",
        "",
    ));
    let original = input.clone();
    let cues = dense_step_query(&input, &mut budget()).expect("syntax-preserving query");
    assert_eq!(
        input, original,
        "query sampling never rewrites original/rendered input"
    );
    assert!(cues.text.contains(paraphrase) && cues.text.contains(correction));
    assert!(
        cues.text.find(old).expect("earlier phrasing")
            < cues.text.find(paraphrase).expect("later phrasing")
    );
    assert!(!cues.text.contains("opaque_locator") && !cues.text.contains("source_digest"));
    assert!(!cues.text.contains("CONTROL_SENTINEL") && !cues.text.contains("OLD_HISTORY_SENTINEL"));
    assert_eq!(
        cues.inspected_bytes,
        (old.len() + paraphrase.len() + correction.len()) as u64
    );
    assert_eq!(cues.omitted_bytes, 0);
    assert_eq!(
        cues.text_digest,
        ContentDigest::from_bytes(*blake3::hash(cues.text.as_bytes()).as_bytes())
    );
    assert!(!format!("{cues:?}").contains(paraphrase));
    for fragment in &cues.fragments {
        let message = input
            .current
            .iter()
            .find(|message| message.id == fragment.message_id)
            .expect("message");
        let bytes = message
            .text
            .get(fragment.message_start as usize..fragment.message_end as usize)
            .expect("exact rendered excerpt");
        assert_eq!(
            &cues.text[fragment.query_start as usize..fragment.query_end as usize],
            bytes
        );
        let source = fragment.source.as_ref().expect("attributed excerpt");
        assert_eq!(
            source.span_digest,
            ContentDigest::from_bytes(*blake3::hash(bytes.as_bytes()).as_bytes())
        );
    }
}

#[test]
fn dense_cues_skip_only_the_supported_page_metadata_anchor_and_keep_preview() {
    let body = "The newest observation cancels the prior instruction.";
    let preview = observed("preview", OutgoingRole::Tool, body, "")
        .originals
        .remove(0)
        .span;
    let view = ToolResultPageView {
        handle: OriginalPageHandle {
            database_id: "dense-fixture".into(),
            event_id: preview.event_id,
            payload_digest: preview.payload_digest,
            byte_length: 8192,
        },
        preview: preview.clone(),
    };
    let metadata = serde_json::to_string(&view).expect("exact host page metadata");
    let prefix = "[original tool view]\nhandle=opaque_locator\n";
    let mut message = observed("tool-page", OutgoingRole::Tool, &metadata, prefix);
    message.text.push('\n');
    let start = message.text.len() as u64;
    message.text.push_str(body);
    message.originals.push(VisibleOriginal {
        span: preview,
        text_start: start,
        text_end: message.text.len() as u64,
    });
    let cues =
        dense_step_query(&base(vec![message]), &mut budget()).expect("actual original preview");
    assert!(cues.text.contains(body));
    assert!(
        !cues.text.contains("opaque_locator")
            && !cues.text.contains("database_id")
            && !cues.text.contains("payload_digest")
    );
    assert_eq!(cues.inspected_bytes, body.len() as u64);
    assert_eq!(
        cues.omitted_bytes, 0,
        "protocol anchors are excluded from eligible source-text bytes"
    );
    assert_eq!(cues.fragments.len(), 1);
}

#[test]
fn dense_cues_bound_utf8_samples_and_preserve_head_tail_and_channel_quotas() {
    let user = format!(
        "Вопрос: Кто теперь отвечает за это? {} ИТОГ: прежнее решение отменено!",
        "ё🙂 Япония. ".repeat(500)
    );
    let tool = format!(
        "НОВОЕ: исправленная дата. {} ИСПРАВЛЕНИЕ: срок завтра, не вчера!",
        "空🙂 Наблюдение. ".repeat(500)
    );
    let input = base(vec![
        observed("utf8-user", OutgoingRole::User, &user, ""),
        observed("utf8-tool", OutgoingRole::Tool, &tool, "header=locator\n"),
    ]);
    let cues = dense_step_query(&input, &mut budget()).expect("bounded source cues");
    assert!(cues.text.len() <= MAX_DENSE_QUERY_CUE_BYTES);
    assert!(
        cues.text.contains("Вопрос: Кто теперь отвечает за это?")
            && cues.text.contains("ИТОГ: прежнее решение отменено!")
    );
    assert!(
        cues.text.contains("НОВОЕ: исправленная дата.")
            && cues.text.contains("ИСПРАВЛЕНИЕ: срок завтра, не вчера!")
    );
    assert!(cues.text.contains("[omitted]") && !cues.text.contains("header=locator"));
    assert_eq!(
        cues.inspected_bytes + cues.omitted_bytes,
        (user.len() + tool.len()) as u64
    );
    assert!(
        cues.fragments
            .iter()
            .any(|fragment| fragment.channel == DenseCueChannel::User)
    );
    assert!(
        cues.fragments
            .iter()
            .any(|fragment| fragment.channel == DenseCueChannel::Tool)
    );
    for fragment in &cues.fragments {
        let message = input
            .current
            .iter()
            .find(|message| message.id == fragment.message_id)
            .expect("message");
        let actual = message
            .text
            .get(fragment.message_start as usize..fragment.message_end as usize)
            .expect("UTF-8 boundaries");
        assert_eq!(
            actual,
            &cues.text[fragment.query_start as usize..fragment.query_end as usize]
        );
    }
}

#[test]
fn dense_cues_refuse_bad_render_spans_and_use_the_parent_limits() {
    let mut input = base(vec![observed(
        "broken",
        OutgoingRole::User,
        "🙂 safe source",
        "header\n",
    )]);
    input.current[0].originals[0].text_start += 1;
    assert_eq!(
        dense_step_query(&input, &mut budget())
            .expect_err("bisected rendering span")
            .code,
        contextdb_service::ErrorCode::InvalidArgument
    );
    let input = base(vec![observed(
        "valid",
        OutgoingRole::User,
        "Which version applies now?",
        "",
    )]);
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    for mut allowance in [
        QueryBudget::new(
            1_000_000,
            16 * 1024 * 1024,
            Duration::from_secs(10),
            cancellation,
        ),
        QueryBudget::new(1_000_000, 0, Duration::from_secs(10), Default::default()),
        QueryBudget::new(
            0,
            16 * 1024 * 1024,
            Duration::from_secs(10),
            Default::default(),
        ),
        QueryBudget::new(
            1_000_000,
            16 * 1024 * 1024,
            Duration::ZERO,
            Default::default(),
        ),
    ] {
        assert_eq!(
            dense_step_query(&input, &mut allowance)
                .expect_err("shared allowance")
                .code,
            contextdb_service::ErrorCode::BudgetExhausted
        );
    }
    let mut allowance = budget();
    let before = (allowance.remaining_work(), allowance.remaining_bytes());
    dense_step_query(&input, &mut allowance).expect("actual charged sample");
    assert!(allowance.remaining_work() < before.0 && allowance.remaining_bytes() < before.1);
}
