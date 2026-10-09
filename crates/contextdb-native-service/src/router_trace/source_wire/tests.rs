//! Actual encrypted accepted-wire verification and current owner gates.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use contextdb_context::{
    BlockId, EncodedOutgoing, OutgoingEncoder, OutgoingMessage, OutgoingRole, OutgoingZone,
    ReferenceOutgoingEncoder, ReferenceTokenizer, RequestCountKind, VisibleOriginal,
};
use contextdb_core::{
    ContentBlockId, EventPayload, EventRole, ModelCallId, ModelRequestManifest, ObservationId,
    OriginalSourceSpan, RequestPart,
};
use contextdb_recall::{QueryBudget, QueryCancellation};
use contextdb_service::{
    AcceptedRouterTraceUnavailable, CapturePort, CognitiveMemoryService, CreateBackupRequest,
    ForgetMode, ForgetRequest, PayloadPort, PrepareContextRequest, ReadOriginalRequest,
    RestoreBackupRequest, StagePayloadRequest,
};
use contextdb_storage::{
    Durability, ReadSnapshot, SnapshotSelector, StorageEngine, WriteTransaction,
};

use super::*;
use crate::router_trace::tests::{budget, capture, envelope, memory_query, publication, source};
use crate::{NativeCustodyKeys, NativeSuppressionLedger, digest_bytes, encode, history_key};

struct Fixture {
    service: Arc<NativeService>,
    ledger: Arc<NativeSuppressionLedger>,
    keys: Arc<NativeCustodyKeys>,
    root: tempfile::TempDir,
    _ledger_directory: tempfile::TempDir,
    _key_directory: tempfile::TempDir,
    database: &'static str,
}

fn fixture(database: &'static str) -> Fixture {
    let root = tempfile::tempdir().expect("source-wire native directory");
    let (ledger_directory, ledger) = crate::suppression::tests::authority(database);
    let (key_directory, keys) = crate::encryption::tests::authority(database);
    let service = Arc::new(
        NativeService::open_encrypted(
            root.path().join("native"),
            database,
            [7; 32],
            ledger.clone(),
            keys.clone(),
        )
        .expect("actual encrypted owner"),
    );
    Fixture {
        service,
        ledger,
        keys,
        root,
        _ledger_directory: ledger_directory,
        _key_directory: key_directory,
        database,
    }
}

fn allowance() -> QueryBudget {
    QueryBudget::new(
        2_000_000,
        1024 * 1024 * 1024,
        Duration::from_secs(30),
        QueryCancellation::default(),
    )
}

fn read_request(accepted: &capture::TraceCaptureFixture) -> ReadAcceptedRouterTraceRequest {
    ReadAcceptedRouterTraceRequest {
        context: accepted.context.clone(),
        receipt: accepted.acceptance.receipt.clone(),
    }
}

fn complete(
    service: &NativeService,
    accepted: &capture::TraceCaptureFixture,
    runtime: Option<RouterSourceWireRuntime<'_>>,
    budget: &mut QueryBudget,
) -> Box<CurrentSourceWireVerification> {
    let mut request = read_request(accepted);
    if runtime.is_some() {
        request
            .context
            .capability_grants
            .insert(Capability::ModelProcessing);
    }
    match service
        .verify_accepted_router_source_wire(request, runtime, budget)
        .expect("current accepted source wire")
    {
        CurrentSourceWireVerificationResult::Complete(proof) => proof,
        CurrentSourceWireVerificationResult::Unavailable(reason) => {
            panic!("actual protected request unavailable: {reason:?}");
        }
    }
}

fn sequence(service: &NativeService) -> contextdb_storage::StorageSequence {
    service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("native sequence")
        .sequence()
}

fn poison_original(service: &NativeService, event: ObservationId) {
    let mut tx = service.engine.begin_write().expect("protected body fault");
    tx.put(
        &service.keyspaces.observations_content,
        digest_bytes(event.to_string().as_bytes()).into_bytes(),
        b"poisoned protected body behind current admission".to_vec(),
    )
    .expect("fault body");
    tx.commit(Durability::Sync).expect("fault Sync");
}

const TEST_CHUNK_BYTES: usize = 256 * 1024;
const ESCAPED_TEXT: &str = "Привет: \"C:\\путь\"\nи\tтабуляция.";
const SECOND_TEXT: &str = "SECOND-SOURCE";

fn staged_text() -> String {
    [
        "x".repeat(TEST_CHUNK_BYTES - 8),
        ESCAPED_TEXT.into(),
        SECOND_TEXT.into(),
    ]
    .concat()
}

fn span(
    original: &contextdb_service::CaptureRequest,
    text: &str,
    start: usize,
    end: usize,
) -> OriginalSourceSpan {
    OriginalSourceSpan {
        event_id: original.event.event_id,
        payload_digest: original
            .event
            .payload
            .digest()
            .expect("actual source digest"),
        start: start as u64,
        end: end as u64,
        span_digest: ContentDigest::from_bytes(
            *blake3::hash(&text.as_bytes()[start..end]).as_bytes(),
        ),
    }
}

fn protocol_setup(
    service: &NativeService,
    original: &contextdb_service::CaptureRequest,
    plan: &mut PrepareContextRequest,
) {
    capture::replay_profile(service, original, plan);
    let text = staged_text();
    let first_start = TEST_CHUNK_BYTES - 12;
    let first_end = TEST_CHUNK_BYTES - 8 + ESCAPED_TEXT.len();
    let first = &text[first_start..first_end];
    let message = format!("{first} | {SECOND_TEXT}");
    plan.base.current.push(OutgoingMessage {
        id: BlockId::new("cross-chunk-current").expect("message ID"),
        zone: OutgoingZone::CurrentTurn,
        role: OutgoingRole::User,
        text: message,
        originals: vec![
            VisibleOriginal {
                span: span(original, &text, first_start, first_end),
                text_start: 0,
                text_end: first.len() as u64,
            },
            VisibleOriginal {
                span: span(original, &text, first_end, text.len()),
                text_start: (first.len() + 3) as u64,
                text_end: (first.len() + 3 + SECOND_TEXT.len()) as u64,
            },
        ],
        tool_calls: Vec::new(),
        tool_result: None,
    });
    // Real observed assistant/tool bodies enter the complete outgoing protocol.
    // These observations do not execute a tool or acquire a dispatch grant.
    for (sequence, role, outgoing_role, body) in [
        (
            11,
            EventRole::Assistant,
            OutgoingRole::Assistant,
            "Calling bounded fixture tool.",
        ),
        (
            12,
            EventRole::Tool,
            OutgoingRole::Tool,
            "Actual observed fixture tool result.",
        ),
    ] {
        let mut item = source(sequence, body);
        item.context = original.context.clone();
        item.event.role = role;
        service
            .append_event(item.clone())
            .expect("actual tool-protocol observation");
        plan.base.hot.push(OutgoingMessage {
            id: BlockId::new(format!("protocol-{sequence}")).expect("protocol ID"),
            zone: OutgoingZone::HotHistory,
            role: outgoing_role,
            text: body.into(),
            originals: vec![VisibleOriginal {
                span: span(&item, body, 0, body.len()),
                text_start: 0,
                text_end: body.len() as u64,
            }],
            tool_calls: if role == EventRole::Assistant {
                vec!["source-wire-tool".into()]
            } else {
                Vec::new()
            },
            tool_result: if role == EventRole::Tool {
                Some("source-wire-tool".into())
            } else {
                None
            },
        });
    }
}

fn unchanged_source_part(_: &NativeService, request: &mut contextdb_service::CaptureRequest) {
    let EventPayload::Assembly { manifest } = &mut request.event.payload else {
        panic!("actual prepared assembly");
    };
    let part = manifest
        .parts
        .iter_mut()
        .find(|part| {
            matches!(part,
        RequestPart::JsonStringSource { span, byte_length, digest }
            if *byte_length == span.end - span.start && *digest == span.span_digest)
        })
        .expect("one JSON contents span needs no escaping");
    let RequestPart::JsonStringSource { span, .. } = part else {
        unreachable!()
    };
    *part = RequestPart::Source { span: span.clone() };
}

#[derive(Debug)]
struct UpperBoundEncoder<'a>(ReferenceOutgoingEncoder<'a>);

impl OutgoingEncoder for UpperBoundEncoder<'_> {
    fn id(&self) -> &str {
        self.0.id()
    }
    fn tokenizer_id(&self) -> &str {
        self.0.tokenizer_id()
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> contextdb_context::Result<EncodedOutgoing> {
        let mut outgoing = self.0.encode(messages, budget)?;
        outgoing.count_kind = RequestCountKind::ConservativeUpperBound;
        Ok(outgoing)
    }
}

#[test]
fn encrypted_current_wire_replays_protocol_and_cross_chunk_utf8_after_cold_restore() {
    let f = fixture("source-wire-cold-protocol");
    let encoder = ReferenceOutgoingEncoder(&ReferenceTokenizer);
    let runtime = RouterSourceWireRuntime {
        tokenizer: &ReferenceTokenizer,
        encoder: &encoder,
    };
    let accepted = capture::accepted_fixture_with_manifest(
        &f.service,
        &staged_text(),
        protocol_setup,
        &encoder,
        unchanged_source_part,
    );
    let EventPayload::Assembly { manifest } = &accepted.request.event.payload else {
        panic!("actual accepted request");
    };
    assert!(
        manifest
            .parts
            .iter()
            .any(|part| matches!(part, RequestPart::Source { .. }))
    );
    assert!(manifest.parts.iter().any(
        |part| matches!(part, RequestPart::JsonStringSource { span, .. }
        if span.start < TEST_CHUNK_BYTES as u64 && span.end > TEST_CHUNK_BYTES as u64)
    ));
    assert!(
        manifest
            .parts
            .iter()
            .any(|part| matches!(part, RequestPart::Novel { .. }))
    );
    assert!(
        accepted
            .prepared
            .messages
            .iter()
            .any(|message| !message.tool_calls.is_empty())
    );
    assert!(
        accepted
            .prepared
            .messages
            .iter()
            .any(|message| message.tool_result.is_some())
    );
    let before = sequence(&f.service);
    let missing = complete(&f.service, &accepted, None, &mut allowance());
    assert_eq!(missing.source_wire, CurrentSourceWireStatus::Verified);
    assert_eq!(
        missing.historical_selection,
        CurrentSourceWireStatus::Unavailable(CurrentSourceWireUnavailableReason::MissingRuntime)
    );
    assert_eq!(missing.trusted_token_count, missing.historical_selection);
    assert!(missing.trusted_input_tokens.is_none());
    let mut shared = allowance();
    let initial_bytes = shared.remaining_bytes();
    let proof = complete(&f.service, &accepted, Some(runtime), &mut shared);
    assert!(shared.remaining_bytes() < initial_bytes);
    for status in [
        proof.current_custody,
        proof.source_wire,
        proof.historical_selection,
        proof.trusted_token_count,
    ] {
        assert_eq!(status, CurrentSourceWireStatus::Verified);
    }
    assert_eq!(proof.receipt, accepted.acceptance.receipt);
    assert_eq!(proof.wire_digest, manifest.wire_digest);
    assert_eq!(
        proof.wire_byte_length,
        accepted.prepared.outgoing.wire.len() as u64
    );
    assert_eq!(
        proof.trusted_input_tokens,
        Some(accepted.prepared.outgoing.input_tokens)
    );
    let encoded = serde_json::to_string(&proof).expect("commitment-only result");
    assert!(!encoded.contains("Привет"));
    assert!(!encoded.contains(SECOND_TEXT));
    assert!(!format!("{proof:?}").contains("Привет"));
    assert_eq!(
        sequence(&f.service),
        before,
        "no proof operation writes native state"
    );
    let backup = f
        .service
        .create_backup(CreateBackupRequest {
            context: accepted.context.clone(),
        })
        .expect("verified actual encrypted archive");
    let restored = NativeService::open_encrypted(
        f.root.path().join("restored"),
        f.database,
        [9; 32],
        f.ledger.clone(),
        f.keys.clone(),
    )
    .expect("fresh encrypted owner");
    restored
        .restore_backup(RestoreBackupRequest {
            context: accepted.context.clone(),
            bytes: backup.bytes,
            format: backup.format,
            digest: backup.digest,
        })
        .expect("real cold encrypted restore");
    let before = sequence(&restored);
    let cold = complete(&restored, &accepted, Some(runtime), &mut allowance());
    assert_eq!(cold.receipt, proof.receipt);
    assert_eq!(cold.header, proof.header);
    assert_eq!(cold.wire_digest, proof.wire_digest);
    assert_eq!(cold.wire_byte_length, proof.wire_byte_length);
    assert_eq!(cold.historical_selection, proof.historical_selection);
    assert_eq!(cold.trusted_input_tokens, proof.trusted_input_tokens);
    assert_eq!(sequence(&restored), before);

    let staged_source = manifest
        .parts
        .iter()
        .find_map(|part| match part {
            RequestPart::JsonStringSource { span, .. }
                if span.start < TEST_CHUNK_BYTES as u64 && span.end > TEST_CHUNK_BYTES as u64 =>
            {
                Some(span.event_id)
            }
            _ => None,
        })
        .expect("actual cross-chunk source identity");
    let original = f
        .service
        .read_original(ReadOriginalRequest {
            context: accepted.context.clone(),
            event_id: staged_source,
            after_receipt: None,
        })
        .expect("actual selected staged source");
    let EventPayload::Staged { reference, .. } = original.event.payload else {
        panic!("cross-chunk source was genuinely staged");
    };
    let mut key = format!("payload/chunk/{}/", reference.block_id).into_bytes();
    key.extend_from_slice(&1_u32.to_be_bytes());
    let mut tx = f
        .service
        .engine
        .begin_write()
        .expect("selected source chunk fault");
    tx.put(
        &f.service.keyspaces.continuous,
        key,
        b"changed selected source chunk".to_vec(),
    )
    .expect("change actual source bytes, keep trace envelope intact");
    tx.commit(Durability::Sync).expect("source fault Sync");
    let before = sequence(&f.service);
    assert_eq!(
        f.service
            .verify_accepted_router_source_wire(read_request(&accepted), None, &mut allowance(),)
            .expect_err("accepted trace metadata cannot replace exact source rematerialization")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(sequence(&f.service), before);

    let g = fixture("source-wire-upper-bound");
    let upper = UpperBoundEncoder(ReferenceOutgoingEncoder(&ReferenceTokenizer));
    let accepted = capture::accepted_fixture_with_ports(
        &g.service,
        "Actual upper-bound protocol source.",
        capture::replay_profile,
        &upper,
    );
    let upper_runtime = RouterSourceWireRuntime {
        tokenizer: &ReferenceTokenizer,
        encoder: &upper,
    };
    let before = sequence(&g.service);
    let bounded = complete(&g.service, &accepted, Some(upper_runtime), &mut allowance());
    assert_eq!(bounded.source_wire, CurrentSourceWireStatus::Verified);
    assert_eq!(
        bounded.historical_selection,
        CurrentSourceWireStatus::Verified
    );
    assert_eq!(
        bounded.trusted_token_count,
        CurrentSourceWireStatus::Unavailable(
            CurrentSourceWireUnavailableReason::NonExactRequestCount
        )
    );
    assert!(bounded.trusted_input_tokens.is_none());
    assert_eq!(sequence(&g.service), before);

    // StoredNovel is deliberately refused by protected leases. Exercise the
    // shared assembler's staged branch directly, without claiming acceptance.
    let bytes = b"durably staged novel protocol bytes".to_vec();
    let staged = g
        .service
        .stage_payload(StagePayloadRequest {
            context: accepted.context.clone(),
            idempotency_key: "direct-stored-novel".into(),
            block_id: ContentBlockId::new(),
            bytes: bytes.clone(),
        })
        .expect("genuine durable staging");
    let manifest = ModelRequestManifest {
        model_call_id: ModelCallId::new(),
        renderer: "direct-novel-test/v1".into(),
        wire_digest: staged.reference.digest,
        byte_length: bytes.len() as u64,
        parts: vec![RequestPart::StoredNovel {
            payload: staged.reference.clone(),
        }],
        router_trace: None,
    };
    let snapshot = g
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("one source snapshot");
    let before = snapshot.sequence();
    assert_eq!(g.service.assemble_request_with_budget(
        &snapshot, &accepted.context, &manifest, &mut allowance(),
    ).expect("real budgeted StoredNovel reconstruction"), bytes);
    let mut tiny = QueryBudget::new(
        100,
        1,
        Duration::from_secs(30),
        QueryCancellation::default(),
    );
    assert_eq!(
        g.service
            .assemble_request_with_budget(&snapshot, &accepted.context, &manifest, &mut tiny,)
            .expect_err("staged allocation is charged before materialization")
            .code,
        ErrorCode::BudgetExhausted
    );
    drop(snapshot);
    let mut key = format!("payload/chunk/{}/", staged.reference.block_id).into_bytes();
    key.extend_from_slice(&0_u32.to_be_bytes());
    let mut tx = g.service.engine.begin_write().expect("actual chunk fault");
    tx.put(
        &g.service.keyspaces.continuous,
        key,
        b"wrong actual chunk bytes".to_vec(),
    )
    .expect("replace only durable chunk");
    tx.commit(Durability::Sync).expect("chunk fault Sync");
    let snapshot = g
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("fault snapshot");
    assert_ne!(snapshot.sequence(), before);
    let before = snapshot.sequence();
    assert_eq!(g.service.assemble_request_with_budget(
        &snapshot, &accepted.context, &manifest, &mut allowance(),
    ).expect_err("bad staged chunk is integrity failure").code, ErrorCode::IntegrityFailure);
    drop(snapshot);
    assert_eq!(sequence(&g.service), before);
}

fn generic_setup(
    service: &NativeService,
    original: &contextdb_service::CaptureRequest,
    plan: &mut PrepareContextRequest,
) {
    for id in ["match", "unrelated-archive-item"] {
        service
            .publish_memory_from_sources(
                publication(&original.context, id),
                &BTreeSet::from([original.event.event_id]),
                &mut budget(),
            )
            .expect("actual registered source-aware generic version");
    }
    plan.memory_query = Some(memory_query());
    capture::replay_profile(service, original, plan);
}

#[test]
fn current_wire_requires_all_discarded_raw_and_generic_rights_before_protected_bodies() {
    let f = fixture("source-wire-raw-rights");
    let (accepted, discarded) = capture::accepted_unselected_replay_fixture(&f.service);
    let frozen = envelope(&accepted.prepared);
    assert!(frozen.origins.originals.contains(&discarded));
    assert!(
        !accepted
            .prepared
            .assembly
            .read_set
            .originals
            .iter()
            .any(|span| span.event_id == discarded)
    );
    complete(&f.service, &accepted, None, &mut allowance());
    let mut training = read_request(&accepted);
    training.context.request.purpose = "personalisation".into();
    assert_eq!(
        f.service
            .verify_accepted_router_source_wire(training, None, &mut allowance())
            .expect_err("conversation does not authorize training purpose")
            .code,
        ErrorCode::PermissionDenied
    );
    f.service
        .revoke_original(
            &accepted.context,
            discarded,
            "source-wire-discarded-revocation",
            &mut budget(),
        )
        .expect("real source revocation");
    let mut caught_up = false;
    for _ in 0..16 {
        if f.service
            .maintain_custody(&accepted.context, 64, &mut budget())
            .expect("bounded actual propagation")
            .caught_up
        {
            caught_up = true;
            break;
        }
    }
    assert!(caught_up);
    poison_original(&f.service, accepted.request.event.event_id);
    let before = sequence(&f.service);
    let error = f
        .service
        .verify_accepted_router_source_wire(read_request(&accepted), None, &mut allowance())
        .expect_err("unselected revoked root precedes protected body decode");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(sequence(&f.service), before);
    assert!(!format!("{error:?}").contains("amber"));
    assert!(!format!("{error:?}").contains("cobalt"));
    let selected = accepted
        .prepared
        .assembly
        .read_set
        .originals
        .iter()
        .find(|span| span.event_id != discarded)
        .expect("independent selected root")
        .event_id;
    f.service
        .read_original(ReadOriginalRequest {
            context: accepted.context.clone(),
            event_id: selected,
            after_receipt: None,
        })
        .expect("independent selected source remains permitted");

    let g = fixture("source-wire-generic-rights");
    let accepted = capture::accepted_fixture_with_setup(&g.service, generic_setup);
    let frozen = envelope(&accepted.prepared);
    assert_eq!(frozen.retrieval_origins.records.len(), 2);
    assert_eq!(
        frozen
            .materials
            .candidates
            .iter()
            .filter(|candidate| candidate.id.as_str().starts_with("native:"))
            .count(),
        1
    );
    complete(&g.service, &accepted, None, &mut allowance());
    let snapshot = g
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("generic head");
    let historical = g
        .service
        .load_head(&snapshot, "unrelated-archive-item")
        .expect("registered head")
        .expect("actual unselected record");
    drop(snapshot);
    g.service
        .retract_from_sources(
            ForgetRequest {
                context: accepted.context.clone(),
                idempotency_key: "source-wire-retract".into(),
                target_id: "unrelated-archive-item".into(),
                mode: ForgetMode::Retract,
                reason: "historical access remains".into(),
            },
            &frozen.retrieval_origins.originals,
            &mut budget(),
        )
        .expect("actual reversible retraction");
    complete(&g.service, &accepted, None, &mut allowance());
    let snapshot = g
        .service
        .engine
        .begin_read(SnapshotSelector::Latest)
        .expect("current head");
    let mut denied = g
        .service
        .load_head(&snapshot, "unrelated-archive-item")
        .expect("current registered head")
        .expect("retained generic revision");
    drop(snapshot);
    assert!(denied.revision > historical.revision);
    denied.access.retrievable = false;
    let mut tx = g
        .service
        .engine
        .begin_write()
        .expect("current ACL fault fixture");
    tx.put(
        &g.service.keyspaces.policy_head,
        denied.record_digest.as_bytes().to_vec(),
        encode(&denied).expect("current policy metadata"),
    )
    .expect("current head denial");
    tx.put(
        &g.service.keyspaces.content_history,
        history_key(&historical.record_digest, historical.revision),
        b"poisoned historical generic body".to_vec(),
    )
    .expect("generic body fault");
    tx.put(
        &g.service.keyspaces.observations_content,
        digest_bytes(accepted.request.event.event_id.to_string().as_bytes()).into_bytes(),
        b"poisoned protected request body".to_vec(),
    )
    .expect("request body fault");
    tx.commit(Durability::Sync).expect("ACL fault Sync");
    let before = sequence(&g.service);
    assert_eq!(
        g.service
            .verify_accepted_router_source_wire(read_request(&accepted), None, &mut allowance(),)
            .expect_err("discarded current generic denial precedes both bodies")
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(sequence(&g.service), before);
    g.service
        .read_original(ReadOriginalRequest {
            context: accepted.context.clone(),
            event_id: *frozen
                .retrieval_origins
                .originals
                .first()
                .expect("generic raw source"),
            after_receipt: None,
        })
        .expect("raw source permission is independent of generic head denial");
}

#[test]
fn source_wire_preserves_legacy_off_and_v1_and_shared_fault_admission() {
    let f = fixture("source-wire-read-admission");
    let v1 = capture::accepted_fixture(&f.service);
    let encoder = ReferenceOutgoingEncoder(&ReferenceTokenizer);
    let runtime = RouterSourceWireRuntime {
        tokenizer: &ReferenceTokenizer,
        encoder: &encoder,
    };
    let proof = complete(&f.service, &v1, None, &mut allowance());
    assert_eq!(proof.current_custody, CurrentSourceWireStatus::Verified);
    assert_eq!(proof.source_wire, CurrentSourceWireStatus::Verified);
    assert_eq!(
        proof.historical_selection,
        CurrentSourceWireStatus::Unavailable(
            CurrentSourceWireUnavailableReason::MissingReplayPreparation
        )
    );
    assert_eq!(proof.trusted_token_count, proof.historical_selection);
    assert!(proof.trusted_input_tokens.is_none());
    let with_runtime = complete(&f.service, &v1, Some(runtime), &mut allowance());
    assert_eq!(
        with_runtime.historical_selection,
        proof.historical_selection
    );
    let mut off = source(9, "Actual captured trace-disabled source.");
    off.context = v1.context.clone();
    let receipt = f
        .service
        .append_event(off)
        .expect("actual legacy Off capture");
    assert!(matches!(
        f.service
            .verify_accepted_router_source_wire(
                ReadAcceptedRouterTraceRequest {
                    context: v1.context.clone(),
                    receipt
                },
                None,
                &mut allowance(),
            )
            .expect("current authorized Off occurrence"),
        CurrentSourceWireVerificationResult::Unavailable(AcceptedRouterTraceUnavailable::LegacyOff)
    ));

    // Authentication and the shared allowance must win over a poisoned body.
    poison_original(&f.service, v1.request.event.event_id);
    let before = sequence(&f.service);
    let mut no_model = read_request(&v1);
    no_model
        .context
        .capability_grants
        .remove(&Capability::ModelProcessing);
    assert_eq!(
        f.service
            .verify_accepted_router_source_wire(no_model, Some(runtime), &mut allowance())
            .expect_err("trusted runtime requires ModelProcessing upfront")
            .code,
        ErrorCode::Unauthorized
    );
    let mut admin_only = read_request(&v1);
    admin_only.context.capability_grants = BTreeSet::from([Capability::Admin]);
    assert_eq!(
        f.service
            .verify_accepted_router_source_wire(admin_only, None, &mut allowance())
            .expect_err("Admin supplies no source read capability")
            .code,
        ErrorCode::Unauthorized
    );
    let mut wrong_receipt = read_request(&v1);
    wrong_receipt.receipt.token.push('0');
    assert_eq!(
        f.service
            .verify_accepted_router_source_wire(wrong_receipt, None, &mut allowance())
            .expect_err("receipt-shaped bytes are not acceptance")
            .code,
        ErrorCode::InvalidArgument
    );
    let mut zero = QueryBudget::new(0, 0, Duration::from_secs(30), QueryCancellation::default());
    assert_eq!(
        f.service
            .verify_accepted_router_source_wire(read_request(&v1), None, &mut zero)
            .expect_err("zero allowance precedes protected body")
            .code,
        ErrorCode::BudgetExhausted
    );
    let cancellation = QueryCancellation::default();
    cancellation.cancel();
    let mut cancelled = QueryBudget::new(
        2_000_000,
        1024 * 1024 * 1024,
        Duration::from_secs(30),
        cancellation,
    );
    assert_eq!(
        f.service
            .verify_accepted_router_source_wire(read_request(&v1), None, &mut cancelled)
            .expect_err("cancelled enclosing query")
            .message,
        "indexed query cancelled"
    );
    assert_eq!(
        f.service
            .verify_accepted_router_source_wire(read_request(&v1), None, &mut allowance())
            .expect_err("actual protected body corruption is not Pruned")
            .code,
        ErrorCode::IntegrityFailure
    );
    assert_eq!(sequence(&f.service), before);
}
