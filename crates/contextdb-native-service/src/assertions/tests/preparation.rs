use super::*;
use contextdb_context::*;
use contextdb_recall::{IndexedQuery, IndexedSelection};
use contextdb_service::{Capability, PrepareContextPort, PrepareContextRequest};

mod leases;

fn allowance() -> QueryBudget {
    QueryBudget::new(
        500_000,
        512 * 1024 * 1024,
        Duration::from_secs(30),
        Default::default(),
    )
}
fn setup(service: &NativeService) -> CaptureRequest {
    let mut input = capture(
        1,
        "Данные остаются локально. Нельзя отправлять их в облако.",
    );
    input.context.request.purpose = "conversation".into();
    service.append_event(input.clone()).expect("source capture");
    let mut asserted = assertion(&input, "local-only", 0, None, vec![]);
    asserted.revision.envelope.ownership.allowed_purposes = BTreeSet::from([Purpose::Conversation]);
    publish(
        service,
        &input,
        "initial",
        vec![
            AssertionMutation::Policy {
                policy: policy(&input),
            },
            change(asserted),
        ],
    );
    input
}
fn request(input: &CaptureRequest) -> PrepareContextRequest {
    let mut context = input.context.clone();
    context.capability_grants.extend([
        Capability::Runtime,
        Capability::ReadMemory,
        Capability::ReadConflict,
    ]);
    PrepareContextRequest {
        context,
        pack_id: ContextPackId::new(),
        purpose: PackPurpose::Conversation,
        known_at: None,
        valid_at: None,
        after_receipt: None,
        raw_queries: Vec::new(),
        required_facets: Vec::new(),
        memory_budget: ContextBudgets {
            hard_tokens: 14000,
            soft_tokens: 12000,
            max_blocks: 64,
            max_evidence_blocks: 128,
            max_raw_evidence_tokens: 10000,
            max_history_tokens: 10000,
            max_conflict_tokens: 10000,
            max_serialized_bytes: 2 * 1024 * 1024,
            max_selection_evaluations: 128,
        },
        model_profile: ModelProfile {
            id: "native-reference-json".into(),
            family: "reference".into(),
            tokenizer_id: ReferenceTokenizer::ID.into(),
            renderer: RendererKind::Compact,
            max_context_tokens: 32000,
            reserved_output_tokens: 4000,
            preferred_structured_format: StructuredFormat::CompactText,
            supports_tool_results: true,
            supports_native_citations: false,
            supports_prompt_caching: false,
            position_profile: PositionProfile::CriticalFirst,
            instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
            max_schema_complexity: 64,
            external_processing: false,
        },
        base: OutgoingBase {
            working: Vec::new(),
            control: Vec::new(),
            hot: Vec::new(),
            current: Vec::new(),
        },
        outgoing_budget: OutgoingBudget {
            max_input_tokens: 27000,
            safety_tokens: 1000,
            max_wire_bytes: 2 * 1024 * 1024,
        },
        explicit_memory_request: false,
    }
}
fn prepare(
    service: &NativeService,
    request: PrepareContextRequest,
) -> ServiceResult<contextdb_service::PreparedContext> {
    service.prepare_context(
        request,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        &mut allowance(),
    )
}

#[test]
fn native_prepare_discovers_mandatory_state_without_a_model_key_list_and_reopens() {
    let directory = tempfile::tempdir().expect("fixture");
    let service = NativeService::open(directory.path(), "prepare", [7; 32]).expect("open");
    let input = setup(&service);
    assert_eq!(
        prepare(&service, request(&input))
            .expect_err("catalog migration required")
            .code,
        ErrorCode::IndexTooStale
    );
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let prepared = prepare(&service, request(&input)).expect("prepare");
    assert_eq!(prepared.context_pack.sections.decisions.len(), 1);
    assert!(
        prepared
            .messages
            .iter()
            .any(|message| message.text.contains("local-only"))
    );
    assert_eq!(prepared.context_pack.snapshot.commit_seq, 0);
    assert!(
        !prepared
            .messages
            .iter()
            .any(|message| message.text.contains("known_at_commit"))
    );
    assert!(prepared.assembly.read_set.binding.valid_until.is_some());
    assert_eq!(
        prepared.context_pack.evidence[0]
            .original_span
            .as_ref()
            .expect("span")
            .event_id,
        input.event.event_id
    );
    service.verify_native(true).expect("deep closure");
    drop(service);
    let reopened = NativeService::open(directory.path(), "prepare", [7; 32]).expect("reopen");
    assert_eq!(
        prepare(&reopened, request(&input))
            .expect("reopened preparation")
            .context_pack
            .sections
            .decisions
            .len(),
        1
    );
}

#[test]
fn raw_joke_is_returned_without_promotion_and_pending_correction_is_explicit() {
    let directory = tempfile::tempdir().expect("fixture");
    let service = NativeService::open(directory.path(), "prepare", [7; 32]).expect("open");
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let mut joke = capture(
        2,
        "Та самая идея между фильмом и лапшой: открыть ресторан для нейросетей.",
    );
    joke.context.request.purpose = "conversation".into();
    service
        .append_event(joke.clone())
        .expect("capture incidental detail");
    publish(&service, &joke, "joke-coverage", Vec::new());
    let mut plan = request(&input);
    plan.raw_queries.push(IndexedQuery {
        filter: RawFilter {
            event_ids: BTreeSet::from([joke.event.event_id]),
            ..Default::default()
        },
        text: None,
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 4 },
    });
    let prepared = prepare(&service, plan).expect("raw retrieval and mandatory state");
    assert_eq!(prepared.context_pack.sections.raw_observations.len(), 1);
    assert!(
        prepared.context_pack.sections.raw_observations[0]
            .claim_ids
            .is_empty()
    );
    assert!(
        prepared
            .messages
            .iter()
            .any(|message| message.text.contains("ресторан для нейросетей"))
    );
    assert_eq!(prepared.context_pack.sections.decisions.len(), 1);
    let mut correction = capture(3, "Стоп, правила изменились, пока ничего не делай.");
    correction.context.request.purpose = "conversation".into();
    service
        .append_event(correction)
        .expect("new unprocessed constraint");
    let pending = prepare(&service, request(&input)).expect("explicit pending context");
    assert!(pending.pending_interpretation);
    assert!(pending.context_pack.sections.decisions.is_empty());
    assert!(
        !pending
            .context_pack
            .compilation
            .sufficiency
            .blocking_unknowns
            .is_empty()
    );
    assert!(
        !pending
            .messages
            .iter()
            .any(|message| message.text.contains("local-only"))
    );
}

#[test]
fn revoked_hot_source_and_bad_span_fail_before_disclosure() {
    let directory = tempfile::tempdir().expect("fixture");
    let service = NativeService::open(directory.path(), "prepare", [7; 32]).expect("open");
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let initial = prepare(&service, request(&input)).expect("initial");
    let evidence = &initial.context_pack.evidence[0];
    let mut plan = request(&input);
    let text = evidence.excerpt.clone().expect("quote");
    plan.base.hot.push(OutgoingMessage {
        id: BlockId::new("old-user").expect("id"),
        zone: OutgoingZone::HotHistory,
        role: OutgoingRole::User,
        originals: vec![VisibleOriginal {
            span: evidence.original_span.clone().expect("span"),
            text_start: 0,
            text_end: text.len() as u64,
        }],
        text,
        tool_calls: Vec::new(),
        tool_result: None,
    });
    assert!(
        !prepare(&service, plan.clone())
            .expect("hot exact coverage")
            .messages
            .iter()
            .any(|message| message.zone == OutgoingZone::Evidence)
    );
    let mut malformed = plan.clone();
    malformed.base.hot[0].originals[0].span.payload_digest = ContentDigest::from_bytes([3; 32]);
    assert!(prepare(&service, malformed).is_err());
    service
        .revoke_original(
            &input.context,
            input.event.event_id,
            "revoke",
            &mut allowance(),
        )
        .expect("revoke");
    assert!(prepare(&service, plan).is_err());
}

#[derive(Debug)]
struct ConcurrentCapture {
    service: Arc<NativeService>,
    input: CaptureRequest,
    changed: std::sync::atomic::AtomicBool,
}
impl OutgoingEncoder for ConcurrentCapture {
    fn id(&self) -> &str {
        "contextdb.reference-request-json.v1"
    }
    fn tokenizer_id(&self) -> &str {
        ReferenceTokenizer::ID
    }
    fn encode(
        &self,
        messages: &[OutgoingMessage],
        budget: &mut QueryBudget,
    ) -> Result<EncodedOutgoing> {
        if !self.changed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.service
                .append_event(self.input.clone())
                .expect("concurrent publication");
        }
        ReferenceOutgoingEncoder(&ReferenceTokenizer).encode(messages, budget)
    }
}

#[test]
fn preparation_rechecks_scopes_after_rendering_and_catalog_loss_is_detected() {
    let directory = tempfile::tempdir().expect("fixture");
    let service =
        Arc::new(NativeService::open(directory.path(), "prepare", [7; 32]).expect("open"));
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let mut next = capture(2, "Новый запрет появился между чтением и отправкой.");
    next.context.request.purpose = "conversation".into();
    let encoder = ConcurrentCapture {
        service: service.clone(),
        input: next,
        changed: Default::default(),
    };
    let result = service.prepare_context(
        request(&input),
        &ReferenceTokenizer,
        &encoder,
        &mut allowance(),
    );
    assert_eq!(
        result.expect_err("scope changed").code,
        ErrorCode::IndexTooStale
    );
    let mut tx = service.engine.begin_write().expect("fixture corruption");
    for entry in tx
        .scan_prefix(&service.keyspaces.continuous, b"catalog/")
        .expect("catalog rows")
    {
        tx.delete(&service.keyspaces.continuous, entry.key)
            .expect("delete fixture row");
    }
    tx.commit(Durability::Sync).expect("fixture corruption");
    assert_eq!(
        service
            .verify_native(true)
            .expect_err("whole catalog loss")
            .code,
        ErrorCode::IntegrityFailure
    );
}

#[test]
fn raw_context_keeps_surrounding_words_and_reports_unrendered_originals() {
    use contextdb_service::OriginalRenderOmission;
    let directory = tempfile::tempdir().expect("fixture");
    let service = NativeService::open(directory.path(), "prepare", [7; 32]).expect("open");
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let text = "а ".repeat(12000)
        + "До шутки был фильм. Ресторан для нейросетей оказался столовой. Потом обсуждали лапшу."
        + &" б".repeat(12000);
    let mut source = capture(2, &text);
    source.context.request.purpose = "conversation".into();
    service
        .append_event(source.clone())
        .expect("large original");
    let mut binary = capture(3, "placeholder");
    binary.context.request.purpose = "conversation".into();
    let bytes = vec![0xff, 0x00, 0x81];
    binary.event.payload = EventPayload::InlineBytes {
        digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
        bytes,
        media_type: "image/png".into(),
    };
    service
        .append_event(binary.clone())
        .expect("binary original");
    publish(&service, &source, "coverage", Vec::new());
    let mut plan = request(&input);
    plan.raw_queries.push(IndexedQuery {
        filter: RawFilter::default(),
        text: Some(RawTextQuery::ExactPhrase("Ресторан".into())),
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 4 },
    });
    let prepared = prepare(&service, plan).expect("bounded lexical context");
    assert!(
        prepared
            .messages
            .iter()
            .any(|message| message.text.contains("До шутки был фильм.")
                && message.text.contains("Потом обсуждали лапшу."))
    );
    let quote = prepared
        .context_pack
        .evidence
        .iter()
        .find(|evidence| {
            evidence
                .original_span
                .as_ref()
                .is_some_and(|span| span.event_id == source.event.event_id)
        })
        .expect("original context");
    assert!(quote.excerpt.as_ref().expect("quote").len() < 4096);
    let mut plan = request(&input);
    plan.raw_queries.push(IndexedQuery {
        filter: RawFilter {
            event_ids: BTreeSet::from([source.event.event_id, binary.event.event_id]),
            ..Default::default()
        },
        text: None,
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 4 },
    });
    let partial = prepare(&service, plan).expect("explicit renderer limits");
    assert_eq!(partial.unrendered_sources.len(), 2);
    assert!(
        partial
            .unrendered_sources
            .iter()
            .any(|source| source.reason == OriginalRenderOmission::RangeRequired)
    );
    assert!(
        partial
            .unrendered_sources
            .iter()
            .any(|source| source.reason == OriginalRenderOmission::NonText)
    );
    assert_eq!(
        partial
            .context_pack
            .compilation
            .sufficiency
            .blocking_unknowns
            .len(),
        2
    );
    assert!(partial.context_pack.sections.raw_observations.is_empty());
}

#[test]
fn catalog_tracks_new_authority_slots_and_survives_rotated_restore() {
    use contextdb_service::{CognitiveMemoryService, CreateBackupRequest, RestoreBackupRequest};
    let directory = tempfile::tempdir().expect("fixture");
    let target = tempfile::tempdir().expect("restore fixture");
    let service = NativeService::open(directory.path(), "prepare", [7; 32]).expect("open");
    let input = setup(&service);
    service
        .initialize_state_catalog(&input.context, &mut allowance())
        .expect("catalog");
    let mut second = policy(&input);
    second.key.predicate = PredicateId::new();
    publish(
        &service,
        &input,
        "new-slot",
        vec![AssertionMutation::Policy { policy: second }],
    );
    let before = prepare(&service, request(&input)).expect("new slot automatically discovered");
    assert_eq!(before.context_pack.sections.unknowns.len(), 1);
    let backup = service
        .create_backup(CreateBackupRequest {
            context: input.context.clone(),
        })
        .expect("backup");
    let restored = NativeService::open(target.path(), "prepare", [8; 32]).expect("fresh target");
    restored
        .restore_backup(RestoreBackupRequest {
            context: input.context.clone(),
            format: backup.format,
            bytes: backup.bytes,
            digest: backup.digest,
        })
        .expect("restore");
    restored.verify_native(true).expect("catalog closure");
    let after = prepare(&restored, request(&input)).expect("restored preparation");
    assert_eq!(before.context_pack.sections, after.context_pack.sections);
}
