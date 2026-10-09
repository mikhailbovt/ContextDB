//! The semantic view observes the real selector, rather than rebuilding trials.

use super::*;
use contextdb_recall::QueryCancellation;
use serde_json::Value;

#[derive(Debug)]
struct Observation {
    selected: BTreeSet<BlockId>,
    seeds: BTreeSet<BlockId>,
    closure: BTreeSet<BlockId>,
    choices: Vec<SemanticVariantChoice>,
    model: Value,
    added_bytes: u64,
    marginal: Option<i64>,
}

#[derive(Debug)]
struct SemanticProbe {
    winner: BTreeSet<BlockId>,
    observations: Mutex<Vec<Observation>>,
}

impl SemanticProbe {
    fn new(ids: &[&str]) -> Self {
        Self {
            winner: ids.iter().map(|id| must(BlockId::new(*id))).collect(),
            observations: Mutex::new(Vec::new()),
        }
    }
}

impl ContextScorer for SemanticProbe {
    fn id(&self) -> &str {
        "test-semantic-observation"
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        Some(SemanticScoringProfile::RenderedClosureV1)
    }
    fn score(&self, _: &ScoringUnit, _: &mut QueryBudget) -> Result<Option<u64>> {
        panic!("explicit semantic profile must not call the scalar scorer")
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> Result<Option<u64>> {
        let selected: BTreeSet<_> = unit
            .selected
            .pack
            .sections
            .iter()
            .map(|block| block.id.clone())
            .collect();
        let bytes = unit.model_input_json(budget)?;
        assert!(!format!("{unit:?}").contains("AtlasDB"));
        assert!(bytes.len() <= MAX_SEMANTIC_SCORING_BYTES);
        assert_eq!(
            unit.budget.exact_marginal_input_tokens,
            (unit.selected.count_kind == RequestCountKind::Exact
                && unit.trial.count_kind == RequestCountKind::Exact)
                .then_some(
                    i64::from(unit.trial.input_tokens) - i64::from(unit.selected.input_tokens)
                )
        );
        self.observations
            .lock()
            .expect("observations")
            .push(Observation {
                selected: selected.clone(),
                seeds: unit.identity.seed_ids.clone(),
                closure: unit.identity.closure_ids.clone(),
                choices: unit.trial.chosen_variants.to_vec(),
                model: serde_json::from_slice(&bytes).expect("semantic model JSON"),
                added_bytes: unit.budget.added_original_bytes,
                marginal: unit.budget.exact_marginal_input_tokens,
            });
        // Host IDs make this fixture deterministic; they never enter the model record.
        Ok((!self.winner.is_empty()
            && !self.winner.is_subset(&selected)
            && *unit.identity.seed_ids == self.winner)
            .then_some(1_000_000))
    }
}

fn semantic_fixture(mandatory: bool, complement: bool) -> Fixture {
    let original = shared_fixture(mandatory);
    let mut candidates: Vec<_> = must(original.data.candidate_labels())
        .into_iter()
        .map(|label| {
            let mut candidate = must(original.data.materialize_candidate(&label.id));
            for representation in &mut candidate.representations {
                representation.summary = "Storage choice preserves offline custody.".into();
                representation.fields =
                    BTreeMap::from([("reason".into(), "offline custody".into())]);
            }
            if candidate.id.as_str() == "a" {
                candidate.exact_fragments.push(ExactFragment {
                    label: "storage code".into(),
                    value: "AtlasDB".into(),
                });
                candidate.epistemic.conflict = ConflictState::Resolved {
                    set_id: conflict(99),
                };
                candidate.utility_micros = 987_654_321;
            }
            ProviderCandidate {
                access: access(AccessConsent::Granted),
                use_policy: use_policy(DisclosureRule::MayMention),
                candidate,
            }
        })
        .collect();
    let mut raw = fact("metadata-only-raw-id", "shared", false);
    raw.candidate.kind = PackBlockKind::RawObservation;
    raw.candidate.claim_ids.clear();
    raw.candidate.interpretation = InterpretationRule::HistoricalData;
    for representation in &mut raw.candidate.representations {
        representation.summary = "metadata-only-raw-preview-id".into();
        representation.fields = BTreeMap::from([(
            "synthetic source".into(),
            "metadata-only-raw-preview-id".into(),
        )]);
    }
    candidates.push(raw);
    let evidence = ["shared", "alternative"]
        .into_iter()
        .map(|id| ProviderEvidence {
            access: access(AccessConsent::Granted),
            external_model_use: PolicyDecision::Allow,
            evidence: must(
                original
                    .data
                    .materialize_evidence(&must(EvidenceHandle::new(id))),
            ),
        })
        .collect();
    let mut result = fixture(candidates, evidence);
    result.dependencies = original.dependencies;
    if complement {
        result
            .dependencies
            .get_mut(&must(BlockId::new("a")))
            .expect("dependency")
            .complements
            .insert(must(BlockId::new("b")));
    }
    result
}

fn add_base_source(
    provider: &mut Fixture,
    id: &str,
    text: &str,
    role: OutgoingRole,
    zone: OutgoingZone,
) -> OutgoingMessage {
    let original = source(id, claim(1), text).evidence;
    provider.originals.insert(
        original.original_span.as_ref().expect("span").event_id,
        text.as_bytes().to_vec(),
    );
    let mut message = message(id, &original, role);
    message.zone = zone;
    message
}

#[test]
fn semantic_selected_base_advances_after_real_winner_and_stop_preserves_mandatory_state() {
    let mut provider = semantic_fixture(false, false);
    let mut request = input();
    request.context.required_facets.push(PackFacetRequirement {
        name: "unobserved current deployment".into(),
        minimum_confidence_micros: 800_000,
        require_evidence: true,
    });
    request.base.control.push(OutgoingMessage {
        id: must(BlockId::new("metadata-only-control-id")), zone: OutgoingZone::ToolDefinitions,
        role: OutgoingRole::Developer,
        text: "Host tool schema: {\"type\":\"object\",\"properties\":{\"route\":{\"type\":\"string\"}}}".into(),
        originals: Vec::new(), tool_calls: Vec::new(), tool_result: None,
    });
    request.base.working.push(add_base_source(
        &mut provider,
        "metadata-only-working-id",
        "Keep the offline custody obligation open.",
        OutgoingRole::User,
        OutgoingZone::WorkingState,
    ));
    request.base.hot.push(add_base_source(
        &mut provider,
        "metadata-only-hot-id",
        "Previously accepted a local-only archive.",
        OutgoingRole::User,
        OutgoingZone::HotHistory,
    ));
    let mut call = add_base_source(
        &mut provider,
        "metadata-only-assistant-id",
        "Inspect the local store.",
        OutgoingRole::Assistant,
        OutgoingZone::CurrentTurn,
    );
    call.tool_calls.push("metadata-only-call-id".into());
    let mut tool = add_base_source(
        &mut provider,
        "metadata-only-tool-id",
        "The local store remains available.",
        OutgoingRole::Tool,
        OutgoingZone::CurrentTurn,
    );
    tool.tool_result = Some("metadata-only-call-id".into());
    request.base.current.extend([
        call,
        tool,
        add_base_source(
            &mut provider,
            "metadata-only-user-id",
            "Which storage preserves that requirement?",
            OutgoingRole::User,
            OutgoingZone::CurrentTurn,
        ),
    ]);
    let probe = SemanticProbe::new(&["a"]);
    let compiled = must(routed(&request, &provider, &probe));
    assert_eq!(
        compiled.request.binding.feature_schema,
        SEMANTIC_SCORING_FEATURE_SCHEMA
    );
    assert_eq!(
        compiled.assembly.optional_seeds,
        BTreeSet::from([must(BlockId::new("a"))])
    );
    let observations = probe.observations.lock().expect("observations");
    let before = observations
        .iter()
        .find(|item| item.seeds == BTreeSet::from([must(BlockId::new("a"))]))
        .expect("first winner");
    assert!(!before.selected.contains(&must(BlockId::new("a"))));
    let after = observations
        .iter()
        .find(|item| item.selected.contains(&must(BlockId::new("a"))))
        .expect("subsequent callback has actual selected base");
    assert!(after.selected.contains(&must(BlockId::new("dependency"))));
    assert!(
        after.model["selected"]["blocks"]
            .as_array()
            .expect("blocks")
            .iter()
            .any(|block| block["kind"] == "unknown")
    );
    assert_eq!(
        before.model["base"]["control"][0]["text"],
        request.base.control[0].text
    );
    assert_eq!(
        before.model["base"]["working"][0]["text"],
        request.base.working[0].text
    );
    assert_eq!(
        before.model["base"]["hot"][0]["text"],
        request.base.hot[0].text
    );
    assert_eq!(
        before.model["base"]["current"][0]["tool_calls"],
        serde_json::json!([0])
    );
    assert_eq!(before.model["base"]["current"][1]["tool_result"], 0);
    for observation in observations.iter() {
        let text = observation.model.to_string();
        for forbidden in [
            "metadata-only-",
            "987654321",
            "prior_utility",
            "claim_ids",
            "memory_refs",
            "payload_digest",
            "span_digest",
            "set_id",
            "training_dataset",
            "evaluation_target",
        ] {
            assert!(
                !text.contains(forbidden),
                "host/label metadata leaked: {forbidden}"
            );
        }
        assert!(!text.contains(&conflict(99).to_string()));
        assert!(!text.contains(&claim(1).to_string()));
    }
    let raw = observations
        .iter()
        .flat_map(|item| item.model["trial"]["blocks"].as_array().expect("blocks"))
        .find(|block| block["kind"] == "raw_observation")
        .expect("actual raw trial");
    assert!(raw["representation"]["summary"].is_null());
    assert!(raw["representation"]["fields"].is_null());
    assert!(observations.iter().any(|item| {
        item.model["trial"]["supports"]
            .as_array()
            .expect("supports")
            .iter()
            .any(|support| {
                support["excerpt"]
                    .as_str()
                    .is_some_and(|text| text.contains("AtlasDB"))
            })
    }));
    drop(observations);
    let stop = SemanticProbe::new(&[]);
    let mandatory = must(routed(&input(), &semantic_fixture(true, false), &stop));
    assert!(mandatory.assembly.optional_seeds.is_empty());
    assert!(
        mandatory
            .assembly
            .context
            .pack
            .compilation
            .selected_blocks
            .contains(&must(BlockId::new("a")))
    );
    assert!(
        mandatory
            .assembly
            .context
            .pack
            .compilation
            .selected_blocks
            .contains(&must(BlockId::new("dependency")))
    );
    assert!(!stop.observations.lock().expect("observations").is_empty());
}

#[test]
fn semantic_trials_expose_actual_support_variant_hard_complement_and_resident_source_union() {
    let provider = semantic_fixture(false, true);
    let shared = must(
        provider
            .data
            .materialize_evidence(&must(EvidenceHandle::new("shared"))),
    );
    let source_text = shared.excerpt.as_deref().expect("source");
    let prefix_len = "The accepted storage is AtlasDB ".len();
    let mut resident = message("metadata-only-resident", &shared, OutgoingRole::User);
    resident.text = source_text[..prefix_len].into();
    resident.originals[0].text_end = prefix_len as u64;
    resident.originals[0].span.end = prefix_len as u64;
    resident.originals[0].span.span_digest =
        ContentDigest::from_bytes(*blake3::hash(resident.text.as_bytes()).as_bytes());
    let mut request = input();
    request.base.hot.push(resident);
    let probe = SemanticProbe::new(&["a", "b"]);
    let compiled = must(routed(&request, &provider, &probe));
    assert_eq!(compiled.assembly.optional_seeds.len(), 2);
    let observations = probe.observations.lock().expect("observations");
    let pair = observations
        .iter()
        .find(|item| item.seeds.len() == 2)
        .expect("complement pair");
    assert_eq!(
        pair.closure,
        BTreeSet::from([
            must(BlockId::new("a")),
            must(BlockId::new("b")),
            must(BlockId::new("dependency"))
        ])
    );
    assert_eq!(
        pair.choices
            .iter()
            .find(|choice| choice.block_id.as_str() == "a")
            .expect("actual a variant")
            .alternative_index,
        1
    );
    assert_eq!(pair.added_bytes, (source_text.len() - prefix_len) as u64);
    assert_eq!(
        pair.model["trial"]["supports"]
            .as_array()
            .expect("supports")
            .len(),
        1
    );
    assert_eq!(pair.model["trial"]["supports"][0]["excerpt"], source_text);
    let originals = pair.model["trial"]["rendered_originals"]
        .as_array()
        .expect("originals");
    assert_eq!(
        originals
            .iter()
            .filter(|item| item["zone"] == "evidence")
            .map(|item| item["text"].as_str().expect("text"))
            .collect::<String>(),
        &source_text[prefix_len..]
    );
    assert_eq!(
        originals
            .iter()
            .filter(|item| item["zone"] == "hot_history")
            .map(|item| item["text"].as_str().expect("text"))
            .collect::<String>(),
        &source_text[..prefix_len]
    );
    assert!(!pair.model.to_string().contains("Original "));
    let exact = pair.model["trial"]["blocks"]
        .as_array()
        .expect("blocks")
        .iter()
        .find(|item| {
            item["exact_fragments"]
                .as_array()
                .is_some_and(|values| !values.is_empty())
        })
        .expect("exact fragment");
    assert_eq!(exact["exact_fragments"][0]["value"], "AtlasDB");
    assert_eq!(exact["support_slots"], serde_json::json!([0]));
    assert_eq!(exact["alternative_index"], 1);
}

#[derive(Debug)]
struct CountedProvider<'a> {
    inner: &'a Fixture,
    calls: Mutex<[usize; 9]>,
}
impl CountedProvider<'_> {
    fn record(&self, index: usize) {
        self.calls.lock().expect("calls")[index] += 1;
    }
}
impl ContextProvider for CountedProvider<'_> {
    fn snapshot(&self) -> Result<ProviderSnapshot> {
        self.record(0);
        self.inner.snapshot()
    }
    fn candidate_labels(&self) -> Result<Vec<CandidatePolicyLabel>> {
        self.record(1);
        self.inner.candidate_labels()
    }
    fn materialize_candidate(&self, id: &BlockId) -> Result<PackCandidate> {
        self.record(2);
        self.inner.materialize_candidate(id)
    }
    fn evidence_labels(&self, ids: &[EvidenceHandle]) -> Result<Vec<EvidencePolicyLabel>> {
        self.record(3);
        self.inner.evidence_labels(ids)
    }
    fn materialize_evidence(&self, id: &EvidenceHandle) -> Result<PackEvidence> {
        self.record(4);
        self.inner.materialize_evidence(id)
    }
}
impl AssemblyProvider for CountedProvider<'_> {
    fn binding(&self) -> Result<AssemblyBinding> {
        self.record(5);
        self.inner.binding()
    }
    fn dependencies(&self, id: &BlockId) -> Result<EvidenceDependencies> {
        self.record(6);
        self.inner.dependencies(id)
    }
    fn verify_original(
        &self,
        span: &OriginalSourceSpan,
        bytes: &[u8],
        budget: &mut QueryBudget,
    ) -> Result<()> {
        self.record(7);
        self.inner.verify_original(span, bytes, budget)
    }
    fn validate_read_set(&self, read: &AssemblyReadSet, budget: &mut QueryBudget) -> Result<()> {
        self.record(8);
        self.inner.validate_read_set(read, budget)
    }
}

#[derive(Debug, Default)]
struct OptOutR0 {
    scalar: AtomicUsize,
    semantic: AtomicUsize,
}
impl ContextScorer for OptOutR0 {
    fn id(&self) -> &str {
        R0Scorer.id()
    }
    fn score(&self, unit: &ScoringUnit, budget: &mut QueryBudget) -> Result<Option<u64>> {
        self.scalar.fetch_add(1, Ordering::SeqCst);
        R0Scorer.score(unit, budget)
    }
    fn score_semantic(
        &self,
        _: &SemanticScoringUnit<'_>,
        _: &mut QueryBudget,
    ) -> Result<Option<u64>> {
        self.semantic.fetch_add(1, Ordering::SeqCst);
        panic!("default None must not prepare or dispatch semantic features")
    }
}

#[test]
fn default_profile_preserves_r0_wire_budget_and_provider_reads() {
    let fixture = semantic_fixture(false, true);
    let request = input();
    let direct = CountedProvider {
        inner: &fixture,
        calls: Mutex::new([0; 9]),
    };
    let adapted = CountedProvider {
        inner: &fixture,
        calls: Mutex::new([0; 9]),
    };
    let mut first_budget = allowance();
    let mut second_budget = allowance();
    let compiler = must(ContextCompiler::new([7; 32]));
    let first = must(compiler.compile_assembly(
        &request,
        &direct,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        &R0Scorer,
        &mut first_budget,
    ));
    let scorer = OptOutR0::default();
    let second = must(compiler.compile_assembly(
        &request,
        &adapted,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        &scorer,
        &mut second_budget,
    ));
    assert_eq!(
        first.context.canonical_protobuf,
        second.context.canonical_protobuf
    );
    assert_eq!(first.outgoing, second.outgoing);
    assert_eq!(first.messages, second.messages);
    assert_eq!(first.manifest, second.manifest);
    assert_eq!(first.optional_seeds, second.optional_seeds);
    assert_eq!(
        first_budget.remaining_work(),
        second_budget.remaining_work()
    );
    assert_eq!(
        first_budget.remaining_bytes(),
        second_budget.remaining_bytes()
    );
    assert_eq!(
        *direct.calls.lock().expect("calls"),
        *adapted.calls.lock().expect("calls")
    );
    assert!(scorer.scalar.load(Ordering::SeqCst) > 0);
    assert_eq!(scorer.semantic.load(Ordering::SeqCst), 0);
}

#[derive(Debug)]
struct ProjectionFault {
    cancellation: Option<QueryCancellation>,
    calls: AtomicUsize,
}
impl ContextScorer for ProjectionFault {
    fn id(&self) -> &str {
        "test-semantic-projection-fault"
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        Some(SemanticScoringProfile::RenderedClosureV1)
    }
    fn score(&self, _: &ScoringUnit, _: &mut QueryBudget) -> Result<Option<u64>> {
        panic!("semantic only")
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> Result<Option<u64>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        } else {
            must(budget.charge(0, budget.remaining_bytes()));
        }
        assert!(matches!(
            unit.model_input_json(budget),
            Err(ContextError::BudgetExceeded(_))
        ));
        // A caller cannot turn feature failure into a false STOP and proceed.
        unit.model_input_json(budget).map(|_| None)
    }
}

#[derive(Debug)]
struct SameIdSemantic(SemanticProbe);
impl ContextScorer for SameIdSemantic {
    fn id(&self) -> &str {
        R0Scorer.id()
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        self.0.semantic_profile()
    }
    fn score(&self, unit: &ScoringUnit, budget: &mut QueryBudget) -> Result<Option<u64>> {
        self.0.score(unit, budget)
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> Result<Option<u64>> {
        self.0.score_semantic(unit, budget)
    }
}

#[derive(Debug)]
struct FiniteSemantic {
    probe: SemanticProbe,
    nonfinite: bool,
}
impl FiniteContextScorer for FiniteSemantic {
    fn id(&self) -> &str {
        "test-finite-semantic"
    }
    fn semantic_profile(&self) -> Option<SemanticScoringProfile> {
        self.probe.semantic_profile()
    }
    fn score(&self, _: &ScoringUnit, _: &mut QueryBudget) -> Result<Option<f64>> {
        panic!("finite semantic only")
    }
    fn score_semantic(
        &self,
        unit: &SemanticScoringUnit<'_>,
        budget: &mut QueryBudget,
    ) -> Result<Option<f64>> {
        let value = self.probe.score_semantic(unit, budget)?;
        Ok(if self.nonfinite {
            Some(f64::NAN)
        } else {
            value.map(|value| value as f64 / 1_000_000.0)
        })
    }
}

#[test]
fn semantic_upper_bounds_have_no_exact_marginal_and_projection_uses_shared_allowance() {
    let provider = semantic_fixture(false, false);
    let request = input();
    let compiler = must(ContextCompiler::new([7; 32]));
    let probe = SemanticProbe::new(&[]);
    must(compiler.compile_assembly(
        &request,
        &provider,
        &ReferenceTokenizer,
        &TextProtocol { upper_bound: true },
        &probe,
        &mut allowance(),
    ));
    let observations = probe.observations.lock().expect("observations");
    assert!(!observations.is_empty());
    assert!(observations.iter().all(|item| item.marginal.is_none()
        && item.model["budget"]["exact_marginal_input_tokens"].is_null()));
    drop(observations);
    let semantic = SameIdSemantic(SemanticProbe::new(&[]));
    let retained = must(compiler.compile_assembly_with_router_replay(
        &request,
        &provider,
        &ReferenceTokenizer,
        &ReferenceOutgoingEncoder(&ReferenceTokenizer),
        &semantic,
        &mut allowance(),
    ));
    assert_eq!(retained.request.binding.scorer, R0Scorer.id());
    assert!(matches!(
        must(ContextCompiler::replay_router_r0(
            &retained.request,
            &retained.plan,
            &retained.manifest,
            &request.base,
            &retained.prepared_material,
            retained
                .replay_observation
                .as_ref()
                .expect("actual compiler observation"),
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            &mut allowance()
        )),
        crate::router::RouterHistoricalReplayResult::Unavailable(
            crate::router::RouterReplayUnavailableReason::UnsupportedScorerProvenance
        )
    ));
    let finite = FiniteScoreAdapter(FiniteSemantic {
        probe: SemanticProbe::new(&["a"]),
        nonfinite: false,
    });
    assert_eq!(
        must(compile(&request, &provider, &finite)).optional_seeds,
        BTreeSet::from([must(BlockId::new("a"))])
    );
    assert!(
        !finite
            .0
            .probe
            .observations
            .lock()
            .expect("observations")
            .is_empty()
    );
    let nonfinite = FiniteScoreAdapter(FiniteSemantic {
        probe: SemanticProbe::new(&[]),
        nonfinite: true,
    });
    assert!(matches!(
        compile(&request, &provider, &nonfinite),
        Err(ContextError::RouterScore(_))
    ));
    for cancel in [false, true] {
        let cancellation = QueryCancellation::default();
        let fault = ProjectionFault {
            cancellation: cancel.then(|| cancellation.clone()),
            calls: AtomicUsize::new(0),
        };
        let mut budget = QueryBudget::new(
            500_000,
            512 * 1024 * 1024,
            std::time::Duration::from_secs(20),
            cancellation,
        );
        assert!(matches!(
            compiler.compile_assembly(
                &request,
                &provider,
                &ReferenceTokenizer,
                &ReferenceOutgoingEncoder(&ReferenceTokenizer),
                &fault,
                &mut budget
            ),
            Err(ContextError::BudgetExceeded(_))
        ));
        assert_eq!(fault.calls.load(Ordering::SeqCst), 1);
    }
}
