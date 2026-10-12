//! Fixed public native-preparation witnesses for a tokenizer-only sizing census.
//! No existing archive input, learned model, labels, dispatch or default export.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    mem::{size_of, take},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use contextdb_context::router::{canonical_bytes, canonical_digest};
use contextdb_core::{
    ContentDigest, EventRole, MemorySubjectId, ObservationId, OriginalSourceSpan,
};
use contextdb_recall::{QueryCancellation, QueryLimit};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;

mod output;
mod scoring;
use output::{export, fresh_root};
use scoring::{bound, bytes};

const FORMAT: &str = "contextdb.native-semantic-census.v1";
const GENERATOR: &str = "contextdb.native-semantic-census-builtin.v1";
const LINEAGE: &str = "synthetic:native-census-public-family:v1";
const OUTPUT_ENV: &str = "CONTEXTDB_NATIVE_SEMANTIC_CENSUS_OUTPUT";
const MAX_CASES: usize = 64;
const MAX_CASE_ROWS: usize = 128;
const MAX_ROWS: usize = 512;
const MAX_BASE_TRIALS: usize = 16;
const MAX_INPUT: usize = 2 * 1024 * 1024;
const MAX_CORPUS: usize = 64 * 1024 * 1024;
const MAX_ORIGINS: usize = 2048;
const SENTENCE: &str = "The wooden crates are in the northern store room. Inventory reconciliation is scheduled for Friday; painting, shelf repair and delivery sequencing will be discussed at the next routine meeting. ";
const CURRENT: &str = "Continue local inventory work. Storage must be local-only. The proposals keep proposal open and close proposal conflict; neither alternative has been resolved. ";

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Exploration {
    AlwaysStop,
    ConstantPositive,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Choice {
    block_id: BlockId,
    alternative_index: u32,
    generated: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    pack: ContextPack,
    messages: Vec<OutgoingMessage>,
    outgoing: EncodedOutgoing,
    choices: Vec<Choice>,
}

struct Pending {
    input: Value,
    seeds: BTreeSet<BlockId>,
    closure: BTreeSet<BlockId>,
    selected: Witness,
    trial: Witness,
}

struct Collector {
    exploration: Exploration,
    rows: Mutex<Vec<Pending>>,
}

impl fmt::Debug for Collector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicNativeSizingCollector")
            .finish_non_exhaustive()
    }
}

fn invalid() -> ContextError {
    ContextError::Provider("public native sizing witness is invalid".into())
}

fn limited(reason: QueryLimit) -> ContextError {
    ContextError::BudgetExceeded(format!("public native sizing allowance: {reason:?}"))
}

fn charge(budget: &mut QueryBudget, work: u64, bytes: u64) -> Result<()> {
    budget.charge(work, bytes).map_err(limited)
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInterval {
    event_id: ObservationId,
    payload_digest: ContentDigest,
    start: u64,
    end: u64,
}

fn origins(witness: &Witness, budget: &mut QueryBudget) -> Result<Vec<SourceInterval>> {
    let spans = witness
        .pack
        .evidence
        .iter()
        .filter_map(|item| item.original_span.as_ref())
        .chain(
            witness
                .messages
                .iter()
                .flat_map(|item| item.originals.iter().map(|item| &item.span)),
        );
    let mut ranges: BTreeMap<(ObservationId, ContentDigest), Vec<(u64, u64)>> = BTreeMap::new();
    for (count, span) in spans.enumerate() {
        if count >= MAX_ORIGINS || span.end <= span.start {
            return Err(invalid());
        }
        charge(budget, 1, size_of::<SourceInterval>() as u64)?;
        ranges
            .entry((span.event_id, span.payload_digest))
            .or_default()
            .push((span.start, span.end));
    }
    let mut result = Vec::new();
    for ((event_id, payload_digest), mut spans) in ranges {
        spans.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in spans {
            if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        for (start, end) in merged {
            charge(budget, 1, size_of::<SourceInterval>() as u64)?;
            result.push(SourceInterval {
                event_id,
                payload_digest,
                start,
                end,
            });
        }
    }
    Ok(result)
}

fn selected_ids(witness: &Witness, budget: &mut QueryBudget) -> Result<BTreeSet<BlockId>> {
    let size = witness
        .pack
        .sections
        .iter()
        .map(|block| {
            block
                .id
                .as_str()
                .len()
                .saturating_add(size_of::<BlockId>() + 64)
        })
        .sum::<usize>();
    charge(budget, 1, size as u64)?;
    Ok(witness
        .pack
        .sections
        .iter()
        .map(|block| block.id.clone())
        .collect())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    row_id: String,
    input: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    row_id: String,
    case_id: String,
    partition: String,
    lineage_scope: String,
    evaluation: u32,
    feature_digest: ContentDigest,
    request_digest: ContentDigest,
    selected_base_digest: ContentDigest,
    trial_wire_digest: ContentDigest,
    outgoing_fits: bool,
    seed_ids: BTreeSet<BlockId>,
    closure_ids: BTreeSet<BlockId>,
    selected_origins: Vec<SourceInterval>,
    trial_origins: Vec<SourceInterval>,
    selected: Witness,
    trial: Witness,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseObservation {
    case_id: String,
    partition: String,
    lineage_scope: String,
    trace_profile: RouterTraceProfile,
    exploration: Exploration,
    prepared_trace_digest: ContentDigest,
    envelope: RouterEnvelope,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observations {
    cases: Vec<CaseObservation>,
    rows: Vec<Observation>,
}

struct Corpus {
    inputs: Vec<Input>,
    observations: Observations,
}

fn observed_message(
    service: &NativeService,
    owner: &CaptureRequest,
    sequence: u64,
    text: &str,
    role: EventRole,
    zone: OutgoingZone,
) -> OutgoingMessage {
    let mut item = source(sequence, text);
    item.context = owner.context.clone();
    item.event.role = role;
    service
        .append_event(item.clone())
        .expect("fixed public source observation");
    let digest = item
        .event
        .payload
        .digest()
        .expect("fixed exact source digest");
    let outgoing_role = match role {
        EventRole::Assistant => OutgoingRole::Assistant,
        EventRole::Tool => OutgoingRole::Tool,
        _ => OutgoingRole::User,
    };
    OutgoingMessage {
        id: BlockId::new(format!("public-census-{sequence}")).expect("fixture ID"),
        zone,
        role: outgoing_role,
        text: text.into(),
        originals: vec![VisibleOriginal {
            span: OriginalSourceSpan {
                event_id: item.event.event_id,
                payload_digest: digest,
                start: 0,
                end: text.len() as u64,
                span_digest: digest,
            },
            text_start: 0,
            text_end: text.len() as u64,
        }],
        tool_calls: vec![],
        tool_result: None,
    }
}

fn collect_case(
    case_id: &str,
    repeats: usize,
    profile: RouterTraceProfile,
    exploration: Exploration,
    budget: &mut QueryBudget,
) -> Result<(CaseObservation, Vec<Input>, Vec<Observation>)> {
    if ![0, 12, 22].contains(&repeats) {
        return Err(invalid());
    }
    let directory = tempfile::tempdir().expect("fresh public synthetic owner");
    let (_ledger_root, ledger) = crate::suppression::tests::authority("native-semantic-census");
    let (_keys_root, keys) = crate::encryption::tests::authority("native-semantic-census");
    let collector = Arc::new(Collector {
        exploration,
        rows: Mutex::new(vec![]),
    });
    let service = Arc::new(
        NativeService::open_encrypted(
            directory.path(),
            "native-semantic-census",
            [7; 32],
            ledger,
            keys,
        )
        .expect("fresh encrypted native owner")
        .with_preparation_scorer(collector.clone())
        .expect("inert immutable public sizing collector"),
    );
    let mut current = source(1, &format!("{CURRENT}{}", SENTENCE.repeat(repeats)));
    current.context = request(&current).context;
    current
        .context
        .capability_grants
        .insert(Capability::ModelProcessing);
    current.context.request.subject_id = MemorySubjectId::from_uuid(uuid::Uuid::from_u128(10))
        .expect("typed public fixture owner")
        .to_string();
    current.context.request.audiences =
        BTreeSet::from([current.context.request.subject_id.clone()]);
    service
        .append_event(current.clone())
        .expect("fixed public current source");
    let mut plan = request(&current);
    plan.router_trace_profile = profile;
    let mut optional = BTreeSet::new();
    for (sequence, text) in [
        (2, "Earlier inventory observation: amber crates."),
        (3, "Earlier inventory observation: cobalt shelves."),
    ] {
        let item = observed_message(
            &service,
            &current,
            sequence,
            text,
            EventRole::User,
            OutgoingZone::HotHistory,
        );
        optional.insert(item.originals[0].span.event_id);
    }
    plan.base.working.push(observed_message(
        &service,
        &current,
        4,
        "Open action: verify inventory locally before shipment; preserve the unresolved checklist.",
        EventRole::User,
        OutgoingZone::WorkingState,
    ));
    let mut call = observed_message(
        &service,
        &current,
        5,
        "Requesting the bounded public inventory fixture observation.",
        EventRole::Assistant,
        OutgoingZone::HotHistory,
    );
    call.tool_calls.push("public-census-inventory".into());
    let mut result = observed_message(
        &service,
        &current,
        6,
        "Observed inventory fixture: shipment is pending local verification.",
        EventRole::Tool,
        OutgoingZone::HotHistory,
    );
    result.tool_result = Some("public-census-inventory".into());
    // Observed tool protocol, not execution of an external tool or dispatch.
    plan.base.hot.extend([call, result]);
    plan.base.current.push(OutgoingMessage {
        id: BlockId::new("public-census-current").expect("current ID"),
        zone: OutgoingZone::CurrentTurn,
        role: OutgoingRole::User,
        text: format!("{CURRENT}{}", SENTENCE.repeat(repeats)),
        originals: vec![VisibleOriginal {
            span: OriginalSourceSpan {
                event_id: current.event.event_id,
                payload_digest: current.event.payload.digest().expect("current digest"),
                start: 0,
                end: (CURRENT.len() + SENTENCE.len() * repeats) as u64,
                span_digest: current.event.payload.digest().expect("current span digest"),
            },
            text_start: 0,
            text_end: (CURRENT.len() + SENTENCE.len() * repeats) as u64,
        }],
        tool_calls: vec![],
        tool_result: None,
    });
    semantic::states(&service, &current, &mut plan);
    service
        .initialize_state_catalog(&plan.context, budget)
        .expect("native state catalog");
    assert!(
        service
            .project_originals(&plan.context, false, 256, budget)
            .expect("actual public raw frontier")
            .caught_up
    );
    plan.raw_queries.push(IndexedQuery {
        filter: RawFilter {
            event_ids: optional,
            ..Default::default()
        },
        text: None,
        neighbor_of: None,
        selection: IndexedSelection::TopK { limit: 2 },
    });
    let prepared = service
        .prepare_context(
            plan,
            &ReferenceTokenizer,
            &ReferenceOutgoingEncoder(&ReferenceTokenizer),
            budget,
        )
        .expect("actual successful protected public native preparation");
    let trace = prepared.router_trace.as_ref().ok_or_else(invalid)?;
    trace.validate().map_err(|_| invalid())?;
    if trace.canonical_json.len() > MAX_INPUT {
        return Err(invalid());
    }
    charge(
        budget,
        1,
        (trace.canonical_json.len() as u64).saturating_mul(2),
    )?;
    let envelope: RouterEnvelope =
        serde_json::from_str(&trace.canonical_json).map_err(|_| invalid())?;
    envelope.validate(budget).map_err(|_| invalid())?;
    if canonical_bytes(&envelope, budget)? != trace.canonical_json.as_bytes()
        || trace.version != profile.version().ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    let pending = take(&mut *collector.rows.lock().map_err(|_| invalid())?);
    if pending.is_empty()
        || pending.len() != envelope.plan.scores.len()
        || pending.len() > MAX_CASE_ROWS
    {
        return Err(invalid());
    }
    let mut inputs = Vec::new();
    let mut observations = Vec::new();
    for (row, score) in pending.into_iter().zip(&envelope.plan.scores) {
        let selected_ids = selected_ids(&row.selected, budget)?;
        let selected_base_digest = canonical_digest(
            &(
                envelope.request.digest,
                &selected_ids,
                &row.selected.pack,
                &row.selected.messages,
                &row.selected.outgoing,
            ),
            budget,
        )?;
        charge(budget, row.trial.outgoing.wire.len() as u64 / 4096 + 1, 0)?;
        let trial_wire_digest =
            ContentDigest::from_bytes(*blake3::hash(&row.trial.outgoing.wire).as_bytes());
        if row.seeds.iter().ne(score.seed_ids.iter())
            || row.closure.iter().ne(score.closure_ids.iter())
            || selected_base_digest != score.selected_base_digest
            || trial_wire_digest != score.trial_wire_digest
            || envelope.request.digest != score.request_digest
            || row.trial.outgoing.input_tokens != score.trial_input_tokens
            || row
                .trial
                .outgoing
                .input_tokens
                .saturating_sub(row.selected.outgoing.input_tokens)
                != score.marginal_tokens
            || row.input["budget"]["outgoing_fits"].as_bool() != Some(score.outgoing_fits)
        {
            return Err(invalid());
        }
        let feature_digest = canonical_digest(&row.input, budget)?;
        let selected_origins = origins(&row.selected, budget)?;
        let trial_origins = origins(&row.trial, budget)?;
        if selected_origins
            .iter()
            .chain(&trial_origins)
            .any(|origin| !envelope.origins.originals.contains(&origin.event_id))
        {
            return Err(invalid());
        }
        let row_id = format!("{case_id}:callback:{}", score.evaluation);
        inputs.push(Input {
            row_id: row_id.clone(),
            input: row.input,
        });
        observations.push(Observation {
            row_id,
            case_id: case_id.into(),
            partition: "train".into(),
            lineage_scope: LINEAGE.into(),
            evaluation: score.evaluation,
            feature_digest,
            request_digest: score.request_digest,
            selected_base_digest,
            trial_wire_digest,
            outgoing_fits: score.outgoing_fits,
            seed_ids: row.seeds,
            closure_ids: row.closure,
            selected_origins,
            trial_origins,
            selected: row.selected,
            trial: row.trial,
        });
    }
    Ok((
        CaseObservation {
            case_id: case_id.into(),
            partition: "train".into(),
            lineage_scope: LINEAGE.into(),
            trace_profile: profile,
            exploration,
            prepared_trace_digest: trace.trace_digest,
            envelope,
        },
        inputs,
        observations,
    ))
}

fn collect(budget: &mut QueryBudget) -> Result<Corpus> {
    let mut corpus = Corpus {
        inputs: vec![],
        observations: Observations {
            cases: vec![],
            rows: vec![],
        },
    };
    for repeats in [0, 12, 22] {
        for profile in [
            RouterTraceProfile::Required,
            RouterTraceProfile::RequiredReplayV2,
        ] {
            for exploration in [Exploration::AlwaysStop, Exploration::ConstantPositive] {
                if corpus.observations.cases.len() >= MAX_CASES {
                    return Err(invalid());
                }
                let mode = match exploration {
                    Exploration::AlwaysStop => "stop",
                    Exploration::ConstantPositive => "positive",
                };
                let id = format!(
                    "public-notes-{repeats}-v{}-{mode}",
                    profile.version().ok_or_else(invalid)?
                );
                let mut child = budget
                    .reserve(1_000_000, 128 * 1024 * 1024)
                    .map_err(limited)?;
                let (case, inputs, rows) =
                    collect_case(&id, repeats, profile, exploration, &mut child)?;
                if corpus.inputs.len().saturating_add(inputs.len()) > MAX_ROWS {
                    return Err(invalid());
                }
                corpus.observations.cases.push(case);
                corpus.inputs.extend(inputs);
                corpus.observations.rows.extend(rows);
            }
        }
    }
    validate(&corpus, budget)?;
    Ok(corpus)
}

fn validate(corpus: &Corpus, budget: &mut QueryBudget) -> Result<()> {
    if corpus.observations.cases.len() != 12
        || corpus.inputs.is_empty()
        || corpus.inputs.len() > MAX_ROWS
        || corpus.inputs.len() != corpus.observations.rows.len()
    {
        return Err(invalid());
    }
    let mut cases = BTreeMap::new();
    for case in &corpus.observations.cases {
        if case.partition != "train"
            || case.lineage_scope != LINEAGE
            || cases.insert(&case.case_id, case).is_some()
        {
            return Err(invalid());
        }
        case.envelope.validate(budget).map_err(|_| invalid())?;
        if case.envelope.request.binding.scorer != GENERATOR
            || canonical_digest(&case.envelope, budget)? != case.prepared_trace_digest
            || case.trace_profile.is_off()
            || case.envelope.origins.states.len() != 3
            || case.envelope.base.working.len() != 1
            || case.envelope.base.hot.len() != 2
            || case.envelope.base.current.len() != 1
        {
            return Err(invalid());
        }
    }
    let mut identifiers = BTreeSet::new();
    let mut grouped = BTreeMap::new();
    for (input, observation) in corpus.inputs.iter().zip(&corpus.observations.rows) {
        let case = cases.get(&observation.case_id).ok_or_else(invalid)?;
        if input.row_id != observation.row_id
            || !identifiers.insert(&input.row_id)
            || observation.partition != "train"
            || observation.lineage_scope != LINEAGE
            || canonical_digest(&input.input, budget)? != observation.feature_digest
        {
            return Err(invalid());
        }
        let score = case
            .envelope
            .plan
            .scores
            .iter()
            .find(|score| score.evaluation == observation.evaluation)
            .ok_or_else(invalid)?;
        let selected_ids = selected_ids(&observation.selected, budget)?;
        charge(
            budget,
            observation.trial.outgoing.wire.len() as u64 / 4096 + 1,
            0,
        )?;
        if score.request_digest != observation.request_digest
            || score.selected_base_digest != observation.selected_base_digest
            || score.trial_wire_digest != observation.trial_wire_digest
            || score.outgoing_fits != observation.outgoing_fits
            || observation.seed_ids.iter().ne(score.seed_ids.iter())
            || observation.closure_ids.iter().ne(score.closure_ids.iter())
            || canonical_digest(
                &(
                    case.envelope.request.digest,
                    &selected_ids,
                    &observation.selected.pack,
                    &observation.selected.messages,
                    &observation.selected.outgoing,
                ),
                budget,
            )? != observation.selected_base_digest
            || ContentDigest::from_bytes(*blake3::hash(&observation.trial.outgoing.wire).as_bytes())
                != observation.trial_wire_digest
            || observation.selected_origins != origins(&observation.selected, budget)?
            || observation.trial_origins != origins(&observation.trial, budget)?
        {
            return Err(invalid());
        }
        let count = grouped
            .entry((&observation.case_id, observation.selected_base_digest))
            .or_insert(0);
        *count += 1;
        if *count > MAX_BASE_TRIALS {
            return Err(invalid());
        }
        bound(&input.input, MAX_INPUT, budget)?;
    }
    bound(
        &(corpus.inputs.as_slice(), &corpus.observations),
        MAX_CORPUS,
        budget,
    )?;
    Ok(())
}

fn allowance() -> QueryBudget {
    QueryBudget::new(
        20_000_000,
        2 * 1024 * 1024 * 1024,
        // The whole census opens twelve native databases, including on slow CI.
        Duration::from_secs(300),
        Default::default(),
    )
}

#[test]
fn public_native_semantic_census_observes_current_mandatory_and_protocol_witnesses() {
    let mut budget = allowance();
    let corpus = collect(&mut budget).expect("bounded actual native public sizing witnesses");
    for row in &corpus.observations.rows {
        assert!(!row.selected.pack.sections.decisions.is_empty());
        assert!(!row.selected.pack.sections.conflicts.is_empty());
        assert!(!row.selected.pack.sections.unknowns.is_empty());
        assert!(
            row.selected
                .messages
                .iter()
                .any(|message| message.zone == OutgoingZone::WorkingState)
        );
        assert!(
            row.selected
                .messages
                .iter()
                .any(|message| message.role == OutgoingRole::Tool && message.tool_result.is_some())
        );
        assert!(
            row.selected
                .messages
                .iter()
                .any(|message| message.zone == OutgoingZone::CurrentTurn)
        );
        assert_eq!(row.selected.outgoing.count_kind, RequestCountKind::Exact);
    }
    assert!(
        corpus
            .observations
            .cases
            .iter()
            .any(|case| case.envelope.base.current[0].text
                == format!("{CURRENT}{}", SENTENCE.repeat(12)))
    );
    assert!(
        corpus
            .observations
            .cases
            .iter()
            .any(|case| case.envelope.base.current[0].text
                == format!("{CURRENT}{}", SENTENCE.repeat(22)))
    );
    if let Some(output) = std::env::var_os(OUTPUT_ENV) {
        let root = PathBuf::from(output);
        let digest =
            export(&root, &corpus, &mut budget).expect("explicit fresh isolated census output");
        eprintln!(
            "native sizing census cases={} rows={} manifest={digest}",
            corpus.observations.cases.len(),
            corpus.inputs.len()
        );
    }
}

#[test]
fn public_native_census_refuses_tamper_exhaustion_and_nonfresh_outputs() {
    let mut budget = allowance();
    let mut corpus = collect(&mut budget).expect("fixed public corpus");
    corpus.observations.rows[0].evaluation = u32::MAX;
    assert!(validate(&corpus, &mut budget).is_err());
    let cancelled = QueryCancellation::default();
    cancelled.cancel();
    for mut exhausted in [
        QueryBudget::new(0, 0, Duration::from_secs(60), Default::default()),
        QueryBudget::new(
            20_000_000,
            2 * 1024 * 1024 * 1024,
            Duration::from_secs(60),
            cancelled,
        ),
    ] {
        assert!(collect(&mut exhausted).is_err());
    }
    let root = tempfile::tempdir().expect("output gate parent");
    assert!(fresh_root(Path::new("relative-census")).is_err());
    assert!(fresh_root(root.path()).is_err());
    let archive = root.path().join("fixture.ctxb");
    fs::write(&archive, b"explicit public output-gate sentinel").expect("public fixture sentinel");
    assert!(fresh_root(&root.path().join("census-output")).is_err());
    assert_eq!(
        fs::read(archive).expect("unchanged sentinel"),
        b"explicit public output-gate sentinel"
    );
}
