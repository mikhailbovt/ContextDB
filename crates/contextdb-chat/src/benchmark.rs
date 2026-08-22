//! Deterministic BENCH-A workload and report contracts.

#![allow(
    missing_docs,
    reason = "benchmark DTO field names are the stable report schema"
)]

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::{ChatError, Result};

/// Stable BENCH-A generator version.
pub const BENCH_A_VERSION: &str = "contextdb-bench-a-v1";

/// Normative full workload or bounded CI smoke workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchAScale {
    /// Fast deterministic coverage for package CI.
    Smoke,
    /// RFC M11 release workload: 1,000 sessions and 50,000 turns.
    Full,
}

/// Auditable synthetic history dimensions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchAManifest {
    /// Generator contract.
    pub version: String,
    /// Virtual duration.
    pub virtual_years: u32,
    /// Conversation count.
    pub sessions: u32,
    /// Total durable turns.
    pub turns: u32,
    /// Distinct people.
    pub people: u32,
    /// Distinct topics.
    pub topics: u32,
    /// Shared references introduced.
    pub shared_references: u32,
    /// Preference changes introduced.
    pub preference_changes: u32,
    /// Corrections introduced.
    pub corrections: u32,
    /// Open loops introduced.
    pub open_loops: u32,
    /// Labelled sensitive memories.
    pub sensitive_memories: u32,
    /// Runtime/model epochs.
    pub model_migrations: u32,
    /// Queries per class.
    pub queries_per_class: u32,
}

impl BenchAManifest {
    /// RFC-conformant full dimensions.
    #[must_use]
    pub fn full() -> Self {
        Self {
            version: BENCH_A_VERSION.to_owned(),
            virtual_years: 5,
            sessions: 1_000,
            turns: 50_000,
            people: 50,
            topics: 200,
            shared_references: 120,
            preference_changes: 120,
            corrections: 120,
            open_loops: 120,
            sensitive_memories: 120,
            model_migrations: 4,
            queries_per_class: 100,
        }
    }

    /// Bounded CI dimensions preserving every adversarial class.
    #[must_use]
    pub fn smoke() -> Self {
        Self {
            version: BENCH_A_VERSION.to_owned(),
            virtual_years: 2,
            sessions: 40,
            turns: 2_000,
            people: 10,
            topics: 25,
            shared_references: 12,
            preference_changes: 12,
            corrections: 12,
            open_loops: 12,
            sensitive_memories: 12,
            model_migrations: 2,
            queries_per_class: 10,
        }
    }

    /// Validates that no dimension silently drops an M11 scenario class.
    pub fn validate(&self) -> Result<()> {
        if self.version != BENCH_A_VERSION
            || self.virtual_years == 0
            || self.sessions == 0
            || self.turns < self.sessions
            || self.people == 0
            || self.topics == 0
            || self.shared_references == 0
            || self.preference_changes == 0
            || self.corrections == 0
            || self.open_loops == 0
            || self.sensitive_memories == 0
            || self.model_migrations < 2
            || self.queries_per_class == 0
        {
            return Err(ChatError::InvalidInput("bench_a_manifest"));
        }
        Ok(())
    }
}

/// Synthetic event category represented in the lifetime history.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchAEventKind {
    Casual,
    SharedReference,
    PreferenceChange,
    Correction,
    OpenLoop,
    Sensitive,
    Contradiction,
    TemporaryMood,
    ForgetRequest,
}

/// Payload-light deterministic turn descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchATurn {
    pub ordinal: u32,
    pub session: u32,
    pub virtual_day: u32,
    pub person: u32,
    pub topic: u32,
    pub runtime_epoch: u32,
    pub memory_id: String,
    pub kind: BenchAEventKind,
    pub private: bool,
}

/// Required benchmark query classes from RFC section 28.7.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchAQueryClass {
    ExplicitRecall,
    ImplicitContinuity,
    PersonResolution,
    SharedReference,
    HistoricalBelief,
    CurrentState,
    Correction,
    Unknown,
    AppropriateSilence,
    Reflective,
}

const QUERY_CLASSES: [BenchAQueryClass; 10] = [
    BenchAQueryClass::ExplicitRecall,
    BenchAQueryClass::ImplicitContinuity,
    BenchAQueryClass::PersonResolution,
    BenchAQueryClass::SharedReference,
    BenchAQueryClass::HistoricalBelief,
    BenchAQueryClass::CurrentState,
    BenchAQueryClass::Correction,
    BenchAQueryClass::Unknown,
    BenchAQueryClass::AppropriateSilence,
    BenchAQueryClass::Reflective,
];

/// One deterministic expected-result contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchAQuery {
    pub id: String,
    pub class: BenchAQueryClass,
    /// Provider-neutral natural-language cue presented to the recall stack.
    pub query_text: String,
    pub expected_memory_ids: BTreeSet<String>,
    /// Labelled same-surface memories belonging to another person.
    pub wrong_person_memory_ids: BTreeSet<String>,
    /// Labelled records from the wrong valid-time view.
    pub temporally_forbidden_memory_ids: BTreeSet<String>,
    pub forbidden_memory_ids: BTreeSet<String>,
    pub expect_silence: bool,
}

/// Complete reproducible BENCH-A dataset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchADataset {
    pub manifest: BenchAManifest,
    pub turns: Vec<BenchATurn>,
    pub queries: Vec<BenchAQuery>,
    pub digest: ContentDigest,
}

impl BenchADataset {
    /// Generates a stable workload without random-number or model dependencies.
    pub fn generate(scale: BenchAScale) -> Result<Self> {
        let manifest = match scale {
            BenchAScale::Smoke => BenchAManifest::smoke(),
            BenchAScale::Full => BenchAManifest::full(),
        };
        Self::generate_from(manifest)
    }

    /// Generates from an explicit validated manifest.
    pub fn generate_from(manifest: BenchAManifest) -> Result<Self> {
        manifest.validate()?;
        let mut turns = Vec::with_capacity(
            usize::try_from(manifest.turns).map_err(|_| ChatError::ArithmeticOverflow)?,
        );
        let virtual_days = manifest.virtual_years.saturating_mul(365);
        for ordinal in 0..manifest.turns {
            let kind = event_kind(ordinal, &manifest);
            turns.push(BenchATurn {
                ordinal,
                session: ordinal.saturating_mul(manifest.sessions) / manifest.turns,
                virtual_day: ordinal.saturating_mul(virtual_days) / manifest.turns,
                person: ordinal.saturating_mul(17) % manifest.people,
                topic: ordinal.saturating_mul(31) % manifest.topics,
                runtime_epoch: ordinal.saturating_mul(manifest.model_migrations) / manifest.turns,
                memory_id: format!("memory-{ordinal:08}"),
                kind,
                private: matches!(kind, BenchAEventKind::Sensitive),
            });
        }
        let sensitive = turns
            .iter()
            .filter(|turn| turn.private)
            .map(|turn| turn.memory_id.clone())
            .collect::<Vec<_>>();
        let by_kind = turns.iter().fold(
            BTreeMap::<BenchAEventKind, Vec<String>>::new(),
            |mut map, turn| {
                map.entry(turn.kind)
                    .or_default()
                    .push(turn.memory_id.clone());
                map
            },
        );
        let mut queries = Vec::new();
        for class in QUERY_CLASSES {
            for ordinal in 0..manifest.queries_per_class {
                let expected = expected_for(class, ordinal, &by_kind);
                queries.push(BenchAQuery {
                    id: format!("{:?}-{ordinal:04}", class).to_lowercase(),
                    class,
                    query_text: query_text(class, ordinal),
                    expected_memory_ids: expected,
                    wrong_person_memory_ids: wrong_person_for(class, ordinal, &by_kind),
                    temporally_forbidden_memory_ids: temporal_for(class, ordinal, &by_kind),
                    forbidden_memory_ids: sensitive.iter().cloned().collect(),
                    expect_silence: matches!(
                        class,
                        BenchAQueryClass::Unknown | BenchAQueryClass::AppropriateSilence
                    ),
                });
            }
        }
        let digest = dataset_digest(&manifest, &turns, &queries)?;
        Ok(Self {
            manifest,
            turns,
            queries,
            digest,
        })
    }

    /// Recomputes the content digest to detect accidental workload drift.
    pub fn verify_digest(&self) -> Result<()> {
        if dataset_digest(&self.manifest, &self.turns, &self.queries)? != self.digest {
            return Err(ChatError::InvalidInput("bench_a_dataset_digest"));
        }
        Ok(())
    }
}

/// One system-under-test result. IDs and digests allow deterministic scoring
/// without storing response prose in the benchmark report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchAQueryOutcome {
    pub query_id: String,
    pub recalled_memory_ids: BTreeSet<String>,
    pub mentioned_memory_ids: BTreeSet<String>,
    pub answer_digest: ContentDigest,
    pub restart_answer_digest: ContentDigest,
    pub second_runtime_answer_digest: ContentDigest,
    pub recall_latency_micros: u64,
    pub context_tokens: u32,
}

/// One normalized system answer before cross-restart/runtime comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchAAnswer {
    pub recalled_memory_ids: BTreeSet<String>,
    pub mentioned_memory_ids: BTreeSet<String>,
    /// Digest of normalized semantic answer, not provider-specific prose.
    pub semantic_answer_digest: ContentDigest,
    pub recall_latency_micros: u64,
    /// Complete compiler-rendered input cost for the selected runtime lane.
    pub context_tokens: u32,
}

/// Runtime lane used to prove that BENCH-A is not tied to one provider format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchARuntimeLane {
    Primary,
    Secondary,
}

/// Executable boundary implemented by a reference vertical or integration test.
pub trait BenchASystem {
    /// Ingests one ordered synthetic turn.
    fn ingest(&mut self, turn: &BenchATurn) -> Result<()>;
    /// Reopens the persistent system in a new process-equivalent instance.
    fn restart(&mut self) -> Result<()>;
    /// Evaluates one query through a selected provider-neutral runtime lane.
    fn query(&mut self, query: &BenchAQuery, runtime: BenchARuntimeLane) -> Result<BenchAAnswer>;
}

/// Deterministic BENCH-A ingestion, restart, runtime-switch, and scoring harness.
#[derive(Clone, Copy, Debug, Default)]
pub struct BenchAHarness;

impl BenchAHarness {
    /// Runs the complete dataset. It queries the primary runtime before and
    /// after restart, then the secondary runtime over the same durable state.
    pub fn run<S: BenchASystem>(dataset: &BenchADataset, system: &mut S) -> Result<BenchAReport> {
        dataset.verify_digest()?;
        for turn in &dataset.turns {
            system.ingest(turn)?;
        }
        let baseline = dataset
            .queries
            .iter()
            .map(|query| system.query(query, BenchARuntimeLane::Primary))
            .collect::<Result<Vec<_>>>()?;
        system.restart()?;
        let mut outcomes = Vec::with_capacity(dataset.queries.len());
        for (query, first) in dataset.queries.iter().zip(baseline) {
            let restarted = system.query(query, BenchARuntimeLane::Primary)?;
            let secondary = system.query(query, BenchARuntimeLane::Secondary)?;
            outcomes.push(BenchAQueryOutcome {
                query_id: query.id.clone(),
                recalled_memory_ids: first.recalled_memory_ids,
                mentioned_memory_ids: first.mentioned_memory_ids,
                answer_digest: first.semantic_answer_digest,
                restart_answer_digest: restarted.semantic_answer_digest,
                second_runtime_answer_digest: secondary.semantic_answer_digest,
                recall_latency_micros: first
                    .recall_latency_micros
                    .max(restarted.recall_latency_micros)
                    .max(secondary.recall_latency_micros),
                context_tokens: first
                    .context_tokens
                    .max(restarted.context_tokens)
                    .max(secondary.context_tokens),
            });
        }
        BenchAReport::evaluate(dataset, &outcomes)
    }
}

/// Machine-readable aggregate metrics. Rates use integer basis points or ppm.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchAReport {
    pub dataset_digest: ContentDigest,
    pub queries: u64,
    pub memory_precision_basis_points: u32,
    pub memory_recall_basis_points: u32,
    pub referent_resolution_basis_points: u32,
    pub current_truth_basis_points: u32,
    pub historical_truth_basis_points: u32,
    pub temporal_leakage_ppm: u32,
    pub wrong_person_ppm: u32,
    pub correction_survival_basis_points: u32,
    pub shared_reference_basis_points: u32,
    pub implicit_continuity_basis_points: u32,
    pub unknown_precision_basis_points: u32,
    pub continuity_preference_basis_points: u32,
    pub private_memory_leak_ppm: u32,
    pub unsolicited_mention_ppm: u32,
    pub restart_consistency_basis_points: u32,
    pub cross_runtime_consistency_basis_points: u32,
    pub context_tokens_p95: u32,
    pub recall_latency_p95_micros: u64,
}

/// Published M11 acceptance floor/ceilings. These are project gates because the
/// RFC names metrics but deliberately leaves deployment thresholds open.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchAThresholds {
    pub minimum_precision_basis_points: u32,
    pub minimum_recall_basis_points: u32,
    pub minimum_referent_resolution_basis_points: u32,
    pub minimum_current_truth_basis_points: u32,
    pub minimum_historical_truth_basis_points: u32,
    pub maximum_temporal_leakage_ppm: u32,
    pub maximum_wrong_person_ppm: u32,
    pub minimum_correction_survival_basis_points: u32,
    pub minimum_shared_reference_basis_points: u32,
    pub minimum_implicit_continuity_basis_points: u32,
    pub minimum_unknown_precision_basis_points: u32,
    pub minimum_continuity_preference_basis_points: u32,
    pub maximum_private_memory_leak_ppm: u32,
    pub maximum_unsolicited_mention_ppm: u32,
    pub minimum_restart_consistency_basis_points: u32,
    pub minimum_cross_runtime_consistency_basis_points: u32,
    pub maximum_context_tokens_p95: u32,
    pub maximum_recall_p95_micros: u64,
}

impl Default for BenchAThresholds {
    fn default() -> Self {
        Self {
            minimum_precision_basis_points: 9_000,
            minimum_recall_basis_points: 8_500,
            minimum_referent_resolution_basis_points: 9_500,
            minimum_current_truth_basis_points: 9_500,
            minimum_historical_truth_basis_points: 9_500,
            maximum_temporal_leakage_ppm: 10_000,
            maximum_wrong_person_ppm: 10_000,
            minimum_correction_survival_basis_points: 9_900,
            minimum_shared_reference_basis_points: 9_500,
            minimum_implicit_continuity_basis_points: 9_000,
            minimum_unknown_precision_basis_points: 9_900,
            minimum_continuity_preference_basis_points: 9_000,
            maximum_private_memory_leak_ppm: 0,
            maximum_unsolicited_mention_ppm: 5_000,
            minimum_restart_consistency_basis_points: 10_000,
            minimum_cross_runtime_consistency_basis_points: 10_000,
            maximum_context_tokens_p95: 4_096,
            maximum_recall_p95_micros: 500_000,
        }
    }
}

/// Named failed gates rather than one lossy Boolean.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchAGateFailure {
    Precision,
    Recall,
    ReferentResolution,
    CurrentTruth,
    HistoricalTruth,
    TemporalLeakage,
    WrongPerson,
    CorrectionSurvival,
    SharedReference,
    ImplicitContinuity,
    UnknownPrecision,
    ContinuityPreference,
    PrivateMemoryLeak,
    UnsolicitedMention,
    RestartConsistency,
    CrossRuntimeConsistency,
    ContextTokens,
    RecallLatency,
}

impl BenchAReport {
    /// Scores exactly one outcome for every generated query.
    pub fn evaluate(dataset: &BenchADataset, outcomes: &[BenchAQueryOutcome]) -> Result<Self> {
        dataset.verify_digest()?;
        if outcomes.len() != dataset.queries.len() {
            return Err(ChatError::InvalidInput("bench_a_outcome_count"));
        }
        let by_id = outcomes
            .iter()
            .map(|outcome| (outcome.query_id.as_str(), outcome))
            .collect::<BTreeMap<_, _>>();
        if by_id.len() != outcomes.len() {
            return Err(ChatError::InvalidInput("bench_a_duplicate_outcome"));
        }
        let mut true_positive = 0_u64;
        let mut false_positive = 0_u64;
        let mut false_negative = 0_u64;
        let mut correction_total = 0_u64;
        let mut correction_hits = 0_u64;
        let mut referent_total = 0_u64;
        let mut referent_hits = 0_u64;
        let mut current_total = 0_u64;
        let mut current_hits = 0_u64;
        let mut historical_total = 0_u64;
        let mut historical_hits = 0_u64;
        let mut temporal_total = 0_u64;
        let mut temporal_leaks = 0_u64;
        let mut wrong_person_total = 0_u64;
        let mut wrong_person_hits = 0_u64;
        let mut shared_total = 0_u64;
        let mut shared_hits = 0_u64;
        let mut implicit_total = 0_u64;
        let mut implicit_hits = 0_u64;
        let mut unknown_total = 0_u64;
        let mut unknown_hits = 0_u64;
        let mut continuity_total = 0_u64;
        let mut continuity_hits = 0_u64;
        let mut private_leaks = 0_u64;
        let mut disclosed = 0_u64;
        let mut silence_queries = 0_u64;
        let mut unsolicited = 0_u64;
        let mut restart_equal = 0_u64;
        let mut runtime_equal = 0_u64;
        let mut latencies = Vec::with_capacity(outcomes.len());
        let mut context_tokens = Vec::with_capacity(outcomes.len());
        for query in &dataset.queries {
            let outcome = by_id
                .get(query.id.as_str())
                .ok_or(ChatError::InvalidInput("bench_a_missing_outcome"))?;
            true_positive = true_positive.saturating_add(
                u64::try_from(
                    outcome
                        .recalled_memory_ids
                        .intersection(&query.expected_memory_ids)
                        .count(),
                )
                .map_err(|_| ChatError::ArithmeticOverflow)?,
            );
            false_positive = false_positive.saturating_add(
                u64::try_from(
                    outcome
                        .recalled_memory_ids
                        .difference(&query.expected_memory_ids)
                        .count(),
                )
                .map_err(|_| ChatError::ArithmeticOverflow)?,
            );
            false_negative = false_negative.saturating_add(
                u64::try_from(
                    query
                        .expected_memory_ids
                        .difference(&outcome.recalled_memory_ids)
                        .count(),
                )
                .map_err(|_| ChatError::ArithmeticOverflow)?,
            );
            private_leaks = private_leaks.saturating_add(
                u64::try_from(
                    outcome
                        .mentioned_memory_ids
                        .intersection(&query.forbidden_memory_ids)
                        .count(),
                )
                .map_err(|_| ChatError::ArithmeticOverflow)?,
            );
            disclosed = disclosed.saturating_add(
                u64::try_from(outcome.mentioned_memory_ids.len())
                    .map_err(|_| ChatError::ArithmeticOverflow)?,
            );
            if query.expect_silence {
                silence_queries = silence_queries.saturating_add(1);
                if !outcome.mentioned_memory_ids.is_empty() {
                    unsolicited = unsolicited.saturating_add(1);
                }
            }
            if query.class == BenchAQueryClass::Correction {
                correction_total = correction_total.saturating_add(1);
                if query
                    .expected_memory_ids
                    .is_subset(&outcome.recalled_memory_ids)
                {
                    correction_hits = correction_hits.saturating_add(1);
                }
            }
            let exact_match = outcome.recalled_memory_ids == query.expected_memory_ids;
            match query.class {
                BenchAQueryClass::PersonResolution => {
                    referent_total = referent_total.saturating_add(1);
                    referent_hits = referent_hits.saturating_add(u64::from(exact_match));
                    wrong_person_total = wrong_person_total.saturating_add(1);
                    if !outcome
                        .recalled_memory_ids
                        .is_disjoint(&query.wrong_person_memory_ids)
                    {
                        wrong_person_hits = wrong_person_hits.saturating_add(1);
                    }
                }
                BenchAQueryClass::CurrentState => {
                    current_total = current_total.saturating_add(1);
                    current_hits = current_hits.saturating_add(u64::from(exact_match));
                    temporal_total = temporal_total.saturating_add(1);
                    if !outcome
                        .recalled_memory_ids
                        .is_disjoint(&query.temporally_forbidden_memory_ids)
                    {
                        temporal_leaks = temporal_leaks.saturating_add(1);
                    }
                }
                BenchAQueryClass::HistoricalBelief => {
                    historical_total = historical_total.saturating_add(1);
                    historical_hits = historical_hits.saturating_add(u64::from(exact_match));
                    temporal_total = temporal_total.saturating_add(1);
                    if !outcome
                        .recalled_memory_ids
                        .is_disjoint(&query.temporally_forbidden_memory_ids)
                    {
                        temporal_leaks = temporal_leaks.saturating_add(1);
                    }
                }
                BenchAQueryClass::SharedReference => {
                    shared_total = shared_total.saturating_add(1);
                    shared_hits = shared_hits.saturating_add(u64::from(exact_match));
                    continuity_total = continuity_total.saturating_add(1);
                    continuity_hits = continuity_hits.saturating_add(u64::from(exact_match));
                }
                BenchAQueryClass::ImplicitContinuity => {
                    implicit_total = implicit_total.saturating_add(1);
                    implicit_hits = implicit_hits.saturating_add(u64::from(exact_match));
                    continuity_total = continuity_total.saturating_add(1);
                    continuity_hits = continuity_hits.saturating_add(u64::from(exact_match));
                }
                BenchAQueryClass::Reflective => {
                    continuity_total = continuity_total.saturating_add(1);
                    continuity_hits = continuity_hits.saturating_add(u64::from(exact_match));
                }
                BenchAQueryClass::Unknown => {
                    unknown_total = unknown_total.saturating_add(1);
                    unknown_hits = unknown_hits
                        .saturating_add(u64::from(outcome.mentioned_memory_ids.is_empty()));
                }
                BenchAQueryClass::ExplicitRecall
                | BenchAQueryClass::Correction
                | BenchAQueryClass::AppropriateSilence => {}
            }
            if outcome.answer_digest == outcome.restart_answer_digest {
                restart_equal = restart_equal.saturating_add(1);
            }
            if outcome.answer_digest == outcome.second_runtime_answer_digest {
                runtime_equal = runtime_equal.saturating_add(1);
            }
            latencies.push(outcome.recall_latency_micros);
            context_tokens.push(u64::from(outcome.context_tokens));
        }
        latencies.sort_unstable();
        context_tokens.sort_unstable();
        let query_count =
            u64::try_from(dataset.queries.len()).map_err(|_| ChatError::ArithmeticOverflow)?;
        Ok(Self {
            dataset_digest: dataset.digest,
            queries: query_count,
            memory_precision_basis_points: ratio(
                true_positive,
                true_positive + false_positive,
                10_000,
            ),
            memory_recall_basis_points: ratio(
                true_positive,
                true_positive + false_negative,
                10_000,
            ),
            referent_resolution_basis_points: ratio(referent_hits, referent_total, 10_000),
            current_truth_basis_points: ratio(current_hits, current_total, 10_000),
            historical_truth_basis_points: ratio(historical_hits, historical_total, 10_000),
            temporal_leakage_ppm: ratio(temporal_leaks, temporal_total, 1_000_000),
            wrong_person_ppm: ratio(wrong_person_hits, wrong_person_total, 1_000_000),
            correction_survival_basis_points: ratio(correction_hits, correction_total, 10_000),
            shared_reference_basis_points: ratio(shared_hits, shared_total, 10_000),
            implicit_continuity_basis_points: ratio(implicit_hits, implicit_total, 10_000),
            unknown_precision_basis_points: ratio(unknown_hits, unknown_total, 10_000),
            continuity_preference_basis_points: ratio(continuity_hits, continuity_total, 10_000),
            private_memory_leak_ppm: ratio(private_leaks, disclosed.max(1), 1_000_000),
            unsolicited_mention_ppm: ratio(unsolicited, silence_queries, 1_000_000),
            restart_consistency_basis_points: ratio(restart_equal, query_count, 10_000),
            cross_runtime_consistency_basis_points: ratio(runtime_equal, query_count, 10_000),
            context_tokens_p95: u32::try_from(percentile_95(&context_tokens)).unwrap_or(u32::MAX),
            recall_latency_p95_micros: percentile_95(&latencies),
        })
    }

    /// Returns every unmet release gate.
    #[must_use]
    pub fn failures(&self, thresholds: BenchAThresholds) -> Vec<BenchAGateFailure> {
        let mut failures = Vec::new();
        if self.memory_precision_basis_points < thresholds.minimum_precision_basis_points {
            failures.push(BenchAGateFailure::Precision);
        }
        if self.memory_recall_basis_points < thresholds.minimum_recall_basis_points {
            failures.push(BenchAGateFailure::Recall);
        }
        if self.referent_resolution_basis_points
            < thresholds.minimum_referent_resolution_basis_points
        {
            failures.push(BenchAGateFailure::ReferentResolution);
        }
        if self.current_truth_basis_points < thresholds.minimum_current_truth_basis_points {
            failures.push(BenchAGateFailure::CurrentTruth);
        }
        if self.historical_truth_basis_points < thresholds.minimum_historical_truth_basis_points {
            failures.push(BenchAGateFailure::HistoricalTruth);
        }
        if self.temporal_leakage_ppm > thresholds.maximum_temporal_leakage_ppm {
            failures.push(BenchAGateFailure::TemporalLeakage);
        }
        if self.wrong_person_ppm > thresholds.maximum_wrong_person_ppm {
            failures.push(BenchAGateFailure::WrongPerson);
        }
        if self.correction_survival_basis_points
            < thresholds.minimum_correction_survival_basis_points
        {
            failures.push(BenchAGateFailure::CorrectionSurvival);
        }
        if self.shared_reference_basis_points < thresholds.minimum_shared_reference_basis_points {
            failures.push(BenchAGateFailure::SharedReference);
        }
        if self.implicit_continuity_basis_points
            < thresholds.minimum_implicit_continuity_basis_points
        {
            failures.push(BenchAGateFailure::ImplicitContinuity);
        }
        if self.unknown_precision_basis_points < thresholds.minimum_unknown_precision_basis_points {
            failures.push(BenchAGateFailure::UnknownPrecision);
        }
        if self.continuity_preference_basis_points
            < thresholds.minimum_continuity_preference_basis_points
        {
            failures.push(BenchAGateFailure::ContinuityPreference);
        }
        if self.private_memory_leak_ppm > thresholds.maximum_private_memory_leak_ppm {
            failures.push(BenchAGateFailure::PrivateMemoryLeak);
        }
        if self.unsolicited_mention_ppm > thresholds.maximum_unsolicited_mention_ppm {
            failures.push(BenchAGateFailure::UnsolicitedMention);
        }
        if self.restart_consistency_basis_points
            < thresholds.minimum_restart_consistency_basis_points
        {
            failures.push(BenchAGateFailure::RestartConsistency);
        }
        if self.cross_runtime_consistency_basis_points
            < thresholds.minimum_cross_runtime_consistency_basis_points
        {
            failures.push(BenchAGateFailure::CrossRuntimeConsistency);
        }
        if self.context_tokens_p95 > thresholds.maximum_context_tokens_p95 {
            failures.push(BenchAGateFailure::ContextTokens);
        }
        if self.recall_latency_p95_micros > thresholds.maximum_recall_p95_micros {
            failures.push(BenchAGateFailure::RecallLatency);
        }
        failures
    }
}

fn event_kind(ordinal: u32, manifest: &BenchAManifest) -> BenchAEventKind {
    if ordinal < manifest.shared_references {
        BenchAEventKind::SharedReference
    } else if ordinal < manifest.shared_references + manifest.preference_changes {
        BenchAEventKind::PreferenceChange
    } else if ordinal
        < manifest.shared_references + manifest.preference_changes + manifest.corrections
    {
        BenchAEventKind::Correction
    } else if ordinal
        < manifest.shared_references
            + manifest.preference_changes
            + manifest.corrections
            + manifest.open_loops
    {
        BenchAEventKind::OpenLoop
    } else if ordinal
        < manifest.shared_references
            + manifest.preference_changes
            + manifest.corrections
            + manifest.open_loops
            + manifest.sensitive_memories
    {
        BenchAEventKind::Sensitive
    } else {
        match ordinal % 5 {
            0 => BenchAEventKind::Casual,
            1 => BenchAEventKind::Contradiction,
            2 => BenchAEventKind::TemporaryMood,
            3 => BenchAEventKind::ForgetRequest,
            _ => BenchAEventKind::Casual,
        }
    }
}

fn expected_for(
    class: BenchAQueryClass,
    ordinal: u32,
    by_kind: &BTreeMap<BenchAEventKind, Vec<String>>,
) -> BTreeSet<String> {
    let kind = match class {
        BenchAQueryClass::SharedReference | BenchAQueryClass::PersonResolution => {
            Some(BenchAEventKind::SharedReference)
        }
        BenchAQueryClass::ImplicitContinuity => Some(BenchAEventKind::OpenLoop),
        BenchAQueryClass::Correction | BenchAQueryClass::CurrentState => {
            Some(BenchAEventKind::Correction)
        }
        BenchAQueryClass::HistoricalBelief => Some(BenchAEventKind::PreferenceChange),
        BenchAQueryClass::Reflective => Some(BenchAEventKind::Contradiction),
        BenchAQueryClass::ExplicitRecall => Some(BenchAEventKind::Casual),
        BenchAQueryClass::Unknown | BenchAQueryClass::AppropriateSilence => None,
    };
    kind.and_then(|kind| by_kind.get(&kind))
        .filter(|values| !values.is_empty())
        .and_then(|values| values.get(usize::try_from(ordinal).ok()? % values.len()))
        .cloned()
        .into_iter()
        .collect()
}

fn query_text(class: BenchAQueryClass, ordinal: u32) -> String {
    let cue = query_cue(class, ordinal);
    match class {
        BenchAQueryClass::ExplicitRecall => format!("What did I say about {cue}?"),
        BenchAQueryClass::ImplicitContinuity => format!("Should we continue {cue}?"),
        BenchAQueryClass::PersonResolution => format!("Who was the person behind {cue}?"),
        BenchAQueryClass::SharedReference => format!("Do you remember {cue}?"),
        BenchAQueryClass::HistoricalBelief => format!("What did I believe at {cue}?"),
        BenchAQueryClass::CurrentState => format!("What is current for {cue}?"),
        BenchAQueryClass::Correction => format!("Which correction applies to {cue}?"),
        // Single synthetic OOV tokens keep the labelled negative classes from
        // matching unrelated records merely through English stop words.
        BenchAQueryClass::Unknown => format!(
            "unsupportedx{ordinal:04} unsupportedy{ordinal:04} unsupportedz{ordinal:04} unsupportedw{ordinal:04}"
        ),
        BenchAQueryClass::AppropriateSilence => format!(
            "unrelatedx{ordinal:04} unrelatedy{ordinal:04} unrelatedz{ordinal:04} unrelatedw{ordinal:04}"
        ),
        BenchAQueryClass::Reflective => format!("Which pattern returns at {cue}?"),
    }
}

/// Stable exact-alias cue used by reference-stack BENCH-A adapters.
#[must_use]
pub fn query_cue(class: BenchAQueryClass, ordinal: u32) -> String {
    let class = match class {
        BenchAQueryClass::ExplicitRecall => "explicit",
        BenchAQueryClass::ImplicitContinuity => "implicit",
        BenchAQueryClass::PersonResolution => "person",
        BenchAQueryClass::SharedReference => "shared",
        BenchAQueryClass::HistoricalBelief => "historical",
        BenchAQueryClass::CurrentState => "current",
        BenchAQueryClass::Correction => "correction",
        BenchAQueryClass::Unknown => "unknown",
        BenchAQueryClass::AppropriateSilence => "silence-sensitive",
        BenchAQueryClass::Reflective => "reflective",
    };
    format!("bench-a-{class}-{ordinal:04}")
}

fn wrong_person_for(
    class: BenchAQueryClass,
    ordinal: u32,
    by_kind: &BTreeMap<BenchAEventKind, Vec<String>>,
) -> BTreeSet<String> {
    if class != BenchAQueryClass::PersonResolution {
        return BTreeSet::new();
    }
    alternate_for(BenchAEventKind::SharedReference, ordinal, by_kind)
}

fn temporal_for(
    class: BenchAQueryClass,
    ordinal: u32,
    by_kind: &BTreeMap<BenchAEventKind, Vec<String>>,
) -> BTreeSet<String> {
    let kind = match class {
        BenchAQueryClass::HistoricalBelief => Some(BenchAEventKind::Correction),
        BenchAQueryClass::CurrentState => Some(BenchAEventKind::PreferenceChange),
        _ => None,
    };
    kind.and_then(|kind| by_kind.get(&kind))
        .filter(|values| !values.is_empty())
        .and_then(|values| values.get(usize::try_from(ordinal).ok()? % values.len()))
        .cloned()
        .into_iter()
        .collect()
}

fn alternate_for(
    kind: BenchAEventKind,
    ordinal: u32,
    by_kind: &BTreeMap<BenchAEventKind, Vec<String>>,
) -> BTreeSet<String> {
    by_kind
        .get(&kind)
        .filter(|values| values.len() > 1)
        .and_then(|values| {
            let index = usize::try_from(ordinal).ok()? % values.len();
            values.get((index + 1) % values.len())
        })
        .cloned()
        .into_iter()
        .collect()
}

fn dataset_digest(
    manifest: &BenchAManifest,
    turns: &[BenchATurn],
    queries: &[BenchAQuery],
) -> Result<ContentDigest> {
    let bytes = serde_json::to_vec(&(manifest, turns, queries))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb-bench-a-dataset-v1\0");
    hasher.update(&bytes);
    Ok(ContentDigest::from_bytes(*hasher.finalize().as_bytes()))
}

fn ratio(numerator: u64, denominator: u64, scale: u64) -> u32 {
    if denominator == 0 {
        return u32::try_from(scale).unwrap_or(u32::MAX);
    }
    let scaled = u128::from(numerator).saturating_mul(u128::from(scale));
    u32::try_from(scaled / u128::from(denominator)).unwrap_or(u32::MAX)
}

fn percentile_95(sorted: &[u64]) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let numerator = sorted.len().saturating_mul(95).saturating_add(99);
    let rank = numerator / 100;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}
