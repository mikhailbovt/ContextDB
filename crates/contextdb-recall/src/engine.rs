use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, Instant},
};

use contextdb_core::{PolicyDecision, QueryContent, RecallIntent, TemporalConstraint};
use serde::Serialize;

use crate::{
    AuthorizedCorpus, BudgetUsage, CountBucket, DeterministicRecallRequest,
    DeterministicRecallResult, DocumentId, GateReason, MemoryGateDecision, MemoryUseDecision,
    PLAN_VERSION, ProviderRequest, ProviderSnapshot, RecallConflictState, RecallContinuationToken,
    RecallDepth, RecallDocument, RecallDocumentKind, RecallError, RecallItem, RecallMode,
    RecallProvider, RecallRelation, RecallRelationKind, RecallRoute, RecallStatus, RecallTrace,
    RecallTraceStep, Result, RouteContribution, ScoreBreakdown, SelectedEvidence, StopReason,
    SufficiencyReport, WorkBucket, evidence_satisfies, is_explicit_intent,
};

const RRF_K: u64 = 60;
const SCORE_SCALE: u64 = 1_000_000;

/// Deterministic planner/executor. The key authenticates opaque continuation
/// state; production hosts should supply a random, stable per-database key.
#[derive(Clone)]
pub struct RecallEngine {
    continuation_key: [u8; 32],
}

impl RecallEngine {
    /// Constructs an engine with a host-managed continuation authentication key.
    #[must_use]
    pub const fn new(continuation_key: [u8; 32]) -> Self {
        Self { continuation_key }
    }

    /// Runs recall against a single policy-filtered coherent snapshot.
    pub fn recall<P: RecallProvider>(
        &self,
        provider: &P,
        request: &DeterministicRecallRequest,
    ) -> Result<DeterministicRecallResult> {
        request.validate()?;
        let gate = memory_gate(request);
        let filter_digest = filter_digest(&self.continuation_key, request)?;
        if !gate.run_recall {
            return Ok(skipped_result(gate, filter_digest));
        }

        if let Some(token) = &request.continuation {
            self.verify_continuation_authenticator(token, &filter_digest)?;
        }

        let requested_commit = request
            .continuation
            .as_ref()
            .map(|token| token.snapshot.commit_seq)
            .or_else(|| temporal_snapshot(request));
        let snapshot = provider.snapshot(requested_commit)?;
        snapshot.validate()?;

        let prior = if let Some(token) = &request.continuation {
            self.verify_continuation(token, request, &snapshot, &filter_digest)?;
            token.consumed
        } else {
            BudgetUsage::default()
        };
        verify_budget_integrity(prior, request)?;

        let provider_request = ProviderRequest {
            snapshot: snapshot.clone(),
            principal: request.principal.clone(),
            filter_digest: filter_digest.clone(),
        };
        // Provider authorization is deliberately outside the execution clock.
        // Consequently even a pathological forbidden corpus cannot perturb a
        // permitted request's deadline bucket or explain trace.
        let corpus = provider.authorized_corpus(&provider_request)?;
        corpus.verify_binding(&provider_request)?;
        let started = Instant::now();
        let deadline = Duration::from_micros(request.deadline_micros());

        self.execute(
            request,
            gate,
            snapshot,
            filter_digest,
            corpus,
            prior,
            started,
            deadline,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the executor boundary makes every continuation and budget binding explicit"
    )]
    fn execute(
        &self,
        request: &DeterministicRecallRequest,
        gate: MemoryGateDecision,
        snapshot: ProviderSnapshot,
        filter_digest: String,
        corpus: AuthorizedCorpus,
        prior: BudgetUsage,
        started: Instant,
        deadline: Duration,
    ) -> Result<DeterministicRecallResult> {
        let query = query_text(request);
        let query_tokens = tokens(&query);
        let participant_keys = participant_keys(request);
        let mut usage = prior;
        let mut trace_steps = Vec::new();

        let remaining_nodes = request
            .max_nodes_examined()
            .saturating_sub(prior.nodes_examined) as usize;
        let mut visible = Vec::new();
        let mut hit_node_budget = false;
        for document in corpus.documents() {
            if started.elapsed() >= deadline {
                return Ok(deadline_result(
                    gate,
                    snapshot,
                    filter_digest,
                    usage,
                    trace_steps,
                ));
            }
            if visible.len() >= remaining_nodes {
                hit_node_budget = true;
                break;
            }
            usage.nodes_examined = usage.nodes_examined.saturating_add(1);
            if temporal_visible(document, request, snapshot.commit_seq)
                && perspective_visible(document, &participant_keys, &query)
            {
                visible.push(document);
            }
        }

        trace_steps.push(RecallTraceStep {
            stage: "temporal_perspective_filter".to_owned(),
            route: None,
            authorized_input: CountBucket::from_authorized(corpus.documents().len()),
            output: CountBucket::from_authorized(visible.len()),
            work: WorkBucket::from_units(u64::from(usage.nodes_examined - prior.nodes_examined)),
            selected_ids: visible.iter().map(|document| document.id.clone()).collect(),
            explanation:
                "Applied explicit temporal mode and participant perspective after authorization"
                    .to_owned(),
        });

        let (route_results, route_deadline) = build_routes(
            request,
            &gate,
            &visible,
            &query,
            &query_tokens,
            &participant_keys,
            started,
            deadline,
        );
        let mut scores = BTreeMap::<DocumentId, CandidateScore>::new();
        for (route, ranked) in route_results {
            let selected = ranked
                .iter()
                .take(request.limits.max_seed_candidates as usize)
                .cloned()
                .collect::<Vec<_>>();
            for (rank_index, (id, route_score)) in selected.iter().enumerate() {
                let rank = u32::try_from(rank_index + 1).unwrap_or(u32::MAX);
                let contribution = rrf_contribution(route, rank);
                let score = scores.entry(id.clone()).or_default();
                score.rrf_micros = score.rrf_micros.saturating_add(contribution);
                score.route_strength = score.route_strength.max(*route_score);
                score.routes.push(RouteContribution {
                    route,
                    rank,
                    rrf_micros: contribution,
                });
            }
            trace_steps.push(RecallTraceStep {
                stage: "seed_route".to_owned(),
                route: Some(route),
                authorized_input: CountBucket::from_authorized(visible.len()),
                output: CountBucket::from_authorized(selected.len()),
                work: WorkBucket::from_units(visible.len() as u64),
                selected_ids: selected.into_iter().map(|(id, _)| id).collect(),
                explanation: route_explanation(route).to_owned(),
            });
        }

        apply_modifiers(&mut scores, &visible, &query, &participant_keys, request);
        let graph_stop = if route_deadline {
            Some(StopReason::Deadline)
        } else {
            spread_activation(
                &mut scores,
                &visible,
                corpus.relations(),
                request,
                &mut usage,
                started,
                deadline,
                &mut trace_steps,
            )
        };

        let mut ranked = scores
            .into_iter()
            .filter_map(|(id, score)| {
                visible
                    .iter()
                    .find(|document| document.id == id)
                    .map(|document| RankedCandidate { document, score })
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .score
                .final_score()
                .cmp(&left.score.final_score())
                .then_with(|| left.document.id.cmp(&right.document.id))
        });

        let offset = request
            .continuation
            .as_ref()
            .map_or(0_usize, |token| token.next_offset as usize);
        if offset > ranked.len() {
            return Err(RecallError::InvalidContinuation);
        }
        if let Some(token) = &request.continuation {
            let recomputed_visited = keyed_digest_serializable(
                &self.continuation_key,
                "contextdb-recall-visited-v1",
                &ranked
                    .iter()
                    .take(offset)
                    .map(|candidate| candidate.document.id.as_str())
                    .collect::<Vec<_>>(),
            )?;
            if recomputed_visited != token.visited_digest {
                return Err(RecallError::InvalidContinuation);
            }
        }
        let prior_covered = request
            .continuation
            .as_ref()
            .map_or_else(BTreeSet::new, |token| token.covered_facet_digests.clone());
        let prior_evidence = request
            .continuation
            .as_ref()
            .map_or_else(BTreeSet::new, |token| {
                token.selected_evidence_digests.clone()
            });
        let selection = select_context(
            &ranked[offset..],
            offset,
            request,
            &gate,
            prior,
            &prior_covered,
            &prior_evidence,
            &self.continuation_key,
            &mut usage,
            started,
            deadline,
        );
        let sufficiency = assess_sufficiency(request, &gate, &selection);

        let stop_reason = if sufficiency.sufficient {
            StopReason::Sufficient
        } else if selection.deadline {
            StopReason::Deadline
        } else if selection.token_limited {
            StopReason::TokenBudget
        } else if let Some(reason) = graph_stop {
            reason
        } else if hit_node_budget {
            StopReason::NodeBudget
        } else if !sufficiency.unresolved_conflicts.is_empty()
            || !sufficiency.unsupported_documents.is_empty()
        {
            StopReason::UnknownOrConflicted
        } else {
            StopReason::NoUsefulCandidates
        };

        let has_included = selection
            .items
            .iter()
            .any(|item| item.use_decision.is_included());
        let status = if sufficiency.sufficient {
            RecallStatus::Complete
        } else if has_included {
            RecallStatus::Partial
        } else {
            RecallStatus::Unknown
        };

        let next_offset = offset.saturating_add(selection.processed);
        let more = next_offset < ranked.len();
        let continuation = if more && stop_reason == StopReason::TokenBudget {
            Some(
                self.make_continuation(
                    snapshot.clone(),
                    filter_digest.clone(),
                    next_offset,
                    usage,
                    ranked
                        .iter()
                        .take(next_offset)
                        .map(|candidate| &candidate.document.id),
                    &selection.covered_facets,
                    prior_evidence
                        .into_iter()
                        .chain(selection.evidence.iter().map(|item| {
                            sensitive_digest(&self.continuation_key, "evidence", &item.evidence.id)
                        })),
                )?,
            )
        } else {
            None
        };

        trace_steps.push(RecallTraceStep {
            stage: "sufficiency_and_use".to_owned(),
            route: None,
            authorized_input: CountBucket::from_authorized(ranked.len()),
            output: CountBucket::from_authorized(selection.items.len()),
            work: WorkBucket::from_units(selection.processed as u64),
            selected_ids: selection
                .items
                .iter()
                .map(|item| item.document_id.clone())
                .collect(),
            explanation: "Applied conflict, evidence, privacy-use, facet, and context budgets"
                .to_owned(),
        });

        let freshness_warnings = freshness_warnings(&snapshot);
        Ok(DeterministicRecallResult {
            status,
            snapshot: Some(snapshot.clone()),
            gate,
            items: selection.items,
            evidence: selection.evidence,
            sufficiency,
            stop_reason,
            usage,
            trace: RecallTrace {
                plan_version: PLAN_VERSION.to_owned(),
                filter_digest,
                snapshot: Some(snapshot),
                steps: trace_steps,
            },
            continuation,
            freshness_warnings,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "signed continuation state keeps each privacy and budget component explicit"
    )]
    fn make_continuation<'a>(
        &self,
        snapshot: ProviderSnapshot,
        filter_digest: String,
        next_offset: usize,
        consumed: BudgetUsage,
        visited: impl Iterator<Item = &'a DocumentId>,
        covered_facets: &BTreeSet<String>,
        selected_evidence_digests: impl Iterator<Item = String>,
    ) -> Result<RecallContinuationToken> {
        let visited_digest = keyed_digest_serializable(
            &self.continuation_key,
            "contextdb-recall-visited-v1",
            &visited.map(DocumentId::as_str).collect::<Vec<_>>(),
        )?;
        let next_offset = u32::try_from(next_offset).map_err(|_| {
            RecallError::InvalidRequest("continuation offset exceeds u32".to_owned())
        })?;
        let mut token = RecallContinuationToken {
            snapshot,
            plan_version: PLAN_VERSION.to_owned(),
            filter_digest,
            next_offset,
            visited_digest,
            covered_facet_digests: covered_facets
                .iter()
                .map(|facet| sensitive_digest(&self.continuation_key, "facet", facet))
                .collect(),
            selected_evidence_digests: selected_evidence_digests.collect(),
            consumed,
            binding_digest: String::new(),
        };
        token.binding_digest = self.continuation_binding(&token)?;
        Ok(token)
    }

    fn verify_continuation(
        &self,
        token: &RecallContinuationToken,
        request: &DeterministicRecallRequest,
        snapshot: &ProviderSnapshot,
        filter_digest: &str,
    ) -> Result<BudgetUsage> {
        if token.plan_version != PLAN_VERSION
            || &token.snapshot != snapshot
            || token.filter_digest != filter_digest
            || token.binding_digest != self.continuation_binding(token)?
        {
            return Err(RecallError::InvalidContinuation);
        }
        verify_budget_integrity(token.consumed, request)?;
        Ok(token.consumed)
    }

    fn verify_continuation_authenticator(
        &self,
        token: &RecallContinuationToken,
        filter_digest: &str,
    ) -> Result<()> {
        if token.plan_version != PLAN_VERSION
            || token.filter_digest != filter_digest
            || token.binding_digest != self.continuation_binding(token)?
        {
            return Err(RecallError::InvalidContinuation);
        }
        Ok(())
    }

    fn continuation_binding(&self, token: &RecallContinuationToken) -> Result<String> {
        #[derive(Serialize)]
        struct Binding<'a> {
            snapshot: &'a ProviderSnapshot,
            plan_version: &'a str,
            filter_digest: &'a str,
            next_offset: u32,
            visited_digest: &'a str,
            covered_facet_digests: &'a BTreeSet<String>,
            selected_evidence_digests: &'a BTreeSet<String>,
            consumed: BudgetUsage,
        }
        let payload = serde_json::to_vec(&Binding {
            snapshot: &token.snapshot,
            plan_version: &token.plan_version,
            filter_digest: &token.filter_digest,
            next_offset: token.next_offset,
            visited_digest: &token.visited_digest,
            covered_facet_digests: &token.covered_facet_digests,
            selected_evidence_digests: &token.selected_evidence_digests,
            consumed: token.consumed,
        })
        .map_err(|error| RecallError::InvalidRequest(error.to_string()))?;
        Ok(blake3::keyed_hash(&self.continuation_key, &payload)
            .to_hex()
            .to_string())
    }
}

impl fmt::Debug for RecallEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecallEngine")
            .field("continuation_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
struct CandidateScore {
    rrf_micros: u64,
    activation_micros: u64,
    modifier_micros: u64,
    route_strength: u64,
    routes: Vec<RouteContribution>,
}

impl CandidateScore {
    fn final_score(&self) -> u64 {
        self.rrf_micros
            .saturating_add(self.activation_micros)
            .saturating_add(self.modifier_micros)
    }

    fn breakdown(&self) -> ScoreBreakdown {
        ScoreBreakdown {
            rrf_micros: self.rrf_micros,
            activation_micros: self.activation_micros,
            modifier_micros: self.modifier_micros,
            final_micros: self.final_score(),
            routes: self.routes.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct RankedCandidate<'a> {
    document: &'a RecallDocument,
    score: CandidateScore,
}

#[derive(Debug, Default)]
struct Selection {
    items: Vec<RecallItem>,
    evidence: Vec<SelectedEvidence>,
    unresolved_conflicts: BTreeSet<String>,
    unsupported_documents: BTreeSet<DocumentId>,
    covered_facets: BTreeSet<String>,
    processed: usize,
    token_limited: bool,
    deadline: bool,
}

fn memory_gate(request: &DeterministicRecallRequest) -> MemoryGateDecision {
    let query = normalize(&query_text(request));
    let mut reasons = BTreeSet::new();
    let mut preferred = BTreeSet::new();
    let required_facets = request
        .request
        .required_facets
        .iter()
        .filter(|facet| facet.required)
        .map(|facet| normalize(&facet.name))
        .collect::<BTreeSet<_>>();

    if request.mode == RecallMode::Never {
        reasons.insert(GateReason::ModeNever);
        return MemoryGateDecision {
            run_recall: false,
            depth: RecallDepth::None,
            reasons: reasons.into_iter().collect(),
            mandatory_facets: required_facets,
            preferred_routes: Vec::new(),
        };
    }
    if matches!(request.mode, RecallMode::Required | RecallMode::Explicit) {
        reasons.insert(GateReason::RequiredByCaller);
    }
    if contains_any(
        &query,
        &[
            "remember",
            "recall",
            "memory",
            "помнишь",
            "вспомни",
            "раньше",
            "тогда",
        ],
    ) {
        reasons.insert(GateReason::ExplicitMemoryLanguage);
        preferred.insert(RecallRoute::ExactAlias);
        preferred.insert(RecallRoute::Lexical);
    }
    if contains_any(
        &query,
        &[
            "это", "этот", "эта", "там", "он", "она", "they", "it", "that",
        ],
    ) || query.split_whitespace().count() <= 3
    {
        reasons.insert(GateReason::VagueReference);
        preferred.insert(RecallRoute::ActiveContext);
    }
    if !request.request.cues.active_referents.is_empty() {
        reasons.insert(GateReason::ActiveReferent);
        preferred.insert(RecallRoute::ActiveContext);
        preferred.insert(RecallRoute::Structural);
    }
    if !request.request.cues.active_topics.is_empty() {
        reasons.insert(GateReason::ActiveTopic);
        preferred.insert(RecallRoute::ActiveContext);
        preferred.insert(RecallRoute::Structural);
    }
    if !matches!(request.request.temporal, TemporalConstraint::Current)
        || contains_any(
            &query,
            &["when", "before", "after", "когда", "раньше", "прошл"],
        )
    {
        reasons.insert(GateReason::TemporalLanguage);
        preferred.insert(RecallRoute::Temporal);
    }
    if matches!(
        request.request.intent,
        RecallIntent::HistoricalTruth | RecallIntent::Forensic
    ) || matches!(request.mode, RecallMode::Historical | RecallMode::Forensic)
    {
        reasons.insert(GateReason::HistoricalIntent);
        preferred.insert(RecallRoute::Temporal);
        preferred.insert(RecallRoute::Episodic);
    }
    if matches!(request.request.intent, RecallIntent::Relational)
        || matches!(request.mode, RecallMode::Relational)
        || contains_any(
            &query,
            &["we", "us", "our", "together", "мы", "нам", "наш", "вместе"],
        )
    {
        reasons.insert(GateReason::RelationshipIntent);
        preferred.insert(RecallRoute::Relationship);
        preferred.insert(RecallRoute::Episodic);
    }
    if request.request.evidence_policy.require_primary_evidence {
        reasons.insert(GateReason::EvidenceRequired);
    }

    let signalled = !reasons.is_empty();
    let mandatory = matches!(
        request.mode,
        RecallMode::Required
            | RecallMode::Explicit
            | RecallMode::ImplicitContinuity
            | RecallMode::Associative
            | RecallMode::Relational
            | RecallMode::Historical
            | RecallMode::Forensic
    );
    let run_recall =
        mandatory || (matches!(request.mode, RecallMode::Auto | RecallMode::Optional) && signalled);
    if !run_recall {
        reasons.insert(GateReason::SelfContained);
    }
    let depth = if !run_recall {
        RecallDepth::None
    } else if matches!(request.mode, RecallMode::Historical | RecallMode::Forensic) {
        RecallDepth::Deep
    } else if reasons.contains(&GateReason::VagueReference)
        && reasons.contains(&GateReason::ActiveReferent)
    {
        RecallDepth::Standard
    } else {
        RecallDepth::Hot
    };
    if preferred.is_empty() && run_recall {
        preferred.extend([
            RecallRoute::ExactAlias,
            RecallRoute::Lexical,
            RecallRoute::Structural,
        ]);
    }
    if request.query_vector.is_some() {
        preferred.insert(RecallRoute::SuppliedVector);
    }
    MemoryGateDecision {
        run_recall,
        depth,
        reasons: reasons.into_iter().collect(),
        mandatory_facets: required_facets,
        preferred_routes: preferred.into_iter().collect(),
    }
}

fn skipped_result(gate: MemoryGateDecision, filter_digest: String) -> DeterministicRecallResult {
    DeterministicRecallResult {
        status: RecallStatus::Skipped,
        snapshot: None,
        gate,
        items: Vec::new(),
        evidence: Vec::new(),
        sufficiency: SufficiencyReport {
            sufficient: true,
            covered_facets: BTreeSet::new(),
            missing_facets: BTreeSet::new(),
            unresolved_conflicts: BTreeSet::new(),
            unsupported_documents: BTreeSet::new(),
            confidence_micros: SCORE_SCALE as u32,
        },
        stop_reason: StopReason::GateSkipped,
        usage: BudgetUsage::default(),
        trace: RecallTrace {
            plan_version: PLAN_VERSION.to_owned(),
            filter_digest,
            snapshot: None,
            steps: vec![RecallTraceStep {
                stage: "memory_gate".to_owned(),
                route: None,
                authorized_input: CountBucket::Zero,
                output: CountBucket::Zero,
                work: WorkBucket::Constant,
                selected_ids: Vec::new(),
                explanation: "Memory gate skipped provider access".to_owned(),
            }],
        },
        continuation: None,
        freshness_warnings: Vec::new(),
    }
}

fn deadline_result(
    gate: MemoryGateDecision,
    snapshot: ProviderSnapshot,
    filter_digest: String,
    usage: BudgetUsage,
    mut steps: Vec<RecallTraceStep>,
) -> DeterministicRecallResult {
    steps.push(RecallTraceStep {
        stage: "deadline".to_owned(),
        route: None,
        authorized_input: CountBucket::Zero,
        output: CountBucket::Zero,
        work: WorkBucket::Constant,
        selected_ids: Vec::new(),
        explanation: "Execution deadline exhausted after policy authorization".to_owned(),
    });
    DeterministicRecallResult {
        status: RecallStatus::Partial,
        snapshot: Some(snapshot.clone()),
        gate,
        items: Vec::new(),
        evidence: Vec::new(),
        sufficiency: SufficiencyReport {
            sufficient: false,
            covered_facets: BTreeSet::new(),
            missing_facets: BTreeSet::new(),
            unresolved_conflicts: BTreeSet::new(),
            unsupported_documents: BTreeSet::new(),
            confidence_micros: 0,
        },
        stop_reason: StopReason::Deadline,
        usage,
        trace: RecallTrace {
            plan_version: PLAN_VERSION.to_owned(),
            filter_digest,
            snapshot: Some(snapshot.clone()),
            steps,
        },
        continuation: None,
        freshness_warnings: freshness_warnings(&snapshot),
    }
}

fn temporal_snapshot(request: &DeterministicRecallRequest) -> Option<u64> {
    match request.request.temporal {
        TemporalConstraint::KnownAt { commit_seq }
        | TemporalConstraint::Bitemporal {
            known_at: commit_seq,
            ..
        } => Some(commit_seq.get()),
        TemporalConstraint::Current | TemporalConstraint::ValidDuring { .. } => None,
    }
}

fn temporal_visible(
    document: &RecallDocument,
    request: &DeterministicRecallRequest,
    snapshot_commit: u64,
) -> bool {
    let transaction_commit = match request.request.temporal {
        TemporalConstraint::KnownAt { commit_seq }
        | TemporalConstraint::Bitemporal {
            known_at: commit_seq,
            ..
        } => commit_seq,
        TemporalConstraint::Current | TemporalConstraint::ValidDuring { .. } => {
            contextdb_core::CommitSeq::new(snapshot_commit)
        }
    };
    if !document
        .temporal
        .transaction_time
        .contains(transaction_commit)
    {
        return false;
    }
    let valid = match request.request.temporal {
        TemporalConstraint::Current => document
            .temporal
            .valid_time
            .is_none_or(|range| range.contains(request.request.cues.temporal_context.now)),
        TemporalConstraint::ValidDuring { range }
        | TemporalConstraint::Bitemporal {
            valid_during: range,
            ..
        } => document
            .temporal
            .valid_time
            .is_none_or(|document_range| document_range.overlaps(range)),
        TemporalConstraint::KnownAt { .. } => true,
    };
    if !valid {
        return false;
    }
    match (&document.conflict, request.request.intent.clone()) {
        (
            RecallConflictState::ResolvedLoser { .. } | RecallConflictState::Superseded { .. },
            RecallIntent::HistoricalTruth | RecallIntent::Forensic,
        ) => true,
        (RecallConflictState::ResolvedLoser { .. } | RecallConflictState::Superseded { .. }, _) => {
            false
        }
        _ => true,
    }
}

fn perspective_visible(
    document: &RecallDocument,
    participants: &BTreeSet<String>,
    query: &str,
) -> bool {
    let qualified_subjects = document
        .subjects
        .iter()
        .chain(&document.participants)
        .chain(document.perspective.knower.iter())
        .collect::<BTreeSet<_>>();
    if qualified_subjects.is_empty() {
        return true;
    }
    if qualified_subjects
        .iter()
        .any(|subject| participants.contains(*subject))
    {
        return true;
    }
    let query = normalize(query);
    document
        .canonical_name
        .iter()
        .chain(&document.aliases)
        .any(|name| !name.trim().is_empty() && query.contains(&normalize(name)))
}

fn query_text(request: &DeterministicRecallRequest) -> String {
    match &request.request.cues.current_input {
        QueryContent::Text(text) => text.clone(),
        QueryContent::Artifact(id) => id.to_string(),
        QueryContent::Structured(value) => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn participant_keys(request: &DeterministicRecallRequest) -> BTreeSet<String> {
    let mut values = request
        .request
        .cues
        .participants
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    values.insert(request.principal.subject.clone());
    values
}

fn normalize(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn tokens(value: &str) -> BTreeSet<String> {
    normalize(value)
        .split_whitespace()
        .filter(|token| token.chars().count() >= 2)
        .map(ToOwned::to_owned)
        .collect()
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn filter_digest(
    continuation_key: &[u8; 32],
    request: &DeterministicRecallRequest,
) -> Result<String> {
    #[derive(Serialize)]
    struct Filter<'a> {
        cues: &'a contextdb_core::CueBundle,
        intent: &'a RecallIntent,
        scopes: &'a contextdb_core::NonEmptyVec<contextdb_core::ScopeRef>,
        temporal: &'a TemporalConstraint,
        required_facets: &'a [contextdb_core::FacetRequirement],
        evidence_policy: contextdb_core::EvidencePolicy,
        memory_use_policy: contextdb_core::PolicyId,
        purpose: &'a contextdb_core::Purpose,
        target_model: Option<contextdb_core::ModelProfileId>,
        principal: &'a crate::RecallPrincipal,
        mode: RecallMode,
        query_vector: &'a Option<crate::SuppliedVector>,
        plan_version: &'static str,
    }
    keyed_digest_serializable(
        continuation_key,
        "contextdb-recall-filter-v1",
        &Filter {
            cues: &request.request.cues,
            intent: &request.request.intent,
            scopes: &request.request.scopes,
            temporal: &request.request.temporal,
            required_facets: &request.request.required_facets,
            evidence_policy: request.request.evidence_policy,
            memory_use_policy: request.request.memory_use_policy,
            purpose: &request.request.purpose,
            target_model: request.request.target_model,
            principal: &request.principal,
            mode: request.mode,
            query_vector: &request.query_vector,
            plan_version: PLAN_VERSION,
        },
    )
}

fn keyed_digest_serializable<T: Serialize + ?Sized>(
    key: &[u8; 32],
    domain: &str,
    value: &T,
) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| RecallError::InvalidRequest(error.to_string()))?;
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn sensitive_digest(key: &[u8; 32], domain: &str, value: &str) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"contextdb-recall-sensitive-v1");
    hasher.update(&[0]);
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(value.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn verify_budget_integrity(
    consumed: BudgetUsage,
    request: &DeterministicRecallRequest,
) -> Result<()> {
    if consumed.nodes_examined > request.max_nodes_examined()
        || consumed.graph_edges_examined > request.request.budgets.max_graph_visits
        || consumed.max_hop_reached > request.limits.max_graph_hops
        || consumed.evidence_units > request.max_evidence_units()
        || consumed.context_tokens > request.max_context_tokens()
    {
        return Err(RecallError::InvalidContinuation);
    }
    Ok(())
}

fn freshness_warnings(snapshot: &ProviderSnapshot) -> Vec<String> {
    let mut warnings = Vec::new();
    for (name, watermark) in [
        ("semantic", snapshot.watermarks.semantic),
        ("lexical", snapshot.watermarks.lexical),
        ("graph", snapshot.watermarks.graph),
    ] {
        if watermark < snapshot.commit_seq {
            warnings.push(format!("{name} projection lags snapshot"));
        }
    }
    for (space, watermark) in &snapshot.watermarks.vector {
        if *watermark < snapshot.commit_seq {
            warnings.push(format!("vector projection {space} lags snapshot"));
        }
    }
    warnings.sort();
    warnings
}

type RouteRanking = Vec<(DocumentId, u64)>;

#[allow(
    clippy::too_many_arguments,
    reason = "route planning keeps authorization-filtered cues and cooperative deadline explicit"
)]
fn build_routes(
    request: &DeterministicRecallRequest,
    gate: &MemoryGateDecision,
    documents: &[&RecallDocument],
    query: &str,
    query_tokens: &BTreeSet<String>,
    participants: &BTreeSet<String>,
    started: Instant,
    deadline: Duration,
) -> (Vec<(RecallRoute, RouteRanking)>, bool) {
    let active_ids = active_ids(request);
    let active_surfaces = request
        .request
        .cues
        .active_referents
        .iter()
        .map(|referent| normalize(&referent.surface))
        .collect::<BTreeSet<_>>();
    let required_facets = &gate.mandatory_facets;
    let normalized_query = normalize(query);

    let mut routes = BTreeMap::<RecallRoute, RouteRanking>::new();
    for route in [
        RecallRoute::ActiveContext,
        RecallRoute::ExactAlias,
        RecallRoute::Relationship,
        RecallRoute::Episodic,
        RecallRoute::Temporal,
        RecallRoute::Structural,
        RecallRoute::Lexical,
        RecallRoute::SuppliedVector,
    ] {
        routes.insert(route, Vec::new());
    }

    let mut deadline_reached = false;
    for document in documents {
        if started.elapsed() >= deadline {
            deadline_reached = true;
            break;
        }
        let names = document
            .canonical_name
            .iter()
            .chain(&document.aliases)
            .map(|value| normalize(value))
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();

        let active_match = document
            .active_keys
            .iter()
            .any(|key| active_ids.contains(key))
            || active_ids.contains(document.id.as_str())
            || names.iter().any(|name| active_surfaces.contains(name));
        if active_match {
            push_route(
                &mut routes,
                RecallRoute::ActiveContext,
                &document.id,
                if active_ids.contains(document.id.as_str()) {
                    SCORE_SCALE
                } else {
                    800_000
                },
            );
        }

        let exact_strength = names
            .iter()
            .map(|name| {
                if &normalized_query == name {
                    SCORE_SCALE
                } else if !name.is_empty() && normalized_query.contains(name) {
                    900_000
                } else if !normalized_query.is_empty() && name.contains(&normalized_query) {
                    700_000
                } else {
                    0
                }
            })
            .max()
            .unwrap_or(0);
        if exact_strength > 0 {
            push_route(
                &mut routes,
                RecallRoute::ExactAlias,
                &document.id,
                exact_strength,
            );
        }

        if matches!(
            document.kind,
            RecallDocumentKind::Relationship | RecallDocumentKind::SharedReference
        ) {
            let overlap = document
                .participants
                .iter()
                .filter(|participant| participants.contains(*participant))
                .count();
            if overlap > 0 || active_match {
                let strength = if overlap >= 2 { SCORE_SCALE } else { 750_000 };
                push_route(
                    &mut routes,
                    RecallRoute::Relationship,
                    &document.id,
                    strength,
                );
            }
        }

        if matches!(
            document.kind,
            RecallDocumentKind::Episode | RecallDocumentKind::Observation
        ) {
            let participant = document
                .participants
                .iter()
                .any(|subject| participants.contains(subject));
            let lexical = overlap_count(query_tokens, &document_tokens(document));
            if participant || lexical > 0 || active_match {
                push_route(
                    &mut routes,
                    RecallRoute::Episodic,
                    &document.id,
                    if participant && lexical > 0 {
                        SCORE_SCALE
                    } else {
                        700_000
                    },
                );
            }
        }

        let temporal_strength = match request.request.temporal {
            TemporalConstraint::Current => document.temporal.valid_time.map_or(0, |range| {
                if range.contains(request.request.cues.temporal_context.now) {
                    700_000
                } else {
                    0
                }
            }),
            TemporalConstraint::ValidDuring { range }
            | TemporalConstraint::Bitemporal {
                valid_during: range,
                ..
            } => document
                .temporal
                .valid_time
                .map_or(500_000, |document_range| {
                    if document_range.overlaps(range) {
                        SCORE_SCALE
                    } else {
                        0
                    }
                }),
            TemporalConstraint::KnownAt { .. } => 600_000,
        };
        if temporal_strength > 0 {
            push_route(
                &mut routes,
                RecallRoute::Temporal,
                &document.id,
                temporal_strength,
            );
        }

        let facet_overlap = document
            .facets
            .iter()
            .map(|facet| normalize(facet))
            .filter(|facet| required_facets.contains(facet))
            .count();
        let key_overlap = document
            .active_keys
            .iter()
            .filter(|key| active_ids.contains(*key))
            .count();
        if facet_overlap > 0 || key_overlap > 0 {
            let numerator = (facet_overlap + key_overlap).min(4) as u64;
            push_route(
                &mut routes,
                RecallRoute::Structural,
                &document.id,
                500_000_u64.saturating_add(numerator.saturating_mul(125_000)),
            );
        }

        let document_tokens = document_tokens(document);
        let overlap = overlap_count(query_tokens, &document_tokens);
        if overlap > 0 && !query_tokens.is_empty() {
            let strength = (overlap as u64).saturating_mul(SCORE_SCALE) / query_tokens.len() as u64;
            push_route(&mut routes, RecallRoute::Lexical, &document.id, strength);
        }

        if let (Some(query_vector), Some(document_vector)) =
            (&request.query_vector, &document.vector)
            && query_vector.space == document_vector.space
            && query_vector.values.len() == document_vector.values.len()
            && let Some(strength) = cosine_strength(&query_vector.values, &document_vector.values)
        {
            push_route(
                &mut routes,
                RecallRoute::SuppliedVector,
                &document.id,
                strength,
            );
        }
        if started.elapsed() >= deadline {
            deadline_reached = true;
            break;
        }
    }

    (
        routes
            .into_iter()
            .map(|(route, mut ranking)| {
                ranking
                    .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
                (route, ranking)
            })
            .collect(),
        deadline_reached,
    )
}

fn push_route(
    routes: &mut BTreeMap<RecallRoute, RouteRanking>,
    route: RecallRoute,
    id: &DocumentId,
    strength: u64,
) {
    if strength > 0 {
        routes
            .entry(route)
            .or_default()
            .push((id.clone(), strength));
    }
}

fn active_ids(request: &DeterministicRecallRequest) -> BTreeSet<String> {
    let mut ids = request
        .request
        .cues
        .active_topics
        .iter()
        .chain(&request.request.cues.interaction_signals)
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    ids.extend(
        request
            .request
            .cues
            .recent_observations
            .iter()
            .map(ToString::to_string),
    );
    if let Some(location) = request.request.cues.location_context {
        ids.insert(location.to_string());
    }
    for referent in &request.request.cues.active_referents {
        ids.extend(
            referent
                .candidates
                .iter()
                .map(|candidate| candidate.node_id.to_string()),
        );
        if let Some(resolved) = referent.resolved {
            ids.insert(resolved.to_string());
        }
    }
    ids
}

fn document_tokens(document: &RecallDocument) -> BTreeSet<String> {
    let mut values = tokens(&document.text);
    if let Some(name) = &document.canonical_name {
        values.extend(tokens(name));
    }
    for alias in &document.aliases {
        values.extend(tokens(alias));
    }
    for facet in &document.facets {
        values.extend(tokens(facet));
    }
    values
}

fn overlap_count(left: &BTreeSet<String>, right: &BTreeSet<String>) -> usize {
    left.intersection(right).count()
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "finite cosine is clamped to the fixed-point scoring interval"
)]
fn cosine_strength(left: &[f32], right: &[f32]) -> Option<u64> {
    let dot = left
        .iter()
        .zip(right)
        .map(|(left, right)| f64::from(*left) * f64::from(*right))
        .sum::<f64>();
    let left_norm = left
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    let right_norm = right
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    if left_norm == 0.0 || right_norm == 0.0 {
        return None;
    }
    let cosine = (dot / (left_norm * right_norm)).clamp(-1.0, 1.0);
    if cosine <= 0.0 {
        None
    } else {
        Some((cosine * SCORE_SCALE as f64).round() as u64)
    }
}

fn route_weight(route: RecallRoute) -> u64 {
    match route {
        RecallRoute::ActiveContext => 1_300,
        RecallRoute::ExactAlias => 1_250,
        RecallRoute::Relationship => 1_150,
        RecallRoute::Episodic => 1_050,
        RecallRoute::Temporal => 950,
        RecallRoute::Structural => 900,
        RecallRoute::Lexical => 800,
        RecallRoute::SuppliedVector => 850,
    }
}

fn rrf_contribution(route: RecallRoute, rank: u32) -> u64 {
    route_weight(route).saturating_mul(SCORE_SCALE) / RRF_K.saturating_add(u64::from(rank))
}

fn route_explanation(route: RecallRoute) -> &'static str {
    match route {
        RecallRoute::ActiveContext => {
            "Matched authorized active referents, topics, participants, or observations"
        }
        RecallRoute::ExactAlias => "Matched an authorized canonical name or alias",
        RecallRoute::Relationship => {
            "Matched an authorized relationship/shared-reference perspective"
        }
        RecallRoute::Episodic => "Matched an authorized episode or observation cue",
        RecallRoute::Temporal => "Matched the explicit valid/system-time constraint",
        RecallRoute::Structural => "Matched required facets or active structural keys",
        RecallRoute::Lexical => "Matched normalized query tokens in authorized text",
        RecallRoute::SuppliedVector => {
            "Matched a caller-supplied vector in the same declared space"
        }
    }
}

fn apply_modifiers(
    scores: &mut BTreeMap<DocumentId, CandidateScore>,
    documents: &[&RecallDocument],
    query: &str,
    participants: &BTreeSet<String>,
    request: &DeterministicRecallRequest,
) {
    let normalized_query = normalize(query);
    for (id, score) in scores {
        let Some(document) = documents.iter().find(|document| document.id == *id) else {
            continue;
        };
        let exact = document
            .canonical_name
            .iter()
            .chain(&document.aliases)
            .any(|name| normalize(name) == normalized_query);
        let participant_match = document
            .subjects
            .iter()
            .chain(&document.participants)
            .any(|subject| participants.contains(subject));
        let temporal_match = document
            .temporal
            .valid_time
            .is_none_or(|range| range.contains(request.request.cues.temporal_context.now));
        let trust = quantize_unit(document.source_trust);
        let importance = quantize_unit(document.importance);
        score.modifier_micros = score
            .modifier_micros
            .saturating_add(trust / 2)
            .saturating_add(importance / 3)
            .saturating_add(score.route_strength / 5)
            .saturating_add(if exact { 500_000 } else { 0 })
            .saturating_add(if participant_match { 300_000 } else { 0 })
            .saturating_add(if temporal_match { 150_000 } else { 0 });
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "validated unit values are clamped before fixed-point conversion"
)]
fn quantize_unit(value: f32) -> u64 {
    (f64::from(value.clamp(0.0, 1.0)) * SCORE_SCALE as f64).round() as u64
}

#[allow(
    clippy::too_many_arguments,
    reason = "graph execution receives every strict budget and trace accumulator explicitly"
)]
fn spread_activation(
    scores: &mut BTreeMap<DocumentId, CandidateScore>,
    documents: &[&RecallDocument],
    relations: &[RecallRelation],
    request: &DeterministicRecallRequest,
    usage: &mut BudgetUsage,
    started: Instant,
    deadline: Duration,
    trace: &mut Vec<RecallTraceStep>,
) -> Option<StopReason> {
    if scores.is_empty() || relations.is_empty() {
        return None;
    }
    let allowed = documents
        .iter()
        .map(|document| document.id.clone())
        .collect::<BTreeSet<_>>();
    let mut adjacency = BTreeMap::<DocumentId, Vec<&RecallRelation>>::new();
    for relation in relations {
        if allowed.contains(&relation.source) && allowed.contains(&relation.target) {
            adjacency
                .entry(relation.source.clone())
                .or_default()
                .push(relation);
            adjacency
                .entry(relation.target.clone())
                .or_default()
                .push(relation);
        }
    }
    for edges in adjacency.values_mut() {
        edges.sort_by(|left, right| left.id.cmp(&right.id));
    }

    let max_graph = request.request.budgets.max_graph_visits;
    let max_hops = request.limits.max_graph_hops;
    let frontier_limit = request.limits.max_frontier_per_hop as usize;
    let mut frontier = scores
        .iter()
        .map(|(id, score)| (id.clone(), score.final_score()))
        .collect::<Vec<_>>();
    sort_frontier(&mut frontier);
    frontier.truncate(frontier_limit);
    let mut visited = frontier
        .iter()
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let mut stop = None;

    for hop in 1..=max_hops {
        if frontier.is_empty() {
            break;
        }
        if started.elapsed() >= deadline {
            stop = Some(StopReason::Deadline);
            break;
        }
        usage.max_hop_reached = usage.max_hop_reached.max(hop);
        let mut next = BTreeMap::<DocumentId, u64>::new();
        for (source, source_activation) in &frontier {
            let Some(edges) = adjacency.get(source) else {
                continue;
            };
            for relation in edges {
                if usage.graph_edges_examined >= max_graph {
                    stop = Some(StopReason::GraphBudget);
                    break;
                }
                if started.elapsed() >= deadline {
                    stop = Some(StopReason::Deadline);
                    break;
                }
                usage.graph_edges_examined = usage.graph_edges_examined.saturating_add(1);
                if !relation_temporal_visible(relation, request) {
                    continue;
                }
                let neighbour = if relation.source == *source {
                    &relation.target
                } else {
                    &relation.source
                };
                if visited.contains(neighbour) {
                    continue;
                }
                let type_weight = relation_weight(&relation.kind, &request.request.intent);
                if type_weight == 0 {
                    continue;
                }
                let relation_weight = quantize_unit(relation.weight);
                let trust = quantize_unit(relation.trust);
                let decay = fixed_decay(700_000, hop);
                let contribution = fixed_product(&[
                    (*source_activation).min(100_000_000),
                    type_weight,
                    relation_weight,
                    trust,
                    decay,
                ]);
                if contribution < 10_000 {
                    continue;
                }
                next.entry(neighbour.clone())
                    .and_modify(|value| *value = value.saturating_add(contribution))
                    .or_insert(contribution);
            }
            if stop.is_some() {
                break;
            }
        }
        let mut next_frontier = next.into_iter().collect::<Vec<_>>();
        sort_frontier(&mut next_frontier);
        next_frontier.truncate(frontier_limit);
        for (id, activation) in &next_frontier {
            let score = scores.entry(id.clone()).or_default();
            score.activation_micros = score.activation_micros.saturating_add(*activation);
            visited.insert(id.clone());
        }
        trace.push(RecallTraceStep {
            stage: format!("typed_activation_hop_{hop}"),
            route: None,
            authorized_input: CountBucket::from_authorized(frontier.len()),
            output: CountBucket::from_authorized(next_frontier.len()),
            work: WorkBucket::from_units(u64::from(usage.graph_edges_examined)),
            selected_ids: next_frontier.iter().map(|(id, _)| id.clone()).collect(),
            explanation: "Spread activation only over typed, authorized endpoints with trust and temporal constraints"
                .to_owned(),
        });
        frontier = next_frontier;
        if stop.is_some() {
            break;
        }
        if hop == max_hops && !frontier.is_empty() {
            stop = Some(StopReason::HopBudget);
        }
    }
    stop
}

fn sort_frontier(frontier: &mut [(DocumentId, u64)]) {
    frontier.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
}

fn relation_weight(kind: &RecallRelationKind, intent: &RecallIntent) -> u64 {
    use RecallRelationKind as Kind;
    let base: u64 = match kind {
        Kind::Contains | Kind::PartOf | Kind::HierarchyParent => 650_000,
        Kind::About | Kind::RelatedTo | Kind::SimilarTo => 600_000,
        Kind::Supports | Kind::Refines | Kind::VerifiedBy | Kind::LearnedFrom => 800_000,
        Kind::OccurredIn | Kind::ParticipantIn | Kind::PrecededBy | Kind::FollowedBy => 750_000,
        Kind::Triggered | Kind::ResultedIn | Kind::MotivatedBy | Kind::CausedBy => 700_000,
        Kind::Supersedes | Kind::CorrectedBy => 850_000,
        Kind::Contradicts => 300_000,
        Kind::SharedWith | Kind::SharedHistory | Kind::RunningJoke => 900_000,
        Kind::HasBoundary | Kind::CommittedTo | Kind::Requires => 850_000,
        Kind::Domain(_) => 550_000,
    };
    let boost: u64 = match intent {
        RecallIntent::Relational
            if matches!(
                kind,
                Kind::SharedWith | Kind::SharedHistory | Kind::RunningJoke | Kind::RelatedTo
            ) =>
        {
            200_000
        }
        RecallIntent::HistoricalTruth | RecallIntent::Forensic
            if matches!(
                kind,
                Kind::OccurredIn
                    | Kind::PrecededBy
                    | Kind::FollowedBy
                    | Kind::Supersedes
                    | Kind::CorrectedBy
                    | Kind::Contradicts
            ) =>
        {
            150_000
        }
        RecallIntent::Procedural
            if matches!(kind, Kind::Requires | Kind::VerifiedBy | Kind::LearnedFrom) =>
        {
            150_000
        }
        _ => 0,
    };
    base.saturating_add(boost).min(SCORE_SCALE)
}

fn fixed_product(values: &[u64]) -> u64 {
    let mut result = u128::from(values[0]);
    for value in &values[1..] {
        result = result.saturating_mul(u128::from(*value)) / u128::from(SCORE_SCALE);
    }
    u64::try_from(result).unwrap_or(u64::MAX)
}

fn relation_temporal_visible(
    relation: &RecallRelation,
    request: &DeterministicRecallRequest,
) -> bool {
    let Some(valid) = relation.valid_time else {
        return true;
    };
    match request.request.temporal {
        TemporalConstraint::Current => valid.contains(request.request.cues.temporal_context.now),
        TemporalConstraint::KnownAt { .. } => true,
        TemporalConstraint::ValidDuring { range }
        | TemporalConstraint::Bitemporal {
            valid_during: range,
            ..
        } => valid.overlaps(range),
    }
}

fn fixed_decay(factor: u64, exponent: u8) -> u64 {
    let mut value = SCORE_SCALE;
    for _ in 0..exponent {
        value = value.saturating_mul(factor) / SCORE_SCALE;
    }
    value
}

#[allow(
    clippy::too_many_arguments,
    reason = "selection explicitly receives every policy and budget input"
)]
fn select_context(
    ranked: &[RankedCandidate<'_>],
    _offset: usize,
    request: &DeterministicRecallRequest,
    gate: &MemoryGateDecision,
    prior: BudgetUsage,
    prior_covered_digests: &BTreeSet<String>,
    prior_evidence_digests: &BTreeSet<String>,
    continuation_key: &[u8; 32],
    usage: &mut BudgetUsage,
    started: Instant,
    deadline: Duration,
) -> Selection {
    let mut selection = Selection::default();
    selection.covered_facets.extend(
        gate.mandatory_facets
            .iter()
            .filter(|facet| {
                prior_covered_digests.contains(&sensitive_digest(continuation_key, "facet", facet))
            })
            .cloned(),
    );
    let mut used_evidence_digests = prior_evidence_digests.clone();
    let max_evidence = request.max_evidence_units();
    let max_tokens = request.max_context_tokens();

    for candidate in ranked {
        if started.elapsed() >= deadline {
            selection.deadline = true;
            break;
        }
        let document = candidate.document;
        let mut decision = memory_use_decision(document, request);
        if let Some(set_id) = document.conflict.set_id()
            && matches!(document.conflict, RecallConflictState::Unresolved { .. })
        {
            selection.unresolved_conflicts.insert(set_id.to_owned());
            decision = MemoryUseDecision::WithholdDueToUncertainty;
        }

        let evidence_supported =
            evidence_satisfies(request.request.evidence_policy, &document.evidence);
        if !evidence_supported && requires_evidence(document.kind) {
            selection.unsupported_documents.insert(document.id.clone());
            decision = MemoryUseDecision::WithholdDueToUncertainty;
        }

        let mut selected_evidence = if decision.is_included() {
            choose_evidence(document, request)
        } else {
            Vec::new()
        };
        selected_evidence.retain(|evidence| {
            !used_evidence_digests.contains(&sensitive_digest(
                continuation_key,
                "evidence",
                &evidence.id,
            ))
        });
        let new_evidence_count = u32::try_from(selected_evidence.len()).unwrap_or(u32::MAX);
        if usage.evidence_units.saturating_add(new_evidence_count) > max_evidence {
            selected_evidence.clear();
            if request.request.evidence_policy.require_primary_evidence
                || !request.request.evidence_policy.permit_derived_only
            {
                decision = MemoryUseDecision::WithholdDueToUncertainty;
                selection.unsupported_documents.insert(document.id.clone());
            }
        }
        for evidence in &selected_evidence {
            used_evidence_digests.insert(sensitive_digest(
                continuation_key,
                "evidence",
                &evidence.id,
            ));
        }
        let evidence_tokens = selected_evidence
            .iter()
            .map(|evidence| evidence.estimated_tokens)
            .sum::<u32>();
        let context_cost = if decision.is_included() {
            document.estimated_tokens.saturating_add(evidence_tokens)
        } else {
            0
        };
        if usage.context_tokens.saturating_add(context_cost) > max_tokens {
            selection.token_limited = true;
            break;
        }

        selection.processed = selection.processed.saturating_add(1);
        if decision.is_included() {
            usage.context_tokens = usage.context_tokens.saturating_add(context_cost);
            usage.evidence_units = usage.evidence_units.saturating_add(new_evidence_count);
            selection.covered_facets.extend(
                document
                    .facets
                    .iter()
                    .map(|facet| normalize(facet))
                    .filter(|facet| {
                        !facet.is_empty() && facet_meets_confidence(facet, document, request)
                    }),
            );
            selection
                .evidence
                .extend(selected_evidence.into_iter().map(|mut evidence| {
                    if !request.request.evidence_policy.include_quotes {
                        evidence.excerpt = None;
                    }
                    SelectedEvidence {
                        document_id: document.id.clone(),
                        evidence,
                    }
                }));
        }
        selection.items.push(RecallItem {
            document_id: document.id.clone(),
            kind: document.kind,
            content: decision.is_included().then(|| document.text.clone()),
            score: candidate.score.breakdown(),
            covered_facets: document
                .facets
                .iter()
                .map(|facet| normalize(facet))
                .collect(),
            use_decision: decision,
            estimated_tokens: context_cost,
        });

        if mandatory_covered(gate, &selection.covered_facets)
            && selection.unresolved_conflicts.is_empty()
            && selection.unsupported_documents.is_empty()
            && selection
                .items
                .iter()
                .any(|item| item.use_decision.is_included())
        {
            break;
        }
    }

    // The caller-provided prior state remains part of the authenticated total.
    debug_assert!(usage.context_tokens >= prior.context_tokens);
    selection
}

fn choose_evidence(
    document: &RecallDocument,
    request: &DeterministicRecallRequest,
) -> Vec<crate::RecallEvidence> {
    let mut evidence = document.evidence.clone();
    evidence.sort_by(|left, right| {
        right
            .primary
            .cmp(&left.primary)
            .then_with(|| right.trust.total_cmp(&left.trust))
            .then_with(|| left.estimated_tokens.cmp(&right.estimated_tokens))
            .then_with(|| left.id.cmp(&right.id))
    });
    if request.request.evidence_policy.require_primary_evidence {
        evidence.retain(|item| item.primary);
    }
    // Greedy minimal support: one best unit per selected document. Wider raw
    // evidence is a continuation/deep-recall concern.
    evidence.truncate(1);
    evidence
}

fn requires_evidence(kind: RecallDocumentKind) -> bool {
    !matches!(
        kind,
        RecallDocumentKind::Entity | RecallDocumentKind::Domain
    )
}

fn memory_use_decision(
    document: &RecallDocument,
    request: &DeterministicRecallRequest,
) -> MemoryUseDecision {
    let profile = document.use_profile;
    if profile.influence == PolicyDecision::Deny
        || request.request.target_model.is_some()
            && profile.external_model_use != PolicyDecision::Allow
    {
        return MemoryUseDecision::WithholdDueToPrivacy;
    }
    if profile.influence == PolicyDecision::Conditional {
        return MemoryUseDecision::WithholdDueToUncertainty;
    }
    if profile.personal_detail
        && !profile.shared_with_principal
        && !is_explicit_intent(&request.request.intent, request.mode)
    {
        return MemoryUseDecision::WithholdDueToPrivacy;
    }
    if profile.constraint_only {
        return MemoryUseDecision::IncludeOnlyAsConstraint;
    }
    if profile.style_only {
        return MemoryUseDecision::IncludeOnlyAsStyleSignal;
    }
    if profile.mention == PolicyDecision::Allow
        && is_explicit_intent(&request.request.intent, request.mode)
    {
        MemoryUseDecision::IncludeAndMention
    } else {
        MemoryUseDecision::IncludeSilently
    }
}

fn mandatory_covered(required: &MemoryGateDecision, covered: &BTreeSet<String>) -> bool {
    required.mandatory_facets.is_subset(covered)
}

fn facet_meets_confidence(
    normalized_facet: &str,
    document: &RecallDocument,
    request: &DeterministicRecallRequest,
) -> bool {
    request
        .request
        .required_facets
        .iter()
        .filter(|requirement| normalize(&requirement.name) == normalized_facet)
        .all(|requirement| document.source_trust >= requirement.minimum_confidence)
}

fn assess_sufficiency(
    request: &DeterministicRecallRequest,
    gate: &MemoryGateDecision,
    selection: &Selection,
) -> SufficiencyReport {
    let missing_facets = gate
        .mandatory_facets
        .difference(&selection.covered_facets)
        .cloned()
        .collect::<BTreeSet<_>>();
    let has_included = selection
        .items
        .iter()
        .any(|item| item.use_decision.is_included());
    let sufficient = missing_facets.is_empty()
        && selection.unresolved_conflicts.is_empty()
        && selection.unsupported_documents.is_empty()
        && has_included;
    let facet_confidence = if gate.mandatory_facets.is_empty() {
        if has_included { SCORE_SCALE } else { 0 }
    } else {
        let covered = gate
            .mandatory_facets
            .intersection(&selection.covered_facets)
            .count() as u64;
        covered.saturating_mul(SCORE_SCALE) / gate.mandatory_facets.len() as u64
    };
    let evidence_penalty = if request.request.evidence_policy.require_primary_evidence
        && !selection.unsupported_documents.is_empty()
    {
        400_000
    } else {
        0
    };
    let conflict_penalty = if selection.unresolved_conflicts.is_empty() {
        0
    } else {
        500_000
    };
    SufficiencyReport {
        sufficient,
        covered_facets: selection.covered_facets.clone(),
        missing_facets,
        unresolved_conflicts: selection.unresolved_conflicts.clone(),
        unsupported_documents: selection.unsupported_documents.clone(),
        confidence_micros: u32::try_from(
            facet_confidence.saturating_sub(evidence_penalty + conflict_penalty),
        )
        .unwrap_or(u32::MAX),
    }
}
