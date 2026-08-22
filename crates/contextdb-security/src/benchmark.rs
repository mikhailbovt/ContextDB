use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{SecurityError, SecurityResult, canonical_json, digest};

/// Normative BENCH-G scenario.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchGScenario {
    /// User-private versus shared memory.
    UserPrivateVsShared,
    /// Pairwise versus team scope.
    PairwiseVsTeam,
    /// Consent revoked after derivation.
    RevokedConsent,
    /// Authorized but socially suppressed memory.
    DoNotMention,
    /// Local-only content versus external route.
    LocalOnly,
    /// Hard deletion including old snapshots.
    HardDelete,
    /// Backup lineage and post-delete restore.
    BackupLineage,
    /// Explicit redacted export subset.
    ExportSubset,
    /// Malicious prompt-injection or poisoning source.
    MaliciousSource,
}

/// Observable output compared with and without prohibited content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchGObservation {
    /// Digest of candidate identities in deterministic order.
    pub candidate_digest: String,
    /// Digest of scores/ranks in deterministic order.
    pub ranking_digest: String,
    /// Digest of the compiled summary/context output.
    pub summary_digest: String,
    /// Digest of evidence handles and selected source lineage.
    pub evidence_digest: String,
    /// Coarse deterministic latency bucket, never raw nanoseconds.
    pub latency_bucket: u64,
    /// Count of prohibited identities touched before policy.
    pub prohibited_touches: u64,
    /// Count of prohibited bytes materialized.
    pub prohibited_bytes: u64,
}

/// One controlled forbidden-influence comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchGCase {
    /// Stable case identity.
    pub case_id: String,
    /// Scenario under test.
    pub scenario: BenchGScenario,
    /// Run where the forbidden object is absent.
    pub baseline: BenchGObservation,
    /// Run where the forbidden object exists but policy rejects it.
    pub forbidden_present: BenchGObservation,
    /// Maximum permitted absolute latency-bucket delta.
    pub allowed_latency_bucket_delta: u64,
}

/// Per-case BENCH-G verdict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchGCaseResult {
    /// Stable case identity.
    pub case_id: String,
    /// Scenario.
    pub scenario: BenchGScenario,
    /// Candidate sets are identical.
    pub candidates_invariant: bool,
    /// Ranking is identical.
    pub ranking_invariant: bool,
    /// Summary/context is identical.
    pub summary_invariant: bool,
    /// Evidence lineage is identical.
    pub evidence_invariant: bool,
    /// No rejected object was touched or materialized.
    pub strict_no_touch: bool,
    /// Timing is within the declared coarse leakage budget.
    pub timing_within_budget: bool,
    /// Overall case verdict.
    pub passed: bool,
}

/// Deterministic BENCH-G report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchGReport {
    /// Report schema identifier.
    pub schema: String,
    /// Dataset/case-set digest.
    pub dataset_digest: String,
    /// Per-scenario results.
    pub cases: Vec<BenchGCaseResult>,
    /// Number of cases.
    pub total_cases: u64,
    /// Number of passing cases.
    pub passed_cases: u64,
    /// Prohibited touches across variants.
    pub prohibited_touches: u64,
    /// Prohibited bytes materialized across variants.
    pub prohibited_bytes: u64,
    /// Overall release-gate verdict.
    pub passed: bool,
}

/// Evaluates controlled absent-versus-forbidden-present pairs. Every
/// normative scenario must be represented at least once.
pub fn evaluate_bench_g(cases: &[BenchGCase]) -> SecurityResult<BenchGReport> {
    if cases.is_empty() {
        return Err(SecurityError::InvalidInput(
            "BENCH-G requires cases".to_owned(),
        ));
    }
    let mut seen = BTreeMap::<BenchGScenario, u64>::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut results = Vec::with_capacity(cases.len());
    let mut prohibited_touches = 0_u64;
    let mut prohibited_bytes = 0_u64;
    for case in cases {
        if case.case_id.trim().is_empty() || !ids.insert(case.case_id.clone()) {
            return Err(SecurityError::InvalidInput(
                "BENCH-G case IDs must be non-empty and unique".to_owned(),
            ));
        }
        *seen.entry(case.scenario).or_default() += 1;
        prohibited_touches = prohibited_touches
            .checked_add(case.forbidden_present.prohibited_touches)
            .ok_or_else(|| {
                SecurityError::ResourceExhausted("BENCH-G touch counter overflow".to_owned())
            })?;
        prohibited_bytes = prohibited_bytes
            .checked_add(case.forbidden_present.prohibited_bytes)
            .ok_or_else(|| {
                SecurityError::ResourceExhausted("BENCH-G byte counter overflow".to_owned())
            })?;
        let candidates_invariant =
            case.baseline.candidate_digest == case.forbidden_present.candidate_digest;
        let ranking_invariant =
            case.baseline.ranking_digest == case.forbidden_present.ranking_digest;
        let summary_invariant =
            case.baseline.summary_digest == case.forbidden_present.summary_digest;
        let evidence_invariant =
            case.baseline.evidence_digest == case.forbidden_present.evidence_digest;
        let strict_no_touch = case.forbidden_present.prohibited_touches == 0
            && case.forbidden_present.prohibited_bytes == 0;
        let timing_within_budget = case
            .baseline
            .latency_bucket
            .abs_diff(case.forbidden_present.latency_bucket)
            <= case.allowed_latency_bucket_delta;
        let passed = candidates_invariant
            && ranking_invariant
            && summary_invariant
            && evidence_invariant
            && strict_no_touch
            && timing_within_budget;
        results.push(BenchGCaseResult {
            case_id: case.case_id.clone(),
            scenario: case.scenario,
            candidates_invariant,
            ranking_invariant,
            summary_invariant,
            evidence_invariant,
            strict_no_touch,
            timing_within_budget,
            passed,
        });
    }
    for scenario in [
        BenchGScenario::UserPrivateVsShared,
        BenchGScenario::PairwiseVsTeam,
        BenchGScenario::RevokedConsent,
        BenchGScenario::DoNotMention,
        BenchGScenario::LocalOnly,
        BenchGScenario::HardDelete,
        BenchGScenario::BackupLineage,
        BenchGScenario::ExportSubset,
        BenchGScenario::MaliciousSource,
    ] {
        if !seen.contains_key(&scenario) {
            return Err(SecurityError::InvalidInput(format!(
                "BENCH-G is missing {scenario:?}"
            )));
        }
    }
    results.sort_unstable_by(|left, right| left.case_id.cmp(&right.case_id));
    let total_cases = u64::try_from(results.len())
        .map_err(|_| SecurityError::ResourceExhausted("BENCH-G case count overflow".to_owned()))?;
    let passed_cases = u64::try_from(results.iter().filter(|result| result.passed).count())
        .map_err(|_| SecurityError::ResourceExhausted("BENCH-G pass count overflow".to_owned()))?;
    let dataset_digest = digest(&canonical_json(cases)?);
    Ok(BenchGReport {
        schema: "contextdb.bench-g.v1".to_owned(),
        dataset_digest,
        cases: results,
        total_cases,
        passed_cases,
        prohibited_touches,
        prohibited_bytes,
        passed: passed_cases == total_cases && prohibited_touches == 0 && prohibited_bytes == 0,
    })
}

/// Runs the deterministic reference BENCH-G fixture. Each case compares an
/// identical authorized corpus with a variant containing one additional
/// policy-denied record. The policy label is evaluated before payload access.
pub fn run_reference_bench_g() -> SecurityResult<BenchGReport> {
    let scenarios = [
        BenchGScenario::UserPrivateVsShared,
        BenchGScenario::PairwiseVsTeam,
        BenchGScenario::RevokedConsent,
        BenchGScenario::DoNotMention,
        BenchGScenario::LocalOnly,
        BenchGScenario::HardDelete,
        BenchGScenario::BackupLineage,
        BenchGScenario::ExportSubset,
        BenchGScenario::MaliciousSource,
    ];
    let cases = scenarios
        .into_iter()
        .enumerate()
        .map(|(index, scenario)| {
            let allowed = FixtureRecord {
                identity: format!("allowed:{index}"),
                policy: FixturePolicy::Allowed,
                payload: format!("authorized evidence for scenario {index}"),
            };
            let forbidden = FixtureRecord {
                identity: format!("forbidden:{index}"),
                policy: FixturePolicy::Denied,
                payload: format!("prohibited unique payload {scenario:?}"),
            };
            Ok(BenchGCase {
                case_id: format!("bench-g:{index}:{scenario:?}"),
                scenario,
                baseline: execute_fixture(std::slice::from_ref(&allowed))?,
                forbidden_present: execute_fixture(&[allowed, forbidden])?,
                allowed_latency_bucket_delta: 0,
            })
        })
        .collect::<SecurityResult<Vec<_>>>()?;
    evaluate_bench_g(&cases)
}

#[derive(Clone)]
struct FixtureRecord {
    identity: String,
    policy: FixturePolicy,
    payload: String,
}

#[derive(Clone, Copy)]
enum FixturePolicy {
    Allowed,
    Denied,
}

fn execute_fixture(records: &[FixtureRecord]) -> SecurityResult<BenchGObservation> {
    let mut candidates = Vec::<(&str, String)>::new();
    let mut prohibited_touches = 0_u64;
    let mut prohibited_bytes = 0_u64;
    for record in records {
        if matches!(record.policy, FixturePolicy::Denied) {
            continue;
        }
        // Payload access is deliberately below the policy gate.
        let payload = materialize(record, &mut prohibited_touches, &mut prohibited_bytes);
        candidates.push((&record.identity, digest(payload)));
    }
    candidates.sort_unstable();
    let candidate_ids = candidates
        .iter()
        .map(|(identity, _)| *identity)
        .collect::<Vec<_>>();
    let ranking = candidates
        .iter()
        .enumerate()
        .map(|(rank, (identity, payload_digest))| (rank, *identity, payload_digest))
        .collect::<Vec<_>>();
    Ok(BenchGObservation {
        candidate_digest: digest(&canonical_json(&candidate_ids)?),
        ranking_digest: digest(&canonical_json(&ranking)?),
        summary_digest: digest(&canonical_json(&candidates)?),
        evidence_digest: digest(&canonical_json(&candidate_ids)?),
        latency_bucket: u64::try_from(candidates.len()).unwrap_or(u64::MAX),
        prohibited_touches,
        prohibited_bytes,
    })
}

fn materialize<'a>(
    record: &'a FixtureRecord,
    prohibited_touches: &mut u64,
    prohibited_bytes: &mut u64,
) -> &'a [u8] {
    if matches!(record.policy, FixturePolicy::Denied) {
        *prohibited_touches = prohibited_touches.saturating_add(1);
        *prohibited_bytes = prohibited_bytes.saturating_add(record.payload.len() as u64);
    }
    record.payload.as_bytes()
}
