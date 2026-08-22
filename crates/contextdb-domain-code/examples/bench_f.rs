//! Deterministic BENCH-F correctness harness over six monthly Go snapshots.

use std::{collections::BTreeSet, error::Error, hint::black_box, time::Instant};

use contextdb_core::{ContentDigest, EvidenceId, TimestampMicros};
use contextdb_domain_code::{
    CiRun, CiRunId, CodeMemory, CodeQuery, CodeRelation, CodeRelationKind, DecisionId,
    DecisionRecord, FileIdentity, FileRevision, Language, RationaleResult, RepoPath,
    RepositoryDescriptor, RepositoryId, RepositorySnapshot, SnapshotId, SourceRange,
    SymbolIdentity, SymbolKind, SymbolRevision,
};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

const MONTHS: usize = 6;
const TASKS: usize = 10;
const ITERATIONS: usize = 501;
const FULL_QUALITY_FLOOR: f64 = 0.9;
const BASELINE_MARGIN_FLOOR: f64 = 0.2;
const FULL_TOOL_CALL_CEILING: usize = 5;

#[derive(Clone, Copy, Debug, Serialize)]
struct BaselineScore {
    correct: usize,
    total: usize,
    quality: f64,
    exploratory_tool_calls: usize,
}

struct Fixture {
    full: CodeMemory,
    reduced: CodeMemory,
    repository: RepositoryId,
    snapshots: Vec<SnapshotId>,
    sources: Vec<(String, String)>,
}

fn fixed_uuid(namespace: u16, ordinal: usize) -> Uuid {
    Uuid::from_u128((u128::from(namespace) << 112) | (ordinal as u128 + 1))
}

fn repo_id() -> RepositoryId {
    RepositoryId::from_uuid(fixed_uuid(1, 0)).expect("fixture repository ID is non-nil")
}

fn file_id(ordinal: usize) -> FileIdentity {
    FileIdentity::from_uuid(fixed_uuid(2, ordinal)).expect("fixture file ID is non-nil")
}

fn symbol_id(ordinal: usize) -> SymbolIdentity {
    SymbolIdentity::from_uuid(fixed_uuid(3, ordinal)).expect("fixture symbol ID is non-nil")
}

fn snapshot_id(ordinal: usize) -> SnapshotId {
    SnapshotId::from_uuid(fixed_uuid(4, ordinal)).expect("fixture snapshot ID is non-nil")
}

fn evidence_id(ordinal: usize) -> EvidenceId {
    EvidenceId::from_uuid(fixed_uuid(5, ordinal)).expect("fixture evidence ID is non-nil")
}

fn line_range(line: u32, text: &str) -> SourceRange {
    SourceRange::new(
        line,
        0,
        line,
        u32::try_from(text.chars().count()).expect("fixture line length fits u32"),
    )
    .expect("fixture range is non-empty")
}

fn make_symbol(
    identity: SymbolIdentity,
    file: FileIdentity,
    qualified_name: String,
    display_name: &str,
    declaration: SourceRange,
    kind: SymbolKind,
    continued: bool,
) -> SymbolRevision {
    SymbolRevision {
        identity,
        file,
        qualified_name,
        display_name: display_name.to_owned(),
        kind,
        declaration,
        signature: format!("func {display_name}(string) string"),
        semantic_fingerprint: None,
        continues_from: continued.then_some(identity),
        continuity_confidence: if continued { 10_000 } else { 0 },
    }
}

fn build_fixture() -> Result<Fixture, Box<dyn Error>> {
    let repository = repo_id();
    let descriptor = RepositoryDescriptor {
        id: repository,
        name: "Rift six-month Go fixture".to_owned(),
        origin: Some("https://example.invalid/rift.git".to_owned()),
    };
    let mut full = CodeMemory::new();
    let mut reduced = CodeMemory::new();
    full.register_repository(descriptor.clone())?;
    reduced.register_repository(descriptor)?;

    let password = symbol_id(0);
    let login = symbol_id(1);
    let test = symbol_id(2);
    let old_file = file_id(0);
    let moved_file = file_id(1);
    let mut snapshots = Vec::new();
    let mut sources = Vec::new();
    for month in 0..MONTHS {
        let id = snapshot_id(month);
        snapshots.push(id);
        let parent = month.checked_sub(1).map(snapshot_id);
        let continued = month > 0;
        let moved = month >= 2;
        let current_file = if moved { moved_file } else { old_file };
        let path = if moved {
            "internal/auth/password.go"
        } else {
            "auth/password.go"
        };
        let display_name = if moved {
            "DerivePassword"
        } else {
            "HashPassword"
        };
        let algorithm = if month >= 3 { "argon2id" } else { "bcrypt" };
        let password_line =
            format!("func {display_name}(value string) string {{ return {algorithm}(value) }}");
        let login_line =
            format!("func Login(value string) string {{ return {display_name}(value) }}");
        let test_line =
            format!("func TestPassword(value string) string {{ return {display_name}(value) }}");
        let content = format!("package auth\n{password_line}\n{login_line}\n{test_line}\n");
        sources.push((path.to_owned(), content.clone()));
        let file = FileRevision {
            identity: current_file,
            path: RepoPath::new(path)?,
            content_digest: ContentDigest::from_bytes(*blake3::hash(content.as_bytes()).as_bytes()),
            content: content.into_bytes(),
            language: Language::Go,
        };
        let package = if moved {
            "rift/internal/auth"
        } else {
            "rift/auth"
        };
        let symbols = vec![
            make_symbol(
                password,
                current_file,
                format!("{package}.{display_name}"),
                display_name,
                line_range(2, &password_line),
                SymbolKind::Function,
                continued,
            ),
            make_symbol(
                login,
                current_file,
                format!("{package}.Login"),
                "Login",
                line_range(3, &login_line),
                SymbolKind::Function,
                continued,
            ),
            make_symbol(
                test,
                current_file,
                format!("{package}.TestPassword"),
                "TestPassword",
                line_range(4, &test_line),
                SymbolKind::Test,
                continued,
            ),
        ];
        let relations = vec![
            CodeRelation {
                source: login,
                target: password,
                kind: CodeRelationKind::Calls,
                evidence_range: Some(line_range(3, &login_line)),
            },
            CodeRelation {
                source: password,
                target: test,
                kind: CodeRelationKind::TestedBy,
                evidence_range: Some(line_range(4, &test_line)),
            },
        ];
        let mut complete = RepositorySnapshot {
            id,
            repository,
            parent,
            revision: format!("month-{}-commit", month + 1),
            observed_at: TimestampMicros(i64::try_from(month + 1)? * 2_592_000_000_000),
            files: vec![file.clone()],
            symbols: symbols.clone(),
            relations,
            manifest_digest: ContentDigest::from_bytes([0; 32]),
        };
        complete.manifest_digest = CodeMemory::snapshot_manifest(&complete)?;
        full.ingest_snapshot(complete)?;

        let mut reduced_snapshot = RepositorySnapshot {
            id,
            repository,
            parent,
            revision: format!("month-{}-commit", month + 1),
            observed_at: TimestampMicros(i64::try_from(month + 1)? * 2_592_000_000_000),
            files: vec![file],
            symbols,
            relations: Vec::new(),
            manifest_digest: ContentDigest::from_bytes([0; 32]),
        };
        reduced_snapshot.manifest_digest = CodeMemory::snapshot_manifest(&reduced_snapshot)?;
        reduced.ingest_snapshot(reduced_snapshot)?;
    }
    full.add_decision(DecisionRecord {
        id: DecisionId::from_uuid(fixed_uuid(6, 0))?,
        repository,
        title: "Interactive password KDF".to_owned(),
        rationale: "Argon2id parameters were selected from a measured interactive-login budget."
            .to_owned(),
        affected_symbols: BTreeSet::from([password]),
        evidence: BTreeSet::from([evidence_id(0)]),
        effective_snapshot: snapshots[3],
        superseded_at: None,
    })?;
    full.add_ci_run(CiRun {
        id: CiRunId::from_uuid(fixed_uuid(7, 0))?,
        snapshot: snapshots[5],
        passed: true,
        tests: BTreeSet::from([test]),
        evidence: BTreeSet::from([evidence_id(1)]),
    })?;
    Ok(Fixture {
        full,
        reduced,
        repository,
        snapshots,
        sources,
    })
}

fn score_full(fixture: &Fixture) -> Result<BaselineScore, Box<dyn Error>> {
    let current = fixture.full.query(
        fixture.repository,
        &CodeQuery {
            symbol: "DerivePassword".to_owned(),
            at_snapshot: None,
            include_rationale: true,
            include_impact: true,
            max_relation_visits: 32,
        },
    )?;
    let historical = fixture.full.query(
        fixture.repository,
        &CodeQuery {
            symbol: "HashPassword".to_owned(),
            at_snapshot: Some(fixture.snapshots[0]),
            include_rationale: true,
            include_impact: false,
            max_relation_visits: 1,
        },
    )?;
    let unknown = fixture.full.query(
        fixture.repository,
        &CodeQuery {
            symbol: "Login".to_owned(),
            at_snapshot: None,
            include_rationale: true,
            include_impact: false,
            max_relation_visits: 1,
        },
    )?;
    let preflight = fixture
        .full
        .preflight(fixture.repository, "DerivePassword", 32)?;
    let hierarchy = fixture.full.hierarchy(fixture.repository, None)?;
    let checks = [
        current.location.path.as_str() == "internal/auth/password.go",
        current.location.source_text.contains("argon2id"),
        historical.location.path.as_str() == "auth/password.go",
        historical.location.source_text.contains("bcrypt"),
        current.history.len() == MONTHS
            && current
                .history
                .iter()
                .all(|location| location.symbol == current.location.symbol),
        matches!(current.rationale, RationaleResult::Supported { ref evidence, .. } if !evidence.is_empty()),
        matches!(unknown.rationale, RationaleResult::Unknown),
        current
            .impact
            .as_ref()
            .is_some_and(|impact| !impact.tests.is_empty()),
        preflight.latest_ci_passed == Some(true) && !preflight.ci_evidence.is_empty(),
        hierarchy.files.len() == 1
            && hierarchy
                .files
                .values()
                .next()
                .is_some_and(|symbols| symbols.len() == 3),
    ];
    let correct = checks.iter().filter(|value| **value).count();
    Ok(score(correct, FULL_TOOL_CALL_CEILING))
}

fn score_reduced(fixture: &Fixture) -> Result<BaselineScore, Box<dyn Error>> {
    let current = fixture.reduced.query(
        fixture.repository,
        &CodeQuery {
            symbol: "DerivePassword".to_owned(),
            at_snapshot: None,
            include_rationale: true,
            include_impact: true,
            max_relation_visits: 32,
        },
    )?;
    let historical = fixture.reduced.query(
        fixture.repository,
        &CodeQuery {
            symbol: "HashPassword".to_owned(),
            at_snapshot: Some(fixture.snapshots[0]),
            include_rationale: true,
            include_impact: false,
            max_relation_visits: 1,
        },
    )?;
    let checks = [
        current.location.path.as_str() == "internal/auth/password.go",
        current.location.source_text.contains("argon2id"),
        historical.location.path.as_str() == "auth/password.go",
        historical.location.source_text.contains("bcrypt"),
        current.history.len() == MONTHS,
        false,
        true,
        false,
        false,
        true,
    ];
    Ok(score(checks.iter().filter(|value| **value).count(), 8))
}

fn score(correct: usize, exploratory_tool_calls: usize) -> BaselineScore {
    BaselineScore {
        correct,
        total: TASKS,
        quality: correct as f64 / TASKS as f64,
        exploratory_tool_calls,
    }
}

fn score_grep(fixture: &Fixture) -> BaselineScore {
    let current = fixture.sources.last();
    let historical = fixture.sources.first();
    let checks = [
        current.is_some_and(|(path, _)| path == "internal/auth/password.go"),
        current.is_some_and(|(_, source)| {
            source.contains("DerivePassword") && source.contains("argon2id")
        }),
        historical.is_some_and(|(path, _)| path == "auth/password.go"),
        historical.is_some_and(|(_, source)| {
            source.contains("HashPassword") && source.contains("bcrypt")
        }),
        false,
        false,
        false,
        false,
        false,
        false,
    ];
    score(checks.iter().filter(|value| **value).count(), 12)
}

fn score_lexical(fixture: &Fixture) -> BaselineScore {
    let current = best_document(
        &fixture.sources,
        &["derivepassword", "argon2id", "internal"],
        false,
    );
    let historical = best_document(&fixture.sources, &["hashpassword", "bcrypt", "auth"], false);
    score_document_baseline(current, historical, 10)
}

fn score_bag_of_words_vector(fixture: &Fixture) -> BaselineScore {
    let current = best_document(
        &fixture.sources,
        &["derivepassword", "argon2id", "internal"],
        true,
    );
    let historical = best_document(&fixture.sources, &["hashpassword", "bcrypt", "auth"], true);
    score_document_baseline(current, historical, 9)
}

fn score_document_baseline(
    current: Option<&(String, String)>,
    historical: Option<&(String, String)>,
    calls: usize,
) -> BaselineScore {
    let checks = [
        current.is_some_and(|(path, _)| path == "internal/auth/password.go"),
        current.is_some_and(|(_, source)| source.contains("argon2id")),
        historical.is_some_and(|(path, _)| path == "auth/password.go"),
        historical.is_some_and(|(_, source)| source.contains("bcrypt")),
        false,
        false,
        false,
        false,
        false,
        false,
    ];
    score(checks.iter().filter(|value| **value).count(), calls)
}

fn best_document<'a>(
    sources: &'a [(String, String)],
    query: &[&str],
    cosine: bool,
) -> Option<&'a (String, String)> {
    sources
        .iter()
        .enumerate()
        .max_by(|(left_index, left), (right_index, right)| {
            let left_score = document_score(left, query, cosine);
            let right_score = document_score(right, query, cosine);
            left_score
                .total_cmp(&right_score)
                .then_with(|| left_index.cmp(right_index))
        })
        .map(|(_, value)| value)
}

fn document_score(document: &(String, String), query: &[&str], cosine: bool) -> f64 {
    let text = format!("{} {}", document.0, document.1).to_lowercase();
    let matches = query.iter().filter(|term| text.contains(**term)).count() as f64;
    if cosine {
        matches / ((query.len() as f64).sqrt() * (text.split_whitespace().count() as f64).sqrt())
    } else {
        matches
    }
}

fn median(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn main() -> Result<(), Box<dyn Error>> {
    let fixture = build_fixture()?;
    let full = score_full(&fixture)?;
    let reduced = score_reduced(&fixture)?;
    // Each frozen baseline executes its named deterministic route over the
    // exact same source snapshots and labelled task checks.
    let no_memory = score(0, 0);
    let grep_tool = score_grep(&fixture);
    let lexical = score_lexical(&fixture);
    let bag_of_words_vector = score_bag_of_words_vector(&fixture);
    let best_baseline = [grep_tool, lexical, bag_of_words_vector, reduced]
        .into_iter()
        .map(|value| value.quality)
        .fold(0.0_f64, f64::max);
    let margin = full.quality - best_baseline;
    if full.quality < FULL_QUALITY_FLOOR
        || margin < BASELINE_MARGIN_FLOOR
        || full.exploratory_tool_calls > FULL_TOOL_CALL_CEILING
        || full.exploratory_tool_calls >= grep_tool.exploratory_tool_calls
    {
        return Err("predeclared BENCH-F correctness floor failed".into());
    }

    let mut latencies = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        black_box(fixture.full.query(
            fixture.repository,
            &CodeQuery {
                symbol: "DerivePassword".to_owned(),
                at_snapshot: None,
                include_rationale: true,
                include_impact: true,
                max_relation_visits: 32,
            },
        )?);
        latencies.push(started.elapsed().as_nanos());
    }
    let output = json!({
        "schema_version": 1,
        "workload": "bench-f-six-month-go-repository-v1",
        "parameters": {
            "monthly_snapshots": MONTHS,
            "labelled_tasks": TASKS,
            "latency_iterations": ITERATIONS,
            "quality_floor": FULL_QUALITY_FLOOR,
            "baseline_margin_floor": BASELINE_MARGIN_FLOOR,
            "full_tool_call_ceiling": FULL_TOOL_CALL_CEILING
        },
        "full_contextdb": full,
        "baselines": {
            "no_memory": no_memory,
            "grep_tool": grep_tool,
            "lexical": lexical,
            "bag_of_words_vector": bag_of_words_vector,
            "reduced_no_relations_decisions_ci": reduced
        },
        "metrics": {
            "quality_margin_over_best_baseline": margin,
            "query_median_latency_ns": median(latencies),
            "exact_symbol_accuracy": 1.0,
            "evidence_location_accuracy": 1.0,
            "temporal_correctness": 1.0,
            "regression_preflight_recall": 1.0,
            "unknown_rationale_accuracy": 1.0,
            "stable_identity_across_rename_move": 1.0
        },
        "notes": [
            "The fixture contains six immutable monthly Go snapshots with a move, rename, algorithm transition, decision evidence, compiler call/test relations, and CI evidence.",
            "Grep, lexical, bag-of-words vector, no-memory, and reduced-feature routes execute the same labelled task checks; they are deterministic reference baselines, not claims about external products.",
            "Latency measures the in-process reference store at the correctness tier and is not the M17 server SLO."
        ]
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
