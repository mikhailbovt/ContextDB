//! Deterministic BENCH-C fixture and labelled reference evaluator.

use std::{collections::BTreeSet, str::FromStr};

use contextdb_context::{
    CompileRequest, ContextBudgets, ContextCompiler, ContextProvider, InstructionHierarchy,
    ModelProfile, PackFacetRequirement, PackPurpose, PositionProfile, ReferenceTokenizer,
    RendererKind, StructuredFormat,
};
use contextdb_core::{
    AccessCapability, ActorId, Audience, AudienceGrant, ConsentPolicy, DerivationKind,
    DerivationRef, EpistemicRole, MemorySpaceId, MemorySubjectId, MemoryUsePolicy,
    ModificationPolicy, NonEmptyVec, OwnershipPolicy, PipelineIdentity, PolicyDecision, PolicyId,
    Purpose, RetentionPolicy, ScopeInheritance, ScopeKind, ScopeRef, SecurityClassification,
    SecurityPolicy, SemanticEnvelope, TemporalConstraint, TimeRange, TimestampMicros, TrustClass,
    ValidationError, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::{
    DocumentAdapterConfig, DocumentFormat, DocumentRevisionInput, DocumentRevisionKind,
    DocumentSectionInput, DocumentStatementAction, DocumentStatementInput, GenericDocumentAdapter,
    KnowledgeAnswerState, KnowledgeContextAdapter, KnowledgeLedger, KnowledgeQuery,
    KnowledgeQueryResult, Result, SourceConstraint, SourceStatementRef, StatementEpistemic,
};

/// Canonical, fixed-identity evolving-source fixture for M13.
#[derive(Clone, Debug)]
pub struct BenchCFixture {
    pub workspace_id: WorkspaceId,
    pub memory_space_id: MemorySpaceId,
    pub actor_id: ActorId,
    pub subject_id: MemorySubjectId,
    pub policy_id: PolicyId,
    pub scope: ScopeRef,
    pub envelope: SemanticEnvelope,
}

impl BenchCFixture {
    /// Creates the stable Redis -> PostgreSQL + disagreement/retraction corpus.
    pub fn canonical() -> Result<Self> {
        let workspace_id = fixed("00000000-0000-4000-8000-000000000013")?;
        let memory_space_id = fixed("00000000-0000-4000-8001-000000000013")?;
        let actor_id = fixed("00000000-0000-4000-8002-000000000013")?;
        let subject_id = fixed("00000000-0000-4000-8003-000000000013")?;
        let policy_id = fixed("00000000-0000-4000-8006-000000000013")?;
        let scope = ScopeRef {
            kind: ScopeKind::Workspace,
            id: fixed("00000000-0000-4000-8004-000000000013")?,
            inheritance: ScopeInheritance::Descendants,
        };
        let purposes = BTreeSet::from([Purpose::KnowledgeRecall]);
        let envelope = SemanticEnvelope {
            scopes: NonEmptyVec::new(scope.clone()),
            perspective: contextdb_core::Perspective {
                knower: subject_id,
                experiencer: None,
                narrator: actor_id,
                role: EpistemicRole::Asserter,
            },
            ownership: OwnershipPolicy {
                owners: NonEmptyVec::new(subject_id),
                audience_grants: vec![AudienceGrant {
                    audience: Audience::Subject { id: subject_id },
                    purposes: purposes.clone(),
                    capabilities: BTreeSet::from([
                        AccessCapability::Retrieve,
                        AccessCapability::InfluenceResponse,
                        AccessCapability::Mention,
                        AccessCapability::Derive,
                    ]),
                }],
                allowed_purposes: purposes,
                modification: ModificationPolicy {
                    owners_may_modify: true,
                    delegates_may_modify: false,
                    system_may_derive: true,
                },
            },
            consent: ConsentPolicy {
                required: false,
                decisions: Vec::new(),
            },
            use_policy: MemoryUsePolicy {
                retrieve: PolicyDecision::Allow,
                influence_response: PolicyDecision::Allow,
                mention_explicitly: PolicyDecision::Allow,
                external_model_use: PolicyDecision::Deny,
                retention: RetentionPolicy::Indefinite,
            },
            security: SecurityPolicy {
                classification: SecurityClassification::Internal,
                labels: BTreeSet::from(["bench-c".to_owned()]),
                required_compartments: BTreeSet::new(),
                allow_external_processing: false,
            },
            derivation: DerivationRef {
                id: fixed("00000000-0000-4000-8005-000000000013")?,
                kind: DerivationKind::Import,
                actor: Some(actor_id),
                model_call: None,
                pipeline: PipelineIdentity {
                    name: "bench-c-fixture".to_owned(),
                    version: "1".to_owned(),
                    schema_version: "1".to_owned(),
                },
                inputs: Vec::new(),
            },
        };
        Ok(Self {
            workspace_id,
            memory_space_id,
            actor_id,
            subject_id,
            policy_id,
            scope,
            envelope,
        })
    }

    /// D1: Redis was used before the migration boundary.
    #[must_use]
    pub fn redis_document(&self) -> DocumentRevisionInput {
        self.document(
            "architecture-v1",
            "official-architecture",
            "rev-1",
            None,
            "Architecture v1",
            "Product uses Redis for sessions before version 2.0.",
            vec![assertion(
                "sessions-backend",
                "Product uses Redis for sessions",
                "Redis",
                TimeRange {
                    start: TimestampMicros(0),
                    end: Some(TimestampMicros(200)),
                },
            )],
        )
    }

    /// D2: PostgreSQL is current after version 2.0; rationale stays unknown.
    #[must_use]
    pub fn postgres_document(&self) -> DocumentRevisionInput {
        self.document(
            "migration-v2",
            "official-release",
            "rev-1",
            None,
            "Version 2.0 migration",
            "Version 2.0 migrated sessions to PostgreSQL. The migration rationale is not documented.",
            vec![
                assertion(
                    "sessions-backend",
                    "migrated sessions to PostgreSQL",
                    "PostgreSQL",
                    TimeRange::open_ended(TimestampMicros(200)),
                ),
                DocumentStatementInput {
                    statement_key: "migration-rationale".to_owned(),
                    subject_key: "sessions".to_owned(),
                    subject_label: "Sessions".to_owned(),
                    predicate_key: "migration_rationale".to_owned(),
                    quote: "The migration rationale is not documented".to_owned(),
                    action: DocumentStatementAction::OpenQuestion {
                        question: "Why were sessions migrated to PostgreSQL?".to_owned(),
                        reason: "The source explicitly says the rationale is not documented"
                            .to_owned(),
                    },
                },
            ],
        )
    }

    /// A dependent mirror of D2. It must not count as independent support.
    #[must_use]
    pub fn postgres_mirror(&self) -> DocumentRevisionInput {
        self.document(
            "migration-v2-mirror",
            "official-release",
            "rev-1",
            None,
            "Syndicated migration note",
            "A mirror reports that sessions migrated to PostgreSQL.",
            vec![assertion(
                "sessions-backend",
                "sessions migrated to PostgreSQL",
                "PostgreSQL",
                TimeRange::open_ended(TimestampMicros(200)),
            )],
        )
    }

    /// Independent conflicting report used to test visible disagreement.
    #[must_use]
    pub fn mysql_disagreement(&self) -> DocumentRevisionInput {
        self.document(
            "community-status",
            "community-observation",
            "rev-1",
            None,
            "Community status report",
            "The community status report says sessions use MySQL.",
            vec![assertion(
                "sessions-backend",
                "sessions use MySQL",
                "MySQL",
                TimeRange::open_ended(TimestampMicros(200)),
            )],
        )
    }

    /// Same source family retracts the conflicting report without erasing it.
    #[must_use]
    pub fn mysql_retraction(&self) -> DocumentRevisionInput {
        self.document_with_kind(
            "community-status",
            "community-observation",
            "rev-2",
            Some("rev-1"),
            "Community correction",
            "The earlier MySQL status report is retracted as incorrect.",
            vec![DocumentStatementInput {
                statement_key: "retract-sessions-backend".to_owned(),
                subject_key: "sessions".to_owned(),
                subject_label: "Sessions".to_owned(),
                predicate_key: "backend".to_owned(),
                quote: "MySQL status report is retracted as incorrect".to_owned(),
                action: DocumentStatementAction::Retract {
                    target: SourceStatementRef {
                        source_key: "community-status".to_owned(),
                        statement_key: "sessions-backend".to_owned(),
                    },
                    reason: "The originating source withdrew the report".to_owned(),
                },
            }],
            DocumentRevisionKind::Upsert,
        )
    }

    /// Creates a hypothesis-only document after an external support ID is known.
    #[must_use]
    pub fn hypothesis_document(
        &self,
        supporting_evidence: contextdb_core::EvidenceId,
    ) -> DocumentRevisionInput {
        self.document(
            "analysis-note",
            "analyst-hypothesis",
            "rev-1",
            None,
            "Unverified analysis",
            "An analyst hypothesises that operational cost caused the migration.",
            vec![DocumentStatementInput {
                statement_key: "migration-driver".to_owned(),
                subject_key: "sessions".to_owned(),
                subject_label: "Sessions".to_owned(),
                predicate_key: "migration_driver".to_owned(),
                quote: "operational cost caused the migration".to_owned(),
                action: DocumentStatementAction::Assert {
                    object: contextdb_core::ClaimObject::String("operational cost".to_owned()),
                    valid_time: TimeRange::open_ended(TimestampMicros(200)),
                    epistemic: StatementEpistemic::DerivedHypothesis {
                        supporting_evidence: vec![supporting_evidence],
                    },
                },
            }],
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "fixture helper mirrors the generic document revision contract"
    )]
    fn document(
        &self,
        source_key: &str,
        source_family: &str,
        native_revision: &str,
        supersedes: Option<&str>,
        title: &str,
        content: &str,
        statements: Vec<DocumentStatementInput>,
    ) -> DocumentRevisionInput {
        self.document_with_kind(
            source_key,
            source_family,
            native_revision,
            supersedes,
            title,
            content,
            statements,
            DocumentRevisionKind::Upsert,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "fixture builder mirrors the generic document contract"
    )]
    fn document_with_kind(
        &self,
        source_key: &str,
        source_family: &str,
        native_revision: &str,
        supersedes: Option<&str>,
        title: &str,
        content: &str,
        statements: Vec<DocumentStatementInput>,
        revision_kind: DocumentRevisionKind,
    ) -> DocumentRevisionInput {
        DocumentRevisionInput {
            workspace_id: self.workspace_id,
            memory_space_id: self.memory_space_id,
            actor_id: self.actor_id,
            corpus_key: "bench-c".to_owned(),
            source_key: source_key.to_owned(),
            source_family: source_family.to_owned(),
            native_locator: format!("bench-c://{source_key}/{native_revision}"),
            native_revision: native_revision.to_owned(),
            supersedes_native_revision: supersedes.map(str::to_owned),
            title: title.to_owned(),
            format: DocumentFormat::Markdown,
            revision_kind,
            created_at: Some(TimestampMicros(100)),
            effective_at: TimestampMicros(100),
            observed_at: TimestampMicros(110),
            recorded_at: TimestampMicros(120),
            trust: TrustClass::Verified,
            ingestion_policy: self.policy_id,
            expected_content_hash: None,
            envelope: self.envelope.clone(),
            sections: vec![DocumentSectionInput {
                path: vec![title.to_owned()],
                content: content.to_owned(),
                statements,
            }],
        }
    }
}

fn assertion(
    statement_key: &str,
    quote: &str,
    object: &str,
    valid_time: TimeRange,
) -> DocumentStatementInput {
    DocumentStatementInput {
        statement_key: statement_key.to_owned(),
        subject_key: "sessions".to_owned(),
        subject_label: "Sessions".to_owned(),
        predicate_key: "backend".to_owned(),
        quote: quote.to_owned(),
        action: DocumentStatementAction::Assert {
            object: contextdb_core::ClaimObject::String(object.to_owned()),
            valid_time,
            epistemic: StatementEpistemic::SourceAssertion,
        },
    }
}

fn fixed<T>(value: &str) -> std::result::Result<T, ValidationError>
where
    T: FromStr<Err = ValidationError>,
{
    value.parse()
}

/// Label for a deterministic BENCH-C result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum BenchCExpectedState {
    Supported {
        object: contextdb_core::ClaimObject,
    },
    Disputed {
        objects: Vec<contextdb_core::ClaimObject>,
    },
    Unknown,
}

/// One labelled BENCH-C observation.
#[derive(Clone, Debug)]
pub struct BenchCCase<'a> {
    pub id: &'a str,
    pub result: &'a KnowledgeQueryResult,
    pub expected: BenchCExpectedState,
    pub permitted_evidence: &'a BTreeSet<contextdb_core::EvidenceId>,
    pub stale_summary_selected: bool,
    pub rendered_tokens: u64,
}

/// Count-aware BENCH-C report. Zero-denominator rates never pass release floors.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchCReport {
    pub cases: u64,
    pub supported_cases: u64,
    pub correct_supported_cases: u64,
    pub correct_state_cases: u64,
    pub attributed_supported_cases: u64,
    pub conflict_cases: u64,
    pub correct_conflict_cases: u64,
    pub unknown_cases: u64,
    pub correct_unknown_cases: u64,
    pub stale_summary_selections: u64,
    pub citations: u64,
    pub hallucinated_citations: u64,
    pub rendered_tokens: u64,
    pub supported_rendered_tokens: u64,
    pub claim_support: f64,
    pub source_attribution: f64,
    pub conflict_handling: f64,
    pub unknown_accuracy: f64,
    pub stale_summary_rate: f64,
    pub hallucinated_evidence_rate: f64,
    pub tokens_per_supported_answer: f64,
}

/// Frozen threshold shape for a declared BENCH-C run.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchCThresholds {
    pub min_cases: u64,
    pub min_supported_cases: u64,
    pub min_conflict_cases: u64,
    pub min_unknown_cases: u64,
    pub min_claim_support: f64,
    pub min_source_attribution: f64,
    pub min_conflict_handling: f64,
    pub min_unknown_accuracy: f64,
    pub max_stale_summary_rate: f64,
    pub max_hallucinated_evidence_rate: f64,
    pub max_tokens_per_supported_answer: f64,
}

impl Default for BenchCThresholds {
    fn default() -> Self {
        Self {
            min_cases: 6,
            min_supported_cases: 2,
            min_conflict_cases: 1,
            min_unknown_cases: 2,
            min_claim_support: 1.0,
            min_source_attribution: 1.0,
            min_conflict_handling: 1.0,
            min_unknown_accuracy: 1.0,
            max_stale_summary_rate: 0.0,
            max_hallucinated_evidence_rate: 0.0,
            // Includes canonical ContextPack control, evidence, and history
            // rendered by the deterministic reference tokenizer.
            max_tokens_per_supported_answer: 4_096.0,
        }
    }
}

impl BenchCReport {
    /// Checks both sample floors and quality targets.
    #[must_use]
    pub fn meets(&self, thresholds: BenchCThresholds) -> bool {
        self.cases >= thresholds.min_cases
            && self.supported_cases >= thresholds.min_supported_cases
            && self.conflict_cases >= thresholds.min_conflict_cases
            && self.unknown_cases >= thresholds.min_unknown_cases
            && self.claim_support >= thresholds.min_claim_support
            && self.source_attribution >= thresholds.min_source_attribution
            && self.conflict_handling >= thresholds.min_conflict_handling
            && self.unknown_accuracy >= thresholds.min_unknown_accuracy
            && self.stale_summary_rate <= thresholds.max_stale_summary_rate
            && self.hallucinated_evidence_rate <= thresholds.max_hallucinated_evidence_rate
            && self.tokens_per_supported_answer <= thresholds.max_tokens_per_supported_answer
    }
}

/// Evaluates labelled logical outputs without invoking a model.
#[derive(Clone, Copy, Debug, Default)]
pub struct BenchCEvaluator;

impl BenchCEvaluator {
    /// Computes M13 quality metrics and exact citation integrity.
    #[must_use]
    pub fn evaluate(cases: &[BenchCCase<'_>]) -> BenchCReport {
        let mut report = BenchCReport {
            cases: cases.len() as u64,
            supported_cases: 0,
            correct_supported_cases: 0,
            correct_state_cases: 0,
            attributed_supported_cases: 0,
            conflict_cases: 0,
            correct_conflict_cases: 0,
            unknown_cases: 0,
            correct_unknown_cases: 0,
            stale_summary_selections: 0,
            citations: 0,
            hallucinated_citations: 0,
            rendered_tokens: 0,
            supported_rendered_tokens: 0,
            claim_support: 0.0,
            source_attribution: 0.0,
            conflict_handling: 0.0,
            unknown_accuracy: 0.0,
            stale_summary_rate: 0.0,
            hallucinated_evidence_rate: 0.0,
            tokens_per_supported_answer: 0.0,
        };
        for case in cases {
            report.rendered_tokens = report.rendered_tokens.saturating_add(case.rendered_tokens);
            if matches!(case.expected, BenchCExpectedState::Supported { .. }) {
                report.supported_rendered_tokens = report
                    .supported_rendered_tokens
                    .saturating_add(case.rendered_tokens);
            }
            report.stale_summary_selections = report
                .stale_summary_selections
                .saturating_add(u64::from(case.stale_summary_selected));
            let citations = result_citations(case.result);
            report.citations = report.citations.saturating_add(citations.len() as u64);
            report.hallucinated_citations = report.hallucinated_citations.saturating_add(
                citations
                    .iter()
                    .filter(|citation| !case.permitted_evidence.contains(&citation.evidence_id))
                    .count() as u64,
            );
            match (&case.expected, &case.result.state) {
                (
                    BenchCExpectedState::Supported { object: expected },
                    KnowledgeAnswerState::Supported { answer },
                ) if &answer.object == expected => {
                    report.supported_cases = report.supported_cases.saturating_add(1);
                    report.correct_supported_cases =
                        report.correct_supported_cases.saturating_add(1);
                    report.correct_state_cases = report.correct_state_cases.saturating_add(1);
                    if !answer.citations.is_empty() {
                        report.attributed_supported_cases =
                            report.attributed_supported_cases.saturating_add(1);
                    }
                }
                (
                    BenchCExpectedState::Disputed { objects: expected },
                    KnowledgeAnswerState::Disputed { alternatives, .. },
                ) => {
                    report.conflict_cases = report.conflict_cases.saturating_add(1);
                    let mut actual: Vec<_> = alternatives
                        .iter()
                        .map(|alternative| canonical_object(&alternative.object))
                        .collect();
                    let mut expected: Vec<_> = expected.iter().map(canonical_object).collect();
                    actual.sort();
                    expected.sort();
                    if actual == expected {
                        report.correct_state_cases = report.correct_state_cases.saturating_add(1);
                        report.correct_conflict_cases =
                            report.correct_conflict_cases.saturating_add(1);
                    }
                }
                (BenchCExpectedState::Unknown, KnowledgeAnswerState::Unknown { .. }) => {
                    report.unknown_cases = report.unknown_cases.saturating_add(1);
                    report.correct_state_cases = report.correct_state_cases.saturating_add(1);
                    report.correct_unknown_cases = report.correct_unknown_cases.saturating_add(1);
                }
                (BenchCExpectedState::Supported { .. }, _) => {
                    report.supported_cases = report.supported_cases.saturating_add(1);
                }
                (BenchCExpectedState::Disputed { .. }, _) => {
                    report.conflict_cases = report.conflict_cases.saturating_add(1);
                }
                (BenchCExpectedState::Unknown, _) => {
                    report.unknown_cases = report.unknown_cases.saturating_add(1);
                }
            }
        }
        report.claim_support = ratio(report.correct_supported_cases, report.supported_cases);
        report.source_attribution =
            ratio(report.attributed_supported_cases, report.supported_cases);
        report.conflict_handling = ratio(report.correct_conflict_cases, report.conflict_cases);
        report.unknown_accuracy = ratio(report.correct_unknown_cases, report.unknown_cases);
        report.stale_summary_rate = error_ratio(report.stale_summary_selections, report.cases);
        report.hallucinated_evidence_rate =
            error_ratio(report.hallucinated_citations, report.citations);
        report.tokens_per_supported_answer = if report.supported_cases == 0 {
            f64::INFINITY
        } else {
            report.supported_rendered_tokens as f64 / report.supported_cases as f64
        };
        report
    }
}

/// Fully materialized, provider-free BENCH-C demonstration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchCDemo {
    pub redis_snapshot: contextdb_core::SnapshotRef,
    pub postgres_snapshot: contextdb_core::SnapshotRef,
    pub disagreement_snapshot: contextdb_core::SnapshotRef,
    pub retraction_snapshot: contextdb_core::SnapshotRef,
    pub current: KnowledgeQueryResult,
    pub historical: KnowledgeQueryResult,
    pub rationale_unknown: KnowledgeQueryResult,
    pub system_time_unknown: KnowledgeQueryResult,
    pub disputed: KnowledgeQueryResult,
    pub restored: KnowledgeQueryResult,
    pub report: BenchCReport,
}

/// Runs the fixed Redis -> PostgreSQL -> disagreement -> retraction scenario
/// without a model, network, wall clock, or random identifier.
pub fn run_bench_c_demo() -> Result<BenchCDemo> {
    let fixture = BenchCFixture::canonical()?;
    let adapter = GenericDocumentAdapter::new(DocumentAdapterConfig::default())?;
    let mut ledger = KnowledgeLedger::default();
    let redis = ledger.publish(adapter.adapt(&fixture.redis_document())?)?;
    let postgres = ledger.publish(adapter.adapt(&fixture.postgres_document())?)?;
    let current = ledger.query(&bench_query(&fixture, postgres.snapshot, "backend", 250))?;
    let historical = ledger.query(&bench_query(&fixture, postgres.snapshot, "backend", 100))?;
    let rationale_unknown = ledger.query(&bench_query(
        &fixture,
        postgres.snapshot,
        "migration_rationale",
        250,
    ))?;
    let system_time_unknown =
        ledger.query(&bench_query(&fixture, redis.snapshot, "backend", 250))?;
    let disagreement = ledger.publish(adapter.adapt(&fixture.mysql_disagreement())?)?;
    let disputed = ledger.query(&bench_query(
        &fixture,
        disagreement.snapshot,
        "backend",
        250,
    ))?;
    let retraction = ledger.publish(adapter.adapt(&fixture.mysql_retraction())?)?;
    let restored = ledger.query(&bench_query(&fixture, retraction.snapshot, "backend", 250))?;
    let permitted_evidence: BTreeSet<_> = ledger
        .export()
        .sources
        .values()
        .flatten()
        .flat_map(|revision| revision.evidence.iter().map(|evidence| evidence.id))
        .collect();
    let current_tokens = bench_rendered_tokens(
        &ledger,
        &bench_query(&fixture, postgres.snapshot, "backend", 250),
        21,
    )?;
    let historical_tokens = bench_rendered_tokens(
        &ledger,
        &bench_query(&fixture, postgres.snapshot, "backend", 100),
        22,
    )?;
    let rationale_tokens = bench_rendered_tokens(
        &ledger,
        &bench_query(&fixture, postgres.snapshot, "migration_rationale", 250),
        23,
    )?;
    let system_time_tokens = bench_rendered_tokens(
        &ledger,
        &bench_query(&fixture, redis.snapshot, "backend", 250),
        24,
    )?;
    let disagreement_tokens = bench_rendered_tokens(
        &ledger,
        &bench_query(&fixture, disagreement.snapshot, "backend", 250),
        25,
    )?;
    let retraction_tokens = bench_rendered_tokens(
        &ledger,
        &bench_query(&fixture, retraction.snapshot, "backend", 250),
        26,
    )?;
    let cases = [
        BenchCCase {
            id: "current",
            result: &current,
            expected: BenchCExpectedState::Supported {
                object: contextdb_core::ClaimObject::String("PostgreSQL".to_owned()),
            },
            permitted_evidence: &permitted_evidence,
            stale_summary_selected: false,
            rendered_tokens: current_tokens,
        },
        BenchCCase {
            id: "historical",
            result: &historical,
            expected: BenchCExpectedState::Supported {
                object: contextdb_core::ClaimObject::String("Redis".to_owned()),
            },
            permitted_evidence: &permitted_evidence,
            stale_summary_selected: false,
            rendered_tokens: historical_tokens,
        },
        BenchCCase {
            id: "rationale-unknown",
            result: &rationale_unknown,
            expected: BenchCExpectedState::Unknown,
            permitted_evidence: &permitted_evidence,
            stale_summary_selected: false,
            rendered_tokens: rationale_tokens,
        },
        BenchCCase {
            id: "system-time-unknown",
            result: &system_time_unknown,
            expected: BenchCExpectedState::Unknown,
            permitted_evidence: &permitted_evidence,
            stale_summary_selected: false,
            rendered_tokens: system_time_tokens,
        },
        BenchCCase {
            id: "disagreement",
            result: &disputed,
            expected: BenchCExpectedState::Disputed {
                objects: vec![
                    contextdb_core::ClaimObject::String("MySQL".to_owned()),
                    contextdb_core::ClaimObject::String("PostgreSQL".to_owned()),
                ],
            },
            permitted_evidence: &permitted_evidence,
            stale_summary_selected: false,
            rendered_tokens: disagreement_tokens,
        },
        BenchCCase {
            id: "retracted",
            result: &restored,
            expected: BenchCExpectedState::Supported {
                object: contextdb_core::ClaimObject::String("PostgreSQL".to_owned()),
            },
            permitted_evidence: &permitted_evidence,
            stale_summary_selected: false,
            rendered_tokens: retraction_tokens,
        },
    ];
    let report = BenchCEvaluator::evaluate(&cases);
    Ok(BenchCDemo {
        redis_snapshot: redis.snapshot,
        postgres_snapshot: postgres.snapshot,
        disagreement_snapshot: disagreement.snapshot,
        retraction_snapshot: retraction.snapshot,
        current,
        historical,
        rationale_unknown,
        system_time_unknown,
        disputed,
        restored,
        report,
    })
}

fn bench_rendered_tokens(
    ledger: &KnowledgeLedger,
    query: &KnowledgeQuery,
    continuation_key: u8,
) -> Result<u64> {
    let material = KnowledgeContextAdapter::prepare(ledger, query)?;
    let snapshot = material.provider.snapshot()?;
    let request = CompileRequest {
        pack_id: contextdb_core::ContextPackId::from_uuid(crate::adapter::deterministic_uuid(&[
            b"bench-c-context-pack",
            &[continuation_key],
        ]))?,
        snapshot,
        principal: query.principal.clone(),
        filter_digest: "bench-c-policy-filter-v1".to_owned(),
        purpose: PackPurpose::Knowledge,
        scopes: query.principal.scopes.clone(),
        temporal_view: TemporalConstraint::Bitemporal {
            valid_during: TimeRange::open_ended(query.valid_at),
            known_at: query.known_at.commit_seq,
        },
        required_facets: vec![PackFacetRequirement {
            name: query.predicate_key.clone(),
            minimum_confidence_micros: 0,
            require_evidence: false,
        }],
        budgets: ContextBudgets {
            hard_tokens: 20_000,
            soft_tokens: 16_000,
            max_blocks: 64,
            max_evidence_blocks: 64,
            max_raw_evidence_tokens: 8_000,
            max_history_tokens: 8_000,
            max_conflict_tokens: 4_000,
            max_serialized_bytes: 1_000_000,
            max_selection_evaluations: 128,
        },
        model_profile: ModelProfile {
            id: "bench-c-reference-model".to_owned(),
            family: "deterministic-fixture".to_owned(),
            tokenizer_id: ReferenceTokenizer::ID.to_owned(),
            renderer: RendererKind::CanonicalJson,
            max_context_tokens: 32_000,
            reserved_output_tokens: 2_000,
            preferred_structured_format: StructuredFormat::Json,
            supports_tool_results: false,
            supports_native_citations: true,
            supports_prompt_caching: false,
            position_profile: PositionProfile::EvidenceAdjacent,
            instruction_hierarchy: InstructionHierarchy::SeparatedChannels,
            max_schema_complexity: 64,
            external_processing: false,
        },
        explicit_memory_request: true,
        require_primary_evidence: true,
        continuation: None,
    };
    let compiled = ContextCompiler::new([continuation_key; 32])?.compile(
        &request,
        &material.provider,
        &ReferenceTokenizer,
    )?;
    Ok(u64::from(compiled.rendered.total_tokens))
}

fn bench_query(
    fixture: &BenchCFixture,
    known_at: contextdb_core::SnapshotRef,
    predicate_key: &str,
    valid_at: i64,
) -> KnowledgeQuery {
    KnowledgeQuery {
        subject_key: "sessions".to_owned(),
        predicate_key: predicate_key.to_owned(),
        valid_at: TimestampMicros(valid_at),
        known_at,
        source: SourceConstraint::AnyAuthorized,
        include_history: true,
        disclose_conflicts: true,
        include_excerpts: true,
        principal: contextdb_recall::RecallPrincipal {
            subject: fixture.subject_id.to_string(),
            audiences: BTreeSet::new(),
            workspace: fixture.workspace_id.to_string(),
            scopes: BTreeSet::from([fixture.scope.id.to_string()]),
            purpose: contextdb_recall::purpose_key(&Purpose::KnowledgeRecall),
            clearance: contextdb_recall::RecallSensitivity::Internal,
        },
    }
}

fn result_citations(result: &KnowledgeQueryResult) -> Vec<&crate::KnowledgeCitation> {
    let mut citations = Vec::new();
    match &result.state {
        KnowledgeAnswerState::Supported { answer } => citations.extend(&answer.citations),
        KnowledgeAnswerState::Disputed { alternatives, .. } => {
            for alternative in alternatives {
                citations.extend(&alternative.citations);
            }
        }
        KnowledgeAnswerState::Unknown { .. } => {}
    }
    citations
}

fn canonical_object(object: &contextdb_core::ClaimObject) -> String {
    serde_json::to_string(object).unwrap_or_else(|_| "<invalid>".to_owned())
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn error_ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}
