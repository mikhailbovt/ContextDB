use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{ContentDigest, EvidenceId, TimestampMicros};
use serde::{Deserialize, Serialize};

use crate::{
    CodeDomainError, CodeRelationKind, DecisionId, RepoPath, Result, SnapshotId, SourceRange,
    SymbolIdentity, SymbolKind,
};

/// Query for current or historical code and its supported context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeQuery {
    /// Repository-local identifier or fully qualified symbol fragment.
    pub symbol: String,
    /// Exact snapshot, when historical state is required.
    pub at_snapshot: Option<SnapshotId>,
    /// Whether evidence-backed rationale is requested.
    pub include_rationale: bool,
    /// Whether tests and transitive dependents are requested.
    pub include_impact: bool,
    /// Maximum graph edges visited by impact traversal.
    pub max_relation_visits: usize,
}

impl CodeQuery {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::types::validate_text(&self.symbol, "code_query.symbol")?;
        if self.max_relation_visits == 0 || self.max_relation_visits > 100_000 {
            return Err(CodeDomainError::InvalidBudget);
        }
        Ok(())
    }
}

/// Exact code location safe to cite to a user or tool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedCodeLocation {
    /// Stable symbol identity.
    pub symbol: SymbolIdentity,
    /// Name at the selected revision.
    pub qualified_name: String,
    /// Domain symbol kind.
    pub kind: SymbolKind,
    /// Repository-relative path at the selected revision.
    pub path: RepoPath,
    /// Exact declaration range.
    pub declaration: SourceRange,
    /// Compiler signature at the selected revision.
    pub signature: String,
    /// Exact declaration source bytes decoded as UTF-8 after range validation.
    pub source_text: String,
    /// Digest of `source_text`, suitable for evidence binding.
    pub source_digest: ContentDigest,
    /// Selected immutable snapshot.
    pub snapshot: SnapshotId,
    /// Git commit or adapter revision associated with the snapshot.
    pub revision: String,
    /// Snapshot observation time.
    pub observed_at: TimestampMicros,
}

/// Evidence state of a requested rationale.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RationaleResult {
    /// Supported decision records and evidence are available.
    Supported {
        /// Human-readable rationale derived from the decision source.
        text: String,
        /// Decision identities.
        decisions: Vec<DecisionId>,
        /// Exact evidence spans supporting the rationale.
        evidence: BTreeSet<EvidenceId>,
    },
    /// No authorized evidence supports a rationale.
    Unknown,
}

/// Bounded compiler/test impact report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactReport {
    /// Direct or transitive dependent symbols.
    pub affected_symbols: BTreeSet<SymbolIdentity>,
    /// Test symbols linked to the selected symbol or its dependents.
    pub tests: BTreeSet<SymbolIdentity>,
    /// Typed relation kinds which contributed.
    pub relation_kinds: BTreeSet<CodeRelationKind>,
    /// Edges examined under the hard query budget.
    pub relation_visits: usize,
    /// True when the traversal budget stopped complete exploration.
    pub truncated: bool,
}

/// Repository/file/symbol containment at one immutable snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryHierarchy {
    /// Selected snapshot.
    pub snapshot: SnapshotId,
    /// Stable symbols grouped by repository-relative file.
    pub files: BTreeMap<RepoPath, BTreeSet<SymbolIdentity>>,
}

/// Coding preflight that keeps compiler impact distinct from observed CI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReport {
    /// Selected implementation location.
    pub location: ResolvedCodeLocation,
    /// Bounded compiler relation traversal.
    pub impact: ImpactReport,
    /// Latest retained CI outcome covering any impacted test, when available.
    pub latest_ci_passed: Option<bool>,
    /// Exact evidence spans from the selected CI result.
    pub ci_evidence: BTreeSet<EvidenceId>,
    /// True when no retained CI run covers the impacted tests.
    pub missing_test_execution_evidence: bool,
}

/// Complete source-backed coding query result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeQueryResult {
    /// Current or historical exact location.
    pub location: ResolvedCodeLocation,
    /// Stable identity history from oldest retained revision to selected revision.
    pub history: Vec<ResolvedCodeLocation>,
    /// Supported rationale or explicit unknown.
    pub rationale: RationaleResult,
    /// Optional bounded impact report.
    pub impact: Option<ImpactReport>,
}
