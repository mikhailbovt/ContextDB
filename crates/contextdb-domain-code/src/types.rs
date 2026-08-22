use std::{collections::BTreeSet, fmt};

use contextdb_core::{ContentDigest, EvidenceId, TimestampMicros};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CodeDomainError, Result};

macro_rules! domain_id {
    ($name:ident) => {
        #[doc = concat!("Stable coding-domain identifier for `", stringify!($name), "`.")]
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a time-sortable identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Validates an existing non-nil UUID.
            pub fn from_uuid(value: Uuid) -> Result<Self> {
                if value.is_nil() {
                    return Err(CodeDomainError::InvalidText(stringify!($name)));
                }
                Ok(Self(value))
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

domain_id!(RepositoryId);
domain_id!(SnapshotId);
domain_id!(FileIdentity);
domain_id!(SymbolIdentity);
domain_id!(DecisionId);
domain_id!(CiRunId);

/// Language or compiler family which produced structural facts.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// Go source understood through compiler-native metadata.
    Go,
    /// Rust source understood through compiler-native metadata.
    Rust,
    /// TypeScript or JavaScript compiler metadata.
    TypeScript,
    /// Generic syntax-tree adapter.
    TreeSitter(String),
}

/// Symbol kind supplied by the domain adapter rather than universal core.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// Function or method.
    Function,
    /// Type declaration.
    Type,
    /// Variable or constant.
    Value,
    /// Package, module, or namespace.
    Module,
    /// Interface or trait.
    Interface,
    /// Test case or suite.
    Test,
    /// Language-specific extension.
    Other(String),
}

/// One-based half-open exact source range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRange {
    /// Inclusive one-based start line.
    pub start_line: u32,
    /// Zero-based start column.
    pub start_column: u32,
    /// Inclusive one-based end line.
    pub end_line: u32,
    /// Zero-based exclusive end column on `end_line`.
    pub end_column: u32,
}

impl SourceRange {
    /// Creates a non-empty ordered source range.
    pub fn new(start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> Result<Self> {
        if start_line == 0 || end_line == 0 || (start_line, start_column) >= (end_line, end_column)
        {
            return Err(CodeDomainError::InvalidRange {
                path: "<range>".to_owned(),
            });
        }
        Ok(Self {
            start_line,
            start_column,
            end_line,
            end_column,
        })
    }

    /// Returns whether this range overlaps another range in the same file.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        (self.start_line, self.start_column) < (other.end_line, other.end_column)
            && (other.start_line, other.start_column) < (self.end_line, self.end_column)
    }
}

/// Canonical repository-relative path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoPath(String);

impl RepoPath {
    /// Validates and normalizes `/`-separated repository-relative paths.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().replace('\\', "/");
        if value.is_empty()
            || value.starts_with('/')
            || value.contains('\0')
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || (value.len() >= 2 && value.as_bytes()[1] == b':')
        {
            return Err(CodeDomainError::InvalidPath(value));
        }
        Ok(Self(value))
    }

    /// Returns the canonical relative path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Repository registration shared by all retained snapshots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryDescriptor {
    /// Stable repository identity.
    pub id: RepositoryId,
    /// Human-readable name.
    pub name: String,
    /// Optional canonical upstream URI.
    pub origin: Option<String>,
}

/// Immutable file revision in one repository snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRevision {
    /// Identity retained across moves and renames.
    pub identity: FileIdentity,
    /// Path at this snapshot.
    pub path: RepoPath,
    /// Digest of exact file bytes.
    pub content_digest: ContentDigest,
    /// Exact file bytes, used by the reference adapter and portable archive.
    pub content: Vec<u8>,
    /// Language selected by the adapter.
    pub language: Language,
}

/// Symbol location and compiler signature at one snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolRevision {
    /// Identity retained across supported rename/move changes.
    pub identity: SymbolIdentity,
    /// File identity containing the declaration.
    pub file: FileIdentity,
    /// Fully qualified compiler name at this revision.
    pub qualified_name: String,
    /// Local declaration name.
    pub display_name: String,
    /// Domain kind.
    pub kind: SymbolKind,
    /// Exact declaration range.
    pub declaration: SourceRange,
    /// Normalized compiler signature.
    pub signature: String,
    /// Optional adapter-defined semantic fingerprint used as continuity
    /// evidence. It is not universal identity and never bypasses ambiguity.
    #[serde(default)]
    pub semantic_fingerprint: Option<String>,
    /// Optional identity from the immediately preceding snapshot.
    pub continues_from: Option<SymbolIdentity>,
    /// Adapter confidence in continuity, in basis points.
    pub continuity_confidence: u16,
}

/// Compiler- or adapter-backed relation between stable symbols.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeRelationKind {
    /// Function or method call.
    Calls,
    /// Import or module dependency.
    Imports,
    /// Type use or implementation.
    UsesType,
    /// Test covers or directly invokes production symbol.
    TestedBy,
    /// Contains symbol in repository hierarchy.
    Contains,
}

/// One relation with exact optional source evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRelation {
    /// Source symbol.
    pub source: SymbolIdentity,
    /// Target symbol.
    pub target: SymbolIdentity,
    /// Typed relation.
    pub kind: CodeRelationKind,
    /// Exact source range proving the relation when available.
    pub evidence_range: Option<SourceRange>,
}

/// Immutable repository snapshot derived from Git and compiler inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositorySnapshot {
    /// Snapshot identity.
    pub id: SnapshotId,
    /// Repository identity.
    pub repository: RepositoryId,
    /// Optional parent snapshot.
    pub parent: Option<SnapshotId>,
    /// Git commit or adapter revision string.
    pub revision: String,
    /// Observation timestamp.
    pub observed_at: TimestampMicros,
    /// Immutable file revisions.
    pub files: Vec<FileRevision>,
    /// Compiler-derived symbol revisions.
    pub symbols: Vec<SymbolRevision>,
    /// Compiler-derived relations.
    pub relations: Vec<CodeRelation>,
    /// Canonical digest over this snapshot excluding this field.
    pub manifest_digest: ContentDigest,
}

/// Evidence-backed architectural or implementation decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    /// Stable decision identity.
    pub id: DecisionId,
    /// Repository to which this decision applies.
    pub repository: RepositoryId,
    /// Decision title.
    pub title: String,
    /// Supported rationale text. Empty rationale is invalid; use no record for unknown.
    pub rationale: String,
    /// Stable affected symbols.
    pub affected_symbols: BTreeSet<SymbolIdentity>,
    /// Core evidence spans supporting the decision.
    pub evidence: BTreeSet<EvidenceId>,
    /// Snapshot at which the decision became applicable.
    pub effective_snapshot: SnapshotId,
    /// Optional snapshot at which it stopped being applicable.
    pub superseded_at: Option<SnapshotId>,
}

/// CI result connected to exact tests and production symbols.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiRun {
    /// Stable run identity.
    pub id: CiRunId,
    /// Snapshot tested by this run.
    pub snapshot: SnapshotId,
    /// Passed or failed.
    pub passed: bool,
    /// Test symbols exercised by the run.
    pub tests: BTreeSet<SymbolIdentity>,
    /// Exact external evidence, such as a signed CI artifact.
    pub evidence: BTreeSet<EvidenceId>,
}

/// Canonical digest helper used by adapters and persistence verification.
pub(crate) fn digest_json<T: Serialize>(domain: &[u8], value: &T) -> Result<ContentDigest> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&bytes);
    Ok(ContentDigest::from_bytes(*hasher.finalize().as_bytes()))
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 4_096 {
        return Err(CodeDomainError::InvalidText(field));
    }
    Ok(())
}
