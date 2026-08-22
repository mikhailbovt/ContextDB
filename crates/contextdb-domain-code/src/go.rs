use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{ContentDigest, TimestampMicros};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CodeDomainError, CodeMemory, CodeRelation, CodeRelationKind, FileIdentity, FileRevision,
    Language, RepoPath, RepositoryId, RepositorySnapshot, Result, SnapshotId, SourceRange,
    SymbolIdentity, SymbolKind, SymbolRevision,
};

/// Exact Go source file emitted by the compiler-native helper.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoSourceFile {
    /// Repository-relative path.
    pub path: String,
    /// Exact UTF-8 Go source.
    pub content: String,
}

/// One `go/ast` + `go/types` symbol record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoIndexSymbol {
    /// Adapter-local key, normally package path plus object name.
    pub key: String,
    /// Compiler-qualified name.
    pub qualified_name: String,
    /// Source declaration name.
    pub display_name: String,
    /// `function`, `type`, `interface`, `value`, or `test`.
    pub kind: String,
    /// Repository-relative source file.
    pub file: String,
    /// Exact declaration range.
    pub range: SourceRange,
    /// `go/types` signature.
    pub signature: String,
    /// Name/path-independent digest used only as continuity evidence.
    pub semantic_fingerprint: String,
}

/// Compiler-resolved relation between two index symbol keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoIndexRelation {
    /// Calling/dependent symbol key.
    pub source: String,
    /// Called/dependency symbol key.
    pub target: String,
    /// `calls`, `tested_by`, `imports`, or `uses_type`.
    pub kind: String,
    /// Exact relation source when the compiler provides one.
    pub range: Option<SourceRange>,
}

/// Deterministic output contract of `tools/contextdb-go-indexer`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoCompilerIndex {
    /// Contract version.
    pub schema_version: u16,
    /// Go module path.
    pub module: String,
    /// Package path indexed by this result.
    pub package: String,
    /// Exact sources.
    pub files: Vec<GoSourceFile>,
    /// Compiler symbols.
    pub symbols: Vec<GoIndexSymbol>,
    /// Compiler relations.
    pub relations: Vec<GoIndexRelation>,
}

impl GoCompilerIndex {
    /// Parses strict helper JSON before any durable snapshot is constructed.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(CodeDomainError::PortableIntegrity);
        }
        crate::types::validate_text(&self.module, "go_index.module")?;
        crate::types::validate_text(&self.package, "go_index.package")?;
        let mut paths = BTreeSet::new();
        for file in &self.files {
            let path = RepoPath::new(file.path.clone())?;
            if !paths.insert(path) {
                return Err(CodeDomainError::Duplicate {
                    kind: "go source path",
                    value: file.path.clone(),
                });
            }
        }
        let mut keys = BTreeSet::new();
        for symbol in &self.symbols {
            crate::types::validate_text(&symbol.key, "go_symbol.key")?;
            crate::types::validate_text(&symbol.qualified_name, "go_symbol.qualified_name")?;
            crate::types::validate_text(&symbol.display_name, "go_symbol.display_name")?;
            crate::types::validate_text(&symbol.signature, "go_symbol.signature")?;
            if symbol.semantic_fingerprint.len() != 64
                || !symbol
                    .semantic_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || !paths.contains(&RepoPath::new(symbol.file.clone())?)
                || !keys.insert(symbol.key.clone())
            {
                return Err(CodeDomainError::InvalidContinuity(
                    "invalid Go symbol key, source, or semantic fingerprint",
                ));
            }
            map_symbol_kind(&symbol.kind)?;
        }
        let mut relation_keys = BTreeSet::new();
        for relation in &self.relations {
            if !keys.contains(&relation.source)
                || !keys.contains(&relation.target)
                || !relation_keys.insert((
                    relation.source.clone(),
                    relation.target.clone(),
                    relation.kind.clone(),
                ))
            {
                return Err(CodeDomainError::InvalidRelation);
            }
            map_relation_kind(&relation.kind)?;
        }
        Ok(())
    }
}

/// Converts compiler-helper output into a validated ContextDB code snapshot.
#[derive(Clone, Copy, Debug, Default)]
pub struct GoSnapshotAdapter;

impl GoSnapshotAdapter {
    /// Builds an immutable snapshot and carries stable symbol identities only
    /// when a semantic fingerprint has one unambiguous direct-parent match.
    pub fn build(
        repository: RepositoryId,
        snapshot_id: SnapshotId,
        parent: Option<&RepositorySnapshot>,
        revision: &str,
        observed_at: TimestampMicros,
        index: &GoCompilerIndex,
    ) -> Result<RepositorySnapshot> {
        index.validate()?;
        crate::types::validate_text(revision, "snapshot.revision")?;
        if parent.is_some_and(|value| value.repository != repository) {
            return Err(CodeDomainError::InvalidContinuity(
                "Go adapter parent belongs to another repository",
            ));
        }

        let parent_fingerprints = parent.map(parent_fingerprint_map).unwrap_or_default();
        let mut file_id_by_path = BTreeMap::new();
        let parent_files: BTreeMap<_, _> = parent
            .into_iter()
            .flat_map(|snapshot| snapshot.files.iter())
            .map(|file| (file.path.clone(), file.identity))
            .collect();
        let mut files = Vec::with_capacity(index.files.len());
        for source in &index.files {
            let path = RepoPath::new(source.path.clone())?;
            let identity = match parent_files.get(&path).copied() {
                Some(identity) => identity,
                None => derived_file_id(repository, &path)?,
            };
            file_id_by_path.insert(path.clone(), identity);
            files.push(FileRevision {
                identity,
                path,
                content_digest: ContentDigest::from_bytes(
                    *blake3::hash(source.content.as_bytes()).as_bytes(),
                ),
                content: source.content.as_bytes().to_vec(),
                language: Language::Go,
            });
        }

        let mut symbol_id_by_key = BTreeMap::new();
        let mut symbols = Vec::with_capacity(index.symbols.len());
        for symbol in &index.symbols {
            let matches = parent_fingerprints
                .get(&symbol.semantic_fingerprint)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let (identity, continues_from, confidence) = match matches {
                [identity] => (*identity, Some(*identity), 10_000),
                _ => (
                    derived_symbol_id(repository, &symbol.key, &symbol.semantic_fingerprint)?,
                    None,
                    0,
                ),
            };
            let path = RepoPath::new(symbol.file.clone())?;
            let file = file_id_by_path
                .get(&path)
                .copied()
                .ok_or(CodeDomainError::InvalidRelation)?;
            symbol_id_by_key.insert(symbol.key.clone(), identity);
            symbols.push(SymbolRevision {
                identity,
                file,
                qualified_name: symbol.qualified_name.clone(),
                display_name: symbol.display_name.clone(),
                kind: map_symbol_kind(&symbol.kind)?,
                declaration: symbol.range,
                signature: symbol.signature.clone(),
                semantic_fingerprint: Some(symbol.semantic_fingerprint.clone()),
                continues_from,
                continuity_confidence: confidence,
            });
        }
        let relations = index
            .relations
            .iter()
            .map(|relation| {
                Ok(CodeRelation {
                    source: *symbol_id_by_key
                        .get(&relation.source)
                        .ok_or(CodeDomainError::InvalidRelation)?,
                    target: *symbol_id_by_key
                        .get(&relation.target)
                        .ok_or(CodeDomainError::InvalidRelation)?,
                    kind: map_relation_kind(&relation.kind)?,
                    evidence_range: relation.range,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut snapshot = RepositorySnapshot {
            id: snapshot_id,
            repository,
            parent: parent.map(|value| value.id),
            revision: revision.to_owned(),
            observed_at,
            files,
            symbols,
            relations,
            manifest_digest: ContentDigest::from_bytes([0; 32]),
        };
        snapshot.manifest_digest = CodeMemory::snapshot_manifest(&snapshot)?;
        Ok(snapshot)
    }
}

fn parent_fingerprint_map(parent: &RepositorySnapshot) -> BTreeMap<String, Vec<SymbolIdentity>> {
    let mut result: BTreeMap<String, Vec<_>> = BTreeMap::new();
    for symbol in &parent.symbols {
        let Some(file) = parent
            .files
            .iter()
            .find(|file| file.identity == symbol.file)
        else {
            continue;
        };
        let fingerprint = semantic_fingerprint_from_source(file, symbol);
        result.entry(fingerprint).or_default().push(symbol.identity);
    }
    result
}

fn semantic_fingerprint_from_source(file: &FileRevision, symbol: &SymbolRevision) -> String {
    symbol.semantic_fingerprint.clone().unwrap_or_else(|| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"contextdb-go-parent-fallback-v1\0");
        hasher.update(file.content_digest.as_bytes());
        hasher.update(symbol.display_name.as_bytes());
        hasher.finalize().to_hex().to_string()
    })
}

fn derived_file_id(repository: RepositoryId, path: &RepoPath) -> Result<FileIdentity> {
    FileIdentity::from_uuid(derived_uuid(
        b"contextdb-code-file-v1",
        &[repository.as_uuid().as_bytes(), path.as_str().as_bytes()],
    ))
}

fn derived_symbol_id(
    repository: RepositoryId,
    key: &str,
    fingerprint: &str,
) -> Result<SymbolIdentity> {
    SymbolIdentity::from_uuid(derived_uuid(
        b"contextdb-code-symbol-v1",
        &[
            repository.as_uuid().as_bytes(),
            key.as_bytes(),
            fingerprint.as_bytes(),
        ],
    ))
}

fn derived_uuid(domain: &[u8], values: &[&[u8]]) -> Uuid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for value in values {
        hasher.update(&[0]);
        hasher.update(value);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[15] = 1;
    }
    Uuid::from_bytes(bytes)
}

fn map_symbol_kind(value: &str) -> Result<SymbolKind> {
    match value {
        "function" => Ok(SymbolKind::Function),
        "type" => Ok(SymbolKind::Type),
        "interface" => Ok(SymbolKind::Interface),
        "value" => Ok(SymbolKind::Value),
        "test" => Ok(SymbolKind::Test),
        _ => Err(CodeDomainError::InvalidText("go_symbol.kind")),
    }
}

fn map_relation_kind(value: &str) -> Result<CodeRelationKind> {
    match value {
        "calls" => Ok(CodeRelationKind::Calls),
        "tested_by" => Ok(CodeRelationKind::TestedBy),
        "imports" => Ok(CodeRelationKind::Imports),
        "uses_type" => Ok(CodeRelationKind::UsesType),
        _ => Err(CodeDomainError::InvalidText("go_relation.kind")),
    }
}
