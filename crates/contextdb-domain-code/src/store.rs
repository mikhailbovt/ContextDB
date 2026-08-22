use std::collections::{BTreeMap, BTreeSet, VecDeque};

use contextdb_core::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::{
    CiRun, CodeDomainError, CodeQuery, CodeQueryResult, CodeRelation, CodeRelationKind,
    DecisionRecord, ImpactReport, PreflightReport, RationaleResult, RepositoryDescriptor,
    RepositoryHierarchy, RepositoryId, RepositorySnapshot, ResolvedCodeLocation, Result,
    SnapshotId, SymbolIdentity, SymbolRevision, digest_json,
};

const SNAPSHOT_DOMAIN: &[u8] = b"contextdb-code-snapshot-v1";
const PORTABLE_DOMAIN: &[u8] = b"contextdb-code-portable-v1";

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeState {
    repositories: BTreeMap<RepositoryId, RepositoryDescriptor>,
    snapshots: BTreeMap<SnapshotId, RepositorySnapshot>,
    heads: BTreeMap<RepositoryId, SnapshotId>,
    decisions: BTreeMap<DecisionId, DecisionRecord>,
    ci_runs: BTreeMap<CiRunId, CiRun>,
}

/// Self-verifying portable coding-domain archive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableCodeMemory {
    /// Archive format version.
    pub schema_version: u16,
    /// Digest of the exact payload.
    pub payload_digest: ContentDigest,
    /// Canonical JSON state bytes.
    pub payload: Vec<u8>,
}

/// Deterministic reference store for repository/compiler/Git/CI memory.
#[derive(Clone, Debug, Default)]
pub struct CodeMemory {
    state: CodeState,
}

impl CodeMemory {
    /// Creates an empty domain store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns one immutable snapshot for an adapter continuity pass.
    #[must_use]
    pub fn snapshot(&self, id: SnapshotId) -> Option<&RepositorySnapshot> {
        self.state.snapshots.get(&id)
    }

    /// Registers one repository before snapshots are ingested.
    pub fn register_repository(&mut self, repository: RepositoryDescriptor) -> Result<()> {
        crate::types::validate_text(&repository.name, "repository.name")?;
        if let Some(origin) = &repository.origin {
            crate::types::validate_text(origin, "repository.origin")?;
        }
        if self
            .state
            .repositories
            .insert(repository.id, repository)
            .is_some()
        {
            return Err(CodeDomainError::Duplicate {
                kind: "repository",
                value: "stable-id".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical manifest digest adapters must place in a snapshot.
    pub fn snapshot_manifest(snapshot: &RepositorySnapshot) -> Result<ContentDigest> {
        #[derive(Serialize)]
        struct Manifest<'a> {
            id: SnapshotId,
            repository: RepositoryId,
            parent: Option<SnapshotId>,
            revision: &'a str,
            observed_at: contextdb_core::TimestampMicros,
            files: &'a [crate::FileRevision],
            symbols: &'a [SymbolRevision],
            relations: &'a [CodeRelation],
        }
        digest_json(
            SNAPSHOT_DOMAIN,
            &Manifest {
                id: snapshot.id,
                repository: snapshot.repository,
                parent: snapshot.parent,
                revision: &snapshot.revision,
                observed_at: snapshot.observed_at,
                files: &snapshot.files,
                symbols: &snapshot.symbols,
                relations: &snapshot.relations,
            },
        )
    }

    /// Validates and atomically ingests one immutable compiler/Git snapshot.
    pub fn ingest_snapshot(&mut self, snapshot: RepositorySnapshot) -> Result<()> {
        if !self.state.repositories.contains_key(&snapshot.repository) {
            return Err(unknown("repository", snapshot.repository));
        }
        if self.state.snapshots.contains_key(&snapshot.id) {
            return Err(CodeDomainError::Duplicate {
                kind: "snapshot",
                value: snapshot.id.to_string(),
            });
        }
        if self.state.heads.get(&snapshot.repository).copied() != snapshot.parent {
            return Err(CodeDomainError::StaleParent);
        }
        crate::types::validate_text(&snapshot.revision, "snapshot.revision")?;
        if Self::snapshot_manifest(&snapshot)? != snapshot.manifest_digest {
            return Err(CodeDomainError::PortableIntegrity);
        }

        let mut file_ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut file_by_id = BTreeMap::new();
        for file in &snapshot.files {
            if !file_ids.insert(file.identity) || !paths.insert(file.path.clone()) {
                return Err(CodeDomainError::Duplicate {
                    kind: "file",
                    value: file.path.to_string(),
                });
            }
            let expected = ContentDigest::from_bytes(*blake3::hash(&file.content).as_bytes());
            if expected != file.content_digest {
                return Err(CodeDomainError::ContentDigestMismatch(
                    file.path.to_string(),
                ));
            }
            file_by_id.insert(file.identity, file);
        }

        let parent_symbols = snapshot
            .parent
            .and_then(|parent| self.state.snapshots.get(&parent))
            .map(|parent| {
                parent
                    .symbols
                    .iter()
                    .map(|symbol| (symbol.identity, symbol))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let mut symbol_ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for symbol in &snapshot.symbols {
            crate::types::validate_text(&symbol.qualified_name, "symbol.qualified_name")?;
            crate::types::validate_text(&symbol.display_name, "symbol.display_name")?;
            crate::types::validate_text(&symbol.signature, "symbol.signature")?;
            if symbol.semantic_fingerprint.as_ref().is_some_and(|value| {
                value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            }) {
                return Err(CodeDomainError::InvalidContinuity(
                    "invalid semantic fingerprint",
                ));
            }
            if symbol.continuity_confidence > 10_000
                || !symbol_ids.insert(symbol.identity)
                || !names.insert(symbol.qualified_name.clone())
            {
                return Err(CodeDomainError::InvalidContinuity(
                    "duplicate or invalid-confidence symbol revision",
                ));
            }
            let Some(file) = file_by_id.get(&symbol.file) else {
                return Err(CodeDomainError::InvalidRange {
                    path: "<unknown-file>".to_owned(),
                });
            };
            if extract_source_range(&file.content, symbol.declaration).is_none() {
                return Err(CodeDomainError::InvalidRange {
                    path: file.path.to_string(),
                });
            }
            match (snapshot.parent, symbol.continues_from) {
                (None, None) => {}
                (Some(_), Some(previous))
                    if previous == symbol.identity && parent_symbols.contains_key(&previous) => {}
                (Some(_), None) if !parent_symbols.contains_key(&symbol.identity) => {}
                _ => {
                    return Err(CodeDomainError::InvalidContinuity(
                        "continued identity is absent from the direct parent",
                    ));
                }
            }
        }
        let mut relations = BTreeSet::new();
        for relation in &snapshot.relations {
            if !symbol_ids.contains(&relation.source)
                || !symbol_ids.contains(&relation.target)
                || !relations.insert((relation.source, relation.target, relation.kind))
            {
                return Err(CodeDomainError::InvalidRelation);
            }
        }
        let repository = snapshot.repository;
        let id = snapshot.id;
        self.state.snapshots.insert(id, snapshot);
        self.state.heads.insert(repository, id);
        Ok(())
    }

    /// Adds one evidence-backed decision; absence is represented as unknown.
    pub fn add_decision(&mut self, decision: DecisionRecord) -> Result<()> {
        if !self.state.repositories.contains_key(&decision.repository)
            || !self
                .state
                .snapshots
                .contains_key(&decision.effective_snapshot)
            || decision.evidence.is_empty()
        {
            return Err(CodeDomainError::InvalidRelation);
        }
        crate::types::validate_text(&decision.title, "decision.title")?;
        crate::types::validate_text(&decision.rationale, "decision.rationale")?;
        if self.state.decisions.insert(decision.id, decision).is_some() {
            return Err(CodeDomainError::Duplicate {
                kind: "decision",
                value: "stable-id".to_owned(),
            });
        }
        Ok(())
    }

    /// Adds one CI result after checking referenced snapshot and test symbols.
    pub fn add_ci_run(&mut self, run: CiRun) -> Result<()> {
        let Some(snapshot) = self.state.snapshots.get(&run.snapshot) else {
            return Err(unknown("snapshot", run.snapshot));
        };
        let symbols: BTreeSet<_> = snapshot
            .symbols
            .iter()
            .map(|symbol| symbol.identity)
            .collect();
        if !run.tests.is_subset(&symbols) || run.evidence.is_empty() {
            return Err(CodeDomainError::InvalidRelation);
        }
        if self.state.ci_runs.insert(run.id, run).is_some() {
            return Err(CodeDomainError::Duplicate {
                kind: "ci_run",
                value: "stable-id".to_owned(),
            });
        }
        Ok(())
    }

    /// Resolves current or historical code with explicit unknown rationale.
    pub fn query(&self, repository: RepositoryId, query: &CodeQuery) -> Result<CodeQueryResult> {
        query.validate()?;
        let snapshot_id = query
            .at_snapshot
            .or_else(|| self.state.heads.get(&repository).copied())
            .ok_or_else(|| unknown("repository head", repository))?;
        let snapshot = self
            .state
            .snapshots
            .get(&snapshot_id)
            .ok_or_else(|| unknown("snapshot", snapshot_id))?;
        if snapshot.repository != repository {
            return Err(unknown("snapshot in repository", snapshot_id));
        }
        let normalized = query.symbol.to_lowercase();
        let matches: Vec<_> = snapshot
            .symbols
            .iter()
            .filter(|symbol| {
                symbol.qualified_name.to_lowercase() == normalized
                    || symbol.display_name.to_lowercase() == normalized
                    || symbol
                        .qualified_name
                        .to_lowercase()
                        .ends_with(&format!(".{normalized}"))
            })
            .collect();
        let symbol = match matches.as_slice() {
            [symbol] => *symbol,
            [] => return Err(unknown("symbol", &query.symbol)),
            _ => return Err(CodeDomainError::AmbiguousSymbol),
        };
        let location = resolve_location(snapshot, symbol)?;
        let mut history = self.symbol_history(repository, symbol.identity, snapshot_id)?;
        if history.last() != Some(&location) {
            history.push(location.clone());
        }
        let rationale = if query.include_rationale {
            self.rationale(repository, symbol.identity, snapshot_id)
        } else {
            RationaleResult::Unknown
        };
        let impact = if query.include_impact {
            Some(self.impact(snapshot, symbol.identity, query.max_relation_visits))
        } else {
            None
        };
        Ok(CodeQueryResult {
            location,
            history,
            rationale,
            impact,
        })
    }

    /// Builds the exact repository/file/symbol hierarchy for one snapshot.
    pub fn hierarchy(
        &self,
        repository: RepositoryId,
        at_snapshot: Option<SnapshotId>,
    ) -> Result<RepositoryHierarchy> {
        let snapshot_id = at_snapshot
            .or_else(|| self.state.heads.get(&repository).copied())
            .ok_or_else(|| unknown("repository head", repository))?;
        let snapshot = self
            .state
            .snapshots
            .get(&snapshot_id)
            .filter(|snapshot| snapshot.repository == repository)
            .ok_or_else(|| unknown("snapshot in repository", snapshot_id))?;
        let mut files: BTreeMap<_, BTreeSet<_>> = snapshot
            .files
            .iter()
            .map(|file| (file.path.clone(), BTreeSet::new()))
            .collect();
        let paths: BTreeMap<_, _> = snapshot
            .files
            .iter()
            .map(|file| (file.identity, file.path.clone()))
            .collect();
        for symbol in &snapshot.symbols {
            let path = paths
                .get(&symbol.file)
                .ok_or(CodeDomainError::InvalidRelation)?;
            files
                .get_mut(path)
                .ok_or(CodeDomainError::InvalidRelation)?
                .insert(symbol.identity);
        }
        Ok(RepositoryHierarchy {
            snapshot: snapshot_id,
            files,
        })
    }

    /// Runs a bounded current-state compiler impact analysis and attaches only
    /// actually retained CI execution evidence.
    pub fn preflight(
        &self,
        repository: RepositoryId,
        symbol: &str,
        max_relation_visits: usize,
    ) -> Result<PreflightReport> {
        let result = self.query(
            repository,
            &CodeQuery {
                symbol: symbol.to_owned(),
                at_snapshot: None,
                include_rationale: false,
                include_impact: true,
                max_relation_visits,
            },
        )?;
        let impact = result.impact.ok_or(CodeDomainError::InvalidRelation)?;
        let latest_ci = self
            .state
            .ci_runs
            .values()
            .filter(|run| {
                run.snapshot == result.location.snapshot && !run.tests.is_disjoint(&impact.tests)
            })
            .max_by_key(|run| run.id);
        Ok(PreflightReport {
            location: result.location,
            impact,
            latest_ci_passed: latest_ci.map(|run| run.passed),
            ci_evidence: latest_ci
                .map(|run| run.evidence.clone())
                .unwrap_or_default(),
            missing_test_execution_evidence: latest_ci.is_none(),
        })
    }

    /// Exports all retained coding state as one canonical, self-verifying archive.
    pub fn export_portable(&self) -> Result<PortableCodeMemory> {
        let payload = serde_json::to_vec(&self.state)?;
        Ok(PortableCodeMemory {
            schema_version: crate::FORMAT_VERSION,
            payload_digest: digest_json(PORTABLE_DOMAIN, &self.state)?,
            payload,
        })
    }

    /// Restores a portable archive after replaying all nested validation.
    pub fn from_portable(portable: &PortableCodeMemory) -> Result<Self> {
        if portable.schema_version != crate::FORMAT_VERSION {
            return Err(CodeDomainError::PortableIntegrity);
        }
        let state: CodeState = serde_json::from_slice(&portable.payload)?;
        if digest_json(PORTABLE_DOMAIN, &state)? != portable.payload_digest {
            return Err(CodeDomainError::PortableIntegrity);
        }
        let mut rebuilt = Self::new();
        for repository in state.repositories.values() {
            rebuilt.register_repository(repository.clone())?;
        }
        let mut remaining = state.snapshots.clone();
        while !remaining.is_empty() {
            let ready: Vec<_> = remaining
                .iter()
                .filter(|(_, snapshot)| {
                    rebuilt.state.heads.get(&snapshot.repository).copied() == snapshot.parent
                })
                .map(|(id, _)| *id)
                .collect();
            if ready.is_empty() {
                return Err(CodeDomainError::PortableIntegrity);
            }
            for id in ready {
                let snapshot = remaining
                    .remove(&id)
                    .ok_or(CodeDomainError::PortableIntegrity)?;
                rebuilt.ingest_snapshot(snapshot)?;
            }
        }
        for decision in state.decisions.values() {
            rebuilt.add_decision(decision.clone())?;
        }
        for run in state.ci_runs.values() {
            rebuilt.add_ci_run(run.clone())?;
        }
        if rebuilt.state != state {
            return Err(CodeDomainError::PortableIntegrity);
        }
        Ok(rebuilt)
    }

    fn symbol_history(
        &self,
        repository: RepositoryId,
        identity: SymbolIdentity,
        through: SnapshotId,
    ) -> Result<Vec<ResolvedCodeLocation>> {
        let mut chain = Vec::new();
        let mut current = Some(through);
        while let Some(snapshot_id) = current {
            let snapshot = self
                .state
                .snapshots
                .get(&snapshot_id)
                .ok_or_else(|| unknown("snapshot", snapshot_id))?;
            if snapshot.repository != repository {
                return Err(CodeDomainError::InvalidContinuity(
                    "cross-repository history",
                ));
            }
            if let Some(symbol) = snapshot
                .symbols
                .iter()
                .find(|symbol| symbol.identity == identity)
            {
                chain.push(resolve_location(snapshot, symbol)?);
            }
            current = snapshot.parent;
        }
        chain.reverse();
        Ok(chain)
    }

    fn rationale(
        &self,
        repository: RepositoryId,
        identity: SymbolIdentity,
        snapshot: SnapshotId,
    ) -> RationaleResult {
        let ancestors = self.ancestor_set(snapshot);
        let mut decisions: Vec<_> = self
            .state
            .decisions
            .values()
            .filter(|decision| {
                decision.repository == repository
                    && decision.affected_symbols.contains(&identity)
                    && ancestors.contains(&decision.effective_snapshot)
                    && decision
                        .superseded_at
                        .is_none_or(|end| !ancestors.contains(&end))
            })
            .collect();
        decisions.sort_by_key(|decision| decision.id);
        if decisions.is_empty() {
            return RationaleResult::Unknown;
        }
        RationaleResult::Supported {
            text: decisions
                .iter()
                .map(|decision| decision.rationale.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            decisions: decisions.iter().map(|decision| decision.id).collect(),
            evidence: decisions
                .iter()
                .flat_map(|decision| decision.evidence.iter().copied())
                .collect(),
        }
    }

    fn impact(
        &self,
        snapshot: &RepositorySnapshot,
        selected: SymbolIdentity,
        max_visits: usize,
    ) -> ImpactReport {
        let mut affected = BTreeSet::new();
        let mut tests = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        let mut queue = VecDeque::from([selected]);
        let mut visited_nodes = BTreeSet::from([selected]);
        let mut visits = 0;
        let mut truncated = false;
        while let Some(current) = queue.pop_front() {
            for relation in &snapshot.relations {
                let dependent = match relation.kind {
                    CodeRelationKind::Calls
                    | CodeRelationKind::Imports
                    | CodeRelationKind::UsesType
                        if relation.target == current =>
                    {
                        Some(relation.source)
                    }
                    CodeRelationKind::TestedBy if relation.source == current => {
                        tests.insert(relation.target);
                        Some(relation.target)
                    }
                    _ => None,
                };
                let Some(dependent) = dependent else { continue };
                if visits == max_visits {
                    truncated = true;
                    break;
                }
                visits += 1;
                kinds.insert(relation.kind);
                if dependent != selected {
                    affected.insert(dependent);
                }
                if visited_nodes.insert(dependent) {
                    queue.push_back(dependent);
                }
            }
            if truncated {
                break;
            }
        }
        ImpactReport {
            affected_symbols: affected,
            tests,
            relation_kinds: kinds,
            relation_visits: visits,
            truncated,
        }
    }

    fn ancestor_set(&self, snapshot: SnapshotId) -> BTreeSet<SnapshotId> {
        let mut ancestors = BTreeSet::new();
        let mut current = Some(snapshot);
        while let Some(id) = current {
            if !ancestors.insert(id) {
                break;
            }
            current = self.state.snapshots.get(&id).and_then(|value| value.parent);
        }
        ancestors
    }
}

fn resolve_location(
    snapshot: &RepositorySnapshot,
    symbol: &SymbolRevision,
) -> Result<ResolvedCodeLocation> {
    let file = snapshot
        .files
        .iter()
        .find(|file| file.identity == symbol.file)
        .ok_or(CodeDomainError::InvalidRelation)?;
    let source_text = extract_source_range(&file.content, symbol.declaration).ok_or_else(|| {
        CodeDomainError::InvalidRange {
            path: file.path.to_string(),
        }
    })?;
    let source_digest = ContentDigest::from_bytes(*blake3::hash(source_text.as_bytes()).as_bytes());
    Ok(ResolvedCodeLocation {
        symbol: symbol.identity,
        qualified_name: symbol.qualified_name.clone(),
        kind: symbol.kind.clone(),
        path: file.path.clone(),
        declaration: symbol.declaration,
        signature: symbol.signature.clone(),
        source_text,
        source_digest,
        snapshot: snapshot.id,
        revision: snapshot.revision.clone(),
        observed_at: snapshot.observed_at,
    })
}

fn extract_source_range(content: &[u8], range: crate::SourceRange) -> Option<String> {
    let text = std::str::from_utf8(content).ok()?;
    let lines: Vec<_> = text.split('\n').collect();
    let start_index = usize::try_from(range.start_line.checked_sub(1)?).ok()?;
    let end_index = usize::try_from(range.end_line.checked_sub(1)?).ok()?;
    if start_index > end_index {
        return None;
    }
    let start_line = lines.get(start_index)?;
    let end_line = lines.get(end_index)?;
    let start_column = usize::try_from(range.start_column).ok()?;
    let end_column = usize::try_from(range.end_column).ok()?;
    let start_chars: Vec<_> = start_line.chars().collect();
    let end_chars: Vec<_> = end_line.chars().collect();
    if start_column > start_chars.len()
        || end_column > end_chars.len()
        || (start_index == end_index && start_column >= end_column)
    {
        return None;
    }
    if start_index == end_index {
        return Some(start_chars[start_column..end_column].iter().collect());
    }
    let mut selected: String = start_chars[start_column..].iter().collect();
    for line in &lines[start_index + 1..end_index] {
        selected.push('\n');
        selected.push_str(line);
    }
    selected.push('\n');
    selected.extend(end_chars[..end_column].iter());
    Some(selected)
}

fn unknown(kind: &'static str, id: impl std::fmt::Display) -> CodeDomainError {
    CodeDomainError::Unknown {
        kind,
        id: id.to_string(),
    }
}

use crate::{CiRunId, DecisionId};
