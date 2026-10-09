use super::*;
use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterLineageKind {
    Workspace,
    Project,
    Entity,
    Session,
    Run,
    SourceVersion,
    DerivedView,
    Query,
    Evaluation,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterLineageRef {
    pub kind: RouterLineageKind,
    pub domain: String,
    pub id: String,
    pub version: Option<String>,
}
impl RouterLineageRef {
    pub(super) fn validate(&self) -> Result<()> {
        identity(&self.domain)?;
        identity(&self.id)?;
        if let Some(version) = &self.version {
            identity(version)?;
        }
        if self.kind == RouterLineageKind::SourceVersion && self.version.is_none() {
            return Err(invalid());
        }
        Ok(())
    }
}
impl std::fmt::Debug for RouterLineageRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterLineageRef")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterLineageNode {
    pub reference: RouterLineageRef,
    pub available_at: u64,
    pub parents: Vec<RouterLineageRef>,
}
impl std::fmt::Debug for RouterLineageNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterLineageNode")
            .field("kind", &self.reference.kind)
            .field("available_at", &self.available_at)
            .field("parents", &self.parents.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterExampleLineage {
    pub example_id: String,
    pub logical_domain: String,
    pub cutoff: u64,
    /// Query-time dependencies, including discarded candidates and derived views.
    pub roots: Vec<RouterLineageRef>,
}
impl std::fmt::Debug for RouterExampleLineage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterExampleLineage")
            .field("cutoff", &self.cutoff)
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterTimeCutoffs {
    pub train_until: u64,
    pub validation_until: u64,
}

/// Each logical sequence domain has explicitly declared cutoffs; numbers from
/// unrelated domains are never ordered against one another.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterSplitSpec {
    pub domains: BTreeMap<String, RouterTimeCutoffs>,
}
impl std::fmt::Debug for RouterSplitSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterSplitSpec")
            .field("domains", &self.domains.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterPartition {
    Train,
    Validation,
    Test,
    Quarantined,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterSplitAssignment {
    pub example_id: String,
    pub group_digest: ContentDigest,
    pub partition: RouterPartition,
    pub window_start: u64,
    pub window_end: u64,
}
impl std::fmt::Debug for RouterSplitAssignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterSplitAssignment")
            .field("group", &self.group_digest)
            .field("partition", &self.partition)
            .field("window_start", &self.window_start)
            .field("window_end", &self.window_end)
            .finish_non_exhaustive()
    }
}

struct Components(Vec<usize>);
impl Components {
    fn root(&mut self, id: usize) -> usize {
        let mut at = id;
        while self.0[at] != at {
            at = self.0[at];
        }
        let root = at;
        let mut at = id;
        while self.0[at] != at {
            let next = self.0[at];
            self.0[at] = root;
            at = next;
        }
        root
    }
    fn join(&mut self, left: usize, right: usize) {
        let a = self.root(left);
        let b = self.root(right);
        self.0[a.max(b)] = a.min(b);
    }
}

pub fn assign_router_group_time_split(
    nodes: &[RouterLineageNode],
    examples: &[RouterExampleLineage],
    spec: &RouterSplitSpec,
    budget: &mut QueryBudget,
) -> Result<Vec<RouterSplitAssignment>> {
    if nodes.len() > MAX_ROUTER_LINEAGE_NODES
        || examples.len() > MAX_ROUTER_EXAMPLES
        || spec.domains.len() > MAX_ROUTER_EXAMPLES
    {
        return Err(invalid());
    }
    bounded_size(&(nodes, examples, spec), MAX_ROUTER_EXAMPLE_BYTES, budget)?;
    for (domain, cutoff) in &spec.domains {
        identity(domain)?;
        if cutoff.train_until >= cutoff.validation_until {
            return Err(invalid());
        }
    }
    let mut index = BTreeMap::new();
    let mut components = Components((0..nodes.len()).collect());
    for (at, node) in nodes.iter().enumerate() {
        charge(budget, 1, 0)?;
        node.reference.validate()?;
        if !spec.domains.contains_key(&node.reference.domain)
            || node.parents.len() > 64
            || node.parents.windows(2).any(|pair| pair[0] >= pair[1])
            || index.insert(&node.reference, at).is_some()
        {
            return Err(invalid());
        }
    }
    let mut children = vec![Vec::new(); nodes.len()];
    let mut incoming = vec![0usize; nodes.len()];
    let mut identities = BTreeMap::new();
    for (at, node) in nodes.iter().enumerate() {
        charge(budget, node.parents.len() as u64 + 1, 0)?;
        if matches!(
            node.reference.kind,
            RouterLineageKind::Workspace
                | RouterLineageKind::Project
                | RouterLineageKind::Entity
                | RouterLineageKind::Session
                | RouterLineageKind::Run
                | RouterLineageKind::SourceVersion
        ) {
            let key = (
                node.reference.kind,
                &node.reference.domain,
                &node.reference.id,
            );
            if let Some(previous) = identities.insert(key, at) {
                components.join(at, previous);
            }
        }
        for parent in &node.parents {
            let previous = *index.get(parent).ok_or_else(invalid)?;
            if parent.domain != node.reference.domain
                || nodes[previous].available_at > node.available_at
            {
                return Err(invalid());
            }
            components.join(at, previous);
            children[previous].push(at);
            incoming[at] += 1;
        }
    }
    let mut ready: VecDeque<_> = incoming
        .iter()
        .enumerate()
        .filter_map(|(at, count)| (*count == 0).then_some(at))
        .collect();
    let mut visited = 0;
    while let Some(at) = ready.pop_front() {
        charge(budget, children[at].len() as u64 + 1, 0)?;
        visited += 1;
        for child in &children[at] {
            incoming[*child] -= 1;
            if incoming[*child] == 0 {
                ready.push_back(*child);
            }
        }
    }
    if visited != nodes.len() {
        return Err(invalid());
    }
    let mut example_ids = BTreeSet::new();
    let mut root_by_example = Vec::new();
    for example in examples {
        identity(&example.example_id)?;
        identity(&example.logical_domain)?;
        charge(budget, example.roots.len() as u64 + 1, 0)?;
        if !example_ids.insert(&example.example_id)
            || example.roots.is_empty()
            || example.roots.len() > MAX_ROUTER_LINEAGE_NODES
            || example.roots.windows(2).any(|pair| pair[0] >= pair[1])
            || !spec.domains.contains_key(&example.logical_domain)
        {
            return Err(invalid());
        }
        let mut first = None;
        for root in &example.roots {
            let at = *index.get(root).ok_or_else(invalid)?;
            if root.domain != example.logical_domain || nodes[at].available_at > example.cutoff {
                return Err(invalid());
            }
            if let Some(previous) = first {
                components.join(previous, at);
            } else {
                first = Some(at);
            }
        }
        let mut pending: Vec<_> = example
            .roots
            .iter()
            .map(|root| index.get(root).copied().ok_or_else(invalid))
            .collect::<Result<_>>()?;
        let mut checked = BTreeSet::new();
        while let Some(at) = pending.pop() {
            charge(budget, nodes[at].parents.len() as u64 + 1, 0)?;
            if !checked.insert(at) {
                continue;
            }
            if nodes[at].reference.kind == RouterLineageKind::Evaluation {
                return Err(invalid());
            }
            for parent in &nodes[at].parents {
                pending.push(*index.get(parent).ok_or_else(invalid)?);
            }
        }
        root_by_example.push(first.ok_or_else(invalid)?);
    }
    let mut groups: BTreeMap<usize, Vec<&RouterLineageNode>> = BTreeMap::new();
    for (at, node) in nodes.iter().enumerate() {
        charge(budget, 1, 0)?;
        groups.entry(components.root(at)).or_default().push(node);
    }
    let mut group_end = BTreeMap::<usize, u64>::new();
    for (example, at) in examples.iter().zip(&root_by_example) {
        charge(budget, 1, 0)?;
        let end = group_end.entry(components.root(*at)).or_default();
        *end = (*end).max(example.cutoff);
    }
    let mut group_metadata = BTreeMap::new();
    for (root, members) in &groups {
        charge(budget, members.len() as u64 + 1, 0)?;
        let mut references: Vec<_> = members.iter().map(|node| &node.reference).collect();
        references.sort();
        let start = members
            .iter()
            .map(|node| node.available_at)
            .min()
            .ok_or_else(invalid)?;
        let end = members
            .iter()
            .map(|node| node.available_at)
            .max()
            .unwrap_or(start)
            .max(group_end.get(root).copied().unwrap_or(start));
        group_metadata.insert(*root, (digest(&references, budget)?, start, end));
    }
    let mut result = Vec::new();
    for (example, at) in examples.iter().zip(root_by_example) {
        charge(budget, 1, 0)?;
        let root = components.root(at);
        let (group_digest, start, end) = *group_metadata.get(&root).ok_or_else(invalid)?;
        let cutoff = spec
            .domains
            .get(&example.logical_domain)
            .ok_or_else(invalid)?;
        let partition = if end <= cutoff.train_until {
            RouterPartition::Train
        } else if start > cutoff.train_until && end <= cutoff.validation_until {
            RouterPartition::Validation
        } else if start > cutoff.validation_until {
            RouterPartition::Test
        } else {
            RouterPartition::Quarantined
        };
        result.push(RouterSplitAssignment {
            example_id: example.example_id.clone(),
            group_digest,
            partition,
            window_start: start,
            window_end: end,
        });
    }
    result.sort_by(|a, b| a.example_id.cmp(&b.example_id));
    Ok(result)
}

/// Associates all query-time roots before split assignment; target artifacts stay
/// in their own later lineage and cannot become a feature derivation parent.
pub fn validate_router_example_lineage(
    input: &RouterQueryTimeRecord,
    lineage: &RouterExampleLineage,
) -> Result<()> {
    if lineage.example_id != input.query.id
        || lineage.logical_domain != input.query.logical_domain
        || lineage.cutoff != input.query.known_at
        || lineage.roots != input.observation.source_nodes
        || lineage
            .roots
            .iter()
            .any(|root| root.kind == RouterLineageKind::Evaluation)
    {
        return Err(invalid());
    }
    Ok(())
}
