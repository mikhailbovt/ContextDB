use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    ActorId, ArtifactId, CandidateId, ClaimId, ConflictSetId, ContextPackId, DerivationId, EdgeId,
    EpisodeViewId, EvidenceId, ModelCallId, NodeId, ObservationId, SummaryId, Validate,
    ValidationError, ValidationResult,
};

/// One-based revision number with a stable integer representation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RevisionNumber(u32);

impl RevisionNumber {
    /// The first revision in every chain.
    pub const FIRST: Self = Self(1);

    /// Creates a one-based revision number.
    pub fn new(value: u32) -> ValidationResult<Self> {
        if value == 0 {
            return Err(ValidationError::InvalidRevisionSequence);
        }
        Ok(Self(value))
    }

    /// Returns the integer representation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns the next revision, or `None` at integer exhaustion.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl<'de> Deserialize<'de> for RevisionNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Identifies the deterministic or model-assisted pipeline that produced data.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineIdentity {
    pub name: String,
    pub version: String,
    pub schema_version: String,
}

impl Validate for PipelineIdentity {
    fn validate(&self) -> ValidationResult {
        validate_non_blank(&self.name, "pipeline.name")?;
        validate_non_blank(&self.version, "pipeline.version")?;
        validate_non_blank(&self.schema_version, "pipeline.schema_version")
    }
}

/// Mechanism that produced a derived logical value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationKind {
    ActorAssertion,
    DeterministicProjector,
    ModelExtraction,
    Consolidation,
    HumanAdjudication,
    Migration,
    Import,
}

/// A stable reference to a versioned or immutable memory item.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LineageNode {
    Observation {
        id: ObservationId,
    },
    EpisodeView {
        id: EpisodeViewId,
        revision: RevisionNumber,
    },
    Artifact {
        id: ArtifactId,
    },
    Evidence {
        id: EvidenceId,
    },
    NodeRevision {
        id: NodeId,
        revision: RevisionNumber,
    },
    ClaimRevision {
        id: ClaimId,
        revision: RevisionNumber,
    },
    EdgeRevision {
        id: EdgeId,
        revision: RevisionNumber,
    },
    ConflictRevision {
        id: ConflictSetId,
        revision: RevisionNumber,
    },
    ContinuityProfile {
        id: crate::ContinuityProfileId,
        revision: RevisionNumber,
    },
    Candidate {
        id: CandidateId,
    },
    Summary {
        id: SummaryId,
    },
    ContextPack {
        id: ContextPackId,
    },
    External {
        namespace: String,
        identifier: String,
    },
}

impl Validate for LineageNode {
    fn validate(&self) -> ValidationResult {
        if let Self::External {
            namespace,
            identifier,
        } = self
        {
            validate_non_blank(namespace, "lineage.namespace")?;
            validate_non_blank(identifier, "lineage.identifier")?;
        }
        Ok(())
    }
}

/// Complete provenance attached to a semantic revision or derived projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationRef {
    pub id: DerivationId,
    pub kind: DerivationKind,
    pub actor: Option<ActorId>,
    pub model_call: Option<ModelCallId>,
    pub pipeline: PipelineIdentity,
    pub inputs: Vec<LineageNode>,
}

impl DerivationRef {
    /// Ensures the target is not one of its own direct supports.
    pub fn validate_for(&self, target: &LineageNode) -> ValidationResult {
        self.validate()?;
        if self.inputs.iter().any(|input| input == target) {
            return Err(ValidationError::SelfSupportingLineage);
        }
        Ok(())
    }
}

impl Validate for DerivationRef {
    fn validate(&self) -> ValidationResult {
        self.pipeline.validate()?;
        for input in &self.inputs {
            input.validate()?;
        }
        if self.kind == DerivationKind::ActorAssertion && self.actor.is_none() {
            return Err(ValidationError::InvalidAssertionDerivation);
        }
        if self.kind == DerivationKind::ModelExtraction && self.model_call.is_none() {
            return Err(ValidationError::InvalidState {
                reason: "model extraction requires model_call",
            });
        }
        Ok(())
    }
}

/// Directed dependency from a derived item to one of its supports.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageEdge {
    pub derived: LineageNode,
    pub source: LineageNode,
}

/// A pure logical lineage graph used to reject support cycles before commit.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageGraph {
    pub edges: Vec<LineageEdge>,
}

impl Validate for LineageGraph {
    fn validate(&self) -> ValidationResult {
        let mut adjacency: BTreeMap<&LineageNode, Vec<&LineageNode>> = BTreeMap::new();
        for edge in &self.edges {
            edge.derived.validate()?;
            edge.source.validate()?;
            if edge.derived == edge.source {
                return Err(ValidationError::SelfSupportingLineage);
            }
            adjacency
                .entry(&edge.derived)
                .or_default()
                .push(&edge.source);
            adjacency.entry(&edge.source).or_default();
        }

        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for node in adjacency.keys().copied() {
            visit_lineage(node, &adjacency, &mut visiting, &mut visited)?;
        }
        Ok(())
    }
}

fn visit_lineage<'a>(
    node: &'a LineageNode,
    adjacency: &BTreeMap<&'a LineageNode, Vec<&'a LineageNode>>,
    visiting: &mut BTreeSet<&'a LineageNode>,
    visited: &mut BTreeSet<&'a LineageNode>,
) -> ValidationResult {
    if visited.contains(node) {
        return Ok(());
    }
    if !visiting.insert(node) {
        return Err(ValidationError::LineageCycle);
    }
    if let Some(sources) = adjacency.get(node) {
        for source in sources {
            visit_lineage(source, adjacency, visiting, visited)?;
        }
    }
    visiting.remove(node);
    visited.insert(node);
    Ok(())
}

pub(crate) fn validate_non_blank(value: &str, field: &'static str) -> ValidationResult {
    if value.trim().is_empty() {
        return Err(ValidationError::BlankText { field });
    }
    Ok(())
}
