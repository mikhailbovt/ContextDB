use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ActorId, AgentId, ContinuityProfileId, MemorySpaceId, MemorySubjectId, NonEmptyVec,
    OwnershipPolicy, PolicyId, RetentionPolicy, Validate, ValidationError, ValidationResult,
    WorkspaceId,
};

/// Administrative container. Cognitive continuity is rooted in a memory subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub policy_profile: PolicyId,
    pub ontology_profile: String,
    pub state: WorkspaceState,
}

impl Validate for Workspace {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.name, "workspace.name")?;
        crate::provenance::validate_non_blank(&self.ontology_profile, "workspace.ontology_profile")
    }
}

/// Administrative lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceState {
    Active,
    ReadOnly,
    Archived,
}

/// Kind of ownership/isolation space.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySpaceKind {
    UserPrivate,
    AgentPrivate,
    SharedUserAgent,
    Group,
    Organisation,
    PublicKnowledge,
    Session,
    Domain,
    FictionalWorld,
    DeviceLocal,
    Other(String),
}

/// Owned memory partition with explicit default access and retention.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySpace {
    pub id: MemorySpaceId,
    pub workspace_id: WorkspaceId,
    pub kind: MemorySpaceKind,
    pub owners: NonEmptyVec<MemorySubjectId>,
    pub default_policy: OwnershipPolicy,
    pub retention_policy: RetentionPolicy,
    pub parent: Option<MemorySpaceId>,
}

impl Validate for MemorySpace {
    fn validate(&self) -> ValidationResult {
        if let MemorySpaceKind::Other(label) = &self.kind {
            crate::provenance::validate_non_blank(label, "memory_space.kind")?;
        }
        if self.parent == Some(self.id) {
            return Err(ValidationError::HierarchyCycle);
        }
        let owner_set: BTreeSet<_> = self.owners.iter().copied().collect();
        if owner_set.len() != self.owners.len() {
            return Err(ValidationError::DuplicateIdentifier {
                field: "memory_space.owners",
            });
        }
        self.default_policy.validate()?;
        let policy_owners: BTreeSet<_> = self.default_policy.owners.iter().copied().collect();
        if owner_set != policy_owners {
            return Err(ValidationError::InvalidState {
                reason: "memory-space owners and default-policy owners differ",
            });
        }
        Ok(())
    }
}

/// Continuity-bearing subject independent of a particular model instance.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    User,
    Agent,
    Relationship,
    Group,
    Organisation,
    World,
    Project,
    Other(String),
}

/// Stable cognitive subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySubject {
    pub id: MemorySubjectId,
    pub workspace_id: WorkspaceId,
    pub kind: SubjectKind,
    pub canonical_node: crate::NodeId,
    pub primary_spaces: NonEmptyVec<MemorySpaceId>,
    pub continuity_policy: PolicyId,
}

impl Validate for MemorySubject {
    fn validate(&self) -> ValidationResult {
        if let SubjectKind::Other(label) = &self.kind {
            crate::provenance::validate_non_blank(label, "memory_subject.kind")?;
        }
        let spaces: BTreeSet<_> = self.primary_spaces.iter().copied().collect();
        if spaces.len() != self.primary_spaces.len() {
            return Err(ValidationError::DuplicateIdentifier {
                field: "memory_subject.primary_spaces",
            });
        }
        Ok(())
    }
}

/// Runtime capabilities advertised by an agent identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    StructuredOutput,
    ToolUse,
    MultimodalInput,
    LocalInference,
    ExternalInference,
    MemoryModification,
    MemoryDeletion,
    Other(String),
}

/// Stable AI identity, explicitly distinct from a model runtime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub id: AgentId,
    pub subject_id: MemorySubjectId,
    pub display_name: String,
    pub configured_role: String,
    pub memory_policy: PolicyId,
    pub capabilities: BTreeSet<Capability>,
    pub continuity_profile: ContinuityProfileId,
}

impl Validate for AgentIdentity {
    fn validate(&self) -> ValidationResult {
        crate::provenance::validate_non_blank(&self.display_name, "agent.display_name")?;
        crate::provenance::validate_non_blank(&self.configured_role, "agent.configured_role")?;
        for capability in &self.capabilities {
            if let Capability::Other(label) = capability {
                crate::provenance::validate_non_blank(label, "agent.capability")?;
            }
        }
        Ok(())
    }
}

/// Source category for actions and assertions.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    Agent,
    Service,
    Tool,
    External,
    Other(String),
}

/// Coarse source trust used as an input to confidence, never as truth itself.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    Untrusted,
    Unknown,
    SelfAsserted,
    Authenticated,
    Verified,
}

/// Origin of a message, observation, or semantic operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub id: ActorId,
    pub kind: ActorKind,
    pub subject_id: Option<MemorySubjectId>,
    pub canonical_node: Option<crate::NodeId>,
    pub trust: TrustClass,
}

impl Validate for Actor {
    fn validate(&self) -> ValidationResult {
        if let ActorKind::Other(label) = &self.kind {
            crate::provenance::validate_non_blank(label, "actor.kind")?;
        }
        Ok(())
    }
}
