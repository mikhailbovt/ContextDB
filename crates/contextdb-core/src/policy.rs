use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ActorId, DerivationRef, LineageNode, MemorySpaceId, MemorySubjectId, NonEmptyVec, ScopeId,
    TimeRange, Validate, ValidationError, ValidationResult,
};

/// Semantic dimension used to constrain identity, truth, and retrieval.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Workspace,
    MemorySpace,
    Subject,
    Relationship,
    Project,
    Repository,
    Organisation,
    Team,
    Session,
    Task,
    Place,
    TimeRegion,
    SecurityCompartment,
    Domain,
    Other(String),
}

/// Controls whether a scope applies only at one node or to descendants.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeInheritance {
    Exact,
    Descendants,
}

/// Stable reference to a semantic scope.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRef {
    pub kind: ScopeKind,
    pub id: ScopeId,
    pub inheritance: ScopeInheritance,
}

impl Validate for ScopeRef {
    fn validate(&self) -> ValidationResult {
        if let ScopeKind::Other(label) = &self.kind {
            crate::provenance::validate_non_blank(label, "scope.kind")?;
        }
        Ok(())
    }
}

/// Epistemic position from which a memory is represented.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Perspective {
    pub knower: MemorySubjectId,
    pub experiencer: Option<MemorySubjectId>,
    pub narrator: ActorId,
    pub role: EpistemicRole,
}

/// Role of the narrator with respect to a statement.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicRole {
    Experiencer,
    Witness,
    Asserter,
    Interpreter,
    Verifier,
    ExternalReporter,
    FictionalNarrator,
    Other(String),
}

impl Validate for Perspective {
    fn validate(&self) -> ValidationResult {
        if let EpistemicRole::Other(label) = &self.role {
            crate::provenance::validate_non_blank(label, "perspective.role")?;
        }
        Ok(())
    }
}

/// Explicit purpose for which memory may be used.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Conversation,
    Personalisation,
    TaskExecution,
    KnowledgeRecall,
    Safety,
    Audit,
    Export,
    Migration,
    UserSpecified(String),
}

impl Validate for Purpose {
    fn validate(&self) -> ValidationResult {
        if let Self::UserSpecified(label) = self {
            crate::provenance::validate_non_blank(label, "purpose")?;
        }
        Ok(())
    }
}

/// Principal or collection to which a grant applies.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Audience {
    Public,
    Owner,
    Subject { id: MemorySubjectId },
    Group { id: MemorySubjectId },
    MemorySpace { id: MemorySpaceId },
}

impl Audience {
    fn covers(&self, narrower: &Self) -> bool {
        self == &Self::Public || self == narrower
    }
}

/// Capability granted to an audience for allowed purposes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessCapability {
    Retrieve,
    InfluenceResponse,
    Mention,
    Export,
    Derive,
    Modify,
}

/// Purpose-limited audience grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceGrant {
    pub audience: Audience,
    pub purposes: BTreeSet<Purpose>,
    pub capabilities: BTreeSet<AccessCapability>,
}

impl Validate for AudienceGrant {
    fn validate(&self) -> ValidationResult {
        if self.purposes.is_empty() {
            return Err(ValidationError::EmptyCollection {
                field: "audience_grant.purposes",
            });
        }
        if self.capabilities.is_empty() {
            return Err(ValidationError::EmptyCollection {
                field: "audience_grant.capabilities",
            });
        }
        for purpose in &self.purposes {
            purpose.validate()?;
        }
        Ok(())
    }
}

/// Who may alter an item independently of read access.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModificationPolicy {
    pub owners_may_modify: bool,
    pub delegates_may_modify: bool,
    pub system_may_derive: bool,
}

/// Ownership, audience, and purpose limitation for memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipPolicy {
    pub owners: NonEmptyVec<MemorySubjectId>,
    pub audience_grants: Vec<AudienceGrant>,
    pub allowed_purposes: BTreeSet<Purpose>,
    pub modification: ModificationPolicy,
}

impl Validate for OwnershipPolicy {
    fn validate(&self) -> ValidationResult {
        ensure_distinct(self.owners.iter().copied(), "ownership.owners")?;
        if self.allowed_purposes.is_empty() {
            return Err(ValidationError::EmptyCollection {
                field: "ownership.allowed_purposes",
            });
        }
        for purpose in &self.allowed_purposes {
            purpose.validate()?;
        }
        for grant in &self.audience_grants {
            grant.validate()?;
            if !grant.purposes.is_subset(&self.allowed_purposes) {
                return Err(ValidationError::InvalidState {
                    reason: "grant purpose is not allowed by ownership policy",
                });
            }
        }
        Ok(())
    }
}

/// Class of memory for consent and retention decisions.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryClass {
    RawExperience,
    PersonalFact,
    Relationship,
    Sensitive,
    Procedural,
    Operational,
    Artifact,
    Other(String),
}

/// Explicit consent state. Unknown never means granted.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    Denied,
    Unknown,
    Granted,
}

/// Versionable consent decision embedded in the policy envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentState {
    pub subject: MemorySubjectId,
    pub memory_class: MemoryClass,
    pub status: ConsentStatus,
    pub valid_time: TimeRange,
}

impl Validate for ConsentState {
    fn validate(&self) -> ValidationResult {
        if let MemoryClass::Other(label) = &self.memory_class {
            crate::provenance::validate_non_blank(label, "consent.memory_class")?;
        }
        self.valid_time.validate()
    }
}

/// Consent requirements attached to a memory item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPolicy {
    pub required: bool,
    pub decisions: Vec<ConsentState>,
}

impl Validate for ConsentPolicy {
    fn validate(&self) -> ValidationResult {
        if self.required && self.decisions.is_empty() {
            return Err(ValidationError::EmptyCollection {
                field: "consent.decisions",
            });
        }
        for decision in &self.decisions {
            decision.validate()?;
        }
        Ok(())
    }
}

/// Permission level for each stage of memory use.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Deny,
    Conditional,
    Allow,
}

/// Retention is independent of whether memory may be mentioned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetentionPolicy {
    Ephemeral,
    Session,
    Duration { microseconds: u64 },
    Indefinite,
}

impl RetentionPolicy {
    fn permits_at_most(self, source: Self) -> bool {
        match (self, source) {
            (_, Self::Indefinite) | (Self::Ephemeral, _) => true,
            (Self::Session, Self::Session | Self::Duration { .. }) => true,
            (
                Self::Duration {
                    microseconds: derived,
                },
                Self::Duration {
                    microseconds: original,
                },
            ) => derived <= original,
            (left, right) => left == right,
        }
    }
}

/// Independent gates for retrieval, influence, disclosure, and external use.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUsePolicy {
    pub retrieve: PolicyDecision,
    pub influence_response: PolicyDecision,
    pub mention_explicitly: PolicyDecision,
    pub external_model_use: PolicyDecision,
    pub retention: RetentionPolicy,
}

/// Ordered information sensitivity classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Security labels propagated to all derived indexes and artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityPolicy {
    pub classification: SecurityClassification,
    pub labels: BTreeSet<String>,
    pub required_compartments: BTreeSet<ScopeId>,
    pub allow_external_processing: bool,
}

impl Validate for SecurityPolicy {
    fn validate(&self) -> ValidationResult {
        for label in &self.labels {
            crate::provenance::validate_non_blank(label, "security.label")?;
        }
        Ok(())
    }
}

/// Common mandatory policy and provenance fields for semantic revisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticEnvelope {
    pub scopes: NonEmptyVec<ScopeRef>,
    pub perspective: Perspective,
    pub ownership: OwnershipPolicy,
    pub consent: ConsentPolicy,
    pub use_policy: MemoryUsePolicy,
    pub security: SecurityPolicy,
    pub derivation: DerivationRef,
}

impl SemanticEnvelope {
    /// Validates the envelope and rejects a derivation that directly supports itself.
    pub fn validate_for_target(&self, target: &LineageNode) -> ValidationResult {
        self.validate()?;
        self.derivation.validate_for(target)
    }

    /// Rejects any automatic derived object that broadens access, purpose, use,
    /// retention, consent, or security relative to its source.
    pub fn validate_derived_from(&self, source: &Self) -> ValidationResult {
        self.validate()?;
        source.validate()?;

        let source_scopes: BTreeSet<_> = source.scopes.iter().collect();
        if self
            .scopes
            .iter()
            .any(|scope| !source_scopes.contains(scope))
        {
            return Err(ValidationError::PolicyWeakening {
                reason: "derived scope is not constrained by the source",
            });
        }
        let derived_owners: BTreeSet<_> = self.ownership.owners.iter().copied().collect();
        let source_owners: BTreeSet<_> = source.ownership.owners.iter().copied().collect();
        if derived_owners != source_owners {
            return Err(ValidationError::PolicyWeakening {
                reason: "derived ownership differs from source ownership",
            });
        }
        if !self
            .ownership
            .allowed_purposes
            .is_subset(&source.ownership.allowed_purposes)
        {
            return Err(ValidationError::PolicyWeakening {
                reason: "derived purpose set is broader",
            });
        }
        if modification_is_broader(self.ownership.modification, source.ownership.modification) {
            return Err(ValidationError::PolicyWeakening {
                reason: "derived modification permissions are broader",
            });
        }
        for derived_grant in &self.ownership.audience_grants {
            let covered = source.ownership.audience_grants.iter().any(|source_grant| {
                source_grant.audience.covers(&derived_grant.audience)
                    && derived_grant.purposes.is_subset(&source_grant.purposes)
                    && derived_grant
                        .capabilities
                        .is_subset(&source_grant.capabilities)
            });
            if !covered {
                return Err(ValidationError::PolicyWeakening {
                    reason: "derived audience grant is broader",
                });
            }
        }
        if self.use_policy.retrieve > source.use_policy.retrieve
            || self.use_policy.influence_response > source.use_policy.influence_response
            || self.use_policy.mention_explicitly > source.use_policy.mention_explicitly
            || self.use_policy.external_model_use > source.use_policy.external_model_use
            || !self
                .use_policy
                .retention
                .permits_at_most(source.use_policy.retention)
        {
            return Err(ValidationError::PolicyWeakening {
                reason: "derived memory-use policy is broader",
            });
        }
        if self.security.classification < source.security.classification
            || !source.security.labels.is_subset(&self.security.labels)
            || !source
                .security
                .required_compartments
                .is_subset(&self.security.required_compartments)
            || (self.security.allow_external_processing
                && !source.security.allow_external_processing)
        {
            return Err(ValidationError::PolicyWeakening {
                reason: "derived security policy is weaker",
            });
        }
        validate_consent_derivation(&self.consent, &source.consent)
    }
}

impl Validate for SemanticEnvelope {
    fn validate(&self) -> ValidationResult {
        for scope in &self.scopes {
            scope.validate()?;
        }
        self.perspective.validate()?;
        self.ownership.validate()?;
        self.consent.validate()?;
        self.security.validate()?;
        self.derivation.validate()
    }
}

fn modification_is_broader(derived: ModificationPolicy, source: ModificationPolicy) -> bool {
    (derived.owners_may_modify && !source.owners_may_modify)
        || (derived.delegates_may_modify && !source.delegates_may_modify)
        || (derived.system_may_derive && !source.system_may_derive)
}

fn validate_consent_derivation(
    derived: &ConsentPolicy,
    source: &ConsentPolicy,
) -> ValidationResult {
    if source.required && !derived.required {
        return Err(ValidationError::PolicyWeakening {
            reason: "derived memory removed consent requirement",
        });
    }
    for decision in &derived.decisions {
        let source_status = source
            .decisions
            .iter()
            .filter(|item| {
                item.subject == decision.subject && item.memory_class == decision.memory_class
            })
            .map(|item| item.status)
            .max();
        if source_status.is_none_or(|status| decision.status > status) {
            return Err(ValidationError::PolicyWeakening {
                reason: "derived memory broadened consent",
            });
        }
    }
    Ok(())
}

fn ensure_distinct<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> ValidationResult {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ValidationError::DuplicateIdentifier { field });
        }
    }
    Ok(())
}
