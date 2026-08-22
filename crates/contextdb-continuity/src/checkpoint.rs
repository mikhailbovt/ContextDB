//! Portable checkpoint validation and canonical manifests.

use std::collections::BTreeSet;

use contextdb_core::{
    AccessCapability, Audience, Checkpoint, ConsentPolicy, ConsentStatus, ContinuityProfile,
    ContinuityProfileId, MemorySubjectId, MemoryUsePolicy, ModelProfileId, NonEmptyVec,
    OwnershipPolicy, PolicyDecision, Purpose, RevisionNumber, ScopeRef, SecurityPolicy,
    SemanticEnvelope, TimestampMicros, Validate, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::{
    CONTINUITY_FORMAT_VERSION, ContinuityError, ContinuityIdentityKind, Result, RuntimeDescriptor,
    canonical_digest, ensure_digest_nonzero,
};

/// Explicit caller approvals for conditional policy decisions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalApprovals {
    /// Caller proved an interactive approval for conditional retrieval/influence.
    pub memory_use: bool,
    /// Caller proved approval for external model processing.
    pub external_processing: bool,
}

/// Policy envelope for portable working state, kept separate from semantic truth.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityPolicyEnvelope {
    /// Workspace in which the checkpoint was created.
    pub workspace_id: WorkspaceId,
    /// Explicit semantic scopes carried by the checkpoint.
    pub scopes: NonEmptyVec<ScopeRef>,
    /// Ownership, audience, and purpose limits.
    pub ownership: OwnershipPolicy,
    /// Consent state for migration/export.
    pub consent: ConsentPolicy,
    /// Independent retrieval, influence, mention, and external-use gates.
    pub use_policy: MemoryUsePolicy,
    /// Sensitivity and compartment boundary.
    pub security: SecurityPolicy,
}

impl ContinuityPolicyEnvelope {
    /// Validates the local envelope without granting any operation.
    pub fn validate(&self) -> Result<()> {
        self.ownership
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        self.consent
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        self.security
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        let mut scopes = BTreeSet::new();
        for scope in &self.scopes {
            scope
                .validate()
                .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
            if !scopes.insert(scope) {
                return Err(ContinuityError::InvalidInput(
                    "continuity policy repeats a scope".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Proves that a portable working-state policy does not broaden its semantic source.
    pub fn validate_derived_from(&self, source: &SemanticEnvelope) -> Result<()> {
        self.validate()?;
        source
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        let derived = SemanticEnvelope {
            scopes: self.scopes.clone(),
            perspective: source.perspective.clone(),
            ownership: self.ownership.clone(),
            consent: self.consent.clone(),
            use_policy: self.use_policy,
            security: self.security.clone(),
            derivation: source.derivation.clone(),
        };
        derived
            .validate_derived_from(source)
            .map_err(|error| ContinuityError::PolicyDenied(error.to_string()))
    }

    /// Authorizes same-agent model migration without weakening conditional gates.
    pub fn authorize_migration(
        &self,
        stable_subject: MemorySubjectId,
        at: TimestampMicros,
        target_external: bool,
        approvals: ConditionalApprovals,
    ) -> Result<()> {
        self.validate()?;
        if !self.ownership.owners.contains(&stable_subject) {
            return Err(ContinuityError::PolicyDenied(
                "stable subject is not an owner of the checkpoint".to_owned(),
            ));
        }
        if !self
            .ownership
            .allowed_purposes
            .contains(&Purpose::Migration)
        {
            return Err(ContinuityError::PolicyDenied(
                "checkpoint ownership policy does not allow migration".to_owned(),
            ));
        }
        self.authorize_consent(at)?;
        require_decision(
            self.use_policy.retrieve,
            approvals.memory_use,
            "checkpoint retrieval",
        )?;
        require_decision(
            self.use_policy.influence_response,
            approvals.memory_use,
            "checkpoint response influence",
        )?;
        if target_external {
            if !self.security.allow_external_processing {
                return Err(ContinuityError::PolicyDenied(
                    "security policy forbids external migration processing".to_owned(),
                ));
            }
            require_decision(
                self.use_policy.external_model_use,
                approvals.external_processing,
                "external model use",
            )?;
        }
        Ok(())
    }

    /// Authorizes an explicit recipient export and all required compartments.
    pub fn authorize_handoff(
        &self,
        recipient: MemorySubjectId,
        at: TimestampMicros,
        recipient_compartments: &BTreeSet<contextdb_core::ScopeId>,
        target_external: bool,
        approvals: ConditionalApprovals,
    ) -> Result<()> {
        self.validate()?;
        if !self.ownership.allowed_purposes.contains(&Purpose::Export) {
            return Err(ContinuityError::PolicyDenied(
                "checkpoint ownership policy does not allow export".to_owned(),
            ));
        }
        let required = BTreeSet::from([
            AccessCapability::Retrieve,
            AccessCapability::InfluenceResponse,
            AccessCapability::Export,
        ]);
        let granted = self.ownership.audience_grants.iter().any(|grant| {
            (matches!(grant.audience, Audience::Public)
                || matches!(grant.audience, Audience::Subject { id } if id == recipient))
                && grant.purposes.contains(&Purpose::Export)
                && required.is_subset(&grant.capabilities)
        });
        if !granted {
            return Err(ContinuityError::PolicyDenied(
                "recipient lacks an explicit export/retrieve/influence grant".to_owned(),
            ));
        }
        if !self
            .security
            .required_compartments
            .is_subset(recipient_compartments)
        {
            return Err(ContinuityError::PolicyDenied(
                "recipient lacks a required security compartment".to_owned(),
            ));
        }
        self.authorize_consent(at)?;
        require_decision(
            self.use_policy.retrieve,
            approvals.memory_use,
            "handoff retrieval",
        )?;
        require_decision(
            self.use_policy.influence_response,
            approvals.memory_use,
            "handoff response influence",
        )?;
        if target_external {
            if !self.security.allow_external_processing {
                return Err(ContinuityError::PolicyDenied(
                    "security policy forbids external handoff processing".to_owned(),
                ));
            }
            require_decision(
                self.use_policy.external_model_use,
                approvals.external_processing,
                "external handoff processing",
            )?;
        }
        Ok(())
    }

    fn authorize_consent(&self, at: TimestampMicros) -> Result<()> {
        if !self.consent.required {
            return Ok(());
        }
        for owner in &self.ownership.owners {
            let granted = self.consent.decisions.iter().any(|decision| {
                decision.subject == *owner
                    && decision.status == ConsentStatus::Granted
                    && decision.valid_time.contains(at)
            });
            if !granted {
                return Err(ContinuityError::PolicyDenied(format!(
                    "owner {owner} has no active granted consent"
                )));
            }
        }
        Ok(())
    }
}

fn require_decision(
    decision: PolicyDecision,
    conditional_approved: bool,
    name: &str,
) -> Result<()> {
    match decision {
        PolicyDecision::Allow => Ok(()),
        PolicyDecision::Conditional if conditional_approved => Ok(()),
        PolicyDecision::Conditional => Err(ContinuityError::PolicyDenied(format!(
            "{name} requires explicit conditional approval"
        ))),
        PolicyDecision::Deny => Err(ContinuityError::PolicyDenied(format!("{name} is denied"))),
    }
}

/// Canonical, digest-bound checkpoint portable across process and model switches.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableCheckpoint {
    /// Stable artifact format.
    pub format_version: u16,
    /// Model-neutral core checkpoint. Its frame remains working state, not truth.
    pub checkpoint: Checkpoint,
    /// Workspace binding copied from the continuity profile and policy.
    pub workspace_id: WorkspaceId,
    /// Stable agent identity, explicitly distinct from a model profile.
    pub agent_id: contextdb_core::AgentId,
    /// Stable memory subject preserved by migration.
    pub stable_subject: MemorySubjectId,
    /// Continuity profile identity and revision used to seal the checkpoint.
    pub continuity_profile_id: ContinuityProfileId,
    /// Continuity profile revision used to seal the checkpoint.
    pub continuity_profile_revision: RevisionNumber,
    /// Digest of the exact ContinuityProfile, including policy and model lineage.
    pub continuity_profile_digest: contextdb_core::ContentDigest,
    /// Source runtime profile at checkpoint time.
    pub source_model_profile: ModelProfileId,
    /// Digest of the exact source runtime descriptor.
    pub source_runtime_digest: contextdb_core::ContentDigest,
    /// Continuity-profile facets that every bootstrap must request.
    pub required_bootstrap_facets: NonEmptyVec<String>,
    /// Policy applied before any resume/bootstrap materialization.
    pub policy: ContinuityPolicyEnvelope,
    /// Always operational; no API variant represents psychological sameness.
    pub identity_kind: ContinuityIdentityKind,
    /// Digest over every preceding field.
    pub digest: contextdb_core::ContentDigest,
}

impl PortableCheckpoint {
    /// Validates identities and creates a canonical content-bound checkpoint.
    pub fn new(
        mut checkpoint: Checkpoint,
        profile: &ContinuityProfile,
        source_runtime: &RuntimeDescriptor,
        policy: ContinuityPolicyEnvelope,
    ) -> Result<Self> {
        checkpoint
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        profile
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        source_runtime.validate()?;
        source_runtime.validate_as_active_lineage(profile)?;
        policy.validate_derived_from(&profile.envelope)?;
        if profile.workspace_id != policy.workspace_id {
            return Err(ContinuityError::IdentityMismatch(
                "continuity profile and checkpoint policy use different workspaces".to_owned(),
            ));
        }
        if !policy.ownership.owners.contains(&profile.stable_subject) {
            return Err(ContinuityError::PolicyDenied(
                "portable checkpoint policy omits the stable subject owner".to_owned(),
            ));
        }
        if checkpoint.created_seq < profile.transaction_time.start
            || profile
                .transaction_time
                .end
                .is_some_and(|end| checkpoint.created_seq >= end)
        {
            return Err(ContinuityError::IdentityMismatch(
                "checkpoint was created outside the continuity profile revision".to_owned(),
            ));
        }
        checkpoint.required_memory_refs.sort();
        if checkpoint
            .required_memory_refs
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(ContinuityError::InvalidInput(
                "checkpoint repeats a required memory reference".to_owned(),
            ));
        }
        checkpoint.frame_snapshot.open_loops.sort();
        if checkpoint
            .frame_snapshot
            .open_loops
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(ContinuityError::InvalidInput(
                "checkpoint repeats an open loop".to_owned(),
            ));
        }
        let mut value = Self {
            format_version: CONTINUITY_FORMAT_VERSION,
            checkpoint,
            workspace_id: profile.workspace_id,
            agent_id: profile.agent_id,
            stable_subject: profile.stable_subject,
            continuity_profile_id: profile.id,
            continuity_profile_revision: profile.revision,
            continuity_profile_digest: canonical_digest(profile)?,
            source_model_profile: source_runtime.model.id,
            source_runtime_digest: canonical_digest(source_runtime)?,
            required_bootstrap_facets: profile.required_bootstrap_facets.clone(),
            policy,
            identity_kind: ContinuityIdentityKind::OperationalContinuity,
            digest: contextdb_core::ContentDigest::from_bytes([0_u8; 32]),
        };
        value.digest = value.compute_digest()?;
        value.validate_against(profile, source_runtime)?;
        Ok(value)
    }

    /// Revalidates all identities, policy, canonical ordering, and digest.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != CONTINUITY_FORMAT_VERSION {
            return Err(ContinuityError::InvalidInput(
                "unsupported portable checkpoint format".to_owned(),
            ));
        }
        self.checkpoint
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        self.policy.validate()?;
        ensure_digest_nonzero(
            self.continuity_profile_digest,
            "checkpoint continuity profile digest",
        )?;
        ensure_digest_nonzero(
            self.source_runtime_digest,
            "checkpoint source runtime digest",
        )?;
        if self.workspace_id != self.policy.workspace_id
            || !self.policy.ownership.owners.contains(&self.stable_subject)
        {
            return Err(ContinuityError::IdentityMismatch(
                "portable checkpoint identity/policy binding differs".to_owned(),
            ));
        }
        if self
            .checkpoint
            .required_memory_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self
                .checkpoint
                .frame_snapshot
                .open_loops
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ContinuityError::InvalidInput(
                "portable checkpoint sets are not in strict canonical order".to_owned(),
            ));
        }
        if self
            .required_bootstrap_facets
            .iter()
            .any(|facet| facet.trim().is_empty())
        {
            return Err(ContinuityError::InvalidInput(
                "portable checkpoint contains a blank bootstrap facet".to_owned(),
            ));
        }
        let distinct_facets: BTreeSet<_> = self.required_bootstrap_facets.iter().collect();
        if distinct_facets.len() != self.required_bootstrap_facets.len() {
            return Err(ContinuityError::InvalidInput(
                "portable checkpoint repeats a bootstrap facet".to_owned(),
            ));
        }
        if self.identity_kind != ContinuityIdentityKind::OperationalContinuity {
            return Err(ContinuityError::InvalidInput(
                "unsupported identity continuity claim".to_owned(),
            ));
        }
        if self.digest != self.compute_digest()? {
            return Err(ContinuityError::InvalidInput(
                "portable checkpoint digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Revalidates an imported checkpoint against the exact profile and source runtime.
    pub fn validate_against(
        &self,
        profile: &ContinuityProfile,
        source_runtime: &RuntimeDescriptor,
    ) -> Result<()> {
        self.validate()?;
        profile
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        source_runtime.validate()?;
        source_runtime.validate_as_active_lineage(profile)?;
        if self.workspace_id != profile.workspace_id
            || self.agent_id != profile.agent_id
            || self.stable_subject != profile.stable_subject
            || self.continuity_profile_id != profile.id
            || self.continuity_profile_revision != profile.revision
            || self.required_bootstrap_facets != profile.required_bootstrap_facets
        {
            return Err(ContinuityError::IdentityMismatch(
                "portable checkpoint differs from its continuity profile".to_owned(),
            ));
        }
        if self.continuity_profile_digest != canonical_digest(profile)? {
            return Err(ContinuityError::IdentityMismatch(
                "portable checkpoint continuity-profile digest differs".to_owned(),
            ));
        }
        if self.source_model_profile != source_runtime.model.id
            || self.source_runtime_digest != canonical_digest(source_runtime)?
        {
            return Err(ContinuityError::IdentityMismatch(
                "portable checkpoint source-runtime binding differs".to_owned(),
            ));
        }
        self.policy.validate_derived_from(&profile.envelope)
    }

    /// Canonical JSON bytes after full validation.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| ContinuityError::Serialization(error.to_string()))
    }

    /// Parses canonical JSON and rejects any tampering or invalid identity binding.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ContinuityError::Serialization(error.to_string()))?;
        value.validate()?;
        if value.to_json()? != bytes {
            return Err(ContinuityError::Serialization(
                "portable checkpoint JSON is not canonical".to_owned(),
            ));
        }
        Ok(value)
    }

    fn compute_digest(&self) -> Result<contextdb_core::ContentDigest> {
        canonical_digest(&(
            self.format_version,
            &self.checkpoint,
            self.workspace_id,
            self.agent_id,
            self.stable_subject,
            self.continuity_profile_id,
            self.continuity_profile_revision,
            self.continuity_profile_digest,
            self.source_model_profile,
            self.source_runtime_digest,
            &self.required_bootstrap_facets,
            &self.policy,
            self.identity_kind,
        ))
    }
}
