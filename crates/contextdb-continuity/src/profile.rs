//! Continuity-profile and model-renderer compatibility adapters.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::{
    InstructionHierarchy as ContextInstructionHierarchy, ModelProfile as ContextModelProfile,
    PositionProfile as ContextPositionProfile, RendererKind,
    StructuredFormat as ContextStructuredFormat,
};
use contextdb_core::{
    CommitRange, ContentDigest, ContinuityProfile, ModelRuntimeRef, RevisionNumber,
    SemanticEnvelope, Validate, VectorSpaceId,
};
use contextdb_model::{
    Modality, ModelCapability, ModelProfile as RuntimeModelProfile, ModelRevision, ProviderId,
    StructuredFormat as RuntimeStructuredFormat,
};
use serde::{Deserialize, Serialize};

use crate::{
    ContinuityError, PromptCacheNamespace, Result, ToolId, ensure_digest_nonzero, validate_text,
};

/// One tool exposed by a runtime, independent from model-native tool support.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDescriptor {
    /// Stable tool identity.
    pub id: ToolId,
    /// Exact adapter or schema revision.
    pub revision: String,
    /// Stable operation names advertised by the adapter.
    pub operations: BTreeSet<String>,
}

impl ToolDescriptor {
    /// Validates bounded revision and operation labels.
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.revision, "tool.revision", 256)?;
        if self.operations.is_empty() {
            return Err(ContinuityError::InvalidInput(format!(
                "tool {} advertises no operations",
                self.id
            )));
        }
        for operation in &self.operations {
            validate_text(operation, "tool.operation", 256)?;
        }
        Ok(())
    }
}

/// Immutable representation space available to a runtime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingSpaceDescriptor {
    /// Stable vector-space identity. Different encoders must not reuse it.
    pub id: VectorSpaceId,
    /// Input/output modality represented by the space.
    pub modality: Modality,
    /// Provider-neutral encoder family.
    pub encoder_family: String,
    /// Exact encoder revision.
    pub encoder_revision: ModelRevision,
    /// Fixed vector dimensions.
    pub dimensions: u32,
    /// Whether vectors are normalized by contract.
    pub normalized: bool,
    /// Digest of executable encoder and preprocessing configuration.
    pub fingerprint: ContentDigest,
}

impl EmbeddingSpaceDescriptor {
    /// Rejects empty families, zero dimensions, and placeholder fingerprints.
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.encoder_family, "embedding.encoder_family", 256)?;
        if self.dimensions == 0 {
            return Err(ContinuityError::InvalidInput(
                "embedding dimensions must be positive".to_owned(),
            ));
        }
        ensure_digest_nonzero(self.fingerprint, "embedding fingerprint")
    }

    /// Returns true only when vectors are directly comparable without rebuild.
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.id == other.id && self.has_same_vector_semantics(other)
    }

    /// Returns true when vector values are comparable, independently of their space ID.
    #[must_use]
    pub fn has_same_vector_semantics(&self, other: &Self) -> bool {
        self.modality == other.modality
            && self.dimensions == other.dimensions
            && self.normalized == other.normalized
            && self.fingerprint == other.fingerprint
    }
}

/// Complete deterministic runtime surface used for migration analysis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDescriptor {
    /// Provider or deployment family hosting this runtime.
    pub provider: ProviderId,
    /// Versioned model-runtime profile from M11.
    pub model: RuntimeModelProfile,
    /// M8 renderer chosen by the host for this runtime.
    pub renderer: RendererKind,
    /// Specialized compute capabilities routed to the runtime.
    pub capabilities: BTreeSet<ModelCapability>,
    /// Installed tool adapters keyed by stable identity.
    pub tools: BTreeMap<ToolId, ToolDescriptor>,
    /// Available immutable vector spaces keyed by their stable identity.
    pub embedding_spaces: BTreeMap<VectorSpaceId, EmbeddingSpaceDescriptor>,
    /// Versioned prompt-cache namespace, when the host uses one.
    pub prompt_cache_namespace: Option<PromptCacheNamespace>,
    /// Whether memory crosses the deployment-local processing boundary.
    pub external_processing: bool,
}

impl RuntimeDescriptor {
    /// Validates all M11, tool, vector-space, and renderer compatibility fields.
    pub fn validate(&self) -> Result<()> {
        self.model
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        for capability in &self.capabilities {
            if let ModelCapability::Domain(label) = capability {
                validate_text(label, "runtime capability domain", 256)?;
            }
        }
        for (id, tool) in &self.tools {
            if id != &tool.id {
                return Err(ContinuityError::InvalidInput(
                    "tool map key differs from descriptor identity".to_owned(),
                ));
            }
            tool.validate()?;
        }
        for (id, space) in &self.embedding_spaces {
            if id != &space.id {
                return Err(ContinuityError::InvalidInput(
                    "embedding map key differs from descriptor identity".to_owned(),
                ));
            }
            space.validate()?;
        }
        if self.renderer == RendererKind::HostedStructured && !self.model.supports_tool_results {
            return Err(ContinuityError::IncompatibleRuntime(
                "hosted structured renderer requires a tool-result boundary".to_owned(),
            ));
        }
        if self.renderer == RendererKind::Coding && !self.model.modalities.contains(&Modality::Code)
        {
            return Err(ContinuityError::IncompatibleRuntime(
                "coding renderer requires evaluated code modality".to_owned(),
            ));
        }
        if self.renderer == RendererKind::CanonicalJson
            && self.model.preferred_structured_format != RuntimeStructuredFormat::JsonSchema
        {
            return Err(ContinuityError::IncompatibleRuntime(
                "canonical JSON renderer requires JSON-schema output support".to_owned(),
            ));
        }
        Ok(())
    }

    /// Converts an M11 model profile into the strict M8 rendering profile.
    pub fn context_profile(&self) -> Result<ContextModelProfile> {
        self.validate()?;
        let preferred_structured_format = match self.renderer {
            RendererKind::Compact => ContextStructuredFormat::CompactText,
            RendererKind::HostedStructured => ContextStructuredFormat::ToolResult,
            RendererKind::Chat | RendererKind::Coding => ContextStructuredFormat::Markdown,
            RendererKind::CanonicalJson => ContextStructuredFormat::Json,
        };
        let available_input = self
            .model
            .max_context_tokens
            .saturating_sub(self.model.reserved_output_tokens);
        let position_profile = if available_input <= 8_192 {
            ContextPositionProfile::SmallModelExplicit
        } else if self.model.position_profile.constraints_first
            || self.model.position_profile.unknowns_before_actions
        {
            ContextPositionProfile::CriticalFirst
        } else if self.model.position_profile.evidence_near_claim {
            ContextPositionProfile::EvidenceAdjacent
        } else {
            ContextPositionProfile::Balanced
        };
        let instruction_hierarchy = if self.model.instruction_hierarchy.isolates_user_content
            && (!self.model.supports_tool_results
                || self.model.instruction_hierarchy.isolates_tool_results)
        {
            ContextInstructionHierarchy::SeparatedChannels
        } else {
            ContextInstructionHierarchy::SinglePromptDelimited
        };
        Ok(ContextModelProfile {
            id: format!("{}@{}", self.model.id, self.model.revision),
            family: self.model.family.clone(),
            tokenizer_id: self.model.tokenizer.clone(),
            renderer: self.renderer,
            max_context_tokens: self.model.max_context_tokens,
            reserved_output_tokens: self.model.reserved_output_tokens,
            preferred_structured_format,
            supports_tool_results: self.model.supports_tool_results,
            supports_native_citations: self.model.supports_native_citations,
            supports_prompt_caching: self.model.supports_prompt_caching,
            position_profile,
            instruction_hierarchy,
            max_schema_complexity: self.model.max_schema_complexity,
            external_processing: self.external_processing,
        })
    }

    /// Returns the lineage entry corresponding to this exact runtime descriptor.
    #[must_use]
    pub fn lineage_ref(&self, first_used_at: contextdb_core::TimestampMicros) -> ModelRuntimeRef {
        ModelRuntimeRef {
            provider: self.provider.to_string(),
            model: self.model.id.to_string(),
            revision: Some(self.model.revision.to_string()),
            first_used_at,
            last_used_at: None,
        }
    }

    /// Checks that this descriptor is the currently active lineage runtime.
    pub fn validate_as_active_lineage(&self, profile: &ContinuityProfile) -> Result<()> {
        self.validate()?;
        validate_model_lineage(&profile.model_lineage)?;
        let active = profile.model_lineage.last().ok_or_else(|| {
            ContinuityError::IdentityMismatch(
                "continuity profile has no active model runtime".to_owned(),
            )
        })?;
        if active.provider != self.provider.to_string()
            || active.model != self.model.id.to_string()
            || active.revision.as_deref() != Some(self.model.revision.as_str())
            || active.last_used_at.is_some()
        {
            return Err(ContinuityError::IdentityMismatch(
                "runtime descriptor differs from the active model lineage".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Creates the next immutable continuity-profile revision with an appended runtime.
///
/// Stable profile, agent, subject, migration policy, and identity-claim policy
/// are preserved. The supplied envelope may only narrow the prior policy.
pub fn append_model_lineage(
    previous: &ContinuityProfile,
    target: ModelRuntimeRef,
    revision: RevisionNumber,
    transaction_time: CommitRange,
    envelope: SemanticEnvelope,
) -> Result<ContinuityProfile> {
    previous
        .validate()
        .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
    validate_model_lineage(&previous.model_lineage)?;
    target
        .validate()
        .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
    transaction_time
        .validate()
        .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
    let expected = previous.revision.checked_next().ok_or_else(|| {
        ContinuityError::InvalidInput("continuity profile revision overflow".to_owned())
    })?;
    if revision != expected {
        return Err(ContinuityError::InvalidInput(
            "continuity profile revision is not the exact successor".to_owned(),
        ));
    }
    if transaction_time.start <= previous.transaction_time.start {
        return Err(ContinuityError::InvalidInput(
            "new continuity profile transaction time is not later".to_owned(),
        ));
    }
    if target.last_used_at.is_some() {
        return Err(ContinuityError::InvalidInput(
            "new target runtime must start as the active lineage entry".to_owned(),
        ));
    }
    envelope
        .validate_derived_from(&previous.envelope)
        .map_err(|error| ContinuityError::PolicyDenied(error.to_string()))?;
    let mut model_lineage = previous.model_lineage.clone();
    if let Some(source) = model_lineage.last_mut() {
        if source.provider == target.provider
            && source.model == target.model
            && source.revision == target.revision
        {
            return Err(ContinuityError::InvalidInput(
                "target runtime is identical to the active source runtime".to_owned(),
            ));
        }
        if source.first_used_at >= target.first_used_at
            || source
                .last_used_at
                .is_some_and(|ended| ended > target.first_used_at)
        {
            return Err(ContinuityError::InvalidInput(
                "target runtime begins before the source lineage entry".to_owned(),
            ));
        }
        source.last_used_at = Some(target.first_used_at);
    }
    model_lineage.push(target);
    let next = ContinuityProfile {
        id: previous.id,
        revision,
        transaction_time,
        workspace_id: previous.workspace_id,
        agent_id: previous.agent_id,
        stable_subject: previous.stable_subject,
        model_lineage,
        required_bootstrap_facets: previous.required_bootstrap_facets.clone(),
        migration_policy: previous.migration_policy.clone(),
        identity_claim_policy: previous.identity_claim_policy,
        envelope,
    };
    next.validate()
        .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
    Ok(next)
}

fn validate_model_lineage(lineage: &[ModelRuntimeRef]) -> Result<()> {
    if lineage.is_empty() {
        return Err(ContinuityError::IdentityMismatch(
            "continuity profile has no model lineage".to_owned(),
        ));
    }
    for (index, runtime) in lineage.iter().enumerate() {
        runtime
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        let is_last = index + 1 == lineage.len();
        if is_last != runtime.last_used_at.is_none() {
            return Err(ContinuityError::InvalidInput(
                "exactly the final model-lineage entry must be active".to_owned(),
            ));
        }
        if let Some(next) = lineage.get(index + 1)
            && (runtime.last_used_at != Some(next.first_used_at)
                || runtime.first_used_at >= next.first_used_at)
        {
            return Err(ContinuityError::InvalidInput(
                "model lineage is not contiguous and chronological".to_owned(),
            ));
        }
    }
    Ok(())
}
