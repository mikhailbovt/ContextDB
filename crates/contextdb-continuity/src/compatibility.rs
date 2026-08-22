//! Deterministic source/target model compatibility analysis.

use std::collections::BTreeSet;

use contextdb_context::RendererKind;
use contextdb_core::{AgentId, ContentDigest, MemorySubjectId, ModelProfileId, WorkspaceId};
use contextdb_model::ModelCapability;
use serde::{Deserialize, Serialize};

use crate::{
    ContinuityError, MigrationId, PromptCacheNamespace, ReembeddingJobSpec, Result,
    RuntimeDescriptor, ToolId, canonical_digest,
};

/// Severity controls whether bootstrap may proceed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Describes a change or required rebuild without quality loss.
    Informational,
    /// Migration may proceed, but the caller must surface or mitigate degradation.
    Warning,
    /// Bootstrap must not proceed until the incompatibility is resolved.
    Blocking,
}

/// Machine-readable compatibility finding code.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityCode {
    /// The target cannot fit the declared minimum bootstrap input.
    ContextBudgetInsufficient,
    /// The target has fewer available input tokens.
    ContextBudgetReduced,
    /// Exact token accounting must use another tokenizer.
    TokenizerChanged,
    /// The target prefers another structured-output encoding.
    StructuredFormatChanged,
    /// The target cannot represent the declared minimum schema.
    SchemaComplexityInsufficient,
    /// The target supports a smaller schema complexity.
    SchemaComplexityReduced,
    /// A required tool is absent.
    ToolUnavailable,
    /// A tool remains installed but its revision/operation contract changed.
    ToolContractChanged,
    /// A required model capability is absent.
    CapabilityUnavailable,
    /// Native citations are no longer available.
    NativeCitationsUnavailable,
    /// Prompt caches are runtime-specific and cannot be copied.
    PromptCacheRebuildRequired,
    /// ContextPack placement/encoding changes.
    RendererChanged,
    /// Trusted/untrusted channel behavior differs.
    InstructionHierarchyChanged,
    /// Measured position sensitivity differs.
    PositionBehaviorChanged,
    /// The target lacks evaluated language coverage.
    LanguageCoverageReduced,
    /// The target lacks evaluated modality coverage.
    ModalityCoverageReduced,
    /// Local versus external processing changed.
    ExternalProcessingBoundaryChanged,
    /// A new immutable representation space requires population.
    EmbeddingRebuildRequired,
    /// Existing representations have no target space of the same modality.
    EmbeddingTargetUnavailable,
    /// One stable vector-space ID was reused for incompatible semantics.
    EmbeddingSpaceIdCollision,
    /// Identical vector semantics were assigned two different stable space IDs.
    EmbeddingSpaceSemanticAlias,
    /// Operational memory continuity cannot promise identical behavior.
    BehavioralContinuityNotGuaranteed,
    /// Configured style is preserved as memory, but realization can vary by model.
    StyleBehaviorMayDiffer,
}

/// One stable, payload-free difference between source and target runtimes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityFinding {
    /// Whether this difference blocks bootstrap.
    pub severity: FindingSeverity,
    /// Stable machine-readable category.
    pub code: CompatibilityCode,
    /// Payload-free affected capability/tool/space label.
    pub subject: String,
    /// Human-readable non-secret explanation.
    pub detail: String,
}

impl CompatibilityFinding {
    /// Validates bounded, payload-free diagnostic labels and detail.
    pub fn validate(&self) -> Result<()> {
        crate::validate_text(&self.subject, "compatibility finding subject", 256)?;
        crate::validate_text(&self.detail, "compatibility finding detail", 2_048)
    }
}

/// Explicit requirements of the workload being migrated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRequirements {
    /// Capabilities without which operational resume is unsafe or meaningless.
    pub required_capabilities: BTreeSet<ModelCapability>,
    /// Tools required by current work/open loops.
    pub required_tools: BTreeSet<ToolId>,
    /// Minimum input tokens required by the bounded bootstrap pack.
    pub minimum_input_tokens: u32,
    /// Minimum structured-schema complexity needed by the lifecycle contract.
    pub minimum_schema_complexity: u32,
    /// A workload that requires exact native citations cannot silently degrade.
    pub require_native_citations: bool,
}

impl MigrationRequirements {
    /// Validates non-zero contract bounds and bounded domain capability labels.
    pub fn validate(&self) -> Result<()> {
        if self.minimum_input_tokens == 0 || self.minimum_schema_complexity == 0 {
            return Err(ContinuityError::InvalidInput(
                "migration requirements need positive input and schema bounds".to_owned(),
            ));
        }
        for capability in &self.required_capabilities {
            if let ModelCapability::Domain(label) = capability {
                crate::types::validate_text(label, "required capability", 256)?;
            }
        }
        Ok(())
    }
}

/// Privacy-safe migration trace and executable rebuild plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationCompatibilityReport {
    /// Stable migration identity.
    pub migration_id: MigrationId,
    /// Workspace containing the preserved subject.
    pub workspace_id: WorkspaceId,
    /// Stable agent identity, distinct from the model.
    pub agent_id: AgentId,
    /// Stable memory subject preserved by migration.
    pub stable_subject: MemorySubjectId,
    /// Source M11 model profile.
    pub source_profile: ModelProfileId,
    /// Target M11 model profile.
    pub target_profile: ModelProfileId,
    /// Digest of the exact source runtime descriptor.
    pub source_runtime_digest: ContentDigest,
    /// Digest of the exact target runtime descriptor.
    pub target_runtime_digest: ContentDigest,
    /// Source ContextPack renderer.
    pub source_renderer: RendererKind,
    /// Target ContextPack renderer.
    pub target_renderer: RendererKind,
    /// Must remain true; false is rejected.
    pub preserved_memory_subject: bool,
    /// Canonically sorted capability differences and warnings.
    pub findings: Vec<CompatibilityFinding>,
    /// Deterministic provider-neutral representation rebuild plan.
    pub reembedding_jobs: Vec<ReembeddingJobSpec>,
    /// True only when no blocking finding exists.
    pub compatible: bool,
    /// Digest over the complete report excluding this field.
    pub report_digest: ContentDigest,
}

impl MigrationCompatibilityReport {
    /// Validates ordering, compatibility summary, and digest binding.
    pub fn validate(&self) -> Result<()> {
        crate::ensure_digest_nonzero(self.source_runtime_digest, "source runtime digest")?;
        crate::ensure_digest_nonzero(self.target_runtime_digest, "target runtime digest")?;
        for finding in &self.findings {
            finding.validate()?;
        }
        if !self.preserved_memory_subject {
            return Err(ContinuityError::IdentityMismatch(
                "compatibility report did not preserve the memory subject".to_owned(),
            ));
        }
        if self
            .findings
            .windows(2)
            .any(|pair| (&pair[0].code, &pair[0].subject) >= (&pair[1].code, &pair[1].subject))
        {
            return Err(ContinuityError::InvalidInput(
                "compatibility findings are not in strict canonical order".to_owned(),
            ));
        }
        if self.reembedding_jobs.windows(2).any(|pair| {
            (&pair[0].target.id, &pair[0].source.id) >= (&pair[1].target.id, &pair[1].source.id)
        }) {
            return Err(ContinuityError::InvalidInput(
                "re-embedding jobs are not in strict target/source-space order".to_owned(),
            ));
        }
        for job in &self.reembedding_jobs {
            job.validate()?;
            if job.migration_id != self.migration_id || job.workspace_id != self.workspace_id {
                return Err(ContinuityError::IdentityMismatch(
                    "re-embedding job belongs to another migration/workspace".to_owned(),
                ));
            }
        }
        let expected_compatible = !self
            .findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Blocking);
        if self.compatible != expected_compatible {
            return Err(ContinuityError::InvalidInput(
                "compatibility summary differs from blocking findings".to_owned(),
            ));
        }
        if self.report_digest != self.compute_digest()? {
            return Err(ContinuityError::InvalidInput(
                "migration compatibility report digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Emits compact canonical JSON after full report validation.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| ContinuityError::Serialization(error.to_string()))
    }

    /// Parses canonical JSON, validates the digest, and rejects alternate encodings.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ContinuityError::Serialization(error.to_string()))?;
        value.validate()?;
        if value.to_json()? != bytes {
            return Err(ContinuityError::Serialization(
                "migration compatibility JSON is not canonical".to_owned(),
            ));
        }
        Ok(value)
    }

    fn compute_digest(&self) -> Result<ContentDigest> {
        canonical_digest(&(
            &self.migration_id,
            self.workspace_id,
            self.agent_id,
            self.stable_subject,
            self.source_profile,
            self.target_profile,
            self.source_runtime_digest,
            self.target_runtime_digest,
            self.source_renderer,
            self.target_renderer,
            self.preserved_memory_subject,
            &self.findings,
            &self.reembedding_jobs,
            self.compatible,
        ))
    }
}

/// Pure migration compatibility oracle.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompatibilityAnalyzer;

impl CompatibilityAnalyzer {
    /// Compares two validated runtimes without loading checkpoint or memory payloads.
    #[allow(
        clippy::too_many_arguments,
        reason = "all stable identities remain explicit migration bindings"
    )]
    pub fn analyze(
        migration_id: MigrationId,
        workspace_id: WorkspaceId,
        agent_id: AgentId,
        stable_subject: MemorySubjectId,
        source: &RuntimeDescriptor,
        target: &RuntimeDescriptor,
        requirements: &MigrationRequirements,
        reembedding_scopes: contextdb_core::NonEmptyVec<contextdb_core::ScopeRef>,
        snapshot_commit: contextdb_core::CommitSeq,
    ) -> Result<MigrationCompatibilityReport> {
        source.validate()?;
        target.validate()?;
        requirements.validate()?;
        let mut distinct_scopes = BTreeSet::new();
        for scope in &reembedding_scopes {
            contextdb_core::Validate::validate(scope)
                .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
            if !distinct_scopes.insert(scope) {
                return Err(ContinuityError::InvalidInput(
                    "re-embedding analysis repeats a scope".to_owned(),
                ));
            }
        }
        let source_digest = canonical_digest(source)?;
        let target_digest = canonical_digest(target)?;
        let mut findings = Vec::new();

        let source_input = source
            .model
            .max_context_tokens
            .saturating_sub(source.model.reserved_output_tokens);
        let target_input = target
            .model
            .max_context_tokens
            .saturating_sub(target.model.reserved_output_tokens);
        if target_input < requirements.minimum_input_tokens {
            findings.push(finding(
                FindingSeverity::Blocking,
                CompatibilityCode::ContextBudgetInsufficient,
                "context_window",
                format!(
                    "target provides {target_input} input tokens but workload requires {}",
                    requirements.minimum_input_tokens
                ),
            ));
        } else if target_input < source_input {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::ContextBudgetReduced,
                "context_window",
                format!("available input reduced from {source_input} to {target_input} tokens"),
            ));
        }
        if source.model.tokenizer != target.model.tokenizer {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::TokenizerChanged,
                "tokenizer",
                format!(
                    "tokenizer changed from {} to {}",
                    source.model.tokenizer, target.model.tokenizer
                ),
            ));
        }
        if source.model.preferred_structured_format != target.model.preferred_structured_format {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::StructuredFormatChanged,
                "structured_output",
                "preferred structured-output format changed".to_owned(),
            ));
        }
        if target.model.max_schema_complexity < requirements.minimum_schema_complexity {
            findings.push(finding(
                FindingSeverity::Blocking,
                CompatibilityCode::SchemaComplexityInsufficient,
                "schema_complexity",
                format!(
                    "target schema complexity {} is below workload minimum {}",
                    target.model.max_schema_complexity, requirements.minimum_schema_complexity
                ),
            ));
        } else if target.model.max_schema_complexity < source.model.max_schema_complexity {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::SchemaComplexityReduced,
                "schema_complexity",
                format!(
                    "schema complexity reduced from {} to {}",
                    source.model.max_schema_complexity, target.model.max_schema_complexity
                ),
            ));
        }
        let compared_capabilities: BTreeSet<_> = source
            .capabilities
            .union(&requirements.required_capabilities)
            .cloned()
            .collect();
        for capability in &compared_capabilities {
            if !target.capabilities.contains(capability) {
                findings.push(finding(
                    if requirements.required_capabilities.contains(capability) {
                        FindingSeverity::Blocking
                    } else {
                        FindingSeverity::Warning
                    },
                    CompatibilityCode::CapabilityUnavailable,
                    format!("{capability:?}"),
                    if requirements.required_capabilities.contains(capability) {
                        "required model capability is unavailable".to_owned()
                    } else {
                        "source model capability is unavailable on the target".to_owned()
                    },
                ));
            }
        }
        let compared_tools: BTreeSet<_> = source
            .tools
            .keys()
            .chain(&requirements.required_tools)
            .cloned()
            .collect();
        for tool in &compared_tools {
            if !target.tools.contains_key(tool) {
                findings.push(finding(
                    if requirements.required_tools.contains(tool) {
                        FindingSeverity::Blocking
                    } else {
                        FindingSeverity::Warning
                    },
                    CompatibilityCode::ToolUnavailable,
                    tool.to_string(),
                    if requirements.required_tools.contains(tool) {
                        "tool required by current work is unavailable".to_owned()
                    } else {
                        "source runtime tool is unavailable on the target".to_owned()
                    },
                ));
            }
        }
        for (id, source_tool) in &source.tools {
            let Some(target_tool) = target.tools.get(id) else {
                continue;
            };
            let missing_operations: BTreeSet<_> = source_tool
                .operations
                .difference(&target_tool.operations)
                .cloned()
                .collect();
            if source_tool.revision != target_tool.revision || !missing_operations.is_empty() {
                findings.push(finding(
                    if requirements.required_tools.contains(id) && !missing_operations.is_empty() {
                        FindingSeverity::Blocking
                    } else {
                        FindingSeverity::Warning
                    },
                    CompatibilityCode::ToolContractChanged,
                    id.to_string(),
                    format!(
                        "tool changed from revision {} to {}; missing operations {missing_operations:?}",
                        source_tool.revision, target_tool.revision
                    ),
                ));
            }
        }
        if requirements.require_native_citations && !target.model.supports_native_citations {
            findings.push(finding(
                FindingSeverity::Blocking,
                CompatibilityCode::NativeCitationsUnavailable,
                "native_citations",
                "workload requires native citations but target has no citation surface".to_owned(),
            ));
        } else if source.model.supports_native_citations && !target.model.supports_native_citations
        {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::NativeCitationsUnavailable,
                "native_citations",
                "target runtime has no native citation surface".to_owned(),
            ));
        }
        if cache_rebuild_required(
            source.model.supports_prompt_caching,
            target.model.supports_prompt_caching,
            source.prompt_cache_namespace.as_ref(),
            target.prompt_cache_namespace.as_ref(),
        ) {
            findings.push(finding(
                FindingSeverity::Informational,
                CompatibilityCode::PromptCacheRebuildRequired,
                "prompt_cache",
                "prompt cache is runtime-specific and must be rebuilt".to_owned(),
            ));
        }
        if source.renderer != target.renderer {
            findings.push(finding(
                FindingSeverity::Informational,
                CompatibilityCode::RendererChanged,
                "renderer",
                format!(
                    "ContextPack renderer changed from {:?} to {:?}",
                    source.renderer, target.renderer
                ),
            ));
        }
        if source.model.instruction_hierarchy != target.model.instruction_hierarchy {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::InstructionHierarchyChanged,
                "instruction_hierarchy",
                "trusted/untrusted placement behavior differs".to_owned(),
            ));
        }
        if source.model.position_profile != target.model.position_profile {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::PositionBehaviorChanged,
                "position_profile",
                "measured position sensitivity differs; renderer adaptation is required".to_owned(),
            ));
        }
        let missing_languages: BTreeSet<_> = source
            .model
            .languages
            .difference(&target.model.languages)
            .map(ToString::to_string)
            .collect();
        if !missing_languages.is_empty() {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::LanguageCoverageReduced,
                "languages",
                format!("target lacks evaluated coverage for {missing_languages:?}"),
            ));
        }
        let missing_modalities: BTreeSet<_> = source
            .model
            .modalities
            .difference(&target.model.modalities)
            .copied()
            .collect();
        if !missing_modalities.is_empty() {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::ModalityCoverageReduced,
                "modalities",
                format!("target lacks evaluated modalities {missing_modalities:?}"),
            ));
        }
        if source.external_processing != target.external_processing {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::ExternalProcessingBoundaryChanged,
                "privacy_boundary",
                "model processing locality changed; policy must be re-evaluated".to_owned(),
            ));
        }

        let mut reembedding_jobs = Vec::new();
        for (id, source_space) in &source.embedding_spaces {
            let Some(target_space) = target.embedding_spaces.get(id) else {
                continue;
            };
            if source_space.is_compatible_with(target_space) {
                continue;
            }
            findings.push(finding(
                FindingSeverity::Blocking,
                CompatibilityCode::EmbeddingSpaceIdCollision,
                id.to_string(),
                "same vector-space ID has incompatible encoder semantics".to_owned(),
            ));
        }
        for source_space in source.embedding_spaces.values() {
            if target
                .embedding_spaces
                .values()
                .any(|target_space| source_space.is_compatible_with(target_space))
            {
                continue;
            }
            if let Some(alias) = target
                .embedding_spaces
                .values()
                .find(|target_space| source_space.has_same_vector_semantics(target_space))
            {
                findings.push(finding(
                    FindingSeverity::Blocking,
                    CompatibilityCode::EmbeddingSpaceSemanticAlias,
                    alias.id.to_string(),
                    format!(
                        "identical vector semantics changed stable space ID from {} to {}",
                        source_space.id, alias.id
                    ),
                ));
                continue;
            }
            let Some(target_space) = target
                .embedding_spaces
                .values()
                .filter(|space| space.modality == source_space.modality)
                .min_by_key(|space| space.id)
            else {
                findings.push(finding(
                    if requirements
                        .required_capabilities
                        .contains(&ModelCapability::GenerateEmbedding)
                    {
                        FindingSeverity::Blocking
                    } else {
                        FindingSeverity::Warning
                    },
                    CompatibilityCode::EmbeddingTargetUnavailable,
                    source_space.id.to_string(),
                    "existing representations have no target space of the same modality".to_owned(),
                ));
                continue;
            };
            if source_space.id == target_space.id {
                continue;
            }
            findings.push(finding(
                FindingSeverity::Informational,
                CompatibilityCode::EmbeddingRebuildRequired,
                target_space.id.to_string(),
                format!(
                    "rebuild {} representations into immutable target space {}",
                    source_space.id, target_space.id
                ),
            ));
            reembedding_jobs.push(ReembeddingJobSpec::new(
                migration_id.clone(),
                workspace_id,
                snapshot_commit,
                reembedding_scopes.clone(),
                source_space.clone(),
                target_space.clone(),
            )?);
        }
        findings.push(finding(
            FindingSeverity::Informational,
            CompatibilityCode::BehavioralContinuityNotGuaranteed,
            "operational_continuity",
            "memory continuity preserves operational state, not identical behavior or wording"
                .to_owned(),
        ));
        if source.model.id != target.model.id
            || source.model.revision != target.model.revision
            || source.model.family != target.model.family
        {
            findings.push(finding(
                FindingSeverity::Warning,
                CompatibilityCode::StyleBehaviorMayDiffer,
                "style_realization",
                "configured style remains memory, but realization can differ on the target model"
                    .to_owned(),
            ));
        }
        findings
            .sort_by(|left, right| (&left.code, &left.subject).cmp(&(&right.code, &right.subject)));
        findings.dedup_by(|left, right| left.code == right.code && left.subject == right.subject);
        reembedding_jobs.sort_by_key(|job| (job.target.id, job.source.id));
        let compatible = !findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Blocking);
        let mut report = MigrationCompatibilityReport {
            migration_id,
            workspace_id,
            agent_id,
            stable_subject,
            source_profile: source.model.id,
            target_profile: target.model.id,
            source_runtime_digest: source_digest,
            target_runtime_digest: target_digest,
            source_renderer: source.renderer,
            target_renderer: target.renderer,
            preserved_memory_subject: true,
            findings,
            reembedding_jobs,
            compatible,
            report_digest: ContentDigest::from_bytes([0_u8; 32]),
        };
        report.report_digest = report.compute_digest()?;
        report.validate()?;
        Ok(report)
    }
}

fn cache_rebuild_required(
    source_support: bool,
    target_support: bool,
    source: Option<&PromptCacheNamespace>,
    target: Option<&PromptCacheNamespace>,
) -> bool {
    (source_support || target_support) && source != target
}

fn finding(
    severity: FindingSeverity,
    code: CompatibilityCode,
    subject: impl Into<String>,
    detail: String,
) -> CompatibilityFinding {
    CompatibilityFinding {
        severity,
        code,
        subject: subject.into(),
        detail,
    }
}
