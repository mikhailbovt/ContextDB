//! Post-migration bootstrap planning and validation.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_context::{
    CanonicalSerializer, CompileRequest, CompiledContext, ContextBudgets, ContextCompiler,
    ContextProvider, ModelProfile as ContextModelProfile, PackFacetRequirement, PackPurpose,
    PackStatus, TokenCounter,
};
use contextdb_core::{
    AgentId, ContentDigest, ContinuityProfile, MemorySubjectId, ModelProfileId, ScopeRef,
    TemporalConstraint, WorkspaceId,
};
use contextdb_recall::{ProviderSnapshot, RecallPrincipal};
use serde::{Deserialize, Serialize};

use crate::{
    ConditionalApprovals, ContinuityError, MigrationCompatibilityReport, MigrationId,
    PortableCheckpoint, Result, RuntimeDescriptor, canonical_digest,
};

/// Canonical facet names used by the bounded migration bootstrap pack.
pub mod facets {
    /// Operational agent identity and configured role.
    pub const AGENT_IDENTITY: &str = "agent_identity";
    /// Participant identity relevant to the current session.
    pub const PARTICIPANT_IDENTITY: &str = "participant_identity";
    /// Current relationship role and boundaries.
    pub const RELATIONSHIP_ROLE: &str = "relationship_role";
    /// Current circumstances/time/environment.
    pub const CURRENT_CIRCUMSTANCES: &str = "current_circumstances";
    /// Recent milestones needed for orientation.
    pub const RECENT_MILESTONES: &str = "recent_milestones";
    /// Active goals and unfinished work.
    pub const OPEN_LOOPS: &str = "open_loops";
    /// Corrections that must override stale prior state.
    pub const IMPORTANT_CORRECTIONS: &str = "important_corrections";
    /// Communication and style preferences.
    pub const COMMUNICATION_PREFERENCES: &str = "communication_preferences";
    /// Strict behavioral or disclosure boundaries.
    pub const STRICT_BOUNDARIES: &str = "strict_boundaries";
    /// Small set of active shared references.
    pub const SHARED_REFERENCES: &str = "shared_references";
    /// Projection/index freshness needed to calibrate uncertainty.
    pub const INDEX_FRESHNESS: &str = "index_freshness";
}

/// Deterministic bootstrap request derived from a portable checkpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    /// Portable working state to resume.
    pub checkpoint: PortableCheckpoint,
    /// Exact authoritative continuity profile bound by the checkpoint.
    pub continuity_profile: ContinuityProfile,
    /// Exact source runtime bound by the checkpoint and compatibility report.
    pub source_runtime: RuntimeDescriptor,
    /// Compatibility report for the exact source/target runtime pair.
    pub compatibility: MigrationCompatibilityReport,
    /// Stable caller-provided ContextPack identity; retries reuse it.
    pub pack_id: contextdb_core::ContextPackId,
    /// Target ContextPack profile produced from the M11 runtime descriptor.
    pub model_profile: ContextModelProfile,
    /// Fixed snapshot used by the ContextPack provider.
    pub snapshot: ProviderSnapshot,
    /// M8 recall principal already authorized for the target runtime.
    pub principal: RecallPrincipal,
    /// Exact filter digest shared with the provider/recall layer.
    pub filter_digest: String,
    /// Explicit textual scopes understood by the ContextPack provider.
    pub pack_scopes: BTreeSet<String>,
    /// Explicit semantic scopes recorded in the lifecycle manifest.
    pub semantic_scopes: BTreeSet<ScopeRef>,
    /// Small hard bootstrap budget; deep history is cue-driven later.
    pub budgets: ContextBudgets,
    /// Additional host-required facets and confidence thresholds.
    pub facet_overrides: BTreeMap<String, PackFacetRequirement>,
    /// Whether the caller explicitly requested use of conditional memory.
    pub explicit_memory_request: bool,
    /// Host-supplied time at which migration policy/consent is evaluated.
    pub migration_at: contextdb_core::TimestampMicros,
    /// Explicit approvals for conditional memory/external-processing gates.
    pub approvals: ConditionalApprovals,
}

impl BootstrapRequest {
    /// Validates exact migration/checkpoint/target bindings before provider access.
    pub fn validate(&self, target: &RuntimeDescriptor) -> Result<()> {
        self.checkpoint
            .validate_against(&self.continuity_profile, &self.source_runtime)?;
        self.compatibility.validate()?;
        target.validate()?;
        if !self.compatibility.compatible {
            return Err(ContinuityError::IncompatibleRuntime(
                "bootstrap is blocked by migration compatibility findings".to_owned(),
            ));
        }
        if self.checkpoint.agent_id != self.compatibility.agent_id
            || self.checkpoint.stable_subject != self.compatibility.stable_subject
            || self.checkpoint.workspace_id != self.compatibility.workspace_id
            || self.checkpoint.source_model_profile != self.compatibility.source_profile
            || self.checkpoint.source_runtime_digest != self.compatibility.source_runtime_digest
            || canonical_digest(&self.source_runtime)? != self.compatibility.source_runtime_digest
            || target.model.id != self.compatibility.target_profile
            || canonical_digest(target)? != self.compatibility.target_runtime_digest
        {
            return Err(ContinuityError::IdentityMismatch(
                "bootstrap checkpoint/report/target identities differ".to_owned(),
            ));
        }
        if self.model_profile != target.context_profile()? {
            return Err(ContinuityError::IdentityMismatch(
                "bootstrap renderer profile differs from target runtime adapter".to_owned(),
            ));
        }
        if self.snapshot.commit_seq < self.checkpoint.checkpoint.created_seq.get() {
            return Err(ContinuityError::IdentityMismatch(
                "bootstrap source snapshot predates the portable checkpoint".to_owned(),
            ));
        }
        self.checkpoint.policy.authorize_migration(
            self.checkpoint.stable_subject,
            self.migration_at,
            target.external_processing,
            self.approvals,
        )?;
        if self.pack_scopes.is_empty()
            || self.pack_scopes.iter().any(|scope| scope.trim().is_empty())
            || self.semantic_scopes.is_empty()
        {
            return Err(ContinuityError::InvalidInput(
                "bootstrap requires explicit non-empty pack and semantic scopes".to_owned(),
            ));
        }
        if self.principal.subject != self.checkpoint.stable_subject.to_string()
            || self.principal.workspace != self.checkpoint.workspace_id.to_string()
            || !self.pack_scopes.is_subset(&self.principal.scopes)
        {
            return Err(ContinuityError::IdentityMismatch(
                "bootstrap principal differs from stable subject/workspace/scopes".to_owned(),
            ));
        }
        if self.filter_digest.trim().is_empty() {
            return Err(ContinuityError::InvalidInput(
                "bootstrap filter digest must not be blank".to_owned(),
            ));
        }
        let policy_scopes: BTreeSet<_> = self.checkpoint.policy.scopes.iter().cloned().collect();
        if !self.semantic_scopes.is_subset(&policy_scopes) {
            return Err(ContinuityError::PolicyDenied(
                "bootstrap semantic scopes exceed the checkpoint policy".to_owned(),
            ));
        }
        let semantic_scope_ids: BTreeSet<_> = self
            .semantic_scopes
            .iter()
            .map(|scope| scope.id.to_string())
            .collect();
        if self.pack_scopes != semantic_scope_ids {
            return Err(ContinuityError::IdentityMismatch(
                "bootstrap textual scopes differ from semantic scope identities".to_owned(),
            ));
        }
        Ok(())
    }

    fn required_facets(&self) -> Result<Vec<PackFacetRequirement>> {
        let mut required: BTreeMap<String, PackFacetRequirement> = BTreeMap::new();
        for name in [
            facets::AGENT_IDENTITY,
            facets::PARTICIPANT_IDENTITY,
            facets::RELATIONSHIP_ROLE,
            facets::CURRENT_CIRCUMSTANCES,
            facets::RECENT_MILESTONES,
            facets::OPEN_LOOPS,
            facets::IMPORTANT_CORRECTIONS,
            facets::COMMUNICATION_PREFERENCES,
            facets::STRICT_BOUNDARIES,
            facets::SHARED_REFERENCES,
            facets::INDEX_FRESHNESS,
        ] {
            required.insert(
                name.to_owned(),
                PackFacetRequirement {
                    name: name.to_owned(),
                    minimum_confidence_micros: 700_000,
                    require_evidence: matches!(
                        name,
                        facets::IMPORTANT_CORRECTIONS
                            | facets::STRICT_BOUNDARIES
                            | facets::RECENT_MILESTONES
                    ),
                },
            );
        }
        for name in &self.checkpoint.required_bootstrap_facets {
            required
                .entry(name.clone())
                .or_insert(PackFacetRequirement {
                    name: name.clone(),
                    minimum_confidence_micros: 700_000,
                    require_evidence: false,
                });
        }
        for (name, override_value) in &self.facet_overrides {
            if name != &override_value.name {
                return Err(ContinuityError::InvalidInput(
                    "bootstrap facet override key differs from its name".to_owned(),
                ));
            }
            if let Some(baseline) = required.get(name)
                && (override_value.minimum_confidence_micros < baseline.minimum_confidence_micros
                    || baseline.require_evidence && !override_value.require_evidence)
            {
                return Err(ContinuityError::InvalidInput(
                    "bootstrap facet override weakens a required baseline".to_owned(),
                ));
            }
            required.insert(name.clone(), override_value.clone());
        }
        Ok(required.into_values().collect())
    }
}

/// Compiled bootstrap plus a payload-free migration trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapResult {
    /// Migration/restart operation that produced this bootstrap.
    pub migration_id: MigrationId,
    /// Workspace binding copied from the checkpoint/report.
    pub workspace_id: WorkspaceId,
    /// Stable operational agent copied from the checkpoint/report.
    pub agent_id: AgentId,
    /// Target-rendered M8 pack.
    pub compiled: CompiledContext,
    /// Stable subject explicitly preserved.
    pub stable_subject: MemorySubjectId,
    /// Exact source and target model profiles from compatibility analysis.
    pub source_profile: ModelProfileId,
    /// Exact target model profile from compatibility analysis.
    pub target_profile: ModelProfileId,
    /// Exact portable checkpoint used for compilation.
    pub checkpoint_digest: ContentDigest,
    /// Exact accepted compatibility report.
    pub compatibility_digest: ContentDigest,
    /// Exact target runtime descriptor.
    pub target_runtime_digest: ContentDigest,
    /// Provider snapshot used to compile the pack.
    pub snapshot: ProviderSnapshot,
    /// Exact provider authorization/filter identity.
    pub filter_digest: String,
    /// Open loops present in the portable checkpoint.
    pub checkpoint_open_loops: BTreeSet<contextdb_core::NodeId>,
    /// True when all checkpoint open loops are represented by typed open-loop blocks.
    pub open_loops_preserved: bool,
    /// Complete required memory source set from the portable checkpoint.
    pub checkpoint_required_memory_refs: BTreeSet<contextdb_core::MemoryRef>,
    /// True when every checkpoint-required memory source is in the compiled graph.
    pub required_memory_refs_preserved: bool,
    /// Compatibility warnings intentionally surfaced to the caller.
    pub compatibility_warnings: Vec<crate::CompatibilityFinding>,
    /// Payload-free digest of checkpoint/report/pack identities.
    pub trace_digest: ContentDigest,
}

impl BootstrapResult {
    /// Revalidates artifact bindings, canonical ContextPack bytes, and preservation claims.
    pub fn validate(&self) -> Result<()> {
        self.compiled
            .pack
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        self.snapshot
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        crate::validate_text(&self.filter_digest, "bootstrap filter digest", 512)?;
        crate::ensure_digest_nonzero(self.checkpoint_digest, "bootstrap checkpoint digest")?;
        crate::ensure_digest_nonzero(self.compatibility_digest, "bootstrap compatibility digest")?;
        crate::ensure_digest_nonzero(
            self.target_runtime_digest,
            "bootstrap target runtime digest",
        )?;
        if self.compiled.pack.snapshot != self.snapshot
            || self.compiled.pack.scope_manifest.workspace != self.workspace_id.to_string()
            || self.compiled.pack.scope_manifest.subject != self.stable_subject.to_string()
            || self.compiled.pack.scope_manifest.filter_digest != self.filter_digest
            || self.compiled.pack.purpose != PackPurpose::Bootstrap
        {
            return Err(ContinuityError::IdentityMismatch(
                "bootstrap ContextPack scope/snapshot binding differs".to_owned(),
            ));
        }
        if CanonicalSerializer::digest(&self.compiled.pack)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?
            != self.compiled.canonical_digest
        {
            return Err(ContinuityError::InvalidInput(
                "bootstrap canonical ContextPack digest differs".to_owned(),
            ));
        }
        let expected_json = CanonicalSerializer::to_json(&self.compiled.pack)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        let expected_protobuf = CanonicalSerializer::to_protobuf(&self.compiled.pack)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        if self.compiled.canonical_json != expected_json
            || self.compiled.canonical_protobuf != expected_protobuf
            || self.compiled.rendered.profile_id != self.compiled.pack.compilation.model_profile
            || self.compiled.rendered.renderer != self.compiled.pack.compilation.renderer
            || self.compiled.rendered.control_tokens
                != self.compiled.pack.compilation.usage.control_tokens
            || self.compiled.rendered.data_tokens
                != self.compiled.pack.compilation.usage.data_tokens
            || self.compiled.rendered.total_tokens
                != self.compiled.pack.compilation.usage.rendered_tokens
        {
            return Err(ContinuityError::InvalidInput(
                "bootstrap compiled bytes/rendering differ from the canonical ContextPack"
                    .to_owned(),
            ));
        }
        let represented_open_loop_nodes: BTreeSet<_> = self
            .compiled
            .pack
            .sections
            .open_loops
            .iter()
            .flat_map(|block| &block.memory_refs)
            .filter_map(|memory| match memory {
                contextdb_core::MemoryRef::Node { id } => Some(*id),
                _ => None,
            })
            .collect();
        let expected_open_loops = self
            .checkpoint_open_loops
            .is_subset(&represented_open_loop_nodes);
        let represented_memory_refs: BTreeSet<_> = self
            .compiled
            .pack
            .graph_manifest
            .memory_refs
            .iter()
            .cloned()
            .collect();
        let expected_required = self
            .checkpoint_required_memory_refs
            .is_subset(&represented_memory_refs);
        if self.open_loops_preserved != expected_open_loops
            || self.required_memory_refs_preserved != expected_required
        {
            return Err(ContinuityError::InvalidInput(
                "bootstrap preservation summary differs from its ContextPack".to_owned(),
            ));
        }
        if self
            .compatibility_warnings
            .windows(2)
            .any(|pair| (&pair[0].code, &pair[0].subject) >= (&pair[1].code, &pair[1].subject))
            || self
                .compatibility_warnings
                .iter()
                .any(|finding| finding.severity != crate::FindingSeverity::Warning)
        {
            return Err(ContinuityError::InvalidInput(
                "bootstrap warnings are not canonical warning-only findings".to_owned(),
            ));
        }
        for finding in &self.compatibility_warnings {
            finding.validate()?;
        }
        if self.trace_digest != self.compute_trace_digest()? {
            return Err(ContinuityError::InvalidInput(
                "bootstrap trace digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    fn compute_trace_digest(&self) -> Result<ContentDigest> {
        canonical_digest(&(
            (
                &self.migration_id,
                self.workspace_id,
                self.agent_id,
                self.stable_subject,
                self.source_profile,
                self.target_profile,
                self.checkpoint_digest,
                self.compatibility_digest,
                self.target_runtime_digest,
            ),
            (
                &self.snapshot,
                &self.filter_digest,
                self.compiled.canonical_digest.as_str(),
                &self.checkpoint_open_loops,
                self.open_loops_preserved,
                &self.checkpoint_required_memory_refs,
                self.required_memory_refs_preserved,
                &self.compatibility_warnings,
                &self.compiled.rendered.trusted_control,
                &self.compiled.rendered.untrusted_data,
            ),
        ))
    }
}

/// M8-backed post-migration bootstrap compiler.
#[derive(Clone, Debug)]
pub struct BootstrapCompiler {
    context: ContextCompiler,
}

impl BootstrapCompiler {
    /// Creates a compiler using a host-managed non-zero continuation key.
    pub fn new(continuation_key: [u8; 32]) -> Result<Self> {
        Ok(Self {
            context: ContextCompiler::new(continuation_key)
                .map_err(|error| ContinuityError::Dependency(error.to_string()))?,
        })
    }

    /// Compiles a bounded bootstrap pack after compatibility and identity checks.
    pub fn compile(
        &self,
        request: &BootstrapRequest,
        target: &RuntimeDescriptor,
        provider: &dyn ContextProvider,
        tokenizer: &dyn TokenCounter,
    ) -> Result<BootstrapResult> {
        request.validate(target)?;
        let context_request = CompileRequest {
            pack_id: request.pack_id,
            snapshot: request.snapshot.clone(),
            principal: request.principal.clone(),
            filter_digest: request.filter_digest.clone(),
            purpose: PackPurpose::Bootstrap,
            scopes: request.pack_scopes.clone(),
            temporal_view: TemporalConstraint::Current,
            required_facets: request.required_facets()?,
            budgets: request.budgets,
            model_profile: request.model_profile.clone(),
            explicit_memory_request: request.explicit_memory_request,
            require_primary_evidence: true,
            continuation: None,
        };
        let compiled = self
            .context
            .compile(&context_request, provider, tokenizer)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        if compiled.pack.status == PackStatus::NoMemory {
            return Err(ContinuityError::IncompatibleRuntime(
                "migration bootstrap produced no authorized memory".to_owned(),
            ));
        }
        let checkpoint_open_loops: BTreeSet<_> = request
            .checkpoint
            .checkpoint
            .frame_snapshot
            .open_loops
            .iter()
            .copied()
            .collect();
        let represented_memory_refs: BTreeSet<_> = compiled
            .pack
            .graph_manifest
            .memory_refs
            .iter()
            .cloned()
            .collect();
        let represented_open_loop_nodes: BTreeSet<_> = compiled
            .pack
            .sections
            .open_loops
            .iter()
            .flat_map(|block| &block.memory_refs)
            .filter_map(|memory| match memory {
                contextdb_core::MemoryRef::Node { id } => Some(*id),
                _ => None,
            })
            .collect();
        let open_loops_preserved = checkpoint_open_loops.is_subset(&represented_open_loop_nodes);
        let checkpoint_required_memory_refs: BTreeSet<_> = request
            .checkpoint
            .checkpoint
            .required_memory_refs
            .iter()
            .cloned()
            .collect();
        let required_memory_refs_preserved =
            checkpoint_required_memory_refs.is_subset(&represented_memory_refs);
        let compatibility_warnings = request
            .compatibility
            .findings
            .iter()
            .filter(|finding| finding.severity != crate::FindingSeverity::Informational)
            .cloned()
            .collect();
        let mut result = BootstrapResult {
            migration_id: request.compatibility.migration_id.clone(),
            workspace_id: request.checkpoint.workspace_id,
            agent_id: request.checkpoint.agent_id,
            compiled,
            stable_subject: request.checkpoint.stable_subject,
            source_profile: request.compatibility.source_profile,
            target_profile: request.compatibility.target_profile,
            checkpoint_digest: request.checkpoint.digest,
            compatibility_digest: request.compatibility.report_digest,
            target_runtime_digest: request.compatibility.target_runtime_digest,
            snapshot: request.snapshot.clone(),
            filter_digest: request.filter_digest.clone(),
            checkpoint_open_loops,
            open_loops_preserved,
            checkpoint_required_memory_refs,
            required_memory_refs_preserved,
            compatibility_warnings,
            trace_digest: ContentDigest::from_bytes([0_u8; 32]),
        };
        result.trace_digest = result.compute_trace_digest()?;
        result.validate()?;
        Ok(result)
    }
}
