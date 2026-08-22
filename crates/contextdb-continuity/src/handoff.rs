//! Recipient-authorized, source-set-rebuilt handoff compilation.

use std::collections::BTreeSet;

use contextdb_context::{
    BlockId, CanonicalSerializer, CompileRequest, CompiledContext, ContextCompiler, ContextError,
    ContextProvider, EvidenceHandle, EvidencePolicyLabel, PackBlockKind, PackCandidate,
    PackEvidence, PackPurpose, PackStatus, TokenCounter,
};
use contextdb_core::{
    ContentDigest, MemoryRef, MemorySubjectId, NodeId, ScopeId, TimestampMicros, WorkspaceId,
};
use contextdb_recall::ProviderSnapshot;
use serde::{Deserialize, Serialize};

use crate::{
    ConditionalApprovals, ContinuityError, HandoffId, PortableCheckpoint, Result, canonical_digest,
};

/// Explicit multi-agent publication topology. Private state is not a handoff scope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySharingScope {
    /// Agent-private state; rejected by the handoff compiler.
    AgentPrivate,
    /// Explicit sender/recipient shared memory.
    PairwiseShared,
    /// Explicit team audience.
    TeamShared,
    /// Memory shared with a user subject.
    UserShared,
    /// Organisation audience.
    Organisation,
    /// Explicit public publication.
    Public,
}

/// Recipient, publication, expiry, and source-set contract for one handoff.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRequest {
    /// Stable handoff identity, reused by idempotent retries.
    pub id: HandoffId,
    /// Portable checkpoint supplying sender identity and publication policy.
    pub checkpoint: PortableCheckpoint,
    /// M8 request configured for `PackPurpose::Handoff` and recipient principal.
    pub compile: CompileRequest,
    /// Recipient whose explicit export grants will be evaluated.
    pub recipient: MemorySubjectId,
    /// Explicit multi-agent sharing topology.
    pub sharing_scope: MemorySharingScope,
    /// Recipient security compartments evaluated before source materialization.
    pub recipient_compartments: BTreeSet<ScopeId>,
    /// Whether the target renderer/provider crosses a local processing boundary.
    pub target_external_processing: bool,
    /// Explicit approvals for conditional gates.
    pub approvals: ConditionalApprovals,
    /// Candidate identities explicitly approved for handoff consideration.
    pub publishable_blocks: BTreeSet<BlockId>,
    /// Declared memory provenance from which summaries may be rebuilt.
    pub publishable_memory_refs: BTreeSet<MemoryRef>,
    /// Commitments explicitly accepted by the receiving agent/subject.
    pub accepted_commitments: BTreeSet<NodeId>,
    /// Deterministic issue time supplied by the host.
    pub issued_at: TimestampMicros,
    /// Mandatory handoff expiry.
    pub expires_at: TimestampMicros,
    /// Revocation handle checked by the host before every use.
    pub revocation_id: HandoffId,
}

impl HandoffRequest {
    /// Performs recipient policy and request binding before provider labels are read.
    pub fn validate(&self) -> Result<()> {
        self.checkpoint.validate()?;
        self.compile
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        if self.compile.purpose != PackPurpose::Handoff {
            return Err(ContinuityError::InvalidInput(
                "handoff must compile with the export purpose".to_owned(),
            ));
        }
        if self.sharing_scope == MemorySharingScope::AgentPrivate {
            return Err(ContinuityError::PolicyDenied(
                "agent-private memory cannot be published as a handoff".to_owned(),
            ));
        }
        if self.compile.principal.subject != self.recipient.to_string()
            || self.compile.principal.workspace != self.checkpoint.workspace_id.to_string()
        {
            return Err(ContinuityError::IdentityMismatch(
                "handoff recipient principal differs from recipient/workspace".to_owned(),
            ));
        }
        if self.compile.model_profile.external_processing != self.target_external_processing {
            return Err(ContinuityError::IdentityMismatch(
                "handoff external-processing flag differs from model profile".to_owned(),
            ));
        }
        if self.compile.snapshot.commit_seq < self.checkpoint.checkpoint.created_seq.get() {
            return Err(ContinuityError::IdentityMismatch(
                "handoff source snapshot predates the portable checkpoint".to_owned(),
            ));
        }
        let policy_scopes: BTreeSet<_> = self
            .checkpoint
            .policy
            .scopes
            .iter()
            .map(|scope| scope.id.to_string())
            .collect();
        if !self.compile.scopes.is_subset(&policy_scopes) {
            return Err(ContinuityError::PolicyDenied(
                "handoff pack scopes exceed the checkpoint policy".to_owned(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(ContinuityError::InvalidInput(
                "handoff must expire after issue time".to_owned(),
            ));
        }
        if self.publishable_blocks.is_empty() || self.publishable_memory_refs.is_empty() {
            return Err(ContinuityError::InvalidInput(
                "handoff requires an explicit publishable block and memory source set".to_owned(),
            ));
        }
        self.checkpoint.policy.authorize_handoff(
            self.recipient,
            self.issued_at,
            &self.recipient_compartments,
            self.target_external_processing,
            self.approvals,
        )?;
        Ok(())
    }
}

/// Canonical recipient-visible handoff manifest. It contains no memory payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffManifest {
    /// Stable handoff identity.
    pub id: HandoffId,
    /// Sender's stable operational agent identity.
    pub sender_agent: contextdb_core::AgentId,
    /// Recipient subject.
    pub recipient: MemorySubjectId,
    /// Workspace in which publication policy was evaluated.
    pub workspace_id: WorkspaceId,
    /// Exact portable checkpoint used for the handoff.
    pub checkpoint_digest: ContentDigest,
    /// Exact effective policy envelope evaluated before source access.
    pub policy_digest: ContentDigest,
    /// Coherent source snapshot bound into the ContextPack.
    pub snapshot: ProviderSnapshot,
    /// Exact authorization/filter identity used by the provider.
    pub filter_digest: String,
    /// Target ContextPack model/renderer profile identity.
    pub target_model_profile: String,
    /// Explicit publication topology.
    pub sharing_scope: MemorySharingScope,
    /// Canonical selected block IDs after recipient authorization.
    pub selected_blocks: Vec<BlockId>,
    /// Canonical source identities represented by selected blocks.
    pub memory_refs: BTreeSet<MemoryRef>,
    /// Canonical evidence handles independently authorized for the recipient.
    pub evidence_handles: BTreeSet<EvidenceHandle>,
    /// Explicitly accepted commitment node IDs.
    pub accepted_commitments: BTreeSet<NodeId>,
    /// Host-supplied issue time.
    pub issued_at: TimestampMicros,
    /// Expiry time enforced by the host.
    pub expires_at: TimestampMicros,
    /// Revocation handle enforced by the host.
    pub revocation_id: HandoffId,
    /// Digest of the recipient-authorized source set.
    pub source_set_digest: ContentDigest,
    /// Digest of the canonical ContextPack bytes.
    pub pack_digest: String,
    /// Digest of the exact target-rendered trusted/data channels and token counts.
    pub rendered_digest: ContentDigest,
    /// Digest over this manifest excluding this field.
    pub manifest_digest: ContentDigest,
}

impl HandoffManifest {
    /// Validates canonical ordering, accepted commitments, expiry, and digests.
    pub fn validate(&self) -> Result<()> {
        self.snapshot
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        crate::ensure_digest_nonzero(self.checkpoint_digest, "handoff checkpoint digest")?;
        crate::ensure_digest_nonzero(self.policy_digest, "handoff policy digest")?;
        crate::ensure_digest_nonzero(self.rendered_digest, "handoff rendered digest")?;
        crate::validate_text(&self.filter_digest, "handoff filter digest", 512)?;
        crate::validate_text(
            &self.target_model_profile,
            "handoff target model profile",
            512,
        )?;
        if self.expires_at <= self.issued_at {
            return Err(ContinuityError::InvalidInput(
                "handoff manifest is already expired at issue time".to_owned(),
            ));
        }
        if self.sharing_scope == MemorySharingScope::AgentPrivate {
            return Err(ContinuityError::PolicyDenied(
                "agent-private scope is not a publishable handoff manifest".to_owned(),
            ));
        }
        if self
            .selected_blocks
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(ContinuityError::InvalidInput(
                "handoff selected blocks are not in strict canonical order".to_owned(),
            ));
        }
        if self.selected_blocks.is_empty() || self.memory_refs.is_empty() {
            return Err(ContinuityError::InvalidInput(
                "handoff manifest has no selected block or represented memory source".to_owned(),
            ));
        }
        if self.pack_digest.len() != 64
            || !self
                .pack_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ContinuityError::InvalidInput(
                "handoff pack digest is not canonical lowercase hexadecimal".to_owned(),
            ));
        }
        let expected_source = canonical_digest(&(
            &self.selected_blocks,
            &self.memory_refs,
            &self.evidence_handles,
        ))?;
        if self.source_set_digest != expected_source {
            return Err(ContinuityError::InvalidInput(
                "handoff source-set digest mismatch".to_owned(),
            ));
        }
        if self.manifest_digest != self.compute_digest()? {
            return Err(ContinuityError::InvalidInput(
                "handoff manifest digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Enforces issue/expiry and a host-supplied live revocation decision before use.
    pub fn validate_use(&self, now: TimestampMicros, revoked: bool) -> Result<()> {
        self.validate()?;
        if revoked {
            return Err(ContinuityError::PolicyDenied(
                "handoff revocation handle is active".to_owned(),
            ));
        }
        if now < self.issued_at || now >= self.expires_at {
            return Err(ContinuityError::PolicyDenied(
                "handoff is not active at the requested time".to_owned(),
            ));
        }
        Ok(())
    }

    /// Emits compact canonical JSON after complete validation.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| ContinuityError::Serialization(error.to_string()))
    }

    /// Parses canonical JSON and rejects tampering or alternate encodings.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ContinuityError::Serialization(error.to_string()))?;
        value.validate()?;
        if value.to_json()? != bytes {
            return Err(ContinuityError::Serialization(
                "handoff manifest JSON is not canonical".to_owned(),
            ));
        }
        Ok(value)
    }

    fn compute_digest(&self) -> Result<ContentDigest> {
        canonical_digest(&(
            (
                &self.id,
                self.sender_agent,
                self.recipient,
                self.workspace_id,
                self.checkpoint_digest,
                self.policy_digest,
                &self.snapshot,
                &self.filter_digest,
                &self.target_model_profile,
            ),
            (
                self.sharing_scope,
                &self.selected_blocks,
                &self.memory_refs,
                &self.evidence_handles,
                &self.accepted_commitments,
                self.issued_at,
                self.expires_at,
                &self.revocation_id,
                self.source_set_digest,
                &self.pack_digest,
                self.rendered_digest,
            ),
        ))
    }
}

/// Recipient-visible handoff artifact and its compiled ContextPack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffResult {
    /// Handoff-purpose ContextPack rebuilt from recipient-authorized sources.
    pub compiled: CompiledContext,
    /// Payload-free publication/audit manifest.
    pub manifest: HandoffManifest,
}

impl HandoffResult {
    /// Revalidates canonical bytes, rendered channels, manifest, and source-set bindings.
    pub fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        self.compiled
            .pack
            .validate()
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        let expected_json = CanonicalSerializer::to_json(&self.compiled.pack)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        let expected_protobuf = CanonicalSerializer::to_protobuf(&self.compiled.pack)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        let expected_pack_digest = CanonicalSerializer::digest(&self.compiled.pack)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        let expected_rendered_digest = canonical_digest(&(
            &self.compiled.rendered.profile_id,
            self.compiled.rendered.renderer,
            &self.compiled.rendered.trusted_control,
            &self.compiled.rendered.untrusted_data,
            self.compiled.rendered.control_tokens,
            self.compiled.rendered.data_tokens,
            self.compiled.rendered.total_tokens,
        ))?;
        let mut selected_blocks = self.compiled.pack.compilation.selected_blocks.clone();
        selected_blocks.sort();
        let memory_refs = self.compiled.pack.graph_manifest.memory_refs.clone();
        let evidence_handles: BTreeSet<_> = self
            .compiled
            .pack
            .evidence
            .iter()
            .map(|evidence| evidence.id.clone())
            .collect();
        if self.compiled.canonical_json != expected_json
            || self.compiled.canonical_protobuf != expected_protobuf
            || self.compiled.canonical_digest != expected_pack_digest
            || self.manifest.pack_digest != expected_pack_digest
            || self.manifest.rendered_digest != expected_rendered_digest
            || self.compiled.rendered.profile_id != self.compiled.pack.compilation.model_profile
            || self.compiled.rendered.renderer != self.compiled.pack.compilation.renderer
            || self.compiled.rendered.control_tokens
                != self.compiled.pack.compilation.usage.control_tokens
            || self.compiled.rendered.data_tokens
                != self.compiled.pack.compilation.usage.data_tokens
            || self.compiled.rendered.total_tokens
                != self.compiled.pack.compilation.usage.rendered_tokens
            || self.manifest.snapshot != self.compiled.pack.snapshot
            || self.manifest.filter_digest != self.compiled.pack.scope_manifest.filter_digest
            || self.manifest.target_model_profile != self.compiled.rendered.profile_id
            || self.manifest.workspace_id.to_string() != self.compiled.pack.scope_manifest.workspace
            || self.manifest.recipient.to_string() != self.compiled.pack.scope_manifest.subject
            || self.manifest.selected_blocks != selected_blocks
            || self.manifest.memory_refs != memory_refs
            || self.manifest.evidence_handles != evidence_handles
        {
            return Err(ContinuityError::InvalidInput(
                "handoff compiled output differs from its manifest".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Pure M8-backed handoff compiler.
#[derive(Clone, Debug)]
pub struct HandoffCompiler {
    context: ContextCompiler,
}

impl HandoffCompiler {
    /// Creates a handoff compiler with a host-managed non-zero continuation key.
    pub fn new(continuation_key: [u8; 32]) -> Result<Self> {
        Ok(Self {
            context: ContextCompiler::new(continuation_key)
                .map_err(|error| ContinuityError::Dependency(error.to_string()))?,
        })
    }

    /// Applies policy before provider labels, rebuilds the pack, and seals a manifest.
    pub fn compile(
        &self,
        request: &HandoffRequest,
        provider: &dyn ContextProvider,
        tokenizer: &dyn TokenCounter,
    ) -> Result<HandoffResult> {
        request.validate()?;
        let scoped = PublishableSourceProvider {
            inner: provider,
            blocks: &request.publishable_blocks,
            memory_refs: &request.publishable_memory_refs,
        };
        let compiled = self
            .context
            .compile(&request.compile, &scoped, tokenizer)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?;
        if compiled.pack.status == PackStatus::NoMemory {
            return Err(ContinuityError::PolicyDenied(
                "handoff source set produced no recipient-authorized memory".to_owned(),
            ));
        }
        if compiled.pack.sections.iter().any(|block| {
            !matches!(
                block.kind,
                PackBlockKind::Situation
                    | PackBlockKind::Fact
                    | PackBlockKind::Boundary
                    | PackBlockKind::Goal
                    | PackBlockKind::Decision
                    | PackBlockKind::Procedure
                    | PackBlockKind::Constraint
                    | PackBlockKind::OpenLoop
                    | PackBlockKind::Conflict
                    | PackBlockKind::Unknown
            )
        }) {
            return Err(ContinuityError::PolicyDenied(
                "handoff contains a category outside goal/state/decision/constraint/open-loop/evidence/unknown scope"
                    .to_owned(),
            ));
        }
        let represented_commitments: BTreeSet<_> = compiled
            .pack
            .graph_manifest
            .memory_refs
            .iter()
            .filter_map(|item| match item {
                MemoryRef::Node { id } => Some(*id),
                _ => None,
            })
            .collect();
        if !request
            .accepted_commitments
            .is_subset(&represented_commitments)
        {
            return Err(ContinuityError::InvalidInput(
                "accepted commitment is absent from the recipient-visible pack".to_owned(),
            ));
        }
        let mut selected_blocks = compiled.pack.compilation.selected_blocks.clone();
        selected_blocks.sort();
        let memory_refs = compiled.pack.graph_manifest.memory_refs.clone();
        let evidence_handles = compiled
            .pack
            .evidence
            .iter()
            .map(|evidence| evidence.id.clone())
            .collect();
        let source_set_digest =
            canonical_digest(&(&selected_blocks, &memory_refs, &evidence_handles))?;
        let policy_digest = canonical_digest(&request.checkpoint.policy)?;
        let rendered_digest = canonical_digest(&(
            &compiled.rendered.profile_id,
            compiled.rendered.renderer,
            &compiled.rendered.trusted_control,
            &compiled.rendered.untrusted_data,
            compiled.rendered.control_tokens,
            compiled.rendered.data_tokens,
            compiled.rendered.total_tokens,
        ))?;
        let mut manifest = HandoffManifest {
            id: request.id.clone(),
            sender_agent: request.checkpoint.agent_id,
            recipient: request.recipient,
            workspace_id: request.checkpoint.workspace_id,
            checkpoint_digest: request.checkpoint.digest,
            policy_digest,
            snapshot: request.compile.snapshot.clone(),
            filter_digest: request.compile.filter_digest.clone(),
            target_model_profile: request.compile.model_profile.id.clone(),
            sharing_scope: request.sharing_scope,
            selected_blocks,
            memory_refs,
            evidence_handles,
            accepted_commitments: request.accepted_commitments.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            revocation_id: request.revocation_id.clone(),
            source_set_digest,
            pack_digest: compiled.canonical_digest.clone(),
            rendered_digest,
            manifest_digest: ContentDigest::from_bytes([0_u8; 32]),
        };
        manifest.manifest_digest = manifest.compute_digest()?;
        manifest.validate()?;
        if CanonicalSerializer::digest(&compiled.pack)
            .map_err(|error| ContinuityError::Dependency(error.to_string()))?
            != manifest.pack_digest
        {
            return Err(ContinuityError::InvalidInput(
                "handoff manifest and ContextPack digest differ".to_owned(),
            ));
        }
        let result = HandoffResult { compiled, manifest };
        result.validate()?;
        Ok(result)
    }
}

#[derive(Debug)]
struct PublishableSourceProvider<'a> {
    inner: &'a dyn ContextProvider,
    blocks: &'a BTreeSet<BlockId>,
    memory_refs: &'a BTreeSet<MemoryRef>,
}

impl ContextProvider for PublishableSourceProvider<'_> {
    fn snapshot(&self) -> contextdb_context::Result<ProviderSnapshot> {
        self.inner.snapshot()
    }

    fn candidate_labels(
        &self,
    ) -> contextdb_context::Result<Vec<contextdb_context::CandidatePolicyLabel>> {
        Ok(self
            .inner
            .candidate_labels()?
            .into_iter()
            .filter(|label| self.blocks.contains(&label.id))
            .collect())
    }

    fn materialize_candidate(&self, id: &BlockId) -> contextdb_context::Result<PackCandidate> {
        if !self.blocks.contains(id) {
            return Err(ContextError::Authorization(
                "candidate is outside the explicit publishable handoff source set".to_owned(),
            ));
        }
        let candidate = self.inner.materialize_candidate(id)?;
        if candidate
            .memory_refs
            .iter()
            .any(|memory| !self.memory_refs.contains(memory))
        {
            return Err(ContextError::Authorization(
                "candidate provenance exceeds the publishable handoff source set".to_owned(),
            ));
        }
        Ok(candidate)
    }

    fn evidence_labels(
        &self,
        requested: &[EvidenceHandle],
    ) -> contextdb_context::Result<Vec<EvidencePolicyLabel>> {
        self.inner.evidence_labels(requested)
    }

    fn materialize_evidence(&self, id: &EvidenceHandle) -> contextdb_context::Result<PackEvidence> {
        self.inner.materialize_evidence(id)
    }
}
