//! Canonical application contract shared by embedded, gRPC, HTTP, CLI, MCP,
//! and generated SDK adapters.
//!
//! Transport crates translate bytes and status codes only. Authorization,
//! idempotency, snapshots, continuation binding, canonical errors, archive
//! integrity, and explain traces live here.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod assertion;
mod authenticated;
mod capability_manifest;
mod capture;
mod context_pack;
mod continuation;
mod domain;
mod error;
mod high_level;
mod prepare;
mod raw;
mod reference;
mod runtime;
mod streaming;
mod subscription;
mod types;

use authenticated::require_capability;

pub use assertion::*;
pub use authenticated::*;
pub use capability_manifest::*;
pub use capture::*;
pub use context_pack::*;
pub use domain::*;
pub use error::{ErrorCode, ServiceError, ServiceResult};
pub use high_level::{
    HighLevelControlRequest, HighLevelMutationResponse, HighLevelPolicyResult,
    HighLevelQueryRequest, HighLevelSemanticStatus, HighLevelTransferRequest,
    HighLevelWriteRequest,
};
pub use prepare::*;
pub use raw::*;
pub use reference::{HostArchiveAuthority, ReferenceService};
pub use runtime::{
    ValidatedPostflightSubmission, canonical_postflight_record_digest, canonical_preflight_report,
    validate_postflight_submission,
};
pub use streaming::*;
pub use subscription::*;
pub use types::*;

/// Version of the canonical embedded and wire-facing service schema.
pub const SERVICE_SCHEMA_VERSION: u16 = 1;

/// Synchronous canonical application service. Async transports call this
/// boundary from a bounded blocking executor; semantic code remains sync.
pub trait CognitiveMemoryService: Send + Sync {
    /// Captures one immutable observation with durable idempotency.
    fn observe(&self, request: ObserveRequest) -> ServiceResult<ObserveResponse>;

    /// Captures an ordered batch. Each request retains its own idempotency key.
    fn observe_batch(&self, requests: Vec<ObserveRequest>) -> Vec<ServiceResult<ObserveResponse>> {
        requests
            .into_iter()
            .map(|request| self.observe(request))
            .collect()
    }

    /// Runs policy-first lexical recall at one coherent snapshot.
    fn recall(&self, request: RecallRequest) -> ServiceResult<RecallResponse>;

    /// Runs deterministic policy-first recall and compiles its exact authorized
    /// selection into one canonical, model-neutral ContextPack.
    ///
    /// Profiles without a native recall/context executor remain explicitly
    /// unsupported instead of silently falling back to the legacy ID-only
    /// recall surface.
    fn compile_context(
        &self,
        request: CompileContextRequest,
    ) -> ServiceResult<CompileContextResponse> {
        require_capability(&request.context, Capability::Recall)?;
        if request.plan.model_profile.external_processing {
            require_capability(&request.context, Capability::ModelProcessing)?;
        }
        if request.plan.include_evidence_quotes {
            require_capability(&request.context, Capability::RawEvidence)?;
        }
        Err(unsupported(
            "policy-first ContextPack compilation is unavailable in this service profile",
        ))
    }

    /// Returns the privacy-safe trace carried by a recall response.
    fn explain_recall(&self, request: ExplainRecallRequest) -> ServiceResult<RecallTrace>;

    /// Requests a caller-scoped logical export.
    ///
    /// Implementations must authenticate the caller before rejecting an
    /// unsupported scope. Workspace authority must never be interpreted as
    /// permission to materialize a database-global archive.
    fn export_archive(&self, request: ExportRequest) -> ServiceResult<ExportResponse>;

    /// Requests a caller-scoped logical import.
    ///
    /// Implementations must authenticate the caller before rejecting an
    /// unsupported scope. Workspace authority must never replace
    /// database-global state.
    fn import_archive(&self, request: ImportRequest) -> ServiceResult<ImportResponse>;

    /// Performs an in-process logical integrity check.
    fn verify(&self, request: VerifyRequest) -> ServiceResult<VerifyResponse>;

    /// Starts one authenticated conversation session through durable capture.
    fn begin_session(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "BeginSession", true)
    }

    /// Prepares bounded memory for the current turn through canonical recall.
    fn before_turn(&self, request: HighLevelQueryRequest) -> ServiceResult<RecallResponse> {
        high_level::execute_query(self, request, "BeforeTurn", true)
    }

    /// Durably captures one completed user/assistant turn.
    fn after_turn(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "AfterTurn", true)
    }

    /// Resolves a bounded referent candidate set without exposing graph internals.
    fn resolve_referent(&self, request: HighLevelQueryRequest) -> ServiceResult<RecallResponse> {
        high_level::execute_query(self, request, "ResolveReferent", true)
    }

    /// Recalls policy-authorized history for the authenticated shared subject.
    fn recall_shared_history(
        &self,
        request: HighLevelQueryRequest,
    ) -> ServiceResult<RecallResponse> {
        high_level::execute_query(self, request, "RecallSharedHistory", false)
    }

    /// Ends one authenticated conversation session through durable capture.
    fn end_session(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "EndSession", true)
    }

    /// Bootstraps subject continuity with an explicit durable source record.
    fn bootstrap_subject(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "BootstrapSubject", false)
    }

    /// Records an explicit memory candidate through canonical Observe.
    fn remember(&self, request: HighLevelWriteRequest) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "Remember", false)
    }

    /// Pins a memory when the profile has an atomic semantic-control executor.
    fn pin(&self, request: HighLevelControlRequest) -> ServiceResult<MutationResponse> {
        high_level::unsupported_control(
            &request,
            Capability::Correct,
            "Pin",
            "pinning requires an atomic semantic-control executor",
        )
    }

    /// Suppresses a memory when the profile has an atomic semantic-control executor.
    fn suppress(&self, request: HighLevelControlRequest) -> ServiceResult<MutationResponse> {
        high_level::unsupported_control(
            &request,
            Capability::Correct,
            "Suppress",
            "suppression requires an atomic semantic-control executor",
        )
    }

    /// Changes a memory audience without accepting a raw policy/graph patch.
    fn change_audience(&self, request: HighLevelControlRequest) -> ServiceResult<MutationResponse> {
        high_level::unsupported_control(
            &request,
            Capability::Correct,
            "ChangeAudience",
            "audience changes require an atomic policy-revision executor",
        )
    }

    /// Changes retention without pretending that recording a command applied it.
    fn change_retention(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        high_level::unsupported_control(
            &request,
            Capability::Correct,
            "ChangeRetention",
            "retention changes require an atomic policy-revision executor",
        )
    }

    /// Explains authorized memory selection through canonical recall traces.
    fn explain_memory(&self, request: HighLevelQueryRequest) -> ServiceResult<RecallResponse> {
        high_level::execute_query(self, request, "ExplainMemory", false)
    }

    /// Lists authorized subject memories through bounded canonical recall.
    fn list_subject_memories(
        &self,
        request: HighLevelQueryRequest,
    ) -> ServiceResult<RecallResponse> {
        high_level::execute_query(self, request, "ListSubjectMemories", false)
    }

    /// Exports one subject when a profile can prove complete filtered closure.
    fn export_subject(&self, request: HighLevelTransferRequest) -> ServiceResult<ExportResponse> {
        high_level::unsupported_transfer(
            &request,
            Capability::ReadMemory,
            "ExportSubject",
            "subject export requires a complete policy-filtered closure executor",
        )
    }

    /// Imports one subject when a profile can prove atomic archive isolation.
    fn import_subject(&self, request: HighLevelTransferRequest) -> ServiceResult<ImportResponse> {
        require_capability(&request.context, Capability::Observe)?;
        high_level::unsupported_transfer(
            &request,
            Capability::Admin,
            "ImportSubject",
            "subject import requires an atomic subject-archive executor",
        )
    }

    /// Creates a memory subject through an explicit high-level source record.
    fn create_memory_subject(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "CreateMemorySubject", false)
    }

    /// Creates a relationship space without exposing raw graph edges.
    fn create_relationship_space(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "CreateRelationshipSpace", false)
    }

    /// Retrieves a bounded continuity profile through policy-authorized recall.
    fn get_continuity_profile(
        &self,
        request: HighLevelQueryRequest,
    ) -> ServiceResult<RecallResponse> {
        high_level::execute_query(self, request, "GetContinuityProfile", false)
    }

    /// Updates a configured role only through an atomic runtime executor.
    fn update_configured_role(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        high_level::unsupported_control(
            &request,
            Capability::Runtime,
            "UpdateConfiguredRole",
            "configured-role updates require an atomic runtime executor",
        )
    }

    /// Migrates agent runtime only through a checkpoint-aware runtime executor.
    fn migrate_agent_runtime(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        high_level::unsupported_control(
            &request,
            Capability::Runtime,
            "MigrateAgentRuntime",
            "agent runtime migration requires a checkpoint-aware executor",
        )
    }

    /// Publishes to shared memory only through an atomic policy revision.
    fn publish_to_shared_memory(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        high_level::unsupported_control(
            &request,
            Capability::Correct,
            "PublishToSharedMemory",
            "shared-memory publication requires an atomic policy-revision executor",
        )
    }

    /// Revokes shared memory only through an atomic policy revision.
    fn revoke_shared_memory(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        high_level::unsupported_control(
            &request,
            Capability::Correct,
            "RevokeSharedMemory",
            "shared-memory revocation requires an atomic policy-revision executor",
        )
    }

    /// Ingests artifact bytes only through a configured blob/hash executor.
    fn ingest_artifact(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::unsupported_write(
            &request,
            Capability::Observe,
            "IngestArtifact",
            "artifact ingestion requires a configured blob and hash executor",
        )
    }

    /// Attaches artifact metadata to an episode through durable high-level capture.
    fn attach_artifact_to_episode(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "AttachArtifactToEpisode", false)
    }

    /// Adds a derived representation only after a profile verifies its bytes.
    fn add_derived_representation(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::unsupported_write(
            &request,
            Capability::Observe,
            "AddDerivedRepresentation",
            "derived representation requires a configured blob and hash executor",
        )
    }

    /// Records a bounded evidence selector separately from artifact content.
    fn add_evidence_selector(
        &self,
        request: HighLevelWriteRequest,
    ) -> ServiceResult<HighLevelMutationResponse> {
        high_level::execute_write(self, request, "AddEvidenceSelector", false)
    }

    /// Retrieves authorized artifact metadata without returning artifact bytes.
    fn get_artifact_metadata(
        &self,
        request: HighLevelQueryRequest,
    ) -> ServiceResult<RecallResponse> {
        high_level::execute_query(self, request, "GetArtifactMetadata", false)
    }

    /// Deletes complete artifact lineage only through verified hard deletion.
    fn delete_artifact_lineage(
        &self,
        request: HighLevelControlRequest,
    ) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Forget)?;
        high_level::unsupported_control(
            &request,
            Capability::HardDelete,
            "DeleteArtifactLineage",
            "artifact lineage deletion requires a verified closure and erasure executor",
        )
    }

    /// Accepts one ordered, resumable source-revision frame.
    fn ingest_frame(&self, request: IngestFrame) -> ServiceResult<IngestAck> {
        require_capability(&request.context, Capability::StreamIngest)?;
        Err(unsupported(
            "resumable source-revision ingestion is unavailable in this service profile",
        ))
    }

    /// Returns one finite at-least-once subscription delivery page.
    fn subscribe(&self, request: SubscribeRequest) -> ServiceResult<SubscriptionPage> {
        require_capability(&request.context, Capability::Subscribe)?;
        Err(unsupported(
            "memory subscriptions are unavailable in this service profile",
        ))
    }

    /// Publishes one explicitly requested, subject-owned semantic memory.
    ///
    /// This is intentionally separate from raw observation acceptance. The
    /// selected service profile must derive policy from authenticated host
    /// authority and atomically publish a recallable semantic object.
    fn publish_memory(&self, request: PublishMemoryRequest) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Correct)?;
        require_capability(&request.context, Capability::Observe)?;
        Err(unsupported(
            "explicit semantic memory publication is unavailable in this service profile",
        ))
    }

    /// Persists one quarantined structured proposal and its candidate-only
    /// hierarchy links as one atomic mutation.
    fn propose_memory(
        &self,
        request: ProposeMemoryRequest,
    ) -> ServiceResult<ProposeMemoryResponse> {
        require_capability(&request.context, Capability::Observe)?;
        Err(unsupported(
            "quarantined structured-memory proposals are unavailable in this service profile",
        ))
    }

    /// Runs policy-first lexical lookup over quarantined candidates only.
    fn recall_candidates(
        &self,
        request: RecallCandidatesRequest,
    ) -> ServiceResult<RecallCandidatesResponse> {
        require_capability(&request.context, Capability::Recall)?;
        Err(unsupported(
            "quarantined candidate recall is unavailable in this service profile",
        ))
    }

    /// Materializes one authorized quarantined candidate as untrusted data.
    fn get_candidate(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_capability(&request.context, Capability::ReadMemory)?;
        Err(unsupported(
            "quarantined candidate lookup is unavailable in this service profile",
        ))
    }

    /// Traverses only candidate nodes and candidate-only hierarchy links.
    fn traverse_candidates(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        require_capability(&request.context, Capability::Traverse)?;
        Err(unsupported(
            "quarantined candidate traversal is unavailable in this service profile",
        ))
    }

    /// Publishes a correction with an explicit successor identity.
    fn correct(&self, request: CorrectRequest) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Correct)?;
        Err(unsupported(
            "semantic correction is unavailable in this service profile",
        ))
    }

    /// Retracts or hard-deletes a logical record.
    fn forget(&self, request: ForgetRequest) -> ServiceResult<MutationResponse> {
        require_capability(&request.context, Capability::Forget)?;
        Err(unsupported(
            "memory forgetting is unavailable in this service profile",
        ))
    }

    /// Retrieves a node at one coherent snapshot.
    fn get_node(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_capability(&request.context, Capability::ReadMemory)?;
        Err(unsupported(
            "node lookup is unavailable in this service profile",
        ))
    }

    /// Retrieves one ordinary semantic-memory object at a coherent snapshot.
    fn get_memory(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_capability(&request.context, Capability::ReadMemory)?;
        Err(unsupported(
            "semantic-memory lookup is unavailable in this service profile",
        ))
    }

    /// Traverses authorized graph records at one coherent snapshot.
    fn traverse(&self, request: TraverseRequest) -> ServiceResult<TraverseResponse> {
        require_capability(&request.context, Capability::Traverse)?;
        Err(unsupported(
            "graph traversal is unavailable in this service profile",
        ))
    }

    /// Retrieves authorized bitemporal history.
    fn get_timeline(&self, request: GetTimelineRequest) -> ServiceResult<TimelineResponse> {
        require_capability(&request.context, Capability::ReadMemory)?;
        Err(unsupported(
            "memory timeline is unavailable in this service profile",
        ))
    }

    /// Retrieves an evidence record at one coherent snapshot.
    fn get_evidence(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_capability(&request.context, Capability::ReadEvidence)?;
        require_capability(&request.context, Capability::RawEvidence)?;
        Err(unsupported(
            "evidence lookup is unavailable in this service profile",
        ))
    }

    /// Retrieves a conflict-set record at one coherent snapshot.
    fn get_conflict(&self, request: GetMemoryRequest) -> ServiceResult<MemoryRecord> {
        require_capability(&request.context, Capability::ReadConflict)?;
        Err(unsupported(
            "conflict lookup is unavailable in this service profile",
        ))
    }

    /// Compiles runtime bootstrap state.
    fn bootstrap(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_capability(&request.context, Capability::Runtime)?;
        Err(unsupported(
            "runtime bootstrap requires a lifecycle executor",
        ))
    }

    /// Evaluates runtime preflight memory use.
    fn preflight(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_capability(&request.context, Capability::Runtime)?;
        Err(unsupported(
            "runtime preflight requires a lifecycle executor",
        ))
    }

    /// Records runtime postflight state.
    fn postflight(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_capability(&request.context, Capability::Runtime)?;
        Err(unsupported(
            "runtime postflight requires a lifecycle executor",
        ))
    }

    /// Creates a portable runtime checkpoint.
    fn checkpoint(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_capability(&request.context, Capability::Runtime)?;
        Err(unsupported(
            "runtime checkpoint requires a lifecycle executor",
        ))
    }

    /// Resumes a portable runtime checkpoint.
    fn resume(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_capability(&request.context, Capability::Runtime)?;
        Err(unsupported("runtime resume requires a lifecycle executor"))
    }

    /// Compiles a cross-agent runtime handoff.
    fn handoff(&self, request: RuntimeRequest) -> ServiceResult<RuntimeResponse> {
        require_capability(&request.context, Capability::Runtime)?;
        Err(unsupported("runtime handoff requires a lifecycle executor"))
    }

    /// Runs bounded semantic consolidation.
    fn consolidate(&self, request: MaintenanceRequest) -> ServiceResult<MaintenanceResponse> {
        require_capability(&request.context, Capability::Maintenance)?;
        Err(unsupported(
            "consolidation requires a configured maintenance executor",
        ))
    }

    /// Runs bounded reflection.
    fn reflect(&self, request: MaintenanceRequest) -> ServiceResult<MaintenanceResponse> {
        require_capability(&request.context, Capability::Maintenance)?;
        Err(unsupported(
            "reflection requires a configured maintenance executor",
        ))
    }

    /// Rebuilds derived indexes.
    fn reindex(&self, request: MaintenanceRequest) -> ServiceResult<MaintenanceResponse> {
        require_capability(&request.context, Capability::Maintenance)?;
        Err(unsupported(
            "reindexing requires a configured projection executor",
        ))
    }

    /// Compacts physical storage.
    fn compact(&self, request: MaintenanceRequest) -> ServiceResult<MaintenanceResponse> {
        require_capability(&request.context, Capability::Maintenance)?;
        Err(unsupported(
            "compaction requires a physical storage backend",
        ))
    }

    /// Returns content-free administrative status.
    fn get_status(&self, request: GetStatusRequest) -> ServiceResult<StatusResponse> {
        require_capability(&request.context, Capability::Admin)?;
        Err(unsupported(
            "administrative status is unavailable in this service profile",
        ))
    }

    /// Requests a backup within the caller's authenticated authority.
    ///
    /// A workspace administrator is not implicitly a database-global host
    /// administrator.
    fn create_backup(&self, request: CreateBackupRequest) -> ServiceResult<BackupResponse> {
        require_capability(&request.context, Capability::Admin)?;
        Err(unsupported(
            "logical backup is unavailable in this service profile",
        ))
    }

    /// Requests a restore within the caller's authenticated authority.
    ///
    /// A workspace administrator is not implicitly a database-global host
    /// administrator.
    fn restore_backup(
        &self,
        request: RestoreBackupRequest,
    ) -> ServiceResult<RestoreBackupResponse> {
        require_capability(&request.context, Capability::Admin)?;
        Err(unsupported(
            "logical restore is unavailable in this service profile",
        ))
    }

    /// Migrates a physical/logical format through an explicit target version.
    fn migrate_format(&self, request: MigrateFormatRequest) -> ServiceResult<StatusResponse> {
        require_capability(&request.context, Capability::Admin)?;
        Err(unsupported(
            "format migration requires a configured migration executor",
        ))
    }
}

fn unsupported(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::Unsupported, message, false).with_context(
        Vec::new(),
        None,
        Some("select a service profile that advertises this capability".to_owned()),
        None,
    )
}

#[cfg(test)]
mod tests;
