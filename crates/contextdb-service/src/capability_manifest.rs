//! Stable runtime capability vocabulary shared by status and health surfaces.

use std::collections::BTreeMap;

pub use contextdb_core::{
    CAPABILITY_MANIFEST_SCHEMA_VERSION, CapabilityManifestV1, CapabilityState,
};

/// Capabilities classified by every service status manifest in schema v1.
///
/// The vocabulary deliberately includes important unavailable production
/// executors. Omitting those gaps would turn a machine-readable profile into a
/// marketing string with extra steps.
pub const SERVICE_CAPABILITY_IDS_V1: [&str; 49] = [
    "admin_native_logical_backup",
    "admin_native_pristine_restore",
    "ann_hnsw_runtime",
    "archive_export",
    "archive_import",
    "artifact_blob_store",
    "async_maintenance",
    "background_semantic_adjudication",
    "bootstrap",
    "candidate_hierarchy_dag",
    "canonical_context_pack_protobuf_bytes",
    "checkpoint",
    "compact",
    "compression_zstd",
    "consolidate",
    "context_pack_recall",
    "codex_composite_backup",
    "codex_composite_restore_pristine_native_only",
    "durable_fjall_storage",
    "durable_postflight_receipt",
    "embedded_builder",
    "grpc_transport",
    "handoff",
    "hard_delete",
    "http_transport",
    "journal_graph_projection",
    "lexical_tantivy",
    "live_restore",
    "mcp_transport",
    "native_graph_store",
    "native_service_executor",
    "observation_semantic_extraction",
    "ordered_journal_recovery",
    "persistent_ann_recall_projection",
    "persistent_lexical_recall_projection",
    "pin",
    "policy_first_candidate_recall",
    "policy_first_candidate_traversal",
    "quarantined_memory_proposals",
    "reflect",
    "restart_verification",
    "resume",
    "retention_revision",
    "runtime_model_migration",
    "runtime_state",
    "status",
    "storage_migration",
    "subject_transfer",
    "verify",
];

/// Builds one complete schema-v1 service manifest.
///
/// Every stable capability begins as `unsupported`; explicitly supplied
/// `compiled_only` entries are then promoted, followed by executable
/// `available` entries. Unknown extension identifiers are retained so a newer
/// producer remains additive for map-aware older consumers.
#[must_use]
pub fn service_capability_manifest_v1(
    profile: impl Into<String>,
    available: &[&str],
    compiled_only: &[&str],
) -> CapabilityManifestV1 {
    let mut capabilities = SERVICE_CAPABILITY_IDS_V1
        .into_iter()
        .map(|capability| (capability.to_owned(), CapabilityState::Unsupported))
        .collect::<BTreeMap<_, _>>();
    for capability in compiled_only {
        capabilities.insert((*capability).to_owned(), CapabilityState::CompiledOnly);
    }
    for capability in available {
        capabilities.insert((*capability).to_owned(), CapabilityState::Available);
    }
    CapabilityManifestV1::new(profile, false, capabilities)
}

/// Honest capability declaration for the non-production in-memory reference service.
#[must_use]
pub fn reference_capability_manifest_v1() -> CapabilityManifestV1 {
    service_capability_manifest_v1(
        "reference-in-memory",
        &[
            "context_pack_recall",
            "embedded_builder",
            "hard_delete",
            "status",
            "verify",
        ],
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_manifest_classifies_the_complete_v1_vocabulary() {
        let manifest = reference_capability_manifest_v1();
        assert_eq!(manifest.schema_version, CAPABILITY_MANIFEST_SCHEMA_VERSION);
        assert!(!manifest.server_v1_release_ready);
        assert_eq!(manifest.capabilities.len(), SERVICE_CAPABILITY_IDS_V1.len());
        assert_eq!(
            manifest.capability("context_pack_recall"),
            Some(CapabilityState::Available)
        );
        assert_eq!(
            manifest.capability("persistent_ann_recall_projection"),
            Some(CapabilityState::Unsupported)
        );
        for capability in [
            "background_semantic_adjudication",
            "candidate_hierarchy_dag",
            "consolidate",
            "observation_semantic_extraction",
            "policy_first_candidate_recall",
            "policy_first_candidate_traversal",
            "quarantined_memory_proposals",
            "reflect",
        ] {
            assert_eq!(
                manifest.capability(capability),
                Some(CapabilityState::Unsupported),
                "the reference profile does not implement {capability}"
            );
        }
    }

    #[test]
    fn extension_capabilities_are_additive_and_available_wins() {
        let manifest = service_capability_manifest_v1(
            "extension-test",
            &["future_executor", "status"],
            &["future_executor", "grpc_transport"],
        );
        assert_eq!(
            manifest.capability("future_executor"),
            Some(CapabilityState::Available)
        );
        assert_eq!(
            manifest.capability("grpc_transport"),
            Some(CapabilityState::CompiledOnly)
        );
    }
}
