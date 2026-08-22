//! Typed policy and physical-projection maintenance transactions.
//!
//! Maintenance records never become semantic truth by themselves. They make
//! publication of policy revisions and rebuildable generations explicit,
//! ordered, auditable, and replayable alongside semantic commits.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    ContentDigest, DeletionJobId, DerivedWorkItem, HierarchyViewId, LineageNode, MutationId,
    NonEmptyVec, PolicyId, SemanticEnvelope, SnapshotRef, SummaryId, Validate, ValidationError,
    ValidationResult,
};

/// One atomic maintenance decision. Large physical work is staged separately;
/// this operation is the small publish/switch record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MaintenanceOperation {
    /// Replaces the effective policy for one lineage-addressable object.
    PolicyRevision {
        policy_id: PolicyId,
        target: LineageNode,
        envelope: Box<SemanticEnvelope>,
    },
    /// Atomically exposes a verified hierarchy generation.
    HierarchyPublication {
        view_id: HierarchyViewId,
        generation: u64,
        manifest_digest: ContentDigest,
    },
    /// Publishes a derived summary revision without changing its sources.
    SummaryRevision {
        summary_id: SummaryId,
        revision: u64,
        content_digest: ContentDigest,
    },
    /// Records an explicit merge or split decision and its complete lineage.
    MergeSplitDecision {
        namespace: String,
        identifier: String,
        inputs: NonEmptyVec<LineageNode>,
        outputs: NonEmptyVec<LineageNode>,
    },
    /// Publishes closure of a deletion propagation job.
    DeletionPropagation {
        job_id: DeletionJobId,
        targets: NonEmptyVec<LineageNode>,
    },
    /// Records a physical compaction generation; semantic identity is unchanged.
    CompactionMetadata {
        component: String,
        from_generation: u64,
        to_generation: u64,
        manifest_digest: ContentDigest,
    },
    /// Atomically selects a fully built derived-index generation.
    IndexGenerationSwitch {
        index: String,
        from_generation: u64,
        to_generation: u64,
        manifest_digest: ContentDigest,
    },
}

impl Validate for MaintenanceOperation {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::PolicyRevision {
                target, envelope, ..
            } => {
                target.validate()?;
                envelope.validate()
            }
            Self::HierarchyPublication {
                generation,
                manifest_digest,
                ..
            } => validate_generation(*generation, manifest_digest),
            Self::SummaryRevision {
                revision,
                content_digest,
                ..
            } => validate_generation(*revision, content_digest),
            Self::MergeSplitDecision {
                namespace,
                identifier,
                inputs,
                outputs,
            } => {
                crate::provenance::validate_non_blank(namespace, "maintenance.namespace")?;
                crate::provenance::validate_non_blank(identifier, "maintenance.identifier")?;
                validate_lineage_set(inputs, "maintenance.inputs")?;
                validate_lineage_set(outputs, "maintenance.outputs")
            }
            Self::DeletionPropagation { targets, .. } => {
                validate_lineage_set(targets, "maintenance.targets")
            }
            Self::CompactionMetadata {
                component,
                from_generation,
                to_generation,
                manifest_digest,
            } => {
                crate::provenance::validate_non_blank(component, "maintenance.component")?;
                validate_generation_switch(*from_generation, *to_generation, manifest_digest)
            }
            Self::IndexGenerationSwitch {
                index,
                from_generation,
                to_generation,
                manifest_digest,
            } => {
                crate::provenance::validate_non_blank(index, "maintenance.index")?;
                validate_generation_switch(*from_generation, *to_generation, manifest_digest)
            }
        }
    }
}

/// Exact logical payload published by the ordered maintenance transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceMutationSet {
    pub id: MutationId,
    pub base_snapshot: SnapshotRef,
    pub operation: MaintenanceOperation,
    /// Rebuildable work made visible atomically with the publish record.
    pub derived_work: Vec<DerivedWorkItem>,
}

impl Validate for MaintenanceMutationSet {
    fn validate(&self) -> ValidationResult {
        self.operation.validate()
    }
}

fn validate_generation(value: u64, digest: &ContentDigest) -> ValidationResult {
    if value == 0 {
        return Err(ValidationError::InvalidState {
            reason: "maintenance generation must be positive",
        });
    }
    if digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ValidationError::InvalidState {
            reason: "maintenance manifest digest must not be zero",
        });
    }
    Ok(())
}

fn validate_generation_switch(from: u64, to: u64, digest: &ContentDigest) -> ValidationResult {
    validate_generation(to, digest)?;
    if to <= from {
        return Err(ValidationError::InvalidState {
            reason: "maintenance generation switch must advance",
        });
    }
    Ok(())
}

fn validate_lineage_set(
    values: &NonEmptyVec<LineageNode>,
    field: &'static str,
) -> ValidationResult {
    let mut distinct = BTreeSet::new();
    for value in values {
        value.validate()?;
        if !distinct.insert(value) {
            return Err(ValidationError::DuplicateIdentifier { field });
        }
    }
    Ok(())
}
