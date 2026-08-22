use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    BackupSigningKey, BackupVerifyingKey, SecurityError, SecurityResult, canonical_json, digest,
    require_label,
};

const DELETION_SIGNATURE_DOMAIN: &[u8] = b"contextdb/deletion-receipt/v1\0";

/// Required deletion target class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionTargetClass {
    /// Primary source/content bytes.
    PrimaryContent,
    /// Episode/block representation.
    Episode,
    /// Evidence spans or materialization handles.
    Evidence,
    /// Canonical claim or typed memory.
    SemanticMemory,
    /// Derived summary or hierarchy materialization.
    Summary,
    /// Embedding bytes.
    Embedding,
    /// ANN generation or tombstone.
    AnnIndex,
    /// Lexical-search document.
    LexicalIndex,
    /// Cache entry or prompt cache.
    Cache,
    /// Checkpoint or multi-agent handoff.
    CheckpointOrHandoff,
    /// External model-provider retained copy.
    ProviderCopy,
    /// Managed export.
    Export,
    /// Managed backup.
    Backup,
}

/// How a deletion target was resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionDisposition {
    /// Target is immediately suppressed but physical work remains.
    SuppressedPending,
    /// Bytes/index entry were physically removed.
    Deleted,
    /// Derived object was rebuilt from remaining authorized evidence.
    Rebuilt,
    /// Dedicated encryption key was destroyed after complete copy inventory.
    CryptographicallyErased,
    /// Target was proven absent for this lineage.
    ProvenAbsent,
    /// An external processor acknowledged deletion with a receipt digest.
    ExternalReceipt,
}

impl DeletionDisposition {
    fn is_complete(self) -> bool {
        !matches!(self, Self::SuppressedPending)
    }
}

/// One content-free deletion target and its verification evidence.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionTarget {
    /// Stable target identity or one-way identity digest.
    pub target_id: String,
    /// Target class.
    pub class: DeletionTargetClass,
    /// Resolution state.
    pub disposition: DeletionDisposition,
    /// Digest of verification output or external receipt.
    pub verification_digest: Option<String>,
    /// Last logical update time.
    pub updated_at_micros: i64,
}

impl fmt::Debug for DeletionTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeletionTarget")
            .field("target_id", &"[REDACTED]")
            .field("class", &self.class)
            .field("disposition", &self.disposition)
            .field("has_verification", &self.verification_digest.is_some())
            .field("updated_at_micros", &self.updated_at_micros)
            .finish()
    }
}

/// Independent authority that validates both the enumerated dependency
/// closure and each completion proof before a deletion receipt can be signed.
/// Implementations typically query canonical lineage, storage indexes,
/// provider receipts, export registries, and backup catalogs.
pub trait DeletionEvidenceVerifier {
    /// Verifies one target's disposition and evidence digest against its owning
    /// authoritative system rather than trusting caller-supplied syntax.
    fn verify_target(
        &self,
        deletion_id: &str,
        workspace_id: &str,
        root_lineage_digest: &str,
        target: &DeletionTarget,
    ) -> SecurityResult<()>;

    /// Proves that the complete authoritative dependency inventory is exactly
    /// represented by the proposed targets and immediate suppression set.
    fn verify_closure(
        &self,
        deletion_id: &str,
        workspace_id: &str,
        root_lineage_digest: &str,
        suppressed_ids: &BTreeSet<String>,
        targets: &[DeletionTarget],
    ) -> SecurityResult<()>;
}

/// Signed, machine-verifiable deletion completion receipt.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionReceipt {
    /// Workflow identity.
    pub deletion_id: String,
    /// Database/workspace identity.
    pub workspace_id: String,
    /// One-way root lineage identity digest.
    pub root_lineage_digest: String,
    /// Current policy digest that enforces immediate suppression.
    pub policy_digest: String,
    /// Workflow creation time.
    pub requested_at_micros: i64,
    /// Completion time.
    pub completed_at_micros: i64,
    /// Every inventoried primary, derived, provider, export, and backup target.
    pub targets: Vec<DeletionTarget>,
    /// Digest of the canonical unsigned receipt.
    pub receipt_digest: String,
    /// Signing-key identifier.
    pub signing_key_id: String,
    /// Ed25519 signature over the receipt digest in a deletion-specific domain.
    pub signature: Vec<u8>,
}

impl fmt::Debug for DeletionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeletionReceipt")
            .field("deletion_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("root_lineage_digest", &"[REDACTED]")
            .field("policy_digest", &"[REDACTED]")
            .field("requested_at_micros", &self.requested_at_micros)
            .field("completed_at_micros", &self.completed_at_micros)
            .field("target_count", &self.targets.len())
            .field("receipt_digest", &"[REDACTED]")
            .field("signing_key_id", &self.signing_key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct UnsignedReceipt<'a> {
    deletion_id: &'a str,
    workspace_id: &'a str,
    root_lineage_digest: &'a str,
    policy_digest: &'a str,
    requested_at_micros: i64,
    completed_at_micros: i64,
    targets: &'a [DeletionTarget],
}

/// Deletion workflow with a live deny overlay that applies to old snapshots.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionWorkflow {
    deletion_id: String,
    workspace_id: String,
    root_lineage_digest: String,
    policy_digest: String,
    requested_at_micros: i64,
    suppressed_ids: BTreeSet<String>,
    targets: BTreeMap<String, DeletionTarget>,
}

impl fmt::Debug for DeletionWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeletionWorkflow")
            .field("deletion_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("root_lineage_digest", &"[REDACTED]")
            .field("policy_digest", &"[REDACTED]")
            .field("requested_at_micros", &self.requested_at_micros)
            .field("suppressed_count", &self.suppressed_ids.len())
            .field("target_count", &self.targets.len())
            .finish_non_exhaustive()
    }
}

impl DeletionWorkflow {
    /// Starts a deletion and atomically establishes the live deny overlay.
    pub fn new(
        deletion_id: impl Into<String>,
        workspace_id: impl Into<String>,
        root_lineage_digest: impl Into<String>,
        policy_digest: impl Into<String>,
        requested_at_micros: i64,
        immediately_suppressed_ids: BTreeSet<String>,
    ) -> SecurityResult<Self> {
        let deletion_id = deletion_id.into();
        let workspace_id = workspace_id.into();
        let root_lineage_digest = root_lineage_digest.into();
        let policy_digest = policy_digest.into();
        require_label(&deletion_id, "deletion_id")?;
        require_label(&workspace_id, "workspace_id")?;
        require_digest(&root_lineage_digest, "root_lineage_digest")?;
        require_digest(&policy_digest, "policy_digest")?;
        if immediately_suppressed_ids.is_empty() {
            return Err(SecurityError::InvalidInput(
                "deletion must immediately suppress at least one lineage identity".to_owned(),
            ));
        }
        for identity in &immediately_suppressed_ids {
            require_label(identity, "suppressed_id")?;
        }
        Ok(Self {
            deletion_id,
            workspace_id,
            root_lineage_digest,
            policy_digest,
            requested_at_micros,
            suppressed_ids: immediately_suppressed_ids,
            targets: BTreeMap::new(),
        })
    }

    /// Checks the live deletion overlay. Every recall, including old snapshot
    /// reads, must call this before candidate generation or materialization.
    #[must_use]
    pub fn is_suppressed(&self, identity: &str) -> bool {
        self.suppressed_ids.contains(identity)
    }

    /// Extends the dependency closure and immediately suppresses it.
    pub fn suppress_dependency(&mut self, identity: impl Into<String>) -> SecurityResult<()> {
        let identity = identity.into();
        require_label(&identity, "suppressed_dependency")?;
        self.suppressed_ids.insert(identity);
        Ok(())
    }

    /// Records or idempotently replays a deletion target. A changed target at
    /// the same logical time is rejected; progress requires a later time.
    pub fn record_target(&mut self, target: DeletionTarget) -> SecurityResult<()> {
        validate_target(&target)?;
        if target.updated_at_micros < self.requested_at_micros {
            return Err(SecurityError::IntegrityFailure(
                "deletion target update predates the workflow".to_owned(),
            ));
        }
        self.suppressed_ids.insert(target.target_id.clone());
        if let Some(previous) = self.targets.get(&target.target_id) {
            if previous == &target {
                return Ok(());
            }
            if target.updated_at_micros <= previous.updated_at_micros
                || previous.disposition.is_complete()
            {
                return Err(SecurityError::IntegrityFailure(
                    "deletion target regressed or was rewritten".to_owned(),
                ));
            }
        }
        self.targets.insert(target.target_id.clone(), target);
        Ok(())
    }

    /// Seals a receipt only when all mandatory target classes are inventoried
    /// and every target has independently verifiable completion evidence.
    pub fn complete(
        &self,
        completed_at_micros: i64,
        signing_key: &BackupSigningKey,
        evidence_verifier: &dyn DeletionEvidenceVerifier,
    ) -> SecurityResult<DeletionReceipt> {
        if completed_at_micros < self.requested_at_micros {
            return Err(SecurityError::InvalidInput(
                "deletion completion predates request".to_owned(),
            ));
        }
        for class in mandatory_target_classes() {
            if !self.targets.values().any(|target| target.class == class) {
                return Err(SecurityError::DeletionIncomplete(format!(
                    "missing disposition for {class:?}"
                )));
            }
        }
        if self.targets.values().any(|target| {
            !target.disposition.is_complete()
                || target.verification_digest.is_none()
                || target.updated_at_micros > completed_at_micros
        }) {
            return Err(SecurityError::DeletionIncomplete(
                "one or more targets remain pending or unverified".to_owned(),
            ));
        }
        let targets = self.targets.values().cloned().collect::<Vec<_>>();
        for target in &targets {
            evidence_verifier.verify_target(
                &self.deletion_id,
                &self.workspace_id,
                &self.root_lineage_digest,
                target,
            )?;
        }
        evidence_verifier.verify_closure(
            &self.deletion_id,
            &self.workspace_id,
            &self.root_lineage_digest,
            &self.suppressed_ids,
            &targets,
        )?;
        let unsigned = UnsignedReceipt {
            deletion_id: &self.deletion_id,
            workspace_id: &self.workspace_id,
            root_lineage_digest: &self.root_lineage_digest,
            policy_digest: &self.policy_digest,
            requested_at_micros: self.requested_at_micros,
            completed_at_micros,
            targets: &targets,
        };
        let receipt_digest = digest(&canonical_json(&unsigned)?);
        let signature =
            signing_key.sign_domain(DELETION_SIGNATURE_DOMAIN, receipt_digest.as_bytes());
        Ok(DeletionReceipt {
            deletion_id: self.deletion_id.clone(),
            workspace_id: self.workspace_id.clone(),
            root_lineage_digest: self.root_lineage_digest.clone(),
            policy_digest: self.policy_digest.clone(),
            requested_at_micros: self.requested_at_micros,
            completed_at_micros,
            targets,
            receipt_digest,
            signing_key_id: signing_key.key_id().to_owned(),
            signature,
        })
    }
}

impl DeletionReceipt {
    /// Verifies canonical digest, mandatory completion, and signature.
    pub fn verify(&self, verifying_key: &BackupVerifyingKey) -> SecurityResult<()> {
        if self.signing_key_id != verifying_key.key_id {
            return Err(SecurityError::IntegrityFailure(
                "deletion receipt key ID mismatch".to_owned(),
            ));
        }
        require_label(&self.deletion_id, "deletion_id")?;
        require_label(&self.workspace_id, "workspace_id")?;
        require_digest(&self.root_lineage_digest, "root_lineage_digest")?;
        require_digest(&self.policy_digest, "policy_digest")?;
        require_digest(&self.receipt_digest, "receipt_digest")?;
        if self.completed_at_micros < self.requested_at_micros {
            return Err(SecurityError::IntegrityFailure(
                "deletion receipt completion predates request".to_owned(),
            ));
        }
        let mut target_ids = BTreeSet::new();
        for target in &self.targets {
            validate_target(target)?;
            if !target_ids.insert(&target.target_id) {
                return Err(SecurityError::IntegrityFailure(
                    "deletion receipt contains duplicate target identities".to_owned(),
                ));
            }
            if !target.disposition.is_complete() || target.verification_digest.is_none() {
                return Err(SecurityError::DeletionIncomplete(
                    "receipt contains an incomplete target".to_owned(),
                ));
            }
            if target.updated_at_micros < self.requested_at_micros
                || target.updated_at_micros > self.completed_at_micros
            {
                return Err(SecurityError::IntegrityFailure(
                    "deletion receipt target time is outside the workflow interval".to_owned(),
                ));
            }
        }
        for class in mandatory_target_classes() {
            if !self.targets.iter().any(|target| target.class == class) {
                return Err(SecurityError::DeletionIncomplete(format!(
                    "receipt is missing disposition for {class:?}"
                )));
            }
        }
        let unsigned = UnsignedReceipt {
            deletion_id: &self.deletion_id,
            workspace_id: &self.workspace_id,
            root_lineage_digest: &self.root_lineage_digest,
            policy_digest: &self.policy_digest,
            requested_at_micros: self.requested_at_micros,
            completed_at_micros: self.completed_at_micros,
            targets: &self.targets,
        };
        let expected = digest(&canonical_json(&unsigned)?);
        if expected != self.receipt_digest {
            return Err(SecurityError::IntegrityFailure(
                "deletion receipt digest mismatch".to_owned(),
            ));
        }
        verifying_key.verify_domain(
            DELETION_SIGNATURE_DOMAIN,
            self.receipt_digest.as_bytes(),
            &self.signature,
        )
    }
}

fn mandatory_target_classes() -> [DeletionTargetClass; 13] {
    [
        DeletionTargetClass::PrimaryContent,
        DeletionTargetClass::Episode,
        DeletionTargetClass::Evidence,
        DeletionTargetClass::SemanticMemory,
        DeletionTargetClass::Summary,
        DeletionTargetClass::Embedding,
        DeletionTargetClass::AnnIndex,
        DeletionTargetClass::LexicalIndex,
        DeletionTargetClass::Cache,
        DeletionTargetClass::CheckpointOrHandoff,
        DeletionTargetClass::ProviderCopy,
        DeletionTargetClass::Export,
        DeletionTargetClass::Backup,
    ]
}

fn validate_target(target: &DeletionTarget) -> SecurityResult<()> {
    require_label(&target.target_id, "deletion_target_id")?;
    if let Some(value) = &target.verification_digest {
        require_digest(value, "deletion_verification_digest")?;
    }
    Ok(())
}

fn require_digest(value: &str, field: &str) -> SecurityResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SecurityError::InvalidInput(field.to_owned()));
    }
    Ok(())
}
