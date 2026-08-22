use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    DeletionHandleV2, DeletionReceiptVerifierV2, DeletionTargetHandleV2, EvidenceHandleV2,
    KeyHandleV2, Result, SECURE_STORE_FORMAT_VERSION, SecureStoreError, SignedDeletionReceiptV2,
    StateNamespaceV2, StateRootV2, canonical_json,
};

/// Maximum JSON bytes accepted when recovering one deletion workflow.
pub const MAX_DELETION_WORKFLOW_JSON_BYTES_V2: usize = 8 * 1024 * 1024;
/// Maximum opaque targets in one authoritative deletion closure.
pub const MAX_DELETION_CLOSURE_TARGETS_V2: usize = 65_536;

/// The authoritative 13 dependency classes in every hard-delete closure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionClosureClassV2 {
    /// Original source/content bytes.
    PrimaryContent,
    /// Episode/block materialization.
    Episode,
    /// Evidence spans and source handles.
    Evidence,
    /// Canonical claims or typed memories.
    SemanticMemory,
    /// Derived summaries and hierarchy materializations.
    Summary,
    /// Embedding vectors.
    Embedding,
    /// ANN generations, postings, and tombstones.
    AnnIndex,
    /// Lexical documents and postings.
    LexicalIndex,
    /// Caches, prompt caches, and retained materializations.
    Cache,
    /// Checkpoints and multi-agent handoffs.
    CheckpointOrHandoff,
    /// Copies retained by an external model or tool provider.
    ProviderCopy,
    /// Managed export copies.
    Export,
    /// Managed backup copies.
    Backup,
}

impl DeletionClosureClassV2 {
    /// Returns whether the class requires a managed-copy disposition.
    #[must_use]
    pub const fn is_managed_copy(self) -> bool {
        matches!(self, Self::ProviderCopy | Self::Export | Self::Backup)
    }
}

/// Exact ordered set of classes required by the v2 deletion contract.
pub const ALL_DELETION_CLOSURE_CLASSES_V2: [DeletionClosureClassV2; 13] = [
    DeletionClosureClassV2::PrimaryContent,
    DeletionClosureClassV2::Episode,
    DeletionClosureClassV2::Evidence,
    DeletionClosureClassV2::SemanticMemory,
    DeletionClosureClassV2::Summary,
    DeletionClosureClassV2::Embedding,
    DeletionClosureClassV2::AnnIndex,
    DeletionClosureClassV2::LexicalIndex,
    DeletionClosureClassV2::Cache,
    DeletionClosureClassV2::CheckpointOrHandoff,
    DeletionClosureClassV2::ProviderCopy,
    DeletionClosureClassV2::Export,
    DeletionClosureClassV2::Backup,
];

/// One exact class in an authoritative dependency-closure inventory.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ClassInventoryWireV2", into = "ClassInventoryWireV2")]
pub struct ClassInventoryV2 {
    class: DeletionClosureClassV2,
    targets: BTreeSet<DeletionTargetHandleV2>,
    absent_evidence: Option<EvidenceHandleV2>,
}

impl ClassInventoryV2 {
    /// Records an exact target set, or an independently proven absence.
    pub fn new(
        class: DeletionClosureClassV2,
        targets: BTreeSet<DeletionTargetHandleV2>,
        absent_evidence: Option<EvidenceHandleV2>,
    ) -> Result<Self> {
        let value = Self {
            class,
            targets,
            absent_evidence,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the authoritative target class.
    #[must_use]
    pub const fn class(&self) -> DeletionClosureClassV2 {
        self.class
    }

    /// Returns every opaque target in the class.
    #[must_use]
    pub fn targets(&self) -> &BTreeSet<DeletionTargetHandleV2> {
        &self.targets
    }

    /// Returns evidence proving an empty class inventory.
    #[must_use]
    pub fn absent_evidence(&self) -> Option<&EvidenceHandleV2> {
        self.absent_evidence.as_ref()
    }

    fn validate(&self) -> Result<()> {
        if self.targets.len() > MAX_DELETION_CLOSURE_TARGETS_V2 {
            return Err(SecureStoreError::InvalidInput(
                "deletion class exceeds the target bound".to_owned(),
            ));
        }
        if self.targets.is_empty() != self.absent_evidence.is_some() {
            return Err(SecureStoreError::DeletionIncomplete(
                "each closure class needs targets or exact absence evidence, exclusively"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ClassInventoryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassInventoryV2")
            .field("class", &self.class)
            .field("target_count", &self.targets.len())
            .field("has_absence_evidence", &self.absent_evidence.is_some())
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassInventoryWireV2 {
    class: DeletionClosureClassV2,
    targets: BTreeSet<DeletionTargetHandleV2>,
    absent_evidence: Option<EvidenceHandleV2>,
}

impl TryFrom<ClassInventoryWireV2> for ClassInventoryV2 {
    type Error = SecureStoreError;

    fn try_from(value: ClassInventoryWireV2) -> Result<Self> {
        Self::new(value.class, value.targets, value.absent_evidence)
    }
}

impl From<ClassInventoryV2> for ClassInventoryWireV2 {
    fn from(value: ClassInventoryV2) -> Self {
        Self {
            class: value.class,
            targets: value.targets,
            absent_evidence: value.absent_evidence,
        }
    }
}

/// Complete, canonical, authoritative 13-class dependency closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeletionClosureInventoryV2(Vec<ClassInventoryV2>);

impl DeletionClosureInventoryV2 {
    /// Builds a closure only when every class occurs exactly once and target
    /// handles are globally unique.
    pub fn try_new(mut classes: Vec<ClassInventoryV2>) -> Result<Self> {
        for class in &classes {
            class.validate()?;
        }
        classes.sort_by_key(ClassInventoryV2::class);
        let actual = classes
            .iter()
            .map(ClassInventoryV2::class)
            .collect::<Vec<_>>();
        if actual.as_slice() != ALL_DELETION_CLOSURE_CLASSES_V2 {
            return Err(SecureStoreError::DeletionIncomplete(
                "authoritative inventory must contain each of the 13 classes exactly once"
                    .to_owned(),
            ));
        }
        let mut targets = BTreeSet::new();
        for class in &classes {
            for target in &class.targets {
                if targets.len() == MAX_DELETION_CLOSURE_TARGETS_V2 {
                    return Err(SecureStoreError::InvalidInput(
                        "deletion closure exceeds the target bound".to_owned(),
                    ));
                }
                if !targets.insert(target.clone()) {
                    return Err(SecureStoreError::Integrity(
                        "closure target appears in more than one class".to_owned(),
                    ));
                }
            }
        }
        Ok(Self(classes))
    }

    /// Returns the canonical 13 class inventories.
    #[must_use]
    pub fn classes(&self) -> &[ClassInventoryV2] {
        &self.0
    }

    /// Returns the exact class of an inventoried opaque target.
    #[must_use]
    pub fn class_of(&self, target: &DeletionTargetHandleV2) -> Option<DeletionClosureClassV2> {
        self.0
            .iter()
            .find(|class| class.targets.contains(target))
            .map(ClassInventoryV2::class)
    }

    /// Returns the canonical closure commitment.
    pub fn root(&self) -> Result<StateRootV2> {
        StateRootV2::commit("deletion-closure-v2", &canonical_json(self)?)
    }

    /// Fails unless an independently supplied authoritative inventory is exact.
    pub fn require_exact(&self, authoritative: &Self) -> Result<()> {
        if self != authoritative {
            return Err(SecureStoreError::DeletionIncomplete(
                "deletion closure differs from authoritative inventory".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Disposition for locally controlled content or derived state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum LocalDeletionDispositionV2 {
    /// Recall is suppressed while physical work remains.
    Suppressed {
        /// Opaque evidence of the live suppression decision.
        evidence: EvidenceHandleV2,
    },
    /// Every authoritative local byte/index copy was physically purged.
    Purged {
        /// Opaque storage/media verification evidence.
        evidence: EvidenceHandleV2,
    },
    /// Complete copy inventory was encrypted under one destroyed DEK.
    CryptographicallyErased {
        /// Opaque destroyed key identity.
        key_handle: KeyHandleV2,
        /// Final monotonic key generation, normally `Destroyed` generation 3.
        key_generation: u64,
        /// Opaque key-authority destruction evidence.
        evidence: EvidenceHandleV2,
    },
    /// A derived object was rebuilt without the deleted lineage.
    Rebuilt {
        /// Opaque rebuild-verification evidence.
        evidence: EvidenceHandleV2,
    },
    /// The inventoried target was independently proven absent.
    ProvenAbsent {
        /// Opaque absence evidence.
        evidence: EvidenceHandleV2,
    },
}

impl LocalDeletionDispositionV2 {
    const fn rank(&self) -> u8 {
        match self {
            Self::Suppressed { .. } => 1,
            Self::Purged { .. }
            | Self::CryptographicallyErased { .. }
            | Self::Rebuilt { .. }
            | Self::ProvenAbsent { .. } => 2,
        }
    }

    const fn is_complete(&self) -> bool {
        self.rank() == 2
    }

    fn validate(&self) -> Result<()> {
        if let Self::CryptographicallyErased { key_generation, .. } = self
            && *key_generation < 3
        {
            return Err(SecureStoreError::DeletionIncomplete(
                "cryptographic erasure requires a destroyed key generation".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Disposition for provider, export, or backup copies outside local media.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ManagedCopyDispositionV2 {
    /// The copy is suppressed locally but no external deletion is acknowledged.
    SuppressionPending,
    /// An external or managed-store deletion request was durably accepted.
    DeletionRequested {
        /// Opaque request/audit handle.
        request: EvidenceHandleV2,
    },
    /// The responsible authority acknowledged deletion.
    Deleted {
        /// Opaque authority receipt handle.
        receipt: EvidenceHandleV2,
    },
    /// The responsible authority independently proved no copy was retained.
    ProvenAbsent {
        /// Opaque absence evidence.
        evidence: EvidenceHandleV2,
    },
    /// Copy existence is known but the system lacks verifiable control.
    OutsideControl {
        /// Opaque evidence documenting the unresolved boundary.
        evidence: EvidenceHandleV2,
    },
}

impl ManagedCopyDispositionV2 {
    const fn rank(&self) -> u8 {
        match self {
            Self::SuppressionPending => 0,
            Self::DeletionRequested { .. } | Self::OutsideControl { .. } => 1,
            Self::Deleted { .. } | Self::ProvenAbsent { .. } => 2,
        }
    }

    const fn is_complete(&self) -> bool {
        self.rank() == 2
    }
}

/// Class-correct target disposition recorded by a deletion workflow.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "control")]
pub enum DeletionTargetDispositionV2 {
    /// Disposition for a locally controlled class.
    Local(LocalDeletionDispositionV2),
    /// Disposition for provider/export/backup managed copies.
    Managed(ManagedCopyDispositionV2),
}

impl DeletionTargetDispositionV2 {
    fn rank(&self) -> u8 {
        match self {
            Self::Local(value) => value.rank(),
            Self::Managed(value) => value.rank(),
        }
    }

    fn is_complete(&self) -> bool {
        match self {
            Self::Local(value) => value.is_complete(),
            Self::Managed(value) => value.is_complete(),
        }
    }

    pub(crate) fn validate_for_class(&self, class: DeletionClosureClassV2) -> Result<()> {
        match (class.is_managed_copy(), self) {
            (false, Self::Local(value)) => value.validate(),
            (true, Self::Managed(_)) => Ok(()),
            _ => Err(SecureStoreError::Integrity(
                "deletion disposition does not match target control class".to_owned(),
            )),
        }
    }
}

/// Independently verifies closure-absence and target-completion evidence.
pub trait DeletionEvidenceVerifierV2 {
    /// Verifies one empty authoritative class against its owning subsystem.
    fn verify_absent_class(
        &self,
        namespace: &StateNamespaceV2,
        class: DeletionClosureClassV2,
        evidence: &EvidenceHandleV2,
    ) -> Result<()>;

    /// Verifies one target disposition against its owning storage or provider.
    fn verify_target(
        &self,
        namespace: &StateNamespaceV2,
        deletion: &DeletionHandleV2,
        target: &DeletionTargetHandleV2,
        class: DeletionClosureClassV2,
        disposition: &DeletionTargetDispositionV2,
    ) -> Result<()>;
}

/// External boundary proving that a suppression commitment is durably bound
/// into the expected composite state head and live overlay.
pub trait SuppressionCommitmentVerifierV2 {
    /// Verifies the exact namespace, workflow, closure, and suppression commitment.
    fn verify_suppression(
        &self,
        namespace: &StateNamespaceV2,
        deletion: &DeletionHandleV2,
        suppression_pending_workflow_root: &StateRootV2,
        closure_root: &StateRootV2,
        suppression_commitment: &StateRootV2,
    ) -> Result<()>;
}

/// Monotonic states of the durable hard-delete v2 workflow.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionWorkflowStateV2 {
    /// Exact closure is prepared but suppression publication has not started.
    Prepared,
    /// Composite-head publication is pending; all reads must fail closed.
    SuppressionPending,
    /// Live deletion overlay is durably bound into the composite head.
    Suppressed,
    /// Local physical purge, rebuild, or DEK destruction is in progress.
    Purging,
    /// Local work is complete and external/provider receipts are outstanding.
    AwaitingExternal,
    /// Exact closure and all target evidence were independently verified.
    Verified,
    /// An external signer must issue and verify the final receipt.
    ReceiptPending,
    /// Receipt is durably bound; no further workflow mutation is permitted.
    Complete,
}

impl DeletionWorkflowStateV2 {
    const fn next(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::SuppressionPending),
            Self::SuppressionPending => Some(Self::Suppressed),
            Self::Suppressed => Some(Self::Purging),
            Self::Purging => Some(Self::AwaitingExternal),
            Self::AwaitingExternal => Some(Self::Verified),
            Self::Verified => Some(Self::ReceiptPending),
            Self::ReceiptPending => Some(Self::Complete),
            Self::Complete => None,
        }
    }

    const fn minimum_revision(self) -> u64 {
        match self {
            Self::Prepared => 1,
            Self::SuppressionPending => 2,
            Self::Suppressed => 3,
            Self::Purging => 4,
            Self::AwaitingExternal => 5,
            Self::Verified => 6,
            Self::ReceiptPending => 7,
            Self::Complete => 8,
        }
    }
}

/// Durable monotonic hard-delete workflow; it performs no backend I/O itself.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct DeletionWorkflowV2 {
    format_version: u16,
    handle: DeletionHandleV2,
    namespace: StateNamespaceV2,
    state: DeletionWorkflowStateV2,
    revision: u64,
    requested_at_micros: u64,
    updated_at_micros: u64,
    inventory: DeletionClosureInventoryV2,
    dispositions: BTreeMap<DeletionTargetHandleV2, DeletionTargetDispositionV2>,
    suppression_pending_root: Option<StateRootV2>,
    suppression_pending_at_micros: Option<u64>,
    suppression_commitment: Option<StateRootV2>,
    verification_commitment: Option<StateRootV2>,
    receipt_pending_root: Option<StateRootV2>,
    receipt_pending_at_micros: Option<u64>,
    signed_receipt: Option<SignedDeletionReceiptV2>,
}

impl DeletionWorkflowV2 {
    /// Prepares a workflow from a complete authoritative 13-class inventory.
    pub fn prepare(
        namespace: StateNamespaceV2,
        inventory: DeletionClosureInventoryV2,
        requested_at_micros: u64,
    ) -> Result<Self> {
        let workflow = Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            handle: DeletionHandleV2::generate()?,
            namespace,
            state: DeletionWorkflowStateV2::Prepared,
            revision: 1,
            requested_at_micros,
            updated_at_micros: requested_at_micros,
            inventory,
            dispositions: BTreeMap::new(),
            suppression_pending_root: None,
            suppression_pending_at_micros: None,
            suppression_commitment: None,
            verification_commitment: None,
            receipt_pending_root: None,
            receipt_pending_at_micros: None,
            signed_receipt: None,
        };
        workflow.validate()?;
        Ok(workflow)
    }

    /// Returns the opaque workflow handle.
    #[must_use]
    pub fn handle(&self) -> &DeletionHandleV2 {
        &self.handle
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the current monotonic workflow state.
    #[must_use]
    pub const fn state(&self) -> DeletionWorkflowStateV2 {
        self.state
    }

    /// Returns the monotonic workflow revision used for optimistic concurrency.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the request time.
    #[must_use]
    pub const fn requested_at_micros(&self) -> u64 {
        self.requested_at_micros
    }

    /// Returns the last mutation time.
    #[must_use]
    pub const fn updated_at_micros(&self) -> u64 {
        self.updated_at_micros
    }

    /// Returns the immutable exact closure inventory.
    #[must_use]
    pub fn inventory(&self) -> &DeletionClosureInventoryV2 {
        &self.inventory
    }

    /// Returns recorded target dispositions.
    #[must_use]
    pub fn dispositions(&self) -> &BTreeMap<DeletionTargetHandleV2, DeletionTargetDispositionV2> {
        &self.dispositions
    }

    /// Returns the exact independent-verification commitment, if reached.
    #[must_use]
    pub fn verification_commitment(&self) -> Option<&StateRootV2> {
        self.verification_commitment.as_ref()
    }

    /// Returns the embedded externally signed receipt once complete.
    #[must_use]
    pub fn signed_receipt(&self) -> Option<&SignedDeletionReceiptV2> {
        self.signed_receipt.as_ref()
    }

    /// Returns the canonical content-free workflow commitment.
    pub fn root(&self) -> Result<StateRootV2> {
        self.binding_root_for(self.state, self.revision, self.updated_at_micros)
    }

    /// Recovers a workflow only from a bounded buffer and revalidates every
    /// external trust boundary required by its persisted state.
    pub fn from_json_bounded(
        bytes: &[u8],
        suppression_verifier: &dyn SuppressionCommitmentVerifierV2,
        evidence_verifier: &dyn DeletionEvidenceVerifierV2,
        receipt_verifier: &dyn DeletionReceiptVerifierV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_DELETION_WORKFLOW_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "deletion workflow exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: DeletionWorkflowWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        let workflow = Self::try_from(wire)?;
        workflow.validate_external(suppression_verifier, evidence_verifier, receipt_verifier)?;
        Ok(workflow)
    }

    /// Advances `Prepared` to `SuppressionPending`.
    pub fn begin_suppression(&mut self, expected_revision: u64, at_micros: u64) -> Result<()> {
        self.require_transition(
            expected_revision,
            DeletionWorkflowStateV2::SuppressionPending,
        )?;
        self.require_revision_and_time(expected_revision, at_micros)?;
        let mut candidate = self.clone();
        candidate.state = DeletionWorkflowStateV2::SuppressionPending;
        candidate.bump_revision(at_micros)?;
        candidate.suppression_pending_at_micros = Some(at_micros);
        candidate.suppression_pending_root =
            Some(candidate.computed_suppression_pending_root(at_micros)?);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records a durably MAC-bound live overlay and advances to `Suppressed`.
    pub fn confirm_suppressed(
        &mut self,
        expected_revision: u64,
        at_micros: u64,
        suppression_commitment: StateRootV2,
        verifier: &dyn SuppressionCommitmentVerifierV2,
    ) -> Result<()> {
        self.require_transition(expected_revision, DeletionWorkflowStateV2::Suppressed)?;
        self.require_revision_and_time(expected_revision, at_micros)?;
        verifier.verify_suppression(
            &self.namespace,
            &self.handle,
            self.suppression_pending_root.as_ref().ok_or_else(|| {
                SecureStoreError::Integrity("suppression workflow root is unavailable".to_owned())
            })?,
            &self.inventory.root()?,
            &suppression_commitment,
        )?;
        let mut candidate = self.clone();
        candidate.suppression_commitment = Some(suppression_commitment);
        candidate.finish_transition(at_micros, DeletionWorkflowStateV2::Suppressed)?;
        *self = candidate;
        Ok(())
    }

    /// Advances `Suppressed` to `Purging`.
    pub fn begin_purging(&mut self, expected_revision: u64, at_micros: u64) -> Result<()> {
        self.advance(
            expected_revision,
            at_micros,
            DeletionWorkflowStateV2::Purging,
        )
    }

    /// Records monotonic class-correct work for one exact inventoried target.
    pub fn record_disposition(
        &mut self,
        expected_revision: u64,
        at_micros: u64,
        target: DeletionTargetHandleV2,
        disposition: DeletionTargetDispositionV2,
    ) -> Result<()> {
        self.require_revision_and_time(expected_revision, at_micros)?;
        if !matches!(
            self.state,
            DeletionWorkflowStateV2::Purging | DeletionWorkflowStateV2::AwaitingExternal
        ) {
            return Err(SecureStoreError::StateConflict(
                "target dispositions can change only while purging or awaiting external work"
                    .to_owned(),
            ));
        }
        let class = self.inventory.class_of(&target).ok_or_else(|| {
            SecureStoreError::DeletionIncomplete(
                "target is outside the authoritative closure".to_owned(),
            )
        })?;
        disposition.validate_for_class(class)?;
        if let Some(previous) = self.dispositions.get(&target) {
            if previous == &disposition {
                return Ok(());
            }
            let records_terminal_outside_control = matches!(
                (previous, &disposition),
                (
                    DeletionTargetDispositionV2::Managed(
                        ManagedCopyDispositionV2::DeletionRequested { .. }
                    ),
                    DeletionTargetDispositionV2::Managed(
                        ManagedCopyDispositionV2::OutsideControl { .. }
                    )
                )
            );
            if std::mem::discriminant(previous) != std::mem::discriminant(&disposition)
                || previous.is_complete()
                || (disposition.rank() <= previous.rank() && !records_terminal_outside_control)
            {
                return Err(SecureStoreError::StateConflict(
                    "target disposition regressed or rewrote terminal evidence".to_owned(),
                ));
            }
        }
        let mut candidate = self.clone();
        candidate.dispositions.insert(target, disposition);
        candidate.bump_revision(at_micros)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Advances to `AwaitingExternal` after every local target is complete and
    /// every managed target has at least a durable external disposition.
    pub fn await_external(&mut self, expected_revision: u64, at_micros: u64) -> Result<()> {
        self.require_transition(expected_revision, DeletionWorkflowStateV2::AwaitingExternal)?;
        for class in self.inventory.classes() {
            for target in class.targets() {
                let disposition = self.dispositions.get(target).ok_or_else(|| {
                    SecureStoreError::DeletionIncomplete(
                        "inventoried target has no disposition".to_owned(),
                    )
                })?;
                if !class.class().is_managed_copy() && !disposition.is_complete() {
                    return Err(SecureStoreError::DeletionIncomplete(
                        "local target remains incomplete".to_owned(),
                    ));
                }
                if class.class().is_managed_copy() && disposition.rank() == 0 {
                    return Err(SecureStoreError::DeletionIncomplete(
                        "managed copy lacks a durable external disposition".to_owned(),
                    ));
                }
            }
        }
        self.finish_transition(at_micros, DeletionWorkflowStateV2::AwaitingExternal)
    }

    /// Verifies exact closure equality and every completion/absence proof, then
    /// advances to `Verified`.
    pub fn verify_closure(
        &mut self,
        expected_revision: u64,
        at_micros: u64,
        authoritative: &DeletionClosureInventoryV2,
        verifier: &dyn DeletionEvidenceVerifierV2,
    ) -> Result<()> {
        self.require_transition(expected_revision, DeletionWorkflowStateV2::Verified)?;
        self.require_revision_and_time(expected_revision, at_micros)?;
        self.inventory.require_exact(authoritative)?;
        self.verify_all_evidence(verifier)?;
        let mut candidate = self.clone();
        candidate.verification_commitment = Some(candidate.computed_verification_commitment()?);
        candidate.finish_transition(at_micros, DeletionWorkflowStateV2::Verified)?;
        *self = candidate;
        Ok(())
    }

    /// Advances `Verified` to `ReceiptPending`.
    pub fn begin_receipt(&mut self, expected_revision: u64, at_micros: u64) -> Result<()> {
        self.require_transition(expected_revision, DeletionWorkflowStateV2::ReceiptPending)?;
        self.require_revision_and_time(expected_revision, at_micros)?;
        let mut candidate = self.clone();
        candidate.state = DeletionWorkflowStateV2::ReceiptPending;
        candidate.bump_revision(at_micros)?;
        candidate.receipt_pending_at_micros = Some(at_micros);
        candidate.receipt_pending_root = Some(candidate.root()?);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub(crate) fn complete_with_receipt(
        &mut self,
        expected_revision: u64,
        at_micros: u64,
        signed_receipt: SignedDeletionReceiptV2,
    ) -> Result<()> {
        self.require_transition(expected_revision, DeletionWorkflowStateV2::Complete)?;
        self.require_revision_and_time(expected_revision, at_micros)?;
        let mut candidate = self.clone();
        candidate.signed_receipt = Some(signed_receipt);
        candidate.finish_transition(at_micros, DeletionWorkflowStateV2::Complete)?;
        *self = candidate;
        Ok(())
    }

    fn advance(
        &mut self,
        expected_revision: u64,
        at_micros: u64,
        next: DeletionWorkflowStateV2,
    ) -> Result<()> {
        self.require_transition(expected_revision, next)?;
        self.finish_transition(at_micros, next)
    }

    fn require_transition(
        &self,
        expected_revision: u64,
        next: DeletionWorkflowStateV2,
    ) -> Result<()> {
        if self.state.next() != Some(next) {
            return Err(SecureStoreError::StateConflict(
                "deletion workflow transition is non-monotonic".to_owned(),
            ));
        }
        if self.revision != expected_revision {
            return Err(SecureStoreError::StateConflict(
                "deletion workflow revision is stale".to_owned(),
            ));
        }
        Ok(())
    }

    fn finish_transition(&mut self, at_micros: u64, next: DeletionWorkflowStateV2) -> Result<()> {
        if at_micros < self.updated_at_micros {
            return Err(SecureStoreError::StateConflict(
                "deletion workflow time regressed".to_owned(),
            ));
        }
        let mut candidate = self.clone();
        candidate.state = next;
        candidate.bump_revision(at_micros)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn require_revision_and_time(&self, expected_revision: u64, at_micros: u64) -> Result<()> {
        if self.revision != expected_revision || at_micros < self.updated_at_micros {
            return Err(SecureStoreError::StateConflict(
                "deletion workflow revision or time is stale".to_owned(),
            ));
        }
        Ok(())
    }

    fn bump_revision(&mut self, at_micros: u64) -> Result<()> {
        self.revision = self.revision.checked_add(1).ok_or_else(|| {
            SecureStoreError::StateConflict("deletion workflow revision exhausted".to_owned())
        })?;
        self.updated_at_micros = at_micros;
        Ok(())
    }

    fn binding_root_for(
        &self,
        state: DeletionWorkflowStateV2,
        revision: u64,
        updated_at_micros: u64,
    ) -> Result<StateRootV2> {
        #[derive(Serialize)]
        struct WorkflowBinding<'a> {
            format_version: u16,
            handle: &'a DeletionHandleV2,
            namespace: &'a StateNamespaceV2,
            state: DeletionWorkflowStateV2,
            revision: u64,
            requested_at_micros: u64,
            updated_at_micros: u64,
            inventory: &'a DeletionClosureInventoryV2,
            dispositions: &'a BTreeMap<DeletionTargetHandleV2, DeletionTargetDispositionV2>,
            suppression_commitment: &'a Option<StateRootV2>,
            verification_commitment: &'a Option<StateRootV2>,
            signed_receipt_commitment: Option<StateRootV2>,
        }
        let signed_receipt_commitment = if state == DeletionWorkflowStateV2::Complete {
            Some(
                self.signed_receipt
                    .as_ref()
                    .ok_or_else(|| {
                        SecureStoreError::Integrity(
                            "complete workflow lacks a signed receipt".to_owned(),
                        )
                    })?
                    .commitment()?,
            )
        } else {
            None
        };
        StateRootV2::commit(
            "deletion-workflow-v2",
            &canonical_json(&WorkflowBinding {
                format_version: self.format_version,
                handle: &self.handle,
                namespace: &self.namespace,
                state,
                revision,
                requested_at_micros: self.requested_at_micros,
                updated_at_micros,
                inventory: &self.inventory,
                dispositions: &self.dispositions,
                suppression_commitment: &self.suppression_commitment,
                verification_commitment: &self.verification_commitment,
                signed_receipt_commitment,
            })?,
        )
    }

    fn computed_verification_commitment(&self) -> Result<StateRootV2> {
        #[derive(Serialize)]
        struct VerifiedClosure<'a> {
            deletion: &'a DeletionHandleV2,
            namespace: &'a StateNamespaceV2,
            inventory: &'a DeletionClosureInventoryV2,
            dispositions: &'a BTreeMap<DeletionTargetHandleV2, DeletionTargetDispositionV2>,
        }
        StateRootV2::commit(
            "verified-deletion-closure-v2",
            &canonical_json(&VerifiedClosure {
                deletion: &self.handle,
                namespace: &self.namespace,
                inventory: &self.inventory,
                dispositions: &self.dispositions,
            })?,
        )
    }

    fn computed_suppression_pending_root(&self, at_micros: u64) -> Result<StateRootV2> {
        #[derive(Serialize)]
        struct SuppressionPendingBinding<'a> {
            format_version: u16,
            deletion: &'a DeletionHandleV2,
            namespace: &'a StateNamespaceV2,
            state: DeletionWorkflowStateV2,
            revision: u64,
            requested_at_micros: u64,
            updated_at_micros: u64,
            closure_root: StateRootV2,
        }
        StateRootV2::commit(
            "suppression-pending-workflow-v2",
            &canonical_json(&SuppressionPendingBinding {
                format_version: self.format_version,
                deletion: &self.handle,
                namespace: &self.namespace,
                state: DeletionWorkflowStateV2::SuppressionPending,
                revision: 2,
                requested_at_micros: self.requested_at_micros,
                updated_at_micros: at_micros,
                closure_root: self.inventory.root()?,
            })?,
        )
    }

    fn verify_all_evidence(&self, verifier: &dyn DeletionEvidenceVerifierV2) -> Result<()> {
        for class in self.inventory.classes() {
            if let Some(evidence) = class.absent_evidence() {
                verifier.verify_absent_class(&self.namespace, class.class(), evidence)?;
            }
            for target in class.targets() {
                let disposition = self.dispositions.get(target).ok_or_else(|| {
                    SecureStoreError::DeletionIncomplete(
                        "inventoried target has no disposition".to_owned(),
                    )
                })?;
                if !disposition.is_complete() {
                    return Err(SecureStoreError::DeletionIncomplete(
                        "inventoried target is not complete".to_owned(),
                    ));
                }
                verifier.verify_target(
                    &self.namespace,
                    &self.handle,
                    target,
                    class.class(),
                    disposition,
                )?;
            }
        }
        Ok(())
    }

    fn validate_awaiting_conditions(&self) -> Result<()> {
        for class in self.inventory.classes() {
            for target in class.targets() {
                let disposition = self.dispositions.get(target).ok_or_else(|| {
                    SecureStoreError::DeletionIncomplete(
                        "inventoried target has no disposition".to_owned(),
                    )
                })?;
                if !class.class().is_managed_copy() && !disposition.is_complete() {
                    return Err(SecureStoreError::DeletionIncomplete(
                        "local target remains incomplete".to_owned(),
                    ));
                }
                if class.class().is_managed_copy() && disposition.rank() == 0 {
                    return Err(SecureStoreError::DeletionIncomplete(
                        "managed copy lacks a durable external disposition".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_external(
        &self,
        suppression_verifier: &dyn SuppressionCommitmentVerifierV2,
        evidence_verifier: &dyn DeletionEvidenceVerifierV2,
        receipt_verifier: &dyn DeletionReceiptVerifierV2,
    ) -> Result<()> {
        if self.state >= DeletionWorkflowStateV2::Suppressed {
            suppression_verifier.verify_suppression(
                &self.namespace,
                &self.handle,
                self.suppression_pending_root.as_ref().ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "suppression workflow root is unavailable".to_owned(),
                    )
                })?,
                &self.inventory.root()?,
                self.suppression_commitment.as_ref().ok_or_else(|| {
                    SecureStoreError::Integrity("suppressed workflow lacks a commitment".to_owned())
                })?,
            )?;
        }
        if self.state >= DeletionWorkflowStateV2::Verified {
            self.verify_all_evidence(evidence_verifier)?;
        }
        if let Some(receipt) = &self.signed_receipt {
            receipt.verify(&self.namespace, receipt_verifier)?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.format_version != SECURE_STORE_FORMAT_VERSION
            || self.revision < self.state.minimum_revision()
            || self.updated_at_micros < self.requested_at_micros
        {
            return Err(SecureStoreError::Integrity(
                "deletion workflow version, revision, or time is invalid".to_owned(),
            ));
        }
        let exact_early_revision = match self.state {
            DeletionWorkflowStateV2::Prepared => Some(1),
            DeletionWorkflowStateV2::SuppressionPending => Some(2),
            DeletionWorkflowStateV2::Suppressed => Some(3),
            _ => None,
        };
        if exact_early_revision.is_some_and(|expected| self.revision != expected) {
            return Err(SecureStoreError::Integrity(
                "early deletion workflow revision is not exact".to_owned(),
            ));
        }
        DeletionClosureInventoryV2::try_new(self.inventory.classes().to_vec())?;
        for (target, disposition) in &self.dispositions {
            let class = self.inventory.class_of(target).ok_or_else(|| {
                SecureStoreError::Integrity(
                    "workflow disposition is outside its inventory".to_owned(),
                )
            })?;
            disposition.validate_for_class(class)?;
        }
        let inventoried_count = self
            .inventory
            .classes()
            .iter()
            .map(|class| class.targets().len())
            .sum::<usize>();
        if self.dispositions.len() > inventoried_count
            || inventoried_count > MAX_DELETION_CLOSURE_TARGETS_V2
        {
            return Err(SecureStoreError::Integrity(
                "workflow disposition cardinality is invalid".to_owned(),
            ));
        }
        if self.state < DeletionWorkflowStateV2::Purging && !self.dispositions.is_empty() {
            return Err(SecureStoreError::Integrity(
                "workflow has target work before purging".to_owned(),
            ));
        }
        if self.state >= DeletionWorkflowStateV2::AwaitingExternal {
            self.validate_awaiting_conditions()?;
        }
        let suppression_required = self.state >= DeletionWorkflowStateV2::Suppressed;
        let suppression_started = self.state >= DeletionWorkflowStateV2::SuppressionPending;
        if suppression_started != self.suppression_pending_root.is_some()
            || suppression_started != self.suppression_pending_at_micros.is_some()
        {
            return Err(SecureStoreError::Integrity(
                "workflow suppression-pending root disagrees with state".to_owned(),
            ));
        }
        if suppression_started {
            let pending_at = self.suppression_pending_at_micros.ok_or_else(|| {
                SecureStoreError::Integrity("workflow lacks suppression-pending time".to_owned())
            })?;
            if pending_at < self.requested_at_micros || pending_at > self.updated_at_micros {
                return Err(SecureStoreError::Integrity(
                    "workflow suppression-pending time is invalid".to_owned(),
                ));
            }
            let expected = self.computed_suppression_pending_root(pending_at)?;
            if self.suppression_pending_root.as_ref() != Some(&expected) {
                return Err(SecureStoreError::Integrity(
                    "workflow suppression-pending root is not exact".to_owned(),
                ));
            }
        }
        if suppression_required != self.suppression_commitment.is_some() {
            return Err(SecureStoreError::Integrity(
                "workflow suppression commitment disagrees with state".to_owned(),
            ));
        }
        let verification_required = self.state >= DeletionWorkflowStateV2::Verified;
        if verification_required != self.verification_commitment.is_some() {
            return Err(SecureStoreError::Integrity(
                "workflow verification commitment disagrees with state".to_owned(),
            ));
        }
        if let Some(commitment) = &self.verification_commitment
            && commitment != &self.computed_verification_commitment()?
        {
            return Err(SecureStoreError::Integrity(
                "workflow verification commitment is not exact".to_owned(),
            ));
        }
        let receipt_stage = self.state >= DeletionWorkflowStateV2::ReceiptPending;
        if receipt_stage != self.receipt_pending_root.is_some()
            || receipt_stage != self.receipt_pending_at_micros.is_some()
            || (self.state == DeletionWorkflowStateV2::Complete) != self.signed_receipt.is_some()
        {
            return Err(SecureStoreError::Integrity(
                "workflow receipt fields disagree with state".to_owned(),
            ));
        }
        if receipt_stage {
            let pending_at = self.receipt_pending_at_micros.ok_or_else(|| {
                SecureStoreError::Integrity("workflow lacks receipt-pending time".to_owned())
            })?;
            let pending_revision = if self.state == DeletionWorkflowStateV2::Complete {
                self.revision.checked_sub(1).ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "complete workflow revision cannot reconstruct pending state".to_owned(),
                    )
                })?
            } else {
                self.revision
            };
            let expected_pending_root = self.binding_root_for(
                DeletionWorkflowStateV2::ReceiptPending,
                pending_revision,
                pending_at,
            )?;
            if self.receipt_pending_root.as_ref() != Some(&expected_pending_root) {
                return Err(SecureStoreError::Integrity(
                    "receipt-pending workflow root is not exact".to_owned(),
                ));
            }
        }
        if self.state >= DeletionWorkflowStateV2::Verified {
            if self.dispositions.values().any(|value| !value.is_complete()) {
                return Err(SecureStoreError::DeletionIncomplete(
                    "verified workflow contains an incomplete target".to_owned(),
                ));
            }
            if inventoried_count != self.dispositions.len() {
                return Err(SecureStoreError::DeletionIncomplete(
                    "verified workflow does not cover every target".to_owned(),
                ));
            }
        }
        if let Some(receipt) = &self.signed_receipt {
            let unsigned = receipt.unsigned();
            if unsigned.deletion() != &self.handle
                || unsigned.namespace() != &self.namespace
                || Some(unsigned.workflow_root()) != self.receipt_pending_root.as_ref()
                || unsigned.closure_inventory_root() != &self.inventory.root()?
                || Some(unsigned.verification_commitment()) != self.verification_commitment.as_ref()
                || unsigned.requested_at_micros() != self.requested_at_micros
                || unsigned.completed_at_micros() != self.updated_at_micros
            {
                return Err(SecureStoreError::Integrity(
                    "signed receipt does not bind the recovered complete workflow".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DeletionWorkflowV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeletionWorkflowV2")
            .field("handle", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("state", &self.state)
            .field("revision", &self.revision)
            .field("requested_at_micros", &self.requested_at_micros)
            .field("updated_at_micros", &self.updated_at_micros)
            .field("target_count", &self.dispositions.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionWorkflowWireV2 {
    format_version: u16,
    handle: DeletionHandleV2,
    namespace: StateNamespaceV2,
    state: DeletionWorkflowStateV2,
    revision: u64,
    requested_at_micros: u64,
    updated_at_micros: u64,
    inventory: Vec<ClassInventoryV2>,
    dispositions: BTreeMap<DeletionTargetHandleV2, DeletionTargetDispositionV2>,
    suppression_pending_root: Option<StateRootV2>,
    suppression_pending_at_micros: Option<u64>,
    suppression_commitment: Option<StateRootV2>,
    verification_commitment: Option<StateRootV2>,
    receipt_pending_root: Option<StateRootV2>,
    receipt_pending_at_micros: Option<u64>,
    signed_receipt: Option<crate::receipt::SignedDeletionReceiptWireV2>,
}

impl TryFrom<DeletionWorkflowWireV2> for DeletionWorkflowV2 {
    type Error = SecureStoreError;

    fn try_from(value: DeletionWorkflowWireV2) -> Result<Self> {
        let workflow = Self {
            format_version: value.format_version,
            handle: value.handle,
            namespace: value.namespace,
            state: value.state,
            revision: value.revision,
            requested_at_micros: value.requested_at_micros,
            updated_at_micros: value.updated_at_micros,
            inventory: DeletionClosureInventoryV2::try_new(value.inventory)?,
            dispositions: value.dispositions,
            suppression_pending_root: value.suppression_pending_root,
            suppression_pending_at_micros: value.suppression_pending_at_micros,
            suppression_commitment: value.suppression_commitment,
            verification_commitment: value.verification_commitment,
            receipt_pending_root: value.receipt_pending_root,
            receipt_pending_at_micros: value.receipt_pending_at_micros,
            signed_receipt: value.signed_receipt.map(TryInto::try_into).transpose()?,
        };
        workflow.validate()?;
        Ok(workflow)
    }
}

impl From<DeletionWorkflowV2> for DeletionWorkflowWireV2 {
    fn from(value: DeletionWorkflowV2) -> Self {
        Self {
            format_version: value.format_version,
            handle: value.handle,
            namespace: value.namespace,
            state: value.state,
            revision: value.revision,
            requested_at_micros: value.requested_at_micros,
            updated_at_micros: value.updated_at_micros,
            inventory: value.inventory.0,
            dispositions: value.dispositions,
            suppression_pending_root: value.suppression_pending_root,
            suppression_pending_at_micros: value.suppression_pending_at_micros,
            suppression_commitment: value.suppression_commitment,
            verification_commitment: value.verification_commitment,
            receipt_pending_root: value.receipt_pending_root,
            receipt_pending_at_micros: value.receipt_pending_at_micros,
            signed_receipt: value.signed_receipt.map(Into::into),
        }
    }
}
