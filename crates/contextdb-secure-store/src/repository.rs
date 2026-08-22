use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AuthorityEvidenceKindV2, AuthorityEvidenceVerifierV2, AuthorityProvenanceV2,
    AuthorityProvenanceVerifierV2, AuthorityRoleV2, CompositeStateHeadV2, HeadMacAuthorityV2,
    OperationRequestIdV2, Result, SecureStoreError, StateNamespaceV2, StateRootV2,
    VerifiedAuthorityEvidenceV2, intent_commitment, require_role,
};

/// Maximum signed successor receipts accepted in one lineage proof.
pub const MAX_COMPOSITE_HEAD_LINEAGE_RECEIPTS_V2: usize = 4_096;
/// Maximum JSON bytes accepted when recovering one persisted repository CAS intent.
pub const MAX_COMPOSITE_HEAD_CAS_REQUEST_JSON_BYTES_V2: usize = 256 * 1024;

/// Exact sequence-and-commitment anti-rollback anchor for a composite head.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct HeadAnchorV2 {
    namespace: StateNamespaceV2,
    sequence: u64,
    head_commitment: StateRootV2,
}

impl HeadAnchorV2 {
    /// Derives an exact anchor from an authenticated composite head.
    pub fn from_head(head: &CompositeStateHeadV2) -> Result<Self> {
        Ok(Self {
            namespace: head.namespace().clone(),
            sequence: head.sequence(),
            head_commitment: head.commitment()?,
        })
    }

    /// Returns the bound namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the monotonic anchored sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact complete-head commitment.
    #[must_use]
    pub fn head_commitment(&self) -> &StateRootV2 {
        &self.head_commitment
    }

    pub(crate) fn from_recovery_wire(
        wire: HeadAnchorRecoveryWireV2,
        expected_namespace: &StateNamespaceV2,
    ) -> Result<Self> {
        if &wire.namespace != expected_namespace || wire.sequence == 0 {
            return Err(SecureStoreError::Integrity(
                "persisted head anchor namespace or sequence is invalid".to_owned(),
            ));
        }
        Ok(Self {
            namespace: wire.namespace,
            sequence: wire.sequence,
            head_commitment: wire.head_commitment,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeadAnchorRecoveryWireV2 {
    namespace: StateNamespaceV2,
    sequence: u64,
    head_commitment: StateRootV2,
}

impl fmt::Debug for HeadAnchorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeadAnchorV2")
            .field("namespace", &self.namespace)
            .field("sequence", &self.sequence)
            .field("head_commitment", &"[COMMITMENT]")
            .finish()
    }
}

/// Authority-signed durable receipt for one exact repository anchor.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct HeadAnchorReceiptV2 {
    anchor: HeadAnchorV2,
    previous_anchor: Option<HeadAnchorV2>,
    provenance: AuthorityProvenanceV2,
    authority_evidence: VerifiedAuthorityEvidenceV2,
}

impl HeadAnchorReceiptV2 {
    /// Binds already verified repository evidence to one exact head anchor.
    pub fn from_verified(
        anchor: HeadAnchorV2,
        previous_anchor: Option<HeadAnchorV2>,
        provenance: AuthorityProvenanceV2,
        authority_evidence: VerifiedAuthorityEvidenceV2,
    ) -> Result<Self> {
        require_role(&provenance, AuthorityRoleV2::CompositeHeadRepository)?;
        validate_anchor_link(previous_anchor.as_ref(), &anchor)?;
        let subject = head_anchor_subject(previous_anchor.as_ref(), &anchor)?;
        if authority_evidence.kind() != AuthorityEvidenceKindV2::CompositeHeadAnchored
            || authority_evidence.provenance() != &provenance
            || authority_evidence.namespace() != anchor.namespace()
            || authority_evidence.subject_commitment() != &subject
        {
            return Err(SecureStoreError::Integrity(
                "repository receipt does not bind the exact head anchor".to_owned(),
            ));
        }
        Ok(Self {
            anchor,
            previous_anchor,
            provenance,
            authority_evidence,
        })
    }

    /// Returns the exact durable anchor.
    #[must_use]
    pub fn anchor(&self) -> &HeadAnchorV2 {
        &self.anchor
    }

    /// Returns the immediately preceding durable anchor, or `None` for sequence one.
    #[must_use]
    pub fn previous_anchor(&self) -> Option<&HeadAnchorV2> {
        self.previous_anchor.as_ref()
    }

    /// Returns repository deployment provenance.
    #[must_use]
    pub fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }

    /// Returns externally verified signed anchor evidence.
    #[must_use]
    pub fn authority_evidence(&self) -> &VerifiedAuthorityEvidenceV2 {
        &self.authority_evidence
    }

    /// Rechecks signature and current repository trust/revocation state.
    pub fn verify_current(
        &self,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityEvidenceVerifierV2,
    ) -> Result<()> {
        self.authority_evidence.verify_exact(
            AuthorityEvidenceKindV2::CompositeHeadAnchored,
            &self.provenance,
            self.anchor.namespace(),
            self.authority_evidence.request_id(),
            &head_anchor_subject(self.previous_anchor.as_ref(), &self.anchor)?,
            evaluated_at_micros,
            verifier,
        )
    }
}

impl fmt::Debug for HeadAnchorReceiptV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeadAnchorReceiptV2")
            .field("anchor", &self.anchor)
            .field("previous_anchor", &self.previous_anchor)
            .field("provenance", &self.provenance)
            .field("authority_evidence", &self.authority_evidence)
            .finish()
    }
}

/// Composite head plus the repository's signed durable anchor receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnchoredCompositeHeadV2 {
    head: CompositeStateHeadV2,
    receipt: HeadAnchorReceiptV2,
}

/// Bounded chain of signed repository receipts proving every successor step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompositeHeadLineageProofV2 {
    receipts: Vec<HeadAnchorReceiptV2>,
}

impl CompositeHeadLineageProofV2 {
    /// Validates every intermediate signed anchor from `expected` to `observed`.
    pub fn try_new(
        expected: &HeadAnchorV2,
        observed: &AnchoredCompositeHeadV2,
        receipts: Vec<HeadAnchorReceiptV2>,
    ) -> Result<Self> {
        if receipts.is_empty() || receipts.len() > MAX_COMPOSITE_HEAD_LINEAGE_RECEIPTS_V2 {
            return Err(SecureStoreError::InvalidInput(
                "composite-head lineage proof count is invalid".to_owned(),
            ));
        }
        let expected_count = observed
            .anchor()
            .sequence()
            .checked_sub(expected.sequence())
            .ok_or_else(|| {
                SecureStoreError::StateConflict(
                    "lineage observation predates expected anchor".to_owned(),
                )
            })?;
        if usize::try_from(expected_count).ok() != Some(receipts.len()) {
            return Err(SecureStoreError::Integrity(
                "lineage proof omits or duplicates an intermediate anchor".to_owned(),
            ));
        }
        let mut cursor = expected.clone();
        let mut request_ids = BTreeSet::new();
        for receipt in &receipts {
            if receipt.previous_anchor() != Some(&cursor)
                || receipt.anchor().namespace() != expected.namespace()
                || receipt.provenance() != observed.receipt().provenance()
            {
                return Err(SecureStoreError::Integrity(
                    "lineage proof contains a fork, namespace replay, or authority change"
                        .to_owned(),
                ));
            }
            if !request_ids.insert(receipt.authority_evidence().request_id()) {
                return Err(SecureStoreError::Integrity(
                    "lineage proof reuses one idempotency request identity".to_owned(),
                ));
            }
            validate_anchor_link(Some(&cursor), receipt.anchor())?;
            cursor = receipt.anchor().clone();
        }
        if &cursor != observed.anchor() || receipts.last() != Some(observed.receipt()) {
            return Err(SecureStoreError::Integrity(
                "lineage proof does not terminate at the observed head".to_owned(),
            ));
        }
        Ok(Self { receipts })
    }

    /// Returns the exact ordered signed successor receipts.
    #[must_use]
    pub fn receipts(&self) -> &[HeadAnchorReceiptV2] {
        &self.receipts
    }

    /// Rechecks every receipt signature and current repository trust decision.
    pub fn verify_current(
        &self,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityEvidenceVerifierV2,
    ) -> Result<()> {
        for receipt in &self.receipts {
            receipt.verify_current(evaluated_at_micros, verifier)?;
        }
        Ok(())
    }
}

impl AnchoredCompositeHeadV2 {
    /// Validates that the head and durable receipt are exact matches.
    pub fn try_new(head: CompositeStateHeadV2, receipt: HeadAnchorReceiptV2) -> Result<Self> {
        if HeadAnchorV2::from_head(&head)? != *receipt.anchor() {
            return Err(SecureStoreError::Integrity(
                "anchored head does not match its durable receipt".to_owned(),
            ));
        }
        Ok(Self { head, receipt })
    }

    /// Returns the authenticated composite head.
    #[must_use]
    pub fn head(&self) -> &CompositeStateHeadV2 {
        &self.head
    }

    /// Returns the authority-signed durable anchor receipt.
    #[must_use]
    pub fn receipt(&self) -> &HeadAnchorReceiptV2 {
        &self.receipt
    }

    /// Returns the exact sequence-and-commitment anchor.
    #[must_use]
    pub fn anchor(&self) -> &HeadAnchorV2 {
        self.receipt.anchor()
    }
}

/// Rollback-aware load request carrying the caller's last durable anchor.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct CompositeHeadLoadRequestV2 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    expected_anchor: Option<HeadAnchorV2>,
}

impl CompositeHeadLoadRequestV2 {
    /// Creates a load request and rejects a cross-namespace expectation.
    pub fn new(
        request_id: OperationRequestIdV2,
        namespace: StateNamespaceV2,
        expected_anchor: Option<HeadAnchorV2>,
    ) -> Result<Self> {
        if expected_anchor
            .as_ref()
            .is_some_and(|anchor| anchor.namespace() != &namespace)
        {
            return Err(SecureStoreError::Integrity(
                "load expectation namespace does not match destination".to_owned(),
            ));
        }
        Ok(Self {
            request_id,
            namespace,
            expected_anchor,
        })
    }

    /// Returns the request identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the destination namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the caller's last durable anchor, if one exists.
    #[must_use]
    pub fn expected_anchor(&self) -> Option<&HeadAnchorV2> {
        self.expected_anchor.as_ref()
    }
}

impl fmt::Debug for CompositeHeadLoadRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompositeHeadLoadRequestV2")
            .field("request_id", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("expected_anchor", &self.expected_anchor)
            .finish()
    }
}

/// Result of rollback-aware composite-head loading.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "value")]
pub enum CompositeHeadLoadOutcomeV2 {
    /// No head exists and the caller had no prior anchor.
    Empty,
    /// Repository state exactly matches the caller's anchor or no anchor was supplied.
    Exact(AnchoredCompositeHeadV2),
    /// Repository state is a valid monotonic successor of the caller's older anchor.
    Ahead {
        /// Current anchored head.
        current: AnchoredCompositeHeadV2,
        /// Exact signed proof of every successor after the caller's anchor.
        lineage: CompositeHeadLineageProofV2,
    },
    /// A higher sequence was returned without a complete authenticated lineage.
    MissingLineage {
        /// Caller-anchored sequence.
        expected_sequence: u64,
        /// Unproven higher sequence.
        observed_sequence: u64,
    },
    /// Repository state is older than the caller's durable anchor.
    Rollback {
        /// Minimum sequence required by the caller.
        expected_sequence: u64,
        /// Older sequence returned by the repository, or zero for a missing head.
        observed_sequence: u64,
    },
    /// The same sequence has a different complete-head commitment.
    Divergence {
        /// Sequence at which histories diverged.
        sequence: u64,
        /// Caller-anchored commitment.
        expected_commitment: StateRootV2,
        /// Repository-returned commitment.
        observed_commitment: StateRootV2,
    },
    /// The repository could not provide a strongly consistent answer.
    Unavailable,
}

/// Exact expected-anchor CAS request for one authenticated successor head.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct CompositeHeadCasRequestV2 {
    request_id: OperationRequestIdV2,
    expected_anchor: Option<HeadAnchorV2>,
    next_head: CompositeStateHeadV2,
}

impl CompositeHeadCasRequestV2 {
    /// Creates a request only for the exact next sequence in the same namespace.
    pub fn new(
        request_id: OperationRequestIdV2,
        expected_anchor: Option<HeadAnchorV2>,
        next_head: CompositeStateHeadV2,
    ) -> Result<Self> {
        match expected_anchor.as_ref() {
            None if next_head.sequence() == 1 => {}
            Some(expected)
                if next_head.namespace() == expected.namespace()
                    && next_head.sequence()
                        == expected.sequence().checked_add(1).ok_or_else(|| {
                            SecureStoreError::StateConflict(
                                "head anchor sequence exhausted".to_owned(),
                            )
                        })? => {}
            _ => {
                return Err(SecureStoreError::StateConflict(
                    "repository CAS candidate is not initial or the exact namespace successor"
                        .to_owned(),
                ));
            }
        }
        Ok(Self {
            request_id,
            expected_anchor,
            next_head,
        })
    }

    /// Returns the idempotency identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the exact expected durable anchor.
    #[must_use]
    pub fn expected_anchor(&self) -> Option<&HeadAnchorV2> {
        self.expected_anchor.as_ref()
    }

    /// Returns the exact authenticated successor candidate.
    #[must_use]
    pub fn next_head(&self) -> &CompositeStateHeadV2 {
        &self.next_head
    }

    /// Returns the canonical idempotency-intent commitment.
    pub fn intent_commitment(&self) -> Result<StateRootV2> {
        intent_commitment("composite-head-repository-cas-v2", self)
    }

    /// Recovers an exact persisted CAS intent only after authenticating its
    /// successor head for the configured namespace.
    pub fn from_json_bounded(
        bytes: &[u8],
        expected_namespace: &StateNamespaceV2,
        mac_authority: &dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_COMPOSITE_HEAD_CAS_REQUEST_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "composite-head CAS request exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: CompositeHeadCasRequestRecoveryWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        let expected_anchor = wire
            .expected_anchor
            .map(|anchor| HeadAnchorV2::from_recovery_wire(anchor, expected_namespace))
            .transpose()?;
        let head_bytes =
            serde_json::to_vec(&wire.next_head).map_err(|_| SecureStoreError::Serialization)?;
        let next_head = CompositeStateHeadV2::from_json_bounded(
            &head_bytes,
            expected_namespace,
            mac_authority,
        )?;
        Self::new(wire.request_id, expected_anchor, next_head)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompositeHeadCasRequestRecoveryWireV2 {
    request_id: OperationRequestIdV2,
    expected_anchor: Option<HeadAnchorRecoveryWireV2>,
    next_head: serde_json::Value,
}

impl fmt::Debug for CompositeHeadCasRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompositeHeadCasRequestV2")
            .field("request_id", &"[OPAQUE]")
            .field("expected_anchor", &self.expected_anchor)
            .field("next_head", &self.next_head)
            .finish()
    }
}

/// Result of an idempotent, durable composite-head compare-and-swap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "value")]
pub enum CompositeHeadCasOutcomeV2 {
    /// The exact successor was durably anchored by this call.
    Applied(AnchoredCompositeHeadV2),
    /// The same request ID and candidate were already durably anchored.
    AlreadyAnchored(AnchoredCompositeHeadV2),
    /// Current repository state does not equal the expected anchor.
    Conflict {
        /// Current durable anchor, or `None` if the repository is empty.
        current: Option<HeadAnchorV2>,
    },
    /// Current state has the expected sequence but a different commitment.
    Divergence {
        /// Divergent sequence.
        sequence: u64,
        /// CAS request's expected commitment.
        expected_commitment: StateRootV2,
        /// Repository's current commitment.
        observed_commitment: StateRootV2,
    },
    /// No authoritative durability answer is available; callers must fail closed.
    Unavailable,
}

/// Durable repository backend distinct from the head MAC authority.
///
/// Implementations MUST provide linearizable load/CAS, permanently bind each
/// request ID to one intent, fsync or equivalently commit the head and receipt
/// before returning `Applied`, and never substitute MAC computation for durable
/// anchoring. A MAC proves authenticity; this repository proves monotonicity.
/// Direct calls are transport-level only; integration callers use
/// [`CurrentCompositeHeadRepositoryV2`] so freshness and returned evidence
/// cannot be forgotten.
pub trait CompositeHeadRepositoryV2: Send + Sync {
    /// Returns authenticated provenance for this repository deployment.
    fn provenance(&self) -> &AuthorityProvenanceV2;

    /// Loads an anchored head and explicitly classifies rollback/ahead/divergence.
    fn load(&self, request: &CompositeHeadLoadRequestV2) -> Result<CompositeHeadLoadOutcomeV2>;

    /// Atomically anchors an exact authenticated successor.
    fn compare_and_swap(
        &self,
        request: &CompositeHeadCasRequestV2,
    ) -> Result<CompositeHeadCasOutcomeV2>;
}

/// Integration-eligible repository view with mandatory per-use trust checks.
pub struct CurrentCompositeHeadRepositoryV2<'a> {
    backend: &'a dyn CompositeHeadRepositoryV2,
    provenance_verifier: &'a dyn AuthorityProvenanceVerifierV2,
    evidence_verifier: &'a dyn AuthorityEvidenceVerifierV2,
    mac_authority: &'a dyn HeadMacAuthorityV2,
}

impl<'a> CurrentCompositeHeadRepositoryV2<'a> {
    /// Binds a repository only after a current production provenance decision.
    pub fn bind(
        backend: &'a dyn CompositeHeadRepositoryV2,
        evaluated_at_micros: u64,
        provenance_verifier: &'a dyn AuthorityProvenanceVerifierV2,
        evidence_verifier: &'a dyn AuthorityEvidenceVerifierV2,
        mac_authority: &'a dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        require_role(
            backend.provenance(),
            AuthorityRoleV2::CompositeHeadRepository,
        )?;
        backend
            .provenance()
            .require_current(evaluated_at_micros, provenance_verifier)?;
        Ok(Self {
            backend,
            provenance_verifier,
            evidence_verifier,
            mac_authority,
        })
    }

    /// Loads state only after fresh trust, MAC, receipt, and lineage validation.
    pub fn load(
        &self,
        evaluated_at_micros: u64,
        request: &CompositeHeadLoadRequestV2,
    ) -> Result<CompositeHeadLoadOutcomeV2> {
        self.require_current(evaluated_at_micros)?;
        let outcome = self.backend.load(request)?;
        match &outcome {
            CompositeHeadLoadOutcomeV2::Empty => {
                if request.expected_anchor().is_some() {
                    return Err(SecureStoreError::Integrity(
                        "repository returned Empty despite a durable caller anchor".to_owned(),
                    ));
                }
            }
            CompositeHeadLoadOutcomeV2::Exact(current) => {
                self.validate_anchored(current, request.namespace(), evaluated_at_micros)?;
                if request
                    .expected_anchor()
                    .is_some_and(|expected| expected != current.anchor())
                {
                    return Err(SecureStoreError::Integrity(
                        "repository labeled a non-exact head as Exact".to_owned(),
                    ));
                }
            }
            CompositeHeadLoadOutcomeV2::Ahead { current, lineage } => {
                let expected = request.expected_anchor().ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "repository returned Ahead without a caller anchor".to_owned(),
                    )
                })?;
                self.validate_anchored(current, request.namespace(), evaluated_at_micros)?;
                CompositeHeadLineageProofV2::try_new(
                    expected,
                    current,
                    lineage.receipts().to_vec(),
                )?;
                lineage.verify_current(evaluated_at_micros, self.evidence_verifier)?;
            }
            CompositeHeadLoadOutcomeV2::MissingLineage { .. }
            | CompositeHeadLoadOutcomeV2::Rollback { .. }
            | CompositeHeadLoadOutcomeV2::Divergence { .. }
            | CompositeHeadLoadOutcomeV2::Unavailable => {}
        }
        Ok(outcome)
    }

    /// Publishes only after fresh trust and validates the durable returned receipt.
    pub fn compare_and_swap(
        &self,
        evaluated_at_micros: u64,
        request: &CompositeHeadCasRequestV2,
    ) -> Result<CompositeHeadCasOutcomeV2> {
        self.require_current(evaluated_at_micros)?;
        request
            .next_head()
            .verify(request.next_head().namespace(), self.mac_authority)?;
        let outcome = self.backend.compare_and_swap(request)?;
        match &outcome {
            CompositeHeadCasOutcomeV2::Applied(current)
            | CompositeHeadCasOutcomeV2::AlreadyAnchored(current) => {
                self.validate_anchored(
                    current,
                    request.next_head().namespace(),
                    evaluated_at_micros,
                )?;
                if current.head() != request.next_head()
                    || current.receipt().previous_anchor() != request.expected_anchor()
                    || current.receipt().authority_evidence().request_id() != request.request_id()
                {
                    return Err(SecureStoreError::Integrity(
                        "repository CAS receipt does not bind the exact requested successor"
                            .to_owned(),
                    ));
                }
            }
            CompositeHeadCasOutcomeV2::Conflict { .. }
            | CompositeHeadCasOutcomeV2::Divergence { .. }
            | CompositeHeadCasOutcomeV2::Unavailable => {}
        }
        Ok(outcome)
    }

    fn require_current(&self, evaluated_at_micros: u64) -> Result<()> {
        self.backend
            .provenance()
            .require_current(evaluated_at_micros, self.provenance_verifier)
    }

    fn validate_anchored(
        &self,
        current: &AnchoredCompositeHeadV2,
        namespace: &StateNamespaceV2,
        evaluated_at_micros: u64,
    ) -> Result<()> {
        current.head().verify(namespace, self.mac_authority)?;
        if current.receipt().provenance() != self.backend.provenance() {
            return Err(SecureStoreError::Integrity(
                "repository receipt provenance differs from configured backend".to_owned(),
            ));
        }
        current
            .receipt()
            .verify_current(evaluated_at_micros, self.evidence_verifier)
    }
}

impl fmt::Debug for CurrentCompositeHeadRepositoryV2<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentCompositeHeadRepositoryV2")
            .field("provenance", self.backend.provenance())
            .finish_non_exhaustive()
    }
}

/// Classifies a repository load against the caller's durable expectation.
pub fn classify_composite_head_load_v2(
    expected: Option<&HeadAnchorV2>,
    observed: Option<AnchoredCompositeHeadV2>,
    lineage: Option<CompositeHeadLineageProofV2>,
) -> Result<CompositeHeadLoadOutcomeV2> {
    let Some(observed) = observed else {
        return Ok(match expected {
            None => CompositeHeadLoadOutcomeV2::Empty,
            Some(anchor) => CompositeHeadLoadOutcomeV2::Rollback {
                expected_sequence: anchor.sequence(),
                observed_sequence: 0,
            },
        });
    };
    let Some(expected) = expected else {
        return Ok(CompositeHeadLoadOutcomeV2::Exact(observed));
    };
    if observed.anchor().namespace() != expected.namespace() {
        return Err(SecureStoreError::Integrity(
            "loaded head namespace differs from the expected anchor".to_owned(),
        ));
    }
    if observed.anchor().sequence() < expected.sequence() {
        return Ok(CompositeHeadLoadOutcomeV2::Rollback {
            expected_sequence: expected.sequence(),
            observed_sequence: observed.anchor().sequence(),
        });
    }
    if observed.anchor().sequence() > expected.sequence() {
        return match lineage {
            Some(lineage) => {
                let validated =
                    CompositeHeadLineageProofV2::try_new(expected, &observed, lineage.receipts)?;
                Ok(CompositeHeadLoadOutcomeV2::Ahead {
                    current: observed,
                    lineage: validated,
                })
            }
            None => Ok(CompositeHeadLoadOutcomeV2::MissingLineage {
                expected_sequence: expected.sequence(),
                observed_sequence: observed.anchor().sequence(),
            }),
        };
    }
    if observed.anchor().head_commitment() != expected.head_commitment() {
        return Ok(CompositeHeadLoadOutcomeV2::Divergence {
            sequence: expected.sequence(),
            expected_commitment: expected.head_commitment().clone(),
            observed_commitment: observed.anchor().head_commitment().clone(),
        });
    }
    Ok(CompositeHeadLoadOutcomeV2::Exact(observed))
}

pub(crate) fn head_anchor_subject(
    previous_anchor: Option<&HeadAnchorV2>,
    anchor: &HeadAnchorV2,
) -> Result<StateRootV2> {
    #[derive(Serialize)]
    struct Subject<'a> {
        previous_anchor: Option<&'a HeadAnchorV2>,
        anchor: &'a HeadAnchorV2,
    }
    intent_commitment(
        "composite-head-anchor-evidence-subject-v2",
        &Subject {
            previous_anchor,
            anchor,
        },
    )
}

fn validate_anchor_link(previous: Option<&HeadAnchorV2>, anchor: &HeadAnchorV2) -> Result<()> {
    match previous {
        None if anchor.sequence() == 1 => Ok(()),
        Some(previous)
            if previous.namespace() == anchor.namespace()
                && previous.sequence().checked_add(1) == Some(anchor.sequence()) =>
        {
            Ok(())
        }
        _ => Err(SecureStoreError::Integrity(
            "repository anchor receipt is not the exact chained successor".to_owned(),
        )),
    }
}
