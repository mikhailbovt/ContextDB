use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    EvidenceHandleV2, OperationRequestIdV2, ReceiptSignatureV2, ReceiptSigningKeyRefV2, Result,
    SECURE_STORE_FORMAT_VERSION, SecureStoreError, StateNamespaceV2, StateRootV2, canonical_json,
    validate_label,
};

const AUTHORITY_ATTESTATION_DOMAIN_V2: &[u8] = b"contextdb/authority-provenance-attestation/v2\0";
const AUTHORITY_EVIDENCE_DOMAIN_V2: &[u8] = b"contextdb/authority-evidence/v2\0";

/// Maximum bytes accepted for one authority-provenance attestation.
pub const MAX_AUTHORITY_PROVENANCE_JSON_BYTES_V2: usize = 64 * 1024;
/// Maximum bytes accepted for one signed authority-evidence envelope.
pub const MAX_AUTHORITY_EVIDENCE_JSON_BYTES_V2: usize = 256 * 1024;
/// Maximum authority components evaluated in one production trust gate.
pub const MAX_PRODUCTION_TRUST_COMPONENTS_V2: usize = 256;

/// Security role performed by an external production-boundary adapter.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRoleV2 {
    /// Creates and destroys content-encryption keys.
    KeyAuthority,
    /// Durably anchors authenticated composite state heads.
    CompositeHeadRepository,
    /// Deletes a provider, export, or backup copy.
    ManagedCopyProvider,
}

/// Authenticated deployment trust classification of an adapter.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterTrustLevelV2 {
    /// Volatile, test, development, or otherwise non-authoritative adapter.
    NonProduction,
    /// Adapter whose deployment provenance was verified by an external trust root.
    Production,
}

/// Validated provenance of one concrete authority deployment.
///
/// Production provenance has no public unchecked constructor or `Deserialize`
/// implementation. It can only be recovered from a bounded attestation that an
/// external trust-root verifier accepts. Non-production provenance is explicit.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AuthorityProvenanceV2 {
    format_version: u16,
    role: AuthorityRoleV2,
    trust_level: AdapterTrustLevelV2,
    authority_id: String,
    deployment_id: String,
    attestation_generation: u64,
    attested_at_micros: u64,
    expires_at_micros: u64,
}

impl AuthorityProvenanceV2 {
    /// Creates explicitly non-production provenance for tests and development.
    pub fn non_production(
        role: AuthorityRoleV2,
        authority_id: impl Into<String>,
        deployment_id: impl Into<String>,
    ) -> Result<Self> {
        Self::validated(
            role,
            AdapterTrustLevelV2::NonProduction,
            authority_id.into(),
            deployment_id.into(),
            0,
            0,
            0,
        )
    }

    /// Decodes and verifies an attested production provenance statement.
    pub fn from_attested_json_bounded(
        bytes: &[u8],
        expected_role: AuthorityRoleV2,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityProvenanceVerifierV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_AUTHORITY_PROVENANCE_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "authority provenance exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: AttestedAuthorityProvenanceWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        wire.unsigned.validate()?;
        if wire.unsigned.role != expected_role
            || wire.unsigned.trust_level != AdapterTrustLevelV2::Production
        {
            return Err(SecureStoreError::Integrity(
                "authority provenance role or trust level is not expected".to_owned(),
            ));
        }
        verifier.verify_attestation(
            &wire.signing_key,
            &authority_attestation_message(&wire.unsigned, &wire.signing_key)?,
            wire.signature.as_bytes(),
        )?;
        let provenance = Self::validated(
            wire.unsigned.role,
            wire.unsigned.trust_level,
            wire.unsigned.authority_id,
            wire.unsigned.deployment_id,
            wire.unsigned.attestation_generation,
            wire.unsigned.attested_at_micros,
            wire.unsigned.expires_at_micros,
        )?;
        provenance.require_current(evaluated_at_micros, verifier)?;
        Ok(provenance)
    }

    /// Returns the adapter security role.
    #[must_use]
    pub const fn role(&self) -> AuthorityRoleV2 {
        self.role
    }

    /// Returns the externally attested trust level.
    #[must_use]
    pub const fn trust_level(&self) -> AdapterTrustLevelV2 {
        self.trust_level
    }

    /// Returns the stable authority identity.
    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    /// Returns the exact deployment or trust-domain identity.
    #[must_use]
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    /// Returns the monotonic trust-attestation generation, or zero for non-production.
    #[must_use]
    pub const fn attestation_generation(&self) -> u64 {
        self.attestation_generation
    }

    /// Returns the production attestation issue time, or zero for non-production.
    #[must_use]
    pub const fn attested_at_micros(&self) -> u64 {
        self.attested_at_micros
    }

    /// Returns the exclusive production attestation expiry, or zero for non-production.
    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }

    /// Requires a fresh host-provided revocation/current-trust decision.
    pub fn require_current(
        &self,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityProvenanceVerifierV2,
    ) -> Result<()> {
        self.validate()?;
        if self.trust_level != AdapterTrustLevelV2::Production
            || evaluated_at_micros < self.attested_at_micros
            || evaluated_at_micros >= self.expires_at_micros
        {
            return Err(SecureStoreError::DeletionIncomplete(
                "authority provenance is not currently production-trusted".to_owned(),
            ));
        }
        verifier.verify_current(self, evaluated_at_micros)
    }

    fn validated(
        role: AuthorityRoleV2,
        trust_level: AdapterTrustLevelV2,
        authority_id: String,
        deployment_id: String,
        attestation_generation: u64,
        attested_at_micros: u64,
        expires_at_micros: u64,
    ) -> Result<Self> {
        validate_label(&authority_id, "authority provenance ID")?;
        validate_label(&deployment_id, "authority deployment ID")?;
        match trust_level {
            AdapterTrustLevelV2::NonProduction
                if attestation_generation == 0
                    && attested_at_micros == 0
                    && expires_at_micros == 0 => {}
            AdapterTrustLevelV2::Production
                if attestation_generation > 0
                    && attested_at_micros > 0
                    && expires_at_micros > attested_at_micros => {}
            _ => {
                return Err(SecureStoreError::Integrity(
                    "authority trust level and attestation lifetime disagree".to_owned(),
                ));
            }
        }
        Ok(Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            role,
            trust_level,
            authority_id,
            deployment_id,
            attestation_generation,
            attested_at_micros,
            expires_at_micros,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.format_version != SECURE_STORE_FORMAT_VERSION {
            return Err(SecureStoreError::Integrity(
                "authority provenance format version is invalid".to_owned(),
            ));
        }
        validate_label(&self.authority_id, "authority provenance ID")?;
        validate_label(&self.deployment_id, "authority deployment ID")?;
        match self.trust_level {
            AdapterTrustLevelV2::NonProduction
                if self.attestation_generation == 0
                    && self.attested_at_micros == 0
                    && self.expires_at_micros == 0 =>
            {
                Ok(())
            }
            AdapterTrustLevelV2::Production
                if self.attestation_generation > 0
                    && self.attested_at_micros > 0
                    && self.expires_at_micros > self.attested_at_micros =>
            {
                Ok(())
            }
            _ => Err(SecureStoreError::Integrity(
                "authority trust level and attestation lifetime disagree".to_owned(),
            )),
        }
    }
}

impl fmt::Debug for AuthorityProvenanceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityProvenanceV2")
            .field("role", &self.role)
            .field("trust_level", &self.trust_level)
            .field("authority_id", &"[REDACTED]")
            .field("deployment_id", &"[REDACTED]")
            .field("attestation_generation", &self.attestation_generation)
            .field("attested_at_micros", &self.attested_at_micros)
            .field("expires_at_micros", &self.expires_at_micros)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityProvenanceUnsignedWireV2 {
    format_version: u16,
    role: AuthorityRoleV2,
    trust_level: AdapterTrustLevelV2,
    authority_id: String,
    deployment_id: String,
    attestation_generation: u64,
    attested_at_micros: u64,
    expires_at_micros: u64,
}

impl AuthorityProvenanceUnsignedWireV2 {
    fn validate(&self) -> Result<()> {
        if self.format_version != SECURE_STORE_FORMAT_VERSION {
            return Err(SecureStoreError::Integrity(
                "authority provenance format version is invalid".to_owned(),
            ));
        }
        validate_label(&self.authority_id, "authority provenance ID")?;
        validate_label(&self.deployment_id, "authority deployment ID")?;
        match self.trust_level {
            AdapterTrustLevelV2::NonProduction
                if self.attestation_generation == 0
                    && self.attested_at_micros == 0
                    && self.expires_at_micros == 0 =>
            {
                Ok(())
            }
            AdapterTrustLevelV2::Production
                if self.attestation_generation > 0
                    && self.attested_at_micros > 0
                    && self.expires_at_micros > self.attested_at_micros =>
            {
                Ok(())
            }
            _ => Err(SecureStoreError::Integrity(
                "authority trust level and attestation lifetime disagree".to_owned(),
            )),
        }
    }
}

impl From<&AuthorityProvenanceV2> for AuthorityProvenanceUnsignedWireV2 {
    fn from(value: &AuthorityProvenanceV2) -> Self {
        Self {
            format_version: value.format_version,
            role: value.role,
            trust_level: value.trust_level,
            authority_id: value.authority_id.clone(),
            deployment_id: value.deployment_id.clone(),
            attestation_generation: value.attestation_generation,
            attested_at_micros: value.attested_at_micros,
            expires_at_micros: value.expires_at_micros,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestedAuthorityProvenanceWireV2 {
    unsigned: AuthorityProvenanceUnsignedWireV2,
    signing_key: ReceiptSigningKeyRefV2,
    signature: ReceiptSignatureV2,
}

/// External trust-root verifier for production authority provenance.
pub trait AuthorityProvenanceVerifierV2: Send + Sync {
    /// Verifies an exact bounded, domain-separated provenance attestation.
    fn verify_attestation(
        &self,
        signing_key: &ReceiptSigningKeyRefV2,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()>;

    /// Consults the host's current trust/revocation state for every use.
    fn verify_current(
        &self,
        provenance: &AuthorityProvenanceV2,
        evaluated_at_micros: u64,
    ) -> Result<()>;
}

/// Semantic kind of an externally signed authority-evidence envelope.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityEvidenceKindV2 {
    /// A DEK was irreversibly destroyed by the named key authority.
    KeyDestroyed,
    /// A composite state head was durably and rollback-resistently anchored.
    CompositeHeadAnchored,
    /// A managed copy was deleted by its responsible authority.
    ManagedCopyDeleted,
    /// A managed copy was independently proven absent.
    ManagedCopyProvenAbsent,
    /// A managed copy is outside verifiable control and remains incomplete.
    ManagedCopyOutsideControl,
}

/// Externally verified, signed evidence with exact namespace and intent binding.
///
/// This type has no public constructor and no `Deserialize` implementation.
/// Callers can only obtain it through bounded signature verification or from an
/// authority adapter that already returns this verified type.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct VerifiedAuthorityEvidenceV2 {
    format_version: u16,
    kind: AuthorityEvidenceKindV2,
    provenance: AuthorityProvenanceV2,
    namespace: StateNamespaceV2,
    request_id: OperationRequestIdV2,
    subject_commitment: StateRootV2,
    issued_at_micros: u64,
    evidence_handle: EvidenceHandleV2,
    signing_key: ReceiptSigningKeyRefV2,
    signature: ReceiptSignatureV2,
}

impl VerifiedAuthorityEvidenceV2 {
    /// Decodes bounded signed evidence and verifies every expected binding.
    #[allow(
        clippy::too_many_arguments,
        reason = "all expected evidence bindings must be supplied explicitly"
    )]
    pub fn from_json_bounded(
        bytes: &[u8],
        expected_kind: AuthorityEvidenceKindV2,
        expected_provenance: &AuthorityProvenanceV2,
        expected_namespace: &StateNamespaceV2,
        expected_request_id: &OperationRequestIdV2,
        expected_subject_commitment: &StateRootV2,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityEvidenceVerifierV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_AUTHORITY_EVIDENCE_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "authority evidence exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: VerifiedAuthorityEvidenceWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        let evidence = Self::from_wire(wire)?;
        evidence.verify_exact(
            expected_kind,
            expected_provenance,
            expected_namespace,
            expected_request_id,
            expected_subject_commitment,
            evaluated_at_micros,
            verifier,
        )?;
        Ok(evidence)
    }

    /// Returns the evidence semantic kind.
    #[must_use]
    pub const fn kind(&self) -> AuthorityEvidenceKindV2 {
        self.kind
    }

    /// Returns authenticated authority provenance.
    #[must_use]
    pub fn provenance(&self) -> &AuthorityProvenanceV2 {
        &self.provenance
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the idempotent request identity bound by the signature.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the exact public subject commitment bound by the signature.
    #[must_use]
    pub fn subject_commitment(&self) -> &StateRootV2 {
        &self.subject_commitment
    }

    /// Returns the authority issuance time.
    #[must_use]
    pub const fn issued_at_micros(&self) -> u64 {
        self.issued_at_micros
    }

    /// Returns an opaque audit/evidence handle.
    #[must_use]
    pub fn evidence_handle(&self) -> &EvidenceHandleV2 {
        &self.evidence_handle
    }

    /// Returns the exact signing-key generation.
    #[must_use]
    pub fn signing_key(&self) -> &ReceiptSigningKeyRefV2 {
        &self.signing_key
    }

    /// Re-verifies this evidence against exact caller-supplied bindings.
    #[allow(
        clippy::too_many_arguments,
        reason = "all expected evidence bindings must be supplied explicitly"
    )]
    pub fn verify_exact(
        &self,
        expected_kind: AuthorityEvidenceKindV2,
        expected_provenance: &AuthorityProvenanceV2,
        expected_namespace: &StateNamespaceV2,
        expected_request_id: &OperationRequestIdV2,
        expected_subject_commitment: &StateRootV2,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityEvidenceVerifierV2,
    ) -> Result<()> {
        self.validate_shape()?;
        if self.kind != expected_kind
            || &self.provenance != expected_provenance
            || &self.namespace != expected_namespace
            || &self.request_id != expected_request_id
            || &self.subject_commitment != expected_subject_commitment
        {
            return Err(SecureStoreError::Integrity(
                "authority evidence does not match the expected operation".to_owned(),
            ));
        }
        if self.issued_at_micros > evaluated_at_micros
            || (self.provenance.trust_level == AdapterTrustLevelV2::Production
                && (self.issued_at_micros < self.provenance.attested_at_micros
                    || self.issued_at_micros >= self.provenance.expires_at_micros
                    || evaluated_at_micros >= self.provenance.expires_at_micros))
        {
            return Err(SecureStoreError::Integrity(
                "authority evidence time is outside the current attestation window".to_owned(),
            ));
        }
        verifier.verify_current_provenance(&self.provenance, evaluated_at_micros)?;
        verifier.verify_evidence(
            &self.provenance,
            &self.signing_key,
            &authority_evidence_message(self)?,
            self.signature.as_bytes(),
        )
    }

    fn from_wire(wire: VerifiedAuthorityEvidenceWireV2) -> Result<Self> {
        wire.provenance.validate()?;
        let provenance = AuthorityProvenanceV2::validated(
            wire.provenance.role,
            wire.provenance.trust_level,
            wire.provenance.authority_id,
            wire.provenance.deployment_id,
            wire.provenance.attestation_generation,
            wire.provenance.attested_at_micros,
            wire.provenance.expires_at_micros,
        )?;
        let evidence = Self {
            format_version: wire.format_version,
            kind: wire.kind,
            provenance,
            namespace: wire.namespace,
            request_id: wire.request_id,
            subject_commitment: wire.subject_commitment,
            issued_at_micros: wire.issued_at_micros,
            evidence_handle: wire.evidence_handle,
            signing_key: wire.signing_key,
            signature: wire.signature,
        };
        evidence.validate_shape()?;
        Ok(evidence)
    }

    fn validate_shape(&self) -> Result<()> {
        self.provenance.validate()?;
        if self.format_version != SECURE_STORE_FORMAT_VERSION || self.issued_at_micros == 0 {
            return Err(SecureStoreError::Integrity(
                "authority evidence version or issue time is invalid".to_owned(),
            ));
        }
        ReceiptSignatureV2::try_new(self.signature.as_bytes().to_vec())?;
        Ok(())
    }
}

impl fmt::Debug for VerifiedAuthorityEvidenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthorityEvidenceV2")
            .field("kind", &self.kind)
            .field("provenance", &self.provenance)
            .field("namespace", &self.namespace)
            .field("request_id", &"[OPAQUE]")
            .field("subject_commitment", &"[COMMITMENT]")
            .field("issued_at_micros", &self.issued_at_micros)
            .field("evidence_handle", &"[OPAQUE]")
            .field("signing_key_generation", &self.signing_key.generation())
            .field("signature", &"[AUTHENTICATOR]")
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedAuthorityEvidenceWireV2 {
    format_version: u16,
    kind: AuthorityEvidenceKindV2,
    provenance: AuthorityProvenanceUnsignedWireV2,
    namespace: StateNamespaceV2,
    request_id: OperationRequestIdV2,
    subject_commitment: StateRootV2,
    issued_at_micros: u64,
    evidence_handle: EvidenceHandleV2,
    signing_key: ReceiptSigningKeyRefV2,
    signature: ReceiptSignatureV2,
}

impl From<&VerifiedAuthorityEvidenceV2> for VerifiedAuthorityEvidenceWireV2 {
    fn from(value: &VerifiedAuthorityEvidenceV2) -> Self {
        Self {
            format_version: value.format_version,
            kind: value.kind,
            provenance: (&value.provenance).into(),
            namespace: value.namespace.clone(),
            request_id: value.request_id.clone(),
            subject_commitment: value.subject_commitment.clone(),
            issued_at_micros: value.issued_at_micros,
            evidence_handle: value.evidence_handle.clone(),
            signing_key: value.signing_key.clone(),
            signature: value.signature.clone(),
        }
    }
}

/// External signature verifier for authority-issued operation evidence.
pub trait AuthorityEvidenceVerifierV2: Send + Sync {
    /// Consults current host trust/revocation state on every evidence use.
    fn verify_current_provenance(
        &self,
        provenance: &AuthorityProvenanceV2,
        evaluated_at_micros: u64,
    ) -> Result<()>;

    /// Verifies exact authority provenance, signing generation, message, and signature.
    fn verify_evidence(
        &self,
        provenance: &AuthorityProvenanceV2,
        signing_key: &ReceiptSigningKeyRefV2,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

/// Explicit result of an idempotent external authority call.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "value")]
pub enum AuthorityOperationOutcomeV2<T> {
    /// This call applied the requested intent.
    Applied(T),
    /// The same request ID and exact intent had already been applied.
    AlreadyApplied(T),
    /// The request ID or expected generation is bound to another intent/state.
    Conflict {
        /// Commitment to the authority's existing intent or current public state.
        existing_commitment: StateRootV2,
    },
    /// The authority could not provide an authoritative answer; callers must fail closed.
    Unavailable,
}

impl<T> fmt::Debug for AuthorityOperationOutcomeV2<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied(_) => formatter.write_str("AuthorityOperationOutcomeV2::Applied(..)"),
            Self::AlreadyApplied(_) => {
                formatter.write_str("AuthorityOperationOutcomeV2::AlreadyApplied(..)")
            }
            Self::Conflict { .. } => {
                formatter.write_str("AuthorityOperationOutcomeV2::Conflict([COMMITMENT])")
            }
            Self::Unavailable => formatter.write_str("AuthorityOperationOutcomeV2::Unavailable"),
        }
    }
}

/// Production capability whose integration boundary is being evaluated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionCapabilityV2 {
    /// Advertise or execute production hard deletion.
    HardDelete,
    /// Treat a deletion workflow as production-complete.
    Complete,
}

/// Trust-gate result; this never enables a service capability by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionTrustGateV2 {
    /// At least one required adapter is explicitly non-production.
    DeniedNonProduction {
        /// Role of the first non-production component.
        role: AuthorityRoleV2,
    },
    /// All supplied boundaries are attested, but production wiring and the
    /// remaining P3-P6 gates still decide whether the capability can exist.
    EligibleForIntegrationOnly,
}

/// Exact authority cardinalities required by one integration decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionTrustRequirementsV2 {
    managed_copy_authority_count: usize,
}

impl ProductionTrustRequirementsV2 {
    /// Declares how many managed-copy authorities the authoritative inventory
    /// requires. Zero is valid only when all managed classes have independently
    /// verified absence evidence.
    pub fn new(managed_copy_authority_count: usize) -> Result<Self> {
        if managed_copy_authority_count > MAX_PRODUCTION_TRUST_COMPONENTS_V2.saturating_sub(2) {
            return Err(SecureStoreError::InvalidInput(
                "managed-copy authority count exceeds trust bound".to_owned(),
            ));
        }
        Ok(Self {
            managed_copy_authority_count,
        })
    }

    /// Returns the exact required managed-copy authority count.
    #[must_use]
    pub const fn managed_copy_authority_count(self) -> usize {
        self.managed_copy_authority_count
    }
}

/// Evaluates adapter provenance without enabling a runtime capability.
///
/// A key authority and composite-head repository are mandatory. Managed-copy
/// providers may repeat because one closure can span several authorities.
pub fn evaluate_production_trust_v2(
    _capability: ProductionCapabilityV2,
    requirements: ProductionTrustRequirementsV2,
    authorities: &[AuthorityProvenanceV2],
    evaluated_at_micros: u64,
    verifier: &dyn AuthorityProvenanceVerifierV2,
) -> Result<ProductionTrustGateV2> {
    if authorities.is_empty() || authorities.len() > MAX_PRODUCTION_TRUST_COMPONENTS_V2 {
        return Err(SecureStoreError::InvalidInput(
            "production trust component count is invalid".to_owned(),
        ));
    }
    let key_count = authorities
        .iter()
        .filter(|value| value.role == AuthorityRoleV2::KeyAuthority)
        .count();
    let repository_count = authorities
        .iter()
        .filter(|value| value.role == AuthorityRoleV2::CompositeHeadRepository)
        .count();
    let managed_count = authorities
        .iter()
        .filter(|value| value.role == AuthorityRoleV2::ManagedCopyProvider)
        .count();
    if key_count != 1
        || repository_count != 1
        || managed_count != requirements.managed_copy_authority_count
        || authorities.len() != 2_usize.saturating_add(managed_count)
    {
        return Err(SecureStoreError::InvalidInput(
            "production trust authority roles/counts do not match requirements".to_owned(),
        ));
    }
    if let Some(authority) = authorities
        .iter()
        .find(|value| value.trust_level == AdapterTrustLevelV2::NonProduction)
    {
        return Ok(ProductionTrustGateV2::DeniedNonProduction {
            role: authority.role,
        });
    }
    for authority in authorities {
        authority.require_current(evaluated_at_micros, verifier)?;
    }
    Ok(ProductionTrustGateV2::EligibleForIntegrationOnly)
}

pub(crate) fn intent_commitment<T: Serialize + ?Sized>(
    domain: &str,
    value: &T,
) -> Result<StateRootV2> {
    StateRootV2::commit(domain, &canonical_json(value)?)
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) trait NonProductionAuthorityEvidenceSignerV2 {
    fn signing_key(&self) -> Result<ReceiptSigningKeyRefV2>;
    fn sign_evidence(&self, message: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(any(test, feature = "test-support"))]
#[allow(
    clippy::too_many_arguments,
    reason = "test issuer mirrors every signed authority-evidence field"
)]
pub(crate) fn issue_non_production_evidence(
    kind: AuthorityEvidenceKindV2,
    provenance: AuthorityProvenanceV2,
    namespace: StateNamespaceV2,
    request_id: OperationRequestIdV2,
    subject_commitment: StateRootV2,
    issued_at_micros: u64,
    evidence_handle: EvidenceHandleV2,
    signer: &dyn NonProductionAuthorityEvidenceSignerV2,
) -> Result<VerifiedAuthorityEvidenceV2> {
    if provenance.trust_level != AdapterTrustLevelV2::NonProduction {
        return Err(SecureStoreError::Integrity(
            "test evidence issuer accepts only non-production provenance".to_owned(),
        ));
    }
    let signing_key = signer.signing_key()?;
    let mut evidence = VerifiedAuthorityEvidenceV2 {
        format_version: SECURE_STORE_FORMAT_VERSION,
        kind,
        provenance,
        namespace,
        request_id,
        subject_commitment,
        issued_at_micros,
        evidence_handle,
        signing_key,
        signature: ReceiptSignatureV2::try_new(vec![1])?,
    };
    evidence.validate_shape()?;
    evidence.signature = ReceiptSignatureV2::try_new(
        signer.sign_evidence(&authority_evidence_message(&evidence)?)?,
    )?;
    Ok(evidence)
}

fn authority_attestation_message(
    unsigned: &AuthorityProvenanceUnsignedWireV2,
    signing_key: &ReceiptSigningKeyRefV2,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Payload<'a> {
        unsigned: &'a AuthorityProvenanceUnsignedWireV2,
        signing_key: &'a ReceiptSigningKeyRefV2,
    }
    domain_separated_message(
        AUTHORITY_ATTESTATION_DOMAIN_V2,
        &Payload {
            unsigned,
            signing_key,
        },
    )
}

fn authority_evidence_message(evidence: &VerifiedAuthorityEvidenceV2) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Payload<'a> {
        format_version: u16,
        kind: AuthorityEvidenceKindV2,
        provenance: &'a AuthorityProvenanceV2,
        namespace: &'a StateNamespaceV2,
        request_id: &'a OperationRequestIdV2,
        subject_commitment: &'a StateRootV2,
        issued_at_micros: u64,
        evidence_handle: &'a EvidenceHandleV2,
        signing_key: &'a ReceiptSigningKeyRefV2,
    }
    domain_separated_message(
        AUTHORITY_EVIDENCE_DOMAIN_V2,
        &Payload {
            format_version: evidence.format_version,
            kind: evidence.kind,
            provenance: &evidence.provenance,
            namespace: &evidence.namespace,
            request_id: &evidence.request_id,
            subject_commitment: &evidence.subject_commitment,
            issued_at_micros: evidence.issued_at_micros,
            evidence_handle: &evidence.evidence_handle,
            signing_key: &evidence.signing_key,
        },
    )
}

fn domain_separated_message<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let canonical = canonical_json(value)?;
    let mut message = Vec::with_capacity(
        domain
            .len()
            .saturating_add(8)
            .saturating_add(canonical.len()),
    );
    message.extend_from_slice(domain);
    message.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    message.extend_from_slice(&canonical);
    Ok(message)
}
