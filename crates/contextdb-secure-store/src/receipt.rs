use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    DeletionHandleV2, DeletionWorkflowStateV2, DeletionWorkflowV2, Result,
    SECURE_STORE_FORMAT_VERSION, SecureStoreError, StateNamespaceV2, StateRootV2, canonical_json,
    validate_label,
};

const RECEIPT_SIGNATURE_DOMAIN_V2: &[u8] = b"contextdb/deletion-receipt/v2\0";
const MAX_RECEIPT_SIGNATURE_BYTES: usize = 8 * 1024;
/// Maximum JSON bytes accepted for a standalone signed deletion receipt.
pub const MAX_SIGNED_DELETION_RECEIPT_JSON_BYTES_V2: usize = 256 * 1024;

/// Non-secret identity and generation of an external receipt-signing key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ReceiptSigningKeyWireV2", into = "ReceiptSigningKeyWireV2")]
pub struct ReceiptSigningKeyRefV2 {
    key_id: String,
    generation: u64,
}

impl ReceiptSigningKeyRefV2 {
    /// Creates a validated signing-key reference.
    pub fn new(key_id: impl Into<String>, generation: u64) -> Result<Self> {
        let key_id = key_id.into();
        validate_label(&key_id, "receipt signing key ID")?;
        if generation == 0 {
            return Err(SecureStoreError::InvalidInput(
                "receipt signing key generation must be non-zero".to_owned(),
            ));
        }
        Ok(Self { key_id, generation })
    }

    /// Returns the external key-management identity.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the monotonic signing-key generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSigningKeyWireV2 {
    key_id: String,
    generation: u64,
}

impl TryFrom<ReceiptSigningKeyWireV2> for ReceiptSigningKeyRefV2 {
    type Error = SecureStoreError;

    fn try_from(value: ReceiptSigningKeyWireV2) -> Result<Self> {
        Self::new(value.key_id, value.generation)
    }
}

impl From<ReceiptSigningKeyRefV2> for ReceiptSigningKeyWireV2 {
    fn from(value: ReceiptSigningKeyRefV2) -> Self {
        Self {
            key_id: value.key_id,
            generation: value.generation,
        }
    }
}

/// External receipt signer that never exposes private key bytes.
pub trait DeletionReceiptSignerV2 {
    /// Returns the exact key generation used for the next signature.
    fn active_signing_key(&self) -> Result<ReceiptSigningKeyRefV2>;

    /// Signs the already domain-separated canonical receipt message.
    fn sign(&self, key: &ReceiptSigningKeyRefV2, message: &[u8]) -> Result<Vec<u8>>;
}

/// External receipt verifier backed by a trusted key catalog, HSM, or KMS.
pub trait DeletionReceiptVerifierV2 {
    /// Verifies an exact signature and signing-key generation.
    fn verify(&self, key: &ReceiptSigningKeyRefV2, message: &[u8], signature: &[u8]) -> Result<()>;
}

/// Canonical unsigned v2 deletion receipt contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "UnsignedDeletionReceiptWireV2",
    into = "UnsignedDeletionReceiptWireV2"
)]
pub struct UnsignedDeletionReceiptV2 {
    format_version: u16,
    deletion: DeletionHandleV2,
    namespace: StateNamespaceV2,
    receipt_pending_workflow_root: StateRootV2,
    closure_inventory_root: StateRootV2,
    verification_commitment: StateRootV2,
    requested_at_micros: u64,
    completed_at_micros: u64,
}

impl UnsignedDeletionReceiptV2 {
    /// Derives an unsigned contract only from a verified `ReceiptPending` workflow.
    pub fn from_workflow(workflow: &DeletionWorkflowV2, completed_at_micros: u64) -> Result<Self> {
        if workflow.state() != DeletionWorkflowStateV2::ReceiptPending {
            return Err(SecureStoreError::StateConflict(
                "receipt requires a ReceiptPending workflow".to_owned(),
            ));
        }
        if completed_at_micros < workflow.updated_at_micros() {
            return Err(SecureStoreError::InvalidInput(
                "receipt completion predates workflow evidence".to_owned(),
            ));
        }
        let receipt = Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            deletion: workflow.handle().clone(),
            namespace: workflow.namespace().clone(),
            receipt_pending_workflow_root: workflow.root()?,
            closure_inventory_root: workflow.inventory().root()?,
            verification_commitment: workflow.verification_commitment().cloned().ok_or_else(
                || {
                    SecureStoreError::DeletionIncomplete(
                        "receipt workflow lacks verified-closure commitment".to_owned(),
                    )
                },
            )?,
            requested_at_micros: workflow.requested_at_micros(),
            completed_at_micros,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Returns the opaque deletion handle.
    #[must_use]
    pub fn deletion(&self) -> &DeletionHandleV2 {
        &self.deletion
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the bound `ReceiptPending` workflow root.
    #[must_use]
    pub fn workflow_root(&self) -> &StateRootV2 {
        &self.receipt_pending_workflow_root
    }

    /// Returns the exact authoritative closure root.
    #[must_use]
    pub fn closure_inventory_root(&self) -> &StateRootV2 {
        &self.closure_inventory_root
    }

    /// Returns the independent verification commitment.
    #[must_use]
    pub fn verification_commitment(&self) -> &StateRootV2 {
        &self.verification_commitment
    }

    /// Returns the request time.
    #[must_use]
    pub const fn requested_at_micros(&self) -> u64 {
        self.requested_at_micros
    }

    /// Returns the declared completion time.
    #[must_use]
    pub const fn completed_at_micros(&self) -> u64 {
        self.completed_at_micros
    }

    fn validate(&self) -> Result<()> {
        if self.format_version != SECURE_STORE_FORMAT_VERSION
            || self.completed_at_micros < self.requested_at_micros
        {
            return Err(SecureStoreError::Integrity(
                "unsigned deletion receipt version or time is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedDeletionReceiptWireV2 {
    format_version: u16,
    deletion: DeletionHandleV2,
    namespace: StateNamespaceV2,
    receipt_pending_workflow_root: StateRootV2,
    closure_inventory_root: StateRootV2,
    verification_commitment: StateRootV2,
    requested_at_micros: u64,
    completed_at_micros: u64,
}

impl TryFrom<UnsignedDeletionReceiptWireV2> for UnsignedDeletionReceiptV2 {
    type Error = SecureStoreError;

    fn try_from(value: UnsignedDeletionReceiptWireV2) -> Result<Self> {
        let receipt = Self {
            format_version: value.format_version,
            deletion: value.deletion,
            namespace: value.namespace,
            receipt_pending_workflow_root: value.receipt_pending_workflow_root,
            closure_inventory_root: value.closure_inventory_root,
            verification_commitment: value.verification_commitment,
            requested_at_micros: value.requested_at_micros,
            completed_at_micros: value.completed_at_micros,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

impl From<UnsignedDeletionReceiptV2> for UnsignedDeletionReceiptWireV2 {
    fn from(value: UnsignedDeletionReceiptV2) -> Self {
        Self {
            format_version: value.format_version,
            deletion: value.deletion,
            namespace: value.namespace,
            receipt_pending_workflow_root: value.receipt_pending_workflow_root,
            closure_inventory_root: value.closure_inventory_root,
            verification_commitment: value.verification_commitment,
            requested_at_micros: value.requested_at_micros,
            completed_at_micros: value.completed_at_micros,
        }
    }
}

/// Validated opaque signature bytes from an external signer.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ReceiptSignatureV2(Vec<u8>);

impl ReceiptSignatureV2 {
    /// Validates bounded non-empty signature bytes.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_SIGNATURE_BYTES {
            return Err(SecureStoreError::Integrity(
                "receipt signature size is invalid".to_owned(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns signature bytes for external verification.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ReceiptSignatureV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ReceiptSignatureV2")
            .field(&format_args!("{} bytes", self.0.len()))
            .finish()
    }
}

impl TryFrom<Vec<u8>> for ReceiptSignatureV2 {
    type Error = SecureStoreError;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::try_new(value)
    }
}

impl From<ReceiptSignatureV2> for Vec<u8> {
    fn from(value: ReceiptSignatureV2) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for ReceiptSignatureV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = crate::bounded::receipt_signature(deserializer)?;
        Self::try_new(bytes).map_err(serde::de::Error::custom)
    }
}

/// Externally signed v2 deletion receipt, including signing-key generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SignedDeletionReceiptV2 {
    unsigned: UnsignedDeletionReceiptV2,
    signing_key: ReceiptSigningKeyRefV2,
    signature: ReceiptSignatureV2,
}

impl SignedDeletionReceiptV2 {
    /// Decodes a bounded standalone receipt and verifies its exact namespace
    /// and external signature before returning it.
    pub fn from_json_bounded(
        bytes: &[u8],
        expected_namespace: &StateNamespaceV2,
        verifier: &dyn DeletionReceiptVerifierV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_SIGNED_DELETION_RECEIPT_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "signed deletion receipt exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: SignedDeletionReceiptWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        let receipt = Self::try_from(wire)?;
        receipt.verify(expected_namespace, verifier)?;
        Ok(receipt)
    }

    /// Signs an unsigned receipt through an external signer.
    pub fn sign(
        unsigned: UnsignedDeletionReceiptV2,
        signer: &dyn DeletionReceiptSignerV2,
    ) -> Result<Self> {
        unsigned.validate()?;
        let signing_key = signer.active_signing_key()?;
        let message = signature_message(&unsigned, &signing_key)?;
        let signature = ReceiptSignatureV2::try_new(signer.sign(&signing_key, &message)?)?;
        Ok(Self {
            unsigned,
            signing_key,
            signature,
        })
    }

    /// Returns the canonical unsigned contract.
    #[must_use]
    pub fn unsigned(&self) -> &UnsignedDeletionReceiptV2 {
        &self.unsigned
    }

    /// Returns the exact signing-key generation.
    #[must_use]
    pub fn signing_key(&self) -> &ReceiptSigningKeyRefV2 {
        &self.signing_key
    }

    /// Returns opaque signature bytes.
    #[must_use]
    pub fn signature(&self) -> &ReceiptSignatureV2 {
        &self.signature
    }

    /// Verifies the namespace and signature through an external verifier.
    pub fn verify(
        &self,
        expected_namespace: &StateNamespaceV2,
        verifier: &dyn DeletionReceiptVerifierV2,
    ) -> Result<()> {
        self.unsigned.validate()?;
        if self.unsigned.namespace() != expected_namespace {
            return Err(SecureStoreError::Integrity(
                "deletion receipt namespace does not match destination".to_owned(),
            ));
        }
        verifier.verify(
            &self.signing_key,
            &signature_message(&self.unsigned, &self.signing_key)?,
            self.signature.as_bytes(),
        )
    }

    /// Returns a commitment over the complete signed receipt.
    pub fn commitment(&self) -> Result<StateRootV2> {
        StateRootV2::commit("signed-deletion-receipt-v2", &canonical_json(self)?)
    }

    /// Verifies and atomically binds this receipt into its exact pending workflow.
    pub fn complete_workflow(
        &self,
        workflow: &mut DeletionWorkflowV2,
        expected_revision: u64,
        at_micros: u64,
        verifier: &dyn DeletionReceiptVerifierV2,
    ) -> Result<()> {
        self.verify(workflow.namespace(), verifier)?;
        if workflow.state() != DeletionWorkflowStateV2::ReceiptPending
            || self.unsigned.deletion() != workflow.handle()
            || self.unsigned.workflow_root() != &workflow.root()?
            || self.unsigned.closure_inventory_root() != &workflow.inventory().root()?
            || self.unsigned.verification_commitment()
                != workflow.verification_commitment().ok_or_else(|| {
                    SecureStoreError::DeletionIncomplete(
                        "workflow lacks verification commitment".to_owned(),
                    )
                })?
            || self.unsigned.completed_at_micros() != at_micros
        {
            return Err(SecureStoreError::Integrity(
                "signed receipt does not bind the exact pending workflow".to_owned(),
            ));
        }
        workflow.complete_with_receipt(expected_revision, at_micros, self.clone())
    }

    fn validate_shape(&self) -> Result<()> {
        self.unsigned.validate()?;
        ReceiptSigningKeyRefV2::new(
            self.signing_key.key_id().to_owned(),
            self.signing_key.generation(),
        )?;
        ReceiptSignatureV2::try_new(self.signature.as_bytes().to_vec())?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedDeletionReceiptWireV2 {
    unsigned: UnsignedDeletionReceiptV2,
    signing_key: ReceiptSigningKeyRefV2,
    signature: ReceiptSignatureV2,
}

impl TryFrom<SignedDeletionReceiptWireV2> for SignedDeletionReceiptV2 {
    type Error = SecureStoreError;

    fn try_from(value: SignedDeletionReceiptWireV2) -> Result<Self> {
        let receipt = Self {
            unsigned: value.unsigned,
            signing_key: value.signing_key,
            signature: value.signature,
        };
        receipt.validate_shape()?;
        Ok(receipt)
    }
}

impl From<SignedDeletionReceiptV2> for SignedDeletionReceiptWireV2 {
    fn from(value: SignedDeletionReceiptV2) -> Self {
        Self {
            unsigned: value.unsigned,
            signing_key: value.signing_key,
            signature: value.signature,
        }
    }
}

fn signature_message(
    unsigned: &UnsignedDeletionReceiptV2,
    signing_key: &ReceiptSigningKeyRefV2,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct SignaturePayload<'a> {
        signing_key: &'a ReceiptSigningKeyRefV2,
        unsigned: &'a UnsignedDeletionReceiptV2,
    }
    let canonical = canonical_json(&SignaturePayload {
        signing_key,
        unsigned,
    })?;
    let mut message = Vec::with_capacity(
        RECEIPT_SIGNATURE_DOMAIN_V2
            .len()
            .saturating_add(8)
            .saturating_add(canonical.len()),
    );
    message.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN_V2);
    message.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    message.extend_from_slice(&canonical);
    Ok(message)
}
