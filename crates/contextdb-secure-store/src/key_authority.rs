use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    ContentHandleV2, ErasureDomainV2, EvidenceHandleV2, KeyHandleV2, Result, SecureStoreError,
    StateRootV2, canonical_json,
};

/// Per-object and per-erasure-domain scope of a random data-encryption key.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "DekScopeWireV2", into = "DekScopeWireV2")]
pub struct DekScopeV2 {
    content_handle: ContentHandleV2,
    erasure_domain: ErasureDomainV2,
    security_context: ContentSecurityContextV2,
}

impl DekScopeV2 {
    /// Creates an exact, non-shareable DEK scope.
    pub fn new(
        content_handle: ContentHandleV2,
        erasure_domain: ErasureDomainV2,
        security_context: ContentSecurityContextV2,
    ) -> Result<Self> {
        security_context.validate()?;
        Ok(Self {
            content_handle,
            erasure_domain,
            security_context,
        })
    }

    /// Returns the object identity bound to the DEK.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns the independent erasure domain bound to the DEK.
    #[must_use]
    pub fn erasure_domain(&self) -> &ErasureDomainV2 {
        &self.erasure_domain
    }

    /// Returns the exact database, workspace, owner, record, and revision binding.
    #[must_use]
    pub fn security_context(&self) -> &ContentSecurityContextV2 {
        &self.security_context
    }
}

impl fmt::Debug for DekScopeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DekScopeV2")
            .field("content_handle", &"[OPAQUE]")
            .field("erasure_domain", &"[OPAQUE]")
            .field("security_context", &self.security_context)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DekScopeWireV2 {
    content_handle: ContentHandleV2,
    erasure_domain: ErasureDomainV2,
    security_context: ContentSecurityContextV2,
}

impl TryFrom<DekScopeWireV2> for DekScopeV2 {
    type Error = SecureStoreError;

    fn try_from(value: DekScopeWireV2) -> Result<Self> {
        Self::new(
            value.content_handle,
            value.erasure_domain,
            value.security_context,
        )
    }
}

impl From<DekScopeV2> for DekScopeWireV2 {
    fn from(value: DekScopeV2) -> Self {
        Self {
            content_handle: value.content_handle,
            erasure_domain: value.erasure_domain,
            security_context: value.security_context,
        }
    }
}

/// Exact authorization and anti-relocation context bound into a DEK and AEAD.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    try_from = "ContentSecurityContextWireV2",
    into = "ContentSecurityContextWireV2"
)]
pub struct ContentSecurityContextV2 {
    database_id: String,
    workspace_id: String,
    record_kind: String,
    logical_owner: String,
    policy_revision: StateRootV2,
    key_revision: u64,
}

impl ContentSecurityContextV2 {
    /// Creates a validated exact content-security binding.
    pub fn new(
        database_id: impl Into<String>,
        workspace_id: impl Into<String>,
        record_kind: impl Into<String>,
        logical_owner: impl Into<String>,
        policy_revision: StateRootV2,
        key_revision: u64,
    ) -> Result<Self> {
        let context = Self {
            database_id: database_id.into(),
            workspace_id: workspace_id.into(),
            record_kind: record_kind.into(),
            logical_owner: logical_owner.into(),
            policy_revision,
            key_revision,
        };
        context.validate()?;
        Ok(context)
    }

    /// Returns the database namespace.
    #[must_use]
    pub fn database_id(&self) -> &str {
        &self.database_id
    }

    /// Returns the workspace or tenant namespace.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Returns the stable logical record kind or protected-field role.
    #[must_use]
    pub fn record_kind(&self) -> &str {
        &self.record_kind
    }

    /// Returns the logical owner identity.
    #[must_use]
    pub fn logical_owner(&self) -> &str {
        &self.logical_owner
    }

    /// Returns the exact policy revision commitment.
    #[must_use]
    pub fn policy_revision(&self) -> &StateRootV2 {
        &self.policy_revision
    }

    /// Returns the non-zero key-policy revision.
    #[must_use]
    pub const fn key_revision(&self) -> u64 {
        self.key_revision
    }

    pub(crate) fn validate(&self) -> Result<()> {
        crate::validate_label(&self.database_id, "content database ID")?;
        crate::validate_label(&self.workspace_id, "content workspace ID")?;
        crate::validate_label(&self.record_kind, "content record kind")?;
        crate::validate_label(&self.logical_owner, "content logical owner")?;
        if self.key_revision == 0 {
            return Err(SecureStoreError::InvalidInput(
                "content key revision must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ContentSecurityContextV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContentSecurityContextV2")
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("record_kind", &self.record_kind)
            .field("logical_owner", &"[REDACTED]")
            .field("policy_revision", &"[COMMITMENT]")
            .field("key_revision", &self.key_revision)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentSecurityContextWireV2 {
    database_id: String,
    workspace_id: String,
    record_kind: String,
    logical_owner: String,
    policy_revision: StateRootV2,
    key_revision: u64,
}

impl TryFrom<ContentSecurityContextWireV2> for ContentSecurityContextV2 {
    type Error = SecureStoreError;

    fn try_from(value: ContentSecurityContextWireV2) -> Result<Self> {
        Self::new(
            value.database_id,
            value.workspace_id,
            value.record_kind,
            value.logical_owner,
            value.policy_revision,
            value.key_revision,
        )
    }
}

impl From<ContentSecurityContextV2> for ContentSecurityContextWireV2 {
    fn from(value: ContentSecurityContextV2) -> Self {
        Self {
            database_id: value.database_id,
            workspace_id: value.workspace_id,
            record_kind: value.record_kind,
            logical_owner: value.logical_owner,
            policy_revision: value.policy_revision,
            key_revision: value.key_revision,
        }
    }
}

/// Monotonic lifecycle of an authority-managed DEK.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLifecycleV2 {
    /// Key material is usable for authenticated encryption and decryption.
    Active,
    /// Destruction has been requested; content access is already denied.
    DestroyPending,
    /// Authority reports that key material is irreversibly destroyed.
    Destroyed,
}

impl KeyLifecycleV2 {
    const fn required_generation(self) -> u64 {
        match self {
            Self::Active => 1,
            Self::DestroyPending => 2,
            Self::Destroyed => 3,
        }
    }
}

/// Non-secret, serializable catalog descriptor for one DEK.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "KeyDescriptorWireV2", into = "KeyDescriptorWireV2")]
pub struct KeyDescriptorV2 {
    key_handle: KeyHandleV2,
    scope: DekScopeV2,
    generation: u64,
    lifecycle: KeyLifecycleV2,
    destruction_evidence: Option<EvidenceHandleV2>,
}

impl KeyDescriptorV2 {
    /// Returns the opaque key-management reference.
    #[must_use]
    pub fn key_handle(&self) -> &KeyHandleV2 {
        &self.key_handle
    }

    /// Returns the exact per-object erasure scope.
    #[must_use]
    pub fn scope(&self) -> &DekScopeV2 {
        &self.scope
    }

    /// Returns the monotonic catalog generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the fail-closed key lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> KeyLifecycleV2 {
        self.lifecycle
    }

    /// Returns opaque authority evidence after confirmed destruction.
    #[must_use]
    pub fn destruction_evidence(&self) -> Option<&EvidenceHandleV2> {
        self.destruction_evidence.as_ref()
    }

    /// Creates the generation-one descriptor returned by a key authority after
    /// it has independently generated and retained a random DEK.
    ///
    /// This constructs non-secret catalog metadata only. Possessing a
    /// descriptor never grants access to key bytes.
    pub fn authority_active(key_handle: KeyHandleV2, scope: DekScopeV2) -> Result<Self> {
        scope.security_context.validate()?;
        Ok(Self {
            key_handle,
            scope,
            generation: 1,
            lifecycle: KeyLifecycleV2::Active,
            destruction_evidence: None,
        })
    }

    /// Derives exact generation-two metadata after an authority durably accepts
    /// an irreversible destruction request.
    pub fn authority_destroy_pending(&self) -> Result<Self> {
        self.validate()?;
        if self.lifecycle != KeyLifecycleV2::Active {
            return Err(SecureStoreError::StateConflict(
                "only an active key can enter destroy-pending".to_owned(),
            ));
        }
        Ok(Self {
            key_handle: self.key_handle.clone(),
            scope: self.scope.clone(),
            generation: 2,
            lifecycle: KeyLifecycleV2::DestroyPending,
            destruction_evidence: None,
        })
    }

    /// Derives exact generation-three metadata after an authority has discarded
    /// the DEK and produced opaque destruction evidence.
    pub fn authority_destroyed(&self, evidence: EvidenceHandleV2) -> Result<Self> {
        self.validate()?;
        if self.lifecycle != KeyLifecycleV2::DestroyPending {
            return Err(SecureStoreError::StateConflict(
                "only a destroy-pending key can be confirmed destroyed".to_owned(),
            ));
        }
        Ok(Self {
            key_handle: self.key_handle.clone(),
            scope: self.scope.clone(),
            generation: 3,
            lifecycle: KeyLifecycleV2::Destroyed,
            destruction_evidence: Some(evidence),
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.generation != self.lifecycle.required_generation() {
            return Err(SecureStoreError::Integrity(
                "key lifecycle and generation disagree".to_owned(),
            ));
        }
        if (self.lifecycle == KeyLifecycleV2::Destroyed) != self.destruction_evidence.is_some() {
            return Err(SecureStoreError::Integrity(
                "key destruction evidence disagrees with lifecycle".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for KeyDescriptorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyDescriptorV2")
            .field("key_handle", &"[OPAQUE]")
            .field("scope", &self.scope)
            .field("generation", &self.generation)
            .field("lifecycle", &self.lifecycle)
            .field(
                "has_destruction_evidence",
                &self.destruction_evidence.is_some(),
            )
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDescriptorWireV2 {
    key_handle: KeyHandleV2,
    scope: DekScopeV2,
    generation: u64,
    lifecycle: KeyLifecycleV2,
    destruction_evidence: Option<EvidenceHandleV2>,
}

impl TryFrom<KeyDescriptorWireV2> for KeyDescriptorV2 {
    type Error = SecureStoreError;

    fn try_from(value: KeyDescriptorWireV2) -> Result<Self> {
        let descriptor = Self {
            key_handle: value.key_handle,
            scope: value.scope,
            generation: value.generation,
            lifecycle: value.lifecycle,
            destruction_evidence: value.destruction_evidence,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

impl From<KeyDescriptorV2> for KeyDescriptorWireV2 {
    fn from(value: KeyDescriptorV2) -> Self {
        Self {
            key_handle: value.key_handle,
            scope: value.scope,
            generation: value.generation,
            lifecycle: value.lifecycle,
            destruction_evidence: value.destruction_evidence,
        }
    }
}

/// Authenticated ciphertext payload returned by a key authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SealedPayloadWireV2", into = "SealedPayloadWireV2")]
pub struct SealedPayloadV2 {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl SealedPayloadV2 {
    /// Constructs a validated XChaCha-style sealed payload.
    pub fn try_new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<Self> {
        let payload = Self { nonce, ciphertext };
        payload.validate()?;
        Ok(payload)
    }

    /// Returns the public encryption nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns authenticated ciphertext including its authentication tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn validate(&self) -> Result<()> {
        if self.nonce.len() != 24 || self.ciphertext.len() <= 16 {
            return Err(SecureStoreError::Integrity(
                "sealed payload shape is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for SealedPayloadV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedPayloadV2")
            .field("nonce_bytes", &self.nonce.len())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedPayloadWireV2 {
    #[serde(deserialize_with = "crate::bounded::nonce_24")]
    nonce: Vec<u8>,
    #[serde(deserialize_with = "crate::bounded::encrypted_ciphertext")]
    ciphertext: Vec<u8>,
}

impl TryFrom<SealedPayloadWireV2> for SealedPayloadV2 {
    type Error = SecureStoreError;

    fn try_from(value: SealedPayloadWireV2) -> Result<Self> {
        Self::try_new(value.nonce, value.ciphertext)
    }
}

impl From<SealedPayloadV2> for SealedPayloadWireV2 {
    fn from(value: SealedPayloadV2) -> Self {
        Self {
            nonce: value.nonce,
            ciphertext: value.ciphertext,
        }
    }
}

/// Backend-neutral authority for random DEKs and monotonic key destruction.
///
/// Implementations MUST create an independent CSPRNG-generated key for every
/// call to [`KeyAuthorityV2::create_random_dek`]. Deriving a DEK from content,
/// a content digest, handle, tenant secret, or erasure-domain identity is
/// forbidden. Key bytes never cross this interface.
pub trait KeyAuthorityV2 {
    /// Creates a new random DEK bound to exactly one object and erasure domain.
    fn create_random_dek(&mut self, scope: DekScopeV2) -> Result<KeyDescriptorV2>;

    /// Returns the current non-secret descriptor for an opaque key handle.
    fn descriptor(&self, key_handle: &KeyHandleV2) -> Result<KeyDescriptorV2>;

    /// Authenticated-encrypts bounded content without releasing key bytes.
    fn seal(
        &self,
        key: &KeyDescriptorV2,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedPayloadV2>;

    /// Authenticated-decrypts content and returns zeroizing plaintext memory.
    fn open(
        &self,
        key: &KeyDescriptorV2,
        payload: &SealedPayloadV2,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// Atomically advances `Active` to `DestroyPending` at the expected generation.
    fn request_destroy(
        &mut self,
        key_handle: &KeyHandleV2,
        expected_generation: u64,
    ) -> Result<KeyDescriptorV2>;

    /// Atomically advances `DestroyPending` to `Destroyed` and discards key material.
    fn confirm_destroy(
        &mut self,
        key_handle: &KeyHandleV2,
        expected_generation: u64,
        authority_evidence: EvidenceHandleV2,
    ) -> Result<KeyDescriptorV2>;
}

/// Content-free, serializable snapshot of the authority key catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KeyCatalogSnapshotV2(Vec<KeyDescriptorV2>);

impl KeyCatalogSnapshotV2 {
    /// Builds a canonical catalog, rejecting duplicate opaque key handles.
    pub fn try_new(mut descriptors: Vec<KeyDescriptorV2>) -> Result<Self> {
        for descriptor in &descriptors {
            descriptor.validate()?;
        }
        descriptors.sort_by(|left, right| left.key_handle.cmp(&right.key_handle));
        if descriptors
            .windows(2)
            .any(|pair| pair[0].key_handle == pair[1].key_handle)
        {
            return Err(SecureStoreError::Integrity(
                "key catalog contains a duplicate key handle".to_owned(),
            ));
        }
        let mut scopes = std::collections::BTreeSet::new();
        if descriptors
            .iter()
            .any(|descriptor| !scopes.insert(descriptor.scope.clone()))
        {
            return Err(SecureStoreError::Integrity(
                "key catalog contains more than one DEK for an exact object scope".to_owned(),
            ));
        }
        Ok(Self(descriptors))
    }

    /// Returns canonical non-secret key descriptors.
    #[must_use]
    pub fn descriptors(&self) -> &[KeyDescriptorV2] {
        &self.0
    }

    /// Computes the key-catalog state root.
    pub fn root(&self) -> Result<StateRootV2> {
        StateRootV2::commit("key-catalog-v2", &canonical_json(self)?)
    }
}

/// Validates the only permitted lifecycle transition and exact generation bump.
pub fn validate_key_transition(previous: &KeyDescriptorV2, next: &KeyDescriptorV2) -> Result<()> {
    previous.validate()?;
    next.validate()?;
    if previous.key_handle != next.key_handle || previous.scope != next.scope {
        return Err(SecureStoreError::Integrity(
            "key identity or scope changed".to_owned(),
        ));
    }
    let expected = match previous.lifecycle {
        KeyLifecycleV2::Active => KeyLifecycleV2::DestroyPending,
        KeyLifecycleV2::DestroyPending => KeyLifecycleV2::Destroyed,
        KeyLifecycleV2::Destroyed => {
            return Err(SecureStoreError::StateConflict(
                "destroyed key cannot transition".to_owned(),
            ));
        }
    };
    if next.lifecycle != expected || next.generation != previous.generation + 1 {
        return Err(SecureStoreError::StateConflict(
            "key lifecycle transition is stale or non-monotonic".to_owned(),
        ));
    }
    Ok(())
}
