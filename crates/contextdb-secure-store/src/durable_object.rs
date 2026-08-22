use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    AnchoredCompositeHeadV2, AuthorityEvidenceVerifierV2, AuthorityProvenanceV2, AuthorityRoleV2,
    CompositeHeadCasOutcomeV2, CompositeHeadCasRequestV2, ContentHandleV2,
    ContentSecurityContextV2, DekScopeV2, DeletionClosureClassV2, EncryptedContentV2,
    ErasureDomainV2, HeadAnchorV2, HeadMacAuthorityV2, KeyDescriptorV2, KeyLifecycleV2,
    OperationRequestIdV2, ProductionKeyCreateRequestV2, Result, SECURE_STORE_FORMAT_VERSION,
    SecureStoreError, SourceMaterialHandleV2, StateNamespaceV2, StateRootV2, canonical_json,
    require_role,
};

/// Maximum bytes accepted when recovering one durable object creation intent.
pub const MAX_DURABLE_OBJECT_INTENT_JSON_BYTES_V2: usize = 128 * 1024;
/// Maximum bytes accepted when recovering one durable object catalog entry.
pub const MAX_DURABLE_OBJECT_ENTRY_JSON_BYTES_V2: usize = 8 * 1024 * 1024;
/// Maximum summary items returned by one durable object catalog page.
pub const MAX_DURABLE_OBJECT_CATALOG_PAGE_ITEMS_V2: usize = 4_096;
/// Maximum canonical bytes returned by one durable object catalog page.
pub const MAX_DURABLE_OBJECT_CATALOG_PAGE_BYTES_V2: usize = 4 * 1024 * 1024;

const MANAGED_COPY_CLASSES_V2: [DeletionClosureClassV2; 3] = [
    DeletionClosureClassV2::ProviderCopy,
    DeletionClosureClassV2::Export,
    DeletionClosureClassV2::Backup,
];

/// Durable, caller-preallocated identity and idempotency intent for one object.
///
/// This DTO contains no plaintext. A host persists it before asking a KMS to
/// create a DEK, which makes a retry after `KMS created -> process crashed`
/// address the same object, scope, and authority intent.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "DurableObjectCreateIntentWireV2",
    into = "DurableObjectCreateIntentWireV2"
)]
pub struct DurableObjectCreateIntentV2 {
    format_version: u16,
    reservation_request_id: OperationRequestIdV2,
    key_create_request_id: OperationRequestIdV2,
    object_create_request_id: OperationRequestIdV2,
    head_publish_request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    source_material_handle: SourceMaterialHandleV2,
    managed_copy_commitments: ManagedCopyCatalogCommitmentsV2,
    content_handle: ContentHandleV2,
    erasure_domain: ErasureDomainV2,
    security_context: ContentSecurityContextV2,
}

impl DurableObjectCreateIntentV2 {
    /// Generates all opaque identities before any external authority call.
    pub fn preallocate(
        namespace: StateNamespaceV2,
        security_context: ContentSecurityContextV2,
        managed_copy_commitments: ManagedCopyCatalogCommitmentsV2,
    ) -> Result<Self> {
        Self::new_preallocated(
            OperationRequestIdV2::generate()?,
            OperationRequestIdV2::generate()?,
            OperationRequestIdV2::generate()?,
            OperationRequestIdV2::generate()?,
            namespace,
            SourceMaterialHandleV2::generate()?,
            managed_copy_commitments,
            ContentHandleV2::generate()?,
            ErasureDomainV2::generate()?,
            security_context,
        )
    }

    /// Validates caller-preallocated handles and exact operation identities.
    #[allow(
        clippy::too_many_arguments,
        reason = "every independently persisted boundary has an explicit identity"
    )]
    pub fn new_preallocated(
        reservation_request_id: OperationRequestIdV2,
        key_create_request_id: OperationRequestIdV2,
        object_create_request_id: OperationRequestIdV2,
        head_publish_request_id: OperationRequestIdV2,
        namespace: StateNamespaceV2,
        source_material_handle: SourceMaterialHandleV2,
        managed_copy_commitments: ManagedCopyCatalogCommitmentsV2,
        content_handle: ContentHandleV2,
        erasure_domain: ErasureDomainV2,
        security_context: ContentSecurityContextV2,
    ) -> Result<Self> {
        if security_context.database_id() != namespace.database_id()
            || security_context.workspace_id() != namespace.workspace_id()
        {
            return Err(SecureStoreError::Integrity(
                "durable object security context is outside its namespace".to_owned(),
            ));
        }
        let request_ids = [
            reservation_request_id.clone(),
            key_create_request_id.clone(),
            object_create_request_id.clone(),
            head_publish_request_id.clone(),
        ];
        if request_ids.iter().collect::<BTreeSet<_>>().len() != request_ids.len() {
            return Err(SecureStoreError::InvalidInput(
                "durable object boundary request IDs must be distinct".to_owned(),
            ));
        }
        DekScopeV2::new(
            content_handle.clone(),
            erasure_domain.clone(),
            security_context.clone(),
        )?;
        Ok(Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            reservation_request_id,
            key_create_request_id,
            object_create_request_id,
            head_publish_request_id,
            namespace,
            source_material_handle,
            managed_copy_commitments,
            content_handle,
            erasure_domain,
            security_context,
        })
    }

    /// Recovers one bounded persisted preallocation intent.
    pub fn from_json_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DURABLE_OBJECT_INTENT_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "durable object intent exceeds decode byte limit".to_owned(),
            ));
        }
        serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)
    }

    /// Returns the durable reservation idempotency identity.
    #[must_use]
    pub fn reservation_request_id(&self) -> &OperationRequestIdV2 {
        &self.reservation_request_id
    }

    /// Returns the external KMS create-or-get identity.
    #[must_use]
    pub fn key_create_request_id(&self) -> &OperationRequestIdV2 {
        &self.key_create_request_id
    }

    /// Returns the atomic encrypted-object/catalog create-or-get identity.
    #[must_use]
    pub fn object_create_request_id(&self) -> &OperationRequestIdV2 {
        &self.object_create_request_id
    }

    /// Returns the exact composite-head publication identity.
    #[must_use]
    pub fn head_publish_request_id(&self) -> &OperationRequestIdV2 {
        &self.head_publish_request_id
    }

    /// Returns the anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the opaque host-owned recovery source retained until publication.
    #[must_use]
    pub fn source_material_handle(&self) -> &SourceMaterialHandleV2 {
        &self.source_material_handle
    }

    /// Returns exact provider, export, and backup inventory commitments.
    #[must_use]
    pub fn managed_copy_commitments(&self) -> &ManagedCopyCatalogCommitmentsV2 {
        &self.managed_copy_commitments
    }

    /// Returns the preallocated encrypted-object handle.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns the preallocated independent erasure domain.
    #[must_use]
    pub fn erasure_domain(&self) -> &ErasureDomainV2 {
        &self.erasure_domain
    }

    /// Returns the exact content-security context.
    #[must_use]
    pub fn security_context(&self) -> &ContentSecurityContextV2 {
        &self.security_context
    }

    /// Reconstructs the exact idempotent P3 KMS request after a crash.
    pub fn key_create_request(&self) -> Result<ProductionKeyCreateRequestV2> {
        ProductionKeyCreateRequestV2::new(
            self.key_create_request_id.clone(),
            self.namespace.clone(),
            DekScopeV2::new(
                self.content_handle.clone(),
                self.erasure_domain.clone(),
                self.security_context.clone(),
            )?,
        )
    }

    /// Returns the canonical durable creation-intent commitment.
    pub fn commitment(&self) -> Result<StateRootV2> {
        StateRootV2::commit("durable-object-create-intent-v2", &canonical_json(self)?)
    }
}

impl fmt::Debug for DurableObjectCreateIntentV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableObjectCreateIntentV2")
            .field("request_ids", &"[OPAQUE; 4]")
            .field("namespace", &self.namespace)
            .field("source_material_handle", &"[OPAQUE]")
            .field("managed_copy_commitment_count", &3)
            .field("content_handle", &"[OPAQUE]")
            .field("erasure_domain", &"[OPAQUE]")
            .field("security_context", &self.security_context)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableObjectCreateIntentWireV2 {
    format_version: u16,
    reservation_request_id: OperationRequestIdV2,
    key_create_request_id: OperationRequestIdV2,
    object_create_request_id: OperationRequestIdV2,
    head_publish_request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    source_material_handle: SourceMaterialHandleV2,
    managed_copy_commitments: ManagedCopyCatalogCommitmentsV2,
    content_handle: ContentHandleV2,
    erasure_domain: ErasureDomainV2,
    security_context: ContentSecurityContextV2,
}

impl TryFrom<DurableObjectCreateIntentWireV2> for DurableObjectCreateIntentV2 {
    type Error = SecureStoreError;

    fn try_from(value: DurableObjectCreateIntentWireV2) -> Result<Self> {
        if value.format_version != SECURE_STORE_FORMAT_VERSION {
            return Err(SecureStoreError::Integrity(
                "durable object intent format version is invalid".to_owned(),
            ));
        }
        Self::new_preallocated(
            value.reservation_request_id,
            value.key_create_request_id,
            value.object_create_request_id,
            value.head_publish_request_id,
            value.namespace,
            value.source_material_handle,
            value.managed_copy_commitments,
            value.content_handle,
            value.erasure_domain,
            value.security_context,
        )
    }
}

impl From<DurableObjectCreateIntentV2> for DurableObjectCreateIntentWireV2 {
    fn from(value: DurableObjectCreateIntentV2) -> Self {
        Self {
            format_version: value.format_version,
            reservation_request_id: value.reservation_request_id,
            key_create_request_id: value.key_create_request_id,
            object_create_request_id: value.object_create_request_id,
            head_publish_request_id: value.head_publish_request_id,
            namespace: value.namespace,
            source_material_handle: value.source_material_handle,
            managed_copy_commitments: value.managed_copy_commitments,
            content_handle: value.content_handle,
            erasure_domain: value.erasure_domain,
            security_context: value.security_context,
        }
    }
}

/// Exact generation/root commitment for one managed-copy inventory class.
///
/// This is inventory metadata, not provider deletion evidence or an erasure
/// receipt.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    try_from = "ManagedCopyCatalogCommitmentWireV2",
    into = "ManagedCopyCatalogCommitmentWireV2"
)]
pub struct ManagedCopyCatalogCommitmentV2 {
    class: DeletionClosureClassV2,
    inventory_generation: u64,
    inventory_root: StateRootV2,
}

impl ManagedCopyCatalogCommitmentV2 {
    /// Creates a non-zero generation commitment for a managed-copy class.
    pub fn new(
        class: DeletionClosureClassV2,
        inventory_generation: u64,
        inventory_root: StateRootV2,
    ) -> Result<Self> {
        if !class.is_managed_copy() || inventory_generation == 0 {
            return Err(SecureStoreError::InvalidInput(
                "managed-copy catalog class or generation is invalid".to_owned(),
            ));
        }
        Ok(Self {
            class,
            inventory_generation,
            inventory_root,
        })
    }

    /// Returns the provider/export/backup class.
    #[must_use]
    pub const fn class(&self) -> DeletionClosureClassV2 {
        self.class
    }

    /// Returns the exact managed inventory generation.
    #[must_use]
    pub const fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    /// Returns the exact managed inventory commitment.
    #[must_use]
    pub fn inventory_root(&self) -> &StateRootV2 {
        &self.inventory_root
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedCopyCatalogCommitmentWireV2 {
    class: DeletionClosureClassV2,
    inventory_generation: u64,
    inventory_root: StateRootV2,
}

impl TryFrom<ManagedCopyCatalogCommitmentWireV2> for ManagedCopyCatalogCommitmentV2 {
    type Error = SecureStoreError;

    fn try_from(value: ManagedCopyCatalogCommitmentWireV2) -> Result<Self> {
        Self::new(
            value.class,
            value.inventory_generation,
            value.inventory_root,
        )
    }
}

impl From<ManagedCopyCatalogCommitmentV2> for ManagedCopyCatalogCommitmentWireV2 {
    fn from(value: ManagedCopyCatalogCommitmentV2) -> Self {
        Self {
            class: value.class,
            inventory_generation: value.inventory_generation,
            inventory_root: value.inventory_root,
        }
    }
}

/// Canonical exact commitments for provider, export, and backup inventories.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "[ManagedCopyCatalogCommitmentV2; 3]",
    into = "[ManagedCopyCatalogCommitmentV2; 3]"
)]
pub struct ManagedCopyCatalogCommitmentsV2([ManagedCopyCatalogCommitmentV2; 3]);

impl ManagedCopyCatalogCommitmentsV2 {
    /// Requires all three managed-copy classes exactly once.
    pub fn try_new(mut commitments: Vec<ManagedCopyCatalogCommitmentV2>) -> Result<Self> {
        let commitments: &mut [ManagedCopyCatalogCommitmentV2; 3] =
            commitments.as_mut_slice().try_into().map_err(|_| {
                SecureStoreError::DeletionIncomplete(
                    "managed-copy catalog requires exactly three commitments".to_owned(),
                )
            })?;
        commitments.sort_by_key(ManagedCopyCatalogCommitmentV2::class);
        let classes = commitments
            .iter()
            .map(ManagedCopyCatalogCommitmentV2::class)
            .collect::<Vec<_>>();
        if classes.as_slice() != MANAGED_COPY_CLASSES_V2 {
            return Err(SecureStoreError::DeletionIncomplete(
                "managed-copy catalog requires provider, export, and backup commitments".to_owned(),
            ));
        }
        Ok(Self(commitments.clone()))
    }

    /// Returns the exact canonical three-class commitments.
    #[must_use]
    pub fn commitments(&self) -> &[ManagedCopyCatalogCommitmentV2] {
        &self.0
    }

    /// Returns a commitment to managed-copy inventory metadata only.
    pub fn root(&self) -> Result<StateRootV2> {
        StateRootV2::commit(
            "managed-copy-catalog-commitments-v2",
            &canonical_json(self)?,
        )
    }
}

impl TryFrom<[ManagedCopyCatalogCommitmentV2; 3]> for ManagedCopyCatalogCommitmentsV2 {
    type Error = SecureStoreError;

    fn try_from(value: [ManagedCopyCatalogCommitmentV2; 3]) -> Result<Self> {
        Self::try_new(Vec::from(value))
    }
}

impl From<ManagedCopyCatalogCommitmentsV2> for [ManagedCopyCatalogCommitmentV2; 3] {
    fn from(value: ManagedCopyCatalogCommitmentsV2) -> Self {
        value.0
    }
}

/// Ciphertext-only catalog descriptor stored atomically beside one object.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "StoredEncryptedObjectDescriptorWireV2",
    into = "StoredEncryptedObjectDescriptorWireV2"
)]
pub struct StoredEncryptedObjectDescriptorV2 {
    content_handle: ContentHandleV2,
    key: KeyDescriptorV2,
    ciphertext_bytes: u64,
    encrypted_object_commitment: StateRootV2,
    managed_copy_commitments: ManagedCopyCatalogCommitmentsV2,
}

impl StoredEncryptedObjectDescriptorV2 {
    fn from_encrypted(
        intent: &DurableObjectCreateIntentV2,
        encrypted_object: &EncryptedContentV2,
        managed_copy_commitments: ManagedCopyCatalogCommitmentsV2,
    ) -> Result<Self> {
        let key_request = intent.key_create_request()?;
        key_request.validate_response(encrypted_object.header().key())?;
        if encrypted_object.header().content_handle() != intent.content_handle() {
            return Err(SecureStoreError::Integrity(
                "encrypted object handle differs from the durable preallocation".to_owned(),
            ));
        }
        let ciphertext_bytes = encrypted_object.sealed_payload().ciphertext().len() as u64;
        let descriptor = Self {
            content_handle: intent.content_handle.clone(),
            key: encrypted_object.header().key().clone(),
            ciphertext_bytes,
            encrypted_object_commitment: encrypted_object_commitment(encrypted_object)?,
            managed_copy_commitments,
        };
        descriptor.validate_shape()?;
        Ok(descriptor)
    }

    /// Returns the preallocated object handle.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns the exact active key descriptor committed beside the object.
    #[must_use]
    pub fn key(&self) -> &KeyDescriptorV2 {
        &self.key
    }

    /// Returns authenticated ciphertext bytes, excluding the public nonce.
    #[must_use]
    pub const fn ciphertext_bytes(&self) -> u64 {
        self.ciphertext_bytes
    }

    /// Returns a commitment to the complete ciphertext envelope.
    #[must_use]
    pub fn encrypted_object_commitment(&self) -> &StateRootV2 {
        &self.encrypted_object_commitment
    }

    /// Returns exact provider/export/backup inventory commitments.
    #[must_use]
    pub fn managed_copy_commitments(&self) -> &ManagedCopyCatalogCommitmentsV2 {
        &self.managed_copy_commitments
    }

    /// Revalidates a loaded ciphertext body against this catalog descriptor.
    pub fn validate_encrypted_object(&self, encrypted_object: &EncryptedContentV2) -> Result<()> {
        if encrypted_object.header().content_handle() != &self.content_handle
            || encrypted_object.header().key() != &self.key
            || encrypted_object.sealed_payload().ciphertext().len() as u64 != self.ciphertext_bytes
            || encrypted_object_commitment(encrypted_object)? != self.encrypted_object_commitment
        {
            return Err(SecureStoreError::Integrity(
                "loaded encrypted object does not match its durable catalog descriptor".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_against_intent(&self, intent: &DurableObjectCreateIntentV2) -> Result<()> {
        self.validate_shape()?;
        intent.key_create_request()?.validate_response(&self.key)?;
        if &self.content_handle != intent.content_handle() {
            return Err(SecureStoreError::Integrity(
                "stored object descriptor differs from its durable intent".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        self.key.validate()?;
        if self.key.lifecycle() != KeyLifecycleV2::Active
            || self.key.generation() != 1
            || self.key.scope().content_handle() != &self.content_handle
            || self.ciphertext_bytes <= 16
            || self.ciphertext_bytes > crate::MAX_ENCRYPTED_CONTENT_BYTES as u64 + 16
        {
            return Err(SecureStoreError::Integrity(
                "stored encrypted-object descriptor is invalid".to_owned(),
            ));
        }
        ManagedCopyCatalogCommitmentsV2::try_new(
            self.managed_copy_commitments.commitments().to_vec(),
        )?;
        Ok(())
    }
}

impl fmt::Debug for StoredEncryptedObjectDescriptorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredEncryptedObjectDescriptorV2")
            .field("content_handle", &"[OPAQUE]")
            .field("key", &self.key)
            .field("ciphertext_bytes", &self.ciphertext_bytes)
            .field("encrypted_object_commitment", &"[COMMITMENT]")
            .field("managed_copy_commitment_count", &3)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEncryptedObjectDescriptorWireV2 {
    content_handle: ContentHandleV2,
    key: KeyDescriptorV2,
    ciphertext_bytes: u64,
    encrypted_object_commitment: StateRootV2,
    managed_copy_commitments: ManagedCopyCatalogCommitmentsV2,
}

impl TryFrom<StoredEncryptedObjectDescriptorWireV2> for StoredEncryptedObjectDescriptorV2 {
    type Error = SecureStoreError;

    fn try_from(value: StoredEncryptedObjectDescriptorWireV2) -> Result<Self> {
        let descriptor = Self {
            content_handle: value.content_handle,
            key: value.key,
            ciphertext_bytes: value.ciphertext_bytes,
            encrypted_object_commitment: value.encrypted_object_commitment,
            managed_copy_commitments: value.managed_copy_commitments,
        };
        descriptor.validate_shape()?;
        Ok(descriptor)
    }
}

impl From<StoredEncryptedObjectDescriptorV2> for StoredEncryptedObjectDescriptorWireV2 {
    fn from(value: StoredEncryptedObjectDescriptorV2) -> Self {
        Self {
            content_handle: value.content_handle,
            key: value.key,
            ciphertext_bytes: value.ciphertext_bytes,
            encrypted_object_commitment: value.encrypted_object_commitment,
            managed_copy_commitments: value.managed_copy_commitments,
        }
    }
}

/// Atomic create-or-get request carrying a bounded authenticated ciphertext.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct DurableEncryptedObjectCreateRequestV2 {
    intent: DurableObjectCreateIntentV2,
    expected_catalog_revision: u64,
    encrypted_object: EncryptedContentV2,
    descriptor: StoredEncryptedObjectDescriptorV2,
    request_intent_commitment: StateRootV2,
}

impl DurableEncryptedObjectCreateRequestV2 {
    /// Builds an exact atomic encrypted-object plus key-catalog insertion.
    pub fn new(
        entry: &DurableObjectCatalogEntryV2,
        encrypted_object: EncryptedContentV2,
    ) -> Result<Self> {
        entry.validate()?;
        if entry.stage() != DurableObjectCatalogStageV2::KeyCreated
            || entry.key() != Some(encrypted_object.header().key())
        {
            return Err(SecureStoreError::StateConflict(
                "durable object must persist the exact KMS result before ciphertext".to_owned(),
            ));
        }
        let intent = entry.intent().clone();
        let descriptor = StoredEncryptedObjectDescriptorV2::from_encrypted(
            &intent,
            &encrypted_object,
            intent.managed_copy_commitments.clone(),
        )?;
        let request_intent_commitment = object_create_intent_commitment(&intent, &descriptor)?;
        Ok(Self {
            intent,
            expected_catalog_revision: entry.revision(),
            encrypted_object,
            descriptor,
            request_intent_commitment,
        })
    }

    /// Returns the persisted creation intent.
    #[must_use]
    pub fn intent(&self) -> &DurableObjectCreateIntentV2 {
        &self.intent
    }

    /// Returns the atomic local create-or-get request identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        self.intent.object_create_request_id()
    }

    /// Returns the required key-created catalog revision.
    #[must_use]
    pub const fn expected_catalog_revision(&self) -> u64 {
        self.expected_catalog_revision
    }

    /// Returns the authenticated ciphertext body.
    #[must_use]
    pub fn encrypted_object(&self) -> &EncryptedContentV2 {
        &self.encrypted_object
    }

    /// Returns the ciphertext-only catalog descriptor.
    #[must_use]
    pub fn descriptor(&self) -> &StoredEncryptedObjectDescriptorV2 {
        &self.descriptor
    }

    /// Returns the canonical forever-bound idempotency intent.
    #[must_use]
    pub fn request_intent_commitment(&self) -> &StateRootV2 {
        &self.request_intent_commitment
    }

    fn validate(&self) -> Result<()> {
        self.descriptor.validate_against_intent(&self.intent)?;
        self.descriptor
            .validate_encrypted_object(&self.encrypted_object)?;
        if object_create_intent_commitment(&self.intent, &self.descriptor)?
            != self.request_intent_commitment
        {
            return Err(SecureStoreError::Integrity(
                "durable encrypted-object request commitment changed".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for DurableEncryptedObjectCreateRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableEncryptedObjectCreateRequestV2")
            .field("intent", &self.intent)
            .field("expected_catalog_revision", &self.expected_catalog_revision)
            .field("descriptor", &self.descriptor)
            .field("encrypted_object", &"[CIPHERTEXT]")
            .field("request_intent_commitment", &"[COMMITMENT]")
            .finish()
    }
}

/// Monotonic crash-recovery stage of one durable object creation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableObjectCatalogStageV2 {
    /// Preallocated identities and source handle are durable; KMS work may start.
    Reserved,
    /// The exact active KMS descriptor is durable; ciphertext creation may resume.
    KeyCreated,
    /// Ciphertext and key/catalog metadata are atomically durable but unpublished.
    ObjectStored,
    /// The exact P3 composite-head CAS intent is durable and may be retried.
    PublicationPending,
    /// A real P3 anchored-head result was durably recorded.
    Published,
}

impl DurableObjectCatalogStageV2 {
    const fn required_revision(self) -> u64 {
        match self {
            Self::Reserved => 1,
            Self::KeyCreated => 2,
            Self::ObjectStored => 3,
            Self::PublicationPending => 4,
            Self::Published => 5,
        }
    }
}

/// Exact generation and roots returned by an atomic catalog mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurableObjectCatalogSnapshotV2 {
    namespace: StateNamespaceV2,
    generation: u64,
    key_catalog_root: StateRootV2,
    encrypted_object_catalog_root: StateRootV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableObjectCatalogSnapshotRecoveryWireV2 {
    namespace: StateNamespaceV2,
    generation: u64,
    key_catalog_root: StateRootV2,
    encrypted_object_catalog_root: StateRootV2,
}

impl<'de> Deserialize<'de> for DurableObjectCatalogSnapshotV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DurableObjectCatalogSnapshotRecoveryWireV2::deserialize(deserializer)?;
        Self::new(
            wire.namespace,
            wire.generation,
            wire.key_catalog_root,
            wire.encrypted_object_catalog_root,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl DurableObjectCatalogSnapshotV2 {
    /// Creates a non-zero exact catalog snapshot.
    pub fn new(
        namespace: StateNamespaceV2,
        generation: u64,
        key_catalog_root: StateRootV2,
        encrypted_object_catalog_root: StateRootV2,
    ) -> Result<Self> {
        if generation == 0 {
            return Err(SecureStoreError::InvalidInput(
                "durable object catalog generation must be non-zero".to_owned(),
            ));
        }
        Ok(Self {
            namespace,
            generation,
            key_catalog_root,
            encrypted_object_catalog_root,
        })
    }

    /// Returns the exact catalog namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the monotonic adapter generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the canonical key-catalog root.
    #[must_use]
    pub fn key_catalog_root(&self) -> &StateRootV2 {
        &self.key_catalog_root
    }

    /// Returns the canonical ciphertext-object catalog root.
    #[must_use]
    pub fn encrypted_object_catalog_root(&self) -> &StateRootV2 {
        &self.encrypted_object_catalog_root
    }

    /// Returns the root that a composite head binds in its key-catalog slot.
    ///
    /// The outer commitment prevents publishing a current key list beside a
    /// rolled-back ciphertext catalog or vice versa.
    pub fn publication_root(&self) -> Result<StateRootV2> {
        #[derive(Serialize)]
        struct PublicationRoot<'a> {
            namespace: &'a StateNamespaceV2,
            key_catalog_root: &'a StateRootV2,
            encrypted_object_catalog_root: &'a StateRootV2,
        }
        StateRootV2::commit(
            "durable-secure-catalog-publication-v2",
            &canonical_json(&PublicationRoot {
                namespace: &self.namespace,
                key_catalog_root: &self.key_catalog_root,
                encrypted_object_catalog_root: &self.encrypted_object_catalog_root,
            })?,
        )
    }
}

/// Persisted exact P3 publication intent for one stored object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurableObjectHeadPublishRequestV2 {
    content_handle: ContentHandleV2,
    expected_catalog_revision: u64,
    catalog_snapshot: DurableObjectCatalogSnapshotV2,
    expected_repository_provenance: AuthorityProvenanceV2,
    repository_request: CompositeHeadCasRequestV2,
}

impl DurableObjectHeadPublishRequestV2 {
    /// Validates and freezes an exact successor publication before repository I/O.
    pub fn new(
        entry: &DurableObjectCatalogEntryV2,
        catalog_snapshot: DurableObjectCatalogSnapshotV2,
        expected_repository_provenance: AuthorityProvenanceV2,
        repository_request: CompositeHeadCasRequestV2,
        mac_authority: &dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        entry.validate()?;
        require_role(
            &expected_repository_provenance,
            AuthorityRoleV2::CompositeHeadRepository,
        )?;
        if entry.stage != DurableObjectCatalogStageV2::ObjectStored
            || catalog_snapshot.namespace() != entry.intent.namespace()
            || repository_request.request_id() != entry.intent.head_publish_request_id()
            || repository_request.next_head().namespace() != entry.intent.namespace()
            || repository_request.next_head().payload().key_catalog_root
                != catalog_snapshot.publication_root()?
        {
            return Err(SecureStoreError::Integrity(
                "durable object head intent does not bind the exact stored catalog".to_owned(),
            ));
        }
        repository_request
            .next_head()
            .verify(entry.intent.namespace(), mac_authority)?;
        Ok(Self {
            content_handle: entry.intent.content_handle.clone(),
            expected_catalog_revision: entry.revision,
            catalog_snapshot,
            expected_repository_provenance,
            repository_request,
        })
    }

    /// Returns the exact object being published.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns the required object-catalog revision.
    #[must_use]
    pub const fn expected_catalog_revision(&self) -> u64 {
        self.expected_catalog_revision
    }

    /// Returns the exact catalog roots frozen before repository I/O.
    #[must_use]
    pub fn catalog_snapshot(&self) -> &DurableObjectCatalogSnapshotV2 {
        &self.catalog_snapshot
    }

    /// Returns the exact repository deployment whose receipt is acceptable.
    #[must_use]
    pub fn expected_repository_provenance(&self) -> &AuthorityProvenanceV2 {
        &self.expected_repository_provenance
    }

    /// Returns the exact idempotent P3 repository request to retry.
    #[must_use]
    pub fn repository_request(&self) -> &CompositeHeadCasRequestV2 {
        &self.repository_request
    }

    /// Returns the complete publication intent commitment.
    pub fn intent_commitment(&self) -> Result<StateRootV2> {
        StateRootV2::commit(
            "durable-object-head-publication-intent-v2",
            &canonical_json(self)?,
        )
    }

    fn from_recovery_value(
        value: serde_json::Value,
        expected_namespace: &StateNamespaceV2,
        expected_repository_provenance: &AuthorityProvenanceV2,
        mac_authority: &dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        let wire: DurableObjectHeadPublishRecoveryWireV2 =
            serde_json::from_value(value).map_err(|_| SecureStoreError::Serialization)?;
        let configured_provenance = serde_json::to_value(expected_repository_provenance)
            .map_err(|_| SecureStoreError::Serialization)?;
        if wire.expected_repository_provenance != configured_provenance
            || wire.catalog_snapshot.namespace() != expected_namespace
        {
            return Err(SecureStoreError::Integrity(
                "persisted publication provenance or namespace changed".to_owned(),
            ));
        }
        require_role(
            expected_repository_provenance,
            AuthorityRoleV2::CompositeHeadRepository,
        )?;
        let repository_request_bytes = serde_json::to_vec(&wire.repository_request)
            .map_err(|_| SecureStoreError::Serialization)?;
        let repository_request = CompositeHeadCasRequestV2::from_json_bounded(
            &repository_request_bytes,
            expected_namespace,
            mac_authority,
        )?;
        if repository_request.next_head().payload().key_catalog_root
            != wire.catalog_snapshot.publication_root()?
        {
            return Err(SecureStoreError::Integrity(
                "persisted publication no longer binds its catalog roots".to_owned(),
            ));
        }
        Ok(Self {
            content_handle: wire.content_handle,
            expected_catalog_revision: wire.expected_catalog_revision,
            catalog_snapshot: wire.catalog_snapshot,
            expected_repository_provenance: expected_repository_provenance.clone(),
            repository_request,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableObjectHeadPublishRecoveryWireV2 {
    content_handle: ContentHandleV2,
    expected_catalog_revision: u64,
    catalog_snapshot: DurableObjectCatalogSnapshotV2,
    expected_repository_provenance: serde_json::Value,
    repository_request: serde_json::Value,
}

/// Durable catalog state for one preallocated encrypted object.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct DurableObjectCatalogEntryV2 {
    format_version: u16,
    intent: DurableObjectCreateIntentV2,
    stage: DurableObjectCatalogStageV2,
    revision: u64,
    key: Option<KeyDescriptorV2>,
    stored: Option<StoredEncryptedObjectDescriptorV2>,
    pending_publication: Option<DurableObjectHeadPublishRequestV2>,
    published_anchor: Option<HeadAnchorV2>,
}

impl DurableObjectCatalogEntryV2 {
    /// Creates the durable reservation that must precede external KMS I/O.
    pub fn reserved(intent: DurableObjectCreateIntentV2) -> Result<Self> {
        let entry = Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            intent,
            stage: DurableObjectCatalogStageV2::Reserved,
            revision: 1,
            key: None,
            stored: None,
            pending_publication: None,
            published_anchor: None,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Returns the immutable preallocation and operation intent.
    #[must_use]
    pub fn intent(&self) -> &DurableObjectCreateIntentV2 {
        &self.intent
    }

    /// Returns the monotonic creation stage.
    #[must_use]
    pub const fn stage(&self) -> DurableObjectCatalogStageV2 {
        self.stage
    }

    /// Returns the optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the exact current key descriptor once persisted.
    #[must_use]
    pub fn key(&self) -> Option<&KeyDescriptorV2> {
        self.key.as_ref()
    }

    /// Returns ciphertext-only stored metadata once atomically persisted.
    #[must_use]
    pub fn stored(&self) -> Option<&StoredEncryptedObjectDescriptorV2> {
        self.stored.as_ref()
    }

    /// Returns the exact persisted P3 retry intent once publication is pending.
    #[must_use]
    pub fn pending_publication(&self) -> Option<&DurableObjectHeadPublishRequestV2> {
        self.pending_publication.as_ref()
    }

    /// Returns the real repository anchor recorded after publication.
    #[must_use]
    pub fn published_anchor(&self) -> Option<&HeadAnchorV2> {
        self.published_anchor.as_ref()
    }

    /// Returns a content-free commitment to this catalog entry.
    pub fn root(&self) -> Result<StateRootV2> {
        StateRootV2::commit("durable-object-catalog-entry-v2", &canonical_json(self)?)
    }

    /// Recovers one bounded persisted entry using the configured exact
    /// repository provenance and an authenticating head-MAC authority.
    ///
    /// Publication state is never accepted through unchecked deserialization:
    /// the persisted provenance must equal the configured deployment and every
    /// pending successor head is MAC-verified before the entry is returned.
    pub fn from_json_bounded(
        bytes: &[u8],
        expected_repository_provenance: &AuthorityProvenanceV2,
        mac_authority: &dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_DURABLE_OBJECT_ENTRY_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "durable object entry exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: DurableObjectCatalogEntryRecoveryWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        let namespace = wire.intent.namespace().clone();
        let pending_publication = wire
            .pending_publication
            .map(|value| {
                DurableObjectHeadPublishRequestV2::from_recovery_value(
                    value,
                    &namespace,
                    expected_repository_provenance,
                    mac_authority,
                )
            })
            .transpose()?;
        let published_anchor = wire
            .published_anchor
            .map(|value| {
                let anchor: crate::repository::HeadAnchorRecoveryWireV2 =
                    serde_json::from_value(value).map_err(|_| SecureStoreError::Serialization)?;
                HeadAnchorV2::from_recovery_wire(anchor, &namespace)
            })
            .transpose()?;
        let entry = Self {
            format_version: wire.format_version,
            intent: wire.intent,
            stage: wire.stage,
            revision: wire.revision,
            key: wire.key,
            stored: wire.stored,
            pending_publication,
            published_anchor,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Derives the exact `KeyCreated` successor for adapter implementations.
    pub fn record_key_created(&self, descriptor: KeyDescriptorV2) -> Result<Self> {
        self.validate()?;
        self.intent
            .key_create_request()?
            .validate_response(&descriptor)?;
        if self.stage != DurableObjectCatalogStageV2::Reserved {
            if self.key.as_ref() == Some(&descriptor) {
                return Ok(self.clone());
            }
            return Err(SecureStoreError::StateConflict(
                "durable object key result conflicts with current stage".to_owned(),
            ));
        }
        let mut next = self.clone();
        next.stage = DurableObjectCatalogStageV2::KeyCreated;
        next.revision = 2;
        next.key = Some(descriptor);
        next.validate()?;
        Ok(next)
    }

    /// Derives the exact atomic object-stored successor.
    pub fn record_object_stored(
        &self,
        request: &DurableEncryptedObjectCreateRequestV2,
    ) -> Result<Self> {
        self.validate()?;
        request.validate()?;
        if request.intent != self.intent
            || request.expected_catalog_revision != self.revision
            || self.stage != DurableObjectCatalogStageV2::KeyCreated
            || self.key.as_ref() != Some(request.descriptor.key())
        {
            return Err(SecureStoreError::StateConflict(
                "durable encrypted-object create request is stale or substituted".to_owned(),
            ));
        }
        let mut next = self.clone();
        next.stage = DurableObjectCatalogStageV2::ObjectStored;
        next.revision = 3;
        next.stored = Some(request.descriptor.clone());
        next.validate()?;
        Ok(next)
    }

    /// Derives the exact publication-pending successor before repository I/O.
    pub fn record_publication_pending(
        &self,
        request: &DurableObjectHeadPublishRequestV2,
    ) -> Result<Self> {
        self.validate()?;
        if self.stage != DurableObjectCatalogStageV2::ObjectStored
            || request.content_handle() != self.intent.content_handle()
            || request.expected_catalog_revision() != self.revision
            || request.repository_request().request_id() != self.intent.head_publish_request_id()
        {
            return Err(SecureStoreError::StateConflict(
                "durable head publication request is stale or substituted".to_owned(),
            ));
        }
        let mut next = self.clone();
        next.stage = DurableObjectCatalogStageV2::PublicationPending;
        next.revision = 4;
        next.pending_publication = Some(request.clone());
        next.validate()?;
        Ok(next)
    }

    /// Derives the exact published successor from a prevalidated record request.
    pub fn record_published_request(
        &self,
        request: &DurableObjectPublishedRequestV2,
    ) -> Result<Self> {
        self.validate()?;
        let pending = self.pending_publication.as_ref().ok_or_else(|| {
            SecureStoreError::StateConflict("durable publication is not pending".to_owned())
        })?;
        if self.stage != DurableObjectCatalogStageV2::PublicationPending
            || request.content_handle() != self.intent.content_handle()
            || request.expected_catalog_revision() != self.revision
            || request.publication_intent_commitment() != &pending.intent_commitment()?
        {
            return Err(SecureStoreError::StateConflict(
                "published head record request is stale or substituted".to_owned(),
            ));
        }
        validate_anchored_publication(pending, request.anchored_head())?;
        let mut next = self.clone();
        next.stage = DurableObjectCatalogStageV2::Published;
        next.revision = 5;
        next.published_anchor = Some(request.anchored_head().anchor().clone());
        next.validate()?;
        Ok(next)
    }

    fn validate(&self) -> Result<()> {
        if self.format_version != SECURE_STORE_FORMAT_VERSION
            || self.revision != self.stage.required_revision()
        {
            return Err(SecureStoreError::Integrity(
                "durable object stage or revision is invalid".to_owned(),
            ));
        }
        self.intent.key_create_request()?;
        if let Some(key) = &self.key {
            self.intent.key_create_request()?.validate_response(key)?;
        }
        if let Some(stored) = &self.stored {
            stored.validate_against_intent(&self.intent)?;
            if self.key.as_ref() != Some(stored.key()) {
                return Err(SecureStoreError::Integrity(
                    "durable object key and stored descriptor disagree".to_owned(),
                ));
            }
        }
        let expected_fields = match self.stage {
            DurableObjectCatalogStageV2::Reserved => (false, false, false, false),
            DurableObjectCatalogStageV2::KeyCreated => (true, false, false, false),
            DurableObjectCatalogStageV2::ObjectStored => (true, true, false, false),
            DurableObjectCatalogStageV2::PublicationPending => (true, true, true, false),
            DurableObjectCatalogStageV2::Published => (true, true, true, true),
        };
        if (
            self.key.is_some(),
            self.stored.is_some(),
            self.pending_publication.is_some(),
            self.published_anchor.is_some(),
        ) != expected_fields
        {
            return Err(SecureStoreError::Integrity(
                "durable object catalog fields disagree with the creation stage".to_owned(),
            ));
        }
        if let Some(pending) = &self.pending_publication
            && (pending.content_handle() != self.intent.content_handle()
                || pending.expected_catalog_revision() != 3
                || pending.repository_request().request_id()
                    != self.intent.head_publish_request_id()
                || pending
                    .repository_request()
                    .next_head()
                    .payload()
                    .key_catalog_root
                    != pending.catalog_snapshot().publication_root()?)
        {
            return Err(SecureStoreError::Integrity(
                "persisted durable publication intent changed".to_owned(),
            ));
        }
        if let (Some(pending), Some(anchor)) = (&self.pending_publication, &self.published_anchor)
            && (anchor.namespace() != self.intent.namespace()
                || anchor.sequence() != pending.repository_request().next_head().sequence()
                || anchor.head_commitment()
                    != &pending.repository_request().next_head().commitment()?)
        {
            return Err(SecureStoreError::Integrity(
                "published durable object anchor differs from its pending head".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableObjectCatalogEntryRecoveryWireV2 {
    format_version: u16,
    intent: DurableObjectCreateIntentV2,
    stage: DurableObjectCatalogStageV2,
    revision: u64,
    key: Option<KeyDescriptorV2>,
    stored: Option<StoredEncryptedObjectDescriptorV2>,
    pending_publication: Option<serde_json::Value>,
    published_anchor: Option<serde_json::Value>,
}

impl fmt::Debug for DurableObjectCatalogEntryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableObjectCatalogEntryV2")
            .field("intent", &self.intent)
            .field("stage", &self.stage)
            .field("revision", &self.revision)
            .field("key", &self.key)
            .field("has_stored_ciphertext", &self.stored.is_some())
            .field(
                "has_pending_publication",
                &self.pending_publication.is_some(),
            )
            .field("has_published_anchor", &self.published_anchor.is_some())
            .finish()
    }
}

/// Exact entry and catalog roots returned after a durable mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurableObjectMutationV2 {
    entry: DurableObjectCatalogEntryV2,
    snapshot: DurableObjectCatalogSnapshotV2,
}

impl DurableObjectMutationV2 {
    /// Binds an entry to the exact roots observed after its durable mutation.
    pub fn new(
        entry: DurableObjectCatalogEntryV2,
        snapshot: DurableObjectCatalogSnapshotV2,
    ) -> Result<Self> {
        entry.validate()?;
        if entry.intent.namespace() != snapshot.namespace() {
            return Err(SecureStoreError::Integrity(
                "durable mutation entry and catalog snapshot namespaces differ".to_owned(),
            ));
        }
        Ok(Self { entry, snapshot })
    }

    /// Returns the exact durable object state.
    #[must_use]
    pub fn entry(&self) -> &DurableObjectCatalogEntryV2 {
        &self.entry
    }

    /// Returns catalog generation and roots after the mutation.
    #[must_use]
    pub fn snapshot(&self) -> &DurableObjectCatalogSnapshotV2 {
        &self.snapshot
    }
}

/// Explicit idempotent result of one durable adapter mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "value")]
pub enum DurableObjectMutationOutcomeV2 {
    /// The exact mutation was newly committed durably.
    Applied(DurableObjectMutationV2),
    /// The exact request and result were already durably committed.
    AlreadyApplied(DurableObjectMutationV2),
    /// Existing durable state is bound to another request or revision.
    Conflict {
        /// Commitment to the existing intent or entry.
        existing_commitment: StateRootV2,
    },
    /// The adapter cannot provide an authoritative durability answer.
    Unavailable,
}

/// Point-read request for one preallocated durable object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableObjectLoadRequestV2 {
    namespace: StateNamespaceV2,
    content_handle: ContentHandleV2,
}

impl DurableObjectLoadRequestV2 {
    /// Creates an exact namespace/object lookup.
    #[must_use]
    pub const fn new(namespace: StateNamespaceV2, content_handle: ContentHandleV2) -> Self {
        Self {
            namespace,
            content_handle,
        }
    }

    /// Returns the exact namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the opaque object handle.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }
}

/// Strongly classified point-read result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableObjectLoadOutcomeV2 {
    /// No reservation exists for the exact namespace and handle.
    Missing,
    /// Durable catalog state exists; ciphertext appears only after object storage.
    Found {
        /// Exact validated catalog state.
        entry: Box<DurableObjectCatalogEntryV2>,
        /// Authenticated ciphertext body, absent before `ObjectStored`.
        encrypted_object: Option<Box<EncryptedContentV2>>,
        /// Exact current adapter roots.
        snapshot: DurableObjectCatalogSnapshotV2,
    },
    /// No authoritative read is currently available.
    Unavailable,
}

impl DurableObjectLoadOutcomeV2 {
    /// Revalidates a backend result against the exact point-read request.
    pub fn validate_for(&self, request: &DurableObjectLoadRequestV2) -> Result<()> {
        let Self::Found {
            entry,
            encrypted_object,
            snapshot,
        } = self
        else {
            return Ok(());
        };
        entry.validate()?;
        if entry.intent.namespace() != request.namespace()
            || entry.intent.content_handle() != request.content_handle()
            || snapshot.namespace() != request.namespace()
        {
            return Err(SecureStoreError::Integrity(
                "durable object point read returned another namespace or handle".to_owned(),
            ));
        }
        match (entry.stored(), encrypted_object.as_deref()) {
            (None, None) => Ok(()),
            (Some(descriptor), Some(encrypted)) => descriptor.validate_encrypted_object(encrypted),
            _ => Err(SecureStoreError::Integrity(
                "durable object point read omitted or invented ciphertext".to_owned(),
            )),
        }
    }
}

/// Exact KMS result to persist after a durable reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableObjectKeyCreatedRequestV2 {
    content_handle: ContentHandleV2,
    expected_catalog_revision: u64,
    key_create_request_id: OperationRequestIdV2,
    key_create_intent_commitment: StateRootV2,
    descriptor: KeyDescriptorV2,
}

impl DurableObjectKeyCreatedRequestV2 {
    /// Binds an exact active KMS response to the reserved catalog entry.
    pub fn new(entry: &DurableObjectCatalogEntryV2, descriptor: KeyDescriptorV2) -> Result<Self> {
        entry.validate()?;
        if entry.stage() != DurableObjectCatalogStageV2::Reserved {
            return Err(SecureStoreError::StateConflict(
                "key-created persistence requires a reserved object".to_owned(),
            ));
        }
        let key_request = entry.intent().key_create_request()?;
        key_request.validate_response(&descriptor)?;
        Ok(Self {
            content_handle: entry.intent.content_handle.clone(),
            expected_catalog_revision: entry.revision,
            key_create_request_id: entry.intent.key_create_request_id.clone(),
            key_create_intent_commitment: key_request.intent_commitment()?,
            descriptor,
        })
    }

    /// Returns the exact object handle.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns the required reserved revision.
    #[must_use]
    pub const fn expected_catalog_revision(&self) -> u64 {
        self.expected_catalog_revision
    }

    /// Returns the external KMS request identity.
    #[must_use]
    pub fn key_create_request_id(&self) -> &OperationRequestIdV2 {
        &self.key_create_request_id
    }

    /// Returns the exact KMS create intent commitment.
    #[must_use]
    pub fn key_create_intent_commitment(&self) -> &StateRootV2 {
        &self.key_create_intent_commitment
    }

    /// Returns the exact active descriptor returned by the KMS.
    #[must_use]
    pub fn descriptor(&self) -> &KeyDescriptorV2 {
        &self.descriptor
    }
}

/// Successful P3 repository result to record in the local catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurableObjectPublishedRequestV2 {
    content_handle: ContentHandleV2,
    expected_catalog_revision: u64,
    publication_intent_commitment: StateRootV2,
    anchored_head: AnchoredCompositeHeadV2,
}

impl DurableObjectPublishedRequestV2 {
    /// Accepts only `Applied` or `AlreadyAnchored` for the exact pending intent.
    ///
    /// Callers must obtain `outcome` through the P3 current repository view so
    /// its MAC, evidence signature, provenance freshness, and request binding
    /// have already been checked. This constructor never synthesizes evidence.
    pub fn from_repository_outcome(
        entry: &DurableObjectCatalogEntryV2,
        outcome: &CompositeHeadCasOutcomeV2,
        evaluated_at_micros: u64,
        verifier: &dyn AuthorityEvidenceVerifierV2,
    ) -> Result<Self> {
        entry.validate()?;
        let pending = entry.pending_publication().ok_or_else(|| {
            SecureStoreError::StateConflict("durable publication is not pending".to_owned())
        })?;
        let anchored_head = match outcome {
            CompositeHeadCasOutcomeV2::Applied(value)
            | CompositeHeadCasOutcomeV2::AlreadyAnchored(value) => value.clone(),
            CompositeHeadCasOutcomeV2::Conflict { .. }
            | CompositeHeadCasOutcomeV2::Divergence { .. }
            | CompositeHeadCasOutcomeV2::Unavailable => {
                return Err(SecureStoreError::StateConflict(
                    "repository did not return a durable exact anchor".to_owned(),
                ));
            }
        };
        validate_anchored_publication(pending, &anchored_head)?;
        anchored_head
            .receipt()
            .verify_current(evaluated_at_micros, verifier)?;
        Ok(Self {
            content_handle: entry.intent.content_handle.clone(),
            expected_catalog_revision: entry.revision,
            publication_intent_commitment: pending.intent_commitment()?,
            anchored_head,
        })
    }

    /// Returns the exact published object.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns the required publication-pending revision.
    #[must_use]
    pub const fn expected_catalog_revision(&self) -> u64 {
        self.expected_catalog_revision
    }

    /// Returns the exact persisted publication intent commitment.
    #[must_use]
    pub fn publication_intent_commitment(&self) -> &StateRootV2 {
        &self.publication_intent_commitment
    }

    /// Returns the repository-provided anchored head and signed evidence.
    #[must_use]
    pub fn anchored_head(&self) -> &AnchoredCompositeHeadV2 {
        &self.anchored_head
    }
}

/// Bounded, exclusive-cursor request for content-free catalog summaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableObjectCatalogPageRequestV2 {
    namespace: StateNamespaceV2,
    expected_generation: Option<u64>,
    after: Option<ContentHandleV2>,
    max_items: usize,
    max_bytes: usize,
}

impl DurableObjectCatalogPageRequestV2 {
    /// Creates a page request with caller-selected count and canonical-byte caps.
    pub fn new(
        namespace: StateNamespaceV2,
        expected_generation: Option<u64>,
        after: Option<ContentHandleV2>,
        max_items: usize,
        max_bytes: usize,
    ) -> Result<Self> {
        if expected_generation == Some(0)
            || max_items == 0
            || max_items > MAX_DURABLE_OBJECT_CATALOG_PAGE_ITEMS_V2
            || max_bytes == 0
            || max_bytes > MAX_DURABLE_OBJECT_CATALOG_PAGE_BYTES_V2
        {
            return Err(SecureStoreError::InvalidInput(
                "durable object catalog page limits are invalid".to_owned(),
            ));
        }
        Ok(Self {
            namespace,
            expected_generation,
            after,
            max_items,
            max_bytes,
        })
    }

    /// Returns the exact namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the stable generation required after the first page.
    #[must_use]
    pub const fn expected_generation(&self) -> Option<u64> {
        self.expected_generation
    }

    /// Returns the exclusive opaque cursor.
    #[must_use]
    pub fn after(&self) -> Option<&ContentHandleV2> {
        self.after.as_ref()
    }

    /// Returns the item cap.
    #[must_use]
    pub const fn max_items(&self) -> usize {
        self.max_items
    }

    /// Returns the canonical encoded-byte cap.
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

/// Content-free summary used by bounded catalog scans.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurableObjectCatalogSummaryV2 {
    content_handle: ContentHandleV2,
    stage: DurableObjectCatalogStageV2,
    revision: u64,
    key_generation: Option<u64>,
    key_lifecycle: Option<KeyLifecycleV2>,
    ciphertext_bytes: Option<u64>,
    entry_root: StateRootV2,
}

impl DurableObjectCatalogSummaryV2 {
    /// Derives a content-free summary from one validated catalog entry.
    pub fn from_entry(entry: &DurableObjectCatalogEntryV2) -> Result<Self> {
        entry.validate()?;
        Ok(Self {
            content_handle: entry.intent.content_handle.clone(),
            stage: entry.stage,
            revision: entry.revision,
            key_generation: entry.key.as_ref().map(KeyDescriptorV2::generation),
            key_lifecycle: entry.key.as_ref().map(KeyDescriptorV2::lifecycle),
            ciphertext_bytes: entry.stored.as_ref().map(|value| value.ciphertext_bytes),
            entry_root: entry.root()?,
        })
    }

    /// Returns the exclusive-cursor identity.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns the creation stage.
    #[must_use]
    pub const fn stage(&self) -> DurableObjectCatalogStageV2 {
        self.stage
    }

    /// Returns the catalog entry revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the current key generation, if KMS creation is durable.
    #[must_use]
    pub const fn key_generation(&self) -> Option<u64> {
        self.key_generation
    }

    /// Returns the current key lifecycle, if KMS creation is durable.
    #[must_use]
    pub const fn key_lifecycle(&self) -> Option<KeyLifecycleV2> {
        self.key_lifecycle
    }

    /// Returns ciphertext bytes once the encrypted object is durable.
    #[must_use]
    pub const fn ciphertext_bytes(&self) -> Option<u64> {
        self.ciphertext_bytes
    }

    /// Returns the entry commitment.
    #[must_use]
    pub fn entry_root(&self) -> &StateRootV2 {
        &self.entry_root
    }
}

/// One stable, bounded catalog summary page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurableObjectCatalogPageV2 {
    snapshot: DurableObjectCatalogSnapshotV2,
    items: Vec<DurableObjectCatalogSummaryV2>,
    next_after: Option<ContentHandleV2>,
}

impl DurableObjectCatalogPageV2 {
    /// Validates ordering, cursor exclusivity, generation, count, and bytes.
    pub fn new(
        request: &DurableObjectCatalogPageRequestV2,
        snapshot: DurableObjectCatalogSnapshotV2,
        items: Vec<DurableObjectCatalogSummaryV2>,
        has_more: bool,
    ) -> Result<Self> {
        if snapshot.namespace() != request.namespace()
            || request
                .expected_generation()
                .is_some_and(|expected| expected != snapshot.generation())
            || items.len() > request.max_items()
            || (has_more && items.is_empty())
        {
            return Err(SecureStoreError::StateConflict(
                "durable object catalog page snapshot or count is invalid".to_owned(),
            ));
        }
        if items
            .windows(2)
            .any(|pair| pair[0].content_handle >= pair[1].content_handle)
            || items.iter().any(|item| {
                request
                    .after()
                    .is_some_and(|after| item.content_handle() <= after)
            })
        {
            return Err(SecureStoreError::Integrity(
                "durable object catalog page cursor ordering is invalid".to_owned(),
            ));
        }
        let next_after = has_more.then(|| {
            items
                .last()
                .expect("has_more requires a non-empty bounded page")
                .content_handle
                .clone()
        });
        #[derive(Serialize)]
        struct BoundedPage<'a> {
            snapshot: &'a DurableObjectCatalogSnapshotV2,
            items: &'a [DurableObjectCatalogSummaryV2],
            next_after: &'a Option<ContentHandleV2>,
        }
        let canonical_bytes = canonical_json(&BoundedPage {
            snapshot: &snapshot,
            items: &items,
            next_after: &next_after,
        })?
        .len();
        if canonical_bytes > request.max_bytes() {
            return Err(SecureStoreError::InvalidInput(
                "durable object catalog page exceeds canonical byte cap".to_owned(),
            ));
        }
        Ok(Self {
            snapshot,
            items,
            next_after,
        })
    }

    /// Returns exact roots and stable generation for this page.
    #[must_use]
    pub fn snapshot(&self) -> &DurableObjectCatalogSnapshotV2 {
        &self.snapshot
    }

    /// Returns ordered content-free entry summaries.
    #[must_use]
    pub fn items(&self) -> &[DurableObjectCatalogSummaryV2] {
        &self.items
    }

    /// Returns the exclusive cursor for the next page, if any.
    #[must_use]
    pub fn next_after(&self) -> Option<&ContentHandleV2> {
        self.next_after.as_ref()
    }
}

/// Explicit result of a bounded stable-generation scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableObjectCatalogPageOutcomeV2 {
    /// One validated page at the requested generation.
    Page(DurableObjectCatalogPageV2),
    /// The catalog changed; restart from the first page at this generation.
    GenerationChanged {
        /// Current generation observed by the adapter.
        current_generation: u64,
    },
    /// No authoritative bounded scan answer is available.
    Unavailable,
}

/// Durable encrypted-object and key/catalog adapter contract.
///
/// Implementations MUST durably commit each `Applied` result before returning,
/// permanently bind every request ID to one exact intent, and return
/// `Unavailable` rather than a cache guess. `create_or_get_object` atomically
/// stores the ciphertext body, its exact catalog descriptor, current key
/// descriptor, and managed-copy commitments. Publication preparation is a
/// separate durable step that precedes P3 repository I/O. No method emits
/// deletion evidence or an erasure receipt.
pub trait DurableEncryptedObjectCatalogV2: Send + Sync {
    /// Durably creates or replays a caller-preallocated reservation.
    fn reserve(
        &self,
        intent: &DurableObjectCreateIntentV2,
    ) -> Result<DurableObjectMutationOutcomeV2>;

    /// Durably records the exact active descriptor returned by KMS create-or-get.
    fn record_key_created(
        &self,
        request: &DurableObjectKeyCreatedRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2>;

    /// Atomically creates or replays ciphertext plus key/object catalog state.
    fn create_or_get_object(
        &self,
        request: &DurableEncryptedObjectCreateRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2>;

    /// Durably records the exact P3 CAS intent before external repository I/O.
    fn prepare_head_publication(
        &self,
        request: &DurableObjectHeadPublishRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2>;

    /// Durably records a real exact P3 anchored-head result.
    fn record_head_published(
        &self,
        request: &DurableObjectPublishedRequestV2,
    ) -> Result<DurableObjectMutationOutcomeV2>;

    /// Performs a strongly consistent point read with bounded ciphertext size.
    fn load(&self, request: &DurableObjectLoadRequestV2) -> Result<DurableObjectLoadOutcomeV2>;

    /// Returns one content-free, stable-generation, count-and-byte-bounded page.
    fn scan_page(
        &self,
        request: &DurableObjectCatalogPageRequestV2,
    ) -> Result<DurableObjectCatalogPageOutcomeV2>;
}

/// Recovery action derived only from validated durable catalog state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableObjectRecoveryActionV2 {
    /// Retry exact idempotent P3 KMS create-or-get.
    RetryKeyCreate(ProductionKeyCreateRequestV2),
    /// Reload the opaque retained source, seal under the exact key, and retry
    /// the atomic object/catalog create-or-get.
    SealAndStore {
        /// Host-owned opaque source reference; not plaintext or a plaintext digest.
        source_material_handle: SourceMaterialHandleV2,
        /// Exact active descriptor already durably cataloged.
        key: KeyDescriptorV2,
        /// Required key-created catalog revision.
        expected_catalog_revision: u64,
    },
    /// Build and durably prepare an exact successor head for these current roots.
    PrepareHeadPublication(DurableObjectCatalogSnapshotV2),
    /// Retry the already persisted exact P3 repository CAS.
    RetryHeadPublication(CompositeHeadCasRequestV2),
    /// Local catalog and real P3 head anchor are durably converged.
    Complete(HeadAnchorV2),
}

/// Plans one bounded, convergent recovery step without performing external I/O.
pub fn plan_durable_object_recovery_v2(
    entry: &DurableObjectCatalogEntryV2,
    current_snapshot: &DurableObjectCatalogSnapshotV2,
) -> Result<DurableObjectRecoveryActionV2> {
    entry.validate()?;
    if current_snapshot.namespace() != entry.intent.namespace() {
        return Err(SecureStoreError::Integrity(
            "recovery catalog snapshot namespace differs from the object".to_owned(),
        ));
    }
    match entry.stage {
        DurableObjectCatalogStageV2::Reserved => Ok(DurableObjectRecoveryActionV2::RetryKeyCreate(
            entry.intent.key_create_request()?,
        )),
        DurableObjectCatalogStageV2::KeyCreated => {
            Ok(DurableObjectRecoveryActionV2::SealAndStore {
                source_material_handle: entry.intent.source_material_handle.clone(),
                key: entry.key.clone().ok_or_else(|| {
                    SecureStoreError::Integrity("key-created entry lacks its key".to_owned())
                })?,
                expected_catalog_revision: entry.revision,
            })
        }
        DurableObjectCatalogStageV2::ObjectStored => Ok(
            DurableObjectRecoveryActionV2::PrepareHeadPublication(current_snapshot.clone()),
        ),
        DurableObjectCatalogStageV2::PublicationPending => {
            Ok(DurableObjectRecoveryActionV2::RetryHeadPublication(
                entry
                    .pending_publication
                    .as_ref()
                    .ok_or_else(|| {
                        SecureStoreError::Integrity(
                            "publication-pending entry lacks its retry intent".to_owned(),
                        )
                    })?
                    .repository_request
                    .clone(),
            ))
        }
        DurableObjectCatalogStageV2::Published => Ok(DurableObjectRecoveryActionV2::Complete(
            entry.published_anchor.clone().ok_or_else(|| {
                SecureStoreError::Integrity("published entry lacks a repository anchor".to_owned())
            })?,
        )),
    }
}

fn encrypted_object_commitment(encrypted_object: &EncryptedContentV2) -> Result<StateRootV2> {
    StateRootV2::commit(
        "durable-encrypted-object-v2",
        &canonical_json(encrypted_object)?,
    )
}

pub(crate) fn object_create_intent_commitment(
    intent: &DurableObjectCreateIntentV2,
    descriptor: &StoredEncryptedObjectDescriptorV2,
) -> Result<StateRootV2> {
    #[derive(Serialize)]
    struct ObjectCreateIntent<'a> {
        request_id: &'a OperationRequestIdV2,
        durable_intent_commitment: StateRootV2,
        descriptor: &'a StoredEncryptedObjectDescriptorV2,
    }
    StateRootV2::commit(
        "durable-encrypted-object-create-or-get-v2",
        &canonical_json(&ObjectCreateIntent {
            request_id: intent.object_create_request_id(),
            durable_intent_commitment: intent.commitment()?,
            descriptor,
        })?,
    )
}

fn validate_anchored_publication(
    pending: &DurableObjectHeadPublishRequestV2,
    anchored: &AnchoredCompositeHeadV2,
) -> Result<()> {
    if anchored.head() != pending.repository_request().next_head()
        || anchored.receipt().previous_anchor() != pending.repository_request().expected_anchor()
        || anchored.receipt().provenance() != pending.expected_repository_provenance()
        || anchored.receipt().authority_evidence().request_id()
            != pending.repository_request().request_id()
    {
        return Err(SecureStoreError::Integrity(
            "anchored head does not bind the exact durable publication intent".to_owned(),
        ));
    }
    Ok(())
}
