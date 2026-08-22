use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use redb::{
    Database, Durability as RedbDurability, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CompositeStateHeadV2, ContentHandleV2, ContentSecurityContextV2, DekScopeV2,
    DeletionTargetHandleV2, DurableObjectCreateIntentV2, EvidenceHandleV2, HeadMacAuthorityV2,
    KeyCatalogSnapshotV2, KeyDescriptorV2, KeyHandleV2, KeyLifecycleV2, LifecyclePayloadV1,
    LiveSuppressionDecisionV2, LiveSuppressionOverlayV2, OperationRequestIdV2, Result,
    SECURE_STORE_FORMAT_VERSION, SealedPayloadV2, SecureStoreError, SourceMaterialHandleV2,
    StateNamespaceV2, StateRootV2, SuppressionAwareReadV2, SuppressionBindingV2, canonical_json,
    encode_hex,
};

const LOCAL_META_BYTES: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("local_crypto_meta_bytes_v1");
const LOCAL_META_U64: TableDefinition<'static, &'static [u8], u64> =
    TableDefinition::new("local_crypto_meta_u64_v1");
const LOCAL_OBJECTS: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("local_crypto_objects_v1");
const LOCAL_STAGING: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("local_crypto_staging_v1");
const LOCAL_REQUESTS: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("local_crypto_requests_v1");
const LOCAL_GENERATIONS: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("local_crypto_generations_v1");

const META_NAMESPACE: &[u8] = b"namespace";
const META_STORE_SALT: &[u8] = b"store_salt";
const META_MASTER_BINDING: &[u8] = b"master_binding";
const META_GENERATION: &[u8] = b"generation";
const INITIAL_GENERATION: u64 = 1;

const MAX_LOCAL_DECRYPTED_OBJECT_RECORD_JSON_BYTES_V1: usize = 96 * 1024 * 1024;
const MAX_LOCAL_DECRYPTED_STAGING_RECORD_JSON_BYTES_V1: usize = 96 * 1024 * 1024;
const PERSISTED_ENVELOPE_OVERHEAD_BYTES_V1: usize = 64;
/// Maximum opaque encrypted bytes accepted for one local object record.
pub const MAX_LOCAL_OBJECT_RECORD_JSON_BYTES_V1: usize =
    MAX_LOCAL_DECRYPTED_OBJECT_RECORD_JSON_BYTES_V1 + PERSISTED_ENVELOPE_OVERHEAD_BYTES_V1;
/// Maximum opaque encrypted bytes accepted for one source-staging record.
pub const MAX_LOCAL_STAGING_RECORD_JSON_BYTES_V1: usize =
    MAX_LOCAL_DECRYPTED_STAGING_RECORD_JSON_BYTES_V1 + PERSISTED_ENVELOPE_OVERHEAD_BYTES_V1;
/// Maximum JSON bytes accepted for one authenticated local-authority head.
pub const MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1: usize = 256 * 1024;
/// Maximum items returned by one opaque recovery page.
pub const MAX_LOCAL_RECOVERY_PAGE_ITEMS_V1: usize = 4_096;
/// Maximum canonical bytes returned by one opaque recovery page.
pub const MAX_LOCAL_RECOVERY_PAGE_BYTES_V1: usize = 4 * 1024 * 1024;

/// Externally custodied 256-bit master key for the local crypto authority.
///
/// The wrapper is intentionally neither cloneable nor serializable and exposes
/// no byte accessor. Construct it from zeroizing memory supplied by the host's
/// secret provider. File/ACL protection and durable custody remain host
/// responsibilities; this type is not evidence of DPAPI, KMS, or HSM custody.
pub struct LocalMasterKeyV1(Zeroizing<[u8; 32]>);

impl LocalMasterKeyV1 {
    /// Takes ownership of exactly 256 bits already held in zeroizing memory.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Generates a fresh key for a newly provisioned local store.
    ///
    /// The returned wrapper still cannot be serialized; a host that needs to
    /// reopen the store must place the key in an external secret-custody system.
    pub fn generate_ephemeral() -> Result<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SecureStoreError::CryptographicFailure)?;
        Ok(Self(bytes))
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LocalMasterKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalMasterKeyV1([REDACTED])")
    }
}

/// Opaque deletion targets preallocated for one locally encrypted object.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "LocalDeletionTargetsWireV1",
    into = "LocalDeletionTargetsWireV1"
)]
pub struct LocalDeletionTargetsV1 {
    wrapped_dek: DeletionTargetHandleV2,
    encrypted_object: DeletionTargetHandleV2,
    staged_source: DeletionTargetHandleV2,
}

impl LocalDeletionTargetsV1 {
    /// Generates distinct opaque targets before any plaintext enters staging.
    pub fn generate() -> Result<Self> {
        Self::new(
            DeletionTargetHandleV2::generate()?,
            DeletionTargetHandleV2::generate()?,
            DeletionTargetHandleV2::generate()?,
        )
    }

    /// Validates caller-preallocated deletion targets.
    pub fn new(
        wrapped_dek: DeletionTargetHandleV2,
        encrypted_object: DeletionTargetHandleV2,
        staged_source: DeletionTargetHandleV2,
    ) -> Result<Self> {
        if BTreeSet::from([
            wrapped_dek.clone(),
            encrypted_object.clone(),
            staged_source.clone(),
        ])
        .len()
            != 3
        {
            return Err(SecureStoreError::InvalidInput(
                "local deletion targets must be distinct".to_owned(),
            ));
        }
        Ok(Self {
            wrapped_dek,
            encrypted_object,
            staged_source,
        })
    }

    /// Returns the wrapped-DEK deletion target.
    #[must_use]
    pub fn wrapped_dek(&self) -> &DeletionTargetHandleV2 {
        &self.wrapped_dek
    }

    /// Returns the ciphertext-object deletion target.
    #[must_use]
    pub fn encrypted_object(&self) -> &DeletionTargetHandleV2 {
        &self.encrypted_object
    }

    /// Returns the temporary encrypted-source deletion target.
    #[must_use]
    pub fn staged_source(&self) -> &DeletionTargetHandleV2 {
        &self.staged_source
    }
}

impl fmt::Debug for LocalDeletionTargetsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalDeletionTargetsV1([OPAQUE; 3])")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalDeletionTargetsWireV1 {
    wrapped_dek: DeletionTargetHandleV2,
    encrypted_object: DeletionTargetHandleV2,
    staged_source: DeletionTargetHandleV2,
}

impl TryFrom<LocalDeletionTargetsWireV1> for LocalDeletionTargetsV1 {
    type Error = SecureStoreError;

    fn try_from(value: LocalDeletionTargetsWireV1) -> Result<Self> {
        Self::new(
            value.wrapped_dek,
            value.encrypted_object,
            value.staged_source,
        )
    }
}

impl From<LocalDeletionTargetsV1> for LocalDeletionTargetsWireV1 {
    fn from(value: LocalDeletionTargetsV1) -> Self {
        Self {
            wrapped_dek: value.wrapped_dek,
            encrypted_object: value.encrypted_object,
            staged_source: value.staged_source,
        }
    }
}

/// Exact idempotent intent for encrypted source staging and final sealing.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "LocalObjectSealRequestWireV1",
    into = "LocalObjectSealRequestWireV1"
)]
pub struct LocalObjectSealRequestV1 {
    format_version: u16,
    intent: DurableObjectCreateIntentV2,
    lifecycle: LifecyclePayloadV1,
    deletion_targets: LocalDeletionTargetsV1,
}

impl LocalObjectSealRequestV1 {
    /// Creates an exact local seal request and preallocates deletion targets.
    pub fn from_durable_intent(
        intent: DurableObjectCreateIntentV2,
        lifecycle: LifecyclePayloadV1,
    ) -> Result<Self> {
        Self::new(intent, lifecycle, LocalDeletionTargetsV1::generate()?)
    }

    /// Creates an exact local seal request using caller-preallocated targets.
    pub fn new(
        intent: DurableObjectCreateIntentV2,
        lifecycle: LifecyclePayloadV1,
        deletion_targets: LocalDeletionTargetsV1,
    ) -> Result<Self> {
        if lifecycle.workspace_id() != intent.namespace().workspace_id()
            || lifecycle.workspace_id() != intent.security_context().workspace_id()
            || lifecycle.subject_id() != intent.security_context().logical_owner()
        {
            return Err(SecureStoreError::Integrity(
                "lifecycle workspace or subject differs from the encryption intent".to_owned(),
            ));
        }
        Ok(Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            intent,
            lifecycle,
            deletion_targets,
        })
    }

    /// Recovers a bounded request and reruns every cross-binding invariant.
    pub fn from_json_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len()
            > crate::MAX_DURABLE_OBJECT_INTENT_JSON_BYTES_V2
                + crate::MAX_LIFECYCLE_PAYLOAD_JSON_BYTES_V1
                + 4 * 1024
        {
            return Err(SecureStoreError::InvalidInput(
                "local object seal request exceeds decode byte limit".to_owned(),
            ));
        }
        serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)
    }

    /// Returns the idempotency request identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        self.intent.object_create_request_id()
    }

    /// Returns the exact durable preallocation intent.
    #[must_use]
    pub fn intent(&self) -> &DurableObjectCreateIntentV2 {
        &self.intent
    }

    /// Returns the exact lifecycle metadata bound into ciphertext.
    #[must_use]
    pub fn lifecycle(&self) -> &LifecyclePayloadV1 {
        &self.lifecycle
    }

    /// Returns preallocated opaque deletion targets.
    #[must_use]
    pub fn deletion_targets(&self) -> &LocalDeletionTargetsV1 {
        &self.deletion_targets
    }

    /// Returns the exact per-object DEK scope.
    pub fn dek_scope(&self) -> Result<DekScopeV2> {
        DekScopeV2::new(
            self.intent.content_handle().clone(),
            self.intent.erasure_domain().clone(),
            self.intent.security_context().clone(),
        )
    }

    /// Returns the canonical retry commitment.
    pub fn commitment(&self) -> Result<StateRootV2> {
        StateRootV2::commit("local-object-seal-request-v1", &canonical_json(self)?)
    }

    fn validate(&self) -> Result<()> {
        if self.format_version != SECURE_STORE_FORMAT_VERSION {
            return Err(SecureStoreError::Integrity(
                "local seal request format version changed".to_owned(),
            ));
        }
        let rebuilt = Self::new(
            self.intent.clone(),
            self.lifecycle.clone(),
            self.deletion_targets.clone(),
        )?;
        if &rebuilt != self {
            return Err(SecureStoreError::Integrity(
                "local seal request failed canonical reconstruction".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for LocalObjectSealRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalObjectSealRequestV1")
            .field("request_id", &"[OPAQUE]")
            .field("content_handle", &"[OPAQUE]")
            .field("source_material_handle", &"[OPAQUE]")
            .field("lifecycle", &self.lifecycle)
            .field("deletion_targets", &self.deletion_targets)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalObjectSealRequestWireV1 {
    format_version: u16,
    intent: DurableObjectCreateIntentV2,
    lifecycle: LifecyclePayloadV1,
    deletion_targets: LocalDeletionTargetsV1,
}

impl TryFrom<LocalObjectSealRequestWireV1> for LocalObjectSealRequestV1 {
    type Error = SecureStoreError;

    fn try_from(value: LocalObjectSealRequestWireV1) -> Result<Self> {
        if value.format_version != SECURE_STORE_FORMAT_VERSION {
            return Err(SecureStoreError::Integrity(
                "local seal request format version changed".to_owned(),
            ));
        }
        Self::new(value.intent, value.lifecycle, value.deletion_targets)
    }
}

impl From<LocalObjectSealRequestV1> for LocalObjectSealRequestWireV1 {
    fn from(value: LocalObjectSealRequestV1) -> Self {
        Self {
            format_version: value.format_version,
            intent: value.intent,
            lifecycle: value.lifecycle,
            deletion_targets: value.deletion_targets,
        }
    }
}

/// Authenticated local ciphertext whose AAD binds lifecycle metadata and targets.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "LocalSealedObjectWireV1", into = "LocalSealedObjectWireV1")]
pub struct LocalSealedObjectV1 {
    format_version: u16,
    request_commitment: StateRootV2,
    lifecycle_commitment: StateRootV2,
    source_material_handle: SourceMaterialHandleV2,
    content_handle: ContentHandleV2,
    initial_key: KeyDescriptorV2,
    lifecycle: LifecyclePayloadV1,
    deletion_targets: LocalDeletionTargetsV1,
    sealed: SealedPayloadV2,
}

impl LocalSealedObjectV1 {
    /// Returns the exact create-intent commitment.
    #[must_use]
    pub fn request_commitment(&self) -> &StateRootV2 {
        &self.request_commitment
    }

    /// Returns the exact lifecycle-metadata commitment.
    #[must_use]
    pub fn lifecycle_commitment(&self) -> &StateRootV2 {
        &self.lifecycle_commitment
    }

    /// Returns the opaque source staging identity.
    #[must_use]
    pub fn source_material_handle(&self) -> &SourceMaterialHandleV2 {
        &self.source_material_handle
    }

    /// Returns the opaque encrypted-object identity.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns immutable generation-one key metadata authenticated by the AAD.
    #[must_use]
    pub fn initial_key(&self) -> &KeyDescriptorV2 {
        &self.initial_key
    }

    /// Returns lifecycle metadata authenticated by the AAD.
    #[must_use]
    pub fn lifecycle(&self) -> &LifecyclePayloadV1 {
        &self.lifecycle
    }

    /// Returns exact opaque deletion targets authenticated by the AAD.
    #[must_use]
    pub fn deletion_targets(&self) -> &LocalDeletionTargetsV1 {
        &self.deletion_targets
    }

    /// Returns public nonce and ciphertext bytes.
    #[must_use]
    pub fn sealed_payload(&self) -> &SealedPayloadV2 {
        &self.sealed
    }

    fn new(
        request: &LocalObjectSealRequestV1,
        initial_key: KeyDescriptorV2,
        sealed: SealedPayloadV2,
    ) -> Result<Self> {
        let value = Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            request_commitment: request.commitment()?,
            lifecycle_commitment: request.lifecycle().commitment()?,
            source_material_handle: request.intent().source_material_handle().clone(),
            content_handle: request.intent().content_handle().clone(),
            initial_key,
            lifecycle: request.lifecycle().clone(),
            deletion_targets: request.deletion_targets().clone(),
            sealed,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        self.initial_key.validate()?;
        if self.format_version != SECURE_STORE_FORMAT_VERSION
            || self.initial_key.lifecycle() != KeyLifecycleV2::Active
            || self.initial_key.generation() != 1
            || self.initial_key.scope().content_handle() != &self.content_handle
            || self.lifecycle.commitment()? != self.lifecycle_commitment
            || self.sealed.ciphertext().len() > crate::MAX_ENCRYPTED_CONTENT_BYTES + 16
        {
            return Err(SecureStoreError::Integrity(
                "local sealed object metadata is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    fn associated_data(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Header<'a> {
            format_version: u16,
            request_commitment: &'a StateRootV2,
            lifecycle_commitment: &'a StateRootV2,
            source_material_handle: &'a SourceMaterialHandleV2,
            content_handle: &'a ContentHandleV2,
            initial_key: &'a KeyDescriptorV2,
            lifecycle: &'a LifecyclePayloadV1,
            deletion_targets: &'a LocalDeletionTargetsV1,
        }
        domain_message(
            b"contextdb/local-sealed-object/v1\0",
            &canonical_json(&Header {
                format_version: self.format_version,
                request_commitment: &self.request_commitment,
                lifecycle_commitment: &self.lifecycle_commitment,
                source_material_handle: &self.source_material_handle,
                content_handle: &self.content_handle,
                initial_key: &self.initial_key,
                lifecycle: &self.lifecycle,
                deletion_targets: &self.deletion_targets,
            })?,
        )
    }
}

impl fmt::Debug for LocalSealedObjectV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSealedObjectV1")
            .field("request_commitment", &"[COMMITMENT]")
            .field("lifecycle_commitment", &"[COMMITMENT]")
            .field("source_material_handle", &"[OPAQUE]")
            .field("content_handle", &"[OPAQUE]")
            .field("initial_key", &self.initial_key)
            .field("lifecycle", &self.lifecycle)
            .field("deletion_targets", &self.deletion_targets)
            .field("ciphertext_bytes", &self.sealed.ciphertext().len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSealedObjectWireV1 {
    format_version: u16,
    request_commitment: StateRootV2,
    lifecycle_commitment: StateRootV2,
    source_material_handle: SourceMaterialHandleV2,
    content_handle: ContentHandleV2,
    initial_key: KeyDescriptorV2,
    lifecycle: LifecyclePayloadV1,
    deletion_targets: LocalDeletionTargetsV1,
    sealed: SealedPayloadV2,
}

impl TryFrom<LocalSealedObjectWireV1> for LocalSealedObjectV1 {
    type Error = SecureStoreError;

    fn try_from(value: LocalSealedObjectWireV1) -> Result<Self> {
        let object = Self {
            format_version: value.format_version,
            request_commitment: value.request_commitment,
            lifecycle_commitment: value.lifecycle_commitment,
            source_material_handle: value.source_material_handle,
            content_handle: value.content_handle,
            initial_key: value.initial_key,
            lifecycle: value.lifecycle,
            deletion_targets: value.deletion_targets,
            sealed: value.sealed,
        };
        object.validate()?;
        Ok(object)
    }
}

impl From<LocalSealedObjectV1> for LocalSealedObjectWireV1 {
    fn from(value: LocalSealedObjectV1) -> Self {
        Self {
            format_version: value.format_version,
            request_commitment: value.request_commitment,
            lifecycle_commitment: value.lifecycle_commitment,
            source_material_handle: value.source_material_handle,
            content_handle: value.content_handle,
            initial_key: value.initial_key,
            lifecycle: value.lifecycle,
            deletion_targets: value.deletion_targets,
            sealed: value.sealed,
        }
    }
}

/// Outcome of an idempotent local create-and-seal operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalCreateOutcomeV1 {
    /// A new encrypted object was durably committed.
    Applied(LocalSealedObjectV1),
    /// The exact prior result was recovered for the same request and plaintext.
    AlreadyApplied(LocalSealedObjectV1),
}

impl LocalCreateOutcomeV1 {
    /// Returns the exact durable encrypted object for either successful state.
    #[must_use]
    pub fn object(&self) -> &LocalSealedObjectV1 {
        match self {
            Self::Applied(value) | Self::AlreadyApplied(value) => value,
        }
    }
}

/// Synchronous local key-destruction request bound to an active generation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "LocalDestroyRequestWireV1",
    into = "LocalDestroyRequestWireV1"
)]
pub struct LocalDestroyRequestV1 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    expected_descriptor: KeyDescriptorV2,
}

impl LocalDestroyRequestV1 {
    /// Creates an exact idempotent destruction request.
    pub fn new(
        request_id: OperationRequestIdV2,
        namespace: StateNamespaceV2,
        expected_descriptor: KeyDescriptorV2,
    ) -> Result<Self> {
        expected_descriptor.validate()?;
        if expected_descriptor.lifecycle() != KeyLifecycleV2::Active
            || expected_descriptor.scope().security_context().database_id()
                != namespace.database_id()
            || expected_descriptor
                .scope()
                .security_context()
                .workspace_id()
                != namespace.workspace_id()
        {
            return Err(SecureStoreError::Integrity(
                "local destroy request is outside its active key namespace".to_owned(),
            ));
        }
        Ok(Self {
            request_id,
            namespace,
            expected_descriptor,
        })
    }

    /// Returns the idempotency identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the exact active generation expected by the caller.
    #[must_use]
    pub fn expected_descriptor(&self) -> &KeyDescriptorV2 {
        &self.expected_descriptor
    }

    /// Returns the canonical destruction intent commitment.
    pub fn commitment(&self) -> Result<StateRootV2> {
        StateRootV2::commit("local-destroy-request-v1", &canonical_json(self)?)
    }
}

impl fmt::Debug for LocalDestroyRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDestroyRequestV1")
            .field("request_id", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("expected_descriptor", &self.expected_descriptor)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalDestroyRequestWireV1 {
    request_id: OperationRequestIdV2,
    namespace: StateNamespaceV2,
    expected_descriptor: KeyDescriptorV2,
}

impl TryFrom<LocalDestroyRequestWireV1> for LocalDestroyRequestV1 {
    type Error = SecureStoreError;

    fn try_from(value: LocalDestroyRequestWireV1) -> Result<Self> {
        Self::new(value.request_id, value.namespace, value.expected_descriptor)
    }
}

impl From<LocalDestroyRequestV1> for LocalDestroyRequestWireV1 {
    fn from(value: LocalDestroyRequestV1) -> Self {
        Self {
            request_id: value.request_id,
            namespace: value.namespace,
            expected_descriptor: value.expected_descriptor,
        }
    }
}

/// Authenticated rollback anchor that must be retained outside the redb file.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "LocalAuthorityAnchorWireV1",
    into = "LocalAuthorityAnchorWireV1"
)]
pub struct LocalAuthorityAnchorV1 {
    generation: u64,
    state_root: StateRootV2,
    catalog_root: StateRootV2,
    chain_root: StateRootV2,
    authentication_tag: StateRootV2,
}

impl LocalAuthorityAnchorV1 {
    /// Recovers a bounded externally custodied anchor.
    pub fn from_json_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1 {
            return Err(SecureStoreError::InvalidInput(
                "local authority anchor exceeds decode byte limit".to_owned(),
            ));
        }
        serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)
    }

    /// Returns the monotonic local-authority generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the complete durable-state commitment.
    #[must_use]
    pub fn state_root(&self) -> &StateRootV2 {
        &self.state_root
    }

    /// Returns the public key-catalog commitment suitable for head publication.
    #[must_use]
    pub fn catalog_root(&self) -> &StateRootV2 {
        &self.catalog_root
    }

    /// Returns the append-only generation-chain commitment.
    #[must_use]
    pub fn chain_root(&self) -> &StateRootV2 {
        &self.chain_root
    }

    fn validate(&self) -> Result<()> {
        if self.generation == 0 {
            return Err(SecureStoreError::Integrity(
                "local authority anchor generation is zero".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for LocalAuthorityAnchorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalAuthorityAnchorV1")
            .field("generation", &self.generation)
            .field("state_root", &"[COMMITMENT]")
            .field("catalog_root", &"[COMMITMENT]")
            .field("chain_root", &"[COMMITMENT]")
            .field("authentication_tag", &"[AUTHENTICATOR]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalAuthorityAnchorWireV1 {
    generation: u64,
    state_root: StateRootV2,
    catalog_root: StateRootV2,
    chain_root: StateRootV2,
    authentication_tag: StateRootV2,
}

impl TryFrom<LocalAuthorityAnchorWireV1> for LocalAuthorityAnchorV1 {
    type Error = SecureStoreError;

    fn try_from(value: LocalAuthorityAnchorWireV1) -> Result<Self> {
        let anchor = Self {
            generation: value.generation,
            state_root: value.state_root,
            catalog_root: value.catalog_root,
            chain_root: value.chain_root,
            authentication_tag: value.authentication_tag,
        };
        anchor.validate()?;
        Ok(anchor)
    }
}

impl From<LocalAuthorityAnchorV1> for LocalAuthorityAnchorWireV1 {
    fn from(value: LocalAuthorityAnchorV1) -> Self {
        Self {
            generation: value.generation,
            state_root: value.state_root,
            catalog_root: value.catalog_root,
            chain_root: value.chain_root,
            authentication_tag: value.authentication_tag,
        }
    }
}

/// Strongly consistent non-secret descriptor read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalKeyDescriptionV1 {
    descriptor: KeyDescriptorV2,
    record_revision: u64,
    anchor: LocalAuthorityAnchorV1,
}

impl LocalKeyDescriptionV1 {
    /// Returns the current monotonic key descriptor.
    #[must_use]
    pub fn descriptor(&self) -> &KeyDescriptorV2 {
        &self.descriptor
    }

    /// Returns the current object-record revision.
    #[must_use]
    pub const fn record_revision(&self) -> u64 {
        self.record_revision
    }

    /// Returns the authenticated authority anchor observed by the read.
    #[must_use]
    pub fn anchor(&self) -> &LocalAuthorityAnchorV1 {
        &self.anchor
    }
}

/// Local destruction result. It proves only local logical key removal.
///
/// The result is not physical-purge evidence and not a KMS/HSM/provider receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDestroyReceiptV1 {
    descriptor: KeyDescriptorV2,
    deletion_targets: LocalDeletionTargetsV1,
    anchor: LocalAuthorityAnchorV1,
}

impl LocalDestroyReceiptV1 {
    /// Returns the generation-three local tombstone descriptor.
    #[must_use]
    pub fn descriptor(&self) -> &KeyDescriptorV2 {
        &self.descriptor
    }

    /// Returns targets still requiring host/provider physical deletion closure.
    #[must_use]
    pub fn deletion_targets(&self) -> &LocalDeletionTargetsV1 {
        &self.deletion_targets
    }

    /// Returns the authenticated post-destruction local anchor.
    #[must_use]
    pub fn anchor(&self) -> &LocalAuthorityAnchorV1 {
        &self.anchor
    }
}

/// Outcome of an idempotent local destruction request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalDestroyOutcomeV1 {
    /// The wrapped DEK was removed by a newly committed mutation.
    Applied(LocalDestroyReceiptV1),
    /// The exact prior local destruction result was replayed.
    AlreadyApplied(LocalDestroyReceiptV1),
}

impl LocalDestroyOutcomeV1 {
    /// Returns the local destruction receipt for either successful state.
    #[must_use]
    pub fn receipt(&self) -> &LocalDestroyReceiptV1 {
        match self {
            Self::Applied(value) | Self::AlreadyApplied(value) => value,
        }
    }
}

/// Opaque authorization permit issued only after authenticated suppression checks.
///
/// A permit is neither cloneable nor serializable. Every use reloads the
/// durable descriptor and revision, so destruction revokes all prior permits.
pub struct LocalOpenPermitV1 {
    content_handle: ContentHandleV2,
    key_handle: KeyHandleV2,
    active_descriptor: KeyDescriptorV2,
    record_revision: u64,
    lifecycle_commitment: StateRootV2,
    expected_context: ContentSecurityContextV2,
    publication_head_commitment: StateRootV2,
}

/// Linearizable current-authorization lease for local permit consumption.
///
/// The implementation owns the current authenticated publication head and
/// suppression state. It must acquire the same shared lease that suppression
/// publication acquires exclusively, compare `publication_head_commitment`
/// with the current authenticated head, and evaluate the exact content handle.
/// While that lease is still held it must invoke `open` exactly once for
/// [`LiveSuppressionDecisionV2::Allow`], or not at all for
/// [`LiveSuppressionDecisionV2::Suppressed`]. Returning `Allow` without the
/// callback, invoking it more than once, or invoking it before returning
/// `Suppressed` is rejected by [`RedbLocalCryptoAuthorityV1`].
///
/// This callback is the read/suppression linearization point: a suppression
/// publication that obtains its exclusive lease first revokes the permit;
/// a read that obtains its shared lease first completes its fully bound
/// descriptor, revision, key, context, unwrap, and decrypt checks before the
/// suppression publication can commit.
pub trait LocalOpenAuthorizationEpochV1: Send + Sync {
    /// Revalidates the exact current authorization epoch and, only when
    /// allowed, runs the authority-owned unwrap/decrypt operation under lease.
    fn with_current_authorization(
        &self,
        namespace: &StateNamespaceV2,
        publication_head_commitment: &StateRootV2,
        content_handle: &ContentHandleV2,
        open: &mut dyn FnMut() -> Result<()>,
    ) -> Result<LiveSuppressionDecisionV2>;
}

impl fmt::Debug for LocalOpenPermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalOpenPermitV1")
            .field("content_handle", &"[OPAQUE]")
            .field("key_handle", &"[OPAQUE]")
            .field("key_generation", &self.active_descriptor.generation())
            .field("record_revision", &self.record_revision)
            .field("lifecycle_commitment", &"[COMMITMENT]")
            .field("publication_head_commitment", &"[COMMITMENT]")
            .finish_non_exhaustive()
    }
}

/// Result of suppression authorization before any wrapped-DEK operation.
pub enum LocalOpenAuthorizationV1 {
    /// No object exists for the exact opaque handle.
    Missing,
    /// The exact live overlay suppresses the object.
    Suppressed,
    /// Suppression allowed a short-lived, generation-bound permit.
    Permitted(Box<LocalOpenPermitV1>),
}

impl fmt::Debug for LocalOpenAuthorizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("LocalOpenAuthorizationV1::Missing"),
            Self::Suppressed => formatter.write_str("LocalOpenAuthorizationV1::Suppressed"),
            Self::Permitted(value) => formatter.debug_tuple("Permitted").field(value).finish(),
        }
    }
}

/// Content-free recovery summary containing opaque identities only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalRecoveryItemV1 {
    request_id: OperationRequestIdV2,
    source_material_handle: SourceMaterialHandleV2,
    content_handle: ContentHandleV2,
    deletion_targets: LocalDeletionTargetsV1,
}

impl LocalRecoveryItemV1 {
    /// Returns the exact idempotency identity.
    #[must_use]
    pub fn request_id(&self) -> &OperationRequestIdV2 {
        &self.request_id
    }

    /// Returns the opaque encrypted-staging identity.
    #[must_use]
    pub fn source_material_handle(&self) -> &SourceMaterialHandleV2 {
        &self.source_material_handle
    }

    /// Returns the opaque destination-object identity.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        &self.content_handle
    }

    /// Returns preallocated opaque deletion targets.
    #[must_use]
    pub fn deletion_targets(&self) -> &LocalDeletionTargetsV1 {
        &self.deletion_targets
    }
}

/// Stable-generation, count-and-byte-bounded encrypted-staging recovery page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalRecoveryPageV1 {
    generation: u64,
    items: Vec<LocalRecoveryItemV1>,
    next_after: Option<SourceMaterialHandleV2>,
}

impl LocalRecoveryPageV1 {
    /// Returns the stable authority generation for cursor continuation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns opaque staged recovery summaries.
    #[must_use]
    pub fn items(&self) -> &[LocalRecoveryItemV1] {
        &self.items
    }

    /// Returns the exclusive opaque cursor when more items remain.
    #[must_use]
    pub fn next_after(&self) -> Option<&SourceMaterialHandleV2> {
        self.next_after.as_ref()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalObjectRecordV1 {
    request: LocalObjectSealRequestV1,
    object: LocalSealedObjectV1,
    current_descriptor: KeyDescriptorV2,
    wrapped_dek: Option<SealedPayloadV2>,
    record_revision: u64,
    destroy_request_id: Option<OperationRequestIdV2>,
    destroy_commitment: Option<StateRootV2>,
}

impl LocalObjectRecordV1 {
    fn active(
        request: LocalObjectSealRequestV1,
        object: LocalSealedObjectV1,
        wrapped_dek: SealedPayloadV2,
    ) -> Result<Self> {
        let value = Self {
            current_descriptor: object.initial_key.clone(),
            request,
            object,
            wrapped_dek: Some(wrapped_dek),
            record_revision: 1,
            destroy_request_id: None,
            destroy_commitment: None,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.object.validate()?;
        self.current_descriptor.validate()?;
        if self.object.request_commitment != self.request.commitment()?
            || self.object.initial_key.scope() != &self.request.dek_scope()?
            || self.object.deletion_targets != self.request.deletion_targets
            || self.record_revision == 0
        {
            return Err(SecureStoreError::Integrity(
                "local object record bindings are invalid".to_owned(),
            ));
        }
        match self.current_descriptor.lifecycle() {
            KeyLifecycleV2::Active => {
                if self.current_descriptor != self.object.initial_key
                    || self.wrapped_dek.is_none()
                    || self.record_revision != 1
                    || self.destroy_request_id.is_some()
                    || self.destroy_commitment.is_some()
                {
                    return Err(SecureStoreError::Integrity(
                        "active local object record is malformed".to_owned(),
                    ));
                }
            }
            KeyLifecycleV2::Destroyed => {
                if self.current_descriptor.key_handle() != self.object.initial_key.key_handle()
                    || self.current_descriptor.scope() != self.object.initial_key.scope()
                    || self.wrapped_dek.is_some()
                    || self.record_revision != 2
                    || self.destroy_request_id.is_none()
                    || self.destroy_commitment.is_none()
                {
                    return Err(SecureStoreError::Integrity(
                        "destroyed local object record is malformed".to_owned(),
                    ));
                }
            }
            KeyLifecycleV2::DestroyPending => {
                return Err(SecureStoreError::Integrity(
                    "local synchronous authority persisted destroy-pending state".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn destroy(&self, request: &LocalDestroyRequestV1) -> Result<Self> {
        self.validate()?;
        if self.current_descriptor != *request.expected_descriptor() {
            return Err(SecureStoreError::StateConflict(
                "local destroy descriptor is stale".to_owned(),
            ));
        }
        let pending = self.current_descriptor.authority_destroy_pending()?;
        let destroyed = pending.authority_destroyed(EvidenceHandleV2::generate()?)?;
        let value = Self {
            request: self.request.clone(),
            object: self.object.clone(),
            current_descriptor: destroyed,
            wrapped_dek: None,
            record_revision: 2,
            destroy_request_id: Some(request.request_id().clone()),
            destroy_commitment: Some(request.commitment()?),
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalStagingRecordV1 {
    request: LocalObjectSealRequestV1,
    wrapped_staging_key: SealedPayloadV2,
    encrypted_source: SealedPayloadV2,
}

impl LocalStagingRecordV1 {
    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        if self.encrypted_source.ciphertext().len() > crate::MAX_ENCRYPTED_CONTENT_BYTES + 16 {
            return Err(SecureStoreError::Integrity(
                "encrypted source staging exceeds the supported bound".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LocalRequestKindV1 {
    Create,
    Destroy,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRequestBindingV1 {
    kind: LocalRequestKindV1,
    commitment: StateRootV2,
    content_handle: ContentHandleV2,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalGenerationRecordV1 {
    generation: u64,
    state_root: StateRootV2,
    catalog_root: StateRootV2,
    previous_chain_root: Option<StateRootV2>,
    chain_root: StateRootV2,
    authentication_tag: StateRootV2,
}

impl LocalGenerationRecordV1 {
    fn new(
        generation: u64,
        state_root: StateRootV2,
        catalog_root: StateRootV2,
        previous_chain_root: Option<StateRootV2>,
        namespace: &StateNamespaceV2,
        master_key: &LocalMasterKeyV1,
    ) -> Result<Self> {
        if generation == 0 || (generation == 1) != previous_chain_root.is_none() {
            return Err(SecureStoreError::Integrity(
                "local authority generation predecessor is invalid".to_owned(),
            ));
        }
        #[derive(Serialize)]
        struct ChainSubject<'a> {
            generation: u64,
            state_root: &'a StateRootV2,
            catalog_root: &'a StateRootV2,
            previous_chain_root: &'a Option<StateRootV2>,
        }
        let chain_root = StateRootV2::commit(
            "local-authority-generation-chain-v1",
            &canonical_json(&ChainSubject {
                generation,
                state_root: &state_root,
                catalog_root: &catalog_root,
                previous_chain_root: &previous_chain_root,
            })?,
        )?;
        let authentication_tag = keyed_state_root(
            master_key,
            "contextdb/local-authority-generation-auth/v1",
            &canonical_json(&(namespace, generation, &chain_root))?,
        )?;
        Ok(Self {
            generation,
            state_root,
            catalog_root,
            previous_chain_root,
            chain_root,
            authentication_tag,
        })
    }

    fn validate(
        &self,
        expected_generation: u64,
        expected_previous: Option<&StateRootV2>,
        namespace: &StateNamespaceV2,
        master_key: &LocalMasterKeyV1,
    ) -> Result<()> {
        if self.generation != expected_generation
            || self.previous_chain_root.as_ref() != expected_previous
        {
            return Err(SecureStoreError::Integrity(
                "local authority generation chain is discontinuous".to_owned(),
            ));
        }
        let rebuilt = Self::new(
            self.generation,
            self.state_root.clone(),
            self.catalog_root.clone(),
            self.previous_chain_root.clone(),
            namespace,
            master_key,
        )?;
        if rebuilt.chain_root != self.chain_root
            || !constant_time_equal(
                rebuilt.authentication_tag.as_str().as_bytes(),
                self.authentication_tag.as_str().as_bytes(),
            )
        {
            return Err(SecureStoreError::Integrity(
                "local authority generation authentication failed".to_owned(),
            ));
        }
        Ok(())
    }

    fn anchor(&self) -> LocalAuthorityAnchorV1 {
        LocalAuthorityAnchorV1 {
            generation: self.generation,
            state_root: self.state_root.clone(),
            catalog_root: self.catalog_root.clone(),
            chain_root: self.chain_root.clone(),
            authentication_tag: self.authentication_tag.clone(),
        }
    }
}

struct VerifiedLocalStateV1 {
    records: BTreeMap<ContentHandleV2, LocalObjectRecordV1>,
    staging: BTreeMap<SourceMaterialHandleV2, LocalStagingRecordV1>,
    requests: BTreeMap<OperationRequestIdV2, LocalRequestBindingV1>,
    generation: u64,
    anchor: LocalAuthorityAnchorV1,
}

/// Deep-verification summary for the local authority database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAuthorityVerifyReportV1 {
    anchor: LocalAuthorityAnchorV1,
    object_count: u64,
    staged_source_count: u64,
    request_binding_count: u64,
}

impl LocalAuthorityVerifyReportV1 {
    /// Returns the authenticated current anchor.
    #[must_use]
    pub fn anchor(&self) -> &LocalAuthorityAnchorV1 {
        &self.anchor
    }

    /// Returns the number of durable object/tombstone records.
    #[must_use]
    pub const fn object_count(&self) -> u64 {
        self.object_count
    }

    /// Returns the number of encrypted source records awaiting convergence.
    #[must_use]
    pub const fn staged_source_count(&self) -> u64 {
        self.staged_source_count
    }

    /// Returns the number of exact idempotency bindings.
    #[must_use]
    pub const fn request_binding_count(&self) -> u64 {
        self.request_binding_count
    }
}

/// Durable local encrypted-source and per-object-DEK authority.
///
/// This adapter performs real local cryptography and immediate redb commits,
/// but deliberately does not implement [`crate::KeyAuthorityV2`]: there is no
/// public raw-decrypt path. Reads require an authenticated suppression decision.
/// The host must protect the database directory with platform ACLs, custody the
/// master key separately, and retain returned rollback anchors outside this
/// redb file. These host duties are not proven by this adapter, and this type is
/// not a production KMS/HSM/DPAPI claim.
pub struct RedbLocalCryptoAuthorityV1 {
    database: Mutex<Database>,
    operation_lock: Mutex<()>,
    namespace: StateNamespaceV2,
    master_key: LocalMasterKeyV1,
    store_salt: [u8; 32],
}

impl RedbLocalCryptoAuthorityV1 {
    /// Opens or initializes one single-namespace authority and deep-verifies it.
    ///
    /// `expected_anchor` must come from independent caller custody to detect a
    /// restored older database or same-generation divergence.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: StateNamespaceV2,
        master_key: LocalMasterKeyV1,
        expected_anchor: Option<&LocalAuthorityAnchorV1>,
    ) -> Result<Self> {
        let database = Database::create(path).map_err(redb_unavailable)?;
        let mut authority = Self {
            database: Mutex::new(database),
            operation_lock: Mutex::new(()),
            namespace,
            master_key,
            store_salt: [0_u8; 32],
        };
        authority.initialize_or_load_salt()?;
        authority.deep_verify(expected_anchor)?;
        Ok(authority)
    }

    /// Recomputes every record, request binding, generation authenticator, and
    /// optional independently custodied rollback anchor.
    pub fn deep_verify(
        &self,
        expected_anchor: Option<&LocalAuthorityAnchorV1>,
    ) -> Result<LocalAuthorityVerifyReportV1> {
        let database = self.lock_database()?;
        let state = self.verify_database(&database, expected_anchor)?;
        Ok(LocalAuthorityVerifyReportV1 {
            anchor: state.anchor,
            object_count: state.records.len() as u64,
            staged_source_count: state.staging.len() as u64,
            request_binding_count: state.requests.len() as u64,
        })
    }

    /// Returns the current external-custody anchor after a full deep verify.
    pub fn current_anchor(&self) -> Result<LocalAuthorityAnchorV1> {
        self.deep_verify(None).map(|report| report.anchor)
    }

    /// Returns the current public key-catalog root after a full deep verify.
    pub fn current_catalog_root(&self) -> Result<StateRootV2> {
        self.current_anchor().map(|anchor| anchor.catalog_root)
    }

    /// Stages plaintext only as authenticated ciphertext, then atomically
    /// commits a random wrapped DEK and final ciphertext while removing staging.
    ///
    /// A retry with the same request but different plaintext fails closed. A
    /// crash before final commit leaves one encrypted recovery record; a crash
    /// after commit leaves the exact final result and no source staging.
    pub fn create_and_seal_or_get(
        &self,
        request: &LocalObjectSealRequestV1,
        plaintext: &[u8],
    ) -> Result<LocalCreateOutcomeV1> {
        let _operation = self.lock_operation()?;
        request.validate()?;
        validate_plaintext(plaintext)?;
        if request.intent().namespace() != &self.namespace {
            return Err(SecureStoreError::Integrity(
                "local seal request targets another authority namespace".to_owned(),
            ));
        }
        if let Some(existing) = self.exact_existing_object(request)? {
            self.verify_retry_plaintext(&existing, plaintext)?;
            return Ok(LocalCreateOutcomeV1::AlreadyApplied(existing.object));
        }
        self.stage_source_if_needed(request, plaintext)?;
        self.finalize_staged(request.intent().source_material_handle())
            .map(LocalCreateOutcomeV1::Applied)
    }

    /// Converges one already-durable encrypted staging record without exposing
    /// its recovered plaintext to the caller.
    pub fn resume_staged(
        &self,
        source_material_handle: &SourceMaterialHandleV2,
    ) -> Result<LocalCreateOutcomeV1> {
        let _operation = self.lock_operation()?;
        self.finalize_staged(source_material_handle)
            .map(LocalCreateOutcomeV1::Applied)
    }

    /// Returns a stable, bounded page of opaque recovery identities.
    pub fn recovery_page(
        &self,
        expected_generation: Option<u64>,
        after: Option<&SourceMaterialHandleV2>,
        max_items: usize,
        max_bytes: usize,
    ) -> Result<LocalRecoveryPageV1> {
        if expected_generation == Some(0)
            || max_items == 0
            || max_items > MAX_LOCAL_RECOVERY_PAGE_ITEMS_V1
            || max_bytes == 0
            || max_bytes > MAX_LOCAL_RECOVERY_PAGE_BYTES_V1
        {
            return Err(SecureStoreError::InvalidInput(
                "local recovery page limits are invalid".to_owned(),
            ));
        }
        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        if expected_generation.is_some_and(|expected| expected != state.generation) {
            return Err(SecureStoreError::StateConflict(
                "local recovery generation changed; restart the scan".to_owned(),
            ));
        }
        let mut candidates = state
            .staging
            .iter()
            .filter(|(handle, _)| after.is_none_or(|cursor| *handle > cursor))
            .map(|(_, stage)| LocalRecoveryItemV1 {
                request_id: stage.request.request_id().clone(),
                source_material_handle: stage.request.intent().source_material_handle().clone(),
                content_handle: stage.request.intent().content_handle().clone(),
                deletion_targets: stage.request.deletion_targets().clone(),
            })
            .collect::<Vec<_>>();
        let has_more = candidates.len() > max_items;
        candidates.truncate(max_items);
        let next_after = has_more.then(|| {
            candidates
                .last()
                .expect("has_more requires a non-empty recovery page")
                .source_material_handle
                .clone()
        });
        let page = LocalRecoveryPageV1 {
            generation: state.generation,
            items: candidates,
            next_after,
        };
        if canonical_json(&page)?.len() > max_bytes {
            return Err(SecureStoreError::InvalidInput(
                "local recovery page exceeds canonical byte cap".to_owned(),
            ));
        }
        Ok(page)
    }

    /// Performs a cache-free descriptor read with exact scope and generation checks.
    pub fn describe_strongly_consistent(
        &self,
        key_handle: &KeyHandleV2,
        expected_scope: &DekScopeV2,
        minimum_generation: u64,
    ) -> Result<LocalKeyDescriptionV1> {
        if minimum_generation == 0 {
            return Err(SecureStoreError::InvalidInput(
                "minimum local key generation must be non-zero".to_owned(),
            ));
        }
        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        let record = state
            .records
            .values()
            .find(|record| record.current_descriptor.key_handle() == key_handle)
            .ok_or(SecureStoreError::KeyUnavailable)?;
        if record.current_descriptor.scope() != expected_scope
            || record.current_descriptor.generation() < minimum_generation
        {
            return Err(SecureStoreError::StateConflict(
                "local key descriptor scope or generation differs".to_owned(),
            ));
        }
        Ok(LocalKeyDescriptionV1 {
            descriptor: record.current_descriptor.clone(),
            record_revision: record.record_revision,
            anchor: state.anchor,
        })
    }

    /// Authenticates the publication head and evaluates live suppression before
    /// issuing a non-serializable, generation-bound open permit.
    pub fn authorize_open_after_suppression(
        &self,
        head: &CompositeStateHeadV2,
        content_handle: &ContentHandleV2,
        expected_context: &ContentSecurityContextV2,
        mac_authority: &dyn HeadMacAuthorityV2,
        overlay: &dyn LiveSuppressionOverlayV2,
    ) -> Result<LocalOpenAuthorizationV1> {
        head.verify(&self.namespace, mac_authority)?;
        if expected_context.database_id() != self.namespace.database_id()
            || expected_context.workspace_id() != self.namespace.workspace_id()
        {
            return Err(SecureStoreError::Integrity(
                "local open context is outside the authority namespace".to_owned(),
            ));
        }
        match &head.payload().suppression {
            SuppressionBindingV2::Pending { .. } => {
                return Err(SecureStoreError::DeletionIncomplete(
                    "all local opens are denied while suppression publication is pending"
                        .to_owned(),
                ));
            }
            SuppressionBindingV2::Enforced { overlay_root } => {
                match overlay.check_content(&self.namespace, overlay_root, content_handle)? {
                    LiveSuppressionDecisionV2::Suppressed => {
                        return Ok(LocalOpenAuthorizationV1::Suppressed);
                    }
                    LiveSuppressionDecisionV2::Allow => {}
                }
            }
            SuppressionBindingV2::Clear => {}
        }
        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        if head.payload().key_catalog_root != *state.anchor.catalog_root() {
            return Err(SecureStoreError::Integrity(
                "publication head does not bind the current local key catalog".to_owned(),
            ));
        }
        let Some(record) = state.records.get(content_handle) else {
            return Ok(LocalOpenAuthorizationV1::Missing);
        };
        if record.current_descriptor.lifecycle() != KeyLifecycleV2::Active
            || record.object.lifecycle != record.request.lifecycle
            || record.object.initial_key.scope().security_context() != expected_context
        {
            return Err(SecureStoreError::KeyUnavailable);
        }
        Ok(LocalOpenAuthorizationV1::Permitted(Box::new(
            LocalOpenPermitV1 {
                content_handle: content_handle.clone(),
                key_handle: record.current_descriptor.key_handle().clone(),
                active_descriptor: record.current_descriptor.clone(),
                record_revision: record.record_revision,
                lifecycle_commitment: record.object.lifecycle_commitment.clone(),
                expected_context: expected_context.clone(),
                publication_head_commitment: head.commitment()?,
            },
        )))
    }

    /// Opens final ciphertext only under a linearizable current-authorization
    /// lease and after rechecking the permit's exact descriptor, revision, key,
    /// lifecycle, content context, and ciphertext against durable state.
    pub fn open_with_permit(
        &self,
        permit: LocalOpenPermitV1,
        authorization_epoch: &dyn LocalOpenAuthorizationEpochV1,
    ) -> Result<SuppressionAwareReadV2> {
        let publication_head_commitment = permit.publication_head_commitment.clone();
        let content_handle = permit.content_handle.clone();
        let mut pending_permit = Some(permit);
        let mut plaintext = None;
        let decision = {
            let mut open = || {
                let permit = pending_permit.take().ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "local authorization lease invoked one permit more than once".to_owned(),
                    )
                })?;
                plaintext = Some(self.open_bound_permit(permit)?);
                Ok(())
            };
            authorization_epoch.with_current_authorization(
                &self.namespace,
                &publication_head_commitment,
                &content_handle,
                &mut open,
            )?
        };
        match (decision, pending_permit.is_none(), plaintext) {
            (LiveSuppressionDecisionV2::Allow, true, Some(plaintext)) => {
                Ok(SuppressionAwareReadV2::Decrypted(plaintext))
            }
            (LiveSuppressionDecisionV2::Suppressed, false, None) => {
                Ok(SuppressionAwareReadV2::Suppressed)
            }
            _ => Err(SecureStoreError::Integrity(
                "local authorization lease violated its callback contract".to_owned(),
            )),
        }
    }

    fn open_bound_permit(&self, permit: LocalOpenPermitV1) -> Result<Zeroizing<Vec<u8>>> {
        let _operation = self.lock_operation()?;
        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        let record = state
            .records
            .get(&permit.content_handle)
            .ok_or(SecureStoreError::KeyUnavailable)?;
        if record.current_descriptor.lifecycle() != KeyLifecycleV2::Active
            || record.current_descriptor != permit.active_descriptor
            || record.current_descriptor.key_handle() != &permit.key_handle
            || record.record_revision != permit.record_revision
            || record.object.lifecycle_commitment != permit.lifecycle_commitment
            || record.object.initial_key.scope().security_context() != &permit.expected_context
        {
            return Err(SecureStoreError::KeyUnavailable);
        }
        let wrapped = record
            .wrapped_dek
            .as_ref()
            .ok_or(SecureStoreError::KeyUnavailable)?;
        let dek = self.unwrap_key(
            wrapped,
            &wrap_aad(
                &self.namespace,
                &record.object.request_commitment,
                record.object.initial_key.key_handle().as_str(),
                "object-dek",
            )?,
        )?;
        let plaintext = open_bytes(
            &dek,
            record.object.sealed_payload(),
            &record.object.associated_data()?,
        )?;
        Ok(plaintext)
    }

    /// Convenience read that keeps authorization and permit consumption in one call.
    pub fn open_after_suppression(
        &self,
        head: &CompositeStateHeadV2,
        content_handle: &ContentHandleV2,
        expected_context: &ContentSecurityContextV2,
        mac_authority: &dyn HeadMacAuthorityV2,
        overlay: &dyn LiveSuppressionOverlayV2,
        authorization_epoch: &dyn LocalOpenAuthorizationEpochV1,
    ) -> Result<SuppressionAwareReadV2> {
        match self.authorize_open_after_suppression(
            head,
            content_handle,
            expected_context,
            mac_authority,
            overlay,
        )? {
            LocalOpenAuthorizationV1::Missing => Ok(SuppressionAwareReadV2::Missing),
            LocalOpenAuthorizationV1::Suppressed => Ok(SuppressionAwareReadV2::Suppressed),
            LocalOpenAuthorizationV1::Permitted(permit) => {
                self.open_with_permit(*permit, authorization_epoch)
            }
        }
    }

    /// Synchronously removes the wrapped DEK and commits a generation-three
    /// tombstone. All previously issued permits fail their mandatory reread.
    ///
    /// Ciphertext and database-page physical purge remain explicit external
    /// deletion targets and are not claimed by this operation.
    pub fn destroy(&self, request: &LocalDestroyRequestV1) -> Result<LocalDestroyOutcomeV1> {
        let _operation = self.lock_operation()?;
        if request.namespace() != &self.namespace {
            return Err(SecureStoreError::Integrity(
                "local destruction targets another authority namespace".to_owned(),
            ));
        }
        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        let content_handle = request.expected_descriptor().scope().content_handle();
        let current = state
            .records
            .get(content_handle)
            .ok_or(SecureStoreError::KeyUnavailable)?;
        let commitment = request.commitment()?;
        if let Some(existing) = state.requests.get(request.request_id()) {
            if existing.kind != LocalRequestKindV1::Destroy
                || existing.commitment != commitment
                || existing.content_handle != *content_handle
                || current.destroy_request_id.as_ref() != Some(request.request_id())
                || current.destroy_commitment.as_ref() != Some(&commitment)
                || current.current_descriptor.lifecycle() != KeyLifecycleV2::Destroyed
            {
                return Err(SecureStoreError::StateConflict(
                    "local destroy request identity is bound to another intent".to_owned(),
                ));
            }
            return Ok(LocalDestroyOutcomeV1::AlreadyApplied(
                LocalDestroyReceiptV1 {
                    descriptor: current.current_descriptor.clone(),
                    deletion_targets: current.object.deletion_targets.clone(),
                    anchor: state.anchor,
                },
            ));
        }
        if current.current_descriptor != *request.expected_descriptor() {
            return Err(SecureStoreError::StateConflict(
                "local destruction expected a stale key generation".to_owned(),
            ));
        }
        let destroyed = current.destroy(request)?;
        let mut next_records = state.records.clone();
        next_records.insert(content_handle.clone(), destroyed.clone());
        let mut next_requests = state.requests.clone();
        next_requests.insert(
            request.request_id().clone(),
            LocalRequestBindingV1 {
                kind: LocalRequestKindV1::Destroy,
                commitment,
                content_handle: content_handle.clone(),
            },
        );
        let next = self.next_generation(&state, &next_records, &state.staging, &next_requests)?;
        let record_bytes = self.encrypt_persisted_record(
            "object-record",
            content_handle.as_str(),
            &destroyed,
            MAX_LOCAL_DECRYPTED_OBJECT_RECORD_JSON_BYTES_V1,
            MAX_LOCAL_OBJECT_RECORD_JSON_BYTES_V1,
        )?;
        let request_bytes = encode_bounded(
            next_requests
                .get(request.request_id())
                .expect("inserted destroy request binding"),
            MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1,
        )?;
        let generation_bytes = encode_bounded(&next, MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1)?;
        let mut transaction = database.begin_write().map_err(redb_unavailable)?;
        self.require_generation(&transaction, state.generation)?;
        transaction
            .open_table(LOCAL_OBJECTS)
            .map_err(redb_unavailable)?
            .insert(content_handle.as_str().as_bytes(), record_bytes.as_slice())
            .map_err(redb_unavailable)?;
        transaction
            .open_table(LOCAL_REQUESTS)
            .map_err(redb_unavailable)?
            .insert(
                request.request_id().as_str().as_bytes(),
                request_bytes.as_slice(),
            )
            .map_err(redb_unavailable)?;
        self.write_generation(&mut transaction, &next, &generation_bytes)?;
        commit_immediate(transaction)?;
        Ok(LocalDestroyOutcomeV1::Applied(LocalDestroyReceiptV1 {
            descriptor: destroyed.current_descriptor,
            deletion_targets: destroyed.object.deletion_targets,
            anchor: next.anchor(),
        }))
    }

    fn lock_database(&self) -> Result<MutexGuard<'_, Database>> {
        self.database.lock().map_err(|_| {
            SecureStoreError::StateConflict("local crypto authority lock is poisoned".to_owned())
        })
    }

    fn lock_operation(&self) -> Result<MutexGuard<'_, ()>> {
        self.operation_lock.lock().map_err(|_| {
            SecureStoreError::StateConflict(
                "local crypto authority operation lock is poisoned".to_owned(),
            )
        })
    }

    fn initialize_or_load_salt(&mut self) -> Result<()> {
        let database = self.database.lock().map_err(|_| {
            SecureStoreError::StateConflict("local crypto authority lock is poisoned".to_owned())
        })?;
        let transaction = database.begin_write().map_err(redb_unavailable)?;
        let existing_namespace = {
            let table = transaction
                .open_table(LOCAL_META_BYTES)
                .map_err(redb_unavailable)?;
            table
                .get(META_NAMESPACE)
                .map_err(redb_unavailable)?
                .map(|value| bounded_copy(value.value(), 64 * 1024))
                .transpose()?
        };
        if let Some(namespace_bytes) = existing_namespace {
            let stored_namespace: StateNamespaceV2 = serde_json::from_slice(&namespace_bytes)
                .map_err(|_| SecureStoreError::Serialization)?;
            if stored_namespace != self.namespace {
                return Err(SecureStoreError::Integrity(
                    "local crypto authority namespace changed".to_owned(),
                ));
            }
            let (salt, binding) = {
                let table = transaction
                    .open_table(LOCAL_META_BYTES)
                    .map_err(redb_unavailable)?;
                let salt = table
                    .get(META_STORE_SALT)
                    .map_err(redb_unavailable)?
                    .ok_or_else(|| {
                        SecureStoreError::Integrity(
                            "local crypto authority salt is missing".to_owned(),
                        )
                    })?;
                let binding = table
                    .get(META_MASTER_BINDING)
                    .map_err(redb_unavailable)?
                    .ok_or_else(|| {
                        SecureStoreError::Integrity(
                            "local crypto authority master binding is missing".to_owned(),
                        )
                    })?;
                (
                    copy_exact_32(salt.value())?,
                    bounded_copy(binding.value(), 32)?,
                )
            };
            let expected = master_binding(&self.master_key, &self.namespace, &salt)?;
            if !constant_time_equal(&binding, &expected) {
                return Err(SecureStoreError::CryptographicFailure);
            }
            self.store_salt = salt;
            transaction.abort().map_err(redb_unavailable)?;
            return Ok(());
        }
        {
            let objects = transaction
                .open_table(LOCAL_OBJECTS)
                .map_err(redb_unavailable)?;
            let staging = transaction
                .open_table(LOCAL_STAGING)
                .map_err(redb_unavailable)?;
            let requests = transaction
                .open_table(LOCAL_REQUESTS)
                .map_err(redb_unavailable)?;
            let generations = transaction
                .open_table(LOCAL_GENERATIONS)
                .map_err(redb_unavailable)?;
            if objects.len().map_err(redb_unavailable)? != 0
                || staging.len().map_err(redb_unavailable)? != 0
                || requests.len().map_err(redb_unavailable)? != 0
                || generations.len().map_err(redb_unavailable)? != 0
            {
                return Err(SecureStoreError::Integrity(
                    "uninitialized local authority contains orphan state".to_owned(),
                ));
            }
        }
        let mut salt = [0_u8; 32];
        getrandom::fill(&mut salt).map_err(|_| SecureStoreError::CryptographicFailure)?;
        let binding = master_binding(&self.master_key, &self.namespace, &salt)?;
        let records = BTreeMap::new();
        let staging = BTreeMap::new();
        let requests = BTreeMap::new();
        let generation = LocalGenerationRecordV1::new(
            INITIAL_GENERATION,
            local_state_root(&records, &staging, &requests)?,
            local_catalog_root(&records)?,
            None,
            &self.namespace,
            &self.master_key,
        )?;
        let namespace_bytes = encode_bounded(&self.namespace, 64 * 1024)?;
        let generation_bytes = encode_bounded(&generation, MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1)?;
        {
            let mut table = transaction
                .open_table(LOCAL_META_BYTES)
                .map_err(redb_unavailable)?;
            table
                .insert(META_NAMESPACE, namespace_bytes.as_slice())
                .map_err(redb_unavailable)?;
            table
                .insert(META_STORE_SALT, salt.as_slice())
                .map_err(redb_unavailable)?;
            table
                .insert(META_MASTER_BINDING, binding.as_slice())
                .map_err(redb_unavailable)?;
        }
        {
            let mut table = transaction
                .open_table(LOCAL_META_U64)
                .map_err(redb_unavailable)?;
            table
                .insert(META_GENERATION, INITIAL_GENERATION)
                .map_err(redb_unavailable)?;
        }
        transaction
            .open_table(LOCAL_GENERATIONS)
            .map_err(redb_unavailable)?
            .insert(INITIAL_GENERATION, generation_bytes.as_slice())
            .map_err(redb_unavailable)?;
        commit_immediate(transaction)?;
        self.store_salt = salt;
        Ok(())
    }

    fn verify_database(
        &self,
        database: &Database,
        expected_anchor: Option<&LocalAuthorityAnchorV1>,
    ) -> Result<VerifiedLocalStateV1> {
        let transaction = database.begin_read().map_err(redb_unavailable)?;
        let (stored_namespace, stored_salt, stored_binding) = {
            let table = transaction
                .open_table(LOCAL_META_BYTES)
                .map_err(redb_unavailable)?;
            let namespace = table
                .get(META_NAMESPACE)
                .map_err(redb_unavailable)?
                .ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "local crypto authority namespace is missing".to_owned(),
                    )
                })?;
            let salt = table
                .get(META_STORE_SALT)
                .map_err(redb_unavailable)?
                .ok_or_else(|| {
                    SecureStoreError::Integrity("local crypto authority salt is missing".to_owned())
                })?;
            let binding = table
                .get(META_MASTER_BINDING)
                .map_err(redb_unavailable)?
                .ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "local crypto authority master binding is missing".to_owned(),
                    )
                })?;
            (
                bounded_copy(namespace.value(), 64 * 1024)?,
                copy_exact_32(salt.value())?,
                bounded_copy(binding.value(), 32)?,
            )
        };
        let stored_namespace: StateNamespaceV2 = serde_json::from_slice(&stored_namespace)
            .map_err(|_| SecureStoreError::Serialization)?;
        if stored_namespace != self.namespace || stored_salt != self.store_salt {
            return Err(SecureStoreError::Integrity(
                "local crypto authority identity metadata changed".to_owned(),
            ));
        }
        let expected_binding = master_binding(&self.master_key, &self.namespace, &self.store_salt)?;
        if !constant_time_equal(&stored_binding, &expected_binding) {
            return Err(SecureStoreError::CryptographicFailure);
        }
        let generation = {
            let table = transaction
                .open_table(LOCAL_META_U64)
                .map_err(redb_unavailable)?;
            table
                .get(META_GENERATION)
                .map_err(redb_unavailable)?
                .map(|value| value.value())
                .ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "local crypto authority generation is missing".to_owned(),
                    )
                })?
        };
        if generation == 0 {
            return Err(SecureStoreError::Integrity(
                "local crypto authority generation is zero".to_owned(),
            ));
        }
        let records = {
            let table = transaction
                .open_table(LOCAL_OBJECTS)
                .map_err(redb_unavailable)?;
            collect_records(&table, self)?
        };
        let staging = {
            let table = transaction
                .open_table(LOCAL_STAGING)
                .map_err(redb_unavailable)?;
            collect_staging(&table, self)?
        };
        let requests = {
            let table = transaction
                .open_table(LOCAL_REQUESTS)
                .map_err(redb_unavailable)?;
            collect_local_requests(&table)?
        };
        validate_local_inventory(&records, &staging, &requests)?;
        let state_root = local_state_root(&records, &staging, &requests)?;
        let catalog_root = local_catalog_root(&records)?;
        let (current, expected_record) = {
            let table = transaction
                .open_table(LOCAL_GENERATIONS)
                .map_err(redb_unavailable)?;
            if table.len().map_err(redb_unavailable)? != generation {
                return Err(SecureStoreError::Integrity(
                    "local authority generation history has gaps or extras".to_owned(),
                ));
            }
            let mut previous: Option<StateRootV2> = None;
            let mut current = None;
            let mut expected_record = None;
            for sequence in 1..=generation {
                let bytes = table
                    .get(sequence)
                    .map_err(redb_unavailable)?
                    .ok_or_else(|| {
                        SecureStoreError::Integrity(
                            "local authority generation history has a gap".to_owned(),
                        )
                    })?;
                let record: LocalGenerationRecordV1 =
                    decode_bounded(bytes.value(), MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1)?;
                record.validate(
                    sequence,
                    previous.as_ref(),
                    &self.namespace,
                    &self.master_key,
                )?;
                if expected_anchor.is_some_and(|anchor| anchor.generation == sequence) {
                    expected_record = Some(record.clone());
                }
                previous = Some(record.chain_root.clone());
                current = Some(record);
            }
            (
                current.ok_or_else(|| {
                    SecureStoreError::Integrity(
                        "local authority current generation is missing".to_owned(),
                    )
                })?,
                expected_record,
            )
        };
        if current.state_root != state_root || current.catalog_root != catalog_root {
            return Err(SecureStoreError::Integrity(
                "local authority table roots differ from authenticated head".to_owned(),
            ));
        }
        if let Some(expected) = expected_anchor {
            expected.validate()?;
            if expected.generation > generation {
                return Err(SecureStoreError::Integrity(
                    "local authority database was rolled back behind caller custody".to_owned(),
                ));
            }
            let observed = expected_record.ok_or_else(|| {
                SecureStoreError::Integrity(
                    "caller-custodied local authority generation is missing".to_owned(),
                )
            })?;
            let observed_anchor = observed.anchor();
            if observed_anchor.generation != expected.generation
                || observed_anchor.state_root != expected.state_root
                || observed_anchor.catalog_root != expected.catalog_root
                || observed_anchor.chain_root != expected.chain_root
                || !constant_time_equal(
                    observed_anchor.authentication_tag.as_str().as_bytes(),
                    expected.authentication_tag.as_str().as_bytes(),
                )
            {
                return Err(SecureStoreError::Integrity(
                    "local authority rollback anchor diverged".to_owned(),
                ));
            }
        }
        Ok(VerifiedLocalStateV1 {
            records,
            staging,
            requests,
            generation,
            anchor: current.anchor(),
        })
    }

    fn exact_existing_object(
        &self,
        request: &LocalObjectSealRequestV1,
    ) -> Result<Option<LocalObjectRecordV1>> {
        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        let Some(record) = state.records.get(request.intent().content_handle()) else {
            if let Some(binding) = state.requests.get(request.request_id()) {
                let stage_matches = state.staging.values().any(|stage| {
                    stage.request == *request
                        && stage.request.intent().content_handle()
                            == request.intent().content_handle()
                });
                if binding.kind != LocalRequestKindV1::Create
                    || binding.commitment != request.commitment()?
                    || binding.content_handle != *request.intent().content_handle()
                    || !stage_matches
                {
                    return Err(SecureStoreError::StateConflict(
                        "local create request is bound to another recovery intent".to_owned(),
                    ));
                }
            }
            return Ok(None);
        };
        let expected = request.commitment()?;
        let binding = state.requests.get(request.request_id()).ok_or_else(|| {
            SecureStoreError::Integrity("local object lacks its create request binding".to_owned())
        })?;
        if binding.kind != LocalRequestKindV1::Create
            || binding.commitment != expected
            || binding.content_handle != *request.intent().content_handle()
            || record.request != *request
        {
            return Err(SecureStoreError::StateConflict(
                "local create request or object handle is bound to another intent".to_owned(),
            ));
        }
        if record.current_descriptor.lifecycle() != KeyLifecycleV2::Active {
            return Err(SecureStoreError::KeyUnavailable);
        }
        Ok(Some(record.clone()))
    }

    fn verify_retry_plaintext(&self, record: &LocalObjectRecordV1, plaintext: &[u8]) -> Result<()> {
        let wrapped = record
            .wrapped_dek
            .as_ref()
            .ok_or(SecureStoreError::KeyUnavailable)?;
        let dek = self.unwrap_key(
            wrapped,
            &wrap_aad(
                &self.namespace,
                &record.object.request_commitment,
                record.object.initial_key.key_handle().as_str(),
                "object-dek",
            )?,
        )?;
        let existing = open_bytes(
            &dek,
            record.object.sealed_payload(),
            &record.object.associated_data()?,
        )?;
        if !constant_time_equal(existing.as_slice(), plaintext) {
            return Err(SecureStoreError::StateConflict(
                "local create retry supplied different source material".to_owned(),
            ));
        }
        Ok(())
    }

    fn stage_source_if_needed(
        &self,
        request: &LocalObjectSealRequestV1,
        plaintext: &[u8],
    ) -> Result<()> {
        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        let source_handle = request.intent().source_material_handle();
        if let Some(existing) = state.staging.get(source_handle) {
            if existing.request != *request {
                return Err(SecureStoreError::StateConflict(
                    "local source handle is bound to another staging intent".to_owned(),
                ));
            }
            let recovered = self.open_staged(existing)?;
            if !constant_time_equal(recovered.as_slice(), plaintext) {
                return Err(SecureStoreError::StateConflict(
                    "local staging retry supplied different source material".to_owned(),
                ));
            }
            return Ok(());
        }
        if state
            .records
            .contains_key(request.intent().content_handle())
            || state.requests.contains_key(request.request_id())
            || state.staging.values().any(|stage| {
                stage.request.intent().content_handle() == request.intent().content_handle()
            })
        {
            return Err(SecureStoreError::StateConflict(
                "local create identity is already bound".to_owned(),
            ));
        }
        let mut staging_key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(staging_key.as_mut())
            .map_err(|_| SecureStoreError::CryptographicFailure)?;
        let request_commitment = request.commitment()?;
        let stage_aad = staging_aad(request, &request_commitment)?;
        let encrypted_source = seal_bytes(&staging_key, plaintext, &stage_aad)?;
        let wrapped_staging_key = self.wrap_key(
            &staging_key,
            &wrap_aad(
                &self.namespace,
                &request_commitment,
                source_handle.as_str(),
                "staging-key",
            )?,
        )?;
        let stage = LocalStagingRecordV1 {
            request: request.clone(),
            wrapped_staging_key,
            encrypted_source,
        };
        stage.validate()?;
        let binding = LocalRequestBindingV1 {
            kind: LocalRequestKindV1::Create,
            commitment: request_commitment,
            content_handle: request.intent().content_handle().clone(),
        };
        let mut next_staging = state.staging.clone();
        next_staging.insert(source_handle.clone(), stage.clone());
        let mut next_requests = state.requests.clone();
        next_requests.insert(request.request_id().clone(), binding.clone());
        let next = self.next_generation(&state, &state.records, &next_staging, &next_requests)?;
        let stage_bytes = self.encrypt_persisted_record(
            "source-staging",
            source_handle.as_str(),
            &stage,
            MAX_LOCAL_DECRYPTED_STAGING_RECORD_JSON_BYTES_V1,
            MAX_LOCAL_STAGING_RECORD_JSON_BYTES_V1,
        )?;
        let binding_bytes = encode_bounded(&binding, MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1)?;
        let generation_bytes = encode_bounded(&next, MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1)?;
        let mut transaction = database.begin_write().map_err(redb_unavailable)?;
        self.require_generation(&transaction, state.generation)?;
        transaction
            .open_table(LOCAL_STAGING)
            .map_err(redb_unavailable)?
            .insert(source_handle.as_str().as_bytes(), stage_bytes.as_slice())
            .map_err(redb_unavailable)?;
        transaction
            .open_table(LOCAL_REQUESTS)
            .map_err(redb_unavailable)?
            .insert(
                request.request_id().as_str().as_bytes(),
                binding_bytes.as_slice(),
            )
            .map_err(redb_unavailable)?;
        self.write_generation(&mut transaction, &next, &generation_bytes)?;
        commit_immediate(transaction)
    }

    fn open_staged(&self, stage: &LocalStagingRecordV1) -> Result<Zeroizing<Vec<u8>>> {
        stage.validate()?;
        let commitment = stage.request.commitment()?;
        let key = self.unwrap_key(
            &stage.wrapped_staging_key,
            &wrap_aad(
                &self.namespace,
                &commitment,
                stage.request.intent().source_material_handle().as_str(),
                "staging-key",
            )?,
        )?;
        open_bytes(
            &key,
            &stage.encrypted_source,
            &staging_aad(&stage.request, &commitment)?,
        )
    }

    fn finalize_staged(
        &self,
        source_material_handle: &SourceMaterialHandleV2,
    ) -> Result<LocalSealedObjectV1> {
        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        let stage = state
            .staging
            .get(source_material_handle)
            .cloned()
            .ok_or_else(|| {
                SecureStoreError::StateConflict(
                    "encrypted source staging record is missing".to_owned(),
                )
            })?;
        let request = &stage.request;
        let binding = state.requests.get(request.request_id()).ok_or_else(|| {
            SecureStoreError::Integrity("staging record lacks request binding".to_owned())
        })?;
        if binding.kind != LocalRequestKindV1::Create
            || binding.commitment != request.commitment()?
            || binding.content_handle != *request.intent().content_handle()
        {
            return Err(SecureStoreError::Integrity(
                "staging request binding changed".to_owned(),
            ));
        }
        if state
            .records
            .contains_key(request.intent().content_handle())
        {
            return Err(SecureStoreError::StateConflict(
                "staged destination object already exists".to_owned(),
            ));
        }
        let plaintext = self.open_staged(&stage)?;
        let record = self.build_final_record(request, plaintext.as_slice(), &state.records)?;
        let mut next_records = state.records.clone();
        next_records.insert(request.intent().content_handle().clone(), record.clone());
        let mut next_staging = state.staging.clone();
        next_staging.remove(source_material_handle);
        let next = self.next_generation(&state, &next_records, &next_staging, &state.requests)?;
        let record_bytes = self.encrypt_persisted_record(
            "object-record",
            request.intent().content_handle().as_str(),
            &record,
            MAX_LOCAL_DECRYPTED_OBJECT_RECORD_JSON_BYTES_V1,
            MAX_LOCAL_OBJECT_RECORD_JSON_BYTES_V1,
        )?;
        let generation_bytes = encode_bounded(&next, MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1)?;
        let mut transaction = database.begin_write().map_err(redb_unavailable)?;
        self.require_generation(&transaction, state.generation)?;
        transaction
            .open_table(LOCAL_OBJECTS)
            .map_err(redb_unavailable)?
            .insert(
                request.intent().content_handle().as_str().as_bytes(),
                record_bytes.as_slice(),
            )
            .map_err(redb_unavailable)?;
        transaction
            .open_table(LOCAL_STAGING)
            .map_err(redb_unavailable)?
            .remove(source_material_handle.as_str().as_bytes())
            .map_err(redb_unavailable)?;
        self.write_generation(&mut transaction, &next, &generation_bytes)?;
        commit_immediate(transaction)?;
        Ok(record.object)
    }

    fn build_final_record(
        &self,
        request: &LocalObjectSealRequestV1,
        plaintext: &[u8],
        existing_records: &BTreeMap<ContentHandleV2, LocalObjectRecordV1>,
    ) -> Result<LocalObjectRecordV1> {
        let mut dek = Zeroizing::new([0_u8; 32]);
        getrandom::fill(dek.as_mut()).map_err(|_| SecureStoreError::CryptographicFailure)?;
        let key_handle = (0..8)
            .find_map(|_| {
                let candidate = KeyHandleV2::generate().ok()?;
                (!existing_records
                    .values()
                    .any(|record| record.current_descriptor.key_handle() == &candidate))
                .then_some(candidate)
            })
            .ok_or(SecureStoreError::CryptographicFailure)?;
        let descriptor = KeyDescriptorV2::authority_active(key_handle, request.dek_scope()?)?;
        let object_without_sealed = LocalSealedObjectV1 {
            format_version: SECURE_STORE_FORMAT_VERSION,
            request_commitment: request.commitment()?,
            lifecycle_commitment: request.lifecycle().commitment()?,
            source_material_handle: request.intent().source_material_handle().clone(),
            content_handle: request.intent().content_handle().clone(),
            initial_key: descriptor.clone(),
            lifecycle: request.lifecycle().clone(),
            deletion_targets: request.deletion_targets().clone(),
            // Shape-valid placeholder used only to derive AAD; it is replaced
            // before validation and is never persisted.
            sealed: SealedPayloadV2::try_new(vec![0_u8; 24], vec![0_u8; 17])?,
        };
        let sealed = seal_bytes(&dek, plaintext, &object_without_sealed.associated_data()?)?;
        let object = LocalSealedObjectV1::new(request, descriptor.clone(), sealed)?;
        let wrapped_dek = self.wrap_key(
            &dek,
            &wrap_aad(
                &self.namespace,
                &object.request_commitment,
                descriptor.key_handle().as_str(),
                "object-dek",
            )?,
        )?;
        LocalObjectRecordV1::active(request.clone(), object, wrapped_dek)
    }

    fn wrap_key(&self, key: &[u8; 32], associated_data: &[u8]) -> Result<SealedPayloadV2> {
        seal_bytes(self.master_key.bytes(), key, associated_data)
    }

    fn encrypt_persisted_record<T: Serialize>(
        &self,
        table_domain: &str,
        opaque_key: &str,
        value: &T,
        plaintext_limit: usize,
        envelope_limit: usize,
    ) -> Result<Vec<u8>> {
        let plaintext = Zeroizing::new(encode_bounded(value, plaintext_limit)?);
        let sealed = seal_bytes(
            self.master_key.bytes(),
            &plaintext,
            &persisted_record_aad(&self.namespace, table_domain, opaque_key)?,
        )?;
        encode_persisted_envelope(&sealed, envelope_limit)
    }

    fn decrypt_persisted_record<T>(
        &self,
        table_domain: &str,
        opaque_key: &str,
        bytes: &[u8],
        envelope_limit: usize,
        plaintext_limit: usize,
    ) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let envelope = decode_persisted_envelope(bytes, envelope_limit)?;
        let plaintext = open_bytes(
            self.master_key.bytes(),
            &envelope,
            &persisted_record_aad(&self.namespace, table_domain, opaque_key)?,
        )?;
        decode_bounded(&plaintext, plaintext_limit)
    }

    fn unwrap_key(
        &self,
        wrapped: &SealedPayloadV2,
        associated_data: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut plaintext = open_bytes(self.master_key.bytes(), wrapped, associated_data)?;
        if plaintext.len() != 32 {
            return Err(SecureStoreError::CryptographicFailure);
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(key)
    }

    fn next_generation(
        &self,
        state: &VerifiedLocalStateV1,
        records: &BTreeMap<ContentHandleV2, LocalObjectRecordV1>,
        staging: &BTreeMap<SourceMaterialHandleV2, LocalStagingRecordV1>,
        requests: &BTreeMap<OperationRequestIdV2, LocalRequestBindingV1>,
    ) -> Result<LocalGenerationRecordV1> {
        let generation = state.generation.checked_add(1).ok_or_else(|| {
            SecureStoreError::StateConflict("local authority generation exhausted".to_owned())
        })?;
        LocalGenerationRecordV1::new(
            generation,
            local_state_root(records, staging, requests)?,
            local_catalog_root(records)?,
            Some(state.anchor.chain_root.clone()),
            &self.namespace,
            &self.master_key,
        )
    }

    fn require_generation(
        &self,
        transaction: &redb::WriteTransaction,
        expected: u64,
    ) -> Result<()> {
        let observed = transaction
            .open_table(LOCAL_META_U64)
            .map_err(redb_unavailable)?
            .get(META_GENERATION)
            .map_err(redb_unavailable)?
            .map(|value| value.value())
            .ok_or_else(|| {
                SecureStoreError::Integrity(
                    "local authority generation vanished before mutation".to_owned(),
                )
            })?;
        if observed != expected {
            return Err(SecureStoreError::StateConflict(
                "local authority generation changed during mutation".to_owned(),
            ));
        }
        Ok(())
    }

    fn write_generation(
        &self,
        transaction: &mut redb::WriteTransaction,
        generation: &LocalGenerationRecordV1,
        encoded: &[u8],
    ) -> Result<()> {
        transaction
            .open_table(LOCAL_GENERATIONS)
            .map_err(redb_unavailable)?
            .insert(generation.generation, encoded)
            .map_err(redb_unavailable)?;
        transaction
            .open_table(LOCAL_META_U64)
            .map_err(redb_unavailable)?
            .insert(META_GENERATION, generation.generation)
            .map_err(redb_unavailable)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn stage_only_for_process_kill_test(
        &self,
        request: &LocalObjectSealRequestV1,
        plaintext: &[u8],
    ) -> Result<()> {
        self.stage_source_if_needed(request, plaintext)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_object_value_for_test(&self) -> Result<()> {
        let database = self.lock_database()?;
        let transaction = database.begin_write().map_err(redb_unavailable)?;
        let (key, mut value) = {
            let table = transaction
                .open_table(LOCAL_OBJECTS)
                .map_err(redb_unavailable)?;
            let item = table
                .iter()
                .map_err(redb_unavailable)?
                .next()
                .ok_or_else(|| {
                    SecureStoreError::StateConflict("test object record is missing".to_owned())
                })?
                .map_err(redb_unavailable)?;
            (item.0.value().to_vec(), item.1.value().to_vec())
        };
        let byte = value
            .last_mut()
            .ok_or_else(|| SecureStoreError::Integrity("test object record is empty".to_owned()))?;
        *byte ^= 1;
        transaction
            .open_table(LOCAL_OBJECTS)
            .map_err(redb_unavailable)?
            .insert(key.as_slice(), value.as_slice())
            .map_err(redb_unavailable)?;
        commit_immediate(transaction)
    }

    #[cfg(test)]
    pub(crate) fn hold_after_key_allocation_for_process_kill_test(
        &self,
        source_material_handle: &SourceMaterialHandleV2,
    ) -> Result<()> {
        use std::io::Write as _;

        let database = self.lock_database()?;
        let state = self.verify_database(&database, None)?;
        let stage = state.staging.get(source_material_handle).ok_or_else(|| {
            SecureStoreError::StateConflict("test staging record is missing".to_owned())
        })?;
        let plaintext = self.open_staged(stage)?;
        let record = self.build_final_record(&stage.request, &plaintext, &state.records)?;
        let mut next_records = state.records.clone();
        next_records.insert(
            stage.request.intent().content_handle().clone(),
            record.clone(),
        );
        let mut next_staging = state.staging.clone();
        next_staging.remove(source_material_handle);
        let next = self.next_generation(&state, &next_records, &next_staging, &state.requests)?;
        let record_bytes = self.encrypt_persisted_record(
            "object-record",
            stage.request.intent().content_handle().as_str(),
            &record,
            MAX_LOCAL_DECRYPTED_OBJECT_RECORD_JSON_BYTES_V1,
            MAX_LOCAL_OBJECT_RECORD_JSON_BYTES_V1,
        )?;
        let generation_bytes = encode_bounded(&next, MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1)?;
        let mut transaction = database.begin_write().map_err(redb_unavailable)?;
        self.require_generation(&transaction, state.generation)?;
        transaction
            .open_table(LOCAL_OBJECTS)
            .map_err(redb_unavailable)?
            .insert(
                stage.request.intent().content_handle().as_str().as_bytes(),
                record_bytes.as_slice(),
            )
            .map_err(redb_unavailable)?;
        transaction
            .open_table(LOCAL_STAGING)
            .map_err(redb_unavailable)?
            .remove(source_material_handle.as_str().as_bytes())
            .map_err(redb_unavailable)?;
        self.write_generation(&mut transaction, &next, &generation_bytes)?;
        println!("CONTEXTDB_LOCAL_DEK_ALLOCATED_UNCOMMITTED");
        std::io::stdout().flush().map_err(|_| {
            SecureStoreError::StateConflict("test process stdout is unavailable".to_owned())
        })?;
        loop {
            std::thread::park();
        }
    }
}

impl fmt::Debug for RedbLocalCryptoAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedbLocalCryptoAuthorityV1")
            .field("namespace", &self.namespace)
            .field("master_key", &"[REDACTED]")
            .field("store_salt", &"[PUBLIC RANDOM BINDING]")
            .finish_non_exhaustive()
    }
}

fn collect_records<T>(
    table: &T,
    authority: &RedbLocalCryptoAuthorityV1,
) -> Result<BTreeMap<ContentHandleV2, LocalObjectRecordV1>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut records = BTreeMap::new();
    for item in table.iter().map_err(redb_unavailable)? {
        let (key, value) = item.map_err(redb_unavailable)?;
        let handle = parse_content_key(key.value())?;
        let record: LocalObjectRecordV1 = authority.decrypt_persisted_record(
            "object-record",
            handle.as_str(),
            value.value(),
            MAX_LOCAL_OBJECT_RECORD_JSON_BYTES_V1,
            MAX_LOCAL_DECRYPTED_OBJECT_RECORD_JSON_BYTES_V1,
        )?;
        record.validate()?;
        if record.request.intent().content_handle() != &handle
            || record.object.content_handle() != &handle
            || records.insert(handle, record).is_some()
        {
            return Err(SecureStoreError::Integrity(
                "local object key or uniqueness is invalid".to_owned(),
            ));
        }
    }
    Ok(records)
}

fn collect_staging<T>(
    table: &T,
    authority: &RedbLocalCryptoAuthorityV1,
) -> Result<BTreeMap<SourceMaterialHandleV2, LocalStagingRecordV1>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut staging = BTreeMap::new();
    for item in table.iter().map_err(redb_unavailable)? {
        let (key, value) = item.map_err(redb_unavailable)?;
        let handle = parse_source_key(key.value())?;
        let record: LocalStagingRecordV1 = authority.decrypt_persisted_record(
            "source-staging",
            handle.as_str(),
            value.value(),
            MAX_LOCAL_STAGING_RECORD_JSON_BYTES_V1,
            MAX_LOCAL_DECRYPTED_STAGING_RECORD_JSON_BYTES_V1,
        )?;
        record.validate()?;
        if record.request.intent().source_material_handle() != &handle
            || staging.insert(handle, record).is_some()
        {
            return Err(SecureStoreError::Integrity(
                "local staging key or uniqueness is invalid".to_owned(),
            ));
        }
    }
    Ok(staging)
}

fn collect_local_requests<T>(
    table: &T,
) -> Result<BTreeMap<OperationRequestIdV2, LocalRequestBindingV1>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut requests = BTreeMap::new();
    for item in table.iter().map_err(redb_unavailable)? {
        let (key, value) = item.map_err(redb_unavailable)?;
        let request_id = parse_request_key(key.value())?;
        let binding: LocalRequestBindingV1 =
            decode_bounded(value.value(), MAX_LOCAL_AUTHORITY_HEAD_JSON_BYTES_V1)?;
        if requests.insert(request_id, binding).is_some() {
            return Err(SecureStoreError::Integrity(
                "local request binding is duplicated".to_owned(),
            ));
        }
    }
    Ok(requests)
}

fn validate_local_inventory(
    records: &BTreeMap<ContentHandleV2, LocalObjectRecordV1>,
    staging: &BTreeMap<SourceMaterialHandleV2, LocalStagingRecordV1>,
    requests: &BTreeMap<OperationRequestIdV2, LocalRequestBindingV1>,
) -> Result<()> {
    let mut expected = BTreeMap::new();
    let mut scopes = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for (handle, record) in records {
        record.validate()?;
        if !scopes.insert(record.object.initial_key.scope().clone())
            || !sources.insert(record.object.source_material_handle.clone())
        {
            return Err(SecureStoreError::Integrity(
                "local object catalog duplicates a DEK scope or source handle".to_owned(),
            ));
        }
        insert_expected_binding(
            &mut expected,
            record.request.request_id().clone(),
            LocalRequestBindingV1 {
                kind: LocalRequestKindV1::Create,
                commitment: record.request.commitment()?,
                content_handle: handle.clone(),
            },
        )?;
        if let (Some(request_id), Some(commitment)) =
            (&record.destroy_request_id, &record.destroy_commitment)
        {
            insert_expected_binding(
                &mut expected,
                request_id.clone(),
                LocalRequestBindingV1 {
                    kind: LocalRequestKindV1::Destroy,
                    commitment: commitment.clone(),
                    content_handle: handle.clone(),
                },
            )?;
        }
    }
    for (source_handle, stage) in staging {
        stage.validate()?;
        if records.contains_key(stage.request.intent().content_handle())
            || !scopes.insert(stage.request.dek_scope()?)
            || !sources.insert(source_handle.clone())
        {
            return Err(SecureStoreError::Integrity(
                "local staging overlaps a durable object or another scope".to_owned(),
            ));
        }
        insert_expected_binding(
            &mut expected,
            stage.request.request_id().clone(),
            LocalRequestBindingV1 {
                kind: LocalRequestKindV1::Create,
                commitment: stage.request.commitment()?,
                content_handle: stage.request.intent().content_handle().clone(),
            },
        )?;
    }
    if &expected != requests {
        return Err(SecureStoreError::Integrity(
            "local idempotency bindings are missing or orphaned".to_owned(),
        ));
    }
    Ok(())
}

fn insert_expected_binding(
    expected: &mut BTreeMap<OperationRequestIdV2, LocalRequestBindingV1>,
    request_id: OperationRequestIdV2,
    binding: LocalRequestBindingV1,
) -> Result<()> {
    if expected.insert(request_id, binding).is_some() {
        return Err(SecureStoreError::Integrity(
            "one local request identity is reused across operations".to_owned(),
        ));
    }
    Ok(())
}

fn local_state_root(
    records: &BTreeMap<ContentHandleV2, LocalObjectRecordV1>,
    staging: &BTreeMap<SourceMaterialHandleV2, LocalStagingRecordV1>,
    requests: &BTreeMap<OperationRequestIdV2, LocalRequestBindingV1>,
) -> Result<StateRootV2> {
    #[derive(Serialize)]
    struct State<'a> {
        records: Vec<(&'a ContentHandleV2, &'a LocalObjectRecordV1)>,
        staging: Vec<(&'a SourceMaterialHandleV2, &'a LocalStagingRecordV1)>,
        requests: Vec<(&'a OperationRequestIdV2, &'a LocalRequestBindingV1)>,
    }
    StateRootV2::commit(
        "local-crypto-authority-state-v1",
        &canonical_json(&State {
            records: records.iter().collect(),
            staging: staging.iter().collect(),
            requests: requests.iter().collect(),
        })?,
    )
}

fn local_catalog_root(
    records: &BTreeMap<ContentHandleV2, LocalObjectRecordV1>,
) -> Result<StateRootV2> {
    KeyCatalogSnapshotV2::try_new(
        records
            .values()
            .map(|record| record.current_descriptor.clone())
            .collect(),
    )?
    .root()
}

fn staging_aad(request: &LocalObjectSealRequestV1, commitment: &StateRootV2) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Subject<'a> {
        request_commitment: &'a StateRootV2,
        source_material_handle: &'a SourceMaterialHandleV2,
        content_handle: &'a ContentHandleV2,
        lifecycle_commitment: StateRootV2,
        deletion_target: &'a DeletionTargetHandleV2,
    }
    domain_message(
        b"contextdb/encrypted-source-staging/v1\0",
        &canonical_json(&Subject {
            request_commitment: commitment,
            source_material_handle: request.intent().source_material_handle(),
            content_handle: request.intent().content_handle(),
            lifecycle_commitment: request.lifecycle().commitment()?,
            deletion_target: request.deletion_targets().staged_source(),
        })?,
    )
}

fn wrap_aad(
    namespace: &StateNamespaceV2,
    request_commitment: &StateRootV2,
    opaque_target: &str,
    purpose: &str,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Subject<'a> {
        namespace: &'a StateNamespaceV2,
        request_commitment: &'a StateRootV2,
        opaque_target: &'a str,
        purpose: &'a str,
    }
    domain_message(
        b"contextdb/local-key-wrap/v1\0",
        &canonical_json(&Subject {
            namespace,
            request_commitment,
            opaque_target,
            purpose,
        })?,
    )
}

fn persisted_record_aad(
    namespace: &StateNamespaceV2,
    table_domain: &str,
    opaque_key: &str,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Subject<'a> {
        namespace: &'a StateNamespaceV2,
        table_domain: &'a str,
        opaque_key: &'a str,
    }
    domain_message(
        b"contextdb/local-persisted-record/v1\0",
        &canonical_json(&Subject {
            namespace,
            table_domain,
            opaque_key,
        })?,
    )
}

fn encode_persisted_envelope(payload: &SealedPayloadV2, maximum: usize) -> Result<Vec<u8>> {
    const MAGIC: &[u8; 8] = b"CDBLCR1\0";
    let total = MAGIC
        .len()
        .checked_add(payload.nonce().len())
        .and_then(|value| value.checked_add(payload.ciphertext().len()))
        .ok_or_else(|| {
            SecureStoreError::InvalidInput("local encrypted record length overflow".to_owned())
        })?;
    if total > maximum {
        return Err(SecureStoreError::InvalidInput(
            "local encrypted record exceeds its persisted bound".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(payload.nonce());
    bytes.extend_from_slice(payload.ciphertext());
    Ok(bytes)
}

fn decode_persisted_envelope(bytes: &[u8], maximum: usize) -> Result<SealedPayloadV2> {
    const MAGIC: &[u8; 8] = b"CDBLCR1\0";
    const HEADER: usize = 8 + 24;
    if bytes.len() > maximum || bytes.len() <= HEADER + 16 || !bytes.starts_with(MAGIC) {
        return Err(SecureStoreError::Integrity(
            "local encrypted record envelope is invalid".to_owned(),
        ));
    }
    SealedPayloadV2::try_new(bytes[8..HEADER].to_vec(), bytes[HEADER..].to_vec())
}

fn domain_message(domain: &[u8], canonical: &[u8]) -> Result<Vec<u8>> {
    if domain.is_empty() || canonical.is_empty() {
        return Err(SecureStoreError::InvalidInput(
            "local cryptographic domain or binding is empty".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(
        domain
            .len()
            .saturating_add(8)
            .saturating_add(canonical.len()),
    );
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    bytes.extend_from_slice(canonical);
    Ok(bytes)
}

fn seal_bytes(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<SealedPayloadV2> {
    if plaintext.is_empty() || associated_data.is_empty() {
        return Err(SecureStoreError::InvalidInput(
            "local encryption requires non-empty content and associated data".to_owned(),
        ));
    }
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SecureStoreError::CryptographicFailure)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| SecureStoreError::CryptographicFailure)?;
    SealedPayloadV2::try_new(nonce.to_vec(), ciphertext)
}

fn open_bytes(
    key: &[u8; 32],
    payload: &SealedPayloadV2,
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if associated_data.is_empty() {
        return Err(SecureStoreError::InvalidInput(
            "local decryption requires associated data".to_owned(),
        ));
    }
    let nonce: [u8; 24] = payload
        .nonce()
        .try_into()
        .map_err(|_| SecureStoreError::CryptographicFailure)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: payload.ciphertext(),
                aad: associated_data,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SecureStoreError::CryptographicFailure)
}

fn master_binding(
    master_key: &LocalMasterKeyV1,
    namespace: &StateNamespaceV2,
    salt: &[u8; 32],
) -> Result<[u8; 32]> {
    let message = domain_message(
        b"contextdb/local-master-binding/v1\0",
        &canonical_json(&(namespace, salt.as_slice()))?,
    )?;
    Ok(*blake3::keyed_hash(master_key.bytes(), &message).as_bytes())
}

fn keyed_state_root(
    master_key: &LocalMasterKeyV1,
    domain: &str,
    canonical: &[u8],
) -> Result<StateRootV2> {
    let message = domain_message(domain.as_bytes(), canonical)?;
    StateRootV2::parse(encode_hex(
        blake3::keyed_hash(master_key.bytes(), &message).as_bytes(),
    ))
}

fn validate_plaintext(plaintext: &[u8]) -> Result<()> {
    if plaintext.is_empty() || plaintext.len() > crate::MAX_ENCRYPTED_CONTENT_BYTES {
        return Err(SecureStoreError::InvalidInput(
            "local encrypted content size is outside the supported range".to_owned(),
        ));
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let maximum = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..maximum {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

fn parse_content_key(bytes: &[u8]) -> Result<ContentHandleV2> {
    ContentHandleV2::parse(parse_opaque_utf8(bytes)?)
}

fn parse_source_key(bytes: &[u8]) -> Result<SourceMaterialHandleV2> {
    SourceMaterialHandleV2::parse(parse_opaque_utf8(bytes)?)
}

fn parse_request_key(bytes: &[u8]) -> Result<OperationRequestIdV2> {
    OperationRequestIdV2::parse(parse_opaque_utf8(bytes)?)
}

fn parse_opaque_utf8(bytes: &[u8]) -> Result<String> {
    if bytes.len() > 256 {
        return Err(SecureStoreError::Integrity(
            "local opaque table key exceeds its recovery bound".to_owned(),
        ));
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| SecureStoreError::Integrity("local table key is not UTF-8".to_owned()))
}

fn copy_exact_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        SecureStoreError::Integrity("local 256-bit metadata has an invalid length".to_owned())
    })
}

fn bounded_copy(bytes: &[u8], maximum: usize) -> Result<Vec<u8>> {
    if bytes.len() > maximum {
        return Err(SecureStoreError::Integrity(
            "local persisted value exceeds its recovery bound".to_owned(),
        ));
    }
    Ok(bytes.to_vec())
}

fn encode_bounded<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| SecureStoreError::Serialization)?;
    if bytes.len() > maximum {
        return Err(SecureStoreError::InvalidInput(
            "local persisted value exceeds its encode bound".to_owned(),
        ));
    }
    Ok(bytes)
}

fn decode_bounded<T>(bytes: &[u8], maximum: usize) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    if bytes.len() > maximum {
        return Err(SecureStoreError::Integrity(
            "local persisted value exceeds its recovery bound".to_owned(),
        ));
    }
    serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)
}

fn commit_immediate(mut transaction: redb::WriteTransaction) -> Result<()> {
    transaction
        .set_durability(RedbDurability::Immediate)
        .map_err(redb_unavailable)?;
    transaction.commit().map_err(redb_unavailable)
}

fn redb_unavailable(error: impl fmt::Display) -> SecureStoreError {
    SecureStoreError::StateConflict(format!("local durable authority is unavailable: {error}"))
}
