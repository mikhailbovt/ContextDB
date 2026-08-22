use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    ContentHandleV2, ContentSecurityContextV2, DeletionTargetHandleV2, EncryptedContentHeaderV2,
    EncryptedContentV2, ErasureDomainV2, ExportHandleV2, KeyHandleV2, Result,
    SECURE_STORE_FORMAT_VERSION, SecureStoreError, StateNamespaceV2, StateRootV2,
};

/// Maximum descriptors in one streaming-export manifest page.
pub const MAX_CANONICAL_EXPORT_OBJECTS_V2: usize = 4_096;
/// Maximum encoded JSON bytes accepted for one export manifest page.
pub const MAX_CANONICAL_EXPORT_JSON_BYTES_V2: usize = 4 * 1024 * 1024;
/// Maximum ciphertext bytes in one independently decoded streaming chunk.
pub const MAX_EXPORT_CIPHERTEXT_CHUNK_BYTES_V2: usize = 1024 * 1024;

/// Ciphertext-stream descriptor for one encrypted object.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "ExportObjectDescriptorWireV2",
    into = "ExportObjectDescriptorWireV2"
)]
pub struct ExportObjectDescriptorV2 {
    header: EncryptedContentHeaderV2,
    erasure_domain: ErasureDomainV2,
    nonce: Vec<u8>,
    ciphertext_bytes: u64,
    ciphertext_commitment: StateRootV2,
}

impl ExportObjectDescriptorV2 {
    /// Describes an encrypted envelope without copying its ciphertext into the manifest.
    pub fn from_encrypted(envelope: &EncryptedContentV2) -> Result<Self> {
        let mut committed = Vec::with_capacity(
            8_usize
                .saturating_add(envelope.sealed_payload().nonce().len())
                .saturating_add(envelope.sealed_payload().ciphertext().len()),
        );
        committed
            .extend_from_slice(&(envelope.sealed_payload().nonce().len() as u64).to_be_bytes());
        committed.extend_from_slice(envelope.sealed_payload().nonce());
        committed.extend_from_slice(envelope.sealed_payload().ciphertext());
        let descriptor = Self {
            header: envelope.header().clone(),
            erasure_domain: envelope.header().key().scope().erasure_domain().clone(),
            nonce: envelope.sealed_payload().nonce().to_vec(),
            ciphertext_bytes: envelope.sealed_payload().ciphertext().len() as u64,
            ciphertext_commitment: StateRootV2::commit("export-ciphertext-v2", &committed)?,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Returns the opaque encrypted-content identity.
    #[must_use]
    pub fn content_handle(&self) -> &ContentHandleV2 {
        self.header.content_handle()
    }

    /// Returns the opaque DEK authority identity.
    #[must_use]
    pub fn key_handle(&self) -> &KeyHandleV2 {
        self.header.key().key_handle()
    }

    /// Returns the exact anti-relocation security context.
    #[must_use]
    pub fn security_context(&self) -> &ContentSecurityContextV2 {
        self.header.key().scope().security_context()
    }

    /// Returns the public AEAD nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns the exact expected ciphertext byte length.
    #[must_use]
    pub const fn ciphertext_bytes(&self) -> u64 {
        self.ciphertext_bytes
    }

    /// Returns a ciphertext—not plaintext—stream commitment.
    #[must_use]
    pub fn ciphertext_commitment(&self) -> &StateRootV2 {
        &self.ciphertext_commitment
    }

    fn validate(&self) -> Result<()> {
        if self.nonce.len() != 24
            || self.ciphertext_bytes <= 16
            || self.ciphertext_bytes > crate::MAX_ENCRYPTED_CONTENT_BYTES as u64 + 16
            || self.header.key().scope().erasure_domain() != &self.erasure_domain
        {
            return Err(SecureStoreError::Integrity(
                "export object descriptor is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ExportObjectDescriptorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportObjectDescriptorV2")
            .field("content_handle", &"[OPAQUE]")
            .field("key_handle", &"[OPAQUE]")
            .field("erasure_domain", &"[OPAQUE]")
            .field("ciphertext_bytes", &self.ciphertext_bytes)
            .field("ciphertext_commitment", &"[COMMITMENT]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportObjectDescriptorWireV2 {
    header: EncryptedContentHeaderV2,
    erasure_domain: ErasureDomainV2,
    #[serde(deserialize_with = "crate::bounded::nonce_24")]
    nonce: Vec<u8>,
    ciphertext_bytes: u64,
    ciphertext_commitment: StateRootV2,
}

impl TryFrom<ExportObjectDescriptorWireV2> for ExportObjectDescriptorV2 {
    type Error = SecureStoreError;

    fn try_from(value: ExportObjectDescriptorWireV2) -> Result<Self> {
        let descriptor = Self {
            header: value.header,
            erasure_domain: value.erasure_domain,
            nonce: value.nonce,
            ciphertext_bytes: value.ciphertext_bytes,
            ciphertext_commitment: value.ciphertext_commitment,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

impl From<ExportObjectDescriptorV2> for ExportObjectDescriptorWireV2 {
    fn from(value: ExportObjectDescriptorV2) -> Self {
        Self {
            header: value.header,
            erasure_domain: value.erasure_domain,
            nonce: value.nonce,
            ciphertext_bytes: value.ciphertext_bytes,
            ciphertext_commitment: value.ciphertext_commitment,
        }
    }
}

/// Canonical streaming export manifest with no plaintext or ciphertext bodies.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct CanonicalExportV2 {
    format_version: u16,
    export_handle: ExportHandleV2,
    managed_copy_target: DeletionTargetHandleV2,
    namespace: StateNamespaceV2,
    state_head_root: StateRootV2,
    created_at_micros: u64,
    encrypted_objects: Vec<ExportObjectDescriptorV2>,
}

impl CanonicalExportV2 {
    /// Creates a bounded manifest from ciphertext-stream descriptors.
    pub fn new(
        namespace: StateNamespaceV2,
        state_head_root: StateRootV2,
        created_at_micros: u64,
        encrypted_objects: Vec<ExportObjectDescriptorV2>,
    ) -> Result<Self> {
        let export = Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            export_handle: ExportHandleV2::generate()?,
            managed_copy_target: DeletionTargetHandleV2::generate()?,
            namespace,
            state_head_root,
            created_at_micros,
            encrypted_objects,
        };
        export.validate()?;
        Ok(export)
    }

    /// Creates a manifest page from encrypted objects without retaining their bodies.
    pub fn from_encrypted(
        namespace: StateNamespaceV2,
        state_head_root: StateRootV2,
        created_at_micros: u64,
        encrypted_objects: &[EncryptedContentV2],
    ) -> Result<Self> {
        let descriptors = encrypted_objects
            .iter()
            .map(ExportObjectDescriptorV2::from_encrypted)
            .collect::<Result<Vec<_>>>()?;
        Self::new(namespace, state_head_root, created_at_micros, descriptors)
    }

    /// Decodes only a realistically bounded manifest buffer.
    pub fn from_json_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CANONICAL_EXPORT_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "canonical export manifest exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: CanonicalExportWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        Self::try_from(wire)
    }

    /// Returns the opaque export identity.
    #[must_use]
    pub fn export_handle(&self) -> &ExportHandleV2 {
        &self.export_handle
    }

    /// Returns the deletion-closure target representing this managed copy.
    #[must_use]
    pub fn managed_copy_target(&self) -> &DeletionTargetHandleV2 {
        &self.managed_copy_target
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the bound composite state-head root.
    #[must_use]
    pub fn state_head_root(&self) -> &StateRootV2 {
        &self.state_head_root
    }

    /// Returns streaming descriptors; ciphertext bodies travel in bounded chunks.
    #[must_use]
    pub fn encrypted_objects(&self) -> &[ExportObjectDescriptorV2] {
        &self.encrypted_objects
    }

    fn validate(&self) -> Result<()> {
        if self.format_version != SECURE_STORE_FORMAT_VERSION
            || self.encrypted_objects.is_empty()
            || self.encrypted_objects.len() > MAX_CANONICAL_EXPORT_OBJECTS_V2
        {
            return Err(SecureStoreError::Integrity(
                "canonical export version or descriptor count is invalid".to_owned(),
            ));
        }
        let mut handles = BTreeSet::new();
        for object in &self.encrypted_objects {
            object.validate()?;
            let context = object.security_context();
            if context.database_id() != self.namespace.database_id()
                || context.workspace_id() != self.namespace.workspace_id()
            {
                return Err(SecureStoreError::Integrity(
                    "exported ciphertext belongs to another database or workspace".to_owned(),
                ));
            }
            if !handles.insert(object.content_handle().clone()) {
                return Err(SecureStoreError::Integrity(
                    "canonical export contains a duplicate content handle".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CanonicalExportV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalExportV2")
            .field("format_version", &self.format_version)
            .field("export_handle", &"[OPAQUE]")
            .field("managed_copy_target", &"[OPAQUE]")
            .field("namespace", &self.namespace)
            .field("state_head_root", &"[COMMITMENT]")
            .field("created_at_micros", &self.created_at_micros)
            .field("encrypted_object_count", &self.encrypted_objects.len())
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalExportWireV2 {
    format_version: u16,
    export_handle: ExportHandleV2,
    managed_copy_target: DeletionTargetHandleV2,
    namespace: StateNamespaceV2,
    state_head_root: StateRootV2,
    created_at_micros: u64,
    encrypted_objects: Vec<ExportObjectDescriptorV2>,
}

impl TryFrom<CanonicalExportWireV2> for CanonicalExportV2 {
    type Error = SecureStoreError;

    fn try_from(value: CanonicalExportWireV2) -> Result<Self> {
        let export = Self {
            format_version: value.format_version,
            export_handle: value.export_handle,
            managed_copy_target: value.managed_copy_target,
            namespace: value.namespace,
            state_head_root: value.state_head_root,
            created_at_micros: value.created_at_micros,
            encrypted_objects: value.encrypted_objects,
        };
        export.validate()?;
        Ok(export)
    }
}

/// One bounded ciphertext body chunk transported beside an export manifest.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "ExportCiphertextChunkWireV2",
    into = "ExportCiphertextChunkWireV2"
)]
pub struct ExportCiphertextChunkV2 {
    export_handle: ExportHandleV2,
    content_handle: ContentHandleV2,
    chunk_index: u64,
    final_chunk: bool,
    ciphertext: Vec<u8>,
}

impl ExportCiphertextChunkV2 {
    /// Creates one non-empty bounded ciphertext stream chunk.
    pub fn new(
        export_handle: ExportHandleV2,
        content_handle: ContentHandleV2,
        chunk_index: u64,
        final_chunk: bool,
        ciphertext: Vec<u8>,
    ) -> Result<Self> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_EXPORT_CIPHERTEXT_CHUNK_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "export ciphertext chunk is outside the byte bound".to_owned(),
            ));
        }
        Ok(Self {
            export_handle,
            content_handle,
            chunk_index,
            final_chunk,
            ciphertext,
        })
    }

    /// Returns ciphertext bytes; this type has no plaintext field or digest.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for ExportCiphertextChunkV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportCiphertextChunkV2")
            .field("export_handle", &"[OPAQUE]")
            .field("content_handle", &"[OPAQUE]")
            .field("chunk_index", &self.chunk_index)
            .field("final_chunk", &self.final_chunk)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportCiphertextChunkWireV2 {
    export_handle: ExportHandleV2,
    content_handle: ContentHandleV2,
    chunk_index: u64,
    final_chunk: bool,
    #[serde(deserialize_with = "crate::bounded::export_chunk")]
    ciphertext: Vec<u8>,
}

impl TryFrom<ExportCiphertextChunkWireV2> for ExportCiphertextChunkV2 {
    type Error = SecureStoreError;

    fn try_from(value: ExportCiphertextChunkWireV2) -> Result<Self> {
        Self::new(
            value.export_handle,
            value.content_handle,
            value.chunk_index,
            value.final_chunk,
            value.ciphertext,
        )
    }
}

impl From<ExportCiphertextChunkV2> for ExportCiphertextChunkWireV2 {
    fn from(value: ExportCiphertextChunkV2) -> Self {
        Self {
            export_handle: value.export_handle,
            content_handle: value.content_handle,
            chunk_index: value.chunk_index,
            final_chunk: value.final_chunk,
            ciphertext: value.ciphertext,
        }
    }
}

impl From<CanonicalExportV2> for CanonicalExportWireV2 {
    fn from(value: CanonicalExportV2) -> Self {
        Self {
            format_version: value.format_version,
            export_handle: value.export_handle,
            managed_copy_target: value.managed_copy_target,
            namespace: value.namespace,
            state_head_root: value.state_head_root,
            created_at_micros: value.created_at_micros,
            encrypted_objects: value.encrypted_objects,
        }
    }
}
