use std::fmt;

use zeroize::Zeroizing;

use crate::{
    CompositeStateHeadV2, ContentHandleV2, ContentSecurityContextV2,
    DurableEncryptedObjectCatalogV2, DurableObjectLoadOutcomeV2, DurableObjectLoadRequestV2,
    HeadMacAuthorityV2, KeyAuthorityV2, Result, SecureStoreError, StateNamespaceV2, StateRootV2,
    SuppressionBindingV2,
};

/// Result of consulting the exact live deletion overlay bound by a state head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveSuppressionDecisionV2 {
    /// The exact object is not suppressed by the authenticated live overlay.
    Allow,
    /// The exact object is suppressed and must not cross a decryption boundary.
    Suppressed,
}

/// Strongly consistent reader for the live suppression overlay.
///
/// Implementations must return `Unavailable` as an error rather than consulting
/// a stale cache. The caller supplies the exact overlay root authenticated by
/// the composite head, so a result for another generation is invalid.
pub trait LiveSuppressionOverlayV2: Send + Sync {
    /// Checks one opaque object against the exact authenticated overlay root.
    fn check_content(
        &self,
        namespace: &StateNamespaceV2,
        overlay_root: &StateRootV2,
        content_handle: &ContentHandleV2,
    ) -> Result<LiveSuppressionDecisionV2>;
}

/// Outcome of a read that enforces suppression before invoking the key authority.
pub enum SuppressionAwareReadV2 {
    /// No durable reservation exists for the exact namespace and handle.
    Missing,
    /// The authenticated live overlay suppresses this object. No DEK operation ran.
    Suppressed,
    /// Decryption was permitted and returned zeroizing plaintext memory.
    Decrypted(Zeroizing<Vec<u8>>),
}

impl SuppressionAwareReadV2 {
    /// Returns plaintext only for an explicitly decrypted outcome.
    #[must_use]
    pub fn plaintext(&self) -> Option<&[u8]> {
        match self {
            Self::Missing | Self::Suppressed => None,
            Self::Decrypted(value) => Some(value.as_slice()),
        }
    }
}

impl fmt::Debug for SuppressionAwareReadV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("SuppressionAwareReadV2::Missing"),
            Self::Suppressed => formatter.write_str("SuppressionAwareReadV2::Suppressed"),
            Self::Decrypted(value) => formatter
                .debug_tuple("SuppressionAwareReadV2::Decrypted")
                .field(&format_args!("[REDACTED; {} bytes]", value.len()))
                .finish(),
        }
    }
}

/// Authenticates publication and evaluates suppression before any DEK access.
///
/// `Pending` suppression denies every read without consulting either the live
/// overlay or the key authority. `Enforced` suppression requires an exact live
/// overlay decision. Only after that decision allows the read is the exact
/// object loaded through the durable catalog. Its recomputed snapshot must be
/// the catalog root published in the authenticated head, and its persisted
/// descriptor must authenticate the exact ciphertext envelope.
pub fn decrypt_after_suppression_v2(
    head: &CompositeStateHeadV2,
    request: &DurableObjectLoadRequestV2,
    mac_authority: &dyn HeadMacAuthorityV2,
    expected_context: &ContentSecurityContextV2,
    catalog: &dyn DurableEncryptedObjectCatalogV2,
    overlay: &dyn LiveSuppressionOverlayV2,
    key_authority: &dyn KeyAuthorityV2,
) -> Result<SuppressionAwareReadV2> {
    let namespace = request.namespace();
    head.verify(namespace, mac_authority)?;
    if expected_context.database_id() != namespace.database_id()
        || expected_context.workspace_id() != namespace.workspace_id()
    {
        return Err(SecureStoreError::Integrity(
            "secure read namespace and expected content context do not match".to_owned(),
        ));
    }
    match &head.payload().suppression {
        SuppressionBindingV2::Pending { .. } => {
            return Err(SecureStoreError::DeletionIncomplete(
                "all reads are denied while suppression publication is pending".to_owned(),
            ));
        }
        SuppressionBindingV2::Enforced { overlay_root } => {
            match overlay.check_content(namespace, overlay_root, request.content_handle())? {
                LiveSuppressionDecisionV2::Suppressed => {
                    return Ok(SuppressionAwareReadV2::Suppressed);
                }
                LiveSuppressionDecisionV2::Allow => {}
            }
        }
        SuppressionBindingV2::Clear => {}
    }
    let outcome = catalog.load(request)?;
    outcome.validate_for(request)?;
    let DurableObjectLoadOutcomeV2::Found {
        entry,
        encrypted_object,
        snapshot,
    } = outcome
    else {
        return match outcome {
            DurableObjectLoadOutcomeV2::Missing => Ok(SuppressionAwareReadV2::Missing),
            DurableObjectLoadOutcomeV2::Unavailable => Err(SecureStoreError::StateConflict(
                "durable catalog is unavailable for an allowed secure read".to_owned(),
            )),
            DurableObjectLoadOutcomeV2::Found { .. } => unreachable!(),
        };
    };
    if head.payload().key_catalog_root != snapshot.publication_root()? {
        return Err(SecureStoreError::Integrity(
            "durable catalog snapshot is not the one published by the authenticated head"
                .to_owned(),
        ));
    }
    let descriptor = entry.stored().ok_or_else(|| {
        SecureStoreError::StateConflict(
            "durable object has no ciphertext descriptor for an allowed secure read".to_owned(),
        )
    })?;
    let encrypted = encrypted_object.ok_or_else(|| {
        SecureStoreError::Integrity(
            "durable object omitted ciphertext for an allowed secure read".to_owned(),
        )
    })?;
    descriptor.validate_encrypted_object(&encrypted)?;
    if encrypted.header().key().scope().security_context() != expected_context {
        return Err(SecureStoreError::Integrity(
            "durable ciphertext content context differs from the expected read context".to_owned(),
        ));
    }
    encrypted
        .decrypt(key_authority, expected_context)
        .map(SuppressionAwareReadV2::Decrypted)
}
