use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    Result, SECURE_STORE_FORMAT_VERSION, SecureStoreError, StateRootV2, canonical_json, encode_hex,
    validate_hex_32, validate_label,
};

/// Maximum JSON bytes accepted when decoding one authenticated composite head.
pub const MAX_COMPOSITE_HEAD_JSON_BYTES_V2: usize = 64 * 1024;

/// Non-secret reference to a state-head MAC key generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "HeadMacKeyWireV2", into = "HeadMacKeyWireV2")]
pub struct HeadMacKeyRefV2 {
    key_id: String,
    generation: u64,
}

impl HeadMacKeyRefV2 {
    /// Creates a validated key-generation reference.
    pub fn new(key_id: impl Into<String>, generation: u64) -> Result<Self> {
        let key_id = key_id.into();
        validate_label(&key_id, "head MAC key ID")?;
        if generation == 0 {
            return Err(SecureStoreError::InvalidInput(
                "head MAC generation must be non-zero".to_owned(),
            ));
        }
        Ok(Self { key_id, generation })
    }

    /// Returns the host key-management identity.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the monotonic MAC-key generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadMacKeyWireV2 {
    key_id: String,
    generation: u64,
}

impl TryFrom<HeadMacKeyWireV2> for HeadMacKeyRefV2 {
    type Error = SecureStoreError;

    fn try_from(value: HeadMacKeyWireV2) -> Result<Self> {
        Self::new(value.key_id, value.generation)
    }
}

impl From<HeadMacKeyRefV2> for HeadMacKeyWireV2 {
    fn from(value: HeadMacKeyRefV2) -> Self {
        Self {
            key_id: value.key_id,
            generation: value.generation,
        }
    }
}

/// Validated 256-bit MAC tag; this is never key material.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HeadMacTagV2(String);

impl HeadMacTagV2 {
    /// Encodes a raw 256-bit authenticator returned by a MAC authority.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(encode_hex(&bytes))
    }

    /// Parses a canonical lowercase hexadecimal MAC tag.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_hex_32(&value, "head MAC tag")?;
        blake3::Hash::from_hex(&value)
            .map_err(|_| SecureStoreError::InvalidInput("head MAC tag".to_owned()))?;
        Ok(Self(value))
    }

    /// Returns the canonical tag encoding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HeadMacTagV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeadMacTagV2([AUTHENTICATOR])")
    }
}

impl TryFrom<String> for HeadMacTagV2 {
    type Error = SecureStoreError;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(value)
    }
}

impl From<HeadMacTagV2> for String {
    fn from(value: HeadMacTagV2) -> Self {
        value.0
    }
}

/// External MAC authority for composite state heads.
///
/// Implementations retain all secret bytes and must support verification of
/// every still-trusted historical generation returned in a persisted head.
pub trait HeadMacAuthorityV2 {
    /// Returns the generation used to authenticate newly published heads.
    fn active_key(&self) -> Result<HeadMacKeyRefV2>;

    /// Computes a domain-separated 256-bit MAC without releasing key bytes.
    fn compute_mac(&self, key: &HeadMacKeyRefV2, message: &[u8]) -> Result<HeadMacTagV2>;
}

/// Exact installation/database/workspace/partition namespace of a state head.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "StateNamespaceWireV2", into = "StateNamespaceWireV2")]
pub struct StateNamespaceV2 {
    authority_namespace: String,
    database_id: String,
    workspace_id: String,
    partition_id: String,
}

impl StateNamespaceV2 {
    /// Creates a validated anti-replay namespace.
    pub fn new(
        authority_namespace: impl Into<String>,
        database_id: impl Into<String>,
        workspace_id: impl Into<String>,
        partition_id: impl Into<String>,
    ) -> Result<Self> {
        let namespace = Self {
            authority_namespace: authority_namespace.into(),
            database_id: database_id.into(),
            workspace_id: workspace_id.into(),
            partition_id: partition_id.into(),
        };
        namespace.validate()?;
        Ok(namespace)
    }

    /// Returns the installation or MAC-authority namespace.
    #[must_use]
    pub fn authority_namespace(&self) -> &str {
        &self.authority_namespace
    }

    /// Returns the exact database identity.
    #[must_use]
    pub fn database_id(&self) -> &str {
        &self.database_id
    }

    /// Returns the exact workspace identity.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Returns the exact storage/policy partition identity.
    #[must_use]
    pub fn partition_id(&self) -> &str {
        &self.partition_id
    }

    fn validate(&self) -> Result<()> {
        validate_label(&self.authority_namespace, "head authority namespace")?;
        validate_label(&self.database_id, "head database ID")?;
        validate_label(&self.workspace_id, "head workspace ID")?;
        validate_label(&self.partition_id, "head partition ID")
    }
}

impl fmt::Debug for StateNamespaceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateNamespaceV2")
            .field("authority_namespace", &"[REDACTED]")
            .field("database_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("partition_id", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateNamespaceWireV2 {
    authority_namespace: String,
    database_id: String,
    workspace_id: String,
    partition_id: String,
}

impl TryFrom<StateNamespaceWireV2> for StateNamespaceV2 {
    type Error = SecureStoreError;

    fn try_from(value: StateNamespaceWireV2) -> Result<Self> {
        Self::new(
            value.authority_namespace,
            value.database_id,
            value.workspace_id,
            value.partition_id,
        )
    }
}

impl From<StateNamespaceV2> for StateNamespaceWireV2 {
    fn from(value: StateNamespaceV2) -> Self {
        Self {
            authority_namespace: value.authority_namespace,
            database_id: value.database_id,
            workspace_id: value.workspace_id,
            partition_id: value.partition_id,
        }
    }
}

/// Durable deletion-suppression binding carried by a composite head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SuppressionBindingV2 {
    /// No deletion workflow is waiting for or relying on the live overlay.
    Clear,
    /// Suppression is not durably committed; reads must fail closed globally.
    Pending {
        /// Root of the exact pending workflow overlay.
        overlay_root: StateRootV2,
        /// Number of workflows awaiting durable suppression.
        pending_workflow_count: u64,
    },
    /// Suppression is durable; reads must consult the bound live overlay.
    Enforced {
        /// Root of the exact enforced workflow overlay.
        overlay_root: StateRootV2,
    },
}

/// Read behavior required by a composite head's suppression state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuppressionReadGateV2 {
    /// Normal reads can proceed.
    Open,
    /// All reads fail closed until the pending overlay is durably committed.
    DenyWhilePending,
    /// Reads proceed only after checking the exact bound live deletion overlay.
    RequireLiveOverlay,
}

/// Four-root state atomically bound into one authenticated publication head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "CompositeHeadPayloadWireV2",
    into = "CompositeHeadPayloadWireV2"
)]
pub struct CompositeHeadPayloadV2 {
    /// Canonical projection root.
    pub projection_root: StateRootV2,
    /// Current effective policy root.
    pub policy_root: StateRootV2,
    /// Current key-catalog root.
    pub key_catalog_root: StateRootV2,
    /// Current deletion-workflow/overlay root.
    pub deletion_workflow_root: StateRootV2,
    /// Fail-closed suppression publication state.
    pub suppression: SuppressionBindingV2,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompositeHeadPayloadWireV2 {
    projection_root: StateRootV2,
    policy_root: StateRootV2,
    key_catalog_root: StateRootV2,
    deletion_workflow_root: StateRootV2,
    suppression: SuppressionBindingV2,
}

impl TryFrom<CompositeHeadPayloadWireV2> for CompositeHeadPayloadV2 {
    type Error = SecureStoreError;

    fn try_from(value: CompositeHeadPayloadWireV2) -> Result<Self> {
        let payload = Self {
            projection_root: value.projection_root,
            policy_root: value.policy_root,
            key_catalog_root: value.key_catalog_root,
            deletion_workflow_root: value.deletion_workflow_root,
            suppression: value.suppression,
        };
        payload.validate()?;
        Ok(payload)
    }
}

impl From<CompositeHeadPayloadV2> for CompositeHeadPayloadWireV2 {
    fn from(value: CompositeHeadPayloadV2) -> Self {
        Self {
            projection_root: value.projection_root,
            policy_root: value.policy_root,
            key_catalog_root: value.key_catalog_root,
            deletion_workflow_root: value.deletion_workflow_root,
            suppression: value.suppression,
        }
    }
}

impl CompositeHeadPayloadV2 {
    /// Validates cross-root suppression binding invariants.
    pub fn validate(&self) -> Result<()> {
        match &self.suppression {
            SuppressionBindingV2::Clear => Ok(()),
            SuppressionBindingV2::Pending {
                overlay_root,
                pending_workflow_count,
            } => {
                if *pending_workflow_count == 0 {
                    return Err(SecureStoreError::Integrity(
                        "pending suppression count must be non-zero".to_owned(),
                    ));
                }
                require_same_overlay(overlay_root, &self.deletion_workflow_root)
            }
            SuppressionBindingV2::Enforced { overlay_root } => {
                require_same_overlay(overlay_root, &self.deletion_workflow_root)
            }
        }
    }

    /// Returns the mandatory read gate implied by the suppression binding.
    #[must_use]
    pub const fn read_gate(&self) -> SuppressionReadGateV2 {
        match self.suppression {
            SuppressionBindingV2::Clear => SuppressionReadGateV2::Open,
            SuppressionBindingV2::Pending { .. } => SuppressionReadGateV2::DenyWhilePending,
            SuppressionBindingV2::Enforced { .. } => SuppressionReadGateV2::RequireLiveOverlay,
        }
    }
}

/// MAC metadata attached to a composite state head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadAuthenticationV2 {
    key: HeadMacKeyRefV2,
    tag: HeadMacTagV2,
}

impl HeadAuthenticationV2 {
    /// Returns the MAC key generation reference.
    #[must_use]
    pub fn key(&self) -> &HeadMacKeyRefV2 {
        &self.key
    }

    /// Returns the persisted MAC tag.
    #[must_use]
    pub fn tag(&self) -> &HeadMacTagV2 {
        &self.tag
    }
}

/// Authenticated composite state head used as the only publication CAS value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompositeStateHeadV2 {
    format_version: u16,
    sequence: u64,
    namespace: StateNamespaceV2,
    payload: CompositeHeadPayloadV2,
    authentication: HeadAuthenticationV2,
}

impl CompositeStateHeadV2 {
    /// Decodes a bounded buffer and verifies its namespace and MAC before
    /// returning an authenticated state head.
    pub fn from_json_bounded(
        bytes: &[u8],
        expected_namespace: &StateNamespaceV2,
        authority: &dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        if bytes.len() > MAX_COMPOSITE_HEAD_JSON_BYTES_V2 {
            return Err(SecureStoreError::InvalidInput(
                "composite state head exceeds decode byte limit".to_owned(),
            ));
        }
        let wire: CompositeHeadWireV2 =
            serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)?;
        let head = Self::try_from(wire)?;
        head.verify(expected_namespace, authority)?;
        Ok(head)
    }

    /// Creates the first authenticated head at sequence one.
    pub fn initial(
        namespace: StateNamespaceV2,
        payload: CompositeHeadPayloadV2,
        authority: &dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        Self::seal(1, namespace, payload, authority)
    }

    /// Creates the exact next authenticated head after verifying this head.
    pub fn successor(
        &self,
        expected_namespace: &StateNamespaceV2,
        payload: CompositeHeadPayloadV2,
        authority: &dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        self.verify(expected_namespace, authority)?;
        let active = authority.active_key()?;
        if active.generation() < self.authentication.key.generation() {
            return Err(SecureStoreError::StateConflict(
                "head MAC key generation regressed".to_owned(),
            ));
        }
        let sequence = self.sequence.checked_add(1).ok_or_else(|| {
            SecureStoreError::StateConflict("state-head sequence exhausted".to_owned())
        })?;
        Self::seal(sequence, self.namespace.clone(), payload, authority)
    }

    /// Verifies payload invariants and the MAC using the referenced generation.
    pub fn verify(
        &self,
        expected_namespace: &StateNamespaceV2,
        authority: &dyn HeadMacAuthorityV2,
    ) -> Result<()> {
        self.validate_shape()?;
        expected_namespace.validate()?;
        if &self.namespace != expected_namespace {
            return Err(SecureStoreError::Integrity(
                "composite state-head namespace does not match destination".to_owned(),
            ));
        }
        let expected = authority.compute_mac(&self.authentication.key, &self.mac_message()?)?;
        let expected_hash = blake3::Hash::from_hex(expected.as_str()).map_err(|_| {
            SecureStoreError::Integrity("MAC authority returned an invalid tag".to_owned())
        })?;
        let persisted_hash =
            blake3::Hash::from_hex(self.authentication.tag.as_str()).map_err(|_| {
                SecureStoreError::Integrity("persisted state-head MAC tag is invalid".to_owned())
            })?;
        if expected_hash != persisted_hash {
            return Err(SecureStoreError::Integrity(
                "composite state-head MAC mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the monotonic publication sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact anti-replay namespace.
    #[must_use]
    pub fn namespace(&self) -> &StateNamespaceV2 {
        &self.namespace
    }

    /// Returns the atomically bound roots and suppression state.
    #[must_use]
    pub fn payload(&self) -> &CompositeHeadPayloadV2 {
        &self.payload
    }

    /// Returns the MAC metadata.
    #[must_use]
    pub fn authentication(&self) -> &HeadAuthenticationV2 {
        &self.authentication
    }

    /// Returns a canonical commitment to the complete authenticated head.
    ///
    /// Repositories use this together with the sequence as the exact durable
    /// anti-rollback anchor. It is a commitment to public state, never plaintext.
    pub fn commitment(&self) -> Result<StateRootV2> {
        StateRootV2::commit(
            "authenticated-composite-state-head-v2",
            &canonical_json(self)?,
        )
    }

    /// Returns the exact token required by compare-and-swap publication.
    #[must_use]
    pub fn cas_token(&self) -> HeadCasTokenV2 {
        HeadCasTokenV2 {
            sequence: self.sequence,
            tag: self.authentication.tag.clone(),
        }
    }

    fn seal(
        sequence: u64,
        namespace: StateNamespaceV2,
        payload: CompositeHeadPayloadV2,
        authority: &dyn HeadMacAuthorityV2,
    ) -> Result<Self> {
        payload.validate()?;
        namespace.validate()?;
        if sequence == 0 {
            return Err(SecureStoreError::InvalidInput(
                "state-head sequence must be non-zero".to_owned(),
            ));
        }
        let key = authority.active_key()?;
        let unsigned = UnsignedCompositeHeadV2 {
            format_version: SECURE_STORE_FORMAT_VERSION,
            sequence,
            namespace: &namespace,
            payload: &payload,
            mac_key: &key,
        };
        let tag = authority.compute_mac(&key, &mac_message(&unsigned)?)?;
        Ok(Self {
            format_version: SECURE_STORE_FORMAT_VERSION,
            sequence,
            namespace,
            payload,
            authentication: HeadAuthenticationV2 { key, tag },
        })
    }

    fn validate_shape(&self) -> Result<()> {
        if self.format_version != SECURE_STORE_FORMAT_VERSION || self.sequence == 0 {
            return Err(SecureStoreError::Integrity(
                "composite state-head version or sequence is invalid".to_owned(),
            ));
        }
        self.namespace.validate()?;
        self.payload.validate()
    }

    fn mac_message(&self) -> Result<Vec<u8>> {
        mac_message(&UnsignedCompositeHeadV2 {
            format_version: self.format_version,
            sequence: self.sequence,
            namespace: &self.namespace,
            payload: &self.payload,
            mac_key: &self.authentication.key,
        })
    }
}

#[derive(Serialize)]
struct UnsignedCompositeHeadV2<'a> {
    format_version: u16,
    sequence: u64,
    namespace: &'a StateNamespaceV2,
    payload: &'a CompositeHeadPayloadV2,
    mac_key: &'a HeadMacKeyRefV2,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompositeHeadWireV2 {
    format_version: u16,
    sequence: u64,
    namespace: StateNamespaceV2,
    payload: CompositeHeadPayloadV2,
    authentication: HeadAuthenticationV2,
}

impl TryFrom<CompositeHeadWireV2> for CompositeStateHeadV2 {
    type Error = SecureStoreError;

    fn try_from(value: CompositeHeadWireV2) -> Result<Self> {
        let head = Self {
            format_version: value.format_version,
            sequence: value.sequence,
            namespace: value.namespace,
            payload: value.payload,
            authentication: value.authentication,
        };
        head.validate_shape()?;
        Ok(head)
    }
}

impl From<CompositeStateHeadV2> for CompositeHeadWireV2 {
    fn from(value: CompositeStateHeadV2) -> Self {
        Self {
            format_version: value.format_version,
            sequence: value.sequence,
            namespace: value.namespace,
            payload: value.payload,
            authentication: value.authentication,
        }
    }
}

/// Exact expected value for monotonic composite-head compare-and-swap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadCasTokenV2 {
    sequence: u64,
    tag: HeadMacTagV2,
}

impl HeadCasTokenV2 {
    /// Returns the expected publication sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the expected authenticated tag.
    #[must_use]
    pub fn tag(&self) -> &HeadMacTagV2 {
        &self.tag
    }
}

/// Validates an atomic monotonic CAS without performing backend I/O.
pub fn validate_composite_head_cas(
    expected: &HeadCasTokenV2,
    expected_namespace: &StateNamespaceV2,
    current: &CompositeStateHeadV2,
    next: &CompositeStateHeadV2,
    authority: &dyn HeadMacAuthorityV2,
) -> Result<()> {
    current.verify(expected_namespace, authority)?;
    next.verify(expected_namespace, authority)?;
    if expected != &current.cas_token() {
        return Err(SecureStoreError::StateConflict(
            "composite state-head CAS token is stale".to_owned(),
        ));
    }
    if next.namespace != current.namespace {
        return Err(SecureStoreError::StateConflict(
            "composite state-head namespace changed".to_owned(),
        ));
    }
    if next.sequence
        != current.sequence.checked_add(1).ok_or_else(|| {
            SecureStoreError::StateConflict("state-head sequence exhausted".to_owned())
        })?
    {
        return Err(SecureStoreError::StateConflict(
            "composite state-head sequence is not the exact successor".to_owned(),
        ));
    }
    if next.authentication.key.generation() < current.authentication.key.generation() {
        return Err(SecureStoreError::StateConflict(
            "composite state-head MAC key generation regressed".to_owned(),
        ));
    }
    let active_key = authority.active_key()?;
    if next.authentication.key != active_key {
        return Err(SecureStoreError::StateConflict(
            "composite state-head successor uses a stale MAC key generation".to_owned(),
        ));
    }
    Ok(())
}

fn require_same_overlay(overlay: &StateRootV2, workflow: &StateRootV2) -> Result<()> {
    if overlay != workflow {
        return Err(SecureStoreError::Integrity(
            "suppression overlay root is not the deletion-workflow root".to_owned(),
        ));
    }
    Ok(())
}

fn mac_message(unsigned: &UnsignedCompositeHeadV2<'_>) -> Result<Vec<u8>> {
    let canonical = canonical_json(unsigned)?;
    let mut message = Vec::with_capacity(48_usize.saturating_add(canonical.len()));
    message.extend_from_slice(b"contextdb/composite-state-head/v2\0");
    message.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    message.extend_from_slice(&canonical);
    Ok(message)
}
