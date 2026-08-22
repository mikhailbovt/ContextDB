use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Result, SecureStoreError, StateRootV2, canonical_json, validate_label};

/// Maximum canonical JSON size accepted for lifecycle metadata.
pub const MAX_LIFECYCLE_PAYLOAD_JSON_BYTES_V1: usize = 64 * 1024;
/// Maximum number of exact audiences bound into one lifecycle payload.
pub const MAX_LIFECYCLE_AUDIENCES_V1: usize = 64;
/// Maximum number of exact authorization scopes bound into one lifecycle payload.
pub const MAX_LIFECYCLE_SCOPES_V1: usize = 64;
/// Maximum number of provenance hops bound into one lifecycle payload.
pub const MAX_LIFECYCLE_PROVENANCE_V1: usize = 64;

/// Explicit classification of source material entering the local secure store.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleContentClassV1 {
    /// User-authored durable memory.
    UserAuthoredMemory,
    /// A user-visible excerpt from a conversation.
    ConversationExcerpt,
    /// A user-visible observation returned by a tool.
    ToolObservation,
    /// A user-visible summary produced by a model.
    ModelVisibleSummary,
    /// Private model reasoning. This value is deliberately rejected by every
    /// [`LifecyclePayloadV1`] constructor and decoder.
    ModelHiddenReasoning,
}

/// One bounded provenance hop for lifecycle-controlled source material.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    try_from = "LifecycleProvenanceWireV1",
    into = "LifecycleProvenanceWireV1"
)]
pub struct LifecycleProvenanceV1 {
    source_system: String,
    source_reference: String,
    tool_run_id: Option<String>,
}

impl LifecycleProvenanceV1 {
    /// Creates one exact provenance hop.
    pub fn new(
        source_system: impl Into<String>,
        source_reference: impl Into<String>,
        tool_run_id: Option<String>,
    ) -> Result<Self> {
        let value = Self {
            source_system: source_system.into(),
            source_reference: source_reference.into(),
            tool_run_id,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the source-system identity.
    #[must_use]
    pub fn source_system(&self) -> &str {
        &self.source_system
    }

    /// Returns the source-system record reference.
    #[must_use]
    pub fn source_reference(&self) -> &str {
        &self.source_reference
    }

    /// Returns the exact tool-run identity when a tool produced this material.
    #[must_use]
    pub fn tool_run_id(&self) -> Option<&str> {
        self.tool_run_id.as_deref()
    }

    fn validate(&self) -> Result<()> {
        validate_label(&self.source_system, "lifecycle provenance source system")?;
        validate_label(
            &self.source_reference,
            "lifecycle provenance source reference",
        )?;
        if let Some(value) = &self.tool_run_id {
            validate_label(value, "lifecycle provenance tool-run ID")?;
        }
        Ok(())
    }
}

impl fmt::Debug for LifecycleProvenanceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleProvenanceV1")
            .field("source_system", &self.source_system)
            .field("source_reference", &"[REDACTED]")
            .field("has_tool_run_id", &self.tool_run_id.is_some())
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleProvenanceWireV1 {
    source_system: String,
    source_reference: String,
    tool_run_id: Option<String>,
}

impl TryFrom<LifecycleProvenanceWireV1> for LifecycleProvenanceV1 {
    type Error = SecureStoreError;

    fn try_from(value: LifecycleProvenanceWireV1) -> Result<Self> {
        Self::new(
            value.source_system,
            value.source_reference,
            value.tool_run_id,
        )
    }
}

impl From<LifecycleProvenanceV1> for LifecycleProvenanceWireV1 {
    fn from(value: LifecycleProvenanceV1) -> Self {
        Self {
            source_system: value.source_system,
            source_reference: value.source_reference,
            tool_run_id: value.tool_run_id,
        }
    }
}

/// Bounded authorization and provenance metadata bound into local ciphertext.
///
/// This value is metadata only; it never contains source plaintext or a source
/// plaintext digest. Audience, scope, and provenance collections are sorted and
/// duplicate-free so their commitment has one canonical meaning.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "LifecyclePayloadWireV1", into = "LifecyclePayloadWireV1")]
pub struct LifecyclePayloadV1 {
    schema_version: u16,
    content_class: LifecycleContentClassV1,
    workspace_id: String,
    agent_id: String,
    subject_id: String,
    audiences: Vec<String>,
    scopes: Vec<String>,
    profile_id: String,
    tool_id: Option<String>,
    provenance: Vec<LifecycleProvenanceV1>,
}

impl LifecyclePayloadV1 {
    /// Creates validated lifecycle metadata and explicitly rejects hidden model
    /// reasoning as source material.
    #[allow(
        clippy::too_many_arguments,
        reason = "every lifecycle authorization binding is intentionally explicit"
    )]
    pub fn new(
        content_class: LifecycleContentClassV1,
        workspace_id: impl Into<String>,
        agent_id: impl Into<String>,
        subject_id: impl Into<String>,
        audiences: Vec<String>,
        scopes: Vec<String>,
        profile_id: impl Into<String>,
        tool_id: Option<String>,
        provenance: Vec<LifecycleProvenanceV1>,
    ) -> Result<Self> {
        let mut value = Self {
            schema_version: 1,
            content_class,
            workspace_id: workspace_id.into(),
            agent_id: agent_id.into(),
            subject_id: subject_id.into(),
            audiences,
            scopes,
            profile_id: profile_id.into(),
            tool_id,
            provenance,
        };
        value.audiences.sort();
        value.scopes.sort();
        value.provenance.sort();
        value.validate()?;
        Ok(value)
    }

    /// Recovers bounded lifecycle metadata and reruns every invariant.
    pub fn from_json_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_LIFECYCLE_PAYLOAD_JSON_BYTES_V1 {
            return Err(SecureStoreError::InvalidInput(
                "lifecycle payload exceeds decode byte limit".to_owned(),
            ));
        }
        serde_json::from_slice(bytes).map_err(|_| SecureStoreError::Serialization)
    }

    /// Returns the allowed source-material class.
    #[must_use]
    pub const fn content_class(&self) -> LifecycleContentClassV1 {
        self.content_class
    }

    /// Returns the exact workspace binding.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Returns the exact agent binding.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Returns the exact subject binding.
    #[must_use]
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    /// Returns canonical exact audiences.
    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// Returns canonical exact authorization scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Returns the exact profile binding.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the exact tool binding, including an explicit absence.
    #[must_use]
    pub fn tool_id(&self) -> Option<&str> {
        self.tool_id.as_deref()
    }

    /// Returns canonical provenance hops.
    #[must_use]
    pub fn provenance(&self) -> &[LifecycleProvenanceV1] {
        &self.provenance
    }

    /// Returns the canonical metadata commitment bound into ciphertext AAD.
    pub fn commitment(&self) -> Result<StateRootV2> {
        StateRootV2::commit("lifecycle-payload-v1", &canonical_json(self)?)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(SecureStoreError::InvalidInput(
                "lifecycle payload schema version".to_owned(),
            ));
        }
        if self.content_class == LifecycleContentClassV1::ModelHiddenReasoning {
            return Err(SecureStoreError::InvalidInput(
                "model hidden reasoning is forbidden lifecycle source material".to_owned(),
            ));
        }
        validate_label(&self.workspace_id, "lifecycle workspace ID")?;
        validate_label(&self.agent_id, "lifecycle agent ID")?;
        validate_label(&self.subject_id, "lifecycle subject ID")?;
        validate_label(&self.profile_id, "lifecycle profile ID")?;
        if let Some(value) = &self.tool_id {
            validate_label(value, "lifecycle tool ID")?;
        }
        validate_labels(
            &self.audiences,
            MAX_LIFECYCLE_AUDIENCES_V1,
            "lifecycle audiences",
        )?;
        validate_labels(&self.scopes, MAX_LIFECYCLE_SCOPES_V1, "lifecycle scopes")?;
        if self.provenance.is_empty()
            || self.provenance.len() > MAX_LIFECYCLE_PROVENANCE_V1
            || self.provenance.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(SecureStoreError::InvalidInput(
                "lifecycle provenance must be non-empty, bounded, sorted, and unique".to_owned(),
            ));
        }
        for hop in &self.provenance {
            hop.validate()?;
        }
        if canonical_json(self)?.len() > MAX_LIFECYCLE_PAYLOAD_JSON_BYTES_V1 {
            return Err(SecureStoreError::InvalidInput(
                "lifecycle payload exceeds canonical byte limit".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for LifecyclePayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecyclePayloadV1")
            .field("content_class", &self.content_class)
            .field("workspace_id", &"[REDACTED]")
            .field("agent_id", &"[REDACTED]")
            .field("subject_id", &"[REDACTED]")
            .field("audience_count", &self.audiences.len())
            .field("scope_count", &self.scopes.len())
            .field("profile_id", &"[REDACTED]")
            .field("has_tool_id", &self.tool_id.is_some())
            .field("provenance_count", &self.provenance.len())
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecyclePayloadWireV1 {
    schema_version: u16,
    content_class: LifecycleContentClassV1,
    workspace_id: String,
    agent_id: String,
    subject_id: String,
    audiences: Vec<String>,
    scopes: Vec<String>,
    profile_id: String,
    tool_id: Option<String>,
    provenance: Vec<LifecycleProvenanceV1>,
}

impl TryFrom<LifecyclePayloadWireV1> for LifecyclePayloadV1 {
    type Error = SecureStoreError;

    fn try_from(value: LifecyclePayloadWireV1) -> Result<Self> {
        if value.schema_version != 1 {
            return Err(SecureStoreError::InvalidInput(
                "lifecycle payload schema version".to_owned(),
            ));
        }
        Self::new(
            value.content_class,
            value.workspace_id,
            value.agent_id,
            value.subject_id,
            value.audiences,
            value.scopes,
            value.profile_id,
            value.tool_id,
            value.provenance,
        )
    }
}

impl From<LifecyclePayloadV1> for LifecyclePayloadWireV1 {
    fn from(value: LifecyclePayloadV1) -> Self {
        Self {
            schema_version: value.schema_version,
            content_class: value.content_class,
            workspace_id: value.workspace_id,
            agent_id: value.agent_id,
            subject_id: value.subject_id,
            audiences: value.audiences,
            scopes: value.scopes,
            profile_id: value.profile_id,
            tool_id: value.tool_id,
            provenance: value.provenance,
        }
    }
}

fn validate_labels(values: &[String], maximum: usize, field: &str) -> Result<()> {
    if values.is_empty()
        || values.len() > maximum
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(SecureStoreError::InvalidInput(format!(
            "{field} must be non-empty, bounded, sorted, and unique"
        )));
    }
    for value in values {
        validate_label(value, field)?;
    }
    Ok(())
}
