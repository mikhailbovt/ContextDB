//! Shared continuity identifiers and canonical helpers.

use std::fmt;

use contextdb_core::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::{ContinuityError, Result};

macro_rules! bounded_identifier {
    ($($name:ident => $field:literal),+ $(,)?) => {
        $(
            #[doc = concat!("Bounded stable `", stringify!($name), "` identifier.")]
            #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
            #[serde(transparent)]
            pub struct $name(String);

            impl $name {
                #[doc = concat!("Creates a validated `", stringify!($name), "`.")]
                pub fn new(value: impl Into<String>) -> Result<Self> {
                    let value = value.into();
                    validate_text(&value, $field, 256)?;
                    Ok(Self(value))
                }

                /// Returns the stable textual representation.
                #[must_use]
                pub fn as_str(&self) -> &str {
                    &self.0
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    self.0.fmt(formatter)
                }
            }

            impl<'de> Deserialize<'de> for $name {
                fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    let value = String::deserialize(deserializer)?;
                    Self::new(value).map_err(serde::de::Error::custom)
                }
            }
        )+
    };
}

bounded_identifier!(
    MigrationId => "migration_id",
    HandoffId => "handoff_id",
    ActionId => "action_id",
    ToolId => "tool_id",
    PromptCacheNamespace => "prompt_cache_namespace",
);

/// Honest identity statement carried across every migration artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityIdentityKind {
    /// Stable memory subject and obligations, without a metaphysical identity claim.
    OperationalContinuity,
}

/// Canonical lowercase BLAKE3 digest of a serializable value.
pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<ContentDigest> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ContinuityError::Serialization(error.to_string()))?;
    Ok(ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()))
}

pub(crate) fn validate_text(value: &str, field: &str, maximum: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(ContinuityError::InvalidInput(format!(
            "{field} must not be blank"
        )));
    }
    if value.len() > maximum {
        return Err(ContinuityError::InvalidInput(format!(
            "{field} exceeds {maximum} UTF-8 bytes"
        )));
    }
    Ok(())
}

pub(crate) fn ensure_digest_nonzero(digest: ContentDigest, field: &str) -> Result<()> {
    if digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ContinuityError::InvalidInput(format!(
            "{field} must not be an all-zero digest"
        )));
    }
    Ok(())
}
