//! Versioned, machine-readable runtime capability declarations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Schema emitted for a runtime capability declaration.
pub const CAPABILITY_MANIFEST_SCHEMA_VERSION: u16 = 1;

/// Availability of one named capability in the selected runtime profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// The selected composition exposes an executor for this capability.
    Available,
    /// Supporting code is present in the build, but is not wired to this data plane.
    CompiledOnly,
    /// The selected composition has no executor for this capability.
    Unsupported,
}

/// Versioned, content-free declaration of one selected runtime profile.
///
/// Capability identifiers are stable snake-case strings. A map is used rather
/// than fields so additions remain wire-compatible while every reported state
/// retains an explicit meaning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifestV1 {
    /// Schema of this capability declaration.
    pub schema_version: u16,
    /// Honest profile identity for the service or process which produced it.
    pub profile: String,
    /// Whether this exact profile has satisfied the complete server-v1 release contract.
    pub server_v1_release_ready: bool,
    /// Stable capability identifiers in canonical order.
    pub capabilities: BTreeMap<String, CapabilityState>,
}

impl CapabilityManifestV1 {
    /// Creates a schema-v1 manifest from an explicitly classified capability map.
    #[must_use]
    pub fn new(
        profile: impl Into<String>,
        server_v1_release_ready: bool,
        capabilities: BTreeMap<String, CapabilityState>,
    ) -> Self {
        Self {
            schema_version: CAPABILITY_MANIFEST_SCHEMA_VERSION,
            profile: profile.into(),
            server_v1_release_ready,
            capabilities,
        }
    }

    /// Returns the state of one stable capability identifier.
    #[must_use]
    pub fn capability(&self, capability: &str) -> Option<CapabilityState> {
        self.capabilities.get(capability).copied()
    }
}
