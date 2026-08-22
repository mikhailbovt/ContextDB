//! Content-free process liveness and readiness contracts.

use std::sync::Arc;

use contextdb_service::{
    CapabilityManifestV1, CapabilityState, SERVICE_CAPABILITY_IDS_V1,
    reference_capability_manifest_v1, service_capability_manifest_v1,
};
use serde::{Deserialize, Serialize};

/// Stable health state exposed without application authentication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// The HTTP process and router are responsive.
    Live,
    /// The configured service publication is ready to receive traffic.
    Ready,
    /// The service must not receive application traffic yet.
    NotReady,
}

/// Closed, non-secret runtime profile labels allowed on unauthenticated health routes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HealthProfile {
    /// Transport-only router with no configured application health provider.
    #[serde(rename = "transport")]
    Transport,
    /// Fjall-backed production composition.
    #[serde(rename = "production-fjall-v1")]
    ProductionFjallV1,
    /// Explicitly non-production in-memory reference composition.
    #[serde(rename = "development-reference")]
    DevelopmentReference,
}

/// Closed reason codes allowed on unauthenticated readiness responses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthReason {
    /// No host-owned provider was installed.
    HealthProviderNotConfigured,
    /// The development reference profile is intentionally not production-ready.
    DevelopmentReferenceNonproduction,
    /// The durable publication no longer matches its external authority.
    PublicationReconciliationRequired,
    /// The in-process publication is quarantined or unavailable.
    ServicePublicationUnavailable,
    /// A custom provider returned a malformed or internally inconsistent summary.
    InvalidProviderResponse,
    /// Another bounded readiness check is already in progress.
    HealthCheckBusy,
}

/// Content-free readiness checks owned by the already-open host process.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthChecks {
    /// The application service was loaded successfully.
    pub service_loaded: bool,
    /// The physical store passed startup verification.
    pub fjall_verified_at_startup: bool,
    /// The external rollback authority was reconciled at publication.
    pub external_head_reconciled: bool,
    /// A verified immutable publication is available to readers.
    pub publication_available: bool,
}

/// Bounded unauthenticated readiness response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSummary {
    /// Health response schema.
    pub schema_version: u16,
    /// Aggregate state.
    pub state: HealthState,
    /// Bounded non-secret runtime profile label.
    pub profile: HealthProfile,
    /// Explicit content-free checks.
    pub checks: HealthChecks,
    /// Closed, content-free capability declaration for the selected host profile.
    pub capability_manifest: CapabilityManifestV1,
    /// Stable bounded reason code for a non-ready state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<HealthReason>,
}

impl HealthSummary {
    /// Constructs and validates a bounded health summary.
    pub fn new(
        state: HealthState,
        profile: HealthProfile,
        checks: HealthChecks,
        reason_code: Option<HealthReason>,
    ) -> Result<Self, &'static str> {
        let summary = Self {
            schema_version: 1,
            state,
            profile,
            checks,
            capability_manifest: health_capability_manifest(profile),
            reason_code,
        };
        summary.validate()?;
        Ok(summary)
    }

    /// Returns the fixed process-liveness response.
    #[must_use]
    pub fn live() -> Self {
        Self {
            schema_version: 1,
            state: HealthState::Live,
            profile: HealthProfile::Transport,
            checks: HealthChecks {
                service_loaded: false,
                fjall_verified_at_startup: false,
                external_head_reconciled: false,
                publication_available: false,
            },
            capability_manifest: health_capability_manifest(HealthProfile::Transport),
            reason_code: None,
        }
    }

    /// Whether a readiness endpoint may return success.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == HealthState::Ready && self.validate().is_ok()
    }

    /// Validates every invariant before an unauthenticated response is emitted.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1 {
            return Err("health schema version is unsupported");
        }
        let expected_profile = match self.profile {
            HealthProfile::Transport => "transport-http-v1",
            HealthProfile::ProductionFjallV1 => "production-fjall-v1",
            HealthProfile::DevelopmentReference => "reference-in-memory",
        };
        if self.capability_manifest.schema_version
            != contextdb_service::CAPABILITY_MANIFEST_SCHEMA_VERSION
            || self.capability_manifest.profile != expected_profile
            || self.capability_manifest.server_v1_release_ready
            || self.capability_manifest.capabilities.len() != SERVICE_CAPABILITY_IDS_V1.len()
            || SERVICE_CAPABILITY_IDS_V1.iter().any(|capability| {
                !self
                    .capability_manifest
                    .capabilities
                    .contains_key(*capability)
            })
            || self.capability_manifest.capability("http_transport")
                != Some(CapabilityState::Available)
        {
            return Err("health capability manifest is invalid or outside the closed profile");
        }
        match self.state {
            HealthState::Ready
                if self.checks.service_loaded
                    && self.checks.fjall_verified_at_startup
                    && self.checks.external_head_reconciled
                    && self.checks.publication_available
                    && self.reason_code.is_none() =>
            {
                Ok(())
            }
            HealthState::Ready => Err("ready health requires every check and no reason code"),
            HealthState::NotReady if self.reason_code.is_some() => Ok(()),
            HealthState::NotReady => Err("not-ready health requires a reason code"),
            HealthState::Live
                if self.profile == HealthProfile::Transport
                    && self.checks
                        == (HealthChecks {
                            service_loaded: false,
                            fjall_verified_at_startup: false,
                            external_head_reconciled: false,
                            publication_available: false,
                        })
                    && self.reason_code.is_none() =>
            {
                Ok(())
            }
            HealthState::Live => Err("live health must use the fixed transport response"),
        }
    }

    /// Replaces an invalid custom-provider response with a fixed safe failure.
    #[must_use]
    pub fn sanitized(self) -> Self {
        if self.validate().is_ok() {
            self
        } else {
            Self::invalid_provider()
        }
    }

    pub(crate) fn invalid_provider() -> Self {
        Self::new(
            HealthState::NotReady,
            HealthProfile::Transport,
            HealthChecks {
                service_loaded: false,
                fjall_verified_at_startup: false,
                external_head_reconciled: false,
                publication_available: false,
            },
            Some(HealthReason::InvalidProviderResponse),
        )
        .expect("fixed invalid-provider health summary is valid")
    }

    #[cfg(feature = "http")]
    pub(crate) fn health_check_busy() -> Self {
        Self::new(
            HealthState::NotReady,
            HealthProfile::Transport,
            HealthChecks {
                service_loaded: false,
                fjall_verified_at_startup: false,
                external_head_reconciled: false,
                publication_available: false,
            },
            Some(HealthReason::HealthCheckBusy),
        )
        .expect("fixed busy health summary is valid")
    }
}

fn health_capability_manifest(profile: HealthProfile) -> CapabilityManifestV1 {
    let mut manifest = match profile {
        HealthProfile::Transport => {
            service_capability_manifest_v1("transport-http-v1", &["http_transport"], &[])
        }
        HealthProfile::ProductionFjallV1 => service_capability_manifest_v1(
            "production-fjall-v1",
            &[
                "durable_fjall_storage",
                "http_transport",
                "restart_verification",
                "status",
                "verify",
            ],
            &[],
        ),
        HealthProfile::DevelopmentReference => reference_capability_manifest_v1(),
    };
    manifest
        .capabilities
        .insert("http_transport".to_owned(), CapabilityState::Available);
    manifest
}

/// Host-owned source for a content-free readiness snapshot.
pub trait HealthProvider: Send + Sync + 'static {
    /// Returns the current bounded readiness snapshot.
    fn readiness(&self) -> HealthSummary;
}

impl<T> HealthProvider for Arc<T>
where
    T: HealthProvider + ?Sized,
{
    fn readiness(&self) -> HealthSummary {
        (**self).readiness()
    }
}

/// Shared health provider used by transport constructors.
pub type SharedHealthProvider = Arc<dyn HealthProvider>;

/// Immutable provider for tests, development profiles, and closed defaults.
#[derive(Clone, Debug)]
pub struct FixedHealthProvider {
    summary: HealthSummary,
}

impl FixedHealthProvider {
    /// Creates an immutable provider from an already validated summary.
    #[must_use]
    pub fn new(summary: HealthSummary) -> Self {
        Self {
            summary: summary.sanitized(),
        }
    }

    /// Returns a fail-closed provider used by legacy router constructors.
    #[must_use]
    pub fn not_configured() -> Self {
        Self {
            summary: HealthSummary::new(
                HealthState::NotReady,
                HealthProfile::Transport,
                HealthChecks {
                    service_loaded: false,
                    fjall_verified_at_startup: false,
                    external_head_reconciled: false,
                    publication_available: false,
                },
                Some(HealthReason::HealthProviderNotConfigured),
            )
            .expect("fixed health summary is valid"),
        }
    }
}

impl HealthProvider for FixedHealthProvider {
    fn readiness(&self) -> HealthSummary {
        self.summary.clone()
    }
}
