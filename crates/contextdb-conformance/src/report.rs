use serde::{Deserialize, Serialize};

use crate::{CONFORMANCE_SCHEMA_VERSION, CapabilityManifest, InterfaceKind};

/// Outcome of one named conformance assertion.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Assertion passed with evidence.
    Passed,
    /// Assertion ran and failed.
    Failed,
    /// Required external artifact or prior dependent result was unavailable.
    NotExercised,
}

/// One deterministic assertion result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    /// Stable check identifier.
    pub id: String,
    /// Pass/fail/proof state.
    pub status: CheckStatus,
    /// Content-free explanation.
    pub detail: String,
    /// BLAKE3 of canonical evidence JSON, when evidence exists.
    pub evidence_digest: Option<String>,
}

/// Machine-readable deterministic proof report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReport {
    /// Report schema version.
    pub schema_version: u16,
    /// Interface under test.
    pub interface: InterfaceKind,
    /// Explicit capability profile.
    pub manifest: CapabilityManifest,
    /// Assertions in deterministic execution order.
    pub checks: Vec<CheckResult>,
    /// Digest of checks only, suitable for semantic parity comparison.
    pub semantic_digest: String,
    /// Digest of the complete report except this field.
    pub report_digest: String,
}

impl ConformanceReport {
    pub(crate) fn new(manifest: CapabilityManifest) -> Self {
        Self {
            schema_version: CONFORMANCE_SCHEMA_VERSION,
            interface: manifest.interface,
            manifest,
            checks: Vec::new(),
            semantic_digest: String::new(),
            report_digest: String::new(),
        }
    }

    pub(crate) fn push<T: Serialize>(
        &mut self,
        id: &str,
        passed: bool,
        detail: &str,
        evidence: Option<&T>,
    ) {
        self.checks.push(CheckResult {
            id: id.to_owned(),
            status: if passed {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            detail: detail.to_owned(),
            evidence_digest: evidence.and_then(digest),
        });
    }

    pub(crate) fn not_exercised(&mut self, id: &str, detail: &str) {
        self.checks.push(CheckResult {
            id: id.to_owned(),
            status: CheckStatus::NotExercised,
            detail: detail.to_owned(),
            evidence_digest: None,
        });
    }

    pub(crate) fn finalize(&mut self) {
        self.semantic_digest = digest(&self.checks).unwrap_or_default();
        #[derive(Serialize)]
        struct ReportBody<'a> {
            schema_version: u16,
            interface: InterfaceKind,
            manifest: &'a CapabilityManifest,
            checks: &'a [CheckResult],
            semantic_digest: &'a str,
        }
        self.report_digest = digest(&ReportBody {
            schema_version: self.schema_version,
            interface: self.interface,
            manifest: &self.manifest,
            checks: &self.checks,
            semantic_digest: &self.semantic_digest,
        })
        .unwrap_or_default();
    }

    /// True only when every check passed and the manifest contains no profile
    /// gap or unexercised external proof.
    #[must_use]
    pub fn strictly_passed(&self) -> bool {
        self.manifest.is_strictly_satisfied()
            && self
                .checks
                .iter()
                .all(|check| check.status == CheckStatus::Passed)
    }

    /// True when every executable semantic assertion passed, independent of
    /// separately declared interface profile gaps.
    #[must_use]
    pub fn semantic_checks_passed(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == CheckStatus::Passed)
    }
}

fn digest<T: Serialize + ?Sized>(value: &T) -> Option<String> {
    serde_json::to_vec(value)
        .ok()
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
}
