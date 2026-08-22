use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{SecurityError, SecurityResult};

/// Taint attached to untrusted retrieved or imported content.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTaint {
    /// Instruction-like language occurs inside data.
    InstructionInContent,
    /// Content requests credentials or secrets.
    CredentialRequest,
    /// Content attempts data exfiltration.
    DataExfiltrationPattern,
    /// Content asks the agent to invoke a tool or command.
    ToolInvocationRequest,
    /// Content attempts to override caller/system policy.
    PolicyOverrideAttempt,
    /// Content carries an encoded payload that requires separate inspection.
    EncodedPayload,
}

/// Security-sensitive inference classes denied by default.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveInferenceClass {
    /// Physical or mental health.
    Health,
    /// Religious belief or practice.
    Religion,
    /// Political belief or affiliation.
    Politics,
    /// Sexual orientation or behavior.
    Sexuality,
    /// Biometric identity or templates.
    Biometrics,
    /// Criminal allegation or history.
    CriminalAllegation,
    /// Psychological diagnosis.
    PsychologicalDiagnosis,
    /// Financial state or vulnerability.
    FinancialState,
    /// Precise location patterns.
    PreciseLocation,
}

/// Explicit policy required to permit a sensitive inference class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveInferencePolicy {
    /// Explicitly permitted classes.
    pub allowed_classes: BTreeSet<SensitiveInferenceClass>,
    /// Whether a non-empty legal/policy basis was independently verified.
    pub verified_basis: bool,
    /// Whether the memory subject explicitly consented to this use.
    pub explicit_consent: bool,
}

impl SensitiveInferencePolicy {
    /// Authorizes one class. Absence, unknown state, or an empty basis fails
    /// closed and must happen before source content influences inference.
    pub fn authorize(
        &self,
        class: SensitiveInferenceClass,
        policy_basis: &str,
    ) -> SecurityResult<()> {
        if !self.verified_basis
            || !self.explicit_consent
            || !self.allowed_classes.contains(&class)
            || policy_basis.trim().is_empty()
        {
            return Err(SecurityError::PolicyDenied(
                "sensitive inference is denied by default".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Bounded result of source sanitization. `content` remains untrusted data and
/// receives no instruction or tool authority.
///
/// The verdict is intentionally serialization-only. Untrusted wire data must
/// be passed through [`sanitize_untrusted_source`] instead of being promoted
/// into an authoritative verdict:
///
/// ```compile_fail
/// use contextdb_security::TaintedContent;
///
/// let _: TaintedContent = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaintedContent {
    /// UTF-8 content with prohibited control characters removed.
    content: String,
    /// Detected taint labels.
    taints: BTreeSet<SourceTaint>,
}

impl TaintedContent {
    /// Sanitized but still untrusted content bytes.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Detected taint labels.
    #[must_use]
    pub fn taints(&self) -> &BTreeSet<SourceTaint> {
        &self.taints
    }

    /// Untrusted content can never grant instruction authority.
    #[must_use]
    pub const fn grants_instruction_authority(&self) -> bool {
        false
    }

    /// Untrusted content can never grant tool authority.
    #[must_use]
    pub const fn grants_tool_authority(&self) -> bool {
        false
    }
}

impl fmt::Debug for TaintedContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaintedContent")
            .field("content_bytes", &self.content.len())
            .field("taints", &self.taints)
            .field(
                "grants_instruction_authority",
                &self.grants_instruction_authority(),
            )
            .field("grants_tool_authority", &self.grants_tool_authority())
            .finish_non_exhaustive()
    }
}

/// Detects common injection patterns and strips non-whitespace control
/// characters. This deterministic layer supplements, but does not replace,
/// source-specific parsers and adversarial evaluation.
pub fn sanitize_untrusted_source(input: &str, max_bytes: usize) -> SecurityResult<TaintedContent> {
    if max_bytes == 0 || input.len() > max_bytes {
        return Err(SecurityError::ResourceExhausted(
            "untrusted source exceeds the sanitization budget".to_owned(),
        ));
    }
    let content = input
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect::<String>();
    let lower = content.to_ascii_lowercase();
    let mut taints = BTreeSet::new();
    if contains_any(
        &lower,
        &[
            "ignore previous",
            "ignore all previous",
            "system prompt",
            "developer message",
            "follow these instructions",
            "new instructions:",
        ],
    ) {
        taints.insert(SourceTaint::InstructionInContent);
    }
    if contains_any(
        &lower,
        &[
            "send your password",
            "reveal your api key",
            "provide credentials",
            "show me the token",
            "private key",
        ],
    ) {
        taints.insert(SourceTaint::CredentialRequest);
    }
    if contains_any(
        &lower,
        &[
            "upload to http",
            "send to http",
            "exfiltrate",
            "post the data",
            "curl http",
            "curl -x post",
        ],
    ) {
        taints.insert(SourceTaint::DataExfiltrationPattern);
    }
    if contains_any(
        &lower,
        &[
            "run this command",
            "execute this command",
            "call the tool",
            "invoke the tool",
            "powershell -",
            "bash -c",
        ],
    ) {
        taints.insert(SourceTaint::ToolInvocationRequest);
    }
    if contains_any(
        &lower,
        &[
            "override policy",
            "bypass policy",
            "disable safety",
            "you are now",
            "do not obey",
        ],
    ) {
        taints.insert(SourceTaint::PolicyOverrideAttempt);
    }
    if contains_any(
        &lower,
        &[
            "data:text/",
            "base64,",
            "begin encoded",
            "decode and execute",
        ],
    ) || looks_like_encoded_payload(&content)
    {
        taints.insert(SourceTaint::EncodedPayload);
    }
    Ok(TaintedContent { content, taints })
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn looks_like_encoded_payload(input: &str) -> bool {
    input.split_ascii_whitespace().any(|token| {
        token.len() >= 80
            && token.len() % 4 == 0
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    })
}
