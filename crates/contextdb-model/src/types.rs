use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use contextdb_core::{ContentDigest, ModelProfileId};
use serde::{Deserialize, Serialize};

use crate::{ModelRuntimeError, Result};

pub(crate) const MAX_ID_BYTES: usize = 256;
pub(crate) const MAX_TEXT_BYTES: usize = 16 * 1024;

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[doc = concat!("Bounded stable `", stringify!($name), "` identifier.")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated `", stringify!($name), "`.")]
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_text(&value, $field, MAX_ID_BYTES)?;
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
    };
}

bounded_identifier!(ProviderId, "provider_id");
bounded_identifier!(ModelRevision, "model_revision");
bounded_identifier!(SchemaId, "schema_id");
bounded_identifier!(PromptAssetId, "prompt_asset_id");
bounded_identifier!(RegionId, "region_id");
bounded_identifier!(LanguageTag, "language_tag");

/// ISO-4217-style three-letter uppercase currency code used to prevent mixing
/// incomparable cost budgets.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    /// Creates a three-letter uppercase ASCII currency code.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(ModelRuntimeError::InvalidText {
                field: "currency_code",
                reason: "must contain three uppercase ASCII letters",
            });
        }
        Ok(Self(value))
    }

    /// Returns the stable textual code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for CurrencyCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Versioned specialized compute capability.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    /// Extract memory candidates from durable episodes.
    ExtractMemoryCandidates,
    /// Segment observations into episode proposals.
    SegmentEpisodes,
    /// Resolve speaker or source perspective.
    ResolvePerspective,
    /// Interpret a natural-language recall request.
    InterpretRecallIntent,
    /// Resolve conversational references.
    ResolveConversationalReferents,
    /// Judge proposed-memory salience.
    JudgeMemorySalience,
    /// Propose silent, mention, constraint-only, or suppress use.
    DecideMemoryUse,
    /// Produce a representation in one explicit vector space.
    GenerateEmbedding,
    /// Rerank an already policy-filtered candidate set.
    RerankCandidates,
    /// Propose a source-bound region summary.
    SummarizeRegion,
    /// Judge whether required semantic facets are covered.
    JudgeSufficiency,
    /// Propose a conflict classification or adjudication.
    AdjudicateConflict,
    /// Classify content sensitivity.
    ClassifySensitivity,
    /// Propose a reusable procedure.
    DetectProcedure,
    /// Propose patterns over bounded episode windows.
    ReflectOnEpisodes,
    /// Compress already selected context.
    CompressContext,
    /// Describe an artifact without replacing it.
    DescribeArtifact,
    /// Transcribe an artifact without replacing it.
    TranscribeArtifact,
    /// Produce a cross-modal representation.
    CrossModalRepresent,
    /// Versioned domain extension.
    Domain(String),
}

impl ModelCapability {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Self::Domain(value) = self {
            validate_text(value, "model_capability.domain", MAX_ID_BYTES)?;
        }
        Ok(())
    }
}

/// Input or output modality advertised by a route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// UTF-8 or structured text.
    Text,
    /// Image content or derived regions.
    Image,
    /// Audio content or time spans.
    Audio,
    /// Video content or time spans.
    Video,
    /// General document structure.
    Document,
    /// Source code.
    Code,
    /// Tool result data.
    ToolResult,
    /// Numeric vector output.
    Vector,
}

/// Model structured-output representation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredFormat {
    /// Strict JSON constrained by a versioned schema.
    JsonSchema,
    /// Protobuf-derived structured output.
    Protobuf,
}

/// Model-specific placement behavior measured by evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PositionProfile {
    /// Keep hard constraints near the beginning.
    pub constraints_first: bool,
    /// Place exact evidence adjacent to supported claims.
    pub evidence_near_claim: bool,
    /// Prefer summary before detail.
    pub summary_before_detail: bool,
    /// Place unknowns before action instructions.
    pub unknowns_before_actions: bool,
}

/// Provider-specific instruction hierarchy behavior.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionHierarchy {
    /// Highest-to-lowest supported instruction channels.
    pub channels: Vec<String>,
    /// Whether tool results have a distinct non-instruction boundary.
    pub isolates_tool_results: bool,
    /// Whether caller content has a distinct non-instruction boundary.
    pub isolates_user_content: bool,
}

impl InstructionHierarchy {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.channels.is_empty() {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "instruction_hierarchy.channels",
                reason: "must not be empty",
            });
        }
        let mut distinct = BTreeSet::new();
        for channel in &self.channels {
            validate_text(channel, "instruction_hierarchy.channel", MAX_ID_BYTES)?;
            if !distinct.insert(channel) {
                return Err(ModelRuntimeError::RegistryConflict(
                    "duplicate instruction channel".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Versioned runtime description of one model revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProfile {
    /// Stable profile identity from the model-independent core.
    pub id: ModelProfileId,
    /// Provider-neutral family label.
    pub family: String,
    /// Exact model revision.
    pub revision: ModelRevision,
    /// Tokenizer family and revision.
    pub tokenizer: String,
    /// Maximum complete context window.
    pub max_context_tokens: u32,
    /// Tokens reserved for model output.
    pub reserved_output_tokens: u32,
    /// Preferred structured output format.
    pub preferred_structured_format: StructuredFormat,
    /// Tool-result boundary support.
    pub supports_tool_results: bool,
    /// Native citation support.
    pub supports_native_citations: bool,
    /// Prompt-prefix cache support.
    pub supports_prompt_caching: bool,
    /// Measured placement behavior.
    pub position_profile: PositionProfile,
    /// Instruction/data boundary behavior.
    pub instruction_hierarchy: InstructionHierarchy,
    /// Maximum supported schema complexity score.
    pub max_schema_complexity: u32,
    /// Evaluated languages.
    pub languages: BTreeSet<LanguageTag>,
    /// Evaluated modalities.
    pub modalities: BTreeSet<Modality>,
}

impl ModelProfile {
    /// Checks the profile without consulting providers or external state.
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.family, "model_profile.family", MAX_ID_BYTES)?;
        validate_text(&self.tokenizer, "model_profile.tokenizer", MAX_ID_BYTES)?;
        if self.max_context_tokens == 0
            || self.reserved_output_tokens == 0
            || self.reserved_output_tokens >= self.max_context_tokens
            || self.max_schema_complexity == 0
            || self.languages.is_empty()
            || self.modalities.is_empty()
        {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "model_profile",
                reason: "invalid context, output, schema, or modality bounds",
            });
        }
        self.instruction_hierarchy.validate()
    }
}

/// Strong reference to one immutable structured-output schema.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRef {
    /// Schema family.
    pub id: SchemaId,
    /// Monotonic family-local version.
    pub version: u32,
    /// Digest of the exact executable schema definition.
    pub digest: ContentDigest,
}

/// Strong reference to one immutable prompt asset.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptAssetRef {
    /// Prompt family.
    pub id: PromptAssetId,
    /// Monotonic family-local version.
    pub version: u32,
    /// Digest of the exact prompt metadata, schema binding, and text.
    pub digest: ContentDigest,
}

/// Coarse content classification evaluated before routing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Public data.
    Public,
    /// Workspace-internal data.
    Internal,
    /// Confidential data needing an explicit external policy.
    Confidential,
    /// Restricted data normally routed locally or redacted.
    Restricted,
    /// Secret material; model calls are forbidden by default.
    Secret,
}

/// Local versus external provider execution boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLocality {
    /// In-process, on-device, or deployment-local execution.
    Local,
    /// External hosted execution.
    Hosted,
}

/// Stable fixed-point score in basis points (`0..=10_000`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BasisPoints(u16);

impl BasisPoints {
    /// Creates a score in the closed unit interval.
    pub fn new(value: u16) -> Result<Self> {
        if value > 10_000 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "basis_points",
                reason: "must be at most 10000",
            });
        }
        Ok(Self(value))
    }

    /// Returns the stable integer representation.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for BasisPoints {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Deterministic monetary estimate in integer micro-units.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostProfile {
    /// Currency of every micro-unit.
    pub currency: CurrencyCode,
    /// Fixed request cost.
    pub request_micros: u64,
    /// Input cost per one million tokens.
    pub input_micros_per_million_tokens: u64,
    /// Output cost per one million tokens.
    pub output_micros_per_million_tokens: u64,
}

impl CostProfile {
    /// Computes a conservative deterministic cost estimate.
    pub fn estimate(&self, input_tokens: u32, output_tokens: u32) -> Result<u64> {
        let input = u128::from(self.input_micros_per_million_tokens)
            .saturating_mul(u128::from(input_tokens))
            .saturating_add(999_999)
            / 1_000_000;
        let output = u128::from(self.output_micros_per_million_tokens)
            .saturating_mul(u128::from(output_tokens))
            .saturating_add(999_999)
            / 1_000_000;
        let total = u128::from(self.request_micros)
            .saturating_add(input)
            .saturating_add(output);
        u64::try_from(total).map_err(|_| ModelRuntimeError::ArithmeticOverflow)
    }
}

/// Measured route latency profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyProfile {
    /// Median latency.
    pub p50_ms: u64,
    /// Tail latency used by routing.
    pub p95_ms: u64,
}

impl LatencyProfile {
    pub(crate) fn validate(self) -> Result<()> {
        if self.p50_ms > self.p95_ms {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "latency_profile",
                reason: "p50 must not exceed p95",
            });
        }
        Ok(())
    }
}

/// Data-handling promises advertised by a route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataHandlingPolicy {
    /// Execution boundary.
    pub locality: ExecutionLocality,
    /// Processing region, if meaningful.
    pub region: Option<RegionId>,
    /// Provider declares that inputs are not used for training.
    pub no_training: bool,
    /// Provider declares no post-call payload retention.
    pub no_retention: bool,
    /// Highest accepted input classification.
    pub maximum_sensitivity: Sensitivity,
}

/// Capability implementation advertised by one provider/model route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDescriptor {
    /// Specialized operation.
    pub capability: ModelCapability,
    /// Model profile used by this route.
    pub model_profile: ModelProfileId,
    /// Accepted input modalities.
    pub input_modalities: BTreeSet<Modality>,
    /// Exact structured output contract.
    pub output_schema: SchemaRef,
    /// Hard input token bound.
    pub max_input_tokens: u32,
    /// Whether the adapter can accept compatible batches.
    pub supports_batching: bool,
    /// Whether streaming is supported at the provider boundary.
    pub supports_streaming: bool,
    /// Cost estimate used before execution.
    pub expected_cost: CostProfile,
    /// Measured latency.
    pub latency_profile: LatencyProfile,
    /// Privacy and residency boundary.
    pub data_policy: DataHandlingPolicy,
    /// Golden/adversarial benchmark score.
    pub benchmark_score: BasisPoints,
    /// Measured strict-schema success rate.
    pub schema_reliability: BasisPoints,
    /// Evaluated languages; empty means language-agnostic/unknown.
    pub languages: BTreeSet<LanguageTag>,
}

impl CapabilityDescriptor {
    /// Checks route-local invariants.
    pub fn validate(&self) -> Result<()> {
        self.capability.validate()?;
        if self.input_modalities.is_empty() || self.max_input_tokens == 0 {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "capability_descriptor",
                reason: "modalities and input budget must be non-empty",
            });
        }
        if self.output_schema.version == 0
            || self
                .output_schema
                .digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ModelRuntimeError::InvalidNumber {
                field: "capability_descriptor.output_schema",
                reason: "version and digest must be non-zero",
            });
        }
        self.latency_profile.validate()
    }
}

/// One registered provider/model/capability route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRoute {
    /// Provider boundary identity.
    pub provider: ProviderId,
    /// Exact provider model revision.
    pub model_revision: ModelRevision,
    /// Capability contract.
    pub descriptor: CapabilityDescriptor,
}

impl CapabilityRoute {
    /// Checks route-local invariants.
    pub fn validate(&self) -> Result<()> {
        self.descriptor.validate()
    }
}

/// Provider-safe token usage returned after a call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelUsage {
    /// Input tokens, when measured.
    pub input_tokens: Option<u64>,
    /// Output tokens, when measured.
    pub output_tokens: Option<u64>,
    /// Charged integer micro-units, when known.
    pub cost_micros: Option<u64>,
}

pub(crate) fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(ModelRuntimeError::InvalidText {
            field,
            reason: "must not be blank",
        });
    }
    if value.len() > maximum {
        return Err(ModelRuntimeError::InvalidText {
            field,
            reason: "exceeds UTF-8 byte limit",
        });
    }
    Ok(())
}

pub(crate) fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> ContentDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&part.len().to_be_bytes());
        hasher.update(part);
    }
    ContentDigest::from_bytes(*hasher.finalize().as_bytes())
}

pub(crate) fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<ContentDigest> {
    let encoded = serde_json::to_vec(value)?;
    Ok(digest_parts(domain, &[&encoded]))
}

/// Low-cardinality route attributes suitable for metrics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSummary {
    /// Capability.
    pub capability: ModelCapability,
    /// Provider identifier.
    pub provider: ProviderId,
    /// Local versus hosted.
    pub locality: ExecutionLocality,
    /// Conservative cost estimate.
    pub estimated_cost_micros: u64,
    /// Currency of the conservative cost estimate.
    pub estimated_cost_currency: CurrencyCode,
    /// Tail latency estimate.
    pub expected_p95_ms: u64,
}

/// Snapshot of registered profiles for migration and diagnostics.
pub type ModelProfileMap = BTreeMap<ModelProfileId, ModelProfile>;
