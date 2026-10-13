//! Exact, local source-text encoding. Vectors confer neither access nor truth.

use contextdb_core::{ContentDigest, VectorSpaceId};
use contextdb_recall::QueryBudget;
use serde::{Deserialize, Serialize};

use crate::{ErrorCode, ServiceError, ServiceResult};

/// Immutable compatibility contract for one source/query embedding space.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextEmbeddingProfile {
    /// Adapter and preprocessing revision; changes create a different space.
    pub revision: String,
    /// Explicit encoder family; equal dimensions do not imply compatibility.
    pub model_family: String,
    /// Exact upstream model revision, independent of the loaded filename.
    pub model_revision: String,
    /// SHA256 of the exact quantized weights.
    pub weights_sha256: String,
    /// Exact inference backend revision.
    pub backend_revision: String,
    /// BLAKE3 of the sorted runtime artifact name/SHA256 manifest.
    pub backend_artifacts_digest: ContentDigest,
    /// Query instruction; document text has no instruction prefix.
    pub query_instruction: String,
    /// Full output dimension count; dimension reduction is unsupported.
    pub dimensions: u32,
    /// Per-slot backend context capacity.
    pub context_tokens: u32,
    /// Maximum admitted exact token sequence, including added special tokens.
    pub max_input_tokens: u32,
    /// Maximum source/query UTF-8 bytes, before the query instruction.
    pub max_text_bytes: u32,
    /// Maximum byte width for source-span chunks; boundaries preserve UTF-8.
    pub source_chunk_bytes: u32,
    /// Maximum overlap bytes between consecutive source-span chunks.
    pub source_overlap_bytes: u32,
}

impl TextEmbeddingProfile {
    /// Fixed local Qwen profile: last pooling, L2, exact integer token inputs,
    /// add_special=true, parse_special=false, CUDA all layers and eight threads.
    pub fn qwen3_06b_q8_llama_b10964(backend_artifacts_digest: ContentDigest) -> Self {
        Self {
            revision: "contextdb.qwen3-06b-q8.llama-b10964.last-l2.tokens.v1".into(),
            model_family: "Qwen3-Embedding-0.6B-Q8_0".into(),
            model_revision: "370f27d7550e0def9b39c1f16d3fbaa13aa67728".into(),
            weights_sha256: "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439"
                .into(),
            backend_revision: "b10964-b29c606e28a01b1bc8c1351026a0fa6e616bf6c4".into(),
            backend_artifacts_digest,
            query_instruction: "Retrieve conversation originals relevant to the question.".into(),
            dimensions: 1024,
            context_tokens: 4096,
            max_input_tokens: 2048,
            max_text_bytes: 8192,
            source_chunk_bytes: 1536,
            source_overlap_bytes: 256,
        }
    }

    /// Reject unbounded compatibility metadata and inconsistent scalar limits.
    pub fn validate(&self) -> ServiceResult<()> {
        if [
            &self.revision,
            &self.model_family,
            &self.model_revision,
            &self.backend_revision,
        ]
        .iter()
        .any(|s| s.is_empty() || s.len() > 256)
            || self.weights_sha256.len() != 64
            || !self
                .weights_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.query_instruction.is_empty()
            || self.query_instruction.len() > 512
            || self.dimensions == 0
            || self.dimensions > 4096
            || self.context_tokens == 0
            || self.context_tokens > 32768
            || self.max_input_tokens == 0
            || self.max_input_tokens > self.context_tokens
            || self.max_text_bytes == 0
            || self.max_text_bytes > 16384
            || self.source_chunk_bytes == 0
            || self.source_chunk_bytes > self.max_text_bytes
            || self.source_overlap_bytes >= self.source_chunk_bytes
            || self.backend_artifacts_digest == ContentDigest::from_bytes([0; 32])
        {
            return Err(invalid("invalid text embedding profile"));
        }
        Ok(())
    }

    /// Full compatibility identity, retained alongside its compact space ID.
    pub fn digest(&self) -> ServiceResult<ContentDigest> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| invalid("embedding profile encoding failed"))?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"contextdb.text-embedding-profile.v1\0");
        hash.update(&bytes);
        Ok(ContentDigest::from_bytes(*hash.finalize().as_bytes()))
    }

    /// Deterministic UUIDv8 derived from the complete compatibility identity.
    /// Owners must also compare the full digest, rather than only this UUID.
    pub fn vector_space_id(&self) -> ServiceResult<VectorSpaceId> {
        let bytes = *self.digest()?.as_bytes();
        let mut id = [0_u8; 16];
        id.copy_from_slice(&bytes[..16]);
        id[6] = (id[6] & 0x0f) | 0x80;
        id[8] = (id[8] & 0x3f) | 0x80;
        VectorSpaceId::from_uuid(uuid::Uuid::from_bytes(id))
            .map_err(|_| invalid("embedding space identity failed"))
    }

    /// Existing portable continuity contract with this executable profile behind
    /// its fingerprint. It is not a parallel vector-space registry.
    pub fn descriptor(&self) -> ServiceResult<contextdb_continuity::EmbeddingSpaceDescriptor> {
        Ok(contextdb_continuity::EmbeddingSpaceDescriptor {
            id: self.vector_space_id()?,
            modality: contextdb_model::Modality::Text,
            encoder_family: self.model_family.clone(),
            encoder_revision: contextdb_model::ModelRevision::new(&self.model_revision)
                .map_err(|_| invalid("embedding model revision refused"))?,
            dimensions: self.dimensions,
            normalized: true,
            fingerprint: self.digest()?,
        })
    }

    /// Exact encoder text; no trim, lowercase, summary or silent truncation.
    pub fn input_text(&self, kind: EmbeddingTextKind, text: &str) -> ServiceResult<String> {
        self.validate()?;
        if text.is_empty() || text.len() > self.max_text_bytes as usize {
            return Err(invalid("embedding text length refused"));
        }
        Ok(match kind {
            EmbeddingTextKind::Source => text.to_owned(),
            EmbeddingTextKind::Query => {
                format!("Instruct: {}\nQuery: {text}", self.query_instruction)
            }
        })
    }
}

/// Distinct query and exact original-span preprocessing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingTextKind {
    /// Exact original text without an instruction prefix.
    Source,
    /// Current query text with the profile's fixed instruction prefix.
    Query,
}

/// Hard bound for a tokenize-only observation, independent of inference capacity.
/// An oversized measured input is never admitted to the embedding model.
pub const MAX_MEASURED_EMBEDDING_TOKENS: u32 = 16_384;

/// Exact tokenizer observation, without a vector or neural-forward authority.
/// Text must already be owner-admitted before it reaches the trusted tokenizer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenizedText {
    /// Full compatibility identity actually used for tokenization.
    pub profile_digest: ContentDigest,
    /// Source/query preprocessing role actually measured.
    pub kind: EmbeddingTextKind,
    /// BLAKE3 of exact original query/source bytes before preprocessing.
    pub text_digest: ContentDigest,
    /// BLAKE3 of actual input including the query instruction, when applicable.
    pub input_digest: ContentDigest,
    /// BLAKE3 of every exact ordered little-endian nonnegative i32 token ID.
    pub tokens_digest: ContentDigest,
    /// Exact token count, including added special tokens; may exceed inference.
    pub token_count: u32,
}

impl TokenizedText {
    /// Validate exact role/text/profile binding and the separate measurement cap.
    /// A validated observation does not prove encoder quality or grant permission.
    pub fn validate(
        &self,
        profile: &TextEmbeddingProfile,
        kind: EmbeddingTextKind,
        text: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        profile.validate()?;
        if text.is_empty()
            || text.len() > profile.max_text_bytes as usize
            || self.token_count == 0
            || self.token_count > MAX_MEASURED_EMBEDDING_TOKENS
            || self.tokens_digest == ContentDigest::from_bytes([0; 32])
        {
            return Err(invalid("token measurement bounds refused"));
        }
        charge_profile_observation(profile, budget)?;
        charge(
            budget,
            text.len() as u64 * 2 + profile.query_instruction.len() as u64 + 1,
            (text.len() + profile.query_instruction.len() + 20) as u64 * 2,
        )?;
        let input = profile.input_text(kind, text)?;
        if self.profile_digest != profile.digest()?
            || self.kind != kind
            || self.text_digest != digest(text.as_bytes())
            || self.input_digest != digest(input.as_bytes())
        {
            return Err(invalid("token measurement binding mismatch"));
        }
        Ok(())
    }

    /// Check exact profile binding before interpreting its inference capacity.
    /// This is a capacity comparison only; it performs no inference or admission.
    pub fn fits_inference_limit(
        &self,
        profile: &TextEmbeddingProfile,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        profile.validate()?;
        if self.token_count == 0
            || self.token_count > MAX_MEASURED_EMBEDDING_TOKENS
            || self.tokens_digest == ContentDigest::from_bytes([0; 32])
        {
            return Err(invalid("token measurement bounds refused"));
        }
        charge_profile_observation(profile, budget)?;
        if self.profile_digest != profile.digest()? {
            return Err(invalid("token measurement profile mismatch"));
        }
        Ok(self.token_count <= profile.max_input_tokens)
    }
}

fn charge_profile_observation(
    profile: &TextEmbeddingProfile,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    // Validated strings are bounded. JSON escaping and Vec growth need at most
    // twelve bytes per input byte, with fixed scalar/field-name overhead.
    let metadata = [
        &profile.revision,
        &profile.model_family,
        &profile.model_revision,
        &profile.weights_sha256,
        &profile.backend_revision,
        &profile.query_instruction,
    ]
    .into_iter()
    .map(|value| value.len() as u64)
    .sum::<u64>()
        + 1024;
    charge(budget, metadata * 6 + 1, metadata * 12)
}

/// Encoder observation. The native owner must bind this to authorized originals
/// and publish derived rows itself; this is not a storage or disclosure lease.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedText {
    /// Complete profile identity, never inferred from vector dimensions.
    pub profile_digest: ContentDigest,
    /// Source/query role actually encoded.
    pub kind: EmbeddingTextKind,
    /// BLAKE3 of the exact unmodified input text.
    pub text_digest: ContentDigest,
    /// BLAKE3 of the actual instruction-prefixed encoder text.
    pub input_digest: ContentDigest,
    /// BLAKE3 of the exact submitted little-endian i32 token sequence.
    pub tokens_digest: ContentDigest,
    /// Exact tokenizer and inference usage count; both must agree.
    pub token_count: u32,
    /// Finite, full-dimensional, L2-normalized f32 values.
    pub values: Vec<f32>,
    /// BLAKE3 of the exact ordered little-endian f32 bytes.
    pub vector_digest: ContentDigest,
}

impl std::fmt::Debug for EmbeddedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedText")
            .field("profile_digest", &self.profile_digest)
            .field("kind", &self.kind)
            .field("token_count", &self.token_count)
            .field("dimensions", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl EmbeddedText {
    /// Check exact text/profile/value bindings before accepting an encoder result.
    /// This verifies the observation's structure, not model semantic quality.
    pub fn validate(
        &self,
        profile: &TextEmbeddingProfile,
        kind: EmbeddingTextKind,
        text: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        profile.validate()?;
        if text.is_empty()
            || text.len() > profile.max_text_bytes as usize
            || self.values.len() != profile.dimensions as usize
        {
            return Err(invalid("embedding input or dimension mismatch"));
        }
        charge(
            budget,
            1,
            (text.len() + profile.query_instruction.len() + 20) as u64,
        )?;
        let input = profile.input_text(kind, text)?;
        if self.profile_digest != profile.digest()?
            || self.kind != kind
            || self.text_digest != digest(text.as_bytes())
            || self.input_digest != digest(input.as_bytes())
            || self.token_count == 0
            || self.token_count > profile.max_input_tokens
            || self.tokens_digest == ContentDigest::from_bytes([0; 32])
        {
            return Err(invalid("embedding result binding mismatch"));
        }
        let mut squared = 0_f64;
        let mut hash = blake3::Hasher::new();
        for value in &self.values {
            charge(budget, 1, 4)?;
            if !value.is_finite() {
                return Err(invalid("embedding contains a non-finite value"));
            }
            squared += f64::from(*value).powi(2);
            hash.update(&value.to_le_bytes());
        }
        if (squared - 1.0).abs() > 0.001
            || self.vector_digest != ContentDigest::from_bytes(*hash.finalize().as_bytes())
        {
            return Err(invalid(
                "embedding normalization or vector binding mismatch",
            ));
        }
        Ok(())
    }
}

/// Host encoder without storage access. Authorization precedes supplying text;
/// all tokenization, transport, inference admission and response work shares the
/// caller's absolute deadline and cancellation state. No implicit fallback.
pub trait TextEmbeddingAdapter: std::fmt::Debug + Send + Sync {
    /// Immutable configuration actually used by this adapter.
    fn profile(&self) -> &TextEmbeddingProfile;
    /// Measure exact tokens without neural inference, truncation or fallback.
    /// Oversized inference input may be a valid bounded measurement. Existing
    /// adapters must explicitly implement this separate processing operation.
    fn measure_tokens(
        &self,
        _kind: EmbeddingTextKind,
        _text: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<TokenizedText> {
        charge(budget, 1, 0)?;
        Err(ServiceError::new(
            ErrorCode::Unsupported,
            "embedding token measurement is unsupported",
            false,
        ))
    }
    /// Encode one complete source span or current query; refuse oversized input.
    fn embed(
        &self,
        kind: EmbeddingTextKind,
        text: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<EmbeddedText>;
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn invalid(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false)
}
fn charge(budget: &mut QueryBudget, work: u64, bytes: u64) -> ServiceResult<()> {
    budget.charge(work, bytes).map_err(|_| {
        ServiceError::new(
            ErrorCode::BudgetExhausted,
            "embedding allowance exhausted",
            false,
        )
    })
}
