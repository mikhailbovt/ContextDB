//! Owner-published exact source-span vectors. Encoding coverage is explicit.

use super::*;
use contextdb_core::{EventPayload, OriginalSourceSpan, VectorSpaceId};
use contextdb_service::{EmbeddedText, EmbeddingTextKind, TextEmbeddingProfile};

pub(crate) mod graph;
mod projection;
pub use graph::DenseGraphManifest;
pub(in crate::raw_index) use projection::receipt_key;
#[cfg(test)]
mod tests;
mod verify;

pub(crate) const FEATURE: &str = "continuous-raw-source-embeddings-v1";
pub(crate) const OPERATION: &str = "raw_source_embeddings";
const MAX_SOURCE_BYTES: u64 = 64 * 1024;
const MAX_SOURCE_SPANS: usize = 64;
const MAX_DENSE_ROW_BYTES: usize = 64 * 1024;
const RECEIPT_DOMAIN: &[u8] = b"contextdb.native-source-embedding-receipt.v1\0";
const DOCUMENT_DOMAIN: &[u8] = b"contextdb.native-source-embedding-document.v1\0";
const VECTOR_DOMAIN: &[u8] = b"contextdb.native-source-embedding-vector.v1\0";

type DenseSourcePlan = (
    Option<DenseOmission>,
    Vec<OriginalSourceSpan>,
    zeroize::Zeroizing<Vec<u8>>,
);
type ReconstructedDenseSource = (DenseDocument, BTreeMap<Vec<u8>, Vec<u8>>);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenseManifest {
    pub(crate) profile: TextEmbeddingProfile,
    pub(crate) profile_digest: ContentDigest,
    pub(crate) vector_space_id: VectorSpaceId,
    pub(crate) through: u64,
    pub(crate) sources: u64,
    pub(crate) embedded_sources: u64,
    pub(crate) spans: u64,
    pub(crate) omitted_sources: u64,
    /// Ordered commitment to every complete source document and its vector hashes.
    pub(crate) commitment: ContentDigest,
}

impl DenseManifest {
    pub(super) fn empty(profile: &TextEmbeddingProfile) -> ServiceResult<Self> {
        validate_profile(profile)?;
        Ok(Self {
            profile: profile.clone(),
            profile_digest: profile.digest()?,
            vector_space_id: profile.vector_space_id()?,
            through: 0,
            sources: 0,
            embedded_sources: 0,
            spans: 0,
            omitted_sources: 0,
            commitment: digest(b"contextdb.native-source-embedding-empty.v1\0"),
        })
    }

    pub(crate) fn validate(&self, raw_through: u64) -> ServiceResult<()> {
        validate_profile(&self.profile)?;
        if self.profile_digest != self.profile.digest()?
            || self.vector_space_id != self.profile.vector_space_id()?
            || self.through > raw_through
            || self.sources > self.through
            || self.embedded_sources.checked_add(self.omitted_sources) != Some(self.sources)
            || self.spans < self.embedded_sources
            || self.spans
                > self
                    .embedded_sources
                    .saturating_mul(MAX_SOURCE_SPANS as u64)
        {
            return Err(integrity("source embedding manifest binding differs"));
        }
        Ok(())
    }

    pub(super) fn accept(&mut self, document: &DenseDocument) -> ServiceResult<()> {
        self.sources = self
            .sources
            .checked_add(1)
            .ok_or_else(|| exhausted("dense source count overflow"))?;
        if document.omission.is_none() {
            self.embedded_sources = self
                .embedded_sources
                .checked_add(1)
                .ok_or_else(|| exhausted("dense encoded count overflow"))?;
            self.spans = self
                .spans
                .checked_add(document.spans.len() as u64)
                .ok_or_else(|| exhausted("dense span count overflow"))?;
        } else {
            self.omitted_sources = self
                .omitted_sources
                .checked_add(1)
                .ok_or_else(|| exhausted("dense omission count overflow"))?;
        }
        self.commitment = ContentDigest::from_bytes(
            *blake3::hash(&encode(&(
                "contextdb.native-source-embedding-chain.v1",
                self.commitment,
                document,
            ))?)
            .as_bytes(),
        );
        Ok(())
    }
}

/// A synchronized maintenance receipt, not a claim of semantic recall or erasure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenseProjectionReceipt {
    /// Native database and workspace, also covered by the owner authentication tag.
    pub database_id: String,
    /// Workspace whose accepted outbox was consumed.
    pub workspace_id: String,
    /// Existing raw/BM25 generation; vectors have the same retirement lifecycle.
    pub generation: u64,
    /// Raw prefix visible before this publication; dense may explicitly lag it.
    pub raw_through: u64,
    /// Raw documents in that prefix, used to refuse missing outbox coverage.
    pub raw_sources: u64,
    /// Authorization epoch used for every forwarded original.
    pub authorization_epoch: u64,
    /// Complete consumed dense prefix, including explicit omissions/removals.
    pub through: u64,
    /// Sources with a document, including omissions, excluding prepared removals.
    pub sources: u64,
    /// Sources whose entire admitted span plan was encoded.
    pub embedded_sources: u64,
    /// Encoded exact source spans.
    pub spans: u64,
    /// Explicit excluded sources; not negative relevance labels.
    pub omitted_sources: u64,
    /// Whether dense caught up with this receipt's raw prefix.
    pub caught_up: bool,
    /// Immutable full encoder manifest survives retired-generation GC.
    pub profile: TextEmbeddingProfile,
    /// Full compatibility identity; dimensions alone never select a space.
    pub profile_digest: ContentDigest,
    /// Owner-accepted ordered source/vector commitment.
    pub commitment: ContentDigest,
    /// Native publication position, protected by the owner authentication tag.
    pub global_commit: u64,
    /// Owner authentication; no encoder or model JSON can mint this receipt.
    pub token: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DenseOmission {
    ModelRequestEcho,
    DerivedAssembly,
    OperationalControl,
    Unavailable,
    NonText,
    TooLarge,
    EmptyText,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenseSpan {
    pub(crate) span: OriginalSourceSpan,
    pub(crate) vector_digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenseDocument {
    pub(crate) source: RawSource,
    pub(crate) event_digest: ContentDigest,
    pub(crate) commit: u64,
    pub(crate) policy_domain: String,
    pub(crate) profile_digest: ContentDigest,
    pub(crate) omission: Option<DenseOmission>,
    pub(crate) spans: Vec<DenseSpan>,
    pub(crate) token: String,
}

/// Exact f32 bits avoid JSON numeric round-trip changing a vector commitment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenseVector {
    pub(crate) source: RawSource,
    pub(crate) event_digest: ContentDigest,
    pub(crate) commit: u64,
    pub(crate) policy_domain: String,
    pub(crate) profile_digest: ContentDigest,
    pub(crate) ordinal: u32,
    pub(crate) span: OriginalSourceSpan,
    pub(crate) input_digest: ContentDigest,
    pub(crate) tokens_digest: ContentDigest,
    pub(crate) token_count: u32,
    pub(crate) values_bits: Vec<u32>,
    pub(crate) vector_digest: ContentDigest,
    pub(crate) token: String,
}

pub(crate) fn document_key(workspace: &str, generation: u64, event: ObservationId) -> Vec<u8> {
    format!(
        "{}dense/document/{event}",
        generation_prefix(workspace, generation)
    )
    .into_bytes()
}
pub(crate) fn vector_key(
    workspace: &str,
    generation: u64,
    event: ObservationId,
    ordinal: u32,
) -> Vec<u8> {
    format!(
        "{}dense/vector/{event}/{ordinal:08x}",
        generation_prefix(workspace, generation)
    )
    .into_bytes()
}
fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}
fn validate_profile(profile: &TextEmbeddingProfile) -> ServiceResult<()> {
    profile.validate()?;
    if profile != &TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(profile.backend_artifacts_digest)
        || profile.backend_artifacts_digest.as_bytes() == &[0; 32]
    {
        return Err(integrity(
            "dense projection requires the fixed local encoder profile",
        ));
    }
    Ok(())
}

/// Pure deterministic byte plan. Every admitted character is covered; no trim.
fn spans_for_text(
    event: &EventEnvelope,
    text: &str,
    profile: &TextEmbeddingProfile,
) -> ServiceResult<Vec<OriginalSourceSpan>> {
    let mut spans = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + profile.source_chunk_bytes as usize).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if end <= start || spans.len() >= MAX_SOURCE_SPANS {
            return Err(integrity("dense span plan exceeds its fixed bound"));
        }
        spans.push(OriginalSourceSpan {
            event_id: event.event_id,
            payload_digest: event
                .payload
                .digest()
                .ok_or_else(|| integrity("dense original has no complete digest"))?,
            start: start as u64,
            end: end as u64,
            span_digest: digest(&text.as_bytes()[start..end]),
        });
        if end == text.len() {
            break;
        }
        let mut next = end.saturating_sub(profile.source_overlap_bytes as usize);
        while !text.is_char_boundary(next) {
            next += 1;
        }
        if next <= start {
            return Err(integrity("dense span plan made no progress"));
        }
        start = next;
    }
    Ok(spans)
}

impl NativeService {
    fn dense_plan<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
        profile: &TextEmbeddingProfile,
        context: Option<&AuthenticatedRequestContext>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseSourcePlan> {
        let source = RawSource::from(event);
        let omission = if event.kind == EventKind::ModelRequested {
            Some(DenseOmission::ModelRequestEcho)
        } else if matches!(event.payload, EventPayload::Assembly { .. }) {
            Some(DenseOmission::DerivedAssembly)
        } else if matches!(
            event.kind,
            EventKind::RunStarted
                | EventKind::RunCheckpointed
                | EventKind::RunResumed
                | EventKind::RunCancelled
        ) {
            Some(DenseOmission::OperationalControl)
        } else if source.payload_digest.is_none() || source.byte_length.is_none() {
            Some(DenseOmission::Unavailable)
        } else if source.byte_length.is_some_and(|n| n > MAX_SOURCE_BYTES) {
            Some(DenseOmission::TooLarge)
        } else if source.byte_length == Some(0) {
            Some(DenseOmission::EmptyText)
        } else if matches!(&event.payload, EventPayload::InlineBytes { media_type, .. } | EventPayload::Staged { media_type, .. }
                if !(media_type.starts_with("text/") || media_type == "application/json"))
        {
            Some(DenseOmission::NonText)
        } else {
            None
        };
        if omission.is_some() {
            return Ok((omission, Vec::new(), zeroize::Zeroizing::new(Vec::new())));
        }
        let length = source
            .byte_length
            .ok_or_else(|| integrity("dense length absent"))?;
        let bytes = zeroize::Zeroizing::new(if let Some(context) = context {
            self.original_range_with_budget(snapshot, context, event, 0, length, budget)?
        } else {
            self.original_range_for_custody_with_budget(snapshot, event, 0, length, budget)?
        });
        if digest(&bytes)
            != source
                .payload_digest
                .ok_or_else(|| integrity("dense payload digest absent"))?
        {
            return Err(integrity(
                "dense source bytes differ from accepted original",
            ));
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Ok((Some(DenseOmission::NonText), Vec::new(), bytes));
        };
        budget
            .charge(1, MAX_SOURCE_SPANS as u64 * 192)
            .map_err(budget_error)?;
        let spans = spans_for_text(event, text, profile)?;
        Ok((None, spans, bytes))
    }

    fn sign_dense_document(&self, document: &mut DenseDocument) -> ServiceResult<()> {
        document.token.clear();
        document.token = crate::keyed_token(&self.token_key, DOCUMENT_DOMAIN, &encode(document)?);
        Ok(())
    }
    fn sign_dense_vector(&self, vector: &mut DenseVector) -> ServiceResult<()> {
        vector.token.clear();
        vector.token = crate::keyed_token(&self.token_key, VECTOR_DOMAIN, &encode(vector)?);
        Ok(())
    }
    pub(in crate::raw_index) fn check_dense_document_token(
        &self,
        document: &DenseDocument,
    ) -> ServiceResult<()> {
        let mut expected = document.clone();
        self.sign_dense_document(&mut expected)?;
        if expected.token != document.token {
            return Err(integrity("dense document owner authentication differs"));
        }
        Ok(())
    }
    pub(in crate::raw_index) fn check_dense_vector_token(
        &self,
        vector: &DenseVector,
    ) -> ServiceResult<()> {
        let mut expected = vector.clone();
        self.sign_dense_vector(&mut expected)?;
        if expected.token != vector.token {
            return Err(integrity("dense vector owner authentication differs"));
        }
        Ok(())
    }
}
