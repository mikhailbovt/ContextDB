use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{CommitSeq, LineageNode, RepresentationId, TimeRange, TimestampMicros};
use serde::{Deserialize, Serialize};
#[cfg(feature = "lexical-tantivy")]
use tantivy::collector::TopDocs;
#[cfg(feature = "lexical-tantivy")]
use tantivy::query::QueryParser;
#[cfg(feature = "lexical-tantivy")]
use tantivy::schema::{INDEXED, STORED, Schema, TEXT, TantivyDocument, Value};
#[cfg(feature = "lexical-tantivy")]
use tantivy::{Index, doc};

use crate::{IndexError, IndexPolicy, IndexPrincipal, Result};

/// Rebuildable lexical projection of one semantic or evidence representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LexicalDocument {
    pub id: RepresentationId,
    pub target: LineageNode,
    pub text: String,
    pub aliases: Vec<String>,
    pub policy: IndexPolicy,
    pub valid_time: TimeRange,
    pub projected_at: CommitSeq,
    pub lineage: Vec<LineageNode>,
    pub tombstone_at: Option<CommitSeq>,
}

impl LexicalDocument {
    /// Enforces non-empty content and ordered projection/deletion times.
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        if self.text.trim().is_empty() {
            return Err(IndexError::Invalid("lexical text must not be blank"));
        }
        if self.aliases.iter().any(|alias| alias.trim().is_empty()) {
            return Err(IndexError::Invalid("lexical alias must not be blank"));
        }
        if self
            .tombstone_at
            .is_some_and(|deleted| deleted < self.projected_at)
        {
            return Err(IndexError::Invalid(
                "lexical tombstone precedes its projection",
            ));
        }
        Ok(())
    }
}

/// Opaque, policy-filtered document universe. Text is deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedLexicalUniverse {
    snapshot: CommitSeq,
    generation: u64,
    document_ids: BTreeSet<RepresentationId>,
}

/// One lexical result with stable representation and target identity.
#[derive(Clone, Debug, PartialEq)]
pub struct LexicalHit {
    pub representation_id: RepresentationId,
    pub target: LineageNode,
    pub score: f32,
}

/// Privacy-safe query diagnostics. Rejected-document counts are not exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LexicalTrace {
    pub snapshot: CommitSeq,
    pub generation: u64,
    pub authorized_examined: u64,
    pub returned: u64,
    pub watermark: CommitSeq,
}

/// Result from either the deterministic oracle or Tantivy projection.
#[derive(Clone, Debug, PartialEq)]
pub struct LexicalSearchResult {
    pub hits: Vec<LexicalHit>,
    pub trace: LexicalTrace,
}

/// Self-verifying portable lexical generation used for staged publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentLexicalGeneration {
    pub schema_version: u16,
    pub generation: u64,
    pub watermark: CommitSeq,
    pub payload_digest: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LexicalPayload {
    schema_version: u16,
    generation: u64,
    watermark: CommitSeq,
    documents: BTreeMap<RepresentationId, LexicalDocument>,
}

/// Immutable lexical generation plus mutable exact delta.
#[derive(Clone, Debug, Default)]
pub struct LexicalIndex {
    generation: u64,
    watermark: CommitSeq,
    base: BTreeMap<RepresentationId, LexicalDocument>,
    delta: BTreeMap<RepresentationId, LexicalDocument>,
}

impl LexicalIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stages or replaces a delta projection after structural validation.
    pub fn upsert(&mut self, document: LexicalDocument) -> Result<()> {
        document.validate()?;
        self.delta.insert(document.id, document);
        Ok(())
    }

    /// Publishes deterministic base+delta and returns its canonical digest.
    pub fn publish_generation(
        &mut self,
        generation: u64,
        watermark: CommitSeq,
    ) -> Result<[u8; 32]> {
        if generation <= self.generation {
            return Err(IndexError::StaleGeneration);
        }
        if watermark < self.watermark {
            return Err(IndexError::StaleGeneration);
        }
        let mut next = self.base.clone();
        let eligible = self
            .delta
            .iter()
            .filter_map(|(id, document)| (document.projected_at <= watermark).then_some(*id))
            .collect::<Vec<_>>();
        for id in &eligible {
            let document = self
                .delta
                .get(id)
                .ok_or(IndexError::UnknownRepresentation(*id))?;
            next.insert(*id, document.clone());
        }
        let bytes = serde_json::to_vec(&(generation, watermark, &next))?;
        let digest = *blake3::hash(&bytes).as_bytes();
        self.base = next;
        for id in eligible {
            self.delta.remove(&id);
        }
        self.generation = generation;
        self.watermark = watermark;
        Ok(digest)
    }

    /// Exports the active immutable generation with a canonical digest.
    pub fn export_generation(&self) -> Result<PersistentLexicalGeneration> {
        let payload = LexicalPayload {
            schema_version: 1,
            generation: self.generation,
            watermark: self.watermark,
            documents: self.base.clone(),
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(PersistentLexicalGeneration {
            schema_version: 1,
            generation: self.generation,
            watermark: self.watermark,
            payload_digest: *blake3::hash(&bytes).as_bytes(),
            payload: bytes,
        })
    }

    /// Restores a verified immutable generation into an empty index.
    pub fn import_generation(&mut self, bundle: PersistentLexicalGeneration) -> Result<()> {
        if !self.base.is_empty() || !self.delta.is_empty() || self.generation != 0 {
            return Err(IndexError::Invalid(
                "lexical generation restore target must be empty",
            ));
        }
        if bundle.schema_version != 1
            || *blake3::hash(&bundle.payload).as_bytes() != bundle.payload_digest
        {
            return Err(IndexError::Invalid(
                "lexical generation schema or digest mismatch",
            ));
        }
        let payload: LexicalPayload = serde_json::from_slice(&bundle.payload)?;
        if payload.schema_version != bundle.schema_version
            || payload.generation != bundle.generation
            || payload.watermark != bundle.watermark
        {
            return Err(IndexError::Invalid("lexical generation manifest mismatch"));
        }
        for document in payload.documents.values() {
            document.validate()?;
            if document.projected_at > payload.watermark {
                return Err(IndexError::FutureWatermark {
                    watermark: document.projected_at,
                    snapshot: payload.watermark,
                });
            }
        }
        self.base = payload.documents;
        self.generation = payload.generation;
        self.watermark = payload.watermark;
        Ok(())
    }

    /// Builds an opaque universe using policy metadata only.
    pub fn authorize(
        &self,
        principal: &IndexPrincipal,
        snapshot: CommitSeq,
    ) -> Result<AuthorizedLexicalUniverse> {
        if self.watermark > snapshot {
            return Err(IndexError::FutureWatermark {
                watermark: self.watermark,
                snapshot,
            });
        }
        let documents = self.documents();
        let mut ids = BTreeSet::new();
        for (id, document) in documents {
            if document.projected_at <= snapshot
                && document
                    .tombstone_at
                    .is_none_or(|deleted| deleted > snapshot)
                && document.policy.authorizes(principal, snapshot)
            {
                ids.insert(id);
            }
        }
        Ok(AuthorizedLexicalUniverse {
            snapshot,
            generation: self.generation,
            document_ids: ids,
        })
    }

    /// Deterministic exact lexical oracle over only authorized documents.
    pub fn search_exact(
        &self,
        universe: &AuthorizedLexicalUniverse,
        query: &str,
        valid_at: Option<TimestampMicros>,
        limit: usize,
    ) -> Result<LexicalSearchResult> {
        self.validate_universe(universe)?;
        if limit == 0 {
            return Err(IndexError::InvalidBudget);
        }
        let query_terms = tokens(query);
        if query_terms.is_empty() {
            return Err(IndexError::Invalid("lexical query has no searchable terms"));
        }
        let documents = self.documents();
        let mut hits = Vec::new();
        let mut examined = 0_u64;
        for id in &universe.document_ids {
            let document = documents
                .get(id)
                .ok_or(IndexError::UnknownRepresentation(*id))?;
            if valid_at.is_some_and(|instant| !document.valid_time.contains(instant)) {
                continue;
            }
            examined = examined.saturating_add(1);
            let mut document_terms = tokens(&document.text);
            for alias in &document.aliases {
                document_terms.extend(tokens(alias));
            }
            let score = exact_score(&query_terms, &document_terms);
            if score > 0.0 {
                hits.push(LexicalHit {
                    representation_id: *id,
                    target: document.target.clone(),
                    score,
                });
            }
        }
        hits.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.representation_id.cmp(&right.representation_id))
        });
        hits.truncate(limit);
        Ok(LexicalSearchResult {
            trace: LexicalTrace {
                snapshot: universe.snapshot,
                generation: universe.generation,
                authorized_examined: examined,
                returned: u64::try_from(hits.len()).unwrap_or(u64::MAX),
                watermark: self.watermark,
            },
            hits,
        })
    }

    /// Runs Tantivy over an ephemeral index containing only authorized docs.
    /// Forbidden text therefore cannot alter token statistics or ranking.
    #[cfg(feature = "lexical-tantivy")]
    pub fn search_tantivy(
        &self,
        universe: &AuthorizedLexicalUniverse,
        query: &str,
        valid_at: Option<TimestampMicros>,
        limit: usize,
    ) -> Result<LexicalSearchResult> {
        self.validate_universe(universe)?;
        if limit == 0 {
            return Err(IndexError::InvalidBudget);
        }
        if tokens(query).is_empty() {
            return Err(IndexError::Invalid("lexical query has no searchable terms"));
        }
        let mut builder = Schema::builder();
        let ordinal_field = builder.add_u64_field("ordinal", STORED | INDEXED);
        let text_field = builder.add_text_field("text", TEXT);
        let index = Index::create_in_ram(builder.build());
        let mut writer = index
            .writer(15_000_000)
            .map_err(|_| IndexError::Invalid("Tantivy writer creation failed"))?;
        let documents = self.documents();
        let mut ids = Vec::new();
        for id in &universe.document_ids {
            let document = documents
                .get(id)
                .ok_or(IndexError::UnknownRepresentation(*id))?;
            if valid_at.is_some_and(|instant| !document.valid_time.contains(instant)) {
                continue;
            }
            let ordinal = u64::try_from(ids.len())
                .map_err(|_| IndexError::Invalid("authorized lexical universe too large"))?;
            ids.push(*id);
            let searchable = std::iter::once(document.text.as_str())
                .chain(document.aliases.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join("\n");
            writer
                .add_document(doc!(ordinal_field => ordinal, text_field => searchable))
                .map_err(|_| IndexError::Invalid("Tantivy document indexing failed"))?;
        }
        writer
            .commit()
            .map_err(|_| IndexError::Invalid("Tantivy commit failed"))?;
        let reader = index
            .reader()
            .map_err(|_| IndexError::Invalid("Tantivy reader creation failed"))?;
        let searcher = reader.searcher();
        let parsed = QueryParser::for_index(&index, vec![text_field])
            .parse_query(query)
            .map_err(|_| IndexError::Invalid("Tantivy query parse failed"))?;
        let top = searcher
            .search(&parsed, &TopDocs::with_limit(limit).order_by_score())
            .map_err(|_| IndexError::Invalid("Tantivy search failed"))?;
        let mut hits = Vec::with_capacity(top.len());
        for (score, address) in top {
            let stored: TantivyDocument = searcher
                .doc(address)
                .map_err(|_| IndexError::Invalid("Tantivy stored document read failed"))?;
            let ordinal = stored
                .get_first(ordinal_field)
                .and_then(|value| value.as_u64())
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(IndexError::Invalid("Tantivy ordinal is missing"))?;
            let id = *ids
                .get(ordinal)
                .ok_or(IndexError::Invalid("Tantivy ordinal is out of range"))?;
            let document = documents
                .get(&id)
                .ok_or(IndexError::UnknownRepresentation(id))?;
            hits.push(LexicalHit {
                representation_id: id,
                target: document.target.clone(),
                score,
            });
        }
        hits.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.representation_id.cmp(&right.representation_id))
        });
        Ok(LexicalSearchResult {
            trace: LexicalTrace {
                snapshot: universe.snapshot,
                generation: universe.generation,
                authorized_examined: u64::try_from(ids.len()).unwrap_or(u64::MAX),
                returned: u64::try_from(hits.len()).unwrap_or(u64::MAX),
                watermark: self.watermark,
            },
            hits,
        })
    }

    /// Reports that the optional Tantivy backend is absent without inspecting
    /// the universe, query, or indexed content.
    #[cfg(not(feature = "lexical-tantivy"))]
    pub fn search_tantivy(
        &self,
        _universe: &AuthorizedLexicalUniverse,
        _query: &str,
        _valid_at: Option<TimestampMicros>,
        _limit: usize,
    ) -> Result<LexicalSearchResult> {
        Err(IndexError::CapabilityUnavailable {
            capability: "lexical-tantivy",
        })
    }

    fn documents(&self) -> BTreeMap<RepresentationId, &LexicalDocument> {
        let mut documents = self
            .base
            .iter()
            .map(|(id, document)| (*id, document))
            .collect::<BTreeMap<_, _>>();
        for (id, document) in &self.delta {
            documents.insert(*id, document);
        }
        documents
    }

    fn validate_universe(&self, universe: &AuthorizedLexicalUniverse) -> Result<()> {
        if universe.generation != self.generation || universe.snapshot < self.watermark {
            return Err(IndexError::StaleAuthorization);
        }
        Ok(())
    }
}

fn tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn exact_score(query: &[String], document: &[String]) -> f32 {
    let frequencies = document.iter().fold(BTreeMap::new(), |mut map, token| {
        *map.entry(token).or_insert(0_u32) += 1;
        map
    });
    query
        .iter()
        .map(|term| frequencies.get(term).copied().unwrap_or(0) as f32)
        .sum::<f32>()
        / (document.len().max(1) as f32).sqrt()
}
