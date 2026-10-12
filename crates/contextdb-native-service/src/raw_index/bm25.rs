//! Fixed, source-bound BM25 statistics published with the native raw outbox.

use super::*;
use contextdb_core::EventPayload;
use contextdb_index::{IndexError, analyze_raw_bm25_original};

mod df;

pub(crate) const FEATURE: &str = "continuous-raw-bm25-v1";
pub(crate) const REVISION: &str = "native-raw-bm25-unicode-v1";
pub(crate) const K1_MILLIS: u32 = 1200;
pub(crate) const B_MILLIS: u32 = 750;
pub(crate) const OPERATION: &str = "raw_projection_bm25";

/// Frozen method declaration. An absent declaration retains the legacy profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bm25Profile {
    pub(crate) revision: u16,
    pub(crate) analyzer: String,
    pub(crate) method: String,
    pub(crate) k1_millis: u32,
    pub(crate) b_millis: u32,
}

impl Bm25Profile {
    pub(crate) fn fixed() -> Self {
        Self {
            revision: 1,
            analyzer: RAW_ANALYZER.into(),
            method: REVISION.into(),
            k1_millis: K1_MILLIS,
            b_millis: B_MILLIS,
        }
    }

    pub(crate) fn validate(&self) -> ServiceResult<()> {
        if self != &Self::fixed() {
            return Err(integrity(
                "BM25 generation method differs from its fixed profile",
            ));
        }
        Ok(())
    }
}

/// Recorded exclusion/coverage state; omitted values never invent text or TF.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Bm25Omission {
    ModelRequestEcho,
    OperationalControl,
    Unavailable,
    NonText,
    TooLarge,
    LexicalLimit,
    RowLimit,
    EmptyText,
}

/// One derived copy, bound to its complete accepted source and frozen domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bm25Document {
    pub(crate) source: RawSource,
    pub(crate) event_digest: ContentDigest,
    pub(crate) commit: u64,
    pub(crate) policy_domain: String,
    pub(crate) token_count: u64,
    pub(crate) term_frequencies: BTreeMap<String, u64>,
    pub(crate) omission: Option<Bm25Omission>,
}

impl Bm25Document {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        if self.commit == 0 || blake3::Hash::from_hex(&self.policy_domain).is_err() {
            return Err(integrity(
                "BM25 source identity or policy domain is invalid",
            ));
        }
        if self.omission.is_some() {
            if self.token_count != 0 || !self.term_frequencies.is_empty() {
                return Err(integrity(
                    "excluded BM25 document contains frequency statistics",
                ));
            }
            return Ok(());
        }
        if self.token_count == 0
            || self.source.payload_digest.is_none()
            || !self
                .source
                .byte_length
                .is_some_and(|length| length <= 1024 * 1024)
            || self.term_frequencies.is_empty()
            || self.term_frequencies.len() > MAX_INDEX_TERMS
        {
            return Err(integrity(
                "eligible BM25 document exceeds its exact text profile",
            ));
        }
        let mut total = 0_u64;
        for (term, frequency) in &self.term_frequencies {
            if term.is_empty()
                || term.len() > contextdb_index::MAX_RAW_QUERY_BYTES
                || *frequency == 0
            {
                return Err(integrity("BM25 term or frequency is invalid"));
            }
            total = total
                .checked_add(*frequency)
                .ok_or_else(|| integrity("BM25 frequency sum overflow"))?;
        }
        if total != self.token_count {
            return Err(integrity("BM25 token length differs from its frequencies"));
        }
        Ok(())
    }

    pub(crate) fn coverage_omitted(&self) -> bool {
        matches!(
            self.omission,
            Some(
                Bm25Omission::Unavailable
                    | Bm25Omission::NonText
                    | Bm25Omission::TooLarge
                    | Bm25Omission::LexicalLimit
                    | Bm25Omission::RowLimit
            )
        )
    }
}

/// Shared statistics. Every published domain has a row, including zero rows.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainStatistics {
    pub(crate) documents: u64,
    pub(crate) total_tokens: u64,
    pub(crate) omitted_documents: u64,
}

impl DomainStatistics {
    pub(crate) fn validate(&self) -> ServiceResult<()> {
        if (self.documents == 0) != (self.total_tokens == 0) || self.total_tokens < self.documents {
            return Err(integrity("BM25 corpus counters are incoherent"));
        }
        Ok(())
    }

    pub(crate) fn add(&mut self, document: &Bm25Document) -> ServiceResult<()> {
        self.validate()?;
        document.validate()?;
        if document.omission.is_none() {
            self.documents = self
                .documents
                .checked_add(1)
                .ok_or_else(|| exhausted("BM25 domain document counter overflow"))?;
            self.total_tokens = self
                .total_tokens
                .checked_add(document.token_count)
                .ok_or_else(|| exhausted("BM25 domain token counter overflow"))?;
        } else if document.coverage_omitted() {
            self.omitted_documents = self
                .omitted_documents
                .checked_add(1)
                .ok_or_else(|| exhausted("BM25 domain omission counter overflow"))?;
        }
        Ok(())
    }
}

/// Stable upper bound for eligibility rows. Permission changes can reorder
/// custody labels, so the first routing label is not a reconstruction invariant.
pub(crate) fn routing_scope_count(policies: &[AccessPolicy]) -> ServiceResult<usize> {
    policies
        .iter()
        .map(|policy| policy.scopes.len())
        .filter(|count| *count > 0)
        .max()
        .ok_or_else(|| integrity("raw domain has no scoped policy"))
}

/// Sparse shared DF. Absence represents zero only when no eligible TF exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TermStatistics {
    pub(crate) term: String,
    pub(crate) document_frequency: u64,
}

pub(crate) fn document_key(workspace: &str, generation: u64, event: ObservationId) -> Vec<u8> {
    format!(
        "{}bm25/document/{event}",
        generation_prefix(workspace, generation)
    )
    .into_bytes()
}

pub(crate) fn corpus_key(workspace: &str, generation: u64, domain: &str) -> Vec<u8> {
    format!(
        "{}bm25/corpus/{domain}",
        generation_prefix(workspace, generation)
    )
    .into_bytes()
}

pub(crate) fn df_key(workspace: &str, generation: u64, domain: &str, term: &str) -> Vec<u8> {
    format!(
        "{}bm25/df/{domain}/{}",
        generation_prefix(workspace, generation),
        digest_bytes(term.as_bytes())
    )
    .into_bytes()
}

/// Derive all rows without trusting cached aggregates. Used by owner verification.
pub(crate) fn reconstruct_rows(
    workspace: &str,
    generation: u64,
    documents: &[Bm25Document],
) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut rows = BTreeMap::new();
    let mut domains = BTreeMap::<String, DomainStatistics>::new();
    let mut terms = BTreeMap::<(String, String), u64>::new();
    for document in documents {
        document.validate()?;
        if rows
            .insert(
                document_key(workspace, generation, document.source.event_id),
                encode(document)?,
            )
            .is_some()
        {
            return Err(integrity("BM25 reconstruction repeats a captured source"));
        }
        domains
            .entry(document.policy_domain.clone())
            .or_default()
            .add(document)?;
        for term in document.term_frequencies.keys() {
            let frequency = terms
                .entry((document.policy_domain.clone(), term.clone()))
                .or_default();
            *frequency = frequency
                .checked_add(1)
                .ok_or_else(|| exhausted("BM25 document frequency overflow"))?;
        }
    }
    for (domain, statistics) in domains {
        rows.insert(
            corpus_key(workspace, generation, &domain),
            encode(&statistics)?,
        );
    }
    for ((domain, term), document_frequency) in terms {
        rows.insert(
            df_key(workspace, generation, &domain, &term),
            encode(&TermStatistics {
                term,
                document_frequency,
            })?,
        );
    }
    Ok(rows)
}

impl NativeService {
    /// Budgeted immutable reconstruction; caller supplies the frozen domain and
    /// separately establishes maintenance/disclosure authority before this call.
    #[allow(
        clippy::too_many_arguments,
        reason = "reconstruction binds the complete source and frozen routing policy"
    )]
    pub(crate) fn build_bm25_document<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
        commit: u64,
        event_digest: ContentDigest,
        policy_domain: &str,
        routing_scope_count: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Bm25Document> {
        Ok(self
            .build_raw_bm25_documents(
                snapshot,
                event,
                commit,
                event_digest,
                policy_domain,
                routing_scope_count,
                budget,
            )?
            .1)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one analyzer produces both source-bound projections"
    )]
    pub(crate) fn build_raw_bm25_documents<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
        commit: u64,
        event_digest: ContentDigest,
        policy_domain: &str,
        routing_scope_count: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(IndexedOriginal, Bm25Document)> {
        budget.charge(1, 512).map_err(budget_error)?;
        let source = RawSource::from(event);
        let mut first_terms = BTreeMap::new();
        let mut lexical_complete = source.byte_length.is_none();
        let mut token_count = 0;
        let mut term_frequencies = BTreeMap::new();
        let omission = if event.kind == EventKind::ModelRequested {
            Some(Bm25Omission::ModelRequestEcho)
        } else if let (Some(length), Some(digest)) = (source.byte_length, source.payload_digest) {
            if length > 1024 * 1024 {
                Some(Bm25Omission::TooLarge)
            } else {
                let bytes = self
                    .original_range_for_custody_with_budget(snapshot, event, 0, length, budget)?;
                let mut limit_failure = None;
                let analysis = analyze_raw_bm25_original(
                    event.event_id,
                    digest,
                    &bytes,
                    |work, allocation| {
                        budget.charge(work, allocation).map_err(|reason| {
                            limit_failure = Some(budget_error(reason));
                            IndexError::InvalidBudget
                        })
                    },
                );
                if let Some(error) = limit_failure {
                    return Err(error);
                }
                let analysis =
                    analysis.map_err(|_| integrity("BM25 analyzer differs from the original"))?;
                if let Some(analysis) = analysis {
                    lexical_complete = analysis.lexical.first_terms.len() <= MAX_INDEX_TERMS;
                    let bounded = lexical_complete
                        && analysis
                            .lexical
                            .first_terms
                            .keys()
                            .all(|term| term.len() <= contextdb_index::MAX_RAW_QUERY_BYTES);
                    first_terms = analysis.lexical.first_terms;
                    first_terms
                        .retain(|term, _| term.len() <= contextdb_index::MAX_RAW_QUERY_BYTES);
                    while first_terms.len() > MAX_INDEX_TERMS {
                        first_terms.pop_last();
                    }
                    let text_media = match &event.payload {
                        EventPayload::InlineBytes { media_type, .. }
                        | EventPayload::Staged { media_type, .. } => {
                            media_type.starts_with("text/")
                                || matches!(
                                    media_type.as_str(),
                                    "application/json" | "application/xml"
                                )
                        }
                        _ => true,
                    };
                    if !text_media {
                        Some(Bm25Omission::NonText)
                    } else if !bounded {
                        Some(Bm25Omission::LexicalLimit)
                    } else if analysis.token_count == 0 {
                        Some(Bm25Omission::EmptyText)
                    } else {
                        token_count = analysis.token_count;
                        term_frequencies = analysis.term_frequencies;
                        if first_terms.keys().ne(term_frequencies.keys()) {
                            return Err(integrity("BM25 frequencies and raw spans disagree"));
                        }
                        None
                    }
                } else {
                    lexical_complete = true;
                    Some(Bm25Omission::NonText)
                }
            }
        } else {
            Some(Bm25Omission::Unavailable)
        };
        let omission = if matches!(
            event.kind,
            EventKind::RunStarted
                | EventKind::RunCheckpointed
                | EventKind::RunResumed
                | EventKind::RunCancelled
        ) {
            token_count = 0;
            term_frequencies.clear();
            Some(Bm25Omission::OperationalControl)
        } else {
            omission
        };
        budget
            .charge(
                1,
                policy_domain.len() as u64 + (event.parent_event_ids.len() as u64 + 1) * 1024,
            )
            .map_err(budget_error)?;
        let parents: BTreeSet<_> = event
            .parent_event_ids
            .iter()
            .chain(event.supersedes_event_id.iter())
            .copied()
            .collect();
        // This intrinsic bound is independent of batching, generation identity
        // and whether a DF is already present. Reconstruction makes the same
        // decision from the frozen source and policy.
        let source_rows = 7_usize
            .checked_add(first_terms.len())
            .and_then(|count| count.checked_add(term_frequencies.len()))
            .and_then(|count| count.checked_add(usize::from(source.session_id.is_some())))
            .and_then(|count| count.checked_add(parents.len()))
            .and_then(|count| count.checked_add(usize::from(!lexical_complete)))
            .and_then(|count| count.checked_add(routing_scope_count))
            .ok_or_else(|| exhausted("BM25 source-row counter overflow"))?;
        let omission = if omission.is_none() && source_rows > MAX_PROJECTION_ROWS {
            token_count = 0;
            term_frequencies.clear();
            Some(Bm25Omission::RowLimit)
        } else {
            omission
        };
        let statistics = Bm25Document {
            source: source.clone(),
            event_digest,
            commit,
            policy_domain: policy_domain.into(),
            token_count,
            term_frequencies,
            omission,
        };
        statistics.validate()?;
        let document = IndexedOriginal {
            source,
            event_digest,
            commit,
            policy_domain: policy_domain.into(),
            lexical_complete,
            first_terms,
            parents,
        };
        Ok((document, statistics))
    }

    /// Assemble one original's aggregate updates without mutating the staged map.
    pub(super) fn bm25_source_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: u64,
        document: &Bm25Document,
        staged: &BTreeMap<Vec<u8>, Vec<u8>>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        document.validate()?;
        let mut rows = BTreeMap::new();
        let key = corpus_key(workspace, generation, &document.policy_domain);
        let previous: Option<DomainStatistics> =
            staged_value(self, snapshot, staged, &key, budget)?;
        if previous.is_none()
            && staged_value::<PolicyDomain, _>(
                self,
                snapshot,
                staged,
                &domain_key(workspace, generation, &document.policy_domain),
                budget,
            )?
            .is_some()
        {
            return Err(integrity("published BM25 domain corpus is absent"));
        }
        let mut corpus = previous.unwrap_or_default();
        corpus.add(document)?;
        rows.insert(key, encode(&corpus)?);
        rows.insert(
            document_key(workspace, generation, document.source.event_id),
            encode(document)?,
        );
        for term in document.term_frequencies.keys() {
            budget
                .charge(1, term.len() as u64 + 256)
                .map_err(budget_error)?;
            let key = df_key(workspace, generation, &document.policy_domain, term);
            let previous: Option<TermStatistics> =
                staged_value(self, snapshot, staged, &key, budget)?;
            if previous.is_none() {
                self.require_absent_bm25_df(
                    snapshot, workspace, generation, document, term, staged, budget,
                )?;
            }
            if previous
                .as_ref()
                .is_some_and(|statistics| statistics.document_frequency == 0)
            {
                return Err(integrity("published BM25 document frequency is zero"));
            }
            let mut statistics = previous.unwrap_or(TermStatistics {
                term: term.clone(),
                document_frequency: 0,
            });
            if statistics.term != *term || statistics.document_frequency >= corpus.documents {
                return Err(integrity("BM25 previous document frequency is invalid"));
            }
            statistics.document_frequency = statistics
                .document_frequency
                .checked_add(1)
                .ok_or_else(|| exhausted("BM25 document frequency overflow"))?;
            rows.insert(key, encode(&statistics)?);
        }
        Ok(rows)
    }
}

impl NativeService {
    pub(crate) fn require_raw_bm25_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.charge(1, 0).map_err(budget_error)?;
        let bytes = snapshot
            .get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("BM25 native manifest is absent"))?;
        if bytes.len() > super::super::MAX_JSON_BYTES {
            return Err(integrity("BM25 native manifest exceeds its metadata bound"));
        }
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let manifest: super::super::Manifest = decode(&bytes, "BM25 native manifest")?;
        super::super::validate_manifest(&manifest, &self.database_id)?;
        if !manifest.features.contains(FEATURE) {
            return Err(integrity("BM25 generation format feature is absent"));
        }
        Ok(())
    }
}

pub(super) fn staged_value<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
    service: &NativeService,
    snapshot: &S,
    staged: &BTreeMap<Vec<u8>, Vec<u8>>,
    key: &[u8],
    budget: &mut QueryBudget,
) -> ServiceResult<Option<T>> {
    budget.charge(1, key.len() as u64).map_err(budget_error)?;
    if let Some(bytes) = staged.get(key) {
        budget
            .charge(1, (bytes.len() as u64).saturating_mul(2))
            .map_err(budget_error)?;
        return decode(bytes, "staged BM25 statistics").map(Some);
    }
    let bytes = snapshot
        .get(&service.keyspaces.continuous, key)
        .map_err(storage_error)?;
    bytes
        .map(|bytes| {
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(integrity("BM25 metadata exceeds its byte bound"));
            }
            budget
                .charge(1, (bytes.len() as u64).saturating_mul(2))
                .map_err(budget_error)?;
            decode(&bytes, "BM25 statistics")
        })
        .transpose()
}

#[cfg(test)]
mod tests;
