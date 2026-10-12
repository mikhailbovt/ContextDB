//! Persistent authorized BM25 OR postings, with one bounded fresh-tail join.

use super::*;
use crate::raw_index::bm25::{self as statistics, Bm25Document, DomainStatistics, TermStatistics};
use contextdb_core::{EventCoverage, RawFilter};
use contextdb_service::{
    RawBm25Completion, RawBm25Hit, RawBm25Page, RawBm25ProfileStatus, RawBm25Query,
};

mod budget;
#[cfg(test)]
mod tests;

const MAX_POSTINGS: usize = 4096;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

struct Ranked {
    document: Bm25Document,
    raw: IndexedOriginal,
    score: f64,
}

impl NativeIndexedRecallProvider<'_> {
    /// Separate budgeted view; legacy indexed operations keep their old profile.
    pub fn open_bm25_view(
        &self,
        known_at: Option<u64>,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<NativeIndexedView> {
        for capability in [
            Capability::Recall,
            Capability::ReadEvidence,
            Capability::RawEvidence,
        ] {
            require_capability(self.context, capability)?;
        }
        allowance.charge(1, 0).map_err(budget_error)?;
        self.service
            .index_views
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 64).then_some(count + 1)
            })
            .map_err(|_| super::super::exhausted("native indexed read-view limit reached"))?;
        let permit = ViewPermit(Arc::clone(&self.service.index_views));
        let snapshot = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(self.context.request.workspace_id.as_bytes());
        let (global, state, auth, generation, current) =
            budget::metadata(&snapshot, allowance, |reader| {
                self.service.require_custody_ready(reader, &workspace)?;
                let latest = self
                    .service
                    .workspace_state(reader, &self.context.request.workspace_id)?;
                let (global, state) = self.service.select_snapshot(
                    reader,
                    &self.context.request.workspace_id,
                    known_at,
                )?;
                let auth = self.service.raw_authorization_epoch(reader, &workspace)?;
                let index: IndexState = self
                    .service
                    .raw_value(reader, &state_key(&workspace))?
                    .unwrap_or_default();
                super::super::raw_index::retained_generations(&index)?;
                let generation = if let Some(number) = index.active {
                    self.service
                        .raw_value::<Generation, _>(reader, &generation_key(&workspace, number))?
                        .ok_or_else(|| integrity("active raw generation manifest is absent"))?
                } else {
                    Generation {
                        number: 0,
                        custody_version: super::super::custody::CUSTODY_VERSION,
                        analyzer: RAW_ANALYZER.into(),
                        through: 0,
                        authorization_epoch: auth,
                        projected_sources: 0,
                        removal_through: None,
                        bm25: None,
                        dense: None,
                    }
                };
                let current = state.watermarks.journal == latest.watermarks.journal;
                Ok((global, state, auth, generation, current))
            })?;
        if generation.authorization_epoch != auth
            || generation.analyzer != RAW_ANALYZER
            || generation.custody_version != super::super::custody::CUSTODY_VERSION
        {
            return Err(stale_index());
        }
        let mut eligible = BTreeSet::new();
        for scope in &self.context.request.scopes {
            let prefix = format!(
                "{}eligibility/{}/",
                generation_prefix(&workspace, generation.number),
                digest_bytes(scope.as_bytes())
            )
            .into_bytes();
            let page = budget::metadata(&snapshot, allowance, |reader| {
                reader
                    .scan_prefix_page(
                        &self.service.keyspaces.continuous,
                        ScanPageRequest {
                            prefix: &prefix,
                            start_after: None,
                            max_entries: MAX_DOMAINS,
                            max_bytes: 1024 * 1024,
                        },
                    )
                    .map_err(storage_error)
            })?;
            if page.continuation.is_some() {
                return Err(stale_index());
            }
            for entry in page.entries {
                allowance
                    .charge(1, entry.value.len() as u64)
                    .map_err(budget_error)?;
                let id: String = decode(&entry.value, "index domain eligibility")?;
                if id.len() != 64 || blake3::Hash::from_hex(&id).is_err() {
                    return Err(integrity("index domain eligibility identity is invalid"));
                }
                if entry.key != [prefix.as_slice(), id.as_bytes()].concat() {
                    return Err(integrity("index eligibility key differs"));
                }
                eligible.insert(id);
                if eligible.len() > MAX_DOMAINS {
                    return Err(stale_index());
                }
            }
        }
        let mut domains = BTreeMap::new();
        for id in eligible {
            let domain: PolicyDomain = value(
                self,
                &snapshot,
                &domain_key(&workspace, generation.number, &id),
                allowance,
            )?
            .ok_or_else(|| integrity("eligible raw domain is absent"))?;
            allowance
                .charge(domain.policies.len() as u64 + 1, 0)
                .map_err(budget_error)?;
            if domain.policies.is_empty() || canonical_digest(&domain.policies)? != id {
                return Err(integrity("raw domain label binding is invalid"));
            }
            if domain
                .policies
                .iter()
                .all(|policy| policy_allows(&self.context.request, policy))
            {
                domains.insert(id, domain);
            }
        }
        Ok(NativeIndexedView {
            _permit: permit,
            database_id: self.service.database_id.clone(),
            snapshot,
            workspace,
            known_at: state.watermarks.journal,
            global,
            generation,
            domains,
            principal: self.context.authorization_binding_digest()?,
            opened: Instant::now(),
            current_snapshot: current,
            budgeted_for_bm25: true,
        })
    }

    /// Scores a bounded union of postings. Completion concerns captured lexical
    /// data only; it is neither exhaustive archive recall nor semantic coverage.
    pub fn bm25_candidates(
        &self,
        view: &NativeIndexedView,
        query: &RawBm25Query,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<RawBm25Page> {
        if !view.budgeted_for_bm25 {
            return Err(super::super::invalid(
                "BM25 requires its separate budgeted native view",
            ));
        }
        if !(1..=100).contains(&query.limit) {
            return Err(super::super::invalid("BM25 candidate limit must be 1..100"));
        }
        if query.text.is_empty() || query.text.len() > contextdb_index::MAX_RAW_QUERY_BYTES {
            return Err(super::super::invalid(
                "BM25 text query exceeds its bounded analyzer profile",
            ));
        }
        allowance
            .charge(query.text.len() as u64 + 1, query.text.len() as u64 * 4)
            .map_err(budget_error)?;
        let terms = raw_query_terms(&RawTextQuery::AllTerms(query.text.clone()))
            .map_err(|_| super::super::invalid("BM25 text query exceeds its analyzer profile"))?;
        self.check_bm25_view(view, allowance)?;
        let mut output = RawBm25Page {
            terms: terms.clone(),
            hits: vec![],
            profile_status: RawBm25ProfileStatus::Supported,
            completion: RawBm25Completion::Complete,
            snapshot: random_view_id()?,
        };
        if query.filter != RawFilter::default() {
            output.profile_status = RawBm25ProfileStatus::UnsupportedFilter;
            return Ok(output);
        }
        if !view.current_snapshot || view.generation.through > view.known_at {
            output.profile_status = RawBm25ProfileStatus::UnsupportedHistorical;
            return Ok(output);
        }
        let Some(profile) = &view.generation.bm25 else {
            output.profile_status = RawBm25ProfileStatus::MissingProjection;
            return Ok(output);
        };
        profile.validate()?;
        budget::metadata(&view.snapshot, allowance, |reader| {
            let manifest = self.service.raw_manifest(reader)?;
            super::super::validate_manifest(&manifest, &self.service.database_id)?;
            if !manifest.features.contains(statistics::FEATURE) {
                return Err(integrity("BM25 generation format feature is absent"));
            }
            Ok(())
        })?;
        let through = view.generation.through;
        let mut population = DomainStatistics::default();
        let mut frequencies = BTreeMap::<String, u64>::new();
        for (domain, policy) in &view.domains {
            if policy.first_commit > through {
                continue;
            }
            let corpus: DomainStatistics = value(
                self,
                &view.snapshot,
                &statistics::corpus_key(&view.workspace, view.generation.number, domain),
                allowance,
            )?
            .ok_or_else(|| integrity("published BM25 domain corpus statistics are absent"))?;
            merge_population(&mut population, &corpus)?;
            for term in &terms {
                let df: Option<TermStatistics> = value(
                    self,
                    &view.snapshot,
                    &statistics::df_key(&view.workspace, view.generation.number, domain, term),
                    allowance,
                )?;
                if let Some(df) = df {
                    if df.term != *term
                        || df.document_frequency == 0
                        || df.document_frequency > corpus.documents
                    {
                        return Err(integrity(
                            "BM25 domain term statistics differ from their population",
                        ));
                    }
                    checked_add(
                        frequencies.entry(term.clone()).or_default(),
                        df.document_frequency,
                    )?;
                }
            }
        }
        // The complete admitted tail population is joined once before any score.
        let tail = self.bm25_tail(view, through, allowance)?;
        let Some(tail) = tail else {
            output.profile_status = RawBm25ProfileStatus::TailOverflow;
            return Ok(output);
        };
        let mut tail_documents = Vec::new();
        for id in tail {
            if let Some((raw, document)) = self.bm25_tail_document(view, id, allowance)? {
                population.add(&document)?;
                for term in &terms {
                    if document.term_frequencies.contains_key(term) {
                        checked_add(frequencies.entry(term.clone()).or_default(), 1)?;
                    }
                }
                if document.omission.is_none() {
                    tail_documents.push((raw, document));
                }
            }
        }
        if population.omitted_documents > 0 {
            output.profile_status = RawBm25ProfileStatus::IncompleteLexicalCoverage;
        }
        if population.documents == 0 {
            if population.total_tokens != 0 {
                return Err(integrity("empty BM25 population has token statistics"));
            }
            self.check_bm25_view(view, allowance)?;
            return Ok(output);
        }
        if population.total_tokens < population.documents {
            return Err(integrity("BM25 population token statistics are invalid"));
        }
        let mut ranked = Vec::new();
        let mut seen = BTreeSet::new();
        let mut matched = 0_usize;
        for (raw, document) in tail_documents {
            allowance.charge(1, 64).map_err(budget_error)?;
            seen.insert(document.source.event_id);
            self.rank_bm25(
                raw,
                document,
                &terms,
                &population,
                &frequencies,
                query.limit,
                &mut ranked,
                &mut matched,
                allowance,
            )?;
        }
        allowance
            .charge(terms.len() as u64 + 1, query.text.len() as u64 + 2048)
            .map_err(budget_error)?;
        let mut ordered_terms = terms.clone();
        // Intentional control/echo omissions retain legacy term routes. A zero
        // eligible DF must not make those unrelated postings consume the query.
        ordered_terms.retain(|term| frequencies.get(term).copied().unwrap_or(0) > 0);
        ordered_terms.sort_by(|a, b| {
            frequencies
                .get(a)
                .copied()
                .unwrap_or(0)
                .cmp(&frequencies.get(b).copied().unwrap_or(0))
                .then(a.cmp(b))
        });
        let mut postings = 0;
        'routes: for term in ordered_terms {
            for (domain, policy) in &view.domains {
                if policy.first_commit > through {
                    continue;
                }
                let prefix = format!(
                    "{}route/{domain}/term/{}/",
                    generation_prefix(&view.workspace, view.generation.number),
                    digest_bytes(term.as_bytes())
                )
                .into_bytes();
                let upper = commit_upper(&prefix, through);
                let mut after = None;
                loop {
                    if postings == MAX_POSTINGS {
                        output.completion = RawBm25Completion::PostingLimit;
                        break 'routes;
                    }
                    let page = budget::metadata(&view.snapshot, allowance, |reader| {
                        reader
                            .scan_prefix_page(
                                &self.service.keyspaces.continuous,
                                ScanPageRequest {
                                    prefix: &prefix,
                                    start_after: after.as_deref(),
                                    max_entries: 1,
                                    max_bytes: 16 * 1024,
                                },
                            )
                            .map_err(storage_error)
                    });
                    let page = match page {
                        Ok(page) => page,
                        Err(error) => {
                            if let Some(limit) = limited(&error) {
                                output.completion = limit;
                                break 'routes;
                            }
                            return Err(error);
                        }
                    };
                    let Some(entry) = page.entries.first() else {
                        break;
                    };
                    if upper.as_ref().is_some_and(|upper| &entry.key >= upper) {
                        break;
                    }
                    after = Some(entry.key.clone());
                    postings += 1;
                    let id: ObservationId = decode(&entry.value, "BM25 raw posting source")?;
                    if let Err(reason) = allowance.charge(1, 64) {
                        output.completion =
                            limited(&budget_error(reason)).ok_or_else(|| budget_error(reason))?;
                        break 'routes;
                    }
                    if !seen.insert(id) {
                        continue;
                    }
                    let candidate =
                        self.bm25_indexed_document(view, id, domain, through, allowance);
                    match candidate {
                        Ok(Some((raw, document))) => {
                            if let Err(reason) = allowance.charge(1, 128) {
                                output.completion = limited(&budget_error(reason))
                                    .ok_or_else(|| budget_error(reason))?;
                                break 'routes;
                            }
                            if entry.key
                                != [
                                    prefix.as_slice(),
                                    format!("{:020}/{}", document.commit, id).as_bytes(),
                                ]
                                .concat()
                                || !raw.first_terms.contains_key(&term)
                            {
                                return Err(integrity(
                                    "BM25 term posting key differs from its accepted source",
                                ));
                            }
                            if let Err(error) = self.rank_bm25(
                                raw,
                                document,
                                &terms,
                                &population,
                                &frequencies,
                                query.limit,
                                &mut ranked,
                                &mut matched,
                                allowance,
                            ) {
                                if let Some(limit) = limited(&error) {
                                    output.completion = limit;
                                    break 'routes;
                                }
                                return Err(error);
                            }
                        }
                        Ok(None) => (),
                        Err(error) => {
                            if let Some(limit) = limited(&error) {
                                output.completion = limit;
                                break 'routes;
                            }
                            return Err(error);
                        }
                    }
                    if page.continuation.is_none() {
                        break;
                    }
                }
            }
        }
        if output.completion == RawBm25Completion::Complete && matched > query.limit as usize {
            output.completion = RawBm25Completion::RankedLimit;
        }
        if let Err(error) = self.check_bm25_view(view, allowance) {
            if let Some(limit) = limited(&error) {
                output.completion = limit;
                return Ok(output);
            }
            return Err(error);
        }
        for candidate in ranked {
            if candidate.document.source.coverage != EventCoverage::CompleteObservation
                || candidate.document.source.upstream_truncated
            {
                output.profile_status = RawBm25ProfileStatus::IncompleteLexicalCoverage;
            }
            match self.bm25_hit(view, candidate, &terms, allowance) {
                Ok(hit) => output.hits.push(hit),
                Err(error) => {
                    if let Some(limit) = limited(&error) {
                        output.completion = limit;
                        break;
                    }
                    return Err(error);
                }
            }
        }
        match self.check_bm25_view(view, allowance) {
            Ok(()) => (),
            Err(error) => {
                if let Some(limit) = limited(&error) {
                    output.hits.clear();
                    output.completion = limit;
                } else {
                    return Err(error);
                }
            }
        }
        Ok(output)
    }

    fn check_bm25_view(
        &self,
        view: &NativeIndexedView,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<()> {
        allowance.check().map_err(budget_error)?;
        if view.opened.elapsed() > Duration::from_secs(30) {
            return Err(ServiceError::new(
                ErrorCode::SnapshotExpired,
                "BM25 indexed read view expired",
                true,
            ));
        }
        if view.database_id != self.service.database_id
            || view.principal != self.context.authorization_binding_digest()?
        {
            return Err(super::super::permission_denied());
        }
        allowance.charge(1, 0).map_err(budget_error)?;
        let current = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        budget::metadata(&current, allowance, |reader| {
            self.service
                .require_custody_ready(reader, &view.workspace)?;
            if self
                .service
                .raw_authorization_epoch(reader, &view.workspace)?
                != view.generation.authorization_epoch
            {
                return Err(stale_index());
            }
            Ok(())
        })
    }

    fn bm25_tail(
        &self,
        view: &NativeIndexedView,
        through: u64,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<Option<Vec<super::super::capture::CaptureWork>>> {
        let prefix = format!("outbox/{}/", view.workspace).into_bytes();
        let after = [prefix.as_slice(), &through.to_be_bytes()].concat();
        let page = budget::metadata(&view.snapshot, allowance, |reader| {
            reader
                .scan_prefix_page(
                    &self.service.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: Some(&after),
                        max_entries: MAX_TAIL + 1,
                        max_bytes: 2 * 1024 * 1024,
                    },
                )
                .map_err(storage_error)
        })?;
        let mut ids = Vec::new();
        for entry in page.entries {
            let work: super::super::capture::CaptureWork = decode(&entry.value, "BM25 tail work")?;
            if work.workspace_commit > view.known_at {
                break;
            }
            if entry.key != super::super::capture::work_key(&view.workspace, work.workspace_commit)
            {
                return Err(integrity("BM25 tail outbox key differs"));
            }
            if ids.len() == MAX_TAIL {
                return Ok(None);
            }
            allowance.charge(1, 128).map_err(budget_error)?;
            ids.push(work);
        }
        if page.continuation.is_some() {
            return Ok(None);
        }
        Ok(Some(ids))
    }

    fn bm25_tail_document(
        &self,
        view: &NativeIndexedView,
        work: super::super::capture::CaptureWork,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<Option<(IndexedOriginal, Bm25Document)>> {
        let id = work.event_id;
        if !self.authorize_bm25_source(view, id, allowance)? {
            return Ok(None);
        }
        let original =
            self.service
                .load_captured_original_with_budget(&view.snapshot, id, allowance)?;
        if original.receipt.workspace_commit > view.known_at
            || original.receipt.workspace_commit != work.workspace_commit
            || original.receipt.event_digest != work.event_digest
        {
            return Err(integrity("BM25 tail work differs from its accepted source"));
        }
        let labels =
            self.service
                .stored_custody_policies_with_budget(&view.snapshot, id, allowance)?;
        allowance
            .charge(labels.len() as u64 + 1, 512)
            .map_err(budget_error)?;
        let domain = canonical_digest(&labels)?;
        let scope_count = statistics::routing_scope_count(&labels)?;
        let pair = self.service.build_raw_bm25_documents(
            &view.snapshot,
            &original.event,
            original.receipt.workspace_commit,
            original.receipt.event_digest,
            &domain,
            scope_count,
            allowance,
        )?;
        Ok(Some(pair))
    }

    fn authorize_bm25_source(
        &self,
        view: &NativeIndexedView,
        id: ObservationId,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        let policy = match self.service.authorized_capture_policy_with_budget(
            &view.snapshot,
            self.context,
            id,
            allowance,
        ) {
            Ok(policy) => policy,
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::PermissionDenied | ErrorCode::NotFound
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if policy.accepted_global_commit > view.global {
            return Ok(false);
        }
        match self.service.authorize_derived_custody_with_budget(
            &view.snapshot,
            self.context,
            id,
            allowance,
        ) {
            Ok(_) => Ok(true),
            Err(error) if error.code == ErrorCode::PermissionDenied => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn bm25_indexed_document(
        &self,
        view: &NativeIndexedView,
        id: ObservationId,
        domain: &str,
        through: u64,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<Option<(IndexedOriginal, Bm25Document)>> {
        if !self.authorize_bm25_source(view, id, allowance)? {
            return Ok(None);
        }
        let document: Bm25Document = value(
            self,
            &view.snapshot,
            &statistics::document_key(&view.workspace, view.generation.number, id),
            allowance,
        )?
        .ok_or_else(|| integrity("BM25 posting document statistics are absent"))?;
        allowance
            .charge(document.term_frequencies.len() as u64 * 3 + 1, 0)
            .map_err(budget_error)?;
        document.validate()?;
        let raw: IndexedOriginal = value(
            self,
            &view.snapshot,
            &doc_key(&view.workspace, view.generation.number, id),
            allowance,
        )?
        .ok_or_else(|| integrity("BM25 raw posting document is absent"))?;
        let original =
            self.service
                .load_captured_original_with_budget(&view.snapshot, id, allowance)?;
        let labels =
            self.service
                .stored_custody_policies_with_budget(&view.snapshot, id, allowance)?;
        allowance
            .charge(labels.len() as u64 + 1, 512)
            .map_err(budget_error)?;
        if canonical_digest(&labels)? != domain {
            return Err(integrity(
                "BM25 posting differs from its current custody domain",
            ));
        }
        if document.source != RawSource::from(&original.event)
            || raw.source != document.source
            || raw.event_digest != document.event_digest
            || original.receipt.event_digest != document.event_digest
            || document.commit != raw.commit
            || document.commit > through
            || document.policy_domain != domain
            || raw.policy_domain != domain
            || original.receipt.workspace_commit != document.commit
        {
            return Err(integrity(
                "BM25 statistics differ from their accepted source/version/domain",
            ));
        }
        if !raw.lexical_complete
            || !document.source.independent_source
            || document.omission.is_some()
        {
            return Ok(None);
        }
        if raw.first_terms.keys().ne(document.term_frequencies.keys()) {
            return Err(integrity("BM25 frequencies and first-term spans differ"));
        }
        Ok(Some((raw, document)))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "fixed population and query jointly determine the bounded rank"
    )]
    fn rank_bm25(
        &self,
        raw: IndexedOriginal,
        document: Bm25Document,
        terms: &[String],
        population: &DomainStatistics,
        frequencies: &BTreeMap<String, u64>,
        limit: u32,
        ranked: &mut Vec<Ranked>,
        matched: &mut usize,
        allowance: &mut QueryBudget,
    ) -> ServiceResult<()> {
        allowance
            .charge(terms.len() as u64 + 1, 0)
            .map_err(budget_error)?;
        let score = score(&document, terms, population, frequencies)?;
        if score <= 0.0 {
            return Ok(());
        }
        *matched += 1;
        allowance
            .charge(1, size_of::<Ranked>() as u64)
            .map_err(budget_error)?;
        ranked.push(Ranked {
            document,
            raw,
            score,
        });
        ranked.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then(a.document.source.event_id.cmp(&b.document.source.event_id))
        });
        ranked.truncate(limit as usize);
        Ok(())
    }

    fn bm25_hit(
        &self,
        view: &NativeIndexedView,
        candidate: Ranked,
        terms: &[String],
        allowance: &mut QueryBudget,
    ) -> ServiceResult<RawBm25Hit> {
        let id = candidate.document.source.event_id;
        if !self.authorize_bm25_source(view, id, allowance)? {
            return Err(super::super::permission_denied());
        }
        let original =
            self.service
                .load_captured_original_with_budget(&view.snapshot, id, allowance)?;
        let digest = candidate
            .document
            .source
            .payload_digest
            .ok_or_else(|| integrity("BM25 source payload digest is absent"))?;
        let mut matches = Vec::new();
        for term in terms {
            let Some(range) = candidate.raw.first_terms.get(term) else {
                continue;
            };
            if range.end <= range.start
                || range.end - range.start > contextdb_index::MAX_RAW_QUERY_BYTES as u64
            {
                return Err(integrity("BM25 first-term range is invalid"));
            }
            let bytes = self.service.original_range_with_budget(
                &view.snapshot,
                self.context,
                &original.event,
                range.start,
                range.end,
                allowance,
            )?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| integrity("BM25 term range is not UTF-8"))?;
            allowance
                .charge(
                    bytes.len() as u64 + 1,
                    (bytes.len() as u64).saturating_mul(3) + 128,
                )
                .map_err(budget_error)?;
            if text.to_lowercase() != *term {
                return Err(integrity(
                    "BM25 first-term bytes differ from the normalized query term",
                ));
            }
            matches.push(contextdb_core::OriginalSourceSpan {
                event_id: id,
                payload_digest: digest,
                start: range.start,
                end: range.end,
                span_digest: contextdb_core::ContentDigest::from_bytes(
                    *blake3::hash(&bytes).as_bytes(),
                ),
            });
        }
        matches.sort_by_key(|span| (span.start, span.end));
        matches.dedup();
        if matches.is_empty() {
            return Err(integrity(
                "positive BM25 rank has no authenticated term span",
            ));
        }
        Ok(RawBm25Hit {
            source: candidate.document.source,
            matches,
            score: candidate.score,
        })
    }
}

fn value<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
    provider: &NativeIndexedRecallProvider<'_>,
    snapshot: &S,
    key: &[u8],
    allowance: &mut QueryBudget,
) -> ServiceResult<Option<T>> {
    budget::metadata(snapshot, allowance, |reader| {
        let bytes = reader
            .get(&provider.service.keyspaces.continuous, key)
            .map_err(storage_error)?;
        bytes
            .map(|bytes| {
                if bytes.len() > MAX_RECORD_BYTES {
                    return Err(integrity("BM25 metadata exceeds its bounded row profile"));
                }
                decode(&bytes, "BM25 native record")
            })
            .transpose()
    })
}

fn merge_population(target: &mut DomainStatistics, source: &DomainStatistics) -> ServiceResult<()> {
    if (source.documents == 0) != (source.total_tokens == 0)
        || source.total_tokens < source.documents
    {
        return Err(integrity("BM25 domain population is invalid"));
    }
    checked_add(&mut target.documents, source.documents)?;
    checked_add(&mut target.total_tokens, source.total_tokens)?;
    checked_add(&mut target.omitted_documents, source.omitted_documents)
}
fn checked_add(target: &mut u64, value: u64) -> ServiceResult<()> {
    *target = target
        .checked_add(value)
        .ok_or_else(|| integrity("BM25 population statistics overflow"))?;
    Ok(())
}
fn limited(error: &ServiceError) -> Option<RawBm25Completion> {
    if error.code != ErrorCode::BudgetExhausted {
        return None;
    }
    match error.message.as_str() {
        "indexed work budget exhausted" => Some(RawBm25Completion::WorkLimit),
        "indexed byte budget exhausted" => Some(RawBm25Completion::ByteLimit),
        _ => None,
    }
}
fn score(
    document: &Bm25Document,
    terms: &[String],
    population: &DomainStatistics,
    frequencies: &BTreeMap<String, u64>,
) -> ServiceResult<f64> {
    let n = population.documents as f64;
    let average = population.total_tokens as f64 / n;
    let k1 = f64::from(statistics::K1_MILLIS) / 1000.0;
    let b = f64::from(statistics::B_MILLIS) / 1000.0;
    let mut score = 0.0;
    for term in terms {
        let Some(tf) = document.term_frequencies.get(term) else {
            continue;
        };
        let df = frequencies.get(term).copied().unwrap_or(0);
        if df == 0 || df > population.documents {
            return Err(integrity(
                "positive BM25 term has missing or future population frequency",
            ));
        }
        let idf = (1.0 + (n - df as f64 + 0.5) / (df as f64 + 0.5)).ln();
        let tf = *tf as f64;
        score += idf * tf * (k1 + 1.0)
            / (tf + k1 * (1.0 - b + b * document.token_count as f64 / average));
    }
    if !score.is_finite() || score < 0.0 {
        return Err(integrity("BM25 score is non-finite or negative"));
    }
    Ok(score)
}
