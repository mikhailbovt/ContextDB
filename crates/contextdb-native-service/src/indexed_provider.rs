//! Authorized persistent posting routes with bounded raw-tail reconciliation.

#[cfg(test)]
mod tests;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use contextdb_core::{ObservationId, RawSource, RawTextQuery, Validate};
use contextdb_index::{RAW_ANALYZER, match_raw_original, raw_query_terms};
use contextdb_recall::{
    IndexedCompletion, IndexedHit, IndexedPage, IndexedQuery, IndexedRecallProvider,
    IndexedSelection, QueryBudget, QueryCancellation, QueryLimit,
};
use contextdb_service::{
    AuthenticatedRequestContext, Capability, CapturePort, ErrorCode, RawPageStatus, RawRecallHit,
    RawRecallPage, RawRecallRequest, ServiceError, ServiceResult,
};
use contextdb_storage::{ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine};
use contextdb_storage_fjall::FjallSnapshot;
use serde::{Deserialize, Serialize};

use super::raw_index::{
    Generation, IndexState, IndexedOriginal, MAX_DOMAINS, MAX_TAIL, PolicyDomain, budget_error,
    doc_key, domain_key, generation_key, generation_prefix, stale_index, state_key,
};
use super::{
    NativeService, canonical_digest, decode, digest_bytes, encode, encode_hex, integrity,
    policy_allows, require_capability, storage_error,
};

const CURSOR_DOMAIN: &[u8] = b"contextdb/indexed-original-cursor/v1";

/// Short-lived authorized native index reader. It does not materialize a corpus.
#[derive(Debug)]
pub struct NativeIndexedView {
    _permit: ViewPermit,
    database_id: String,
    snapshot: FjallSnapshot,
    workspace: String,
    known_at: u64,
    global: u64,
    generation: Generation,
    domains: BTreeMap<String, PolicyDomain>,
    principal: String,
    opened: Instant,
}

#[derive(Debug)]
struct ViewPermit(Arc<AtomicUsize>);

impl Drop for ViewPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Native implementation of the storage-neutral indexed recall boundary.
#[derive(Debug)]
pub struct NativeIndexedRecallProvider<'a> {
    service: &'a NativeService,
    context: &'a AuthenticatedRequestContext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexCursor {
    snapshot_id: String,
    issued_at: u64,
    binding: String,
    known_at: u64,
    generation: u64,
    through: u64,
    authorization_epoch: u64,
    stage: u8,
    route: usize,
    after: Option<Vec<u8>>,
    direct: usize,
    tail: usize,
}

#[derive(Debug)]
struct Route {
    prefix: Vec<u8>,
    lower: Option<Vec<u8>>,
    upper: Option<Vec<u8>>,
    term: bool,
}

#[derive(Clone, Copy, Debug)]
struct CandidateRef {
    id: ObservationId,
    indexed: bool,
    term_route: bool,
}

impl NativeService {
    /// Bind indexed operations to a host-authenticated current principal.
    pub const fn indexed_recall_provider<'a>(
        &'a self,
        context: &'a AuthenticatedRequestContext,
    ) -> NativeIndexedRecallProvider<'a> {
        NativeIndexedRecallProvider {
            service: self,
            context,
        }
    }

    pub(super) fn recall_originals_indexed(
        &self,
        request: RawRecallRequest,
    ) -> ServiceResult<RawRecallPage> {
        if !request.filter.event_ids.is_empty() {
            return self.recall_originals_oracle(request);
        }
        super::raw::validate_request(&request)?;
        if let Some(receipt) = &request.after_receipt {
            self.resolve_capture_receipt(&request.context, receipt)?;
        }
        let known_at = if let Some(token) = &request.continuation {
            let cursor: IndexCursor = self.open_private_cursor(CURSOR_DOMAIN, token)?;
            Some(cursor.known_at)
        } else {
            request.known_at
        };
        if request
            .known_at
            .is_some_and(|value| Some(value) != known_at)
            || request.after_receipt.as_ref().is_some_and(|receipt| {
                known_at.is_some_and(|value| value < receipt.workspace_commit)
            })
        {
            return Err(super::raw::invalid_cursor());
        }
        let mut budget = QueryBudget::new(
            u64::from(request.budget.max_records),
            request.budget.max_payload_bytes,
            Duration::from_secs(30),
            QueryCancellation::default(),
        );
        let provider = self.indexed_recall_provider(&request.context);
        let view = provider.open_view(known_at, &mut budget)?;
        let page = provider.candidates(
            &view,
            &IndexedQuery {
                filter: request.filter,
                text: request.text,
                neighbor_of: None,
                selection: IndexedSelection::Exhaustive {
                    page_size: request.page_size,
                    continuation: request.continuation,
                },
            },
            &mut budget,
        )?;
        Ok(RawRecallPage {
            hits: page
                .hits
                .into_iter()
                .map(|hit| RawRecallHit {
                    source: hit.source,
                    matches: hit.matches,
                })
                .collect(),
            status: match page.completion {
                IndexedCompletion::Complete => RawPageStatus::Complete,
                IndexedCompletion::More => RawPageStatus::PageLimit,
                IndexedCompletion::WorkLimit => RawPageStatus::WorkLimit,
                IndexedCompletion::ByteLimit => RawPageStatus::ByteLimit,
            },
            snapshot: page.snapshot,
            continuation: page.continuation,
        })
    }
}

impl IndexedRecallProvider for NativeIndexedRecallProvider<'_> {
    type View = NativeIndexedView;
    type Error = ServiceError;

    fn open_view(
        &self,
        known_at: Option<u64>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeIndexedView> {
        require_capability(self.context, Capability::Recall)?;
        require_capability(self.context, Capability::ReadEvidence)?;
        require_capability(self.context, Capability::RawEvidence)?;
        budget.check().map_err(budget_error)?;
        self.service
            .index_views
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 64).then_some(count + 1)
            })
            .map_err(|_| {
                ServiceError::new(
                    ErrorCode::ResourceExhausted,
                    "native indexed read-view limit reached",
                    true,
                )
            })?;
        let permit = ViewPermit(Arc::clone(&self.service.index_views));
        let snapshot = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(self.context.request.workspace_id.as_bytes());
        let (global, state) = self.service.select_snapshot(
            &snapshot,
            &self.context.request.workspace_id,
            known_at,
        )?;
        let auth = self
            .service
            .raw_authorization_epoch(&snapshot, &workspace)?;
        let index: IndexState = self
            .service
            .raw_value(&snapshot, &state_key(&workspace))?
            .unwrap_or_default();
        let generation = if let Some(number) = index.active {
            self.service
                .raw_value::<Generation, _>(&snapshot, &generation_key(&workspace, number))?
                .ok_or_else(|| integrity("active raw generation manifest is absent"))?
        } else {
            Generation {
                number: 0,
                analyzer: RAW_ANALYZER.into(),
                through: 0,
                authorization_epoch: auth,
                projected_sources: 0,
            }
        };
        if generation.authorization_epoch != auth || generation.analyzer != RAW_ANALYZER {
            return Err(stale_index());
        }
        let mut eligible = BTreeSet::new();
        for scope in &self.context.request.scopes {
            budget.check().map_err(budget_error)?;
            let prefix = format!(
                "{}eligibility/{}/",
                generation_prefix(&workspace, generation.number),
                digest_bytes(scope.as_bytes())
            )
            .into_bytes();
            let page = snapshot
                .scan_prefix_page(
                    &self.service.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: None,
                        max_entries: MAX_DOMAINS,
                        max_bytes: 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            if page.continuation.is_some() {
                return Err(stale_index());
            }
            for entry in page.entries {
                let id: String = decode(&entry.value, "index domain eligibility")?;
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
        for eligible_id in eligible {
            budget.check().map_err(budget_error)?;
            let domain: PolicyDomain = self
                .service
                .raw_value(
                    &snapshot,
                    &domain_key(&workspace, generation.number, &eligible_id),
                )?
                .ok_or_else(|| integrity("eligible raw domain is absent"))?;
            if domain.policies.is_empty() {
                return Err(integrity("raw domain has no authorization labels"));
            }
            if !domain
                .policies
                .iter()
                .all(|policy| policy_allows(&self.context.request, policy))
            {
                continue;
            }
            budget.charge(1, 0).map_err(budget_error)?;
            let id = canonical_digest(&domain.policies)?;
            if eligible_id != id {
                return Err(integrity("raw domain label binding is invalid"));
            }
            domains.insert(id, domain);
        }
        Ok(NativeIndexedView {
            _permit: permit,
            database_id: self.service.database_id.clone(),
            snapshot,
            workspace,
            global,
            known_at: state.watermarks.journal,
            generation,
            domains,
            principal: self.context.authorization_binding_digest()?,
            opened: Instant::now(),
        })
    }

    fn candidates(
        &self,
        view: &NativeIndexedView,
        query: &IndexedQuery,
        budget: &mut QueryBudget,
    ) -> ServiceResult<IndexedPage> {
        self.check_view(view, budget)?;
        let (limit, continuation, topk) = match &query.selection {
            IndexedSelection::Exhaustive {
                page_size,
                continuation,
            } => (*page_size, continuation.as_deref(), false),
            IndexedSelection::TopK { limit } => (*limit, None, true),
        };
        if limit == 0 || limit > 256 || query.filter.event_ids.len() > 64 {
            return Err(super::invalid("indexed selection bound invalid"));
        }
        if let Some(range) = query.filter.recorded_range {
            range
                .validate()
                .map_err(|_| super::invalid("indexed time range is invalid"))?;
        }
        if let Some(query) = &query.text {
            raw_query_terms(query).map_err(|_| super::invalid("indexed text query invalid"))?;
        }
        let binding = canonical_digest(&(
            &self.service.database_id,
            &view.principal,
            &query.filter,
            &query.text,
            query.neighbor_of,
            topk,
        ))?;
        let mut cursor: IndexCursor = if let Some(token) = continuation {
            self.service.open_private_cursor(CURSOR_DOMAIN, token)?
        } else {
            IndexCursor {
                snapshot_id: random_view_id()?,
                issued_at: unix_seconds()?,
                binding: binding.clone(),
                known_at: view.known_at,
                generation: view.generation.number,
                through: view.generation.through.min(view.known_at),
                authorization_epoch: view.generation.authorization_epoch,
                stage: 0,
                route: 0,
                after: None,
                direct: 0,
                tail: 0,
            }
        };
        let now = unix_seconds()?;
        if now < cursor.issued_at || now - cursor.issued_at > 900 {
            return Err(ServiceError::new(
                ErrorCode::ContinuationExpired,
                "indexed cursor expired",
                false,
            ));
        }
        if cursor.binding != binding
            || cursor.known_at != view.known_at
            || cursor.authorization_epoch != view.generation.authorization_epoch
        {
            return Err(super::raw::invalid_cursor());
        }
        if cursor.generation != view.generation.number
            || cursor.through > view.generation.through.min(view.known_at)
        {
            return Err(ServiceError::new(
                ErrorCode::SnapshotExpired,
                "indexed generation changed; start a new selection",
                false,
            ));
        }
        let mut direct = query.filter.event_ids.iter().copied().collect::<Vec<_>>();
        if let Some(id) = query.neighbor_of {
            let policy =
                self.service
                    .authorized_capture_policy(&view.snapshot, self.context, id)?;
            if policy.accepted_global_commit > view.global {
                return Err(super::not_found());
            }
            self.service
                .authorize_capture_dependencies(&view.snapshot, self.context, id)?;
            let event = self.service.load_captured_original(&view.snapshot, id)?;
            direct.extend(
                event
                    .event
                    .parent_event_ids
                    .iter()
                    .chain(event.event.supersedes_event_id.iter()),
            );
            direct.sort();
            direct.dedup();
        }
        let direct_only = !query.filter.event_ids.is_empty();
        let tail = if direct_only {
            Vec::new()
        } else {
            self.pending_tail(view, cursor.through, budget)?
        };
        let routes = if direct_only {
            Vec::new()
        } else {
            routes(view, query, cursor.through)?
        };
        let initial = encode(&cursor)?;
        let mut hits = Vec::new();
        let mut completion = IndexedCompletion::Complete;
        loop {
            budget.check().map_err(budget_error)?;
            let previous = cursor.clone();
            let candidate = match cursor.stage {
                0 => {
                    if let Some(id) = direct.get(cursor.direct) {
                        cursor.direct += 1;
                        Some(CandidateRef {
                            id: *id,
                            indexed: false,
                            term_route: false,
                        })
                    } else {
                        cursor.stage = 1;
                        continue;
                    }
                }
                1 => {
                    if let Some(route) = routes.get(cursor.route) {
                        let page = view
                            .snapshot
                            .scan_prefix_page(
                                &self.service.keyspaces.continuous,
                                ScanPageRequest {
                                    prefix: &route.prefix,
                                    start_after: cursor.after.as_deref().or(route.lower.as_deref()),
                                    max_entries: 1,
                                    max_bytes: 16 * 1024,
                                },
                            )
                            .map_err(storage_error)?;
                        if let Some(entry) = page.entries.first() {
                            if route
                                .upper
                                .as_ref()
                                .is_some_and(|upper| &entry.key >= upper)
                            {
                                cursor.route += 1;
                                cursor.after = None;
                                continue;
                            }
                            cursor.after = Some(entry.key.clone());
                            let id = decode(&entry.value, "raw posting identity")?;
                            Some(CandidateRef {
                                id,
                                indexed: true,
                                term_route: route.term,
                            })
                        } else {
                            cursor.route += 1;
                            cursor.after = None;
                            continue;
                        }
                    } else {
                        cursor.stage = 2;
                        continue;
                    }
                }
                2 => {
                    if let Some(id) = tail.get(cursor.tail) {
                        cursor.tail += 1;
                        Some(CandidateRef {
                            id: *id,
                            indexed: false,
                            term_route: false,
                        })
                    } else {
                        cursor.stage = 3;
                        break;
                    }
                }
                3 => break,
                _ => return Err(super::raw::invalid_cursor()),
            };
            let Some(candidate) = candidate else {
                continue;
            };
            if let Err(reason) = budget.charge(1, 0) {
                cursor = previous;
                completion = partial_limit(reason)?;
                break;
            }
            match self.match_candidate(view, query, candidate, cursor.through, budget) {
                Ok(Some(hit)) => {
                    hits.push(hit);
                    if topk {
                        hits.sort_by_key(rank);
                        hits.truncate(limit as usize);
                    } else if hits.len() == limit as usize {
                        completion = IndexedCompletion::More;
                        break;
                    }
                }
                Ok(None) => (),
                Err(error)
                    if error.code == ErrorCode::BudgetExhausted
                        && error.message == "indexed byte budget exhausted" =>
                {
                    cursor = previous;
                    completion = IndexedCompletion::ByteLimit;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if completion != IndexedCompletion::Complete && encode(&cursor)? == initial {
            return Err(ServiceError::new(
                ErrorCode::BudgetExhausted,
                "indexed page cannot advance within its allowance",
                false,
            ));
        }
        self.check_view(view, budget)?;
        let token = if !topk && completion != IndexedCompletion::Complete {
            Some(self.service.seal_private_cursor(CURSOR_DOMAIN, &cursor)?)
        } else {
            None
        };
        let snapshot = cursor.snapshot_id;
        Ok(IndexedPage {
            hits,
            completion,
            continuation: token,
            snapshot,
        })
    }
}

impl NativeIndexedRecallProvider<'_> {
    fn check_view(&self, view: &NativeIndexedView, budget: &QueryBudget) -> ServiceResult<()> {
        budget.check().map_err(budget_error)?;
        if view.opened.elapsed() > Duration::from_secs(30) {
            return Err(ServiceError::new(
                ErrorCode::SnapshotExpired,
                "indexed read view expired",
                false,
            ));
        }
        if view.database_id != self.service.database_id
            || view.principal != self.context.authorization_binding_digest()?
        {
            return Err(super::permission_denied());
        }
        let current = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self
            .service
            .raw_authorization_epoch(&current, &view.workspace)?
            != view.generation.authorization_epoch
        {
            return Err(stale_index());
        }
        Ok(())
    }

    fn pending_tail(
        &self,
        view: &NativeIndexedView,
        through: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<ObservationId>> {
        let prefix = format!("outbox/{}/", view.workspace).into_bytes();
        let mut after = prefix.clone();
        after.extend_from_slice(&through.to_be_bytes());
        let page = view
            .snapshot
            .scan_prefix_page(
                &self.service.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: Some(&after),
                    max_entries: MAX_TAIL + 1,
                    max_bytes: 2 * 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        let mut ids = Vec::new();
        for entry in page.entries {
            budget.charge(1, 0).map_err(budget_error)?;
            let work: super::capture::CaptureWork = decode(&entry.value, "raw tail work")?;
            if work.workspace_commit > view.known_at {
                break;
            }
            if ids.len() == MAX_TAIL {
                return Err(stale_index());
            }
            ids.push(work.event_id);
        }
        Ok(ids)
    }

    fn match_candidate(
        &self,
        view: &NativeIndexedView,
        query: &IndexedQuery,
        candidate: CandidateRef,
        through: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<IndexedHit>> {
        let CandidateRef {
            id,
            indexed,
            term_route,
        } = candidate;
        let policy = match self
            .service
            .authorized_capture_policy(&view.snapshot, self.context, id)
        {
            Ok(policy) => policy,
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::PermissionDenied | ErrorCode::NotFound
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if policy.accepted_global_commit > view.global {
            return Ok(None);
        }
        match self
            .service
            .authorize_capture_dependencies(&view.snapshot, self.context, id)
        {
            Ok(()) => (),
            Err(error) if error.code == ErrorCode::PermissionDenied => return Ok(None),
            Err(error) => return Err(error),
        }
        let document = if indexed {
            let document: IndexedOriginal = self
                .service
                .raw_value(
                    &view.snapshot,
                    &doc_key(&view.workspace, view.generation.number, id),
                )?
                .ok_or_else(|| integrity("raw posting document absent"))?;
            if document.commit > through || (term_route && !document.lexical_complete) {
                return Ok(None);
            }
            if !query.filter.matches(&document.source) {
                return Ok(None);
            }
            if let Some(RawTextQuery::AllTerms(_)) = &query.text {
                let terms = raw_query_terms(
                    query
                        .text
                        .as_ref()
                        .ok_or_else(|| integrity("query absent"))?,
                )
                .map_err(|_| super::invalid("text query invalid"))?;
                if document.lexical_complete
                    && terms
                        .iter()
                        .any(|term| !document.first_terms.contains_key(term))
                {
                    return Ok(None);
                }
            }
            Some(document)
        } else {
            None
        };
        let original = self.service.load_captured_original(&view.snapshot, id)?;
        let source = RawSource::from(&original.event);
        if !query.filter.matches(&source) {
            return Ok(None);
        }
        if let Some(parent) = query.neighbor_of {
            let target = self
                .service
                .load_captured_original(&view.snapshot, parent)?;
            if !original.event.parent_event_ids.contains(&parent)
                && original.event.supersedes_event_id != Some(parent)
                && !target.event.parent_event_ids.contains(&id)
                && target.event.supersedes_event_id != Some(id)
            {
                return Ok(None);
            }
        }
        if let Some(document) = document
            && (document.source != source || document.event_digest != original.receipt.event_digest)
        {
            return Err(integrity(
                "indexed source differs from its accepted original",
            ));
        }
        let matches = if let Some(text) = &query.text {
            let (Some(length), Some(digest)) = (source.byte_length, source.payload_digest) else {
                return Ok(None);
            };
            budget.charge(0, length).map_err(budget_error)?;
            let bytes = self.service.original_range(
                &view.snapshot,
                self.context,
                &original.event,
                0,
                length,
            )?;
            budget.check().map_err(budget_error)?;
            let Some(matches) = match_raw_original(id, digest, &bytes, text)
                .map_err(|_| integrity("raw indexed original digest mismatch"))?
            else {
                return Ok(None);
            };
            matches
        } else {
            Vec::new()
        };
        Ok(Some(IndexedHit { source, matches }))
    }
}

fn rank(hit: &IndexedHit) -> (u64, u64, ObservationId) {
    let spread = hit
        .matches
        .first()
        .zip(hit.matches.last())
        .map_or(u64::MAX, |(first, last)| last.end - first.start);
    (
        spread,
        hit.source.byte_length.unwrap_or(u64::MAX),
        hit.source.event_id,
    )
}

fn random_view_id() -> ServiceResult<String> {
    let mut id = [0; 32];
    getrandom::fill(&mut id).map_err(|_| integrity("view identity generation failed"))?;
    Ok(encode_hex(&id))
}

fn unix_seconds() -> ServiceResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| integrity("current time precedes supported cursor epoch"))
}

fn partial_limit(reason: QueryLimit) -> ServiceResult<IndexedCompletion> {
    match reason {
        QueryLimit::Work => Ok(IndexedCompletion::WorkLimit),
        QueryLimit::Bytes => Ok(IndexedCompletion::ByteLimit),
        _ => Err(budget_error(reason)),
    }
}

fn routes(
    view: &NativeIndexedView,
    query: &IndexedQuery,
    through: u64,
) -> ServiceResult<Vec<Route>> {
    let anchor = match &query.text {
        Some(RawTextQuery::AllTerms(_)) => raw_query_terms(
            query
                .text
                .as_ref()
                .ok_or_else(|| integrity("query absent"))?,
        )
        .map_err(|_| super::invalid("query invalid"))?
        .into_iter()
        .next(),
        Some(RawTextQuery::ExactPhrase(phrase)) => contextdb_index::raw_phrase_anchor(phrase),
        None => None,
    };
    let mut output = Vec::new();
    for (domain, policy) in &view.domains {
        if policy.first_commit > through {
            continue;
        }
        let base = format!(
            "{}route/{domain}/",
            generation_prefix(&view.workspace, view.generation.number)
        );
        let (route, term) = if let Some(parent) = query.neighbor_of {
            (format!("child/{parent}/"), false)
        } else if let Some(source) = query.filter.source_id {
            (format!("source/{source}/"), false)
        } else if let Some(session) = query.filter.session_id {
            (format!("session/{session}/"), false)
        } else if let Some(anchor) = &anchor {
            (format!("term/{}/", digest_bytes(anchor.as_bytes())), true)
        } else if query.filter.recorded_range.is_some() {
            ("time/".into(), false)
        } else {
            ("all/".into(), false)
        };
        let prefix = format!("{base}{route}").into_bytes();
        let (lower, upper) = if route == "time/" {
            let range = query
                .filter
                .recorded_range
                .ok_or_else(|| integrity("time route lacks range"))?;
            let time_key = |instant: i64| {
                [
                    prefix.clone(),
                    format!("{:020}/", (instant as u64) ^ (1_u64 << 63)).into_bytes(),
                ]
                .concat()
            };
            (
                Some(time_key(range.start.0)),
                range.end.map(|end| time_key(end.0)),
            )
        } else {
            (None, commit_upper(&prefix, through))
        };
        output.push(Route {
            prefix,
            lower,
            upper,
            term,
        });
        if term {
            let prefix = format!("{base}unindexed/").into_bytes();
            output.push(Route {
                upper: commit_upper(&prefix, through),
                prefix,
                lower: None,
                term: false,
            });
        }
    }
    Ok(output)
}

fn commit_upper(prefix: &[u8], through: u64) -> Option<Vec<u8>> {
    through
        .checked_add(1)
        .map(|next| [prefix, format!("{next:020}/").as_bytes()].concat())
}
