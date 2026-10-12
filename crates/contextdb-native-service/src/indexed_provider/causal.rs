//! One-hop projected adjacency from owner-admitted seeds. No payload reads.

use super::*;
use crate::budgeted;
use contextdb_core::EventCoverage;
use contextdb_service::AccessPolicy;

const MAX_SEEDS: usize = 8;
const MAX_SOURCES: usize = 256;
const MAX_POSTINGS: usize = 1024;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

/// Completion of this bounded projected route, never semantic/archive recall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CausalCompletion {
    Complete,
    RawLag,
    UnprojectedSource,
    CandidateLimit,
    PostingLimit,
    WorkLimit,
    ByteLimit,
    UnsupportedProfile,
}

#[derive(Debug)]
pub(crate) struct CausalPage {
    pub hits: Vec<IndexedHit>,
    /// Every permitted source actually admitted, including unranked suppliers.
    pub admitted_sources: BTreeMap<ObservationId, RawSource>,
    pub completion: CausalCompletion,
    pub raw_lag: bool,
    pub source_coverage_incomplete: bool,
}

/// Projected current originals authenticated under the same owned query view.
#[derive(Debug)]
pub(crate) struct CausalSeedPage {
    pub seeds: Vec<RawSource>,
    pub unprojected: bool,
}

impl CausalPage {
    fn empty(completion: CausalCompletion) -> Self {
        Self {
            hits: Vec::new(),
            admitted_sources: BTreeMap::new(),
            completion,
            raw_lag: false,
            source_coverage_incomplete: false,
        }
    }
}

enum DocumentAdmission {
    Admitted(Box<IndexedOriginal>),
    Inaccessible,
    Unprojected,
}

impl NativeIndexedRecallProvider<'_> {
    /// Only the native owner supplies these IDs from its admitted preflight
    /// fragments. Inaccessible current input refuses instead of becoming an
    /// apparently successful empty seed route.
    pub(crate) fn causal_owned_query_seeds(
        &self,
        view: &NativeIndexedView,
        ids: &[ObservationId],
        budget: &mut QueryBudget,
    ) -> ServiceResult<CausalSeedPage> {
        budget.check().map_err(budget_error)?;
        if ids.len() > MAX_SEEDS {
            return Err(super::super::invalid(
                "causal current input admits at most eight owner IDs",
            ));
        }
        self.causal_check_view(view, budget)?;
        budget
            .charge(
                ids.len() as u64 + 1,
                (ids.len() * (size_of::<RawSource>() + size_of::<ObservationId>())) as u64,
            )
            .map_err(budget_error)?;
        let mut seeds = Vec::with_capacity(ids.len());
        let mut seen = Vec::with_capacity(ids.len());
        let mut unprojected = false;
        for id in ids {
            budget
                .charge(MAX_SEEDS as u64 + 1, 0)
                .map_err(budget_error)?;
            if seen.contains(id) {
                continue;
            }
            seen.push(*id);
            match self.causal_document(view, *id, budget)? {
                DocumentAdmission::Admitted(document) => seeds.push(document.source),
                DocumentAdmission::Unprojected => unprojected = true,
                DocumentAdmission::Inaccessible => return Err(super::super::permission_denied()),
            }
        }
        self.causal_check_view(view, budget)?;
        Ok(CausalSeedPage { seeds, unprojected })
    }

    /// Internal owner integration only. Seed metadata is compared to accepted
    /// captures again; an ID supplied by a model never authorizes this route.
    pub(crate) fn causal_candidates(
        &self,
        view: &NativeIndexedView,
        owner_seeds: &[RawSource],
        budget: &mut QueryBudget,
    ) -> ServiceResult<CausalPage> {
        budget.check().map_err(budget_error)?;
        if owner_seeds.len() > MAX_SEEDS {
            return Err(super::super::invalid(
                "causal route admits at most eight owner seeds",
            ));
        }
        if !view.budgeted_for_bm25 || !view.current_snapshot || view.generation.number == 0 {
            return Ok(CausalPage::empty(CausalCompletion::UnsupportedProfile));
        }
        let mut page = CausalPage::empty(CausalCompletion::Complete);
        let result = self.causal_route(view, owner_seeds, &mut page, budget);
        if let Err(error) = result {
            if let Some(limit) = limited(&error) {
                page.completion = limit;
            } else if error.code == ErrorCode::Unsupported {
                page.completion = CausalCompletion::UnsupportedProfile;
            } else {
                return Err(error);
            }
        }
        // A partial budget cannot be refreshed. Return no usable hits if the
        // current epoch/publication cannot still be proved on this allowance.
        match self.causal_check_view(view, budget) {
            Ok(()) => (),
            Err(error) => {
                if let Some(limit) = limited(&error) {
                    page.hits.clear();
                    page.completion = limit;
                } else {
                    return Err(error);
                }
            }
        }
        if page.completion == CausalCompletion::Complete && page.raw_lag {
            page.completion = CausalCompletion::RawLag;
        }
        Ok(page)
    }

    fn causal_route(
        &self,
        view: &NativeIndexedView,
        seeds: &[RawSource],
        output: &mut CausalPage,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.causal_check_view(view, budget)?;
        output.raw_lag = self.causal_raw_lag(view, budget)?;
        for seed in seeds {
            let bytes = seed.source_version.as_ref().map_or(0, String::len);
            if bytes > 2048 {
                return Err(integrity("causal seed exceeds captured metadata bound"));
            }
            budget.charge(bytes as u64 + 1, 0).map_err(budget_error)?;
        }
        // Admit structural map nodes and vector growth before first insertion;
        // their multi-slot allocations are larger than one source-sized fee.
        let scratch = MAX_SOURCES * 2 * (12 * size_of::<(ObservationId, RawSource)>() + 512)
            + MAX_SOURCES * 2 * (12 * size_of::<ObservationId>() + 512)
            + MAX_SOURCES * 2 * size_of::<IndexedHit>();
        budget.charge(1, scratch as u64).map_err(budget_error)?;
        budget
            .charge(
                seeds.len() as u64 * 16 + 1,
                (seeds.len() * size_of::<&RawSource>()) as u64,
            )
            .map_err(budget_error)?;
        let mut ordered: Vec<_> = seeds.iter().collect();
        ordered.sort_unstable_by_key(|source| source.event_id);
        for pair in ordered.windows(2) {
            if pair[0].event_id == pair[1].event_id && pair[0] != pair[1] {
                return Err(integrity(
                    "causal seeds disagree on immutable original version",
                ));
            }
        }
        ordered.dedup_by_key(|source| source.event_id);
        let mut ranked = BTreeSet::new();
        let mut postings = 0;
        for seed in ordered {
            budget.check().map_err(budget_error)?;
            if output.admitted_sources.len() == MAX_SOURCES
                && !output.admitted_sources.contains_key(&seed.event_id)
            {
                output.completion = CausalCompletion::CandidateLimit;
                return Ok(());
            }
            let source = match self.causal_document(view, seed.event_id, budget)? {
                DocumentAdmission::Admitted(source) => *source,
                DocumentAdmission::Inaccessible => continue,
                DocumentAdmission::Unprojected => {
                    if output.completion == CausalCompletion::Complete {
                        output.completion = CausalCompletion::UnprojectedSource;
                    }
                    continue;
                }
            };
            if source.source != *seed {
                return Err(integrity(
                    "causal owner seed differs from accepted original metadata",
                ));
            }
            admit(&source.source, output, budget)?;
            // Parents and supersedes are authenticated as one exact immutable
            // set by capture recovery, independently of mutable route rows.
            for id in source.parents {
                budget.charge(8, 0).map_err(budget_error)?;
                if ranked.contains(&id) {
                    continue;
                }
                if output.admitted_sources.len() == MAX_SOURCES
                    && !output.admitted_sources.contains_key(&id)
                {
                    output.completion = CausalCompletion::CandidateLimit;
                    return Ok(());
                }
                match self.causal_document(view, id, budget)? {
                    DocumentAdmission::Admitted(parent) => {
                        admit(&parent.source, output, budget)?;
                        rank(parent.source, output, &mut ranked, budget)?;
                    }
                    DocumentAdmission::Inaccessible => (),
                    DocumentAdmission::Unprojected => {
                        if output.completion == CausalCompletion::Complete {
                            output.completion = CausalCompletion::UnprojectedSource;
                        }
                    }
                }
            }
            for (domain, policy) in &view.domains {
                budget.charge(1, 512).map_err(budget_error)?;
                if policy.first_commit > view.generation.through {
                    continue;
                }
                let prefix = format!(
                    "{}route/{domain}/child/{}/",
                    generation_prefix(&view.workspace, view.generation.number),
                    seed.event_id
                )
                .into_bytes();
                let mut after = None;
                loop {
                    if postings == MAX_POSTINGS {
                        output.completion = CausalCompletion::PostingLimit;
                        return Ok(());
                    }
                    let batch = budgeted::metadata(&view.snapshot, budget, |reader| {
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
                    })?;
                    let Some(row) = batch.entries.into_iter().next() else {
                        if batch.continuation.is_some() {
                            return Err(integrity(
                                "causal posting page has no complete absence boundary",
                            ));
                        }
                        break;
                    };
                    budget
                        .charge(1, row.value.len() as u64 + row.key.len() as u64)
                        .map_err(budget_error)?;
                    let id: ObservationId = decode(&row.value, "causal child posting")?;
                    after = Some(row.key.clone());
                    postings += 1;
                    if output.admitted_sources.len() == MAX_SOURCES
                        && !output.admitted_sources.contains_key(&id)
                    {
                        output.completion = CausalCompletion::CandidateLimit;
                        return Ok(());
                    }
                    // Recheck even a repeated posting: every supplied domain,
                    // exact commit/key and edge must match accepted metadata.
                    match self.causal_document(view, id, budget)? {
                        DocumentAdmission::Admitted(child) => {
                            budget.charge(1, 512).map_err(budget_error)?;
                            let expected = [
                                prefix.as_slice(),
                                format!("{:020}/{id}", child.commit).as_bytes(),
                            ]
                            .concat();
                            if row.key != expected
                                || child.policy_domain != *domain
                                || !child.parents.contains(&seed.event_id)
                            {
                                return Err(integrity(
                                    "causal child posting differs from accepted source edge",
                                ));
                            }
                            admit(&child.source, output, budget)?;
                            rank(child.source, output, &mut ranked, budget)?;
                        }
                        DocumentAdmission::Inaccessible => (),
                        DocumentAdmission::Unprojected => {
                            return Err(integrity("causal posting source document is absent"));
                        }
                    }
                    if batch.continuation.is_none() {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn causal_check_view(
        &self,
        view: &NativeIndexedView,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.charge(1, 4096).map_err(budget_error)?;
        if view.opened.elapsed() > Duration::from_secs(30) {
            return Err(ServiceError::new(
                ErrorCode::SnapshotExpired,
                "causal read view expired",
                true,
            ));
        }
        if !view.budgeted_for_bm25
            || !view.current_snapshot
            || view.database_id != self.service.database_id
            || view.principal != budgeted::auth::binding_digest(self.context, budget)?
        {
            return Err(super::super::permission_denied());
        }
        let current = self
            .service
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        budgeted::metadata(&current, budget, |reader| {
            self.service
                .require_custody_ready(reader, &view.workspace)?;
            let epoch = self
                .service
                .raw_authorization_epoch(reader, &view.workspace)?;
            let workspace = self
                .service
                .workspace_state(reader, &self.context.request.workspace_id)?;
            let state: IndexState = self
                .service
                .raw_value(reader, &state_key(&view.workspace))?
                .ok_or_else(stale_index)?;
            if epoch != view.generation.authorization_epoch
                || workspace.watermarks.journal != view.known_at
                || state.active != Some(view.generation.number)
            {
                return Err(stale_index());
            }
            Ok(())
        })?;
        let generation: Generation = value(
            self,
            &current,
            &generation_key(&view.workspace, view.generation.number),
            budget,
        )?
        .ok_or_else(stale_index)?;
        if generation != view.generation {
            return Err(stale_index());
        }
        Ok(())
    }

    fn causal_document(
        &self,
        view: &NativeIndexedView,
        id: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DocumentAdmission> {
        self.causal_check_view(view, budget)?;
        let policy = match self.service.authorized_capture_policy_with_budget(
            &view.snapshot,
            self.context,
            id,
            budget,
        ) {
            Ok(policy) => policy,
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::PermissionDenied | ErrorCode::NotFound
                ) =>
            {
                return Ok(DocumentAdmission::Inaccessible);
            }
            Err(error) => return Err(error),
        };
        if policy.accepted_global_commit > view.global {
            return Ok(DocumentAdmission::Inaccessible);
        }
        match self.service.authorize_derived_custody_with_budget(
            &view.snapshot,
            self.context,
            id,
            budget,
        ) {
            Ok(_) => (),
            Err(error) if error.code == ErrorCode::PermissionDenied => {
                return Ok(DocumentAdmission::Inaccessible);
            }
            Err(error) => return Err(error),
        }
        if self.service.source_prepared_at(
            &view.snapshot,
            &view.workspace,
            id,
            view.generation.removal_through,
            budget,
        )? {
            return Ok(DocumentAdmission::Inaccessible);
        }
        let labels =
            self.service
                .stored_custody_policies_with_budget(&view.snapshot, id, budget)?;
        charge_labels(&labels, budget)?;
        let domain = canonical_digest(&labels)?;
        if !view.domains.contains_key(&domain) {
            return Ok(DocumentAdmission::Inaccessible);
        }
        let Some(document) = value::<IndexedOriginal, _>(
            self,
            &view.snapshot,
            &doc_key(&view.workspace, view.generation.number, id),
            budget,
        )?
        else {
            return Ok(DocumentAdmission::Unprojected);
        };
        if document.source.event_id != id
            || document.policy_domain != domain
            || document.commit > view.generation.through
            || document.commit > view.known_at
        {
            return Err(integrity(
                "causal raw document differs from pinned generation or custody",
            ));
        }
        self.service.verify_projected_causal_metadata(
            &view.snapshot,
            &view.workspace,
            &document,
            budget,
        )?;
        budget
            .charge(1, size_of::<IndexedOriginal>() as u64)
            .map_err(budget_error)?;
        Ok(DocumentAdmission::Admitted(Box::new(document)))
    }

    fn causal_raw_lag(
        &self,
        view: &NativeIndexedView,
        budget: &mut QueryBudget,
    ) -> ServiceResult<bool> {
        budget.charge(1, 1024).map_err(budget_error)?;
        let prefix = format!("outbox/{}/", view.workspace).into_bytes();
        let mut after = prefix.clone();
        after.extend_from_slice(&view.generation.through.to_be_bytes());
        let page = budgeted::metadata(&view.snapshot, budget, |reader| {
            reader
                .scan_prefix_page(
                    &self.service.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: Some(&after),
                        max_entries: 1,
                        max_bytes: 4096,
                    },
                )
                .map_err(storage_error)
        })?;
        let Some(row) = page.entries.into_iter().next() else {
            if page.continuation.is_some() {
                return Err(integrity(
                    "causal lag page has no complete absence boundary",
                ));
            }
            return Ok(false);
        };
        budget
            .charge(1, row.value.len() as u64)
            .map_err(budget_error)?;
        let work: crate::capture::CaptureWork = decode(&row.value, "causal accepted raw lag")?;
        if work.workspace_commit <= view.generation.through
            || work.workspace_commit > view.known_at
            || row.key != crate::capture::work_key(&view.workspace, work.workspace_commit)
        {
            return Err(integrity("causal raw lag outbox differs from pinned view"));
        }
        self.service
            .verify_causal_capture_work(&view.snapshot, &view.workspace, &work, budget)?;
        Ok(true)
    }
}

fn value<T: serde::de::DeserializeOwned, S: ReadSnapshot>(
    provider: &NativeIndexedRecallProvider<'_>,
    snapshot: &S,
    key: &[u8],
    budget: &mut QueryBudget,
) -> ServiceResult<Option<T>> {
    let Some(bytes) = budgeted::read_value(
        snapshot,
        &provider.service.keyspaces.continuous,
        key,
        MAX_RECORD_BYTES,
        budget,
    )?
    else {
        return Ok(None);
    };
    budget
        .charge(bytes.len() as u64 + 1, bytes.len() as u64)
        .map_err(budget_error)?;
    decode(&bytes, "causal bounded metadata").map(Some)
}

fn admit(source: &RawSource, page: &mut CausalPage, budget: &mut QueryBudget) -> ServiceResult<()> {
    let bytes = source.source_version.as_ref().map_or(0, String::len);
    budget.charge(bytes as u64 + 8, 0).map_err(budget_error)?;
    if let Some(existing) = page.admitted_sources.get(&source.event_id) {
        return if existing == source {
            Ok(())
        } else {
            Err(integrity("causal route source version collision"))
        };
    }
    if page.admitted_sources.len() == MAX_SOURCES {
        return Err(super::super::exhausted(
            "causal admitted source frontier exceeds its bound",
        ));
    }
    budget
        .charge(1, 1024 + bytes as u64 * 2)
        .map_err(budget_error)?;
    page.source_coverage_incomplete |=
        source.coverage != EventCoverage::CompleteObservation || source.upstream_truncated;
    page.admitted_sources
        .insert(source.event_id, source.clone());
    Ok(())
}

fn rank(
    source: RawSource,
    page: &mut CausalPage,
    ranked: &mut BTreeSet<ObservationId>,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    if !source.independent_source || ranked.contains(&source.event_id) {
        return Ok(());
    }
    budget.charge(8, 1024).map_err(budget_error)?;
    ranked.insert(source.event_id);
    page.hits.push(IndexedHit {
        source,
        matches: Vec::new(),
    });
    Ok(())
}

fn charge_labels(labels: &[AccessPolicy], budget: &mut QueryBudget) -> ServiceResult<()> {
    if labels.len() > 128 {
        return Err(integrity(
            "causal custody conjunction exceeds native label bound",
        ));
    }
    for label in labels {
        // JSON escaping is at most six bytes per input byte. Reserve this
        // conservative encoding bound before canonicalizing an actual label set.
        budget.charge(1, 512).map_err(budget_error)?;
        for text in std::iter::once(&label.workspace_id)
            .chain(label.scopes.iter())
            .chain(label.owners.iter())
            .chain(label.audience.iter())
            .chain(label.purposes.iter())
        {
            budget
                .charge(text.len() as u64 + 1, text.len() as u64 * 6 + 8)
                .map_err(budget_error)?;
        }
        for (audience, purposes) in &label.audience_purpose_grants {
            budget
                .charge(audience.len() as u64 + 1, audience.len() as u64 * 6 + 16)
                .map_err(budget_error)?;
            for purpose in purposes {
                budget
                    .charge(purpose.len() as u64 + 1, purpose.len() as u64 * 6 + 8)
                    .map_err(budget_error)?;
            }
        }
    }
    Ok(())
}

fn limited(error: &ServiceError) -> Option<CausalCompletion> {
    if error.code != ErrorCode::BudgetExhausted {
        return None;
    }
    match error.message.as_str() {
        "indexed work budget exhausted" => Some(CausalCompletion::WorkLimit),
        "indexed byte budget exhausted" => Some(CausalCompletion::ByteLimit),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
