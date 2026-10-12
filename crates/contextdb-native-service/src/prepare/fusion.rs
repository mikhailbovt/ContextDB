//! Fixed source-level rank fusion. Scores are routing priors, not probabilities.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
};

use contextdb_core::{ObservationId, OriginalSourceSpan, RawSource};
use contextdb_recall::{IndexedHit, QueryBudget};
use contextdb_service::ServiceResult;

use crate::{exhausted, integrity, invalid, raw_index::budget_error};

pub(super) const SOURCE_RRF_REVISION: &str = "native-source-rrf-equal-k60-micros-v1";
const MAX_SOURCES: usize = 256;
const MAX_ROUTES: usize = 3;
const K: u64 = 60;
const MICROS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum SourceRoute {
    Bm25,
    Dense,
    Causal,
}

/// Each route has already admitted these sources under the owner query fence.
/// Metadata supplied here does not create admission or a disclosure grant.
#[derive(Debug)]
pub(super) struct SourceRouteInput {
    pub route: SourceRoute,
    pub hits: Vec<IndexedHit>,
    pub admitted_sources: BTreeMap<ObservationId, RawSource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceRouteRank {
    pub route: SourceRoute,
    pub rank: u32,
}

#[derive(Debug)]
pub(super) struct FusedSource {
    pub hit: IndexedHit,
    pub routing_micros: u64,
    pub route_ranks: Vec<SourceRouteRank>,
}

#[derive(Debug)]
pub(super) struct SourceFusion {
    pub revision: &'static str,
    pub selected: Vec<FusedSource>,
    /// Includes admitted suppliers and omissions discarded by all ranked lists.
    pub admitted_sources: BTreeMap<ObservationId, RawSource>,
    pub ranked_out: bool,
}

#[derive(Default)]
struct Votes {
    micros: u64,
    ranks: BTreeMap<SourceRoute, u32>,
}

/// Equal weights, k=60, floor-to-micros per route and one vote per source.
/// Exact original matches are unioned before selecting the final 20..100 sources.
pub(super) fn fuse_sources(
    routes: Vec<SourceRouteInput>,
    final_limit: u32,
    budget: &mut QueryBudget,
) -> ServiceResult<SourceFusion> {
    budget.check().map_err(budget_error)?;
    if !(20..=100).contains(&final_limit) || routes.len() > MAX_ROUTES {
        return Err(invalid(
            "source fusion route or final source limit is invalid",
        ));
    }
    admit_scratch(&routes, budget)?;
    let mut kinds = BTreeSet::new();
    let mut frontier = BTreeMap::new();
    let mut votes = BTreeMap::<ObservationId, Votes>::new();
    let mut batches = BTreeMap::new();
    for input in routes {
        budget.charge(1, 128).map_err(budget_error)?;
        if !kinds.insert(input.route) {
            return Err(invalid("source fusion repeats a route"));
        }
        if input.hits.len() > MAX_SOURCES || input.admitted_sources.len() > MAX_SOURCES {
            return Err(exhausted("source fusion route exceeds its source bound"));
        }
        for (id, source) in &input.admitted_sources {
            source_work(source, budget)?;
            if *id != source.event_id {
                return Err(integrity("source fusion frontier identity differs"));
            }
        }
        for hit in &input.hits {
            source_work(&hit.source, budget)?;
            if input.admitted_sources.get(&hit.source.event_id) != Some(&hit.source) {
                return Err(integrity(
                    "ranked source is absent from its admitted route frontier",
                ));
            }
        }
        // The complete route frontier is capped before any new vote can grow
        // another map. A second disjoint route cannot allocate a 512-source vote set.
        for (id, source) in input.admitted_sources {
            budget.charge(8, 0).map_err(budget_error)?;
            if let Some(existing) = frontier.get(&id) {
                if existing != &source {
                    return Err(integrity(
                        "source fusion routes disagree on original version",
                    ));
                }
                continue;
            }
            if frontier.len() == MAX_SOURCES {
                return Err(exhausted("source fusion full frontier exceeds its bound"));
            }
            budget
                .charge(1, (size_of::<(ObservationId, RawSource)>() + 128) as u64)
                .map_err(budget_error)?;
            frontier.insert(id, source);
        }
        let mut seen = BTreeSet::new();
        for hit in &input.hits {
            budget.charge(8, 128).map_err(budget_error)?;
            if !seen.insert(hit.source.event_id) {
                continue;
            }
            let rank =
                u32::try_from(seen.len()).map_err(|_| exhausted("source fusion rank overflows"))?;
            let denominator = K
                .checked_add(u64::from(rank))
                .ok_or_else(|| exhausted("source fusion denominator overflows"))?;
            let contribution = MICROS
                .checked_div(denominator)
                .ok_or_else(|| integrity("source fusion denominator is zero"))?;
            budget.charge(8, 256).map_err(budget_error)?;
            let vote = votes.entry(hit.source.event_id).or_default();
            vote.micros = vote
                .micros
                .checked_add(contribution)
                .ok_or_else(|| exhausted("source fusion routing prior overflows"))?;
            vote.ranks.insert(input.route, rank);
        }
        batches.insert(input.route, input.hits);
    }
    budget
        .charge(
            MAX_ROUTES as u64,
            (MAX_ROUTES * size_of::<Vec<IndexedHit>>()) as u64,
        )
        .map_err(budget_error)?;
    let hits = super::frontier::union_raw_hits(batches.into_values().collect(), budget)?;
    budget
        .charge(
            hits.len() as u64,
            (hits.len() * size_of::<FusedSource>()) as u64,
        )
        .map_err(budget_error)?;
    let mut ranked = Vec::with_capacity(hits.len());
    for hit in hits {
        budget.charge(8, 0).map_err(budget_error)?;
        let vote = votes
            .remove(&hit.source.event_id)
            .ok_or_else(|| integrity("source fusion source has no route rank"))?;
        budget
            .charge(
                vote.ranks.len() as u64,
                (vote.ranks.len() * size_of::<SourceRouteRank>()) as u64,
            )
            .map_err(budget_error)?;
        ranked.push(FusedSource {
            hit,
            routing_micros: vote.micros,
            route_ranks: vote
                .ranks
                .into_iter()
                .map(|(route, rank)| SourceRouteRank { route, rank })
                .collect(),
        });
    }
    // The fixed source ceiling bounds sort comparisons; IDs break score ties.
    budget
        .charge(ranked.len() as u64 * 16, 0)
        .map_err(budget_error)?;
    ranked.sort_unstable_by(|left, right| {
        right
            .routing_micros
            .cmp(&left.routing_micros)
            .then_with(|| left.hit.source.event_id.cmp(&right.hit.source.event_id))
            .then_with(|| {
                left.hit
                    .source
                    .source_version
                    .cmp(&right.hit.source.source_version)
            })
    });
    let ranked_out = ranked.len() > final_limit as usize;
    ranked.truncate(final_limit as usize);
    Ok(SourceFusion {
        revision: SOURCE_RRF_REVISION,
        selected: ranked,
        admitted_sources: frontier,
        ranked_out,
    })
}

fn admit_scratch(routes: &[SourceRouteInput], budget: &mut QueryBudget) -> ServiceResult<()> {
    let mut admitted = 0_usize;
    let mut route_hits = 0_usize;
    let mut matches = 0_usize;
    for input in routes {
        budget.charge(1, 0).map_err(budget_error)?;
        if input.hits.len() > MAX_SOURCES || input.admitted_sources.len() > MAX_SOURCES {
            return Err(exhausted("source fusion route exceeds its source bound"));
        }
        admitted += input.admitted_sources.len();
        route_hits += input.hits.len();
        for hit in &input.hits {
            budget.charge(1, 0).map_err(budget_error)?;
            if hit.matches.len() > 64 {
                return Err(exhausted(
                    "source fusion raw match source exceeds its bound",
                ));
            }
            matches += hit.matches.len();
        }
    }
    let sources = admitted.min(MAX_SOURCES);
    let ranked = route_hits.min(MAX_SOURCES);
    // BTree nodes have multiple slots and may split; an entry-sized fee does
    // not admit their first allocation. Reserve complete bounded scratch trees
    // (including the shared union helper) before creating any of them. Unused
    // reserved capacity remains spent on the same parent, like QueryBudget::reserve.
    fn tree<T>(entries: usize) -> usize {
        entries * 2 * (12 * size_of::<T>() + 512)
    }
    let bytes = tree::<(ObservationId, RawSource)>(sources)
        + tree::<(ObservationId, Votes)>(ranked)
        + tree::<(SourceRoute, u32)>(ranked)
        + tree::<ObservationId>(route_hits)
        + tree::<SourceRoute>(routes.len())
        + tree::<(SourceRoute, Vec<IndexedHit>)>(routes.len())
        + tree::<(ObservationId, usize)>(ranked)
        + ranked * 2 * (size_of::<IndexedHit>() + size_of::<FusedSource>())
        + matches.min(2048) * 4 * size_of::<OriginalSourceSpan>();
    budget.charge(1, bytes as u64).map_err(budget_error)
}

fn source_work(source: &RawSource, budget: &mut QueryBudget) -> ServiceResult<()> {
    let version_bytes = source.source_version.as_ref().map_or(0, String::len);
    if version_bytes > 2048 {
        return Err(integrity(
            "source fusion version exceeds captured metadata bound",
        ));
    }
    budget
        .charge(version_bytes as u64 + 1, version_bytes as u64)
        .map_err(budget_error)
}

#[cfg(test)]
mod tests;
