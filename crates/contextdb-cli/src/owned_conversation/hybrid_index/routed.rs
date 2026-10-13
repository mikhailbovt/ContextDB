//! Explicit routed maintenance. Earlier accepted frames survive later errors.

use std::io::{self, Write};

use contextdb_native_service::{
    DensePrefixBaseReceiptV2, DensePrefixBaseRequestV2, DenseProjectionReceipt,
    DirectoryRouterReceiptV1, NativeRoutedMaintenanceTarget, NativeService,
    PrefixSegmentPublicationV2, PrefixSegmentSealRequestV2, RawProjectionProgress,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, ErrorCode, ServiceError, TextEmbeddingAdapter,
    TextEmbeddingProfile,
};
use serde::Serialize;

use super::{Mode, budget_error};
use crate::CliResult;
use crate::owned_conversation::invalid;

#[cfg(test)]
mod tests;

const PROFILE: &str = "contextdb.cli-owned-routed-index.v1";
const RAW_BATCH: u32 = 64;
const RAW_BATCHES: u8 = 8;
const BASE_BATCH: u32 = 64;
const MAX_BASE_WORK: u64 = 128;
const MAX_BASE_SPANS: u64 = 4096;
const SEAL_BATCH: u32 = 4;
const REQUEST_BYTES: usize = 128 * 1024;

/// Every graph publication is an explicit operator stage.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    Raw,
    Base,
    Seal,
    Router,
}

/// Accepted observations from this command, never a serving-readiness claim.
#[derive(Serialize)]
pub(in crate::owned_conversation) struct Progress {
    profile: &'static str,
    mode: Mode,
    stage: Stage,
    raw_batches: u8,
    dense_batches: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<RawProjectionProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<NativeRoutedMaintenanceTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<NativeRoutedMaintenanceTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<DensePrefixBaseReceiptV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seal: Option<PrefixSegmentPublicationV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    router: Option<DirectoryRouterReceiptV1>,
}

/// Emit each exact publication request before its native acceptance. An observer
/// failure prevents that publication; previous synchronized work is not undone.
pub(in crate::owned_conversation) fn advance(
    owner: &NativeService,
    context: &AuthenticatedRequestContext,
    encoder: Option<&dyn TextEmbeddingAdapter>,
    mode: Mode,
    stage: Stage,
    parent: &mut QueryBudget,
    mut observe_request: impl FnMut(&serde_json::Value) -> CliResult<()>,
) -> CliResult<Progress> {
    parent.charge(1, 4096).map_err(budget_error)?;
    if mode == Mode::Bootstrap && stage != Stage::Raw {
        return Err(invalid("routed bootstrap is only valid for the raw stage"));
    }
    let mut progress = Progress {
        profile: PROFILE,
        mode,
        stage,
        raw_batches: 0,
        dense_batches: 0,
        raw: None,
        before: None,
        after: None,
        base: None,
        seal: None,
        router: None,
    };
    if stage == Stage::Raw {
        let mut raw =
            owner.project_originals_bm25(context, mode == Mode::Bootstrap, RAW_BATCH, parent)?;
        progress.raw_batches = 1;
        while !raw.caught_up && progress.raw_batches < RAW_BATCHES {
            parent.charge(1, 0).map_err(budget_error)?;
            raw = owner.project_originals_bm25(context, false, RAW_BATCH, parent)?;
            progress.raw_batches += 1;
        }
        progress.raw = Some(raw);
        return Ok(progress);
    }

    let mut observed = owner.original_span_routed_maintenance_target(context, parent)?;
    match stage {
        Stage::Base => {
            if let Some(base) = &observed.base {
                progress.base = Some(bounded_clone(base, parent)?);
                progress.before = Some(observed);
                return Ok(progress);
            }
            let mut target = match &observed.dense {
                Some(target) => bounded_clone(target, parent)?,
                None => {
                    let target = project(owner, context, encoder, &observed, BASE_BATCH, parent)?;
                    progress.dense_batches += 1;
                    target
                }
            };
            if target.spans == 0 && !target.caught_up && target.sources <= u64::from(BASE_BATCH) {
                // At most two 64-work batches. An existing zero-vector target
                // above 64 sources cannot authorize another batch by this stage.
                observed = owner.original_span_routed_maintenance_target(context, parent)?;
                target = project(owner, context, encoder, &observed, BASE_BATCH, parent)?;
                progress.dense_batches += 1;
            }
            if target.spans == 0 || target.spans > MAX_BASE_SPANS || target.sources > MAX_BASE_WORK
            {
                return Err(ServiceError::new(
                    ErrorCode::ResourceExhausted,
                    "routed base requires a genuine prefix within 128 work and 1..4096 spans",
                    false,
                )
                .into());
            }
            let request = DensePrefixBaseRequestV2 {
                generation: observed.generation,
                target,
            };
            observe_request(&request_json(&request, parent)?)?;
            progress.base =
                Some(owner.publish_original_span_prefix_base(context, &request, parent)?);
        }
        Stage::Seal => {
            if observed.base.is_none() || observed.covered.is_none() {
                return Err(invalid("routed seal requires an accepted prefix base"));
            }
            if !pending_documents(&observed) && needs_dense_advance(&observed) {
                project(owner, context, encoder, &observed, SEAL_BATCH, parent)?;
                progress.dense_batches += 1;
                progress.before = Some(observed);
                observed = owner.original_span_routed_maintenance_target(context, parent)?;
            }
            if pending_documents(&observed) {
                let target = bounded_clone(
                    observed
                        .dense
                        .as_ref()
                        .ok_or_else(|| invalid("routed seal has no dense target"))?,
                    parent,
                )?;
                parent.charge(1, 4096).map_err(budget_error)?;
                let request = PrefixSegmentSealRequestV2 {
                    generation: observed.generation,
                    previous: observed.directory_ref.clone(),
                    target,
                };
                // Native proves the COMPLETE interval, whole source plans and
                // <=128 work/256 vectors. Counter hints never replace that proof.
                observe_request(&request_json(&request, parent)?)?;
                progress.seal =
                    Some(owner.seal_original_span_prefix_segment(context, &request, parent)?);
            } else {
                // A later receipt/cutoff alone is not a nonempty source interval.
                progress.after = Some(observed);
                return Ok(progress);
            }
        }
        Stage::Router => {
            let request = owner.original_span_directory_router_target(
                context,
                observed.generation,
                parent,
            )?;
            observe_request(&request_json(&request, parent)?)?;
            progress.router =
                Some(owner.publish_original_span_directory_router(context, &request, parent)?);
        }
        Stage::Raw => unreachable!("raw stage returned before target admission"),
    }
    if progress.before.is_none() {
        progress.before = Some(observed);
    }
    progress.after = Some(owner.original_span_routed_maintenance_target(context, parent)?);
    Ok(progress)
}

// Status already proves monotonic complete manifests. With nonzero removals
// closed, unchanged document counters/commitment are a no-op hint, not work proof.
fn pending_documents(observed: &NativeRoutedMaintenanceTarget) -> bool {
    match (&observed.dense, &observed.covered) {
        (Some(dense), Some(covered)) => {
            dense.sources != covered.sources || dense.commitment != covered.commitment
        }
        _ => false,
    }
}

fn needs_dense_advance(observed: &NativeRoutedMaintenanceTarget) -> bool {
    observed
        .dense
        .as_ref()
        .is_none_or(|dense| !dense.caught_up || !observed.dense_matches_raw)
}

fn project(
    owner: &NativeService,
    context: &AuthenticatedRequestContext,
    encoder: Option<&dyn TextEmbeddingAdapter>,
    observed: &NativeRoutedMaintenanceTarget,
    batch: u32,
    parent: &mut QueryBudget,
) -> CliResult<DenseProjectionReceipt> {
    let encoder = encoder
        .ok_or_else(|| invalid("this routed stage needs its verified local source encoder"))?;
    parent.charge(1, 16384).map_err(budget_error)?;
    let profile = encoder.profile().clone();
    profile.validate()?;
    if profile != TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(profile.backend_artifacts_digest)
        || observed
            .dense
            .as_ref()
            .is_some_and(|dense| dense.profile != profile)
    {
        return Err(invalid(
            "routed maintenance encoder differs from the fixed source profile",
        ));
    }
    let digest = profile.digest()?;
    if encoder.profile() != &profile {
        return Err(invalid(
            "routed source encoder profile changed before projection",
        ));
    }
    let dense = owner.project_original_spans(context, encoder, batch, parent)?;
    if encoder.profile() != &profile
        || dense.profile != profile
        || dense.profile_digest != digest
        || dense.generation != observed.generation
        || dense.raw_through != observed.raw_through
        || dense.raw_sources != observed.raw_sources
    {
        return Err(ServiceError::new(
            ErrorCode::IndexTooStale,
            "routed source generation or encoder changed during maintenance",
            true,
        )
        .into());
    }
    Ok(dense)
}

fn bounded_clone<T: Clone + Serialize>(value: &T, parent: &mut QueryBudget) -> CliResult<T> {
    let bytes = json_size(value, parent)?;
    parent
        .charge(bytes as u64 + 1, bytes as u64 * 16 + 8192)
        .map_err(budget_error)?;
    Ok(value.clone())
}

fn request_json<T: Serialize>(value: &T, parent: &mut QueryBudget) -> CliResult<serde_json::Value> {
    let bytes = json_size(value, parent)?;
    parent
        .charge(bytes as u64 + 1, bytes as u64 * 32 + 8192)
        .map_err(budget_error)?;
    serde_json::to_value(value)
        .map_err(|_| invalid("routed publication request cannot be serialized"))
}

fn json_size<T: Serialize>(value: &T, parent: &mut QueryBudget) -> CliResult<usize> {
    struct Counter<'a> {
        parent: &'a mut QueryBudget,
        bytes: usize,
        limit: Option<contextdb_recall::QueryLimit>,
    }
    impl Write for Counter<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Err(limit) = self.parent.charge(bytes.len() as u64 + 1, 0) {
                self.limit = Some(limit);
                return Err(io::Error::other(
                    "routed request serialization allowance exhausted",
                ));
            }
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= REQUEST_BYTES)
                .ok_or_else(|| io::Error::other("routed request exceeds its metadata bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        parent,
        bytes: 0,
        limit: None,
    };
    let result = serde_json::to_writer(&mut counter, value);
    if let Some(limit) = counter.limit {
        return Err(budget_error(limit).into());
    }
    result.map_err(|_| invalid("routed publication metadata exceeds its serialization bound"))?;
    Ok(counter.bytes)
}
