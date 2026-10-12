//! Explicit offline source maintenance; no encoder launch or serving activation.
//!
//! The caller retains the existing production lifecycle lock, verified native
//! owner, authenticated host context and owned encoder throughout this operation.

use contextdb_native_service::{
    DenseGraphReceipt, DenseProjectionReceipt, NativeService, RawProjectionProgress,
};
use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, ErrorCode, ServiceError, TextEmbeddingAdapter,
    TextEmbeddingProfile,
};
use serde::Serialize;

use super::invalid;
use crate::CliResult;

const PROFILE: &str = "contextdb.cli-owned-hybrid-index.v1";
const BATCH_EVENTS: u32 = 64;
const MAX_BATCHES: u8 = 8;
const MAX_GRAPH_SPANS: u64 = 4096;

/// Rebuild is an explicit operator choice, never an interactive error recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Mode {
    Bootstrap,
    Continue,
}

/// Exact accepted maintenance observations, without a semantic-recall claim.
#[derive(Serialize)]
pub(super) struct Progress {
    profile: &'static str,
    mode: Mode,
    raw_batches: u8,
    dense_batches: u8,
    raw: RawProjectionProgress,
    dense: Option<DenseProjectionReceipt>,
    /// None means this call did not observe a graph, never that no graph exists.
    graph: Option<DenseGraphReceipt>,
    /// True only when this call obtained an accepted immutable base receipt.
    graph_ready: bool,
    serving_activated: bool,
}

/// Advance finite source batches under one supplied parent allowance. An
/// unfinished build returns its accepted progress for explicit continuation.
/// Startup verification and encoder provisioning belong to the shared host.
/// A later error leaves earlier synchronized source batches durable; it never
/// rolls them back or starts a replacement generation implicitly.
pub(super) fn advance(
    owner: &NativeService,
    context: &AuthenticatedRequestContext,
    encoder: &dyn TextEmbeddingAdapter,
    mode: Mode,
    parent: &mut QueryBudget,
) -> CliResult<Progress> {
    parent.charge(1, 8192).map_err(budget_error)?;
    let profile = encoder.profile().clone();
    profile.validate()?;
    if profile != TextEmbeddingProfile::qwen3_06b_q8_llama_b10964(profile.backend_artifacts_digest)
    {
        return Err(invalid(
            "owned hybrid indexing requires the fixed local encoder profile",
        ));
    }
    let profile_digest = profile.digest()?;

    // Only the operator's first bootstrap batch starts a fresh generation. A
    // retained unfinished generation refuses another bootstrap; use Continue.
    let mut raw =
        owner.project_originals_bm25(context, mode == Mode::Bootstrap, BATCH_EVENTS, parent)?;
    let mut raw_batches = 1;
    while !raw.caught_up && raw_batches < MAX_BATCHES {
        parent.charge(1, 0).map_err(budget_error)?;
        raw = owner.project_originals_bm25(context, false, BATCH_EVENTS, parent)?;
        raw_batches += 1;
    }
    let mut progress = Progress {
        profile: PROFILE,
        mode,
        raw_batches,
        dense_batches: 0,
        raw,
        dense: None,
        graph: None,
        graph_ready: false,
        serving_activated: false,
    };
    if !progress.raw.caught_up {
        return Ok(progress);
    }

    for _ in 0..MAX_BATCHES {
        parent.charge(1, 0).map_err(budget_error)?;
        let dense = owner.project_original_spans(context, encoder, BATCH_EVENTS, parent)?;
        progress.dense_batches += 1;
        if dense.generation != progress.raw.generation
            || dense.raw_through != progress.raw.through
            || dense.raw_sources != progress.raw.projected_sources
            || dense.profile != profile
            || dense.profile_digest != profile_digest
            || encoder.profile() != &profile
        {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "owned hybrid source generation or encoder changed during maintenance",
                true,
            )
            .into());
        }
        let caught_up = dense.caught_up;
        progress.dense = Some(dense);
        if caught_up {
            break;
        }
    }
    let dense = progress
        .dense
        .as_ref()
        .expect("one bounded dense batch ran");
    if !dense.caught_up {
        return Ok(progress);
    }
    if dense.through != progress.raw.through || dense.sources != progress.raw.projected_sources {
        return Err(ServiceError::new(
            ErrorCode::IntegrityFailure,
            "complete dense receipt differs from its accepted raw prefix",
            false,
        )
        .into());
    }
    if dense.spans == 0 {
        return Err(invalid(
            "owned hybrid graph requires at least one encoded original span",
        ));
    }
    if dense.spans > MAX_GRAPH_SPANS {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "owned hybrid graph exceeds 4096 spans; paged maintenance is required",
            false,
        )
        .into());
    }

    // Native publication authenticates the full current dense census, policy
    // epoch and final graph in one CAS transaction. An unchanged exact retry
    // returns its accepted receipt. A changed/stripped base is never treated as
    // absent, and IndexTooStale never triggers an implicit rebuild here.
    parent.charge(1, 0).map_err(budget_error)?;
    progress.graph = Some(owner.publish_original_span_graph(context, parent)?);
    progress.graph_ready = true;
    Ok(progress)
}

fn budget_error(_: contextdb_recall::QueryLimit) -> ServiceError {
    ServiceError::new(
        ErrorCode::BudgetExhausted,
        "owned hybrid maintenance parent allowance exhausted",
        true,
    )
}
