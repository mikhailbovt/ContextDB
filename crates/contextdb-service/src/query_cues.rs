//! Shared source-preserving query sampling for owned runtime and native admission.
//! Sampling grants no storage, processing or disclosure authority.

use contextdb_context::{BlockId, OutgoingBase, OutgoingMessage, OutgoingRole, VisibleOriginal};
use contextdb_continuity::ToolResultPageView;
use contextdb_core::{ContentDigest, OriginalSourceSpan};
use contextdb_recall::QueryBudget;

use crate::{ErrorCode, ServiceError, ServiceResult};

/// Fixed syntax-preserving query sample, separate from lexical term extraction.
pub const DENSE_QUERY_CUE_REVISION: &str = "contextdb.owned-step-syntax-cues.v1";
/// Complete query-text ceiling, including channel labels and omission markers.
pub const MAX_DENSE_QUERY_CUE_BYTES: usize = 4096;
/// Explicit byte refinements measured before any query inference.
pub const DENSE_QUERY_PREFLIGHT_BYTE_LIMITS: [usize; 4] = [4096, 2048, 1024, 512];
/// Quota-preserving excerpts with an explicit byte limit and fresh provenance.
pub const DENSE_QUERY_REFINEMENT_REVISION: &str = "contextdb.owned-step-syntax-cues.bytes.v2";

/// Observational channel; no channel grants instruction or source authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenseCueChannel {
    /// Recent actual user phrasing.
    User,
    /// Recent visible tool observations.
    Tool,
    /// Source-backed active obligations.
    Working,
    /// Recent assistant observations or proposals.
    Assistant,
}

/// One exact excerpt inside the sampled query, with original rendering offsets.
/// Its source span describes bytes; the native owner must authorize them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenseCueFragment {
    /// Original channel of this observation.
    pub channel: DenseCueChannel,
    /// Message whose actual rendered text was sampled.
    pub message_id: BlockId,
    /// Inclusive UTF-8 byte offset in that message.
    pub message_start: u64,
    /// Exclusive UTF-8 byte offset in that message.
    pub message_end: u64,
    /// Inclusive byte offset in the complete sampled query.
    pub query_start: u32,
    /// Exclusive byte offset in the complete sampled query.
    pub query_end: u32,
    /// Exact selected original range, when the message attributes its bytes.
    pub source: Option<OriginalSourceSpan>,
}

/// Bounded process observation, not a rewritten original or an embedding receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct DenseQueryCues {
    /// Version of channel quotas, ordering and UTF-8 sampling rules.
    pub revision: &'static str,
    /// Case, punctuation and word order retained in selected source excerpts.
    pub text: String,
    /// BLAKE3 of these exact query bytes, including labels and omission markers.
    pub text_digest: ContentDigest,
    /// Exact excerpt provenance, excluding synthetic labels and gap markers.
    pub fragments: Vec<DenseCueFragment>,
    /// Selected observed bytes, excluding host-added formatting.
    pub inspected_bytes: u64,
    /// Eligible observed bytes omitted by this bounded sample.
    pub omitted_bytes: u64,
}
impl std::fmt::Debug for DenseQueryCues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DenseQueryCues")
            .field("revision", &self.revision)
            .field("text_digest", &self.text_digest)
            .field("query_bytes", &self.text.len())
            .field("fragments", &self.fragments.len())
            .field("inspected_bytes", &self.inspected_bytes)
            .field("omitted_bytes", &self.omitted_bytes)
            .finish_non_exhaustive()
    }
}

struct DensePart<'a> {
    message: &'a OutgoingMessage,
    order: (usize, usize),
    text: &'a str,
    message_start: usize,
    original: Option<&'a VisibleOriginal>,
}
struct DenseSample<'a> {
    part: DensePart<'a>,
    head_end: usize,
    tail_start: usize,
}

/// Sample actual current observations for a future dense query. This helper
/// performs no embedding, retrieval or settings change. It keeps syntax instead
/// of using BM25's sorted words; originals and the reader request remain intact.
/// Newest excerpts get channel quotas, then appear in their original order.
/// A clipped excerpt has an explicit gap; no provider may silently truncate it.
pub fn dense_step_query(
    base: &OutgoingBase,
    budget: &mut QueryBudget,
) -> ServiceResult<DenseQueryCues> {
    sample_dense_query(
        base,
        MAX_DENSE_QUERY_CUE_BYTES,
        DENSE_QUERY_CUE_REVISION,
        budget,
    )
}

/// Re-form a complete source-preserving sample at an explicit smaller byte cap.
/// This is a new observation, not truncation of a tokenized or embedded input.
/// The caller still needs owner admission and exact token measurement before
/// inference; a byte limit alone does not establish encoder capacity.
pub fn dense_step_query_with_byte_limit(
    base: &OutgoingBase,
    max_bytes: usize,
    budget: &mut QueryBudget,
) -> ServiceResult<DenseQueryCues> {
    if !(512..=MAX_DENSE_QUERY_CUE_BYTES).contains(&max_bytes) {
        return Err(invalid("dense query refinement byte cap is invalid"));
    }
    sample_dense_query(base, max_bytes, DENSE_QUERY_REFINEMENT_REVISION, budget)
}

fn sample_dense_query(
    base: &OutgoingBase,
    max_bytes: usize,
    revision: &'static str,
    budget: &mut QueryBudget,
) -> ServiceResult<DenseQueryCues> {
    const MAX_MESSAGES: usize = 256;
    const MAX_PARTS: usize = 2048;
    const MAX_CHANNEL_PARTS: usize = 8;
    const GAP: &str = "\n[omitted]\n";
    charge(budget, 1, 0)?;
    if base.current.len().saturating_add(base.working.len()) > MAX_MESSAGES {
        return Err(invalid("dense query message frontier exceeds its bound"));
    }
    let part_count =
        base.current
            .iter()
            .chain(&base.working)
            .try_fold(0_usize, |count, message| {
                charge(budget, 1, 0)?;
                count
                    .checked_add(message.originals.len().max(1))
                    .filter(|count| *count <= MAX_PARTS)
                    .ok_or_else(|| invalid("dense query source frontier exceeds its bound"))
            })?;
    charge(
        budget,
        1,
        max_bytes as u64 + 64 * size_of::<DenseCueFragment>() as u64,
    )?;
    let mut text = String::with_capacity(max_bytes);
    let mut fragments = Vec::with_capacity(64);
    let mut eligible_bytes = 0_u64;
    let mut inspected_bytes = 0_u64;
    for (messages, role, channel, quota, label) in [
        (
            &base.current,
            Some(OutgoingRole::User),
            DenseCueChannel::User,
            1952,
            "User:\n",
        ),
        (
            &base.current,
            Some(OutgoingRole::Tool),
            DenseCueChannel::Tool,
            1120,
            "\nTool:\n",
        ),
        (
            &base.working,
            None,
            DenseCueChannel::Working,
            704,
            "\nWorking:\n",
        ),
        (
            &base.current,
            Some(OutgoingRole::Assistant),
            DenseCueChannel::Assistant,
            320,
            "\nAssistant:\n",
        ),
    ] {
        charge(
            budget,
            messages.len() as u64 + 1,
            part_count as u64 * size_of::<DensePart<'_>>() as u64,
        )?;
        let mut parts = Vec::with_capacity(part_count);
        for (index, message) in messages
            .iter()
            .enumerate()
            .filter(|(_, message)| role.is_none_or(|expected| message.role == expected))
        {
            charge(budget, 1, 0)?;
            if message.originals.is_empty() {
                // Protocol-only wrappers are not a substitute for observed text.
                if !message.tool_calls.is_empty() || message.tool_result.is_some() {
                    continue;
                }
                eligible_bytes = eligible_bytes
                    .checked_add(message.text.len() as u64)
                    .ok_or_else(|| invalid("dense query byte count overflow"))?;
                parts.push(DensePart {
                    message,
                    order: (index, 0),
                    text: &message.text,
                    message_start: 0,
                    original: None,
                });
            } else {
                for original in &message.originals {
                    charge(budget, 1, 0)?;
                    let start = usize::try_from(original.text_start)
                        .map_err(|_| invalid("dense query source offset overflow"))?;
                    let end = usize::try_from(original.text_end)
                        .map_err(|_| invalid("dense query source offset overflow"))?;
                    let observed = message.text.get(start..end).ok_or_else(|| {
                        invalid("dense query source range is outside its message")
                    })?;
                    if original.span.end.checked_sub(original.span.start)
                        != Some(observed.len() as u64)
                    {
                        return Err(invalid("dense query source/render lengths differ"));
                    }
                    // A page result stores a separate metadata anchor and preview.
                    // Exclude only that exact supported metadata/preview pairing.
                    if channel == DenseCueChannel::Tool
                        && message.originals.len() > 1
                        && observed.len() <= 4096
                    {
                        charge(budget, observed.len() as u64 + 1, observed.len() as u64 * 3)?;
                        if let Ok(view) = serde_json::from_str::<ToolResultPageView>(observed) {
                            charge(budget, message.originals.len() as u64 + 1, 0)?;
                            if view.validate().is_ok()
                                && message
                                    .originals
                                    .iter()
                                    .any(|shown| shown.span == view.preview)
                            {
                                continue;
                            }
                        }
                    }
                    eligible_bytes = eligible_bytes
                        .checked_add(observed.len() as u64)
                        .ok_or_else(|| invalid("dense query byte count overflow"))?;
                    parts.push(DensePart {
                        message,
                        order: (index, start),
                        text: observed,
                        message_start: start,
                        original: Some(original),
                    });
                }
            }
        }
        charge(budget, parts.len() as u64 * 12 + 1, 0)?;
        parts.sort_by_key(|part| part.order);
        charge(
            budget,
            1,
            MAX_CHANNEL_PARTS as u64 * size_of::<DenseSample<'_>>() as u64,
        )?;
        let mut samples = Vec::with_capacity(MAX_CHANNEL_PARTS);
        let mut remaining = quota * max_bytes / MAX_DENSE_QUERY_CUE_BYTES - label.len();
        for part in parts.into_iter().rev() {
            if samples.len() == MAX_CHANNEL_PARTS || remaining <= GAP.len() + 2 {
                break;
            }
            if part.text.is_empty() {
                continue;
            }
            let available = remaining.saturating_sub(usize::from(!samples.is_empty()));
            let (head_end, tail_start) = if part.text.len() <= available {
                (part.text.len(), part.text.len())
            } else {
                let body = available - GAP.len();
                let mut head = body / 2;
                while !part.text.is_char_boundary(head) {
                    head -= 1;
                }
                let mut tail = part.text.len() - (body - head);
                while !part.text.is_char_boundary(tail) {
                    tail += 1;
                }
                (head, tail)
            };
            let selected = head_end + part.text.len() - tail_start;
            if selected == 0 {
                continue;
            }
            charge(budget, selected as u64 + 1, 0)?;
            remaining -= selected
                + usize::from(tail_start != head_end) * GAP.len()
                + usize::from(!samples.is_empty());
            samples.push(DenseSample {
                part,
                head_end,
                tail_start,
            });
        }
        if samples.is_empty() {
            continue;
        }
        samples.sort_by_key(|sample| sample.part.order);
        text.push_str(label);
        for (index, sample) in samples.iter().enumerate() {
            if index != 0 {
                text.push('\n');
            }
            for (start, end) in [
                (0, sample.head_end),
                (sample.tail_start, sample.part.text.len()),
            ] {
                if start == end {
                    continue;
                }
                if start != 0 {
                    text.push_str(GAP);
                }
                let excerpt = &sample.part.text[start..end];
                charge(budget, 1, sample.part.message.id.as_str().len() as u64)?;
                let query_start = text.len() as u32;
                text.push_str(excerpt);
                inspected_bytes += excerpt.len() as u64;
                let source = sample.part.original.map(|original| OriginalSourceSpan {
                    event_id: original.span.event_id,
                    payload_digest: original.span.payload_digest,
                    start: original.span.start + start as u64,
                    end: original.span.start + end as u64,
                    span_digest: ContentDigest::from_bytes(
                        *blake3::hash(excerpt.as_bytes()).as_bytes(),
                    ),
                });
                fragments.push(DenseCueFragment {
                    channel,
                    message_id: sample.part.message.id.clone(),
                    message_start: (sample.part.message_start + start) as u64,
                    message_end: (sample.part.message_start + end) as u64,
                    query_start,
                    query_end: text.len() as u32,
                    source,
                });
            }
        }
    }
    if text.len() > max_bytes {
        return Err(invalid("dense query sample exceeds its complete byte cap"));
    }
    charge(budget, text.len() as u64 + 1, 0)?;
    Ok(DenseQueryCues {
        revision,
        text_digest: ContentDigest::from_bytes(*blake3::hash(text.as_bytes()).as_bytes()),
        text,
        fragments,
        inspected_bytes,
        omitted_bytes: eligible_bytes
            .checked_sub(inspected_bytes)
            .ok_or_else(|| invalid("dense query sample repeats uncounted bytes"))?,
    })
}

fn invalid(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false)
}

fn charge(budget: &mut QueryBudget, work: u64, bytes: u64) -> ServiceResult<()> {
    budget.charge(work, bytes).map_err(|_| {
        ServiceError::new(
            ErrorCode::BudgetExhausted,
            "shared runtime allowance exhausted",
            false,
        )
    })
}
