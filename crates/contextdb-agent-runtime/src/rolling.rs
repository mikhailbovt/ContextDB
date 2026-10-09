use std::{cmp::Reverse, collections::BTreeSet};

use contextdb_context::{
    BlockId, OutgoingBase, OutgoingEncoder, OutgoingMessage, OutgoingRole, OutgoingZone,
    VisibleOriginal,
};
use contextdb_continuity::{ObligationStatus, OwnedRunCheckpoint};
use contextdb_core::{OriginalSourceSpan, RawFilter, RawTextQuery};
use contextdb_recall::{IndexedQuery, IndexedSelection, QueryBudget};
use contextdb_service::{AuthenticatedRequestContext, PayloadPort, ServiceResult};

use super::{charge, context_error, exhausted, invalid};

/// Hysteresis measured against the complete encoded base, before optional recall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollingPolicy {
    /// Crossing this input count starts a rotation.
    pub high_tokens: u32,
    /// Evict complete groups in chunks until at or below this count.
    pub low_tokens: u32,
    /// Preserve this many complete recent exchanges, in addition to pending work.
    pub keep_complete_groups: usize,
    /// Maximum groups removed before recounting the whole base.
    pub chunk_groups: usize,
    /// Bounded prepare/rotate attempts when mandatory recall adds more context.
    pub max_prepare_attempts: u8,
}
impl RollingPolicy {
    /// Reject zero, inverted or unbounded rolling profiles.
    pub fn validate(&self, max_input: u32) -> ServiceResult<()> {
        if self.low_tokens == 0
            || self.low_tokens >= self.high_tokens
            || self.high_tokens >= max_input
            || self.keep_complete_groups == 0
            || self.keep_complete_groups > 32
            || self.chunk_groups == 0
            || self.chunk_groups > 16
            || self.max_prepare_attempts == 0
            || self.max_prepare_attempts > 8
        {
            return Err(invalid("invalid rolling-window profile"));
        }
        Ok(())
    }
}

/// Complete-group eviction; current input, pending tools and obligations survive.
pub(crate) fn evict(state: &mut OwnedRunCheckpoint, policy: RollingPolicy) -> usize {
    let eligible = state
        .groups
        .iter()
        .take_while(|group| group.complete)
        .count()
        .saturating_sub(policy.keep_complete_groups)
        .min(policy.chunk_groups);
    state.groups.drain(..eligible);
    eligible
}

pub(crate) fn rehydrate<S: PayloadPort + ?Sized>(
    owner: &S,
    context: &AuthenticatedRequestContext,
    state: &OwnedRunCheckpoint,
    control: &[OutgoingMessage],
    budget: &mut QueryBudget,
) -> ServiceResult<OutgoingBase> {
    let mut base = OutgoingBase {
        control: control.to_vec(),
        working: vec![],
        hot: vec![],
        current: vec![],
    };
    for obligation in state
        .obligations
        .iter()
        .filter(|item| item.status == ObligationStatus::Open)
    {
        base.working.push(message(
            owner,
            context,
            &obligation.source,
            BlockId::new(format!("obligation:{}", obligation.id)).map_err(context_error)?,
            OutgoingRole::User,
            OutgoingZone::WorkingState,
            budget,
        )?);
    }
    for group in &state.groups {
        for item in &group.messages {
            let mut rendered = message(
                owner,
                context,
                &item.source,
                item.id.clone(),
                item.role,
                if group.complete {
                    OutgoingZone::HotHistory
                } else {
                    OutgoingZone::CurrentTurn
                },
                budget,
            )?;
            rendered.tool_calls = item.tool_calls.clone();
            rendered.tool_result = item.tool_result.clone();
            if group.complete {
                base.hot.push(rendered);
            } else {
                base.current.push(rendered);
            }
        }
    }
    Ok(base)
}

fn message<S: PayloadPort + ?Sized>(
    owner: &S,
    context: &AuthenticatedRequestContext,
    span: &OriginalSourceSpan,
    id: BlockId,
    role: OutgoingRole,
    zone: OutgoingZone,
    budget: &mut QueryBudget,
) -> ServiceResult<OutgoingMessage> {
    charge(budget, 1, span.end - span.start)?;
    let bytes = owner.read_original_span(context, span)?;
    if bytes.len() as u64 != span.end - span.start
        || blake3::hash(&bytes).as_bytes() != span.span_digest.as_bytes()
    {
        return Err(invalid("rehydrated original differs from checkpoint"));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| invalid("text runtime requires an explicit media adapter"))?;
    Ok(OutgoingMessage {
        id,
        zone,
        role,
        originals: vec![VisibleOriginal {
            span: span.clone(),
            text_start: 0,
            text_end: text.len() as u64,
        }],
        text,
        tool_calls: vec![],
        tool_result: None,
    })
}

pub(crate) fn count_base(
    encoder: &dyn OutgoingEncoder,
    base: &OutgoingBase,
    budget: &mut QueryBudget,
) -> ServiceResult<u32> {
    let messages = base
        .control
        .iter()
        .chain(&base.working)
        .chain(&base.hot)
        .chain(&base.current)
        .cloned()
        .collect::<Vec<_>>();
    Ok(encoder
        .encode(&messages, budget)
        .map_err(context_error)?
        .input_tokens)
}

/// Bounded R0 discovery from current input, without a mandatory retrieval LLM.
/// This is a lexical heuristic, not a guarantee of semantic or associative recall.
pub fn conversation_routes(base: &OutgoingBase) -> Vec<IndexedQuery> {
    let mut terms = BTreeSet::new();
    for message in base
        .current
        .iter()
        .filter(|item| item.role == OutgoingRole::User)
    {
        for term in message
            .text
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        {
            if term.chars().count() >= 3 && term.len() <= 256 {
                terms.insert(term.to_lowercase());
            }
        }
    }
    let mut terms = terms.into_iter().collect::<Vec<_>>();
    terms.sort_by(|a, b| b.chars().count().cmp(&a.chars().count()).then(a.cmp(b)));
    terms
        .into_iter()
        .take(8)
        .map(|term| IndexedQuery {
            filter: RawFilter::default(),
            text: Some(RawTextQuery::AllTerms(term)),
            neighbor_of: None,
            selection: IndexedSelection::TopK { limit: 8 },
        })
        .collect()
}

pub(crate) struct StepRecallCues {
    pub routes: Vec<IndexedQuery>,
    pub inspected_bytes: u64,
    pub omitted_bytes: u64,
}

// Search cues are observations, not instructions or assertions of fact. Each
// channel gets its own allowance so a large tool response cannot crowd out the
// user's request or an open obligation. Originals are never modified here.
pub(crate) fn current_step_routes(
    base: &OutgoingBase,
    budget: &mut QueryBudget,
) -> ServiceResult<StepRecallCues> {
    let mut inspected = 0_u64;
    let mut omitted = 0_u64;
    charge(budget, 1, 4 * size_of::<Vec<String>>() as u64)?;
    let mut channels = Vec::new();
    for (messages, role) in [
        (&base.current, Some(OutgoingRole::User)),
        (&base.current, Some(OutgoingRole::Tool)),
        (&base.working, None),
        (&base.current, Some(OutgoingRole::Assistant)),
    ] {
        let mut remaining = 16 * 1024;
        let mut terms = BTreeSet::new();
        for message in messages
            .iter()
            .rev()
            .filter(|message| role.is_none_or(|expected| message.role == expected))
        {
            charge(budget, 1, 0)?;
            let text = &message.text;
            let allowance = remaining.min(4096).min(text.len());
            let mut used = 0;
            if allowance == text.len() {
                collect_cues(text, 0, text.len(), &mut terms, budget)?;
                used = text.len();
            } else if allowance != 0 {
                let mut head_end = allowance / 2;
                while !text.is_char_boundary(head_end) {
                    head_end -= 1;
                }
                let mut tail_start = text.len() - (allowance - head_end);
                while !text.is_char_boundary(tail_start) {
                    tail_start += 1;
                }
                collect_cues(text, 0, head_end, &mut terms, budget)?;
                collect_cues(text, tail_start, text.len(), &mut terms, budget)?;
                used = head_end + text.len() - tail_start;
            }
            remaining -= used;
            inspected += used as u64;
            omitted += (text.len() - used) as u64;
        }
        charge(budget, 1, (terms.len() * size_of::<String>()) as u64)?;
        channels.push(terms.into_iter().map(|(_, term)| term).collect::<Vec<_>>());
    }
    charge(budget, 1, 8 * size_of::<String>() as u64)?;
    let mut chosen = Vec::new();
    for (terms, quota) in channels.iter().zip([3, 2, 2, 1]) {
        for term in terms.iter().take(quota) {
            if !chosen.contains(term) {
                charge(budget, 1, term.len() as u64)?;
                chosen.push(term.clone());
            }
        }
    }
    // Empty/duplicate channels release their slots to the remaining channels.
    for offset in 0..128 {
        for terms in &channels {
            if chosen.len() == 8 {
                break;
            }
            if let Some(term) = terms.get(offset)
                && !chosen.contains(term)
            {
                charge(budget, 1, term.len() as u64)?;
                chosen.push(term.clone());
            }
        }
        if chosen.len() == 8 {
            break;
        }
    }
    charge(budget, 1, (chosen.len() * size_of::<IndexedQuery>()) as u64)?;
    Ok(StepRecallCues {
        routes: chosen
            .into_iter()
            .map(|term| IndexedQuery {
                filter: RawFilter::default(),
                text: Some(RawTextQuery::AllTerms(term)),
                neighbor_of: None,
                selection: IndexedSelection::TopK { limit: 8 },
            })
            .collect(),
        inspected_bytes: inspected,
        omitted_bytes: omitted,
    })
}

fn cue_character(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn collect_cues(
    source: &str,
    start: usize,
    end: usize,
    terms: &mut BTreeSet<(Reverse<usize>, String)>,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    charge(budget, (end - start) as u64, (end - start) as u64)?;
    let fragment = &source[start..end];
    let skip_first = start != 0
        && source[..start]
            .chars()
            .next_back()
            .is_some_and(cue_character);
    let skip_last = end != source.len() && source[end..].chars().next().is_some_and(cue_character);
    let mut pieces = fragment.split(|c| !cue_character(c)).peekable();
    let mut first = true;
    while let Some(term) = pieces.next() {
        let clipped = (first && skip_first) || (pieces.peek().is_none() && skip_last);
        first = false;
        if clipped || term.len() > 256 || term.chars().count() < 3 {
            continue;
        }
        // Unicode lowercase may expand; reserve before creating the string.
        charge(budget, 1, (term.len() * 3 + 64) as u64)?;
        let term = term.to_lowercase();
        if term.len() <= 256 {
            terms.insert((Reverse(term.chars().count()), term));
            if terms.len() > 128 {
                terms.pop_last();
            }
        }
    }
    Ok(())
}

pub(crate) fn rotate<S: PayloadPort + ?Sized>(
    owner: &S,
    context: &AuthenticatedRequestContext,
    state: &mut OwnedRunCheckpoint,
    control: &[OutgoingMessage],
    encoder: &dyn OutgoingEncoder,
    policy: RollingPolicy,
    budget: &mut QueryBudget,
) -> ServiceResult<(OutgoingBase, usize)> {
    let mut base = rehydrate(owner, context, state, control, budget)?;
    let mut count = count_base(encoder, &base, budget)?;
    let mut removed = 0;
    if count > policy.high_tokens {
        while count > policy.low_tokens {
            let chunk = evict(state, policy);
            if chunk == 0 {
                break;
            }
            removed += chunk;
            base = rehydrate(owner, context, state, control, budget)?;
            count = count_base(encoder, &base, budget)?;
        }
    }
    if state.groups.len() > 64 {
        return Err(exhausted("hot interaction group limit reached"));
    }
    Ok((base, removed))
}
