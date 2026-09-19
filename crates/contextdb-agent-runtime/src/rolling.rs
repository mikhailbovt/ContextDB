use std::collections::BTreeSet;

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
