//! Request-bound, budgeted discovery of independently retained observations.

use super::*;
use crate::{NativeDeletionLineage, NativeRemovalRequestReceipt, suppression::RemovalCheckpoint};

const CURSOR_DOMAIN: &[u8] = b"contextdb/raw-removal-copy-cursor/v1";
const MAX_CURSOR_BYTES: usize = 4096;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCopyScan {
    pub frontier: RemovalCheckpoint,
    pub through: RemovalCheckpoint,
}

pub(crate) struct RawCopyScanPage {
    pub state: RawCopyScan,
    pub examined: u32,
    pub witnesses: Vec<(NativeRawCopyReceipt, NativeRawCopyWitness)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u16,
    database: String,
    authority: Uuid,
    authorization: String,
    request: String,
    scan: RawCopyScan,
}

/// Selected source rows and unresolved shared/unknown obligations from one page.
/// Independent source-owned rows are omitted; missing historical coverage is not
/// converted into absence. This is observed-copy evidence, never a purge receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawRemovalCopy {
    /// Independent acceptance, including observations whose subsequent GC failed.
    pub witness: NativeRawCopyReceipt,
    /// Observed local generation number, not a global copy identity.
    pub generation: u64,
    /// Commitment to the observed generation manifest.
    pub generation_digest: String,
    /// Observed native global position; it can repeat after restore.
    pub native_commit: u64,
    /// Commitment distinguishing native histories at that position.
    pub native_event_digest: String,
    /// True when this page followed an already removed, untracked prefix.
    pub untracked_prefix: bool,
    /// Selected source rows plus shared, manifest and unknown rows. The latter
    /// have no single source owner and cannot be treated as independently absent.
    pub rows: Vec<NativeRawCopyObservation>,
}

/// A page over the retained observation journal for an exact removal request.
/// Reaching the journal frontier says nothing about current generations, copies
/// reclaimed before observation tracking, external copies or physical erasure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRawRemovalCopyPage {
    /// Exact independent removal request used to select source controls.
    pub request: NativeRemovalRequestReceipt,
    /// Fixed retained-journal frontier of this enumeration.
    pub observation_sequence: u64,
    /// Journal commitment at that frontier.
    pub observation_digest: String,
    /// Last journal event examined, including unrelated events.
    pub scanned_through: u64,
    /// Journal events consumed in this call, at most the requested limit.
    pub examined_events: u32,
    /// Relevant observations in retained acceptance order.
    pub copies: Vec<NativeRawRemovalCopy>,
    /// Authenticated continuation. Authority growth requires a fresh scan;
    /// reopening with the same token key preserves it, key rotation does not.
    pub continuation: Option<String>,
}

impl NativeService {
    /// Discover raw copies without knowing old GC receipt IDs. Each call consumes
    /// at most the requested 1..64 journal events and selects up to 8 MiB of
    /// witness metadata. Full request inventory, predecessor validation, decoding,
    /// selection and output share the budget.
    /// Exhaustion or a changed retained frontier returns no partial page.
    pub fn read_raw_removal_copies(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        continuation: Option<&str>,
        max_events: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawRemovalCopyPage> {
        let lineage = self.read_original_removal_inventory(context, request, budget)?;
        let sources = source_controls(&lineage, budget)?;
        let scan = continuation
            .map(|token| self.decode_raw_copy_cursor(context, request, token, budget))
            .transpose()?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("raw copy authority absent"))?;
        let page = ledger.scan_raw_copy_witnesses(
            &digest_bytes(context.request.workspace_id.as_bytes()),
            scan.as_ref(),
            max_events,
            budget,
        )?;
        let copies = select_copies(page.witnesses, &sources, budget)?;
        let continuation = if page.state.through == page.state.frontier {
            None
        } else {
            Some(self.encode_raw_copy_cursor(context, request, page.state.clone())?)
        };
        let result = NativeRawRemovalCopyPage {
            request: request.clone(),
            observation_sequence: page.state.frontier.sequence,
            observation_digest: page.state.frontier.digest.clone(),
            scanned_through: page.state.through.sequence,
            examined_events: page.examined,
            copies,
            continuation,
        };
        crate::retention::keys::charge_report(&result, budget)?;
        ledger.require_raw_copy_frontier(&page.state.frontier, budget)?;
        Ok(result)
    }

    fn encode_raw_copy_cursor(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        scan: RawCopyScan,
    ) -> ServiceResult<String> {
        let cursor = Cursor {
            version: 1,
            database: digest_bytes(self.database_id.as_bytes()),
            authority: request.authority_id,
            authorization: context.authorization_binding_digest()?,
            request: canonical_digest(request)?,
            scan,
        };
        let payload = crate::encode_hex(&encode(&cursor)?);
        let mac = crate::keyed_token(&self.token_key, CURSOR_DOMAIN, payload.as_bytes());
        Ok(format!("{payload}.{mac}"))
    }

    fn decode_raw_copy_cursor(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        token: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<RawCopyScan> {
        if token.len() > MAX_CURSOR_BYTES {
            return Err(bad_cursor());
        }
        budget.charge(1, token.len() as u64).map_err(budget_error)?;
        let (payload, mac) = token.rsplit_once('.').ok_or_else(bad_cursor)?;
        if crate::keyed_token(&self.token_key, CURSOR_DOMAIN, payload.as_bytes()) != mac {
            return Err(bad_cursor());
        }
        let cursor: Cursor =
            serde_json::from_slice(&crate::decode_hex(payload).ok_or_else(bad_cursor)?)
                .map_err(|_| bad_cursor())?;
        if cursor.version != 1
            || cursor.database != digest_bytes(self.database_id.as_bytes())
            || cursor.authority != request.authority_id
            || cursor.authorization != context.authorization_binding_digest()?
            || cursor.request != canonical_digest(request)?
        {
            return Err(bad_cursor());
        }
        Ok(cursor.scan)
    }
}

pub(crate) fn select_copies(
    witnesses: Vec<(NativeRawCopyReceipt, NativeRawCopyWitness)>,
    sources: &BTreeMap<ObservationId, NativeRawSourceControl>,
    budget: &mut QueryBudget,
) -> ServiceResult<Vec<NativeRawRemovalCopy>> {
    let mut result = Vec::new();
    for (receipt, witness) in witnesses {
        budget
            .charge(witness.rows.len() as u64, 0)
            .map_err(budget_error)?;
        let mut selected = BTreeSet::new();
        for (id, control) in &witness.sources {
            budget.charge(1, 0).map_err(budget_error)?;
            if let Some(source) = sources.get(id) {
                if control != source {
                    return Err(integrity(
                        "raw observation source differs from removal inventory",
                    ));
                }
                selected.insert(*id);
            }
        }
        let untracked_prefix = witness.previous.is_none() && witness.removed_before != 0;
        let rows: Vec<_> = witness
            .rows
            .into_iter()
            .filter(|row| row.source.is_none_or(|id| selected.contains(&id)))
            .collect();
        if !rows.is_empty() || untracked_prefix {
            result.push(NativeRawRemovalCopy {
                witness: receipt,
                generation: witness.generation,
                generation_digest: witness.generation_digest,
                native_commit: witness.native_commit,
                native_event_digest: witness.native_event_digest,
                untracked_prefix,
                rows,
            });
        }
    }
    Ok(result)
}

pub(crate) fn source_controls(
    lineage: &NativeDeletionLineage,
    budget: &mut QueryBudget,
) -> ServiceResult<BTreeMap<ObservationId, NativeRawSourceControl>> {
    let mut sources = BTreeMap::new();
    for source in &lineage.sources {
        let control = NativeRawSourceControl {
            capture_commit: source.receipt.workspace_commit,
            event_digest: source.receipt.event_digest,
            control_digest: source.control_digest,
        };
        budget
            .charge(1, (16 + encode(&control)?.len()) as u64)
            .map_err(budget_error)?;
        sources.insert(source.receipt.event_id, control);
    }
    Ok(sources)
}

fn bad_cursor() -> ServiceError {
    crate::invalid("raw copy cursor is invalid for this request, authority or token key")
}
