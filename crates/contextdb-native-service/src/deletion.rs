//! Administrative source-lineage discovery from accepted history. Search indexes,
//! ACL equivalence and ordinary causal parents do not establish data dependency.
//! This is the source/payload part of an inventory, not a deletion executor.

use contextdb_core::{ContentBlockId, ContentDigest, ObservationId, OriginalPayloadRef};
use contextdb_recall::{QueryBudget, QueryLimit};
use contextdb_service::CaptureReceipt;

use super::*;

const DOMAIN: &str = "contextdb/native-source-deletion-lineage/v1";
const PAGE_ENTRIES: usize = 256;
const PAGE_BYTES: usize = 1024 * 1024;
const MAX_TARGETS: usize = 65_536;

/// A source occurrence and the journal commitment needed for future pruning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDeletionSource {
    /// Original immutable acceptance, not a deletion receipt.
    pub receipt: CaptureReceipt,
    /// Digest of the accepted content-free recovery metadata.
    pub recovery_digest: ContentDigest,
}

/// Exact captured descendants and shared payload owners at one workspace commit.
///
/// This report excludes semantic-record, cache, provider, export, backup and key
/// inventories. It authorizes no removal and makes no physical-erasure claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDeletionLineage {
    /// Database identity of the inspected authority.
    pub database_id: String,
    /// Workspace inspected under administrative authorization.
    pub workspace_id: String,
    /// Native workspace commit rechecked before returning this report.
    pub workspace_commit: u64,
    /// Current native source-authorization epoch at that commit.
    pub authorization_epoch: u64,
    /// Explicitly selected source identities, in canonical order.
    pub roots: BTreeSet<ObservationId>,
    /// Affected captures in acceptance order, including shared-block owners.
    pub sources: Vec<NativeDeletionSource>,
    /// Referenced blocks with no unaffected captured owner, in block-ID order.
    pub payloads: Vec<OriginalPayloadRef>,
    /// Referenced novel blocks still used by an independent, unaffected capture.
    /// Removing a dependent request must preserve these shared source bytes.
    pub retained_shared_payloads: Vec<OriginalPayloadRef>,
    /// Domain-separated commitment to this report; never an authorization token.
    pub digest: ContentDigest,
}

struct SourceNode {
    receipt: CaptureReceipt,
    recovery_digest: Option<ContentDigest>,
    inputs: custody::Inputs,
    owned_payload: Option<ContentBlockId>,
}

#[derive(Default)]
struct SourceGraph {
    nodes: BTreeMap<ObservationId, SourceNode>,
    children: BTreeMap<ObservationId, BTreeSet<ObservationId>>,
    staged: BTreeMap<ContentBlockId, OriginalPayloadRef>,
    owners: BTreeMap<ContentBlockId, BTreeSet<ObservationId>>,
}

impl NativeService {
    /// Discover captured data dependencies for 1..256 explicit original IDs.
    ///
    /// The bounded administrative scan validates the complete workspace journal
    /// prefix, then follows revisions, model/tool/checkpoint inputs and shared
    /// staged blocks to a fixed point. It reads no search index and retains no
    /// original text in its result. Equal bytes in independent captures remain
    /// independent. A staged block shared by several occurrences affects all its
    /// owners, including owners accepted before a selected root.
    ///
    /// Work, materialized bytes and time use the supplied budget. Exhaustion or a
    /// concurrent workspace change returns an error, never a partial closure.
    /// Selected legacy captures require recovery-metadata migration before they
    /// can enter this report. No native write, suppression or removal is performed.
    pub fn inspect_original_deletion(
        &self,
        context: &AuthenticatedRequestContext,
        roots: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeDeletionLineage> {
        require_capability(context, Capability::Admin)?;
        if !(1..=256).contains(&roots.len()) {
            return Err(invalid("source deletion inspection requires 1..256 roots"));
        }
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        // Authenticate the root's workspace before reading any original body.
        // An administrator may inventory an already revoked source's identities.
        for id in roots {
            budget.charge(1, 0).map_err(budget_error)?;
            let receipt = self.captured_receipt_metadata(&snapshot, *id)?;
            if receipt.workspace_id.to_string() != context.request.workspace_id {
                return Err(permission_denied());
            }
        }
        let graph = self.read_source_graph(&snapshot, &world, budget)?;
        let (sources, payloads, retained_shared_payloads) = graph.closure(roots, budget)?;
        let mut report = NativeDeletionLineage {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            workspace_commit: world.watermarks.journal,
            authorization_epoch: self
                .raw_authorization_epoch(&snapshot, &world.workspace_digest)?,
            roots: roots.clone(),
            sources,
            payloads,
            retained_shared_payloads,
            digest: ContentDigest::from_bytes([0; 32]),
        };
        let bytes = encode(&(DOMAIN, &report))?;
        budget.charge(0, bytes.len() as u64).map_err(budget_error)?;
        report.digest = ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes());
        #[cfg(test)]
        BEFORE_CURRENT_CHECK.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        // Only the current-commit comparison holds publication authority.
        let _guard = self.lock_index_publication(budget)?;
        let current = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if self.workspace_state(&current, &context.request.workspace_id)? != world {
            return Err(ServiceError::new(
                ErrorCode::IndexTooStale,
                "workspace changed during source deletion inspection; inspect again",
                true,
            ));
        }
        budget.check().map_err(budget_error)?;
        Ok(report)
    }

    fn read_source_graph<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        world: &WorkspaceState,
        budget: &mut QueryBudget,
    ) -> ServiceResult<SourceGraph> {
        self.verify_source_lineage_journal(snapshot, budget)?;
        let prefix = format!("{}/", world.workspace_digest).into_bytes();
        let mut after = None;
        let mut through = 0_u64;
        let mut last_global = 0;
        let mut graph = SourceGraph::default();
        loop {
            budget.check().map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.workspace_map,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: after.as_deref(),
                        max_entries: PAGE_ENTRIES,
                        max_bytes: PAGE_BYTES,
                    },
                )
                .map_err(storage_error)?;
            for entry in page.entries {
                budget
                    .charge(1, entry.value.len() as u64)
                    .map_err(budget_error)?;
                let map: CommitMap = decode(&entry.value, "deletion workspace history")?;
                let next = through
                    .checked_add(1)
                    .ok_or_else(|| exhausted("workspace commit overflow"))?;
                if entry.key != workspace_map_key(&world.workspace_digest, next)
                    || next > world.watermarks.journal
                    || map.schema_version != SCHEMA_VERSION
                    || map.state.workspace_digest != world.workspace_digest
                    || map.state.watermarks.journal != next
                    || map.global_commit <= last_global
                    || map.state.latest_global_commit != map.global_commit
                {
                    return Err(integrity(
                        "source deletion history has a gap or invalid mapping",
                    ));
                }
                validate_workspace_state(&map.state, &world.workspace_digest)?;
                let bytes = snapshot
                    .get(&self.keyspaces.events, &map.global_commit.to_be_bytes())
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("source deletion journal is absent"))?;
                budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
                let journal: StoredEvent = decode(&bytes, "source deletion journal")?;
                if journal.schema_version != SCHEMA_VERSION
                    || journal.global_commit != map.global_commit
                    || journal.workspace_commit != next
                    || journal.workspace_digest != world.workspace_digest
                    || journal.event_digest != event_digest(&journal)?
                    || (journal.operation == "capture") != journal.accepted_original.is_some()
                    || (journal.operation == "stage_payload") != journal.accepted_payload.is_some()
                {
                    return Err(integrity("source deletion journal binding is invalid"));
                }
                if let Some(reference) = &journal.accepted_payload {
                    self.verify_payload_journal_reference(snapshot, &journal)?;
                    budget
                        .charge(1, encode(reference)?.len() as u64)
                        .map_err(budget_error)?;
                    if graph
                        .staged
                        .insert(reference.block_id, reference.clone())
                        .is_some()
                    {
                        return Err(integrity("staged payload identity was accepted twice"));
                    }
                }
                if let Some(work) = &journal.accepted_original {
                    let original = self.load_captured_original(snapshot, work.event_id)?;
                    budget
                        .charge(1, encode(&original.event)?.len() as u64)
                        .map_err(budget_error)?;
                    if work != &self.capture_work_for_receipt(snapshot, &original.receipt)?
                        || original.receipt.workspace_commit != next
                        || digest_bytes(original.receipt.workspace_id.to_string().as_bytes())
                            != world.workspace_digest
                    {
                        return Err(integrity(
                            "source deletion capture differs from accepted history",
                        ));
                    }
                    let inputs = custody::inputs(&original.event)?;
                    // Account retained graph metadata as well as materialized bodies.
                    budget
                        .charge(
                            (inputs.sources.len() + inputs.payloads.len()) as u64,
                            2 * encode(&inputs)?.len() as u64 + 512,
                        )
                        .map_err(budget_error)?;
                    let owned_payload = match &original.event.payload {
                        contextdb_core::EventPayload::Staged { reference, .. } => {
                            Some(reference.block_id)
                        }
                        _ => None,
                    };
                    graph.insert(SourceNode {
                        receipt: original.receipt,
                        recovery_digest: work.recovery_digest,
                        inputs,
                        owned_payload,
                    })?;
                }
                through = next;
                last_global = map.global_commit;
                after = Some(entry.key);
                if through == world.watermarks.journal && map.state != *world {
                    return Err(integrity(
                        "source deletion history differs from workspace head",
                    ));
                }
            }
            if page.continuation.is_none() {
                break;
            }
        }
        if through != world.watermarks.journal || last_global != world.latest_global_commit {
            return Err(integrity("source deletion history is incomplete"));
        }
        Ok(graph)
    }

    // Verify the content-free global chain as well as the workspace mapping.
    // Otherwise changing a frame's operation and rehashing that one frame could
    // hide a capture from the inventory while its accepted original still exists.
    fn verify_source_lineage_journal<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let expected = self.global_head(snapshot)?;
        let mut through = 0_u64;
        let mut after = None;
        let mut previous = None;
        loop {
            budget.check().map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.events,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: PAGE_ENTRIES,
                        max_bytes: PAGE_BYTES,
                    },
                )
                .map_err(storage_error)?;
            for entry in page.entries {
                budget
                    .charge(1, entry.value.len() as u64)
                    .map_err(budget_error)?;
                through = through
                    .checked_add(1)
                    .ok_or_else(|| exhausted("global commit overflow"))?;
                let event: StoredEvent = decode(&entry.value, "source deletion journal chain")?;
                if through > expected
                    || entry.key != through.to_be_bytes()
                    || event.schema_version != SCHEMA_VERSION
                    || event.global_commit != through
                    || event.previous_event_digest != previous
                    || event.event_digest != event_digest(&event)?
                {
                    return Err(integrity("source deletion journal chain is invalid"));
                }
                previous = Some(event.event_digest);
                after = Some(entry.key);
            }
            if page.continuation.is_none() {
                break;
            }
        }
        budget.charge(1, 64).map_err(budget_error)?;
        let terminal = snapshot
            .get(&self.keyspaces.meta, META_EVENT_DIGEST_KEY)
            .map_err(storage_error)?;
        if through != expected || terminal.as_deref() != previous.as_deref().map(str::as_bytes) {
            return Err(integrity(
                "source deletion journal terminal binding is invalid",
            ));
        }
        Ok(())
    }
}

impl SourceGraph {
    fn insert(&mut self, node: SourceNode) -> ServiceResult<()> {
        let id = node.receipt.event_id;
        for source in &node.inputs.sources {
            // Native input edges must point to an earlier accepted capture in
            // this workspace. Ordinary causal-only parents are not input edges.
            if !self.nodes.contains_key(source) {
                return Err(integrity(
                    "source deletion input lacks an earlier accepted original",
                ));
            }
            self.children.entry(*source).or_default().insert(id);
        }
        for payload in &node.inputs.payloads {
            if self.staged.get(&payload.block_id) != Some(payload) {
                return Err(integrity(
                    "source deletion payload differs from accepted staging",
                ));
            }
            self.owners.entry(payload.block_id).or_default().insert(id);
        }
        if self.nodes.insert(id, node).is_some() {
            return Err(integrity(
                "source deletion capture identity was accepted twice",
            ));
        }
        Ok(())
    }

    fn closure(
        &self,
        roots: &BTreeSet<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<SourceClosure> {
        let mut pending = VecDeque::from_iter(roots.iter().copied());
        let mut selected = roots.clone();
        let mut blocks = BTreeMap::new();
        let mut sources = Vec::new();
        while let Some(id) = pending.pop_front() {
            budget.charge(1, 0).map_err(budget_error)?;
            let node = self
                .nodes
                .get(&id)
                .ok_or_else(|| integrity("selected original lacks journal acceptance"))?;
            let recovery_digest = node.recovery_digest.ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::FormatIncompatible,
                    "selected legacy source needs recovery metadata migration",
                    false,
                )
            })?;
            sources.push(NativeDeletionSource {
                receipt: node.receipt.clone(),
                recovery_digest,
            });
            let mut add = |child: ObservationId| -> ServiceResult<()> {
                budget.charge(1, 32).map_err(budget_error)?;
                if selected.insert(child) {
                    if selected.len() + blocks.len() > MAX_TARGETS {
                        return Err(exhausted("source deletion lineage exceeds 65536 targets"));
                    }
                    pending.push_back(child);
                }
                Ok(())
            };
            if let Some(children) = self.children.get(&id) {
                for child in children {
                    add(*child)?;
                }
            }
            // A staged original owns its full block. Releasing that source also
            // reaches earlier co-owners and their descendants. Request assembly
            // merely referencing an independent novel block does not delete its
            // other owners: retaining those bytes is necessary for their history.
            if let Some(block) = node.owned_payload {
                for owner in self.owners.get(&block).into_iter().flatten() {
                    add(*owner)?;
                }
            }
            for payload in &node.inputs.payloads {
                blocks.insert(payload.block_id, payload.clone());
            }
            if selected.len() + blocks.len() > MAX_TARGETS {
                return Err(exhausted("source deletion lineage exceeds 65536 targets"));
            }
        }
        sources.sort_by_key(|source| source.receipt.workspace_commit);
        let (released, retained) = blocks.into_values().partition(|block| {
            self.owners
                .get(&block.block_id)
                .is_some_and(|owners| owners.is_subset(&selected))
        });
        Ok((sources, released, retained))
    }
}

type SourceClosure = (
    Vec<NativeDeletionSource>,
    Vec<OriginalPayloadRef>,
    Vec<OriginalPayloadRef>,
);

fn budget_error(reason: QueryLimit) -> ServiceError {
    ServiceError::new(
        ErrorCode::BudgetExhausted,
        format!("source deletion inspection limit: {reason:?}"),
        false,
    )
}

#[cfg(test)]
thread_local! {
    static BEFORE_CURRENT_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default();
}

#[cfg(test)]
mod tests;
