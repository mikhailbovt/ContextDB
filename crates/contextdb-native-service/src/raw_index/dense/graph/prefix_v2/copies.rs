//! Immutable copy attribution survives deletion of live receipt/topology rows.

use super::*;
use contextdb_core::ObservationId;

fn decode_copy<T: serde::de::DeserializeOwned + Serialize>(value: &[u8]) -> ServiceResult<T> {
    let row: T = decode(value, "canonical prefix-base copy")?;
    if encode(&row)? != value {
        return Err(integrity("prefix-base copy encoding is not canonical"));
    }
    Ok(row)
}

impl NativeService {
    pub(in crate::raw_index) fn verify_dense_prefix_base_copy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        key: &[u8],
        value: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<ObservationId>> {
        budget.check().map_err(budget_error)?;
        if key.len() > types::KEY_BYTES as usize || value.len() > types::ROW_BYTES {
            return Err(integrity("prefix-base copy exceeds its row/key bound"));
        }
        budget
            .charge(1, key.len() as u64 * 4 + value.len() as u64 * 16 + 8192)
            .map_err(budget_error)?;
        let text =
            std::str::from_utf8(key).map_err(|_| integrity("prefix copy key is not UTF-8"))?;
        let mut parts = text.split('/');
        if parts.next() != Some("raw") || parts.next() != Some("g") {
            return Err(integrity("prefix copy namespace differs"));
        }
        let workspace = parts
            .next()
            .ok_or_else(|| integrity("prefix copy workspace absent"))?;
        let prefix = prefix_key(workspace, generation.number)?;
        let relative = key
            .strip_prefix(prefix.as_slice())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or_else(|| integrity("prefix copy generation namespace differs"))?;
        let accepted = self.accepted_prefix_base(snapshot, workspace, generation.number, budget)?;
        self.check_prefix_generation_binding(snapshot, workspace, generation, &accepted, budget)?;
        let manifest = &accepted.manifest;
        match relative.split('/').next() {
            Some("receipt") if relative == "receipt" => {
                let receipt: DensePrefixBaseReceiptV2 = decode_copy(value)?;
                if key != receipt_key(workspace, generation.number)? || receipt != accepted {
                    return Err(integrity(
                        "prefix receipt copy differs from retained acceptance",
                    ));
                }
                Ok(None)
            }
            Some("member") => {
                let row: PrefixMemberV2 = decode_copy(value)?;
                if key != member_key(workspace, generation.number, row.representation_id)? {
                    return Err(integrity("prefix member copy key differs"));
                }
                self.check_prefix_member(workspace, manifest, &row, budget)?;
                // The actual accepted envelope supplies the original version.
                let original =
                    self.load_captured_original_with_budget(snapshot, row.source.event_id, budget)?;
                budget
                    .charge(
                        original.event.parent_event_ids.len() as u64 + 2,
                        (original.event.parent_event_ids.len() as u64 + 1) * 2048
                            + original
                                .event
                                .source_version
                                .as_ref()
                                .map_or(0, |v| v.len() as u64 * 8)
                            + 8192,
                    )
                    .map_err(budget_error)?;
                let source = RawSource::from(&original.event);
                if source != row.source
                    || original.receipt.event_id != row.source.event_id
                    || original.receipt.workspace_commit != row.commit
                    || original.receipt.event_digest != row.event_digest
                    || digest_bytes(original.event.workspace_id.to_string().as_bytes()) != workspace
                {
                    return Err(integrity("prefix copy differs from actual captured source"));
                }
                let mut parents: BTreeSet<_> =
                    original.event.parent_event_ids.iter().copied().collect();
                if let Some(superseded) = original.event.supersedes_event_id {
                    parents.insert(superseded);
                }
                let document = IndexedOriginal {
                    source,
                    event_digest: original.receipt.event_digest,
                    commit: original.receipt.workspace_commit,
                    policy_domain: row.policy_domain,
                    lexical_complete: false,
                    first_terms: BTreeMap::new(),
                    parents,
                };
                self.verify_projected_causal_metadata(snapshot, workspace, &document, budget)?;
                Ok(Some(document.source.event_id))
            }
            Some("cohort") => {
                let row: PrefixCohortV2 = decode_copy(value)?;
                if key != cohort_key(workspace, generation.number, &row.policy_domain)? {
                    return Err(integrity("prefix cohort copy key differs"));
                }
                self.check_prefix_cohort(workspace, manifest, &row, budget)?;
                Ok(None)
            }
            Some("node") => {
                let row: PrefixNodeV2 = decode_copy(value)?;
                if key != node_key(workspace, generation.number, row.representation_id)? {
                    return Err(integrity("prefix node copy key differs"));
                }
                self.check_prefix_node(workspace, manifest, &row, budget)?;
                Ok(None)
            }
            _ => Err(integrity("unknown prefix-base copy row")),
        }
    }
}
