//! Retained declarations survive generation GC; rows verify independently.
use super::*;
use contextdb_index::{AnnNodeV2, ann_v2_partition_key};

impl NativeService {
    pub(super) fn check_graph_publication(
        &self,
        event: &crate::StoredEvent,
        receipt: &DenseGraphReceipt,
    ) -> ServiceResult<()> {
        self.check_graph_receipt(receipt)?;
        if event.schema_version != crate::SCHEMA_VERSION
            || event.operation != OPERATION
            || event.global_commit != receipt.global_commit
            || event.workspace_digest != digest_bytes(receipt.workspace_id.as_bytes())
            || event.workspace_commit <= receipt.manifest.dense.through
            || event.event_digest != crate::event_digest(event)?
            || event.request_digest != canonical_digest(receipt)?
            || event.response_digest != digest_bytes(&encode(receipt)?)
        {
            return Err(integrity("accepted graph publication binding differs"));
        }
        Ok(())
    }
    fn graph_accepted_receipt<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &crate::StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseGraphReceipt> {
        let stored: crate::StoredIdempotency = self
            .graph_read(
                snapshot,
                &self.keyspaces.idempotency,
                event.request_digest.as_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("graph retained receipt absent"))?;
        if stored.schema_version != crate::SCHEMA_VERSION
            || stored.operation != OPERATION
            || stored.request_digest != event.request_digest
            || stored.response_digest != event.response_digest
            || stored.response_digest != digest_bytes(&stored.response_bytes)
        {
            return Err(integrity("graph retained idempotency binding differs"));
        }
        let receipt: DenseGraphReceipt = decode(&stored.response_bytes, "graph retained receipt")?;
        self.graph_tag_allowance(&receipt.manifest, 8192, budget)?;
        self.check_graph_publication(event, &receipt)?;
        Ok(receipt)
    }
    pub(super) fn graph_declarations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<(String, u64), DenseGraphReceipt>> {
        let mut declarations = BTreeMap::new();
        let mut after = None;
        let mut previous = 0;
        loop {
            let cap = (budget.remaining_bytes().saturating_sub(256) / 4).min(512 * 1024) as usize;
            if cap < 1024 {
                return Err(exhausted("graph declaration allowance exhausted"));
            }
            budget
                .charge(33, cap as u64 * 4 + 256)
                .map_err(budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.events,
                    ScanPageRequest {
                        prefix: b"",
                        start_after: after.as_deref(),
                        max_entries: 32,
                        max_bytes: cap,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                let event: crate::StoredEvent = decode(&row.value, "graph accepted event")?;
                if row.key != event.global_commit.to_be_bytes() || event.global_commit <= previous {
                    return Err(integrity("graph journal ordering differs"));
                }
                previous = event.global_commit;
                if event.operation != OPERATION {
                    continue;
                }
                let receipt = self.graph_accepted_receipt(snapshot, &event, budget)?;
                let key = (event.workspace_digest, receipt.manifest.generation);
                if declarations.insert(key, receipt).is_some() {
                    return Err(integrity(
                        "raw generation has multiple accepted immutable graphs",
                    ));
                }
            }
            let Some(next) = page.continuation else { break };
            if after.as_ref().is_some_and(|p: &Vec<u8>| next <= *p) {
                return Err(integrity("graph declaration scan made no progress"));
            }
            after = Some(next);
        }
        if !declarations.is_empty() {
            self.require_graph_feature(snapshot, budget)?;
        }
        Ok(declarations)
    }
    pub(in crate::raw_index) fn accepted_dense_graph_generations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<(String, u64), DenseGraphReceipt>> {
        self.graph_declarations(snapshot, &mut crate::retention::audit_budget())
    }
    pub(in crate::raw_index) fn validate_dense_graph_declaration(
        &self,
        workspace: &str,
        generation: &Generation,
        declaration: Option<&DenseGraphReceipt>,
    ) -> ServiceResult<()> {
        match (&generation.dense_graph, declaration) {
            (None, None) => Ok(()),
            (Some(m), Some(r))
                if &r.manifest == m
                    && digest_bytes(r.workspace_id.as_bytes()) == workspace
                    && m.generation == generation.number =>
            {
                // The supplied declaration comes from the already authenticated
                // accepted map; this pure join introduces no second read budget.
                self.graph_base(m)?;
                Ok(())
            }
            _ => Err(integrity(
                "graph manifest differs from retained accepted declaration",
            )),
        }
    }
    pub(super) fn graph_base(&self, m: &DenseGraphManifest) -> ServiceResult<Generation> {
        m.validate()?;
        if m.source_generation.len() > ROW_BYTES {
            return Err(integrity("graph frozen generation exceeds bound"));
        }
        let base: Generation = decode(&m.source_generation, "graph frozen raw generation")?;
        if base.dense_graph.is_some()
            || base.dense_segments.is_some()
            || base.number != m.generation
            || base.dense.as_ref() != Some(&m.dense)
            || base.authorization_epoch != m.authorization_epoch
            || base.through != m.dense.through
            || base.projected_sources != m.dense.sources
            || source_generation_digest(&base)? != m.source_generation_digest
            || base.custody_version != crate::custody::CUSTODY_VERSION
            || base.analyzer != RAW_ANALYZER
            || base.bm25.is_none()
            || encode(&base)? != m.source_generation
        {
            return Err(integrity("graph frozen source generation binding differs"));
        }
        Ok(base)
    }
    pub(super) fn current_graph_receipt<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseGraphReceipt> {
        let manifest = generation.dense_graph.as_ref().ok_or_else(stale_index)?;
        self.graph_tag_allowance(manifest, 8192, budget)?;
        self.graph_base(manifest)?;
        if manifest.source_generation_digest != source_generation_digest(generation)?
            || manifest.authorization_epoch != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        self.accepted_graph_receipt(snapshot, workspace, generation, budget)
    }
    /// Accepted immutable base only; advancement admission belongs to the
    /// separate opt-in tail envelope, never to the strict serving API.
    pub(super) fn accepted_graph_receipt<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseGraphReceipt> {
        let manifest = generation.dense_graph.as_ref().ok_or_else(stale_index)?;
        self.require_graph_feature(snapshot, budget)?;
        let receipt: DenseGraphReceipt = self
            .graph_read(
                snapshot,
                &self.keyspaces.continuous,
                &receipt_key(workspace, generation.number),
                budget,
            )?
            .ok_or_else(|| integrity("graph current receipt absent"))?;
        if &receipt.manifest != manifest
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
        {
            return Err(integrity("graph current receipt differs"));
        }
        let event: crate::StoredEvent = self
            .graph_read(
                snapshot,
                &self.keyspaces.events,
                &receipt.global_commit.to_be_bytes(),
                budget,
            )?
            .ok_or_else(|| integrity("graph publication absent"))?;
        if self.graph_accepted_receipt(snapshot, &event, budget)? != receipt {
            return Err(integrity(
                "graph point receipt differs from accepted receipt",
            ));
        }
        Ok(receipt)
    }
    pub(in crate::raw_index) fn reconstruct_dense_graph_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        let Some(manifest) = &generation.dense_graph else {
            return Ok(BTreeMap::new());
        };
        let frozen = self.graph_base(manifest)?;
        let inputs =
            self.graph_inputs(snapshot, workspace, &frozen, &manifest.dense, None, budget)?;
        let (reconstructed, mut rows) =
            self.construct_graph(workspace, &frozen, &manifest.dense, &inputs, budget)?;
        if reconstructed != *manifest {
            return Err(integrity("graph final canonical reconstruction differs"));
        }
        let receipt: DenseGraphReceipt = self
            .graph_read(
                snapshot,
                &self.keyspaces.continuous,
                &receipt_key(workspace, generation.number),
                budget,
            )?
            .ok_or_else(|| integrity("graph reconstruction receipt absent"))?;
        self.graph_tag_allowance(&receipt.manifest, 8192, budget)?;
        self.check_graph_receipt(&receipt)?;
        if &receipt.manifest != manifest
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
        {
            return Err(integrity("graph reconstruction receipt differs"));
        }
        rows.insert(receipt_key(workspace, generation.number), encode(&receipt)?);
        Ok(rows)
    }
    pub(super) fn check_graph_member(
        &self,
        workspace: &str,
        m: &DenseGraphManifest,
        row: &GraphMember,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.graph_tag_allowance(m, 8192, budget)?;
        let full = digest(&encode(&(
            "native-span-ann-member/v1",
            &self.database_id,
            workspace,
            m.generation,
            &row.source,
            row.event_digest,
            row.commit,
            row.ordinal,
            &row.span,
            &row.policy_domain,
            row.profile_digest,
            row.vector_digest,
        ))?);
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&full.as_bytes()[..16]);
        bytes[6] = (bytes[6] & 15) | 128;
        bytes[8] = (bytes[8] & 63) | 128;
        if row.identity_digest != full
            || row.representation_id.as_uuid().as_bytes() != &bytes
            || row.graph_digest != m.content_digest
            || row.token != self.graph_member_token(m, row, budget)?
            || row.commit > m.dense.through
            || row.profile_digest != m.dense.profile_digest
            || !m
                .cohorts
                .iter()
                .any(|c| c.policy_domain == row.policy_domain)
            || row.span.event_id != row.source.event_id
            || row.source.payload_digest != Some(row.span.payload_digest)
            || row.span.start >= row.span.end
            || row
                .source
                .byte_length
                .is_none_or(|length| row.span.end > length)
            || !row.source.independent_source
        {
            return Err(integrity(
                "graph member authentication or full identity differs",
            ));
        }
        Ok(())
    }
    pub(super) fn check_graph_cohort(
        &self,
        m: &DenseGraphManifest,
        row: &GraphCohort,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AnnPartitionManifestV2> {
        self.graph_tag_allowance(m, ROW_BYTES as u64, budget)?;
        let summary = m
            .cohorts
            .iter()
            .find(|c| c.policy_domain == row.policy_domain)
            .ok_or_else(|| integrity("graph cohort not admitted"))?;
        let partition = AnnPartitionManifestV2::decode_json(&row.partition).map_err(ann_error)?;
        let policy = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        if row.graph_digest != m.content_digest
            || row.token != self.graph_cohort_token(m, row, budget)?
            || canonical_digest(&row.policies)? != row.policy_domain
            || digest(&row.partition) != summary.partition_digest
            || partition.generation != m.generation
            || partition.policy_digest != policy
            || partition.vector_space_id != m.dense.vector_space_id
            || partition.membership_epoch != portable_epoch(m.authorization_epoch)?
            || partition.node_count != summary.nodes
        {
            return Err(integrity(
                "graph cohort native policy or owner seal differs",
            ));
        }
        Ok(partition)
    }
    pub(super) fn check_graph_node(
        &self,
        m: &DenseGraphManifest,
        row: &GraphNode,
        budget: &mut QueryBudget,
    ) -> ServiceResult<AnnNodeV2> {
        self.graph_tag_allowance(m, row.canonical_node.len() as u64 * 4 + 2048, budget)?;
        let node = AnnNodeV2::decode_canonical(&row.canonical_node).map_err(ann_error)?;
        let domain = *blake3::Hash::from_hex(&row.policy_domain)
            .map_err(ann_error)?
            .as_bytes();
        if row.token != self.graph_node_token(m, row, budget)?
            || row.graph_digest != m.content_digest
            || node.representation_id != row.representation_id
            || node.generation != m.generation
            || node.partition_key
                != ann_v2_partition_key(m.dense.vector_space_id, domain).map_err(ann_error)?
            || !m
                .cohorts
                .iter()
                .any(|c| c.policy_domain == row.policy_domain)
        {
            return Err(integrity("graph node owner seal differs"));
        }
        Ok(node)
    }
    pub(in crate::raw_index) fn verify_dense_graph_copy<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        key: &[u8],
        value: &[u8],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<ObservationId>> {
        let m = generation
            .dense_graph
            .as_ref()
            .ok_or_else(|| integrity("graph copy manifest absent"))?;
        budget
            .charge(
                m.cohorts.len() as u64 + 1,
                m.source_generation.len() as u64 * 8 + 8192,
            )
            .map_err(budget_error)?;
        self.graph_base(m)?;
        self.require_graph_feature(snapshot, budget)?;
        if value.len() > ROW_BYTES {
            return Err(integrity("graph copy exceeds row cap"));
        }
        budget
            .charge(1, value.len() as u64 * 3)
            .map_err(budget_error)?;
        let text = std::str::from_utf8(key).map_err(|_| integrity("graph copy key invalid"))?;
        let workspace = text
            .strip_prefix("raw/g/")
            .and_then(|s| s.split('/').next())
            .ok_or_else(|| integrity("graph copy workspace absent"))?;
        let prefix = graph_prefix(workspace, generation.number);
        if key == receipt_key(workspace, generation.number) {
            let r: DenseGraphReceipt = decode(value, "graph receipt copy")?;
            self.graph_tag_allowance(&r.manifest, 8192, budget)?;
            self.check_graph_receipt(&r)?;
            if r.manifest != *m || digest_bytes(r.workspace_id.as_bytes()) != workspace {
                return Err(integrity("graph receipt copy differs"));
            }
            return Ok(None);
        }
        let relative = key
            .strip_prefix(prefix.as_slice())
            .ok_or_else(|| integrity("graph copy key differs"))?;
        if relative.starts_with(b"member/") {
            let row: GraphMember = decode(value, "graph member copy")?;
            self.check_graph_member(workspace, m, &row, budget)?;
            if key != member_key(workspace, generation.number, row.representation_id) {
                return Err(integrity("graph member copy key differs"));
            }
            let original =
                self.load_captured_original_with_budget(snapshot, row.source.event_id, budget)?;
            if RawSource::from(&original.event) != row.source
                || original.receipt.workspace_commit != row.commit
                || original.receipt.event_digest != row.event_digest
                || digest_bytes(original.event.workspace_id.to_string().as_bytes()) != workspace
            {
                return Err(integrity("graph member copy source differs"));
            }
            Ok(Some(row.source.event_id))
        } else if relative.starts_with(b"cohort/") {
            let row: GraphCohort = decode(value, "graph cohort copy")?;
            self.check_graph_cohort(m, &row, budget)?;
            if key != cohort_key(workspace, generation.number, &row.policy_domain) {
                return Err(integrity("graph cohort copy key differs"));
            }
            Ok(None)
        } else if relative.starts_with(b"node/") {
            let row: GraphNode = decode(value, "graph node copy")?;
            self.check_graph_node(m, &row, budget)?;
            if key != node_key(workspace, generation.number, row.representation_id) {
                return Err(integrity("graph node copy key differs"));
            }
            Ok(None)
        } else {
            Err(integrity("unknown native graph copy row"))
        }
    }
}
