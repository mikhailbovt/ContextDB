//! Offline complete finite construction, then one native owner transaction.
use super::*;
use contextdb_index::{
    AnnNodeV2, AnnPartitionBuildBudgetV2, AnnPartitionBuildErrorV2, AnnPartitionBuildInputV2,
    AnnPartitionBuildSpecV2, build_ann_partition_v2,
};

struct BuildBudget<'a>(&'a mut QueryBudget);
impl AnnPartitionBuildBudgetV2 for BuildBudget<'_> {
    type Error = ServiceError;
    fn charge(&mut self, work: u64, bytes: u64) -> ServiceResult<()> {
        self.0.charge(work, bytes).map_err(budget_error)
    }
}
pub(super) struct GraphInput {
    pub vector: DenseVector,
    pub values: Vec<f32>,
    pub policies: Vec<AccessPolicy>,
}
type GraphRows = BTreeMap<Vec<u8>, Vec<u8>>;

impl NativeService {
    /// Build one finite immutable native ANN base. Any subsequent raw or dense
    /// advance requires a new raw generation; no serving activation is implied.
    pub fn publish_original_span_graph(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<DenseGraphReceipt> {
        for c in [
            Capability::Admin,
            Capability::ReadEvidence,
            Capability::RawEvidence,
            Capability::ModelProcessing,
        ] {
            require_capability(context, c)?;
        }
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        crate::budgeted::metadata(&snapshot, budget, |r| {
            self.require_custody_rebuilt(r, &workspace)
        })?;
        let state: IndexState = self
            .graph_read(
                &snapshot,
                &self.keyspaces.continuous,
                &state_key(&workspace),
                budget,
            )?
            .unwrap_or_default();
        let number = state.active.ok_or_else(stale_index)?;
        let generation: Generation = self
            .graph_read(
                &snapshot,
                &self.keyspaces.continuous,
                &generation_key(&workspace, number),
                budget,
            )?
            .ok_or_else(stale_index)?;
        if generation.custody_version != crate::custody::CUSTODY_VERSION
            || generation.analyzer != RAW_ANALYZER
            || generation.bm25.is_none()
        {
            return Err(stale_index());
        }
        generation
            .bm25
            .as_ref()
            .ok_or_else(stale_index)?
            .validate()?;
        if generation.authorization_epoch != self.graph_epoch(&snapshot, &workspace, budget)? {
            return Err(stale_index());
        }
        if generation.dense_graph.is_some() {
            return self.current_graph_receipt(&snapshot, &workspace, &generation, budget);
        }
        self.validate_dense_generation(&snapshot, &workspace, &generation, budget)?;
        let dense = generation.dense.as_ref().ok_or_else(stale_index)?;
        if dense.spans > MAX_NODES as u64 {
            return Err(exhausted("native graph complete node input exceeds 4096"));
        }
        if dense.through != generation.through || dense.sources != generation.projected_sources {
            return Err(stale_index());
        }
        if !self
            .graph_rows(&snapshot, &graph_prefix(&workspace, number), budget)?
            .is_empty()
        {
            return Err(integrity("orphan graph rows precede activation"));
        }
        // First activation alone walks retained declarations, under this same
        // budget. Regular retries and all queries use only exact point rows.
        let accepted = self.graph_declarations(&snapshot, budget)?;
        if accepted.contains_key(&(workspace.clone(), number)) {
            return Err(integrity("accepted graph was jointly stripped"));
        }
        let inputs = self.graph_inputs(
            &snapshot,
            &workspace,
            &generation,
            dense,
            Some(context),
            budget,
        )?;
        let (manifest, rows) =
            self.construct_graph(&workspace, &generation, dense, &inputs, budget)?;
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        crate::budgeted::metadata(&tx, budget, |r| self.require_custody_rebuilt(r, &workspace))?;
        if self.graph_read::<IndexState, _>(
            &tx,
            &self.keyspaces.continuous,
            &state_key(&workspace),
            budget,
        )? != Some(state)
            || self.graph_read::<Generation, _>(
                &tx,
                &self.keyspaces.continuous,
                &generation_key(&workspace, number),
                budget,
            )? != Some(generation.clone())
            || self.graph_epoch(&tx, &workspace, budget)? != generation.authorization_epoch
        {
            return Err(stale_index());
        }
        for input in &inputs {
            self.authorized_capture_policy_with_budget(
                &tx,
                context,
                input.vector.source.event_id,
                budget,
            )?;
            self.authorize_derived_custody_with_budget(
                &tx,
                context,
                input.vector.source.event_id,
                budget,
            )?;
            if self.stored_custody_policies_with_budget(
                &tx,
                input.vector.source.event_id,
                budget,
            )? != input.policies
            {
                return Err(stale_index());
            }
        }
        let frame = crate::budgeted::metadata(&tx, budget, |r| {
            self.begin_frame(r, &context.request.workspace_id, false)
        })?;
        self.graph_tag_allowance(&manifest, 8192, budget)?;
        let mut receipt = DenseGraphReceipt {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            manifest: manifest.clone(),
            global_commit: frame.global_commit,
            token: String::new(),
        };
        self.graph_tag_allowance(&receipt.manifest, 8192, budget)?;
        self.sign_graph_receipt(&mut receipt)?;
        self.enable_capture_extension(&mut tx, FEATURE)?;
        for (key, value) in rows {
            budget.charge(1, value.len() as u64).map_err(budget_error)?;
            tx.put(&self.keyspaces.continuous, key, value)
                .map_err(storage_error)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            receipt_key(&workspace, number),
            encode(&receipt)?,
        )
        .map_err(storage_error)?;
        let mut next = generation;
        next.dense_graph = Some(manifest);
        tx.put(
            &self.keyspaces.continuous,
            generation_key(&workspace, number),
            encode(&next)?,
        )
        .map_err(storage_error)?;
        let request = canonical_digest(&receipt)?;
        self.finish_frame(
            &mut tx,
            &frame,
            OPERATION,
            request.as_bytes(),
            &request,
            &receipt,
        )?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(receipt)
    }

    pub(super) fn graph_inputs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        dense: &DenseManifest,
        context: Option<&AuthenticatedRequestContext>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<GraphInput>> {
        let prefix = format!(
            "{}dense/document/",
            generation_prefix(workspace, generation.number)
        );
        let mut documents = Vec::new();
        for row in self.graph_rows(snapshot, prefix.as_bytes(), budget)? {
            let doc: DenseDocument = decode(&row.value, "graph source document")?;
            if row.key != document_key(workspace, generation.number, doc.source.event_id) {
                return Err(integrity("graph source document key differs"));
            }
            if doc.commit <= dense.through {
                documents.push(doc);
            }
        }
        budget
            .charge(
                documents.len() as u64 * 16 + 1,
                documents.len() as u64 * 256,
            )
            .map_err(budget_error)?;
        documents.sort_by_key(|d| d.commit);
        if documents.windows(2).any(|p| p[0].commit >= p[1].commit) {
            return Err(integrity("graph census source order differs"));
        }
        let mut census = DenseManifest::empty(&dense.profile)?;
        let mut inputs = Vec::new();
        let mut frozen = generation.clone();
        frozen.dense = Some(dense.clone());
        for document in documents {
            let id = document.source.event_id;
            if let Some(context) = context {
                self.authorized_capture_policy_with_budget(snapshot, context, id, budget)?;
                self.authorize_derived_custody_with_budget(snapshot, context, id, budget)?;
            }
            let original = self.load_captured_original_with_budget(snapshot, id, budget)?;
            if digest_bytes(original.event.workspace_id.to_string().as_bytes()) != workspace {
                return Err(integrity("graph source crosses workspace"));
            }
            let policies = self.stored_custody_policies_with_budget(snapshot, id, budget)?;
            if canonical_digest(&policies)? != document.policy_domain {
                return Err(integrity(
                    "graph cohort differs from complete native policies",
                ));
            }
            let policy_bytes = encode(&policies)?.len();
            if policy_bytes > ROW_BYTES / 2 {
                return Err(exhausted(
                    "native graph compound policy exceeds cohort row allowance",
                ));
            }
            let (checked, _) = self.reconstruct_dense_source(
                snapshot,
                workspace,
                &frozen,
                &original.event,
                original.receipt.workspace_commit,
                original.receipt.event_digest,
                &document.policy_domain,
                budget,
            )?;
            if checked != document {
                return Err(integrity("graph document reconstruction differs"));
            }
            census.accept(&document)?;
            for ordinal in 0..document.spans.len() {
                if inputs.len() >= MAX_NODES {
                    return Err(exhausted("native graph node cap exceeded"));
                }
                let vector: DenseVector = self
                    .graph_read(
                        snapshot,
                        &self.keyspaces.continuous,
                        &vector_key(workspace, generation.number, id, ordinal as u32),
                        budget,
                    )?
                    .ok_or_else(|| integrity("graph vector absent"))?;
                budget
                    .charge(
                        1,
                        vector.values_bits.len() as u64 * 4 + 8192 + policy_bytes as u64 * 4,
                    )
                    .map_err(budget_error)?;
                let values = vector
                    .values_bits
                    .iter()
                    .map(|bits| f32::from_bits(*bits))
                    .collect();
                inputs.push(GraphInput {
                    vector,
                    values,
                    policies: policies.clone(),
                });
            }
        }
        census.through = dense.through;
        if census != *dense {
            return Err(integrity(
                "graph input census differs from accepted dense commitment",
            ));
        }
        Ok(inputs)
    }

    pub(super) fn construct_graph(
        &self,
        workspace: &str,
        generation: &Generation,
        dense: &DenseManifest,
        inputs: &[GraphInput],
        budget: &mut QueryBudget,
    ) -> ServiceResult<(DenseGraphManifest, GraphRows)> {
        if inputs.len() > MAX_NODES {
            return Err(exhausted("native graph node cap exceeded"));
        }
        let mut groups = BTreeMap::<String, Vec<(GraphMember, &GraphInput)>>::new();
        let mut ids = BTreeSet::new();
        for input in inputs {
            budget.charge(1, 4096).map_err(budget_error)?;
            let (full, id) = identity(
                &self.database_id,
                workspace,
                generation.number,
                &input.vector,
            )?;
            if !ids.insert(id) {
                return Err(integrity("native graph representation collision"));
            }
            let v = &input.vector;
            let member = GraphMember {
                representation_id: id,
                identity_digest: full,
                source: v.source.clone(),
                event_digest: v.event_digest,
                commit: v.commit,
                ordinal: v.ordinal,
                span: v.span.clone(),
                policy_domain: v.policy_domain.clone(),
                profile_digest: v.profile_digest,
                vector_digest: v.vector_digest,
                graph_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            };
            groups
                .entry(v.policy_domain.clone())
                .or_default()
                .push((member, input));
            if groups.len() > MAX_COHORTS {
                return Err(exhausted("native graph cohort cap exceeded"));
            }
        }
        let space = vector_space(dense);
        let mut cohorts = Vec::new();
        let mut nodes = Vec::new();
        let mut members = Vec::new();
        let mut summaries = Vec::new();
        for (domain, mut group) in groups {
            budget
                .charge(group.len() as u64 * 16 + 1, group.len() as u64 * 64)
                .map_err(budget_error)?;
            group.sort_by_key(|(m, _)| m.representation_id);
            let policies = group[0].1.policies.clone();
            if group.iter().any(|(_, i)| i.policies != policies)
                || canonical_digest(&policies)? != domain
            {
                return Err(integrity("graph compound policy collision"));
            }
            let policy = *blake3::Hash::from_hex(&domain)
                .map_err(ann_error)?
                .as_bytes();
            let args: Vec<_> = group
                .iter()
                .map(|(m, i)| AnnPartitionBuildInputV2 {
                    representation_id: m.representation_id,
                    values: &i.values,
                })
                .collect();
            let built = build_ann_partition_v2(
                &mut BuildBudget(budget),
                &space,
                AnnPartitionBuildSpecV2 {
                    generation: generation.number,
                    policy_digest: policy,
                    membership_epoch: portable_epoch(generation.authorization_epoch)?,
                    global_leaf_index: cohorts.len() as u64,
                    valid_for_all_from: TimestampMicros(i64::MIN),
                    valid_for_all_until: None,
                    parameters: parameters(),
                },
                &args,
            )
            .map_err(|e| match e {
                AnnPartitionBuildErrorV2::Budget(e) => e,
                other => ann_error(other),
            })?;
            let partition = built.partition.encode_json().map_err(ann_error)?;
            summaries.push(GraphCohortSummary {
                policy_domain: domain.clone(),
                partition_digest: digest(&partition),
                nodes: group.len() as u64,
            });
            cohorts.push(GraphCohort {
                policy_domain: domain.clone(),
                policies,
                partition,
                graph_digest: ContentDigest::from_bytes([0; 32]),
                token: String::new(),
            });
            for object in built.nodes {
                let node = AnnNodeV2::decode_canonical(object.value()).map_err(ann_error)?;
                nodes.push(GraphNode {
                    representation_id: node.representation_id,
                    policy_domain: domain.clone(),
                    canonical_node: object.value().to_vec(),
                    graph_digest: ContentDigest::from_bytes([0; 32]),
                    token: String::new(),
                });
            }
            members.extend(group.into_iter().map(|(m, _)| m));
        }
        members.sort_by_key(|m| m.representation_id);
        nodes.sort_by_key(|n| n.representation_id);
        let mut base = generation.clone();
        base.dense_graph = None;
        let mut manifest = DenseGraphManifest {
            revision: 1,
            generation: generation.number,
            source_generation_digest: source_generation_digest(generation)?,
            source_generation: encode(&base)?,
            dense: dense.clone(),
            authorization_epoch: generation.authorization_epoch,
            builder_revision: contextdb_index::ANN_PARTITION_BUILD_REVISION_V2.into(),
            nodes: members.len() as u64,
            cohorts: summaries,
            content_digest: ContentDigest::from_bytes([0; 32]),
        };
        budget
            .charge(
                members.len() as u64 + 1,
                (members.len() + nodes.len()) as u64 * 16384
                    + cohorts.len() as u64 * ROW_BYTES as u64,
            )
            .map_err(budget_error)?;
        manifest.content_digest = digest(&encode(&(
            "native-span-ann-final/v1",
            &manifest,
            &members,
            &cohorts,
            &nodes,
        ))?);
        manifest.validate()?;
        let mut rows = GraphRows::new();
        for mut m in members {
            m.graph_digest = manifest.content_digest;
            m.token = self.graph_member_token(&manifest, &m, budget)?;
            rows.insert(
                member_key(workspace, generation.number, m.representation_id),
                encode(&m)?,
            );
        }
        for mut c in cohorts {
            c.graph_digest = manifest.content_digest;
            c.token = self.graph_cohort_token(&manifest, &c, budget)?;
            rows.insert(
                cohort_key(workspace, generation.number, &c.policy_domain),
                encode(&c)?,
            );
        }
        for mut n in nodes {
            n.graph_digest = manifest.content_digest;
            n.token = self.graph_node_token(&manifest, &n, budget)?;
            rows.insert(
                node_key(workspace, generation.number, n.representation_id),
                encode(&n)?,
            );
        }
        if rows.values().any(|v| v.len() > ROW_BYTES) || rows.len() + 16 > MAX_PROJECTION_ROWS {
            return Err(exhausted("native graph publication row cap exceeded"));
        }
        Ok((manifest, rows))
    }
}
