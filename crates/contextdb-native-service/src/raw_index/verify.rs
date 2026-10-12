//! Administrative reconstruction of rebuildable rows and accepted revocations.

use std::time::Duration;

use contextdb_recall::QueryCancellation;

use super::*;

impl NativeService {
    fn accepted_raw_bm25_generations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<(String, u64), RawProjectionProgress>> {
        let mut declared = BTreeMap::<(String, u64), RawProjectionProgress>::new();
        let mut budget = super::super::retention::audit_budget();
        let mut previous_commit = 0;
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: super::super::StoredEvent = decode(&row.value, "raw BM25 publication")?;
            if event.operation != bm25::OPERATION {
                continue;
            }
            if event.schema_version != super::super::SCHEMA_VERSION
                || row.key != event.global_commit.to_be_bytes()
                || event.global_commit <= previous_commit
                || event.event_digest != super::super::event_digest(&event)?
            {
                return Err(integrity(
                    "BM25 publication journal ordering or binding differs",
                ));
            }
            previous_commit = event.global_commit;
            budget
                .charge(1, (row.key.len() + row.value.len()) as u64)
                .map_err(budget_error)?;
            let bytes = snapshot
                .get(&self.keyspaces.idempotency, event.request_digest.as_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("accepted BM25 projection receipt is absent"))?;
            if bytes.len() > 8 * 1024 {
                return Err(integrity(
                    "BM25 projection receipt exceeds its metadata bound",
                ));
            }
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
            let receipt: super::super::StoredIdempotency =
                decode(&bytes, "accepted BM25 projection receipt")?;
            let progress: RawProjectionProgress =
                decode(&receipt.response_bytes, "accepted BM25 projection progress")?;
            if receipt.schema_version != super::super::SCHEMA_VERSION
                || receipt.operation != event.operation
                || receipt.request_digest != event.request_digest
                || receipt.response_digest != event.response_digest
                || receipt.response_digest != digest_bytes(&receipt.response_bytes)
                || progress.generation == 0
                || progress.through >= event.workspace_commit
                || progress.projected_sources > progress.through
            {
                return Err(integrity(
                    "accepted BM25 projection receipt binding differs",
                ));
            }
            let identity = (event.workspace_digest, progress.generation);
            if declared.get(&identity).is_some_and(|previous| {
                progress.through < previous.through
                    || progress.projected_sources < previous.projected_sources
            }) {
                return Err(integrity("accepted BM25 projection prefix moved backwards"));
            }
            declared.insert(identity, progress);
        }
        if !declared.is_empty() {
            let bytes = snapshot
                .get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("BM25 native manifest is absent"))?;
            if bytes.len() > super::super::MAX_JSON_BYTES {
                return Err(integrity("BM25 native manifest exceeds its metadata bound"));
            }
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
            let manifest: super::super::Manifest = decode(&bytes, "BM25 native manifest")?;
            super::super::validate_manifest(&manifest, &self.database_id)?;
            if !manifest.features.contains(bm25::FEATURE) {
                return Err(integrity(
                    "accepted BM25 projection format feature is absent",
                ));
            }
        }
        Ok(declared)
    }

    pub(in crate::raw_index) fn validate_raw_bm25_generation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        generation: &Generation,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let Some(profile) = &generation.bm25 else {
            return Ok(());
        };
        profile.validate()?;
        self.require_raw_bm25_feature(snapshot, budget)
    }

    pub(crate) fn accepted_raw_revocations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<Vec<(String, OriginalRevocationReceipt)>> {
        let mut accepted = Vec::new();
        let mut epochs = BTreeMap::<String, u64>::new();
        let mut budget = super::super::retention::audit_budget();
        for entry in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: super::super::StoredEvent = decode(&entry.value, "native revocation event")?;
            match (event.accepted_original_revocation, event.operation.as_str()) {
                (Some(receipt), "original_revocation") => {
                    let epoch = epochs.entry(event.workspace_digest.clone()).or_default();
                    *epoch += 1;
                    if receipt.workspace_commit != event.workspace_commit
                        || receipt.authorization_epoch != *epoch
                        || event.response_digest != digest_bytes(&encode(&receipt)?)
                    {
                        return Err(integrity("accepted original revocation binding is invalid"));
                    }
                    let control =
                        self.verified_capture_control(snapshot, receipt.event_id, &mut budget)?;
                    if digest_bytes(control.receipt.workspace_id.to_string().as_bytes())
                        != event.workspace_digest
                    {
                        return Err(integrity("original revocation crosses workspaces"));
                    }
                    let policy: super::super::StoredObservationPolicy = decode(
                        &snapshot
                            .get(
                                &self.keyspaces.observations_policy,
                                digest_bytes(receipt.event_id.to_string().as_bytes()).as_bytes(),
                            )
                            .map_err(storage_error)?
                            .ok_or_else(|| integrity("revoked original policy missing"))?,
                        "revoked policy",
                    )?;
                    if policy.access.retrievable {
                        return Err(integrity("accepted original revocation was not enforced"));
                    }
                    accepted.push((event.workspace_digest, receipt));
                }
                (None, operation) if operation != "original_revocation" => (),
                _ => {
                    return Err(integrity(
                        "native original revocation reference kind invalid",
                    ));
                }
            }
        }
        Ok(accepted)
    }

    pub(crate) fn raw_revocation_scope_epochs<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<Vec<u8>, u64>> {
        let mut scopes = BTreeMap::new();
        let mut budget = super::super::retention::audit_budget();
        for (workspace, receipt) in self.accepted_raw_revocations(snapshot)? {
            let control = self.verified_capture_control(snapshot, receipt.event_id, &mut budget)?;
            for scope in control.recovery.scope_ids {
                let epoch = scopes
                    .entry(super::super::capture::scope_key(
                        &workspace,
                        &scope.to_string(),
                    ))
                    .or_insert(0);
                *epoch = (*epoch).max(receipt.workspace_commit);
            }
        }
        Ok(scopes)
    }

    pub(crate) fn verify_raw_index_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        self.verify_raw_copy_publications(snapshot)?;
        let bm25_generations = self.accepted_raw_bm25_generations(snapshot)?;
        let dense_generations = self.accepted_dense_generations(snapshot)?;
        let graph_generations = self.accepted_dense_graph_generations(snapshot)?;
        let mut segment_budget = super::super::retention::audit_budget();
        let segment_generations =
            self.accepted_dense_segment_generations(snapshot, &mut segment_budget)?;
        let prefix_generations = self.prefix_base_declarations(snapshot, &mut segment_budget)?;
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"raw/")
            .map_err(storage_error)?;
        let revocations = self.accepted_raw_revocations(snapshot)?;
        if actual.is_empty() && revocations.is_empty() {
            for entry in snapshot
                .scan_prefix(&self.keyspaces.events, b"")
                .map_err(storage_error)?
            {
                let event: super::super::StoredEvent =
                    decode(&entry.value, "native index publication")?;
                if event.operation == "raw_projection"
                    || event.operation == bm25::OPERATION
                    || event.operation == dense::OPERATION
                    || event.operation == dense::graph::OPERATION
                {
                    return Err(integrity("published raw index state is absent"));
                }
            }
            return Ok(());
        }
        let manifest: super::super::Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest missing"))?,
            "native manifest",
        )?;
        if !manifest.features.contains(INDEX_FEATURE) {
            return Err(integrity("raw index format feature missing"));
        }
        let mut expected = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        for (workspace, receipt) in revocations {
            expected.insert(
                revocation_key(&workspace, receipt.authorization_epoch),
                encode(&receipt)?,
            );
            expected.insert(auth_key(&workspace), encode(&receipt.authorization_epoch)?);
        }
        for entry in snapshot
            .scan_prefix(&self.keyspaces.continuous, b"raw/state/")
            .map_err(storage_error)?
        {
            let state: IndexState = decode(&entry.value, "raw index state")?;
            let workspace = std::str::from_utf8(&entry.key[b"raw/state/".len()..])
                .map_err(|_| integrity("raw index workspace invalid"))?;
            let world: super::super::WorkspaceState = decode(
                &snapshot
                    .get(&self.keyspaces.workspace, workspace.as_bytes())
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("raw index workspace is missing"))?,
                "raw index workspace",
            )?;
            let retained = retained_generations(&state)?;
            if (state.retained.is_some() || state.reclaiming.is_some())
                && !manifest.features.contains(GC_FEATURE)
            {
                return Err(integrity("raw reclamation format feature missing"));
            }
            expected.insert(entry.key.clone(), encode(&state)?);
            for number in retained {
                let generation: Generation = self
                    .raw_value(snapshot, &generation_key(workspace, number))?
                    .ok_or_else(|| integrity("retained raw generation missing"))?;
                if generation.number != number
                    || generation.through > world.watermarks.journal
                    || generation
                        .removal_through
                        .is_some_and(|through| through > world.watermarks.journal)
                    || generation.custody_version > super::super::custody::CUSTODY_VERSION
                    || (generation.custody_version != 0
                        && !manifest
                            .features
                            .contains(super::super::custody::CUSTODY_FEATURE))
                    || generation.analyzer != RAW_ANALYZER
                    || generation.authorization_epoch
                        > self.raw_authorization_epoch(snapshot, workspace)?
                    || (generation.removal_through.is_some()
                        && !manifest.features.contains(REMOVAL_FEATURE))
                {
                    return Err(integrity("raw generation binding invalid"));
                }
                let declaration = bm25_generations.get(&(workspace.to_owned(), number));
                if generation.bm25.is_some() != declaration.is_some()
                    || declaration.is_some_and(|progress| {
                        progress.through != generation.through
                            || progress.projected_sources != generation.projected_sources
                    })
                {
                    return Err(integrity(
                        "BM25 generation differs from its accepted projection prefix",
                    ));
                }
                self.validate_raw_bm25_generation(
                    snapshot,
                    &generation,
                    &mut super::super::retention::audit_budget(),
                )?;
                self.validate_dense_declaration(
                    workspace,
                    &generation,
                    dense_generations.get(&(workspace.to_owned(), number)),
                )?;
                self.validate_dense_graph_declaration(
                    workspace,
                    &generation,
                    graph_generations.get(&(workspace.to_owned(), number)),
                )?;
                self.validate_dense_segment_declaration(
                    snapshot,
                    workspace,
                    &generation,
                    segment_generations.get(&(workspace.to_owned(), number)),
                    &mut segment_budget,
                )?;
                let prefix_base = prefix_generations.get(&(workspace.to_owned(), number));
                self.validate_dense_prefix_base_declaration(
                    snapshot,
                    workspace,
                    &generation,
                    prefix_base,
                    &mut segment_budget,
                )?;
                expected.insert(generation_key(workspace, number), encode(&generation)?);
                if state
                    .reclaiming
                    .as_ref()
                    .is_some_and(|job| job.generation == number)
                {
                    // This unreachable generation is being discarded, not
                    // repaired or admitted to queries. Its remaining rows are
                    // opaque garbage; every usable generation still requires
                    // complete reconstruction below. No cursor or restart may
                    // turn this unfinished job back into an active generation.
                    for row in snapshot
                        .scan_prefix(
                            &self.keyspaces.continuous,
                            generation_prefix(workspace, number).as_bytes(),
                        )
                        .map_err(storage_error)?
                    {
                        if row.key[generation_prefix(workspace, number).len()..]
                            .starts_with(b"dense/prefix-base-v2/")
                            && generation.dense_prefix_base.is_none()
                        {
                            return Err(integrity(
                                "reclaiming prefix rows lost their accepted owner seal",
                            ));
                        }
                        if row.key[generation_prefix(workspace, number).len()..]
                            .starts_with(b"dense/graph/segment")
                            && generation.dense_segments.is_none()
                        {
                            return Err(integrity(
                                "reclaiming segment rows lost their accepted directory",
                            ));
                        }
                        if row.key[generation_prefix(workspace, number).len()..]
                            .starts_with(b"dense/graph/")
                            && generation.dense_graph.is_none()
                        {
                            return Err(integrity(
                                "reclaiming graph rows lost their accepted owner seal",
                            ));
                        }
                        if row.key[generation_prefix(workspace, number).len()..]
                            .starts_with(b"bm25/")
                            && generation.bm25.is_none()
                        {
                            return Err(integrity(
                                "reclaiming BM25 rows lost their generation profile",
                            ));
                        }
                        if row.key[generation_prefix(workspace, number).len()..]
                            .starts_with(b"dense/")
                            && generation.dense.is_none()
                        {
                            return Err(integrity(
                                "reclaiming dense rows lost their generation profile",
                            ));
                        }
                        expected.insert(row.key, row.value);
                    }
                    continue;
                }
                if let Some(receipt) = prefix_base {
                    for (key, value) in self.reconstruct_prefix_base_rows(
                        snapshot,
                        workspace,
                        receipt,
                        &mut segment_budget,
                    )? {
                        if expected.insert(key, value).is_some() {
                            return Err(integrity(
                                "prefix reconstruction overlaps another key family",
                            ));
                        }
                    }
                }
                let mut domains = BTreeMap::<String, PolicyDomain>::new();
                let mut bm25_documents = Vec::new();
                let mut dense_reconstructed = generation
                    .dense
                    .as_ref()
                    .map(|profile| dense::DenseManifest::empty(&profile.profile))
                    .transpose()?;
                let mut count = 0;
                let outbox = format!("outbox/{workspace}/");
                for entry in snapshot
                    .scan_prefix(&self.keyspaces.continuous, outbox.as_bytes())
                    .map_err(storage_error)?
                {
                    let work: super::super::capture::CaptureWork =
                        decode(&entry.value, "index verification outbox")?;
                    if work.workspace_commit > generation.through {
                        break;
                    }
                    let mut budget = QueryBudget::new(
                        u64::MAX,
                        u64::MAX,
                        Duration::from_secs(60),
                        QueryCancellation::default(),
                    );
                    if self.source_prepared_at(
                        snapshot,
                        workspace,
                        work.event_id,
                        generation.removal_through,
                        &mut budget,
                    )? {
                        continue;
                    }
                    let document: IndexedOriginal = self
                        .raw_value(snapshot, &doc_key(workspace, number, work.event_id))?
                        .ok_or_else(|| integrity("raw generation lost an accepted original"))?;
                    let original = self.load_captured_original(snapshot, work.event_id)?;
                    let reconstructed = self.build_raw_document(
                        snapshot,
                        &original.event,
                        work.workspace_commit,
                        work.event_digest,
                        &document.policy_domain,
                        &mut budget,
                    )?;
                    if reconstructed != document {
                        return Err(integrity(
                            "raw document differs from its immutable original",
                        ));
                    }
                    let key = domain_key(workspace, number, &document.policy_domain);
                    let labels: PolicyDomain = self
                        .raw_value(snapshot, &key)?
                        .ok_or_else(|| integrity("raw domain labels missing"))?;
                    if generation.bm25.is_some() {
                        bm25_documents.push(self.build_bm25_document(
                            snapshot,
                            &original.event,
                            work.workspace_commit,
                            work.event_digest,
                            &document.policy_domain,
                            bm25::routing_scope_count(&labels.policies)?,
                            &mut budget,
                        )?);
                    }
                    if canonical_digest(&labels.policies)? != document.policy_domain
                        || labels.policies.is_empty()
                        || labels
                            .policies
                            .iter()
                            .any(|policy| digest_bytes(policy.workspace_id.as_bytes()) != workspace)
                    {
                        return Err(integrity("raw domain identity invalid"));
                    }
                    if generation.custody_version == super::super::custody::CUSTODY_VERSION
                        && generation.authorization_epoch
                            == self.raw_authorization_epoch(snapshot, workspace)?
                        && labels.policies
                            != self.stored_custody_policies(snapshot, work.event_id)?
                    {
                        return Err(integrity("raw domain authorization closure differs"));
                    }
                    domains
                        .entry(document.policy_domain.clone())
                        .or_insert(PolicyDomain {
                            policies: labels.policies,
                            first_commit: document.commit,
                        });
                    expected.extend(document_rows(workspace, number, &document)?);
                    if generation
                        .dense
                        .as_ref()
                        .is_some_and(|dense| work.workspace_commit <= dense.through)
                    {
                        let (source, rows) = self.reconstruct_dense_source(
                            snapshot,
                            workspace,
                            &generation,
                            &original.event,
                            work.workspace_commit,
                            work.event_digest,
                            &document.policy_domain,
                            &mut budget,
                        )?;
                        dense_reconstructed
                            .as_mut()
                            .ok_or_else(|| integrity("dense reconstruction profile absent"))?
                            .accept(&source)?;
                        expected.extend(rows);
                    }
                    count += 1;
                }
                if count != generation.projected_sources {
                    return Err(integrity("raw source count differs from captured prefix"));
                }
                if generation.bm25.is_some() {
                    expected.extend(bm25::reconstruct_rows(workspace, number, &bm25_documents)?);
                }
                if let Some(mut reconstructed) = dense_reconstructed {
                    let dense = generation
                        .dense
                        .as_ref()
                        .ok_or_else(|| integrity("dense generation profile absent"))?;
                    reconstructed.through = dense.through;
                    if reconstructed != *dense {
                        return Err(integrity(
                            "dense owner commitment differs from exact source rows",
                        ));
                    }
                    let receipt = dense_generations
                        .get(&(workspace.to_owned(), number))
                        .ok_or_else(|| integrity("dense accepted receipt absent"))?;
                    expected.insert(dense::receipt_key(workspace, number), encode(receipt)?);
                }
                if generation.dense_graph.is_some() {
                    expected.extend(self.reconstruct_dense_graph_rows(
                        snapshot,
                        workspace,
                        &generation,
                        &mut super::super::retention::audit_budget(),
                    )?);
                }
                if generation.dense_segments.is_some() {
                    expected.extend(self.reconstruct_dense_segment_rows(
                        snapshot,
                        workspace,
                        &generation,
                        &mut segment_budget,
                    )?);
                }
                for (id, labels) in domains {
                    for key in domain_eligibility_keys(workspace, number, &id, &labels)? {
                        expected.insert(key, encode(&id)?);
                    }
                    expected.insert(domain_key(workspace, number, &id), encode(&labels)?);
                }
            }
        }
        if actual.len() != expected.len()
            || actual
                .iter()
                .any(|entry| expected.get(&entry.key) != Some(&entry.value))
        {
            return Err(integrity(
                "raw rows differ from reconstructed generations and accepted revocations",
            ));
        }
        Ok(())
    }
}
