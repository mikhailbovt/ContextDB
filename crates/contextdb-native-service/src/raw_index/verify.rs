//! Administrative reconstruction of rebuildable rows and accepted revocations.

use std::time::Duration;

use contextdb_recall::QueryCancellation;

use super::*;

impl NativeService {
    pub(crate) fn accepted_raw_revocations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<Vec<(String, OriginalRevocationReceipt)>> {
        let mut accepted = Vec::new();
        let mut epochs = BTreeMap::<String, u64>::new();
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
                    let original = self.load_captured_original(snapshot, receipt.event_id)?;
                    if digest_bytes(original.event.workspace_id.to_string().as_bytes())
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
        for (workspace, receipt) in self.accepted_raw_revocations(snapshot)? {
            let original = self.load_captured_original(snapshot, receipt.event_id)?;
            for scope in original.event.scope_ids {
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
                if event.operation == "raw_projection" {
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
            if state.next == 0
                || state.next > MAX_GENERATIONS
                || state.active == state.building
                || state
                    .active
                    .into_iter()
                    .chain(state.building)
                    .any(|number| number == 0 || number > state.next)
            {
                return Err(integrity("raw index generation state invalid"));
            }
            expected.insert(entry.key.clone(), encode(&state)?);
            for number in 1..=state.next {
                let generation: Generation = self
                    .raw_value(snapshot, &generation_key(workspace, number))?
                    .ok_or_else(|| integrity("retained raw generation missing"))?;
                if generation.number != number
                    || generation.analyzer != RAW_ANALYZER
                    || generation.authorization_epoch
                        > self.raw_authorization_epoch(snapshot, workspace)?
                {
                    return Err(integrity("raw generation binding invalid"));
                }
                expected.insert(generation_key(workspace, number), encode(&generation)?);
                let mut domains = BTreeMap::<String, PolicyDomain>::new();
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
                    let document: IndexedOriginal = self
                        .raw_value(snapshot, &doc_key(workspace, number, work.event_id))?
                        .ok_or_else(|| integrity("raw generation lost an accepted original"))?;
                    let original = self.load_captured_original(snapshot, work.event_id)?;
                    let mut budget = QueryBudget::new(
                        u64::MAX,
                        u64::MAX,
                        Duration::from_secs(60),
                        QueryCancellation::default(),
                    );
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
                    if canonical_digest(&labels.policies)? != document.policy_domain
                        || labels.policies.is_empty()
                        || labels
                            .policies
                            .iter()
                            .any(|policy| digest_bytes(policy.workspace_id.as_bytes()) != workspace)
                    {
                        return Err(integrity("raw domain identity invalid"));
                    }
                    if generation.authorization_epoch
                        == self.raw_authorization_epoch(snapshot, workspace)?
                        && labels.policies
                            != self.capture_index_policies(snapshot, work.event_id)?
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
                    count += 1;
                }
                if count != generation.projected_sources {
                    return Err(integrity("raw source count differs from captured prefix"));
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
