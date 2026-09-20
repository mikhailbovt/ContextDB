//! Exact closure and per-revision origins for atomic record mutation groups.

use super::*;

mod correction;
use correction::Correction;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordWriteGroup {
    primary: String,
    inputs: BTreeMap<ObservationId, ContentDigest>,
    pub(super) previous: Vec<RecordSourceControl>,
    pub(super) scopes: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    correction: Option<Correction>,
}

pub(crate) struct GroupRequest<'a> {
    operation: &'a str,
    digest: &'a str,
    idempotency_key: &'a [u8],
    primary: &'a str,
    correction: Option<Correction>,
}

impl<'a> GroupRequest<'a> {
    pub(crate) fn new(
        operation: &'a str,
        digest: &'a str,
        idempotency_key: &'a [u8],
        primary: &'a str,
    ) -> Self {
        Self {
            operation,
            digest,
            idempotency_key,
            primary,
            correction: None,
        }
    }

    pub(crate) fn correcting(mut self, target: &StoredPolicy, rewires: &[HierarchyRewire]) -> Self {
        self.correction = Some(Correction::new(target, rewires));
        self
    }
}

impl NativeService {
    pub(crate) fn charge_source_record_body<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        policy: &StoredPolicy,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget.charge(1, 0).map_err(raw_index::budget_error)?;
        let bytes = snapshot
            .get(
                &self.keyspaces.content_history,
                &history_key(&policy.record_digest, policy.revision),
            )
            .map_err(storage_error)?
            .ok_or_else(|| integrity("source-aware record body absent"))?;
        budget
            .charge(0, bytes.len() as u64)
            .map_err(raw_index::budget_error)
    }

    // Structural writes require a complete authorized graph in the affected
    // access domain. Query-time omission of unavailable edges is not safe here.
    pub(crate) fn source_graph_policies<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        principal: &RequestContext,
        global: u64,
        access: &AccessPolicy,
        family: AuthorizedPolicyFamily,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<String, StoredPolicy>> {
        self.require_suppression_current(
            snapshot,
            &digest_bytes(principal.workspace_id.as_bytes()),
        )?;
        let prefix = policy_route_prefix(&principal.workspace_id);
        let mut after: Option<Vec<u8>> = None;
        let mut selected = BTreeMap::new();
        loop {
            budget.check().map_err(raw_index::budget_error)?;
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.policy_route,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: after.as_deref(),
                        max_entries: SCAN_PAGE_ENTRIES,
                        max_bytes: SCAN_PAGE_BYTES,
                    },
                )
                .map_err(storage_error)?;
            for row in page.entries {
                budget
                    .charge(1, row.value.len() as u64)
                    .map_err(raw_index::budget_error)?;
                let policy: StoredPolicy = decode(&row.value, "source-aware graph policy")?;
                validate_stored_policy(&policy)?;
                if policy.access != *access
                    || !visible_at(&policy, global)
                    || policy.lifecycle != MemoryLifecycle::Active
                    || !family.accepts(policy.kind)
                    || !matches!(
                        policy.kind,
                        MemoryRecordKind::Edge | MemoryRecordKind::Candidate
                    )
                {
                    continue;
                }
                if !policy_allows(principal, &policy.access) {
                    return Err(permission_denied());
                }
                self.authorize_record_sources(snapshot, principal, &policy)?;
                selected.insert(policy.record_digest.clone(), policy);
                if selected.len() > MAX_AUTHORIZED_CANDIDATES {
                    return Err(exhausted("source-aware graph exceeds the service bound"));
                }
            }
            let Some(next) = page.continuation else {
                break;
            };
            if after.as_ref().is_some_and(|old| &next <= old) {
                return Err(integrity("source-aware graph cursor did not advance"));
            }
            after = Some(next);
        }
        Ok(selected)
    }

    pub(crate) fn stage_record_group<T: WriteTransaction>(
        &self,
        tx: &mut T,
        frame: &CommitFrame,
        request: GroupRequest<'_>,
        prepared: PreparedWrite,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let refs = self.accepted_record_mutations(tx, frame)?;
        let records = self.record_group_records(
            tx,
            frame.global_commit,
            &frame.workspace_digest,
            &refs,
            budget,
        )?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("record source authority absent"))?;
        let mut previous = Vec::new();
        for record in &records {
            let id = digest_bytes(record.document.id.as_bytes());
            if record.transaction_to.is_some() {
                let entry = ledger
                    .retained_record_sources(&frame.workspace_digest, &id, record.revision)?
                    .ok_or_else(|| {
                        ServiceError::new(
                            ErrorCode::EvidenceRequired,
                            "copied record has no retained origins",
                            false,
                        )
                    })?;
                previous.push(entry.record_control()?.clone());
            } else if (record.revision == 1
                && ledger.record_identity_retained(&frame.workspace_digest, &id)?)
                || ledger
                    .retained_record_sources(&frame.workspace_digest, &id, record.revision)?
                    .is_some()
            {
                return Err(invalid(
                    "record revision is reserved by retained provenance",
                ));
            }
        }
        let group = RecordWriteGroup {
            primary: digest_bytes(request.primary.as_bytes()),
            inputs: prepared.sources,
            previous,
            scopes: records
                .iter()
                .flat_map(|record| record.document.access.scopes.iter().cloned())
                .collect(),
            correction: request.correction,
        };
        let origins = group.origins(
            request.operation,
            frame.global_commit,
            &frame.workspace_digest,
            &records,
        )?;
        let intent = RecordWriteIntent {
            global_commit: frame.global_commit,
            workspace: frame.workspace_digest.clone(),
            request_digest: request.digest.into(),
            idempotency_key: request.idempotency_key.into(),
            records: refs,
            origins,
            group: Some(group),
        };
        let bytes = encode(&intent)?;
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(exhausted("record source intent exceeds its bounded group"));
        }
        budget
            .charge(1, bytes.len() as u64)
            .map_err(raw_index::budget_error)?;
        self.enable_capture_extension(tx, WRITE_FEATURE)?;
        self.enable_capture_extension(tx, GROUP_FEATURE)?;
        if request.operation == CORRECT {
            self.enable_capture_extension(tx, CORRECTION_FEATURE)?;
        }
        tx.put(
            &self.keyspaces.continuous,
            intent_key(frame.global_commit),
            bytes,
        )
        .map_err(storage_error)
    }

    fn record_group_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        global: u64,
        workspace: &str,
        refs: &[record_journal::RecordMutationRef],
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<MemoryRecord>> {
        if refs.is_empty() || refs.len() > record_journal::MAX_WRITES {
            return Err(integrity("record group exceeds its mutation bound"));
        }
        let mut records = Vec::new();
        let mut total = 0usize;
        let mut keys = BTreeSet::new();
        for reference in refs {
            let bytes = snapshot
                .get(&self.keyspaces.continuous, &reference.key)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("record group mutation absent"))?;
            budget
                .charge(1, bytes.len() as u64)
                .map_err(raw_index::budget_error)?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| exhausted("record group byte counter overflow"))?;
            if total > record_journal::MAX_BYTES {
                return Err(exhausted("record group exceeds its byte bound"));
            }
            let record: MemoryRecord = decode(&bytes, "source-aware group mutation")?;
            validate_stored_policy(&policy_for(&record)?)?;
            if reference.digest != digest_bytes(&bytes)
                || reference.key
                    != format!(
                        "semantic/record/{global:020}/{}/{:010}",
                        digest_bytes(record.document.id.as_bytes()),
                        record.revision
                    )
                    .as_bytes()
                || digest_bytes(record.document.access.workspace_id.as_bytes()) != workspace
                || !keys.insert(reference.key.clone())
                || record.transaction_to.unwrap_or(record.transaction_from) != global
                || (record.transaction_to.is_some() && record.transaction_from >= global)
            {
                return Err(integrity("record group mutation binding differs"));
            }
            records.push(record);
        }
        Ok(records)
    }

    pub(super) fn verified_record_group<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
        intent: &RecordWriteIntent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let group = intent
            .group
            .as_ref()
            .ok_or_else(|| integrity("record group metadata absent"))?;
        let records = self.record_group_records(
            snapshot,
            event.global_commit,
            &event.workspace_digest,
            &intent.records,
            budget,
        )?;
        if group.origins(
            &event.operation,
            event.global_commit,
            &event.workspace_digest,
            &records,
        )? != intent.origins
        {
            return Err(integrity("record group omits copied content origins"));
        }
        for (id, digest) in &group.inputs {
            let source = self.verified_capture_control(snapshot, *id, budget)?;
            let policy: StoredObservationPolicy = decode(
                &snapshot
                    .get(
                        &self.keyspaces.observations_policy,
                        digest_bytes(id.to_string().as_bytes()).as_bytes(),
                    )
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("record group input policy absent"))?,
                "record group input policy",
            )?;
            if source.control_digest != *digest
                || policy.accepted_global_commit >= event.global_commit
                || digest_bytes(source.receipt.workspace_id.to_string().as_bytes())
                    != event.workspace_digest
            {
                return Err(integrity(
                    "record group input does not precede its accepted mutation",
                ));
            }
        }
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("record source authority absent"))?;
        for prior in &group.previous {
            let retained = ledger
                .retained_record_sources(
                    &event.workspace_digest,
                    &prior.record_digest,
                    prior.revision,
                )?
                .ok_or_else(|| integrity("record group predecessor origins absent"))?;
            if retained.record_control()? != prior {
                return Err(integrity("record group predecessor origins differ"));
            }
        }
        for control in intent.origins.iter().chain(&group.previous) {
            if snapshot
                .get(
                    &self.keyspaces.policy_history,
                    &history_key(&control.record_digest, control.revision),
                )
                .map_err(storage_error)?
                .is_none()
            {
                return Err(integrity("record group lost a revision projection"));
            }
            self.verify_local_record_origin(snapshot, control, budget)?;
        }
        Ok(())
    }
}

impl RecordWriteGroup {
    pub(super) fn is_correction(&self) -> bool {
        self.correction.is_some()
    }

    pub(super) fn validate_proposal_response(
        &self,
        response: &ProposeMemoryResponse,
        intent: &RecordWriteIntent,
    ) -> ServiceResult<()> {
        let edges: BTreeSet<_> = response
            .candidate_edge_ids
            .iter()
            .map(|id| digest_bytes(id.as_bytes()))
            .collect();
        let expected: BTreeSet<_> = intent
            .origins
            .iter()
            .filter(|control| control.revision == 1 && control.record_digest != self.primary)
            .map(|control| control.record_digest.clone())
            .collect();
        if response.canonical
            || response.proposal_state != contextdb_service::CandidateProposalState::Quarantined
            || digest_bytes(response.candidate_id.as_bytes()) != self.primary
            || edges.len() != response.candidate_edge_ids.len()
            || edges != expected
        {
            return Err(integrity(
                "proposal retry response differs from its accepted group",
            ));
        }
        Ok(())
    }

    fn origins(
        &self,
        operation: &str,
        global: u64,
        workspace: &str,
        records: &[MemoryRecord],
    ) -> ServiceResult<Vec<RecordSourceControl>> {
        if !matches!(operation, PROPOSE | RETRACT | CORRECT)
            || (operation == CORRECT) != self.is_correction()
            || !(1..=64).contains(&self.inputs.len())
            || blake3::Hash::from_hex(&self.primary).is_err()
            || self.previous.len() > record_journal::MAX_WRITES
            || self.scopes
                != records
                    .iter()
                    .flat_map(|record| record.document.access.scopes.iter().cloned())
                    .collect()
        {
            return Err(integrity("record group declaration is invalid"));
        }
        let mut closed = BTreeMap::new();
        let mut births = BTreeMap::new();
        for record in records {
            let destination = if record.transaction_to.is_some() {
                &mut closed
            } else {
                &mut births
            };
            if destination
                .insert(identity(&record.document.id, record.revision), record)
                .is_some()
            {
                return Err(integrity("record group repeats a revision"));
            }
        }
        let prior: BTreeMap<_, _> = self
            .previous
            .iter()
            .map(|control| ((control.record_digest.clone(), control.revision), control))
            .collect();
        if prior.len() != self.previous.len() || prior.len() != closed.len() {
            return Err(integrity("record group predecessor closure differs"));
        }
        for (key, old) in &closed {
            let control = prior
                .get(key)
                .ok_or_else(|| integrity("closed record has no bound predecessor"))?;
            control.validate()?;
            let mut birth = (*old).clone();
            birth.transaction_to = None;
            if control.workspace != workspace
                || control.transaction_from != birth.transaction_from
                || control.birth_digest != canonical_digest(&birth)?
                || control.document_digest != canonical_digest(&birth.document)?
                || control.scopes != birth.document.access.scopes
            {
                return Err(integrity("closed record differs from its retained birth"));
            }
        }
        let primary: Vec<_> = births
            .values()
            .filter(|record| digest_bytes(record.document.id.as_bytes()) == self.primary)
            .copied()
            .collect();
        if primary.len() != 1 {
            return Err(integrity("record group has no unique primary birth"));
        }
        self.validate_shape(operation, primary[0], &closed, &births)?;
        let mut origins = Vec::new();
        for ((id, revision), record) in &births {
            let mut sources = self.inputs.clone();
            let mut copied = self
                .correction
                .as_ref()
                .and_then(|correction| correction.rewires.get(id));
            if *revision > 1 {
                let key = (id.clone(), revision - 1);
                let old = closed
                    .get(&key)
                    .ok_or_else(|| integrity("copied revision lacks its atomic closure"))?;
                if old.document.lifecycle != MemoryLifecycle::Active {
                    return Err(integrity("copied predecessor is not active"));
                }
                let mut expected = old.document.clone();
                expected.lifecycle = if operation == PROPOSE {
                    MemoryLifecycle::Superseded
                } else {
                    MemoryLifecycle::Retracted
                };
                if expected != record.document {
                    return Err(integrity("copied revision changed its predecessor body"));
                }
                copied = prior.get_key_value(&key).map(|(key, _)| key);
            }
            if let Some(key) = copied {
                let previous = prior
                    .get(key)
                    .ok_or_else(|| integrity("copied edge has no bound predecessor"))?;
                for (source, digest) in &previous.sources {
                    if sources
                        .insert(*source, *digest)
                        .is_some_and(|previous| previous != *digest)
                    {
                        return Err(integrity("record group input control changed"));
                    }
                }
            }
            let control = RecordSourceControl {
                workspace: workspace.into(),
                record_digest: id.clone(),
                revision: *revision,
                transaction_from: global,
                birth_digest: canonical_digest(record)?,
                document_digest: canonical_digest(&record.document)?,
                scopes: record.document.access.scopes.clone(),
                sources,
            };
            control.validate()?;
            origins.push(control);
        }
        Ok(origins)
    }

    fn validate_shape(
        &self,
        operation: &str,
        primary: &MemoryRecord,
        closed: &BTreeMap<(String, u32), &MemoryRecord>,
        births: &BTreeMap<(String, u32), &MemoryRecord>,
    ) -> ServiceResult<()> {
        if operation == CORRECT {
            return self
                .correction
                .as_ref()
                .ok_or_else(|| integrity("correction mapping absent"))?
                .validate_shape(primary, closed, births);
        }
        if operation == RETRACT {
            if births.len() != 1
                || primary.revision <= 1
                || primary.document.lifecycle != MemoryLifecycle::Retracted
            {
                return Err(integrity("retraction group has an invalid successor"));
            }
            for old in closed.values() {
                if old.document.id != primary.document.id
                    && (!managed_edge(&old.document)
                        || !incident(&old.document, &primary.document.id))
                {
                    return Err(integrity("retraction group closes an unrelated record"));
                }
            }
            return Ok(());
        }
        if primary.revision != 1
            || primary.document.kind != MemoryRecordKind::Candidate
            || candidate_role(&primary.document) != Some(CANDIDATE_MEMORY_ROLE)
            || primary.document.lifecycle != MemoryLifecycle::Active
        {
            return Err(integrity(
                "proposal group has an invalid quarantined candidate",
            ));
        }
        let predecessors: BTreeSet<_> = closed
            .values()
            .filter(|record| candidate_role(&record.document) == Some(CANDIDATE_MEMORY_ROLE))
            .map(|record| record.document.id.clone())
            .collect();
        if primary.document.links.supersedes != predecessors {
            return Err(integrity("proposal supersession closure differs"));
        }
        for old in closed.values() {
            if old.document.kind != MemoryRecordKind::Candidate
                || old.document.lifecycle != MemoryLifecycle::Active
            {
                return Err(integrity(
                    "proposal closes a noncandidate or inactive revision",
                ));
            }
            if candidate_role(&old.document) == Some(CANDIDATE_MEMORY_ROLE) {
                let revision = old
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| exhausted("candidate revision overflow"))?;
                if !births.contains_key(&identity(&old.document.id, revision)) {
                    return Err(integrity("superseded candidate lacks its copied revision"));
                }
            } else if candidate_role(&old.document) != Some(CANDIDATE_EDGE_ROLE)
                || !predecessors.iter().any(|id| incident(&old.document, id))
            {
                return Err(integrity("proposal closes an unrelated candidate edge"));
            }
        }
        for record in births.values() {
            if record.document.id == primary.document.id || record.revision > 1 {
                continue;
            }
            let source = record
                .document
                .links
                .source
                .as_deref()
                .ok_or_else(|| integrity("candidate edge source absent"))?;
            if record.document.kind != MemoryRecordKind::Candidate
                || candidate_role(&record.document) != Some(CANDIDATE_EDGE_ROLE)
                || record.document.lifecycle != MemoryLifecycle::Active
                || record.document.links.predicate.as_deref()
                    != Some(CANDIDATE_HIERARCHY_PARENT_PREDICATE)
                || record.document.links.target.as_deref() != Some(&primary.document.id)
                || record.document.id != candidate_hierarchy_edge_id(source, &primary.document.id)?
            {
                return Err(integrity("proposal creates an unrelated candidate edge"));
            }
        }
        Ok(())
    }
}

fn identity(id: &str, revision: u32) -> (String, u32) {
    (digest_bytes(id.as_bytes()), revision)
}
fn incident(document: &MemoryDocument, id: &str) -> bool {
    document.links.source.as_deref() == Some(id) || document.links.target.as_deref() == Some(id)
}
fn managed_edge(document: &MemoryDocument) -> bool {
    (document.kind == MemoryRecordKind::Edge
        && document.links.predicate.as_deref() == Some(HIERARCHY_PARENT_PREDICATE))
        || (document.kind == MemoryRecordKind::Candidate
            && candidate_role(document) == Some(CANDIDATE_EDGE_ROLE))
}
