use super::*;

impl NativeService {
    pub(in crate::record_journal) fn prepared_record_controls<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        source: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, RecordControl>> {
        let global: u64 = decode(
            &required_bytes(
                snapshot,
                &self.keyspaces.continuous,
                &group_key(source.global_commit),
                budget,
            )?,
            "prepared record group locator",
        )?;
        let event = self.recovery_global_event(snapshot, global, budget)?;
        self.verify_prepared_group(snapshot, &event, source, budget)
    }

    pub(in crate::record_journal) fn verify_record_control_preparations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<BTreeMap<Vec<u8>, RecordControl>> {
        let mut budget = QueryBudget::new(
            u64::MAX,
            u64::MAX,
            std::time::Duration::from_secs(3600),
            Default::default(),
        );
        let mut expected = BTreeSet::new();
        let mut controls = BTreeMap::new();
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&row.value, "record preparation journal")?;
            let Some(publication) = declaration(&event)? else {
                continue;
            };
            if row.key != event.global_commit.to_be_bytes() {
                return Err(integrity("record preparation journal address differs"));
            }
            let (_, source) = self.recovery_event(
                snapshot,
                &event.workspace_digest,
                publication.source_commit,
                &mut budget,
            )?;
            if !expected.insert(group_key(source.global_commit)) {
                return Err(integrity("duplicate accepted record preparation"));
            }
            for (key, control) in
                self.verify_prepared_group(snapshot, &event, &source, &mut budget)?
            {
                expected.insert(prepared_key(&key)?);
                if controls.insert(key, control).is_some() {
                    return Err(integrity("duplicate prepared record control"));
                }
            }
        }
        if self.raw_manifest(snapshot)?.features.contains(FEATURE) != !expected.is_empty() {
            return Err(integrity(
                "record preparation feature differs from accepted history",
            ));
        }
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, PREFIX)
            .map_err(storage_error)?;
        if actual.len() != expected.len() || actual.iter().any(|row| !expected.contains(&row.key)) {
            return Err(integrity("missing or orphaned record preparation controls"));
        }
        Ok(controls)
    }

    pub(super) fn verify_prepared_group<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
        source: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, RecordControl>> {
        let publication = declaration(event)?
            .ok_or_else(|| integrity("record preparation declaration absent"))?;
        self.require_legacy_record_group(snapshot, source)
            .map_err(|_| integrity("prepared group is not pre-control history"))?;
        if !self.raw_manifest(snapshot)?.features.contains(FEATURE)
            || source.global_commit != publication.source_global
            || source.workspace_commit != publication.source_commit
            || source.event_digest != publication.source_event_digest
            || source.workspace_digest != event.workspace_digest
            || self
                .recovery_event(
                    snapshot,
                    &event.workspace_digest,
                    event.workspace_commit,
                    budget,
                )?
                .1
                != *event
            || source.accepted_records.len() != publication.controls.len()
            || decode::<u64>(
                &required_bytes(
                    snapshot,
                    &self.keyspaces.continuous,
                    &group_key(source.global_commit),
                    budget,
                )?,
                "record preparation locator",
            )? != event.global_commit
        {
            return Err(integrity("prepared group differs from original acceptance"));
        }
        let mut controls = BTreeMap::new();
        let mut total = 0usize;
        for (original, reference) in source.accepted_records.iter().zip(&publication.controls) {
            let mut unextended = reference.clone();
            let digest = unextended
                .control_digest
                .take()
                .ok_or_else(|| integrity("prepared record commitment absent"))?;
            if unextended != *original {
                return Err(integrity(
                    "prepared record references differ from original acceptance",
                ));
            }
            let bytes = required_bytes(
                snapshot,
                &self.keyspaces.continuous,
                &prepared_key(&reference.key)?,
                budget,
            )?;
            total = total.saturating_add(bytes.len());
            if total > MAX_BYTES || digest_bytes(&bytes) != digest {
                return Err(integrity(
                    "prepared control differs from its accepted commitment",
                ));
            }
            let control: RecordControl = decode(&bytes, "prepared record control")?;
            control.validate_binding(source, reference)?;
            if controls.insert(reference.key.clone(), control).is_some() {
                return Err(integrity("duplicate prepared mutation"));
            }
        }
        Ok(controls)
    }
}
