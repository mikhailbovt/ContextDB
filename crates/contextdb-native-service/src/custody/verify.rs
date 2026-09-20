//! Administrative reconstruction, separate from policy-before-content reads.

use super::*;

impl NativeService {
    pub(crate) fn require_capture_custody_metadata<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &EventEnvelope,
    ) -> ServiceResult<()> {
        let record = self
            .custody_record(snapshot, event.event_id)
            .map_err(|_| integrity("accepted capture custody is missing"))?;
        let workspace = digest_bytes(event.workspace_id.to_string().as_bytes());
        if record.workspace != workspace || self.custody_state(snapshot, &workspace)?.is_none() {
            return Err(integrity("accepted capture custody workspace is absent"));
        }
        Ok(())
    }

    pub(crate) fn verify_custody_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"custody/")
            .map_err(storage_error)?;
        if actual.is_empty() {
            return Ok(());
        }
        let manifest: super::super::Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "custody format",
        )?;
        if !manifest.features.contains(CUSTODY_FEATURE) {
            return Err(integrity("custody format feature missing"));
        }
        let mut expected = BTreeSet::new();
        for entry in snapshot
            .scan_prefix(&self.keyspaces.continuous, b"custody/state/")
            .map_err(storage_error)?
        {
            let workspace = std::str::from_utf8(&entry.key[b"custody/state/".len()..])
                .map_err(|_| integrity("custody workspace key invalid"))?;
            let state = self
                .custody_state(snapshot, workspace)?
                .ok_or_else(|| integrity("custody state absent"))?;
            let world: super::super::WorkspaceState = decode(
                &snapshot
                    .get(&self.keyspaces.workspace, workspace.as_bytes())
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("custody workspace absent"))?,
                "custody workspace",
            )?;
            if state.through > world.watermarks.journal {
                return Err(integrity("custody prefix exceeds accepted history"));
            }
            expected.insert(entry.key.clone());
            let mut reconstructed = BTreeMap::new();
            let mut last = 0;
            for entry in snapshot
                .scan_prefix(
                    &self.keyspaces.continuous,
                    format!("outbox/{workspace}/").as_bytes(),
                )
                .map_err(storage_error)?
            {
                let work: super::super::capture::CaptureWork =
                    decode(&entry.value, "custody outbox")?;
                let original = self.load_captured_original(snapshot, work.event_id)?;
                let key = record_key(work.event_id);
                if work.workspace_commit <= last
                    || original.receipt.workspace_commit != work.workspace_commit
                    || original.receipt.event_digest != work.event_digest
                    || digest_bytes(original.event.workspace_id.to_string().as_bytes()) != workspace
                {
                    return Err(integrity("custody capture order or workspace differs"));
                }
                last = work.workspace_commit;
                if work.workspace_commit <= state.through {
                    let record = self.build_custody_record(
                        snapshot,
                        &original.event,
                        work.workspace_commit,
                        &reconstructed,
                        None,
                    )?;
                    if self.custody_record(snapshot, work.event_id)? != record {
                        return Err(integrity(
                            "materialized custody differs from original inputs",
                        ));
                    }
                    expected.insert(key);
                    reconstructed.insert(work.event_id, record);
                } else if snapshot
                    .get(&self.keyspaces.continuous, &key)
                    .map_err(storage_error)?
                    .is_some()
                {
                    // An unfinished migration may still hold old restrictions.
                    // They are unreachable behind the workspace barrier; exact
                    // current-label reconstruction is mandatory before admission.
                    let record = self.custody_record(snapshot, work.event_id)?;
                    if record.event_digest != work.event_digest
                        || record.commit != work.workspace_commit
                        || record.inputs != inputs(&original.event)?
                        || record.workspace != workspace
                    {
                        return Err(integrity(
                            "pending custody identity differs from its original",
                        ));
                    }
                    expected.insert(key);
                }
            }
            if !state.pending && last > state.through {
                return Err(integrity("custody admission omits accepted captures"));
            }
        }
        if actual.len() != expected.len()
            || actual.iter().any(|entry| !expected.contains(&entry.key))
        {
            return Err(integrity(
                "custody rows lack an accepted original or workspace",
            ));
        }
        Ok(())
    }
}
