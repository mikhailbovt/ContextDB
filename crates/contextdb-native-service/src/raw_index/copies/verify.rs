//! Bind accepted GC progress to its independently retained observations.

use super::*;

impl NativeService {
    pub(in crate::raw_index) fn verify_raw_copy_publications<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        let mut latest = BTreeMap::<(String, u64), RawReclaimProgress>::new();
        let mut budget = crate::retention::audit_budget();
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: crate::StoredEvent = decode(&row.value, "raw copy publication")?;
            let progress = match (&event.accepted_raw_reclamation, event.operation.as_str()) {
                (Some(progress), "raw_reclamation_with_copies") => progress,
                (None, operation) if operation != "raw_reclamation_with_copies" => continue,
                _ => return Err(integrity("raw copy publication kind differs")),
            };
            let receipt = progress
                .copies
                .as_ref()
                .ok_or_else(|| integrity("raw reclamation witness reference absent"))?;
            let ledger = self
                .suppression
                .as_ref()
                .ok_or_else(|| integrity("raw copy authority absent"))?;
            let witness =
                ledger.read_raw_copy_witness(receipt, &event.workspace_digest, &mut budget)?;
            let identity = (event.workspace_digest.clone(), witness.generation);
            let previous = latest.get(&identity);
            if witness.native_commit.checked_add(1) != Some(event.global_commit)
                || event.previous_event_digest.as_ref() != Some(&witness.native_event_digest)
                || progress.generation != Some(witness.generation)
                || u64::from(progress.removed_rows) != witness.row_count()
                || witness.removed_before.checked_add(witness.row_count())
                    != Some(progress.total_removed_rows)
                || progress.finished != witness.finished
                || progress.retained_generations > MAX_GENERATIONS as u32
                || witness.previous.as_ref() != previous.and_then(|prior| prior.copies.as_ref())
                || previous.is_some_and(|prior| {
                    prior.finished || prior.total_removed_rows != witness.removed_before
                })
                || event.response_digest != digest_bytes(&encode(progress)?)
                || event.request_digest
                    != canonical_digest(&(&event.workspace_digest, event.global_commit, progress))?
            {
                return Err(integrity(
                    "raw copy observation differs from native reclamation",
                ));
            }
            let manifest: crate::Manifest = decode(
                &snapshot
                    .get(&self.keyspaces.meta, crate::META_MANIFEST_KEY)
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("raw copy format manifest absent"))?,
                "raw copy format",
            )?;
            if !manifest.features.contains(COPY_FEATURE) {
                return Err(integrity("raw copy format feature absent"));
            }
            latest.insert(identity, progress.clone());
        }
        for row in snapshot
            .scan_prefix(&self.keyspaces.continuous, b"raw/state/")
            .map_err(storage_error)?
        {
            let state: IndexState = decode(&row.value, "raw copy index state")?;
            if let Some(job) = state.reclaiming {
                let workspace = std::str::from_utf8(&row.key[b"raw/state/".len()..])
                    .map_err(|_| integrity("raw copy workspace key invalid"))?;
                let prior = latest.remove(&(workspace.to_owned(), job.generation));
                if job.copies.as_ref()
                    != prior.as_ref().and_then(|progress| progress.copies.as_ref())
                    || prior.as_ref().is_some_and(|progress| {
                        progress.finished || progress.total_removed_rows != job.removed_rows
                    })
                {
                    return Err(integrity(
                        "raw reclamation state lost its accepted copy witness",
                    ));
                }
            }
        }
        if latest.values().any(|progress| !progress.finished) {
            return Err(integrity("unfinished raw reclamation lost its native job"));
        }
        Ok(())
    }
}
