//! Observe and authenticate a bounded native GC page before publication.

use super::*;
use crate::encryption::NativeSnapshot;
use contextdb_storage::Entry;

impl NativeService {
    pub(in crate::raw_index) fn observe_raw_copies(
        &self,
        snapshot: &NativeSnapshot,
        workspace_id: &str,
        job: &gc::Reclaiming,
        entries: &[Entry],
        finished: bool,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawCopyWitness> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let manifest_key = generation_key(&workspace, job.generation);
        let manifest = snapshot
            .get(&self.keyspaces.continuous, &manifest_key)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("raw copy generation manifest missing"))?;
        let generation: Generation = decode(&manifest, "raw copy generation")?;
        if generation.number != job.generation {
            return Err(integrity("raw copy generation identity differs"));
        }
        let head = self.global_head(snapshot)?;
        let event: crate::StoredEvent = decode(
            &snapshot
                .get(&self.keyspaces.events, &head.to_be_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("raw copy native head missing"))?,
            "raw copy native event",
        )?;
        if event.global_commit != head || event.event_digest != crate::event_digest(&event)? {
            return Err(integrity("raw copy native head differs"));
        }
        let prefix = generation_prefix(&workspace, job.generation);
        let mut sources = BTreeMap::new();
        let mut documents = BTreeMap::new();
        let mut rows = Vec::new();
        for entry in entries {
            let relative = std::str::from_utf8(&entry.key)
                .ok()
                .and_then(|key| key.strip_prefix(&prefix));
            let (kind, owner) = match relative {
                Some(key) if key.starts_with("doc/") => {
                    let document: IndexedOriginal = decode(&entry.value, "raw copy document")?;
                    (
                        NativeRawCopyKind::Document,
                        Some((document.source.event_id, document.policy_domain)),
                    )
                }
                Some(key) if key.starts_with("route/") => {
                    let domain = key["route/".len()..]
                        .split('/')
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    (
                        NativeRawCopyKind::Route,
                        Some((decode(&entry.value, "raw copy route owner")?, domain)),
                    )
                }
                Some(key) if key.starts_with("domain/") || key.starts_with("eligibility/") => {
                    (NativeRawCopyKind::SharedMetadata, None)
                }
                _ => (NativeRawCopyKind::Unknown, None),
            };
            let source = if let Some((id, domain)) = owner {
                if blake3::Hash::from_hex(&domain).is_err() {
                    return Err(integrity("raw copy policy domain invalid"));
                }
                let document_key = (id, domain.clone());
                if !documents.contains_key(&document_key) {
                    let control = self.verified_capture_control(snapshot, id, budget)?;
                    if control.receipt.workspace_id.to_string() != workspace_id
                        || control.receipt.workspace_commit > generation.through
                        || generation.analyzer != RAW_ANALYZER
                    {
                        return Err(integrity("raw copy source or generation differs"));
                    }
                    let original = control
                        .original
                        .ok_or_else(|| integrity("raw copy source was pruned before its index"))?;
                    let length = RawSource::from(&original).byte_length.unwrap_or_default();
                    budget.charge(1, length).map_err(budget_error)?;
                    let document = self.build_raw_document(
                        snapshot,
                        &original,
                        control.receipt.workspace_commit,
                        control.receipt.event_digest,
                        &domain,
                        budget,
                    )?;
                    let expected = document_rows(&workspace, job.generation, &document)?;
                    for (key, value) in &expected {
                        budget
                            .charge(1, (key.len() + value.len()) as u64)
                            .map_err(budget_error)?;
                    }
                    sources.insert(
                        id,
                        NativeRawSourceControl {
                            capture_commit: control.receipt.workspace_commit,
                            event_digest: control.receipt.event_digest,
                            control_digest: control.control_digest,
                        },
                    );
                    documents.insert(document_key.clone(), expected);
                }
                if documents[&document_key].get(&entry.key) != Some(&entry.value) {
                    return Err(integrity("raw copy differs from its source-derived row"));
                }
                Some(id)
            } else {
                None
            };
            rows.push(self.observe_raw_row(snapshot, entry, kind, source, budget)?);
        }
        if finished {
            rows.push(self.observe_raw_row(
                snapshot,
                &Entry {
                    key: manifest_key,
                    value: manifest.clone(),
                },
                NativeRawCopyKind::Manifest,
                None,
                budget,
            )?);
        }
        let witness = NativeRawCopyWitness {
            database_id: self.database_id.clone(),
            workspace_id: workspace_id.into(),
            native_commit: head,
            native_event_digest: event.event_digest,
            generation: job.generation,
            generation_digest: digest_bytes(&manifest),
            removed_before: job.removed_rows,
            previous: job.copies.clone(),
            finished,
            sources,
            rows,
        };
        witness.validate(&digest_bytes(self.database_id.as_bytes()))?;
        budget
            .charge(1, encode(&witness)?.len() as u64)
            .map_err(budget_error)?;
        Ok(witness)
    }

    fn observe_raw_row(
        &self,
        snapshot: &NativeSnapshot,
        entry: &Entry,
        kind: NativeRawCopyKind,
        source: Option<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawCopyObservation> {
        let version = if let Some(keys) = &self.engine.keys {
            let ciphertext = snapshot
                .inner
                .get(&self.keyspaces.continuous, &entry.key)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("observed raw ciphertext absent"))?;
            budget
                .charge(1, ciphertext.len() as u64)
                .map_err(budget_error)?;
            Some(crate::encryption::observe_value_version(
                keys,
                &self.keyspaces.continuous,
                &entry.key,
                &ciphertext,
                &entry.value,
            )?)
        } else {
            None
        };
        Ok(NativeRawCopyObservation {
            address_digest: crate::encryption::address(&self.keyspaces.continuous, &entry.key),
            value_digest: digest_bytes(&entry.value),
            kind,
            source,
            version,
        })
    }
}
