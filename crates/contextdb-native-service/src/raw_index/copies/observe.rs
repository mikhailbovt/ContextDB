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
        let (sources, mut rows) =
            self.observe_raw_generation_rows(snapshot, workspace_id, &generation, entries, budget)?;
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

    pub(in crate::raw_index) fn observe_raw_generation_rows(
        &self,
        snapshot: &NativeSnapshot,
        workspace_id: &str,
        generation: &Generation,
        entries: &[Entry],
        budget: &mut QueryBudget,
    ) -> ServiceResult<(
        BTreeMap<ObservationId, NativeRawSourceControl>,
        Vec<NativeRawCopyObservation>,
    )> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let prefix = generation_prefix(&workspace, generation.number);
        self.validate_raw_bm25_generation(snapshot, generation, budget)?;
        let prefix_interval_rows = entries.iter().any(|entry| {
            std::str::from_utf8(&entry.key)
                .ok()
                .and_then(|key| key.strip_prefix(&prefix))
                .is_some_and(|key| {
                    key.starts_with("dense/prefix-segment-v2/")
                        || key == "dense/prefix-segments-v2/head"
                })
        });
        let router_rows = entries.iter().any(|entry| {
            std::str::from_utf8(&entry.key)
                .ok()
                .and_then(|key| key.strip_prefix(&prefix))
                .is_some_and(|key| {
                    key.starts_with("dense/directory-router-v1/")
                        || key == "dense/directory-routers-v1/head"
                })
        });
        if generation.dense_directory_router.is_some() || router_rows {
            let current = self.current_directory_router_heads(snapshot, workspace_id, budget)?;
            if current
                .directory_routers
                .as_ref()
                .and_then(|heads| heads.get(&generation.number))
                != generation.dense_directory_router.as_ref()
                || current
                    .prefix_bases
                    .as_ref()
                    .and_then(|heads| heads.get(&generation.number))
                    != generation.dense_prefix_base.as_ref()
                || current
                    .prefix_segment_heads
                    .as_ref()
                    .and_then(|heads| heads.get(&generation.number))
                    != generation.dense_prefix_segments.as_ref()
            {
                return Err(integrity(
                    "live router copy differs from certified native generation roots",
                ));
            }
        }
        if generation.dense_prefix_base.is_some()
            || generation.dense_prefix_segments.is_some()
            || prefix_interval_rows
        {
            let current = self.current_prefix_segment_heads(snapshot, workspace_id, budget)?;
            if current
                .prefix_segment_heads
                .as_ref()
                .and_then(|heads| heads.get(&generation.number))
                != generation.dense_prefix_segments.as_ref()
            {
                return Err(integrity(
                    "live raw copy generation differs from certified prefix directory",
                ));
            }
        }
        let mut sources = BTreeMap::new();
        let mut documents = BTreeMap::new();
        let mut rows = Vec::new();
        for entry in entries {
            let relative = std::str::from_utf8(&entry.key)
                .ok()
                .and_then(|key| key.strip_prefix(&prefix));
            if relative.is_some_and(|key| {
                key.starts_with("dense/graph/")
                    || key.starts_with("dense/prefix-base-v2/")
                    || key.starts_with("dense/prefix-segment-v2/")
                    || key == "dense/prefix-segments-v2/head"
                    || key.starts_with("dense/directory-router-v1/")
                    || key == "dense/directory-routers-v1/head"
            }) {
                let owner = if relative.is_some_and(|key| {
                    key.starts_with("dense/directory-router-v1/")
                        || key == "dense/directory-routers-v1/head"
                }) {
                    self.verify_dense_directory_router_copy(
                        snapshot,
                        generation,
                        &entry.key,
                        &entry.value,
                        budget,
                    )?;
                    None
                } else if relative.is_some_and(|key| {
                    key.starts_with("dense/prefix-segment-v2/")
                        || key == "dense/prefix-segments-v2/head"
                }) {
                    self.verify_dense_prefix_segment_copy(
                        snapshot,
                        generation,
                        &entry.key,
                        &entry.value,
                        budget,
                    )?
                } else if relative.is_some_and(|key| key.starts_with("dense/prefix-base-v2/")) {
                    self.verify_dense_prefix_base_copy(
                        snapshot,
                        generation,
                        &entry.key,
                        &entry.value,
                        budget,
                    )?
                } else if relative.is_some_and(|key| {
                    key.starts_with("dense/graph/segment/") || key == "dense/graph/segments/head"
                }) {
                    self.verify_dense_segment_copy(
                        snapshot,
                        generation,
                        &entry.key,
                        &entry.value,
                        budget,
                    )?
                } else {
                    self.verify_dense_graph_copy(
                        snapshot,
                        generation,
                        &entry.key,
                        &entry.value,
                        budget,
                    )?
                };
                if let Some(id) = owner {
                    let control = self.verified_capture_control(snapshot, id, budget)?;
                    if control.receipt.workspace_id.to_string() != workspace_id
                        || control.original.is_none()
                    {
                        return Err(integrity("graph copy lost its captured source owner"));
                    }
                    sources.insert(
                        id,
                        NativeRawSourceControl {
                            capture_commit: control.receipt.workspace_commit,
                            event_digest: control.receipt.event_digest,
                            control_digest: control.control_digest,
                        },
                    );
                }
                rows.push(self.observe_raw_row(
                    snapshot,
                    entry,
                    if owner.is_some() {
                        NativeRawCopyKind::Document
                    } else {
                        NativeRawCopyKind::SharedMetadata
                    },
                    owner,
                    budget,
                )?);
                continue;
            }
            if relative.is_some_and(|key| key.starts_with("dense/")) {
                let dense = generation
                    .dense
                    .as_ref()
                    .ok_or_else(|| integrity("observed dense row lost its generation profile"))?;
                dense.validate(generation.through)?;
                self.require_dense_feature(snapshot, budget)?;
                if entry.key == dense::receipt_key(&workspace, generation.number) {
                    self.verify_dense_receipt_copy(snapshot, generation, &entry.value, budget)?;
                    rows.push(self.observe_raw_row(
                        snapshot,
                        entry,
                        NativeRawCopyKind::SharedMetadata,
                        None,
                        budget,
                    )?);
                    continue;
                }
                let (id, domain) = if relative.is_some_and(|key| key.starts_with("dense/document/"))
                {
                    let document: dense::DenseDocument =
                        decode(&entry.value, "observed dense document")?;
                    (document.source.event_id, document.policy_domain)
                } else if relative.is_some_and(|key| key.starts_with("dense/vector/")) {
                    let vector: dense::DenseVector = decode(&entry.value, "observed dense vector")?;
                    (vector.source.event_id, vector.policy_domain)
                } else {
                    return Err(integrity("unknown row under dense profile prefix"));
                };
                let control = self.verified_capture_control(snapshot, id, budget)?;
                if control.receipt.workspace_id.to_string() != workspace_id
                    || control.receipt.workspace_commit > dense.through
                {
                    return Err(integrity(
                        "observed dense owner crosses workspace or prefix",
                    ));
                }
                let original = control.original.ok_or_else(|| {
                    integrity("dense original was pruned before its derived copies")
                })?;
                self.verify_dense_copy(
                    snapshot,
                    generation,
                    &entry.key,
                    &entry.value,
                    &original,
                    control.receipt.workspace_commit,
                    control.receipt.event_digest,
                    &domain,
                    budget,
                )?;
                sources.insert(
                    id,
                    NativeRawSourceControl {
                        capture_commit: control.receipt.workspace_commit,
                        event_digest: control.receipt.event_digest,
                        control_digest: control.control_digest,
                    },
                );
                rows.push(self.observe_raw_row(
                    snapshot,
                    entry,
                    NativeRawCopyKind::Document,
                    Some(id),
                    budget,
                )?);
                continue;
            }
            if relative.is_some_and(|key| key.starts_with("bm25/")) && generation.bm25.is_none() {
                return Err(integrity("observed BM25 row lost its generation profile"));
            }
            let (kind, owner) = match relative {
                Some(key) if key.starts_with("bm25/document/") => {
                    let document: bm25::Bm25Document = decode(&entry.value, "BM25 copy document")?;
                    (
                        NativeRawCopyKind::Document,
                        Some((document.source.event_id, document.policy_domain)),
                    )
                }
                Some(key) if key.starts_with("bm25/corpus/") => {
                    let _: bm25::DomainStatistics =
                        decode(&entry.value, "BM25 shared corpus statistics")?;
                    (NativeRawCopyKind::SharedMetadata, None)
                }
                Some(key) if key.starts_with("bm25/df/") => {
                    let _: bm25::TermStatistics =
                        decode(&entry.value, "BM25 shared term statistics")?;
                    (NativeRawCopyKind::SharedMetadata, None)
                }
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
                    let mut expected = document_rows(&workspace, generation.number, &document)?;
                    if generation.bm25.is_some() {
                        // Domain rows may already have been reclaimed on an
                        // earlier page. Custody scope labels remain with the
                        // accepted source; revocation changes permission only.
                        let policies =
                            self.stored_custody_policies_with_budget(snapshot, id, budget)?;
                        let statistics = self.build_bm25_document(
                            snapshot,
                            &original,
                            control.receipt.workspace_commit,
                            control.receipt.event_digest,
                            &domain,
                            bm25::routing_scope_count(&policies)?,
                            budget,
                        )?;
                        expected.insert(
                            bm25::document_key(&workspace, generation.number, id),
                            encode(&statistics)?,
                        );
                    }
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
        Ok((sources, rows))
    }

    pub(in crate::raw_index) fn observe_raw_row(
        &self,
        snapshot: &NativeSnapshot,
        entry: &Entry,
        kind: NativeRawCopyKind,
        source: Option<ObservationId>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawCopyObservation> {
        let version = if let Some(keys) = &self.engine.keys {
            let ciphertext = crate::budgeted::read_value(
                &snapshot.inner,
                &self.keyspaces.continuous,
                &entry.key,
                entry
                    .value
                    .len()
                    .saturating_add(crate::encryption::VALUE_ENVELOPE_BYTES),
                budget,
            )?
            .ok_or_else(|| integrity("observed raw ciphertext absent"))?;
            budget
                .charge(1, entry.value.len() as u64)
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
