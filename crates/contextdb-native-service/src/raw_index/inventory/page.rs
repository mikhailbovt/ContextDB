//! Scan outside the native writer, then fence the snapshot through external Sync.

use super::*;
use contextdb_storage::Entry;

const MAX_CURSOR_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u16,
    previous: NativeRawIndexInventoryReceipt,
    after: Option<Vec<u8>>,
}

impl NativeService {
    /// Retain at most 1024 present rows from one retained raw generation, with an
    /// 8 MiB scan and a 1 MiB witness bound. All validation shares the budget.
    /// Exact retries recover the accepted page. Native changes require a new
    /// scan; old witnesses remain independently readable. No native row changes.
    pub fn inventory_raw_removal_copies(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        continuation: Option<&str>,
        max_rows: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawIndexInventoryPage> {
        if !(1..=1024).contains(&max_rows) {
            return Err(crate::invalid("raw index inventory requires 1..1024 rows"));
        }
        self.read_original_removal_inventory(context, request, budget)?;
        let ledger = self
            .suppression
            .as_ref()
            .ok_or_else(|| integrity("raw inventory authority absent"))?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let cursor = continuation
            .map(|token| self.decode_raw_inventory_cursor(context, request, token, budget))
            .transpose()?;
        let previous = cursor
            .as_ref()
            .map(|cursor| ledger.read_raw_index_inventory(&cursor.previous, &workspace, budget))
            .transpose()?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let anchor =
            self.raw_inventory_snapshot(&snapshot, &context.request.workspace_id, budget)?;
        let (generation_index, rows_before, after) = if let Some(parent) = &previous {
            if parent.request != *request || parent.snapshot != anchor || parent.finished {
                return Err(inventory_stale());
            }
            let after = cursor.as_ref().and_then(|cursor| cursor.after.clone());
            if parent.generation_finished {
                if after.is_some() {
                    return Err(bad_cursor());
                }
                (parent.generation_index + 1, 0, None)
            } else {
                if after
                    .as_ref()
                    .map(|key| crate::encryption::address(&self.keyspaces.continuous, key))
                    != parent.last_digest
                {
                    return Err(bad_cursor());
                }
                (
                    parent.generation_index,
                    parent
                        .rows_before
                        .checked_add(parent.row_count())
                        .ok_or_else(|| exhausted("raw inventory row count overflow"))?,
                    after,
                )
            }
        } else {
            (0, 0, None)
        };
        let descriptor = anchor.generations.get(generation_index as usize);
        let mut end_key = None;
        let (sources, rows, generation_finished) = if let Some(descriptor) = descriptor {
            let prefix = generation_prefix(&workspace, descriptor.number);
            if after
                .as_ref()
                .is_some_and(|key| !key.starts_with(prefix.as_bytes()))
            {
                return Err(bad_cursor());
            }
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: prefix.as_bytes(),
                        start_after: after.as_deref(),
                        max_entries: max_rows as usize,
                        max_bytes: 8 * 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            for row in &page.entries {
                budget
                    .charge(1, (row.key.len() + row.value.len()) as u64)
                    .map_err(budget_error)?;
            }
            end_key = page.entries.last().map(|row| row.key.clone());
            let finished = page.continuation.is_none();
            let manifest_key = generation_key(&workspace, descriptor.number);
            let manifest = snapshot
                .get(&self.keyspaces.continuous, &manifest_key)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("raw inventory generation absent"))?;
            let generation: Generation = decode(&manifest, "raw inventory generation")?;
            let (sources, mut rows) = self.observe_raw_generation_rows(
                &snapshot,
                &context.request.workspace_id,
                &generation,
                &page.entries,
                budget,
            )?;
            if finished {
                rows.push(self.observe_raw_row(
                    &snapshot,
                    &Entry {
                        key: manifest_key,
                        value: manifest,
                    },
                    NativeRawCopyKind::Manifest,
                    None,
                    budget,
                )?);
            }
            (sources, rows, finished)
        } else {
            (BTreeMap::new(), Vec::new(), true)
        };
        let finished = generation_finished
            && (anchor.generations.is_empty()
                || generation_index as usize + 1 == anchor.generations.len());
        let witness = NativeRawIndexInventoryWitness {
            database_id: self.database_id.clone(),
            workspace_id: context.request.workspace_id.clone(),
            request: request.clone(),
            snapshot: anchor,
            generation_index,
            rows_before,
            max_rows,
            after_digest: after
                .as_ref()
                .map(|key| crate::encryption::address(&self.keyspaces.continuous, key)),
            last_digest: end_key
                .as_ref()
                .map(|key| crate::encryption::address(&self.keyspaces.continuous, key)),
            previous: cursor.map(|cursor| cursor.previous),
            generation_finished,
            finished,
            sources,
            rows,
        };
        witness.validate(&digest_bytes(self.database_id.as_bytes()))?;
        budget
            .charge(1, encode(&witness)?.len() as u64)
            .map_err(budget_error)?;
        #[cfg(test)]
        BEFORE_RETAIN.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let tx = self.engine.begin_write().map_err(storage_error)?;
        if tx.sequence() != snapshot.sequence()
            || self.raw_inventory_snapshot(&tx, &context.request.workspace_id, budget)?
                != witness.snapshot
        {
            return Err(inventory_stale());
        }
        let receipt = ledger.retain_raw_index_inventory(&witness, budget)?;
        let continuation = if finished {
            None
        } else {
            Some(self.encode_raw_inventory_cursor(
                context,
                request,
                Cursor {
                    version: 1,
                    previous: receipt.clone(),
                    after: if generation_finished { None } else { end_key },
                },
            )?)
        };
        let result = NativeRawIndexInventoryPage {
            receipt,
            witness,
            continuation,
        };
        crate::retention::keys::charge_report(&result, budget)?;
        Ok(result)
    }

    /// Read an independently retained observation even after native pruning or
    /// older restore. Exact acceptance, request/source controls and the immediate
    /// predecessor are verified; the key inventory verifies the entire page chain.
    pub fn read_raw_index_inventory_witness(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &NativeRawIndexInventoryReceipt,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawIndexInventoryWitness> {
        require_capability(context, Capability::Admin)?;
        self.suppression
            .as_ref()
            .ok_or_else(|| integrity("raw inventory authority absent"))?
            .read_raw_index_inventory(
                receipt,
                &digest_bytes(context.request.workspace_id.as_bytes()),
                budget,
            )
    }

    fn raw_inventory_snapshot<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRawIndexSnapshot> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let state: Option<IndexState> = self.raw_value(snapshot, &state_key(&workspace))?;
        let retained = retained_generations(&state.clone().unwrap_or_default())?;
        let world = self.workspace_state(snapshot, workspace_id)?;
        let native_commit = self.global_head(snapshot)?;
        let terminal = snapshot
            .get(&self.keyspaces.meta, crate::META_EVENT_DIGEST_KEY)
            .map_err(storage_error)?;
        let native_event_digest = if native_commit == 0 {
            if terminal.is_some() {
                return Err(integrity("empty raw inventory history has an event digest"));
            }
            canonical_digest(&("contextdb/raw-index-empty-history/v1", &self.database_id))?
        } else {
            let bytes = snapshot
                .get(&self.keyspaces.events, &native_commit.to_be_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("raw inventory native event absent"))?;
            budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
            let event: crate::StoredEvent = decode(&bytes, "raw inventory native event")?;
            if event.global_commit != native_commit
                || event.event_digest != crate::event_digest(&event)?
                || terminal.as_deref() != Some(event.event_digest.as_bytes())
            {
                return Err(integrity("raw inventory native event binding differs"));
            }
            event.event_digest
        };
        let tail = snapshot
            .scan_prefix_page(
                &self.keyspaces.events,
                ScanPageRequest {
                    prefix: b"",
                    start_after: Some(&native_commit.to_be_bytes()),
                    max_entries: 1,
                    max_bytes: 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        if !tail.entries.is_empty() {
            return Err(integrity("raw inventory native head is behind its journal"));
        }
        let manifest_prefix = format!("raw/generation/{workspace}/");
        let manifests = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: manifest_prefix.as_bytes(),
                    start_after: None,
                    max_entries: MAX_GENERATIONS as usize + 1,
                    max_bytes: 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        if manifests.continuation.is_some() || manifests.entries.len() != retained.len() {
            return Err(integrity(
                "raw inventory retained manifests differ from state",
            ));
        }
        let mut generations = Vec::new();
        for (number, entry) in retained.into_iter().zip(manifests.entries) {
            budget
                .charge(1, (entry.key.len() + entry.value.len()) as u64)
                .map_err(budget_error)?;
            let generation: Generation = decode(&entry.value, "raw inventory manifest")?;
            if entry.key != generation_key(&workspace, number)
                || generation.number != number
                || generation.through > world.watermarks.journal
                || generation.analyzer != RAW_ANALYZER
                || generation.custody_version > crate::custody::CUSTODY_VERSION
            {
                return Err(integrity("raw inventory generation binding differs"));
            }
            let state = state
                .as_ref()
                .ok_or_else(|| integrity("raw inventory index state absent"))?;
            let job = state
                .reclaiming
                .as_ref()
                .filter(|job| job.generation == number);
            let role = if state.active == Some(number) {
                NativeRawGenerationRole::Active
            } else if state.building == Some(number) {
                NativeRawGenerationRole::Building
            } else if job.is_some() {
                NativeRawGenerationRole::Reclaiming
            } else {
                NativeRawGenerationRole::Retained
            };
            generations.push(NativeRawIndexGeneration {
                number,
                manifest_digest: digest_bytes(&entry.value),
                role,
                removed_before: job.map_or(0, |job| job.removed_rows),
                reclamation: job.and_then(|job| job.copies.clone()),
            });
        }
        if generations.is_empty() {
            let prefix = format!("raw/g/{workspace}/");
            let rows = snapshot
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: prefix.as_bytes(),
                        start_after: None,
                        max_entries: 1,
                        max_bytes: 8 * 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            if !rows.entries.is_empty() {
                return Err(integrity("raw inventory lost its generation manifests"));
            }
        }
        let result = NativeRawIndexSnapshot {
            native_commit,
            native_event_digest,
            state_digest: canonical_digest(&state)?,
            generations,
        };
        budget
            .charge(1, encode(&result)?.len() as u64)
            .map_err(budget_error)?;
        Ok(result)
    }

    fn raw_inventory_cursor_aad(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
    ) -> ServiceResult<Vec<u8>> {
        encode(&(
            "contextdb/raw-index-inventory-cursor/v1",
            &self.database_id,
            context.authorization_binding_digest()?,
            request,
        ))
    }

    fn encode_raw_inventory_cursor(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        cursor: Cursor,
    ) -> ServiceResult<String> {
        let ciphertext = crate::encryption::seal(
            &self.token_key,
            &self.raw_inventory_cursor_aad(context, request)?,
            &encode(&cursor)?,
        )
        .map_err(storage_error)?;
        let token = crate::encode_hex(&ciphertext);
        if token.len() > MAX_CURSOR_BYTES {
            return Err(exhausted("raw inventory cursor exceeds its bound"));
        }
        Ok(token)
    }

    fn decode_raw_inventory_cursor(
        &self,
        context: &AuthenticatedRequestContext,
        request: &NativeRemovalRequestReceipt,
        token: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Cursor> {
        if token.len() > MAX_CURSOR_BYTES {
            return Err(bad_cursor());
        }
        budget.charge(1, token.len() as u64).map_err(budget_error)?;
        let bytes = crate::decode_hex(token).ok_or_else(bad_cursor)?;
        let plaintext = crate::encryption::open(
            &self.token_key,
            &self.raw_inventory_cursor_aad(context, request)?,
            &bytes,
        )
        .map_err(|_| bad_cursor())?;
        let cursor: Cursor = serde_json::from_slice(&plaintext).map_err(|_| bad_cursor())?;
        if cursor.version != 1 {
            return Err(bad_cursor());
        }
        Ok(cursor)
    }
}

fn bad_cursor() -> ServiceError {
    crate::invalid("raw inventory cursor is invalid for this caller, request or token key")
}
fn inventory_stale() -> ServiceError {
    ServiceError::new(
        ErrorCode::IndexTooStale,
        "native raw inventory changed; restart inspection",
        true,
    )
}

#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_RETAIN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
