//! Bounded recovery follows accepted workspace commits, not a pending-work index.

use super::*;

#[cfg(test)]
mod tests;

const CURSOR_DOMAIN: &[u8] = b"contextdb/native-record-recovery/v1\0";
const MAX_CURSOR_BYTES: usize = 8 * 1024;
const MAX_MAP_BYTES: usize = 4096;

/// One page of accepted groups without a valid completion locator. Recovery
/// additionally checks the later journal before creating any missing completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePendingRecordWrites {
    /// Workspace-local commits to inspect or repair; no document bodies or IDs.
    pub pending: Vec<u64>,
    /// Last workspace commit examined, including non-record operations.
    pub through: u64,
    /// Fixed accepted frontier for this pass; later writes belong to the next pass.
    pub scan_head: u64,
    /// Number of workspace commits examined in this page, at most 256.
    pub scanned: u32,
    /// Enumeration reached its frontier; this does not certify completed repair.
    pub caught_up: bool,
    /// Authenticated progress. At a completed frontier, reuse starts an incremental pass.
    pub continuation: String,
}

/// Fully repaired page. Its continuation advances only after all discovered
/// groups complete; an interrupted page may safely be retried with its input cursor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRecordWriteRecoveryProgress {
    /// Completed groups from this page, preserving their original mutation receipts.
    pub completed: Vec<NativeRecordWriteReceipt>,
    /// Last examined workspace commit whose page has been repaired.
    pub through: u64,
    /// Fixed accepted frontier for this pass.
    pub scan_head: u64,
    /// Number of examined workspace commits in this page.
    pub scanned: u32,
    /// This pass finished; concurrent later writes require another pass.
    pub caught_up: bool,
    /// Repair-only authenticated progress; discovery cursors cannot skip repair.
    pub continuation: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    commit: u64,
    global: u64,
    event_digest: String,
}

impl Anchor {
    fn of(event: &StoredEvent) -> Self {
        Self {
            commit: event.workspace_commit,
            global: event.global_commit,
            event_digest: event.event_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanState {
    head: Anchor,
    after: Anchor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Discover,
    Repair,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u16,
    database: String,
    workspace: String,
    authorization: String,
    mode: Mode,
    state: ScanState,
}

/// Process-local acceleration only. Reopen starts from accepted history; cache
/// entries are revalidated and never replace the journal or completion proofs.
#[derive(Default)]
pub(crate) struct RecoveryCache(BTreeMap<String, ScanState>);

impl NativeService {
    /// Examine 1..256 authoritative workspace commits under one shared budget.
    /// Requires Admin. No source/record body is loaded or authority changed.
    pub fn pending_record_source_writes(
        &self,
        context: &AuthenticatedRequestContext,
        continuation: Option<&str>,
        max_commits: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePendingRecordWrites> {
        self.record_write_page(context, continuation, max_commits, Mode::Discover, budget)
    }

    /// Discover and finish one page, without remembering individual requests or
    /// commits. Use only this method's continuation for incremental repair.
    pub fn repair_record_source_writes(
        &self,
        context: &AuthenticatedRequestContext,
        continuation: Option<&str>,
        max_commits: u32,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeRecordWriteRecoveryProgress> {
        let page =
            self.record_write_page(context, continuation, max_commits, Mode::Repair, budget)?;
        let mut completed = Vec::new();
        for commit in page.pending {
            completed.push(self.resume_record_source_write(context, commit, budget)?);
        }
        budget.check().map_err(raw_index::budget_error)?;
        Ok(NativeRecordWriteRecoveryProgress {
            completed,
            through: page.through,
            scan_head: page.scan_head,
            scanned: page.scanned,
            caught_up: page.caught_up,
            continuation: page.continuation,
        })
    }

    fn record_write_page(
        &self,
        context: &AuthenticatedRequestContext,
        continuation: Option<&str>,
        max_commits: u32,
        mode: Mode,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativePendingRecordWrites> {
        require_capability(context, Capability::Admin)?;
        if !(1..=256).contains(&max_commits) {
            return Err(invalid("record recovery page must contain 1..256 commits"));
        }
        budget.check().map_err(raw_index::budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let world = self.recovery_workspace(&snapshot, &workspace, budget)?;
        let current = if world.watermarks.journal == 0 {
            Anchor::default()
        } else {
            let (mapping, event) =
                self.recovery_event(&snapshot, &workspace, world.watermarks.journal, budget)?;
            if mapping.state != world {
                return Err(integrity(
                    "record recovery head differs from its accepted map",
                ));
            }
            Anchor::of(&event)
        };
        let mut state = match continuation {
            Some(token) => {
                self.decode_recovery_cursor(context, token, mode, budget)?
                    .state
            }
            None => ScanState {
                head: current.clone(),
                after: Anchor::default(),
            },
        };
        if state.after.commit > state.head.commit || state.head.commit > current.commit {
            return Err(expired());
        }
        for anchor in [&state.head, &state.after] {
            if anchor.commit == 0 {
                if *anchor != Anchor::default() {
                    return Err(expired());
                }
            } else {
                let (_, event) =
                    self.recovery_event(&snapshot, &workspace, anchor.commit, budget)?;
                if Anchor::of(&event) != *anchor {
                    return Err(expired());
                }
            }
        }
        if state.after == state.head {
            state.head = current;
        }
        let start = state.after.commit;
        let end = start
            .saturating_add(u64::from(max_commits))
            .min(state.head.commit);
        let mut pending = Vec::new();
        while state.after.commit < end {
            let commit = state.after.commit + 1;
            let (_, event) = self.recovery_event(&snapshot, &workspace, commit, budget)?;
            if event.global_commit <= state.after.global {
                return Err(integrity("record recovery journal order regressed"));
            }
            if is_source_write(&event.operation) {
                if self
                    .budgeted_record_write_completion(&snapshot, &event, &mut Some(&mut *budget))?
                    .is_none()
                {
                    pending.push(commit);
                }
            } else if event.accepted_record_write.is_some() {
                return Err(integrity(
                    "record write intent has an invalid journal owner",
                ));
            }
            if event.operation == COMPLETE {
                let publication = event
                    .accepted_record_write_completion
                    .as_ref()
                    .ok_or_else(|| integrity("record completion declaration absent"))?;
                let write =
                    self.recovery_global_event(&snapshot, publication.write_global_commit, budget)?;
                if write.workspace_digest != workspace
                    || self
                        .budgeted_record_write_completion(
                            &snapshot,
                            &write,
                            &mut Some(&mut *budget),
                        )?
                        .as_ref()
                        != Some(&event)
                {
                    return Err(integrity(
                        "record completion journal lost its exact locator",
                    ));
                }
            } else if event.accepted_record_write_completion.is_some() {
                return Err(integrity("record completion has an invalid journal owner"));
            }
            state.after = Anchor::of(&event);
        }
        let result = NativePendingRecordWrites {
            pending,
            through: state.after.commit,
            scan_head: state.head.commit,
            scanned: (state.after.commit - start) as u32,
            caught_up: state.after == state.head,
            continuation: self.encode_recovery_cursor(context, state, mode)?,
        };
        budget.check().map_err(raw_index::budget_error)?;
        Ok(result)
    }

    fn recovery_workspace<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<WorkspaceState> {
        let state = match control_bytes(
            snapshot,
            &self.keyspaces.workspace,
            workspace.as_bytes(),
            MAX_MAP_BYTES,
            &mut Some(&mut *budget),
        )? {
            Some(bytes) => {
                let state: WorkspaceState = decode(&bytes, "recovery workspace")?;
                validate_workspace_state(&state, workspace)?;
                state
            }
            None => WorkspaceState::genesis(workspace.into()),
        };
        // A missing or lowered head cannot silently hide accepted mappings.
        budget.charge(1, 0).map_err(raw_index::budget_error)?;
        let after = workspace_map_key(workspace, state.watermarks.journal);
        let tail = snapshot
            .scan_prefix_page(
                &self.keyspaces.workspace_map,
                ScanPageRequest {
                    prefix: format!("{workspace}/").as_bytes(),
                    start_after: if state.watermarks.journal == 0 {
                        None
                    } else {
                        Some(&after)
                    },
                    max_entries: 1,
                    max_bytes: MAX_MAP_BYTES,
                },
            )
            .map_err(storage_error)?;
        for entry in &tail.entries {
            budget
                .charge(1, (entry.key.len() + entry.value.len()) as u64)
                .map_err(raw_index::budget_error)?;
        }
        if !tail.entries.is_empty() || tail.continuation.is_some() {
            return Err(integrity(
                "record recovery head omits accepted workspace mappings",
            ));
        }
        Ok(state)
    }

    pub(super) fn recovery_event<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        commit: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(CommitMap, StoredEvent)> {
        let bytes = control_bytes(
            snapshot,
            &self.keyspaces.workspace_map,
            &workspace_map_key(workspace, commit),
            MAX_MAP_BYTES,
            &mut Some(&mut *budget),
        )?
        .ok_or_else(|| integrity("record recovery workspace mapping absent"))?;
        let mapping: CommitMap = decode(&bytes, "record recovery mapping")?;
        validate_workspace_state(&mapping.state, workspace)?;
        let event = self.recovery_global_event(snapshot, mapping.global_commit, budget)?;
        if commit == 0
            || mapping.schema_version != SCHEMA_VERSION
            || mapping.state.watermarks.journal != commit
            || mapping.state.latest_global_commit != mapping.global_commit
            || event.workspace_commit != commit
            || event.workspace_digest != workspace
        {
            return Err(integrity(
                "record recovery mapping differs from accepted history",
            ));
        }
        Ok((mapping, event))
    }

    fn recovery_global_event<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        global: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<StoredEvent> {
        let bytes = control_bytes(
            snapshot,
            &self.keyspaces.events,
            &global.to_be_bytes(),
            MAX_JSON_BYTES,
            &mut Some(budget),
        )?
        .ok_or_else(|| integrity("record recovery journal event absent"))?;
        let event: StoredEvent = decode(&bytes, "record recovery journal event")?;
        if global == 0
            || event.schema_version != SCHEMA_VERSION
            || event.global_commit != global
            || event.event_digest != event_digest(&event)?
        {
            return Err(integrity(
                "record recovery event differs from accepted history",
            ));
        }
        Ok(event)
    }

    // A missing locator may be corruption after an already accepted completion.
    // Prove its absence from the authoritative suffix before creating another.
    pub(super) fn require_record_completion_absent<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        write: &StoredEvent,
        world: &WorkspaceState,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if world.watermarks.journal < write.workspace_commit {
            return Err(integrity("record completion frontier precedes acceptance"));
        }
        let mut previous = write.global_commit;
        let Some(first) = write.workspace_commit.checked_add(1) else {
            return Ok(());
        };
        for commit in first..=world.watermarks.journal {
            let (_, event) =
                self.recovery_event(snapshot, &write.workspace_digest, commit, budget)?;
            if event.global_commit <= previous {
                return Err(integrity("record completion suffix regressed"));
            }
            if event
                .accepted_record_write_completion
                .as_ref()
                .is_some_and(|completion| completion.write_global_commit == write.global_commit)
            {
                return Err(integrity("accepted record completion lost its locator"));
            }
            previous = event.global_commit;
        }
        Ok(())
    }

    fn encode_recovery_cursor(
        &self,
        context: &AuthenticatedRequestContext,
        state: ScanState,
        mode: Mode,
    ) -> ServiceResult<String> {
        let cursor = Cursor {
            version: 1,
            database: digest_bytes(self.database_id.as_bytes()),
            workspace: digest_bytes(context.request.workspace_id.as_bytes()),
            authorization: context.authorization_binding_digest()?,
            mode,
            state,
        };
        let payload = encode_hex(&encode(&cursor)?);
        let mac = keyed_token(&self.token_key, CURSOR_DOMAIN, payload.as_bytes());
        Ok(format!("{payload}.{mac}"))
    }

    fn decode_recovery_cursor(
        &self,
        context: &AuthenticatedRequestContext,
        token: &str,
        mode: Mode,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Cursor> {
        if token.len() > MAX_CURSOR_BYTES {
            return Err(invalid_cursor());
        }
        budget
            .charge(1, token.len() as u64)
            .map_err(raw_index::budget_error)?;
        let (payload, mac) = token.rsplit_once('.').ok_or_else(invalid_cursor)?;
        if keyed_token(&self.token_key, CURSOR_DOMAIN, payload.as_bytes()) != mac {
            return Err(invalid_cursor());
        }
        let cursor: Cursor =
            serde_json::from_slice(&decode_hex(payload).ok_or_else(invalid_cursor)?)
                .map_err(|_| invalid_cursor())?;
        if cursor.version != 1
            || cursor.database != digest_bytes(self.database_id.as_bytes())
            || cursor.workspace != digest_bytes(context.request.workspace_id.as_bytes())
            || cursor.authorization != context.authorization_binding_digest()?
            || cursor.mode != mode
        {
            return Err(invalid_cursor());
        }
        Ok(cursor)
    }

    pub(crate) fn recover_runtime_record_writes(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        require_capability(context, Capability::Runtime)?;
        budget.check().map_err(raw_index::budget_error)?;
        let workspace = digest_bytes(context.request.workspace_id.as_bytes());
        let Some(ledger) = &self.suppression else {
            return Ok(());
        };
        if !ledger.supports_record_sources() || ledger.current_record_sources(&workspace)?.is_none()
        {
            return Ok(());
        }
        require_capability(context, Capability::Admin)?;
        let cached = self
            .record_write_recovery
            .try_lock()
            .map_err(|_| pending("record recovery cache is busy"))?
            .0
            .get(&workspace)
            .cloned();
        let mut cursor = cached
            .map(|state| self.encode_recovery_cursor(context, state, Mode::Repair))
            .transpose()?;
        let mut restarted = false;
        loop {
            let page =
                match self.repair_record_source_writes(context, cursor.as_deref(), 64, budget) {
                    Err(error) if error.code == ErrorCode::SnapshotExpired && !restarted => {
                        cursor = None;
                        restarted = true;
                        continue;
                    }
                    result => result?,
                };
            let state = self
                .decode_recovery_cursor(context, &page.continuation, Mode::Repair, budget)?
                .state;
            {
                let mut cache = self
                    .record_write_recovery
                    .try_lock()
                    .map_err(|_| pending("record recovery cache is busy"))?;
                if cache.0.len() >= 64 && !cache.0.contains_key(&workspace) {
                    cache.0.pop_first();
                }
                cache.0.insert(workspace.clone(), state);
            }
            if page.caught_up {
                return Ok(());
            }
            cursor = Some(page.continuation);
        }
    }
}

fn invalid_cursor() -> ServiceError {
    ServiceError::new(
        ErrorCode::InvalidContinuation,
        "record recovery cursor is not bound to this caller, database or operation",
        false,
    )
}
fn expired() -> ServiceError {
    ServiceError::new(
        ErrorCode::SnapshotExpired,
        "record recovery cursor no longer names the same accepted history",
        false,
    )
}
