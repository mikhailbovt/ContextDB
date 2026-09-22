//! Bounded host-admin logical backup for the native Fjall authority.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_service::{
    BackupResponse, Capability, CreateBackupRequest, ErrorCode, RestoreBackupRequest,
    RestoreBackupResponse, ServiceError, ServiceResult,
};
use contextdb_storage::{
    Durability, Entry, Keyspace, ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine,
    VerifyMode, WriteTransaction,
};
use contextdb_storage_fjall::FJALL_INTERNAL_META_KEYSPACE;

use super::{
    FORMAT_NAME, MAX_JSON_BYTES, META_EVENT_DIGEST_KEY, META_GLOBAL_HEAD_KEY, META_MANIFEST_KEY,
    Manifest, NativeService, SCHEMA_VERSION, StoredContent, StoredEvent, StoredObservationContent,
    StoredObservationPolicy, StoredPolicy, WorkspaceState, canonical_digest, decode, digest_bytes,
    encode, event_digest, exhausted, history_key, integrity, policy_for, require_capability,
    require_sync, storage_error, validate_manifest, validate_stored_policy,
    validate_workspace_state, workspace_map_key,
};

mod artifacts;
mod cleanup;
mod contents;
mod executor;
pub(crate) mod jobs;
pub(crate) mod preservation;
mod recovery;
pub(crate) mod replacements;
mod routing;
pub use cleanup::{NativeBackupCleanupProgress, NativeBackupCleanupStage};
pub use executor::{
    NativeArchiveCleanup, NativeArchiveCleanupAction, NativeArchiveCleanupAdvance,
    NativeArchiveCleanupEntry, NativeArchiveCleanupInventory, NativeArchiveCleanupState,
};
pub use jobs::NativeBackupCleanupJobProgress;
pub use preservation::{NativeBackupPreservation, NativeBackupPreservationPath};
pub use recovery::{
    NativeBackupRecovery, NativeBackupRecoveryInput, NativeBackupRecoveryInventory,
    NativeBackupRecoveryState,
};
pub use replacements::NativeRemovalBackup;

/// Exact format returned by the native administrative backup operation.
pub const NATIVE_BACKUP_FORMAT: &str = "contextdb.native-fjall.logical-backup.v1";
/// Backup format including the continuous capture authority.
pub const NATIVE_CONTINUOUS_BACKUP_FORMAT: &str = "contextdb.native-fjall.logical-backup.v2";
/// Ciphertext-preserving native backup requiring its retained key authority.
pub const NATIVE_ENCRYPTED_BACKUP_FORMAT: &str = "contextdb.native-fjall.encrypted-backup.v3";

const BACKUP_MAGIC: &[u8] = b"contextdb/native-backup/v1\0";
const BACKUP_FOOTER_BYTES: usize = 32;
pub(crate) const MAX_BACKUP_BYTES: usize = 256 * 1024 * 1024;
const MAX_BACKUP_RAW_BYTES: usize = 128 * 1024 * 1024;
pub(crate) const MAX_BACKUP_ENTRIES: usize = 2_000_000;
const MAX_BACKUP_KEY_BYTES: usize = 64 * 1024;
const MAX_BACKUP_VALUE_BYTES: usize = 16 * 1024 * 1024 + 64;
const BACKUP_SCAN_PAGE_ENTRIES: usize = 4_096;
const BACKUP_SCAN_PAGE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackupKeyspace {
    name: String,
    entries: Vec<Entry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeBackup {
    format: String,
    database_id: String,
    commit_seq: u64,
    deep_digest: String,
    custody_authority: Option<uuid::Uuid>,
    keyspaces: Vec<BackupKeyspace>,
}

impl NativeService {
    pub(super) fn create_native_backup(
        &self,
        request: CreateBackupRequest,
    ) -> ServiceResult<BackupResponse> {
        require_capability(&request.context, Capability::Admin)?;
        if let Some(keys) = &self.engine.keys {
            keys.require_backup_registry()?;
        }
        let _guard = self.lock_writes()?;
        let (archive, response) = self.build_native_backup()?;
        if let Some(keys) = &self.engine.keys {
            if keys.supports_backup_contents() {
                self.retain_verified_backup_contents(
                    &archive,
                    &response,
                    true,
                    &mut contents::issuance_budget(),
                )?;
            } else {
                keys.register_backup(
                    &response.digest,
                    response.commit_seq,
                    &archive.deep_digest,
                    response.bytes.len() as u64,
                )
                .map_err(storage_error)?;
            }
            #[cfg(test)]
            AFTER_REGISTRATION.with(|hook| {
                if let Some(hook) = hook.take() {
                    hook();
                }
            });
        }
        Ok(response)
    }

    // Caller holds native publication until the verified bytes are issued.
    fn build_native_backup(&self) -> ServiceResult<(NativeBackup, BackupResponse)> {
        self.verify_physical_backup_layout()?;
        let backend = self
            .engine
            .verify(VerifyMode::Deep)
            .map_err(storage_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if backend.sequence != snapshot.sequence() {
            return Err(integrity(
                "native storage changed during backup verification",
            ));
        }
        let keyspaces = if self.engine.is_encrypted() {
            self.collect_backup_rows(&snapshot.inner)?
        } else {
            self.collect_backup_rows(&snapshot)?
        };
        // Verify the exact bounded rows that will be encoded, rather than
        // rescanning an unbounded source keyspace after the cap-enforcing
        // paged collection pass.
        let mut archive = NativeBackup {
            format: if self.engine.is_encrypted() {
                NATIVE_ENCRYPTED_BACKUP_FORMAT
            } else if keyspaces.len() == self.keyspaces.all().len() {
                NATIVE_CONTINUOUS_BACKUP_FORMAT
            } else {
                NATIVE_BACKUP_FORMAT
            }
            .to_owned(),
            database_id: self.database_id.clone(),
            commit_seq: 0,
            deep_digest: "0".repeat(64),
            custody_authority: self.engine.keys.as_ref().map(|keys| keys.authority_id()),
            keyspaces,
        };
        let (commit_seq, deep_digest) = {
            let archive_snapshot = self.engine.decode_snapshot(BackupSnapshot::new(&archive));
            self.verify_backup_snapshot(&archive_snapshot)?
        };
        archive.commit_seq = commit_seq;
        archive.deep_digest = deep_digest;
        let bytes = encode_backup(&archive)?;
        let digest = digest_bytes(&bytes);
        let response = BackupResponse {
            format: archive.format.clone(),
            digest,
            bytes,
            commit_seq,
        };
        Ok((archive, response))
    }

    pub(super) fn restore_native_backup(
        &self,
        request: RestoreBackupRequest,
    ) -> ServiceResult<RestoreBackupResponse> {
        // Authentication is deliberately first: format, size, digest, and
        // database identity must not be usable as an oracle by an untrusted
        // caller.
        require_capability(&request.context, Capability::Admin)?;
        if !matches!(
            request.format.as_str(),
            NATIVE_BACKUP_FORMAT | NATIVE_CONTINUOUS_BACKUP_FORMAT | NATIVE_ENCRYPTED_BACKUP_FORMAT
        ) {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "native backup format is incompatible",
                false,
            ));
        }
        if request.bytes.len() > MAX_BACKUP_BYTES {
            return Err(exhausted("native backup exceeds the 256 MiB limit"));
        }
        if request.digest != digest_bytes(&request.bytes) {
            return Err(integrity("native backup digest is invalid"));
        }
        let RestoreBackupRequest {
            context,
            bytes,
            format,
            ..
        } = request;
        let archive = decode_backup(&bytes, &self.database_id)?;
        if archive.custody_authority != self.engine.keys.as_ref().map(|keys| keys.authority_id()) {
            return Err(integrity(
                "backup requires its exact retained custody key authority",
            ));
        }
        if archive.format != format {
            return Err(integrity("native backup format differs from its header"));
        }
        drop(bytes);
        let archive_snapshot = self.engine.decode_snapshot(BackupSnapshot::new(&archive));
        let manifest: Manifest = decode(
            &archive_snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native backup manifest is absent"))?,
            "native backup manifest",
        )?;
        self.verify_suppression_binding(&manifest)?;
        self.verify_encryption_binding(&manifest)?;
        if manifest.features.contains(super::capture::CAPTURE_FEATURE)
            && manifest.suppression_authority.is_none()
        {
            return Err(super::unsupported(
                "continuous restore requires an independently retained current suppression authority; unbound archives need explicit migration",
            ));
        }
        let (commit_seq, deep_digest) = self.verify_backup_snapshot(&archive_snapshot)?;
        if commit_seq != archive.commit_seq || deep_digest != archive.deep_digest {
            return Err(integrity(
                "native backup verification receipt differs from its header",
            ));
        }
        let restored_workspace =
            self.workspace_state(&archive_snapshot, &context.request.workspace_id)?;

        let _guard = self.lock_writes()?;
        self.verify_physical_backup_layout()?;
        let mut transaction = self.engine.begin_write().map_err(storage_error)?;
        self.require_pristine_restore_target(&transaction)?;
        for keyspace in self.keyspaces.all() {
            for entry in transaction
                .scan_prefix(keyspace, b"")
                .map_err(storage_error)?
            {
                transaction
                    .delete(keyspace, entry.key)
                    .map_err(storage_error)?;
            }
        }
        for keyspace in &archive.keyspaces {
            let target = self
                .keyspaces
                .all()
                .into_iter()
                .find(|candidate| candidate.as_str() == keyspace.name)
                .ok_or_else(|| integrity("native backup keyspace is not admitted"))?;
            for entry in &keyspace.entries {
                if self.engine.is_encrypted() {
                    transaction
                        .put_ciphertext(target, entry.key.clone(), entry.value.clone())
                        .map_err(storage_error)?;
                    continue;
                }
                let logical_value = archive_snapshot
                    .get(target, &entry.key)
                    .map_err(storage_error)?
                    .ok_or_else(|| integrity("verified backup value disappeared"))?;
                transaction
                    .put(target, entry.key.clone(), logical_value)
                    .map_err(storage_error)?;
            }
        }
        require_sync(
            transaction
                .commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;

        let verified = self.verify_native(true)?;
        if verified.commit_seq != archive.commit_seq
            || verified.archive_digest.as_deref() != Some(archive.deep_digest.as_str())
        {
            return Err(integrity(
                "native restored authority differs from the verified backup",
            ));
        }
        Ok(RestoreBackupResponse {
            commit_seq: archive.commit_seq,
            watermarks: restored_workspace.watermarks,
        })
    }

    fn verify_physical_backup_layout(&self) -> ServiceResult<()> {
        let mut allowed = self
            .keyspaces
            .all()
            .into_iter()
            .map(|keyspace| keyspace.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        allowed.insert(FJALL_INTERNAL_META_KEYSPACE.to_owned());
        allowed.extend(self.engine.protocol_keyspaces().map_err(storage_error)?);
        let actual = self
            .engine
            .physical_keyspace_names()
            .into_iter()
            .collect::<BTreeSet<_>>();
        if !actual.is_subset(&allowed) {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "native physical store contains an unknown keyspace",
                false,
            ));
        }
        Ok(())
    }

    fn collect_backup_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<Vec<BackupKeyspace>> {
        let mut total_entries = 0_usize;
        let mut total_bytes = 0_usize;
        let mut output = Vec::with_capacity(self.keyspaces.all().len());
        for keyspace in self.keyspaces.all() {
            let mut continuation: Option<Vec<u8>> = None;
            let mut previous_key: Option<Vec<u8>> = None;
            let mut entries = Vec::new();
            loop {
                let page = snapshot
                    .scan_prefix_page(
                        keyspace,
                        ScanPageRequest {
                            prefix: b"",
                            start_after: continuation.as_deref(),
                            max_entries: BACKUP_SCAN_PAGE_ENTRIES,
                            max_bytes: BACKUP_SCAN_PAGE_BYTES,
                        },
                    )
                    .map_err(storage_error)?;
                if page.continuation.is_some() && page.entries.is_empty() {
                    return Err(integrity("native backup scan made no progress"));
                }
                for entry in page.entries {
                    validate_backup_entry(&entry)?;
                    if previous_key
                        .as_ref()
                        .is_some_and(|previous| previous >= &entry.key)
                    {
                        return Err(integrity(
                            "native backup scan is not in canonical key order",
                        ));
                    }
                    total_entries = total_entries
                        .checked_add(1)
                        .ok_or_else(|| exhausted("native backup entry count overflowed"))?;
                    if total_entries > MAX_BACKUP_ENTRIES {
                        return Err(exhausted(
                            "native backup exceeds the two-million-entry limit",
                        ));
                    }
                    total_bytes = total_bytes
                        .checked_add(entry.key.len())
                        .and_then(|bytes| bytes.checked_add(entry.value.len()))
                        .ok_or_else(|| exhausted("native backup byte count overflowed"))?;
                    if total_bytes > MAX_BACKUP_RAW_BYTES {
                        return Err(exhausted("native backup exceeds the 128 MiB raw limit"));
                    }
                    previous_key = Some(entry.key.clone());
                    entries.push(entry);
                }
                let Some(next) = page.continuation else {
                    break;
                };
                if continuation
                    .as_ref()
                    .is_some_and(|previous| &next <= previous)
                {
                    return Err(integrity("native backup scan cursor did not advance"));
                }
                continuation = Some(next);
            }
            // Preserve the exact v1 archive layout when capture has never run.
            if keyspace == &self.keyspaces.continuous
                && entries.is_empty()
                && !self.engine.is_encrypted()
            {
                continue;
            }
            output.push(BackupKeyspace {
                name: keyspace.as_str().to_owned(),
                entries,
            });
        }
        Ok(output)
    }

    fn verify_backup_snapshot<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<(u64, String)> {
        let manifest_bytes = snapshot
            .get(&self.keyspaces.meta, META_MANIFEST_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("native backup manifest is absent"))?;
        let manifest: Manifest = decode(&manifest_bytes, "native backup manifest")?;
        validate_manifest(&manifest, &self.database_id)?;
        let global_head = self.global_head(snapshot)?;
        self.verify_event_chain(snapshot, global_head)?;
        self.verify_backup_closure(snapshot, global_head)?;
        let deep_digest = self.verify_all_records(snapshot)?;
        Ok((global_head, deep_digest))
    }

    fn verify_backup_closure<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        global_head: u64,
    ) -> ServiceResult<()> {
        let meta = snapshot
            .scan_prefix(&self.keyspaces.meta, b"")
            .map_err(storage_error)?;
        let expected_meta = if global_head == 0 { 2 } else { 3 };
        if meta.len() != expected_meta
            || !meta.iter().any(|entry| entry.key == META_MANIFEST_KEY)
            || !meta.iter().any(|entry| entry.key == META_GLOBAL_HEAD_KEY)
            || (global_head > 0) != meta.iter().any(|entry| entry.key == META_EVENT_DIGEST_KEY)
        {
            return Err(integrity("native backup metadata key closure is invalid"));
        }

        for entry in snapshot
            .scan_prefix(&self.keyspaces.content_history, b"")
            .map_err(storage_error)?
        {
            let stored: StoredContent = decode(&entry.value, "native backup record content")?;
            let policy = policy_for(&stored.record)?;
            if stored.schema_version != SCHEMA_VERSION
                || stored.record_digest != policy.record_digest
                || stored.digest != policy.content_digest
                || stored.digest != digest_bytes(&encode(&stored.record)?)
                || entry.key != history_key(&policy.record_digest, policy.revision)
                || snapshot
                    .get(&self.keyspaces.policy_history, &entry.key)
                    .map_err(storage_error)?
                    .as_deref()
                    != Some(encode(&policy)?.as_slice())
            {
                return Err(integrity(
                    "native backup content is not an exact policy-history member",
                ));
            }
        }

        for entry in snapshot
            .scan_prefix(&self.keyspaces.policy_history, b"")
            .map_err(storage_error)?
        {
            let policy: StoredPolicy = decode(&entry.value, "native backup historical policy")?;
            validate_stored_policy(&policy)?;
            if policy.transaction_from > global_head
                || policy
                    .transaction_to
                    .is_some_and(|value| value > global_head)
            {
                return Err(integrity(
                    "native backup policy transaction exceeds the global head",
                ));
            }
        }

        for entry in snapshot
            .scan_prefix(&self.keyspaces.observations_content, b"")
            .map_err(storage_error)?
        {
            let content: StoredObservationContent =
                decode(&entry.value, "native backup observation content")?;
            let digest = digest_bytes(content.observation_id.as_bytes());
            if content.schema_version != SCHEMA_VERSION
                || entry.key != digest.as_bytes()
                || content.digest
                    != canonical_digest(&(
                        &content.observation_id,
                        &content.metadata,
                        &content.content,
                    ))?
            {
                return Err(integrity("native backup observation content is invalid"));
            }
            let policy_bytes = snapshot
                .get(&self.keyspaces.observations_policy, digest.as_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native backup observation policy is absent"))?;
            let policy: StoredObservationPolicy =
                decode(&policy_bytes, "native backup observation policy")?;
            if policy.content_digest != content.digest {
                return Err(integrity(
                    "native backup observation reverse binding is invalid",
                ));
            }
        }

        for entry in snapshot
            .scan_prefix(&self.keyspaces.workspace_map, b"")
            .map_err(storage_error)?
        {
            let mapping: super::CommitMap = decode(&entry.value, "native backup commit map")?;
            validate_workspace_state(&mapping.state, &mapping.state.workspace_digest)?;
            if mapping.schema_version != SCHEMA_VERSION
                || mapping.global_commit == 0
                || mapping.global_commit > global_head
                || entry.key
                    != workspace_map_key(
                        &mapping.state.workspace_digest,
                        mapping.state.watermarks.journal,
                    )
            {
                return Err(integrity("native backup workspace map is invalid"));
            }
            let event_bytes = snapshot
                .get(&self.keyspaces.events, &mapping.global_commit.to_be_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native backup mapped event is absent"))?;
            let event: StoredEvent = decode(&event_bytes, "native backup mapped event")?;
            if event.event_digest != event_digest(&event)?
                || event.workspace_digest != mapping.state.workspace_digest
                || event.workspace_commit != mapping.state.watermarks.journal
            {
                return Err(integrity(
                    "native backup workspace map event binding is invalid",
                ));
            }
        }

        for entry in snapshot
            .scan_prefix(&self.keyspaces.workspace, b"")
            .map_err(storage_error)?
        {
            let state: WorkspaceState = decode(&entry.value, "native backup workspace state")?;
            let digest = std::str::from_utf8(&entry.key)
                .map_err(|_| integrity("native backup workspace key is invalid"))?;
            validate_workspace_state(&state, digest)?;
            if state.latest_global_commit > global_head || state.watermarks.journal == 0 {
                return Err(integrity("native backup workspace head is invalid"));
            }
            let mapping_bytes = snapshot
                .get(
                    &self.keyspaces.workspace_map,
                    &workspace_map_key(digest, state.watermarks.journal),
                )
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native backup workspace head map is absent"))?;
            let mapping: super::CommitMap =
                decode(&mapping_bytes, "native backup workspace head map")?;
            if mapping.global_commit != state.latest_global_commit || mapping.state != state {
                return Err(integrity(
                    "native backup workspace head differs from its map",
                ));
            }
        }
        Ok(())
    }

    fn require_pristine_restore_target<S: ReadSnapshot>(&self, snapshot: &S) -> ServiceResult<()> {
        let manifest_bytes = snapshot
            .get(&self.keyspaces.meta, META_MANIFEST_KEY)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("native restore target manifest is absent"))?;
        let manifest: Manifest = decode(&manifest_bytes, "native restore target manifest")?;
        validate_manifest(&manifest, &self.database_id)?;
        if self.global_head(snapshot)? != 0 {
            return Err(non_pristine_restore());
        }
        for keyspace in self.keyspaces.all() {
            let entries = snapshot.scan_prefix(keyspace, b"").map_err(storage_error)?;
            if keyspace == &self.keyspaces.meta {
                if entries.len() != 2
                    || !entries.iter().any(|entry| entry.key == META_MANIFEST_KEY)
                    || !entries
                        .iter()
                        .any(|entry| entry.key == META_GLOBAL_HEAD_KEY)
                {
                    return Err(non_pristine_restore());
                }
            } else if !entries.is_empty() {
                return Err(non_pristine_restore());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static AFTER_REGISTRATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn non_pristine_restore() -> ServiceError {
    ServiceError::new(
        ErrorCode::Unsupported,
        "native logical restore requires a pristine target",
        false,
    )
    .with_context(
        Vec::new(),
        Some("restore:pristine-target-only".to_owned()),
        Some("open a fresh native sidecar with the same database identity".to_owned()),
        None,
    )
}

fn validate_backup_entry(entry: &Entry) -> ServiceResult<()> {
    if entry.key.is_empty() || entry.key.len() > MAX_BACKUP_KEY_BYTES {
        return Err(exhausted("native backup key exceeds the 64 KiB limit"));
    }
    if entry.value.len() > MAX_BACKUP_VALUE_BYTES {
        return Err(exhausted("native backup value exceeds the 16 MiB limit"));
    }
    Ok(())
}

fn encode_backup(archive: &NativeBackup) -> ServiceResult<Vec<u8>> {
    let mut output = Vec::new();
    push_bytes(&mut output, BACKUP_MAGIC)?;
    push_u16(
        &mut output,
        if archive.format == NATIVE_ENCRYPTED_BACKUP_FORMAT {
            3
        } else if archive.format == NATIVE_BACKUP_FORMAT {
            1
        } else {
            2
        },
    )?;
    push_string(&mut output, &archive.format)?;
    push_string(&mut output, FORMAT_NAME)?;
    push_string(&mut output, &archive.database_id)?;
    push_u64(&mut output, archive.commit_seq)?;
    push_string(&mut output, &archive.deep_digest)?;
    if let Some(authority) = archive.custody_authority {
        push_bytes(&mut output, authority.as_bytes())?;
    }
    let keyspace_count = u16::try_from(archive.keyspaces.len())
        .map_err(|_| exhausted("native backup keyspace count exceeds u16"))?;
    push_u16(&mut output, keyspace_count)?;
    for keyspace in &archive.keyspaces {
        push_string(&mut output, &keyspace.name)?;
        let entry_count = u64::try_from(keyspace.entries.len())
            .map_err(|_| exhausted("native backup entry count exceeds u64"))?;
        push_u64(&mut output, entry_count)?;
        for entry in &keyspace.entries {
            validate_backup_entry(entry)?;
            push_len_prefixed(&mut output, &entry.key)?;
            push_len_prefixed(&mut output, &entry.value)?;
        }
    }
    let footer = *blake3::hash(&output).as_bytes();
    push_bytes(&mut output, &footer)?;
    Ok(output)
}

fn decode_backup(bytes: &[u8], database_id: &str) -> ServiceResult<NativeBackup> {
    if bytes.len() > MAX_BACKUP_BYTES || bytes.len() < BACKUP_MAGIC.len() + BACKUP_FOOTER_BYTES {
        return Err(integrity("native backup length is invalid"));
    }
    let body_len = bytes
        .len()
        .checked_sub(BACKUP_FOOTER_BYTES)
        .ok_or_else(|| integrity("native backup footer is absent"))?;
    let (body, footer) = bytes.split_at(body_len);
    if footer != blake3::hash(body).as_bytes() {
        return Err(integrity("native backup footer digest is invalid"));
    }
    let mut reader = BackupReader::new(body);
    let magic = reader.take(BACKUP_MAGIC.len())?;
    let schema = reader.read_u16()?;
    let format = reader.read_string(128)?;
    if magic != BACKUP_MAGIC
        || !matches!(
            (schema, format.as_str()),
            (1, NATIVE_BACKUP_FORMAT)
                | (2, NATIVE_CONTINUOUS_BACKUP_FORMAT)
                | (3, NATIVE_ENCRYPTED_BACKUP_FORMAT)
        )
        || reader.read_string(128)? != FORMAT_NAME
    {
        return Err(ServiceError::new(
            ErrorCode::FormatIncompatible,
            "native backup header is incompatible",
            false,
        ));
    }
    let archive_database_id = reader.read_string(1_024)?;
    if archive_database_id != database_id {
        return Err(ServiceError::new(
            ErrorCode::FormatIncompatible,
            "native backup database identity differs from the restore target",
            false,
        ));
    }
    let commit_seq = reader.read_u64()?;
    let deep_digest = reader.read_string(64)?;
    if deep_digest.len() != 64 || blake3::Hash::from_hex(&deep_digest).is_err() {
        return Err(integrity("native backup deep digest is invalid"));
    }
    let custody_authority = if schema == 3 {
        let id = uuid::Uuid::from_slice(reader.take(16)?)
            .map_err(|_| integrity("backup custody authority is invalid"))?;
        if id.is_nil() {
            return Err(integrity("backup custody authority is nil"));
        }
        Some(id)
    } else {
        None
    };
    let expected_keyspaces = super::Keyspaces::new()?
        .all()
        .into_iter()
        .take(if schema == 1 { 11 } else { 12 })
        .map(|keyspace| keyspace.as_str().to_owned())
        .collect::<Vec<_>>();
    if usize::from(reader.read_u16()?) != expected_keyspaces.len() {
        return Err(ServiceError::new(
            ErrorCode::FormatIncompatible,
            "native backup keyspace count is incompatible",
            false,
        ));
    }
    let mut total_entries = 0_usize;
    let mut total_raw_bytes = 0_usize;
    let mut keyspaces = Vec::with_capacity(expected_keyspaces.len());
    for expected_name in expected_keyspaces {
        let name = reader.read_string(128)?;
        if name != expected_name {
            return Err(ServiceError::new(
                ErrorCode::FormatIncompatible,
                "native backup keyspace order is incompatible",
                false,
            ));
        }
        let count = usize::try_from(reader.read_u64()?)
            .map_err(|_| exhausted("native backup entry count exceeds this platform"))?;
        total_entries = total_entries
            .checked_add(count)
            .ok_or_else(|| exhausted("native backup entry count overflowed"))?;
        if total_entries > MAX_BACKUP_ENTRIES {
            return Err(exhausted(
                "native backup exceeds the two-million-entry limit",
            ));
        }
        let mut entries = Vec::with_capacity(count.min(BACKUP_SCAN_PAGE_ENTRIES));
        let mut previous: Option<Vec<u8>> = None;
        for _ in 0..count {
            let key = reader.read_len_prefixed(MAX_BACKUP_KEY_BYTES)?;
            let value = reader.read_len_prefixed(MAX_BACKUP_VALUE_BYTES)?;
            let entry = Entry { key, value };
            validate_backup_entry(&entry)?;
            if previous.as_ref().is_some_and(|value| value >= &entry.key) {
                return Err(integrity(
                    "native backup entries are not in canonical key order",
                ));
            }
            total_raw_bytes = total_raw_bytes
                .checked_add(entry.key.len())
                .and_then(|bytes| bytes.checked_add(entry.value.len()))
                .ok_or_else(|| exhausted("native backup byte count overflowed"))?;
            if total_raw_bytes > MAX_BACKUP_RAW_BYTES {
                return Err(exhausted("native backup exceeds the 128 MiB raw limit"));
            }
            previous = Some(entry.key.clone());
            entries.push(entry);
        }
        keyspaces.push(BackupKeyspace { name, entries });
    }
    if !reader.is_finished() {
        return Err(integrity("native backup contains trailing body bytes"));
    }
    let archive = NativeBackup {
        format,
        database_id: archive_database_id,
        commit_seq,
        deep_digest,
        custody_authority,
        keyspaces,
    };
    if encode_backup(&archive)? != bytes {
        return Err(integrity("native backup encoding is non-canonical"));
    }
    Ok(archive)
}

struct BackupSnapshot<'a> {
    archive: &'a NativeBackup,
    rows: BTreeMap<&'a str, &'a [Entry]>,
}

impl<'a> BackupSnapshot<'a> {
    fn new(archive: &'a NativeBackup) -> Self {
        Self {
            archive,
            rows: archive
                .keyspaces
                .iter()
                .map(|keyspace| (keyspace.name.as_str(), keyspace.entries.as_slice()))
                .collect(),
        }
    }
}

impl ReadSnapshot for BackupSnapshot<'_> {
    fn sequence(&self) -> u64 {
        self.archive.commit_seq
    }

    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
        Ok(self.rows.get(keyspace.as_str()).and_then(|entries| {
            entries
                .binary_search_by(|entry| entry.key.as_slice().cmp(key))
                .ok()
                .map(|index| entries[index].value.clone())
        }))
    }

    fn scan_prefix(
        &self,
        keyspace: &Keyspace,
        prefix: &[u8],
    ) -> contextdb_storage::Result<Vec<Entry>> {
        Ok(self
            .rows
            .get(keyspace.as_str())
            .into_iter()
            .flat_map(|entries| entries.iter())
            .filter(|entry| entry.key.starts_with(prefix))
            .cloned()
            .collect())
    }
}

struct BackupReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> BackupReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, count: usize) -> ServiceResult<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| integrity("native backup is truncated"))?;
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> ServiceResult<u16> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| integrity("native backup u16 is truncated"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> ServiceResult<u32> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| integrity("native backup u32 is truncated"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> ServiceResult<u64> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| integrity("native backup u64 is truncated"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_string(&mut self, maximum: usize) -> ServiceResult<String> {
        let length = usize::from(self.read_u16()?);
        if length == 0 || length > maximum {
            return Err(integrity("native backup string length is invalid"));
        }
        let bytes = self.take(length)?;
        std::str::from_utf8(bytes)
            .map(ToOwned::to_owned)
            .map_err(|_| integrity("native backup string is not UTF-8"))
    }

    fn read_len_prefixed(&mut self, maximum: usize) -> ServiceResult<Vec<u8>> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_| exhausted("native backup row length exceeds this platform"))?;
        if length > maximum {
            return Err(exhausted("native backup row exceeds its byte limit"));
        }
        self.take(length).map(ToOwned::to_owned)
    }

    const fn is_finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> ServiceResult<()> {
    let required = output
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| exhausted("native backup encoding length overflowed"))?;
    if required > MAX_BACKUP_BYTES {
        return Err(exhausted("native backup exceeds the 256 MiB limit"));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16) -> ServiceResult<()> {
    push_bytes(output, &value.to_be_bytes())
}

fn push_u64(output: &mut Vec<u8>, value: u64) -> ServiceResult<()> {
    push_bytes(output, &value.to_be_bytes())
}

fn push_string(output: &mut Vec<u8>, value: &str) -> ServiceResult<()> {
    let length =
        u16::try_from(value.len()).map_err(|_| exhausted("native backup string exceeds u16"))?;
    if length == 0 {
        return Err(integrity("native backup string is empty"));
    }
    push_u16(output, length)?;
    push_bytes(output, value.as_bytes())
}

fn push_len_prefixed(output: &mut Vec<u8>, value: &[u8]) -> ServiceResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| exhausted("native backup row length exceeds u32"))?;
    push_bytes(output, &length.to_be_bytes())?;
    push_bytes(output, value)
}

#[cfg(test)]
pub(super) fn maximum_native_backup_bytes() -> usize {
    MAX_BACKUP_BYTES
}

const _: () = assert!(MAX_BACKUP_VALUE_BYTES >= MAX_JSON_BYTES);
