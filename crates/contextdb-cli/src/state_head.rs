//! Externally anchored state-head custody for the standalone CLI host.
//!
//! The logical archive is deliberately portable and therefore replayable.  A
//! keyed, external state head binds the currently accepted archive digest to
//! its canonical path, logical database identity, and monotonic commit. Schema
//! v2 also binds a monotonic durable generation and keyed ledger root covering
//! production receipts which need not advance the semantic archive (notably
//! resumable stream frames). File replacement uses an authenticated
//! `active + pending` transaction so crash recovery accepts exactly the old or
//! the staged new archive, never an arbitrary third value.
//!
//! The external authority is part of the trusted computing base.  Replaying a
//! valid old archive *and* a valid old authority snapshot is not something a
//! MAC can detect.  Production custody therefore has to prevent authority
//! rollback (for example with a monotonic secret-store/KMS adapter).  On
//! Windows this reference host uses HKCU rather than another raceable file; on
//! Unix it requires an explicitly external owner-controlled file.
//!
//! Unix activation syncs both the replacement and its parent directory.  With
//! `unsafe_code` forbidden, the safe Windows registry wrapper does not expose
//! `RegFlushKey`; HKCU updates therefore provide process-crash reconciliation
//! after the OS accepts a write, but this reference host does not claim a
//! power-loss-stable registry flush.  Deployments requiring that stronger
//! guarantee need a monotonic external authority adapter.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Read;
#[cfg(unix)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const STATE_HEAD_FILE_ENV: &str = "CONTEXTDB_STATE_HEAD_FILE";
pub const STATE_HEAD_ID_ENV: &str = "CONTEXTDB_STATE_HEAD_ID";

pub const MAX_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;
const MAX_AUTHORITY_BYTES: usize = 16 * 1024;
const AUTHORITY_SCHEMA_VERSION: u16 = 2;
const LEGACY_AUTHORITY_SCHEMA_VERSION: u16 = 1;
const ARCHIVE_FORMAT: &str = "contextdb.logical.v1";
const HEAD_KEY_CONTEXT: &str = "contextdb/cli-state-head-key/v1";
#[cfg(not(test))]
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const LOCK_TIMEOUT: Duration = Duration::from_millis(150);

type HeadResult<T> = Result<T, String>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveIdentity {
    pub database_id: String,
    pub commit_seq: u64,
    pub archive_digest: String,
}

/// Externally anchored monotonic durable-ledger identity. The digest is a
/// keyed content-free binding selected by the production storage host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableIdentity {
    pub generation: u64,
    pub ledger_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadRecord {
    canonical_path_digest: String,
    database_id: String,
    commit_seq: u64,
    archive_digest: String,
    durable_generation: u64,
    ledger_digest: String,
    previous_head_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyHeadRecord {
    canonical_path_digest: String,
    database_id: String,
    commit_seq: u64,
    archive_digest: String,
    previous_head_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct UnsignedAuthority<'a> {
    schema_version: u16,
    authority_binding: &'a str,
    active: &'a Option<HeadRecord>,
    pending: &'a Option<HeadRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEnvelope {
    schema_version: u16,
    authority_binding: String,
    active: Option<HeadRecord>,
    pending: Option<HeadRecord>,
    mac: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAuthorityEnvelope {
    schema_version: u16,
    authority_binding: String,
    active: Option<LegacyHeadRecord>,
    pending: Option<LegacyHeadRecord>,
    mac: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct UnsignedLegacyAuthority<'a> {
    schema_version: u16,
    authority_binding: &'a str,
    active: &'a Option<LegacyHeadRecord>,
    pending: &'a Option<LegacyHeadRecord>,
}

#[derive(Deserialize)]
struct LogicalArchiveHeader {
    format: String,
    database_id: String,
    head: u64,
}

#[derive(Clone)]
enum AuthorityBackend {
    #[cfg(unix)]
    File(PathBuf),
    #[cfg(windows)]
    Registry { key_path: String },
    /// Process-local authority used by quiesced custody verification. It is
    /// deliberately available outside tests: recovery against a detached
    /// filesystem snapshot must never write the live external authority.
    Detached(Arc<std::sync::Mutex<Option<Vec<u8>>>>),
    #[cfg(test)]
    Memory(Arc<std::sync::Mutex<Option<Vec<u8>>>>),
}

/// A state-head backend plus an exclusive cross-process transaction lock.
#[derive(Clone)]
pub struct StateHeadStore {
    backend: AuthorityBackend,
    canonical_archive_path: PathBuf,
    canonical_path_digest: String,
    authority_binding: String,
    _lock: Option<Arc<File>>,
    #[cfg(test)]
    fail_next_backend_write: Arc<AtomicBool>,
    #[cfg(test)]
    fail_final_activation: Arc<AtomicBool>,
}

impl std::fmt::Debug for StateHeadStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateHeadStore")
            .field("canonical_archive_path", &"[REDACTED]")
            .field("canonical_path_digest", &"[REDACTED]")
            .field("authority_binding", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl StateHeadStore {
    /// Resolves the platform authority selected by the host environment and
    /// holds its lock until this value (and all clones) are dropped.
    pub fn open(archive_path: &Path) -> HeadResult<Self> {
        let canonical_archive_path = canonical_archive_path(archive_path)?;
        let canonical_path_digest = path_digest(&canonical_archive_path);
        let file_value = std::env::var_os(STATE_HEAD_FILE_ENV);
        let id_value = std::env::var_os(STATE_HEAD_ID_ENV);

        #[cfg(unix)]
        {
            if id_value.is_some() {
                return Err(format!(
                    "{STATE_HEAD_ID_ENV} is Windows-only; use {STATE_HEAD_FILE_ENV} on Unix"
                ));
            }
            let value = file_value.ok_or_else(|| {
                format!(
                    "an external state-head authority is required through {STATE_HEAD_FILE_ENV}"
                )
            })?;
            let path = PathBuf::from(value);
            let canonical_head_path = validate_unix_authority_path(&canonical_archive_path, &path)?;
            let authority_binding = format!("unix-file:{}", path_digest(&canonical_head_path));
            let lock = acquire_file_lock(&lock_path_for(&canonical_head_path)?)?;
            Ok(Self {
                backend: AuthorityBackend::File(canonical_head_path),
                canonical_archive_path,
                canonical_path_digest,
                authority_binding,
                _lock: Some(Arc::new(lock)),
                #[cfg(test)]
                fail_next_backend_write: Arc::new(AtomicBool::new(false)),
                #[cfg(test)]
                fail_final_activation: Arc::new(AtomicBool::new(false)),
            })
        }

        #[cfg(windows)]
        {
            if file_value.is_some() {
                return Err(format!(
                    "{STATE_HEAD_FILE_ENV} is disabled on Windows because safe DACL and reparse-point custody cannot be proven; use the HKCU authority selected by {STATE_HEAD_ID_ENV}"
                ));
            }
            let id = id_value
                .ok_or_else(|| {
                    format!("an HKCU state-head authority is required through {STATE_HEAD_ID_ENV}")
                })?
                .into_string()
                .map_err(|_| format!("{STATE_HEAD_ID_ENV} must be valid Unicode"))?;
            validate_authority_id(&id)?;
            let id_digest = blake3::hash(id.as_bytes()).to_hex().to_string();
            let authority_binding = format!("windows-hkcu:{id_digest}");
            let key_path = format!("Software\\ContextDB\\StateHeads\\{id_digest}");
            let lock = acquire_windows_registry_lock(&id_digest)?;
            Ok(Self {
                backend: AuthorityBackend::Registry { key_path },
                canonical_archive_path,
                canonical_path_digest,
                authority_binding,
                _lock: Some(Arc::new(lock)),
                #[cfg(test)]
                fail_next_backend_write: Arc::new(AtomicBool::new(false)),
                #[cfg(test)]
                fail_final_activation: Arc::new(AtomicBool::new(false)),
            })
        }
    }

    /// Snapshots one already authenticated authority into a process-local
    /// backend for verification against `detached_archive_path`.
    ///
    /// The archive path used for filesystem I/O changes, but both bindings
    /// retained inside the authenticated authority remain those of the live
    /// source. Any recovery writes therefore update only the detached RAM
    /// backend while validating the exact source-bound records.
    pub(crate) fn detached_snapshot(
        &self,
        detached_archive_path: &Path,
        key: &[u8; 32],
    ) -> HeadResult<Self> {
        let bytes = self
            .read_backend()?
            .ok_or_else(|| "state-head authority is absent".to_owned())?;
        self.decode_current_envelope(&bytes, key)?;
        let canonical_archive_path = canonical_archive_path(detached_archive_path)?;
        Ok(Self {
            backend: AuthorityBackend::Detached(Arc::new(std::sync::Mutex::new(Some(bytes)))),
            canonical_archive_path,
            canonical_path_digest: self.canonical_path_digest.clone(),
            authority_binding: self.authority_binding.clone(),
            _lock: None,
            #[cfg(test)]
            fail_next_backend_write: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fail_final_activation: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) fn archive_path(&self) -> &Path {
        &self.canonical_archive_path
    }

    #[cfg(test)]
    pub fn memory(archive_path: &Path) -> HeadResult<Self> {
        let canonical_archive_path = canonical_archive_path(archive_path)?;
        let canonical_path_digest = path_digest(&canonical_archive_path);
        Ok(Self {
            backend: AuthorityBackend::Memory(Arc::new(std::sync::Mutex::new(None))),
            canonical_archive_path,
            canonical_path_digest: canonical_path_digest.clone(),
            authority_binding: format!("test-memory:{canonical_path_digest}"),
            _lock: None,
            fail_next_backend_write: Arc::new(AtomicBool::new(false)),
            fail_final_activation: Arc::new(AtomicBool::new(false)),
        })
    }

    #[cfg(test)]
    pub fn memory_for_same_authority(&self, archive_path: &Path) -> HeadResult<Self> {
        let AuthorityBackend::Memory(contents) = &self.backend else {
            return Err("test authority is not memory-backed".to_owned());
        };
        let canonical_archive_path = canonical_archive_path(archive_path)?;
        Ok(Self {
            backend: AuthorityBackend::Memory(contents.clone()),
            canonical_path_digest: path_digest(&canonical_archive_path),
            canonical_archive_path,
            authority_binding: self.authority_binding.clone(),
            _lock: None,
            fail_next_backend_write: self.fail_next_backend_write.clone(),
            fail_final_activation: self.fail_final_activation.clone(),
        })
    }

    #[cfg(test)]
    pub fn raw_authority(&self) -> HeadResult<Option<Vec<u8>>> {
        let AuthorityBackend::Memory(contents) = &self.backend else {
            return Err("test authority is not memory-backed".to_owned());
        };
        contents
            .lock()
            .map_err(|_| "test authority lock poisoned".to_owned())
            .map(|guard| guard.clone())
    }

    #[cfg(test)]
    pub fn replace_raw_authority(&self, value: Option<Vec<u8>>) -> HeadResult<()> {
        let AuthorityBackend::Memory(contents) = &self.backend else {
            return Err("test authority is not memory-backed".to_owned());
        };
        *contents
            .lock()
            .map_err(|_| "test authority lock poisoned".to_owned())? = value;
        Ok(())
    }

    #[cfg(test)]
    pub fn fail_next_backend_write_for_test(&self) {
        self.fail_next_backend_write.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub fn fail_final_activation_for_test(&self) {
        self.fail_final_activation.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub fn adopt_existing_for_test(
        &self,
        key: &[u8; 32],
        bytes: &[u8],
    ) -> HeadResult<ArchiveIdentity> {
        let identity = inspect_archive(bytes)?;
        let record = self.record_for(
            &identity,
            DurableIdentity {
                generation: 0,
                ledger_digest: empty_ledger_digest(),
            },
            None,
        );
        self.write_envelope(key, Some(record), None)?;
        Ok(identity)
    }

    /// Installs the first archive into an empty destination.  Once the backend
    /// accepts the pending head, recovery can resume only with the exact same
    /// bytes.
    pub fn bootstrap(&self, key: &[u8; 32], bytes: &[u8]) -> HeadResult<ArchiveIdentity> {
        self.bootstrap_with_ledger(key, bytes, 0, &empty_ledger_digest())
    }

    /// Installs the first archive together with the exact durable-ledger root.
    pub fn bootstrap_with_ledger(
        &self,
        key: &[u8; 32],
        bytes: &[u8],
        durable_generation: u64,
        ledger_digest: &str,
    ) -> HeadResult<ArchiveIdentity> {
        let identity = inspect_archive(bytes)?;
        let durable = validate_durable_identity(durable_generation, ledger_digest)?;
        let candidate = self.record_for(&identity, durable, None);
        let existing = self.read_envelope(key)?;
        match existing {
            None => {
                if self.canonical_archive_path.exists() {
                    return Err(
                        "destination archive exists without an authenticated state head; import into a new empty path instead"
                            .to_owned(),
                    );
                }
                self.write_envelope(key, None, Some(candidate.clone()))?;
            }
            Some(envelope)
                if envelope.active.is_none()
                    && envelope.pending.as_ref() == Some(&candidate)
                    && !self.canonical_archive_path.exists() => {}
            Some(envelope)
                if envelope.active.is_none()
                    && envelope.pending.as_ref() == Some(&candidate)
                    && self.canonical_archive_path.exists() =>
            {
                let installed = read_archive_bounded(&self.canonical_archive_path)?;
                if !record_matches_bytes(&candidate, &installed)? {
                    return Err(
                        "incomplete bootstrap contains neither the selected archive nor an empty destination"
                            .to_owned(),
                    );
                }
                self.write_envelope(key, Some(candidate), None)?;
                return Ok(identity);
            }
            Some(_) => {
                return Err(
                    "state-head authority already contains a database; overwriting live state is disabled"
                        .to_owned(),
                );
            }
        }

        super::atomic_write(&self.canonical_archive_path, bytes, false)
            .map_err(|error| error.to_string())?;
        self.write_envelope(key, Some(candidate), None)?;
        Ok(identity)
    }

    /// Reads one bounded archive and reconciles an interrupted exact
    /// active/pending transaction before returning it.
    pub fn load_verified(&self, key: &[u8; 32]) -> HeadResult<(Vec<u8>, ArchiveIdentity)> {
        let (bytes, identity, _) = self.load_verified_with_ledger(key)?;
        Ok((bytes, identity))
    }

    /// Returns the bounded authenticated active authority identity without
    /// opening or materializing the archive. A pending transaction is not a
    /// readiness proof: normal recovery must reconcile it first.
    pub fn authenticated_active_identity(
        &self,
        key: &[u8; 32],
    ) -> HeadResult<(ArchiveIdentity, DurableIdentity)> {
        let envelope = self.read_envelope(key)?.ok_or_else(|| {
            "archive has no external authenticated state head; clone it with `contextdb import` into a new empty destination"
                .to_owned()
        })?;
        if envelope.pending.is_some() {
            return Err("state-head transaction requires recovery before readiness".to_owned());
        }
        let active = envelope
            .active
            .as_ref()
            .ok_or_else(|| "state-head active record is absent".to_owned())?;
        Ok((
            ArchiveIdentity {
                database_id: active.database_id.clone(),
                commit_seq: active.commit_seq,
                archive_digest: active.archive_digest.clone(),
            },
            durable_from_record(active),
        ))
    }

    /// Reads and verifies the archive plus its externally anchored durable
    /// ledger generation/root.
    pub fn load_verified_with_ledger(
        &self,
        key: &[u8; 32],
    ) -> HeadResult<(Vec<u8>, ArchiveIdentity, DurableIdentity)> {
        let envelope = self.read_envelope(key)?.ok_or_else(|| {
            "archive has no external authenticated state head; clone it with `contextdb import` into a new empty destination"
                .to_owned()
        })?;
        let bytes = read_archive_bounded(&self.canonical_archive_path)?;
        let identity = inspect_archive(&bytes)?;
        let active_matches = envelope
            .active
            .as_ref()
            .is_some_and(|head| record_matches(head, &identity, &self.canonical_path_digest));
        let pending_matches = envelope
            .pending
            .as_ref()
            .is_some_and(|head| record_matches(head, &identity, &self.canonical_path_digest));

        let durable = if pending_matches {
            let pending = envelope
                .pending
                .ok_or_else(|| "state-head pending record disappeared".to_owned())?;
            let durable = durable_from_record(&pending);
            self.write_envelope(key, Some(pending), None)?;
            durable
        } else if active_matches {
            let durable = envelope
                .active
                .as_ref()
                .map(durable_from_record)
                .ok_or_else(|| "state-head active record disappeared".to_owned())?;
            if envelope.pending.is_some() {
                self.write_envelope(key, envelope.active, None)?;
            }
            durable
        } else {
            return Err(
                "archive does not match the authenticated active or pending state head (rollback, path swap, or tampering detected)"
                    .to_owned(),
            );
        };
        Ok((bytes, identity, durable))
    }

    /// Advances an already anchored database through the two-phase state-head
    /// transaction.  Equal canonical bytes are a no-op; every changed archive
    /// must strictly advance the logical head.
    #[cfg(any(feature = "current-server", feature = "mcp", test))]
    pub fn advance(&self, key: &[u8; 32], bytes: &[u8]) -> HeadResult<ArchiveIdentity> {
        let (_, _, durable) = self.load_verified_with_ledger(key)?;
        let generation = durable
            .generation
            .checked_add(1)
            .ok_or_else(|| "durable ledger generation is exhausted".to_owned())?;
        let digest = compatibility_ledger_digest(generation, &durable.ledger_digest, bytes);
        self.advance_with_ledger(key, bytes, generation, &digest)
    }

    /// Advances the semantic archive while atomically binding the exact
    /// already-synchronized production-ledger generation/root.
    pub fn advance_with_ledger(
        &self,
        key: &[u8; 32],
        bytes: &[u8],
        durable_generation: u64,
        ledger_digest: &str,
    ) -> HeadResult<ArchiveIdentity> {
        let (_current_bytes, current_identity, current_durable) =
            self.load_verified_with_ledger(key)?;
        let current_envelope = self
            .read_envelope(key)?
            .ok_or_else(|| "state-head authority disappeared while locked".to_owned())?;
        let active = current_envelope
            .active
            .ok_or_else(|| "state-head authority has no active record".to_owned())?;
        let candidate_identity = inspect_archive(bytes)?;
        let candidate_durable = validate_durable_identity(durable_generation, ledger_digest)?;
        if candidate_identity == current_identity && candidate_durable == current_durable {
            return Ok(candidate_identity);
        }
        if candidate_identity.database_id != current_identity.database_id {
            return Err("a state-head advance cannot change logical database identity".to_owned());
        }
        if candidate_identity.commit_seq <= current_identity.commit_seq {
            return Err(
                "a changed archive must strictly advance commit_seq; live rollback/replacement is disabled"
                    .to_owned(),
            );
        }
        if candidate_durable.generation <= current_durable.generation {
            return Err(
                "a changed archive must strictly advance the durable ledger generation".to_owned(),
            );
        }
        let previous = head_digest(&active)?;
        let candidate = self.record_for(&candidate_identity, candidate_durable, Some(previous));
        self.write_envelope(key, Some(active), Some(candidate.clone()))?;
        super::atomic_write(&self.canonical_archive_path, bytes, true)
            .map_err(|error| error.to_string())?;
        #[cfg(test)]
        if self.fail_final_activation.swap(false, Ordering::SeqCst) {
            return Err("injected final state-head activation failure".to_owned());
        }
        self.write_envelope(key, Some(candidate), None)?;
        Ok(candidate_identity)
    }

    /// Advances only the externally anchored durable-ledger root after Fjall
    /// has already synchronized the exact successor. Semantic bytes remain
    /// unchanged.
    pub fn advance_ledger(
        &self,
        key: &[u8; 32],
        expected_archive: &ArchiveIdentity,
        durable_generation: u64,
        ledger_digest: &str,
    ) -> HeadResult<DurableIdentity> {
        let (_bytes, current_identity, current_durable) = self.load_verified_with_ledger(key)?;
        if &current_identity != expected_archive {
            return Err("durable ledger advance is bound to another semantic archive".to_owned());
        }
        let candidate_durable = validate_durable_identity(durable_generation, ledger_digest)?;
        if candidate_durable == current_durable {
            return Ok(candidate_durable);
        }
        if candidate_durable.generation <= current_durable.generation {
            return Err("durable ledger generation must strictly advance".to_owned());
        }
        let envelope = self
            .read_envelope(key)?
            .ok_or_else(|| "state-head authority disappeared while locked".to_owned())?;
        let active = envelope
            .active
            .ok_or_else(|| "state-head authority has no active record".to_owned())?;
        let previous = head_digest(&active)?;
        let candidate =
            self.record_for(&current_identity, candidate_durable.clone(), Some(previous));
        self.write_envelope(key, Some(active), Some(candidate.clone()))?;
        #[cfg(test)]
        if self.fail_final_activation.swap(false, Ordering::SeqCst) {
            return Err("injected final state-head activation failure".to_owned());
        }
        self.write_envelope(key, Some(candidate), None)?;
        Ok(candidate_durable)
    }

    /// Explicitly migrates a legacy schema-v1 authority only after exact
    /// current archive validation and a caller-supplied durable ledger root.
    /// Ordinary reads never perform this migration implicitly.
    pub fn migrate_legacy_exact(
        &self,
        key: &[u8; 32],
        bytes: &[u8],
        durable_generation: u64,
        ledger_digest: &str,
    ) -> HeadResult<DurableIdentity> {
        let legacy = self.read_legacy_envelope(key)?;
        let current = legacy
            .active
            .ok_or_else(|| "legacy state-head authority has no active record".to_owned())?;
        if legacy.pending.is_some() {
            return Err("legacy authority migration requires no pending transaction".to_owned());
        }
        let identity = inspect_archive(bytes)?;
        if !legacy_record_matches(&current, &identity, &self.canonical_path_digest)
            || read_archive_bounded(&self.canonical_archive_path)? != bytes
        {
            return Err("legacy authority migration exact-current validation failed".to_owned());
        }
        let durable = validate_durable_identity(durable_generation, ledger_digest)?;
        let record = self.record_for(&identity, durable.clone(), None);
        self.write_envelope(key, Some(record), None)?;
        Ok(durable)
    }

    /// Explicitly rebinds the schema-v2 bootstrap placeholder to the first
    /// exact production-ledger root. This is permitted only at generation
    /// zero, against unchanged exact archive bytes, before any later durable
    /// transition exists.
    pub fn bind_fresh_ledger_root(
        &self,
        key: &[u8; 32],
        bytes: &[u8],
        ledger_digest: &str,
    ) -> HeadResult<DurableIdentity> {
        let (_current_bytes, identity, durable) = self.load_verified_with_ledger(key)?;
        if durable.generation != 0 || durable.ledger_digest != empty_ledger_digest() {
            return Err("fresh ledger binding requires the generation-zero placeholder".to_owned());
        }
        if inspect_archive(bytes)? != identity
            || read_archive_bounded(&self.canonical_archive_path)? != bytes
        {
            return Err("fresh ledger binding exact-current validation failed".to_owned());
        }
        let candidate = validate_durable_identity(0, ledger_digest)?;
        let record = self.record_for(&identity, candidate.clone(), None);
        self.write_envelope(key, Some(record), None)?;
        Ok(candidate)
    }

    fn record_for(
        &self,
        identity: &ArchiveIdentity,
        durable: DurableIdentity,
        previous_head_digest: Option<String>,
    ) -> HeadRecord {
        HeadRecord {
            canonical_path_digest: self.canonical_path_digest.clone(),
            database_id: identity.database_id.clone(),
            commit_seq: identity.commit_seq,
            archive_digest: identity.archive_digest.clone(),
            durable_generation: durable.generation,
            ledger_digest: durable.ledger_digest,
            previous_head_digest,
        }
    }

    fn read_envelope(&self, key: &[u8; 32]) -> HeadResult<Option<AuthorityEnvelope>> {
        let Some(bytes) = self.read_backend()? else {
            return Ok(None);
        };
        self.decode_current_envelope(&bytes, key).map(Some)
    }

    fn decode_current_envelope(
        &self,
        bytes: &[u8],
        key: &[u8; 32],
    ) -> HeadResult<AuthorityEnvelope> {
        if bytes.len() > MAX_AUTHORITY_BYTES {
            return Err("state-head authority exceeds its size limit".to_owned());
        }
        let schema: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid state-head authority JSON: {error}"))?;
        if schema
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            == Some(u64::from(LEGACY_AUTHORITY_SCHEMA_VERSION))
        {
            return Err(
                "legacy state-head authority requires explicit exact-current migration".to_owned(),
            );
        }
        let envelope: AuthorityEnvelope = serde_json::from_value(schema)
            .map_err(|error| format!("invalid state-head authority JSON: {error}"))?;
        self.validate_envelope(&envelope, key)?;
        Ok(envelope)
    }

    fn read_legacy_envelope(&self, key: &[u8; 32]) -> HeadResult<LegacyAuthorityEnvelope> {
        let bytes = self
            .read_backend()?
            .ok_or_else(|| "legacy state-head authority is absent".to_owned())?;
        let envelope: LegacyAuthorityEnvelope = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid legacy state-head authority JSON: {error}"))?;
        if envelope.schema_version != LEGACY_AUTHORITY_SCHEMA_VERSION
            || envelope.authority_binding != self.authority_binding
        {
            return Err("legacy state-head authority binding or schema is invalid".to_owned());
        }
        for record in envelope.active.iter().chain(envelope.pending.iter()) {
            validate_legacy_record(record)?;
            if record.canonical_path_digest != self.canonical_path_digest {
                return Err(
                    "legacy state-head authority belongs to another archive path".to_owned(),
                );
            }
        }
        validate_legacy_transition_shape(envelope.active.as_ref(), envelope.pending.as_ref())?;
        let expected = legacy_authority_mac(&envelope, key)?;
        if !authenticated_hash_eq(&expected, &envelope.mac) {
            return Err("legacy state-head authority MAC is invalid".to_owned());
        }
        Ok(envelope)
    }

    fn write_envelope(
        &self,
        key: &[u8; 32],
        active: Option<HeadRecord>,
        pending: Option<HeadRecord>,
    ) -> HeadResult<()> {
        validate_transition_shape(active.as_ref(), pending.as_ref())?;
        let mut envelope = AuthorityEnvelope {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            authority_binding: self.authority_binding.clone(),
            active,
            pending,
            mac: String::new(),
        };
        envelope.mac = authority_mac(&envelope, key)?;
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|error| format!("cannot serialize state-head authority: {error}"))?;
        if bytes.len() > MAX_AUTHORITY_BYTES {
            return Err("state-head authority exceeds its size limit".to_owned());
        }
        self.write_backend(&bytes)
    }

    fn validate_envelope(&self, envelope: &AuthorityEnvelope, key: &[u8; 32]) -> HeadResult<()> {
        if envelope.schema_version != AUTHORITY_SCHEMA_VERSION
            || envelope.authority_binding != self.authority_binding
        {
            return Err("state-head authority binding or schema is invalid".to_owned());
        }
        validate_transition_shape(envelope.active.as_ref(), envelope.pending.as_ref())?;
        for record in envelope.active.iter().chain(envelope.pending.iter()) {
            validate_record(record)?;
            if record.canonical_path_digest != self.canonical_path_digest {
                return Err("state-head authority belongs to a different archive path".to_owned());
            }
        }
        let expected = authority_mac(envelope, key)?;
        if !authenticated_hash_eq(&expected, &envelope.mac) {
            return Err("state-head authority MAC is invalid".to_owned());
        }
        Ok(())
    }

    fn read_backend(&self) -> HeadResult<Option<Vec<u8>>> {
        match &self.backend {
            #[cfg(unix)]
            AuthorityBackend::File(path) => read_unix_protected_file(path, MAX_AUTHORITY_BYTES),
            #[cfg(windows)]
            AuthorityBackend::Registry { key_path } => read_registry_value(key_path),
            AuthorityBackend::Detached(contents) => contents
                .lock()
                .map_err(|_| "detached state-head authority lock poisoned".to_owned())
                .map(|guard| guard.clone()),
            #[cfg(test)]
            AuthorityBackend::Memory(contents) => contents
                .lock()
                .map_err(|_| "test state-head authority lock poisoned".to_owned())
                .map(|guard| guard.clone()),
        }
    }

    fn write_backend(&self, bytes: &[u8]) -> HeadResult<()> {
        #[cfg(test)]
        if self.fail_next_backend_write.swap(false, Ordering::SeqCst) {
            return Err("injected state-head backend write failure".to_owned());
        }
        match &self.backend {
            #[cfg(unix)]
            AuthorityBackend::File(path) => atomic_write_unix_authority(path, bytes),
            #[cfg(windows)]
            AuthorityBackend::Registry { key_path } => write_registry_value(key_path, bytes),
            AuthorityBackend::Detached(contents) => {
                *contents
                    .lock()
                    .map_err(|_| "detached state-head authority lock poisoned".to_owned())? =
                    Some(bytes.to_vec());
                Ok(())
            }
            #[cfg(test)]
            AuthorityBackend::Memory(contents) => {
                *contents
                    .lock()
                    .map_err(|_| "test state-head authority lock poisoned".to_owned())? =
                    Some(bytes.to_vec());
                Ok(())
            }
        }
    }
}

fn authority_mac(envelope: &AuthorityEnvelope, key: &[u8; 32]) -> HeadResult<String> {
    let unsigned = UnsignedAuthority {
        schema_version: envelope.schema_version,
        authority_binding: &envelope.authority_binding,
        active: &envelope.active,
        pending: &envelope.pending,
    };
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| format!("cannot serialize state-head MAC input: {error}"))?;
    let derived = blake3::derive_key(HEAD_KEY_CONTEXT, key);
    Ok(blake3::keyed_hash(&derived, &bytes).to_hex().to_string())
}

fn legacy_authority_mac(envelope: &LegacyAuthorityEnvelope, key: &[u8; 32]) -> HeadResult<String> {
    let unsigned = UnsignedLegacyAuthority {
        schema_version: envelope.schema_version,
        authority_binding: &envelope.authority_binding,
        active: &envelope.active,
        pending: &envelope.pending,
    };
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| format!("cannot serialize legacy state-head MAC input: {error}"))?;
    let derived = blake3::derive_key(HEAD_KEY_CONTEXT, key);
    Ok(blake3::keyed_hash(&derived, &bytes).to_hex().to_string())
}

fn head_digest(record: &HeadRecord) -> HeadResult<String> {
    serde_json::to_vec(record)
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        .map_err(|error| format!("cannot serialize state-head record: {error}"))
}

fn validate_transition_shape(
    active: Option<&HeadRecord>,
    pending: Option<&HeadRecord>,
) -> HeadResult<()> {
    if active.is_none() && pending.is_none() {
        return Err("state-head authority cannot be empty".to_owned());
    }
    match (active, pending) {
        (None, Some(next)) if next.previous_head_digest.is_some() => {
            Err("bootstrap state head cannot name a predecessor".to_owned())
        }
        (Some(current), Some(next)) => {
            let expected = head_digest(current)?;
            if next.previous_head_digest.as_deref() != Some(expected.as_str())
                || next.database_id != current.database_id
                || next.canonical_path_digest != current.canonical_path_digest
                || next.durable_generation <= current.durable_generation
                || (next.commit_seq < current.commit_seq)
                || (next.commit_seq == current.commit_seq
                    && (next.database_id != current.database_id
                        || next.archive_digest != current.archive_digest))
            {
                return Err("pending state head is not a strict successor".to_owned());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_record(record: &HeadRecord) -> HeadResult<()> {
    require_digest(&record.canonical_path_digest, "canonical path digest")?;
    require_digest(&record.archive_digest, "archive digest")?;
    require_digest(&record.ledger_digest, "durable ledger digest")?;
    if let Some(previous) = &record.previous_head_digest {
        require_digest(previous, "previous state-head digest")?;
    }
    if record.database_id.is_empty()
        || record.database_id.len() > 1_024
        || record.database_id.chars().any(char::is_control)
    {
        return Err("state-head database identity is invalid".to_owned());
    }
    Ok(())
}

fn validate_legacy_record(record: &LegacyHeadRecord) -> HeadResult<()> {
    require_digest(&record.canonical_path_digest, "canonical path digest")?;
    require_digest(&record.archive_digest, "archive digest")?;
    if let Some(previous) = &record.previous_head_digest {
        require_digest(previous, "previous state-head digest")?;
    }
    if record.database_id.is_empty()
        || record.database_id.len() > 1_024
        || record.database_id.chars().any(char::is_control)
    {
        return Err("legacy state-head database identity is invalid".to_owned());
    }
    Ok(())
}

fn validate_legacy_transition_shape(
    active: Option<&LegacyHeadRecord>,
    pending: Option<&LegacyHeadRecord>,
) -> HeadResult<()> {
    if active.is_none() && pending.is_none() {
        return Err("legacy state-head authority cannot be empty".to_owned());
    }
    match (active, pending) {
        (None, Some(next)) if next.previous_head_digest.is_some() => {
            Err("legacy bootstrap head cannot name a predecessor".to_owned())
        }
        (Some(current), Some(next)) => {
            let expected = serde_json::to_vec(current)
                .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
                .map_err(|error| format!("cannot serialize legacy state-head record: {error}"))?;
            if next.previous_head_digest.as_deref() != Some(expected.as_str())
                || next.database_id != current.database_id
                || next.canonical_path_digest != current.canonical_path_digest
                || next.commit_seq <= current.commit_seq
            {
                return Err("legacy pending state head is not a strict successor".to_owned());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn require_digest(value: &str, label: &str) -> HeadResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not canonical lowercase hex"));
    }
    Ok(())
}

fn authenticated_hash_eq(expected: &str, candidate: &str) -> bool {
    if require_digest(expected, "expected authenticated digest").is_err()
        || require_digest(candidate, "authenticated digest").is_err()
    {
        return false;
    }
    let Ok(expected) = blake3::Hash::from_hex(expected) else {
        return false;
    };
    let Ok(candidate) = blake3::Hash::from_hex(candidate) else {
        return false;
    };
    expected == candidate
}

fn record_matches(record: &HeadRecord, identity: &ArchiveIdentity, path_digest: &str) -> bool {
    record.canonical_path_digest == path_digest
        && record.database_id == identity.database_id
        && record.commit_seq == identity.commit_seq
        && record.archive_digest == identity.archive_digest
}

fn legacy_record_matches(
    record: &LegacyHeadRecord,
    identity: &ArchiveIdentity,
    path_digest: &str,
) -> bool {
    record.canonical_path_digest == path_digest
        && record.database_id == identity.database_id
        && record.commit_seq == identity.commit_seq
        && record.archive_digest == identity.archive_digest
}

fn durable_from_record(record: &HeadRecord) -> DurableIdentity {
    DurableIdentity {
        generation: record.durable_generation,
        ledger_digest: record.ledger_digest.clone(),
    }
}

fn validate_durable_identity(generation: u64, ledger_digest: &str) -> HeadResult<DurableIdentity> {
    require_digest(ledger_digest, "durable ledger digest")?;
    Ok(DurableIdentity {
        generation,
        ledger_digest: ledger_digest.to_owned(),
    })
}

fn empty_ledger_digest() -> String {
    blake3::hash(b"contextdb/empty-durable-ledger/v1")
        .to_hex()
        .to_string()
}

#[cfg(any(feature = "current-server", feature = "mcp", test))]
fn compatibility_ledger_digest(generation: u64, previous_digest: &str, archive: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb/compatibility-durable-ledger/v1\0");
    hasher.update(&generation.to_be_bytes());
    hasher.update(previous_digest.as_bytes());
    hasher.update(blake3::hash(archive).as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn record_matches_bytes(record: &HeadRecord, bytes: &[u8]) -> HeadResult<bool> {
    let identity = inspect_archive(bytes)?;
    Ok(record.database_id == identity.database_id
        && record.commit_seq == identity.commit_seq
        && record.archive_digest == identity.archive_digest)
}

pub fn inspect_archive(bytes: &[u8]) -> HeadResult<ArchiveIdentity> {
    if bytes.is_empty() || bytes.len() > MAX_ARCHIVE_BYTES {
        return Err("logical archive size is outside the supported bound".to_owned());
    }
    let header: LogicalArchiveHeader = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid logical archive header: {error}"))?;
    if header.format != ARCHIVE_FORMAT {
        return Err(format!(
            "unsupported logical archive format {}",
            header.format
        ));
    }
    if header.database_id.is_empty()
        || header.database_id.len() > 1_024
        || header.database_id.chars().any(char::is_control)
    {
        return Err("logical archive database identity is invalid".to_owned());
    }
    Ok(ArchiveIdentity {
        database_id: header.database_id,
        commit_seq: header.head,
        archive_digest: blake3::hash(bytes).to_hex().to_string(),
    })
}

pub fn read_archive_bounded(path: &Path) -> HeadResult<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot open state archive: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect state archive: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_ARCHIVE_BYTES as u64 {
        return Err("state archive is not a bounded regular file".to_owned());
    }
    read_bounded(&mut file, MAX_ARCHIVE_BYTES, "state archive")
}

fn read_bounded(reader: &mut impl Read, maximum: usize, label: &str) -> HeadResult<Vec<u8>> {
    let limit = u64::try_from(maximum)
        .map_err(|_| format!("{label} size limit is unsupported"))?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    if bytes.len() > maximum {
        return Err(format!("{label} exceeds its size limit"));
    }
    Ok(bytes)
}

pub(crate) fn canonical_archive_path(path: &Path) -> HeadResult<PathBuf> {
    if path.exists() {
        reject_archive_link(path)?;
        return fs::canonicalize(path)
            .map_err(|error| format!("cannot resolve state archive path: {error}"));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("cannot resolve state archive directory: {error}"))?;
    let name = path
        .file_name()
        .ok_or_else(|| "state archive path must name a file".to_owned())?;
    Ok(parent.join(name))
}

fn reject_archive_link(path: &Path) -> HeadResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect state archive path: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("state archive path cannot be a symbolic link".to_owned());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("state archive path cannot be a reparse point".to_owned());
        }
    }
    Ok(())
}

pub(crate) fn path_digest(path: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"contextdb/cli-canonical-path/v1\0");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for unit in path.as_os_str().encode_wide() {
            hasher.update(&unit.to_le_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn acquire_file_lock(path: &Path) -> HeadResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| format!("cannot open state-head transaction lock: {error}"))?;
    acquire_lock_bounded(file)
}

fn acquire_lock_bounded(file: File) -> HeadResult<File> {
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if started.elapsed() < LOCK_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(TryLockError::WouldBlock) => {
                return Err("state-head transaction lock timed out".to_owned());
            }
            Err(TryLockError::Error(error)) => {
                return Err(format!("cannot lock state-head authority: {error}"));
            }
        }
    }
}

#[cfg(unix)]
fn validate_unix_authority_path(archive_path: &Path, path: &Path) -> HeadResult<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute() {
        return Err(format!("{STATE_HEAD_FILE_ENV} must be an absolute path"));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!("{STATE_HEAD_FILE_ENV} cannot name a symbolic link"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!("cannot inspect state-head authority path: {error}"));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{STATE_HEAD_FILE_ENV} must have a parent directory"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("cannot resolve state-head directory: {error}"))?;
    let parent_metadata = fs::metadata(&parent)
        .map_err(|error| format!("cannot inspect state-head directory: {error}"))?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(
            "state-head directory must be owned by the current user and not group/world writable"
                .to_owned(),
        );
    }
    let name = path
        .file_name()
        .ok_or_else(|| format!("{STATE_HEAD_FILE_ENV} must name a file"))?;
    let canonical = parent.join(name);
    let archive_directory = archive_path
        .parent()
        .ok_or_else(|| "state archive must have a parent directory".to_owned())?;
    if canonical.starts_with(archive_directory) {
        return Err(format!(
            "{STATE_HEAD_FILE_ENV} must be outside the ContextDB archive directory"
        ));
    }
    if canonical.exists() {
        let _ = read_unix_protected_file(&canonical, MAX_AUTHORITY_BYTES)?;
    }
    Ok(canonical)
}

#[cfg(unix)]
fn lock_path_for(authority_path: &Path) -> HeadResult<PathBuf> {
    let name = authority_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "state-head file name must be valid Unicode".to_owned())?;
    Ok(authority_path.with_file_name(format!(".{name}.lock")))
}

#[cfg(unix)]
fn read_unix_protected_file(path: &Path, maximum: usize) -> HeadResult<Option<Vec<u8>>> {
    use std::os::unix::fs::MetadataExt;

    let descriptor = match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(format!("cannot open protected file: {error}")),
    };
    let mut file = File::from(descriptor);
    let handle_metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect protected file handle: {error}"))?;
    if !handle_metadata.is_file()
        || handle_metadata.nlink() != 1
        || handle_metadata.uid() != rustix::process::geteuid().as_raw()
        || handle_metadata.mode() & 0o077 != 0
        || handle_metadata.len() > maximum as u64
    {
        return Err(
            "protected file must be a bounded owner-only regular file with one link".to_owned(),
        );
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve protected file: {error}"))?;
    let path_metadata = fs::metadata(&canonical)
        .map_err(|error| format!("cannot inspect protected file path: {error}"))?;
    if path_metadata.dev() != handle_metadata.dev() || path_metadata.ino() != handle_metadata.ino()
    {
        return Err("protected file changed identity during validation".to_owned());
    }
    read_bounded(&mut file, maximum, "protected file").map(Some)
}

#[cfg(unix)]
fn atomic_write_unix_authority(path: &Path, bytes: &[u8]) -> HeadResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| "state-head authority must have a parent directory".to_owned())?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create temporary state-head authority: {error}"))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot protect temporary state-head authority: {error}"))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| format!("cannot sync temporary state-head authority: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("cannot activate state-head authority: {}", error.error))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync state-head directory: {error}"))?;
    Ok(())
}

#[cfg(windows)]
fn validate_authority_id(id: &str) -> HeadResult<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(format!(
            "{STATE_HEAD_ID_ENV} must be 1..128 ASCII letters, digits, dot, underscore, colon, or hyphen"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn acquire_windows_registry_lock(id_digest: &str) -> HeadResult<File> {
    let local = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| "LOCALAPPDATA is required for the HKCU authority lock".to_owned())?;
    let directory = PathBuf::from(local)
        .join("ContextDB")
        .join("authority-locks");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create state-head lock directory: {error}"))?;
    acquire_file_lock(&directory.join(format!("{id_digest}.lock")))
}

#[cfg(windows)]
fn read_registry_value(key_path: &str) -> HeadResult<Option<Vec<u8>>> {
    let key = match winreg::HKCU.open_subkey(key_path) {
        Ok(key) => key,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot open HKCU state-head authority: {error}")),
    };
    let value: String = match key.get_value("authority") {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read HKCU state-head authority: {error}")),
    };
    if value.len() > MAX_AUTHORITY_BYTES {
        return Err("HKCU state-head authority exceeds its size limit".to_owned());
    }
    Ok(Some(value.into_bytes()))
}

#[cfg(windows)]
fn write_registry_value(key_path: &str, bytes: &[u8]) -> HeadResult<()> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| "state-head authority serialization is not UTF-8".to_owned())?;
    let (key, _) = winreg::HKCU
        .create_subkey(key_path)
        .map_err(|error| format!("cannot create HKCU state-head authority: {error}"))?;
    key.set_value("authority", &value)
        .map_err(|error| format!("cannot commit HKCU state-head authority: {error}"))
}

#[cfg(all(test, windows, feature = "current-server", feature = "mcp"))]
pub fn delete_test_registry_authority(id: &str) -> HeadResult<()> {
    validate_authority_id(id)?;
    let digest = blake3::hash(id.as_bytes()).to_hex().to_string();
    let path = format!("Software\\ContextDB\\StateHeads\\{digest}");
    match winreg::HKCU.delete_subkey_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot remove test HKCU authority: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::{
        LegacyAuthorityEnvelope, LegacyHeadRecord, StateHeadStore, acquire_file_lock,
        acquire_lock_bounded, legacy_authority_mac,
    };

    const KEY: [u8; 32] = [7; 32];

    fn archive(database_id: &str, head: u64, marker: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "format": "contextdb.logical.v1",
            "database_id": database_id,
            "head": head,
            "test_marker": marker,
        }))
        .expect("archive fixture")
    }

    #[test]
    fn current_head_rejects_old_archive_after_newer_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("rollback.ctxb");
        let store = StateHeadStore::memory(&path).expect("memory authority");
        let old = archive("database:rollback", 0, "old");
        let newer = archive("database:rollback", 1, "delete-or-newer-state");
        store.bootstrap(&KEY, &old).expect("bootstrap old state");
        store.advance(&KEY, &newer).expect("advance state");

        fs::write(&path, &old).expect("replay old archive");
        let error = store
            .load_verified(&KEY)
            .expect_err("current external head rejects old archive replay");
        assert!(error.contains("rollback") || error.contains("tampering"));
    }

    #[test]
    fn stale_tampered_wrong_path_and_wrong_database_are_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("bound.ctxb");
        let other_path = directory.path().join("other.ctxb");
        let store = StateHeadStore::memory(&path).expect("memory authority");
        let original = archive("database:bound", 0, "original");
        let newer = archive("database:bound", 1, "newer");
        store.bootstrap(&KEY, &original).expect("bootstrap");
        let stale_authority = store
            .raw_authority()
            .expect("read authority")
            .expect("authority exists");
        store.advance(&KEY, &newer).expect("advance");
        let current_authority = store
            .raw_authority()
            .expect("read authority")
            .expect("authority exists");

        store
            .replace_raw_authority(Some(stale_authority))
            .expect("restore stale authority");
        assert!(store.load_verified(&KEY).is_err());
        store
            .replace_raw_authority(Some(current_authority.clone()))
            .expect("restore current authority");

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&current_authority).expect("authority JSON");
        tampered["active"]["commit_seq"] = json!(99);
        store
            .replace_raw_authority(Some(
                serde_json::to_vec(&tampered).expect("tampered authority"),
            ))
            .expect("install tampered authority");
        assert!(store.load_verified(&KEY).is_err());
        store
            .replace_raw_authority(Some(current_authority))
            .expect("restore current authority");

        fs::copy(&path, &other_path).expect("copy archive");
        let swapped = store
            .memory_for_same_authority(&other_path)
            .expect("same external authority at another path");
        assert!(swapped.load_verified(&KEY).is_err());
        assert!(
            store
                .advance(&KEY, &archive("database:other", 2, "wrong database"))
                .is_err()
        );
    }

    #[test]
    fn detached_authority_recovery_cannot_write_the_live_authority() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source_path = directory.path().join("source.ctxb");
        let detached_path = directory.path().join("detached.ctxb");
        let source = StateHeadStore::memory(&source_path).expect("source authority");
        let original = archive("database:detached", 0, "original");
        let successor = archive("database:detached", 1, "successor");
        source.bootstrap(&KEY, &original).expect("bootstrap source");
        fs::copy(&source_path, &detached_path).expect("copy source archive");
        let live_authority = source
            .raw_authority()
            .expect("read live authority")
            .expect("live authority exists");

        let detached = source
            .detached_snapshot(&detached_path, &KEY)
            .expect("authenticated detached snapshot");
        detached
            .advance(&KEY, &successor)
            .expect("advance only detached authority and archive");

        assert_eq!(
            source
                .raw_authority()
                .expect("re-read live authority")
                .expect("live authority remains present"),
            live_authority
        );
        assert_eq!(fs::read(&source_path).expect("source archive"), original);
        assert_eq!(
            fs::read(&detached_path).expect("detached archive"),
            successor
        );
        let (_, source_identity) = source.load_verified(&KEY).expect("live source still valid");
        assert_eq!(source_identity.commit_seq, 0);
    }

    #[test]
    fn malformed_and_one_bit_authority_macs_are_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("authority-mac.ctxb");
        let store = StateHeadStore::memory(&path).expect("memory authority");
        let bytes = archive("database:authority-mac", 0, "original");
        store.bootstrap(&KEY, &bytes).expect("bootstrap");
        let original = store
            .raw_authority()
            .expect("read authority")
            .expect("authority exists");

        let mut one_bit: serde_json::Value =
            serde_json::from_slice(&original).expect("authority JSON");
        let mac = one_bit["mac"].as_str().expect("authority MAC");
        let replacement = if mac.ends_with('0') { '1' } else { '0' };
        let mut changed = mac.to_owned();
        changed.pop();
        changed.push(replacement);
        one_bit["mac"] = json!(changed);
        store
            .replace_raw_authority(Some(
                serde_json::to_vec(&one_bit).expect("one-bit authority"),
            ))
            .expect("install one-bit MAC mutation");
        let one_bit_error = store
            .load_verified(&KEY)
            .expect_err("one-bit MAC mutation must fail closed");
        assert!(one_bit_error.contains("MAC is invalid"));

        for malformed in ["0".repeat(63), "g".repeat(64), "A".repeat(64)] {
            let mut authority: serde_json::Value =
                serde_json::from_slice(&original).expect("authority JSON");
            authority["mac"] = json!(malformed);
            store
                .replace_raw_authority(Some(
                    serde_json::to_vec(&authority).expect("malformed authority"),
                ))
                .expect("install malformed MAC");
            let malformed_error = store
                .load_verified(&KEY)
                .expect_err("malformed MAC must fail closed");
            assert!(malformed_error.contains("MAC is invalid"));
        }
    }

    #[test]
    fn existing_destination_and_changed_equal_head_are_never_overwritten() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let existing_path = directory.path().join("existing.ctxb");
        let existing = archive("database:existing", 0, "existing");
        fs::write(&existing_path, &existing).expect("existing archive");
        let existing_store =
            StateHeadStore::memory(&existing_path).expect("existing-path authority");
        assert!(existing_store.bootstrap(&KEY, &existing).is_err());
        assert_eq!(
            fs::read(&existing_path).expect("unchanged archive"),
            existing
        );

        let path = directory.path().join("equal-head.ctxb");
        let store = StateHeadStore::memory(&path).expect("memory authority");
        let original = archive("database:equal", 7, "original");
        store.bootstrap(&KEY, &original).expect("bootstrap");
        assert!(
            store
                .advance(&KEY, &archive("database:equal", 7, "replacement"))
                .is_err()
        );
        assert_eq!(fs::read(path).expect("unchanged archive"), original);
    }

    #[test]
    fn replay_of_archive_and_authority_together_is_explicitly_custodian_compromise() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("custodian.ctxb");
        let store = StateHeadStore::memory(&path).expect("memory authority");
        let old = archive("database:custodian", 0, "old");
        let newer = archive("database:custodian", 1, "newer");
        store.bootstrap(&KEY, &old).expect("bootstrap");
        let old_authority = store
            .raw_authority()
            .expect("read authority")
            .expect("authority exists");
        store.advance(&KEY, &newer).expect("advance");

        // A MAC authenticates a snapshot; it is not a hardware monotonic
        // counter. The authority custodian must prevent this paired replay.
        fs::write(&path, &old).expect("replay archive");
        store
            .replace_raw_authority(Some(old_authority))
            .expect("replay authority");
        let (_, identity) = store
            .load_verified(&KEY)
            .expect("paired replay is outside the archive-attacker model");
        assert_eq!(identity.commit_seq, 0);
    }

    #[test]
    fn legacy_authority_requires_explicit_exact_current_migration() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("legacy.ctxb");
        let bytes = archive("database:legacy", 0, "legacy");
        fs::write(&path, &bytes).expect("legacy archive");
        let store = StateHeadStore::memory(&path).expect("memory authority");
        let identity = super::inspect_archive(&bytes).expect("archive identity");
        let record = LegacyHeadRecord {
            canonical_path_digest: store.canonical_path_digest.clone(),
            database_id: identity.database_id,
            commit_seq: identity.commit_seq,
            archive_digest: identity.archive_digest,
            previous_head_digest: None,
        };
        let mut legacy = LegacyAuthorityEnvelope {
            schema_version: super::LEGACY_AUTHORITY_SCHEMA_VERSION,
            authority_binding: store.authority_binding.clone(),
            active: Some(record),
            pending: None,
            mac: String::new(),
        };
        legacy.mac = legacy_authority_mac(&legacy, &KEY).expect("legacy MAC");
        store
            .replace_raw_authority(Some(
                serde_json::to_vec(&legacy).expect("legacy authority JSON"),
            ))
            .expect("install legacy authority");
        let error = store
            .load_verified(&KEY)
            .expect_err("ordinary read must never migrate implicitly");
        assert!(error.contains("explicit exact-current migration"));

        let ledger_digest = blake3::hash(b"exact production ledger")
            .to_hex()
            .to_string();
        let migrated = store
            .migrate_legacy_exact(&KEY, &bytes, 0, &ledger_digest)
            .expect("explicit exact-current migration");
        assert_eq!(migrated.generation, 0);
        assert_eq!(migrated.ledger_digest, ledger_digest);
        let (_, _, verified) = store
            .load_verified_with_ledger(&KEY)
            .expect("schema-v2 authority");
        assert_eq!(verified, migrated);
    }

    #[test]
    fn a_second_transaction_lock_cannot_fork_the_head() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("authority.lock");
        let first = acquire_file_lock(&path).expect("first lock");
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("second handle");
        let started = Instant::now();
        let error = acquire_lock_bounded(second).expect_err("second lock must time out");
        assert!(error.contains("timed out"));
        assert!(started.elapsed() >= Duration::from_millis(100));
        drop(first);
        acquire_file_lock(&path).expect("lock is reusable after release");
    }

    #[cfg(unix)]
    #[test]
    fn archive_and_authority_symbolic_links_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let data = tempfile::tempdir().expect("data directory");
        let authority = tempfile::tempdir().expect("authority directory");
        fs::set_permissions(authority.path(), fs::Permissions::from_mode(0o700))
            .expect("protect authority directory");
        let target = data.path().join("target.ctxb");
        fs::write(&target, archive("database:link", 0, "target")).expect("target archive");
        let archive_link = data.path().join("archive-link.ctxb");
        symlink(&target, &archive_link).expect("archive symlink");
        assert!(StateHeadStore::memory(&archive_link).is_err());

        let archive_path = data.path().join("new.ctxb");
        let authority_target = authority.path().join("target.head");
        fs::write(&authority_target, b"not-an-authority").expect("authority target");
        fs::set_permissions(&authority_target, fs::Permissions::from_mode(0o600))
            .expect("protect authority target");
        let authority_link = authority.path().join("authority.head");
        symlink(&authority_target, &authority_link).expect("authority symlink");
        assert!(super::validate_unix_authority_path(&archive_path, &authority_link).is_err());
    }
}
