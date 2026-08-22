//! Minimal physical storage boundary used by ContextDB.
//!
//! The interface deliberately exposes ContextDB requirements rather than a
//! particular embedded key-value database API. Semantic meaning lives above
//! this crate.

#![forbid(unsafe_code)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Monotonically increasing physical commit sequence.
pub type StorageSequence = u64;

/// A named physical keyspace. Names are part of the storage manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Keyspace(String);

impl Keyspace {
    /// Creates a non-empty, portable keyspace name.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if !valid {
            return Err(StorageError::InvalidKeyspace(value));
        }
        Ok(Self(value))
    }

    /// Returns the portable keyspace name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Selects a stable storage snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSelector {
    /// Select the most recently committed snapshot.
    Latest,
    /// Select an exact historical sequence when the backend retains it.
    At(StorageSequence),
}

/// Durability required before a commit may be acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    /// Commit is visible but may only reside in process memory. Test-only.
    Ephemeral,
    /// Journal and data required for recovery are synchronized to stable media.
    Sync,
}

/// One lexicographically ordered key-value item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Raw, portable key bytes.
    pub key: Vec<u8>,
    /// Raw, versioned value bytes.
    pub value: Vec<u8>,
}

/// Largest page that the portable storage contract accepts by entry count.
pub const MAX_SCAN_PAGE_ENTRIES: usize = 65_536;

/// Largest page that the portable storage contract accepts by key/value bytes.
pub const MAX_SCAN_PAGE_BYTES: usize = 64 * 1024 * 1024;

/// Exclusive, bounded request for one deterministic prefix-scan page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanPageRequest<'a> {
    /// Key prefix to match.
    pub prefix: &'a [u8],
    /// Last key returned by the preceding page. It is never returned again.
    pub start_after: Option<&'a [u8]>,
    /// Maximum number of entries in the returned page.
    pub max_entries: usize,
    /// Maximum aggregate `key.len() + value.len()` in the returned page.
    pub max_bytes: usize,
}

impl ScanPageRequest<'_> {
    /// Validates that both limits are non-zero and within portable hard bounds.
    pub fn validate(self) -> Result<()> {
        if self.max_entries == 0 || self.max_entries > MAX_SCAN_PAGE_ENTRIES {
            return Err(StorageError::InvalidScanPage {
                field: "max_entries",
                value: self.max_entries,
                maximum: MAX_SCAN_PAGE_ENTRIES,
            });
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_SCAN_PAGE_BYTES {
            return Err(StorageError::InvalidScanPage {
                field: "max_bytes",
                value: self.max_bytes,
                maximum: MAX_SCAN_PAGE_BYTES,
            });
        }
        Ok(())
    }
}

/// One bounded, bytewise-ordered prefix-scan page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPage {
    /// Entries in strict lexicographic key order.
    pub entries: Vec<Entry>,
    /// Last returned key when another matching entry exists; `None` marks end.
    pub continuation: Option<Vec<u8>>,
}

/// Applies the portable page contract to an already ordered entry iterator.
///
/// Backends should seek to `start_after` (exclusive) before constructing the
/// iterator. The defensive filters and ordering checks keep adapter mistakes
/// fail-closed without weakening snapshot stability.
pub fn collect_scan_page<I>(request: ScanPageRequest<'_>, entries: I) -> Result<ScanPage>
where
    I: IntoIterator<Item = Result<Entry>>,
{
    request.validate()?;
    let mut page = Vec::new();
    let mut used_bytes = 0_usize;
    let mut previous_key: Option<Vec<u8>> = None;

    for item in entries {
        let entry = item?;
        if let Some(previous) = &previous_key
            && entry.key <= *previous
        {
            return Err(StorageError::ScanContractViolation(
                "backend scan is not in strict lexicographic key order",
            ));
        }
        previous_key = Some(entry.key.clone());

        if !entry.key.starts_with(request.prefix) {
            if entry.key.as_slice() < request.prefix {
                continue;
            }
            break;
        }
        if request
            .start_after
            .is_some_and(|start_after| entry.key.as_slice() <= start_after)
        {
            continue;
        }

        let entry_bytes = entry.key.len().checked_add(entry.value.len()).ok_or(
            StorageError::ResourceExhausted {
                resource: "scan_page_bytes",
                limit: request.max_bytes,
                required: usize::MAX,
            },
        )?;
        if page.is_empty() && entry_bytes > request.max_bytes {
            return Err(StorageError::ResourceExhausted {
                resource: "scan_page_bytes",
                limit: request.max_bytes,
                required: entry_bytes,
            });
        }
        if page.len() == request.max_entries
            || used_bytes
                .checked_add(entry_bytes)
                .is_none_or(|next| next > request.max_bytes)
        {
            return Ok(ScanPage {
                continuation: page.last().map(|entry: &Entry| entry.key.clone()),
                entries: page,
            });
        }
        used_bytes += entry_bytes;
        page.push(entry);
    }

    Ok(ScanPage {
        entries: page,
        continuation: None,
    })
}

const LEGACY_SCAN_PAGE_ENTRIES: usize = 4_096;
const LEGACY_SCAN_PAGE_BYTES: usize = 16 * 1024 * 1024;
const LEGACY_SCAN_MAX_ENTRIES: usize = 10_000_000;
const LEGACY_SCAN_MAX_BYTES: usize = 512 * 1024 * 1024;

/// Collects the legacy vector API through bounded pages with finite total caps.
pub fn collect_prefix_pages<S: ReadSnapshot + ?Sized>(
    snapshot: &S,
    keyspace: &Keyspace,
    prefix: &[u8],
) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut continuation: Option<Vec<u8>> = None;
    let mut total_bytes = 0_usize;
    loop {
        let page = snapshot.scan_prefix_page(
            keyspace,
            ScanPageRequest {
                prefix,
                start_after: continuation.as_deref(),
                max_entries: LEGACY_SCAN_PAGE_ENTRIES,
                max_bytes: LEGACY_SCAN_PAGE_BYTES,
            },
        )?;
        if page.continuation.is_some() && page.entries.is_empty() {
            return Err(StorageError::ScanContractViolation(
                "continuation page made no progress",
            ));
        }
        if let (Some(previous), Some(next)) = (&continuation, &page.continuation)
            && next <= previous
        {
            return Err(StorageError::ScanContractViolation(
                "continuation key did not advance",
            ));
        }
        for entry in &page.entries {
            let entry_bytes = entry.key.len().checked_add(entry.value.len()).ok_or(
                StorageError::ResourceExhausted {
                    resource: "legacy_scan_bytes",
                    limit: LEGACY_SCAN_MAX_BYTES,
                    required: usize::MAX,
                },
            )?;
            total_bytes =
                total_bytes
                    .checked_add(entry_bytes)
                    .ok_or(StorageError::ResourceExhausted {
                        resource: "legacy_scan_bytes",
                        limit: LEGACY_SCAN_MAX_BYTES,
                        required: usize::MAX,
                    })?;
        }
        let required_entries = entries.len().saturating_add(page.entries.len());
        if required_entries > LEGACY_SCAN_MAX_ENTRIES {
            return Err(StorageError::ResourceExhausted {
                resource: "legacy_scan_entries",
                limit: LEGACY_SCAN_MAX_ENTRIES,
                required: required_entries,
            });
        }
        if total_bytes > LEGACY_SCAN_MAX_BYTES {
            return Err(StorageError::ResourceExhausted {
                resource: "legacy_scan_bytes",
                limit: LEGACY_SCAN_MAX_BYTES,
                required: total_bytes,
            });
        }
        entries.extend(page.entries);
        let Some(next) = page.continuation else {
            return Ok(entries);
        };
        continuation = Some(next);
    }
}

/// Result of an atomic physical commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitReceipt {
    /// Newly published sequence.
    pub sequence: StorageSequence,
    /// Durability level actually achieved before returning.
    pub durability: Durability,
}

/// Backend-independent verification depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Validate manifest and readily available metadata.
    Quick,
    /// Read and validate every record available through the backend.
    Deep,
}

/// Result of a verification pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Snapshot that was verified.
    pub sequence: StorageSequence,
    /// Number of keyspaces visited.
    pub keyspaces: u64,
    /// Number of records visited.
    pub records: u64,
    /// Recoverable warnings which do not invalidate the snapshot.
    pub warnings: Vec<String>,
}

/// Request for backend physical compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompactRequest {
    /// Optional upper bound on work. A backend may stop safely before it.
    pub max_bytes: Option<u64>,
}

/// Backend compaction report. Compaction never changes logical sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactReport {
    /// Logical snapshot observed before and after compaction.
    pub sequence: StorageSequence,
    /// Physical bytes reclaimed when the backend can measure them.
    pub bytes_reclaimed: u64,
}

/// Portable checkpoint metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointManifest {
    /// Storage schema version used by the checkpoint.
    pub format_version: u32,
    /// Included physical sequence.
    pub sequence: StorageSequence,
    /// Backend identifier for diagnostics; imports cannot depend on it.
    pub backend: String,
}

/// Stable read view.
pub trait ReadSnapshot {
    /// Returns this snapshot's immutable sequence.
    fn sequence(&self) -> StorageSequence;

    /// Reads one value.
    fn get(&self, keyspace: &Keyspace, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Returns entries whose key starts with `prefix`, ordered bytewise.
    fn scan_prefix(&self, keyspace: &Keyspace, prefix: &[u8]) -> Result<Vec<Entry>>;

    /// Returns one bounded page in bytewise order.
    ///
    /// `start_after` is a strict exclusive cursor. A non-`None` continuation
    /// is the final returned key and proves that another matching entry exists.
    fn scan_prefix_page(
        &self,
        keyspace: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> Result<ScanPage> {
        // Compatibility path for third-party implementations. In-tree engines
        // override this so their physical scans are bounded before allocation.
        collect_scan_page(
            request,
            self.scan_prefix(keyspace, request.prefix)?
                .into_iter()
                .map(Ok),
        )
    }
}

/// Atomic write transaction prepared against one head sequence.
pub trait WriteTransaction: ReadSnapshot {
    /// Stages a key replacement.
    fn put(&mut self, keyspace: &Keyspace, key: Vec<u8>, value: Vec<u8>) -> Result<()>;

    /// Stages deletion of a key. Deleting an absent key is idempotent.
    fn delete(&mut self, keyspace: &Keyspace, key: Vec<u8>) -> Result<()>;

    /// Atomically publishes all staged changes.
    fn commit(self, durability: Durability) -> Result<CommitReceipt>;

    /// Abandons all staged changes.
    fn rollback(self) -> Result<()>;
}

/// Storage capabilities needed by the ContextDB kernel.
pub trait StorageEngine: Send + Sync + 'static {
    /// Stable read snapshot type.
    type ReadSnapshot<'a>: ReadSnapshot
    where
        Self: 'a;
    /// Atomic writer type.
    type WriteTransaction<'a>: WriteTransaction
    where
        Self: 'a;

    /// Returns the current committed sequence.
    fn head_sequence(&self) -> Result<StorageSequence>;

    /// Opens a stable read snapshot.
    fn begin_read(&self, selector: SnapshotSelector) -> Result<Self::ReadSnapshot<'_>>;

    /// Opens a writer against the current head.
    fn begin_write(&self) -> Result<Self::WriteTransaction<'_>>;

    /// Creates a recoverable physical checkpoint.
    fn checkpoint(&self, target: &Path) -> Result<CheckpointManifest>;

    /// Performs physical-only compaction.
    fn compact(&self, request: CompactRequest) -> Result<CompactReport>;

    /// Verifies physical state without changing it.
    fn verify(&self, mode: VerifyMode) -> Result<VerifyReport>;
}

/// Storage boundary failures.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Keyspace name is empty or non-portable.
    #[error("invalid keyspace name: {0:?}")]
    InvalidKeyspace(String),
    /// Requested snapshot is not retained.
    #[error("snapshot {requested} is unavailable; head is {head}")]
    SnapshotUnavailable {
        /// Requested sequence.
        requested: StorageSequence,
        /// Current head.
        head: StorageSequence,
    },
    /// Writer was prepared against an obsolete head.
    #[error("write conflict: transaction base {base}, current head {head}")]
    WriteConflict {
        /// Transaction base sequence.
        base: StorageSequence,
        /// Current head sequence.
        head: StorageSequence,
    },
    /// A synchronization primitive was poisoned.
    #[error("storage lock poisoned")]
    LockPoisoned,
    /// A page limit was zero or exceeded the portable hard maximum.
    #[error("invalid scan page {field}={value}; expected 1..={maximum}")]
    InvalidScanPage {
        /// Invalid request field.
        field: &'static str,
        /// Supplied value.
        value: usize,
        /// Portable maximum.
        maximum: usize,
    },
    /// A bounded operation cannot fit the required indivisible item or result.
    #[error("resource exhausted for {resource}: limit {limit}, required {required}")]
    ResourceExhausted {
        /// Stable resource identifier.
        resource: &'static str,
        /// Configured limit.
        limit: usize,
        /// Minimum known requirement.
        required: usize,
    },
    /// A backend violated ordering or continuation semantics.
    #[error("storage scan contract violation: {0}")]
    ScanContractViolation(&'static str),
    /// Backend-specific failure, sanitized for the domain boundary.
    #[error("{backend} storage error: {message}")]
    Backend {
        /// Stable backend identifier.
        backend: &'static str,
        /// Human-readable detail without record content.
        message: String,
    },
    /// Requested operation is not supported by the backend.
    #[error("{backend} does not support {operation}")]
    Unsupported {
        /// Stable backend identifier.
        backend: &'static str,
        /// Requested capability.
        operation: &'static str,
    },
}

/// Storage result type.
pub type Result<T> = std::result::Result<T, StorageError>;

#[cfg(test)]
mod tests {
    use super::{
        Entry, Keyspace, MAX_SCAN_PAGE_BYTES, MAX_SCAN_PAGE_ENTRIES, ScanPageRequest, StorageError,
        collect_scan_page,
    };

    #[test]
    fn keyspace_names_are_portable() {
        assert!(Keyspace::new("journal_v1").is_ok());
        assert!(Keyspace::new("").is_err());
        assert!(Keyspace::new("contains/slash").is_err());
    }

    #[test]
    fn page_limits_are_nonzero_and_portably_bounded() {
        for (max_entries, max_bytes, field) in [
            (0, 1, "max_entries"),
            (MAX_SCAN_PAGE_ENTRIES + 1, 1, "max_entries"),
            (1, 0, "max_bytes"),
            (1, MAX_SCAN_PAGE_BYTES + 1, "max_bytes"),
        ] {
            let error = ScanPageRequest {
                prefix: b"a",
                start_after: None,
                max_entries,
                max_bytes,
            }
            .validate()
            .expect_err("invalid bound must fail");
            assert!(matches!(
                error,
                StorageError::InvalidScanPage {
                    field: actual,
                    ..
                } if actual == field
            ));
        }
    }

    #[test]
    fn page_continuation_is_exclusive_and_only_marks_known_more_data() {
        let source = || {
            [b"a0", b"a1", b"a2", b"b0"].into_iter().map(|key| {
                Ok(Entry {
                    key: key.to_vec(),
                    value: vec![1],
                })
            })
        };
        let first = collect_scan_page(
            ScanPageRequest {
                prefix: b"a",
                start_after: None,
                max_entries: 2,
                max_bytes: 100,
            },
            source(),
        )
        .expect("first page");
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| &entry.key)
                .collect::<Vec<_>>(),
            [b"a0".to_vec(), b"a1".to_vec()].iter().collect::<Vec<_>>()
        );
        assert_eq!(first.continuation.as_deref(), Some(b"a1".as_slice()));

        let final_page = collect_scan_page(
            ScanPageRequest {
                prefix: b"a",
                start_after: first.continuation.as_deref(),
                max_entries: 2,
                max_bytes: 100,
            },
            source(),
        )
        .expect("final page");
        assert_eq!(final_page.entries.len(), 1);
        assert_eq!(final_page.entries[0].key, b"a2");
        assert_eq!(final_page.continuation, None);
    }

    #[test]
    fn indivisible_oversized_entry_fails_explicitly() {
        let error = collect_scan_page(
            ScanPageRequest {
                prefix: b"a",
                start_after: None,
                max_entries: 1,
                max_bytes: 3,
            },
            [Ok(Entry {
                key: b"aa".to_vec(),
                value: b"vv".to_vec(),
            })],
        )
        .expect_err("four-byte entry cannot fit a three-byte page");
        assert!(matches!(
            error,
            StorageError::ResourceExhausted {
                resource: "scan_page_bytes",
                limit: 3,
                required: 4
            }
        ));
    }
}
