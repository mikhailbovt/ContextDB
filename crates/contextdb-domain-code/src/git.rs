use contextdb_core::{ContentDigest, TimestampMicros};
use serde::{Deserialize, Serialize};

use crate::{CodeDomainError, RepoPath, Result};

/// Git path-change category parsed from `git diff-tree --name-status -z`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitChangeKind {
    /// New path.
    Added,
    /// Removed path.
    Deleted,
    /// Content or mode changed at the same path.
    Modified,
    /// Path renamed with Git similarity evidence.
    Renamed,
    /// Path copied with Git similarity evidence.
    Copied,
}

/// One canonical Git path change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitChange {
    /// Change category.
    pub kind: GitChangeKind,
    /// Old path for deletion, rename, or copy.
    pub old_path: Option<RepoPath>,
    /// New/current path for add, modify, rename, or copy.
    pub new_path: Option<RepoPath>,
    /// Optional Git similarity score for rename/copy.
    pub similarity: Option<u8>,
}

/// Content-minimized Git commit metadata bound to exact path changes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitCommitDescriptor {
    /// Full lowercase hexadecimal object ID.
    pub object_id: String,
    /// Parent object IDs in declared Git order.
    pub parents: Vec<String>,
    /// Author timestamp.
    pub authored_at: TimestampMicros,
    /// Digest of commit message bytes; message content need not be retained.
    pub message_digest: ContentDigest,
    /// Deterministically ordered path changes.
    pub changes: Vec<GitChange>,
}

impl GitCommitDescriptor {
    /// Builds and validates a descriptor from exact commit fields and the
    /// NUL-delimited output of `git diff-tree --name-status -r -M -C -z`.
    pub fn from_name_status_z(
        object_id: impl Into<String>,
        parents: Vec<String>,
        authored_at: TimestampMicros,
        message: &[u8],
        name_status_z: &[u8],
    ) -> Result<Self> {
        let object_id = object_id.into();
        validate_object_id(&object_id)?;
        for parent in &parents {
            validate_object_id(parent)?;
        }
        let mut changes = parse_name_status_z(name_status_z)?;
        changes.sort_by(|left, right| {
            left.new_path
                .cmp(&right.new_path)
                .then_with(|| left.old_path.cmp(&right.old_path))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        Ok(Self {
            object_id,
            parents,
            authored_at,
            message_digest: ContentDigest::from_bytes(*blake3::hash(message).as_bytes()),
            changes,
        })
    }
}

fn parse_name_status_z(bytes: &[u8]) -> Result<Vec<GitChange>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut fields = bytes.split(|byte| *byte == 0);
    let mut changes = Vec::new();
    while let Some(status) = fields.next() {
        if status.is_empty() {
            if fields.next().is_some() {
                return Err(CodeDomainError::InvalidText("git.name_status"));
            }
            break;
        }
        let status =
            std::str::from_utf8(status).map_err(|_| CodeDomainError::InvalidText("git.status"))?;
        let code = status
            .bytes()
            .next()
            .ok_or(CodeDomainError::InvalidText("git.status"))?;
        let similarity = if matches!(code, b'R' | b'C') {
            let value = status[1..]
                .parse::<u8>()
                .map_err(|_| CodeDomainError::InvalidText("git.similarity"))?;
            if value > 100 {
                return Err(CodeDomainError::InvalidText("git.similarity"));
            }
            Some(value)
        } else {
            if status.len() != 1 {
                return Err(CodeDomainError::InvalidText("git.status"));
            }
            None
        };
        let first = next_path(&mut fields)?;
        let change = match code {
            b'A' => GitChange {
                kind: GitChangeKind::Added,
                old_path: None,
                new_path: Some(first),
                similarity: None,
            },
            b'D' => GitChange {
                kind: GitChangeKind::Deleted,
                old_path: Some(first),
                new_path: None,
                similarity: None,
            },
            b'M' | b'T' => GitChange {
                kind: GitChangeKind::Modified,
                old_path: Some(first.clone()),
                new_path: Some(first),
                similarity: None,
            },
            b'R' | b'C' => GitChange {
                kind: if code == b'R' {
                    GitChangeKind::Renamed
                } else {
                    GitChangeKind::Copied
                },
                old_path: Some(first),
                new_path: Some(next_path(&mut fields)?),
                similarity,
            },
            _ => return Err(CodeDomainError::InvalidText("git.status")),
        };
        changes.push(change);
    }
    Ok(changes)
}

fn next_path<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> Result<RepoPath> {
    let bytes = fields
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(CodeDomainError::InvalidText("git.path"))?;
    let path = std::str::from_utf8(bytes).map_err(|_| CodeDomainError::InvalidText("git.path"))?;
    RepoPath::new(path)
}

fn validate_object_id(value: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CodeDomainError::InvalidText("git.object_id"));
    }
    Ok(())
}
