use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::{ValidationError, ValidationResult};

macro_rules! stable_id {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Stable external identifier for `", stringify!($name), "` values.")]
            #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
            #[serde(transparent)]
            pub struct $name(Uuid);

            impl $name {
                /// Generates a time-sortable UUIDv7 identifier.
                #[must_use]
                pub fn new() -> Self {
                    Self(Uuid::now_v7())
                }

                /// Validates an existing UUID as a ContextDB external identifier.
                pub fn from_uuid(value: Uuid) -> ValidationResult<Self> {
                    if value.is_nil() {
                        return Err(ValidationError::NilIdentifier { kind: stringify!($name) });
                    }
                    Ok(Self(value))
                }

                /// Returns the underlying UUID without changing its stable identity.
                #[must_use]
                pub const fn as_uuid(self) -> Uuid {
                    self.0
                }
            }

            impl fmt::Debug for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    self.0.fmt(formatter)
                }
            }

            impl FromStr for $name {
                type Err = ValidationError;

                fn from_str(input: &str) -> Result<Self, Self::Err> {
                    let value = Uuid::parse_str(input)
                        .map_err(|_| ValidationError::InvalidIdentifier { kind: stringify!($name) })?;
                    Self::from_uuid(value)
                }
            }

            impl<'de> Deserialize<'de> for $name {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    let value = Uuid::deserialize(deserializer)?;
                    Self::from_uuid(value).map_err(serde::de::Error::custom)
                }
            }

            impl Default for $name {
                fn default() -> Self {
                    Self::new()
                }
            }
        )+
    };
}

stable_id!(
    WorkspaceId,
    MemorySpaceId,
    MemorySubjectId,
    AgentId,
    ActorId,
    SourceId,
    StreamId,
    ObservationId,
    EpisodeViewId,
    ArtifactId,
    ContentBlockId,
    EvidenceId,
    NodeId,
    NodeRevisionId,
    AliasId,
    PredicateId,
    ClaimId,
    EdgeId,
    EdgeTypeId,
    ConflictSetId,
    CandidateId,
    ProcedureId,
    RelationshipStateId,
    SelfModelId,
    ContinuityProfileId,
    SessionId,
    AgentRunId,
    TaskId,
    CheckpointId,
    RecallRunId,
    ContextPackId,
    ModelCallId,
    DerivationId,
    SummaryId,
    ScopeId,
    PolicyId,
    VectorSpaceId,
    RepresentationId,
    DeletionJobId,
    MutationId,
    PublicationId,
    HierarchyViewId,
    ModelProfileId,
);

/// A monotonically increasing semantic commit sequence.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct CommitSeq(u64);

impl CommitSeq {
    /// The empty database snapshot.
    pub const GENESIS: Self = Self(0);

    /// Creates a commit sequence from its stable integer representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the integer representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next sequence, or `None` at integer exhaustion.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl fmt::Display for CommitSeq {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Identifies the consistent primary-state snapshot used by a read.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRef {
    pub commit_seq: CommitSeq,
}
