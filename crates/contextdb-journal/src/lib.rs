//! Durable semantic journal and ordered transaction coordinator.
//!
//! Observation acceptance and semantic publication are distinct logical commit
//! classes. Every durable logical frame is protected by
//! [`contextdb_format::RecordEnvelope`], while exact validated request bytes are
//! retained for deterministic replay. The storage backend supplies only atomic
//! physical transactions and synchronization.

#![forbid(unsafe_code)]

mod coordinator;
mod error;
mod key;
mod model;

#[cfg(test)]
mod tests;

pub use coordinator::JournalCoordinator;
pub use error::{JournalError, Result};
pub use model::{
    CommitOptions, CommitStage, IdempotencyKey, JournalEvent, JournalSnapshot,
    JournalSnapshotSelector, JournalVerifyReport, MaintenanceReceipt, ObservationReceipt,
    PortableJournalBackup, PublicationReceipt, RecoveryReport, ReplayMaintenance, ReplayMutation,
    RestoreReport, ValidatedMaintenanceBytes, ValidatedMutationBytes, ValidatedObservationBytes,
};
