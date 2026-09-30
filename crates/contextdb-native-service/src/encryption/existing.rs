//! Existing-only opening validates application state before custody recovery.

use std::{path::Path, sync::Arc};

use contextdb_service::ServiceResult;

use super::{NativeCustodyKeys, NativeStorage};
use crate::{NativeService, NativeSuppressionLedger, storage_error, validate_manifest};

#[cfg(test)]
mod tests;

impl NativeService {
    /// Reopen an already provisioned encrypted database. Missing physical
    /// controls, required native-use protocol or application state fail without creating
    /// a database, registration or manifest. Valid pending commits may recover
    /// their existing custody acknowledgement after these checks.
    pub fn open_encrypted_existing(
        path: impl AsRef<Path>,
        database_id: impl Into<String>,
        token_key: [u8; 32],
        suppression: Arc<NativeSuppressionLedger>,
        keys: Arc<NativeCustodyKeys>,
    ) -> ServiceResult<Self> {
        let database_id = database_id.into();
        Self::validate_open_bindings(&database_id, &token_key, Some(&suppression), Some(&keys))?;
        let engine = NativeStorage::open_existing(path.as_ref(), keys).map_err(storage_error)?;
        let service = Self::from_native_storage(
            path.as_ref(),
            database_id,
            token_key,
            Some(suppression),
            engine,
        )?;
        let snapshot = service
            .engine
            .snapshot_before_recovery()
            .map_err(storage_error)?;
        let manifest = service.raw_manifest(&snapshot)?;
        validate_manifest(&manifest, &service.database_id)?;
        service.verify_suppression_binding(&manifest)?;
        service.verify_encryption_binding(&manifest)?;
        service.verify_event_chain(&snapshot, service.global_head(&snapshot)?)?;
        drop(snapshot);
        service.verify_native(false)?;
        Ok(service)
    }
}
