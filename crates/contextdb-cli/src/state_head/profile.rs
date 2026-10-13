//! Immutable native-profile opt-in retained outside the replayable store.

use super::*;

impl StateHeadStore {
    /// Read authenticated configuration only. A pending lifecycle transaction
    /// does not change this commitment or become a readiness/recovery proof.
    pub(crate) fn native_profile_digest(&self, key: &[u8; 32]) -> HeadResult<Option<String>> {
        let envelope = self
            .read_envelope(key)?
            .ok_or_else(|| "native profile requires an authenticated state head".to_owned())?;
        Ok(envelope.native_profile_digest)
    }

    /// The proxy may inspect the immutable commitment while the broker owns the
    /// writer lock. This reads no archive and never reconciles or writes a head.
    #[cfg(any(feature = "mcp", test))]
    pub(crate) fn probe_native_profile_digest(
        archive_path: &Path,
        key: &[u8; 32],
    ) -> HeadResult<Option<String>> {
        Self::resolve(archive_path, false)?.native_profile_digest(key)
    }

    /// Explicit initializer only: opt in once under the external writer lock,
    /// before creating native stores. Ordinary publications cannot clear it.
    #[cfg(any(feature = "mcp", test))]
    pub(crate) fn pin_native_profile(&self, key: &[u8; 32], digest: &str) -> HeadResult<()> {
        require_digest(digest, "native profile digest")?;
        self.authenticated_active_identity(key)?;
        self.load_verified(key)?;
        let envelope = self
            .read_envelope(key)?
            .ok_or_else(|| "native profile state head disappeared".to_owned())?;
        if let Some(current) = envelope.native_profile_digest {
            return if current == digest {
                Ok(())
            } else {
                Err("native profile commitment is immutable".to_owned())
            };
        }
        self.write_envelope_with_profile(key, envelope.active, None, Some(digest.to_owned()), false)
    }

    #[cfg(any(feature = "mcp", test))]
    pub(crate) fn require_native_restore_ready(&self, key: &[u8; 32]) -> HeadResult<()> {
        let envelope = self
            .read_envelope(key)?
            .ok_or_else(|| "native restore requires an authenticated state head".to_owned())?;
        if envelope.native_restore_pending {
            return Err(
                "native restore is incomplete; explicit operator recovery is required".to_owned(),
            );
        }
        Ok(())
    }

    #[cfg(any(feature = "mcp", test))]
    pub(crate) fn probe_native_restore_ready(
        archive_path: &Path,
        key: &[u8; 32],
    ) -> HeadResult<()> {
        Self::resolve(archive_path, false)?.require_native_restore_ready(key)
    }

    /// Fence before any missing native target is created. Replaying a locally
    /// signed Ready descriptor cannot clear this independently retained intent.
    #[cfg(any(feature = "mcp", test))]
    pub(crate) fn begin_native_restore(&self, key: &[u8; 32], digest: &str) -> HeadResult<()> {
        self.update_native_restore(key, digest, true)
    }

    /// Operator only, after native restore and deep verification have succeeded.
    #[cfg(any(feature = "mcp", test))]
    pub(crate) fn finish_native_restore(&self, key: &[u8; 32], digest: &str) -> HeadResult<()> {
        self.update_native_restore(key, digest, false)
    }

    #[cfg(any(feature = "mcp", test))]
    fn update_native_restore(&self, key: &[u8; 32], digest: &str, pending: bool) -> HeadResult<()> {
        require_digest(digest, "native profile digest")?;
        self.authenticated_active_identity(key)?;
        self.load_verified(key)?;
        let envelope = self
            .read_envelope(key)?
            .ok_or_else(|| "native restore state head disappeared".to_owned())?;
        if envelope.native_profile_digest.as_deref() != Some(digest)
            || envelope.native_restore_pending == pending
        {
            return Err("native restore transition lacks its configured predecessor".to_owned());
        }
        self.write_envelope_with_profile(
            key,
            envelope.active,
            None,
            envelope.native_profile_digest,
            pending,
        )
    }
}

#[cfg(test)]
mod tests;
