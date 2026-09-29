//! Authenticate content-free semantic classifications after the old bytes vanish.
//! Only verified service code issues these; they neither prove use nor retire keys.

use super::*;

const DOMAIN: &str = "contextdb/native-assertion-value-ownership/v1";

impl NativeCustodyKeys {
    pub(crate) fn supports_value_ownership(&self) -> bool {
        self.tracks_native_use()
    }

    pub(crate) fn attest_assertion_values(
        &self,
        digest: &str,
    ) -> contextdb_service::ServiceResult<Vec<u8>> {
        if !self.supports_value_ownership() || blake3::Hash::from_hex(digest).is_err() {
            return Err(crate::invalid(
                "assertion value attestation requires v4 and an exact commitment",
            ));
        }
        seal(
            &self.master.0,
            &encode(&(DOMAIN, &self.identity)).map_err(crate::storage_error)?,
            digest.as_bytes(),
        )
        .map_err(crate::storage_error)
    }

    pub(crate) fn verify_assertion_value_attestation(
        &self,
        digest: &str,
        proof: &[u8],
    ) -> contextdb_service::ServiceResult<()> {
        if !self.supports_value_ownership()
            || proof.len() != 64 + NONCE_BYTES + TAG_BYTES
            || blake3::Hash::from_hex(digest).is_err()
        {
            return Err(crate::integrity(
                "assertion value attestation shape differs",
            ));
        }
        let bytes = open(
            &self.master.0,
            &encode(&(DOMAIN, &self.identity)).map_err(crate::storage_error)?,
            proof,
        )
        .map_err(|_| crate::integrity("assertion value attestation is not authenticated"))?;
        if bytes.as_slice() != digest.as_bytes() {
            return Err(crate::integrity(
                "assertion value attestation commitment differs",
            ));
        }
        Ok(())
    }
}
