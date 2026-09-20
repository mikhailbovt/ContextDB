//! Native encrypted values and independently retained row keys.
//!
//! Key inventory is incremental. Reads address one descriptor; full inventory
//! verification is administrative work. No physical key-erasure claim is made.

mod keys;
mod storage;
#[cfg(test)]
pub(crate) mod tests;

pub use keys::{CustodyMasterKey, NativeCustodyKeys};
pub(super) use storage::{NativeSnapshot, NativeStorage};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use contextdb_storage::{Keyspace, StorageError};
use zeroize::Zeroizing;

const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
const VALUE_MAGIC: &[u8] = b"CTXENC1\0";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
pub(super) const ENCRYPTION_FEATURE: &str = "continuous-encrypted-custody-v1";

impl crate::NativeService {
    /// Open encrypted native storage with independently retained suppression and
    /// key authorities. Existing plaintext stores require explicit migration.
    pub fn open_encrypted(
        path: impl AsRef<std::path::Path>,
        database_id: impl Into<String>,
        token_key: [u8; 32],
        suppression: std::sync::Arc<crate::NativeSuppressionLedger>,
        keys: std::sync::Arc<NativeCustodyKeys>,
    ) -> contextdb_service::ServiceResult<Self> {
        Self::open_internal(
            path,
            database_id.into(),
            token_key,
            Some(suppression),
            Some(keys),
        )
    }

    pub(super) fn verify_encryption_binding(
        &self,
        manifest: &crate::Manifest,
    ) -> contextdb_service::ServiceResult<()> {
        if manifest.custody_authority != self.engine.keys.as_ref().map(|keys| keys.authority_id()) {
            return Err(crate::integrity(
                "native store requires its exact custody key authority",
            ));
        }
        Ok(())
    }
}

fn failure(message: &'static str) -> StorageError {
    StorageError::Backend {
        backend: "native-custody",
        message: message.into(),
    }
}

fn encode<T: serde::Serialize>(value: &T) -> contextdb_storage::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| failure("custody serialization failed"))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> contextdb_storage::Result<T> {
    serde_json::from_slice(bytes).map_err(|_| failure("custody record is invalid"))
}

fn address(space: &Keyspace, key: &[u8]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"contextdb/native-value-address/v1\0");
    hash.update(&(space.as_str().len() as u64).to_be_bytes());
    hash.update(space.as_str().as_bytes());
    hash.update(key);
    hash.finalize().to_hex().to_string()
}

fn random_key() -> contextdb_storage::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(key.as_mut()).map_err(|_| failure("custody entropy source unavailable"))?;
    Ok(key)
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> contextdb_storage::Result<Vec<u8>> {
    if plaintext.len() > MAX_VALUE_BYTES {
        return Err(failure("custody value exceeds 16 MiB"));
    }
    let mut nonce = [0; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| failure("custody nonce source unavailable"))?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| failure("custody encryption failed"))?;
    Ok([nonce.as_slice(), ciphertext.as_slice()].concat())
}

fn open(
    key: &[u8; 32],
    aad: &[u8],
    ciphertext: &[u8],
) -> contextdb_storage::Result<Zeroizing<Vec<u8>>> {
    if !(NONCE_BYTES + TAG_BYTES..=MAX_VALUE_BYTES + NONCE_BYTES + TAG_BYTES)
        .contains(&ciphertext.len())
    {
        return Err(failure("custody ciphertext size is invalid"));
    }
    let nonce: [u8; NONCE_BYTES] = ciphertext[..NONCE_BYTES]
        .try_into()
        .map_err(|_| failure("custody nonce is invalid"))?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext[NONCE_BYTES..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| failure("custody authentication failed"))
}
