//! Isolated hard-delete v2 secure-storage foundation.
//!
//! This crate is not wired into the production service. Its contracts are a
//! prerequisite for, rather than evidence of, production hard deletion.
//!
//! Opaque identifiers cannot be constructed from unchecked strings:
//!
//! ```compile_fail
//! use contextdb_secure_store::ContentHandleV2;
//! let forged = ContentHandleV2("cth2_unchecked".to_owned());
//! ```
//!
//! Authority destruction evidence also cannot be materialized through unchecked
//! deserialization; callers must cross a signature-verifying boundary:
//!
//! ```compile_fail
//! use contextdb_secure_store::KeyDestructionEvidenceV2;
//! let forged: KeyDestructionEvidenceV2 = serde_json::from_slice(b"{}").unwrap();
//! ```
//!
//! Local master keys cannot cross a serialization boundary:
//!
//! ```compile_fail
//! use contextdb_secure_store::LocalMasterKeyV1;
//! use zeroize::Zeroizing;
//! let key = LocalMasterKeyV1::from_zeroizing(Zeroizing::new([7_u8; 32]));
//! let leaked = serde_json::to_vec(&key).unwrap();
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod boundary;
mod bounded;
mod content;
mod deletion;
mod durable_object;
mod error;
mod export;
mod head;
mod identity;
mod key_authority;
mod lifecycle_payload;
mod local_crypto_authority;
mod managed_copy;
mod managed_copy_workflow;
mod production_key_authority;
mod read_gate;
mod receipt;
mod redb_catalog;
mod repository;

pub use boundary::*;
pub use content::*;
pub use deletion::*;
pub use durable_object::*;
pub use error::*;
pub use export::*;
pub use head::*;
pub use identity::*;
pub use key_authority::*;
pub use lifecycle_payload::*;
pub use local_crypto_authority::*;
pub use managed_copy::*;
pub use managed_copy_workflow::*;
pub use production_key_authority::*;
pub use read_gate::*;
pub use receipt::*;
pub use redb_catalog::*;
pub use repository::*;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// Hard-delete v2 foundation format version.
pub const SECURE_STORE_FORMAT_VERSION: u16 = 2;

pub(crate) fn canonical_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| SecureStoreError::Serialization)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod p3_tests;

#[cfg(test)]
mod p4_tests;

#[cfg(test)]
mod p5_tests;

#[cfg(test)]
mod local_crypto_authority_tests;
