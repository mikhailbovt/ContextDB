use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Result, SecureStoreError};

const OPAQUE_BYTES: usize = 32;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal, $docs:literal) => {
        #[doc = $docs]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Generates a fresh opaque identity using the operating-system CSPRNG.
            pub fn generate() -> Result<Self> {
                let mut random = [0_u8; OPAQUE_BYTES];
                getrandom::fill(&mut random).map_err(|_| SecureStoreError::CryptographicFailure)?;
                Ok(Self(format!("{}{}", $prefix, encode_hex(&random))))
            }

            /// Parses and validates the versioned opaque wire representation.
            pub fn parse(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_opaque(&value, $prefix)?;
                Ok(Self(value))
            }

            /// Returns the opaque wire representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([OPAQUE])"))
            }
        }

        impl TryFrom<String> for $name {
            type Error = SecureStoreError;

            fn try_from(value: String) -> Result<Self> {
                Self::parse(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

opaque_id!(
    ContentHandleV2,
    "cth2_",
    "Opaque, random identity of one encrypted content object."
);
opaque_id!(
    SourceMaterialHandleV2,
    "src2_",
    "Opaque reference to recoverable source material retained until durable publication."
);
opaque_id!(
    ErasureDomainV2,
    "erd2_",
    "Opaque identity of an independently erasable key domain."
);
opaque_id!(
    KeyHandleV2,
    "dek2_",
    "Opaque authority-managed reference to one content-encryption key."
);
opaque_id!(
    DeletionHandleV2,
    "del2_",
    "Opaque identity of one monotonic hard-delete workflow."
);
opaque_id!(
    DeletionTargetHandleV2,
    "dct2_",
    "Opaque identity of one authoritative deletion-closure target."
);
opaque_id!(
    EvidenceHandleV2,
    "evh2_",
    "Opaque reference to independently verifiable purge or external evidence."
);
opaque_id!(
    ExportHandleV2,
    "exp2_",
    "Opaque identity of one ciphertext-only canonical export."
);
opaque_id!(
    OperationRequestIdV2,
    "req2_",
    "Opaque idempotency identity for one external authority operation."
);
opaque_id!(
    AuthorityTicketHandleV2,
    "atk2_",
    "Opaque authority-issued handle for one asynchronous operation ticket."
);

/// A validated 256-bit state commitment, never a digest of plaintext content.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct StateRootV2(String);

impl StateRootV2 {
    /// Parses a canonical lowercase 256-bit hexadecimal commitment.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_hex_32(&value, "state root")?;
        Ok(Self(value))
    }

    /// Commits to canonical non-secret state in a caller-supplied domain.
    pub fn commit(domain: &str, canonical_state: &[u8]) -> Result<Self> {
        validate_label(domain, "state-root domain")?;
        let mut hasher = blake3::Hasher::new_derive_key("contextdb/secure-store/state-root/v2");
        hasher.update(&(domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        hasher.update(&(canonical_state.len() as u64).to_be_bytes());
        hasher.update(canonical_state);
        Ok(Self(hasher.finalize().to_hex().to_string()))
    }

    /// Returns the canonical commitment representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for StateRootV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StateRootV2([COMMITMENT])")
    }
}

impl TryFrom<String> for StateRootV2 {
    type Error = SecureStoreError;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(value)
    }
}

impl From<StateRootV2> for String {
    fn from(value: StateRootV2) -> Self {
        value.0
    }
}

pub(crate) fn validate_label(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(SecureStoreError::InvalidInput(field.to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_hex_32(value: &str, field: &str) -> Result<()> {
    if value.len() != OPAQUE_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SecureStoreError::InvalidInput(field.to_owned()));
    }
    Ok(())
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_opaque(value: &str, prefix: &str) -> Result<()> {
    let Some(encoded) = value.strip_prefix(prefix) else {
        return Err(SecureStoreError::InvalidInput(
            "opaque identity prefix".to_owned(),
        ));
    };
    validate_hex_32(encoded, "opaque identity")
}
