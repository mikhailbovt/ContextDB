use std::fmt;

use serde::Deserializer;
use serde::de::{Error, SeqAccess, Visitor};

use crate::{MAX_ENCRYPTED_CONTENT_BYTES, MAX_EXPORT_CIPHERTEXT_CHUNK_BYTES_V2};

pub(crate) fn nonce_24<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bytes_bounded::<D, 24>(deserializer, 24)
}

pub(crate) fn encrypted_ciphertext<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bytes_bounded::<D, { MAX_ENCRYPTED_CONTENT_BYTES + 16 }>(deserializer, 0)
}

pub(crate) fn export_chunk<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bytes_bounded::<D, MAX_EXPORT_CIPHERTEXT_CHUNK_BYTES_V2>(deserializer, 0)
}

pub(crate) fn receipt_signature<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bytes_bounded::<D, { 8 * 1024 }>(deserializer, 0)
}

fn deserialize_bytes_bounded<'de, D, const MAX: usize>(
    deserializer: D,
    exact: usize,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedBytesVisitor<const MAX: usize> {
        exact: usize,
    }

    impl<'de, const MAX: usize> Visitor<'de> for BoundedBytesVisitor<MAX> {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX} bytes")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let initial = sequence.size_hint().unwrap_or(0).min(MAX);
            let mut bytes = Vec::with_capacity(initial);
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() == MAX {
                    return Err(A::Error::custom("bounded byte sequence is too large"));
                }
                bytes.push(byte);
            }
            if self.exact != 0 && bytes.len() != self.exact {
                return Err(A::Error::custom("bounded byte sequence has wrong length"));
            }
            Ok(bytes)
        }

        fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_byte_buf(bytes.to_vec())
        }

        fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if bytes.len() > MAX || (self.exact != 0 && bytes.len() != self.exact) {
                return Err(E::custom("bounded byte sequence has invalid length"));
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_byte_buf(BoundedBytesVisitor::<MAX> { exact })
}
