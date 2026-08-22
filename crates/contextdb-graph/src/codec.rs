use serde::{Serialize, de::DeserializeOwned};

use crate::{GraphError, Result};

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| GraphError::Corrupt(error.to_string()))
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|error| GraphError::Corrupt(error.to_string()))
}

pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(blake3::hash(&encode(value)?).to_hex().to_string())
}

pub(crate) fn external_key(id: impl std::fmt::Display) -> Vec<u8> {
    id.to_string().into_bytes()
}

pub(crate) fn revision_key(id: impl std::fmt::Display, revision: u32) -> Vec<u8> {
    format!("{id}/{revision:010}").into_bytes()
}

pub(crate) fn u64_key(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}
