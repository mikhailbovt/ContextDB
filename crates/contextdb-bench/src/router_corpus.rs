//! Bounded synthetic corpus contracts. Observations and hashes never grant use rights.

mod builtin;
mod features;
mod fixture;
mod lineage;
mod types;

pub use builtin::*;
pub use features::*;
pub use lineage::*;
pub use types::*;

use crate::{BenchError, Result};
use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use serde::{Serialize, de::DeserializeOwned};
use std::io::Write;

pub const ROUTER_CORPUS_VERSION: &str = "contextdb.router-corpus.synthetic.v1";
pub const ROUTER_QUERY_VERSION: &str = "contextdb.router-query-time.v1";
pub const ROUTER_BEHAVIOR_VERSION: &str = "contextdb.router-behavior.v1";
pub const ROUTER_TARGET_VERSION: &str = "contextdb.router-utility-targets.v1";
pub const ROUTER_FEATURE_VERSION: &str = "contextdb.router-features.semantic-input.v1";
pub const MAX_ROUTER_EXAMPLES: usize = 64;
pub const MAX_ROUTER_EXAMPLE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ROUTER_TARGET_BYTES: usize = 1024 * 1024;
pub const MAX_ROUTER_CORPUS_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_ROUTER_LINEAGE_NODES: usize = 1024;

pub(super) fn invalid() -> BenchError {
    BenchError::Integrity("router corpus contract is invalid or unsupported".into())
}
pub(super) fn charge(budget: &mut QueryBudget, work: u64, bytes: u64) -> Result<()> {
    budget
        .charge(work, bytes)
        .map_err(|_| BenchError::TelemetryBudget("router corpus allowance exhausted".into()))
}
pub(super) fn identity(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}

struct Bounded<'a> {
    bytes: Vec<u8>,
    size: usize,
    limit: usize,
    retain: bool,
    budget: &'a mut QueryBudget,
}
impl Write for Bounded<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let size = self
            .size
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("bounded corpus overflow"))?;
        if size > self.limit {
            return Err(std::io::Error::other("bounded corpus ceiling"));
        }
        self.budget
            .charge(0, bytes.len() as u64)
            .map_err(|_| std::io::Error::other("bounded corpus allowance"))?;
        self.size = size;
        if self.retain {
            self.bytes.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn serialize<'a, T: Serialize>(
    value: &T,
    limit: usize,
    retain: bool,
    budget: &'a mut QueryBudget,
) -> Result<Bounded<'a>> {
    charge(budget, 1, 0)?;
    let mut writer = Bounded {
        bytes: Vec::new(),
        size: 0,
        limit,
        retain,
        budget,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| invalid())?;
    Ok(writer)
}
pub(super) fn bounded_size<T: Serialize>(
    value: &T,
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<usize> {
    Ok(serialize(value, limit, false, budget)?.size)
}
/// Canonical bounded bytes, without writing or granting export permission.
pub fn router_corpus_bytes<T: Serialize>(
    value: &T,
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<Vec<u8>> {
    if limit > MAX_ROUTER_EXAMPLE_BYTES {
        return Err(invalid());
    }
    Ok(serialize(value, limit, true, budget)?.bytes)
}
pub(super) fn digest<T: Serialize>(value: &T, budget: &mut QueryBudget) -> Result<ContentDigest> {
    Ok(ContentDigest::from_bytes(
        *blake3::hash(&router_corpus_bytes(
            value,
            MAX_ROUTER_EXAMPLE_BYTES,
            budget,
        )?)
        .as_bytes(),
    ))
}
pub(super) fn decode<T: Serialize + DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
    budget: &mut QueryBudget,
) -> Result<T> {
    if bytes.len() > limit {
        return Err(invalid());
    }
    charge(budget, 1, bytes.len() as u64)?;
    let value: T = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    // Byte-exact canonical roundtrip also rejects enum metadata, duplicate map/set
    // entries and nested ignored fields in older embedded core transports.
    if router_corpus_bytes(&value, limit, budget)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

#[cfg(test)]
mod tests;
