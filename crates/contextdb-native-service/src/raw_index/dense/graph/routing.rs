//! Complete owner-published routing over genuine prefix base/interval paths.
//! Maintenance acceptance is distinct from serving and source evidence.

mod construction;
mod copies;
mod crypto;
pub(crate) mod heads;
mod inputs;
mod proof;
mod publication;
pub(crate) mod query;
mod reconstruction;
mod status;
pub(crate) mod types;
mod verification;

pub use status::NativeRoutedMaintenanceTarget;

use super::*;
use types::*;
use types::{FEATURE, MAX_COHORTS, OPERATION, ROW_BYTES, receipt_key};

#[cfg(test)]
mod tests;
