//! Immutable native intervals over a genuine accepted partial prefix.
//! Maintenance is distinct from serving and keeps legacy families unchanged.

mod construction;
mod copies;
mod crypto;
pub(crate) mod heads;
mod inputs;
mod proof;
mod publication;
mod reconstruction;
pub(crate) mod types;
mod verification;

use super::*;
use types::*;

#[cfg(test)]
mod tests;
