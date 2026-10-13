//! Explicit finite prefix-base maintenance; no query or runtime activation.

mod construction;
mod copies;
mod crypto;
pub(crate) mod heads;
pub(in crate::raw_index::dense::graph) mod inputs;
mod publication;
mod reconstruction;
pub(crate) mod types;
pub(in crate::raw_index::dense::graph) mod verification;

use super::*;
use types::{
    DensePrefixBaseManifestV2, DensePrefixBaseReceiptV2, DensePrefixBaseRequestV2, PrefixBaseRefV2,
    PrefixCohortV2, PrefixMemberV2, PrefixNodeV2, PrefixRawBindingV2, RetainedPrefixBaseLocatorV2,
    cohort_key, member_key, node_key, prefix_key, receipt_key, retained_locator_key,
};

#[cfg(test)]
mod tests;
