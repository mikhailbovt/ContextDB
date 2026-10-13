//! Exact retained fine-path resolution, never a v1 graph reinterpretation.

use super::super::super::prefix_segments_v2::types::PrefixSegmentPublicationV2;
use super::super::super::prefix_v2::types::DensePrefixBaseReceiptV2;
use super::super::super::segments::crypto::{metered_encode, metered_json_len};
use super::super::*;
use super::view::VerifiedRoutedQueryView;

#[expect(
    clippy::large_enum_variant,
    reason = "One metered retained receipt is resolved at a time without another heap allocation"
)]
pub(in crate::raw_index::dense::graph::routing::query) enum VerifiedRoutedFinePath {
    Base {
        receipt: DensePrefixBaseReceiptV2,
        path: DirectoryRouterFinePathV1,
    },
    Segment {
        publication: PrefixSegmentPublicationV2,
        path: DirectoryRouterFinePathV1,
    },
}
impl VerifiedRoutedFinePath {
    pub(in crate::raw_index::dense::graph::routing::query) fn path(
        &self,
    ) -> &DirectoryRouterFinePathV1 {
        match self {
            Self::Base { path, .. } | Self::Segment { path, .. } => path,
        }
    }
    pub(in crate::raw_index::dense::graph::routing::query) fn dense(&self) -> &DenseManifest {
        match self {
            Self::Base { receipt, .. } => &receipt.manifest.prefix,
            Self::Segment { publication, .. } => &publication.delta.manifest.after,
        }
    }
    pub(in crate::raw_index::dense::graph::routing::query) fn summaries(
        &self,
    ) -> &[GraphCohortSummary] {
        match self {
            Self::Base { receipt, .. } => &receipt.manifest.cohorts,
            Self::Segment { publication, .. } => &publication.delta.manifest.cohorts,
        }
    }
}

impl NativeService {
    pub(in crate::raw_index::dense::graph::routing::query) fn resolve_routed_fine_path<
        S: ReadSnapshot,
    >(
        &self,
        snapshot: &S,
        view: &VerifiedRoutedQueryView,
        path: &DirectoryRouterFinePathV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<VerifiedRoutedFinePath> {
        let bytes = metered_json_len(path, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 8 + 4096)
            .map_err(budget_error)?;
        path.validate()?;
        if !path.admitted_by(&view.router().manifest.coverage) {
            return Err(integrity(
                "routed selected path is outside accepted coverage",
            ));
        }
        match path {
            DirectoryRouterFinePathV1::Base { base } => {
                let receipt = self.accepted_prefix_base(
                    snapshot,
                    view.workspace(),
                    view.generation().number,
                    parent,
                )?;
                self.check_prefix_generation_binding(
                    snapshot,
                    view.workspace(),
                    view.generation(),
                    &receipt,
                    parent,
                )?;
                if self.prefix_segment_base_reference(
                    snapshot,
                    view.workspace(),
                    &receipt,
                    parent,
                )? != *base
                    || &receipt != view.base()
                {
                    return Err(integrity(
                        "routed selected base differs from genuine native acceptance",
                    ));
                }
                Ok(VerifiedRoutedFinePath::Base {
                    receipt,
                    path: path.clone(),
                })
            }
            DirectoryRouterFinePathV1::Segment {
                ordinal,
                publication,
                receipt_digest,
                content_digest,
            } => {
                let accepted = self.accepted_prefix_segment_for_ordinal(
                    snapshot,
                    view.workspace(),
                    view.generation().number,
                    *ordinal,
                    parent,
                )?;
                self.check_prefix_segment_generation_binding(
                    snapshot,
                    view.workspace(),
                    view.generation(),
                    &accepted,
                    parent,
                )?;
                let reference =
                    self.prefix_publication_ref(snapshot, accepted.delta.global_commit, parent)?;
                let bytes = metered_encode(&accepted.delta, parent, MAX_PUBLICATION_BYTES)?;
                parent
                    .charge(bytes.len() as u64 + 1, 0)
                    .map_err(budget_error)?;
                if reference != *publication
                    || digest(&bytes) != *receipt_digest
                    || accepted.delta.manifest.content_digest != *content_digest
                    || accepted.delta.manifest.base != view.router().manifest.coverage.base
                    || accepted.delta.manifest.after.through
                        > view.router().manifest.covered.through
                {
                    return Err(integrity(
                        "routed selected interval differs from exact native path",
                    ));
                }
                Ok(VerifiedRoutedFinePath::Segment {
                    publication: accepted,
                    path: path.clone(),
                })
            }
        }
    }
}
