//! Exact immutable interval reconstruction; no neural encoding or live-head replay.

use super::crypto::{metered_encode, metered_json_len};
use super::*;

impl NativeService {
    /// An accepted historical interval remains inside its genuine retained raw
    /// generation. Current head equality is required for the final ordinal even
    /// when live siblings are already absent during incremental reclamation.
    pub(in crate::raw_index) fn check_prefix_segment_generation_binding<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        publication: &PrefixSegmentPublicationV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.check().map_err(budget_error)?;
        let reference =
            self.prefix_publication_ref(snapshot, publication.delta.global_commit, parent)?;
        self.check_prefix_segment_publication(
            snapshot,
            workspace,
            &reference,
            publication,
            parent,
        )?;
        let manifest = &publication.delta.manifest;
        let raw = &manifest.raw;
        let current = generation.dense_prefix_segments.as_ref().ok_or_else(|| {
            integrity("prefix interval declaration lost its generation directory")
        })?;
        current.validate()?;
        let latest = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("prefix interval generation lost its actual dense state"))?;
        let base = self.accepted_prefix_base(snapshot, workspace, generation.number, parent)?;
        self.check_prefix_generation_binding(snapshot, workspace, generation, &base, parent)?;
        if raw.generation != generation.number
            || raw.custody_version != generation.custody_version
            || raw.analyzer != generation.analyzer
            || generation.bm25.as_ref() != Some(&raw.bm25)
            || raw.authorization_epoch != generation.authorization_epoch
            || raw.removal_through != generation.removal_through
            || raw.through > generation.through
            || raw.projected_sources > generation.projected_sources
            || (raw.through == generation.through
                && raw.projected_sources != generation.projected_sources)
            || generation.dense_graph.is_some()
            || generation.dense_segments.is_some()
            || manifest.after.profile != latest.profile
            || manifest.after.profile_digest != latest.profile_digest
            || manifest.after.vector_space_id != latest.vector_space_id
            || manifest.after.through > latest.through
            || manifest.after.sources > latest.sources
            || manifest.after.embedded_sources > latest.embedded_sources
            || manifest.after.omitted_sources > latest.omitted_sources
            || manifest.after.spans > latest.spans
            || (manifest.after.through == latest.through && manifest.after != *latest)
            || manifest.ordinal > current.count
            || manifest.base
                != self.prefix_segment_base_reference(snapshot, workspace, &base, parent)?
        {
            return Err(integrity(
                "prefix interval differs from its full retained raw generation",
            ));
        }
        if manifest.ordinal == current.count
            && self.prefix_segment_directory_reference(snapshot, &publication.directory, parent)?
                != *current
        {
            return Err(integrity(
                "latest prefix interval differs from exact generation directory reference",
            ));
        }
        Ok(())
    }

    /// The caller supplies the complete ascending accepted declaration set.
    /// Missing ordinals or a stripped/latest mismatched root refuse before any
    /// remaining GC row may be treated as opaque authenticated data.
    pub(in crate::raw_index) fn validate_prefix_segment_declarations<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        declarations: &[&PrefixSegmentPublicationV2],
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.check().map_err(budget_error)?;
        let Some(current) = &generation.dense_prefix_segments else {
            return if declarations.is_empty() {
                Ok(())
            } else {
                Err(integrity(
                    "accepted prefix intervals lost their generation directory",
                ))
            };
        };
        current.validate()?;
        let count = u64::try_from(declarations.len())
            .map_err(|_| exhausted("prefix declaration cardinality overflow"))?;
        if count != current.count {
            return Err(integrity(
                "prefix interval declarations do not cover every accepted ordinal",
            ));
        }
        let mut previous: Option<&PrefixSegmentPublicationV2> = None;
        for (index, publication) in declarations.iter().copied().enumerate() {
            parent.charge(1, 0).map_err(budget_error)?;
            let ordinal = u64::try_from(index)
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| exhausted("prefix declaration ordinal overflow"))?;
            if publication.delta.manifest.ordinal != ordinal
                || publication.directory.head.count != ordinal
            {
                return Err(integrity(
                    "prefix interval declarations are not contiguous from one",
                ));
            }
            self.check_prefix_segment_generation_binding(
                snapshot,
                workspace,
                generation,
                publication,
                parent,
            )?;
            match previous {
                None => {
                    if publication.directory.head.previous.is_some() {
                        return Err(integrity(
                            "first prefix interval has an invented predecessor",
                        ));
                    }
                }
                Some(previous) => {
                    self.check_prefix_interval_predecessor(snapshot, previous, publication, parent)?
                }
            }
            previous = Some(publication);
        }
        let last = previous.ok_or_else(|| {
            integrity("prefix directory has no complete accepted declaration set")
        })?;
        if self.prefix_segment_directory_reference(snapshot, &last.directory, parent)? != *current {
            return Err(integrity(
                "complete prefix declaration set ends at a different generation head",
            ));
        }
        Ok(())
    }

    fn check_prefix_interval_predecessor<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        previous: &PrefixSegmentPublicationV2,
        next: &PrefixSegmentPublicationV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let old = &previous.delta.manifest;
        let new = &next.delta.manifest;
        let expected =
            self.prefix_segment_directory_reference(snapshot, &previous.directory, parent)?;
        if old.ordinal.checked_add(1) != Some(new.ordinal)
            || next.directory.head.previous.as_ref() != Some(&expected)
            || new.base != old.base
            || new.before != old.after
            || new.before_dense != old.target_dense
            || new.start != old.end
            || new.raw.generation != old.raw.generation
            || new.raw.custody_version != old.raw.custody_version
            || new.raw.analyzer != old.raw.analyzer
            || new.raw.bm25 != old.raw.bm25
            || new.raw.authorization_epoch != old.raw.authorization_epoch
            || new.raw.removal_through != old.raw.removal_through
            || new.raw.through < old.raw.through
            || new.raw.projected_sources < old.raw.projected_sources
            || (new.raw.through == old.raw.through
                && new.raw.projected_sources != old.raw.projected_sources)
            || new.admitted_known_at < old.admitted_known_at
            || new.admitted_global_commit <= old.admitted_global_commit
            || next.delta.global_commit <= previous.delta.global_commit
        {
            return Err(integrity(
                "prefix interval chain differs from its exact accepted predecessor",
            ));
        }
        Ok(())
    }

    /// Reconstruct only immutable rows. The caller adds the latest mutable
    /// directory ONCE after checking the complete ascending declaration set.
    pub(in crate::raw_index) fn reconstruct_prefix_segment_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        publication: &PrefixSegmentPublicationV2,
        parent: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        parent.check().map_err(budget_error)?;
        let reference =
            self.prefix_publication_ref(snapshot, publication.delta.global_commit, parent)?;
        self.check_prefix_segment_publication(
            snapshot,
            workspace,
            &reference,
            publication,
            parent,
        )?;
        let accepted = &publication.delta.manifest;
        if accepted.ordinal > 1 {
            let previous = self.accepted_prefix_segment_for_ordinal(
                snapshot,
                workspace,
                accepted.raw.generation,
                accepted.ordinal - 1,
                parent,
            )?;
            self.check_prefix_interval_predecessor(snapshot, &previous, publication, parent)?;
        }
        let before = self.verify_prefix_segment_dense_state(
            snapshot,
            workspace,
            &accepted.before_dense,
            parent,
        )?;
        let after = self.verify_prefix_segment_dense_state(
            snapshot,
            workspace,
            &accepted.target_dense,
            parent,
        )?;
        if before.manifest() != &accepted.before || after.manifest() != &accepted.after {
            return Err(integrity(
                "prefix reconstruction accepted dense states differ",
            ));
        }
        let start = self.verify_prefix_segment_capture_boundary(
            snapshot,
            workspace,
            &accepted.start,
            parent,
        )?;
        let proof =
            self.verify_prefix_segment_interval(snapshot, workspace, before, after, start, parent)?;
        if proof.end().reference() != &accepted.end
            || proof.work().len() as u64 != u64::from(accepted.interval.work_items)
        {
            return Err(integrity(
                "prefix reconstruction actual ending/work interval differs",
            ));
        }
        let base =
            self.accepted_prefix_base(snapshot, workspace, accepted.raw.generation, parent)?;
        if self.prefix_segment_base_reference(snapshot, workspace, &base, parent)? != accepted.base
        {
            return Err(integrity(
                "prefix reconstruction lost its exact accepted base",
            ));
        }
        let base_reference = self.prefix_base_reference(snapshot, &base, parent)?;
        let bytes = metered_json_len(accepted, parent, types::ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 32 + 16384)
            .map_err(budget_error)?;
        let raw = &accepted.raw;
        // This is the signed FULL raw admission envelope plus its accepted
        // after state. It is not a fabricated lower-counter v1 generation or a
        // reconstructed physical snapshot. The new directory is not builder input.
        let frozen = Generation {
            number: raw.generation,
            custody_version: raw.custody_version,
            analyzer: raw.analyzer.clone(),
            through: raw.through,
            authorization_epoch: raw.authorization_epoch,
            projected_sources: raw.projected_sources,
            removal_through: raw.removal_through,
            bm25: Some(raw.bm25.clone()),
            dense: Some(accepted.after.clone()),
            dense_graph: None,
            dense_segments: None,
            dense_prefix_base: Some(base_reference),
            dense_prefix_segments: None,
        };
        let input = self.prefix_segment_build_input(
            snapshot,
            None,
            workspace,
            &frozen,
            &accepted.base,
            &proof,
            parent,
        )?;
        if input.interval != accepted.interval {
            return Err(integrity(
                "prefix reconstruction full interval digest differs",
            ));
        }
        let mut manifest = accepted.clone();
        let mut rows = self.construct_prefix_segment(
            workspace,
            &frozen,
            &mut manifest,
            &input.inputs,
            parent,
        )?;
        if &manifest != accepted {
            return Err(integrity(
                "prefix reconstructed entire final manifest differs",
            ));
        }
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let key = delta_receipt_key(workspace, raw.generation, accepted.ordinal)?;
        let value = metered_encode(&publication.delta, parent, types::ROW_BYTES)?;
        // Reserve a full possible BTree split chain before moving buffers into
        // the map; the metered encoder has already admitted the value allocation.
        let height = usize::BITS - rows.len().saturating_add(1).leading_zeros() + 2;
        parent
            .charge(1, u64::from(height) * 2048)
            .map_err(budget_error)?;
        if rows.insert(key, value).is_some() {
            return Err(integrity(
                "prefix receipt overlaps reconstructed immutable topology",
            ));
        }
        Ok(rows)
    }
}
