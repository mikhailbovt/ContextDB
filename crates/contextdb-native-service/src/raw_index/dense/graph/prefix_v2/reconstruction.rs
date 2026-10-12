//! Reconstruct the accepted historical prefix without neural re-embedding.

use super::*;

impl NativeService {
    pub(in crate::raw_index::dense::graph) fn check_prefix_generation_binding<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        receipt: &DensePrefixBaseReceiptV2,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let raw = &receipt.manifest.raw;
        let prefix = &receipt.manifest.prefix;
        let latest = generation
            .dense
            .as_ref()
            .ok_or_else(|| integrity("prefix generation lost dense profile"))?;
        if receipt.database_id != self.database_id
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || raw.generation != generation.number
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
            || prefix.profile != latest.profile
            || prefix.profile_digest != latest.profile_digest
            || prefix.vector_space_id != latest.vector_space_id
            || prefix.through > latest.through
            || prefix.sources > latest.sources
            || prefix.spans > latest.spans
            || prefix.embedded_sources > latest.embedded_sources
            || prefix.omitted_sources > latest.omitted_sources
            || generation.dense_prefix_base.as_ref()
                != Some(&self.prefix_base_reference(snapshot, receipt, budget)?)
        {
            return Err(integrity(
                "prefix base differs from its real retained generation",
            ));
        }
        Ok(())
    }

    pub(in crate::raw_index) fn validate_dense_prefix_base_declaration<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        declaration: Option<&DensePrefixBaseReceiptV2>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if generation.dense_prefix_base.is_some() != declaration.is_some() {
            return Err(integrity(
                "prefix generation differs from its accepted declaration",
            ));
        }
        if let Some(receipt) = declaration {
            self.check_prefix_generation_binding(snapshot, workspace, generation, receipt, budget)?;
        }
        Ok(())
    }

    pub(in crate::raw_index) fn reconstruct_prefix_base_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        receipt: &DensePrefixBaseReceiptV2,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        let target = self.verify_accepted_prefix_dense_target(
            snapshot,
            workspace,
            &receipt.manifest.target,
            budget,
        )?;
        let raw = &receipt.manifest.raw;
        budget.charge(1, 32768).map_err(budget_error)?;
        // These are the owner-accepted FULL raw admission values. They are not
        // reduced to the dense cutoff and never become a legacy graph receipt.
        let admission = Generation {
            number: raw.generation,
            custody_version: raw.custody_version,
            analyzer: raw.analyzer.clone(),
            through: raw.through,
            authorization_epoch: raw.authorization_epoch,
            projected_sources: raw.projected_sources,
            removal_through: raw.removal_through,
            bm25: Some(raw.bm25.clone()),
            dense: Some(receipt.manifest.prefix.clone()),
            dense_graph: None,
            dense_segments: None,
            dense_prefix_base: None,
            dense_prefix_segments: None,
        };
        let input =
            self.prefix_build_input(snapshot, None, workspace, &admission, &target, budget)?;
        if input.interval != receipt.manifest.interval {
            return Err(integrity("prefix accepted interval reconstruction differs"));
        }
        let mut manifest = receipt.manifest.clone();
        let mut rows = self.construct_prefix_base(
            workspace,
            &admission,
            &mut manifest,
            &input.inputs,
            budget,
        )?;
        if manifest != receipt.manifest {
            return Err(integrity("prefix topology reconstruction differs"));
        }
        rows.insert(receipt_key(workspace, raw.generation)?, encode(receipt)?);
        Ok(rows)
    }
}
