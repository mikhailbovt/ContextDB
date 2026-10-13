//! Exact immutable reconstruction from accepted historical directory authority.

use super::super::segments::crypto::{metered_encode, metered_json_len};
use super::*;

impl NativeService {
    /// Reconstruct one immutable router revision only. The administrative caller
    /// inserts the latest mutable head once after checking all declarations.
    pub(in crate::raw_index) fn reconstruct_directory_router_rows<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        receipt: &DirectoryRouterReceiptV1,
        parent: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        parent.check().map_err(budget_error)?;
        let proof = self.verify_accepted_router_directory(snapshot, workspace, receipt, parent)?;
        let input = self.router_build_input(snapshot, None, &proof, parent)?;
        let accepted = &receipt.manifest;
        if input.coverage_count != accepted.coverage_count
            || input.coverage_digest != accepted.coverage_digest
            || input.inputs.len() as u64 != accepted.representatives
        {
            return Err(integrity("router complete historical coverage differs"));
        }
        let bytes = metered_json_len(accepted, parent, ROW_BYTES)?;
        parent
            .charge(bytes as u64 + 1, bytes as u64 * 32 + 16384)
            .map_err(budget_error)?;
        let mut manifest = accepted.clone();
        let mut rows = self.construct_directory_router(
            workspace,
            proof.generation(),
            &mut manifest,
            &input.inputs,
            parent,
        )?;
        if &manifest != accepted {
            return Err(integrity(
                "router entire reconstructed final manifest differs",
            ));
        }
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let key = receipt_key(workspace, accepted.raw.generation, accepted.serial)?;
        let value = metered_encode(receipt, parent, ROW_BYTES)?;
        let levels = u64::from(usize::BITS - rows.len().saturating_add(1).leading_zeros()) + 2;
        parent
            .charge(levels * 12, levels * 2048)
            .map_err(budget_error)?;
        if rows.insert(key, value).is_some() {
            return Err(integrity(
                "router receipt overlaps immutable reconstructed topology",
            ));
        }
        Ok(rows)
    }
}
