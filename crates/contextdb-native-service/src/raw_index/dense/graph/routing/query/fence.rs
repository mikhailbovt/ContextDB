//! Exact current bytes of an already fully admitted, private serving view.
//! This avoids repeat reconstruction, never initial authority or source gates.

use super::super::super::super::prefix_segments_v2::{
    heads::CertifiedCurrentHeadRows, types::PrefixSegmentDirectoryReceiptV2,
};
use super::super::super::super::prefix_v2::types::DensePrefixBaseReceiptV2;
use super::super::super::super::segments::crypto::metered_encode;
use super::super::*;
use contextdb_storage::ScanPageRequest;
use std::mem::size_of;

const HEAD_BYTES: usize = 8 * 1024;
const MAX_ROWS: usize = 10;

#[derive(Clone, Copy)]
enum Space {
    Meta,
    Workspace,
    Map,
    Event,
    Continuous,
}
struct Row {
    space: Space,
    key: Vec<u8>,
    bytes: Vec<u8>,
    cap: usize,
}
pub(super) struct AdmittedRows<'a> {
    pub(super) state: &'a IndexState,
    pub(super) generation: &'a Generation,
    pub(super) router: &'a DirectoryRouterReceiptV1,
    pub(super) dense: &'a DenseProjectionReceipt,
    pub(super) base: &'a DensePrefixBaseReceiptV2,
    pub(super) directory: Option<&'a PrefixSegmentDirectoryReceiptV2>,
}
pub(super) struct CurrentCertificate {
    rows: Vec<Row>,
    workspace_prefix: Vec<u8>,
    map_key: Vec<u8>,
    latest_global: u64,
}

impl CurrentCertificate {
    pub(super) fn mint(
        heads: CertifiedCurrentHeadRows,
        world: &crate::WorkspaceState,
        admitted: AdmittedRows<'_>,
        parent: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        // Fixed slots, capped keys and all buffers are admitted before growth.
        // The six canonical encodings below equal the exact bytes which the
        // successful initial prefix_read/point admission already compared.
        parent
            .charge(
                (MAX_ROWS as u64 + 2) * KEY_BYTES + 1,
                MAX_ROWS as u64 * (size_of::<Row>() as u64 + KEY_BYTES)
                    + 2 * KEY_BYTES
                    + size_of::<Self>() as u64
                    + 256,
            )
            .map_err(budget_error)?;
        let mut rows = Vec::with_capacity(MAX_ROWS);
        let workspace = &world.workspace_digest;
        let generation = admitted.generation.number;
        let map_key = crate::workspace_map_key(workspace, world.watermarks.journal);
        let mut workspace_prefix = workspace.as_bytes().to_vec();
        workspace_prefix.push(b'/');
        push(
            &mut rows,
            Space::Workspace,
            workspace.as_bytes().to_vec(),
            required(heads.workspace)?,
            HEAD_BYTES,
        )?;
        push(
            &mut rows,
            Space::Meta,
            crate::META_MANIFEST_KEY.to_vec(),
            required(heads.manifest)?,
            ROW_BYTES,
        )?;
        push(
            &mut rows,
            Space::Map,
            map_key.clone(),
            required(heads.mapping)?,
            HEAD_BYTES,
        )?;
        push(
            &mut rows,
            Space::Event,
            world.latest_global_commit.to_be_bytes().to_vec(),
            required(heads.event)?,
            crate::MAX_JSON_BYTES,
        )?;
        push(
            &mut rows,
            Space::Continuous,
            state_key(workspace),
            metered_encode(admitted.state, parent, ROW_BYTES)?,
            ROW_BYTES,
        )?;
        push(
            &mut rows,
            Space::Continuous,
            generation_key(workspace, generation),
            metered_encode(admitted.generation, parent, ROW_BYTES)?,
            ROW_BYTES,
        )?;
        push(
            &mut rows,
            Space::Continuous,
            head_key(workspace, generation)?,
            metered_encode(admitted.router, parent, ROW_BYTES)?,
            ROW_BYTES,
        )?;
        push(
            &mut rows,
            Space::Continuous,
            dense::receipt_key(workspace, generation),
            metered_encode(admitted.dense, parent, ROW_BYTES)?,
            ROW_BYTES,
        )?;
        push(
            &mut rows,
            Space::Continuous,
            prefix_v2::types::receipt_key(workspace, generation)?,
            metered_encode(admitted.base, parent, ROW_BYTES)?,
            ROW_BYTES,
        )?;
        if let Some(directory) = admitted.directory {
            push(
                &mut rows,
                Space::Continuous,
                prefix_segments_v2::types::directory_head_key(workspace, generation)?,
                metered_encode(directory, parent, ROW_BYTES)?,
                ROW_BYTES,
            )?;
        }
        let cap = [crate::MAX_JSON_BYTES, 2 * HEAD_BYTES, 7 * ROW_BYTES]
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .ok_or_else(|| integrity("routed current certificate bound overflow"))?;
        let bytes = rows
            .iter()
            .try_fold(0usize, |sum, row| sum.checked_add(row.bytes.len()))
            .ok_or_else(|| integrity("routed current certificate size overflow"))?;
        if bytes > cap {
            return Err(integrity(
                "routed current certificate exceeds fixed row bounds",
            ));
        }
        parent.check().map_err(budget_error)?;
        Ok(Self {
            rows,
            workspace_prefix,
            map_key,
            latest_global: world.latest_global_commit,
        })
    }

    pub(super) fn check<S: ReadSnapshot>(
        &self,
        native: &NativeService,
        current: &S,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.check().map_err(budget_error)?;
        for row in &self.rows {
            let space = match row.space {
                Space::Meta => &native.keyspaces.meta,
                Space::Workspace => &native.keyspaces.workspace,
                Space::Map => &native.keyspaces.workspace_map,
                Space::Event => &native.keyspaces.events,
                Space::Continuous => &native.keyspaces.continuous,
            };
            // Preserve the original metadata row bound and storage error types.
            // Caps are not charges: reads pay actual returned bytes. A genuine
            // larger, legally bounded row is a changed view, never new authority.
            let actual = crate::budgeted::read_value(current, space, &row.key, row.cap, parent)?
                .ok_or_else(stale_index)?;
            // Prepay every possible comparison byte, even an early mismatch.
            // Transfer/allocation was charged by read_value under this parent.
            parent
                .charge((actual.len() + row.bytes.len()) as u64 + 1, 0)
                .map_err(budget_error)?;
            if actual != row.bytes {
                return Err(stale_index());
            }
        }
        let head = crate::budgeted::read_value(
            current,
            &native.keyspaces.meta,
            crate::META_GLOBAL_HEAD_KEY,
            8,
            parent,
        )?;
        parent.charge(9, 0).map_err(budget_error)?;
        let global = head
            .as_deref()
            .map(|bytes| crate::decode_u64(bytes, "routed current global head"))
            .transpose()?
            .unwrap_or(0);
        // A foreign workspace may advance the global scalar. It cannot change
        // this query's exact workspace certificate or create fresh authority.
        if global < self.latest_global {
            return Err(integrity("routed workspace exceeds current global head"));
        }
        let page = crate::budgeted::metadata(current, parent, |meter| {
            meter
                .scan_prefix_page(
                    &native.keyspaces.workspace_map,
                    ScanPageRequest {
                        prefix: &self.workspace_prefix,
                        start_after: Some(&self.map_key),
                        max_entries: 1,
                        max_bytes: HEAD_BYTES + 256,
                    },
                )
                .map_err(storage_error)
        })?;
        if !page.entries.is_empty() || page.continuation.is_some() {
            return Err(integrity(
                "routed current workspace has an accepted successor",
            ));
        }
        parent.check().map_err(budget_error)
    }
}

fn required(bytes: Option<Vec<u8>>) -> ServiceResult<Vec<u8>> {
    bytes.ok_or_else(|| integrity("routed admitted canonical head row absent"))
}
fn push(
    rows: &mut Vec<Row>,
    space: Space,
    key: Vec<u8>,
    bytes: Vec<u8>,
    cap: usize,
) -> ServiceResult<()> {
    if rows.len() >= MAX_ROWS || key.len() > KEY_BYTES as usize || bytes.len() > cap {
        return Err(integrity("routed certificate row exceeds admitted bounds"));
    }
    rows.push(Row {
        space,
        key,
        bytes,
        cap,
    });
    Ok(())
}
