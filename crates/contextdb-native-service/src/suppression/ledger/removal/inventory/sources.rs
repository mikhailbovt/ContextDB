//! Point lookup of an accepted source witness using a request-bound page hash.
//! A forged locator cannot turn a source absent from the request into a target.

use crate::NativeDeletionSource;

use super::*;

const PAGE_ENTRIES: usize = 256;
const PAGE_BYTES: usize = 512 * 1024;

pub(in super::super) fn source_page_digests(
    inventory: &NativeDeletionLineage,
) -> ServiceResult<Vec<ContentDigest>> {
    inventory
        .sources
        .chunks(PAGE_ENTRIES)
        .enumerate()
        .map(|(index, page)| Ok(page_digest(inventory.digest, index, &encode_page(page)?)))
        .collect()
}

pub(super) fn source_rows(
    inventory: &NativeDeletionLineage,
    budget: &mut QueryBudget,
) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut rows = BTreeMap::new();
    for (index, page) in inventory.sources.chunks(PAGE_ENTRIES).enumerate() {
        let bytes = encode_page(page)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        rows.insert(page_key(inventory.digest, index), bytes);
        for source in page {
            let key = source_key(inventory.digest, source.receipt.event_id);
            let value = encode(&index)?;
            budget
                .charge(1, (key.len() + value.len()) as u64)
                .map_err(budget_error)?;
            rows.insert(key, value);
        }
    }
    Ok(rows)
}

impl NativeSuppressionLedger {
    pub(crate) fn removal_source(
        &self,
        workspace: &str,
        request: &RemovalCheckpoint,
        id: ObservationId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeDeletionSource> {
        self.require_removal_authority()?;
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let head = self.removal_global_head(&snapshot)?;
        if request.sequence == 0 || request.sequence > head.sequence {
            return Err(integrity("removal source references an unknown request"));
        }
        let event = self.read_removal_event(&snapshot, request.sequence)?;
        budget
            .charge(1, encode(&event)?.len() as u64)
            .map_err(budget_error)?;
        let Operation::Request {
            intent,
            source_pages,
        } = &event.operation
        else {
            return Err(integrity(
                "removal source references workspace registration",
            ));
        };
        if event.checkpoint() != *request || intent.workspace != workspace {
            return Err(integrity("removal source request binding differs"));
        }
        let bytes = snapshot
            .get(&self.rows, &source_key(intent.lineage_digest, id))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("removal source is absent from the accepted inventory"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let index: usize = decode(&bytes, "removal source locator")?;
        let expected = source_pages
            .get(index)
            .ok_or_else(|| integrity("removal source page is outside its manifest"))?;
        let bytes = snapshot
            .get(&self.rows, &page_key(intent.lineage_digest, index))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("removal source page is missing"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > PAGE_BYTES
            || page_digest(intent.lineage_digest, index, &bytes) != *expected
        {
            return Err(integrity(
                "removal source page differs from its accepted commitment",
            ));
        }
        let page: Vec<NativeDeletionSource> = decode(&bytes, "removal source page")?;
        if page.is_empty() || page.len() > PAGE_ENTRIES {
            return Err(integrity("removal source page exceeds its bound"));
        }
        let source = page
            .into_iter()
            .find(|source| source.receipt.event_id == id)
            .ok_or_else(|| integrity("removal source locator points at another source"))?;
        if digest_bytes(source.receipt.workspace_id.to_string().as_bytes()) != workspace
            || digest_bytes(source.receipt.database_id.as_bytes()) != self.identity.database
        {
            return Err(integrity("removal source belongs to another authority"));
        }
        Ok(source)
    }
}

fn encode_page(page: &[NativeDeletionSource]) -> ServiceResult<Vec<u8>> {
    let bytes = encode(&page)?;
    if bytes.len() > PAGE_BYTES {
        return Err(exhausted("removal source page exceeds 512 KiB"));
    }
    Ok(bytes)
}

fn page_digest(lineage: ContentDigest, index: usize, bytes: &[u8]) -> ContentDigest {
    let mut hash = blake3::Hasher::new();
    hash.update(b"contextdb/native-removal-source-page/v1\0");
    hash.update(lineage.as_bytes());
    hash.update(&(index as u64).to_be_bytes());
    hash.update(bytes);
    ContentDigest::from_bytes(*hash.finalize().as_bytes())
}

fn page_key(lineage: ContentDigest, index: usize) -> Vec<u8> {
    format!("removal/control/{lineage}/page/{index:08}").into_bytes()
}
fn source_key(lineage: ContentDigest, id: ObservationId) -> Vec<u8> {
    format!("removal/control/{lineage}/source/{id}").into_bytes()
}
