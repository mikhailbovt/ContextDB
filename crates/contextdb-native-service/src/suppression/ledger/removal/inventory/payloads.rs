//! Bounded proof of selected block membership, excluding independently shared blocks.

use contextdb_core::{ContentBlockId, OriginalPayloadRef};

use super::*;

const PAGE_ENTRIES: usize = 256;
const PAGE_BYTES: usize = 128 * 1024;

pub(in super::super) fn payload_page_digests(
    inventory: &NativeDeletionLineage,
) -> ServiceResult<Vec<ContentDigest>> {
    inventory
        .payloads
        .chunks(PAGE_ENTRIES)
        .enumerate()
        .map(|(index, page)| Ok(page_digest(inventory.digest, index, &encode_page(page)?)))
        .collect()
}

pub(super) fn payload_rows(
    inventory: &NativeDeletionLineage,
    budget: &mut QueryBudget,
) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut rows = BTreeMap::new();
    for (index, page) in inventory.payloads.chunks(PAGE_ENTRIES).enumerate() {
        let bytes = encode_page(page)?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        rows.insert(page_key(inventory.digest, index), bytes);
        for payload in page {
            let key = payload_key(inventory.digest, payload.block_id);
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
    pub(crate) fn removal_payload(
        &self,
        workspace: &str,
        request: &RemovalCheckpoint,
        id: ContentBlockId,
        budget: &mut QueryBudget,
    ) -> ServiceResult<OriginalPayloadRef> {
        self.require_removal_authority()?;
        budget.check().map_err(budget_error)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        if request.sequence == 0 || request.sequence > self.removal_global_head(&snapshot)?.sequence
        {
            return Err(integrity("removal payload references an unknown request"));
        }
        let event = self.read_removal_event(&snapshot, request.sequence)?;
        budget
            .charge(1, encode(&event)?.len() as u64)
            .map_err(budget_error)?;
        let Operation::Request {
            intent,
            payload_pages,
            ..
        } = &event.operation
        else {
            return Err(integrity(
                "removal payload references workspace registration",
            ));
        };
        if event.checkpoint() != *request || intent.workspace != workspace {
            return Err(integrity("removal payload request binding differs"));
        }
        let bytes = snapshot
            .get(&self.rows, &payload_key(intent.lineage_digest, id))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("payload is not selected by the retained removal request"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let index: usize = decode(&bytes, "removal payload locator")?;
        let expected = payload_pages
            .get(index)
            .ok_or_else(|| integrity("removal payload page is outside its manifest"))?;
        let bytes = snapshot
            .get(&self.rows, &page_key(intent.lineage_digest, index))
            .map_err(storage_error)?
            .ok_or_else(|| integrity("removal payload page is absent"))?;
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        if bytes.len() > PAGE_BYTES
            || page_digest(intent.lineage_digest, index, &bytes) != *expected
        {
            return Err(integrity(
                "removal payload page differs from its accepted commitment",
            ));
        }
        let page: Vec<OriginalPayloadRef> = decode(&bytes, "removal payload page")?;
        if page.is_empty() || page.len() > PAGE_ENTRIES {
            return Err(integrity("removal payload page exceeds its bound"));
        }
        page.into_iter()
            .find(|payload| payload.block_id == id)
            .ok_or_else(|| integrity("removal payload locator points at another block"))
    }
}

fn encode_page(page: &[OriginalPayloadRef]) -> ServiceResult<Vec<u8>> {
    let bytes = encode(&page)?;
    if bytes.len() > PAGE_BYTES {
        return Err(exhausted("removal payload page exceeds 128 KiB"));
    }
    Ok(bytes)
}
fn page_digest(lineage: ContentDigest, index: usize, bytes: &[u8]) -> ContentDigest {
    let mut hash = blake3::Hasher::new();
    hash.update(b"contextdb/native-removal-payload-page/v1\0");
    hash.update(lineage.as_bytes());
    hash.update(&(index as u64).to_be_bytes());
    hash.update(bytes);
    ContentDigest::from_bytes(*hash.finalize().as_bytes())
}
fn page_key(lineage: ContentDigest, index: usize) -> Vec<u8> {
    format!("removal/control/{lineage}/payload-page/{index:08}").into_bytes()
}
fn payload_key(lineage: ContentDigest, id: ContentBlockId) -> Vec<u8> {
    format!("removal/control/{lineage}/payload/{id}").into_bytes()
}
