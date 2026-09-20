//! Exact inspected source closure, retained in the same Sync as its request.
//! Chunking bounds each value; the request commits the complete canonical report.

use crate::NativeDeletionLineage;

use super::*;

const CHUNK_BYTES: usize = 256 * 1024;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_TARGETS: usize = 65_536;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    bytes: usize,
    chunks: usize,
    digest: ContentDigest,
}

pub(super) fn rows(
    inventory: &NativeDeletionLineage,
    budget: &mut QueryBudget,
) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let bytes = encode(inventory)?;
    if bytes.len() > MAX_BYTES {
        return Err(exhausted("retained source inventory exceeds 64 MiB"));
    }
    budget
        .charge(
            (inventory.sources.len()
                + inventory.payloads.len()
                + inventory.retained_shared_payloads.len()) as u64,
            bytes.len() as u64,
        )
        .map_err(budget_error)?;
    let header = Header {
        bytes: bytes.len(),
        chunks: bytes.len().div_ceil(CHUNK_BYTES),
        digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
    };
    let prefix = prefix(inventory.digest);
    let mut rows = BTreeMap::from([(format!("{prefix}head").into_bytes(), encode(&header)?)]);
    for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        rows.insert(format!("{prefix}{index:08}").into_bytes(), chunk.to_vec());
    }
    Ok(rows)
}

impl NativeSuppressionLedger {
    pub(super) fn validate_removal_inventory(
        &self,
        intent: &RemovalIntent,
        inventory: &NativeDeletionLineage,
    ) -> ServiceResult<()> {
        let ids: BTreeSet<_> = inventory
            .sources
            .iter()
            .map(|s| s.receipt.event_id)
            .collect();
        let roots: Vec<_> = inventory
            .sources
            .iter()
            .filter(|s| inventory.roots.contains(&s.receipt.event_id))
            .map(|s| s.receipt.clone())
            .collect();
        let blocks: BTreeSet<_> = inventory
            .payloads
            .iter()
            .chain(&inventory.retained_shared_payloads)
            .map(|b| b.block_id)
            .collect();
        if inventory.digest != intent.lineage_digest
            || digest_bytes(inventory.database_id.as_bytes()) != self.identity.database
            || digest_bytes(inventory.workspace_id.as_bytes()) != intent.workspace
            || inventory.workspace_commit != intent.native_commit
            || inventory.roots != intent.roots.iter().map(|s| s.event_id).collect()
            || roots != intent.roots
            || !inventory.roots.is_subset(&ids)
            || ids.len() != inventory.sources.len()
            || blocks.len() != inventory.payloads.len() + inventory.retained_shared_payloads.len()
            || ids.len() + blocks.len() > MAX_TARGETS
            || inventory
                .sources
                .windows(2)
                .any(|pair| pair[0].receipt.workspace_commit >= pair[1].receipt.workspace_commit)
            || inventory.sources.iter().any(|source| {
                let receipt = &source.receipt;
                receipt.domain != contextdb_service::NATIVE_CAPTURE_DOMAIN
                    || receipt.database_id != inventory.database_id
                    || receipt.workspace_id.to_string() != inventory.workspace_id
                    || receipt.workspace_commit == 0
                    || receipt.workspace_commit > inventory.workspace_commit
            })
        {
            return Err(integrity(
                "retained source inventory differs from its request",
            ));
        }
        inventory.verify_commitment()
    }

    pub(super) fn read_removal_inventory<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        intent: &RemovalIntent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeDeletionLineage> {
        let prefix = prefix(intent.lineage_digest);
        let encoded = snapshot
            .get(&self.rows, format!("{prefix}head").as_bytes())
            .map_err(storage_error)?
            .ok_or_else(|| integrity("retained source inventory header is missing"))?;
        budget
            .charge(1, encoded.len() as u64)
            .map_err(budget_error)?;
        let header: Header = decode(&encoded, "retained source inventory header")?;
        if header.bytes == 0
            || header.bytes > MAX_BYTES
            || header.chunks != header.bytes.div_ceil(CHUNK_BYTES)
        {
            return Err(integrity("retained source inventory bounds are invalid"));
        }
        budget
            .charge(0, header.bytes as u64)
            .map_err(budget_error)?;
        let mut bytes = Vec::with_capacity(header.bytes);
        for index in 0..header.chunks {
            let chunk = snapshot
                .get(&self.rows, format!("{prefix}{index:08}").as_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| integrity("retained source inventory chunk is missing"))?;
            budget.charge(1, chunk.len() as u64).map_err(budget_error)?;
            if chunk.len() != (header.bytes - bytes.len()).min(CHUNK_BYTES) {
                return Err(integrity("retained source inventory chunk length differs"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()) != header.digest {
            return Err(integrity("retained source inventory bytes differ"));
        }
        let inventory: NativeDeletionLineage = decode(&bytes, "retained source inventory")?;
        self.validate_removal_inventory(intent, &inventory)?;
        Ok(inventory)
    }
}

fn prefix(digest: ContentDigest) -> String {
    format!("removal/inventory/{digest}/")
}

pub(super) fn verification_budget() -> QueryBudget {
    QueryBudget::new(
        u64::MAX,
        u64::MAX,
        std::time::Duration::from_secs(3600),
        Default::default(),
    )
}
