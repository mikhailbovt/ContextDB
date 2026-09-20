//! Accepted metadata for a record birth or closure, without its arbitrary bodies.
//! Bodies remain mandatory until a separate verified pruning transition exists.

use contextdb_service::{DomainTimeRange, MemoryLinks};

use super::*;

pub(crate) mod preparation;
pub(crate) mod witness;

#[cfg(test)]
mod tests;

pub(crate) const CONTROL_FEATURE: &str = "continuous-record-controls-v1";
const PREFIX: &[u8] = b"record-control/";
const ACTIVATED: &[u8] = b"record-control/activated";

/// Access policy is host configuration. Record identifiers, linkage strings,
/// values, lexical text, vectors and extension attributes are committed by hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordControl {
    version: u16,
    pub(super) policy: StoredPolicy,
    document_digest: String,
    valid_time: DomainTimeRange,
    /// Every string is a digest; the original IDs/predicates are never copied.
    links: MemoryLinks,
    value_digest: String,
    search_digest: String,
    vector_digest: String,
    attributes_digest: String,
}

impl RecordControl {
    pub(super) fn from_record(record: &MemoryRecord) -> ServiceResult<Self> {
        let document = &record.document;
        let hash = |value: &str| digest_bytes(value.as_bytes());
        let optional = |value: &Option<String>| value.as_deref().map(hash);
        let set = |values: &BTreeSet<String>| values.iter().map(|value| hash(value)).collect();
        Ok(Self {
            version: 1,
            policy: policy_for(record)?,
            document_digest: canonical_digest(document)?,
            valid_time: document.valid_time,
            links: MemoryLinks {
                subject: optional(&document.links.subject),
                source: optional(&document.links.source),
                target: optional(&document.links.target),
                predicate: optional(&document.links.predicate),
                conflict_set: optional(&document.links.conflict_set),
                supersedes: set(&document.links.supersedes),
                evidence: set(&document.links.evidence),
                conflict_members: set(&document.links.conflict_members),
                single_valued: document.links.single_valued,
            },
            value_digest: canonical_digest(&document.value)?,
            search_digest: canonical_digest(&document.search_text)?,
            vector_digest: canonical_digest(&document.vector)?,
            attributes_digest: canonical_digest(&document.attributes)?,
        })
    }

    fn validate(&self) -> ServiceResult<()> {
        validate_stored_policy(&self.policy)?;
        let mut digests = [
            &self.document_digest,
            &self.value_digest,
            &self.search_digest,
            &self.vector_digest,
            &self.attributes_digest,
        ]
        .into_iter()
        .chain(
            [
                &self.links.subject,
                &self.links.source,
                &self.links.target,
                &self.links.predicate,
                &self.links.conflict_set,
            ]
            .into_iter()
            .flatten(),
        )
        .chain(&self.links.supersedes)
        .chain(&self.links.evidence)
        .chain(&self.links.conflict_members);
        if self.version != 1
            || self
                .valid_time
                .from
                .zip(self.valid_time.to)
                .is_some_and(|(from, to)| from >= to)
            || digests.any(|digest| blake3::Hash::from_hex(digest).is_err())
        {
            return Err(integrity("record control metadata is invalid"));
        }
        Ok(())
    }

    fn validate_binding(
        &self,
        event: &StoredEvent,
        reference: &RecordMutationRef,
    ) -> ServiceResult<()> {
        self.validate()?;
        let policy = &self.policy;
        if event.event_digest != event_digest(event)?
            || event.global_commit == 0
            || !owns_record_mutations(&event.operation)
            || policy.transaction_to.unwrap_or(policy.transaction_from) != event.global_commit
            || digest_bytes(policy.access.workspace_id.as_bytes()) != event.workspace_digest
            || policy.content_digest != reference.digest
            || reference.key
                != format!(
                    "{}{}/{:010}",
                    mutation_prefix(event.global_commit),
                    policy.record_digest,
                    policy.revision
                )
                .as_bytes()
        {
            return Err(integrity(
                "record control is not bound to this accepted mutation",
            ));
        }
        Ok(())
    }
}

impl NativeService {
    pub(super) fn retain_record_control<T: WriteTransaction>(
        &self,
        tx: &mut T,
        frame: &CommitFrame,
        record: &MemoryRecord,
        total_bytes: &mut usize,
    ) -> ServiceResult<String> {
        let control = RecordControl::from_record(record)?;
        let bytes = encode(&control)?;
        *total_bytes = total_bytes.saturating_add(bytes.len());
        if *total_bytes > MAX_BYTES {
            return Err(exhausted(
                "record controls exceed the bounded journal batch",
            ));
        }
        if tx
            .get(&self.keyspaces.continuous, ACTIVATED)
            .map_err(storage_error)?
            .is_none()
        {
            let mut manifest = self.raw_manifest(tx)?;
            manifest.features.insert(CONTROL_FEATURE.into());
            manifest.checksum = manifest_checksum(&manifest)?;
            tx.put(
                &self.keyspaces.meta,
                META_MANIFEST_KEY.to_vec(),
                encode(&manifest)?,
            )
            .map_err(storage_error)?;
            tx.put(
                &self.keyspaces.continuous,
                ACTIVATED.to_vec(),
                encode(&frame.global_commit)?,
            )
            .map_err(storage_error)?;
        }
        let digest = digest_bytes(&bytes);
        tx.put(
            &self.keyspaces.continuous,
            control_key(&mutation_key(frame.global_commit, record))?,
            bytes,
        )
        .map_err(storage_error)?;
        Ok(digest)
    }

    pub(super) fn record_control_activation<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<Option<u64>> {
        let activated: Option<u64> = self.raw_value(snapshot, ACTIVATED)?;
        let manifest = self.raw_manifest(snapshot)?;
        if activated.is_some() != manifest.features.contains(CONTROL_FEATURE)
            || activated == Some(0)
        {
            return Err(integrity("record control feature and activation disagree"));
        }
        Ok(activated)
    }

    pub(super) fn record_mutation_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
        reference: &RecordMutationRef,
        activated: Option<u64>,
    ) -> ServiceResult<Option<RecordControl>> {
        self.budgeted_record_mutation_control(snapshot, event, reference, activated, None)
    }

    fn budgeted_record_mutation_control<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        event: &StoredEvent,
        reference: &RecordMutationRef,
        activated: Option<u64>,
        budget: Option<&mut contextdb_recall::QueryBudget>,
    ) -> ServiceResult<Option<RecordControl>> {
        if activated.is_some_and(|first| first <= event.global_commit)
            != reference.control_digest.is_some()
        {
            return Err(integrity(
                "accepted record lost its required control commitment",
            ));
        }
        let Some(digest) = &reference.control_digest else {
            return Ok(None);
        };
        let bytes = snapshot
            .get(&self.keyspaces.continuous, &control_key(&reference.key)?)
            .map_err(storage_error)?
            .ok_or_else(|| integrity("accepted record control absent"))?;
        if let Some(budget) = budget {
            budget
                .charge(1, bytes.len() as u64)
                .map_err(raw_index::budget_error)?;
        }
        if bytes.len() > MAX_BYTES || digest_bytes(&bytes) != *digest {
            return Err(integrity(
                "record control differs from its accepted commitment",
            ));
        }
        let control: RecordControl = decode(&bytes, "record mutation control")?;
        control.validate_binding(event, reference)?;
        Ok(Some(control))
    }

    pub(super) fn verify_record_control_keys<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        expected: &BTreeSet<Vec<u8>>,
        activated: Option<u64>,
    ) -> ServiceResult<()> {
        let rows = snapshot
            .scan_prefix(&self.keyspaces.continuous, PREFIX)
            .map_err(storage_error)?;
        if rows.len() != expected.len() + usize::from(activated.is_some())
            || rows
                .iter()
                .any(|row| row.key != ACTIVATED && !expected.contains(&row.key))
        {
            return Err(integrity("orphaned or missing accepted record controls"));
        }
        Ok(())
    }
}

pub(super) fn control_key(mutation: &[u8]) -> ServiceResult<Vec<u8>> {
    let suffix = mutation
        .strip_prefix(b"semantic/record/")
        .ok_or_else(|| integrity("record control has an invalid mutation address"))?;
    Ok([PREFIX, suffix].concat())
}
