use contextdb_core::{MutationId, ObservationId};
use contextdb_storage::{Keyspace, Result as StorageResult};

pub(crate) const HEAD_KEY: &[u8] = b"head";
pub(crate) const EVENT_PREFIX: &[u8] = b"e";
pub(crate) const OUTBOX_PREFIX: &[u8] = b"o";
pub(crate) const IDEMPOTENCY_PREFIX: &[u8] = b"i";
pub(crate) const OBSERVATION_PREFIX: &[u8] = b"b";
pub(crate) const MUTATION_PREFIX: &[u8] = b"m";

pub(crate) struct Keyspaces {
    pub(crate) meta: Keyspace,
    pub(crate) events: Keyspace,
    pub(crate) outbox: Keyspace,
    pub(crate) idempotency: Keyspace,
    pub(crate) observations: Keyspace,
    pub(crate) mutations: Keyspace,
}

impl Keyspaces {
    pub(crate) fn new() -> StorageResult<Self> {
        Ok(Self {
            meta: Keyspace::new("journal_meta")?,
            events: Keyspace::new("semantic_journal")?,
            outbox: Keyspace::new("journal_outbox")?,
            idempotency: Keyspace::new("journal_idempotency")?,
            observations: Keyspace::new("journal_observation")?,
            mutations: Keyspace::new("journal_mutation")?,
        })
    }
}

pub(crate) fn event_key(sequence: u64) -> Vec<u8> {
    sequence_key(EVENT_PREFIX, sequence)
}

pub(crate) fn outbox_key(sequence: u64, index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(13);
    key.extend_from_slice(OUTBOX_PREFIX);
    key.extend_from_slice(&sequence.to_be_bytes());
    key.extend_from_slice(&index.to_be_bytes());
    key
}

pub(crate) fn outbox_sequence_prefix(sequence: u64) -> Vec<u8> {
    sequence_key(OUTBOX_PREFIX, sequence)
}

pub(crate) fn idempotency_key(digest: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(IDEMPOTENCY_PREFIX);
    key.extend_from_slice(digest);
    key
}

pub(crate) fn observation_key(id: ObservationId) -> Vec<u8> {
    uuid_key(OBSERVATION_PREFIX, id.as_uuid().as_bytes())
}

pub(crate) fn mutation_key(id: MutationId) -> Vec<u8> {
    uuid_key(MUTATION_PREFIX, id.as_uuid().as_bytes())
}

pub(crate) fn sequence_from_key(key: &[u8], prefix: &[u8], suffix_len: usize) -> Option<u64> {
    if key.len() != prefix.len().checked_add(8)?.checked_add(suffix_len)?
        || !key.starts_with(prefix)
    {
        return None;
    }
    let bytes: [u8; 8] = key.get(prefix.len()..prefix.len() + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn sequence_key(prefix: &[u8], sequence: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 8);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

fn uuid_key(prefix: &[u8], uuid: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + uuid.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(uuid);
    key
}
