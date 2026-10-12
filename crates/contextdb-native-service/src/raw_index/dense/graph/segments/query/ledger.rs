//! One finite operation ledger shared by every immutable path and fresh tail.
//! Membership and current access are established by the owner point reader.

use crate::{exhausted, integrity, invalid, raw_index::budget_error};
use contextdb_core::{
    ContentDigest, ObservationId, OriginalSourceSpan, RawSource, RepresentationId,
};
use contextdb_index::ANN_PARTITION_QUERY_MAX_READS_V2;
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use std::{collections::BTreeMap, mem::size_of};

const MAX_SOURCES: usize = 256;
const MAX_SOURCE_VERSION_BYTES: usize = 2048;
const MAP_NODE_BYTES: u64 = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Caps {
    pub(super) nodes: usize,
    pub(super) vectors: usize,
    pub(super) discovered: usize,
}

impl Caps {
    /// Forward redistribution uses the actual remaining ledger on each call.
    /// Zero remaining capacity stays zero; later paths must report skipped work.
    pub(super) fn fair_share(self, remaining_paths: usize) -> ServiceResult<Self> {
        if remaining_paths == 0 {
            return Err(invalid("segment quota requires a remaining path"));
        }
        let share = |value: usize| value.div_ceil(remaining_paths);
        Ok(Self {
            nodes: share(self.nodes),
            vectors: share(self.vectors),
            discovered: share(self.discovered),
        })
    }

    fn valid(self) -> bool {
        [self.nodes, self.vectors, self.discovered]
            .into_iter()
            .all(|value| value <= ANN_PARTITION_QUERY_MAX_READS_V2)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Counts {
    pub(super) node_reads: u64,
    pub(super) vector_reads: u64,
    pub(super) discovered: u64,
    pub(super) tail_vector_reads: u64,
}

struct Identity {
    digest: ContentDigest,
    source: ObservationId,
    span: OriginalSourceSpan,
}

pub(super) struct QueryLedger {
    total: Caps,
    counts: Counts,
    identities: BTreeMap<RepresentationId, Identity>,
    spans: BTreeMap<(ObservationId, u64, u64), OriginalSourceSpan>,
    suppliers: BTreeMap<ObservationId, RawSource>,
}

pub(super) struct LedgerResult {
    pub(super) counts: Counts,
    pub(super) admitted_sources: BTreeMap<ObservationId, RawSource>,
}

fn map_allowance(length: usize) -> (u64, u64) {
    // A split may cascade through every ancestor. This binary height bound
    // exceeds BTreeMap's balanced height, including a replacement root.
    let levels = u64::from(usize::BITS - length.saturating_add(1).leading_zeros()) + 2;
    (levels * 12, levels * MAP_NODE_BYTES)
}

fn source_work(source: &RawSource, parent: &mut QueryBudget) -> ServiceResult<()> {
    let version = source.source_version.as_deref();
    if version.is_some_and(|value| value.len() > MAX_SOURCE_VERSION_BYTES) {
        return Err(integrity(
            "segment supplier version exceeds the original metadata bound",
        ));
    }
    parent
        .charge(version.map_or(0, |value| value.len() as u64 * 3) + 8, 0)
        .map_err(budget_error)?;
    if version.is_some_and(|value| value.trim().is_empty() || value.contains('\0')) {
        return Err(integrity("segment supplier original version is invalid"));
    }
    Ok(())
}

fn check_span(source: &RawSource, span: &OriginalSourceSpan) -> ServiceResult<()> {
    if !source.independent_source
        || source.omission.is_some()
        || span.event_id != source.event_id
        || source.payload_digest != Some(span.payload_digest)
        || span.payload_digest.as_bytes() == &[0; 32]
        || span.span_digest.as_bytes() == &[0; 32]
        || span.start >= span.end
        || source.byte_length.is_none_or(|end| span.end > end)
    {
        return Err(integrity(
            "segment supplier span differs from its immutable original",
        ));
    }
    Ok(())
}

impl QueryLedger {
    pub(super) fn new(total: Caps, parent: &mut QueryBudget) -> ServiceResult<Self> {
        parent
            .charge(1, size_of::<Self>() as u64 + 256)
            .map_err(budget_error)?;
        if !total.valid() {
            return Err(invalid(
                "segment operation caps exceed the existing ANN bound",
            ));
        }
        Ok(Self {
            total,
            counts: Counts::default(),
            identities: BTreeMap::new(),
            spans: BTreeMap::new(),
            suppliers: BTreeMap::new(),
        })
    }

    pub(super) fn remaining(&self) -> Caps {
        // Every recorded counter was checked against this usize total first.
        Caps {
            nodes: self.total.nodes - self.counts.node_reads as usize,
            vectors: self.total.vectors - self.counts.vector_reads as usize,
            discovered: self.total.discovered - self.counts.discovered as usize,
        }
    }

    /// The reader checks its own local cache first. A repeated representation
    /// reaching this global seam from another namespace is always a refusal.
    pub(super) fn admit(
        &mut self,
        id: RepresentationId,
        identity_digest: ContentDigest,
        source: &RawSource,
        span: &OriginalSourceSpan,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.check().map_err(budget_error)?;
        source_work(source, parent)?;
        check_span(source, span)?;
        parent
            .charge(24 + self.identities.len().max(1).ilog2() as u64 * 4, 0)
            .map_err(budget_error)?;
        let mut expected = [0; 16];
        expected.copy_from_slice(&identity_digest.as_bytes()[..16]);
        expected[6] = (expected[6] & 15) | 128;
        expected[8] = (expected[8] & 63) | 128;
        if identity_digest.as_bytes() == &[0; 32] || id.as_uuid().as_bytes() != &expected {
            return Err(integrity(
                "segment compact identity differs from its full identity",
            ));
        }
        if let Some(existing) = self.identities.get(&id) {
            if existing.digest != identity_digest
                || existing.source != source.event_id
                || existing.span != *span
            {
                return Err(integrity(
                    "segment representation collides across immutable paths",
                ));
            }
            return Err(integrity(
                "segment representation repeats across immutable paths",
            ));
        }
        if self.identities.len() >= self.total.discovered {
            return Err(exhausted(
                "segment operation identity frontier exceeds its discovery cap",
            ));
        }
        self.check_supplier(source)?;
        let key = (source.event_id, span.start, span.end);
        if let Some(existing) = self.spans.get(&key) {
            if existing != span {
                return Err(integrity(
                    "segment exact source range has conflicting digests",
                ));
            }
            return Err(integrity(
                "segment exact source span repeats under another representation",
            ));
        }
        let (id_work, id_bytes) = map_allowance(self.identities.len());
        let (span_work, span_bytes) = map_allowance(self.spans.len());
        let supplier_new = !self.suppliers.contains_key(&source.event_id);
        let (source_work, source_bytes) = if supplier_new {
            map_allowance(self.suppliers.len())
        } else {
            (0, 0)
        };
        parent
            .charge(
                id_work + span_work + source_work,
                id_bytes
                    + span_bytes
                    + source_bytes
                    + size_of::<Identity>() as u64
                    + size_of::<OriginalSourceSpan>() as u64
                    + if supplier_new {
                        size_of::<RawSource>() as u64
                            + source
                                .source_version
                                .as_ref()
                                .map_or(0, |value| value.len() as u64 + 64)
                    } else {
                        0
                    },
            )
            .map_err(budget_error)?;
        // All mutation follows the single allocation admission, so a refusal
        // cannot leave a partially inserted identity or supplier.
        if supplier_new {
            self.suppliers.insert(source.event_id, source.clone());
        }
        self.spans.insert(key, span.clone());
        self.identities.insert(
            id,
            Identity {
                digest: identity_digest,
                source: source.event_id,
                span: span.clone(),
            },
        );
        Ok(())
    }

    pub(super) fn admit_tail(
        &mut self,
        id: RepresentationId,
        identity_digest: ContentDigest,
        source: &RawSource,
        span: &OriginalSourceSpan,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.admit(id, identity_digest, source, span, parent)
    }

    fn check_supplier(&self, source: &RawSource) -> ServiceResult<()> {
        if let Some(existing) = self.suppliers.get(&source.event_id) {
            if existing != source {
                return Err(integrity(
                    "segment paths disagree on the full original source version",
                ));
            }
        } else if self.suppliers.len() == MAX_SOURCES {
            return Err(exhausted(
                "segment full supplier frontier exceeds 256 sources",
            ));
        }
        Ok(())
    }

    /// Complete permitted tail documents remain suppliers even when scoring
    /// stops. Omissions/echoes have no invented representation or vector.
    pub(super) fn add_tail_source(
        &mut self,
        source: &RawSource,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent.check().map_err(budget_error)?;
        source_work(source, parent)?;
        parent
            .charge(8 + self.suppliers.len().max(1).ilog2() as u64 * 2, 0)
            .map_err(budget_error)?;
        self.check_supplier(source)?;
        if self.suppliers.contains_key(&source.event_id) {
            return Ok(());
        }
        let (work, bytes) = map_allowance(self.suppliers.len());
        parent
            .charge(
                work,
                bytes
                    + size_of::<RawSource>() as u64
                    + source
                        .source_version
                        .as_ref()
                        .map_or(0, |value| value.len() as u64 + 64),
            )
            .map_err(budget_error)?;
        self.suppliers.insert(source.event_id, source.clone());
        Ok(())
    }

    pub(super) fn record_kernel(
        &mut self,
        assigned: Caps,
        actual_nodes: u64,
        actual_vectors: u64,
        actual_discovered: u64,
    ) -> ServiceResult<()> {
        let remaining = self.remaining();
        let nodes = usize::try_from(actual_nodes)
            .map_err(|_| integrity("segment node count overflows usize"))?;
        let vectors = usize::try_from(actual_vectors)
            .map_err(|_| integrity("segment vector count overflows usize"))?;
        let discovered = usize::try_from(actual_discovered)
            .map_err(|_| integrity("segment discovery count overflows usize"))?;
        if assigned.nodes > remaining.nodes
            || assigned.vectors > remaining.vectors
            || assigned.discovered > remaining.discovered
            || nodes > assigned.nodes
            || vectors > assigned.vectors
            || discovered > assigned.discovered
        {
            return Err(integrity(
                "segment kernel exceeded its assigned or global caps",
            ));
        }
        let next_nodes = self
            .counts
            .node_reads
            .checked_add(actual_nodes)
            .ok_or_else(|| integrity("segment node counter overflow"))?;
        let next_vectors = self
            .counts
            .vector_reads
            .checked_add(actual_vectors)
            .ok_or_else(|| integrity("segment vector counter overflow"))?;
        let next_discovered = self
            .counts
            .discovered
            .checked_add(actual_discovered)
            .ok_or_else(|| integrity("segment discovery counter overflow"))?;
        if next_discovered > self.identities.len() as u64 {
            return Err(integrity(
                "segment kernel discovery has no admitted identity",
            ));
        }
        self.counts.node_reads = next_nodes;
        self.counts.vector_reads = next_vectors;
        self.counts.discovered = next_discovered;
        Ok(())
    }

    /// Called only after actual tail vector read, validation and finite score.
    pub(super) fn record_tail_vector(&mut self) -> ServiceResult<()> {
        let remaining = self.remaining();
        if remaining.vectors == 0 || remaining.discovered == 0 {
            return Err(exhausted("segment tail exceeds the shared operation caps"));
        }
        let next_vectors = self
            .counts
            .vector_reads
            .checked_add(1)
            .ok_or_else(|| integrity("segment vector counter overflow"))?;
        let next_discovered = self
            .counts
            .discovered
            .checked_add(1)
            .ok_or_else(|| integrity("segment discovery counter overflow"))?;
        let next_tail = self
            .counts
            .tail_vector_reads
            .checked_add(1)
            .ok_or_else(|| integrity("segment tail counter overflow"))?;
        if next_discovered > self.identities.len() as u64 {
            return Err(integrity(
                "segment tail vector has no admitted full identity",
            ));
        }
        self.counts.vector_reads = next_vectors;
        self.counts.discovered = next_discovered;
        self.counts.tail_vector_reads = next_tail;
        Ok(())
    }

    pub(super) fn counts(&self) -> Counts {
        self.counts
    }

    #[cfg(test)]
    pub(super) fn admitted_sources(&self) -> &BTreeMap<ObservationId, RawSource> {
        &self.suppliers
    }

    pub(super) fn finish(self) -> LedgerResult {
        LedgerResult {
            counts: self.counts,
            admitted_sources: self.suppliers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contextdb_recall::QueryCancellation;
    use contextdb_service::ErrorCode;
    use std::time::Duration;

    fn budget() -> QueryBudget {
        QueryBudget::new(
            10_000_000,
            128 * 1024 * 1024,
            Duration::from_secs(60),
            Default::default(),
        )
    }
    fn identity(number: u64) -> (RepresentationId, ContentDigest) {
        let mut full = [1; 32];
        full[..8].copy_from_slice(&number.to_be_bytes());
        let mut compact = [0; 16];
        compact.copy_from_slice(&full[..16]);
        compact[6] = (compact[6] & 15) | 128;
        compact[8] = (compact[8] & 63) | 128;
        (
            RepresentationId::from_uuid(uuid::Uuid::from_bytes(compact)).expect("nonzero identity"),
            ContentDigest::from_bytes(full),
        )
    }
    fn source(sequence: u64) -> RawSource {
        RawSource::from(
            &crate::capture::tests::request(sequence, "actual independent source bytes").event,
        )
    }
    fn span(source: &RawSource, start: u64) -> OriginalSourceSpan {
        let bytes = b"actual independent source bytes";
        OriginalSourceSpan {
            event_id: source.event_id,
            payload_digest: source.payload_digest.expect("actual original"),
            start,
            end: start + 2,
            span_digest: ContentDigest::from_bytes(
                *blake3::hash(&bytes[start as usize..start as usize + 2]).as_bytes(),
            ),
        }
    }

    #[test]
    fn fair_caps_use_actual_remaining_and_zero_is_never_invented() {
        let remaining = Caps {
            nodes: 7,
            vectors: 2,
            discovered: 0,
        };
        assert_eq!(
            remaining.fair_share(3).expect("first share"),
            Caps {
                nodes: 3,
                vectors: 1,
                discovered: 0
            }
        );
        assert_eq!(
            Caps {
                nodes: 0,
                vectors: 0,
                discovered: 0
            }
            .fair_share(100)
            .expect("empty share"),
            Caps {
                nodes: 0,
                vectors: 0,
                discovered: 0
            }
        );
        assert!(remaining.fair_share(0).is_err());
        let mut ledger = QueryLedger::new(
            Caps {
                nodes: 7,
                vectors: 2,
                discovered: 2,
            },
            &mut budget(),
        )
        .expect("ledger");
        let s = source(1);
        let (id, full) = identity(1);
        ledger
            .admit(id, full, &s, &span(&s, 0), &mut budget())
            .expect("first source");
        ledger
            .record_kernel(ledger.remaining().fair_share(3).expect("assigned"), 1, 1, 1)
            .expect("actual kernel");
        assert_eq!(
            ledger
                .remaining()
                .fair_share(2)
                .expect("unused quota redistributed"),
            Caps {
                nodes: 3,
                vectors: 1,
                discovered: 1
            }
        );
    }

    #[test]
    fn kernels_and_tail_share_checked_totals_and_failed_record_is_atomic() {
        let mut ledger = QueryLedger::new(
            Caps {
                nodes: 5,
                vectors: 3,
                discovered: 3,
            },
            &mut budget(),
        )
        .expect("ledger");
        let s = source(1);
        for number in 1..=2 {
            let (id, full) = identity(number);
            ledger
                .admit(id, full, &s, &span(&s, (number - 1) * 2), &mut budget())
                .expect("kernel metadata");
        }
        ledger
            .record_kernel(
                Caps {
                    nodes: 3,
                    vectors: 2,
                    discovered: 2,
                },
                2,
                2,
                2,
            )
            .expect("actual kernel totals");
        let before = ledger.counts();
        assert!(
            ledger
                .record_kernel(
                    Caps {
                        nodes: 4,
                        vectors: 1,
                        discovered: 1
                    },
                    0,
                    0,
                    0
                )
                .is_err()
        );
        assert!(
            ledger
                .record_kernel(ledger.remaining(), u64::MAX, 0, 0)
                .is_err()
        );
        assert_eq!(ledger.counts(), before);
        let (id, full) = identity(3);
        ledger
            .admit_tail(id, full, &s, &span(&s, 4), &mut budget())
            .expect("tail metadata before read");
        ledger
            .record_tail_vector()
            .expect("one actual scored tail vector");
        assert_eq!(
            ledger.counts(),
            Counts {
                node_reads: 2,
                vector_reads: 3,
                discovered: 3,
                tail_vector_reads: 1
            }
        );
        assert!(ledger.record_tail_vector().is_err());
        assert_eq!(
            ledger.remaining(),
            Caps {
                nodes: 3,
                vectors: 0,
                discovered: 0
            }
        );
    }

    #[test]
    fn cross_path_ids_full_versions_and_equal_ranges_cannot_alias() {
        let mut ledger = QueryLedger::new(
            Caps {
                nodes: 10,
                vectors: 10,
                discovered: 10,
            },
            &mut budget(),
        )
        .expect("ledger");
        let s = source(1);
        let (id, full) = identity(1);
        let original = span(&s, 0);
        ledger
            .admit(id, full, &s, &original, &mut budget())
            .expect("first path");
        assert_eq!(
            ledger
                .admit_tail(id, full, &s, &original, &mut budget())
                .expect_err("cross-path repeat")
                .code,
            ErrorCode::IntegrityFailure
        );
        let mut colliding_full = *full.as_bytes();
        colliding_full[31] = 9;
        assert!(
            ledger
                .admit(
                    id,
                    ContentDigest::from_bytes(colliding_full),
                    &s,
                    &original,
                    &mut budget()
                )
                .is_err(),
            "matching compact ID cannot conceal a different full identity"
        );
        let (other_id, other_full) = identity(2);
        let mut different_version = s.clone();
        different_version.source_version = Some("different actual version".into());
        assert!(
            ledger
                .admit(
                    other_id,
                    other_full,
                    &different_version,
                    &span(&s, 2),
                    &mut budget()
                )
                .is_err()
        );
        let mut conflict = original.clone();
        conflict.span_digest = ContentDigest::from_bytes([3; 32]);
        assert!(
            ledger
                .admit(other_id, other_full, &s, &conflict, &mut budget())
                .is_err()
        );
        assert!(
            ledger
                .admit(other_id, full, &s, &span(&s, 2), &mut budget())
                .is_err(),
            "compact/full mismatch"
        );
        assert_eq!(ledger.admitted_sources().len(), 1);
        assert_eq!(ledger.identities.len(), 1);
    }

    #[test]
    fn supplier_cap_retains_omissions_without_inventing_vectors() {
        let mut ledger = QueryLedger::new(
            Caps {
                nodes: 300,
                vectors: 300,
                discovered: 300,
            },
            &mut budget(),
        )
        .expect("ledger");
        for sequence in 1..=MAX_SOURCES as u64 {
            let mut supplier = source(sequence);
            if sequence == 1 {
                supplier.payload_digest = None;
                supplier.byte_length = None;
                supplier.omission = Some(contextdb_core::PayloadOmission::NotExposedByUpstream);
                supplier.coverage = contextdb_core::EventCoverage::PartialObservation;
            }
            ledger
                .add_tail_source(&supplier, &mut budget())
                .expect("whole supplier or explicit omission");
        }
        assert!(
            ledger
                .add_tail_source(&source(MAX_SOURCES as u64 + 1), &mut budget())
                .is_err()
        );
        assert_eq!(ledger.admitted_sources().len(), MAX_SOURCES);
        assert_eq!(ledger.counts(), Counts::default());
        assert!(
            ledger.record_tail_vector().is_err(),
            "supplier metadata cannot invent a read"
        );
        let result = ledger.finish();
        assert_eq!(result.counts, Counts::default());
        assert_eq!(result.admitted_sources.len(), MAX_SOURCES);
    }

    #[test]
    fn parent_byte_refusal_and_cancellation_leave_no_partial_admission() {
        let cancellation = QueryCancellation::default();
        let mut parent =
            QueryBudget::new(100_000, 4096, Duration::from_secs(10), cancellation.clone());
        let mut ledger = QueryLedger::new(
            Caps {
                nodes: 10,
                vectors: 10,
                discovered: 10,
            },
            &mut parent,
        )
        .expect("empty ledger");
        let s = source(1);
        let (id, full) = identity(1);
        assert_eq!(
            ledger
                .admit(id, full, &s, &span(&s, 0), &mut parent)
                .expect_err("allocation precharge")
                .code,
            ErrorCode::BudgetExhausted
        );
        assert!(
            ledger.identities.is_empty() && ledger.spans.is_empty() && ledger.suppliers.is_empty()
        );
        cancellation.cancel();
        assert_eq!(
            ledger
                .add_tail_source(&s, &mut parent)
                .expect_err("same parent cancellation")
                .code,
            ErrorCode::BudgetExhausted
        );
        assert!(ledger.suppliers.is_empty());
        assert!(
            QueryLedger::new(
                Caps {
                    nodes: 1,
                    vectors: 1,
                    discovered: 1
                },
                &mut parent
            )
            .is_err()
        );
    }
}
