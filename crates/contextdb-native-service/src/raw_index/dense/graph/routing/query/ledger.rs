//! One operation allowance for routing identities, source spans and fresh work.
use super::*;
use contextdb_index::ANN_PARTITION_QUERY_MAX_READS_V2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Caps {
    pub(super) nodes: usize,
    pub(super) vectors: usize,
    pub(super) discovered: usize,
}
impl Caps {
    pub(super) fn fair_share(self, paths: usize) -> ServiceResult<Self> {
        if paths == 0 {
            return Err(crate::invalid("routed quota has no remaining path"));
        }
        Ok(Self {
            nodes: self.nodes.div_ceil(paths),
            vectors: self.vectors.div_ceil(paths),
            discovered: self.discovered.div_ceil(paths),
        })
    }
    pub(super) fn reserve(self, fine: bool, fresh: bool) -> Self {
        Self {
            nodes: self.nodes.saturating_sub(usize::from(fine)),
            vectors: self
                .vectors
                .saturating_sub(usize::from(fine) + usize::from(fresh)),
            discovered: self
                .discovered
                .saturating_sub(usize::from(fine) + usize::from(fresh)),
        }
    }
    pub(super) fn min(self, other: Self) -> Self {
        Self {
            nodes: self.nodes.min(other.nodes),
            vectors: self.vectors.min(other.vectors),
            discovered: self.discovered.min(other.discovered),
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Counts {
    pub(super) node_reads: u64,
    pub(super) vector_reads: u64,
    pub(super) discovered: u64,
}
#[derive(Clone, Copy)]
pub(super) enum Stage {
    Coarse,
    Fine,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Identity {
    Route(ContentDigest),
    Source(ContentDigest),
}
pub(super) struct QueryLedger {
    total: Caps,
    counts: Counts,
    coarse: Counts,
    fine: Counts,
    tail_vectors: u64,
    route_identities: usize,
    source_identities: usize,
    identities: BTreeMap<RepresentationId, Identity>,
    route_paths: BTreeMap<u64, DirectoryRouterFinePathV1>,
    spans: BTreeMap<(ObservationId, u64, u64), OriginalSourceSpan>,
    suppliers: BTreeMap<ObservationId, RawSource>,
}
pub(super) struct LedgerResult {
    pub(super) counts: Counts,
    pub(super) coarse: Counts,
    pub(super) tail_vector_reads: u64,
    pub(super) admitted_sources: BTreeMap<ObservationId, RawSource>,
}
fn map_fee(length: usize, pair_bytes: usize) -> (u64, u64) {
    let height = u64::from(usize::BITS - length.saturating_add(1).leading_zeros()) + 2;
    (
        height * 12,
        height * (12 * pair_bytes as u64 + 256).max(2048),
    )
}
fn compact(id: RepresentationId, digest: ContentDigest) -> ServiceResult<()> {
    let mut expected = [0; 16];
    expected.copy_from_slice(&digest.as_bytes()[..16]);
    expected[6] = (expected[6] & 15) | 128;
    expected[8] = (expected[8] & 63) | 128;
    if digest.as_bytes() == &[0; 32] || id.as_uuid().as_bytes() != &expected {
        return Err(integrity(
            "routed compact/full representation identity differs",
        ));
    }
    Ok(())
}
impl QueryLedger {
    pub(super) fn new(total: Caps, parent: &mut QueryBudget) -> ServiceResult<Self> {
        parent
            .charge(1, size_of::<Self>() as u64 + 256)
            .map_err(budget_error)?;
        if [total.nodes, total.vectors, total.discovered]
            .iter()
            .any(|n| *n > ANN_PARTITION_QUERY_MAX_READS_V2)
        {
            return Err(crate::invalid("routed global caps exceed ANN bound"));
        }
        Ok(Self {
            total,
            counts: Counts::default(),
            coarse: Counts::default(),
            fine: Counts::default(),
            tail_vectors: 0,
            route_identities: 0,
            source_identities: 0,
            identities: BTreeMap::new(),
            route_paths: BTreeMap::new(),
            spans: BTreeMap::new(),
            suppliers: BTreeMap::new(),
        })
    }
    pub(super) fn remaining(&self) -> Caps {
        Caps {
            nodes: self.total.nodes - self.counts.node_reads as usize,
            vectors: self.total.vectors - self.counts.vector_reads as usize,
            discovered: self.total.discovered - self.counts.discovered as usize,
        }
    }
    pub(super) fn counts(&self) -> Counts {
        self.counts
    }
    fn new_identity(
        &self,
        id: RepresentationId,
        identity: Identity,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent
            .charge(24 + self.identities.len().max(1).ilog2() as u64 * 4, 0)
            .map_err(budget_error)?;
        let digest = match identity {
            Identity::Route(d) | Identity::Source(d) => d,
        };
        compact(id, digest)?;
        if let Some(existing) = self.identities.get(&id) {
            // Cross-kind and cross-path reuse is never a new observation. The
            // reader suppresses legitimate repeats in its own local cache.
            return Err(integrity(if existing == &identity {
                "routed identity repeats across namespaces"
            } else {
                "routed compact identity collides across kinds or full digests"
            }));
        }
        if self.identities.len() >= self.total.discovered {
            return Err(exhausted(
                "routed global identity frontier exceeds discovery cap",
            ));
        }
        Ok(())
    }
    pub(super) fn admit_route(
        &mut self,
        id: RepresentationId,
        digest: ContentDigest,
        path: &DirectoryRouterFinePathV1,
        domain: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.new_identity(id, Identity::Route(digest), parent)?;
        path.validate()?;
        if !valid_hex(domain) {
            return Err(integrity("routed coarse policy domain differs"));
        }
        if self
            .route_paths
            .get(&path.ordinal())
            .is_some_and(|old| old != path)
        {
            return Err(integrity("routed coarse paths conflict at one ordinal"));
        }
        let path_bytes = crypto::metered_json_len(path, parent, ROW_BYTES)? as u64;
        let (w, b) = map_fee(
            self.identities.len(),
            size_of::<(RepresentationId, Identity)>(),
        );
        let new_path = !self.route_paths.contains_key(&path.ordinal());
        let (pw, pb) = if new_path {
            map_fee(
                self.route_paths.len(),
                size_of::<(u64, DirectoryRouterFinePathV1)>(),
            )
        } else {
            (0, 0)
        };
        parent
            .charge(
                w + pw,
                b + pb + path_bytes * 8 + size_of::<Identity>() as u64 + domain.len() as u64 + 256,
            )
            .map_err(budget_error)?;
        if new_path {
            self.route_paths.insert(path.ordinal(), path.clone());
        }
        self.identities.insert(id, Identity::Route(digest));
        self.route_identities += 1;
        Ok(())
    }
    fn supplier(&self, source: &RawSource, parent: &mut QueryBudget) -> ServiceResult<()> {
        let version = source.source_version.as_deref();
        parent
            .charge(version.map_or(0, |s| s.len() as u64 * 3) + 8, 0)
            .map_err(budget_error)?;
        if version.is_some_and(|s| s.len() > 2048 || s.trim().is_empty() || s.contains('\0')) {
            return Err(integrity("routed original version is invalid"));
        }
        if let Some(old) = self.suppliers.get(&source.event_id) {
            if old != source {
                return Err(integrity("routed paths disagree on full source version"));
            }
        } else if self.suppliers.len() == 256 {
            return Err(exhausted("routed source frontier exceeds 256"));
        }
        Ok(())
    }
    pub(super) fn admit_span(
        &mut self,
        id: RepresentationId,
        digest: ContentDigest,
        source: &RawSource,
        span: &OriginalSourceSpan,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.new_identity(id, Identity::Source(digest), parent)?;
        self.supplier(source, parent)?;
        if !source.independent_source
            || source.omission.is_some()
            || span.event_id != source.event_id
            || source.payload_digest != Some(span.payload_digest)
            || span.start >= span.end
            || span.span_digest.as_bytes() == &[0; 32]
            || source.byte_length.is_none_or(|end| span.end > end)
        {
            return Err(integrity("routed span differs from immutable original"));
        }
        let key = (source.event_id, span.start, span.end);
        if self.spans.contains_key(&key) {
            return Err(integrity(
                "routed source span repeats or conflicts across paths",
            ));
        }
        let (iw, ib) = map_fee(
            self.identities.len(),
            size_of::<(RepresentationId, Identity)>(),
        );
        let (sw, sb) = map_fee(
            self.spans.len(),
            size_of::<((ObservationId, u64, u64), OriginalSourceSpan)>(),
        );
        let new_source = !self.suppliers.contains_key(&source.event_id);
        let (pw, pb) = if new_source {
            map_fee(
                self.suppliers.len(),
                size_of::<(ObservationId, RawSource)>(),
            )
        } else {
            (0, 0)
        };
        parent
            .charge(
                iw + sw + pw,
                ib + sb
                    + pb
                    + size_of::<Identity>() as u64
                    + size_of::<OriginalSourceSpan>() as u64 * 2
                    + if new_source {
                        size_of::<RawSource>() as u64
                            + source
                                .source_version
                                .as_ref()
                                .map_or(0, |v| v.len() as u64 + 64)
                    } else {
                        0
                    },
            )
            .map_err(budget_error)?;
        if new_source {
            self.suppliers.insert(source.event_id, source.clone());
        }
        self.spans.insert(key, span.clone());
        self.identities.insert(id, Identity::Source(digest));
        self.source_identities += 1;
        Ok(())
    }
    pub(super) fn add_fresh_source(
        &mut self,
        source: &RawSource,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.supplier(source, parent)?;
        if self.suppliers.contains_key(&source.event_id) {
            return Ok(());
        }
        let (w, b) = map_fee(
            self.suppliers.len(),
            size_of::<(ObservationId, RawSource)>(),
        );
        parent
            .charge(
                w,
                b + size_of::<RawSource>() as u64
                    + source
                        .source_version
                        .as_ref()
                        .map_or(0, |v| v.len() as u64 + 64),
            )
            .map_err(budget_error)?;
        self.suppliers.insert(source.event_id, source.clone());
        Ok(())
    }
    pub(super) fn record_kernel(
        &mut self,
        stage: Stage,
        assigned: Caps,
        nodes: u64,
        vectors: u64,
        discovered: u64,
    ) -> ServiceResult<()> {
        let remaining = self.remaining();
        let n = usize::try_from(nodes).map_err(|_| integrity("routed node count overflow"))?;
        let v = usize::try_from(vectors).map_err(|_| integrity("routed vector count overflow"))?;
        let d = usize::try_from(discovered)
            .map_err(|_| integrity("routed discovery count overflow"))?;
        if assigned.nodes > remaining.nodes
            || assigned.vectors > remaining.vectors
            || assigned.discovered > remaining.discovered
            || n > assigned.nodes
            || v > assigned.vectors
            || d > assigned.discovered
        {
            return Err(integrity("routed kernel exceeds assigned/global caps"));
        }
        let add = |old: Counts| -> ServiceResult<Counts> {
            Ok(Counts {
                node_reads: old
                    .node_reads
                    .checked_add(nodes)
                    .ok_or_else(|| integrity("routed node counter overflow"))?,
                vector_reads: old
                    .vector_reads
                    .checked_add(vectors)
                    .ok_or_else(|| integrity("routed vector counter overflow"))?,
                discovered: old
                    .discovered
                    .checked_add(discovered)
                    .ok_or_else(|| integrity("routed discovery counter overflow"))?,
            })
        };
        let next = add(self.counts)?;
        let local = add(match stage {
            Stage::Coarse => self.coarse,
            Stage::Fine => self.fine,
        })?;
        let admitted = match stage {
            Stage::Coarse => self.route_identities,
            Stage::Fine => self.source_identities,
        };
        if local.discovered > admitted as u64 || next.discovered > self.identities.len() as u64 {
            return Err(integrity("routed observations lack admitted identities"));
        }
        self.counts = next;
        match stage {
            Stage::Coarse => self.coarse = local,
            Stage::Fine => self.fine = local,
        };
        Ok(())
    }
    pub(super) fn record_fresh_vector(&mut self) -> ServiceResult<()> {
        let r = self.remaining();
        if r.vectors == 0 || r.discovered == 0 {
            return Err(exhausted("routed fresh vector exceeds global cap"));
        }
        let tail = self
            .tail_vectors
            .checked_add(1)
            .ok_or_else(|| integrity("routed fresh counter overflow"))?;
        let source_observed = self
            .fine
            .discovered
            .checked_add(tail)
            .ok_or_else(|| integrity("routed source counter overflow"))?;
        if source_observed > self.source_identities as u64 {
            return Err(integrity(
                "routed fresh score lacks admitted source identity",
            ));
        }
        let vectors = self
            .counts
            .vector_reads
            .checked_add(1)
            .ok_or_else(|| integrity("routed vector counter overflow"))?;
        let discovered = self
            .counts
            .discovered
            .checked_add(1)
            .ok_or_else(|| integrity("routed discovery counter overflow"))?;
        self.counts.vector_reads = vectors;
        self.counts.discovered = discovered;
        self.tail_vectors = tail;
        Ok(())
    }
    pub(super) fn finish(self) -> ServiceResult<LedgerResult> {
        if self.coarse.discovered != self.route_identities as u64
            || self.fine.discovered + self.tail_vectors != self.source_identities as u64
            || self.counts.discovered != self.identities.len() as u64
            || self.counts.vector_reads != self.counts.discovered
        {
            return Err(integrity(
                "routed completed observations differ from admitted identity frontier",
            ));
        }
        Ok(LedgerResult {
            counts: self.counts,
            coarse: self.coarse,
            tail_vector_reads: self.tail_vectors,
            admitted_sources: self.suppliers,
        })
    }
}
