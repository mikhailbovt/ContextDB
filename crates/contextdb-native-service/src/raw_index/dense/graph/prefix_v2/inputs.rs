//! Complete owner-accepted prefix input, without changing the real raw census.

use super::types::{
    INTERVAL_DOMAIN, KEY_BYTES, MAX_COHORTS, MAX_NODES, MAX_WORK, PrefixIntervalV2,
    PrefixRawBindingV2, ROW_BYTES,
};
use super::verification::VerifiedDensePrefixTarget;
use crate::raw_index::dense::graph::publication::GraphInput;
use crate::raw_index::dense::graph::segments::crypto::metered_json_len;
use crate::raw_index::dense::{
    DenseDocument, DenseManifest, DenseVector, document_key, vector_key,
};
use crate::raw_index::{Generation, IndexedOriginal, budget_error, doc_key, stale_index};
use crate::{NativeService, decode, digest_bytes, integrity, storage_error};
use contextdb_core::{ContentDigest, ObservationId};
use contextdb_recall::{QueryBudget, QueryLimit};
use contextdb_service::{AccessPolicy, AuthenticatedRequestContext, CaptureReceipt, ServiceResult};
use contextdb_storage::{ReadSnapshot, SnapshotSelector, StorageEngine};
use serde::Serialize;
use std::{
    io::{self, Write},
    mem::size_of,
};

#[cfg(test)]
#[path = "input_tests.rs"]
pub(in crate::raw_index::dense::graph) mod tests;

const RAW_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

pub(super) struct PrefixBuildInput {
    pub(super) documents: Vec<DenseDocument>,
    pub(super) inputs: Vec<GraphInput>,
    pub(super) interval: PrefixIntervalV2,
}

#[derive(Serialize)]
struct IntervalHeader<'a> {
    database_id: &'a str,
    workspace_digest: &'a str,
    raw: &'a PrefixRawBindingV2,
    target: &'a super::super::segments::types::AcceptedPublicationRef,
    before: &'a DenseManifest,
    after: &'a DenseManifest,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum IntervalOutcome<'a> {
    Document { document: &'a DenseDocument },
    PreparedRemoval { removal_through: Option<u64> },
}

#[derive(Serialize)]
struct IntervalRow<'a> {
    work: &'a crate::capture::CaptureWork,
    capture: &'a CaptureReceipt,
    recovery: &'a Option<crate::capture::CaptureRecovery>,
    outcome: IntervalOutcome<'a>,
}

struct IntervalHash {
    hasher: blake3::Hasher,
    work_items: u32,
}

/// Encoding goes directly into a hash. A sticky parent limit is recovered as
/// its typed native error; no encoded control buffer or fresh allowance exists.
struct BudgetHashWriter<'a> {
    hasher: &'a mut blake3::Hasher,
    parent: &'a mut QueryBudget,
    limit: Option<QueryLimit>,
}
impl Write for BudgetHashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.limit.is_some() {
            return Err(io::Error::other("prefix-v2 parent allowance ended"));
        }
        let length = bytes.len() as u64;
        if let Err(limit) = self
            .parent
            .charge(length.saturating_add(1), length.saturating_mul(2))
        {
            self.limit = Some(limit);
            return Err(io::Error::other("prefix-v2 parent allowance ended"));
        }
        self.hasher.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.limit.is_some() {
            return Err(io::Error::other("prefix-v2 parent allowance ended"));
        }
        if let Err(limit) = self.parent.check() {
            self.limit = Some(limit);
            return Err(io::Error::other("prefix-v2 parent allowance ended"));
        }
        Ok(())
    }
}

impl IntervalHash {
    fn new(header: IntervalHeader<'_>, parent: &mut QueryBudget) -> ServiceResult<Self> {
        parent
            .charge(1, size_of::<Self>() as u64 + 256)
            .map_err(budget_error)?;
        let mut value = Self {
            hasher: blake3::Hasher::new(),
            work_items: 0,
        };
        let mut writer = BudgetHashWriter {
            hasher: &mut value.hasher,
            parent,
            limit: None,
        };
        let result = writer.write_all(INTERVAL_DOMAIN);
        if let Some(limit) = writer.limit {
            return Err(budget_error(limit));
        }
        result.map_err(|_| integrity("prefix-v2 interval domain encoding failed"))?;
        value.part(&header, parent)?;
        Ok(value)
    }

    fn part<T: Serialize>(&mut self, part: &T, parent: &mut QueryBudget) -> ServiceResult<()> {
        let mut writer = BudgetHashWriter {
            hasher: &mut self.hasher,
            parent,
            limit: None,
        };
        let result = serde_json::to_writer(&mut writer, part);
        if let Some(limit) = writer.limit {
            return Err(budget_error(limit));
        }
        result.map_err(|_| integrity("prefix-v2 interval canonical encoding failed"))?;
        // A literal NUL cannot occur in JSON, so ordered parts are unambiguous.
        let result = writer.write_all(&[0]);
        if let Some(limit) = writer.limit {
            return Err(budget_error(limit));
        }
        result.map_err(|_| integrity("prefix-v2 interval separator encoding failed"))
    }

    fn row(&mut self, row: IntervalRow<'_>, parent: &mut QueryBudget) -> ServiceResult<()> {
        let count = self
            .work_items
            .checked_add(1)
            .filter(|n| *n <= MAX_WORK)
            .ok_or_else(|| crate::exhausted("prefix-v2 accepted work exceeds 128"))?;
        self.part(&row, parent)?;
        self.work_items = count;
        Ok(())
    }

    fn finish(self, parent: &mut QueryBudget) -> ServiceResult<PrefixIntervalV2> {
        parent.charge(1, 256).map_err(budget_error)?;
        Ok(PrefixIntervalV2 {
            work_items: self.work_items,
            digest: ContentDigest::from_bytes(*self.hasher.finalize().as_bytes()),
        })
    }
}

struct CohortInput {
    domain: String,
    policies: Vec<AccessPolicy>,
}

impl NativeService {
    #[allow(
        clippy::too_many_arguments,
        reason = "actual raw census, opaque target and shared parent remain explicit"
    )]
    pub(super) fn prefix_build_input<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        workspace: &str,
        actual_generation: &Generation,
        target: &VerifiedDensePrefixTarget,
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixBuildInput> {
        parent.check().map_err(budget_error)?;
        let target_manifest = target.manifest();
        let receipt = target.receipt();
        if target_manifest.spans == 0 {
            return Err(crate::invalid(
                "prefix-v2 requires a nonempty accepted source-span plan",
            ));
        }
        if target_manifest.spans > MAX_NODES || target_manifest.sources > u64::from(MAX_WORK) {
            return Err(crate::exhausted(
                "prefix-v2 complete input exceeds its span or accepted-work bound",
            ));
        }
        if target.work().len() > MAX_WORK as usize {
            return Err(crate::exhausted(
                "prefix-v2 authoritative accepted work exceeds 128",
            ));
        }
        if target.work().is_empty() || target_manifest.sources > target.work().len() as u64 {
            return Err(integrity(
                "prefix-v2 accepted target has no complete source-work prefix",
            ));
        }
        parent.charge(1, 2048).map_err(budget_error)?;
        let profile_bytes = metered_json_len(&target_manifest.profile, parent, ROW_BYTES)?;
        parent
            .charge(profile_bytes as u64 + 1, profile_bytes as u64 * 8 + 8192)
            .map_err(budget_error)?;
        if receipt.generation != actual_generation.number
            || receipt.authorization_epoch != actual_generation.authorization_epoch
            || digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || receipt.raw_through != actual_generation.through
            || receipt.raw_sources != actual_generation.projected_sources
            || target_manifest.through > receipt.raw_through
            || target_manifest.sources > receipt.raw_sources
            || receipt.profile != target_manifest.profile
            || receipt.profile_digest != target_manifest.profile_digest
            || receipt.through != target_manifest.through
            || receipt.sources != target_manifest.sources
            || receipt.embedded_sources != target_manifest.embedded_sources
            || receipt.spans != target_manifest.spans
            || receipt.omitted_sources != target_manifest.omitted_sources
            || receipt.commitment != target_manifest.commitment
            || context.is_some_and(|c| digest_bytes(c.request.workspace_id.as_bytes()) != workspace)
        {
            return Err(integrity(
                "prefix-v2 target escapes the actual raw admission",
            ));
        }
        let raw = PrefixRawBindingV2::from_generation(actual_generation, parent)?;
        target_manifest.validate(actual_generation.through)?;
        let mut reconstructed = DenseManifest::empty(&target_manifest.profile)?;
        let mut tracking = IntervalHash::new(
            IntervalHeader {
                database_id: &self.database_id,
                workspace_digest: workspace,
                raw: &raw,
                target: target.reference(),
                before: &reconstructed,
                after: target_manifest,
            },
            parent,
        )?;

        // Every collection has its complete bounded capacity admitted before
        // allocation. Individual vectors/policies retain their separate IO fees.
        parent
            .charge(
                1,
                u64::from(MAX_WORK) * size_of::<DenseDocument>() as u64 * 2
                    + target_manifest.spans * size_of::<GraphInput>() as u64 * 2
                    + MAX_COHORTS as u64 * size_of::<CohortInput>() as u64 * 2
                    + 4096,
            )
            .map_err(budget_error)?;
        let mut documents = Vec::with_capacity(MAX_WORK as usize);
        let mut inputs = Vec::with_capacity(target_manifest.spans as usize);
        let mut cohorts: Vec<CohortInput> = Vec::with_capacity(MAX_COHORTS);
        let mut last = 0;
        for expected in target.work() {
            if expected.workspace_commit <= last
                || expected.workspace_commit > target_manifest.through
            {
                return Err(integrity(
                    "prefix-v2 authoritative accepted-work order or cutoff differs",
                ));
            }
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let work: crate::capture::CaptureWork = self
                .graph_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &crate::capture::work_key(workspace, expected.workspace_commit),
                    parent,
                )?
                .ok_or_else(|| {
                    integrity("prefix-v2 authoritative accepted outbox work is absent")
                })?;
            if &work != expected {
                return Err(integrity(
                    "prefix-v2 outbox differs from authoritative native accepted work",
                ));
            }
            last = work.workspace_commit;
            let (capture, recovery) =
                self.capture_recovery_metadata(snapshot, work.event_id, parent)?;
            if recovery.is_none()
                || work.recovery_digest.is_none()
                || self.capture_work_for_receipt_with_budget(snapshot, &capture, parent)? != work
            {
                return Err(integrity("prefix-v2 accepted capture control differs"));
            }
            self.verify_causal_capture_work(snapshot, workspace, &work, parent)?;
            if self.source_prepared_at(
                snapshot,
                workspace,
                work.event_id,
                actual_generation.removal_through,
                parent,
            )? {
                tracking.row(
                    IntervalRow {
                        work: &work,
                        capture: &capture,
                        recovery: &recovery,
                        outcome: IntervalOutcome::PreparedRemoval {
                            removal_through: actual_generation.removal_through,
                        },
                    },
                    parent,
                )?;
                continue;
            }
            self.admit_prefix_source(context, workspace, actual_generation, work.event_id, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let doc: DenseDocument = self
                .graph_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &document_key(workspace, actual_generation.number, work.event_id),
                    parent,
                )?
                .ok_or_else(|| integrity("prefix-v2 tagged source document is absent"))?;
            let doc_bytes = metered_json_len(&doc, parent, ROW_BYTES)?;
            parent
                .charge(doc_bytes as u64 + 1, doc_bytes as u64 * 8 + 8192)
                .map_err(budget_error)?;
            self.check_dense_document_token(&doc)?;
            if doc.source.event_id != work.event_id
                || doc.event_digest != work.event_digest
                || doc.commit != work.workspace_commit
                || doc.profile_digest != target_manifest.profile_digest
                || doc.source.payload_digest != capture.payload_digest
                || doc.spans.len() > crate::raw_index::dense::MAX_SOURCE_SPANS
                || (doc.omission.is_some() && !doc.spans.is_empty())
                || (doc.omission.is_none() && doc.spans.is_empty())
                || doc.spans.iter().any(|span| {
                    span.span.event_id != doc.source.event_id
                        || Some(span.span.payload_digest) != doc.source.payload_digest
                        || span.span.start >= span.span.end
                        || doc.source.byte_length.is_none_or(|n| span.span.end > n)
                })
            {
                return Err(integrity(
                    "prefix-v2 document differs from its complete accepted source plan",
                ));
            }
            let total = inputs
                .len()
                .checked_add(doc.spans.len())
                .filter(|n| *n <= MAX_NODES as usize && *n as u64 <= target_manifest.spans)
                .ok_or_else(|| {
                    crate::exhausted("prefix-v2 entire source plan exceeds its node bound")
                })?;
            self.admit_prefix_source(context, workspace, actual_generation, work.event_id, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let raw_key = doc_key(workspace, actual_generation.number, work.event_id);
            let bytes = crate::budgeted::read_value(
                snapshot,
                &self.keyspaces.continuous,
                &raw_key,
                RAW_DOCUMENT_BYTES,
                parent,
            )?
            .ok_or_else(|| integrity("prefix-v2 actual raw source metadata is absent"))?;
            parent
                .charge(bytes.len() as u64 + 1, bytes.len() as u64 * 8 + 8192)
                .map_err(budget_error)?;
            let original: IndexedOriginal = decode(&bytes, "prefix-v2 actual indexed original")?;
            self.verify_projected_causal_metadata(snapshot, workspace, &original, parent)?;
            if original.source != doc.source
                || original.event_digest != doc.event_digest
                || original.commit != doc.commit
                || original.policy_domain != doc.policy_domain
            {
                return Err(integrity(
                    "prefix-v2 full original version or metadata differs",
                ));
            }
            let policies =
                self.stored_custody_policies_with_budget(snapshot, work.event_id, parent)?;
            let policy_bytes = metered_json_len(&policies, parent, ROW_BYTES / 2)?;
            parent
                .charge(policy_bytes as u64 + 1, policy_bytes as u64 * 4 + 8192)
                .map_err(budget_error)?;
            if crate::canonical_digest(&policies)? != doc.policy_domain {
                return Err(integrity(
                    "prefix-v2 complete compound source policy differs",
                ));
            }
            if !doc.spans.is_empty() {
                parent
                    .charge(cohorts.len() as u64 * (policy_bytes as u64 + 1) + 1, 0)
                    .map_err(budget_error)?;
                if let Some(existing) = cohorts
                    .iter()
                    .find(|cohort| cohort.domain == doc.policy_domain)
                {
                    if existing.policies != policies {
                        return Err(integrity(
                            "prefix-v2 compound-policy domain aliases different labels",
                        ));
                    }
                } else {
                    if cohorts.len() == MAX_COHORTS {
                        return Err(crate::exhausted(
                            "prefix-v2 complete input exceeds 64 policy cohorts",
                        ));
                    }
                    parent
                        .charge(
                            1,
                            policy_bytes as u64 * 8 + doc.policy_domain.len() as u64 * 4 + 4096,
                        )
                        .map_err(budget_error)?;
                    cohorts.push(CohortInput {
                        domain: doc.policy_domain.clone(),
                        policies: policies.clone(),
                    });
                }
            }
            for (ordinal, span) in doc.spans.iter().enumerate() {
                self.admit_prefix_source(
                    context,
                    workspace,
                    actual_generation,
                    work.event_id,
                    parent,
                )?;
                parent.charge(1, KEY_BYTES).map_err(budget_error)?;
                let vector: DenseVector = self
                    .graph_read(
                        snapshot,
                        &self.keyspaces.continuous,
                        &vector_key(
                            workspace,
                            actual_generation.number,
                            work.event_id,
                            ordinal as u32,
                        ),
                        parent,
                    )?
                    .ok_or_else(|| integrity("prefix-v2 exact planned vector is absent"))?;
                parent
                    .charge(
                        vector.values_bits.len() as u64 + 1,
                        vector.values_bits.len() as u64 * 32
                            + policy_bytes as u64 * 8
                            + 32768
                            + vector
                                .source
                                .source_version
                                .as_ref()
                                .map_or(0, |v| v.len() as u64 * 8),
                    )
                    .map_err(budget_error)?;
                self.check_dense_vector_token(&vector)?;
                if vector.source != doc.source
                    || vector.event_digest != doc.event_digest
                    || vector.commit != doc.commit
                    || vector.ordinal != ordinal as u32
                    || vector.span != span.span
                    || vector.policy_domain != doc.policy_domain
                    || vector.profile_digest != target_manifest.profile_digest
                    || vector.vector_digest != span.vector_digest
                    || vector.values_bits.len() != target_manifest.profile.dimensions as usize
                {
                    return Err(integrity(
                        "prefix-v2 vector differs from its full tagged source plan",
                    ));
                }
                let values = super::super::query::query_vector_values(
                    &target_manifest.profile,
                    vector.clone(),
                    parent,
                )?;
                inputs.push(GraphInput {
                    vector,
                    values,
                    policies: policies.clone(),
                });
            }
            if inputs.len() != total {
                return Err(integrity("prefix-v2 source plan was not kept whole"));
            }
            tracking.row(
                IntervalRow {
                    work: &work,
                    capture: &capture,
                    recovery: &recovery,
                    outcome: IntervalOutcome::Document { document: &doc },
                },
                parent,
            )?;
            // accept() encodes the exact authenticated document. Its full buffer
            // and hashing work were admitted above, before allocation.
            reconstructed.accept(&doc)?;
            documents.push(doc);
        }
        if tracking.work_items as usize != target.work().len() {
            return Err(integrity(
                "prefix-v2 complete replay lost authoritative accepted work",
            ));
        }
        reconstructed.through = target_manifest.through;
        if reconstructed != *target_manifest || inputs.len() as u64 != target_manifest.spans {
            return Err(integrity(
                "prefix-v2 entire ordered prefix differs from the accepted target",
            ));
        }
        Ok(PrefixBuildInput {
            documents,
            inputs,
            interval: tracking.finish(parent)?,
        })
    }

    pub(in crate::raw_index::dense::graph) fn admit_prefix_source(
        &self,
        context: Option<&AuthenticatedRequestContext>,
        workspace: &str,
        generation: &Generation,
        id: ObservationId,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if let Some(context) = context {
            parent.charge(1, 0).map_err(budget_error)?;
            let current = self
                .engine
                .begin_read(SnapshotSelector::Latest)
                .map_err(storage_error)?;
            if self.graph_epoch(&current, workspace, parent)? != generation.authorization_epoch {
                return Err(stale_index());
            }
            self.authorized_capture_policy_with_budget(&current, context, id, parent)?;
            self.authorize_derived_custody_with_budget(&current, context, id, parent)?;
        }
        Ok(())
    }
}
