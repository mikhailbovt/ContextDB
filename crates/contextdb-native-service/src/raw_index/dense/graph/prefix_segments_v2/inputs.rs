//! Complete whole-source replay from authenticated capture-interval proofs.

use super::super::publication::GraphInput;
use super::super::segments::crypto::metered_json_len;
use super::proof::VerifiedPrefixSegmentInterval;
use super::types::{
    INTERVAL_DOMAIN, KEY_BYTES, MAX_COHORTS, MAX_NODES, MAX_WORK, PrefixIntervalV2,
    PrefixRawBindingV2, PrefixSegmentBaseRefV2, ROW_BYTES,
};
use crate::raw_index::dense::{
    DenseDocument, DenseManifest, DenseVector, document_key, vector_key,
};
use crate::raw_index::{Generation, IndexedOriginal, budget_error, doc_key};
use crate::{NativeService, decode, integrity};
use contextdb_core::{ContentDigest, ObservationId};
use contextdb_recall::{QueryBudget, QueryLimit};
use contextdb_service::{AccessPolicy, AuthenticatedRequestContext, CaptureReceipt, ServiceResult};
use contextdb_storage::ReadSnapshot;
use serde::Serialize;
use std::{
    io::{self, Write},
    mem::size_of,
};

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;

const RAW_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

pub(in crate::raw_index::dense::graph) struct PrefixSegmentBuildInput {
    pub(in crate::raw_index::dense::graph) documents: Vec<DenseDocument>,
    pub(in crate::raw_index::dense::graph) inputs: Vec<GraphInput>,
    pub(in crate::raw_index::dense::graph) interval: PrefixIntervalV2,
}

#[derive(Serialize)]
struct IntervalHeader<'a> {
    database_id: &'a str,
    workspace_digest: &'a str,
    raw: &'a PrefixRawBindingV2,
    base: &'a PrefixSegmentBaseRefV2,
    before_dense: &'a super::types::AcceptedPublicationRef,
    target_dense: &'a super::types::AcceptedPublicationRef,
    start: &'a super::types::CaptureBoundaryRefV2,
    end: &'a super::types::CaptureBoundaryRefV2,
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
    hash: blake3::Hasher,
    work_items: u32,
}
struct HashWriter<'a> {
    hash: &'a mut blake3::Hasher,
    parent: &'a mut QueryBudget,
    failure: Option<QueryLimit>,
}
impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() {
            return Err(io::Error::other("prefix segment stream ended"));
        }
        if let Err(failure) = self
            .parent
            .charge(bytes.len() as u64 + 1, bytes.len() as u64 * 2)
        {
            self.failure = Some(failure);
            return Err(io::Error::other("prefix segment parent refused"));
        }
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failure.is_some() {
            return Err(io::Error::other("prefix segment stream ended"));
        }
        if let Err(failure) = self.parent.check() {
            self.failure = Some(failure);
            return Err(io::Error::other("prefix segment parent refused"));
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
            hash: blake3::Hasher::new(),
            work_items: 0,
        };
        let mut writer = HashWriter {
            hash: &mut value.hash,
            parent,
            failure: None,
        };
        let result = writer.write_all(INTERVAL_DOMAIN);
        if let Some(failure) = writer.failure {
            return Err(budget_error(failure));
        }
        result.map_err(|_| integrity("prefix segment interval domain failed"))?;
        value.part(&header, parent)?;
        Ok(value)
    }
    fn part<T: Serialize>(&mut self, value: &T, parent: &mut QueryBudget) -> ServiceResult<()> {
        let mut writer = HashWriter {
            hash: &mut self.hash,
            parent,
            failure: None,
        };
        let result = serde_json::to_writer(&mut writer, value);
        if let Some(failure) = writer.failure {
            return Err(budget_error(failure));
        }
        result.map_err(|_| integrity("prefix segment interval encoding failed"))?;
        let result = writer.write_all(&[0]);
        if let Some(failure) = writer.failure {
            return Err(budget_error(failure));
        }
        result.map_err(|_| integrity("prefix segment interval separator failed"))
    }
    fn row(&mut self, row: IntervalRow<'_>, parent: &mut QueryBudget) -> ServiceResult<()> {
        let count = self
            .work_items
            .checked_add(1)
            .filter(|n| *n <= MAX_WORK)
            .ok_or_else(|| crate::exhausted("prefix segment interval exceeds 128 work"))?;
        self.part(&row, parent)?;
        self.work_items = count;
        Ok(())
    }
    fn finish(self, parent: &mut QueryBudget) -> ServiceResult<PrefixIntervalV2> {
        parent.charge(1, 256).map_err(budget_error)?;
        Ok(PrefixIntervalV2 {
            work_items: self.work_items,
            digest: ContentDigest::from_bytes(*self.hash.finalize().as_bytes()),
        })
    }
}

struct CohortInput {
    domain: String,
    policies: Vec<AccessPolicy>,
}

impl NativeService {
    /// The owner resolves the accepted base/current head before this call. Its
    /// base reference is a hash-header binding, never a content access grant.
    /// Only opaque states/capture proofs and current source/custody checks admit
    /// materialization. Historical None is internal administrative reconstruction.
    #[allow(
        clippy::too_many_arguments,
        reason = "raw admission, opaque interval and parent stay distinct"
    )]
    pub(in crate::raw_index::dense::graph) fn prefix_segment_build_input<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        workspace: &str,
        actual_generation: &Generation,
        base: &PrefixSegmentBaseRefV2,
        proof: &VerifiedPrefixSegmentInterval,
        parent: &mut QueryBudget,
    ) -> ServiceResult<PrefixSegmentBuildInput> {
        parent.check().map_err(budget_error)?;
        base.validate()?;
        let before = proof.before().manifest();
        let after = proof.after().manifest();
        let old_receipt = proof.before().receipt();
        let receipt = proof.after().receipt();
        let nodes = after
            .spans
            .checked_sub(before.spans)
            .ok_or_else(|| integrity("prefix segment source spans regressed"))?;
        if proof.work().is_empty() {
            return Err(crate::invalid("prefix segment has no accepted work"));
        }
        if proof.work().len() > MAX_WORK as usize || nodes > MAX_NODES {
            return Err(crate::exhausted(
                "prefix segment interval exceeds its complete work/span bound",
            ));
        }
        let ending = proof
            .work()
            .last()
            .ok_or_else(|| crate::invalid("prefix segment has no accepted work"))?;
        if receipt.generation != actual_generation.number
            || old_receipt.generation != actual_generation.number
            || receipt.authorization_epoch != actual_generation.authorization_epoch
            || old_receipt.authorization_epoch != actual_generation.authorization_epoch
            || receipt.database_id != self.database_id
            || old_receipt.database_id != self.database_id
            || crate::digest_bytes(receipt.workspace_id.as_bytes()) != workspace
            || receipt.raw_through != actual_generation.through
            || receipt.raw_sources != actual_generation.projected_sources
            || old_receipt.raw_through > actual_generation.through
            || old_receipt.raw_sources > actual_generation.projected_sources
            || after
                .sources
                .checked_sub(before.sources)
                .is_none_or(|n| n > proof.work().len() as u64)
            || context.is_some_and(|c| {
                crate::digest_bytes(c.request.workspace_id.as_bytes()) != workspace
            })
            || (context.is_some() && actual_generation.dense.as_ref() != Some(after))
            || proof.end().reference().work != *ending
        {
            return Err(integrity(
                "prefix segment accepted states escape actual full raw admission",
            ));
        }
        let raw = PrefixRawBindingV2::from_generation(actual_generation, parent)?;
        before.validate(actual_generation.through)?;
        after.validate(actual_generation.through)?;
        let manifest_bytes = metered_json_len(before, parent, ROW_BYTES)?;
        parent
            .charge(manifest_bytes as u64 + 1, manifest_bytes as u64 * 8 + 8192)
            .map_err(budget_error)?;
        let mut reconstructed = before.clone();
        let mut tracking = IntervalHash::new(
            IntervalHeader {
                database_id: &self.database_id,
                workspace_digest: workspace,
                raw: &raw,
                base,
                before_dense: proof.before().reference(),
                target_dense: proof.after().reference(),
                start: proof.start().reference(),
                end: proof.end().reference(),
                before,
                after,
            },
            parent,
        )?;
        parent
            .charge(
                1,
                u64::from(MAX_WORK) * size_of::<DenseDocument>() as u64 * 2
                    + nodes * size_of::<GraphInput>() as u64 * 2
                    + MAX_COHORTS as u64 * size_of::<CohortInput>() as u64 * 2
                    + 4096,
            )
            .map_err(budget_error)?;
        let mut documents = Vec::with_capacity(MAX_WORK as usize);
        let mut inputs = Vec::with_capacity(nodes as usize);
        let mut cohorts = Vec::with_capacity(MAX_COHORTS);
        let mut last = before.through;
        for expected in proof.work() {
            if expected.workspace_commit <= last || expected.workspace_commit > after.through {
                return Err(integrity(
                    "prefix segment expected work order/cutoff differs",
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
                    integrity("prefix segment authoritative accepted outbox work is absent")
                })?;
            if &work != expected {
                return Err(integrity(
                    "prefix segment exact accepted outbox work differs",
                ));
            }
            last = work.workspace_commit;
            self.verified_capture_boundary_metadata(snapshot, workspace, &work, parent)?;
            let (capture, recovery) =
                self.capture_recovery_metadata(snapshot, work.event_id, parent)?;
            if recovery.is_none()
                || work.recovery_digest.is_none()
                || self.capture_work_for_receipt_with_budget(snapshot, &capture, parent)? != work
            {
                return Err(integrity("prefix segment actual capture control differs"));
            }
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
            let document: DenseDocument = self
                .graph_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &document_key(workspace, actual_generation.number, work.event_id),
                    parent,
                )?
                .ok_or_else(|| integrity("prefix segment full tagged document is absent"))?;
            let doc_bytes = metered_json_len(&document, parent, ROW_BYTES)?;
            parent
                .charge(doc_bytes as u64 + 1, doc_bytes as u64 * 8 + 8192)
                .map_err(budget_error)?;
            self.check_dense_document_token(&document)?;
            if document.source.event_id != work.event_id
                || document.event_digest != work.event_digest
                || document.commit != work.workspace_commit
                || document.profile_digest != after.profile_digest
                || document.source.payload_digest != capture.payload_digest
                || document.spans.len() > crate::raw_index::dense::MAX_SOURCE_SPANS
                || (document.omission.is_some() && !document.spans.is_empty())
                || (document.omission.is_none() && document.spans.is_empty())
                || document.spans.iter().any(|span| {
                    span.span.event_id != document.source.event_id
                        || Some(span.span.payload_digest) != document.source.payload_digest
                        || span.span.start >= span.span.end
                        || document
                            .source
                            .byte_length
                            .is_none_or(|n| span.span.end > n)
                })
            {
                return Err(integrity(
                    "prefix segment document differs from its whole accepted source plan",
                ));
            }
            let total = inputs
                .len()
                .checked_add(document.spans.len())
                .filter(|n| *n <= MAX_NODES as usize && *n as u64 <= nodes)
                .ok_or_else(|| {
                    crate::exhausted("prefix segment whole source plan exceeds remaining vectors")
                })?;
            self.prefix_segment_source_plan(
                snapshot,
                context,
                workspace,
                actual_generation,
                after,
                &document,
                &mut cohorts,
                &mut inputs,
                parent,
            )?;
            if inputs.len() != total {
                return Err(integrity("prefix segment source plan was not kept whole"));
            }
            tracking.row(
                IntervalRow {
                    work: &work,
                    capture: &capture,
                    recovery: &recovery,
                    outcome: IntervalOutcome::Document {
                        document: &document,
                    },
                },
                parent,
            )?;
            reconstructed.accept(&document)?;
            documents.push(document);
        }
        reconstructed.through = after.through;
        if tracking.work_items as usize != proof.work().len()
            || reconstructed != *after
            || inputs.len() as u64 != nodes
        {
            return Err(integrity(
                "prefix segment complete ordered replay differs from accepted after state",
            ));
        }
        Ok(PrefixSegmentBuildInput {
            documents,
            inputs,
            interval: tracking.finish(parent)?,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one complete source plan uses the existing parent and shared fixed buffers"
    )]
    fn prefix_segment_source_plan<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: Option<&AuthenticatedRequestContext>,
        workspace: &str,
        generation: &Generation,
        after: &DenseManifest,
        document: &DenseDocument,
        cohorts: &mut Vec<CohortInput>,
        inputs: &mut Vec<GraphInput>,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let id: ObservationId = document.source.event_id;
        self.admit_prefix_source(context, workspace, generation, id, parent)?;
        parent.charge(1, KEY_BYTES).map_err(budget_error)?;
        let bytes = crate::budgeted::read_value(
            snapshot,
            &self.keyspaces.continuous,
            &doc_key(workspace, generation.number, id),
            RAW_DOCUMENT_BYTES,
            parent,
        )?
        .ok_or_else(|| integrity("prefix segment actual raw metadata is absent"))?;
        parent
            .charge(bytes.len() as u64 + 1, bytes.len() as u64 * 16 + 8192)
            .map_err(budget_error)?;
        let original: IndexedOriginal = decode(&bytes, "prefix segment actual raw metadata")?;
        self.verify_projected_causal_metadata(snapshot, workspace, &original, parent)?;
        if original.source != document.source
            || original.event_digest != document.event_digest
            || original.commit != document.commit
            || original.policy_domain != document.policy_domain
        {
            return Err(integrity("prefix segment actual source/version differs"));
        }
        let policies = self.stored_custody_policies_with_budget(snapshot, id, parent)?;
        let policy_bytes = metered_json_len(&policies, parent, ROW_BYTES / 2)?;
        parent
            .charge(policy_bytes as u64 + 1, policy_bytes as u64 * 8 + 8192)
            .map_err(budget_error)?;
        if crate::canonical_digest(&policies)? != document.policy_domain {
            return Err(integrity("prefix segment actual compound policy differs"));
        }
        if !document.spans.is_empty() {
            parent
                .charge(cohorts.len() as u64 * (policy_bytes as u64 + 1) + 1, 0)
                .map_err(budget_error)?;
            if let Some(cohort) = cohorts.iter().find(|c| c.domain == document.policy_domain) {
                if cohort.policies != policies {
                    return Err(integrity("prefix segment policy domain aliases labels"));
                }
            } else {
                if cohorts.len() == MAX_COHORTS {
                    return Err(crate::exhausted(
                        "prefix segment exceeds 64 complete cohorts",
                    ));
                }
                parent
                    .charge(
                        1,
                        policy_bytes as u64 * 8 + document.policy_domain.len() as u64 * 4 + 4096,
                    )
                    .map_err(budget_error)?;
                cohorts.push(CohortInput {
                    domain: document.policy_domain.clone(),
                    policies: policies.clone(),
                });
            }
        }
        for (ordinal, span) in document.spans.iter().enumerate() {
            self.admit_prefix_source(context, workspace, generation, id, parent)?;
            parent.charge(1, KEY_BYTES).map_err(budget_error)?;
            let vector: DenseVector = self
                .graph_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &vector_key(workspace, generation.number, id, ordinal as u32),
                    parent,
                )?
                .ok_or_else(|| integrity("prefix segment planned vector is absent"))?;
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
            if vector.source != document.source
                || vector.event_digest != document.event_digest
                || vector.commit != document.commit
                || vector.ordinal != ordinal as u32
                || vector.span != span.span
                || vector.policy_domain != document.policy_domain
                || vector.profile_digest != after.profile_digest
                || vector.vector_digest != span.vector_digest
                || vector.values_bits.len() != after.profile.dimensions as usize
            {
                return Err(integrity(
                    "prefix segment exact vector differs from tagged whole source plan",
                ));
            }
            let values =
                super::super::query::query_vector_values(&after.profile, vector.clone(), parent)?;
            inputs.push(GraphInput {
                vector,
                values,
                policies: policies.clone(),
            });
        }
        Ok(())
    }
}
