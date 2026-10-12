//! Reproduce an entire accepted dense interval before it can be sealed.
//! Tracking is optional; the original base-tail path retains its read and fee shape.

use super::*;
use contextdb_recall::QueryLimit;
use std::io::{self, Write};

#[cfg(test)]
mod tests;

const INTERVAL_DOMAIN: &[u8] = b"contextdb.native-span-ann-dense-prefix-interval.v1\0";

#[derive(Serialize)]
struct IntervalHeader<'a> {
    database_id: &'a str,
    workspace_digest: &'a str,
    generation: u64,
    authorization_epoch: u64,
    removal_through: Option<u64>,
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

/// Canonical JSON is streamed into the hash. Every write is admitted before
/// hashing; no encoded document/control buffer or replacement allowance exists.
struct BudgetHashWriter<'a> {
    hasher: &'a mut blake3::Hasher,
    budget: &'a mut QueryBudget,
    limit: Option<QueryLimit>,
}

impl Write for BudgetHashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.limit.is_some() {
            return Err(io::Error::other("dense interval parent allowance ended"));
        }
        let length = bytes.len() as u64;
        if let Err(limit) = self
            .budget
            .charge(length.saturating_add(1), length.saturating_mul(2))
        {
            self.limit = Some(limit);
            return Err(io::Error::other("dense interval parent allowance ended"));
        }
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.limit.is_some() {
            return Err(io::Error::other("dense interval parent allowance ended"));
        }
        if let Err(limit) = self.budget.check() {
            self.limit = Some(limit);
            return Err(io::Error::other("dense interval parent allowance ended"));
        }
        Ok(())
    }
}

impl IntervalHash {
    fn new(header: IntervalHeader<'_>, budget: &mut QueryBudget) -> ServiceResult<Self> {
        budget
            .charge(1, size_of::<Self>() as u64 + 256)
            .map_err(budget_error)?;
        let mut value = Self {
            hasher: blake3::Hasher::new(),
            work_items: 0,
        };
        let mut writer = BudgetHashWriter {
            hasher: &mut value.hasher,
            budget,
            limit: None,
        };
        let result = writer.write_all(INTERVAL_DOMAIN);
        if let Some(limit) = writer.limit {
            return Err(budget_error(limit));
        }
        result.map_err(|_| integrity("dense interval domain encoding failed"))?;
        value.part(&header, budget)?;
        Ok(value)
    }

    fn part<T: Serialize>(&mut self, part: &T, budget: &mut QueryBudget) -> ServiceResult<()> {
        let mut writer = BudgetHashWriter {
            hasher: &mut self.hasher,
            budget,
            limit: None,
        };
        let result = serde_json::to_writer(&mut writer, part);
        if let Some(limit) = writer.limit {
            return Err(budget_error(limit));
        }
        result.map_err(|_| integrity("dense interval canonical encoding failed"))?;
        // A literal NUL cannot occur in a JSON encoding, so this separates parts
        // without allocating an intermediate length-prefixed representation.
        let result = writer.write_all(&[0]);
        if let Some(limit) = writer.limit {
            return Err(budget_error(limit));
        }
        result.map_err(|_| integrity("dense interval separator encoding failed"))
    }

    fn row(&mut self, row: IntervalRow<'_>, budget: &mut QueryBudget) -> ServiceResult<()> {
        let count = self
            .work_items
            .checked_add(1)
            .filter(|count| *count <= MAX_TAIL_WORK as u32)
            .ok_or_else(|| exhausted("dense interval work count exceeded"))?;
        self.part(&row, budget)?;
        self.work_items = count;
        Ok(())
    }

    fn finish(self, budget: &mut QueryBudget) -> ServiceResult<DensePrefixInterval> {
        budget.charge(1, 256).map_err(budget_error)?;
        Ok(DensePrefixInterval {
            work_items: self.work_items,
            digest: ContentDigest::from_bytes(*self.hasher.finalize().as_bytes()),
        })
    }
}

impl NativeService {
    #[allow(
        clippy::too_many_arguments,
        reason = "authenticated starting prefix, current ending prefix and parent remain explicit"
    )]
    pub(in crate::raw_index::dense::graph) fn dense_prefix_witness<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        generation: &Generation,
        anchor: AuthenticatedDensePrefixAnchor<'_>,
        max_work: usize,
        tracked: bool,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Witness> {
        if tracked && !(1..=MAX_TAIL_WORK).contains(&max_work) {
            return Err(crate::invalid(
                "dense interval requires 1..128 accepted work items",
            ));
        }
        let latest = generation.dense.as_ref().ok_or_else(stale_index)?;
        budget
            .charge(1, 8192 + max_work as u64 * 512)
            .map_err(budget_error)?;
        let mut witness = anchor.manifest.clone();
        let mut documents = Vec::new();
        let mut work_items = 0_u32;
        let mut tracking = if tracked {
            Some(IntervalHash::new(
                IntervalHeader {
                    database_id: &self.database_id,
                    workspace_digest: workspace,
                    generation: generation.number,
                    authorization_epoch: generation.authorization_epoch,
                    removal_through: generation.removal_through,
                    before: anchor.manifest,
                    after: latest,
                },
                budget,
            )?)
        } else {
            None
        };
        if witness == *latest {
            return Ok(Witness {
                documents,
                complete: true,
                interval: tracking.map(|value| value.finish(budget)).transpose()?,
                work_items,
            });
        }
        let prefix = format!("outbox/{workspace}/").into_bytes();
        let mut after = prefix.clone();
        after.extend_from_slice(&witness.through.to_be_bytes());
        let page = crate::budgeted::metadata(snapshot, budget, |r| {
            r.scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: Some(&after),
                    max_entries: max_work,
                    max_bytes: 256 * 1024,
                },
            )
            .map_err(storage_error)
        })?;
        let mut last = witness.through;
        let mut beyond = false;
        for row in page.entries {
            budget.charge(1, 1024).map_err(budget_error)?;
            let work: crate::capture::CaptureWork = decode(&row.value, "dense tail accepted work")?;
            if row.key != crate::capture::work_key(workspace, work.workspace_commit)
                || work.workspace_commit <= last
            {
                return Err(integrity("dense tail outbox identity or order differs"));
            }
            last = work.workspace_commit;
            if work.workspace_commit > latest.through {
                beyond = true;
                break;
            }
            if tracked {
                work_items += 1;
            }
            let (captured, recovery) =
                self.capture_recovery_metadata(snapshot, work.event_id, budget)?;
            if recovery.is_none()
                || work.recovery_digest.is_none()
                || self.capture_work_for_receipt_with_budget(snapshot, &captured, budget)? != work
            {
                return Err(integrity("dense tail accepted control differs"));
            }
            self.tail_capture_publication(snapshot, workspace, &captured, &work, budget)?;
            if self.source_prepared_at(
                snapshot,
                workspace,
                work.event_id,
                generation.removal_through,
                budget,
            )? {
                if let Some(value) = &mut tracking {
                    value.row(
                        IntervalRow {
                            work: &work,
                            capture: &captured,
                            recovery: &recovery,
                            outcome: IntervalOutcome::PreparedRemoval {
                                removal_through: generation.removal_through,
                            },
                        },
                        budget,
                    )?;
                }
                continue;
            }
            let doc: DenseDocument = self
                .graph_read(
                    snapshot,
                    &self.keyspaces.continuous,
                    &document_key(workspace, generation.number, work.event_id),
                    budget,
                )?
                .ok_or_else(|| integrity("tail tagged document absent"))?;
            budget
                .charge(
                    1,
                    8192 + doc.spans.len() as u64 * 1024
                        + doc
                            .source
                            .source_version
                            .as_ref()
                            .map_or(0, |s| s.len() as u64 * 8),
                )
                .map_err(budget_error)?;
            self.check_dense_document_token(&doc)?;
            if doc.source.event_id != work.event_id
                || doc.event_digest != work.event_digest
                || doc.commit != work.workspace_commit
                || doc.profile_digest != latest.profile_digest
                || doc.source.payload_digest != captured.payload_digest
                || doc.spans.len() > MAX_SOURCE_SPANS
                || (doc.omission.is_some() && !doc.spans.is_empty())
                || (doc.omission.is_none() && doc.spans.is_empty())
                || doc.spans.iter().any(|s| {
                    s.span.event_id != doc.source.event_id
                        || Some(s.span.payload_digest) != doc.source.payload_digest
                        || s.span.start >= s.span.end
                        || doc
                            .source
                            .byte_length
                            .is_none_or(|length| s.span.end > length)
                })
            {
                return Err(integrity(
                    "tail document source/version or exact spans differ",
                ));
            }
            if let Some(value) = &mut tracking {
                value.row(
                    IntervalRow {
                        work: &work,
                        capture: &captured,
                        recovery: &recovery,
                        outcome: IntervalOutcome::Document { document: &doc },
                    },
                    budget,
                )?;
            }
            witness.accept(&doc)?;
            documents.push(doc);
        }
        let complete = beyond || last >= latest.through || page.continuation.is_none();
        if !complete {
            return Ok(Witness {
                documents: Vec::new(),
                complete: false,
                interval: None,
                work_items,
            });
        }
        witness.through = latest.through;
        if witness != *latest {
            return Err(integrity(
                "dense tail complete prefix witness differs from accepted latest manifest",
            ));
        }
        Ok(Witness {
            documents,
            complete: true,
            interval: tracking.map(|value| value.finish(budget)).transpose()?,
            work_items,
        })
    }
}
