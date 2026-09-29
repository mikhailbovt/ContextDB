//! Carry completed cleanup forward through independently authorized replacements.

use super::*;
use crate::{NativeBackupKeyInventory, NativeBackupReplacement};

#[derive(Clone, Copy)]
struct Anchor<'a> {
    job: &'a NativeBackupCleanupJobReceipt,
    previous: Option<&'a NativeBackupReplacement>,
}

pub(super) struct CleanCoverage<'a> {
    anchors: BTreeMap<u64, Anchor<'a>>,
}

impl<'a> CleanCoverage<'a> {
    // Inputs come from one verified custody snapshot. Seeds are exact terminal
    // jobs for the inspected request; every edge's request has been checked in
    // the current workspace/authority. Replacement acceptance preserves prior
    // native history and pruning controls, including earlier authorized removals.
    pub fn new(
        catalog: &'a NativeBackupKeyInventory,
        replacements: &'a [NativeBackupReplacement],
        seeds: BTreeMap<u64, &'a NativeBackupCleanupJobReceipt>,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        let mut archives = BTreeMap::new();
        for archive in &catalog.archives {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            if archives
                .insert(archive.registration.sequence, archive)
                .is_some()
            {
                return Err(integrity("archive coverage repeats an issuance"));
            }
        }
        let mut incoming = BTreeMap::<_, Vec<_>>::new();
        for proof in replacements {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            let source = proof.source.registration.sequence;
            let target = proof.target.registration.sequence;
            if archives.get(&source).and_then(|a| a.contents.as_ref()) != Some(&proof.source)
                || archives.get(&target).and_then(|a| a.contents.as_ref()) != Some(&proof.target)
                || proof.target.registration.native_commit
                    <= proof.source.registration.native_commit
            {
                return Err(integrity(
                    "archive coverage has different contents or ancestry",
                ));
            }
            incoming.entry(target).or_default().push(proof);
        }
        let mut anchors = BTreeMap::new();
        for (sequence, job) in seeds {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            if archives
                .get(&sequence)
                .and_then(|archive| archive.contents.as_ref())
                .is_none()
            {
                return Err(integrity("archive cleanup anchor has no verified contents"));
            }
            anchors.insert(
                sequence,
                Anchor {
                    job,
                    previous: None,
                },
            );
        }
        let mut ordered: Vec<_> = archives.values().copied().collect();
        ordered.sort_by_key(|archive| {
            (
                archive.registration.native_commit,
                archive.registration.sequence,
            )
        });
        for archive in ordered {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            let sequence = archive.registration.sequence;
            if anchors.contains_key(&sequence) {
                continue;
            }
            for proof in incoming.get(&sequence).into_iter().flatten() {
                budget
                    .charge(1, 0)
                    .map_err(crate::raw_index::budget_error)?;
                if let Some(anchor) = anchors.get(&proof.source.registration.sequence).copied() {
                    anchors.insert(
                        sequence,
                        Anchor {
                            job: anchor.job,
                            previous: Some(proof),
                        },
                    );
                    break;
                }
            }
        }
        Ok(Self { anchors })
    }

    pub fn contains(&self, sequence: u64) -> bool {
        self.anchors.contains_key(&sequence)
    }

    // Store one predecessor per endpoint; materialize the path only under the
    // same whole-report bound as the original-to-readable-target ancestry.
    pub fn proof(
        &self,
        sequence: u64,
        report_bytes: &mut usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<(NativeBackupCleanupJobReceipt, NativeBackupPreservationPath)> {
        let anchor = self
            .anchors
            .get(&sequence)
            .ok_or_else(|| integrity("clean archive job disappeared"))?;
        let mut path = NativeBackupPreservationPath {
            target_sequence: sequence,
            replacements: Vec::new(),
        };
        let mut cursor = sequence;
        while let Some(proof) = self.anchors[&cursor].previous {
            routing::reserve(&proof.receipt, report_bytes, budget)?;
            path.replacements.push(proof.receipt.clone());
            cursor = proof.source.registration.sequence;
        }
        path.replacements.reverse();
        routing::reserve(anchor.job, report_bytes, budget)?;
        Ok((anchor.job.clone(), path))
    }
}
