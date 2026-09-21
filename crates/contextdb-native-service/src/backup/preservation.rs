//! Request-scoped paths from affected archives to available clean replacements.

use std::collections::BTreeMap;

use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use serde::{Deserialize, Serialize};

use crate::{
    NativeBackupArtifactReceipt, NativeBackupKeyCopy, NativeBackupKeyInventory,
    NativeBackupReplacement, NativeBackupReplacementReceipt, encode, exhausted, integrity,
    raw_index::budget_error,
};

#[cfg(test)]
mod tests;

/// Accepted preservation edges from one issued archive to a clean target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupPreservationPath {
    /// Target issuance sequence in the enclosing verified archive inventory.
    pub target_sequence: u64,
    /// Ordered source-to-target proofs, each separately authorized by a retained
    /// request in this workspace and removal authority.
    pub replacements: Vec<NativeBackupReplacementReceipt>,
}

/// Preservation of one archive relative to the enclosing report's selected keys.
/// This is neither global deletion completion nor permission to retire a key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeBackupPreservation {
    /// Legacy membership is unknown; an empty copy list cannot establish absence.
    UnknownContents,
    /// At least one selected value lacks authenticated content composition.
    UnclassifiedValues,
    /// Complete membership contains no selected value requiring removal.
    NotRequired,
    /// No accepted path reaches a target clear of the selected removal values.
    ReplacementRequired,
    /// A clean target is proven, but its complete bytes are not retained.
    AwaitingArtifact {
        /// Exact clean target and its preservation provenance.
        path: NativeBackupPreservationPath,
    },
    /// A proven clean target has independently retained, fully verified bytes and
    /// currently usable keys at the enclosing archive/refusal frontier.
    Preserved {
        /// Exact clean target and its preservation provenance.
        path: NativeBackupPreservationPath,
        /// Complete artifact acceptance, not merely an issued archive digest.
        artifact: NativeBackupArtifactReceipt,
    },
}

pub(crate) enum CopyDisposition {
    Remove,
    Retain,
    Unknown,
}

// Only service-derived reports reach this helper. Preserve every issued archive
// obligation, including unknown membership and incomplete replacement artifacts.
pub(crate) fn retained_targets(
    backups: &NativeBackupKeyInventory,
    preservation: &BTreeMap<u64, NativeBackupPreservation>,
    budget: &mut QueryBudget,
) -> ServiceResult<std::collections::BTreeSet<String>> {
    let archives: BTreeMap<_, _> = backups
        .archives
        .iter()
        .map(|archive| (archive.registration.sequence, archive))
        .collect();
    if archives.keys().ne(preservation.keys()) {
        return Err(integrity("key retirement archive coverage differs"));
    }
    let mut targets = std::collections::BTreeSet::new();
    for status in preservation.values() {
        budget.charge(1, 0).map_err(budget_error)?;
        match status {
            NativeBackupPreservation::NotRequired => {}
            NativeBackupPreservation::Preserved { path, artifact } => {
                let target = archives
                    .get(&path.target_sequence)
                    .ok_or_else(|| integrity("key retirement preservation target is absent"))?;
                if !target.keys_available
                    || target
                        .artifact
                        .as_ref()
                        .is_none_or(|progress| !progress.complete || progress.receipt != *artifact)
                {
                    return Err(integrity("key retirement preservation artifact differs"));
                }
                targets.insert(target.registration.archive_digest.clone());
            }
            _ => {
                return Err(crate::invalid(
                    "selected archive preservation remains unresolved",
                ));
            }
        }
    }
    Ok(targets)
}

#[derive(Clone, Copy)]
struct Route<'a> {
    target: u64,
    next: Option<&'a NativeBackupReplacement>,
}

#[derive(Default)]
struct Routes<'a> {
    clean: Option<Route<'a>>,
    available: Option<Route<'a>>,
}

// Both inputs come from one fully verified custody snapshot. Replacement proofs
// have already been filtered by workspace/authority and each exact request was
// independently verified. Matching roots alone never authorizes another edge.
pub(crate) fn inventory(
    backups: &NativeBackupKeyInventory,
    replacements: &[NativeBackupReplacement],
    mut classify: impl FnMut(&NativeBackupKeyCopy) -> ServiceResult<CopyDisposition>,
    budget: &mut QueryBudget,
) -> ServiceResult<BTreeMap<u64, NativeBackupPreservation>> {
    let mut archives = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    for archive in &backups.archives {
        budget.charge(1, 0).map_err(budget_error)?;
        let sequence = archive.registration.sequence;
        if archives.insert(sequence, archive).is_some() {
            return Err(integrity("archive preservation repeats an issuance"));
        }
        let mut unknown = false;
        let mut removed = false;
        for copy in &archive.copies {
            budget.charge(1, 0).map_err(budget_error)?;
            match classify(copy)? {
                CopyDisposition::Remove => removed = true,
                CopyDisposition::Retain => {}
                CopyDisposition::Unknown => unknown = true,
            }
        }
        let status = if archive.contents.is_none() {
            NativeBackupPreservation::UnknownContents
        } else if unknown {
            NativeBackupPreservation::UnclassifiedValues
        } else if removed {
            NativeBackupPreservation::ReplacementRequired
        } else {
            NativeBackupPreservation::NotRequired
        };
        statuses.insert(sequence, status);
    }
    let mut edges = BTreeMap::<_, Vec<_>>::new();
    for proof in replacements {
        budget.charge(1, 0).map_err(budget_error)?;
        let source = proof.source.registration.sequence;
        let target = proof.target.registration.sequence;
        if archives.get(&source).and_then(|a| a.contents.as_ref()) != Some(&proof.source)
            || archives.get(&target).and_then(|a| a.contents.as_ref()) != Some(&proof.target)
            || proof.target.registration.native_commit <= proof.source.registration.native_commit
        {
            return Err(integrity(
                "archive preservation edge has different contents or ancestry",
            ));
        }
        edges.entry(source).or_default().push(proof);
    }
    // Issuance order is not ancestry: an older native snapshot can be issued later.
    // Strictly increasing native commits make verified preservation edges a DAG.
    let mut ordered: Vec<_> = archives.values().copied().collect();
    ordered.sort_by_key(|archive| {
        std::cmp::Reverse((
            archive.registration.native_commit,
            archive.registration.sequence,
        ))
    });
    let mut routes = BTreeMap::<u64, Routes<'_>>::new();
    for archive in ordered {
        budget.charge(1, 0).map_err(budget_error)?;
        let sequence = archive.registration.sequence;
        let mut route = Routes::default();
        if statuses[&sequence] == NativeBackupPreservation::NotRequired && archive.keys_available {
            route.clean = Some(Route {
                target: sequence,
                next: None,
            });
            if archive.artifact.as_ref().is_some_and(|a| a.complete) {
                route.available = route.clean;
            }
        }
        for proof in edges.get(&sequence).into_iter().flatten() {
            budget.charge(1, 0).map_err(budget_error)?;
            let target = routes
                .get(&proof.target.registration.sequence)
                .ok_or_else(|| integrity("archive preservation target is not ordered"))?;
            for (current, candidate) in [
                (&mut route.clean, target.clean),
                (&mut route.available, target.available),
            ] {
                if current.is_none()
                    && let Some(candidate) = candidate
                {
                    *current = Some(Route {
                        target: candidate.target,
                        next: Some(proof),
                    });
                }
            }
        }
        routes.insert(sequence, route);
    }
    let mut report_bytes = 0usize;
    for (sequence, status) in &mut statuses {
        if *status == NativeBackupPreservation::ReplacementRequired {
            let route = &routes[sequence];
            if let Some(terminal) = route.available.or(route.clean) {
                let available = route.available.is_some();
                let mut path = NativeBackupPreservationPath {
                    target_sequence: terminal.target,
                    replacements: Vec::new(),
                };
                let mut cursor = *sequence;
                while cursor != terminal.target {
                    let next = &routes[&cursor];
                    let step = if available {
                        next.available
                    } else {
                        next.clean
                    }
                    .and_then(|route| route.next)
                    .ok_or_else(|| integrity("archive preservation path is incomplete"))?;
                    reserve(&step.receipt, &mut report_bytes, budget)?;
                    path.replacements.push(step.receipt.clone());
                    cursor = step.target.registration.sequence;
                }
                *status = if available {
                    let artifact = archives[&terminal.target]
                        .artifact
                        .as_ref()
                        .ok_or_else(|| integrity("archive preservation artifact disappeared"))?;
                    NativeBackupPreservation::Preserved {
                        path,
                        artifact: artifact.receipt.clone(),
                    }
                } else {
                    NativeBackupPreservation::AwaitingArtifact { path }
                };
            }
        }
        // Path receipts were reserved before cloning, so long chains cannot build
        // an unbounded quadratic result; routing stores one next step per archive.
        reserve(&(*sequence, &status), &mut report_bytes, budget)?;
    }
    Ok(statuses)
}

fn reserve<T: Serialize>(
    value: &T,
    total: &mut usize,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    let bytes = encode(value)?.len() + 64;
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| exhausted("archive preservation size overflow"))?;
    if *total > 32 * 1024 * 1024 {
        return Err(exhausted("archive preservation exceeds 32 MiB"));
    }
    budget.charge(1, bytes as u64).map_err(budget_error)
}

impl crate::NativeService {
    // Earlier authorized removals remain usable after their old keys are refused.
    // This lets A -> B (request 1) -> C (request 2) preserve all permitted data
    // without decrypting A again. The custody seal is not substitute authority
    // for an independently retained request in the currently supplied ledger.
    pub(crate) fn verify_backup_replacement_requests(
        &self,
        context: &contextdb_service::AuthenticatedRequestContext,
        request: &crate::NativeRemovalRequestReceipt,
        replacements: &[NativeBackupReplacement],
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let workspace = crate::digest_bytes(context.request.workspace_id.as_bytes());
        let mut verified = BTreeMap::new();
        for proof in replacements {
            budget.charge(1, 0).map_err(budget_error)?;
            if proof.workspace_digest != workspace
                || proof.request.authority_id != request.authority_id
            {
                return Err(integrity(
                    "archive preservation crosses workspace or removal authority",
                ));
            }
            if proof.request != *request {
                if let Some(previous) = verified.get(&proof.request.sequence) {
                    if *previous != &proof.request {
                        return Err(integrity(
                            "archive preservation repeats a request with different fields",
                        ));
                    }
                } else {
                    self.read_original_removal_inventory(context, &proof.request, budget)?;
                    verified.insert(proof.request.sequence, &proof.request);
                }
            }
        }
        Ok(())
    }
}
