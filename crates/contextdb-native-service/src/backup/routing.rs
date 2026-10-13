//! Shared routing through exact authorized archive-preservation edges.

use super::*;
use crate::{
    NativeBackupArtifactReceipt, NativeBackupKeyArchive, NativeBackupKeyInventory,
    NativeBackupReplacement,
};
use contextdb_recall::QueryBudget;
use serde::Serialize;

#[derive(Clone, Copy)]
struct Route<'a> {
    target: u64,
    next: Option<&'a NativeBackupReplacement>,
}

#[derive(Default)]
struct Routes<'a> {
    readable: Option<Route<'a>>,
    available: Option<Route<'a>>,
}

pub(super) struct ArchiveRoutes<'a> {
    archives: BTreeMap<u64, &'a NativeBackupKeyArchive>,
    routes: BTreeMap<u64, Routes<'a>>,
}

pub(super) struct RoutedArchive {
    pub path: NativeBackupPreservationPath,
    pub artifact: Option<NativeBackupArtifactReceipt>,
}

impl<'a> ArchiveRoutes<'a> {
    // Inputs share one verified custody snapshot; every supplied edge's request
    // has already been independently checked in the current workspace/authority.
    pub fn new(
        backups: &'a NativeBackupKeyInventory,
        replacements: &'a [NativeBackupReplacement],
        mut eligible: impl FnMut(u64) -> bool,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        let mut archives = BTreeMap::new();
        for archive in &backups.archives {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            if archives
                .insert(archive.registration.sequence, archive)
                .is_some()
            {
                return Err(integrity("archive routing repeats an issuance"));
            }
        }
        let mut edges = BTreeMap::<_, Vec<_>>::new();
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
                    "archive route has different contents or ancestry",
                ));
            }
            edges.entry(source).or_default().push(proof);
        }
        // Issuance order is not ancestry: an older snapshot can be issued later.
        let mut ordered: Vec<_> = archives.values().copied().collect();
        ordered.sort_by_key(|archive| {
            std::cmp::Reverse((
                archive.registration.native_commit,
                archive.registration.sequence,
            ))
        });
        let mut routes = BTreeMap::<u64, Routes<'_>>::new();
        for archive in ordered {
            budget
                .charge(1, 0)
                .map_err(crate::raw_index::budget_error)?;
            let sequence = archive.registration.sequence;
            let mut route = Routes::default();
            if eligible(sequence) && archive.contents.is_some() && archive.keys_available {
                route.readable = Some(Route {
                    target: sequence,
                    next: None,
                });
                if archive.artifact.as_ref().is_some_and(|a| a.complete) {
                    route.available = route.readable;
                }
            }
            for proof in edges.get(&sequence).into_iter().flatten() {
                budget
                    .charge(1, 0)
                    .map_err(crate::raw_index::budget_error)?;
                let target = routes
                    .get(&proof.target.registration.sequence)
                    .ok_or_else(|| integrity("archive route target is not ordered"))?;
                for (current, candidate) in [
                    (&mut route.readable, target.readable),
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
        Ok(Self { archives, routes })
    }

    pub fn best(
        &self,
        sequence: u64,
        report_bytes: &mut usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<RoutedArchive>> {
        let route = self
            .routes
            .get(&sequence)
            .ok_or_else(|| integrity("archive routing source is absent"))?;
        let Some(terminal) = route.available.or(route.readable) else {
            return Ok(None);
        };
        let available = route.available.is_some();
        let mut path = NativeBackupPreservationPath {
            target_sequence: terminal.target,
            replacements: Vec::new(),
        };
        let mut cursor = sequence;
        while cursor != terminal.target {
            let next = &self.routes[&cursor];
            let step = if available {
                next.available
            } else {
                next.readable
            }
            .and_then(|route| route.next)
            .ok_or_else(|| integrity("archive route is incomplete"))?;
            reserve(&step.receipt, report_bytes, budget)?;
            path.replacements.push(step.receipt.clone());
            cursor = step.target.registration.sequence;
        }
        let artifact = if available {
            Some(
                self.archives[&terminal.target]
                    .artifact
                    .as_ref()
                    .ok_or_else(|| integrity("archive route artifact disappeared"))?
                    .receipt
                    .clone(),
            )
        } else {
            None
        };
        Ok(Some(RoutedArchive { path, artifact }))
    }
}

// Reserve before cloning long paths, bounding the whole report rather than each
// individual route. Routing itself stores only one next edge per archive.
pub(super) fn reserve<T: Serialize>(
    value: &T,
    total: &mut usize,
    budget: &mut QueryBudget,
) -> ServiceResult<()> {
    let bytes = encode(value)?.len() + 64;
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| exhausted("archive routing size overflow"))?;
    if *total > 32 * 1024 * 1024 {
        return Err(exhausted("archive routing exceeds 32 MiB"));
    }
    budget
        .charge(1, bytes as u64)
        .map_err(crate::raw_index::budget_error)
}
