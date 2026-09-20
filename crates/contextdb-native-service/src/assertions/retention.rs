//! Explicitly pruned semantic batches. Accepted full-body receipts are never
//! reinterpreted as receipts for a rewritten batch.

#[cfg(test)]
mod tests;
mod verify;

use super::*;
use crate::suppression::RemovalCheckpoint;
use contextdb_core::{ClaimId, TimeRange};

pub(crate) const PRUNING_FEATURE: &str = "continuous-assertion-pruning-v1";

/// Result of removing the selected source copies in one accepted assertion batch.
/// This is not a complete local removal or physical-erasure receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssertionPruningReceipt {
    /// Native publication that durably removed these semantic copies.
    pub workspace_commit: u64,
    /// Original accepted assertion publication; its receipt remains unchanged.
    pub assertion_commit: u64,
    /// Original mutation positions removed by this publication.
    pub mutations: BTreeSet<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssertionPruningPublication {
    request: RemovalCheckpoint,
    workspace_commit: u64,
    receipt: AssertionReceipt,
    control_digest: String,
    selected_sources: BTreeSet<ObservationId>,
    removed: BTreeMap<usize, String>,
}

/// Workspace access and authority policies originate in authenticated host
/// configuration. Interpreter strings are committed, not copied into recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchControl {
    pub(super) workspace_id: String,
    pub(super) access: contextdb_service::AccessPolicy,
    pub(super) scope: ScopeId,
    pub(super) commit: u64,
    pub(super) observed_scope_epoch: u64,
    pub(super) request_digest: String,
    pub(super) pipeline_digest: String,
    pub(super) interpretations: Vec<contextdb_service::EventInterpretation>,
    pub(super) coverage: Coverage,
    pub(super) mutations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RemovedKind {
    Assert {
        claim: ClaimId,
        stance: AssertionStance,
        supersedes: Vec<ClaimId>,
    },
    Retract {
        target: ClaimId,
    },
}

/// No assertion value, envelope, original span text or arbitrary actor string.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RemovedMutation {
    pub(super) key: StateKey,
    pub(super) body_digest: String,
    pub(super) source_digest: String,
    pub(super) origin: ObservationId,
    pub(super) sources: BTreeSet<ObservationId>,
    pub(super) evidence: BTreeMap<contextdb_core::EvidenceId, OriginalSourceSpan>,
    pub(super) valid_time: TimeRange,
    pub(super) kind: RemovedKind,
}

impl RemovedMutation {
    pub(super) fn from_mutation(mutation: &AssertionMutation) -> ServiceResult<Self> {
        let (source, origin, evidence, valid_time, kind) = match mutation {
            AssertionMutation::Assert { assertion } => (
                &assertion.source,
                assertion.originating_event,
                &assertion.original_evidence,
                assertion.revision.temporal.valid_time,
                RemovedKind::Assert {
                    claim: assertion.claim.id,
                    stance: assertion.stance,
                    supersedes: assertion.revision.supersedes.clone(),
                },
            ),
            AssertionMutation::Retract { retraction } => (
                &retraction.source,
                retraction.originating_event,
                &retraction.original_evidence,
                retraction.temporal.valid_time,
                RemovedKind::Retract {
                    target: retraction.target,
                },
            ),
            AssertionMutation::Policy { .. } => {
                return Err(invalid("host authority policies are not source assertions"));
            }
        };
        Ok(Self {
            key: mutation.key().clone(),
            body_digest: digest_bytes(&encode(mutation)?),
            source_digest: canonical_digest(source)?,
            origin,
            sources: evidence.iter().map(|span| span.event_id).collect(),
            evidence: match mutation {
                AssertionMutation::Assert { assertion } => assertion
                    .revision
                    .evidence
                    .iter()
                    .copied()
                    .zip(assertion.original_evidence.iter().cloned())
                    .collect(),
                _ => BTreeMap::new(),
            },
            valid_time,
            kind,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RetainedMutation {
    Live { mutation: AssertionMutation },
    Removed { control: RemovedMutation, at: u64 },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedAssertions {
    pub(super) control: BatchControl,
    pub(super) mutations: Vec<RetainedMutation>,
}

impl RetainedAssertions {
    pub(super) fn from_accepted(accepted: &AcceptedAssertions) -> ServiceResult<Self> {
        Ok(Self {
            control: BatchControl {
                workspace_id: accepted.workspace_id.clone(),
                access: accepted.access.clone(),
                scope: accepted.scope,
                commit: accepted.commit,
                observed_scope_epoch: accepted.observed_scope_epoch,
                request_digest: accepted.request_digest.clone(),
                pipeline_digest: canonical_digest(&accepted.pipeline)?,
                interpretations: accepted.interpretations.clone(),
                coverage: accepted.coverage.clone(),
                mutations: accepted
                    .mutations
                    .iter()
                    .map(|mutation| Ok(digest_bytes(&encode(mutation)?)))
                    .collect::<ServiceResult<_>>()?,
            },
            mutations: accepted
                .mutations
                .iter()
                .cloned()
                .map(|mutation| RetainedMutation::Live { mutation })
                .collect(),
        })
    }
}

#[derive(Clone, Copy)]
enum ProjectionMutation<'a> {
    Live(&'a AssertionMutation),
    Removed {
        control: &'a RemovedMutation,
        at: u64,
    },
}

pub(super) fn accepted_projection(
    accepted: &AcceptedAssertions,
) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    projection_rows(
        &accepted.workspace_id,
        &accepted.access,
        accepted.scope,
        accepted.commit,
        &accepted.coverage,
        accepted.mutations.iter().map(ProjectionMutation::Live),
    )
}

pub(super) fn retained_rows(
    batch: &RetainedAssertions,
) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let accepted = &batch.control;
    projection_rows(
        &accepted.workspace_id,
        &accepted.access,
        accepted.scope,
        accepted.commit,
        &accepted.coverage,
        batch.mutations.iter().map(|mutation| match mutation {
            RetainedMutation::Live { mutation } => ProjectionMutation::Live(mutation),
            RetainedMutation::Removed { control, at } => {
                ProjectionMutation::Removed { control, at: *at }
            }
        }),
    )
}

fn projection_rows<'a>(
    workspace_id: &str,
    access: &contextdb_service::AccessPolicy,
    scope: ScopeId,
    commit: u64,
    coverage: &Coverage,
    mutations: impl Iterator<Item = ProjectionMutation<'a>>,
) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let workspace = digest_bytes(workspace_id.as_bytes());
    let mut rows = BTreeMap::new();
    rows.insert(coverage_head(&workspace, scope), encode(coverage)?);
    rows.insert(
        format!("{}{:020}", coverage_prefix(&workspace, scope), commit).into_bytes(),
        encode(coverage)?,
    );
    for (ordinal, retained) in mutations.enumerate() {
        let (key, label, mutation) = match retained {
            ProjectionMutation::Removed { control, at } => {
                let body_key = match &control.kind {
                    RemovedKind::Assert { claim, .. } => claim_key(*claim),
                    RemovedKind::Retract { .. } => retraction_key(&workspace, commit, ordinal),
                };
                (
                    &control.key,
                    MutationLabel {
                        commit,
                        sources: control.sources.clone(),
                        body_key,
                        body_digest: control.body_digest.clone(),
                        envelope: None,
                        pruned_at: Some(at),
                    },
                    None,
                )
            }
            ProjectionMutation::Live(mutation) => {
                if let AssertionMutation::Policy { policy } = mutation {
                    rows.insert(
                        format!(
                            "state/policy/{workspace}/{}/{:010}",
                            canonical_digest(&policy.key)?,
                            policy.version.get()
                        )
                        .into_bytes(),
                        encode(&StoredAuthority {
                            commit,
                            access: access.clone(),
                            policy: policy.clone(),
                        })?,
                    );
                    continue;
                }
                let body = encode(mutation)?;
                let (body_key, evidence) = match mutation {
                    AssertionMutation::Assert { assertion } => {
                        (claim_key(assertion.claim.id), &assertion.original_evidence)
                    }
                    AssertionMutation::Retract { retraction } => (
                        retraction_key(&workspace, commit, ordinal),
                        &retraction.original_evidence,
                    ),
                    AssertionMutation::Policy { .. } => unreachable!(),
                };
                let label = MutationLabel {
                    commit,
                    sources: evidence.iter().map(|span| span.event_id).collect(),
                    body_key: body_key.clone(),
                    body_digest: digest_bytes(&body),
                    envelope: match mutation {
                        AssertionMutation::Assert { assertion } => {
                            Some(assertion.revision.envelope.clone())
                        }
                        _ => None,
                    },
                    pruned_at: None,
                };
                rows.insert(body_key, body);
                (mutation.key(), label, Some(mutation))
            }
        };
        rows.insert(
            format!(
                "{}{:020}/{ordinal:03}",
                slot_prefix(&workspace, &canonical_digest(key)?),
                commit
            )
            .into_bytes(),
            encode(&label)?,
        );
        match retained {
            ProjectionMutation::Removed {
                control:
                    RemovedMutation {
                        kind: RemovedKind::Assert { claim, .. },
                        ..
                    },
                ..
            } => {
                rows.insert(claim_label_key(*claim), encode(&label)?);
            }
            _ => {
                if let Some(AssertionMutation::Assert { assertion }) = mutation {
                    rows.insert(claim_label_key(assertion.claim.id), encode(&label)?);
                    for (id, span) in assertion
                        .revision
                        .evidence
                        .iter()
                        .zip(&assertion.original_evidence)
                    {
                        let value = encode(span)?;
                        if let Some(previous) = rows.insert(evidence_key(*id), value.clone())
                            && previous != value
                        {
                            return Err(integrity(
                                "evidence identity conflicts within a retained batch",
                            ));
                        }
                    }
                }
            }
        }
        if let ProjectionMutation::Removed { control, .. } = retained {
            for (id, span) in &control.evidence {
                let value = encode(span)?;
                if let Some(previous) = rows.insert(evidence_key(*id), value.clone())
                    && previous != value
                {
                    return Err(integrity(
                        "retained evidence identity conflicts within the batch",
                    ));
                }
            }
        }
    }
    Ok(rows)
}

fn retraction_key(workspace: &str, commit: u64, ordinal: usize) -> Vec<u8> {
    format!("state/retraction/{workspace}/{commit:020}/{ordinal:03}").into_bytes()
}
fn retained_key(workspace: &str, commit: u64) -> Vec<u8> {
    format!("state/pruned-journal/{workspace}/{commit:020}").into_bytes()
}
fn pruning_digest(
    workspace: &str,
    request: &RemovalCheckpoint,
    assertion_commit: u64,
) -> ServiceResult<String> {
    canonical_digest(&(PRUNING_FEATURE, workspace, request, assertion_commit))
}
fn pruning_receipt(publication: &AssertionPruningPublication) -> NativeAssertionPruningReceipt {
    NativeAssertionPruningReceipt {
        workspace_commit: publication.workspace_commit,
        assertion_commit: publication.receipt.workspace_commit,
        mutations: publication.removed.keys().copied().collect(),
    }
}

impl NativeService {
    /// Remove source-supported assertions/retractions in one accepted batch,
    /// retaining independent mutations and content-free replay controls. Analysis
    /// verifies semantic history outside the writer; publication compares the
    /// workspace head. This administrative scan is not a constant-time query.
    pub fn prune_source_assertions(
        &self,
        context: &AuthenticatedRequestContext,
        receipt: &crate::NativeRemovalRequestReceipt,
        assertion_commit: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<NativeAssertionPruningReceipt> {
        require_capability(context, Capability::Admin)?;
        let inventory = self.read_original_removal_inventory(context, receipt, budget)?;
        let selected: BTreeSet<_> = inventory
            .sources
            .iter()
            .map(|source| source.receipt.event_id)
            .collect();
        let request = RemovalCheckpoint {
            sequence: receipt.sequence,
            digest: receipt.digest.clone(),
        };
        let workspace = workspace(context);
        let digest = pruning_digest(&workspace, &request, assertion_commit)?;
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let world = self.workspace_state(&snapshot, &context.request.workspace_id)?;
        // Validate before an exact retry too: marker loss or resurrection must
        // not be mistaken for an already successful cleanup.
        self.verify_assertion_records_budget(&snapshot, budget)?;
        if let Some(accepted) = self.replay::<AssertionPruningPublication, _>(
            &snapshot,
            digest.as_bytes(),
            "assertion_prune",
            &digest,
        )? {
            return Ok(pruning_receipt(&accepted));
        }
        let (global, _) = self.select_snapshot(
            &snapshot,
            &context.request.workspace_id,
            Some(assertion_commit),
        )?;
        let event: crate::StoredEvent = decode(
            &snapshot
                .get(&self.keyspaces.events, &global.to_be_bytes())
                .map_err(storage_error)?
                .ok_or_else(|| invalid("assertion publication is absent"))?,
            "selected assertion publication",
        )?;
        if event.operation != "assertions"
            || event.workspace_commit != assertion_commit
            || event.workspace_digest != workspace
        {
            return Err(invalid(
                "selected commit is not this workspace's assertion publication",
            ));
        }
        let bindings = self.assertion_pruning_bindings(&snapshot, budget)?;
        let (old_key, _, mut batch) = self.load_retained_assertions(
            &snapshot,
            &event,
            bindings.get(&(workspace.clone(), assertion_commit)),
            budget,
        )?;
        let before = retained_rows(&batch)?;
        let next = world
            .watermarks
            .journal
            .checked_add(1)
            .ok_or_else(|| exhausted("workspace commits exhausted"))?;
        let mut removed = BTreeMap::new();
        let mut selected_sources = BTreeSet::new();
        for (ordinal, retained) in batch.mutations.iter_mut().enumerate() {
            let RetainedMutation::Live { mutation } = retained else {
                continue;
            };
            if matches!(mutation, AssertionMutation::Policy { .. }) {
                continue;
            }
            let control = RemovedMutation::from_mutation(mutation)?;
            if control.sources.is_disjoint(&selected) {
                continue;
            }
            selected_sources.extend(control.sources.intersection(&selected).copied());
            removed.insert(ordinal, canonical_digest(&control)?);
            *retained = RetainedMutation::Removed { control, at: next };
        }
        if removed.is_empty() {
            return Err(invalid(
                "batch has no remaining assertions supported by this removal request",
            ));
        }
        for id in &selected_sources {
            if !self.source_prepared_at(
                &snapshot,
                &workspace,
                *id,
                Some(world.watermarks.journal),
                budget,
            )? {
                return Err(stale(
                    "prepare each selected source before pruning semantic copies",
                ));
            }
        }
        let after = retained_rows(&batch)?;
        let bytes = encode(&batch)?;
        if bytes.len() > MAX_STATE_BYTES + 1024 * 1024 {
            return Err(exhausted(
                "pruned semantic controls exceed their bounded profile",
            ));
        }
        budget.charge(1, bytes.len() as u64).map_err(budget_error)?;
        let publication = AssertionPruningPublication {
            request,
            workspace_commit: next,
            receipt: event
                .accepted_assertions
                .ok_or_else(|| integrity("assertion receipt absent"))?,
            control_digest: canonical_digest(&batch.control)?,
            selected_sources,
            removed,
        };
        if encode(&publication)?.len() > 512 * 1024 {
            return Err(exhausted("assertion pruning publication exceeds 512 KiB"));
        }
        #[cfg(test)]
        BEFORE_PUBLICATION.with(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        if self.workspace_state(&tx, &context.request.workspace_id)? != world {
            return Err(stale("workspace changed during semantic pruning"));
        }
        let frame = self.begin_frame(&tx, &context.request.workspace_id, false)?;
        for key in before.keys().filter(|key| !after.contains_key(*key)) {
            tx.delete(&self.keyspaces.continuous, key.clone())
                .map_err(storage_error)?;
        }
        for (key, value) in after {
            // Coverage heads from an older batch must not overwrite newer heads.
            if before.get(&key) != Some(&value) {
                tx.put(&self.keyspaces.continuous, key, value)
                    .map_err(storage_error)?;
            }
        }
        tx.delete(&self.keyspaces.continuous, old_key)
            .map_err(storage_error)?;
        tx.put(
            &self.keyspaces.continuous,
            retained_key(&workspace, assertion_commit),
            bytes,
        )
        .map_err(storage_error)?;
        self.enable_capture_extension(&mut tx, PRUNING_FEATURE)?;
        self.finish_frame(
            &mut tx,
            &frame,
            "assertion_prune",
            digest.as_bytes(),
            &digest,
            &publication,
        )?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )?;
        Ok(pruning_receipt(&publication))
    }
}

#[cfg(test)]
thread_local! { static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = Default::default(); }
