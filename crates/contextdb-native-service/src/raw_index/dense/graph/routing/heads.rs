//! Owner-stamped directory-router heads and accepted append/GC replay.
//!
//! None keeps legacy bytes. Some(empty) survives final GC. The existing frame
//! predecessor reader supplies the same finite snapshot; no writer budget is
//! invented here. Budgeted current reads and offline replay retain their parent.

use super::types::{
    DirectoryRouterHeadStampV1, DirectoryRouterRefV1, FEATURE, OPERATION, WORKSPACE_HEADS_MAC,
};
use crate::{
    CommitMap, Manifest, NativeService, SCHEMA_VERSION, StoredEvent, WorkspaceState, decode,
    digest_bytes, encode, event_digest, integrity, keyed_token, validate_workspace_state,
    workspace_map_key,
};
use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::ReadSnapshot;
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use std::collections::{BTreeMap, BTreeSet};

const HEAD_BYTES: usize = 8 * 1024;
const MANIFEST_BYTES: usize = 128 * 1024;
const MAX_HEADS: usize = crate::raw_index::MAX_GENERATIONS as usize;

pub(crate) fn deserialize_directory_routers<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<BTreeMap<u64, DirectoryRouterRefV1>>, D::Error> {
    struct Heads(BTreeMap<u64, DirectoryRouterRefV1>);
    impl<'de> Deserialize<'de> for Heads {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Bound;
            impl<'de> Visitor<'de> for Bound {
                type Value = Heads;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("at most three unique retained directory-router heads")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Heads, A::Error> {
                    let mut heads = BTreeMap::new();
                    while let Some(key) = map.next_key::<u64>()? {
                        if heads.len() == MAX_HEADS || heads.contains_key(&key) {
                            return Err(serde::de::Error::custom(
                                "directory-router heads bound or duplicate key",
                            ));
                        }
                        heads.insert(key, map.next_value::<DirectoryRouterRefV1>()?);
                    }
                    Ok(Heads(heads))
                }
            }
            d.deserialize_map(Bound)
        }
    }
    Option::<Heads>::deserialize(d).map(|heads| heads.map(|h| h.0))
}

pub(crate) fn validate_directory_routers(state: &WorkspaceState) -> ServiceResult<()> {
    let Some(heads) = &state.directory_routers else {
        return Ok(());
    };
    if heads.len() > MAX_HEADS || state.watermarks.journal == 0 || !hex(&state.workspace_digest) {
        return Err(integrity(
            "workspace directory-router heads exceed their retained bound",
        ));
    }
    for (generation, reference) in heads {
        reference.validate()?;
        if *generation == 0 || reference.global_commit > state.latest_global_commit {
            return Err(integrity(
                "workspace directory-router head identity is invalid",
            ));
        }
    }
    Ok(())
}

impl NativeService {
    pub(crate) fn directory_router_head_stamp(
        &self,
        state: &WorkspaceState,
        event: &StoredEvent,
    ) -> ServiceResult<Option<DirectoryRouterHeadStampV1>> {
        let Some(heads) = &state.directory_routers else {
            return Ok(None);
        };
        validate_workspace_state(state, &event.workspace_digest)?;
        if event.schema_version != SCHEMA_VERSION
            || event.global_commit != state.latest_global_commit
            || event.workspace_commit != state.watermarks.journal
            || event.global_commit == 0
            || event.operation.trim().is_empty()
            || event.operation.len() > crate::MAX_IDENTIFIER_BYTES
            || !hex(&event.request_digest)
            || !hex(&event.response_digest)
            || (event.global_commit == 1) != event.previous_event_digest.is_none()
            || event
                .previous_event_digest
                .as_ref()
                .is_some_and(|s| !hex(s))
        {
            return Err(integrity(
                "workspace directory-router stamp frame binding is invalid",
            ));
        }
        let map_digest = ContentDigest::from_bytes(*blake3::hash(&encode(heads)?).as_bytes());
        // The root ref contains position/request/response, never this event's
        // digest: the latter is formed only after all independent stamps.
        let token = keyed_token(
            &self.token_key,
            WORKSPACE_HEADS_MAC,
            &encode(&(
                1_u16,
                &self.database_id,
                &event.workspace_digest,
                event.global_commit,
                event.workspace_commit,
                &event.previous_event_digest,
                &event.operation,
                &event.request_digest,
                &event.response_digest,
                map_digest,
                sibling_map_digest(state)?,
            ))?,
        );
        Ok(Some(DirectoryRouterHeadStampV1 {
            revision: 1,
            map_digest,
            token,
        }))
    }

    pub(crate) fn check_directory_router_head_stamp(
        &self,
        state: &WorkspaceState,
        event: &StoredEvent,
    ) -> ServiceResult<()> {
        if let Some(stamp) = &event.directory_routers {
            stamp.validate()?;
        }
        if event.directory_routers != self.directory_router_head_stamp(state, event)? {
            return Err(integrity(
                "workspace directory-router head map differs from its owner stamp",
            ));
        }
        Ok(())
    }

    /// Reuses the existing frame's decoded manifest/map/event and its single
    /// successor proof. This adds no IO to an ordinary all-None predecessor.
    pub(crate) fn check_directory_router_head_predecessor(
        &self,
        state: &WorkspaceState,
        event: &StoredEvent,
        manifest: &Manifest,
    ) -> ServiceResult<()> {
        if (state.directory_routers.is_some() || event.directory_routers.is_some())
            && !manifest.features.contains(FEATURE)
        {
            return Err(integrity(
                "workspace predecessor lost its directory-router feature",
            ));
        }
        self.check_directory_router_head_stamp(state, event)
    }

    fn directory_router_head_auth(
        &self,
        state: &WorkspaceState,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        validate_directory_routers(state)?;
        let roots = state.directory_routers.as_ref().map_or(0, BTreeMap::len)
            + state.segment_heads.as_ref().map_or(0, BTreeMap::len)
            + state.prefix_bases.as_ref().map_or(0, BTreeMap::len)
            + state.prefix_segment_heads.as_ref().map_or(0, BTreeMap::len);
        let stamps = u64::from(state.directory_routers.is_some())
            + u64::from(state.segment_heads.is_some())
            + u64::from(state.prefix_bases.is_some())
            + u64::from(state.prefix_segment_heads.is_some());
        parent
            .charge(
                32768 + roots as u64 + stamps,
                (roots as u64 + stamps) * 4096 + self.database_id.len() as u64 * 12 + 8192,
            )
            .map_err(crate::raw_index::budget_error)
    }

    /// Exact latest owner-map admission, including authentic None. Retained
    /// ordinal publication absence is a separate first-appender proof.
    pub(crate) fn current_directory_router_heads<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<WorkspaceState> {
        // The prefix-directory reader authenticates all FOUR independent stamps
        // under its existing exact map/event/global/one-successor read pattern.
        // Coverage may be stale after a fine append; this is latest ROOT metadata.
        self.current_prefix_segment_heads(snapshot, workspace_id, parent)
    }

    /// Bounded administrative replay under ONE parent, not a hot corpus scan.
    pub(crate) fn verify_directory_router_heads_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.verify_directory_router_heads_inner(snapshot, parent, true)
    }

    fn verify_directory_router_heads_inner<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        parent: &mut QueryBudget,
        transitions: bool,
    ) -> ServiceResult<()> {
        let mut activated = BTreeMap::<String, (u64, WorkspaceState)>::new();
        self.head_walk(
            snapshot,
            &self.keyspaces.workspace_map,
            HEAD_BYTES,
            parent,
            |row, parent| {
                let mapping: CommitMap =
                    decode(&row.value, "directory-router workspace historical map")?;
                if mapping.state.directory_routers.is_none() {
                    if activated.contains_key(&mapping.state.workspace_digest) {
                        return Err(integrity(
                            "activated directory-router workspace map downgraded to None",
                        ));
                    }
                    return Ok(());
                }
                validate_workspace_state(&mapping.state, &mapping.state.workspace_digest)?;
                if mapping.schema_version != SCHEMA_VERSION
                    || mapping.global_commit != mapping.state.latest_global_commit
                    || row.key
                        != workspace_map_key(
                            &mapping.state.workspace_digest,
                            mapping.state.watermarks.journal,
                        )
                    || encode(&mapping)? != row.value
                {
                    return Err(integrity(
                        "directory-router historical workspace map binding differs",
                    ));
                }
                if let Some((_, before)) = activated.get(&mapping.state.workspace_digest)
                    && (before.watermarks.journal.checked_add(1)
                        != Some(mapping.state.watermarks.journal)
                        || before.latest_global_commit >= mapping.global_commit)
                {
                    return Err(integrity(
                        "activated directory-router workspace history has a gap",
                    ));
                }
                let event = self
                    .head_read::<StoredEvent, _>(
                        snapshot,
                        &self.keyspaces.events,
                        &mapping.global_commit.to_be_bytes(),
                        crate::MAX_JSON_BYTES,
                        parent,
                    )?
                    .ok_or_else(|| integrity("directory-router historical event absent"))?;
                self.directory_router_head_auth(&mapping.state, parent)?;
                if event.event_digest != event_digest(&event)? {
                    return Err(integrity(
                        "directory-router historical event digest differs",
                    ));
                }
                self.check_directory_router_head_stamp(&mapping.state, &event)?;
                if transitions {
                    self.check_directory_router_head_transition(
                        snapshot,
                        activated
                            .get(&mapping.state.workspace_digest)
                            .map(|(_, state)| state),
                        &mapping.state,
                        &event,
                        parent,
                    )?;
                }
                let first = activated
                    .get(&mapping.state.workspace_digest)
                    .map_or(mapping.state.watermarks.journal, |(first, _)| *first);
                parent
                    .charge(
                        1,
                        HEAD_BYTES as u64 + mapping.state.workspace_digest.len() as u64 * 2,
                    )
                    .map_err(crate::raw_index::budget_error)?;
                activated.insert(
                    mapping.state.workspace_digest.clone(),
                    (first, mapping.state),
                );
                Ok(())
            },
        )?;
        // Retained publication/stamp declarations survive stripping every live root.
        self.head_walk(
            snapshot,
            &self.keyspaces.events,
            crate::MAX_JSON_BYTES,
            parent,
            |row, parent| {
                let event: StoredEvent =
                    decode(&row.value, "retained directory-router head event")?;
                if event.directory_routers.is_none() {
                    if (transitions && event.operation == OPERATION)
                        || activated
                            .get(&event.workspace_digest)
                            .is_some_and(|(first, _)| event.workspace_commit >= *first)
                    {
                        return Err(integrity(
                            "accepted directory-router workspace journal lost its root stamp",
                        ));
                    }
                    return Ok(());
                }
                parent
                    .charge(1, 1024)
                    .map_err(crate::raw_index::budget_error)?;
                let mapping = self
                    .head_read::<CommitMap, _>(
                        snapshot,
                        &self.keyspaces.workspace_map,
                        &workspace_map_key(&event.workspace_digest, event.workspace_commit),
                        HEAD_BYTES,
                        parent,
                    )?
                    .ok_or_else(|| {
                        integrity("directory-router stamped event workspace map absent")
                    })?;
                if mapping.schema_version != SCHEMA_VERSION
                    || row.key != event.global_commit.to_be_bytes()
                    || mapping.global_commit != event.global_commit
                    || mapping.state.latest_global_commit != event.global_commit
                    || event.event_digest != event_digest(&event)?
                {
                    return Err(integrity(
                        "directory-router stamped event map identity differs",
                    ));
                }
                self.directory_router_head_auth(&mapping.state, parent)?;
                self.check_directory_router_head_stamp(&mapping.state, &event)?;
                Ok(())
            },
        )?;
        if activated.is_empty() {
            return Ok(());
        }
        let manifest = self
            .head_read::<Manifest, _>(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                MANIFEST_BYTES,
                parent,
            )?
            .ok_or_else(|| integrity("directory-router heads retained format absent"))?;
        parent
            .charge(1, 4096)
            .map_err(crate::raw_index::budget_error)?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        if !manifest.features.contains(FEATURE) {
            return Err(integrity("directory-router heads retained feature absent"));
        }
        let mut current = BTreeSet::new();
        self.head_walk(
            snapshot,
            &self.keyspaces.workspace,
            HEAD_BYTES,
            parent,
            |row, parent| {
                let state: WorkspaceState = decode(&row.value, "prefix current workspace state")?;
                match activated.get(&state.workspace_digest) {
                    Some((_, latest))
                        if state == *latest && row.key == state.workspace_digest.as_bytes() =>
                    {
                        parent
                            .charge(1, state.workspace_digest.len() as u64 * 2 + 256)
                            .map_err(crate::raw_index::budget_error)?;
                        current.insert(state.workspace_digest);
                    }
                    Some(_) => {
                        return Err(integrity(
                            "current directory-router workspace differs from newest accepted map",
                        ));
                    }
                    None if state.directory_routers.is_some() => {
                        return Err(integrity(
                            "directory-router workspace has no accepted stamped map",
                        ));
                    }
                    None => (),
                }
                Ok(())
            },
        )?;
        if current.len() != activated.len() {
            return Err(integrity(
                "activated directory-router workspace state absent",
            ));
        }
        Ok(())
    }

    fn check_directory_router_head_transition<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        before: Option<&WorkspaceState>,
        current: &WorkspaceState,
        event: &StoredEvent,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        parent
            .charge(8, HEAD_BYTES as u64 * 4)
            .map_err(crate::raw_index::budget_error)?;
        let heads = current
            .directory_routers
            .as_ref()
            .ok_or_else(|| integrity("directory-router transition map absent"))?;
        let before = before.and_then(|state| state.directory_routers.as_ref());
        if before.is_none() && event.operation != OPERATION {
            return Err(integrity(
                "router roots activated without accepted publication",
            ));
        }
        let mut expected = before.cloned().unwrap_or_default();
        if event.operation == OPERATION {
            let mut change = None;
            for (generation, reference) in heads {
                if expected.get(generation) != Some(reference) {
                    if change.is_some() {
                        return Err(integrity(
                            "router publication changes multiple generation roots",
                        ));
                    }
                    change = Some((*generation, reference));
                }
            }
            let (generation, reference) =
                change.ok_or_else(|| integrity("router publication changed no generation root"))?;
            let old = expected.get(&generation);
            let serial = old
                .map_or(Some(1), |head| head.serial.checked_add(1))
                .ok_or_else(|| integrity("directory-router serial overflow"))?;
            if reference.serial != serial
                || reference.global_commit != event.global_commit
                || reference.request_digest != event.request_digest
                || reference.response_digest != event.response_digest
            {
                return Err(integrity(
                    "router root differs from accepted frame position",
                ));
            }
            let receipt = self.accepted_directory_router(
                snapshot,
                &current.workspace_digest,
                generation,
                serial,
                parent,
            )?;
            let manifest = &receipt.manifest;
            let base = current
                .prefix_bases
                .as_ref()
                .and_then(|roots| roots.get(&generation))
                .ok_or_else(|| {
                    integrity("router publication has no current accepted prefix base")
                })?;
            if self.directory_router_reference(snapshot, &receipt, parent)? != *reference
                || receipt.global_commit != event.global_commit
                || manifest.raw.generation != generation
                || manifest.serial != serial
                || manifest.previous.as_ref() != old
                || base.global_commit != manifest.coverage.base.publication.global_commit
                || base.request_digest != manifest.coverage.base.publication.request_digest
                || base.response_digest != manifest.coverage.base.publication.response_digest
                || base.receipt_digest != manifest.coverage.base.receipt_digest
                || base.content_digest != manifest.coverage.base.content_digest
                || current
                    .prefix_segment_heads
                    .as_ref()
                    .and_then(|roots| roots.get(&generation))
                    != manifest.coverage.directory.as_ref()
            {
                return Err(integrity(
                    "router publication differs from its certified coverage roots",
                ));
            }
            if let Some(old) = old {
                let prior = self.accepted_directory_router(
                    snapshot,
                    &current.workspace_digest,
                    generation,
                    old.serial,
                    parent,
                )?;
                let previous = &prior.manifest;
                let old_count = previous
                    .coverage
                    .directory
                    .as_ref()
                    .map_or(0, |head| head.count);
                let new_count = manifest
                    .coverage
                    .directory
                    .as_ref()
                    .map_or(0, |head| head.count);
                if self.directory_router_reference(snapshot, &prior, parent)? != *old
                    || manifest.coverage.base != previous.coverage.base
                    || new_count <= old_count
                    || manifest.raw.generation != previous.raw.generation
                    || manifest.raw.custody_version != previous.raw.custody_version
                    || manifest.raw.analyzer != previous.raw.analyzer
                    || manifest.raw.bm25 != previous.raw.bm25
                    || manifest.raw.authorization_epoch != previous.raw.authorization_epoch
                    || manifest.raw.removal_through != previous.raw.removal_through
                    || manifest.raw.through < previous.raw.through
                    || manifest.raw.projected_sources < previous.raw.projected_sources
                    || manifest.covered.profile != previous.covered.profile
                    || manifest.source_profile_digest != previous.source_profile_digest
                    || manifest.source_space_id != previous.source_space_id
                    || manifest.coarse_space_digest != previous.coarse_space_digest
                    || manifest.coarse_space_id != previous.coarse_space_id
                    || manifest.recipe != previous.recipe
                    || old.global_commit >= event.global_commit
                {
                    return Err(integrity(
                        "router replacement changed its base/profile or did not extend coverage",
                    ));
                }
            }
            expected.insert(generation, reference.clone());
        } else if heads != &expected
            && matches!(
                event.operation.as_str(),
                "raw_reclamation" | "raw_reclamation_with_copies"
            )
        {
            let generation =
                self.directory_router_completed_gc(snapshot, current, event, parent)?;
            if expected.remove(&generation).is_none() {
                return Err(integrity("router GC removed an unaccepted generation"));
            }
        }
        if heads != &expected {
            return Err(integrity(
                "router root transition differs from publication or completed GC",
            ));
        }
        Ok(())
    }

    fn directory_router_completed_gc<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        current: &WorkspaceState,
        event: &StoredEvent,
        parent: &mut QueryBudget,
    ) -> ServiceResult<u64> {
        let stored = self
            .head_read::<crate::StoredIdempotency, _>(
                snapshot,
                &self.keyspaces.idempotency,
                event.request_digest.as_bytes(),
                MANIFEST_BYTES,
                parent,
            )?
            .ok_or_else(|| integrity("directory-router GC accepted response absent"))?;
        parent
            .charge(1, stored.response_bytes.len() as u64 * 8 + 4096)
            .map_err(crate::raw_index::budget_error)?;
        let progress: crate::RawReclaimProgress =
            decode(&stored.response_bytes, "directory-router completed GC")?;
        if stored.schema_version != SCHEMA_VERSION
            || stored.operation != event.operation
            || stored.request_digest != event.request_digest
            || stored.response_digest != event.response_digest
            || stored.response_digest != digest_bytes(&stored.response_bytes)
            || encode(&progress)? != stored.response_bytes
            || crate::canonical_digest(&(
                &current.workspace_digest,
                event.global_commit,
                &progress,
            ))? != event.request_digest
            || !progress.finished
            || progress.total_removed_rows < u64::from(progress.removed_rows)
            || progress.retained_generations > MAX_HEADS as u32
            || (event.operation == "raw_reclamation_with_copies"
                && event.accepted_raw_reclamation.as_ref() != Some(&progress))
            || (event.operation == "raw_reclamation" && event.accepted_raw_reclamation.is_some())
        {
            return Err(integrity(
                "directory-router head removal is not exact accepted complete generation GC",
            ));
        }
        progress
            .generation
            .ok_or_else(|| integrity("directory-router GC removed no generation"))
    }
}

fn sibling_map_digest(state: &WorkspaceState) -> ServiceResult<ContentDigest> {
    Ok(ContentDigest::from_bytes(
        *blake3::hash(&encode(&(
            &state.segment_heads,
            &state.prefix_bases,
            &state.prefix_segment_heads,
        ))?)
        .as_bytes(),
    ))
}

fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests;
