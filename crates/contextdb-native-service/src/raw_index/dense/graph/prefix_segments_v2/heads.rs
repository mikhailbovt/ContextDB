//! Owner-stamped prefix-segment heads and accepted append/GC replay.
//!
//! None keeps legacy bytes. Some(empty) survives final GC. The existing frame
//! predecessor reader supplies the same finite snapshot; no writer budget is
//! invented here. Budgeted current reads and offline replay retain their parent.

use super::types::{
    FEATURE, OPERATION, PrefixSegmentDirectoryRefV2, PrefixSegmentHeadStampV2, WORKSPACE_HEADS_MAC,
};
use crate::{
    CommitMap, Manifest, NativeService, SCHEMA_VERSION, StoredEvent, WorkspaceState, decode,
    digest_bytes, encode, event_digest, integrity, keyed_token, storage_error,
    validate_workspace_state, workspace_map_key,
};
use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::{ReadSnapshot, ScanPageRequest};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use std::collections::{BTreeMap, BTreeSet};

const HEAD_BYTES: usize = 8 * 1024;
const MANIFEST_BYTES: usize = 128 * 1024;
const MAX_HEADS: usize = crate::raw_index::MAX_GENERATIONS as usize;

pub(crate) fn deserialize_prefix_segment_heads<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<BTreeMap<u64, PrefixSegmentDirectoryRefV2>>, D::Error> {
    struct Heads(BTreeMap<u64, PrefixSegmentDirectoryRefV2>);
    impl<'de> Deserialize<'de> for Heads {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Bound;
            impl<'de> Visitor<'de> for Bound {
                type Value = Heads;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("at most three unique retained prefix-segment heads")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Heads, A::Error> {
                    let mut heads = BTreeMap::new();
                    while let Some(key) = map.next_key::<u64>()? {
                        if heads.len() == MAX_HEADS || heads.contains_key(&key) {
                            return Err(serde::de::Error::custom(
                                "prefix-segment heads bound or duplicate key",
                            ));
                        }
                        heads.insert(key, map.next_value::<PrefixSegmentDirectoryRefV2>()?);
                    }
                    Ok(Heads(heads))
                }
            }
            d.deserialize_map(Bound)
        }
    }
    Option::<Heads>::deserialize(d).map(|heads| heads.map(|h| h.0))
}

pub(crate) fn validate_prefix_segment_heads(state: &WorkspaceState) -> ServiceResult<()> {
    let Some(heads) = &state.prefix_segment_heads else {
        return Ok(());
    };
    if heads.len() > MAX_HEADS || state.watermarks.journal == 0 || !hex(&state.workspace_digest) {
        return Err(integrity(
            "workspace prefix-segment heads exceed their retained bound",
        ));
    }
    for (generation, reference) in heads {
        reference.validate()?;
        if *generation == 0 || reference.global_commit > state.latest_global_commit {
            return Err(integrity(
                "workspace prefix-segment head identity is invalid",
            ));
        }
    }
    Ok(())
}

impl NativeService {
    pub(crate) fn prefix_segment_head_stamp(
        &self,
        state: &WorkspaceState,
        event: &StoredEvent,
    ) -> ServiceResult<Option<PrefixSegmentHeadStampV2>> {
        let Some(heads) = &state.prefix_segment_heads else {
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
                "workspace prefix-segment stamp frame binding is invalid",
            ));
        }
        let map_digest = ContentDigest::from_bytes(*blake3::hash(&encode(heads)?).as_bytes());
        // The root ref contains position/request/response, never this event's
        // digest: the latter is formed only after all independent stamps.
        let token = keyed_token(
            &self.token_key,
            WORKSPACE_HEADS_MAC,
            &encode(&(
                2_u16,
                &self.database_id,
                &event.workspace_digest,
                event.global_commit,
                event.workspace_commit,
                &event.previous_event_digest,
                &event.operation,
                &event.request_digest,
                &event.response_digest,
                map_digest,
            ))?,
        );
        Ok(Some(PrefixSegmentHeadStampV2 {
            revision: 2,
            map_digest,
            token,
        }))
    }

    pub(crate) fn check_prefix_segment_head_stamp(
        &self,
        state: &WorkspaceState,
        event: &StoredEvent,
    ) -> ServiceResult<()> {
        if let Some(stamp) = &event.prefix_segment_heads {
            stamp.validate()?;
        }
        if event.prefix_segment_heads != self.prefix_segment_head_stamp(state, event)? {
            return Err(integrity(
                "workspace prefix-segment head map differs from its owner stamp",
            ));
        }
        Ok(())
    }

    /// Reuses the existing frame's decoded manifest/map/event and its single
    /// successor proof. This adds no IO to an ordinary all-None predecessor.
    pub(crate) fn check_prefix_segment_head_predecessor(
        &self,
        state: &WorkspaceState,
        event: &StoredEvent,
        manifest: &Manifest,
    ) -> ServiceResult<()> {
        if (state.prefix_segment_heads.is_some() || event.prefix_segment_heads.is_some())
            && !manifest.features.contains(FEATURE)
        {
            return Err(integrity(
                "workspace predecessor lost its prefix-segment feature",
            ));
        }
        self.check_prefix_segment_head_stamp(state, event)
    }

    fn prefix_segment_head_auth(
        &self,
        state: &WorkspaceState,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        validate_prefix_segment_heads(state)?;
        let roots = state.prefix_segment_heads.as_ref().map_or(0, BTreeMap::len)
            + state.segment_heads.as_ref().map_or(0, BTreeMap::len)
            + state.prefix_bases.as_ref().map_or(0, BTreeMap::len);
        let router_roots = state
            .directory_routers
            .as_ref()
            .map_or(0, |roots| roots.len() + 1);
        let stamps = u64::from(state.prefix_segment_heads.is_some())
            + u64::from(state.segment_heads.is_some())
            + u64::from(state.prefix_bases.is_some());
        parent
            .charge(
                8 + roots as u64 + stamps + 32768 * u64::from(state.directory_routers.is_some()),
                (roots as u64 + stamps + router_roots as u64) * 4096
                    + 8192 * u64::from(state.directory_routers.is_some())
                    + self.database_id.len() as u64 * 12
                    + 4096,
            )
            .map_err(crate::raw_index::budget_error)
    }

    /// Exact latest owner-map admission, including authentic None. Retained
    /// ordinal publication absence is a separate first-appender proof.
    pub(crate) fn current_prefix_segment_heads<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        parent: &mut QueryBudget,
    ) -> ServiceResult<WorkspaceState> {
        parent.check().map_err(crate::raw_index::budget_error)?;
        if workspace_id.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(crate::invalid(
                "prefix-segment heads workspace exceeds its bound",
            ));
        }
        parent
            .charge(1, workspace_id.len() as u64 * 2 + 1024)
            .map_err(crate::raw_index::budget_error)?;
        crate::validate_identifier(workspace_id, "prefix-segment heads workspace")?;
        let workspace = digest_bytes(workspace_id.as_bytes());
        let state = self
            .head_read::<WorkspaceState, _>(
                snapshot,
                &self.keyspaces.workspace,
                workspace.as_bytes(),
                HEAD_BYTES,
                parent,
            )?
            .unwrap_or_else(|| WorkspaceState::genesis(workspace.clone()));
        validate_workspace_state(&state, &workspace)?;
        let manifest = self
            .head_read::<Manifest, _>(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                MANIFEST_BYTES,
                parent,
            )?
            .ok_or_else(|| integrity("prefix-segment heads format manifest absent"))?;
        parent
            .charge(1, 4096)
            .map_err(crate::raw_index::budget_error)?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        let key = workspace_map_key(&workspace, state.watermarks.journal);
        let mapping = self.head_read::<CommitMap, _>(
            snapshot,
            &self.keyspaces.workspace_map,
            &key,
            HEAD_BYTES,
            parent,
        )?;
        if state.watermarks.journal == 0 {
            if mapping.is_some()
                || state.prefix_segment_heads.is_some()
                || state.segment_heads.is_some()
                || state.prefix_bases.is_some()
                || state.directory_routers.is_some()
            {
                return Err(integrity("genesis workspace has committed derived roots"));
            }
        } else {
            let mapping =
                mapping.ok_or_else(|| integrity("current prefix-segment workspace map absent"))?;
            if mapping.schema_version != SCHEMA_VERSION
                || mapping.global_commit != state.latest_global_commit
                || mapping.state != state
            {
                return Err(integrity(
                    "current prefix state differs from its exact committed map",
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
                .ok_or_else(|| integrity("current prefix-segment workspace event absent"))?;
            self.prefix_segment_head_auth(&state, parent)?;
            if event.schema_version != SCHEMA_VERSION
                || event.workspace_digest != workspace
                || event.workspace_commit != state.watermarks.journal
                || event.global_commit != mapping.global_commit
                || event.event_digest != event_digest(&event)?
            {
                return Err(integrity(
                    "current prefix-segment workspace event binding differs",
                ));
            }
            self.check_prefix_segment_head_predecessor(&state, &event, &manifest)?;
            self.check_prefix_base_predecessor(&state, &event, &manifest)?;
            self.check_directory_router_head_predecessor(&state, &event, &manifest)?;
            if (state.segment_heads.is_some() || event.segment_heads.is_some())
                && !manifest
                    .features
                    .contains(super::super::segments::types::FEATURE)
            {
                return Err(integrity("current workspace lost its segment feature"));
            }
            self.check_segment_head_stamp(&state, &event)?;
        }
        let head = crate::budgeted::read_value(
            snapshot,
            &self.keyspaces.meta,
            crate::META_GLOBAL_HEAD_KEY,
            8,
            parent,
        )?;
        let global = head
            .as_deref()
            .map(|bytes| crate::decode_u64(bytes, "prefix-segment heads global head"))
            .transpose()?
            .unwrap_or(0);
        if state.latest_global_commit > global {
            return Err(integrity(
                "prefix-segment workspace head exceeds actual global head",
            ));
        }
        parent
            .charge(1, 512)
            .map_err(crate::raw_index::budget_error)?;
        let mut prefix = workspace.into_bytes();
        prefix.push(b'/');
        let page = crate::budgeted::metadata(snapshot, parent, |meter| {
            meter
                .scan_prefix_page(
                    &self.keyspaces.workspace_map,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: Some(&key),
                        max_entries: 1,
                        max_bytes: HEAD_BYTES + 256,
                    },
                )
                .map_err(storage_error)
        })?;
        if !page.entries.is_empty() || page.continuation.is_some() {
            return Err(integrity(
                "prefix-segment workspace head has a committed successor",
            ));
        }
        Ok(state)
    }

    /// Bounded administrative replay under ONE parent, not a hot corpus scan.
    pub(crate) fn verify_prefix_segment_heads_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.verify_prefix_segment_heads_inner(snapshot, parent, true)
    }

    fn verify_prefix_segment_heads_inner<S: ReadSnapshot>(
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
                    decode(&row.value, "prefix-segment workspace historical map")?;
                if mapping.state.prefix_segment_heads.is_none() {
                    if activated.contains_key(&mapping.state.workspace_digest) {
                        return Err(integrity(
                            "activated prefix-segment workspace map downgraded to None",
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
                        "prefix-segment historical workspace map binding differs",
                    ));
                }
                if let Some((_, before)) = activated.get(&mapping.state.workspace_digest)
                    && (before.watermarks.journal.checked_add(1)
                        != Some(mapping.state.watermarks.journal)
                        || before.latest_global_commit >= mapping.global_commit)
                {
                    return Err(integrity(
                        "activated prefix-segment workspace history has a gap",
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
                    .ok_or_else(|| integrity("prefix-segment historical event absent"))?;
                self.prefix_segment_head_auth(&mapping.state, parent)?;
                if event.event_digest != event_digest(&event)? {
                    return Err(integrity("prefix-segment historical event digest differs"));
                }
                self.check_prefix_segment_head_stamp(&mapping.state, &event)?;
                if transitions {
                    self.check_prefix_segment_head_transition(
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
                let event: StoredEvent = decode(&row.value, "retained prefix-segment head event")?;
                if event.prefix_segment_heads.is_none() {
                    if (transitions && event.operation == OPERATION)
                        || activated
                            .get(&event.workspace_digest)
                            .is_some_and(|(first, _)| event.workspace_commit >= *first)
                    {
                        return Err(integrity(
                            "accepted prefix-segment workspace journal lost its root stamp",
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
                        integrity("prefix-segment stamped event workspace map absent")
                    })?;
                if mapping.schema_version != SCHEMA_VERSION
                    || row.key != event.global_commit.to_be_bytes()
                    || mapping.global_commit != event.global_commit
                    || mapping.state.latest_global_commit != event.global_commit
                    || event.event_digest != event_digest(&event)?
                {
                    return Err(integrity(
                        "prefix-segment stamped event map identity differs",
                    ));
                }
                self.prefix_segment_head_auth(&mapping.state, parent)?;
                self.check_prefix_segment_head_stamp(&mapping.state, &event)?;
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
            .ok_or_else(|| integrity("prefix-segment heads retained format absent"))?;
        parent
            .charge(1, 4096)
            .map_err(crate::raw_index::budget_error)?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        if !manifest.features.contains(FEATURE) {
            return Err(integrity("prefix-segment heads retained feature absent"));
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
                            "current prefix-segment workspace differs from newest accepted map",
                        ));
                    }
                    None if state.prefix_segment_heads.is_some() => {
                        return Err(integrity(
                            "prefix-segment workspace has no accepted stamped map",
                        ));
                    }
                    None => (),
                }
                Ok(())
            },
        )?;
        if current.len() != activated.len() {
            return Err(integrity("activated prefix-segment workspace state absent"));
        }
        Ok(())
    }

    fn check_prefix_segment_head_transition<S: ReadSnapshot>(
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
            .prefix_segment_heads
            .as_ref()
            .ok_or_else(|| integrity("prefix-segment transition map absent"))?;
        let before = before.and_then(|state| state.prefix_segment_heads.as_ref());
        if before.is_none() && event.operation != OPERATION {
            return Err(integrity(
                "prefix-segment map activated without accepted append",
            ));
        }
        let mut expected = before.cloned().unwrap_or_default();
        if event.operation == OPERATION {
            let mut change = None;
            for (generation, reference) in heads {
                if expected.get(generation) != Some(reference) {
                    if change.is_some() {
                        return Err(integrity(
                            "prefix-segment append changes multiple generation heads",
                        ));
                    }
                    change = Some((*generation, reference));
                }
            }
            let (generation, reference) = change
                .ok_or_else(|| integrity("prefix-segment append changed no generation head"))?;
            let old = expected.get(&generation);
            let ordinal = old
                .map_or(Some(1), |head| head.count.checked_add(1))
                .ok_or_else(|| integrity("prefix-segment ordinal overflow"))?;
            if reference.count != ordinal
                || reference.global_commit != event.global_commit
                || reference.request_digest != event.request_digest
                || reference.response_digest != event.response_digest
            {
                return Err(integrity(
                    "prefix-segment head differs from accepted frame position",
                ));
            }
            let publication = self.accepted_prefix_segment_for_ordinal(
                snapshot,
                &current.workspace_digest,
                generation,
                ordinal,
                parent,
            )?;
            let directory = &publication.directory;
            let delta = &publication.delta.manifest;
            let base_root = current
                .prefix_bases
                .as_ref()
                .and_then(|roots| roots.get(&generation))
                .ok_or_else(|| {
                    integrity("prefix-segment append has no current accepted prefix base")
                })?;
            if base_root.global_commit != delta.base.publication.global_commit
                || base_root.request_digest != delta.base.publication.request_digest
                || base_root.response_digest != delta.base.publication.response_digest
                || base_root.receipt_digest != delta.base.receipt_digest
                || base_root.content_digest != delta.base.content_digest
            {
                return Err(integrity(
                    "prefix-segment append differs from its current prefix base root",
                ));
            }
            if self.prefix_segment_directory_reference(snapshot, directory, parent)? != *reference
                || publication.delta.global_commit != event.global_commit
                || directory.global_commit != event.global_commit
                || directory.head.generation != generation
                || directory.head.count != ordinal
                || directory.head.previous.as_ref() != old
                || delta.raw.generation != generation
                || delta.ordinal != ordinal
                || directory.head.base != delta.base
                || directory.head.covered != delta.after
                || directory.head.covered_dense != delta.target_dense
                || directory.head.ending != delta.end
            {
                return Err(integrity(
                    "prefix-segment directory differs from retained accepted append",
                ));
            }
            if let Some(old) = old {
                let predecessor = self.accepted_prefix_segment_for_ordinal(
                    snapshot,
                    &current.workspace_digest,
                    generation,
                    old.count,
                    parent,
                )?;
                let prior = &predecessor.delta.manifest;
                if self.prefix_segment_directory_reference(
                    snapshot,
                    &predecessor.directory,
                    parent,
                )? != *old
                    || prior.base != delta.base
                    || predecessor.directory.head.base != directory.head.base
                    || predecessor.directory.head.covered != delta.before
                    || predecessor.directory.head.covered_dense != delta.before_dense
                    || predecessor.directory.head.ending != delta.start
                    || delta.raw.generation != prior.raw.generation
                    || delta.raw.custody_version != prior.raw.custody_version
                    || delta.raw.analyzer != prior.raw.analyzer
                    || delta.raw.bm25 != prior.raw.bm25
                    || delta.raw.authorization_epoch != prior.raw.authorization_epoch
                    || delta.raw.removal_through != prior.raw.removal_through
                    || delta.raw.through < prior.raw.through
                    || delta.raw.projected_sources < prior.raw.projected_sources
                    || delta.before.profile != prior.after.profile
                    || delta.before.profile_digest != prior.after.profile_digest
                    || delta.before.vector_space_id != prior.after.vector_space_id
                    || old.global_commit >= event.global_commit
                {
                    return Err(integrity(
                        "prefix-segment append changed its base or previous covered boundary",
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
            let generation = self.prefix_segment_completed_gc(snapshot, current, event, parent)?;
            if expected.remove(&generation).is_none() {
                return Err(integrity(
                    "prefix-segment GC removed an unaccepted generation",
                ));
            }
        }
        if heads != &expected {
            return Err(integrity(
                "prefix-segment map differs from accepted append or completed GC",
            ));
        }
        Ok(())
    }

    fn prefix_segment_completed_gc<S: ReadSnapshot>(
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
            .ok_or_else(|| integrity("prefix-segment GC accepted response absent"))?;
        parent
            .charge(1, stored.response_bytes.len() as u64 * 8 + 4096)
            .map_err(crate::raw_index::budget_error)?;
        let progress: crate::RawReclaimProgress =
            decode(&stored.response_bytes, "prefix-segment completed GC")?;
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
                "prefix-segment head removal is not exact accepted complete generation GC",
            ));
        }
        progress
            .generation
            .ok_or_else(|| integrity("prefix-segment GC removed no generation"))
    }
}

fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests;
