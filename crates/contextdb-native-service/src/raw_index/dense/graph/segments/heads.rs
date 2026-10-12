//! Owner certificate for the latest bounded segment directory map.
//!
//! This authenticates stored heads, not append/GC transitions or source access.
//! Publication activation and execution of the acceptance proofs remain gates. Every
//! owner frame checks its bounded predecessor before signing, including replay
//! of preactivation None. Legacy writers retain their existing IO contract.

use super::types::{DirectoryRef, FEATURE, OPERATION, SegmentHeadStamp, WORKSPACE_HEADS_MAC};
use crate::{
    CommitMap, Manifest, NativeService, SCHEMA_VERSION, StoredEvent, WorkspaceState, decode,
    digest_bytes, encode, event_digest, integrity, keyed_token, storage_error,
    validate_workspace_state, workspace_map_key,
};
use contextdb_core::ContentDigest;
use contextdb_recall::QueryBudget;
use contextdb_service::ServiceResult;
use contextdb_storage::{Entry, Keyspace, ReadSnapshot, ScanPageRequest};
use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};

const HEAD_BYTES: usize = 8 * 1024;
const MANIFEST_BYTES: usize = 128 * 1024;
const MAX_HEADS: usize = crate::raw_index::MAX_GENERATIONS as usize;

pub(crate) fn deserialize_heads<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<u64, DirectoryRef>>, D::Error> {
    struct Heads(BTreeMap<u64, DirectoryRef>);
    impl<'de> Deserialize<'de> for Heads {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Bounded;
            impl<'de> Visitor<'de> for Bounded {
                type Value = Heads;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("at most three unique retained segment generation heads")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Heads, A::Error> {
                    let mut heads = BTreeMap::new();
                    while let Some(key) = map.next_key::<u64>()? {
                        if heads.len() == MAX_HEADS || heads.contains_key(&key) {
                            return Err(serde::de::Error::custom(
                                "segment heads bound or duplicate key",
                            ));
                        }
                        heads.insert(key, map.next_value::<DirectoryRef>()?);
                    }
                    Ok(Heads(heads))
                }
            }
            d.deserialize_map(Bounded)
        }
    }
    Option::<Heads>::deserialize(deserializer).map(|heads| heads.map(|h| h.0))
}

pub(crate) fn validate_segment_heads(state: &WorkspaceState) -> ServiceResult<()> {
    let Some(heads) = &state.segment_heads else {
        return Ok(());
    };
    if heads.len() > MAX_HEADS
        || state.watermarks.journal == 0
        || !hex_digest(&state.workspace_digest)
    {
        return Err(integrity(
            "workspace segment heads exceed their retained bound",
        ));
    }
    for (generation, reference) in heads {
        reference.validate()?;
        if *generation == 0 || reference.global_commit > state.latest_global_commit {
            return Err(integrity("workspace segment head identity is invalid"));
        }
    }
    Ok(())
}

impl NativeService {
    pub(crate) fn segment_frame_workspace<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
    ) -> ServiceResult<WorkspaceState> {
        let workspace = digest_bytes(workspace_id.as_bytes());
        let state = self
            .predecessor_row::<WorkspaceState, _>(
                snapshot,
                &self.keyspaces.workspace,
                workspace.as_bytes(),
                HEAD_BYTES,
            )?
            .unwrap_or_else(|| WorkspaceState::genesis(workspace.clone()));
        validate_workspace_state(&state, &workspace)?;
        Ok(state)
    }

    /// Called by EVERY begin_frame on the existing transaction/snapshot. An
    /// enclosing metadata Meter retains its parent; legacy unbudgeted writers
    /// get finite point/one-row reads, not an invented audit budget.
    pub(crate) fn admit_segment_head_predecessor<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        state: &WorkspaceState,
        global_head: u64,
    ) -> ServiceResult<()> {
        if state.latest_global_commit > global_head {
            return Err(integrity(
                "workspace predecessor exceeds the actual global head",
            ));
        }
        let manifest = self
            .predecessor_row::<Manifest, _>(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                MANIFEST_BYTES,
            )?
            .ok_or_else(|| integrity("workspace predecessor format manifest absent"))?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        let activated_format = manifest.features.contains(FEATURE);
        let prefix_format = manifest
            .features
            .contains(super::super::prefix_v2::types::FEATURE);
        if state.segment_heads.is_some() && !activated_format {
            return Err(integrity("workspace predecessor lost its segment feature"));
        }
        if state.prefix_bases.is_some() && !prefix_format {
            return Err(integrity(
                "workspace predecessor lost its prefix-base feature",
            ));
        }
        let key = workspace_map_key(&state.workspace_digest, state.watermarks.journal);
        let mapping = self.predecessor_row::<CommitMap, _>(
            snapshot,
            &self.keyspaces.workspace_map,
            &key,
            HEAD_BYTES,
        )?;
        if state.watermarks.journal == 0 {
            if mapping.is_some() || state.segment_heads.is_some() || state.prefix_bases.is_some() {
                return Err(integrity(
                    "genesis workspace has a committed segment predecessor",
                ));
            }
        } else if let Some(mapping) = mapping {
            if mapping.schema_version != SCHEMA_VERSION
                || mapping.global_commit != state.latest_global_commit
                || mapping.state != *state
            {
                return Err(integrity(
                    "workspace predecessor differs from its exact committed map",
                ));
            }
            let event = self
                .predecessor_row::<StoredEvent, _>(
                    snapshot,
                    &self.keyspaces.events,
                    &mapping.global_commit.to_be_bytes(),
                    crate::MAX_JSON_BYTES,
                )?
                .ok_or_else(|| integrity("workspace predecessor event absent"))?;
            if event.schema_version != SCHEMA_VERSION
                || event.global_commit != mapping.global_commit
                || event.workspace_digest != state.workspace_digest
                || event.workspace_commit != state.watermarks.journal
                || event.event_digest != event_digest(&event)?
                || (event.segment_heads.is_some() && !activated_format)
            {
                return Err(integrity(
                    "workspace predecessor event identity or feature differs",
                ));
            }
            self.check_segment_head_stamp(state, &event)?;
            self.check_prefix_base_predecessor(state, &event, &manifest)?;
        } else {
            if activated_format
                || prefix_format
                || state.segment_heads.is_some()
                || state.prefix_bases.is_some()
            {
                return Err(integrity("activated workspace predecessor map absent"));
            }
            // Only the inherited missing-map exception needs this additional
            // point read. A surviving stamp/declaration cannot become legacy
            // None merely by deleting its map and stripping the format flag.
            if let Some(event) = self.predecessor_row::<StoredEvent, _>(
                snapshot,
                &self.keyspaces.events,
                &state.latest_global_commit.to_be_bytes(),
                crate::MAX_JSON_BYTES,
            )? && (event.prefix_bases.is_some()
                || event.segment_heads.is_some()
                || event.operation == super::super::prefix_v2::types::OPERATION
                || event.operation == OPERATION)
            {
                return Err(integrity(
                    "stamped workspace predecessor lost its committed map",
                ));
            }
        }
        // Legacy historical mappings may expire. A missing None map is still
        // permitted when the new format is absent; a successor never is. This
        // also rejects rollback to authentic None, even with a stripped feature.
        let mut prefix = state.workspace_digest.as_bytes().to_vec();
        prefix.push(b'/');
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.workspace_map,
                ScanPageRequest {
                    prefix: &prefix,
                    start_after: Some(&key),
                    max_entries: 1,
                    max_bytes: HEAD_BYTES + 256,
                },
            )
            .map_err(storage_error)?;
        if !page.entries.is_empty() || page.continuation.is_some() {
            return Err(integrity("workspace predecessor has a committed successor"));
        }
        Ok(())
    }

    fn predecessor_row<T: DeserializeOwned + serde::Serialize, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        space: &Keyspace,
        key: &[u8],
        cap: usize,
    ) -> ServiceResult<Option<T>> {
        let page = snapshot
            .scan_prefix_page(
                space,
                ScanPageRequest {
                    prefix: key,
                    start_after: None,
                    max_entries: 1,
                    max_bytes: cap.saturating_add(key.len()).saturating_add(256),
                },
            )
            .map_err(storage_error)?;
        let Some(row) = page.entries.into_iter().next().filter(|r| r.key == key) else {
            return Ok(None);
        };
        if row.value.len() > cap {
            return Err(integrity(
                "workspace predecessor row exceeds its declared bound",
            ));
        }
        let value: T = decode(&row.value, "bounded workspace predecessor")?;
        if encode(&value)? != row.value {
            return Err(integrity("workspace predecessor is not canonical"));
        }
        Ok(Some(value))
    }

    /// None preserves the exact old event encoding. Some(empty) is an activated,
    /// authenticated state and must keep propagating through ordinary writes.
    pub(crate) fn segment_head_stamp(
        &self,
        state: &WorkspaceState,
        event: &StoredEvent,
    ) -> ServiceResult<Option<SegmentHeadStamp>> {
        let Some(heads) = &state.segment_heads else {
            return Ok(None);
        };
        validate_workspace_state(state, &event.workspace_digest)?;
        if event.schema_version != SCHEMA_VERSION
            || event.global_commit != state.latest_global_commit
            || event.workspace_commit != state.watermarks.journal
            || event.global_commit == 0
            || event.operation.trim().is_empty()
            || event.operation.len() > crate::MAX_IDENTIFIER_BYTES
            || !hex_digest(&event.request_digest)
            || !hex_digest(&event.response_digest)
            || (event.global_commit == 1) != event.previous_event_digest.is_none()
            || event
                .previous_event_digest
                .as_ref()
                .is_some_and(|s| !hex_digest(s))
        {
            return Err(integrity(
                "workspace segment stamp frame binding is invalid",
            ));
        }
        let map_digest = ContentDigest::from_bytes(*blake3::hash(&encode(heads)?).as_bytes());
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
            ))?,
        );
        Ok(Some(SegmentHeadStamp {
            revision: 1,
            map_digest,
            token,
        }))
    }

    pub(crate) fn check_segment_head_stamp(
        &self,
        state: &WorkspaceState,
        event: &StoredEvent,
    ) -> ServiceResult<()> {
        if let Some(stamp) = &event.segment_heads {
            stamp.validate()?;
        }
        if event.segment_heads != self.segment_head_stamp(state, event)? {
            return Err(integrity(
                "workspace segment head map differs from its owner stamp",
            ));
        }
        Ok(())
    }

    /// Point-only admission of the current accepted workspace head. Source
    /// policy and accepted append/GC transition checks are not granted by this.
    pub(crate) fn current_segment_heads<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace_id: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<WorkspaceState> {
        budget.check().map_err(crate::raw_index::budget_error)?;
        if workspace_id.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(crate::invalid("segment heads workspace exceeds its bound"));
        }
        budget
            .charge(1, workspace_id.len() as u64 * 2 + 1024)
            .map_err(crate::raw_index::budget_error)?;
        crate::validate_identifier(workspace_id, "segment heads workspace")?;
        let workspace = digest_bytes(workspace_id.as_bytes());
        let state = self
            .head_read::<WorkspaceState, _>(
                snapshot,
                &self.keyspaces.workspace,
                workspace.as_bytes(),
                HEAD_BYTES,
                budget,
            )?
            .unwrap_or_else(|| WorkspaceState::genesis(workspace.clone()));
        validate_workspace_state(&state, &workspace)?;
        // Historical legacy maps may expire. Do not alter None admission.
        if state.segment_heads.is_none() {
            return Ok(state);
        }
        self.require_segment_heads_feature(snapshot, budget)?;
        budget
            .charge(1, 1024)
            .map_err(crate::raw_index::budget_error)?;
        let key = workspace_map_key(&workspace, state.watermarks.journal);
        let mapping = self
            .head_read::<CommitMap, _>(
                snapshot,
                &self.keyspaces.workspace_map,
                &key,
                HEAD_BYTES,
                budget,
            )?
            .ok_or_else(|| integrity("current segment workspace map absent"))?;
        if mapping.schema_version != SCHEMA_VERSION
            || mapping.global_commit != state.latest_global_commit
            || mapping.state != state
        {
            return Err(integrity(
                "current segment workspace state differs from its exact map",
            ));
        }
        let event = self
            .head_read::<StoredEvent, _>(
                snapshot,
                &self.keyspaces.events,
                &mapping.global_commit.to_be_bytes(),
                crate::MAX_JSON_BYTES,
                budget,
            )?
            .ok_or_else(|| integrity("current segment head journal event absent"))?;
        self.admit_segment_head_auth(&state, budget)?;
        if event.workspace_digest != workspace
            || event.workspace_commit != state.watermarks.journal
            || event.global_commit != mapping.global_commit
            || event.event_digest != event_digest(&event)?
        {
            return Err(integrity(
                "current segment workspace map event binding differs",
            ));
        }
        self.check_segment_head_stamp(&state, &event)?;
        let head = crate::budgeted::read_value(
            snapshot,
            &self.keyspaces.meta,
            crate::META_GLOBAL_HEAD_KEY,
            8,
            budget,
        )?
        .ok_or_else(|| integrity("segment heads global head absent"))?;
        if mapping.global_commit > crate::decode_u64(&head, "segment heads global head")? {
            return Err(integrity("segment workspace head exceeds global head"));
        }
        // Any later mapping, even after a deleted intermediate map, defeats a
        // replayed old legitimate workspace row. No history scan is performed.
        budget
            .charge(1, 512)
            .map_err(crate::raw_index::budget_error)?;
        let mut prefix = workspace.into_bytes();
        prefix.push(b'/');
        let page = crate::budgeted::metadata(snapshot, budget, |meter| {
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
                "segment workspace head has a committed successor",
            ));
        }
        Ok(state)
    }

    pub(crate) fn head_read<T: DeserializeOwned + serde::Serialize, S: ReadSnapshot>(
        &self,
        snapshot: &S,
        space: &Keyspace,
        key: &[u8],
        cap: usize,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Option<T>> {
        let Some(bytes) = crate::budgeted::read_value(snapshot, space, key, cap, budget)? else {
            return Ok(None);
        };
        // This covers typed decoding/re-encoding and subsequent event digest
        // clone/serialization. The actual admitted byte length is known here,
        // before decoding or any event clone, without another sizing encode.
        budget
            .charge(1, bytes.len() as u64 * 12 + 256)
            .map_err(crate::raw_index::budget_error)?;
        let value: T = decode(&bytes, "bounded segment heads metadata")?;
        if encode(&value)? != bytes {
            return Err(integrity("segment heads metadata is not canonical"));
        }
        Ok(Some(value))
    }

    fn admit_segment_head_auth(
        &self,
        state: &WorkspaceState,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        validate_segment_heads(state)?;
        // Event digest cloning was prepaid from actual row bytes in head_read.
        // Map serialization and the keyed tuple have separate small envelopes.
        budget
            .charge(
                8 + state.segment_heads.as_ref().map_or(0, |m| m.len() as u64),
                state
                    .segment_heads
                    .as_ref()
                    .map_or(0, |m| m.len() as u64 * 4096)
                    + self.database_id.len() as u64 * 12
                    + 4096,
            )
            .map_err(crate::raw_index::budget_error)?;
        Ok(())
    }

    fn require_segment_heads_feature<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let manifest = self
            .head_read::<Manifest, _>(
                snapshot,
                &self.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                MANIFEST_BYTES,
                budget,
            )?
            .ok_or_else(|| integrity("segment heads format manifest absent"))?;
        budget
            .charge(1, 4096)
            .map_err(crate::raw_index::budget_error)?;
        crate::validate_manifest(&manifest, &self.database_id)?;
        if !manifest.features.contains(FEATURE) {
            return Err(integrity("segment heads retained format feature absent"));
        }
        Ok(())
    }

    /// Offline deep verification. None-only histories keep their prior behavior;
    /// from the first Some map onward, every snapshot must remain stamped and
    /// the live workspace must equal its newest map. Accepted append/GC replay
    /// is joined to exact segment publications or completed generation GC.
    pub(crate) fn verify_segment_heads_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.verify_segment_heads_inner(snapshot, budget, true)
    }

    #[cfg(test)]
    fn verify_segment_head_certificates<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        // Certificate fixtures deliberately have no accepted delta receipts.
        // Production verification can never select this primitive-only path.
        self.verify_segment_heads_inner(snapshot, budget, false)
    }

    fn verify_segment_heads_inner<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
        transitions: bool,
    ) -> ServiceResult<()> {
        let mut activated = BTreeMap::<String, (u64, WorkspaceState)>::new();
        self.head_walk(
            snapshot,
            &self.keyspaces.workspace_map,
            HEAD_BYTES,
            budget,
            |row, budget| {
                let mapping: CommitMap = decode(&row.value, "segment workspace historical map")?;
                if mapping.state.segment_heads.is_none() {
                    if activated.contains_key(&mapping.state.workspace_digest) {
                        return Err(integrity(
                            "activated segment workspace map downgraded to None",
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
                {
                    return Err(integrity(
                        "segment historical workspace map binding invalid",
                    ));
                }
                if let Some((_, previous)) = activated.get(&mapping.state.workspace_digest)
                    && (previous.watermarks.journal.checked_add(1)
                        != Some(mapping.state.watermarks.journal)
                        || previous.latest_global_commit >= mapping.global_commit)
                {
                    return Err(integrity(
                        "activated segment workspace map history has a gap",
                    ));
                }
                let event = self
                    .head_read::<StoredEvent, _>(
                        snapshot,
                        &self.keyspaces.events,
                        &mapping.global_commit.to_be_bytes(),
                        crate::MAX_JSON_BYTES,
                        budget,
                    )?
                    .ok_or_else(|| integrity("segment historical event absent"))?;
                self.admit_segment_head_auth(&mapping.state, budget)?;
                if event.event_digest != event_digest(&event)? {
                    return Err(integrity("segment historical event digest differs"));
                }
                self.check_segment_head_stamp(&mapping.state, &event)?;
                if transitions {
                    self.check_segment_head_transition(
                        snapshot,
                        activated
                            .get(&mapping.state.workspace_digest)
                            .map(|(_, state)| state),
                        &mapping.state,
                        &event,
                        budget,
                    )?;
                }
                let first = activated
                    .get(&mapping.state.workspace_digest)
                    .map_or(mapping.state.watermarks.journal, |(first, _)| *first);
                budget
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
        // A stamp cannot survive without its exact map, even if all current
        // segment pointers were stripped. This is administrative history work.
        self.head_walk(
            snapshot,
            &self.keyspaces.events,
            crate::MAX_JSON_BYTES,
            budget,
            |row, budget| {
                let event: StoredEvent = decode(&row.value, "retained segment head event")?;
                if event.segment_heads.is_none() {
                    if transitions && event.operation == OPERATION {
                        return Err(integrity(
                            "accepted segment append lost its stamped workspace map",
                        ));
                    }
                    if activated
                        .get(&event.workspace_digest)
                        .is_some_and(|(first, _)| event.workspace_commit >= *first)
                    {
                        return Err(integrity("activated workspace journal lost its head stamp"));
                    }
                    return Ok(());
                }
                budget
                    .charge(1, 1024)
                    .map_err(crate::raw_index::budget_error)?;
                let mapping = self
                    .head_read::<CommitMap, _>(
                        snapshot,
                        &self.keyspaces.workspace_map,
                        &workspace_map_key(&event.workspace_digest, event.workspace_commit),
                        HEAD_BYTES,
                        budget,
                    )?
                    .ok_or_else(|| integrity("stamped event workspace map absent"))?;
                if mapping.schema_version != SCHEMA_VERSION
                    || row.key != event.global_commit.to_be_bytes()
                    || mapping.global_commit != event.global_commit
                    || mapping.state.latest_global_commit != event.global_commit
                {
                    return Err(integrity("stamped event workspace map commit differs"));
                }
                if event.event_digest != event_digest(&event)? {
                    return Err(integrity("stamped event digest differs"));
                }
                self.admit_segment_head_auth(&mapping.state, budget)?;
                self.check_segment_head_stamp(&mapping.state, &event)?;
                Ok(())
            },
        )?;
        if activated.is_empty() {
            return Ok(());
        }
        self.require_segment_heads_feature(snapshot, budget)?;
        let mut current = BTreeSet::new();
        self.head_walk(
            snapshot,
            &self.keyspaces.workspace,
            HEAD_BYTES,
            budget,
            |row, budget| {
                let state: WorkspaceState = decode(&row.value, "segment current workspace state")?;
                match activated.get(&state.workspace_digest) {
                    Some((_, latest))
                        if state == *latest && row.key == state.workspace_digest.as_bytes() =>
                    {
                        budget
                            .charge(1, state.workspace_digest.len() as u64 * 2 + 256)
                            .map_err(crate::raw_index::budget_error)?;
                        current.insert(state.workspace_digest);
                    }
                    Some(_) => {
                        return Err(integrity(
                            "current segment workspace differs from newest accepted map",
                        ));
                    }
                    None if state.segment_heads.is_some() => {
                        return Err(integrity("segment workspace has no accepted stamped map"));
                    }
                    None => (),
                }
                Ok(())
            },
        )?;
        if current.len() != activated.len() {
            return Err(integrity(
                "activated segment workspace current state absent",
            ));
        }
        Ok(())
    }

    fn check_segment_head_transition<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        previous: Option<&WorkspaceState>,
        current: &WorkspaceState,
        event: &StoredEvent,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        budget
            .charge(8, HEAD_BYTES as u64 * 4)
            .map_err(crate::raw_index::budget_error)?;
        let heads = current
            .segment_heads
            .as_ref()
            .ok_or_else(|| integrity("segment transition has no current map"))?;
        let before = previous.and_then(|state| state.segment_heads.as_ref());
        if before.is_none() && event.operation != OPERATION {
            return Err(integrity(
                "workspace heads activated without accepted segment append",
            ));
        }
        let mut expected = before.cloned().unwrap_or_default();
        if event.operation == OPERATION {
            let mut change = None;
            for (generation, reference) in heads {
                if expected.get(generation) != Some(reference) {
                    if change.is_some() {
                        return Err(integrity(
                            "segment append changes multiple generation heads",
                        ));
                    }
                    change = Some((*generation, reference));
                }
            }
            let (generation, reference) = change
                .ok_or_else(|| integrity("accepted segment append changed no generation head"))?;
            let old = expected.get(&generation);
            let ordinal = old
                .map_or(Some(1), |head| head.count.checked_add(1))
                .ok_or_else(|| integrity("segment head ordinal overflow"))?;
            if reference.count != ordinal
                || reference.global_commit != event.global_commit
                || reference.request_digest != event.request_digest
                || reference.response_digest != event.response_digest
            {
                return Err(integrity(
                    "segment head transition differs from exact accepted frame",
                ));
            }
            let publication = self.accepted_segment_for_ordinal(
                snapshot,
                &current.workspace_digest,
                generation,
                ordinal,
                budget,
            )?;
            let directory = &publication.directory;
            let delta = &publication.delta.manifest;
            if publication.delta.global_commit != event.global_commit
                || directory.global_commit != event.global_commit
                || directory.head.generation != generation
                || directory.head.count != ordinal
                || directory.head.content_digest != reference.content_digest
                || directory.head.previous.as_ref() != old
                || delta.binding.generation != generation
                || delta.ordinal != ordinal
            {
                return Err(integrity(
                    "segment directory transition differs from retained acceptance",
                ));
            }
            if let Some(old) = old {
                let predecessor = self.accepted_segment_for_ordinal(
                    snapshot,
                    &current.workspace_digest,
                    generation,
                    old.count,
                    budget,
                )?;
                let prior = &predecessor.delta.manifest;
                let binding = &delta.binding;
                let prior_binding = &prior.binding;
                if predecessor.directory.global_commit != old.global_commit
                    || predecessor.directory.head.content_digest != old.content_digest
                    || prior.base != delta.base
                    || predecessor.directory.head.base != directory.head.base
                    || predecessor.directory.head.covered != delta.before
                    || binding.generation != prior_binding.generation
                    || binding.custody_version != prior_binding.custody_version
                    || binding.analyzer != prior_binding.analyzer
                    || binding.bm25 != prior_binding.bm25
                    || binding.authorization_epoch != prior_binding.authorization_epoch
                    || binding.removal_through != prior_binding.removal_through
                    || binding.raw_through < prior_binding.raw_through
                    || binding.raw_sources < prior_binding.raw_sources
                    || delta.before.profile != prior.after.profile
                    || delta.before.profile_digest != prior.after.profile_digest
                    || delta.before.vector_space_id != prior.after.vector_space_id
                    || old.global_commit >= event.global_commit
                {
                    return Err(integrity(
                        "segment append changed its immutable base or previous covered prefix",
                    ));
                }
                // The old reference's request/response identity must name the
                // same accepted event as its immutable predecessor publication.
                let accepted = self
                    .head_read::<StoredEvent, _>(
                        snapshot,
                        &self.keyspaces.events,
                        &old.global_commit.to_be_bytes(),
                        crate::MAX_JSON_BYTES,
                        budget,
                    )?
                    .ok_or_else(|| integrity("segment predecessor accepted event absent"))?;
                if accepted.request_digest != old.request_digest
                    || accepted.response_digest != old.response_digest
                {
                    return Err(integrity(
                        "segment old head request/response differs from accepted predecessor",
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
            let stored = self
                .head_read::<crate::StoredIdempotency, _>(
                    snapshot,
                    &self.keyspaces.idempotency,
                    event.request_digest.as_bytes(),
                    MANIFEST_BYTES,
                    budget,
                )?
                .ok_or_else(|| integrity("segment head GC accepted response absent"))?;
            budget
                .charge(1, stored.response_bytes.len() as u64 * 8 + 4096)
                .map_err(crate::raw_index::budget_error)?;
            let progress: crate::RawReclaimProgress =
                decode(&stored.response_bytes, "segment head completed GC")?;
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
                || (event.operation == "raw_reclamation"
                    && event.accepted_raw_reclamation.is_some())
            {
                return Err(integrity(
                    "segment map removal is not exact accepted complete generation GC",
                ));
            }
            let generation = progress
                .generation
                .ok_or_else(|| integrity("segment head GC removed no generation"))?;
            if expected.remove(&generation).is_none() {
                return Err(integrity(
                    "segment head GC removed an unaccepted generation",
                ));
            }
        }
        if heads != &expected {
            return Err(integrity(
                "workspace segment map transition differs from accepted append or completed GC",
            ));
        }
        Ok(())
    }

    pub(crate) fn head_walk<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        space: &Keyspace,
        row_cap: usize,
        budget: &mut QueryBudget,
        mut visit: impl FnMut(Entry, &mut QueryBudget) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        let mut after = None;
        loop {
            let page = crate::budgeted::metadata(snapshot, budget, |meter| {
                meter
                    .scan_prefix_page(
                        space,
                        ScanPageRequest {
                            prefix: b"",
                            start_after: after.as_deref(),
                            max_entries: 32,
                            max_bytes: row_cap.saturating_add(4096),
                        },
                    )
                    .map_err(storage_error)
            })?;
            for row in page.entries {
                if row.value.len() > row_cap {
                    return Err(integrity("segment history row exceeds its declared bound"));
                }
                // Before typed decoding, event clone/digest serialization, or
                // retaining map identities; no fresh per-page/row budget.
                budget
                    .charge(1, row.value.len() as u64 * 12 + row.key.len() as u64 + 1024)
                    .map_err(crate::raw_index::budget_error)?;
                visit(row, budget)?;
            }
            let Some(next) = page.continuation else { break };
            if after
                .as_ref()
                .is_some_and(|previous: &Vec<u8>| next <= *previous)
            {
                return Err(integrity("segment history page made no progress"));
            }
            after = Some(next);
        }
        Ok(())
    }
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests;
