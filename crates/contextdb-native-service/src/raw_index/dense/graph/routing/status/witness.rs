//! Complete bounded control IO; buffers come from the concrete admitted snapshot.

use super::*;
use crate::encryption::NativeSnapshot;
use contextdb_storage::{
    Entry, Keyspace, ScanPage, ScanPageRequest, StorageError, StorageSequence,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    mem::size_of,
};

const MAX_CALLS: usize = 128;
const MAX_PAGES: usize = 64;
const KEY_BYTES: usize = 128;
const MAX_WITNESS_BYTES: usize = MAX_PAGES * 2 * (crate::MAX_JSON_BYTES + KEY_BYTES + 256);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Space {
    Meta,
    Workspace,
    Mapping,
    Events,
    Idempotency,
    Continuous,
}

#[derive(Clone, Copy)]
struct Descriptor {
    space: Space,
    prefix: [u8; KEY_BYTES],
    prefix_len: usize,
    start: [u8; KEY_BYTES],
    start_len: Option<usize>,
    max_bytes: usize,
    current_world: bool,
}
impl Descriptor {
    fn prefix(&self) -> &[u8] {
        &self.prefix[..self.prefix_len]
    }
    fn start(&self) -> Option<&[u8]> {
        self.start_len.map(|n| &self.start[..n])
    }
    fn request(&self) -> ScanPageRequest<'_> {
        ScanPageRequest {
            prefix: self.prefix(),
            start_after: self.start(),
            max_entries: 1,
            max_bytes: self.max_bytes,
        }
    }
    fn same_selector(&self, other: &Self) -> bool {
        self.space == other.space
            && self.prefix() == other.prefix()
            && self.start() == other.start()
            && self.current_world == other.current_world
    }
    fn key(&self, parent: &mut QueryBudget) -> ServiceResult<[u8; 32]> {
        parent
            .charge(
                (self.prefix_len + self.start_len.unwrap_or(0) + 64) as u64,
                256,
            )
            .map_err(budget_error)?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"contextdb/native-status-read-selector/v2\0");
        hash.update(&[self.space as u8, u8::from(self.current_world)]);
        hash.update(&(self.prefix_len as u64).to_be_bytes());
        hash.update(self.prefix());
        hash.update(&[u8::from(self.start_len.is_some())]);
        hash.update(&(self.start_len.unwrap_or(0) as u64).to_be_bytes());
        if let Some(start) = self.start() {
            hash.update(start);
        }
        Ok(*hash.finalize().as_bytes())
    }
}

pub(super) struct Recorder<'a> {
    owner: &'a NativeService,
    snapshot: &'a NativeSnapshot,
    workspace: &'a str,
    continuous: [Vec<u8>; 3],
    locators: [Vec<u8>; 3],
    calls: RefCell<Vec<Descriptor>>,
    failed: Cell<bool>,
}
impl<'a> Recorder<'a> {
    pub(super) fn new(
        owner: &'a NativeService,
        snapshot: &'a NativeSnapshot,
        workspace: &'a str,
        generation: &Generation,
        parent: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        // Fixed descriptor storage and worst-case bounded zero/copy/classifier
        // work are paid before a nested read can record its short-lived keys.
        parent
            .charge(
                (MAX_CALLS * (8 * KEY_BYTES + 64)) as u64,
                (MAX_CALLS * size_of::<Descriptor>() + 12 * KEY_BYTES + 4096) as u64,
            )
            .map_err(budget_error)?;
        let n = generation.number;
        let continuous = [
            prefix_types::receipt_key(workspace, n)?,
            interval_types::directory_head_key(workspace, n)?,
            head_key(workspace, n)?,
        ];
        let locators = [
            prefix_types::retained_locator_key(workspace, n)?,
            interval_types::retained_locator_key(
                workspace,
                n,
                generation
                    .dense_prefix_segments
                    .as_ref()
                    .map_or(1, |r| r.count),
            )?,
            retained_locator_key(
                workspace,
                n,
                generation
                    .dense_directory_router
                    .as_ref()
                    .map_or(1, |r| r.serial),
            )?,
        ];
        if continuous
            .iter()
            .chain(locators.iter())
            .any(|key| key.len() > KEY_BYTES)
        {
            return Err(exhausted(
                "routed status control key exceeds its witness bound",
            ));
        }
        Ok(Self {
            owner,
            snapshot,
            workspace,
            continuous,
            locators,
            calls: RefCell::new(Vec::with_capacity(MAX_CALLS)),
            failed: Cell::new(false),
        })
    }

    fn space(&self, space: &Keyspace) -> Option<Space> {
        // Nested point helpers borrow the actual owner's keyspace fields.
        [
            (&self.owner.keyspaces.meta, Space::Meta),
            (&self.owner.keyspaces.workspace, Space::Workspace),
            (&self.owner.keyspaces.workspace_map, Space::Mapping),
            (&self.owner.keyspaces.events, Space::Events),
            (&self.owner.keyspaces.idempotency, Space::Idempotency),
            (&self.owner.keyspaces.continuous, Space::Continuous),
        ]
        .into_iter()
        .find_map(|(actual, tag)| std::ptr::eq(actual, space).then_some(tag))
    }

    fn control(&self, space: Space, key: &[u8]) -> bool {
        match space {
            Space::Meta => key == crate::META_MANIFEST_KEY,
            Space::Workspace => key == self.workspace.as_bytes(),
            Space::Mapping => {
                key.len() == self.workspace.len() + 9
                    && key.starts_with(self.workspace.as_bytes())
                    && key[self.workspace.len()] == b'/'
            }
            Space::Events => key.len() == 8,
            Space::Idempotency => {
                (key.len() == 64
                    && key
                        .iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)))
                    || self
                        .locators
                        .iter()
                        .any(|expected| expected.len() == key.len() && expected == key)
            }
            Space::Continuous => {
                (key.len() == 44 && key.starts_with(b"receipt/"))
                    || (key.len() == 82 && key.starts_with(b"position/"))
                    || self
                        .continuous
                        .iter()
                        .any(|expected| expected.len() == key.len() && expected == key)
            }
        }
    }

    fn refuse(&self) -> StorageError {
        self.failed.set(true);
        StorageError::Unsupported {
            backend: "native-status-witness",
            operation: "unrecorded or oversized control read",
        }
    }

    pub(super) fn result<T>(&self, result: ServiceResult<T>) -> ServiceResult<T> {
        if self.failed.get() {
            return Err(exhausted(
                "routed status read witness is incomplete or exceeds its bound",
            ));
        }
        result
    }

    pub(super) fn materialize(self, parent: &mut QueryBudget) -> ServiceResult<ControlReadWitness> {
        if self.failed.get() {
            return Err(exhausted("routed status read witness is incomplete"));
        }
        parent
            .charge(1, (MAX_PAGES * size_of::<WitnessPage>() + 4096) as u64)
            .map_err(budget_error)?;
        let mut pages: Vec<WitnessPage> = Vec::with_capacity(MAX_PAGES);
        let mut indices = BTreeMap::<[u8; 32], usize>::new();
        let mut bytes = 0_usize;
        for descriptor in self.calls.into_inner() {
            let key = descriptor.key(parent)?;
            if let Some(&index) = indices.get(&key) {
                let previous = &mut pages[index];
                parent
                    .charge(
                        (descriptor.prefix_len
                            + previous.descriptor.prefix_len
                            + descriptor.start_len.unwrap_or(0)
                            + previous.descriptor.start_len.unwrap_or(0)
                            + 64) as u64,
                        0,
                    )
                    .map_err(budget_error)?;
                if !descriptor.same_selector(&previous.descriptor) {
                    return Err(integrity("routed status read selector collision"));
                }
                // Successful one-entry pages on this immutable snapshot have
                // identical results; retain the tightest original byte cap.
                previous.descriptor.max_bytes =
                    previous.descriptor.max_bytes.min(descriptor.max_bytes);
                continue;
            }
            if pages.len() == MAX_PAGES {
                return Err(exhausted("routed status witness exceeds 64 control pages"));
            }
            parent.charge(1, 1024).map_err(budget_error)?;
            let page = read_page(self.owner, self.snapshot, &descriptor, parent)?;
            bytes = bytes
                .checked_add(page_bytes(&page)?)
                .filter(|n| *n <= MAX_WITNESS_BYTES)
                .ok_or_else(|| exhausted("routed status witness bytes exceed their bound"))?;
            indices.insert(key, pages.len());
            pages.push(WitnessPage { descriptor, page });
        }
        parent.check().map_err(budget_error)?;
        Ok(ControlReadWitness { pages })
    }
}

impl ReadSnapshot for Recorder<'_> {
    fn sequence(&self) -> StorageSequence {
        self.snapshot.sequence()
    }
    fn get(&self, _: &Keyspace, _: &[u8]) -> contextdb_storage::Result<Option<Vec<u8>>> {
        Err(self.refuse())
    }
    fn scan_prefix(&self, _: &Keyspace, _: &[u8]) -> contextdb_storage::Result<Vec<Entry>> {
        Err(self.refuse())
    }
    fn scan_prefix_page(
        &self,
        space: &Keyspace,
        request: ScanPageRequest<'_>,
    ) -> contextdb_storage::Result<ScanPage> {
        let Some(tag) = self.space(space) else {
            return Err(self.refuse());
        };
        if request.max_entries != 1
            || request.prefix.len() > KEY_BYTES
            || request.start_after.is_some_and(|key| key.len() > KEY_BYTES)
            || !self.control(tag, request.prefix)
        {
            return Err(self.refuse());
        }
        request.validate()?;
        let mut calls = self.calls.try_borrow_mut().map_err(|_| self.refuse())?;
        if calls.len() == MAX_CALLS {
            return Err(self.refuse());
        }
        let mut descriptor = Descriptor {
            space: tag,
            prefix: [0; KEY_BYTES],
            prefix_len: request.prefix.len(),
            start: [0; KEY_BYTES],
            start_len: request.start_after.map(<[u8]>::len),
            max_bytes: request.max_bytes,
            current_world: tag == Space::Workspace,
        };
        descriptor.prefix[..request.prefix.len()].copy_from_slice(request.prefix);
        if let Some(start) = request.start_after {
            descriptor.start[..start.len()].copy_from_slice(start);
        }
        calls.push(descriptor);
        drop(calls);
        self.snapshot.scan_prefix_page(space, request)
    }
}

struct WitnessPage {
    descriptor: Descriptor,
    page: ScanPage,
}
pub(super) struct ControlReadWitness {
    pages: Vec<WitnessPage>,
}

impl ControlReadWitness {
    pub(super) fn check(
        &self,
        owner: &NativeService,
        snapshot: &NativeSnapshot,
        current_world: &[u8],
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        for witness in &self.pages {
            let current = read_page(owner, snapshot, &witness.descriptor, parent)?;
            let work = page_bytes(&current)?
                .checked_add(page_bytes(&witness.page)?)
                .and_then(|n| {
                    n.checked_add(
                        current_world.len() * usize::from(witness.descriptor.current_world) + 64,
                    )
                })
                .ok_or_else(|| exhausted("routed status witness comparison overflow"))?;
            parent.charge(work as u64, 0).map_err(budget_error)?;
            let equal = if witness.descriptor.current_world {
                current.entries.len() == 1
                    && witness.page.entries.len() == 1
                    && current.entries[0].key == witness.page.entries[0].key
                    && current.entries[0].key == witness.descriptor.prefix()
                    && current.entries[0].value == current_world
                    && current.continuation == witness.page.continuation
            } else {
                current == witness.page
            };
            if !equal {
                return Err(stale_index());
            }
        }
        parent.check().map_err(budget_error)
    }
}

fn page_bytes(page: &ScanPage) -> ServiceResult<usize> {
    let mut bytes = page.continuation.as_ref().map_or(0, Vec::len);
    for entry in &page.entries {
        bytes = bytes
            .checked_add(entry.key.len())
            .and_then(|n| n.checked_add(entry.value.len()))
            .ok_or_else(|| exhausted("routed status control page size overflow"))?;
    }
    Ok(bytes)
}

fn read_page(
    owner: &NativeService,
    snapshot: &NativeSnapshot,
    descriptor: &Descriptor,
    parent: &mut QueryBudget,
) -> ServiceResult<ScanPage> {
    parent
        .charge(1, (size_of::<ScanPage>() + KEY_BYTES + 256) as u64)
        .map_err(budget_error)?;
    let space = match descriptor.space {
        Space::Meta => &owner.keyspaces.meta,
        Space::Workspace => &owner.keyspaces.workspace,
        Space::Mapping => &owner.keyspaces.workspace_map,
        Space::Events => &owner.keyspaces.events,
        Space::Idempotency => &owner.keyspaces.idempotency,
        Space::Continuous => &owner.keyspaces.continuous,
    };
    let page = crate::budgeted::metadata(snapshot, parent, |reader| {
        reader
            .scan_prefix_page(space, descriptor.request())
            .map_err(storage_error)
    })?;
    if page.entries.len() > 1
        || page.entries.iter().any(|entry| {
            !entry.key.starts_with(descriptor.prefix())
                || descriptor
                    .start()
                    .is_some_and(|after| entry.key.as_slice() <= after)
        })
    {
        return Err(integrity(
            "routed status control page differs from its selector",
        ));
    }
    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_index::dense::graph::prefix_v2::inputs::tests::{
        budget, fixture, read_generation,
    };
    use contextdb_service::ErrorCode;
    use contextdb_storage::{Durability, WriteTransaction};
    use std::time::Duration;

    #[test]
    fn incomplete_or_overflowing_control_reads_cannot_materialize_a_witness() {
        let f = fixture();
        let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
        let generation = read_generation(&f.native, &f.context, &mut budget());
        let snapshot = f
            .native
            .engine
            .begin_read(SnapshotSelector::Latest)
            .expect("concrete native snapshot");
        let mut tiny = QueryBudget::new(1, 1, Duration::from_secs(30), Default::default());
        assert!(
            matches!(Recorder::new(&f.native, &snapshot, &workspace, &generation, &mut tiny),
            Err(error) if error.code == ErrorCode::BudgetExhausted)
        );

        for mode in 0..3 {
            let mut parent = budget();
            let recorder =
                Recorder::new(&f.native, &snapshot, &workspace, &generation, &mut parent)
                    .expect("prepaid control scratch");
            let outcome = match mode {
                0 => recorder
                    .get(&f.native.keyspaces.meta, crate::META_MANIFEST_KEY)
                    .map(|_| ()),
                1 => recorder
                    .scan_prefix_page(
                        &f.native.keyspaces.continuous,
                        ScanPageRequest {
                            prefix: b"payload/chunk/never-a-control",
                            start_after: None,
                            max_entries: 1,
                            max_bytes: 1024,
                        },
                    )
                    .map(|_| ()),
                _ => recorder
                    .scan_prefix_page(
                        &f.native.keyspaces.meta,
                        ScanPageRequest {
                            prefix: b"unknown-control",
                            start_after: None,
                            max_entries: 1,
                            max_bytes: 1024,
                        },
                    )
                    .map(|_| ()),
            };
            assert!(outcome.is_err());
            assert!(
                matches!(recorder.materialize(&mut parent), Err(error) if error.code == ErrorCode::ResourceExhausted)
            );
        }

        let mut parent = budget();
        let recorder = Recorder::new(&f.native, &snapshot, &workspace, &generation, &mut parent)
            .expect("bounded recorder");
        for _ in 0..MAX_CALLS {
            crate::budgeted::read_value(
                &recorder,
                &f.native.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                ROW_BYTES,
                &mut parent,
            )
            .expect("each real bounded read remains recorded")
            .expect("actual manifest");
        }
        assert!(
            crate::budgeted::read_value(
                &recorder,
                &f.native.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                ROW_BYTES,
                &mut parent
            )
            .is_err()
        );
        assert!(
            matches!(recorder.materialize(&mut parent), Err(error) if error.code == ErrorCode::ResourceExhausted)
        );
    }

    #[test]
    fn actual_control_pages_bind_absence_neighbors_and_continuation() {
        for absent in [false, true] {
            let f = fixture();
            let workspace = digest_bytes(f.context.request.workspace_id.as_bytes());
            let generation = read_generation(&f.native, &f.context, &mut budget());
            let snapshot = f
                .native
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("actual initial native snapshot");
            let typed = crate::budgeted::read_value(
                &snapshot,
                &f.native.keyspaces.meta,
                crate::META_MANIFEST_KEY,
                ROW_BYTES,
                &mut budget(),
            )
            .expect("actual typed manifest bytes")
            .expect("existing manifest");
            drop(snapshot);
            let space = if absent {
                &f.native.keyspaces.continuous
            } else {
                &f.native.keyspaces.meta
            };
            let key = if absent {
                interval_types::directory_head_key(&workspace, generation.number)
                    .expect("genuine absent directory address")
            } else {
                crate::META_MANIFEST_KEY.to_vec()
            };
            let mut neighbor = key.clone();
            neighbor.extend_from_slice(b"/witness-test-neighbor");
            let mut parent = budget();
            parent
                .charge(
                    typed.len() as u64 + 1,
                    typed.len() as u64 * 2 + neighbor.len() as u64 + 256,
                )
                .expect("pay test control copy");
            let mut tx = f
                .native
                .engine
                .begin_write()
                .expect("temporary typed control neighbor");
            tx.put(space, neighbor.clone(), typed.clone())
                .expect("actual encrypted neighbor row");
            tx.commit(Durability::Sync).expect("durable neighbor setup");
            let snapshot = f
                .native
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("concrete witnessed snapshot");
            let recorder =
                Recorder::new(&f.native, &snapshot, &workspace, &generation, &mut parent)
                    .expect("prepaid recorder");
            let before =
                crate::budgeted::read_value(&recorder, space, &key, ROW_BYTES, &mut parent)
                    .expect("actual point semantics");
            assert_eq!(before.is_none(), absent);
            let witness = recorder
                .materialize(&mut parent)
                .expect("actual complete IO witness, not a serving seed");
            assert_eq!(witness.pages.len(), 1);
            assert_eq!(witness.pages[0].page.continuation.is_some(), !absent);
            assert_eq!(
                witness.pages[0].page.entries[0].key,
                if absent {
                    neighbor.clone()
                } else {
                    key.clone()
                }
            );
            drop(snapshot);
            let mut tx = f.native.engine.begin_write().expect("neighbor fault");
            tx.delete(space, neighbor.clone())
                .expect("remove only neighbor, retaining exact point value");
            tx.commit(Durability::Sync)
                .expect("durable neighbor removal");
            let current = f
                .native
                .engine
                .begin_read(SnapshotSelector::Latest)
                .expect("actual changed page");
            let after = crate::budgeted::read_value(&current, space, &key, ROW_BYTES, &mut parent)
                .expect("point value remains unchanged");
            assert_eq!(after, before);
            let outcome = witness.check(
                &f.native,
                &current,
                b"unused for immutable controls",
                &mut parent,
            );
            drop(current);

            parent
                .charge(typed.len() as u64 + 1, typed.len() as u64 * 2 + 256)
                .expect("pay exact restoration copy");
            let mut tx = f
                .native
                .engine
                .begin_write()
                .expect("restore observed neighbor bytes");
            tx.put(space, neighbor.clone(), typed)
                .expect("exact typed neighbor restoration");
            tx.commit(Durability::Sync).expect("durable restoration");
            // The neighbor was fixture-only IO, never an accepted publication.
            let mut tx = f
                .native
                .engine
                .begin_write()
                .expect("restore clean fixture baseline");
            tx.delete(space, neighbor)
                .expect("remove fixture-only neighbor");
            tx.commit(Durability::Sync).expect("durable clean baseline");
            assert!(matches!(outcome, Err(error) if error.code == ErrorCode::IndexTooStale));
            assert!(
                f.native
                    .verify_native(true)
                    .expect("actual clean native deep proof")
                    .valid
            );
        }
    }
}
