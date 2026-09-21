use super::*;

impl NativeCustodyKeys {
    pub(super) fn use_head<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> contextdb_storage::Result<UseCheckpoint> {
        let bytes = snapshot
            .get(&self.rows, HEAD)?
            .ok_or_else(|| failure("native key-use journal head is absent"))?;
        let head: UseCheckpoint = decode(&self.open_use(HEAD, &bytes, "journal")?)?;
        validate_checkpoint(&head, true)?;
        if head.sequence != 0 && self.use_event(snapshot, head.sequence)?.checkpoint != head {
            return Err(failure("native key-use terminal differs"));
        }
        let tail = snapshot.scan_prefix_page(
            &self.rows,
            ScanPageRequest {
                prefix: EVENTS,
                start_after: Some(&event_key(head.sequence)),
                max_entries: 1,
                max_bytes: MAX_EVENT_BYTES + NONCE_BYTES + TAG_BYTES,
            },
        )?;
        if !tail.entries.is_empty() {
            return Err(failure("native key-use head is behind its journal"));
        }
        Ok(head)
    }

    pub(super) fn use_event<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        sequence: u64,
    ) -> contextdb_storage::Result<UseEvent> {
        let key = event_key(sequence);
        let bytes = snapshot
            .get(&self.rows, &key)?
            .ok_or_else(|| failure("native key-use event is absent"))?;
        let event: UseEvent = decode(&self.open_use(&key, &bytes, "journal")?)?;
        validate_checkpoint(&event.checkpoint, false)?;
        if event.checkpoint.sequence != sequence
            || event.checkpoint.digest.as_deref() != Some(event.digest()?.as_str())
        {
            return Err(failure("native key-use event commitment differs"));
        }
        Ok(event)
    }

    pub(super) fn use_state<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        instance: Uuid,
    ) -> contextdb_storage::Result<InstanceState> {
        let key = state_key(instance);
        let bytes = snapshot
            .get(&self.rows, &key)?
            .ok_or_else(|| failure("native key-use instance is not registered"))?;
        let state: InstanceState = decode(&self.open_use(&key, &bytes, "journal")?)?;
        if state.marker.instance != instance
            || state.marker.native_sequence == 0
            || state.revision == 0
        {
            return Err(failure("native key-use instance binding differs"));
        }
        let key = instance_key(instance, state.revision);
        let bytes = snapshot
            .get(&self.rows, &key)?
            .ok_or_else(|| failure("native key-use instance acceptance is absent"))?;
        let accepted: UseCheckpoint = decode(&self.open_use(&key, &bytes, "journal")?)?;
        let event = self.use_event(snapshot, accepted.sequence)?;
        if accepted != state.accepted || event.checkpoint != accepted {
            return Err(failure("native key-use instance acceptance differs"));
        }
        match event.change {
            UseOperation::Register {
                instance: registered,
            } => {
                if registered != instance
                    || state.revision != 1
                    || state.pending.is_some()
                    || state.marker.native_sequence != 1
                    || state.marker.usage.is_some()
                {
                    return Err(failure("native key-use registration state differs"));
                }
            }
            UseOperation::Prepare { preparation } => {
                if state.marker != preparation.previous
                    || state.pending
                        != Some(PendingUse {
                            preparation,
                            checkpoint: accepted.clone(),
                        })
                {
                    return Err(failure("native key-use pending state differs"));
                }
            }
            UseOperation::Complete {
                prepared,
                instance: recorded,
                committed,
            } => {
                let preparation_event = self.use_event(snapshot, prepared.sequence)?;
                let UseOperation::Prepare { preparation } = preparation_event.change else {
                    return Err(failure("native key-use outcome preparation is absent"));
                };
                let pending = PendingUse {
                    preparation,
                    checkpoint: prepared.clone(),
                };
                let expected = if committed {
                    pending.expected()?
                } else {
                    pending.preparation.previous
                };
                let key = outcome_key(prepared.sequence);
                let bytes = snapshot
                    .get(&self.rows, &key)?
                    .ok_or_else(|| failure("native key-use outcome locator is absent"))?;
                let outcome: UseCheckpoint = decode(&self.open_use(&key, &bytes, "journal")?)?;
                if recorded != instance
                    || preparation_event.checkpoint != prepared
                    || outcome != accepted
                    || state.pending.is_some()
                    || state.marker != expected
                {
                    return Err(failure("native key-use completed state differs"));
                }
            }
            UseOperation::Page { .. } => {
                return Err(failure(
                    "native key-use instance state references a transition page",
                ));
            }
        }
        let prefix = format!("use/instance/{instance}/");
        let tail = snapshot.scan_prefix_page(
            &self.rows,
            ScanPageRequest {
                prefix: prefix.as_bytes(),
                start_after: Some(&key),
                max_entries: 1,
                max_bytes: MAX_EVENT_BYTES,
            },
        )?;
        if !tail.entries.is_empty() {
            return Err(failure(
                "native key-use instance state is behind its journal",
            ));
        }
        Ok(state)
    }

    pub(super) fn put_use_state<T: WriteTransaction>(
        &self,
        tx: &mut T,
        state: &InstanceState,
    ) -> contextdb_storage::Result<()> {
        let reference = instance_key(state.marker.instance, state.revision);
        if tx.get(&self.rows, &reference)?.is_some() {
            return Err(failure("native key-use instance revision already exists"));
        }
        tx.put(
            &self.rows,
            reference.clone(),
            self.seal_use(&reference, &encode(&state.accepted)?, "journal")?,
        )?;
        let key = state_key(state.marker.instance);
        tx.put(
            &self.rows,
            key.clone(),
            self.seal_use(&key, &encode(state)?, "journal")?,
        )
    }

    pub(super) fn append_use_event<T: WriteTransaction>(
        &self,
        tx: &mut T,
        head: &mut UseCheckpoint,
        change: UseOperation,
    ) -> contextdb_storage::Result<UseCheckpoint> {
        let sequence = head
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure("native key-use journal exhausted"))?;
        let key = event_key(sequence);
        if tx.get(&self.rows, &key)?.is_some() {
            return Err(failure("native key-use event already exists"));
        }
        let mut event = UseEvent {
            checkpoint: UseCheckpoint {
                sequence,
                digest: None,
            },
            previous_digest: head.digest.clone(),
            change,
        };
        event.checkpoint.digest = Some(event.digest()?);
        let bytes = encode(&event)?;
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(failure("native key-use event exceeds its bound"));
        }
        tx.put(
            &self.rows,
            key.clone(),
            self.seal_use(&key, &bytes, "journal")?,
        )?;
        *head = event.checkpoint.clone();
        tx.put(
            &self.rows,
            HEAD.to_vec(),
            self.seal_use(HEAD, &encode(head)?, "journal")?,
        )?;
        Ok(event.checkpoint)
    }

    pub(super) fn validate_use_keys<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        change: &NativeKeyUseChange,
    ) -> contextdb_storage::Result<u64> {
        change.validate()?;
        let mut inspected_bytes = 0;
        for version in change.before.iter().chain(change.after.iter()) {
            let key = versions::version_key(&change.address_digest, version.key_id);
            let bytes = snapshot
                .get(&self.rows, &key)?
                .ok_or_else(|| failure("native key-use version has no allocated key"))?;
            inspected_bytes += bytes.len() as u64;
            let record: KeyRecord = decode(&bytes)?;
            if record.id != version.key_id {
                return Err(failure("native key-use allocated UUID differs"));
            }
            self.unwrap(&change.address_digest, &record)?;
        }
        Ok(inspected_bytes)
    }

    pub(super) fn visit_use_changes<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        pending: &PendingUse,
        mut visit: impl FnMut(NativeKeyUseChange) -> contextdb_storage::Result<()>,
    ) -> contextdb_storage::Result<()> {
        let preparation = &pending.preparation;
        if preparation.previous.native_sequence == 0
            || u64::from(preparation.pages) != preparation.changes.div_ceil(CHANGES_PER_PAGE as u64)
            || u64::from(preparation.pages) >= pending.checkpoint.sequence
        {
            return Err(failure("native key-use preparation bounds differ"));
        }
        let start = pending
            .checkpoint
            .sequence
            .checked_sub(u64::from(preparation.pages))
            .ok_or_else(|| failure("native key-use page range underflows"))?;
        let mut last = None;
        let mut count = 0_u64;
        let mut prior_digest = None;
        for index in 0..preparation.pages {
            let event = self.use_event(snapshot, start + u64::from(index))?;
            if index != 0 && event.previous_digest != prior_digest {
                return Err(failure("native key-use page chain differs"));
            }
            prior_digest = event.checkpoint.digest;
            let UseOperation::Page {
                transaction,
                index: ordinal,
                changes,
            } = event.change
            else {
                return Err(failure("native key-use preparation lost a page"));
            };
            if transaction != preparation.transaction
                || ordinal != index
                || !(1..=CHANGES_PER_PAGE).contains(&changes.len())
                || (index + 1 < preparation.pages && changes.len() != CHANGES_PER_PAGE)
            {
                return Err(failure("native key-use page identity or bound differs"));
            }
            for change in changes {
                if last
                    .as_ref()
                    .is_some_and(|last| last >= &change.address_digest)
                {
                    return Err(failure("native key-use address repeats or is out of order"));
                }
                self.validate_use_keys(snapshot, &change)?;
                last = Some(change.address_digest.clone());
                visit(change)?;
                count += 1;
            }
        }
        let terminal = self.use_event(snapshot, pending.checkpoint.sequence)?;
        if terminal.checkpoint != pending.checkpoint
            || terminal.change
                != (UseOperation::Prepare {
                    preparation: preparation.clone(),
                })
            || (preparation.pages != 0 && terminal.previous_digest != prior_digest)
            || count != preparation.changes
            || count > MAX_CHANGES as u64
        {
            return Err(failure(
                "native key-use preparation differs from its complete pages",
            ));
        }
        Ok(())
    }

    pub(in crate::encryption::keys) fn verify_native_use<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> contextdb_storage::Result<()> {
        let head = self.use_head(snapshot)?;
        let mut previous = UseCheckpoint::default();
        let mut states: BTreeMap<Uuid, InstanceState> = BTreeMap::new();
        let mut copies: BTreeMap<(Uuid, String), NativeKeyUseVersion> = BTreeMap::new();
        let mut transactions = BTreeSet::new();
        let mut references = BTreeMap::new();
        let mut outcomes = BTreeMap::new();
        let mut unclaimed_pages = 0_u32;
        let mut transaction = None;
        for sequence in 1..=head.sequence {
            let event = self.use_event(snapshot, sequence)?;
            if event.previous_digest != previous.digest {
                return Err(failure("native key-use journal is discontinuous"));
            }
            match event.change {
                UseOperation::Register { instance } => {
                    if unclaimed_pages != 0
                        || instance.is_nil()
                        || states
                            .insert(
                                instance,
                                InstanceState {
                                    revision: 1,
                                    accepted: event.checkpoint.clone(),
                                    marker: LocalMarker {
                                        instance,
                                        native_sequence: 1,
                                        usage: None,
                                    },
                                    pending: None,
                                },
                            )
                            .is_some()
                    {
                        return Err(failure(
                            "native key-use instance registration repeats or interrupts pages",
                        ));
                    }
                    references.insert(instance_key(instance, 1), event.checkpoint.clone());
                }
                UseOperation::Page {
                    transaction: id,
                    index,
                    changes,
                } => {
                    if id.is_nil()
                        || index != unclaimed_pages
                        || transaction.is_some_and(|prior| prior != id)
                        || !(1..=CHANGES_PER_PAGE).contains(&changes.len())
                        || unclaimed_pages as usize >= MAX_CHANGES.div_ceil(CHANGES_PER_PAGE)
                    {
                        return Err(failure("native key-use journal page order differs"));
                    }
                    transaction = Some(id);
                    unclaimed_pages += 1;
                }
                UseOperation::Prepare { preparation } => {
                    let instance = preparation.previous.instance;
                    let state = states
                        .get_mut(&instance)
                        .ok_or_else(|| failure("native key-use preparation has no instance"))?;
                    if preparation.transaction.is_nil()
                        || !transactions.insert(preparation.transaction)
                        || state.pending.is_some()
                        || preparation.previous != state.marker
                        || preparation.pages != unclaimed_pages
                        || transaction.is_some_and(|prior| prior != preparation.transaction)
                        || preparation.changes > MAX_CHANGES as u64
                    {
                        return Err(failure("native key-use preparation state differs"));
                    }
                    let pending = PendingUse {
                        preparation,
                        checkpoint: event.checkpoint.clone(),
                    };
                    self.visit_use_changes(snapshot, &pending, |change| {
                        if copies.get(&(instance, change.address_digest)).cloned() != change.before
                        {
                            return Err(failure(
                                "native key-use preimage differs from accepted instance history",
                            ));
                        }
                        Ok(())
                    })?;
                    state.pending = Some(pending);
                    advance_state(state, &event.checkpoint)?;
                    references.insert(
                        instance_key(instance, state.revision),
                        event.checkpoint.clone(),
                    );
                    unclaimed_pages = 0;
                    transaction = None;
                }
                UseOperation::Complete {
                    prepared,
                    instance,
                    committed,
                } => {
                    let state = states
                        .get_mut(&instance)
                        .ok_or_else(|| failure("native key-use outcome has no instance"))?;
                    let pending = state
                        .pending
                        .take()
                        .ok_or_else(|| failure("native key-use outcome has no preparation"))?;
                    if unclaimed_pages != 0 || pending.checkpoint != prepared {
                        return Err(failure(
                            "native key-use outcome references another preparation",
                        ));
                    }
                    if outcomes
                        .insert(outcome_key(prepared.sequence), event.checkpoint.clone())
                        .is_some()
                    {
                        return Err(failure("native key-use outcome repeats"));
                    }
                    if committed {
                        self.visit_use_changes(snapshot, &pending, |change| {
                            let key = (instance, change.address_digest);
                            if let Some(after) = change.after {
                                copies.insert(key, after);
                            } else {
                                copies.remove(&key);
                            }
                            Ok(())
                        })?;
                        state.marker = pending.expected()?;
                    }
                    advance_state(state, &event.checkpoint)?;
                    references.insert(
                        instance_key(instance, state.revision),
                        event.checkpoint.clone(),
                    );
                }
            }
            previous = event.checkpoint;
        }
        if previous != head || unclaimed_pages != 0 {
            return Err(failure(
                "native key-use journal terminal or pages are incomplete",
            ));
        }
        let actual = snapshot.scan_prefix(&self.rows, STATES)?;
        if actual.len() != states.len() {
            return Err(failure("native key-use instance inventory differs"));
        }
        for row in actual {
            let state: InstanceState = decode(&self.open_use(&row.key, &row.value, "journal")?)?;
            if row.key != state_key(state.marker.instance)
                || states.remove(&state.marker.instance) != Some(state)
            {
                return Err(failure(
                    "native key-use instance state differs from its journal",
                ));
            }
        }
        for row in snapshot.scan_prefix(&self.rows, b"use/")? {
            if row.key != HEAD
                && !row.key.starts_with(EVENTS)
                && !row.key.starts_with(STATES)
                && !row.key.starts_with(INSTANCES)
                && !row.key.starts_with(OUTCOMES)
            {
                return Err(failure("native key-use inventory contains an unknown row"));
            }
        }
        for row in snapshot.scan_prefix(&self.rows, INSTANCES)? {
            let value: UseCheckpoint = decode(&self.open_use(&row.key, &row.value, "journal")?)?;
            if references.remove(&row.key) != Some(value) {
                return Err(failure("native key-use instance history differs"));
            }
        }
        if !references.is_empty() {
            return Err(failure("native key-use instance history is incomplete"));
        }
        for row in snapshot.scan_prefix(&self.rows, OUTCOMES)? {
            let value: UseCheckpoint = decode(&self.open_use(&row.key, &row.value, "journal")?)?;
            if outcomes.remove(&row.key) != Some(value) {
                return Err(failure("native key-use outcome index differs"));
            }
        }
        if !outcomes.is_empty() {
            return Err(failure("native key-use outcome index is incomplete"));
        }
        // The ordered key names themselves are required; aliases cannot hide next
        // to the exact events read by sequence above.
        if snapshot.scan_prefix(&self.rows, EVENTS)?.len() as u64 != head.sequence {
            return Err(failure("native key-use event inventory contains aliases"));
        }
        Ok(())
    }
}

pub(super) fn advance_state(
    state: &mut InstanceState,
    accepted: &UseCheckpoint,
) -> contextdb_storage::Result<()> {
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or_else(|| failure("native key-use instance revision exhausted"))?;
    state.accepted = accepted.clone();
    Ok(())
}
