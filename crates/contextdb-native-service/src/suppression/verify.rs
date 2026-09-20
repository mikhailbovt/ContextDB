//! Reconstruct applied prefixes from native receipts and the retained authority.

use super::*;

impl NativeService {
    pub(crate) fn verify_suppression_records<S: ReadSnapshot>(
        &self,
        snapshot: &S,
    ) -> ServiceResult<()> {
        let manifest: Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native suppression manifest is missing"))?,
            "suppression manifest",
        )?;
        self.verify_suppression_binding(&manifest)?;
        let mut applied = BTreeMap::<String, Checkpoint>::new();
        for row in snapshot
            .scan_prefix(&self.keyspaces.events, b"")
            .map_err(storage_error)?
        {
            let event: StoredEvent = decode(&row.value, "native suppression event")?;
            match (event.accepted_suppression, event.operation.as_str()) {
                (Some(publication), "suppression_reconcile") => {
                    let ledger = self.suppression.as_ref().ok_or_else(|| {
                        integrity("suppression receipt has no external authority")
                    })?;
                    let from = applied
                        .get(&event.workspace_digest)
                        .cloned()
                        .map_or_else(|| ledger.genesis(&event.workspace_digest), Ok)?;
                    if publication.from != from
                        || publication.through.epoch <= from.epoch
                        || publication.through.epoch - from.epoch > 256
                        || event.response_digest != digest_bytes(&encode(&publication)?)
                    {
                        return Err(integrity("accepted suppression prefix is invalid"));
                    }
                    for epoch in from.epoch + 1..=publication.through.epoch {
                        let entry = ledger.entry(&event.workspace_digest, epoch)?;
                        if epoch == publication.through.epoch
                            && entry.checkpoint() != publication.through
                        {
                            return Err(integrity(
                                "applied suppression differs from its current authority",
                            ));
                        }
                        if let Some(bytes) = snapshot
                            .get(
                                &self.keyspaces.observations_policy,
                                digest_bytes(entry.event_id.to_string().as_bytes()).as_bytes(),
                            )
                            .map_err(storage_error)?
                        {
                            let policy: StoredObservationPolicy =
                                decode(&bytes, "suppressed source policy")?;
                            let receipt =
                                self.captured_receipt_metadata(snapshot, entry.event_id)?;
                            if policy.access.retrievable
                                || receipt.event_digest != entry.event_digest
                                || digest_bytes(receipt.workspace_id.to_string().as_bytes())
                                    != event.workspace_digest
                            {
                                return Err(integrity(
                                    "accepted external suppression was not enforced",
                                ));
                            }
                        }
                    }
                    applied.insert(event.workspace_digest, publication.through);
                }
                (None, operation) if operation != "suppression_reconcile" => (),
                _ => return Err(integrity("suppression publication kind differs")),
            }
        }
        let expected = applied
            .into_iter()
            .map(|(workspace, checkpoint)| Ok((applied_key(&workspace), encode(&checkpoint)?)))
            .collect::<ServiceResult<BTreeMap<_, _>>>()?;
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"suppression/")
            .map_err(storage_error)?;
        if actual.len() != expected.len()
            || actual
                .iter()
                .any(|row| expected.get(&row.key) != Some(&row.value))
        {
            return Err(integrity(
                "applied suppression state differs from native receipts",
            ));
        }
        if let Some(ledger) = &self.suppression {
            for (workspace, receipt) in self.accepted_raw_revocations(snapshot)? {
                if !ledger.denied(&workspace, receipt.event_id)? {
                    return Err(integrity(
                        "native revocation lacks an external durable denial",
                    ));
                }
            }
        }
        Ok(())
    }
}
