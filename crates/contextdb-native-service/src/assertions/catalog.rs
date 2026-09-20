//! Scoped authority-key directory. Built explicitly by maintenance, then kept in
//! the same semantic publication transaction. Query paths never rebuild it.

use super::*;

pub(in super::super) const CATALOG_FEATURE: &str = "continuous-state-catalog-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    key: StateKey,
    access: contextdb_service::AccessPolicy,
    first_commit: u64,
    version: RevisionNumber,
}

impl NativeService {
    /// Build the bounded authority directory for this workspace once. Existing
    /// accepted journal bytes are unchanged. Subsequent semantic writes maintain it.
    pub fn initialize_state_catalog(
        &self,
        context: &AuthenticatedRequestContext,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        require_capability(context, Capability::Admin)?;
        let workspace = workspace(context);
        let _guard = self.lock_index_publication(budget)?;
        let mut tx = self.engine.begin_write().map_err(storage_error)?;
        let mut manifest: super::super::Manifest = decode(
            &tx.get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if manifest.state_catalogs.contains(&workspace) {
            return Ok(());
        }
        if manifest.state_catalogs.len() >= 1024 {
            return Err(exhausted("state catalog workspace bound exceeded"));
        }
        let rows = self.expected_state_catalog(&tx, &workspace, budget)?;
        for (key, value) in rows {
            budget.charge(1, value.len() as u64).map_err(budget_error)?;
            tx.put(&self.keyspaces.continuous, key, value)
                .map_err(storage_error)?;
        }
        self.enable_capture_format(&mut tx)?;
        // Reload because capture activation updates the same manifest.
        manifest = decode(
            &tx.get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        manifest.state_catalogs.insert(workspace);
        manifest.features.insert(CATALOG_FEATURE.into());
        manifest.checksum = super::super::manifest_checksum(&manifest)?;
        tx.put(
            &self.keyspaces.meta,
            super::super::META_MANIFEST_KEY.to_vec(),
            encode(&manifest)?,
        )
        .map_err(storage_error)?;
        budget.check().map_err(budget_error)?;
        require_sync(
            tx.commit(Durability::Sync)
                .map_err(storage_error)?
                .durability,
        )
    }

    pub(super) fn update_state_catalog<T: WriteTransaction>(
        &self,
        tx: &mut T,
        accepted: &AcceptedAssertions,
    ) -> ServiceResult<()> {
        let workspace = digest_bytes(accepted.workspace_id.as_bytes());
        let manifest: super::super::Manifest = decode(
            &tx.get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if !manifest.state_catalogs.contains(&workspace) {
            return Ok(());
        }
        for mutation in &accepted.mutations {
            let AssertionMutation::Policy { policy } = mutation else {
                continue;
            };
            let key = catalog_key(&workspace, &policy.key)?;
            let previous: Option<CatalogEntry> = self.raw_value(tx, &key)?;
            let row = CatalogEntry {
                key: policy.key.clone(),
                access: accepted.access.clone(),
                first_commit: previous.map_or(accepted.commit, |row| row.first_commit),
                version: policy.version,
            };
            tx.put(&self.keyspaces.continuous, key, encode(&row)?)
                .map_err(storage_error)?;
        }
        Ok(())
    }

    /// Metadata-only scoped discovery; current policy is checked before a key is
    /// admitted to the state resolver. Historical reads also use current access.
    pub(in super::super) fn scoped_state_keys<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        context: &AuthenticatedRequestContext,
        scope: ScopeId,
        known: u64,
        budget: &mut QueryBudget,
    ) -> ServiceResult<Vec<StateKey>> {
        require_scope(context, scope, Capability::Recall)?;
        let workspace = workspace(context);
        self.require_suppression_current(snapshot, &workspace)?;
        let manifest: super::super::Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        if !manifest.state_catalogs.contains(&workspace) {
            return Err(stale(
                "initialize the workspace state catalog before preparation",
            ));
        }
        let prefix = format!("catalog/{workspace}/{scope}/");
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: 513,
                    max_bytes: MAX_STATE_BYTES,
                },
            )
            .map_err(storage_error)?;
        if page.continuation.is_some() || page.entries.len() > 512 {
            return Err(exhausted("scoped authority catalog exceeds 512 slots"));
        }
        let mut keys = Vec::new();
        for entry in page.entries {
            let row: CatalogEntry = decode(&entry.value, "state catalog entry")?;
            if !super::super::policy_allows(&context.request, &row.access) {
                continue;
            }
            budget
                .charge(1, entry.value.len() as u64)
                .map_err(budget_error)?;
            if row.key.scope != scope || catalog_key(&workspace, &row.key)? != entry.key {
                return Err(integrity("state catalog key disagrees"));
            }
            if row.first_commit <= known {
                keys.push(row.key);
            }
        }
        Ok(keys)
    }

    fn expected_state_catalog<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        workspace: &str,
        budget: &mut QueryBudget,
    ) -> ServiceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
        let prefix = format!("state/policy/{workspace}/");
        let page = snapshot
            .scan_prefix_page(
                &self.keyspaces.continuous,
                ScanPageRequest {
                    prefix: prefix.as_bytes(),
                    start_after: None,
                    max_entries: 32769,
                    max_bytes: 64 * 1024 * 1024,
                },
            )
            .map_err(storage_error)?;
        if page.continuation.is_some() || page.entries.len() > 32768 {
            return Err(exhausted(
                "state catalog maintenance exceeds its 32768-version profile",
            ));
        }
        let mut entries = BTreeMap::<Vec<u8>, CatalogEntry>::new();
        for entry in page.entries {
            budget
                .charge(1, entry.value.len() as u64)
                .map_err(budget_error)?;
            let authority: StoredAuthority = decode(&entry.value, "catalog authority")?;
            let key = catalog_key(workspace, &authority.policy.key)?;
            let first_commit = entries.get(&key).map_or(authority.commit, |old| {
                old.first_commit.min(authority.commit)
            });
            if entries
                .get(&key)
                .is_none_or(|old| old.version < authority.policy.version)
            {
                entries.insert(
                    key,
                    CatalogEntry {
                        key: authority.policy.key,
                        access: authority.access,
                        first_commit,
                        version: authority.policy.version,
                    },
                );
            }
        }
        entries
            .into_iter()
            .map(|(key, entry)| Ok((key, encode(&entry)?)))
            .collect()
    }

    pub(in super::super) fn verify_state_catalog<S: ReadSnapshot>(
        &self,
        snapshot: &S,
        budget: &mut QueryBudget,
    ) -> ServiceResult<()> {
        let manifest: super::super::Manifest = decode(
            &snapshot
                .get(&self.keyspaces.meta, super::super::META_MANIFEST_KEY)
                .map_err(storage_error)?
                .ok_or_else(|| integrity("native manifest absent"))?,
            "native manifest",
        )?;
        let mut expected = BTreeMap::new();
        for workspace in manifest.state_catalogs {
            expected.extend(self.expected_state_catalog(snapshot, &workspace, budget)?);
        }
        let actual = snapshot
            .scan_prefix(&self.keyspaces.continuous, b"catalog/")
            .map_err(storage_error)?;
        if actual.len() != expected.len()
            || actual
                .iter()
                .any(|entry| expected.get(&entry.key) != Some(&entry.value))
        {
            return Err(integrity(
                "scoped state catalog differs from accepted authority history",
            ));
        }
        Ok(())
    }
}

fn catalog_key(workspace: &str, key: &StateKey) -> ServiceResult<Vec<u8>> {
    Ok(format!(
        "catalog/{workspace}/{}/{}",
        key.scope,
        canonical_digest(key)?
    )
    .into_bytes())
}
