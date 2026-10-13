//! Explicit copy witnesses distinguish a supplied successor from rewired edges.

use super::*;

#[cfg(test)]
mod tests;

type Revision = (String, u32);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Correction {
    target: Revision,
    /// New edge digest -> exact closed predecessor revision.
    pub(super) rewires: BTreeMap<String, Revision>,
}

impl Correction {
    pub(super) fn new(target: &StoredPolicy, rewires: &[HierarchyRewire]) -> Self {
        Self {
            target: (target.record_digest.clone(), target.revision),
            rewires: rewires
                .iter()
                .map(|rewire| {
                    (
                        digest_bytes(rewire.new_edge_id.as_bytes()),
                        (
                            rewire.old_policy.record_digest.clone(),
                            rewire.old_policy.revision,
                        ),
                    )
                })
                .collect(),
        }
    }

    pub(super) fn validate_shape(
        &self,
        primary: &MemoryRecord,
        closed: &BTreeMap<Revision, &MemoryRecord>,
        births: &BTreeMap<Revision, &MemoryRecord>,
    ) -> ServiceResult<()> {
        let target = closed
            .get(&self.target)
            .ok_or_else(|| integrity("correction target closure absent"))?;
        if primary.revision != 1
            || primary.document.id == target.document.id
            || primary.document.kind == MemoryRecordKind::Candidate
            || primary.document.kind != target.document.kind
            || primary.document.lifecycle != MemoryLifecycle::Active
            || target.document.lifecycle != MemoryLifecycle::Active
            || primary.document.access != target.document.access
            || !primary
                .document
                .links
                .supersedes
                .contains(&target.document.id)
            || managed_edge(&target.document)
            || births.len() != self.rewires.len() + 1
            || closed.len() != self.rewires.len() + 1
            || (target.document.kind == MemoryRecordKind::Edge && !self.rewires.is_empty())
        {
            return Err(integrity(
                "correction group has an invalid successor or closure",
            ));
        }
        validate_structured_successor(&target.document, &primary.document)
            .map_err(|_| integrity("correction changes the structured memory kind"))?;
        let mut predecessors = BTreeSet::from([self.target.clone()]);
        for (id, key) in &self.rewires {
            let old = closed
                .get(key)
                .ok_or_else(|| integrity("rewired predecessor closure absent"))?;
            let new = births
                .get(&(id.clone(), 1))
                .ok_or_else(|| integrity("rewired successor birth absent"))?;
            if !predecessors.insert(key.clone())
                || new.document.id == primary.document.id
                || old.document.kind != MemoryRecordKind::Edge
                || old.document.lifecycle != MemoryLifecycle::Active
                || old.document.links.predicate.as_deref() != Some(HIERARCHY_PARENT_PREDICATE)
                || old.document.access != target.document.access
                || !incident(&old.document, &target.document.id)
            {
                return Err(integrity(
                    "correction copy witness is not a unique incident hierarchy edge",
                ));
            }
            let replace = |endpoint: &Option<String>| -> ServiceResult<String> {
                let endpoint = endpoint
                    .as_ref()
                    .ok_or_else(|| integrity("copied hierarchy endpoint absent"))?;
                Ok(if endpoint == &target.document.id {
                    primary.document.id.clone()
                } else {
                    endpoint.clone()
                })
            };
            let source = replace(&old.document.links.source)?;
            let destination = replace(&old.document.links.target)?;
            if source == destination
                || hierarchy_rewire_document(&old.document, &source, &destination)? != new.document
            {
                return Err(integrity(
                    "rewired edge changed its copied metadata or endpoints",
                ));
            }
        }
        Ok(())
    }
}
