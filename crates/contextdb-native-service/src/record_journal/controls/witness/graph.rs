use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CandidateRole {
    Memory,
    Edge,
}

/// Typed validation facts and commitments only; arbitrary actor/request strings
/// and original endpoint names never become retained control fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GraphControl {
    candidate_role: Option<CandidateRole>,
    provenance_digest: Option<String>,
    derived_edge_digest: Option<String>,
}

impl GraphControl {
    pub(super) fn from_document(document: &MemoryDocument) -> ServiceResult<Self> {
        let mut control = Self {
            candidate_role: None,
            provenance_digest: None,
            derived_edge_digest: None,
        };
        let predicate = document.links.predicate.as_deref();
        if document.kind == MemoryRecordKind::Edge && predicate == Some(HIERARCHY_PARENT_PREDICATE)
        {
            let (source, target) = endpoints(document)?;
            control.derived_edge_digest =
                Some(digest_bytes(hierarchy_edge_id(source, target)?.as_bytes()));
        }
        if document.kind == MemoryRecordKind::Candidate {
            control.candidate_role = Some(match candidate_role(document) {
                Some(CANDIDATE_MEMORY_ROLE) => {
                    validate_candidate_proposal_document(document)?;
                    CandidateRole::Memory
                }
                Some(CANDIDATE_EDGE_ROLE) => {
                    validate_candidate_provenance_attributes(document)?;
                    let (source, target) = endpoints(document)?;
                    if predicate != Some(CANDIDATE_HIERARCHY_PARENT_PREDICATE) {
                        return Err(integrity("candidate witness predicate differs"));
                    }
                    control.derived_edge_digest = Some(digest_bytes(
                        candidate_hierarchy_edge_id(source, target)?.as_bytes(),
                    ));
                    CandidateRole::Edge
                }
                _ => return Err(integrity("record removal candidate role is invalid")),
            });
            let values: Vec<_> = [
                "contextdb.proposal.schema_version",
                "contextdb.proposal.state",
                "contextdb.proposal.input_digest",
                "contextdb.proposal.actor_id",
                "contextdb.proposal.agent_id",
                "contextdb.proposal.session_id",
                "contextdb.proposal.request_id",
                "contextdb.proposal.schema_id",
            ]
            .iter()
            .map(|key| document.attributes.get(*key))
            .collect();
            control.provenance_digest = Some(canonical_digest(&values)?);
        } else if candidate_role(document).is_some()
            || predicate == Some(CANDIDATE_HIERARCHY_PARENT_PREDICATE)
        {
            return Err(integrity(
                "canonical removal witness contains candidate metadata",
            ));
        }
        if control
            .derived_edge_digest
            .as_ref()
            .is_some_and(|digest| *digest != digest_bytes(document.id.as_bytes()))
        {
            return Err(integrity("record removal edge identity is invalid"));
        }
        Ok(control)
    }

    pub(super) fn validate(&self, control: &RecordControl) -> ServiceResult<()> {
        let candidate = control.policy.kind == MemoryRecordKind::Candidate;
        let hierarchy = control.policy.kind == MemoryRecordKind::Edge
            && control.links.predicate == Some(digest_bytes(HIERARCHY_PARENT_PREDICATE.as_bytes()));
        if candidate != self.candidate_role.is_some()
            || candidate != self.provenance_digest.is_some()
            || self
                .provenance_digest
                .as_ref()
                .is_some_and(|digest| blake3::Hash::from_hex(digest).is_err())
            || (!candidate
                && control.links.predicate
                    == Some(digest_bytes(
                        CANDIDATE_HIERARCHY_PARENT_PREDICATE.as_bytes(),
                    )))
        {
            return Err(integrity("record witness graph role is invalid"));
        }
        let edge = hierarchy || self.candidate_role == Some(CandidateRole::Edge);
        if edge != self.derived_edge_digest.is_some()
            || (edge
                && (control.links.source.is_none()
                    || control.links.target.is_none()
                    || control.links.source == control.links.target
                    || self.derived_edge_digest.as_ref() != Some(&control.policy.record_digest)))
            || (self.candidate_role == Some(CandidateRole::Edge)
                && control.links.predicate
                    != Some(digest_bytes(
                        CANDIDATE_HIERARCHY_PARENT_PREDICATE.as_bytes(),
                    )))
            || (self.candidate_role == Some(CandidateRole::Memory)
                && (control.links.source.is_some()
                    || control.links.target.is_some()
                    || control.links.predicate.is_some()))
        {
            return Err(integrity("record witness graph identity is invalid"));
        }
        Ok(())
    }
}

fn endpoints(document: &MemoryDocument) -> ServiceResult<(&str, &str)> {
    let source = document
        .links
        .source
        .as_deref()
        .ok_or_else(|| integrity("record removal edge source absent"))?;
    let target = document
        .links
        .target
        .as_deref()
        .ok_or_else(|| integrity("record removal edge target absent"))?;
    if source == target {
        return Err(integrity("record removal edge links itself"));
    }
    Ok((source, target))
}
