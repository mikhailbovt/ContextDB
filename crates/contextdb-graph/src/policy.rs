use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::{
    Audience, ConsentStatus, MemorySpaceId, PolicyDecision, Purpose, ScopeKind, SemanticEnvelope,
};

use crate::{PolicyIndexEntry, ReadPrincipal};

pub(crate) fn build_policy(
    workspace_id: contextdb_core::WorkspaceId,
    envelope: &SemanticEnvelope,
) -> PolicyIndexEntry {
    let owners = envelope.ownership.owners.iter().copied().collect();
    let scopes = envelope.scopes.iter().map(|scope| scope.id).collect();
    let mut memory_spaces = envelope
        .scopes
        .iter()
        .filter(|scope| scope.kind == ScopeKind::MemorySpace)
        .filter_map(|scope| MemorySpaceId::from_uuid(scope.id.as_uuid()).ok())
        .collect::<BTreeSet<_>>();
    let mut audience_purposes = BTreeMap::<String, BTreeSet<Purpose>>::new();
    for grant in &envelope.ownership.audience_grants {
        let key = audience_key(&grant.audience);
        if let Audience::MemorySpace { id } = grant.audience {
            memory_spaces.insert(id);
        }
        audience_purposes
            .entry(key)
            .or_default()
            .extend(grant.purposes.iter().cloned());
    }
    let consent_granted = !envelope.consent.required
        || !envelope.consent.decisions.is_empty()
            && envelope
                .consent
                .decisions
                .iter()
                .all(|decision| decision.status == ConsentStatus::Granted);
    PolicyIndexEntry {
        workspace_id,
        scopes,
        owners,
        subjects: [envelope.perspective.knower]
            .into_iter()
            .chain(envelope.perspective.experiencer)
            .collect(),
        memory_spaces,
        audience_purposes,
        allowed_purposes: envelope
            .ownership
            .allowed_purposes
            .iter()
            .cloned()
            .collect(),
        classification: envelope.security.classification,
        compartments: envelope.security.required_compartments.clone(),
        retrievable: envelope.use_policy.retrieve == PolicyDecision::Allow,
        consent_granted,
    }
}

pub(crate) fn allows(policy: &PolicyIndexEntry, principal: &ReadPrincipal) -> bool {
    if policy.workspace_id != principal.workspace_id
        || !policy.retrievable
        || !policy.consent_granted
        || policy.classification > principal.clearance
        || !policy.compartments.is_subset(&principal.compartments)
        || !policy.allowed_purposes.contains(&principal.purpose)
        || !policy.scopes.is_empty() && policy.scopes.is_disjoint(&principal.scopes)
        || !policy.memory_spaces.is_empty()
            && policy.memory_spaces.is_disjoint(&principal.memory_spaces)
    {
        return false;
    }
    let is_owner = policy.owners.contains(&principal.subject);
    policy.audience_purposes.iter().any(|(audience, purposes)| {
        purposes.contains(&principal.purpose)
            && match audience.as_str() {
                "public" => true,
                "owner" => is_owner,
                _ => {
                    audience.as_str() == principal.subject.to_string()
                        || principal
                            .audience_subjects
                            .iter()
                            .any(|subject| audience.as_str() == format!("group:{subject}"))
                        || principal
                            .memory_spaces
                            .iter()
                            .any(|space| audience.as_str() == format!("space:{space}"))
                }
            }
    })
}

pub(crate) fn audience_key(audience: &Audience) -> String {
    match audience {
        Audience::Public => "public".to_owned(),
        Audience::Owner => "owner".to_owned(),
        Audience::Subject { id } => id.to_string(),
        Audience::Group { id } => format!("group:{id}"),
        Audience::MemorySpace { id } => format!("space:{id}"),
    }
}
