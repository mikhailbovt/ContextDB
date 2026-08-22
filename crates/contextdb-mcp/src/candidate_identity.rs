use contextdb_service::{
    AuthenticatedRequestContext, ErrorCode, ServiceError, ServiceResult, StructuredMemoryKind,
};
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

pub(crate) const CANDIDATE_IDENTITY_CONTRACT: &str =
    "contextdb.candidate_identity.nfkc_lower_whitespace.v1";

const MAX_RAW_IDENTITY_BYTES: usize = 4_096;
// A hierarchy identity can contain all sixteen opaque parent IDs. Keep the
// normalized cap aligned with the public raw-input cap so the service's
// supported parent bound remains expressible after normalization.
const MAX_NORMALIZED_IDENTITY_BYTES: usize = 4_096;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DerivedCandidateIdentity {
    pub(crate) candidate_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) identity_digest: String,
    pub(crate) normalized_identity: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CandidateHierarchyContract {
    Project,
    Topic { project_candidate_id: String },
    AnchoredMemory,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ValidatedCandidateIdentity {
    pub(crate) derived: DerivedCandidateIdentity,
    pub(crate) hierarchy: CandidateHierarchyContract,
}

#[derive(Serialize)]
struct IdentityBinding<'a> {
    contract: &'static str,
    workspace_id: &'a str,
    subject_id: &'a str,
    audiences: &'a std::collections::BTreeSet<String>,
    scopes: &'a std::collections::BTreeSet<String>,
    purpose: &'a str,
    clearance: contextdb_service::Sensitivity,
    actor_id: &'a str,
    agent_id: &'a str,
    semantic_kind: StructuredMemoryKind,
    normalized_identity: &'a str,
}

pub(crate) fn validate_and_derive_candidate_identity(
    context: &AuthenticatedRequestContext,
    semantic_kind: StructuredMemoryKind,
    identity_key: &str,
    parent_candidate_ids: &[String],
) -> ServiceResult<ValidatedCandidateIdentity> {
    let normalized_identity = normalize_identity(identity_key)?;
    let hierarchy =
        validate_identity_shape(semantic_kind, &normalized_identity, parent_candidate_ids)?;
    let binding = IdentityBinding {
        contract: CANDIDATE_IDENTITY_CONTRACT,
        workspace_id: &context.request.workspace_id,
        subject_id: &context.request.subject_id,
        audiences: &context.request.audiences,
        scopes: &context.request.scopes,
        purpose: &context.request.purpose,
        clearance: context.request.clearance,
        actor_id: &context.actor_id,
        agent_id: &context.agent_id,
        semantic_kind,
        normalized_identity: &normalized_identity,
    };
    let bytes = serde_json::to_vec(&binding).map_err(|_| {
        ServiceError::new(
            ErrorCode::IntegrityFailure,
            "candidate identity serialization failed",
            false,
        )
    })?;
    let identity_digest = blake3::hash(&bytes).to_hex().to_string();
    Ok(ValidatedCandidateIdentity {
        derived: DerivedCandidateIdentity {
            candidate_id: format!("candidate:auto:v1:{identity_digest}"),
            idempotency_key: format!("candidate-auto-v1:{identity_digest}"),
            identity_digest,
            normalized_identity,
        },
        hierarchy,
    })
}

fn validate_identity_shape(
    semantic_kind: StructuredMemoryKind,
    normalized_identity: &str,
    parent_candidate_ids: &[String],
) -> ServiceResult<CandidateHierarchyContract> {
    match semantic_kind {
        StructuredMemoryKind::Project => {
            let repo_key = normalized_identity
                .strip_prefix("project|repo=")
                .ok_or_else(|| {
                    invalid_contract("project identity must use project|repo=<canonical-repo-key>")
                })?;
            if !parent_candidate_ids.is_empty() {
                return Err(invalid_contract(
                    "project candidates must have zero parent_candidate_ids",
                ));
            }
            validate_repo_key(repo_key)?;
            Ok(CandidateHierarchyContract::Project)
        }
        StructuredMemoryKind::Topic => {
            let topic = normalized_identity
                .strip_prefix("topic|project=")
                .ok_or_else(|| invalid_contract("topic identity must use topic|project=<project-candidate-id>|key=<ascii-kebab-topic>"))?;
            let (project_candidate_id, topic_key) = topic.split_once("|key=").ok_or_else(|| {
                invalid_contract(
                    "topic identity must use topic|project=<project-candidate-id>|key=<ascii-kebab-topic>",
                )
            })?;
            validate_candidate_id(project_candidate_id)?;
            validate_ascii_kebab(topic_key, "topic key")?;
            if parent_candidate_ids != [project_candidate_id] {
                return Err(invalid_contract(
                    "topic parent_candidate_ids must contain exactly the project candidate ID named in identity_key",
                ));
            }
            Ok(CandidateHierarchyContract::Topic {
                project_candidate_id: project_candidate_id.to_owned(),
            })
        }
        kind => {
            let memory = normalized_identity
                .strip_prefix("memory|kind=")
                .ok_or_else(|| invalid_contract("non-project/topic identity must use memory|kind=<semantic-kind>|parents=<sorted-parent-ids>|subject=<ascii-kebab-subject>|revision=<eight-digits>"))?;
            let (identity_kind, memory) = memory.split_once("|parents=").ok_or_else(|| {
                invalid_contract(
                    "non-project/topic identity must include the exact semantic kind and sorted parents",
                )
            })?;
            if identity_kind != structured_kind_name(kind) {
                return Err(invalid_contract(
                    "identity_key semantic kind must exactly match semantic_kind",
                ));
            }
            let (identity_parents, memory) = memory.split_once("|subject=").ok_or_else(|| {
                invalid_contract(
                    "non-project/topic identity must include sorted parents and a subject key",
                )
            })?;
            let (subject_key, revision) = memory.split_once("|revision=").ok_or_else(|| {
                invalid_contract(
                    "non-project/topic identity must end with subject=<ascii-kebab-subject>|revision=<eight-digits>",
                )
            })?;
            validate_ascii_kebab(subject_key, "subject key")?;
            validate_revision(revision)?;
            if parent_candidate_ids.is_empty() {
                return Err(invalid_contract(
                    "non-project/topic candidates require at least one active project or topic parent",
                ));
            }
            if parent_candidate_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                return Err(invalid_contract(
                    "parent_candidate_ids must be unique and sorted in ordinal ascending order",
                ));
            }
            for parent_id in parent_candidate_ids {
                validate_candidate_id(parent_id)?;
            }
            let parsed_parents = identity_parents.split(',').collect::<Vec<_>>();
            if parsed_parents.len() != parent_candidate_ids.len()
                || parsed_parents
                    .iter()
                    .zip(parent_candidate_ids)
                    .any(|(identity_parent, supplied_parent)| *identity_parent != supplied_parent)
            {
                return Err(invalid_contract(
                    "identity_key parents must exactly equal the sorted parent_candidate_ids array",
                ));
            }
            Ok(CandidateHierarchyContract::AnchoredMemory)
        }
    }
}

fn validate_repo_key(repo_key: &str) -> ServiceResult<()> {
    if repo_key.is_empty()
        || repo_key.contains(['\\', '|'])
        || repo_key.ends_with('/')
        || repo_key.chars().any(char::is_uppercase)
    {
        return Err(invalid_contract(
            "repo key must be a lowercase canonical absolute path with forward slashes and no trailing slash",
        ));
    }

    let path = if let Some(unc) = repo_key.strip_prefix("//") {
        let mut parts = unc.split('/');
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        if server.is_empty() || share.is_empty() {
            return Err(invalid_contract(
                "UNC repo key must include nonempty server and share components",
            ));
        }
        unc
    } else if let Some(unix) = repo_key.strip_prefix('/') {
        unix
    } else if repo_key.len() >= 4
        && repo_key.as_bytes()[0].is_ascii_lowercase()
        && repo_key.as_bytes()[1] == b':'
        && repo_key.as_bytes()[2] == b'/'
    {
        &repo_key[3..]
    } else {
        return Err(invalid_contract(
            "repo key must be an absolute POSIX, Windows-drive, or UNC path",
        ));
    };
    if path.is_empty()
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(invalid_contract(
            "repo key must contain only canonical nonempty path components",
        ));
    }
    Ok(())
}

fn validate_candidate_id(candidate_id: &str) -> ServiceResult<()> {
    let digest = candidate_id
        .strip_prefix("candidate:auto:v1:")
        .ok_or_else(|| {
            invalid_contract("parent IDs must be host-derived Candidate identity v1 IDs")
        })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_contract(
            "parent IDs must be host-derived Candidate identity v1 IDs",
        ));
    }
    Ok(())
}

fn validate_ascii_kebab(value: &str, label: &'static str) -> ServiceResult<()> {
    let mut previous_hyphen = true;
    for byte in value.bytes() {
        if byte == b'-' {
            if previous_hyphen {
                return Err(invalid_contract(match label {
                    "topic key" => "topic key must be nonempty lowercase ASCII kebab-case",
                    _ => "subject key must be nonempty lowercase ASCII kebab-case",
                }));
            }
            previous_hyphen = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_hyphen = false;
        } else {
            return Err(invalid_contract(match label {
                "topic key" => "topic key must be nonempty lowercase ASCII kebab-case",
                _ => "subject key must be nonempty lowercase ASCII kebab-case",
            }));
        }
    }
    if previous_hyphen {
        return Err(invalid_contract(match label {
            "topic key" => "topic key must be nonempty lowercase ASCII kebab-case",
            _ => "subject key must be nonempty lowercase ASCII kebab-case",
        }));
    }
    Ok(())
}

fn validate_revision(revision: &str) -> ServiceResult<()> {
    if revision.len() != 8
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
        || revision == "00000000"
    {
        return Err(invalid_contract(
            "memory revision must be eight decimal digits starting at 00000001",
        ));
    }
    Ok(())
}

const fn structured_kind_name(kind: StructuredMemoryKind) -> &'static str {
    match kind {
        StructuredMemoryKind::Project => "project",
        StructuredMemoryKind::Topic => "topic",
        StructuredMemoryKind::Decision => "decision",
        StructuredMemoryKind::Constraint => "constraint",
        StructuredMemoryKind::Goal => "goal",
        StructuredMemoryKind::OpenLoop => "open_loop",
        StructuredMemoryKind::Milestone => "milestone",
        StructuredMemoryKind::Preference => "preference",
        StructuredMemoryKind::Fact => "fact",
        StructuredMemoryKind::EvidenceSummary => "evidence_summary",
    }
}

fn normalize_identity(identity: &str) -> ServiceResult<String> {
    if identity.len() > MAX_RAW_IDENTITY_BYTES {
        return Err(invalid_identity(
            "candidate identity key exceeds the 4096-byte input limit",
        ));
    }
    if identity
        .chars()
        .any(|character| character.is_control() && !character.is_whitespace())
    {
        return Err(invalid_identity(
            "candidate identity key contains a prohibited control character",
        ));
    }

    let compatibility_normalized = identity.nfkc().collect::<String>();
    let lowercase = compatibility_normalized
        .chars()
        .flat_map(char::to_lowercase)
        .collect::<String>();
    let normalized_case = lowercase.nfkc().collect::<String>();
    let mut normalized = String::with_capacity(normalized_case.len());
    let mut pending_space = false;
    for character in normalized_case.chars() {
        if character.is_whitespace() {
            pending_space = !normalized.is_empty();
            continue;
        }
        if pending_space {
            normalized.push(' ');
            pending_space = false;
        }
        normalized.push(character);
    }
    if normalized.is_empty() {
        return Err(invalid_identity(
            "candidate identity key is empty after normalization",
        ));
    }
    if normalized.len() > MAX_NORMALIZED_IDENTITY_BYTES {
        return Err(invalid_identity(
            "normalized candidate identity exceeds the 4096-byte limit",
        ));
    }
    Ok(normalized)
}

fn invalid_identity(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false)
}

fn invalid_contract(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false).with_context(
        Vec::new(),
        None,
        Some(
            "use the exact Candidate identity v1 form advertised by contextdb_ensure_candidate"
                .to_owned(),
        ),
        None,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use contextdb_service::{
        AuthenticatedRequestContext, AuthenticationEvidence, Capability, RequestContext,
        Sensitivity, StructuredMemoryKind,
    };

    use super::{
        CandidateHierarchyContract, normalize_identity, validate_and_derive_candidate_identity,
    };

    fn context() -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            request: RequestContext {
                request_id: "request:test".to_owned(),
                workspace_id: "workspace:test".to_owned(),
                subject_id: "subject:test".to_owned(),
                audiences: BTreeSet::from(["audience:test".to_owned()]),
                scopes: BTreeSet::from(["scope:test".to_owned()]),
                purpose: "assist".to_owned(),
                clearance: Sensitivity::Private,
            },
            actor_id: "actor:test".to_owned(),
            agent_id: "agent:test".to_owned(),
            session_id: Some("session:test".to_owned()),
            authentication: AuthenticationEvidence::AuthenticatedChannel {
                channel_id: "channel:test".to_owned(),
                peer_identity: "actor:test".to_owned(),
                binding_digest: "11".repeat(32),
            },
            capability_grants: BTreeSet::from([Capability::Observe]),
        }
    }

    #[test]
    fn v1_normalization_is_compatibility_case_and_whitespace_stable() {
        assert_eq!(
            normalize_identity("  CONTEXTDB\tＰＲＯＪＥＣＴ  ROOT \n").expect("normalize"),
            "contextdb project root"
        );
    }

    #[test]
    fn v1_project_identity_is_stable_across_codex_session_restart() {
        let mut first = context();
        first.request.workspace_id = "codex-workspace".to_owned();
        first.request.subject_id = "codex-user".to_owned();
        first.request.audiences = BTreeSet::from(["codex-user".to_owned()]);
        first.request.scopes = BTreeSet::from(["work-memory".to_owned()]);
        first.request.purpose = "conversation".to_owned();
        first.actor_id = "codex-user".to_owned();
        first.agent_id = "codex-auto-hierarchy-test".to_owned();
        first.session_id = Some("codex-auto-hierarchy-test-session-a".to_owned());
        let mut second = first.clone();
        second.session_id = Some("codex-auto-hierarchy-test-session-b".to_owned());

        let canonical = validate_and_derive_candidate_identity(
            &first,
            StructuredMemoryKind::Project,
            "project|repo=d:/develop/contextdb",
            &[],
        )
        .expect("canonical project");
        let equivalent = validate_and_derive_candidate_identity(
            &second,
            StructuredMemoryKind::Project,
            "  PROJECT|REPO=D:/DEVELOP/ＣＯＮＴＥＸＴＤＢ  \n",
            &[],
        )
        .expect("equivalent project");
        assert_eq!(canonical.derived, equivalent.derived);
    }

    #[test]
    fn v1_normalization_rejects_empty_control_and_oversized_keys() {
        assert!(normalize_identity(" \n\t ").is_err());
        assert!(normalize_identity("project\u{0000}root").is_err());
        assert!(normalize_identity(&"x".repeat(4_097)).is_err());
        // U+0130 expands when lowercased, so the normalized bound remains
        // independently enforced even when the raw UTF-8 input fits.
        assert!(normalize_identity(&"İ".repeat(1_500)).is_err());
    }

    #[test]
    fn v1_identity_can_represent_the_full_sixteen_parent_bound() {
        let parents = (0..16)
            .map(|index| format!("candidate:auto:v1:{index:064x}"))
            .collect::<Vec<_>>()
            .join(",");
        let key = format!(
            "memory|kind=decision|parents={parents}|subject=hierarchy-bound|revision=00000001"
        );
        assert!(key.len() > 1_024);
        assert_eq!(normalize_identity(&key).expect("normalize"), key);
    }

    #[test]
    fn v1_contract_accepts_exact_project_topic_and_multi_parent_memory_shapes() {
        let context = context();
        let project = validate_and_derive_candidate_identity(
            &context,
            StructuredMemoryKind::Project,
            " PROJECT|REPO=D:/Develop/ＣＯＮＴＥＸＴＤＢ ",
            &[],
        )
        .expect("project identity");
        assert_eq!(project.hierarchy, CandidateHierarchyContract::Project);
        let canonical_project = validate_and_derive_candidate_identity(
            &context,
            StructuredMemoryKind::Project,
            "project|repo=d:/develop/contextdb",
            &[],
        )
        .expect("canonical project identity");
        assert_eq!(
            project.derived.candidate_id, canonical_project.derived.candidate_id,
            "compatibility, case, and outer whitespace must not fork a project root"
        );
        let project_id = project.derived.candidate_id;

        let topic = validate_and_derive_candidate_identity(
            &context,
            StructuredMemoryKind::Topic,
            &format!("topic|project={project_id}|key=automatic-continuity"),
            std::slice::from_ref(&project_id),
        )
        .expect("topic identity");
        assert_eq!(
            topic.hierarchy,
            CandidateHierarchyContract::Topic {
                project_candidate_id: project_id.clone(),
            }
        );
        let topic_id = topic.derived.candidate_id;
        let mut parents = vec![project_id, topic_id];
        parents.sort();
        let memory = validate_and_derive_candidate_identity(
            &context,
            StructuredMemoryKind::Decision,
            &format!(
                "memory|kind=decision|parents={}|subject=automatic-memory|revision=00000001",
                parents.join(",")
            ),
            &parents,
        )
        .expect("memory identity");
        assert_eq!(memory.hierarchy, CandidateHierarchyContract::AnchoredMemory);
    }

    #[test]
    fn v1_contract_rejects_live_malformed_shapes() {
        let context = context();
        assert!(
            validate_and_derive_candidate_identity(
                &context,
                StructuredMemoryKind::Project,
                "project:contextdb",
                &[],
            )
            .is_err()
        );
        assert!(
            validate_and_derive_candidate_identity(
                &context,
                StructuredMemoryKind::Topic,
                "topic:contextdb:automatic-memory",
                &[],
            )
            .is_err()
        );
        assert!(
            validate_and_derive_candidate_identity(
                &context,
                StructuredMemoryKind::Decision,
                "decision:automatic-memory",
                &[],
            )
            .is_err()
        );
    }
}
