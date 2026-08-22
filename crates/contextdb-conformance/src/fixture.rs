use std::collections::{BTreeMap, BTreeSet};

use contextdb_service::{
    AccessPolicy, Consent, ObserveRequest, RecallRequest, RequestContext, Sensitivity,
};
use serde::{Deserialize, Serialize};

/// Deterministic cross-interface fixture. It deliberately includes two visible
/// memories, one forbidden memory with the same lexical terms, and a later
/// visible memory used to prove snapshot-bound continuation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceFixture {
    /// Commit head after the canonical semantic seed transaction.
    pub initial_commit_seq: u64,
    /// Authorized semantic record identities expected from recall.
    pub expected_visible_ids: Vec<String>,
    /// Seeded semantic record which must never influence the caller's result.
    pub forbidden_semantic_id: String,
    /// Authorized caller.
    pub caller: RequestContext,
    /// A different principal in the same workspace.
    pub other_principal: RequestContext,
    /// Administrative caller for archive/verify operations.
    pub administrator: RequestContext,
    /// First visible observation.
    pub visible_a: ObserveRequest,
    /// Second visible observation.
    pub visible_b: ObserveRequest,
    /// Same cue, but inaccessible to the caller.
    pub forbidden: ObserveRequest,
    /// Visible observation committed after the first recall page.
    pub late_visible: ObserveRequest,
    /// Stable lexical cue shared by all observations.
    pub query: String,
}

impl Default for ConformanceFixture {
    fn default() -> Self {
        Self::standard()
    }
}

impl ConformanceFixture {
    /// Builds the canonical M15 fixture.
    #[must_use]
    pub fn standard() -> Self {
        let caller = context("request:fixture", "subject:alice", "assist");
        let other_principal = context("request:fixture", "subject:bob", "assist");
        let administrator = RequestContext {
            request_id: "request:admin".to_owned(),
            workspace_id: "workspace:conformance".to_owned(),
            subject_id: "subject:admin".to_owned(),
            audiences: BTreeSet::from(["subject:admin".to_owned()]),
            scopes: BTreeSet::from(["project:conformance".to_owned()]),
            purpose: "contextdb:admin".to_owned(),
            clearance: Sensitivity::Restricted,
        };
        Self {
            initial_commit_seq: 1,
            expected_visible_ids: vec![
                "semantic:visible-a".to_owned(),
                "semantic:visible-b".to_owned(),
            ],
            forbidden_semantic_id: "semantic:forbidden".to_owned(),
            visible_a: observation(
                &caller,
                "idempotency:visible-a",
                "observation:visible-a",
                "subject:alice",
                "Japan bar served yuzu tea beside the station",
            ),
            visible_b: observation(
                &caller,
                "idempotency:visible-b",
                "observation:visible-b",
                "subject:alice",
                "Japan bar had quiet seats and a blue entrance",
            ),
            forbidden: observation(
                &other_principal,
                "idempotency:forbidden",
                "observation:forbidden",
                "subject:bob",
                "Japan bar secret bankruptcy dossier and private code",
            ),
            late_visible: observation(
                &caller,
                "idempotency:late",
                "observation:late",
                "subject:alice",
                "Japan bar later added a rooftop room",
            ),
            caller,
            other_principal,
            administrator,
            query: "Japan bar".to_owned(),
        }
    }

    /// Creates a recall request bound to this fixture's caller.
    #[must_use]
    pub fn recall(&self, page_size: u32) -> RecallRequest {
        RecallRequest {
            context: self.caller.clone(),
            query: self.query.clone(),
            page_size,
            at_commit: None,
            continuation: None,
        }
    }

    /// Reuses the first idempotency key with changed canonical input.
    #[must_use]
    pub fn idempotency_conflict(&self) -> ObserveRequest {
        let mut request = self.visible_a.clone();
        request.content = serde_json::json!({"text": "changed payload"});
        request
    }

    /// Produces an otherwise valid observation with no owner.
    #[must_use]
    pub fn policy_omission(&self) -> ObserveRequest {
        let mut request = self.visible_a.clone();
        request.idempotency_key = "idempotency:missing-owner".to_owned();
        request.observation_id = "observation:missing-owner".to_owned();
        request.access.owners.clear();
        request
    }
}

fn context(request_id: &str, subject: &str, purpose: &str) -> RequestContext {
    RequestContext {
        request_id: request_id.to_owned(),
        workspace_id: "workspace:conformance".to_owned(),
        subject_id: subject.to_owned(),
        audiences: BTreeSet::from([subject.to_owned()]),
        scopes: BTreeSet::from(["project:conformance".to_owned()]),
        purpose: purpose.to_owned(),
        clearance: Sensitivity::Private,
    }
}

fn observation(
    caller: &RequestContext,
    idempotency_key: &str,
    observation_id: &str,
    audience: &str,
    text: &str,
) -> ObserveRequest {
    ObserveRequest {
        context: caller.clone(),
        idempotency_key: idempotency_key.to_owned(),
        observation_id: observation_id.to_owned(),
        metadata: BTreeMap::from([("source".to_owned(), serde_json::json!("m15-fixture"))]),
        content: serde_json::json!({"text": text}),
        access: AccessPolicy {
            workspace_id: caller.workspace_id.clone(),
            scopes: caller.scopes.clone(),
            owners: BTreeSet::from([audience.to_owned()]),
            audience: BTreeSet::from([audience.to_owned()]),
            audience_purpose_grants: BTreeMap::new(),
            purposes: BTreeSet::from([caller.purpose.clone()]),
            sensitivity: Sensitivity::Private,
            consent: Consent::Granted,
            retrievable: true,
        },
    }
}
