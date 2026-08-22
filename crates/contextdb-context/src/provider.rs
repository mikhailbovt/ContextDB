//! Two-phase provider boundary enforcing authorization before payload materialization.

use std::collections::BTreeMap;

use contextdb_core::PolicyDecision;
use contextdb_recall::{AccessRule, ProviderSnapshot, RecallPrincipal};
use serde::{Deserialize, Serialize};

use crate::{
    BlockId, CandidateUsePolicy, ContextError, DisclosureRule, EvidenceHandle, PackCandidate,
    PackEvidence, Result, UseAction,
};

/// Non-content policy label fetched before candidate payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePolicyLabel {
    pub id: BlockId,
    pub access: AccessRule,
    pub use_policy: CandidateUsePolicy,
}

impl CandidatePolicyLabel {
    pub(crate) fn validate(&self) -> Result<()> {
        self.access
            .validate()
            .map_err(|error| ContextError::Provider(error.to_string()))
    }

    /// Evaluates policy metadata without reading the candidate payload.
    #[must_use]
    pub fn authorize(
        &self,
        principal: &RecallPrincipal,
        external_processing: bool,
        explicit_memory_request: bool,
    ) -> Option<UseAction> {
        if !principal.allows(&self.access)
            || !decision_allows(self.use_policy.influence, explicit_memory_request)
            || self.use_policy.disclosure == DisclosureRule::DoNotDisclose
            || (external_processing && self.use_policy.external_model_use != PolicyDecision::Allow)
        {
            return None;
        }

        let mention_allowed = decision_allows(self.use_policy.mention, explicit_memory_request);
        match self.use_policy.disclosure {
            DisclosureRule::MayMention if mention_allowed => Some(UseAction::MentionNaturally),
            DisclosureRule::MentionOnlyWhenExplicit
                if explicit_memory_request && mention_allowed =>
            {
                Some(UseAction::MentionNaturally)
            }
            DisclosureRule::MayMention
            | DisclosureRule::UseSilently
            | DisclosureRule::MentionOnlyWhenExplicit => Some(UseAction::UseSilently),
            DisclosureRule::DoNotDisclose => None,
        }
    }
}

/// Non-content evidence policy label. Raw evidence is authorized independently.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePolicyLabel {
    pub id: EvidenceHandle,
    pub access: AccessRule,
    pub external_model_use: PolicyDecision,
}

impl EvidencePolicyLabel {
    pub(crate) fn validate(&self) -> Result<()> {
        self.access
            .validate()
            .map_err(|error| ContextError::Provider(error.to_string()))
    }

    /// Evaluates evidence authorization before loading its selector or excerpt.
    #[must_use]
    pub fn authorize(&self, principal: &RecallPrincipal, external_processing: bool) -> bool {
        principal.allows(&self.access)
            && (!external_processing || self.external_model_use == PolicyDecision::Allow)
    }
}

/// Provider record used by the reference in-memory implementation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCandidate {
    pub access: AccessRule,
    pub use_policy: CandidateUsePolicy,
    pub candidate: PackCandidate,
}

/// Independently labelled provider evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEvidence {
    pub access: AccessRule,
    pub external_model_use: PolicyDecision,
    pub evidence: PackEvidence,
}

/// Policy-first data provider.
///
/// Callers first expose non-content labels. The compiler invokes payload methods
/// only for labels it authorized. Implementations must return the exact identity
/// requested and must preserve snapshot immutability for the duration of a call.
pub trait ContextProvider: std::fmt::Debug {
    /// Snapshot served by all label and payload reads in this provider instance.
    fn snapshot(&self) -> Result<ProviderSnapshot>;

    /// Candidate policy labels. Ordering is irrelevant; the compiler canonicalizes it.
    fn candidate_labels(&self) -> Result<Vec<CandidatePolicyLabel>>;

    /// Loads one candidate after the compiler has authorized its label.
    fn materialize_candidate(&self, id: &BlockId) -> Result<PackCandidate>;

    /// Evidence policy labels for handles referenced by authorized candidates.
    fn evidence_labels(&self, requested: &[EvidenceHandle]) -> Result<Vec<EvidencePolicyLabel>>;

    /// Loads one evidence unit after its own authorization succeeds.
    fn materialize_evidence(&self, id: &EvidenceHandle) -> Result<PackEvidence>;
}

/// Deterministic in-memory provider suitable for embedding, fixtures, and adapters.
#[derive(Clone, Debug)]
pub struct InMemoryContextProvider {
    snapshot: ProviderSnapshot,
    candidates: BTreeMap<BlockId, ProviderCandidate>,
    evidence: BTreeMap<EvidenceHandle, ProviderEvidence>,
}

impl InMemoryContextProvider {
    /// Creates a provider without validating payloads. Payload validation occurs
    /// only after authorization, so malformed forbidden content remains inert.
    pub fn new(
        snapshot: ProviderSnapshot,
        candidates: Vec<ProviderCandidate>,
        evidence: Vec<ProviderEvidence>,
    ) -> Result<Self> {
        snapshot
            .validate()
            .map_err(|error| ContextError::Provider(error.to_string()))?;
        let mut candidate_map = BTreeMap::new();
        for candidate in candidates {
            let id = candidate.candidate.id.clone();
            if candidate_map.insert(id.clone(), candidate).is_some() {
                return Err(ContextError::Provider(format!(
                    "duplicate provider candidate {id}"
                )));
            }
        }
        let mut evidence_map = BTreeMap::new();
        for evidence in evidence {
            let id = evidence.evidence.id.clone();
            if evidence_map.insert(id.clone(), evidence).is_some() {
                return Err(ContextError::Provider(format!(
                    "duplicate provider evidence {id}"
                )));
            }
        }
        Ok(Self {
            snapshot,
            candidates: candidate_map,
            evidence: evidence_map,
        })
    }
}

impl ContextProvider for InMemoryContextProvider {
    fn snapshot(&self) -> Result<ProviderSnapshot> {
        Ok(self.snapshot.clone())
    }

    fn candidate_labels(&self) -> Result<Vec<CandidatePolicyLabel>> {
        Ok(self
            .candidates
            .iter()
            .map(|(id, entry)| CandidatePolicyLabel {
                id: id.clone(),
                access: entry.access.clone(),
                use_policy: entry.use_policy,
            })
            .collect())
    }

    fn materialize_candidate(&self, id: &BlockId) -> Result<PackCandidate> {
        self.candidates
            .get(id)
            .map(|entry| entry.candidate.clone())
            .ok_or_else(|| ContextError::Provider(format!("candidate {id} is unavailable")))
    }

    fn evidence_labels(&self, requested: &[EvidenceHandle]) -> Result<Vec<EvidencePolicyLabel>> {
        Ok(requested
            .iter()
            .filter_map(|id| {
                self.evidence.get(id).map(|entry| EvidencePolicyLabel {
                    id: id.clone(),
                    access: entry.access.clone(),
                    external_model_use: entry.external_model_use,
                })
            })
            .collect())
    }

    fn materialize_evidence(&self, id: &EvidenceHandle) -> Result<PackEvidence> {
        self.evidence
            .get(id)
            .map(|entry| entry.evidence.clone())
            .ok_or_else(|| ContextError::Provider(format!("evidence {id} is unavailable")))
    }
}

const fn decision_allows(value: PolicyDecision, explicit: bool) -> bool {
    matches!(value, PolicyDecision::Allow)
        || (explicit && matches!(value, PolicyDecision::Conditional))
}
