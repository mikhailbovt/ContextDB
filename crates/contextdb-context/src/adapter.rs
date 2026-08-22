//! Binding from deterministic recall output to ContextPack materialization.

use std::collections::{BTreeMap, BTreeSet};

use contextdb_core::PolicyDecision;
use contextdb_recall::{
    DeterministicRecallResult, DocumentId, MemoryUseDecision, ProviderSnapshot,
};
use serde::{Deserialize, Serialize};

use crate::{
    BlockId, CandidatePolicyLabel, ContextError, ContextProvider, EvidenceHandle,
    EvidencePolicyLabel, PackCandidate, PackEvidence, Result,
};

/// Explicit mapping from recall document/evidence identities to canonical pack identities.
///
/// Adapters may keep identities equal, but the mapping makes that assumption visible
/// and rejects missing or many-to-one bindings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecallContextBinding {
    pub documents: BTreeMap<DocumentId, BlockId>,
    pub evidence: BTreeMap<String, EvidenceHandle>,
}

impl RecallContextBinding {
    /// Identity-style binding for providers whose stable document IDs are also block IDs.
    pub fn identity(result: &DeterministicRecallResult) -> Result<Self> {
        let documents = result
            .items
            .iter()
            .filter(|item| item.use_decision.is_included())
            .map(|item| {
                Ok((
                    item.document_id.clone(),
                    BlockId::new(item.document_id.as_str())?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let evidence = result
            .evidence
            .iter()
            .map(|item| {
                Ok((
                    item.evidence.id.clone(),
                    EvidenceHandle::new(&item.evidence.id)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(Self {
            documents,
            evidence,
        })
    }

    fn resolve(&self, result: &DeterministicRecallResult) -> Result<ResolvedBinding> {
        let included_documents: BTreeMap<_, _> = result
            .items
            .iter()
            .filter(|item| item.use_decision.is_included())
            .map(|item| (item.document_id.clone(), item.use_decision))
            .collect();
        let mut blocks = BTreeMap::new();
        for (document, use_decision) in &included_documents {
            let block = self.documents.get(document).ok_or_else(|| {
                ContextError::InvalidRequest(format!(
                    "recall document {document} has no ContextPack binding"
                ))
            })?;
            if blocks.insert(block.clone(), *use_decision).is_some() {
                return Err(ContextError::InvalidRequest(
                    "multiple recalled documents map to one ContextPack block".to_owned(),
                ));
            }
        }
        let selected_evidence_ids: BTreeSet<_> = result
            .evidence
            .iter()
            .filter(|item| included_documents.contains_key(&item.document_id))
            .map(|item| item.evidence.id.clone())
            .collect();
        let mut evidence = BTreeSet::new();
        for id in selected_evidence_ids {
            let handle = self.evidence.get(&id).ok_or_else(|| {
                ContextError::InvalidRequest(format!(
                    "recalled evidence {id} has no ContextPack binding"
                ))
            })?;
            if !evidence.insert(handle.clone()) {
                return Err(ContextError::InvalidRequest(
                    "multiple recalled evidence units map to one ContextPack handle".to_owned(),
                ));
            }
        }
        Ok(ResolvedBinding { blocks, evidence })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedBinding {
    blocks: BTreeMap<BlockId, MemoryUseDecision>,
    evidence: BTreeSet<EvidenceHandle>,
}

/// Provider view restricted to the exact authorized selection emitted by recall.
#[derive(Debug)]
pub struct RecallBoundProvider<'a> {
    inner: &'a dyn ContextProvider,
    snapshot: ProviderSnapshot,
    binding: ResolvedBinding,
}

impl<'a> RecallBoundProvider<'a> {
    /// Binds a provider to a deterministic recall result and verifies the snapshot.
    pub fn new(
        inner: &'a dyn ContextProvider,
        recall: &DeterministicRecallResult,
        binding: &RecallContextBinding,
    ) -> Result<Self> {
        let recall_snapshot = recall.snapshot.clone().ok_or_else(|| {
            ContextError::InvalidRequest("recall result has no fixed snapshot".to_owned())
        })?;
        let provider_snapshot = inner.snapshot()?;
        if recall_snapshot != provider_snapshot {
            return Err(ContextError::InvalidRequest(
                "recall and ContextPack provider snapshots differ".to_owned(),
            ));
        }
        if recall
            .items
            .iter()
            .any(|item| item.use_decision.is_included() && item.content.is_none())
        {
            return Err(ContextError::InvalidRequest(
                "included recall item is missing its authorized content marker".to_owned(),
            ));
        }
        let binding = binding.resolve(recall)?;
        Ok(Self {
            inner,
            snapshot: recall_snapshot,
            binding,
        })
    }
}

impl ContextProvider for RecallBoundProvider<'_> {
    fn snapshot(&self) -> Result<ProviderSnapshot> {
        Ok(self.snapshot.clone())
    }

    fn candidate_labels(&self) -> Result<Vec<CandidatePolicyLabel>> {
        Ok(self
            .inner
            .candidate_labels()?
            .into_iter()
            .filter_map(|mut label| {
                let decision = self.binding.blocks.get(&label.id)?;
                match decision {
                    MemoryUseDecision::IncludeAndMention => {}
                    MemoryUseDecision::IncludeSilently
                    | MemoryUseDecision::IncludeOnlyAsConstraint
                    | MemoryUseDecision::IncludeOnlyAsStyleSignal => {
                        label.use_policy.mention = PolicyDecision::Deny;
                        label.use_policy.disclosure = crate::DisclosureRule::UseSilently;
                    }
                    MemoryUseDecision::WithholdDueToUncertainty
                    | MemoryUseDecision::WithholdDueToPrivacy
                    | MemoryUseDecision::WithholdAsIrrelevant => return None,
                }
                Some(label)
            })
            .collect())
    }

    fn materialize_candidate(&self, id: &BlockId) -> Result<PackCandidate> {
        let Some(decision) = self.binding.blocks.get(id) else {
            return Err(ContextError::Authorization(
                "candidate was not selected by the bound recall result".to_owned(),
            ));
        };
        let candidate = self.inner.materialize_candidate(id)?;
        match decision {
            MemoryUseDecision::IncludeOnlyAsConstraint
                if candidate.interpretation != crate::InterpretationRule::ConstraintData =>
            {
                Err(ContextError::InvalidRequest(
                    "recall constraint-only decision is incompatible with candidate semantics"
                        .to_owned(),
                ))
            }
            MemoryUseDecision::IncludeOnlyAsStyleSignal
                if candidate.interpretation != crate::InterpretationRule::StyleSignal =>
            {
                Err(ContextError::InvalidRequest(
                    "recall style-only decision is incompatible with candidate semantics"
                        .to_owned(),
                ))
            }
            MemoryUseDecision::WithholdDueToUncertainty
            | MemoryUseDecision::WithholdDueToPrivacy
            | MemoryUseDecision::WithholdAsIrrelevant => Err(ContextError::Authorization(
                "withheld recall item cannot be materialized".to_owned(),
            )),
            MemoryUseDecision::IncludeAndMention
            | MemoryUseDecision::IncludeSilently
            | MemoryUseDecision::IncludeOnlyAsConstraint
            | MemoryUseDecision::IncludeOnlyAsStyleSignal => Ok(candidate),
        }
    }

    fn evidence_labels(&self, requested: &[EvidenceHandle]) -> Result<Vec<EvidencePolicyLabel>> {
        let allowed: Vec<_> = requested
            .iter()
            .filter(|handle| self.binding.evidence.contains(*handle))
            .cloned()
            .collect();
        self.inner.evidence_labels(&allowed)
    }

    fn materialize_evidence(&self, id: &EvidenceHandle) -> Result<PackEvidence> {
        if !self.binding.evidence.contains(id) {
            return Err(ContextError::Authorization(
                "evidence was not selected by the bound recall result".to_owned(),
            ));
        }
        self.inner.materialize_evidence(id)
    }
}
