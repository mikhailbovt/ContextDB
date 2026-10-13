//! Admission of context metadata before new query authentication and cloning.
//! This does not meter transport decoding, legacy controls or external custody IO.

use contextdb_recall::QueryBudget;
use contextdb_service::{
    AuthenticatedRequestContext, AuthenticationEvidence, Capability, ServiceResult,
};

use crate::{exhausted, invalid, raw_index::budget_error};

/// Checked allocation/work envelope for immutable authenticated metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextCost {
    text_bytes: u64,
    entries: u64,
    signed: bool,
}

impl ContextCost {
    /// Inspect only lengths/cardinalities, charging each visited entry first.
    /// Semantic authentication and its existing error rules remain unchanged.
    pub(crate) fn for_context(
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<Self> {
        parent.charge(1, 0).map_err(budget_error)?;
        if context.request.audiences.len() > 4096
            || context.request.scopes.len() > 4096
            || context.capability_grants.len() > 256
        {
            return Err(exhausted(
                "owned query authenticated metadata set exceeds service bounds",
            ));
        }
        let mut cost = Self {
            text_bytes: 0,
            entries: (context.request.audiences.len()
                + context.request.scopes.len()
                + context.capability_grants.len()) as u64,
            signed: matches!(
                &context.authentication,
                AuthenticationEvidence::RequestSignature { .. }
            ),
        };
        for value in [
            &context.request.request_id,
            &context.request.workspace_id,
            &context.request.subject_id,
            &context.request.purpose,
            &context.actor_id,
            &context.agent_id,
        ]
        .into_iter()
        .chain(context.session_id.iter())
        .chain(context.request.audiences.iter())
        .chain(context.request.scopes.iter())
        {
            cost.add_text(value, parent)?;
        }
        match &context.authentication {
            AuthenticationEvidence::AuthenticatedChannel {
                channel_id,
                peer_identity,
                binding_digest,
            } => {
                for value in [channel_id, peer_identity, binding_digest] {
                    cost.add_text(value, parent)?;
                }
            }
            AuthenticationEvidence::RequestSignature {
                algorithm,
                key_id,
                signature,
                signed_context_digest,
            } => {
                for value in [algorithm, key_id, signature, signed_context_digest] {
                    cost.add_text(value, parent)?;
                }
            }
        }
        // Enum entries cannot carry variable strings, but visiting/copying their
        // bounded tree is work and belongs to the same parent allowance.
        parent
            .charge(context.capability_grants.len() as u64, 0)
            .map_err(budget_error)?;
        Ok(cost)
    }

    fn add_text(&mut self, value: &str, parent: &mut QueryBudget) -> ServiceResult<()> {
        parent.charge(1, 0).map_err(budget_error)?;
        if value.len() > 1024 {
            return Err(invalid(
                "owned query authentication string exceeds service bound",
            ));
        }
        self.text_bytes = self
            .text_bytes
            .checked_add(value.len() as u64)
            .ok_or_else(|| exhausted("owned query authentication metadata size overflow"))?;
        Ok(())
    }

    fn check(
        self,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        if Self::for_context(context, parent)? != self {
            return Err(invalid(
                "owned query authentication cost belongs to different metadata",
            ));
        }
        Ok(())
    }

    fn serialization(self, parent: &mut QueryBudget) -> ServiceResult<()> {
        // JSON escape expansion is <=6 per input byte. Twelve accounts for
        // Vec growth; bounded field names/scalars and tree overhead are explicit.
        let bytes = self
            .text_bytes
            .checked_mul(12)
            .and_then(|bytes| {
                self.entries
                    .checked_mul(128)
                    .and_then(|nodes| bytes.checked_add(nodes))
            })
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or_else(|| exhausted("owned query authentication serialization cost overflow"))?;
        let work = self
            .text_bytes
            .checked_mul(6)
            .and_then(|work| work.checked_add(self.entries * 4 + 256))
            .ok_or_else(|| exhausted("owned query authentication work cost overflow"))?;
        parent.charge(work, bytes).map_err(budget_error)
    }

    /// Pay identifier validation and, for signed authentication, its unsigned
    /// context serialization before calling the unchanged native validator.
    pub(crate) fn require_capability(
        self,
        context: &AuthenticatedRequestContext,
        capability: Capability,
        parent: &mut QueryBudget,
    ) -> ServiceResult<()> {
        self.check(context, parent)?;
        if self.signed {
            self.serialization(parent)?;
        } else {
            // No unsigned serializer for channel auth; reserve only bounded
            // validation/error metadata rather than charging a nonexistent JSON.
            parent
                .charge(self.text_bytes + self.entries * 4 + 256, 4096)
                .map_err(budget_error)?;
        }
        crate::require_capability(context, capability)
    }

    /// Bound the actual authorization-binding serializer before allocation.
    pub(crate) fn binding_digest(
        self,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<String> {
        self.check(context, parent)?;
        self.serialization(parent)?;
        context.authorization_binding_digest()
    }

    /// Bound all strings/trees before constructing the private immutable guard.
    pub(crate) fn clone_context(
        self,
        context: &AuthenticatedRequestContext,
        parent: &mut QueryBudget,
    ) -> ServiceResult<AuthenticatedRequestContext> {
        self.check(context, parent)?;
        let bytes = self.text_bytes + self.entries * 128 + 4096;
        parent
            .charge(self.text_bytes + self.entries + 1, bytes)
            .map_err(budget_error)?;
        Ok(context.clone())
    }
}

pub(crate) fn require_capability(
    context: &AuthenticatedRequestContext,
    capability: Capability,
    parent: &mut QueryBudget,
) -> ServiceResult<()> {
    ContextCost::for_context(context, parent)?.require_capability(context, capability, parent)
}

pub(crate) fn binding_digest(
    context: &AuthenticatedRequestContext,
    parent: &mut QueryBudget,
) -> ServiceResult<String> {
    ContextCost::for_context(context, parent)?.binding_digest(context, parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use contextdb_service::ErrorCode;
    use std::time::Duration;

    fn parent(work: u64, bytes: u64) -> QueryBudget {
        QueryBudget::new(work, bytes, Duration::from_secs(30), Default::default())
    }
    fn signed_context() -> AuthenticatedRequestContext {
        let mut context = crate::capture::tests::request(1, "public auth budget fixture").context;
        context.request.audiences = (0..128)
            .map(|n| format!("audience/{n:04}/{}", "x".repeat(900)))
            .collect();
        context.authentication = AuthenticationEvidence::RequestSignature {
            algorithm: "ed25519".into(),
            key_id: "host-fixture-trust-store".into(),
            signature: "01".repeat(64),
            signed_context_digest: String::new(),
        };
        let digest = context
            .unsigned_context_digest()
            .expect("trusted fixture signature binding");
        if let AuthenticationEvidence::RequestSignature {
            signed_context_digest,
            ..
        } = &mut context.authentication
        {
            *signed_context_digest = digest;
        }
        context
    }

    #[test]
    fn signed_context_refuses_small_parent_before_auth_and_digest_allocation() {
        let context = signed_context();
        let cost = ContextCost::for_context(&context, &mut parent(10000, 0))
            .expect("length census needs no byte allocation");
        let mut malformed = context.clone();
        if let AuthenticationEvidence::RequestSignature {
            signed_context_digest,
            ..
        } = &mut malformed.authentication
        {
            *signed_context_digest = "00".repeat(32);
        }
        // The malformed signature would report Unauthorized if auth validation
        // ran first. Budget refusal proves admission precedes that serializer.
        let error = cost
            .require_capability(
                &malformed,
                Capability::Recall,
                &mut parent(2_000_000, 16 * 1024),
            )
            .expect_err("large signed metadata cannot use a 16 KiB allowance");
        assert_eq!(error.code, ErrorCode::BudgetExhausted);
        assert_eq!(
            cost.binding_digest(&context, &mut parent(2_000_000, 16 * 1024))
                .expect_err("binding preallocation refusal")
                .code,
            ErrorCode::BudgetExhausted
        );
        assert_eq!(
            ContextCost::for_context(&context, &mut parent(0, 0))
                .expect_err("zero work cannot inspect metadata")
                .code,
            ErrorCode::BudgetExhausted
        );
        let cancelled = contextdb_recall::QueryCancellation::default();
        cancelled.cancel();
        let mut stopped = QueryBudget::new(
            2_000_000,
            16 * 1024 * 1024,
            Duration::from_secs(30),
            cancelled,
        );
        let error = cost
            .binding_digest(&context, &mut stopped)
            .expect_err("original cancellation retained");
        assert_eq!(error.code, ErrorCode::BudgetExhausted);
        assert_eq!(error.message, "indexed query cancelled");
        let mut expired = QueryBudget::new(
            2_000_000,
            16 * 1024 * 1024,
            Duration::ZERO,
            Default::default(),
        );
        let error = cost
            .clone_context(&context, &mut expired)
            .expect_err("absolute deadline retained");
        assert_eq!(error.code, ErrorCode::BudgetExhausted);
        assert_eq!(error.message, "indexed deadline exceeded");
        let mut enough = parent(20_000_000, 16 * 1024 * 1024);
        cost.require_capability(&context, Capability::Recall, &mut enough)
            .expect("unchanged signed validator");
        assert_eq!(
            cost.binding_digest(&context, &mut enough)
                .expect("paid exact binding"),
            context
                .authorization_binding_digest()
                .expect("fixture reference")
        );
    }

    #[test]
    fn cached_context_cost_admits_exact_clone_and_refuses_changed_size() {
        let context = signed_context();
        let cost =
            ContextCost::for_context(&context, &mut parent(10000, 0)).expect("bounded census");
        assert_eq!(
            cost.clone_context(&context, &mut parent(2_000_000, 1024))
                .expect_err("clone preallocation refusal")
                .code,
            ErrorCode::BudgetExhausted
        );
        let mut enough = parent(2_000_000, 1024 * 1024);
        assert_eq!(
            cost.clone_context(&context, &mut enough)
                .expect("admitted clone"),
            context
        );
        let mut changed = context.clone();
        changed.request.audiences.insert("new audience".into());
        assert_eq!(
            cost.clone_context(&changed, &mut enough)
                .expect_err("cached cost cannot underprice changed metadata")
                .code,
            ErrorCode::InvalidArgument
        );
    }
}
