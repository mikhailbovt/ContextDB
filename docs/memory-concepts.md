# Memory, identity and consent concepts

ContextDB treats "memory" as attributed, temporal evidence and belief—not a
bag of text snippets.

## Subject, actor and agent

The memory subject is who or what the memory is about. The actor is accountable
for an operation. The agent is the software acting for that actor. A runtime
session may further narrow authority. These identities are independent: an
assistant acting for Alice is not Alice, and a shared workspace is not a shared
subject.

## Perspective

Perspective records whose point of view a statement represents. "I prefer
tea" said by Alice cannot become the assistant's preference or Bob's fact.
First-person language is resolved against authenticated speaker and session
context before publication.

## Ownership and audience

Ownership controls stewardship and lifecycle authority. Audience controls who
may receive a value. Purpose controls why it may be used. A value is usable only
when the resolved audience-purpose grant, scope, clearance, consent and current
policy all permit the operation.

Being an owner does not automatically grant every disclosure purpose. Being in
an audience does not grant mutation or deletion authority.

## Memory spaces and scopes

A workspace is the administrative tenant. A memory space is a durable policy
partition inside it. Scopes are exact semantic grants, not string prefixes or
best-effort filters. Cross-workspace and cross-space influence is rejected
before content access.

## Consent and sensitivity

Consent is explicit policy state. Sensitivity is a label enforced before
retrieval/materialization. `Secret` data fails closed unless a dedicated policy
and protected processing path exists; it is not made safe by prompt wording.

Consent can narrow or revoke future use. Derived summaries and indexes inherit
the source policy and must be invalidated or excluded when that policy changes.

## Current truth, history and unknown

ContextDB preserves both current and historical state. A correction or changed
preference closes/supersedes the earlier head instead of deleting history by
default. Retraction is reversible lifecycle state. Hard deletion erases content
indirections and retains only the minimum non-content proof required by policy.

When evidence is absent, conflicting or stale, the result is explicitly
unknown/disputed. ContextDB does not manufacture a convenient answer to fill a
prompt slot.

## User controls

Correction, retraction, forgetting, privacy changes and sharing are typed
operations. A conversational UI may collect confirmation, but only an
authorized host executor can publish the mutation and return a durable receipt.
No UI acknowledgement is proof that deletion or policy propagation completed.
