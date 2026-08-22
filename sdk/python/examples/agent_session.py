"""Minimal provider-neutral agent loop integration."""

from contextdb import (
    AccessPolicy,
    AgentSession,
    Consent,
    ContextDbClient,
    RequestContext,
    Sensitivity,
)

client = ContextDbClient.http(
    "http://127.0.0.1:8080",
    # Optional deployment-owned authentication, when configured:
    # bearer_token="...",
)
context = RequestContext(
    request_id="example-start",
    workspace_id="workspace-1",
    subject_id="subject-1",
    audiences=frozenset({"subject:subject-1"}),
    scopes=frozenset({"project:example"}),
    purpose="assistant",
    clearance=Sensitivity.PRIVATE,
)
access = AccessPolicy(
    workspace_id="workspace-1",
    scopes=frozenset({"project:example"}),
    owners=frozenset({"subject-1"}),
    audience=frozenset({"subject:subject-1"}),
    audience_purpose_grants={"subject:subject-1": frozenset({"assistant"})},
    purposes=frozenset(),
    sensitivity=Sensitivity.PRIVATE,
    consent=Consent.GRANTED,
    retrievable=True,
)

with AgentSession(
    client,
    context=context,
    access=access,
    agent_id="example-agent",
    session_id="example-session",
) as memory:
    recalled = memory.before_turn("What did we decide about the launch?")
    # Feed only authorized `recalled.hits` to your model/provider.
    memory.after_turn(
        "What did we decide about the launch?",
        "We decided to keep the staged rollout.",
    )
