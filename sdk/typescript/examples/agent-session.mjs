import { AgentSession, ContextDbClient } from "@contextdb/sdk";

const client = new ContextDbClient("http://127.0.0.1:8080");
const context = {
  request_id: "example-start",
  workspace_id: "workspace-1",
  subject_id: "subject-1",
  audiences: ["subject:subject-1"],
  scopes: ["project:example"],
  purpose: "assistant",
  clearance: "private",
};
const access = {
  workspace_id: "workspace-1",
  scopes: ["project:example"],
  owners: ["subject-1"],
  audience: ["subject:subject-1"],
  audience_purpose_grants: { "subject:subject-1": ["assistant"] },
  purposes: [],
  sensitivity: "private",
  consent: "granted",
  retrievable: true,
};
const memory = new AgentSession(client, {
  context,
  access,
  agentId: "example-agent",
  sessionId: "example-session",
});

const recalled = await memory.beforeTurn("What did we decide about the launch?");
// Feed only authorized `recalled.hits` to your model/provider.
await memory.afterTurn(
  "What did we decide about the launch?",
  "We decided to keep the staged rollout.",
);

console.log({ hits: recalled.hits.length, traceId: memory.lastTrace?.trace_id });
