import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ContextDbClient,
  parseIngestAck,
  ProtocolError,
  Routes,
  TransportError,
} from "../dist/index.js";

const fixture = JSON.parse(
  await readFile(new URL("../../fixtures/http_v1_contract.json", import.meta.url), "utf8"),
);

const auth = () => structuredClone(fixture.authenticated_context);

test("shared signature-evidence fixture has the exact tagged envelope", () => {
  assert.deepEqual(fixture.request_signature_evidence, {
    kind: "request_signature",
    algorithm: "ed25519",
    key_id: "key-1",
    signature: "b".repeat(128),
    signed_context_digest: "c".repeat(64),
  });
});

test("ingest acknowledgement lease deadline is additive and safe-integer bounded", () => {
  const legacyWire = {
    stream_id: "stream-1",
    position: 0,
    disposition: "accepted",
    frame_digest: "frame",
    resume_cursor: "cursor",
    commit_seq: null,
    partial_result_refs: [],
  };
  const legacy = parseIngestAck(legacyWire);
  assert.equal(Object.hasOwn(legacy, "lease_expires_at_ms"), false);
  assert.equal(JSON.stringify(legacy).includes("lease_expires_at_ms"), false);

  const leased = parseIngestAck({
    ...legacyWire,
    lease_expires_at_ms: Number.MAX_SAFE_INTEGER,
  });
  assert.equal(leased.lease_expires_at_ms, Number.MAX_SAFE_INTEGER);
  assert.equal(
    JSON.parse(JSON.stringify(leased)).lease_expires_at_ms,
    Number.MAX_SAFE_INTEGER,
  );

  for (const invalid of [-1, Number.MAX_SAFE_INTEGER + 1, null, true]) {
    assert.throws(
      () => parseIngestAck({ ...legacyWire, lease_expires_at_ms: invalid }),
      ProtocolError,
    );
  }
  assert.throws(() => parseIngestAck({ ...legacyWire, unexpected: 1 }), ProtocolError);
});
const access = () => ({
  workspace_id: "workspace-1",
  scopes: ["project"],
  owners: ["subject-1"],
  audience: ["team"],
  audience_purpose_grants: { team: ["assistant"] },
  purposes: [],
  sensitivity: "private",
  consent: "granted",
  retrievable: true,
});
const watermarks = () => ({ journal: 7, semantic: 7, lexical: 7, vector: 7, graph: 7 });
const document = () => ({
  id: "memory-1",
  kind: "node",
  access: access(),
  valid_time: { from: -1, to: null },
  lifecycle: "active",
  links: {
    subject: null,
    source: null,
    target: null,
    predicate: null,
    conflict_set: null,
    supersedes: [],
    evidence: [],
    conflict_members: [],
    single_valued: false,
  },
  value: { text: "hello" },
  search_text: "hello",
  vector: [0.25, 0.5],
  attributes: { source: "test" },
});
const record = () => ({
  document: document(),
  revision: 1,
  transaction_from: 7,
  transaction_to: null,
});
const json = (value, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });

test("authenticated/domain/admin HTTP surface exercises all 23 added routes", async () => {
  const calls = [];
  const attestations = new Set();
  let providerCalls = 0;
  const runtimePaths = new Set([
    Routes.bootstrap,
    Routes.preflight,
    Routes.postflight,
    Routes.checkpoint,
    Routes.resume,
    Routes.handoff,
  ]);
  const maintenancePaths = new Set([
    Routes.consolidate,
    Routes.reflect,
    Routes.reindex,
    Routes.compact,
  ]);
  const fetch = async (url, init) => {
    const path = new URL(url).pathname;
    const body = JSON.parse(init.body);
    calls.push(path);
    assert.equal(init.headers.get("x-contextdb-gateway-id"), "gateway-1");
    assert.match(init.headers.get("x-contextdb-gateway-attestation"), /^ephemeral-[0-9]+$/);
    attestations.add(init.headers.get("x-contextdb-gateway-attestation"));
    assert.equal(init.headers.get("Content-Type"), "application/json");
    assert.equal(body.context.authentication.kind, "authenticated_channel");
    assert.equal(Object.hasOwn(body.context, "x-contextdb-gateway-attestation"), false);
    if (path === Routes.ingestFrame) {
      return json({ stream_id: "stream-1", position: 0, disposition: "accepted", frame_digest: "frame", resume_cursor: "cursor", commit_seq: null, partial_result_refs: [] });
    }
    if (path === Routes.correct || path === Routes.forget) {
      return json({ commit_seq: 7, replayed: false, request_digest: "digest", watermarks: watermarks() });
    }
    if (path === Routes.subscribe) {
      return json({ events: [{ event_id: "event-1", commit_seq: 7, ordinal: 0, kind: "record_changed", object_refs: ["memory-1"], attributes: {} }], resume_cursor: "cursor", caught_up: true });
    }
    if ([Routes.getNode, Routes.getEvidence, Routes.getConflict].includes(path)) return json(record());
    if (path === Routes.traverse) return json({ node_ids: ["memory-1"], snapshot_seq: 7, authorized_candidates: 1, watermarks: watermarks() });
    if (path === Routes.getTimeline) return json({ revisions: [record()], snapshot_seq: 7, watermarks: watermarks() });
    if (runtimePaths.has(path)) return json({ operation_id: "operation-1", payload: { ok: true } });
    if (maintenancePaths.has(path)) return json({ operation_id: "operation-1", payload: { ok: true } });
    if (path === Routes.getStatus || path === Routes.migrateFormat) return json({
      schema_version: 1,
      profile: "reference",
      commit_seq: 7,
      watermarks: watermarks(),
      capability_manifest: {
        schema_version: 1,
        profile: "reference",
        server_v1_release_ready: false,
        capabilities: {
          background_semantic_adjudication: "unsupported",
          candidate_hierarchy_dag: "unsupported",
          consolidate: "unsupported",
          hard_delete: "unsupported",
          native_graph_store: "unsupported",
          observation_semantic_extraction: "unsupported",
          policy_first_candidate_recall: "unsupported",
          policy_first_candidate_traversal: "unsupported",
          quarantined_memory_proposals: "unsupported",
          reflect: "unsupported",
          status: "available",
        },
      },
    });
    if (path === Routes.createBackup) return json({ format: "contextdb-logical-v1", bytes: [0, 127, 255], digest: "archive", commit_seq: 7 });
    if (path === Routes.restoreBackup) {
      assert.deepEqual(body.bytes, [0, 127, 255]);
      return json({ commit_seq: 7, watermarks: watermarks() });
    }
    throw new Error(`unexpected path ${path}`);
  };
  const client = new ContextDbClient("https://contextdb.invalid", {
    fetch,
    headerProvider: async ({ path, body }) => {
      providerCalls += 1;
      assert.ok(path.startsWith("/v1/"));
      assert.ok(body.includes('"context"'));
      return {
        "x-contextdb-gateway-id": "gateway-1",
        "x-contextdb-gateway-attestation": `ephemeral-${providerCalls}`,
        "Content-Type": "text/plain",
      };
    },
  });
  const context = auth();
  const runtime = { context, operation_id: "operation-1", payload: { input: true } };
  const maintenance = { context, operation_id: "operation-1", payload: { input: true } };
  const get = { context, record_id: "memory-1", at_commit: null };
  await Promise.all([
    client.ingestFrame({ context, stream_id: "stream-1", position: 0, resume_cursor: null, value: { kind: "manifest", value: { source_id: "source-1", revision_id: "revision-1", snapshot_id: "snapshot-1", expected_items: 0, ordered_items_digest: "digest", compression: "identity", attributes: {} } } }),
    client.correct({ context, idempotency_key: "key", target_id: "memory-0", replacement: document() }),
    client.forget({ context, idempotency_key: "key", target_id: "memory-1", mode: "retract", reason: "requested" }),
    client.subscribe({ context, filters: ["record_changed"], resume_cursor: null, max_events: 20 }),
    client.getNode(get),
    client.traverse({ context, start_ids: ["memory-1"], direction: "both", predicate_ids: [], max_hops: 2, max_nodes: 20, at_commit: null }),
    client.getTimeline({ context, record_id: "memory-1", expected_kind: "node", at_commit: null, max_revisions: 20 }),
    client.getEvidence(get),
    client.getConflict(get),
    client.bootstrap(runtime),
    client.preflight(runtime),
    client.postflight(runtime),
    client.checkpoint(runtime),
    client.resume(runtime),
    client.handoff(runtime),
    client.consolidate(maintenance),
    client.reflect(maintenance),
    client.reindex(maintenance),
    client.compact(maintenance),
    client.getStatus({ context }),
    client.createBackup({ context }),
    client.restoreBackup({ context, format: "contextdb-logical-v1", bytes: Uint8Array.from([0, 127, 255]), digest: "archive" }),
    client.migrateFormat({ context, target_format: "contextdb-logical-v1", operation_id: "operation-1" }),
  ]);
  assert.equal(providerCalls, 23);
  assert.equal(attestations.size, 23);
  assert.deepEqual(new Set(calls), new Set([
    Routes.ingestFrame, Routes.correct, Routes.forget, Routes.subscribe,
    Routes.getNode, Routes.traverse, Routes.getTimeline, Routes.getEvidence, Routes.getConflict,
    ...runtimePaths, ...maintenancePaths, Routes.getStatus, Routes.createBackup,
    Routes.restoreBackup, Routes.migrateFormat,
  ]));
});

test("all 29 high-level routes preserve exact fresh attestation bytes", async () => {
  const surface = JSON.parse(
    await readFile(new URL("../../../crates/contextdb-conformance/tests/fixtures/high_level_v1_surface.json", import.meta.url), "utf8"),
  ).http_routes;
  const operationByPath = Object.fromEntries(Object.entries(fixture.routes).map(([name, path]) => [path, name]));
  assert.deepEqual(
    new Set(Object.keys(surface)),
    new Set(Object.values(fixture.routes).slice(-fixture.high_level_surface.route_count)),
  );
  for (const [path, spec] of Object.entries(surface)) {
    for (const capability of spec.capabilities) {
      assert.ok(fixture.capability_routes[capability].includes(operationByPath[path]));
    }
  }
  const providerBodies = [];
  const seen = [];
  const fetch = async (url, init) => {
    const path = new URL(url).pathname;
    seen.push(path);
    assert.equal(init.body, providerBodies.at(-1));
    const spec = surface[path];
    assert.ok(spec);
    if (spec.response === "high_level_mutation") return json({ operation: spec.operation, logical_id: "logical-1", policy_result: "accepted", semantic_status: "pending", receipt: { commit_seq: 7, replayed: false, request_digest: "digest", watermarks: watermarks() } });
    if (spec.response === "recall") return json({ hits: [], trace: { trace_id: "trace", snapshot_seq: 7, operation: "lexical", authorized_candidates: 0, selected_ids: [], watermarks: watermarks() }, continuation: null });
    if (spec.response === "mutation") return json({ commit_seq: 7, replayed: false, request_digest: "digest", watermarks: watermarks() });
    if (spec.response === "export") return json({ format: "contextdb-subject-v1", bytes: [], digest: "digest", commit_seq: 7 });
    return json({ commit_seq: 7, watermarks: watermarks() });
  };
  const client = new ContextDbClient("https://contextdb.invalid", {
    fetch,
    headerProvider: ({ path, body }) => {
      assert.equal(path, Object.keys(surface)[providerBodies.length]);
      providerBodies.push(body);
      return { "x-contextdb-gateway-id": "gateway-1", "x-contextdb-gateway-attestation": `fresh-${providerBodies.length}` };
    },
  });
  const context = auth();
  const write = { context, idempotency_key: "key", target_subject_id: "subject-1", session_id: "session-1", logical_id: "logical-1", access: access(), payload: {}, references: [] };
  const query = { context, target_subject_id: "subject-1", cue: "cue", page_size: 20, at_commit: null, continuation: null };
  const control = { context, idempotency_key: "key", target_subject_id: "subject-1", target_id: "target-1", parameters: {} };
  const transfer = { context, idempotency_key: "key", target_subject_id: "subject-1", format: "contextdb-subject-v1", bytes: new Uint8Array(), digest: "" };
  const calls = [
    ["attachArtifactToEpisode", write], ["deleteArtifactLineage", control], ["addDerivedRepresentation", write],
    ["addEvidenceSelector", write], ["ingestArtifact", write], ["getArtifactMetadata", query],
    ["afterTurn", write], ["beforeTurn", query], ["beginSession", write], ["bootstrapSubject", write],
    ["endSession", write], ["recallSharedHistory", query], ["resolveReferent", query],
    ["changeAudience", control], ["changeRetention", control], ["explainMemory", query],
    ["exportSubject", transfer], ["importSubject", transfer], ["listSubjectMemories", query],
    ["pin", control], ["remember", write], ["suppress", control], ["createRelationshipSpace", write],
    ["publishToSharedMemory", control], ["revokeSharedMemory", control], ["migrateAgentRuntime", control],
    ["updateConfiguredRole", control], ["getContinuityProfile", query], ["createMemorySubject", write],
  ];
  for (const [method, request] of calls) await client[method](request);
  assert.equal(providerBodies.length, 29);
  assert.deepEqual(seen, Object.keys(surface));
});

test("authenticated DTO cannot derive gateway headers and provider failure stops send", async () => {
  let requests = 0;
  const client = new ContextDbClient("https://contextdb.invalid", {
    fetch: async (_url, init) => {
      requests += 1;
      assert.equal(init.headers.has("x-contextdb-gateway-id"), false);
      assert.equal(init.headers.has("x-contextdb-gateway-attestation"), false);
      return json({ stream_id: "stream-1", position: 0, disposition: "accepted", frame_digest: "frame", resume_cursor: "cursor", commit_seq: null, partial_result_refs: [] });
    },
  });
  await client.ingestFrame({
    context: auth(),
    stream_id: "stream-1",
    position: 0,
    resume_cursor: null,
    value: { kind: "manifest", value: { source_id: "source-1", revision_id: "revision-1", snapshot_id: "snapshot-1", expected_items: 0, ordered_items_digest: "digest", compression: "identity", attributes: {} } },
  });
  assert.equal(requests, 1);

  const failing = new ContextDbClient("https://contextdb.invalid", {
    fetch: async () => {
      requests += 1;
      throw new Error("must not send");
    },
    headerProvider: async () => {
      throw new Error("no attestation");
    },
  });
  await assert.rejects(
    failing.ingestFrame({
      context: auth(),
      stream_id: "stream-1",
      position: 0,
      resume_cursor: null,
      value: { kind: "manifest", value: { source_id: "source-1", revision_id: "revision-1", snapshot_id: "snapshot-1", expected_items: 0, ordered_items_digest: "digest", compression: "identity", attributes: {} } },
    }),
    TransportError,
  );
  assert.equal(requests, 1);
});

test("legacy route gets a fresh operation-aware attestation provider call", async () => {
  let providerCalls = 0;
  const providerBodies = [];
  let requests = 0;
  const client = new ContextDbClient("https://contextdb.invalid", {
    headerProvider: async ({ path, body }) => {
      providerCalls += 1;
      providerBodies.push(body);
      assert.equal(path, Routes.verify);
      assert.equal(JSON.parse(body).context.workspace_id, "workspace-1");
      return {
        "x-contextdb-gateway-id": "gateway-1",
        "x-contextdb-gateway-attestation": `ephemeral-${providerCalls}`,
      };
    },
    fetch: async (url, init) => {
      requests += 1;
      assert.equal(new URL(url).pathname, Routes.verify);
      assert.equal(init.body, providerBodies[requests - 1]);
      assert.equal(init.headers.get("x-contextdb-gateway-attestation"), `ephemeral-${requests}`);
      return json({ valid: true, commit_seq: 0, archive_digest: null });
    },
  });
  for (let index = 0; index < 2; index += 1) {
    await client.verify({ context: fixture.authenticated_context.request, deep: true });
  }
  assert.equal(providerCalls, 2);
  assert.equal(requests, 2);
});

test("new nested responses and domain-time integers fail closed", async () => {
  const unknown = record();
  unknown.document.secret = "must fail";
  for (const response of [
    json(unknown),
    json({ ...record(), document: { ...document(), valid_time: { from: 9007199254740992, to: null } } }),
  ]) {
    const client = new ContextDbClient("https://contextdb.invalid", {
      fetch: async () => response.clone(),
    });
    await assert.rejects(client.getNode({ context: auth(), record_id: "memory-1", at_commit: null }), ProtocolError);
  }
  const runtimeClient = new ContextDbClient("https://contextdb.invalid", {
    fetch: async () => json({ operation_id: "operation-1", payload: { sequence: 9007199254740992 } }),
  });
  await assert.rejects(
    runtimeClient.bootstrap({ context: auth(), operation_id: "operation-1", payload: null }),
    ProtocolError,
  );
  const badStatus = {
    schema_version: 1,
    profile: "reference",
    commit_seq: 1,
    watermarks: watermarks(),
    capability_manifest: {
      schema_version: 1,
      profile: "different-profile",
      server_v1_release_ready: false,
      capabilities: { status: "available" },
    },
  };
  const statusClient = new ContextDbClient("https://contextdb.invalid", {
    fetch: async () => json(badStatus),
  });
  await assert.rejects(statusClient.getStatus({ context: auth() }), ProtocolError);
  badStatus.capability_manifest.profile = "reference";
  badStatus.capability_manifest.capabilities.status = "maybe";
  await assert.rejects(statusClient.getStatus({ context: auth() }), ProtocolError);
});

test("deployment headers cannot override HTTP framing", async () => {
  assert.throws(
    () => new ContextDbClient("https://contextdb.invalid", { headers: { "Content-Length": "1" } }),
    TypeError,
  );
  assert.throws(
    () => new ContextDbClient("https://contextdb.invalid", {
      headers: { "x-contextdb-gateway-attestation": "must-not-be-retained" },
    }),
    TypeError,
  );
  const client = new ContextDbClient("https://contextdb.invalid", {
    fetch: async () => json({ valid: true, commit_seq: 0, archive_digest: null }),
    headerProvider: () => ({ "Transfer-Encoding": "chunked" }),
  });
  await assert.rejects(client.verify({ context: fixture.authenticated_context.request, deep: false }), ProtocolError);
});
