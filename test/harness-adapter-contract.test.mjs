import assert from "node:assert/strict";
import test from "node:test";

import {
  HARNESS_EVENT_SCHEMA,
  RETAINED_LOCAL_ACTION_SCHEMA,
  createLocalHarnessAdapter,
  validateHarnessEvent,
  validateRetainedLocalAction,
} from "../src/harness/harness-adapter-contract.mjs";

const SESSION = "11111111-2222-4333-8444-555555555555";
const DIGEST = "a".repeat(64);

function retainedAction(overrides = {}) {
  return {
    schema: RETAINED_LOCAL_ACTION_SCHEMA,
    sessionId: SESSION,
    role: "initiator",
    actionId: "action-1",
    operation: "verify-certificate",
    requestDigest: DIGEST,
    requestLength: 4247,
    commandSha256: "b".repeat(64),
    commandLength: 97,
    policyDigest: "c".repeat(64),
    issuedAtMs: 1786337000000,
    expiresAtMs: 1786337060000,
    adapterRecordDigest: "d".repeat(64),
    adapterSignature: Buffer.alloc(64, 1).toString("base64"),
    adapterPublicKey: Buffer.alloc(32, 2).toString("base64"),
    ...overrides,
  };
}

test("retained local actions must be adapter-signed and never expose argv or shell payloads", () => {
  assert.equal(validateRetainedLocalAction(retainedAction()).schema, RETAINED_LOCAL_ACTION_SCHEMA);
  for (const candidate of [
    { ...retainedAction(), adapterSignature: undefined },
    { ...retainedAction(), argv: ["node", "helper.cjs"] },
    { ...retainedAction(), shellCommand: "node helper.cjs" },
    { ...retainedAction(), privateKey: "0x" + "a".repeat(64) },
    { ...retainedAction(), requestLength: 0 },
    { ...retainedAction(), expiresAtMs: 1786336999999 },
  ]) {
    assert.throws(() => validateRetainedLocalAction(candidate));
  }
});

test("harness events are normalized, redacted, and non-authoritative", () => {
  const event = {
    schema: HARNESS_EVENT_SCHEMA,
    sessionId: SESSION,
    role: "responder",
    harness: "claude",
    sequence: "1",
    type: "runtime.ready",
    timestampMs: 1786337000000,
    redacted: true,
    publicSummary: "runtime ready",
    evidenceRef: "sha256:" + DIGEST,
  };
  assert.deepEqual(validateHarnessEvent(event), event);
  for (const candidate of [
    { ...event, redacted: false },
    { ...event, transcript: "private message" },
    { ...event, verdict: "VERIFIED" },
    { ...event, publicSummary: "/private/tmp/secret" },
  ]) {
    assert.throws(() => validateHarnessEvent(candidate));
  }
});

test("local harness adapter shim exposes only capabilities and sanitized evidence", async () => {
  const adapter = createLocalHarnessAdapter({ harness: "codex" });
  assert.deepEqual(await adapter.inspectCapabilities({ runtime: { runtimeId: "runtime-1" } }), {
    schema: "clockchain.harness-capabilities/v1",
    harness: "codex",
    retainedLocalActions: true,
    rawPayloadTransport: false,
  });
  const launched = await adapter.launchSession({
    runtime: { runtimeId: "runtime-1", role: "initiator" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: "https://mcp.clockchain.network/handshake/mcp",
    a2aConfig: { mode: "local-shim" },
  });
  await adapter.terminateSession({ sessionId: launched.sessionId, reason: "test" });
  const evidence = await adapter.collectEvidence({ sessionId: launched.sessionId });
  assert.equal(evidence.teardown.completed, true);
  assert.equal(JSON.stringify(evidence).includes("privateKey"), false);
});

test("local harness adapter factory rejects authority fields and missing teardown proof", async () => {
  for (const options of [
    { privateKey: "0x" + "a".repeat(64) },
    { signer: { privateKey: "secret" } },
    { retainedActions: [{ privateKey: "secret" }] },
    { retainedActions: [{ ...retainedAction(), adapterSignature: undefined }] },
  ]) {
    assert.throws(() => createLocalHarnessAdapter(options));
  }
  const adapter = createLocalHarnessAdapter({ harness: "codex" });
  const launched = await adapter.launchSession({
    runtime: { runtimeId: "runtime-1", role: "initiator" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: "https://mcp.clockchain.network/handshake/mcp",
    a2aConfig: { mode: "local-shim" },
  });
  await assert.rejects(() => adapter.collectEvidence({ sessionId: launched.sessionId }));
});
