import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";

import { rawEd25519PublicKey } from "../src/agent-handshake/v2/host-key-certificate.mjs";
import {
  HARNESS_EVENT_SCHEMA,
  RETAINED_LOCAL_ACTION_SCHEMA,
  validateHarnessEvent,
} from "../src/harness/harness-adapter-contract.mjs";

export const SESSION = "11111111-2222-4333-8444-555555555555";
export const OTHER_SESSION = "22222222-3333-4444-8555-666666666666";
export const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
export const DIGEST = "a".repeat(64);
export const INVITATION = `${"a".repeat(96)}.${"b".repeat(43)}`;

export function retainedAction(overrides = {}) {
  const { privateKey } = generateKeyPairSync("ed25519");
  const unsigned = {
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
    ...overrides,
  };
  const bodyBytes = Buffer.from(JSON.stringify(unsigned), "utf8");
  const adapterRecordDigest = createHash("sha256").update(bodyBytes).digest("hex");
  return {
    ...unsigned,
    adapterRecordDigest,
    adapterSignature: sign(null, bodyBytes, privateKey).toString("base64"),
    adapterPublicKey: rawEd25519PublicKey(createPublicKey(privateKey)),
  };
}

export function a2aConfig(role) {
  return {
    endpoint: `https://a2a.example.test/${role}`,
    peerCard: {
      id: role === "initiator" ? "responder-card" : "initiator-card",
      endpoint: `https://a2a.example.test/${role === "initiator" ? "responder" : "initiator"}`,
    },
    ...(role === "responder" ? { invitation: INVITATION } : {}),
  };
}

export function transportHarness({ harness, pin, role, calls }) {
  return {
    async launch({ acp, runtime, mandate, mcpEndpoint, a2aConfig: observedA2a }) {
      calls.push(["launch", acp, runtime, mandate, mcpEndpoint, observedA2a]);
      return { sessionId: runtime.sessionId, role, harness };
    },
    async decideLocalAction(args) {
      calls.push(["decide", args]);
      return { decision: "authorize" };
    },
    async executeRetainedAction(args) {
      calls.push(["execute", args]);
      return { executed: true, actionId: args.actionId };
    },
    async streamEvents({ sessionId }) {
      calls.push(["stream", sessionId]);
      return [{
        schema: HARNESS_EVENT_SCHEMA,
        sessionId,
        role,
        harness,
        sequence: "1",
        type: "terminal.status",
        timestampMs: 1786337000000,
        redacted: true,
        publicSummary: "terminal status ready",
        evidenceRef: "sha256:" + DIGEST,
      }];
    },
    async terminate({ sessionId, reason }) {
      calls.push(["terminate", sessionId, reason]);
      return { terminated: true };
    },
    async collectEvidence({ sessionId }) {
      calls.push(["evidence", sessionId]);
      return {
        schema: "clockchain.harness-evidence/v1",
        sessionId,
        harness,
        role,
        terminalStatus: "completed",
        usage: { inputTokens: "1", outputTokens: "2" },
        teardown: { completed: true },
      };
    },
    expectedPin: pin,
  };
}

export async function runAcpAdapterBehavior({ createAdapter, harness, pin, role }) {
  const action = retainedAction({ role });
  const calls = [];
  const adapter = createAdapter({
    decisionCallback({ retainedAction: candidate }) {
      assert.equal(candidate.actionId, action.actionId);
      return { decision: "authorize" };
    },
    nowMs: () => 1786337001000,
    retainedActions: [action],
    transport: transportHarness({ harness, pin, role, calls }),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  const runtime = { runtimeId: `runtime-${role}`, sessionId: SESSION, role, harness };
  const launched = await adapter.launchSession({
    runtime,
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig(role),
  });
  assert.deepEqual(launched, { sessionId: SESSION, role, harness });
  assert.deepEqual(calls[0][1], pin);
  assert.equal(calls[0][4], MCP_ENDPOINT);
  assert.deepEqual(calls[0][5], a2aConfig(role));

  await assert.rejects(() => adapter.decideLocalAction({ sessionId: OTHER_SESSION, role, retainedAction: action }));
  await assert.rejects(() => adapter.decideLocalAction({ sessionId: SESSION, role, retainedAction: { ...action, argv: ["node"] } }));
  assert.deepEqual(await adapter.decideLocalAction({ sessionId: SESSION, role, retainedAction: action }), {
    decision: "authorize",
    retainedAction: action,
  });
  await assert.rejects(() => adapter.executeRetainedAction({ sessionId: SESSION, role, actionId: action.actionId, argv: ["node"] }));
  assert.equal((await adapter.executeRetainedAction({ sessionId: SESSION, role, actionId: action.actionId })).executed, true);
  const executeCall = calls.find((entry) => entry[0] === "execute" && entry[1].actionId === action.actionId);
  assert.deepEqual(Object.keys(executeCall[1]).sort(), ["actionId", "role", "sessionId"]);
  assert.equal(Object.isFrozen(executeCall[1]), true);
  await assert.rejects(() => adapter.executeRetainedAction({ sessionId: SESSION, role, actionId: action.actionId }));

  const events = await adapter.streamEvents({ sessionId: SESSION });
  assert.equal(events.length, 1);
  assert.deepEqual(validateHarnessEvent(events[0]), events[0]);
  await adapter.terminateSession({ sessionId: SESSION, reason: "test-complete" });
  const evidence = await adapter.collectEvidence({ sessionId: SESSION });
  assert.equal(evidence.teardown.completed, true);
  assert.equal(evidence.terminalStatus, "completed");
  assert.deepEqual(evidence.acp, pin);
  assert.equal(JSON.stringify(evidence).includes("transcript"), false);
  assert.equal(JSON.stringify(evidence).includes("reasoning"), false);
}
