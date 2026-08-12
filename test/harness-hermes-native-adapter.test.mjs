import assert from "node:assert/strict";
import test from "node:test";

import { createHermesNativeHarnessAdapter } from "../src/harness/hermes-native-adapter.mjs";
import { DIGEST, MCP_ENDPOINT, SESSION, a2aConfig, retainedAction } from "./harness-acp-fixtures.mjs";

const HERMES_TOOLS = Object.freeze([
  "agent_handshake_invite",
  "agent_handshake_accept_invitation",
  "agent_handshake_join",
  "agent_handshake_status",
  "agent_handshake_next",
  "agent_handshake_submit",
  "agent_handshake_get_certificate",
]);

function hermesTransport({ role, calls }) {
  return {
    async launch(args) {
      calls.push(["launch", args]);
      return { sessionId: args.runtime.sessionId, role, harness: "hermes" };
    },
    async executeRetainedAction(args) {
      calls.push(["execute", args]);
      return { executed: true, actionId: args.actionId };
    },
    async streamEvents({ sessionId }) {
      calls.push(["stream", sessionId]);
      return [{
        schema: "clockchain.harness-event/v1",
        sessionId,
        role,
        harness: "hermes",
        sequence: "1",
        type: "terminal.status",
        timestampMs: 1786337000000,
        redacted: true,
        publicSummary: "hermes terminal status ready",
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
        harness: "hermes",
        role,
        terminalStatus: "completed",
        usage: { inputTokens: "3", outputTokens: "4" },
        teardown: { completed: true },
      };
    },
  };
}

for (const role of ["initiator", "responder"]) {
  test(`Hermes native adapter satisfies retained-action harness conformance as ${role}`, async () => {
    const action = retainedAction({ role });
    const calls = [];
    const adapter = createHermesNativeHarnessAdapter({
      decisionCallback({ retainedAction: candidate }) {
        assert.equal(candidate.actionId, action.actionId);
        return { decision: "authorize" };
      },
      nowMs: () => 1786337001000,
      retainedActions: [action],
      transport: hermesTransport({ role, calls }),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    assert.deepEqual(await adapter.inspectCapabilities(), {
      schema: "clockchain.harness-capabilities/v1",
      harness: "hermes",
      retainedLocalActions: true,
      rawPayloadTransport: false,
    });
    const launched = await adapter.launchSession({
      runtime: { runtimeId: `runtime-${role}`, sessionId: SESSION, role, harness: "hermes" },
      mandate: { reference: "NS-1847", statement: "Two stakeholder agents may communicate about shipment NS-1847." },
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig(role),
    });
    assert.deepEqual(launched, { sessionId: SESSION, role, harness: "hermes" });
    const launch = calls.find((entry) => entry[0] === "launch")[1];
    assert.equal(launch.mcpEndpoint, MCP_ENDPOINT);
    assert.deepEqual(launch.tools, HERMES_TOOLS);
    assert.deepEqual(launch.a2aConfig, a2aConfig(role));
    assert.equal(launch.publicRole, role);
    assert.equal(launch.legacyRole, role === "initiator" ? "payer" : "requestor");
    assert.match(launch.prompt, new RegExp(`Role: ${role === "initiator" ? "Initiator" : "Responder"}`));
    assert.doesNotMatch(launch.prompt, /payer|requestor|payment|invoice/i);

    assert.deepEqual(await adapter.decideLocalAction({ sessionId: SESSION, role, retainedAction: action }), {
      decision: "authorize",
      retainedAction: action,
    });
    await assert.rejects(() => adapter.executeRetainedAction({ sessionId: SESSION, role, actionId: action.actionId, argv: ["node"] }));
    assert.equal((await adapter.executeRetainedAction({ sessionId: SESSION, role, actionId: action.actionId })).executed, true);
    const execute = calls.find((entry) => entry[0] === "execute")[1];
    assert.deepEqual(Object.keys(execute).sort(), ["actionId", "role", "sessionId"]);
    assert.equal(Object.isFrozen(execute), true);
    await assert.rejects(() => adapter.executeRetainedAction({ sessionId: SESSION, role, actionId: action.actionId }));

    const events = await adapter.streamEvents({ sessionId: SESSION });
    assert.equal(events.length, 1);
    await adapter.terminateSession({ sessionId: SESSION, reason: "test-complete" });
    const evidence = await adapter.collectEvidence({ sessionId: SESSION });
    assert.equal(evidence.harness, "hermes");
    assert.equal(evidence.role, role);
    assert.equal(evidence.teardown.completed, true);
    assert.equal(JSON.stringify(evidence).includes("transcript"), false);
    assert.equal(JSON.stringify(evidence).includes("reasoning"), false);
  });
}

test("Hermes native adapter rejects generic MCP endpoints, raw events, and authority options", async () => {
  const action = retainedAction({ role: "initiator" });
  assert.throws(() => createHermesNativeHarnessAdapter({
    privateKey: "secret",
    retainedActions: [],
    transport: {},
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  }));
  const adapter = createHermesNativeHarnessAdapter({
    retainedActions: [],
    transport: {
      async launch() {},
      async streamEvents() {
        return [{
          schema: "clockchain.harness-event/v1",
          sessionId: SESSION,
          role: "initiator",
          harness: "hermes",
          sequence: "1",
          type: "raw",
          timestampMs: 1786337000000,
          redacted: true,
          publicSummary: "raw",
          evidenceRef: "sha256:" + DIGEST,
          transcript: "private",
        }];
      },
    },
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  const runtime = { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "hermes" };
  await assert.rejects(() => adapter.launchSession({ runtime, mandate: { reference: "NS-1847" }, mcpEndpoint: "https://mcp.clockchain.network/mcp", a2aConfig: a2aConfig("initiator") }));
  await adapter.launchSession({ runtime, mandate: { reference: "NS-1847" }, mcpEndpoint: MCP_ENDPOINT, a2aConfig: a2aConfig("initiator") });
  await assert.rejects(() => adapter.streamEvents({ sessionId: SESSION }));
});
