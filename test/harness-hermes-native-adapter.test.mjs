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
const KIT_COMMIT = "0123456789abcdef0123456789abcdef01234567";

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
      kitCommit: KIT_COMMIT,
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
    kitCommit: KIT_COMMIT,
    privateKey: "secret",
    retainedActions: [],
    transport: {},
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  }));
  const adapter = createHermesNativeHarnessAdapter({
    kitCommit: KIT_COMMIT,
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

test("Hermes native adapter requires an explicit nonzero lowercase kit commit before transport", async () => {
  const action = retainedAction({ role: "initiator" });
  for (const badKitCommit of [undefined, "0".repeat(40), "A".repeat(40), "abc"]) {
    const calls = [];
    const options = {
      retainedActions: [],
      transport: hermesTransport({ role: "initiator", calls }),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    };
    if (badKitCommit !== undefined) options.kitCommit = badKitCommit;
    assert.throws(() => createHermesNativeHarnessAdapter(options));
    assert.deepEqual(calls, []);
  }
});

test("Hermes native adapter rejects mandate smuggling before transport while allowing public URLs", async () => {
  const action = retainedAction({ role: "initiator" });
  for (const mandate of [
    { reference: "NS-1847", transcript: "hidden" },
    { reference: "NS-1847", reasoning: "hidden" },
    { reference: "NS-1847", nested: { filePath: "/private/tmp/secret" } },
    { reference: "NS-1847", nested: { cwd: "/workspace" } },
    { reference: "NS-1847", nested: { home: "~/state" } },
    { reference: "NS-1847", nested: { publicStatement: "C:\\Users\\secret\\file" } },
  ]) {
    const calls = [];
    const adapter = createHermesNativeHarnessAdapter({
      kitCommit: KIT_COMMIT,
      retainedActions: [],
      transport: hermesTransport({ role: "initiator", calls }),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    await assert.rejects(() => adapter.launchSession({
      runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "hermes" },
      mandate,
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig("initiator"),
    }));
    assert.deepEqual(calls, []);
  }

  const calls = [];
  const adapter = createHermesNativeHarnessAdapter({
    kitCommit: KIT_COMMIT,
    retainedActions: [],
    transport: hermesTransport({ role: "initiator", calls }),
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await adapter.launchSession({
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "hermes" },
    mandate: {
      reference: "NS-1847",
      terms: {
        statement: "Verify the Clockchain mechanics proof.",
        evidenceUrl: "https://example.test/public",
      },
    },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  });
  assert.equal(calls.length, 1);
});

test("Hermes native adapter rejects Proxy inputs before traps execute", async () => {
  const action = retainedAction({ role: "initiator" });
  const counts = { options: 0, runtime: 0, mandate: 0, a2a: 0 };
  const proxy = (key, value) => new Proxy(value, {
    ownKeys(target) {
      counts[key] += 1;
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, property) {
      counts[key] += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  assert.throws(() => createHermesNativeHarnessAdapter(proxy("options", {
    kitCommit: KIT_COMMIT,
    retainedActions: [],
    transport: {},
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  })));
  assert.equal(counts.options, 0);

  const adapter = createHermesNativeHarnessAdapter({
    kitCommit: KIT_COMMIT,
    retainedActions: [],
    transport: {},
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  });
  await assert.rejects(() => adapter.launchSession({
    runtime: proxy("runtime", { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "hermes" }),
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }));
  await assert.rejects(() => adapter.launchSession({
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "hermes" },
    mandate: proxy("mandate", { reference: "NS-1847" }),
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: a2aConfig("initiator"),
  }));
  await assert.rejects(() => adapter.launchSession({
    runtime: { runtimeId: "runtime-initiator", sessionId: SESSION, role: "initiator", harness: "hermes" },
    mandate: { reference: "NS-1847" },
    mcpEndpoint: MCP_ENDPOINT,
    a2aConfig: proxy("a2a", a2aConfig("initiator")),
  }));
  assert.deepEqual(counts, { options: 0, runtime: 0, mandate: 0, a2a: 0 });
});
