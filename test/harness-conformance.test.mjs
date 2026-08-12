import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { HARNESS_EVENT_SCHEMA } from "../src/harness/harness-adapter-contract.mjs";
import { createAcpClaudeHarnessAdapter } from "../src/harness/acp-claude-adapter.mjs";
import { createAcpCodexHarnessAdapter, createAcpHarnessAdapter } from "../src/harness/acp-codex-adapter.mjs";
import { createLocalRuntimeAdapter } from "../src/runtime/runtime-adapter-contract.mjs";
import { runMechanicsProofController } from "../src/testing/mechanics-proof-controller.mjs";
import { ACP_VERSION_PINS, assertAcpPackageLockPins } from "../src/harness/version-pins.mjs";
import { DIGEST, MCP_ENDPOINT, SESSION, a2aConfig, retainedAction, transportHarness } from "./harness-acp-fixtures.mjs";

test("official ACP package versions and lockfile integrity are exact", async () => {
  assert.deepEqual(Object.keys(ACP_VERSION_PINS).sort(), ["claude", "codex"]);
  assert.equal(ACP_VERSION_PINS.codex.version, "1.1.14");
  assert.equal(ACP_VERSION_PINS.claude.version, "0.66.0");
  const lock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
  assertAcpPackageLockPins(lock);
  assert.throws(() => assertAcpPackageLockPins({
    packages: {
      "": { dependencies: { [ACP_VERSION_PINS.codex.packageName]: "^1.1.14", [ACP_VERSION_PINS.claude.packageName]: "0.66.0" } },
      "node_modules/@agentclientprotocol/codex-acp": { version: "1.1.14", integrity: ACP_VERSION_PINS.codex.integrity, bin: { "codex-acp": "dist/index.js" } },
      "node_modules/@agentclientprotocol/claude-agent-acp": { version: "0.66.0", integrity: ACP_VERSION_PINS.claude.integrity, bin: { "claude-agent-acp": "dist/index.js" } },
    },
  }));
});

test("generic ACP harness factory rejects unpinned fake package metadata", () => {
  const action = retainedAction();
  assert.throws(() => createAcpHarnessAdapter({
    harness: "codex",
    pin: {
      packageName: "@evil/fake-acp",
      version: "9.9.9",
      integrity: "sha512-" + "a".repeat(88),
      executableName: "codex-acp",
    },
    retainedActions: [],
    transport: {},
    trustedAdapterPublicKeys: [action.adapterPublicKey],
  }));
});

for (const { name, createAdapter, harness, pin, role } of [
  { name: "Codex", createAdapter: createAcpCodexHarnessAdapter, harness: "codex", pin: ACP_VERSION_PINS.codex, role: "initiator" },
  { name: "Claude", createAdapter: createAcpClaudeHarnessAdapter, harness: "claude", pin: ACP_VERSION_PINS.claude, role: "responder" },
]) {
  test(`${name} ACP adapter remains compatible with the Phase 2 controller inspection path`, async () => {
    const roleConfigs = {
      initiator: { harness: "codex", secretsRef: "secret-initiator", stateRef: "state-initiator" },
      responder: { harness: "claude", secretsRef: "secret-responder", stateRef: "state-responder" },
    };
    const runtimeAdapter = createLocalRuntimeAdapter({ sourceCommit: "0".repeat(40) });
    let observed;
    const result = await runMechanicsProofController({
      sessionId: SESSION,
      runtimeAdapter,
      harnessAdapters: {
        initiator: createAcpCodexHarnessAdapter({ retainedActions: [], transport: {}, trustedAdapterPublicKeys: [retainedAction({ role: "initiator" }).adapterPublicKey] }),
        responder: createAcpClaudeHarnessAdapter({ retainedActions: [], transport: {}, trustedAdapterPublicKeys: [retainedAction({ role: "responder" }).adapterPublicKey] }),
      },
      executePair: async (payload) => {
        observed = payload;
        return { ok: true };
      },
      roles: roleConfigs,
      networkPolicy: { mode: "local-controller" },
      ttlMs: 60_000,
      costTags: { phase: "phase3a" },
    });
    assert.equal(result.handshakeEvidence.ok, true);
    assert.deepEqual(observed.harnessCapabilities.initiator, {
      schema: "clockchain.harness-capabilities/v1",
      harness: "codex",
      retainedLocalActions: true,
      rawPayloadTransport: false,
    });
    assert.deepEqual(observed.harnessCapabilities.responder, {
      schema: "clockchain.harness-capabilities/v1",
      harness: "claude",
      retainedLocalActions: true,
      rawPayloadTransport: false,
    });
  });

  test(`${name} ACP adapter rejects generic MCP endpoints, missing A2A, raw outputs, and authority options`, async () => {
    const action = retainedAction({ role });
    const adapter = createAdapter({
      decisionCallback: () => ({ decision: "authorize" }),
      retainedActions: [action],
      transport: transportHarness({ harness, pin, role, calls: [] }),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    const runtime = { runtimeId: `runtime-${role}`, sessionId: SESSION, role, harness };
    const getterCounts = { options: 0, runtime: 0, a2a: 0, child: 0 };
    assert.throws(() => createAdapter(Object.defineProperty({
      retainedActions: [],
      transport: {},
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    }, "processFactory", {
      enumerable: true,
      get() {
        getterCounts.options += 1;
        return () => {};
      },
    })));
    assert.equal(getterCounts.options, 0);

    await assert.rejects(() => adapter.launchSession({ runtime, mandate: { reference: "NS-1847" }, mcpEndpoint: "https://mcp.clockchain.network/mcp", a2aConfig: a2aConfig(role) }));
    await assert.rejects(() => adapter.launchSession({ runtime, mandate: { reference: "NS-1847" }, mcpEndpoint: MCP_ENDPOINT, a2aConfig: null }));
    await assert.rejects(() => adapter.launchSession({ runtime, mandate: { reference: "NS-1847" }, mcpEndpoint: MCP_ENDPOINT, a2aConfig: { ...a2aConfig(role), transcript: "private" } }));
    await assert.rejects(() => adapter.launchSession({ runtime, mandate: { reference: "NS-1847" }, mcpEndpoint: MCP_ENDPOINT, a2aConfig: { endpoint: a2aConfig(role).endpoint, peerCard: { ...a2aConfig(role).peerCard, extra: "x" } } }));
    await assert.rejects(() => adapter.launchSession({
      runtime: Object.defineProperty({ runtimeId: `runtime-${role}`, sessionId: SESSION, role }, "harness", {
        enumerable: true,
        get() {
          getterCounts.runtime += 1;
          return harness;
        },
      }),
      mandate: { reference: "NS-1847" },
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig(role),
    }));
    assert.equal(getterCounts.runtime, 0);
    await assert.rejects(() => adapter.launchSession({
      runtime,
      mandate: { reference: "NS-1847" },
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: Object.defineProperty({ peerCard: a2aConfig(role).peerCard }, "endpoint", {
        enumerable: true,
        get() {
          getterCounts.a2a += 1;
          return `https://a2a.example.test/${role}`;
        },
      }),
    }));
    assert.equal(getterCounts.a2a, 0);
    assert.throws(() => createAdapter({ privateKey: "secret", retainedActions: [], transport: {}, trustedAdapterPublicKeys: [action.adapterPublicKey] }));
    await assert.rejects(() => adapter.launchSession({ runtime, mandate: { reference: "NS-1847", controllerOverride: true }, mcpEndpoint: MCP_ENDPOINT, a2aConfig: a2aConfig(role) }));
    await assert.rejects(() => adapter.launchSession({ runtime, mandate: { reference: "NS-1847", helper: () => "bad" }, mcpEndpoint: MCP_ENDPOINT, a2aConfig: a2aConfig(role) }));
    await assert.rejects(() => adapter.launchSession({ runtime, mandate: Object.assign(new Date(), { reference: "NS-1847" }), mcpEndpoint: MCP_ENDPOINT, a2aConfig: a2aConfig(role) }));
    const accessorMandate = {};
    Object.defineProperty(accessorMandate, "reference", {
      enumerable: true,
      get() { throw new Error("getter invoked"); },
    });
    await assert.rejects(() => adapter.launchSession({ runtime, mandate: accessorMandate, mcpEndpoint: MCP_ENDPOINT, a2aConfig: a2aConfig(role) }));

    const mandateAdapter = createAdapter({
      retainedActions: [],
      transport: transportHarness({ harness, pin, role, calls: [] }),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    await mandateAdapter.launchSession({
      runtime,
      mandate: {
        reference: "NS-1847",
        terms: {
          statement: "Verify the Clockchain mechanics proof.",
          validForSeconds: "90",
        },
      },
      mcpEndpoint: MCP_ENDPOINT,
      a2aConfig: a2aConfig(role),
    });

    const rawAdapter = createAdapter({
      retainedActions: [],
      transport: {
        async launch() { return { sessionId: SESSION, role, harness }; },
        async streamEvents() {
          return [{
            schema: HARNESS_EVENT_SCHEMA,
            sessionId: SESSION,
            role,
            harness,
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
    await rawAdapter.launchSession({ runtime, mandate: { reference: "NS-1847" }, mcpEndpoint: MCP_ENDPOINT, a2aConfig: a2aConfig(role) });
    await assert.rejects(() => rawAdapter.streamEvents({ sessionId: SESSION }));

    assert.throws(() => createAdapter({
      retainedActions: [],
      transport: Object.defineProperty({}, "launch", {
        enumerable: true,
        get() { throw new Error("transport getter invoked"); },
      }),
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    }));
    assert.throws(() => createAdapter({
      retainedActions: [],
      transport: { launch: "not-a-function" },
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    }));
    const processAdapter = createAdapter({
      retainedActions: [],
      processFactory: async () => Object.defineProperty({}, "launch", {
        enumerable: true,
        get() {
          getterCounts.child += 1;
          return async () => {};
        },
      }),
      transport: {},
      trustedAdapterPublicKeys: [action.adapterPublicKey],
    });
    await assert.rejects(() => processAdapter.launchSession({ runtime, mandate: { reference: "NS-1847" }, mcpEndpoint: MCP_ENDPOINT, a2aConfig: a2aConfig(role) }));
    assert.equal(getterCounts.child, 0);
  });
}
