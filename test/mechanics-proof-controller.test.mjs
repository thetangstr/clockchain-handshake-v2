import assert from "node:assert/strict";
import test from "node:test";

import { LOCAL_RUNTIME_EVIDENCE_SCHEMA } from "../src/runtime/runtime-adapter-contract.mjs";
import { runMechanicsProofController } from "../src/testing/mechanics-proof-controller.mjs";
import { createFreshAgentRunnerExecutePair } from "../scripts/run-fresh-agent-handshake.mjs";

const SESSION = "11111111-2222-4333-8444-555555555555";
const HANDSHAKE_EVIDENCE = Object.freeze({ schema: "clockchain.fresh-agent-canary-attempt/v1", ok: true });

function localEvidence(role, runtimeId, overrides = {}) {
  return {
    schema: LOCAL_RUNTIME_EVIDENCE_SCHEMA,
    provider: "local-shim",
    runtimeId,
    role,
    harness: role === "initiator" ? "codex" : "claude",
    status: "DESTROYED",
    createdAtMs: 1786337000000,
    stoppedAtMs: 1786337000001,
    cleanupCompleted: true,
    sourceCommitDigest: "a".repeat(64),
    credentialRefDigest: role === "initiator" ? "b".repeat(64) : "c".repeat(64),
    workspaceRootDigest: role === "initiator" ? "d".repeat(64) : "e".repeat(64),
    stateRootDigest: role === "initiator" ? "f".repeat(64) : "1".repeat(64),
    signerRootDigest: role === "initiator" ? "2".repeat(64) : "3".repeat(64),
    sessionSanitizationDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    ...overrides,
  };
}

function runtimeAdapter(overrides = {}) {
  const calls = [];
  return {
    calls,
    async provisionPartyRuntime({ role, harness }) {
      calls.push(["provision", role]);
      return Object.freeze({ runtimeId: `runtime-${role}`, role, harness });
    },
    async attestRuntime({ runtimeId }) {
      calls.push(["attest", runtimeId]);
      return Object.freeze({ runtimeId, status: "PROVISIONED" });
    },
    async streamRuntimeEvents({ runtimeId }) {
      calls.push(["stream", runtimeId]);
      return Object.freeze([]);
    },
    async terminateRuntime({ runtimeId }) {
      calls.push(["terminate", runtimeId]);
      return Object.freeze({ runtimeId, status: "STOPPED" });
    },
    async destroyRuntime({ runtimeId }) {
      calls.push(["destroy", runtimeId]);
      return Object.freeze({ runtimeId, destroyed: true });
    },
    async collectRuntimeEvidence({ runtimeId }) {
      calls.push(["collect", runtimeId]);
      const role = runtimeId.endsWith("initiator") ? "initiator" : "responder";
      return localEvidence(role, runtimeId);
    },
    ...overrides,
  };
}

function harnessAdapter(harness) {
  return {
    async inspectCapabilities() {
      return Object.freeze({
        schema: "clockchain.harness-capabilities/v1",
        harness,
        retainedLocalActions: true,
        rawPayloadTransport: false,
      });
    },
  };
}

function config(overrides = {}) {
  return {
    sessionId: SESSION,
    runtimeAdapter: runtimeAdapter(),
    harnessAdapters: {
      initiator: harnessAdapter("codex"),
      responder: harnessAdapter("claude"),
    },
    executePair: async () => HANDSHAKE_EVIDENCE,
    roles: {
      initiator: { harness: "codex", secretsRef: "secret-initiator", stateRef: "state-initiator" },
      responder: { harness: "claude", secretsRef: "secret-responder", stateRef: "state-responder" },
    },
    networkPolicy: { mode: "local-only" },
    ttlMs: 60_000,
    costTags: { phase: "test" },
    ...overrides,
  };
}

test("mechanics-proof controller rejects private authority and authority-bearing terms fields", async () => {
  for (const candidate of [
    config({ signer: "controller-key" }),
    config({ controllerPrivateKey: "secret" }),
    config({ roles: { initiator: { harness: "codex", secretsRef: "secret-initiator", stateRef: "state-initiator", termsOverride: {} }, responder: { harness: "claude", secretsRef: "secret-responder", stateRef: "state-responder" } } }),
    config({ mandateOverrides: { reference: "NS-1847" } }),
  ]) {
    await assert.rejects(() => runMechanicsProofController(candidate));
  }
});

test("mechanics-proof controller rejects shared opaque credential or state refs", async () => {
  await assert.rejects(() => runMechanicsProofController(config({
    roles: {
      initiator: { harness: "codex", secretsRef: "shared-secret", stateRef: "state-initiator" },
      responder: { harness: "claude", secretsRef: "shared-secret", stateRef: "state-responder" },
    },
  })));
  await assert.rejects(() => runMechanicsProofController(config({
    roles: {
      initiator: { harness: "codex", secretsRef: "secret-initiator", stateRef: "shared-state" },
      responder: { harness: "claude", secretsRef: "secret-responder", stateRef: "shared-state" },
    },
  })));
});

test("mechanics-proof controller validates adapter method surfaces", async () => {
  const badRuntime = runtimeAdapter();
  delete badRuntime.destroyRuntime;
  await assert.rejects(() => runMechanicsProofController(config({ runtimeAdapter: badRuntime })));
  await assert.rejects(() => runMechanicsProofController(config({
    harnessAdapters: { initiator: {}, responder: harnessAdapter("claude") },
  })));
});

test("mechanics-proof controller executes pair without private authority and returns separated evidence", async () => {
  const runtime = runtimeAdapter();
  let observed;
  const result = await runMechanicsProofController(config({
    runtimeAdapter: runtime,
    executePair: async (payload) => {
      observed = payload;
      assert.equal(Object.isFrozen(payload), true);
      assert.equal(Object.isFrozen(payload.runtimes.initiator), true);
      assert.equal("runtimeAdapter" in payload, false);
      assert.deepEqual(Object.keys(payload.runtimes.initiator).sort(), ["harness", "role", "runtimeId"]);
      assert.equal("signer" in payload, false);
      assert.equal("privateKey" in JSON.parse(JSON.stringify(payload)), false);
      assert.equal("terms" in payload, false);
      return HANDSHAKE_EVIDENCE;
    },
  }));

  assert.equal(result.handshakeEvidence, HANDSHAKE_EVIDENCE);
  assert.equal(result.runtimeEvidence.initiator.schema, LOCAL_RUNTIME_EVIDENCE_SCHEMA);
  assert.equal(result.runtimeEvidence.responder.cleanupCompleted, true);
  assert.deepEqual(observed.harnessCapabilities.initiator.harness, "codex");
  assert.deepEqual(runtime.calls.map((entry) => entry[0]), [
    "provision", "attest", "provision", "attest", "terminate", "destroy", "terminate", "destroy", "collect", "collect",
  ]);
});

test("mechanics-proof controller rejects authority smuggled through runtime or harness capabilities", async () => {
  const smuggledRuntime = runtimeAdapter({
    async provisionPartyRuntime({ role, harness }) {
      smuggledRuntime.calls.push(["provision", role]);
      return Object.freeze({ runtimeId: `runtime-${role}`, role, harness, signer: "forbidden" });
    },
  });
  await assert.rejects(() => runMechanicsProofController(config({
    runtimeAdapter: smuggledRuntime,
  })));
  assert.deepEqual(smuggledRuntime.calls.map((entry) => entry[0]), ["provision", "terminate", "destroy"]);

  await assert.rejects(() => runMechanicsProofController(config({
    harnessAdapters: {
      initiator: {
        async inspectCapabilities() {
          return {
            schema: "clockchain.harness-capabilities/v1",
            harness: "codex",
            retainedLocalActions: true,
            rawPayloadTransport: false,
            termsOverride: {},
          };
        },
      },
      responder: harnessAdapter("claude"),
    },
  })));
});

test("mechanics-proof controller cleans up after executePair failure and rejects missing cleanup evidence", async () => {
  const runtime = runtimeAdapter();
  await assert.rejects(() => runMechanicsProofController(config({
    runtimeAdapter: runtime,
    executePair: async () => { throw new Error("pair failed"); },
  })));
  assert.deepEqual(runtime.calls.filter((entry) => entry[0] === "destroy").map((entry) => entry[1]), [
    "runtime-initiator", "runtime-responder",
  ]);

  await assert.rejects(() => runMechanicsProofController(config({
    runtimeAdapter: runtimeAdapter({
      async collectRuntimeEvidence({ runtimeId }) {
        const role = runtimeId.endsWith("initiator") ? "initiator" : "responder";
        return localEvidence(role, runtimeId, { cleanupCompleted: false, status: "STOPPED" });
      },
    }),
  })));
});

test("mechanics-proof controller fails after best-effort cleanup errors", async () => {
  const runtime = runtimeAdapter({
    async terminateRuntime({ runtimeId }) {
      runtime.calls.push(["terminate", runtimeId]);
      throw new Error("terminate failed");
    },
  });

  await assert.rejects(() => runMechanicsProofController(config({ runtimeAdapter: runtime })));
  assert.deepEqual(runtime.calls.filter((entry) => entry[0] === "destroy").map((entry) => entry[1]), [
    "runtime-initiator", "runtime-responder",
  ]);
});

test("fresh-agent runner executePair wrapper calls current runFreshAgentHandshake unchanged", async () => {
  const calls = [];
  const executePair = createFreshAgentRunnerExecutePair({
    authentication: Object.freeze({ initiator: { existingLoginIsolated: false, environment: {}, secretCanaries: [] }, responder: { existingLoginIsolated: true, environment: {}, secretCanaries: [] } }),
    clients: Object.freeze({ initiator: "codex", responder: "claude" }),
    parent: "/tmp/fresh-parent",
    prompts: Object.freeze({ initiator: "init", responder: "resp" }),
    release: Object.freeze({ mcp: { manifestDigest: "a".repeat(64), hostRoots: ["b".repeat(64)] }, research: { manifestDigest: "c".repeat(64), hostRoots: ["d".repeat(64)] } }),
    runtime: Object.freeze({ execPath: "/opt/homebrew/opt/node@24/bin/node", version: "v24.0.0" }),
    runFreshAgentHandshakeImpl: async (options) => {
      calls.push(options);
      return HANDSHAKE_EVIDENCE;
    },
    configureClientImpl: async () => {},
    prepareClientImpl: async () => true,
    monitorImpl: async () => {},
  });

  assert.equal(await executePair(Object.freeze({ runtimes: {}, runtimeAdapter: {}, harnessAdapters: {}, harnessCapabilities: {} })), HANDSHAKE_EVIDENCE);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].authenticationModes.initiator, "disposable");
  assert.equal(calls[0].authenticationModes.responder, "existing_login_isolated");
  assert.equal(calls[0].parent, "/tmp/fresh-parent");
  assert.equal("runtimeEvidence" in calls[0], false);
});
