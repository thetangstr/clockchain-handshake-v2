import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  LOCAL_RUNTIME_EVIDENCE_SCHEMA,
  RUNTIME_EVIDENCE_SCHEMA,
} from "../src/runtime/runtime-adapter-contract.mjs";
import { runMechanicsProofController } from "../src/testing/mechanics-proof-controller.mjs";
import { createFreshAgentRunnerExecutePair } from "../scripts/run-fresh-agent-handshake.mjs";

const SESSION = "11111111-2222-4333-8444-555555555555";
const HANDSHAKE_EVIDENCE = Object.freeze({ schema: "clockchain.fresh-agent-canary-attempt/v1", ok: true });
const CERTIFICATE_DIGEST = "1".repeat(64);
const HOST_ROOT = "2".repeat(64);
const HOST_CERT = "3".repeat(64);
const SOURCE_COMMIT = "1234567890abcdef1234567890abcdef12345678";

function evidenceDigest(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

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

function awsEvidence(role, runtimeId, overrides = {}) {
  const isInitiator = role === "initiator";
  return {
    schema: RUNTIME_EVIDENCE_SCHEMA,
    runtimeId,
    role,
    taskArn: `arn:aws:ecs:us-west-2:123456789012:task/clockchain/${role}`,
    taskStatus: "STOPPED",
    createdAtMs: 1786337000000,
    stoppedAtMs: 1786337001000,
    taskRoleArn: `arn:aws:iam::123456789012:role/clockchain-${role}-task`,
    executionRoleArn: `arn:aws:iam::123456789012:role/clockchain-${role}-execution`,
    inTaskStsCallerIdentity: {
      account: "123456789012",
      arn: `arn:aws:sts::123456789012:assumed-role/clockchain-${role}-task/session`,
      userId: `ARO${role.toUpperCase()}:session`,
    },
    imageDigest: `sha256:${isInitiator ? "4" : "5"}`.padEnd(71, isInitiator ? "4" : "5"),
    taskDefinitionArn: `arn:aws:ecs:us-west-2:123456789012:task-definition/${role}:1`,
    taskDefinitionRevision: "1",
    taskDefinitionDigest: isInitiator ? "6".repeat(64) : "7".repeat(64),
    eniId: `eni-${role}`,
    subnetId: `subnet-${role}`,
    securityGroupIds: [`sg-${role}`],
    writableVolumeSummary: { ephemeral: true, sharedWritable: false },
    sharedEfsMounts: [],
    secretArnDigests: [isInitiator ? "8".repeat(64) : "9".repeat(64)],
    credentialRefDigest: isInitiator ? "a".repeat(64) : "b".repeat(64),
    workspaceRootDigest: isInitiator ? "c".repeat(64) : "d".repeat(64),
    stateRootDigest: isInitiator ? "e".repeat(64) : "f".repeat(64),
    signerRootDigest: isInitiator ? "0".repeat(64) : "1".repeat(64),
    logStreamDigests: [isInitiator ? "2".repeat(64) : "3".repeat(64)],
    cloudTrailEventDigests: [isInitiator ? "4".repeat(64) : "5".repeat(64)],
    ecsDescribeTasksDigest: isInitiator ? "6".repeat(64) : "7".repeat(64),
    cleanupEvidenceDigest: isInitiator ? "8".repeat(64) : "9".repeat(64),
    sessionSanitizationDigest: isInitiator ? "a".repeat(64) : "b".repeat(64),
    ...overrides,
  };
}

function liveAttemptArtifact(overrides = {}) {
  const receiptIds = [
    "11111111-2222-4333-8444-555555555551",
    "11111111-2222-4333-8444-555555555552",
    "11111111-2222-4333-8444-555555555553",
  ];
  const registration = (agentId) => ({
    agentId,
    chainId: "eip155:11155111",
    reference: `eip155:11155111:0x${"9".repeat(40)}:${agentId}`,
    registrationBlock: "12345",
    registrationTx: `0x${agentId === "101" ? "a" : "b"}`.padEnd(66, agentId === "101" ? "a" : "b"),
    registryAddress: `0x${"9".repeat(40)}`,
  });
  const roleEvidence = (role) => ({
    address: role === "initiator" ? `0x${"1".repeat(40)}` : `0x${"2".repeat(40)}`,
    certificateDigest: CERTIFICATE_DIGEST,
    certificateVerified: true,
    erc8004: registration(role === "initiator" ? "101" : "202"),
    externalBusinessActionPerformed: false,
    policyDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    receiptIds,
    role,
    sessionId: SESSION,
  });
  const artifact = {
    schema: "clockchain.fresh-agent-canary-attempt/v1",
    attemptId: "phase6-live-attempt",
    outcome: "success",
    result: {
      schema: "clockchain.fresh-agent-canary-evidence/v1",
      runId: "phase6-live-run",
      release: { manifestDigest: "6".repeat(64), hostRoots: [HOST_ROOT] },
      clients: { initiator: "codex", responder: "claude" },
      roles: { initiator: roleEvidence("initiator"), responder: roleEvidence("responder") },
      certificateVerified: true,
      binding: {
        certificateDigest: CERTIFICATE_DIGEST,
        hostRootFingerprint: HOST_ROOT,
        hostSessionKeyCertificateDigest: HOST_CERT,
        repositorySha: "1234567890abcdef1234567890abcdef12345678",
        sessionDeadlineMs: 1786337600000,
      },
      monitor: {
        certificate: { digest: CERTIFICATE_DIGEST, issuedAtMs: 1786337100000, outcome: "VERIFIED" },
        checker: { stage: "VERIFIED", lastSeenMs: 1786337100001 },
        hostTrust: {
          rootKid: "root",
          rootFingerprint: HOST_ROOT,
          sessionPublicKey: Buffer.alloc(32, 7).toString("base64"),
          sessionKeyCertificateDigest: HOST_CERT,
        },
        receipts: {
          proposal: { blockHeight: "1", blockTimeRaw: "2026-08-11T12:00:00.000Z", digest: "7".repeat(64), explorerUrl: `https://clockchain.network/ledger/${receiptIds[0]}`, kind: "proposal", ledgerId: receiptIds[0] },
          acceptance: { blockHeight: "2", blockTimeRaw: "2026-08-11T12:01:00.000Z", digest: "8".repeat(64), explorerUrl: `https://clockchain.network/ledger/${receiptIds[1]}`, kind: "acceptance", ledgerId: receiptIds[1] },
          acknowledgment: { blockHeight: "3", blockTimeRaw: "2026-08-11T12:02:00.000Z", digest: "9".repeat(64), explorerUrl: `https://clockchain.network/ledger/${receiptIds[2]}`, kind: "acknowledgment", ledgerId: receiptIds[2] },
        },
        sessionId: SESSION,
      },
      cleanup: { completed: true },
    },
  };
  return { ...artifact, ...overrides };
}

function livePreflight(overrides = {}) {
  return {
    schema: "clockchain.fargate-live-preflight/v1",
    sourceCommit: SOURCE_COMMIT,
    pair: "codex:claude",
    directA2A: true,
    mcpUrl: "https://mcp.clockchain.network/handshake/mcp",
    deploymentReady: false,
    imageProvenanceVerified: false,
    ...overrides,
  };
}

function liveArtifact({ runtimeEvidence, overrides = {} } = {}) {
  const initiatorRuntime = runtimeEvidence?.initiator ?? awsEvidence("initiator", "runtime-initiator");
  const responderRuntime = runtimeEvidence?.responder ?? awsEvidence("responder", "runtime-responder");
  return {
    schema: "clockchain.mechanics-proof-live-artifact/v1",
    sessionId: SESSION,
    sourceCommit: SOURCE_COMMIT,
    clients: { initiator: "codex", responder: "claude" },
    runtimeBindings: {
      initiator: {
        runtimeId: "runtime-initiator",
        taskArn: initiatorRuntime.taskArn,
        runtimeEvidenceDigest: evidenceDigest(initiatorRuntime),
      },
      responder: {
        runtimeId: "runtime-responder",
        taskArn: responderRuntime.taskArn,
        runtimeEvidenceDigest: evidenceDigest(responderRuntime),
      },
    },
    directA2A: {
      agentCardDigests: { initiator: "a".repeat(64), responder: "b".repeat(64) },
      envelopeDigests: ["c".repeat(64), "d".repeat(64)],
      commitmentCheckpointDigests: ["e".repeat(64), "f".repeat(64)],
      controllerRoutedRawContent: false,
    },
    roles: {
      initiator: { address: `0x${"1".repeat(40)}`, erc8004AgentId: "101" },
      responder: { address: `0x${"2".repeat(40)}`, erc8004AgentId: "202" },
    },
    certificateVerified: true,
    certificateDigest: CERTIFICATE_DIGEST,
    cleanup: { completed: true, stoppedAndSanitized: true },
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

function authorityBearingHarnessAdapter(harness, marker) {
  return {
    ...harnessAdapter(harness),
    async executeRetainedAction() {
      marker.called = true;
      throw new Error("must not be reachable");
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
    requireLiveEvidence: false,
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

test("mechanics-proof controller live gate requires fresh success evidence and AWS runtime cleanup", async () => {
  const collected = {};
  const runtime = runtimeAdapter({
    async collectRuntimeEvidence({ runtimeId }) {
      runtime.calls.push(["collect", runtimeId]);
      const role = runtimeId.endsWith("initiator") ? "initiator" : "responder";
      collected[role] = awsEvidence(role, runtimeId);
      return collected[role];
    },
  });

  const result = await runMechanicsProofController(config({
    runtimeAdapter: runtime,
    requireLiveEvidence: true,
    livePreflight: livePreflight(),
    executePair: async (payload) => {
      assert.equal("runtimeAdapter" in payload, false);
      assert.equal("harnessAdapters" in payload, false);
      return liveArtifact({
        runtimeEvidence: {
          initiator: awsEvidence("initiator", "runtime-initiator"),
          responder: awsEvidence("responder", "runtime-responder"),
        },
      });
    },
  }));

  assert.equal(result.handshakeEvidence.certificateVerified, true);
  assert.equal(result.handshakeEvidence.clients.initiator, "codex");
  assert.equal(result.handshakeEvidence.clients.responder, "claude");
  assert.notEqual(result.handshakeEvidence.roles.initiator.erc8004AgentId, result.handshakeEvidence.roles.responder.erc8004AgentId);
  assert.equal(result.runtimeEvidence.initiator.schema, RUNTIME_EVIDENCE_SCHEMA);
  assert.deepEqual(runtime.calls.map((entry) => entry[0]), [
    "provision", "attest", "provision", "attest", "terminate", "destroy", "terminate", "destroy", "collect", "collect",
  ]);
});

test("mechanics-proof controller live gate rejects local evidence and malformed live artifacts", async () => {
  await assert.rejects(() => runMechanicsProofController(config({
    requireLiveEvidence: true,
    livePreflight: livePreflight(),
    executePair: async () => HANDSHAKE_EVIDENCE,
  })));

  const runtime = runtimeAdapter({
    async collectRuntimeEvidence({ runtimeId }) {
      const role = runtimeId.endsWith("initiator") ? "initiator" : "responder";
      return awsEvidence(role, runtimeId);
    },
  });
  for (const artifact of [
    liveAttemptArtifact(),
    liveArtifact({ overrides: { sessionId: "22222222-2222-4333-8444-555555555555" } }),
    liveArtifact({ overrides: { sourceCommit: "abcdefabcdefabcdefabcdefabcdefabcdefabcd" } }),
    liveArtifact({ overrides: { clients: { initiator: "claude", responder: "codex" } } }),
    liveArtifact({ overrides: { runtimeBindings: { ...liveArtifact().runtimeBindings, initiator: { ...liveArtifact().runtimeBindings.initiator, runtimeId: "runtime-responder" } } } }),
    liveArtifact({ overrides: { directA2A: { ...liveArtifact().directA2A, agentCardDigests: { initiator: "a".repeat(64) } } } }),
    liveArtifact({ overrides: { directA2A: { ...liveArtifact().directA2A, envelopeDigests: [] } } }),
    liveArtifact({ overrides: { directA2A: { ...liveArtifact().directA2A, commitmentCheckpointDigests: [] } } }),
    liveArtifact({ overrides: { directA2A: { ...liveArtifact().directA2A, rawTranscript: "private" } } }),
    liveArtifact({ overrides: { certificateVerified: false } }),
    liveArtifact({ overrides: { roles: { initiator: { address: `0x${"1".repeat(40)}`, erc8004AgentId: "101" }, responder: { address: `0x${"1".repeat(40)}`, erc8004AgentId: "202" } } } }),
    liveArtifact({ overrides: { cleanup: { completed: true, stoppedAndSanitized: false } } }),
  ]) {
    await assert.rejects(() => runMechanicsProofController(config({
      requireLiveEvidence: true,
      livePreflight: livePreflight(),
      runtimeAdapter: runtime,
      executePair: async () => artifact,
    })));
  }
});

test("mechanics-proof controller snapshots config before proxy or accessor traps", async () => {
  let traps = 0;
  const proxy = new Proxy({}, {
    ownKeys() {
      traps += 1;
      return [];
    },
    get() {
      traps += 1;
      return "secret-canary /Users/alice/secret";
    },
  });
  await assert.rejects(
    () => runMechanicsProofController(proxy),
    (error) => {
      assert.match(error.message, /Mechanics-proof controller validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);

  await assert.rejects(
    () => runMechanicsProofController({ get sessionId() { throw new Error("secret-canary /Users/alice/secret"); } }),
    (error) => {
      assert.match(error.message, /Mechanics-proof controller validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
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
      assert.equal("harnessAdapters" in payload, false);
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

test("mechanics-proof controller does not expose raw harness adapter action methods to executePair", async () => {
  const marker = { called: false };
  await runMechanicsProofController(config({
    harnessAdapters: {
      initiator: authorityBearingHarnessAdapter("codex", marker),
      responder: harnessAdapter("claude"),
    },
    executePair: async (payload) => {
      assert.equal("harnessAdapters" in payload, false);
      assert.equal("executeRetainedAction" in payload, false);
      assert.equal("executeRetainedAction" in JSON.parse(JSON.stringify(payload)), false);
      return HANDSHAKE_EVIDENCE;
    },
  }));
  assert.equal(marker.called, false);
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
