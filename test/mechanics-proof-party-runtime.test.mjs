import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { lstat, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createMechanicsProofPartyRuntime } from "../src/testing/mechanics-proof-party-runtime.mjs";

const RUN_ID = "11111111-2222-4333-8444-555555555555";
const PROTOCOL_SESSION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const DIGEST = "a".repeat(64);
const OTHER_DIGEST = "b".repeat(64);
const CERTIFICATE = "-----BEGIN CERTIFICATE-----\npublic-test-certificate\n-----END CERTIFICATE-----\n";

function publicKey() {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" });
}

function options(root, overrides = {}) {
  return {
    harness: "claude",
    listenHost: "0.0.0.0",
    manifestDigest: DIGEST,
    mandate: {
      reference: "northstar-harbor-demo",
      statement: "Confirm both agents agree to the same operational terms.",
      validForSeconds: "10",
      identityPolicy: { erc8004: "required_fresh", chainId: "eip155:11155111", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
    },
    mcpEndpoint: "https://mcp.clockchain.network/handshake/mcp",
    opensslPath: "/usr/bin/openssl",
    port: 8443,
    publicEndpoint: "https://responder.task.local:8443",
    role: "responder",
    root,
    runId: RUN_ID,
    runtimeId: "runtime-responder",
    taskId: "task-responder",
    workloadAttestationDigest: DIGEST,
    ...overrides,
  };
}

function peerDescriptor(overrides = {}) {
  return {
    schema: "clockchain.mechanics-proof-party-bootstrap/v1",
    bootstrapPublicKey: publicKey(),
    harness: "codex",
    role: "initiator",
    runId: RUN_ID,
    runtime: {
      endpoint: "https://initiator.task.local:8443",
      runtimeId: "runtime-initiator",
      taskId: "task-initiator",
      tlsCertificateSha256: OTHER_DIGEST,
      workloadAttestationDigest: OTHER_DIGEST,
    },
    tlsCertificate: CERTIFICATE,
    ...overrides,
  };
}

function dependencies(calls, overrides = {}) {
  const invitation = {
    async close() { calls.push("invitation.close"); return { closed: true }; },
    publicEvidence() { return { sessionId: PROTOCOL_SESSION_ID, invitations: [{ direction: "inbound" }] }; },
    async sendInvitation() { throw new Error("responder must not send invitation"); },
    takeInvitation() { calls.push("invitation.take"); return { invitation: "private-invitation", sessionId: PROTOCOL_SESSION_ID }; },
  };
  const bridgeEvidence = {
    schema: "clockchain.direct-a2a-party-bridge-evidence/v1",
    sessionId: PROTOCOL_SESSION_ID,
    role: "responder",
    cardDigests: { initiator: DIGEST, responder: OTHER_DIGEST },
    invitations: [{ acknowledged: true, invitationDigest: DIGEST }],
    deliveries: [{ acknowledged: true, artifactDigest: DIGEST, artifactType: "acceptance", checkpointDigest: OTHER_DIGEST, messageDigests: [DIGEST, OTHER_DIGEST] }],
    certificate: { verified: true, proofDigest: DIGEST },
  };
  return {
    async createTlsIdentity() {
      calls.push("tls.create");
      return {
        certificate: CERTIFICATE,
        certificateSha256: DIGEST,
        privateKey: "private-runtime-only",
        async destroy() { calls.push("tls.destroy"); return { destroyed: true }; },
      };
    },
    createBootstrapSigner() {
      calls.push("bootstrap.create");
      return { publicKey: publicKey(), signCanonicalBytes() {}, destroy() { calls.push("bootstrap.destroy"); } };
    },
    async createInvitationTransport() { calls.push("invitation.listen"); return invitation; },
    async waitForInvitation() { calls.push("invitation.wait"); return invitation.takeInvitation(); },
    async createActionRecorder() {
      calls.push("recorder.create");
      return {
        actionRecorder: { record() {} },
        trustedAdapterPublicKey: publicKey(),
        setCompletionHandler() {},
        async close() { calls.push("recorder.close"); },
      };
    },
    createCheckpointClient() { calls.push("checkpoint.create"); return { submitCheckpoint() {} }; },
    createBridge() {
      calls.push("bridge.create");
      return {
        async destroy() { calls.push("bridge.destroy"); return { destroyed: true }; },
        publicEvidence() { return bridgeEvidence; },
        observeToolResult() {},
      };
    },
    createProcessTransport() { calls.push("transport.create"); return {}; },
    createHarnessAdapter() {
      calls.push("adapter.create");
      return {
        async launchSession(input) {
          calls.push("agent.launch");
          assert.equal(input.runtime.sessionId, RUN_ID);
          assert.equal(input.a2aConfig.invitationPath.endsWith("/responder-invitation.txt"), true);
          return { sessionId: RUN_ID, role: "responder", harness: "claude" };
        },
        async terminateSession() { calls.push("agent.terminate"); return { terminated: true }; },
        async collectEvidence() {
          calls.push("agent.evidence");
          return { schema: "clockchain.harness-evidence/v1", sessionId: RUN_ID, harness: "claude", role: "responder", terminalStatus: "completed", usage: { inputTokens: "7", outputTokens: "3" }, teardown: { completed: true }, acp: { version: "pinned" } };
        },
      };
    },
    ...overrides,
  };
}

test("one responder runtime listens before launch and returns only digest-bound terminal evidence", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-"));
  const root = join(parent, "responder");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const calls = [];
  const runtime = await createMechanicsProofPartyRuntime(options(root), dependencies(calls));
  const descriptor = runtime.bootstrapDescriptor();
  assert.equal(descriptor.schema, "clockchain.mechanics-proof-party-bootstrap/v1");
  assert.equal(descriptor.runtime.tlsCertificateSha256, DIGEST);
  assert.equal(descriptor.role, "responder");
  assert.doesNotMatch(JSON.stringify(descriptor), /private-runtime-only|roleAccess|invitation/i);
  const evidence = await runtime.run({ peerDescriptor: peerDescriptor() });
  assert.equal(evidence.schema, "clockchain.mechanics-proof-party-evidence/v1");
  assert.equal(evidence.protocolSessionId, PROTOCOL_SESSION_ID);
  assert.equal(evidence.certificateProofDigest, DIGEST);
  assert.equal(evidence.externalBusinessActionPerformed, false);
  assert.equal(evidence.teardown.completed, true);
  assert.doesNotMatch(JSON.stringify(evidence), /private-invitation|roleAccess|signature|transcript|reasoning|BEGIN/i);
  assert.ok(calls.indexOf("invitation.listen") < calls.indexOf("agent.launch"));
  assert.ok(calls.indexOf("invitation.take") < calls.indexOf("agent.launch"));
  for (const expected of ["agent.terminate", "bridge.destroy", "recorder.close", "invitation.close", "bootstrap.destroy", "tls.destroy"]) {
    assert.ok(calls.includes(expected), expected);
  }
});

test("party runtime rejects controller authority, stale state, peer drift, and shared identities", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-reject-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  await assert.rejects(
    () => createMechanicsProofPartyRuntime(options(join(parent, "authority"), { controllerPrivateKey: "forbidden" }), dependencies([])),
    /Mechanics proof party runtime failed safely/,
  );
  await assert.rejects(
    () => createMechanicsProofPartyRuntime(options(join(parent, "harness"), { harness: "other" }), dependencies([])),
    /Mechanics proof party runtime failed safely/,
  );
  const existing = join(parent, "existing");
  await mkdir(existing, { mode: 0o700 });
  await assert.rejects(
    () => createMechanicsProofPartyRuntime(options(existing), dependencies([])),
    /Mechanics proof party runtime failed safely/,
  );

  for (const [name, mutation] of [
    ["runtime", { runtime: { ...peerDescriptor().runtime, runtimeId: "runtime-responder" } }],
    ["workload", { runtime: { ...peerDescriptor().runtime, workloadAttestationDigest: DIGEST } }],
    ["role", { role: "responder" }],
    ["run", { runId: "33333333-4444-4555-8666-777777777777" }],
  ]) {
    const calls = [];
    const runtime = await createMechanicsProofPartyRuntime(options(join(parent, name)), dependencies(calls));
    await assert.rejects(() => runtime.run({ peerDescriptor: peerDescriptor(mutation) }), /Mechanics proof party runtime failed safely/);
  }
});

test("party runtime attempts every teardown and fails closed when any cleanup is incomplete", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-teardown-"));
  const root = join(parent, "responder");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const calls = [];
  const deps = dependencies(calls, {
    async createActionRecorder() {
      calls.push("recorder.create");
      return {
        actionRecorder: { record() {} }, trustedAdapterPublicKey: publicKey(), setCompletionHandler() {},
        async close() { calls.push("recorder.close"); throw new Error("sensitive teardown detail"); },
      };
    },
  });
  const runtime = await createMechanicsProofPartyRuntime(options(root), deps);
  await assert.rejects(() => runtime.run({ peerDescriptor: peerDescriptor() }), (error) => {
    assert.equal(error.message, "Mechanics proof party runtime failed safely.");
    assert.doesNotMatch(error.message, /sensitive/i);
    return true;
  });
  for (const expected of ["agent.terminate", "bridge.destroy", "recorder.close", "invitation.close", "bootstrap.destroy", "tls.destroy"]) {
    assert.ok(calls.includes(expected), expected);
  }
});

test("party runtime removes its exact root when initialization fails", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-init-fail-"));
  const root = join(parent, "responder");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const deps = dependencies([], {
    async createTlsIdentity() { throw new Error("openssl sensitive detail"); },
  });
  await assert.rejects(() => createMechanicsProofPartyRuntime(options(root), deps), /Mechanics proof party runtime failed safely/);
  await assert.rejects(() => lstat(root), { code: "ENOENT" });
});
