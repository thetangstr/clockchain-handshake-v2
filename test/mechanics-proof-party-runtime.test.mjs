import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { lstat, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createMechanicsProofPartyRuntime,
  mechanicsProofPartyRuntimeFailureStage,
} from "../src/testing/mechanics-proof-party-runtime.mjs";
import { createVerifiedReleaseActionRecorder } from "../src/harness/verified-release-action-recorder.mjs";

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
  const { bridgeEvidence: customBridgeEvidence, ...dependencyOverrides } = overrides;
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
    cardSignerAddresses: {
      initiator: "0x2222222222222222222222222222222222222222",
      responder: "0x1111111111111111111111111111111111111111",
    },
    invitations: [{ acknowledged: true, invitationDigest: DIGEST }],
    deliveries: [{ acknowledged: true, artifactDigest: DIGEST, artifactType: "acceptance", checkpointDigest: OTHER_DIGEST, messageDigests: [DIGEST, OTHER_DIGEST] }],
    certificate: {
      verified: true,
      proofDigest: DIGEST,
      certificateDigest: OTHER_DIGEST,
      resultDigest: DIGEST,
      identity: {
        sessionKeyAddress: "0x1111111111111111111111111111111111111111",
        policyDigest: DIGEST,
        erc8004: {
          agentId: "9453",
          chainId: "eip155:11155111",
          registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
          reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9453",
          registrationTx: "0x" + "1".repeat(64),
          registrationBlock: "7001",
        },
      },
      anchors: [
        { blockHeight: "7010", digest: DIGEST, kind: "proposal", ledgerId: "33333333-4444-4555-8666-777777777770" },
        { blockHeight: "7011", digest: OTHER_DIGEST, kind: "acceptance", ledgerId: "33333333-4444-4555-8666-777777777771" },
        { blockHeight: "7012", digest: "c".repeat(64), kind: "acknowledgment", ledgerId: "33333333-4444-4555-8666-777777777772" },
      ],
    },
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
    async createInvitationTransport(input) {
      calls.push("invitation.listen");
      assert.deepEqual(Object.keys(input.bootstrapSigner).sort(), ["publicKey", "signCanonicalBytes"]);
      assert.equal("destroy" in input.bootstrapSigner, false);
      return invitation;
    },
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
        publicEvidence() { return customBridgeEvidence ?? bridgeEvidence; },
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
          if (input.runtime.role === "responder") {
            assert.equal(input.a2aConfig.invitationPath.endsWith("/responder-invitation.txt"), true);
          } else {
            assert.equal("invitationPath" in input.a2aConfig, false);
          }
          return { sessionId: RUN_ID, role: "responder", harness: "claude" };
        },
        async terminateSession() { calls.push("agent.terminate"); return { terminated: true }; },
        async collectEvidence() {
          calls.push("agent.evidence");
          return { schema: "clockchain.harness-evidence/v1", sessionId: RUN_ID, harness: "claude", role: "responder", terminalStatus: "completed", usage: { inputTokens: "7", outputTokens: "3" }, teardown: { completed: true }, acp: { version: "pinned" } };
        },
      };
    },
    ...dependencyOverrides,
  };
}

function initiatorBridgeEvidence() {
  const base = dependencies([]).createBridge().publicEvidence();
  return {
    ...base,
    role: "initiator",
    deliveries: [{ acknowledged: true, artifactDigest: DIGEST, artifactType: "proposal", checkpointDigest: OTHER_DIGEST, messageDigests: [DIGEST, OTHER_DIGEST] }],
    certificate: {
      ...base.certificate,
      identity: {
        ...base.certificate.identity,
        sessionKeyAddress: "0x2222222222222222222222222222222222222222",
        erc8004: {
          ...base.certificate.identity.erc8004,
          agentId: "9452",
          reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9452",
        },
      },
    },
  };
}

async function usingTemporaryEnv(values, fn) {
  const previous = {};
  for (const key of Object.keys(values)) previous[key] = process.env[key];
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return await fn();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function codexSerializedAuth() {
  return JSON.stringify({
    auth_mode: "chatgpt",
    last_refresh: "2026-08-12T00:00:00.000Z",
    tokens: {
      access_token: "codex-access-secret",
      id_token: "codex-id-secret",
      refresh_token: "codex-refresh-secret",
      account_id: "acct-test",
    },
  });
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
  const events = [];
  const evidence = await runtime.run({ peerDescriptor: peerDescriptor(), onPublicEvent: (event) => events.push(event) });
  assert.equal(evidence.schema, "clockchain.mechanics-proof-party-evidence/v1");
  assert.equal(evidence.protocolSessionId, PROTOCOL_SESSION_ID);
  assert.equal(evidence.certificateProofDigest, DIGEST);
  assert.equal(evidence.certificateDigest, OTHER_DIGEST);
  assert.equal(evidence.resultDigest, DIGEST);
  assert.equal(evidence.certificateVerified, true);
  assert.equal(evidence.identity.erc8004.agentId, "9453");
  assert.equal(evidence.a2aCardSignerAddress, evidence.identity.sessionKeyAddress);
  assert.deepEqual(evidence.anchors.map((anchor) => anchor.kind), ["proposal", "acceptance", "acknowledgment"]);
  assert.deepEqual(evidence.directDelivery, {
    acknowledged: true,
    artifactDigest: DIGEST,
    artifactType: "acceptance",
    checkpointDigest: OTHER_DIGEST,
    messageDigests: [DIGEST, OTHER_DIGEST],
  });
  assert.equal(evidence.externalBusinessActionPerformed, false);
  assert.equal(evidence.teardown.completed, true);
  assert.doesNotMatch(JSON.stringify(evidence), /private-invitation|roleAccess|signature|transcript|reasoning|BEGIN/i);
  assert.ok(calls.indexOf("invitation.listen") < calls.indexOf("agent.launch"));
  assert.ok(calls.indexOf("invitation.take") < calls.indexOf("agent.launch"));
  assert.equal(events[0].schema, "clockchain.mechanics-proof-party-event/v1");
  assert.equal(events[0].type, "a2a.listener.ready");
  assert.match(events[0].evidenceDigest, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(events), /private-invitation|BEGIN|bootstrapPublicKey/i);
  for (const expected of ["agent.terminate", "bridge.destroy", "recorder.close", "invitation.close", "bootstrap.destroy", "tls.destroy"]) {
    assert.ok(calls.includes(expected), expected);
  }
});

test("initiator runtime installs serialized Codex subscription auth into isolated HOME without leaking it", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-codex-auth-"));
  const root = join(parent, "initiator");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const serialized = codexSerializedAuth();
  await usingTemporaryEnv({
    CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: Buffer.from(serialized, "utf8").toString("base64"),
    CLOCKCHAIN_CODEX_MODEL: "gpt-5.6-terra",
    CODEX_API_KEY: undefined,
    OPENAI_API_KEY: undefined,
    CLAUDE_CODE_USE_BEDROCK: undefined,
    ANTHROPIC_MODEL: undefined,
    AWS_ACCESS_KEY_ID: undefined,
    AWS_SECRET_ACCESS_KEY: undefined,
    AWS_SESSION_TOKEN: undefined,
  }, async () => {
    const calls = [];
    const bridgeEvidence = initiatorBridgeEvidence();
    let transportEnv;
    const runtime = await createMechanicsProofPartyRuntime(options(root, {
      harness: "codex",
      publicEndpoint: "https://initiator.task.local:8443",
      role: "initiator",
      runtimeId: "runtime-initiator",
      taskId: "task-initiator",
    }), dependencies(calls, {
      bridgeEvidence,
      createProcessTransport(input) {
        calls.push("transport.create");
        transportEnv = input.env;
        const installed = readFileSync(join(root, "home", ".codex", "auth.json"), "utf8");
        assert.deepEqual(JSON.parse(installed), JSON.parse(serialized));
        return {};
      },
    }));
    const evidence = await runtime.run({
      peerDescriptor: peerDescriptor({
        harness: "claude",
        role: "responder",
        runtime: {
          endpoint: "https://responder.task.local:8443",
          runtimeId: "runtime-responder",
          taskId: "task-responder",
          tlsCertificateSha256: OTHER_DIGEST,
          workloadAttestationDigest: OTHER_DIGEST,
        },
      }),
    });
    assert.equal(evidence.role, "initiator");
    assert.equal(transportEnv.CLOCKCHAIN_CODEX_MODEL, "gpt-5.6-terra");
    assert.equal("CLOCKCHAIN_CODEX_AUTH_JSON_BASE64" in transportEnv, false);
    assert.equal("CODEX_API_KEY" in transportEnv, false);
    assert.equal("OPENAI_API_KEY" in transportEnv, false);
    assert.doesNotMatch(JSON.stringify({ evidence, calls, transportEnv }), /codex-access-secret|codex-id-secret|codex-refresh-secret|CLOCKCHAIN_CODEX_AUTH_JSON_BASE64/i);
  });
});

test("Codex runtime tolerates ECS task credential env but does not pass AWS creds to the harness", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-codex-ecs-"));
  const root = join(parent, "initiator");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const serialized = codexSerializedAuth();
  await usingTemporaryEnv({
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/12345678-1234-4234-9234-123456789abc",
    AWS_DEFAULT_REGION: "us-west-2",
    AWS_REGION: "us-west-2",
    CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: Buffer.from(serialized, "utf8").toString("base64"),
    CLOCKCHAIN_CODEX_MODEL: "gpt-5.6-terra",
    CODEX_API_KEY: undefined,
    OPENAI_API_KEY: undefined,
  }, async () => {
    let transportEnv;
    const calls = [];
    const runtime = await createMechanicsProofPartyRuntime(options(root, {
      harness: "codex",
      publicEndpoint: "https://initiator.task.local:8443",
      role: "initiator",
      runtimeId: "runtime-initiator",
      taskId: "task-initiator",
    }), dependencies(calls, {
      bridgeEvidence: initiatorBridgeEvidence(),
      createProcessTransport(input) { transportEnv = input.env; return {}; },
    }));
    await runtime.run({
      peerDescriptor: peerDescriptor({
        harness: "claude",
        role: "responder",
        runtime: {
          endpoint: "https://responder.task.local:8443",
          runtimeId: "runtime-responder",
          taskId: "task-responder",
          tlsCertificateSha256: OTHER_DIGEST,
          workloadAttestationDigest: OTHER_DIGEST,
        },
      }),
    });
    assert.equal(transportEnv.CLOCKCHAIN_CODEX_MODEL, "gpt-5.6-terra");
    for (const key of ["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]) {
      assert.equal(key in transportEnv, false, key);
    }
  });
});

test("Claude Bedrock runtime passes only platform relative credentials and regions", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-claude-ecs-"));
  const root = join(parent, "responder");
  t.after(() => rm(parent, { recursive: true, force: true }));
  await usingTemporaryEnv({
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/12345678-1234-4234-9234-123456789abc",
    AWS_DEFAULT_REGION: "us-west-2",
    AWS_REGION: "us-west-2",
    CLAUDE_CODE_USE_BEDROCK: "1",
    ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6",
  }, async () => {
    let transportEnv;
    const runtime = await createMechanicsProofPartyRuntime(options(root), dependencies([], {
      createProcessTransport(input) { transportEnv = input.env; return {}; },
    }));
    await runtime.run({ peerDescriptor: peerDescriptor() });
    assert.equal(transportEnv.CLAUDE_CODE_USE_BEDROCK, "1");
    assert.equal(transportEnv.ANTHROPIC_MODEL, "us.anthropic.claude-sonnet-4-6");
    assert.equal(transportEnv.AWS_REGION, "us-west-2");
    assert.equal(transportEnv.AWS_DEFAULT_REGION, "us-west-2");
    assert.equal(transportEnv.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, "/v2/credentials/12345678-1234-4234-9234-123456789abc");
    for (const key of ["AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "ANTHROPIC_API_KEY"]) {
      assert.equal(key in transportEnv, false, key);
    }
  });
});

test("party runtime rejects mixed and cross-role provider authentication", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-auth-reject-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const serialized = Buffer.from(codexSerializedAuth(), "utf8").toString("base64");
  for (const [name, harness, envValues] of [
    ["codex-missing", "codex", {}],
    ["codex-mixed", "codex", { CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: serialized, CODEX_API_KEY: "codex-api-secret", OPENAI_API_KEY: undefined }],
    ["codex-claude-env", "codex", { CLAUDE_CODE_USE_BEDROCK: "1", ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6", CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: serialized }],
    ["claude-codex-env", "claude", { CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: serialized, CLOCKCHAIN_CODEX_MODEL: "gpt-5.6-terra" }],
    ["claude-anthropic-key", "claude", { ANTHROPIC_API_KEY: "anthropic-secret", CLAUDE_CODE_USE_BEDROCK: "1", ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6" }],
  ]) {
    await usingTemporaryEnv({
      CLOCKCHAIN_CODEX_AUTH_JSON_BASE64: undefined,
      CODEX_API_KEY: undefined,
      OPENAI_API_KEY: undefined,
      CLOCKCHAIN_CODEX_MODEL: undefined,
      CLAUDE_CODE_USE_BEDROCK: undefined,
      ANTHROPIC_MODEL: undefined,
      AWS_ACCESS_KEY_ID: undefined,
      AWS_SECRET_ACCESS_KEY: undefined,
      AWS_SESSION_TOKEN: undefined,
      ANTHROPIC_API_KEY: undefined,
      ...envValues,
    }, async () => {
      const root = join(parent, name);
      const runtime = await createMechanicsProofPartyRuntime(options(root, {
        harness,
        publicEndpoint: harness === "codex" ? "https://initiator.task.local:8443" : "https://responder.task.local:8443",
        role: harness === "codex" ? "initiator" : "responder",
        runtimeId: `runtime-${name}`,
        taskId: `task-${name}`,
      }), dependencies([]));
      await assert.rejects(() => runtime.run({
        peerDescriptor: peerDescriptor(harness === "codex" ? {
          harness: "claude",
          role: "responder",
          runtime: {
            endpoint: "https://responder.task.local:8443",
            runtimeId: "runtime-responder",
            taskId: "task-responder",
            tlsCertificateSha256: OTHER_DIGEST,
            workloadAttestationDigest: OTHER_DIGEST,
          },
        } : {}),
      }), /Mechanics proof party runtime failed safely/);
    });
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

test("party runtime exposes only its branded allowlisted failure stage", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-stage-"));
  const root = join(parent, "responder");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const runtime = await createMechanicsProofPartyRuntime(options(root), dependencies([], {
    async createInvitationTransport() { throw new Error("secret listener detail"); },
  }));
  await assert.rejects(() => runtime.run({ peerDescriptor: peerDescriptor() }), (error) => {
    assert.equal(error.message, "Mechanics proof party runtime failed safely.");
    assert.equal(mechanicsProofPartyRuntimeFailureStage(error), "listener-create");
    assert.equal(mechanicsProofPartyRuntimeFailureStage(new Error("Mechanics proof party runtime failed safely.")), null);
    assert.doesNotMatch(JSON.stringify(error), /secret|listener/i);
    return true;
  });
});

test("party runtime preserves a branded recorder retrieval substage", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-recorder-stage-"));
  const root = join(parent, "responder");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const runtime = await createMechanicsProofPartyRuntime(options(root), dependencies([], {
    createActionRecorder(input) {
      return createVerifiedReleaseActionRecorder({
        ...input,
        fetchImpl: async () => ({ ok: false, arrayBuffer: async () => Buffer.alloc(0) }),
      });
    },
  }));
  await assert.rejects(() => runtime.run({ peerDescriptor: peerDescriptor() }), (error) => {
    assert.equal(error.message, "Mechanics proof party runtime failed safely.");
    assert.equal(mechanicsProofPartyRuntimeFailureStage(error), "recorder-release-manifest-fetch");
    assert.doesNotMatch(JSON.stringify(error), /github|manifest\.json|secret/i);
    return true;
  });
});

test("party runtime rejects terminal evidence with missing result digest or mismatched card signer", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "clockchain-party-runtime-terminal-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const base = dependencies([]).createBridge().publicEvidence();
  const cases = [
    ["missing-result-digest", { ...base, certificate: { ...base.certificate, resultDigest: undefined } }],
    ["missing-card-signer", { ...base, cardSignerAddresses: { initiator: "0x2222222222222222222222222222222222222222", responder: null } }],
    ["mismatched-card-signer", { ...base, cardSignerAddresses: { initiator: "0x2222222222222222222222222222222222222222", responder: "0x3333333333333333333333333333333333333333" } }],
    ["shared-card-signer", { ...base, cardSignerAddresses: { initiator: "0x1111111111111111111111111111111111111111", responder: "0x1111111111111111111111111111111111111111" } }],
  ];
  for (const [name, bridgeEvidence] of cases) {
    const runtime = await createMechanicsProofPartyRuntime(options(join(parent, name)), dependencies([], { bridgeEvidence }));
    await assert.rejects(
      () => runtime.run({ peerDescriptor: peerDescriptor() }),
      /Mechanics proof party runtime failed safely/,
      name,
    );
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
