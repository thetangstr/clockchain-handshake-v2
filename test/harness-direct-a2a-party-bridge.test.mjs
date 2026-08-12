import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import test from "node:test";

import { createDirectTaskChannel } from "../src/a2a/direct-task-channel.mjs";
import { initializeWallet } from "../src/core/wallet-bridge.mjs";
import { createDirectA2APartyBridge } from "../src/harness/direct-a2a-party-bridge.mjs";
import {
  createPartyA2AAuthority,
  PARTY_A2A_ENVELOPE_CAPABILITY,
} from "../src/harness/party-a2a-authority.mjs";
import {
  NOW_MS,
  REPOSITORY_SHA,
  SESSION_ID,
  TERMS,
  buildV2Fixture,
} from "./support/agent-handshake-v2-fixture.mjs";

const KEYS = Object.freeze({ initiator: `0x${"4".repeat(64)}`, responder: `0x${"5".repeat(64)}` });
const RUNTIME = Object.freeze({
  initiator: Object.freeze({
    endpoint: "https://initiator.task.local:8443",
    runtimeId: "runtime-initiator",
    taskId: "task-initiator",
    tlsCertificateSha256: "6".repeat(64),
    workloadAttestationDigest: "4".repeat(64),
  }),
  responder: Object.freeze({
    endpoint: "https://responder.task.local:8443",
    runtimeId: "runtime-responder",
    taskId: "task-responder",
    tlsCertificateSha256: "7".repeat(64),
    workloadAttestationDigest: "5".repeat(64),
  }),
});

async function setup(t, {
  transformAuthority = (authority) => authority,
  transformTaskTransport = (transport) => transport,
} = {}) {
  const fixture = await buildV2Fixture();
  const root = await mkdtemp(join(tmpdir(), "direct-a2a-party-bridge-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const authorities = {};
  for (const role of ["initiator", "responder"]) {
    const statePath = join(root, role, "wallet.json");
    await initializeWallet({ statePath, platform: "darwin", generatePrivateKey: () => KEYS[role] });
    authorities[role] = await createPartyA2AAuthority({
      nowMs: () => NOW_MS,
      peerRuntime: RUNTIME[role === "initiator" ? "responder" : "initiator"],
      platform: "darwin",
      policyDigest: fixture.parties[role].policyDigest,
      repositorySha: REPOSITORY_SHA,
      role,
      runtime: RUNTIME[role],
      sessionId: SESSION_ID,
      statePath,
      terms: TERMS,
    });
  }
  const responderCard = await authorities.responder.signResponderCard({
    expiresAtMs: String(NOW_MS + 20_000),
    jti: "jti-responder-card",
    nonce: "nonce-responder-card",
  });
  const initiatorCard = await authorities.initiator.signInitiatorCard({
    expiresAtMs: String(NOW_MS + 20_000),
    jti: "jti-initiator-card",
    nonce: "nonce-initiator-card",
    responderCard,
  });
  const cards = Object.freeze({ initiator: initiatorCard, responder: responderCard });
  const channel = await createDirectTaskChannel({ sessionId: SESSION_ID, initiatorCard, responderCard, nowMs: NOW_MS });
  function taskTransport(role) {
    const peer = role === "initiator" ? "responder" : "initiator";
    return Object.freeze({
      async close() {},
      publicEvidence() { return channel.publicEvidence(); },
      receive() { return channel.receive({ role }); },
      sendEnvelope({ envelope }) { return channel.send({ fromRole: role, toRole: peer, envelope, nowMs: NOW_MS }); },
    });
  }
  const invitationCalls = [];
  const bridges = {};
  const completionHandlers = {};
  const activationCalls = [];
  for (const role of ["initiator", "responder"]) {
    const completionRecorder = Object.freeze({
      setCompletionHandler(handler) {
        assert.equal(completionHandlers[role], undefined);
        completionHandlers[role] = handler;
      },
    });
    bridges[role] = createDirectA2APartyBridge({
      activateSignedChannel: async () => {
        activationCalls.push(role);
        return {
          authority: transformAuthority(authorities[role], role),
          cards,
          taskTransport: transformTaskTransport(taskTransport(role), role),
        };
      },
      completionRecorder,
      invitationTransport: Object.freeze({
        async sendInvitation(input) {
          invitationCalls.push(input);
          return { acknowledged: true, invitationDigest: createHash("sha256").update(input.invitation).digest("hex") };
        },
      }),
      nowMs: () => NOW_MS,
      role,
      sessionId: SESSION_ID,
    });
  }
  return { activationCalls, authorities, bridges, channel, completionHandlers, fixture, invitationCalls };
}

function lifecycleStep(role) {
  const shellCommand = `node helper init ${role}`;
  const commandSha256 = createHash("sha256").update(shellCommand).digest("hex");
  return Object.freeze({
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
    commandLength: Buffer.byteLength(shellCommand),
    commandSha256,
    operation: "init",
    role,
    sessionId: SESSION_ID,
    shellCommand,
  });
}

function lifecycleCompletion(role, step) {
  return Object.freeze({
    actionId: `init-${role}`,
    commandSha256: step.commandSha256,
    operation: "init",
    requestDigest: role === "initiator" ? "a".repeat(64) : "b".repeat(64),
    result: Object.freeze({
      address: role === "initiator" ? "0x1111111111111111111111111111111111111111" : "0x2222222222222222222222222222222222222222",
      helperVersion: "2.1.2",
      operation: "init",
      schema: "clockchain.agent-handshake-cli-result/v1",
    }),
    role,
    sessionId: SESSION_ID,
  });
}

function signingStep({ envelope, operation, role, policyDigest }) {
  const raw = Buffer.from(JSON.stringify(envelope.payload));
  const request = {
    schema: "clockchain.agent-handshake-signing-request/v1",
    helperVersion: "2.1.2",
    operation,
    role,
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: String(NOW_MS + 30_000),
    hostSessionKeyCertificate: {},
    terms: TERMS,
    policyDigest,
    bytesGzipBase64Url: gzipSync(raw).toString("base64url"),
    bytesSha256: createHash("sha256").update(raw).digest("hex"),
    externalBusinessActionPerformed: false,
  };
  const payload = Buffer.from(JSON.stringify(request)).toString("base64url");
  const shellCommand = `node helper sign --state-dir "$TMPDIR/.clockchain/handshakes/${SESSION_ID}/${role}" --payload-base64url ${payload}`;
  const commandSha256 = createHash("sha256").update(shellCommand).digest("hex");
  return {
    request,
    step: Object.freeze({
      approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
      commandLength: Buffer.byteLength(shellCommand),
      commandSha256,
      operation: "sign",
      policyDigest,
      role,
      sessionId: SESSION_ID,
      shellCommand,
    }),
  };
}

function completion({ envelope, request, step, role }) {
  return Object.freeze({
    actionId: `action-${role}`,
    commandSha256: step.commandSha256,
    operation: "sign",
    requestDigest: createHash("sha256").update(Buffer.from(JSON.stringify(request))).digest("hex"),
    result: Object.freeze({
      address: envelope.signature.address,
      bytesSha256: request.bytesSha256,
      helperVersion: "2.1.2",
      operation: "sign",
      schema: "clockchain.agent-handshake-cli-result/v1",
      signatureHex: envelope.signature.value,
    }),
    role,
    sessionId: SESSION_ID,
  });
}

test("party-local bridges deliver invitation before signer readiness, then proposal and acceptance with additive checkpoints", async (t) => {
  const { activationCalls, bridges, channel, completionHandlers, fixture, invitationCalls } = await setup(t);
  const invitation = "opaque.responder.invitation";
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_invite",
    result: { responderInvitation: invitation },
  });
  assert.equal(invitationCalls.length, 1);
  assert.equal(invitationCalls[0].invitation, invitation);
  assert.deepEqual(bridges.initiator.publicEvidence().cardDigests, { initiator: null, responder: null });

  for (const role of ["initiator", "responder"]) {
    const step = lifecycleStep(role);
    await bridges[role].observeToolResult({
      toolName: "agent_handshake_next",
      result: { structuredContent: { localAction: { helperStep: step } } },
    });
    assert.deepEqual(await completionHandlers[role](lifecycleCompletion(role, step)), { accepted: true });
  }
  assert.deepEqual(activationCalls.sort(), ["initiator", "responder"]);

  const proposal = signingStep({
    envelope: fixture.proposalEnvelope,
    operation: "proposal",
    policyDigest: fixture.parties.initiator.policyDigest,
    role: "initiator",
  });
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: proposal.step } } },
  });
  const proposalCompletion = await completionHandlers.initiator(completion({
    envelope: fixture.proposalEnvelope,
    request: proposal.request,
    role: "initiator",
    step: proposal.step,
  }));
  assert.deepEqual(proposalCompletion, { accepted: true });

  const acceptance = signingStep({
    envelope: fixture.acceptanceEnvelope,
    operation: "acceptance",
    policyDigest: fixture.parties.responder.policyDigest,
    role: "responder",
  });
  await bridges.responder.observeToolResult({
    toolName: "agent_handshake_next",
    result: { content: [{ type: "text", text: JSON.stringify({ localAction: { helperStep: acceptance.step } }) }] },
  });
  assert.deepEqual(await completionHandlers.responder(completion({
    envelope: fixture.acceptanceEnvelope,
    request: acceptance.request,
    role: "responder",
    step: acceptance.step,
  })), { accepted: true });

  const initiatorInbound = [await channel.receive({ role: "initiator" }), await channel.receive({ role: "initiator" })];
  assert.equal(initiatorInbound[0].body.payload.schema, "clockchain.agent-handshake-acceptance/v2");
  assert.equal(initiatorInbound[1].body.payload.schema, "clockchain.agent-handshake-commitment-checkpoint/v1");
  for (const evidence of [bridges.initiator.publicEvidence(), bridges.responder.publicEvidence()]) {
    assert.equal(evidence.schema, "clockchain.direct-a2a-party-bridge-evidence/v1");
    assert.doesNotMatch(JSON.stringify(evidence), /opaque\.responder|helperStep|shellCommand|signatureHex|bytesGzip|body|payload|private/i);
  }
});

test("bridge rejects spoofed provenance, arbitrary completion, and replay without public evidence", async (t) => {
  const { bridges, completionHandlers, fixture } = await setup(t);
  const proposal = signingStep({
    envelope: fixture.proposalEnvelope,
    operation: "proposal",
    policyDigest: fixture.parties.initiator.policyDigest,
    role: "initiator",
  });
  await assert.rejects(
    bridges.initiator.observeToolResult({ toolName: "Bash", result: { helperStep: proposal.step } }),
    /Direct A2A party bridge failed safely/,
  );
  await assert.rejects(
    completionHandlers.initiator(completion({ envelope: fixture.proposalEnvelope, request: proposal.request, role: "initiator", step: proposal.step })),
    /Direct A2A party bridge failed safely/,
  );
  assert.equal(bridges.initiator.publicEvidence().deliveries.length, 0);
  assert.doesNotMatch(JSON.stringify(bridges.initiator.publicEvidence()), /helperStep|shellCommand|payload|signature/i);
});

test("checkpoint rejection sends no direct business artifact and releases no completion", async (t) => {
  const { bridges, channel, completionHandlers, fixture } = await setup(t, {
    transformAuthority(authority, role) {
      if (role !== "initiator") return authority;
      const wrapped = { ...authority, async signProposalCheckpoint() { throw new Error("reject"); } };
      Object.defineProperty(wrapped, PARTY_A2A_ENVELOPE_CAPABILITY, {
        enumerable: false,
        value: authority[PARTY_A2A_ENVELOPE_CAPABILITY],
      });
      return Object.freeze(wrapped);
    },
  });
  const initStep = lifecycleStep("initiator");
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: initStep } } },
  });
  assert.deepEqual(await completionHandlers.initiator(lifecycleCompletion("initiator", initStep)), { accepted: true });
  const proposal = signingStep({
    envelope: fixture.proposalEnvelope,
    operation: "proposal",
    policyDigest: fixture.parties.initiator.policyDigest,
    role: "initiator",
  });
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: proposal.step } } },
  });
  await assert.rejects(
    completionHandlers.initiator(completion({
      envelope: fixture.proposalEnvelope,
      request: proposal.request,
      role: "initiator",
      step: proposal.step,
    })),
    /Direct A2A party bridge failed safely/,
  );
  assert.equal(channel.publicEvidence().messages.length, 0);
  assert.equal(bridges.initiator.publicEvidence().deliveries.length, 0);
});

test("identity and evidence signing completions remain local and do not require an active A2A channel", async (t) => {
  const { bridges, channel, completionHandlers, fixture } = await setup(t);
  const localOnly = signingStep({
    envelope: fixture.proposalEnvelope,
    operation: "proposal",
    policyDigest: fixture.parties.initiator.policyDigest,
    role: "initiator",
  });
  const request = { ...localOnly.request, operation: "identity" };
  const payload = Buffer.from(JSON.stringify(request)).toString("base64url");
  const shellCommand = localOnly.step.shellCommand.replace(/--payload-base64url\s+[A-Za-z0-9_-]+/, `--payload-base64url ${payload}`);
  const commandSha256 = createHash("sha256").update(shellCommand).digest("hex");
  const step = {
    ...localOnly.step,
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
    commandLength: Buffer.byteLength(shellCommand),
    commandSha256,
    shellCommand,
  };
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: step } } },
  });
  const localCompletion = completion({ envelope: fixture.proposalEnvelope, request, role: "initiator", step });
  assert.deepEqual(await completionHandlers.initiator(localCompletion), { accepted: true });
  assert.equal(channel.publicEvidence().messages.length, 0);
  assert.deepEqual(bridges.initiator.publicEvidence().cardDigests, { initiator: null, responder: null });
});

test("destroy tears down party authority and returns a generic failure when transport close fails", async (t) => {
  let authorityDestroyed = 0;
  const { bridges, completionHandlers } = await setup(t, {
    transformAuthority(authority, role) {
      if (role !== "initiator") return authority;
      const wrapped = { ...authority, async destroy() { authorityDestroyed += 1; await authority.destroy(); } };
      Object.defineProperty(wrapped, PARTY_A2A_ENVELOPE_CAPABILITY, {
        enumerable: false,
        value: authority[PARTY_A2A_ENVELOPE_CAPABILITY],
      });
      return Object.freeze(wrapped);
    },
    transformTaskTransport(transport, role) {
      if (role !== "initiator") return transport;
      return Object.freeze({ ...transport, async close() { throw new Error("raw transport detail"); } });
    },
  });
  const step = lifecycleStep("initiator");
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: step } } },
  });
  assert.deepEqual(await completionHandlers.initiator(lifecycleCompletion("initiator", step)), { accepted: true });

  await assert.rejects(bridges.initiator.destroy(), (error) => {
    assert.equal(error.message, "Direct A2A party bridge failed safely.");
    assert.doesNotMatch(error.message, /transport/i);
    return true;
  });
  assert.equal(authorityDestroyed, 1);
});
