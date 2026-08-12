import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import test from "node:test";

import { createDirectTaskChannel } from "../src/a2a/direct-task-channel.mjs";
import { commitmentCheckpointDigest } from "../src/agent-handshake/v2/commitment-checkpoint.mjs";
import { initializeWallet } from "../src/core/wallet-bridge.mjs";
import { digestHex } from "../src/core/canonical.mjs";
import {
  createDirectA2APartyBridge,
  directA2APartyBridgeFailureStage,
} from "../src/harness/direct-a2a-party-bridge.mjs";
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
const ROLE_ACCESS = Object.freeze({ initiator: `ccra_${"I".repeat(22)}`, responder: `ccra_${"R".repeat(22)}` });
const OTHER_SESSION_ID = "33333333-4444-4555-8666-777777777777";
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
  initialSessionId = SESSION_ID,
  transformAuthority = (authority) => authority,
  transformCheckpointSubmission = async (input, role) => ({
    role,
    sessionId: SESSION_ID,
    stage: `${input.checkpoint.artifactType}_checkpoint_submitted`,
    checkpointDigest: commitmentCheckpointDigest(input.checkpoint),
  }),
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
  const activationContexts = [];
  const checkpointCalls = [];
  for (const role of ["initiator", "responder"]) {
    const completionRecorder = Object.freeze({
      setCompletionHandler(handler) {
        assert.equal(completionHandlers[role], undefined);
        completionHandlers[role] = handler;
      },
    });
    bridges[role] = createDirectA2APartyBridge({
      activateSignedChannel: async (context) => {
        activationCalls.push(role);
        activationContexts.push(context);
        return {
          authority: transformAuthority(authorities[role], role),
          cards,
          taskTransport: transformTaskTransport(taskTransport(role), role),
        };
      },
      completionRecorder,
      invitationTransport: Object.freeze({
        publicEvidence() { return { sessionId: SESSION_ID }; },
        async sendInvitation(input) {
          invitationCalls.push(input);
          return { acknowledged: true, invitationDigest: createHash("sha256").update(input.invitation).digest("hex") };
        },
      }),
      nowMs: () => NOW_MS,
      role,
      sessionId: initialSessionId,
      submitCheckpoint: async (input) => {
        checkpointCalls.push({ ...input, observedMessages: channel.publicEvidence().messages.length });
        return transformCheckpointSubmission(input, role);
      },
    });
  }
  return { activationCalls, activationContexts, authorities, bridges, channel, checkpointCalls, completionHandlers, fixture, invitationCalls };
}

function lifecycleStep(role, operation = "init") {
  const shellCommand = `node helper ${operation} ${role}`;
  const commandSha256 = createHash("sha256").update(shellCommand).digest("hex");
  return Object.freeze({
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
    commandLength: Buffer.byteLength(shellCommand),
    commandSha256,
    operation,
    role,
    sessionId: SESSION_ID,
    shellCommand,
  });
}

function certificateStep(role, certificate) {
  const payload = Buffer.from(JSON.stringify({
    schema: "clockchain.agent-handshake-certificate-verification/v1",
    helperVersion: "2.1.2",
    role,
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: String(NOW_MS + 30_000),
    certificate,
    externalBusinessActionPerformed: false,
  })).toString("base64url");
  const shellCommand = `node helper verify-certificate --state-dir "$TMPDIR/.clockchain/handshakes/${SESSION_ID}/${role}" --payload-base64url ${payload}`;
  const commandSha256 = createHash("sha256").update(shellCommand).digest("hex");
  return Object.freeze({
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
    commandLength: Buffer.byteLength(shellCommand),
    commandSha256,
    operation: "verify-certificate",
    role,
    sessionId: SESSION_ID,
    shellCommand,
  });
}

function lifecycleCompletion(role, step, result = {}) {
  const payloadMatch = step.shellCommand.match(/--payload-base64url\s+([A-Za-z0-9_-]+)(?:\s|$)/);
  const requestDigest = payloadMatch === null
    ? (role === "initiator" ? "a".repeat(64) : "b".repeat(64))
    : createHash("sha256").update(Buffer.from(payloadMatch[1], "base64url")).digest("hex");
  return Object.freeze({
    actionId: `${step.operation}-${role}`,
    commandSha256: step.commandSha256,
    operation: step.operation,
    requestDigest,
    result: Object.freeze({
      ...(step.operation === "verify-certificate" ? {} : {
        address: role === "initiator" ? "0x1111111111111111111111111111111111111111" : "0x2222222222222222222222222222222222222222",
      }),
      helperVersion: "2.1.2",
      operation: step.operation,
      schema: "clockchain.agent-handshake-cli-result/v1",
      ...result,
    }),
    role,
    sessionId: SESSION_ID,
  });
}

function joinResult(role, fixture) {
  const party = fixture.parties[role];
  return Object.freeze({
    role,
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: String(NOW_MS + 30_000),
    signingRequest: Object.freeze({
      policyDigest: party.policyDigest,
      repositorySha: REPOSITORY_SHA,
      role,
      sessionId: SESSION_ID,
      terms: TERMS,
    }),
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

test("party-local bridges activate only from authoritative join context, then deliver proposal and acceptance with additive checkpoints", async (t) => {
  const { activationCalls, activationContexts, bridges, channel, checkpointCalls, completionHandlers, fixture, invitationCalls } = await setup(t);
  const invitation = "opaque.responder.invitation";
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_invite",
    result: { responderInvitation: invitation, roleAccess: ROLE_ACCESS.initiator, sessionId: SESSION_ID },
  });
  assert.deepEqual(bridges.initiator.completionStatus(), { complete: false, protocolSessionId: SESSION_ID });
  assert.equal(invitationCalls.length, 1);
  assert.equal(invitationCalls[0].invitation, invitation);
  assert.deepEqual(bridges.initiator.publicEvidence().cardDigests, { initiator: null, responder: null });

  for (const role of ["initiator", "responder"]) {
    const step = lifecycleStep(role);
    await bridges[role].observeToolResult({
      toolName: "agent_handshake_next",
      result: { structuredContent: { localAction: { helperStep: step }, roleAccess: ROLE_ACCESS[role] } },
    });
    assert.deepEqual(await completionHandlers[role](lifecycleCompletion(role, step)), { accepted: true });
    assert.equal(activationCalls.includes(role), false);
    await bridges[role].observeToolResult({
      toolName: "agent_handshake_join",
      result: joinResult(role, fixture),
    });
  }
  assert.deepEqual(activationCalls.sort(), ["initiator", "responder"]);
  assert.deepEqual(activationContexts.map((context) => context.role).sort(), ["initiator", "responder"]);
  for (const context of activationContexts) {
    assert.equal(context.sessionId, SESSION_ID);
    assert.equal(context.repositorySha, REPOSITORY_SHA);
    assert.deepEqual(context.terms, TERMS);
    assert.equal(context.policyDigest, fixture.parties[context.role].policyDigest);
  }

  const proposal = signingStep({
    envelope: fixture.proposalEnvelope,
    operation: "proposal",
    policyDigest: fixture.parties.initiator.policyDigest,
    role: "initiator",
  });
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: proposal.step }, roleAccess: ROLE_ACCESS.initiator } },
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
    result: { content: [{ type: "text", text: JSON.stringify({ localAction: { helperStep: acceptance.step }, roleAccess: ROLE_ACCESS.responder }) }] },
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
  assert.equal(checkpointCalls.length, 2);
  assert.deepEqual(checkpointCalls.map((call) => [call.access, call.artifactSignatureHex, call.observedMessages]), [
    [ROLE_ACCESS.initiator, fixture.proposalEnvelope.signature.value, 2],
    [ROLE_ACCESS.responder, fixture.acceptanceEnvelope.signature.value, 4],
  ]);
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
    (error) => {
      assert.equal(error.message, "Direct A2A party bridge failed safely.");
      assert.equal(directA2APartyBridgeFailureStage(error), "tool-name");
      return true;
    },
  );
  await assert.rejects(
    completionHandlers.initiator(completion({ envelope: fixture.proposalEnvelope, request: proposal.request, role: "initiator", step: proposal.step })),
    /Direct A2A party bridge failed safely/,
  );
  assert.equal(bridges.initiator.publicEvidence().deliveries.length, 0);
  assert.doesNotMatch(JSON.stringify(bridges.initiator.publicEvidence()), /helperStep|shellCommand|payload|signature/i);
});

test("bridges bind the protocol session once from authoritative invite and accept results", async (t) => {
  const { bridges } = await setup(t, { initialSessionId: null });
  const invitation = "opaque.responder.invitation";
  const initiated = await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_invite",
    result: { responderInvitation: invitation, roleAccess: ROLE_ACCESS.initiator, sessionId: SESSION_ID },
  });
  assert.equal(initiated.protocolSessionId, SESSION_ID);
  assert.equal(bridges.initiator.publicEvidence().sessionId, SESSION_ID);
  const accepted = await bridges.responder.observeToolResult({
    toolName: "agent_handshake_accept_invitation",
    result: { roleAccess: ROLE_ACCESS.responder, sessionId: SESSION_ID },
  });
  assert.equal(accepted.protocolSessionId, SESSION_ID);
  assert.equal(bridges.responder.publicEvidence().sessionId, SESSION_ID);
  await assert.rejects(
    bridges.initiator.observeToolResult({
      toolName: "agent_handshake_invite",
      result: { responderInvitation: invitation, roleAccess: ROLE_ACCESS.initiator, sessionId: OTHER_SESSION_ID },
    }),
    /Direct A2A party bridge failed safely/,
  );
  await assert.rejects(
    bridges.responder.observeToolResult({
      toolName: "agent_handshake_accept_invitation",
      result: { roleAccess: ROLE_ACCESS.responder, sessionId: OTHER_SESSION_ID },
    }),
    /Direct A2A party bridge failed safely/,
  );
});

test("dynamic bridge rejects retained helper action before authoritative session binding", async (t) => {
  const { bridges } = await setup(t, { initialSessionId: null });
  const step = lifecycleStep("initiator");
  await assert.rejects(
    bridges.initiator.observeToolResult({
      toolName: "agent_handshake_next",
      result: { structuredContent: { localAction: { helperStep: step }, roleAccess: ROLE_ACCESS.initiator } },
    }),
    /Direct A2A party bridge failed safely/,
  );
  assert.equal(bridges.initiator.publicEvidence().sessionId, null);
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
    result: { structuredContent: { localAction: { helperStep: initStep }, roleAccess: ROLE_ACCESS.initiator } },
  });
  assert.deepEqual(await completionHandlers.initiator(lifecycleCompletion("initiator", initStep)), { accepted: true });
  await bridges.initiator.observeToolResult({ toolName: "agent_handshake_join", result: joinResult("initiator", fixture) });
  const proposal = signingStep({
    envelope: fixture.proposalEnvelope,
    operation: "proposal",
    policyDigest: fixture.parties.initiator.policyDigest,
    role: "initiator",
  });
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: proposal.step }, roleAccess: ROLE_ACCESS.initiator } },
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

test("private MCP checkpoint rejection keeps the helper completion unreleased", async (t) => {
  const { bridges, channel, checkpointCalls, completionHandlers, fixture } = await setup(t, {
    transformCheckpointSubmission: async () => { throw new Error("private access and checkpoint must not escape"); },
  });
  const proposal = signingStep({
    envelope: fixture.proposalEnvelope,
    operation: "proposal",
    policyDigest: fixture.parties.initiator.policyDigest,
    role: "initiator",
  });
  await bridges.initiator.observeToolResult({ toolName: "agent_handshake_join", result: joinResult("initiator", fixture) });
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: proposal.step }, roleAccess: ROLE_ACCESS.initiator } },
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
  assert.equal(checkpointCalls.length, 1);
  assert.equal(checkpointCalls[0].observedMessages, 2);
  assert.equal(channel.publicEvidence().messages.length, 2);
  assert.equal(bridges.initiator.publicEvidence().deliveries.length, 0);
  assert.doesNotMatch(JSON.stringify(bridges.initiator.publicEvidence()), /ccra_|signature|checkpoint.*payload/i);
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
    result: { structuredContent: { localAction: { helperStep: step }, roleAccess: ROLE_ACCESS.initiator } },
  });
  const localCompletion = completion({ envelope: fixture.proposalEnvelope, request, role: "initiator", step });
  assert.deepEqual(await completionHandlers.initiator(localCompletion), { accepted: true });
  assert.equal(channel.publicEvidence().messages.length, 0);
  assert.deepEqual(bridges.initiator.publicEvidence().cardDigests, { initiator: null, responder: null });
});

test("destroy tears down party authority and returns a generic failure when transport close fails", async (t) => {
  let authorityDestroyed = 0;
  const { bridges, completionHandlers, fixture } = await setup(t, {
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
      return Object.freeze({ ...transport, close() { throw new Error("raw transport detail"); } });
    },
  });
  const step = lifecycleStep("initiator");
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_next",
    result: { structuredContent: { localAction: { helperStep: step } } },
  });
  assert.deepEqual(await completionHandlers.initiator(lifecycleCompletion("initiator", step)), { accepted: true });
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_join",
    result: joinResult("initiator", fixture),
  });

  await assert.rejects(bridges.initiator.destroy(), (error) => {
    assert.equal(error.message, "Direct A2A party bridge failed safely.");
    assert.doesNotMatch(error.message, /transport/i);
    return true;
  });
  assert.equal(authorityDestroyed, 1);
});

test("bridge records public certificate summary only after exact terminal certificate verification", async (t) => {
  const { bridges, completionHandlers, fixture } = await setup(t);
  const step = certificateStep("initiator", fixture.resultEnvelope);
  const certificateDigest = digestHex(fixture.resultEnvelope);
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_get_certificate",
    result: {
      certificate: fixture.resultEnvelope,
      localAction: { helperStep: step },
      roleAccess: ROLE_ACCESS.initiator,
    },
  });
  assert.deepEqual(await completionHandlers.initiator(lifecycleCompletion("initiator", step, {
    certificateVerified: true,
    externalBusinessActionPerformed: false,
    identity: { sessionKeyAddress: "0x1111111111111111111111111111111111111111" },
    outcome: "VERIFIED",
    policyDigest: "a".repeat(64),
    role: "initiator",
    sessionId: SESSION_ID,
    statementDigest: "b".repeat(64),
  })), { accepted: true });
  const evidence = bridges.initiator.publicEvidence();
  assert.deepEqual(bridges.initiator.completionStatus(), { complete: false, protocolSessionId: SESSION_ID });
  assert.equal(evidence.certificate.verified, true);
  assert.match(evidence.certificate.proofDigest, /^[0-9a-f]{64}$/);
  assert.equal(evidence.certificate.certificateDigest, certificateDigest);
  assert.equal(evidence.certificate.identity.sessionKeyAddress, fixture.parties.initiator.sessionKeyAddress);
  assert.deepEqual(evidence.certificate.anchors.map((anchor) => anchor.kind), ["proposal", "acceptance", "acknowledgment"]);
  assert.deepEqual(evidence.certificate.anchors.map((anchor) => anchor.digest), fixture.receipts.map((receipt) => receipt.digest));
  assert.doesNotMatch(JSON.stringify(evidence), /roleAccess|signatureHex|rootSignature|hostSessionKeyCertificate|transcript|reasoning/i);
});

test("bridge verifies the compact production certificate response without a duplicate top-level certificate", async (t) => {
  const { bridges, completionHandlers, fixture } = await setup(t);
  const step = certificateStep("initiator", fixture.resultEnvelope);
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_get_certificate",
    result: {
      certificateSummary: {
        schema: "clockchain.agent-handshake-certificate-summary/v1",
        outcome: "VERIFIED",
        resultDigest: digestHex(fixture.resultEnvelope.result),
        role: "initiator",
        sessionId: SESSION_ID,
      },
      localAction: { helperStep: step },
    },
  });

  assert.deepEqual(await completionHandlers.initiator(lifecycleCompletion("initiator", step, {
    certificateVerified: true,
    externalBusinessActionPerformed: false,
    identity: { sessionKeyAddress: "0x1111111111111111111111111111111111111111" },
    outcome: "VERIFIED",
    policyDigest: "a".repeat(64),
    role: "initiator",
    sessionId: SESSION_ID,
    statementDigest: "b".repeat(64),
  })), { accepted: true });

  const evidence = bridges.initiator.publicEvidence();
  assert.equal(evidence.certificate.certificateDigest, digestHex(fixture.resultEnvelope));
  assert.equal(evidence.certificate.identity.agentId, fixture.parties.initiator.agentId);
  assert.deepEqual(evidence.certificate.anchors.map((anchor) => anchor.kind), ["proposal", "acceptance", "acknowledgment"]);
});
