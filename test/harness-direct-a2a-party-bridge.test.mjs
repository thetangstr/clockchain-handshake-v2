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
import { createPartyA2AAuthority } from "../src/harness/party-a2a-authority.mjs";
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

async function setup(t) {
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
      publicEvidence() { return channel.publicEvidence(); },
      receive() { return channel.receive({ role }); },
      sendEnvelope({ envelope }) { return channel.send({ fromRole: role, toRole: peer, envelope, nowMs: NOW_MS }); },
    });
  }
  const invitationCalls = [];
  const bridges = {};
  for (const role of ["initiator", "responder"]) {
    bridges[role] = createDirectA2APartyBridge({
      authority: authorities[role],
      cards,
      invitationTransport: Object.freeze({
        async sendInvitation(input) {
          invitationCalls.push(input);
          return { acknowledged: true, invitationDigest: createHash("sha256").update(input.invitation).digest("hex") };
        },
      }),
      nowMs: () => NOW_MS,
      role,
      sessionId: SESSION_ID,
      taskTransport: taskTransport(role),
    });
  }
  return { authorities, bridges, channel, fixture, invitationCalls };
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

test("party-local bridges deliver proposal and acceptance with additive checkpoints before completion", async (t) => {
  const { bridges, channel, fixture, invitationCalls } = await setup(t);
  const invitation = "opaque.responder.invitation";
  await bridges.initiator.observeToolResult({
    toolName: "agent_handshake_invite",
    result: { responderInvitation: invitation },
  });
  assert.equal(invitationCalls.length, 1);
  assert.equal(invitationCalls[0].invitation, invitation);

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
  const proposalCompletion = await bridges.initiator.completionHandler(completion({
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
  assert.deepEqual(await bridges.responder.completionHandler(completion({
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
  const { bridges, fixture } = await setup(t);
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
    bridges.initiator.completionHandler(completion({ envelope: fixture.proposalEnvelope, request: proposal.request, role: "initiator", step: proposal.step })),
    /Direct A2A party bridge failed safely/,
  );
  assert.equal(bridges.initiator.publicEvidence().deliveries.length, 0);
  assert.doesNotMatch(JSON.stringify(bridges.initiator.publicEvidence()), /helperStep|shellCommand|payload|signature/i);
});
