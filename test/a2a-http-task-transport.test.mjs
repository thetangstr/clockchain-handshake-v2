import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/core/canonical.mjs";
import { A2A_AGENT_CARD_SCHEMA, a2aAgentCardDigest, signA2AAgentCard } from "../src/a2a/agent-card.mjs";
import { A2A_ENVELOPE_SCHEMA, a2aEnvelopeDigest, signA2AEnvelope } from "../src/a2a/envelope.mjs";
import { createHttpTaskTransport } from "../src/a2a/http-task-transport.mjs";

const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const INITIATOR = privateKeyToAccount(`0x${"1".repeat(64)}`);
const RESPONDER = privateKeyToAccount(`0x${"2".repeat(64)}`);
const INITIATOR_CARD = privateKeyToAccount(`0x${"6".repeat(64)}`);
const RESPONDER_CARD = privateKeyToAccount(`0x${"7".repeat(64)}`);

function unsignedCard(account, role, peerCardDigest = null) {
  return {
    schema: A2A_AGENT_CARD_SCHEMA,
    version: 1,
    sessionId: SESSION_ID,
    role,
    partySignerAddress: account.address.toLowerCase(),
    partySignerPublicKey: account.publicKey,
    a2aCardPublicKey: role === "initiator" ? INITIATOR_CARD.publicKey : RESPONDER_CARD.publicKey,
    workloadAttestationDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    runtimeId: `runtime-${role}`,
    taskId: `task-${role}`,
    endpoint: `https://${role}.task.local:8443/a2a`,
    peerCardDigest,
    issuedAtMs: "1000",
    expiresAtMs: "3000",
    nonce: `nonce-${role}`,
    jti: `jti-${role}`,
    supportedArtifacts: ["invitation", "proposal", "counterproposal", "acceptance"],
  };
}

async function cards() {
  const responder = await signA2AAgentCard({
    card: unsignedCard(RESPONDER, "responder"),
    signMessage: (raw) => RESPONDER.signMessage({ message: { raw } }),
  });
  const initiator = await signA2AAgentCard({
    card: unsignedCard(INITIATOR, "initiator", a2aAgentCardDigest(responder)),
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });
  return { initiator, responder };
}

async function signedArtifact(account, payload) {
  return {
    payload,
    signature: {
      address: account.address.toLowerCase(),
      algorithm: "eip191",
      value: await account.signMessage({ message: { raw: canonicalBytes(payload) } }),
    },
  };
}

async function envelope({ fromAccount, fromCard, toCard, sequence, artifactType = "proposal", previousMessageDigest = null, nonce = `message-${sequence}` }) {
  const artifact = await signedArtifact(fromAccount, { kind: artifactType, sequence });
  return signA2AEnvelope({
    envelope: {
      schema: A2A_ENVELOPE_SCHEMA,
      version: 1,
      sessionId: SESSION_ID,
      fromCardDigest: a2aAgentCardDigest(fromCard),
      toCardDigest: a2aAgentCardDigest(toCard),
      sequence,
      artifactType,
      artifactDigest: a2aEnvelopeDigest({ artifact }),
      previousMessageDigest,
      expiresAtMs: "2500",
      nonce,
      body: artifact,
      ciphertext: null,
    },
    fromCard,
    toCard,
    signMessage: (raw) => (fromAccount === INITIATOR ? INITIATOR_CARD : RESPONDER_CARD).signMessage({ message: { raw } }),
  });
}

test("HTTP task transport exchanges A2A envelopes directly without controller content routing", async (t) => {
  const pair = await cards();
  const controller = { routed: false, routeRawContent() { this.routed = true; } };
  const initiator = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "initiator",
    ownCard: pair.initiator,
    peerCard: pair.responder,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
  });
  t.after(() => initiator.close());
  const responder = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "responder",
    ownCard: pair.responder,
    peerCard: pair.initiator,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
  });
  t.after(() => responder.close());
  initiator.setPeerUrl(responder.url);
  responder.setPeerUrl(initiator.url);

  const proposal = await envelope({ fromAccount: INITIATOR, fromCard: pair.initiator, toCard: pair.responder, sequence: "1" });
  const sentProposal = await initiator.sendEnvelope({ envelope: proposal });
  const receivedProposal = await responder.receive();
  assert.equal(receivedProposal.body.payload.kind, "proposal");
  const acceptance = await envelope({ fromAccount: RESPONDER, fromCard: pair.responder, toCard: pair.initiator, sequence: "1", artifactType: "acceptance", nonce: "message-acceptance-1" });
  const sentAcceptance = await responder.sendEnvelope({ envelope: acceptance });
  const receivedAcceptance = await initiator.receive();
  assert.equal(receivedAcceptance.body.payload.kind, "acceptance");
  assert.equal(controller.routed, false);

  for (const evidence of [initiator.publicEvidence(), responder.publicEvidence()]) {
    assert.equal(evidence.schema, "clockchain.a2a-http-task-transport-evidence/v1");
    assert.equal(evidence.sessionId, SESSION_ID);
    assert.match(evidence.cardDigests.initiator, /^[0-9a-f]{64}$/);
    assert.match(evidence.cardDigests.responder, /^[0-9a-f]{64}$/);
    assert.doesNotMatch(JSON.stringify(evidence), /body|ciphertext|transcript|private reasoning|proposal\\W+1|acceptance\\W+1/i);
  }
  assert.match(sentProposal.messageDigest, /^[0-9a-f]{64}$/);
  assert.match(sentAcceptance.messageDigest, /^[0-9a-f]{64}$/);
});

test("HTTP task transport rejects wrong paths, replay, oversized bodies, and unsigned claims", async (t) => {
  const pair = await cards();
  const responder = await createHttpTaskTransport({
    sessionId: SESSION_ID,
    role: "responder",
    ownCard: pair.responder,
    peerCard: pair.initiator,
    listenHost: "127.0.0.1",
    port: 0,
    nowMs: () => 1500,
    maxBytes: 2048,
  });
  t.after(() => responder.close());
  const proposal = await envelope({ fromAccount: INITIATOR, fromCard: pair.initiator, toCard: pair.responder, sequence: "1" });
  const first = await fetch(`${responder.url}/a2a/v1/envelopes`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ envelope: proposal }),
  });
  assert.equal(first.status, 202);
  const replay = await fetch(`${responder.url}/a2a/v1/envelopes`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ envelope: proposal }),
  });
  assert.equal(replay.status, 400);
  const wrongPath = await fetch(`${responder.url}/a2a/v1/raw`, {
    method: "POST",
    body: "{}",
  });
  assert.equal(wrongPath.status, 404);
  const unsigned = await fetch(`${responder.url}/a2a/v1/envelopes`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ transcript: "private", envelope: { ...proposal, signature: undefined } }),
  });
  assert.equal(unsigned.status, 400);
  assert.equal(responder.publicEvidence().messages.length, 1);
});
