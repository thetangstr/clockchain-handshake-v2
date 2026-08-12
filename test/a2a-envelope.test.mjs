import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  A2A_AGENT_CARD_SCHEMA,
  a2aAgentCardDigest,
  signA2AAgentCard,
} from "../src/a2a/agent-card.mjs";
import {
  A2A_ENVELOPE_SCHEMA,
  a2aEnvelopeDigest,
  signA2AEnvelope,
  verifyA2AEnvelope,
} from "../src/a2a/envelope.mjs";

const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const INITIATOR = privateKeyToAccount(`0x${"1".repeat(64)}`);
const RESPONDER = privateKeyToAccount(`0x${"2".repeat(64)}`);
const DIRECTOR = privateKeyToAccount(`0x${"3".repeat(64)}`);

function cardPayload(account, role) {
  return {
    schema: A2A_AGENT_CARD_SCHEMA,
    version: 1,
    sessionId: SESSION_ID,
    role,
    partySignerAddress: account.address.toLowerCase(),
    partySignerPublicKey: `0x${role === "initiator" ? "a" : "b"}`.padEnd(132, role === "initiator" ? "a" : "b"),
    a2aCardPublicKey: `0x${role === "initiator" ? "c" : "d"}`.padEnd(132, role === "initiator" ? "c" : "d"),
    workloadAttestationDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    runtimeId: `runtime-${role}`,
    taskId: `task-${role}`,
    endpoint: `https://${role}.example.test/a2a`,
    peerCardDigest: null,
    issuedAtMs: "1000",
    expiresAtMs: "3000",
    nonce: `nonce-${role}`,
    jti: `jti-${role}`,
    supportedArtifacts: ["invitation", "proposal", "counterproposal", "acceptance"],
  };
}

async function cardPair() {
  const responder = await signA2AAgentCard({
    card: cardPayload(RESPONDER, "responder"),
    signMessage: (raw) => RESPONDER.signMessage({ message: { raw } }),
  });
  const initiator = await signA2AAgentCard({
    card: { ...cardPayload(INITIATOR, "initiator"), peerCardDigest: a2aAgentCardDigest(responder) },
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });
  return { initiator, responder };
}

async function signedArtifact(account, artifact) {
  return {
    payload: artifact,
    signature: {
      address: account.address.toLowerCase(),
      algorithm: "eip191",
      value: await account.signMessage({ message: { raw: canonicalBytes(artifact) } }),
    },
  };
}

test("A2A envelopes bind card digests, artifact signatures, sequence, and predecessor", async () => {
  const { initiator, responder } = await cardPair();
  const artifact = await signedArtifact(INITIATOR, { statement: "proposal", amount: "100" });
  const envelope = await signA2AEnvelope({
    envelope: {
      schema: A2A_ENVELOPE_SCHEMA,
      version: 1,
      sessionId: SESSION_ID,
      fromCardDigest: a2aAgentCardDigest(initiator),
      toCardDigest: a2aAgentCardDigest(responder),
      sequence: "1",
      artifactType: "proposal",
      artifactDigest: a2aEnvelopeDigest({ artifact }),
      previousMessageDigest: null,
      expiresAtMs: "2500",
      nonce: "message-1",
      body: artifact,
      ciphertext: null,
    },
    fromCard: initiator,
    toCard: responder,
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });

  const verified = await verifyA2AEnvelope({ envelope, fromCard: initiator, toCard: responder, nowMs: 1500 });
  assert.equal(verified.schema, A2A_ENVELOPE_SCHEMA);
  assert.equal(a2aEnvelopeDigest(verified).length, 64);
});

test("A2A envelopes reject changed digest, director-authored artifacts, expiry, and card mismatch", async () => {
  const { initiator, responder } = await cardPair();
  const artifact = await signedArtifact(INITIATOR, { statement: "proposal", amount: "100" });
  const envelope = await signA2AEnvelope({
    envelope: {
      schema: A2A_ENVELOPE_SCHEMA,
      version: 1,
      sessionId: SESSION_ID,
      fromCardDigest: a2aAgentCardDigest(initiator),
      toCardDigest: a2aAgentCardDigest(responder),
      sequence: "1",
      artifactType: "proposal",
      artifactDigest: a2aEnvelopeDigest({ artifact }),
      previousMessageDigest: null,
      expiresAtMs: "2500",
      nonce: "message-1",
      body: artifact,
      ciphertext: null,
    },
    fromCard: initiator,
    toCard: responder,
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });
  const directorArtifact = await signedArtifact(DIRECTOR, { statement: "proposal", amount: "100" });
  const { signature: _signature, ...unsignedEnvelope } = envelope;
  const directorEnvelope = await signA2AEnvelope({
    envelope: { ...unsignedEnvelope, artifactDigest: a2aEnvelopeDigest({ artifact: directorArtifact }), body: directorArtifact },
    fromCard: initiator,
    toCard: responder,
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });

  for (const [name, badEnvelope, nowMs = 1500] of [
    ["changed digest", { ...envelope, artifactDigest: "9".repeat(64) }],
    ["director artifact", directorEnvelope],
    ["wrong card", { ...envelope, fromCardDigest: "8".repeat(64) }],
    ["extra key", { ...envelope, transcript: "raw private reasoning" }],
    ["expired", envelope, 2500],
  ]) {
    await assert.rejects(
      () => verifyA2AEnvelope({ envelope: badEnvelope, fromCard: initiator, toCard: responder, nowMs }),
      /A2A verification failed safely/,
      name,
    );
  }
});
