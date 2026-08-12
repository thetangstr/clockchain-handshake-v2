import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/core/canonical.mjs";
import { A2A_AGENT_CARD_SCHEMA, a2aAgentCardDigest, signA2AAgentCard } from "../src/a2a/agent-card.mjs";
import { A2A_ENVELOPE_SCHEMA, a2aEnvelopeDigest, signA2AEnvelope } from "../src/a2a/envelope.mjs";
import { createDirectTaskChannel } from "../src/a2a/direct-task-channel.mjs";

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
    endpoint: `https://${role}.example.test/a2a`,
    peerCardDigest,
    issuedAtMs: "1000",
    expiresAtMs: "3000",
    nonce: `nonce-${role}`,
    jti: `jti-${role}`,
    supportedArtifacts: ["invitation", "proposal", "counterproposal", "acceptance"],
  };
}

async function pair(overrides = {}) {
  const responder = await signA2AAgentCard({
    card: { ...unsignedCard(RESPONDER, "responder"), ...overrides.responder },
    signMessage: (raw) => RESPONDER.signMessage({ message: { raw } }),
  });
  const initiator = await signA2AAgentCard({
    card: { ...unsignedCard(INITIATOR, "initiator", a2aAgentCardDigest(responder)), ...overrides.initiator },
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });
  return { initiator, responder };
}

async function signedArtifact(account, value) {
  return {
    payload: value,
    signature: {
      address: account.address.toLowerCase(),
      algorithm: "eip191",
      value: await account.signMessage({ message: { raw: canonicalBytes(value) } }),
    },
  };
}

async function message({ fromAccount, fromCard, toCard, sequence, previousMessageDigest = null, nonce = `message-${sequence}` }) {
  const artifact = await signedArtifact(fromAccount, { kind: "proposal", sequence });
  return signA2AEnvelope({
    envelope: {
      schema: A2A_ENVELOPE_SCHEMA,
      version: 1,
      sessionId: SESSION_ID,
      fromCardDigest: a2aAgentCardDigest(fromCard),
      toCardDigest: a2aAgentCardDigest(toCard),
      sequence,
      artifactType: "proposal",
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

test("direct task channel delivers private bodies while evidence retains only public digests", async () => {
  const cards = await pair();
  const channel = await createDirectTaskChannel({
    sessionId: SESSION_ID,
    initiatorCard: cards.initiator,
    responderCard: cards.responder,
    nowMs: 1500,
  });
  const first = await message({ fromAccount: INITIATOR, fromCard: cards.initiator, toCard: cards.responder, sequence: "1" });
  await channel.send({ fromRole: "initiator", toRole: "responder", envelope: first, nowMs: 1500 });
  const received = await channel.receive({ role: "responder" });

  assert.equal(received.body.payload.kind, "proposal");
  const evidence = channel.publicEvidence();
  assert.equal(evidence.schema, "clockchain.a2a-direct-task-channel-evidence/v1");
  assert.deepEqual(Object.keys(evidence.messages[0]).sort(), [
    "artifactDigest",
    "artifactType",
    "fromRole",
    "messageDigest",
    "sequence",
    "toRole",
  ]);
  assert.doesNotMatch(JSON.stringify(evidence), /transcript|private reasoning|body|ciphertext/);
});

test("direct task channel rejects reused card jti or nonce during bootstrap", async () => {
  const reusedJti = await pair({ initiator: { jti: "shared-jti" }, responder: { jti: "shared-jti" } });
  await assert.rejects(
    () => createDirectTaskChannel({
      sessionId: SESSION_ID,
      initiatorCard: reusedJti.initiator,
      responderCard: reusedJti.responder,
      nowMs: 1500,
    }),
    /A2A verification failed safely/,
    "reused jti",
  );
  const reusedNonce = await pair({ initiator: { nonce: "shared-nonce" }, responder: { nonce: "shared-nonce" } });
  await assert.rejects(
    () => createDirectTaskChannel({
      sessionId: SESSION_ID,
      initiatorCard: reusedNonce.initiator,
      responderCard: reusedNonce.responder,
      nowMs: 1500,
    }),
    /A2A verification failed safely/,
    "reused nonce",
  );
});

test("direct task channel rejects collapsed A2A card keys and nondeterministic peer bootstrap pins", async () => {
  const sharedCardKey = await pair({
    responder: { a2aCardPublicKey: INITIATOR_CARD.publicKey },
  });
  await assert.rejects(
    () => createDirectTaskChannel({
      sessionId: SESSION_ID,
      initiatorCard: sharedCardKey.initiator,
      responderCard: sharedCardKey.responder,
      nowMs: 1500,
    }),
    /A2A verification failed safely/,
    "shared delegated key",
  );

  const arbitraryResponderPin = await pair({
    responder: { peerCardDigest: "9".repeat(64) },
  });
  await assert.rejects(
    () => createDirectTaskChannel({
      sessionId: SESSION_ID,
      initiatorCard: arbitraryResponderPin.initiator,
      responderCard: arbitraryResponderPin.responder,
      nowMs: 1500,
    }),
    /A2A verification failed safely/,
    "responder cannot pin arbitrary bootstrap peer",
  );
});

test("direct task channel rejects replay, nonmonotonic sequence, and broken predecessor chains", async () => {
  const cards = await pair();
  const channel = await createDirectTaskChannel({
    sessionId: SESSION_ID,
    initiatorCard: cards.initiator,
    responderCard: cards.responder,
    nowMs: 1500,
  });
  const first = await message({ fromAccount: INITIATOR, fromCard: cards.initiator, toCard: cards.responder, sequence: "1" });
  await channel.send({ fromRole: "initiator", toRole: "responder", envelope: first, nowMs: 1500 });

  await assert.rejects(
    () => channel.send({ fromRole: "initiator", toRole: "responder", envelope: first, nowMs: 1500 }),
    /A2A verification failed safely/,
    "replay nonce",
  );
  await assert.rejects(
    () => channel.send({ fromRole: "initiator", toRole: "responder", envelope: { ...first, nonce: "message-2" }, nowMs: 1500 }),
    /A2A verification failed safely/,
    "nonmonotonic sequence",
  );
  const second = await message({
    fromAccount: INITIATOR,
    fromCard: cards.initiator,
    toCard: cards.responder,
    sequence: "2",
    previousMessageDigest: "9".repeat(64),
    nonce: "message-2",
  });
  await assert.rejects(
    () => channel.send({ fromRole: "initiator", toRole: "responder", envelope: second, nowMs: 1500 }),
    /A2A verification failed safely/,
    "broken predecessor",
  );
});
