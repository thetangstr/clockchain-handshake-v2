import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import {
  A2A_AGENT_CARD_SCHEMA,
  a2aAgentCardDigest,
  signA2AAgentCard,
  verifyA2AAgentCard,
} from "../src/a2a/agent-card.mjs";

const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const INITIATOR = privateKeyToAccount(`0x${"1".repeat(64)}`);
const RESPONDER = privateKeyToAccount(`0x${"2".repeat(64)}`);
const DIRECTOR = privateKeyToAccount(`0x${"3".repeat(64)}`);

function baseCard(account, role, overrides = {}) {
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
    expiresAtMs: "2000",
    nonce: `nonce-${role}`,
    jti: `jti-${role}`,
    supportedArtifacts: ["invitation", "proposal", "counterproposal", "acceptance"],
    ...overrides,
  };
}

async function signedCard(account, role, overrides = {}) {
  return signA2AAgentCard({
    card: baseCard(account, role, overrides),
    signMessage: (raw) => account.signMessage({ message: { raw } }),
  });
}

test("A2A agent cards are exact party-signed peer-bound public objects", async () => {
  const responder = await signedCard(RESPONDER, "responder");
  const initiator = await signedCard(INITIATOR, "initiator", {
    peerCardDigest: a2aAgentCardDigest(responder),
  });
  const verified = await verifyA2AAgentCard({
    card: initiator,
    expectedSessionId: SESSION_ID,
    expectedRole: "initiator",
    expectedPeerCardDigest: a2aAgentCardDigest(responder),
    nowMs: 1500,
  });

  assert.equal(verified.schema, A2A_AGENT_CARD_SCHEMA);
  assert.equal(verified.partySignerAddress, INITIATOR.address.toLowerCase());
  assert.match(a2aAgentCardDigest(verified), /^[0-9a-f]{64}$/);
});

test("A2A agent cards reject signature, peer, expiry, replay id, and schema drift", async () => {
  const responder = await signedCard(RESPONDER, "responder");
  const card = await signedCard(INITIATOR, "initiator", {
    peerCardDigest: a2aAgentCardDigest(responder),
  });
  const foreign = await signA2AAgentCard({
    card: { ...baseCard(INITIATOR, "initiator"), peerCardDigest: a2aAgentCardDigest(responder) },
    signMessage: (raw) => DIRECTOR.signMessage({ message: { raw } }),
  });
  const cases = [
    ["foreign signature", foreign],
    ["wrong peer", { ...card, peerCardDigest: "9".repeat(64) }],
    ["wrong session", { ...card, sessionId: "22222222-2222-4333-8444-555555555555" }],
    ["wrong role", { ...card, role: "responder" }],
    ["extra key", { ...card, transcript: "secret" }],
  ];

  for (const [name, badCard] of cases) {
    await assert.rejects(
      () => verifyA2AAgentCard({
        card: badCard,
        expectedSessionId: SESSION_ID,
        expectedRole: "initiator",
        expectedPeerCardDigest: a2aAgentCardDigest(responder),
        nowMs: 1500,
      }),
      /A2A verification failed safely/,
      name,
    );
  }
  await assert.rejects(
    () => verifyA2AAgentCard({ card, expectedSessionId: SESSION_ID, expectedRole: "initiator", nowMs: 2000 }),
    /A2A verification failed safely/,
    "expired",
  );

  const seenJtis = new Set([card.jti]);
  await assert.rejects(
    () => verifyA2AAgentCard({ card, expectedSessionId: SESSION_ID, expectedRole: "initiator", nowMs: 1500, seenJtis }),
    /A2A verification failed safely/,
    "replayed jti",
  );
});
