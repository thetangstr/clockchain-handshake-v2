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
const INITIATOR_CARD = privateKeyToAccount(`0x${"6".repeat(64)}`);
const RESPONDER_CARD = privateKeyToAccount(`0x${"7".repeat(64)}`);

function baseCard(account, role, overrides = {}) {
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

  const seenJtis = new Set();
  const seenNonces = new Set();
  await verifyA2AAgentCard({ card, expectedSessionId: SESSION_ID, expectedRole: "initiator", nowMs: 1500, seenJtis, seenNonces });
  assert.equal(seenJtis.has(card.jti), true);
  assert.equal(seenNonces.has(card.nonce), true);
  await assert.rejects(
    () => verifyA2AAgentCard({ card, expectedSessionId: SESSION_ID, expectedRole: "initiator", nowMs: 1500, seenJtis, seenNonces }),
    /A2A verification failed safely/,
    "replayed jti",
  );
});

test("A2A agent cards reject party public keys that do not derive to the party signer address", async () => {
  const responder = await signedCard(RESPONDER, "responder");
  const mismatch = await signA2AAgentCard({
    card: baseCard(INITIATOR, "initiator", {
      partySignerPublicKey: RESPONDER.publicKey,
      peerCardDigest: a2aAgentCardDigest(responder),
    }),
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });

  await assert.rejects(
    () => verifyA2AAgentCard({
      card: mismatch,
      expectedSessionId: SESSION_ID,
      expectedRole: "initiator",
      expectedPeerCardDigest: a2aAgentCardDigest(responder),
      nowMs: 1500,
    }),
    /A2A verification failed safely/,
  );
});

test("A2A agent cards require a delegated card key distinct from the party signer", async () => {
  const responder = await signedCard(RESPONDER, "responder");
  const collapsed = await signA2AAgentCard({
    card: baseCard(INITIATOR, "initiator", {
      a2aCardPublicKey: INITIATOR.publicKey,
      peerCardDigest: a2aAgentCardDigest(responder),
    }),
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });

  await assert.rejects(
    () => verifyA2AAgentCard({
      card: collapsed,
      expectedSessionId: SESSION_ID,
      expectedRole: "initiator",
      expectedPeerCardDigest: a2aAgentCardDigest(responder),
      nowMs: 1500,
    }),
    /A2A verification failed safely/,
  );
});

test("A2A agent cards reject hostile supportedArtifacts arrays without invoking getters or leaking contents", async () => {
  let getterCount = 0;
  const artifacts = ["invitation", "proposal", "counterproposal", "acceptance"];
  Object.defineProperty(artifacts, "0", {
    enumerable: true,
    get() {
      getterCount += 1;
      throw new Error("secret /private/tmp/card-artifacts");
    },
  });

  await assert.rejects(
    () => signA2AAgentCard({
      card: baseCard(INITIATOR, "initiator", { supportedArtifacts: artifacts }),
      signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
    }),
    (error) => {
      assert.equal(error.message, "A2A verification failed safely.");
      assert.doesNotMatch(error.message, /secret|private\/tmp/);
      return true;
    },
  );
  assert.equal(getterCount, 0);
});

test("A2A agent cards reject proxied supportedArtifacts before any proxy trap", async () => {
  let trapCount = 0;
  const artifacts = new Proxy(["invitation", "proposal", "counterproposal", "acceptance"], {
    get() {
      trapCount += 1;
      throw new Error("secret /Users/alice/card-artifacts");
    },
    getOwnPropertyDescriptor() {
      trapCount += 1;
      throw new Error("secret /Users/alice/card-artifacts");
    },
    getPrototypeOf() {
      trapCount += 1;
      throw new Error("secret /Users/alice/card-artifacts");
    },
    ownKeys() {
      trapCount += 1;
      throw new Error("secret /Users/alice/card-artifacts");
    },
  });

  await assert.rejects(
    () => signA2AAgentCard({
      card: baseCard(INITIATOR, "initiator", { supportedArtifacts: artifacts }),
      signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
    }),
    (error) => {
      assert.equal(error.message, "A2A verification failed safely.");
      assert.doesNotMatch(error.message, /secret|Users\/alice/);
      return true;
    },
  );
  assert.equal(trapCount, 0);
});
