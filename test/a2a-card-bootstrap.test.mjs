import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { A2A_AGENT_CARD_SCHEMA, a2aAgentCardDigest, signA2AAgentCard } from "../src/a2a/agent-card.mjs";
import { createA2ACardBootstrap } from "../src/a2a/card-bootstrap.mjs";
import { createDirectTaskChannel } from "../src/a2a/direct-task-channel.mjs";
import { INVITATION_BOOTSTRAP_CARD_CAPABILITY } from "../src/a2a/invitation-bootstrap-transport.mjs";

const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const NOW = 1786337000000;
const INITIATOR = privateKeyToAccount(`0x${"1".repeat(64)}`);
const RESPONDER = privateKeyToAccount(`0x${"2".repeat(64)}`);
const INITIATOR_CARD = privateKeyToAccount(`0x${"6".repeat(64)}`);
const RESPONDER_CARD = privateKeyToAccount(`0x${"7".repeat(64)}`);

function binding(role) {
  const account = role === "initiator" ? INITIATOR : RESPONDER;
  return {
    partySignerAddress: account.address.toLowerCase(),
    runtimeId: `runtime-${role}`,
    workloadAttestationDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    taskId: `task-${role}`,
    endpoint: `https://${role}.task.local:8443`,
  };
}

function unsignedCard(role, peerCardDigest = null, overrides = {}) {
  const account = role === "initiator" ? INITIATOR : RESPONDER;
  const cardAccount = role === "initiator" ? INITIATOR_CARD : RESPONDER_CARD;
  return {
    schema: A2A_AGENT_CARD_SCHEMA,
    version: 1,
    sessionId: SESSION_ID,
    role,
    partySignerAddress: account.address.toLowerCase(),
    partySignerPublicKey: account.publicKey,
    a2aCardPublicKey: cardAccount.publicKey,
    workloadAttestationDigest: binding(role).workloadAttestationDigest,
    runtimeId: binding(role).runtimeId,
    taskId: binding(role).taskId,
    endpoint: binding(role).endpoint,
    peerCardDigest,
    issuedAtMs: String(NOW - 1_000),
    expiresAtMs: String(NOW + 60_000),
    nonce: `nonce-${role}`,
    jti: `jti-${role}`,
    supportedArtifacts: ["invitation", "proposal", "counterproposal", "acceptance"],
    ...overrides,
  };
}

async function signedCard(role, peerCardDigest = null, overrides = {}) {
  const account = role === "initiator" ? INITIATOR : RESPONDER;
  return signA2AAgentCard({
    card: unsignedCard(role, peerCardDigest, overrides),
    signMessage: (raw) => account.signMessage({ message: { raw } }),
  });
}

function connectedTransports() {
  const state = {
    initiator: { receiver: null, retired: false },
    responder: { receiver: null, retired: false },
  };
  function transport(role) {
    const peerRole = role === "initiator" ? "responder" : "initiator";
    return Object.freeze({
      [INVITATION_BOOTSTRAP_CARD_CAPABILITY]: Object.freeze({
        registerReceiver(receiver) {
          assert.equal(state[role].receiver, null);
          state[role].receiver = receiver;
        },
        async sendCard({ artifactKind, body, expiresAtMs }) {
          assert.equal(state[role].retired, false);
          assert.ok(Number.isSafeInteger(expiresAtMs));
          const artifactDigest = await state[peerRole].receiver({ artifactKind, body });
          return { artifactDigest, acknowledged: true };
        },
        retire() {
          state[role].retired = true;
          state[role].receiver = null;
        },
      }),
    });
  }
  return { initiator: transport("initiator"), responder: transport("responder"), state };
}

async function bootstraps() {
  const transports = connectedTransports();
  const initiator = createA2ACardBootstrap({
    role: "initiator",
    sessionId: SESSION_ID,
    nowMs: () => NOW,
    ownBinding: binding("initiator"),
    peerBinding: binding("responder"),
    transport: transports.initiator,
  });
  const responder = createA2ACardBootstrap({
    role: "responder",
    sessionId: SESSION_ID,
    nowMs: () => NOW,
    ownBinding: binding("responder"),
    peerBinding: binding("initiator"),
    transport: transports.responder,
  });
  return { initiator, responder, transports };
}

test("card bootstrap deterministically binds responder first then the initiator pin", async () => {
  const { initiator, responder, transports } = await bootstraps();
  const responderCard = await signedCard("responder");
  await responder.publishResponderCard({ card: responderCard, expiresAtMs: NOW + 10_000 });
  assert.equal(a2aAgentCardDigest(initiator.takeResponderCard()), a2aAgentCardDigest(responderCard));

  const initiatorCard = await signedCard("initiator", a2aAgentCardDigest(responderCard));
  await initiator.publishInitiatorCard({ card: initiatorCard, expiresAtMs: NOW + 10_000 });
  assert.equal(a2aAgentCardDigest(responder.takeInitiatorCard()), a2aAgentCardDigest(initiatorCard));

  const initiatorPair = await initiator.verifiedPair();
  const responderPair = await responder.verifiedPair();
  for (const pair of [initiatorPair, responderPair]) {
    assert.equal(a2aAgentCardDigest(pair.initiatorCard), a2aAgentCardDigest(initiatorCard));
    assert.equal(a2aAgentCardDigest(pair.responderCard), a2aAgentCardDigest(responderCard));
    assert.ok(await createDirectTaskChannel({ sessionId: SESSION_ID, ...pair, nowMs: NOW }));
  }
  assert.equal(transports.state.initiator.retired, true);
  assert.equal(transports.state.responder.retired, true);
  for (const evidence of [initiator.publicEvidence(), responder.publicEvidence()]) {
    assert.equal(evidence.schema, "clockchain.a2a-card-bootstrap-evidence/v1");
    assert.match(evidence.cardDigests.initiator, /^[0-9a-f]{64}$/);
    assert.match(evidence.cardDigests.responder, /^[0-9a-f]{64}$/);
    assert.doesNotMatch(JSON.stringify(evidence), /partySignerPublicKey|a2aCardPublicKey|signature|private/i);
  }
});

test("card bootstrap rejects wrong order, peer pin, and immutable bindings", async () => {
  const { initiator, responder } = await bootstraps();
  const responderCard = await signedCard("responder");
  const initiatorCard = await signedCard("initiator", a2aAgentCardDigest(responderCard));
  await assert.rejects(
    () => initiator.publishInitiatorCard({ card: initiatorCard, expiresAtMs: NOW + 10_000 }),
    /A2A card bootstrap failed safely/,
  );
  await assert.rejects(
    () => responder.publishResponderCard({ card: initiatorCard, expiresAtMs: NOW + 10_000 }),
    /A2A card bootstrap failed safely/,
  );
  const pinnedResponderCard = await signedCard("responder", "9".repeat(64));
  await assert.rejects(
    () => responder.publishResponderCard({ card: pinnedResponderCard, expiresAtMs: NOW + 10_000 }),
    /A2A card bootstrap failed safely/,
  );
  const forgedResponderCard = await signA2AAgentCard({
    card: unsignedCard("responder"),
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });
  await assert.rejects(
    () => responder.publishResponderCard({ card: forgedResponderCard, expiresAtMs: NOW + 10_000 }),
    /A2A card bootstrap failed safely/,
  );
  const wrongPartyCard = await signA2AAgentCard({
    card: unsignedCard("responder", null, {
      partySignerAddress: INITIATOR.address.toLowerCase(),
      partySignerPublicKey: INITIATOR.publicKey,
    }),
    signMessage: (raw) => INITIATOR.signMessage({ message: { raw } }),
  });
  await assert.rejects(
    () => responder.publishResponderCard({ card: wrongPartyCard, expiresAtMs: NOW + 10_000 }),
    /A2A card bootstrap failed safely/,
  );

  const mutations = [
    { sessionId: "22222222-3333-4444-8555-666666666666" },
    { runtimeId: "runtime-other" },
    { workloadAttestationDigest: "8".repeat(64) },
    { taskId: "task-other" },
    { endpoint: "https://other.task.local:8443" },
  ];
  for (const mutation of mutations) {
    const fresh = await bootstraps();
    const mutatedCard = await signedCard("responder", null, mutation);
    await assert.rejects(
      () => fresh.responder.publishResponderCard({ card: mutatedCard, expiresAtMs: NOW + 10_000 }),
      /A2A card bootstrap failed safely/,
    );
  }
});

test("card bootstrap is one-use, rejects replay and expiry, and retires its bootstrap capability", async () => {
  const { initiator, responder, transports } = await bootstraps();
  const responderCard = await signedCard("responder");
  await assert.rejects(
    () => responder.publishResponderCard({ card: responderCard, expiresAtMs: NOW - 1 }),
    /A2A card bootstrap failed safely/,
  );
  const expiredCard = await signedCard("responder", null, { expiresAtMs: String(NOW) });
  await assert.rejects(
    () => responder.publishResponderCard({ card: expiredCard, expiresAtMs: NOW + 10_000 }),
    /A2A card bootstrap failed safely/,
  );
  await responder.publishResponderCard({ card: responderCard, expiresAtMs: NOW + 10_000 });
  await assert.rejects(
    () => responder.publishResponderCard({ card: responderCard, expiresAtMs: NOW + 10_000 }),
    /A2A card bootstrap failed safely/,
  );
  initiator.takeResponderCard();
  assert.throws(() => initiator.takeResponderCard(), /A2A card bootstrap failed safely/);
  const initiatorCard = await signedCard("initiator", a2aAgentCardDigest(responderCard));
  await initiator.publishInitiatorCard({ card: initiatorCard, expiresAtMs: NOW + 10_000 });
  responder.takeInitiatorCard();
  await initiator.verifiedPair();
  await responder.verifiedPair();
  await assert.rejects(
    () => transports.initiator[INVITATION_BOOTSTRAP_CARD_CAPABILITY].sendCard({
      artifactKind: "initiator_card",
      body: JSON.stringify(initiatorCard),
      expiresAtMs: NOW + 10_000,
    }),
  );
});

test("card bootstrap rejects hostile transport and capability accessors without executing traps", () => {
  let traps = 0;
  const hostileTransport = new Proxy({}, {
    get() {
      traps += 1;
      return null;
    },
  });
  assert.throws(() => createA2ACardBootstrap({
    role: "initiator",
    sessionId: SESSION_ID,
    nowMs: () => NOW,
    ownBinding: binding("initiator"),
    peerBinding: binding("responder"),
    transport: hostileTransport,
  }), /A2A card bootstrap failed safely/);
  assert.equal(traps, 0);

  const hostileCapability = {};
  Object.defineProperty(hostileCapability, "registerReceiver", {
    enumerable: true,
    get() {
      traps += 1;
      return () => {};
    },
  });
  Object.defineProperty(hostileCapability, "sendCard", { enumerable: true, value: async () => ({}) });
  Object.defineProperty(hostileCapability, "retire", { enumerable: true, value: () => {} });
  const transport = {};
  Object.defineProperty(transport, INVITATION_BOOTSTRAP_CARD_CAPABILITY, {
    enumerable: false,
    value: hostileCapability,
  });
  assert.throws(() => createA2ACardBootstrap({
    role: "initiator",
    sessionId: SESSION_ID,
    nowMs: () => NOW,
    ownBinding: binding("initiator"),
    peerBinding: binding("responder"),
    transport,
  }), /A2A card bootstrap failed safely/);
  assert.equal(traps, 0);
});
