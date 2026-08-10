import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_HANDSHAKE_TRANSITION_SCHEMA,
  AgentHandshakeProtocolError,
  agentTransitionDigest,
  createAgentAcceptance,
  createAgentAcknowledgment,
  createAgentProposal,
  validateAgentTransition,
  validateAgentTransitionChain,
} from "../src/agent-handshake/protocol.mjs";

const BASE = Object.freeze({
  expiresAtMs: "1786339800000",
  initiator: Object.freeze({
    address: "0x00112233445566778899aabbccddeeff00112233",
    agentId: "9452",
  }),
  reference: "NS-1847",
  responder: Object.freeze({
    address: "0xffeeddccbbaa99887766554433221100ffeeddcc",
    agentId: "9453",
  }),
  sessionDigest: "a".repeat(64),
  statementDigest: "b".repeat(64),
});

function chain() {
  const proposed = createAgentProposal(BASE);
  const accepted = createAgentAcceptance({
    ...BASE,
    predecessor: agentTransitionDigest(proposed),
  }, proposed);
  const acknowledged = createAgentAcknowledgment({
    ...BASE,
    predecessor: agentTransitionDigest(accepted),
  }, accepted);
  return { accepted, acknowledged, proposed };
}

test("generic transitions bind one statement in strict order", () => {
  const { accepted, acknowledged, proposed } = chain();
  assert.deepEqual(
    [proposed.kind, accepted.kind, acknowledged.kind],
    ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"],
  );
  assert.deepEqual(
    [proposed.sequence, accepted.sequence, acknowledged.sequence],
    ["1", "2", "3"],
  );
  assert.equal(proposed.predecessor, null);
  assert.equal(accepted.predecessor, agentTransitionDigest(proposed));
  assert.equal(acknowledged.predecessor, agentTransitionDigest(accepted));
  assert.equal(accepted.statementDigest, proposed.statementDigest);
  assert.equal(acknowledged.sessionDigest, proposed.sessionDigest);
  assert.equal(proposed.schema, AGENT_HANDSHAKE_TRANSITION_SCHEMA);
});

test("every transition validates as an exact, immutable public object", () => {
  for (const transition of Object.values(chain())) {
    const verified = validateAgentTransition(transition);
    assert.deepEqual(verified, transition);
    assert.ok(Object.isFrozen(verified));
    assert.ok(Object.isFrozen(verified.initiator));
    assert.ok(Object.isFrozen(verified.responder));
  }
  assert.deepEqual(
    validateAgentTransitionChain([chain().proposed, chain().accepted, chain().acknowledged]),
    [chain().proposed, chain().accepted, chain().acknowledged],
  );
});

test("transition validation fails closed on binding mutations", () => {
  const { accepted, acknowledged, proposed } = chain();
  const mutations = [
    { ...accepted, predecessor: "c".repeat(64) },
    { ...accepted, statementDigest: "c".repeat(64) },
    { ...accepted, sessionDigest: "c".repeat(64) },
    { ...accepted, expiresAtMs: "1786339800001" },
    { ...accepted, sequence: "3" },
    { ...accepted, kind: "ACKNOWLEDGED" },
    { ...accepted, initiator: { ...accepted.initiator, agentId: "9454" } },
    { ...accepted, responder: accepted.initiator },
    { ...accepted, externalActionPerformed: true },
    { ...accepted, extra: "field" },
  ];
  for (const value of [
    mutations[4],
    mutations[5],
    mutations[7],
    mutations[8],
    mutations[9],
  ]) {
    assert.throws(
      () => validateAgentTransition(value),
      (error) =>
        error instanceof AgentHandshakeProtocolError &&
        error.code === "AGENT_HANDSHAKE_TRANSITION_INVALID",
    );
  }
  assert.throws(
    () => createAgentAcceptance(
      { ...BASE, predecessor: agentTransitionDigest(acknowledged) },
      proposed,
    ),
    { code: "AGENT_HANDSHAKE_PREDECESSOR_INVALID" },
  );
  assert.throws(
    () => createAgentAcknowledgment(
      { ...BASE, predecessor: agentTransitionDigest(proposed) },
      accepted,
    ),
    { code: "AGENT_HANDSHAKE_PREDECESSOR_INVALID" },
  );
  for (const value of [...mutations.slice(0, 4), mutations[6]]) {
    assert.throws(
      () => validateAgentTransitionChain([proposed, value, acknowledged]),
      { code: "AGENT_HANDSHAKE_CHAIN_INVALID" },
    );
  }
});

test("generic transition bytes contain no payment vocabulary", () => {
  const text = JSON.stringify(chain()).toLowerCase();
  for (const word of [
    "amount",
    "currency",
    "invoice",
    "payer",
    "payee",
    "payment",
    "requestor",
  ]) {
    assert.equal(text.includes(word), false, word);
  }
});
