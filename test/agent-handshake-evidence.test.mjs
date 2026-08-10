import assert from "node:assert/strict";
import test from "node:test";

import {
  agentTransitionDigest,
} from "../src/agent-handshake/protocol.mjs";
import {
  AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA,
  AgentHandshakeEvidenceError,
  signAgentHandshakeEvidence,
  verifyAgentHandshakeEvidence,
} from "../src/agent-handshake/evidence.mjs";
import {
  INITIATOR,
  REPOSITORY_SHA,
  buildAgentHandshakeFixture,
} from "./support/agent-handshake-fixture.mjs";

function result(fixture, role = "initiator", overrides = {}) {
  const party = fixture[role];
  return {
    externalActionPerformed: false,
    party,
    reference: fixture.base.reference,
    repositorySha: REPOSITORY_SHA,
    role,
    schema: AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA,
    sessionDigest: fixture.base.sessionDigest,
    statementDigest: fixture.base.statementDigest,
    transitionDigests: fixture.transitions.map(agentTransitionDigest),
    ...overrides,
  };
}

async function signed(fixture, role = "initiator", overrides = {}) {
  const account = role === "initiator" ? INITIATOR : (await import("./support/agent-handshake-fixture.mjs")).RESPONDER;
  return signAgentHandshakeEvidence({
    result: result(fixture, role, overrides),
    signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }),
  });
}

test("each stakeholder signs a complete statement-bound result", async () => {
  const fixture = await buildAgentHandshakeFixture();
  for (const role of ["initiator", "responder"]) {
    const envelope = await signed(fixture, role);
    const verified = await verifyAgentHandshakeEvidence({
      envelope,
      expectedParty: fixture[role],
      expectedReference: fixture.base.reference,
      expectedRepositorySha: REPOSITORY_SHA,
      expectedRole: role,
      expectedSessionDigest: fixture.base.sessionDigest,
      expectedStatementDigest: fixture.base.statementDigest,
      expectedTransitionDigests: fixture.transitions.map(agentTransitionDigest),
    });
    assert.equal(verified.result.role, role);
    assert.equal(verified.result.externalActionPerformed, false);
  }
});

test("evidence rejects signature, role, party, statement, receipt, and repository drift", async () => {
  const fixture = await buildAgentHandshakeFixture();
  const envelope = await signed(fixture);
  const common = {
    envelope,
    expectedParty: fixture.initiator,
    expectedReference: fixture.base.reference,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedRole: "initiator",
    expectedSessionDigest: fixture.base.sessionDigest,
    expectedStatementDigest: fixture.base.statementDigest,
    expectedTransitionDigests: fixture.transitions.map(agentTransitionDigest),
  };
  const cases = [
    { ...common, expectedRole: "responder" },
    { ...common, expectedParty: fixture.responder },
    { ...common, expectedStatementDigest: "f".repeat(64) },
    { ...common, expectedRepositorySha: "e".repeat(40) },
    { ...common, expectedTransitionDigests: [...common.expectedTransitionDigests].reverse() },
    { ...common, expectedReference: "NS-1848" },
  ];
  for (const value of cases) {
    await assert.rejects(
      () => verifyAgentHandshakeEvidence(value),
      (error) => error instanceof AgentHandshakeEvidenceError,
    );
  }
  const tampered = structuredClone(envelope);
  tampered.signature.value = `0x${"0".repeat(130)}`;
  await assert.rejects(
    () => verifyAgentHandshakeEvidence({ ...common, envelope: tampered }),
    (error) => error instanceof AgentHandshakeEvidenceError,
  );
});

test("generic evidence contains no payment vocabulary", async () => {
  const fixture = await buildAgentHandshakeFixture();
  const text = JSON.stringify(await signed(fixture)).toLowerCase();
  for (const word of ["amount", "currency", "invoice", "payer", "payee", "payment", "requestor"]) {
    assert.equal(text.includes(word), false, word);
  }
});
