import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import { agentTransitionDigest } from "../src/agent-handshake/protocol.mjs";
import {
  AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA,
  signAgentHandshakeEvidence,
} from "../src/agent-handshake/evidence.mjs";
import {
  AgentHandshakeVerdictError,
  verifyAgentHandshakeAuthorization,
} from "../src/agent-handshake/verdict.mjs";
import {
  INITIATOR,
  NOW_MS,
  REPOSITORY_SHA,
  RESPONDER,
  SESSION_ID,
  TERMS,
  buildAgentHandshakeFixture,
} from "./support/agent-handshake-fixture.mjs";

async function partyEvidence(fixture, role, account) {
  return signAgentHandshakeEvidence({
    result: {
      externalActionPerformed: false,
      party: fixture[role],
      reference: TERMS.reference,
      repositorySha: REPOSITORY_SHA,
      role,
      schema: AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA,
      sessionDigest: fixture.base.sessionDigest,
      statementDigest: fixture.base.statementDigest,
      transitionDigests: fixture.transitions.map(agentTransitionDigest),
    },
    signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }),
  });
}

async function validInput() {
  const fixture = await buildAgentHandshakeFixture();
  return {
    acceptanceEnvelope: fixture.acceptanceEnvelope,
    descriptorEnvelope: fixture.descriptorEnvelope,
    evidence: {
      initiator: await partyEvidence(fixture, "initiator", INITIATOR),
      responder: await partyEvidence(fixture, "responder", RESPONDER),
    },
    expectedPublicKey: fixture.host.publicKey,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
    proposalEnvelope: fixture.proposalEnvelope,
    receipts: fixture.receipts,
    resolveOwner: async (agentId) =>
      agentId === fixture.initiator.agentId
        ? fixture.initiator.address
        : fixture.responder.address,
    transitions: fixture.transitions,
  };
}

test("only complete, distinct, statement-bound evidence verifies", async () => {
  const verdict = await verifyAgentHandshakeAuthorization(await validInput());
  assert.equal(verdict.outcome, "VERIFIED");
  assert.equal(verdict.externalActionPerformed, false);
  assert.deepEqual(verdict.transitions.map(({ kind }) => kind), [
    "proposal",
    "acceptance",
    "acknowledgment",
  ]);
});

test("the positive outcome has one emission site", async () => {
  const source = await readFile(new URL("../src/agent-handshake/verdict.mjs", import.meta.url), "utf8");
  assert.equal(source.match(/VERIFIED/g)?.length, 1);
});

test("checker rejects missing evidence, identity mismatch, same owner, ordering, time, and context drift", async () => {
  const cases = [];
  const missing = await validInput();
  missing.evidence = { ...missing.evidence, responder: null };
  cases.push(missing);
  const ownerMismatch = await validInput();
  ownerMismatch.resolveOwner = async () => "0x9999999999999999999999999999999999999999";
  cases.push(ownerMismatch);
  const sameOwner = await validInput();
  sameOwner.resolveOwner = async () => sameOwner.descriptorEnvelope.descriptor.initiator.address;
  cases.push(sameOwner);
  const reordered = await validInput();
  reordered.receipts = [...reordered.receipts].reverse();
  cases.push(reordered);
  const wrongHeight = await validInput();
  wrongHeight.receipts = wrongHeight.receipts.map((entry, index) => ({
    ...entry,
    blockHeight: index === 1 ? "6999" : entry.blockHeight,
  }));
  cases.push(wrongHeight);
  const late = await validInput();
  late.nowMs = 1786339800000;
  cases.push(late);
  const statementDrift = await validInput();
  statementDrift.expectedTerms = { ...TERMS, statement: `${TERMS.statement} Changed.` };
  cases.push(statementDrift);
  const repositoryDrift = await validInput();
  repositoryDrift.expectedRepositorySha = "e".repeat(40);
  cases.push(repositoryDrift);
  for (const value of cases) {
    await assert.rejects(
      () => verifyAgentHandshakeAuthorization(value),
      (error) => error instanceof AgentHandshakeVerdictError,
    );
  }
});
