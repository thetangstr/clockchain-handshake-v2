import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA,
  AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA,
  AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA,
  AGENT_HANDSHAKE_PROPOSAL_SCHEMA,
  agentHandshakeAcceptanceDigest,
  agentHandshakeProposalDigest,
  agentHandshakeStatementDigest,
  signAgentHandshakeAcceptance,
  signAgentHandshakeProposal,
  validateAgentHandshakeTerms,
  verifyAgentHandshakeAcceptance,
  verifyAgentHandshakeProposal,
} from "../src/agent-handshake/statement.mjs";

const INITIATOR = privateKeyToAccount(`0x${"1".repeat(64)}`);
const RESPONDER = privateKeyToAccount(`0x${"2".repeat(64)}`);
const IMPOSTOR = privateKeyToAccount(`0x${"3".repeat(64)}`);
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const STATEMENT = "Northstar Logistics and Harbor Supply confirm that these two registered agents are authorized to communicate about shipment reference NS-1847 for the next 45 minutes.";

function terms(overrides = {}) {
  return {
    reference: "NS-1847",
    statement: STATEMENT,
    validForMinutes: "45",
    ...overrides,
  };
}

function proposal(overrides = {}) {
  return {
    expiresAtMs: "1786339800000",
    externalActionPerformed: false,
    initiator: { address: INITIATOR.address.toLowerCase(), agentId: "101" },
    issuedAtMs: "1786337100000",
    protocol: "clockchain.agent-handshake/v1",
    reference: "NS-1847",
    repositorySha: "a".repeat(40),
    responder: { address: RESPONDER.address.toLowerCase(), agentId: "202" },
    schema: AGENT_HANDSHAKE_PROPOSAL_SCHEMA,
    sessionId: SESSION_ID,
    statement: STATEMENT,
    statementDigest: agentHandshakeStatementDigest(terms()),
    subjectRun: "stakeholder",
    validForMinutes: "45",
    ...overrides,
  };
}

async function signedProposal(overrides = {}, signer = INITIATOR) {
  return signAgentHandshakeProposal({
    proposal: proposal(overrides),
    signMessage: (bytes) => signer.signMessage({ message: { raw: bytes } }),
  });
}

function acceptance(proposalEnvelope, overrides = {}) {
  return {
    decision: "ACCEPTED",
    expiresAtMs: proposalEnvelope.proposal.expiresAtMs,
    externalActionPerformed: false,
    initiator: proposalEnvelope.proposal.initiator,
    issuedAtMs: "1786337160000",
    proposalDigest: agentHandshakeProposalDigest(proposalEnvelope),
    protocol: "clockchain.agent-handshake/v1",
    reference: proposalEnvelope.proposal.reference,
    repositorySha: proposalEnvelope.proposal.repositorySha,
    responder: proposalEnvelope.proposal.responder,
    schema: AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA,
    sessionId: proposalEnvelope.proposal.sessionId,
    statementDigest: "",
    subjectRun: "stakeholder",
    ...overrides,
  };
}

async function signedAcceptance(proposalEnvelope, overrides = {}, signer = RESPONDER) {
  const value = acceptance(proposalEnvelope, overrides);
  value.statementDigest = agentHandshakeStatementDigest({
    reference: proposalEnvelope.proposal.reference,
    statement: proposalEnvelope.proposal.statement,
    validForMinutes: "45",
  });
  return signAgentHandshakeAcceptance({
    acceptance: value,
    proposalEnvelope,
    signMessage: (bytes) => signer.signMessage({ message: { raw: bytes } }),
  });
}

test("generic terms contain only reference, statement, and validity", () => {
  assert.deepEqual(validateAgentHandshakeTerms(terms()), terms());
  for (const candidate of [
    { ...terms(), amount: "1" },
    { ...terms(), reference: "" },
    { ...terms(), statement: " x" },
    { ...terms(), validForMinutes: "045" },
    { ...terms(), validForMinutes: "61" },
  ]) {
    assert.throws(() => validateAgentHandshakeTerms(candidate), { code: "AGENT_HANDSHAKE_STATEMENT_INVALID" });
  }
});

test("the Initiator signs exact generic proposal bytes with no payment vocabulary", async () => {
  const envelope = await signedProposal();
  assert.equal(envelope.schema, AGENT_HANDSHAKE_PROPOSAL_ENVELOPE_SCHEMA);
  assert.deepEqual(Object.keys(envelope), ["proposal", "schema", "signature"]);
  assert.deepEqual(canonicalBytes(envelope.proposal), canonicalBytes(proposal()));
  assert.match(agentHandshakeProposalDigest(envelope), /^[0-9a-f]{64}$/);
  const text = canonicalBytes(envelope.proposal).toString("utf8").toLowerCase();
  for (const word of ["amount", "currency", "invoice", "payer", "payee", "payment", "requestor"]) {
    assert.equal(text.includes(word), false, word);
  }
  await assert.doesNotReject(verifyAgentHandshakeProposal({
    envelope,
    expectedTerms: terms(),
    expectedSessionId: SESSION_ID,
    expectedRepositorySha: "a".repeat(40),
    nowMs: 1786337160000,
  }));
});

test("the Responder signs acceptance bound to the exact proposal", async () => {
  const proposalEnvelope = await signedProposal();
  const envelope = await signedAcceptance(proposalEnvelope);
  assert.equal(envelope.schema, AGENT_HANDSHAKE_ACCEPTANCE_ENVELOPE_SCHEMA);
  assert.match(agentHandshakeAcceptanceDigest(envelope), /^[0-9a-f]{64}$/);
  await assert.doesNotReject(verifyAgentHandshakeAcceptance({
    envelope,
    proposalEnvelope,
    expectedTerms: terms(),
    expectedSessionId: SESSION_ID,
    expectedRepositorySha: "a".repeat(40),
    nowMs: 1786337160000,
  }));
});

test("generic proposal and acceptance fail closed under mutation or foreign signing", async () => {
  const proposalEnvelope = await signedProposal();
  const acceptanceEnvelope = await signedAcceptance(proposalEnvelope);
  const proposalVerify = (envelope) => verifyAgentHandshakeProposal({
    envelope,
    expectedTerms: terms(),
    expectedSessionId: SESSION_ID,
    expectedRepositorySha: "a".repeat(40),
    nowMs: 1786337160000,
  });
  const acceptanceVerify = (envelope, proposalValue = proposalEnvelope) => verifyAgentHandshakeAcceptance({
    envelope,
    proposalEnvelope: proposalValue,
    expectedTerms: terms(),
    expectedSessionId: SESSION_ID,
    expectedRepositorySha: "a".repeat(40),
    nowMs: 1786337160000,
  });

  await assert.rejects(proposalVerify(await signedProposal({}, IMPOSTOR)));
  await assert.rejects(acceptanceVerify(await signedAcceptance(proposalEnvelope, {}, IMPOSTOR)));

  const changedProposal = structuredClone(proposalEnvelope);
  changedProposal.proposal.statement = `${STATEMENT} Changed.`;
  await assert.rejects(proposalVerify(changedProposal));

  const changedAcceptance = structuredClone(acceptanceEnvelope);
  changedAcceptance.acceptance.reference = "OTHER";
  await assert.rejects(acceptanceVerify(changedAcceptance));

  await assert.rejects(acceptanceVerify(
    acceptanceEnvelope,
    await signedProposal({
      reference: "OTHER",
      statementDigest: agentHandshakeStatementDigest({
        ...terms(),
        reference: "OTHER",
      }),
    }),
  ));
});
