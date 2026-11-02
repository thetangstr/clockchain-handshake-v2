// H-REQ-02: an acceptance must agree with the proposal it names on every bound
// field, at construction time and at host verification time.
import assert from "node:assert/strict";
import test from "node:test";
import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/core/canonical.mjs";
import * as protocol from "../src/agent-handshake/v2/protocol.mjs";
import {
  agentHandshakeV2ProposalDigest,
  signAgentHandshakeV2Acceptance,
  signAgentHandshakeV2Proposal,
  validateAgentHandshakeV2AcceptancePayload,
  verifyAgentHandshakeV2Acceptance,
} from "../src/agent-handshake/v2/protocol.mjs";
import { verifyAgentHandshakeV2Authorization } from "../src/agent-handshake/v2/verdict.mjs";
import {
  INITIATOR, NOW_MS, REPOSITORY_SHA, RESPONDER, SESSION_ID, TERMS, buildV2Fixture,
} from "./support/agent-handshake-v2-fixture.mjs";

const ACCEPTANCE_ENVELOPE_SCHEMA = "clockchain.agent-handshake-acceptance-envelope/v2";
const PROPOSAL_ENVELOPE_SCHEMA = "clockchain.agent-handshake-proposal-envelope/v2";
const THIRD = privateKeyToAccount("0x" + "6".repeat(64));

async function signed(payload, schema, account, address = account.address.toLowerCase()) {
  return {
    payload,
    schema,
    signature: {
      address,
      algorithm: "eip191",
      value: await account.signMessage({ message: { raw: canonicalBytes(payload) } }),
    },
  };
}

// Each entry changes exactly one bound field of the valid acceptance and
// leaves the payload structurally valid on its own.
function contradictions(fixture) {
  const base = fixture.acceptanceEnvelope.payload;
  const proposal = fixture.proposalEnvelope.payload;
  return [
    ["repositorySha", { ...base, repositorySha: "e".repeat(40) }],
    ["reference", { ...base, reference: "NS-1848" }],
    ["statementDigest", { ...base, statementDigest: "f".repeat(64) }],
    ["identityPolicy", { ...base, identityPolicy: { ...base.identityPolicy, erc8004: "required_existing_or_fresh" } }],
    ["issuedAtMs", { ...base, issuedAtMs: String(BigInt(proposal.issuedAtMs) - 1n) }],
  ];
}

function hostInput(fixture, envelope, overrides = {}) {
  return {
    envelope,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
    proposalEnvelope: fixture.proposalEnvelope,
    ...overrides,
  };
}

function authorizationInput(fixture, acceptanceEnvelope) {
  return {
    acceptanceEnvelope,
    descriptorEnvelope: fixture.descriptorEnvelope,
    evidence: fixture.evidence,
    expectedHostSessionKeyCertificateDigest: fixture.descriptorEnvelope.descriptor.hostSessionKeyCertificateDigest,
    expectedPublicKey: fixture.host.publicKey,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    expectedTerms: TERMS,
    nowMs: NOW_MS,
    proposalEnvelope: fixture.proposalEnvelope,
    receipts: fixture.receipts,
    resolveRegistration: async (agentId) => {
      const role = agentId === "9452" ? "initiator" : "responder";
      return {
        owner: fixture.parties[role].sessionKeyAddress,
        registrationBlock: fixture.parties[role].erc8004.registrationBlock,
      };
    },
    transitions: fixture.transitions,
  };
}

// Every case runs, so a failure names each field that was not refused.
async function outcomes(cases, run) {
  const result = {};
  for (const [field, payload] of cases) {
    result[field] = await run(payload).then(() => "accepted", (error) => error?.name ?? "refused");
  }
  return result;
}

test("the host acceptance verifier refuses each validly signed acceptance that contradicts its proposal", async () => {
  const fixture = await buildV2Fixture();
  const cases = contradictions(fixture);
  for (const [field, payload] of cases) {
    assert.doesNotThrow(() => validateAgentHandshakeV2AcceptancePayload(payload), field);
  }
  const actual = await outcomes(cases, async (payload) => verifyAgentHandshakeV2Acceptance(
    hostInput(fixture, await signed(payload, ACCEPTANCE_ENVELOPE_SCHEMA, RESPONDER)),
  ));
  assert.deepEqual(actual, Object.fromEntries(cases.map(([field]) => [field, "AgentHandshakeV2ProtocolError"])));
});

test("constructor refuses the same five, and signMessage is never called", async () => {
  const fixture = await buildV2Fixture();
  let calls = 0;
  const signMessage = async (bytes) => {
    calls += 1;
    return RESPONDER.signMessage({ message: { raw: bytes } });
  };
  for (const [field, payload] of contradictions(fixture)) {
    await assert.rejects(
      () => signAgentHandshakeV2Acceptance({ acceptance: payload, proposalEnvelope: fixture.proposalEnvelope, signMessage }),
      { name: "AgentHandshakeV2ProtocolError" },
      `constructor signed an acceptance with a contradictory ${field}`,
    );
  }
  assert.equal(calls, 0);
});

test("verifyAgentHandshakeV2Authorization refuses a contradictory acceptance", async () => {
  const fixture = await buildV2Fixture();
  const valid = await verifyAgentHandshakeV2Authorization(authorizationInput(fixture, fixture.acceptanceEnvelope));
  assert.equal(valid.outcome, "VERIFIED");
  const cases = contradictions(fixture);
  const actual = await outcomes(cases, async (payload) => verifyAgentHandshakeV2Authorization(
    authorizationInput(fixture, await signed(payload, ACCEPTANCE_ENVELOPE_SCHEMA, RESPONDER)),
  ));
  assert.deepEqual(Object.entries(actual).filter(([, value]) => value === "accepted").map(([field]) => field), []);
});

test("assertAgentHandshakeV2AcceptanceBinding accepts the matching pair and refuses each contradiction", async () => {
  const fixture = await buildV2Fixture();
  const assertBinding = protocol.assertAgentHandshakeV2AcceptanceBinding;
  assert.equal(typeof assertBinding, "function");
  const proposal = fixture.proposalEnvelope.payload;
  assert.doesNotThrow(() => assertBinding({ acceptance: fixture.acceptanceEnvelope.payload, proposal }));
  const base = fixture.acceptanceEnvelope.payload;
  for (const [field, payload] of [
    ...contradictions(fixture),
    ["proposalDigest", { ...base, proposalDigest: "a".repeat(64) }],
    ["sessionId", { ...base, sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }],
    ["expiresAtMs", { ...base, expiresAtMs: String(BigInt(base.expiresAtMs) - 1n) }],
    ["initiator", { ...base, initiator: { ...base.initiator, policyDigest: "9".repeat(64) } }],
    ["responder", { ...base, responder: { ...base.responder, policyDigest: "9".repeat(64) } }],
  ]) {
    assert.throws(
      () => assertBinding({ acceptance: payload, proposal }),
      { name: "AgentHandshakeV2ProtocolError" },
      `binding accepted a contradictory ${field}`,
    );
  }
});

test("wrong proposal signer, mismatched proposalDigest, and a proposal naming another responder are refused", async () => {
  const fixture = await buildV2Fixture();
  const base = fixture.acceptanceEnvelope.payload;
  const proposal = fixture.proposalEnvelope.payload;
  let calls = 0;
  const signMessage = async (bytes) => {
    calls += 1;
    return RESPONDER.signMessage({ message: { raw: bytes } });
  };

  // The proposal bytes are unchanged but the signature is not the initiator's.
  for (const mismatched of [
    await signed(proposal, PROPOSAL_ENVELOPE_SCHEMA, RESPONDER, proposal.initiator.sessionKeyAddress),
    await signed(proposal, PROPOSAL_ENVELOPE_SCHEMA, THIRD, proposal.initiator.sessionKeyAddress),
    await signed(proposal, PROPOSAL_ENVELOPE_SCHEMA, RESPONDER),
  ]) {
    await assert.rejects(() => verifyAgentHandshakeV2Acceptance(
      hostInput(fixture, fixture.acceptanceEnvelope, { proposalEnvelope: mismatched }),
    ));
  }

  const wrongDigest = { ...base, proposalDigest: "a".repeat(64) };
  const wrongDigestEnvelope = await signed(wrongDigest, ACCEPTANCE_ENVELOPE_SCHEMA, RESPONDER);
  await assert.rejects(() => verifyAgentHandshakeV2Acceptance(hostInput(fixture, wrongDigestEnvelope)));
  await assert.rejects(() => signAgentHandshakeV2Acceptance({
    acceptance: wrongDigest, proposalEnvelope: fixture.proposalEnvelope, signMessage,
  }));

  const responder = fixture.parties.responder;
  const otherResponder = {
    sessionKeyAddress: THIRD.address.toLowerCase(),
    policyDigest: responder.policyDigest,
    erc8004: {
      ...responder.erc8004,
      agentId: "9454",
      reference: `${responder.erc8004.chainId}:${responder.erc8004.registryAddress}:9454`,
    },
  };
  const otherProposal = await signAgentHandshakeV2Proposal({
    proposal: { ...proposal, responder: otherResponder },
    signMessage: (bytes) => INITIATOR.signMessage({ message: { raw: bytes } }),
  });
  const reboundAcceptance = { ...base, proposalDigest: agentHandshakeV2ProposalDigest(otherProposal) };
  const reboundEnvelope = await signed(reboundAcceptance, ACCEPTANCE_ENVELOPE_SCHEMA, RESPONDER);
  await assert.rejects(() => verifyAgentHandshakeV2Acceptance(
    hostInput(fixture, reboundEnvelope, { proposalEnvelope: otherProposal }),
  ));
  await assert.rejects(() => signAgentHandshakeV2Acceptance({
    acceptance: reboundAcceptance, proposalEnvelope: otherProposal, signMessage,
  }));
  assert.equal(calls, 0);
});

test("a valid acceptance passes constructor and host; an acceptance issued at the proposal's issue time is accepted", async () => {
  const fixture = await buildV2Fixture();
  const signMessage = (bytes) => RESPONDER.signMessage({ message: { raw: bytes } });
  const rebuilt = await signAgentHandshakeV2Acceptance({
    acceptance: fixture.acceptanceEnvelope.payload,
    proposalEnvelope: fixture.proposalEnvelope,
    signMessage,
  });
  assert.deepEqual(rebuilt, fixture.acceptanceEnvelope);
  const verified = await verifyAgentHandshakeV2Acceptance(hostInput(fixture, fixture.acceptanceEnvelope));
  assert.equal(verified.payload.proposalDigest, agentHandshakeV2ProposalDigest(fixture.proposalEnvelope));

  const sameInstant = await signAgentHandshakeV2Acceptance({
    acceptance: { ...fixture.acceptanceEnvelope.payload, issuedAtMs: fixture.proposalEnvelope.payload.issuedAtMs },
    proposalEnvelope: fixture.proposalEnvelope,
    signMessage,
  });
  const boundary = await verifyAgentHandshakeV2Acceptance(hostInput(fixture, sameInstant));
  assert.equal(boundary.payload.issuedAtMs, fixture.proposalEnvelope.payload.issuedAtMs);
});
