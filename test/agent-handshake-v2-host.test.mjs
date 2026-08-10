import assert from "node:assert/strict";
import test from "node:test";

import {
  prepareAgentHandshakeV2Identities,
  runAgentHandshakeV2HostSession,
} from "../src/agent-handshake/v2/host.mjs";
import { buildV2Fixture, SESSION_OPENED_BLOCK, buildV2Fixture as fixtureFactory } from "./support/agent-handshake-v2-fixture.mjs";

function ports(fixture, { existing = {}, registrationBlock } = {}) {
  const calls = [];
  return {
    calls,
    awaitIdentityClaim: async (role) => ({
      policyDigest: fixture.parties[role].policyDigest,
      sessionKeyAddress: fixture.parties[role].sessionKeyAddress,
    }),
    awaitPartyReady: async (role) => fixture.parties[role],
    findExistingIdentity: async (address) => existing[address] ?? null,
    fundIdentity: async (input) => { calls.push(["fund", input]); },
    reserveFunding: async (input) => { calls.push(["reserve", input]); },
    resolveRegistration: async (party) => {
      const role = party.erc8004.agentId === "9452" ? "initiator" : "responder";
      assert.deepEqual(party, fixture.parties[role]);
      return {
        owner: fixture.parties[role].sessionKeyAddress,
        registrationBlock: registrationBlock ?? fixture.parties[role].erc8004.registrationBlock,
      };
    },
  };
}

test("required-fresh reserves both exact claims, funds role-tagged seats, then proves post-session ownership", async () => {
  const fixture = await buildV2Fixture();
  const active = ports(fixture);
  const parties = await prepareAgentHandshakeV2Identities({
    identityPolicy: fixture.descriptorEnvelope.descriptor.identityPolicy,
    ports: active,
    sessionId: fixture.descriptorEnvelope.descriptor.sessionId,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
  });
  assert.deepEqual(parties, fixture.parties);
  assert.equal(active.calls[0][0], "reserve");
  assert.deepEqual(active.calls[0][1].addresses, [
    fixture.parties.initiator.sessionKeyAddress,
    fixture.parties.responder.sessionKeyAddress,
  ]);
  assert.deepEqual(active.calls.slice(1).map(([, value]) => value.role), ["initiator", "responder"]);
});

test("required-existing-or-fresh funds only missing identities and not-required performs no chain work", async () => {
  const fixture = await buildV2Fixture();
  const existing = ports(fixture, {
    existing: {
      [fixture.parties.initiator.sessionKeyAddress]: fixture.parties.initiator,
      [fixture.parties.responder.sessionKeyAddress]: fixture.parties.responder,
    },
  });
  await prepareAgentHandshakeV2Identities({
    identityPolicy: { ...fixture.descriptorEnvelope.descriptor.identityPolicy, erc8004: "required_existing_or_fresh" },
    ports: existing,
    sessionId: fixture.descriptorEnvelope.descriptor.sessionId,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
  });
  assert.equal(existing.calls.filter(([kind]) => kind === "fund").length, 0);

  const keyOnly = {
    initiator: { ...fixture.parties.initiator, erc8004: null },
    responder: { ...fixture.parties.responder, erc8004: null },
  };
  const noChainCalls = [];
  const noChain = {
    awaitIdentityClaim: async (role) => ({
      policyDigest: keyOnly[role].policyDigest,
      sessionKeyAddress: keyOnly[role].sessionKeyAddress,
    }),
    awaitPartyReady: async (role) => keyOnly[role],
    fundIdentity: async () => noChainCalls.push("fund"),
    reserveFunding: async () => noChainCalls.push("reserve"),
    resolveRegistration: async () => noChainCalls.push("resolve"),
    findExistingIdentity: async () => noChainCalls.push("find"),
  };
  await prepareAgentHandshakeV2Identities({
    identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null },
    ports: noChain,
    sessionId: fixture.descriptorEnvelope.descriptor.sessionId,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
  });
  assert.deepEqual(noChainCalls, []);
});

test("duplicate claims, pre-session fresh registration, and party drift fail closed", async () => {
  const fixture = await fixtureFactory();
  const same = ports(fixture);
  same.awaitIdentityClaim = async () => ({
    policyDigest: fixture.parties.initiator.policyDigest,
    sessionKeyAddress: fixture.parties.initiator.sessionKeyAddress,
  });
  await assert.rejects(() => prepareAgentHandshakeV2Identities({
    identityPolicy: fixture.descriptorEnvelope.descriptor.identityPolicy,
    ports: same,
    sessionId: fixture.descriptorEnvelope.descriptor.sessionId,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
  }));
  await assert.rejects(() => prepareAgentHandshakeV2Identities({
    identityPolicy: fixture.descriptorEnvelope.descriptor.identityPolicy,
    ports: ports(fixture, { registrationBlock: SESSION_OPENED_BLOCK }),
    sessionId: fixture.descriptorEnvelope.descriptor.sessionId,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
  }));
});

test("the v2 host verifies the full artifact chain and publishes one closing certificate", async () => {
  const fixture = await buildV2Fixture();
  const active = ports(fixture);
  let publishedDescriptor = null;
  let publishedResult = null;
  Object.assign(active, {
    acceptanceSigned: async () => {},
    anchorsRecorded: async () => {},
    awaitAcceptance: async () => fixture.acceptanceEnvelope,
    awaitAnchors: async () => ({
      receipts: fixture.receipts,
      transitions: fixture.transitions,
    }),
    awaitEvidence: async (role) => fixture.evidence[role],
    awaitInvitationClaimed: async () => 1786337000001,
    awaitProposal: async () => fixture.proposalEnvelope,
    certificateIssued: async () => {},
    checkerStage: async () => {},
    evidenceReceived: async () => {},
    failed: async () => {},
    partiesReady: async () => {},
    proposalSigned: async () => {},
    publishInitial: async () => {},
    publishDescriptor: async (value) => { publishedDescriptor = value; },
    publishResult: async (value) => { publishedResult = value; },
  });
  const result = await runAgentHandshakeV2HostSession({
    now: () => 1786337160000,
    ports: active,
    session: {
      expectedPublicKey: fixture.host.publicKey,
      hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
      keyId: fixture.host.keyId,
      privateKeyPem: fixture.host.privateKeyPem,
      protocol: "clockchain.agent-handshake/v2",
      repositorySha: "d".repeat(40),
      sessionDeadlineMs: 1786337600000,
      sessionId: "22222222-3333-4444-8555-666666666666",
      sessionOpenedAtMs: 1786337000000,
      sessionOpenedBlock: "6999",
      terms: {
        reference: "NS-1847",
        statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
        validForSeconds: "90",
        identityPolicy: fixture.descriptorEnvelope.descriptor.identityPolicy,
      },
    },
  });
  assert.deepEqual(publishedDescriptor, result.descriptorEnvelope);
  assert.deepEqual(publishedResult, result.certificate);
  assert.equal(result.verdict.outcome, "VERIFIED");
});
