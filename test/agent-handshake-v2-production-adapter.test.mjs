import assert from "node:assert/strict";
import test from "node:test";
import { encodeEventTopics, parseAbiItem, zeroAddress } from "viem";

import {
  AGENT_HANDSHAKE_V2_FUNDING_AMOUNT_ETH,
  createAgentHandshakeV2HostPorts,
  loadAgentHandshakeV2Session,
} from "../src/agent-handshake/v2/production-adapter.mjs";
import { verifyHostSessionKeyCertificate, ed25519PublicKeyFingerprint } from "../src/agent-handshake/v2/host-key-certificate.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { agentHandshakeV2StatementDigest } from "../src/agent-handshake/v2/terms.mjs";
import { buildV2Fixture, ed25519, INITIATOR, REPOSITORY_SHA, SESSION_ID, TERMS } from "./support/agent-handshake-v2-fixture.mjs";

test("production session fails closed without an immutable repository SHA", async () => {
  assert.equal(AGENT_HANDSHAKE_V2_FUNDING_AMOUNT_ETH, "0.01");
  await assert.rejects(
    loadAgentHandshakeV2Session({ env: {} }),
    /HANDSHAKE_SHA_INVALID/,
  );
});

test("production session publishes a root-signed host key before discovery with independent clocks", async () => {
  const root = ed25519("root-2026-08");
  const calls = [];
  const now = 1_786_337_000_000;
  const session = await loadAgentHandshakeV2Session({
    env: { HANDSHAKE_SHA: "d".repeat(40) },
    loadRoot: async () => root,
    now: () => now,
    publicClient: { getBlockNumber: async () => 6999n },
    relayClient: { createSession: async (input) => calls.push(input) },
  });
  assert.equal(session.protocol, "clockchain.agent-handshake/v2");
  assert.equal(session.sessionDeadlineMs, now + 10 * 60_000);
  assert.equal(session.invitationExpiresAtMs, now + 300_000);
  assert.equal(session.terms.validForSeconds, "90");
  assert.equal(session.sessionOpenedBlock, "6999");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].discovery.sessionOpenedBlock, "6999");
  assert.deepEqual(calls[0].discovery.hostSessionKeyCertificate, session.hostSessionKeyCertificate);
  verifyHostSessionKeyCertificate(session.hostSessionKeyCertificate, {
    expectedRepositorySha: session.repositorySha,
    expectedSessionId: session.sessionId,
    nowMs: now,
    rootKeyRing: [{
      kid: root.keyId,
      publicKey: root.publicKey,
      fingerprint: ed25519PublicKeyFingerprint(root.publicKey),
    }],
    sessionDeadlineMs: session.sessionDeadlineMs,
  });
});

test("production ports map only role-tagged v2 messages and reserve before funding", async () => {
  const seen = [];
  const identityClaim = {
    schema: "clockchain.agent-handshake-identity-claim/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    role: "initiator",
    sessionKeyAddress: INITIATOR.address.toLowerCase(),
    policyDigest: "a".repeat(64),
    statementDigest: agentHandshakeV2StatementDigest(TERMS),
    externalBusinessActionPerformed: false,
  };
  const messages = {
    agent_v2_invitation_created: { body: {
      createdAtMs: "1786337000001",
      externalBusinessActionPerformed: false,
    } },
    agent_v2_invitation_claimed: { body: {
      claimedAtMs: "1786337000002",
      externalBusinessActionPerformed: false,
    } },
    agent_v2_identity_claim: { body: {
      claim: identityClaim,
      signature: {
        address: identityClaim.sessionKeyAddress,
        algorithm: "eip191",
        value: await INITIATOR.signMessage({ message: { raw: canonicalBytes(identityClaim) } }),
      },
    } },
    agent_v2_party_ready: { body: { ok: "party" } },
    agent_v2_proposal: { body: { proposalEnvelope: { ok: "proposal" } } },
    agent_v2_acceptance: { body: { acceptanceEnvelope: { ok: "acceptance" } } },
    agent_v2_evidence: { body: { evidenceEnvelope: { ok: "evidence" } } },
    agent_v2_anchor_report: { body: { transitions: [{}, {}, {}] } },
  };
  const ports = await createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionOpenedAtMs: 1786337000000,
    invitationExpiresAtMs: 1786337300000,
    sessionDeadlineMs: Date.now() + 60_000,
    sessionId: SESSION_ID,
    terms: TERMS,
  }, {
    fundingBudget: { reserve: async (input) => seen.push(["reserve", input]) },
    fundIdentity: async (input) => seen.push(["fund", input]),
    postHostMessage: async (kind, body) => seen.push([kind, body]),
    publicClient: {},
    monitor: {
      invitationCreated: async (createdAtMs) => seen.push(["created", createdAtMs]),
      invitationClaimed: async (claimedAtMs) => seen.push(["invitation", claimedAtMs]),
      identityClaimed: async (role, claim) => seen.push(["identity", role, claim]),
    },
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
    waitForMessage: async (kind, role, deadlineMs) => {
      seen.push(["wait", kind, role, deadlineMs]);
      return messages[kind];
    },
  });
  assert.equal(await ports.awaitInvitationCreated(), 1786337000001);
  assert.deepEqual(seen.slice(0, 2), [
    ["wait", "agent_v2_invitation_created", "initiator", 1786337300000],
    ["created", 1786337000001],
  ]);
  assert.equal(await ports.awaitInvitationClaimed(), 1786337000002);
  assert.deepEqual(seen.slice(2, 4), [
    ["wait", "agent_v2_invitation_claimed", "responder", 1786337300000],
    ["invitation", 1786337000002],
  ]);
  assert.equal((await ports.awaitIdentityClaim("initiator")).policyDigest, "a".repeat(64));
  assert.deepEqual(await ports.awaitProposal(), { ok: "proposal" });
  await ports.reserveFunding({
    addresses: ["0x" + "1".repeat(40), "0x" + "2".repeat(40)],
    identityMode: "required_fresh",
    sessionId: "22222222-3333-4444-8555-666666666666",
  });
  await ports.fundIdentity({ address: identityClaim.sessionKeyAddress, role: "initiator" });
  assert.deepEqual(seen.slice(-2).map(([kind]) => kind), ["reserve", "fund"]);
});

test("production funding configuration enforces the deployed queue cap", async () => {
  const previous = process.env.AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT;
  process.env.AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT = "1";
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const ports = await createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    sessionDeadlineMs: Date.now() + 60_000,
    sessionId: "22222222-3333-4444-8555-666666666666",
  }, {
    fundingStore: {
      load: async () => { await gate; return []; },
      save: async () => {},
    },
    monitor: {},
    publicClient: {},
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
  });
  try {
    const first = ports.reserveFunding({
      addresses: ["0x" + "1".repeat(40), "0x" + "2".repeat(40)],
      identityMode: "required_fresh",
      sessionId: "22222222-3333-4444-8555-666666666666",
    });
    const second = ports.reserveFunding({
      addresses: ["0x" + "3".repeat(40), "0x" + "4".repeat(40)],
      identityMode: "required_fresh",
      sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    });
    const secondOutcome = await Promise.race([
      second.then(() => "fulfilled", () => "rejected"),
      new Promise((resolve) => setTimeout(() => resolve("pending"), 10)),
    ]);
    assert.equal(secondOutcome, "rejected");
    release();
    await Promise.allSettled([first, second]);
  } finally {
    if (previous === undefined) delete process.env.AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT;
    else process.env.AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT = previous;
  }
});

test("production registration proof uses the exact receipt instead of an unbounded log scan", async () => {
  const fixture = await buildV2Fixture();
  const party = fixture.parties.initiator;
  const transfer = parseAbiItem("event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)");
  let logScans = 0;
  const ports = await createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    sessionDeadlineMs: Date.now() + 60_000,
    sessionId: SESSION_ID,
  }, {
    fundingStore: { load: async () => [], save: async () => {} },
    monitor: {},
    publicClient: {
      getLogs: async () => { logScans += 1; return []; },
      getTransactionReceipt: async ({ hash }) => {
        assert.equal(hash, party.erc8004.registrationTx);
        return {
          blockNumber: BigInt(party.erc8004.registrationBlock),
          logs: [{
            address: party.erc8004.registryAddress,
            data: "0x",
            topics: encodeEventTopics({ abi: [transfer], eventName: "Transfer", args: {
              from: zeroAddress,
              to: party.sessionKeyAddress,
              tokenId: BigInt(party.erc8004.agentId),
            } }),
          }],
          status: "success",
          to: party.erc8004.registryAddress,
        };
      },
      readContract: async () => party.sessionKeyAddress,
    },
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
  });
  assert.deepEqual(await ports.resolveRegistration(party), {
    owner: party.sessionKeyAddress,
    registrationBlock: party.erc8004.registrationBlock,
  });
  assert.equal(logScans, 0);
});
