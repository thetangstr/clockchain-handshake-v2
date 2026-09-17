import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentHandshakeV2HostPorts,
  loadAgentHandshakeV2Session,
} from "../src/agent-handshake/v2/production-adapter.mjs";
import { verifyHostSessionKeyCertificate, ed25519PublicKeyFingerprint } from "../src/agent-handshake/v2/host-key-certificate.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { agentHandshakeV2StatementDigest } from "../src/agent-handshake/v2/terms.mjs";
import { ed25519, INITIATOR, REPOSITORY_SHA, RESPONDER, SESSION_ID, TERMS } from "./support/agent-handshake-v2-fixture.mjs";

test("production session fails closed without an immutable repository SHA", async () => {
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
  assert.equal(session.invitationExpiresAtMs, now + 120_000);
  assert.equal(session.terms.validForSeconds, "90");
  assert.equal(session.sessionOpenedBlock, "6999");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].discovery.sessionOpenedBlock, "6999");
  assert.deepEqual(calls[0].discovery.hostSessionKeyCertificate, session.hostSessionKeyCertificate);
  assert.deepEqual(calls[0].discovery.terms, session.terms);
  assert.equal(
    agentHandshakeV2StatementDigest(calls[0].discovery.terms),
    agentHandshakeV2StatementDigest(session.terms),
  );
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
    agent_v2_invitation_claimed: { body: {
      claimedAtMs: "1786337000001",
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
    invitationExpiresAtMs: 1786337120000,
    sessionDeadlineMs: Date.now() + 60_000,
    sessionId: SESSION_ID,
    terms: TERMS,
  }, {
    fundingBudget: { reserve: async (input) => seen.push(["reserve", input]) },
    fundIdentity: async (input) => seen.push(["fund", input]),
    postHostMessage: async (kind, body) => seen.push([kind, body]),
    publicClient: {},
    monitor: {
      invitationClaimed: async (claimedAtMs) => seen.push(["invitation", claimedAtMs]),
      identityClaimed: async (role, claim) => seen.push(["identity", role, claim]),
    },
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
    waitForMessage: async (kind, role) => {
      seen.push(["wait", kind, role]);
      return messages[kind];
    },
  });
  assert.equal(await ports.awaitInvitationClaimed(), 1786337000001);
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

function rotationPorts(session, pollMessages) {
  return createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    terms: TERMS,
    ...session,
  }, {
    fundingBudget: { reserve: async () => {} },
    monitor: {},
    publicClient: {},
    relayClient: {
      generateEnvelopeKeyPair: () => ({}),
      pollMessages,
      verifyEnvelope: () => true,
    },
  });
}

test("an unclaimed invitation wait ends at the rendezvous expiry so the host rotates", async () => {
  const opened = Date.now();
  let polls = 0;
  // The session deadline is bounded at 2s so a regression that drops the invitation bound fails fast
  // instead of hanging for the real 10-minute deadline.
  const ports = await rotationPorts(
    {
      sessionOpenedAtMs: opened,
      invitationExpiresAtMs: opened + 300,
      sessionDeadlineMs: opened + 2_000,
    },
    async () => { polls += 1; return { messages: [] }; },
  );
  const started = Date.now();
  await assert.rejects(
    () => ports.awaitInvitationClaimed(),
    (error) => error?.name === "SessionEnded" && error?.code === "EXPIRED",
  );
  assert.ok(polls > 0);
  assert.ok(
    Date.now() - started < 1_500,
    "the claim wait must end at the 300ms invitation window, not the 2s session deadline",
  );
});

test("an already-expired invitation window rejects the claim wait without polling", async () => {
  const opened = Date.now();
  let polls = 0;
  const ports = await rotationPorts(
    {
      sessionOpenedAtMs: opened - 120_000,
      invitationExpiresAtMs: opened - 1,
      sessionDeadlineMs: opened + 2_000,
    },
    async () => { polls += 1; return { messages: [] }; },
  );
  await assert.rejects(
    () => ports.awaitInvitationClaimed(),
    (error) => error?.name === "SessionEnded" && error?.code === "EXPIRED",
  );
  assert.equal(polls, 0);
});

test("waits after the invitation claim keep the full session deadline", async () => {
  const opened = Date.now();
  // The proposal only becomes visible once the rendezvous window has already lapsed, proving post-claim
  // waits are bounded by the session deadline, not invitationExpiresAtMs.
  const ports = await rotationPorts(
    {
      sessionOpenedAtMs: opened,
      invitationExpiresAtMs: opened + 150,
      sessionDeadlineMs: opened + 5_000,
    },
    async () => ({
      messages: Date.now() - opened < 200 ? [] : [{
        kind: "agent_v2_proposal",
        role: "initiator",
        seq: "1",
        sessionId: SESSION_ID,
        body: { proposalEnvelope: { ok: "proposal" } },
      }],
    }),
  );
  assert.deepEqual(await ports.awaitProposal(), { ok: "proposal" });
  assert.ok(Date.now() - opened >= 150, "the proposal wait must continue past the invitation expiry");
});

function erc8004Provider({ head, registrations = [], owners = {}, reverts = new Set() }) {
  // Mirrors the live RPC: any getLogs span wider than 50,000 blocks — or one
  // with no explicit toBlock — fails the way the production provider did.
  const calls = [];
  const provider = {
    calls,
    getBlockNumber: async () => head,
    getLogs: async ({ args, fromBlock, toBlock }) => {
      calls.push({ args, fromBlock, toBlock });
      if (
        typeof fromBlock !== "bigint" ||
        typeof toBlock !== "bigint" ||
        toBlock - fromBlock + 1n > 50_000n
      ) {
        const error = new Error("exceed maximum block range: 50000");
        error.name = "RpcRequestError";
        throw error;
      }
      return registrations.filter((entry) =>
        entry.blockNumber >= fromBlock &&
        entry.blockNumber <= toBlock &&
        entry.blockNumber !== undefined &&
        (args?.agentId === undefined || entry.args.agentId === args.agentId) &&
        (args?.owner === undefined ||
          String(entry.args.owner).toLowerCase() === String(args.owner).toLowerCase())
      ).sort((left, right) => Number(left.blockNumber - right.blockNumber));
    },
    readContract: async ({ args, functionName }) => {
      assert.equal(functionName, "ownerOf");
      if (reverts.has(String(args[0]))) throw new Error("ERC721: invalid token ID");
      return owners[String(args[0])] ?? "0x" + "0".repeat(40);
    },
  };
  return provider;
}

function registrationPorts(publicClient, terms = TERMS) {
  return createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionOpenedAtMs: 1786337000000,
    invitationExpiresAtMs: 1786337120000,
    sessionDeadlineMs: Date.now() + 60_000,
    sessionId: SESSION_ID,
    sessionOpenedBlock: "11722800",
    terms,
  }, {
    fundingBudget: { reserve: async () => {} },
    monitor: {},
    publicClient,
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
  });
}

test("resolveRegistration verifies a fresh mint at the exact claimed block", async () => {
  const owner = INITIATOR.address.toLowerCase();
  const provider = erc8004Provider({
    head: 11_722_870n,
    owners: { "10324": owner },
    registrations: [{
      args: { agentId: 10324n, owner },
      blockNumber: 11_722_863n,
    }],
  });
  const ports = await registrationPorts(provider);
  const resolved = await ports.resolveRegistration("10324", {
    expectedOwner: owner,
    registrationBlock: "11722863",
  });
  assert.deepEqual(resolved, { owner, registrationBlock: "11722863" });
  // The claim pins the block: exactly one single-block query, no history scan.
  assert.deepEqual(
    provider.calls.map(({ fromBlock, toBlock }) => [fromBlock, toBlock]),
    [[11_722_863n, 11_722_863n]],
  );
});

test("resolveRegistration rejects wrong owner, agentId, block, and malformed claims", async () => {
  const owner = INITIATOR.address.toLowerCase();
  const other = RESPONDER.address.toLowerCase();
  const provider = erc8004Provider({
    head: 11_722_870n,
    owners: { "10324": owner },
    registrations: [{
      args: { agentId: 10324n, owner },
      blockNumber: 11_722_863n,
    }],
  });
  const ports = await registrationPorts(provider);
  const missing = /REGISTRATION_MISSING/;
  await assert.rejects(
    () => ports.resolveRegistration("10324", { expectedOwner: other, registrationBlock: "11722863" }),
    missing,
  );
  await assert.rejects(
    () => ports.resolveRegistration("10325", { expectedOwner: owner, registrationBlock: "11722863" }),
    missing,
  );
  await assert.rejects(
    () => ports.resolveRegistration("10324", { expectedOwner: owner, registrationBlock: "11722864" }),
    missing,
  );
  await assert.rejects(
    () => ports.resolveRegistration("10324", { expectedOwner: owner, registrationBlock: "11722863.0" }),
    missing,
  );
  await assert.rejects(
    () => ports.resolveRegistration("10324", { expectedOwner: owner, registrationBlock: "abc" }),
    missing,
  );
  await assert.rejects(
    () => ports.resolveRegistration("10324", { expectedOwner: owner, registrationBlock: "" }),
    missing,
  );
  await assert.rejects(() => ports.resolveRegistration("10324"), missing);
  // A minted-then-transferred agent fails the current-owner check.
  const transferred = erc8004Provider({
    head: 11_722_870n,
    owners: { "10324": other },
    registrations: [{ args: { agentId: 10324n, owner }, blockNumber: 11_722_863n }],
  });
  const transferredPorts = await registrationPorts(transferred);
  await assert.rejects(
    () => transferredPorts.resolveRegistration("10324", { expectedOwner: owner, registrationBlock: "11722863" }),
    missing,
  );
});

test("findExistingIdentity reverse-scans Registered in provider-safe chunks to genesis", async () => {
  const owner = RESPONDER.address.toLowerCase();
  const head = 11_722_870n;
  const mintBlock = head - 200_000n;
  const provider = erc8004Provider({
    head,
    owners: { "9001": owner },
    registrations: [{ args: { agentId: 9001n, owner }, blockNumber: mintBlock }],
  });
  const ports = await registrationPorts(provider, {
    ...TERMS,
    identityPolicy: { ...TERMS.identityPolicy, erc8004: "required_existing_or_fresh" },
  });
  const found = await ports.findExistingIdentity(owner);
  assert.deepEqual(found, {
    agentId: "9001",
    owner,
    registrationBlock: String(mintBlock),
  });
  assert.ok(provider.calls.length >= 5, "the scan must chunk across the 50k provider limit");
  assert.ok(provider.calls.every(
    ({ fromBlock, toBlock }) => toBlock - fromBlock + 1n <= 50_000n,
  ));
  // Chunks walk backwards from the head: first call ends at head.
  assert.equal(provider.calls[0].toBlock, head);
});

test("findExistingIdentity skips identities the address no longer owns", async () => {
  const owner = RESPONDER.address.toLowerCase();
  const other = INITIATOR.address.toLowerCase();
  const head = 60_000n;
  const provider = erc8004Provider({
    head,
    owners: { "9002": other, "9003": owner },
    registrations: [
      // Newest first in the same chunk: a transferred-away registration is
      // ignored, and the older still-owned one is found.
      { args: { agentId: 9002n, owner }, blockNumber: 55_000n },
      { args: { agentId: 9003n, owner }, blockNumber: 10_000n },
    ],
  });
  const ports = await registrationPorts(provider);
  const found = await ports.findExistingIdentity(owner);
  assert.deepEqual(found, {
    agentId: "9003",
    owner,
    registrationBlock: "10000",
  });
});

test("findExistingIdentity returns null after scanning every chunk to block 0", async () => {
  const owner = RESPONDER.address.toLowerCase();
  const head = 120_000n;
  const provider = erc8004Provider({ head, owners: {}, registrations: [] });
  const ports = await registrationPorts(provider);
  assert.equal(await ports.findExistingIdentity(owner), null);
  // head 120_000 with 50k-wide inclusive chunks: [120000..70001], [70000..20001], [20000..0].
  assert.equal(provider.calls.length, 3);
  assert.equal(provider.calls.at(-1).fromBlock, 0n);
});

test("findExistingIdentity skips candidates whose ownerOf reverts and keeps scanning", async () => {
  const owner = RESPONDER.address.toLowerCase();
  const head = 60_000n;
  const provider = erc8004Provider({
    head,
    // The newer candidate's token is burned/unreadable — ownerOf reverts —
    // and the older one is still owned by the address.
    owners: { "9003": owner },
    reverts: new Set(["9002"]),
    registrations: [
      { args: { agentId: 9002n, owner }, blockNumber: 55_000n },
      { args: { agentId: 9003n, owner }, blockNumber: 10_000n },
    ],
  });
  const ports = await registrationPorts(provider);
  assert.deepEqual(await ports.findExistingIdentity(owner), {
    agentId: "9003",
    owner,
    registrationBlock: "10000",
  });
});

test("findExistingIdentity returns null when every candidate reverts or is owned elsewhere", async () => {
  const owner = RESPONDER.address.toLowerCase();
  const other = INITIATOR.address.toLowerCase();
  const head = 120_000n;
  const provider = erc8004Provider({
    head,
    owners: { "9004": other },
    reverts: new Set(["9005"]),
    registrations: [
      { args: { agentId: 9004n, owner }, blockNumber: 80_000n },
      { args: { agentId: 9005n, owner }, blockNumber: 30_000n },
    ],
  });
  const ports = await registrationPorts(provider);
  assert.equal(await ports.findExistingIdentity(owner), null);
  assert.equal(provider.calls.at(-1).fromBlock, 0n);
  assert.ok(provider.calls.every(
    ({ fromBlock, toBlock }) => toBlock - fromBlock + 1n <= 50_000n,
  ));
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
