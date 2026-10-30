import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import {
  createAgentHandshakeV2HostPorts,
  loadAgentHandshakeV2Session,
} from "../src/agent-handshake/v2/production-adapter.mjs";
import { verifyHostSessionKeyCertificate, ed25519PublicKeyFingerprint } from "../src/agent-handshake/v2/host-key-certificate.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { agentHandshakeV2StatementDigest } from "../src/agent-handshake/v2/terms.mjs";
import { buildV2Fixture, ed25519, INITIATOR, REPOSITORY_SHA, RESPONDER, SESSION_ID, SESSION_OPENED_BLOCK, TERMS } from "./support/agent-handshake-v2-fixture.mjs";
import * as relay from "../src/relay/client.mjs";
import { RelayError } from "../src/relay/errors.mjs";

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
    env: { HANDSHAKE_SHA: "d".repeat(40), AGENT_HANDSHAKE_V2_RELAY_BINDING: "off" },
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
    relayBinding: { mode: "off" },
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
    monitor: { invitationClaimed: async () => {} },
    relayBinding: { mode: "off" },
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

test("an observed mint extends the claim wait to the minted expiry", async () => {
  const opened = Date.now();
  // The mint cutoff lapses at +300ms, but the mint published a mint-relative
  // claim expiry at +1500ms: the host must keep observing and accept a claim
  // that lands at +1200ms — inside the minted window, past the mint cutoff.
  const claimExpMs = opened + 1_500;
  const ports = await rotationPorts(
    {
      sessionOpenedAtMs: opened,
      invitationExpiresAtMs: opened + 300,
      sessionDeadlineMs: opened + 5_000,
    },
    async () => ({
      messages: [
        {
          kind: "agent_v2_invitation_created",
          role: "initiator",
          seq: "1",
          sessionId: SESSION_ID,
          body: {
            claimExpiresAtMs: String(claimExpMs),
            createdAtMs: String(opened + 50),
            externalBusinessActionPerformed: false,
          },
        },
        ...(Date.now() - opened >= 1_200 ? [{
          kind: "agent_v2_invitation_claimed",
          role: "responder",
          seq: "2",
          sessionId: SESSION_ID,
          body: {
            claimedAtMs: String(opened + 1_200),
            externalBusinessActionPerformed: false,
          },
        }] : []),
      ],
    }),
  );
  assert.equal(await ports.awaitInvitationClaimed(), opened + 1_200);
});

test("a mint without claimExpiresAtMs extends the wait by the legacy window", async () => {
  const opened = Date.now();
  // Coordinators before claimExpiresAtMs minted mint-relative at +120s (or
  // pinned to the session window): the host derives the bound from the
  // message's createdAtMs so a claim past the mint cutoff is still observed.
  const ports = await rotationPorts(
    {
      sessionOpenedAtMs: opened,
      invitationExpiresAtMs: opened + 300,
      sessionDeadlineMs: opened + 5_000,
    },
    async () => ({
      messages: [
        {
          kind: "agent_v2_invitation_created",
          role: "initiator",
          seq: "1",
          sessionId: SESSION_ID,
          body: {
            createdAtMs: String(opened + 50),
            externalBusinessActionPerformed: false,
          },
        },
        ...(Date.now() - opened >= 600 ? [{
          kind: "agent_v2_invitation_claimed",
          role: "responder",
          seq: "2",
          sessionId: SESSION_ID,
          body: {
            claimedAtMs: String(opened + 600),
            externalBusinessActionPerformed: false,
          },
        }] : []),
      ],
    }),
  );
  assert.equal(await ports.awaitInvitationClaimed(), opened + 600);
});

test("a claim stamped past the minted expiry is an explicit invitation expiry even when observed", async () => {
  const opened = Date.now();
  const ports = await rotationPorts(
    {
      sessionOpenedAtMs: opened,
      invitationExpiresAtMs: opened + 300,
      sessionDeadlineMs: opened + 5_000,
    },
    async () => ({
      messages: [
        {
          kind: "agent_v2_invitation_created",
          role: "initiator",
          seq: "1",
          sessionId: SESSION_ID,
          body: {
            claimExpiresAtMs: String(opened + 600),
            createdAtMs: String(opened + 50),
            externalBusinessActionPerformed: false,
          },
        },
        ...(Date.now() - opened >= 400 ? [{
          kind: "agent_v2_invitation_claimed",
          role: "responder",
          seq: "2",
          sessionId: SESSION_ID,
          body: {
            claimedAtMs: String(opened + 700),
            externalBusinessActionPerformed: false,
          },
        }] : []),
      ],
    }),
  );
  await assert.rejects(
    () => ports.awaitInvitationClaimed(),
    (error) => error?.name === "AgentHandshakeV2SessionFailure" &&
      error.code === "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED",
  );
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
    relayBinding: { mode: "off" },
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
    relayBinding: { mode: "off" },
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

// --- H-REQ-07: result publication retries only while the result can still be
// verified. ---

const PUBLICATION_DEADLINE_MS = 1786337600000;

// A relay whose result PUT takes attemptMs of scripted time (or less, when the
// attempt's timeout is shorter) and then fails as unreachable, unless
// succeeds(attemptNumber) says otherwise.
function publication({ startMs, attemptMs = 3_000, succeeds = () => false, validUntilMs = PUBLICATION_DEADLINE_MS }) {
  const clock = { value: startMs };
  const attempts = [];
  const putResult = async ({ retryBudgetMs, timeoutMs }) => {
    attempts.push({ atMs: clock.value, retryBudgetMs, timeoutMs });
    const limitMs = Number.isSafeInteger(timeoutMs) ? timeoutMs : Infinity;
    clock.value += Math.min(attemptMs, limitMs);
    if (attemptMs <= limitMs && succeeds(attempts.length)) return { ok: true };
    throw new RelayError("The relay could not be reached within the wait budget.", "RENDEZVOUS_UNAVAILABLE", { status: 0 });
  };
  const envelope = {
    hostSessionKeyCertificate: { certificate: { validUntilMs: String(validUntilMs) } },
    result: {},
    signer: {},
  };
  const run = async () => {
    const ports = await createAgentHandshakeV2HostPorts({
      relayUrl: "https://relay.test",
      repositorySha: REPOSITORY_SHA,
      sessionDeadlineMs: PUBLICATION_DEADLINE_MS,
      sessionId: SESSION_ID,
      terms: TERMS,
    }, {
      fundingBudget: { reserve: async () => {} },
      monitor: {},
      now: () => clock.value,
      relayBinding: { mode: "off" },
      publicClient: {},
      relayClient: { generateEnvelopeKeyPair: () => ({}), putResult },
      sleep: async (ms) => { clock.value += ms; },
    });
    return ports.publishResult(envelope).then((value) => ({ value }), (error) => ({ error }));
  };
  return { attempts, clock, run };
}

// No attempt starts at or after the bound, and none may run past it.
function assertInsideBound(attempts, boundMs, label) {
  for (const { atMs, retryBudgetMs, timeoutMs } of attempts) {
    assert.ok(atMs < boundMs, `${label}: an attempt started at ${atMs}, bound ${boundMs}`);
    assert.ok(Number.isSafeInteger(retryBudgetMs) && atMs + retryBudgetMs <= boundMs, `${label}: retry budget ${retryBudgetMs} at ${atMs} runs past ${boundMs}`);
    assert.ok(Number.isSafeInteger(timeoutMs) && atMs + timeoutMs <= boundMs, `${label}: timeout ${timeoutMs} at ${atMs} runs past ${boundMs}`);
  }
}

test("result publication retries until the session deadline and stops there", async () => {
  const run = publication({ startMs: PUBLICATION_DEADLINE_MS - 10_000 });
  const outcome = await run.run();
  assert.equal(outcome.error?.code, "RENDEZVOUS_UNAVAILABLE");
  assert.ok(run.attempts.length >= 2, "publication was not retried");
  assertInsideBound(run.attempts, PUBLICATION_DEADLINE_MS, "session deadline");
  assert.equal(run.clock.value, PUBLICATION_DEADLINE_MS);
});

test("result publication retries until the host key's validity ends when that comes first", async () => {
  const validUntilMs = PUBLICATION_DEADLINE_MS - 20_000;
  const run = publication({ startMs: validUntilMs - 10_000, validUntilMs });
  const outcome = await run.run();
  assert.equal(outcome.error?.code, "RENDEZVOUS_UNAVAILABLE");
  assert.ok(run.attempts.length >= 2, "publication was not retried");
  assertInsideBound(run.attempts, validUntilMs, "host key validity");
  assert.equal(run.clock.value, validUntilMs);
});

test("result publication far from the deadline keeps a 30 s retry budget", async () => {
  const startMs = PUBLICATION_DEADLINE_MS - 300_000;
  const run = publication({ startMs });
  const outcome = await run.run();
  assert.equal(outcome.error?.code, "RENDEZVOUS_UNAVAILABLE");
  assertInsideBound(run.attempts, startMs + 30_000, "retry budget");
  assert.equal(run.clock.value, startMs + 30_000);
});

test("result publication at the bound makes no attempt; 1 ms before it makes one", async () => {
  const validUntilMs = PUBLICATION_DEADLINE_MS - 5_000;
  for (const [label, boundMs, options] of [
    ["session deadline", PUBLICATION_DEADLINE_MS, {}],
    ["host key validity", validUntilMs, { validUntilMs }],
  ]) {
    const atBound = publication({ startMs: boundMs, ...options });
    const refused = await atBound.run();
    assert.equal(refused.error?.code, "RENDEZVOUS_UNAVAILABLE", label);
    assert.deepEqual(atBound.attempts, [], label);
    const lastMs = publication({ startMs: boundMs - 1, attemptMs: 1, succeeds: () => true, ...options });
    const published = await lastMs.run();
    assert.equal(published.error, undefined, `${label}: ${published.error?.message}`);
    assert.equal(lastMs.attempts.length, 1, label);
    assertInsideBound(lastMs.attempts, boundMs, label);
  }
});

test("result publication refuses a result whose host key validity is not a time", async () => {
  const run = publication({ startMs: PUBLICATION_DEADLINE_MS - 10_000, validUntilMs: "never" });
  const outcome = await run.run();
  assert.ok(outcome.error);
  assert.deepEqual(run.attempts, []);
});

// --- H-REQ-07: host relay messages and snapshot PUTs are sent only before
// their stop time. Protocol messages stop at the earliest of the session
// deadline, the end of the host key's validity and, once known, the agreement
// expiry; failure notices and snapshots stop at the earliest of the first two.
// Every relay call is a single attempt (retryBudgetMs 0) whose timeout is the
// time left, and the clock is read again before each one. ---

const HOST_OPENED_AT_MS = 1786337000000;
const HOST_DEADLINE_MS = 1786337600000;
const AGREEMENT_EXPIRES_AT_MS = 1786337190000;

// A relay whose calls each take stepMs of scripted time (less when the call's
// timeout is shorter, and then the call fails) and fail as unreachable for the
// first `failures` calls.
function scriptedRelay({ startMs, failures = 0, stepMs = 2_000 }) {
  const clock = { value: startMs };
  const calls = [];
  const posted = [];
  const snapshots = [];
  let failed = 0;
  const step = (op, input) => {
    calls.push({ op, atMs: clock.value, retryBudgetMs: input.retryBudgetMs, timeoutMs: input.timeoutMs });
    const limitMs = Number.isSafeInteger(input.timeoutMs) ? input.timeoutMs : Infinity;
    clock.value += Math.min(stepMs, limitMs);
    if (stepMs > limitMs || failed < failures) {
      failed += 1;
      throw new RelayError("The relay could not be reached within the wait budget.", "RENDEZVOUS_UNAVAILABLE", { status: 0 });
    }
  };
  const relayClient = {
    ...relay,
    pollMessages: async (input) => { step("poll", input); return { messages: [] }; },
    postMessage: async (input) => {
      step("post", input);
      posted.push(input.envelope);
      return { seq: input.envelope.seq };
    },
    putSnapshot: async (input) => {
      step("snapshot", input);
      snapshots.push(input.snapshot);
      return { sessionId: SESSION_ID };
    },
  };
  return { calls, clock, posted, relayClient, snapshots };
}

// Every call started before the stop time and could not run past it.
function assertCallsBefore(calls, stopAtMs, label) {
  for (const { atMs, op, retryBudgetMs, timeoutMs } of calls) {
    assert.ok(atMs < stopAtMs, `${label}: ${op} started at ${atMs}, stop ${stopAtMs}`);
    assert.equal(retryBudgetMs, 0, `${label}: ${op} retry budget`);
    assert.ok(Number.isSafeInteger(timeoutMs) && atMs + timeoutMs <= stopAtMs, `${label}: ${op} timeout ${timeoutMs} at ${atMs} runs past ${stopAtMs}`);
  }
}

async function scriptedPorts(scripted, {
  deadlineMs = HOST_DEADLINE_MS,
  keyValidUntilMs = HOST_DEADLINE_MS,
  logs = [],
  monitor = {},
  receiptAtMs,
} = {}) {
  const fixture = await buildV2Fixture();
  const certificate = fixture.hostSessionKeyCertificate;
  const session = {
    hostSessionKeyCertificate: {
      ...certificate,
      certificate: { ...certificate.certificate, validUntilMs: String(keyValidUntilMs) },
    },
    invitationExpiresAtMs: HOST_OPENED_AT_MS + 120_000,
    privateKeyPem: fixture.host.privateKeyPem,
    protocol: "clockchain.agent-handshake/v2",
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: deadlineMs,
    sessionId: SESSION_ID,
    sessionOpenedAtMs: HOST_OPENED_AT_MS,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
    terms: TERMS,
  };
  const ports = await createAgentHandshakeV2HostPorts(session, {
    fundingBudget: { reserve: async () => {} },
    log: (event) => logs.push(event),
    ...(monitor === null ? {} : { monitor }),
    now: () => scripted.clock.value,
    publicClient: {
      waitForTransactionReceipt: async () => {
        scripted.clock.value = receiptAtMs;
        return { blockNumber: 7000n };
      },
    },
    relayBinding: { mode: "off" },
    relayClient: scripted.relayClient,
    sendFundingTransaction: async () => "0x" + "ab".repeat(32),
    sleep: async (ms) => { scripted.clock.value += ms; },
  });
  return { fixture, ports };
}

const settle = (promise) => promise.then((value) => ({ value }), (error) => ({ error }));

test("a host relay message that fails is retried and posted before its stop time", async () => {
  const scripted = scriptedRelay({ startMs: AGREEMENT_EXPIRES_AT_MS - 20_000, failures: 2 });
  const { fixture, ports } = await scriptedPorts(scripted);
  const outcome = await settle(ports.publishDescriptor(fixture.descriptorEnvelope));
  assert.equal(outcome.error, undefined, outcome.error?.message);
  assert.equal(scripted.posted.length, 1);
  assert.equal(scripted.posted[0].kind, "agent_v2_handshake_required");
  assert.ok(scripted.calls.length >= 4, "the failed calls were not retried");
  assertCallsBefore(scripted.calls, AGREEMENT_EXPIRES_AT_MS, "descriptor");
});

test("the descriptor is posted only before the agreement expiry, the session deadline and the end of the host key's validity, whichever comes first", async () => {
  for (const [label, stopAtMs, options] of [
    ["agreement expiry", AGREEMENT_EXPIRES_AT_MS, {}],
    ["host key validity", AGREEMENT_EXPIRES_AT_MS - 5_000, { keyValidUntilMs: AGREEMENT_EXPIRES_AT_MS - 5_000 }],
    ["session deadline", AGREEMENT_EXPIRES_AT_MS - 7_000, { deadlineMs: AGREEMENT_EXPIRES_AT_MS - 7_000 }],
  ]) {
    const failing = scriptedRelay({ startMs: stopAtMs - 10_000, failures: Infinity });
    const run = await scriptedPorts(failing, options);
    const refused = await settle(run.ports.publishDescriptor(run.fixture.descriptorEnvelope));
    assert.equal(refused.error?.code, "RENDEZVOUS_UNAVAILABLE", label);
    assert.deepEqual(failing.posted, [], label);
    assert.ok(failing.calls.length >= 2, `${label}: the failed calls were not retried`);
    assertCallsBefore(failing.calls, stopAtMs, label);
    assert.equal(failing.clock.value, stopAtMs, label);

    const atStop = scriptedRelay({ startMs: stopAtMs, stepMs: 0 });
    const late = await scriptedPorts(atStop, options);
    const none = await settle(late.ports.publishDescriptor(late.fixture.descriptorEnvelope));
    assert.equal(none.error?.code, "RENDEZVOUS_UNAVAILABLE", label);
    assert.deepEqual(atStop.calls, [], label);

    const lastMs = scriptedRelay({ startMs: stopAtMs - 1, stepMs: 0 });
    const inTime = await scriptedPorts(lastMs, options);
    const sent = await settle(inTime.ports.publishDescriptor(inTime.fixture.descriptorEnvelope));
    assert.equal(sent.error, undefined, `${label}: ${sent.error?.message}`);
    assert.equal(lastMs.posted.length, 1, label);
    assertCallsBefore(lastMs.calls, stopAtMs, label);
  }
});

test("the funding record is posted only before the stop time, read again after the receipt wait", async () => {
  const address = INITIATOR.address.toLowerCase();
  for (const [label, stopAtMs, options] of [
    ["session deadline", HOST_DEADLINE_MS, {}],
    ["host key validity", HOST_DEADLINE_MS - 50_000, { keyValidUntilMs: HOST_DEADLINE_MS - 50_000 }],
  ]) {
    const startMs = stopAtMs - 200_000;
    const atStop = scriptedRelay({ startMs, stepMs: 0 });
    const late = await scriptedPorts(atStop, { ...options, receiptAtMs: stopAtMs });
    const refused = await settle(late.ports.fundIdentity({ address, role: "initiator" }));
    assert.equal(refused.error?.code, "RENDEZVOUS_UNAVAILABLE", `${label}: ${refused.error?.message ?? "a record was accepted at the stop time"}`);
    assert.deepEqual(atStop.calls, [], label);
    assert.deepEqual(atStop.posted, [], label);

    const lastMs = scriptedRelay({ startMs, stepMs: 0 });
    const inTime = await scriptedPorts(lastMs, { ...options, receiptAtMs: stopAtMs - 1 });
    const sent = await settle(inTime.ports.fundIdentity({ address, role: "initiator" }));
    assert.equal(sent.error, undefined, `${label}: ${sent.error?.message}`);
    assert.equal(lastMs.posted.length, 1, label);
    assert.equal(lastMs.posted[0].kind, "agent_v2_funding_record", label);
    assertCallsBefore(lastMs.calls, stopAtMs, label);

    const flaky = scriptedRelay({ startMs, failures: 2 });
    const retried = await scriptedPorts(flaky, { ...options, receiptAtMs: stopAtMs - 30_000 });
    const posted = await settle(retried.ports.fundIdentity({ address, role: "initiator" }));
    assert.equal(posted.error, undefined, `${label}: ${posted.error?.message}`);
    assert.equal(flaky.posted.length, 1, label);
    assertCallsBefore(flaky.calls, stopAtMs, label);
  }
});

test("a failure notice is posted only before the session deadline and the end of the host key's validity", async () => {
  for (const [label, stopAtMs, options] of [
    ["session deadline", HOST_DEADLINE_MS, {}],
    ["host key validity", HOST_DEADLINE_MS - 50_000, { keyValidUntilMs: HOST_DEADLINE_MS - 50_000 }],
  ]) {
    const atStop = scriptedRelay({ startMs: stopAtMs, stepMs: 0 });
    const logs = [];
    const late = await scriptedPorts(atStop, { ...options, logs });
    await late.ports.notifySessionFailed("AGENT_HANDSHAKE_V2_SIGNING_WINDOW_EXPIRED");
    assert.deepEqual(atStop.calls, [], label);
    assert.deepEqual(logs.map((entry) => [entry.event, entry.relayCode]), [
      ["agent_handshake_v2_session_failed_notice_unpublished", "RENDEZVOUS_UNAVAILABLE"],
    ], label);

    // The notice that a lapse ended the session still reaches the relay after
    // the agreement expiry.
    const lastMs = scriptedRelay({ startMs: stopAtMs - 1, stepMs: 0 });
    const inTime = await scriptedPorts(lastMs, options);
    await inTime.ports.notifySessionFailed("AGENT_HANDSHAKE_V2_SIGNING_WINDOW_EXPIRED");
    assert.equal(lastMs.posted.length, 1, label);
    assert.equal(lastMs.posted[0].kind, "agent_v2_session_failed", label);
    assertCallsBefore(lastMs.calls, stopAtMs, label);
  }
});

test("snapshot PUTs retry for at most 30 s and never at or after the session deadline or the end of the host key's validity", async () => {
  const farMs = HOST_DEADLINE_MS - 300_000;
  for (const [label, startMs, stopAtMs, options] of [
    ["retry budget", farMs, farMs + 30_000, {}],
    ["session deadline", HOST_DEADLINE_MS - 10_000, HOST_DEADLINE_MS, {}],
    ["host key validity", farMs, farMs + 10_000, { keyValidUntilMs: farMs + 10_000 }],
  ]) {
    const failing = scriptedRelay({ startMs, failures: Infinity });
    const run = await scriptedPorts(failing, { ...options, monitor: null });
    const refused = await settle(run.ports.publishInitial());
    assert.equal(refused.error?.code, "RENDEZVOUS_UNAVAILABLE", label);
    assert.deepEqual(failing.snapshots, [], label);
    assert.ok(failing.calls.length >= 2, `${label}: the failed PUTs were not retried`);
    assertCallsBefore(failing.calls, stopAtMs, label);
    assert.equal(failing.clock.value, stopAtMs, label);
  }
  for (const [label, stopAtMs, options] of [
    ["session deadline", HOST_DEADLINE_MS, {}],
    ["host key validity", farMs, { keyValidUntilMs: farMs }],
  ]) {
    const atStop = scriptedRelay({ startMs: stopAtMs, stepMs: 0 });
    const late = await scriptedPorts(atStop, { ...options, monitor: null });
    const none = await settle(late.ports.publishInitial());
    assert.equal(none.error?.code, "RENDEZVOUS_UNAVAILABLE", label);
    assert.deepEqual(atStop.calls, [], label);

    const lastMs = scriptedRelay({ startMs: stopAtMs - 1, stepMs: 0 });
    const inTime = await scriptedPorts(lastMs, { ...options, monitor: null });
    const sent = await settle(inTime.ports.publishInitial());
    assert.equal(sent.error, undefined, `${label}: ${sent.error?.message}`);
    assert.equal(lastMs.snapshots.length, 1, label);
    assertCallsBefore(lastMs.calls, stopAtMs, label);
  }
  const flaky = scriptedRelay({ startMs: farMs, failures: 2 });
  const retried = await scriptedPorts(flaky, { monitor: null });
  const stored = await settle(retried.ports.publishInitial());
  assert.equal(stored.error, undefined, stored.error?.message);
  assert.equal(flaky.snapshots.length, 1);
  assertCallsBefore(flaky.calls, farMs + 30_000, "retried snapshot");
});

// --- H-REQ-07: the stop time also bounds a relay response whose body stalls
// after prompt headers, through the host's own snapshot PUTs and messages. ---

async function stalledBodyRelay(t, { bodyDelayMs }) {
  const requests = [];
  const timers = new Set();
  const server = createServer((req, res) => {
    requests.push({ atMs: Date.now(), method: req.method });
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.flushHeaders();
    const timer = setTimeout(() => res.end(JSON.stringify({ messages: [] })), bodyDelayMs);
    timers.add(timer);
    res.on("close", () => clearTimeout(timer));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => {
    for (const timer of timers) clearTimeout(timer);
    server.closeAllConnections();
    return new Promise((resolve) => server.close(resolve));
  });
  return { relayUrl: `http://127.0.0.1:${server.address().port}`, requests };
}

async function wallClockPorts(relayUrl, { deadlineMs, logs = [] }) {
  const fixture = await buildV2Fixture();
  const certificate = fixture.hostSessionKeyCertificate;
  return createAgentHandshakeV2HostPorts({
    hostSessionKeyCertificate: {
      ...certificate,
      certificate: { ...certificate.certificate, validUntilMs: String(deadlineMs) },
    },
    invitationExpiresAtMs: deadlineMs - 480_000,
    privateKeyPem: fixture.host.privateKeyPem,
    protocol: "clockchain.agent-handshake/v2",
    relayUrl,
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: deadlineMs,
    sessionId: SESSION_ID,
    sessionOpenedAtMs: deadlineMs - 600_000,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
    terms: TERMS,
  }, {
    fundingBudget: { reserve: async () => {} },
    log: (event) => logs.push(event),
    publicClient: {},
    relayBinding: { mode: "off" },
    relayClient: relay,
  });
}

test("H-REQ-07 (host): a snapshot PUT and a host message whose response body stalls end at the stop time", async (t) => {
  const { relayUrl, requests } = await stalledBodyRelay(t, { bodyDelayMs: 5_000 });

  const snapshotStopMs = Date.now() + 800;
  const snapshotPorts = await wallClockPorts(relayUrl, { deadlineMs: snapshotStopMs });
  const snapshot = await settle(snapshotPorts.publishInitial());
  const snapshotEndedMs = Date.now();
  assert.equal(snapshot.error?.code, "RENDEZVOUS_UNAVAILABLE", `the snapshot PUT returned ${snapshotEndedMs - snapshotStopMs} ms after the stop time`);
  assert.ok(snapshotEndedMs - snapshotStopMs < 500, `the snapshot PUT ended ${snapshotEndedMs - snapshotStopMs} ms after the stop time`);
  assert.ok(requests.some(({ method }) => method === "PUT"), "no snapshot PUT reached the relay");

  requests.length = 0;
  const logs = [];
  const noticeStopMs = Date.now() + 800;
  const noticePorts = await wallClockPorts(relayUrl, { deadlineMs: noticeStopMs, logs });
  await noticePorts.notifySessionFailed("AGENT_HANDSHAKE_V2_SIGNING_WINDOW_EXPIRED");
  const noticeEndedMs = Date.now();
  assert.ok(noticeEndedMs - noticeStopMs < 500, `the host message ended ${noticeEndedMs - noticeStopMs} ms after the stop time`);
  assert.deepEqual(logs.map((entry) => [entry.event, entry.relayCode]), [
    ["agent_handshake_v2_session_failed_notice_unpublished", "RENDEZVOUS_UNAVAILABLE"],
  ]);
  assert.ok(requests.length >= 1, "the host message never reached the relay");
});

// --- H-REQ-07: funding stops at the protocol stop time. The clock is read
// again after the funding wallet opens, before the transaction is signed and
// before it is broadcast; the transaction's RPC calls, their retries and the
// receipt wait end by the stop time; nothing is sent after it. ---

const FUNDING_HASH = "0x" + "cd".repeat(32);
const TREASURY = privateKeyToAccount("0x" + "6".repeat(64));

function rpcAnswer(id, method) {
  const results = {
    eth_chainId: "0xaa36a7",
    eth_estimateGas: "0x5208",
    eth_gasPrice: "0x3b9aca00",
    eth_getBlockByNumber: {
      baseFeePerGas: "0x3b9aca00",
      difficulty: "0x0",
      extraData: "0x",
      gasLimit: "0x1c9c380",
      gasUsed: "0x0",
      hash: "0x" + "11".repeat(32),
      logsBloom: "0x" + "00".repeat(256),
      miner: "0x" + "00".repeat(20),
      mixHash: "0x" + "00".repeat(32),
      nonce: "0x0000000000000000",
      number: "0x1b58",
      parentHash: "0x" + "22".repeat(32),
      receiptsRoot: "0x" + "33".repeat(32),
      sha3Uncles: "0x" + "44".repeat(32),
      size: "0x200",
      stateRoot: "0x" + "55".repeat(32),
      timestamp: "0x6553f100",
      transactions: [],
      transactionsRoot: "0x" + "66".repeat(32),
      uncles: [],
    },
    eth_getTransactionCount: "0x0",
    eth_maxPriorityFeePerGas: "0x3b9aca00",
    eth_sendRawTransaction: FUNDING_HASH,
  };
  return Object.hasOwn(results, method)
    ? { id, jsonrpc: "2.0", result: results[method] }
    : { error: { code: -32601, message: `the method ${method} does not exist/is not available` }, id, jsonrpc: "2.0" };
}

// A JSON-RPC node on 127.0.0.1. `answer(method)` runs before each reply and
// returns "stall" to never reply or "unavailable" to reply 503.
async function fundingNode(t, { answer = () => {} } = {}) {
  const methods = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => { raw += chunk; });
    req.on("end", () => {
      const { id, method } = JSON.parse(raw);
      methods.push(method);
      const action = answer(method);
      if (action === "stall") return;
      if (action === "unavailable") {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "unavailable" }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(rpcAnswer(id, method)));
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => {
    server.closeAllConnections();
    return new Promise((resolve) => server.close(resolve));
  });
  return { methods, rpcUrl: `http://127.0.0.1:${server.address().port}` };
}

// Points the funding RPC at `rpcUrl` and the funding keystore at a path that
// does not exist, so a funding path that ignores the injected wallet fails
// instead of reading one.
async function fundingEnvironment(t, rpcUrl) {
  const saved = {
    keystore: process.env.CLOCKCHAIN_FUNDING_KEYSTORE,
    rpcUrl: process.env.SEPOLIA_RPC_URL,
  };
  const directory = await mkdtemp(join(tmpdir(), "hs-funding-"));
  process.env.CLOCKCHAIN_FUNDING_KEYSTORE = join(directory, "absent-wallet.json");
  process.env.SEPOLIA_RPC_URL = rpcUrl;
  t.after(async () => {
    if (saved.keystore === undefined) delete process.env.CLOCKCHAIN_FUNDING_KEYSTORE;
    else process.env.CLOCKCHAIN_FUNDING_KEYSTORE = saved.keystore;
    if (saved.rpcUrl === undefined) delete process.env.SEPOLIA_RPC_URL;
    else process.env.SEPOLIA_RPC_URL = saved.rpcUrl;
    await rm(directory, { force: true, recursive: true });
  });
}

function treasuryWallet({ onSign = () => {} } = {}) {
  const signed = [];
  const account = {
    ...TREASURY,
    signTransaction: async (transaction, options) => {
      onSign();
      signed.push(transaction);
      return TREASURY.signTransaction(transaction, options);
    },
  };
  return { account, signed };
}

// Ports whose funding runs on the default transaction path. With `clock` the
// ports read that scripted clock; without it they read the wall clock.
async function fundingPorts({
  clock,
  deadlineMs = HOST_DEADLINE_MS,
  keyValidUntilMs = deadlineMs,
  openFundingWallet,
  receiptMs = 0,
  receipts = [],
  relayClient,
  sendFundingTransaction,
}) {
  const fixture = await buildV2Fixture();
  const certificate = fixture.hostSessionKeyCertificate;
  return createAgentHandshakeV2HostPorts({
    hostSessionKeyCertificate: {
      ...certificate,
      certificate: { ...certificate.certificate, validUntilMs: String(keyValidUntilMs) },
    },
    invitationExpiresAtMs: HOST_OPENED_AT_MS + 120_000,
    privateKeyPem: fixture.host.privateKeyPem,
    protocol: "clockchain.agent-handshake/v2",
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: deadlineMs,
    sessionId: SESSION_ID,
    sessionOpenedAtMs: HOST_OPENED_AT_MS,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
    terms: TERMS,
  }, {
    fundingBudget: { reserve: async () => {} },
    log: () => {},
    monitor: {},
    ...(clock === undefined ? {} : {
      now: () => clock.value,
      sleep: async (ms) => { clock.value += ms; },
    }),
    ...(openFundingWallet === undefined ? {} : { openFundingWallet }),
    ...(sendFundingTransaction === undefined ? {} : { sendFundingTransaction }),
    // A receipt wait that takes receiptMs, or fails at its timeout when that
    // is shorter.
    publicClient: {
      waitForTransactionReceipt: async ({ hash, timeout }) => {
        receipts.push({ atMs: clock?.value ?? Date.now(), hash, timeout });
        const tookMs = Math.min(receiptMs, Number.isSafeInteger(timeout) ? timeout : Infinity);
        if (clock !== undefined) clock.value += tookMs;
        else await new Promise((resolve) => setTimeout(resolve, tookMs));
        if (receiptMs > timeout) throw new Error("The receipt wait timed out.");
        return { blockNumber: 7000n };
      },
    },
    relayBinding: { mode: "off" },
    relayClient,
  });
}

const FUNDING_STOPS = [
  ["session deadline", HOST_DEADLINE_MS, {}],
  ["host key validity", HOST_DEADLINE_MS - 50_000, { keyValidUntilMs: HOST_DEADLINE_MS - 50_000 }],
];

test("H-REQ-07 (host): funding signs and sends nothing when the window closes while the funding wallet opens", async (t) => {
  const address = INITIATOR.address.toLowerCase();
  for (const [label, stopAtMs, options] of FUNDING_STOPS) {
    for (const [openedAtMs, sends] of [[stopAtMs, false], [stopAtMs - 1, true]]) {
      const node = await fundingNode(t);
      await fundingEnvironment(t, node.rpcUrl);
      const scripted = scriptedRelay({ startMs: stopAtMs - 60_000, stepMs: 0 });
      const wallet = treasuryWallet();
      const receipts = [];
      const opened = [];
      const ports = await fundingPorts({
        ...options,
        clock: scripted.clock,
        openFundingWallet: async () => {
          opened.push(scripted.clock.value);
          scripted.clock.value = openedAtMs;
          return { account: wallet.account };
        },
        receipts,
        relayClient: scripted.relayClient,
      });
      const outcome = await settle(ports.fundIdentity({ address, role: "initiator" }));
      const at = `${label}, wallet open until ${openedAtMs - stopAtMs} ms from the stop time`;
      assert.equal(opened.length, 1, `${at}: the injected wallet was not opened`);
      if (!sends) {
        assert.equal(outcome.error?.code, "RENDEZVOUS_UNAVAILABLE", `${at}: ${outcome.error?.message ?? "funding completed"}`);
        assert.deepEqual(node.methods, [], at);
        assert.deepEqual(wallet.signed, [], at);
        assert.deepEqual(receipts, [], at);
        assert.deepEqual(scripted.calls, [], at);
        continue;
      }
      assert.equal(outcome.error, undefined, `${at}: ${outcome.error?.message}`);
      assert.equal(wallet.signed.length, 1, at);
      assert.deepEqual(node.methods.filter((method) => method === "eth_sendRawTransaction"), ["eth_sendRawTransaction"], at);
      assert.equal(node.methods.at(-1), "eth_sendRawTransaction", at);
      assert.equal(receipts.length, 1, at);
      assert.equal(receipts[0].hash, FUNDING_HASH, at);
      assert.ok(receipts[0].atMs + receipts[0].timeout <= stopAtMs, `${at}: receipt wait ${receipts[0].timeout} ms at ${receipts[0].atMs}`);
      assert.equal(scripted.posted.length, 1, at);
      assert.equal(scripted.posted[0].kind, "agent_v2_funding_record", at);
      assert.equal(scripted.posted[0].body.transactionHash, FUNDING_HASH, at);
    }
  }
});

test("H-REQ-07 (host): funding sends nothing when the window closes while the transaction is prepared or signed", async (t) => {
  const address = INITIATOR.address.toLowerCase();
  for (const [label, stopAtMs, options] of FUNDING_STOPS) {
    for (const stage of ["prepare", "sign"]) {
      for (const [doneAtMs, sends] of [[stopAtMs, false], [stopAtMs - 1, true]]) {
        const scripted = scriptedRelay({ startMs: stopAtMs - 60_000, stepMs: 0 });
        const node = await fundingNode(t, {
          answer: (method) => {
            if (stage === "prepare" && method === "eth_estimateGas") scripted.clock.value = doneAtMs;
          },
        });
        await fundingEnvironment(t, node.rpcUrl);
        const wallet = treasuryWallet({
          onSign: () => {
            if (stage === "sign") scripted.clock.value = doneAtMs;
          },
        });
        const receipts = [];
        const ports = await fundingPorts({
          ...options,
          clock: scripted.clock,
          openFundingWallet: async () => ({ account: wallet.account }),
          receipts,
          relayClient: scripted.relayClient,
        });
        const outcome = await settle(ports.fundIdentity({ address, role: "initiator" }));
        const at = `${label}, ${stage} until ${doneAtMs - stopAtMs} ms from the stop time`;
        assert.ok(node.methods.includes("eth_estimateGas"), `${at}: the transaction was not prepared`);
        const broadcasts = node.methods.filter((method) => method === "eth_sendRawTransaction");
        if (!sends) {
          assert.equal(outcome.error?.code, "RENDEZVOUS_UNAVAILABLE", `${at}: ${outcome.error?.message ?? "funding completed"}`);
          assert.deepEqual(broadcasts, [], at);
          assert.equal(wallet.signed.length, stage === "sign" ? 1 : 0, at);
          assert.deepEqual(receipts, [], at);
          assert.deepEqual(scripted.calls, [], at);
          continue;
        }
        assert.equal(outcome.error, undefined, `${at}: ${outcome.error?.message}`);
        assert.equal(broadcasts.length, 1, at);
        assert.equal(scripted.posted.length, 1, at);
      }
    }
  }
});

test("H-REQ-07 (host): the funding receipt wait is bounded by the window", async () => {
  const address = INITIATOR.address.toLowerCase();
  for (const [label, stopAtMs, options] of FUNDING_STOPS) {
    const scripted = scriptedRelay({ startMs: stopAtMs - 30_000, stepMs: 0 });
    const receipts = [];
    const ports = await fundingPorts({
      ...options,
      clock: scripted.clock,
      receiptMs: 120_000,
      receipts,
      relayClient: scripted.relayClient,
      sendFundingTransaction: async () => FUNDING_HASH,
    });
    const outcome = await settle(ports.fundIdentity({ address, role: "initiator" }));
    assert.equal(outcome.error?.code, "RENDEZVOUS_UNAVAILABLE", `${label}: ${outcome.error?.message ?? "funding completed"}`);
    assert.equal(receipts.length, 1, label);
    assert.ok(receipts[0].atMs + receipts[0].timeout <= stopAtMs, `${label}: receipt wait ${receipts[0].timeout} ms at ${receipts[0].atMs}, stop ${stopAtMs}`);
    assert.ok(scripted.clock.value <= stopAtMs, `${label}: the receipt wait ran to ${scripted.clock.value}, stop ${stopAtMs}`);
    assert.deepEqual(scripted.calls, [], label);

    // Far from the stop time the receipt wait keeps its own 180 s cap.
    const far = scriptedRelay({ startMs: stopAtMs - 300_000, stepMs: 0 });
    const farReceipts = [];
    const farPorts = await fundingPorts({
      ...options,
      clock: far.clock,
      receipts: farReceipts,
      relayClient: far.relayClient,
      sendFundingTransaction: async () => FUNDING_HASH,
    });
    const funded = await settle(farPorts.fundIdentity({ address, role: "initiator" }));
    assert.equal(funded.error, undefined, `${label}: ${funded.error?.message}`);
    assert.equal(farReceipts[0].timeout, 180_000, label);
    assert.equal(far.posted.length, 1, label);
  }
});

test("H-REQ-07 (host): the funding transaction's RPC calls and their retries end at the stop time", async (t) => {
  const address = INITIATOR.address.toLowerCase();
  for (const action of ["stall", "unavailable"]) {
    const node = await fundingNode(t, { answer: () => action });
    await fundingEnvironment(t, node.rpcUrl);
    const scripted = scriptedRelay({ startMs: 0, stepMs: 0 });
    const wallet = treasuryWallet();
    const receipts = [];
    const stopAtMs = Date.now() + 700;
    const ports = await fundingPorts({
      deadlineMs: stopAtMs,
      openFundingWallet: async () => ({ account: wallet.account }),
      receipts,
      relayClient: scripted.relayClient,
    });
    const outcome = await settle(ports.fundIdentity({ address, role: "initiator" }));
    const endedMs = Date.now();
    assert.equal(outcome.error?.code, "RENDEZVOUS_UNAVAILABLE", `${action}: ${outcome.error?.message ?? "funding completed"}`);
    assert.ok(endedMs - stopAtMs < 400, `${action}: funding ended ${endedMs - stopAtMs} ms after the stop time`);
    assert.ok(node.methods.length >= 1, `${action}: no RPC call was made`);
    assert.ok(!node.methods.includes("eth_sendRawTransaction"), action);
    assert.deepEqual(wallet.signed, [], action);
    assert.deepEqual(receipts, [], action);
    assert.deepEqual(scripted.calls, [], action);
  }
});

// --- H-REQ-07: session creation. The publication clock is established when
// the session window opens and read again after the block-number read; the
// creation POST is a single bounded attempt at a time, retried only before
// the invitation window closes (which is before the session deadline and the
// end of the host key's validity); a session whose invitation window has
// already closed is never published, and the host rotates instead. ---

const CREATION_OPENED_AT_MS = 1_786_337_000_000;
const CREATION_STOP_MS = CREATION_OPENED_AT_MS + 120_000;

function creationRun({ blockReadUntilMs = CREATION_OPENED_AT_MS, failures = 0, stepMs = 0 } = {}) {
  const clock = { value: CREATION_OPENED_AT_MS };
  const created = [];
  let failed = 0;
  const run = () => settle(loadAgentHandshakeV2Session({
    env: { HANDSHAKE_SHA: "d".repeat(40), AGENT_HANDSHAKE_V2_RELAY_BINDING: "off" },
    loadRoot: async () => ed25519("root-2026-08"),
    log: () => {},
    now: () => clock.value,
    publicClient: {
      getBlockNumber: async () => {
        clock.value = blockReadUntilMs;
        return 6999n;
      },
    },
    relayClient: {
      createSession: async (input) => {
        created.push({ atMs: clock.value, retryBudgetMs: input.retryBudgetMs, timeoutMs: input.timeoutMs });
        const limitMs = Number.isSafeInteger(input.timeoutMs) ? input.timeoutMs : Infinity;
        clock.value += Math.min(stepMs, limitMs);
        if (stepMs > limitMs || failed < failures) {
          failed += 1;
          throw new RelayError("The relay could not be reached within the wait budget.", "RENDEZVOUS_UNAVAILABLE", { status: 0 });
        }
        return { sessionId: input.sessionId };
      },
    },
    sleep: async (ms) => { clock.value += ms; },
  }));
  return { clock, created, run };
}

test("H-REQ-07 (host): a session whose invitation window closes during the block-number read is never published, and the host rotates", async () => {
  const late = creationRun({ blockReadUntilMs: CREATION_STOP_MS });
  const rotated = await late.run();
  assert.equal(rotated.error?.name, "SessionEnded", rotated.error?.message ?? "the session was published");
  assert.equal(rotated.error.code, "EXPIRED");
  assert.deepEqual(late.created, []);

  const lastMs = creationRun({ blockReadUntilMs: CREATION_STOP_MS - 1 });
  const published = await lastMs.run();
  assert.equal(published.error, undefined, published.error?.message);
  assert.equal(published.value.sessionOpenedAtMs, CREATION_OPENED_AT_MS);
  assert.equal(published.value.invitationExpiresAtMs, CREATION_STOP_MS);
  assert.deepEqual(lastMs.created, [{ atMs: CREATION_STOP_MS - 1, retryBudgetMs: 0, timeoutMs: 1 }]);
});

test("H-REQ-07 (host): a creation POST that keeps failing is retried only before the invitation window closes, one bounded attempt at a time", async () => {
  const failing = creationRun({ blockReadUntilMs: CREATION_STOP_MS - 20_000, failures: Infinity, stepMs: 3_000 });
  const refused = await failing.run();
  assert.equal(refused.error?.code, "RENDEZVOUS_UNAVAILABLE", refused.error?.message ?? "the session was published");
  assert.ok(failing.created.length >= 2, "the failed POST was not retried");
  for (const { atMs, retryBudgetMs, timeoutMs } of failing.created) {
    assert.ok(atMs < CREATION_STOP_MS, `a POST started at ${atMs}, stop ${CREATION_STOP_MS}`);
    assert.equal(retryBudgetMs, 0);
    assert.ok(Number.isSafeInteger(timeoutMs) && atMs + timeoutMs <= CREATION_STOP_MS, `timeout ${timeoutMs} at ${atMs} runs past ${CREATION_STOP_MS}`);
  }
  assert.equal(failing.clock.value, CREATION_STOP_MS);

  const flaky = creationRun({ blockReadUntilMs: CREATION_STOP_MS - 20_000, failures: 2, stepMs: 1_000 });
  const created = await flaky.run();
  assert.equal(created.error, undefined, created.error?.message);
  assert.equal(flaky.created.length, 3);
  for (const { atMs, timeoutMs } of flaky.created) assert.ok(atMs + timeoutMs <= CREATION_STOP_MS);
});

test("H-REQ-07 (host): the ports keep the publication clock the session window was opened on", async () => {
  const openedAtMs = Date.now();
  const clock = { value: openedAtMs };
  const load = () => loadAgentHandshakeV2Session({
    env: { HANDSHAKE_SHA: "d".repeat(40), AGENT_HANDSHAKE_V2_RELAY_BINDING: "off" },
    loadRoot: async () => ed25519("root-2026-08"),
    log: () => {},
    now: () => clock.value,
    publicClient: { getBlockNumber: async () => 6999n },
    relayClient: { createSession: async () => ({}) },
  });
  const portsFor = async (session, snapshots) => createAgentHandshakeV2HostPorts(session, {
    fundingBudget: { reserve: async () => {} },
    log: () => {},
    publicClient: {},
    relayBinding: { mode: "off" },
    relayClient: {
      generateEnvelopeKeyPair: relay.generateEnvelopeKeyPair,
      putSnapshot: async (input) => { snapshots.push(input); return { sessionId: input.sessionId }; },
    },
  });

  // A clock read below the session's opening read stops publication.
  const rolledBack = [];
  const rolledBackPorts = await portsFor(await load(), rolledBack);
  clock.value = openedAtMs - 1;
  const refused = await settle(rolledBackPorts.publishInitial());
  assert.equal(refused.error?.name, "MonotonicClockError", refused.error?.message ?? "the snapshot was published");
  assert.deepEqual(rolledBack, []);

  clock.value = openedAtMs;
  const stored = [];
  const ports = await portsFor(await load(), stored);
  clock.value = openedAtMs + 1;
  const published = await settle(ports.publishInitial());
  assert.equal(published.error, undefined, published.error?.message);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].timeoutMs, 30_000);
});
