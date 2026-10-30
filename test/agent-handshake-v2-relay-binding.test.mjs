// H-REQ-01 (host): the v2 host consumes a role's relay messages only when they
// are signed by the key the coordinator enrolled for that role, and takes the
// invitation's mint and claim facts from the coordinator-signed enrollments.
import assert from "node:assert/strict";
import test from "node:test";
import { privateKeyToAccount } from "viem/accounts";

import * as relay from "../src/relay/client.mjs";
import {
  createAgentHandshakeV2HostPorts,
  loadAgentHandshakeV2Session,
} from "../src/agent-handshake/v2/production-adapter.mjs";
import { prepareAgentHandshakeV2Identities } from "../src/agent-handshake/v2/host.mjs";
import { AGENT_HANDSHAKE_V2_RELAY_AUTHORIZATION_SCHEMA } from "../src/agent-handshake/v2/relay-enrollment.mjs";
import { agentHandshakeV2StatementDigest } from "../src/agent-handshake/v2/terms.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { awaitRoleMessages } from "../src/roles/host.mjs";
import {
  buildV2Fixture,
  ed25519,
  INITIATOR,
  REPOSITORY_SHA,
  RESPONDER,
  SESSION_ID,
  SESSION_OPENED_BLOCK,
  TERMS,
} from "./support/agent-handshake-v2-fixture.mjs";
import {
  COORDINATOR_KEY_RING,
  enrollmentEnvelope,
  envelopeFrom,
  INVITATION_DIGEST,
  SENDERS,
  signedEnrollment,
} from "./support/sender-enrollment-fixture.mjs";

const UNENROLLED_ACCOUNT = privateKeyToAccount("0x" + "6".repeat(64));
const ENFORCE = Object.freeze({ mode: "enforce", coordinatorKeyRing: COORDINATOR_KEY_RING });
const OTHER_SESSION_ID = "33333333-4444-4555-8666-777777777777";

function liveSession(openedAtMs, { invitationMs = 120_000, deadlineMs = 600_000 } = {}) {
  return {
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    sessionOpenedAtMs: openedAtMs,
    invitationExpiresAtMs: openedAtMs + invitationMs,
    sessionDeadlineMs: openedAtMs + deadlineMs,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
    terms: TERMS,
  };
}

// Enrollment timing for a session opened at `openedAtMs`.
function timingFor(session, { mintAfterMs = 10, claimWindowMs = 180_000, redeemAfterMs = 20 } = {}) {
  return {
    sessionDeadlineMs: session.sessionDeadlineMs,
    mintedAtMs: session.sessionOpenedAtMs + mintAfterMs,
    claimExpiresAtMs: session.sessionOpenedAtMs + mintAfterMs + claimWindowMs,
    redeemedAtMs: session.sessionOpenedAtMs + redeemAfterMs,
  };
}

function enrolled(seq, role, timing, overrides = {}, { sender = SENDERS[role], sessionId = SESSION_ID } = {}) {
  return enrollmentEnvelope({
    seq,
    role,
    sender,
    sessionId,
    body: signedEnrollment(role, overrides, { timing }),
  });
}

function said(seq, role, kind, body, sender = SENDERS[role]) {
  return envelopeFrom({ seq, role, kind, body, sender });
}

function invitationCreated(seq, timing, sender = SENDERS.initiator) {
  return said(seq, "initiator", "agent_v2_invitation_created", {
    claimExpiresAtMs: String(timing.claimExpiresAtMs),
    createdAtMs: String(timing.mintedAtMs),
    externalBusinessActionPerformed: false,
  }, sender);
}

function invitationClaimed(seq, claimedAtMs, sender = SENDERS.responder) {
  return said(seq, "responder", "agent_v2_invitation_claimed", {
    claimedAtMs: String(claimedAtMs),
    externalBusinessActionPerformed: false,
  }, sender);
}

async function boundPorts(session, messages, overrides = {}) {
  const observed = { claimed: [], identities: [], logs: [] };
  const ports = await createAgentHandshakeV2HostPorts(session, {
    fundingBudget: { reserve: async () => {} },
    log: (event) => observed.logs.push(event),
    monitor: {
      identityClaimed: async (role, claim) => observed.identities.push([role, claim.sessionKeyAddress]),
      invitationClaimed: async (claimedAtMs) => observed.claimed.push(claimedAtMs),
    },
    postHostMessage: async () => {},
    publicClient: {},
    relayBinding: ENFORCE,
    relayClient: {
      ...relay,
      pollMessages: async () => ({ messages: typeof messages === "function" ? messages() : messages }),
    },
    ...overrides,
  });
  return { observed, ports };
}

function quietRotation(error) {
  return error?.name === "SessionEnded" && error?.code === "EXPIRED";
}

function invitationExpired(error) {
  return error?.code === "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED";
}

function bindingInvalid(error) {
  return error?.name === "AgentHandshakeV2SessionFailure" &&
    error.code === "AGENT_HANDSHAKE_V2_RELAY_BINDING_INVALID";
}

test("H-REQ-01 (host): only an invitation_created from the enrolled initiator key extends the claim wait", async () => {
  const opened = Date.now();
  const session = liveSession(opened, { invitationMs: 300, deadlineMs: 5_000 });
  const timing = timingFor(session, { mintAfterMs: 50, claimWindowMs: 3_000 });
  const { observed, ports } = await boundPorts(session, [
    invitationCreated(1, timing, SENDERS.unenrolled),
  ]);
  const started = Date.now();
  await assert.rejects(() => ports.awaitInvitationClaimed(), quietRotation);
  assert.ok(Date.now() - started < 1_500, "the wait must end at the 300ms mint cutoff");
  assert.deepEqual(observed.claimed, []);
});

test("H-REQ-01 (host): only an invitation_claimed from the enrolled responder key starts preparation", async () => {
  const opened = Date.now();
  const session = liveSession(opened, { invitationMs: 300, deadlineMs: 1_500 });
  const timing = timingFor(session, { mintAfterMs: 50, claimWindowMs: 400 });
  const { observed, ports } = await boundPorts(session, [
    enrolled(1, "initiator", timing),
    invitationCreated(2, timing),
    // A self-signed responder enrollment and a claim under that key.
    enrollmentEnvelope({
      seq: 3,
      role: "responder",
      sender: SENDERS.unenrolled,
      body: signedEnrollment("responder", { senderKey: SENDERS.unenrolled.publicKey }, {
        signer: SENDERS.unenrolled,
        timing,
      }),
    }),
    invitationClaimed(4, timing.redeemedAtMs, SENDERS.unenrolled),
  ]);
  await assert.rejects(() => ports.awaitInvitationClaimed(), invitationExpired);
  assert.deepEqual(observed.claimed, []);
  assert.ok(observed.logs.some((entry) =>
    entry.event === "agent_handshake_v2_relay_binding_violation" && entry.kind === "agent_v2_invitation_claimed"));
});

test("H-REQ-01 (host): the claim time comes from the redemption enrollment", async () => {
  const opened = Date.now() - 1_000;
  const session = liveSession(opened);
  const timing = timingFor(session, { redeemAfterMs: 400 });
  const { observed, ports } = await boundPorts(session, [
    enrolled(1, "initiator", timing),
    invitationCreated(2, timing),
    enrolled(3, "responder", timing),
    invitationClaimed(4, timing.redeemedAtMs),
  ]);
  assert.equal(await ports.awaitInvitationClaimed(), timing.redeemedAtMs);
  assert.deepEqual(observed.claimed, [timing.redeemedAtMs]);
});

test("H-REQ-01 (host): a claim body that disagrees with the redemption enrollment fails", async () => {
  const opened = Date.now() - 1_000;
  const session = liveSession(opened);
  const timing = timingFor(session, { redeemAfterMs: 400 });
  const { observed, ports } = await boundPorts(session, [
    enrolled(1, "initiator", timing),
    invitationCreated(2, timing),
    enrolled(3, "responder", timing),
    invitationClaimed(4, timing.redeemedAtMs - 1),
  ]);
  await assert.rejects(() => ports.awaitInvitationClaimed(), bindingInvalid);
  assert.deepEqual(observed.claimed, []);
});

test("H-REQ-01 (host): a redemption enrolled after the claim expiry is an explicit invitation expiry", async () => {
  const opened = Date.now() - 1_000;
  const session = liveSession(opened);
  const timing = timingFor(session, { claimWindowMs: 300, redeemAfterMs: 500 });
  const { observed, ports } = await boundPorts(session, [
    enrolled(1, "initiator", timing),
    invitationCreated(2, timing),
    enrolled(3, "responder", timing),
    invitationClaimed(4, timing.redeemedAtMs),
  ]);
  await assert.rejects(() => ports.awaitInvitationClaimed(), invitationExpired);
  assert.deepEqual(observed.claimed, []);
});

test("H-REQ-01 (host): roles enrolled for different invitations fail closed", async () => {
  const opened = Date.now() - 1_000;
  const session = liveSession(opened);
  const timing = timingFor(session);
  assert.notEqual(INVITATION_DIGEST, "e".repeat(64));
  const { observed, ports } = await boundPorts(session, [
    enrolled(1, "initiator", timing),
    invitationCreated(2, timing),
    enrolled(3, "responder", timing, { invitationDigest: "e".repeat(64) }),
    invitationClaimed(4, timing.redeemedAtMs),
  ]);
  await assert.rejects(() => ports.awaitInvitationClaimed(), bindingInvalid);
  assert.deepEqual(observed.claimed, []);
});

test("H-REQ-01 (host): an invitation_created that disagrees with the mint enrollment fails", async () => {
  const opened = Date.now() - 1_000;
  const session = liveSession(opened);
  const timing = timingFor(session);
  const { ports } = await boundPorts(session, [
    enrolled(1, "initiator", timing),
    invitationCreated(2, { ...timing, claimExpiresAtMs: timing.claimExpiresAtMs + 60_000 }),
  ]);
  await assert.rejects(() => ports.awaitInvitationClaimed(), bindingInvalid);
});

test("H-REQ-01 (host): an enrollment from another session or for another deadline is refused", async () => {
  for (const responder of [
    (timing) => enrolled(3, "responder", timing, { sessionId: OTHER_SESSION_ID }),
    (timing) => enrolled(3, "responder", timing, { sessionDeadlineMs: String(timing.sessionDeadlineMs + 60_000) }),
  ]) {
    const opened = Date.now();
    const session = liveSession(opened, { invitationMs: 300, deadlineMs: 1_500 });
    const timing = timingFor(session, { claimWindowMs: 400 });
    const { observed, ports } = await boundPorts(session, [
      enrolled(1, "initiator", timing),
      invitationCreated(2, timing),
      responder(timing),
      invitationClaimed(4, timing.redeemedAtMs),
    ]);
    await assert.rejects(() => ports.awaitInvitationClaimed(), invitationExpired);
    assert.deepEqual(observed.claimed, []);
  }
});

test("H-REQ-01 (host): a stale enrollment is refused", async () => {
  const opened = Date.now();
  const session = liveSession(opened, { invitationMs: 300, deadlineMs: 5_000 });
  const timing = timingFor(session, { claimWindowMs: 400 });
  const { observed, ports } = await boundPorts(session, [
    enrolled(1, "initiator", timing),
    invitationCreated(2, timing),
    enrolled(3, "responder", timing),
    invitationClaimed(4, timing.redeemedAtMs),
  ], { now: () => session.sessionDeadlineMs });
  // Nothing binds, so nothing is admitted: no mint is observed and the
  // unclaimed session rotates at the mint cutoff.
  await assert.rejects(() => ports.awaitInvitationClaimed(), quietRotation);
  assert.deepEqual(observed.claimed, []);
});

async function identityClaimMessage(seq, role, account, policyDigest, relaySender) {
  const claim = {
    schema: "clockchain.agent-handshake-identity-claim/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    role,
    sessionKeyAddress: account.address.toLowerCase(),
    policyDigest,
    statementDigest: agentHandshakeV2StatementDigest(TERMS),
    externalBusinessActionPerformed: false,
  };
  return said(seq, role, "agent_v2_identity_claim", {
    claim,
    signature: {
      address: claim.sessionKeyAddress,
      algorithm: "eip191",
      value: await account.signMessage({ message: { raw: canonicalBytes(claim) } }),
    },
  }, relaySender);
}

function unenrolledParty(fixture, role) {
  const party = fixture.parties[role];
  return {
    ...party,
    sessionKeyAddress: UNENROLLED_ACCOUNT.address.toLowerCase(),
    erc8004: { ...party.erc8004, agentId: "9999", reference: party.erc8004.reference.replace(/:[0-9]+$/, ":9999") },
  };
}

async function preparationLog(fixture, timing) {
  const policy = (role) => fixture.parties[role].policyDigest;
  return [
    enrolled(1, "initiator", timing),
    invitationCreated(2, timing),
    enrolled(3, "responder", timing),
    invitationClaimed(4, timing.redeemedAtMs),
    await identityClaimMessage(5, "initiator", UNENROLLED_ACCOUNT, policy("initiator"), SENDERS.unenrolled),
    await identityClaimMessage(6, "initiator", INITIATOR, policy("initiator"), SENDERS.initiator),
    await identityClaimMessage(7, "responder", UNENROLLED_ACCOUNT, policy("responder"), SENDERS.unenrolled),
    await identityClaimMessage(8, "responder", RESPONDER, policy("responder"), SENDERS.responder),
    said(9, "initiator", "agent_v2_party_ready", unenrolledParty(fixture, "initiator"), SENDERS.unenrolled),
    said(10, "initiator", "agent_v2_party_ready", fixture.parties.initiator),
    said(11, "responder", "agent_v2_party_ready", unenrolledParty(fixture, "responder"), SENDERS.unenrolled),
    said(12, "responder", "agent_v2_party_ready", fixture.parties.responder),
  ];
}

test("H-REQ-01 (host): identity claims and party-ready messages are consumed, and parties funded, only from enrolled keys", async () => {
  const fixture = await buildV2Fixture();
  const opened = Date.now() - 1_000;
  const session = liveSession(opened);
  const timing = timingFor(session, { redeemAfterMs: 400 });
  const funded = [];
  const reserved = [];
  const { observed, ports } = await boundPorts(session, await preparationLog(fixture, timing), {
    fundIdentity: async ({ address, role }) => funded.push([role, address]),
    fundingBudget: { reserve: async ({ addresses }) => reserved.push(...addresses) },
    resolveRegistration: async (agentId) => {
      const role = agentId === fixture.parties.initiator.erc8004.agentId ? "initiator" : "responder";
      return {
        owner: fixture.parties[role].sessionKeyAddress,
        registrationBlock: fixture.parties[role].erc8004.registrationBlock,
      };
    },
  });
  assert.equal(await ports.awaitInvitationClaimed(), timing.redeemedAtMs);
  const parties = await prepareAgentHandshakeV2Identities({
    identityPolicy: TERMS.identityPolicy,
    ports,
    sessionId: SESSION_ID,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
  });
  const unenrolledAddress = UNENROLLED_ACCOUNT.address.toLowerCase();
  assert.deepEqual(observed.identities, [
    ["initiator", INITIATOR.address.toLowerCase()],
    ["responder", RESPONDER.address.toLowerCase()],
  ]);
  assert.deepEqual(funded, [
    ["initiator", INITIATOR.address.toLowerCase()],
    ["responder", RESPONDER.address.toLowerCase()],
  ]);
  assert.ok(!reserved.includes(unenrolledAddress));
  assert.equal(parties.initiator.sessionKeyAddress, INITIATOR.address.toLowerCase());
  assert.equal(parties.responder.sessionKeyAddress, RESPONDER.address.toLowerCase());
  assert.ok(observed.logs.filter((entry) => entry.event === "agent_handshake_v2_relay_binding_violation").length >= 4);
});

test("H-REQ-01 (host): observe mode consumes as before and logs; enforce mode refuses", async () => {
  const fixture = await buildV2Fixture();
  const opened = Date.now() - 1_000;
  const session = liveSession(opened);
  const timing = timingFor(session, { redeemAfterMs: 400 });
  const log = [
    enrolled(1, "initiator", timing),
    await identityClaimMessage(2, "initiator", UNENROLLED_ACCOUNT, fixture.parties.initiator.policyDigest, SENDERS.unenrolled),
    await identityClaimMessage(3, "initiator", INITIATOR, fixture.parties.initiator.policyDigest, SENDERS.initiator),
  ];
  const observing = await boundPorts(session, log, { relayBinding: { ...ENFORCE, mode: "observe" } });
  const consumed = await observing.ports.awaitIdentityClaim("initiator");
  assert.equal(consumed.sessionKeyAddress, UNENROLLED_ACCOUNT.address.toLowerCase());
  const violations = observing.observed.logs.filter((entry) => entry.event === "agent_handshake_v2_relay_binding_violation");
  assert.equal(violations.length, 1);
  assert.deepEqual(
    { action: violations[0].action, kind: violations[0].kind, mode: violations[0].mode, role: violations[0].role, seq: violations[0].seq },
    { action: "observed", kind: "agent_v2_identity_claim", mode: "observe", role: "initiator", seq: "2" },
  );
  const enforcing = await boundPorts(session, log);
  const admitted = await enforcing.ports.awaitIdentityClaim("initiator");
  assert.equal(admitted.sessionKeyAddress, INITIATOR.address.toLowerCase());
  const refusals = enforcing.observed.logs.filter((entry) => entry.event === "agent_handshake_v2_relay_binding_violation");
  assert.equal(refusals.length, 1);
  assert.equal(refusals[0].action, "refused");
  assert.equal(refusals[0].seq, "2");
});

test("H-REQ-01 (host): an unknown or empty binding mode, enforce or observe without a key ring, or a configured key ring that does not validate fails at load", async () => {
  const root = ed25519("root-2026-08");
  const load = (env) => loadAgentHandshakeV2Session({
    env: { HANDSHAKE_SHA: "d".repeat(40), ...env },
    loadRoot: async () => root,
    log: () => {},
    now: () => 1_786_337_000_000,
    publicClient: { getBlockNumber: async () => 6999n },
    relayClient: { createSession: async () => {} },
  });
  const invalid = /AGENT_HANDSHAKE_V2_RELAY_BINDING_INVALID/;
  await assert.rejects(load({ AGENT_HANDSHAKE_V2_RELAY_BINDING: "" }), invalid);
  await assert.rejects(load({ AGENT_HANDSHAKE_V2_RELAY_BINDING: "enforce" }), invalid);
  await assert.rejects(load({ AGENT_HANDSHAKE_V2_RELAY_BINDING: "observe" }), invalid);
  await assert.rejects(load({ AGENT_HANDSHAKE_V2_RELAY_BINDING: "strict" }), invalid);
  await assert.rejects(load({ AGENT_HANDSHAKE_V2_COORDINATOR_KEYS: "not json" }), invalid);
  await assert.rejects(load({ AGENT_HANDSHAKE_V2_COORDINATOR_KEYS: JSON.stringify([{ kid: "x" }]) }), invalid);
  // A key ring that is configured is checked in every mode, off included.
  for (const keys of ["", "not json", JSON.stringify([{ kid: "x" }])]) {
    await assert.rejects(load({ AGENT_HANDSHAKE_V2_RELAY_BINDING: "off", AGENT_HANDSHAKE_V2_COORDINATOR_KEYS: keys }), invalid, keys);
  }
  const ports = (relayBinding) => createAgentHandshakeV2HostPorts(liveSession(Date.now()), {
    fundingBudget: { reserve: async () => {} },
    log: () => {},
    monitor: {},
    publicClient: {},
    relayBinding,
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
  });
  await assert.rejects(ports({ mode: "enforce" }), invalid);
  await assert.rejects(ports({ mode: "sometimes" }), invalid);
});

const DEFAULT_OFF_WARNING = Object.freeze({
  event: "agent_handshake_v2_relay_binding_default_off",
  mode: "off",
});

test("H-REQ-01 (host): an unset binding mode means off and logs one startup warning; observe and enforce come only from an explicit value", async () => {
  const root = ed25519("root-2026-08");
  const created = [];
  const logs = [];
  const load = (env) => loadAgentHandshakeV2Session({
    env: { HANDSHAKE_SHA: "d".repeat(40), ...env },
    loadRoot: async () => root,
    log: (event) => logs.push(event),
    now: () => 1_786_337_000_000,
    publicClient: { getBlockNumber: async () => 6999n },
    relayClient: { createSession: async (input) => created.push(input) },
  });
  const ring = JSON.stringify(COORDINATOR_KEY_RING);
  // Unset, with or without an absent key ring: off, the relay session is not
  // opted in, and exactly one warning line is logged.
  for (const env of [{}, { AGENT_HANDSHAKE_V2_COORDINATOR_KEYS: ring }]) {
    logs.length = 0;
    created.length = 0;
    const session = await load(env);
    assert.equal(session.relayBinding.mode, "off");
    assert.equal(created.length, 1);
    assert.deepEqual(Object.keys(created[0]).sort(), ["discovery", "relayUrl", "retryBudgetMs", "sessionId", "timeoutMs"]);
    assert.deepEqual(logs, [DEFAULT_OFF_WARNING]);
  }
  // An explicit value is used as given and logs no warning.
  for (const mode of ["off", "observe", "enforce"]) {
    logs.length = 0;
    const session = await load({ AGENT_HANDSHAKE_V2_RELAY_BINDING: mode, AGENT_HANDSHAKE_V2_COORDINATOR_KEYS: ring });
    assert.equal(session.relayBinding.mode, mode);
    assert.deepEqual(logs, []);
  }
  // Ports built without a loaded binding read the environment the same way.
  const previous = {
    mode: process.env.AGENT_HANDSHAKE_V2_RELAY_BINDING,
    keys: process.env.AGENT_HANDSHAKE_V2_COORDINATOR_KEYS,
  };
  delete process.env.AGENT_HANDSHAKE_V2_RELAY_BINDING;
  delete process.env.AGENT_HANDSHAKE_V2_COORDINATOR_KEYS;
  try {
    const portLogs = [];
    await createAgentHandshakeV2HostPorts(liveSession(Date.now()), {
      fundingBudget: { reserve: async () => {} },
      log: (event) => portLogs.push(event),
      monitor: {},
      publicClient: {},
      relayClient: { generateEnvelopeKeyPair: () => ({}) },
    });
    assert.deepEqual(portLogs, [DEFAULT_OFF_WARNING]);
  } finally {
    if (previous.mode !== undefined) process.env.AGENT_HANDSHAKE_V2_RELAY_BINDING = previous.mode;
    if (previous.keys !== undefined) process.env.AGENT_HANDSHAKE_V2_COORDINATOR_KEYS = previous.keys;
  }
});

test("H-REQ-01 (host): enforce mode opts the relay session in without touching the discovery document", async () => {
  const root = ed25519("root-2026-08");
  const created = [];
  const env = {
    HANDSHAKE_SHA: "d".repeat(40),
    AGENT_HANDSHAKE_V2_RELAY_BINDING: "enforce",
    AGENT_HANDSHAKE_V2_COORDINATOR_KEYS: JSON.stringify(COORDINATOR_KEY_RING),
  };
  const session = await loadAgentHandshakeV2Session({
    env,
    loadRoot: async () => root,
    now: () => 1_786_337_000_000,
    publicClient: { getBlockNumber: async () => 6999n },
    relayClient: { createSession: async (input) => created.push(input) },
  });
  assert.equal(created.length, 1);
  assert.deepEqual(Object.keys(created[0]).sort(), ["discovery", "relayAuthorization", "relayUrl", "retryBudgetMs", "sessionId", "timeoutMs"]);
  assert.deepEqual(Object.keys(created[0].discovery).sort(), [
    "createdAtMs", "externalBusinessActionPerformed", "hostSessionKeyCertificate",
    "invitationExpiresAtMs", "kitRepoUrl", "protocol", "relayUrl", "repositorySha",
    "schema", "sessionDeadlineMs", "sessionId", "sessionOpenedBlock", "terms",
  ]);
  assert.deepEqual(created[0].relayAuthorization, {
    schema: AGENT_HANDSHAKE_V2_RELAY_AUTHORIZATION_SCHEMA,
    coordinatorKeys: COORDINATOR_KEY_RING,
    hostSenderKey: session.relayEnvelopeKey.senderKey,
  });
  // Host messages are signed by the declared host sender key. The ports read
  // the session's own clock: a notice is sent only before its deadline.
  const posted = [];
  const ports = await createAgentHandshakeV2HostPorts(session, {
    fundingBudget: { reserve: async () => {} },
    log: () => {},
    monitor: {},
    now: () => 1_786_337_000_000,
    publicClient: {},
    relayClient: {
      ...relay,
      pollMessages: async () => ({ messages: [] }),
      postMessage: async ({ envelope }) => { posted.push(envelope); return { seq: envelope.seq }; },
    },
  });
  await ports.notifySessionFailed("AGENT_HANDSHAKE_V2_INVITATION_EXPIRED");
  assert.equal(posted.length, 1);
  assert.equal(posted[0].role, "host");
  assert.equal(posted[0].senderKey, created[0].relayAuthorization.hostSenderKey);
  assert.equal(relay.verifyEnvelope(posted[0]), true);
  // Off and observe modes leave the relay session as it was.
  for (const mode of ["off", "observe"]) {
    const calls = [];
    await loadAgentHandshakeV2Session({
      env: { ...env, AGENT_HANDSHAKE_V2_RELAY_BINDING: mode },
      loadRoot: async () => root,
      now: () => 1_786_337_000_000,
      publicClient: { getBlockNumber: async () => 6999n },
      relayClient: { createSession: async (input) => calls.push(input) },
    });
    assert.deepEqual(Object.keys(calls[0]).sort(), ["discovery", "relayUrl", "retryBudgetMs", "sessionId", "timeoutMs"]);
  }
});

test("H-REQ-01 (roles): awaitRoleMessages consumes only admitted messages, and only they extend a deadline", async () => {
  const base = {
    budgetMs: 200,
    kind: "wanted",
    relayUrl: "https://relay.test",
    roles: ["initiator"],
    sessionId: SESSION_ID,
    sleep: async () => {},
    waitMs: 0,
  };
  const batch = [
    { seq: "1", role: "initiator", kind: "wanted", body: "unadmitted" },
    { seq: "2", role: "initiator", kind: "other", body: "kept" },
    { seq: "3", role: "initiator", kind: "wanted", body: "admitted" },
  ];
  const seen = [];
  const extended = [];
  const result = await awaitRoleMessages({
    ...base,
    admit: (message) => message.body !== "unadmitted",
    extendDeadline: (message, deadline) => { extended.push(message.seq); return deadline; },
    observe: (message) => seen.push(message.seq),
    relayClient: { pollMessages: async () => ({ messages: batch }) },
  });
  assert.equal(result.messages.initiator.body, "admitted");
  assert.deepEqual(result.buffer.map((message) => message.seq), ["2"]);
  assert.deepEqual(seen, ["1", "2", "3"]);
  assert.deepEqual(extended, ["2", "3"]);
  assert.equal(result.after, "3");
  // Without the hooks the first matching message is taken, as before.
  const legacy = await awaitRoleMessages({
    ...base,
    relayClient: { pollMessages: async () => ({ messages: batch }) },
  });
  assert.equal(legacy.messages.initiator.body, "unadmitted");
});
