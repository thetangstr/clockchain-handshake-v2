// Host invitation-expiry and snapshot-rejection handling.
//
// Production P8 (2026-10-07, relay session 130fd2a5): the host pre-created a
// session (mint cutoff = open + 120 s). The initiator minted the invitation at
// +82 s (38 s left before the cutoff); the coordinator gave the responder a
// mint-relative claim window (mint + 180 s). The responder claimed at +158 s,
// 38 s past the cutoff but inside its window. The host accepted the claim and
// PUT a snapshot carrying it; a relay validator that still bounded the claim by
// the cutoff answered 400 MALFORMED_SNAPSHOT, the host process died, and both
// parties long-polled the abandoned session to its 10-minute deadline.
import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_HANDSHAKE_V2_SESSION_FAILED_KIND,
  createAgentHandshakeV2HostPorts,
  isRelayRejection,
} from "../src/agent-handshake/v2/production-adapter.mjs";
import { runAgentHandshakeV2HostSession } from "../src/agent-handshake/v2/host.mjs";
import { createAgentHandshakeV2Monitor } from "../src/monitor/agent-snapshot-v2-producer.mjs";
import { validateAgentHandshakeV2Snapshot } from "../src/monitor/agent-snapshot-v2.mjs";
import { RelayError } from "../src/relay/errors.mjs";
import { SessionEnded } from "../src/roles/host.mjs";
import {
  buildV2Fixture,
  REPOSITORY_SHA,
  SESSION_ID,
  SESSION_OPENED_BLOCK,
  TERMS,
} from "./support/agent-handshake-v2-fixture.mjs";

const P8 = Object.freeze({
  mintAtMs: 82_106,
  claimWindowMs: 180_000,
  claimAtMs: 158_124,
});

function relaySession(fixture, openedAtMs) {
  return {
    hostSessionKeyCertificate: fixture.hostSessionKeyCertificate,
    invitationExpiresAtMs: openedAtMs + 120_000,
    protocol: "clockchain.agent-handshake/v2",
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: openedAtMs + 600_000,
    sessionId: SESSION_ID,
    sessionOpenedAtMs: openedAtMs,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
    terms: TERMS,
  };
}

function message(seq, role, kind, body) {
  return { body, kind, role, seq: String(seq), sessionId: SESSION_ID };
}

// The P8 relay log: mint at +82 s with a mint-relative claim expiry, then the
// responder's claim stamped at +158 s.
function p8Messages(openedAtMs) {
  return [
    message(1, "initiator", "agent_v2_invitation_created", {
      claimExpiresAtMs: String(openedAtMs + P8.mintAtMs + P8.claimWindowMs),
      createdAtMs: String(openedAtMs + P8.mintAtMs),
      externalBusinessActionPerformed: false,
    }),
    message(3, "responder", "agent_v2_invitation_claimed", {
      claimedAtMs: String(openedAtMs + P8.claimAtMs),
      externalBusinessActionPerformed: false,
    }),
  ];
}

// A relay double whose snapshot PUT runs `accepts` (the relay's validator, or
// an emulation of the pre-fix one) and answers a refusal exactly as the relay
// does: RelayError 400 MALFORMED_SNAPSHOT.
function fakeRelay({ accepts, messages, posted, snapshots }) {
  return {
    generateEnvelopeKeyPair: () => ({}),
    pollMessages: async () => ({ messages }),
    verifyEnvelope: () => true,
    putSnapshot: async ({ snapshot }) => {
      if (!accepts(snapshot)) {
        throw new RelayError("Relay request failed: MALFORMED_SNAPSHOT.", "MALFORMED_SNAPSHOT", { status: 400 });
      }
      snapshots.push(snapshot);
      return { sessionId: snapshot.sessionId };
    },
  };
}

function relayValidator(snapshot) {
  try {
    return validateAgentHandshakeV2Snapshot(snapshot) === true;
  } catch {
    return false;
  }
}

// The relay validator deployed before this fix bounded the claim by the mint
// cutoff instead of the session deadline.
function preFixRelayValidator(snapshot) {
  if (!relayValidator(snapshot)) return false;
  const claimed = snapshot.invitation.responderClaimedAtMs;
  return claimed === null || claimed < snapshot.timing.invitationExpiresAtMs;
}

async function p8Ports({ accepts, openedAtMs, logs = [] }) {
  const fixture = await buildV2Fixture();
  const session = relaySession(fixture, openedAtMs);
  const snapshots = [];
  const posted = [];
  const relayClient = fakeRelay({ accepts, messages: p8Messages(openedAtMs), posted, snapshots });
  const monitor = createAgentHandshakeV2Monitor({
    now: () => openedAtMs + P8.claimAtMs + 50,
    publish: (snapshot) => relayClient.putSnapshot({ snapshot }),
    session,
  });
  const ports = await createAgentHandshakeV2HostPorts(session, {
    fundingBudget: { reserve: async () => {} },
    log: (event) => logs.push(event),
    monitor,
    postHostMessage: async (kind, body) => posted.push([kind, body]),
    publicClient: {},
    relayClient,
  });
  return { logs, monitor, ports, posted, session, snapshots };
}

test("P8 replay: a claim inside the mint-relative window succeeds and the relay accepts its snapshot", async () => {
  // The host has been observing since before the mint; it is now just past
  // the mint (the cutoff is 38 s away) and the claim lands 38 s past it.
  const openedAtMs = Date.now() - P8.mintAtMs - 100;
  const { ports, posted, snapshots } = await p8Ports({ accepts: relayValidator, openedAtMs });
  await ports.publishInitial();
  assert.equal(await ports.awaitInvitationClaimed(), openedAtMs + P8.claimAtMs);
  const last = snapshots.at(-1);
  assert.equal(last.invitation.responderClaimedAtMs, openedAtMs + P8.claimAtMs);
  assert.ok(last.invitation.responderClaimedAtMs > last.timing.invitationExpiresAtMs);
  assert.equal(last.failure, null);
  assert.deepEqual(posted, []);
});

test("P8 replay against the pre-fix relay: the rejection ends the session visibly and notifies both parties", async () => {
  const openedAtMs = Date.now() - P8.mintAtMs - 100;
  const { logs, ports, posted, snapshots } = await p8Ports({ accepts: preFixRelayValidator, openedAtMs });
  await ports.publishInitial();
  await assert.rejects(
    () => ports.awaitInvitationClaimed(),
    (error) =>
      error?.name === "AgentHandshakeV2SessionFailure" &&
      error.code === "AGENT_HANDSHAKE_V2_SNAPSHOT_REJECTED" &&
      error.cause?.code === "MALFORMED_SNAPSHOT",
  );
  // The terminal snapshot is the last accepted state plus the failure: the
  // refused claim is not re-sent, so the relay accepts it.
  const last = snapshots.at(-1);
  assert.equal(snapshots.length, 2);
  assert.equal(last.invitation.responderClaimedAtMs, null);
  assert.deepEqual(last.failure, { reasonCode: "AGENT_HANDSHAKE_V2_SNAPSHOT_REJECTED" });
  assert.equal(last.checker.stage, "FAILED");
  assert.deepEqual(posted, [[AGENT_HANDSHAKE_V2_SESSION_FAILED_KIND, {
    externalBusinessActionPerformed: false,
    reasonCode: "AGENT_HANDSHAKE_V2_SNAPSHOT_REJECTED",
  }]]);
  assert.deepEqual(logs.map((entry) => entry.event), ["agent_handshake_v2_snapshot_rejected"]);
  assert.equal(logs[0].relayStatus, 400);
});

test("a claim after the minted window is an explicit expiry, never a snapshot carrying the late claim", async () => {
  const fixture = await buildV2Fixture();
  const openedAtMs = Date.now() - 1_000;
  const session = relaySession(fixture, openedAtMs);
  const snapshots = [];
  const posted = [];
  const relayClient = fakeRelay({
    accepts: relayValidator,
    messages: [
      message(1, "initiator", "agent_v2_invitation_created", {
        claimExpiresAtMs: String(openedAtMs + 200_000),
        createdAtMs: String(openedAtMs + 500),
        externalBusinessActionPerformed: false,
      }),
      message(2, "responder", "agent_v2_invitation_claimed", {
        claimedAtMs: String(openedAtMs + 200_000),
        externalBusinessActionPerformed: false,
      }),
    ],
    posted,
    snapshots,
  });
  const ports = await createAgentHandshakeV2HostPorts(session, {
    fundingBudget: { reserve: async () => {} },
    log: () => {},
    monitor: createAgentHandshakeV2Monitor({
      now: () => openedAtMs + 1_000,
      publish: (snapshot) => relayClient.putSnapshot({ snapshot }),
      session,
    }),
    postHostMessage: async (kind, body) => posted.push([kind, body]),
    publicClient: {},
    relayClient,
  });
  const result = await runAgentHandshakeV2HostSession({
    now: () => openedAtMs + 1_000,
    ports: { ...ports, awaitIdentityClaim: ports.awaitIdentityClaim, awaitPartyReady: ports.awaitPartyReady },
    session: {
      ...session,
      expectedPublicKey: fixture.host.publicKey,
      keyId: fixture.host.keyId,
      privateKeyPem: fixture.host.privateKeyPem,
    },
  }).then(() => null, (error) => error);
  assert.equal(result?.code, "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED");
  const last = snapshots.at(-1);
  assert.equal(last.invitation.responderClaimedAtMs, null);
  assert.deepEqual(last.failure, { reasonCode: "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED" });
  assert.equal(last.checker.stage, "FAILED");
  for (const snapshot of snapshots) assert.equal(relayValidator(snapshot), true);
  assert.deepEqual(posted, [[AGENT_HANDSHAKE_V2_SESSION_FAILED_KIND, {
    externalBusinessActionPerformed: false,
    reasonCode: "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED",
  }]]);
});

test("a minted invitation nobody claims in its window expires explicitly", async () => {
  const opened = Date.now();
  const posted = [];
  const ports = await createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    terms: TERMS,
    sessionOpenedAtMs: opened,
    invitationExpiresAtMs: opened + 200,
    sessionDeadlineMs: opened + 5_000,
  }, {
    fundingBudget: { reserve: async () => {} },
    log: () => {},
    monitor: { invitationClaimed: async () => {} },
    postHostMessage: async (kind, body) => posted.push([kind, body]),
    publicClient: {},
    relayClient: {
      generateEnvelopeKeyPair: () => ({}),
      pollMessages: async () => ({
        messages: [message(1, "initiator", "agent_v2_invitation_created", {
          claimExpiresAtMs: String(opened + 400),
          createdAtMs: String(opened + 50),
          externalBusinessActionPerformed: false,
        })],
      }),
      verifyEnvelope: () => true,
    },
  });
  await assert.rejects(
    () => ports.awaitInvitationClaimed(),
    (error) =>
      error?.code === "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED" &&
      error.cause instanceof SessionEnded,
  );
});

test("an unminted session still rotates quietly: no failure is published", async () => {
  const fixture = await buildV2Fixture();
  const failed = [];
  const notified = [];
  const error = new SessionEnded("EXPIRED", "Timed out waiting for agent_v2_invitation_claimed.");
  const session = relaySession(fixture, 1786337000000);
  await assert.rejects(
    () => runAgentHandshakeV2HostSession({
      now: () => 1786337000001,
      ports: hostPorts({
        awaitInvitationClaimed: async () => { throw error; },
        failed: async (code) => failed.push(code),
        notifySessionFailed: async (code) => notified.push(code),
      }),
      session,
    }),
    (thrown) => thrown === error,
  );
  assert.deepEqual(failed, []);
  assert.deepEqual(notified, []);
});

test("the host runner publishes and notifies an invitation expiry once, and keeps the source error", async () => {
  const fixture = await buildV2Fixture();
  const failed = [];
  const notified = [];
  const error = Object.assign(new Error("expired"), { code: "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED" });
  await assert.rejects(
    () => runAgentHandshakeV2HostSession({
      now: () => 1786337000001,
      ports: hostPorts({
        awaitInvitationClaimed: async () => { throw error; },
        failed: async (code) => failed.push(code),
        notifySessionFailed: async (code) => notified.push(code),
      }),
      session: relaySession(fixture, 1786337000000),
    }),
    (thrown) => thrown === error,
  );
  assert.deepEqual(failed, ["AGENT_HANDSHAKE_V2_INVITATION_EXPIRED"]);
  assert.deepEqual(notified, ["AGENT_HANDSHAKE_V2_INVITATION_EXPIRED"]);
});

test("preparation failures also notify both parties", async () => {
  const fixture = await buildV2Fixture();
  const notified = [];
  const source = new Error("identity claim unavailable");
  await assert.rejects(
    () => runAgentHandshakeV2HostSession({
      now: () => 1786337000001,
      ports: hostPorts({
        awaitIdentityClaim: async () => { throw source; },
        notifySessionFailed: async (code) => notified.push(code),
      }),
      session: relaySession(fixture, 1786337000000),
    }),
    (thrown) => thrown === source,
  );
  assert.deepEqual(notified, ["AGENT_HANDSHAKE_V2_IDENTITY_PREPARATION_FAILED"]);
});

test("a failing notification never masks the session's own error", async () => {
  const fixture = await buildV2Fixture();
  const error = Object.assign(new Error("expired"), { code: "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED" });
  await assert.rejects(
    () => runAgentHandshakeV2HostSession({
      now: () => 1786337000001,
      ports: hostPorts({
        awaitInvitationClaimed: async () => { throw error; },
        failed: async () => { throw new Error("monitor down"); },
        notifySessionFailed: async () => { throw new Error("relay down"); },
      }),
      session: relaySession(fixture, 1786337000000),
    }),
    (thrown) => thrown === error,
  );
});

test("the notice to the parties is posted at most once and a refused post is only logged", async () => {
  const logs = [];
  let posts = 0;
  const ports = await createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    terms: TERMS,
    sessionOpenedAtMs: 1,
    invitationExpiresAtMs: 120_001,
    sessionDeadlineMs: 600_001,
  }, {
    fundingBudget: { reserve: async () => {} },
    log: (event) => logs.push(event),
    monitor: {},
    postHostMessage: async () => {
      posts += 1;
      throw new RelayError("Relay request failed: UNKNOWN_SESSION.", "UNKNOWN_SESSION", { status: 404 });
    },
    publicClient: {},
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
  });
  await ports.notifySessionFailed("AGENT_HANDSHAKE_V2_INVITATION_EXPIRED");
  await ports.notifySessionFailed("AGENT_HANDSHAKE_V2_INVITATION_EXPIRED");
  assert.equal(posts, 1);
  assert.deepEqual(logs.map((entry) => [entry.event, entry.relayCode]), [
    ["agent_handshake_v2_session_failed_notice_unpublished", "UNKNOWN_SESSION"],
  ]);
});

test("only a relay 4xx other than 429 counts as a snapshot rejection", () => {
  assert.equal(isRelayRejection(new RelayError("x", "MALFORMED_SNAPSHOT", { status: 400 })), true);
  assert.equal(isRelayRejection(new RelayError("x", "UNKNOWN_SESSION", { status: 404 })), true);
  assert.equal(isRelayRejection(new RelayError("x", "BODY_TOO_LARGE", { status: 413 })), true);
  assert.equal(isRelayRejection(new RelayError("x", "RATE_BLOCKED", { status: 429 })), false);
  assert.equal(isRelayRejection(new RelayError("x", "SERVER_ERROR", { status: 503 })), false);
  assert.equal(isRelayRejection(new RelayError("x", "RENDEZVOUS_UNAVAILABLE", { status: 0 })), false);
  assert.equal(isRelayRejection(Object.assign(new Error("x"), { status: 400 })), false);
});

test("a transient snapshot failure is not turned into a terminal session failure", async () => {
  const posted = [];
  const transient = new RelayError("x", "SERVER_ERROR", { status: 503 });
  const ports = await createAgentHandshakeV2HostPorts({
    relayUrl: "https://relay.test",
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    terms: TERMS,
    sessionOpenedAtMs: 1,
    invitationExpiresAtMs: 120_001,
    sessionDeadlineMs: 600_001,
  }, {
    fundingBudget: { reserve: async () => {} },
    log: () => {},
    monitor: { start: async () => { throw transient; } },
    postHostMessage: async (kind, body) => posted.push([kind, body]),
    publicClient: {},
    relayClient: { generateEnvelopeKeyPair: () => ({}) },
  });
  await assert.rejects(() => ports.publishInitial(), (error) => error === transient);
  assert.deepEqual(posted, []);
});

function hostPorts(overrides) {
  const noop = async () => {};
  return {
    acceptanceSigned: noop,
    anchorsRecorded: noop,
    awaitAcceptance: noop,
    awaitAnchors: noop,
    awaitEvidence: noop,
    awaitIdentityClaim: noop,
    awaitInvitationClaimed: async () => 1786337000001,
    awaitPartyReady: noop,
    awaitProposal: noop,
    certificateIssued: noop,
    checkerStage: noop,
    evidenceReceived: noop,
    failed: noop,
    partiesReady: noop,
    proposalSigned: noop,
    publishDescriptor: noop,
    publishInitial: noop,
    publishResult: noop,
    ...overrides,
  };
}
