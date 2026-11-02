// H-REQ-07: the host re-reads its clock after every await that can take time,
// and refuses to sign or publish once the agreement, host key or session has
// lapsed. The clock below is scripted from inside the ports.
import assert from "node:assert/strict";
import test from "node:test";

import { runAgentHandshakeV2HostSession } from "../src/agent-handshake/v2/host.mjs";
import { createHostSessionKeyCertificate } from "../src/agent-handshake/v2/host-key-certificate.mjs";
import { agentHandshakeV2DescriptorDigest } from "../src/agent-handshake/v2/descriptor.mjs";
import { signAgentHandshakeV2Evidence } from "../src/agent-handshake/v2/evidence.mjs";
import {
  agentHandshakeV2TransitionDigest,
  createAgentHandshakeV2Acceptance,
  createAgentHandshakeV2Acknowledgment,
  createAgentHandshakeV2Proposal,
} from "../src/agent-handshake/v2/protocol.mjs";
import {
  INITIATOR,
  REPOSITORY_SHA,
  RESPONDER,
  SESSION_ID,
  SESSION_OPENED_AT_MS,
  SESSION_OPENED_BLOCK,
  TERMS,
  buildV2Fixture,
} from "./support/agent-handshake-v2-fixture.mjs";

const WINDOW_EXPIRED = "AGENT_HANDSHAKE_V2_SIGNING_WINDOW_EXPIRED";
const OPENED_AT_MS = Number(SESSION_OPENED_AT_MS);
const ACCEPTANCE_ISSUED_AT_MS = 1786337160000;
const AGREEMENT_EXPIRES_AT_MS = 1786337190000;

// `value` is the current time; `queue` holds the next reads, in order, and each
// queued read becomes the current time once it is returned.
function scriptedClock(start = ACCEPTANCE_ISSUED_AT_MS) {
  const clock = {
    queue: [],
    reads: [],
    value: start,
    now() {
      if (clock.queue.length > 0) clock.value = clock.queue.shift();
      clock.reads.push(clock.value);
      return clock.value;
    },
  };
  return clock;
}

function certificateFor(fixture, { validFromMs, validUntilMs }) {
  return createHostSessionKeyCertificate({
    certificate: {
      schema: "clockchain.host-session-key/v1",
      rootKid: fixture.root.keyId,
      sessionId: SESSION_ID,
      repositorySha: REPOSITORY_SHA,
      sessionPublicKey: fixture.host.publicKey,
      validFromMs: String(validFromMs),
      validUntilMs: String(validUntilMs),
    },
    root: { keyId: fixture.root.keyId, privateKeyPem: fixture.root.privateKeyPem },
  });
}

function sessionFor(fixture, { openedAtMs = OPENED_AT_MS, certificate = fixture.hostSessionKeyCertificate } = {}) {
  return {
    expectedPublicKey: fixture.host.publicKey,
    hostSessionKeyCertificate: certificate,
    invitationExpiresAtMs: openedAtMs + 120_000,
    keyId: fixture.host.keyId,
    privateKeyPem: fixture.host.privateKeyPem,
    protocol: "clockchain.agent-handshake/v2",
    repositorySha: REPOSITORY_SHA,
    sessionDeadlineMs: openedAtMs + 600_000,
    sessionId: SESSION_ID,
    sessionOpenedAtMs: openedAtMs,
    sessionOpenedBlock: SESSION_OPENED_BLOCK,
    terms: TERMS,
  };
}

// Anchors and evidence are derived from the descriptor the host actually
// publishes, so a session with a different opening time or host key still
// carries a fully valid chain.
async function anchorsFor(fixture, descriptorEnvelope) {
  const descriptor = descriptorEnvelope.descriptor;
  const base = {
    expiresAtMs: descriptor.agreementExpiresAtMs,
    externalBusinessActionPerformed: false,
    initiator: fixture.parties.initiator,
    reference: TERMS.reference,
    responder: fixture.parties.responder,
    sessionDigest: agentHandshakeV2DescriptorDigest(descriptor),
    statementDigest: descriptor.statementDigest,
  };
  const proposed = createAgentHandshakeV2Proposal(base);
  const accepted = createAgentHandshakeV2Acceptance({ ...base, predecessor: agentHandshakeV2TransitionDigest(proposed) }, proposed);
  const acknowledged = createAgentHandshakeV2Acknowledgment({ ...base, predecessor: agentHandshakeV2TransitionDigest(accepted) }, accepted);
  const transitions = [proposed, accepted, acknowledged];
  const transitionDigests = transitions.map(agentHandshakeV2TransitionDigest);
  const receipts = transitions.map((transition, index) => ({
    blockHeight: String(7010 + index),
    blockTimeRaw: `2026-08-09T17:0${index}:00.000Z`,
    digest: transitionDigests[index],
    kind: ["proposal", "acceptance", "acknowledgment"][index],
    ledgerId: `33333333-4444-4555-8666-77777777777${index}`,
  }));
  const evidence = {};
  for (const [role, account] of [["initiator", INITIATOR], ["responder", RESPONDER]]) {
    evidence[role] = await signAgentHandshakeV2Evidence({
      result: {
        externalBusinessActionPerformed: false,
        party: fixture.parties[role],
        policyDigest: fixture.parties[role].policyDigest,
        reference: TERMS.reference,
        repositorySha: REPOSITORY_SHA,
        role,
        schema: "clockchain.agent-handshake-party-result/v2",
        sessionDigest: base.sessionDigest,
        statementDigest: base.statementDigest,
        transitionDigests,
      },
      signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }),
    });
  }
  return { evidence, receipts, transitions };
}

// hooks.afterProposal / afterAcceptance run when the host receives that
// artifact; hooks.duringVerdict runs once, inside the verdict's registration
// lookup (an awaited RPC in production). The same port also serves identity
// preparation, so the hook waits for the checker's VERIFYING stage.
function harness(fixture, hooks = {}) {
  const clock = scriptedClock();
  const calls = {
    acceptanceSigned: 0,
    certificateIssued: 0,
    failed: [],
    notified: [],
    proposalSigned: 0,
    publishResult: [],
  };
  let anchors = null;
  let verifying = false;
  let verdictHookRan = false;
  const ports = {
    acceptanceSigned: async () => { calls.acceptanceSigned += 1; },
    anchorsRecorded: async () => {},
    awaitAcceptance: async () => {
      hooks.afterAcceptance?.(clock);
      return fixture.acceptanceEnvelope;
    },
    awaitAnchors: async (descriptorEnvelope) => {
      anchors = await anchorsFor(fixture, descriptorEnvelope);
      return { receipts: anchors.receipts, transitions: anchors.transitions };
    },
    awaitEvidence: async (role) => anchors.evidence[role],
    awaitIdentityClaim: async (role) => ({
      policyDigest: fixture.parties[role].policyDigest,
      sessionKeyAddress: fixture.parties[role].sessionKeyAddress,
    }),
    awaitInvitationClaimed: async () => OPENED_AT_MS + 1,
    awaitPartyReady: async (role) => fixture.parties[role],
    awaitProposal: async () => {
      hooks.afterProposal?.(clock);
      return fixture.proposalEnvelope;
    },
    certificateIssued: async () => { calls.certificateIssued += 1; },
    checkerStage: async (stage) => { if (stage === "VERIFYING") verifying = true; },
    evidenceReceived: async () => {},
    failed: async (code) => { calls.failed.push(code); },
    fundIdentity: async () => {},
    notifySessionFailed: async (code) => { calls.notified.push(code); },
    partiesReady: async () => {},
    proposalSigned: async () => { calls.proposalSigned += 1; },
    publishDescriptor: async () => {},
    publishInitial: async () => {},
    publishResult: async (value) => { calls.publishResult.push(value); },
    reserveFunding: async () => {},
    resolveRegistration: async (agentId) => {
      if (verifying && !verdictHookRan) {
        verdictHookRan = true;
        hooks.duringVerdict?.(clock);
      }
      const role = agentId === "9452" ? "initiator" : "responder";
      return {
        owner: fixture.parties[role].sessionKeyAddress,
        registrationBlock: fixture.parties[role].erc8004.registrationBlock,
      };
    },
  };
  return { calls, clock, ports };
}

async function run(fixture, { hooks, session, clock: replaceClock } = {}) {
  const active = harness(fixture, hooks);
  const now = replaceClock ? replaceClock(active.clock) : () => active.clock.now();
  const outcome = await runAgentHandshakeV2HostSession({
    now,
    ports: active.ports,
    session: session ?? sessionFor(fixture),
  }).then((value) => ({ value }), (error) => ({ error }));
  return { ...active, ...outcome };
}

function assertWindowExpired(result) {
  assert.equal(result.error?.code, WINDOW_EXPIRED, `expected ${WINDOW_EXPIRED}, got ${result.error?.code ?? "success"}`);
  assert.deepEqual(result.calls.publishResult, []);
  assert.equal(result.calls.certificateIssued, 0);
  assert.deepEqual(result.calls.failed, [WINDOW_EXPIRED]);
  assert.deepEqual(result.calls.notified, [WINDOW_EXPIRED]);
}

test("monotonicClock passes equal and later reads and refuses rollback and non-integer reads", async () => {
  const { monotonicClock } = await import("../src/agent-handshake/v2/clock.mjs");
  const values = [5, 5, 9];
  const clock = monotonicClock(() => values.shift());
  assert.deepEqual([clock.read(), clock.read(), clock.read()], [5, 5, 9]);
  const rolledBack = monotonicClock(((sequence) => () => sequence.shift())([10, 9]));
  assert.equal(rolledBack.read(), 10);
  assert.throws(() => rolledBack.read());
  for (const bad of [Number.NaN, 1.5, Number.MAX_SAFE_INTEGER + 1, "1786337160000", null]) {
    assert.throws(() => monotonicClock(() => bad).read());
  }
  assert.throws(() => monotonicClock(42));
});

test("nonDecreasingClock returns the highest read so far and refuses non-integer reads", async () => {
  const { nonDecreasingClock } = await import("../src/agent-handshake/v2/clock.mjs");
  const values = [5, 9, 7, 9, 12, 3];
  const clock = nonDecreasingClock(() => values.shift());
  assert.deepEqual([1, 2, 3, 4, 5, 6].map(() => clock.read()), [5, 9, 9, 9, 12, 12]);
  for (const bad of [Number.NaN, 1.5, Number.MAX_SAFE_INTEGER + 1, "1786337160000", null]) {
    assert.throws(() => nonDecreasingClock(() => bad).read());
  }
  assert.throws(() => nonDecreasingClock(42));
});

test("proposal window lapsing during verification refuses, proposalSigned not called", async () => {
  const fixture = await buildV2Fixture();
  const result = await run(fixture, {
    hooks: { afterProposal: (clock) => clock.queue.push(ACCEPTANCE_ISSUED_AT_MS, AGREEMENT_EXPIRES_AT_MS) },
  });
  assert.equal(result.calls.proposalSigned, 0);
  assert.equal(result.calls.acceptanceSigned, 0);
  assertWindowExpired(result);
});

test("acceptance window lapsing during verification refuses, acceptanceSigned not called", async () => {
  const fixture = await buildV2Fixture();
  const result = await run(fixture, {
    hooks: { afterAcceptance: (clock) => clock.queue.push(ACCEPTANCE_ISSUED_AT_MS, AGREEMENT_EXPIRES_AT_MS) },
  });
  assert.equal(result.calls.proposalSigned, 1);
  assert.equal(result.calls.acceptanceSigned, 0);
  assertWindowExpired(result);
});

test("verdict finishing after agreement expiry refuses, publishResult not called, failed called once", async () => {
  const fixture = await buildV2Fixture();
  const result = await run(fixture, {
    hooks: { duringVerdict: (clock) => { clock.value = AGREEMENT_EXPIRES_AT_MS + 5_000; } },
  });
  assertWindowExpired(result);
});

test("a lapse between issuance and publication refuses, publishResult not called", async () => {
  const fixture = await buildV2Fixture();
  const result = await run(fixture, {
    hooks: { duringVerdict: (clock) => clock.queue.push(1786337180000, AGREEMENT_EXPIRES_AT_MS) },
  });
  assertWindowExpired(result);
});

test("issuedAtMs is the post-verification read", async () => {
  const fixture = await buildV2Fixture();
  let readsBeforeVerdictReturned = null;
  const result = await run(fixture, {
    hooks: {
      duringVerdict: (clock) => {
        readsBeforeVerdictReturned = clock.reads.length;
        clock.value = 1786337170123;
      },
    },
  });
  assert.equal(result.error, undefined);
  assert.equal(result.calls.publishResult.length, 1);
  // The verdict itself ran at the earlier read; the certificate carries the
  // first read taken after it returned.
  assert.equal(result.clock.reads[readsBeforeVerdictReturned - 1], ACCEPTANCE_ISSUED_AT_MS);
  assert.equal(result.clock.reads[readsBeforeVerdictReturned], 1786337170123);
  assert.equal(result.value.certificate.result.issuedAtMs, "1786337170123");
  assert.deepEqual(result.calls.failed, []);
});

test("a jump past the session deadline before issuance refuses", async () => {
  const fixture = await buildV2Fixture();
  // The session deadline falls inside the agreement window and the host key
  // outlives both, so only the deadline bound can refuse.
  const deadlineMs = AGREEMENT_EXPIRES_AT_MS - 1_000;
  const openedAtMs = deadlineMs - 600_000;
  const session = sessionFor(fixture, {
    openedAtMs,
    certificate: certificateFor(fixture, { validFromMs: openedAtMs, validUntilMs: AGREEMENT_EXPIRES_AT_MS + 60_000 }),
  });
  const passing = await run(fixture, {
    session,
    hooks: { duringVerdict: (clock) => { clock.value = deadlineMs - 1; } },
  });
  assert.equal(passing.error, undefined);
  assert.equal(passing.calls.publishResult.length, 1);
  const late = await run(fixture, {
    session,
    hooks: { duringVerdict: (clock) => { clock.value = deadlineMs; } },
  });
  assertWindowExpired(late);
});

test("issuance is bounded by the host-key certificate's validity", async () => {
  const fixture = await buildV2Fixture();
  // The host key expires inside the agreement window.
  const shortKey = sessionFor(fixture, {
    certificate: certificateFor(fixture, { validFromMs: OPENED_AT_MS, validUntilMs: AGREEMENT_EXPIRES_AT_MS - 5_000 }),
  });
  const beforeEnd = await run(fixture, {
    session: shortKey,
    hooks: { duringVerdict: (clock) => { clock.value = AGREEMENT_EXPIRES_AT_MS - 5_001; } },
  });
  assert.equal(beforeEnd.error, undefined);
  assert.equal(beforeEnd.value.certificate.result.issuedAtMs, String(AGREEMENT_EXPIRES_AT_MS - 5_001));
  const atEnd = await run(fixture, {
    session: shortKey,
    hooks: { duringVerdict: (clock) => { clock.value = AGREEMENT_EXPIRES_AT_MS - 5_000; } },
  });
  assertWindowExpired(atEnd);

  // The host key only becomes valid after the verdict's clock read: issuing
  // before its start fails closed and is not reported as a lapsed window.
  const lateKey = sessionFor(fixture, {
    certificate: certificateFor(fixture, { validFromMs: 1786337175000, validUntilMs: Number(fixture.hostSessionKeyCertificate.certificate.validUntilMs) }),
  });
  const early = await run(fixture, {
    session: lateKey,
    hooks: { duringVerdict: (clock) => { clock.value = 1786337174999; } },
  });
  assert.ok(early.error);
  assert.notEqual(early.error.code, WINDOW_EXPIRED);
  assert.deepEqual(early.calls.publishResult, []);
  assert.equal(early.calls.failed.includes(WINDOW_EXPIRED), false);
});

test("rollback at any read fails closed", async () => {
  const fixture = await buildV2Fixture();
  const baseline = await run(fixture);
  assert.equal(baseline.error, undefined);
  const reads = baseline.clock.reads.length;
  assert.ok(reads >= 2);
  const refused = [];
  for (let index = 1; index < reads; index += 1) {
    const result = await run(fixture, {
      clock: (clock) => {
        let count = 0;
        return () => {
          const value = clock.now();
          count += 1;
          return count === index + 1 ? value - 1 : value;
        };
      },
    });
    if (
      result.error !== undefined &&
      result.error.code !== WINDOW_EXPIRED &&
      result.calls.publishResult.length === 0 &&
      !result.calls.failed.includes(WINDOW_EXPIRED)
    ) refused.push(index);
  }
  assert.deepEqual(refused, Array.from({ length: reads - 1 }, (_, offset) => offset + 1));
  const nonInteger = await run(fixture, { clock: () => () => 1786337160000.5 });
  assert.ok(nonInteger.error);
  assert.deepEqual(nonInteger.calls.publishResult, []);
});

test("exact expiry refuses; expiry minus 1 ms passes", async () => {
  const fixture = await buildV2Fixture();
  const stages = {
    afterProposal: (at) => (clock) => clock.queue.push(ACCEPTANCE_ISSUED_AT_MS, at),
    afterAcceptance: (at) => (clock) => clock.queue.push(ACCEPTANCE_ISSUED_AT_MS, at),
    duringVerdict: (at) => (clock) => { clock.value = at; },
  };
  for (const [stage, hookAt] of Object.entries(stages)) {
    const atExpiry = await run(fixture, { hooks: { [stage]: hookAt(AGREEMENT_EXPIRES_AT_MS) } });
    assertWindowExpired(atExpiry);
    const lastMs = await run(fixture, { hooks: { [stage]: hookAt(AGREEMENT_EXPIRES_AT_MS - 1) } });
    assert.equal(lastMs.error, undefined, `${stage}: expiry minus 1 ms was refused (${lastMs.error?.code})`);
    assert.equal(lastMs.calls.publishResult.length, 1);
    assert.equal(lastMs.value.certificate.result.issuedAtMs, String(AGREEMENT_EXPIRES_AT_MS - 1));
  }
});

// --- Every signing, publishing or admission step that follows an await reads
// the clock again first. ---

// The session deadline falls inside the agreement and the host key outlives
// both, so only the deadline bounds the steps before the proposal.
const DEADLINE_INSIDE_AGREEMENT_MS = AGREEMENT_EXPIRES_AT_MS - 1_000;

function deadlineInsideAgreement(fixture) {
  const openedAtMs = DEADLINE_INSIDE_AGREEMENT_MS - 600_000;
  return sessionFor(fixture, {
    openedAtMs,
    certificate: certificateFor(fixture, { validFromMs: openedAtMs, validUntilMs: AGREEMENT_EXPIRES_AT_MS + 60_000 }),
  });
}

// Runs the host with every port call recorded in order. during[name] runs
// inside that port: it stands for time that passes while the host awaits it.
async function runRecorded(fixture, during = {}, { session } = {}) {
  const active = harness(fixture);
  const order = [];
  const ports = Object.fromEntries(Object.entries(active.ports).map(([name, port]) => [
    name,
    async (...args) => {
      order.push(args.length > 0 && typeof args[0] === "string" ? `${name}:${args[0]}` : name);
      during[name]?.(active.clock, ...args);
      return port(...args);
    },
  ]));
  const outcome = await runAgentHandshakeV2HostSession({
    now: () => active.clock.now(),
    ports,
    session: session ?? sessionFor(fixture),
  }).then((value) => ({ value }), (error) => ({ error }));
  return { ...active, ...outcome, order };
}

function assertStoppedBefore(result, step, label) {
  assert.equal(result.error?.code, WINDOW_EXPIRED, `${label}: expected ${WINDOW_EXPIRED}, got ${result.error?.code ?? "success"}`);
  assert.equal(result.order.includes(step), false, `${label}: ${step} ran after the window ended`);
  assert.deepEqual(result.calls.failed, [WINDOW_EXPIRED], label);
  assert.deepEqual(result.calls.notified, [WINDOW_EXPIRED], label);
}

function assertCompleted(result, step, label) {
  assert.equal(result.error, undefined, `${label}: ${result.error?.code ?? result.error?.message}`);
  assert.equal(result.order.includes(step), true, `${label}: ${step} did not run`);
  assert.equal(result.calls.publishResult.length, 1, label);
  assert.equal(result.calls.certificateIssued, 1, label);
}

// For each step: the port whose await ends the window, the step that must not
// run once it has ended, the bound, and the session.
function boundaryCases(fixture) {
  const early = deadlineInsideAgreement(fixture);
  const at = (port, filter) => (bound) => ({
    [port]: (clock, ...args) => { if (filter === undefined || args[0] === filter) clock.value = bound; },
  });
  return [
    { label: "funding reservation", during: at("awaitIdentityClaim", "responder"), step: "reserveFunding", bound: DEADLINE_INSIDE_AGREEMENT_MS, session: early },
    { label: "identity funding", during: at("reserveFunding"), step: "fundIdentity", bound: DEADLINE_INSIDE_AGREEMENT_MS, session: early },
    { label: "parties ready", during: at("awaitPartyReady", "responder"), step: "partiesReady", bound: DEADLINE_INSIDE_AGREEMENT_MS, session: early },
    { label: "descriptor", during: at("acceptanceSigned"), step: "publishDescriptor", bound: AGREEMENT_EXPIRES_AT_MS },
    { label: "anchors", during: at("awaitAnchors"), step: "anchorsRecorded", bound: AGREEMENT_EXPIRES_AT_MS },
    { label: "initiator evidence", during: at("awaitEvidence", "initiator"), step: "evidenceReceived:initiator", bound: AGREEMENT_EXPIRES_AT_MS },
    { label: "responder evidence", during: at("awaitEvidence", "responder"), step: "evidenceReceived:responder", bound: AGREEMENT_EXPIRES_AT_MS },
    { label: "verification stage", during: at("evidenceReceived", "responder"), step: "checkerStage:VERIFYING", bound: AGREEMENT_EXPIRES_AT_MS },
  ];
}

test("a window that ends during an awaited step stops the next signing, publishing or admission step", async () => {
  const fixture = await buildV2Fixture();
  for (const { label, during, step, bound, session } of boundaryCases(fixture)) {
    const atBound = await runRecorded(fixture, during(bound), { session });
    assertStoppedBefore(atBound, step, `${label} at the bound`);
    assert.deepEqual(atBound.calls.publishResult, [], label);
    const lastMs = await runRecorded(fixture, during(bound - 1), { session });
    assertCompleted(lastMs, step, `${label} 1 ms before the bound`);
  }
});

test("the descriptor is signed only inside the agreement", async () => {
  const fixture = await buildV2Fixture();
  const atBound = await runRecorded(fixture, {
    acceptanceSigned: (clock) => { clock.value = AGREEMENT_EXPIRES_AT_MS; },
  });
  assertStoppedBefore(atBound, "publishDescriptor", "descriptor at agreement expiry");
  assert.equal(atBound.order.includes("awaitAnchors"), false);
  const lastMs = await runRecorded(fixture, {
    acceptanceSigned: (clock) => { clock.value = AGREEMENT_EXPIRES_AT_MS - 1; },
  });
  assertCompleted(lastMs, "publishDescriptor", "descriptor 1 ms before agreement expiry");
  assert.equal(lastMs.value.certificate.result.issuedAtMs, String(AGREEMENT_EXPIRES_AT_MS - 1));
});

test("a result whose publication returned is recorded as issued", async () => {
  const fixture = await buildV2Fixture();
  // The agreement bounds the issue time; a publication that returns after the
  // agreement has ended is still recorded.
  const result = await runRecorded(fixture, {
    publishResult: (clock) => { clock.value = AGREEMENT_EXPIRES_AT_MS; },
  });
  assertCompleted(result, "certificateIssued", "recorded after the agreement");
  assert.deepEqual(result.calls.failed, []);
});
