// H-REQ-01 (relay): a session created with a relay authorization admits a
// role's message only from the key the coordinator enrolled for that role, and
// host messages only from the declared host key. Sessions created without one
// keep the legacy mailbox behaviour.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { appendFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createRelayServer } from "../src/relay/server.mjs";
import * as relayClient from "../src/relay/client.mjs";
import { createRelayAuthorization } from "../src/agent-handshake/v2/relay-enrollment.mjs";
import { SESSION_ID } from "./support/agent-handshake-v2-fixture.mjs";
import {
  COORDINATOR_KEY_RING,
  DEADLINE_MS,
  enrollmentEnvelope,
  envelopeFrom,
  REDEEMED_AT_MS,
  SENDERS,
  signedEnrollment,
} from "./support/sender-enrollment-fixture.mjs";

const RELAY_NOW_MS = REDEEMED_AT_MS + 1_000;
const OTHER_SESSION_ID = "33333333-4444-4555-8666-777777777777";
const AUTHORIZATION = createRelayAuthorization({
  coordinatorKeyRing: COORDINATOR_KEY_RING,
  hostSenderKey: SENDERS.host.publicKey,
});

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), "handshake-relay-enrollment-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  return directory;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function closeServer(server) {
  const closed = new Promise((resolve) => server.close(resolve));
  server.closeAllConnections();
  return closed;
}

async function startServer(t, { stateDir, now = () => RELAY_NOW_MS, appendJournal } = {}) {
  const dir = stateDir ?? (await temporaryDirectory(t));
  const server = await createRelayServer({
    stateDir: dir,
    now,
    ...(appendJournal ? { appendJournal } : {}),
  });
  const baseUrl = await listen(server);
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await closeServer(server);
  };
  t.after(close);
  return { baseUrl, close, stateDir: dir };
}

async function send(method, url, body) {
  const response = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function createSession(baseUrl, { sessionId = SESSION_ID, relayAuthorization = AUTHORIZATION } = {}) {
  return send("POST", `${baseUrl}/v1/sessions`, {
    sessionId,
    discovery: { schema: "test-discovery" },
    ...(relayAuthorization === null ? {} : { relayAuthorization }),
  });
}

function post(baseUrl, envelope, sessionId = SESSION_ID) {
  return send("POST", `${baseUrl}/v1/sessions/${sessionId}/messages`, envelope);
}

async function messages(baseUrl, sessionId = SESSION_ID) {
  return (await send("GET", `${baseUrl}/v1/sessions/${sessionId}/messages?after=0&waitMs=0`)).body.messages;
}

function said(seq, role, sender, kind = "agent_v2_identity_claim") {
  return envelopeFrom({ seq, role, kind, body: { note: `${role}-${seq}` }, sender });
}

function enrollment(seq, role, overrides = {}, { sender = SENDERS[role], signer } = {}) {
  return enrollmentEnvelope({
    seq,
    role,
    sender,
    body: signedEnrollment(role, overrides, signer ? { signer } : {}),
  });
}

function refusedWith(response, status, code) {
  assert.equal(response.status, status, JSON.stringify(response.body));
  assert.equal(response.body.error, code);
}

test("H-REQ-01 (relay): a legacy session keeps the mailbox behaviour", async (t) => {
  const { baseUrl } = await startServer(t);
  assert.equal((await createSession(baseUrl, { relayAuthorization: null })).status, 201);
  const unverifiable = {
    sessionId: SESSION_ID,
    seq: "1",
    role: "initiator",
    kind: "agent_v2_identity_claim",
    body: {},
    senderKey: randomBytes(32).toString("base64"),
    sig: randomBytes(64).toString("base64"),
  };
  assert.equal((await post(baseUrl, unverifiable)).status, 201);
  assert.equal((await post(baseUrl, said(2, "payer", SENDERS.unenrolled))).status, 201);
  assert.equal((await post(baseUrl, said(3, "host", SENDERS.unenrolled))).status, 201);
  assert.equal((await messages(baseUrl)).length, 3);
});

test("H-REQ-01 (relay): a malformed relay authorization is refused and creates no session", async (t) => {
  const { baseUrl } = await startServer(t);
  for (const relayAuthorization of [
    { ...AUTHORIZATION, schema: "other" },
    { ...AUTHORIZATION, coordinatorKeys: [] },
    { ...AUTHORIZATION, hostSenderKey: "short" },
    { ...AUTHORIZATION, extra: true },
    "not an object",
  ]) {
    refusedWith(await createSession(baseUrl, { relayAuthorization }), 400, "MALFORMED_REQUEST");
  }
  refusedWith(await send("GET", `${baseUrl}/v1/sessions/${SESSION_ID}/messages?after=0&waitMs=0`), 404, "UNKNOWN_SESSION");
});

test("H-REQ-01 (relay): a role speaks only after its enrollment and only with the enrolled key", async (t) => {
  const { baseUrl } = await startServer(t);
  assert.equal((await createSession(baseUrl)).status, 201);
  refusedWith(await post(baseUrl, said(1, "initiator", SENDERS.initiator)), 403, "BINDING_MISMATCH");
  refusedWith(await post(baseUrl, said(1, "initiator", SENDERS.initiator, "agent_v2_invitation_created")), 403, "BINDING_MISMATCH");
  assert.equal((await post(baseUrl, enrollment(1, "initiator"))).status, 201);
  assert.equal((await post(baseUrl, said(2, "initiator", SENDERS.initiator))).status, 201);
  // Right role, wrong key.
  refusedWith(await post(baseUrl, said(3, "initiator", SENDERS.unenrolled)), 403, "BINDING_MISMATCH");
  // The enrolled key named, signed by another key.
  refusedWith(await post(baseUrl, {
    ...said(3, "initiator", SENDERS.unenrolled),
    senderKey: SENDERS.initiator.publicKey,
  }), 403, "BINDING_MISMATCH");
  // Right key, wrong role: before and after that role enrolls.
  refusedWith(await post(baseUrl, said(3, "responder", SENDERS.initiator)), 403, "BINDING_MISMATCH");
  assert.equal((await post(baseUrl, enrollment(3, "responder"))).status, 201);
  refusedWith(await post(baseUrl, said(4, "responder", SENDERS.initiator)), 403, "BINDING_MISMATCH");
  assert.equal((await post(baseUrl, said(4, "responder", SENDERS.responder))).status, 201);
  // Any other role.
  refusedWith(await post(baseUrl, said(5, "payer", SENDERS.initiator)), 403, "BINDING_MISMATCH");
  refusedWith(await post(baseUrl, said(5, "coordinator", SENDERS.initiator)), 403, "BINDING_MISMATCH");
});

test("H-REQ-01 (relay): an enrollment that does not verify is refused", async (t) => {
  const { baseUrl } = await startServer(t);
  assert.equal((await createSession(baseUrl)).status, 201);
  const refusals = [
    // Another session's enrollment.
    enrollment(1, "initiator", { sessionId: OTHER_SESSION_ID }),
    // Signed by a key outside the coordinator ring.
    enrollment(1, "initiator", {}, { signer: SENDERS.unenrolled }),
    // The valid body under another sender key.
    enrollmentEnvelope({ seq: 1, role: "initiator", sender: SENDERS.unenrolled, body: signedEnrollment("initiator") }),
    // The valid body labelled with the other role.
    enrollmentEnvelope({ seq: 1, role: "responder", sender: SENDERS.initiator, body: signedEnrollment("initiator") }),
    // An envelope signature that does not verify, over a valid enrollment.
    { ...enrollment(1, "initiator"), sig: randomBytes(64).toString("base64") },
  ];
  for (const envelope of refusals) {
    refusedWith(await post(baseUrl, envelope), 403, "BINDING_MISMATCH");
  }
  assert.deepEqual(await messages(baseUrl), []);
});

test("H-REQ-01 (relay): a stale enrollment is refused", async (t) => {
  const { baseUrl } = await startServer(t, { now: () => DEADLINE_MS });
  assert.equal((await createSession(baseUrl)).status, 201);
  refusedWith(await post(baseUrl, enrollment(1, "initiator")), 403, "BINDING_MISMATCH");
});

test("H-REQ-07 (relay): enrollment freshness is judged against a clock that never reads earlier than a previous read", async (t) => {
  const clock = { value: DEADLINE_MS };
  const { baseUrl } = await startServer(t, { now: () => clock.value });
  assert.equal((await createSession(baseUrl)).status, 201);
  refusedWith(await post(baseUrl, enrollment(1, "initiator")), 403, "BINDING_MISMATCH");
  // The clock now reads an earlier time; the enrollment is still stale.
  clock.value = RELAY_NOW_MS;
  refusedWith(await post(baseUrl, enrollment(1, "initiator")), 403, "BINDING_MISMATCH");
  assert.deepEqual(await messages(baseUrl), []);
  // A relay whose clock only moves forward admits the same enrollment.
  const forward = await startServer(t, { now: () => RELAY_NOW_MS });
  assert.equal((await createSession(forward.baseUrl)).status, 201);
  assert.equal((await post(forward.baseUrl, enrollment(1, "initiator"))).status, 201);
});

test("H-REQ-01 (relay): a role is enrolled once, and one key holds at most one role", async (t) => {
  const { baseUrl } = await startServer(t);
  assert.equal((await createSession(baseUrl)).status, 201);
  assert.equal((await post(baseUrl, enrollment(1, "initiator"))).status, 201);
  refusedWith(await post(baseUrl, enrollment(2, "initiator")), 409, "ROLE_ALREADY_BOUND");
  refusedWith(await post(baseUrl, enrollment(2, "initiator", { senderKey: SENDERS.unenrolled.publicKey }, {
    sender: SENDERS.unenrolled,
  })), 409, "ROLE_ALREADY_BOUND");
  refusedWith(await post(baseUrl, enrollment(2, "responder", { senderKey: SENDERS.initiator.publicKey }, {
    sender: SENDERS.initiator,
  })), 403, "BINDING_MISMATCH");
  assert.equal((await post(baseUrl, enrollment(2, "responder"))).status, 201);
});

test("H-REQ-01 (relay): host messages need the declared host key and a valid signature", async (t) => {
  const { baseUrl } = await startServer(t);
  assert.equal((await createSession(baseUrl)).status, 201);
  refusedWith(await post(baseUrl, said(1, "host", SENDERS.unenrolled, "agent_v2_session_failed")), 403, "BINDING_MISMATCH");
  refusedWith(await post(baseUrl, {
    ...said(1, "host", SENDERS.unenrolled, "agent_v2_session_failed"),
    senderKey: SENDERS.host.publicKey,
  }), 403, "BINDING_MISMATCH");
  refusedWith(await post(baseUrl, enrollmentEnvelope({
    seq: 1, role: "host", sender: SENDERS.unenrolled, body: signedEnrollment("initiator"),
  })), 403, "BINDING_MISMATCH");
  assert.equal((await post(baseUrl, said(1, "host", SENDERS.host, "agent_v2_handshake_required"))).status, 201);
});

test("H-REQ-01 (relay): the relay serves only the messages it admitted", async (t) => {
  const { baseUrl } = await startServer(t);
  assert.equal((await createSession(baseUrl)).status, 201);
  await post(baseUrl, said(1, "initiator", SENDERS.unenrolled));
  await post(baseUrl, enrollment(1, "initiator"));
  await post(baseUrl, said(2, "initiator", SENDERS.unenrolled));
  await post(baseUrl, said(2, "host", SENDERS.host));
  await post(baseUrl, said(3, "responder", SENDERS.responder));
  await post(baseUrl, said(3, "initiator", SENDERS.initiator));
  const served = await messages(baseUrl);
  assert.deepEqual(served.map(({ seq, role, senderKey }) => [seq, role, senderKey]), [
    ["1", "initiator", SENDERS.initiator.publicKey],
    ["2", "host", SENDERS.host.publicKey],
    ["3", "initiator", SENDERS.initiator.publicKey],
  ]);
});

test("H-REQ-01 (relay): a restarted relay restores the bindings from its journal", async (t) => {
  const first = await startServer(t);
  assert.equal((await createSession(first.baseUrl)).status, 201);
  assert.equal((await post(first.baseUrl, enrollment(1, "initiator"))).status, 201);
  assert.equal((await post(first.baseUrl, said(2, "initiator", SENDERS.initiator))).status, 201);
  await first.close();
  const journal = (await readFile(join(first.stateDir, `${SESSION_ID}.jsonl`), "utf8"))
    .trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(journal[0].relayAuthorization, AUTHORIZATION);

  const second = await startServer(t, { stateDir: first.stateDir });
  refusedWith(await post(second.baseUrl, said(3, "initiator", SENDERS.unenrolled)), 403, "BINDING_MISMATCH");
  refusedWith(await post(second.baseUrl, enrollment(3, "initiator")), 409, "ROLE_ALREADY_BOUND");
  refusedWith(await post(second.baseUrl, said(3, "host", SENDERS.unenrolled)), 403, "BINDING_MISMATCH");
  assert.equal((await post(second.baseUrl, said(3, "initiator", SENDERS.initiator))).status, 201);
  assert.equal((await post(second.baseUrl, enrollment(4, "responder"))).status, 201);
  assert.equal((await messages(second.baseUrl)).length, 4);
});

// A journal writer that parks appends while held, so a second request can be
// queued behind the first one's journal write.
function heldJournal() {
  const parked = [];
  const parkWaiters = [];
  let held = false;
  return {
    append(journalPath, line) {
      if (!held) return appendFile(journalPath, line, "utf8");
      return new Promise((resolve, reject) => {
        parked.push(() => appendFile(journalPath, line, "utf8").then(resolve, reject));
        for (const waiter of parkWaiters.splice(0)) waiter();
      });
    },
    hold() { held = true; },
    async parked(count) {
      while (parked.length < count) await new Promise((resolve) => parkWaiters.push(resolve));
    },
    releaseAll() {
      held = false;
      for (const release of parked.splice(0)) release();
    },
  };
}

test("H-REQ-01 (relay): two concurrent enrollments for one role bind exactly one", async (t) => {
  const journal = heldJournal();
  const { baseUrl } = await startServer(t, { appendJournal: journal.append });
  assert.equal((await createSession(baseUrl)).status, 201);
  journal.hold();
  const first = post(baseUrl, enrollment(1, "initiator"));
  await journal.parked(1);
  // Queued behind the first enrollment's journal write, with the next seq.
  const second = post(baseUrl, enrollment(2, "initiator", { senderKey: SENDERS.unenrolled.publicKey }, {
    sender: SENDERS.unenrolled,
  }));
  await new Promise((resolve) => setTimeout(resolve, 50));
  journal.releaseAll();
  const [won, lost] = await Promise.all([first, second]);
  assert.equal(won.status, 201);
  refusedWith(lost, 409, "ROLE_ALREADY_BOUND");
  assert.equal((await post(baseUrl, said(2, "initiator", SENDERS.initiator))).status, 201);
  refusedWith(await post(baseUrl, said(3, "initiator", SENDERS.unenrolled)), 403, "BINDING_MISMATCH");
  assert.equal((await messages(baseUrl)).length, 2);
});

test("H-REQ-01 (relay client): the client opts a session in and checks envelopes against the enrolled key", async (t) => {
  const { baseUrl } = await startServer(t);
  await relayClient.createSession({
    relayUrl: baseUrl,
    sessionId: SESSION_ID,
    discovery: { schema: "test-discovery" },
    relayAuthorization: AUTHORIZATION,
    retryBudgetMs: 0,
  });
  await assert.rejects(
    relayClient.postMessage({ relayUrl: baseUrl, sessionId: SESSION_ID, envelope: said(1, "initiator", SENDERS.unenrolled), retryBudgetMs: 0 }),
    (error) => error?.code === "BINDING_MISMATCH" && error.status === 403,
  );
  const enrolled = enrollment(1, "initiator");
  await relayClient.postMessage({ relayUrl: baseUrl, sessionId: SESSION_ID, envelope: enrolled, retryBudgetMs: 0 });
  // A reader that knows the enrolled key checks the envelope against it, not
  // against the key the envelope names.
  const fromEnrolledKey = said(2, "initiator", SENDERS.initiator);
  assert.equal(relayClient.verifyEnvelope(fromEnrolledKey, { expectedSenderKey: SENDERS.initiator.publicKey }), true);
  assert.throws(
    () => relayClient.verifyEnvelope(said(2, "initiator", SENDERS.unenrolled), {
      expectedSenderKey: SENDERS.initiator.publicKey,
    }),
    (error) => error?.code === "BINDING_MISMATCH",
  );
  // Without an expected key the check is unchanged.
  assert.equal(relayClient.verifyEnvelope(said(2, "initiator", SENDERS.unenrolled)), true);
});

// --- H-REQ-07 (relay): an enrollment's freshness is judged when it is
// admitted, under the session lock, and the journal keeps that decision. ---

// A relay clock that counts its reads, so a test can wait until a request has
// passed its arrival check.
function countedClock(startMs) {
  const clock = {
    reads: 0,
    value: startMs,
    now: () => { clock.reads += 1; return clock.value; },
    async readsAbove(count) {
      while (clock.reads <= count) await new Promise((resolve) => setTimeout(resolve, 1));
    },
  };
  return clock;
}

// The initiator enrollment's journal write is held; the responder enrollment
// arrives, passes its arrival check at RELAY_NOW_MS, and waits for the session
// lock; the clock then moves to `admittedAtMs` before the write is released.
async function queuedEnrollment(t, admittedAtMs, { stateDir } = {}) {
  const clock = countedClock(RELAY_NOW_MS);
  const journal = heldJournal();
  const server = await startServer(t, { stateDir, now: clock.now, appendJournal: journal.append });
  assert.equal((await createSession(server.baseUrl)).status, 201);
  journal.hold();
  const first = post(server.baseUrl, enrollment(1, "initiator"));
  await journal.parked(1);
  const readsBefore = clock.reads;
  const second = post(server.baseUrl, enrollment(2, "responder"));
  await clock.readsAbove(readsBefore);
  clock.value = admittedAtMs;
  journal.releaseAll();
  const [initiator, responder] = await Promise.all([first, second]);
  return { initiator, responder, server };
}

test("H-REQ-07 (relay): an enrollment queued behind another write is admitted only before its deadline", async (t) => {
  const atDeadline = await queuedEnrollment(t, DEADLINE_MS);
  assert.equal(atDeadline.initiator.status, 201);
  refusedWith(atDeadline.responder, 403, "BINDING_MISMATCH");
  assert.deepEqual((await messages(atDeadline.server.baseUrl)).map(({ seq, role }) => [seq, role]), [["1", "initiator"]]);

  const lastMs = await queuedEnrollment(t, DEADLINE_MS - 1);
  assert.equal(lastMs.initiator.status, 201);
  assert.equal(lastMs.responder.status, 201, JSON.stringify(lastMs.responder.body));
  assert.deepEqual((await messages(lastMs.server.baseUrl)).map(({ seq, role }) => [seq, role]), [["1", "initiator"], ["2", "responder"]]);
});

test("H-REQ-07 (relay): a restarted relay serves what it admitted and nothing it refused, whatever its clock reads", async (t) => {
  const stateDir = await temporaryDirectory(t);
  const queued = await queuedEnrollment(t, DEADLINE_MS, { stateDir });
  refusedWith(queued.responder, 403, "BINDING_MISMATCH");
  assert.equal((await post(queued.server.baseUrl, said(2, "initiator", SENDERS.initiator))).status, 201);
  await queued.server.close();

  // Restarted after the enrollments' deadline: admission is not judged again.
  const late = await startServer(t, { stateDir, now: () => DEADLINE_MS + 60_000 });
  assert.deepEqual((await messages(late.baseUrl)).map(({ seq, role }) => [seq, role]), [["1", "initiator"], ["2", "initiator"]]);
  assert.equal((await post(late.baseUrl, said(3, "initiator", SENDERS.initiator))).status, 201);
  refusedWith(await post(late.baseUrl, said(4, "responder", SENDERS.responder)), 403, "BINDING_MISMATCH");
  await late.close();

  // Restarted inside the window: the refused responder enrollment was never
  // recorded, so the role is still open to a current enrollment.
  const current = await startServer(t, { stateDir });
  assert.equal((await post(current.baseUrl, enrollment(4, "responder"))).status, 201);
  assert.equal((await post(current.baseUrl, said(5, "responder", SENDERS.responder))).status, 201);
  assert.equal((await messages(current.baseUrl)).length, 5);
});
