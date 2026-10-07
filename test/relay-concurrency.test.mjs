// Concurrency and durability of the relay's session mutations.
//
// Every mutating handler used to follow read-check-await-write: it checked
// session state, awaited the journal append, and only then (or, for evidence,
// snapshot and result, already before) changed memory. Two requests that
// interleave across that await both pass the check -- the B3 loopback e2e saw
// both parties post party_ready with the same seq, both got 201, and every
// later read failed MESSAGE_SEQ_ORDER_INVALID until timeout.
//
// These tests pin the interleaving down deterministically with an injected
// journal writer that holds a write open until the test releases it, so the
// outcome never depends on scheduling luck. They also check the durability
// rule: memory only ever advances after its journal line is on disk, and a
// failed append leaves the session exactly as it was.
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { appendFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createRelayServer } from "../src/relay/server.mjs";
import { buildSignedResult } from "../src/core/result.mjs";
import { buildSnapshot } from "../src/monitor/snapshot.mjs";

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), "handshake-relay-race-"));
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

// Closes even with requests still parked on a held journal write (a failing
// run can leave one behind), so a red test fails instead of hanging.
function closeServer(server) {
  const closed = new Promise((resolve) => server.close(resolve));
  server.closeAllConnections();
  return closed;
}

// A journal writer the test controls. While open it writes straight through;
// once closed, each append is parked until release() or fail() is called on
// it. Writes that do happen go to the real file, so restart replay and direct
// journal reads see exactly what the relay committed.
function controlledJournal() {
  const parked = [];
  const parkWaiters = [];
  let closed = false;
  let failNext = 0;
  const journal = {
    appendCount: 0,
    append(journalPath, line) {
      journal.appendCount += 1;
      if (failNext > 0) {
        failNext -= 1;
        return Promise.reject(Object.assign(new Error("disk full"), { code: "ENOSPC" }));
      }
      if (!closed) {
        return appendFile(journalPath, line, "utf8");
      }
      return new Promise((resolve, reject) => {
        parked.push({
          line,
          release: () => appendFile(journalPath, line, "utf8").then(resolve, reject),
          fail: () => reject(Object.assign(new Error("disk full"), { code: "ENOSPC" })),
        });
        for (const waiter of parkWaiters.splice(0)) waiter();
      });
    },
    hold() {
      closed = true;
    },
    open() {
      closed = false;
    },
    failNextAppend() {
      failNext += 1;
    },
    async nextParked() {
      while (parked.length === 0) {
        await new Promise((resolve) => parkWaiters.push(resolve));
      }
      return parked.shift();
    },
    parkedCount() {
      return parked.length;
    },
  };
  return journal;
}

async function startRelay(t, { journal, stateDir } = {}) {
  const dir = stateDir ?? (await temporaryDirectory(t));
  const server = await createRelayServer({
    stateDir: dir,
    ...(journal ? { appendJournal: journal.append } : {}),
  });
  const baseUrl = await listen(server);
  let closed = false;
  const close = async () => {
    if (!closed) {
      closed = true;
      await closeServer(server);
    }
  };
  t.after(close);
  return { server, baseUrl, stateDir: dir, close };
}

// Resolves once the server has consumed the full body of the `nth` request
// (1-based) whose path ends in `pathSuffix`, then lets every microtask that
// follows run. After this the handler has done all of its synchronous
// validation and is parked on its next real await -- whichever that is.
function bodyConsumed(server, pathSuffix, nth) {
  return new Promise((resolve) => {
    let seen = 0;
    const onRequest = (req) => {
      if (!req.url.split("?")[0].endsWith(pathSuffix)) return;
      seen += 1;
      if (seen !== nth) return;
      server.removeListener("request", onRequest);
      req.once("end", () => setImmediate(() => setImmediate(resolve)));
    };
    server.on("request", onRequest);
  });
}

function randomBase64(byteLength) {
  return randomBytes(byteLength).toString("base64");
}

function envelope({ sessionId, seq, role = "payer", kind = "party_ready" }) {
  return {
    sessionId,
    seq,
    role,
    kind,
    body: { note: `${role}:${kind}:${seq}` },
    senderKey: randomBase64(32),
    sig: randomBase64(64),
  };
}

async function send(method, url, body) {
  const response = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

const post = (url, body) => send("POST", url, body);
const put = (url, body) => send("PUT", url, body);
const get = (url) => send("GET", url);

async function createSession(baseUrl, sessionId) {
  const created = await post(`${baseUrl}/v1/sessions`, sessionId ? { sessionId } : {});
  assert.equal(created.status, 201, JSON.stringify(created.body));
  return created.body.sessionId;
}

async function journalRecords(stateDir, sessionId) {
  const raw = await readFile(join(stateDir, `${sessionId}.jsonl`), "utf8");
  return raw.split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

// The same contiguity rule the relay client applies to a read: seqs must be
// exactly 1..N with no gap and no duplicate.
function assertReadsCleanly(messages) {
  messages.forEach((message, index) => {
    assert.equal(message.seq, String(index + 1), `message ${index} must carry seq ${index + 1}`);
  });
}

function evidenceTriple(tag) {
  return {
    json: Buffer.from(JSON.stringify({ tag })).toString("base64"),
    markdown: Buffer.from(`# ${tag}`).toString("base64"),
    marker: Buffer.from(JSON.stringify({ marker: tag })).toString("base64"),
  };
}

function minimalSnapshot(sessionId, updatedAtMs) {
  return buildSnapshot({
    anchors: { acceptance: null, acknowledgment: null, proposal: null },
    currentStage: "SESSION_STARTED",
    funding: null,
    heartbeat: { payee: null, payer: null, verifier: null },
    reasonCode: null,
    sessionId,
    stageHistory: [{ atMs: updatedAtMs, status: "SESSION_STARTED" }],
    subjectRun: "stakeholder",
    updatedAtMs,
    verdict: null,
  });
}

function signedResultFor(sessionId, issuedAtMs = "1785802329000") {
  const { privateKey } = generateKeyPairSync("ed25519");
  const party = (digit, agentId) => ({
    address: `0x${digit.repeat(40)}`,
    agentId,
    reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${agentId}`,
  });
  return buildSignedResult({
    issuedAtMs,
    keyId: "handshake-host",
    parties: { payer: party("1", "9400"), payee: party("2", "9401") },
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    sessionDigest: "d".repeat(64),
    sessionId,
    verdict: {
      outcome: "AUTHORIZED",
      paymentMoved: false,
      transitions: [
        { blockHeight: "100", blockTimeRaw: "2026-08-04T00:00:01Z", digest: "a".repeat(64), kind: "proposal", ledgerId: "11111111-1111-4111-8111-111111111111" },
        { blockHeight: "200", blockTimeRaw: "2026-08-04T00:00:02Z", digest: "b".repeat(64), kind: "acceptance", ledgerId: "22222222-2222-4222-8222-222222222222" },
        { blockHeight: "300", blockTimeRaw: "2026-08-04T00:00:03Z", digest: "c".repeat(64), kind: "acknowledgment", ledgerId: "33333333-3333-4333-8333-333333333333" },
      ],
    },
  });
}

// --- messages -------------------------------------------------------------

test("two concurrent POSTs with the same seq: exactly one 201, one 409 SEQ_CONFLICT, one stored message", async (t) => {
  const journal = controlledJournal();
  const { server, baseUrl, stateDir, close } = await startRelay(t, { journal });
  const sessionId = await createSession(baseUrl, "race-same-seq");
  const messagesUrl = `${baseUrl}/v1/sessions/${sessionId}/messages`;

  journal.hold();
  // Payer's party_ready reaches the journal and is held there.
  const first = post(messagesUrl, envelope({ sessionId, seq: "1", role: "payer" }));
  const firstWrite = await journal.nextParked();

  // Payee's party_ready, same seq, arrives while the payer's write is still in
  // flight. Wait until the relay has fully read and validated it before
  // letting the payer's write land -- this is the exact interleaving that
  // corrupted the B3 session.
  const secondRead = bodyConsumed(server, "/messages", 1);
  const second = post(messagesUrl, envelope({ sessionId, seq: "1", role: "payee" }));
  await secondRead;

  journal.open();
  await firstWrite.release();
  const results = await Promise.all([first, second]);

  const statuses = results.map((r) => r.status).sort();
  assert.deepEqual(statuses, [201, 409], `got ${JSON.stringify(results)}`);
  const conflict = results.find((r) => r.status === 409);
  assert.equal(conflict.body.error, "SEQ_CONFLICT");
  assert.equal(conflict.body.detail.expectedSeq, "2");
  assert.equal(results.find((r) => r.status === 201).body.seq, "1");

  // Memory: one message, and the session reads cleanly.
  const read = await get(`${messagesUrl}?after=0&waitMs=0`);
  assert.equal(read.status, 200);
  assert.equal(read.body.messages.length, 1);
  assert.equal(read.body.messages[0].role, "payer", "the write that reached the journal first wins");
  assertReadsCleanly(read.body.messages);

  // The loser retries at the next seq and the session keeps moving.
  const retry = await post(messagesUrl, envelope({ sessionId, seq: "2", role: "payee" }));
  assert.equal(retry.status, 201, JSON.stringify(retry.body));
  const after = await get(`${messagesUrl}?after=0&waitMs=0`);
  assert.deepEqual(after.body.messages.map((m) => [m.seq, m.role]), [["1", "payer"], ["2", "payee"]]);
  assertReadsCleanly(after.body.messages);

  // Journal: one record per accepted message, no duplicate seq.
  const records = (await journalRecords(stateDir, sessionId)).filter((r) => r.type === "message");
  assert.deepEqual(records.map((r) => [r.envelope.seq, r.envelope.role]), [["1", "payer"], ["2", "payee"]]);

  // And a restarted relay replays the same clean history.
  await close();
  const restarted = await startRelay(t, { stateDir });
  const replayed = await get(`${restarted.baseUrl}/v1/sessions/${sessionId}/messages?after=0&waitMs=0`);
  assert.deepEqual(replayed.body.messages.map((m) => [m.seq, m.role]), [["1", "payer"], ["2", "payee"]]);
});

test("many concurrent same-seq POSTs against the real journal never store a duplicate", async (t) => {
  const { baseUrl, stateDir } = await startRelay(t);
  const rounds = 25;
  for (let round = 0; round < rounds; round += 1) {
    const sessionId = await createSession(baseUrl, `race-real-${round}`);
    const messagesUrl = `${baseUrl}/v1/sessions/${sessionId}/messages`;
    const results = await Promise.all(
      ["payer", "payee", "payer", "payee"].map((role) =>
        post(messagesUrl, envelope({ sessionId, seq: "1", role })),
      ),
    );
    const created = results.filter((r) => r.status === 201);
    const conflicts = results.filter((r) => r.status === 409 && r.body.error === "SEQ_CONFLICT");
    assert.equal(created.length, 1, `round ${round}: ${JSON.stringify(results.map((r) => r.status))}`);
    assert.equal(conflicts.length, 3, `round ${round}`);
    const read = await get(`${messagesUrl}?after=0&waitMs=0`);
    assert.equal(read.body.messages.length, 1, `round ${round}`);
    const records = (await journalRecords(stateDir, sessionId)).filter((r) => r.type === "message");
    assert.equal(records.length, 1, `round ${round}`);
  }
});

test("a message is not visible to readers or long-pollers until its journal line is written", async (t) => {
  const journal = controlledJournal();
  const { baseUrl } = await startRelay(t, { journal });
  const sessionId = await createSession(baseUrl);
  const messagesUrl = `${baseUrl}/v1/sessions/${sessionId}/messages`;

  journal.hold();
  const posted = post(messagesUrl, envelope({ sessionId, seq: "1" }));
  const write = await journal.nextParked();

  const during = await get(`${messagesUrl}?after=0&waitMs=0`);
  assert.equal(during.body.messages.length, 0, "an unjournalled message must not be served");
  const snapshot = await get(`${baseUrl}/v1/sessions/${sessionId}/snapshot`);
  assert.equal(snapshot.body.lastSeq, "0");

  const longPoll = get(`${messagesUrl}?after=0&waitMs=5000`);
  journal.open();
  await write.release();
  assert.equal((await posted).status, 201);
  const woke = await longPoll;
  assert.deepEqual(woke.body.messages.map((m) => m.seq), ["1"]);
});

test("a failed message append leaves the session unchanged and does not wedge later writes", async (t) => {
  const journal = controlledJournal();
  const { baseUrl, stateDir } = await startRelay(t, { journal });
  const sessionId = await createSession(baseUrl);
  const messagesUrl = `${baseUrl}/v1/sessions/${sessionId}/messages`;

  journal.failNextAppend();
  const failed = await post(messagesUrl, envelope({ sessionId, seq: "1" }));
  assert.equal(failed.status, 500);
  assert.equal(failed.body.error, "FAILED");

  const read = await get(`${messagesUrl}?after=0&waitMs=0`);
  assert.equal(read.body.messages.length, 0, "state must not advance past a failed append");

  // The same seq is still the next one, and the session's write path still works.
  const retry = await post(messagesUrl, envelope({ sessionId, seq: "1" }));
  assert.equal(retry.status, 201, JSON.stringify(retry.body));
  const next = await post(messagesUrl, envelope({ sessionId, seq: "2" }));
  assert.equal(next.status, 201, JSON.stringify(next.body));
  const records = (await journalRecords(stateDir, sessionId)).filter((r) => r.type === "message");
  assert.deepEqual(records.map((r) => r.envelope.seq), ["1", "2"]);
});

test("a failed append parked behind another write does not take the next request down with it", async (t) => {
  const journal = controlledJournal();
  const { baseUrl } = await startRelay(t, { journal });
  const sessionId = await createSession(baseUrl);
  const messagesUrl = `${baseUrl}/v1/sessions/${sessionId}/messages`;

  journal.hold();
  const first = post(messagesUrl, envelope({ sessionId, seq: "1" }));
  const write = await journal.nextParked();
  journal.open();
  write.fail();
  assert.equal((await first).status, 500);

  const second = await post(messagesUrl, envelope({ sessionId, seq: "1" }));
  assert.equal(second.status, 201, JSON.stringify(second.body));
});

// --- session creation -----------------------------------------------------

test("session create: a failed journal append does not leave a phantom session behind", async (t) => {
  const journal = controlledJournal();
  const { baseUrl } = await startRelay(t, { journal });

  journal.failNextAppend();
  const failed = await post(`${baseUrl}/v1/sessions`, { sessionId: "phantom" });
  assert.equal(failed.status, 500);

  const snapshot = await get(`${baseUrl}/v1/sessions/phantom/snapshot`);
  assert.equal(snapshot.status, 404);
  assert.equal(snapshot.body.error, "UNKNOWN_SESSION");
  const health = await get(`${baseUrl}/healthz`);
  assert.equal(health.body.sessions, 0);

  const retry = await post(`${baseUrl}/v1/sessions`, { sessionId: "phantom" });
  assert.equal(retry.status, 201, JSON.stringify(retry.body));
});

test("session create: the id is reserved while its journal line is in flight, and invisible until written", async (t) => {
  const journal = controlledJournal();
  const { baseUrl } = await startRelay(t, { journal });

  journal.hold();
  const first = post(`${baseUrl}/v1/sessions`, { sessionId: "pending" });
  const write = await journal.nextParked();

  const duplicate = await post(`${baseUrl}/v1/sessions`, { sessionId: "pending" });
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.body.error, "SESSION_EXISTS");
  const early = await post(`${baseUrl}/v1/sessions/pending/messages`, envelope({ sessionId: "pending", seq: "1" }));
  assert.equal(early.status, 404, "a session is not usable before its creation is durable");
  assert.equal(early.body.error, "UNKNOWN_SESSION");
  assert.equal(journal.parkedCount(), 0, "the duplicate never reached the journal");

  journal.open();
  await write.release();
  assert.equal((await first).status, 201);
  const posted = await post(`${baseUrl}/v1/sessions/pending/messages`, envelope({ sessionId: "pending", seq: "1" }));
  assert.equal(posted.status, 201);
});

// --- evidence -------------------------------------------------------------

test("evidence PUT: not visible until journalled, and a failed append leaves no evidence", async (t) => {
  const journal = controlledJournal();
  const { baseUrl } = await startRelay(t, { journal });
  const sessionId = await createSession(baseUrl);
  const evidenceUrl = `${baseUrl}/v1/sessions/${sessionId}/evidence/payer`;

  journal.failNextAppend();
  const failed = await put(evidenceUrl, evidenceTriple("lost"));
  assert.equal(failed.status, 500);
  const afterFailure = await get(evidenceUrl);
  assert.equal(afterFailure.status, 404, "a failed append must not leave evidence in memory");
  assert.equal(afterFailure.body.error, "EVIDENCE_NOT_FOUND");

  journal.hold();
  const pending = put(evidenceUrl, evidenceTriple("kept"));
  const write = await journal.nextParked();
  const during = await get(evidenceUrl);
  assert.equal(during.status, 404, "evidence must not be served before it is durable");
  journal.open();
  await write.release();
  assert.equal((await pending).status, 200);
  const served = await get(evidenceUrl);
  assert.equal(served.status, 200);
  assert.deepEqual(served.body.json, evidenceTriple("kept").json);
});

test("evidence PUT: concurrent uploads for one role leave memory equal to what a restart replays", async (t) => {
  const journal = controlledJournal();
  const { server, baseUrl, stateDir, close } = await startRelay(t, { journal });
  const sessionId = await createSession(baseUrl);
  const evidenceUrl = `${baseUrl}/v1/sessions/${sessionId}/evidence/payee`;

  journal.hold();
  const first = put(evidenceUrl, evidenceTriple("first"));
  const firstWrite = await journal.nextParked();
  const secondRead = bodyConsumed(server, "/evidence/payee", 1);
  const second = put(evidenceUrl, evidenceTriple("second"));
  await secondRead;
  journal.open();
  await firstWrite.release();
  assert.deepEqual((await Promise.all([first, second])).map((r) => r.status), [200, 200]);

  const live = await get(evidenceUrl);
  await close();
  const restarted = await startRelay(t, { stateDir });
  const replayed = await get(`${restarted.baseUrl}/v1/sessions/${sessionId}/evidence/payee`);
  assert.deepEqual(replayed.body, live.body, "memory and journal must agree on the last write");
  assert.equal(live.body.json, evidenceTriple("second").json, "arrival order is preserved");
});

// --- monitor snapshot -----------------------------------------------------

test("snapshot PUT: not visible until journalled, and a failed append leaves the previous snapshot", async (t) => {
  const journal = controlledJournal();
  const { baseUrl } = await startRelay(t, { journal });
  const sessionId = await createSession(baseUrl);
  const snapshotUrl = `${baseUrl}/v1/sessions/${sessionId}/snapshot`;

  const kept = minimalSnapshot(sessionId, 1_700_000_000_000);
  const put1 = await put(snapshotUrl, kept);
  assert.equal(put1.status, 200, JSON.stringify(put1.body));

  journal.failNextAppend();
  const failed = await put(snapshotUrl, minimalSnapshot(sessionId, 1_700_000_001_000));
  assert.equal(failed.status, 500);
  assert.equal((await get(snapshotUrl)).body.updatedAtMs, kept.updatedAtMs);

  journal.hold();
  const pending = put(snapshotUrl, minimalSnapshot(sessionId, 1_700_000_002_000));
  const write = await journal.nextParked();
  assert.equal((await get(snapshotUrl)).body.updatedAtMs, kept.updatedAtMs, "not served before durable");
  journal.open();
  await write.release();
  assert.equal((await pending).status, 200);
  assert.equal((await get(snapshotUrl)).body.updatedAtMs, 1_700_000_002_000);
});

// --- closing certificate --------------------------------------------------

test("result PUT: not visible until journalled, and a failed append publishes nothing", async (t) => {
  const journal = controlledJournal();
  const { baseUrl, stateDir, close } = await startRelay(t, { journal });
  const sessionId = await createSession(baseUrl);
  const resultUrl = `${baseUrl}/v1/sessions/${sessionId}/result`;

  journal.failNextAppend();
  const failed = await put(resultUrl, signedResultFor(sessionId));
  assert.equal(failed.status, 500);
  const afterFailure = await get(resultUrl);
  assert.equal(afterFailure.status, 404);
  assert.equal(afterFailure.body.error, "RESULT_NOT_SET");

  const envelope = signedResultFor(sessionId);
  journal.hold();
  const pending = put(resultUrl, envelope);
  const write = await journal.nextParked();
  assert.equal((await get(resultUrl)).status, 404, "a certificate must not be served before it is durable");
  journal.open();
  await write.release();
  assert.equal((await pending).status, 200);
  const served = await get(resultUrl);
  assert.equal(served.status, 200);
  assert.deepEqual(served.body, JSON.parse(JSON.stringify(envelope)));

  await close();
  const restarted = await startRelay(t, { stateDir });
  assert.deepEqual((await get(`${restarted.baseUrl}/v1/sessions/${sessionId}/result`)).body, served.body);
});
