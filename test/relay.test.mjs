// Server-side behaviour of the rendezvous relay. These tests talk raw HTTP
// (fetch) to the relay so the server's own validation is exercised directly,
// independent of the client half's retry/signing logic (see
// test/relay-client.test.mjs for that).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { EVIDENCE_PART_LIMITS, createRelayServer } from "../src/relay/server.mjs";
import { RelayError, verifyEnvelope } from "../src/relay/client.mjs";

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), "handshake-relay-"));
  t.after(async () => {
    await rm(directory, { force: true, recursive: true });
  });
  return directory;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server.address().port;
}

async function startServer(t, stateDir) {
  const dir = stateDir ?? (await temporaryDirectory(t));
  const server = await createRelayServer({ stateDir: dir });
  const port = await listen(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { server, baseUrl: `http://127.0.0.1:${port}`, stateDir: dir };
}

function randomBase64(byteLength) {
  return randomBytes(byteLength).toString("base64");
}

function rawEnvelope({
  sessionId,
  seq,
  role = "payer",
  kind = "status",
  body = { note: "hi" },
}) {
  return {
    sessionId,
    seq,
    role,
    kind,
    body,
    senderKey: randomBase64(32),
    sig: randomBase64(64),
  };
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function putJson(url, body) {
  const response = await fetch(url, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function getJson(url) {
  const response = await fetch(url);
  return { status: response.status, body: await response.json() };
}

test("session round trip: post then poll returns it; poll with after=N returns only newer", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  assert.equal(created.status, 201);
  const sessionId = created.body.sessionId;

  const first = await postJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages`,
    rawEnvelope({ sessionId, seq: "1" }),
  );
  assert.equal(first.status, 201);
  const second = await postJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages`,
    rawEnvelope({ sessionId, seq: "2", kind: "mandate" }),
  );
  assert.equal(second.status, 201);

  const all = await getJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages?after=0&waitMs=0`,
  );
  assert.equal(all.status, 200);
  assert.deepEqual(
    all.body.messages.map((m) => m.seq),
    ["1", "2"],
  );

  const onlyNewer = await getJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages?after=1&waitMs=0`,
  );
  assert.equal(onlyNewer.body.messages.length, 1);
  assert.equal(onlyNewer.body.messages[0].kind, "mandate");
});

test("long-poll returns promptly when a message arrives, and returns empty at timeout", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const timeoutStart = Date.now();
  const emptyPoll = await getJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages?after=0&waitMs=50`,
  );
  const timeoutElapsed = Date.now() - timeoutStart;
  assert.equal(emptyPoll.body.messages.length, 0);
  assert.ok(
    timeoutElapsed >= 30,
    "an empty long-poll should not resolve before its wait elapses",
  );

  const pollStart = Date.now();
  const pollPromise = getJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages?after=0&waitMs=5000`,
  );
  setTimeout(() => {
    postJson(
      `${baseUrl}/v1/sessions/${sessionId}/messages`,
      rawEnvelope({ sessionId, seq: "1" }),
    ).catch(() => {});
  }, 20);
  const arrived = await pollPromise;
  const elapsed = Date.now() - pollStart;
  assert.equal(arrived.body.messages.length, 1);
  assert.ok(
    elapsed < 2000,
    "a long-poll should return as soon as a message lands, not wait out the full budget",
  );
});

test("journal restart: prior messages are readable and seq continues after reconstruction", async (t) => {
  const dir = await temporaryDirectory(t);
  let server = await createRelayServer({ stateDir: dir });
  let port = await listen(server);
  let baseUrl = `http://127.0.0.1:${port}`;

  const created = await postJson(`${baseUrl}/v1/sessions`, {
    sessionId: "restart-session",
  });
  assert.equal(created.status, 201);
  await postJson(
    `${baseUrl}/v1/sessions/restart-session/messages`,
    rawEnvelope({ sessionId: "restart-session", seq: "1" }),
  );

  await new Promise((resolve) => server.close(resolve));

  server = await createRelayServer({ stateDir: dir });
  port = await listen(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  baseUrl = `http://127.0.0.1:${port}`;

  const replayed = await getJson(
    `${baseUrl}/v1/sessions/restart-session/messages?after=0&waitMs=0`,
  );
  assert.equal(replayed.body.messages.length, 1);
  assert.equal(replayed.body.messages[0].seq, "1");

  const next = await postJson(
    `${baseUrl}/v1/sessions/restart-session/messages`,
    rawEnvelope({ sessionId: "restart-session", seq: "2" }),
  );
  assert.equal(next.status, 201);
  assert.equal(next.body.seq, "2");
});

test("oversize message body is refused with a named reason", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const oversized = rawEnvelope({
    sessionId,
    seq: "1",
    body: { note: "x".repeat(300_000) },
  });
  const response = await postJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages`,
    oversized,
  );
  assert.equal(response.status, 413);
  assert.equal(response.body.error, "BODY_TOO_LARGE");
});

test("oversize evidence part is refused with a named reason", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const oversizeMarkdown = Buffer.alloc(EVIDENCE_PART_LIMITS.markdown + 1, "a");
  const response = await putJson(
    `${baseUrl}/v1/sessions/${sessionId}/evidence/payer`,
    {
      json: Buffer.from("{}").toString("base64"),
      markdown: oversizeMarkdown.toString("base64"),
      marker: Buffer.from("{}").toString("base64"),
    },
  );
  assert.equal(response.status, 413);
  assert.equal(response.body.error, "EVIDENCE_TOO_LARGE");
});

test("a maximal VALID evidence triple is accepted", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const json = Buffer.alloc(EVIDENCE_PART_LIMITS.json, "j");
  const markdown = Buffer.alloc(EVIDENCE_PART_LIMITS.markdown, "m");
  const marker = Buffer.alloc(EVIDENCE_PART_LIMITS.marker, "k");

  const putResponse = await putJson(
    `${baseUrl}/v1/sessions/${sessionId}/evidence/payer`,
    {
      json: json.toString("base64"),
      markdown: markdown.toString("base64"),
      marker: marker.toString("base64"),
    },
  );
  assert.equal(putResponse.status, 200);

  const getResponse = await getJson(
    `${baseUrl}/v1/sessions/${sessionId}/evidence/payer`,
  );
  assert.equal(getResponse.status, 200);
  assert.equal(
    Buffer.from(getResponse.body.json, "base64").byteLength,
    EVIDENCE_PART_LIMITS.json,
  );
  assert.equal(
    Buffer.from(getResponse.body.markdown, "base64").byteLength,
    EVIDENCE_PART_LIMITS.markdown,
  );
  assert.equal(
    Buffer.from(getResponse.body.marker, "base64").byteLength,
    EVIDENCE_PART_LIMITS.marker,
  );
});

test("the relay does not reject a message with a garbage signature; the client's verify function does", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const garbage = rawEnvelope({ sessionId, seq: "1" });
  const response = await postJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages`,
    garbage,
  );
  assert.equal(response.status, 201, "the relay must not validate signatures");

  assert.throws(
    () => verifyEnvelope(garbage),
    (error) => error instanceof RelayError && error.code.startsWith("ENVELOPE_"),
  );
});

test("unknown session, unknown role, and bad seq ordering fail with distinct named reasons", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;

  const unknownSession = await postJson(
    `${baseUrl}/v1/sessions/does-not-exist/messages`,
    rawEnvelope({ sessionId: "does-not-exist", seq: "1" }),
  );
  assert.equal(unknownSession.status, 404);
  assert.equal(unknownSession.body.error, "UNKNOWN_SESSION");

  const unknownRole = await getJson(
    `${baseUrl}/v1/sessions/${sessionId}/evidence/notarole`,
  );
  assert.equal(unknownRole.status, 400);
  assert.equal(unknownRole.body.error, "UNKNOWN_ROLE");

  const badSeq = await postJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages`,
    rawEnvelope({ sessionId, seq: "5" }),
  );
  assert.equal(badSeq.status, 409);
  assert.equal(badSeq.body.error, "SEQ_CONFLICT");

  const codes = new Set([
    unknownSession.body.error,
    unknownRole.body.error,
    badSeq.body.error,
  ]);
  assert.equal(codes.size, 3, "each failure must carry a distinct named reason");
});

test("healthz reports paymentMoved:false and the current session count", async (t) => {
  const { baseUrl } = await startServer(t);
  const before = await getJson(`${baseUrl}/healthz`);
  assert.equal(before.body.ok, true);
  assert.equal(before.body.paymentMoved, false);
  assert.equal(before.body.sessions, 0);

  await postJson(`${baseUrl}/v1/sessions`, {});
  const after = await getJson(`${baseUrl}/healthz`);
  assert.equal(after.body.sessions, 1);
});

test("discovery: unset session returns a named reason, set discovery round-trips verbatim", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const noDiscoverySessionId = created.body.sessionId;

  const notSet = await getJson(`${baseUrl}/v1/discovery/${noDiscoverySessionId}`);
  assert.equal(notSet.status, 404);
  assert.equal(notSet.body.error, "DISCOVERY_NOT_SET");

  const discovery = { schema: "handshake-discovery/v2", issuedAtMs: 1 };
  const withDiscovery = await postJson(`${baseUrl}/v1/sessions`, { discovery });
  const discoverySessionId = withDiscovery.body.sessionId;

  const fetched = await getJson(`${baseUrl}/v1/discovery/${discoverySessionId}`);
  assert.equal(fetched.status, 200);
  assert.deepEqual(fetched.body, discovery);

  const unknown = await getJson(`${baseUrl}/v1/discovery/does-not-exist`);
  assert.equal(unknown.status, 404);
  assert.equal(unknown.body.error, "UNKNOWN_SESSION");
});

// One alias serves the invitation link and the projector link, so a demo hands
// out URLs that never change. Both endpoints must resolve it, and to the same
// run -- a monitor pointing at a different session than the stakeholder was sent
// would narrate the wrong handshake to an audience.
test("current: discovery and snapshot both resolve the alias, to the newest published session", async (t) => {
  const { baseUrl } = await startServer(t);

  const empty = await getJson(`${baseUrl}/v1/discovery/current`);
  assert.equal(empty.status, 404);
  assert.equal(empty.body.error, "DISCOVERY_NOT_SET");
  const emptySnapshot = await getJson(`${baseUrl}/v1/sessions/current/snapshot`);
  assert.equal(emptySnapshot.status, 404);
  assert.equal(emptySnapshot.body.error, "UNKNOWN_SESSION");

  // A session with no discovery must never win the alias, however recent.
  await postJson(`${baseUrl}/v1/sessions`, {});

  const older = { schema: "handshake-discovery/v2", issuedAtMs: 1 };
  const olderSession = await postJson(`${baseUrl}/v1/sessions`, { discovery: older });
  const newer = { schema: "handshake-discovery/v2", issuedAtMs: 2 };
  const newerSession = await postJson(`${baseUrl}/v1/sessions`, { discovery: newer });

  const resolved = await getJson(`${baseUrl}/v1/discovery/current`);
  assert.equal(resolved.status, 200);
  assert.deepEqual(resolved.body, newer, "the alias must follow the newest published session");

  const snapshot = await getJson(`${baseUrl}/v1/sessions/current/snapshot`);
  assert.equal(snapshot.status, 200);
  assert.equal(
    snapshot.body.sessionId,
    newerSession.body.sessionId,
    "the monitor must land on the same run the invitation points at",
  );
  assert.notEqual(snapshot.body.sessionId, olderSession.body.sessionId);
  assert.equal(snapshot.body.paymentMoved, false);
});

test("snapshot summarizes message and evidence bookkeeping without inventing authority", async (t) => {
  const { baseUrl } = await startServer(t);
  const created = await postJson(`${baseUrl}/v1/sessions`, {});
  const sessionId = created.body.sessionId;
  await postJson(
    `${baseUrl}/v1/sessions/${sessionId}/messages`,
    rawEnvelope({ sessionId, seq: "1", role: "payer", kind: "role_claim" }),
  );
  await putJson(`${baseUrl}/v1/sessions/${sessionId}/evidence/payer`, {
    json: Buffer.from("{}").toString("base64"),
    markdown: Buffer.from("#").toString("base64"),
    marker: Buffer.from("{}").toString("base64"),
  });

  const snapshot = await getJson(`${baseUrl}/v1/sessions/${sessionId}/snapshot`);
  assert.equal(snapshot.status, 200);
  assert.equal(snapshot.body.paymentMoved, false);
  assert.equal(snapshot.body.lastSeq, "1");
  assert.equal(snapshot.body.messageCount, 1);
  assert.deepEqual(snapshot.body.evidence, { payer: true, payee: false });
});
