// Client-side behaviour of the rendezvous relay: retry/backoff over network
// failure, envelope signing/verification, and the named-reason mappings the
// shared contract calls out explicitly (RENDEZVOUS_UNAVAILABLE, RATE_BLOCKED,
// ROLE_ALREADY_BOUND).
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createRelayServer } from "../src/relay/server.mjs";
import {
  RelayError,
  claimRole,
  createSession,
  generateEnvelopeKeyPair,
  getEvidence,
  health,
  pollMessages,
  postMessage,
  putEvidence,
  signEnvelope,
  verifyEnvelope,
} from "../src/relay/client.mjs";

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), "handshake-relay-client-"));
  t.after(async () => {
    await rm(directory, { force: true, recursive: true });
  });
  return directory;
}

async function listen(server, port = 0) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  return server.address().port;
}

async function startServer(t) {
  const dir = await temporaryDirectory(t);
  const server = await createRelayServer({ stateDir: dir });
  const port = await listen(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { server, relayUrl: `http://127.0.0.1:${port}` };
}

// Grabs a genuinely free ephemeral port and immediately releases it, so a
// connection to it fails fast with ECONNREFUSED (nothing is listening)
// rather than colliding with another test's server.
async function freePort() {
  const probe = createServer(() => {});
  const port = await listen(probe);
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

const instantSleeper = () => Promise.resolve();

test("a connection refused at first is retried and then succeeds once the relay starts", async (t) => {
  const port = await freePort();
  const relayUrl = `http://127.0.0.1:${port}`;
  const heartbeats = [];

  const healthPromise = health({
    relayUrl,
    retryBudgetMs: 60_000,
    sleeper: instantSleeper,
    onHeartbeat: (info) => heartbeats.push(info),
  });

  // Give the client a moment to hammer the refused port a few times before
  // the relay comes up -- this is the staggered-startup case the previous
  // build died to.
  await new Promise((resolve) => setTimeout(resolve, 20));

  const dir = await temporaryDirectory(t);
  const server = await createRelayServer({ stateDir: dir });
  await listen(server, port);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const result = await healthPromise;
  assert.equal(result.ok, true);
  assert.equal(result.paymentMoved, false);
});

test("exhausting the retry budget against an unreachable relay closes with RENDEZVOUS_UNAVAILABLE", async (t) => {
  const port = await freePort();
  let fakeNow = 0;

  await assert.rejects(
    () =>
      health({
        relayUrl: `http://127.0.0.1:${port}`,
        retryBudgetMs: 3_000,
        sleeper: instantSleeper,
        monotonicNow: () => {
          fakeNow += 1_000;
          return fakeNow;
        },
      }),
    (error) => error instanceof RelayError && error.code === "RENDEZVOUS_UNAVAILABLE",
  );
});

test("an HTTP 429 maps to RATE_BLOCKED", async (t) => {
  const stub = createServer((req, res) => {
    res.writeHead(429, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "TOO_MANY_REQUESTS" }));
  });
  const port = await listen(stub);
  t.after(() => new Promise((resolve) => stub.close(resolve)));

  await assert.rejects(
    () => health({ relayUrl: `http://127.0.0.1:${port}` }),
    (error) => error instanceof RelayError && error.code === "RATE_BLOCKED",
  );
});

test("postMessage and pollMessages resume from seq via the client, and every envelope verifies", async (t) => {
  const { relayUrl } = await startServer(t);
  const created = await createSession({ relayUrl });
  const sessionId = created.sessionId;
  const keys = generateEnvelopeKeyPair();

  const envelope1 = signEnvelope({
    sessionId,
    seq: "1",
    role: "payer",
    kind: "status",
    body: { note: "hello" },
    senderKey: keys.senderKey,
    privateKeyPem: keys.privateKeyPem,
  });
  await postMessage({ relayUrl, sessionId, envelope: envelope1 });

  const envelope2 = signEnvelope({
    sessionId,
    seq: "2",
    role: "payer",
    kind: "status",
    body: { note: "world" },
    senderKey: keys.senderKey,
    privateKeyPem: keys.privateKeyPem,
  });
  await postMessage({ relayUrl, sessionId, envelope: envelope2 });

  const all = await pollMessages({ relayUrl, sessionId, after: 0, waitMs: 0 });
  assert.equal(all.messages.length, 2);
  for (const message of all.messages) {
    assert.equal(verifyEnvelope(message), true);
  }

  const onlyNewest = await pollMessages({
    relayUrl,
    sessionId,
    after: 1,
    waitMs: 0,
  });
  assert.equal(onlyNewest.messages.length, 1);
  assert.equal(onlyNewest.messages[0].body.note, "world");
});

test("putEvidence and getEvidence round-trip through the client", async (t) => {
  const { relayUrl } = await startServer(t);
  const created = await createSession({ relayUrl });
  const sessionId = created.sessionId;

  await putEvidence({
    relayUrl,
    sessionId,
    role: "payer",
    json: Buffer.from(JSON.stringify({ a: 1 })),
    markdown: "# hi",
    marker: Buffer.from(JSON.stringify({ m: true })),
  });

  const fetched = await getEvidence({ relayUrl, sessionId, role: "payer" });
  assert.deepEqual(JSON.parse(fetched.json.toString("utf8")), { a: 1 });
  assert.equal(fetched.markdown.toString("utf8"), "# hi");
  assert.deepEqual(JSON.parse(fetched.marker.toString("utf8")), { m: true });
});

test("verifyEnvelope accepts a validly signed envelope and rejects a tampered one", () => {
  const keys = generateEnvelopeKeyPair();
  const envelope = signEnvelope({
    sessionId: "session-abc",
    seq: "1",
    role: "payer",
    kind: "status",
    body: { note: "ok" },
    senderKey: keys.senderKey,
    privateKeyPem: keys.privateKeyPem,
  });
  assert.equal(verifyEnvelope(envelope), true);

  const tampered = { ...envelope, body: { note: "tampered" } };
  assert.throws(
    () => verifyEnvelope(tampered),
    (error) => error instanceof RelayError && error.code === "ENVELOPE_SIGNATURE",
  );
});

test("claimRole refuses a role that is already bound with ROLE_ALREADY_BOUND", async (t) => {
  const { relayUrl } = await startServer(t);
  const created = await createSession({ relayUrl });
  const sessionId = created.sessionId;
  const keysA = generateEnvelopeKeyPair();
  const keysB = generateEnvelopeKeyPair();

  await claimRole({
    relayUrl,
    sessionId,
    role: "payer",
    senderKey: keysA.senderKey,
    privateKeyPem: keysA.privateKeyPem,
  });

  await assert.rejects(
    () =>
      claimRole({
        relayUrl,
        sessionId,
        role: "payer",
        senderKey: keysB.senderKey,
        privateKeyPem: keysB.privateKeyPem,
      }),
    (error) => error instanceof RelayError && error.code === "ROLE_ALREADY_BOUND",
  );
});
