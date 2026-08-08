// The discovery document is the whole handover: one URL, no key, no token, no
// session id copied by hand. The relay that serves it is an untrusted mailbox, so
// every field is checked before it is used, and every refusal closes with a named
// public reason. These tests pin both directions.
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  BUSINESS_STAGE,
  DISCOVERY_SCHEMA,
  discoveryUrlFor,
  fetchDiscovery,
  readDiscovery,
} from "../src/roles/session.mjs";

const NOW = 1_760_000_000_000;
const THIRTY_MINUTES_MS = 30 * 60_000;

function validDocument(overrides = {}) {
  return {
    schema: DISCOVERY_SCHEMA,
    sessionId: "0a2f1e6c-7b4d-4a11-9d3e-2c5b8f0a1e77",
    relayUrl: "http://relay.invalid:8080",
    kitRepoUrl: "https://github.com/thetangstr/clockchain-handshake-v2.git",
    repositorySha: "b30049313d1688e7d32e0e12a0d34244ec4e8d4c",
    operatorPublicKey: "Zm9vYmFyMDEyMzQ1Njc4OWFiY2RlZg==",
    issuedAtMs: String(NOW),
    expiresAtMs: String(NOW + 45 * 60_000),
    paymentMoved: false,
    ...overrides,
  };
}

test("a well-formed invitation yields a relay url and a session id", () => {
  const result = readDiscovery(validDocument(), { now: NOW });
  assert.equal(result.ok, true);
  assert.equal(result.discovery.relayUrl, "http://relay.invalid:8080");
  assert.equal(result.discovery.sessionId, "0a2f1e6c-7b4d-4a11-9d3e-2c5b8f0a1e77");
  assert.equal(result.discovery.issuedAtMs, NOW);
  assert.equal(result.discovery.paymentMoved, false);
});

test("a trailing slash on the relay url does not produce a doubled path", () => {
  const result = readDiscovery(validDocument({ relayUrl: "http://relay.invalid:8080/" }), { now: NOW });
  assert.equal(result.ok, true);
  assert.equal(
    discoveryUrlFor({ relayUrl: result.discovery.relayUrl, sessionId: result.discovery.sessionId }),
    "http://relay.invalid:8080/v1/discovery/0a2f1e6c-7b4d-4a11-9d3e-2c5b8f0a1e77",
  );
});

test("audience-facing session copy names the host and checker, not the retired operator", () => {
  assert.match(BUSINESS_STAGE.FUNDED, /session host/i);
  assert.match(BUSINESS_STAGE.VERIFYING, /independent checker/i);
  assert.doesNotMatch(BUSINESS_STAGE.FUNDED, /operator/i);
  assert.doesNotMatch(BUSINESS_STAGE.VERIFYING, /verifier/i);
});

test("a missing discovery key is described as the session host key", () => {
  const result = readDiscovery(validDocument({ operatorPublicKey: "" }), { now: NOW });

  assert.equal(result.ok, false);
  assert.match(result.sentence, /session host key/i);
  assert.doesNotMatch(result.sentence, /payer key|operator key/i);
});

test("discoveryUrlFor is the address the relay actually serves", () => {
  assert.equal(
    discoveryUrlFor({ relayUrl: "http://relay.invalid:8080///", sessionId: "abc def" }),
    "http://relay.invalid:8080/v1/discovery/abc%20def",
  );
});

// Each of these is a way the one URL a stakeholder holds could be wrong, and each
// must close with MALFORMED rather than a stack trace or a half-joined session.
for (const [label, overrides] of [
  ["a foreign schema", { schema: "something-else/v1" }],
  ["a missing session id", { sessionId: undefined }],
  ["a session id the relay cannot address", { sessionId: "not/a/session" }],
  ["a relay url that is not a url", { relayUrl: "relay.invalid:8080" }],
  ["a relay url on a non-http scheme", { relayUrl: "file:///etc/passwd" }],
  ["a relay url smuggling a query string", { relayUrl: "http://relay.invalid:8080/?x=1" }],
  ["a kit repo url that is not a url", { kitRepoUrl: "github.com/thetangstr" }],
  ["an unreadable version pin", { repositorySha: "not-a-sha" }],
  ["an empty operator key", { operatorPublicKey: "" }],
  ["an undated invitation", { issuedAtMs: "later" }],
  ["a non-numeric expiry", { expiresAtMs: {} }],
  ["a window too short for a person", { expiresAtMs: String(NOW + THIRTY_MINUTES_MS - 1) }],
  ["a dropped no-money-moves guarantee", { paymentMoved: true }],
]) {
  test(`${label} closes MALFORMED`, () => {
    const result = readDiscovery(validDocument(overrides), { now: NOW });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "MALFORMED");
    assert.ok(result.sentence.length > 0);
    assert.ok(!/Error|at \w+ \(/.test(result.sentence), "no stack trace reaches a stakeholder");
  });
}

for (const [label, document] of [
  ["a JSON array", []],
  ["a bare string", "nope"],
  ["null", null],
]) {
  test(`${label} instead of an invitation closes MALFORMED`, () => {
    const result = readDiscovery(document, { now: NOW });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "MALFORMED");
  });
}

test("an invitation whose window has already closed says EXPIRED, not MALFORMED", () => {
  const document = validDocument();
  const result = readDiscovery(document, { now: Number(document.expiresAtMs) });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "EXPIRED");
});

test("fetchDiscovery refuses something that is not a link at all", async () => {
  const result = await fetchDiscovery({ discoveryUrl: "paste the link here" });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "MALFORMED");
});

test("fetchDiscovery reads the invitation the relay serves", async () => {
  const seen = [];
  const result = await fetchDiscovery({
    discoveryUrl: "http://relay.invalid:8080/v1/discovery/s1",
    fetchImpl: async (url) => {
      seen.push(url);
      return { ok: true, json: async () => validDocument() };
    },
    now: () => NOW,
  });
  assert.equal(result.ok, true);
  assert.deepEqual(seen, ["http://relay.invalid:8080/v1/discovery/s1"]);
});

test("fetchDiscovery retries a link that is not answering yet, then succeeds", async () => {
  const beats = [];
  let call = 0;
  let clock = NOW;
  const result = await fetchDiscovery({
    discoveryUrl: "http://relay.invalid:8080/v1/discovery/s1",
    fetchImpl: async () => {
      call += 1;
      if (call === 1) throw new Error("connection refused");
      if (call === 2) return { ok: false, status: 404 };
      return { ok: true, json: async () => validDocument() };
    },
    now: () => clock,
    onHeartbeat: (attempt) => beats.push(attempt),
    sleep: async (ms) => {
      clock += ms;
    },
  });
  assert.equal(result.ok, true);
  assert.equal(call, 3);
  assert.deepEqual(beats, [1, 2], "a watching audience sees a heartbeat per attempt");
});

test("fetchDiscovery gives up on a dead link with RENDEZVOUS_UNAVAILABLE", async () => {
  let clock = NOW;
  const result = await fetchDiscovery({
    budgetMs: 20_000,
    discoveryUrl: "http://relay.invalid:8080/v1/discovery/s1",
    fetchImpl: async () => {
      throw new Error("connection refused");
    },
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "RENDEZVOUS_UNAVAILABLE");
  assert.ok(!/connection refused/.test(result.sentence), "the transport error stays internal");
});

test("fetchDiscovery closes MALFORMED when the link answers with something unreadable", async () => {
  const result = await fetchDiscovery({
    discoveryUrl: "http://relay.invalid:8080/v1/discovery/s1",
    fetchImpl: async () => ({
      ok: true,
      json: async () => {
        throw new Error("Unexpected token < in JSON");
      },
    }),
    now: () => NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "MALFORMED");
});
