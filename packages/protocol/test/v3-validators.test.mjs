import assert from "node:assert/strict";
import test from "node:test";

import {
  validateHandshakeV3CallbackEvent,
  validateHandshakeV3FailureReceipt,
  validateHandshakeV3Party,
  validateHandshakeV3Policy,
  validateHandshakeV3Receipt,
  validateHandshakeV3Session,
} from "@clockchain/handshake-protocol/v3";

test("policy, party, receipt, callback, and session validators freeze strict records", () => {
  assert.equal(Object.isFrozen(validateHandshakeV3Policy({
    policyId: "policy_a",
    scope: "scope:demo",
    expiresAt: "2026-08-29T21:00:00Z",
    statementDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    policyDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  })), true);

  assert.equal(validateHandshakeV3Party({
    role: "INITIATOR",
    partyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    principalDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    signingKeyId: "agent-a-key",
    proofKeyThumbprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  }).signingKeyId, "agent-a-key");

  assert.equal(validateHandshakeV3Receipt({
    requestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    stateVersion: 2,
    eventDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    recordedAt: "2026-08-29T20:00:00Z",
    mutated: true,
  }).mutated, true);

  assert.equal(validateHandshakeV3FailureReceipt({
    requestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    stateVersion: 2,
    recordedAt: "2026-08-29T20:00:00Z",
    mutated: false,
  }).mutated, false);

  assert.equal(validateHandshakeV3CallbackEvent({
    eventId: "event_a",
    sessionId: "sess_a",
    eventType: "CERTIFICATE_ISSUED",
    eventDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    stateVersion: 8,
    occurredAt: "2026-08-29T20:00:00Z",
  }).eventType, "CERTIFICATE_ISSUED");

  assert.equal(validateHandshakeV3Session({
    sessionId: "sess_a",
    state: "CERTIFICATE_ISSUED",
    stateVersion: 8,
    tenantDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    createdAt: "2026-08-29T19:00:00Z",
    expiresAt: "2026-08-29T21:00:00Z",
  }).state, "CERTIFICATE_ISSUED");
});

test("validators reject unknown, business-shaped, accessor, and proxy records", () => {
  assert.throws(() => validateHandshakeV3Receipt({
    requestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    stateVersion: 2,
    recordedAt: "2026-08-29T20:00:00Z",
    mutated: true,
    businessContent: "forbidden",
  }), { code: "SCHEMA_INVALID" });

  const accessor = {};
  Object.defineProperty(accessor, "requestDigest", { enumerable: true, get() { return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; } });
  Object.assign(accessor, {
    stateVersion: 2,
    recordedAt: "2026-08-29T20:00:00Z",
    mutated: true,
  });
  assert.throws(() => validateHandshakeV3Receipt(accessor), { code: "SCHEMA_INVALID" });

  const proxy = new Proxy({
    requestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    stateVersion: 2,
    recordedAt: "2026-08-29T20:00:00Z",
    mutated: true,
  }, {
    getOwnPropertyDescriptor() {
      throw new Error("proxy trap must not escape");
    },
  });
  assert.throws(() => validateHandshakeV3Receipt(proxy), { code: "SCHEMA_INVALID" });
});
