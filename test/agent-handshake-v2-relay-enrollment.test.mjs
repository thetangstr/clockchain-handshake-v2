// H-REQ-01: coordinator-signed sender enrollments bind each relay role to one
// sender key. These tests cover the enrollment module on its own; the relay
// server and the host consume it in relay-enrollment.test.mjs and
// agent-handshake-v2-relay-binding.test.mjs.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AGENT_HANDSHAKE_V2_RELAY_AUTHORIZATION_SCHEMA,
  AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND,
  createRelayAuthorization,
  createSenderBindings,
  senderEnrollmentDigest,
  signSenderEnrollment,
  validateCoordinatorKeyRing,
  validateRelayAuthorization,
  verifySenderEnrollment,
  verifySenderEnrollmentBinding,
} from "../src/agent-handshake/v2/relay-enrollment.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { SESSION_ID } from "./support/agent-handshake-v2-fixture.mjs";
import {
  CLAIM_EXPIRES_AT_MS,
  COORDINATOR,
  COORDINATOR_KEY_RING,
  DEADLINE_MS,
  enrollmentEnvelope,
  enrollmentFor,
  envelopeFrom,
  INVITATION_DIGEST,
  keyRingEntry,
  MINTED_AT_MS,
  OTHER_COORDINATOR,
  REDEEMED_AT_MS,
  SENDERS,
  signedEnrollment,
  STATEMENT_DIGEST,
} from "./support/sender-enrollment-fixture.mjs";

const NOW_MS = REDEEMED_AT_MS + 1_000;
const OTHER_SESSION_ID = "33333333-4444-4555-8666-777777777777";

function expectations(role, overrides = {}) {
  return {
    coordinatorKeyRing: COORDINATOR_KEY_RING,
    expectedRole: role,
    expectedSenderKey: SENDERS[role].publicKey,
    expectedSessionDeadlineMs: DEADLINE_MS,
    expectedSessionId: SESSION_ID,
    expectedStatementDigest: STATEMENT_DIGEST,
    nowMs: NOW_MS,
    ...overrides,
  };
}

function refused(fn) {
  assert.throws(fn, (error) => error?.code === "AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_INVALID");
}

test("H-REQ-01: a coordinator enrollment verifies for each role", () => {
  for (const role of ["initiator", "responder"]) {
    const body = signedEnrollment(role);
    const verified = verifySenderEnrollment(body, expectations(role));
    assert.equal(verified.enrollment.role, role);
    assert.equal(verified.enrollment.senderKey, SENDERS[role].publicKey);
    assert.equal(verified.enrollment.event, role === "initiator" ? "minted" : "redeemed");
    assert.equal(verified.keyId, COORDINATOR.keyId);
    assert.equal(verified.digest, senderEnrollmentDigest(body.enrollment));
    assert.deepEqual(Object.keys(body).sort(), ["coordinatorSignature", "enrollment", "externalBusinessActionPerformed"]);
    assert.equal(body.externalBusinessActionPerformed, false);
    assert.deepEqual(Object.keys(body.coordinatorSignature).sort(), ["algorithm", "keyId", "signature"]);
  }
});

test("H-REQ-01: an enrollment signed by a key outside the coordinator key ring is refused", () => {
  // Names the ring's keyId but is signed by another key.
  refused(() => verifySenderEnrollment(
    signedEnrollment("initiator", {}, { signer: OTHER_COORDINATOR, keyId: COORDINATOR.keyId }),
    expectations("initiator"),
  ));
  // Names a keyId the ring does not hold.
  refused(() => verifySenderEnrollment(
    signedEnrollment("initiator", {}, { signer: OTHER_COORDINATOR }),
    expectations("initiator"),
  ));
  // A ring that does hold the other key accepts it, so the refusal above is
  // about the ring, not about the key.
  verifySenderEnrollment(
    signedEnrollment("initiator", {}, { signer: OTHER_COORDINATOR }),
    expectations("initiator", {
      coordinatorKeyRing: [keyRingEntry(COORDINATOR), keyRingEntry(OTHER_COORDINATOR)],
    }),
  );
});

test("H-REQ-01: an enrollment bound to another session, role or sender key is refused", () => {
  refused(() => verifySenderEnrollment(
    signedEnrollment("initiator", { sessionId: OTHER_SESSION_ID }),
    expectations("initiator"),
  ));
  refused(() => verifySenderEnrollment(signedEnrollment("initiator"), expectations("responder", {
    expectedSenderKey: SENDERS.initiator.publicKey,
  })));
  refused(() => verifySenderEnrollment(signedEnrollment("initiator"), expectations("initiator", {
    expectedSenderKey: SENDERS.unenrolled.publicKey,
  })));
  // A role is enrolled only at its own event: the initiator at the mint, the
  // responder at the redemption.
  refused(() => verifySenderEnrollment(
    signedEnrollment("initiator", { event: "redeemed" }),
    expectations("initiator"),
  ));
  refused(() => verifySenderEnrollment(
    signedEnrollment("responder", { event: "minted" }),
    expectations("responder"),
  ));
  refused(() => verifySenderEnrollment(
    signedEnrollment("host", { senderKey: SENDERS.host.publicKey }),
    expectations("host", { expectedSenderKey: SENDERS.host.publicKey }),
  ));
});

test("H-REQ-01: a stale or future-dated enrollment is refused", () => {
  refused(() => verifySenderEnrollment(signedEnrollment("initiator"), expectations("initiator", {
    nowMs: DEADLINE_MS,
  })));
  refused(() => verifySenderEnrollment(signedEnrollment("initiator"), expectations("initiator", {
    nowMs: MINTED_AT_MS - 120_000,
  })));
  refused(() => verifySenderEnrollment(
    signedEnrollment("initiator", { issuedAtMs: String(MINTED_AT_MS - 1) }),
    expectations("initiator"),
  ));
  refused(() => verifySenderEnrollment(
    signedEnrollment("initiator", { issuedAtMs: String(DEADLINE_MS) }),
    expectations("initiator", { nowMs: DEADLINE_MS - 1 }),
  ));
  refused(() => verifySenderEnrollment(
    signedEnrollment("initiator", { claimExpiresAtMs: String(MINTED_AT_MS) }),
    expectations("initiator"),
  ));
});

test("H-REQ-01: an enrollment for another deadline or statement is refused", () => {
  refused(() => verifySenderEnrollment(signedEnrollment("initiator"), expectations("initiator", {
    expectedSessionDeadlineMs: DEADLINE_MS + 1,
  })));
  refused(() => verifySenderEnrollment(signedEnrollment("initiator"), expectations("initiator", {
    expectedStatementDigest: "f".repeat(64),
  })));
  // The relay-grade check binds session, role and key but does not know the
  // terms; the host-grade check above is the one that holds the statement.
  verifySenderEnrollmentBinding(signedEnrollment("initiator", { statementDigest: "f".repeat(64) }), {
    coordinatorKeyRing: COORDINATOR_KEY_RING,
    expectedRole: "initiator",
    expectedSenderKey: SENDERS.initiator.publicKey,
    expectedSessionId: SESSION_ID,
    nowMs: NOW_MS,
  });
});

test("H-REQ-01: an enrollment is accepted only with the bytes the coordinator signed, in its exact shape, and with no business action", () => {
  const body = signedEnrollment("initiator");
  refused(() => verifySenderEnrollment({
    ...body,
    enrollment: { ...body.enrollment, claimExpiresAtMs: String(CLAIM_EXPIRES_AT_MS + 60_000) },
  }, expectations("initiator")));
  refused(() => verifySenderEnrollment({ ...body, extra: true }, expectations("initiator")));
  refused(() => verifySenderEnrollment({ ...body, externalBusinessActionPerformed: true }, expectations("initiator")));
  refused(() => verifySenderEnrollment(
    signedEnrollment("initiator", { externalBusinessActionPerformed: true }),
    expectations("initiator"),
  ));
  refused(() => verifySenderEnrollment(
    { ...body, coordinatorSignature: { ...body.coordinatorSignature, algorithm: "eip191" } },
    expectations("initiator"),
  ));
  refused(() => verifySenderEnrollment(null, expectations("initiator")));
  refused(() => verifySenderEnrollment(body, expectations("initiator", { nowMs: undefined })));
});

test("H-REQ-01: the coordinator key ring is validated like the host root ring", () => {
  assert.deepEqual(validateCoordinatorKeyRing(COORDINATOR_KEY_RING), COORDINATOR_KEY_RING);
  refused(() => validateCoordinatorKeyRing([]));
  refused(() => validateCoordinatorKeyRing("not a ring"));
  refused(() => validateCoordinatorKeyRing([{ ...COORDINATOR_KEY_RING[0], fingerprint: "0".repeat(64) }]));
  refused(() => validateCoordinatorKeyRing([COORDINATOR_KEY_RING[0], COORDINATOR_KEY_RING[0]]));
  refused(() => validateCoordinatorKeyRing([{ ...COORDINATOR_KEY_RING[0], extra: "x" }]));
  refused(() => validateCoordinatorKeyRing([
    keyRingEntry(COORDINATOR),
    keyRingEntry(OTHER_COORDINATOR),
    keyRingEntry(SENDERS.unenrolled),
  ]));
});

test("H-REQ-01: the relay authorization names the coordinator ring and the host sender key", () => {
  const authorization = createRelayAuthorization({
    coordinatorKeyRing: COORDINATOR_KEY_RING,
    hostSenderKey: SENDERS.host.publicKey,
  });
  assert.deepEqual(authorization, {
    schema: AGENT_HANDSHAKE_V2_RELAY_AUTHORIZATION_SCHEMA,
    coordinatorKeys: COORDINATOR_KEY_RING,
    hostSenderKey: SENDERS.host.publicKey,
  });
  assert.deepEqual(validateRelayAuthorization(JSON.parse(JSON.stringify(authorization))), authorization);
  refused(() => validateRelayAuthorization({ ...authorization, schema: "other" }));
  refused(() => validateRelayAuthorization({ ...authorization, hostSenderKey: "short" }));
  refused(() => validateRelayAuthorization({ ...authorization, extra: 1 }));
  refused(() => validateRelayAuthorization({ ...authorization, coordinatorKeys: [] }));
});

function bindingsAt(nowMs = NOW_MS) {
  return createSenderBindings({
    coordinatorKeyRing: COORDINATOR_KEY_RING,
    now: () => nowMs,
    sessionDeadlineMs: DEADLINE_MS,
    sessionId: SESSION_ID,
    statementDigest: STATEMENT_DIGEST,
  });
}

function roleMessage(seq, role, sender, kind = "agent_v2_identity_claim") {
  return envelopeFrom({ seq, role, kind, body: { note: "x" }, sender });
}

test("H-REQ-01: bindings admit only messages signed by the enrolled key for that role", () => {
  const bindings = bindingsAt();
  assert.equal(bindings.admits(roleMessage(1, "initiator", SENDERS.initiator)), false);
  const enrolled = enrollmentEnvelope({ seq: 2, role: "initiator", body: signedEnrollment("initiator") });
  assert.deepEqual(bindings.observe(enrolled), { status: "bound", role: "initiator" });
  assert.equal(bindings.admits(enrolled), true);
  assert.equal(bindings.admits(roleMessage(3, "initiator", SENDERS.initiator)), true);
  // Right role, wrong key; right key, wrong role; another session.
  assert.equal(bindings.admits(roleMessage(4, "initiator", SENDERS.unenrolled)), false);
  assert.equal(bindings.admits(roleMessage(5, "responder", SENDERS.initiator)), false);
  assert.equal(bindings.admits(envelopeFrom({
    sessionId: OTHER_SESSION_ID, seq: 6, role: "initiator", kind: "x", body: {}, sender: SENDERS.initiator,
  })), false);
  // A message that names the enrolled key but is signed by another key
  // signature is not admitted either.
  const otherSigner = { ...roleMessage(7, "initiator", SENDERS.unenrolled), senderKey: SENDERS.initiator.publicKey };
  assert.equal(bindings.admits(otherSigner), false);
  assert.equal(bindings.enrollment("initiator").senderKey, SENDERS.initiator.publicKey);
  assert.equal(bindings.enrollment("responder"), null);
  assert.deepEqual(bindings.invitation(), {
    claimExpiresAtMs: String(CLAIM_EXPIRES_AT_MS),
    invitationDigest: INVITATION_DIGEST,
    mintedAtMs: String(MINTED_AT_MS),
    redeemedAtMs: null,
  });
});

test("H-REQ-01: an enrollment that does not verify neither binds a role nor ends the bindings", () => {
  const bindings = bindingsAt();
  const outcomes = [
    // Signed by a key outside the coordinator key ring.
    enrollmentEnvelope({
      seq: 1,
      role: "initiator",
      sender: SENDERS.unenrolled,
      body: signedEnrollment("initiator", { senderKey: SENDERS.unenrolled.publicKey }, { signer: SENDERS.unenrolled }),
    }),
    // The valid body under another sender key.
    enrollmentEnvelope({ seq: 2, role: "initiator", sender: SENDERS.unenrolled, body: signedEnrollment("initiator") }),
    // A valid enrollment from another session.
    enrollmentEnvelope({
      seq: 3,
      role: "initiator",
      body: signedEnrollment("initiator", { sessionId: OTHER_SESSION_ID }),
    }),
  ].map((message) => bindings.observe(message));
  for (const outcome of outcomes) {
    assert.deepEqual(outcome, { status: "refused", role: "initiator", reason: "BINDING_MISMATCH", fatal: false });
  }
  assert.equal(bindings.failure(), null);
  assert.equal(bindings.enrollment("initiator"), null);
  assert.deepEqual(
    bindings.observe(enrollmentEnvelope({ seq: 4, role: "initiator", body: signedEnrollment("initiator") })),
    { status: "bound", role: "initiator" },
  );
});

test("H-REQ-01: a stale enrollment is not bound", () => {
  const bindings = bindingsAt(DEADLINE_MS);
  assert.equal(
    bindings.observe(enrollmentEnvelope({ seq: 1, role: "initiator", body: signedEnrollment("initiator") })).status,
    "refused",
  );
  assert.equal(bindings.enrollment("initiator"), null);
});

test("H-REQ-07: bindings judge an enrollment against a clock that never reads earlier than a previous read", () => {
  const clock = { value: DEADLINE_MS };
  const bindings = createSenderBindings({
    coordinatorKeyRing: COORDINATOR_KEY_RING,
    now: () => clock.value,
    sessionDeadlineMs: DEADLINE_MS,
    sessionId: SESSION_ID,
    statementDigest: STATEMENT_DIGEST,
  });
  const enrolled = enrollmentEnvelope({ seq: 1, role: "initiator", body: signedEnrollment("initiator") });
  const stale = { status: "refused", role: "initiator", reason: "BINDING_MISMATCH", fatal: false };
  assert.deepEqual(bindings.observe(enrolled), stale);
  // The clock now reads an earlier time; the enrollment is still stale.
  clock.value = NOW_MS;
  assert.deepEqual(bindings.observe(enrolled), stale);
  assert.equal(bindings.enrollment("initiator"), null);
  // A clock that only moves forward binds the same enrollment.
  assert.deepEqual(bindingsAt(NOW_MS).observe(enrolled), { status: "bound", role: "initiator" });
});

test("H-REQ-01: the same enrollment seen again is idempotent; a second different one fails closed", () => {
  const bindings = bindingsAt();
  const first = enrollmentEnvelope({ seq: 1, role: "initiator", body: signedEnrollment("initiator") });
  assert.equal(bindings.observe(first).status, "bound");
  assert.deepEqual(bindings.observe(first), { status: "unchanged", role: "initiator" });
  const second = enrollmentEnvelope({
    seq: 2,
    role: "initiator",
    sender: SENDERS.unenrolled,
    body: signedEnrollment("initiator", { senderKey: SENDERS.unenrolled.publicKey }),
  });
  assert.deepEqual(bindings.observe(second), {
    status: "refused", role: "initiator", reason: "ROLE_ALREADY_BOUND", fatal: true,
  });
  assert.equal(bindings.failure(), "ROLE_ALREADY_BOUND");
  assert.equal(bindings.admits(roleMessage(3, "initiator", SENDERS.initiator)), false);
});

test("H-REQ-01: both roles must enroll for the same invitation and claim expiry", () => {
  for (const overrides of [
    { invitationDigest: "e".repeat(64) },
    { claimExpiresAtMs: String(CLAIM_EXPIRES_AT_MS + 1) },
  ]) {
    const bindings = bindingsAt();
    assert.equal(bindings.observe(
      enrollmentEnvelope({ seq: 1, role: "initiator", body: signedEnrollment("initiator") }),
    ).status, "bound");
    assert.deepEqual(bindings.observe(
      enrollmentEnvelope({ seq: 2, role: "responder", body: signedEnrollment("responder", overrides) }),
    ), { status: "refused", role: "responder", reason: "BINDING_MISMATCH", fatal: true });
    assert.equal(bindings.failure(), "BINDING_MISMATCH");
  }
  // One key may not speak for both roles.
  const shared = bindingsAt();
  shared.observe(enrollmentEnvelope({ seq: 1, role: "initiator", body: signedEnrollment("initiator") }));
  assert.equal(shared.observe(enrollmentEnvelope({
    seq: 2,
    role: "responder",
    sender: SENDERS.initiator,
    body: signedEnrollment("responder", { senderKey: SENDERS.initiator.publicKey }),
  })).fatal, true);
  // The matching pair binds both roles and reports the redemption.
  const pair = bindingsAt();
  pair.observe(enrollmentEnvelope({ seq: 1, role: "initiator", body: signedEnrollment("initiator") }));
  assert.equal(pair.observe(
    enrollmentEnvelope({ seq: 2, role: "responder", body: signedEnrollment("responder") }),
  ).status, "bound");
  assert.equal(pair.invitation().redeemedAtMs, String(REDEEMED_AT_MS));
});

test("H-REQ-01: non-enrollment messages are not observed as enrollments", () => {
  const bindings = bindingsAt();
  assert.equal(bindings.observe(roleMessage(1, "initiator", SENDERS.initiator)), null);
  assert.equal(bindings.observe(null), null);
  assert.equal(AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND, "agent_v2_sender_enrollment");
});

// The coordinator's TypeScript port must reproduce these bytes exactly.
test("H-REQ-01: the known-answer vector reproduces byte for byte", async () => {
  const vector = JSON.parse(await readFile(
    new URL("./fixtures/agent-handshake-v2-sender-enrollment.json", import.meta.url),
    "utf8",
  ));
  assert.equal(vector.schema, "clockchain.agent-handshake-sender-enrollment-vector/v1");
  const keys = { coordinator: COORDINATOR, ...SENDERS };
  for (const [name, entry] of Object.entries(vector.keys)) {
    const key = keys[name];
    assert.ok(key, name);
    assert.equal(entry.seedHex, createHash("sha256").update(`clockchain-test:${key.keyId}`).digest("hex"));
    assert.equal(entry.publicKey, key.publicKey);
  }
  assert.deepEqual(vector.keys.coordinator.keyRingEntry, COORDINATOR_KEY_RING[0]);
  assert.deepEqual(vector.relayAuthorization, createRelayAuthorization({
    coordinatorKeyRing: COORDINATOR_KEY_RING,
    hostSenderKey: SENDERS.host.publicKey,
  }));
  for (const role of ["initiator", "responder"]) {
    const record = vector.enrollments[role];
    const enrollment = enrollmentFor(role);
    assert.deepEqual(record.enrollment, enrollment);
    const bytes = canonicalBytes(enrollment);
    assert.equal(record.canonicalBytesHex, bytes.toString("hex"));
    assert.equal(record.canonicalJson, bytes.toString("utf8"));
    assert.equal(record.digest, senderEnrollmentDigest(enrollment));
    const body = signSenderEnrollment({
      enrollment,
      keyId: COORDINATOR.keyId,
      privateKeyPem: COORDINATOR.privateKeyPem,
    });
    assert.deepEqual(record.body, body);
    const envelope = enrollmentEnvelope({ seq: record.envelope.seq, role, body });
    assert.deepEqual(record.envelope, envelope);
    assert.equal(record.envelopeSigningBytesHex, canonicalBytes({
      sessionId: envelope.sessionId,
      seq: envelope.seq,
      role: envelope.role,
      kind: envelope.kind,
      body: envelope.body,
    }).toString("hex"));
    verifySenderEnrollment(record.body, expectations(role));
  }
});
