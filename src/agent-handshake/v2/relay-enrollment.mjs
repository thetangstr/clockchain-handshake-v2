// H-REQ-01: sender enrollments bind each relay role to exactly one sender key.
//
// A relay envelope's role label is a statement by whoever signed the envelope.
// The host treats it as the role's speech only once the coordinator, which
// mints and redeems the session's invitation, has said which key speaks for
// that role. It says so with a sender enrollment: an Ed25519
// signature, under a key from a configured coordinator key ring, over the
// canonical bytes of
//
//   {schema, protocol, sessionId, role, senderKey, statementDigest,
//    sessionDeadlineMs, invitationDigest, claimExpiresAtMs,
//    event, eventAtMs, issuedAtMs, externalBusinessActionPerformed}
//
// The initiator is enrolled when the invitation is minted (event "minted",
// eventAtMs = mint time); the responder when it is redeemed (event "redeemed",
// eventAtMs = claim time). Both enrollments name the same invitationDigest and
// claimExpiresAtMs. The enrollment travels as the body of the role's FIRST
// relay message, kind agent_v2_sender_enrollment, and that envelope is signed
// by the key being enrolled.
//
// Canonical bytes are the repository's bilateral profile (src/core/canonical.mjs):
// UTF-8 JSON with keys sorted by code unit, no whitespace, strings only (every
// millisecond value is a decimal string), booleans as literals.
import {
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { types } from "node:util";

import { canonicalBytes, digestHex } from "../../core/canonical.mjs";
import { verifyEnvelope } from "../../relay/client.mjs";
import { nonDecreasingClock } from "./clock.mjs";
import { ed25519PublicKeyFingerprint } from "./host-key-certificate.mjs";

export const AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND = "agent_v2_sender_enrollment";
export const AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_SCHEMA =
  "clockchain.agent-handshake-sender-enrollment/v1";
export const AGENT_HANDSHAKE_V2_RELAY_AUTHORIZATION_SCHEMA =
  "clockchain.agent-handshake-relay-authorization/v1";
// Which invitation event enrolls which role.
export const AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_EVENTS = Object.freeze({
  initiator: "minted",
  responder: "redeemed",
});
// How far ahead of the verifier's clock an issuedAtMs may be, to absorb clock
// difference between the coordinator and the relay or host.
export const SENDER_ENROLLMENT_CLOCK_SKEW_MS = 60_000;

const PROTOCOL = "clockchain.agent-handshake/v2";
const ROLES = Object.freeze(["initiator", "responder"]);
const ENROLLMENT_KEYS = Object.freeze([
  "schema", "protocol", "sessionId", "role", "senderKey", "statementDigest",
  "sessionDeadlineMs", "invitationDigest", "claimExpiresAtMs", "event",
  "eventAtMs", "issuedAtMs", "externalBusinessActionPerformed",
]);
const BODY_KEYS = Object.freeze([
  "enrollment", "coordinatorSignature", "externalBusinessActionPerformed",
]);
const SIGNATURE_KEYS = Object.freeze(["algorithm", "keyId", "signature"]);
const RING_ENTRY_KEYS = Object.freeze(["kid", "publicKey", "fingerprint"]);
const AUTHORIZATION_KEYS = Object.freeze(["schema", "coordinatorKeys", "hostSenderKey"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class AgentHandshakeV2SenderEnrollmentError extends Error {
  constructor() {
    super("Agent handshake v2 sender enrollment verification failed.");
    this.name = "AgentHandshakeV2SenderEnrollmentError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_INVALID";
  }
}

function invalid() { throw new AgentHandshakeV2SenderEnrollmentError(); }

function exact(value, keys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
      types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
    const actual = Reflect.ownKeys(value);
    if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) invalid();
    const result = {};
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeV2SenderEnrollmentError) throw error;
    invalid();
  }
}

function same(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function rawKey(value) {
  if (
    typeof value !== "string" || !BASE64.test(value) ||
    Buffer.from(value, "base64").length !== 32 ||
    Buffer.from(value, "base64").toString("base64") !== value
  ) invalid();
  return value;
}

function keyFromRaw(value) {
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(rawKey(value), "base64")]),
    format: "der",
    type: "spki",
  });
}

function milliseconds(value) {
  if (typeof value !== "string" || !DECIMAL.test(value)) invalid();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) invalid();
  return parsed;
}

export function validateCoordinatorKeyRing(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 2) invalid();
  const ring = value.map((entry) => {
    const item = exact(entry, RING_ENTRY_KEYS);
    if (!KID.test(item.kid)) invalid();
    rawKey(item.publicKey);
    let fingerprint;
    try { fingerprint = ed25519PublicKeyFingerprint(item.publicKey); } catch { invalid(); }
    if (item.fingerprint !== fingerprint) invalid();
    return Object.freeze(item);
  });
  if (
    new Set(ring.map((entry) => entry.kid)).size !== ring.length ||
    new Set(ring.map((entry) => entry.publicKey)).size !== ring.length
  ) invalid();
  return Object.freeze(ring);
}

export function validateSenderEnrollment(value) {
  const item = exact(value, ENROLLMENT_KEYS);
  if (
    item.schema !== AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_SCHEMA ||
    item.protocol !== PROTOCOL ||
    typeof item.sessionId !== "string" || !UUID.test(item.sessionId) ||
    !ROLES.includes(item.role) ||
    item.event !== AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_EVENTS[item.role] ||
    typeof item.statementDigest !== "string" || !DIGEST.test(item.statementDigest) ||
    typeof item.invitationDigest !== "string" || !DIGEST.test(item.invitationDigest) ||
    item.externalBusinessActionPerformed !== false
  ) invalid();
  rawKey(item.senderKey);
  const sessionDeadlineMs = milliseconds(item.sessionDeadlineMs);
  const claimExpiresAtMs = milliseconds(item.claimExpiresAtMs);
  const eventAtMs = milliseconds(item.eventAtMs);
  const issuedAtMs = milliseconds(item.issuedAtMs);
  if (
    eventAtMs > issuedAtMs ||
    issuedAtMs >= sessionDeadlineMs ||
    (item.event === "minted" && claimExpiresAtMs <= eventAtMs)
  ) invalid();
  return Object.freeze(item);
}

export function senderEnrollmentDigest(enrollment) {
  return digestHex(validateSenderEnrollment(enrollment));
}

function coordinatorSignature(value) {
  const item = exact(value, SIGNATURE_KEYS);
  if (
    item.algorithm !== "ed25519" ||
    typeof item.keyId !== "string" || !KID.test(item.keyId) ||
    typeof item.signature !== "string" || !BASE64.test(item.signature) ||
    Buffer.from(item.signature, "base64").length !== 64
  ) invalid();
  return Object.freeze(item);
}

function enrollmentBody(value) {
  const item = exact(value, BODY_KEYS);
  if (item.externalBusinessActionPerformed !== false) invalid();
  return Object.freeze({
    enrollment: validateSenderEnrollment(item.enrollment),
    coordinatorSignature: coordinatorSignature(item.coordinatorSignature),
    externalBusinessActionPerformed: false,
  });
}

// The coordinator side. The TypeScript port must produce identical bytes: see
// test/fixtures/agent-handshake-v2-sender-enrollment.json.
export function signSenderEnrollment({ enrollment, keyId, privateKeyPem }) {
  const verified = validateSenderEnrollment(enrollment);
  if (typeof keyId !== "string" || !KID.test(keyId)) invalid();
  let privateKey;
  try { privateKey = createPrivateKey(privateKeyPem); } catch { invalid(); }
  if (privateKey.asymmetricKeyType !== "ed25519") invalid();
  return enrollmentBody({
    enrollment: verified,
    coordinatorSignature: {
      algorithm: "ed25519",
      keyId,
      signature: sign(null, canonicalBytes(verified), privateKey).toString("base64"),
    },
    externalBusinessActionPerformed: false,
  });
}

// The time-dependent part of the checks below, for a verifier that admits an
// enrollment later than it first verified it (H-REQ-07): at nowMs the
// enrollment is still before its signed session deadline and is not dated
// ahead of nowMs by more than the allowed skew.
export function isSenderEnrollmentCurrent(enrollment, nowMs) {
  return Number.isSafeInteger(nowMs) &&
    nowMs < Number(enrollment?.sessionDeadlineMs) &&
    Number(enrollment?.issuedAtMs) <= nowMs + SENDER_ENROLLMENT_CLOCK_SKEW_MS;
}

// Relay-grade check: a coordinator-signed enrollment of THIS sender key for
// THIS role of THIS session, not past its own signed deadline and not dated
// ahead of the verifier's clock. It does not know the session's terms; the
// host's verifySenderEnrollment below also binds the statement and deadline.
export function verifySenderEnrollmentBinding(value, {
  coordinatorKeyRing,
  expectedRole,
  expectedSenderKey,
  expectedSessionId,
  nowMs,
} = {}) {
  const ring = validateCoordinatorKeyRing(coordinatorKeyRing);
  const body = enrollmentBody(value);
  const { enrollment } = body;
  if (
    typeof expectedSessionId !== "string" || enrollment.sessionId !== expectedSessionId ||
    typeof expectedRole !== "string" || enrollment.role !== expectedRole ||
    !same(enrollment.senderKey, expectedSenderKey) ||
    !isSenderEnrollmentCurrent(enrollment, nowMs)
  ) invalid();
  const trusted = ring.find((entry) => entry.kid === body.coordinatorSignature.keyId);
  if (!trusted) invalid();
  let accepted = false;
  try {
    accepted = verify(
      null,
      canonicalBytes(enrollment),
      keyFromRaw(trusted.publicKey),
      Buffer.from(body.coordinatorSignature.signature, "base64"),
    );
  } catch { accepted = false; }
  if (!accepted) invalid();
  return Object.freeze({
    digest: digestHex(enrollment),
    enrollment,
    keyId: trusted.kid,
  });
}

// Host-grade check: the relay-grade binding plus the session's own statement
// and deadline.
export function verifySenderEnrollment(value, {
  coordinatorKeyRing,
  expectedRole,
  expectedSenderKey,
  expectedSessionDeadlineMs,
  expectedSessionId,
  expectedStatementDigest,
  nowMs,
} = {}) {
  const verified = verifySenderEnrollmentBinding(value, {
    coordinatorKeyRing,
    expectedRole,
    expectedSenderKey,
    expectedSessionId,
    nowMs,
  });
  if (
    !Number.isSafeInteger(expectedSessionDeadlineMs) ||
    verified.enrollment.sessionDeadlineMs !== String(expectedSessionDeadlineMs) ||
    typeof expectedStatementDigest !== "string" ||
    verified.enrollment.statementDigest !== expectedStatementDigest
  ) invalid();
  return verified;
}

// The opt-in a host sends with POST /v1/sessions. It never enters the
// discovery document.
export function validateRelayAuthorization(value) {
  const item = exact(value, AUTHORIZATION_KEYS);
  if (item.schema !== AGENT_HANDSHAKE_V2_RELAY_AUTHORIZATION_SCHEMA) invalid();
  return Object.freeze({
    schema: AGENT_HANDSHAKE_V2_RELAY_AUTHORIZATION_SCHEMA,
    coordinatorKeys: validateCoordinatorKeyRing(item.coordinatorKeys),
    hostSenderKey: rawKey(item.hostSenderKey),
  });
}

export function createRelayAuthorization({ coordinatorKeyRing, hostSenderKey }) {
  return validateRelayAuthorization({
    schema: AGENT_HANDSHAKE_V2_RELAY_AUTHORIZATION_SCHEMA,
    coordinatorKeys: coordinatorKeyRing,
    hostSenderKey,
  });
}

function otherRole(role) {
  return role === "initiator" ? "responder" : "initiator";
}

function isEnvelopeLike(message) {
  return message !== null && typeof message === "object" && !Array.isArray(message);
}

// The reader side. `observe` is shown every relay message once it arrives (it
// acts only on enrollments); `admits` says whether a message may be consumed
// as speech by its labelled role. A second valid enrollment for a role, or two
// roles enrolled for different invitations, ends the bindings: nothing is
// admitted afterwards and `failure()` names the reason. An enrollment that does
// not verify is ignored: it neither binds a role nor ends the bindings, so only
// a verified enrollment changes them.
export function createSenderBindings({
  coordinatorKeyRing,
  now = Date.now,
  sessionDeadlineMs,
  sessionId,
  statementDigest,
} = {}) {
  const ring = validateCoordinatorKeyRing(coordinatorKeyRing);
  if (
    typeof sessionId !== "string" || !UUID.test(sessionId) ||
    typeof statementDigest !== "string" || !DIGEST.test(statementDigest) ||
    !Number.isSafeInteger(sessionDeadlineMs) ||
    typeof now !== "function"
  ) invalid();
  // H-REQ-07: enrollment freshness is judged against a clock that never reads
  // earlier than a previous read.
  const clock = nonDecreasingClock(now);
  const bound = { initiator: null, responder: null };
  let failed = null;
  const refused = (role, reason, fatal) => {
    if (fatal && failed === null) failed = reason;
    return Object.freeze({ status: "refused", role, reason, fatal });
  };

  const observe = (message) => {
    if (!isEnvelopeLike(message) || message.kind !== AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND) {
      return null;
    }
    const role = typeof message.role === "string" ? message.role : null;
    if (failed !== null) return refused(role, failed, true);
    if (!ROLES.includes(role) || message.sessionId !== sessionId) {
      return refused(role, "BINDING_MISMATCH", false);
    }
    const current = bound[role];
    if (current !== null && message.senderKey === current.senderKey) {
      let digest = null;
      try { digest = senderEnrollmentDigest(message.body?.enrollment); } catch {}
      if (digest === current.digest) return Object.freeze({ status: "unchanged", role });
    }
    let verified;
    try {
      verifyEnvelope(message);
      verified = verifySenderEnrollment(message.body, {
        coordinatorKeyRing: ring,
        expectedRole: role,
        expectedSenderKey: message.senderKey,
        expectedSessionDeadlineMs: sessionDeadlineMs,
        expectedSessionId: sessionId,
        expectedStatementDigest: statementDigest,
        nowMs: clock.read(),
      });
    } catch {
      return refused(role, "BINDING_MISMATCH", false);
    }
    if (current !== null) return refused(role, "ROLE_ALREADY_BOUND", true);
    const other = bound[otherRole(role)];
    if (
      other !== null && (
        other.senderKey === message.senderKey ||
        other.enrollment.invitationDigest !== verified.enrollment.invitationDigest ||
        other.enrollment.claimExpiresAtMs !== verified.enrollment.claimExpiresAtMs
      )
    ) return refused(role, "BINDING_MISMATCH", true);
    bound[role] = Object.freeze({
      digest: verified.digest,
      enrollment: verified.enrollment,
      senderKey: message.senderKey,
    });
    return Object.freeze({ status: "bound", role });
  };

  const admits = (message) => {
    if (
      failed !== null || !isEnvelopeLike(message) ||
      message.sessionId !== sessionId || !ROLES.includes(message.role)
    ) return false;
    const current = bound[message.role];
    if (current === null || !same(message.senderKey, current.senderKey)) return false;
    try {
      return verifyEnvelope(message, { expectedSenderKey: current.senderKey }) === true;
    } catch {
      return false;
    }
  };

  const invitation = () => {
    const any = bound.initiator ?? bound.responder;
    if (any === null) return null;
    return Object.freeze({
      claimExpiresAtMs: any.enrollment.claimExpiresAtMs,
      invitationDigest: any.enrollment.invitationDigest,
      mintedAtMs: bound.initiator?.enrollment.eventAtMs ?? null,
      redeemedAtMs: bound.responder?.enrollment.eventAtMs ?? null,
    });
  };

  return Object.freeze({
    admits,
    enrollment: (role) => bound[role]?.enrollment ?? null,
    failure: () => failed,
    invitation,
    observe,
  });
}
