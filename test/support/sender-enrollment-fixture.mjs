// Deterministic test keys and helpers for H-REQ-01 sender enrollments.
//
// Every key here comes from the public test seed derivation in
// agent-handshake-v2-fixture.mjs (sha256 of "clockchain-test:<label>"); none of
// them is, or may ever become, a deployed key.
import { createHash } from "node:crypto";

import {
  AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND,
  AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_SCHEMA,
  signSenderEnrollment,
} from "../../src/agent-handshake/v2/relay-enrollment.mjs";
import { ed25519PublicKeyFingerprint } from "../../src/agent-handshake/v2/host-key-certificate.mjs";
import { agentHandshakeV2StatementDigest } from "../../src/agent-handshake/v2/terms.mjs";
import { signEnvelope } from "../../src/relay/client.mjs";
import { ed25519, SESSION_ID, TERMS } from "./agent-handshake-v2-fixture.mjs";

export const COORDINATOR = ed25519("coordinator-test-2026-10");
export const OTHER_COORDINATOR = ed25519("coordinator-test-other");
export const SENDERS = Object.freeze({
  initiator: ed25519("relay-sender-initiator"),
  responder: ed25519("relay-sender-responder"),
  host: ed25519("relay-sender-host"),
  unenrolled: ed25519("relay-sender-unenrolled"),
});

export function keyRingEntry(key) {
  return Object.freeze({
    kid: key.keyId,
    publicKey: key.publicKey,
    fingerprint: ed25519PublicKeyFingerprint(key.publicKey),
  });
}

export const COORDINATOR_KEY_RING = Object.freeze([keyRingEntry(COORDINATOR)]);
export const STATEMENT_DIGEST = agentHandshakeV2StatementDigest(TERMS);
export const INVITATION_DIGEST = createHash("sha256")
  .update("clockchain-test:invitation")
  .digest("hex");
export const OPENED_AT_MS = 1786337000000;
export const DEADLINE_MS = OPENED_AT_MS + 600_000;
export const MINTED_AT_MS = OPENED_AT_MS + 82_106;
export const CLAIM_EXPIRES_AT_MS = MINTED_AT_MS + 180_000;
export const REDEEMED_AT_MS = OPENED_AT_MS + 158_124;

// The enrollment the coordinator signs for one role. Initiator enrollments
// record the mint; responder enrollments record the redemption.
export function enrollmentFor(role, overrides = {}, {
  sessionId = SESSION_ID,
  sessionDeadlineMs = DEADLINE_MS,
  mintedAtMs = MINTED_AT_MS,
  claimExpiresAtMs = CLAIM_EXPIRES_AT_MS,
  redeemedAtMs = REDEEMED_AT_MS,
} = {}) {
  const eventAtMs = role === "responder" ? redeemedAtMs : mintedAtMs;
  return {
    schema: AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_SCHEMA,
    protocol: "clockchain.agent-handshake/v2",
    sessionId,
    role,
    senderKey: (SENDERS[role] ?? SENDERS.unenrolled).publicKey,
    statementDigest: STATEMENT_DIGEST,
    sessionDeadlineMs: String(sessionDeadlineMs),
    invitationDigest: INVITATION_DIGEST,
    claimExpiresAtMs: String(claimExpiresAtMs),
    event: role === "responder" ? "redeemed" : "minted",
    eventAtMs: String(eventAtMs),
    issuedAtMs: String(eventAtMs + 5),
    externalBusinessActionPerformed: false,
    ...overrides,
  };
}

export function signedEnrollment(role, overrides = {}, {
  signer = COORDINATOR,
  keyId = signer.keyId,
  timing,
} = {}) {
  return signSenderEnrollment({
    enrollment: enrollmentFor(role, overrides, timing),
    keyId,
    privateKeyPem: signer.privateKeyPem,
  });
}

export function envelopeFrom({
  sessionId = SESSION_ID,
  seq,
  role,
  kind,
  body,
  sender,
}) {
  return signEnvelope({
    sessionId,
    seq: String(seq),
    role,
    kind,
    body,
    senderKey: sender.publicKey,
    privateKeyPem: sender.privateKeyPem,
  });
}

export function enrollmentEnvelope({ seq, role, sender = SENDERS[role], body, sessionId = SESSION_ID }) {
  return envelopeFrom({
    sessionId,
    seq,
    role,
    kind: AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND,
    body,
    sender,
  });
}
