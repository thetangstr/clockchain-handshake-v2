// The closing certificate: clockchain.handshake-result/v1.
//
// RESULT_SCHEMA sat in constants.mjs with no emitter, and the requestor never
// received the verdict at all -- it finished its side and was told the decision
// would appear on someone else's screen. This module is the emitter. The host
// signs one small document naming the outcome, the parties, and the three
// anchors, and BOTH kits fetch it: the run's deliverable, portable and checkable
// by a stranger holding nothing but this file and the session's operator key.
//
// The signature mirrors the descriptor envelope exactly -- ed25519 over
// canonicalBytes(result), same key, same encoding -- so a verifier that already
// trusts the descriptor's operator key can check the certificate with no new
// machinery. Everything in the document is a string or a boolean: the canonical
// profile bans numbers, and that constraint is inherited here rather than
// re-decided.
//
// The certificate asserts nothing on its own authority. outcome is the
// verifier's word verbatim; anchors are the verifier's transitions verbatim.
// Forging it requires the operator key; disputing it requires disputing the
// receipts it points at.
import {
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

import { canonicalBytes } from "./canonical.mjs";
import {
  RESULT_SCHEMA,
  SINGLE_VALIDATOR_DISCLAIMER,
} from "./constants.mjs";

export const RESULT_KEYS = Object.freeze([
  "anchors",
  "disclaimer",
  "issuedAtMs",
  "outcome",
  "parties",
  "paymentMoved",
  "schema",
  "sessionDigest",
  "sessionId",
  "subjectRun",
]);

export const RESULT_ANCHOR_KEYS = Object.freeze([
  "blockHeight",
  "blockTimeRaw",
  "digest",
  "kind",
  "ledgerId",
]);

export const RESULT_PARTY_KEYS = Object.freeze([
  "address",
  "agentId",
  "reference",
]);

// Mirrors the descriptor envelope's operator block, keyId included, so the two
// artifacts are checkable with one code path.
export const RESULT_SIGNER_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "signature",
]);

export const RESULT_ENVELOPE_KEYS = Object.freeze(["result", "signer"]);

// The three transitions, in the only order a valid run can produce them.
const ANCHOR_KIND_ORDER = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const HEX64_PATTERN = /^[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

export class ResultError extends Error {
  constructor(reason) {
    super(`Handshake result is invalid: ${reason}`);
    this.name = new.target.name;
    this.code = "HANDSHAKE_RESULT_INVALID";
  }
}

function invalid(reason) {
  throw new ResultError(reason);
}

function hasExactKeys(value, expected) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return (
    actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index])
  );
}

function requireString(value, what, pattern = null) {
  if (typeof value !== "string" || value.length === 0) {
    invalid(`${what} must be a non-empty string`);
  }
  if (pattern !== null && !pattern.test(value)) {
    invalid(`${what} is malformed`);
  }
  return value;
}

function validateParty(party, role) {
  if (!hasExactKeys(party, RESULT_PARTY_KEYS)) {
    invalid(`parties.${role} has the wrong shape`);
  }
  requireString(party.address, `parties.${role}.address`, ADDRESS_PATTERN);
  requireString(party.agentId, `parties.${role}.agentId`, DECIMAL_PATTERN);
  requireString(party.reference, `parties.${role}.reference`);
}

/**
 * Structural validation only -- no cryptography. The relay calls this before
 * storing (it is an untrusted mailbox and never checks signatures); readers
 * call verifyResultEnvelope, which starts here and then checks the signature.
 */
export function validateResultEnvelope(envelope) {
  if (!hasExactKeys(envelope, RESULT_ENVELOPE_KEYS)) {
    invalid("envelope must have exactly result and signer");
  }
  const { result, signer } = envelope;
  if (!hasExactKeys(result, RESULT_KEYS)) {
    invalid("result has the wrong shape");
  }
  if (result.schema !== RESULT_SCHEMA) {
    invalid(`result.schema must be ${RESULT_SCHEMA}`);
  }
  if (result.paymentMoved !== false) {
    invalid("result.paymentMoved must be false");
  }
  requireString(result.sessionId, "result.sessionId", UUID_PATTERN);
  requireString(result.sessionDigest, "result.sessionDigest", HEX64_PATTERN);
  requireString(result.outcome, "result.outcome");
  requireString(result.issuedAtMs, "result.issuedAtMs", DECIMAL_PATTERN);
  requireString(result.disclaimer, "result.disclaimer");
  if (result.subjectRun !== "stakeholder" && result.subjectRun !== "rehearsal") {
    invalid("result.subjectRun must be stakeholder or rehearsal");
  }

  if (!hasExactKeys(result.parties, ["payee", "payer"])) {
    invalid("result.parties must have exactly payer and payee");
  }
  validateParty(result.parties.payer, "payer");
  validateParty(result.parties.payee, "payee");

  if (!Array.isArray(result.anchors) || result.anchors.length !== 3) {
    invalid("result.anchors must be exactly three transitions");
  }
  let previousHeight = null;
  for (const [index, anchor] of result.anchors.entries()) {
    if (!hasExactKeys(anchor, RESULT_ANCHOR_KEYS)) {
      invalid(`anchors[${index}] has the wrong shape`);
    }
    if (anchor.kind !== ANCHOR_KIND_ORDER[index]) {
      invalid(
        `anchors[${index}] must be ${ANCHOR_KIND_ORDER[index]}, in order`,
      );
    }
    requireString(anchor.blockHeight, `anchors[${index}].blockHeight`, DECIMAL_PATTERN);
    requireString(anchor.blockTimeRaw, `anchors[${index}].blockTimeRaw`);
    requireString(anchor.digest, `anchors[${index}].digest`, HEX64_PATTERN);
    requireString(anchor.ledgerId, `anchors[${index}].ledgerId`, UUID_PATTERN);
    if (previousHeight !== null && BigInt(anchor.blockHeight) <= previousHeight) {
      invalid("anchors must sit at strictly increasing block heights");
    }
    previousHeight = BigInt(anchor.blockHeight);
  }

  if (!hasExactKeys(signer, RESULT_SIGNER_KEYS)) {
    invalid("signer has the wrong shape");
  }
  if (signer.algorithm !== "ed25519") {
    invalid("signer.algorithm must be ed25519");
  }
  requireString(signer.keyId, "signer.keyId", KEY_ID_PATTERN);
  requireString(signer.publicKey, "signer.publicKey");
  requireString(signer.signature, "signer.signature");
  return true;
}

function rawKeyToPem(publicKeyBase64) {
  let raw;
  try {
    raw = Buffer.from(publicKeyBase64, "base64");
  } catch {
    invalid("signer.publicKey is not base64");
  }
  if (raw.length !== 32) {
    invalid("signer.publicKey must be a raw 32-byte ed25519 key");
  }
  // SPKI prefix for an ed25519 public key; the raw key is the last 32 bytes.
  const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

/**
 * Build and sign the certificate. Everything comes from the verifier's own
 * return value and the session's already-signed artifacts -- nothing here is
 * computed, decided, or improved upon.
 */
export function buildSignedResult({
  issuedAtMs,
  keyId,
  parties,
  privateKeyPem,
  sessionDigest,
  sessionId,
  subjectRun = "stakeholder",
  verdict,
}) {
  const anchors = (verdict?.transitions ?? []).map((transition) =>
    Object.freeze({
      blockHeight: String(transition.blockHeight),
      blockTimeRaw: String(transition.blockTimeRaw),
      digest: String(transition.digest),
      kind: String(transition.kind),
      ledgerId: String(transition.ledgerId),
    }),
  );
  const result = Object.freeze({
    anchors: Object.freeze(anchors),
    disclaimer: SINGLE_VALIDATOR_DISCLAIMER,
    issuedAtMs: String(issuedAtMs),
    outcome: String(verdict.outcome),
    parties: Object.freeze({
      payee: Object.freeze({ ...parties.payee }),
      payer: Object.freeze({ ...parties.payer }),
    }),
    paymentMoved: false,
    schema: RESULT_SCHEMA,
    sessionDigest: String(sessionDigest),
    sessionId: String(sessionId),
    subjectRun,
  });

  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch {
    invalid("signing key is not a usable private key");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    invalid("signing key must be ed25519");
  }
  const publicKey = createPublicKey(privateKey)
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");

  const envelope = Object.freeze({
    result,
    signer: Object.freeze({
      algorithm: "ed25519",
      keyId: String(keyId),
      publicKey,
      signature: sign(null, canonicalBytes(result), privateKey).toString("base64"),
    }),
  });
  validateResultEnvelope(envelope);
  return envelope;
}

/**
 * Full verification: structure, then the ed25519 signature over the canonical
 * bytes, then -- when the caller knows which operator key this session used --
 * that the embedded key IS that key. A certificate signed by some other key is
 * a valid-looking document about a session it had no authority over; the
 * expectedPublicKey check is what closes that.
 */
export function verifyResultEnvelope(envelope, { expectedPublicKey = null } = {}) {
  validateResultEnvelope(envelope);
  const { result, signer } = envelope;

  if (expectedPublicKey !== null) {
    const given = Buffer.from(signer.publicKey, "base64");
    const expected = Buffer.from(expectedPublicKey, "base64");
    if (
      given.length !== expected.length ||
      !timingSafeEqual(given, expected)
    ) {
      invalid("signer.publicKey is not the session's operator key");
    }
  }

  const key = rawKeyToPem(signer.publicKey);
  let signatureBytes;
  try {
    signatureBytes = Buffer.from(signer.signature, "base64");
  } catch {
    invalid("signer.signature is not base64");
  }
  let ok;
  try {
    ok = verify(null, canonicalBytes(result), key, signatureBytes);
  } catch {
    invalid("signature verification failed");
  }
  if (!ok) {
    invalid("signature does not match the result");
  }
  return result;
}
