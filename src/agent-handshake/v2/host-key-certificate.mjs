import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { types } from "node:util";

import { canonicalBytes, digestHex } from "../../core/canonical.mjs";

export const HOST_SESSION_KEY_CERTIFICATE_SCHEMA = "clockchain.host-session-key/v1";

const CERTIFICATE_KEYS = Object.freeze([
  "schema", "rootKid", "sessionId", "repositorySha", "sessionPublicKey",
  "validFromMs", "validUntilMs",
]);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm", "keyId", "publicKey", "signature",
]);
const ENVELOPE_KEYS = Object.freeze(["certificate", "rootSignature"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class HostSessionKeyCertificateError extends Error {
  constructor() {
    super("Host session key certificate verification failed.");
    this.name = "HostSessionKeyCertificateError";
    this.category = "verification";
    this.code = "HOST_SESSION_KEY_CERTIFICATE_INVALID";
  }
}
function invalid() { throw new HostSessionKeyCertificateError(); }
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
    if (error instanceof HostSessionKeyCertificateError) throw error;
    invalid();
  }
}
function same(left, right) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}
function publicKey(value) {
  if (typeof value !== "string" || !BASE64.test(value) || Buffer.from(value, "base64").length !== 32) invalid();
  return value;
}
function keyFromRaw(value) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey(value), "base64")]), format: "der", type: "spki" });
}
export function rawEd25519PublicKey(value) {
  try {
    const key = value?.type === "public" ? value : createPublicKey(value);
    const der = key.export({ format: "der", type: "spki" });
    if (der.length !== 44 || !der.subarray(0, 12).equals(SPKI_PREFIX)) invalid();
    return der.subarray(-32).toString("base64");
  } catch (error) {
    if (error instanceof HostSessionKeyCertificateError) throw error;
    invalid();
  }
}
export function ed25519PublicKeyFingerprint(value) {
  return createHash("sha256").update(Buffer.from(publicKey(value), "base64")).digest("hex");
}
function certificate(value) {
  const item = exact(value, CERTIFICATE_KEYS);
  if (item.schema !== HOST_SESSION_KEY_CERTIFICATE_SCHEMA || !KID.test(item.rootKid) ||
    !UUID.test(item.sessionId) || !SHA.test(item.repositorySha) ||
    !DECIMAL.test(item.validFromMs) || !DECIMAL.test(item.validUntilMs) ||
    BigInt(item.validFromMs) >= BigInt(item.validUntilMs)) invalid();
  publicKey(item.sessionPublicKey);
  return Object.freeze(item);
}
function rootSignature(value) {
  const item = exact(value, SIGNATURE_KEYS);
  if (item.algorithm !== "ed25519" || !KID.test(item.keyId) ||
    typeof item.signature !== "string" || !BASE64.test(item.signature) ||
    Buffer.from(item.signature, "base64").length !== 64) invalid();
  publicKey(item.publicKey);
  return Object.freeze(item);
}
function envelope(value) {
  const item = exact(value, ENVELOPE_KEYS);
  return Object.freeze({ certificate: certificate(item.certificate), rootSignature: rootSignature(item.rootSignature) });
}
export function createHostSessionKeyCertificate({ certificate: value, root }) {
  const verified = certificate(value);
  if (root === null || typeof root !== "object" || root.keyId !== verified.rootKid || !KID.test(root.keyId)) invalid();
  let privateKey;
  try { privateKey = createPrivateKey(root.privateKeyPem); } catch { invalid(); }
  if (privateKey.asymmetricKeyType !== "ed25519") invalid();
  const rootPublicKey = rawEd25519PublicKey(createPublicKey(privateKey));
  return envelope({
    certificate: verified,
    rootSignature: {
      algorithm: "ed25519",
      keyId: root.keyId,
      publicKey: rootPublicKey,
      signature: sign(null, canonicalBytes(verified), privateKey).toString("base64"),
    },
  });
}
export function hostSessionKeyCertificateDigest(value) {
  return digestHex(envelope(value));
}
export function verifyHostSessionKeyCertificate(value, {
  expectedRepositorySha, expectedSessionId, nowMs, rootKeyRing, sessionDeadlineMs,
}) {
  const verified = envelope(value);
  if (!SHA.test(expectedRepositorySha) || !UUID.test(expectedSessionId) ||
    !Number.isSafeInteger(nowMs) || !Number.isSafeInteger(sessionDeadlineMs) ||
    verified.certificate.repositorySha !== expectedRepositorySha ||
    verified.certificate.sessionId !== expectedSessionId ||
    Number(verified.certificate.validFromMs) > nowMs ||
    Number(verified.certificate.validUntilMs) <= nowMs ||
    Number(verified.certificate.validUntilMs) > sessionDeadlineMs ||
    verified.rootSignature.keyId !== verified.certificate.rootKid) invalid();
  if (!Array.isArray(rootKeyRing) || rootKeyRing.length < 1 || rootKeyRing.length > 2) invalid();
  const trusted = rootKeyRing.find((entry) =>
    entry?.kid === verified.rootSignature.keyId &&
    same(entry.publicKey, verified.rootSignature.publicKey) &&
    entry.fingerprint === ed25519PublicKeyFingerprint(entry.publicKey));
  if (!trusted) invalid();
  let accepted = false;
  try {
    accepted = verify(null, canonicalBytes(verified.certificate), keyFromRaw(verified.rootSignature.publicKey), Buffer.from(verified.rootSignature.signature, "base64"));
  } catch { accepted = false; }
  if (!accepted) invalid();
  return verified;
}
