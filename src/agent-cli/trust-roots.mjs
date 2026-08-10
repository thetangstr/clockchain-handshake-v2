import { types } from "node:util";

import {
  ed25519PublicKeyFingerprint,
  verifyHostSessionKeyCertificate,
} from "../agent-handshake/v2/host-key-certificate.mjs";

const ROOT_KEYS = Object.freeze([
  "kid",
  "publicKey",
  "fingerprint",
  "notBeforeMs",
  "notAfterMs",
]);
const KID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

// Populated only by the reviewed post-release pin commit in Task 6.
export const EMBEDDED_HOST_ROOT_KEY_RING = Object.freeze([]);

function invalid() {
  throw new Error("Agent handshake operation failed safely.");
}

function exact(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== ROOT_KEYS.length || keys.some((key) => !ROOT_KEYS.includes(key))) invalid();
  const result = {};
  for (const key of ROOT_KEYS) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
    result[key] = property.value;
  }
  return result;
}

export function validateHostRootKeyRing(value, { nowMs } = {}) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 2 || !Number.isSafeInteger(nowMs)) invalid();
  const seen = new Set();
  const seenFingerprints = new Set();
  const ring = value.map((entry) => {
    const root = exact(entry);
    if (
      !KID.test(root.kid) ||
      typeof root.publicKey !== "string" ||
      Buffer.from(root.publicKey, "base64").length !== 32 ||
      !DIGEST.test(root.fingerprint) ||
      root.fingerprint !== ed25519PublicKeyFingerprint(root.publicKey) ||
      !DECIMAL.test(root.notBeforeMs) ||
      !DECIMAL.test(root.notAfterMs) ||
      BigInt(root.notBeforeMs) >= BigInt(root.notAfterMs) ||
      nowMs < Number(root.notBeforeMs) ||
      nowMs >= Number(root.notAfterMs) ||
      seen.has(root.kid) ||
      seenFingerprints.has(root.fingerprint)
    ) invalid();
    seen.add(root.kid);
    seenFingerprints.add(root.fingerprint);
    return Object.freeze({ ...root });
  });
  return Object.freeze(ring);
}

export function verifyPinnedHostSessionKey(value, options) {
  const rootKeyRing = validateHostRootKeyRing(options?.rootKeyRing, {
    nowMs: options?.nowMs,
  });
  return verifyHostSessionKeyCertificate(value, { ...options, rootKeyRing });
}
