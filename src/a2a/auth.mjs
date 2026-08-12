import { recoverMessageAddress } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import { createHash } from "node:crypto";
import { types } from "node:util";

export const A2A_ROLES = Object.freeze(["initiator", "responder"]);
export const A2A_ARTIFACTS = Object.freeze(["invitation", "proposal", "counterproposal", "acceptance"]);

const ADDRESS = /^0x[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const EIP191 = /^0x[0-9a-f]{130}$/;
const TOKEN = /^[A-Za-z0-9._:-]{1,128}$/;
const URL = /^https:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{1,240}$/;
const PUBLIC_KEY = /^0x[0-9a-f]{130}$/;
const MAX_DEPTH = 24;
const MAX_STRING = 4096;

export class A2AVerificationError extends Error {
  constructor() {
    super("A2A verification failed safely.");
    this.name = "A2AVerificationError";
    this.category = "verification";
    this.code = "A2A_VERIFICATION_FAILED";
  }
}

export function invalid() {
  throw new A2AVerificationError();
}

export function exact(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) invalid();
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
    if (error instanceof A2AVerificationError) throw error;
    invalid();
  }
}

function canonicalize(value, ancestors = new Set(), depth = 0) {
  if (depth > MAX_DEPTH) invalid();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.length > MAX_STRING) invalid();
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid();
    return value;
  }
  if (typeof value !== "object" || types.isProxy(value) || ancestors.has(value)) invalid();
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (value.length > 128) invalid();
      for (const key of Reflect.ownKeys(descriptors)) {
        if (key === "length") continue;
        if (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key)) invalid();
        const descriptor = descriptors[key];
        if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
      }
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(descriptors, String(index))) invalid();
      }
      return value.map((entry) => canonicalize(entry, ancestors, depth + 1));
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
    const result = {};
    const keys = Reflect.ownKeys(value);
    if (keys.length > 128) invalid();
    for (const key of keys.sort()) {
      if (typeof key !== "string") invalid();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
      result[key] = canonicalize(descriptor.value, ancestors, depth + 1);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

export function a2aCanonicalBytes(value) {
  return Buffer.from(JSON.stringify(canonicalize(value)), "utf8");
}

export function digest(value) {
  try {
    return createHash("sha256").update(a2aCanonicalBytes(value)).digest("hex");
  } catch {
    invalid();
  }
}

export function assertDigest(value) {
  if (typeof value !== "string" || !DIGEST.test(value)) invalid();
  return value;
}

export function assertAddress(value) {
  if (typeof value !== "string" || !ADDRESS.test(value)) invalid();
  return value;
}

export function assertPublicKey(value) {
  if (typeof value !== "string" || !PUBLIC_KEY.test(value)) invalid();
  return value;
}

export function addressFromPublicKey(value) {
  assertPublicKey(value);
  try {
    return publicKeyToAddress(value).toLowerCase();
  } catch {
    invalid();
  }
}

export function assertToken(value) {
  if (typeof value !== "string" || !TOKEN.test(value)) invalid();
  return value;
}

export function assertUrl(value) {
  if (typeof value !== "string" || !URL.test(value)) invalid();
  return value;
}

export function assertDecimal(value) {
  if (typeof value !== "string" || !DECIMAL.test(value)) invalid();
  return value;
}

export function assertWindow({ issuedAtMs, expiresAtMs, nowMs = null }) {
  assertDecimal(issuedAtMs);
  assertDecimal(expiresAtMs);
  if (BigInt(issuedAtMs) >= BigInt(expiresAtMs)) invalid();
  if (nowMs !== null) {
    if (!Number.isSafeInteger(nowMs)) invalid();
    if (BigInt(nowMs) < BigInt(issuedAtMs) || BigInt(nowMs) >= BigInt(expiresAtMs)) invalid();
  }
}

export function signature(value) {
  const item = exact(value, ["address", "algorithm", "value"]);
  assertAddress(item.address);
  if (item.algorithm !== "eip191" || typeof item.value !== "string" || !EIP191.test(item.value)) invalid();
  return Object.freeze(item);
}

export async function recoverSigner(payload, signatureValue) {
  try {
    return (await recoverMessageAddress({ message: { raw: a2aCanonicalBytes(payload) }, signature: signatureValue })).toLowerCase();
  } catch {
    invalid();
  }
}

export async function signPayload({ payload, signerAddress, signMessage }) {
  assertAddress(signerAddress);
  if (typeof signMessage !== "function") invalid();
  let value;
  try {
    value = await signMessage(a2aCanonicalBytes(payload));
  } catch {
    invalid();
  }
  return signature({ address: signerAddress, algorithm: "eip191", value });
}

export function assertArtifacts(value) {
  try {
    if (value === null || typeof value !== "object" || types.isProxy(value) || !Array.isArray(value)) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== A2A_ARTIFACTS.length + 1 || !keys.includes("length")) invalid();
    const length = descriptors.length;
    if (length?.enumerable !== false || !Object.hasOwn(length, "value") || length.value !== A2A_ARTIFACTS.length) invalid();
    const result = [];
    for (let index = 0; index < A2A_ARTIFACTS.length; index += 1) {
      const key = String(index);
      const descriptor = descriptors[key];
      if (!keys.includes(key) || descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value") || descriptor.value !== A2A_ARTIFACTS[index]) invalid();
      result.push(descriptor.value);
    }
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof A2AVerificationError) throw error;
    invalid();
  }
}
