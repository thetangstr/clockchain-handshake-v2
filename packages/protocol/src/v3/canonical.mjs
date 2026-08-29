import { createHash } from "node:crypto";

import { HandshakeV3Error, fail } from "./constants.mjs";

const LONE_SURROGATE_PATTERN = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/u;

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertString(value) {
  if (LONE_SURROGATE_PATTERN.test(value)) {
    fail("SCHEMA_INVALID", "Strings containing lone surrogates are outside RFC8785 JSON.");
  }
  return value;
}

function assertDataOnly(record, code) {
  for (const key of Reflect.ownKeys(record)) {
    if (Array.isArray(record) && key === "length") {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (typeof key !== "string" || !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      fail("SCHEMA_INVALID");
    }
  }
}

function canonicalize(value, ancestors) {
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    return assertString(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("SCHEMA_INVALID", "Non-finite numbers are outside RFC8785 JSON.");
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value !== "object") {
    fail("SCHEMA_INVALID");
  }
  if (ancestors.has(value)) {
    fail("SCHEMA_INVALID");
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.length !== value.length + 1 ||
        keys.some((key) => key !== "length" && (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))
      ) {
        fail("SCHEMA_INVALID");
      }
      assertDataOnly(value, "SCHEMA_INVALID");
      return value.map((entry) => canonicalize(entry, ancestors));
    }
    if (!isPlainObject(value)) {
      fail("SCHEMA_INVALID");
    }
    assertDataOnly(value, "SCHEMA_INVALID");
    const result = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      assertString(key);
      result[key] = canonicalize(value[key], ancestors);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalJsonString(value) {
  try {
    return JSON.stringify(canonicalize(value, new Set()));
  } catch (error) {
    if (error instanceof HandshakeV3Error) throw error;
    fail("SCHEMA_INVALID");
  }
}

export function canonicalJsonBytes(value) {
  return Buffer.from(canonicalJsonString(value), "utf8");
}

export function sha256Digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function handshakeV3Digest(value) {
  return sha256Digest(canonicalJsonBytes(value));
}
