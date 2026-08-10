import {
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { types } from "node:util";

import { canonicalBytes, digestHex } from "../core/canonical.mjs";
import {
  AGENT_HANDSHAKE_PROTOCOL,
  AGENT_HANDSHAKE_REFERENCE_MAX,
} from "./constants.mjs";

export const AGENT_HANDSHAKE_DESCRIPTOR_SCHEMA =
  "clockchain.agent-handshake-descriptor/v1";
export const AGENT_HANDSHAKE_CHAIN_ID = "11155111";
export const AGENT_HANDSHAKE_REGISTRY_ADDRESS =
  "0x8004a818bfb912233c491871b3d84c89a494bd9e";

const DESCRIPTOR_KEYS = Object.freeze([
  "chainId",
  "expiresAtMs",
  "externalActionPerformed",
  "initiator",
  "operatorPublicKey",
  "protocol",
  "reference",
  "registryAddress",
  "repositorySha",
  "responder",
  "schema",
  "sessionId",
  "statementDigest",
]);
const PARTY_KEYS = Object.freeze(["address", "agentId"]);
const ENVELOPE_KEYS = Object.freeze(["descriptor", "operator"]);
const OPERATOR_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "signature",
]);
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RAW_PUBLIC_KEY_LENGTH = 44;
const SIGNATURE_LENGTH = 88;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class AgentHandshakeDescriptorError extends Error {
  constructor(code = "AGENT_HANDSHAKE_DESCRIPTOR_INVALID") {
    super("Agent handshake descriptor validation failed.");
    this.name = "AgentHandshakeDescriptorError";
    this.category = "verification";
    this.code = code;
  }
}

export class OperatorKeyMismatchError extends AgentHandshakeDescriptorError {
  constructor() {
    super("AGENT_HANDSHAKE_OPERATOR_KEY_MISMATCH");
    this.name = "OperatorKeyMismatchError";
  }
}

function invalid(code) {
  throw new AgentHandshakeDescriptorError(code);
}

function record(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) invalid();
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some((key) => typeof key !== "string" || !keys.includes(key))
    ) invalid();
    const result = {};
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (
        property?.enumerable !== true ||
        !Object.hasOwn(property, "value")
      ) invalid();
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeDescriptorError) throw error;
    invalid();
  }
}

function decimal(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 16 &&
    DECIMAL_PATTERN.test(value)
  );
}

function printable(value, max) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    PRINTABLE_PATTERN.test(value) &&
    value.trim() === value
  );
}

function party(value) {
  const result = record(value, PARTY_KEYS);
  if (
    !ADDRESS_PATTERN.test(result.address) ||
    !decimal(result.agentId)
  ) invalid();
  return Object.freeze(result);
}

function publicKey(value) {
  if (
    typeof value !== "string" ||
    value.length !== RAW_PUBLIC_KEY_LENGTH ||
    !BASE64_PATTERN.test(value)
  ) invalid();
  try {
    const decoded = Buffer.from(value, "base64");
    if (decoded.length !== 32 || decoded.toString("base64") !== value) invalid();
    createPublicKey({
      format: "der",
      key: Buffer.concat([ED25519_SPKI_PREFIX, decoded]),
      type: "spki",
    });
  } catch (error) {
    if (error instanceof AgentHandshakeDescriptorError) throw error;
    invalid();
  }
  return value;
}

function descriptor(value) {
  const result = record(value, DESCRIPTOR_KEYS);
  const initiator = party(result.initiator);
  const responder = party(result.responder);
  if (
    result.chainId !== AGENT_HANDSHAKE_CHAIN_ID ||
    result.schema !== AGENT_HANDSHAKE_DESCRIPTOR_SCHEMA ||
    result.protocol !== AGENT_HANDSHAKE_PROTOCOL ||
    result.registryAddress !== AGENT_HANDSHAKE_REGISTRY_ADDRESS ||
    result.externalActionPerformed !== false ||
    !decimal(result.expiresAtMs) ||
    !printable(result.reference, AGENT_HANDSHAKE_REFERENCE_MAX) ||
    !REPOSITORY_SHA_PATTERN.test(result.repositorySha) ||
    !UUID_PATTERN.test(result.sessionId) ||
    !DIGEST_PATTERN.test(result.statementDigest) ||
    initiator.address === responder.address
  ) invalid();
  publicKey(result.operatorPublicKey);
  return Object.freeze({ ...result, initiator, responder });
}

function operator(value) {
  const result = record(value, OPERATOR_KEYS);
  if (
    result.algorithm !== "ed25519" ||
    !KEY_ID_PATTERN.test(result.keyId) ||
    typeof result.signature !== "string" ||
    result.signature.length !== SIGNATURE_LENGTH ||
    !BASE64_PATTERN.test(result.signature) ||
    Buffer.from(result.signature, "base64").length !== 64
  ) invalid("AGENT_HANDSHAKE_DESCRIPTOR_SIGNATURE");
  publicKey(result.publicKey);
  return Object.freeze(result);
}

function envelope(value) {
  const result = record(value, ENVELOPE_KEYS);
  return Object.freeze({
    descriptor: descriptor(result.descriptor),
    operator: operator(result.operator),
  });
}

function keyFromRaw(value) {
  publicKey(value);
  return createPublicKey({
    format: "der",
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(value, "base64")]),
    type: "spki",
  });
}

function sameText(left, right) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export function rawAgentOperatorPublicKey(value) {
  try {
    const key = value?.type === "public" ? value : createPublicKey(value);
    const der = key.export({ format: "der", type: "spki" });
    if (
      der.length !== ED25519_SPKI_PREFIX.length + 32 ||
      !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
    ) invalid();
    return der.subarray(-32).toString("base64");
  } catch (error) {
    if (error instanceof AgentHandshakeDescriptorError) throw error;
    invalid();
  }
}

export function validateAgentDescriptor(value) {
  return descriptor(value);
}

export function agentDescriptorDigest(value) {
  return digestHex(descriptor(value));
}

export function createAgentDescriptorEnvelope(value, { keyId, privateKeyPem }) {
  const verified = descriptor(value);
  if (!KEY_ID_PATTERN.test(keyId)) invalid();
  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch {
    invalid();
  }
  if (!sameText(rawAgentOperatorPublicKey(createPublicKey(privateKey)), verified.operatorPublicKey)) {
    throw new OperatorKeyMismatchError();
  }
  const signature = sign(null, canonicalBytes(verified), privateKey).toString("base64");
  return envelope({
    descriptor: verified,
    operator: {
      algorithm: "ed25519",
      keyId,
      publicKey: verified.operatorPublicKey,
      signature,
    },
  });
}

export function verifyAgentDescriptorEnvelope(value, { expectedPublicKey }) {
  const verified = envelope(value);
  publicKey(expectedPublicKey);
  if (
    !sameText(verified.descriptor.operatorPublicKey, expectedPublicKey) ||
    !sameText(verified.operator.publicKey, expectedPublicKey)
  ) {
    throw new OperatorKeyMismatchError();
  }
  let accepted = false;
  try {
    accepted = verify(
      null,
      canonicalBytes(verified.descriptor),
      keyFromRaw(verified.operator.publicKey),
      Buffer.from(verified.operator.signature, "base64"),
    );
  } catch {
    accepted = false;
  }
  if (!accepted) invalid("AGENT_HANDSHAKE_DESCRIPTOR_SIGNATURE");
  return verified;
}
