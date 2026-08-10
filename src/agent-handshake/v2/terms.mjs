import { types } from "node:util";

import { digestHex } from "../../core/canonical.mjs";
import {
  AGENT_HANDSHAKE_V2_IDENTITY_MODES,
  AGENT_HANDSHAKE_V2_MAX_VALID_FOR_SECONDS,
  AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS,
  AGENT_HANDSHAKE_V2_SEPOLIA_CHAIN,
} from "./constants.mjs";

const IDENTITY_POLICY_KEYS = Object.freeze([
  "erc8004",
  "chainId",
  "registryAddress",
]);
const TERMS_KEYS = Object.freeze([
  "reference",
  "statement",
  "validForSeconds",
  "identityPolicy",
]);
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const PRINTABLE = /^[ -~]+$/;

export class AgentHandshakeV2TermsError extends Error {
  constructor() {
    super("Agent handshake v2 terms are invalid.");
    this.name = "AgentHandshakeV2TermsError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_V2_TERMS_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeV2TermsError();
}

function exact(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) invalid();
    const actual = Reflect.ownKeys(value);
    if (
      actual.length !== keys.length ||
      actual.some((key) => typeof key !== "string" || !keys.includes(key))
    ) invalid();
    const result = {};
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeV2TermsError) throw error;
    invalid();
  }
}

function printable(value, max) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    PRINTABLE.test(value) &&
    value.trim() === value
  );
}

export function validateIdentityPolicy(value) {
  const policy = exact(value, IDENTITY_POLICY_KEYS);
  if (!AGENT_HANDSHAKE_V2_IDENTITY_MODES.includes(policy.erc8004)) invalid();
  if (policy.erc8004 === "not_required") {
    if (policy.chainId !== null || policy.registryAddress !== null) invalid();
  } else if (
    policy.chainId !== AGENT_HANDSHAKE_V2_SEPOLIA_CHAIN ||
    policy.registryAddress !== AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS
  ) invalid();
  return Object.freeze({
    erc8004: policy.erc8004,
    chainId: policy.chainId,
    registryAddress: policy.registryAddress,
  });
}

export function validateAgentHandshakeV2Terms(value) {
  const terms = exact(value, TERMS_KEYS);
  if (
    !printable(terms.reference, 128) ||
    !printable(terms.statement, 512) ||
    typeof terms.validForSeconds !== "string" ||
    !DECIMAL.test(terms.validForSeconds) ||
    BigInt(terms.validForSeconds) < 1n ||
    BigInt(terms.validForSeconds) > AGENT_HANDSHAKE_V2_MAX_VALID_FOR_SECONDS
  ) invalid();
  return Object.freeze({
    reference: terms.reference,
    statement: terms.statement,
    validForSeconds: terms.validForSeconds,
    identityPolicy: validateIdentityPolicy(terms.identityPolicy),
  });
}

export function agentHandshakeV2StatementDigest(value) {
  return digestHex(validateAgentHandshakeV2Terms(value));
}
