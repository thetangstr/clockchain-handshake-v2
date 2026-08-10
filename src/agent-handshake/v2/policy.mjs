import { types } from "node:util";

import { digestHex } from "../../core/canonical.mjs";
import {
  AGENT_HANDSHAKE_V2_MAX_VALID_FOR_SECONDS,
  AGENT_HANDSHAKE_V2_MCP_ORIGIN,
  AGENT_HANDSHAKE_V2_POLICY_SCHEMA,
  AGENT_HANDSHAKE_V2_PROTOCOL,
  AGENT_HANDSHAKE_V2_ROLES,
} from "./constants.mjs";
import { validateIdentityPolicy } from "./terms.mjs";

const POLICY_KEYS = Object.freeze([
  "schema",
  "protocol",
  "role",
  "mcpOrigin",
  "reference",
  "statementDigest",
  "maxValidForSeconds",
  "identityPolicy",
  "externalBusinessActionsAllowed",
]);
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const DIGEST = /^[0-9a-f]{64}$/;
const PRINTABLE = /^[ -~]+$/;

export class AgentHandshakeV2PolicyError extends Error {
  constructor() {
    super("Agent handshake v2 local policy is invalid.");
    this.name = "AgentHandshakeV2PolicyError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_V2_POLICY_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeV2PolicyError();
}

function exact(value) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) invalid();
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== POLICY_KEYS.length ||
      keys.some((key) => typeof key !== "string" || !POLICY_KEYS.includes(key))
    ) invalid();
    const result = {};
    for (const key of POLICY_KEYS) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeV2PolicyError) throw error;
    invalid();
  }
}

export function validateLocalPolicy(value) {
  const policy = exact(value);
  if (
    policy.schema !== AGENT_HANDSHAKE_V2_POLICY_SCHEMA ||
    policy.protocol !== AGENT_HANDSHAKE_V2_PROTOCOL ||
    !AGENT_HANDSHAKE_V2_ROLES.includes(policy.role) ||
    policy.mcpOrigin !== AGENT_HANDSHAKE_V2_MCP_ORIGIN ||
    typeof policy.reference !== "string" ||
    policy.reference.length === 0 ||
    policy.reference.length > 128 ||
    !PRINTABLE.test(policy.reference) ||
    policy.reference.trim() !== policy.reference ||
    typeof policy.statementDigest !== "string" ||
    !DIGEST.test(policy.statementDigest) ||
    typeof policy.maxValidForSeconds !== "string" ||
    !DECIMAL.test(policy.maxValidForSeconds) ||
    BigInt(policy.maxValidForSeconds) < 1n ||
    BigInt(policy.maxValidForSeconds) > AGENT_HANDSHAKE_V2_MAX_VALID_FOR_SECONDS ||
    policy.externalBusinessActionsAllowed !== false
  ) invalid();
  let identityPolicy;
  try {
    identityPolicy = validateIdentityPolicy(policy.identityPolicy);
  } catch {
    invalid();
  }
  return Object.freeze({
    schema: policy.schema,
    protocol: policy.protocol,
    role: policy.role,
    mcpOrigin: policy.mcpOrigin,
    reference: policy.reference,
    statementDigest: policy.statementDigest,
    maxValidForSeconds: policy.maxValidForSeconds,
    identityPolicy,
    externalBusinessActionsAllowed: false,
  });
}

export function localPolicyDigest(value) {
  return digestHex(validateLocalPolicy(value));
}
