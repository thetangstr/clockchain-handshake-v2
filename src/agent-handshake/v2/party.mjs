import { types } from "node:util";

import { validateIdentityPolicy } from "./terms.mjs";

const PARTY_KEYS = Object.freeze([
  "sessionKeyAddress",
  "policyDigest",
  "erc8004",
]);
const ERC8004_KEYS = Object.freeze([
  "agentId",
  "chainId",
  "registryAddress",
  "reference",
  "registrationTx",
  "registrationBlock",
]);
const ADDRESS = /^0x[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TRANSACTION = /^0x[0-9a-f]{64}$/;

export class AgentHandshakeV2PartyError extends Error {
  constructor() {
    super("Agent handshake v2 party is invalid.");
    this.name = "AgentHandshakeV2PartyError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_V2_PARTY_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeV2PartyError();
}

function exact(value, expectedKeys) {
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
      keys.length !== expectedKeys.length ||
      keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
    ) invalid();
    const result = {};
    for (const key of expectedKeys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeV2PartyError) throw error;
    invalid();
  }
}

function registration(value, identityPolicy) {
  const item = exact(value, ERC8004_KEYS);
  if (
    typeof item.agentId !== "string" ||
    !DECIMAL.test(item.agentId) ||
    item.chainId !== identityPolicy.chainId ||
    item.registryAddress !== identityPolicy.registryAddress ||
    item.reference !== item.chainId + ":" + item.registryAddress + ":" + item.agentId ||
    typeof item.registrationTx !== "string" ||
    !TRANSACTION.test(item.registrationTx) ||
    typeof item.registrationBlock !== "string" ||
    !DECIMAL.test(item.registrationBlock)
  ) invalid();
  return Object.freeze({
    agentId: item.agentId,
    chainId: item.chainId,
    registryAddress: item.registryAddress,
    reference: item.reference,
    registrationTx: item.registrationTx,
    registrationBlock: item.registrationBlock,
  });
}

export function validateAgentHandshakeV2Party(value, { identityPolicy: rawPolicy } = {}) {
  const party = exact(value, PARTY_KEYS);
  let identityPolicy;
  try {
    identityPolicy = validateIdentityPolicy(rawPolicy);
  } catch {
    invalid();
  }
  if (
    typeof party.sessionKeyAddress !== "string" ||
    !ADDRESS.test(party.sessionKeyAddress) ||
    typeof party.policyDigest !== "string" ||
    !DIGEST.test(party.policyDigest)
  ) invalid();
  const erc8004 = identityPolicy.erc8004 === "not_required"
    ? party.erc8004 === null ? null : invalid()
    : party.erc8004 === null ? invalid() : registration(party.erc8004, identityPolicy);
  return Object.freeze({
    sessionKeyAddress: party.sessionKeyAddress,
    policyDigest: party.policyDigest,
    erc8004,
  });
}
