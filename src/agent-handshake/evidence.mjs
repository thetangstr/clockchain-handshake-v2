import { types } from "node:util";

import { recoverMessageAddress } from "viem";

import { canonicalBytes } from "../core/canonical.mjs";
import {
  AGENT_HANDSHAKE_PROTOCOL,
  AGENT_HANDSHAKE_REFERENCE_MAX,
  AGENT_HANDSHAKE_ROLES,
} from "./constants.mjs";

export const AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA =
  "clockchain.agent-handshake-party-result/v1";
export const AGENT_HANDSHAKE_EVIDENCE_SCHEMA =
  "clockchain.agent-handshake-evidence/v1";

const RESULT_KEYS = Object.freeze([
  "externalActionPerformed",
  "party",
  "reference",
  "repositorySha",
  "role",
  "schema",
  "sessionDigest",
  "statementDigest",
  "transitionDigests",
]);
const PARTY_KEYS = Object.freeze(["address", "agentId"]);
const ENVELOPE_KEYS = Object.freeze(["result", "schema", "signature"]);
const SIGNATURE_KEYS = Object.freeze(["address", "algorithm", "value"]);
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;

export class AgentHandshakeEvidenceError extends Error {
  constructor() {
    super("Agent handshake evidence verification failed.");
    this.name = "AgentHandshakeEvidenceError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_EVIDENCE_INVALID";
  }
}

function invalid() {
  throw new AgentHandshakeEvidenceError();
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
      if (property?.enumerable !== true || !Object.hasOwn(property, "value")) {
        invalid();
      }
      result[key] = property.value;
    }
    return result;
  } catch (error) {
    if (error instanceof AgentHandshakeEvidenceError) throw error;
    invalid();
  }
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
    !DECIMAL_PATTERN.test(result.agentId)
  ) invalid();
  return Object.freeze(result);
}

function digestArray(value) {
  if (
    !Array.isArray(value) ||
    value.length !== 3 ||
    Reflect.ownKeys(value).length !== 4 ||
    value.some((entry) => typeof entry !== "string" || !DIGEST_PATTERN.test(entry))
  ) invalid();
  return Object.freeze([...value]);
}

function result(value) {
  const verified = record(value, RESULT_KEYS);
  const verifiedParty = party(verified.party);
  if (
    verified.schema !== AGENT_HANDSHAKE_PARTY_RESULT_SCHEMA ||
    verified.externalActionPerformed !== false ||
    !AGENT_HANDSHAKE_ROLES.includes(verified.role) ||
    !printable(verified.reference, AGENT_HANDSHAKE_REFERENCE_MAX) ||
    !SHA_PATTERN.test(verified.repositorySha) ||
    !DIGEST_PATTERN.test(verified.sessionDigest) ||
    !DIGEST_PATTERN.test(verified.statementDigest)
  ) invalid();
  return Object.freeze({
    ...verified,
    party: verifiedParty,
    transitionDigests: digestArray(verified.transitionDigests),
  });
}

function signature(value) {
  const verified = record(value, SIGNATURE_KEYS);
  if (
    !ADDRESS_PATTERN.test(verified.address) ||
    verified.algorithm !== "eip191" ||
    !SIGNATURE_PATTERN.test(verified.value)
  ) invalid();
  return Object.freeze(verified);
}

function envelope(value) {
  const verified = record(value, ENVELOPE_KEYS);
  if (verified.schema !== AGENT_HANDSHAKE_EVIDENCE_SCHEMA) invalid();
  return Object.freeze({
    result: result(verified.result),
    schema: verified.schema,
    signature: signature(verified.signature),
  });
}

function same(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

async function recoverAddress(value, signedResult) {
  try {
    return (await recoverMessageAddress({
      message: { raw: canonicalBytes(signedResult) },
      signature: value,
    })).toLowerCase();
  } catch {
    invalid();
  }
}

export async function signAgentHandshakeEvidence({ result: value, signMessage }) {
  const verified = result(value);
  if (typeof signMessage !== "function") invalid();
  let valueSignature;
  try {
    valueSignature = await signMessage(canonicalBytes(verified));
  } catch {
    invalid();
  }
  return envelope({
    result: verified,
    schema: AGENT_HANDSHAKE_EVIDENCE_SCHEMA,
    signature: {
      address: verified.party.address,
      algorithm: "eip191",
      value: valueSignature,
    },
  });
}

export async function verifyAgentHandshakeEvidence({
  envelope: value,
  expectedParty,
  expectedReference,
  expectedRepositorySha,
  expectedRole,
  expectedSessionDigest,
  expectedStatementDigest,
  expectedTransitionDigests,
}) {
  const verified = envelope(value);
  const verifiedExpectedParty = party(expectedParty);
  const expectedDigests = digestArray(expectedTransitionDigests);
  if (
    !AGENT_HANDSHAKE_ROLES.includes(expectedRole) ||
    !printable(expectedReference, AGENT_HANDSHAKE_REFERENCE_MAX) ||
    !SHA_PATTERN.test(expectedRepositorySha) ||
    !DIGEST_PATTERN.test(expectedSessionDigest) ||
    !DIGEST_PATTERN.test(expectedStatementDigest) ||
    verified.result.role !== expectedRole ||
    verified.result.reference !== expectedReference ||
    verified.result.repositorySha !== expectedRepositorySha ||
    verified.result.sessionDigest !== expectedSessionDigest ||
    verified.result.statementDigest !== expectedStatementDigest ||
    !same(verified.result.party, verifiedExpectedParty) ||
    !same(
      { transitionDigests: verified.result.transitionDigests },
      { transitionDigests: expectedDigests },
    ) ||
    verified.signature.address !== verifiedExpectedParty.address ||
    await recoverAddress(verified.signature.value, verified.result) !==
      verifiedExpectedParty.address
  ) invalid();
  return verified;
}

export const AGENT_HANDSHAKE_EVIDENCE_PROTOCOL = AGENT_HANDSHAKE_PROTOCOL;
