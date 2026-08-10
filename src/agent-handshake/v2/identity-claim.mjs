import { types } from "node:util";
import { recoverMessageAddress } from "viem";

import { canonicalBytes } from "../../core/canonical.mjs";

const CLAIM_KEYS = Object.freeze([
  "schema", "protocol", "sessionId", "repositorySha", "role",
  "sessionKeyAddress", "policyDigest", "statementDigest",
  "externalBusinessActionPerformed",
]);
const ENVELOPE_KEYS = Object.freeze(["claim", "signature"]);
const SIGNATURE_KEYS = Object.freeze(["address", "algorithm", "value"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;

export class AgentHandshakeV2IdentityClaimError extends Error {
  constructor() {
    super("Agent handshake v2 identity claim verification failed.");
    this.name = "AgentHandshakeV2IdentityClaimError";
    this.category = "verification";
    this.code = "AGENT_HANDSHAKE_V2_IDENTITY_CLAIM_INVALID";
  }
}

function invalid() { throw new AgentHandshakeV2IdentityClaimError(); }

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
    if (error instanceof AgentHandshakeV2IdentityClaimError) throw error;
    invalid();
  }
}

export function validateAgentHandshakeV2IdentityClaim(value) {
  const item = exact(value, CLAIM_KEYS);
  if (
    item.schema !== "clockchain.agent-handshake-identity-claim/v2" ||
    item.protocol !== "clockchain.agent-handshake/v2" ||
    !UUID.test(item.sessionId) || !SHA.test(item.repositorySha) ||
    !["initiator", "responder"].includes(item.role) ||
    !ADDRESS.test(item.sessionKeyAddress) || !DIGEST.test(item.policyDigest) ||
    !DIGEST.test(item.statementDigest) ||
    item.externalBusinessActionPerformed !== false
  ) invalid();
  return Object.freeze(item);
}

function envelope(value) {
  const item = exact(value, ENVELOPE_KEYS);
  const claim = validateAgentHandshakeV2IdentityClaim(item.claim);
  const signature = exact(item.signature, SIGNATURE_KEYS);
  if (
    !ADDRESS.test(signature.address) || signature.algorithm !== "eip191" ||
    !SIGNATURE.test(signature.value) || signature.address !== claim.sessionKeyAddress
  ) invalid();
  return Object.freeze({ claim, signature: Object.freeze(signature) });
}

export async function verifyAgentHandshakeV2IdentityClaimEnvelope(value, {
  expectedRepositorySha,
  expectedRole,
  expectedSessionId,
  expectedStatementDigest,
} = {}) {
  const verified = envelope(value);
  if (
    verified.claim.repositorySha !== expectedRepositorySha ||
    verified.claim.role !== expectedRole ||
    verified.claim.sessionId !== expectedSessionId ||
    verified.claim.statementDigest !== expectedStatementDigest
  ) invalid();
  let recovered;
  try {
    recovered = (await recoverMessageAddress({
      message: { raw: canonicalBytes(verified.claim) },
      signature: verified.signature.value,
    })).toLowerCase();
  } catch { invalid(); }
  if (recovered !== verified.claim.sessionKeyAddress) invalid();
  return verified;
}
