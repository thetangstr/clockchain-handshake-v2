import { createHash } from "node:crypto";
import { types } from "node:util";

import { canonicalBytes } from "../core/canonical.mjs";
import { decodeSigningBytes } from "../core/wallet-bridge.mjs";
import { validateLocalPolicy, localPolicyDigest } from "../agent-handshake/v2/policy.mjs";
import {
  validateAgentHandshakeV2AcceptancePayload,
  validateAgentHandshakeV2ProposalPayload,
} from "../agent-handshake/v2/protocol.mjs";
import { validateAgentHandshakeV2EvidenceResult } from "../agent-handshake/v2/evidence.mjs";
import {
  agentHandshakeV2StatementDigest,
  validateAgentHandshakeV2Terms,
} from "../agent-handshake/v2/terms.mjs";
import {
  agentHandshakeV2DescriptorDigest,
  verifyAgentHandshakeV2DescriptorEnvelope,
} from "../agent-handshake/v2/descriptor.mjs";
import { hostSessionKeyCertificateDigest } from "../agent-handshake/v2/host-key-certificate.mjs";
import { verifyPinnedHostSessionKey } from "./trust-roots.mjs";

export const AGENT_HANDSHAKE_HELPER_VERSION = "2.1.3";
export const AGENT_SIGNING_REQUEST_SCHEMA = "clockchain.agent-handshake-signing-request/v1";

const REQUEST_KEYS = Object.freeze([
  "schema", "helperVersion", "operation", "role", "sessionId", "repositorySha",
  "sessionDeadlineMs", "hostSessionKeyCertificate", "terms", "policyDigest",
  "descriptorEnvelope", "bytesGzipBase64Url", "bytesSha256",
  "externalBusinessActionPerformed",
]);
const OPERATIONS = Object.freeze(["identity_claim", "proposal", "acceptance", "evidence"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;

function invalid() { throw new Error("Agent handshake operation failed safely."); }

function exact(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) invalid();
  const result = {};
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
    result[key] = property.value;
  }
  return result;
}

function same(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

function identityClaim(value) {
  const keys = ["schema", "protocol", "sessionId", "repositorySha", "role", "sessionKeyAddress", "policyDigest", "statementDigest", "externalBusinessActionPerformed"];
  const item = exact(value, keys);
  if (
    item.schema !== "clockchain.agent-handshake-identity-claim/v2" ||
    item.protocol !== "clockchain.agent-handshake/v2" ||
    !UUID.test(item.sessionId) || !SHA.test(item.repositorySha) ||
    !["initiator", "responder"].includes(item.role) || !ADDRESS.test(item.sessionKeyAddress) ||
    !DIGEST.test(item.policyDigest) || !DIGEST.test(item.statementDigest) ||
    item.externalBusinessActionPerformed !== false
  ) invalid();
  return item;
}

function payloadFor(operation, value, identityPolicy) {
  if (operation === "identity_claim") return identityClaim(value);
  if (operation === "proposal") return validateAgentHandshakeV2ProposalPayload(value);
  if (operation === "acceptance") return validateAgentHandshakeV2AcceptancePayload(value);
  if (operation === "evidence") return validateAgentHandshakeV2EvidenceResult(value, { identityPolicy });
  invalid();
}

function assertPayloadBinding(payload, request, address, policy, statementDigest) {
  if (
    request.operation !== "evidence" && payload.sessionId !== request.sessionId ||
    payload.repositorySha !== request.repositorySha ||
    payload.role !== undefined && payload.role !== request.role ||
    payload.statementDigest !== statementDigest ||
    payload.externalBusinessActionPerformed !== false
  ) invalid();
  if (request.operation === "identity_claim" && (payload.sessionKeyAddress !== address || payload.policyDigest !== request.policyDigest)) invalid();
  if (request.operation === "proposal" && (request.role !== "initiator" || payload.initiator.sessionKeyAddress !== address || payload.initiator.policyDigest !== request.policyDigest)) invalid();
  if (request.operation === "acceptance" && (request.role !== "responder" || payload.responder.sessionKeyAddress !== address || payload.responder.policyDigest !== request.policyDigest)) invalid();
  if (request.operation === "evidence") {
    let descriptorEnvelope;
    try {
      descriptorEnvelope = verifyAgentHandshakeV2DescriptorEnvelope(request.descriptorEnvelope, {
        expectedPublicKey: request.hostSessionKey.certificate.sessionPublicKey,
        expectedHostSessionKeyCertificateDigest: hostSessionKeyCertificateDigest(
          request.hostSessionKey,
        ),
      });
    } catch {
      invalid();
    }
    const descriptor = descriptorEnvelope.descriptor;
    const party = descriptor[request.role];
    if (
      descriptor.sessionId !== request.sessionId ||
      descriptor.repositorySha !== request.repositorySha ||
      descriptor.reference !== policy.reference ||
      descriptor.statementDigest !== statementDigest ||
      agentHandshakeV2DescriptorDigest(descriptor) !== payload.sessionDigest ||
      !same(descriptor.identityPolicy, policy.identityPolicy) ||
      !same(party, payload.party) ||
      payload.party.sessionKeyAddress !== address ||
      payload.policyDigest !== request.policyDigest
    ) invalid();
  } else if (request.descriptorEnvelope !== null) invalid();
  if (payload.identityPolicy !== undefined && !same(payload.identityPolicy, policy.identityPolicy)) invalid();
  if (payload.reference !== undefined && payload.reference !== policy.reference) invalid();
  if (payload.issuedAtMs !== undefined) {
    const issuedAtMs = Number(payload.issuedAtMs);
    const expiresAtMs = Number(payload.expiresAtMs);
    if (
      !Number.isSafeInteger(issuedAtMs) ||
      !Number.isSafeInteger(expiresAtMs) ||
      request.nowMs < issuedAtMs ||
      request.nowMs >= expiresAtMs ||
      expiresAtMs > Number(request.sessionDeadlineMs) ||
      expiresAtMs - issuedAtMs < 1 ||
      expiresAtMs - issuedAtMs > Number(policy.maxValidForSeconds) * 1_000 ||
      request.operation === "proposal" &&
        expiresAtMs - issuedAtMs !== Number(policy.maxValidForSeconds) * 1_000
    ) invalid();
  }
}

export function validateAgentSigningRequest({ address, localPolicy, nowMs, request: input, rootKeyRing }) {
  const request = exact(input, REQUEST_KEYS);
  const policy = validateLocalPolicy(localPolicy);
  const terms = validateAgentHandshakeV2Terms(request.terms);
  if (
    request.schema !== AGENT_SIGNING_REQUEST_SCHEMA ||
    request.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
    !OPERATIONS.includes(request.operation) ||
    request.role !== policy.role ||
    !ADDRESS.test(address) ||
    !UUID.test(request.sessionId) ||
    !SHA.test(request.repositorySha) ||
    !DECIMAL.test(request.sessionDeadlineMs) ||
    !DIGEST.test(request.policyDigest) ||
    request.policyDigest !== localPolicyDigest(policy) ||
    request.externalBusinessActionPerformed !== false ||
    policy.externalBusinessActionsAllowed !== false ||
    terms.reference !== policy.reference ||
    terms.validForSeconds !== policy.maxValidForSeconds ||
    !same(terms.identityPolicy, policy.identityPolicy) ||
    !Number.isSafeInteger(nowMs) || nowMs >= Number(request.sessionDeadlineMs)
  ) invalid();
  const statementDigest = agentHandshakeV2StatementDigest(terms);
  if (statementDigest !== policy.statementDigest) invalid();
  const hostSessionKey = verifyPinnedHostSessionKey(request.hostSessionKeyCertificate, {
    expectedRepositorySha: request.repositorySha,
    expectedSessionId: request.sessionId,
    nowMs,
    rootKeyRing,
    sessionDeadlineMs: Number(request.sessionDeadlineMs),
  });
  let raw;
  try { raw = decodeSigningBytes({ bytesGzipBase64Url: request.bytesGzipBase64Url }); } catch { invalid(); }
  if (createHash("sha256").update(raw).digest("hex") !== request.bytesSha256) invalid();
  let parsed;
  try { parsed = JSON.parse(raw.toString("utf8")); } catch { invalid(); }
  const payload = payloadFor(request.operation, parsed, policy.identityPolicy);
  if (!canonicalBytes(payload).equals(raw)) invalid();
  assertPayloadBinding(
    payload,
    { ...request, hostSessionKey, nowMs },
    address,
    policy,
    statementDigest,
  );
  return Object.freeze({
    bytesGzipBase64Url: request.bytesGzipBase64Url,
    bytesSha256: request.bytesSha256,
    payload,
  });
}

export async function executeAgentSigningRequest(options) {
  const verified = validateAgentSigningRequest(options);
  if (typeof options.sign !== "function") invalid();
  let result;
  try { result = await options.sign({ bytesGzipBase64Url: verified.bytesGzipBase64Url }); } catch { invalid(); }
  if (
    result?.address?.toLowerCase() !== options.address ||
    result?.bytesSha256 !== verified.bytesSha256 ||
    !SIGNATURE.test(result?.signatureHex)
  ) invalid();
  return Object.freeze({
    address: options.address,
    bytesSha256: verified.bytesSha256,
    signatureHex: result.signatureHex,
  });
}
