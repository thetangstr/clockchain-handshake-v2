import { createHash } from "node:crypto";
import { types } from "node:util";

import { recoverMessageAddress } from "viem";

import { canonicalBytes, digestHex } from "../core/canonical.mjs";
import { validateAgentHandshakeV2Party } from "../agent-handshake/v2/party.mjs";
import { validateLocalPolicy, localPolicyDigest } from "../agent-handshake/v2/policy.mjs";
import {
  validateAgentHandshakeV2AcceptancePayload,
  validateAgentHandshakeV2ProposalPayload,
} from "../agent-handshake/v2/protocol.mjs";
import { validateIdentityPolicy } from "../agent-handshake/v2/terms.mjs";
import { normalizeRegistrationForDirectSigner } from "./bindings.mjs";
import { DIRECT_AGENT_SIGNER_VERSION } from "./constants.mjs";

export const DIRECT_AGENT_CHECKPOINT_REQUEST_SCHEMA = "clockchain.direct-agent-signer-checkpoint-request/v1";
export const DIRECT_AGENT_CHECKPOINT_RESULT_SCHEMA = "clockchain.direct-agent-signer-checkpoint-result/v1";
export const COMMITMENT_CHECKPOINT_SCHEMA = "clockchain.agent-handshake-commitment-checkpoint/v1";

const SAFE_MESSAGE = "Direct agent signer failed safely.";
const REQUEST_KEYS = Object.freeze([
  "schema",
  "adapterVersion",
  "role",
  "sessionId",
  "repositorySha",
  "sessionDeadlineMs",
  "artifactType",
  "artifactPayload",
  "artifactSignatureHex",
  "previousCheckpoint",
  "issuedAtMs",
  "expiresAtMs",
  "externalBusinessActionPerformed",
]);
const CHECKPOINT_KEYS = Object.freeze([
  "artifactDigest",
  "artifactType",
  "expiresAtMs",
  "issuedAtMs",
  "previousCheckpointDigest",
  "protocol",
  "role",
  "schema",
  "sequence",
  "sessionId",
  "signature",
  "signerAddress",
  "version",
]);
const SIGNATURE_KEYS = Object.freeze(["address", "algorithm", "value"]);
const RESULT_KEYS = Object.freeze([
  "schema",
  "adapterVersion",
  "role",
  "sessionId",
  "artifactType",
  "checkpoint",
  "checkpointDigest",
  "signerAddress",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;

function invalid(diagnosticCode = "DIRECT_SIGNER_CHECKPOINT_INTERNAL_FAILURE") {
  const error = new Error(SAFE_MESSAGE);
  error.diagnosticCode = diagnosticCode;
  throw error;
}

function classify(code, operation) {
  try {
    return operation();
  } catch {
    invalid(code);
  }
}

async function classifyAsync(code, operation) {
  try {
    return await operation();
  } catch {
    invalid(code);
  }
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) invalid();
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

function checkpointCanonicalBytes(value, ancestors = new Set(), depth = 0) {
  function normalize(item, level) {
    if (level > 24) invalid();
    if (item === null || typeof item === "boolean") return item;
    if (typeof item === "string") {
      if (item.length === 0 || item.length > 512 || item.trim() !== item || !/^[ -~]+$/.test(item)) invalid();
      return item;
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item)) invalid();
      return item;
    }
    if (typeof item !== "object" || Array.isArray(item) || ancestors.has(item)) invalid();
    if (![Object.prototype, null].includes(Object.getPrototypeOf(item))) invalid();
    ancestors.add(item);
    try {
      const keys = Reflect.ownKeys(item);
      if (keys.length > 32 || keys.some((key) => typeof key !== "string")) invalid();
      const result = {};
      for (const key of keys.sort()) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
        result[key] = normalize(descriptor.value, level + 1);
      }
      return result;
    } finally {
      ancestors.delete(item);
    }
  }
  return Buffer.from(JSON.stringify(normalize(value, depth)), "utf8");
}

export function commitmentCheckpointSigningBytes(checkpoint) {
  const item = exact(checkpoint, CHECKPOINT_KEYS);
  const { signature: _signature, ...unsigned } = item;
  return checkpointCanonicalBytes(unsigned);
}

export function commitmentCheckpointDigest(checkpoint) {
  return createHash("sha256").update(checkpointCanonicalBytes(checkpoint)).digest("hex");
}

function signature(value, signerAddress) {
  const item = exact(value, SIGNATURE_KEYS);
  if (item.address !== signerAddress || item.algorithm !== "eip191" || !SIGNATURE.test(item.value)) invalid();
  return Object.freeze(item);
}

export function validateCommitmentCheckpoint(value) {
  const item = exact(value, CHECKPOINT_KEYS);
  if (
    item.schema !== COMMITMENT_CHECKPOINT_SCHEMA ||
    item.version !== "1" ||
    item.protocol !== "clockchain.agent-handshake/v2" ||
    !UUID.test(item.sessionId) ||
    !["initiator", "responder"].includes(item.role) ||
    !["proposal", "acceptance"].includes(item.artifactType) ||
    (item.artifactType === "proposal" ? item.role !== "initiator" : item.role !== "responder") ||
    !DIGEST.test(item.artifactDigest) ||
    item.sequence !== (item.artifactType === "proposal" ? "1" : "2") ||
    (item.artifactType === "proposal" ? item.previousCheckpointDigest !== null : !DIGEST.test(item.previousCheckpointDigest)) ||
    !DECIMAL.test(item.issuedAtMs) ||
    !DECIMAL.test(item.expiresAtMs) ||
    BigInt(item.issuedAtMs) >= BigInt(item.expiresAtMs) ||
    !ADDRESS.test(item.signerAddress)
  ) invalid();
  return Object.freeze({
    ...item,
    signature: signature(item.signature, item.signerAddress),
  });
}

function request(input) {
  const item = exact(input, REQUEST_KEYS);
  if (
    item.schema !== DIRECT_AGENT_CHECKPOINT_REQUEST_SCHEMA ||
    item.adapterVersion !== DIRECT_AGENT_SIGNER_VERSION ||
    !["initiator", "responder"].includes(item.role) ||
    !UUID.test(item.sessionId) ||
    !SHA.test(item.repositorySha) ||
    !DECIMAL.test(item.sessionDeadlineMs) ||
    !["proposal", "acceptance"].includes(item.artifactType) ||
    (item.artifactType === "proposal" ? item.role !== "initiator" : item.role !== "responder") ||
    !SIGNATURE.test(item.artifactSignatureHex) ||
    !DECIMAL.test(item.issuedAtMs) ||
    !DECIMAL.test(item.expiresAtMs) ||
    BigInt(item.issuedAtMs) >= BigInt(item.expiresAtMs) ||
    BigInt(item.expiresAtMs) > BigInt(item.sessionDeadlineMs) ||
    BigInt(item.expiresAtMs) - BigInt(item.issuedAtMs) > 60_000n ||
    item.externalBusinessActionPerformed !== false
  ) invalid();
  return item;
}

function verifyParty({ address, localPolicy, registration }) {
  const policy = validateLocalPolicy(localPolicy);
  const policyDigest = localPolicyDigest(policy);
  const identityPolicy = validateIdentityPolicy(policy.identityPolicy);
  const party = validateAgentHandshakeV2Party({
    sessionKeyAddress: address,
    policyDigest,
    erc8004: normalizeRegistrationForDirectSigner(registration, identityPolicy),
  }, { identityPolicy });
  return { party, policy, policyDigest };
}

function same(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

function validateArtifactPayload({ address, localPolicy, party, policyDigest, request: checkpointRequest }) {
  const payload = checkpointRequest.artifactType === "proposal"
    ? validateAgentHandshakeV2ProposalPayload(checkpointRequest.artifactPayload)
    : validateAgentHandshakeV2AcceptancePayload(checkpointRequest.artifactPayload);
  const roleParty = payload[checkpointRequest.role];
  if (
    payload.sessionId !== checkpointRequest.sessionId ||
    payload.repositorySha !== checkpointRequest.repositorySha ||
    payload.reference !== localPolicy.reference ||
    payload.statementDigest !== localPolicy.statementDigest ||
    payload.externalBusinessActionPerformed !== false ||
    !same(payload.identityPolicy, localPolicy.identityPolicy) ||
    !same(roleParty, party) ||
    roleParty.sessionKeyAddress !== address ||
    roleParty.policyDigest !== policyDigest ||
    !checkpointCanonicalBytes(payload).equals(canonicalBytes(payload))
  ) invalid();
  return payload;
}

async function verifyArtifactSignature({ address, artifactPayload, artifactSignatureHex }) {
  let recovered;
  try {
    recovered = await recoverMessageAddress({
      message: { raw: canonicalBytes(artifactPayload) },
      signature: artifactSignatureHex,
    });
  } catch {
    invalid();
  }
  if (recovered.toLowerCase() !== address) invalid();
}

function validatePrevious({ nowMs, previousCheckpoint, request: checkpointRequest }) {
  if (checkpointRequest.artifactType === "proposal") {
    if (previousCheckpoint !== null) invalid();
    return null;
  }
  const previous = validateCommitmentCheckpoint(previousCheckpoint);
  if (
    previous.artifactType !== "proposal" ||
    previous.role !== "initiator" ||
    previous.sequence !== "1" ||
    previous.sessionId !== checkpointRequest.sessionId ||
    nowMs >= Number(previous.expiresAtMs)
  ) invalid();
  return previous;
}

function buildUnsignedCheckpoint({ address, artifactPayload, previous, request: checkpointRequest }) {
  const envelope = {
    payload: artifactPayload,
    schema: `clockchain.agent-handshake-${checkpointRequest.artifactType}-envelope/v2`,
    signature: {
      address,
      algorithm: "eip191",
      value: checkpointRequest.artifactSignatureHex,
    },
  };
  return {
    schema: COMMITMENT_CHECKPOINT_SCHEMA,
    version: "1",
    protocol: "clockchain.agent-handshake/v2",
    sessionId: checkpointRequest.sessionId,
    role: checkpointRequest.role,
    artifactType: checkpointRequest.artifactType,
    artifactDigest: digestHex(envelope),
    sequence: checkpointRequest.artifactType === "proposal" ? "1" : "2",
    previousCheckpointDigest: previous === null ? null : commitmentCheckpointDigest(previous),
    issuedAtMs: checkpointRequest.issuedAtMs,
    expiresAtMs: checkpointRequest.expiresAtMs,
    signerAddress: address,
  };
}

export function validateDirectAgentCheckpointResult(input) {
  const result = exact(input, RESULT_KEYS);
  const checkpoint = validateCommitmentCheckpoint(result.checkpoint);
  if (
    result.schema !== DIRECT_AGENT_CHECKPOINT_RESULT_SCHEMA ||
    result.adapterVersion !== DIRECT_AGENT_SIGNER_VERSION ||
    result.role !== checkpoint.role ||
    result.sessionId !== checkpoint.sessionId ||
    result.artifactType !== checkpoint.artifactType ||
    result.checkpointDigest !== commitmentCheckpointDigest(checkpoint) ||
    result.signerAddress !== checkpoint.signerAddress
  ) invalid();
  return Object.freeze({ ...result, checkpoint });
}

export async function executeDirectAgentCheckpointRequest({
  address,
  localPolicy,
  nowMs,
  registration,
  request: input,
  sign,
} = {}) {
  try {
    const checkpointRequest = classify("DIRECT_SIGNER_CHECKPOINT_REQUEST_INVALID", () => request(input));
    if (
      typeof address !== "string" ||
      !ADDRESS.test(address) ||
      !Number.isSafeInteger(nowMs) ||
      Number(checkpointRequest.issuedAtMs) > nowMs ||
      typeof sign !== "function"
    ) invalid("DIRECT_SIGNER_CHECKPOINT_REQUEST_INVALID");
    if (
      nowMs >= Number(checkpointRequest.expiresAtMs) ||
      nowMs >= Number(checkpointRequest.sessionDeadlineMs)
    ) invalid("DIRECT_SIGNER_CHECKPOINT_SESSION_EXPIRED");
    const { party, policy, policyDigest } = classify(
      "DIRECT_SIGNER_CHECKPOINT_LOCAL_BINDING_INVALID",
      () => verifyParty({ address, localPolicy, registration }),
    );
    if (policy.role !== checkpointRequest.role) {
      invalid("DIRECT_SIGNER_CHECKPOINT_LOCAL_BINDING_INVALID");
    }
    const artifactPayload = classify("DIRECT_SIGNER_CHECKPOINT_ARTIFACT_INVALID", () => validateArtifactPayload({
      address,
      localPolicy: policy,
      party,
      policyDigest,
      request: checkpointRequest,
    }));
    await classifyAsync("DIRECT_SIGNER_CHECKPOINT_ARTIFACT_SIGNATURE_INVALID", () => verifyArtifactSignature({
      address,
      artifactPayload,
      artifactSignatureHex: checkpointRequest.artifactSignatureHex,
    }));
    const previous = classify("DIRECT_SIGNER_CHECKPOINT_PREVIOUS_INVALID", () => validatePrevious({
      nowMs,
      previousCheckpoint: checkpointRequest.previousCheckpoint,
      request: checkpointRequest,
    }));
    const unsigned = buildUnsignedCheckpoint({
      address,
      artifactPayload,
      previous,
      request: checkpointRequest,
    });
    const bytes = checkpointCanonicalBytes(unsigned);
    const expectedBytesSha256 = createHash("sha256").update(bytes).digest("hex");
    const signed = await classifyAsync("DIRECT_SIGNER_CHECKPOINT_SIGNING_FAILED", () => sign({
      bytesHex: `0x${bytes.toString("hex")}`,
      expectedBytesSha256,
    }));
    if (
      signed?.address?.toLowerCase() !== address ||
      signed?.bytesSha256 !== expectedBytesSha256 ||
      !SIGNATURE.test(signed?.signatureHex)
    ) invalid("DIRECT_SIGNER_CHECKPOINT_SIGNING_RESULT_INVALID");
    const checkpoint = classify("DIRECT_SIGNER_CHECKPOINT_RESULT_INVALID", () => validateCommitmentCheckpoint({
      ...unsigned,
      signature: { address, algorithm: "eip191", value: signed.signatureHex },
    }));
    return classify("DIRECT_SIGNER_CHECKPOINT_RESULT_INVALID", () => validateDirectAgentCheckpointResult({
      schema: DIRECT_AGENT_CHECKPOINT_RESULT_SCHEMA,
      adapterVersion: DIRECT_AGENT_SIGNER_VERSION,
      role: checkpoint.role,
      sessionId: checkpoint.sessionId,
      artifactType: checkpoint.artifactType,
      checkpoint,
      checkpointDigest: commitmentCheckpointDigest(checkpoint),
      signerAddress: checkpoint.signerAddress,
    }));
  } catch (error) {
    if (error?.message === SAFE_MESSAGE && typeof error?.diagnosticCode === "string") throw error;
    invalid("DIRECT_SIGNER_CHECKPOINT_INTERNAL_FAILURE");
  }
}
