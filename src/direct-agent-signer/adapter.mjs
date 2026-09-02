import { createHash } from "node:crypto";
import { isAbsolute, join } from "node:path";
import { types } from "node:util";

import * as walletBridge from "../core/wallet-bridge.mjs";
import { canonicalBytes } from "../core/canonical.mjs";
import { validateAgentHandshakeV2Party } from "../agent-handshake/v2/party.mjs";
import { validateLocalPolicy, localPolicyDigest } from "../agent-handshake/v2/policy.mjs";
import { verifyAgentHandshakeV2Result } from "../agent-handshake/v2/result.mjs";
import { validateIdentityPolicy } from "../agent-handshake/v2/terms.mjs";
import { readAgentPolicy } from "../agent-cli/policy.mjs";
import { decodeSigningBytes } from "../core/wallet-bridge.mjs";
import {
  EMBEDDED_HOST_ROOT_KEY_RING,
  validateHostRootKeyRing,
} from "../agent-cli/trust-roots.mjs";
import {
  executeDirectAgentCheckpointRequest,
  validateDirectAgentCheckpointResult,
} from "./checkpoint.mjs";
export {
  DIRECT_AGENT_SIGNER_PURPOSES,
  DIRECT_AGENT_SIGNER_REQUEST_SCHEMA,
  DIRECT_AGENT_SIGNER_RESULT_SCHEMA,
  DIRECT_AGENT_SIGNER_VERSION,
} from "./constants.mjs";
import {
  DIRECT_AGENT_SIGNER_PURPOSES,
  DIRECT_AGENT_SIGNER_REQUEST_SCHEMA,
  DIRECT_AGENT_SIGNER_RESULT_SCHEMA,
  DIRECT_AGENT_SIGNER_VERSION,
} from "./constants.mjs";
import { normalizeRegistrationForDirectSigner } from "./bindings.mjs";

const SAFE_MESSAGE = "Direct agent signer failed safely.";
const REQUEST_KEYS = Object.freeze([
  "schema",
  "role",
  "purpose",
  "sessionId",
  "repositorySha",
  "sessionDeadlineMs",
  "retainedV2Certificate",
  "bytesGzipBase64Url",
  "bytesSha256",
  "externalBusinessActionPerformed",
]);
const RESULT_KEYS = Object.freeze([
  "schema",
  "adapterVersion",
  "address",
  "bytesSha256",
  "purpose",
  "role",
  "sessionId",
  "signatureHex",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;

function invalid(diagnosticCode = "DIRECT_SIGNER_INTERNAL_FAILURE") {
  const error = new Error(SAFE_MESSAGE);
  error.diagnosticCode = diagnosticCode;
  throw error;
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

function pathFor(stateDir) {
  if (typeof stateDir !== "string" || !isAbsolute(stateDir)) invalid();
  return join(stateDir, "wallet.json");
}

function validateRequest(input, policy) {
  const request = exact(input, REQUEST_KEYS);
  if (
    request.schema !== DIRECT_AGENT_SIGNER_REQUEST_SCHEMA ||
    request.role !== policy.role ||
    !DIRECT_AGENT_SIGNER_PURPOSES.includes(request.purpose) ||
    !UUID.test(request.sessionId) ||
    !SHA.test(request.repositorySha) ||
    !DECIMAL.test(request.sessionDeadlineMs) ||
    !DIGEST.test(request.bytesSha256) ||
    request.externalBusinessActionPerformed !== false
  ) invalid();
  return request;
}

function verifyCanonicalJsonBytes(request) {
  let raw;
  try {
    raw = decodeSigningBytes({ bytesGzipBase64Url: request.bytesGzipBase64Url });
  } catch {
    invalid();
  }
  if (createHash("sha256").update(raw).digest("hex") !== request.bytesSha256) invalid();
  let parsed;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    invalid();
  }
  if (!canonicalBytes(parsed).equals(raw)) invalid();
}

function validateLocalRoleBinding({ address, policy, registration }) {
  const policyDigest = localPolicyDigest(policy);
  const identityPolicy = validateIdentityPolicy(policy.identityPolicy);
  const party = validateAgentHandshakeV2Party({
    sessionKeyAddress: address,
    policyDigest,
    erc8004: normalizeRegistrationForDirectSigner(registration, identityPolicy),
  }, { identityPolicy });
  return { identityPolicy, party, policyDigest };
}

export function validateDirectAgentSigningResult(input) {
  let result;
  try {
    result = exact(input, RESULT_KEYS);
  } catch {
    invalid("DIRECT_SIGNER_RESULT_INVALID");
  }
  if (
    result.schema !== DIRECT_AGENT_SIGNER_RESULT_SCHEMA ||
    result.adapterVersion !== DIRECT_AGENT_SIGNER_VERSION ||
    !ADDRESS.test(result.address) ||
    !DIGEST.test(result.bytesSha256) ||
    !DIRECT_AGENT_SIGNER_PURPOSES.includes(result.purpose) ||
    !["initiator", "responder"].includes(result.role) ||
    !UUID.test(result.sessionId) ||
    !SIGNATURE.test(result.signatureHex)
  ) invalid("DIRECT_SIGNER_RESULT_INVALID");
  return Object.freeze(result);
}

export function validateDirectAgentSigningRequest({
  address,
  localPolicy,
  nowMs,
  registration,
  request: input,
  rootKeyRing,
} = {}) {
  let policy;
  try {
    policy = validateLocalPolicy(localPolicy);
  } catch {
    invalid("DIRECT_SIGNER_LOCAL_POLICY_INVALID");
  }
  let request;
  try {
    request = validateRequest(input, policy);
  } catch {
    invalid("DIRECT_SIGNER_REQUEST_INVALID");
  }
  if (
    typeof address !== "string" ||
    !ADDRESS.test(address) ||
    !Number.isSafeInteger(nowMs)
  ) invalid("DIRECT_SIGNER_REQUEST_INVALID");
  if (nowMs >= Number(request.sessionDeadlineMs)) {
    invalid("DIRECT_SIGNER_SESSION_EXPIRED");
  }
  let party;
  let policyDigest;
  try {
    ({ party, policyDigest } = validateLocalRoleBinding({ address, policy, registration }));
  } catch {
    invalid("DIRECT_SIGNER_LOCAL_BINDING_INVALID");
  }
  try {
    verifyCanonicalJsonBytes(request);
  } catch {
    invalid("DIRECT_SIGNER_CANONICAL_BYTES_INVALID");
  }
  if (request.purpose === "agent_contract_direct_identity") {
    if (request.retainedV2Certificate !== null) {
      invalid("DIRECT_SIGNER_CERTIFICATE_BOUNDARY_INVALID");
    }
    return Object.freeze({
      address,
      bytesGzipBase64Url: request.bytesGzipBase64Url,
      bytesSha256: request.bytesSha256,
      purpose: request.purpose,
      role: request.role,
      sessionId: request.sessionId,
    });
  }
  if (request.retainedV2Certificate === null) {
    invalid("DIRECT_SIGNER_CERTIFICATE_REQUIRED");
  }
  let activeRootKeyRing;
  try {
    activeRootKeyRing = validateHostRootKeyRing(rootKeyRing, { nowMs });
  } catch {
    invalid("DIRECT_SIGNER_ROOT_RING_INVALID");
  }
  let verified;
  try {
    verified = verifyAgentHandshakeV2Result(request.retainedV2Certificate, {
      expectedParty: party,
      expectedPolicyDigest: policyDigest,
      expectedRepositorySha: request.repositorySha,
      expectedRole: request.role,
      expectedSessionId: request.sessionId,
      nowMs,
      rootKeyRing: activeRootKeyRing,
      sessionDeadlineMs: Number(request.sessionDeadlineMs),
    });
  } catch {
    invalid("DIRECT_SIGNER_CERTIFICATE_INVALID");
  }
  if (
    verified.externalBusinessActionPerformed !== false ||
    verified.identity.sessionKeyAddress !== address ||
    verified.policyDigest !== policyDigest ||
    verified.role !== request.role ||
    verified.sessionId !== request.sessionId
  ) invalid("DIRECT_SIGNER_CERTIFICATE_BINDING_INVALID");
  return Object.freeze({
    address,
    bytesGzipBase64Url: request.bytesGzipBase64Url,
    bytesSha256: request.bytesSha256,
    purpose: request.purpose,
    role: request.role,
    sessionId: request.sessionId,
  });
}

export async function executeDirectAgentSigningRequest(options = {}) {
  try {
    const verified = validateDirectAgentSigningRequest(options);
    if (typeof options.sign !== "function") {
      invalid("DIRECT_SIGNER_SIGNING_BACKEND_INVALID");
    }
    let signed;
    try {
      signed = await options.sign({ bytesGzipBase64Url: verified.bytesGzipBase64Url });
    } catch {
      invalid("DIRECT_SIGNER_SIGNING_FAILED");
    }
    if (
      signed?.address?.toLowerCase() !== verified.address ||
      signed?.bytesSha256 !== verified.bytesSha256 ||
      !SIGNATURE.test(signed?.signatureHex)
    ) invalid("DIRECT_SIGNER_SIGNING_RESULT_INVALID");
    return validateDirectAgentSigningResult({
      schema: DIRECT_AGENT_SIGNER_RESULT_SCHEMA,
      adapterVersion: DIRECT_AGENT_SIGNER_VERSION,
      address: verified.address,
      bytesSha256: verified.bytesSha256,
      purpose: verified.purpose,
      role: verified.role,
      sessionId: verified.sessionId,
      signatureHex: signed.signatureHex,
    });
  } catch (error) {
    if (error?.message === SAFE_MESSAGE && typeof error?.diagnosticCode === "string") throw error;
    invalid();
  }
}

export function createDirectAgentSignerOperations({
  bridge = walletBridge,
  now = Date.now,
  platform = process.platform,
  rootKeyRing = EMBEDDED_HOST_ROOT_KEY_RING,
  runIcacls,
} = {}) {
  async function dispatch({ operation, stateDir, payload } = {}) {
    if (!["sign", "checkpoint"].includes(operation)) invalid();
    try {
      let committed;
      try {
        committed = await readAgentPolicy({ stateDir, platform, runIcacls });
      } catch {
        invalid("DIRECT_SIGNER_LOCAL_POLICY_STATE_INVALID");
      }
      let wallet;
      try {
        wallet = await bridge.inspectWallet({
          statePath: pathFor(stateDir),
          platform,
          runIcacls,
        });
      } catch {
        invalid("DIRECT_SIGNER_ROLE_WALLET_STATE_INVALID");
      }
      if (operation === "checkpoint") {
        return validateDirectAgentCheckpointResult(await executeDirectAgentCheckpointRequest({
          address: wallet.address.toLowerCase(),
          localPolicy: committed.policy,
          nowMs: now(),
          registration: wallet.registration,
          request: payload,
          sign: (input) => bridge.signExactBytes({
            bytesHex: input.bytesHex,
            statePath: pathFor(stateDir),
            platform,
            runIcacls,
          }),
        }));
      }
      return await executeDirectAgentSigningRequest({
        address: wallet.address.toLowerCase(),
        localPolicy: committed.policy,
        nowMs: now(),
        registration: wallet.registration,
        request: payload,
        rootKeyRing,
        sign: (input) => bridge.signExactBytes({
          ...input,
          statePath: pathFor(stateDir),
          platform,
          runIcacls,
        }),
      });
    } catch (error) {
      if (error?.message === SAFE_MESSAGE && typeof error?.diagnosticCode === "string") throw error;
      invalid();
    }
  }
  return Object.freeze({ dispatch, names: Object.freeze(["sign", "checkpoint"]) });
}
