import { isAbsolute, join } from "node:path";
import { types } from "node:util";

import * as walletBridge from "../core/wallet-bridge.mjs";
import { validateIdentityPolicy } from "../agent-handshake/v2/terms.mjs";
import { validateAgentHandshakeV2Party } from "../agent-handshake/v2/party.mjs";
import { verifyAgentHandshakeV2Result } from "../agent-handshake/v2/result.mjs";
import { commitAgentPolicy, readAgentPolicy } from "./policy.mjs";
import {
  AGENT_HANDSHAKE_HELPER_VERSION,
  executeAgentSigningRequest,
} from "./signing-request.mjs";
import {
  EMBEDDED_HOST_ROOT_KEY_RING,
  validateHostRootKeyRing,
} from "./trust-roots.mjs";

export const AGENT_CLI_OPERATIONS = Object.freeze([
  "init", "policy", "inspect", "register", "sign", "verify-certificate",
]);
const RESULT_SCHEMA = "clockchain.agent-handshake-cli-result/v1";
const VERIFY_SCHEMA = "clockchain.agent-handshake-certificate-verification/v1";
const VERIFY_KEYS = Object.freeze([
  "schema", "helperVersion", "role", "sessionId", "repositorySha",
  "sessionDeadlineMs", "certificate", "externalBusinessActionPerformed",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

function invalid() { throw new Error("Agent handshake operation failed safely."); }
function pathFor(stateDir) {
  if (typeof stateDir !== "string" || !isAbsolute(stateDir)) invalid();
  return join(stateDir, "wallet.json");
}
function result(operation, value) {
  return Object.freeze({ schema: RESULT_SCHEMA, helperVersion: AGENT_HANDSHAKE_HELPER_VERSION, operation, ...value });
}
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
function publicRegistration(record, identityPolicy) {
  if (identityPolicy.erc8004 === "not_required") return null;
  if (record === null) return null;
  if (record?.schema !== "clockchain.handshake-registration-recovery/v1") invalid();
  const registration = {
    agentId: record.agentId,
    chainId: identityPolicy.chainId,
    registryAddress: identityPolicy.registryAddress,
    reference: `${identityPolicy.chainId}:${identityPolicy.registryAddress}:${record.agentId}`,
    registrationTx: record.registerTx.toLowerCase(),
    registrationBlock: record.registerBlock,
  };
  return registration;
}
function registrationResult(value, identityPolicy) {
  return {
    agentId: value.agentId,
    chainId: identityPolicy.chainId,
    registryAddress: identityPolicy.registryAddress,
    reference: `${identityPolicy.chainId}:${identityPolicy.registryAddress}:${value.agentId}`,
    registrationTx: value.transaction?.register?.toLowerCase(),
    registrationBlock: value.block?.register,
  };
}
async function policyOrNull(options) {
  try { return await readAgentPolicy(options); } catch (error) { if (error?.code === "ENOENT") return null; throw error; }
}

export function createAgentCliOperations({
  bridge = walletBridge,
  now = Date.now,
  platform = process.platform,
  rootKeyRing = EMBEDDED_HOST_ROOT_KEY_RING,
  runIcacls,
} = {}) {
  async function inspect(stateDir) {
    const wallet = await bridge.inspectWallet({ statePath: pathFor(stateDir), platform, runIcacls });
    const committed = await policyOrNull({ stateDir, platform, runIcacls });
    return { wallet, committed };
  }
  async function dispatch({ operation, stateDir, payload } = {}) {
    if (!AGENT_CLI_OPERATIONS.includes(operation)) invalid();
    try {
      if (operation === "init") {
        return result(operation, await bridge.initializeWallet({ statePath: pathFor(stateDir), platform, runIcacls }));
      }
      if (operation === "policy") {
        await bridge.inspectWallet({ statePath: pathFor(stateDir), platform, runIcacls });
        return result(operation, await commitAgentPolicy({ stateDir, policy: payload, platform, runIcacls }));
      }
      const { wallet, committed } = await inspect(stateDir);
      if (operation === "inspect") {
        return result(operation, {
          address: wallet.address.toLowerCase(),
          policyDigest: committed?.policyDigest ?? null,
          registration: committed === null ? null : publicRegistration(wallet.registration, committed.policy.identityPolicy),
        });
      }
      if (committed === null) invalid();
      if (operation === "register") {
        const identityPolicy = validateIdentityPolicy(committed.policy.identityPolicy);
        if (identityPolicy.erc8004 === "not_required") invalid();
        const registered = await bridge.registerWalletIdentity({
          displayName: `Clockchain ${committed.policy.role} ${committed.policy.reference}`,
          statePath: pathFor(stateDir),
          platform,
          runIcacls,
        });
        const registration = registrationResult(registered, identityPolicy);
        validateAgentHandshakeV2Party({
          sessionKeyAddress: wallet.address.toLowerCase(),
          policyDigest: committed.policyDigest,
          erc8004: registration,
        }, { identityPolicy });
        return result(operation, { address: wallet.address.toLowerCase(), registration });
      }
      if (operation === "sign") {
        const signed = await executeAgentSigningRequest({
          address: wallet.address.toLowerCase(),
          localPolicy: committed.policy,
          nowMs: now(),
          request: payload,
          rootKeyRing,
          sign: (input) => bridge.signExactBytes({ ...input, statePath: pathFor(stateDir), platform, runIcacls }),
        });
        return result(operation, signed);
      }
      const request = exact(payload, VERIFY_KEYS);
      if (
        request.schema !== VERIFY_SCHEMA || request.helperVersion !== AGENT_HANDSHAKE_HELPER_VERSION ||
        request.role !== committed.policy.role || !UUID.test(request.sessionId) ||
        !SHA.test(request.repositorySha) || !DECIMAL.test(request.sessionDeadlineMs) ||
        request.externalBusinessActionPerformed !== false
      ) invalid();
      const party = validateAgentHandshakeV2Party({
        sessionKeyAddress: wallet.address.toLowerCase(),
        policyDigest: committed.policyDigest,
        erc8004: publicRegistration(wallet.registration, committed.policy.identityPolicy),
      }, { identityPolicy: committed.policy.identityPolicy });
      const activeRootKeyRing = validateHostRootKeyRing(rootKeyRing, { nowMs: now() });
      return result(operation, verifyAgentHandshakeV2Result(request.certificate, {
        expectedParty: party,
        expectedPolicyDigest: committed.policyDigest,
        expectedRepositorySha: request.repositorySha,
        expectedRole: request.role,
        expectedSessionId: request.sessionId,
        nowMs: now(),
        rootKeyRing: activeRootKeyRing,
        sessionDeadlineMs: Number(request.sessionDeadlineMs),
      }));
    } catch (error) {
      if (error?.message === "Agent handshake operation failed safely.") throw error;
      invalid();
    }
  }
  return Object.freeze({ dispatch, names: AGENT_CLI_OPERATIONS });
}
