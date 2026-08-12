import { createHash } from "node:crypto";
import { types } from "node:util";

import { validateLocalRuntimeEvidence, validateRuntimePairEvidence } from "../runtime/runtime-adapter-contract.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);
const CONTROLLER_KEYS = Object.freeze([
  "costTags", "executePair", "harnessAdapters", "networkPolicy", "roles", "runtimeAdapter",
  "livePreflight", "requireLiveEvidence", "sessionId", "ttlMs",
]);
const ROLE_KEYS = Object.freeze(["harness", "secretsRef", "stateRef"]);
const PUBLIC_RUNTIME_KEYS = Object.freeze(["harness", "role", "runtimeId"]);
const HARNESS_CAPABILITY_KEYS = Object.freeze(["harness", "rawPayloadTransport", "retainedLocalActions", "schema"]);
const LIVE_PREFLIGHT_KEYS = Object.freeze(["deploymentReady", "directA2A", "imageProvenanceVerified", "mcpUrl", "pair", "schema", "sourceCommit"]);
const LIVE_ARTIFACT_KEYS = Object.freeze([
  "certificateDigest", "certificateVerified", "cleanup", "clients", "directA2A", "roles", "runtimeBindings",
  "schema", "sessionId", "sourceCommit",
]);
const LIVE_A2A_KEYS = Object.freeze(["agentCardDigests", "commitmentCheckpointDigests", "controllerRoutedRawContent", "envelopeDigests"]);
const LIVE_ROLE_KEYS = Object.freeze(["address", "erc8004AgentId"]);
const LIVE_RUNTIME_BINDING_KEYS = Object.freeze(["runtimeEvidenceDigest", "runtimeId", "taskArn"]);
const RUNTIME_METHODS = Object.freeze([
  "attestRuntime", "collectRuntimeEvidence", "destroyRuntime", "provisionPartyRuntime",
  "streamRuntimeEvents", "terminateRuntime",
]);
const HARNESS_METHODS = Object.freeze(["inspectCapabilities"]);
const SHA256 = /^[0-9a-f]{64}$/;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function fail() {
  throw new Error("Mechanics-proof controller validation failed safely.");
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(descriptors);
  if (
    actual.some((key) => typeof key !== "string") ||
    actual.length !== keys.length ||
    actual.some((key) => !keys.includes(key))
  ) fail();
  const snapshot = {};
  for (const key of actual) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function controllerConfig(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const present = new Set(Reflect.ownKeys(descriptors));
  if ([...present].some((key) => typeof key !== "string")) fail();
  const item = exactObject(value, CONTROLLER_KEYS.filter((key) => {
    if (key === "requireLiveEvidence") return present.has(key);
    if (key === "livePreflight") return present.has(key);
    return true;
  }));
  return Object.freeze({ requireLiveEvidence: false, livePreflight: null, ...item });
}

function rejectAuthorityFields(value) {
  if (value === null || value === undefined) return;
  if (typeof value === "object" && types.isProxy(value)) fail();
  if (Array.isArray(value)) {
    for (const item of value) rejectAuthorityFields(item);
    return;
  }
  if (typeof value !== "object") return;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") fail();
    const descriptor = descriptors[key];
    if (!descriptor.enumerable) continue;
    if (!Object.hasOwn(descriptor, "value")) fail();
    if (/(?:private.?key|secret.?key|controller.?private.?key|signer|terms|mandate)/i.test(key)) fail();
    rejectAuthorityFields(descriptor.value);
  }
}

function roleConfig(value) {
  const item = exactObject(value, ROLE_KEYS);
  if (
    typeof item.harness !== "string" || item.harness.length === 0 ||
    typeof item.secretsRef !== "string" || item.secretsRef.length === 0 ||
    typeof item.stateRef !== "string" || item.stateRef.length === 0
  ) fail();
  return Object.freeze({ ...item });
}

function exactRoleObject(value) {
  const item = exactObject(value, ROLES);
  return Object.freeze({
    initiator: roleConfig(item.initiator),
    responder: roleConfig(item.responder),
  });
}

function methodSurface(adapter, methods) {
  if (adapter === null || typeof adapter !== "object" || types.isProxy(adapter)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(adapter);
  for (const method of methods) {
    const descriptor = descriptors[method];
    if (!descriptor || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail();
  }
  return adapter;
}

function publicRuntimeDescriptor(value, role) {
  rejectAuthorityFields(value);
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  if (
    typeof value.runtimeId !== "string" || value.runtimeId.length === 0 ||
    value.role !== role ||
    typeof value.harness !== "string" || value.harness.length === 0
  ) fail();
  return Object.freeze({
    runtimeId: value.runtimeId,
    role,
    harness: value.harness,
  });
}

function cleanupRuntimeReference(value, role) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    typeof value.runtimeId !== "string" || value.runtimeId.length === 0
  ) fail();
  return Object.freeze({ runtimeId: value.runtimeId, role });
}

function validateHarnessCapabilities(value, role, harness) {
  rejectAuthorityFields(value);
  const item = exactObject(value, HARNESS_CAPABILITY_KEYS);
  if (
    item.schema !== "clockchain.harness-capabilities/v1" ||
    item.harness !== harness ||
    item.retainedLocalActions !== true ||
    item.rawPayloadTransport !== false
  ) fail();
  return Object.freeze({ ...item });
}

function frozenRuntimes(runtimes) {
  return Object.freeze({
    initiator: Object.freeze({ ...runtimes.initiator }),
    responder: Object.freeze({ ...runtimes.responder }),
  });
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function assertDigest(value) {
  if (typeof value !== "string" || !SHA256.test(value)) fail();
}

function assertDigestArray(value) {
  if (value === null || typeof value !== "object" || types.isProxy(value) || !Array.isArray(value) || value.length < 1 || value.length > 32) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    assertDigest(descriptor.value);
    result.push(descriptor.value);
  }
  if (Reflect.ownKeys(descriptors).some((key) => key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(String(key)))) fail();
  return Object.freeze(result);
}

function validateLivePreflight(value) {
  const item = exactObject(value, LIVE_PREFLIGHT_KEYS);
  if (
    item.schema !== "clockchain.fargate-live-preflight/v1" ||
    !SOURCE_COMMIT.test(item.sourceCommit) ||
    item.pair !== "codex:claude" ||
    item.directA2A !== true ||
    item.mcpUrl !== "https://mcp.clockchain.network/handshake/mcp" ||
    item.deploymentReady !== false ||
    item.imageProvenanceVerified !== false
  ) fail();
  return Object.freeze({ ...item });
}

function validateLiveRole(value) {
  const item = exactObject(value, LIVE_ROLE_KEYS);
  if (!EVM_ADDRESS.test(item.address) || typeof item.erc8004AgentId !== "string" || item.erc8004AgentId.length === 0) fail();
  return Object.freeze({ address: item.address.toLowerCase(), erc8004AgentId: item.erc8004AgentId });
}

function validateLiveRuntimeBinding(value, runtime, role) {
  const item = exactObject(value, LIVE_RUNTIME_BINDING_KEYS);
  if (
    item.runtimeId !== runtime.runtimeId ||
    item.taskArn !== runtime.taskArn ||
    item.runtimeEvidenceDigest !== digest(runtime)
  ) fail();
  return Object.freeze({ ...item });
}

function validateLiveHandshakeEvidence(value, { sessionId, sourceCommit, runtimeEvidence }) {
  rejectAuthorityFields(value);
  const item = exactObject(value, LIVE_ARTIFACT_KEYS);
  const clients = exactObject(item.clients, ROLES);
  const cleanup = exactObject(item.cleanup, ["completed", "stoppedAndSanitized"]);
  const roles = exactObject(item.roles, ROLES);
  const runtimeBindings = exactObject(item.runtimeBindings, ROLES);
  const directA2A = exactObject(item.directA2A, LIVE_A2A_KEYS);
  const cardDigests = exactObject(directA2A.agentCardDigests, ROLES);
  for (const role of ROLES) assertDigest(cardDigests[role]);
  const validatedRoles = {
    initiator: validateLiveRole(roles.initiator),
    responder: validateLiveRole(roles.responder),
  };
  if (
    item.schema !== "clockchain.mechanics-proof-live-artifact/v1" ||
    item.sessionId !== sessionId ||
    item.sourceCommit !== sourceCommit ||
    clients.initiator !== "codex" ||
    clients.responder !== "claude" ||
    item.certificateVerified !== true ||
    !SHA256.test(item.certificateDigest) ||
    cleanup.completed !== true ||
    cleanup.stoppedAndSanitized !== true ||
    directA2A.controllerRoutedRawContent !== false ||
    validatedRoles.initiator.address === validatedRoles.responder.address ||
    validatedRoles.initiator.erc8004AgentId === validatedRoles.responder.erc8004AgentId
  ) fail();
  const envelopeDigests = assertDigestArray(directA2A.envelopeDigests);
  const checkpointDigests = assertDigestArray(directA2A.commitmentCheckpointDigests);
  const bindings = {
    initiator: validateLiveRuntimeBinding(runtimeBindings.initiator, runtimeEvidence.initiator, "initiator"),
    responder: validateLiveRuntimeBinding(runtimeBindings.responder, runtimeEvidence.responder, "responder"),
  };
  return Object.freeze({
    schema: item.schema,
    sessionId,
    sourceCommit,
    clients: Object.freeze({ initiator: "codex", responder: "claude" }),
    runtimeBindings: Object.freeze({
      initiator: bindings.initiator,
      responder: bindings.responder,
    }),
    directA2A: Object.freeze({
      agentCardDigests: Object.freeze({ initiator: cardDigests.initiator, responder: cardDigests.responder }),
      envelopeDigests,
      commitmentCheckpointDigests: checkpointDigests,
      controllerRoutedRawContent: false,
    }),
    roles: Object.freeze({
      initiator: validatedRoles.initiator,
      responder: validatedRoles.responder,
    }),
    certificateVerified: true,
    certificateDigest: item.certificateDigest,
    cleanup: Object.freeze({ completed: true, stoppedAndSanitized: true }),
  });
}

function validatePairIsolation(runtimeEvidence, { requireLiveEvidence }) {
  if (requireLiveEvidence) {
    return validateRuntimePairEvidence(runtimeEvidence);
  }
  const initiator = validateLocalRuntimeEvidence(runtimeEvidence.initiator);
  const responder = validateLocalRuntimeEvidence(runtimeEvidence.responder);
  if (initiator.role !== "initiator" || responder.role !== "responder") fail();
  for (const key of ["runtimeId", "credentialRefDigest", "workspaceRootDigest", "stateRootDigest", "signerRootDigest"]) {
    if (initiator[key] === responder[key]) fail();
  }
  if (initiator.cleanupCompleted !== true || responder.cleanupCompleted !== true) fail();
  return Object.freeze({ initiator, responder });
}

async function cleanup(runtimeAdapter, runtimes) {
  const errors = [];
  for (const role of ROLES) {
    const runtime = runtimes[role];
    if (runtime === undefined) continue;
    try { await runtimeAdapter.terminateRuntime({ runtimeId: runtime.runtimeId, role }); } catch (error) { errors.push(error); }
    try { await runtimeAdapter.destroyRuntime({ runtimeId: runtime.runtimeId, role }); } catch (error) { errors.push(error); }
  }
  if (errors.length > 0) fail();
}

export async function runMechanicsProofController(config) {
  const item = controllerConfig(config);
  rejectAuthorityFields(item);
  const roles = exactRoleObject(item.roles);
  if (roles.initiator.secretsRef === roles.responder.secretsRef || roles.initiator.stateRef === roles.responder.stateRef) fail();
  if (typeof item.sessionId !== "string" || item.sessionId.length === 0) fail();
  if (!Number.isSafeInteger(item.ttlMs) || item.ttlMs < 1) fail();
  const requireLiveEvidence = item.requireLiveEvidence ?? false;
  if (typeof requireLiveEvidence !== "boolean") fail();
  const livePreflight = requireLiveEvidence ? validateLivePreflight(item.livePreflight) : null;
  if (item.networkPolicy === null || typeof item.networkPolicy !== "object" || Array.isArray(item.networkPolicy)) fail();
  if (item.costTags === null || typeof item.costTags !== "object" || Array.isArray(item.costTags)) fail();
  if (typeof item.executePair !== "function") fail();
  const runtimeAdapter = methodSurface(item.runtimeAdapter, RUNTIME_METHODS);
  const harnessAdapters = exactObject(item.harnessAdapters, ROLES);
  for (const role of ROLES) methodSurface(harnessAdapters[role], HARNESS_METHODS);

  const runtimes = {};
  const harnessCapabilities = {};
  let handshakeEvidence;
  try {
    for (const role of ROLES) {
      const runtime = await runtimeAdapter.provisionPartyRuntime({
        sessionId: item.sessionId,
        role,
        harness: roles[role].harness,
        secretsRef: roles[role].secretsRef,
        stateRef: roles[role].stateRef,
        networkPolicy: item.networkPolicy,
        ttlMs: item.ttlMs,
        costTags: item.costTags,
      });
      runtimes[role] = cleanupRuntimeReference(runtime, role);
      runtimes[role] = publicRuntimeDescriptor(runtime, role);
      await runtimeAdapter.attestRuntime({ runtimeId: runtimes[role].runtimeId, role });
      harnessCapabilities[role] = validateHarnessCapabilities(
        await harnessAdapters[role].inspectCapabilities({ runtime: runtimes[role], role }),
        role,
        roles[role].harness,
      );
    }
    handshakeEvidence = await item.executePair(Object.freeze({
      harnessCapabilities: Object.freeze({
        initiator: Object.freeze({ ...harnessCapabilities.initiator }),
        responder: Object.freeze({ ...harnessCapabilities.responder }),
      }),
      runtimes: frozenRuntimes(runtimes),
    }));
  } finally {
    await cleanup(runtimeAdapter, runtimes);
  }

  const runtimeEvidence = {};
  for (const role of ROLES) {
    runtimeEvidence[role] = await runtimeAdapter.collectRuntimeEvidence({ runtimeId: runtimes[role].runtimeId, role });
  }
  const validatedRuntimeEvidence = validatePairIsolation(runtimeEvidence, { requireLiveEvidence });
  if (requireLiveEvidence) {
    handshakeEvidence = validateLiveHandshakeEvidence(handshakeEvidence, {
      sessionId: item.sessionId,
      sourceCommit: livePreflight.sourceCommit,
      runtimeEvidence: validatedRuntimeEvidence,
    });
  }
  return Object.freeze({
    handshakeEvidence,
    runtimeEvidence: validatedRuntimeEvidence,
  });
}
