import { validateLocalRuntimeEvidence } from "../runtime/runtime-adapter-contract.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);
const CONTROLLER_KEYS = Object.freeze([
  "costTags", "executePair", "harnessAdapters", "networkPolicy", "roles", "runtimeAdapter",
  "sessionId", "ttlMs",
]);
const ROLE_KEYS = Object.freeze(["harness", "secretsRef", "stateRef"]);
const PUBLIC_RUNTIME_KEYS = Object.freeze(["harness", "role", "runtimeId"]);
const HARNESS_CAPABILITY_KEYS = Object.freeze(["harness", "rawPayloadTransport", "retainedLocalActions", "schema"]);
const RUNTIME_METHODS = Object.freeze([
  "attestRuntime", "collectRuntimeEvidence", "destroyRuntime", "provisionPartyRuntime",
  "streamRuntimeEvents", "terminateRuntime",
]);
const HARNESS_METHODS = Object.freeze(["inspectCapabilities"]);

function fail() {
  throw new Error("Mechanics-proof controller validation failed safely.");
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail();
  return value;
}

function rejectAuthorityFields(value) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    for (const item of value) rejectAuthorityFields(item);
    return;
  }
  if (typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (/(?:private.?key|secret.?key|controller.?private.?key|signer|terms|mandate)/i.test(key)) fail();
    rejectAuthorityFields(child);
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
  if (adapter === null || typeof adapter !== "object") fail();
  for (const method of methods) {
    if (typeof adapter[method] !== "function") fail();
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

function validatePairIsolation(runtimeEvidence) {
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
  rejectAuthorityFields(config);
  const item = exactObject(config, CONTROLLER_KEYS);
  const roles = exactRoleObject(item.roles);
  if (roles.initiator.secretsRef === roles.responder.secretsRef || roles.initiator.stateRef === roles.responder.stateRef) fail();
  if (typeof item.sessionId !== "string" || item.sessionId.length === 0) fail();
  if (!Number.isSafeInteger(item.ttlMs) || item.ttlMs < 1) fail();
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
  return Object.freeze({
    handshakeEvidence,
    runtimeEvidence: validatePairIsolation(runtimeEvidence),
  });
}
