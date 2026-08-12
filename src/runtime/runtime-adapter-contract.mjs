import { createHash } from "node:crypto";

export const RUNTIME_EVIDENCE_SCHEMA = "clockchain.runtime-evidence/v1";
export const LOCAL_RUNTIME_EVIDENCE_SCHEMA = "clockchain.local-runtime-evidence/v1";
export const FARGATE_LIVE_RESULT_SCHEMA = "clockchain.fargate-live-result/v1";
export const FARGATE_LIVE_STATUS_SUCCEEDED = "SUCCEEDED";
export const FARGATE_LIVE_STATUS_CLEANUP_UNCONFIRMED = "CLEANUP_UNCONFIRMED";
export const FARGATE_LIVE_STATUS_PROTOCOL_FAILED_CLEAN = "PROTOCOL_FAILED_CLEAN";

const ROLES = Object.freeze(["initiator", "responder"]);
const SHA = /^[0-9a-f]{64}$/;
const LONG_SHA = /^sha256:[0-9a-f]{64}$/;
const AWS_ARN = /^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:.+/;
const NONEMPTY = /^.{1,512}$/u;

const RUNTIME_EVIDENCE_KEYS = Object.freeze([
  "cleanupEvidenceDigest", "cloudTrailEventDigests", "createdAtMs", "credentialRefDigest",
  "ecsDescribeTasksDigest", "eniId", "executionRoleArn", "imageDigest", "inTaskStsCallerIdentity",
  "logStreamDigests", "role", "runtimeId", "schema", "secretArnDigests", "securityGroupIds",
  "sessionSanitizationDigest", "sharedEfsMounts", "signerRootDigest", "stateRootDigest",
  "stoppedAtMs", "subnetId", "taskArn", "taskDefinitionArn", "taskDefinitionDigest",
  "taskDefinitionRevision", "taskRoleArn", "taskStatus", "workspaceRootDigest",
  "writableVolumeSummary",
]);
const LOCAL_RUNTIME_EVIDENCE_KEYS = Object.freeze([
  "cleanupCompleted", "createdAtMs", "credentialRefDigest", "harness", "provider", "role",
  "runtimeId", "schema", "sessionSanitizationDigest", "signerRootDigest", "sourceCommitDigest",
  "stateRootDigest", "status", "stoppedAtMs", "workspaceRootDigest",
]);

function fail() {
  throw new Error("Runtime adapter contract validation failed safely.");
}

function rejectAuthorityFields(value) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    for (const item of value) rejectAuthorityFields(item);
    return;
  }
  if (typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (/(?:private.?key|secret.?key|controller.?private.?key|signer)$/i.test(key)) fail();
    rejectAuthorityFields(child);
  }
}

function exactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail();
  return value;
}

function cleanRole(value) {
  if (!ROLES.includes(value)) fail();
  return value;
}

function nonempty(value) {
  if (typeof value !== "string" || !NONEMPTY.test(value)) fail();
  return value;
}

function digest(value) {
  if (typeof value !== "string" || !SHA.test(value)) fail();
  return value;
}

function digestList(value) {
  if (!Array.isArray(value) || value.length < 1 || value.some((entry) => !SHA.test(entry))) fail();
  return Object.freeze([...value]);
}

function secretDigestList(value, role) {
  if (!Array.isArray(value) || value.some((entry) => !SHA.test(entry))) fail();
  if (role === "initiator" && value.length < 1) fail();
  return Object.freeze([...value]);
}

function timestamp(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail();
  return value;
}

function digestOf(value) {
  return createHash("sha256").update(value).digest("hex");
}

function localStatus(value) {
  if (!["PROVISIONED", "STOPPED", "DESTROYED"].includes(value)) fail();
  return value;
}

export function validateRuntimeEvidence(value) {
  const item = exactObject(value, RUNTIME_EVIDENCE_KEYS);
  const sts = exactObject(item.inTaskStsCallerIdentity, ["account", "arn", "userId"]);
  const volume = exactObject(item.writableVolumeSummary, ["ephemeral", "sharedWritable"]);
  if (
    item.schema !== RUNTIME_EVIDENCE_SCHEMA ||
    item.taskStatus !== "STOPPED" ||
    !AWS_ARN.test(item.taskArn) ||
    !AWS_ARN.test(item.taskRoleArn) ||
    !AWS_ARN.test(item.executionRoleArn) ||
    !AWS_ARN.test(item.taskDefinitionArn) ||
    !/^(?:0|[1-9][0-9]*)$/.test(item.taskDefinitionRevision) ||
    !LONG_SHA.test(item.imageDigest) ||
    volume.ephemeral !== true ||
    volume.sharedWritable !== false ||
    !Array.isArray(item.sharedEfsMounts) ||
    item.sharedEfsMounts.length !== 0
  ) fail();
  const createdAtMs = timestamp(item.createdAtMs);
  const stoppedAtMs = timestamp(item.stoppedAtMs);
  if (stoppedAtMs < createdAtMs) fail();
  if (
    !/^[0-9]{12}$/.test(sts.account) ||
    !AWS_ARN.test(sts.arn) ||
    typeof sts.userId !== "string" ||
    sts.userId.length === 0
  ) fail();
  return Object.freeze({
    schema: RUNTIME_EVIDENCE_SCHEMA,
    runtimeId: nonempty(item.runtimeId),
    role: cleanRole(item.role),
    taskArn: item.taskArn,
    taskStatus: "STOPPED",
    createdAtMs,
    stoppedAtMs,
    taskRoleArn: item.taskRoleArn,
    executionRoleArn: item.executionRoleArn,
    inTaskStsCallerIdentity: Object.freeze({ ...sts }),
    imageDigest: item.imageDigest,
    taskDefinitionArn: item.taskDefinitionArn,
    taskDefinitionRevision: item.taskDefinitionRevision,
    taskDefinitionDigest: digest(item.taskDefinitionDigest),
    eniId: nonempty(item.eniId),
    subnetId: nonempty(item.subnetId),
    securityGroupIds: Object.freeze([...item.securityGroupIds].map(nonempty)),
    writableVolumeSummary: Object.freeze({ ...volume }),
    sharedEfsMounts: Object.freeze([]),
    secretArnDigests: secretDigestList(item.secretArnDigests, item.role),
    credentialRefDigest: digest(item.credentialRefDigest),
    workspaceRootDigest: digest(item.workspaceRootDigest),
    stateRootDigest: digest(item.stateRootDigest),
    signerRootDigest: digest(item.signerRootDigest),
    logStreamDigests: digestList(item.logStreamDigests),
    cloudTrailEventDigests: digestList(item.cloudTrailEventDigests),
    ecsDescribeTasksDigest: digest(item.ecsDescribeTasksDigest),
    cleanupEvidenceDigest: digest(item.cleanupEvidenceDigest),
    sessionSanitizationDigest: digest(item.sessionSanitizationDigest),
  });
}

export function validateRuntimePairEvidence(value) {
  const item = exactObject(value, ROLES);
  const initiator = validateRuntimeEvidence(item.initiator);
  const responder = validateRuntimeEvidence(item.responder);
  if (initiator.role !== "initiator" || responder.role !== "responder") fail();
  for (const field of [
    "runtimeId", "taskArn", "taskRoleArn", "credentialRefDigest", "workspaceRootDigest",
    "stateRootDigest", "signerRootDigest",
  ]) {
    if (initiator[field] === responder[field]) fail();
  }
  const initiatorSecrets = new Set(initiator.secretArnDigests);
  if (responder.secretArnDigests.some((entry) => initiatorSecrets.has(entry))) fail();
  return Object.freeze({ initiator, responder });
}

export function validateLocalRuntimeEvidence(value) {
  const item = exactObject(value, LOCAL_RUNTIME_EVIDENCE_KEYS);
  if (
    item.schema !== LOCAL_RUNTIME_EVIDENCE_SCHEMA ||
    item.provider !== "local-shim" ||
    typeof item.harness !== "string" ||
    item.harness.length === 0 ||
    typeof item.cleanupCompleted !== "boolean"
  ) fail();
  const status = localStatus(item.status);
  if ((status === "DESTROYED") !== item.cleanupCompleted) fail();
  const createdAtMs = timestamp(item.createdAtMs);
  const stoppedAtMs = item.stoppedAtMs === null ? null : timestamp(item.stoppedAtMs);
  if (status === "PROVISIONED" && stoppedAtMs !== null) fail();
  if (status !== "PROVISIONED" && (stoppedAtMs === null || stoppedAtMs < createdAtMs)) fail();
  return Object.freeze({
    schema: LOCAL_RUNTIME_EVIDENCE_SCHEMA,
    provider: "local-shim",
    runtimeId: nonempty(item.runtimeId),
    role: cleanRole(item.role),
    harness: item.harness,
    status,
    createdAtMs,
    stoppedAtMs,
    cleanupCompleted: item.cleanupCompleted,
    sourceCommitDigest: digest(item.sourceCommitDigest),
    credentialRefDigest: digest(item.credentialRefDigest),
    workspaceRootDigest: digest(item.workspaceRootDigest),
    stateRootDigest: digest(item.stateRootDigest),
    signerRootDigest: digest(item.signerRootDigest),
    sessionSanitizationDigest: digest(item.sessionSanitizationDigest),
  });
}

export function createLocalRuntimeAdapter(options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) fail();
  rejectAuthorityFields(options);
  const { sourceCommit = "0".repeat(40), overrides = {} } = options;
  const runtimes = new Map();
  const cleanCommit = typeof sourceCommit === "string" && /^[0-9a-f]{40}$/.test(sourceCommit) ? sourceCommit : "0".repeat(40);

  function buildLocalEvidence(runtime) {
    const roleSeed = `${cleanCommit}:${runtime.role}`;
    const baseDigest = (name) => digestOf(`${roleSeed}:${name}`);
    return {
      schema: LOCAL_RUNTIME_EVIDENCE_SCHEMA,
      provider: "local-shim",
      runtimeId: runtime.runtimeId,
      role: runtime.role,
      harness: runtime.harness,
      status: runtime.status,
      createdAtMs: runtime.createdAtMs,
      stoppedAtMs: runtime.stoppedAtMs,
      cleanupCompleted: runtime.status === "DESTROYED",
      sourceCommitDigest: digestOf(cleanCommit),
      credentialRefDigest: baseDigest(`credential:${runtime.secretsRef}`),
      workspaceRootDigest: baseDigest("workspace"),
      stateRootDigest: baseDigest("state"),
      signerRootDigest: baseDigest("signer"),
      sessionSanitizationDigest: baseDigest("sanitization"),
      ...(overrides[runtime.role] ?? {}),
    };
  }

  return Object.freeze({
    async provisionPartyRuntime({ sessionId, role, harness, secretsRef, networkPolicy, ttlMs, costTags }) {
      cleanRole(role);
      if (
        typeof sessionId !== "string" || sessionId.length === 0 ||
        typeof harness !== "string" || harness.length === 0 ||
        typeof secretsRef !== "string" || secretsRef.length === 0 ||
        networkPolicy === null || typeof networkPolicy !== "object" ||
        !Number.isSafeInteger(ttlMs) || ttlMs < 1 ||
        costTags === null || typeof costTags !== "object" || Array.isArray(costTags)
      ) fail();
      const runtime = Object.freeze({
        runtimeId: `local-${role}-${digestOf(`${sessionId}:${role}:${harness}`).slice(0, 16)}`,
        role,
        harness,
        secretsRef,
        createdAtMs: 1786337000000 + runtimes.size,
        stoppedAtMs: null,
      });
      runtimes.set(runtime.runtimeId, { ...runtime, status: "PROVISIONED" });
      return runtime;
    },
    async attestRuntime({ runtimeId }) {
      const runtime = runtimes.get(runtimeId);
      if (runtime === undefined) fail();
      return validateLocalRuntimeEvidence(buildLocalEvidence(runtime));
    },
    async streamRuntimeEvents({ runtimeId, since = null }) {
      if (!runtimes.has(runtimeId) || since !== null && typeof since !== "string") fail();
      return Object.freeze([]);
    },
    async terminateRuntime({ runtimeId }) {
      const runtime = runtimes.get(runtimeId);
      if (runtime === undefined) fail();
      runtimes.set(runtimeId, { ...runtime, status: "STOPPED", stoppedAtMs: runtime.createdAtMs + 1 });
      return Object.freeze({ runtimeId, status: "STOPPED" });
    },
    async destroyRuntime({ runtimeId }) {
      const runtime = runtimes.get(runtimeId);
      if (runtime === undefined || runtime.status !== "STOPPED") fail();
      runtimes.set(runtimeId, { ...runtime, status: "DESTROYED" });
      return Object.freeze({ runtimeId, destroyed: true });
    },
    async collectRuntimeEvidence({ runtimeId }) {
      const runtime = runtimes.get(runtimeId);
      if (runtime === undefined || runtime.status !== "DESTROYED") fail();
      return validateLocalRuntimeEvidence(buildLocalEvidence(runtime));
    },
  });
}
