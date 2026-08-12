import {
  RUNTIME_EVIDENCE_SCHEMA,
  validateRuntimeEvidence,
} from "./runtime-adapter-contract.mjs";
import {
  sha256Hex,
  stableJson,
  validateFargateRuntimePlan,
} from "./aws-fargate-runtime-adapter.mjs";
import { assertSecretFree } from "../core/redact.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);
const SHA = /^[0-9a-f]{64}$/;
const LOCAL_PATH_FRAGMENT = /(?:^|[^A-Za-z0-9])\/(?=\S)|~\/|[A-Za-z]:[\\/]/;
const RECORD_KEYS = Object.freeze({
  "clockchain.fargate-runtime-attestation/v1": Object.freeze([
    "role", "schema", "sessionId", "signerRootDigest", "stateRootDigest", "workspaceRootDigest",
  ]),
  "clockchain.fargate-in-task-sts/v1": Object.freeze([
    "callerIdentity", "role", "schema", "sessionId",
  ]),
  "clockchain.fargate-session-sanitization/v1": Object.freeze([
    "privatePathsRedacted", "role", "schema", "secretCanariesAbsent", "sessionId",
  ]),
});
const CLOUDTRAIL_KEYS = Object.freeze([
  "account", "eventName", "eventSource", "eventTime", "requestParameters", "taskArn",
]);

function fail() {
  throw new Error("Fargate runtime evidence validation failed safely.");
}

function object(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function digestListFromRaw(items) {
  if (!Array.isArray(items) || items.length === 0) fail();
  return items.map((entry) => sha256Hex(stableJson(entry)));
}

function publicLogDigests(logs) {
  if (!Array.isArray(logs) || logs.length === 0) fail();
  const digests = [];
  for (const log of logs) {
    const item = object(log);
    if (typeof item.logGroupName !== "string" || typeof item.logStreamName !== "string") fail();
    if (Object.hasOwn(item, "publicEventDigests")) fail();
    if (!Array.isArray(item.events) || item.events.length === 0) fail();
    try {
      assertSecretFree(item, ["secret-canary"]);
    } catch {
      fail();
    }
    digests.push(sha256Hex({
      logGroupName: item.logGroupName,
      logStreamName: item.logStreamName,
      events: item.events,
    }));
  }
  return digests;
}

function exactKeys(value, keys) {
  if (JSON.stringify(Object.keys(object(value)).sort()) !== JSON.stringify([...keys].sort())) fail();
  return value;
}

function eventTimeMs(value) {
  const ms = Date.parse(value);
  if (!Number.isSafeInteger(ms)) fail();
  return ms;
}

function parseLogRecords(logs, planLogGroupName, sessionId, role) {
  if (!Array.isArray(logs) || logs.length !== 1) fail();
  const item = object(logs[0]);
  if (typeof item.logGroupName !== "string" || typeof item.logStreamName !== "string") fail();
  if (item.logGroupName !== planLogGroupName || item.logStreamName !== `${role}/session/${sessionId}`) fail();
  if (Object.hasOwn(item, "publicEventDigests")) fail();
  if (!Array.isArray(item.events) || item.events.length !== 3) fail();
  const records = new Map();
  for (const event of item.events) {
    const entry = object(event);
    if (typeof entry.message !== "string" || entry.message.length > 4096) fail();
    eventTimeMs(entry.timestamp);
    if (LOCAL_PATH_FRAGMENT.test(entry.message)) fail();
    try {
      assertSecretFree(entry.message, ["secret-canary"]);
    } catch {
      fail();
    }
    let parsed;
    try {
      parsed = JSON.parse(entry.message);
    } catch {
      fail();
    }
    const record = exactKeys(parsed, RECORD_KEYS[object(parsed).schema] ?? []);
    if (record.sessionId !== sessionId || record.role !== role || typeof record.schema !== "string") fail();
    if (records.has(record.schema)) fail();
    records.set(record.schema, record);
  }
  for (const schema of Object.keys(RECORD_KEYS)) {
    if (!records.has(schema)) fail();
  }
  return records;
}

function attachmentDetail(task, name) {
  const attachments = task.attachments;
  if (!Array.isArray(attachments)) fail();
  for (const attachment of attachments) {
    if (attachment?.type !== "ElasticNetworkInterface" || !Array.isArray(attachment.details)) continue;
    const found = attachment.details.find((entry) => entry?.name === name);
    if (found?.value) return found.value;
  }
  fail();
}

function taskDefinitionDigest(taskDefinition) {
  return sha256Hex(taskDefinition);
}

function secretDigests(secrets) {
  return secrets.map((entry) => sha256Hex(entry.valueFrom)).sort();
}

function timestampMs(value) {
  const ms = Date.parse(value);
  if (!Number.isSafeInteger(ms)) fail();
  return ms;
}

function taskRoleName(taskRoleArn) {
  const match = /:role\/([^/]+)$/.exec(taskRoleArn);
  if (!match) fail();
  return match[1];
}

function arnAccount(arn) {
  const match = /^arn:aws:[^:]+:[^:]*:([0-9]{12}):/.exec(arn);
  if (!match) fail();
  return match[1];
}

function assertSameJson(left, right) {
  if (stableJson(left) !== stableJson(right)) fail();
}

function attestedDigest(value) {
  if (typeof value !== "string" || !SHA.test(value)) fail();
  return value;
}

function requireCloudTrail(events, eventName, taskArn, account, sessionId) {
  if (!Array.isArray(events) || events.length === 0 || events.length > 20) fail();
  const found = events.find((event) =>
    exactKeys(event, CLOUDTRAIL_KEYS).eventSource === "ecs.amazonaws.com" &&
    event.eventName === eventName &&
    event.taskArn === taskArn &&
    event.account === account &&
    object(event.requestParameters).startedBy === sessionId);
  if (!found) fail();
  exactKeys(found.requestParameters, ["startedBy"]);
  eventTimeMs(found.eventTime);
  return found;
}

export function collectFargateRuntimeEvidence({ plan, sessionId, role, aws }) {
  const verified = validateFargateRuntimePlan(plan);
  if (!ROLES.includes(role) || typeof sessionId !== "string" || sessionId.length === 0) fail();
  const party = verified.parties[role];
  const input = object(aws);
  if (
    Object.hasOwn(input, "cloudTrailEventDigests") ||
    Object.hasOwn(input, "logStreamDigests") ||
    Object.hasOwn(input, "cleanupEvidenceDigest") ||
    Object.hasOwn(input, "sessionSanitizationDigest") ||
    Object.hasOwn(input, "inTaskStsCallerIdentity") ||
    Object.hasOwn(input, "runtimeAttestation") ||
    Object.hasOwn(input, "sessionSanitization") ||
    Object.hasOwn(input, "cleanupEvidence")
  ) fail();

  const describeTasks = object(input.describeTasks);
  if (!Array.isArray(describeTasks.tasks) || describeTasks.tasks.length !== 1) fail();
  const task = object(describeTasks.tasks[0]);
  if (task.lastStatus !== "STOPPED") fail();
  const definitionEnvelope = object(input.taskDefinition);
  const taskDefinition = object(definitionEnvelope.taskDefinition);
  if (
    task.taskDefinitionArn !== taskDefinition.taskDefinitionArn ||
    taskDefinition.taskRoleArn !== party.taskRoleArn ||
    taskDefinition.executionRoleArn !== party.executionRoleArn ||
    taskDefinition.networkMode !== "awsvpc" ||
    String(taskDefinition.cpu) !== "512" ||
    String(taskDefinition.memory) !== "1024" ||
    !Array.isArray(taskDefinition.requiresCompatibilities) ||
    !taskDefinition.requiresCompatibilities.includes("FARGATE")
  ) fail();
  const container = object(taskDefinition.containerDefinitions?.[0]);
  if (container.image !== party.image || object(task.containers?.[0]).imageDigest !== party.imageDigest) fail();
  if (container.readonlyRootFilesystem !== true || container.user !== party.user) fail();
  assertSameJson(container.environment, party.environment);
  assertSameJson(container.secrets, party.secrets);
  assertSameJson(container.mountPoints, party.mountPoints);
  assertSameJson(container.logConfiguration, party.logConfiguration);
  assertSameJson(taskDefinition.volumes, party.volumes);
  if (taskDefinition.volumes?.some((volume) => Object.hasOwn(object(volume), "efsVolumeConfiguration"))) fail();

  const eniId = attachmentDetail(task, "networkInterfaceId");
  const subnetId = attachmentDetail(task, "subnetId");
  const eni = object(input.networkInterface);
  if (eni.NetworkInterfaceId !== eniId || eni.SubnetId !== subnetId || eni.Association !== null) fail();
  const eniGroups = eni.Groups;
  if (!Array.isArray(eniGroups) || eniGroups.length !== 1 || eniGroups[0].GroupId !== party.securityGroupId) fail();
  const group = object(object(input.securityGroups)[party.securityGroupId]);
  const permissions = group.IpPermissions;
  if (!Array.isArray(permissions) || permissions.length !== 1) fail();
  const permission = object(permissions[0]);
  const peerRole = role === "initiator" ? "responder" : "initiator";
  if (
    permission.IpProtocol !== "tcp" ||
    permission.FromPort !== 8443 ||
    permission.ToPort !== 8443 ||
    !Array.isArray(permission.UserIdGroupPairs) ||
    permission.UserIdGroupPairs.length !== 1 ||
    permission.UserIdGroupPairs[0].GroupId !== verified.parties[peerRole].securityGroupId
  ) fail();
  const egress = group.IpPermissionsEgress;
  if (!Array.isArray(egress)) fail();
  const peerEgress = egress.find((rule) => rule.IpProtocol === "tcp" && rule.FromPort === 8443 && rule.ToPort === 8443);
  if (!peerEgress || !Array.isArray(peerEgress.UserIdGroupPairs) || peerEgress.UserIdGroupPairs[0]?.GroupId !== verified.parties[peerRole].securityGroupId) fail();

  const logRecords = parseLogRecords(input.cloudWatchLogs, party.logConfiguration.options["awslogs-group"], sessionId, role);
  const runtimeAttestation = object(logRecords.get("clockchain.fargate-runtime-attestation/v1"));
  const stsRecord = object(logRecords.get("clockchain.fargate-in-task-sts/v1"));
  const sts = object(stsRecord.callerIdentity);
  const sessionSanitization = object(logRecords.get("clockchain.fargate-session-sanitization/v1"));
  if (
    sessionSanitization.privatePathsRedacted !== true ||
    sessionSanitization.secretCanariesAbsent !== true
  ) fail();
  if (sts.account !== arnAccount(party.taskRoleArn)) fail();
  if (typeof sts.arn !== "string" || !sts.arn.includes(`assumed-role/${taskRoleName(party.taskRoleArn)}/`)) fail();
  const runTaskEvent = requireCloudTrail(input.cloudTrailEvents, "RunTask", task.taskArn, sts.account, sessionId);
  const stopTaskEvent = requireCloudTrail(input.cloudTrailEvents, "StopTask", task.taskArn, sts.account, sessionId);
  if (eventTimeMs(runTaskEvent.eventTime) > timestampMs(task.createdAt)) fail();
  if (eventTimeMs(stopTaskEvent.eventTime) < timestampMs(task.stoppedAt)) fail();

  const evidence = {
    schema: RUNTIME_EVIDENCE_SCHEMA,
    runtimeId: `fargate:${sessionId}:${role}`,
    role,
    taskArn: task.taskArn,
    taskStatus: "STOPPED",
    createdAtMs: timestampMs(task.createdAt),
    stoppedAtMs: timestampMs(task.stoppedAt),
    taskRoleArn: party.taskRoleArn,
    executionRoleArn: party.executionRoleArn,
    inTaskStsCallerIdentity: {
      account: sts.account,
      arn: sts.arn,
      userId: sts.userId,
    },
    imageDigest: party.imageDigest,
    taskDefinitionArn: taskDefinition.taskDefinitionArn,
    taskDefinitionRevision: String(taskDefinition.revision),
    taskDefinitionDigest: taskDefinitionDigest(taskDefinition),
    eniId,
    subnetId,
    securityGroupIds: [party.securityGroupId],
    writableVolumeSummary: { ephemeral: true, sharedWritable: false },
    sharedEfsMounts: [],
    secretArnDigests: secretDigests(party.secrets),
    credentialRefDigest: sha256Hex(secretDigests(party.secrets).join(":")),
    workspaceRootDigest: attestedDigest(runtimeAttestation.workspaceRootDigest),
    stateRootDigest: attestedDigest(runtimeAttestation.stateRootDigest),
    signerRootDigest: attestedDigest(runtimeAttestation.signerRootDigest),
    logStreamDigests: publicLogDigests(input.cloudWatchLogs),
    cloudTrailEventDigests: digestListFromRaw(input.cloudTrailEvents),
    ecsDescribeTasksDigest: sha256Hex(describeTasks),
    cleanupEvidenceDigest: sha256Hex({
      taskArn: task.taskArn,
      taskStatus: task.lastStatus,
      stoppedAt: task.stoppedAt,
      stopTaskEvent,
    }),
    sessionSanitizationDigest: sha256Hex(sessionSanitization),
  };
  return validateRuntimeEvidence(evidence);
}

export function validateFargateRuntimeEvidence(value) {
  return validateRuntimeEvidence(value);
}
