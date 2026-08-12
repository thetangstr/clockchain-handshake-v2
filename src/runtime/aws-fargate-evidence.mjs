import {
  RUNTIME_EVIDENCE_SCHEMA,
  validateRuntimeEvidence,
} from "./runtime-adapter-contract.mjs";
import {
  normalizeFargateTaskDefinitionForProof,
  sanitizeFargateData,
  sha256Hex,
  stableJson,
  validateFargateRuntimePlan,
} from "./aws-fargate-runtime-adapter.mjs";
import { assertSecretFree } from "../core/redact.mjs";

const ROLES = Object.freeze(["initiator", "responder"]);
export const FARGATE_RUNTIME_PROOF_PLAN_SCHEMA = "clockchain.fargate-runtime-proof-plan/v1";
const SHA = /^[0-9a-f]{64}$/;
const IMAGE = /^.+@sha256:[0-9a-f]{64}$/;
const LONG_SHA = /^sha256:[0-9a-f]{64}$/;
const AWS_ARN = /^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:.+/;
const LOCAL_PATH_FRAGMENT = /(?:^|[^A-Za-z0-9])\/(?=\S)|~\/|[A-Za-z]:[\\/]/;
const RECORD_KEYS = Object.freeze({
  "clockchain.mechanics-proof-ecs-attestation/v1": Object.freeze([
    "accountId", "availabilityZone", "containerArn", "family", "imageId", "launchType", "privateIp",
    "region", "revision", "role", "schema", "stsArn", "stsUserId", "taskArn", "taskId",
    "workloadAttestationDigest",
  ]),
  "clockchain.mechanics-proof-party-event/v1": Object.freeze([
    "evidenceDigest", "role", "runId", "schema", "sequence", "type",
  ]),
  "clockchain.mechanics-proof-party-evidence/v1": Object.freeze([
    "a2aCardSignerAddress",
    "anchors", "bridgeEvidenceDigest", "certificateDigest", "certificateProofDigest", "certificateVerified",
    "directDelivery", "externalBusinessActionPerformed", "harness", "harnessEvidenceDigest", "identity",
    "peerRuntimeId", "protocolSessionId", "resultDigest", "role", "runId", "runtimeId", "schema",
    "teardown", "terminalStatus", "workloadAttestationDigest",
  ]),
});
const REQUIRED_LOG_SCHEMAS = Object.freeze([
  "clockchain.mechanics-proof-ecs-attestation/v1",
]);
const PARTY_EVENT_TYPES = Object.freeze([
  "a2a.listener.ready",
  "a2a.invitation.received",
  "agent.starting",
  "certificate.verified",
]);
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
  if (Number.isSafeInteger(value) && value >= 0) return value;
  const ms = Date.parse(value);
  if (!Number.isSafeInteger(ms)) fail();
  return ms;
}

function parseLogRecords(logs, planLogGroupName, streamPrefix, runId, role, taskId) {
  if (!Array.isArray(logs) || logs.length !== 1) fail();
  const item = object(logs[0]);
  if (typeof item.logGroupName !== "string" || typeof item.logStreamName !== "string") fail();
  if (item.logGroupName !== planLogGroupName || item.logStreamName !== `${streamPrefix}/${role}/${taskId}`) fail();
  if (Object.hasOwn(item, "publicEventDigests")) fail();
  if (!Array.isArray(item.events) || item.events.length < 2 || item.events.length > 16) fail();
  const records = new Map();
  const partyEvents = [];
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
      parsed = sanitizeFargateData(JSON.parse(entry.message), fail);
    } catch {
      fail();
    }
    const record = exactKeys(parsed, RECORD_KEYS[object(parsed).schema] ?? []);
    if ((record.runId !== undefined && record.runId !== runId) || record.role !== role || typeof record.schema !== "string") fail();
    if (record.schema === "clockchain.mechanics-proof-party-event/v1") {
      partyEvents.push(record);
      continue;
    }
    if (records.has(record.schema)) fail();
    records.set(record.schema, record);
  }
  const expectedPartyEventTypes = role === "initiator"
    ? ["a2a.listener.ready", "agent.starting", "certificate.verified"]
    : PARTY_EVENT_TYPES;
  if (partyEvents.length !== expectedPartyEventTypes.length) fail();
  for (let index = 0; index < partyEvents.length; index += 1) {
    const event = partyEvents[index];
    if (
      event.sequence !== String(index + 1) ||
      event.type !== expectedPartyEventTypes[index] ||
      !SHA.test(event.evidenceDigest)
    ) fail();
  }
  for (const schema of REQUIRED_LOG_SCHEMAS) {
    if (!records.has(schema)) fail();
  }
  if (!records.has("clockchain.mechanics-proof-party-evidence/v1")) fail();
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

function parseAwsArn(arn) {
  const match = /^arn:aws:([^:]+):([^:]*):([0-9]{12}):(.+)$/.exec(arn);
  if (!match) fail();
  return {
    service: match[1],
    region: match[2],
    account: match[3],
    resource: match[4],
  };
}

function taskIdFromArn(arn) {
  const resource = parseAwsArn(arn).resource;
  const parts = resource.split("/");
  const taskId = parts.at(-1);
  if (typeof taskId !== "string" || taskId.length === 0) fail();
  return taskId;
}

function assertSameJson(left, right) {
  if (stableJson(left) !== stableJson(right)) fail();
}

function attestedDigest(value) {
  if (typeof value !== "string" || !SHA.test(value)) fail();
  return value;
}

function string(value) {
  if (typeof value !== "string" || value.length === 0) fail();
  return value;
}

function validateProofParty(value, role) {
  const item = object(value);
  const normalized = normalizeFargateTaskDefinitionForProof(item.taskDefinition, role);
  const container = object(normalized.containerDefinitions[0]);
  if (
    item.role !== role ||
    item.family !== normalized.family ||
    item.taskRoleArn !== normalized.taskRoleArn ||
    item.executionRoleArn !== normalized.executionRoleArn ||
    item.image !== container.image ||
    item.imageDigest !== string(container.image).slice(container.image.indexOf("@") + 1) ||
    item.user !== container.user ||
    item.readonlyRootFilesystem !== container.readonlyRootFilesystem ||
    item.privileged !== container.privileged ||
    !AWS_ARN.test(item.taskRoleArn) ||
    !AWS_ARN.test(item.executionRoleArn) ||
    !IMAGE.test(item.image) ||
    !LONG_SHA.test(item.imageDigest) ||
    normalized.networkMode !== "awsvpc" ||
    normalized.cpu !== "512" ||
    normalized.memory !== "1024" ||
    normalized.requiresCompatibilities.length !== 1 ||
    normalized.requiresCompatibilities[0] !== "FARGATE" ||
    normalized.runtimePlatform.operatingSystemFamily !== "LINUX" ||
    normalized.runtimePlatform.cpuArchitecture !== "X86_64" ||
    container.essential !== true ||
    container.privileged !== false ||
    container.readonlyRootFilesystem !== true ||
    container.user === "0" ||
    container.user === "root" ||
    typeof item.securityGroupId !== "string" ||
    item.securityGroupId.length === 0
  ) fail();
  if (!Array.isArray(container.secrets) || (role === "initiator" ? container.secrets.length !== 1 : container.secrets.length !== 0)) fail();
  if (!Array.isArray(container.environment) || container.environment.find((entry) => entry?.name === "CLOCKCHAIN_ROLE")?.value !== role) fail();
  const log = object(container.logConfiguration);
  const options = object(log.options);
  if (
    log.logDriver !== "awslogs" ||
    options.mode !== "blocking" ||
    options["awslogs-stream-prefix"] !== role ||
    typeof options["awslogs-group"] !== "string" ||
    options["awslogs-group"].length === 0
  ) fail();
  return Object.freeze({
    role,
    taskDefinition: normalized,
    family: normalized.family,
    requiresCompatibilities: normalized.requiresCompatibilities,
    networkMode: normalized.networkMode,
    cpu: normalized.cpu,
    memory: normalized.memory,
    runtimePlatform: normalized.runtimePlatform,
    taskRoleArn: normalized.taskRoleArn,
    executionRoleArn: normalized.executionRoleArn,
    image: container.image,
    imageDigest: item.imageDigest,
    user: container.user,
    readonlyRootFilesystem: container.readonlyRootFilesystem,
    privileged: container.privileged,
    portMappings: container.portMappings,
    environment: container.environment,
    secrets: container.secrets,
    mountPoints: container.mountPoints,
    logConfiguration: container.logConfiguration,
    volumes: normalized.volumes,
    securityGroupId: item.securityGroupId,
  });
}

export function buildFargateRuntimeProofPlan(input) {
  const item = object(sanitizeFargateData(input, fail));
  const parties = object(item.parties);
  const initiator = validateProofParty(parties.initiator, "initiator");
  const responder = validateProofParty(parties.responder, "responder");
  if (
    initiator.taskRoleArn === responder.taskRoleArn ||
    initiator.executionRoleArn === responder.executionRoleArn ||
    initiator.securityGroupId === responder.securityGroupId ||
    initiator.logConfiguration.options["awslogs-group"] === responder.logConfiguration.options["awslogs-group"] ||
    initiator.imageDigest !== responder.imageDigest
  ) fail();
  return Object.freeze({
    schema: FARGATE_RUNTIME_PROOF_PLAN_SCHEMA,
    parties: Object.freeze({ initiator, responder }),
  });
}

function validateRuntimeProofPlan(plan) {
  const item = object(plan);
  if (item.schema === FARGATE_RUNTIME_PROOF_PLAN_SCHEMA) return buildFargateRuntimeProofPlan(item);
  return validateFargateRuntimePlan(item);
}

function attestationDigest(record) {
  const core = {
    schema: "clockchain.mechanics-proof-ecs-attestation-core/v1",
    accountId: record.accountId,
    availabilityZone: record.availabilityZone,
    containerArn: record.containerArn,
    family: record.family,
    imageId: record.imageId,
    launchType: record.launchType,
    privateIp: record.privateIp,
    region: record.region,
    revision: record.revision,
    role: record.role,
    stsArn: record.stsArn,
    stsUserId: record.stsUserId,
    taskArn: record.taskArn,
    taskId: record.taskId,
  };
  return sha256Hex(core);
}

function normalizeCloudTrailEvent(event) {
  const item = object(event);
  if (typeof item.CloudTrailEvent === "string") {
    let parsed;
    try {
      parsed = JSON.parse(item.CloudTrailEvent);
    } catch {
      fail();
    }
    const detail = object(parsed);
    const eventName = detail.eventName;
    const eventSource = detail.eventSource;
    const account = detail.recipientAccountId;
    const eventTime = detail.eventTime;
    const requestParameters = object(detail.requestParameters ?? {});
    const responseElements = detail.responseElements === null ? {} : object(detail.responseElements ?? {});
    let taskArn = requestParameters.task;
    if (eventName === "RunTask") taskArn = responseElements.tasks?.[0]?.taskArn;
    if (eventName === "StopTask") taskArn = responseElements.task?.taskArn ?? requestParameters.task;
    return { account, eventName, eventSource, eventTime, requestParameters, taskArn };
  }
  return item;
}

function requireCloudTrail(events, eventName, taskArn, account, sessionId) {
  if (!Array.isArray(events) || events.length === 0 || events.length > 20) fail();
  const normalized = events.map(normalizeCloudTrailEvent);
  const found = normalized.find((event) =>
    exactKeys(event, CLOUDTRAIL_KEYS).eventSource === "ecs.amazonaws.com" &&
    event.eventName === eventName &&
    event.taskArn === taskArn &&
    event.account === account &&
    (eventName === "RunTask"
      ? object(event.requestParameters).startedBy === sessionId
      : String(object(event.requestParameters).reason ?? "").includes("clockchain cleanup")));
  if (!found) fail();
  eventTimeMs(found.eventTime);
  return found;
}

export function collectFargateRuntimeEvidence(inputOptions) {
  try {
    return collectFargateRuntimeEvidenceStrict(inputOptions);
  } catch (error) {
    if (error?.message === "Fargate runtime evidence validation failed safely.") throw error;
    fail();
  }
}

function collectFargateRuntimeEvidenceStrict(inputOptions) {
  const options = sanitizeFargateData(inputOptions, fail);
  const { plan, sessionId, role, aws } = object(options);
  let verified;
  let input;
  try {
    verified = validateRuntimeProofPlan(plan);
    input = object(sanitizeFargateData(aws, fail));
  } catch (error) {
    if (error?.message === "Fargate runtime evidence validation failed safely.") throw error;
    fail();
  }
  if (!ROLES.includes(role) || typeof sessionId !== "string" || sessionId.length === 0) fail();
  const party = verified.parties[role];
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
  const expectedTaskDefinition = normalizeFargateTaskDefinitionForProof(party.taskDefinition, role);
  const describedTaskDefinition = normalizeFargateTaskDefinitionForProof(taskDefinition, role, { server: true });
  const describedWithoutServerMetadata = {
    ...describedTaskDefinition,
  };
  delete describedWithoutServerMetadata.taskDefinitionArn;
  delete describedWithoutServerMetadata.revision;
  assertSameJson(describedWithoutServerMetadata, expectedTaskDefinition);
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
  if (container.readonlyRootFilesystem !== true || container.user !== party.user || container.privileged !== false) fail();
  assertSameJson(container.environment, party.environment);
  assertSameJson(container.secrets, party.secrets);
  assertSameJson(container.mountPoints, party.mountPoints);
  assertSameJson(container.logConfiguration, party.logConfiguration);
  assertSameJson(taskDefinition.volumes, party.volumes);
  if (taskDefinition.volumes?.some((volume) => Object.hasOwn(object(volume), "efsVolumeConfiguration"))) fail();

  const taskRoleArn = parseAwsArn(party.taskRoleArn);
  const executionRoleArn = parseAwsArn(party.executionRoleArn);
  const taskArn = parseAwsArn(task.taskArn);
  const taskDefinitionArn = parseAwsArn(task.taskDefinitionArn);
  const responseTaskDefinitionArn = parseAwsArn(taskDefinition.taskDefinitionArn);
  if (
    taskRoleArn.service !== "iam" ||
    executionRoleArn.service !== "iam" ||
    taskArn.service !== "ecs" ||
    taskDefinitionArn.service !== "ecs" ||
    responseTaskDefinitionArn.service !== "ecs" ||
    taskArn.account !== taskRoleArn.account ||
    taskDefinitionArn.account !== taskRoleArn.account ||
    responseTaskDefinitionArn.account !== taskRoleArn.account ||
    executionRoleArn.account !== taskRoleArn.account ||
    taskDefinitionArn.region !== taskArn.region ||
    responseTaskDefinitionArn.region !== taskArn.region
  ) fail();
  for (const secret of party.secrets) {
    const secretArn = parseAwsArn(secret.valueFrom);
    if (secretArn.account !== taskRoleArn.account || secretArn.region !== taskArn.region) fail();
  }

  const eniId = attachmentDetail(task, "networkInterfaceId");
  const subnetId = attachmentDetail(task, "subnetId");
  const eni = object(input.networkInterface);
  if (
    eni.NetworkInterfaceId !== eniId ||
    eni.SubnetId !== subnetId ||
    typeof eni.VpcId !== "string" ||
    eni.VpcId.length === 0 ||
    (eni.Association !== undefined && eni.Association !== null) ||
    (eni.PublicIp !== undefined && eni.PublicIp !== null) ||
    (Array.isArray(eni.PrivateIpAddresses) && eni.PrivateIpAddresses.some((entry) => object(entry).Association?.PublicIp !== undefined)) ||
    (Array.isArray(eni.Ipv6Addresses) && eni.Ipv6Addresses.length !== 0)
  ) fail();
  const subnetEnvelope = object(input.describeSubnet);
  const subnet = object(subnetEnvelope.Subnet);
  if (
    subnet.SubnetId !== subnetId ||
    subnet.VpcId !== eni.VpcId ||
    subnet.MapPublicIpOnLaunch !== false ||
    subnet.State !== "available" ||
    (
      subnet.AvailableIpAddressCount !== undefined &&
      (!Number.isSafeInteger(subnet.AvailableIpAddressCount) || subnet.AvailableIpAddressCount < 0)
    )
  ) fail();
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

  const taskId = taskIdFromArn(task.taskArn);
  const logRecords = parseLogRecords(
    input.cloudWatchLogs,
    party.logConfiguration.options["awslogs-group"],
    party.logConfiguration.options["awslogs-stream-prefix"],
    sessionId,
    role,
    taskId,
  );
  const runtimeAttestation = object(logRecords.get("clockchain.mechanics-proof-ecs-attestation/v1"));
  if (
    runtimeAttestation.taskArn !== task.taskArn ||
    runtimeAttestation.taskId !== taskId ||
    runtimeAttestation.accountId !== taskRoleArn.account ||
    runtimeAttestation.region !== taskArn.region ||
    runtimeAttestation.family !== taskDefinition.family ||
    String(runtimeAttestation.revision) !== String(taskDefinition.revision) ||
    runtimeAttestation.containerArn !== object(task.containers?.[0]).containerArn ||
    runtimeAttestation.imageId !== object(task.containers?.[0]).imageDigest ||
    runtimeAttestation.privateIp !== attachmentDetail(task, "privateIPv4Address") ||
    runtimeAttestation.launchType !== "FARGATE" ||
    runtimeAttestation.workloadAttestationDigest !== attestationDigest(runtimeAttestation)
  ) fail();
  if (typeof runtimeAttestation.stsArn !== "string" || !runtimeAttestation.stsArn.includes(`assumed-role/${taskRoleName(party.taskRoleArn)}/`)) fail();
  if (typeof runtimeAttestation.stsUserId !== "string" || runtimeAttestation.stsUserId.length === 0) fail();
  const runTaskEvent = requireCloudTrail(input.cloudTrailEvents, "RunTask", task.taskArn, runtimeAttestation.accountId, sessionId);
  const stopTaskEvent = requireCloudTrail(input.cloudTrailEvents, "StopTask", task.taskArn, runtimeAttestation.accountId, sessionId);
  const createdAtMs = timestampMs(task.createdAt);
  const stoppedAtMs = timestampMs(task.stoppedAt);
  if (eventTimeMs(runTaskEvent.eventTime) > createdAtMs) fail();
  if (eventTimeMs(stopTaskEvent.eventTime) < createdAtMs || eventTimeMs(stopTaskEvent.eventTime) > stoppedAtMs) fail();

  const evidence = {
    schema: RUNTIME_EVIDENCE_SCHEMA,
    runtimeId: `ecs-${runtimeAttestation.taskId}`,
    role,
    taskArn: task.taskArn,
    taskStatus: "STOPPED",
    createdAtMs,
    stoppedAtMs,
    taskRoleArn: party.taskRoleArn,
    executionRoleArn: party.executionRoleArn,
    inTaskStsCallerIdentity: {
      account: runtimeAttestation.accountId,
      arn: runtimeAttestation.stsArn,
      userId: runtimeAttestation.stsUserId,
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
    workspaceRootDigest: attestedDigest(sha256Hex({ taskArn: task.taskArn, mountPath: "/workspace", volume: "workspace" })),
    stateRootDigest: attestedDigest(sha256Hex({ taskArn: task.taskArn, path: "/workspace/state" })),
    signerRootDigest: attestedDigest(sha256Hex({ taskArn: task.taskArn, signerAddress: object(logRecords.get("clockchain.mechanics-proof-party-evidence/v1")).a2aCardSignerAddress })),
    logStreamDigests: publicLogDigests(input.cloudWatchLogs),
    cloudTrailEventDigests: digestListFromRaw(input.cloudTrailEvents),
    ecsDescribeTasksDigest: sha256Hex({
      describeTasks,
      networkInterface: eni,
      describeSubnet: subnetEnvelope,
    }),
    cleanupEvidenceDigest: sha256Hex({
      taskArn: task.taskArn,
      taskStatus: task.lastStatus,
      stoppedAt: task.stoppedAt,
      stopTaskEvent,
    }),
    sessionSanitizationDigest: sha256Hex({
      taskArn: task.taskArn,
      taskStatus: task.lastStatus,
      stoppedAt: task.stoppedAt,
      teardown: object(logRecords.get("clockchain.mechanics-proof-party-evidence/v1")).teardown,
      stopTaskEvent,
    }),
  };
  return validateRuntimeEvidence(evidence);
}

export function validateFargateRuntimeEvidence(value) {
  return validateRuntimeEvidence(value);
}
