import { assertSecretFree } from "../core/redact.mjs";
import { collectFargateRuntimeEvidence } from "../runtime/aws-fargate-evidence.mjs";
import { sha256Hex } from "../runtime/aws-fargate-runtime-adapter.mjs";
import {
  validateRuntimeEvidence,
  validateRuntimePairEvidence,
} from "../runtime/runtime-adapter-contract.mjs";

export const MECHANICS_PROOF_CLOUD_EVIDENCE_SCHEMA = "clockchain.mechanics-proof-cloud-evidence/v1";

const ROLES = Object.freeze(["initiator", "responder"]);
const DIGEST = /^[0-9a-f]{64}$/;
const IMAGE = /^sha256:[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const LEDGER_KINDS = Object.freeze(["proposal", "acceptance", "acknowledgment"]);
const AUTH_WORDING = "SQS publication authenticated by task-role IAM and message binding; exchanged public keys verify later signed A2A envelopes.";
const TRANSPORT_WORDING = "Private workflow content used direct peer HTTPS; SQS carried only public bootstrap descriptors.";

function fail() {
  throw new Error("Mechanics proof cloud evidence validation failed safely.");
}

function object(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function exact(value, keys) {
  const item = object(value);
  if (JSON.stringify(Object.keys(item).sort()) !== JSON.stringify([...keys].sort())) fail();
  return item;
}

function digest(value) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail();
  return value;
}

function unique(values) {
  if (new Set(values).size !== values.length) fail();
}

function assertPrintable(value) {
  try {
    assertSecretFree(value, ["secret-canary"]);
  } catch {
    fail();
  }
  const printed = JSON.stringify(value);
  if (
    /(?:\/Users|\/private\/tmp|raw-log|privateKey|signerSeed|prompt|transcript|reasoning|modelProse|descriptorSignature)/i.test(printed)
  ) fail();
}

function cleanIdentity(value) {
  const item = exact(value, ["erc8004", "policyDigest", "sessionKeyAddress"]);
  const erc8004 = exact(item.erc8004, [
    "agentId", "chainId", "reference", "registrationBlock", "registrationTx", "registryAddress",
  ]);
  if (
    !ADDRESS.test(item.sessionKeyAddress) ||
    !DIGEST.test(item.policyDigest) ||
    !/^(?:0|[1-9][0-9]*)$/.test(erc8004.agentId) ||
    erc8004.chainId !== "eip155:11155111" ||
    erc8004.registryAddress !== "0x8004a818bfb912233c491871b3d84c89a494bd9e" ||
    erc8004.reference !== `${erc8004.chainId}:${erc8004.registryAddress}:${erc8004.agentId}` ||
    !/^0x[0-9a-fA-F]{64}$/.test(erc8004.registrationTx) ||
    !/^(?:0|[1-9][0-9]*)$/.test(erc8004.registrationBlock)
  ) fail();
  return Object.freeze({
    signerAddress: item.sessionKeyAddress.toLowerCase(),
    policyDigest: item.policyDigest,
    erc8004AgentId: erc8004.agentId,
    erc8004Reference: erc8004.reference,
  });
}

function cleanAnchors(value) {
  if (!Array.isArray(value) || value.length !== 3) fail();
  return Object.freeze(value.map((entry, index) => {
    const item = exact(entry, ["blockHeight", "digest", "kind", "ledgerId"]);
    if (
      item.kind !== LEDGER_KINDS[index] ||
      !DIGEST.test(item.digest) ||
      !UUID.test(item.ledgerId) ||
      !/^(?:0|[1-9][0-9]*)$/.test(item.blockHeight)
    ) fail();
    return Object.freeze({ ...item });
  }));
}

function cleanDirectDelivery(value, role) {
  const item = exact(value, [
    "acknowledged", "artifactDigest", "artifactType", "checkpointAcknowledged", "checkpointDigest", "messageDigests",
  ]);
  if (
    item.acknowledged !== true ||
    item.checkpointAcknowledged !== true ||
    item.artifactType !== (role === "initiator" ? "proposal" : "acceptance") ||
    !DIGEST.test(item.artifactDigest) ||
    !DIGEST.test(item.checkpointDigest) ||
    !Array.isArray(item.messageDigests) ||
    item.messageDigests.length !== 2 ||
    item.messageDigests.some((entry) => !DIGEST.test(entry))
  ) fail();
  return Object.freeze({ ...item, messageDigests: Object.freeze([...item.messageDigests]) });
}

function cleanTerminal(value, role, runId) {
  const item = exact(value, [
    "a2aCardSignerAddress", "anchors", "bridgeEvidenceDigest", "certificateDigest", "certificateProofDigest", "certificateVerified",
    "directDelivery", "externalBusinessActionPerformed", "harness", "harnessEvidenceDigest", "identity",
    "peerRuntimeId", "protocolSessionId", "resultDigest", "role", "runId", "runtimeId", "schema",
    "teardown", "terminalStatus", "workloadAttestationDigest",
  ]);
  if (
    item.schema !== "clockchain.mechanics-proof-party-evidence/v1" ||
    item.runId !== runId ||
    item.role !== role ||
    item.harness !== (role === "initiator" ? "codex" : "claude") ||
    item.terminalStatus !== "completed" ||
    item.teardown?.completed !== true ||
    item.certificateVerified !== true ||
    item.externalBusinessActionPerformed !== false ||
    !UUID.test(item.protocolSessionId) ||
    !DIGEST.test(item.workloadAttestationDigest) ||
    !DIGEST.test(item.bridgeEvidenceDigest) ||
    !DIGEST.test(item.harnessEvidenceDigest) ||
    !DIGEST.test(item.certificateProofDigest) ||
    !DIGEST.test(item.certificateDigest) ||
    !DIGEST.test(item.resultDigest) ||
    !ADDRESS.test(item.a2aCardSignerAddress)
  ) fail();
  const identity = cleanIdentity(item.identity);
  if (item.a2aCardSignerAddress.toLowerCase() !== identity.signerAddress) fail();
  return Object.freeze({
    ...item,
    a2aCardSignerAddress: item.a2aCardSignerAddress.toLowerCase(),
    identity,
    anchors: cleanAnchors(item.anchors),
    directDelivery: cleanDirectDelivery(item.directDelivery, role),
    teardown: Object.freeze({ completed: true }),
  });
}

function cleanCleanup(value) {
  const item = exact(value, [
    "confirmAbsence", "listActiveTaskDefinitions", "listInactiveTaskDefinitions", "listQueues", "stoppedTasks", "targets",
  ]);
  const targets = exact(item.targets, ["queueUrls", "stackName", "taskArns", "taskDefinitionArns", "taskDefinitionFamilies"]);
  const queueUrls = exact(targets.queueUrls, ROLES);
  const taskArns = exact(targets.taskArns, ROLES);
  const taskDefinitionArns = exact(targets.taskDefinitionArns, ROLES);
  const taskDefinitionFamilies = exact(targets.taskDefinitionFamilies, ROLES);
  const absence = exact(item.confirmAbsence, ["absent"]);
  if (absence.absent !== true || typeof targets.stackName !== "string") fail();
  const queues = object(item.listQueues);
  if (Object.keys(queues).some((key) => key !== "QueueUrls")) fail();
  const listedQueues = queues.QueueUrls ?? [];
  if (!Array.isArray(listedQueues)) fail();
  for (const role of ROLES) {
    if (
      typeof queueUrls[role] !== "string" ||
      !queueUrls[role].includes(targets.stackName) ||
      listedQueues.includes(queueUrls[role]) ||
      typeof taskDefinitionFamilies[role] !== "string" ||
      !taskDefinitionFamilies[role].includes(role) ||
      typeof taskDefinitionArns[role] !== "string" ||
      !taskDefinitionArns[role].includes(taskDefinitionFamilies[role]) ||
      typeof taskArns[role] !== "string"
    ) fail();
  }
  const active = exact(item.listActiveTaskDefinitions, ["taskDefinitionArns"]);
  const inactive = exact(item.listInactiveTaskDefinitions, ["taskDefinitionArns"]);
  if (!Array.isArray(active.taskDefinitionArns) || !Array.isArray(inactive.taskDefinitionArns)) fail();
  for (const arn of active.taskDefinitionArns) {
    if (ROLES.some((role) => arn.includes(taskDefinitionFamilies[role]))) fail();
  }
  for (const role of ROLES) {
    if (!inactive.taskDefinitionArns.includes(taskDefinitionArns[role])) fail();
  }
  const stopped = exact(item.stoppedTasks, ROLES);
  const tasks = ROLES.map((role) => exact(stopped[role], ["lastStatus", "taskArn"]));
  for (const role of ROLES) {
    const task = tasks.find((entry) => entry.taskArn === taskArns[role]);
    if (
      task?.lastStatus !== "STOPPED" ||
      typeof task.taskArn !== "string"
    ) fail();
  }
  return Object.freeze({ absence, queues, active, inactive, tasks, targets });
}

function rawEnvelopeDigests(value) {
  if (!Array.isArray(value) || value.length === 0) fail();
  return Object.freeze(value.map((entry) => sha256Hex(entry)));
}

export function buildMechanicsProofCloudEvidence(input) {
  try {
    return buildMechanicsProofCloudEvidenceStrict(input);
  } catch (error) {
    if (error?.message === "Mechanics proof cloud evidence validation failed safely.") throw error;
    fail();
  }
}

function buildMechanicsProofCloudEvidenceStrict(input) {
  const item = exact(input, ["cleanupResponses", "imageDigest", "rawControlPlaneEnvelopes", "runId", "runtimeInputs"]);
  if (typeof item.runId !== "string" || !UUID.test(item.runId) || !IMAGE.test(item.imageDigest)) fail();
  const runtimeInputs = exact(item.runtimeInputs, ROLES);
  const runtimes = validateRuntimePairEvidence({
    initiator: collectRuntime(runtimeInputs.initiator, "initiator", item.runId),
    responder: collectRuntime(runtimeInputs.responder, "responder", item.runId),
  });
  const protocol = {
    initiator: terminalFromRuntimeInput(runtimeInputs.initiator, "initiator", item.runId),
    responder: terminalFromRuntimeInput(runtimeInputs.responder, "responder", item.runId),
  };
  const cleanup = cleanCleanup(item.cleanupResponses);
  if (
    runtimes.initiator.imageDigest !== item.imageDigest ||
    runtimes.responder.imageDigest !== item.imageDigest ||
    runtimes.initiator.cloudTrailEventDigests.length < 2 ||
    runtimes.responder.cloudTrailEventDigests.length < 2 ||
    protocol.initiator.protocolSessionId !== protocol.responder.protocolSessionId ||
    protocol.initiator.certificateDigest !== protocol.responder.certificateDigest ||
    protocol.initiator.resultDigest !== protocol.responder.resultDigest ||
    protocol.initiator.runtimeId !== runtimes.initiator.runtimeId ||
    protocol.responder.runtimeId !== runtimes.responder.runtimeId ||
    protocol.initiator.peerRuntimeId !== protocol.responder.runtimeId ||
    protocol.responder.peerRuntimeId !== protocol.initiator.runtimeId ||
    protocol.initiator.workloadAttestationDigest === protocol.responder.workloadAttestationDigest ||
    JSON.stringify(protocol.initiator.anchors) !== JSON.stringify(protocol.responder.anchors)
  ) fail();
  unique([
    runtimes.initiator.taskArn, runtimes.responder.taskArn,
    runtimes.initiator.taskRoleArn, runtimes.responder.taskRoleArn,
    runtimes.initiator.executionRoleArn, runtimes.responder.executionRoleArn,
    runtimes.initiator.eniId, runtimes.responder.eniId,
    runtimes.initiator.workspaceRootDigest, runtimes.responder.workspaceRootDigest,
    runtimes.initiator.signerRootDigest, runtimes.responder.signerRootDigest,
    protocol.initiator.identity.signerAddress, protocol.responder.identity.signerAddress,
    protocol.initiator.identity.erc8004AgentId, protocol.responder.identity.erc8004AgentId,
  ]);
  unique([...runtimes.initiator.securityGroupIds, ...runtimes.responder.securityGroupIds]);
  const rawDigests = rawEnvelopeDigests([
    ...item.rawControlPlaneEnvelopes,
    item.cleanupResponses,
  ]);
  const receiptIds = protocol.initiator.anchors.map((anchor) => anchor.ledgerId);
  const evidence = Object.freeze({
    schema: MECHANICS_PROOF_CLOUD_EVIDENCE_SCHEMA,
    runId: item.runId,
    protocolSessionId: protocol.initiator.protocolSessionId,
    imageDigest: item.imageDigest,
    certificateDigest: protocol.initiator.certificateDigest,
    resultDigest: protocol.initiator.resultDigest,
    certificateVerified: true,
    externalBusinessActionPerformed: false,
    bootstrapPublicationAuthority: AUTH_WORDING,
    privateProtocolTransport: TRANSPORT_WORDING,
    receiptIds: Object.freeze(receiptIds),
    directDeliveries: Object.freeze({
      initiator: protocol.initiator.directDelivery,
      responder: protocol.responder.directDelivery,
    }),
    parties: Object.freeze({
      initiator: publicParty(runtimes.initiator, protocol.initiator),
      responder: publicParty(runtimes.responder, protocol.responder),
    }),
    cleanup: Object.freeze({
      stackAbsent: true,
      queuesAbsent: true,
      taskDefinitionsDeregistered: true,
      activeTaskDefinitionsAbsent: true,
      tasksStopped: true,
      absenceProofDigest: sha256Hex(cleanup),
    }),
    rawControlPlaneEnvelopeDigests: rawDigests,
  });
  assertPrintable(evidence);
  return evidence;
}

function collectRuntime(value, role, runId) {
  const item = exact(value, ["aws", "plan", "role", "sessionId"]);
  if (item.role !== role || item.sessionId !== runId) fail();
  return validateRuntimeEvidence(collectFargateRuntimeEvidence(item));
}

function terminalFromRuntimeInput(value, role, runId) {
  const item = exact(value, ["aws", "plan", "role", "sessionId"]);
  if (item.role !== role || item.sessionId !== runId) fail();
  const aws = object(item.aws);
  if (!Array.isArray(aws.cloudWatchLogs) || aws.cloudWatchLogs.length !== 1) fail();
  const log = object(aws.cloudWatchLogs[0]);
  if (!Array.isArray(log.events)) fail();
  const terminals = [];
  for (const event of log.events) {
    const entry = object(event);
    if (typeof entry.message !== "string") fail();
    let parsed;
    try {
      parsed = JSON.parse(entry.message);
    } catch {
      fail();
    }
    if (parsed?.schema === "clockchain.mechanics-proof-party-evidence/v1") terminals.push(parsed);
  }
  if (terminals.length !== 1) fail();
  return cleanTerminal(terminals[0], role, runId);
}

function publicParty(runtime, terminal) {
  return Object.freeze({
    role: runtime.role,
    taskArn: runtime.taskArn,
    taskRoleArn: runtime.taskRoleArn,
    executionRoleArn: runtime.executionRoleArn,
    taskDefinitionArn: runtime.taskDefinitionArn,
    imageDigest: runtime.imageDigest,
    eniId: runtime.eniId,
    securityGroupIds: runtime.securityGroupIds,
    writableRootBindingDigest: runtime.workspaceRootDigest,
    signerRootBindingDigest: runtime.signerRootDigest,
    signerAddress: terminal.identity.signerAddress,
    a2aCardSignerAddress: terminal.a2aCardSignerAddress,
    erc8004AgentId: terminal.identity.erc8004AgentId,
    erc8004Reference: terminal.identity.erc8004Reference,
    stsCallerIdentityDigest: sha256Hex(runtime.inTaskStsCallerIdentity),
    ecsDescribeTasksDigest: runtime.ecsDescribeTasksDigest,
    taskDefinitionDigest: runtime.taskDefinitionDigest,
    cloudTrailEventDigests: runtime.cloudTrailEventDigests,
    logStreamDigests: runtime.logStreamDigests,
    cleanupEvidenceDigest: runtime.cleanupEvidenceDigest,
    ephemeralSessionTeardownDigest: runtime.sessionSanitizationDigest,
  });
}
