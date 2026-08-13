#!/usr/bin/env node

import { fileURLToPath } from "node:url";
import { chmod, link, lstat, mkdir, open, realpath, stat, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { tmpdir } from "node:os";

import { createAwsCliControlPlane } from "../src/runtime/aws-cli-control-plane.mjs";
import { buildFargateLiveStackPlan } from "../src/runtime/aws-fargate-live-plan.mjs";
import {
  buildFargateLivePreflightPlan,
  buildFargateDryRunSummary,
  loadFargateDryRunPlan,
} from "../src/runtime/aws-fargate-runtime-adapter.mjs";
import { runFargateLiveMechanicsProof } from "../src/runtime/aws-fargate-live-adapter.mjs";
import { buildFargateRuntimeProofPlan } from "../src/runtime/aws-fargate-evidence.mjs";
import { buildMechanicsProofCloudEvidence } from "../src/testing/mechanics-proof-cloud-evidence.mjs";

const PRODUCTION_MCP_URL = "https://mcp.clockchain.network/handshake/mcp";
const REQUIRED_TOOLS = Object.freeze([
  "agent_handshake_accept_invitation",
  "agent_handshake_get_certificate",
  "agent_handshake_invite",
  "agent_handshake_join",
  "agent_handshake_next",
  "agent_handshake_status",
  "agent_handshake_submit",
  "agent_handshake_submit_checkpoint",
].sort());
const MCP_BODY_LIMIT_BYTES = 131_072;
const PRODUCTION_DISCOVERY_URL = "http://44.249.47.220:8080/v1/discovery/current";

function fail() {
  throw new Error("Fargate mechanics proof runner failed safely.");
}

function die() {
  process.stderr.write("Fargate mechanics proof runner failed safely.\n");
  process.exitCode = 1;
}

function take(args, flag) {
  const index = args.indexOf(flag);
  if (index < 0 || index === args.length - 1) fail();
  const value = args[index + 1];
  args.splice(index, 2);
  return value;
}

function number(value, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > max) fail();
  return parsed;
}

export function parseFargateRunnerArgs(argv = process.argv) {
  const args = argv.slice(2);
  if (args.length === 1 && args[0] === "--dry-run") return Object.freeze({ mode: "dry-run" });
  if (args.includes("--dry-run") && args.includes("--run")) fail();
  if (
    args.length === 8 &&
    args[0] === "--preflight" &&
    args[1] === "--pair" &&
    args[3] === "--direct-a2a" &&
    args[4] === "--evidence-dir" &&
    args[6] === "--app-image"
  ) {
    return Object.freeze({ mode: "preflight", pair: args[2], evidenceDir: args[5], appImage: args[7] });
  }
  const mode = args.shift();
  if (mode !== "--run") fail();
  const parsed = {
    mode: "run",
    accountId: take(args, "--account"),
    region: take(args, "--region"),
    runId: take(args, "--run-id"),
    vpcId: take(args, "--vpc-id"),
    publicSubnetId: take(args, "--public-subnet-id"),
    initiatorPrivateSubnet: { cidr: take(args, "--initiator-private-cidr"), availabilityZone: take(args, "--initiator-az") },
    responderPrivateSubnet: { cidr: take(args, "--responder-private-cidr"), availabilityZone: take(args, "--responder-az") },
    codexSecretArn: take(args, "--codex-secret-arn"),
    appImage: take(args, "--image"),
    evidenceDir: take(args, "--evidence-dir"),
    ttlSeconds: number(take(args, "--ttl-seconds"), 3600),
    budgetUsd: number(take(args, "--budget-usd"), 25),
    mcpUrl: take(args, "--mcp-url"),
    maxConcurrency: 2,
  };
  if (args.length !== 0 || parsed.mcpUrl !== PRODUCTION_MCP_URL) fail();
  parsed.bedrockModelArn = `arn:aws:bedrock:${parsed.region}:${parsed.accountId}:inference-profile/us.anthropic.claude-sonnet-4-6`;
  return Object.freeze(parsed);
}

function parseMcpEnvelope(bytes, contentType) {
  if (typeof bytes !== "string" || bytes.length === 0 || bytes.length > MCP_BODY_LIMIT_BYTES) fail();
  if (/event-stream/i.test(contentType)) {
    const messages = bytes.trim().split(/\n\n+/).filter(Boolean);
    if (messages.length !== 1) fail();
    const lines = messages[0].split(/\n/);
    if (lines[0] !== "event: message") fail();
    const data = lines.find((line) => line.startsWith("data: "));
    if (!data) fail();
    return JSON.parse(data.slice(6));
  }
  return JSON.parse(bytes);
}

async function readBoundedResponseBody(response) {
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(contentLength) || Number(contentLength) > MCP_BODY_LIMIT_BYTES) fail();
  }
  if (!response.body?.getReader) fail();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) fail();
    total += value.byteLength;
    if (total > MCP_BODY_LIMIT_BYTES) fail();
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

async function rpc(fetchImpl, url, method) {
  const id = `clockchain-fargate-${method}`;
  const response = await fetchImpl(url, {
    method: "POST",
    redirect: "error",
    headers: Object.freeze({ "content-type": "application/json", accept: "application/json, text/event-stream" }),
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params: method === "initialize" ? { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "clockchain-fargate-controller", version: "2.1.3" } } : {} }),
    signal: AbortSignal.timeout(5000),
  });
  if (response?.ok !== true) fail();
  const contentType = response.headers?.get?.("content-type") ?? "";
  try {
    const envelope = parseMcpEnvelope(await readBoundedResponseBody(response), contentType);
    if (envelope.id !== id) fail();
    return envelope;
  } catch {
    fail();
  }
}

export async function checkProductionMcpGate(options = {}) {
  const url = options.url ?? options.mcpUrl;
  if (url !== PRODUCTION_MCP_URL) fail();
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") fail();
  let health;
  try {
    health = await fetchImpl("https://mcp.clockchain.network/health", {
      method: "GET",
      redirect: "error",
      headers: Object.freeze({ accept: "application/json" }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    fail();
  }
  if (health?.ok !== true) fail();
  let healthBody;
  try {
    healthBody = JSON.parse(await readBoundedResponseBody(health));
  } catch {
    fail();
  }
  if (JSON.stringify(healthBody) !== JSON.stringify({ status: "ok" })) fail();
  const initialize = await rpc(fetchImpl, url, "initialize");
  const initResult = initialize.result;
  if (
    initialize.jsonrpc !== "2.0" ||
    initResult?.serverInfo?.name !== "clockchain-agent-handshake" ||
    initResult.serverInfo.version !== "2.1.3" ||
    initResult.protocolVersion !== "2025-06-18"
  ) fail();
  const toolsEnvelope = await rpc(fetchImpl, url, "tools/list");
  const result = toolsEnvelope.result;
  if (toolsEnvelope.jsonrpc !== "2.0" || !Array.isArray(result?.tools)) fail();
  const names = result.tools.map((tool) => tool?.name).sort();
  if (new Set(names).size !== names.length) fail();
  if (JSON.stringify(names) !== JSON.stringify(REQUIRED_TOOLS)) fail();
  return Object.freeze({ healthy: true, checkpointTool: true, endpoint: url, toolNames: Object.freeze(names) });
}

export async function waitProductionInvitationWindow(options = {}) {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const now = options.now ?? (() => Date.now());
  const sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const deadlineMs = options.deadlineMs;
  const minimumRemainingMs = options.minimumRemainingMs;
  if (
    typeof fetchImpl !== "function" || typeof now !== "function" || typeof sleep !== "function" ||
    !Number.isSafeInteger(deadlineMs) || !Number.isSafeInteger(minimumRemainingMs) || minimumRemainingMs !== 90_000
  ) fail();
  for (;;) {
    const observedNow = now();
    if (!Number.isSafeInteger(observedNow) || observedNow >= deadlineMs) fail();
    let response;
    try {
      response = await fetchImpl(PRODUCTION_DISCOVERY_URL, {
        method: "GET",
        redirect: "error",
        headers: Object.freeze({ accept: "application/json" }),
        signal: AbortSignal.timeout(5000),
      });
    } catch { fail(); }
    if (response?.ok !== true) fail();
    let discovery;
    try { discovery = JSON.parse(await readBoundedResponseBody(response)); } catch { fail(); }
    const keys = [
      "createdAtMs", "externalBusinessActionPerformed", "hostSessionKeyCertificate", "invitationExpiresAtMs",
      "kitRepoUrl", "protocol", "relayUrl", "repositorySha", "schema", "sessionDeadlineMs", "sessionId", "sessionOpenedBlock",
    ];
    if (
      discovery === null || typeof discovery !== "object" || Array.isArray(discovery) ||
      JSON.stringify(Object.keys(discovery).sort()) !== JSON.stringify(keys.sort()) ||
      discovery.schema !== "clockchain.agent-handshake-discovery/v2" ||
      discovery.protocol !== "clockchain.agent-handshake/v2" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(discovery.sessionId) ||
      !/^[0-9a-f]{40}$/.test(discovery.repositorySha) ||
      !/^(?:0|[1-9][0-9]*)$/.test(discovery.invitationExpiresAtMs) ||
      !/^(?:0|[1-9][0-9]*)$/.test(discovery.sessionDeadlineMs) ||
      discovery.hostSessionKeyCertificate === null || typeof discovery.hostSessionKeyCertificate !== "object" ||
      discovery.externalBusinessActionPerformed !== false
    ) fail();
    const invitationExpiresAtMs = Number(discovery.invitationExpiresAtMs);
    if (Number.isSafeInteger(invitationExpiresAtMs) && invitationExpiresAtMs - observedNow >= minimumRemainingMs) {
      return Object.freeze({ ready: true });
    }
    await sleep(2000);
  }
}

async function retainEvidenceFile(path, evidence) {
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(evidence)}\n`, "utf8");
  } finally {
    await handle.close();
  }
}

async function unlinkIfPresent(path) {
  try {
    await unlink(path);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

export async function retainFargateSuccessEvidence(evidenceDir, evidenceBundle) {
  const controllerFinal = join(evidenceDir, "controller-evidence.json");
  const publicFinal = join(evidenceDir, "public-proof.json");
  const controllerTemp = join(evidenceDir, ".controller-evidence.json.pending");
  const publicTemp = join(evidenceDir, ".public-proof.json.pending");
  let controllerLinked = false;
  let publicLinked = false;
  try {
    if (
      evidenceBundle === null ||
      typeof evidenceBundle !== "object" ||
      Array.isArray(evidenceBundle) ||
      JSON.stringify(Object.keys(evidenceBundle).sort()) !== JSON.stringify(["controllerEvidence", "publicProof"])
    ) fail();
    await reserveFargateEvidenceDir(evidenceDir);
    await Promise.all([
      lstat(controllerFinal).then(() => fail(), (error) => { if (error?.code !== "ENOENT") throw error; }),
      lstat(publicFinal).then(() => fail(), (error) => { if (error?.code !== "ENOENT") throw error; }),
    ]);
    await retainEvidenceFile(controllerTemp, evidenceBundle.controllerEvidence);
    await retainEvidenceFile(publicTemp, evidenceBundle.publicProof);
    await chmod(controllerTemp, 0o600);
    await chmod(publicTemp, 0o600);
    await link(controllerTemp, controllerFinal);
    controllerLinked = true;
    await link(publicTemp, publicFinal);
    publicLinked = true;
    await unlink(controllerTemp);
    await unlink(publicTemp);
    if (((await stat(controllerFinal)).mode & 0o777) !== 0o600) fail();
    if (((await stat(publicFinal)).mode & 0o777) !== 0o600) fail();
  } catch (error) {
    if (publicLinked) await unlinkIfPresent(publicFinal);
    if (controllerLinked) await unlinkIfPresent(controllerFinal);
    await unlinkIfPresent(publicTemp);
    await unlinkIfPresent(controllerTemp);
    if (error?.message === "Fargate mechanics proof runner failed safely.") throw error;
    fail();
  }
}

export function buildFargatePublicProofEvidence(proofInput) {
  try {
    return buildMechanicsProofCloudEvidence(proofInput);
  } catch (error) {
    if (error?.message === "Fargate mechanics proof runner failed safely.") throw error;
    fail();
  }
}

function roleValue(values, role) {
  const value = values?.[role];
  if (typeof value !== "string" || value.length === 0) fail();
  return value;
}

function taskEniId(task) {
  const details = task?.attachments?.find?.((attachment) => attachment?.type === "ElasticNetworkInterface")?.details;
  const value = details?.find?.((entry) => entry?.name === "networkInterfaceId")?.value;
  if (typeof value !== "string" || value.length === 0) fail();
  return value;
}

function taskSubnetId(task) {
  const details = task?.attachments?.find?.((attachment) => attachment?.type === "ElasticNetworkInterface")?.details;
  const value = details?.find?.((entry) => entry?.name === "subnetId")?.value;
  if (typeof value !== "string" || value.length === 0) fail();
  return value;
}

function taskDefinitionFamily(taskDefinitionArn) {
  const tail = taskDefinitionArn.split("/").at(-1);
  const family = tail?.split(":").at(0);
  if (typeof family !== "string" || family.length === 0) fail();
  return family;
}

function logGroupFromTaskDefinition(taskDefinition, role) {
  const container = taskDefinition?.containerDefinitions?.find?.((entry) => entry?.name === role);
  const value = container?.logConfiguration?.options?.["awslogs-group"];
  if (typeof value !== "string" || value.length === 0) fail();
  return value;
}

function parsedCloudTrailEvent(event) {
  if (typeof event?.CloudTrailEvent !== "string") fail();
  try {
    return JSON.parse(event.CloudTrailEvent);
  } catch {
    fail();
  }
}

function eventTaskArn(event) {
  if (event.eventName === "RunTask") return event.responseElements?.tasks?.[0]?.taskArn;
  if (event.eventName === "StopTask") return event.responseElements?.task?.taskArn ?? event.requestParameters?.task;
  return null;
}

function hasExactCloudTrailEvents(events, taskArns, runId) {
  return ["RunTask", "StopTask"].every((eventName) => taskArns.every((taskArn) => events.some((event) => {
    const parsed = parsedCloudTrailEvent(event);
    return parsed.eventName === eventName &&
      parsed.eventSource === "ecs.amazonaws.com" &&
      eventTaskArn(parsed) === taskArn &&
      (eventName === "RunTask"
        ? parsed.requestParameters?.startedBy === runId
        : String(parsed.requestParameters?.reason ?? "").includes("clockchain cleanup"));
  })));
}

function cloudTrailWindow(tasks) {
  const created = tasks.map((task) => Date.parse(task.createdAt));
  const stopped = tasks.map((task) => Date.parse(task.stoppedAt));
  if ([...created, ...stopped].some((value) => !Number.isSafeInteger(value))) fail();
  return Object.freeze({
    startTime: new Date(Math.min(...created) - 60_000).toISOString(),
    endTime: new Date(Math.max(...stopped) + 60_000).toISOString(),
  });
}

async function lookupEcsCloudTrailEvents({ controlPlane, region, taskArns, runId, startTime, endTime, sleep = (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)) }) {
  const collected = [];
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await controlPlane.lookupEcsCloudTrailEvents({ startTime, endTime });
    if (!Array.isArray(response?.Events)) fail();
    collected.push(...response.Events);
    if (hasExactCloudTrailEvents(collected, taskArns, runId)) return collected;
    if (attempt < 119) await sleep(1000);
  }
  return collected;
}

async function collectRoleLiveInfraInput({ controlPlane, region, role, clusterArn, taskArn, taskDefinitionArn, securityGroupId }) {
  const describeTasks = await controlPlane.describeTasks({ cluster: clusterArn, taskArns: [taskArn] });
  const task = describeTasks.tasks?.[0];
  if (task?.taskArn !== taskArn) fail();
  const taskDefinition = await controlPlane.describeTaskDefinition({ taskDefinitionArn });
  const taskDefinitionBody = taskDefinition.taskDefinition;
  if (taskDefinitionBody?.taskDefinitionArn !== taskDefinitionArn) fail();
  const eniId = taskEniId(task);
  const subnetId = taskSubnetId(task);
  const eniResponse = await controlPlane.describeNetworkInterfaces({ networkInterfaceIds: [eniId] });
  const networkInterface = eniResponse.NetworkInterfaces?.[0];
  const describeSubnet = await controlPlane.describeSubnetsByIds({ subnetIds: [subnetId] });
  const securityGroupResponse = await controlPlane.describeSecurityGroups({ groupIds: [securityGroupId] });
  return Object.freeze({
    role,
    taskDefinition: taskDefinitionBody,
    securityGroupId,
    aws: Object.freeze({
      taskDefinition,
      networkInterface,
      describeSubnet: Object.freeze({ Subnet: describeSubnet.Subnets?.[0] }),
      securityGroups: Object.freeze({ [securityGroupId]: securityGroupResponse.SecurityGroups?.[0] }),
    }),
  });
}

async function collectRoleRuntimeRaw({ controlPlane, runId, region, role, clusterArn, taskArn, taskDefinitionArn, securityGroupId, liveRoleInput = null, cloudTrailEvents }) {
  const describeTasks = await controlPlane.describeTasks({ cluster: clusterArn, taskArns: [taskArn] });
  const task = describeTasks.tasks?.[0];
  if (task?.taskArn !== taskArn || task.lastStatus !== "STOPPED") fail();
  const live = liveRoleInput ?? await collectRoleLiveInfraInput({ controlPlane, region, role, clusterArn, taskArn, taskDefinitionArn, securityGroupId });
  if (live.role !== role || live.securityGroupId !== securityGroupId || live.taskDefinition?.taskDefinitionArn !== taskDefinitionArn) fail();
  if (!Array.isArray(cloudTrailEvents) || cloudTrailEvents.length === 0) fail();
  const logGroupName = logGroupFromTaskDefinition(live.taskDefinition, role);
  const logs = await controlPlane.filterLogEvents({ logGroupName });
  if (!Array.isArray(logs.events)) fail();
  const logStreamName = logs.events.find((event) => typeof event?.logStreamName === "string")?.logStreamName ?? `${role}/${role}/${taskArn.split("/").at(-1)}`;
  return {
    role,
    taskDefinition: live.taskDefinition,
    securityGroupId,
    aws: {
      describeTasks,
      taskDefinition: live.aws.taskDefinition,
      networkInterface: live.aws.networkInterface,
      describeSubnet: live.aws.describeSubnet,
      securityGroups: live.aws.securityGroups,
      cloudTrailEvents,
      cloudWatchLogs: [{
        logGroupName,
        logStreamName,
        events: logs.events ?? [],
      }],
    },
  };
}

export async function collectFargateLiveInfraProofInputs(optionsInput) {
  try {
    const options = optionsInput;
    if (options === null || typeof options !== "object" || Array.isArray(options)) fail();
    const { stackOutputs, clusterArn, taskArns, taskDefinitionArns, controlPlane } = options;
    if (controlPlane === null || typeof controlPlane !== "object" || typeof controlPlane.describeTasks !== "function") fail();
    const runId = typeof options.runId === "string" ? options.runId : options.plan?.runId;
    const region = typeof options.region === "string" ? options.region : options.plan?.region;
    if (typeof runId !== "string" || typeof region !== "string") fail();
    const roles = {};
    for (const role of ["initiator", "responder"]) {
      roles[role] = await collectRoleLiveInfraInput({
        controlPlane,
        region,
        role,
        clusterArn,
        taskArn: roleValue(taskArns, role),
        taskDefinitionArn: roleValue(taskDefinitionArns, role),
        securityGroupId: role === "initiator" ? stackOutputs.InitiatorSecurityGroupId : stackOutputs.ResponderSecurityGroupId,
      });
    }
    return Object.freeze({ runId, roles: Object.freeze(roles) });
  } catch (error) {
    if (error?.message === "Fargate mechanics proof runner failed safely.") throw error;
    fail();
  }
}

export async function collectFargateRuntimeProofInputs(optionsInput) {
  try {
    const options = optionsInput;
    if (options === null || typeof options !== "object" || Array.isArray(options)) fail();
    const { plan, stackOutputs, clusterArn, taskArns, taskDefinitionArns, controlPlane } = options;
    if (
      controlPlane === null ||
      typeof controlPlane !== "object" ||
      typeof controlPlane.describeTasks !== "function" ||
      typeof controlPlane.lookupEcsCloudTrailEvents !== "function"
    ) fail();
    if (plan === null || typeof plan !== "object") fail();
    const runId = typeof options.runId === "string" ? options.runId : plan.runId;
    const region = typeof options.region === "string" ? options.region : plan.region;
    if (typeof runId !== "string" || typeof region !== "string") fail();
    const rawByRole = {};
    const parties = {};
    const rawControlPlaneEnvelopes = [];
    const stoppedTasksForWindow = [];
    for (const role of ["initiator", "responder"]) {
      const described = await controlPlane.describeTasks({ cluster: clusterArn, taskArns: [roleValue(taskArns, role)] });
      const task = described.tasks?.[0];
      if (task?.taskArn !== roleValue(taskArns, role) || task.lastStatus !== "STOPPED") fail();
      stoppedTasksForWindow.push(task);
    }
    const window = cloudTrailWindow(stoppedTasksForWindow);
    const exactTaskArns = ["initiator", "responder"].map((role) => roleValue(taskArns, role));
    const cloudTrailEvents = await lookupEcsCloudTrailEvents({ controlPlane, region, taskArns: exactTaskArns, runId, ...window });
    for (const role of ["initiator", "responder"]) {
      rawByRole[role] = await collectRoleRuntimeRaw({
        controlPlane,
        runId,
        region,
        role,
        clusterArn,
        taskArn: roleValue(taskArns, role),
        taskDefinitionArn: roleValue(taskDefinitionArns, role),
        securityGroupId: role === "initiator" ? stackOutputs.InitiatorSecurityGroupId : stackOutputs.ResponderSecurityGroupId,
        liveRoleInput: options.liveRuntimeInfraInputs?.roles?.[role] ?? null,
        cloudTrailEvents,
      });
      parties[role] = {
        role,
        taskDefinition: rawByRole[role].taskDefinition,
        family: rawByRole[role].taskDefinition.family,
        taskRoleArn: rawByRole[role].taskDefinition.taskRoleArn,
        executionRoleArn: rawByRole[role].taskDefinition.executionRoleArn,
        image: rawByRole[role].taskDefinition.containerDefinitions.find((entry) => entry.name === role).image,
        imageDigest: rawByRole[role].taskDefinition.containerDefinitions.find((entry) => entry.name === role).image.split("@").at(-1),
        user: rawByRole[role].taskDefinition.containerDefinitions.find((entry) => entry.name === role).user,
        readonlyRootFilesystem: rawByRole[role].taskDefinition.containerDefinitions.find((entry) => entry.name === role).readonlyRootFilesystem,
        privileged: rawByRole[role].taskDefinition.containerDefinitions.find((entry) => entry.name === role).privileged,
        securityGroupId: rawByRole[role].securityGroupId,
      };
      rawControlPlaneEnvelopes.push(
        rawByRole[role].aws.describeTasks,
        rawByRole[role].aws.taskDefinition,
        rawByRole[role].aws.networkInterface,
        rawByRole[role].aws.describeSubnet,
        rawByRole[role].aws.securityGroups,
        rawByRole[role].aws.cloudTrailEvents,
        rawByRole[role].aws.cloudWatchLogs,
      );
    }
    const proofPlan = plan.parties === undefined ? buildFargateRuntimeProofPlan({ parties }) : plan;
    const imageDigest = proofPlan.parties?.initiator?.imageDigest;
    if (typeof imageDigest !== "string") fail();
    const runtimeInputs = {};
    for (const role of ["initiator", "responder"]) {
      runtimeInputs[role] = {
        plan: proofPlan,
        sessionId: runId,
        role,
        aws: rawByRole[role].aws,
      };
    }
    return Object.freeze({
      runId,
      imageDigest,
      runtimeInputs,
      rawControlPlaneEnvelopes,
    });
  } catch (error) {
    if (error?.message === "Fargate mechanics proof runner failed safely.") throw error;
    fail();
  }
}

export async function collectFargateCleanupProofInputs(optionsInput) {
  try {
    const options = optionsInput;
    if (options === null || typeof options !== "object" || Array.isArray(options)) fail();
    const { stackOutputs, taskArns, taskDefinitionArns, controlPlane, runtimeProofInput } = options;
    if (controlPlane === null || typeof controlPlane !== "object" || typeof controlPlane.listQueues !== "function" || typeof controlPlane.confirmAbsence !== "function") fail();
    const runId = typeof options.runId === "string" ? options.runId : runtimeProofInput?.runId;
    const region = typeof options.region === "string" ? options.region : undefined;
    if (typeof runId !== "string" || typeof region !== "string") fail();
    const stackName = typeof options.stackName === "string" ? options.stackName : `clockchain-${runId}`;
    const stoppedTasks = {};
    for (const role of ["initiator", "responder"]) {
      const task = runtimeProofInput?.runtimeInputs?.[role]?.aws?.describeTasks?.tasks?.[0];
      if (task?.taskArn !== roleValue(taskArns, role) || task.lastStatus !== "STOPPED") fail();
      stoppedTasks[role] = { taskArn: task.taskArn, lastStatus: task.lastStatus };
    }
    return Object.freeze({
      targets: {
        stackName,
        queueUrls: { initiator: stackOutputs.InitiatorQueueUrl, responder: stackOutputs.ResponderQueueUrl },
        taskDefinitionArns,
        taskDefinitionFamilies: {
          initiator: taskDefinitionFamily(roleValue(taskDefinitionArns, "initiator")),
          responder: taskDefinitionFamily(roleValue(taskDefinitionArns, "responder")),
        },
        taskArns,
      },
      confirmAbsence: await controlPlane.confirmAbsence({ stackName }),
      listQueues: await controlPlane.listQueues({ queueNamePrefix: stackName }),
      listActiveTaskDefinitions: await controlPlane.listTaskDefinitions({ familyPrefix: `${stackName}-`, status: "ACTIVE" }),
      listInactiveTaskDefinitions: await controlPlane.listTaskDefinitions({ familyPrefix: `${stackName}-`, status: "INACTIVE" }),
      stoppedTasks,
    });
  } catch (error) {
    if (error?.message === "Fargate mechanics proof runner failed safely.") throw error;
    fail();
  }
}

export async function collectFargateCloudProofInputs(optionsInput) {
  const runtimeProofInput = await collectFargateRuntimeProofInputs(optionsInput);
  if (optionsInput?.cleanupPhase !== true) return runtimeProofInput;
  return Object.freeze({
    ...runtimeProofInput,
    cleanupResponses: await collectFargateCleanupProofInputs({ ...optionsInput, runtimeProofInput }),
  });
}

export async function reserveFargateEvidenceDir(evidenceDir) {
  const allowedRoots = [tmpdir(), "/private/tmp", resolve(process.cwd(), ".tmp")];
  if (
    typeof evidenceDir !== "string" ||
    !isAbsolute(evidenceDir) ||
    resolve(evidenceDir) !== evidenceDir ||
    evidenceDir === "/" ||
    evidenceDir === process.env.HOME ||
    !/^mechanics-proof/.test(basename(evidenceDir)) ||
    !allowedRoots.some((root) => evidenceDir === root || evidenceDir.startsWith(`${root}/`)) ||
    dirname(evidenceDir) === "/etc"
  ) fail();
  try {
    const existing = await lstat(evidenceDir).catch((error) => {
      if (error?.code === "ENOENT") return null;
      throw error;
    });
    if (existing?.isSymbolicLink()) fail();
    if (existing) {
      if (!existing.isDirectory() || (existing.mode & 0o777) !== 0o700) fail();
    } else {
      await mkdir(evidenceDir, { recursive: false, mode: 0o700 });
      await chmod(evidenceDir, 0o700);
    }
    const realParent = await realpath(dirname(evidenceDir));
    const realAllowed = await Promise.all(allowedRoots.map((root) => realpath(root).catch(() => root)));
    if (!realAllowed.some((root) => realParent === root || realParent.startsWith(`${root}/`))) fail();
    await realpath(evidenceDir);
  } catch (error) {
    if (error?.message === "Fargate mechanics proof runner failed safely.") throw error;
    fail();
  }
}

async function main() {
  try {
    const parsed = parseFargateRunnerArgs(process.argv);
    if (parsed.mode === "dry-run") {
      const plan = await loadFargateDryRunPlan();
      process.stdout.write(`${JSON.stringify(buildFargateDryRunSummary(plan))}\n`);
      return;
    }
    if (parsed.mode === "preflight") {
      const plan = await loadFargateDryRunPlan();
      const summary = await buildFargateLivePreflightPlan({
        plan,
        pair: parsed.pair,
        directA2A: true,
        mcpUrl: PRODUCTION_MCP_URL,
        evidenceDir: parsed.evidenceDir,
        appImage: parsed.appImage,
      });
      process.stdout.write(`${JSON.stringify(summary)}\n`);
      return;
    }
    await reserveFargateEvidenceDir(parsed.evidenceDir);
    const controlPlane = createAwsCliControlPlane({ region: parsed.region, accountId: parsed.accountId });
    const startedAt = new Date().toISOString();
    const expiresAt = new Date(Date.parse(startedAt) + parsed.ttlSeconds * 1000).toISOString();
    const networkInspection = await controlPlane.inspectNetwork({
      vpcId: parsed.vpcId,
      publicSubnetId: parsed.publicSubnetId,
      initiatorPrivateCidr: parsed.initiatorPrivateSubnet.cidr,
      responderPrivateCidr: parsed.responderPrivateSubnet.cidr,
    });
    const plan = await buildFargateLiveStackPlan({
      accountId: parsed.accountId,
      appImage: parsed.appImage,
      bedrockModelArn: parsed.bedrockModelArn,
      budgetUsd: parsed.budgetUsd,
      codexSecretArn: parsed.codexSecretArn,
      expiresAt,
      initiatorPrivateSubnet: parsed.initiatorPrivateSubnet,
      maxConcurrency: 2,
      mcpUrl: parsed.mcpUrl,
      networkInspection,
      publicSubnetId: parsed.publicSubnetId,
      region: parsed.region,
      responderPrivateSubnet: parsed.responderPrivateSubnet,
      runId: parsed.runId,
      startedAt,
      ttlSeconds: parsed.ttlSeconds,
      vpcId: parsed.vpcId,
    });
    const result = await runFargateLiveMechanicsProof({
      plan,
      controlPlane,
      mcpGate: checkProductionMcpGate,
      waitInvitationWindow: waitProductionInvitationWindow,
      collectLiveRuntimeInfraInputs: (context) => collectFargateLiveInfraProofInputs({
        plan,
        runId: context.runId,
        region: parsed.region,
        stackOutputs: context.stackOutputs,
        clusterArn: context.clusterArn,
        taskArns: context.taskArns,
        taskDefinitionArns: context.taskDefinitionArns,
        controlPlane,
      }),
      collectRuntimeEvidenceInputs: (context) => collectFargateRuntimeProofInputs({
        plan,
        runId: context.runId,
        region: parsed.region,
        stackOutputs: context.stackOutputs,
        clusterArn: context.clusterArn,
        taskArns: context.taskArns,
        taskDefinitionArns: context.taskDefinitionArns,
        liveRuntimeInfraInputs: context.liveRuntimeInfraInputs,
        controlPlane,
      }),
      finalizeVerifiedEvidence: async (context) => {
        const cleanupResponses = await collectFargateCleanupProofInputs({
          runId: context.runId,
          region: parsed.region,
          stackName: context.stackName,
          stackOutputs: context.stackOutputs,
          taskArns: context.taskArns,
          taskDefinitionArns: context.taskDefinitionArns,
          runtimeProofInput: context.runtimeEvidenceInputs,
          controlPlane,
        });
        return buildFargatePublicProofEvidence({
          ...context.runtimeEvidenceInputs,
          cleanupResponses,
        });
      },
      retainEvidence: ({ controllerEvidence, publicProof }) => retainFargateSuccessEvidence(parsed.evidenceDir, { controllerEvidence, publicProof }),
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (result.status !== "SUCCEEDED") process.exitCode = 1;
  } catch {
    die();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main();
}
