import assert from "node:assert/strict";
import test from "node:test";

import { buildFargateLiveStackPlan } from "../src/runtime/aws-fargate-live-plan.mjs";
import { runFargateLiveMechanicsProof, CLEANUP_UNCONFIRMED, PROTOCOL_FAILED_CLEAN } from "../src/runtime/aws-fargate-live-adapter.mjs";
import { createAwsCliControlPlane } from "../src/runtime/aws-cli-control-plane.mjs";

const RUN_ID = "11111111-2222-4333-8444-555555555555";
const ACCOUNT = "123456789012";
const REGION = "us-west-2";
const IMAGE = `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/clockchain-mechanics-proof@sha256:${"6".repeat(64)}`;
const STACK_NAME = `clockchain-${RUN_ID}`;
const STACK_ID = `arn:aws:cloudformation:${REGION}:${ACCOUNT}:stack/${STACK_NAME}/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee`;

async function livePlan(overrides = {}) {
  return buildFargateLiveStackPlan({
    accountId: ACCOUNT,
    appImage: IMAGE,
    bedrockModelArn: `arn:aws:bedrock:${REGION}:${ACCOUNT}:inference-profile/us.anthropic.claude-sonnet-4-6`,
    budgetUsd: 25,
    codexSecretArn: `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:clockchain/codex-AbCdEf`,
    expiresAt: "2026-08-12T21:00:00.000Z",
    initiatorPrivateSubnet: { availabilityZone: "us-west-2a", cidr: "10.44.16.0/24" },
    maxConcurrency: 2,
    mcpUrl: "https://mcp.clockchain.network/handshake/mcp",
    networkInspection: {
      existingSubnets: [{ cidr: "10.44.1.0/24", subnetId: "subnet-public", vpcId: "vpc-live" }],
      publicRouteTable: { routeTableId: "rtb-public", routes: [{ destinationCidrBlock: "0.0.0.0/0", gatewayId: "igw-live", state: "active" }] },
      publicSubnet: { availabilityZone: "us-west-2a", cidr: "10.44.1.0/24", mapPublicIpOnLaunch: true, routeTableId: "rtb-public", subnetId: "subnet-public", vpcId: "vpc-live" },
      vpc: { cidrs: ["10.44.0.0/16"], vpcId: "vpc-live" },
    },
    publicSubnetId: "subnet-public",
    region: REGION,
    responderPrivateSubnet: { availabilityZone: "us-west-2b", cidr: "10.44.17.0/24" },
    runId: RUN_ID,
    startedAt: "2026-08-12T20:00:00.000Z",
    ttlSeconds: 3600,
    vpcId: "vpc-live",
    ...overrides,
  });
}

function stackOutputs() {
  return {
    ClusterArn: `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/${STACK_NAME}`,
    InitiatorExecutionRoleArn: `arn:aws:iam::${ACCOUNT}:role/cc-${RUN_ID}-i-exec`,
    InitiatorLogGroupName: `/clockchain/mechanics-proof/${RUN_ID}/initiator`,
    InitiatorPrivateSubnetId: "subnet-i",
    InitiatorQueueUrl: `https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/${STACK_NAME}-initiator`,
    InitiatorSecurityGroupId: "sg-i",
    InitiatorTaskRoleArn: `arn:aws:iam::${ACCOUNT}:role/cc-${RUN_ID}-i-task`,
    ResponderExecutionRoleArn: `arn:aws:iam::${ACCOUNT}:role/cc-${RUN_ID}-r-exec`,
    ResponderLogGroupName: `/clockchain/mechanics-proof/${RUN_ID}/responder`,
    ResponderPrivateSubnetId: "subnet-r",
    ResponderQueueUrl: `https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/${STACK_NAME}-responder`,
    ResponderSecurityGroupId: "sg-r",
    ResponderTaskRoleArn: `arn:aws:iam::${ACCOUNT}:role/cc-${RUN_ID}-r-task`,
  };
}

function stackResources(plan, outputs = stackOutputs()) {
  const physical = new Map([
    ["Cluster", outputs.ClusterArn.split("/").at(-1)],
    ["InitiatorPrivateSubnet", outputs.InitiatorPrivateSubnetId],
    ["ResponderPrivateSubnet", outputs.ResponderPrivateSubnetId],
    ["InitiatorSecurityGroup", outputs.InitiatorSecurityGroupId],
    ["ResponderSecurityGroup", outputs.ResponderSecurityGroupId],
    ["InitiatorQueue", outputs.InitiatorQueueUrl],
    ["ResponderQueue", outputs.ResponderQueueUrl],
    ["InitiatorTaskRole", `cc-${RUN_ID}-i-task`],
    ["ResponderTaskRole", `cc-${RUN_ID}-r-task`],
    ["InitiatorExecutionRole", `cc-${RUN_ID}-i-exec`],
    ["ResponderExecutionRole", `cc-${RUN_ID}-r-exec`],
    ["InitiatorLogGroup", outputs.InitiatorLogGroupName],
    ["ResponderLogGroup", outputs.ResponderLogGroupName],
  ]);
  return {
    stackId: STACK_ID,
    stackName: STACK_NAME,
    resources: Object.entries(plan.template.Resources).map(([logicalResourceId, resource]) => ({
      logicalResourceId,
      physicalResourceId: physical.get(logicalResourceId) ?? `physical-${logicalResourceId}`,
      resourceType: resource.Type,
    })),
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, reject, resolve };
}

function fakeControlPlane(plan, { failAt = null, absent = true, existingStack = false } = {}) {
  const calls = [];
  const resources = stackResources(plan);
  const outputs = stackOutputs();
  const taskDefinitions = {
    initiator: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/${STACK_NAME}-initiator:1`,
    responder: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/${STACK_NAME}-responder:1`,
  };
  const taskArns = {
    initiator: `arn:aws:ecs:${REGION}:${ACCOUNT}:task/${STACK_NAME}/initiator`,
    responder: `arn:aws:ecs:${REGION}:${ACCOUNT}:task/${STACK_NAME}/responder`,
  };
  const maybe = (name) => {
    calls.push(name);
    if (failAt === name) throw new Error(`fail ${name}`);
  };
  return {
    calls,
    async getCallerIdentity() { maybe("identity"); return { accountId: ACCOUNT, arn: `arn:aws:iam::${ACCOUNT}:user/controller`, userId: "AIDA" }; },
    async validateTemplate() { maybe("validate-template"); return { ok: true }; },
    async stackExists() { maybe("stack-exists"); return existingStack; },
    async createStack(input) { maybe("create-stack"); assert.equal(input.capabilities.includes("CAPABILITY_NAMED_IAM"), true); return { StackId: STACK_ID }; },
    async waitStackCreateComplete({ stackId, stackName }) { maybe("wait-stack-create"); assert.equal(stackId, STACK_ID); assert.equal(stackName, STACK_NAME); return { StackId: STACK_ID }; },
    async describeStackOutputs({ stackId, stackName }) { maybe("describe-stack-outputs"); assert.equal(stackId, STACK_ID); assert.equal(stackName, STACK_NAME); return outputs; },
    async listStackResources({ stackId, stackName }) { maybe("list-stack-resources"); assert.equal(stackId, STACK_ID); assert.equal(stackName, STACK_NAME); return resources; },
    async registerTaskDefinition({ role }) { maybe(`register-${role}`); return { taskDefinition: { taskDefinitionArn: taskDefinitions[role] } }; },
    async runTask({ role, networkConfiguration, platformVersion }) {
      maybe(`run-${role}`);
      assert.equal(networkConfiguration.awsvpcConfiguration.assignPublicIp, "DISABLED");
      assert.equal(platformVersion, "1.4.0");
      return { tasks: [{ taskArn: taskArns[role] }], failures: [] };
    },
    async waitTasksRunning({ taskArns: arns }) { maybe(`wait-running-${arns.length}`); return { taskArns: arns }; },
    async waitTasksStopped({ taskArns: arns }) { maybe(`wait-stopped-${arns.length}`); return { taskArns: arns }; },
    async pollPublicEvents({ deadlineMs }) {
      maybe("poll-events");
      assert.ok(deadlineMs - Date.now() > 250_000);
      assert.ok(deadlineMs - Date.now() <= 300_000);
      return [
        partyEvidence("initiator", "a".repeat(64)),
        partyEvidence("responder", "a".repeat(64)),
      ];
    },
    async stopTask({ role }) { maybe(`stop-${role}`); return { role }; },
    async deregisterTaskDefinition({ role }) { maybe(`deregister-${role}`); return { role }; },
    async deleteStack() { maybe("delete-stack"); return { stackId: STACK_ID }; },
    async waitStackDeleteComplete() { maybe("wait-stack-delete"); return { stackId: STACK_ID }; },
    async confirmAbsence() { maybe("confirm-absence"); return { absent }; },
    async reconcileCreatedStack() { maybe("reconcile-stack"); return { stackId: STACK_ID, stackName: STACK_NAME }; },
    async reconcileTaskDefinitions() { maybe("reconcile-task-definitions"); return []; },
    async reconcileTasks() { maybe("reconcile-tasks"); return []; },
  };
}

function partyEvidence(role, certificateDigest, overrides = {}) {
  return {
    schema: "clockchain.mechanics-proof-party-evidence/v1",
    runId: RUN_ID,
    protocolSessionId: "protocol-session-1",
    role,
    harness: role === "initiator" ? "codex" : "claude",
    runtimeId: `runtime-${role}`,
    workloadAttestationDigest: role === "initiator" ? "1".repeat(64) : "2".repeat(64),
    peerRuntimeId: role === "initiator" ? "runtime-responder" : "runtime-initiator",
    bridgeEvidenceDigest: role === "initiator" ? "3".repeat(64) : "4".repeat(64),
    harnessEvidenceDigest: role === "initiator" ? "5".repeat(64) : "6".repeat(64),
    certificateProofDigest: role === "initiator" ? "7".repeat(64) : "8".repeat(64),
    certificateDigest,
    resultDigest: "b".repeat(64),
    certificateVerified: true,
    identity: { address: role === "initiator" ? `0x${"1".repeat(40)}` : `0x${"2".repeat(40)}` },
    anchors: [],
    directDelivery: { acknowledged: true, artifactDigest: "9".repeat(64), checkpointDigest: "0".repeat(64), messageDigest: "b".repeat(64) },
    externalBusinessActionPerformed: false,
    terminalStatus: "completed",
    teardown: { completed: true },
    timestamp: role === "initiator" ? "2026-08-12T20:05:01.000Z" : "2026-08-12T20:05:02.000Z",
    ...overrides,
  };
}

test("live Fargate adapter runs exact lifecycle and starts both tasks before waiting", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan);
  const retained = [];
  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    retainEvidence: async (evidence) => { retained.push(evidence); },
  });

  assert.equal(result.status, "SUCCEEDED");
  assert.deepEqual(controlPlane.calls, [
    "identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "wait-stack-create",
    "describe-stack-outputs", "list-stack-resources", "register-initiator", "register-responder",
    "run-initiator", "run-responder", "wait-running-2", "poll-events", "stop-initiator", "stop-responder",
    "wait-stopped-2", "deregister-initiator", "deregister-responder", "delete-stack",
    "wait-stack-delete", "confirm-absence",
  ]);
  assert.equal(retained.length, 1);
  assert.equal(retained[0].controllerEvidence.stackResourceCount, 25);
  assert.equal(Object.keys(retained[0].controllerEvidence.stackOutputBindings).length, 13);
  assert.deepEqual(retained[0].controllerEvidence.publicEvents, [
    { runId: RUN_ID, role: "initiator", state: "completed", timestamp: "2026-08-12T20:05:01.000Z", digests: {
      bridgeEvidenceDigest: "3".repeat(64),
      certificateDigest: "a".repeat(64),
      certificateProofDigest: "7".repeat(64),
      harnessEvidenceDigest: "5".repeat(64),
      workloadAttestationDigest: "1".repeat(64),
    } },
    { runId: RUN_ID, role: "responder", state: "completed", timestamp: "2026-08-12T20:05:02.000Z", digests: {
      bridgeEvidenceDigest: "4".repeat(64),
      certificateDigest: "a".repeat(64),
      certificateProofDigest: "8".repeat(64),
      harnessEvidenceDigest: "6".repeat(64),
      workloadAttestationDigest: "2".repeat(64),
    } },
  ]);
  assert.equal(JSON.stringify(retained[0].controllerEvidence).includes("directDelivery"), false);
  assert.equal(JSON.stringify(retained[0].controllerEvidence).includes("identity"), false);
});

test("live Fargate adapter exposes full terminal evidence only to an in-memory finalizer after cleanup confirmation", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan);
  const fullEvidence = [];
  const retained = [];
  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    finalizeVerifiedEvidence: async (evidence) => { controlPlane.calls.push("finalize-evidence"); fullEvidence.push(evidence); return { verified: true }; },
    retainEvidence: async (evidence) => { retained.push(evidence); },
  });
  assert.equal(result.status, "SUCCEEDED");
  assert.equal(fullEvidence.length, 1);
  assert.equal(fullEvidence[0].terminalEvents[0].directDelivery.acknowledged, true);
  assert.deepEqual(fullEvidence[0].cleanupAbsence, { absent: true });
  assert.equal(controlPlane.calls.indexOf("confirm-absence") < controlPlane.calls.indexOf("finalize-evidence"), true);
  assert.deepEqual(retained[0].publicProof, { verified: true });
  assert.equal(JSON.stringify(retained[0].controllerEvidence.publicEvents).includes("directDelivery"), false);
});

test("live Fargate adapter collects runtime evidence after tasks stop and before destructive cleanup", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan);
  const liveInfra = { eni: "captured-before-terminal" };
  const collected = { cloudTrail: "run-and-stop", runtimeInputs: { initiator: {}, responder: {} } };
  const finalized = [];
  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    collectLiveRuntimeInfraInputs: async (input) => {
      controlPlane.calls.push("collect-live-infra");
      assert.equal(input.clusterArn, stackOutputs().ClusterArn);
      assert.deepEqual(input.taskArns, {
        initiator: `arn:aws:ecs:${REGION}:${ACCOUNT}:task/${STACK_NAME}/initiator`,
        responder: `arn:aws:ecs:${REGION}:${ACCOUNT}:task/${STACK_NAME}/responder`,
      });
      return liveInfra;
    },
    collectRuntimeEvidenceInputs: async (input) => {
      controlPlane.calls.push("collect-runtime-evidence");
      assert.deepEqual(input.taskArns, {
        initiator: `arn:aws:ecs:${REGION}:${ACCOUNT}:task/${STACK_NAME}/initiator`,
        responder: `arn:aws:ecs:${REGION}:${ACCOUNT}:task/${STACK_NAME}/responder`,
      });
      assert.equal(input.stackId, STACK_ID);
      assert.equal(input.stackName, STACK_NAME);
      assert.equal(input.liveRuntimeInfraInputs, liveInfra);
      assert.deepEqual(input.terminalEvents.map((event) => event.role), ["initiator", "responder"]);
      return collected;
    },
    finalizeVerifiedEvidence: async (evidence) => {
      controlPlane.calls.push("finalize-evidence");
      finalized.push(evidence);
      return { verified: true };
    },
    retainEvidence: async () => {},
  });
  assert.equal(result.status, "SUCCEEDED");
  assert.equal(controlPlane.calls.indexOf("wait-running-2") < controlPlane.calls.indexOf("collect-live-infra"), true);
  assert.equal(controlPlane.calls.indexOf("collect-live-infra") < controlPlane.calls.indexOf("poll-events"), true);
  assert.equal(controlPlane.calls.indexOf("poll-events") < controlPlane.calls.indexOf("stop-initiator"), true);
  assert.equal(controlPlane.calls.indexOf("wait-stopped-2") < controlPlane.calls.indexOf("collect-runtime-evidence"), true);
  assert.equal(controlPlane.calls.indexOf("collect-runtime-evidence") < controlPlane.calls.indexOf("deregister-initiator"), true);
  assert.equal(controlPlane.calls.indexOf("collect-runtime-evidence") < controlPlane.calls.indexOf("delete-stack"), true);
  assert.equal(controlPlane.calls.indexOf("confirm-absence") < controlPlane.calls.indexOf("finalize-evidence"), true);
  assert.equal(finalized[0].runtimeEvidenceInputs, collected);
});

test("live Fargate adapter publishes controller and public proof through one retention call", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan);
  const calls = [];
  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => ({ healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }),
    finalizeVerifiedEvidence: async () => {
      calls.push("build-public-proof");
      return { schema: "clockchain.mechanics-proof-cloud-evidence/v1" };
    },
    retainEvidence: async (bundle) => {
      calls.push("retain-bundle");
      assert.equal(bundle.controllerEvidence.schema, "clockchain.fargate-live-controller-evidence/v1");
      assert.equal(bundle.publicProof.schema, "clockchain.mechanics-proof-cloud-evidence/v1");
    },
  });
  assert.equal(result.status, "SUCCEEDED");
  assert.deepEqual(calls, ["build-public-proof", "retain-bundle"]);
});

test("live Fargate adapter cleans all resources when runtime evidence collection fails", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan);
  const retained = [];
  const finalized = [];
  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    collectRuntimeEvidenceInputs: async () => {
      controlPlane.calls.push("collect-runtime-evidence");
      throw new Error("cloudtrail not ready");
    },
    finalizeVerifiedEvidence: async (evidence) => { finalized.push(evidence); },
    retainEvidence: async (evidence) => { retained.push(evidence); },
  });
  assert.equal(result.status, PROTOCOL_FAILED_CLEAN);
  assert.deepEqual(controlPlane.calls.slice(controlPlane.calls.indexOf("wait-stopped-2") + 1), [
    "collect-runtime-evidence",
    "deregister-initiator",
    "deregister-responder",
    "delete-stack",
    "wait-stack-delete",
    "confirm-absence",
  ]);
  assert.equal(retained.length, 0);
  assert.equal(finalized.length, 0);
});

test("live Fargate adapter issues both RunTask calls before either is awaited", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan);
  const baseRun = controlPlane.runTask;
  const gates = { initiator: deferred(), responder: deferred() };
  const started = [];
  controlPlane.runTask = ({ role, ...rest }) => {
    started.push(role);
    const promise = gates[role].promise.then(() => baseRun({ role, ...rest }));
    if (started.length === 2) {
      gates.initiator.resolve();
      gates.responder.resolve();
    }
    return promise;
  };
  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    retainEvidence: async () => {},
  });
  assert.equal(result.status, "SUCCEEDED");
  assert.deepEqual(started, ["initiator", "responder"]);
});

test("live Fargate adapter enters resource-scoped cleanup after every mutation boundary", async () => {
  const plan = await livePlan();
  const expectations = new Map([
    ["create-stack", ["identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "reconcile-stack", "delete-stack", "wait-stack-delete", "confirm-absence"]],
    ["register-initiator", ["identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "wait-stack-create", "describe-stack-outputs", "list-stack-resources", "register-initiator", "reconcile-task-definitions", "delete-stack", "wait-stack-delete", "confirm-absence"]],
    ["register-responder", ["identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "wait-stack-create", "describe-stack-outputs", "list-stack-resources", "register-initiator", "register-responder", "reconcile-task-definitions", "deregister-initiator", "delete-stack", "wait-stack-delete", "confirm-absence"]],
    ["run-initiator", ["identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "wait-stack-create", "describe-stack-outputs", "list-stack-resources", "register-initiator", "register-responder", "run-initiator", "run-responder", "reconcile-tasks", "deregister-initiator", "deregister-responder", "delete-stack", "wait-stack-delete", "confirm-absence"]],
    ["run-responder", ["identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "wait-stack-create", "describe-stack-outputs", "list-stack-resources", "register-initiator", "register-responder", "run-initiator", "run-responder", "reconcile-tasks", "deregister-initiator", "deregister-responder", "delete-stack", "wait-stack-delete", "confirm-absence"]],
    ["stop-initiator", ["identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "wait-stack-create", "describe-stack-outputs", "list-stack-resources", "register-initiator", "register-responder", "run-initiator", "run-responder", "wait-running-2", "poll-events", "stop-initiator", "stop-responder", "wait-stopped-2", "deregister-initiator", "deregister-responder", "delete-stack", "wait-stack-delete", "confirm-absence"]],
    ["deregister-initiator", ["identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "wait-stack-create", "describe-stack-outputs", "list-stack-resources", "register-initiator", "register-responder", "run-initiator", "run-responder", "wait-running-2", "poll-events", "stop-initiator", "stop-responder", "wait-stopped-2", "deregister-initiator", "deregister-responder", "delete-stack", "wait-stack-delete", "confirm-absence"]],
    ["delete-stack", ["identity", "mcp-gate", "stack-exists", "validate-template", "create-stack", "wait-stack-create", "describe-stack-outputs", "list-stack-resources", "register-initiator", "register-responder", "run-initiator", "run-responder", "wait-running-2", "poll-events", "stop-initiator", "stop-responder", "wait-stopped-2", "deregister-initiator", "deregister-responder", "delete-stack", "wait-stack-delete", "confirm-absence"]],
  ]);

  for (const [failAt, expectedCalls] of expectations) {
    const controlPlane = fakeControlPlane(plan, { failAt });
    const retained = [];
    const result = await runFargateLiveMechanicsProof({
      plan,
      controlPlane,
      mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
      retainEvidence: async (evidence) => { retained.push(evidence); },
    });
    assert.equal(result.status, CLEANUP_UNCONFIRMED, failAt);
    assert.equal(retained.length, 0, failAt);
    assert.deepEqual(controlPlane.calls, expectedCalls, failAt);
  }
});

test("live Fargate adapter returns failed-clean after protocol failure with confirmed cleanup", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan);
  const diagnostic = createAwsCliControlPlane({
    region: REGION,
    executor: async (_file, argv) => {
      const role = argv.some((value) => value.includes("/responder")) ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [{
        timestamp: Date.now(),
        message: `Mechanics proof party failed safely. stage=runtime-run.listener-listen-${role === "initiator" ? "eperm" : "eaddrinuse"}`,
      }] }), stderr: "", exitCode: 0 };
    },
  });
  controlPlane.pollPublicEvents = (input) => diagnostic.pollPublicEvents(input);
  const retained = [];
  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    retainEvidence: async (evidence) => { retained.push(evidence); },
  });

  assert.equal(result.status, PROTOCOL_FAILED_CLEAN);
  assert.deepEqual(result.failureStages, {
    initiator: "runtime-run.listener-listen-eperm",
    responder: "runtime-run.listener-listen-eaddrinuse",
  });
  assert.equal(retained.length, 0);
});

test("live Fargate adapter reports only fixed cleanup step codes when cleanup is unconfirmed", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan, { failAt: "stop-initiator" });
  const diagnostic = createAwsCliControlPlane({
    region: REGION,
    executor: async (_file, argv) => {
      const role = argv.some((value) => value.includes("/responder")) ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [{
        timestamp: Date.now(),
        message: `Mechanics proof party failed safely. stage=runtime-run.listener-create`,
      }] }), stderr: "", exitCode: 0 };
    },
  });
  controlPlane.pollPublicEvents = (input) => diagnostic.pollPublicEvents(input);

  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    retainEvidence: async () => { throw new Error("must not retain"); },
  });

  assert.equal(result.status, CLEANUP_UNCONFIRMED);
  assert.deepEqual(result.failureStages, {
    initiator: "runtime-run.listener-create",
    responder: "runtime-run.listener-create",
  });
  assert.deepEqual(result.cleanupFailedSteps, ["stop-initiator"]);
  assert.equal(JSON.stringify(result).includes("fail stop-initiator"), false);
});

test("live Fargate adapter returns fixed party progress after a clean protocol timeout", async () => {
  const plan = await livePlan();
  const controlPlane = fakeControlPlane(plan);
  let current = 0;
  const diagnostic = createAwsCliControlPlane({
    region: REGION,
    now: () => current,
    sleep: async () => { current = 2000; },
    executor: async (_file, argv) => {
      const role = argv.some((value) => value.includes("/responder")) ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [{
        timestamp: 1786565101000,
        message: JSON.stringify({
          schema: "clockchain.mechanics-proof-party-event/v1",
          runId: RUN_ID,
          role,
          sequence: "1",
          type: "agent.starting",
          evidenceDigest: "1".repeat(64),
        }),
      }] }), stderr: "", exitCode: 0 };
    },
  });
  controlPlane.pollPublicEvents = () => diagnostic.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId: RUN_ID,
    startTimeMs: 0,
    deadlineMs: 1000,
  });

  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane,
    mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    retainEvidence: async () => { throw new Error("must not retain"); },
  });

  assert.equal(result.status, PROTOCOL_FAILED_CLEAN);
  assert.deepEqual(result.progressStages, {
    initiator: "agent.starting",
    responder: "agent.starting",
  });
});

test("live Fargate adapter rejects unsafe live inputs before mutation", async () => {
  const cases = [
    livePlan({ maxConcurrency: 3 }),
    livePlan({ budgetUsd: 26 }),
    livePlan({ ttlSeconds: 7200, expiresAt: "2026-08-12T22:00:00.000Z" }),
    livePlan({ appImage: `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/clockchain-mechanics-proof:latest` }),
    livePlan({ mcpUrl: "https://staging.example.test/mcp" }),
  ];
  for (const candidate of cases) {
    await assert.rejects(candidate, /Fargate live plan validation failed safely/);
  }

  const plan = await livePlan();
  const existingStack = fakeControlPlane(plan, { existingStack: true });
  const result = await runFargateLiveMechanicsProof({
    plan,
    controlPlane: existingStack,
    mcpGate: async () => { existingStack.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
    retainEvidence: async () => { throw new Error("must not retain"); },
  });
  assert.equal(result.status, CLEANUP_UNCONFIRMED);
  assert.deepEqual(existingStack.calls, ["identity", "mcp-gate", "stack-exists"]);
});

test("live Fargate adapter gates MCP endpoint and checkpoint tool before AWS mutation", async () => {
  const plan = await livePlan();
  for (const mcpResult of [
    { healthy: true, checkpointTool: false },
    { healthy: true, checkpointTool: true, endpoint: "https://staging.example.test/mcp" },
  ]) {
    const controlPlane = fakeControlPlane(plan);
    const result = await runFargateLiveMechanicsProof({
      plan,
      controlPlane,
      mcpGate: async ({ mcpUrl }) => {
        controlPlane.calls.push("mcp-gate");
        assert.equal(mcpUrl, "https://mcp.clockchain.network/handshake/mcp");
        return mcpResult;
      },
      retainEvidence: async () => { throw new Error("must not retain"); },
    });
    assert.equal(result.status, CLEANUP_UNCONFIRMED);
    assert.deepEqual(controlPlane.calls, ["identity", "mcp-gate"]);
  }
});

test("live Fargate adapter rejects terminal event prose, wrong run, duplicate role, and cert mismatch", async () => {
  const plan = await livePlan();
  for (const events of [
    [{ message: "model says success" }],
    [partyEvidence("initiator", "a".repeat(64), { runId: "other" }), partyEvidence("responder", "a".repeat(64))],
    [partyEvidence("initiator", "a".repeat(64)), partyEvidence("initiator", "a".repeat(64))],
    [partyEvidence("initiator", "a".repeat(64)), partyEvidence("responder", "b".repeat(64))],
  ]) {
    const controlPlane = fakeControlPlane(plan);
    controlPlane.pollPublicEvents = async () => {
      controlPlane.calls.push("poll-events");
      return events;
    };
    const result = await runFargateLiveMechanicsProof({
      plan,
      controlPlane,
      mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
      retainEvidence: async () => { throw new Error("must not retain"); },
    });
    assert.equal(result.status, PROTOCOL_FAILED_CLEAN);
  }
});

test("live Fargate adapter rejects mixed stack provenance and ambiguous RunTask results", async () => {
  const plan = await livePlan();
  const badResources = fakeControlPlane(plan);
  badResources.listStackResources = async () => ({
    ...stackResources(plan),
    stackId: STACK_ID.replace("aaaaaaaa", "bbbbbbbb"),
  });
  assert.equal((await runFargateLiveMechanicsProof({
    plan,
    controlPlane: badResources,
    mcpGate: async () => ({ healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }),
    retainEvidence: async () => { throw new Error("must not retain"); },
  })).status, CLEANUP_UNCONFIRMED);

  for (const runResponse of [
    { tasks: [], failures: [] },
    { tasks: [{ taskArn: "a" }, { taskArn: "b" }], failures: [] },
    { tasks: [{ taskArn: "a" }], failures: [{ arn: "failed" }] },
  ]) {
    const controlPlane = fakeControlPlane(plan);
    controlPlane.runTask = async ({ role }) => {
      controlPlane.calls.push(`run-${role}`);
      return runResponse;
    };
    const result = await runFargateLiveMechanicsProof({
      plan,
      controlPlane,
      mcpGate: async () => ({ healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }),
      retainEvidence: async () => { throw new Error("must not retain"); },
    });
    assert.equal(result.status, CLEANUP_UNCONFIRMED);
  }
});

test("live Fargate adapter reconciles ambiguous accepted mutations before cleanup", async () => {
  const plan = await livePlan();
  const scenarios = [
    ["create-stack", ["reconcile-stack", "delete-stack"]],
    ["register-initiator", ["reconcile-task-definitions", "deregister-initiator", "delete-stack"]],
    ["run-initiator", ["reconcile-tasks", "stop-initiator", "wait-stopped-1", "deregister-initiator", "deregister-responder", "delete-stack"]],
  ];
  for (const [failAt, required] of scenarios) {
    const controlPlane = fakeControlPlane(plan, { failAt });
    controlPlane.reconcileTaskDefinitions = async () => {
      controlPlane.calls.push("reconcile-task-definitions");
      return [
        { role: "initiator", taskDefinitionArn: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/${STACK_NAME}-initiator:1` },
        { role: "responder", taskDefinitionArn: `arn:aws:ecs:${REGION}:${ACCOUNT}:task-definition/${STACK_NAME}-responder:1` },
      ];
    };
    controlPlane.reconcileTasks = async () => {
      controlPlane.calls.push("reconcile-tasks");
      return [{ role: "initiator", taskArn: `arn:aws:ecs:${REGION}:${ACCOUNT}:task/${STACK_NAME}/initiator` }];
    };
    const result = await runFargateLiveMechanicsProof({
      plan,
      controlPlane,
      mcpGate: async () => { controlPlane.calls.push("mcp-gate"); return { healthy: true, checkpointTool: true, endpoint: "https://mcp.clockchain.network/handshake/mcp" }; },
      retainEvidence: async () => { throw new Error("must not retain"); },
    });
    assert.equal(result.status, CLEANUP_UNCONFIRMED);
    for (const call of required) assert.equal(controlPlane.calls.includes(call), true, `${failAt} missing ${call}`);
  }
});
