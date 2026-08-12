import { buildFargateLiveTaskDefinitions, FARGATE_LIVE_PLAN_SCHEMA } from "./aws-fargate-live-plan.mjs";
import { sha256Hex, stableJson } from "./aws-fargate-runtime-adapter.mjs";
import {
  FARGATE_LIVE_RESULT_SCHEMA,
  FARGATE_LIVE_STATUS_CLEANUP_UNCONFIRMED,
  FARGATE_LIVE_STATUS_PROTOCOL_FAILED_CLEAN,
  FARGATE_LIVE_STATUS_SUCCEEDED,
} from "./runtime-adapter-contract.mjs";

export const CLEANUP_UNCONFIRMED = FARGATE_LIVE_STATUS_CLEANUP_UNCONFIRMED;
export const PROTOCOL_FAILED_CLEAN = FARGATE_LIVE_STATUS_PROTOCOL_FAILED_CLEAN;

const ROLES = Object.freeze(["initiator", "responder"]);
const REQUIRED_OUTPUTS = Object.freeze([
  "ClusterArn", "InitiatorExecutionRoleArn", "InitiatorLogGroupName", "InitiatorPrivateSubnetId",
  "InitiatorQueueUrl", "InitiatorSecurityGroupId", "InitiatorTaskRoleArn", "ResponderExecutionRoleArn",
  "ResponderLogGroupName", "ResponderPrivateSubnetId", "ResponderQueueUrl", "ResponderSecurityGroupId",
  "ResponderTaskRoleArn",
]);

function fail() {
  throw new Error("Fargate live adapter validation failed safely.");
}

function plain(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function validatePlan(plan) {
  const item = plain(plan);
  if (
    item.schema !== FARGATE_LIVE_PLAN_SCHEMA ||
    item.maxConcurrency > 2 ||
    item.controls?.assignPublicIp !== "DISABLED" ||
    item.controls?.maxConcurrency !== 2 ||
    item.controls?.ttlSeconds > 3600 ||
    item.controls?.budgetUsd > 25 ||
    !/^.+@sha256:[0-9a-f]{64}$/.test(item.appImage)
  ) fail();
  return item;
}

function parameters(plan) {
  return Object.entries(plan.parameters).map(([ParameterKey, ParameterValue]) => ({ ParameterKey, ParameterValue: String(ParameterValue) }));
}

function networkConfiguration(outputs, role) {
  const own = role === "initiator" ? "Initiator" : "Responder";
  return Object.freeze({
    awsvpcConfiguration: Object.freeze({
      assignPublicIp: "DISABLED",
      subnets: Object.freeze([outputs[`${own}PrivateSubnetId`]]),
      securityGroups: Object.freeze([outputs[`${own}SecurityGroupId`]]),
    }),
  });
}

function terminalEvents(events, runId) {
  if (!Array.isArray(events) || events.length !== 2) fail();
  const byRole = Object.fromEntries(events.map((event) => [event.role, event]));
  const sessionIds = new Set();
  for (const role of ROLES) {
    const event = plain(byRole[role]);
    if (
      event.schema !== "clockchain.mechanics-proof-party-evidence/v1" ||
      event.runId !== runId ||
      typeof event.protocolSessionId !== "string" ||
      event.terminalStatus !== "completed" ||
      event.teardown?.completed !== true ||
      event.externalBusinessActionPerformed !== false ||
      event.directDelivery === null ||
      typeof event.directDelivery !== "object" ||
      event.directDelivery.acknowledged !== true ||
      !/^[0-9a-f]{64}$/.test(event.certificateDigest) ||
      !/^[0-9a-f]{64}$/.test(event.workloadAttestationDigest) ||
      !/^[0-9a-f]{64}$/.test(event.bridgeEvidenceDigest) ||
      !/^[0-9a-f]{64}$/.test(event.harnessEvidenceDigest) ||
      !/^[0-9a-f]{64}$/.test(event.certificateProofDigest)
    ) fail();
    sessionIds.add(event.protocolSessionId);
  }
  if (sessionIds.size !== 1) fail();
  if (byRole.initiator.certificateDigest !== byRole.responder.certificateDigest) fail();
  return Object.freeze(events.map((event) => Object.freeze({ ...event })));
}

function outputBindings(outputs) {
  const result = {};
  for (const key of REQUIRED_OUTPUTS) {
    if (typeof outputs[key] !== "string" || outputs[key].length === 0) fail();
    result[key] = sha256Hex(outputs[key]);
  }
  return Object.freeze(result);
}

async function cleanup({ controlPlane, stackName, clusterArn, taskArns, taskDefinitions, reconcile, stackCreated }) {
  const cleanupErrors = [];
  if (reconcile.stack) {
    try {
      const stack = await controlPlane.reconcileCreatedStack({ stackName });
      clusterArn = clusterArn ?? stack.clusterArn ?? clusterArn;
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  if (reconcile.taskDefinitions) {
    try {
      for (const item of await controlPlane.reconcileTaskDefinitions({ stackName })) {
        if (ROLES.includes(item.role) && !taskDefinitions[item.role]) taskDefinitions[item.role] = item.taskDefinitionArn;
      }
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  if (reconcile.tasks && clusterArn) {
    try {
      for (const item of await controlPlane.reconcileTasks({ stackName, cluster: clusterArn })) {
        if (ROLES.includes(item.role) && !taskArns[item.role]) taskArns[item.role] = item.taskArn;
      }
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  for (const role of ROLES) {
    if (taskArns[role]) {
      try { await controlPlane.stopTask({ cluster: clusterArn, taskArn: taskArns[role], role }); } catch (error) { cleanupErrors.push(error); }
    }
  }
  const arns = ROLES.map((role) => taskArns[role]).filter(Boolean);
  if (arns.length > 0) {
    try { await controlPlane.waitTasksStopped({ cluster: clusterArn, taskArns: arns }); } catch (error) { cleanupErrors.push(error); }
  }
  for (const role of ROLES) {
    if (taskDefinitions[role]) {
      try { await controlPlane.deregisterTaskDefinition({ taskDefinitionArn: taskDefinitions[role], role }); } catch (error) { cleanupErrors.push(error); }
    }
  }
  if (stackCreated) {
    try { await controlPlane.deleteStack({ stackName }); } catch (error) { cleanupErrors.push(error); }
    try { await controlPlane.waitStackDeleteComplete({ stackName }); } catch (error) { cleanupErrors.push(error); }
  }
  let absence = { absent: false };
  try { absence = await controlPlane.confirmAbsence({ stackName }); } catch (error) { cleanupErrors.push(error); }
  return Object.freeze({ absence, cleanupErrors });
}

export async function runFargateLiveMechanicsProof(optionsInput) {
  const options = plain(optionsInput);
  const plan = validatePlan(options.plan);
  const controlPlane = options.controlPlane;
  if (controlPlane === null || typeof controlPlane !== "object") fail();
  const mcpGate = options.mcpGate;
  const retainEvidence = options.retainEvidence ?? (async () => {});
  if (typeof mcpGate !== "function" || typeof retainEvidence !== "function") fail();
  const stackName = `clockchain-${plan.runId}`;
  const taskArns = {};
  const taskDefinitions = {};
  let clusterArn = null;
  const reconcile = { stack: false, taskDefinitions: false, tasks: false };
  let stackCreated = false;
  let failureClass = "mutation";

  try {
    const identity = await controlPlane.getCallerIdentity();
    if (identity.accountId !== plan.accountId) throw new Error("account mismatch");
    const mcp = await mcpGate({ mcpUrl: plan.mcpUrl });
    if (mcp?.healthy !== true || mcp?.checkpointTool !== true || mcp?.endpoint !== plan.mcpUrl) throw new Error("MCP gate failed");
    if (await controlPlane.stackExists({ stackName })) throw new Error("same run stack already exists");
    await controlPlane.validateTemplate({ templateBody: stableJson(plan.template) });
    reconcile.stack = true;
    const create = await controlPlane.createStack({
      stackName,
      templateBody: stableJson(plan.template),
      parameters: parameters(plan),
      capabilities: ["CAPABILITY_NAMED_IAM"],
    });
    stackCreated = true;
    reconcile.stack = false;
    await controlPlane.waitStackCreateComplete({ stackName, stackId: create.stackId });
    const outputs = await controlPlane.describeStackOutputs({ stackName });
    clusterArn = outputs.ClusterArn;
    const resources = await controlPlane.listStackResources({ stackName });
    if (!Array.isArray(resources.resources) || resources.resources.length !== 25) throw new Error("stack provenance incomplete");
    const definitions = buildFargateLiveTaskDefinitions({ stackPlan: plan, stackOutputs: outputs, stackResources: resources });
    for (const role of ROLES) {
      reconcile.taskDefinitions = true;
      const registered = await controlPlane.registerTaskDefinition({ role, taskDefinition: definitions[role] });
      taskDefinitions[role] = registered.taskDefinition?.taskDefinitionArn;
      if (typeof taskDefinitions[role] !== "string") throw new Error("task definition registration failed");
    }
    reconcile.taskDefinitions = false;
    reconcile.tasks = true;
    const runs = ROLES.map((role) => controlPlane.runTask({
        role,
        cluster: clusterArn,
        taskDefinitionArn: taskDefinitions[role],
        networkConfiguration: networkConfiguration(outputs, role),
        startedBy: plan.runId,
      }).then((run) => [role, run]));
    for (const [role, run] of await Promise.all(runs)) {
      if (Array.isArray(run.failures) && run.failures.length > 0) throw new Error("run task failed");
      taskArns[role] = run.tasks?.[0]?.taskArn;
      if (typeof taskArns[role] !== "string") throw new Error("run task missing task arn");
    }
    reconcile.tasks = false;
    failureClass = "protocol";
    const events = terminalEvents(await controlPlane.pollPublicEvents({
      runId: plan.runId,
      logGroupNames: [outputs.InitiatorLogGroupName, outputs.ResponderLogGroupName],
      deadlineMs: Date.now() + 60_000,
    }), plan.runId);
    const cleaned = await cleanup({ controlPlane, stackName, clusterArn, taskArns, taskDefinitions, reconcile, stackCreated });
    if (cleaned.cleanupErrors.length > 0 || cleaned.absence?.absent !== true) {
      return Object.freeze({ schema: FARGATE_LIVE_RESULT_SCHEMA, status: CLEANUP_UNCONFIRMED });
    }
    const evidence = Object.freeze({
      schema: "clockchain.fargate-live-controller-evidence/v1",
      runId: plan.runId,
      stackName,
      stackResourceCount: resources.resources.length,
      stackResourceEnvelopeDigest: sha256Hex(resources),
      stackOutputBindings: outputBindings(outputs),
      taskDefinitionArns: Object.freeze({ ...taskDefinitions }),
      taskArns: Object.freeze({ ...taskArns }),
      publicEvents: events,
      cleanupAbsenceDigest: sha256Hex(cleaned.absence),
    });
    await retainEvidence(evidence);
    return Object.freeze({ schema: FARGATE_LIVE_RESULT_SCHEMA, status: FARGATE_LIVE_STATUS_SUCCEEDED, evidence });
  } catch (error) {
    if (stackCreated || reconcile.stack) {
      const cleaned = await cleanup({ controlPlane, stackName, clusterArn, taskArns, taskDefinitions, reconcile, stackCreated: stackCreated || reconcile.stack });
      if (failureClass === "protocol" && cleaned.cleanupErrors.length === 0 && cleaned.absence?.absent === true) {
        return Object.freeze({ schema: FARGATE_LIVE_RESULT_SCHEMA, status: PROTOCOL_FAILED_CLEAN });
      }
    }
    return Object.freeze({ schema: FARGATE_LIVE_RESULT_SCHEMA, status: CLEANUP_UNCONFIRMED });
  }
}

export function createAwsFargateLiveRuntimeAdapter(options = {}) {
  return Object.freeze({
    async run() {
      return runFargateLiveMechanicsProof(options);
    },
  });
}
