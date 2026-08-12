import { execFile } from "node:child_process";
import { types } from "node:util";

const ALLOWED = new Set([
  "sts get-caller-identity",
  "cloudformation validate-template",
  "cloudformation describe-stacks",
  "cloudformation create-stack",
  "cloudformation wait stack-create-complete",
  "cloudformation list-stack-resources",
  "cloudformation delete-stack",
  "cloudformation wait stack-delete-complete",
  "ecs register-task-definition",
  "ecs run-task",
  "ecs wait tasks-running",
  "ecs wait tasks-stopped",
  "ecs stop-task",
  "ecs deregister-task-definition",
  "ecs describe-tasks",
  "ecs describe-task-definition",
  "ecs list-tasks",
  "ecs list-task-definitions",
  "ec2 describe-vpcs",
  "ec2 describe-subnets",
  "ec2 describe-route-tables",
  "ec2 describe-network-interfaces",
  "ec2 describe-security-groups",
  "logs filter-log-events",
  "cloudtrail lookup-events",
  "sqs list-queues",
]);
const PARTY_FAILURE_PREFIX = "Mechanics proof party failed safely. stage=";
const PARTY_FAILURE_STAGE = /^(?:runtime-create|exchange-create|bootstrap-publish|bootstrap-await|exchange-destroy|managed-hold|runtime-run(?:\.(?:peer-validate|listener-create|listener-ready|invitation-await|recorder-create|bridge-create|provider-auth|transport-create|adapter-create|agent-starting|agent-launch|evidence-validate|certificate-event|agent-terminate|evidence-collect|teardown|listener-listen-(?:eacces|eaddrinuse|eaddrnotavail|eperm|other)))?)$/;
const PARTY_PROGRESS_TYPES = Object.freeze(["a2a.listener.ready", "a2a.invitation.received", "agent.starting", "certificate.verified"]);
const PUBLIC_PARTY_FAILURES = new WeakMap();
const PUBLIC_PARTY_PROGRESS = new WeakMap();

function partyFailureError(failures, progress = new Map()) {
  const error = new Error("AWS CLI control-plane observed a safe party failure.");
  PUBLIC_PARTY_FAILURES.set(error, Object.freeze(Object.fromEntries([...failures].sort(([left], [right]) => left.localeCompare(right)))));
  if (progress.size > 0) PUBLIC_PARTY_PROGRESS.set(error, Object.freeze(Object.fromEntries([...progress].sort(([left], [right]) => left.localeCompare(right)))));
  return error;
}

function partyProgressError(progress) {
  const error = new Error("AWS CLI control-plane observed a safe party timeout.");
  if (progress.size > 0) PUBLIC_PARTY_PROGRESS.set(error, Object.freeze(Object.fromEntries([...progress].sort(([left], [right]) => left.localeCompare(right)))));
  return error;
}

export function publicPartyFailureStages(error) {
  return PUBLIC_PARTY_FAILURES.get(error) ?? null;
}

export function publicPartyProgressStages(error) {
  return PUBLIC_PARTY_PROGRESS.get(error) ?? null;
}

const STACK = /^clockchain-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ROLES = Object.freeze(["initiator", "responder"]);

function fail() {
  throw new Error("AWS CLI control-plane validation failed safely.");
}

function plain(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  return value;
}

function string(value) {
  if (typeof value !== "string" || value.length === 0 || /[;&|`$<>]/.test(value)) fail();
  return value;
}

function templateJsonBody(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1_048_576 || /[;&|`<>]/.test(value)) fail();
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    fail();
  }
  if (JSON.stringify(canonical(parsed)) !== value) fail();
  return value;
}

function stackName(value) {
  if (!STACK.test(string(value))) fail();
  return value;
}

function stackIdArn(value, { stackName: expectedName, region, accountId = null }) {
  if (typeof value !== "string") fail();
  const match = value.match(/^arn:aws(?:-us-gov)?:cloudformation:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):stack\/(clockchain-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/);
  if (!match || match[1] !== region || match[3] !== expectedName || (accountId !== null && match[2] !== accountId)) fail();
  return value;
}

function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map(canonical);
  const item = plain(value);
  return Object.fromEntries(Object.keys(item).sort().map((key) => [key, canonical(item[key])]));
}

function parse(stdout) {
  try {
    return JSON.parse(stdout);
  } catch {
    fail();
  }
}

function commandKey(argv) {
  if (!Array.isArray(argv) || argv.length < 3) fail();
  if (argv.at(-2) !== "--output" || argv.at(-1) !== "json") fail();
    const head = (argv[0] === "cloudformation" || argv[0] === "ecs") && argv[1] === "wait"
    ? argv.slice(0, 3).join(" ")
    : argv.slice(0, 2).join(" ");
  if (!ALLOWED.has(head)) fail();
  const templateIndex = argv.indexOf("--template-body");
  for (let index = 0; index < argv.length; index += 1) {
    if ((head === "cloudformation validate-template" || head === "cloudformation create-stack") && index === templateIndex + 1) {
      templateJsonBody(argv[index]);
    } else {
      string(argv[index]);
    }
  }
  return head;
}

async function defaultExecutor(file, argv, options) {
  return new Promise((resolve, reject) => {
    execFile(file, argv, { timeout: options.timeoutMs, maxBuffer: 1024 * 1024, windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      resolve({ stdout, stderr, exitCode: 0 });
    });
  });
}

async function stdoutString(stdout) {
  if (typeof stdout === "string") {
    if (stdout.length > 1_048_576) fail();
    return stdout;
  }
  if (stdout?.getReader === undefined) fail();
  const reader = stdout.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > 1_048_576) fail();
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

async function output(value) {
  const result = plain(value);
  if (result.stderr !== "") fail();
  if (result.exitCode !== 0) fail();
  const stdout = await stdoutString(result.stdout);
  if (stdout === "") return {};
  return parse(stdout);
}

function isMissingStack(error) {
  return /Stack with id clockchain-[0-9a-f-]+ does not exist/i.test(String(error?.message ?? error?.stderr ?? ""));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function createAwsCliControlPlane(optionsInput = {}) {
  const options = plain(optionsInput);
  if (Object.keys(options).some((key) => !["accountId", "executor", "now", "region", "sleep", "timeoutMs"].includes(key))) fail();
  const executor = options.executor ?? defaultExecutor;
  if (typeof executor !== "function") fail();
  const region = string(options.region);
  const accountId = options.accountId ?? null;
  if (accountId !== null && !/^[0-9]{12}$/.test(accountId)) fail();
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$/.test(region)) fail();
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) fail();
  const now = options.now ?? (() => Date.now());
  const sleepFn = options.sleep ?? sleep;
  if (typeof now !== "function" || typeof sleepFn !== "function") fail();

  async function callAws(argvInput, options = {}) {
    commandKey(argvInput);
    const regionIndex = argvInput.indexOf("--region");
    if (regionIndex < 0 || argvInput[regionIndex + 1] !== region) fail();
    let response;
    try {
      const commandTimeoutMs = options.timeoutMs ?? timeoutMs;
      if (!Number.isSafeInteger(commandTimeoutMs) || commandTimeoutMs < 1 || commandTimeoutMs > 300_000) fail();
      response = await executor("aws", Object.freeze([...argvInput]), Object.freeze({ timeoutMs: commandTimeoutMs }));
    } catch (error) {
      if (options.allowMissingStack && isMissingStack(error)) throw error;
      fail();
    }
    return output(response);
  }

  return Object.freeze({
    async getCallerIdentity() {
      const identity = await callAws(["sts", "get-caller-identity", "--region", region, "--output", "json"]);
      if (JSON.stringify(Object.keys(identity).sort()) !== JSON.stringify(["Account", "Arn", "UserId"])) fail();
      if (!/^[0-9]{12}$/.test(identity.Account) || typeof identity.Arn !== "string" || typeof identity.UserId !== "string") fail();
      return Object.freeze({ accountId: identity.Account, arn: identity.Arn, userId: identity.UserId });
    },
    describeTasks({ cluster, taskArns }) {
      string(cluster);
      if (!Array.isArray(taskArns) || taskArns.length < 1 || taskArns.length > 2) fail();
      taskArns.forEach(string);
      return callAws(["ecs", "describe-tasks", "--cluster", cluster, "--tasks", ...taskArns, "--region", region, "--output", "json"]);
    },
    describeTaskDefinition({ taskDefinitionArn }) {
      string(taskDefinitionArn);
      return callAws(["ecs", "describe-task-definition", "--task-definition", taskDefinitionArn, "--region", region, "--output", "json"]);
    },
    describeNetworkInterfaces({ networkInterfaceIds }) {
      if (!Array.isArray(networkInterfaceIds) || networkInterfaceIds.length !== 1) fail();
      networkInterfaceIds.forEach(string);
      return callAws(["ec2", "describe-network-interfaces", "--network-interface-ids", ...networkInterfaceIds, "--region", region, "--output", "json"]);
    },
    describeSubnetsByIds({ subnetIds }) {
      if (!Array.isArray(subnetIds) || subnetIds.length !== 1) fail();
      subnetIds.forEach(string);
      return callAws(["ec2", "describe-subnets", "--subnet-ids", ...subnetIds, "--region", region, "--output", "json"]);
    },
    describeSecurityGroups({ groupIds }) {
      if (!Array.isArray(groupIds) || groupIds.length !== 1) fail();
      groupIds.forEach(string);
      return callAws(["ec2", "describe-security-groups", "--group-ids", ...groupIds, "--region", region, "--output", "json"]);
    },
    filterLogEvents({ logGroupName }) {
      if (typeof logGroupName !== "string" || !logGroupName.startsWith("/clockchain/mechanics-proof/")) fail();
      string(logGroupName);
      return callAws(["logs", "filter-log-events", "--log-group-name", logGroupName, "--region", region, "--output", "json"]);
    },
    lookupEcsCloudTrailEvents({ startTime, endTime }) {
      if (
        typeof startTime !== "string" ||
        typeof endTime !== "string" ||
        new Date(startTime).toISOString() !== startTime ||
        new Date(endTime).toISOString() !== endTime ||
        Date.parse(startTime) >= Date.parse(endTime)
      ) fail();
      return callAws([
        "cloudtrail", "lookup-events", "--lookup-attributes", "AttributeKey=EventSource,AttributeValue=ecs.amazonaws.com",
        "--start-time", startTime, "--end-time", endTime, "--no-paginate", "--region", region, "--output", "json",
      ]);
    },
    listQueues({ queueNamePrefix }) {
      stackName(queueNamePrefix);
      return callAws(["sqs", "list-queues", "--queue-name-prefix", queueNamePrefix, "--region", region, "--output", "json"]);
    },
    listTaskDefinitions({ familyPrefix, status }) {
      if (typeof familyPrefix !== "string" || !familyPrefix.endsWith("-") || !STACK.test(familyPrefix.slice(0, -1))) fail();
      if (!['ACTIVE', 'INACTIVE'].includes(status)) fail();
      return callAws(["ecs", "list-task-definitions", "--family-prefix", familyPrefix, "--status", status, "--region", region, "--output", "json"]);
    },
    validateTemplate({ templateBody }) {
      templateJsonBody(templateBody);
      return callAws(["cloudformation", "validate-template", "--template-body", templateBody, "--region", region, "--output", "json"]);
    },
    async stackExists({ stackName: name }) {
      stackName(name);
      let response;
      try {
        response = await callAws(["cloudformation", "describe-stacks", "--stack-name", name, "--region", region, "--output", "json"], { allowMissingStack: true });
      } catch (error) {
        if (isMissingStack(error)) return false;
        fail();
      }
      if (!Array.isArray(response.Stacks)) fail();
      return response.Stacks.length > 0;
    },
    async createStack({ stackName: name, templateBody, parameters, capabilities }) {
      stackName(name);
      templateJsonBody(templateBody);
      if (!Array.isArray(parameters) || !Array.isArray(capabilities) || !capabilities.includes("CAPABILITY_NAMED_IAM")) fail();
      const response = await callAws([
        "cloudformation", "create-stack", "--stack-name", name, "--template-body", templateBody,
        "--parameters", JSON.stringify(parameters), "--capabilities", ...capabilities, "--region", region, "--output", "json",
      ]);
      const responseKeys = Object.keys(response).sort();
      if (
        JSON.stringify(responseKeys) !== JSON.stringify(["StackId"]) &&
        JSON.stringify(responseKeys) !== JSON.stringify(["OperationId", "StackId"])
      ) fail();
      if (response.OperationId !== undefined && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(response.OperationId)) fail();
      stackIdArn(response.StackId, { stackName: name, region, accountId });
      return Object.freeze({ StackId: response.StackId });
    },
    waitStackCreateComplete({ stackName: name, stackId = null }) {
      stackName(name);
      const identifier = stackId === null ? name : stackIdArn(stackId, { stackName: name, region, accountId });
      return callAws(["cloudformation", "wait", "stack-create-complete", "--stack-name", identifier, "--region", region, "--output", "json"], { timeoutMs: 300_000 });
    },
    async describeStackOutputs({ stackName: name, stackId = null }) {
      stackName(name);
      const identifier = stackId === null ? name : stackIdArn(stackId, { stackName: name, region, accountId });
      const response = await callAws(["cloudformation", "describe-stacks", "--stack-name", identifier, "--region", region, "--output", "json"]);
      const stack = response.Stacks?.[0];
      if (!stack || (stackId !== null && stack.StackId !== identifier) || (stack.StackName !== undefined && stack.StackName !== name) || !Array.isArray(stack.Outputs)) fail();
      return Object.freeze(Object.fromEntries(stack.Outputs.map((entry) => [entry.OutputKey, entry.OutputValue])));
    },
    async listStackResources({ stackName: name, stackId = null }) {
      stackName(name);
      const identifier = stackId === null ? name : stackIdArn(stackId, { stackName: name, region, accountId });
      const response = await callAws(["cloudformation", "list-stack-resources", "--stack-name", identifier, "--region", region, "--output", "json"]);
      if (!Array.isArray(response.StackResourceSummaries) || response.StackResourceSummaries.length === 0 || response.NextToken !== undefined) fail();
      return Object.freeze({
        stackId: identifier,
        stackName: name,
        resources: Object.freeze(response.StackResourceSummaries.map((entry) => {
          if (entry.StackId !== undefined || entry.StackName !== undefined) fail();
          return Object.freeze({
            logicalResourceId: entry.LogicalResourceId,
            physicalResourceId: entry.PhysicalResourceId,
            resourceType: entry.ResourceType,
          });
        })),
      });
    },
    registerTaskDefinition({ taskDefinition }) {
      plain(taskDefinition);
      return callAws(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(taskDefinition), "--region", region, "--output", "json"]);
    },
    runTask({ cluster, taskDefinitionArn, role, networkConfiguration, startedBy, platformVersion = "1.4.0" }) {
      if (!["initiator", "responder"].includes(role) || typeof cluster !== "string" || typeof taskDefinitionArn !== "string") fail();
      if (platformVersion !== "1.4.0") fail();
      return callAws([
        "ecs", "run-task", "--cluster", cluster, "--task-definition", taskDefinitionArn,
        "--launch-type", "FARGATE", "--platform-version", platformVersion, "--network-configuration", JSON.stringify(networkConfiguration),
        "--started-by", startedBy, "--region", region, "--output", "json",
      ]);
    },
    waitTasksStopped({ cluster, taskArns }) {
      if (typeof cluster !== "string" || !Array.isArray(taskArns) || taskArns.length > 2 || taskArns.length < 1) fail();
      return callAws(["ecs", "wait", "tasks-stopped", "--cluster", cluster, "--tasks", ...taskArns, "--region", region, "--output", "json"], { timeoutMs: 300_000 });
    },
    waitTasksRunning({ cluster, taskArns }) {
      if (typeof cluster !== "string" || !Array.isArray(taskArns) || taskArns.length !== 2) fail();
      return callAws(["ecs", "wait", "tasks-running", "--cluster", cluster, "--tasks", ...taskArns, "--region", region, "--output", "json"], { timeoutMs: 300_000 });
    },
    stopTask({ cluster, taskArn, role }) {
      if (!["initiator", "responder"].includes(role) || typeof cluster !== "string" || typeof taskArn !== "string") fail();
      return callAws(["ecs", "stop-task", "--cluster", cluster, "--task", taskArn, "--reason", "clockchain cleanup", "--region", region, "--output", "json"]);
    },
    deregisterTaskDefinition({ taskDefinitionArn, role }) {
      if (!["initiator", "responder"].includes(role) || typeof taskDefinitionArn !== "string") fail();
      return callAws(["ecs", "deregister-task-definition", "--task-definition", taskDefinitionArn, "--region", region, "--output", "json"]);
    },
    deleteStack({ stackName: name }) {
      stackName(name);
      return callAws(["cloudformation", "delete-stack", "--stack-name", name, "--region", region, "--output", "json"]);
    },
    waitStackDeleteComplete({ stackName: name }) {
      stackName(name);
      return callAws(["cloudformation", "wait", "stack-delete-complete", "--stack-name", name, "--region", region, "--output", "json"], { timeoutMs: 300_000 });
    },
    async confirmAbsence({ stackName: name }) {
      stackName(name);
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const exists = await this.stackExists({ stackName: name });
        if (!exists) return Object.freeze({ absent: true });
        if (attempt < 4) await sleepFn(1000);
      }
      return Object.freeze({ absent: false });
    },
    async pollPublicEvents({ logGroupNames, deadlineMs }) {
      if (!Array.isArray(logGroupNames) || logGroupNames.length !== 2) fail();
      if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= now() || deadlineMs - now() > 300_000) fail();
      const byRole = new Map();
      const failures = new Map();
      const progress = new Map();
      const progressSequence = new Map();
      const progressEvents = new Map(ROLES.map((role) => [role, new Map()]));
      while (now() <= deadlineMs && byRole.size < 2) {
        for (const group of logGroupNames) {
          const groupRole = group.includes("/initiator") ? "initiator" : group.includes("/responder") ? "responder" : null;
          if (groupRole === null) fail();
          const response = await callAws(["logs", "filter-log-events", "--log-group-name", group, "--region", region, "--output", "json"]);
          if (!Array.isArray(response.events) || response.nextToken !== undefined) fail();
          for (const event of response.events) {
            if (typeof event.message !== "string") fail();
            if (event.message.startsWith(PARTY_FAILURE_PREFIX)) {
              const stage = event.message.slice(PARTY_FAILURE_PREFIX.length);
              if (!PARTY_FAILURE_STAGE.test(stage)) fail();
              const previousFailure = failures.get(groupRole);
              if (previousFailure !== undefined && previousFailure !== stage) fail();
              failures.set(groupRole, stage);
              continue;
            }
            const record = parse(event.message);
            if (record.schema === "clockchain.mechanics-proof-party-event/v1") {
              const keys = Object.keys(record).sort();
              if (
                JSON.stringify(keys) !== JSON.stringify(["evidenceDigest", "role", "runId", "schema", "sequence", "type"]) ||
                record.role !== groupRole || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(record.runId) ||
                !/^[1-9][0-9]*$/.test(record.sequence) || !PARTY_PROGRESS_TYPES.includes(record.type) || !/^[0-9a-f]{64}$/.test(record.evidenceDigest)
              ) fail();
              const sequence = Number(record.sequence);
              if (!Number.isSafeInteger(sequence)) fail();
              const priorType = progressEvents.get(groupRole).get(sequence);
              if (priorType !== undefined) {
                if (priorType !== record.type) fail();
                continue;
              }
              if (sequence <= (progressSequence.get(groupRole) ?? 0)) fail();
              progressEvents.get(groupRole).set(sequence, record.type);
              progressSequence.set(groupRole, sequence);
              progress.set(groupRole, record.type);
              continue;
            }
            if (record.schema !== "clockchain.mechanics-proof-party-evidence/v1") continue;
            if (!Number.isSafeInteger(event.timestamp)) fail();
            if (!["initiator", "responder"].includes(record.role)) fail();
            if (record.role !== groupRole) fail();
            record.timestamp = new Date(event.timestamp).toISOString();
            const previous = byRole.get(record.role);
            const serialized = JSON.stringify(record);
            if (previous !== undefined && JSON.stringify(previous) !== serialized) fail();
            byRole.set(record.role, record);
          }
        }
        if (failures.size === 2) throw partyFailureError(failures, progress);
        if (byRole.size >= 2) break;
        await sleepFn(1000);
      }
      if (failures.size > 0) throw partyFailureError(failures, progress);
      if (byRole.size !== 2) throw partyProgressError(progress);
      return Object.freeze(ROLES.map((role) => byRole.get(role)));
    },
    async inspectNetwork({ vpcId, publicSubnetId }) {
      string(vpcId);
      string(publicSubnetId);
      const vpcs = await callAws(["ec2", "describe-vpcs", "--vpc-ids", vpcId, "--region", region, "--output", "json"]);
      const subnets = await callAws(["ec2", "describe-subnets", "--filters", `Name=vpc-id,Values=${vpcId}`, "--region", region, "--output", "json"]);
      const routes = await callAws(["ec2", "describe-route-tables", "--filters", `Name=association.subnet-id,Values=${publicSubnetId}`, "--region", region, "--output", "json"]);
      const vpc = vpcs.Vpcs?.[0];
      const publicSubnet = subnets.Subnets?.find((subnet) => subnet.SubnetId === publicSubnetId);
      const publicRouteTable = routes.RouteTables?.[0];
      if (!vpc || !publicSubnet || !publicRouteTable) fail();
      return Object.freeze({
        vpc: Object.freeze({ vpcId: vpc.VpcId, cidrs: Object.freeze((vpc.CidrBlockAssociationSet ?? []).map((entry) => entry.CidrBlock)) }),
        publicSubnet: Object.freeze({
          subnetId: publicSubnet.SubnetId,
          vpcId: publicSubnet.VpcId,
          cidr: publicSubnet.CidrBlock,
          availabilityZone: publicSubnet.AvailabilityZone,
          mapPublicIpOnLaunch: publicSubnet.MapPublicIpOnLaunch,
          routeTableId: publicRouteTable.RouteTableId,
        }),
        publicRouteTable: Object.freeze({
          routeTableId: publicRouteTable.RouteTableId,
          routes: Object.freeze((publicRouteTable.Routes ?? []).map((route) => Object.freeze({
            destinationCidrBlock: route.DestinationCidrBlock,
            gatewayId: route.GatewayId,
            state: route.State,
          }))),
        }),
        existingSubnets: Object.freeze((subnets.Subnets ?? []).map((subnet) => Object.freeze({ subnetId: subnet.SubnetId, vpcId: subnet.VpcId, cidr: subnet.CidrBlock }))),
      });
    },
    async reconcileCreatedStack({ stackName: name }) {
      stackName(name);
      const response = await callAws(["cloudformation", "describe-stacks", "--stack-name", name, "--region", region, "--output", "json"]);
      const stack = response.Stacks?.[0];
      if (!stack || stack.StackName !== name) fail();
      const outputs = Object.fromEntries((stack.Outputs ?? []).map((entry) => [entry.OutputKey, entry.OutputValue]));
      return Object.freeze({ stackId: stack.StackId, stackName: name, clusterArn: outputs.ClusterArn ?? null });
    },
    async reconcileTaskDefinitions({ stackName: name }) {
      stackName(name);
      const response = await callAws(["ecs", "list-task-definitions", "--family-prefix", `${name}-`, "--status", "ACTIVE", "--region", region, "--output", "json"]);
      if (!Array.isArray(response.taskDefinitionArns) || response.nextToken !== undefined || response.taskDefinitionArns.length > 2) fail();
      return Object.freeze(response.taskDefinitionArns.map((arn) => {
        const role = arn.includes("-initiator:") ? "initiator" : arn.includes("-responder:") ? "responder" : null;
        if (role === null) fail();
        return Object.freeze({ role, taskDefinitionArn: arn });
      }));
    },
    async reconcileTasks({ stackName: name, cluster }) {
      stackName(name);
      string(cluster);
      const runId = name.slice("clockchain-".length);
      const listed = await callAws(["ecs", "list-tasks", "--cluster", cluster, "--started-by", runId, "--region", region, "--output", "json"]);
      if (!Array.isArray(listed.taskArns) || listed.nextToken !== undefined || listed.taskArns.length > 2) fail();
      if (listed.taskArns.length === 0) return Object.freeze([]);
      const described = await callAws(["ecs", "describe-tasks", "--cluster", cluster, "--tasks", ...listed.taskArns, "--region", region, "--output", "json"]);
      if (!Array.isArray(described.tasks)) fail();
      return Object.freeze(described.tasks.map((task) => {
        if (task.startedBy !== runId) fail();
        const group = String(task.group ?? "");
        const role = group.endsWith("-initiator") ? "initiator" : group.endsWith("-responder") ? "responder" : null;
        if (role === null) fail();
        return Object.freeze({ role, taskArn: task.taskArn });
      }));
    },
  });
}
