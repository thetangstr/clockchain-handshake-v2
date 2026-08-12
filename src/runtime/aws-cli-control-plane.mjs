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
  "logs filter-log-events",
]);

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

function stackName(value) {
  if (!STACK.test(string(value))) fail();
  return value;
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
  for (const arg of argv) string(arg);
  if (argv.at(-2) !== "--output" || argv.at(-1) !== "json") fail();
    const head = (argv[0] === "cloudformation" || argv[0] === "ecs") && argv[1] === "wait"
    ? argv.slice(0, 3).join(" ")
    : argv.slice(0, 2).join(" ");
  if (!ALLOWED.has(head)) fail();
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

function output(value) {
  const result = plain(value);
  if (result.stderr !== "" || typeof result.stdout !== "string") fail();
  if (result.exitCode !== 0) fail();
  if (result.stdout === "") return {};
  return parse(result.stdout);
}

function isMissingStack(error) {
  return /Stack with id clockchain-[0-9a-f-]+ does not exist/i.test(String(error?.message ?? error?.stderr ?? ""));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function createAwsCliControlPlane(optionsInput = {}) {
  const options = plain(optionsInput);
  if (Object.keys(options).some((key) => !["executor", "now", "region", "sleep", "timeoutMs"].includes(key))) fail();
  const executor = options.executor ?? defaultExecutor;
  if (typeof executor !== "function") fail();
  const region = string(options.region);
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
      response = await executor("aws", Object.freeze([...argvInput]), Object.freeze({ timeoutMs }));
    } catch (error) {
      if (options.allowMissingStack && isMissingStack(error)) throw error;
      fail();
    }
    if (typeof response.stdout === "string" && response.stdout.length > 1_048_576) fail();
    return output(response);
  }

  return Object.freeze({
    callAws,
    async getCallerIdentity() {
      const identity = await callAws(["sts", "get-caller-identity", "--region", region, "--output", "json"]);
      if (JSON.stringify(Object.keys(identity).sort()) !== JSON.stringify(["Account", "Arn", "UserId"])) fail();
      if (!/^[0-9]{12}$/.test(identity.Account) || typeof identity.Arn !== "string" || typeof identity.UserId !== "string") fail();
      return Object.freeze({ accountId: identity.Account, arn: identity.Arn, userId: identity.UserId });
    },
    validateTemplate({ templateBody }) {
      if (typeof templateBody !== "string" || templateBody.length === 0) fail();
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
    createStack({ stackName: name, templateBody, parameters, capabilities }) {
      stackName(name);
      if (typeof templateBody !== "string" || !Array.isArray(parameters) || !Array.isArray(capabilities) || !capabilities.includes("CAPABILITY_NAMED_IAM")) fail();
      return callAws([
        "cloudformation", "create-stack", "--stack-name", name, "--template-body", templateBody,
        "--parameters", JSON.stringify(parameters), "--capabilities", ...capabilities, "--region", region, "--output", "json",
      ]);
    },
    waitStackCreateComplete({ stackName: name }) {
      stackName(name);
      return callAws(["cloudformation", "wait", "stack-create-complete", "--stack-name", name, "--region", region, "--output", "json"]);
    },
    async describeStackOutputs({ stackName: name }) {
      stackName(name);
      const response = await callAws(["cloudformation", "describe-stacks", "--stack-name", name, "--region", region, "--output", "json"]);
      const stack = response.Stacks?.[0];
      if (!stack || !Array.isArray(stack.Outputs)) fail();
      return Object.freeze(Object.fromEntries(stack.Outputs.map((entry) => [entry.OutputKey, entry.OutputValue])));
    },
    async listStackResources({ stackName: name }) {
      stackName(name);
      const response = await callAws(["cloudformation", "list-stack-resources", "--stack-name", name, "--region", region, "--output", "json"]);
      if (!Array.isArray(response.StackResourceSummaries) || response.StackResourceSummaries.length === 0 || response.NextToken !== undefined) fail();
      return Object.freeze({
        stackId: response.StackResourceSummaries[0].StackId,
        stackName: name,
        resources: Object.freeze(response.StackResourceSummaries.map((entry) => Object.freeze({
          logicalResourceId: entry.LogicalResourceId,
          physicalResourceId: entry.PhysicalResourceId,
          resourceType: entry.ResourceType,
        }))),
      });
    },
    registerTaskDefinition({ taskDefinition }) {
      plain(taskDefinition);
      return callAws(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(taskDefinition), "--region", region, "--output", "json"]);
    },
    runTask({ cluster, taskDefinitionArn, role, networkConfiguration, startedBy }) {
      if (!["initiator", "responder"].includes(role) || typeof cluster !== "string" || typeof taskDefinitionArn !== "string") fail();
      return callAws([
        "ecs", "run-task", "--cluster", cluster, "--task-definition", taskDefinitionArn,
        "--launch-type", "FARGATE", "--network-configuration", JSON.stringify(networkConfiguration),
        "--started-by", startedBy, "--region", region, "--output", "json",
      ]);
    },
    waitTasksStopped({ cluster, taskArns }) {
      if (typeof cluster !== "string" || !Array.isArray(taskArns) || taskArns.length > 2 || taskArns.length < 1) fail();
      return callAws(["ecs", "wait", "tasks-stopped", "--cluster", cluster, "--tasks", ...taskArns, "--region", region, "--output", "json"]);
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
      return callAws(["cloudformation", "wait", "stack-delete-complete", "--stack-name", name, "--region", region, "--output", "json"]);
    },
    async confirmAbsence({ stackName: name }) {
      stackName(name);
      const exists = await this.stackExists({ stackName: name });
      return Object.freeze({ absent: !exists });
    },
    async pollPublicEvents({ logGroupNames, deadlineMs }) {
      if (!Array.isArray(logGroupNames) || logGroupNames.length !== 2) fail();
      if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= now() || deadlineMs - now() > 300_000) fail();
      const byRole = new Map();
      while (now() <= deadlineMs && byRole.size < 2) {
        for (const group of logGroupNames) {
          const groupRole = group.includes("/initiator") ? "initiator" : group.includes("/responder") ? "responder" : null;
          if (groupRole === null) fail();
          const response = await callAws(["logs", "filter-log-events", "--log-group-name", group, "--region", region, "--output", "json"]);
          if (!Array.isArray(response.events) || response.nextToken !== undefined) fail();
          for (const event of response.events) {
            const record = parse(event.message);
            if (record.schema !== "clockchain.mechanics-proof-party-evidence/v1") continue;
            if (!["initiator", "responder"].includes(record.role)) fail();
            if (record.role !== groupRole) fail();
            const previous = byRole.get(record.role);
            const serialized = JSON.stringify(record);
            if (previous !== undefined && JSON.stringify(previous) !== serialized) fail();
            byRole.set(record.role, record);
          }
        }
        if (byRole.size >= 2) break;
        await sleepFn(1000);
      }
      if (byRole.size !== 2) fail();
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
