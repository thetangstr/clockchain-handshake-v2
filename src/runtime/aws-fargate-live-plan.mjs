import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { types } from "node:util";

export const FARGATE_LIVE_PLAN_SCHEMA = "clockchain.fargate-live-plan/v1";

const PRODUCTION_MCP_URL = "https://mcp.clockchain.network/handshake/mcp";
const HELPER_MANIFEST_DIGEST = "fa3c408a3739227b5bdb71486b4d291b8f4dffdb0d1f2fa79dd59644ba5e09ad";
const DEMO_MANDATE = Object.freeze({
  identityPolicy: Object.freeze({
    chainId: "eip155:11155111",
    erc8004: "required_fresh",
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  }),
  reference: "northstar-harbor-demo",
  statement: "Confirm both agents agree to the same operational terms.",
  validForSeconds: "90",
});
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ACCOUNT_ID = /^[0-9]{12}$/;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$/;
const VPC_ID = /^vpc-[a-z0-9]+$/;
const SUBNET_ID = /^subnet-[a-z0-9-]+$/;
const ROUTE_TABLE_ID = /^rtb-[a-z0-9-]+$/;
const IGW_ID = /^igw-[a-z0-9]+$/;
const SG_ID = /^sg-[a-z0-9-]+$/;
const IMAGE = /^([0-9]{12})\.dkr\.ecr\.([a-z]{2}(?:-gov)?-[a-z]+-[0-9])\.amazonaws\.com\/clockchain-mechanics-proof@sha256:[0-9a-f]{64}$/;
const TEMPLATE_PATH = "infra/mechanics-proof/fargate-live-runtime.yaml";
const TEMPLATE_SCHEMA = "clockchain.fargate-live-runtime-template/v1";
const TEMPLATE_SHA256 = "cd54763b6b21f4392cac8976128d2f46cbabac1337f1663fbef7cf5abcab17b0";
const EXPECTED_OUTPUTS = Object.freeze([
  "ClusterArn",
  "InitiatorExecutionRoleArn",
  "InitiatorLogGroupName",
  "InitiatorPrivateSubnetId",
  "InitiatorQueueUrl",
  "InitiatorSecurityGroupId",
  "InitiatorTaskRoleArn",
  "ResponderExecutionRoleArn",
  "ResponderLogGroupName",
  "ResponderPrivateSubnetId",
  "ResponderQueueUrl",
  "ResponderSecurityGroupId",
  "ResponderTaskRoleArn",
]);
const STACK_RESOURCE_BINDINGS = Object.freeze({
  Cluster: Object.freeze({ output: "ClusterArn", type: "AWS::ECS::Cluster", arnName: true }),
  InitiatorExecutionRole: Object.freeze({ output: "InitiatorExecutionRoleArn", type: "AWS::IAM::Role", arnName: true }),
  InitiatorLogGroup: Object.freeze({ output: "InitiatorLogGroupName", type: "AWS::Logs::LogGroup" }),
  InitiatorPrivateSubnet: Object.freeze({ output: "InitiatorPrivateSubnetId", type: "AWS::EC2::Subnet" }),
  InitiatorQueue: Object.freeze({ output: "InitiatorQueueUrl", type: "AWS::SQS::Queue" }),
  InitiatorSecurityGroup: Object.freeze({ output: "InitiatorSecurityGroupId", type: "AWS::EC2::SecurityGroup" }),
  InitiatorTaskRole: Object.freeze({ output: "InitiatorTaskRoleArn", type: "AWS::IAM::Role", arnName: true }),
  ResponderExecutionRole: Object.freeze({ output: "ResponderExecutionRoleArn", type: "AWS::IAM::Role", arnName: true }),
  ResponderLogGroup: Object.freeze({ output: "ResponderLogGroupName", type: "AWS::Logs::LogGroup" }),
  ResponderPrivateSubnet: Object.freeze({ output: "ResponderPrivateSubnetId", type: "AWS::EC2::Subnet" }),
  ResponderQueue: Object.freeze({ output: "ResponderQueueUrl", type: "AWS::SQS::Queue" }),
  ResponderSecurityGroup: Object.freeze({ output: "ResponderSecurityGroupId", type: "AWS::EC2::SecurityGroup" }),
  ResponderTaskRole: Object.freeze({ output: "ResponderTaskRoleArn", type: "AWS::IAM::Role", arnName: true }),
});
const STACK_INPUT_KEYS = Object.freeze([
  "accountId",
  "appImage",
  "bedrockModelArn",
  "budgetUsd",
  "codexSecretArn",
  "expiresAt",
  "initiatorPrivateSubnet",
  "maxConcurrency",
  "mcpUrl",
  "networkInspection",
  "publicSubnetId",
  "region",
  "responderPrivateSubnet",
  "runId",
  "startedAt",
  "ttlSeconds",
  "vpcId",
]);

function fail() {
  throw new Error("Fargate live plan validation failed safely.");
}

function plain(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) fail();
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  return result;
}

function exact(value, keys) {
  const item = plain(value);
  const actual = Object.keys(item).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail();
  return item;
}

function string(value, pattern) {
  if (typeof value !== "string" || value.length === 0 || (pattern && !pattern.test(value))) fail();
  return value;
}

function cloneJson(value) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    fail();
  }
}

function ipv4(value) {
  const parts = String(value).split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) fail();
  return parts.reduce((result, part) => ((result << 8) | Number(part)) >>> 0, 0);
}

function cidrRange(value, requiredPrefix = null) {
  if (typeof value !== "string") fail();
  const match = /^(\d+\.\d+\.\d+\.\d+)\/(\d|[12]\d|3[0-2])$/.exec(value);
  if (!match) fail();
  const prefix = Number(match[2]);
  if (requiredPrefix !== null && prefix !== requiredPrefix) fail();
  const address = ipv4(match[1]);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const start = (address & mask) >>> 0;
  if (address !== start) fail();
  const size = 2 ** (32 - prefix);
  return Object.freeze({ end: start + size - 1, prefix, start, value });
}

function overlaps(left, right) {
  return left.start <= right.end && right.start <= left.end;
}

function contains(outer, inner) {
  return outer.start <= inner.start && outer.end >= inner.end;
}

function arnParts(value, service, region, accountId) {
  const match = /^arn:aws:([a-z0-9-]+):([a-z0-9-]*):([0-9]{0,12}):(.+)$/.exec(string(value));
  if (!match || match[1] !== service || match[2] !== region || match[3] !== accountId) fail();
  return match;
}

function validateTemplate(templateInput) {
  const template = plain(templateInput);
  if (plain(plain(template.Metadata).ClockchainMechanicsProof).schema !== TEMPLATE_SCHEMA) fail();
  const resources = plain(template.Resources);
  for (const name of [
    "Cluster", "NatEip", "NatGateway", "InitiatorPrivateSubnet", "ResponderPrivateSubnet",
    "InitiatorRouteTable", "ResponderRouteTable", "InitiatorQueue", "ResponderQueue",
    "InitiatorLogGroup", "ResponderLogGroup", "InitiatorSecurityGroup", "ResponderSecurityGroup",
    "InitiatorTaskRole", "ResponderTaskRole", "InitiatorExecutionRole", "ResponderExecutionRole",
  ]) plain(resources[name]);
  if (plain(resources.InitiatorPrivateSubnet.Properties).MapPublicIpOnLaunch !== false) fail();
  if (plain(resources.ResponderPrivateSubnet.Properties).MapPublicIpOnLaunch !== false) fail();
  const serialized = JSON.stringify(template);
  if (/EFS|FileSystem|SIGNER|STATE_REF|MCP_CREDENTIAL/i.test(serialized)) fail();
  return cloneJson(template);
}

export async function loadFargateLiveRuntimeTemplate(optionsInput = {}) {
  const options = exact(optionsInput, Object.keys(optionsInput).length === 0 ? [] : ["root"]);
  const root = options.root ?? process.cwd();
  if (typeof root !== "string" || root.length === 0) fail();
  try {
    const bytes = await readFile(resolve(root, TEMPLATE_PATH), "utf8");
    if (createHash("sha256").update(bytes).digest("hex") !== TEMPLATE_SHA256) fail();
    return validateTemplate(JSON.parse(bytes));
  } catch (error) {
    if (error?.message === "Fargate live plan validation failed safely.") throw error;
    fail();
  }
}

function validateNetwork(options) {
  const inspection = exact(options.networkInspection, ["existingSubnets", "publicRouteTable", "publicSubnet", "vpc"]);
  const vpc = exact(inspection.vpc, ["cidrs", "vpcId"]);
  if (string(vpc.vpcId, VPC_ID) !== options.vpcId || !Array.isArray(vpc.cidrs) || vpc.cidrs.length < 1) fail();
  const vpcRanges = vpc.cidrs.map((cidr) => cidrRange(cidr));

  const publicSubnet = exact(inspection.publicSubnet, ["availabilityZone", "cidr", "mapPublicIpOnLaunch", "routeTableId", "subnetId", "vpcId"]);
  if (
    string(publicSubnet.subnetId, SUBNET_ID) !== options.publicSubnetId ||
    string(publicSubnet.vpcId, VPC_ID) !== options.vpcId ||
    publicSubnet.mapPublicIpOnLaunch !== true
  ) fail();
  string(publicSubnet.availabilityZone);
  cidrRange(publicSubnet.cidr);
  const routeTableId = string(publicSubnet.routeTableId, ROUTE_TABLE_ID);
  const routeTable = exact(inspection.publicRouteTable, ["routeTableId", "routes"]);
  if (string(routeTable.routeTableId, ROUTE_TABLE_ID) !== routeTableId || !Array.isArray(routeTable.routes)) fail();
  const publicRoutes = routeTable.routes.map((route) => exact(route, ["destinationCidrBlock", "gatewayId", "state"]));
  const internetRoute = publicRoutes.find((route) =>
    route.destinationCidrBlock === "0.0.0.0/0" && IGW_ID.test(route.gatewayId) && route.state === "active"
  );
  if (!internetRoute) fail();

  const initiator = exact(options.initiatorPrivateSubnet, ["availabilityZone", "cidr"]);
  const responder = exact(options.responderPrivateSubnet, ["availabilityZone", "cidr"]);
  const initiatorRange = cidrRange(initiator.cidr, 24);
  const responderRange = cidrRange(responder.cidr, 24);
  if (string(initiator.availabilityZone) === string(responder.availabilityZone) || overlaps(initiatorRange, responderRange)) fail();
  if (!vpcRanges.some((range) => contains(range, initiatorRange)) || !vpcRanges.some((range) => contains(range, responderRange))) fail();

  if (!Array.isArray(inspection.existingSubnets)) fail();
  for (const entryInput of inspection.existingSubnets) {
    const entry = exact(entryInput, ["cidr", "subnetId", "vpcId"]);
    string(entry.subnetId, SUBNET_ID);
    if (string(entry.vpcId, VPC_ID) !== options.vpcId) fail();
    const existing = cidrRange(entry.cidr);
    if (overlaps(initiatorRange, existing) || overlaps(responderRange, existing)) fail();
  }
  return Object.freeze({
    initiatorAvailabilityZone: initiator.availabilityZone,
    initiatorCidr: initiator.cidr,
    publicRoute: Object.freeze({ destinationCidrBlock: "0.0.0.0/0", gatewayId: internetRoute.gatewayId, routeTableId }),
    responderAvailabilityZone: responder.availabilityZone,
    responderCidr: responder.cidr,
  });
}

export async function buildFargateLiveStackPlan(optionsInput) {
  const options = plain(optionsInput);
  if (Object.keys(options).some((key) => !STACK_INPUT_KEYS.includes(key))) fail();
  for (const key of STACK_INPUT_KEYS.filter((key) => key !== "root")) if (!Object.hasOwn(options, key)) fail();
  const accountId = string(options.accountId, ACCOUNT_ID);
  const region = string(options.region, REGION);
  const runId = string(options.runId, RUN_ID);
  const vpcId = string(options.vpcId, VPC_ID);
  const publicSubnetId = string(options.publicSubnetId, SUBNET_ID);
  const imageMatch = IMAGE.exec(string(options.appImage));
  if (!imageMatch || imageMatch[1] !== accountId || imageMatch[2] !== region) fail();
  arnParts(options.codexSecretArn, "secretsmanager", region, accountId);
  const bedrock = arnParts(options.bedrockModelArn, "bedrock", region, accountId);
  if (bedrock[4] !== "inference-profile/us.anthropic.claude-sonnet-4-6") fail();
  if (options.mcpUrl !== PRODUCTION_MCP_URL) fail();
  if (!Number.isInteger(options.ttlSeconds) || options.ttlSeconds < 1 || options.ttlSeconds > 3600) fail();
  if (options.maxConcurrency !== 2) fail();
  if (typeof options.budgetUsd !== "number" || !Number.isFinite(options.budgetUsd) || options.budgetUsd <= 0 || options.budgetUsd > 25) fail();
  const startedAt = Date.parse(string(options.startedAt));
  const expiresAt = Date.parse(string(options.expiresAt));
  if (!Number.isFinite(startedAt) || !Number.isFinite(expiresAt) || expiresAt - startedAt !== options.ttlSeconds * 1000) fail();
  const network = validateNetwork({ ...options, vpcId, publicSubnetId });
  const template = await loadFargateLiveRuntimeTemplate();
  return Object.freeze({
    schema: FARGATE_LIVE_PLAN_SCHEMA,
    accountId,
    appImage: options.appImage,
    bedrockModelArn: options.bedrockModelArn,
    codexSecretArn: options.codexSecretArn,
    mcpUrl: PRODUCTION_MCP_URL,
    network,
    parameters: Object.freeze({
      BedrockModelArn: options.bedrockModelArn,
      CodexSecretArn: options.codexSecretArn,
      CostCenter: "mechanics-proof",
      ExpiresAt: options.expiresAt,
      InitiatorAvailabilityZone: network.initiatorAvailabilityZone,
      InitiatorPrivateSubnetCidr: network.initiatorCidr,
      PublicSubnetId: publicSubnetId,
      ResponderAvailabilityZone: network.responderAvailabilityZone,
      ResponderPrivateSubnetCidr: network.responderCidr,
      RunId: runId,
      VpcId: vpcId,
    }),
    region,
    runId,
    template,
    controls: Object.freeze({
      assignPublicIp: "DISABLED",
      budgetUsd: options.budgetUsd,
      controllerRoutesPrivateContent: false,
      maxConcurrency: 2,
      sharedWritableStorage: false,
      temporaryNatGateway: true,
      ttlSeconds: options.ttlSeconds,
    }),
  });
}

function validateOutputs(input, plan) {
  const outputs = exact(input, EXPECTED_OUTPUTS);
  const account = plan.accountId;
  const region = plan.region;
  if (outputs.ClusterArn !== `arn:aws:ecs:${region}:${account}:cluster/clockchain-${plan.runId}`) fail();
  const roleNames = Object.freeze({
    InitiatorTaskRoleArn: `cc-${plan.runId}-i-task`,
    ResponderTaskRoleArn: `cc-${plan.runId}-r-task`,
    InitiatorExecutionRoleArn: `cc-${plan.runId}-i-exec`,
    ResponderExecutionRoleArn: `cc-${plan.runId}-r-exec`,
  });
  for (const [key, roleName] of Object.entries(roleNames)) {
    if (outputs[key] !== `arn:aws:iam::${account}:role/${roleName}`) fail();
  }
  if (
    outputs.InitiatorTaskRoleArn === outputs.ResponderTaskRoleArn ||
    outputs.InitiatorExecutionRoleArn === outputs.ResponderExecutionRoleArn ||
    outputs.InitiatorTaskRoleArn === outputs.InitiatorExecutionRoleArn ||
    outputs.ResponderTaskRoleArn === outputs.ResponderExecutionRoleArn
  ) fail();
  for (const key of ["InitiatorPrivateSubnetId", "ResponderPrivateSubnetId"]) string(outputs[key], SUBNET_ID);
  for (const key of ["InitiatorSecurityGroupId", "ResponderSecurityGroupId"]) string(outputs[key], SG_ID);
  if (outputs.InitiatorPrivateSubnetId === outputs.ResponderPrivateSubnetId || outputs.InitiatorSecurityGroupId === outputs.ResponderSecurityGroupId) fail();
  for (const key of ["InitiatorQueueUrl", "ResponderQueueUrl"]) {
    if (!new RegExp(`^https://sqs\\.${region}\\.amazonaws\\.com/${account}/[A-Za-z0-9_-]+$`).test(string(outputs[key]))) fail();
  }
  if (outputs.InitiatorQueueUrl === outputs.ResponderQueueUrl) fail();
  if (outputs.InitiatorQueueUrl !== `https://sqs.${region}.amazonaws.com/${account}/clockchain-${plan.runId}-initiator`) fail();
  if (outputs.ResponderQueueUrl !== `https://sqs.${region}.amazonaws.com/${account}/clockchain-${plan.runId}-responder`) fail();
  for (const key of ["InitiatorLogGroupName", "ResponderLogGroupName"]) {
    if (!string(outputs[key]).startsWith(`/clockchain/mechanics-proof/${plan.runId}/`)) fail();
  }
  if (outputs.InitiatorLogGroupName === outputs.ResponderLogGroupName) fail();
  return outputs;
}

function validateStackResources(input, plan, outputs) {
  const envelope = exact(input, ["resources", "stackId", "stackName"]);
  const stackName = `clockchain-${plan.runId}`;
  if (envelope.stackName !== stackName) fail();
  const escapedName = stackName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (!new RegExp(`^arn:aws:cloudformation:${plan.region}:${plan.accountId}:stack/${escapedName}/[A-Za-z0-9-]+$`).test(string(envelope.stackId))) fail();
  const templateResources = plain(plan.template.Resources);
  if (!Array.isArray(envelope.resources) || envelope.resources.length !== Object.keys(templateResources).length) fail();
  const seen = new Set();
  for (const resourceInput of envelope.resources) {
    const resource = exact(resourceInput, ["logicalResourceId", "physicalResourceId", "resourceType"]);
    const templateResource = templateResources[resource.logicalResourceId];
    if (!templateResource || seen.has(resource.logicalResourceId) || resource.resourceType !== plain(templateResource).Type) fail();
    string(resource.physicalResourceId);
    const binding = STACK_RESOURCE_BINDINGS[resource.logicalResourceId];
    seen.add(resource.logicalResourceId);
    if (binding) {
      if (resource.resourceType !== binding.type) fail();
      const output = outputs[binding.output];
      const expectedPhysical = binding.arnName ? output.slice(output.lastIndexOf("/") + 1) : output;
      if (resource.physicalResourceId !== expectedPhysical) fail();
    }
  }
  if (seen.size !== Object.keys(templateResources).length) fail();
  return envelope;
}

function env(object) {
  return Object.entries(object).sort(([left], [right]) => left.localeCompare(right)).map(([name, value]) => Object.freeze({ name, value }));
}

function taskDefinition(plan, outputs, role) {
  const initiator = role === "initiator";
  const own = initiator ? "Initiator" : "Responder";
  const peer = initiator ? "Responder" : "Initiator";
  const environment = {
    AWS_REGION: plan.region,
    CLOCKCHAIN_A2A_LISTEN_HOST: "0.0.0.0",
    CLOCKCHAIN_A2A_PORT: "8443",
    CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL: outputs[`${own}QueueUrl`],
    CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL: outputs[`${peer}QueueUrl`],
    CLOCKCHAIN_CLIENT: initiator ? "codex" : "claude",
    CLOCKCHAIN_HELPER_MANIFEST_DIGEST: HELPER_MANIFEST_DIGEST,
    CLOCKCHAIN_HOME: "/workspace/home",
    CLOCKCHAIN_MANDATE_JSON: JSON.stringify(DEMO_MANDATE),
    CLOCKCHAIN_MCP_URL: plan.mcpUrl,
    CLOCKCHAIN_OPENSSL_PATH: "/usr/bin/openssl",
    CLOCKCHAIN_PARTY_ROOT: "/workspace/party",
    CLOCKCHAIN_ROLE: role,
    CLOCKCHAIN_RUN_ID: plan.runId,
    CLOCKCHAIN_STATE_DIR: "/workspace/state",
    CLOCKCHAIN_WORKSPACE: "/workspace/workspace",
    NODE_ENV: "production",
    ...(initiator ? { CLOCKCHAIN_CODEX_MODEL: "gpt-5.6-terra" } : {
      ANTHROPIC_MODEL: "us.anthropic.claude-sonnet-4-6",
      CLAUDE_CODE_USE_BEDROCK: "1",
      CLOCKCHAIN_BEDROCK_MODEL_ID: "us.anthropic.claude-sonnet-4-6",
      CLOCKCHAIN_CLAUDE_PROVIDER: "bedrock",
    }),
  };
  return Object.freeze({
    containerDefinitions: Object.freeze([Object.freeze({
      command: Object.freeze(["--run-managed"]),
      dependsOn: Object.freeze([{ condition: "SUCCESS", containerName: "workspace-init" }]),
      environment: Object.freeze(env(environment)),
      essential: true,
      image: plan.appImage,
      logConfiguration: Object.freeze({
        logDriver: "awslogs",
        options: Object.freeze({
          "awslogs-group": outputs[`${own}LogGroupName`],
          "awslogs-region": plan.region,
          "awslogs-stream-prefix": role,
          mode: "blocking",
        }),
      }),
      mountPoints: Object.freeze([{ containerPath: "/workspace", readOnly: false, sourceVolume: "workspace" }]),
      name: role,
      portMappings: Object.freeze([{ containerPort: 8443, protocol: "tcp" }]),
      privileged: false,
      readonlyRootFilesystem: true,
      secrets: Object.freeze(initiator ? [{ name: "CLOCKCHAIN_CODEX_AUTH_JSON_BASE64", valueFrom: plan.codexSecretArn }] : []),
      stopTimeout: 30,
      user: "1000:1000",
    }), Object.freeze({
      command: Object.freeze(["chown 1000:1000 /workspace"]),
      entryPoint: Object.freeze(["/bin/sh", "-c"]),
      environment: Object.freeze([]),
      essential: false,
      image: plan.appImage,
      mountPoints: Object.freeze([{ containerPath: "/workspace", readOnly: false, sourceVolume: "workspace" }]),
      name: "workspace-init",
      portMappings: Object.freeze([]),
      privileged: false,
      readonlyRootFilesystem: true,
      secrets: Object.freeze([]),
      user: "0:0",
    })]),
    cpu: "512",
    executionRoleArn: outputs[`${own}ExecutionRoleArn`],
    family: `clockchain-${plan.runId}-${role}`,
    memory: "1024",
    networkMode: "awsvpc",
    requiresCompatibilities: Object.freeze(["FARGATE"]),
    runtimePlatform: Object.freeze({ cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }),
    taskRoleArn: outputs[`${own}TaskRoleArn`],
    volumes: Object.freeze([{ name: "workspace" }]),
  });
}

export function buildFargateLiveTaskDefinitions(optionsInput) {
  const options = exact(optionsInput, ["stackOutputs", "stackPlan", "stackResources"]);
  const plan = plain(options.stackPlan);
  if (plan.schema !== FARGATE_LIVE_PLAN_SCHEMA) fail();
  const outputs = validateOutputs(options.stackOutputs, plan);
  validateStackResources(options.stackResources, plan, outputs);
  const definitions = Object.freeze({
    initiator: taskDefinition(plan, outputs, "initiator"),
    responder: taskDefinition(plan, outputs, "responder"),
  });
  const serialized = JSON.stringify(definitions);
  if (/EFS|SIGNER|STATE_REF|MCP_CREDENTIAL|ANTHROPIC_API_KEY/i.test(serialized)) fail();
  return definitions;
}
