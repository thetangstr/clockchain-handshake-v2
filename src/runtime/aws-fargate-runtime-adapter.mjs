import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { types } from "node:util";

import { assertSecretFree } from "../core/redact.mjs";

export const FARGATE_DRY_RUN_PLAN_SCHEMA = "clockchain.fargate-dry-run-plan/v1";

const ROLES = Object.freeze(["initiator", "responder"]);
const IMAGE = /^.+@sha256:[0-9a-f]{64}$/;
const LONG_SHA = /^sha256:[0-9a-f]{64}$/;
const AWS_ARN = /^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:.+/;
const SECRET_REF_ARN = /^arn:aws:(?:secretsmanager|ssm):[a-z0-9-]+:[0-9]{12}:(?:secret|parameter)[:/].+/;
const SENSITIVE_ENV = /(?:secret|token|password|private|key|credential)/i;
const REQUIRED_ENV = Object.freeze({
  CLOCKCHAIN_A2A_PORT: "8443",
  CLOCKCHAIN_MCP_URL: "https://mcp.clockchain.network/handshake/mcp",
  NODE_ENV: "production",
});
const REQUIRED_SECRET_NAMES = Object.freeze([
  "CLOCKCHAIN_PROVIDER_REF",
  "CLOCKCHAIN_MCP_CREDENTIAL_REF",
  "CLOCKCHAIN_SIGNER_REF",
  "CLOCKCHAIN_STATE_REF",
]);
const TASK_DEFINITION_KEYS = Object.freeze([
  "containerDefinitions",
  "cpu",
  "executionRoleArn",
  "family",
  "memory",
  "networkMode",
  "requiresCompatibilities",
  "runtimePlatform",
  "taskRoleArn",
  "volumes",
]);
const TASK_DEFINITION_SERVER_KEYS = Object.freeze([
  ...TASK_DEFINITION_KEYS,
  "revision",
  "taskDefinitionArn",
]);
const CONTAINER_DEFINITION_KEYS = Object.freeze([
  "environment",
  "essential",
  "image",
  "logConfiguration",
  "mountPoints",
  "name",
  "portMappings",
  "privileged",
  "readonlyRootFilesystem",
  "secrets",
  "user",
]);
const RUNTIME_PLATFORM_KEYS = Object.freeze(["cpuArchitecture", "operatingSystemFamily"]);
const MAX_CANONICAL_DEPTH = 24;
const MAX_CANONICAL_KEYS = 256;
const MAX_CANONICAL_ARRAY_LENGTH = 1024;
const MAX_CANONICAL_STRING_LENGTH = 65536;

const RELATIVE_FILES = Object.freeze({
  template: "infra/mechanics-proof/fargate-runtime.yaml",
  initiator: "infra/mechanics-proof/task-definition.initiator.json",
  responder: "infra/mechanics-proof/task-definition.responder.json",
});

function fail() {
  throw new Error("Fargate dry-run validation failed safely.");
}

function strictData(value, failFn, seen = new WeakSet(), depth = 0) {
  if (depth > MAX_CANONICAL_DEPTH) failFn();
  if (value === null) return null;
  const kind = typeof value;
  if (kind === "string") {
    if (value.length > MAX_CANONICAL_STRING_LENGTH) failFn();
    return value;
  }
  if (kind === "boolean") return value;
  if (kind === "number") {
    if (!Number.isFinite(value)) failFn();
    return value;
  }
  if (kind !== "object") failFn();
  if (types.isProxy(value)) failFn();
  if (seen.has(value)) failFn();
  seen.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (Array.isArray(value)) {
    if (value.length > MAX_CANONICAL_ARRAY_LENGTH) failFn();
    for (const key of keys) {
      if (key === "length") continue;
      if (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key)) failFn();
      const index = Number(key);
      if (!Number.isSafeInteger(index) || index < 0 || index >= value.length) failFn();
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) failFn();
    }
    const normalized = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(descriptors, String(index))) failFn();
      normalized.push(strictData(descriptors[String(index)].value, failFn, seen, depth + 1));
    }
    seen.delete(value);
    return normalized;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) failFn();
  if (keys.length > MAX_CANONICAL_KEYS) failFn();
  const normalized = {};
  for (const key of keys.sort()) {
    if (typeof key !== "string") failFn();
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) failFn();
    normalized[key] = strictData(descriptor.value, failFn, seen, depth + 1);
  }
  seen.delete(value);
  return normalized;
}

export function sanitizeFargateData(value, failFn = fail) {
  try {
    return strictData(value, failFn);
  } catch (error) {
    if (error?.message === "Fargate dry-run validation failed safely." || error?.message === "Fargate runtime evidence validation failed safely.") {
      throw error;
    }
    failFn();
  }
}

export function stableJson(value) {
  return JSON.stringify(sanitizeFargateData(value));
}

export function sha256Hex(value) {
  return createHash("sha256").update(typeof value === "string" ? sanitizeFargateData(value) : stableJson(value)).digest("hex");
}

function parseJsonFile(bytes) {
  try {
    return JSON.parse(bytes);
  } catch {
    fail();
  }
}

function object(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function exactKeys(value, expected) {
  const keys = Object.keys(object(value)).sort();
  if (JSON.stringify(keys) !== JSON.stringify([...expected].sort())) fail();
  return value;
}

function string(value) {
  if (typeof value !== "string" || value.length === 0) fail();
  return value;
}

function awsArn(value) {
  if (!AWS_ARN.test(string(value))) fail();
  return value;
}

function digestRefs(refs) {
  return refs.map((entry) => sha256Hex(entry.valueFrom)).sort();
}

function extractSecurityGroups(template) {
  const resources = object(object(template).Resources);
  const initiator = object(object(resources.InitiatorSecurityGroup).Properties);
  const responder = object(object(resources.ResponderSecurityGroup).Properties);
  if (initiator.SecurityGroupIngress !== undefined || responder.SecurityGroupIngress !== undefined) fail();
  const standalone = {
    initiatorIngress: object(object(resources.InitiatorPeerA2AIngress).Properties),
    responderIngress: object(object(resources.ResponderPeerA2AIngress).Properties),
    initiatorEgress: object(object(resources.InitiatorPeerA2AEgress).Properties),
    responderEgress: object(object(resources.ResponderPeerA2AEgress).Properties),
  };
  return {
    initiator: {
      id: "sg-initiator",
      ingress: normalizeStandaloneIngress(standalone.initiatorIngress, "InitiatorSecurityGroup", "ResponderSecurityGroup"),
      egress: normalizeEgress(initiator.SecurityGroupEgress, standalone.initiatorEgress, "InitiatorSecurityGroup", "ResponderSecurityGroup"),
    },
    responder: {
      id: "sg-responder",
      ingress: normalizeStandaloneIngress(standalone.responderIngress, "ResponderSecurityGroup", "InitiatorSecurityGroup"),
      egress: normalizeEgress(responder.SecurityGroupEgress, standalone.responderEgress, "ResponderSecurityGroup", "InitiatorSecurityGroup"),
    },
  };
}

function normalizeStandaloneIngress(rule, expectedGroupRef, expectedPeerRef) {
  const source = rule.SourceSecurityGroupId;
  const group = rule.GroupId;
  if (
    rule.IpProtocol !== "tcp" ||
    rule.FromPort !== 8443 ||
    rule.ToPort !== 8443 ||
    !group ||
    object(group).Ref !== expectedGroupRef ||
    !source ||
    object(source).Ref !== expectedPeerRef ||
    Object.hasOwn(rule, "CidrIp")
  ) fail();
  return [{
    protocol: "tcp",
    fromPort: 8443,
    toPort: 8443,
    peerSecurityGroupRef: expectedPeerRef,
  }];
}

function normalizeEgress(rules, peerRule, expectedGroupRef, expectedPeerRef) {
  if (!Array.isArray(rules) || rules.length !== 1) fail();
  const peerGroup = peerRule.DestinationSecurityGroupId;
  if (
    peerRule.IpProtocol !== "tcp" ||
    peerRule.FromPort !== 8443 ||
    peerRule.ToPort !== 8443 ||
    !peerRule.GroupId ||
    object(peerRule.GroupId).Ref !== expectedGroupRef ||
    !peerGroup ||
    object(peerGroup).Ref !== expectedPeerRef ||
    Object.hasOwn(peerRule, "CidrIp")
  ) fail();
  const https = rules.find((rule) => object(rule).CidrIp === "0.0.0.0/0");
  if (!https || https.IpProtocol !== "tcp" || https.FromPort !== 443 || https.ToPort !== 443) fail();
  const description = String(https.Description ?? "");
  if (
    !/NAT or egress proxy/i.test(description) ||
    !/Docker Hub/i.test(description) ||
    !/Clockchain MCP/i.test(description) ||
    !/model provider/i.test(description) ||
    !/AWS VPC endpoints/i.test(description)
  ) fail();
  return [
    { protocol: "tcp", fromPort: 8443, toPort: 8443, peerSecurityGroupRef: expectedPeerRef },
    { protocol: "tcp", fromPort: 443, toPort: 443, cidrIp: "0.0.0.0/0", privateEgressOnly: true },
  ];
}

export function normalizeFargateTaskDefinitionForProof(taskDefinition, role, { server = false } = {}) {
  const task = object(taskDefinition);
  exactKeys(task, server ? TASK_DEFINITION_SERVER_KEYS : TASK_DEFINITION_KEYS);
  const containers = task.containerDefinitions;
  const volumes = task.volumes;
  if (!Array.isArray(containers) || containers.length !== 1) fail();
  if (!Array.isArray(volumes) || volumes.length !== 1) fail();
  const container = object(containers[0]);
  exactKeys(container, CONTAINER_DEFINITION_KEYS);
  exactKeys(task.runtimePlatform, RUNTIME_PLATFORM_KEYS);
  if (server) {
    awsArn(task.taskDefinitionArn);
    if (!Number.isSafeInteger(task.revision) || task.revision < 1) fail();
  }
  if (container.essential !== true || container.privileged !== false) fail();
  const normalized = {
    family: string(task.family),
    requiresCompatibilities: task.requiresCompatibilities,
    networkMode: task.networkMode,
    cpu: String(task.cpu),
    memory: String(task.memory),
    runtimePlatform: task.runtimePlatform,
    taskRoleArn: task.taskRoleArn,
    executionRoleArn: task.executionRoleArn,
    containerDefinitions: [{
      name: string(container.name),
      essential: container.essential,
      image: container.image,
      readonlyRootFilesystem: container.readonlyRootFilesystem,
      privileged: container.privileged,
      user: container.user,
      portMappings: container.portMappings,
      environment: container.environment,
      secrets: container.secrets,
      mountPoints: container.mountPoints,
      logConfiguration: container.logConfiguration,
    }],
    volumes,
  };
  if (server) {
    normalized.taskDefinitionArn = task.taskDefinitionArn;
    normalized.revision = task.revision;
  }
  return normalized;
}

function normalizeTaskDefinition(taskDefinition, role) {
  const normalized = normalizeFargateTaskDefinitionForProof(taskDefinition, role);
  const container = normalized.containerDefinitions[0];
  return {
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
    imageDigest: string(container.image).slice(container.image.indexOf("@") + 1),
    user: container.user,
    readonlyRootFilesystem: container.readonlyRootFilesystem,
    privileged: container.privileged,
    portMappings: container.portMappings,
    environment: container.environment,
    secrets: container.secrets,
    mountPoints: container.mountPoints,
    logConfiguration: container.logConfiguration,
    volumes: normalized.volumes,
    securityGroupId: `sg-${role}`,
  };
}

function validateTaskParty(party) {
  object(party);
  assertSameTaskDefinition(party);
  if (
    !Array.isArray(party.requiresCompatibilities) ||
    party.requiresCompatibilities.length !== 1 ||
    party.requiresCompatibilities[0] !== "FARGATE" ||
    party.networkMode !== "awsvpc" ||
    party.cpu !== "512" ||
    party.memory !== "1024" ||
    !IMAGE.test(string(party.image)) ||
    !LONG_SHA.test(party.imageDigest) ||
    party.readonlyRootFilesystem !== true ||
    party.privileged !== false ||
    party.user === "0" ||
    party.user === "root" ||
    typeof party.user !== "string" ||
    party.user.length === 0
  ) fail();
  awsArn(party.taskRoleArn);
  awsArn(party.executionRoleArn);
  if (party.taskRoleArn === party.executionRoleArn) fail();
  const platform = object(party.runtimePlatform);
  if (platform.operatingSystemFamily !== "LINUX" || platform.cpuArchitecture !== "X86_64") fail();
  const portMappings = party.portMappings;
  if (
    !Array.isArray(portMappings) ||
    portMappings.length !== 1 ||
    object(portMappings[0]).containerPort !== 8443 ||
    portMappings[0].protocol !== "tcp"
  ) fail();
  const env = party.environment;
  if (!Array.isArray(env) || env.length !== Object.keys(REQUIRED_ENV).length + 1) fail();
  const envNames = new Set();
  for (const entry of env) {
    const item = object(entry);
    if (SENSITIVE_ENV.test(string(item.name))) fail();
    if (typeof item.value !== "string") fail();
    if (envNames.has(item.name)) fail();
    envNames.add(item.name);
    assertSecretFree(item.value, ["secret-canary"]);
  }
  const roleEnv = env.find((entry) => entry.name === "CLOCKCHAIN_ROLE");
  const mcpEnv = env.find((entry) => entry.name === "CLOCKCHAIN_MCP_URL");
  if (roleEnv?.value !== party.role || mcpEnv?.value !== "https://mcp.clockchain.network/handshake/mcp") fail();
  for (const [name, value] of Object.entries(REQUIRED_ENV)) {
    if (env.find((entry) => entry.name === name)?.value !== value) fail();
  }
  const secrets = party.secrets;
  if (!Array.isArray(secrets) || secrets.length !== REQUIRED_SECRET_NAMES.length) fail();
  const secretNames = new Set();
  const secretValues = new Set();
  for (const entry of secrets) {
    const item = object(entry);
    if (!SECRET_REF_ARN.test(string(item.valueFrom))) fail();
    if (typeof item.name !== "string" || item.name.length === 0) fail();
    if (secretNames.has(item.name) || secretValues.has(item.valueFrom)) fail();
    secretNames.add(item.name);
    secretValues.add(item.valueFrom);
  }
  for (const required of REQUIRED_SECRET_NAMES) {
    if (!secretNames.has(required)) fail();
  }
  const log = object(party.logConfiguration);
  const options = object(log.options);
  if (
    log.logDriver !== "awslogs" ||
    options.mode !== "blocking" ||
    typeof options["awslogs-group"] !== "string" ||
    options["awslogs-group"].length === 0
  ) fail();
  const volumes = party.volumes;
  const mounts = party.mountPoints;
  if (!Array.isArray(volumes) || volumes.length !== 1 || !Array.isArray(mounts) || mounts.length !== 1) fail();
  const volume = object(volumes[0]);
  const mount = object(mounts[0]);
  if (
    typeof volume.name !== "string" ||
    volume.name.length === 0 ||
    Object.hasOwn(volume, "efsVolumeConfiguration") ||
    Object.hasOwn(volume, "host") ||
    Object.hasOwn(volume, "dockerVolumeConfiguration") ||
    mount.sourceVolume !== volume.name ||
    mount.containerPath !== "/workspace" ||
    mount.readOnly !== false
  ) fail();
  return party;
}

function assertSameTaskDefinition(party) {
  const container = {
    name: party.role,
    essential: true,
    image: party.image,
    readonlyRootFilesystem: party.readonlyRootFilesystem,
    privileged: party.privileged,
    user: party.user,
    portMappings: party.portMappings,
    environment: party.environment,
    secrets: party.secrets,
    mountPoints: party.mountPoints,
    logConfiguration: party.logConfiguration,
  };
  const expected = {
    family: party.family,
    requiresCompatibilities: party.requiresCompatibilities,
    networkMode: party.networkMode,
    cpu: party.cpu,
    memory: party.memory,
    runtimePlatform: party.runtimePlatform,
    taskRoleArn: party.taskRoleArn,
    executionRoleArn: party.executionRoleArn,
    containerDefinitions: [container],
    volumes: party.volumes,
  };
  if (stableJson(party.taskDefinition) !== stableJson(expected)) fail();
}

function validateNetwork(network) {
  object(network);
  if (network.assignPublicIp !== "DISABLED") fail();
  if (
    typeof network.privateSubnetEgressRequirement !== "string" ||
    !/private subnets/i.test(network.privateSubnetEgressRequirement) ||
    !/NAT or (?:an? )?egress proxy/i.test(network.privateSubnetEgressRequirement) ||
    !/Docker Hub/i.test(network.privateSubnetEgressRequirement) ||
    !/Clockchain MCP/i.test(network.privateSubnetEgressRequirement) ||
    !/model provider HTTPS/i.test(network.privateSubnetEgressRequirement) ||
    !/AWS VPC endpoints may cover CloudWatch Logs, Secrets Manager or SSM, and STS/i.test(network.privateSubnetEgressRequirement) ||
    !/Phase6.*ECR api\/dkr and S3/i.test(network.privateSubnetEgressRequirement) ||
    /NAT or VPC endpoints for ECR.*Clockchain MCP/i.test(network.privateSubnetEgressRequirement)
  ) fail();
  const groups = object(network.securityGroups);
  for (const role of ROLES) {
    const group = object(groups[role]);
    if (!Array.isArray(group.ingress) || group.ingress.length !== 1) fail();
    const ingress = object(group.ingress[0]);
    if (
      ingress.protocol !== "tcp" ||
      ingress.fromPort !== 8443 ||
      ingress.toPort !== 8443 ||
      typeof ingress.peerSecurityGroupRef !== "string" ||
      Object.hasOwn(ingress, "cidrIp")
    ) fail();
    if (!Array.isArray(group.egress) || group.egress.length !== 2) fail();
    const peer = group.egress.find((rule) => rule.peerSecurityGroupRef);
    const https = group.egress.find((rule) => rule.cidrIp === "0.0.0.0/0");
    if (
      !peer ||
      peer.protocol !== "tcp" ||
      peer.fromPort !== 8443 ||
      peer.toPort !== 8443 ||
      !https ||
      https.protocol !== "tcp" ||
      https.fromPort !== 443 ||
      https.toPort !== 443 ||
      https.privateEgressOnly !== true
    ) fail();
  }
  return network;
}

function validateTemplate(template) {
  const resources = object(object(template).Resources);
  for (const name of ["InitiatorTaskRole", "ResponderTaskRole", "InitiatorExecutionRole", "ResponderExecutionRole"]) {
    const role = object(resources[name]);
    if (role.Type !== "AWS::IAM::Role") fail();
    const props = object(role.Properties);
    const assume = object(props.AssumeRolePolicyDocument);
    const statement = assume.Statement;
    if (!Array.isArray(statement) || statement.length !== 1) fail();
    const stmt = object(statement[0]);
    if (
      stmt.Effect !== "Allow" ||
      object(stmt.Principal).Service !== "ecs-tasks.amazonaws.com" ||
      stmt.Action !== "sts:AssumeRole"
    ) fail();
  }
  for (const name of ["InitiatorLogGroup", "ResponderLogGroup"]) {
    const props = object(object(resources[name]).Properties);
    if (typeof props.RetentionInDays !== "number" || props.RetentionInDays < 1) fail();
    if (!Array.isArray(props.Tags) || props.Tags.length < 2) fail();
    const logName = object(props.LogGroupName);
    if (!String(logName["Fn::Sub"] ?? "").includes("${RunId}")) fail();
  }
  for (const name of ["InitiatorSecurityGroup", "ResponderSecurityGroup"]) {
    const props = object(object(resources[name]).Properties);
    const ingress = props.SecurityGroupIngress;
    if (ingress !== undefined) {
      if (!Array.isArray(ingress)) fail();
      for (const rule of ingress) {
        const source = object(rule).SourceSecurityGroupId;
        if (source?.Ref === "InitiatorSecurityGroup" || source?.Ref === "ResponderSecurityGroup") fail();
      }
    }
    const egress = props.SecurityGroupEgress;
    if (!Array.isArray(egress) || egress.some((rule) => object(rule).DestinationSecurityGroupId?.Ref)) fail();
  }
  for (const name of ["InitiatorPeerA2AIngress", "ResponderPeerA2AIngress", "InitiatorPeerA2AEgress", "ResponderPeerA2AEgress"]) {
    if (!object(resources[name]).Type?.startsWith("AWS::EC2::SecurityGroup")) fail();
  }
  for (const name of ["InitiatorExecutionRole", "ResponderExecutionRole"]) {
    const policies = object(resources[name].Properties).Policies;
    if (!Array.isArray(policies) || policies.length !== 1) fail();
    const statements = object(object(policies[0]).PolicyDocument).Statement;
    if (!Array.isArray(statements)) fail();
    const secretStatement = statements.find((stmt) => Array.isArray(stmt.Action) && stmt.Action.includes("secretsmanager:GetSecretValue"));
    if (!secretStatement || secretStatement.Resource === "*") fail();
  }
  const parameters = object(template.Parameters);
  for (const name of ["VpcId", "PrivateSubnetIds", "Node24ImageDigest", "RunId"]) {
    if (!object(parameters[name])) fail();
  }
}

function validateControls(controls) {
  const item = object(controls);
  if (
    item.liveResourcesCreated !== false ||
    item.deploymentReady !== false ||
    item.imagePurpose !== "pinned-node24-base-fixture" ||
    item.ttlSeconds !== 3600 ||
    item.maxConcurrency !== 2 ||
    typeof item.perRunBudgetUsd !== "string" ||
    !/^[0-9]+(?:\.[0-9]{2})$/.test(item.perRunBudgetUsd) ||
    !Array.isArray(item.requiredCostTags) ||
    item.requiredCostTags.length < 3 ||
    item.cleanupSweeperPlan === null ||
    typeof item.cleanupSweeperPlan !== "object" ||
    item.cleanupSweeperPlan.requiresStoppedEvidence !== true
  ) fail();
  return item;
}

export async function loadFargateDryRunPlan({ root = process.cwd() } = {}) {
  const [templateBytes, initiatorBytes, responderBytes] = await Promise.all([
    readFile(resolve(root, RELATIVE_FILES.template), "utf8"),
    readFile(resolve(root, RELATIVE_FILES.initiator), "utf8"),
    readFile(resolve(root, RELATIVE_FILES.responder), "utf8"),
  ]);
  const template = sanitizeFargateData(parseJsonFile(templateBytes));
  const metadata = object(object(template.Metadata).ClockchainMechanicsProof);
  return {
    schema: FARGATE_DRY_RUN_PLAN_SCHEMA,
    template,
    parties: {
      initiator: normalizeTaskDefinition(sanitizeFargateData(parseJsonFile(initiatorBytes)), "initiator"),
      responder: normalizeTaskDefinition(sanitizeFargateData(parseJsonFile(responderBytes)), "responder"),
    },
    network: {
      assignPublicIp: metadata.assignPublicIp,
      privateSubnetEgressRequirement: metadata.privateSubnetEgressRequirement,
      securityGroups: extractSecurityGroups(template),
    },
    controls: {
      liveResourcesCreated: metadata.liveResourcesCreated,
      deploymentReady: metadata.deploymentReady,
      imagePurpose: metadata.imagePurpose,
      ttlSeconds: metadata.ttlSeconds,
      maxConcurrency: metadata.maxConcurrency,
      perRunBudgetUsd: metadata.perRunBudgetUsd,
      requiredCostTags: metadata.requiredCostTags,
      cleanupSweeperPlan: metadata.cleanupSweeperPlan,
    },
  };
}

export function validateFargateRuntimePlan(plan) {
  const item = object(sanitizeFargateData(plan));
  if (item.schema !== FARGATE_DRY_RUN_PLAN_SCHEMA) fail();
  validateTemplate(item.template);
  const parties = object(item.parties);
  const initiator = validateTaskParty(parties.initiator);
  const responder = validateTaskParty(parties.responder);
  if (
    initiator.taskRoleArn === responder.taskRoleArn ||
    initiator.executionRoleArn === responder.executionRoleArn ||
    initiator.logConfiguration.options["awslogs-group"] === responder.logConfiguration.options["awslogs-group"] ||
    initiator.volumes[0].name === responder.volumes[0].name
  ) fail();
  const initiatorSecrets = new Set(digestRefs(initiator.secrets));
  if (digestRefs(responder.secrets).some((digest) => initiatorSecrets.has(digest))) fail();
  return Object.freeze({
    schema: FARGATE_DRY_RUN_PLAN_SCHEMA,
    template: item.template,
    parties: Object.freeze({
      initiator: Object.freeze({ ...initiator }),
      responder: Object.freeze({ ...responder }),
    }),
    network: Object.freeze(validateNetwork(item.network)),
    controls: Object.freeze(validateControls(item.controls)),
  });
}

export function buildFargateDryRunSummary(plan) {
  const verified = validateFargateRuntimePlan(plan);
  const summary = {
    schema: FARGATE_DRY_RUN_PLAN_SCHEMA,
    liveResourcesCreated: false,
    deploymentReady: false,
    imagePurpose: "pinned-node24-base-fixture",
    roles: ROLES,
    ttlSeconds: verified.controls.ttlSeconds,
    maxConcurrency: verified.controls.maxConcurrency,
    perRunBudgetUsd: verified.controls.perRunBudgetUsd,
    requiredCostTags: Object.freeze([...verified.controls.requiredCostTags]),
    cleanupSweeperPlan: Object.freeze({ ...verified.controls.cleanupSweeperPlan }),
    privateSubnetEgressRequirement: verified.network.privateSubnetEgressRequirement,
    network: Object.freeze({ assignPublicIp: verified.network.assignPublicIp, a2aPort: 8443, ingress: "peer-security-group-only", egress: "peer-a2a-and-private-https-only" }),
    taskDefinitionDigests: Object.freeze(Object.fromEntries(ROLES.map((role) => [
      role,
      sha256Hex(verified.parties[role].taskDefinition),
    ]))),
    images: Object.freeze(Object.fromEntries(ROLES.map((role) => [role, verified.parties[role].imageDigest]))),
    roleArnDigests: Object.freeze(Object.fromEntries(ROLES.map((role) => [role, sha256Hex(verified.parties[role].taskRoleArn)]))),
    executionRoleArnDigests: Object.freeze(Object.fromEntries(ROLES.map((role) => [role, sha256Hex(verified.parties[role].executionRoleArn)]))),
    logGroupDigests: Object.freeze(Object.fromEntries(ROLES.map((role) => [
      role,
      sha256Hex(verified.parties[role].logConfiguration.options["awslogs-group"]),
    ]))),
    secretRefDigests: Object.freeze(Object.fromEntries(ROLES.map((role) => [role, Object.freeze(digestRefs(verified.parties[role].secrets))]))),
  };
  if (/secret-canary|arn:aws:secretsmanager|arn:aws:ssm|cc_[A-Za-z0-9_-]{20,}/i.test(JSON.stringify(summary))) fail();
  return Object.freeze(summary);
}

export function createAwsFargateRuntimeAdapter(optionsInput = {}) {
  const options = object(sanitizeFargateData(optionsInput));
  if (Object.keys(options).some((key) => key !== "plan")) fail();
  const configuredPlan = options.plan ?? null;
  return Object.freeze({
    async inspectRuntimePlan() {
      const current = configuredPlan === null ? await loadFargateDryRunPlan() : configuredPlan;
      return buildFargateDryRunSummary(current);
    },
    async provisionPartyRuntime() {
      fail();
    },
    async attestRuntime() {
      fail();
    },
    async streamRuntimeEvents() {
      return Object.freeze([]);
    },
    async terminateRuntime() {
      fail();
    },
    async destroyRuntime() {
      fail();
    },
    async collectRuntimeEvidence() {
      fail();
    },
  });
}
