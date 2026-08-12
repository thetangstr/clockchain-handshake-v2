import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { assertSecretFree } from "../core/redact.mjs";

export const FARGATE_DRY_RUN_PLAN_SCHEMA = "clockchain.fargate-dry-run-plan/v1";

const ROLES = Object.freeze(["initiator", "responder"]);
const IMAGE = /^.+@sha256:[0-9a-f]{64}$/;
const LONG_SHA = /^sha256:[0-9a-f]{64}$/;
const AWS_ARN = /^arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:.+/;
const SECRET_REF_ARN = /^arn:aws:(?:secretsmanager|ssm):[a-z0-9-]+:[0-9]{12}:(?:secret|parameter)[:/].+/;
const SENSITIVE_ENV = /(?:secret|token|password|private|key|credential)/i;

const RELATIVE_FILES = Object.freeze({
  template: "infra/mechanics-proof/fargate-runtime.yaml",
  initiator: "infra/mechanics-proof/task-definition.initiator.json",
  responder: "infra/mechanics-proof/task-definition.responder.json",
});

function fail() {
  throw new Error("Fargate dry-run validation failed safely.");
}

export function stableJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}

export function sha256Hex(value) {
  return createHash("sha256").update(typeof value === "string" ? value : stableJson(value)).digest("hex");
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

function normalizeTaskDefinition(taskDefinition, role) {
  const task = object(taskDefinition);
  const containers = task.containerDefinitions;
  const volumes = task.volumes;
  if (!Array.isArray(containers) || containers.length !== 1) fail();
  if (!Array.isArray(volumes) || volumes.length !== 1) fail();
  const container = object(containers[0]);
  return {
    role,
    taskDefinition,
    family: string(task.family),
    requiresCompatibilities: task.requiresCompatibilities,
    networkMode: task.networkMode,
    cpu: task.cpu,
    memory: task.memory,
    runtimePlatform: task.runtimePlatform,
    taskRoleArn: task.taskRoleArn,
    executionRoleArn: task.executionRoleArn,
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
    volumes,
    securityGroupId: `sg-${role}`,
  };
}

function validateTaskParty(party) {
  object(party);
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
  if (!Array.isArray(env)) fail();
  for (const entry of env) {
    const item = object(entry);
    if (SENSITIVE_ENV.test(string(item.name))) fail();
    if (typeof item.value !== "string") fail();
    assertSecretFree(item.value, ["secret-canary"]);
  }
  const secrets = party.secrets;
  if (!Array.isArray(secrets) || secrets.length < 3) fail();
  const secretNames = new Set();
  for (const entry of secrets) {
    const item = object(entry);
    if (!SECRET_REF_ARN.test(string(item.valueFrom))) fail();
    if (typeof item.name !== "string" || item.name.length === 0) fail();
    secretNames.add(item.name);
  }
  for (const required of ["CLOCKCHAIN_PROVIDER_REF", "CLOCKCHAIN_MCP_CREDENTIAL_REF", "CLOCKCHAIN_SIGNER_REF"]) {
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
  const template = parseJsonFile(templateBytes);
  const metadata = object(object(template.Metadata).ClockchainMechanicsProof);
  return {
    schema: FARGATE_DRY_RUN_PLAN_SCHEMA,
    template,
    parties: {
      initiator: normalizeTaskDefinition(parseJsonFile(initiatorBytes), "initiator"),
      responder: normalizeTaskDefinition(parseJsonFile(responderBytes), "responder"),
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
  const item = object(plan);
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

export function createAwsFargateRuntimeAdapter({ plan = null } = {}) {
  return Object.freeze({
    async inspectRuntimePlan() {
      const current = plan === null ? await loadFargateDryRunPlan() : plan;
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
