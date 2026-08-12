import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  buildFargateLivePreflightPlan,
  buildFargateDryRunSummary,
  createAwsFargateRuntimeAdapter,
  FARGATE_LIVE_PREFLIGHT_SCHEMA,
  loadFargateDryRunPlan,
  normalizeFargateTaskDefinitionForProof,
  sha256Hex,
  stableJson,
  validateFargateRuntimePlan,
} from "../src/runtime/aws-fargate-runtime-adapter.mjs";
import {
  collectFargateRuntimeEvidence,
  validateFargateRuntimeEvidence,
} from "../src/runtime/aws-fargate-evidence.mjs";
import {
  RUNTIME_EVIDENCE_SCHEMA,
  validateRuntimePairEvidence,
} from "../src/runtime/runtime-adapter-contract.mjs";
import { buildFargateLiveStackPlan } from "../src/runtime/aws-fargate-live-plan.mjs";

const execFileAsync = promisify(execFile);
const HEX_A = "a".repeat(64);
const HEX_B = "b".repeat(64);
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const APP_IMAGE = `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-mechanics-proof@sha256:${"6".repeat(64)}`;
const SOURCE_COMMIT = "1234567890abcdef1234567890abcdef12345678";

test("runtime adapter exposes the live stack planning boundary without enabling mutation", async () => {
  const adapter = createAwsFargateRuntimeAdapter({ plan: await checkedPlan() });
  assert.equal(typeof adapter.inspectLiveStackPlan, "function");
  assert.equal(typeof buildFargateLiveStackPlan, "function");
  assert.equal(typeof adapter.provisionPartyRuntime, "function");
});

test("task-definition proof normalization accepts only the one reviewed workspace initializer", async () => {
  const plan = await buildFargateLiveStackPlan({
    accountId: "123456789012",
    appImage: APP_IMAGE,
    bedrockModelArn: "arn:aws:bedrock:us-west-2:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6",
    budgetUsd: 25,
    codexSecretArn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain/codex-AbCdEf",
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
    region: "us-west-2",
    responderPrivateSubnet: { availabilityZone: "us-west-2b", cidr: "10.44.17.0/24" },
    runId: SESSION_ID,
    startedAt: "2026-08-12T20:00:00.000Z",
    ttlSeconds: 3600,
    vpcId: "vpc-live",
  });
  const stackOutputs = {
    ClusterArn: `arn:aws:ecs:us-west-2:123456789012:cluster/clockchain-${SESSION_ID}`,
    InitiatorExecutionRoleArn: `arn:aws:iam::123456789012:role/cc-${SESSION_ID}-i-exec`,
    InitiatorLogGroupName: `/clockchain/mechanics-proof/${SESSION_ID}/initiator`,
    InitiatorPrivateSubnetId: "subnet-i",
    InitiatorQueueUrl: `https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-${SESSION_ID}-initiator`,
    InitiatorSecurityGroupId: "sg-i",
    InitiatorTaskRoleArn: `arn:aws:iam::123456789012:role/cc-${SESSION_ID}-i-task`,
    ResponderExecutionRoleArn: `arn:aws:iam::123456789012:role/cc-${SESSION_ID}-r-exec`,
    ResponderLogGroupName: `/clockchain/mechanics-proof/${SESSION_ID}/responder`,
    ResponderPrivateSubnetId: "subnet-r",
    ResponderQueueUrl: `https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-${SESSION_ID}-responder`,
    ResponderSecurityGroupId: "sg-r",
    ResponderTaskRoleArn: `arn:aws:iam::123456789012:role/cc-${SESSION_ID}-r-task`,
  };
  const boundLogical = [
    ["Cluster", stackOutputs.ClusterArn.split("/").at(-1), "AWS::ECS::Cluster"],
    ["InitiatorPrivateSubnet", "subnet-i", "AWS::EC2::Subnet"], ["ResponderPrivateSubnet", "subnet-r", "AWS::EC2::Subnet"],
    ["InitiatorSecurityGroup", "sg-i", "AWS::EC2::SecurityGroup"], ["ResponderSecurityGroup", "sg-r", "AWS::EC2::SecurityGroup"],
    ["InitiatorQueue", stackOutputs.InitiatorQueueUrl, "AWS::SQS::Queue"], ["ResponderQueue", stackOutputs.ResponderQueueUrl, "AWS::SQS::Queue"],
    ["InitiatorTaskRole", `cc-${SESSION_ID}-i-task`, "AWS::IAM::Role"], ["ResponderTaskRole", `cc-${SESSION_ID}-r-task`, "AWS::IAM::Role"],
    ["InitiatorExecutionRole", `cc-${SESSION_ID}-i-exec`, "AWS::IAM::Role"], ["ResponderExecutionRole", `cc-${SESSION_ID}-r-exec`, "AWS::IAM::Role"],
    ["InitiatorLogGroup", stackOutputs.InitiatorLogGroupName, "AWS::Logs::LogGroup"], ["ResponderLogGroup", stackOutputs.ResponderLogGroupName, "AWS::Logs::LogGroup"],
  ];
  const bound = new Map(boundLogical.map(([logicalResourceId, physicalResourceId]) => [logicalResourceId, physicalResourceId]));
  const { buildFargateLiveTaskDefinitions } = await import("../src/runtime/aws-fargate-live-plan.mjs");
  const definitions = buildFargateLiveTaskDefinitions({
    stackOutputs,
    stackPlan: plan,
    stackResources: {
      stackId: `arn:aws:cloudformation:us-west-2:123456789012:stack/clockchain-${SESSION_ID}/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee`,
      stackName: `clockchain-${SESSION_ID}`,
      resources: Object.entries(plan.template.Resources).map(([logicalResourceId, resource]) => ({
        logicalResourceId,
        physicalResourceId: bound.get(logicalResourceId) ?? `physical-${logicalResourceId.toLowerCase()}`,
        resourceType: resource.Type,
      })),
    },
  });
  assert.equal(normalizeFargateTaskDefinitionForProof(definitions.initiator, "initiator").containerDefinitions.length, 2);

  for (const mutate of [
    (value) => { value.containerDefinitions.push({ ...value.containerDefinitions[1], name: "other-init" }); },
    (value) => { value.containerDefinitions[1].essential = true; },
    (value) => { value.containerDefinitions[1].secrets = [{ name: "SECRET", valueFrom: "arn:aws:secretsmanager:us-west-2:123456789012:secret:x" }]; },
    (value) => { value.containerDefinitions[0].dependsOn[0].condition = "START"; },
    (value) => { value.volumes[0].efsVolumeConfiguration = { fileSystemId: "fs-shared" }; },
    (value) => { value.volumes[0].host = { sourcePath: "/tmp/shared" }; },
  ]) {
    const changed = clone(definitions.initiator);
    mutate(changed);
    assert.throws(() => normalizeFargateTaskDefinitionForProof(changed, "initiator"), /Fargate dry-run validation failed safely/);
  }
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

async function checkedPlan() {
  return loadFargateDryRunPlan({ root: process.cwd() });
}

function mutate(plan, change) {
  const copy = clone(plan);
  change(copy);
  return copy;
}

function rolePlan(plan, role) {
  return plan.parties[role];
}

function partyEvents(role) {
  const types = role === "initiator"
    ? ["a2a.listener.ready", "agent.starting", "certificate.verified"]
    : ["a2a.listener.ready", "a2a.invitation.received", "agent.starting", "certificate.verified"];
  return types.map((type, index) => ({
    schema: "clockchain.mechanics-proof-party-event/v1",
    runId: SESSION_ID,
    role,
    sequence: String(index + 1),
    type,
    evidenceDigest: sha256Hex({ role, type, index }),
  }));
}

function gitExecutor({ status = "", revParse = `${SOURCE_COMMIT}\n` } = {}, calls = []) {
  return async (command) => {
    calls.push(command);
    if (JSON.stringify(command.args) === JSON.stringify(["status", "--porcelain"])) {
      return { stdout: status, stderr: "", exitCode: 0 };
    }
    return { stdout: revParse, stderr: "", exitCode: 0 };
  };
}

async function fakeGitPath(t) {
  const dir = await mkdtemp(join(tmpdir(), "mechanics-proof-fake-git-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const git = join(dir, "git");
  await writeFile(git, `#!/bin/sh
if [ "$1" = "status" ]; then
  exit 0
fi
if [ "$1" = "rev-parse" ]; then
  printf '%s\\n' '${SOURCE_COMMIT}'
  exit 0
fi
exit 1
`);
  await chmod(git, 0o700);
  return `${dir}:${process.env.PATH ?? ""}`;
}

function fakeAwsResponses(plan, role) {
  const party = rolePlan(plan, role);
  const account = "123456789012";
  const opposite = role === "initiator" ? "responder" : "initiator";
  const taskRoleName = party.taskRoleArn.split("/").at(-1);
  const taskArn = `arn:aws:ecs:us-west-2:${account}:task/clockchain-mechanics-proof/${role}`;
  const attestationCore = {
    schema: "clockchain.mechanics-proof-ecs-attestation-core/v1",
    accountId: account,
    availabilityZone: "us-west-2a",
    containerArn: `arn:aws:ecs:us-west-2:${account}:container/clockchain-mechanics-proof/${role}/container-${role}`,
    family: party.family,
    imageId: party.imageDigest,
    launchType: "FARGATE",
    privateIp: role === "initiator" ? "10.44.16.10" : "10.44.17.10",
    region: "us-west-2",
    revision: "1",
    role,
    stsArn: `arn:aws:sts::${account}:assumed-role/${taskRoleName}/session`,
    stsUserId: `ARO${role.toUpperCase()}:session`,
    taskArn,
    taskId: role,
  };
  const publicLogRecords = [
    {
      ...attestationCore,
      schema: "clockchain.mechanics-proof-ecs-attestation/v1",
      workloadAttestationDigest: sha256Hex(attestationCore),
    },
    ...partyEvents(role),
    {
      schema: "clockchain.mechanics-proof-party-evidence/v1",
      runId: SESSION_ID,
      protocolSessionId: "22222222-3333-4444-8555-666666666666",
      role,
      harness: role === "initiator" ? "codex" : "claude",
      runtimeId: `ecs-${role}`,
      workloadAttestationDigest: sha256Hex(attestationCore),
      peerRuntimeId: `ecs-${opposite}`,
      bridgeEvidenceDigest: HEX_A,
      harnessEvidenceDigest: HEX_B,
      certificateProofDigest: HEX_A,
      certificateDigest: HEX_B,
      resultDigest: HEX_A,
      certificateVerified: true,
      identity: {
        sessionKeyAddress: role === "initiator" ? "0x1111111111111111111111111111111111111111" : "0x2222222222222222222222222222222222222222",
        policyDigest: role === "initiator" ? HEX_A : HEX_B,
        erc8004: {
          agentId: role === "initiator" ? "9452" : "9453",
          chainId: "eip155:11155111",
          registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
          reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${role === "initiator" ? "9452" : "9453"}`,
          registrationTx: "0x" + (role === "initiator" ? "4" : "5").repeat(64),
          registrationBlock: role === "initiator" ? "7000" : "7001",
        },
      },
      a2aCardSignerAddress: role === "initiator" ? "0x1111111111111111111111111111111111111111" : "0x2222222222222222222222222222222222222222",
      anchors: [
        { blockHeight: "7010", digest: HEX_A, kind: "proposal", ledgerId: "33333333-4444-4555-8666-777777777770" },
        { blockHeight: "7011", digest: HEX_B, kind: "acceptance", ledgerId: "33333333-4444-4555-8666-777777777771" },
        { blockHeight: "7012", digest: "e".repeat(64), kind: "acknowledgment", ledgerId: "33333333-4444-4555-8666-777777777772" },
      ],
      directDelivery: { acknowledged: true, artifactDigest: HEX_A, artifactType: role === "initiator" ? "proposal" : "acceptance", checkpointAcknowledged: true, checkpointDigest: HEX_B, messageDigests: [HEX_A, HEX_B] },
      externalBusinessActionPerformed: false,
      terminalStatus: "completed",
      teardown: { completed: true },
    },
  ];
  return {
    describeTasks: {
      tasks: [{
        taskArn,
        taskDefinitionArn: `arn:aws:ecs:us-west-2:${account}:task-definition/${role}:1`,
        lastStatus: "STOPPED",
        createdAt: "2026-08-11T12:00:00.000Z",
        stoppedAt: "2026-08-11T12:05:00.000Z",
        containers: [{ containerArn: attestationCore.containerArn, imageDigest: party.imageDigest }],
        attachments: [{
          type: "ElasticNetworkInterface",
          details: [
            { name: "networkInterfaceId", value: `eni-${role}` },
            { name: "subnetId", value: `subnet-private-${role}` },
            { name: "privateIPv4Address", value: attestationCore.privateIp },
          ],
        }],
      }],
    },
    taskDefinition: {
      taskDefinition: {
        taskDefinitionArn: `arn:aws:ecs:us-west-2:${account}:task-definition/${role}:1`,
        revision: 1,
        family: party.family,
        taskRoleArn: party.taskRoleArn,
        executionRoleArn: party.executionRoleArn,
        networkMode: "awsvpc",
        requiresCompatibilities: ["FARGATE"],
        cpu: "512",
        memory: "1024",
        runtimePlatform: party.runtimePlatform,
        containerDefinitions: [{
          name: role,
          image: party.image,
          essential: true,
          readonlyRootFilesystem: true,
          privileged: false,
          user: party.user,
          logConfiguration: party.logConfiguration,
          mountPoints: party.mountPoints,
          portMappings: [{ containerPort: 8443, protocol: "tcp" }],
          secrets: party.secrets,
          environment: party.environment,
        }],
        volumes: party.volumes,
      },
    },
    networkInterface: {
      NetworkInterfaceId: `eni-${role}`,
      SubnetId: `subnet-private-${role}`,
      VpcId: "vpc-mechanics-proof",
      Groups: [{ GroupId: party.securityGroupId }],
      Association: null,
      PublicIp: null,
    },
    describeSubnet: {
      Subnet: {
        SubnetId: `subnet-private-${role}`,
        VpcId: "vpc-mechanics-proof",
        MapPublicIpOnLaunch: false,
        State: "available",
        AvailableIpAddressCount: 64,
      },
    },
    securityGroups: {
      [party.securityGroupId]: {
        GroupId: party.securityGroupId,
        IpPermissions: [{
          IpProtocol: "tcp",
          FromPort: 8443,
          ToPort: 8443,
          UserIdGroupPairs: [{ GroupId: rolePlan(plan, opposite).securityGroupId }],
        }],
        IpPermissionsEgress: [{
          IpProtocol: "tcp",
          FromPort: 8443,
          ToPort: 8443,
          UserIdGroupPairs: [{ GroupId: rolePlan(plan, opposite).securityGroupId }],
        }],
      },
    },
    cloudTrailEvents: [
      { eventName: "RunTask", eventSource: "ecs.amazonaws.com", eventTime: "2026-08-11T11:59:59.000Z", account, taskArn, requestParameters: { startedBy: SESSION_ID } },
      { eventName: "StopTask", eventSource: "ecs.amazonaws.com", eventTime: "2026-08-11T12:04:59.000Z", account, taskArn, requestParameters: { reason: "clockchain cleanup" } },
    ],
    cloudWatchLogs: [{
      logGroupName: party.logConfiguration.options["awslogs-group"],
      logStreamName: `${role}/${role}/${role}`,
      events: publicLogRecords.map((record, index) => ({
        timestamp: `2026-08-11T12:0${index + 1}:00.000Z`,
        message: JSON.stringify(record),
      })),
    }],
  };
}

test("checked-in Fargate dry-run plan is immutable, isolated, and safe to print", async () => {
  const plan = await checkedPlan();
  const verified = validateFargateRuntimePlan(plan);
  const summary = buildFargateDryRunSummary(verified);

  assert.equal(summary.schema, "clockchain.fargate-dry-run-plan/v1");
  assert.equal(summary.liveResourcesCreated, false);
  assert.equal(summary.deploymentReady, false);
  assert.equal(summary.imagePurpose, "pinned-node24-base-fixture");
  assert.equal(summary.maxConcurrency, 2);
  assert.equal(summary.ttlSeconds, 3600);
  assert.equal(summary.taskDefinitionDigests.initiator.length, 64);
  assert.notEqual(summary.taskDefinitionDigests.initiator, summary.taskDefinitionDigests.responder);
  assert.deepEqual(summary.roles, ["initiator", "responder"]);
  assert.equal(summary.network.assignPublicIp, "DISABLED");
  assert.equal(summary.images.initiator, "sha256:44b49d6e2d23f6754fb084ef9d34ff14590343ad1ee168f8acf8f7bc9fccde2f");
  assert.equal(summary.images.responder, "sha256:44b49d6e2d23f6754fb084ef9d34ff14590343ad1ee168f8acf8f7bc9fccde2f");
  assert.equal(plan.parties.initiator.runtimePlatform.operatingSystemFamily, "LINUX");
  assert.equal(plan.parties.initiator.runtimePlatform.cpuArchitecture, "X86_64");
  assert.notDeepEqual(summary.secretRefDigests.initiator, summary.secretRefDigests.responder);
  assert.ok(summary.cleanupSweeperPlan.requiresStoppedEvidence);
  assert.match(summary.privateSubnetEgressRequirement, /NAT or egress proxy for public Docker Hub, Clockchain MCP, and model provider HTTPS/i);
  assert.match(summary.privateSubnetEgressRequirement, /AWS VPC endpoints may cover CloudWatch Logs, Secrets Manager or SSM, and STS/i);
  assert.match(summary.privateSubnetEgressRequirement, /Phase6.*ECR api\/dkr and S3/i);
  assert.doesNotMatch(summary.privateSubnetEgressRequirement, /NAT or VPC endpoints for ECR.*Clockchain MCP/i);
  assert.equal(summary.network.egress, "peer-a2a-and-private-https-only");
  const resources = plan.template.Resources;
  for (const name of ["InitiatorSecurityGroup", "ResponderSecurityGroup"]) {
    assert.equal(resources[name].Properties.SecurityGroupIngress, undefined);
    assert.equal(resources[name].Properties.SecurityGroupEgress.some((rule) => rule.FromPort === 8443), false);
  }

  const printed = JSON.stringify(summary);
  assert.doesNotMatch(printed, /arn:aws:secretsmanager|arn:aws:ssm|secret-canary|cc_[A-Za-z0-9_-]{20,}/i);
  assert.doesNotMatch(JSON.stringify(plan.template), /Node24RepositoryArn|ecr:/);
});

test("Fargate dry-run validation rejects unsafe task and network mutations", async () => {
  const plan = await checkedPlan();
  const cases = [
    ["same task role", (copy) => { copy.parties.responder.taskRoleArn = copy.parties.initiator.taskRoleArn; }],
    ["missing execution role", (copy) => { delete copy.parties.initiator.executionRoleArn; }],
    ["task role equals execution role", (copy) => { copy.parties.initiator.executionRoleArn = copy.parties.initiator.taskRoleArn; }],
    ["identical secret refs", (copy) => { copy.parties.responder.secrets = clone(copy.parties.initiator.secrets); }],
    ["duplicate secret ref inside party", (copy) => { copy.parties.initiator.secrets[1].valueFrom = copy.parties.initiator.secrets[0].valueFrom; }],
    ["duplicate secret name inside party", (copy) => { copy.parties.initiator.secrets[1].name = copy.parties.initiator.secrets[0].name; }],
    ["missing signer ref", (copy) => { copy.parties.initiator.secrets = copy.parties.initiator.secrets.filter((secret) => secret.name !== "CLOCKCHAIN_SIGNER_REF"); }],
    ["wrong public role env", (copy) => { copy.parties.initiator.environment.find((entry) => entry.name === "CLOCKCHAIN_ROLE").value = "responder"; }],
    ["wrong mcp env", (copy) => { copy.parties.initiator.environment.find((entry) => entry.name === "CLOCKCHAIN_MCP_URL").value = "https://mcp.clockchain.network/mcp"; }],
    ["extra public env", (copy) => { copy.parties.initiator.environment.push({ name: "EXTRA_PUBLIC", value: "public" }); }],
    ["extra mirrored public env", (copy) => {
      const entry = { name: "EXTRA_PUBLIC", value: "public" };
      copy.parties.initiator.environment.push(entry);
      copy.parties.initiator.taskDefinition.containerDefinitions[0].environment.push(entry);
    }],
    ["tag image", (copy) => { copy.parties.initiator.image = "example.test/clockchain:latest"; }],
    ["invalid cpu", (copy) => { copy.parties.initiator.cpu = "999"; }],
    ["invalid memory", (copy) => { copy.parties.initiator.memory = "512"; }],
    ["wrong network mode", (copy) => { copy.parties.initiator.networkMode = "bridge"; }],
    ["shared efs", (copy) => { copy.parties.initiator.volumes.push({ name: "efs", efsVolumeConfiguration: { fileSystemId: "fs-123" } }); }],
    ["shared writable volume", (copy) => { copy.parties.responder.volumes[0].name = copy.parties.initiator.volumes[0].name; }],
    ["privileged", (copy) => { copy.parties.initiator.privileged = true; }],
    ["root user", (copy) => { copy.parties.initiator.user = "0"; }],
    ["raw secret env", (copy) => { copy.parties.initiator.environment.push({ name: "SECRET_VALUE", value: "secret-canary" }); }],
    ["sidecar", (copy) => { copy.parties.initiator.taskDefinition.containerDefinitions.push({ name: "sidecar", image: copy.parties.initiator.image }); }],
    ["repository credentials", (copy) => { copy.parties.initiator.taskDefinition.containerDefinitions[0].repositoryCredentials = { credentialsParameter: "arn:aws:secretsmanager:us-west-2:123456789012:secret:repo" }; }],
    ["environment file", (copy) => { copy.parties.initiator.taskDefinition.containerDefinitions[0].environmentFiles = [{ type: "s3", value: "arn:aws:s3:::bucket/env" }]; }],
    ["extra task authority field", (copy) => { copy.parties.initiator.taskDefinition.proxyConfiguration = { type: "APPMESH" }; }],
    ["broad ingress", (copy) => { copy.network.securityGroups.initiator.ingress[0] = { protocol: "tcp", fromPort: 8443, toPort: 8443, cidrIp: "0.0.0.0/0" }; }],
    ["inline peer ingress circular dependency", (copy) => { copy.template.Resources.InitiatorSecurityGroup.Properties.SecurityGroupIngress = [{ IpProtocol: "tcp", FromPort: 8443, ToPort: 8443, SourceSecurityGroupId: { Ref: "ResponderSecurityGroup" } }]; }],
    ["missing peer rule", (copy) => { copy.network.securityGroups.responder.ingress = []; }],
    ["missing peer egress", (copy) => { copy.network.securityGroups.initiator.egress = copy.network.securityGroups.initiator.egress.filter((rule) => rule.fromPort !== 8443); }],
    ["missing subnet egress docs", (copy) => { copy.network.privateSubnetEgressRequirement = ""; }],
    ["ambiguous subnet egress docs", (copy) => { copy.network.privateSubnetEgressRequirement = "Private subnets require NAT or VPC endpoints for ECR, CloudWatch Logs, Secrets Manager or SSM, STS, CloudTrail, and HTTPS access to the dedicated Clockchain MCP endpoint."; }],
    ["nonblocking logs", (copy) => { copy.parties.initiator.logConfiguration.options.mode = "non-blocking"; }],
    ["same log group", (copy) => { copy.parties.responder.logConfiguration.options["awslogs-group"] = copy.parties.initiator.logConfiguration.options["awslogs-group"]; }],
    ["missing ttl", (copy) => { delete copy.controls.ttlSeconds; }],
    ["wrong max concurrency", (copy) => { copy.controls.maxConcurrency = 3; }],
    ["missing budget", (copy) => { delete copy.controls.perRunBudgetUsd; }],
    ["missing cost tags", (copy) => { copy.controls.requiredCostTags = []; }],
    ["missing cleanup sweeper", (copy) => { delete copy.controls.cleanupSweeperPlan; }],
  ];

  for (const [name, change] of cases) {
    assert.throws(
      () => validateFargateRuntimePlan(mutate(plan, change)),
      /Fargate dry-run validation failed safely/,
      name,
    );
  }
});

test("Fargate runtime evidence is derived from control-plane responses and validates as a pair", async () => {
  const plan = validateFargateRuntimePlan(await checkedPlan());
  const initiator = validateFargateRuntimeEvidence(collectFargateRuntimeEvidence({
    plan,
    sessionId: SESSION_ID,
    role: "initiator",
    aws: fakeAwsResponses(plan, "initiator"),
  }));
  const responder = validateFargateRuntimeEvidence(collectFargateRuntimeEvidence({
    plan,
    sessionId: SESSION_ID,
    role: "responder",
    aws: fakeAwsResponses(plan, "responder"),
  }));

  assert.equal(initiator.schema, RUNTIME_EVIDENCE_SCHEMA);
  assert.equal(initiator.taskStatus, "STOPPED");
  assert.notEqual(initiator.taskRoleArn, responder.taskRoleArn);
  assert.notDeepEqual(initiator.secretArnDigests, responder.secretArnDigests);
  validateRuntimePairEvidence({ initiator, responder });

  const printed = JSON.stringify({ initiator, responder });
  assert.doesNotMatch(printed, /secret-canary|raw-log|arn:aws:secretsmanager|arn:aws:ssm/i);
});

test("Fargate runtime evidence rejects self-claims and missing required control-plane proof", async () => {
  const plan = validateFargateRuntimePlan(await checkedPlan());
  const complete = fakeAwsResponses(plan, "initiator");
  const cases = [
    ["self claim only", { selfClaimedStopped: true, taskRoleArn: rolePlan(plan, "initiator").taskRoleArn }],
    ["missing describe tasks", mutate(complete, (copy) => { delete copy.describeTasks; })],
    ["missing task definition", mutate(complete, (copy) => { delete copy.taskDefinition; })],
    ["missing eni", mutate(complete, (copy) => { delete copy.networkInterface; })],
    ["missing subnet", mutate(complete, (copy) => { delete copy.describeSubnet; })],
    ["subnet id mismatch", mutate(complete, (copy) => { copy.describeSubnet.Subnet.SubnetId = "subnet-other"; })],
    ["subnet vpc mismatch", mutate(complete, (copy) => { copy.describeSubnet.Subnet.VpcId = "vpc-other"; })],
    ["subnet public ip mapping", mutate(complete, (copy) => { copy.describeSubnet.Subnet.MapPublicIpOnLaunch = true; })],
    ["subnet unavailable", mutate(complete, (copy) => { copy.describeSubnet.Subnet.State = "pending"; })],
    ["eni vpc mismatch", mutate(complete, (copy) => { copy.networkInterface.VpcId = "vpc-other"; })],
    ["eni public association", mutate(complete, (copy) => { copy.networkInterface.Association = { PublicIp: "203.0.113.10" }; })],
    ["eni public ip", mutate(complete, (copy) => { copy.networkInterface.PublicIp = "203.0.113.10"; })],
    ["missing security group", mutate(complete, (copy) => { delete copy.securityGroups; })],
    ["missing cloudtrail", mutate(complete, (copy) => { copy.cloudTrailEvents = []; })],
    ["missing exact runtask", mutate(complete, (copy) => { copy.cloudTrailEvents = copy.cloudTrailEvents.filter((event) => event.eventName !== "RunTask"); })],
    ["wrong stoptask task", mutate(complete, (copy) => { copy.cloudTrailEvents.find((event) => event.eventName === "StopTask").taskArn = "arn:aws:ecs:us-west-2:123456789012:task/clockchain-mechanics-proof/other"; })],
    ["missing log digest", mutate(complete, (copy) => { copy.cloudWatchLogs = []; })],
    ["precomputed log digest", mutate(complete, (copy) => { copy.cloudWatchLogs[0] = { logGroupName: "/clockchain/mechanics-proof/initiator", publicEventDigests: [HEX_A] }; })],
    ["wrong log group", mutate(complete, (copy) => { copy.cloudWatchLogs[0].logGroupName = "/clockchain/mechanics-proof/wrong"; })],
    ["wrong log stream", mutate(complete, (copy) => { copy.cloudWatchLogs[0].logStreamName = `wrong/session/${SESSION_ID}`; })],
    ["unknown log schema", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events.push({ timestamp: "2026-08-11T12:04:00.000Z", message: JSON.stringify({ schema: "clockchain.unknown/v1", sessionId: SESSION_ID, role: "initiator" }) }); })],
    ["log accessor extra", mutate(complete, (copy) => { const record = JSON.parse(copy.cloudWatchLogs[0].events[0].message); record.extra = "no"; copy.cloudWatchLogs[0].events[0].message = JSON.stringify(record); })],
    ["log local path", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events[0].message = "/Users/alice/secret"; })],
    ["bad log timestamp", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events[0].timestamp = "not-time"; })],
    ["not stopped", mutate(complete, (copy) => { copy.describeTasks.tasks[0].lastStatus = "RUNNING"; })],
    ["sts mismatch", mutate(complete, (copy) => { const record = JSON.parse(copy.cloudWatchLogs[0].events[0].message); record.stsArn = "arn:aws:sts::123456789012:assumed-role/other/session"; copy.cloudWatchLogs[0].events[0].message = JSON.stringify(record); })],
    ["sts account mismatch", mutate(complete, (copy) => { const record = JSON.parse(copy.cloudWatchLogs[0].events[0].message); record.accountId = "210987654321"; copy.cloudWatchLogs[0].events[0].message = JSON.stringify(record); })],
    ["separate sts claim rejected", mutate(complete, (copy) => { copy.inTaskStsCallerIdentity = { account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/clockchain-mechanics-proof-initiator-task/session", userId: "fake" }; })],
    ["missing runtime attestation", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events = copy.cloudWatchLogs[0].events.filter((event) => !event.message.includes("mechanics-proof-ecs-attestation")); })],
    ["attestation role mismatch", mutate(complete, (copy) => { const record = JSON.parse(copy.cloudWatchLogs[0].events[0].message); record.role = "responder"; copy.cloudWatchLogs[0].events[0].message = JSON.stringify(record); })],
    ["separate runtime attestation rejected", mutate(complete, (copy) => { copy.runtimeAttestation = { sessionId: SESSION_ID, role: "initiator", workspaceRootDigest: HEX_A, stateRootDigest: HEX_A, signerRootDigest: HEX_A }; })],
    ["missing terminal record", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events = copy.cloudWatchLogs[0].events.filter((event) => !event.message.includes("mechanics-proof-party-evidence")); })],
    ["secret canary in logs", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events[0].message = "secret-canary"; })],
    ["described env mismatch", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].environment.push({ name: "EXTRA", value: "unsafe" }); })],
    ["described repository credentials", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].repositoryCredentials = { credentialsParameter: "arn:aws:secretsmanager:us-west-2:123456789012:secret:repo" }; })],
    ["described privileged true", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].privileged = true; })],
    ["described sidecar", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions.push({ image: rolePlan(plan, "initiator").image }); })],
    ["described env file", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].environmentFiles = [{ type: "s3", value: "arn:aws:s3:::bucket/env" }]; })],
    ["described extra secret", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].secrets.push({ name: "EXTRA", valueFrom: rolePlan(plan, "initiator").secrets[0].valueFrom }); })],
    ["described extra volume", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.volumes.push({ name: "extra" }); })],
    ["described mount mismatch", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].mountPoints[0].readOnly = true; })],
    ["security group peer mismatch", mutate(complete, (copy) => { copy.securityGroups[rolePlan(plan, "initiator").securityGroupId].IpPermissions[0].UserIdGroupPairs[0].GroupId = "sg-other"; })],
    ["security group egress peer missing", mutate(complete, (copy) => { copy.securityGroups[rolePlan(plan, "initiator").securityGroupId].IpPermissionsEgress = []; })],
    ["cloudtrail extra key", mutate(complete, (copy) => { copy.cloudTrailEvents[0].extra = "no"; })],
    ["runtask too late", mutate(complete, (copy) => { copy.cloudTrailEvents[0].eventTime = "2026-08-11T12:01:00.000Z"; })],
    ["stoptask before task creation", mutate(complete, (copy) => { copy.cloudTrailEvents[1].eventTime = "2026-08-11T11:59:00.000Z"; })],
    ["stoptask after stopped time", mutate(complete, (copy) => { copy.cloudTrailEvents[1].eventTime = "2026-08-11T12:05:01.000Z"; })],
    ["cross-account task arn", mutate(complete, (copy) => { copy.describeTasks.tasks[0].taskArn = copy.describeTasks.tasks[0].taskArn.replace(":123456789012:", ":210987654321:"); })],
    ["cross-account task definition", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.taskDefinitionArn = copy.taskDefinition.taskDefinition.taskDefinitionArn.replace(":123456789012:", ":210987654321:"); copy.describeTasks.tasks[0].taskDefinitionArn = copy.taskDefinition.taskDefinition.taskDefinitionArn; })],
    ["region mismatch task definition", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.taskDefinitionArn = copy.taskDefinition.taskDefinition.taskDefinitionArn.replace(":us-west-2:", ":us-east-1:"); copy.describeTasks.tasks[0].taskDefinitionArn = copy.taskDefinition.taskDefinition.taskDefinitionArn; })],
    ["secret region mismatch", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].secrets[0].valueFrom = copy.taskDefinition.taskDefinition.containerDefinitions[0].secrets[0].valueFrom.replace(":us-west-2:", ":us-east-1:"); })],
    ["precomputed digests only", {
      describeTasks: complete.describeTasks,
      taskDefinition: complete.taskDefinition,
      networkInterface: complete.networkInterface,
      securityGroups: complete.securityGroups,
      cloudTrailEventDigests: [HEX_A],
      logStreamDigests: [HEX_A],
      cleanupEvidenceDigest: HEX_A,
      sessionSanitizationDigest: HEX_A,
      inTaskStsCallerIdentity: complete.inTaskStsCallerIdentity,
    }],
  ];

  for (const [name, aws] of cases) {
    assert.throws(
      () => collectFargateRuntimeEvidence({ plan, sessionId: SESSION_ID, role: "initiator", aws }),
      /Fargate runtime evidence validation failed safely/,
      name,
    );
  }
});

test("Fargate validators reject hostile inputs before invoking traps or leaking contents", async () => {
  const plan = await checkedPlan();
  let traps = 0;
  const proxy = new Proxy({}, {
    ownKeys() {
      traps += 1;
      return [];
    },
    get() {
      traps += 1;
      return "secret-canary /Users/alice/secret";
    },
  });
  assert.throws(() => validateFargateRuntimePlan(proxy), /Fargate dry-run validation failed safely/);
  assert.equal(traps, 0);
  assert.throws(() => buildFargateDryRunSummary({ ...plan, template: { get Resources() { throw new Error("secret-canary /Users/alice/secret"); } } }), /Fargate dry-run validation failed safely/);
  assert.throws(() => createAwsFargateRuntimeAdapter({ get plan() { throw new Error("secret-canary /Users/alice/secret"); } }), /Fargate dry-run validation failed safely/);
  await assert.rejects(() => loadFargateDryRunPlan(proxy), /Fargate dry-run validation failed safely/);
  assert.equal(traps, 0);
  await assert.rejects(
    () => loadFargateDryRunPlan({ get root() { throw new Error("secret-canary /Users/alice/secret"); } }),
    (error) => {
      assert.match(error.message, /Fargate dry-run validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );

  const aws = fakeAwsResponses(validateFargateRuntimePlan(plan), "initiator");
  const nestedProxy = new Proxy({}, {
    ownKeys() {
      traps += 1;
      return [];
    },
  });
  assert.throws(() => collectFargateRuntimeEvidence({ plan, sessionId: SESSION_ID, role: "initiator", aws: nestedProxy }), /Fargate runtime evidence validation failed safely/);
  assert.equal(traps, 0);
  assert.throws(() => collectFargateRuntimeEvidence({
    plan,
    sessionId: SESSION_ID,
    role: "initiator",
    aws: { ...aws, cloudTrailEvents: [{ get eventName() { throw new Error("secret-canary /Users/alice/secret"); } }] },
  }), /Fargate runtime evidence validation failed safely/);
});

test("Fargate canonical JSON rejects non-data values instead of normalizing them", () => {
  assert.notEqual(sha256Hex([]), sha256Hex({}));
  for (const value of [
    [undefined],
    { fn() {} },
    { symbol: Symbol("x") },
    { value: Number.NaN },
    { value: Number.POSITIVE_INFINITY },
    { get value() { return "secret-canary"; } },
    new Proxy({}, {}),
  ]) {
    assert.throws(() => stableJson(value), /Fargate dry-run validation failed safely/);
    assert.throws(() => sha256Hex(value), /Fargate dry-run validation failed safely/);
  }
});

test("Fargate runtime adapter exposes dry-run inspection while rejecting live mutations", async () => {
  const adapter = createAwsFargateRuntimeAdapter({ plan: await checkedPlan() });
  const summary = await adapter.inspectRuntimePlan();
  assert.equal(summary.schema, "clockchain.fargate-dry-run-plan/v1");
  assert.equal(summary.liveResourcesCreated, false);

  await assert.rejects(() => adapter.provisionPartyRuntime({ role: "initiator" }));
  await assert.rejects(() => adapter.terminateRuntime({ runtimeId: "task" }));
});

test("Fargate live preflight assembles a public preflight plan without mutations", async () => {
  const plan = validateFargateRuntimePlan(await checkedPlan());
  const calls = [];
  const summary = await buildFargateLivePreflightPlan({
    plan,
    pair: "codex:claude",
    directA2A: true,
    mcpUrl: "https://mcp.clockchain.network/handshake/mcp",
    appImage: APP_IMAGE,
    evidenceDir: "/private/tmp/mechanics-proof-evidence",
    runId: "phase6-test-run",
    executor: gitExecutor({}, calls),
  });

  assert.equal(summary.schema, FARGATE_LIVE_PREFLIGHT_SCHEMA);
  assert.equal(summary.liveResourcesCreated, false);
  assert.equal(summary.readyForMutation, false);
  assert.equal(summary.deploymentReady, false);
  assert.equal(summary.appImageShapeValid, true);
  assert.equal(summary.imageProvenanceVerified, false);
  assert.equal(summary.pair, "codex:claude");
  assert.equal(summary.directA2A, true);
  assert.equal(summary.mcpUrl, "https://mcp.clockchain.network/handshake/mcp");
  assert.equal(summary.sourceCommit, SOURCE_COMMIT);
  assert.equal(summary.imagePurpose, "deployment-ready-app-image");
  assert.equal(summary.appImageDigest, `sha256:${"6".repeat(64)}`);
  assert.equal(summary.images.initiator, `sha256:${"6".repeat(64)}`);
  assert.equal(summary.images.responder, `sha256:${"6".repeat(64)}`);
  assert.equal(summary.runtimePrerequisites.assignPublicIp, "DISABLED");
  assert.equal(summary.runtimePrerequisites.privateSubnetNatOrEgressProxyRequired, true);
  assert.equal(summary.runtimePrerequisites.directA2AHttpTransportRequired, true);
  assert.equal(summary.runtimePrerequisites.controllerRoutesRawContent, false);
  assert.equal(summary.runtimePrerequisites.codexAuthSecretProvisionedOutOfBand, true);
  assert.equal(summary.runtimePrerequisites.responderUsesBedrockWorkloadIdentity, true);
  assert.deepEqual(summary.directA2AEvidenceRequired, {
    agentCards: true,
    envelopes: true,
    commitmentCheckpoints: true,
  });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], { cmd: "git", args: ["status", "--porcelain"], timeoutMs: 5000 });
  assert.deepEqual(calls[1], { cmd: "git", args: ["rev-parse", "HEAD"], timeoutMs: 5000 });

  const printed = JSON.stringify(summary);
  assert.doesNotMatch(printed, /arn:aws:secretsmanager|arn:aws:ssm|secret-canary|privateKey|signerSeed|\/Users|\/private\/tmp|cc_[A-Za-z0-9_-]{20,}/i);
});

test("Fargate live preflight accepts only safe explicit evidence directories", async (t) => {
  const plan = await checkedPlan();
  const repoEvidenceDir = `${process.cwd()}/.tmp/mechanics-proof-repo-evidence`;
  const tmpEvidenceDir = "/private/tmp/mechanics-proof-evidence";
  const existingTmpEvidenceDir = "/private/tmp/mechanics-proof-existing-dir";
  const fileEvidenceDir = "/private/tmp/mechanics-proof-file-target";
  const symlinkEvidenceDir = "/private/tmp/mechanics-proof-symlink-target";
  const escapedParent = await mkdtemp(join(tmpdir(), "mechanics-proof-escape-"));
  const link = join(process.cwd(), ".tmp", "mechanics-proof-parent-link");
  t.after(() => rm(link, { force: true }));
  t.after(() => rm(existingTmpEvidenceDir, { recursive: true, force: true }));
  t.after(() => rm(fileEvidenceDir, { force: true }));
  t.after(() => rm(symlinkEvidenceDir, { force: true }));
  t.after(() => rm(escapedParent, { recursive: true, force: true }));
  await mkdir(join(process.cwd(), ".tmp"), { recursive: true });
  await mkdir(existingTmpEvidenceDir, { recursive: true });
  await writeFile(fileEvidenceDir, "not a directory");
  await rm(link, { force: true });
  await rm(symlinkEvidenceDir, { force: true });
  await symlink(escapedParent, link);
  await symlink(escapedParent, symlinkEvidenceDir);

  for (const evidenceDir of [repoEvidenceDir, tmpEvidenceDir, existingTmpEvidenceDir]) {
    const summary = await buildFargateLivePreflightPlan({
      plan,
      pair: "codex:claude",
      directA2A: true,
      mcpUrl: "https://mcp.clockchain.network/handshake/mcp",
      appImage: APP_IMAGE,
      evidenceDir,
      executor: gitExecutor(),
    });
    assert.match(summary.evidenceDirDigest, /^[0-9a-f]{64}$/);
  }

  for (const evidenceDir of [
    "/",
    "/private/tmp",
    process.env.HOME,
    process.cwd(),
    fileEvidenceDir,
    symlinkEvidenceDir,
    `${process.cwd()}/.tmp/../mechanics-proof-traversal`,
    `${process.cwd()}/.tmp/not-proof-evidence`,
    `${link}/mechanics-proof-output`,
    "/Users/alice/mechanics-proof-evidence",
  ]) {
    await assert.rejects(() => buildFargateLivePreflightPlan({
      plan,
      pair: "codex:claude",
      directA2A: true,
      mcpUrl: "https://mcp.clockchain.network/handshake/mcp",
      appImage: APP_IMAGE,
      evidenceDir,
      executor: gitExecutor(),
    }), /Fargate live preflight validation failed safely/);
  }
});

test("Fargate live preflight inspection snapshots public options before proxy or accessor traps", async () => {
  const adapter = createAwsFargateRuntimeAdapter({ plan: await checkedPlan() });
  let traps = 0;
  const proxy = new Proxy({}, {
    ownKeys() {
      traps += 1;
      return [];
    },
    get() {
      traps += 1;
      return "secret-canary /Users/alice/secret";
    },
  });
  await assert.rejects(
    () => adapter.inspectLivePreflight(proxy),
    (error) => {
      assert.match(error.message, /Fargate live preflight validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
  assert.equal(traps, 0);
  await assert.rejects(
    () => adapter.inspectLivePreflight({ get evidenceDir() { throw new Error("secret-canary /Users/alice/secret"); } }),
    (error) => {
      assert.match(error.message, /Fargate live preflight validation failed safely/);
      assert.doesNotMatch(error.message, /secret-canary|\/Users\/alice\/secret/);
      return true;
    },
  );
});

test("Fargate live preflight rejects non-production gates and controller-held signer material", async () => {
  const plan = await checkedPlan();
  const cases = [
    ["wrong pair", { pair: "claude:codex", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: APP_IMAGE, evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, executor: gitExecutor() }],
    ["missing direct a2a", { pair: "codex:claude", directA2A: false, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: APP_IMAGE, evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, executor: gitExecutor() }],
    ["generic mcp", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/mcp", appImage: APP_IMAGE, evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, executor: gitExecutor() }],
    ["tagged image", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: "example.test/clockchain:latest", evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, executor: gitExecutor() }],
    ["node base fixture image", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: "docker.io/library/node:24.11.1-bookworm-slim@sha256:44b49d6e2d23f6754fb084ef9d34ff14590343ad1ee168f8acf8f7bc9fccde2f", evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, executor: gitExecutor() }],
    ["relative evidence dir", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: APP_IMAGE, evidenceDir: "relative", executor: gitExecutor() }],
    ["caller source commit claim", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: APP_IMAGE, evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, sourceCommit: SOURCE_COMMIT, executor: gitExecutor() }],
    ["dirty git status", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: APP_IMAGE, evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, executor: gitExecutor({ status: " M src/file.mjs\n" }) }],
    ["bad git stdout", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: APP_IMAGE, evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, executor: gitExecutor({ revParse: "not-a-sha\n" }) }],
    ["controller signer material", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: APP_IMAGE, evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, signerPrivateKey: "0x1234", executor: gitExecutor() }],
    ["provider secret value", { pair: "codex:claude", directA2A: true, mcpUrl: "https://mcp.clockchain.network/handshake/mcp", appImage: APP_IMAGE, evidenceDir: `${process.cwd()}/.tmp/mechanics-proof-evidence`, providerSecret: "secret-canary", executor: gitExecutor() }],
  ];

  for (const [name, options] of cases) {
    await assert.rejects(
      () => buildFargateLivePreflightPlan({ plan, ...options }),
      /Fargate live preflight validation failed safely/,
      name,
    );
  }
});

test("Fargate runner is dry-run only and emits deterministic public JSON", async () => {
  const { stdout } = await execFileAsync(process.execPath, ["scripts/run-mechanics-proof-fargate.mjs", "--dry-run"], {
    cwd: process.cwd(),
  });
  const output = JSON.parse(stdout);
  assert.equal(output.schema, "clockchain.fargate-dry-run-plan/v1");
  assert.equal(output.liveResourcesCreated, false);
  assert.equal(output.maxConcurrency, 2);
  assert.match(output.taskDefinitionDigests.initiator, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(stdout, /arn:aws:secretsmanager|arn:aws:ssm|secret-canary|raw-log|privateKey|cc_[A-Za-z0-9_-]{20,}/i);

  await assert.rejects(
    () => execFileAsync(process.execPath, ["scripts/run-mechanics-proof-fargate.mjs", "--run"], { cwd: process.cwd() }),
    /Command failed/,
  );
});

test("Fargate runner requires explicit live preflight flags and emits no live mutation", async (t) => {
  const evidenceDir = "/private/tmp/mechanics-proof-evidence";
  const fakePath = await fakeGitPath(t);
  const { stdout } = await execFileAsync(process.execPath, [
    "scripts/run-mechanics-proof-fargate.mjs",
    "--preflight",
    "--pair",
    "codex:claude",
    "--direct-a2a",
    "--evidence-dir",
    evidenceDir,
    "--app-image",
    APP_IMAGE,
  ], { cwd: process.cwd(), env: { ...process.env, PATH: fakePath } });
  const output = JSON.parse(stdout);
  assert.equal(output.schema, FARGATE_LIVE_PREFLIGHT_SCHEMA);
  assert.equal(output.liveResourcesCreated, false);
  assert.equal(output.readyForMutation, false);
  assert.equal(output.deploymentReady, false);
  assert.equal(output.appImageShapeValid, true);
  assert.equal(output.imageProvenanceVerified, false);
  assert.equal(output.sourceCommit.length, 40);
  assert.doesNotMatch(stdout, /RunTask|RegisterTaskDefinition|CreateStack|arn:aws:secretsmanager|arn:aws:ssm|secret-canary|privateKey|\/private\/tmp/i);

  for (const args of [
    ["--preflight", "--pair", "claude:codex", "--direct-a2a", "--evidence-dir", evidenceDir, "--app-image", APP_IMAGE],
    ["--preflight", "--pair", "codex:claude", "--evidence-dir", evidenceDir, "--app-image", APP_IMAGE],
    ["--preflight", "--pair", "codex:claude", "--direct-a2a", "--evidence-dir", "relative", "--app-image", APP_IMAGE],
  ]) {
    await assert.rejects(
      () => execFileAsync(process.execPath, ["scripts/run-mechanics-proof-fargate.mjs", ...args], { cwd: process.cwd(), env: { ...process.env, PATH: fakePath } }),
      /Command failed/,
    );
  }
});
