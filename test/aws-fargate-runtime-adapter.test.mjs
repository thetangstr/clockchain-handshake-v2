import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";

import {
  buildFargateDryRunSummary,
  createAwsFargateRuntimeAdapter,
  loadFargateDryRunPlan,
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

const execFileAsync = promisify(execFile);
const HEX_A = "a".repeat(64);
const HEX_B = "b".repeat(64);
const SESSION_ID = "11111111-2222-4333-8444-555555555555";

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

function fakeAwsResponses(plan, role) {
  const party = rolePlan(plan, role);
  const account = "123456789012";
  const opposite = role === "initiator" ? "responder" : "initiator";
  const taskRoleName = party.taskRoleArn.split("/").at(-1);
  const taskArn = `arn:aws:ecs:us-west-2:${account}:task/clockchain-mechanics-proof/${role}`;
  const publicLogRecords = [
    {
      schema: "clockchain.fargate-runtime-attestation/v1",
      sessionId: SESSION_ID,
      role,
      workspaceRootDigest: role === "initiator" ? "9".repeat(64) : "0".repeat(64),
      stateRootDigest: role === "initiator" ? "c".repeat(64) : "d".repeat(64),
      signerRootDigest: role === "initiator" ? "e".repeat(64) : "f".repeat(64),
    },
    {
      schema: "clockchain.fargate-in-task-sts/v1",
      sessionId: SESSION_ID,
      role,
      callerIdentity: {
        account,
        arn: `arn:aws:sts::${account}:assumed-role/${taskRoleName}/session`,
        userId: `ARO${role.toUpperCase()}:session`,
      },
    },
    {
      schema: "clockchain.fargate-session-sanitization/v1",
      sessionId: SESSION_ID,
      role,
      privatePathsRedacted: true,
      secretCanariesAbsent: true,
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
        containers: [{ imageDigest: party.imageDigest }],
        attachments: [{
          type: "ElasticNetworkInterface",
          details: [
            { name: "networkInterfaceId", value: `eni-${role}` },
            { name: "subnetId", value: `subnet-private-${role}` },
          ],
        }],
      }],
    },
    taskDefinition: {
      taskDefinition: {
        taskDefinitionArn: `arn:aws:ecs:us-west-2:${account}:task-definition/${role}:1`,
        revision: 1,
        taskRoleArn: party.taskRoleArn,
        executionRoleArn: party.executionRoleArn,
        networkMode: "awsvpc",
        requiresCompatibilities: ["FARGATE"],
        cpu: "512",
        memory: "1024",
        containerDefinitions: [{
          image: party.image,
          readonlyRootFilesystem: true,
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
      { eventName: "StopTask", eventSource: "ecs.amazonaws.com", eventTime: "2026-08-11T12:05:01.000Z", account, taskArn, requestParameters: { startedBy: SESSION_ID } },
    ],
    cloudWatchLogs: [{
      logGroupName: party.logConfiguration.options["awslogs-group"],
      logStreamName: `${role}/session/${SESSION_ID}`,
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
    ["identical secret refs", (copy) => { copy.parties.responder.secrets = clone(copy.parties.initiator.secrets); }],
    ["tag image", (copy) => { copy.parties.initiator.image = "example.test/clockchain:latest"; }],
    ["invalid cpu", (copy) => { copy.parties.initiator.cpu = "999"; }],
    ["invalid memory", (copy) => { copy.parties.initiator.memory = "512"; }],
    ["wrong network mode", (copy) => { copy.parties.initiator.networkMode = "bridge"; }],
    ["shared efs", (copy) => { copy.parties.initiator.volumes.push({ name: "efs", efsVolumeConfiguration: { fileSystemId: "fs-123" } }); }],
    ["shared writable volume", (copy) => { copy.parties.responder.volumes[0].name = copy.parties.initiator.volumes[0].name; }],
    ["privileged", (copy) => { copy.parties.initiator.privileged = true; }],
    ["root user", (copy) => { copy.parties.initiator.user = "0"; }],
    ["raw secret env", (copy) => { copy.parties.initiator.environment.push({ name: "SECRET_VALUE", value: "secret-canary" }); }],
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
    ["sts mismatch", mutate(complete, (copy) => { const record = JSON.parse(copy.cloudWatchLogs[0].events[1].message); record.callerIdentity.arn = "arn:aws:sts::123456789012:assumed-role/other/session"; copy.cloudWatchLogs[0].events[1].message = JSON.stringify(record); })],
    ["sts account mismatch", mutate(complete, (copy) => { const record = JSON.parse(copy.cloudWatchLogs[0].events[1].message); record.callerIdentity.account = "210987654321"; copy.cloudWatchLogs[0].events[1].message = JSON.stringify(record); })],
    ["separate sts claim rejected", mutate(complete, (copy) => { copy.inTaskStsCallerIdentity = { account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/clockchain-mechanics-proof-initiator-task/session", userId: "fake" }; })],
    ["missing runtime attestation", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events = copy.cloudWatchLogs[0].events.filter((event) => !event.message.includes("fargate-runtime-attestation")); })],
    ["attestation role mismatch", mutate(complete, (copy) => { const record = JSON.parse(copy.cloudWatchLogs[0].events[0].message); record.role = "responder"; copy.cloudWatchLogs[0].events[0].message = JSON.stringify(record); })],
    ["separate runtime attestation rejected", mutate(complete, (copy) => { copy.runtimeAttestation = { sessionId: SESSION_ID, role: "initiator", workspaceRootDigest: HEX_A, stateRootDigest: HEX_A, signerRootDigest: HEX_A }; })],
    ["missing sanitization record", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events = copy.cloudWatchLogs[0].events.filter((event) => !event.message.includes("fargate-session-sanitization")); })],
    ["secret canary in logs", mutate(complete, (copy) => { copy.cloudWatchLogs[0].events[0].message = "secret-canary"; })],
    ["described env mismatch", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].environment.push({ name: "EXTRA", value: "unsafe" }); })],
    ["described mount mismatch", mutate(complete, (copy) => { copy.taskDefinition.taskDefinition.containerDefinitions[0].mountPoints[0].readOnly = true; })],
    ["security group peer mismatch", mutate(complete, (copy) => { copy.securityGroups[rolePlan(plan, "initiator").securityGroupId].IpPermissions[0].UserIdGroupPairs[0].GroupId = "sg-other"; })],
    ["security group egress peer missing", mutate(complete, (copy) => { copy.securityGroups[rolePlan(plan, "initiator").securityGroupId].IpPermissionsEgress = []; })],
    ["cloudtrail extra key", mutate(complete, (copy) => { copy.cloudTrailEvents[0].extra = "no"; })],
    ["runtask too late", mutate(complete, (copy) => { copy.cloudTrailEvents[0].eventTime = "2026-08-11T12:01:00.000Z"; })],
    ["stoptask too early", mutate(complete, (copy) => { copy.cloudTrailEvents[1].eventTime = "2026-08-11T12:04:00.000Z"; })],
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

test("Fargate runtime adapter exposes dry-run inspection while rejecting live mutations", async () => {
  const adapter = createAwsFargateRuntimeAdapter({ plan: await checkedPlan() });
  const summary = await adapter.inspectRuntimePlan();
  assert.equal(summary.schema, "clockchain.fargate-dry-run-plan/v1");
  assert.equal(summary.liveResourcesCreated, false);

  await assert.rejects(() => adapter.provisionPartyRuntime({ role: "initiator" }));
  await assert.rejects(() => adapter.terminateRuntime({ runtimeId: "task" }));
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
