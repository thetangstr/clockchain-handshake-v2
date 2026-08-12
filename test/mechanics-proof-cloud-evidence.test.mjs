import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  buildMechanicsProofCloudEvidence,
  MECHANICS_PROOF_CLOUD_EVIDENCE_SCHEMA,
} from "../src/testing/mechanics-proof-cloud-evidence.mjs";
import {
  loadFargateDryRunPlan,
  sha256Hex,
  validateFargateRuntimePlan,
} from "../src/runtime/aws-fargate-runtime-adapter.mjs";
import {
  buildFargateLiveStackPlan,
  buildFargateLiveTaskDefinitions,
} from "../src/runtime/aws-fargate-live-plan.mjs";
import { RUNTIME_EVIDENCE_SCHEMA } from "../src/runtime/runtime-adapter-contract.mjs";
import {
  collectFargateCloudProofInputs,
  collectFargateCleanupProofInputs,
  collectFargateLiveInfraProofInputs,
  collectFargateRuntimeProofInputs,
  buildFargatePublicProofEvidence,
  retainFargateSuccessEvidence,
} from "../scripts/run-mechanics-proof-fargate.mjs";

const RUN_ID = "11111111-2222-4333-8444-555555555555";
const SESSION_ID = "22222222-3333-4444-8555-666666666666";
const IMAGE_DIGEST = `sha256:${"6".repeat(64)}`;
const CERTIFICATE_DIGEST = "a".repeat(64);
const RESULT_DIGEST = "b".repeat(64);
const DIGEST = "c".repeat(64);
const OTHER_DIGEST = "d".repeat(64);
const THIRD_DIGEST = "e".repeat(64);

function runtimeEvidence(role, overrides = {}) {
  const account = "123456789012";
  return {
    schema: RUNTIME_EVIDENCE_SCHEMA,
    runtimeId: `fargate:${RUN_ID}:${role}`,
    role,
    taskArn: `arn:aws:ecs:us-west-2:${account}:task/clockchain-${RUN_ID}/${role}`,
    taskStatus: "STOPPED",
    createdAtMs: 1786337000000,
    stoppedAtMs: 1786337300000,
    taskRoleArn: `arn:aws:iam::${account}:role/clockchain-${RUN_ID}-${role}-task`,
    executionRoleArn: `arn:aws:iam::${account}:role/clockchain-${RUN_ID}-${role}-execution`,
    inTaskStsCallerIdentity: {
      account,
      arn: `arn:aws:sts::${account}:assumed-role/clockchain-${RUN_ID}-${role}-task/session`,
      userId: `ARO${role.toUpperCase()}:session`,
    },
    imageDigest: IMAGE_DIGEST,
    taskDefinitionArn: `arn:aws:ecs:us-west-2:${account}:task-definition/clockchain-${RUN_ID}-${role}:1`,
    taskDefinitionRevision: "1",
    taskDefinitionDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
    eniId: `eni-${role}`,
    subnetId: `subnet-${role}`,
    securityGroupIds: [`sg-${role}`],
    writableVolumeSummary: { ephemeral: true, sharedWritable: false },
    sharedEfsMounts: [],
    secretArnDigests: [role === "initiator" ? DIGEST : OTHER_DIGEST],
    credentialRefDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
    workspaceRootDigest: role === "initiator" ? "1".repeat(64) : "2".repeat(64),
    stateRootDigest: role === "initiator" ? "3".repeat(64) : "4".repeat(64),
    signerRootDigest: role === "initiator" ? "5".repeat(64) : "7".repeat(64),
    logStreamDigests: [role === "initiator" ? "8".repeat(64) : "9".repeat(64)],
    cloudTrailEventDigests: [role === "initiator" ? "0".repeat(64) : "1".repeat(64), role === "initiator" ? "2".repeat(64) : "3".repeat(64)],
    ecsDescribeTasksDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    cleanupEvidenceDigest: role === "initiator" ? "6".repeat(64) : "7".repeat(64),
    sessionSanitizationDigest: role === "initiator" ? "8".repeat(64) : "9".repeat(64),
    ...overrides,
  };
}

async function checkedPlan() {
  return validateFargateRuntimePlan(await loadFargateDryRunPlan({ root: process.cwd() }));
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
  const taskDefinitionArn = `arn:aws:ecs:us-west-2:${account}:task-definition/clockchain-${RUN_ID}-${role}:1`;
  const taskId = role;
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
    taskId,
  };
  const publicLogRecords = [
    {
      ...attestationCore,
      schema: "clockchain.mechanics-proof-ecs-attestation/v1",
      workloadAttestationDigest: sha256Hex(attestationCore),
    },
    ...partyEvents(role),
    terminal(role),
  ];
  return {
    describeTasks: {
      tasks: [{
        taskArn,
        taskDefinitionArn,
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
        taskDefinitionArn,
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
      PrivateIpAddresses: [{ PrivateIpAddress: attestationCore.privateIp, Primary: true }],
      Ipv6Addresses: [],
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
      { eventName: "RunTask", eventSource: "ecs.amazonaws.com", eventTime: "2026-08-11T11:59:59.000Z", account, taskArn, requestParameters: { startedBy: RUN_ID } },
      { eventName: "StopTask", eventSource: "ecs.amazonaws.com", eventTime: "2026-08-11T12:04:59.000Z", account, taskArn, requestParameters: { reason: "clockchain cleanup" } },
    ],
    cloudWatchLogs: [{
      logGroupName: party.logConfiguration.options["awslogs-group"],
      logStreamName: `${role}/${role}/${role}`,
      events: publicLogRecords.map((record, index) => ({
        timestamp: 1786449660000 + index * 60_000,
        message: JSON.stringify(record),
      })),
    }],
  };
}

function partyEvents(role) {
  const types = role === "initiator"
    ? ["a2a.listener.ready", "agent.starting", "certificate.verified"]
    : ["a2a.listener.ready", "a2a.invitation.received", "agent.starting", "certificate.verified"];
  return types.map((type, index) => ({
    schema: "clockchain.mechanics-proof-party-event/v1",
    runId: RUN_ID,
    role,
    sequence: String(index + 1),
    type,
    evidenceDigest: sha256Hex({ role, type, index }),
  }));
}

function terminal(role, overrides = {}) {
  const peer = role === "initiator" ? "responder" : "initiator";
  return {
    schema: "clockchain.mechanics-proof-party-evidence/v1",
    runId: RUN_ID,
    protocolSessionId: SESSION_ID,
    role,
    harness: role === "initiator" ? "codex" : "claude",
    runtimeId: `ecs-${role}`,
    workloadAttestationDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
    peerRuntimeId: `ecs-${peer}`,
    bridgeEvidenceDigest: role === "initiator" ? "0".repeat(64) : "1".repeat(64),
    harnessEvidenceDigest: role === "initiator" ? "2".repeat(64) : "3".repeat(64),
    certificateProofDigest: role === "initiator" ? "4".repeat(64) : "5".repeat(64),
    certificateDigest: CERTIFICATE_DIGEST,
    resultDigest: RESULT_DIGEST,
    certificateVerified: true,
    identity: {
      sessionKeyAddress: role === "initiator"
        ? "0x1111111111111111111111111111111111111111"
        : "0x2222222222222222222222222222222222222222",
      policyDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
      erc8004: {
        agentId: role === "initiator" ? "9452" : "9453",
        chainId: "eip155:11155111",
        registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${role === "initiator" ? "9452" : "9453"}`,
        registrationTx: role === "initiator" ? "0x" + "4".repeat(64) : "0x" + "5".repeat(64),
        registrationBlock: role === "initiator" ? "7000" : "7001",
      },
    },
    a2aCardSignerAddress: role === "initiator"
      ? "0x1111111111111111111111111111111111111111"
      : "0x2222222222222222222222222222222222222222",
    anchors: [
      { blockHeight: "7010", digest: DIGEST, kind: "proposal", ledgerId: "33333333-4444-4555-8666-777777777770" },
      { blockHeight: "7011", digest: OTHER_DIGEST, kind: "acceptance", ledgerId: "33333333-4444-4555-8666-777777777771" },
      { blockHeight: "7012", digest: THIRD_DIGEST, kind: "acknowledgment", ledgerId: "33333333-4444-4555-8666-777777777772" },
    ],
    directDelivery: {
      acknowledged: true,
      artifactDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
      artifactType: role === "initiator" ? "proposal" : "acceptance",
      checkpointAcknowledged: true,
      checkpointDigest: role === "initiator" ? OTHER_DIGEST : THIRD_DIGEST,
      messageDigests: role === "initiator" ? [DIGEST, OTHER_DIGEST] : [OTHER_DIGEST, THIRD_DIGEST],
    },
    externalBusinessActionPerformed: false,
    terminalStatus: "completed",
    teardown: { completed: true },
    ...overrides,
  };
}

async function cloudInput(overrides = {}) {
  const plan = await checkedPlan();
  return {
    runId: RUN_ID,
    imageDigest: plan.parties.initiator.imageDigest,
    runtimeInputs: {
      initiator: { plan, sessionId: RUN_ID, role: "initiator", aws: fakeAwsResponses(plan, "initiator") },
      responder: { plan, sessionId: RUN_ID, role: "responder", aws: fakeAwsResponses(plan, "responder") },
    },
    cleanupResponses: {
      targets: {
        stackName: `clockchain-${RUN_ID}`,
        queueUrls: {
          initiator: `https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-${RUN_ID}-initiator`,
          responder: `https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-${RUN_ID}-responder`,
        },
        taskDefinitionFamilies: {
          initiator: `clockchain-${RUN_ID}-initiator`,
          responder: `clockchain-${RUN_ID}-responder`,
        },
        taskDefinitionArns: {
          initiator: `arn:aws:ecs:us-west-2:123456789012:task-definition/clockchain-${RUN_ID}-initiator:1`,
          responder: `arn:aws:ecs:us-west-2:123456789012:task-definition/clockchain-${RUN_ID}-responder:1`,
        },
        taskArns: {
          initiator: `arn:aws:ecs:us-west-2:123456789012:task/clockchain-mechanics-proof/initiator`,
          responder: `arn:aws:ecs:us-west-2:123456789012:task/clockchain-mechanics-proof/responder`,
        },
      },
      confirmAbsence: { absent: true },
      listQueues: {},
      listActiveTaskDefinitions: { taskDefinitionArns: [] },
      listInactiveTaskDefinitions: {
        taskDefinitionArns: [
          `arn:aws:ecs:us-west-2:123456789012:task-definition/clockchain-${RUN_ID}-initiator:1`,
          `arn:aws:ecs:us-west-2:123456789012:task-definition/clockchain-${RUN_ID}-responder:1`,
        ],
      },
      stoppedTasks: {
        initiator: { taskArn: `arn:aws:ecs:us-west-2:123456789012:task/clockchain-mechanics-proof/initiator`, lastStatus: "STOPPED" },
        responder: { taskArn: `arn:aws:ecs:us-west-2:123456789012:task/clockchain-mechanics-proof/responder`, lastStatus: "STOPPED" },
      },
    },
    rawControlPlaneEnvelopes: [
      { service: "ecs", operation: "DescribeTasks", role: "initiator", response: { taskArn: "redacted" } },
      { service: "ecs", operation: "DescribeTaskDefinition", role: "responder", response: { family: "redacted" } },
    ],
    ...overrides,
  };
}

function withTerminalChange(input, role, change) {
  const copy = JSON.parse(JSON.stringify(input));
  const events = copy.runtimeInputs[role].aws.cloudWatchLogs[0].events;
  const index = events.findIndex((event) => event.message.includes("clockchain.mechanics-proof-party-evidence/v1"));
  assert.notEqual(index, -1);
  const record = JSON.parse(events[index].message);
  change(record);
  events[index].message = JSON.stringify(record);
  return copy;
}

function withDuplicateTerminal(input, role) {
  const copy = JSON.parse(JSON.stringify(input));
  const events = copy.runtimeInputs[role].aws.cloudWatchLogs[0].events;
  const terminalEvent = events.find((event) => event.message.includes("clockchain.mechanics-proof-party-evidence/v1"));
  events.push({ ...terminalEvent, timestamp: "2026-08-11T12:05:00.000Z" });
  return copy;
}

function liveInputs() {
  return {
    accountId: "123456789012",
    appImage: `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-mechanics-proof@${IMAGE_DIGEST}`,
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
    runId: RUN_ID,
    startedAt: "2026-08-12T20:00:00.000Z",
    ttlSeconds: 3600,
    vpcId: "vpc-live",
  };
}

function liveOutputs() {
  return {
    ClusterArn: `arn:aws:ecs:us-west-2:123456789012:cluster/clockchain-${RUN_ID}`,
    InitiatorExecutionRoleArn: `arn:aws:iam::123456789012:role/cc-${RUN_ID}-i-exec`,
    InitiatorLogGroupName: `/clockchain/mechanics-proof/${RUN_ID}/initiator`,
    InitiatorPrivateSubnetId: "subnet-private-initiator",
    InitiatorQueueUrl: `https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-${RUN_ID}-initiator`,
    InitiatorSecurityGroupId: "sg-initiator",
    InitiatorTaskRoleArn: `arn:aws:iam::123456789012:role/cc-${RUN_ID}-i-task`,
    ResponderExecutionRoleArn: `arn:aws:iam::123456789012:role/cc-${RUN_ID}-r-exec`,
    ResponderLogGroupName: `/clockchain/mechanics-proof/${RUN_ID}/responder`,
    ResponderPrivateSubnetId: "subnet-private-responder",
    ResponderQueueUrl: `https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-${RUN_ID}-responder`,
    ResponderSecurityGroupId: "sg-responder",
    ResponderTaskRoleArn: `arn:aws:iam::123456789012:role/cc-${RUN_ID}-r-task`,
  };
}

function liveResources(plan, outputs) {
  const physical = new Map([
    ["Cluster", outputs.ClusterArn],
    ["InitiatorPrivateSubnet", outputs.InitiatorPrivateSubnetId],
    ["ResponderPrivateSubnet", outputs.ResponderPrivateSubnetId],
    ["InitiatorSecurityGroup", outputs.InitiatorSecurityGroupId],
    ["ResponderSecurityGroup", outputs.ResponderSecurityGroupId],
    ["InitiatorQueue", outputs.InitiatorQueueUrl],
    ["ResponderQueue", outputs.ResponderQueueUrl],
    ["InitiatorTaskRole", outputs.InitiatorTaskRoleArn.split("/").at(-1)],
    ["ResponderTaskRole", outputs.ResponderTaskRoleArn.split("/").at(-1)],
    ["InitiatorExecutionRole", outputs.InitiatorExecutionRoleArn.split("/").at(-1)],
    ["ResponderExecutionRole", outputs.ResponderExecutionRoleArn.split("/").at(-1)],
    ["InitiatorLogGroup", outputs.InitiatorLogGroupName],
    ["ResponderLogGroup", outputs.ResponderLogGroupName],
  ]);
  return {
    stackId: `arn:aws:cloudformation:us-west-2:123456789012:stack/clockchain-${RUN_ID}/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee`,
    stackName: `clockchain-${RUN_ID}`,
    resources: Object.entries(plan.template.Resources).map(([logicalResourceId, resource]) => ({
      logicalResourceId,
      physicalResourceId: physical.get(logicalResourceId) ?? `physical-${logicalResourceId}`,
      resourceType: resource.Type,
    })),
  };
}

function planFromLiveDefinitions(definitions, outputs) {
  const party = (role, definition, securityGroupId) => {
    const container = definition.containerDefinitions[0];
    return {
      role,
      taskDefinition: definition,
      family: definition.family,
      requiresCompatibilities: definition.requiresCompatibilities,
      networkMode: definition.networkMode,
      cpu: definition.cpu,
      memory: definition.memory,
      runtimePlatform: definition.runtimePlatform,
      taskRoleArn: definition.taskRoleArn,
      executionRoleArn: definition.executionRoleArn,
      image: container.image,
      imageDigest: container.image.split("@").at(-1),
      user: container.user,
      readonlyRootFilesystem: container.readonlyRootFilesystem,
      privileged: container.privileged,
      portMappings: container.portMappings,
      environment: container.environment,
      secrets: container.secrets,
      mountPoints: container.mountPoints,
      logConfiguration: container.logConfiguration,
      volumes: definition.volumes,
      securityGroupId,
    };
  };
  return {
    schema: "clockchain.fargate-runtime-proof-plan/v1",
    parties: {
      initiator: party("initiator", definitions.initiator, outputs.InitiatorSecurityGroupId),
      responder: party("responder", definitions.responder, outputs.ResponderSecurityGroupId),
    },
  };
}

test("cloud evidence accepts only corroborated runtime and protocol facts", async () => {
  const input = await cloudInput();
  const evidence = buildMechanicsProofCloudEvidence(input);

  assert.equal(evidence.schema, MECHANICS_PROOF_CLOUD_EVIDENCE_SCHEMA);
  assert.equal(evidence.runId, RUN_ID);
  assert.equal(evidence.protocolSessionId, SESSION_ID);
  assert.equal(evidence.imageDigest, input.imageDigest);
  assert.equal(evidence.certificateDigest, CERTIFICATE_DIGEST);
  assert.equal(evidence.resultDigest, RESULT_DIGEST);
  assert.equal(evidence.certificateVerified, true);
  assert.equal(evidence.externalBusinessActionPerformed, false);
  assert.deepEqual(evidence.receiptIds, [
    "33333333-4444-4555-8666-777777777770",
    "33333333-4444-4555-8666-777777777771",
    "33333333-4444-4555-8666-777777777772",
  ]);
  assert.equal(evidence.bootstrapPublicationAuthority, "SQS publication authenticated by task-role IAM and message binding; exchanged public keys verify later signed A2A envelopes.");
  assert.equal(evidence.privateProtocolTransport, "Private workflow content used direct peer HTTPS; SQS carried only public bootstrap descriptors.");
  assert.notEqual(evidence.parties.initiator.taskArn, evidence.parties.responder.taskArn);
  assert.notEqual(evidence.parties.initiator.taskRoleArn, evidence.parties.responder.taskRoleArn);
  assert.notEqual(evidence.parties.initiator.executionRoleArn, evidence.parties.responder.executionRoleArn);
  assert.notEqual(evidence.parties.initiator.eniId, evidence.parties.responder.eniId);
  assert.notEqual(evidence.parties.initiator.securityGroupIds[0], evidence.parties.responder.securityGroupIds[0]);
  assert.notEqual(evidence.parties.initiator.signerAddress, evidence.parties.responder.signerAddress);
  assert.equal(evidence.parties.initiator.a2aCardSignerAddress, evidence.parties.initiator.signerAddress);
  assert.notEqual(evidence.parties.initiator.a2aCardSignerAddress, evidence.parties.responder.a2aCardSignerAddress);
  assert.notEqual(evidence.parties.initiator.erc8004AgentId, evidence.parties.responder.erc8004AgentId);
  assert.match(evidence.rawControlPlaneEnvelopeDigests[0], /^[0-9a-f]{64}$/);

  const printed = JSON.stringify(evidence);
  assert.doesNotMatch(printed, /raw-log|secret-canary|\/Users|\/private\/tmp|modelProse|descriptorSignature/i);
});

test("cloud evidence accepts live stack plan task definitions and responder zero-secret isolation", async () => {
  const stackPlan = await buildFargateLiveStackPlan(liveInputs());
  const outputs = liveOutputs();
  const definitions = buildFargateLiveTaskDefinitions({
    stackPlan,
    stackOutputs: outputs,
    stackResources: liveResources(stackPlan, outputs),
  });
  assert.equal(definitions.initiator.containerDefinitions[0].secrets.length, 1);
  assert.equal(definitions.responder.containerDefinitions[0].secrets.length, 0);
  assert.equal(definitions.initiator.containerDefinitions[0].stopTimeout, 30);
  assert.equal(definitions.responder.containerDefinitions[0].stopTimeout, 30);

  const proofPlan = planFromLiveDefinitions(definitions, outputs);
  const runtimeInputs = {
    initiator: { plan: proofPlan, sessionId: RUN_ID, role: "initiator", aws: fakeAwsResponses(proofPlan, "initiator") },
    responder: { plan: proofPlan, sessionId: RUN_ID, role: "responder", aws: fakeAwsResponses(proofPlan, "responder") },
  };
  runtimeInputs.initiator.aws.taskDefinition.taskDefinition.containerDefinitions = definitions.initiator.containerDefinitions;
  runtimeInputs.initiator.aws.taskDefinition.taskDefinition.taskRoleArn = definitions.initiator.taskRoleArn;
  runtimeInputs.initiator.aws.taskDefinition.taskDefinition.executionRoleArn = definitions.initiator.executionRoleArn;
  runtimeInputs.initiator.aws.taskDefinition.taskDefinition.family = definitions.initiator.family;
  runtimeInputs.responder.aws.taskDefinition.taskDefinition.containerDefinitions = definitions.responder.containerDefinitions;
  runtimeInputs.responder.aws.taskDefinition.taskDefinition.taskRoleArn = definitions.responder.taskRoleArn;
  runtimeInputs.responder.aws.taskDefinition.taskDefinition.executionRoleArn = definitions.responder.executionRoleArn;
  runtimeInputs.responder.aws.taskDefinition.taskDefinition.family = definitions.responder.family;

  const evidence = buildMechanicsProofCloudEvidence({
    ...(await cloudInput({ runtimeInputs, imageDigest: IMAGE_DIGEST })),
  });
  assert.equal(evidence.imageDigest, IMAGE_DIGEST);
  assert.notEqual(evidence.parties.initiator.taskRoleArn, evidence.parties.responder.taskRoleArn);
  assert.notEqual(evidence.parties.initiator.writableRootBindingDigest, evidence.parties.responder.writableRootBindingDigest);
  assert.equal("writableRootDigest" in evidence.parties.initiator, false);
  assert.equal("sessionSanitizationDigest" in evidence.parties.initiator, false);
  assert.match(evidence.parties.responder.ephemeralSessionTeardownDigest, /^[0-9a-f]{64}$/);
});

test("cloud evidence rejects model prose, forged runtime claims, missing cleanup, and protocol drift", async () => {
  const base = await cloudInput();
  const cases = [
    ["model prose", { ...base, modelProse: "The run succeeded." }],
    ["forged runtime evidence", { ...base, runtimes: { initiator: runtimeEvidence("initiator"), responder: runtimeEvidence("responder") } }],
    ["shared task role", {
      ...base,
      runtimeInputs: { ...base.runtimeInputs, responder: { ...base.runtimeInputs.responder, aws: { ...base.runtimeInputs.responder.aws, taskDefinition: { taskDefinition: { ...base.runtimeInputs.responder.aws.taskDefinition.taskDefinition, taskRoleArn: base.runtimeInputs.initiator.aws.taskDefinition.taskDefinition.taskRoleArn } } } } },
    }],
    ["shared execution role", {
      ...base,
      runtimeInputs: { ...base.runtimeInputs, responder: { ...base.runtimeInputs.responder, aws: { ...base.runtimeInputs.responder.aws, taskDefinition: { taskDefinition: { ...base.runtimeInputs.responder.aws.taskDefinition.taskDefinition, executionRoleArn: base.runtimeInputs.initiator.aws.taskDefinition.taskDefinition.executionRoleArn } } } } },
    }],
    ["shared eni", {
      ...base,
      runtimeInputs: { ...base.runtimeInputs, responder: { ...base.runtimeInputs.responder, aws: { ...base.runtimeInputs.responder.aws, networkInterface: { ...base.runtimeInputs.responder.aws.networkInterface, NetworkInterfaceId: "eni-initiator" } } } },
    }],
    ["shared sg", {
      ...base,
      runtimeInputs: { ...base.runtimeInputs, responder: { ...base.runtimeInputs.responder, aws: { ...base.runtimeInputs.responder.aws, networkInterface: { ...base.runtimeInputs.responder.aws.networkInterface, Groups: [{ GroupId: rolePlan(base.runtimeInputs.initiator.plan, "initiator").securityGroupId }] } } } },
    }],
    ["mismatched image", {
      ...base,
      imageDigest: `sha256:${"7".repeat(64)}`,
    }],
    ["shared writable root", {
      ...base,
      runtimeInputs: { ...base.runtimeInputs, responder: { ...base.runtimeInputs.responder, aws: { ...base.runtimeInputs.responder.aws, cloudWatchLogs: [{ ...base.runtimeInputs.responder.aws.cloudWatchLogs[0], events: base.runtimeInputs.responder.aws.cloudWatchLogs[0].events.map((event, index) => index === 0 ? { ...event, message: JSON.stringify({ ...JSON.parse(event.message), workspaceRootDigest: "9".repeat(64) }) } : event) }] } } },
    }],
    ["missing cloudtrail stop", {
      ...base,
      runtimeInputs: { ...base.runtimeInputs, initiator: { ...base.runtimeInputs.initiator, aws: { ...base.runtimeInputs.initiator.aws, cloudTrailEvents: base.runtimeInputs.initiator.aws.cloudTrailEvents.filter((event) => event.eventName !== "StopTask") } } },
    }],
    ["missing queue cleanup", { ...base, cleanupResponses: { ...base.cleanupResponses, listQueues: { QueueUrls: [base.cleanupResponses.targets.queueUrls.initiator] } } }],
    ["missing checkpoint ack", withTerminalChange(base, "responder", (record) => { record.directDelivery.checkpointAcknowledged = false; })],
    ["unverified certificate", withTerminalChange(base, "initiator", (record) => { record.certificateVerified = false; })],
    ["external action", withTerminalChange(base, "responder", (record) => { record.externalBusinessActionPerformed = true; })],
    ["shared signer address", withTerminalChange(base, "responder", (record) => { record.identity.sessionKeyAddress = terminal("initiator").identity.sessionKeyAddress; })],
    ["card signer mismatch", withTerminalChange(base, "responder", (record) => { record.a2aCardSignerAddress = terminal("initiator").a2aCardSignerAddress; })],
    ["shared erc8004 id", withTerminalChange(base, "responder", (record) => {
      record.identity.erc8004.agentId = terminal("initiator").identity.erc8004.agentId;
      record.identity.erc8004.reference = terminal("initiator").identity.erc8004.reference;
    })],
    ["separate protocol input", { ...base, protocol: { initiator: terminal("initiator"), responder: terminal("responder") } }],
    ["duplicate terminal record", withDuplicateTerminal(base, "initiator")],
    ["descriptor signature wording", {
      ...base,
      bootstrapPublicationAuthority: "SQS publication authenticated by a detached descriptor signature.",
    }],
  ];

  for (const [name, input] of cases) {
    assert.throws(
      () => buildMechanicsProofCloudEvidence(input),
      /Mechanics proof cloud evidence validation failed safely/,
      name,
    );
  }
});

test("runner retains only canonical public cloud proof after reducer validation", async () => {
  const root = await mkdtemp(join(tmpdir(), "mechanics-proof-cloud-"));
  const dir = join(root, "mechanics-proof-public-proof");
  const proof = buildFargatePublicProofEvidence(await cloudInput());
  await retainFargateSuccessEvidence(dir, {
    controllerEvidence: { schema: "clockchain.fargate-live-controller-evidence/v1" },
    publicProof: proof,
  });
  const retained = JSON.parse(await readFile(join(dir, "public-proof.json"), "utf8"));

  assert.equal(retained.schema, MECHANICS_PROOF_CLOUD_EVIDENCE_SCHEMA);
  assert.deepEqual(retained, JSON.parse(JSON.stringify(proof)));
  assert.equal("protocol" in retained, false);
  assert.equal("runtimeInputs" in retained, false);
  assert.equal("rawControlPlaneEnvelopes" in retained, false);
  assert.doesNotMatch(JSON.stringify(retained), /secret-canary|\/private\/tmp|raw-log|modelProse/i);
});

test("runner collector gathers exact raw proof inputs before cleanup and raw absence after cleanup", async () => {
  const base = await cloudInput();
  const calls = [];
  const controlPlane = {
    async describeTasks({ taskArns }) {
      calls.push(["describeTasks", taskArns]);
      return base.runtimeInputs.initiator.aws.describeTasks.tasks[0].taskArn === taskArns[0]
        ? base.runtimeInputs.initiator.aws.describeTasks
        : base.runtimeInputs.responder.aws.describeTasks;
    },
    async describeTaskDefinition({ taskDefinitionArn }) {
      calls.push(["describeTaskDefinition", taskDefinitionArn]);
      return taskDefinitionArn.includes("initiator:1")
        ? base.runtimeInputs.initiator.aws.taskDefinition
        : base.runtimeInputs.responder.aws.taskDefinition;
    },
    async describeNetworkInterfaces({ networkInterfaceIds }) {
      calls.push(["describeNetworkInterfaces", networkInterfaceIds]);
      return { NetworkInterfaces: [networkInterfaceIds.includes("eni-initiator") ? base.runtimeInputs.initiator.aws.networkInterface : base.runtimeInputs.responder.aws.networkInterface] };
    },
    async describeSubnetsByIds({ subnetIds }) {
      calls.push(["describeSubnetsByIds", subnetIds]);
      return subnetIds.includes("subnet-private-initiator")
        ? { Subnets: [base.runtimeInputs.initiator.aws.describeSubnet.Subnet] }
        : { Subnets: [base.runtimeInputs.responder.aws.describeSubnet.Subnet] };
    },
    async describeSecurityGroups({ groupIds }) {
      calls.push(["describeSecurityGroups", groupIds]);
      const role = groupIds.includes(rolePlan(base.runtimeInputs.initiator.plan, "initiator").securityGroupId) ? "initiator" : "responder";
        const sg = rolePlan(base.runtimeInputs[role].plan, role).securityGroupId;
      return { SecurityGroups: [base.runtimeInputs[role].aws.securityGroups[sg]] };
    },
    async lookupEcsCloudTrailEvents({ startTime, endTime }) {
      calls.push(["lookupEcsCloudTrailEvents", { startTime, endTime }]);
      return {
          Events: [
            { eventName: "RunTask", eventSource: "ecs.amazonaws.com", eventTime: "2026-08-11T11:59:00.000Z", account: "123456789012", taskArn: "arn:aws:ecs:us-west-2:123456789012:task/clockchain-mechanics-proof/unrelated", requestParameters: { startedBy: "other-run" } },
            ...base.runtimeInputs.initiator.aws.cloudTrailEvents,
            ...base.runtimeInputs.responder.aws.cloudTrailEvents,
          ].map((event) => ({
            CloudTrailEvent: JSON.stringify({
              eventName: event.eventName,
              eventSource: event.eventSource,
              eventTime: event.eventTime,
              recipientAccountId: event.account,
              requestParameters: event.requestParameters,
              responseElements: event.eventName === "RunTask"
                ? { tasks: [{ taskArn: event.taskArn }] }
                : { task: { taskArn: event.taskArn } },
            }),
          })),
      };
    },
    async filterLogEvents({ logGroupName }) {
      calls.push(["filterLogEvents", logGroupName]);
      return logGroupName.includes("/initiator")
        ? { events: base.runtimeInputs.initiator.aws.cloudWatchLogs[0].events }
        : { events: base.runtimeInputs.responder.aws.cloudWatchLogs[0].events };
    },
    async listQueues({ queueNamePrefix }) {
      calls.push(["listQueues", queueNamePrefix]);
      return base.cleanupResponses.listQueues;
    },
    async listTaskDefinitions({ status }) {
      calls.push(["listTaskDefinitions", status]);
      return status === "ACTIVE"
        ? base.cleanupResponses.listActiveTaskDefinitions
        : base.cleanupResponses.listInactiveTaskDefinitions;
    },
  };

  const liveRuntimeInfraInputs = await collectFargateLiveInfraProofInputs({
    plan: base.runtimeInputs.initiator.plan,
    runId: RUN_ID,
    region: "us-west-2",
    stackOutputs: {
      InitiatorSecurityGroupId: rolePlan(base.runtimeInputs.initiator.plan, "initiator").securityGroupId,
      ResponderSecurityGroupId: rolePlan(base.runtimeInputs.responder.plan, "responder").securityGroupId,
      InitiatorQueueUrl: base.cleanupResponses.targets.queueUrls.initiator,
      ResponderQueueUrl: base.cleanupResponses.targets.queueUrls.responder,
    },
    clusterArn: "arn:aws:ecs:us-west-2:123456789012:cluster/clockchain",
    taskArns: base.cleanupResponses.targets.taskArns,
    taskDefinitionArns: {
      initiator: base.cleanupResponses.listInactiveTaskDefinitions.taskDefinitionArns[0],
      responder: base.cleanupResponses.listInactiveTaskDefinitions.taskDefinitionArns[1],
    },
    controlPlane,
  });
  const runtimeProofInput = await collectFargateRuntimeProofInputs({
    plan: base.runtimeInputs.initiator.plan,
    runId: RUN_ID,
    region: "us-west-2",
    stackOutputs: {
      InitiatorSecurityGroupId: rolePlan(base.runtimeInputs.initiator.plan, "initiator").securityGroupId,
      ResponderSecurityGroupId: rolePlan(base.runtimeInputs.responder.plan, "responder").securityGroupId,
      InitiatorQueueUrl: base.cleanupResponses.targets.queueUrls.initiator,
      ResponderQueueUrl: base.cleanupResponses.targets.queueUrls.responder,
    },
    clusterArn: "arn:aws:ecs:us-west-2:123456789012:cluster/clockchain",
    taskArns: base.cleanupResponses.targets.taskArns,
    taskDefinitionArns: base.cleanupResponses.targets.taskDefinitionArns,
    liveRuntimeInfraInputs,
    controlPlane,
  });
  const cleanupResponses = await collectFargateCleanupProofInputs({
    runId: RUN_ID,
    region: "us-west-2",
    stackOutputs: {
      InitiatorQueueUrl: base.cleanupResponses.targets.queueUrls.initiator,
      ResponderQueueUrl: base.cleanupResponses.targets.queueUrls.responder,
    },
    taskArns: base.cleanupResponses.targets.taskArns,
    taskDefinitionArns: base.cleanupResponses.targets.taskDefinitionArns,
    runtimeProofInput,
    controlPlane: {
      ...controlPlane,
      async confirmAbsence({ stackName }) {
        assert.equal(stackName, `clockchain-${RUN_ID}`);
        return { absent: true };
      },
    },
  });
  const collected = { ...runtimeProofInput, cleanupResponses };

  assert.equal(collected.runId, RUN_ID);
  assert.equal(collected.runtimeInputs.initiator.aws.cloudWatchLogs[0].events.length, 5);
  assert.equal(collected.runtimeInputs.responder.aws.cloudWatchLogs[0].events.length, 6);
  assert.equal(collected.cleanupResponses.confirmAbsence.absent, true);
  assert.doesNotThrow(() => buildMechanicsProofCloudEvidence(collected));
  assert.equal(calls.some(([method]) => method === "filterLogEvents"), true);
  assert.equal(calls.some(([method]) => method === "listQueues"), true);
  const cloudTrailCalls = calls.filter(([method]) => method === "lookupEcsCloudTrailEvents");
  assert.equal(cloudTrailCalls.length, 1);
  assert.equal(typeof cloudTrailCalls[0][1].startTime, "string");
  assert.equal(typeof cloudTrailCalls[0][1].endTime, "string");
});
