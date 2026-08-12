import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  FARGATE_LIVE_PLAN_SCHEMA,
  buildFargateLiveStackPlan,
  buildFargateLiveTaskDefinitions,
  loadFargateLiveRuntimeTemplate,
} from "../src/runtime/aws-fargate-live-plan.mjs";

const ACCOUNT = "123456789012";
const REGION = "us-west-2";
const RUN_ID = "11111111-2222-4333-8444-555555555555";
const IMAGE = `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/clockchain-mechanics-proof@sha256:${"a".repeat(64)}`;
const CODEX_SECRET = `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:clockchain/codex-demo-AbCdEf`;
const BEDROCK_MODEL = `arn:aws:bedrock:${REGION}:${ACCOUNT}:inference-profile/us.anthropic.claude-sonnet-4-6`;
const RESOURCE_TYPES = Object.freeze({
  Cluster: "AWS::ECS::Cluster",
  NatEip: "AWS::EC2::EIP",
  NatGateway: "AWS::EC2::NatGateway",
  InitiatorPrivateSubnet: "AWS::EC2::Subnet",
  ResponderPrivateSubnet: "AWS::EC2::Subnet",
  InitiatorRouteTable: "AWS::EC2::RouteTable",
  ResponderRouteTable: "AWS::EC2::RouteTable",
  InitiatorDefaultRoute: "AWS::EC2::Route",
  ResponderDefaultRoute: "AWS::EC2::Route",
  InitiatorRouteAssociation: "AWS::EC2::SubnetRouteTableAssociation",
  ResponderRouteAssociation: "AWS::EC2::SubnetRouteTableAssociation",
  InitiatorQueue: "AWS::SQS::Queue",
  ResponderQueue: "AWS::SQS::Queue",
  InitiatorLogGroup: "AWS::Logs::LogGroup",
  ResponderLogGroup: "AWS::Logs::LogGroup",
  InitiatorSecurityGroup: "AWS::EC2::SecurityGroup",
  ResponderSecurityGroup: "AWS::EC2::SecurityGroup",
  InitiatorPeerIngress: "AWS::EC2::SecurityGroupIngress",
  ResponderPeerIngress: "AWS::EC2::SecurityGroupIngress",
  InitiatorPeerEgress: "AWS::EC2::SecurityGroupEgress",
  ResponderPeerEgress: "AWS::EC2::SecurityGroupEgress",
  InitiatorTaskRole: "AWS::IAM::Role",
  ResponderTaskRole: "AWS::IAM::Role",
  InitiatorExecutionRole: "AWS::IAM::Role",
  ResponderExecutionRole: "AWS::IAM::Role",
});

function inputs() {
  return {
    accountId: ACCOUNT,
    appImage: IMAGE,
    bedrockModelArn: BEDROCK_MODEL,
    budgetUsd: 25,
    codexSecretArn: CODEX_SECRET,
    expiresAt: "2026-08-12T21:00:00.000Z",
    initiatorPrivateSubnet: { availabilityZone: "us-west-2a", cidr: "10.44.16.0/24" },
    maxConcurrency: 2,
    mcpUrl: "https://mcp.clockchain.network/handshake/mcp",
    networkInspection: {
      existingSubnets: [
        { cidr: "10.44.1.0/24", subnetId: "subnet-public", vpcId: "vpc-1234abcd" },
        { cidr: "10.44.8.0/24", subnetId: "subnet-existing", vpcId: "vpc-1234abcd" },
      ],
      publicRouteTable: {
        routeTableId: "rtb-public",
        routes: [{ destinationCidrBlock: "0.0.0.0/0", gatewayId: "igw-1234abcd", state: "active" }],
      },
      publicSubnet: {
        availabilityZone: "us-west-2a",
        cidr: "10.44.1.0/24",
        mapPublicIpOnLaunch: true,
        routeTableId: "rtb-public",
        subnetId: "subnet-public",
        vpcId: "vpc-1234abcd",
      },
      vpc: { cidrs: ["10.44.0.0/16"], vpcId: "vpc-1234abcd" },
    },
    publicSubnetId: "subnet-public",
    region: REGION,
    responderPrivateSubnet: { availabilityZone: "us-west-2b", cidr: "10.44.17.0/24" },
    runId: RUN_ID,
    startedAt: "2026-08-12T20:00:00.000Z",
    ttlSeconds: 3600,
    vpcId: "vpc-1234abcd",
  };
}

function outputs() {
  return {
    ClusterArn: `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/clockchain-${RUN_ID}`,
    InitiatorExecutionRoleArn: `arn:aws:iam::${ACCOUNT}:role/cc-${RUN_ID}-i-exec`,
    InitiatorLogGroupName: `/clockchain/mechanics-proof/${RUN_ID}/initiator`,
    InitiatorPrivateSubnetId: "subnet-new-initiator",
    InitiatorQueueUrl: `https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/clockchain-${RUN_ID}-initiator`,
    InitiatorSecurityGroupId: "sg-initiator",
    InitiatorTaskRoleArn: `arn:aws:iam::${ACCOUNT}:role/cc-${RUN_ID}-i-task`,
    ResponderExecutionRoleArn: `arn:aws:iam::${ACCOUNT}:role/cc-${RUN_ID}-r-exec`,
    ResponderLogGroupName: `/clockchain/mechanics-proof/${RUN_ID}/responder`,
    ResponderPrivateSubnetId: "subnet-new-responder",
    ResponderQueueUrl: `https://sqs.${REGION}.amazonaws.com/${ACCOUNT}/clockchain-${RUN_ID}-responder`,
    ResponderSecurityGroupId: "sg-responder",
    ResponderTaskRoleArn: `arn:aws:iam::${ACCOUNT}:role/cc-${RUN_ID}-r-task`,
  };
}

function stackResources() {
  const value = outputs();
  const bound = new Map([
    ["Cluster", value.ClusterArn.split("/").at(-1)],
    ["InitiatorPrivateSubnet", value.InitiatorPrivateSubnetId],
    ["ResponderPrivateSubnet", value.ResponderPrivateSubnetId],
    ["InitiatorSecurityGroup", value.InitiatorSecurityGroupId],
    ["ResponderSecurityGroup", value.ResponderSecurityGroupId],
    ["InitiatorQueue", value.InitiatorQueueUrl],
    ["ResponderQueue", value.ResponderQueueUrl],
    ["InitiatorTaskRole", value.InitiatorTaskRoleArn.split("/").at(-1)],
    ["ResponderTaskRole", value.ResponderTaskRoleArn.split("/").at(-1)],
    ["InitiatorExecutionRole", value.InitiatorExecutionRoleArn.split("/").at(-1)],
    ["ResponderExecutionRole", value.ResponderExecutionRoleArn.split("/").at(-1)],
    ["InitiatorLogGroup", value.InitiatorLogGroupName],
    ["ResponderLogGroup", value.ResponderLogGroupName],
  ]);
  return {
    stackId: `arn:aws:cloudformation:${REGION}:${ACCOUNT}:stack/clockchain-${RUN_ID}/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee`,
    stackName: `clockchain-${RUN_ID}`,
    resources: Object.entries(RESOURCE_TYPES).map(([logicalResourceId, resourceType]) => ({
      logicalResourceId,
      physicalResourceId: bound.get(logicalResourceId) ?? `physical-${logicalResourceId.toLowerCase()}`,
      resourceType,
    })),
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test("live Fargate template defines disposable private networking, exact role boundaries, and required tags", async () => {
  const template = await loadFargateLiveRuntimeTemplate({ root: process.cwd() });
  const resources = template.Resources;

  assert.equal(resources.InitiatorPrivateSubnet.Properties.MapPublicIpOnLaunch, false);
  assert.equal(resources.ResponderPrivateSubnet.Properties.MapPublicIpOnLaunch, false);
  assert.equal(resources.NatGateway.Type, "AWS::EC2::NatGateway");
  assert.deepEqual(resources.NatGateway.Properties.SubnetId, { Ref: "PublicSubnetId" });
  assert.equal(resources.InitiatorDefaultRoute.Properties.NatGatewayId.Ref, "NatGateway");
  assert.equal(resources.ResponderDefaultRoute.Properties.NatGatewayId.Ref, "NatGateway");
  assert.equal(resources.InitiatorQueue.Properties.SqsManagedSseEnabled, true);
  assert.equal(resources.ResponderQueue.Properties.SqsManagedSseEnabled, true);
  assert.equal(resources.InitiatorQueue.Properties.KmsMasterKeyId, undefined);
  assert.equal(resources.ResponderQueue.Properties.KmsMasterKeyId, undefined);
  assert.equal(resources.InitiatorQueue.Properties.MessageRetentionPeriod, 900);
  assert.equal(resources.ResponderQueue.Properties.MessageRetentionPeriod, 900);
  assert.ok(resources.Cluster);
  assert.ok(resources.InitiatorLogGroup);
  assert.ok(resources.ResponderLogGroup);
  const trustCondition = {
    ArnLike: { "aws:SourceArn": { "Fn::Sub": "arn:${AWS::Partition}:ecs:${AWS::Region}:${AWS::AccountId}:*" } },
    StringEquals: { "aws:SourceAccount": { Ref: "AWS::AccountId" } },
  };
  for (const name of ["InitiatorTaskRole", "ResponderTaskRole", "InitiatorExecutionRole", "ResponderExecutionRole"]) {
    assert.deepEqual(resources[name].Properties.AssumeRolePolicyDocument.Statement[0].Condition, trustCondition);
  }
  assert.deepEqual(resources.InitiatorTaskRole.Properties.RoleName, { "Fn::Sub": "cc-${RunId}-i-task" });
  assert.deepEqual(resources.ResponderTaskRole.Properties.RoleName, { "Fn::Sub": "cc-${RunId}-r-task" });

  const serialized = JSON.stringify(template);
  assert.doesNotMatch(serialized, /EFS|FileSystem|SIGNER|STATE_REF|MCP_CREDENTIAL/i);
  assert.match(serialized, /bedrock:InvokeModel/);
  const bedrockPolicy = resources.ResponderTaskRole.Properties.Policies.find((policy) => policy.PolicyName === "bedrock-sonnet");
  const bedrockStatement = bedrockPolicy.PolicyDocument.Statement[0];
  assert.deepEqual(bedrockStatement.Action, ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]);
  assert.deepEqual(bedrockStatement.Resource, [
    { Ref: "BedrockModelArn" },
    { "Fn::Sub": "arn:${AWS::Partition}:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-6" },
    { "Fn::Sub": "arn:${AWS::Partition}:bedrock:us-east-2::foundation-model/anthropic.claude-sonnet-4-6" },
    { "Fn::Sub": "arn:${AWS::Partition}:bedrock:us-west-2::foundation-model/anthropic.claude-sonnet-4-6" },
  ]);
  assert.notEqual(bedrockStatement.Resource, "*");
  const initiatorQueueStatements = resources.InitiatorTaskRole.Properties.Policies.find((policy) => policy.PolicyName === "bootstrap-exchange").PolicyDocument.Statement;
  const responderQueueStatements = resources.ResponderTaskRole.Properties.Policies.find((policy) => policy.PolicyName === "bootstrap-exchange").PolicyDocument.Statement;
  assert.deepEqual(initiatorQueueStatements.map((statement) => statement.Action), [
    ["sqs:SendMessage"],
    ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
  ]);
  assert.deepEqual(responderQueueStatements.map((statement) => statement.Action), [
    ["sqs:SendMessage"],
    ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
  ]);
  assert.match(serialized, /secretsmanager:GetSecretValue/);
  for (const tag of ["ClockchainRunId", "ClockchainPhase", "ClockchainExpiresAt", "ClockchainCostCenter"]) {
    assert.match(serialized, new RegExp(tag));
  }
});

test("live stack plan binds explicit validated network inputs without hard-coded fixture account", async () => {
  const plan = await buildFargateLiveStackPlan(inputs());
  assert.equal(plan.schema, FARGATE_LIVE_PLAN_SCHEMA);
  assert.equal(plan.accountId, ACCOUNT);
  assert.equal(plan.region, REGION);
  assert.equal(plan.parameters.VpcId, "vpc-1234abcd");
  assert.equal(plan.parameters.PublicSubnetId, "subnet-public");
  assert.equal(plan.parameters.InitiatorPrivateSubnetCidr, "10.44.16.0/24");
  assert.equal(plan.parameters.ResponderPrivateSubnetCidr, "10.44.17.0/24");
  assert.equal(plan.controls.assignPublicIp, "DISABLED");
  assert.equal(plan.controls.temporaryNatGateway, true);
  assert.equal(plan.controls.maxConcurrency, 2);
  assert.equal(plan.controls.ttlSeconds, 3600);
  assert.equal(plan.controls.budgetUsd, 25);
  assert.deepEqual(plan.network.publicRoute, {
    destinationCidrBlock: "0.0.0.0/0",
    gatewayId: "igw-1234abcd",
    routeTableId: "rtb-public",
  });
  assert.doesNotMatch(JSON.stringify(plan.template), /123456789012/);
});

test("live task definitions use stack outputs and keep party authority inside isolated roles", async () => {
  const plan = await buildFargateLiveStackPlan(inputs());
  const definitions = buildFargateLiveTaskDefinitions({ stackOutputs: outputs(), stackPlan: plan, stackResources: stackResources() });
  const initiator = definitions.initiator;
  const responder = definitions.responder;

  assert.notEqual(initiator.taskRoleArn, responder.taskRoleArn);
  assert.notEqual(initiator.executionRoleArn, responder.executionRoleArn);
  assert.equal(initiator.containerDefinitions[0].image, IMAGE);
  assert.equal(responder.containerDefinitions[0].image, IMAGE);
  assert.equal(initiator.containerDefinitions[0].readonlyRootFilesystem, true);
  assert.equal(responder.containerDefinitions[0].readonlyRootFilesystem, true);
  assert.equal(initiator.containerDefinitions[0].stopTimeout, 30);
  assert.equal(responder.containerDefinitions[0].stopTimeout, 30);
  assert.equal(initiator.containerDefinitions[0].user, "1000:1000");
  assert.deepEqual(initiator.containerDefinitions[0].command, ["--run-managed"]);
  assert.deepEqual(responder.containerDefinitions[0].command, ["--run-managed"]);
  assert.equal(initiator.containerDefinitions[0].secrets.length, 1);
  assert.deepEqual(initiator.containerDefinitions[0].secrets[0], {
    name: "CLOCKCHAIN_CODEX_AUTH_JSON_BASE64",
    valueFrom: CODEX_SECRET,
  });
  assert.deepEqual(responder.containerDefinitions[0].secrets, []);
  for (const definition of [initiator, responder]) {
    const app = definition.containerDefinitions.find((container) => container.name !== "workspace-init");
    const init = definition.containerDefinitions.find((container) => container.name === "workspace-init");
    assert.ok(init);
    assert.equal(init.essential, false);
    assert.equal(init.user, "0:0");
    assert.deepEqual(init.entryPoint, ["/bin/sh", "-c"]);
    assert.deepEqual(init.command, ["chown 1000:1000 /workspace"]);
    assert.deepEqual(init.environment, []);
    assert.deepEqual(init.secrets, []);
    assert.deepEqual(init.portMappings, []);
    assert.deepEqual(app.dependsOn, [{ condition: "SUCCESS", containerName: "workspace-init" }]);
    assert.equal(app.user, "1000:1000");
    assert.equal(app.readonlyRootFilesystem, true);
    assert.deepEqual(definition.volumes, [{ name: "workspace" }]);
    assert.equal(Object.hasOwn(definition.volumes[0], "efsVolumeConfiguration"), false);
    assert.equal(Object.hasOwn(definition.volumes[0], "host"), false);
  }
  assert.deepEqual(initiator.volumes, [{ name: "workspace" }]);
  assert.deepEqual(responder.volumes, [{ name: "workspace" }]);
  assert.doesNotMatch(JSON.stringify(definitions), /EFS|SIGNER|STATE_REF|MCP_CREDENTIAL|ANTHROPIC_API_KEY/i);
  for (const forbidden of [
    "CLOCKCHAIN_A2A_PUBLIC_ENDPOINT",
    "CLOCKCHAIN_RUNTIME_ID",
    "CLOCKCHAIN_TASK_ID",
    "CLOCKCHAIN_WORKLOAD_ATTESTATION_DIGEST",
  ]) {
    assert.doesNotMatch(JSON.stringify(definitions), new RegExp(forbidden));
  }

  const initiatorEnv = Object.fromEntries(initiator.containerDefinitions[0].environment.map(({ name, value }) => [name, value]));
  const responderEnv = Object.fromEntries(responder.containerDefinitions[0].environment.map(({ name, value }) => [name, value]));
  assert.equal(initiatorEnv.CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL, outputs().InitiatorQueueUrl);
  assert.equal(initiatorEnv.CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL, outputs().ResponderQueueUrl);
  assert.equal(responderEnv.CLOCKCHAIN_BOOTSTRAP_OWN_QUEUE_URL, outputs().ResponderQueueUrl);
  assert.equal(responderEnv.CLOCKCHAIN_BOOTSTRAP_PEER_QUEUE_URL, outputs().InitiatorQueueUrl);
  assert.equal(responderEnv.CLOCKCHAIN_CLAUDE_PROVIDER, "bedrock");
  assert.equal(responderEnv.CLOCKCHAIN_BEDROCK_MODEL_ID, "us.anthropic.claude-sonnet-4-6");
  assert.equal(initiatorEnv.CLOCKCHAIN_HELPER_MANIFEST_DIGEST, "fa3c408a3739227b5bdb71486b4d291b8f4dffdb0d1f2fa79dd59644ba5e09ad");
  assert.equal(responderEnv.CLOCKCHAIN_HELPER_MANIFEST_DIGEST, initiatorEnv.CLOCKCHAIN_HELPER_MANIFEST_DIGEST);
  assert.deepEqual(JSON.parse(initiatorEnv.CLOCKCHAIN_MANDATE_JSON), JSON.parse(responderEnv.CLOCKCHAIN_MANDATE_JSON));
  assert.equal(initiatorEnv.CLOCKCHAIN_OPENSSL_PATH, "/usr/bin/openssl");
});

test("live plan rejects unsafe or inferred networking and authority inputs", async () => {
  const cases = [
    ["overlapping private cidrs", (value) => { value.responderPrivateSubnet.cidr = value.initiatorPrivateSubnet.cidr; }],
    ["existing subnet overlap", (value) => { value.initiatorPrivateSubnet.cidr = "10.44.8.0/24"; }],
    ["private cidr outside vpc", (value) => { value.initiatorPrivateSubnet.cidr = "10.55.16.0/24"; }],
    ["same availability zone", (value) => { value.responderPrivateSubnet.availabilityZone = value.initiatorPrivateSubnet.availabilityZone; }],
    ["public subnet wrong vpc", (value) => { value.networkInspection.publicSubnet.vpcId = "vpc-other"; }],
    ["public addresses disabled", (value) => { value.networkInspection.publicSubnet.mapPublicIpOnLaunch = false; }],
    ["route table inferred", (value) => { delete value.networkInspection.publicSubnet.routeTableId; }],
    ["route table mismatch", (value) => { value.networkInspection.publicSubnet.routeTableId = "rtb-other"; }],
    ["missing igw route", (value) => { value.networkInspection.publicRouteTable.routes[0].gatewayId = "nat-1234abcd"; }],
    ["inactive igw route", (value) => { value.networkInspection.publicRouteTable.routes[0].state = "blackhole"; }],
    ["unbounded ttl", (value) => { value.ttlSeconds = 3601; }],
    ["too many tasks", (value) => { value.maxConcurrency = 3; }],
    ["budget overflow", (value) => { value.budgetUsd = 25.01; }],
    ["mutable image", (value) => { value.appImage = `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/app:latest`; }],
    ["cross-account codex secret", (value) => { value.codexSecretArn = value.codexSecretArn.replace(ACCOUNT, "210987654321"); }],
    ["suffixed bedrock profile", (value) => { value.bedrockModelArn += ":copy"; }],
    ["alternate deployment root", (value) => { value.root = "/private/tmp/alternate"; }],
  ];
  for (const [name, mutate] of cases) {
    const value = clone(inputs());
    mutate(value);
    await assert.rejects(() => buildFargateLiveStackPlan(value), /Fargate live plan validation failed safely/, name);
  }
});

test("task definition builder rejects ambiguous outputs and shared role identity", async () => {
  const plan = await buildFargateLiveStackPlan(inputs());
  const shared = outputs();
  shared.ResponderTaskRoleArn = shared.InitiatorTaskRoleArn;
  assert.throws(
    () => buildFargateLiveTaskDefinitions({ stackOutputs: shared, stackPlan: plan, stackResources: stackResources() }),
    /Fargate live plan validation failed safely/,
  );
  const extra = { ...outputs(), SecretValue: "must-not-be-accepted" };
  assert.throws(
    () => buildFargateLiveTaskDefinitions({ stackOutputs: extra, stackPlan: plan, stackResources: stackResources() }),
    /Fargate live plan validation failed safely/,
  );
});

test("task definitions require every generated output to match one exact stack-resource envelope", async () => {
  const plan = await buildFargateLiveStackPlan(inputs());
  const arbitraryRole = outputs();
  arbitraryRole.InitiatorTaskRoleArn = `arn:aws:iam::${ACCOUNT}:role/arbitrary-same-account-role`;
  assert.throws(
    () => buildFargateLiveTaskDefinitions({ stackOutputs: arbitraryRole, stackPlan: plan, stackResources: stackResources() }),
    /Fargate live plan validation failed safely/,
  );
  for (const mutate of [
    (value) => { value.stackName = "clockchain-other"; },
    (value) => { value.stackId = value.stackId.replace(`clockchain-${RUN_ID}`, "clockchain-other"); },
    (value) => { value.resources.find((entry) => entry.logicalResourceId === "InitiatorPrivateSubnet").physicalResourceId = "subnet-foreign"; },
    (value) => { value.resources.find((entry) => entry.logicalResourceId === "NatGateway").resourceType = "AWS::IAM::Role"; },
    (value) => { value.resources.find((entry) => entry.logicalResourceId === "NatGateway").physicalResourceId = ""; },
    (value) => { value.resources = value.resources.filter((entry) => entry.logicalResourceId !== "NatGateway"); },
    (value) => { value.resources.push({ logicalResourceId: "AdminRole", physicalResourceId: "admin", resourceType: "AWS::IAM::Role" }); },
  ]) {
    const resources = clone(stackResources());
    mutate(resources);
    assert.throws(
      () => buildFargateLiveTaskDefinitions({ stackOutputs: outputs(), stackPlan: plan, stackResources: resources }),
      /Fargate live plan validation failed safely/,
    );
  }
});

test("canonical live template loader rejects alternate templates with added administrator authority", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "clockchain-live-template-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const target = join(root, "infra", "mechanics-proof");
  await mkdir(target, { recursive: true });
  const template = JSON.parse(await readFile("infra/mechanics-proof/fargate-live-runtime.yaml", "utf8"));
  template.Resources.AdminRole = {
    Type: "AWS::IAM::Role",
    Properties: {
      AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [] },
      Policies: [{ PolicyName: "admin", PolicyDocument: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] } }],
    },
  };
  await writeFile(join(target, "fargate-live-runtime.yaml"), JSON.stringify(template));
  await assert.rejects(
    () => loadFargateLiveRuntimeTemplate({ root }),
    /Fargate live plan validation failed safely/,
  );
});
