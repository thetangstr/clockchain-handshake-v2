import assert from "node:assert/strict";
import test from "node:test";

import {
  createAwsCliControlPlane,
  publicControlPlaneFailureStage,
  publicPartyFailureStages,
  publicPartyProgressStages,
} from "../src/runtime/aws-cli-control-plane.mjs";
import { loadFargateLiveRuntimeTemplate } from "../src/runtime/aws-fargate-live-plan.mjs";
import { stableJson } from "../src/runtime/aws-fargate-runtime-adapter.mjs";

test("AWS CLI control plane uses only execFile aws argv and parses JSON responses", async () => {
  const calls = [];
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (file, argv, options) => {
      calls.push({ file, argv, options });
      assert.equal(file, "aws");
      assert.equal(argv.includes("--output"), true);
      assert.equal(argv.at(-1), "json");
      assert.equal(argv.includes("--region"), true);
      assert.equal(argv[argv.indexOf("--region") + 1], "us-west-2");
      return { stdout: JSON.stringify({ Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/controller", UserId: "AIDA" }), stderr: "", exitCode: 0 };
    },
  });

  assert.deepEqual(await control.getCallerIdentity(), {
    accountId: "123456789012",
    arn: "arn:aws:iam::123456789012:user/controller",
    userId: "AIDA",
  });
  assert.deepEqual(calls[0].argv, ["sts", "get-caller-identity", "--region", "us-west-2", "--output", "json"]);
});

test("AWS CLI control plane rejects unexpected commands, non-json, stderr, timeout, oversized output, or shell-shaped input", async () => {
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async () => ({ stdout: "not-json", stderr: "", exitCode: 0 }),
  });
  await assert.rejects(() => control.getCallerIdentity(), /AWS CLI control-plane validation failed safely/);

  for (const executor of [
    async () => ({ stdout: "{}", stderr: "warning", exitCode: 0 }),
    async () => ({ stdout: "{}", stderr: "", exitCode: 1 }),
    async () => ({ stdout: "{}".padEnd(2_000_000, " "), stderr: "", exitCode: 0 }),
    async () => { const error = new Error("timeout"); error.killed = true; throw error; },
    async () => { const error = new Error("signal"); error.signal = "SIGTERM"; throw error; },
    async () => ({ stdout: JSON.stringify({ StackResourceSummaries: [] }), stderr: "", exitCode: 0 }),
  ]) {
    const bad = createAwsCliControlPlane({ region: "us-west-2", executor });
    await assert.rejects(() => bad.listStackResources({ stackName: "clockchain-11111111-2222-4333-8444-555555555555" }), /AWS CLI control-plane validation failed safely/);
  }

  const safe = createAwsCliControlPlane({ region: "us-west-2", executor: async () => ({ stdout: "{}", stderr: "", exitCode: 0 }) });
  assert.equal(safe.callAws, undefined, "raw AWS argv execution is not a public control-plane capability");
  assert.throws(() => safe.deleteStack({ stackName: "clockchain-11111111-2222-4333-8444-555555555555;rm" }), /AWS CLI control-plane validation failed safely/);
  assert.throws(() => createAwsCliControlPlane({ region: "us-east-1;profile", executor: async () => ({ stdout: "{}", stderr: "", exitCode: 0 }) }), /AWS CLI control-plane validation failed safely/);
  await assert.rejects(() => safe.getCallerIdentity(), /AWS CLI control-plane validation failed safely/);
});

test("AWS CLI control plane accepts empty wait/delete output but does not treat auth failures as absent", async () => {
  const calls = [];
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (file, argv) => {
      calls.push(argv);
      if (argv[0] === "cloudformation" && argv[1] === "wait") return { stdout: "", stderr: "", exitCode: 0 };
      if (argv[0] === "cloudformation" && argv[1] === "delete-stack") return { stdout: "", stderr: "", exitCode: 0 };
      return { stdout: JSON.stringify({ __type: "AccessDenied", message: "denied" }), stderr: "", exitCode: 254 };
    },
  });
  await assert.doesNotReject(() => control.waitStackDeleteComplete({ stackName: "clockchain-11111111-2222-4333-8444-555555555555" }));
  await assert.doesNotReject(() => control.deleteStack({ stackName: "clockchain-11111111-2222-4333-8444-555555555555" }));
  await assert.rejects(() => control.stackExists({ stackName: "clockchain-11111111-2222-4333-8444-555555555555" }), /AWS CLI control-plane validation failed safely/);
});

test("AWS CLI control plane bounds post-delete absence retries across eventual consistency", async () => {
  const calls = [];
  const sleeps = [];
  const stackName = "clockchain-11111111-2222-4333-8444-555555555555";
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    sleep: async (ms) => { sleeps.push(ms); },
    executor: async (_file, argv) => {
      calls.push(argv);
      if (calls.length < 3) {
        return { stdout: JSON.stringify({ Stacks: [{ StackName: stackName }] }), stderr: "", exitCode: 0 };
      }
      throw new Error(`Stack with id ${stackName} does not exist`);
    },
  });

  assert.deepEqual(await control.confirmAbsence({ stackName }), { absent: true });
  assert.equal(calls.length, 3);
  assert.deepEqual(sleeps, [1000, 1000]);
});

test("AWS CLI control plane stops absence confirmation after one hundred twenty bounded observations", async () => {
  let calls = 0;
  const sleeps = [];
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    sleep: async (ms) => { sleeps.push(ms); },
    executor: async () => {
      calls += 1;
      return { stdout: JSON.stringify({ Stacks: [{ StackName: "clockchain-11111111-2222-4333-8444-555555555555" }] }), stderr: "", exitCode: 0 };
    },
  });

  assert.deepEqual(await control.confirmAbsence({ stackName: "clockchain-11111111-2222-4333-8444-555555555555" }), { absent: false });
  assert.equal(calls, 120);
  assert.equal(sleeps.length, 119);
  assert.equal(sleeps.every((ms) => ms === 1000), true);
});

test("AWS CLI control plane gives bounded CloudFormation waiters enough time for live stack creation", async () => {
  const observedTimeouts = [];
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (_file, _argv, options) => {
      observedTimeouts.push(options.timeoutMs);
      return { stdout: "", stderr: "", exitCode: 0 };
    },
  });
  await control.waitStackCreateComplete({ stackName: "clockchain-11111111-2222-4333-8444-555555555555" });
  await control.waitStackDeleteComplete({ stackName: "clockchain-11111111-2222-4333-8444-555555555555" });
  await control.waitTasksRunning({ cluster: "cluster", taskArns: ["task-a", "task-b"] });
  await control.waitTasksStopped({ cluster: "cluster", taskArns: ["task-a", "task-b"] });
  assert.deepEqual(observedTimeouts, [300_000, 300_000, 300_000, 300_000]);
});

test("AWS CLI control plane waits for newly-created execution role policies before starting tasks", async () => {
  const waits = [];
  const control = createAwsCliControlPlane({
    accountId: "123456789012",
    region: "us-west-2",
    sleep: async (ms) => { waits.push(ms); },
    executor: async () => ({ stdout: "{}", stderr: "", exitCode: 0 }),
  });
  await control.waitExecutionRolePropagation({
    initiatorExecutionRoleArn: "arn:aws:iam::123456789012:role/cc-11111111-2222-4333-8444-555555555555-i-exec",
    responderExecutionRoleArn: "arn:aws:iam::123456789012:role/cc-11111111-2222-4333-8444-555555555555-r-exec",
  });
  assert.deepEqual(waits, [30_000]);
});

test("AWS CLI control plane has exact allowlisted argv shapes for Task 4 actions", async () => {
  const calls = [];
  const responseFor = (argv) => {
    const key = argv.slice(0, argv[0] === "cloudformation" && argv[1] === "wait" || argv[0] === "ecs" && argv[1] === "wait" ? 3 : 2).join(" ");
    if (key === "sts get-caller-identity") return { Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/controller", UserId: "AIDA" };
  if (key === "cloudformation describe-stacks") return { Stacks: [{ Outputs: [{ OutputKey: "ClusterArn", OutputValue: "arn:aws:ecs:us-west-2:123456789012:cluster/c" }] }] };
    if (key === "cloudformation create-stack") return { StackId: "arn:aws:cloudformation:us-west-2:123456789012:stack/clockchain-11111111-2222-4333-8444-555555555555/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" };
    if (key === "cloudformation list-stack-resources") return { StackResourceSummaries: [{ LogicalResourceId: "Cluster", PhysicalResourceId: "cluster", ResourceType: "AWS::ECS::Cluster" }] };
    if (key === "ecs register-task-definition") return { taskDefinition: { taskDefinitionArn: "arn:aws:ecs:us-west-2:123456789012:task-definition/x:1" } };
    if (key === "ecs run-task") return { tasks: [{ taskArn: "arn:aws:ecs:us-west-2:123456789012:task/c/t" }], failures: [] };
    if (key === "logs filter-log-events") {
      const role = argv.includes("/clockchain/mechanics-proof/run/responder") ? "responder" : "initiator";
      return { events: [
        { timestamp: 1786565101000, message: JSON.stringify({ schema: "clockchain.mechanics-proof-party-evidence/v1", runId: "11111111-2222-4333-8444-555555555555", protocolSessionId: "protocol-session-1", role, harness: role === "initiator" ? "codex" : "claude", runtimeId: `runtime-${role}`, workloadAttestationDigest: "1".repeat(64), peerRuntimeId: role === "initiator" ? "runtime-responder" : "runtime-initiator", bridgeEvidenceDigest: "2".repeat(64), harnessEvidenceDigest: "3".repeat(64), certificateProofDigest: "4".repeat(64), certificateDigest: "a".repeat(64), identity: {}, anchors: [], directDelivery: { acknowledged: true }, externalBusinessActionPerformed: false, terminalStatus: "completed", teardown: { completed: true } }) },
      ] };
    }
    return {};
  };
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    accountId: "123456789012",
    executor: async (file, argv) => {
      calls.push([file, argv]);
      return { stdout: JSON.stringify(responseFor(argv)), stderr: "", exitCode: 0 };
    },
  });
  const stackName = "clockchain-11111111-2222-4333-8444-555555555555";
  await control.getCallerIdentity();
  await control.validateTemplate({ templateBody: "{}" });
  await control.stackExists({ stackName });
  await control.createStack({ stackName, templateBody: "{}", parameters: [], capabilities: ["CAPABILITY_NAMED_IAM"] });
  await control.waitStackCreateComplete({ stackName });
  await control.describeStackOutputs({ stackName });
  await control.listStackResources({ stackName });
  await control.registerTaskDefinition({ taskDefinition: { family: "x" } });
  await control.runTask({ cluster: "cluster", taskDefinitionArn: "td", role: "initiator", networkConfiguration: { awsvpcConfiguration: { assignPublicIp: "DISABLED" } }, startedBy: "run" });
  await control.waitTasksRunning({ cluster: "cluster", taskArns: ["task-a", "task-b"] });
  await control.waitTasksStopped({ cluster: "cluster", taskArns: ["task-a", "task-b"] });
  await control.describeTasks({ cluster: "cluster", taskArns: ["task-a"] });
  await control.describeTaskDefinition({ taskDefinitionArn: "td" });
  await control.describeNetworkInterfaces({ networkInterfaceIds: ["eni-1"] });
  await control.describeSubnetsByIds({ subnetIds: ["subnet-1"] });
  await control.describeSecurityGroups({ groupIds: ["sg-1"] });
  await control.filterLogEvents({ logGroupName: "/clockchain/mechanics-proof/run/initiator" });
  await control.lookupEcsCloudTrailEvents({ startTime: "2026-08-12T20:00:00.000Z", endTime: "2026-08-12T20:10:00.000Z" });
  await control.listQueues({ queueNamePrefix: stackName });
  await control.listTaskDefinitions({ familyPrefix: `${stackName}-`, status: "ACTIVE" });
  await control.stopTask({ cluster: "cluster", taskArn: "task-a", role: "initiator" });
  await control.deregisterTaskDefinition({ taskDefinitionArn: "td", role: "initiator" });
  await control.deleteStack({ stackName });
  await control.waitStackDeleteComplete({ stackName });
  await control.pollPublicEvents({ logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"], runId: "11111111-2222-4333-8444-555555555555", startTimeMs: 0, deadlineMs: Date.now() + 1000 });

  for (const [file, argv] of calls) {
    assert.equal(file, "aws");
    assert.equal(argv.includes("--region"), true);
    assert.equal(argv.includes("--output"), true);
    assert.equal(argv.at(-1), "json");
    assert.doesNotMatch(JSON.stringify(argv), /secret|cookie|authorization|;|&&|\|/i);
  }
});

test("AWS CLI control plane validates real create-stack StackId and binds later calls to that identifier", async () => {
  const stackName = "clockchain-11111111-2222-4333-8444-555555555555";
  const stackId = "arn:aws:cloudformation:us-west-2:123456789012:stack/clockchain-11111111-2222-4333-8444-555555555555/840b9190-9665-11f1-8539-0232ad8fd72d";
  const operationId = "a5f2ff95-2d39-4653-aa98-1daf5e41dd79";
  const seen = [];
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (_file, argv) => {
      seen.push(argv);
      const key = argv.slice(0, argv[0] === "cloudformation" && argv[1] === "wait" ? 3 : 2).join(" ");
      if (key === "cloudformation create-stack") return { stdout: JSON.stringify({ StackId: stackId, OperationId: operationId }), stderr: "", exitCode: 0 };
      if (key === "cloudformation describe-stacks") return { stdout: JSON.stringify({ Stacks: [{ StackId: stackId, StackName: stackName, Outputs: [] }] }), stderr: "", exitCode: 0 };
      return { stdout: JSON.stringify({ StackResourceSummaries: [{ LogicalResourceId: "Cluster", PhysicalResourceId: "cluster", ResourceType: "AWS::ECS::Cluster" }] }), stderr: "", exitCode: 0 };
    },
  });
  assert.deepEqual(await control.createStack({ stackName, templateBody: "{}", parameters: [], capabilities: ["CAPABILITY_NAMED_IAM"] }), { StackId: stackId });
  await control.waitStackCreateComplete({ stackName, stackId });
  await control.describeStackOutputs({ stackName, stackId });
  assert.deepEqual(await control.listStackResources({ stackName, stackId }), {
    stackId,
    stackName,
    resources: [{ logicalResourceId: "Cluster", physicalResourceId: "cluster", resourceType: "AWS::ECS::Cluster" }],
  });
  assert.equal(seen.some((argv) => argv[0] === "cloudformation" && argv[1] === "wait" && argv.includes(stackId)), true);
  assert.equal(seen.some((argv) => argv[0] === "cloudformation" && argv[1] === "describe-stacks" && argv.includes(stackId)), true);
  assert.equal(seen.some((argv) => argv[0] === "cloudformation" && argv[1] === "list-stack-resources" && argv.includes(stackId)), true);

  for (const StackId of [
    "stack-id",
    stackId.replace("us-west-2", "us-east-1"),
    stackId.replace("123456789012", "210987654321"),
    stackId.replace(stackName, "clockchain-99999999-2222-4333-8444-555555555555"),
  ]) {
    const bad = createAwsCliControlPlane({
      region: "us-west-2",
      accountId: "123456789012",
      executor: async () => ({ stdout: JSON.stringify({ StackId }), stderr: "", exitCode: 0 }),
    });
    await assert.rejects(() => bad.createStack({ stackName, templateBody: "{}", parameters: [], capabilities: ["CAPABILITY_NAMED_IAM"] }), /AWS CLI control-plane validation failed safely/);
  }
});

test("AWS CLI control plane accepts dollars only inside canonical template JSON argv data", async () => {
  const template = await loadFargateLiveRuntimeTemplate();
  const body = stableJson(template);
  assert.match(body, /\$\{/);
  const stackName = "clockchain-11111111-2222-4333-8444-555555555555";
  const stackId = "arn:aws:cloudformation:us-west-2:123456789012:stack/clockchain-11111111-2222-4333-8444-555555555555/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const seen = [];
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (_file, argv) => {
      seen.push(argv);
      return { stdout: JSON.stringify({ StackId: stackId }), stderr: "", exitCode: 0 };
    },
  });
  await control.createStack({ stackName, templateBody: body, parameters: [], capabilities: ["CAPABILITY_NAMED_IAM"] });
  assert.equal(seen[0].includes(body), true);

  assert.throws(() => control.validateTemplate({ templateBody: "{\"z\":1,\"a\":2}" }), /AWS CLI control-plane validation failed safely/);
  await assert.rejects(() => control.createStack({ stackName, templateBody: "{}", parameters: [{ ParameterKey: "Bad", ParameterValue: "${not-template}" }], capabilities: ["CAPABILITY_NAMED_IAM"] }), /AWS CLI control-plane validation failed safely/);
  assert.equal(control.callAws, undefined);
  assert.throws(() => control.deleteStack({ stackName: `${stackName}$` }), /AWS CLI control-plane validation failed safely/);
});

test("AWS CLI control plane preserves CloudWatch event timestamps with terminal records", async () => {
  const timestamp = 1786565101000;
  const terminal = (role) => ({ schema: "clockchain.mechanics-proof-party-evidence/v1", runId: "11111111-2222-4333-8444-555555555555", protocolSessionId: "protocol-session-1", role, harness: role === "initiator" ? "codex" : "claude", runtimeId: `runtime-${role}`, workloadAttestationDigest: "1".repeat(64), peerRuntimeId: role === "initiator" ? "runtime-responder" : "runtime-initiator", bridgeEvidenceDigest: "2".repeat(64), harnessEvidenceDigest: "3".repeat(64), certificateProofDigest: "4".repeat(64), certificateDigest: "a".repeat(64), identity: {}, anchors: [], directDelivery: { acknowledged: true }, externalBusinessActionPerformed: false, terminalStatus: "completed", teardown: { completed: true } });
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (_file, argv) => {
      const role = argv.includes("/clockchain/mechanics-proof/run/responder") ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [{ timestamp, message: JSON.stringify(terminal(role)) }] }), stderr: "", exitCode: 0 };
    },
  });
  const events = await control.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId: "11111111-2222-4333-8444-555555555555",
    startTimeMs: 1786565100000,
    deadlineMs: Date.now() + 1000,
  });
  assert.equal(events[0].timestamp, "2026-08-12T20:05:01.000Z");
});

test("AWS CLI control plane brands only exact allowlisted party failure stages", async () => {
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (_file, argv) => {
      const role = argv.some((value) => value.includes("/responder")) ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [{
        timestamp: 1786565101000,
        message: role === "initiator"
          ? "Mechanics proof party failed safely. stage=runtime-run.agent-launch-completion-protocol-bridge-incomplete-no-tool-result"
          : "Mechanics proof party failed safely. stage=runtime-run.evidence-validate-session",
      }] }), stderr: "", exitCode: 0 };
    },
  });
  await assert.rejects(() => control.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId: "11111111-2222-4333-8444-555555555555",
    startTimeMs: 0,
    deadlineMs: Date.now() + 1000,
  }), (error) => {
    assert.deepEqual(publicPartyFailureStages(error), {
      initiator: "runtime-run.agent-launch-completion-protocol-bridge-incomplete-no-tool-result",
      responder: "runtime-run.evidence-validate-session",
    });
    assert.equal(publicPartyFailureStages(new Error(error.message)), null);
    assert.doesNotMatch(JSON.stringify(error), /amazonaws|secret|certificate|private/i);
    return true;
  });
});

test("AWS CLI control plane retains only the latest exact public progress stage on timeout", async () => {
  let current = 0;
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    now: () => current,
    sleep: async () => { current = 2000; },
    executor: async (_file, argv) => {
      const role = argv.some((value) => value.includes("/responder")) ? "responder" : "initiator";
      const types = role === "initiator" ? ["a2a.listener.ready", "agent.starting"] : ["a2a.listener.ready", "a2a.invitation.received", "agent.starting"];
      return { stdout: JSON.stringify({ events: types.map((type, index) => ({
        timestamp: 1786565101000 + index,
        message: JSON.stringify({
          schema: "clockchain.mechanics-proof-party-event/v1",
          runId: "11111111-2222-4333-8444-555555555555",
          role,
          sequence: String(index + 1),
          type,
          evidenceDigest: String(index + 1).repeat(64),
        }),
      })) }), stderr: "", exitCode: 0 };
    },
  });

  await assert.rejects(() => control.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId: "11111111-2222-4333-8444-555555555555",
    startTimeMs: 0,
    deadlineMs: 1000,
  }), (error) => {
    assert.deepEqual(publicPartyProgressStages(error), {
      initiator: "agent.starting",
      responder: "agent.starting",
    });
    assert.equal(publicPartyProgressStages(new Error(error.message)), null);
    assert.doesNotMatch(JSON.stringify(error), /amazonaws|secret|certificate|private/i);
    return true;
  });
});

test("AWS CLI control plane accepts the runtime's public ACP trace vocabulary", async () => {
  let current = 0;
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    now: () => current,
    sleep: async () => { current = 2000; },
    executor: async (_file, argv) => {
      const role = argv.some((value) => value.includes("/responder")) ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [{
        timestamp: 1786565101000,
        message: JSON.stringify({
          schema: "clockchain.mechanics-proof-party-event/v1",
          runId: "11111111-2222-4333-8444-555555555555",
          role,
          sequence: "1",
          type: "agent.client.started",
          evidenceDigest: "1".repeat(64),
        }),
      }] }), stderr: "", exitCode: 0 };
    },
  });

  await assert.rejects(() => control.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId: "11111111-2222-4333-8444-555555555555",
    startTimeMs: 0,
    deadlineMs: 1000,
  }), (error) => {
    assert.deepEqual(publicPartyProgressStages(error), {
      initiator: "agent.client.started",
      responder: "agent.client.started",
    });
    assert.equal(publicControlPlaneFailureStage(error), null);
    return true;
  });
});

test("AWS CLI control plane brands a malformed public log line without retaining its contents", async () => {
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async () => ({
      stdout: JSON.stringify({ events: [{ timestamp: 1786565101000, message: "private malformed log contents" }] }),
      stderr: "",
      exitCode: 0,
    }),
  });

  await assert.rejects(() => control.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId: "11111111-2222-4333-8444-555555555555",
    startTimeMs: 0,
    deadlineMs: Date.now() + 1000,
  }), (error) => {
    assert.equal(publicControlPlaneFailureStage(error), "event-json");
    assert.equal(publicControlPlaneFailureStage(new Error(error.message)), null);
    assert.equal(JSON.stringify(error).includes("private malformed log contents"), false);
    return true;
  });
});

test("AWS CLI control plane exposes fixed public-log validation stages only", async () => {
  const timestamp = Date.now();
  const cases = [
    [{ events: "not-an-array" }, "logs-envelope"],
    [{ events: [], nextToken: "opaque" }, "logs-pagination"],
    [{ events: [{ timestamp: "not-an-integer", message: "{}" }] }, "event-timestamp"],
    [{ events: [{ timestamp, message: 7 }] }, "event-message"],
    [{ events: [{ timestamp, message: "Mechanics proof party failed safely. stage=private" }] }, "party-failure-stage"],
    [{ events: [{ timestamp, message: JSON.stringify({ schema: "clockchain.mechanics-proof-ecs-attestation/v1" }) }] }, "attestation-shape"],
    [{ events: [{ timestamp, message: JSON.stringify({ schema: "clockchain.mechanics-proof-party-event/v1" }) }] }, "progress-shape"],
    [{ events: [{ timestamp, message: JSON.stringify({ schema: "clockchain.mechanics-proof-party-evidence/v1" }) }] }, "evidence-shape"],
  ];

  for (const [body, expectedStage] of cases) {
    const control = createAwsCliControlPlane({
      region: "us-west-2",
      executor: async () => ({ stdout: JSON.stringify(body), stderr: "", exitCode: 0 }),
    });
    await assert.rejects(() => control.pollPublicEvents({
      logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
      runId: "11111111-2222-4333-8444-555555555555",
      startTimeMs: 0,
      deadlineMs: Date.now() + 1000,
    }), (error) => {
      assert.equal(publicControlPlaneFailureStage(error), expectedStage);
      assert.equal(JSON.stringify(error).includes("opaque"), false);
      return true;
    });
  }
});

test("AWS CLI control plane excludes stale same-run failures from a later cloud attempt", async () => {
  let current = 2_000;
  const calls = [];
  const runId = "11111111-2222-4333-8444-555555555555";
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    now: () => current,
    sleep: async () => { current = 4_000; },
    executor: async (_file, argv) => {
      calls.push(argv);
      const role = argv.some((value) => value.includes("/responder")) ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [{
        timestamp: 1_000,
        message: "Mechanics proof party failed safely. stage=runtime-run.transport-create",
      }, {
        timestamp: 2_001,
        message: JSON.stringify({
          schema: "clockchain.mechanics-proof-party-event/v1",
          runId,
          role,
          sequence: "1",
          type: "agent.starting",
          evidenceDigest: "1".repeat(64),
        }),
      }] }), stderr: "", exitCode: 0 };
    },
  });

  await assert.rejects(() => control.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId,
    startTimeMs: 2_000,
    deadlineMs: 3_000,
  }), (error) => {
    assert.equal(publicPartyFailureStages(error), null);
    assert.deepEqual(publicPartyProgressStages(error), {
      initiator: "agent.starting",
      responder: "agent.starting",
    });
    return true;
  });
  assert.equal(calls.every((argv) => argv.includes("--start-time") && argv[argv.indexOf("--start-time") + 1] === "2000"), true);
});

test("AWS CLI control plane reduces exact ECS attestations to a fixed public progress stage", async () => {
  let current = 0;
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    now: () => current,
    sleep: async () => { current = 2000; },
    executor: async (_file, argv) => {
      const role = argv.some((value) => value.includes("/responder")) ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [{
        timestamp: 1786565101000,
        message: JSON.stringify({
          schema: "clockchain.mechanics-proof-ecs-attestation/v1",
          accountId: "123456789012",
          availabilityZone: "us-west-2a",
          containerArn: `arn:aws:ecs:us-west-2:123456789012:container/cluster/task/${role}`,
          family: `clockchain-run-${role}`,
          imageId: `sha256:${"1".repeat(64)}`,
          launchType: "FARGATE",
          privateIp: role === "initiator" ? "10.0.2.10" : "10.0.3.10",
          region: "us-west-2",
          revision: "1",
          role,
          stsArn: `arn:aws:sts::123456789012:assumed-role/${role}/task`,
          stsUserId: `USER:${role}`,
          taskArn: `arn:aws:ecs:us-west-2:123456789012:task/cluster/${role}`,
          taskId: `task-${role}`,
          workloadAttestationDigest: "1".repeat(64),
        }),
      }] }), stderr: "", exitCode: 0 };
    },
  });

  await assert.rejects(() => control.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId: "11111111-2222-4333-8444-555555555555",
    startTimeMs: 0,
    deadlineMs: 1000,
  }), (error) => {
    assert.deepEqual(publicPartyProgressStages(error), {
      initiator: "ecs.attested",
      responder: "ecs.attested",
    });
    return true;
  });
});

test("AWS CLI control plane derives VPC inspection only from explicit subnet, route, and CIDR queries", async () => {
  const calls = [];
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (file, argv) => {
      calls.push(argv);
      const key = argv.slice(0, 2).join(" ");
      const body = key === "ec2 describe-vpcs"
        ? { Vpcs: [{ VpcId: "vpc-live", CidrBlockAssociationSet: [{ CidrBlock: "10.44.0.0/16" }] }] }
        : key === "ec2 describe-subnets"
          ? { Subnets: [
            { SubnetId: "subnet-public", VpcId: "vpc-live", CidrBlock: "10.44.1.0/24", AvailabilityZone: "us-west-2a", MapPublicIpOnLaunch: true },
            { SubnetId: "subnet-existing-private", VpcId: "vpc-live", CidrBlock: "10.44.32.0/24", AvailabilityZone: "us-west-2b", MapPublicIpOnLaunch: false },
          ] }
          : { RouteTables: [{ RouteTableId: "rtb-public", Routes: [{ DestinationCidrBlock: "0.0.0.0/0", GatewayId: "igw-live", State: "active" }], Associations: [{ SubnetId: "subnet-public" }] }] };
      return { stdout: JSON.stringify(body), stderr: "", exitCode: 0 };
    },
  });
  const inspection = await control.inspectNetwork({
    vpcId: "vpc-live",
    publicSubnetId: "subnet-public",
    initiatorPrivateCidr: "10.44.16.0/24",
    responderPrivateCidr: "10.44.17.0/24",
  });
  assert.equal(inspection.publicSubnet.mapPublicIpOnLaunch, true);
  assert.equal(inspection.publicSubnet.routeTableId, "rtb-public");
  assert.deepEqual(inspection.existingSubnets.map((subnet) => subnet.subnetId).sort(), ["subnet-existing-private", "subnet-public"]);
  assert.equal(calls.length, 3);
});

test("AWS CLI control plane reconciles run-scoped task definitions and tasks, then polls exact role log groups", async () => {
  const seen = [];
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    executor: async (file, argv) => {
      seen.push(argv);
      const key = argv.slice(0, argv[0] === "ecs" && argv[1] === "wait" ? 3 : 2).join(" ");
      if (key === "cloudformation describe-stacks") return { stdout: JSON.stringify({ Stacks: [{ StackId: "stack-id", StackName: "clockchain-11111111-2222-4333-8444-555555555555", Outputs: [{ OutputKey: "ClusterArn", OutputValue: "cluster" }] }] }), stderr: "", exitCode: 0 };
      if (key === "ecs list-task-definitions") return { stdout: JSON.stringify({ taskDefinitionArns: ["arn:aws:ecs:us-west-2:123456789012:task-definition/clockchain-11111111-2222-4333-8444-555555555555-initiator:1"] }), stderr: "", exitCode: 0 };
      if (key === "ecs list-tasks") return { stdout: JSON.stringify({ taskArns: ["arn:aws:ecs:us-west-2:123456789012:task/cluster/task-i"] }), stderr: "", exitCode: 0 };
      if (key === "ecs describe-tasks") return { stdout: JSON.stringify({ tasks: [{ taskArn: "arn:aws:ecs:us-west-2:123456789012:task/cluster/task-i", startedBy: "11111111-2222-4333-8444-555555555555", group: "family:clockchain-11111111-2222-4333-8444-555555555555-initiator" }] }), stderr: "", exitCode: 0 };
      const role = argv.includes("/clockchain/mechanics-proof/run/responder") ? "responder" : "initiator";
      return { stdout: JSON.stringify({ events: [
        { timestamp: 1786565100000, message: JSON.stringify({ schema: "clockchain.fargate-runtime-attestation/v1", runId: "11111111-2222-4333-8444-555555555555" }) },
        { timestamp: 1786565101000, message: JSON.stringify({ schema: "clockchain.mechanics-proof-party-evidence/v1", runId: "11111111-2222-4333-8444-555555555555", protocolSessionId: "protocol-session-1", role, harness: role === "initiator" ? "codex" : "claude", runtimeId: `runtime-${role}`, workloadAttestationDigest: "1".repeat(64), peerRuntimeId: role === "initiator" ? "runtime-responder" : "runtime-initiator", bridgeEvidenceDigest: "2".repeat(64), harnessEvidenceDigest: "3".repeat(64), certificateProofDigest: "4".repeat(64), certificateDigest: "a".repeat(64), identity: {}, anchors: [], directDelivery: { acknowledged: true }, externalBusinessActionPerformed: false, terminalStatus: "completed", teardown: { completed: true } }) },
      ] }), stderr: "", exitCode: 0 };
    },
  });
  const stackName = "clockchain-11111111-2222-4333-8444-555555555555";
  assert.equal((await control.reconcileCreatedStack({ stackName })).clusterArn, "cluster");
  assert.deepEqual(await control.reconcileTaskDefinitions({ stackName }), [{ role: "initiator", taskDefinitionArn: "arn:aws:ecs:us-west-2:123456789012:task-definition/clockchain-11111111-2222-4333-8444-555555555555-initiator:1" }]);
  assert.deepEqual(await control.reconcileTasks({ stackName, cluster: "cluster" }), [{ role: "initiator", taskArn: "arn:aws:ecs:us-west-2:123456789012:task/cluster/task-i" }]);
  const events = await control.pollPublicEvents({ logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"], runId: "11111111-2222-4333-8444-555555555555", startTimeMs: 0, deadlineMs: Date.now() + 1000 });
  assert.equal(events.length, 2);
  assert.equal(seen.some((argv) => argv.includes("--started-by") && argv.includes("11111111-2222-4333-8444-555555555555")), true);
});

test("AWS CLI control plane log polling rejects conflicting duplicate terminal roles deterministically", async () => {
  let slept = 0;
  const terminal = (digest) => ({ schema: "clockchain.mechanics-proof-party-evidence/v1", runId: "11111111-2222-4333-8444-555555555555", protocolSessionId: "protocol-session-1", role: "initiator", harness: "codex", runtimeId: "runtime-initiator", workloadAttestationDigest: "1".repeat(64), peerRuntimeId: "runtime-responder", bridgeEvidenceDigest: "2".repeat(64), harnessEvidenceDigest: "3".repeat(64), certificateProofDigest: "4".repeat(64), certificateDigest: digest, identity: {}, anchors: [], directDelivery: { acknowledged: true }, externalBusinessActionPerformed: false, terminalStatus: "completed", teardown: { completed: true } });
  const control = createAwsCliControlPlane({
    region: "us-west-2",
    now: () => 1000 + slept,
    sleep: async (ms) => { slept += ms; },
    executor: async () => ({ stdout: JSON.stringify({ events: [
      { message: JSON.stringify(terminal("a".repeat(64))) },
      { message: JSON.stringify(terminal("b".repeat(64))) },
    ] }), stderr: "", exitCode: 0 }),
  });
  await assert.rejects(() => control.pollPublicEvents({
    logGroupNames: ["/clockchain/mechanics-proof/run/initiator", "/clockchain/mechanics-proof/run/responder"],
    runId: "11111111-2222-4333-8444-555555555555",
    startTimeMs: 0,
    deadlineMs: 2000,
  }), /AWS CLI control-plane validation failed safely/);
});
