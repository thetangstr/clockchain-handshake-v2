import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_EVIDENCE_SCHEMA,
  createLocalRuntimeAdapter,
  validateRuntimeEvidence,
  validateRuntimePairEvidence,
} from "../src/runtime/runtime-adapter-contract.mjs";

const DIGEST = "a".repeat(64);
const OTHER_DIGEST = "b".repeat(64);
const SESSION = "11111111-2222-4333-8444-555555555555";

function evidence(role, overrides = {}) {
  return {
    schema: RUNTIME_EVIDENCE_SCHEMA,
    runtimeId: `runtime-${role}`,
    role,
    taskArn: `arn:aws:ecs:us-west-2:123456789012:task/cluster/${role}`,
    taskStatus: "STOPPED",
    createdAtMs: 1786337000000,
    stoppedAtMs: 1786337100000,
    taskRoleArn: `arn:aws:iam::123456789012:role/${role}-task`,
    executionRoleArn: `arn:aws:iam::123456789012:role/${role}-execution`,
    inTaskStsCallerIdentity: {
      account: "123456789012",
      arn: `arn:aws:sts::123456789012:assumed-role/${role}-task/session`,
      userId: `ARO${role.toUpperCase()}:session`,
    },
    imageDigest: `${role === "initiator" ? "sha256:" + DIGEST : "sha256:" + OTHER_DIGEST}`,
    taskDefinitionArn: `arn:aws:ecs:us-west-2:123456789012:task-definition/${role}:1`,
    taskDefinitionRevision: "1",
    taskDefinitionDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
    eniId: `eni-${role}`,
    subnetId: `subnet-${role}`,
    securityGroupIds: [`sg-${role}`],
    writableVolumeSummary: { ephemeral: true, sharedWritable: false },
    sharedEfsMounts: [],
    secretArnDigests: [role === "initiator" ? DIGEST : OTHER_DIGEST],
    credentialRefDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
    workspaceRootDigest: `${role === "initiator" ? "c" : "d"}`.repeat(64),
    stateRootDigest: `${role === "initiator" ? "e" : "f"}`.repeat(64),
    signerRootDigest: `${role === "initiator" ? "1" : "2"}`.repeat(64),
    logStreamDigests: [`${role === "initiator" ? "3" : "4"}`.repeat(64)],
    cloudTrailEventDigests: [`${role === "initiator" ? "5" : "6"}`.repeat(64)],
    ecsDescribeTasksDigest: `${role === "initiator" ? "7" : "8"}`.repeat(64),
    cleanupEvidenceDigest: `${role === "initiator" ? "9" : "0"}`.repeat(64),
    sessionSanitizationDigest: `${role === "initiator" ? "a" : "b"}`.repeat(64),
    ...overrides,
  };
}

test("runtime evidence requires collected control-plane fields rather than self claims", () => {
  const verified = validateRuntimeEvidence(evidence("initiator"));
  assert.equal(verified.schema, RUNTIME_EVIDENCE_SCHEMA);
  assert.equal(verified.taskStatus, "STOPPED");

  for (const candidate of [
    { schema: RUNTIME_EVIDENCE_SCHEMA, runtimeId: "r", role: "initiator", attested: true, cleanup: true },
    evidence("initiator", { attested: true }),
    evidence("initiator", { cloudTrailEventDigests: [] }),
    evidence("initiator", { ecsDescribeTasksDigest: true }),
    evidence("initiator", { sharedEfsMounts: ["fs-123"] }),
    evidence("initiator", { taskStatus: "RUNNING" }),
    evidence("initiator", { stoppedAtMs: null }),
  ]) {
    assert.throws(() => validateRuntimeEvidence(candidate));
  }
});

test("runtime pair evidence rejects shared workload, credential, state, and signer roots", () => {
  const pair = validateRuntimePairEvidence({
    initiator: evidence("initiator"),
    responder: evidence("responder"),
  });
  assert.notEqual(pair.initiator.taskRoleArn, pair.responder.taskRoleArn);

  for (const [field, value] of [
    ["taskRoleArn", evidence("initiator").taskRoleArn],
    ["credentialRefDigest", evidence("initiator").credentialRefDigest],
    ["workspaceRootDigest", evidence("initiator").workspaceRootDigest],
    ["stateRootDigest", evidence("initiator").stateRootDigest],
    ["signerRootDigest", evidence("initiator").signerRootDigest],
  ]) {
    assert.throws(() => validateRuntimePairEvidence({
      initiator: evidence("initiator"),
      responder: evidence("responder", { [field]: value }),
    }));
  }
});

test("local runtime adapter shim emits contract-shaped collected evidence", async () => {
  const adapter = createLocalRuntimeAdapter({ sourceCommit: "1".repeat(40) });
  const provisioned = await Promise.all(["initiator", "responder"].map((role) =>
    adapter.provisionPartyRuntime({
      sessionId: SESSION,
      role,
      harness: role === "initiator" ? "codex" : "claude",
      secretsRef: `secret-${role}`,
      networkPolicy: { mcp: "dedicated" },
      ttlMs: 60_000,
      costTags: { phase: "test" },
    })));
  for (const runtime of provisioned) {
    await adapter.attestRuntime({ runtimeId: runtime.runtimeId });
    await adapter.terminateRuntime({ runtimeId: runtime.runtimeId, reason: "test" });
    await adapter.destroyRuntime({ runtimeId: runtime.runtimeId });
  }
  const pair = validateRuntimePairEvidence({
    initiator: await adapter.collectRuntimeEvidence({ runtimeId: provisioned[0].runtimeId }),
    responder: await adapter.collectRuntimeEvidence({ runtimeId: provisioned[1].runtimeId }),
  });
  assert.equal(pair.initiator.role, "initiator");
  assert.equal(pair.responder.role, "responder");
});

test("local runtime adapter factory rejects authority-bearing private fields", () => {
  for (const options of [
    { privateKey: "0x" + "a".repeat(64) },
    { signer: { privateKey: "secret" } },
    { overrides: { initiator: { controllerPrivateKey: "secret" } } },
  ]) {
    assert.throws(() => createLocalRuntimeAdapter(options));
  }
});
