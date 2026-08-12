import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { chmod, link, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createDockerCliDriver,
  runMechanicsProofContainers,
  validateMechanicsProofContainerPair,
} from "../scripts/run-mechanics-proof-containers.mjs";

const IMAGE = `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-mechanics-proof@sha256:${"a".repeat(64)}`;
const MCP = "https://mcp.clockchain.network/handshake/mcp";
const RUN_ID = "11111111-2222-4333-8444-555555555555";
const SESSION_ID = "22222222-3333-4444-8555-666666666666";
const CERTIFICATE_DIGEST = "b".repeat(64);
const DIGEST = "c".repeat(64);
const OTHER_DIGEST = "d".repeat(64);
const THIRD_DIGEST = "e".repeat(64);

function terminal(role, overrides = {}) {
  const peer = role === "initiator" ? "responder" : "initiator";
  return {
    schema: "clockchain.mechanics-proof-party-evidence/v1",
    runId: RUN_ID,
    protocolSessionId: SESSION_ID,
    role,
    harness: role === "initiator" ? "codex" : "claude",
    runtimeId: `runtime-${role}`,
    workloadAttestationDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
    peerRuntimeId: `runtime-${peer}`,
    bridgeEvidenceDigest: DIGEST,
    harnessEvidenceDigest: OTHER_DIGEST,
    certificateProofDigest: DIGEST,
    certificateDigest: CERTIFICATE_DIGEST,
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
    anchors: [
      { blockHeight: "7010", digest: DIGEST, kind: "proposal", ledgerId: "33333333-4444-4555-8666-777777777770" },
      { blockHeight: "7011", digest: OTHER_DIGEST, kind: "acceptance", ledgerId: "33333333-4444-4555-8666-777777777771" },
      { blockHeight: "7012", digest: THIRD_DIGEST, kind: "acknowledgment", ledgerId: "33333333-4444-4555-8666-777777777772" },
    ],
    directDelivery: {
      acknowledged: true,
      artifactDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
      artifactType: role === "initiator" ? "proposal" : "acceptance",
      checkpointDigest: role === "initiator" ? OTHER_DIGEST : THIRD_DIGEST,
      messageDigests: role === "initiator" ? [DIGEST, OTHER_DIGEST] : [OTHER_DIGEST, THIRD_DIGEST],
    },
    externalBusinessActionPerformed: false,
    terminalStatus: "completed",
    teardown: { completed: true },
    ...overrides,
  };
}

function bootstrap(role) {
  return {
    schema: "clockchain.mechanics-proof-party-bootstrap/v1",
    runId: RUN_ID,
    role,
    harness: role === "initiator" ? "codex" : "claude",
    bootstrapPublicKey: `public-${role}`,
    tlsCertificate: `cert-${role}`,
    runtime: {
      endpoint: `https://${role}.task.local:8443`,
      runtimeId: `runtime-${role}`,
      taskId: `task-${role}`,
      tlsCertificateSha256: role === "initiator" ? DIGEST : OTHER_DIGEST,
      workloadAttestationDigest: role === "initiator" ? DIGEST : OTHER_DIGEST,
    },
  };
}

function event(role, type) {
  return {
    schema: "clockchain.mechanics-proof-party-event/v1",
    runId: RUN_ID,
    role,
    sequence: "1",
    type,
    evidenceDigest: DIGEST,
  };
}

function fakeDocker(calls) {
  const processes = {};
  return {
    async createNetwork(input) {
      calls.push(["network.create", input]);
      return { id: "network-id" };
    },
    async createContainer(input) {
      calls.push(["container.create", input]);
      return { id: `container-${input.role}`, role: input.role };
    },
    async attach(container) {
      calls.push(["container.attach", container]);
      const lines = [
        bootstrap(container.role),
        ...(container.role === "responder" ? [event("responder", "a2a.listener.ready")] : []),
        terminal(container.role),
      ];
      const writes = [];
      processes[container.role] = { writes };
      return {
        async readJsonLine() {
          const line = lines.shift();
          if (line === undefined) throw new Error("empty");
          return line;
        },
        async writeJsonLine(value) {
          writes.push(value);
          calls.push(["stdin.write", container.role, value.role]);
        },
        async waitExit() {
          calls.push(["container.exit", container.role]);
          return { code: 0 };
        },
      };
    },
    async start(container) {
      calls.push(["container.start", container.role]);
    },
    async removeContainer(container) {
      calls.push(["container.remove", container.role]);
    },
    async removeNetwork(network) {
      calls.push(["network.remove", network.id]);
    },
    async assertContainerAbsent(container) {
      calls.push(["container.absent", container.role]);
    },
    async assertNetworkAbsent(network) {
      calls.push(["network.absent", network.id]);
    },
    processes,
  };
}

async function privateEnvFiles(t, { sameInode = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), "mechanics-proof-env-files-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const initiator = join(root, "initiator.env");
  const responder = join(root, "responder.env");
  await writeFile(initiator, "CLOCKCHAIN_CODEX_AUTH_JSON_BASE64=placeholder\n", { mode: 0o600 });
  if (sameInode) {
    await link(initiator, responder);
  } else {
    await writeFile(responder, "CLAUDE_CODE_USE_BEDROCK=1\n", { mode: 0o600 });
  }
  await chmod(initiator, 0o600);
  if (!sameInode) await chmod(responder, 0o600);
  return { initiator, responder, root };
}

function successfulArgs(evidenceDir, envFiles) {
  return [
    "node", "runner", "--run",
    "--app-image", IMAGE,
    "--mcp-endpoint", MCP,
    "--initiator-env-file", envFiles.initiator,
    "--responder-env-file", envFiles.responder,
    "--evidence-dir", evidenceDir,
    "--ttl-seconds", "600",
    "--max-concurrency", "2",
  ];
}

test("two-container controller enforces isolated roots, descriptor swap order, proof validation, and cleanup", async (t) => {
  const evidenceDir = await mkdtemp(join(tmpdir(), "mechanics-proof-two-container-"));
  t.after(() => rm(evidenceDir, { recursive: true, force: true }));
  const envFiles = await privateEnvFiles(t);
  const calls = [];
  const docker = fakeDocker(calls);
  const summary = await runMechanicsProofContainers({
    argv: successfulArgs(evidenceDir, envFiles),
    docker,
    nowMs: () => 1786337160000,
    runId: RUN_ID,
  });
  assert.equal(summary.status, "verified");
  assert.equal(summary.certificateDigest, CERTIFICATE_DIGEST);
  assert.equal(summary.receipts.length, 3);
  assert.equal(summary.externalBusinessActionPerformed, false);
  assert.equal(summary.teardownObserved, true);
  assert.doesNotMatch(JSON.stringify(summary), /init\.env|resp\.env|secret|transcript|prompt|checkpoint.*payload/i);

  const created = calls.filter((call) => call[0] === "container.create").map((call) => call[1]);
  assert.equal(created.length, 2);
  assert.equal(new Set(created.map((entry) => entry.root)).size, 2);
  assert.equal(new Set(created.map((entry) => entry.envFile)).size, 2);
  for (const config of created) {
    assert.equal(config.image, IMAGE);
    assert.equal(config.readOnlyRootfs, true);
    assert.equal(config.network, "network-id");
    assert.equal(config.networkAlias, `${config.role}.task.local`);
    assert.deepEqual(config.mounts, []);
    assert.deepEqual(config.command, ["--run"]);
    assert.equal("user" in config, false);
    assert.equal(config.tmpfs.some((entry) => entry.startsWith("/workspace:rw,nosuid,nodev,exec")), true);
    assert.equal(config.tmpfs.some((entry) => entry.startsWith("/tmp:rw,nosuid,nodev,noexec")), true);
    assert.equal(config.env.CLOCKCHAIN_MCP_URL, MCP);
    assert.equal(config.env.CLOCKCHAIN_PARTY_ROOT, `/workspace/${config.role}`);
    assert.equal(typeof config.env.CLOCKCHAIN_MANDATE_JSON, "string");
    assert.match(config.env.CLOCKCHAIN_WORKLOAD_ATTESTATION_DIGEST, /^[0-9a-f]{64}$/);
    assert.equal(config.labels["clockchain.mechanics-proof.run-id"], RUN_ID);
    assert.equal(Object.values(config.env).some((value) => /secret|token|key/i.test(String(value))), false);
  }
  assert.equal(calls.findIndex((call) => call[0] === "container.start" && call[1] === "responder") <
    calls.findIndex((call) => call[0] === "stdin.write" && call[1] === "initiator"), true);
  assert.deepEqual(calls.filter((call) => call[0] === "container.remove").map((call) => call[1]).sort(), ["initiator", "responder"]);
  assert.deepEqual(calls.filter((call) => call[0] === "container.absent").map((call) => call[1]).sort(), ["initiator", "responder"]);
  assert.equal(calls.at(-1)[0], "network.absent");
});

test("two-container dry-run validates immutable inputs without touching Docker or leaking credential refs", async (t) => {
  const evidenceDir = await mkdtemp(join(tmpdir(), "mechanics-proof-two-container-dry-"));
  t.after(() => rm(evidenceDir, { recursive: true, force: true }));
  const envFiles = await privateEnvFiles(t);
  const summary = await runMechanicsProofContainers({
    argv: [
      "node", "runner", "--dry-run",
      "--app-image", IMAGE,
      "--mcp-endpoint", MCP,
      "--initiator-env-file", envFiles.initiator,
      "--responder-env-file", envFiles.responder,
      "--evidence-dir", evidenceDir,
      "--ttl-seconds", "600",
      "--max-concurrency", "2",
    ],
  });
  assert.equal(summary.schema, "clockchain.mechanics-proof-two-container-plan/v1");
  assert.equal(summary.mode, "dry-run");
  assert.equal(summary.networkInternal, false);
  assert.equal(summary.sharedVolumes, false);
  assert.doesNotMatch(JSON.stringify(summary), /initiator\.env|responder\.env|secret|token|credential/i);
  await assert.rejects(
    () => runMechanicsProofContainers({
      argv: [
        "node", "runner", "--dry-run",
        "--app-image", "node:24",
        "--mcp-endpoint", MCP,
        "--initiator-env-file", envFiles.initiator,
        "--responder-env-file", envFiles.responder,
        "--evidence-dir", evidenceDir,
        "--ttl-seconds", "600",
        "--max-concurrency", "2",
      ],
    }),
    /Mechanics proof container runner failed safely/,
  );
});

test("two-container env-file refs are private regular distinct files for dry-run and run", async (t) => {
  const evidenceDir = await mkdtemp(join(tmpdir(), "mechanics-proof-two-container-env-reject-"));
  t.after(() => rm(evidenceDir, { recursive: true, force: true }));
  const safe = await privateEnvFiles(t);
  const open = await privateEnvFiles(t);
  await chmod(open.initiator, 0o640);
  await assert.rejects(
    () => runMechanicsProofContainers({ argv: successfulArgs(evidenceDir, open).with(2, "--dry-run") }),
    /Mechanics proof container runner failed safely/,
  );
  const empty = await privateEnvFiles(t);
  await writeFile(empty.initiator, "", { mode: 0o600 });
  await assert.rejects(
    () => runMechanicsProofContainers({ argv: successfulArgs(evidenceDir, empty).with(2, "--dry-run") }),
    /Mechanics proof container runner failed safely/,
  );
  const hardlink = await privateEnvFiles(t, { sameInode: true });
  await assert.rejects(
    () => runMechanicsProofContainers({ argv: successfulArgs(evidenceDir, hardlink).with(2, "--dry-run") }),
    /Mechanics proof container runner failed safely/,
  );
  const symlinkCase = await privateEnvFiles(t);
  await rm(symlinkCase.responder);
  await symlink(safe.responder, symlinkCase.responder);
  await assert.rejects(
    () => runMechanicsProofContainers({ argv: successfulArgs(evidenceDir, symlinkCase).with(2, "--dry-run") }),
    /Mechanics proof container runner failed safely/,
  );
  const missing = { initiator: join(evidenceDir, "missing.env"), responder: safe.responder };
  await assert.rejects(
    () => runMechanicsProofContainers({ argv: successfulArgs(evidenceDir, missing).with(2, "--dry-run") }),
    /Mechanics proof container runner failed safely/,
  );
  const oversize = await privateEnvFiles(t);
  await writeFile(oversize.initiator, "A".repeat(65 * 1024), { mode: 0o600 });
  await assert.rejects(
    () => runMechanicsProofContainers({ argv: successfulArgs(evidenceDir, oversize).with(2, "--dry-run") }),
    /Mechanics proof container runner failed safely/,
  );
});

test("two-container controller does not retain verified evidence when exact teardown fails", async (t) => {
  const evidenceDir = await mkdtemp(join(tmpdir(), "mechanics-proof-two-container-teardown-"));
  t.after(() => rm(evidenceDir, { recursive: true, force: true }));
  const envFiles = await privateEnvFiles(t);
  const calls = [];
  const docker = fakeDocker(calls);
  docker.removeNetwork = async () => {
    calls.push(["network.remove.failed"]);
    throw new Error("network still exists");
  };
  await assert.rejects(
    () => runMechanicsProofContainers({
      argv: successfulArgs(evidenceDir, envFiles),
      docker,
      nowMs: () => 1786337160000,
      runId: RUN_ID,
    }),
    /Mechanics proof container runner failed safely/,
  );
  assert.deepEqual(calls.filter((call) => call[0] === "container.remove").map((call) => call[1]).sort(), ["initiator", "responder"]);
  await assert.rejects(() => readFile(join(evidenceDir, "two-container-summary.json")), { code: "ENOENT" });
});

test("two-container teardown fails if Docker reports removed resources still present", async (t) => {
  const evidenceDir = await mkdtemp(join(tmpdir(), "mechanics-proof-two-container-absent-"));
  t.after(() => rm(evidenceDir, { recursive: true, force: true }));
  const envFiles = await privateEnvFiles(t);
  const calls = [];
  const docker = fakeDocker(calls);
  docker.assertContainerAbsent = async (container) => {
    calls.push(["container.present", container.role]);
    if (container.role === "initiator") throw new Error("still present");
  };
  await assert.rejects(
    () => runMechanicsProofContainers({
      argv: successfulArgs(evidenceDir, envFiles),
      docker,
      nowMs: () => 1786337160000,
      runId: RUN_ID,
    }),
    /Mechanics proof container runner failed safely/,
  );
  assert.equal(calls.some((call) => call[0] === "network.absent"), true);
  await assert.rejects(() => readFile(join(evidenceDir, "two-container-summary.json")), { code: "ENOENT" });
});

test("real Docker driver argv includes per-role network aliases and not credential values", async () => {
  const calls = [];
  function fakeSpawn(command, args) {
    calls.push([command, args]);
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    queueMicrotask(() => {
      child.stdout.emit("data", Buffer.from("created-id\n"));
      child.emit("close", 0);
    });
    return child;
  }
  const driver = createDockerCliDriver({ spawnImpl: fakeSpawn });
  await driver.createContainer({
    role: "initiator",
    name: "container-name",
    image: IMAGE,
    readOnlyRootfs: true,
    network: "network-id",
    networkAlias: "initiator.task.local",
    envFile: "/private/tmp/private.env",
    tmpfs: ["/workspace:rw,nosuid,nodev,exec,mode=700,uid=1000,gid=1000"],
    labels: { "clockchain.mechanics-proof.run-id": RUN_ID, "clockchain.mechanics-proof.role": "initiator" },
    env: { CLOCKCHAIN_MCP_URL: MCP },
    command: ["--run"],
  });
  const args = calls[0][1];
  assert.equal(args.includes("--network-alias"), true);
  assert.equal(args[args.indexOf("--network-alias") + 1], "initiator.task.local");
  assert.equal(args.includes("--env-file"), true);
  assert.equal(args.includes("/private/tmp/private.env"), true);
  assert.doesNotMatch(args.join(" "), /secret|token|credential/i);
});

test("two-container proof rejects fake success missing required public proof", () => {
  assert.throws(
    () => validateMechanicsProofContainerPair({
      initiator: terminal("initiator", { certificateDigest: undefined }),
      responder: terminal("responder"),
      exits: { initiator: { code: 0 }, responder: { code: 0 } },
      teardownObserved: true,
    }),
    /Mechanics proof container runner failed safely/,
  );
  assert.throws(
    () => validateMechanicsProofContainerPair({
      initiator: terminal("initiator", { directDelivery: { acknowledged: false } }),
      responder: terminal("responder"),
      exits: { initiator: { code: 0 }, responder: { code: 0 } },
      teardownObserved: true,
    }),
    /Mechanics proof container runner failed safely/,
  );
  assert.throws(
    () => validateMechanicsProofContainerPair({
      initiator: terminal("initiator"),
      responder: terminal("responder"),
      exits: { initiator: { code: 0 }, responder: { code: 1 } },
      teardownObserved: true,
    }),
    /Mechanics proof container runner failed safely/,
  );
  assert.throws(
    () => validateMechanicsProofContainerPair({
      initiator: terminal("initiator", {
        identity: {
          ...terminal("initiator").identity,
          erc8004: { ...terminal("initiator").identity.erc8004, reference: "eip155:11155111:wrong:9452" },
        },
      }),
      responder: terminal("responder"),
      exits: { initiator: { code: 0 }, responder: { code: 0 } },
      teardownObserved: true,
    }),
    /Mechanics proof container runner failed safely/,
  );
  assert.throws(
    () => validateMechanicsProofContainerPair({
      initiator: terminal("initiator", {
        identity: {
          ...terminal("initiator").identity,
          erc8004: { ...terminal("initiator").identity.erc8004, agentId: "09452" },
        },
      }),
      responder: terminal("responder"),
      exits: { initiator: { code: 0 }, responder: { code: 0 } },
      teardownObserved: true,
    }),
    /Mechanics proof container runner failed safely/,
  );
});
