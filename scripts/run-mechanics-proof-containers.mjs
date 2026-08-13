#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const ERROR = "Mechanics proof container runner failed safely.";
const MCP_ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const DIGEST = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IMAGE = /^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$/;
const MAX_ENV_FILE_BYTES = 64 * 1024;
const ROLES = Object.freeze(["initiator", "responder"]);
const HARNESSES = Object.freeze({ initiator: "codex", responder: "claude" });
const MANIFEST_DIGEST = "fa3c408a3739227b5bdb71486b4d291b8f4dffdb0d1f2fa79dd59644ba5e09ad";

function fail() { throw new Error(ERROR); }
function sanitize(error) { if (error?.message === ERROR) throw error; fail(); }
function digest(value) { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }

function exact(value, required, optional = []) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const keys = Object.keys(value);
  const allowed = [...required, ...optional];
  if (keys.some((key) => !allowed.includes(key))) fail();
  for (const key of required) if (!Object.hasOwn(value, key)) fail();
  return value;
}

function cleanPath(value) {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || value.includes("\0")) fail();
  return value;
}

function parseArgs(argv) {
  if (!Array.isArray(argv) || argv.length < 3) fail();
  const args = argv.slice(2);
  const mode = args.shift();
  if (!["--dry-run", "--run"].includes(mode)) fail();
  const parsed = { mode };
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (typeof key !== "string" || !key.startsWith("--") || typeof value !== "string") fail();
    if (Object.hasOwn(parsed, key)) fail();
    parsed[key] = value;
  }
  const required = [
    "--app-image", "--mcp-endpoint", "--initiator-env-file", "--responder-env-file",
    "--evidence-dir", "--ttl-seconds", "--max-concurrency",
  ];
  for (const key of required) if (typeof parsed[key] !== "string") fail();
  if (!IMAGE.test(parsed["--app-image"]) || parsed["--mcp-endpoint"] !== MCP_ENDPOINT) fail();
  if (parsed["--ttl-seconds"] !== "600" || parsed["--max-concurrency"] !== "2") fail();
  const initiatorEnvFile = cleanPath(parsed["--initiator-env-file"]);
  const responderEnvFile = cleanPath(parsed["--responder-env-file"]);
  if (initiatorEnvFile === responderEnvFile) fail();
  return Object.freeze({
    mode: mode.slice(2),
    appImage: parsed["--app-image"],
    mcpEndpoint: parsed["--mcp-endpoint"],
    evidenceDir: cleanPath(parsed["--evidence-dir"]),
    envFiles: Object.freeze({ initiator: initiatorEnvFile, responder: responderEnvFile }),
    ttlSeconds: 600,
    maxConcurrency: 2,
  });
}

async function validateEnvFileRefs(envFiles) {
  const result = {};
  const identities = [];
  for (const role of ROLES) {
    const file = cleanPath(envFiles[role]);
    const metadata = await lstat(file).catch(fail);
    if (
      !metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 ||
      metadata.size > MAX_ENV_FILE_BYTES
    ) fail();
    if (process.platform !== "win32") {
      if ((metadata.mode & 0o077) !== 0) fail();
      if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) fail();
    }
    result[role] = file;
    identities.push(`${metadata.dev}:${metadata.ino}`);
  }
  if (identities[0] === identities[1]) fail();
  return Object.freeze(result);
}

function cleanBootstrap(value, role, runId) {
  const item = exact(value, ["bootstrapPublicKey", "harness", "role", "runId", "runtime", "schema", "tlsCertificate"]);
  if (item.schema !== "clockchain.mechanics-proof-party-bootstrap/v1" || item.role !== role || item.runId !== runId || item.harness !== HARNESSES[role]) fail();
  const runtime = exact(item.runtime, ["endpoint", "runtimeId", "taskId", "tlsCertificateSha256", "workloadAttestationDigest"]);
  if (!DIGEST.test(runtime.tlsCertificateSha256) || !DIGEST.test(runtime.workloadAttestationDigest)) fail();
  for (const key of ["endpoint", "runtimeId", "taskId"]) if (typeof runtime[key] !== "string" || runtime[key].length === 0) fail();
  if (typeof item.bootstrapPublicKey !== "string" || typeof item.tlsCertificate !== "string") fail();
  return Object.freeze({ ...item, runtime: Object.freeze({ ...runtime }) });
}

function cleanEvent(value, role, runId) {
  const item = exact(value, ["evidenceDigest", "role", "runId", "schema", "sequence", "type"]);
  if (
    item.schema !== "clockchain.mechanics-proof-party-event/v1" || item.role !== role || item.runId !== runId ||
    typeof item.sequence !== "string" || !DIGEST.test(item.evidenceDigest) || typeof item.type !== "string"
  ) fail();
  return Object.freeze({ ...item });
}

function cleanDelivery(value, role) {
  const item = exact(value, ["acknowledged", "artifactDigest", "artifactType", "checkpointDigest", "messageDigests"]);
  if (
    item.acknowledged !== true || item.artifactType !== (role === "initiator" ? "proposal" : "acceptance") ||
    !DIGEST.test(item.artifactDigest) || !DIGEST.test(item.checkpointDigest) ||
    !Array.isArray(item.messageDigests) || item.messageDigests.length !== 2 ||
    item.messageDigests.some((entry) => typeof entry !== "string" || !DIGEST.test(entry))
  ) fail();
  return Object.freeze({ ...item, messageDigests: Object.freeze([...item.messageDigests]) });
}

function cleanIdentity(value) {
  const item = exact(value, ["erc8004", "policyDigest", "sessionKeyAddress"]);
  const erc = exact(item.erc8004, ["agentId", "chainId", "reference", "registrationBlock", "registrationTx", "registryAddress"]);
  if (
    typeof item.sessionKeyAddress !== "string" || !/^0x[0-9a-f]{40}$/.test(item.sessionKeyAddress) ||
    !DIGEST.test(item.policyDigest) || typeof erc.agentId !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(erc.agentId) ||
    erc.chainId !== "eip155:11155111" ||
    erc.registryAddress !== "0x8004a818bfb912233c491871b3d84c89a494bd9e" ||
    erc.reference !== `${erc.chainId}:${erc.registryAddress}:${erc.agentId}` || !/^0x[0-9a-f]{64}$/.test(erc.registrationTx) ||
    typeof erc.registrationBlock !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(erc.registrationBlock)
  ) fail();
  return Object.freeze({ sessionKeyAddress: item.sessionKeyAddress, policyDigest: item.policyDigest, erc8004: Object.freeze({ ...erc }) });
}

function cleanAnchors(value) {
  if (!Array.isArray(value) || value.length !== 3) fail();
  const kinds = ["proposal", "acceptance", "acknowledgment"];
  return Object.freeze(value.map((entry, index) => {
    const item = exact(entry, ["blockHeight", "digest", "kind", "ledgerId"]);
    if (item.kind !== kinds[index] || !DIGEST.test(item.digest) || !UUID.test(item.ledgerId) || !/^(?:0|[1-9][0-9]*)$/.test(item.blockHeight)) fail();
    return Object.freeze({ ...item });
  }));
}

function cleanTerminal(value, role, runId) {
  const item = exact(value, [
    "anchors", "bridgeEvidenceDigest", "certificateDigest", "certificateProofDigest", "directDelivery",
    "externalBusinessActionPerformed", "harness", "harnessEvidenceDigest", "identity", "peerRuntimeId",
    "protocolSessionId", "role", "runId", "runtimeId", "schema", "teardown", "terminalStatus",
    "workloadAttestationDigest",
  ]);
  if (
    item.schema !== "clockchain.mechanics-proof-party-evidence/v1" || item.role !== role || item.runId !== runId ||
    item.harness !== HARNESSES[role] || item.terminalStatus !== "completed" ||
    item.externalBusinessActionPerformed !== false || !UUID.test(item.protocolSessionId) ||
    !DIGEST.test(item.bridgeEvidenceDigest) || !DIGEST.test(item.harnessEvidenceDigest) ||
    !DIGEST.test(item.certificateProofDigest) || !DIGEST.test(item.certificateDigest) ||
    !DIGEST.test(item.workloadAttestationDigest) || item.teardown?.completed !== true
  ) fail();
  return Object.freeze({
    ...item,
    identity: cleanIdentity(item.identity),
    anchors: cleanAnchors(item.anchors),
    directDelivery: cleanDelivery(item.directDelivery, role),
    teardown: Object.freeze({ completed: true }),
  });
}

export function validateMechanicsProofContainerPair(input, { requireTeardown = true } = {}) {
  try {
    const item = exact(input, ["exits", "initiator", "responder", "teardownObserved"]);
    const initiator = cleanTerminal(item.initiator, "initiator", item.initiator.runId);
    const responder = cleanTerminal(item.responder, "responder", initiator.runId);
    const exits = exact(item.exits, ["initiator", "responder"]);
    if (
      responder.runId !== initiator.runId || responder.protocolSessionId !== initiator.protocolSessionId ||
      responder.certificateDigest !== initiator.certificateDigest ||
      digest(responder.anchors) !== digest(initiator.anchors) ||
      initiator.runtimeId === responder.runtimeId || initiator.peerRuntimeId !== responder.runtimeId ||
      responder.peerRuntimeId !== initiator.runtimeId ||
      initiator.workloadAttestationDigest === responder.workloadAttestationDigest ||
      initiator.identity.sessionKeyAddress === responder.identity.sessionKeyAddress ||
      initiator.identity.erc8004.agentId === responder.identity.erc8004.agentId ||
      initiator.directDelivery.acknowledged !== true || responder.directDelivery.acknowledged !== true ||
      exits.initiator?.code !== 0 || exits.responder?.code !== 0 ||
      (requireTeardown === true && item.teardownObserved !== true)
    ) fail();
    return Object.freeze({
      status: "verified",
      runId: initiator.runId,
      protocolSessionId: initiator.protocolSessionId,
      certificateDigest: initiator.certificateDigest,
      parties: Object.freeze({
        initiator: Object.freeze({ runtimeId: initiator.runtimeId, identity: initiator.identity }),
        responder: Object.freeze({ runtimeId: responder.runtimeId, identity: responder.identity }),
      }),
      receipts: initiator.anchors,
      directDeliveries: Object.freeze({ initiator: initiator.directDelivery, responder: responder.directDelivery }),
      externalBusinessActionPerformed: false,
      teardownObserved: item.teardownObserved === true,
    });
  } catch (error) { sanitize(error); }
}

function containerConfig({ config, networkId, role, runId }) {
  const peer = role === "initiator" ? "responder" : "initiator";
  const root = `/workspace/${role}`;
  return Object.freeze({
    role,
    name: `clockchain-mechanics-proof-${runId}-${role}`,
    image: config.appImage,
    readOnlyRootfs: true,
    root,
    network: networkId,
    networkAlias: `${role}.task.local`,
    envFile: config.envFiles[role],
    tmpfs: Object.freeze([
      " /workspace:rw,nosuid,nodev,exec,mode=700,uid=1000,gid=1000".trim(),
      " /tmp:rw,nosuid,nodev,noexec,mode=700,uid=1000,gid=1000".trim(),
    ]),
    mounts: Object.freeze([]),
    command: Object.freeze(["--run"]),
    labels: Object.freeze({
      "clockchain.mechanics-proof.run-id": runId,
      "clockchain.mechanics-proof.role": role,
    }),
    env: Object.freeze({
      CLOCKCHAIN_A2A_LISTEN_HOST: "0.0.0.0",
      CLOCKCHAIN_A2A_PORT: "8443",
      CLOCKCHAIN_A2A_PUBLIC_ENDPOINT: `https://${role}.task.local:8443`,
      CLOCKCHAIN_A2A_PEER_ENDPOINT: `https://${peer}.task.local:8443`,
      CLOCKCHAIN_CLIENT: HARNESSES[role],
      CLOCKCHAIN_HELPER_MANIFEST_DIGEST: MANIFEST_DIGEST,
      CLOCKCHAIN_MANDATE_JSON: JSON.stringify({
        reference: "northstar-harbor-demo",
        statement: "Confirm both agents agree to the same operational terms.",
        validForSeconds: "90",
        identityPolicy: {
          erc8004: "required_fresh",
          chainId: "eip155:11155111",
          registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
        },
      }),
      CLOCKCHAIN_MCP_URL: config.mcpEndpoint,
      CLOCKCHAIN_OPENSSL_PATH: "/usr/bin/openssl",
      CLOCKCHAIN_PARTY_ROOT: root,
      CLOCKCHAIN_ROLE: role,
      CLOCKCHAIN_RUN_ID: runId,
      CLOCKCHAIN_RUNTIME_ID: `runtime-${role}`,
      CLOCKCHAIN_TASK_ID: `task-${role}`,
      CLOCKCHAIN_WORKLOAD_ATTESTATION_DIGEST: digest({ image: config.appImage, role, runId }),
      ...(role === "initiator" ? { CLOCKCHAIN_CODEX_MODEL: "gpt-5.6-terra" } : {}),
    }),
  });
}

function timeoutAfter(ms) {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error("ttl expired")), ms).unref?.();
  });
}

export async function runMechanicsProofContainers({ argv = process.argv, docker, nowMs = Date.now, runId = randomUUID() } = {}) {
  try {
    const parsed = parseArgs(argv);
    const config = Object.freeze({ ...parsed, envFiles: await validateEnvFileRefs(parsed.envFiles) });
    if (!UUID.test(runId) || typeof nowMs !== "function") fail();
    const drySummary = Object.freeze({
      schema: "clockchain.mechanics-proof-two-container-plan/v1",
      mode: config.mode,
      imageDigest: config.appImage.slice(config.appImage.indexOf("@sha256:") + 8),
      mcpEndpointDigest: digest(config.mcpEndpoint),
      envFileDigests: Object.freeze({
        initiator: digest(config.envFiles.initiator),
        responder: digest(config.envFiles.responder),
      }),
      ttlSeconds: String(config.ttlSeconds),
      maxConcurrency: String(config.maxConcurrency),
      networkInternal: false,
      readOnlyRootfs: true,
      sharedVolumes: false,
    });
    if (config.mode === "dry-run") return drySummary;
    if (docker === undefined || docker === null) docker = createDockerCliDriver();
    await mkdir(config.evidenceDir, { recursive: true, mode: 0o700 });
    const network = await docker.createNetwork({
      name: `clockchain-mechanics-proof-${runId}`,
      driver: "bridge",
      internal: false,
      labels: { "clockchain.mechanics-proof.run-id": runId },
    });
    const containers = {};
    const attached = {};
    let proof = null;
    async function orchestrate() {
      for (const role of ROLES) {
        containers[role] = await docker.createContainer(containerConfig({ config, networkId: network.id, role, runId }));
      }
      for (const role of ROLES) attached[role] = await docker.startAttached(containers[role]);
      const bootstraps = {};
      for (const role of ROLES) bootstraps[role] = cleanBootstrap(await attached[role].readJsonLine(), role, runId);
      await attached.responder.writeJsonLine(bootstraps.initiator);
      const responderReady = cleanEvent(await attached.responder.readJsonLine(), "responder", runId);
      if (responderReady.type !== "a2a.listener.ready") fail();
      await attached.initiator.writeJsonLine(bootstraps.responder);
      const terminals = {};
      for (const role of ROLES) {
        for (;;) {
          const line = await attached[role].readJsonLine();
          if (line?.schema === "clockchain.mechanics-proof-party-event/v1") {
            cleanEvent(line, role, runId);
            continue;
          }
          terminals[role] = cleanTerminal(line, role, runId);
          break;
        }
      }
      const exits = {};
      for (const role of ROLES) exits[role] = await attached[role].waitExit();
      proof = validateMechanicsProofContainerPair({
        initiator: terminals.initiator,
        responder: terminals.responder,
        exits,
        teardownObserved: false,
      }, { requireTeardown: false });
    }
    try {
      await Promise.race([orchestrate(), timeoutAfter(config.ttlSeconds * 1000)]);
    } finally {
      const removals = await Promise.allSettled([
        ...[...ROLES].reverse().map((role) => containers[role] === undefined ? Promise.resolve() : docker.removeContainer(containers[role])),
        docker.removeNetwork(network),
      ]);
      const absence = await Promise.allSettled([
        ...[...ROLES].reverse().map((role) => containers[role] === undefined ? Promise.resolve() : docker.assertContainerAbsent(containers[role])),
        docker.assertNetworkAbsent(network),
      ]);
      if ([...removals, ...absence].some((result) => result.status === "rejected")) fail();
    }
    const summary = Object.freeze({ ...proof, teardownObserved: true });
    await writeFile(join(config.evidenceDir, "two-container-summary.json"), `${JSON.stringify(summary)}\n`, { flag: "wx", mode: 0o600 });
    return summary;
  } catch (error) { sanitize(error); }
}

export function createDockerCliDriver({ spawnImpl = spawn } = {}) {
  function run(args) {
    const child = spawnImpl("docker", args, { stdio: ["ignore", "pipe", "pipe"] });
    return new Promise((resolve, reject) => {
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
      child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8").slice(0, 4096); });
      child.on("error", reject);
      child.on("close", (code) => {
        if (code === 0) resolve(stdout.trim());
        else reject(new Error(stderr || "docker failed"));
      });
    });
  }
  function assertAbsent(args, missingMessages) {
    const child = spawnImpl("docker", args, { stdio: ["ignore", "pipe", "pipe"] });
    return new Promise((resolve, reject) => {
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => { stdout = `${stdout}${chunk.toString("utf8")}`.slice(0, 8192); });
      child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk.toString("utf8")}`.slice(0, 8192); });
      child.on("error", reject);
      child.on("close", (code) => {
        const cleanStdout = stdout.trim();
        const cleanStderr = stderr.trim();
        if (code === 0) {
          reject(new Error("Docker resource is still present."));
          return;
        }
        if ((cleanStdout === "" || cleanStdout === "[]") && missingMessages.includes(cleanStderr)) {
          resolve();
          return;
        }
        reject(new Error(cleanStderr || "Docker absence check failed."));
      });
    });
  }
  return Object.freeze({
    async createNetwork(input) {
      const id = await run([
        "network", "create", "--driver", input.driver, "--label", `clockchain.mechanics-proof.run-id=${input.labels["clockchain.mechanics-proof.run-id"]}`, input.name,
      ]);
      return Object.freeze({ id: id || input.name, name: input.name });
    },
    async createContainer(input) {
      const args = [
        "create", "--interactive", "--name", input.name, "--read-only", "--network", input.network,
        "--network-alias", input.networkAlias,
        "--env-file", input.envFile, "--label", `clockchain.mechanics-proof.run-id=${input.labels["clockchain.mechanics-proof.run-id"]}`,
        "--label", `clockchain.mechanics-proof.role=${input.role}`,
      ];
      for (const tmpfs of input.tmpfs) args.push("--tmpfs", tmpfs);
      for (const [key, value] of Object.entries(input.env)) args.push("--env", `${key}=${value}`);
      args.push(input.image, ...input.command);
      const id = await run(args);
      return Object.freeze({ id: id || input.name, role: input.role, name: input.name });
    },
    async startAttached(container) {
      const child = spawnImpl("docker", ["start", "--attach", "--interactive", container.name], { stdio: ["pipe", "pipe", "pipe"] });
      const lines = createInterface({ input: child.stdout });
      const iterator = lines[Symbol.asyncIterator]();
      let stderr = "";
      child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk.toString("utf8")}`.slice(0, 4096); });
      const exit = new Promise((resolve) => {
        child.on("error", () => resolve({ error: true }));
        child.on("close", (code) => resolve({ code }));
      });
      return Object.freeze({
        async readJsonLine() {
          const next = await iterator.next();
          if (next.done) fail();
          return JSON.parse(next.value);
        },
        async writeJsonLine(value) {
          child.stdin.end(`${JSON.stringify(value)}\n`);
        },
        async waitExit() {
          const result = await exit;
          if (result.error === true || !Number.isInteger(result.code)) throw new Error(stderr || "Docker attached process failed.");
          return Object.freeze({ code: result.code });
        },
        child,
      });
    },
    async removeContainer(container) { await run(["rm", "-f", container.name]); },
    async removeNetwork(network) { await run(["network", "rm", network.name ?? network.id]); },
    async assertContainerAbsent(container) {
      const name = container.name;
      await assertAbsent(["container", "inspect", name], [
        `Error: No such container: ${name}`,
        `Error response from daemon: No such container: ${name}`,
      ]);
    },
    async assertNetworkAbsent(network) {
      const name = network.name ?? network.id;
      await assertAbsent(["network", "inspect", name], [
        `Error: No such network: ${name}`,
        `Error response from daemon: network ${name} not found`,
      ]);
    },
  });
}

async function main() {
  try {
    const result = await runMechanicsProofContainers();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write(`${ERROR}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  await main();
}
