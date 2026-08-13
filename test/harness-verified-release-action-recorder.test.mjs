import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import test from "node:test";

import { validateRetainedLocalAction } from "../src/harness/harness-adapter-contract.mjs";
import { digestHex } from "../src/core/canonical.mjs";
import { createAcpProcessTransport } from "../src/harness/acp-process-transport.mjs";
import {
  createVerifiedReleaseActionRecorder,
  verifiedReleaseActionRecorderFailureStage,
} from "../src/harness/verified-release-action-recorder.mjs";
import { ACP_VERSION_PINS } from "../src/harness/version-pins.mjs";
import { createFreshAgentRun, VERIFIED_HELPER_BOOTSTRAP } from "../src/testing/fresh-agent-client.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

const execFileAsync = promisify(execFile);
const SESSION = "11111111-2222-4333-8444-555555555555";

function releaseFixture(result) {
  const helperSource = `process.stdout.write(${JSON.stringify(`${JSON.stringify(result)}\n`)});`;
  const helperDigest = createHash("sha256").update(helperSource).digest("hex");
  const manifest = JSON.stringify({
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: "2.1.3",
    nodeRuntime: "24.0.0",
    assets: [{
      filename: "clockchain-agent-handshake.cjs",
      url: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.3/clockchain-agent-handshake.cjs",
      sha256: helperDigest,
    }],
  });
  return {
    helperSource,
    manifest,
    manifestDigest: createHash("sha256").update(manifest).digest("hex"),
    fetchImpl: async (url) => ({
      ok: true,
      arrayBuffer: async () => Buffer.from(url.endsWith("/manifest.json") ? manifest : helperSource),
    }),
  };
}

function helperStep({ manifestDigest, payload, policyDigest = "c".repeat(64), role = "initiator", sessionId = SESSION }) {
  const command = `node --input-type=commonjs --eval '${VERIFIED_HELPER_BOOTSTRAP}' ${manifestDigest} ./manifest.json ./clockchain-agent-handshake.cjs sign --state-dir "$TMPDIR/.clockchain/handshakes/${sessionId}/${role}" --payload-base64url ${payload}`;
  const commandSha256 = createHash("sha256").update(command).digest("hex");
  return {
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
    commandLength: Buffer.byteLength(command),
    commandSha256,
    operation: "sign",
    policyDigest,
    role,
    sessionId,
    shellCommand: command,
  };
}

function policyHelperStep({ manifestDigest, policy }) {
  const payload = Buffer.from(JSON.stringify(policy), "utf8").toString("base64url");
  const command = `node --input-type=commonjs --eval '${VERIFIED_HELPER_BOOTSTRAP}' ${manifestDigest} ./manifest.json ./clockchain-agent-handshake.cjs policy --state-dir "$TMPDIR/.clockchain/handshakes/${SESSION}/initiator" --payload-base64url ${payload}`;
  const commandSha256 = createHash("sha256").update(command).digest("hex");
  return {
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
    commandLength: Buffer.byteLength(command),
    commandSha256,
    operation: "policy",
    role: "initiator",
    sessionId: SESSION,
    shellCommand: command,
  };
}

function sendCompletion(socketPath, value) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let output = "";
    socket.setEncoding("utf8");
    socket.setTimeout(1_000, () => socket.destroy(new Error("timeout")));
    socket.on("connect", () => socket.write(`${JSON.stringify(value)}\n`));
    socket.on("data", (chunk) => { output += chunk; });
    socket.on("end", () => resolve(JSON.parse(output)));
    socket.on("error", reject);
  });
}

test("verified release recorder exposes only the authorization command on the agent PATH", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "verified-release-path-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const run = await createFreshAgentRun({ parent });
  const fixture = releaseFixture({
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: "2.1.3",
    operation: "init",
  });
  const socketRoot = join("/tmp", `verified-path-${randomBytes(6).toString("hex")}`);
  t.after(() => rm(socketRoot, { recursive: true, force: true }));
  const recorder = await createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: run.roles.initiator,
    runtimeExecPath: process.execPath,
    socketRoot,
  });
  t.after(() => recorder.close());

  assert.deepEqual(await readdir(recorder.bin), ["clockchain-agent-authorize"]);
  await assert.rejects(lstat(join(recorder.bin, "node")), { code: "ENOENT" });
});

test("verified release recorder returns an ACP-valid action and privately correlates one helper completion", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "verified-release-recorder-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const run = await createFreshAgentRun({ parent });
  const signingFixture = await buildAgentCliFixture("initiator");
  const result = {
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: "2.1.3",
    operation: "sign",
    address: signingFixture.parties.initiator.sessionKeyAddress,
    bytesSha256: signingFixture.request.bytesSha256,
    signatureHex: `0x${"1".repeat(130)}`,
  };
  const fixture = releaseFixture(result);
  const socketRoot = join("/tmp", `verified-rec-${randomBytes(6).toString("hex")}`);
  t.after(() => rm(socketRoot, { recursive: true, force: true }));
  const signingRequest = Buffer.from(JSON.stringify(signingFixture.request));
  const step = helperStep({
    manifestDigest: fixture.manifestDigest,
    payload: signingRequest.toString("base64url"),
    policyDigest: signingFixture.request.policyDigest,
    role: signingFixture.request.role,
    sessionId: signingFixture.request.sessionId,
  });
  const recorder = await createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: run.roles.initiator,
    runtimeExecPath: process.execPath,
    socketRoot,
  });
  t.after(() => recorder.close());
  const completions = [];
  assert.throws(() => recorder.recordRetainedAction(step), /failed safely/);
  recorder.setCompletionHandler(async (completion) => {
    completions.push(completion);
    return { accepted: true };
  });
  const action = validateRetainedLocalAction(recorder.recordRetainedAction(step));
  assert.deepEqual(recorder.recordRetainedAction(step), action);
  assert.equal(action.adapterPublicKey, recorder.trustedAdapterPublicKey);
  assert.equal(action.requestDigest, createHash("sha256").update(signingRequest).digest("hex"));
  assert.equal(action.requestLength, signingRequest.length);
  const pendingEnvelope = JSON.parse(await readFile(join(recorder.pending, `${step.commandSha256}.json`), "utf8"));
  assert.deepEqual(await sendCompletion(pendingEnvelope.body.completionSocket, {
    actionId: action.actionId,
    actionNonce: "wrong-nonce",
    commandSha256: action.commandSha256,
    requestDigest: action.requestDigest,
    result,
  }), { accepted: false });
  const acp = createAcpProcessTransport({
    actionRecorder: recorder.actionRecorder,
    env: {},
    harness: "codex",
    home: run.roles.initiator.home,
    pin: ACP_VERSION_PINS.codex,
    retainedActions: [],
    retainedActionPolicy: () => ({ decision: "authorize" }),
    trustedAdapterPublicKeys: [recorder.trustedAdapterPublicKey],
    workspace: run.roles.initiator.workspace,
  });
  assert.equal(typeof acp.launch, "function");

  const { stdout } = await execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), [step.commandSha256], {
    cwd: run.roles.initiator.workspace,
    env: { ...process.env, PATH: `${recorder.bin}:${process.env.PATH}`, TMPDIR: run.roles.initiator.tmp },
  });
  assert.equal(stdout, `${JSON.stringify(result)}\n`);
  assert.equal(completions.length, 1);
  assert.deepEqual(completions[0].result, result);
  assert.equal(completions[0].commandSha256, step.commandSha256);
  assert.equal(completions[0].requestDigest, action.requestDigest);
  const socketRootStat = await lstat(socketRoot);
  assert.equal(socketRootStat.isDirectory(), true);
  assert.equal(socketRootStat.mode & 0o777, 0o700);
  await assert.rejects(
    execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), [step.commandSha256], {
      cwd: run.roles.initiator.workspace,
      env: { ...process.env, PATH: `${recorder.bin}:${process.env.PATH}`, TMPDIR: run.roles.initiator.tmp },
    }),
    /HELPER_ACTION_REPLAYED/,
  );
});

test("verified release recorder executes one authorized action by digest without a model-authored shell command", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "verified-release-driver-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const run = await createFreshAgentRun({ parent });
  const signingFixture = await buildAgentCliFixture("initiator");
  const result = {
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: "2.1.3",
    operation: "sign",
    address: signingFixture.parties.initiator.sessionKeyAddress,
    bytesSha256: signingFixture.request.bytesSha256,
    signatureHex: `0x${"1".repeat(130)}`,
  };
  const fixture = releaseFixture(result);
  const socketRoot = join("/tmp", `verified-driver-${randomBytes(6).toString("hex")}`);
  t.after(() => rm(socketRoot, { recursive: true, force: true }));
  const recorder = await createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: run.roles.initiator,
    runtimeExecPath: process.execPath,
    socketRoot,
  });
  t.after(() => recorder.close());
  const completions = [];
  recorder.setCompletionHandler(async (completion) => {
    completions.push(completion);
    return { accepted: true };
  });
  const request = Buffer.from(JSON.stringify(signingFixture.request));
  const step = helperStep({
    manifestDigest: fixture.manifestDigest,
    payload: request.toString("base64url"),
    policyDigest: signingFixture.request.policyDigest,
    role: signingFixture.request.role,
    sessionId: signingFixture.request.sessionId,
  });
  const action = recorder.recordRetainedAction(step);
  await chmod(join(recorder.bin, "clockchain-agent-authorize"), 0o400);
  const executed = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  });
  assert.deepEqual(executed, {
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    executed: true,
    operation: "sign",
    publicResult: result,
    role: "initiator",
    sessionId: signingFixture.request.sessionId,
  });
  assert.equal(completions.length, 1);
  assert.deepEqual(completions[0].result, result);
  await assert.rejects(() => recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  }));
});

test("verified release recorder exposes a fixed execution-launch stage", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "verified-release-exec-stage-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const run = await createFreshAgentRun({ parent });
  const signingFixture = await buildAgentCliFixture("initiator");
  const result = {
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: "2.1.3",
    operation: "sign",
    address: signingFixture.parties.initiator.sessionKeyAddress,
    bytesSha256: signingFixture.request.bytesSha256,
    signatureHex: `0x${"1".repeat(130)}`,
  };
  const fixture = releaseFixture(result);
  const socketRoot = join("/tmp", `verified-exec-stage-${randomBytes(6).toString("hex")}`);
  t.after(() => rm(socketRoot, { recursive: true, force: true }));
  const recorder = await createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: run.roles.initiator,
    runtimeExecPath: process.execPath,
    socketRoot,
  });
  t.after(() => recorder.close());
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const request = Buffer.from(JSON.stringify(signingFixture.request));
  const step = helperStep({
    manifestDigest: fixture.manifestDigest,
    payload: request.toString("base64url"),
    policyDigest: signingFixture.request.policyDigest,
    role: signingFixture.request.role,
    sessionId: signingFixture.request.sessionId,
  });
  const action = recorder.recordRetainedAction(step);
  await unlink(join(recorder.bin, "clockchain-agent-authorize"));
  await assert.rejects(() => recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  }), (error) => verifiedReleaseActionRecorderFailureStage(error) === "execution-launch");
});

test("verified release recorder binds the production policy payload to its canonical digest", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "verified-release-policy-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const run = await createFreshAgentRun({ parent });
  const fixture = releaseFixture({ schema: "clockchain.agent-handshake-cli-result/v1", operation: "policy" });
  const socketRoot = join("/tmp", `verified-policy-${randomBytes(6).toString("hex")}`);
  t.after(() => rm(socketRoot, { recursive: true, force: true }));
  const recorder = await createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: run.roles.initiator,
    runtimeExecPath: process.execPath,
    socketRoot,
  });
  t.after(() => recorder.close());
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const policy = {
    schema: "clockchain.agent-handshake-policy/v1",
    protocol: "clockchain.agent-handshake/v2",
    role: "initiator",
    mcpOrigin: "https://mcp.clockchain.network",
    reference: "NS-1847",
    statementDigest: "d".repeat(64),
    maxValidForSeconds: "90",
    identityPolicy: {
      erc8004: "required_existing_or_fresh",
      chainId: "eip155:11155111",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    },
    externalBusinessActionsAllowed: false,
  };
  const action = recorder.recordRetainedAction(policyHelperStep({ manifestDigest: fixture.manifestDigest, policy }));
  assert.equal(action.operation, "policy");
  assert.equal(action.policyDigest, digestHex(policy));
  assert.equal(action.sessionId, SESSION);
  assert.equal(action.role, "initiator");
});

test("verified release recorder rejects proxy and accessor authority without invoking it", async () => {
  let traps = 0;
  const hostileOptions = new Proxy({}, {
    ownKeys() {
      traps += 1;
      throw new Error("secret-canary");
    },
  });
  await assert.rejects(createVerifiedReleaseActionRecorder(hostileOptions), (error) => {
    assert.equal(error.message, "Verified release action recorder failed safely.");
    assert.doesNotMatch(error.message, /secret-canary/);
    return true;
  });
  assert.equal(traps, 0);

  const fixture = releaseFixture({ schema: "clockchain.agent-handshake-cli-result/v1", helperVersion: "2.1.3", operation: "init" });
  let getterCalls = 0;
  const room = Object.create(null, {
    workspace: { enumerable: true, get() { getterCalls += 1; throw new Error("secret-canary"); } },
    tmp: { enumerable: true, value: "/tmp/unused" },
  });
  await assert.rejects(createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room,
    socketRoot: "/tmp/unused-recorder-root",
  }), /failed safely/);
  assert.equal(getterCalls, 0);
});

test("verified release recorder brands only safe construction failure stages", async () => {
  const classify = verifiedReleaseActionRecorderFailureStage;
  const fixture = releaseFixture({
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: "2.1.3",
    operation: "init",
  });
  const parent = await mkdtemp(join(tmpdir(), "verified-release-stage-"));
  const workspace = join(parent, "workspace");
  const tmp = join(workspace, "tmp");
  await mkdir(workspace, { mode: 0o700 });
  await mkdir(tmp, { mode: 0o700 });
  try {
    let optionsFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        manifestDigest: "not-a-digest",
        room: { workspace, tmp },
        socketRoot: join(parent, "options-socket"),
      });
    } catch (error) { optionsFailure = error; }
    assert.equal(classify(optionsFailure), "construction-options");

    let roomFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        manifestDigest: fixture.manifestDigest,
        room: { workspace },
        socketRoot: join(parent, "room-socket"),
      });
    } catch (error) { roomFailure = error; }
    assert.equal(classify(roomFailure), "construction-room");

    let pathFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        manifestDigest: fixture.manifestDigest,
        room: { workspace, tmp: join(parent, "outside") },
        socketRoot: join(parent, "path-socket"),
      });
    } catch (error) { pathFailure = error; }
    assert.equal(classify(pathFailure), "construction-paths");

    let platformFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        manifestDigest: fixture.manifestDigest,
        platform: "unsupported",
        room: { workspace, tmp },
        socketRoot: join(parent, "platform-socket"),
      });
    } catch (error) { platformFailure = error; }
    assert.equal(classify(platformFailure), "construction-platform");

    let manifestFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        fetchImpl: async () => ({ ok: false, arrayBuffer: async () => Buffer.alloc(0) }),
        manifestDigest: fixture.manifestDigest,
        room: { workspace, tmp },
        socketRoot: join(parent, "manifest-socket"),
      });
    } catch (error) { manifestFailure = error; }
    assert.equal(manifestFailure?.message, "Verified release action recorder failed safely.");
    assert.equal(classify(manifestFailure), "release-manifest-fetch");
    assert.equal(classify(new Error(manifestFailure.message)), null);

    let helperFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        fetchImpl: async (url) => url.endsWith("/manifest.json")
          ? { ok: true, arrayBuffer: async () => Buffer.from(fixture.manifest) }
          : { ok: false, arrayBuffer: async () => Buffer.alloc(0) },
        manifestDigest: fixture.manifestDigest,
        room: { workspace, tmp },
        socketRoot: join(parent, "helper-socket"),
      });
    } catch (error) { helperFailure = error; }
    assert.equal(helperFailure?.message, "Verified release action recorder failed safely.");
    assert.equal(classify(helperFailure), "release-helper-fetch");

    const verifyWorkspace = join(parent, "verify-workspace");
    const verifyTmp = join(verifyWorkspace, "tmp");
    await mkdir(verifyWorkspace, { mode: 0o700 });
    await mkdir(verifyTmp, { mode: 0o700 });
    let releaseFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        fetchImpl: async () => ({ ok: true, arrayBuffer: async () => Buffer.from("wrong-release-bytes") }),
        manifestDigest: fixture.manifestDigest,
        room: { workspace: verifyWorkspace, tmp: verifyTmp },
        socketRoot: join(parent, "verify-socket"),
      });
    } catch (error) { releaseFailure = error; }
    assert.equal(classify(releaseFailure), "release-assets");

    const layoutWorkspace = join(parent, "layout-workspace");
    const layoutTmp = join(layoutWorkspace, "tmp");
    await mkdir(layoutWorkspace, { mode: 0o700 });
    await mkdir(layoutTmp, { mode: 0o700 });
    await writeFile(join(layoutWorkspace, ".clockchain-adapter"), "collision", { mode: 0o600 });
    let layoutFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        fetchImpl: fixture.fetchImpl,
        manifestDigest: fixture.manifestDigest,
        room: { workspace: layoutWorkspace, tmp: layoutTmp },
        socketRoot: join(parent, "layout-socket"),
      });
    } catch (error) { layoutFailure = error; }
    assert.equal(classify(layoutFailure), "adapter-layout");

    const socketWorkspace = join(parent, "socket-workspace");
    const socketTmp = join(socketWorkspace, "tmp");
    const unsafeSocket = join(parent, "unsafe-socket");
    await mkdir(socketWorkspace, { mode: 0o700 });
    await mkdir(socketTmp, { mode: 0o700 });
    await mkdir(unsafeSocket, { mode: 0o755 });
    let socketFailure;
    try {
      await createVerifiedReleaseActionRecorder({
        fetchImpl: fixture.fetchImpl,
        manifestDigest: fixture.manifestDigest,
        room: { workspace: socketWorkspace, tmp: socketTmp },
        socketRoot: unsafeSocket,
      });
    } catch (error) { socketFailure = error; }
    assert.equal(classify(socketFailure), "completion-socket");
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("verified release recorder withholds helper output when the private completion deadline expires", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "verified-release-deadline-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const run = await createFreshAgentRun({ parent });
  const signingFixture = await buildAgentCliFixture("initiator");
  const result = {
    schema: "clockchain.agent-handshake-cli-result/v1",
    helperVersion: "2.1.3",
    operation: "sign",
    address: signingFixture.parties.initiator.sessionKeyAddress,
    bytesSha256: signingFixture.request.bytesSha256,
    signatureHex: `0x${"2".repeat(130)}`,
  };
  const fixture = releaseFixture(result);
  const signingRequest = Buffer.from(JSON.stringify(signingFixture.request));
  const step = helperStep({
    manifestDigest: fixture.manifestDigest,
    payload: signingRequest.toString("base64url"),
    policyDigest: signingFixture.request.policyDigest,
    role: signingFixture.request.role,
    sessionId: signingFixture.request.sessionId,
  });
  const socketRoot = join("/tmp", `verified-rec-${randomBytes(6).toString("hex")}`);
  t.after(() => rm(socketRoot, { recursive: true, force: true }));
  const recorder = await createVerifiedReleaseActionRecorder({
    completionDeadlineMs: 50,
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: run.roles.initiator,
    socketRoot,
  });
  t.after(() => recorder.close());
  recorder.setCompletionHandler(() => new Promise(() => {}));
  recorder.recordRetainedAction(step);
  await assert.rejects(
    execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), [step.commandSha256], {
      cwd: run.roles.initiator.workspace,
      env: { ...process.env, PATH: `${recorder.bin}:${process.env.PATH}`, TMPDIR: run.roles.initiator.tmp },
    }),
    (error) => {
      assert.equal(error.stdout, "");
      assert.match(error.stderr, /HELPER_EXECUTION_FAILED/);
      return true;
    },
  );
});

test("verified release recorder accepts an existing private root and rejects unsafe socket roots", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "verified-release-root-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const run = await createFreshAgentRun({ parent });
  const fixture = releaseFixture({ schema: "clockchain.agent-handshake-cli-result/v1", helperVersion: "2.1.3", operation: "init" });
  const privateRoot = join("/tmp", `verified-rec-${randomBytes(6).toString("hex")}`);
  await mkdir(privateRoot, { mode: 0o700 });
  t.after(() => rm(privateRoot, { recursive: true, force: true }));
  const recorder = await createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: run.roles.initiator,
    socketRoot: privateRoot,
  });
  await recorder.close();
  assert.equal((await lstat(privateRoot)).isDirectory(), true);
  assert.deepEqual(await readdir(privateRoot), []);

  const unsafeRoot = join("/tmp", `verified-rec-${randomBytes(6).toString("hex")}`);
  await mkdir(unsafeRoot, { mode: 0o755 });
  await chmod(unsafeRoot, 0o755);
  t.after(() => rm(unsafeRoot, { recursive: true, force: true }));
  await assert.rejects(createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: run.roles.responder,
    socketRoot: unsafeRoot,
  }), /failed safely/);

  const collisionParent = await mkdtemp(join(tmpdir(), "verified-release-collision-"));
  const collisionRun = await createFreshAgentRun({ parent: collisionParent });
  t.after(() => rm(collisionParent, { recursive: true, force: true }));
  const collisionRoot = join("/tmp", `verified-rec-${randomBytes(6).toString("hex")}`);
  await mkdir(collisionRoot, { mode: 0o700 });
  await writeFile(join(collisionRoot, "completion.sock"), "not-a-socket", { mode: 0o600 });
  t.after(() => rm(collisionRoot, { recursive: true, force: true }));
  await assert.rejects(createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    room: collisionRun.roles.initiator,
    socketRoot: collisionRoot,
  }), /failed safely/);
});

test("verified release recorder rejects unsupported completion transports", async () => {
  const fixture = releaseFixture({ schema: "clockchain.agent-handshake-cli-result/v1", helperVersion: "2.1.3", operation: "init" });
  await assert.rejects(createVerifiedReleaseActionRecorder({
    fetchImpl: fixture.fetchImpl,
    manifestDigest: fixture.manifestDigest,
    platform: "win32",
    room: { workspace: "/tmp/workspace", tmp: "/tmp/workspace/tmp" },
    socketRoot: "/tmp/unsupported-recorder-root",
  }), /failed safely/);
});
