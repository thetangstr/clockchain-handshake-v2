import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
} from "../src/agent-handshake/v2/constants.mjs";
import {
  VERIFIED_HELPER_BOOTSTRAP,
  createVerifiedReleaseActionRecorder,
  verifiedReleaseActionRecorderFailureStage,
} from "../src/harness/verified-release-action-recorder.mjs";
import { createFreshAgentRun } from "../src/testing/fresh-agent-client.mjs";

const execFileAsync = promisify(execFile);
const SESSION = "11111111-2222-4333-8444-555555555555";
const HELPER_SOURCE = `process.stdout.write(${JSON.stringify(`${JSON.stringify({ ok: true, signed: "proposal" })}\n`)});\n`;

function releaseSourceFixture(helperSource = HELPER_SOURCE) {
  const helperDigest = createHash("sha256").update(helperSource).digest("hex");
  const manifest = JSON.stringify({
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    nodeRuntime: "24.9.0",
    assets: [{
      filename: "clockchain-agent-handshake.cjs",
      url: `${AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX}clockchain-agent-handshake.cjs`,
      byteLength: String(Buffer.byteLength(helperSource)),
      sha256: helperDigest,
    }],
  });
  return {
    helperSource,
    manifest,
    manifestDigest: createHash("sha256").update(manifest).digest("hex"),
    releaseAssets: {
      manifestBytes: Buffer.from(manifest),
      helperBytes: Buffer.from(helperSource),
    },
    fetchAsset: async (url) => Buffer.from(
      url.endsWith("/manifest.json") ? manifest : helperSource,
    ),
  };
}

function helperStep({ manifestDigest, payload, policyDigest, role = "initiator", sessionId = SESSION, operation = "init" }) {
  const suffix = payload === undefined ? "" : ` --payload-base64url ${payload}`;
  const command = `node --input-type=commonjs --eval '${VERIFIED_HELPER_BOOTSTRAP}' ${manifestDigest} ./manifest.json ./clockchain-agent-handshake.cjs ${operation} --state-dir "$TMPDIR/.clockchain/handshakes/${sessionId}/${role}"${suffix}`;
  const commandSha256 = createHash("sha256").update(command).digest("hex");
  const step = {
    approvalTool: "mcp__clockchain-local-adapter__authorize_local_action",
    commandLength: Buffer.byteLength(command),
    commandSha256,
    operation,
    role,
    sessionId,
    shellCommand: command,
  };
  if (policyDigest !== undefined) step.policyDigest = policyDigest;
  return step;
}

function signStep({ manifestDigest, role = "initiator", sessionId = SESSION }) {
  const payload = Buffer.from(JSON.stringify({
    operation: "proposal",
    role,
    sessionId,
  })).toString("base64url");
  return helperStep({ manifestDigest, payload, role, sessionId, operation: "sign" });
}

async function makeContext(t, { actionTtlMs, completionDeadlineMs, releaseAssets = true } = {}) {
  const parent = await mkdtemp(join(tmpdir(), "adapter-recorder-"));
  const socketRoot = await mkdtemp(join(tmpdir(), "adapter-socket-"));
  t.after(async () => {
    await rm(parent, { recursive: true, force: true });
    await rm(socketRoot, { recursive: true, force: true });
  });
  const run = await createFreshAgentRun({ parent });
  const workspace = run.roles.initiator.workspace;
  const tmp = join(workspace, ".tmp");
  await mkdir(tmp, { mode: 0o700 });
  const room = Object.freeze({ ...run.roles.initiator, tmp });
  const fixture = releaseSourceFixture();
  const options = {
    manifestDigest: fixture.manifestDigest,
    room,
    socketRoot,
  };
  if (actionTtlMs !== undefined) options.actionTtlMs = actionTtlMs;
  if (completionDeadlineMs !== undefined) options.completionDeadlineMs = completionDeadlineMs;
  if (releaseAssets) options.releaseAssets = fixture.releaseAssets;
  else options.fetchAsset = fixture.fetchAsset;
  const recorder = await createVerifiedReleaseActionRecorder(options);
  t.after(() => recorder.close().catch(() => {}));
  return { fixture, recorder, room, socketRoot, workspace, tmp };
}

function sendCompletion(socketPath, value) {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = createConnection(socketPath);
    let output = "";
    socket.setEncoding("utf8");
    socket.setTimeout(2_000, () => socket.destroy(new Error("timeout")));
    socket.on("connect", () => socket.write(`${JSON.stringify(value)}\n`));
    socket.on("data", (chunk) => { output += chunk; });
    socket.on("end", () => resolvePromise(JSON.parse(output)));
    socket.on("error", rejectPromise);
  });
}

test("verified release recorder exposes only the digest-bound authorization executable on PATH", async (t) => {
  const { recorder } = await makeContext(t);
  assert.equal(
    (await readdir(recorder.bin)).sort().join(","),
    "clockchain-agent-authorize,clockchain-agent-authorize.cjs",
  );
  const executable = await lstat(join(recorder.bin, "clockchain-agent-authorize"));
  assert.equal(executable.isFile(), true);
  assert.equal(executable.mode & 0o777, 0o500);
  const payload = await lstat(join(recorder.bin, "clockchain-agent-authorize.cjs"));
  assert.equal(payload.isFile(), true);
  assert.equal(payload.mode & 0o111, 0);
  await assert.rejects(
    () => execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), []),
    (error) => error.code === 86,
  );
  await assert.rejects(
    () => execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), ["not-a-digest"]),
    (error) => error.code === 86,
  );
});

test("authorization executable still runs under a type:module package scope", async (t) => {
  const { fixture, recorder, workspace } = await makeContext(t);
  await writeFile(join(workspace, "package.json"), '{"type":"module"}\n');
  const attempts = [
    () => execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), []),
    () => execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), ["e".repeat(64)]),
  ];
  for (const attempt of attempts) {
    await assert.rejects(attempt, (error) => {
      assert.equal(error.code, 86);
      assert.doesNotMatch(String(error.stderr), /require is not defined|import statement/);
      return true;
    });
  }
  // Positive path: the exact approval command runs the retained helper step
  // end-to-end through the launcher and consumes the action exactly once.
  const completions = [];
  recorder.setCompletionHandler(async (completion) => {
    completions.push(completion);
    return { accepted: true };
  });
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  const action = recorder.record(step);
  const executed = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  });
  assert.deepEqual(executed.publicResult, { ok: true, signed: "proposal" });
  assert.equal(executed.executed, true);
  assert.equal(completions.length, 1);
  assert.equal(completions[0].actionId, action.actionId);
  assert.equal((await readdir(recorder.pending)).length, 0);
  assert.deepEqual(await readdir(recorder.consumed), [`${step.commandSha256}.json`]);
  const replay = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(replay, "execution-action-replayed");
});

test("recorder refuses to retain an action before the completion handler is installed", async (t) => {
  const { fixture, recorder } = await makeContext(t);
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  assert.throws(() => recorder.record(step));
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const action = recorder.record(step);
  assert.equal(action.commandSha256, step.commandSha256);
});

test("recorder executes a retained action exactly once and reports the helper result", async (t) => {
  const { fixture, recorder, workspace, tmp } = await makeContext(t);
  const completions = [];
  recorder.setCompletionHandler(async (completion) => {
    completions.push(completion);
    return { accepted: true };
  });
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  const action = recorder.record(step);
  assert.equal((await readdir(recorder.pending)).join(","), `${step.commandSha256}.json`);
  const executed = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  });
  assert.deepEqual(executed.publicResult, { ok: true, signed: "proposal" });
  assert.equal(executed.executed, true);
  assert.equal(completions.length, 1);
  assert.equal(completions[0].actionId, action.actionId);
  assert.equal(completions[0].commandSha256, action.commandSha256);
  assert.equal((await readdir(recorder.pending)).length, 0);
  assert.deepEqual(await readdir(recorder.consumed), [`${step.commandSha256}.json`]);
  const stateDir = join(tmp, `.clockchain/handshakes/${SESSION}/initiator`);
  assert.equal((await stat(stateDir)).isDirectory(), true);
  assert.equal((await lstat(stateDir)).mode & 0o777, 0o700);
  assert.equal(workspace.includes(".clockchain-adapter"), false);
});

test("recorder rejects replay of a consumed digest and unknown digests", async (t) => {
  const { fixture, recorder } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  const action = recorder.record(step);
  await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  });
  const replay = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(replay, "execution-action-replayed");
  await assert.rejects(() => recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: "f".repeat(64),
    role: "initiator",
    sessionId: SESSION,
  }));
  await assert.rejects(
    () => execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), ["e".repeat(64)]),
    (error) => error.code === 86 && error.stderr.includes("HELPER_COMMAND_MISMATCH"),
  );
});

test("recorder refuses actions retained under a mismatched digest or expired TTL", async (t) => {
  const { fixture, recorder } = await makeContext(t, { actionTtlMs: 50 });
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  const tampered = { ...step, approvalTool: `mcp__clockchain-local-adapter__authorize_local_action ${"0".repeat(64)}` };
  assert.throws(() => recorder.record(tampered));
  const argForm = { ...step, approvalTool: "authorize_local_action" };
  assert.throws(() => recorder.record(argForm));
  const wrongRole = helperStep({ manifestDigest: fixture.manifestDigest, role: "responder" });
  wrongRole.role = "bogus";
  assert.throws(() => recorder.record(wrongRole));
  const action = recorder.record(step);
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 80));
  const expired = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(expired, "execution-action-expired");
});

test("recorder binds signed payloads and rejects foreign operations and state dirs", async (t) => {
  const { fixture, recorder } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const step = signStep({ manifestDigest: fixture.manifestDigest });
  const action = recorder.record(step);
  assert.equal(action.operation, "sign");
  const executed = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  });
  assert.equal(executed.publicResult.ok, true);
  const foreign = helperStep({ manifestDigest: fixture.manifestDigest, sessionId: "22222222-2222-4333-8444-555555555555" });
  const foreignCommand = foreign.shellCommand.replace(
    `/.clockchain/handshakes/${foreign.sessionId}/initiator`,
    `/.clockchain/handshakes/${SESSION}/initiator`,
  );
  const mismatched = {
    ...foreign,
    shellCommand: foreignCommand,
    commandSha256: createHash("sha256").update(foreignCommand).digest("hex"),
    commandLength: Buffer.byteLength(foreignCommand),
  };
  mismatched.approvalTool = "mcp__clockchain-local-adapter__authorize_local_action";
  assert.throws(() => recorder.record(mismatched));
});

test("recorder rejects malformed, tampered, and foreign completions on the private socket", async (t) => {
  const { fixture, recorder, socketRoot } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  const action = recorder.record(step);
  const socketPath = join(socketRoot, "completion.sock");
  const reply = await sendCompletion(socketPath, {
    actionId: action.actionId,
    actionNonce: "forged",
    commandSha256: action.commandSha256,
    requestDigest: action.requestDigest,
    result: { ok: true },
  });
  assert.deepEqual(reply, { accepted: false });
  const missing = await sendCompletion(socketPath, {
    actionId: "00000000-0000-0000-0000-000000000000",
    actionNonce: "forged",
    commandSha256: action.commandSha256,
    requestDigest: action.requestDigest,
    result: { ok: true },
  });
  assert.deepEqual(missing, { accepted: false });
});

test("recorder completion handler can reject a helper result before it is exposed", async (t) => {
  const { fixture, recorder } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: false }));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  const action = recorder.record(step);
  const stage = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(stage, "execution-completion-failed");
});

test("recorder fails a completion that never acknowledges within the deadline", async (t) => {
  const { fixture, recorder } = await makeContext(t, { completionDeadlineMs: 1_500 });
  recorder.setCompletionHandler(async () => new Promise(() => {}));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  const action = recorder.record(step);
  const stage = await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: action.role,
    sessionId: action.sessionId,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(stage, "execution-completion-failed");
});

test("recorder closes the completion socket without leaking the socket file", async (t) => {
  const { recorder, socketRoot } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const socketPath = join(socketRoot, "completion.sock");
  assert.equal((await lstat(socketPath)).isSocket(), true);
  await recorder.close();
  await assert.rejects(() => lstat(socketPath), (error) => error.code === "ENOENT");
});

test("recorder fetches and verifies release assets when none are supplied", async (t) => {
  const { recorder, workspace } = await makeContext(t, { releaseAssets: false });
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const manifest = JSON.parse((await readFile(join(workspace, "manifest.json"))).toString("utf8"));
  assert.equal(manifest.version, AGENT_HANDSHAKE_HELPER_VERSION);
});

test("recorder fails closed on digest, byteLength, and asset contract violations", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "adapter-recorder-bad-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const run = await createFreshAgentRun({ parent });
  const workspace = run.roles.initiator.workspace;
  const tmp = join(workspace, ".tmp");
  await mkdir(tmp, { mode: 0o700 });
  const room = Object.freeze({ ...run.roles.initiator, tmp });
  const good = releaseSourceFixture();
  const badByteLength = JSON.parse(good.manifest);
  badByteLength.assets[0].byteLength = String(Buffer.byteLength(good.helperSource) + 1);
  const badManifestBytes = Buffer.from(JSON.stringify(badByteLength));
  const cases = [
    { manifestDigest: "z".repeat(64), stage: "construction-options" },
    { manifestDigest: "f".repeat(64), stage: "release-assets" },
    {
      manifestDigest: createHash("sha256").update(badManifestBytes).digest("hex"),
      releaseAssets: { manifestBytes: badManifestBytes, helperBytes: Buffer.from(good.helperSource) },
      stage: "release-assets",
    },
    {
      manifestDigest: good.manifestDigest,
      releaseAssets: { manifestBytes: Buffer.from(good.manifest), helperBytes: Buffer.from("tampered") },
      stage: "release-assets",
    },
  ];
  for (const [index, entry] of cases.entries()) {
    const socketRoot = await mkdtemp(join(tmpdir(), "adapter-socket-"));
    t.after(() => rm(socketRoot, { recursive: true, force: true }));
    const stage = await createVerifiedReleaseActionRecorder({
      manifestDigest: entry.manifestDigest,
      releaseAssets: entry.releaseAssets ?? good.releaseAssets,
      room,
      socketRoot,
    }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
    assert.equal(stage, entry.stage, `case ${index}`);
  }
});

test("recorder refuses a room whose tmp is outside the workspace", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "adapter-recorder-room-"));
  const socketRoot = await mkdtemp(join(tmpdir(), "adapter-socket-"));
  t.after(async () => {
    await rm(parent, { recursive: true, force: true });
    await rm(socketRoot, { recursive: true, force: true });
  });
  const run = await createFreshAgentRun({ parent });
  const fixture = releaseSourceFixture();
  const stage = await createVerifiedReleaseActionRecorder({
    manifestDigest: fixture.manifestDigest,
    releaseAssets: fixture.releaseAssets,
    room: run.roles.initiator,
    socketRoot,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(stage, "construction-paths");
});

test("recorder stages ordered helperSteps and promotes one pending action per accepted completion", async (t) => {
  const { fixture, recorder } = await makeContext(t);
  const completions = [];
  recorder.setCompletionHandler(async (completion) => {
    completions.push(completion);
    return { accepted: true };
  });
  const steps = ["init", "policy", "inspect"].map((operation) =>
    helperStep({ manifestDigest: fixture.manifestDigest, operation }));
  const actions = steps.map((step) => recorder.record(step));
  assert.deepEqual(await readdir(recorder.pending), [`${steps[0].commandSha256}.json`]);
  const queued = (await readdir(recorder.queued)).sort();
  assert.equal(queued.length, 2);
  assert.deepEqual(queued.map((entry) => entry.slice(7)), steps.slice(1).map((step) => `${step.commandSha256}.json`));
  // A queued-but-not-promoted action is not executable.
  await assert.rejects(() => recorder.executeAuthorizedAction({
    actionId: actions[1].actionId,
    commandSha256: actions[1].commandSha256,
    role: "initiator",
    sessionId: SESSION,
  }));
  const results = [];
  for (let index = 0; index < actions.length; index += 1) {
    const executed = await recorder.executeAuthorizedAction({
      actionId: actions[index].actionId,
      commandSha256: actions[index].commandSha256,
      role: "initiator",
      sessionId: SESSION,
    });
    results.push(executed.operation);
    if (index + 1 < actions.length) {
      assert.deepEqual(await readdir(recorder.pending), [`${steps[index + 1].commandSha256}.json`]);
    }
  }
  assert.deepEqual(results, ["init", "policy", "inspect"]);
  assert.deepEqual(completions.map((completion) => completion.operation), ["init", "policy", "inspect"]);
  assert.equal((await readdir(recorder.pending)).length, 0);
  assert.equal((await readdir(recorder.queued)).length, 0);
  assert.deepEqual(
    (await readdir(recorder.consumed)).sort(),
    steps.map((step) => `${step.commandSha256}.json`).sort(),
  );
});

test("recorder does not promote the next queued action when completion fails", async (t) => {
  const { fixture, recorder } = await makeContext(t);
  recorder.setCompletionHandler(async () => { throw new Error("completion rejected"); });
  const steps = ["init", "inspect"].map((operation) =>
    helperStep({ manifestDigest: fixture.manifestDigest, operation }));
  const actions = steps.map((step) => recorder.record(step));
  const stage = await recorder.executeAuthorizedAction({
    actionId: actions[0].actionId,
    commandSha256: actions[0].commandSha256,
    role: "initiator",
    sessionId: SESSION,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(stage, "execution-completion-failed");
  assert.equal((await readdir(recorder.pending)).length, 0);
  assert.equal((await readdir(recorder.queued)).length, 1);
  // The failed action is consumed and the queued one is never promoted.
  assert.deepEqual(await readdir(recorder.consumed), [`${steps[0].commandSha256}.json`]);
  await assert.rejects(() => recorder.executeAuthorizedAction({
    actionId: actions[1].actionId,
    commandSha256: actions[1].commandSha256,
    role: "initiator",
    sessionId: SESSION,
  }));
});

test("adapter fails closed on zero pending, multiple pending, and malformed queue state", async (t) => {
  const { fixture, recorder, workspace } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const executable = join(recorder.bin, "clockchain-agent-authorize");
  const execEnv = { env: { ...process.env, PATH: `${recorder.bin}:${process.env.PATH ?? ""}` } };
  // Zero pending actions.
  await assert.rejects(
    () => execFileAsync(executable, [], { cwd: workspace, ...execEnv }),
    (error) => error.code === 86 && error.stderr.includes("HELPER_COMMAND_MISMATCH"),
  );
  // More than one pending action.
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  recorder.record(step);
  await writeFile(join(recorder.pending, `${"e".repeat(64)}.json`), "junk\n");
  await assert.rejects(
    () => execFileAsync(executable, [], { cwd: workspace, ...execEnv }),
    (error) => error.code === 86 && error.stderr.includes("HELPER_COMMAND_MISMATCH"),
  );
  await rm(join(recorder.pending, `${"e".repeat(64)}.json`));
  // Malformed queued entry name.
  await writeFile(join(recorder.queued, "not-a-queued-action.json"), "junk\n");
  await assert.rejects(
    () => execFileAsync(executable, [], { cwd: workspace, ...execEnv }),
    (error) => error.code === 86 && error.stderr.includes("HELPER_COMMAND_MISMATCH"),
  );
  await rm(join(recorder.queued, "not-a-queued-action.json"));
  // Unexpected non-.json entries fail closed in every private directory.
  for (const dir of [recorder.pending, recorder.queued, recorder.running, recorder.consumed]) {
    await writeFile(join(dir, "stray.txt"), "junk\n");
    await assert.rejects(
      () => execFileAsync(executable, [], { cwd: workspace, ...execEnv }),
      (error) => error.code === 86,
      `unexpected entry in ${dir} must fail closed`,
    );
    await rm(join(dir, "stray.txt"));
  }
  // A stale running entry blocks execution even while pending is valid.
  await writeFile(join(recorder.running, `${step.commandSha256}.99999.json`), "junk\n");
  await assert.rejects(
    () => execFileAsync(executable, [], { cwd: workspace, ...execEnv }),
    (error) => error.code === 86 && error.stderr.includes("HELPER_COMMAND_MISMATCH"),
  );
  await rm(join(recorder.running, `${step.commandSha256}.99999.json`));
  // Malformed pending envelope (unsigned garbage).
  await rm(join(recorder.pending, `${step.commandSha256}.json`));
  await writeFile(join(recorder.pending, `${"f".repeat(64)}.json`), "junk\n");
  await assert.rejects(
    () => execFileAsync(executable, [], { cwd: workspace, ...execEnv }),
    (error) => error.code === 86 && error.stderr.includes("HELPER_COMMAND_MISMATCH"),
  );
});

test("completion is rejected when promotion of the next queued action fails", async (t) => {
  const { fixture, recorder } = await makeContext(t);
  recorder.setCompletionHandler(async () => {
    // The pending slot is empty while the wrapper blocks on the completion
    // socket; inject an unexpected entry so promotion inside the accept path
    // throws and the completion is reported as rejected.
    await writeFile(join(recorder.pending, "stray.txt"), "junk\n");
    return { accepted: true };
  });
  const steps = ["init", "inspect"].map((operation) =>
    helperStep({ manifestDigest: fixture.manifestDigest, operation }));
  const actions = steps.map((step) => recorder.record(step));
  const stage = await recorder.executeAuthorizedAction({
    actionId: actions[0].actionId,
    commandSha256: actions[0].commandSha256,
    role: "initiator",
    sessionId: SESSION,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(stage, "execution-completion-failed");
  assert.deepEqual(await readdir(recorder.pending), ["stray.txt"]);
  assert.equal((await readdir(recorder.queued)).length, 1);
  assert.deepEqual(await readdir(recorder.consumed), [`${steps[0].commandSha256}.json`]);
});

test("replaying a consumed descriptor never executes the next pending action", async (t) => {
  const { fixture, recorder } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const steps = ["init", "inspect"].map((operation) =>
    helperStep({ manifestDigest: fixture.manifestDigest, operation }));
  const actions = steps.map((step) => recorder.record(step));
  await recorder.executeAuthorizedAction({
    actionId: actions[0].actionId,
    commandSha256: actions[0].commandSha256,
    role: "initiator",
    sessionId: SESSION,
  });
  assert.deepEqual(await readdir(recorder.pending), [`${steps[1].commandSha256}.json`]);
  const stage = await recorder.executeAuthorizedAction({
    actionId: actions[0].actionId,
    commandSha256: actions[0].commandSha256,
    role: "initiator",
    sessionId: SESSION,
  }).then(() => null, (error) => verifiedReleaseActionRecorderFailureStage(error));
  assert.equal(stage, "execution-action-replayed");
  // The replayed descriptor must not have executed action 2 under the wrong
  // requested identity — it remains pending and executes normally afterwards.
  assert.deepEqual(await readdir(recorder.pending), [`${steps[1].commandSha256}.json`]);
  assert.deepEqual(await readdir(recorder.consumed), [`${steps[0].commandSha256}.json`]);
  const second = await recorder.executeAuthorizedAction({
    actionId: actions[1].actionId,
    commandSha256: actions[1].commandSha256,
    role: "initiator",
    sessionId: SESSION,
  });
  assert.equal(second.operation, "inspect");
  assert.equal((await readdir(recorder.pending)).length, 0);
});

test("adapter refuses any argv including a digest argument", async (t) => {
  const { fixture, recorder, workspace } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  recorder.record(step);
  const executable = join(recorder.bin, "clockchain-agent-authorize");
  const execEnv = { env: { ...process.env, PATH: `${recorder.bin}:${process.env.PATH ?? ""}` } };
  for (const argv of [[step.commandSha256], ["inspect"], ["--help"]]) {
    await assert.rejects(
      () => execFileAsync(executable, argv, { cwd: workspace, ...execEnv }),
      (error) => error.code === 86 && error.stderr.includes("HELPER_COMMAND_MISMATCH"),
    );
  }
});

test("bare adapter command reports replay once the only action is consumed", async (t) => {
  const { fixture, recorder, workspace } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  const action = recorder.record(step);
  await recorder.executeAuthorizedAction({
    actionId: action.actionId,
    commandSha256: action.commandSha256,
    role: "initiator",
    sessionId: SESSION,
  });
  // The model-facing bare command still surfaces REPLAYED from the wrapper
  // when pending is empty but a consumed marker exists.
  await assert.rejects(
    () => execFileAsync(join(recorder.bin, "clockchain-agent-authorize"), [], {
      cwd: workspace,
      env: { ...process.env, PATH: `${recorder.bin}:${process.env.PATH ?? ""}` },
    }),
    (error) => error.code === 86 && error.stderr.includes("HELPER_ACTION_REPLAYED"),
  );
});

// Minimal stdio JSON-RPC client for the generated local adapter MCP server.
function mcpClient(t, serverPath, cwd, tmp) {
  const child = spawn(process.execPath, [serverPath], {
    cwd,
    env: { ...process.env, TMPDIR: tmp },
    stdio: ["pipe", "pipe", "pipe"],
  });
  t.after(() => { try { child.kill("SIGKILL"); } catch { /* already exited */ } });
  const pending = new Map();
  let nextId = 0;
  let buffer = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    const lines = buffer.split("\n");
    buffer = lines.pop();
    for (const line of lines) {
      if (line.trim().length === 0) continue;
      const message = JSON.parse(line);
      const entry = pending.get(message.id);
      if (entry) { pending.delete(message.id); entry(message); }
    }
  });
  return (method, params) => new Promise((resolvePromise, rejectPromise) => {
    const id = ++nextId;
    pending.set(id, resolvePromise);
    const timer = setTimeout(() => { pending.delete(id); rejectPromise(new Error("mcp timeout")); }, 10_000);
    pending.set(id, (message) => { clearTimeout(timer); resolvePromise(message); });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

test("local adapter MCP server lists one zero-input tool and executes ordered actions", async (t) => {
  const { fixture, recorder, tmp, workspace } = await makeContext(t);
  const completions = [];
  recorder.setCompletionHandler(async (completion) => {
    completions.push(completion);
    return { accepted: true };
  });
  const steps = ["init", "policy", "inspect"].map((operation) =>
    helperStep({ manifestDigest: fixture.manifestDigest, operation }));
  steps.forEach((step) => recorder.record(step));
  const call = mcpClient(t, recorder.mcpServer, workspace, tmp);
  const init = await call("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "0" } });
  assert.equal(init.result.serverInfo.name, "clockchain-local-adapter");
  const listed = await call("tools/list", {});
  assert.equal(listed.result.tools.length, 1);
  assert.equal(listed.result.tools[0].name, "authorize_local_action");
  assert.deepEqual(listed.result.tools[0].inputSchema, { type: "object", properties: {}, additionalProperties: false });
  const results = [];
  for (let index = 0; index < steps.length; index += 1) {
    const response = await call("tools/call", { name: "authorize_local_action", arguments: {} });
    assert.equal(response.result.isError ?? false, false);
    const text = response.result.content[0].text;
    results.push(JSON.parse(text).signed);
    if (index + 1 < steps.length) {
      assert.deepEqual(await readdir(recorder.pending), [`${steps[index + 1].commandSha256}.json`]);
    }
  }
  assert.deepEqual(results, ["proposal", "proposal", "proposal"]);
  assert.deepEqual(completions.map((completion) => completion.operation), ["init", "policy", "inspect"]);
  assert.equal((await readdir(recorder.pending)).length, 0);
});

test("local adapter MCP server rejects any tool input or unknown tool without executing", async (t) => {
  const { fixture, recorder, tmp, workspace } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  recorder.record(step);
  const call = mcpClient(t, recorder.mcpServer, workspace, tmp);
  await call("initialize", {});
  for (const params of [
    { name: "authorize_local_action", arguments: { digest: "0".repeat(64) } },
    { name: "authorize_local_action", arguments: { command: "init" } },
    { name: "authorize_local_action", arguments: ["init"] },
    { name: "authorize_local_action", extra: true },
    { name: "other_tool" },
  ]) {
    const response = await call("tools/call", params);
    assert.ok(response.error || response.result?.isError === true, JSON.stringify(params));
  }
  // Nothing executed: the action is still pending and unconsumed.
  assert.deepEqual(await readdir(recorder.pending), [`${step.commandSha256}.json`]);
  assert.equal((await readdir(recorder.consumed)).length, 0);
  const response = await call("tools/call", { name: "authorize_local_action" });
  assert.equal(response.result.isError ?? false, false);
});

test("local adapter MCP server surfaces rejection without executing on replay", async (t) => {
  const { fixture, recorder, tmp, workspace } = await makeContext(t);
  recorder.setCompletionHandler(async () => ({ accepted: true }));
  const step = helperStep({ manifestDigest: fixture.manifestDigest });
  recorder.record(step);
  const call = mcpClient(t, recorder.mcpServer, workspace, tmp);
  await call("initialize", {});
  const first = await call("tools/call", { name: "authorize_local_action" });
  assert.equal(first.result.isError ?? false, false);
  const replay = await call("tools/call", { name: "authorize_local_action" });
  assert.equal(replay.result.isError, true);
  assert.match(replay.result.content[0].text, /HELPER_ACTION_REPLAYED/);
});
