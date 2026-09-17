import assert from "node:assert/strict";
import { execFile } from "node:child_process";
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
    approvalCommand: `clockchain-agent-authorize ${commandSha256}`,
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
  const tampered = { ...step, approvalCommand: `clockchain-agent-authorize ${"0".repeat(64)}` };
  assert.throws(() => recorder.record(tampered));
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
  mismatched.approvalCommand = `clockchain-agent-authorize ${mismatched.commandSha256}`;
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
