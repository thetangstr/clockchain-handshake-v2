import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { EventEmitter } from "node:events";
import { test } from "node:test";

import {
  buildHermesPrompt,
  readKimiCredential,
  runHermesDemo,
} from "../src/core/hermes-launcher.mjs";

const KIT_URL = "https://github.com/thetangstr/clockchain-handshake-v2.git";
const KIT_COMMIT = "0123456789abcdef0123456789abcdef01234567";
const HERMES = "/Users/maxiaoer/.local/bin/hermes";
const KIMI = "kimi-secret-AAAAAAAAAAAAAAAAAAAAAAAA";
const TOKEN_A = "cc_payer_AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TOKEN_B = "cc_requestor_BBBBBBBBBBBBBBBBBBBBBBBB";

async function tempRoot(t) {
  const root = await mkdtemp(join(tmpdir(), "hermes-launcher-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return resolve(root);
}

async function writePrivateCredential(t, value = KIMI) {
  const root = await tempRoot(t);
  const path = join(root, "kimi.key");
  await writeFile(path, value, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

async function makePrepared(root, role) {
  const roleRoot = join(root, "roles", role);
  const workspace = join(roleRoot, "workspace");
  const evidencePrivate = join(roleRoot, "private-evidence");
  await mkdir(workspace, { recursive: true, mode: 0o700 });
  await mkdir(evidencePrivate, { recursive: true, mode: 0o700 });
  const preProvisionPath = join(evidencePrivate, "pre-provision.json");
  await writeFile(
    preProvisionPath,
    JSON.stringify({
      phase: "pre-provision",
      role,
      tokensPresent: false,
      zeroState: { clean: true },
    }),
    { mode: 0o600 },
  );
  return {
    role,
    roleRoot,
    paths: { evidencePrivate, workspace },
    manifests: { preProvisionPath },
  };
}

function success(role, overrides = {}) {
  const common = {
    sessionId: "session-123",
    certificateDigest: "f".repeat(64),
    certificateVerified: true,
    paymentMoved: false,
  };
  return {
    ...common,
    role,
    address: role === "payer"
      ? "0x1111111111111111111111111111111111111111"
      : "0x2222222222222222222222222222222222222222",
    agentId: role === "payer" ? "agent-payer" : "agent-requestor",
    receipts: [`receipt-${role}`],
    ...overrides,
  };
}

function fakeProcess({ role, output, exitCode = 0, delayMs = 0, spawnLog }) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = (signal) => {
    spawnLog.kills.push({ role, signal });
    child.killed = true;
    return true;
  };
  queueMicrotask(() => {
    if (output !== undefined) child.stdout.emit("data", Buffer.from(`${output}\n`));
    setTimeout(() => child.emit("close", exitCode, null), delayMs);
  });
  return child;
}

function harness(root, t, options = {}) {
  const calls = {
    checkKit: [],
    minted: [],
    prepared: [],
    provisioned: [],
    spawns: [],
    kills: [],
    cleaned: [],
  };
  const prepared = {};
  const provisioned = {};
  const outputs = {
    payer: JSON.stringify(success("payer")),
    requestor: JSON.stringify(success("requestor")),
    ...options.outputs,
  };

  return {
    calls,
    options: {
      checkKit: async (kit) => {
        calls.checkKit.push(kit);
        return true;
      },
      cleanRoom: async ({ roleRoot }) => {
        calls.cleaned.push(roleRoot);
        await rm(roleRoot, { recursive: true, force: true });
      },
      hermesBinary: HERMES,
      inferenceKeyName: "KIMI_API_KEY",
      inferenceKeyValue: KIMI,
      kitCommit: KIT_COMMIT,
      kitUrl: KIT_URL,
      localDebug: options.localDebug ?? false,
      mintDemoToken: async ({ subject }) => {
        calls.minted.push(subject);
        if (options.tokens) return options.tokens[calls.minted.length - 1];
        return calls.minted.length === 1 ? TOKEN_A : TOKEN_B;
      },
      prepareHermesCleanRoom: async ({ role }) => {
        const room = await makePrepared(root, role);
        prepared[role] = room;
        calls.prepared.push({ role, room });
        return room;
      },
      provisionHermesCleanRoom: async ({ prepared: room, role, clockchainMcpToken, inferenceKeyValue }) => {
        const provisionedRoom = {
          ...room,
          env: {
            AUXILIARY_CLOCKCHAIN_MCP_API_KEY: clockchainMcpToken,
            HERMES_HOME: join(room.roleRoot, "hermes-home"),
            HOME: join(room.roleRoot, "home"),
            KIMI_API_KEY: inferenceKeyValue,
            PATH: "/usr/bin:/bin",
          },
          manifests: {
            ...room.manifests,
            prePromptPath: join(room.paths.evidencePrivate, "pre-prompt.json"),
          },
        };
        await writeFile(
          provisionedRoom.manifests.prePromptPath,
          JSON.stringify({ phase: "pre-prompt", role, tokenSha256: "not-a-token" }),
          { mode: 0o600 },
        );
        provisioned[role] = provisionedRoom;
        calls.provisioned.push({ role, token: clockchainMcpToken, room: provisionedRoom });
        return provisionedRoom;
      },
      runId: "run-abc",
      runRoot: root,
      spawnProcess: (command, args, spawnOptions) => {
        const role = spawnOptions.cwd.includes("/payer/") ? "payer" : "requestor";
        calls.spawns.push({ role, command, args, options: spawnOptions });
        return fakeProcess({
          role,
          output: outputs[role],
          exitCode: options.exitCodes?.[role] ?? 0,
          delayMs: options.delays?.[role] ?? 0,
          spawnLog: calls,
        });
      },
      timeoutMs: options.timeoutMs ?? 2_000,
      ...options.extra,
    },
    prepared,
    provisioned,
  };
}

test("mints two distinct tokens only after both pre-provision manifests exist, then starts both roles concurrently", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, { delays: { payer: 25, requestor: 25 } });

  const result = await runHermesDemo(h.options);

  assert.deepEqual(h.calls.prepared.map((entry) => entry.role), ["payer", "requestor"]);
  assert.equal(h.calls.prepared.every(({ room }) => room.manifests.preProvisionPath.endsWith("pre-provision.json")), true);
  assert.deepEqual(h.calls.minted, [
    "hermes-demo:run-abc:payer",
    "hermes-demo:run-abc:requestor",
  ]);
  assert.deepEqual(h.calls.provisioned.map((entry) => entry.role), ["payer", "requestor"]);
  assert.equal(h.calls.spawns.length, 2);
  assert.equal(h.calls.spawns[0].role, "payer");
  assert.equal(h.calls.spawns[1].role, "requestor");
  assert.equal(result.summary.sessionId, "session-123");
  assert.equal(result.summary.certificateVerified, true);
  assert.equal(result.summary.paymentMoved, false);
  assert.notEqual(result.summary.payer.address, result.summary.requestor.address);
  assert.notEqual(result.summary.payer.agentId, result.summary.requestor.agentId);
});

test("malformed, equal, or mismatched tokens abort before either agent starts", async (t) => {
  for (const tokens of [["bad token"], [TOKEN_A, TOKEN_A]]) {
    const root = await tempRoot(t);
    const h = harness(root, t, { tokens });
    await assert.rejects(
      runHermesDemo(h.options),
      /Hermes demo failed safely/,
    );
    assert.equal(h.calls.spawns.length, 0);
  }
});

test("launches Hermes with exact one-shot args and each child receives only its own provisioned env", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t);

  await runHermesDemo(h.options);

  for (const call of h.calls.spawns) {
    assert.equal(call.command, HERMES);
    assert.equal(call.args[0], "-z");
    assert.match(call.args[1], /prompt\.md$/);
    assert.deepEqual(call.args.slice(2), [
      "--usage-file",
      join(root, "roles", call.role, "private-evidence", "usage.json"),
      "--ignore-rules",
      "--provider",
      "kimi-coding",
      "-m",
      "k3",
      "-t",
      "terminal,file,clockchain",
    ]);
    const banned = ["-p", "--profile", "--resume", "--continue", "--safe-mode", "--skills", "--worktree", "--ignore-user-config"];
    for (const flag of banned) assert.equal(call.args.includes(flag), false);
    assert.equal(call.options.detached, true);
    assert.equal(call.options.cwd, join(root, "roles", call.role, "workspace"));
    assert.equal(call.options.env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY, call.role === "payer" ? TOKEN_A : TOKEN_B);
    assert.equal(call.options.env.KIMI_API_KEY, KIMI);
    assert.deepEqual(Object.keys(call.options.env).sort(), [
      "AUXILIARY_CLOCKCHAIN_MCP_API_KEY",
      "HERMES_HOME",
      "HOME",
      "KIMI_API_KEY",
      "PATH",
    ]);
  }
});

test("invalid output, collisions, mismatches, partial failure, and timeouts fail without authorization claims", async (t) => {
  const cases = [
    { outputs: { payer: "prose only" } },
    { outputs: { requestor: JSON.stringify(success("requestor", { address: "0x1111111111111111111111111111111111111111" })) } },
    { outputs: { requestor: JSON.stringify(success("requestor", { certificateDigest: "e".repeat(64) })) } },
    { outputs: { payer: JSON.stringify(success("payer", { certificateVerified: false })) } },
    { outputs: { requestor: JSON.stringify(success("requestor", { paymentMoved: true })) } },
    { exitCodes: { payer: 1 } },
    { delays: { payer: 50, requestor: 50 }, timeoutMs: 1 },
  ];
  for (const bad of cases) {
    const root = await tempRoot(t);
    const h = harness(root, t, bad);
    await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
    const evidencePath = join(root, "evidence", "result.json");
    try {
      const evidence = await readFile(evidencePath, "utf8");
      assert.equal(/AUTHORIZED/i.test(evidence), false);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
});

test("retained evidence is public-only, finalized before cleanup, and byte-for-byte canary clean", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    outputs: {
      payer: `debug ${TOKEN_A}\n${JSON.stringify(success("payer"))}`,
      requestor: `secret ${KIMI}\n${JSON.stringify(success("requestor"))}`,
    },
  });

  const result = await runHermesDemo(h.options);

  assert.equal(h.calls.cleaned.length, 2);
  for (const role of ["payer", "requestor"]) {
    await assert.rejects(readdir(join(root, "roles", role)), /ENOENT/);
  }
  const retained = await readFile(result.evidencePath, "utf8");
  assert.equal(retained.includes(TOKEN_A), false);
  assert.equal(retained.includes(TOKEN_B), false);
  assert.equal(retained.includes(KIMI), false);
  assert.equal(retained.includes("debug cc_payer"), false);
  assert.match(retained, /tokenSha256/);
  assert.match(retained, /certificateDigest/);
  assert.match(retained, /paymentMoved/);
});

test("dry-run prepares zero-state rooms and checks kit but mints no token and starts no agent", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, { extra: { dryRun: true } });

  const result = await runHermesDemo(h.options);

  assert.equal(result.dryRun, true);
  assert.equal(h.calls.checkKit.length, 1);
  assert.deepEqual(h.calls.prepared.map((entry) => entry.role), ["payer", "requestor"]);
  assert.equal(h.calls.minted.length, 0);
  assert.equal(h.calls.spawns.length, 0);
});

test("production wrapper rejects keep-cleanrooms unless local debug is explicit", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, { extra: { keepCleanrooms: true } });
  await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);

  const debug = harness(await tempRoot(t), t, {
    localDebug: true,
    extra: { keepCleanrooms: true },
  });
  await runHermesDemo(debug.options);
  assert.equal(debug.calls.cleaned.length, 0);
});

test("kit URL and commit are validated before prompt creation", () => {
  assert.throws(
    () => buildHermesPrompt({ role: "payer", kitUrl: "https://github.com/thetangstr/clockchain-handshake-v2.git", kitCommit: "abc" }),
    /Hermes demo failed safely/,
  );
  assert.throws(
    () => buildHermesPrompt({ role: "payer", kitUrl: "file:///tmp/repo.git", kitCommit: KIT_COMMIT }),
    /Hermes demo failed safely/,
  );
  const prompt = buildHermesPrompt({ role: "payer", kitUrl: KIT_URL, kitCommit: KIT_COMMIT });
  assert.match(prompt, new RegExp(KIT_COMMIT));
  assert.match(prompt, /paymentMoved:false/);
});

test("credential reader accepts exactly one supported env var or one private file and never searches", async (t) => {
  assert.deepEqual(
    await readKimiCredential({ env: { KIMI_API_KEY: KIMI } }),
    { keyName: "KIMI_API_KEY", value: KIMI },
  );
  assert.deepEqual(
    await readKimiCredential({ env: { KIMI_CODING_API_KEY: KIMI } }),
    { keyName: "KIMI_CODING_API_KEY", value: KIMI },
  );
  await assert.rejects(
    readKimiCredential({ env: { KIMI_API_KEY: KIMI, KIMI_CODING_API_KEY: "other" } }),
    /Hermes demo failed safely/,
  );
  const file = await writePrivateCredential(t);
  assert.deepEqual(
    await readKimiCredential({ credentialFile: file, env: {} }),
    { keyName: "KIMI_API_KEY", value: KIMI },
  );
  await chmod(file, 0o644);
  await assert.rejects(readKimiCredential({ credentialFile: file, env: {} }), /Hermes demo failed safely/);
});
