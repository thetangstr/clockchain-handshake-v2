import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { EventEmitter } from "node:events";
import { test } from "node:test";

import { digestHex } from "../src/core/canonical.mjs";
import {
  buildHermesPrompt,
  readKimiCredential,
  runHermesDemo,
} from "../src/core/hermes-launcher.mjs";

const KIT_URL = "https://github.com/thetangstr/clockchain-handshake-v2.git";
const KIT_COMMIT = "0123456789abcdef0123456789abcdef01234567";
const HERMES = "/Users/maxiaoer/.local/bin/hermes";
const KIMI = "kimi-secret-AAAAAAAAAAAAAAAAAAAAAAAA";
const SESSION_ID = "123e4567-e89b-42d3-a456-426614174000";
const PAYER_ADDRESS = "0x1111111111111111111111111111111111111111";
const REQUESTOR_ADDRESS = "0x2222222222222222222222222222222222222222";
const PAYER_AGENT = "8677";
const REQUESTOR_AGENT = "9001";

function token(jti) {
  const payload = Buffer.from(JSON.stringify({ jti, sub: jti }), "utf8").toString("base64url");
  return `cc_${payload}.abcdefghijklmnopqrstuvwxyz`;
}

const TOKEN_A = token("payer-token");
const TOKEN_B = token("requestor-token");

function certificateResult(overrides = {}) {
  return {
    anchors: [
      {
        blockHeight: "100",
        blockTimeRaw: "2026-08-08T18:00:00.000Z",
        digest: "a".repeat(64),
        kind: "proposal",
        ledgerId: "123e4567-e89b-42d3-a456-426614174001",
      },
      {
        blockHeight: "101",
        blockTimeRaw: "2026-08-08T18:00:02.000Z",
        digest: "b".repeat(64),
        kind: "acceptance",
        ledgerId: "123e4567-e89b-42d3-a456-426614174002",
      },
      {
        blockHeight: "102",
        blockTimeRaw: "2026-08-08T18:00:04.000Z",
        digest: "c".repeat(64),
        kind: "acknowledgment",
        ledgerId: "123e4567-e89b-42d3-a456-426614174003",
      },
    ],
    disclaimer: "single-validator testnet, not court-grade",
    issuedAtMs: "1786212000000",
    outcome: "AUTHORIZED",
    parties: {
      payer: {
        address: PAYER_ADDRESS,
        agentId: PAYER_AGENT,
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${PAYER_AGENT}`,
      },
      payee: {
        address: REQUESTOR_ADDRESS,
        agentId: REQUESTOR_AGENT,
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${REQUESTOR_AGENT}`,
      },
    },
    paymentMoved: false,
    schema: "clockchain.handshake-result/v1",
    sessionDigest: "d".repeat(64),
    sessionId: SESSION_ID,
    subjectRun: "stakeholder",
    ...overrides,
  };
}

const CERT_RESULT = certificateResult();
const CERT_DIGEST = digestHex(CERT_RESULT);

async function tempRoot(t) {
  const root = await mkdtemp(join(tmpdir(), "hermes-launcher-"));
  await chmod(root, 0o700);
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

async function makePrepared(root, role, overrides = {}) {
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
      paths: { workspace: `roles/${role}/workspace` },
      tokensPresent: false,
      zeroState: { clean: true },
      ...overrides.preProvision,
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
  return {
    role,
    sessionId: SESSION_ID,
    address: role === "payer" ? PAYER_ADDRESS : REQUESTOR_ADDRESS,
    agentId: role === "payer" ? PAYER_AGENT : REQUESTOR_AGENT,
    certificateDigest: CERT_DIGEST,
    certificateVerified: true,
    paymentMoved: false,
    ...overrides,
  };
}

function terminal(role, overrides = {}) {
  return `progress line\nFINAL_HANDSHAKE_JSON ${JSON.stringify(success(role, overrides))}`;
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

function envFor(room, tokenValue, inferenceKeyValue) {
  return {
    AUXILIARY_CLOCKCHAIN_MCP_API_KEY: tokenValue,
    COREPACK_HOME: join(room.roleRoot, "corepack-cache"),
    GIT_CONFIG_GLOBAL: join(room.roleRoot, "gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    HERMES_HOME: join(room.roleRoot, "hermes-home"),
    HOME: join(room.roleRoot, "home"),
    KIMI_API_KEY: inferenceKeyValue,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NPM_CONFIG_CACHE: join(room.roleRoot, "npm-cache"),
    PATH: "/usr/bin:/bin",
    PYTHONNOUSERSITE: "1",
    TMPDIR: join(room.roleRoot, "tmp"),
    XDG_CACHE_HOME: join(room.roleRoot, "xdg-cache"),
  };
}

function harness(root, t, options = {}) {
  const calls = {
    checkKit: [],
    credentialReads: [],
    minted: [],
    prepared: [],
    provisioned: [],
    spawns: [],
    kills: [],
    cleaned: [],
    relay: [],
  };
  const outputs = {
    payer: terminal("payer"),
    requestor: terminal("requestor"),
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
      credentialFile: options.credentialFile,
      env: options.env ?? {},
      hermesBinary: HERMES,
      inferenceKeyName: "KIMI_API_KEY",
      inferenceKeyValue: options.inferenceKeyValue ?? KIMI,
      kitCommit: KIT_COMMIT,
      kitUrl: KIT_URL,
      localDebug: options.localDebug ?? false,
      mintDemoToken: async ({ subject }) => {
        calls.minted.push(subject);
        if (options.tokens) return options.tokens[calls.minted.length - 1];
        return calls.minted.length === 1 ? TOKEN_A : TOKEN_B;
      },
      prepareHermesCleanRoom: async ({ role }) => {
        const room = await makePrepared(root, role, options.manifestOverrides?.[role]);
        calls.prepared.push({ role, room });
        return room;
      },
      provisionHermesCleanRoom: async ({ prepared: room, role, clockchainMcpToken, inferenceKeyValue }) => {
        const prePromptPath = join(room.paths.evidencePrivate, "pre-prompt.json");
        await writeFile(
          prePromptPath,
          JSON.stringify({
            phase: "pre-prompt",
            principal: { sha256: role === "payer" ? "1".repeat(64) : "2".repeat(64) },
            role,
            tokensPresent: true,
            zeroState: { clean: true },
            ...options.manifestOverrides?.[role]?.prePrompt,
          }),
          { mode: 0o600 },
        );
        const provisionedRoom = {
          ...room,
          env: envFor(room, clockchainMcpToken, inferenceKeyValue),
          manifests: { ...room.manifests, prePromptPath },
        };
        calls.provisioned.push({ role, token: clockchainMcpToken, room: provisionedRoom });
        return provisionedRoom;
      },
      relayUrl: "http://relay.local",
      runId: "run-abc",
      runRoot: root,
      spawnProcess: (command, args, spawnOptions) => {
        const role = spawnOptions.cwd.includes("/payer/") ? "payer" : "requestor";
        calls.spawns.push({ role, command, args, options: spawnOptions });
        const usagePath = args[args.indexOf("--usage-file") + 1];
        writeFile(usagePath, JSON.stringify(options.usage?.[role] ?? {
          durationMs: 42,
          input: 10,
          model: "k3",
          output: 20,
          provider: "kimi-coding",
          total: 30,
        }), { mode: 0o600 });
        return fakeProcess({
          role,
          output: outputs[role],
          exitCode: options.exitCodes?.[role] ?? 0,
          delayMs: options.delays?.[role] ?? 0,
          spawnLog: calls,
        });
      },
      timeoutMs: options.timeoutMs ?? 2_000,
      verifyRelayResult: async ({ sessionId }) => {
        calls.relay.push(sessionId);
        return {
          discovery: { operatorPublicKey: "test-key" },
          envelope: { result: options.relayResult ?? CERT_RESULT },
          result: options.relayResult ?? CERT_RESULT,
        };
      },
      ...options.extra,
    },
  };
}

test("mints two distinct tokens only after both pre-provision manifests exist and credential read is delayed", async (t) => {
  const root = await tempRoot(t);
  const credentialFile = await writePrivateCredential(t);
  const h = harness(root, t, {
    credentialFile,
    inferenceKeyValue: undefined,
    delays: { payer: 25, requestor: 25 },
  });

  const result = await runHermesDemo(h.options);

  assert.deepEqual(h.calls.prepared.map((entry) => entry.role), ["payer", "requestor"]);
  assert.deepEqual(h.calls.minted, [
    "hermes-demo:run-abc:payer",
    "hermes-demo:run-abc:requestor",
  ]);
  assert.equal(h.calls.prepared.length, 2);
  assert.equal(h.calls.spawns.length, 2);
  assert.equal(result.summary.sessionId, SESSION_ID);
  assert.equal(result.summary.certificateDigest, CERT_DIGEST);
  assert.equal(result.summary.paymentMoved, false);
  assert.deepEqual(h.calls.cleaned.sort(), [join(root, "roles", "payer"), join(root, "roles", "requestor")].sort());
});

test("-z receives prompt text, both prompts are built before spawn, and both children are spawned before awaiting", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t);

  await runHermesDemo(h.options);

  assert.equal(h.calls.spawns.length, 2);
  for (const call of h.calls.spawns) {
    assert.equal(call.command, HERMES);
    assert.equal(call.args[0], "-z");
    assert.match(call.args[1], /^# Clockchain Handshake Hermes/);
    assert.doesNotMatch(call.args[1], /prompt\.md$/);
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
  }
});

test("each child receives the exact provisioned allowlist env and its own token", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t);

  await runHermesDemo(h.options);

  for (const call of h.calls.spawns) {
    assert.equal(call.options.env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY, call.role === "payer" ? TOKEN_A : TOKEN_B);
    assert.equal(call.options.env.KIMI_API_KEY, KIMI);
    assert.deepEqual(Object.keys(call.options.env).sort(), [
      "AUXILIARY_CLOCKCHAIN_MCP_API_KEY",
      "COREPACK_HOME",
      "GIT_CONFIG_GLOBAL",
      "GIT_CONFIG_NOSYSTEM",
      "HERMES_HOME",
      "HOME",
      "KIMI_API_KEY",
      "LANG",
      "LC_ALL",
      "NPM_CONFIG_CACHE",
      "PATH",
      "PYTHONNOUSERSITE",
      "TMPDIR",
      "XDG_CACHE_HOME",
    ]);
  }
});

test("malformed or equal structural tokens abort before either agent starts and still clean up", async (t) => {
  for (const tokens of [["bad token"], [TOKEN_A, TOKEN_A]]) {
    const root = await tempRoot(t);
    const h = harness(root, t, { tokens });
    await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
    assert.equal(h.calls.spawns.length, 0);
    assert.deepEqual(h.calls.cleaned.sort(), [join(root, "roles", "payer"), join(root, "roles", "requestor")].sort());
  }
});

test("success parser requires exact FINAL_HANDSHAKE_JSON marker on the final nonempty line", async (t) => {
  const badOutputs = [
    { payer: JSON.stringify(success("payer")) },
    { payer: `FINAL_HANDSHAKE_JSON ${JSON.stringify(success("payer"))}\ntrailing prose` },
    { payer: `prefix FINAL_HANDSHAKE_JSON ${JSON.stringify(success("payer"))}` },
  ];
  for (const outputs of badOutputs) {
    const root = await tempRoot(t);
    const h = harness(root, t, { outputs });
    await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
  }
});

test("relay verified result is authoritative for digest, parties, receipts, outcome, and paymentMoved", async (t) => {
  const cases = [
    { relayResult: certificateResult({ paymentMoved: true }) },
    { relayResult: certificateResult({ outcome: "FAILED" }) },
    { outputs: { payer: terminal("payer", { certificateDigest: "e".repeat(64) }) } },
    { outputs: { requestor: terminal("requestor", { agentId: "9999" }) } },
    { outputs: { requestor: terminal("requestor", { address: PAYER_ADDRESS }) } },
  ];
  for (const bad of cases) {
    const root = await tempRoot(t);
    const h = harness(root, t, bad);
    await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
  }
});

test("invalid output, partial failure, stderr, timeout, bad usage, and reused principals fail without authorization evidence", async (t) => {
  const cases = [
    { outputs: { payer: terminal("payer", { certificateVerified: false }) } },
    { outputs: { requestor: terminal("requestor", { paymentMoved: true }) } },
    { exitCodes: { payer: 1 } },
    { delays: { payer: 50, requestor: 50 }, timeoutMs: 1 },
    { usage: { payer: { token: TOKEN_A } } },
    { manifestOverrides: { requestor: { prePrompt: { principal: { sha256: "1".repeat(64) } } } } },
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
    assert.deepEqual(h.calls.cleaned.sort(), [join(root, "roles", "payer"), join(root, "roles", "requestor")].sort());
  }
});

test("retained evidence embeds public manifests and usage without token digests, stdout, stderr, or absolute paths", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    outputs: {
      payer: `debug ${TOKEN_A}\n${terminal("payer")}`,
      requestor: `secret ${KIMI}\n${terminal("requestor")}`,
    },
  });

  const result = await runHermesDemo(h.options);

  for (const role of ["payer", "requestor"]) {
    await assert.rejects(readdir(join(root, "roles", role)), /ENOENT/);
  }
  const retained = await readFile(result.evidencePath, "utf8");
  assert.equal(retained.includes(TOKEN_A), false);
  assert.equal(retained.includes(TOKEN_B), false);
  assert.equal(retained.includes(KIMI), false);
  assert.equal(retained.includes(root), false);
  assert.equal(retained.includes("tokenSha256"), false);
  assert.equal(retained.includes("stdout"), false);
  assert.equal(retained.includes("stderr"), false);
  assert.match(retained, /"principals"/);
  assert.match(retained, /"usage"/);
  assert.match(retained, /"receipts"/);
  assert.match(retained, /"certificate"/);
});

test("dry-run prepares zero-state rooms and checks kit but requires no provider secret, token, or agent start", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    inferenceKeyValue: undefined,
    extra: { dryRun: true },
  });

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
    () => buildHermesPrompt({ role: "payer", kitUrl: KIT_URL, kitCommit: "abc" }),
    /Hermes demo failed safely/,
  );
  assert.throws(
    () => buildHermesPrompt({ role: "payer", kitUrl: "https://github.com/other/repo.git", kitCommit: KIT_COMMIT }),
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
