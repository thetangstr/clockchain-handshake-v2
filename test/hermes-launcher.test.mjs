import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { digestHex } from "../src/core/canonical.mjs";
import {
  buildHermesPrompt,
  readInferenceCredential,
  runHermesDemo,
} from "../src/core/hermes-launcher.mjs";
import {
  prepareHermesCleanRoom,
  provisionHermesCleanRoom,
} from "../src/core/hermes-cleanroom.mjs";
import {
  currentPushedCommit,
  parseArgs,
} from "../bin/hermes-demo.mjs";

const execFile = promisify(execFileCallback);
const ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), ".."));
const KIT_URL = "https://github.com/thetangstr/clockchain-handshake-v2.git";
const KIT_COMMIT = "0123456789abcdef0123456789abcdef01234567";
const HERMES = "/Users/maxiaoer/.local/bin/hermes";
const INFERENCE_SECRET = "minimax-secret-AAAAAAAAAAAAAAAAAAAAAAAA";
const SESSION_ID = "123e4567-e89b-42d3-a456-426614174000";
const PAYER_ADDRESS = "0x1111111111111111111111111111111111111111";
const REQUESTOR_ADDRESS = "0x2222222222222222222222222222222222222222";
const PAYER_AGENT = "8677";
const REQUESTOR_AGENT = "9001";
const RUN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PAYER_JTI = "11111111-1111-4111-8111-111111111111";
const REQUESTOR_JTI = "22222222-2222-4222-8222-222222222222";

function token(jti) {
  const payload = Buffer.from(JSON.stringify({
    exp: 2_000_000_000,
    iat: 1_700_000_000,
    jti,
    sub: "optional-public-subject",
    tier: "demo",
    v: 1,
  }), "utf8").toString("base64url");
  return `cc_${payload}.abcdefghijklmnopqrstuvwxyz`;
}

function tokenWithPayload(payload) {
  return `cc_${Buffer.from(JSON.stringify(payload), "utf8").toString("base64url")}.abcdefghijklmnopqrstuvwxyz`;
}

const TOKEN_A = token(PAYER_JTI);
const TOKEN_B = token(REQUESTOR_JTI);

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

async function writePrivateCredential(t, value = INFERENCE_SECRET) {
  const root = await tempRoot(t);
  const path = join(root, "minimax-cn.key");
  await writeFile(path, value, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

function jtiFingerprint(jti) {
  return createHash("sha256").update(`jti:${jti}`).digest("hex");
}

function hermesUsage(overrides = {}) {
  return {
    api_calls: 3,
    cache_read_tokens: 4,
    cache_write_tokens: 5,
    completed: true,
    cost_source: "official_docs_snapshot",
    cost_status: "estimated",
    estimated_cost_usd: 0.0123,
    failed: false,
    input_tokens: 100,
    model: "MiniMax-M3",
    output_tokens: 40,
    provider: "minimax-cn",
    reasoning_tokens: 6,
    service_tier: null,
    session_id: "hermes-private-session-id",
    total_tokens: 155,
    ...overrides,
  };
}

async function makePrepared(root, role, overrides = {}) {
  const roleRoot = join(root, "roles", role);
  const paths = {
    corepackHome: join(roleRoot, "corepack-cache"),
    evidencePrivate: join(roleRoot, "private-evidence"),
    gitConfig: join(roleRoot, "gitconfig"),
    hermesHome: join(roleRoot, "hermes-home"),
    home: join(roleRoot, "home"),
    npmCache: join(roleRoot, "npm-cache"),
    tmp: join(roleRoot, "tmp"),
    workspace: join(roleRoot, "workspace"),
    xdgCache: join(roleRoot, "xdg-cache"),
  };
  for (const path of Object.values(paths).filter((value) => value !== paths.gitConfig)) {
    await mkdir(path, { recursive: true, mode: 0o700 });
  }
  await writeFile(paths.gitConfig, "", { mode: 0o600 });
  const preProvisionPath = join(paths.evidencePrivate, "pre-provision.json");
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
    paths,
    manifests: { preProvisionPath },
  };
}

function createPostRunState({ kitCommit = KIT_COMMIT, role, room }) {
  const repo = join(room.paths.workspace, "handshake-kit");
  mkdirSync(join(repo, ".git"), { recursive: true, mode: 0o700 });
  mkdirSync(join(repo, "node_modules", "viem", "deep-tree-that-must-not-be-recursed"), { recursive: true, mode: 0o700 });
  mkdirSync(join(room.paths.home, ".clockchain"), { recursive: true, mode: 0o700 });
  mkdirSync(join(room.paths.npmCache, "_cacache"), { recursive: true, mode: 0o700 });
  mkdirSync(join(room.paths.corepackHome, "v1"), { recursive: true, mode: 0o700 });
  mkdirSync(join(room.paths.xdgCache, "hermes"), { recursive: true, mode: 0o700 });
  writeFileSync(join(repo, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, role }), { mode: 0o600 });
  writeFileSync(join(repo, "node_modules", "viem", "deep-tree-that-must-not-be-recursed", "sentinel.txt"), "nested dependency content", { mode: 0o600 });
  writeFileSync(join(repo, ".git", "HEAD"), kitCommit, { mode: 0o600 });
  writeFileSync(join(room.paths.home, ".clockchain", "wallet.json"), JSON.stringify({ address: role }), { mode: 0o600 });
  chmodSync(join(room.paths.home, ".clockchain", "wallet.json"), 0o600);
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

function fakeProcess({ role, output, stderr = "", exitCode = 0, delayMs = 0, spawnLog }) {
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
    if (stderr !== "") child.stderr.emit("data", Buffer.from(stderr));
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
    MINIMAX_CN_API_KEY: inferenceKeyValue,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NPM_CONFIG_CACHE: join(room.roleRoot, "npm-cache"),
    PATH: "/usr/bin:/bin",
    PYTHONNOUSERSITE: "1",
    TMPDIR: join(room.roleRoot, "tmp"),
    XDG_CACHE_HOME: join(room.roleRoot, "xdg-cache"),
  };
}

async function writeFakeHermesProfile(profileDirectory) {
  for (const dir of ["cron", "home", "logs", "memories", "plans", "sessions", "skills", "skins", "workspace"]) {
    await mkdir(join(profileDirectory, dir), { recursive: true, mode: 0o755 });
  }
  await writeFile(join(profileDirectory, ".env"), "# generated profile env\n", { mode: 0o600 });
  await writeFile(join(profileDirectory, ".no-bundled-skills"), "\n", { mode: 0o600 });
  await writeFile(join(profileDirectory, "SOUL.md"), "default generated rules\n", { mode: 0o600 });
}

async function realCleanRoomOptions(root) {
  const installRoot = join(root, "hermes-agent");
  await mkdir(installRoot, { recursive: true, mode: 0o700 });
  await writeFile(join(installRoot, ".env"), [
    "MINIMAX_CN_API_KEY=from-shared-dotenv",
    "OPENAI_API_KEY=from-shared-dotenv",
    "CLOCKCHAIN_TOKEN=from-shared-dotenv",
    "",
  ].join("\n"));
  return {
    discoverMcp: async () => ({
      prompts_enabled: false,
      resources_enabled: false,
      registered_tools: [
        "mcp__clockchain__handshake_status",
        "mcp__clockchain__handshake_join",
        "mcp__clockchain__handshake_next",
        "mcp__clockchain__handshake_submit",
        "mcp__clockchain__handshake_get_certificate",
      ],
      servers: [{ enabled: true, name: "clockchain", url: "https://mcp.clockchain.network/mcp" }],
      shutdown_called: true,
    }),
    detectHermes: async ({ hermesInstallRoot }) => ({
      configVersion: 33,
      features: {
        noAlias: true,
        noSkills: true,
        profileCreate: true,
        venvPython: true,
      },
      gitDescribe: "v2026.7.30-357-g87bc71060",
      gitHead: "87bc710609f8b89b6e6b4aa418dde8ee30ec6873",
      installRoot: hermesInstallRoot,
      managedConfigPresent: false,
      managedEnvPresent: false,
      packageVersion: "0.19.1",
      sourceClean: true,
      supported: true,
    }),
    hermesInstallRoot: installRoot,
    probeEnvLoader: async ({ dotenvKeys, env, providerKeyName }) => {
      const emptyKeys = dotenvKeys.filter((key) => key !== providerKeyName);
      return {
        allowed_secret_keys_present: {
          [providerKeyName]: Boolean(env[providerKeyName]),
          AUXILIARY_CLOCKCHAIN_MCP_API_KEY: Boolean(env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY),
        },
        dotenv_empty: Object.fromEntries(emptyKeys.map((key) => [key, env[key] === ""])),
        loaded_count: 1,
        loaded_role_env: true,
        managed_absent: true,
        observed_empty_keys: emptyKeys,
        role_env_comment_only: true,
        terminal_sanitizer_removed_auxiliary: true,
        terminal_sanitizer_removed_provider: true,
      };
    },
    runHermesProfileCreate: async ({ env }) => {
      const profileDirectory = join(env.HERMES_HOME, "profiles", "agent");
      await writeFakeHermesProfile(profileDirectory);
      return { profileDirectory };
    },
  };
}

function harness(root, t, options = {}) {
  const calls = {
    checkKit: [],
    checkPublicServices: [],
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
      checkPublicServices: async (services) => {
        calls.checkPublicServices.push(services);
        return {
          discoveryRepositoryMatches: true,
          mcpAwsHealth: true,
          mcpHealth: true,
          relayDiscovery: true,
          relayHealth: true,
        };
      },
      cleanRoom: async ({ roleRoot }) => {
        calls.cleaned.push(roleRoot);
        await rm(roleRoot, { recursive: true, force: true });
      },
      credentialFile: options.credentialFile,
      env: options.env ?? {},
      hermesBinary: HERMES,
      inferenceKeyName: "MINIMAX_CN_API_KEY",
      inferenceKeyValue: options.inferenceKeyValue ?? INFERENCE_SECRET,
      kitCommit: KIT_COMMIT,
      kitUrl: KIT_URL,
      localDebug: options.localDebug ?? false,
      mintDemoToken: async ({ subject }) => {
        calls.minted.push(subject);
        if (options.tokens) return options.tokens[calls.minted.length - 1];
        return calls.minted.length === 1 ? TOKEN_A : TOKEN_B;
      },
      postRunCommandRunner: async (command, args) => {
        if (command === "git" && args[0] === "-C" && args[2] === "rev-parse" && args[3] === "HEAD") {
          return { stdout: `${KIT_COMMIT}\n`, stderr: "" };
        }
        throw new Error("unexpected post-run command");
      },
      prepareHermesCleanRoom: async ({ role }) => {
        const room = await makePrepared(root, role, options.manifestOverrides?.[role]);
        calls.prepared.push({ role, room });
        return room;
      },
      provisionHermesCleanRoom: async ({ prepared: room, clockchainMcpToken, inferenceKeyValue }) => {
        const role = room.role;
        const prePromptPath = join(room.paths.evidencePrivate, "pre-prompt.json");
        await writeFile(
          prePromptPath,
          JSON.stringify({
            phase: "pre-prompt",
            principalFingerprint: role === "payer" ? jtiFingerprint(PAYER_JTI) : jtiFingerprint(REQUESTOR_JTI),
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
      runId: RUN_ID,
      runRoot: root,
      spawnProcess: (command, args, spawnOptions) => {
        const role = spawnOptions.cwd.includes("/payer/") ? "payer" : "requestor";
        calls.spawns.push({ role, command, args, options: spawnOptions });
        const usagePath = args[args.indexOf("--usage-file") + 1];
        if (!options.missingUsage?.includes(role)) {
          writeFileSync(usagePath, JSON.stringify(options.usage?.[role] ?? hermesUsage()), { mode: 0o600 });
        }
        const provisionedRoom = calls.provisioned.find((entry) => entry.role === role)?.room ?? {
          paths: {
            corepackHome: spawnOptions.env.COREPACK_HOME,
            home: spawnOptions.env.HOME,
            npmCache: spawnOptions.env.NPM_CONFIG_CACHE,
            workspace: spawnOptions.cwd,
            xdgCache: spawnOptions.env.XDG_CACHE_HOME,
          },
        };
        createPostRunState({ role, room: provisionedRoom });
        return fakeProcess({
          role,
          output: outputs[role],
          stderr: options.stderr?.[role] ?? "",
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
    `hermes-demo:${RUN_ID}:payer`,
    `hermes-demo:${RUN_ID}:requestor`,
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
      "minimax-cn",
      "-m",
      "MiniMax-M3",
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
    assert.equal(call.options.env.MINIMAX_CN_API_KEY, INFERENCE_SECRET);
    assert.deepEqual(Object.keys(call.options.env).sort(), [
      "AUXILIARY_CLOCKCHAIN_MCP_API_KEY",
      "COREPACK_HOME",
      "GIT_CONFIG_GLOBAL",
      "GIT_CONFIG_NOSYSTEM",
      "HERMES_HOME",
      "HOME",
      "LANG",
      "LC_ALL",
      "MINIMAX_CN_API_KEY",
      "NPM_CONFIG_CACHE",
      "PATH",
      "PYTHONNOUSERSITE",
      "TMPDIR",
      "XDG_CACHE_HOME",
    ]);
  }
});

test("launcher uses real cleanroom prepare/provision contract with only Hermes runtime probes stubbed", async (t) => {
  const root = await realpath(await tempRoot(t));
  const cleanRoomOptions = await realCleanRoomOptions(root);
  const h = harness(root, t, {
    extra: {
      cleanRoomOptions,
      hermesBinary: join(root, "bin", "hermes"),
      prepareHermesCleanRoom,
      provisionHermesCleanRoom,
    },
  });

  const result = await runHermesDemo(h.options);

  assert.equal(result.summary.sessionId, SESSION_ID);
  assert.equal(h.calls.prepared.length, 0, "harness mock prepare must not be used");
  assert.equal(h.calls.provisioned.length, 0, "harness mock provision must not be used");
  assert.equal(h.calls.spawns.length, 2);
  for (const call of h.calls.spawns) {
    assert.equal(call.options.env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY, call.role === "payer" ? TOKEN_A : TOKEN_B);
    assert.equal(call.options.env.MINIMAX_CN_API_KEY, INFERENCE_SECRET);
    assert.equal(call.options.env.OPENAI_API_KEY, "");
    assert.equal(call.options.env.CLOCKCHAIN_TOKEN, "");
    assert.equal(call.options.env.HOME, join(root, "roles", call.role, "home"));
  }
  const retained = JSON.parse(await readFile(result.evidencePath, "utf8"));
  assert.equal(retained.cleanRooms.payer.preProvision.hermes.packageVersion, "0.19.1");
  assert.deepEqual(retained.cleanRooms.requestor.prePrompt.mcp.registeredTools, [
    "mcp__clockchain__handshake_status",
    "mcp__clockchain__handshake_join",
    "mcp__clockchain__handshake_next",
    "mcp__clockchain__handshake_submit",
    "mcp__clockchain__handshake_get_certificate",
  ]);
  assert.equal(retained.cleanRooms.requestor.prePrompt.mcp.shutdownCalled, true);
  assert.equal(retained.principals.payer.sha256, jtiFingerprint(PAYER_JTI));
  assert.equal(retained.principals.requestor.sha256, jtiFingerprint(REQUESTOR_JTI));
});

test("malformed or equal structural tokens abort before either agent starts and still clean up", async (t) => {
  const audToken = tokenWithPayload({
    aud: "demo",
    exp: 2_000_000_000,
    iat: 1_700_000_000,
    jti: PAYER_JTI,
    v: 1,
  });
  const extraKeyToken = tokenWithPayload({
    exp: 2_000_000_000,
    iat: 1_700_000_000,
    jti: PAYER_JTI,
    scope: "too-broad",
    tier: "demo",
    v: 1,
  });
  for (const tokens of [["bad token"], [audToken, TOKEN_B], [extraKeyToken, TOKEN_B], [TOKEN_A, TOKEN_A]]) {
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

test("checksum-style output addresses are normalized for comparison and evidence", async (t) => {
  const root = await tempRoot(t);
  const relayResult = certificateResult({
    parties: {
      payer: {
        address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        agentId: PAYER_AGENT,
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${PAYER_AGENT}`,
      },
      payee: {
        address: "0xfedcbafedcbafedcbafedcbafedcbafedcbafedc",
        agentId: REQUESTOR_AGENT,
        reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${REQUESTOR_AGENT}`,
      },
    },
  });
  const digest = digestHex(relayResult);
  const h = harness(root, t, {
    relayResult,
    outputs: {
      payer: terminal("payer", {
        address: "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD",
        certificateDigest: digest,
      }),
      requestor: terminal("requestor", {
        address: "0xFEDCBAfedcbaFEDCBAfedcbaFEDCBAfedcbaFEDC",
        certificateDigest: digest,
      }),
    },
  });

  const result = await runHermesDemo(h.options);

  assert.equal(result.summary.payer.address, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
  assert.equal(result.summary.requestor.address, "0xfedcbafedcbafedcbafedcbafedcbafedcbafedc");
});

test("bounded benign stderr is discarded, while secret-bearing stderr fails", async (t) => {
  {
    const root = await tempRoot(t);
    const h = harness(root, t, { stderr: { payer: "Hermes warning: retrying local terminal\n" } });
    const result = await runHermesDemo(h.options);
    const retained = await readFile(result.evidencePath, "utf8");
    assert.equal(retained.includes("Hermes warning"), false);
  }
  {
    const root = await tempRoot(t);
    const h = harness(root, t, { stderr: { requestor: `oops ${TOKEN_B}` } });
    await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
  }
  {
    const root = await tempRoot(t);
    const h = harness(root, t, { outputs: { payer: `oops ${TOKEN_A}\n${terminal("payer")}` } });
    await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
  }
});

test("agent failure retains scrubbed diagnostics after both clean rooms are removed", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    exitCodes: { requestor: 1 },
    outputs: {
      requestor: `payment request was not submitted\nworking at ${root}/roles/requestor/workspace`,
    },
    usage: {
      requestor: hermesUsage({ completed: false, failed: true }),
    },
  });

  let failure;
  try {
    await runHermesDemo(h.options);
  } catch (error) {
    failure = error;
  }

  const evidencePath = join(root, "evidence", "failure.json");
  assert.match(failure?.message ?? "", /Hermes demo failed safely/);
  assert.equal(failure?.failureEvidencePath, evidencePath);
  for (const role of ["payer", "requestor"]) {
    await assert.rejects(readdir(join(root, "roles", role)), /ENOENT/);
  }
  const retained = await readFile(evidencePath, "utf8");
  assert.equal(retained.includes(root), false);
  assert.equal(retained.includes(TOKEN_A), false);
  assert.equal(retained.includes(TOKEN_B), false);
  assert.equal(retained.includes(INFERENCE_SECRET), false);
  assert.equal(/AUTHORIZED/i.test(retained), false);
  const evidence = JSON.parse(retained);
  assert.equal(evidence.schema, "clockchain.hermes-demo-failure/v1");
  assert.equal(evidence.phase, "agents");
  assert.deepEqual(evidence.cleanup, { payerRemoved: true, requestorRemoved: true });
  assert.equal(evidence.cleanRooms.payer.preProvision.tokensPresent, false);
  assert.equal(evidence.cleanRooms.requestor.prePrompt.tokensPresent, true);
  assert.equal(evidence.agents.payer.reason, "completed");
  assert.equal(evidence.agents.requestor.reason, "nonzero_exit");
  assert.equal(evidence.agents.requestor.code, 1);
  assert.match(evidence.agents.requestor.console.outTail, /payment request was not submitted/);
  assert.match(evidence.agents.requestor.console.outTail, /\[PATH\]/);
  assert.equal(evidence.agents.requestor.usage.present, true);
  assert.equal(evidence.agents.requestor.usage.completed, false);
  assert.equal(evidence.agents.requestor.usage.failed, true);
  assert.equal(evidence.agents.requestor.usage.model, "MiniMax-M3");
  assert.equal(evidence.agents.requestor.usage.provider, "minimax-cn");
});

test("secret-bearing agent failure records only the detection class", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    exitCodes: { requestor: 1 },
    outputs: { requestor: `requestor leaked ${TOKEN_B}` },
  });

  await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);

  const retained = await readFile(join(root, "evidence", "failure.json"), "utf8");
  assert.equal(retained.includes(TOKEN_B), false);
  const evidence = JSON.parse(retained);
  assert.equal(evidence.agents.requestor.reason, "secret_detected");
  assert.equal(evidence.agents.requestor.console.outTail, null);
  assert.equal(evidence.agents.requestor.console.errTail, null);
});

test("unrecognized secret-shaped diagnostics are dropped without bypassing cleanup evidence", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    exitCodes: { requestor: 1 },
    outputs: { requestor: "credential=abcdefghijklmnopqrstuvwxyz012345" },
  });

  await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);

  const retained = await readFile(join(root, "evidence", "failure.json"), "utf8");
  assert.equal(retained.includes("abcdefghijklmnopqrstuvwxyz012345"), false);
  const evidence = JSON.parse(retained);
  assert.equal(evidence.agents.requestor.reason, "nonzero_exit");
  assert.match(evidence.agents.requestor.console.outTail, /\[REDACTED\]/);
  assert.deepEqual(evidence.cleanup, { payerRemoved: true, requestorRemoved: true });
});

test("invalid output, partial failure, stderr, timeout, bad usage, and reused principals fail without authorization evidence", async (t) => {
  const cases = [
    { outputs: { payer: terminal("payer", { certificateVerified: false }) } },
    { outputs: { requestor: terminal("requestor", { paymentMoved: true }) } },
    { exitCodes: { payer: 1 } },
    { delays: { payer: 50, requestor: 50 }, timeoutMs: 1 },
    { usage: { payer: { token: TOKEN_A } } },
    { usage: { payer: hermesUsage({ completed: false }) } },
    { usage: { payer: hermesUsage({ failed: true }) } },
    { usage: { payer: { ...hermesUsage(), failure: "boom" } } },
    { usage: { payer: hermesUsage({ model: "other" }) } },
    { usage: { payer: hermesUsage({ session_id: TOKEN_A }) } },
    { missingUsage: ["requestor"] },
    { manifestOverrides: { requestor: { prePrompt: { principalFingerprint: jtiFingerprint(PAYER_JTI) } } } },
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

test("cleanup attempts both exact role roots and fails if either cleanup fails", async (t) => {
  const root = await tempRoot(t);
  const attempted = [];
  const h = harness(root, t, {
    extra: {
      cleanRoom: async ({ role, roleRoot }) => {
        attempted.push({ role, roleRoot });
        if (role === "payer") throw new Error("simulated cleanup failure");
        await rm(roleRoot, { recursive: true, force: true });
      },
    },
  });

  await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
  assert.ok(attempted.some((entry) => entry.role === "payer" && entry.roleRoot === join(root, "roles", "payer")));
  assert.ok(attempted.some((entry) => entry.role === "requestor" && entry.roleRoot === join(root, "roles", "requestor")));
});

test("retained evidence embeds public manifests and usage without token digests, stdout, stderr, or absolute paths", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t);

  const result = await runHermesDemo(h.options);

  for (const role of ["payer", "requestor"]) {
    await assert.rejects(readdir(join(root, "roles", role)), /ENOENT/);
  }
  const retained = await readFile(result.evidencePath, "utf8");
  assert.equal(retained.includes(TOKEN_A), false);
  assert.equal(retained.includes(TOKEN_B), false);
  assert.equal(retained.includes(INFERENCE_SECRET), false);
  assert.equal(retained.includes(root), false);
  assert.equal(retained.includes("tokenSha256"), false);
  assert.equal(retained.includes("stdout"), false);
  assert.equal(retained.includes("stderr"), false);
  assert.equal(retained.includes("session_id"), false);
  assert.equal(retained.includes("hermes-private-session-id"), false);
  const evidence = JSON.parse(retained);
  assert.equal(Object.hasOwn(evidence.cleanRooms.payer.preProvision, "principalFingerprint"), false);
  assert.equal(evidence.cleanRooms.payer.preProvision.tokensPresent, false);
  assert.equal(JSON.stringify(evidence.cleanRooms.payer.preProvision).includes("nodeModulesPresent"), false);
  assert.equal(JSON.stringify(evidence.cleanRooms.payer.preProvision).includes("walletState"), false);
  for (const role of ["payer", "requestor"]) {
    assert.equal(evidence.cleanRooms[role].postRun.role, role);
    assert.equal(evidence.cleanRooms[role].postRun.workspace.pinnedCommit, KIT_COMMIT);
    assert.equal(evidence.cleanRooms[role].postRun.workspace.pinnedCommitMatches, true);
    assert.equal(evidence.cleanRooms[role].postRun.workspace.nodeModulesPresent, true);
    assert.equal(evidence.cleanRooms[role].postRun.workspace.topLevelCount, 1);
    assert.equal(evidence.cleanRooms[role].postRun.workspace.nodeModulesTopLevelCount, 1);
    assert.equal(evidence.cleanRooms[role].postRun.walletState.present, true);
    assert.equal(evidence.cleanRooms[role].postRun.walletState.mode, "0600");
    assert.equal(evidence.cleanRooms[role].postRun.unexpectedSiblingPaths, false);
    assert.ok(evidence.cleanRooms[role].postRun.caches.npm.topLevelCount > 0);
  }
  assert.deepEqual(evidence.cleanup, { payerRemoved: true, requestorRemoved: true });
  assert.match(retained, /"principals"/);
  assert.match(retained, /"usage"/);
  assert.match(retained, /"estimatedCostUsd"/);
  assert.match(retained, /"usageCounts"/);
  assert.match(retained, /"input": 100/);
  assert.match(retained, /"apiCalls"/);
  assert.match(retained, /"postRun"/);
  assert.match(retained, /"packageLockSha256"/);
  assert.match(retained, /"nodeModulesPresent": true/);
  assert.match(retained, /"walletState"/);
  assert.match(retained, /"cleanup"/);
  assert.match(retained, /"payerRemoved": true/);
  assert.match(retained, /"requestorRemoved": true/);
  assert.match(retained, /"receipts"/);
  assert.match(retained, /"certificate"/);
});

test("dry-run checks public services and prepares zero-state rooms without a provider secret, token, or agent start", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    inferenceKeyValue: undefined,
    extra: { dryRun: true },
  });

  const result = await runHermesDemo(h.options);

  assert.equal(result.dryRun, true);
  assert.equal(h.calls.checkKit.length, 1);
  assert.equal(h.calls.checkPublicServices.length, 1);
  assert.deepEqual(result.publicServices, {
    discoveryRepositoryMatches: true,
    mcpAwsHealth: true,
    mcpHealth: true,
    relayDiscovery: true,
    relayHealth: true,
  });
  assert.deepEqual(h.calls.prepared.map((entry) => entry.role), ["payer", "requestor"]);
  assert.equal(h.calls.minted.length, 0);
  assert.equal(h.calls.spawns.length, 0);
});

test("dry-run securely creates a missing runs parent beneath an existing private operator root", async (t) => {
  const operatorRoot = await tempRoot(t);
  const root = join(operatorRoot, "runs", RUN_ID);
  const h = harness(root, t, {
    inferenceKeyValue: undefined,
    extra: { dryRun: true },
  });

  const result = await runHermesDemo(h.options);

  assert.equal(result.dryRun, true);
  assert.equal((await lstat(join(operatorRoot, "runs"))).mode & 0o777, 0o700);
  assert.equal((await lstat(root)).mode & 0o777, 0o700);
  assert.equal(h.calls.minted.length, 0);
  assert.equal(h.calls.spawns.length, 0);
});

test("public-service preflight fails before any clean room or token exists", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    extra: {
      checkPublicServices: async () => {
        throw new Error("network detail that must be hidden");
      },
      dryRun: true,
    },
  });

  await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
  assert.equal(h.calls.prepared.length, 0);
  assert.equal(h.calls.minted.length, 0);
  assert.equal(h.calls.spawns.length, 0);
});

test("default public-service preflight binds both MCP origins and current relay discovery to the kit commit", async (t) => {
  const root = await tempRoot(t);
  const requested = [];
  const bodies = new Map([
    ["https://mcp.clockchain.network/health", { status: "ok" }],
    ["https://mcp-aws.clockchain.network/health", { status: "ok" }],
    ["http://relay.local/healthz", { ok: true, paymentMoved: false, sessions: 1 }],
    ["http://relay.local/v1/discovery/current", {
      expiresAtMs: String(Date.now() + 60_000),
      operatorPublicKey: "public-host-key",
      paymentMoved: false,
      relayUrl: "http://relay.local",
      repositorySha: KIT_COMMIT,
      schema: "handshake-discovery/v2",
      sessionId: SESSION_ID,
    }],
  ]);
  const h = harness(root, t, {
    extra: {
      checkPublicServices: undefined,
      dryRun: true,
      fetchImpl: async (url, options) => {
        requested.push({ options, url });
        return { ok: bodies.has(url), json: async () => bodies.get(url) };
      },
    },
  });

  const result = await runHermesDemo(h.options);
  assert.equal(result.publicServices.discoveryRepositoryMatches, true);
  assert.deepEqual(requested.map(({ url }) => url).sort(), [...bodies.keys()].sort());
  assert.ok(requested.every(({ options }) => options.method === "GET"));

  bodies.get("http://relay.local/v1/discovery/current").repositorySha = "f".repeat(40);
  const mismatchRoot = await tempRoot(t);
  const mismatch = harness(mismatchRoot, t, {
    extra: { checkPublicServices: undefined, dryRun: true, fetchImpl: async (url) => ({ ok: bodies.has(url), json: async () => bodies.get(url) }) },
  });
  await assert.rejects(runHermesDemo(mismatch.options), /Hermes demo failed safely/);
  assert.equal(mismatch.calls.prepared.length, 0);
});

test("default GitHub kit check requires exact commit sha from response JSON", async (t) => {
  const root = await tempRoot(t);
  const h = harness(root, t, {
    extra: {
      checkKit: undefined,
      fetchImpl: async () => ({
        ok: true,
        json: async () => ({ sha: "f".repeat(40) }),
      }),
    },
  });
  await assert.rejects(runHermesDemo(h.options), /Hermes demo failed safely/);
  assert.equal(h.calls.prepared.length, 0);
});

test("production CLI exposes turnkey defaults and rejects debug cleanroom retention", async () => {
  const { stdout } = await execFile(process.execPath, [join(ROOT, "bin", "hermes-demo.mjs"), "--help"], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 8_192,
  });
  assert.match(stdout, /https:\/\/github\.com\/thetangstr\/clockchain-handshake-v2\.git/);
  assert.match(stdout, /http:\/\/44\.249\.47\.220:8080/);
  assert.match(stdout, /CLOCKCHAIN_HERMES_DEMO_ROOT/);
  assert.match(stdout, /\/Users\/maxiaoer\/\.clockchain\/hermes-demo\/minimax-cn\.key/);
  assert.match(stdout, /--keep-cleanrooms is rejected/);
  assert.doesNotMatch(stdout.split("\n")[0], /--run-root/);
  assert.doesNotMatch(stdout, /--kit-url/);

  await assert.rejects(
    execFile(process.execPath, [join(ROOT, "bin", "hermes-demo.mjs"), "--keep-cleanrooms"], {
      cwd: ROOT,
      encoding: "utf8",
      maxBuffer: 8_192,
    }),
    /Hermes demo failed safely/,
  );
});

test("production CLI derives only a clean live remote branch HEAD and validates flag values", async () => {
  const calls = [];
  const commandRunner = async (command, args) => {
    calls.push([command, args]);
    if (args[0] === "status") return { stdout: "", stderr: "" };
    if (args[0] === "rev-parse" && args[1] === "--abbrev-ref") return { stdout: "codex/hermes-turnkey-demo\n", stderr: "" };
    if (args[0] === "rev-parse" && args[1] === "HEAD") return { stdout: `${KIT_COMMIT}\n`, stderr: "" };
    if (args[0] === "ls-remote") return { stdout: `${KIT_COMMIT}\trefs/heads/codex/hermes-turnkey-demo\n`, stderr: "" };
    throw new Error("unexpected git command");
  };

  assert.equal(await currentPushedCommit({ commandRunner }), KIT_COMMIT);
  assert.deepEqual(calls.map((entry) => entry[1][0]), ["status", "rev-parse", "rev-parse", "ls-remote"]);

  const parsed = await parseArgs(["--timeout-ms", "1234"], { commandRunner });
  assert.equal(parsed.kitCommit, KIT_COMMIT);
  assert.equal(parsed.credentialFile, "/Users/maxiaoer/.clockchain/hermes-demo/minimax-cn.key");
  assert.equal(parsed.timeoutMs, 1234);
  const explicitCredential = await parseArgs([
    "--inference-key-file",
    "/private/minimax-cn.key",
  ], { commandRunner });
  assert.equal(explicitCredential.credentialFile, "/private/minimax-cn.key");

  await assert.rejects(currentPushedCommit({
    commandRunner: async (command, args) => {
      if (args[0] === "status") return { stdout: " M src/core/hermes-launcher.mjs\n", stderr: "" };
      return commandRunner(command, args);
    },
  }), /dirty worktree/);
  await assert.rejects(currentPushedCommit({
    commandRunner: async (command, args) => {
      if (args[0] === "ls-remote") return { stdout: `${"f".repeat(40)}\trefs/heads/codex/hermes-turnkey-demo\n`, stderr: "" };
      return commandRunner(command, args);
    },
  }), /unpushed commit/);
  await assert.rejects(parseArgs(["--run-root"], { commandRunner }), /missing argument value/);
  await assert.rejects(parseArgs(["--kit-commit", "--timeout-ms"], { commandRunner }), /missing argument value/);
  await assert.rejects(parseArgs(["--timeout-ms", "0"], { commandRunner }), /unsafe timeout/);
  await assert.rejects(parseArgs(["--kimi-key-file", "/private/retired.key"], { commandRunner }), /unknown argument/);
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
  assert.match(prompt, /Do not cd outside the current blank workspace/i);
  assert.match(prompt, /git clone .* \.\/handshake-kit/i);
  assert.match(prompt, /paymentMoved:false/);
  assert.match(prompt, /handshake_submit is signatures only/i);
  assert.match(prompt, /retryAfterMs/i);
  assert.match(prompt, /start at 5 seconds/i);
  assert.match(prompt, /back off to at most 15 seconds/i);
  assert.match(prompt, /erc8004_identity.*register command above, then call handshake_next again/i);
  assert.doesNotMatch(prompt, /submit the public registration fields/i);
});

test("credential reader accepts exactly one supported env var or one private file and never searches", async (t) => {
  assert.deepEqual(
    await readInferenceCredential({ env: { MINIMAX_CN_API_KEY: INFERENCE_SECRET } }),
    { keyName: "MINIMAX_CN_API_KEY", value: INFERENCE_SECRET },
  );
  await assert.rejects(
    readInferenceCredential({ env: { KIMI_API_KEY: INFERENCE_SECRET } }),
    /Hermes demo failed safely/,
  );
  const file = await writePrivateCredential(t);
  assert.deepEqual(
    await readInferenceCredential({ credentialFile: file, env: {} }),
    { keyName: "MINIMAX_CN_API_KEY", value: INFERENCE_SECRET },
  );
  await chmod(file, 0o644);
  await assert.rejects(readInferenceCredential({ credentialFile: file, env: {} }), /Hermes demo failed safely/);
});
