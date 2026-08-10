import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { test } from "node:test";

import {
  assertPublicCleanRoomEvidence,
  fingerprintClockchainDemoToken,
  prepareHermesCleanRoom,
  provisionHermesCleanRoom,
} from "../src/core/hermes-cleanroom.mjs";

const MAC_BINARY = "/Users/maxiaoer/.local/bin/hermes";
const MAC_INSTALL_ROOT = "/Users/maxiaoer/.hermes/hermes-agent";
const MAC_PATH = "/Users/maxiaoer/.local/bin:/opt/homebrew/opt/node@22/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const HERMES_HEAD = "87bc710609f8b89b6e6b4aa418dde8ee30ec6873";
const HERMES_DESCRIBE = "v2026.7.30-357-g87bc71060";
const RAW_TOOLS = Object.freeze([
  "handshake_status",
  "handshake_join",
  "handshake_next",
  "handshake_submit",
  "handshake_get_certificate",
]);
const REGISTERED_TOOLS = Object.freeze(RAW_TOOLS.map((name) => `mcp__clockchain__${name}`));
const CLOCKCHAIN_URL = "https://mcp.clockchain.network/mcp";
const KIT_COMMIT = "0123456789abcdef0123456789abcdef01234567";

async function temporaryRoot(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "hermes-cleanroom-")));
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

const UUIDS = Object.freeze({
  defaultAdapter: "44444444-4444-4444-8444-444444444444",
  payer: "11111111-1111-4111-8111-111111111111",
  retained: "55555555-5555-4555-8555-555555555555",
  same: "66666666-6666-4666-8666-666666666666",
  wrapper: "33333333-3333-4333-8333-333333333333",
});

function clockchainToken(jti) {
  const payload = {
    exp: 2_000_000_000,
    iat: 1_700_000_000,
    jti,
    sub: "optional-public-subject",
    tier: "demo",
    v: 1,
  };
  return `cc_${Buffer.from(JSON.stringify(payload)).toString("base64url")}.hmacsignature000000`;
}

function clockchainTokenWithPayload(payload) {
  return `cc_${Buffer.from(JSON.stringify(payload)).toString("base64url")}.hmacsignature000000`;
}

function jtiFingerprint(jti) {
  return createHash("sha256").update(`jti:${jti}`).digest("hex");
}

async function makeFakeHermesInstall(root, {
  dirty = false,
  dotenv = [
    "MINIMAX_CN_API_KEY=from-shared-dotenv",
    "OPENAI_API_KEY=from-shared-dotenv",
    "CLOCKCHAIN_TOKEN=from-shared-dotenv",
  ],
} = {}) {
  const installRoot = join(root, "hermes-agent");
  const binDir = join(root, "bin");
  const hermesBinary = join(binDir, "hermes");
  const python = join(installRoot, "venv", "bin", "python");
  await mkdir(binDir, { recursive: true });
  await mkdir(join(installRoot, "venv", "bin"), { recursive: true });
  await writeFile(join(installRoot, ".env"), `${dotenv.join("\n")}\n`);
  await writeFile(join(installRoot, "pyproject.toml"), '[project]\nname = "hermes-agent"\nversion = "0.19.1"\n');
  await writeFile(join(installRoot, "managed-env.txt"), "\n");
  await writeFile(join(installRoot, "managed-config.txt"), "\n");
  await writeFile(join(installRoot, "dirty.txt"), dirty ? "dirty\n" : "\n");
  await writeFile(hermesBinary, `#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
if (process.argv.includes("--version")) {
  process.stdout.write("Hermes CLI 0.19.1 (2026.7.30)\\n");
  process.exit(0);
}
if (process.argv.slice(2).join(" ") === "profile create --help") {
  process.stdout.write("  --no-skills\\n  --no-alias\\n");
  process.exit(0);
}
if (process.argv.slice(2).join(" ") !== "profile create agent --no-skills --no-alias") {
  process.exit(40);
}
const profile = join(process.env.HERMES_HOME, "profiles", "agent");
for (const dir of ["cron", "home", "logs", "memories", "plans", "sessions", "skills", "skins", "workspace"]) {
  mkdirSync(join(profile, dir), { recursive: true, mode: 0o755 });
}
writeFileSync(join(profile, ".env"), "# generated profile env\\n# no values\\n", { mode: 0o600 });
writeFileSync(join(profile, "SOUL.md"), "default generated rules\\n");
writeFileSync(join(profile, ".no-bundled-skills"), "\\n");
`, { mode: 0o755 });
  await chmod(hermesBinary, 0o755);
  await writeFile(python, `#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
if (process.argv[2] !== "-c") process.exit(51);
const code = process.argv[3] || "";
if (code.includes("hermes_cli.config_defaults") && code.includes("DEFAULT_CONFIG")) {
  process.stdout.write(JSON.stringify({ config_version: 33 }));
  process.exit(0);
}
if (code.includes("tools.mcp_tool") && code.includes("discover_mcp_tools") && code.includes("shutdown_mcp_servers")) {
  for (const dir of ["audio_cache", "cron", "hooks", "image_cache", "logs/curator", "memories", "pairing", "sessions"]) {
    mkdirSync(join(process.env.HERMES_HOME, dir), { recursive: true, mode: 0o700 });
  }
  writeFileSync(join(process.env.HERMES_HOME, "SOUL.md"), "default generated rules\\n", { mode: 0o600 });
  writeFileSync(join(process.env.HERMES_HOME, ".mcp-discovery.lock"), "");
  process.stderr.write("masked noisy discovery stderr");
  process.stdout.write(JSON.stringify({
    registered_tools: ${JSON.stringify(REGISTERED_TOOLS)},
    shutdown_called: true
  }));
  process.exit(0);
}
if (!code.includes("hermes_cli.env_loader") || !code.includes("load_hermes_dotenv") || !code.includes("tools.environments.local") || !code.includes("_sanitize_subprocess_env")) process.exit(52);
const envText = readFileSync(join(process.env.HERMES_HOME, ".env"), "utf8");
const emptyKeys = JSON.parse(process.env.HERMES_EMPTY_KEYS_JSON);
const sanitizedKeys = [];
process.stdout.write(JSON.stringify({
  allowed_secret_keys_present: {
    [process.env.HERMES_PROVIDER_KEY_NAME]: Boolean(process.env[process.env.HERMES_PROVIDER_KEY_NAME]),
    AUXILIARY_CLOCKCHAIN_MCP_API_KEY: Boolean(process.env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY)
  },
  dotenv_empty: Object.fromEntries(emptyKeys.map((key) => [key, process.env[key] === ""])),
  managed_absent: process.env.HERMES_MANAGED_PRESENT !== "1",
  loaded_count: 1,
  loaded_role_env: true,
  observed_empty_keys: emptyKeys,
  probe_vars_present: Object.keys(process.env).filter((key) => key.startsWith("HERMES_")).sort(),
  role_env_comment_only: envText.split(/\\r?\\n/).every((line) => line.trim() === "" || line.trim().startsWith("#")),
  terminal_sanitizer_removed_auxiliary: !sanitizedKeys.includes("AUXILIARY_CLOCKCHAIN_MCP_API_KEY"),
  terminal_sanitizer_removed_provider: !sanitizedKeys.includes(process.env.HERMES_PROVIDER_KEY_NAME)
}));
`, { mode: 0o755 });
  await chmod(python, 0o755);
  const commandRunner = async (file, args, options) => {
    if (file === "git" && args[0] === "-C" && args[2] === "rev-parse") return { stdout: `${HERMES_HEAD}\n`, stderr: "" };
    if (file === "git" && args[0] === "-C" && args[2] === "describe") return { stdout: `${HERMES_DESCRIBE}\n`, stderr: "" };
    if (file === "git" && args[0] === "-C" && args[2] === "status") return { stdout: dirty ? " M dirty.py\n" : "", stderr: "" };
    const { execFile } = await import("node:child_process");
    return await new Promise((resolvePromise, rejectPromise) => {
      execFile(file, args, options, (error, stdout, stderr) => {
        if (error) rejectPromise(error);
        else resolvePromise({ stdout, stderr });
      });
    });
  };
  return { commandRunner, hermesBinary, installRoot };
}

function basePrepare(root, install) {
  return {
    hermesBinary: install.hermesBinary,
    hermesInstallRoot: install.installRoot,
    commandRunner: install.commandRunner,
    kitCommit: KIT_COMMIT,
    runRoot: join(root, "run"),
  };
}

function providerInput(jti = UUIDS.payer) {
  return {
    clockchainMcpToken: clockchainToken(jti),
    providerKeyName: "MINIMAX_CN_API_KEY",
    providerKeyValue: "minimax-provider-secret-0000000000000000",
  };
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function assertMode(path, mode) {
  if (process.platform === "win32") return;
  assert.equal((await lstat(path)).mode & 0o777, mode);
}

function assertRelativeToRun(runRoot, value) {
  assert.equal(value.startsWith("roles/"), true);
  assert.equal(relative(runRoot, value).startsWith(".."), true);
}

test("prepare and provision are split so both rooms can be prepared before any secret exists", async (t) => {
  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root);
  const payer = await prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer" });
  const requestor = await prepareHermesCleanRoom({ ...basePrepare(root, install), role: "requestor" });

  assert.equal(Object.hasOwn(payer, "env"), false);
  assert.equal(Object.hasOwn(payer, "principalFingerprint"), false);
  await assertMode(payer.roleRoot, 0o700);
  await assertMode(payer.paths.hermesHome, 0o700);
  await assertMode(join(payer.paths.hermesHome, ".env"), 0o600);
  await assertMode(payer.paths.gitConfig, 0o600);
  await assert.rejects(lstat(payer.paths.bootstrapGitConfig), /ENOENT/);
  assert.notEqual(payer.paths.hermesHome, requestor.paths.hermesHome);

  const profileEntries = (await readdir(payer.paths.hermesHome)).sort();
  assert.deepEqual(profileEntries, [".env", ".no-bundled-skills", "home", "skills"]);
  assert.deepEqual(await readdir(join(payer.paths.hermesHome, "home")), []);
  assert.deepEqual(await readdir(join(payer.paths.hermesHome, "skills")), []);
  await assert.rejects(readFile(join(payer.paths.hermesHome, "SOUL.md")), /ENOENT/);
  await assert.rejects(readFile(join(payer.paths.hermesHome, "sessions")), /ENOENT/);

  const preProvision = await readJson(payer.manifests.preProvisionPath);
  assert.deepEqual(Object.keys(preProvision).sort(), ["hermes", "kitCommit", "paths", "phase", "role", "tokensPresent", "zeroState"]);
  assert.equal(preProvision.phase, "pre-provision");
  assert.equal(Object.hasOwn(preProvision, "principalFingerprint"), false);
  assert.equal(preProvision.tokensPresent, false);
  assert.equal(preProvision.hermes.binary, "test-fixture");
  assert.equal(preProvision.hermes.installRoot, "test-fixture");
  assert.equal(preProvision.hermes.packageVersion, "0.19.1");
  assert.equal(preProvision.hermes.gitHead, HERMES_HEAD);
  assert.equal(preProvision.hermes.gitDescribe, HERMES_DESCRIBE);
  assert.equal(preProvision.hermes.configVersion, 33);
  assert.equal(preProvision.zeroState.clean, true);
  assert.deepEqual(preProvision.zeroState.unexpected, []);
  assertRelativeToRun(payer.runRoot, preProvision.paths.hermesHome);
  assert.equal(JSON.stringify(preProvision).includes(payer.paths.hermesHome), false);

  const provisioned = await provisionHermesCleanRoom({ room: payer, ...providerInput(UUIDS.payer) });
  const config = await readJson(provisioned.paths.config);
  assert.deepEqual(config, {
    _config_version: 33,
    agent: { max_turns: 500 },
    fallback_providers: [],
    hooks: {},
    hooks_auto_accept: false,
    mcp_servers: {
      clockchain: {
        enabled: true,
        headers: { "x-api-key": "${AUXILIARY_CLOCKCHAIN_MCP_API_KEY}" },
        supports_parallel_tool_calls: false,
        tools: {
          exclude: [],
          include: RAW_TOOLS,
          prompts: false,
          resources: false,
        },
        url: CLOCKCHAIN_URL,
      },
    },
    memory: { memory_enabled: false, user_profile_enabled: false },
    model: { default: "MiniMax-M3", provider: "minimax-cn" },
    platform_toolsets: { cli: ["terminal", "file", "clockchain"] },
    security: { redact_secrets: true },
    terminal: {
      auto_source_bashrc: false,
      backend: "local",
      cwd: provisioned.paths.workspace,
      env_passthrough: [],
      home_mode: "profile",
      shell_init_files: [],
    },
  });

  assert.equal(provisioned.env.PATH, MAC_PATH);
  assert.equal(provisioned.env.HOME, payer.paths.home);
  assert.equal(provisioned.env.HERMES_HOME, payer.paths.hermesHome);
  assert.equal(provisioned.env.MINIMAX_CN_API_KEY, "minimax-provider-secret-0000000000000000");
  assert.equal(provisioned.env.OPENAI_API_KEY, "");
  assert.equal(provisioned.env.CLOCKCHAIN_TOKEN, "");
  assert.equal(Object.hasOwn(provisioned.env, "MOONSHOT_API_KEY"), false);
  assert.equal(provisioned.probes.envLoader.terminalSanitizerRemovedAuxiliary, true);
  assert.equal(provisioned.probes.envLoader.terminalSanitizerRemovedProvider, true);
  assert.equal(provisioned.probes.envLoader.loadedCount, 1);
  assert.equal(provisioned.probes.envLoader.loadedRoleEnv, true);
  assert.deepEqual(provisioned.probes.envLoader.observedEmptyKeys, ["CLOCKCHAIN_TOKEN", "OPENAI_API_KEY"]);
  assert.equal(provisioned.probes.mcp.shutdownCalled, true);
  assert.deepEqual(provisioned.probes.mcp.registeredTools, REGISTERED_TOOLS);
  await assert.rejects(readFile(join(payer.paths.hermesHome, ".mcp-discovery.lock")), /ENOENT/);

  const prePrompt = await readJson(provisioned.manifests.prePromptPath);
  assert.deepEqual(Object.keys(prePrompt).sort(), [
    "envProbe",
    "hermes",
    "kitCommit",
    "mcp",
    "paths",
    "phase",
    "principalFingerprint",
    "retainedEvidencePath",
    "role",
    "tokensPresent",
    "zeroState",
  ]);
  assert.equal(prePrompt.phase, "pre-prompt");
  assert.deepEqual(Object.keys(provisioned.env).filter((key) => key.startsWith("HERMES_")), ["HERMES_HOME"]);
  assert.equal(prePrompt.principalFingerprint, jtiFingerprint(UUIDS.payer));
  assert.deepEqual(Object.keys(prePrompt.mcp).sort(), ["registeredTools", "shutdownCalled"]);
  assert.deepEqual(prePrompt.mcp.registeredTools, REGISTERED_TOOLS);
  assert.equal(prePrompt.zeroState.clean, true);
  const retained = `${await readFile(payer.manifests.preProvisionPath, "utf8")}\n${await readFile(join(payer.runRoot, prePrompt.retainedEvidencePath), "utf8")}`;
  assert.equal(retained.includes(providerInput(UUIDS.payer).clockchainMcpToken), false);
  assert.equal(retained.includes(providerInput(UUIDS.payer).providerKeyValue), false);
  assert.equal(retained.includes(payer.paths.hermesHome), false);
  assertPublicCleanRoomEvidence(prePrompt, [
    providerInput(UUIDS.payer).clockchainMcpToken,
    providerInput(UUIDS.payer).providerKeyValue,
    payer.paths.hermesHome,
  ]);
});

test("production default adapters use fake executable and venv-python contracts", async (t) => {
  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root);
  const calls = [];
  const room = await prepareHermesCleanRoom({
    ...basePrepare(root, install),
    commandRunner: async (file, args, options) => {
      calls.push({ args, env: options?.env, file });
      if (file === "git" && args[0] === "-C" && args[2] === "rev-parse") return { stdout: `${HERMES_HEAD}\n`, stderr: "" };
      if (file === "git" && args[0] === "-C" && args[2] === "describe") return { stdout: `${HERMES_DESCRIBE}\n`, stderr: "" };
      if (file === "git" && args[0] === "-C" && args[2] === "status") return { stdout: "", stderr: "" };
      const { execFile } = await import("node:child_process");
      return await new Promise((resolvePromise, rejectPromise) => {
        execFile(file, args, options, (error, stdout, stderr) => {
          if (error) rejectPromise(error);
          else resolvePromise({ stdout, stderr });
        });
      });
    },
    role: "payer",
  });
  assert.equal(calls.some((call) => call.file === install.hermesBinary && call.args.join(" ") === "profile create --help"), true);
  assert.equal(calls.some((call) => call.file === join(install.installRoot, "venv", "bin", "python") && call.args[0] === "-c" && call.args[1].includes("hermes_cli.config_defaults.DEFAULT_CONFIG")), true);
  assert.equal(calls.every((call) => call.env?.HOME === undefined || call.env.HOME.startsWith(root)), true);
  assert.equal(calls.every((call) => call.env?.HERMES_HOME === undefined || call.env.HERMES_HOME.startsWith(root)), true);
  const provisioned = await provisionHermesCleanRoom({
    clockchainMcpToken: providerInput(UUIDS.defaultAdapter).clockchainMcpToken,
    inferenceKeyName: "MINIMAX_CN_API_KEY",
    inferenceKeyValue: "minimax-provider-secret-2222222222222222",
    prepared: room,
  });
  assert.deepEqual(provisioned.probes.mcp.registeredTools, REGISTERED_TOOLS);
  assert.equal(provisioned.probes.envLoader.roleEnvCommentOnly, true);
  assert.equal(provisioned.env.MINIMAX_CN_API_KEY, "minimax-provider-secret-2222222222222222");
});

test("provision removes only the pinned empty artifacts created by live MCP discovery", async (t) => {
  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root);
  const room = await prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer" });
  const discoveryArtifacts = async ({ hermesHome }) => {
    for (const directory of [
      "audio_cache",
      "cron",
      "hooks",
      "image_cache",
      "logs/curator",
      "memories",
      "pairing",
      "sessions",
    ]) {
      await mkdir(join(hermesHome, directory), { recursive: true, mode: 0o700 });
    }
    await writeFile(join(hermesHome, "SOUL.md"), "default generated rules\n", { mode: 0o600 });
    await writeFile(join(hermesHome, ".mcp-discovery.lock"), "", { mode: 0o644 });
    return { registeredTools: REGISTERED_TOOLS, shutdownCalled: true };
  };

  const provisioned = await provisionHermesCleanRoom({
    room,
    ...providerInput(UUIDS.payer),
    discoverMcp: discoveryArtifacts,
  });

  assert.deepEqual((await readdir(provisioned.paths.hermesHome)).sort(), [
    ".env",
    ".no-bundled-skills",
    "config.yaml",
    "home",
    "skills",
  ]);
  assert.equal((await readJson(provisioned.manifests.prePromptPath)).zeroState.clean, true);

  const dirtyRoom = await prepareHermesCleanRoom({ ...basePrepare(root, install), role: "requestor" });
  await assert.rejects(
    provisionHermesCleanRoom({
      room: dirtyRoom,
      ...providerInput(UUIDS.retained),
      discoverMcp: async (input) => {
        const result = await discoveryArtifacts(input);
        await writeFile(join(input.hermesHome, "logs", "unexpected.log"), "state");
        return result;
      },
    }),
    /Clean room preparation failed safely/,
  );

  const rejectionCases = [
    {
      name: "missing required artifact",
      mutate: async ({ hermesHome }) => rm(join(hermesHome, "sessions"), { recursive: true }),
    },
    {
      name: "partial artifact set",
      mutate: async ({ hermesHome }) => {
        for (const entry of [
          "SOUL.md",
          "audio_cache",
          "cron",
          "hooks",
          "image_cache",
          "logs",
          "memories",
          "pairing",
          "sessions",
        ]) {
          await rm(join(hermesHome, entry), { force: true, recursive: true });
        }
      },
    },
    {
      name: "nonempty allowed directory",
      mutate: async ({ hermesHome }) => writeFile(join(hermesHome, "audio_cache", "state"), "state"),
    },
    {
      name: "nonempty curator log directory",
      mutate: async ({ hermesHome }) => writeFile(join(hermesHome, "logs", "curator", "state"), "state"),
    },
    {
      name: "symlinked transient directory",
      mutate: async ({ hermesHome, root: caseRoot }) => {
        const external = join(caseRoot, "external-directory");
        await mkdir(external, { mode: 0o700 });
        await rm(join(hermesHome, "audio_cache"), { recursive: true });
        await symlink(external, join(hermesHome, "audio_cache"), "dir");
      },
    },
    {
      name: "symlinked transient file",
      mutate: async ({ hermesHome, root: caseRoot }) => {
        const external = join(caseRoot, "external-soul.md");
        await writeFile(external, "external rules\n", { mode: 0o600 });
        await rm(join(hermesHome, "SOUL.md"));
        await symlink(external, join(hermesHome, "SOUL.md"));
      },
    },
    {
      name: "wrong SOUL mode",
      mutate: async ({ hermesHome }) => chmod(join(hermesHome, "SOUL.md"), 0o644),
    },
    {
      name: "empty SOUL file",
      mutate: async ({ hermesHome }) => writeFile(join(hermesHome, "SOUL.md"), ""),
    },
    {
      name: "oversize SOUL file",
      mutate: async ({ hermesHome }) => writeFile(join(hermesHome, "SOUL.md"), "x".repeat(4_097)),
    },
    {
      name: "wrong transient directory mode",
      mutate: async ({ hermesHome }) => chmod(join(hermesHome, "sessions"), 0o755),
    },
    {
      name: "nonempty discovery lock",
      mutate: async ({ hermesHome }) => writeFile(join(hermesHome, ".mcp-discovery.lock"), "lock"),
    },
  ];

  for (const [index, rejection] of rejectionCases.entries()) {
    await t.test(`rejects ${rejection.name}`, async (caseTest) => {
      const caseRoot = await temporaryRoot(caseTest);
      const caseInstall = await makeFakeHermesInstall(caseRoot);
      const caseRoom = await prepareHermesCleanRoom({
        ...basePrepare(caseRoot, caseInstall),
        role: "payer",
      });
      await assert.rejects(
        provisionHermesCleanRoom({
          room: caseRoom,
          ...providerInput(`70000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`),
          discoverMcp: async (input) => {
            const result = await discoveryArtifacts(input);
            await rejection.mutate({ ...input, root: caseRoot });
            return result;
          },
        }),
        /Clean room preparation failed safely/,
      );
    });
  }
});

test("prepare rejects non-Mac-compatible Hermes detection and cleans partial role roots", async (t) => {
  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root, { dirty: true });
  await assert.rejects(
    prepareHermesCleanRoom({
      ...basePrepare(root, install),
      commandRunner: async (file, args) => {
        if (file === "git" && args[2] === "status") return { stdout: " M dirty.py\n", stderr: "" };
        if (file === "git" && args[2] === "rev-parse") return { stdout: `${HERMES_HEAD}\n`, stderr: "" };
        if (file === "git" && args[2] === "describe") return { stdout: `${HERMES_DESCRIBE}\n`, stderr: "" };
        return { stdout: "profile create agent --no-skills --no-alias\n", stderr: "" };
      },
      role: "payer",
    }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(readdir(join(root, "run", "roles", "payer")), /ENOENT/);
});

test("prepare rejects unexpected profile entries, symlinks, preexisting content, and reused roles", async (t) => {
  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root);
  await assert.rejects(
    prepareHermesCleanRoom({
      ...basePrepare(root, install),
      role: "host",
    }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    prepareHermesCleanRoom({
      ...basePrepare(root, install),
      role: "payer",
      runRoot: "relative",
    }),
    /Clean room preparation failed safely/,
  );
  const symlinkRun = join(root, "symlink-run");
  await symlink(root, symlinkRun);
  await assert.rejects(
    prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer", runRoot: symlinkRun }),
    /Clean room preparation failed safely/,
  );
  const symlinkParentTarget = join(root, "symlink-parent-target");
  await mkdir(symlinkParentTarget, { mode: 0o700 });
  const symlinkParent = join(root, "symlink-parent");
  await symlink(symlinkParentTarget, symlinkParent);
  await assert.rejects(
    prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer", runRoot: join(symlinkParent, "run") }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(readdir(join(symlinkParentTarget, "run")), /ENOENT/);
  const dirtyRun = join(root, "dirty-run");
  await mkdir(join(dirtyRun, "roles", "payer"), { recursive: true, mode: 0o700 });
  await writeFile(join(dirtyRun, "roles", "payer", "old-session"), "prior");
  await assert.rejects(
    prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer", runRoot: dirtyRun }),
    /Clean room preparation failed safely/,
  );

  const prepared = await prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer" });
  assert.equal(prepared.role, "payer");
  await assert.rejects(
    prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer" }),
    /Clean room preparation failed safely/,
  );

  await assert.rejects(
    prepareHermesCleanRoom({
      ...basePrepare(root, install),
      role: "requestor",
      runHermesProfileCreate: async ({ hermesHome }) => {
        const profile = join(hermesHome, "profiles", "agent");
        await mkdir(join(profile, "skills"), { recursive: true });
        await writeFile(join(profile, ".env"), "# ok\n");
        await writeFile(join(profile, ".no-bundled-skills"), "\n");
        await writeFile(join(profile, "SOUL.md"), "x");
        await writeFile(join(profile, "unexpected.db"), "state");
        return { profileDirectory: profile };
      },
    }),
    /Clean room preparation failed safely/,
  );
});

test("provision rejects bad provider names, malformed tokens, equal peer tokens, bad probes, and MCP drift", async (t) => {
  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root);
  const room = await prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer" });
  await assert.rejects(
    provisionHermesCleanRoom({ room, ...providerInput("bad-provider"), providerKeyName: "KIMI_API_KEY" }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    provisionHermesCleanRoom({ room, ...providerInput("bad-token"), clockchainMcpToken: "cc_opaque_token_without_jti_000000" }),
    /Clean room preparation failed safely/,
  );
  for (const payload of [
    { aud: "demo", exp: 2_000_000_000, iat: 1_700_000_000, jti: UUIDS.payer, v: 1 },
    { exp: 2_000_000_000, iat: 1_700_000_000, jti: UUIDS.payer, tier: "prod", v: 1 },
    { exp: 2_000_000_000, iat: 1_700_000_000, jti: "not-a-uuid", tier: "demo", v: 1 },
    { exp: 1_700_000_000, iat: 1_700_000_000, jti: UUIDS.payer, tier: "demo", v: 1 },
    { exp: 2_000_000_000, iat: 1_700_000_000, jti: UUIDS.payer, tier: "demo", v: 2 },
    { extra: true, exp: 2_000_000_000, iat: 1_700_000_000, jti: UUIDS.payer, tier: "demo", v: 1 },
    { exp: 2_000_000_000, iat: 1_700_000_000, jti: UUIDS.payer, sub: "", tier: "demo", v: 1 },
  ]) {
    await assert.rejects(
      provisionHermesCleanRoom({
        room,
        ...providerInput(UUIDS.payer),
        clockchainMcpToken: clockchainTokenWithPayload(payload),
      }),
      /Clean room preparation failed safely/,
    );
  }
  const token = clockchainToken(UUIDS.same);
  await assert.rejects(
    provisionHermesCleanRoom({ room, ...providerInput(UUIDS.same), clockchainMcpToken: token, peerClockchainMcpToken: token }),
    /Clean room preparation failed safely/,
  );
  const validEnvProbe = {
    allowedSecretKeysPresent: { MINIMAX_CN_API_KEY: true, AUXILIARY_CLOCKCHAIN_MCP_API_KEY: true },
    dotenvEmpty: { CLOCKCHAIN_TOKEN: true, OPENAI_API_KEY: true },
    loadedCount: 1,
    loadedRoleEnv: true,
    managedAbsent: true,
    observedEmptyKeys: ["CLOCKCHAIN_TOKEN", "OPENAI_API_KEY"],
    roleEnvCommentOnly: true,
    terminalSanitizerRemovedAuxiliary: true,
    terminalSanitizerRemovedProvider: true,
  };
  for (const badProbe of [
    { ...validEnvProbe, allowedSecretKeysPresent: { MINIMAX_CN_API_KEY: true } },
    { ...validEnvProbe, allowedSecretKeysPresent: { MINIMAX_CN_API_KEY: true, AUXILIARY_CLOCKCHAIN_MCP_API_KEY: false } },
    { ...validEnvProbe, dotenvEmpty: { CLOCKCHAIN_TOKEN: true } },
    { ...validEnvProbe, loadedCount: 0 },
    { ...validEnvProbe, loadedRoleEnv: false },
    { ...validEnvProbe, observedEmptyKeys: ["CLOCKCHAIN_TOKEN"] },
    { ...validEnvProbe, roleEnvCommentOnly: false },
    { ...validEnvProbe, terminalSanitizerRemovedAuxiliary: false },
    { ...validEnvProbe, terminalSanitizerRemovedProvider: false },
  ]) {
    await assert.rejects(
      provisionHermesCleanRoom({
        room,
        ...providerInput(UUIDS.payer),
        probeEnvLoader: async () => badProbe,
      }),
      /Clean room preparation failed safely/,
    );
  }
  await assert.rejects(
    provisionHermesCleanRoom({
      room,
      ...providerInput(UUIDS.payer),
      discoverMcp: async () => ({
        promptsEnabled: false,
        registeredTools: [...REGISTERED_TOOLS, "mcp__clockchain__handshake_debug"],
        resourcesEnabled: false,
        servers: [{ enabled: true, name: "clockchain", url: CLOCKCHAIN_URL }],
        shutdownCalled: true,
      }),
    }),
    /Clean room preparation failed safely/,
  );
});

test("Clockchain demo token fingerprint uses the real tier payload shape and rejects aud", () => {
  assert.equal(fingerprintClockchainDemoToken(clockchainToken(UUIDS.payer)), jtiFingerprint(UUIDS.payer));
  assert.throws(
    () => fingerprintClockchainDemoToken(clockchainTokenWithPayload({
      aud: "demo",
      exp: 2_000_000_000,
      iat: 1_700_000_000,
      jti: UUIDS.payer,
      v: 1,
    })),
    /Clean room preparation failed safely/,
  );
});

test("evidence scanner rejects embedded absolute paths, canaries, and retained secret bytes", async (t) => {
  assert.throws(
    () => assertPublicCleanRoomEvidence({ message: `prefix ${MAC_INSTALL_ROOT}/secret suffix` }),
    /Secret material detected/,
  );
  assert.throws(
    () => assertPublicCleanRoomEvidence({ nested: ["prefix secret-canary suffix"] }, ["secret-canary"]),
    /Secret material detected/,
  );

  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root);
  const room = await prepareHermesCleanRoom({ ...basePrepare(root, install), role: "payer" });
  const secret = "retired-provider-secret-retained-111111111111111";
  const provisioned = await provisionHermesCleanRoom({
    room,
    ...providerInput(UUIDS.retained),
    providerKeyValue: secret,
  });
  for (const path of [room.manifests.preProvisionPath, provisioned.manifests.prePromptPath]) {
    const bytes = await readFile(path, "utf8");
    assert.equal(bytes.includes(secret), false);
    assert.equal(bytes.includes(provisioned.env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY), false);
    assert.equal(bytes.includes(room.paths.hermesHome), false);
    assertPublicCleanRoomEvidence(JSON.parse(bytes), [secret, provisioned.env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY, room.paths.hermesHome]);
  }
});
