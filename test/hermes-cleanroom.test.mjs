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
  prepareCleanRoom,
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

function jwtWithJti(jti) {
  const enc = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${enc({ alg: "none", typ: "JWT" })}.${enc({ jti, sub: "not-authoritative" })}.signature`;
}

function jtiFingerprint(jti) {
  return createHash("sha256").update(`jti:${jti}`).digest("hex");
}

async function makeFakeHermesInstall(root, {
  dirty = false,
  dotenv = [
    "KIMI_API_KEY=from-shared-dotenv",
    "OPENAI_API_KEY=from-shared-dotenv",
    "CLOCKCHAIN_TOKEN=from-shared-dotenv",
  ],
} = {}) {
  const installRoot = join(root, "hermes-agent");
  const binDir = join(root, "bin");
  const hermesBinary = join(binDir, "hermes");
  const python = join(installRoot, ".venv", "bin", "python");
  await mkdir(binDir, { recursive: true });
  await mkdir(join(installRoot, ".venv", "bin"), { recursive: true });
  await writeFile(join(installRoot, ".env"), `${dotenv.join("\n")}\n`);
  await writeFile(join(installRoot, "package-version.txt"), "0.19.1\n");
  await writeFile(join(installRoot, "config-version.txt"), "33\n");
  await writeFile(join(installRoot, "managed-env.txt"), "\n");
  await writeFile(join(installRoot, "managed-config.txt"), "\n");
  await writeFile(join(installRoot, "dirty.txt"), dirty ? "dirty\n" : "\n");
  await writeFile(hermesBinary, `#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
if (process.argv.includes("--version")) {
  process.stdout.write("hermes 0.19.1\\n");
  process.exit(0);
}
if (process.argv.includes("--help")) {
  process.stdout.write("profile create agent --no-skills --no-alias\\n");
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
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const code = process.argv[2] || "";
if (code.includes("discover_mcp_tools")) {
  writeFileSync(join(process.env.HERMES_HOME, ".mcp-discovery.lock"), "lock");
  process.stdout.write(JSON.stringify({
    prompts_enabled: false,
    resources_enabled: false,
    registered_tools: ${JSON.stringify(REGISTERED_TOOLS)},
    servers: [{ enabled: true, name: "clockchain", url: "${CLOCKCHAIN_URL}" }],
    shutdown_called: true
  }));
  process.exit(0);
}
const envText = readFileSync(join(process.env.HERMES_HOME, ".env"), "utf8");
const emptyKeys = JSON.parse(process.env.HERMES_EMPTY_KEYS_JSON);
process.stdout.write(JSON.stringify({
  allowed_secret_keys_present: {
    [process.env.HERMES_PROVIDER_KEY_NAME]: Boolean(process.env[process.env.HERMES_PROVIDER_KEY_NAME]),
    AUXILIARY_CLOCKCHAIN_MCP_API_KEY: Boolean(process.env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY)
  },
  dotenv_empty: Object.fromEntries(emptyKeys.map((key) => [key, process.env[key] === ""])),
  managed_absent: process.env.HERMES_MANAGED_PRESENT !== "1",
  role_env_comment_only: envText.split(/\\r?\\n/).every((line) => line.trim() === "" || line.trim().startsWith("#")),
  sanitizer_neutralized: true,
  terminal_sanitizer_removed_auxiliary: true,
  terminal_sanitizer_removed_provider: true
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

function providerInput(jti = "payer-token-jti") {
  return {
    clockchainMcpToken: jwtWithJti(jti),
    providerKeyName: "KIMI_API_KEY",
    providerKeyValue: "kimi-provider-secret-00000000000000000000",
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
  assert.equal(preProvision.phase, "pre-provision");
  assert.equal(Object.hasOwn(preProvision, "principalFingerprint"), false);
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

  const provisioned = await provisionHermesCleanRoom({ room: payer, ...providerInput("payer-jti-1") });
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
    model: { default: "k3", provider: "kimi-coding" },
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
  assert.equal(provisioned.env.KIMI_API_KEY, "kimi-provider-secret-00000000000000000000");
  assert.equal(provisioned.env.OPENAI_API_KEY, "");
  assert.equal(provisioned.env.CLOCKCHAIN_TOKEN, "");
  assert.equal(Object.hasOwn(provisioned.env, "MOONSHOT_API_KEY"), false);
  assert.equal(provisioned.probes.envLoader.terminalSanitizerRemovedAuxiliary, true);
  assert.equal(provisioned.probes.envLoader.terminalSanitizerRemovedProvider, true);
  assert.equal(provisioned.probes.mcp.shutdownCalled, true);
  assert.deepEqual(provisioned.probes.mcp.registeredTools, REGISTERED_TOOLS);
  await assert.rejects(readFile(join(payer.paths.hermesHome, ".mcp-discovery.lock")), /ENOENT/);

  const prePrompt = await readJson(provisioned.manifests.prePromptPath);
  assert.equal(prePrompt.phase, "pre-prompt");
  assert.equal(prePrompt.principalFingerprint, jtiFingerprint("payer-jti-1"));
  assert.deepEqual(prePrompt.mcp.registeredTools, REGISTERED_TOOLS);
  assert.equal(prePrompt.zeroState.clean, true);
  const retained = `${await readFile(payer.manifests.preProvisionPath, "utf8")}\n${await readFile(join(payer.runRoot, prePrompt.retainedEvidencePath), "utf8")}`;
  assert.equal(retained.includes(providerInput("payer-jti-1").clockchainMcpToken), false);
  assert.equal(retained.includes("kimi-provider-secret-00000000000000000000"), false);
  assert.equal(retained.includes(payer.paths.hermesHome), false);
  assertPublicCleanRoomEvidence(prePrompt, [
    providerInput("payer-jti-1").clockchainMcpToken,
    "kimi-provider-secret-00000000000000000000",
    payer.paths.hermesHome,
  ]);
});

test("compatibility wrapper preserves ordering by emitting both phase manifests", async (t) => {
  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root);
  const room = await prepareCleanRoom({
    ...basePrepare(root, install),
    role: "payer",
    ...providerInput("wrapper-jti"),
  });
  assert.equal(room.manifests.preProvisionPath.endsWith("pre-provision.json"), true);
  assert.equal(room.manifests.prePromptPath.endsWith("pre-prompt.json"), true);
  const preProvision = await readJson(room.manifests.preProvisionPath);
  assert.equal(Object.hasOwn(preProvision, "principalFingerprint"), false);
});

test("production default adapters use fake executable and venv-python contracts", async (t) => {
  const root = await temporaryRoot(t);
  const install = await makeFakeHermesInstall(root);
  const room = await prepareHermesCleanRoom({
    ...basePrepare(root, install),
    commandRunner: async (file, args, options) => {
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
  const provisioned = await provisionHermesCleanRoom({ room, ...providerInput("default-adapter-jti") });
  assert.deepEqual(provisioned.probes.mcp.registeredTools, REGISTERED_TOOLS);
  assert.equal(provisioned.probes.envLoader.roleEnvCommentOnly, true);
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
    provisionHermesCleanRoom({ room, ...providerInput("bad-provider"), providerKeyName: "MOONSHOT_API_KEY" }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    provisionHermesCleanRoom({ room, ...providerInput("bad-token"), clockchainMcpToken: "cc_opaque_token_without_jti_000000" }),
    /Clean room preparation failed safely/,
  );
  const token = jwtWithJti("same-token");
  await assert.rejects(
    provisionHermesCleanRoom({ room, ...providerInput("same-token"), clockchainMcpToken: token, peerClockchainMcpToken: token }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    provisionHermesCleanRoom({
      room,
      ...providerInput("bad-env-probe"),
      probeEnvLoader: async () => ({
        allowedSecretKeysPresent: { KIMI_API_KEY: true, AUXILIARY_CLOCKCHAIN_MCP_API_KEY: false },
        dotenvEmpty: {},
        managedAbsent: true,
        roleEnvCommentOnly: true,
        sanitizerNeutralized: true,
        terminalSanitizerRemovedAuxiliary: true,
        terminalSanitizerRemovedProvider: true,
      }),
    }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    provisionHermesCleanRoom({
      room,
      ...providerInput("bad-mcp"),
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
  const secret = "kimi-provider-secret-retained-111111111111111111";
  const provisioned = await provisionHermesCleanRoom({
    room,
    ...providerInput("retained-scan"),
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
