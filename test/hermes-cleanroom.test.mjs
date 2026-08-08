import assert from "node:assert/strict";
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
import { isAbsolute, join, relative } from "node:path";
import { test } from "node:test";

import {
  assertPublicCleanRoomEvidence,
  prepareCleanRoom,
} from "../src/core/hermes-cleanroom.mjs";

const CLOCKCHAIN_URL = "https://mcp.clockchain.network/mcp";
const CLOCKCHAIN_TOOLS = Object.freeze([
  "mcp__clockchain__handshake_status",
  "mcp__clockchain__handshake_join",
  "mcp__clockchain__handshake_next",
  "mcp__clockchain__handshake_submit",
  "mcp__clockchain__handshake_get_certificate",
]);

async function temporaryRoot(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "hermes-cleanroom-")));
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

async function createInstallRoot(root, dotenv = [
  "KIMI_API_KEY=from-shared-dotenv",
  "OPENAI_API_KEY=from-shared-dotenv",
  "CLOCKCHAIN_TOKEN=from-shared-dotenv",
]) {
  const installRoot = join(root, "hermes-install");
  await mkdir(installRoot, { recursive: true });
  await writeFile(join(installRoot, ".env"), `${dotenv.join("\n")}\n`);
  return installRoot;
}

function defaultOptions(root, overrides = {}) {
  const calls = {
    profileCreates: [],
    probes: [],
    discoveries: [],
  };

  const options = {
    clockchainMcpToken: "cc_role_token_AAAAAAAAAAAAAAAAAAAAA",
    detectHermes: async () => ({
      configVersion: 33,
      gitDescribe: "v2026.7.30-357-g87bc71060",
      gitHead: "87bc710609f8b89b6e6b4aa418dde8ee30ec6873",
      installRoot: join(root, "hermes-install"),
      managedConfigPresent: false,
      managedEnvPresent: false,
      packageVersion: "0.19.1",
      secretScope: "role",
      supported: true,
      version: "v2026.7.30-357-g87bc71060",
    }),
    discoverMcp: async ({ config, env, hermesHome }) => {
      calls.discoveries.push({ config, env });
      await writeFile(join(hermesHome, ".mcp-discovery.lock"), "lock");
      return {
        resourcesEnabled: false,
        promptsEnabled: false,
        servers: [{ name: "clockchain", url: CLOCKCHAIN_URL }],
        tools: CLOCKCHAIN_TOOLS,
      };
    },
    env: {
      AWS_SECRET_ACCESS_KEY: "ambient-shared-secret",
      HERMES_TOKEN: "ambient-shared-token",
    },
    hermesBinary: join(root, "bin", "hermes"),
    inferenceKeyName: "KIMI_API_KEY",
    inferenceKeyValue: "kimi-role-secret-BBBBBBBBBBBBBBBBBBBB",
    kitCommit: "0123456789abcdef0123456789abcdef01234567",
    pathValue: "/usr/bin:/bin",
    principal: "payer-principal-public-id",
    probeEnvLoader: async ({ emptyKeys, env, allowedSecretKeys }) => {
      calls.probes.push({ emptyKeys, env, allowedSecretKeys });
      return {
        allowedSecretKeys,
        emptyKeys: Object.fromEntries(emptyKeys.map((key) => [key, env[key] === ""])),
      };
    },
    runHermesProfileCreate: async ({ args, env, hermesHome }) => {
      calls.profileCreates.push({ args, env, hermesHome });
      assert.deepEqual(args, ["profile", "create", "agent", "--no-skills", "--no-alias"]);
      assert.equal(args.includes("-p"), false);
      assert.equal(env.HOME.startsWith(root), true);
      assert.equal(env.HERMES_HOME.startsWith(root), true);
      assert.equal(env.KIMI_API_KEY, "");
      assert.equal(env.OPENAI_API_KEY, "");
      assert.equal(env.CLOCKCHAIN_TOKEN, "");
      await mkdir(join(hermesHome, "profiles", "agent", "skills"), { recursive: true, mode: 0o700 });
      await writeFile(join(hermesHome, "profiles", "agent", ".no-bundled-skills"), "\n");
      await writeFile(join(hermesHome, "profiles", "agent", "SOUL.md"), "generated default rules");
      return { profileDirectory: join(hermesHome, "profiles", "agent") };
    },
    runRoot: join(root, "run"),
    role: "payer",
    ...overrides,
  };

  return { calls, options };
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function assertInside(root, value) {
  assert.equal(isAbsolute(value), true);
  assert.equal(relative(root, value).startsWith(".."), false);
}

test("prepareCleanRoom creates disjoint standalone role roots and secret-free manifests", async (t) => {
  const root = await temporaryRoot(t);
  const installRoot = await createInstallRoot(root);
  const payer = defaultOptions(root, { hermesInstallRoot: installRoot, role: "payer" });
  const requestor = defaultOptions(root, {
    clockchainMcpToken: "cc_role_token_CCCCCCCCCCCCCCCCCCCCC",
    hermesInstallRoot: installRoot,
    inferenceKeyValue: "kimi-role-secret-DDDDDDDDDDDDDDDDDDDD",
    principal: "requestor-principal-public-id",
    role: "requestor",
  });

  const payerRoom = await prepareCleanRoom(payer.options);
  const requestorRoom = await prepareCleanRoom(requestor.options);

  assert.equal(payerRoom.role, "payer");
  assert.equal(requestorRoom.role, "requestor");
  assert.notEqual(payerRoom.paths.hermesHome, requestorRoom.paths.hermesHome);
  assert.notEqual(payerRoom.paths.home, requestorRoom.paths.home);
  assert.notEqual(payerRoom.paths.workspace, requestorRoom.paths.workspace);
  for (const path of Object.values(payerRoom.paths)) assertInside(payer.options.runRoot, path);
  assert.equal((await lstat(payerRoom.roleRoot)).mode & 0o777, 0o700);
  assert.equal((await lstat(payerRoom.paths.config)).mode & 0o777, 0o600);
  assert.equal((await lstat(payerRoom.manifests.preProvisionPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(payerRoom.manifests.prePromptPath)).mode & 0o777, 0o600);

  const config = await readJson(payerRoom.paths.config);
  assert.equal(config.model, "k3");
  assert.equal(config.provider, "kimi-coding");
  assert.equal(config.max_turns, 500);
  assert.deepEqual(config.fallbacks, []);
  assert.equal(config.memory.enabled, false);
  assert.equal(config.user_profile.enabled, false);
  assert.equal(config.terminal.home_mode, "profile");
  assert.equal(config.terminal.source_init_files, false);
  assert.deepEqual(config.hooks, {});
  assert.equal(config.redact_secrets, true);
  assert.equal(Object.hasOwn(config, "toolsets"), false);
  assert.deepEqual(Object.keys(config.platform_toolsets.cli.mcp_servers), ["clockchain"]);
  assert.equal(config.platform_toolsets.cli.mcp_servers.clockchain.url, CLOCKCHAIN_URL);
  assert.equal(config.platform_toolsets.cli.mcp_servers.clockchain.headers["x-api-key"], "${AUXILIARY_CLOCKCHAIN_MCP_API_KEY}");
  assert.deepEqual(config.platform_toolsets.cli.mcp_servers.clockchain.include_tools, CLOCKCHAIN_TOOLS);
  assert.equal(config.platform_toolsets.cli.mcp_servers.clockchain.resources, false);
  assert.equal(config.platform_toolsets.cli.mcp_servers.clockchain.prompts, false);
  assert.equal(config.terminal.cwd, payerRoom.paths.workspace);

  assert.equal(payerRoom.env.HOME, payerRoom.paths.home);
  assert.equal(payerRoom.env.HERMES_HOME, payerRoom.paths.hermesHome);
  assert.equal(payerRoom.env.XDG_CACHE_HOME, payerRoom.paths.xdgCache);
  assert.equal(payerRoom.env.NPM_CONFIG_CACHE, payerRoom.paths.npmCache);
  assert.equal(payerRoom.env.COREPACK_HOME, payerRoom.paths.corepackHome);
  assert.equal(payerRoom.env.TMPDIR, payerRoom.paths.tmp);
  assert.equal(payerRoom.env.GIT_CONFIG_GLOBAL, payerRoom.paths.gitConfig);
  assert.equal(payerRoom.env.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(payerRoom.env.PYTHONNOUSERSITE, "1");
  assert.equal(payerRoom.env.PATH, "/usr/bin:/bin");
  assert.equal(payerRoom.env.KIMI_API_KEY, payer.options.inferenceKeyValue);
  assert.equal(payerRoom.env.OPENAI_API_KEY, "");
  assert.equal(payerRoom.env.CLOCKCHAIN_TOKEN, "");
  assert.equal(payerRoom.env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY, payer.options.clockchainMcpToken);
  assert.equal(Object.hasOwn(payerRoom.env, "AWS_SECRET_ACCESS_KEY"), false);
  assert.equal(Object.hasOwn(payerRoom.env, "HERMES_TOKEN"), false);

  const profileEntries = await readdir(payerRoom.paths.hermesHome);
  assert.deepEqual(profileEntries.sort(), [".no-bundled-skills", "config.yaml", "skills"].sort());
  assert.deepEqual(await readdir(join(payerRoom.paths.hermesHome, "skills")), []);
  await assert.rejects(readFile(join(payerRoom.paths.hermesHome, "SOUL.md")), /ENOENT/);
  await assert.rejects(readFile(join(payerRoom.paths.hermesHome, ".mcp-discovery.lock")), /ENOENT/);

  const preProvision = await readJson(payerRoom.manifests.preProvisionPath);
  const prePrompt = await readJson(payerRoom.manifests.prePromptPath);
  assert.equal(preProvision.phase, "pre-provision");
  assert.equal(prePrompt.phase, "pre-prompt");
  assert.equal(preProvision.tokensPresent, false);
  assert.equal(prePrompt.tokensPresent, true);
  assert.equal(preProvision.zeroState.clean, true);
  assert.equal(prePrompt.zeroState.clean, true);
  assert.equal(prePrompt.zeroState.reinspectedBeforePrompt, true);
  assert.equal(prePrompt.hermes.packageVersion, "0.19.1");
  assert.equal(prePrompt.hermes.gitHead, "87bc710609f8b89b6e6b4aa418dde8ee30ec6873");
  assert.equal(prePrompt.hermes.gitDescribe, "v2026.7.30-357-g87bc71060");
  assert.equal(prePrompt.hermes.configVersion, 33);
  assert.deepEqual(prePrompt.mcp.tools, CLOCKCHAIN_TOOLS);
  assert.equal(prePrompt.mcp.servers.length, 1);
  assert.match(prePrompt.principalFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(prePrompt).includes(payer.options.clockchainMcpToken), false);
  assert.equal(JSON.stringify(prePrompt).includes(payer.options.inferenceKeyValue), false);
  assert.equal(JSON.stringify(prePrompt).includes(payerRoom.paths.hermesHome), false);
  assertPublicCleanRoomEvidence(preProvision, [
    payer.options.clockchainMcpToken,
    payer.options.inferenceKeyValue,
    payerRoom.paths.hermesHome,
  ]);
  assertPublicCleanRoomEvidence(prePrompt, [
    payer.options.clockchainMcpToken,
    payer.options.inferenceKeyValue,
    payerRoom.paths.hermesHome,
  ]);

  assert.equal(payer.calls.profileCreates.length, 1);
  assert.equal(payer.calls.probes.length, 1);
  assert.equal(payer.calls.discoveries.length, 1);
});

test("prepareCleanRoom fails closed for invalid or reused role boundaries", async (t) => {
  const root = await temporaryRoot(t);
  const installRoot = await createInstallRoot(root);
  const base = defaultOptions(root, { hermesInstallRoot: installRoot });

  await assert.rejects(
    prepareCleanRoom({ ...base.options, role: "host" }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    prepareCleanRoom({ ...base.options, runRoot: "relative-run" }),
    /Clean room preparation failed safely/,
  );

  await prepareCleanRoom(base.options);
  await assert.rejects(
    prepareCleanRoom(base.options),
    /Clean room preparation failed safely/,
  );

  const linkedRoot = join(root, "linked-run");
  await symlink(base.options.runRoot, linkedRoot);
  await assert.rejects(
    prepareCleanRoom({ ...base.options, runRoot: linkedRoot, role: "requestor" }),
    /Clean room preparation failed safely/,
  );

  const dirtyRun = join(root, "dirty-run");
  await mkdir(join(dirtyRun, "roles", "payer"), { recursive: true, mode: 0o700 });
  await writeFile(join(dirtyRun, "roles", "payer", "old-session"), "prior state");
  await assert.rejects(
    prepareCleanRoom({ ...base.options, runRoot: dirtyRun }),
    /Clean room preparation failed safely/,
  );
});

test("prepareCleanRoom rejects symlinks, inherited state, equal tokens, unsupported Hermes, and managed scope", async (t) => {
  const root = await temporaryRoot(t);
  const installRoot = await createInstallRoot(root);
  const base = defaultOptions(root, { hermesInstallRoot: installRoot });

  await assert.rejects(
    prepareCleanRoom({ ...base.options, clockchainMcpToken: "same", peerClockchainMcpToken: "same" }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    prepareCleanRoom({ ...base.options, detectHermes: async () => ({ supported: false }) }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    prepareCleanRoom({
      ...base.options,
      detectHermes: async () => ({
        build: "managed",
        configVersion: 1,
        installRoot,
        secretScope: "/etc/hermes",
        supported: true,
        version: "1.0.0",
      }),
    }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    prepareCleanRoom({
      ...base.options,
      detectHermes: async () => ({
        configVersion: 33,
        installRoot,
        managedConfigPresent: true,
        managedEnvPresent: false,
        packageVersion: "0.19.1",
        secretScope: "role",
        supported: true,
        version: "v2026.7.30-357-g87bc71060",
      }),
    }),
    /Clean room preparation failed safely/,
  );
  await assert.rejects(
    prepareCleanRoom({
      ...base.options,
      detectHermes: async () => ({
        configVersion: 33,
        installRoot,
        managedConfigPresent: false,
        managedEnvPresent: true,
        packageVersion: "0.19.1",
        secretScope: "role",
        supported: true,
        version: "v2026.7.30-357-g87bc71060",
      }),
    }),
    /Clean room preparation failed safely/,
  );

  const symlinkRun = join(root, "symlink-state-run");
  await mkdir(join(symlinkRun, "roles", "payer", "home"), { recursive: true, mode: 0o700 });
  await symlink(root, join(symlinkRun, "roles", "payer", "home", "sessions"));
  await assert.rejects(
    prepareCleanRoom({ ...base.options, runRoot: symlinkRun }),
    /Clean room preparation failed safely/,
  );
});

test("prepareCleanRoom neutralizes install dotenv but rejects extra secret env", async (t) => {
  const root = await temporaryRoot(t);
  const installRoot = await createInstallRoot(root);
  const base = defaultOptions(root, { hermesInstallRoot: installRoot });

  const room = await prepareCleanRoom(base.options);
  assert.equal(room.env.OPENAI_API_KEY, "");
  assert.equal(room.env.CLOCKCHAIN_TOKEN, "");
  assert.equal(room.probes.envLoader.emptyKeys.OPENAI_API_KEY, true);
  assert.equal(room.probes.envLoader.emptyKeys.CLOCKCHAIN_TOKEN, true);

  await assert.rejects(
    prepareCleanRoom({
      ...base.options,
      role: "requestor",
      extraEnv: { ANALYTICS_TOKEN: "unexpected-secret" },
    }),
    /Clean room preparation failed safely/,
  );
});

test("prepareCleanRoom rejects noncanonical MCP discovery", async (t) => {
  const root = await temporaryRoot(t);
  const installRoot = await createInstallRoot(root);
  const base = defaultOptions(root, { hermesInstallRoot: installRoot });

  await assert.rejects(
    prepareCleanRoom({
      ...base.options,
      discoverMcp: async () => ({
        resourcesEnabled: false,
        promptsEnabled: false,
        servers: [
          { name: "clockchain", url: CLOCKCHAIN_URL },
          { name: "extra", url: "https://example.invalid/mcp" },
        ],
        tools: CLOCKCHAIN_TOOLS,
      }),
    }),
    /Clean room preparation failed safely/,
  );

  await assert.rejects(
    prepareCleanRoom({
      ...base.options,
      role: "requestor",
      discoverMcp: async () => ({
        resourcesEnabled: false,
        promptsEnabled: false,
        servers: [{ name: "clockchain", url: CLOCKCHAIN_URL }],
        tools: [...CLOCKCHAIN_TOOLS, "mcp__clockchain__handshake_debug"],
      }),
    }),
    /Clean room preparation failed safely/,
  );
});

test("public clean-room evidence checker rejects canaries and secret-shaped fields", () => {
  assert.throws(
    () => assertPublicCleanRoomEvidence({ token: "cc_abcdefghijklmnopqrstuvwxyz" }),
    /Secret material detected/,
  );
  assert.throws(
    () => assertPublicCleanRoomEvidence({ path: "/tmp/run/private-home" }, ["/tmp/run/private-home"]),
    /Secret material detected/,
  );
});
