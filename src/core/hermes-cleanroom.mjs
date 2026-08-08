import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
} from "node:path";
import { promisify } from "node:util";

import { writePrivateFile } from "./private-path.mjs";
import { SecretMaterialDetectedError } from "./redact.mjs";

const execFileAsync = promisify(execFileCallback);

const VALID_ROLES = Object.freeze(["payer", "requestor"]);
const CLOCKCHAIN_URL = "https://mcp.clockchain.network/mcp";
const CLOCKCHAIN_TOOLS = Object.freeze([
  "mcp__clockchain__handshake_status",
  "mcp__clockchain__handshake_join",
  "mcp__clockchain__handshake_next",
  "mcp__clockchain__handshake_submit",
  "mcp__clockchain__handshake_get_certificate",
]);
const DEFAULT_HERMES_BINARY = "/Users/maxiaoer/.local/bin/hermes";
const DEFAULT_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";
const DOTENV_KEY_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;
const KIMI_KEY_NAMES = Object.freeze(["KIMI_API_KEY", "MOONSHOT_API_KEY"]);
const SECRET_KEY_PATTERN = /(?:KEY|TOKEN|SECRET|AUTH|PASSWORD|CREDENTIAL)/i;
const FORBIDDEN_STATE_NAMES = Object.freeze([
  ".auth",
  ".cache",
  ".env",
  ".git",
  ".hermes",
  ".mcp-discovery.lock",
  ".mcp-token-cache",
  ".npm",
  ".npmrc",
  ".pnp.cjs",
  ".pnpm-store",
  ".profile",
  ".venv",
  "auth",
  "bundles",
  "contacts",
  "hooks",
  "memory",
  "messages",
  "node_modules",
  "package-lock.json",
  "package.json",
  "pairings",
  "plugins",
  "pnpm-lock.yaml",
  "profile",
  "repo",
  "sessions",
  "skills",
  "wallet",
  "wallet.json",
  "yarn.lock",
]);
const SECRET_STRING_PATTERNS = Object.freeze([
  /\bcc_[A-Za-z0-9_-][A-Za-z0-9._-]{19,}(?![A-Za-z0-9._-])/,
  /\bBearer[ \t]+[A-Za-z0-9._~+/-]{24,}(?:={0,2})(?![A-Za-z0-9._~+/-])/i,
  /\b(?:private[\s_-]?key|priv[\s_-]?key|wallet[\s_-]?key)\b\s*(?:(?:is)\s+|[:=]\s*)?0x[0-9a-f]{64}(?![0-9a-f])/i,
]);

function fail() {
  throw new Error("Clean room preparation failed safely.");
}

function sanitize(error) {
  if (error?.message === "Clean room preparation failed safely.") throw error;
  fail();
}

function canonicalAbsolutePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !isAbsolute(value) ||
    resolve(value) !== value ||
    parse(value).root === value ||
    value.includes("\0")
  ) {
    fail();
  }
  return value;
}

function assertRole(value) {
  if (!VALID_ROLES.includes(value)) fail();
  return value;
}

function assertDescendant(root, child) {
  const path = canonicalAbsolutePath(child);
  const offset = relative(root, path);
  if (offset === "" || offset.startsWith("..") || isAbsolute(offset)) fail();
  return path;
}

async function lstatOptional(path) {
  try {
    return await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

async function assertPrivateDirectory(path) {
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) fail();
  if (process.platform !== "win32" && (stats.mode & 0o777) !== 0o700) fail();
}

async function createPrivateDirectory(path) {
  const parent = dirname(path);
  const parentStats = await lstatOptional(parent);
  if (parentStats === undefined) {
    await createPrivateDirectory(parent);
  }
  await mkdir(path, { mode: 0o700, recursive: false });
  if (process.platform !== "win32") await chmod(path, 0o700);
  await assertPrivateDirectory(path);
}

async function ensureRunRoot(path) {
  const stats = await lstatOptional(path);
  if (stats === undefined) {
    await createPrivateDirectory(path);
  } else if (!stats.isDirectory() || stats.isSymbolicLink()) {
    fail();
  } else {
    await assertPrivateDirectory(path);
  }
  const canonical = await realpath(path);
  if (canonical !== path) fail();
}

async function assertNoSymlinkTree(path) {
  const stats = await lstatOptional(path);
  if (stats === undefined) return;
  if (stats.isSymbolicLink()) fail();
  if (!stats.isDirectory()) return;
  for (const entry of await readdir(path)) {
    await assertNoSymlinkTree(join(path, entry));
  }
}

async function assertMissing(path) {
  if (await lstatOptional(path) !== undefined) fail();
}

async function assertDirectoryEmpty(path) {
  const entries = await readdir(path);
  if (entries.length !== 0) fail();
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

async function parseDotenvKeys(installRoot) {
  const dotenvPath = join(canonicalAbsolutePath(installRoot), ".env");
  let text;
  try {
    text = await readFile(dotenvPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  return sortedUnique(
    text
      .split(/\r?\n/)
      .map((line) => DOTENV_KEY_PATTERN.exec(line)?.[1])
      .filter((value) => value !== undefined),
  );
}

function assertNoAmbientSecretEnv(env) {
  for (const [key, value] of Object.entries(env ?? {})) {
    if (SECRET_KEY_PATTERN.test(key) && value !== "" && value !== undefined) fail();
  }
}

function assertSingleKimiKey(name) {
  if (!KIMI_KEY_NAMES.includes(name)) fail();
  return name;
}

function assertSecretValue(value) {
  if (typeof value !== "string" || value.length === 0) fail();
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function relativeIdentifier(root, path) {
  const offset = relative(root, path);
  if (offset === "" || offset.startsWith("..") || isAbsolute(offset)) fail();
  return offset.split("\\").join("/");
}

function buildConfig({ configVersion, envKeyName, workspace }) {
  return Object.freeze({
    config_version: configVersion,
    fallbacks: [],
    hooks: {},
    max_turns: 500,
    memory: { enabled: false },
    model: "k3",
    platform_toolsets: {
      cli: {
        mcp_servers: {
          clockchain: {
            headers: {
              "x-api-key": "${AUXILIARY_CLOCKCHAIN_MCP_API_KEY}",
            },
            include_tools: CLOCKCHAIN_TOOLS,
            prompts: false,
            resources: false,
            transport: "http",
            url: CLOCKCHAIN_URL,
          },
        },
      },
    },
    provider: "kimi-coding",
    provider_env_key: envKeyName,
    redact_secrets: true,
    terminal: {
      cwd: workspace,
      env_passthrough: false,
      home_mode: "profile",
      local: true,
      source_init_files: false,
    },
    user_profile: { enabled: false },
  });
}

function buildEnvironment({
  clockchainMcpToken,
  dotenvKeys,
  envKeyName,
  inferenceKeyValue,
  paths,
  pathValue,
}) {
  const env = {
    COREPACK_HOME: paths.corepackHome,
    GIT_CONFIG_GLOBAL: paths.gitConfig,
    GIT_CONFIG_NOSYSTEM: "1",
    HERMES_HOME: paths.hermesHome,
    HOME: paths.home,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NPM_CONFIG_CACHE: paths.npmCache,
    PATH: pathValue,
    PYTHONNOUSERSITE: "1",
    TMPDIR: paths.tmp,
    XDG_CACHE_HOME: paths.xdgCache,
  };
  for (const key of dotenvKeys) env[key] = "";
  env[envKeyName] = inferenceKeyValue;
  env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY = clockchainMcpToken;
  return Object.freeze(env);
}

function buildBootstrapEnvironment({ dotenvKeys, pathValue, paths }) {
  const env = {
    COREPACK_HOME: paths.bootstrapCorepackHome,
    GIT_CONFIG_GLOBAL: paths.bootstrapGitConfig,
    GIT_CONFIG_NOSYSTEM: "1",
    HERMES_HOME: paths.bootstrapHermesHome,
    HOME: paths.bootstrapHome,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NPM_CONFIG_CACHE: paths.bootstrapNpmCache,
    PATH: pathValue,
    PYTHONNOUSERSITE: "1",
    TMPDIR: paths.bootstrapTmp,
    XDG_CACHE_HOME: paths.bootstrapXdgCache,
  };
  for (const key of dotenvKeys) env[key] = "";
  return Object.freeze(env);
}

async function defaultDetectHermes({ hermesBinary, hermesInstallRoot }) {
  const { stdout } = await execFileAsync(
    hermesBinary,
    ["--version"],
    { encoding: "utf8", maxBuffer: 16_384 },
  );
  return {
    build: stdout.trim(),
    configVersion: 33,
    installRoot: hermesInstallRoot,
    managedConfigPresent: false,
    managedEnvPresent: false,
    packageVersion: "unknown",
    secretScope: "role",
    supported: true,
    version: stdout.trim(),
  };
}

async function defaultRunHermesProfileCreate({ args, env, hermesBinary }) {
  await execFileAsync(
    hermesBinary,
    args,
    { encoding: "utf8", env, maxBuffer: 16_384 },
  );
  return { profileDirectory: join(env.HERMES_HOME, "profiles", "agent") };
}

async function defaultProbeEnvLoader() {
  fail();
}

async function defaultDiscoverMcp() {
  fail();
}

async function validateHermesDetection({ detection, hermesInstallRoot }) {
  if (detection === null || typeof detection !== "object" || detection.supported !== true) fail();
  if (!Number.isSafeInteger(detection.configVersion) || detection.configVersion < 1) fail();
  if (detection.managedEnvPresent === true || detection.managedConfigPresent === true) fail();
  if (detection.secretScope === "/etc/hermes" || detection.secretScope === "managed") fail();
  const installRoot = canonicalAbsolutePath(detection.installRoot ?? hermesInstallRoot);
  if (installRoot === "/etc/hermes" || installRoot.startsWith("/etc/hermes/")) fail();
  return Object.freeze({
    configVersion: detection.configVersion,
    gitDescribe: String(detection.gitDescribe ?? detection.describe ?? ""),
    gitHead: String(detection.gitHead ?? detection.head ?? ""),
    installRoot,
    packageVersion: String(detection.packageVersion ?? "unknown"),
    version: String(detection.version ?? detection.gitDescribe ?? "unknown"),
  });
}

async function verifyBootstrapProfile({ profileDirectory, roleRoot }) {
  const profile = assertDescendant(roleRoot, canonicalAbsolutePath(profileDirectory));
  await assertPrivateDirectory(profile);
  const marker = join(profile, ".no-bundled-skills");
  const markerStats = await lstatOptional(marker);
  if (markerStats === undefined || !markerStats.isFile() || markerStats.isSymbolicLink()) fail();
  const skills = join(profile, "skills");
  await assertPrivateDirectory(skills);
  await assertDirectoryEmpty(skills);
  await rm(join(profile, "SOUL.md"), { force: true });
  return profile;
}

function classifyStateEntry({ basePath, path, stats }) {
  const name = basename(path);
  if (stats.isSymbolicLink()) return "symlink";
  if (FORBIDDEN_STATE_NAMES.includes(name)) return relativeIdentifier(basePath, path);
  return undefined;
}

async function inspectZeroState({ basePath, paths }) {
  const forbidden = [];
  let fileCount = 0;
  let directoryCount = 0;
  async function walk(path) {
    const stats = await lstatOptional(path);
    if (stats === undefined) return;
    const classified = classifyStateEntry({ basePath, path, stats });
    if (classified !== undefined) forbidden.push(classified);
    if (stats.isSymbolicLink()) return;
    if (stats.isDirectory()) {
      directoryCount += 1;
      for (const entry of await readdir(path)) await walk(join(path, entry));
      return;
    }
    fileCount += 1;
  }
  for (const path of [
    paths.home,
    paths.hermesHome,
    paths.workspace,
    paths.xdgCache,
    paths.npmCache,
    paths.corepackHome,
    paths.tmp,
    paths.evidencePrivate,
  ]) {
    await walk(path);
  }
  const allowedForbidden = new Set([
    relativeIdentifier(basePath, join(paths.hermesHome, "skills")),
  ]);
  const unexpected = forbidden.filter((entry) => !allowedForbidden.has(entry));
  return Object.freeze({
    clean: unexpected.length === 0,
    counts: { directories: directoryCount, files: fileCount },
    forbidden: unexpected.sort(),
  });
}

function assertZeroState(result) {
  if (result.clean !== true) fail();
}

function publicPaths({ paths, roleRoot }) {
  return Object.freeze({
    corepackHome: relativeIdentifier(roleRoot, paths.corepackHome),
    evidencePrivate: relativeIdentifier(roleRoot, paths.evidencePrivate),
    gitConfig: relativeIdentifier(roleRoot, paths.gitConfig),
    hermesHome: relativeIdentifier(roleRoot, paths.hermesHome),
    home: relativeIdentifier(roleRoot, paths.home),
    npmCache: relativeIdentifier(roleRoot, paths.npmCache),
    tmp: relativeIdentifier(roleRoot, paths.tmp),
    workspace: relativeIdentifier(roleRoot, paths.workspace),
  });
}

async function writeJsonPrivate(path, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  return writePrivateFile({ bytes, path });
}

function validateEnvProbe({ allowedSecretKeys, emptyKeys, result }) {
  if (result === null || typeof result !== "object") fail();
  if (!Array.isArray(result.allowedSecretKeys)) fail();
  if (JSON.stringify([...result.allowedSecretKeys].sort()) !== JSON.stringify([...allowedSecretKeys].sort())) fail();
  if (result.emptyKeys === null || typeof result.emptyKeys !== "object") fail();
  for (const key of emptyKeys) {
    if (result.emptyKeys[key] !== true) fail();
  }
  return Object.freeze({
    allowedSecretKeys: [...allowedSecretKeys].sort(),
    emptyKeys: Object.freeze(Object.fromEntries(emptyKeys.map((key) => [key, true]))),
    sanitizerNeutralized: result.sanitizerNeutralized === undefined ? true : result.sanitizerNeutralized === true,
    stdoutCaptured: false,
    stderrCaptured: false,
  });
}

function validateMcpDiscovery(discovery) {
  if (discovery === null || typeof discovery !== "object") fail();
  if (discovery.resourcesEnabled !== false || discovery.promptsEnabled !== false) fail();
  if (!Array.isArray(discovery.servers) || discovery.servers.length !== 1) fail();
  const [server] = discovery.servers;
  if (server?.name !== "clockchain" || server?.url !== CLOCKCHAIN_URL) fail();
  if (
    !Array.isArray(discovery.tools) ||
    JSON.stringify(discovery.tools) !== JSON.stringify(CLOCKCHAIN_TOOLS)
  ) {
    fail();
  }
  return Object.freeze({
    promptsEnabled: false,
    resourcesEnabled: false,
    servers: Object.freeze([{ name: "clockchain", url: CLOCKCHAIN_URL }]),
    tools: CLOCKCHAIN_TOOLS,
  });
}

async function removeDiscoveryLock(hermesHome) {
  await rm(join(hermesHome, ".mcp-discovery.lock"), { force: true });
}

function hasSecretKey(key) {
  return SECRET_KEY_PATTERN.test(key) && key !== "tokensPresent";
}

function scanPublicValue(value, canaries) {
  const seen = new WeakSet();
  function visit(entry, key = "") {
    if (typeof entry === "string") {
      if (isAbsolute(entry)) throw new SecretMaterialDetectedError();
      if (canaries.some((canary) => entry.includes(canary))) throw new SecretMaterialDetectedError();
      if (SECRET_STRING_PATTERNS.some((pattern) => pattern.test(entry))) throw new SecretMaterialDetectedError();
      if (hasSecretKey(key) && entry !== "" && entry !== "[REDACTED]") throw new SecretMaterialDetectedError();
      return;
    }
    if (entry === null || typeof entry !== "object") {
      if (
        hasSecretKey(key) &&
        entry !== false &&
        entry !== true &&
        entry !== null
      ) {
        throw new SecretMaterialDetectedError();
      }
      return;
    }
    if (seen.has(entry)) return;
    seen.add(entry);
    if (Array.isArray(entry)) {
      for (const item of entry) visit(item);
      return;
    }
    for (const [childKey, childValue] of Object.entries(entry)) visit(childValue, childKey);
  }
  visit(value);
}

export function assertPublicCleanRoomEvidence(value, canaries = []) {
  if (
    !Array.isArray(canaries) ||
    canaries.some((canary) => typeof canary !== "string" || canary.length === 0)
  ) {
    throw new TypeError("Canaries must be an array of nonempty strings.");
  }
  scanPublicValue(value, canaries);
}

export async function prepareCleanRoom({
  clockchainMcpToken,
  detectHermes = defaultDetectHermes,
  discoverMcp = defaultDiscoverMcp,
  env = process.env,
  extraEnv = {},
  hermesBinary = DEFAULT_HERMES_BINARY,
  hermesInstallRoot,
  inferenceKeyName = "KIMI_API_KEY",
  inferenceKeyValue,
  kitCommit,
  pathValue = DEFAULT_PATH,
  peerClockchainMcpToken,
  principal,
  probeEnvLoader = defaultProbeEnvLoader,
  role,
  runHermesProfileCreate = defaultRunHermesProfileCreate,
  runRoot,
} = {}) {
  try {
    const cleanRole = assertRole(role);
    const cleanRunRoot = canonicalAbsolutePath(runRoot);
    canonicalAbsolutePath(hermesBinary);
    const cleanInstallRoot = canonicalAbsolutePath(hermesInstallRoot);
    const envKeyName = assertSingleKimiKey(inferenceKeyName);
    const providerSecret = assertSecretValue(inferenceKeyValue);
    const mcpSecret = assertSecretValue(clockchainMcpToken);
    if (peerClockchainMcpToken !== undefined && peerClockchainMcpToken === mcpSecret) fail();
    if (typeof kitCommit !== "string" || !/^[0-9a-f]{40}$/i.test(kitCommit)) fail();
    if (typeof principal !== "string" || principal.length === 0) fail();
    if (env === null || typeof env !== "object" || Array.isArray(env)) fail();
    assertNoAmbientSecretEnv(extraEnv);

    await ensureRunRoot(cleanRunRoot);
    await assertNoSymlinkTree(cleanRunRoot);
    const rolesRoot = join(cleanRunRoot, "roles");
    if ((await lstatOptional(rolesRoot)) === undefined) await createPrivateDirectory(rolesRoot);
    await assertPrivateDirectory(rolesRoot);
    const roleRoot = assertDescendant(cleanRunRoot, join(rolesRoot, cleanRole));
    await assertMissing(roleRoot);
    await createPrivateDirectory(roleRoot);

    const paths = Object.freeze({
      bootstrapCorepackHome: join(roleRoot, "bootstrap-corepack-cache"),
      bootstrapGitConfig: join(roleRoot, "bootstrap-gitconfig"),
      bootstrapHermesHome: join(roleRoot, "bootstrap-hermes-home"),
      bootstrapHome: join(roleRoot, "bootstrap-home"),
      bootstrapNpmCache: join(roleRoot, "bootstrap-npm-cache"),
      bootstrapTmp: join(roleRoot, "bootstrap-tmp"),
      bootstrapXdgCache: join(roleRoot, "bootstrap-xdg-cache"),
      config: join(roleRoot, "hermes-home", "config.yaml"),
      corepackHome: join(roleRoot, "corepack-cache"),
      evidencePrivate: join(roleRoot, "private-evidence"),
      gitConfig: join(roleRoot, "gitconfig"),
      hermesHome: join(roleRoot, "hermes-home"),
      home: join(roleRoot, "home"),
      npmCache: join(roleRoot, "npm-cache"),
      tmp: join(roleRoot, "tmp"),
      workspace: join(roleRoot, "workspace"),
      xdgCache: join(roleRoot, "xdg-cache"),
    });
    for (const path of Object.values(paths)) assertDescendant(cleanRunRoot, path);
    for (const path of [
      paths.bootstrapCorepackHome,
      paths.bootstrapGitConfig,
      paths.bootstrapHermesHome,
      paths.bootstrapHome,
      paths.bootstrapNpmCache,
      paths.bootstrapTmp,
      paths.bootstrapXdgCache,
      paths.corepackHome,
      paths.evidencePrivate,
      paths.home,
      paths.npmCache,
      paths.tmp,
      paths.workspace,
      paths.xdgCache,
    ]) {
      await createPrivateDirectory(path);
    }

    const detection = await validateHermesDetection({
      detection: await detectHermes({
        hermesBinary,
        hermesInstallRoot: cleanInstallRoot,
      }),
      hermesInstallRoot: cleanInstallRoot,
    });
    const dotenvKeys = sortedUnique(await parseDotenvKeys(detection.installRoot));
    const bootstrapEnv = buildBootstrapEnvironment({
      dotenvKeys,
      pathValue,
      paths,
    });
    const profileResult = await runHermesProfileCreate({
      args: ["profile", "create", "agent", "--no-skills", "--no-alias"],
      env: bootstrapEnv,
      hermesBinary,
      hermesHome: paths.bootstrapHermesHome,
    });
    const profileDirectory = await verifyBootstrapProfile({
      profileDirectory: profileResult?.profileDirectory,
      roleRoot,
    });
    await rename(profileDirectory, paths.hermesHome);
    for (const path of [
      paths.bootstrapCorepackHome,
      paths.bootstrapHermesHome,
      paths.bootstrapHome,
      paths.bootstrapNpmCache,
      paths.bootstrapTmp,
      paths.bootstrapXdgCache,
    ]) {
      await rm(path, { force: true, recursive: true });
    }

    const config = buildConfig({
      configVersion: detection.configVersion,
      envKeyName,
      workspace: paths.workspace,
    });
    await writeJsonPrivate(paths.config, config);

    const preProvisionZero = await inspectZeroState({ basePath: roleRoot, paths });
    assertZeroState(preProvisionZero);
    const publicPathMap = publicPaths({ paths, roleRoot });
    const hermesPublic = Object.freeze({
      configVersion: detection.configVersion,
      gitDescribe: detection.gitDescribe,
      gitHead: detection.gitHead,
      packageVersion: detection.packageVersion,
      version: detection.version,
    });
    const preProvision = Object.freeze({
      phase: "pre-provision",
      role: cleanRole,
      hermes: hermesPublic,
      kitCommit,
      paths: publicPathMap,
      principalFingerprint: null,
      tokensPresent: false,
      zeroState: preProvisionZero,
    });
    assertPublicCleanRoomEvidence(preProvision, [mcpSecret, providerSecret, cleanRunRoot]);
    const preProvisionPath = join(paths.evidencePrivate, "pre-provision.json");
    await writeJsonPrivate(preProvisionPath, preProvision);

    const childEnv = buildEnvironment({
      clockchainMcpToken: mcpSecret,
      dotenvKeys,
      envKeyName,
      inferenceKeyValue: providerSecret,
      paths,
      pathValue,
    });
    const emptyKeys = sortedUnique(dotenvKeys.filter(
      (key) => key !== envKeyName && key !== "AUXILIARY_CLOCKCHAIN_MCP_API_KEY",
    ));
    const allowedSecretKeys = sortedUnique([envKeyName, "AUXILIARY_CLOCKCHAIN_MCP_API_KEY"]);
    const envLoader = validateEnvProbe({
      allowedSecretKeys,
      emptyKeys,
      result: await probeEnvLoader({
        allowedSecretKeys,
        emptyKeys,
        env: childEnv,
        hermesBinary,
        hermesHome: paths.hermesHome,
        installRoot: detection.installRoot,
      }),
    });
    const mcp = validateMcpDiscovery(await discoverMcp({
      config,
      configPath: paths.config,
      env: childEnv,
      hermesHome: paths.hermesHome,
      shutdownAfterDiscovery: true,
    }));
    await removeDiscoveryLock(paths.hermesHome);
    const prePromptZero = {
      ...await inspectZeroState({ basePath: roleRoot, paths }),
      reinspectedBeforePrompt: true,
    };
    assertZeroState(prePromptZero);
    const prePrompt = Object.freeze({
      phase: "pre-prompt",
      role: cleanRole,
      envProbe: envLoader,
      hermes: hermesPublic,
      kitCommit,
      mcp,
      paths: publicPathMap,
      principalFingerprint: sha256(principal),
      tokensPresent: true,
      zeroState: Object.freeze(prePromptZero),
    });
    assertPublicCleanRoomEvidence(prePrompt, [mcpSecret, providerSecret, cleanRunRoot]);
    const prePromptPath = join(paths.evidencePrivate, "pre-prompt.json");
    await writeJsonPrivate(prePromptPath, prePrompt);

    return Object.freeze({
      env: childEnv,
      manifests: Object.freeze({ prePromptPath, preProvisionPath }),
      paths,
      probes: Object.freeze({ envLoader, mcp }),
      role: cleanRole,
      roleRoot,
    });
  } catch (error) {
    sanitize(error);
  }
  fail();
}
