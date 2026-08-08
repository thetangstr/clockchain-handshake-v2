import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
} from "node:path";
import { promisify } from "node:util";

import { writePrivateFile } from "./private-path.mjs";
import {
  assertSecretFree,
  SecretMaterialDetectedError,
} from "./redact.mjs";

const execFileAsync = promisify(execFileCallback);

const VALID_ROLES = Object.freeze(["payer", "requestor"]);
const CLOCKCHAIN_URL = "https://mcp.clockchain.network/mcp";
const RAW_CLOCKCHAIN_TOOLS = Object.freeze([
  "handshake_status",
  "handshake_join",
  "handshake_next",
  "handshake_submit",
  "handshake_get_certificate",
]);
const REGISTERED_CLOCKCHAIN_TOOLS = Object.freeze(
  RAW_CLOCKCHAIN_TOOLS.map((name) => `mcp__clockchain__${name}`),
);
const DEFAULT_HERMES_BINARY = "/Users/maxiaoer/.local/bin/hermes";
const DEFAULT_HERMES_INSTALL_ROOT = "/Users/maxiaoer/.hermes/hermes-agent";
const DEFAULT_PATH = "/Users/maxiaoer/.local/bin:/opt/homebrew/opt/node@22/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const EXPECTED_PACKAGE_VERSION = "0.19.1";
const EXPECTED_GIT_HEAD = "87bc710609f8b89b6e6b4aa418dde8ee30ec6873";
const EXPECTED_GIT_DESCRIBE = "v2026.7.30-357-g87bc71060";
const EXPECTED_CONFIG_VERSION = 33;
const DOTENV_KEY_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;
const PROVIDER_KEY_NAMES = Object.freeze(["KIMI_API_KEY", "KIMI_CODING_API_KEY"]);
const SECRET_KEY_PATTERN = /(?:KEY|TOKEN|SECRET|AUTH|PASSWORD|CREDENTIAL)/i;
const CLOCKCHAIN_TOKEN_PATTERN = /^cc_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{16,})$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CLOCKCHAIN_DEMO_TOKEN_KEYS = Object.freeze(["exp", "iat", "jti", "tier", "v"]);
const CLOCKCHAIN_DEMO_TOKEN_KEYS_WITH_SUB = Object.freeze(["exp", "iat", "jti", "sub", "tier", "v"]);
const ABSOLUTE_PATH_FRAGMENT =
  /(?:^|[\s"'=:,(])\/(?:Users|Volumes|private|tmp|var|etc|opt|home)\/[A-Za-z0-9._~@%+,:=-][A-Za-z0-9._~@%+/,:=-]*/;
const SECRET_STRING_PATTERNS = Object.freeze([
  /\bcc_[A-Za-z0-9_-][A-Za-z0-9._-]{19,}(?![A-Za-z0-9._-])/,
  /\bBearer[ \t]+[A-Za-z0-9._~+/-]{24,}(?:={0,2})(?![A-Za-z0-9._~+/-])/i,
  /\b(?:private[\s_-]?key|priv[\s_-]?key|wallet[\s_-]?key)\b\s*(?:(?:is)\s+|[:=]\s*)?0x[0-9a-f]{64}(?![0-9a-f])/i,
]);
const GENERATED_PROFILE_DIRS = Object.freeze([
  "cron",
  "home",
  "logs",
  "memories",
  "plans",
  "sessions",
  "skills",
  "skins",
  "workspace",
]);
const RETAINED_PROFILE_ENTRIES = Object.freeze([
  ".env",
  ".no-bundled-skills",
  "home",
  "skills",
]);
const MCP_DISCOVERY_PERSISTENT_ENTRIES = Object.freeze([
  ...RETAINED_PROFILE_ENTRIES,
  "config.yaml",
]);
const MCP_DISCOVERY_EMPTY_DIRS = Object.freeze([
  "audio_cache",
  "cron",
  "hooks",
  "image_cache",
  "memories",
  "pairing",
  "sessions",
]);
const MCP_DISCOVERY_TRANSIENT_ENTRIES = Object.freeze([
  ".mcp-discovery.lock",
  "SOUL.md",
  ...MCP_DISCOVERY_EMPTY_DIRS,
  "logs",
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

function role(value) {
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

async function statOptional(path) {
  try {
    return await stat(path);
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

async function assertExistingDirectoryNoSymlink(path) {
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) fail();
}

async function createPrivateDirectory(path) {
  const parent = dirname(path);
  if ((await lstatOptional(parent)) === undefined) await createPrivateDirectory(parent);
  else await assertExistingDirectoryNoSymlink(parent);
  await mkdir(path, { mode: 0o700, recursive: false });
  if (process.platform !== "win32") await chmod(path, 0o700);
  await assertPrivateDirectory(path);
}

async function createPrivateEmptyFile(path) {
  const handle = await open(path, "wx", 0o600);
  try {
    if (process.platform !== "win32") await handle.chmod(0o600);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const stats = await lstat(path);
  if (!stats.isFile() || stats.isSymbolicLink() || stats.size !== 0) fail();
  if (process.platform !== "win32" && (stats.mode & 0o777) !== 0o600) fail();
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
  if (await realpath(path) !== path) fail();
}

async function assertNoSymlinkTree(path) {
  const stats = await lstatOptional(path);
  if (stats === undefined) return;
  if (stats.isSymbolicLink()) fail();
  if (!stats.isDirectory()) return;
  for (const entry of await readdir(path)) await assertNoSymlinkTree(join(path, entry));
}

function sorted(values) {
  return [...values].sort();
}

function sortedUnique(values) {
  return sorted(new Set(values));
}

function sameStrings(left, right) {
  return JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
}

async function parseDotenvKeys(installRoot) {
  let text;
  try {
    text = await readFile(join(installRoot, ".env"), "utf8");
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

async function commandRunner(file, args, options) {
  return execFileAsync(file, args, {
    encoding: "utf8",
    maxBuffer: 32_768,
    timeout: 10_000,
    windowsHide: true,
    ...options,
  });
}

async function readTextOptional(path) {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

function scrubbedEnv(pathValue = DEFAULT_PATH) {
  return Object.freeze({
    GIT_CONFIG_NOSYSTEM: "1",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: pathValue,
    PYTHONNOUSERSITE: "1",
  });
}

function scrubbedHermesEnv({ hermesHome, home, pathValue = DEFAULT_PATH }) {
  return Object.freeze({
    ...scrubbedEnv(pathValue),
    HERMES_HOME: hermesHome,
    HOME: home,
  });
}

async function defaultDetectHermes({
  commandRunner: run = commandRunner,
  hermesHome,
  hermesBinary,
  hermesInstallRoot,
  home,
  pathValue,
}) {
  const env = scrubbedHermesEnv({ hermesHome, home, pathValue });
  const python = join(hermesInstallRoot, "venv", "bin", "python");
  const metadataScript = [
    "import json",
    "# hermes_cli.config_defaults.DEFAULT_CONFIG",
    "import hermes_cli.config_defaults as config_defaults",
    "print(json.dumps({'config_version': config_defaults.DEFAULT_CONFIG.get('_config_version')}))",
  ].join("\n");
  const [version, profileCreateHelp, pyproject, metadata, head, describe, status, managedEnv, managedConfig, etcEnv, etcConfig] =
    await Promise.all([
      run(hermesBinary, ["--version"], { env }),
      run(hermesBinary, ["profile", "create", "--help"], { env }),
      readTextOptional(join(hermesInstallRoot, "pyproject.toml")),
      run(python, ["-c", metadataScript], { env }).catch(() => ({ stdout: "{}" })),
      run("git", ["-C", hermesInstallRoot, "rev-parse", "HEAD"], { env }),
      run("git", ["-C", hermesInstallRoot, "describe", "--tags", "--always", "--dirty"], { env }),
      run("git", ["-C", hermesInstallRoot, "status", "--porcelain", "--untracked-files=no"], { env }),
      readTextOptional(join(hermesInstallRoot, "managed-env.txt")),
      readTextOptional(join(hermesInstallRoot, "managed-config.txt")),
      lstatOptional("/etc/hermes/.env"),
      lstatOptional("/etc/hermes/config.yaml"),
    ]);
  let parsedMetadata = {};
  try {
    parsedMetadata = JSON.parse(metadata.stdout);
  } catch {
    parsedMetadata = {};
  }
  const packageVersion = /^\s*version\s*=\s*"([^"]+)"/m.exec(pyproject ?? "")?.[1] ?? "";
  return Object.freeze({
    configVersion: Number.parseInt(String(parsedMetadata.config_version ?? ""), 10),
    features: {
      noAlias: profileCreateHelp.stdout.includes("--no-alias"),
      noSkills: profileCreateHelp.stdout.includes("--no-skills"),
      profileCreate: true,
      venvPython: (await statOptional(join(hermesInstallRoot, "venv", "bin", "python")))?.isFile() === true,
    },
    gitDescribe: describe.stdout.trim(),
    gitHead: head.stdout.trim(),
    installRoot: hermesInstallRoot,
    managedConfigPresent: managedConfig?.trim().length > 0 || etcConfig !== undefined,
    managedEnvPresent: managedEnv?.trim().length > 0 || etcEnv !== undefined,
    packageVersion,
    sourceClean: status.stdout.trim() === "",
    supported: version.stdout.includes("0.19.1"),
  });
}

function validateHermesDetection(detection, installRoot) {
  if (detection === null || typeof detection !== "object") fail();
  if (detection.supported !== true) fail();
  if (detection.installRoot !== installRoot) fail();
  if (detection.packageVersion !== EXPECTED_PACKAGE_VERSION) fail();
  if (detection.gitHead !== EXPECTED_GIT_HEAD) fail();
  if (detection.gitDescribe !== EXPECTED_GIT_DESCRIBE) fail();
  if (detection.configVersion !== EXPECTED_CONFIG_VERSION) fail();
  if (detection.sourceClean !== true) fail();
  if (detection.managedEnvPresent === true || detection.managedConfigPresent === true) fail();
  if (
    detection.features?.profileCreate !== true ||
    detection.features?.noSkills !== true ||
    detection.features?.noAlias !== true ||
    detection.features?.venvPython !== true
  ) {
    fail();
  }
  return Object.freeze({
    configVersion: EXPECTED_CONFIG_VERSION,
    gitDescribe: EXPECTED_GIT_DESCRIBE,
    gitHead: EXPECTED_GIT_HEAD,
    packageVersion: EXPECTED_PACKAGE_VERSION,
  });
}

function buildPaths(runRoot, cleanRole) {
  const roleRoot = join(runRoot, "roles", cleanRole);
  return Object.freeze({
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
}

async function createBaseDirectories(paths) {
  for (const path of [
    paths.bootstrapCorepackHome,
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
  await createPrivateEmptyFile(paths.gitConfig);
  await createPrivateEmptyFile(paths.bootstrapGitConfig);
}

function bootstrapEnv({ dotenvKeys, paths, pathValue }) {
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

async function defaultRunHermesProfileCreate({ commandRunner: run = commandRunner, env, hermesBinary }) {
  await run(
    hermesBinary,
    ["profile", "create", "agent", "--no-skills", "--no-alias"],
    { env },
  );
  return { profileDirectory: join(env.HERMES_HOME, "profiles", "agent") };
}

async function assertCommentOnlyEnv(path) {
  const stats = await lstat(path);
  if (!stats.isFile() || stats.isSymbolicLink()) fail();
  const text = await readFile(path, "utf8");
  if (!text.split(/\r?\n/).every((line) => line.trim() === "" || line.trim().startsWith("#"))) fail();
}

async function hardenDirectoryTree(path) {
  const stats = await lstat(path);
  if (stats.isSymbolicLink()) fail();
  if (stats.isDirectory()) {
    if (process.platform !== "win32") await chmod(path, 0o700);
    for (const entry of await readdir(path)) await hardenDirectoryTree(join(path, entry));
    return;
  }
  if (!stats.isFile()) fail();
  if (process.platform !== "win32") await chmod(path, 0o600);
}

async function assertEmptyPrivateDirectory(path) {
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) fail();
  if (process.platform !== "win32" && (stats.mode & 0o777) !== 0o700) fail();
  if ((await readdir(path)).length !== 0) fail();
}

async function cleanupMcpDiscoveryArtifacts(hermesHome) {
  const entries = sorted(await readdir(hermesHome));
  const extras = entries.filter((entry) => !MCP_DISCOVERY_PERSISTENT_ENTRIES.includes(entry));
  if (extras.length === 0) return;
  if (!sameStrings(extras, MCP_DISCOVERY_TRANSIENT_ENTRIES)) fail();
  for (const name of MCP_DISCOVERY_EMPTY_DIRS) {
    await assertEmptyPrivateDirectory(join(hermesHome, name));
  }
  const logs = join(hermesHome, "logs");
  const logStats = await lstat(logs);
  if (!logStats.isDirectory() || logStats.isSymbolicLink()) fail();
  if (process.platform !== "win32" && (logStats.mode & 0o777) !== 0o700) fail();
  if (!sameStrings(await readdir(logs), ["curator"])) fail();
  await assertEmptyPrivateDirectory(join(logs, "curator"));
  const soul = await lstat(join(hermesHome, "SOUL.md"));
  if (!soul.isFile() || soul.isSymbolicLink() || soul.size < 1 || soul.size > 4_096) fail();
  if (process.platform !== "win32" && (soul.mode & 0o777) !== 0o600) fail();
  const lock = await lstat(join(hermesHome, ".mcp-discovery.lock"));
  if (!lock.isFile() || lock.isSymbolicLink() || lock.size !== 0) fail();
  for (const name of MCP_DISCOVERY_TRANSIENT_ENTRIES) {
    await rm(join(hermesHome, name), { force: true, recursive: true });
  }
  if (!sameStrings(await readdir(hermesHome), MCP_DISCOVERY_PERSISTENT_ENTRIES)) fail();
}

async function validateAndPromoteProfile({ paths }) {
  const profile = join(paths.bootstrapHermesHome, "profiles", "agent");
  const profileStats = await lstat(profile);
  if (!profileStats.isDirectory() || profileStats.isSymbolicLink()) fail();
  const entries = sorted(await readdir(profile));
  if (!sameStrings(entries, [".env", ".no-bundled-skills", "SOUL.md", ...GENERATED_PROFILE_DIRS])) fail();
  await assertCommentOnlyEnv(join(profile, ".env"));
  const marker = await lstat(join(profile, ".no-bundled-skills"));
  if (!marker.isFile() || marker.isSymbolicLink()) fail();
  const soul = await lstat(join(profile, "SOUL.md"));
  if (!soul.isFile() || soul.isSymbolicLink()) fail();
  for (const name of GENERATED_PROFILE_DIRS) {
    const dir = join(profile, name);
    const stats = await lstat(dir);
    if (!stats.isDirectory() || stats.isSymbolicLink()) fail();
    if ((await readdir(dir)).length !== 0) fail();
  }
  await rm(join(profile, "SOUL.md"));
  for (const name of GENERATED_PROFILE_DIRS) {
    if (!["home", "skills"].includes(name)) await rm(join(profile, name), { recursive: true });
  }
  if (!sameStrings(await readdir(profile), RETAINED_PROFILE_ENTRIES)) fail();
  await hardenDirectoryTree(profile);
  await rename(profile, paths.hermesHome);
  await rm(paths.bootstrapHermesHome, { force: true, recursive: true });
}

function relativePath(runRoot, path) {
  const offset = relative(runRoot, path);
  if (offset === "" || offset.startsWith("..") || isAbsolute(offset)) fail();
  return offset.split("\\").join("/");
}

function publicPaths({ paths, runRoot }) {
  return Object.freeze({
    corepackHome: relativePath(runRoot, paths.corepackHome),
    evidencePrivate: relativePath(runRoot, paths.evidencePrivate),
    gitConfig: relativePath(runRoot, paths.gitConfig),
    hermesHome: relativePath(runRoot, paths.hermesHome),
    home: relativePath(runRoot, paths.home),
    npmCache: relativePath(runRoot, paths.npmCache),
    tmp: relativePath(runRoot, paths.tmp),
    workspace: relativePath(runRoot, paths.workspace),
  });
}

async function listTree(path, runRoot) {
  const result = [];
  async function walk(current) {
    const stats = await lstatOptional(current);
    if (stats === undefined) return;
    if (stats.isSymbolicLink()) fail();
    result.push(`${stats.isDirectory() ? "dir" : "file"}:${relativePath(runRoot, current)}`);
    if (stats.isDirectory()) {
      for (const entry of sorted(await readdir(current))) await walk(join(current, entry));
    }
  }
  await walk(path);
  return sorted(result);
}

async function expectedTree({ includeConfig = false, includePreProvision = false, paths, roleRoot, runRoot }) {
  const entries = [
    roleRoot,
    paths.corepackHome,
    paths.evidencePrivate,
    paths.gitConfig,
    paths.hermesHome,
    join(paths.hermesHome, ".env"),
    join(paths.hermesHome, ".no-bundled-skills"),
    join(paths.hermesHome, "home"),
    join(paths.hermesHome, "skills"),
    paths.home,
    paths.npmCache,
    paths.tmp,
    paths.workspace,
    paths.xdgCache,
  ];
  if (includeConfig) entries.push(paths.config);
  if (includePreProvision) entries.push(join(paths.evidencePrivate, "pre-provision.json"));
  const described = [];
  for (const entry of entries) {
    const stats = await lstat(entry);
    described.push(`${stats.isDirectory() ? "dir" : "file"}:${relativePath(runRoot, entry)}`);
  }
  return sorted(described);
}

async function inspectTree({ expected, roleRoot, runRoot }) {
  const actual = await listTree(roleRoot, runRoot);
  const clean = JSON.stringify(actual) === JSON.stringify(expected);
  return Object.freeze({
    clean,
    counts: {
      directories: actual.filter((entry) => entry.startsWith("dir:")).length,
      files: actual.filter((entry) => entry.startsWith("file:")).length,
    },
    expected,
    unexpected: actual.filter((entry) => !expected.includes(entry)),
  });
}

async function writeJsonPrivate(path, value) {
  await writePrivateFile({
    bytes: Buffer.from(`${JSON.stringify(value, null, 2)}\n`),
    path,
  });
}

function publicHermes({ hermesBinary, hermesInstallRoot, identity }) {
  return Object.freeze({
    binary: hermesBinary === DEFAULT_HERMES_BINARY ? "mac-mini-default" : "test-fixture",
    configVersion: identity.configVersion,
    gitDescribe: identity.gitDescribe,
    gitHead: identity.gitHead,
    installRoot: hermesInstallRoot === DEFAULT_HERMES_INSTALL_ROOT ? "mac-mini-default" : "test-fixture",
    packageVersion: identity.packageVersion,
  });
}

function assertProviderKeyName(value) {
  if (!PROVIDER_KEY_NAMES.includes(value)) fail();
  return value;
}

function assertSecretString(value) {
  if (typeof value !== "string" || value.length === 0) fail();
  return value;
}

function parseClockchainDemoTokenPayload(token) {
  const match = CLOCKCHAIN_TOKEN_PATTERN.exec(assertSecretString(token));
  if (match === null) fail();
  let payload;
  try {
    payload = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8"));
  } catch {
    fail();
  }
  const keys = Object.keys(payload ?? {}).sort();
  const allowedKeys = Object.hasOwn(payload ?? {}, "sub")
    ? CLOCKCHAIN_DEMO_TOKEN_KEYS_WITH_SUB
    : CLOCKCHAIN_DEMO_TOKEN_KEYS;
  if (
    payload === null ||
    typeof payload !== "object" ||
    JSON.stringify(keys) !== JSON.stringify(allowedKeys) ||
    payload.v !== 1 ||
    payload.tier !== "demo" ||
    typeof payload.jti !== "string" ||
    !UUID_PATTERN.test(payload.jti) ||
    !Number.isSafeInteger(payload.iat) ||
    !Number.isSafeInteger(payload.exp) ||
    payload.iat < 0 ||
    payload.exp <= payload.iat ||
    (
      Object.hasOwn(payload, "sub") &&
      (typeof payload.sub !== "string" || payload.sub.length === 0 || payload.sub.length > 256)
    )
  ) {
    fail();
  }
  return Object.freeze({
    exp: payload.exp,
    iat: payload.iat,
    jti: payload.jti,
    sub: payload.sub,
    tier: "demo",
    v: 1,
  });
}

export function fingerprintClockchainDemoToken(token) {
  return createHash("sha256").update(`jti:${parseClockchainDemoTokenPayload(token).jti}`).digest("hex");
}

function buildConfig(paths) {
  return Object.freeze({
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
          include: RAW_CLOCKCHAIN_TOOLS,
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
      cwd: paths.workspace,
      env_passthrough: [],
      home_mode: "profile",
      shell_init_files: [],
    },
  });
}

function childEnv({ dotenvKeys, mcpToken, paths, providerKeyName, providerKeyValue }) {
  const env = {
    COREPACK_HOME: paths.corepackHome,
    GIT_CONFIG_GLOBAL: paths.gitConfig,
    GIT_CONFIG_NOSYSTEM: "1",
    HERMES_HOME: paths.hermesHome,
    HOME: paths.home,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NPM_CONFIG_CACHE: paths.npmCache,
    PATH: DEFAULT_PATH,
    PYTHONNOUSERSITE: "1",
    TMPDIR: paths.tmp,
    XDG_CACHE_HOME: paths.xdgCache,
  };
  for (const key of dotenvKeys) env[key] = "";
  env[providerKeyName] = providerKeyValue;
  env.AUXILIARY_CLOCKCHAIN_MCP_API_KEY = mcpToken;
  return Object.freeze(env);
}

function probeEnv({ dotenvKeys, env, providerKeyName }) {
  return Object.freeze({
    ...env,
    HERMES_EMPTY_KEYS_JSON: JSON.stringify(dotenvKeys.filter((key) => key !== providerKeyName)),
    HERMES_MANAGED_PRESENT: "0",
    HERMES_PROVIDER_KEY_NAME: providerKeyName,
  });
}

function normalizeEnvProbe(result, { dotenvKeys, providerKeyName }) {
  if (result === null || typeof result !== "object") fail();
  const present = result.allowedSecretKeysPresent ?? result.allowed_secret_keys_present;
  const empty = result.dotenvEmpty ?? result.dotenv_empty;
  const loadedCount = result.loadedCount ?? result.loaded_count;
  const loadedRoleEnv = result.loadedRoleEnv ?? result.loaded_role_env;
  const observedEmptyKeys = result.observedEmptyKeys ?? result.observed_empty_keys;
  const expectedEmptyKeys = dotenvKeys.filter((key) => key !== providerKeyName);
  if (
    present === null ||
    typeof present !== "object" ||
    !sameStrings(Object.keys(present), [providerKeyName, "AUXILIARY_CLOCKCHAIN_MCP_API_KEY"]) ||
    present[providerKeyName] !== true ||
    present.AUXILIARY_CLOCKCHAIN_MCP_API_KEY !== true
  ) {
    fail();
  }
  if (!Number.isSafeInteger(loadedCount) || loadedCount < 1 || loadedRoleEnv !== true) fail();
  if (!Array.isArray(observedEmptyKeys) || !sameStrings(observedEmptyKeys, expectedEmptyKeys)) fail();
  if (empty === null || typeof empty !== "object") fail();
  if (!sameStrings(Object.keys(empty), expectedEmptyKeys)) fail();
  for (const key of expectedEmptyKeys) if (empty[key] !== true) fail();
  if ((result.managedAbsent ?? result.managed_absent) !== true) fail();
  if ((result.roleEnvCommentOnly ?? result.role_env_comment_only) !== true) fail();
  if ((result.terminalSanitizerRemovedAuxiliary ?? result.terminal_sanitizer_removed_auxiliary) !== true) fail();
  if ((result.terminalSanitizerRemovedProvider ?? result.terminal_sanitizer_removed_provider) !== true) fail();
  return Object.freeze({
    dotenvEmpty: Object.freeze(Object.fromEntries(expectedEmptyKeys.map((key) => [key, true]))),
    loadedCount,
    loadedRoleEnv: true,
    managedAbsent: true,
    observedEmptyKeys: Object.freeze(sorted(observedEmptyKeys)),
    roleEnvCommentOnly: true,
    terminalSanitizerRemovedAuxiliary: true,
    terminalSanitizerRemovedProvider: true,
  });
}

async function defaultProbeEnvLoader({ dotenvKeys, env, hermesInstallRoot, providerKeyName }) {
  const python = join(hermesInstallRoot, "venv", "bin", "python");
  const script = [
    "import contextlib, io, json, os",
    "from pathlib import Path",
    "import hermes_cli.env_loader as env_loader",
    "from hermes_cli.env_loader import load_hermes_dotenv",
    "from tools.environments.local import _sanitize_subprocess_env",
    "env_loader._sanitize_env_file_if_needed = lambda *args, **kwargs: None",
    "empty=json.loads(os.environ['HERMES_EMPTY_KEYS_JSON'])",
    "provider=os.environ['HERMES_PROVIDER_KEY_NAME']",
    "loaded=[]",
    "with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):",
    "    loaded=[str(path) for path in load_hermes_dotenv(hermes_home=os.environ['HERMES_HOME'])]",
    "    sanitized=_sanitize_subprocess_env(dict(os.environ), {})",
    "role_env=Path(os.environ['HERMES_HOME'], '.env')",
    "env_text=role_env.read_text(encoding='utf8')",
    "comment_only=all((not line.strip()) or line.strip().startswith('#') for line in env_text.splitlines())",
    "print(json.dumps({",
    "'allowed_secret_keys_present':{provider:bool(os.environ.get(provider)),'AUXILIARY_CLOCKCHAIN_MCP_API_KEY':bool(os.environ.get('AUXILIARY_CLOCKCHAIN_MCP_API_KEY'))},",
    "'dotenv_empty':{key:os.environ.get(key,'')=='' for key in empty},",
    "'managed_absent':os.environ.get('HERMES_MANAGED_PRESENT')!='1',",
    "'loaded_count':len(loaded),",
    "'loaded_role_env':str(role_env) in loaded,",
    "'observed_empty_keys':empty,",
    "'role_env_comment_only':comment_only,",
    "'terminal_sanitizer_removed_auxiliary':'AUXILIARY_CLOCKCHAIN_MCP_API_KEY' not in sanitized,",
    "'terminal_sanitizer_removed_provider':provider not in sanitized}))",
  ].join("\n");
  const { stdout } = await commandRunner(python, ["-c", script], { env, timeout: 10_000 });
  return JSON.parse(stdout);
}

function normalizeMcpDiscovery(result) {
  if (result === null || typeof result !== "object") fail();
  const registeredTools = result.registeredTools ?? result.registered_tools;
  const shutdownCalled = result.shutdownCalled ?? result.shutdown_called;
  if (shutdownCalled !== true) fail();
  if (
    !Array.isArray(registeredTools) ||
    JSON.stringify(registeredTools) !== JSON.stringify(REGISTERED_CLOCKCHAIN_TOOLS)
  ) {
    fail();
  }
  // Hermes discovery exposes registered tool names. Static server URL/resources/prompts
  // are proven separately by the generated config, not inferred from discovery.
  return Object.freeze({
    registeredTools: REGISTERED_CLOCKCHAIN_TOOLS,
    shutdownCalled: true,
  });
}

async function defaultDiscoverMcp({ env, hermesInstallRoot }) {
  const python = join(hermesInstallRoot, "venv", "bin", "python");
  const script = [
    "import contextlib, io, json",
    "from tools.mcp_tool import discover_mcp_tools, shutdown_mcp_servers",
    "try:",
    "    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):",
    "        tools = discover_mcp_tools()",
    "finally:",
    "    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):",
    "        shutdown_mcp_servers()",
    "print(json.dumps({'registered_tools':tools,'shutdown_called':True}))",
  ].join("\n");
  const { stdout } = await commandRunner(python, ["-c", script], { env, timeout: 10_000 });
  return normalizeMcpDiscovery(JSON.parse(stdout));
}

async function cleanupBootstrap(paths) {
  for (const path of [
    paths.bootstrapCorepackHome,
    paths.bootstrapGitConfig,
    paths.bootstrapHermesHome,
    paths.bootstrapHome,
    paths.bootstrapNpmCache,
    paths.bootstrapTmp,
    paths.bootstrapXdgCache,
  ]) {
    await rm(path, { force: true, recursive: true });
  }
}

function scanPublicValue(value, canaries) {
  const seen = new WeakSet();
  function visit(entry, key = "") {
    if (typeof entry === "string") {
      assertSecretFree(entry, canaries);
      if (ABSOLUTE_PATH_FRAGMENT.test(entry)) throw new SecretMaterialDetectedError();
      if (canaries.some((canary) => entry.includes(canary))) throw new SecretMaterialDetectedError();
      if (SECRET_STRING_PATTERNS.some((pattern) => pattern.test(entry))) throw new SecretMaterialDetectedError();
      if (SECRET_KEY_PATTERN.test(key) && entry !== "" && entry !== "[REDACTED]") throw new SecretMaterialDetectedError();
      return;
    }
    if (entry === null || typeof entry !== "object") {
      if (
        SECRET_KEY_PATTERN.test(key) &&
        key !== "tokensPresent" &&
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

export async function prepareHermesCleanRoom({
  commandRunner: run = commandRunner,
  detectHermes = defaultDetectHermes,
  hermesBinary = DEFAULT_HERMES_BINARY,
  hermesInstallRoot = DEFAULT_HERMES_INSTALL_ROOT,
  kitCommit,
  role: inputRole,
  runHermesProfileCreate = defaultRunHermesProfileCreate,
  runRoot,
} = {}) {
  let roleRoot;
  let roleRootCreated = false;
  try {
    const cleanRole = role(inputRole);
    const cleanRunRoot = canonicalAbsolutePath(runRoot);
    const cleanBinary = canonicalAbsolutePath(hermesBinary);
    const cleanInstallRoot = canonicalAbsolutePath(hermesInstallRoot);
    if (typeof kitCommit !== "string" || !/^[0-9a-f]{40}$/i.test(kitCommit)) fail();
    await ensureRunRoot(cleanRunRoot);
    await assertNoSymlinkTree(cleanRunRoot);
    const rolesRoot = join(cleanRunRoot, "roles");
    if ((await lstatOptional(rolesRoot)) === undefined) await createPrivateDirectory(rolesRoot);
    await assertPrivateDirectory(rolesRoot);
    roleRoot = assertDescendant(cleanRunRoot, join(rolesRoot, cleanRole));
    if ((await lstatOptional(roleRoot)) !== undefined) fail();
    await createPrivateDirectory(roleRoot);
    roleRootCreated = true;
    const paths = buildPaths(cleanRunRoot, cleanRole);
    for (const path of Object.values(paths)) assertDescendant(cleanRunRoot, path);
    await createBaseDirectories(paths);
    const identity = validateHermesDetection(
      await detectHermes({
        commandRunner: run,
        hermesHome: paths.bootstrapHermesHome,
        hermesBinary: cleanBinary,
        hermesInstallRoot: cleanInstallRoot,
        home: paths.bootstrapHome,
        pathValue: DEFAULT_PATH,
      }),
      cleanInstallRoot,
    );
    const dotenvKeys = await parseDotenvKeys(cleanInstallRoot);
    const profileResult = await runHermesProfileCreate({
      commandRunner: run,
      env: bootstrapEnv({ dotenvKeys, paths, pathValue: DEFAULT_PATH }),
      hermesBinary: cleanBinary,
      hermesHome: paths.bootstrapHermesHome,
    });
    if (profileResult?.profileDirectory !== join(paths.bootstrapHermesHome, "profiles", "agent")) fail();
    await validateAndPromoteProfile({ paths });
    await cleanupBootstrap(paths);
    const expected = await expectedTree({ paths, roleRoot, runRoot: cleanRunRoot });
    const zeroState = await inspectTree({ expected, roleRoot, runRoot: cleanRunRoot });
    if (zeroState.clean !== true) fail();
    const hermes = publicHermes({ hermesBinary: cleanBinary, hermesInstallRoot: cleanInstallRoot, identity });
    const preProvision = Object.freeze({
      phase: "pre-provision",
      role: cleanRole,
      hermes,
      kitCommit,
      paths: publicPaths({ paths, runRoot: cleanRunRoot }),
      tokensPresent: false,
      zeroState,
    });
    assertPublicCleanRoomEvidence(preProvision, [cleanRunRoot, cleanInstallRoot]);
    const preProvisionPath = join(paths.evidencePrivate, "pre-provision.json");
    await writeJsonPrivate(preProvisionPath, preProvision);
    return Object.freeze({
      dotenvKeys,
      hermes,
      hermesBinary: cleanBinary,
      hermesInstallRoot: cleanInstallRoot,
      kitCommit,
      manifests: Object.freeze({ preProvisionPath }),
      paths,
      role: cleanRole,
      roleRoot,
      runRoot: cleanRunRoot,
    });
  } catch (error) {
    if (roleRootCreated) await rm(roleRoot, { force: true, recursive: true }).catch(() => {});
    sanitize(error);
  }
  fail();
}

export async function provisionHermesCleanRoom({
  clockchainMcpToken,
  discoverMcp = defaultDiscoverMcp,
  inferenceKeyName,
  inferenceKeyValue,
  peerClockchainMcpToken,
  prepared,
  probeEnvLoader = defaultProbeEnvLoader,
  providerKeyName = "KIMI_API_KEY",
  providerKeyValue,
  room,
} = {}) {
  let configPath;
  let prePromptPath;
  try {
    const preparedRoom = room ?? prepared;
    if (preparedRoom === null || typeof preparedRoom !== "object") fail();
    const providerName = assertProviderKeyName(inferenceKeyName ?? providerKeyName);
    const providerSecret = assertSecretString(inferenceKeyValue ?? providerKeyValue);
    const mcpToken = assertSecretString(clockchainMcpToken);
    if (peerClockchainMcpToken !== undefined && peerClockchainMcpToken === mcpToken) fail();
    const principalFingerprint = fingerprintClockchainDemoToken(mcpToken);
    const paths = preparedRoom.paths;
    const config = buildConfig(paths);
    configPath = paths.config;
    await writeJsonPrivate(configPath, config);
    const env = childEnv({
      dotenvKeys: preparedRoom.dotenvKeys,
      mcpToken,
      paths,
      providerKeyName: providerName,
      providerKeyValue: providerSecret,
    });
    const envLoader = normalizeEnvProbe(
      await probeEnvLoader({
        dotenvKeys: preparedRoom.dotenvKeys,
        env: probeEnv({ dotenvKeys: preparedRoom.dotenvKeys, env, providerKeyName: providerName }),
        hermesInstallRoot: preparedRoom.hermesInstallRoot,
        providerKeyName: providerName,
      }),
      { dotenvKeys: preparedRoom.dotenvKeys, providerKeyName: providerName },
    );
    const mcp = normalizeMcpDiscovery(await discoverMcp({
      config,
      configPath,
      env,
      hermesHome: paths.hermesHome,
      hermesInstallRoot: preparedRoom.hermesInstallRoot,
    }));
    await cleanupMcpDiscoveryArtifacts(paths.hermesHome);
    const expected = await expectedTree({
      includeConfig: true,
      includePreProvision: true,
      paths,
      roleRoot: preparedRoom.roleRoot,
      runRoot: preparedRoom.runRoot,
    });
    const zeroState = await inspectTree({ expected, roleRoot: preparedRoom.roleRoot, runRoot: preparedRoom.runRoot });
    if (zeroState.clean !== true) fail();
    const prePrompt = Object.freeze({
      phase: "pre-prompt",
      role: preparedRoom.role,
      envProbe: envLoader,
      hermes: preparedRoom.hermes,
      kitCommit: preparedRoom.kitCommit,
      mcp,
      paths: publicPaths({ paths, runRoot: preparedRoom.runRoot }),
      principalFingerprint,
      retainedEvidencePath: relativePath(preparedRoom.runRoot, join(paths.evidencePrivate, "pre-prompt.json")),
      tokensPresent: true,
      zeroState: Object.freeze({ ...zeroState, reinspectedBeforePrompt: true }),
    });
    assertPublicCleanRoomEvidence(prePrompt, [mcpToken, providerSecret, preparedRoom.runRoot, preparedRoom.hermesInstallRoot]);
    prePromptPath = join(paths.evidencePrivate, "pre-prompt.json");
    await writeJsonPrivate(prePromptPath, prePrompt);
    return Object.freeze({
      env,
      manifests: Object.freeze({
        prePromptPath,
        preProvisionPath: preparedRoom.manifests.preProvisionPath,
      }),
      paths,
      probes: Object.freeze({ envLoader, mcp }),
      role: preparedRoom.role,
      roleRoot: preparedRoom.roleRoot,
      runRoot: preparedRoom.runRoot,
    });
  } catch (error) {
    if (configPath !== undefined) await rm(configPath, { force: true }).catch(() => {});
    if (prePromptPath !== undefined) await rm(prePromptPath, { force: true }).catch(() => {});
    const cleanupRoom = room ?? prepared;
    if (cleanupRoom?.paths?.hermesHome !== undefined) {
      await rm(join(cleanupRoom.paths.hermesHome, ".mcp-discovery.lock"), { force: true }).catch(() => {});
    }
    sanitize(error);
  }
  fail();
}
