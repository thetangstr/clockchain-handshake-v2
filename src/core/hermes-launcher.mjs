import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  join,
  parse,
  resolve,
} from "node:path";

import { mintDemoToken as defaultMintDemoToken } from "./clockchain.mjs";
import { readPrivateText, writePrivateFile } from "./private-path.mjs";
import { redact } from "./redact.mjs";

const ROLES = Object.freeze(["payer", "requestor"]);
const ROLE_LABELS = Object.freeze({ payer: "Payer", requestor: "Requestor" });
const CLOCKCHAIN_MCP_URL = "https://mcp.clockchain.network/mcp";
const CLOCKCHAIN_TOOLS = Object.freeze([
  "handshake_status",
  "handshake_join",
  "handshake_next",
  "handshake_submit",
  "handshake_get_certificate",
]);
const SUPPORTED_KIMI_KEYS = Object.freeze(["KIMI_API_KEY", "KIMI_CODING_API_KEY"]);
const TOKEN_PATTERN = /^[\x21-\x7e]{1,8192}$/;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const DEFAULT_HERMES_BINARY = "/Users/maxiaoer/.local/bin/hermes";
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;
const MAX_CAPTURE_BYTES = 1_048_576;
const TERMINAL_MARKER = "FINAL_HANDSHAKE_JSON";
const SAFE_ERROR = "Hermes demo failed safely.";

function fail() {
  throw new Error(SAFE_ERROR);
}

function sanitize(error) {
  if (error?.message === SAFE_ERROR) throw error;
  fail();
}

function assertPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function absolutePath(value) {
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
  if (!ROLES.includes(value)) fail();
  return value;
}

function kitUrl(value) {
  if (typeof value !== "string") fail();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail();
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.search !== "" ||
    !/\.git$/.test(parsed.pathname)
  ) {
    fail();
  }
  return parsed.toString();
}

function kitCommit(value) {
  if (typeof value !== "string" || !COMMIT_PATTERN.test(value)) fail();
  return value.toLowerCase();
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validateToken(value) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) fail();
  return value;
}

async function ensurePrivateDirectory(path) {
  await mkdir(path, { mode: 0o700, recursive: true });
  if (process.platform !== "win32") await chmod(path, 0o700);
}

async function assertExists(path) {
  const stats = await lstat(path);
  if (!stats.isFile() || stats.isSymbolicLink()) fail();
}

async function defaultCheckKit({ kitUrl: url, kitCommit: commit }) {
  const response = await fetch(url, { method: "HEAD", redirect: "follow" });
  if (!response.ok) fail();
  if (!commit) fail();
  return true;
}

async function loadDefaultCleanRoomFunctions() {
  const module = await import("./hermes-cleanroom.mjs");
  const prepareHermesCleanRoom =
    module.prepareHermesCleanRoom ??
    module.prepareCleanRoom;
  const provisionHermesCleanRoom =
    module.provisionHermesCleanRoom ??
    (async ({ prepared, clockchainMcpToken, inferenceKeyName, inferenceKeyValue, role: cleanRole, ...rest }) =>
      module.prepareCleanRoom({
        ...rest,
        clockchainMcpToken,
        inferenceKeyName,
        inferenceKeyValue,
        role: cleanRole,
        runRoot: dirname(dirname(prepared.roleRoot)),
      }));
  if (typeof prepareHermesCleanRoom !== "function" || typeof provisionHermesCleanRoom !== "function") fail();
  return { prepareHermesCleanRoom, provisionHermesCleanRoom };
}

export async function readKimiCredential({
  credentialFile,
  env = process.env,
  keyName = "KIMI_API_KEY",
} = {}) {
  try {
    if (!SUPPORTED_KIMI_KEYS.includes(keyName)) fail();
    assertPlainObject(env);
    const present = SUPPORTED_KIMI_KEYS.filter((name) => typeof env[name] === "string" && env[name].length > 0);
    if (credentialFile !== undefined) {
      if (present.length > 0) fail();
      const target = absolutePath(credentialFile);
      const value = (await readPrivateText({ path: target })).trim();
      if (value.length === 0) fail();
      return Object.freeze({ keyName, value });
    }
    if (present.length !== 1) fail();
    return Object.freeze({ keyName: present[0], value: env[present[0]] });
  } catch (error) {
    sanitize(error);
  }
}

function staticPrompt({ role: cleanRole }) {
  const label = ROLE_LABELS[cleanRole];
  const authorLine = cleanRole === "payer"
    ? "You author the mandate only; you must not author the payment request."
    : "You author the payment request only; you must not author the mandate.";
  const forbidden = cleanRole === "payer"
    ? "If a step asks you to create the payment request, stop and emit failure JSON."
    : "If a step asks you to create the mandate, stop and emit failure JSON.";
  return `# Clockchain Handshake Hermes ${label}

Role: ${label}

You are one fresh Hermes agent in an empty workspace. Clockchain is the host, funder, and independent checker; Clockchain is not a party. The Mac mini is only the launcher and gateway. Never read, print, copy, or infer another role's files, wallet, environment, token, or state.

## Install the pinned public kit

Run these commands in your empty workspace:

1. git clone <KIT_URL> handshake-kit
2. cd handshake-kit
3. git checkout <KIT_COMMIT>
4. npm ci

The only acceptable MCP endpoint is ${CLOCKCHAIN_MCP_URL}. Use shared discovery through the Clockchain MCP server and these exact five Clockchain tools: ${CLOCKCHAIN_TOOLS.join(", ")}. Terminal and file tools are available only so you can clone, install, run the wallet bridge, and inspect your own workspace.

## Local wallet and registration

Create your own wallet with node bin/wallet-bridge.mjs init. Inspect it with node bin/wallet-bridge.mjs inspect. Sign only exact 0x byte strings with node bin/wallet-bridge.mjs sign using EIP-191 raw-byte semantics. Register the same local address with node bin/wallet-bridge.mjs register for ERC-8004 identity. Never expose the private key.

## Protocol duties

Call handshake_join for Role: ${label}, then loop on handshake_next. When bytesToSignHex appears, sign those exact bytes locally and submit only the public signature through handshake_submit. ${authorLine} ${forbidden} Both parties sign their own party result and evidence. Hosted MCP coordinators advance PROPOSED, ACCEPTED, and ACKNOWLEDGED; do not invent or claim an ACK signed by a party.

Fetch the certificate with handshake_get_certificate and verify the digest locally. No money moves; the final JSON must include paymentMoved:false. This is a single-validator testnet demo, not court-grade finality.

## Terminal success contract

Do not announce success in prose. The independent checker decides the verdict. End with one line prefixed ${TERMINAL_MARKER} followed by compact JSON:

${TERMINAL_MARKER} {"role":"${cleanRole}","sessionId":"...","address":"0x...","agentId":"...","certificateDigest":"<sha256>","certificateVerified":true,"paymentMoved":false,"receipts":[]}
`;
}

export function buildHermesPrompt({ role: inputRole, kitUrl: inputKitUrl, kitCommit: inputKitCommit } = {}) {
  try {
    const cleanRole = role(inputRole);
    const cleanUrl = kitUrl(inputKitUrl);
    const cleanCommit = kitCommit(inputKitCommit);
    return staticPrompt({ role: cleanRole })
      .replaceAll("<KIT_URL>", cleanUrl)
      .replaceAll("<KIT_COMMIT>", cleanCommit);
  } catch (error) {
    sanitize(error);
  }
}

async function writePrompt(path, text) {
  await writePrivateFile({ path, bytes: Buffer.from(text) });
}

function appendBounded(target, chunk) {
  const next = `${target}${Buffer.from(chunk).toString("utf8")}`;
  if (Buffer.byteLength(next, "utf8") > MAX_CAPTURE_BYTES) {
    return next.slice(-MAX_CAPTURE_BYTES);
  }
  return next;
}

function parseTerminalJson(text) {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index];
    const markerIndex = line.indexOf(TERMINAL_MARKER);
    const candidate = markerIndex >= 0
      ? line.slice(markerIndex + TERMINAL_MARKER.length).trim()
      : line.slice(line.indexOf("{")).trim();
    if (!candidate.startsWith("{")) continue;
    try {
      return JSON.parse(candidate);
    } catch {
      // Continue scanning earlier lines; agent prose is untrusted.
    }
  }
  fail();
}

function validateRoleResult(value, expectedRole) {
  const result = assertPlainObject(value);
  if (result.role !== expectedRole) fail();
  if (typeof result.sessionId !== "string" || result.sessionId.length === 0) fail();
  if (typeof result.agentId !== "string" || result.agentId.length === 0) fail();
  if (typeof result.address !== "string" || !ADDRESS_PATTERN.test(result.address)) fail();
  if (typeof result.certificateDigest !== "string" || !SHA256_PATTERN.test(result.certificateDigest)) fail();
  if (result.certificateVerified !== true) fail();
  if (result.paymentMoved !== false) fail();
  if (!Array.isArray(result.receipts)) fail();
  return Object.freeze({
    address: result.address,
    agentId: result.agentId,
    certificateDigest: result.certificateDigest,
    certificateVerified: true,
    paymentMoved: false,
    receipts: result.receipts.map(String),
    role: expectedRole,
    sessionId: result.sessionId,
  });
}

function validatePair({ payer, requestor }) {
  if (payer.sessionId !== requestor.sessionId) fail();
  if (payer.certificateDigest !== requestor.certificateDigest) fail();
  if (payer.address.toLowerCase() === requestor.address.toLowerCase()) fail();
  if (payer.agentId === requestor.agentId) fail();
  return Object.freeze({
    certificateDigest: payer.certificateDigest,
    certificateVerified: true,
    paymentMoved: false,
    payer,
    requestor,
    sessionId: payer.sessionId,
  });
}

function killChild(child) {
  if (child?.killed === true) return;
  if (Number.isSafeInteger(child?.pid) && child.pid > 0) {
    try {
      process.kill(-child.pid, "SIGTERM");
      return;
    } catch {
      // Fall back to direct child termination below.
    }
  }
  if (typeof child?.kill === "function") child.kill("SIGTERM");
}

function waitForChild({ child, role: cleanRole, canaries, controller, children }) {
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (chunk) => {
    stdout = appendBounded(stdout, chunk);
  });
  child.stderr?.on("data", (chunk) => {
    stderr = appendBounded(stderr, chunk);
  });
  return new Promise((resolvePromise) => {
    child.once("error", (error) => {
      controller.abort();
      for (const entry of children) killChild(entry);
      resolvePromise({
        error: redact(error, canaries),
        role: cleanRole,
        stderr: redact(stderr, canaries),
        stdout: redact(stdout, canaries),
        ok: false,
      });
    });
    child.once("close", (code, signal) => {
      const clean = {
        code,
        role: cleanRole,
        signal,
        stderr: redact(stderr, canaries),
        stdout: redact(stdout, canaries),
      };
      if (code !== 0) {
        controller.abort();
        for (const entry of children) killChild(entry);
        resolvePromise({ ...clean, ok: false });
        return;
      }
      try {
        resolvePromise({
          ...clean,
          ok: true,
          result: validateRoleResult(parseTerminalJson(stdout), cleanRole),
        });
      } catch (error) {
        controller.abort();
        for (const entry of children) killChild(entry);
        resolvePromise({ ...clean, error: redact(error, canaries), ok: false });
      }
    });
  });
}

async function finalizeEvidence({ evidencePath, evidence, canaries }) {
  const text = `${JSON.stringify(evidence, null, 2)}\n`;
  for (const canary of canaries) {
    if (canary && text.includes(canary)) fail();
  }
  await ensurePrivateDirectory(dirname(evidencePath));
  const temp = `${evidencePath}.tmp-${process.pid}`;
  await writePrivateFile({ path: temp, bytes: Buffer.from(text) });
  await rename(temp, evidencePath);
  if (process.platform !== "win32") await chmod(evidencePath, 0o600);
  const retained = await readFile(evidencePath, "utf8");
  for (const canary of canaries) {
    if (canary && retained.includes(canary)) fail();
  }
}

function publicManifestPaths(room) {
  return Object.freeze({
    prePromptPath: room.manifests?.prePromptPath,
    preProvisionPath: room.manifests?.preProvisionPath,
  });
}

async function validatePrepared(room, expectedRole) {
  assertPlainObject(room);
  if (room.role !== expectedRole) fail();
  absolutePath(room.roleRoot);
  absolutePath(room.paths?.workspace);
  absolutePath(room.paths?.evidencePrivate);
  await assertExists(room.manifests?.preProvisionPath);
  return room;
}

async function validateProvisioned(room, expectedRole) {
  await validatePrepared(room, expectedRole);
  await assertExists(room.manifests?.prePromptPath);
  assertPlainObject(room.env);
  return room;
}

export async function runHermesDemo(options = {}) {
  try {
    const {
      checkKit = defaultCheckKit,
      cleanRoom = async ({ roleRoot }) => rm(roleRoot, { force: true, recursive: true }),
      credentialFile,
      dryRun = false,
      env = process.env,
      hermesBinary = DEFAULT_HERMES_BINARY,
      inferenceKeyName,
      inferenceKeyValue,
      keepCleanrooms = false,
      kitCommit: inputKitCommit,
      kitUrl: inputKitUrl,
      localDebug = false,
      mintDemoToken = defaultMintDemoToken,
      runId = `run-${Date.now()}`,
      runRoot: inputRunRoot,
      spawnProcess = spawn,
      timeoutMs = DEFAULT_TIMEOUT_MS,
    } = options;

    if (keepCleanrooms === true && localDebug !== true) fail();
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) fail();
    const cleanRunRoot = absolutePath(inputRunRoot);
    const cleanHermesBinary = absolutePath(hermesBinary);
    const cleanKitUrl = kitUrl(inputKitUrl);
    const cleanKitCommit = kitCommit(inputKitCommit);
    if (typeof checkKit !== "function" || await checkKit({ kitUrl: cleanKitUrl, kitCommit: cleanKitCommit }) !== true) fail();
    await ensurePrivateDirectory(cleanRunRoot);

    const credential = inferenceKeyValue !== undefined
      ? (() => {
          if (!SUPPORTED_KIMI_KEYS.includes(inferenceKeyName)) fail();
          if (typeof inferenceKeyValue !== "string" || inferenceKeyValue.length === 0) fail();
          return { keyName: inferenceKeyName, value: inferenceKeyValue };
        })()
      : await readKimiCredential({ credentialFile, env, keyName: inferenceKeyName ?? "KIMI_API_KEY" });

    const loaded = await loadDefaultCleanRoomFunctions();
    const prepareHermesCleanRoom = options.prepareHermesCleanRoom ?? loaded.prepareHermesCleanRoom;
    const provisionHermesCleanRoom = options.provisionHermesCleanRoom ?? loaded.provisionHermesCleanRoom;

    const prepared = {};
    for (const cleanRole of ROLES) {
      prepared[cleanRole] = await validatePrepared(await prepareHermesCleanRoom({
        hermesBinary: cleanHermesBinary,
        kitCommit: cleanKitCommit,
        kitUrl: cleanKitUrl,
        role: cleanRole,
        runRoot: cleanRunRoot,
      }), cleanRole);
    }

    if (dryRun === true) {
      return Object.freeze({
        dryRun: true,
        manifests: Object.freeze(Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, publicManifestPaths(prepared[cleanRole])]))),
      });
    }

    const tokenEntries = [];
    for (const cleanRole of ROLES) {
      tokenEntries.push([
        cleanRole,
        validateToken(await mintDemoToken({ subject: `hermes-demo:${runId}:${cleanRole}` })),
      ]);
    }
    const tokens = Object.fromEntries(tokenEntries);
    if (tokens.payer === tokens.requestor) fail();
    const canaries = Object.freeze([tokens.payer, tokens.requestor, credential.value]);

    const provisioned = {};
    for (const cleanRole of ROLES) {
      provisioned[cleanRole] = await validateProvisioned(await provisionHermesCleanRoom({
        clockchainMcpToken: tokens[cleanRole],
        inferenceKeyName: credential.keyName,
        inferenceKeyValue: credential.value,
        prepared: prepared[cleanRole],
        role: cleanRole,
      }), cleanRole);
    }

    const children = [];
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
      for (const child of children) killChild(child);
    }, timeoutMs);
    const waiters = [];
    for (const cleanRole of ROLES) {
      const promptPath = join(provisioned[cleanRole].paths.evidencePrivate, "prompt.md");
      const usagePath = join(provisioned[cleanRole].paths.evidencePrivate, "usage.json");
      await writePrompt(promptPath, buildHermesPrompt({
        role: cleanRole,
        kitCommit: cleanKitCommit,
        kitUrl: cleanKitUrl,
      }));
      const args = [
        "-z",
        promptPath,
        "--usage-file",
        usagePath,
        "--ignore-rules",
        "--provider",
        "kimi-coding",
        "-m",
        "k3",
        "-t",
        "terminal,file,clockchain",
      ];
      const child = spawnProcess(cleanHermesBinary, args, {
        cwd: provisioned[cleanRole].paths.workspace,
        detached: true,
        env: provisioned[cleanRole].env,
        signal: controller.signal,
        stdio: ["ignore", "pipe", "pipe"],
      });
      children.push(child);
      waiters.push(waitForChild({
        canaries,
        child,
        children,
        controller,
        role: cleanRole,
      }));
    }

    const settled = await Promise.allSettled(waiters);
    const aborted = controller.signal.aborted;
    clearTimeout(timeout);
    if (aborted) {
      for (const child of children) killChild(child);
    }
    if (aborted) fail();
    if (settled.some((entry) => entry.status !== "fulfilled" || entry.value.ok !== true)) fail();
    const byRole = Object.fromEntries(settled.map((entry) => [entry.value.role, entry.value]));
    const summary = validatePair({
      payer: byRole.payer.result,
      requestor: byRole.requestor.result,
    });

    const evidence = Object.freeze({
      manifests: Object.fromEntries(ROLES.map((cleanRole) => [cleanRole, publicManifestPaths(provisioned[cleanRole])])),
      runId,
      summary,
      tokenSha256: {
        payer: sha256(tokens.payer),
        requestor: sha256(tokens.requestor),
      },
      transcripts: Object.fromEntries(ROLES.map((cleanRole) => [
        cleanRole,
        {
          stderr: byRole[cleanRole].stderr,
          stdout: byRole[cleanRole].stdout,
        },
      ])),
    });
    const evidencePath = join(cleanRunRoot, "evidence", "result.json");
    await finalizeEvidence({ canaries, evidence, evidencePath });

    if (keepCleanrooms !== true) {
      for (const cleanRole of ROLES) {
        await cleanRoom({ role: cleanRole, roleRoot: provisioned[cleanRole].roleRoot });
      }
    }

    return Object.freeze({ evidencePath, summary });
  } catch (error) {
    sanitize(error);
  }
}

export const HERMES_DEMO_TERMINAL_MARKER = TERMINAL_MARKER;
