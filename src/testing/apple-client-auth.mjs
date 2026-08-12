import { constants } from "node:fs";
import { chmod, copyFile, lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

const CLIENTS = Object.freeze(["codex", "claude"]);
const MAX_AUTH_BYTES = 64 * 1024;
const SAFE_ERROR = "Apple client authentication failed safely.";

function fail() {
  throw new Error(SAFE_ERROR);
}

function record(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function secret(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 16 * 1024) fail();
  return value;
}

async function privateSource(source) {
  if (typeof source !== "string" || !isAbsolute(source) || resolve(source) !== source || source.includes("\0")) fail();
  const [resolved, metadata] = await Promise.all([realpath(source), lstat(source)]).catch(fail);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 2 || metadata.size > MAX_AUTH_BYTES) fail();
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) fail();
  return resolved;
}

function parseAuthentication(client, text, nowMs) {
  let parsed;
  try { parsed = record(JSON.parse(text)); } catch { fail(); }
  if (client === "codex") {
    const tokens = record(parsed.tokens);
    return [secret(tokens.access_token), secret(tokens.id_token), secret(tokens.refresh_token)];
  }
  const oauth = record(parsed.claudeAiOauth);
  if (!Number.isSafeInteger(oauth.expiresAt) || oauth.expiresAt <= 0) fail();
  if (nowMs !== undefined && (!Number.isSafeInteger(nowMs) || oauth.expiresAt <= nowMs)) fail();
  return [secret(oauth.accessToken), secret(oauth.refreshToken)];
}

export async function loadAppleClientAuthentication({ client, nowMs, serialized, source } = {}) {
  if (!CLIENTS.includes(client)) fail();
  const hasSource = typeof source === "string";
  const hasSerialized = typeof serialized === "string";
  if (hasSource === hasSerialized) fail();
  const cleanSource = hasSource ? await privateSource(source) : null;
  const text = hasSource ? await readFile(cleanSource, "utf8").catch(fail) : serialized;
  if (Buffer.byteLength(text) < 2 || Buffer.byteLength(text) > MAX_AUTH_BYTES) fail();
  const secretCanaries = parseAuthentication(client, text, nowMs);
  return Object.freeze({
    client,
    environment: Object.freeze({}),
    secretCanaries: Object.freeze(secretCanaries),
    source: cleanSource,
    serialized: hasSerialized ? text : null,
  });
}

export async function installAppleClientAuthentication({ authentication, home } = {}) {
  const clean = record(authentication);
  if (!CLIENTS.includes(clean.client) || typeof home !== "string" || !isAbsolute(home) || resolve(home) !== home) fail();
  const directory = join(home, clean.client === "codex" ? ".codex" : ".claude");
  await mkdir(directory, { recursive: true, mode: 0o700 }).catch(fail);
  if (process.platform !== "win32") await chmod(directory, 0o700).catch(fail);
  const destination = join(directory, clean.client === "codex" ? "auth.json" : ".credentials.json");
  if (clean.source !== null && clean.serialized === null) {
    const source = await privateSource(clean.source);
    await copyFile(source, destination, constants.COPYFILE_EXCL).catch(fail);
  } else if (clean.source === null && typeof clean.serialized === "string") {
    parseAuthentication(clean.client, clean.serialized);
    await writeFile(destination, clean.serialized, { flag: "wx", mode: 0o600 }).catch(fail);
  } else {
    fail();
  }
  if (process.platform !== "win32") await chmod(destination, 0o600).catch(fail);
  return destination;
}
