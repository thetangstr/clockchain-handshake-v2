#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { types } from "node:util";

import { canonicalBytes } from "../src/core/canonical.mjs";

const MANIFEST_KEYS = Object.freeze([
  "schema", "version", "sourceCommit", "nodeRuntime", "assets",
]);
const ASSET_KEYS = Object.freeze([
  "platform", "arch", "upstreamSupport", "filename", "url", "byteLength",
  "sha256", "nativeSignature", "execution",
]);
const SIGNATURE_KEYS = Object.freeze(["type", "verified", "signer", "timestamp", "notarized"]);
const EXECUTION_KEYS = Object.freeze([
  "verified", "platform", "arch", "exitCode", "publicOutputSha256",
]);
const SHA = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const VERSION = /^2\.1\.0$/;

function invalid() { throw new Error("Agent handshake release verification failed."); }

function exact(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) invalid();
  const result = {};
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property?.enumerable !== true || !Object.hasOwn(property, "value")) invalid();
    result[key] = property.value;
  }
  return result;
}

function signature(value, platform) {
  const item = exact(value, SIGNATURE_KEYS);
  const requiredType = platform === "node" ? "none" : "invalid";
  if (
    item.type !== requiredType || item.verified !== true ||
    item.notarized !== null || item.signer !== null || item.timestamp !== null
  ) invalid();
  return Object.freeze(item);
}

function execution(value) {
  const item = exact(value, EXECUTION_KEYS);
  if (
    item.verified !== true || item.platform !== "linux" || item.arch !== "x64" ||
    item.exitCode !== "0" || !SHA.test(item.publicOutputSha256)
  ) invalid();
  return Object.freeze(item);
}

function asset(value, { allowedAssetPrefix, bytesByUrl }) {
  const item = exact(value, ASSET_KEYS);
  if (
    item.platform !== "node" || item.arch !== "any" ||
    item.upstreamSupport !== "node24_portable"
  ) invalid();
  const expectedFilename = "clockchain-agent-handshake.cjs";
  if (
    item.filename !== expectedFilename || typeof item.url !== "string" ||
    !item.url.startsWith(allowedAssetPrefix) || item.url !== allowedAssetPrefix + expectedFilename ||
    !DECIMAL.test(item.byteLength) || BigInt(item.byteLength) < 1n || !SHA.test(item.sha256)
  ) invalid();
  if (bytesByUrl !== undefined) {
    const bytes = bytesByUrl.get(item.url);
    if (!Buffer.isBuffer(bytes) || String(bytes.length) !== item.byteLength || createHash("sha256").update(bytes).digest("hex") !== item.sha256) invalid();
  }
  return Object.freeze({
    ...item,
    nativeSignature: signature(item.nativeSignature, item.platform),
    execution: execution(item.execution),
  });
}

export function agentHandshakeReleaseManifestDigest(value) {
  const item = exact(value, MANIFEST_KEYS);
  return createHash("sha256").update(canonicalBytes(item)).digest("hex");
}

export function validateAgentHandshakeReleaseManifest(value, {
  allowedAssetPrefix,
  bytesByUrl,
  expectedSourceCommit,
} = {}) {
  const item = exact(value, MANIFEST_KEYS);
  if (
    item.schema !== "clockchain.agent-handshake-release-manifest/v1" ||
    !VERSION.test(item.version) || !COMMIT.test(item.sourceCommit) ||
    item.sourceCommit !== expectedSourceCommit || !/^24\.[0-9]+\.[0-9]+$/.test(item.nodeRuntime) ||
    typeof allowedAssetPrefix !== "string" ||
    allowedAssetPrefix !== "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/" ||
    !Array.isArray(item.assets) || item.assets.length !== 1
  ) invalid();
  const assets = item.assets.map((entry) => asset(entry, { allowedAssetPrefix, bytesByUrl }));
  const pairs = assets.map((entry) => `${entry.platform}/${entry.arch}`);
  if (new Set(pairs).size !== pairs.length) invalid();
  const required = ["node/any"];
  if (required.some((pair) => !pairs.includes(pair))) invalid();
  return Object.freeze({ ...item, assets: Object.freeze(assets) });
}

export function assembleAgentHandshakeReleaseManifest({ assets, bytesByUrl, nodeRuntime, sourceCommit }) {
  const value = {
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: "2.1.0",
    sourceCommit,
    nodeRuntime,
    assets,
  };
  return validateAgentHandshakeReleaseManifest(value, {
    allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/",
    bytesByUrl,
    expectedSourceCommit: sourceCommit,
  });
}

async function main(argv) {
  if (argv[0] === "assemble" && argv.length === 5) {
    const recordsDir = resolve(argv[1]);
    const sourceCommit = argv[2];
    const nodeRuntime = argv[3];
    const output = resolve(argv[4]);
    const names = (await readdir(recordsDir)).filter((name) => name.endsWith(".record.json")).sort();
    const assets = await Promise.all(names.map(async (name) => JSON.parse(await readFile(resolve(recordsDir, name), "utf8"))));
    const bytesByUrl = new Map(await Promise.all(assets.map(async (entry) => [
      entry.url,
      await readFile(resolve(recordsDir, entry.filename)),
    ])));
    const manifest = assembleAgentHandshakeReleaseManifest({ assets, bytesByUrl, nodeRuntime, sourceCommit });
    const manifestBytes = canonicalBytes(manifest);
    await writeFile(output, manifestBytes, { flag: "wx", mode: 0o600 });
    process.stdout.write(JSON.stringify({ ok: true, manifestDigest: createHash("sha256").update(manifestBytes).digest("hex") }) + "\n");
    return;
  }
  if (argv.length === 4 && argv[0] === "--manifest" && argv[2] === "--source-commit") {
    const manifestBytes = await readFile(resolve(argv[1]));
    const manifest = JSON.parse(manifestBytes.toString("utf8"));
    validateAgentHandshakeReleaseManifest(manifest, {
      allowedAssetPrefix: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/",
      expectedSourceCommit: argv[3],
    });
    const canonical = canonicalBytes(manifest);
    if (!manifestBytes.equals(canonical)) invalid();
    process.stdout.write(JSON.stringify({ ok: true, manifestDigest: createHash("sha256").update(manifestBytes).digest("hex") }) + "\n");
    return;
  }
  invalid();
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write(JSON.stringify({ error: "AGENT_HANDSHAKE_RELEASE_INVALID" }) + "\n");
    process.exitCode = 1;
  });
}
