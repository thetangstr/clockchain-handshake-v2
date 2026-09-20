#!/usr/bin/env node
// Builds dist/npm-local-adapter/: the bundled stdio server plus the pinned
// release assets (manifest.json + clockchain-agent-handshake.cjs) downloaded
// from the pin's allowedAssetPrefix and verified against
// validateAgentHandshakeReleasePin before anything is written. This download
// is the packager's install-time acquisition — the published package ships
// the verified bytes so the runtime never fetches executable code.
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { build } from "esbuild";

import {
  AGENT_HANDSHAKE_HELPER_NODE_MAJOR,
  AGENT_HANDSHAKE_HELPER_VERSION,
} from "../src/agent-handshake/v2/constants.mjs";
import { validateAgentHandshakeReleasePin } from "./verify-agent-handshake-release.mjs";

const ROOT = new URL("..", import.meta.url).pathname;
const ENTRY = new URL("../bin/clockchain-local-adapter.mjs", import.meta.url).pathname;
const PIN_PATH = new URL("../release/agent-handshake/pin.json", import.meta.url);
const PACKAGING_DIR = new URL("../packaging/local-adapter/", import.meta.url).pathname;
const HELPER_FILENAME = "clockchain-agent-handshake.cjs";
const LEGAL_FILES = ["LICENSE", "NOTICE", "THIRD-PARTY-NOTICES"];

function invalid() { throw new Error("Local adapter npm build failed."); }

async function defaultFetchAsset(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  if (!response.ok) invalid();
  return Buffer.from(await response.arrayBuffer());
}

export async function buildLocalAdapterNpm({ outDir, fetchImpl = defaultFetchAsset } = {}) {
  const directory = resolve(outDir ?? "dist/npm-local-adapter");
  if (typeof fetchImpl !== "function") invalid();
  const pin = JSON.parse(await readFile(PIN_PATH, "utf8"));
  await mkdir(directory, { recursive: true });
  await build({
    absWorkingDir: ROOT,
    entryPoints: [ENTRY],
    outfile: join(directory, "index.mjs"),
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node24",
    // Same publication rule as the helper bundle: reviewers read the shipped
    // artifact, so it is unminified and byte-for-byte what executes.
    minify: false,
    sourcemap: false,
    legalComments: "none",
    logLevel: "silent",
    packages: "bundle",
  });
  const [manifestBytes, helperBytes] = await Promise.all([
    fetchImpl(`${pin.allowedAssetPrefix}manifest.json`),
    fetchImpl(`${pin.allowedAssetPrefix}${HELPER_FILENAME}`),
  ]);
  validateAgentHandshakeReleasePin(pin, { manifestBytes, helperBytes });
  const assetsDir = join(directory, "assets");
  await mkdir(assetsDir, { recursive: true });
  await writeFile(join(assetsDir, "manifest.json"), manifestBytes, { mode: 0o644 });
  await writeFile(join(assetsDir, HELPER_FILENAME), helperBytes, { mode: 0o644 });
  await writeFile(join(assetsDir, "pin.json"), `${JSON.stringify(pin, null, 2)}\n`, { mode: 0o644 });
  await writeFile(join(directory, "package.json"), `${JSON.stringify({
    name: "@d4d.group/local-adapter",
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    description: "Pre-installed local executor for Clockchain agent-handshake localActions: proxies the hosted handshake tools and runs each staged digest-bound helper step through the pinned local helper — no runtime download, no eval of remote bytes.",
    license: "Apache-2.0",
    author: "D4D Group",
    type: "module",
    bin: { "clockchain-local-adapter": "index.mjs" },
    engines: { node: `>=${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}` },
    files: ["index.mjs", "assets", "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES"],
  }, null, 2)}\n`, { mode: 0o644 });
  for (const legalFile of LEGAL_FILES) {
    try {
      await copyFile(join(PACKAGING_DIR, legalFile), join(directory, legalFile));
    } catch {
      invalid();
    }
  }
  return Object.freeze({ outDir: directory, version: AGENT_HANDSHAKE_HELPER_VERSION });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  buildLocalAdapterNpm({ outDir: process.argv[2] }).then(
    (value) => process.stdout.write(`${JSON.stringify({ ok: true, version: value.version })}\n`),
    () => {
      process.stderr.write(`${JSON.stringify({ error: "LOCAL_ADAPTER_NPM_BUILD_FAILED" })}\n`);
      process.exitCode = 1;
    },
  );
}
