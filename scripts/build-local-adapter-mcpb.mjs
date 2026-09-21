#!/usr/bin/env node
// Builds dist/clockchain-local-adapter.mcpb: a DXT/MCPB one-click bundle for
// Claude Desktop. The .mcpb is a zip whose root holds manifest.json (the DXT
// manifest, dxt_version "0.1") and whose server/ directory carries the exact
// bytes produced by buildLocalAdapterNpm — the bundled index.mjs plus the
// pinned assets/. The npm build already validates the pin chain before
// writing, so the bundle ships only verified bytes; the adapter re-verifies
// them at startup and on every tool call regardless.
//
// server.type is "node" with mcp_config.command "node" and the DXT
// ${__dirname} placeholder so the host resolves the entry inside its
// extension install directory. The adapter requires Node >=24, declared in
// compatibility.runtimes.node.
import { execFile } from "node:child_process";
import {
  cp,
  mkdir,
  readdir,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import {
  AGENT_HANDSHAKE_HELPER_NODE_MAJOR,
  AGENT_HANDSHAKE_HELPER_VERSION,
} from "../src/agent-handshake/v2/constants.mjs";
import { buildLocalAdapterNpm } from "./build-local-adapter-npm.mjs";

const execFileAsync = promisify(execFile);

const STAGING_DIR = "dist/mcpb-local-adapter";
const OUT_FILE = "dist/clockchain-local-adapter.mcpb";
// DOS zip timestamps bottom out at 1980-01-01; pinning every entry to it (and
// passing -X to drop UID/GID extras) keeps the archive deterministic.
const ZIP_EPOCH = new Date("1980-01-01T00:00:00Z");

function invalid() { throw new Error("Local adapter mcpb build failed."); }

// Sorted, relative-path list of every directory and file under root, so zip
// writes entries in a stable order with explicit directory entries.
async function listEntries(root) {
  const entries = [];
  async function walk(dir, prefix) {
    const names = (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const name of names) {
      const rel = prefix === "" ? name.name : `${prefix}/${name.name}`;
      if (name.isDirectory()) {
        entries.push(`${rel}/`);
        await walk(join(dir, name.name), rel);
      } else if (name.isFile()) {
        entries.push(rel);
      }
    }
  }
  await walk(root, "");
  return entries;
}

function dxtManifest({ version }) {
  return {
    dxt_version: "0.1",
    name: "clockchain-local-adapter",
    display_name: "Clockchain Local Adapter",
    version,
    description:
      "Pre-installed local executor for Clockchain agent-handshake localActions: " +
      "proxies the hosted handshake tools and runs each staged digest-bound helper " +
      "step through the pinned local helper — no runtime download, no eval of " +
      "remote bytes. Private keys never leave this machine.",
    author: { name: "D4D Group" },
    license: "Apache-2.0",
    keywords: ["clockchain", "agent-handshake", "mcp", "payments", "authorization"],
    server: {
      type: "node",
      entry_point: "server/index.mjs",
      mcp_config: {
        command: "node",
        args: ["${__dirname}/server/index.mjs"],
      },
    },
    tools: [
      {
        name: "authorize_local_action",
        description:
          "Execute the next staged Clockchain local action for this role. " +
          "Takes no arguments; call once per staged step, in order.",
      },
    ],
    compatibility: {
      runtimes: { node: `>=${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}` },
    },
  };
}

export async function buildLocalAdapterMcpb({
  fetchImpl,
  npmOutDir = "dist/npm-local-adapter",
  stagingDir = STAGING_DIR,
  outFile = OUT_FILE,
} = {}) {
  const built = await buildLocalAdapterNpm({ outDir: npmOutDir, fetchImpl });
  const staging = resolve(stagingDir);
  const output = resolve(outFile);
  await rm(staging, { recursive: true, force: true });
  await rm(output, { force: true });
  // Bundle layout per the MCPB spec: manifest.json at the zip root and the
  // server payload under server/ — index.mjs plus the pinned assets/ only
  // (not package.json or any packed tarball that may sit in the npm outDir).
  await mkdir(join(staging, "server"), { recursive: true });
  await cp(join(built.outDir, "index.mjs"), join(staging, "server", "index.mjs"));
  await cp(join(built.outDir, "assets"), join(staging, "server", "assets"), { recursive: true });
  // Apache-2.0 §4: the license text must accompany redistribution of the work,
  // so the legal files ride inside the bundle next to the manifest.
  for (const legal of ["LICENSE", "NOTICE", "THIRD-PARTY-NOTICES"]) {
    await cp(join(built.outDir, legal), join(staging, legal));
  }
  await writeFile(
    join(staging, "manifest.json"),
    `${JSON.stringify(dxtManifest({ version: built.version ?? AGENT_HANDSHAKE_HELPER_VERSION }), null, 2)}\n`,
    { mode: 0o644 },
  );
  const entries = await listEntries(staging);
  if (
    !entries.includes("manifest.json") ||
    !entries.includes("server/index.mjs") ||
    !entries.includes("server/assets/pin.json")
  ) invalid();
  for (const entry of entries) {
    await utimes(join(staging, entry), ZIP_EPOCH, ZIP_EPOCH).catch(invalid);
  }
  // /usr/bin/zip (Info-ZIP 3.0) on macOS; -X excludes UID/GID/timestamp extras
  // beyond the DOS header fields. Run inside the staging dir so archive names
  // are relative paths like manifest.json and server/index.mjs.
  const { stdout, stderr } = await execFileAsync(
    "zip",
    ["-X", "-q", output, ...entries],
    { cwd: staging },
  );
  if (typeof stdout !== "string" || typeof stderr !== "string") invalid();
  return Object.freeze({ outFile: output, stagingDir: staging, version: built.version });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  buildLocalAdapterMcpb({ outFile: process.argv[2] ?? OUT_FILE }).then(
    (value) => process.stdout.write(`${JSON.stringify({ ok: true, version: value.version, outFile: value.outFile })}\n`),
    () => {
      process.stderr.write(`${JSON.stringify({ error: "LOCAL_ADAPTER_MCPB_BUILD_FAILED" })}\n`);
      process.exitCode = 1;
    },
  );
}
