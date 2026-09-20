#!/usr/bin/env node
// Builds self-contained single-file binaries of clockchain-local-adapter via
// `bun build --compile`, on top of the same verified npm bundle the
// build-local-adapter-npm script produces — so the pin chain (pin.json →
// manifest.json → helper bytes) is validated before anything is compiled.
//
// Layout: dist/bin-local-adapter/ holds one binary per target plus a shared
// assets/ directory. At startup the adapter resolves assets/ beside the
// executable (the dirname(process.execPath) candidate in the stdio entry),
// so shipping the directory alongside the binaries is enough — no env var
// required.
//
// Caveat: the pinned helper still needs a real Node >=24 at execution time.
// Under Node the adapter spawns process.execPath; inside a compiled binary
// that path is the binary itself, so set CLOCKCHAIN_LOCAL_ADAPTER_NODE to a
// Node 24+ executable for authorize_local_action to run the helper.
// Proxying (initialize/tools/list/tools/call staging) works without it.
import { execFile } from "node:child_process";
import { cp, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { buildLocalAdapterNpm } from "./build-local-adapter-npm.mjs";

const execFileAsync = promisify(execFile);

const BUN = process.env.BUN_BIN ?? `${process.env.HOME}/.bun/bin/bun`;
const BIN_NAME = "clockchain-local-adapter";

function invalid() { throw new Error("Local adapter binary build failed."); }

// bun --compile targets: omit --target to compile for the host. Named targets
// (bun-darwin-arm64, bun-darwin-x64, bun-linux-x64, bun-windows-x64, …) are
// passed straight through.
export async function buildLocalAdapterBinaries({
  npmOutDir = "dist/npm-local-adapter",
  outDir = "dist/bin-local-adapter",
  targets = [null],
  bun = BUN,
  fetchImpl,
} = {}) {
  const built = await buildLocalAdapterNpm({ outDir: npmOutDir, fetchImpl });
  const entry = join(built.outDir, "index.mjs");
  const directory = resolve(outDir);
  await mkdir(directory, { recursive: true });
  const outputs = [];
  for (const target of targets) {
    const suffix = target === null ? hostSuffix() : target.replace(/^bun-/, "");
    const outfile = join(directory, `${BIN_NAME}-${suffix}`);
    const args = ["build", "--compile", entry, "--outfile", outfile];
    if (target !== null) args.push(`--target=${target}`);
    const { stderr } = await execFileAsync(bun, args, { encoding: "utf8" });
    if (typeof stderr !== "string") invalid();
    outputs.push(outfile);
  }
  // One shared assets/ beside every binary in the directory.
  await cp(join(built.outDir, "assets"), join(directory, "assets"), { recursive: true });
  return Object.freeze({ outDir: directory, outputs, version: built.version });
}

function hostSuffix() {
  const platform = { darwin: "darwin", linux: "linux", win32: "windows" }[process.platform];
  const arch = { arm64: "arm64", x64: "x64" }[process.arch];
  if (platform === undefined || arch === undefined) invalid();
  return `${platform}-${arch}`;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const targets = process.argv.slice(2);
  buildLocalAdapterBinaries({ targets: targets.length > 0 ? targets : undefined }).then(
    (value) => process.stdout.write(`${JSON.stringify({ ok: true, version: value.version, outputs: value.outputs })}\n`),
    (error) => {
      process.stderr.write(`${JSON.stringify({ error: "LOCAL_ADAPTER_BINARY_BUILD_FAILED", detail: String(error?.message ?? error) })}\n`);
      process.exitCode = 1;
    },
  );
}
