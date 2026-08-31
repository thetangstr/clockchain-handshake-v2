#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { build } from "esbuild";

const ENTRY = new URL("../bin/clockchain-direct-agent-signer.mjs", import.meta.url).pathname;

function invalid() {
  throw new Error("Direct agent signer build failed.");
}

export async function buildDirectAgentSignerBundle({ outfile } = {}) {
  if (typeof outfile !== "string" || !resolve(outfile).startsWith(resolve(dirname(outfile)))) invalid();
  await mkdir(dirname(outfile), { recursive: true });
  const result = await build({
    absWorkingDir: new URL("..", import.meta.url).pathname,
    entryPoints: [ENTRY],
    outfile,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    metafile: true,
    minify: true,
    sourcemap: false,
    legalComments: "none",
    logLevel: "silent",
    packages: "bundle",
  });
  auditDirectAgentSignerBundle(result.metafile);
  return result.metafile;
}

export function auditDirectAgentSignerBundle(metafile) {
  if (metafile === null || typeof metafile !== "object" || Array.isArray(metafile)) invalid();
  const outputs = Object.values(metafile.outputs ?? {});
  const entryPoints = outputs.filter((output) => typeof output.entryPoint === "string").length;
  const imports = outputs.flatMap((output) => output.imports ?? []);
  const dynamicImports = imports.filter((entry) => entry.kind === "dynamic-import").length;
  const externalImports = imports
    .filter((entry) => entry.external === true && !entry.path.startsWith("node:"))
    .map((entry) => entry.path)
    .sort();
  const inputs = Object.keys(metafile.inputs ?? {});
  if (
    entryPoints !== 1 ||
    dynamicImports !== 0 ||
    externalImports.length !== 0 ||
    !inputs.some((input) => input.endsWith("bin/clockchain-direct-agent-signer.mjs")) ||
    !inputs.some((input) => input.endsWith("src/direct-agent-signer/adapter.mjs")) ||
    !inputs.some((input) => input.endsWith("src/core/wallet-bridge.mjs")) ||
    !inputs.some((input) => input.includes("node_modules/viem/"))
  ) invalid();
  return Object.freeze({
    dynamicImports,
    entryPoints,
    externalImports: Object.freeze(externalImports),
    inputs: Object.freeze(inputs),
  });
}

async function main(argv) {
  const [command, outfile] = argv;
  if (command === "bundle" && typeof outfile === "string") {
    const target = resolve(outfile);
    const metafile = await buildDirectAgentSignerBundle({ outfile: target });
    const bytes = await readFile(target);
    process.stdout.write(JSON.stringify({
      ...auditDirectAgentSignerBundle(metafile),
      artifact: target,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    }) + "\n");
    return;
  }
  invalid();
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write(JSON.stringify({ error: "DIRECT_AGENT_SIGNER_BUILD_FAILED" }) + "\n");
    process.exitCode = 1;
  });
}
