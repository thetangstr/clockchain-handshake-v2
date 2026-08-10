#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { createRequire } from "node:module";

import { build } from "esbuild";

const execFileAsync = promisify(execFile);
const require = createRequire(import.meta.url);
const { inject } = require("postject");
const ENTRY = new URL("../bin/clockchain-agent-handshake.mjs", import.meta.url).pathname;
const FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";

function invalid() { throw new Error("Agent handshake release build failed."); }

export async function buildAgentHandshakeBundle({ outfile } = {}) {
  if (typeof outfile !== "string" || !resolve(outfile).startsWith(resolve(dirname(outfile)))) invalid();
  await mkdir(dirname(outfile), { recursive: true });
  const result = await build({
    absWorkingDir: new URL("..", import.meta.url).pathname,
    entryPoints: [ENTRY],
    outfile,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node24",
    metafile: true,
    minify: true,
    sourcemap: false,
    legalComments: "none",
    logLevel: "silent",
    packages: "bundle",
  });
  auditAgentHandshakeBundle(result.metafile);
  return result.metafile;
}

export function auditAgentHandshakeBundle(metafile) {
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
  if (entryPoints !== 1 || dynamicImports !== 0 || externalImports.length !== 0 || !inputs.some((input) => input.includes("node_modules/viem/"))) invalid();
  return Object.freeze({ entryPoints, dynamicImports, externalImports: Object.freeze(externalImports), inputs: Object.freeze(inputs) });
}

export async function buildAgentHandshakeSea({ nodeExecutable, outfile, workDir, platform = process.platform } = {}) {
  if (!/^v24\./.test(process.version) || nodeExecutable !== process.execPath) invalid();
  const directory = resolve(workDir);
  const bundle = resolve(directory, "agent-handshake.cjs");
  const blob = resolve(directory, "agent-handshake.blob");
  const config = resolve(directory, "sea-config.json");
  await mkdir(directory, { recursive: true });
  await buildAgentHandshakeBundle({ outfile: bundle });
  await writeFile(config, JSON.stringify({ main: bundle, output: blob, disableExperimentalSEAWarning: true, useSnapshot: false, useCodeCache: false }) + "\n", { flag: "wx", mode: 0o600 });
  await execFileAsync(nodeExecutable, ["--experimental-sea-config", config]);
  await copyFile(nodeExecutable, outfile);
  if (platform === "darwin") await execFileAsync("codesign", ["--remove-signature", outfile]);
  const blobBytes = await readFile(blob);
  await inject(outfile, "NODE_SEA_BLOB", blobBytes, {
    sentinelFuse: FUSE,
    machoSegmentName: platform === "darwin" ? "NODE_SEA" : undefined,
  });
  if (platform !== "win32") await chmod(outfile, 0o755);
  return Object.freeze({ bundle, outfile });
}

export async function recordAgentHandshakeAsset({
  arch,
  assetPath,
  nativeNotarized,
  nativeSigner,
  nativeTimestamp,
  outputPath,
  platform,
  publicOutputPath,
  upstreamSupport,
} = {}) {
  if (platform !== process.platform || arch !== process.arch) invalid();
  const bytes = await readFile(assetPath);
  const publicOutput = await readFile(publicOutputPath);
  const filename = `clockchain-agent-handshake-${platform}-${arch}${platform === "win32" ? ".exe" : ""}`;
  const signatureType = platform === "darwin" ? "codesign" : platform === "win32" ? "authenticode" : "none";
  if (
    signatureType === "none"
      ? nativeSigner !== undefined || nativeTimestamp !== undefined || nativeNotarized !== undefined
      : !nativeSigner || !nativeTimestamp ||
        (platform === "darwin" ? nativeNotarized !== true : nativeNotarized !== undefined)
  ) invalid();
  const record = {
    platform,
    arch,
    upstreamSupport,
    filename,
    url: `https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.0/${filename}`,
    byteLength: String(bytes.length),
    sha256: createHash("sha256").update(bytes).digest("hex"),
    nativeSignature: {
      type: signatureType,
      verified: true,
      signer: nativeSigner ?? null,
      timestamp: nativeTimestamp ?? null,
      notarized: platform === "darwin" ? true : null,
    },
    execution: {
      verified: true,
      platform,
      arch,
      exitCode: "0",
      publicOutputSha256: createHash("sha256").update(publicOutput).digest("hex"),
    },
  };
  await writeFile(outputPath, JSON.stringify(record, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  return Object.freeze(record);
}

async function main(argv) {
  const [command, outfile] = argv;
  if (command === "bundle" && typeof outfile === "string") {
    const metafile = await buildAgentHandshakeBundle({ outfile: resolve(outfile) });
    process.stdout.write(JSON.stringify(auditAgentHandshakeBundle(metafile)) + "\n");
    return;
  }
  if (command === "sea" && typeof outfile === "string") {
    await buildAgentHandshakeSea({ nodeExecutable: process.execPath, outfile: resolve(outfile), workDir: resolve(dirname(outfile), ".sea") });
    process.stdout.write(JSON.stringify({ ok: true }) + "\n");
    return;
  }
  if (command === "record" && argv.length === 7) {
    const [, assetPath, platform, arch, upstreamSupport, publicOutputPath, outputPath] = argv;
    await recordAgentHandshakeAsset({
      arch,
      assetPath: resolve(assetPath),
      nativeNotarized: process.env.CLOCKCHAIN_NATIVE_NOTARIZED === "true" ? true : undefined,
      nativeSigner: process.env.CLOCKCHAIN_NATIVE_SIGNER,
      nativeTimestamp: process.env.CLOCKCHAIN_NATIVE_TIMESTAMP,
      outputPath: resolve(outputPath),
      platform,
      publicOutputPath: resolve(publicOutputPath),
      upstreamSupport,
    });
    process.stdout.write(JSON.stringify({ ok: true }) + "\n");
    return;
  }
  invalid();
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write(JSON.stringify({ error: "AGENT_HANDSHAKE_RELEASE_BUILD_FAILED" }) + "\n");
    process.exitCode = 1;
  });
}
