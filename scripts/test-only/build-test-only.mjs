#!/usr/bin/env node
// TEST-ONLY, NEVER SHIP (Track B B3-2, TB/LLD.md §17.4).
//
// Builds the never-ship test variant of helper 2.1.8 + adapter 2.2.0 into a
// directory OUTSIDE this repository:
//
//   node scripts/test-only/build-test-only.mjs \
//     --out <abs dir> --root-ring <abs ring.json> --endpoint https://127.0.0.1:<19400-19499>/<path>
//
// <ring.json> is the PUBLIC test host root ring (1–2 entries of
// {kid, publicKey, fingerprint, notBeforeMs, notAfterMs}); no private key is
// read. The build refuses the production root, a non-loopback endpoint, and an
// output path inside the repository (dist/ and release/ are what the release
// scripts publish). Output: pin.json, manifest.json,
// clockchain-agent-handshake.cjs and test-only-build.json; serve it with
// bin/clockchain-local-adapter-test-only.mjs.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { build } from "esbuild";

import {
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
  LOCAL_ADAPTER_VERSION,
} from "../../src/agent-handshake/v2/constants.mjs";
import { canonicalBytes } from "../../src/core/canonical.mjs";
import { VERIFIED_HELPER_BOOTSTRAP } from "../../src/harness/verified-release-action-recorder.mjs";
import {
  NEVER_SHIP_REFUSALS,
  NeverShipRefusal,
  TEST_ONLY_BUILD_SCHEMA,
  TEST_ONLY_BUILD_TAG,
  TEST_ONLY_HELPER_MARKER,
  assertLoopbackTestEndpoint,
  assertTestOnlyPin,
  isTestOnlyHelperBytes,
} from "../../src/local-adapter/never-ship-gate.mjs";
import { verifyPinnedAssetBytes } from "../../src/local-adapter/server.mjs";
import { TEST_ONLY_BUILD_RECORD, validateTestOnlyBuildRecord } from "../../src/test-only/adapter.mjs";
import { assertTestOnlyRootKeyRing } from "../../src/test-only/helper.mjs";

const execFileAsync = promisify(execFile);
const ROOT = resolve(new URL("../..", import.meta.url).pathname);
const HELPER_FILENAME = "clockchain-agent-handshake.cjs";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function refuse(code) {
  throw new NeverShipRefusal(code);
}

async function git(args) {
  const { stdout } = await execFileAsync("git", ["-C", ROOT, ...args], { encoding: "utf8" });
  return stdout;
}

async function assertOutputDir(outDir) {
  if (typeof outDir !== "string" || !isAbsolute(outDir)) refuse(NEVER_SHIP_REFUSALS.output);
  const target = resolve(outDir);
  const offset = relative(ROOT, target);
  // Never inside the repository: a test-only artifact must not sit where a
  // release script or a commit could pick it up.
  if (offset === "" || (!offset.startsWith("..") && !isAbsolute(offset))) refuse(NEVER_SHIP_REFUSALS.output);
  await mkdir(target, { recursive: true, mode: 0o700 });
  if ((await readdir(target)).length !== 0) refuse(NEVER_SHIP_REFUSALS.output);
  await chmod(target, 0o700);
  return target;
}

export async function buildTestOnlyHelperBundle({ outfile, rootKeyRing }) {
  const ring = assertTestOnlyRootKeyRing(rootKeyRing);
  const kids = ring.map((root) => root.kid).join(", ");
  const result = await build({
    absWorkingDir: ROOT,
    stdin: {
      contents: [
        `import { runTestOnlyHelperMain } from "./src/test-only/helper.mjs";`,
        `const TEST_ONLY_ROOT_KEY_RING = ${JSON.stringify(ring)};`,
        `runTestOnlyHelperMain({ rootKeyRing: TEST_ONLY_ROOT_KEY_RING });`,
      ].join("\n"),
      resolveDir: ROOT,
      sourcefile: "test-only-helper-entry.mjs",
      loader: "js",
    },
    outfile,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node24",
    metafile: true,
    minify: false,
    sourcemap: false,
    legalComments: "none",
    logLevel: "silent",
    packages: "bundle",
    banner: { js: `/* ${TEST_ONLY_HELPER_MARKER} - TEST-ONLY, NEVER SHIP (Track B B3-2). Host root ring: ${kids}. */` },
  });
  const inputs = Object.keys(result.metafile.inputs ?? {});
  if (!inputs.some((input) => input.includes("node_modules/viem/"))) refuse(NEVER_SHIP_REFUSALS.helper);
  const bytes = await readFile(outfile);
  if (!isTestOnlyHelperBytes(bytes)) refuse(NEVER_SHIP_REFUSALS.helper);
  return bytes;
}

export async function buildTestOnly({ outDir, rootKeyRing, endpoint, now = Date.now } = {}) {
  assertLoopbackTestEndpoint(endpoint);
  const ring = assertTestOnlyRootKeyRing(rootKeyRing);
  const target = await assertOutputDir(outDir);
  const helperPath = join(target, HELPER_FILENAME);
  const helperBytes = await buildTestOnlyHelperBundle({ outfile: helperPath, rootKeyRing: ring });
  await chmod(helperPath, 0o600);
  const sourceCommit = (await git(["rev-parse", "HEAD"])).trim();
  const sourceDirty = (await git(["status", "--porcelain", "--untracked-files=no"])).trim().length > 0;
  // The release manifest schema requires an execution record; this one is the
  // test helper's own --version output, run here (not on the release CI).
  const { stdout: versionOutput } = await execFileAsync(process.execPath, [helperPath, "--version"], { encoding: "utf8" });
  const manifest = {
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    sourceCommit,
    nodeRuntime: process.versions.node,
    assets: [{
      platform: "node",
      arch: "any",
      upstreamSupport: "node24_portable",
      filename: HELPER_FILENAME,
      // Structural: the 2.1.8 manifest schema and the verified bootstrap both
      // require the release URL shape. Nothing ever fetches it; this helper's
      // bytes exist only in this directory.
      url: `${AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX}${HELPER_FILENAME}`,
      byteLength: String(helperBytes.length),
      sha256: sha256(helperBytes),
      nativeSignature: { type: "none", verified: null, signer: null, timestamp: null, notarized: null },
      execution: {
        verified: true,
        platform: "linux",
        arch: "x64",
        exitCode: "0",
        publicOutputSha256: sha256(Buffer.from(versionOutput, "utf8")),
      },
    }],
  };
  const manifestBytes = canonicalBytes(manifest);
  const manifestDigest = sha256(manifestBytes);
  const pin = {
    version: AGENT_HANDSHAKE_HELPER_VERSION,
    sourceCommit,
    manifestDigest,
    allowedAssetPrefix: AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
    hostRoots: ring.map((root) => ({ kid: root.kid, fingerprint: root.fingerprint })),
  };
  assertTestOnlyPin(pin);
  // The release adapter's own install-time gate must accept these bytes.
  verifyPinnedAssetBytes({ pin, manifestBytes, helperBytes });
  const record = validateTestOnlyBuildRecord({
    schema: TEST_ONLY_BUILD_SCHEMA,
    buildTag: TEST_ONLY_BUILD_TAG,
    neverShip: true,
    shipAllowed: false,
    component: "adapter",
    adapterVersion: LOCAL_ADAPTER_VERSION,
    helperVersion: AGENT_HANDSHAKE_HELPER_VERSION,
    sourceCommit,
    sourceDirty,
    endpoint,
    hostRoots: pin.hostRoots,
    manifestDigest,
    helperSha256: sha256(helperBytes),
    builtAt: new Date(now()).toISOString(),
    notes: [
      "TEST-ONLY, NEVER SHIP. Track B offline loopback substrate (TB/LLD.md 17.4).",
      "The helper verifies host certificates against the test ring above only; it refuses to start with the production root.",
      "The adapter serves only the loopback endpoint above; the release adapter refuses this helper (never-ship-gate.mjs).",
      "manifest.json execution fields are structural (the 2.1.8 schema fixes linux/x64); publicOutputSha256 is this helper's --version output on the build host.",
    ],
  });
  await writeFile(join(target, "manifest.json"), manifestBytes, { mode: 0o600 });
  await writeFile(join(target, "pin.json"), `${JSON.stringify(pin, null, 2)}\n`, { mode: 0o600 });
  await writeFile(join(target, TEST_ONLY_BUILD_RECORD), `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  // End to end through the same verified bootstrap the adapter spawns.
  const { stdout } = await execFileAsync(process.execPath, [
    "--input-type=commonjs", "--eval", VERIFIED_HELPER_BOOTSTRAP,
    manifestDigest, join(target, "manifest.json"), helperPath, "--test-only-info",
  ], { encoding: "utf8" });
  const info = JSON.parse(stdout);
  if (info.buildTag !== TEST_ONLY_BUILD_TAG || info.marker !== TEST_ONLY_HELPER_MARKER) refuse(NEVER_SHIP_REFUSALS.helper);
  return Object.freeze({ outDir: target, record, pin, info });
}

function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!["--out", "--root-ring", "--endpoint"].includes(key) || typeof value !== "string") {
      throw new Error("usage: build-test-only.mjs --out <abs dir> --root-ring <abs ring.json> --endpoint https://127.0.0.1:<port>/<path>");
    }
    out[key.slice(2)] = value;
  }
  return out;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (typeof args["root-ring"] !== "string" || !isAbsolute(args["root-ring"])) refuse(NEVER_SHIP_REFUSALS.ring);
  const rootKeyRing = JSON.parse(await readFile(args["root-ring"], "utf8"));
  const { outDir, record } = await buildTestOnly({ outDir: args.out, rootKeyRing, endpoint: args.endpoint });
  process.stdout.write(`${JSON.stringify({ outDir, record }, null, 2)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${JSON.stringify({ error: error instanceof NeverShipRefusal ? error.code : String(error?.message ?? error) })}\n`);
    process.exitCode = error instanceof NeverShipRefusal ? 87 : 1;
  });
}
