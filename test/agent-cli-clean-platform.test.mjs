import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  auditAgentHandshakeBundle,
  buildAgentHandshakeBundle,
} from "../scripts/build-agent-handshake-release.mjs";
import { VERIFIED_HELPER_BOOTSTRAP } from "../src/testing/fresh-agent-client.mjs";

const execFileAsync = promisify(execFile);

test("one audited bundle executes init without a repository, package tree, Node modules, or global Clockchain install", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-agent-bundle-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const outfile = join(directory, "clockchain-agent-handshake.cjs");
  const metafile = await buildAgentHandshakeBundle({ outfile });
  const audit = auditAgentHandshakeBundle(metafile);
  assert.equal(audit.entryPoints, 1);
  assert.equal(audit.dynamicImports, 0);
  assert.deepEqual(audit.externalImports, []);
  assert.ok(audit.inputs.some((input) => input.includes("node_modules/viem/")));
  const stateDir = join(directory, "fresh-state");
  const { stdout, stderr } = await execFileAsync(process.execPath, [outfile, "init", "--state-dir", stateDir], {
    cwd: directory,
    env: { PATH: process.env.PATH ?? "" },
  });
  assert.equal(stderr, "");
  assert.equal(JSON.parse(stdout).operation, "init");
  const bundle = await readFile(outfile, "utf8");
  assert.equal(bundle.includes("node_modules/viem"), false);
  assert.equal(bundle.includes("import("), false);
});

test("verified bootstrap hashes the manifest and exact helper bytes before every in-memory execution", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-agent-verified-bundle-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const helperPath = join(directory, "clockchain-agent-handshake.cjs");
  const manifestPath = join(directory, "manifest.json");
  await buildAgentHandshakeBundle({ outfile: helperPath });
  const helperBytes = await readFile(helperPath);
  const manifestBytes = Buffer.from(JSON.stringify({
    schema: "clockchain.agent-handshake-release-manifest/v1",
    version: "2.1.1",
    sourceCommit: "a".repeat(40),
    nodeRuntime: "24.19.0",
    assets: [{
      filename: "clockchain-agent-handshake.cjs",
      url: "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.1/clockchain-agent-handshake.cjs",
      sha256: createHash("sha256").update(helperBytes).digest("hex"),
    }],
  }));
  await writeFile(manifestPath, manifestBytes);
  const manifestDigest = createHash("sha256").update(manifestBytes).digest("hex");
  const stateDir = join(directory, "verified-state");
  const verified = await execFileAsync(process.execPath, ["--input-type=commonjs", "--eval", VERIFIED_HELPER_BOOTSTRAP, manifestDigest, manifestPath, helperPath, "init", "--state-dir", stateDir], { cwd: directory });
  assert.equal(JSON.parse(verified.stdout).operation, "init");
  await writeFile(helperPath, Buffer.concat([helperBytes, Buffer.from("\n// tampered")]))
  await assert.rejects(() => execFileAsync(process.execPath, ["--input-type=commonjs", "--eval", VERIFIED_HELPER_BOOTSTRAP, manifestDigest, manifestPath, helperPath, "inspect", "--state-dir", stateDir], { cwd: directory }));
});

test("npm developer fallback executes the same public CLI entry point", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-agent-npm-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const packageDir = join(directory, "package");
  const buildScript = new URL("../scripts/build-agent-handshake-npm.mjs", import.meta.url).pathname;
  const built = await execFileAsync(process.execPath, [buildScript, packageDir], { cwd: directory });
  assert.equal(JSON.parse(built.stdout).version, "2.1.1");
  const packageJson = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));
  assert.deepEqual(packageJson.bin, { "clockchain-agent-handshake": "index.cjs" });
  const stateDir = join(directory, "npm-state");
  const executed = await execFileAsync(process.execPath, [join(packageDir, "index.cjs"), "init", "--state-dir", stateDir], { cwd: directory });
  assert.equal(JSON.parse(executed.stdout).operation, "init");
  assert.equal(executed.stderr, "");
});
