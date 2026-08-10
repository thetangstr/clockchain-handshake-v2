import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  auditAgentHandshakeBundle,
  buildAgentHandshakeBundle,
} from "../scripts/build-agent-handshake-release.mjs";

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

test("npm developer fallback executes the same public CLI entry point", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-agent-npm-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const packageDir = join(directory, "package");
  const buildScript = new URL("../scripts/build-agent-handshake-npm.mjs", import.meta.url).pathname;
  const built = await execFileAsync(process.execPath, [buildScript, packageDir], { cwd: directory });
  assert.equal(JSON.parse(built.stdout).version, "2.1.0");
  const packageJson = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));
  assert.deepEqual(packageJson.bin, { "clockchain-agent-handshake": "index.cjs" });
  const stateDir = join(directory, "npm-state");
  const executed = await execFileAsync(process.execPath, [join(packageDir, "index.cjs"), "init", "--state-dir", stateDir], { cwd: directory });
  assert.equal(JSON.parse(executed.stdout).operation, "init");
  assert.equal(executed.stderr, "");
});
