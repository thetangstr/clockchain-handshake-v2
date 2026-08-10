import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const cli = new URL("../bin/clockchain-agent-handshake.mjs", import.meta.url).pathname;

async function run(args) {
  try {
    const result = await execFileAsync(process.execPath, [cli, ...args]);
    return { code: 0, ...result };
  } catch (error) {
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

test("real CLI emits public JSON only and one generic failure", async (t) => {
  const stateDir = join(await mkdtemp(join(tmpdir(), "clockchain-agent-cli-")), "state");
  t.after(() => rm(stateDir, { force: true, recursive: true }));
  const initialized = await run(["init", "--state-dir", stateDir]);
  assert.equal(initialized.code, 0);
  const publicResult = JSON.parse(initialized.stdout);
  assert.equal(publicResult.operation, "init");
  assert.match(publicResult.address, /^0x[0-9A-Fa-f]{40}$/);
  assert.equal(initialized.stderr, "");
  const failed = await run(["shell", "--state-dir", stateDir, "--raw-invitation", "secret"]);
  assert.notEqual(failed.code, 0);
  assert.deepEqual(JSON.parse(failed.stderr), {
    error: { code: "AGENT_HANDSHAKE_FAILED", message: "Agent handshake operation failed safely." },
  });
  for (const output of [initialized.stdout, initialized.stderr, failed.stdout, failed.stderr]) {
    assert.equal(output.includes(stateDir), false);
    assert.equal(output.includes("secret"), false);
    assert.equal(output.toLowerCase().includes("privatekey"), false);
    assert.equal(output.toLowerCase().includes("roleaccess"), false);
  }
});

test("real CLI exposes an exact public version check without creating local state", async () => {
  const result = await run(["--version"]);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    schema: "clockchain.agent-handshake-cli-version/v1",
    version: "2.1.0",
  });
});
