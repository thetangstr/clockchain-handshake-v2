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
    error: {
      code: "AGENT_HANDSHAKE_FAILED",
      diagnosticCode: "AGENT_HANDSHAKE_INTERNAL_FAILURE",
      message: "Agent handshake operation failed safely.",
    },
  });
  for (const output of [initialized.stdout, initialized.stderr, failed.stdout, failed.stderr]) {
    assert.equal(output.includes(stateDir), false);
    assert.equal(output.includes("secret"), false);
    assert.equal(output.toLowerCase().includes("privatekey"), false);
    assert.equal(output.toLowerCase().includes("roleaccess"), false);
  }
});

test("CLI error projection retains only an allowlisted registration failure class", async () => {
  const { agentHandshakeCliSafeError } = await import("../src/agent-cli/main.mjs");
  const privateCanary = "private-registration-detail-must-not-escape";
  const classified = new Error(`Registration failed: ${privateCanary}`);
  classified.diagnosticCode = "AGENT_HANDSHAKE_REGISTER_NETWORK";
  assert.deepEqual(agentHandshakeCliSafeError(classified), {
    error: {
      code: "AGENT_HANDSHAKE_FAILED",
      diagnosticCode: "AGENT_HANDSHAKE_REGISTER_NETWORK",
      message: "Agent handshake operation failed safely.",
    },
  });
  assert.equal(JSON.stringify(agentHandshakeCliSafeError(classified)).includes(privateCanary), false);
  for (const diagnosticCode of [
    "secret-value",
    "AGENT_HANDSHAKE_REGISTER_NETWORK_EXTRA",
    "AGENT_HANDSHAKE_SIGN_INTERNAL_FAILURE",
  ]) {
    const rejected = new Error(privateCanary);
    rejected.diagnosticCode = diagnosticCode;
    assert.deepEqual(agentHandshakeCliSafeError(rejected), {
      error: {
        code: "AGENT_HANDSHAKE_FAILED",
        diagnosticCode: "AGENT_HANDSHAKE_INTERNAL_FAILURE",
        message: "Agent handshake operation failed safely.",
      },
    });
  }
});

test("real CLI exposes an exact public version check without creating local state", async () => {
  const result = await run(["--version"]);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    schema: "clockchain.agent-handshake-cli-version/v1",
    version: "2.1.3",
  });
});
