import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";

const cli = new URL("../bin/clockchain-handshake.mjs", import.meta.url);
const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async function runCli(args, input) {
  const result = await runCliRaw(args, input);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

async function runCliRaw(args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli.pathname, ...args], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    if (input === undefined) {
      child.stdin.end();
    } else if (typeof input === "string") {
      child.stdin.end(input);
    } else {
      child.stdin.end(`${JSON.stringify(input)}\n`);
    }
  });
}

async function runCliRejects(args, input) {
  const result = await runCliRaw(args, input);
  assert.notEqual(result.code, 0);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

function assertFixtureMode(output) {
  assert.equal(output.verificationMode, "explicit_fixture_only");
  assert.equal(output.clockchainTrustVerified, false);
  assert.equal(output.externalBusinessActionPerformed, false);
}

test("CLI prints JSON contract discovery without stdin or side effects", async () => {
  const output = await runCli(["contract"]);
  assert.equal(output.ok, true);
  assert.equal(output.command, "contract");
  assertFixtureMode(output);
  assert.equal(output.result.protocolVersion, "3.0");
  assert.equal(output.result.tools.includes("agent_handshake_session_submit"), true);
});

test("CLI help is JSON and states fixture verification does not establish Clockchain trust", async () => {
  const output = await runCli(["help"]);
  const flagOutput = await runCli(["--help"]);

  assert.equal(output.ok, true);
  assertFixtureMode(output);
  assert.equal(output.result.commands.includes("verify-result-fixture"), true);
  assert.equal(output.result.commands.includes("verify-result"), false);
  assert.match(output.result.trustBoundary, /fixture verification commands do not establish Clockchain trust/i);
  assert.deepEqual(flagOutput.result.commands, output.result.commands);
});

test("CLI validates tool input/result JSON from stdin", async () => {
  const validInput = await runCli(["validate-tool-input", "agent_handshake_session_get_result"], {
    sessionId: "sess_cli_0123456789",
  });
  assert.equal(validInput.ok, true);
  assertFixtureMode(validInput);
  assert.equal(validInput.result.tool, "agent_handshake_session_get_result");

  const validResult = await runCli(["validate-tool-result", "agent_handshake_session_cancel"], {
    sessionId: "sess_cli_0123456789",
    state: "CANCELLED",
  });
  assert.equal(validResult.ok, true);
  assertFixtureMode(validResult);
  assert.equal(validResult.result.state, "CANCELLED");

  const invalid = await runCliRejects(["validate-tool-input", "agent_handshake_session_get_result"], {
    sessionId: "sess_cli_0123456789",
    payload: "business content",
  });
  assert.equal(invalid.ok, false);
  assert.equal(invalid.error.code, "SCHEMA_INVALID");
});

test("CLI prepares signing request JSON but does not sign", async () => {
  const output = await runCli(["prepare-signing"], {
    signingRequestId: "signreq_cli_0123456789",
    actionType: "ACCEPTANCE",
    sessionId: "sess_cli_0123456789",
    stateVersion: 2,
    role: "RESPONDER",
    policyDigest: digestA,
    statementDigest: digestB,
    nonce: "nonce_cli_0123456789",
    issuedAt: "2026-08-29T20:00:00Z",
    expiresAt: "2026-08-29T20:05:00Z",
  });

  assert.equal(output.ok, true);
  assertFixtureMode(output);
  assert.equal(output.result.request.actionType, "ACCEPTANCE");
  assert.equal(output.result.externalBusinessActionPerformed, false);
  assert.equal(output.result.signature, undefined);
  assert.equal(output.result.privateKey, undefined);
});

test("CLI ambiguous legacy verification commands are unknown", async () => {
  const resultOutput = await runCliRejects(["verify-result"], {
    certificate: {},
    continuation: {},
    now: "2026-08-29T20:01:00Z",
  });
  const certificateOutput = await runCliRejects(["verify-certificate"], {
    certificate: {},
    now: "2026-08-29T20:01:00Z",
  });

  assert.equal(resultOutput.error.code, "SCHEMA_INVALID");
  assert.equal(certificateOutput.error.code, "SCHEMA_INVALID");
});

test("CLI fixture verification refuses to run without explicit trust and replay fixtures", async () => {
  const output = await runCliRejects(["verify-result-fixture"], {
    certificate: {},
    continuation: {},
    now: "2026-08-29T20:01:00Z",
  });

  assert.equal(output.ok, false);
  assert.equal(output.error.code, "RESULT_VERIFICATION_FAILED");
});

test("CLI rejects unknown commands as JSON without stderr noise", async () => {
  const output = await runCliRejects(["serve"]);
  assert.equal(output.ok, false);
  assert.equal(output.error.code, "SCHEMA_INVALID");
  assert.equal(output.externalBusinessActionPerformed, false);
});

test("CLI rejects malformed stdin as JSON without stderr noise", async () => {
  const result = await runCliRaw(["prepare-signing"], "{not-json");
  assert.notEqual(result.code, 0);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.equal(output.error.code, "SCHEMA_INVALID");
  assert.equal(output.externalBusinessActionPerformed, false);
});
