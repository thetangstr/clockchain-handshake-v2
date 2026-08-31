import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";

import { runDirectAgentSignerCli } from "../src/direct-agent-signer/main.mjs";
import { localPolicyDigest } from "../src/agent-handshake/v2/policy.mjs";
import { buildAgentCliFixture } from "./support/agent-cli-fixture.mjs";

const execFileAsync = promisify(execFile);

function encode(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

test("CLI accepts only sign with absolute state dir and one payload", async () => {
  const fixture = await buildAgentCliFixture();
  const stateDir = "/tmp/clockchain-direct-agent-signer-test";
  const request = { schema: "clockchain.direct-agent-signer-request/v1" };
  const result = {
    schema: "clockchain.direct-agent-signer-result/v1",
    adapterVersion: "1.0.0",
    address: fixture.parties.initiator.sessionKeyAddress,
    bytesSha256: fixture.request.bytesSha256,
    purpose: "agent_contract_direct_signature",
    role: "initiator",
    sessionId: fixture.request.sessionId,
    signatureHex: "0x" + "2".repeat(130),
  };
  const calls = [];
  const operations = {
    names: ["sign"],
    dispatch: async (input) => {
      calls.push(input);
      return result;
    },
  };

  assert.deepEqual(await runDirectAgentSignerCli(["--version"], { operations }), {
    schema: "clockchain.direct-agent-signer-cli-version/v1",
    version: "1.0.0",
  });
  assert.deepEqual(await runDirectAgentSignerCli([
    "sign", "--state-dir", stateDir, "--payload-base64url", encode(request),
  ], { operations }), result);
  assert.deepEqual(calls, [{ operation: "sign", stateDir, payload: request }]);

  await assert.rejects(() => runDirectAgentSignerCli(["inspect", "--state-dir", stateDir], { operations }));
  await assert.rejects(() => runDirectAgentSignerCli(["sign", "--state-dir", "relative", "--payload-base64url", encode(request)], { operations }));
  await assert.rejects(() => runDirectAgentSignerCli(["sign", "--state-dir", stateDir], { operations }));
  await assert.rejects(() => runDirectAgentSignerCli(["sign", "--state-dir", stateDir, "--payload-base64url", encode(request), "--extra", "x"], { operations }));
  await assert.rejects(() => runDirectAgentSignerCli([
    "sign", "--state-dir", stateDir, "--payload-base64url", encode(request),
  ], {
    operations: {
      names: ["sign"],
      dispatch: async () => ({ ...result, adapterVersion: "1.0.1" }),
    },
  }));

  assert.equal(localPolicyDigest(fixture.policy), fixture.parties.initiator.policyDigest);
});

test("binary emits sanitized JSON version output and failure output", async () => {
  const { stdout } = await execFileAsync(process.execPath, [
    "bin/clockchain-direct-agent-signer.mjs",
    "--version",
  ]);
  assert.deepEqual(JSON.parse(stdout), {
    schema: "clockchain.direct-agent-signer-cli-version/v1",
    version: "1.0.0",
  });

  await assert.rejects(() => execFileAsync(process.execPath, [
    "bin/clockchain-direct-agent-signer.mjs",
    "sign",
  ]), (error) => {
    assert.deepEqual(JSON.parse(error.stderr), {
      error: {
        code: "DIRECT_AGENT_SIGNER_FAILED",
        message: "Direct agent signer failed safely.",
      },
    });
    return true;
  });
});
