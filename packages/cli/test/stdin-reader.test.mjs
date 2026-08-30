import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  HANDSHAKE_CLI_STDIN_IDLE_TIMEOUT_MS,
  HANDSHAKE_CLI_STDIN_MAX_BYTES,
  readHandshakeCliJsonInput,
} from "../src/stdin.mjs";

const cli = new URL("../bin/clockchain-handshake.mjs", import.meta.url);

function openJsonStream(text) {
  const stream = new PassThrough();
  stream.write(text);
  return stream;
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
    child.stdin.end(input);
  });
}

test("stdin reader exports documented finite bounds", () => {
  assert.equal(HANDSHAKE_CLI_STDIN_MAX_BYTES, 1024 * 1024);
  assert.equal(HANDSHAKE_CLI_STDIN_IDLE_TIMEOUT_MS, 5000);
});

test("stdin reader fails closed for oversized JSON before parsing", async () => {
  const stream = openJsonStream(`{"padding":"${"x".repeat(65)}"}`);
  await assert.rejects(() => readHandshakeCliJsonInput(stream, { maxBytes: 64, idleTimeoutMs: 50 }), {
    code: "SCHEMA_INVALID",
  });
  stream.destroy();
});

test("stdin reader fails closed when stdin stays open after partial JSON", async () => {
  const stream = openJsonStream("{");
  await assert.rejects(() => readHandshakeCliJsonInput(stream, { maxBytes: 64, idleTimeoutMs: 10 }), {
    code: "SCHEMA_INVALID",
  });
  stream.destroy();
});

test("CLI binary returns safe JSON for oversized stdin", async () => {
  const result = await runCliRaw(["prepare-signing"], `{"padding":"${"x".repeat(HANDSHAKE_CLI_STDIN_MAX_BYTES + 1)}"}`);
  assert.notEqual(result.code, 0);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.stdout);
  assert.equal(output.ok, false);
  assert.equal(output.error.code, "SCHEMA_INVALID");
  assert.doesNotMatch(output.error.message, /padding|xxxxx|SyntaxError|RangeError/i);
});
