import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const ROOT = new URL("..", import.meta.url);
const DISCOVERY_CURRENT = "http://44.249.47.220:8080/v1/discovery/current";

async function doc(path) {
  return readFile(join(ROOT.pathname, path), "utf8");
}

test("RUNBOOK describes the already-running AWS host and one public discovery URL", async () => {
  const text = await doc("docs/RUNBOOK.md");

  assert.match(text, /already-running AWS host/i);
  assert.match(text, new RegExp(DISCOVERY_CURRENT.replace(/[.]/g, "\\.")));
  assert.match(text, /node bin\/payer\.mjs --discovery-url <DISCOVERY_URL>/);
  assert.match(text, /node bin\/requestor\.mjs --discovery-url <DISCOVERY_URL>/);
  assert.ok(!text.includes("node bin/operator.mjs"), "pre-dry-run public runbook must not tell strangers to start the legacy operator");
  assert.ok(!text.includes("npm run demo"), "pre-dry-run public runbook must not use the legacy demo as the hosted path");
  assert.match(text, /single-validator testnet/i);
  assert.match(text, /not .*court-grade/i);
});

test("for-ken points a stranger at the hosted current invitation without session assembly", async () => {
  const text = await doc("docs/for-ken.md");

  assert.match(text, new RegExp(DISCOVERY_CURRENT.replace(/[.]/g, "\\.")));
  assert.match(text, /node bin\/requestor\.mjs --discovery-url http:\/\/44\.249\.47\.220:8080\/v1\/discovery\/current/);
  assert.ok(!text.includes("--relay-url"));
  assert.ok(!text.includes("--session"));
  assert.match(text, /single-validator testnet/i);
  assert.match(text, /not .*court-grade/i);
});

test("run-the-payer points a stranger at the hosted current invitation without private host material", async () => {
  const text = await doc("docs/run-the-payer.md");

  assert.match(text, new RegExp(DISCOVERY_CURRENT.replace(/[.]/g, "\\.")));
  assert.match(text, /node bin\/payer\.mjs --discovery-url http:\/\/44\.249\.47\.220:8080\/v1\/discovery\/current/);
  assert.ok(!text.includes("keys/"));
  assert.ok(!text.includes("npm run demo"));
  assert.ok(!text.includes("--relay-url"));
  assert.ok(!text.includes("--session"));
  assert.match(text, /single-validator testnet/i);
  assert.match(text, /not .*court-grade/i);
});
