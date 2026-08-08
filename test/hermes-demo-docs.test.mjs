import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const DOC = new URL("../docs/hermes-turnkey-demo.md", import.meta.url);

test("turnkey guide documents one Mac-mini launch path and every public boundary", async () => {
  const text = await readFile(DOC, "utf8");

  assert.match(text, /npm run demo:hermes\n/);
  assert.match(text, /single launch command/i);
  assert.match(text, /authenticated Mac-mini account.*SSH/is);
  assert.match(text, /presenter and relay board have no launch or signing authority/i);
  assert.match(text, /Mac mini launches the agents; it is not a Handshake party/i);
  assert.match(text, /Clockchain is the host, funder, and independent checker/i);
  assert.match(text, /paymentMoved:false/);
});

test("turnkey guide records canonical MCP, token, relay, and presenter endpoints", async () => {
  const text = await readFile(DOC, "utf8");

  for (const endpoint of [
    "https://mcp.clockchain.network/health",
    "https://mcp.clockchain.network/token",
    "https://mcp.clockchain.network/mcp",
    "https://mcp-aws.clockchain.network/health",
    "http://44.249.47.220:8080/healthz",
    "http://44.249.47.220:8080/v1/discovery/current",
    "http://44.249.47.220:8080/monitor/current",
    "https://clockchain-research.vercel.app/handshake/claude-v6",
  ]) {
    assert.ok(text.includes(endpoint), `missing endpoint ${endpoint}`);
  }

  for (const tool of [
    "handshake_status",
    "handshake_join",
    "handshake_next",
    "handshake_submit",
    "handshake_get_certificate",
  ]) {
    assert.ok(text.includes(tool), `missing tool ${tool}`);
  }
});

test("turnkey guide defines freshness, evidence, cleanup, and rollback without legacy profiles or secrets", async () => {
  const text = await readFile(DOC, "utf8");

  assert.match(text, /no inherited sessions, messages, contacts, memories, skills/i);
  assert.match(text, /pre-provision manifest/i);
  assert.match(text, /\/Users\/maxiaoer\/\.clockchain\/hermes-demo\/runs\/<run-id>\/evidence/);
  assert.match(text, /--dry-run/);
  assert.match(text, /mints no MCP tokens/i);
  assert.match(text, /removes both disposable role roots after every success or\s+failure/i);
  assert.match(text, /Application rollback is the previous pushed Handshake commit/i);
  assert.match(text, /single-validator testnet/i);

  for (const banned of [
    "handshake_payer",
    "handshake_requester",
    "handshake_requestor",
    "BEGIN PRIVATE KEY",
    "KIMI_API_KEY=",
    "cc_ey",
  ]) {
    assert.ok(!text.includes(banned), `guide contains banned material: ${banned}`);
  }
});
