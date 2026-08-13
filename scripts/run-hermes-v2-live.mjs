#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";

import { runHermesV2ProductionGate } from "../src/testing/hermes-v2-orchestrator.mjs";

async function providerSecret() {
  if (typeof process.env.KIMI_API_KEY === "string" && process.env.KIMI_API_KEY.length > 0) return process.env.KIMI_API_KEY;
  const text = await readFile("/Users/Kailor/.hermes/.env", "utf8");
  const found = text.split(/\r?\n/).find((line) => line.startsWith("KIMI_API_KEY="));
  if (!found) throw new Error("Hermes production gate failed safely.");
  return found.slice("KIMI_API_KEY=".length);
}

try {
  const result = await runHermesV2ProductionGate({
    parent: "/private/tmp/clockchain-hermes-v2-runs",
    providerSecret: await providerSecret(),
  });
  const record = { event: "production_gate_complete", ...result };
  await writeFile("/private/tmp/clockchain-hermes-v2-last-result.json", `${JSON.stringify(record)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify(record)}\n`);
} catch (error) {
  const code = typeof error?.code === "string" && /^[A-Z0-9_]+$/.test(error.code) ? error.code : "HERMES_V2_LIVE_FAILED";
  const tool = typeof error?.tool === "string" && [
    "agent_handshake_invite", "agent_handshake_accept_invitation", "agent_handshake_join",
    "agent_handshake_status", "agent_handshake_next", "agent_handshake_submit_checkpoint",
    "agent_handshake_submit", "agent_handshake_get_certificate",
  ].includes(error.tool) ? error.tool : undefined;
  const record = { event: "production_gate_failed", code, ...(tool === undefined ? {} : { tool }) };
  await writeFile("/private/tmp/clockchain-hermes-v2-last-result.json", `${JSON.stringify(record)}\n`, { mode: 0o600 });
  process.stderr.write(`${JSON.stringify(record)}\n`);
  process.exitCode = 1;
}
