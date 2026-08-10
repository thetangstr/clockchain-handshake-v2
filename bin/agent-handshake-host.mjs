#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import { runAgentHandshakeHostSession } from "../src/agent-handshake/host.mjs";

export async function main() {
  const adapterUrl = process.env.AGENT_HANDSHAKE_HOST_ADAPTER;
  const adapter = typeof adapterUrl === "string" && adapterUrl.length > 0
    ? await import(adapterUrl)
    : await import("../src/agent-handshake/production-adapter.mjs");
  if (
    typeof adapter.createAgentHandshakeHostPorts !== "function" ||
    typeof adapter.loadAgentHandshakeSession !== "function"
  ) {
    throw new Error("Generic host adapter has the wrong interface.");
  }
  const session = await adapter.loadAgentHandshakeSession();
  const ports = await adapter.createAgentHandshakeHostPorts(session);
  return runAgentHandshakeHostSession({ ports, session });
}

if (
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    if (process.env.HANDSHAKE_DEBUG) {
      process.stderr.write(`${error?.stack ?? error}\n`);
    }
    process.stderr.write(`${JSON.stringify({ reason: error?.code ?? "FAILED", message: "Generic host stopped." })}\n`);
    process.exitCode = 1;
  });
}
