#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import { runAgentHandshakeHostSession } from "../src/agent-handshake/host.mjs";

export async function main() {
  const adapterUrl = process.env.AGENT_HANDSHAKE_HOST_ADAPTER;
  const useV2 = process.env.AGENT_HANDSHAKE_PROTOCOL === "clockchain.agent-handshake/v2";
  const adapter = typeof adapterUrl === "string" && adapterUrl.length > 0
    ? await import(adapterUrl)
    : useV2
      ? await import("../src/agent-handshake/v2/production-adapter.mjs")
      : await import("../src/agent-handshake/production-adapter.mjs");
  const loadName = useV2 ? "loadAgentHandshakeV2Session" : "loadAgentHandshakeSession";
  const portsName = useV2 ? "createAgentHandshakeV2HostPorts" : "createAgentHandshakeHostPorts";
  if (
    typeof adapter[portsName] !== "function" ||
    typeof adapter[loadName] !== "function"
  ) {
    throw new Error("Generic host adapter has the wrong interface.");
  }
  const session = await adapter[loadName]();
  const ports = await adapter[portsName](session);
  if (useV2) {
    const { runAgentHandshakeV2HostSession } = await import(
      "../src/agent-handshake/v2/host.mjs"
    );
    return runAgentHandshakeV2HostSession({ ports, session });
  }
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
