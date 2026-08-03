#!/usr/bin/env node
// CLI wrapper for the rendezvous relay. No money moves here; the relay only
// moves bytes between the two parties, who both connect outbound to it.
import { parseArgs } from "node:util";

import { createRelayServer } from "../src/relay/server.mjs";

function usage() {
  return "Usage: relay.mjs [--host 127.0.0.1] [--port 8787] [--state ./relay-state]";
}

async function main(argv) {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        host: { type: "string", default: "127.0.0.1" },
        port: { type: "string", default: "8787" },
        state: { type: "string", default: "./relay-state" },
        help: { type: "boolean", default: false },
      },
    }));
  } catch (error) {
    process.stderr.write(`${error.message}\n${usage()}\n`);
    process.exitCode = 1;
    return;
  }

  if (values.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const port = Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    process.stderr.write(`Invalid --port: ${values.port}\n`);
    process.exitCode = 1;
    return;
  }

  const server = await createRelayServer({ stateDir: values.state });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, values.host, resolve);
  });

  const address = server.address();
  process.stdout.write(
    `Relay ready. No money moves here -- listening on http://${values.host}:${address.port}, storing session mail under ${values.state}.\n`,
  );

  const shutdown = () => {
    process.stdout.write("Relay shutting down.\n");
    server.close(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(
    `Relay failed to start: ${error?.message ?? "unknown error"}\n`,
  );
  process.exitCode = 1;
});
