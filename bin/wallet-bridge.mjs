#!/usr/bin/env node
import { parseArgs } from "node:util";

import {
  initializeWallet,
  inspectWallet,
  registerWalletIdentity,
  signExactBytes,
} from "../src/core/wallet-bridge.mjs";

const SAFE_ERROR = Object.freeze({
  error: {
    code: "WALLET_BRIDGE_FAILED",
    message: "Wallet bridge operation failed safely.",
  },
});

function emit(value, stream = process.stdout) {
  stream.write(`${JSON.stringify(value)}\n`);
}

function parseCommand(argv) {
  const [command, ...args] = argv;
  if (!["init", "inspect", "sign", "register"].includes(command)) {
    throw new Error("invalid command");
  }
  return { args, command };
}

function parseOptions(args, options) {
  const parsed = parseArgs({
    args,
    allowPositionals: false,
    strict: true,
    options,
  });
  return parsed.values;
}

function requireString(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("missing required option");
  }
  return value;
}

async function main(argv) {
  const { args, command } = parseCommand(argv);
  if (command === "init") {
    const values = parseOptions(args, {
      state: { type: "string" },
    });
    emit(await initializeWallet({ statePath: requireString(values.state) }));
    return;
  }

  if (command === "inspect") {
    const values = parseOptions(args, {
      state: { type: "string" },
    });
    emit(await inspectWallet({ statePath: requireString(values.state) }));
    return;
  }

  if (command === "sign") {
    const values = parseOptions(args, {
      bytes: { type: "string" },
      state: { type: "string" },
    });
    emit(
      await signExactBytes({
        bytesHex: requireString(values.bytes),
        statePath: requireString(values.state),
      }),
    );
    return;
  }

  const values = parseOptions(args, {
    displayName: { type: "string" },
    state: { type: "string" },
  });
  emit(
    await registerWalletIdentity({
      displayName: requireString(values.displayName),
      statePath: requireString(values.state),
    }),
  );
}

main(process.argv.slice(2)).catch(() => {
  emit(SAFE_ERROR, process.stderr);
  process.exitCode = 1;
});
