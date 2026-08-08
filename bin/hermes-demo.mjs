#!/usr/bin/env node
import { resolve } from "node:path";

import { runHermesDemo } from "../src/core/hermes-launcher.mjs";

function usage() {
  return [
    "Usage: node bin/hermes-demo.mjs --run-root <abs> --kit-url <https git url> --kit-commit <40-hex> [--kimi-key-file <abs>] [--dry-run]",
    "",
    "--keep-cleanrooms is rejected by this production wrapper. Use the core localDebug API for local tests only.",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--run-root") {
      options.runRoot = resolve(argv[++index] ?? "");
    } else if (arg === "--kit-url") {
      options.kitUrl = argv[++index];
    } else if (arg === "--kit-commit") {
      options.kitCommit = argv[++index];
    } else if (arg === "--kimi-key-file") {
      options.credentialFile = resolve(argv[++index] ?? "");
    } else if (arg === "--timeout-ms") {
      options.timeoutMs = Number(argv[++index]);
    } else if (arg === "--keep-cleanrooms") {
      throw new Error("keep-cleanrooms is not available in the production wrapper");
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new Error("unknown argument");
    }
  }
  return options;
}

try {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    process.exit(0);
  }
  const result = await runHermesDemo(options);
  console.log(JSON.stringify(result));
} catch {
  console.error("Hermes demo failed safely.");
  process.exit(1);
}
