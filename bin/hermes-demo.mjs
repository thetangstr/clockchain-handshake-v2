#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { promisify } from "node:util";

import {
  HERMES_DEMO_CANONICAL_KIT_URL,
  HERMES_DEMO_DEFAULT_RELAY_URL,
  runHermesDemo,
} from "../src/core/hermes-launcher.mjs";

const execFile = promisify(execFileCallback);
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;

function usage() {
  return [
    "Usage: node bin/hermes-demo.mjs [--kit-commit <40-hex>] [--kimi-key-file <abs>] [--dry-run]",
    "",
    `Defaults: kit ${HERMES_DEMO_CANONICAL_KIT_URL}; relay ${HERMES_DEMO_DEFAULT_RELAY_URL}; run root under CLOCKCHAIN_HERMES_DEMO_ROOT or the Mac operator directory.`,
    "",
    "--keep-cleanrooms is rejected by this production wrapper. Use the core localDebug API for local tests only.",
  ].join("\n");
}

async function currentPushedCommit() {
  const { stdout } = await execFile("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
    maxBuffer: 4_096,
  });
  const commit = stdout.trim();
  if (!COMMIT_PATTERN.test(commit)) throw new Error("unsafe commit");
  const contains = await execFile("git", ["branch", "-r", "--contains", commit], {
    encoding: "utf8",
    maxBuffer: 32_768,
  });
  if (contains.stdout.trim() === "") throw new Error("unpushed commit");
  return commit;
}

async function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--run-root") {
      options.runRoot = resolve(argv[++index] ?? "");
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
  options.kitUrl = HERMES_DEMO_CANONICAL_KIT_URL;
  options.relayUrl = HERMES_DEMO_DEFAULT_RELAY_URL;
  options.runId ??= randomUUID();
  if (options.help !== true) options.kitCommit ??= await currentPushedCommit();
  return options;
}

try {
  const options = await parseArgs(process.argv.slice(2));
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
