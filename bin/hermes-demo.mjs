#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  HERMES_DEMO_CANONICAL_KIT_URL,
  HERMES_DEMO_DEFAULT_RELAY_URL,
  runHermesDemo,
} from "../src/core/hermes-launcher.mjs";

const execFile = promisify(execFileCallback);
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const BRANCH_PATTERN = /^[A-Za-z0-9._/-]{1,200}$/;
const DEFAULT_CREDENTIAL_FILE = "/Users/maxiaoer/.clockchain/hermes-demo/minimax-cn.key";

function usage() {
  return [
    "Usage: node bin/hermes-demo.mjs [--kit-commit <40-hex>] [--inference-key-file <abs>] [--dry-run]",
    "",
    `Defaults: kit ${HERMES_DEMO_CANONICAL_KIT_URL}; relay ${HERMES_DEMO_DEFAULT_RELAY_URL}; run root under CLOCKCHAIN_HERMES_DEMO_ROOT or the Mac operator directory; MiniMax China key file ${DEFAULT_CREDENTIAL_FILE} (0600).`,
    "",
    "--keep-cleanrooms is rejected by this production wrapper. Use the core localDebug API for local tests only.",
  ].join("\n");
}

async function currentPushedCommit({ commandRunner = execFile } = {}) {
  const status = await commandRunner("git", ["status", "--porcelain=v1"], {
    encoding: "utf8",
    maxBuffer: 32_768,
  });
  if (status.stdout.trim() !== "") throw new Error("dirty worktree");
  const branchResult = await commandRunner("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
    encoding: "utf8",
    maxBuffer: 4_096,
  });
  const branch = branchResult.stdout.trim();
  if (branch === "HEAD" || !BRANCH_PATTERN.test(branch) || branch.includes("..")) throw new Error("unsafe branch");
  const { stdout } = await commandRunner("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
    maxBuffer: 4_096,
  });
  const commit = stdout.trim();
  if (!COMMIT_PATTERN.test(commit)) throw new Error("unsafe commit");
  const remote = await commandRunner("git", ["ls-remote", "origin", `refs/heads/${branch}`], {
    encoding: "utf8",
    maxBuffer: 32_768,
  });
  if (remote.stdout.trim() !== `${commit}\trefs/heads/${branch}`) throw new Error("unpushed commit");
  return commit;
}

function readValue(argv, index) {
  const value = argv[index + 1];
  if (typeof value !== "string" || value.length === 0 || value.startsWith("--")) {
    throw new Error("missing argument value");
  }
  return value;
}

async function parseArgs(argv, helpers = {}) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--run-root") {
      options.runRoot = resolve(readValue(argv, index));
      index += 1;
    } else if (arg === "--kit-commit") {
      options.kitCommit = readValue(argv, index);
      if (!COMMIT_PATTERN.test(options.kitCommit)) throw new Error("unsafe commit");
      index += 1;
    } else if (arg === "--inference-key-file") {
      options.credentialFile = resolve(readValue(argv, index));
      index += 1;
    } else if (arg === "--timeout-ms") {
      options.timeoutMs = Number(readValue(argv, index));
      if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1) throw new Error("unsafe timeout");
      index += 1;
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
  options.credentialFile ??= DEFAULT_CREDENTIAL_FILE;
  if (options.help !== true) options.kitCommit ??= await currentPushedCommit(helpers);
  return options;
}

async function main(argv) {
  try {
    const options = await parseArgs(argv);
    if (options.help) {
      console.log(usage());
      return 0;
    }
    const result = await runHermesDemo(options);
    console.log(JSON.stringify(result));
    return 0;
  } catch {
    console.error("Hermes demo failed safely.");
    return 1;
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv.slice(2)));
}

export { currentPushedCommit, parseArgs };
