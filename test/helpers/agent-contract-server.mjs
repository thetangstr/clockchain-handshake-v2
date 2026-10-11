// Loads the REAL agent-contract server code (clockchain-developer-tools
// packages/mcp-server/src/agent-contract) for cross-checking the adapter's
// sign_agent_contract_bind output against the verifier that will consume it.
// The server is TypeScript in another repository, so it is bundled on the
// fly with this repo's esbuild into a temp dir — nothing is installed and no
// network is touched. Returns null when the source tree is not present.
//
// Location: CLOCKCHAIN_AGENT_CONTRACT_SRC, else the sibling checkout next to
// this repo (or next to the repo that owns this worktree).

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { build } from "esbuild";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const RELATIVE = join("clockchain-developer-tools", "packages", "mcp-server", "src", "agent-contract");

export function agentContractSourceDir() {
  const candidates = [
    process.env.CLOCKCHAIN_AGENT_CONTRACT_SRC,
    join(ROOT, "..", RELATIVE),
    join(ROOT, "..", "..", RELATIVE),
  ].filter((value) => typeof value === "string" && value.length > 0);
  for (const candidate of candidates) {
    const dir = resolve(candidate);
    if (existsSync(join(dir, "service.ts")) && existsSync(join(dir, "canonical.ts"))) return dir;
  }
  return null;
}

function sourceCommit(dir) {
  try {
    const head = execFileSync("git", ["-C", dir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    const dirty = execFileSync("git", ["-C", dir, "status", "--porcelain", "--", "."], { encoding: "utf8" }).trim();
    return dirty.length === 0 ? head : `${head}+dirty`;
  } catch {
    return "unknown";
  }
}

let cached;

export async function loadAgentContractServer() {
  if (cached !== undefined) return cached;
  const dir = agentContractSourceDir();
  if (dir === null) {
    cached = null;
    return cached;
  }
  const out = await mkdtemp(join(tmpdir(), "agent-contract-server-"));
  const outfile = join(out, "agent-contract-server.mjs");
  await build({
    stdin: {
      contents: [
        `export { createContractService } from ${JSON.stringify(join(dir, "service.ts"))};`,
        `export { canonicalJson, canonicalDigest } from ${JSON.stringify(join(dir, "canonical.ts"))};`,
        `export * from ${JSON.stringify(join(dir, "eip191.ts"))};`,
      ].join("\n"),
      resolveDir: dir,
      loader: "ts",
    },
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node24",
    outfile,
    logLevel: "silent",
  });
  cached = Object.freeze({
    ...(await import(pathToFileURL(outfile).href)),
    sourceDir: dir,
    sourceCommit: sourceCommit(dir),
  });
  return cached;
}
