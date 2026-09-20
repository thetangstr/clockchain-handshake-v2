#!/usr/bin/env node
// clockchain-local-adapter stdio entry. Resolves the pinned release assets
// once at startup — the install-time gate: any byte that fails the pin chain
// exits 86 before a single JSON-RPC message is served.
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { AGENT_HANDSHAKE_HELPER_NODE_MAJOR } from "../src/agent-handshake/v2/constants.mjs";
import { startLocalAdapterStdio } from "../src/local-adapter/server.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));

function resolveAssetPaths() {
  const envDir = process.env.CLOCKCHAIN_LOCAL_ADAPTER_ASSETS;
  if (typeof envDir === "string" && envDir.length > 0) return { assetDir: envDir };
  // Installed npm layout: index.mjs sits at the package root beside assets/.
  for (const candidate of [join(scriptDir, "assets"), join(scriptDir, "..", "assets")]) {
    if (existsSync(join(candidate, "pin.json"))) return { assetDir: candidate };
  }
  // Repo development layout: the pin lives under release/, and the manifest +
  // helper are the locally built dist/ artifacts.
  return {
    assetDir: join(scriptDir, ".."),
    pinPath: join(scriptDir, "..", "release", "agent-handshake", "pin.json"),
    manifestPath: join(scriptDir, "..", "dist", "manifest.json"),
    helperPath: join(scriptDir, "..", "dist", "clockchain-agent-handshake.cjs"),
  };
}

if (!new RegExp(`^${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}\\.`).test(process.versions.node)) {
  process.stderr.write(
    `${JSON.stringify({ warning: `clockchain-local-adapter requires Node ${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}.x; the pinned helper will refuse under ${process.versions.node}` })}\n`,
  );
}

try {
  startLocalAdapterStdio(resolveAssetPaths());
} catch {
  process.stderr.write(`${JSON.stringify({ error: "ADAPTER_ASSET_VERIFICATION_FAILED" })}\n`);
  process.exit(86);
}
