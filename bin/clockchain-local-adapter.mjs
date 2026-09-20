#!/usr/bin/env node
// clockchain-local-adapter stdio entry. Resolves the pinned release assets
// once at startup — the install-time gate: any byte that fails the pin chain
// exits 86 before a single JSON-RPC message is served.
//
// Node-version preflight FIRST: the pinned helper requires Node >=24, and the
// gate below must execute before any module that might use newer syntax.
// Static imports are hoisted — their module bodies run ahead of this file's
// top-level code — so everything besides the two guaranteed-stable modules
// (constants.mjs, node-support.mjs) and node builtins is pulled in through a
// deferred dynamic import() that only fires after the gate passes. Keep every
// statement ahead of that import parseable on old Node: no optional-chaining
// era+ constructs beyond what ES2020 offers.
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { AGENT_HANDSHAKE_HELPER_NODE_MAJOR } from "../src/agent-handshake/v2/constants.mjs";
import {
  isSupportedNodeVersion,
  unsupportedNodeVersionMessage,
} from "../src/local-adapter/node-support.mjs";

const nodeMajor = Number.parseInt(process.versions.node, 10);
if (!isSupportedNodeVersion(nodeMajor)) {
  process.stderr.write(`${unsupportedNodeVersionMessage(process.versions.node)}\n`);
  process.exit(1);
}
// Newer-than-pinned majors still run, but the helper pins Node 24.x — warn.
if (String(nodeMajor) !== AGENT_HANDSHAKE_HELPER_NODE_MAJOR) {
  process.stderr.write(
    `${JSON.stringify({ warning: `clockchain-local-adapter requires Node ${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}.x; the pinned helper will refuse under ${process.versions.node}` })}\n`,
  );
}

const scriptDir = dirname(fileURLToPath(import.meta.url));

function resolveAssetPaths() {
  const envDir = process.env.CLOCKCHAIN_LOCAL_ADAPTER_ASSETS;
  if (typeof envDir === "string" && envDir.length > 0) return { assetDir: envDir };
  // Installed npm layout: index.mjs sits at the package root beside assets/.
  // The execPath candidate covers single-file compiled builds (e.g.
  // `bun build --compile`), where import.meta.url resolves inside a virtual
  // filesystem and only the executable's own directory is real.
  for (const candidate of [
    join(scriptDir, "assets"),
    join(scriptDir, "..", "assets"),
    join(dirname(process.execPath), "assets"),
  ]) {
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

// Deferred load: in the bundled artifact the server module (and its whole
// dependency chain) stays lazily initialized behind this import, so on an
// unsupported runtime the gate above has already exited before any of it —
// or anything it pulls in — can execute.
import("../src/local-adapter/server.mjs").then(
  ({ startLocalAdapterStdio }) => {
    try {
      startLocalAdapterStdio(resolveAssetPaths());
    } catch {
      process.stderr.write(`${JSON.stringify({ error: "ADAPTER_ASSET_VERIFICATION_FAILED" })}\n`);
      process.exit(86);
    }
  },
  () => {
    process.stderr.write(`${JSON.stringify({ error: "ADAPTER_LOAD_FAILED" })}\n`);
    process.exit(1);
  },
);
