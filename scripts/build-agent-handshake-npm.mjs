#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { buildAgentHandshakeBundle } from "./build-agent-handshake-release.mjs";
import {
  AGENT_HANDSHAKE_HELPER_NODE_MAJOR,
  AGENT_HANDSHAKE_HELPER_VERSION,
} from "../src/agent-handshake/v2/constants.mjs";

const outDir = resolve(process.argv[2] ?? "dist/npm-agent-handshake");
await mkdir(outDir, { recursive: true });
await buildAgentHandshakeBundle({ outfile: join(outDir, "index.cjs") });
await writeFile(join(outDir, "package.json"), JSON.stringify({
  name: "@clockchain/agent-handshake",
  version: AGENT_HANDSHAKE_HELPER_VERSION,
  description: "Local policy, ERC-8004 identity, signing, and verification authority for Clockchain agent handshakes.",
  license: "UNLICENSED",
  bin: { "clockchain-agent-handshake": "index.cjs" },
  engines: { node: `>=${AGENT_HANDSHAKE_HELPER_NODE_MAJOR}` },
  files: ["index.cjs"],
}, null, 2) + "\n", { flag: "wx", mode: 0o600 });
process.stdout.write(JSON.stringify({ ok: true, version: AGENT_HANDSHAKE_HELPER_VERSION }) + "\n");
