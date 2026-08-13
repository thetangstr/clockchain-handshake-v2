#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(process.argv[2] ?? "");
const pin = JSON.parse(await readFile(new URL("../release/agent-handshake/pin.json", import.meta.url), "utf8"));
const prefix = pin.allowedAssetPrefix;

if (process.argv.length !== 3 || !root.startsWith("/") || pin.version !== "2.1.3") process.exit(1);
await mkdir(root, { recursive: false, mode: 0o755 });
const manifestResponse = await fetch(`${prefix}manifest.json`, { redirect: "follow", signal: AbortSignal.timeout(30_000) });
if (!manifestResponse.ok) process.exit(1);
const manifestBytes = Buffer.from(await manifestResponse.arrayBuffer());
if (createHash("sha256").update(manifestBytes).digest("hex") !== pin.manifestDigest) process.exit(1);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
if (manifest.schema !== "clockchain.agent-handshake-release-manifest/v1" || manifest.version !== pin.version || manifest.assets?.length !== 1) process.exit(1);
const asset = manifest.assets[0];
if (asset.url !== `${prefix}clockchain-agent-handshake.cjs` || asset.filename !== "clockchain-agent-handshake.cjs") process.exit(1);
const helperResponse = await fetch(asset.url, { redirect: "follow", signal: AbortSignal.timeout(30_000) });
if (!helperResponse.ok) process.exit(1);
const helperBytes = Buffer.from(await helperResponse.arrayBuffer());
if (createHash("sha256").update(helperBytes).digest("hex") !== asset.sha256) process.exit(1);
await writeFile(`${root}/manifest.json`, manifestBytes, { mode: 0o444 });
await writeFile(`${root}/clockchain-agent-handshake.cjs`, helperBytes, { mode: 0o444 });
