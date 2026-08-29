import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import * as protocol from "@clockchain/handshake-protocol";

const packageRoot = new URL("..", import.meta.url);
const sourceRoot = new URL("../src", import.meta.url);
const execFileAsync = promisify(execFile);

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await sourceFiles(entryPath));
    } else if (entry.isFile() && entry.name.endsWith(".mjs")) {
      files.push(entryPath);
    }
  }
  return files;
}

test("protocol package exposes the transport-independent v2 kernel", async () => {
  const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

  assert.equal(manifest.name, "@clockchain/handshake-protocol");
  assert.equal(manifest.type, "module");
  assert.equal(manifest.private, false);
  assert.deepEqual(manifest.engines, { node: ">=22" });
  assert.equal(manifest.scripts.test, "node --test test/*.test.mjs");
  assert.equal(await stat(sourceRoot).then((value) => value.isDirectory()), true);

  const requiredExports = [
    "canonicalBytes",
    "digestHex",
    "agentHandshakeV2StatementDigest",
    "localPolicyDigest",
    "agentHandshakeV2ProposalDigest",
    "agentHandshakeV2TransitionDigest",
    "agentHandshakeV2DescriptorDigest",
    "hostSessionKeyCertificateDigest",
    "agentHandshakeV2ResultDigest",
    "verifyAgentHandshakeV2Authorization",
    "verifyAgentHandshakeV2Result",
  ];
  for (const exportedName of requiredExports) {
    assert.equal(typeof protocol[exportedName], "function", `${exportedName} must be public`);
  }
});

test("protocol package source has no runtime, relay, wallet, cloud, or demo boundary imports", async () => {
  const forbiddenImportFragments = [
    "@modelcontextprotocol",
    "express",
    "fastify",
    "http",
    "https",
    "oauth",
    "jwks",
    "jose",
    "fs",
    "path",
    "session-supervisor",
    "supervisor",
    "agent-contract",
    "aws",
    "cloud",
    "relay",
    "monitor",
    "process",
    "wallet",
    "server",
    "listener",
    "controller",
    "production-adapter",
    "host-root",
    "funding",
  ];
  const forbiddenSourcePatterns = [
    /\bprocess\.env\b/,
    /\bcreateServer\b/,
    /\blisten\s*\(/,
    /\bfetch\s*\(/,
  ];

  for (const file of await sourceFiles(sourceRoot.pathname)) {
    const text = await readFile(file, "utf8");
    const importSpecifiers = [...text.matchAll(/^\s*import\s+(?:[\s\S]*?\s+from\s+)?["']([^"']+)["'];?/gm)]
      .map((match) => match[1]);
    for (const specifier of importSpecifiers) {
      if (specifier.startsWith("node:")) {
        assert.match(specifier, /^node:(?:crypto|util)$/, `${relative(packageRoot.pathname, file)} imports ${specifier}`);
        continue;
      }
      if (specifier === "viem") {
        continue;
      }
      assert.equal(
        forbiddenImportFragments.some((fragment) => specifier.toLowerCase().includes(fragment)),
        false,
        `${relative(packageRoot.pathname, file)} imports forbidden boundary ${specifier}`,
      );
    }
    for (const pattern of forbiddenSourcePatterns) {
      assert.equal(pattern.test(text), false, `${relative(packageRoot.pathname, file)} contains ${pattern}`);
    }
  }
});

test("package dry-run includes the immutable v2 fixture and extraction provenance", async () => {
  const { stdout } = await execFileAsync("npm", ["pack", "--dry-run", "--json"], {
    cwd: packageRoot,
    maxBuffer: 1024 * 1024,
  });
  const [pack] = JSON.parse(stdout);
  const files = new Set(pack.files.map((entry) => entry.path));

  assert.equal(files.has("test/fixtures/agent-handshake-v2-canonical.json"), true);
  assert.equal(files.has("test/fixtures/v2-provenance.json"), true);
});
