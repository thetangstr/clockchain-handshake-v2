import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";

const packageRoot = new URL("..", import.meta.url);
const sourceRoot = new URL("../src", import.meta.url);

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await sourceFiles(entryPath));
    if (entry.isFile() && entry.name.endsWith(".mjs")) files.push(entryPath);
  }
  return files;
}

function extractModuleSpecifiers(text) {
  const specifiers = [];
  const patterns = [
    /^\s*import\s+(?!["'])(?:[\s\S]*?)\s+from\s+["']([^"']+)["']/gm,
    /^\s*import\s+["']([^"']+)["']/gm,
    /^\s*export\s+(?:\*|\{[\s\S]*?\})\s+from\s+["']([^"']+)["']/gm,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/gm,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) specifiers.push(match[1]);
  }
  return specifiers;
}

test("SDK source imports only the protocol package and no authority-bearing runtime modules", async () => {
  const forbiddenImportFragments = [
    "@modelcontextprotocol",
    "http",
    "https",
    "net",
    "tls",
    "fs",
    "path",
    "oauth",
    "jwks",
    "jose",
    "session-supervisor",
    "supervisor",
    "agent-contract",
    "relay",
    "server",
    "listener",
    "controller",
    "wallet",
    "keychain",
    "credential",
    "aws",
    "cloud",
  ];
  const forbiddenSourcePatterns = [
    /\bfetch\s*\(/,
    /\bprocess\.env\b/,
    /\bcreateServer\b/,
    /\blisten\s*\(/,
    /\bsign(?:ature|Message|TypedData)?\s*\(/i,
    /\bprivateKey\b/,
    /\bbusinessContent\b/,
    /\bexternalBusinessActionPerformed\s*:\s*true\b/,
  ];

  for (const file of await sourceFiles(sourceRoot.pathname)) {
    const text = await readFile(file, "utf8");
    for (const specifier of extractModuleSpecifiers(text)) {
      assert.equal(
        specifier === "@clockchain/handshake-protocol/v3" ||
          specifier === "@clockchain/handshake-protocol/fixtures/standalone-handshake-v3-contract-fixtures.json" ||
          specifier === "@clockchain/handshake-protocol/schemas/standalone-handshake-v3-contract.schema.json",
        true,
        `${relative(packageRoot.pathname, file)} imports ${specifier}`,
      );
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
