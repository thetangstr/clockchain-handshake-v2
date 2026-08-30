import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";

const packageRoot = new URL("..", import.meta.url);
const sourceRoots = [
  new URL("../src", import.meta.url),
  new URL("../bin", import.meta.url),
];

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

function assertNoDynamicExecution(text, label) {
  const forbiddenPatterns = [
    /\bimport\s*\(/,
    /=\s*import\b/,
    /["']import["']/,
    /\bcreateRequire\s*\(/,
    /(?:^|[^\w$])require\s*\(/,
    /\beval\s*\(/,
    /\bFunction\s*\(/,
    /\bnode:vm\b/,
    /\bnode:worker_threads\b/,
  ];
  for (const pattern of forbiddenPatterns) {
    assert.equal(pattern.test(text), false, `${label} contains ${pattern}`);
  }
}

test("CLI boundary scanner rejects dynamic and computed loader evasions", () => {
  const fixtures = [
    'await import("node:http")',
    "const loader = import; await loader('node:https')",
    "createRequire(import.meta.url)('node:fs')",
    "require('node:net')",
    "eval('fetch(1)')",
    "Function('return process')()",
    "import 'node:vm'",
    "import 'node:worker_threads'",
  ];
  for (const fixture of fixtures) {
    assert.throws(() => assertNoDynamicExecution(fixture, "fixture"));
  }
});

test("CLI source stays offline and non-authoritative", async () => {
  const forbiddenImportFragments = [
    "@modelcontextprotocol",
    "http",
    "https",
    "net",
    "tls",
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
    "child_process",
    "cluster",
    "dgram",
    "dns",
    "readline",
    "vm",
    "worker_threads",
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

  for (const root of sourceRoots) {
    for (const file of await sourceFiles(root.pathname)) {
      const text = await readFile(file, "utf8");
      assertNoDynamicExecution(text, relative(packageRoot.pathname, file));
      for (const specifier of extractModuleSpecifiers(text)) {
        const allowed = specifier === "node:process" ||
          specifier === "@clockchain/handshake-sdk" ||
          specifier.startsWith("../src/");
        assert.equal(allowed, true, `${relative(packageRoot.pathname, file)} imports ${specifier}`);
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
  }
});

test("CLI package documentation states fixture verification is not Clockchain trust", async () => {
  const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  const text = `${manifest.description}\n${readme}`;

  assert.match(text, /fixture verification commands do not establish Clockchain trust/i);
  assert.match(text, /verify-result-fixture/i);
  assert.match(text, /verify-certificate-fixture/i);
  assert.doesNotMatch(text, /\bverify-result\b(?!-fixture)/);
  assert.doesNotMatch(text, /\bverify-certificate\b(?!-fixture)/);
});
