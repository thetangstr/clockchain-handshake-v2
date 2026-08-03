// Proves the roles-core severance: the two proven role functions survive intact,
// and the invitation/CLI layer is gone. A regression here means the module has
// re-acquired a dependency on a donor module we deliberately did not port.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const MODULE_PATH = resolve(HERE, "../src/core/roles-core.mjs");
const source = readFileSync(MODULE_PATH, "utf8");

test("exports the two role functions", async () => {
  const module = await import("../src/core/roles-core.mjs");
  assert.equal(typeof module.runPayerRole, "function");
  assert.equal(typeof module.runPayeeRole, "function");
});

test("does not export the dropped CLI layer", async () => {
  const module = await import("../src/core/roles-core.mjs");
  assert.equal(module.runRoleCli, undefined);
  assert.equal(module.buildDefaultRoleInput, undefined);
});

test("carries no invitation reference", () => {
  assert.equal(
    /invitation/i.test(source),
    false,
    "roles-core must not reference the unported invitation module, in code or in argument tables",
  );
});

test("every relative import resolves to a file that exists", () => {
  const specifiers = [...source.matchAll(/from\s*["'](\.[^"']+)["']/g)].map((m) => m[1]);
  assert.ok(specifiers.length > 0, "expected the module to have relative imports");
  for (const specifier of specifiers) {
    const target = resolve(dirname(MODULE_PATH), specifier);
    assert.ok(existsSync(target), `unresolved import ${specifier} -> ${target}`);
  }
});

test("imports nothing from outside the ported core", () => {
  const specifiers = [...source.matchAll(/from\s*["']([^"']+)["']/g)].map((m) => m[1]);
  for (const specifier of specifiers) {
    const allowed =
      specifier.startsWith("node:") ||
      specifier === "viem" ||
      specifier.startsWith("viem/") ||
      specifier.startsWith("./");
    assert.ok(allowed, `unexpected import specifier: ${specifier}`);
  }
});

test("retains the helper closure the role functions depend on", () => {
  // Spot-check the helpers the two role functions call directly. If the severance
  // ever over-reaches, these disappear and the role functions break at call time
  // rather than at import time — so assert their presence statically.
  for (const helper of [
    "verifiedDescriptor",
    "verifyIdentityBindings",
    "tripleFromOutcome",
    "assertLater",
    "signatureFor",
    "evidenceResult",
    "roleResult",
    "runnerOptions",
    "publish",
    "announceReady",
    "discoverProposal",
  ]) {
    assert.ok(
      new RegExp(`(?:function|const)\\s+${helper}\\b`).test(source),
      `helper ${helper} must survive the severance`,
    );
  }
});
