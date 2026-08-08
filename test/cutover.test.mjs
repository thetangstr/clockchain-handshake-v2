import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

const ROOT = new URL("..", import.meta.url);

async function rootFile(path) {
  return readFile(join(ROOT.pathname, path), "utf8");
}

test("final cutover removes the legacy operator entrypoint and package demo script", async () => {
  await assert.rejects(
    access(join(ROOT.pathname, "bin/operator.mjs")),
    /ENOENT/,
    "bin/operator.mjs must be retired after the stranger gate passes",
  );

  const packageJson = JSON.parse(await rootFile("package.json"));
  assert.equal(packageJson.scripts.demo, undefined);
  assert.match(packageJson.scripts["demo:local"], /scripts\/run-local-demo\.mjs/);
  assert.match(packageJson.scripts.host, /bin\/clockchain-host\.mjs/);
});

test("monitor anchor helper is described as the canonical shared helper", async () => {
  const source = await rootFile("src/monitor/anchor.mjs");

  assert.match(source, /canonical shared monitor-anchor helper/i);
  assert.ok(!source.includes("Duplicated from bin/operator.mjs"));
  assert.ok(!source.includes("Keep the operator copy"));
});
