import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createImageReleaseAssetFetch } from "../src/harness/image-release-assets.mjs";

const PREFIX = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.3/";

test("image release fetch serves only regular pinned assets from one immutable root", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "image-release-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, "manifest.json"), "manifest", { mode: 0o444 });
  await writeFile(join(root, "clockchain-agent-handshake.cjs"), "helper", { mode: 0o444 });
  const fetchImpl = createImageReleaseAssetFetch(root);
  assert.equal(Buffer.from(await (await fetchImpl(`${PREFIX}manifest.json`)).arrayBuffer()).toString(), "manifest");
  assert.equal(Buffer.from(await (await fetchImpl(`${PREFIX}clockchain-agent-handshake.cjs`)).arrayBuffer()).toString(), "helper");
  await assert.rejects(() => fetchImpl(`${PREFIX}other.cjs`), /failed safely/);
  await assert.rejects(() => fetchImpl("https://example.test/manifest.json"), /failed safely/);
});

test("image release fetch rejects symlinks and missing assets", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "image-release-bad-"));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const root = join(parent, "assets");
  await mkdir(root);
  await writeFile(join(parent, "outside"), "secret");
  await symlink(join(parent, "outside"), join(root, "manifest.json"));
  const fetchImpl = createImageReleaseAssetFetch(root);
  await assert.rejects(() => fetchImpl(`${PREFIX}manifest.json`), /failed safely/);
  await assert.rejects(() => fetchImpl(`${PREFIX}clockchain-agent-handshake.cjs`), /failed safely/);
  assert.throws(() => createImageReleaseAssetFetch("relative"), /failed safely/);
});
