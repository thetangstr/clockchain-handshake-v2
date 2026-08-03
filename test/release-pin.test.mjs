// release:pin is the only writer of version identity. These tests run against a
// throwaway git repository under the OS temp dir — never against this repo.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "../scripts/release-pin.mjs",
);

async function sandbox(t) {
  const root = await mkdtemp(join(tmpdir(), "handshake-pin-"));
  t.after(async () => {
    await rm(root, { force: true, recursive: true });
  });
  const git = (...arguments_) =>
    execFileSync("git", arguments_, { cwd: root, encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "test@example.invalid");
  git("config", "user.name", "Test");
  git("config", "commit.gpgsign", "false");
  await mkdir(join(root, "scripts"), { recursive: true });
  await writeFile(join(root, "scripts/release-pin.mjs"), await readFile(SCRIPT));
  await writeFile(join(root, "release.json"), "{}\n");
  await writeFile(join(root, "a.txt"), "alpha\n");
  git("add", "-A");
  git("commit", "-qm", "initial");
  return { git, root };
}

function pin(root) {
  return execFileSync("node", ["scripts/release-pin.mjs"], {
    cwd: root,
    encoding: "utf8",
  });
}

test("refuses to pin a dirty working tree", async (t) => {
  const { root } = await sandbox(t);
  await writeFile(join(root, "a.txt"), "changed\n");
  assert.throws(
    () => pin(root),
    (error) => {
      // Named public reason on stderr, non-zero exit, no stack trace.
      assert.equal(error.status, 1);
      assert.match(String(error.stderr), /RELEASE_PIN_WORKING_TREE_DIRTY/);
      assert.equal(/at .*\n/.test(String(error.stderr)), false);
      return true;
    },
  );
});

test("pins the commit and a deterministic manifest digest", async (t) => {
  const { root } = await sandbox(t);
  const output = pin(root);
  const release = JSON.parse(await readFile(join(root, "release.json"), "utf8"));

  assert.equal(release.schema, "handshake-release/v1");
  assert.match(release.repositorySha, /^[0-9a-f]{40}$/);
  assert.match(release.kitManifestDigest, /^[0-9a-f]{64}$/);
  assert.equal(release.paymentMoved, false);
  assert.match(output, /Release identity pinned/);
});

test("the manifest digest survives committing the pin itself", async (t) => {
  const { git, root } = await sandbox(t);
  // The property the requestor kit depends on. release.json holds a digest over
  // the kit's tracked files; committing release.json must NOT invalidate that
  // digest, or the kit could never verify the release it was told to fetch.
  // (This is why release.json is excluded from its own manifest.)
  pin(root);
  const before = JSON.parse(await readFile(join(root, "release.json"), "utf8"));

  git("add", "-A");
  git("commit", "-qm", "pin");
  pin(root);
  const after = JSON.parse(await readFile(join(root, "release.json"), "utf8"));

  assert.equal(
    after.kitManifestDigest,
    before.kitManifestDigest,
    "committing the pin must not change the manifest digest",
  );
});

test("is idempotent: two runs against the same commit are identical", async (t) => {
  const { root } = await sandbox(t);
  pin(root);
  const first = await readFile(join(root, "release.json"), "utf8");
  const output = pin(root);
  const second = await readFile(join(root, "release.json"), "utf8");
  assert.equal(second, first);
  assert.match(output, /unchanged/);
});

test("repositorySha records the commit the pin was taken at", async (t) => {
  const { git, root } = await sandbox(t);
  const head = git("rev-parse", "HEAD").trim();
  pin(root);
  const release = JSON.parse(await readFile(join(root, "release.json"), "utf8"));
  // Pinning is inherently two-step: this records the commit whose content was
  // measured. Committing release.json then advances HEAD past it, which is why
  // the discovery document reads live HEAD at session start rather than trusting
  // this field, and why kitManifestDigest (which excludes release.json) is the
  // value the requestor kit actually verifies against.
  assert.equal(release.repositorySha, head);
});

test("the manifest digest changes when tracked content changes", async (t) => {
  const { git, root } = await sandbox(t);
  pin(root);
  const before = JSON.parse(await readFile(join(root, "release.json"), "utf8"));

  await writeFile(join(root, "a.txt"), "beta\n");
  git("add", "-A");
  git("commit", "-qm", "change");
  pin(root);
  const after = JSON.parse(await readFile(join(root, "release.json"), "utf8"));

  assert.notEqual(after.kitManifestDigest, before.kitManifestDigest);
  assert.notEqual(after.repositorySha, before.repositorySha);
});
