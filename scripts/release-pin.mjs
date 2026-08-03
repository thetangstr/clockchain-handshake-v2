#!/usr/bin/env node
/**
 * The single writer of version identity.
 *
 * A previous build pinned the release sha in five different files that had to move
 * in lockstep; one stale pin became a hard mid-demo failure. Here exactly one file
 * carries identity — release.json — and exactly one command writes it. Everything
 * else (the discovery document above all) reads from that file.
 *
 * Pinning is inherently two-step: this records the commit whose content it
 * measured, and committing release.json then advances HEAD past that commit. So
 * repositorySha here is provenance ("what was measured"), while the discovery
 * document published at session start reads live HEAD. The value a requestor kit
 * verifies against is kitManifestDigest, which excludes release.json precisely so
 * that it survives being committed.
 *
 * Usage: npm run release:pin
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(new URL("..", import.meta.url).pathname);
const RELEASE_PATH = resolve(ROOT, "release.json");
const SCHEMA = "handshake-release/v1";

function git(...arguments_) {
  return execFileSync("git", arguments_, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  }).trim();
}

function stop(reason, detail) {
  // Named public reason, plain language, no stack trace, no secrets.
  process.stderr.write(`RELEASE_PIN_${reason}: ${detail}\n`);
  process.exit(1);
}

let status;
try {
  status = git("status", "--porcelain");
} catch {
  stop("NOT_A_REPOSITORY", "This directory is not a git repository.");
}

// release.json is this tool's own output, so a pending change to it is expected
// and must not block a re-run. Any OTHER pending change is refused: a pin has to
// describe a tree a stakeholder can actually fetch.
const dirtyOther = status
  .split("\n")
  .filter((line) => line.trim().length > 0)
  .filter((line) => !line.endsWith(" release.json"));

if (dirtyOther.length > 0) {
  stop(
    "WORKING_TREE_DIRTY",
    "Commit or stash every change first — a pin taken from a dirty tree does not describe anything a stakeholder can fetch.",
  );
}

const repositorySha = git("rev-parse", "HEAD");
if (!/^[0-9a-f]{40}$/.test(repositorySha)) {
  stop("SHA_UNREADABLE", "Could not read a 40-character commit id for HEAD.");
}

/**
 * kitManifestDigest: sha256 over "<blobSha> <path>\n" for every tracked file, in
 * sorted path order. Derived from git's own object hashes, so it is deterministic
 * across machines and checkouts, and independent of file mtimes or clone order.
 * `git ls-files -s` already prints mode, blob sha, stage and path.
 *
 * release.json is EXCLUDED from its own manifest. Including it would make the
 * digest a fixed-point problem: pinning writes release.json, committing that file
 * changes its blob, and a recomputed digest would then disagree with the one
 * stored inside it — so the requestor kit's integrity check could never pass.
 * Excluding it means the digest is stable across the pin commit, which is exactly
 * the property the kit relies on.
 */
const manifest = git("ls-files", "-s")
  .split("\n")
  .filter((line) => line.length > 0)
  .map((line) => {
    const [meta, path] = line.split("\t");
    const [, blob] = meta.split(" ");
    return `${blob} ${path}`;
  })
  .filter((entry) => !entry.endsWith(" release.json"))
  .sort()
  .join("\n");

const kitManifestDigest = createHash("sha256")
  .update(`${manifest}\n`, "utf8")
  .digest("hex");

const release = {
  schema: SCHEMA,
  repositorySha,
  kitManifestDigest,
  paymentMoved: false,
};

const serialized = `${JSON.stringify(release, null, 2)}\n`;
const previous = (() => {
  try {
    return readFileSync(RELEASE_PATH, "utf8");
  } catch {
    return null;
  }
})();

writeFileSync(RELEASE_PATH, serialized);

process.stdout.write(
  [
    "Release identity pinned.",
    `  commit           ${repositorySha}`,
    `  kit manifest     ${kitManifestDigest}`,
    `  tracked files    ${manifest.split("\n").length}`,
    `  paymentMoved     false`,
    previous === serialized
      ? "  (unchanged — re-pinning the same clean tree is a no-op)"
      : "  release.json updated; commit it so the pin matches a fetchable commit.",
    "",
  ].join("\n"),
);
