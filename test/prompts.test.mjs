// The pasted prompts are the product surface: they are what a stakeholder who has
// never seen this repository actually reads. Every assertion here exists because
// the alternative is a person being asked to assemble something by hand — a SHA to
// paste, a token to keep secret, a session id to copy — which is precisely the
// failure the one-URL handover was built to remove.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PROMPTS = ["requestor", "payer"];
const MAX_LINES = 40;

// A run of 32+ token characters is what a pasted secret looks like: an API key, a
// bearer token, a base64 blob. Nothing legitimate in these prompts is that long.
const TOKEN_SHAPED = /[A-Za-z0-9_-]{32,}/;
const FORTY_HEX = /\b[0-9a-f]{40}\b/i;
const PLACEHOLDER = /<[A-Z][A-Z0-9_]*>/g;

async function load(name) {
  return readFile(join(ROOT, "prompts", `${name}.md`), "utf8");
}

for (const name of PROMPTS) {
  test(`prompts/${name}.md fits in ${MAX_LINES} lines`, async () => {
    const text = await load(name);
    const lines = text.replace(/\n$/, "").split("\n");
    assert.ok(
      lines.length <= MAX_LINES,
      `${name}.md is ${lines.length} lines; a prompt nobody reads to the end is not a prompt`,
    );
  });

  test(`prompts/${name}.md pastes no secret and no version pin`, async () => {
    const text = await load(name);
    const sha = text.match(FORTY_HEX);
    assert.equal(sha, null, `${name}.md asks a person to paste a commit sha: ${sha?.[0]}`);
    const token = text.match(TOKEN_SHAPED);
    assert.equal(token, null, `${name}.md contains a token-shaped literal: ${token?.[0]}`);
  });

  test(`prompts/${name}.md asks for nothing a person must assemble`, async () => {
    const text = await load(name);
    // The two flags the discovery URL replaced. If either reappears in a prompt,
    // the reader is back to assembling a rendezvous by hand.
    assert.ok(!text.includes("--relay-url"), `${name}.md still asks for a relay URL`);
    assert.ok(!text.includes("--session"), `${name}.md still asks for a session id`);
  });

  test(`prompts/${name}.md says no money moves`, async () => {
    const text = await load(name);
    assert.match(text, /no money/i, `${name}.md never tells the reader that no money moves`);
  });

  test(`prompts/${name}.md does not let the agent speak the verdict`, async () => {
    const text = await load(name);
    assert.ok(
      !text.includes("AUTHORIZED"),
      `${name}.md names the outcome; only the independent verifier may emit it`,
    );
    assert.match(
      text,
      /Do not announce success/,
      `${name}.md must forbid claiming success outright`,
    );
    assert.match(text, /independent checker/, `${name}.md must say who actually decides`);
  });

  test(`prompts/${name}.md checks the Node version before anything else`, async () => {
    const text = await load(name);
    assert.match(text, /node --version/);
    assert.match(text, /22 or higher/);
  });
}

// The two prompts diverge past this point, and the divergence is the interesting
// part. The requestor arrives with nothing: it clones a public repository and is
// handed one URL. The payer cannot do that -- keys/ is gitignored, so a clean
// clone has no funding wallet, no password and no ledger token, and would die at
// wallet-unlock. Asserting a shared install path across both, as this file once
// did, encoded a payer setup that could never have worked.

test("prompts/requestor.md installs from a clean clone and takes exactly one input", async () => {
  const text = await load("requestor");
  assert.match(text, /git clone https:\/\/github\.com\/thetangstr\/clockchain-handshake-v2\.git/);
  assert.match(text, /npm ci/);
  assert.match(text, /node bin\/requestor\.mjs --discovery-url <DISCOVERY_URL>/);
  const distinct = new Set(text.match(PLACEHOLDER) ?? []);
  assert.deepEqual(
    [...distinct],
    ["<DISCOVERY_URL>"],
    "requestor.md must have exactly one placeholder, and it must be the discovery URL",
  );
});

test("prompts/payer.md runs on the operator's own machine, with nothing to fill in", async () => {
  const text = await load("payer");
  assert.ok(
    !/git clone/.test(text),
    "payer.md tells the reader to clone, but keys/ is gitignored: that path cannot run",
  );
  assert.match(text, /npm run preflight/);
  assert.match(text, /npm run demo/);
  // The discovery URL is stable now, so this prompt substitutes nothing. A
  // placeholder here would reach the reader as literal angle brackets, which is
  // exactly what happened before.
  const distinct = new Set(text.match(PLACEHOLDER) ?? []);
  assert.deepEqual([...distinct], [], "payer.md must have no placeholder left to fill in");
  assert.match(text, /nothing else/);
});
