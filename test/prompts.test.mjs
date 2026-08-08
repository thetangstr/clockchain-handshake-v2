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
const HERMES_PROMPTS = ["hermes-requestor", "hermes-payer"];
// 40 originally, then 60, now 75 -- and a number I keep raising is a number
// that was never measuring the right thing. What the limit defends against is a
// wall of text nobody reads to the end, so that is now asserted directly: no
// unbroken run of prose longer than MAX_PARAGRAPH_LINES. The ceiling stays as a
// backstop against sprawl, but the paragraph check is the real guard, and it
// does not punish the prompt for gaining a heading and a skippable section.
const MAX_LINES = 75;
const MAX_PARAGRAPH_LINES = 12;

// A run of 32+ token characters is what a pasted secret looks like: an API key, a
// bearer token, a base64 blob. Nothing legitimate in these prompts is that long.
const TOKEN_SHAPED = /[A-Za-z0-9_-]{32,}/;
const FORTY_HEX = /\b[0-9a-f]{40}\b/i;
const PLACEHOLDER = /<[A-Z][A-Z0-9_]*>/g;
const LIVE_BRANCH = "codex/handshake-build";
const STALE_BRANCH = "claude/handshake-v6";

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

  test(`prompts/${name}.md stays skimmable rather than a wall of text`, async () => {
    const text = await load(name);
    let run = 0;
    let worst = 0;
    for (const line of text.split("\n")) {
      run = line.trim() === "" ? 0 : run + 1;
      if (run > worst) worst = run;
    }
    assert.ok(
      worst <= MAX_PARAGRAPH_LINES,
      `${name}.md has an unbroken ${worst}-line block; a reader deciding whether to ` +
        `paste this needs somewhere for the eye to land`,
    );
    assert.match(text, /^## /m, `${name}.md needs headings to be scanned rather than read`);
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

  test(`prompts/${name}.md describes npm ci honestly`, async () => {
    const text = await load(name);
    assert.match(
      text,
      /only direct npm dependency is viem; npm ci installs locked transitive dependencies; nothing globally/i,
    );
    assert.ok(!text.includes("Exactly one package is installed"));
  });

  test(`prompts/${name}.md keeps the testnet limitation honest`, async () => {
    const text = await load(name);
    assert.match(text, /single-validator testnet/i);
    assert.match(text, /not .*court-grade/i);
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
  // The branch has to be explicit. The kit repository's default branch does not
  // carry bin/requestor.mjs -- a plain clone lands a tree with no requestor in
  // it, and the failure surfaces on the stakeholder's machine, at the one
  // moment nobody can debug it. This assertion used to demand the exact
  // unbranched command, which is how that shipped.
  assert.match(
    text,
    /git clone -b codex\/handshake-build https:\/\/github\.com\/thetangstr\/clockchain-handshake-v2\.git/,
    "the clone must pin the branch that actually contains the requestor",
  );
  assert.ok(!text.includes(STALE_BRANCH), `${STALE_BRANCH} is a stale branch for stranger setup`);
  assert.ok(text.includes(LIVE_BRANCH));
  assert.match(text, /npm ci/);
  assert.match(text, /node bin\/requestor\.mjs --discovery-url <DISCOVERY_URL>/);
  const distinct = new Set(text.match(PLACEHOLDER) ?? []);
  assert.deepEqual(
    [...distinct],
    ["<DISCOVERY_URL>"],
    "requestor.md must have exactly one placeholder, and it must be the discovery URL",
  );
});

test("prompts/payer.md installs from a clean clone and takes the hosted discovery URL", async () => {
  const text = await load("payer");
  assert.match(
    text,
    /git clone -b codex\/handshake-build https:\/\/github\.com\/thetangstr\/clockchain-handshake-v2\.git/,
    "the payer prompt must work for a stranger from a clean public checkout",
  );
  assert.ok(!text.includes(STALE_BRANCH), `${STALE_BRANCH} is a stale branch for stranger setup`);
  assert.ok(text.includes(LIVE_BRANCH));
  assert.match(text, /npm ci/);
  assert.match(text, /node bin\/payer\.mjs --discovery-url <DISCOVERY_URL>/);
  assert.ok(!text.includes("npm run demo"), "the hosted path must not start the legacy demo operator");
  assert.ok(!text.includes("keys/"), "the hosted path must not require private host keys");
  const distinct = new Set(text.match(PLACEHOLDER) ?? []);
  assert.deepEqual(
    [...distinct],
    ["<DISCOVERY_URL>"],
    "payer.md must have exactly one placeholder, and it must be the discovery URL",
  );
  assert.match(text, /single-validator testnet/i);
  assert.match(text, /not .*court-grade/i);
});

async function loadHermes(name) {
  return readFile(join(ROOT, "prompts", `${name}.md`), "utf8");
}

for (const name of HERMES_PROMPTS) {
  test(`prompts/${name}.md defines exactly one role and the canonical five MCP tools`, async () => {
    const text = await loadHermes(name);
    const expectedRole = name.endsWith("payer") ? "Payer" : "Requestor";
    const forbiddenRole = expectedRole === "Payer" ? "Requestor" : "Payer";
    assert.match(text, new RegExp(`Role: ${expectedRole}\\b`));
    assert.doesNotMatch(text, new RegExp(`Role: ${forbiddenRole}\\b`));
    for (const tool of [
      "handshake_status",
      "handshake_join",
      "handshake_next",
      "handshake_submit",
      "handshake_get_certificate",
    ]) {
      assert.match(text, new RegExp(`\\b${tool}\\b`));
    }
    assert.match(text, /https:\/\/mcp\.clockchain\.network\/mcp/);
    assert.match(text, /shared discovery/i);
    assert.match(text, /paymentMoved:false/);
    assert.match(text, /single-validator testnet/i);
    assert.match(text, /not .*court-grade/i);
  });

  test(`prompts/${name}.md requires blank-workspace install, wallet bridge, local registration, and terminal JSON`, async () => {
    const text = await loadHermes(name);
    assert.match(text, /empty workspace/i);
    assert.match(text, /git clone/);
    assert.match(text, /git checkout <KIT_COMMIT>/);
    assert.match(text, /npm ci/);
    assert.match(text, /node bin\/wallet-bridge\.mjs init/);
    assert.match(text, /node bin\/wallet-bridge\.mjs inspect/);
    assert.match(text, /node bin\/wallet-bridge\.mjs sign/);
    assert.match(text, /node bin\/wallet-bridge\.mjs register/);
    assert.match(text, /EIP-191/i);
    assert.match(text, /ERC-8004/i);
    assert.match(text, /handshake_get_certificate/i);
    assert.match(text, /handshake_submit`? is signatures only/i);
    assert.match(text, /retryAfterMs/i);
    assert.match(text, /start at 5 seconds/i);
    assert.match(text, /back off to at most 15 seconds/i);
    assert.match(text, /erc8004_identity.*register locally, then call `?handshake_next`? again/i);
    assert.doesNotMatch(text, /submit only public registration fields/i);
    assert.match(text, /certificateVerified/i);
    assert.match(text, /FINAL_HANDSHAKE_JSON/);
  });

  test(`prompts/${name}.md keeps Clockchain host out of party custody and avoids invented ACK signatures`, async () => {
    const text = await loadHermes(name);
    assert.match(text, /Clockchain is the host, funder, and independent checker/i);
    assert.match(text, /not a party/i);
    assert.match(text, /hosted MCP coordinators advance PROPOSED, ACCEPTED, and ACKNOWLEDGED/i);
    assert.doesNotMatch(text, /party ACK signature/i);
    assert.doesNotMatch(text, /host signs as/i);
    assert.doesNotMatch(text, /Mac mini signs/i);
  });
}

test("Hermes payer authors mandate only and never authors the payment request", async () => {
  const text = await loadHermes("hermes-payer");
  assert.match(text, /author the mandate only/i);
  assert.match(text, /must not author the payment request/i);
  assert.doesNotMatch(text, /author the request only/i);
});

test("Hermes requestor authors payment request only and never authors the mandate", async () => {
  const text = await loadHermes("hermes-requestor");
  assert.match(text, /author the payment request only/i);
  assert.match(text, /must not author the mandate/i);
  assert.doesNotMatch(text, /author the mandate only/i);
});
