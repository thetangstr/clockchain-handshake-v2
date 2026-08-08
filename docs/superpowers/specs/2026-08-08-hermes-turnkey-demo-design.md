# Two-agent Hermes turnkey Handshake demo — design

## Outcome

Reuse the existing `/handshake/claude-v6` presenter exactly as the visual baseline, but make the run behind it genuinely bilateral:

- one newly created Hermes agent acts only as **Payer**;
- one separately created Hermes agent acts only as **Requestor**;
- both use the production Clockchain MCP at `https://mcp.clockchain.network/mcp`;
- both generate and retain their own EVM signing key locally;
- Clockchain remains only the **session host & independent checker**;
- no payment moves;
- one authenticated Mac-mini command creates, starts, observes, and cleans up the two agents.

The Mac mini continues to host the Hermes backend/control surface. It is infrastructure, not a Handshake party.

## Locked product decisions

### Preserve the presenter

The public route, two-column layout, typography, role cards, receipt timeline, animations, run history, block detail, and live polling remain. The retrofit changes hard-coded topology copy and the state predicates that drive the existing rows. It does not introduce a new visual system.

### Keep launch control off the public page

The public Vercel page stays read-only. Starting agents from an unauthenticated public page would create a paid-agent spawning endpoint and expose an operational control plane. The turnkey control is a single authenticated command on the Mac mini; the existing page fills itself in from the relay as the run progresses.

### Define “fresh” precisely

For each run, the launcher creates two never-before-used, run-scoped `HERMES_HOME` trees, two synthetic OS home directories, and two empty workspaces. It never invokes or clones a named profile under the machine's shared `~/.hermes`. Both processes are launched with `--ignore-rules`, without `--resume`, `--continue`, or `--safe-mode`.

Before token minting or MCP onboarding, the launcher records a sanitized `pre-provision` manifest proving:

- unique run-scoped Hermes-home, OS-home, workspace, cache, and temporary-directory paths;
- no sessions or messages;
- no contacts, channel directory, pastes, caches, or prior process state;
- no memory or user profile injection;
- no skills, plugins, bundles, hooks, MCP token cache, or global auth store;
- an empty workspace with no repository, lockfile, `node_modules`, virtualenv, or package cache;
- no wallet file yet;
- no inherited MCP servers before onboarding;
- a deliberately constructed environment allowlist, with both `HOME` and `HERMES_HOME` pointing inside the role root.

The launcher then mints two distinct principals, injects only the inference credential and one Clockchain MCP connection into each process, and records a second sanitized `pre-prompt` manifest with the two distinct principal fingerprints and exact five-tool discovery result. It writes a minimal role-local config, sets `terminal.home_mode: profile`, disables shell-startup sourcing, disables memory/user-profile features, assigns separate package caches, and supplies one role-specific task. The MCP token and inference credential are process environment variables, not durable profile state. Together the two manifests prove blank Hermes context, blank task workspaces, and narrowly scoped onboarding. This is not represented as a hardware or kernel isolation boundary.

The agents independently clone the pinned public Handshake branch and install its dependencies after launch. Their EVM wallet files are created inside their own disposable workspaces with mode `0600`, are never sent to MCP or the presenter, and are removed during cleanup.

## Approaches considered

### Selected: read-only presenter plus one-command Mac-mini launcher

This preserves the successful demo, keeps mutation behind SSH/local authentication, gives repeatable clean-room evidence, and avoids introducing a new public security boundary.

### Rejected: browser “Start demo” button

This is cosmetically convenient but requires a public or tunneled spawn API, authentication, replay protection, spend controls, and secret transport. None of that improves the Handshake proof.

### Rejected: two manually prepared Hermes windows

This can demonstrate bilateral signing but cannot reliably prove blank state, is easy to misconfigure, and is not turnkey.

## System shape

```text
Mac mini
  Hermes backend / control surface
  one-command clean-room launcher
    ├── fresh Payer HERMES_HOME + empty workspace + MCP token A + wallet A
    └── fresh Requestor HERMES_HOME + empty workspace + MCP token B + wallet B

Payer Hermes ───────┐
                    ├── HTTPS Streamable MCP ── Clockchain MCP on AWS
Requestor Hermes ───┘                              │
                                                   ├── relay/session mailbox
                                                   ├── registration-gas funding
                                                   ├── Clockchain anchoring
                                                   └── independent verification + certificate

Public `/handshake/claude-v6` page
  └── same-origin read-only proxy ── current relay snapshot / receipts / runs
```

## Agent protocol

Both profiles begin with the same five Clockchain tools, filtered to:

1. `handshake_status`
2. `handshake_join`
3. `handshake_next`
4. `handshake_submit`
5. `handshake_get_certificate`

Each token remains fixed for its agent for the whole run because MCP state is principal-keyed.

Each role follows this loop:

1. Call `handshake_join(role)` and retain the returned session id.
2. Call `handshake_next(sessionId, role)`.
3. If `bytesToSignHex` is returned, sign those exact bytes with the role’s local EIP-191 wallet and submit only `signatureHex` through `handshake_submit`.
4. If `needed` is `funding_record`, wait and call `handshake_next` again.
5. If `needed` is `erc8004_identity`, use the same local wallet to register on Sepolia, then continue.
6. Continue until the party-result signature and evidence upload are complete.
7. Fetch and verify the shared certificate with `handshake_get_certificate`.

The local wallet bridge has only four commands: initialize, inspect, sign exact bytes, and register. It never prints the private key and refuses permissive, symlinked, replaced, or pre-existing state paths.

## Host and monitor truthfulness

The host may create sessions, publish discovery, fund exact role-tagged seats, sign the descriptor, observe anchors, collect evidence, run the verifier, and publish the closing certificate. It may not generate either party key, register either party, author the mandate or payment request, sign a party result, or announce success before verification.

The current host narration advances several business stages while it is only waiting. That is corrected so:

- session creation emits only `SESSION_STARTED`;
- waiting for identities never emits `TERMS_PUBLISHED` or `REQUEST_SUBMITTED`;
- `TERMS_PUBLISHED` requires a real payer mandate;
- `REQUEST_SUBMITTED` requires a real requestor payment request;
- identity/funding/heartbeat display comes from snapshot fields, not a fabricated business stage;
- the host does not automatically mark the payer heartbeat for every host log line;
- the verdict remains sourced only from the independent verifier.

The presenter stops using “furthest enum index” as its source of truth. The real two-agent chronology is not the old enum order. Rows instead complete from concrete facts: snapshot presence, funding/identity fields, named stage-history events, anchor presence, evidence stage, and verdict.

## Presenter retrofit

The existing page is retained and updated as follows:

- `D4D` becomes `Payer` and `BuzzHive` becomes `Requestor`.
- Both role cards say “fresh, isolated Hermes agent.”
- The third boundary is named exactly `Clockchain — session host & independent checker.`
- The Mac mini is described as the Hermes launcher/gateway, never as a signing party.
- Old `npm run demo`, legacy branch, Yang-machine, and one-fresh-side instructions are removed.
- The live monitor retains its receipt drill-down, block links, no-money banner, failure state, liveness indicator, checker card, reset, and run history.
- Identity and receipt labels use Payer/Requestor while the wire key `payee` remains unchanged.

No prompts, tokens, file paths, private keys, provider secrets, or raw Hermes transcripts are published by the page.

## Failure behavior

The launcher fails closed before prompting agents if either freshness manifest contains prior state, either role path escapes or overlaps the run root, the two tokens are equal, the environment contains anything outside the allowlist, provider/MCP setup is incomplete, or either generated config resolves outside its role-local `HERMES_HOME`.

An agent failure, timeout, role collision, invalid signature, registration failure, MCP authorization failure, certificate failure, or missing evidence ends the run without claiming authorization. The evidence bundle retains sanitized logs, manifests, token fingerprints, generated role identifiers, session id, public addresses, agent ids, and certificate/receipt references. Secrets and wallet files are excluded.

Cleanup is explicit and recoverable for evidence: redacted transcripts and sanitized manifests are retained in the run evidence directory; disposable Hermes homes, synthetic OS homes, workspaces, wallet files, and per-agent caches are removed after capture.

## Verification

### Automated

- Wallet bridge tests cover new state, exact-byte signing, registration parsing, private-mode enforcement, replacement/symlink refusal, and no secret output.
- Launcher tests cover empty-manifest gates, disjoint role roots, distinct homes/workspaces/tokens/caches, an environment allowlist, MCP allowlist, sanitized evidence, concurrent launch, and fail-closed cleanup.
- Host tests prove no premature terms/request stages and no automatic payer heartbeat.
- Presenter tests prove exact Payer/Requestor/Clockchain labels, absence of legacy topology copy, artifact-driven row completion, `paymentMoved:false`, and no secret-bearing provenance fields.
- Run targeted tests, full Handshake tests, research typecheck/lint/build, and focused browser QA of the unchanged page layout.

### Live gate

From the Mac mini:

1. Capture both `pre-provision` zero-state manifests.
2. Mint two distinct production MCP tokens, discover the exact five Clockchain tools, and capture both secret-free `pre-prompt` onboarding manifests.
3. Launch both role prompts concurrently through Hermes.
4. Confirm two different local wallet addresses and two new ERC-8004 agent ids.
5. Confirm the relay contains separate role-owned identity, mandate/request, party-result, and evidence records.
6. Confirm three anchored receipts, a verifier-derived verdict, and one certificate verified by both agents.
7. Confirm the public page shows Payer and Requestor as separate agents and never shows the host as a party.
8. Confirm `paymentMoved:false` everywhere.
9. Capture post-run dependency/home manifests and remove both disposable Hermes homes/workspaces.

## Deployment

- Push the Handshake feature branch so each clean agent can clone an exact immutable commit.
- Deploy the corrected host image/service on AWS without rotating the funding wallet or relay session key material.
- Install the launcher under a dedicated Mac-mini path and expose it as one local command; keep the reusable inference credential in a mode-`0600` file outside the repository and mint the two MCP tokens only in memory.
- Deploy the research-page branch to Vercel after tests and visual comparison.
- Run the live gate only after MCP health, host health, relay health, and the public presenter all pass read-only checks.
