# Hermes two-agent turnkey demo implementation plan

> Execute this plan in `/Users/Kailor/.config/superpowers/worktrees/handshake/hermes-turnkey-demo` on branch `codex/hermes-turnkey-demo`. Follow test-driven development. Do not change the MCP wire schema, snapshot schema, verifier logic, validator count, funding wallet, or party-role names on the wire.

## Outcome

One authenticated command on the Mac mini must create two independent, blank-state Hermes agents, let them install the pinned Handshake kit themselves, and drive one production MCP Handshake to a shared verified certificate. The existing relay board remains read-only and truthful. Clockchain hosts, funds registration gas, checks evidence, and certifies; it never signs as either party.

## Immutable boundaries

- Production MCP: `https://mcp.clockchain.network/mcp`.
- Token mint: `POST https://mcp.clockchain.network/token`.
- Exact MCP tools: `handshake_status`, `handshake_join`, `handshake_next`, `handshake_submit`, `handshake_get_certificate`.
- Local party private keys never cross the wallet bridge.
- Each role gets a distinct token, `HOME`, `HERMES_HOME`, workspace, cache, temp directory, wallet, and process.
- Agent processes inherit an explicit environment allowlist, never `process.env` wholesale.
- The public monitor and all retained evidence must be secret-free.
- `paymentMoved` remains `false`.

## Task 1: Build the fail-closed local wallet bridge

**Files**

- Create `src/core/wallet-bridge.mjs`.
- Create `bin/wallet-bridge.mjs`.
- Create `test/wallet-bridge.test.mjs`.

### 1. Write RED tests

Cover these observable behaviors:

1. `initializeWallet({ statePath })` creates one new secp256k1 key and returns only its public address.
2. The parent directory is `0700`; the wallet and recovery/checkpoint files are `0600`.
3. Initialization refuses an existing target, symlink, hard-linked file, relative path, root path, permissive parent, or replacement race.
4. `inspectWallet` returns public address and public registration state only.
5. `signExactBytes` accepts one even-length `0x` byte string, signs it with EIP-191 raw-byte semantics, and returns only `signatureHex` plus the public address.
6. An independently recovered viem address matches the stored public address.
7. `registerWalletIdentity` calls the existing `registerIdentity` with the same key/address, persists every registration checkpoint before broadcast, resumes through `finalizeIdentityRegistration` when a durable partial registration exists, and returns only public agent id, address, transaction, and block fields.
8. No success or failure JSON, exception, stdout, or stderr contains the private key.
9. The CLI exposes only `init`, `inspect`, `sign`, and `register`; malformed flags exit nonzero with a generic safe error.

Use dependency injection for registration/network tests. Do not hit Sepolia in this task.

Run and confirm failure:

```bash
node --test test/wallet-bridge.test.mjs
```

### 2. Implement the minimum bridge

- Reuse `preparePrivateDirectory`, `readPrivateText`, and `writePrivateFile` from `src/core/private-path.mjs`.
- Reuse `registerIdentity` and `finalizeIdentityRegistration` from `src/core/registration.mjs`.
- Store a versioned private state document and a separate durable registration checkpoint beside it.
- Treat all on-disk state as immutable replacement: validate before read and use the private-path writer for every new version.
- Use `privateKeyToAccount` and `account.signMessage({ message: { raw } })` for exact bytes.
- Keep the CLI output to one JSON object per invocation. Never expose stack traces or secret-bearing error details.

### 3. Verify and commit

```bash
node --test test/wallet-bridge.test.mjs
node --test test/registration.test.mjs test/private-path.test.mjs test/redact.test.mjs
```

Commit intent: `Keep every party signature inside its disposable agent boundary`

Required trailers:

```text
Constraint: MCP receives signatures, never party private keys
Rejected: Reusing the host treasury or historical party identities | those violate bilateral custody and freshness
Confidence: high
Scope-risk: moderate
Directive: Preserve exact-byte EIP-191 signing and durable pre-broadcast registration checkpoints
Tested: wallet bridge, registration, private-path, and redaction tests
Not-tested: live Sepolia registration
```

## Task 2: Build and certify two standalone Hermes clean rooms

**Files**

- Create `src/core/hermes-cleanroom.mjs`.
- Create `test/hermes-cleanroom.test.mjs`.

### 1. Write RED tests

Prove that `prepareCleanRoom({ runRoot, role, ... })`:

1. Accepts only `payer` or `requestor` and canonical absolute paths beneath a newly created `0700` run root.
2. Creates disjoint role roots containing a synthetic `HOME`, a standalone `HERMES_HOME`, empty workspace, npm cache, XDG cache, temp directory, and private evidence staging directory.
3. Starts with no sessions, messages, contacts, pairing records, memories, user profile, skills, plugins, bundles, hooks, auth store, MCP token cache, wallet, repository, lockfile, `node_modules`, virtualenv, or package-manager metadata.
4. Uses a scrubbed throwaway bootstrap `HERMES_HOME` to run `hermes profile create agent --no-skills --no-alias`, verifies its empty skills directory and `.no-bundled-skills` marker, then atomically promotes only that generated profile tree into the standalone role `HERMES_HOME`. The real launch never uses `-p` or shared `~/.hermes`.
5. Writes a minimal mode-`0600` `config.yaml` with the feature-detected config version, model `k3`, provider `kimi-coding`, `agent.max_turns: 500`, no fallbacks, memory and user profile disabled, terminal local/profile-home mode, no shell init files, no bashrc sourcing, no hooks, secret redaction enabled, and exactly one enabled HTTP MCP server.
6. Configures the Clockchain server at the canonical URL, with `x-api-key: ${AUXILIARY_CLOCKCHAIN_MCP_API_KEY}` and the exact five-tool include list; utility MCP resources/prompts are disabled. The `AUXILIARY_*_API_KEY` name is required because supported Hermes builds strip it from terminal subprocess environments.
7. Builds an environment from a safe allowlist. `HOME`, `HERMES_HOME`, `XDG_CACHE_HOME`, `NPM_CONFIG_CACHE`, `COREPACK_HOME`, `TMPDIR`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM`, and `PYTHONNOUSERSITE` must be role-local or fixed safe values. Only the selected inference-key variable and `AUXILIARY_CLOCKCHAIN_MCP_API_KEY` may be secret-bearing.
8. Parses the Hermes installation-root `.env` variable names and seeds them empty in the child environment before adding the two allowed secrets, so fallback loading cannot import machine credentials. A managed `/etc/hermes` secret scope aborts the demo.
9. Rejects overlapping paths, reused role roots, a symlink anywhere in the boundary, pre-existing content, equal tokens, extra environment secrets, an unsupported Hermes build, or a config with any second MCP server/tool.
10. Produces `pre-provision` and `pre-prompt` manifests containing file counts, zero-state assertions, paths relative to the run root, Hermes version/build, kit commit, and SHA-256 principal fingerprints—never tokens, provider keys, absolute private paths, or file contents.
11. Runs a supported-Hermes environment-loader probe in the exact child environment and proves that every install-root `.env` key is empty unless it is one of the two explicit role secrets. The probe returns key-presence booleans only, never values.
12. After token injection, connects to the configured MCP without joining a session and proves the registered Clockchain schema contains exactly `mcp__clockchain__handshake_status`, `mcp__clockchain__handshake_join`, `mcp__clockchain__handshake_next`, `mcp__clockchain__handshake_submit`, and `mcp__clockchain__handshake_get_certificate`. Terminal and file remain separate built-in toolsets.

Run and confirm failure:

```bash
node --test test/hermes-cleanroom.test.mjs
```

### 2. Implement the minimum clean-room builder

- Do not use or mutate named profiles under shared `~/.hermes`; the `profile create` bootstrap itself runs under a disposable scrubbed home.
- Generate JSON-valid YAML so no YAML dependency is added. Overwrite the bootstrap config and leave its `.env` secret-free; pass both allowed secrets in the child process environment only.
- Set both synthetic `HOME` and standalone `HERMES_HOME`; this blocks fallback to global Hermes auth, sessions, skills, shell configuration, and contacts.
- Pin or feature-detect the supported Hermes build, config version, `--no-skills` behavior, `AUXILIARY_*_API_KEY` terminal stripping, MCP include filtering, and one-shot invocation before minting tokens.
- Split evidence ordering explicitly: `pre-provision` is captured before token mint/MCP onboarding; `pre-prompt` is captured only after distinct token injection, the environment-loader probe, exact MCP discovery, and a second secret scan.
- Inspect the boundary immediately before prompting and fail closed if the manifest differs from the expected zero state.
- Export a sanitizer that can compare retained artifacts against live secret canaries without recording the canaries.

### 3. Verify and commit

```bash
node --test test/hermes-cleanroom.test.mjs
node --test test/private-path.test.mjs test/redact.test.mjs
```

Commit intent: `Make blank agent state a measured precondition of every demo`

Required trailers:

```text
Constraint: Fresh means no inherited Hermes, shell, package, wallet, credential, or workspace state
Rejected: Named profiles below shared ~/.hermes | a standalone HERMES_HOME plus synthetic HOME provides the stronger boundary
Confidence: high
Scope-risk: moderate
Directive: Keep child environments allowlisted and preserve the pre-provision zero-state gate
Tested: clean-room, private-path, and redaction tests
Not-tested: Mac-mini Hermes process launch
```

## Task 3: Add the two role prompts and one-command launcher

**Files**

- Create `src/core/hermes-launcher.mjs`.
- Create `bin/hermes-demo.mjs`.
- Create `prompts/hermes-payer.md`.
- Create `prompts/hermes-requestor.md`.
- Create `test/hermes-launcher.test.mjs`.
- Extend `test/prompts.test.mjs`.
- Update `package.json` with `demo:hermes`.

### 1. Write RED tests

Cover:

1. Two token requests are made with distinct role/run subjects; equal or malformed responses abort before either agent starts.
2. The token is held in memory and only its SHA-256 fingerprint enters evidence.
3. The launcher verifies the pinned public kit URL and immutable 40-character commit before creating prompts.
4. Each prompt names exactly one role, the shared discovery flow, the five MCP tools, exact wallet CLI operations, local registration, certificate verification, `paymentMoved:false`, and a terminal success JSON contract.
5. Each prompt tells the agent to clone the public repo into its empty workspace, checkout the pinned commit, run `npm ci`, initialize its own wallet, and never print/read/copy another role's state.
6. Neither prompt describes the host as a party. The payer prompt cannot author the request; the requestor prompt cannot author the mandate. No separate party ACK signature is invented.
7. Hermes is launched twice concurrently from the two workspaces with absolute binary/prompt/usage paths; `-z`, `--ignore-rules`, `--provider kimi-coding`, `-m k3`, and `-t terminal,file,clockchain` are present; resume/continue/safe-mode/profile/skills/worktree flags are absent. “Exact five tools” means the five Clockchain MCP tools; the terminal and file built-ins remain intentionally available so a blank agent can clone, install, and call its wallet bridge.
8. Each child receives only its own clean-room environment and token.
9. Success requires both processes to exit zero, emit parseable terminal JSON with distinct addresses/agent ids, agree on the session id/certificate digest, and report certificate verification plus `paymentMoved:false`.
10. Partial failure, timeout, collision, invalid output, mismatched certificate, or missing evidence exits nonzero and never prints an authorization claim.
11. Retained evidence includes pre/post manifests, redacted final response, usage, public identity/session/certificate/receipt data, and a summary; it excludes raw sessions, environment files, wallet files, tokens, provider keys, and secret canaries.
12. Cleanup removes both role roots after evidence is atomically finalized; `--keep-cleanrooms` is accepted only with an explicit local debug flag and is banned by the production wrapper.

Run and confirm failure:

```bash
node --test test/hermes-launcher.test.mjs test/prompts.test.mjs
```

### 2. Implement the launcher

- Use built-in `fetch`, `spawn`, `Promise.allSettled`, and `AbortController`; add no dependencies.
- Read the reusable inference key from one explicit mode-`0600` file outside the repository or one explicit environment variable. Never search the filesystem for it. Accept exactly one supported Kimi key name.
- Mint exactly two production MCP tokens after both zero-state manifests pass.
- Run both agents concurrently from the Mac mini. Create both child process groups before awaiting either; a timeout or first hard failure terminates both groups. Stream role-prefixed, redacted progress to the operator without exposing tool arguments that may contain secrets.
- Validate terminal JSON independently of prose. Treat any agent narrative as untrusted.
- Finalize evidence before cleanup and re-run the secret-canary scan over every retained byte.

### 3. Verify and commit

```bash
node --test test/wallet-bridge.test.mjs test/hermes-cleanroom.test.mjs test/hermes-launcher.test.mjs test/prompts.test.mjs
node --test test/registration.test.mjs test/private-path.test.mjs test/redact.test.mjs
```

Commit intent: `Turn two blank Hermes instances into one reproducible bilateral run`

Required trailers:

```text
Constraint: One authenticated Mac-mini command must launch two independent agents without a public spawn API
Rejected: A browser start button | it would add an unauthenticated paid-agent control plane
Confidence: high
Scope-risk: broad
Directive: Keep role prompts asymmetric, tokens distinct, and terminal success machine-validated
Tested: launcher, prompts, wallet bridge, clean-room, registration, private-path, and redaction tests
Not-tested: live production MCP run
```

## Task 4: Make host narration follow real protocol artifacts

**Files**

- Modify `bin/clockchain-host.mjs`.
- Modify `src/roles/host.mjs` only to add truthful `PROPOSED` narration before the already-validated acceptance/acknowledgment report.
- Extend `test/clockchain-host.test.mjs`.

### 1. Write RED tests

Add source-contract and behavior tests proving:

1. Generic `say()` never bumps payer or requestor liveness.
2. A neutral `refresh()` republishes `lastPublishedStage ?? SESSION_STARTED`, updates time, and never appends a fabricated stage.
3. Session creation and every identity/funding/registration wait remain at the current real stage.
4. `TERMS_PUBLISHED` occurs exactly once and only after a validated payer mandate.
5. `REQUEST_SUBMITTED` occurs exactly once and only after an actual requestor envelope.
6. Funding is set only after both role-tagged funding records are posted; identities are set only after both `party_ready` records.
7. Observed payer/requestor messages update only the actual wire-role heartbeat (`requestor` maps to monitor `payee`).
8. A complete valid anchor report narrates `PROPOSED`, `ACCEPTED`, then `ACKNOWLEDGED`; malformed reports narrate none.
9. The verifier-to-verdict assignment remains sourced only from `verifyBilateralAuthorization`.

Run and confirm failure:

```bash
node --test test/clockchain-host.test.mjs
```

### 2. Implement the minimal correction

- Remove the automatic payer heartbeat from `say`.
- Add `refresh(sentence, extra)` beside `say`; it logs and republishes the current real stage.
- Replace every setup/wait emission that currently advances `FUNDED`, `IDENTITY_REGISTERED`, `TERMS_PUBLISHED`, `REQUEST_SUBMITTED`, or `EVIDENCE_RECEIVED` before its fact with `refresh`.
- Keep real business emissions after their validated artifacts.
- Bump party heartbeats only when a validated role message is actually observed.
- Do not change the v1 snapshot shape, funding record shape, certificate, verifier, or failure semantics.

### 3. Verify and commit

```bash
node --test test/clockchain-host.test.mjs test/monitor-timeline.test.mjs test/monitor-snapshot.test.mjs
node --test test/monitor-live.test.mjs test/verdict.test.mjs
```

Commit intent: `Make the projector narrate artifacts instead of host waiting loops`

Required trailers:

```text
Constraint: Host narration may describe only evidence already present
Rejected: Reordering the snapshot status vocabulary | the v1 wire contract remains stable
Confidence: high
Scope-risk: moderate
Directive: Never infer party liveness or business stages from host log activity
Tested: host, timeline, snapshot, live-monitor, and verdict tests
Not-tested: production host deployment
```

## Task 5: Drive the bundled relay board from facts, not enum order

**Files**

- Modify `src/monitor/stakeholder/messages.mjs`.
- Extend `test/monitor-timeline.test.mjs`.
- Update `test/monitor-snapshot.test.mjs` only where it asserts enum coverage as progress semantics.

### 1. Write RED tests

Cover:

1. `FUNDED` or `IDENTITY_REGISTERED` without a mandate completes no business row.
2. Terms and request rows use exact stage-history membership.
3. Proposal, acceptance, and acknowledgment rows use their corresponding anchor objects independently.
4. Evidence/verification activates the checker but does not fabricate a verdict.
5. A verdict completes the checker only; it does not backfill absent anchors.
6. `FAILED` marks the first fact-incomplete active row while preserving completed facts.
7. Funding/identity facts drive readiness labels without changing the wire schema.

Run and confirm failure:

```bash
node --test test/monitor-timeline.test.mjs test/monitor-snapshot.test.mjs
```

### 2. Implement fact predicates

- Replace `stepIndexForStatus`, furthest-status selection, and enum-coverage assertions with pure fact derivation from `stageHistory`, `funding`, `identities`, `anchors`, evidence/verification stages, and `verdict`.
- Keep the five existing rows, labels, no-money invariant, failure rendering, and v1 snapshot validator.

### 3. Verify and commit

```bash
node --test test/monitor-timeline.test.mjs test/monitor-snapshot.test.mjs test/monitor-live.test.mjs
npm run verify
```

Commit intent: `Keep the stakeholder board truthful when protocol stages arrive out of order`

Required trailers:

```text
Constraint: The two-agent protocol chronology differs from the legacy enum order
Rejected: Verdict and ordinal backfill | missing artifacts must remain visibly missing
Confidence: high
Scope-risk: moderate
Directive: Complete rows only from their named artifacts
Tested: timeline, snapshot, live-monitor, full tests, and invariant checks
Not-tested: browser visual comparison
```

## Task 6: Document, install, and dry-run the Mac-mini control surface

**Files**

- Create `docs/HERMES-TURNKEY-DEMO.md`.
- Create `scripts/install-hermes-demo-mac-mini.mjs` if an idempotent installer is needed.
- Update `HANDOFF.md` evidence/blocker sections without erasing existing history.

### 1. Write RED documentation contract tests

Extend `test/hosted-stranger-docs.test.mjs` or add `test/hermes-demo-docs.test.mjs` to require:

- one launch command;
- canonical MCP/token/health endpoints;
- Mac-mini path and SSH-only control boundary;
- prerequisites and read-only health checks;
- exact freshness proof and evidence locations;
- rollback/cleanup instructions;
- explicit host/party boundary and `paymentMoved:false`;
- no secrets or legacy profile names.

### 2. Add the operator guide and idempotent install path

- Pin the Handshake commit that agents clone.
- Install under a dedicated Mac-mini directory owned by the operator.
- Keep the inference-key file and evidence root outside the Git checkout with `0600`/`0700` modes.
- Expose one local command that rejects debug retention in production.
- Include a no-token, no-agent health/dry-run mode that validates Hermes version/config, MCP/relay/host health, disk permissions, and the public kit commit.

### 3. Verify and commit

```bash
node --test test/hermes-demo-docs.test.mjs test/hosted-stranger-docs.test.mjs
npm run verify
```

Commit intent: `Make the bilateral demo operable from one authenticated Mac-mini command`

Required trailers:

```text
Constraint: Public pages stay read-only; launch authority remains on the Mac mini
Rejected: Manual profile preparation | it cannot prove freshness or reproduce cleanup
Confidence: high
Scope-risk: narrow
Directive: Keep reusable secrets outside Git and treat evidence retention as public-data only
Tested: documentation contracts and full repository verification
Not-tested: remote installation and live run
```

## Task 7: Integrated gates before deployment

Run from a clean checkout at the final branch commit:

```bash
npm ci
npm run verify
node bin/hermes-demo.mjs --dry-run \
  --kit-commit "$(git rev-parse HEAD)" \
  --evidence-root /absolute/private/test/evidence
```

Then verify the dry-run report proves:

- two disjoint zero-state homes and workspaces;
- no token was minted and no agent was started;
- canonical MCP, relay, and host health passed;
- the exact Hermes binary/version is recorded;
- all retained bytes pass the secret-canary scan.

Do not deploy or call the token endpoint until all local gates pass.

The presenter half of this gate is executed from the companion plan at:

```text
/Users/Kailor/.config/superpowers/worktrees/clockchain-research/hermes-turnkey-demo/docs/superpowers/plans/2026-08-08-two-agent-presenter.md
```

That plan owns the existing `/handshake/claude-v6` source, exact visual characterization, two-agent copy, Vercel deployment, and browser comparison. This repository owns the party runner, host, relay board, and evidence.

## Task 8: Deploy and run the production two-fresh-agent proof

This is a required completion gate, not an optional follow-up.

### 1. Pin and deploy reviewed commits

1. Push the final Handshake branch and record its immutable commit.
2. Deploy the corrected host/relay-board build through the existing AWS path without rotating treasury or relay keys.
3. Complete the companion presenter plan and deploy `/handshake/claude-v6` through the existing Vercel path.
4. Install the reviewed launcher commit under the dedicated Mac-mini operator path.
5. Run read-only health checks for MCP, relay, host, public kit commit, presenter monitor proxy, and Hermes feature contract.

### 2. Run the one real command

From the authenticated Mac-mini operator account, run `node bin/hermes-demo.mjs` without `--dry-run`. The command must:

- capture both `pre-provision` zero-state manifests before token mint;
- mint two distinct production MCP principals and capture secret-free `pre-prompt` manifests after exact five-tool discovery;
- start both standalone Hermes homes concurrently;
- make each agent clone the exact pushed commit and run `npm ci` in its own previously empty workspace;
- create two different wallets and two new ERC-8004 agent ids;
- complete one shared session through both independently owned party-result/evidence uploads;
- return the same host-signed certificate digest to both agents;
- report `paymentMoved:false` and no authorization claim before the verifier verdict;
- finalize sanitized evidence, terminate processes, and remove both disposable role roots.

### 3. Cross-check independent evidence

Do not trust the agents' final prose. Independently verify:

1. Relay records bind distinct payer/requestor addresses and agent ids to the same session.
2. The mandate is payer-owned; the payment request is requestor-owned; both party-result signatures recover their matching role address.
3. Three Clockchain receipts bind the same session and preserve proposal → acceptance → acknowledgment order.
4. The verdict is sourced from the host verifier and the certificate binds the verdict, parties, session digest, and transitions.
5. Both Hermes outputs report the same verified certificate digest.
6. `/handshake/claude-v6` shows Payer and Requestor separately and `Clockchain — session host & independent checker.` without painting any absent artifact as complete.
7. The evidence tree contains no token, provider key, private key, raw `.env`, wallet file, or unsanitized session export.
8. Both disposable trees are absent after cleanup; retained evidence contains their zero-state and post-run public manifests.

### 4. Record the live-gate result

Update `HANDOFF.md` sections `Blockers`, `Evidence`, and the operator waiting list with:

- deployed Handshake/research commits and URLs;
- session id, public addresses, agent ids, receipt block heights/ledger ids, verdict, and certificate digest;
- paths to sanitized manifests, logs, screenshots, and verification output;
- exact cleanup result and any remaining operational risk.

Only after every assertion above passes may the goal be marked complete.
