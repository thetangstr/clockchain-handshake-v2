# Zero-Plugin Live ERC-8004 Agent Handshake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Use `superpowers:test-driven-development` for every behavior change and `superpowers:verification-before-completion` before each gate. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let two people start fresh Codex or Claude Code agents, connect only the public Clockchain Handshake MCP endpoint, copy one invitation from Initiator to Responder, create two local policies and fresh ERC-8004 identities, complete a 90-second non-payment agreement, and independently verify the same certificate while the existing research-page layout displays only proven protocol facts.

**Architecture:** Handshake owns the canonical generic v2 protocol, local policy/signing executable, host/checker, certificate, and public snapshot. MCP exposes a separate rate-limited seven-tool Streamable HTTP surface whose invitation and role capabilities cannot reach the authenticated Clockchain tools. Research keeps the accepted `/handshake/claude-v6` page composition, strictly parses generic v1/v2 snapshots, and derives every visible state from the exact relay or checker artifact that proves it.

**Tech Stack:** Node.js ESM, TypeScript, Zod, MCP Streamable HTTP, EIP-191/viem, ERC-8004 on Sepolia, Ed25519 host certificates, Clockchain ledger receipts, Node Single Executable Applications, Next.js/React/Vitest, Node test runner, Docker Compose/Caddy on AWS, Vercel.

---

## Locked inputs

- Design: `docs/superpowers/specs/2026-08-10-zero-plugin-live-erc8004-agent-handshake-design.md`
- Handshake base: `63401f2`
- MCP base: `bef6066`
- Research base: `f81ea0f`
- Public endpoint: `https://mcp.clockchain.network/handshake/mcp`
- Protocol: `clockchain.agent-handshake/v2`
- Snapshot: `clockchain.agent-handshake-snapshot/v2`
- Demo identity policy: `required_fresh`
- Demo chain: `eip155:11155111`
- ERC-8004 registry: `0x8004a818bfb912233c491871b3d84c89a494bd9e`
- Invitation claim window: 120 seconds
- Host session ceiling: 10 minutes
- Role capability expiry: the immutable host session deadline
- Signed agreement window: 90 seconds from proposal creation
- Host trust: root-signed per-session Ed25519 key; current/previous root ring pinned in the verified helper
- Public v2 funding ceilings: 0.01 Sepolia ETH/address, 0.02/session, 0.20/rolling hour, 1.00/UTC day
- Business invariant: `externalBusinessActionPerformed:false`

The existing authenticated `/mcp`, generic v1 handshake, bilateral payment protocol,
historical browser invitation exchange, and previously certified research runs remain
available and byte-compatible throughout the rollout.

## Review record

- Architecture and cross-repository lifecycle: **APPROVE** after separating helper
  source, published artifacts, post-release pin, and public readiness.
- Security: **APPROVE** after adding the root-signed host session key, exact canonical
  HS256 capabilities, independent Research release pin, atomic funding budgets, and
  concrete client execution boundaries.
- Monitoring/demo acceptance: **APPROVE** for preserved layout, strict v1/v2 parsing,
  exact-artifact progression, complete ERC-8004 detail, readiness gating, and live
  chronology tests.
- Portability reference: Node 24 LTS SEA injection remains active-development; release
  tests follow the current [Node SEA documentation](https://nodejs.org/docs/latest-v24.x/api/single-executable-applications.html).

No product implementation starts until this plan is approved by the stakeholder.

## Execution worktrees

Create fresh worktrees before Task 0; do not implement in the plan-only worktree.

```bash
git -C /Volumes/mac_studio_ssd/Projects/handshake worktree add \
  /Users/Kailor/.config/superpowers/worktrees/handshake/zero-plugin-live-erc8004 \
  -b codex/zero-plugin-live-erc8004 63401f2

git -C /Volumes/home/Projects_Hosted/clockchain-developer-tools worktree add \
  /Users/Kailor/.config/superpowers/worktrees/clockchain-developer-tools/zero-plugin-live-erc8004 \
  -b codex/zero-plugin-live-erc8004 bef6066

git -C /Volumes/home/Projects_Hosted/clockchain-research worktree add \
  /Users/Kailor/.config/superpowers/worktrees/clockchain-research/zero-plugin-live-erc8004 \
  -b codex/zero-plugin-live-erc8004 f81ea0f
```

Use these variables in the commands below:

```bash
HANDSHAKE=/Users/Kailor/.config/superpowers/worktrees/handshake/zero-plugin-live-erc8004
MCP=/Users/Kailor/.config/superpowers/worktrees/clockchain-developer-tools/zero-plugin-live-erc8004
RESEARCH=/Users/Kailor/.config/superpowers/worktrees/clockchain-research/zero-plugin-live-erc8004
```

## Gate sequence

1. **C0 — Compatibility frozen:** v1/bilateral wire digests and accepted page layout are locked by tests.
2. **C1 — Canonical v2:** policy, identity, statement, transitions, evidence, checker, and certificate are mutation-tested.
3. **C2 — Host truth:** all three identity policies work; fresh registration and 90-second terms fail closed.
4. **C3 — Public MCP boundary:** the endpoint exposes exactly seven tools and capabilities cannot cross role, session, statement, tool, or expiry boundaries.
5. **C4 — Portable local authority:** signed release assets work without Node, npm, a clone, or global Clockchain state.
6. **C5 — Monitor truth:** v1/v2 coexist, every row is artifact-derived, full ERC-8004 details render, and the certified-run fallback survives.
7. **C6 — Fresh clients:** Codex→Claude and Claude→Codex both finish from the exact two stakeholder prompts.
8. **C7 — Production:** release, host, MCP, and Research deploy in that order; production canaries pass before announcement.

---

### Task 0: Freeze compatibility and accepted presentation

**Handshake files:**
- Create: `test/fixtures/agent-handshake-v1-wire.json`
- Create: `test/fixtures/bilateral-wire-digests.json`
- Create: `test/zero-plugin-compatibility.test.mjs`

**MCP files:**
- Create: `test/fixtures/agent-handshake-v1-tool-contract.json`
- Create: `test/agent-handshake-v1-compatibility.test.mjs`

**Research files:**
- Create: `src/lib/claude-v6-layout-contract.test.tsx`
- Create: `src/lib/fixtures/agent-handshake-v1-snapshot.json`

- [ ] **Step 1: Capture immutable v1 and bilateral fixtures from the authoritative bases**

The Handshake fixture stores canonical base64url bytes and SHA-256 digests for one
valid v1 statement, proposal, acceptance, acknowledgment, descriptor, both evidence
packages, and result certificate. The MCP fixture stores exact v1 tool names and JSON
schemas. Do not hand-edit captured digests.

- [ ] **Step 2: Lock the accepted page shell before any narrative work**

`claude-v6-layout-contract.test.tsx` must assert the current two-column container,
sticky live-monitor width, runbook section order, evidence drawers, and route path.
It must not assert old business copy.

- [ ] **Step 3: Run the three baselines**

```bash
cd "$HANDSHAKE" && npm ci && npm run verify
cd "$MCP/packages/mcp-server" && npm ci && npm test
cd "$MCP" && node --test infra/test/*.test.mjs
cd "$RESEARCH" && npm ci && npm run typecheck && npm test
```

Expected: all authoritative baselines pass before new RED tests are added.

- [ ] **Step 4: Run the compatibility tests**

```bash
cd "$HANDSHAKE" && node --test test/zero-plugin-compatibility.test.mjs
cd "$MCP/packages/mcp-server" && node --test test/agent-handshake-v1-compatibility.test.mjs
cd "$RESEARCH" && npx vitest run src/lib/claude-v6-layout-contract.test.tsx
```

Expected: PASS and no product-code diff.

- [ ] **Step 5: Commit each repository independently**

Intent line: `Freeze the production contract before adding agent-native v2`

Trailers:

```text
Constraint: Existing generic v1, bilateral bytes, and accepted page layout must remain reproducible.
Rejected: Relying on broad regression suites alone | they do not pin public bytes or layout seams.
Confidence: high
Scope-risk: narrow
Directive: Update these fixtures only through an explicit protocol-version or presentation decision.
Tested: Repository baseline plus the new compatibility fixture tests.
Not-tested: Generic v2 behavior begins in later tasks.
```

---

### Task 1: Add exact generic v2 terms, policy, and party identity

**Files:**
- Create: `src/agent-handshake/v2/constants.mjs`
- Create: `src/agent-handshake/v2/terms.mjs`
- Create: `src/agent-handshake/v2/policy.mjs`
- Create: `src/agent-handshake/v2/party.mjs`
- Create: `test/agent-handshake-v2-terms.test.mjs`
- Create: `test/agent-handshake-v2-policy.test.mjs`
- Create: `test/agent-handshake-v2-party.test.mjs`
- Modify: `test/zero-plugin-compatibility.test.mjs`

- [ ] **Step 1: Write RED exact-key and canonical-byte tests**

Cover the three ERC-8004 values, exact Sepolia chain/registry pairing, decimal-string
`validForSeconds`, maximum 90 seconds for the demo profile, lowercase addresses,
decimal agent ids and blocks, transaction hashes, CAIP-10-style references, optional
`erc8004:null`, and the local policy shown in the design. The two required modes demand
the exact chain/registry strings; `not_required` demands `chainId:null` and
`registryAddress:null`.

```js
assert.deepEqual(validateIdentityPolicy({
  erc8004: "required_fresh",
  chainId: "eip155:11155111",
  registryAddress: REGISTRY,
}), expectedPolicy);

assert.equal(
  digestHex(canonicalBytes(validateLocalPolicy(policy))),
  expectedPolicyDigest,
);
```

Mutation cases must add/remove/rename every key and change role, protocol, origin,
reference, statement digest, duration, identity policy, and
`externalBusinessActionsAllowed` independently.

- [ ] **Step 2: Run RED**

```bash
cd "$HANDSHAKE" && node --test \
  test/agent-handshake-v2-terms.test.mjs \
  test/agent-handshake-v2-policy.test.mjs \
  test/agent-handshake-v2-party.test.mjs
```

Expected: FAIL because the v2 modules do not exist.

- [ ] **Step 3: Implement without modifying v1 modules**

Export frozen schemas and validators from `src/agent-handshake/v2`. Reuse only
existing canonical JSON, digest, address, and exact-key primitives. Do not map v2
terms into a v1 or bilateral object. The forbidden public vocabulary scan must reject
`amount`, `currency`, `invoice`, `payment_request`, `payer`, `payee`, `requestor`,
and `paymentMoved` from every canonical v2 byte payload.

- [ ] **Step 4: Run GREEN and C0 regressions**

```bash
cd "$HANDSHAKE" && node --test \
  test/agent-handshake-v2-terms.test.mjs \
  test/agent-handshake-v2-policy.test.mjs \
  test/agent-handshake-v2-party.test.mjs \
  test/zero-plugin-compatibility.test.mjs
```

Expected: PASS; fixture digests unchanged.

- [ ] **Step 5: Commit**

Intent line: `Bind each agent to exact non-payment terms and local policy`

Trailers:

```text
Constraint: V2 must support optional ERC-8004 generally while the demo requires two fresh registrations.
Rejected: Extending v1 objects in place | it would mutate production evidence and retain minute-based semantics.
Confidence: high
Scope-risk: moderate
Directive: Keep policyDigest in every later party-signed v2 artifact.
Tested: V2 terms, policy, party mutations and C0 wire fixtures.
Not-tested: Transitions, host funding, and live registration land later.
```

---

### Task 2: Add v2 transitions, descriptor, evidence, checker, and certificate

**Files:**
- Create: `src/agent-handshake/v2/protocol.mjs`
- Create: `src/agent-handshake/v2/descriptor.mjs`
- Create: `src/agent-handshake/v2/evidence.mjs`
- Create: `src/agent-handshake/v2/verdict.mjs`
- Create: `src/agent-handshake/v2/result.mjs`
- Create: `src/agent-handshake/v2/host-key-certificate.mjs`
- Create: `test/agent-handshake-v2-protocol.test.mjs`
- Create: `test/agent-handshake-v2-descriptor.test.mjs`
- Create: `test/agent-handshake-v2-evidence.test.mjs`
- Create: `test/agent-handshake-v2-verdict.test.mjs`
- Create: `test/agent-handshake-v2-result.test.mjs`
- Create: `test/agent-handshake-v2-host-key-certificate.test.mjs`
- Modify: `test/mandate-invariants.test.mjs`

- [ ] **Step 1: Write RED mutation suites**

Require one ordered proposal → acceptance → acknowledgment chain, exact predecessor
digests, exact statement and policy digests, distinct session keys and ERC-8004 ids,
host-signed descriptor, two independent evidence packages, one positive checker
emission site, and one Ed25519 closing certificate. Require the per-session Ed25519
host key to carry a root-signed `clockchain.host-session-key/v1` certificate binding
root `kid`, session, repository SHA, public key, and a validity interval no longer than
the host session.

Add validly signed negative cases for wrong session, host key, root key/fingerprint,
unknown or stale `kid`, not-yet-valid or expired session-key certificate, role, party, policy,
statement, identity mode, registry, fresh-registration block, receipt, outcome, and
`externalBusinessActionPerformed:true`.

- [ ] **Step 2: Run RED**

```bash
cd "$HANDSHAKE" && node --test test/agent-handshake-v2-{protocol,descriptor,evidence,verdict,result,host-key-certificate}.test.mjs
```

Expected: FAIL on missing modules.

- [ ] **Step 3: Implement by composing existing cryptographic primitives**

The host root signs only the bounded session-key certificate. The resulting session
key may sign only the descriptor and final result. Initiator signs identity,
proposal, and its evidence. Responder signs identity, acceptance, and its evidence.
Acknowledgment remains a protocol/ledger transition; do not invent a third party
signature. Certificate verification pins host key, session, party address, policy
digest, positive outcome, and the external-action invariant.

- [ ] **Step 4: Run GREEN, invariants, and legacy certificate regressions**

```bash
cd "$HANDSHAKE" && node --test \
  test/agent-handshake-v2-{protocol,descriptor,evidence,verdict,result,host-key-certificate}.test.mjs \
  test/agent-handshake-{protocol,descriptor,evidence,verdict,result}.test.mjs \
  test/zero-plugin-compatibility.test.mjs test/mandate-invariants.test.mjs
```

Expected: PASS and exactly one v2 positive verdict emission site.

- [ ] **Step 5: Commit**

Intent line: `Make the agent agreement independently verifiable end to end`

Trailers:

```text
Constraint: Clockchain coordinates and checks but never signs for either stakeholder.
Rejected: Treating certificate presence as proof of missing intermediate artifacts | every binding is verified directly.
Confidence: high
Scope-risk: moderate
Directive: Preserve distinct party authority and the no-external-action invariant.
Tested: Full v2 mutation suites, invariants, v1 generic and bilateral certificate regressions.
Not-tested: Production host and ledger integration begin next.
```

---

### Task 3: Make the host enforce identity policy and truthful timing

**Files:**
- Create: `src/agent-handshake/v2/host.mjs`
- Create: `src/agent-handshake/v2/production-adapter.mjs`
- Create: `src/agent-handshake/v2/funding-budget.mjs`
- Create: `src/agent-handshake/v2/host-root.mjs`
- Modify: `bin/agent-handshake-host.mjs`
- Create: `test/agent-handshake-v2-host.test.mjs`
- Create: `test/agent-handshake-v2-production-adapter.test.mjs`
- Create: `test/agent-handshake-v2-funding-budget.test.mjs`
- Create: `test/agent-handshake-v2-host-root.test.mjs`
- Modify: `test/agent-handshake-host.test.mjs`

- [ ] **Step 1: Write RED branch and chronology tests**

Test `required_fresh`, `required_existing_or_fresh`, and `not_required` separately.
For `required_fresh`, assert the host funds only the exact claimed session-key
address, accepts only a registry ownership transfer after session creation, resolves
`ownerOf(agentId)` to that address, and posts a role-tagged funding record. Reject a
pre-existing id, same id/address for both roles, wrong chain/registry, reordered
funding record, late registration, and ambiguous recovery checkpoint.

Assert the host session expires after 10 minutes but proposal terms expire exactly
90 seconds after proposal creation, not session creation. Freeze the old 45-minute
v1 path. Both role capabilities expire at the immutable session deadline so certificate
retrieval remains possible after the 90-second agreement window without extending the
session.

Reserve funding atomically before either transfer: 0.01 Sepolia ETH per address once,
0.02 per `required_fresh` session, 0.20 per rolling hour, and 1.00 per UTC day. Test
restart recovery, concurrent reservations, duplicate address/session, queue
backpressure, and exhaustion before the first transfer. Require the host root to sign
the session-key certificate before discovery is published; reject missing, malformed,
or weak root-key configuration.

- [ ] **Step 2: Run RED**

```bash
cd "$HANDSHAKE" && node --test \
  test/agent-handshake-v2-host.test.mjs \
  test/agent-handshake-v2-production-adapter.test.mjs \
  test/agent-handshake-v2-funding-budget.test.mjs \
  test/agent-handshake-v2-host-root.test.mjs
```

Expected: FAIL because v2 host dispatch and identity branches are missing.

- [ ] **Step 3: Implement an explicit protocol dispatcher**

Keep the v1 host unchanged. Route only `clockchain.agent-handshake/v2` sessions to
the new adapter. Reuse relay, repository-provenance, funding, ERC-8004 lookup,
ledger-anchor, evidence-storage, checker, and result-publishing ports. Host narration
must never advance the public stage or a party heartbeat; only validated artifacts do.
Load the active host root from its existing protected configuration boundary, create
one bounded session-key certificate, and persist only the public certificate. Persist
the funding reservation ledger mode 0600 and alert before global ceilings.

- [ ] **Step 4: Run GREEN and host regressions**

```bash
cd "$HANDSHAKE" && node --test \
  test/agent-handshake-v2-host.test.mjs \
  test/agent-handshake-v2-production-adapter.test.mjs \
  test/agent-handshake-v2-funding-budget.test.mjs \
  test/agent-handshake-v2-host-root.test.mjs \
  test/agent-handshake-host.test.mjs test/clockchain-host.test.mjs \
  test/zero-plugin-compatibility.test.mjs
```

Expected: PASS with v1 defaults unchanged.

- [ ] **Step 5: Commit**

Intent line: `Fund and verify only the identity mode the initiator mandated`

Trailers:

```text
Constraint: Fresh testnet registration may take longer than the 90-second signed agreement window.
Rejected: Starting agreement expiry at session creation | registration latency would invalidate honest runs.
Confidence: high
Scope-risk: broad
Directive: Keep session, invitation, and signed-agreement clocks independent.
Tested: All identity-policy branches, funding tags, registration chronology, host and v1 regressions.
Not-tested: Live Sepolia and AWS host are production-gate work.
```

---

### Task 4: Publish a strict artifact-based generic v2 snapshot

**Files:**
- Create: `src/monitor/agent-snapshot-v2.mjs`
- Modify: `src/relay/server.mjs`
- Create: `test/monitor-agent-snapshot-v2.test.mjs`
- Modify: `test/relay.test.mjs`
- Modify: `test/monitor-live.test.mjs`

- [ ] **Step 1: Write RED exact-shape snapshot tests**

The public snapshot must include session/version/timing facts, host root `kid` and
fingerprint, host session key and session-key certificate digest, invitation-created and
claimed timestamps, both policy digests, both session-key addresses, complete optional
ERC-8004 registrations, proposal/acceptance digests, each of the three receipt objects,
both evidence receipts, checker stage, verdict, certificate digest/time, independent
role/host/checker freshness, and `externalBusinessActionPerformed:false`.

Reject raw invitation, role access, private key, signature, private path, provider
credential, funding credential, unknown key, partial nested object, non-canonical id,
and top-level schema coercion.

- [ ] **Step 2: Run RED**

```bash
cd "$HANDSHAKE" && node --test \
  test/monitor-agent-snapshot-v2.test.mjs \
  test/relay.test.mjs test/monitor-live.test.mjs
```

Expected: FAIL because the v2 snapshot producer and relay branch are missing.

- [ ] **Step 3: Implement a separate v2 producer and strict relay routing**

Do not rename v1 fields or map v2 through bilateral payment status. Each artifact is
nullable until observed. Stage history is descriptive only; it is not evidence for a
missing receipt, registration, policy, or certificate. Heartbeats affect freshness
labels only.

- [ ] **Step 4: Run GREEN and snapshot compatibility**

```bash
cd "$HANDSHAKE" && node --test \
  test/monitor-agent-snapshot-v2.test.mjs \
  test/agent-handshake-snapshot.test.mjs \
  test/monitor-snapshot.test.mjs \
  test/relay.test.mjs test/monitor-live.test.mjs
```

Expected: PASS for bilateral, generic v1, and generic v2.

- [ ] **Step 5: Commit**

Intent line: `Let the monitor witness artifacts without inventing progress`

Trailers:

```text
Constraint: Stakeholders must see fresh registration and receipts as public facts without seeing capabilities or keys.
Rejected: Reusing ordinal stage completion | later states can falsely backfill missing proof.
Confidence: high
Scope-risk: moderate
Directive: Add a visible completion only when its exact artifact exists.
Tested: Exact v2 snapshot mutations, relay routing, live monitor and v1/bilateral snapshot regressions.
Not-tested: Research parsing and rendering land in Tasks 12 and 13.
```

---

### Task 5: Build the self-contained local policy and signing executable

**Files:**
- Create: `src/agent-cli/policy.mjs`
- Create: `src/agent-cli/signing-request.mjs`
- Create: `src/agent-cli/operations.mjs`
- Create: `src/agent-cli/trust-roots.mjs`
- Create: `src/agent-cli/main.mjs`
- Create: `bin/clockchain-agent-handshake.mjs`
- Modify: `src/core/wallet-bridge.mjs`
- Modify: `src/core/registration.mjs`
- Modify: `src/core/private-path.mjs`
- Create: `test/agent-cli-policy.test.mjs`
- Create: `test/agent-cli-signing-request.test.mjs`
- Create: `test/agent-cli-operations.test.mjs`
- Create: `test/agent-cli-security.test.mjs`
- Create: `test/agent-cli-trust-roots.test.mjs`

- [ ] **Step 1: Write RED fail-closed local-authority tests**

Test `init`, `policy`, `inspect`, `register`, `sign`, and `verify-certificate` through
the CLI entry point. Require mode-0700 directory, mode-0600 state/checkpoint,
exclusive creation, fresh key, durable registration recovery, exact decompressed byte
digest, local policy match, root-signed host-session-key certificate,
host/session/role binding, generic stderr, and public JSON
stdout. Assert no private key, role access, raw invitation, signature input, or path is
ever printed.

The signing spy must remain untouched for every wrong statement, duration, identity
policy, host key, unpinned root/fingerprint, unknown/stale/not-yet-valid `kid`, invalid
session-key certificate, session, role, helper version, schema, operation, byte digest,
or external-action flag.

- [ ] **Step 2: Run RED**

```bash
cd "$HANDSHAKE" && node --test \
  test/agent-cli-policy.test.mjs \
  test/agent-cli-signing-request.test.mjs \
  test/agent-cli-operations.test.mjs \
  test/agent-cli-security.test.mjs \
  test/agent-cli-trust-roots.test.mjs
```

Expected: FAIL because the public CLI does not exist.

- [ ] **Step 3: Implement by reusing the existing bridge and registration code**

Do not create another wallet or registration algorithm. Wrap
`src/core/wallet-bridge.mjs`, `src/core/registration.mjs`, canonical v2 validators,
and v2 result verification behind an exact operation dispatcher. Remove any caller-
controlled RPC, registry, download, updater, plugin, telemetry, or general-command
surface from the stakeholder CLI. Embed the reviewed current/previous host-root public
keys and fingerprints; verify the root-signed session-key certificate before accepting
any signing request or closing certificate. An MCP-returned key never expands this
embedded ring.

- [ ] **Step 4: Run GREEN and bridge regressions**

```bash
cd "$HANDSHAKE" && node --test \
  test/agent-cli-*.test.mjs \
  test/wallet-bridge.test.mjs test/registration.test.mjs \
  test/private-path.test.mjs test/redact.test.mjs
```

Expected: PASS; existing bridge consumers remain compatible.

- [ ] **Step 5: Commit**

Intent line: `Keep each stakeholder key and signing policy local`

Trailers:

```text
Constraint: Fresh Codex and Claude Code agents need local authority without a plugin, wallet UI, or repository clone.
Rejected: Letting MCP sign or returning shell snippets | either crosses the party-authority boundary.
Confidence: high
Scope-risk: broad
Directive: All local signatures must pass the exact policy and signing-request validator.
Tested: CLI operation, mutation, secret-leak, wallet, registration, private-path, and redaction suites.
Not-tested: Packed platform assets land next.
```

---

### Task 6: Produce pinned release assets and an npm developer fallback

**Files:**
- Create: `scripts/build-agent-handshake-release.mjs`
- Create: `scripts/verify-agent-handshake-release.mjs`
- Create: `scripts/build-agent-handshake-npm.mjs`
- Create: `release/agent-handshake/manifest.schema.json`
- Create: `release/agent-handshake/pin.schema.json`
- Modify: `release.json`
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `.github/workflows/agent-handshake-cli-release.yml`
- Create: `test/agent-cli-release.test.mjs`
- Create: `test/agent-cli-clean-platform.test.mjs`

- [ ] **Step 1: Write RED manifest, reproducibility, and clean-platform tests**

Require exact manifest keys: version, source commit, Node runtime, platform, arch,
upstream-support status, asset URL, byte length, SHA-256, native-signature metadata,
and manifest digest. Reject duplicate platforms, relative/network-redirecting URLs,
digest disagreement, extra keys, unsigned macOS/Windows production assets, source SHA
mismatch, and runtime dependency discovery. The macOS x64 entry must state
`clockchain_verified` and carry an actual Intel-Mac execution record; it must not claim
upstream SEA coverage. The bundler metafile must show one entry graph, the pinned
`viem` tree, allowed Node built-ins, no dynamic import, and no runtime filesystem
package lookup. The source-build commit must not contain its future manifest digest.
The later release pin must allow only
`https://github.com/thetangstr/clockchain-handshake-v2/releases/download/` asset URLs
and must include the embedded host-root `kid` and fingerprints.

- [ ] **Step 2: Run RED**

```bash
cd "$HANDSHAKE" && node --test \
  test/agent-cli-release.test.mjs \
  test/agent-cli-clean-platform.test.mjs
```

Expected: FAIL because release build and manifest verification do not exist.

- [ ] **Step 3: Implement the pinned Node 24 LTS SEA injection sequence per target**

Pin `esbuild@0.28.2` with registry integrity
`sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==`
and `postject@1.0.0-alpha.6` with registry integrity
`sha512-b9Eb8h2eVqNE8edvKdwqkrY6O7kAwmI8kcnBv1NScolYJbo59XUF0noFq+lxbC1yN20bmC0WBEbDC5H/7ASb0A==`
as build-only dependencies. Bundle only the CLI dependency graph into one auditable
CommonJS entry and fail on unexpected external or dynamic imports; generate the SEA
blob with `useCodeCache:false` and `useSnapshot:false`; remove any existing platform
signature; inject into the exact matching Node 24 LTS executable; apply required
platform fixups; then sign the final macOS/Windows asset. Build and execute each
architecture on a matching trusted runner or native verification host. Generate the
manifest only after all final binaries are signed, verified, and hashed. The workflow
attaches the manifest and the four upstream-covered assets to one immutable version
tag; it adds macOS x64 only when the Intel-Mac gate passes.

Build `@clockchain/agent-handshake@2.1.0` from the same entry point as a developer
fallback with npm provenance. Its public outputs must match the SEA fixtures.

- [ ] **Step 4: Run GREEN and commit the source/build pipeline without a manifest pin**

```bash
cd "$HANDSHAKE" && npm run agent-cli:release:verify
cd "$HANDSHAKE" && node --test \
  test/agent-cli-release.test.mjs \
  test/agent-cli-clean-platform.test.mjs \
  test/agent-cli-*.test.mjs
```

Expected: PASS. Retained evidence records platform, upstream-support status, version,
manifest digest, asset digest, native signature result, exit code, and public output
only.

- [ ] **Step 5: Publish immutable assets from that exact source commit**

The manifest names the already-created helper source commit. Verify final downloads,
native signatures, byte lengths, hashes, platform execution, and npm provenance before
computing the final manifest digest. Do not amend the source commit after publication.

- [ ] **Step 6: Create and test a separate post-release pin commit**

Update `release.json` with helper version `2.1.0`, source commit, exact manifest digest,
exact asset prefix, supported platform records, and current/previous host-root `kid`
and fingerprints. Add a test that recomputes the manifest digest from the published
bytes and rejects any mismatch. MCP and Research Tasks 9 and 13 must consume this pin
commit; they may not copy values from an uncommitted workspace.

- [ ] **Step 7: Commit the two lifecycle states separately**

Source/build intent line: `Make local agent authority portable without a runtime install`

Trailers:

```text
Constraint: Stakeholder machines may have neither Node nor npm.
Rejected: Npm-only installation | it is not portable to a fresh native agent environment.
Confidence: high
Scope-risk: broad
Directive: Build, execute, sign, and hash each SEA asset on its matching trusted platform before publishing the manifest; label macOS x64 as Clockchain-verified only.
Tested: Manifest mutations, clean-platform execution, CLI parity, native signature, and release verification.
Not-tested: Public download and native notarization are production release gates.
```

Post-release pin intent line: `Pin the independently published helper for agent use`

```text
Constraint: An artifact cannot contain the digest of a manifest that names that artifact's future source commit.
Rejected: Amending the helper commit with its own release digest | it creates a circular and unverifiable build identity.
Confidence: high
Scope-risk: narrow
Directive: MCP and Research consume only this reviewed post-release pin commit.
Tested: Published manifest digest, asset host prefix, source commit, platform records, and host-root fingerprints.
Not-tested: Public endpoint and Research consumption land in later tasks.
```

---

### Task 7: Port canonical v2 validators into MCP with byte parity

**Files (MCP):**
- Create: `packages/mcp-server/src/agent-handshake/v2/protocol.ts`
- Create: `packages/mcp-server/test/agent-handshake-v2-protocol.test.mjs`
- Create: `packages/mcp-server/test/fixtures/agent-handshake-v2-canonical.json`
- Modify: `packages/mcp-server/test/agent-handshake-v1-compatibility.test.mjs`

- [ ] **Step 1: Export canonical fixtures from Handshake Task 2**

The fixture contains valid objects, canonical bytes, and digests for terms, policy,
party, identity claim, proposal, acceptance, evidence, descriptor, and certificate.
Copy the fixture mechanically into MCP and record its Handshake source commit.

- [ ] **Step 2: Write RED TypeScript parity and mutation tests**

Assert byte/digest equality with Handshake and the same exact-key rejections.

- [ ] **Step 3: Run RED**

```bash
cd "$MCP/packages/mcp-server" && npm run build && \
  node --test test/agent-handshake-v2-protocol.test.mjs
```

Expected: FAIL because the v2 port is missing.

- [ ] **Step 4: Implement the minimal TypeScript port and run GREEN**

Do not duplicate signing or checker authority in MCP. Port only validation,
canonicalization, digesting, and signing-request construction required by the
coordinator.

```bash
cd "$MCP/packages/mcp-server" && npm run build && node --test \
  test/agent-handshake-v2-protocol.test.mjs \
  test/agent-handshake-v1-compatibility.test.mjs
```

- [ ] **Step 5: Commit**

Intent line: `Give MCP a byte-faithful view of the agent agreement`

Trailers:

```text
Constraint: The coordinator may validate protocol bytes but may never become a party signer.
Rejected: Reconstructing Handshake objects approximately | one-byte drift breaks signatures.
Confidence: high
Scope-risk: moderate
Directive: Regenerate parity fixtures only from a reviewed Handshake source commit.
Tested: Cross-repository canonical-byte parity, mutations, and v1 compatibility.
Not-tested: Public transport and capability authorization land next.
```

---

### Task 8: Add single-use invitation and role-scoped public capabilities

**Files (MCP):**
- Create: `packages/mcp-server/src/agent-handshake/v2/access.ts`
- Create: `packages/mcp-server/src/agent-handshake/v2/invitation-store.ts`
- Create: `packages/mcp-server/test/agent-handshake-v2-access.test.mjs`
- Create: `packages/mcp-server/test/agent-handshake-v2-invitation-store.test.mjs`
- Modify: `packages/mcp-server/src/config.ts`
- Modify: `packages/mcp-server/test/config.test.mjs`

- [ ] **Step 1: Write RED capability-boundary tests**

Cover the exact encoding
`base64url(canonical-json).base64url(hmac-sha256)` without padding. Require payload
keys `v`, `alg:"HS256"`, `typ:"clockchain-agent-handshake-role-access"`,
`iss:"https://mcp.clockchain.network"`, `aud:"clockchain-agent-handshake"`, active or
previous `kid`, UUID `jti`, session id, role, statement digest, exact allowed-tool
array, decimal-string `nbfMs`, and decimal-string `expMs`. Require `expMs` to equal the
immutable host session deadline for both roles.

Reject unknown/extra key, alg, typ, issuer, audience, `kid`, tamper, non-canonical or
padded encoding, replay, second claim, wrong role, wrong session, wrong statement,
unlisted tool, early use, expiry, clock skew beyond the fixed bound, signature from
another secret, weak secret, raw-secret persistence, and concurrent double claim.
Verify HMAC-SHA256 with `crypto.timingSafeEqual`; accept only active/previous SSM keys
of at least 32 uniformly random bytes. Derive the coordinator principal only from
SHA-256 of a fully verified access value.

- [ ] **Step 2: Run RED**

```bash
cd "$MCP/packages/mcp-server" && npm run build && node --test \
  test/agent-handshake-v2-access.test.mjs \
  test/agent-handshake-v2-invitation-store.test.mjs
```

- [ ] **Step 3: Implement v2 alongside the existing v3 browser token path**

Use a distinct signing domain and storage namespace. Persist mode-0600 digests and
public claim metadata only. Invitation creation yields Initiator access plus one public
Responder invitation; atomic acceptance yields a different Responder access. Neither
value authorizes authenticated `/mcp`. Rotation accepts current and previous keys only
for already-unexpired sessions and never extends `expMs`.

- [ ] **Step 4: Run GREEN and old invitation/token regressions**

```bash
cd "$MCP/packages/mcp-server" && npm run build && node --test \
  test/agent-handshake-v2-{access,invitation-store}.test.mjs \
  test/agent-handshake-invitation-store.test.mjs test/token.test.mjs
```

- [ ] **Step 5: Commit**

Intent line: `Let one copied invitation create two non-transferable roles`

Trailers:

```text
Constraint: Stakeholders must not obtain or share a general Clockchain MCP credential.
Rejected: Reusing one token for both agents | it collapses principal and role independence.
Confidence: high
Scope-risk: broad
Directive: Raw invitations and role access values must never be logged or persisted.
Tested: Tamper, replay, role/session/statement/tool/expiry scope, concurrency, and v1 token regressions.
Not-tested: HTTP exposure and rate limiting land next.
```

---

### Task 9: Expose a dedicated seven-tool Streamable HTTP surface

**Files (MCP):**
- Create: `packages/mcp-server/src/agent-handshake/v2/instructions.ts`
- Create: `packages/mcp-server/src/agent-handshake/v2/public-tools.ts`
- Create: `packages/mcp-server/src/agent-handshake/v2/public-server.ts`
- Modify: `packages/mcp-server/src/http.ts`
- Modify: `packages/mcp-server/src/landing.ts`
- Create: `packages/mcp-server/test/agent-handshake-v2-public-server.test.mjs`
- Modify: `packages/mcp-server/test/http.test.mjs`
- Modify: `packages/mcp-server/test/product-surface.test.mjs`

- [ ] **Step 1: Write RED inventory, initialization, and abuse tests**

Assert `/handshake/mcp` is handled before full-surface authentication, lists exactly
the seven locked tool names, returns the complete safety-critical instructions during
initialize, refuses all authenticated/full-surface tools, accepts no BYO gateway
headers, and exposes no resources or prompts. Test 5 invitations/IP/hour and 120 tool
calls/IP/minute with deterministic clocks; reject spoofed forwarding headers unless
the direct peer is the configured trusted proxy. The first 512 instruction characters
must contain the local-signing boundary, exact helper version, post-release manifest
digest, allowed asset prefix, embedded host-root `kid`/fingerprints, and stop-on-
disagreement rule. Assert no tool uses MCP elicitation or
`requiresUserInteraction:true`.

- [ ] **Step 2: Run RED**

```bash
cd "$MCP/packages/mcp-server" && npm run build && node --test \
  test/agent-handshake-v2-public-server.test.mjs \
  test/http.test.mjs test/product-surface.test.mjs
```

- [ ] **Step 3: Implement a distinct MCP server instance**

Name it `clockchain-agent-handshake`. Pass client-neutral `instructions` through the
SDK constructor. Register only `agent_handshake_invite`,
`agent_handshake_accept_invitation`, `agent_handshake_join`,
`agent_handshake_status`, `agent_handshake_next`, `agent_handshake_submit`, and
`agent_handshake_get_certificate`. Keep the current `/mcp`, `/token`, `/promote`,
landing, manifest, and browser exchange behavior unchanged.

Add `/.well-known/agent-handshake.json` with exact endpoint, protocol, helper version,
post-release manifest digest, allowed asset prefix, current/previous host-root `kid`
and fingerprints, supported clients, and no credential. Read all pin values from the
reviewed Handshake post-release pin commit; fail startup on a partial or mismatched pin.

- [ ] **Step 4: Run GREEN and the full MCP HTTP surface suite**

```bash
cd "$MCP/packages/mcp-server" && npm run build && node --test \
  test/agent-handshake-v2-public-server.test.mjs \
  test/http.test.mjs test/product-surface.test.mjs test/handshake-tools.test.mjs
```

- [ ] **Step 5: Commit**

Intent line: `Expose only the handshake surface to fresh agent clients`

Trailers:

```text
Constraint: The endpoint is public so its authority must be capability-scoped and its tool inventory minimal.
Rejected: Opening the authenticated MCP server without a token | unrelated tools would become public.
Confidence: high
Scope-risk: broad
Directive: Keep /handshake/mcp routing, limits, instructions, and tool registry independent from /mcp.
Tested: Exact inventory, initialization instructions, rate limits, proxy trust, and full-surface regressions.
Not-tested: Role workflow implementation lands next.
```

---

### Task 10: Implement the v2 public coordinator and compact signing loop

**Files (MCP):**
- Create: `packages/mcp-server/src/agent-handshake/v2/coordinator.ts`
- Modify: `packages/mcp-server/src/agent-handshake/v2/public-tools.ts`
- Create: `packages/mcp-server/test/agent-handshake-v2-coordinator.test.mjs`
- Modify: `packages/mcp-server/test/agent-handshake-v2-public-server.test.mjs`

- [ ] **Step 1: Write RED state-machine tests**

Exercise invite → accept → join → identity claim → tagged funding → optional
registration → party ready → proposal/acceptance → three anchors → two evidence
packages → certificate. Test both role orders and all three identity policies. Assert
the same role access is required throughout, role principals remain distinct, the
root-signed host session-key certificate, host public key, and session are stable, and
`gzip-base64url` reduces only transport, not signed bytes. The join response must not
label an MCP-returned public key as a trust root.

Reject every out-of-order, duplicate, wrong-role, wrong-policy-digest, stale,
different-principal, reused-address, reused-agent-id, bad-registration-block, changed
helper version or manifest pin, unpinned root `kid`/fingerprint, invalid host session-
key certificate, and closing-certificate binding case.

- [ ] **Step 2: Run RED**

```bash
cd "$MCP/packages/mcp-server" && npm run build && node --test \
  test/agent-handshake-v2-coordinator.test.mjs
```

- [ ] **Step 3: Implement using existing relay and gateway ports**

Do not reimplement mailbox, ledger, registration lookup, or certificate verification.
The coordinator returns typed local signing requests and registration requirements,
never executable shell. It stores only public state and role-access digests. It waits
when the other role or host owns the next transition.

- [ ] **Step 4: Run GREEN and all generic/bilateral coordinator regressions**

```bash
cd "$MCP/packages/mcp-server" && npm run build && node --test \
  test/agent-handshake-v2-coordinator.test.mjs \
  test/agent-handshake-coordinator.test.mjs \
  test/handshake-coordinator.test.mjs \
  test/agent-handshake-v2-public-server.test.mjs
```

- [ ] **Step 5: Commit**

Intent line: `Coordinate two local signers without taking either role`

Trailers:

```text
Constraint: MCP may sequence and validate but all party signatures remain local.
Rejected: Embedding private keys or a remote signing callback | either lets Clockchain impersonate a stakeholder.
Confidence: high
Scope-risk: broad
Directive: Keep role access stable for one run and return only structured signing requests.
Tested: Full v2 state machine, identity branches, ordering, compression, capability, and coordinator regressions.
Not-tested: Deployed host and public network behavior land in integration gates.
```

---

### Task 11: Route and persist the public endpoint on AWS

**Files (MCP):**
- Modify: `infra/clockchain-mcp/Caddyfile`
- Modify: `infra/clockchain-mcp/docker-compose.yml`
- Modify: `infra/clockchain-mcp/compose-up.sh`
- Create: `infra/test/public-handshake-route.test.mjs`
- Modify: `infra/test/deploy-assets.test.mjs`
- Create: `infra/test/compose-contract.test.mjs`
- Create: `infra/test/caddy-contract.test.mjs`
- Modify: `infra/clockchain-mcp/RUNBOOK.md`

- [ ] **Step 1: Write RED infrastructure contracts**

Assert both `mcp.clockchain.network` and `mcp-aws.clockchain.network` proxy
`/handshake/mcp` unchanged to the existing service, the state volume persists only
digested invitation/public coordinator state, required signing/limit configuration is
SSM-backed, health remains unauthenticated, and no capability appears in compose,
Caddy, logs, or environment snapshots.

Require active/previous role-capability secrets and the active host-root private key to
be independent SSM SecureStrings with least-privilege instance-role reads. Require a
restart-safe funding reservation ledger, queue cap, 0.01/address, 0.02/session,
0.20/rolling-hour, and 1.00/UTC-day hard ceilings plus alert thresholds. A reservation
failure must occur before either seat transfer and must not affect v1/bilateral funds.

- [ ] **Step 2: Run RED**

```bash
cd "$MCP" && node --test infra/test/*.test.mjs
```

- [ ] **Step 3: Implement and document deploy/rollback order**

No new public port or instance is required. Caddy keeps TLS termination and reverse
proxying; application routing distinguishes `/handshake/mcp`. Add SSM parameters only
for server signing/limit state, never stakeholder access. Add persistent budget state,
bounded funding queue, and alerting without putting secrets in Compose. Rollback
restores the prior image while leaving generic v1 and bilateral services up.

- [ ] **Step 4: Run GREEN and container smoke locally**

```bash
cd "$MCP" && node --test infra/test/*.test.mjs
cd "$MCP/infra/clockchain-mcp" && docker compose config --quiet
```

- [ ] **Step 5: Commit**

Intent line: `Carry the public handshake boundary through the existing AWS edge`

Trailers:

```text
Constraint: The current EC2, Caddy, Compose, and SSM topology remains authoritative.
Rejected: A second public service | it would duplicate TLS, state, and operations for one isolated path.
Confidence: high
Scope-risk: moderate
Directive: Never persist or expose raw role capabilities in infrastructure state or logs.
Tested: Caddy, Compose, SSM, route, and container configuration contracts.
Not-tested: Production deploy waits for C1-C5.
```

---

### Task 12: Strictly parse v2 snapshots and derive monitor progress from facts

**Files (Research):**
- Create: `src/lib/agent-handshake-v2-snapshot.ts`
- Create: `src/lib/agent-handshake-v2-view.ts`
- Create: `src/lib/agent-handshake-v2-snapshot.test.ts`
- Create: `src/lib/agent-handshake-v2-view.test.ts`
- Modify: `src/app/api/handshake/monitor/route.ts`
- Modify: `src/app/api/handshake/monitor/route.test.ts`
- Modify: `src/components/ClaudeV6Live.tsx`
- Modify: `src/components/ClaudeV6LiveMonitor.tsx`
- Modify: `src/lib/claude-v6-live.test.ts`

- [ ] **Step 1: Write RED strict-parser tests**

Port the exact Handshake v2 snapshot keys and vocabularies. Reject partial objects,
unknown keys, invalid UUID/address/hash/decimal/reference values, malformed full
receipt or ERC-8004 objects, forbidden secrets, stage/history inconsistency, and
schema masquerading. Validate the public host-root `kid`/fingerprint, session key, and
session-key certificate digest as a complete group. Keep generic v1 and bilateral
validators separate.

- [ ] **Step 2: Write RED fact-derived view tests**

Required cases:

- invitation claim is incomplete until `responderClaimedAtMs` exists;
- policy is incomplete until that role's policy digest and commit time exist;
- funding alone never completes ERC-8004 registration;
- agent id alone never completes registration without address, chain, registry,
  reference, transaction, block, and post-session chronology;
- proposal, acceptance, and each receipt complete independently;
- verdict/certificate never backfill a missing policy, registration, signature, or
  receipt;
- heartbeat staleness changes only connectivity copy;
- `FAILED` marks the first exact unresolved fact;
- both roles display the complete registration reference and explorer links.

- [ ] **Step 3: Run RED**

```bash
cd "$RESEARCH" && npx vitest run \
  src/lib/agent-handshake-v2-snapshot.test.ts \
  src/lib/agent-handshake-v2-view.test.ts \
  src/app/api/handshake/monitor/route.test.ts \
  src/lib/claude-v6-live.test.ts
```

- [ ] **Step 4: Implement strict dual-schema routing and the pure view model**

The same-origin route forwards no cookies, authorization, body, or browser headers.
It returns current valid live state unless pristine; only then may it hold the newest
compatible certified run. Preserve existing certified-run dismissal behavior. React
components consume the pure view model and retain their current layout/classes.

- [ ] **Step 5: Run GREEN and layout compatibility**

```bash
cd "$RESEARCH" && npx vitest run \
  src/lib/agent-handshake-v2-{snapshot,view}.test.ts \
  src/app/api/handshake/monitor/route.test.ts \
  src/lib/claude-v6-live.test.ts \
  src/lib/claude-v6-layout-contract.test.tsx
```

- [ ] **Step 6: Commit**

Intent line: `Make the stakeholder monitor a strict witness of the new handshake`

Trailers:

```text
Constraint: The accepted visual layout stays while protocol facts and identity detail change.
Rejected: Driving rows from ordinal status or terminal verdict | it creates proof that the relay never emitted.
Confidence: high
Scope-risk: broad
Directive: Every done state must name and require its exact public artifact.
Tested: Strict v2 parser, fact view, proxy safety, v1/bilateral coexistence, and frozen layout.
Not-tested: Stakeholder copy and browser visual QA land next.
```

---

### Task 13: Replace the page narrative with the two-person agent-native runbook

**Files (Research):**
- Modify: `src/app/handshake/claude-v6/page.tsx`
- Modify: `src/components/ClaudeV6Runbook.tsx`
- Modify: `src/components/ClaudeV6LiveMonitor.tsx`
- Modify: `src/components/StakeholderPromptCard.tsx`
- Create: `src/lib/agent-handshake-client-setup.ts`
- Create: `src/lib/agent-handshake-client-setup.test.ts`
- Create: `src/app/api/handshake/readiness/route.ts`
- Create: `src/app/api/handshake/readiness/route.test.ts`
- Modify: `src/lib/claude-v6-presenter.test.tsx`
- Create: `public/handshake/claude-v6/v1-preserved-runbook.md`

- [ ] **Step 1: Write RED copy and client-setup contracts**

Assert the exact Codex and Claude Code MCP setup commands, fresh-session requirement,
exact endpoint, exact two stakeholder prompts, 90-second statement, 120-second invite,
fresh ERC-8004 mandate, local key/policy boundary, no external business action, and
full identity details. Add banned-copy assertions for clone, plugin, browser-open,
WalletConnect, wallet sign-in, stakeholder token mint, JSON handoff, payment, invoice,
settlement, per-signature approval, and 45-minute agreement.

Require the page's immutable run data to show the exact helper version, final
post-release manifest digest, allowed GitHub release prefix, and current/previous host-
root `kid`/fingerprints. The prompt data must require these Research values to match MCP
before download or execution. Add a negative test where MCP advertises a different
digest or root fingerprint.

Lock version-tested no-human launch fixtures. Claude Code uses `--strict-mcp-config`,
`--permission-mode dontAsk`, exact `mcp__clockchain-handshake__*` tools, and literal
Bash patterns for the two downloads, hash/signature checks, `chmod`, `--version`, and
the six helper operations. Codex uses `--strict-config`, a strict inline MCP entry,
`workspace-write`, an empty working directory, network enabled for that run, MCP auto
approval, and `approval_policy=never`. The page must state that current Codex lacks
Claude's literal Bash-pattern enforcement and is contained by the empty workspace,
sandbox, and helper policy.

The readiness route returns an exact public `{enabled, checkedAt, reasonCode}` object
from server-only deployment state and no request credentials. Until enabled, copyable
live prompts are disabled and the preserved layout shows "Public handshake not enabled
yet." Tests must prove a query/header/cookie/body cannot make it enabled.

Keep one truthful sentence: after client connection, the only person-to-person action
is copying the Responder invitation from one agent conversation into the other.

- [ ] **Step 2: Run RED**

```bash
cd "$RESEARCH" && npx vitest run \
  src/lib/agent-handshake-client-setup.test.ts \
  src/app/api/handshake/readiness/route.test.ts \
  src/lib/claude-v6-presenter.test.tsx
```

- [ ] **Step 3: Rewrite only the narrative and data bindings**

Preserve the two-column composition, sticky monitor, typography, drawers, copy-button
interaction, route, and receipt/registry link treatment. Add a static link to the
preserved v1 runbook; do not reintroduce the browser join route as the primary path.
Consume the reviewed Handshake post-release pin commit rather than copying values from
MCP or an uncommitted release workspace.

- [ ] **Step 4: Run GREEN, typecheck, and browser-level component tests**

```bash
cd "$RESEARCH" && npm run typecheck && npx vitest run \
  src/lib/agent-handshake-client-setup.test.ts \
  src/app/api/handshake/readiness/route.test.ts \
  src/lib/claude-v6-presenter.test.tsx \
  src/lib/claude-v6-live.test.ts \
  src/lib/claude-v6-layout-contract.test.tsx
```

- [ ] **Step 5: Run visual QA at desktop and mobile widths**

Open `/handshake/claude-v6` against fixtures for pristine, waiting-for-responder,
registrations-complete, receipt-in-progress, certified, stale-role, and failed states.
Capture screenshots at 1440×1000 and 390×844. Require no overflow, truncation of ids
only alongside a copy/full-detail affordance, stable sticky behavior, keyboard-usable
drawers/copy buttons, and WCAG AA state contrast.

- [ ] **Step 6: Commit**

Intent line: `Teach two people the real agent-native handshake without changing the demo shell`

Trailers:

```text
Constraint: Stakeholders use Codex or Claude Code directly and must not clone a repository or install a plugin.
Rejected: A giant operational prompt | MCP instructions and typed tools own the loop.
Confidence: high
Scope-risk: moderate
Directive: Keep stakeholder prompts about business intent and policy, not tool choreography.
Tested: Exact client setup, copy contracts, layout preservation, typecheck, component states, desktop/mobile visual QA.
Not-tested: Live production data waits for integration gates.
```

---

### Task 14: Add a reusable two-client clean-room compatibility harness

**Handshake files:**
- Create: `src/testing/fresh-agent-client.mjs`
- Create: `scripts/run-fresh-agent-handshake.mjs`
- Create: `test/fresh-agent-client.test.mjs`
- Create: `test/fixtures/fresh-agent/prompts.json`
- Create: `docs/agent-handshake-fresh-client-runbook.md`

**Research files:**
- Create: `src/app/api/handshake/monitor/integration.test.ts`

- [ ] **Step 1: Write RED isolation and terminal-proof tests**

The harness creates two disjoint temporary homes/workspaces/caches, copies no project
instructions, connects only `/handshake/mcp`, and accepts externally supplied model
authentication without retaining it. It must support `codex exec` and `claude -p` as
role drivers, pre-authorize only the Clockchain MCP tool family plus the exact pinned
release download/digest/CLI operations where the client supports command patterns,
launch both clients before awaiting either, and kill both process groups on timeout.
Codex must run in its clean workspace-write sandbox and record the documented lack of
literal command-pattern enforcement rather than claiming one.

Add negative client fixtures for `curl | sh`, alternate or redirected initial asset
URL, MCP/Research manifest-digest disagreement, asset digest mismatch, unknown host
root, shell metacharacters, path traversal, arbitrary helper operation, arbitrary
command, repository checkout, and a write outside the role workspace. Each must stop
before the local signing spy or registration transaction.

Retained evidence contains only client/version, run id, role, policy digest, address,
ERC-8004 reference/transaction/block, receipt ids, certificate digest, public terminal
proof, monitor observations, and cleanup result. Test canary secrets across stdout,
stderr, transcript, usage, manifest, monitor response, and retained evidence.

- [ ] **Step 2: Run RED**

```bash
cd "$HANDSHAKE" && node --test test/fresh-agent-client.test.mjs
```

- [ ] **Step 3: Implement deterministic client adapters and monitor polling**

Use the exact version-tested launch fixtures generated in Task 13. At minimum they
contain the following connection commands before a new client session:

```text
Codex: codex mcp add clockchain-handshake --url https://mcp.clockchain.network/handshake/mcp
Claude: claude mcp add --transport http --scope user clockchain-handshake https://mcp.clockchain.network/handshake/mcp
```

For disposable tests, redirect each client's home/config into its role directory and
start a new process only after configuration. Do not use a repository checkout inside
the client workspace. Seed the Research post-release manifest digest and host-root
fingerprints independently from MCP; fail on disagreement. Poll the Research same-
origin monitor route and record each artifact only after it appears in the
corresponding relay/checker state.

- [ ] **Step 4: Run GREEN with mocked client processes and a local full-stack fixture**

```bash
cd "$HANDSHAKE" && node --test \
  test/fresh-agent-client.test.mjs \
  test/agent-handshake-v2-*.test.mjs
cd "$RESEARCH" && npx vitest run src/app/api/handshake/monitor/integration.test.ts
```

- [ ] **Step 5: Commit in Handshake and Research**

Intent line: `Make fresh-agent proof repeatable across Codex and Claude Code`

Trailers:

```text
Constraint: A credible demo starts with two disjoint client homes and no Clockchain repository or prior state.
Rejected: Reusing named profiles | profile isolation does not prove a fresh client environment.
Confidence: high
Scope-risk: moderate
Directive: Retain only public proof and delete disposable homes even after failure.
Tested: Isolation, concurrency, timeout, secret canaries, terminal proof, monitor chronology, and local full-stack fixture.
Not-tested: Real provider-backed clients run at C6.
```

---

### Task 15: Run cross-client integration and security gates

**Files:**
- Modify: `docs/agent-handshake-fresh-client-runbook.md`
- Create: `docs/evidence/zero-plugin-live-erc8004/local-gate.json`
- Create: `docs/evidence/zero-plugin-live-erc8004/codex-initiator.json`
- Create: `docs/evidence/zero-plugin-live-erc8004/claude-initiator.json`

- [ ] **Step 1: Run the local full-stack gate**

Start the real v2 coordinator, local relay, host, deterministic RPC/registry fixtures,
two packed CLI instances, and Research monitor route. Require distinct role access
digests, policies, addresses, ids, three receipts, evidence, one certificate, matching
terminal certificate digests, root-verified host session key, independent Research/MCP
release-pin agreement, and exact monitor chronology.

- [ ] **Step 2: Run fresh Codex Initiator → Claude Code Responder**

Use the exact page prompts without edits. Start from empty homes and no project files.
Require live Sepolia registration for both fresh identities and no signing approval.

- [ ] **Step 3: Run fresh Claude Code Initiator → Codex Responder**

Repeat with reversed clients and two more fresh identities.

- [ ] **Step 4: Run focused security review**

Review public unauthenticated transport, trusted-proxy IP handling, invitation/capability
cryptography, replay/concurrency, state permissions, local-key containment, release
integrity, archive/log redaction, SSRF/path traversal, command allowlisting, monitor
secret exclusion, certificate trust-root binding/rotation, atomic funding reservations,
global gas budgets/alerts, and the explicit Codex command-pattern limitation. Resolve
every P0/P1 and rerun its causal test.

- [ ] **Step 5: Run complete repository verification**

```bash
cd "$HANDSHAKE" && npm run verify
cd "$MCP/packages/mcp-server" && npm test
cd "$MCP" && node --test infra/test/*.test.mjs
cd "$RESEARCH" && npm run typecheck && npm test && npm run lint
```

Expected: all tests and invariants pass. Any pre-existing lint exception must be
recorded with exact file/rule and must not intersect touched code.

- [ ] **Step 6: Commit public evidence only**

Intent line: `Prove both fresh clients can establish the same live identity-bound agreement`

Trailers:

```text
Constraint: Both client directions and the monitor must succeed from the exact stakeholder prompts.
Rejected: Treating unit tests as the production demo proof | they do not exercise client behavior or live registration.
Confidence: high
Scope-risk: moderate
Directive: Never retain model credentials, capabilities, invitations, signatures, private paths, or local key state.
Tested: Local full stack, Codex-to-Claude, Claude-to-Codex, security review, and all repository suites.
Not-tested: Public production routing begins at C7.
```

---

### Task 16: Deploy, canary, and preserve rollback

**Deployment order:**
1. signed `clockchain-agent-handshake 2.1.0` release and manifest;
2. Handshake host with v1 default still available;
3. MCP image with `/handshake/mcp` dark but health-testable;
4. Research site with dual-schema monitor, new narrative, and readiness disabled;
5. enable backend invitation creation without enabling the Research live prompts;
6. run both cross-client production rehearsals;
7. enable the Research readiness state only after every canary passes.

- [ ] **Step 1: Publish and independently verify release assets**

Download every asset from its final public URL, verify manifest digest, asset SHA-256,
native signature/notarization where applicable, `--version`, and clean-platform smoke.
Verify the separate post-release pin commit names that immutable source commit and
published manifest without circular self-reference. Promote that pin into MCP and
Research configuration; do not rebuild the helper.

- [ ] **Step 2: Deploy host and prove v1 compatibility**

Verify host health, discovery, a v1 dry run, immutable repository SHA, SSM secret
resolution, root-signed session-key certificate/current+previous rotation, atomic
funding reservation, budget-ledger recovery, alerting, and no party authority.

- [ ] **Step 3: Deploy MCP dark and probe both origins**

Check `https://mcp-aws.clockchain.network/handshake/mcp` first, then canonical origin.
Verify initialize instructions, exact seven tools, old `/mcp` authenticated behavior,
health/manifest routes, rate limits, restart-safe digested state, and no logs containing
canary capabilities. Verify role capabilities expire at the session deadline, trusted-
proxy IP behavior, funding queue/budgets, and exact agreement among MCP pin metadata,
Research pin metadata, and the published release.

- [ ] **Step 4: Deploy Research and verify monitor states**

Run parser/proxy smoke against live v1 and a staged v2 run. Check pristine/current,
invitation claimed, both registration objects, each receipt, certified fallback, stale
role, host-root/session-key proof, and public failure. Compare desktop/mobile
screenshots to Task 13. Confirm the readiness route is disabled and live prompt copy
controls cannot be activated from browser input.

- [ ] **Step 5: Enable invitation creation and run both production client directions**

Use new ERC-8004 identities for every role. Confirm the two agents in each run report
the same certificate digest and the monitor reports the same public identities,
policies, receipts, checker result, and certificate. Confirm funding reservations stay
within all four ceilings. Only after both directions pass, set the server-side Research
readiness flag and verify the live prompt controls become available.

- [ ] **Step 6: Record production evidence and rollback points**

Record release digest, immutable SHAs/images, health results, public session ids,
identity references, registration transactions/blocks, receipt ids, certificate
digests, monitor screenshots, test commands, and timestamps. Record no secrets.

Rollback order:

1. disable public invitation creation;
2. roll Research back to its dual-compatible prior deployment;
3. roll MCP back to the prior image;
4. roll the host back only after active v2 sessions expire;
5. keep signed release assets immutable and mark the release unsupported rather than
   deleting evidence needed by completed certificates.

- [ ] **Step 7: Final release commit/documentation update**

Intent line: `Make the two-person agent handshake safely repeatable in production`

Trailers:

```text
Constraint: Production rollout must preserve authenticated MCP, generic v1, bilateral, and historical demo evidence.
Rejected: One-step cutover | release, host, transport, and presentation need independent rollback points.
Confidence: high
Scope-risk: broad
Directive: Announce the public endpoint only after both cross-client production canaries and monitor verification pass.
Tested: Release integrity, host/MCP/Research health, compatibility paths, two production client directions, monitor states, and rollback rehearsal.
Not-tested: Long-duration load and non-Sepolia identity registries are outside this release.
```

---

## Completion checklist

- [ ] No stakeholder clone, plugin, browser flow, wallet sign-in, MCP token, JSON handoff, or per-signature approval remains in the primary runbook.
- [ ] Codex and Claude Code use the same public endpoint and receive the same server instructions.
- [ ] Initiator and Responder have distinct local keys, role access, policies, addresses, and fresh ERC-8004 identities.
- [ ] The signed agreement is valid for exactly 90 seconds; invitation and host deadlines remain independent.
- [ ] The host never owns or invokes a party signer.
- [ ] Public MCP exposes exactly seven tools and cannot authorize `/mcp`.
- [ ] All release assets are pinned, signed where required, digest-verified, and runnable without Node/npm.
- [ ] The Research pin is independent of MCP, the release lifecycle is non-circular, and the local helper rejects every unpinned host root/session key.
- [ ] Role capabilities use the exact canonical HS256 contract, expire at the host session deadline, rotate only current/previous keys, and never authorize `/mcp`.
- [ ] Public v2 funding is atomically reserved and bounded per address, session, hour, and day with fail-closed alerts/backpressure.
- [ ] Generic v1 and bilateral wire fixtures remain byte-identical.
- [ ] The accepted research-page layout remains visually intact.
- [ ] Research keeps live prompts disabled until production endpoint, pin, root, rate-limit, invitation, and cross-client canaries pass.
- [ ] The monitoring page renders v1 and v2, complete ERC-8004 details, independent freshness, exact receipt-by-receipt progress, public failure state, and newest-certified-run fallback.
- [ ] A later verdict or certificate cannot fabricate any missing policy, registration, signature, or receipt.
- [ ] Codex→Claude and Claude→Codex production runs both complete from the exact stakeholder prompts.
- [ ] Retained evidence contains no invitation, role access, signature, private key, local path, model credential, or stakeholder state.
