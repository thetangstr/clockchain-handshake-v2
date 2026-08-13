# Hermes Adapter Production Live Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run two blank Hermes K3 roles through the deployed Clockchain v2 handshake to two locally verified copies of one production certificate.

**Architecture:** Add a testing-only orchestrator beside the existing fresh-agent adapter. Hermes decides from digest-bound public packets; the existing adapter executes the pinned helper; a small role-local checkpoint signer uses the same wallet; an MCP SDK client transports exact values to production.

**Tech Stack:** Node.js 24 ESM, `node:test`, viem, Hermes 0.19/K3, MCP Streamable HTTP, existing Clockchain pinned-helper adapter.

---

### Task 1: Lock the decision and checkpoint contracts

**Files:**
- Create: `test/hermes-v2-live.test.mjs`
- Create: `src/testing/hermes-v2-live.mjs`

- [ ] Write failing tests for exact Hermes decision parsing, secret-free decision prompts, signing-request extraction, and proposal/acceptance commitment checkpoints signed by the role wallet.
- [ ] Run `node --test test/hermes-v2-live.test.mjs` and confirm failure because the module is absent.
- [ ] Implement only the pure decision, extraction, canonicalization, and checkpoint helpers.
- [ ] Re-run the focused test and require a clean pass.

### Task 2: Add the isolated Hermes decision runner

**Files:**
- Modify: `src/testing/hermes-v2-live.mjs`
- Modify: `test/hermes-v2-live.test.mjs`

- [ ] Add failing tests for disjoint role environments, K3/kimi-coding pinning, ignored user config/rules, exact MCP endpoint configuration, and strict JSON decisions.
- [ ] Implement the runner with injected process execution for tests and an explicit environment allowlist for live use.
- [ ] Re-run the focused test and the existing fresh-client adapter tests.

### Task 3: Add the production state machine

**Files:**
- Modify: `src/testing/hermes-v2-live.mjs`
- Create: `scripts/run-hermes-v2-live.mjs`
- Modify: `package.json`
- Modify: `test/hermes-v2-live.test.mjs`

- [ ] Add a fake-MCP state-machine test covering invite, accept, setup, identity, funding waits, registration, party readiness, proposal checkpoint, acceptance checkpoint, evidence, certificate verification, and cleanup.
- [ ] Implement the smallest live orchestrator using the existing `createFreshAgentRun` and `prepareAgentHarnessAdapter` functions.
- [ ] Expose `npm run canary:hermes-v2` with production defaults and a secret-free final JSON result.

### Task 4: Run the live gate and verify the monitor

**Files:**
- Retain evidence outside git under the run directory.

- [ ] Verify Hermes K3 and the eight production MCP tools before creating an invitation.
- [ ] Run two isolated roles against production within the current session deadline.
- [ ] Require two fresh distinct ERC-8004 identities, both checkpoints, three receipts, the same verified result digest, and `externalBusinessActionPerformed:false`.
- [ ] Fetch the existing monitor snapshot for the completed session and compare its parties, identities, receipts, and verdict to the local result.
- [ ] Run `npm run verify` and report any unrelated baseline failures separately.

