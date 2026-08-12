# Phase 6C3 Three-Harness Live Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Use strict TDD and preserve every Phase 6C1/6C2 proof boundary.

**Goal:** Prove that Clockchain's handshake mechanics are harness-portable by completing three live isolated runs that cover Codex, Claude Code, and Hermes in both party roles without changing the mandate, MCP protocol, direct-A2A channel, signer authority, or certificate verifier.

**Matrix:** Use a three-run cycle so every harness acts once as Initiator and once as Responder while every cross-harness pairing is exercised exactly once:

1. `codex:claude`
2. `claude:hermes`
3. `hermes:codex`

**Architecture:** Keep the Clockchain-owned `HarnessAdapter` contract above harness-specific process control. Codex and Claude remain pinned ACP adapters. Hermes remains the existing audited native adapter and receives a new process transport compatible with the same retained-action recorder and party bridge; do not force Hermes through ACP or copy Paperclip/Multica control-plane assumptions. All three adapters consume the same role mandate, production MCP endpoint, public peer card, exact helper release, direct commitment checkpoints, and local policy decision callback. AWS is a runtime/provider concern, not a fourth harness: Claude uses Sonnet through Bedrock workload identity in Fargate; Codex uses Terra; Hermes uses pinned MiniMax M3 through one Hermes-only provider secret.

**Repository:** `/private/tmp/clockchain-mechanics-proof`

**Completion rule:** Matrix success is the conjunction of three independently successful runs. Each run must have fresh runtime/workload/party/A2A identities, fresh ERC-8004 IDs, direct delivery/checkpoint evidence, three receipts, one certificate verified by both parties, no external business action, and confirmed teardown. A single baseline certificate cannot be replayed across rows.

---

### Task 1: Freeze the harness matrix and provider policy

**Files:**
- Create: `src/harness/harness-matrix.mjs`
- Modify: `src/testing/mechanics-proof-controller.mjs`
- Modify: `src/runtime/aws-fargate-runtime-adapter.mjs`
- Test: `test/harness-matrix.test.mjs`
- Test: `test/mechanics-proof-controller.test.mjs`
- Test: `test/aws-fargate-runtime-adapter.test.mjs`

- [ ] Write RED table-driven tests for the exact three ordered pairs, exact role coverage, and exact provider/model pins. Reject same-harness pairs, reversed duplicates outside the cycle, unknown harnesses, provider/model overrides, and matrix summaries that omit a row.
- [ ] Implement one immutable matrix module consumed by controller and Fargate preflight. Remove pair literals from those modules.
- [ ] Run focused tests and commit with Lore intent `Freeze the portable harness proof matrix`.

### Task 2: Compose Hermes with the existing live party bridge

**Files:**
- Create: `src/harness/hermes-process-transport.mjs`
- Modify: `src/harness/hermes-native-adapter.mjs`
- Modify: `src/testing/mechanics-proof-party-runtime.mjs`
- Test: `test/harness-hermes-process-transport.test.mjs`
- Test: `test/harness-hermes-native-adapter.test.mjs`
- Test: `test/mechanics-proof-party-runtime.test.mjs`

- [ ] Write RED tests proving a fresh standalone `HOME`/`HERMES_HOME`, empty workspace/state/memory/skills/contacts, pinned Hermes binary/version, pinned MiniMax M3 provider, exact Clockchain MCP tools, no shared profile, and the same trusted retained-action socket used by ACP adapters.
- [ ] Execute Hermes as a harness adapter only: it may observe MCP results and request retained local actions, but it cannot receive party keys, sign directly, bypass policy, or author controller decisions.
- [ ] Normalize Hermes public events/evidence into the existing harness schemas. Raw prompts, transcript, reasoning, provider key, MCP access, helper payload, and filesystem paths remain private.
- [ ] Run Hermes, bridge, party-runtime, cleanup, and secret-canary tests; commit with Lore intent `Run Hermes behind the same party authority boundary`.

### Task 3: Generalize container and Fargate launch configuration

**Files:**
- Modify: `bin/mechanics-proof-party.mjs`
- Modify: `scripts/run-mechanics-proof-containers.mjs`
- Modify: `scripts/run-mechanics-proof-fargate.mjs`
- Modify: `infra/mechanics-proof/fargate-live-runtime.yaml`
- Test: `test/mechanics-proof-party-entrypoint.test.mjs`
- Test: `test/mechanics-proof-two-container.test.mjs`
- Test: `test/mechanics-proof-fargate-runner.test.mjs`

- [ ] Write RED parameterized tests for all three matrix rows. Provider material must be role/harness scoped: Codex auth only to a Codex task, Bedrock permission only to a Claude task, MiniMax secret only to a Hermes task.
- [ ] Replace hard-coded Initiator-Codex/Responder-Claude env construction with matrix-derived exact env builders. Keep all other task isolation, SQS bootstrap, direct A2A, image, TTL, budget, and cleanup gates unchanged.
- [ ] Run focused launch/configuration tests and commit with Lore intent `Launch any approved harness pair without widening authority`.

### Task 4: Add matrix-level evidence aggregation

**Files:**
- Create: `src/testing/mechanics-proof-matrix-evidence.mjs`
- Modify: `scripts/run-mechanics-proof-fargate.mjs`
- Test: `test/mechanics-proof-matrix-evidence.test.mjs`

- [ ] Write RED tests requiring three unique run IDs, six unique runtime IDs/task ARNs/workload identities/party addresses/A2A card addresses/ERC-8004 IDs, three unique certificate digests, nine receipt IDs, exact role coverage, and all cleanup proofs.
- [ ] Reject one-row replay, shared credentials/state/signers, missing role orientation, mixed source/image/helper/MCP pins, model prose as proof, or any matrix result written before all three teardown audits finish.
- [ ] Persist only public per-run proofs plus one digest-only matrix index. Commit with Lore intent `Require independent proof from every harness pairing`.

### Task 5: Execute and verify the live matrix

**Files:**
- Modify: `docs/mechanics-proof-fargate-runbook.md`
- Create: `evidence/mechanics-proof-matrix/<matrix-id>/matrix-proof.json` (generated, sanitized)
- Create: `evidence/mechanics-proof-matrix/<matrix-id>/verification.md` (generated, no secrets)

- [ ] Confirm Phase 6C2's production checkpoint and Fargate proof are green before mutation.
- [ ] Run the three rows sequentially to keep max concurrency two and simplify cost/teardown attribution. Do not start the next row until the previous stack and tasks are absent.
- [ ] Require six fresh ERC-8004 registrations, direct proposal/acceptance and checkpoint evidence for every row, nine receipts, three matching-per-pair certificates, and no external business action.
- [ ] Run `npm run verify`, independent spec review, independent code/security review, and read-only AWS absence audit. Commit with Lore intent `Prove Clockchain across three independent agent harnesses`.

---

Phase 6C3 is not complete because three adapters instantiate or because mocked matrix tests pass. It ends only after the three live evidence rows succeed and their resources are absent. Monitoring and the demo video must consume this verified matrix evidence rather than harness self-reports.
