# Phase 6C4 Verified Monitor and Presenter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Preserve the accepted `/handshake/claude-v6` layout with characterization tests before changing data or copy.

**Goal:** Make the live monitor and canonical research-site demo truthfully show the two independent stakeholder agents, direct-A2A mechanics, cloud isolation, ERC-8004 registrations, receipts, closing certificate, and cleanup proof from validated evidence—without changing the existing two-column/sticky layout or making the page a protocol controller.

**Repositories:**
- Mechanics/evidence producer: `/private/tmp/clockchain-mechanics-proof`
- Canonical presenter: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/hermes-turnkey-demo`

**Architecture:** Keep `clockchain.handshake-snapshot/v1` and `/api/handshake/monitor` as the live business-stage feed. Add a separate immutable public proof document for mechanics/matrix evidence rather than widening or weakening the snapshot schema. The research-site server fetches both through fixed read-only origins, validates exact shapes, and joins them only by exact session ID and certificate digest. The existing page structure—runbook left, sticky monitor right, timeline, identity details, receipt drawers, checker card, and run history—remains intact. New proof details appear inside existing drawers/cards or one additive collapsed “How this run was isolated” section.

**Trust rule:** UI state is derived from validated relay facts plus validated proof documents. Never derive completion, identity, direct delivery, workload isolation, or cleanup from model prose, controller narration, timestamps alone, ordinal stage inference, or URL parameters.

---

### Task 1: Publish a canonical public mechanics-proof document

**Files:**
- Create: `src/monitor/mechanics-proof-public.mjs`
- Modify: `src/relay/server.mjs`
- Modify: `src/relay/client.mjs`
- Modify: `scripts/run-mechanics-proof-fargate.mjs`
- Modify: `scripts/run-mechanics-proof-matrix.mjs`
- Test: `test/monitor-mechanics-proof-public.test.mjs`
- Test: `test/monitor-live.test.mjs`

- [ ] Write RED exact-schema tests for `clockchain.mechanics-proof-public/v1`: session/certificate/source/image/helper/MCP digests; two party entries with harness, role, public address, ERC-8004 ID, runtime/workload/task-role digests, A2A card address; direct artifact/checkpoint acknowledgment digests; three receipts; certificate verification; `externalBusinessActionPerformed:false`; teardown/absence digest; optional matrix row/index fields.
- [ ] Reject raw task ARNs, secret refs, queue URLs/messages, prompts, transcripts, reasoning, private paths, private keys, role access, signatures, self-claims without corroboration, or a proof written before cleanup.
- [ ] Add fixed read-only `GET /v1/sessions/{sid}/mechanics-proof` and exact host-only publication. No browser write path, query-selected origin, or mutable “current proof” alias.
- [ ] Run monitor/relay regressions and commit with Lore intent `Publish only corroborated mechanics proof`.

### Task 2: Add a strict research-site proof proxy and client model

**Files (research site):**
- Create: `src/app/api/handshake/proof/[sessionId]/route.ts`
- Create: `src/lib/handshake-mechanics-proof.ts`
- Modify: `src/components/ClaudeV6Live.tsx`
- Test: `src/app/api/handshake/proof/[sessionId]/route.test.ts`
- Test: `src/lib/handshake-mechanics-proof.test.ts`
- Test: `src/lib/claude-v6-live.test.ts`

- [ ] Write RED tests requiring a UUID route session, fixed relay origin, no forwarded headers/cookies/body, exact proof schema, exact session match, and certificate digest agreement with the terminal snapshot/result binding.
- [ ] Fetch proof only after the current snapshot exposes a terminal certificate binding; clear it on session change/dismissal/failure. Keep one shared polling provider and do not add client-side HTTP relay access.
- [ ] Reject partial/extra-key proofs, stale session, mismatched certificate, payment/external-action claims, absent cleanup, and non-HTTPS external links.
- [ ] Commit with Lore intent `Join the presenter only to verified run proof`.

### Task 3: Preserve the old UI while making the narrative truthful

**Files (research site):**
- Modify: `src/components/ClaudeV6Runbook.tsx`
- Modify: `src/components/ClaudeV6LiveMonitor.tsx`
- Modify: `src/components/ClaudeV6RunLog.tsx`
- Modify metadata only: `src/app/handshake/claude-v6/page.tsx`
- Test: `src/lib/claude-v6-presenter.test.tsx`
- Test: `src/lib/claude-v6-live.test.ts`

- [ ] Add characterization assertions before edits for `max-w-6xl`, `flex-col-reverse`, `xl:flex-row`, `xl:sticky`, `xl:top-8`, `xl:w-[380px]`, timeline ordering, receipt drawers, checker card, run history, reset behavior, desktop/mobile snapshots, and reduced motion.
- [ ] Reframe the narrative around two people, each using a separate fresh local agent client connected to Clockchain MCP. The Initiator creates the bounded invitation/mandate; the Responder receives the copied invitation, evaluates the checked-in local demo policy, and independently accepts or declines.
- [ ] Explain live ERC-8004 registration as the demo's chosen identity mandate. Show full CAIP-style identity reference, controlling public address, network/registry link, and registration proof—not only the four-digit token number.
- [ ] State exactly: no browser approval, no plugin/local companion, no repo clone as the product interaction, no human signing step, no payment, and no external business action. The demo infrastructure may install harness dependencies, but that is not part of the stakeholder prompt.
- [ ] Replace stale Hermes/Mac-mini-only claims with evidence-derived harness/runtime labels. Keep synthetic Northstar/Harbor scenario names clearly marked as the example.
- [ ] Preserve the existing monitor labels and drawers; add one collapsed isolation/proof drawer showing distinct workload/task-role digests, direct-A2A delivery/checkpoints, source/image/helper pins, and teardown digest when proof is available.
- [ ] Commit with Lore intent `Tell the two-stakeholder story through the proven UI`.

### Task 4: Make all visual state fact-derived

**Files:**
- Modify: `src/monitor/stakeholder/messages.mjs`
- Modify: `src/components/ClaudeV6Live.tsx`
- Test: `test/monitor-timeline.test.mjs`
- Test: `test/monitor-snapshot.test.mjs`
- Test: `src/lib/claude-v6-live.test.ts`

- [ ] Parameterize equivalent fixtures in both repositories. Funding/identity fields cannot complete mandate/receipt rows; verdict cannot fabricate missing anchors; a later stage cannot backfill absent earlier artifacts; failure marks the first fact-incomplete row; proof availability cannot advance the business timeline.
- [ ] Direct-A2A/checkpoint, cloud-isolation, and cleanup badges complete only from exact proof fields. Live animation stops at terminal state. A missing proof shows “proof not published” rather than assuming local/isolated execution.
- [ ] Run both repositories' focused timeline tests and commit with Lore intent `Render progress only from named proof facts`.

### Task 5: Verify the preserved presenter visually and functionally

**Files:**
- Modify: `docs/handshake-demo-baseline.md`
- Create: `docs/verified-mechanics-presenter.md`
- Create: approved desktop/mobile screenshots under the research site's test artifact directory.

- [ ] Run mechanics tests: `node --test test/monitor-mechanics-proof-public.test.mjs test/monitor-live.test.mjs test/monitor-timeline.test.mjs test/monitor-snapshot.test.mjs` and `npm run verify`.
- [ ] Run research tests: `npm run typecheck`, targeted Vitest route/live/presenter suites, `npm run build`, and targeted ESLint.
- [ ] Start the research site locally and use browser QA at 1440x1000 and 390x844. Compare `/handshake/claude-v6` to the packaged baseline; the layout must remain recognizable and the experimental `/demos/multi-agent` route must not be imported.
- [ ] Verify a completed mechanics-proof session, an active session, pristine/no-run, failure, stale proof, and unavailable relay. The page remains GET-only/read-only in every state.
- [ ] Run independent spec, security, and visual reviews. Commit with Lore intent `Preserve the stakeholder demo while exposing stronger proof`.

### Task 6: Deploy and smoke the read-only presentation

- [ ] Deploy the relay proof-read endpoint and research site only after Phase 6C3 evidence exists. Do not alter the handshake control plane during presenter deployment.
- [ ] Verify HTTPS 200 for `/handshake/claude-v6`, `/api/handshake/monitor`, one exact session proof route, run history, and a receipt-detail route.
- [ ] Verify production responses contain no credentials/private paths and that the presenter shows the selected live matrix run with exact identity, receipt, certificate, and cleanup facts.
- [ ] Retain the prior source revision and known completed session as the packaged fallback in `docs/handshake-demo-baseline.md`.

---

Phase 6C4 is complete only when the old UI remains available and visually recognizable, the new proof is strictly validated and read-only, and no displayed mechanics claim depends on model/controller prose. The video phase consumes this presenter/proof bundle only after these gates pass.
