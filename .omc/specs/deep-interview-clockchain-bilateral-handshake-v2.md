# Deep Interview Spec: Clockchain Bilateral Handshake Demo v2

## Metadata
- Interview ID: di-handshake-20260803
- Rounds: 3 (plus a 3-agent brownfield review that pre-resolved most context)
- Final Ambiguity Score: 11.5%
- Type: brownfield
- Generated: 2026-08-03
- Threshold: 0.20
- Initial Context Summarized: yes (project CLAUDE.md + consolidated riyadh-v3 review)
- Status: PASSED

## Clarity Breakdown
| Dimension | Score | Weight | Weighted |
|-----------|-------|--------|----------|
| Goal Clarity | 0.92 | 0.35 | 0.322 |
| Constraint Clarity | 0.85 | 0.25 | 0.213 |
| Success Criteria | 0.85 | 0.25 | 0.213 |
| Context Clarity | 0.92 | 0.15 | 0.138 |
| **Total Clarity** | | | **0.885** |
| **Ambiguity** | | | **0.115** |

## Goal

Build, in `/Users/Kailor/Documents/Projects/handshake`, a stakeholder-driveable live demo in which two independent AI agents complete the bilateral payment-authorization handshake — `PROPOSED → ACCEPTED → ACKNOWLEDGED → fresh aggregate verifier → AUTHORIZED`, with `paymentMoved:false` everywhere — anchored as three independently verifiable Clockchain receipts, by **porting the live-proven riyadh-v3 protocol core** and **rebuilding the delivery shell** around an **outbound-only relay rendezvous**, keeping **ERC-8004 on-chain identity registration with the rehearsal + live pair structure** (four freshly funded Sepolia addresses per session).

## Interview Decisions (the three answers)

1. **Reuse strategy — port core, rebuild shell.** Copy the proven protocol modules and their focused tests from riyadh-v3 largely as-is; write a new, radically simpler delivery layer per the project CLAUDE.md. Do not resume riyadh-v3; do not rewrite the proven core.
2. **Topology — outbound-only relay.** A tiny dumb HTTPS+JSON mailbox is the only rendezvous. Payer and Requestor both connect *outbound* (post + long-poll). No participant machine ever accepts inbound connections — the SSH-tunnel failure class (0-for-11) is eliminated by construction. The same relay code serves both topologies: localhost in fully-local mode, one small cloud instance in public mode, switched by a single config flag. The relay is untrusted transport; authority lives only in signatures and Clockchain anchors. Public relay runs on a real domain with a real TLS certificate (the self-signed + fingerprint-pinning machinery leaves the stakeholder path). User accepted the drawbacks (poll latency, relay as restartable SPOF, one small cloud piece to own) with the condition that stakeholders can see everything working — satisfied by agent narration + live monitor + independently verifiable receipts, none of which depend on the transport.
3. **Identity — keep ERC-8004 + rehearsal pair.** Each session registers fresh ERC-8004 identities (registry `0x8004A818BFB912233c491871b3d84c89A494BD9e`, Sepolia) for an internal rehearsal pair, then the live pair — four addresses, matching the spec's funding count. The fresh verifier keeps the on-chain `ownerOf` check. Treasury gas caps from riyadh-v3 are ported.

## Constraints

### Port list (from `/Users/Kailor/conductor/workspaces/clockchain-handshake/riyadh-v3`)
- **Port largely as-is** (proven live Jul 30, stable since): `src/bilateral/{messages,protocol,runner,verdict,canonical,refid,blocktime,descriptor,evidence,payer-mandate,payment-request,roles}.mjs` (roles = `runPayerRole`/`runPayeeRole` only, `invitation.mjs` severed at its injection seam, CLI wrappers dropped; `verdict`/`evidence` are *adapted* ports with explicit edit budgets — see plan's port classification), `src/bilateral/funding/{record,journal,keystore}.mjs`, `src/canonical.mjs`, `src/redact.mjs`, `src/bilateral/private-path.mjs`, registration/ERC-8004 pieces (`src/registration*.mjs`, `scripts/register-bilateral-identity.mjs` equivalents), Clockchain client (`src/mcp.mjs` — keep the read/write retry split and write-intent marker pattern exactly), plus each module's focused tests.
- **Do NOT port**: AWS control plane (`infra/aws/`, `src/bilateral/aws/`), SSH tunnel / public-edge (`local-demo/public-edge.mjs`), sealed bootstrap broker + envelopes + operator approval gates, Payer MCP server (defer; see transport), the 3,910-line coordination store (replace with a simple append-only journal), the 2,826-line `check-docs.mjs` gate, the AWS operator console, invitations (v1 demo artifact).
- **Salvage selectively**: supervisor resume/checkpoint patterns (the *pattern*, not necessarily the 1,071-line module); relay route shapes from `coordination/relay.mjs` (it already models the mailbox).

### Mandatory fixes on port (audit findings that violate the CLAUDE.md rules)
- `blocktime.mjs:17` `EXPIRY_WINDOW_MS = 600000` (10-min anchor window, verifier-enforced, no grace) → ≥ 30 minutes. This is the last sub-30-min bound stretched across the human-paced handshake.
- `coordinator.mjs:176` `INTENT_READINESS_DEADLINE_MS = 90_000` and the 8-min probe window (`probe-bilateral-rendezvous.mjs:63`) → ≥ 30 min or unbounded-with-heartbeat, per rule 2. Grep every `60_000`-scale constant (riyadh-v3's own final-commit directive).
- Funding secret: invert the default — 0600 password file / env var is primary; **no macOS Keychain path at all** (rule 1).
- Version identity: single source of truth + one `release:pin` command (rule 3). riyadh-v3 pins sha/releaseId/imageDigest in ≥5 files.
- Discovery doc: drop the ECR-format `imageDigest` pattern requirement; no AWS-shaped fields in local mode (rule 7). Kit integrity via digest pinned inside the *signed* discovery doc (this replaces the out-of-band SHA handoff).
- Reason codes: add distinct `MISSING` (the donor's aggregate verifier misreports a never-anchored run as `EXPIRED`), `REORDERED` (absent from the donor's aggregate verifier — order violations surface as `ANCHOR_UNVERIFIED`; a working `REORDERED` exists only in the unported watcher `scripts/watch-bilateral-session.mjs:415`, which serves as the reference logic), and named `MALFORMED` (today generic `FAILED`) — AC6 requires distinct named reasons for replay / reorder / tamper.
- Monitor verdict rule: **never** render `AUTHORIZED` before the verifier's signed publication exists; **display it after**, sourced only from that publication (replaces riyadh-v3's unconditional output ban, which contradicts acceptance gate 3).

### Delivery-shell constraints (new build)
- Transport: HTTPS + JSON only. Payer intake = plain JSON endpoint shape over the relay (`request_payment` semantics preserved: responds `HANDSHAKE_REQUIRED` with machine-readable mandate terms, evidence formats, ordered steps). MCP adapter: optional, thin, **after** the first live run, if at all.
- Join model (replaces sealed bootstrap + operator approvals): unguessable session ID from the discovery doc; each party generates a fresh keypair; first valid signed claim binds the role for the session; later claims for a bound role are refused with a named reason. No human approval gates anywhere in the run.
- Stakeholder handoff: ONE pasted prompt containing only the discovery URL + public constants. No out-of-band SHA, no human-relayed readiness signals — the agent discovers readiness by polling with ≥30-min windows.
- Every component idempotent: kill/restart → resume or fail closed with a named public reason. Refused connections during staggered startup retry, never fatal.
- Status output: plain business language + machine fields; no stack traces, no internal code names; `paymentMoved:false` on every line/artifact/page.
- Secrets: operator-local 0600 files or env vars only. Nothing secret in git, prompts, logs, pages, or agent-visible output. Agents handle only public constants + their own fresh keypairs.
- Tests: focused suite < 1 minute covering state machine, signature verification, canonical JSON, idempotent restart, fail-closed cases. No timer-bound tests. No docs-linter CI gate. Full hardening suite only after the first successful live run.
- Sepolia treasury: `0x157a377e4181f3f87c7f6efed5ddc340ccc00dce` (operator-local keystore, ~3.3 ETH). Funding: 4 fresh addresses × 0.01 ETH, replay-safe journal, duplicate/replay refused.
- Clockchain: hosted MCP at `https://mcp.clockchain.network/mcp` (attest/verify primitives; no custom chain).
- Public monitor: add `/handshake/run` page to https://clockchain-research.vercel.app with the single Requestor prompt, live run progress, and immutable receipts of past runs. (Site source lives outside this repo; this repo publishes data.)

### Validation harness (Round 4 — user-mandated)
- **Clean-room agent validation**: acceptance testing of the Requestor (and optional Payer) side MUST use fresh agents with no prior context and no pre-installed skills, given only the single pasted prompt. Primary harness: **Hermes on the user's remote gateway, invoked from this machine's CLI** (used successfully before) — a genuinely separate environment with no shared filesystem or local auth inheritance. Secondary: fresh Claude Code / Codex sessions to prove agent-agnosticism. This deliberately improves on riyadh-v3's `acceptance:clients`, which inherited local auth material and the real `HOME`.
- **Three validation layers**: (1) every-commit machine validation — the <1-min focused suite plus structural greps (no `AUTHORIZED` outside verifier, no sub-30-min windows, no keychain refs); (2) per-milestone clean-room fresh-agent runs; (3) pre-live negative validation — replay / reorder / signature-tamper / duplicate-funding each fail closed with distinct named reasons, and `kill -9` + restart of every component resumes or fails closed.
- **Plan-review gate**: the full consensus implementation plan is shown to the user BEFORE any execution begins (user chose plan-first, pause).

### Presentation layer (Round 5 — user-mandated)
- **Stakeholder/audience view must be understandable by non-technical viewers**: plain-English step timeline (Terms published → Request accepted → Acknowledged → Independent verification → Verdict), green-check progression, "No money has moved" as a human sentence on every state, receipt cards with "View on Clockchain" links. Hashes/JSON/digests only behind an expandable "technical evidence" section — never above the fold.
- **Operator control plane** (localhost page served by the operator process; framework-free, no build step): a polished dashboard for the demo owner to SHOW what is logged on Clockchain — per-anchor block height, ledger ID, timestamp, prettified receipt payload, live read-only "re-verify receipt" action against Clockchain, audit-trail view, funding-journal view, per-role status + heartbeat tail. Exactly two controls: **Start** and **Abort**. It shows, it never gates (no approval actions return). Verdict display rules identical to the public page (only from the verifier's signed publication).
- **Stakeholder-run Payer elevated to standard deliverable** (complexity assessed LOW: payer wrapper is symmetric to the requestor kit; mandate terms travel inside the operator-signed payer discovery doc, payer kit signs/publishes them). Owner-driven payer remains the run-1 fallback; who drives the Payer is a demo-day choice.

### Milestones and gates
| Milestone | Builds | Gate |
|---|---|---|
| M0 Foundation port | Port list + focused tests; mandatory fixes (≥30-min windows, keychain removal, MISSING/REORDERED/MALFORMED codes, release:pin) | G0: suite green < 1 min; structural greps clean |
| M1 Local happy path | Localhost relay, operator script, payer loop, requestor kit, local status page | G1: one script + one pasted prompt → 3 anchors → AUTHORIZED locally; kill/restart passes; negative trio distinct |
| M2 Public topology | Cloud relay (real TLS), topology flag, public discovery, Vercel monitor page | G2: full run, Requestor on different machine via fresh Hermes, prompt-only, < 15 min |
| M3 Stakeholder rehearsal | Payer prompt, immutable run summaries, runbook, rehearsal checklist | G3: clean-room dress rehearsal passes AC1–AC7 + AC9 (AC8's fresh-full-pass half lands at G4) |
| M4 Live demo + hardening | — | G4: live run succeeds → fresh full test pass → only then hardening |

## Non-Goals
- Production hardening before the first successful live run (harden after).
- The v1 turnkey/invitation demo (stays in riyadh-v3; not ported, not maintained here).
- AWS control plane, ECS/EFS/Cognito/SQS/DynamoDB — none of it. Optional cloud = static monitor hosting + the small relay only.
- A2A protocol, AgentDash, mainnet, multi-validator claims.
- MCP as a required transport for any role.
- Merging anything back into riyadh-v3.

## Acceptance Criteria (numbered — gates reference these by AC number)
- [ ] **AC1 — Milestone 1 (first, local)**: one script starts Operator + Payer (+ localhost relay); a single pasted prompt into a fresh agent drives the Requestor; three anchors land on Clockchain in exact order; the fresh verifier emits `AUTHORIZED`; a local page shows the run. Happy path completes live end-to-end.
- [ ] **AC2** — A stakeholder who has never seen the repo pastes ONE prompt (discovery URL + public constants only) into a fresh agent CLI (Claude Code / Codex / Hermes; macOS / Windows / Linux) on their own machine and completes the Requestor side unaided in < 15 minutes including kit install (`npm ci`, no native builds).
- [ ] **AC3** — A second stakeholder can run the Payer side from a second single prompt (standard deliverable; owner-driven fallback for run 1).
- [ ] **AC4** — Public monitor shows the live run and, at completion, three Clockchain receipts with block references in exact order plus the verifier verdict; `paymentMoved:false` throughout; `AUTHORIZED` appears only after (and sourced from) the verifier's signed publication.
- [ ] **AC5** — Kill/restart any component mid-run → clean resume or fail-closed with a named public reason. Never a hang, stack trace, or false success.
- [ ] **AC6** — Negative checks each fail closed with **distinct** named reasons: replaying a previous run's evidence; reordering anchors; tampering with one signature; duplicate funding.
- [ ] **AC7** — Exact order enforced: `PROPOSED → ACCEPTED → ACKNOWLEDGED → verification → AUTHORIZED`; the literal `AUTHORIZED` is emittable only by the operator's fresh verifier.
- [ ] **AC8** — Focused test suite passes in < 1 minute; one fresh full pass after the live run succeeds.
- [ ] **AC9** — Funding is replay-safe across restarts: fresh addresses every run, journal persisted, duplicates refused.

## Assumptions Exposed & Resolved
| Assumption | Challenge | Resolution |
|------------|-----------|------------|
| The failing riyadh-v3 build should be resumed or fully rewritten | Forensics: protocol proven 3× live; delivery shell 0-for-11 | Port the core, rebuild the shell (Round 1) |
| Reaching the Payer requires making a participant machine publicly reachable (tunnel/VPS) | All 11 hybrid failures trace to inbound reachability | Outbound-only relay mailbox; no inbound anywhere; same code local + cloud behind one flag (Round 2) |
| Relay hides progress from stakeholders | Visibility comes from agent narration + monitor + receipts, not transport | Accepted with that condition; drawbacks (latency, restartable SPOF, one cloud piece) acknowledged (Round 2) |
| Sepolia funding might be ceremonial in v2 | Code shows gas pays ERC-8004 registration; verifier checks `ownerOf` on-chain | Keep identity + rehearsal pair; 4 addresses stays meaningful (Round 3) |
| Monitor must never print `AUTHORIZED` (riyadh-v3 invariant) | Contradicts acceptance gate 3 (monitor shows the verdict) | Never before the verifier's signed publication; display after, from that publication only |
| MCP is required for payment intake | Rule 5: boring HTTPS+JSON core | Plain JSON over the relay; MCP optional adapter post-live-run |

## Technical Context (from the 3-agent riyadh-v3 review)
- **Proven asset**: `src/bilateral/` stable since Jul 30; three complete `VERIFIED` runs (Clockchain blocks 2316688/2316708/2316711, 2316836…, 2359628/2359647/2359650) — all single-machine. Write-intent markers prevent double-anchoring; Clockchain writes never retried, reads retried; canonical JSON profile with 4 hard rules; `AUTHORIZED` literal at exactly one site (`verdict.mjs:1154`); `paymentMoved:false` validated everywhere (617 occurrences); replay-safe funding journal; durable resumable checkpoints.
- **Failure history**: AWS track (Jul 31–Aug 2) 0 anchors — 7/10 root causes AWS hosting/auth/networking; pivoted Aug 2 (`6de7cd8`). Hybrid SSH-tunnel track: 0-for-11 in 14 hours (loopback-only reverse-forwards, TLS 1.3 session-resumption vs cert pinning, 8-minute timeouts killing runs while the stakeholder was still `npm ci`-ing, locked-keychain funding death after all protocol steps succeeded, 29-minute unobserved stall). Work stopped 2026-08-03 00:58 mid-fix; run 12 never attempted; `npm run verify` last proven green Jul 26; hybrid entry point unrunnable (gitignored `.context/hybrid-demo/operator.json` never captured).
- **Audit verdicts (13 rules)**: PASS — canonicalization (R4), business statuses (R9), AUTHORIZED containment (R10), no secrets in git (R11), paymentMoved (R12). VIOLATION/PARTIAL — keychain default (R1), residual sub-30-min windows (R2), multi-file version pinning without `release:pin` (R3), MCP-required requestor flow (R5), AWS inside "local" mode: ECR digest pattern + `aws s3 cp` receipts (R7), 106-file 7-min hang-prone suite with no fast core (R8), missing `REORDERED`/`MISSING`/`MALFORMED` codes (R13).
- **Process lessons**: docs-linter CI gate was the most-churned file (37 touches) — do not recreate; 411 commits of additive "Keep/Make/Bind" tightening with no reverts is the anti-pattern signature; every recent commit deferred `npm run verify` because the suite was too slow — the fast-suite rule exists to prevent exactly that.

## Ontology (Key Entities)
| Entity | Type | Fields | Relationships |
|--------|------|--------|---------------|
| Operator | core role | discovery signing key, treasury keystore, verifier | starts Session; publishes Discovery; funds Identities; runs Verifier |
| Payer | core role | fresh keypair, ERC-8004 identity, mandate | posts Mandate; anchors PROPOSED + ACKNOWLEDGED |
| Requestor | core role | fresh keypair, ERC-8004 identity, one pasted prompt | calls request_payment; anchors ACCEPTED |
| Verifier | core role | fresh process, sole AUTHORIZED emitter | re-validates all Anchors + on-chain identity; issues Verdict |
| Session | core domain | session id (unguessable), rehearsal + live sub-runs, expiry ≥ 30 min | contains Anchors, Identities, Funding records |
| Anchor/Transition | core domain | kind (PROPOSED/ACCEPTED/ACKNOWLEDGED), Clockchain receipt, block ref | exactly 3 per sub-run, strict order, distinct ledger IDs, increasing heights |
| Relay | supporting (untrusted) | mailbox routes, localhost or cloud URL, one topology flag | transports messages; holds zero authority |
| Discovery Document | supporting | schema, session id, payer endpoint URL, kit digest, expiry, Ed25519 signature | signed by Operator; the ONLY handoff artifact |
| Client Kit | supporting | Node 22 script, npm ci no-native | fetched per Discovery; drives Requestor |
| ERC-8004 Identity | supporting | agentId, registry 0x8004A818…, Sepolia address | registered per party per sub-run; verifier checks ownerOf |
| Funding/Treasury | supporting | 0x157a377e…, 4 × 0.01 ETH, replay-safe journal, gas caps | funds Identity registration gas |
| Monitor | supporting | public page, live progress, receipts, verdict-after-publication | renders Session; never originates authority |
| Rehearsal Sub-run | supporting | internal pair before live pair | de-risks the live pair inside the same session |
| Clockchain | external system | hosted MCP https://mcp.clockchain.network/mcp | anchors + receipts + audit trail |

## Ontology Convergence
| Round | Entity Count | New | Changed | Stable | Stability |
|-------|-------------|-----|---------|--------|-----------|
| 1 | 11 | 11 | – | – | N/A |
| 2 | 12 | 1 (Relay) | 0 | 11 | 92% |
| 3 | 14 | 2 (ERC-8004 Identity, Rehearsal Sub-run) | 0 | 12 | 86% |

Core roles never shifted across rounds — the domain model is stable.

## Open Logistics (non-blocking, defaults chosen)
- **Demo date**: TBD by owner; plan stays date-agnostic with a rehearsal checklist before any live stakeholder run.
- **Run-1 Payer driver**: demo owner (spec explicitly allows owner OR stakeholder; stakeholder-Payer is optional gate 2).
- **Relay hosting**: any small always-on box with a real domain/TLS; AWS allowed but not required.
- **Treasury keystore**: operator-local 0600 file; location configured in operator config, never committed.

## Interview Transcript
<details>
<summary>Full Q&A (3 rounds)</summary>

### Round 1 — Reuse strategy (Constraints, 0.60 → 0.85 path)
**Q:** How should v2 relate to the riyadh-v3 code, given the core is live-proven and the delivery shell is 0-for-11?
**A:** Port core, rebuild shell.
**Ambiguity:** 25% → 20.5%

### Round 2 — Topology (Constraints)
**Q:** How does the Requestor reach the Payer across the internet (where all 11 hybrid runs died)?
**A:** Outbound-only relay — "fine as long as the stakeholders can see that everything is working as intended, any other drawbacks?" Drawbacks given (latency, restartable SPOF, one cloud piece, story nuance) and accepted; visibility satisfied by narration + monitor + receipts.
**Ambiguity:** 20.5% → 15.5%

### Round 3 — Identity (Goal)
**Q:** Keep ERC-8004 on-chain identity (what funded gas pays for; verifier checks ownerOf), and the rehearsal pair (why four addresses)?
**A:** Keep identity + rehearsal (recommended option).
**Ambiguity:** 15.5% → 11.5% — PASSED

### Round 4 — Validation & bridge (Success Criteria)
**Q:** Execution bridge options presented.
**A:** "What is the validation? can we make sure to use fresh agents with no context and pre-installed skills? I was using hermes on a remote gateway (access from this machine's cli), we can do that again. what are the milestones and gates? show me the full plan first."
**Resolution:** Clean-room fresh-agent validation harness (Hermes remote gateway primary), three validation layers, explicit milestone/gate table added; plan-first-pause chosen — consensus plan produced and shown before any execution.

</details>
