# Consensus Plan: Clockchain Bilateral Handshake Demo v2

- **Status: pending approval** (user reviews full plan before any execution)
- Source spec: `.omc/specs/deep-interview-clockchain-bilateral-handshake-v2.md` (ambiguity 11.5%, PASSED)
- Source workspace for ports: `/Users/Kailor/conductor/workspaces/clockchain-handshake/riyadh-v3` (read-only donor)
- Target repo: `/Users/Kailor/Documents/Projects/handshake`
- Mode: RALPLAN-DR **deliberate** (security-shaped protocol, treasury secrets)
- Version: **v5** (Critic round 1 + Architect iteration-2 dynamic-poll-bound fix — see Changelog)
- Date: 2026-08-03

---

## RALPLAN-DR Summary

### Principles (P1–P5)
- **P1 — Authority lives only in signatures and chain receipts.** Every transport (relay, monitor, control plane) is untrusted; nothing advisory is authoritative. Exactly **one emission site** for `AUTHORIZED` exists (`core/verdict.mjs`, subjectRun-gated); every other occurrence of the literal is on a named allowlist with a stated reason (ban patterns, display maps fed only by the verifier's signed publication, tests).
- **P2 — No inbound connections to participant machines, ever.** All cross-machine connectivity is outbound HTTPS to a dumb relay — including evidence delivery (parties push; the verifier pulls from the relay). *Clarification (Critic open question): the operator control plane binds loopback only; a localhost UI on the operator's own machine is not a cross-machine inbound path and is P2-compliant.*
- **P3 — Fail closed with a named public reason; `paymentMoved:false` always.** Every frozen reason code has an enumerated emission site; no stack traces, no false success. Public reason mapping happens at the role-wrapper/verifier boundary — pure-ported internals (e.g. `runner.mjs`'s 67 `terminal("FAILED")` calls) are not retagged.
- **P4 — Two wait classes, both safe.** *Human-paced waits* (pre-window) are ≥ 30 minutes or unbounded-with-heartbeat, resumable. *In-window waits* (`PROPOSED`→`ACKNOWLEDGED`) are machine-paced, bounded by the signed 10-minute expiry, with one authoritative budget derivation (below) quoted everywhere. Kill/restart anything → resume or fail closed. Refused connections retry.
- **P5 — Thinnest happy path first; harden after live green.** Pure modules port byte-faithfully; adapted modules carry explicit edit budgets with donor tests ported first under a stated pruning policy.

### Decision Drivers (top 3)
1. **The delivery layer is the proven risk — but three delivery assumptions live inside the "proven core"** (verifier's local-directory evidence input, the signed 10-minute expiry, rehearsal-blind `AUTHORIZED`). v2 names and adapts them at plan time, not at G1.
2. **Stakeholder experience is the acceptance gate**: one pasted prompt, fresh agent, no context, < 15 min including `npm ci` — validated clean-room (Hermes remote gateway).
3. **Demo reliability over architectural ambition**: field-learned invariants (write-intent markers, block-time parsing, read/write retry split, 223.5 s rate ceiling) are ported, not relearned live.

### Viable Options considered
| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **A. Port core + rebuild shell on outbound-only relay, with named adaptations** | Reuses live-proven crypto/protocol and field-learned constants; eliminates inbound-reachability class by construction; same code local & public (one flag) | Poll latency (~1–2 s); one small cloud piece; `verdict.mjs` adapted rather than pristine | **CHOSEN** (interview + Architect synthesis) |
| B. Resume riyadh-v3 in place | Fastest to a live attempt | Unrunnable entry (config lost); 7-min hang-prone gate; two demos in one repo; tunnel topology retained | Rejected — the shell is the failure, and it stays |
| C. Minimal greenfield (~1,500 lines) | Clean 30-min windows and cross-machine evidence by construction | Relearns write-intent markers, block-time parser rejections, retry split, rate ceiling — each on live testnet runs with a stakeholder watching | Rejected — cheap to port, expensive to relearn |
| D. Direct public Payer endpoint | Most literal "payer owns its endpoint" | Revives the inbound + self-signed-cert class that went 0-for-11 | Rejected — P2 |

---

## Requirements Summary

Two independent AI agents complete a bilateral payment-**authorization** handshake — `PROPOSED → ACCEPTED → ACKNOWLEDGED → fresh aggregate verification → AUTHORIZED` — each step anchored as an independently verifiable Clockchain receipt, observable live by a business audience, `paymentMoved:false` everywhere. Requestor driven by a stakeholder pasting **one prompt** into a fresh agent CLI; Payer optionally stakeholder-driven the same way. Operator funds four fresh Sepolia addresses (0.01 ETH, replay-safe) paying ERC-8004 registration gas for rehearsal + live pairs; the fresh verifier re-checks everything including on-chain `ownerOf` and alone emits `AUTHORIZED`, only for the stakeholder sub-run. Presentation: non-tech stakeholder view + operator control plane showcasing Clockchain. Full invariants and numbered acceptance criteria AC1–AC9: see spec.

---

## Target Architecture

```
handshake/
├── package.json              # deps: viem only; node >=22; no native builds
├── release.json              # SINGLE source of version identity (repo sha, kit ref)
├── src/
│   ├── core/                 # PORTED from riyadh-v3 — see port classification
│   │   ├── canonical.mjs              # ← src/bilateral/canonical.mjs (bilateral profile)
│   │   ├── canonical-v1.mjs           # ← src/canonical.mjs (v1 receipt-event base profile; bilateral canonical layers on it)
│   │   ├── messages.mjs / protocol.mjs / runner.mjs / descriptor.mjs / payer-mandate.mjs
│   │   ├── payment-request.mjs        # ← src/bilateral/payment-request.mjs (verdict dependency; digest binding at :193)
│   │   ├── roles-core.mjs             # ← roles.mjs runPayerRole(:525-645) + runPayeeRole(:796-923); invitation.mjs
│   │   │                              #   severed (all refs lie outside both functions — Critic-verified);
│   │   │                              #   runRoleCli(:1640) + buildDefaultRoleInput(:1453) dropped
│   │   ├── verdict.mjs                # ADAPTED (evidence-input surface, subjectRun gate, MALFORMED/MISSING/REORDERED sites)
│   │   ├── evidence.mjs               # ADAPTED (publish also uploads to relay; AUTHORIZING_WORD_PATTERN ban stays)
│   │   ├── refid.mjs / blocktime.mjs  # unchanged — expirySeconds stays "600"
│   │   ├── registration.mjs           # ← src/registration.mjs + src/registration-internal.mjs (two donor files, merged; small budget)
│   │   ├── clockchain.mjs             # ← src/mcp.mjs (read/write split, SSE parse, rate bounds intact)
│   │   ├── redact.mjs / private-path.mjs
│   │   └── funding/{record,journal,wallet}.mjs   # wallet = keystore.mjs minus Keychain
│   ├── relay/{server.mjs,client.mjs} # NEW
│   ├── roles/                # NEW thin wrappers around ported roles-core
│   │   ├── operator.mjs / payer.mjs / requestor.mjs / rehearsal-stub.mjs
│   ├── verifier/run.mjs      # NEW CLI around core/verdict — sole AUTHORIZED emission path; hosts the REORDERED check
│   └── monitor/
│       ├── snapshot.mjs      # run snapshot builder (single source for both views)
│       ├── stakeholder/      # public audience page — non-tech readable
│       └── control-plane/    # operator dashboard — Clockchain evidence showcase (loopback only)
├── bin/{operator,payer,requestor,relay,verify-run}.mjs
├── scripts/{release-pin.mjs,negative-checks.mjs,preflight.mjs,clean-agent-run.mjs,check-invariants.sh}
├── prompts/{requestor.md,payer.md}   # single pasted prompts (≤40 lines each)
├── test/                     # focused suite, < 60 s wall clock (see pruning policy)
└── docs/runbook.md           # ONE page; no docs-linter
```

### Port classification (semantic seam)
| Class | Modules | Rule |
|---|---|---|
| **Pure port — byte-faithful, import paths only** | canonical, canonical-v1, refid, blocktime, descriptor, messages, protocol, payer-mandate, payment-request, clockchain, redact, private-path, funding/record, funding/journal, runner | Donor tests ported alongside; any behavioral edit is a plan deviation. In-window bounds are applied **caller-side** via `pollDuration()` args (`runner.mjs:1309-1320`, accepts `[20_000, 1_800_000]`) — never by editing ported constants |
| **Adapted port — explicit edit budget, donor tests FIRST under the pruning policy** | `verdict.mjs` (edits: evidence-input surface; subjectRun gate; MISSING/REORDERED/MALFORMED emission sites), `evidence.mjs` (1 edit: publish-also-uploads seam), `roles-core.mjs` (severance only), `funding/wallet.mjs` (Keychain deletion), `registration.mjs` (two-file merge) | Each edit one commit with its own test |
| **New code** | relay/*, roles/* wrappers, verifier/run.mjs, monitor/*, scripts/* | Small, boring, framework-free |

**Donor-test pruning policy (per adapted module — Critic SHOULD 10):** port the donor test file; delete only describe-blocks exercising *deliberately removed* surfaces — `bilateral-roles.test.mjs` (1,555 L): the 20 `buildDefaultRoleInput`/`runRoleCli` references; `bilateral-funding-keystore.test.mjs` (473 L): the Keychain path — every deletion listed in the commit message; all retained-behavior tests kept. `bilateral-verdict.test.mjs` (2,578 L) ports intact; if the measured suite busts the 60 s budget, split into `test/` (fast subset, every commit) + `test/slow/` (full set, runs at every gate G0–G4) — measure first, split only if needed.

Dependency facts (Architect-verified): the port list cuts free of `coordination/storage.mjs` (3,910 L) and `supervisor.mjs` (1,071 L); the only cross edge is `coordination → verdict`. `runner.mjs` polls **Clockchain** for counterparty anchors (`runner.mjs:1374`) — the relay is out of the anchor path (it IS in the verification path; see Risks).

### Relay contract (NEW, dumb by design) — plain HTTPS+JSON
- `POST /v1/sessions` (operator-signed) → session registered.
- `POST /v1/sessions/{sid}/messages` — append signed envelope `{sessionId, role, seq, kind, body, senderKey, sig}`; relay validates size/shape/session only, never signatures (P1).
- `GET /v1/sessions/{sid}/messages?after=N&waitMs=25000` — long-poll.
- `PUT /v1/sessions/{sid}/evidence/{role}` — party-package triple; per-part bounds from the donor's verifier (`verdict.mjs:116-118`): JSON ≤ 1 MiB, markdown ≤ 2 MiB, marker ≤ 2 KiB → relay total cap **3 MiB + 2 KiB** (a maximal valid triple must pass; the donor's `runner.mjs:64` 1 KiB marker figure is superseded — verifier bounds are authoritative).
- `GET /v1/sessions/{sid}/evidence/{role}` — verifier pulls (outbound from operator).
- `GET /v1/discovery/{sid}` — serves the signed discovery doc.
- `GET /v1/sessions/{sid}/snapshot` — monitor JSON (verdict field only from the verifier's signed publication).
- `GET /healthz`.
- Append-only JSONL journal per session; restart re-reads (idempotent). Local `127.0.0.1` / public small box with real domain+TLS; **`relayUrl` is the entire topology switch.**

### Discovery document v2 (Critic MUST 7 — the ONLY handoff artifact, schema pinned)
Signed Ed25519 over canonical bytes; schema `handshake-discovery/v2`:
```
{ schema, sessionId, subjectRun, protocolVersion, relayUrl, payerEndpoint,
  kitRepoUrl, repositorySha, kitManifestDigest, clockchainUrl, registry, chainId,
  issuedAtMs, expiresAtMs (≥ issuedAtMs + 30 min), paymentMoved:false,
  operatorKeyId, signature }
```
No ECR/image-digest fields, no cert fields (real TLS). Generated from `release.json` at session start (`release:pin` is the only pin writer). **Kit integrity mechanism (both, enforced by the kit before any protocol step):** (1) `repositorySha` — the kit verifies `git rev-parse HEAD` equals it on a clean detached checkout; (2) `kitManifestDigest` — sha256 over the kit's tracked-file manifest at that commit, recomputed post-`npm ci` — belt-and-braces against transport substitution. Signature verified against the operator public key committed in the repo at that same sha.

### Evidence transport (cross-machine seam)
Donor verifier reads party evidence from local directories (`verdict.mjs:95-104`, `:663`). v2: roles upload the party-package triple to the relay **before** declaring `PARTY_COMPLETE` (retried within the wait budget); `verdict.mjs` accepts in-memory `{json, markdown, marker}` triples alongside the directory form with the byte-identical sha256-vs-marker check (`:691-696`); the verifier CLI pulls from the relay. P1/P2 hold for every machine.

### Deadline architecture — one authoritative budget (Critic MUST 4)
`expirySeconds` is a signed canonical descriptor field pinned to `"600"` (`descriptor.mjs:22`, checked at `:398` and `messages.mjs:462`, inside `dSession`). It stays. Safety comes from sequencing:
- **Pre-window (human-paced, ≥ 30 min, resumable, heartbeat):** prompt → `request_payment` → `handshake_required` → keypair/address → funding → ERC-8004 registrations → readiness signals. No anchor exists; nothing can expire. **Construction guard:** `mandate.expiresAtMs − issuedAtMs ≥ 30 min` and ≥ discovery expiry (constructed field, `payer-mandate.mjs:13`/`:201` — invisible to identifier sweeps, so asserted at construction).
- **Window (opens at the `PROPOSED` block time):** the complete arithmetic, quoted everywhere else in this plan (Critic final finding — the two previously omitted terms included):
  `PROPOSED block-time → write-return offset ≤ ~102 s (completion-polling term, mcp.mjs:50) + requestor detection ≤ 20 s + read ≈ 10 s + ACCEPTED write ≤ 223.5 s + payer detection ≤ 20 s (MIN_POLL_INTERVAL_MS, runner.mjs:47) + read ≈ 10 s + ACKNOWLEDGED write ≤ 223.5 s ≈ 609 s — the absolute worst case EXCEEDS the 600 s window.`
  **Two-regime statement (the only quotable version):** in the *healthy regime* the preflight gate admits (median `get_block` < 1.5 s), writes land in seconds and the window completes with several minutes to spare; in the *maximal-throttling regime* the worst case is ≈ 609 s > 600 s, so the run closes named `EXPIRED` **by design** — the dynamic bound + floor check guarantee a clean named failure, never a zombie, and the preflight gate exists precisely to not start runs in that regime. The runbook quotes this two-regime statement verbatim; nothing rosier.
- **Caller-side bound — dynamic, not the whole window (Architect iteration-2 fix):** the window runs from the PROPOSED **block time** (`blocktime.mjs:126`), which starts before the write even returns, and the `ACKNOWLEDGED` write needs its own budget after `ACCEPTED` is found. The payer wrapper therefore computes, at watch start:
  `pollDurationMs = proposalDeadlineMs − now − ACK_WRITE_BUDGET_MS` (with `ACK_WRITE_BUDGET_MS ≈ 223_500`, the rate ceiling; `proposalDeadlineMs` is already threaded through `runner.mjs:77,1127-1162,1208,1251,1432`).
  **Floor check before calling `pollDuration()`:** if the computed bound < `MIN_POLL_INTERVAL_MS` (20 s), the wrapper closes the run itself with named `EXPIRED` ("window too depleted to complete safely") — because `pollDuration()` below the floor throws generic `terminal("FAILED")` (guard at `runner.mjs:1313-1317`, throw at `:1318`), which would violate P3. Ported constants untouched.
- **Invariant test (M0):** in-window poll bounds ≤ **remaining window minus the reserved `ACK_WRITE_BUDGET_MS`** (never merely ≤ `EXPIRY_WINDOW_MS` — `600_000 ≤ 600_000` must NOT pass); mocked-clock tests prove (a) a late `ACCEPTED` discovery still leaves the full ACK budget before `proposalDeadlineMs`, and (b) a sub-floor computed bound closes with named `EXPIRED`, not generic `FAILED`; no human-paced wait inside the window; mandate construction guard; `expirySeconds === "600"`; canonical vectors byte-identical to donor.
- **Escape hatch:** if G1 measurement shows the budget red, take the protocol-version bump deliberately (regenerate vectors) as a named task — never silently.

### Rehearsal sub-run = topology drill
Scripted stub requestor (`roles/rehearsal-stub.mjs`, ~150 L) on the operator machine through the **full external path** (discovery fetch → relay → registration/funding → 3 anchors → evidence upload → verifier assembly). Drills the 0-for-11 failure class, not the proven protocol.
- **Two-layer AUTHORIZED forcing (Critic SHOULD 12):** (1) the rehearsal path calls `verifyRehearsal()`, which returns only `REHEARSAL_PASSED`/named failures and has no code path to the `AUTHORIZED` emission; (2) independent of any CLI flag, the emission site itself asserts `mandate.subjectRun === "stakeholder"` from the *signed mandate* — a routing mistake cannot reopen the double-emission hazard.
- **Mandate invariants + tests:** distinct `intakeRequestId` per sub-run (refid-collision guard — discipline formerly in unported `relay.mjs:1007-1011`, `:1465-1503`); **subjectRun-correctness** (rehearsal mandate constructed with `subjectRun === "rehearsal"`, live with `"stakeholder"`); `verifyRehearsal()` on a stakeholder-mandate input still cannot emit `AUTHORIZED`.
- Rehearsal passing gates stakeholder engagement; 4 identities / 4 funded addresses per spec.

**Join model:** unguessable `sessionId`; fresh keypairs; first valid signed role-claim binds; later claims refused `ROLE_ALREADY_BOUND`. No human gates mid-run.

**Statuses** (business line + machine JSON, all `paymentMoved:false`): `SESSION_STARTED, REHEARSAL_PASSED, TERMS_PUBLISHED, REQUEST_SUBMITTED, HANDSHAKE_REQUIRED, IDENTITY_REGISTERED, FUNDED, PROPOSED, ACCEPTED, ACKNOWLEDGED, EVIDENCE_RECEIVED, VERIFYING, AUTHORIZED (sole emission: verdict, stakeholder sub-run)`.

### Reason codes — enumerated emission sites (Critic MUST 2 + 3)
Frozen public set: `RENDEZVOUS_UNAVAILABLE, EXPIRED, MISSING, DUPLICATE, REORDERED, MALFORMED, AMBIGUOUS_WRITE, BINDING_MISMATCH, ANCHOR_UNVERIFIED, ROLE_ALREADY_BOUND, RATE_BLOCKED, AMOUNT_UNRESOLVED, FUNDING_REPLAYED, FAILED`.
- `MISSING`: verifier empty-search branch, replacing the donor's `EXPIRED` misuse at `verdict.mjs:741-745`. (adapted-port edit)
- **`REORDERED`: implemented in `verifier/run.mjs` (new code)** as an explicit order check over the re-read anchor sequence — the donor's transition-order ladder (`protocol.mjs:126-134`, `PROTOCOL_STATE_ORDER`) stays pure-ported and untouched; **reference implementation for the logic: the donor's working watcher `scripts/watch-bilateral-session.mjs:415`** (`WatcherTerminal("REORDERED")`, tests at `test/bilateral-watcher.test.mjs:394,447`). Block-time monotonicity at `verdict.mjs:901` remains `ANCHOR_UNVERIFIED` — it is a different failure and keeps its code.
- **`MALFORMED`: emitted at input-shape validation boundaries only**, added call-site-by-call-site (each its own commit + failing-shape test): (a) party-package JSON/marker schema checks in `loadPartyPackages` (`verdict.mjs:663-700`); (b) descriptor/mandate/request envelope shape validation on the verifier's recovery entries; (c) anchored-transition payload schema recovery. **The `fail()` default parameter (`verdict.mjs:155`) remains `"FAILED"` — asserted by a negative test** (57 bare `fail()` sites must not be retagged).
- `ROLE_ALREADY_BOUND`, `RENDEZVOUS_UNAVAILABLE`, `RATE_BLOCKED`: relay client (new code). `FUNDING_REPLAYED`: funding-journal refusal path. `AMOUNT_UNRESOLVED`: ported as-is (`protocol.mjs:69,179`). Others: ported sites unchanged.
- `check-invariants.sh` asserts every code in the set has ≥ 1 emission site (grep-driven checklist).

### AUTHORIZED containment — named allowlist (Critic MUST 1)
G0 invariant restated: **exactly one emission site** (`core/verdict.mjs` verdict builder, subjectRun-gated). All other occurrences allowlisted by site + reason in `check-invariants.sh`:
| Site | Reason |
|---|---|
| `core/verdict.mjs` (emission + `validatePublishedBilateralVerdict`) | The verdict itself and its validator |
| `core/evidence.mjs` `AUTHORIZING_WORD_PATTERN` (donor `:180`, used `:436,:463`) | A **ban** pattern — the anti-false-authorization guard; kept |
| `monitor/stakeholder/` + `monitor/control-plane/` message maps | Display-only; rendered exclusively from the verifier's signed publication; pre-verdict absence tested |
| `test/**` | Tests |
Anything else containing the literal fails G0.

### Presentation layer (user Round-5 requirements)
Both views read the same snapshot JSON; both framework-free, zero build step.

**Stakeholder/audience view** (`monitor/stakeholder/`, public in M2): five-step plain-English timeline with green checks ("Payer published the payment terms" → … → verdict); "**No money has moved**" as a human sentence on every state; three receipt cards with block refs and "View on Clockchain" links; hashes/JSON only behind an expandable "Technical evidence" fold; honest-stall display ("still working — last update Ns ago"). **G3 readability rubric (falsifiable):** the message-map completeness test guarantees no raw code ever renders; at G3 a person who has not worked on the project narrates the page aloud during a dress rehearsal and must correctly answer, from the page alone: what step is happening, has any money moved, and where can this be independently checked — recorded in the rehearsal checklist.

**Operator control plane** (`monitor/control-plane/`, loopback only, served by the operator process): per-anchor evidence panel (block height, ledger ID, timestamp, prettified receipt payload, digest chain); **live "Re-verify receipt" button** per anchor doing a real read-only Clockchain call through the operator process; audit-trail view; funding-journal view; per-role status + heartbeat tail; preflight status. Exactly two controls: **Start** and **Abort** — it shows, it never gates. Verdict display rules identical to the public page.

**Stakeholder-run Payer** (standard M3 deliverable; complexity LOW — symmetric wrapper, terms inside the operator-signed payer discovery doc, kit signs/publishes them). Owner-driven payer remains the run-1 fallback.

---

## Spec-deviation register (Critic SHOULD 11)
| # | Spec says | Plan does | Why |
|---|---|---|---|
| D1 | Mandatory fix: `blocktime.mjs:17` `EXPIRY_WINDOW_MS` → ≥ 30 min | **Refused deliberately.** `expirySeconds` is a signed canonical field (`descriptor.mjs:22,398`; `messages.mjs:462`) inside `dSession`; changing it invalidates every refid and canonical vector. Equivalent safety via sequencing + construction guards + caller-side bounds; escape hatch = deliberate version bump after G1 measurement | Architect MUST-FIX 2, Critic-verified |
| D2 | "Salvage relay route shapes from `coordination/relay.mjs` (it already models the mailbox)" | **Rebuilt instead.** The donor relay (2,294 L — unported, not "deleted") is an event-envelope/store-replay machine bound to `storage.mjs` (3,910 L) with one `/v1/` route literal; its two load-bearing behaviors (subjectRun identity binding, `mandateForRun`) are re-encoded as tested invariants | Critic-inspected; rebuilding confirmed correct |
| D3 | Spec claimed `REORDERED` "today collapses into `ANCHOR_UNVERIFIED`/`BINDING_MISMATCH`" | Corrected: the donor's *aggregate verifier* lacks the code; a working `REORDERED` exists in the unported watcher (`watch-bilateral-session.mjs:415`) and serves as reference logic | Critic finding 2; spec text amended |

---

## Implementation Steps (by milestone)

### M0 — Foundation port (2–3 days) → Gate G0
1. Verify the Architect's dependency map (hours): import closure, `payment-request.mjs`, the `roles.mjs` severance boundaries (Critic re-verified: all `invitation` refs lie outside `runPayerRole`/`runPayeeRole`).
2. Scaffold repo: `package.json` (viem 2.55.8 only), `release.json`, git init, `.gitignore` (state roots, keys, journals).
3. Port the **pure** class byte-faithfully, donor tests alongside per the pruning policy; measure suite time (split fast/slow only if > 60 s).
4. Port the **adapted** class — donor tests FIRST, then one commit per edit:
   a. `funding/wallet.mjs`: Keychain path deleted (`keystore.mjs:357-392`); 0600 file / env only.
   b. `verdict.mjs`: in-memory party-package surface (directory form kept for tests).
   c. `verdict.mjs`: `subjectRun === "stakeholder"` assertion at the emission site + `verifyRehearsal()` entry.
   d. `evidence.mjs`: publish-also-uploads seam (transport injected; `AUTHORIZING_WORD_PATTERN` kept).
   e. Reason codes per the enumerated sites: `MISSING` (verdict), `MALFORMED` (three site families, each own commit + test, `fail()` default asserted unchanged). `REORDERED` lands in M1 with `verifier/run.mjs`.
   f. `roles-core.mjs` severance; `registration.mjs` two-file merge.
5. Deadline-coherence invariant test (single budget arithmetic; caller-side bounds; mandate construction guard; `expirySeconds` `"600"`; vectors byte-identical).
6. Mandate invariants tests: distinctness + subjectRun-correctness.
7. `scripts/release-pin.mjs` + `scripts/check-invariants.sh` (AUTHORIZED allowlist; scoped wait-identifier sweep with the named allowlist for `clockchain.mjs` HTTP bounds; reason-code site checklist; single pin source).
- **Gate G0**: suite green (< 60 s fast set; slow set green too); `check-invariants.sh` clean; canonical vectors byte-diff clean vs donor.

### M1a — Protocol path green, local (2–3 days) → Gate G1a (= spec AC1 core)
8. `relay/server.mjs` + `client.mjs` per contract (journal restart test; evidence bounds test incl. maximal-valid-triple acceptance).
9. `roles/operator.mjs`: session → signed discovery (schema above, served by relay) → rehearsal topology drill (stub through full external path) → `verifyRehearsal` gate → register/fund live identities (auto) → payer launch → live sub-run → **fresh verifier spawn** → signed verdict publication to snapshot.
10. `roles/payer.mjs`: bind → publish mandate (construction guards) → await `request_payment` (human-paced ≥ 30 min, heartbeat) → await requestor readiness → anchor `PROPOSED` → in-window watch `ACCEPTED` (dynamic bound: `proposalDeadlineMs − now − ACK_WRITE_BUDGET_MS`, floor-checked with named closure) → anchor `ACKNOWLEDGED` → evidence upload.
11. `roles/requestor.mjs` (kit): discovery fetch → signature + `repositorySha` + `kitManifestDigest` checks → `request_payment` → instructions → keypair/address → funding wait → register → ready → in-window `ACCEPTED` → evidence upload (retried, pre-`PARTY_COMPLETE`) → "this is not authorization".
12. `verifier/run.mjs`: fresh process; pulls discovery/mandate/request/evidence from relay; re-reads 3 anchors from Clockchain; **`REORDERED` order check (watcher logic as reference)**; `ownerOf`; audit trail; `AUTHORIZED` (stakeholder only) or named code; signed publication.
13. `scripts/preflight.mjs` — **pinned latency gate (Critic MUST 5): median of 5 `get_block` reads < 1,500 ms AND p95 < 4,000 ms, sampled within 10 min of run start, printed in preflight output** (initial bounds; re-derived from G1 measured runs + the donor's three green-run telemetry); Sepolia RPC check; treasury ≥ 0.05 ETH; relay `/healthz`.
14. `prompts/requestor.md` v1 (≤ 40 lines).
- **Gate G1a**: one command + one pasted prompt in a fresh local agent → rehearsal drill passes → live sub-run: 3 anchors in order → `AUTHORIZED` → then `kill -9` matrix (each component, incl. **relay killed after `ACKNOWLEDGED` before evidence pull** — resume or named fail-closed) → `npm run negative` (replay / reorder / tamper / duplicate-funding → 4 distinct codes) → **in-window timing measured and logged** (escape-hatch decision).

### M1b — Both views functional (1–2 days) → Gate G1b
15. `monitor/snapshot.mjs` + stakeholder view + control plane, behavior-complete (timeline, receipt cards, evidence fold, honest-stall; evidence panel, live re-verify, Start/Abort, heartbeat tail). Polish deferred to M3.
- **Gate G1b**: both views correct against a live local run; message-map completeness test green; pre-verdict `AUTHORIZED`-absence test green against both views. *(M1b cannot be shed: G1 = G1a + G1b.)*

### M2 — Public topology (2 days) → Gate G2
16. Deploy relay to a small always-on box (real domain + TLS; host = open item, decided here; AWS optional). `--relay-url` is the only delta. Rehearsal drill now exercises the public relay.
17. Public stakeholder page at the public snapshot URL; `/handshake/run` on clockchain-research.vercel.app reads it (separate repo — coordinate; local page remains the fallback).
18. `scripts/clean-agent-run.mjs`: prints the prompt, tails the snapshot, **and asserts isolation for local secondary agents — throwaway `HOME`, scrubbed env (documented against the donor's `acceptance:clients` flaw), printed in harness output** (Critic NICE 14).
- **Gate G2**: full run, Requestor via **fresh Hermes remote gateway** (no context, no skills, prompt only), different machine, < 15 min incl. `npm ci`. Secondary: fresh Claude Code + Codex under the isolation harness; **at least one secondary run from a non-macOS client (the Hermes gateway's Linux environment counts if applicable — record which OS)**.

### M3 — Stakeholder rehearsal + polish (2 days) → Gate G3
19. `prompts/payer.md` (standard deliverable, owner fallback run-1); immutable per-run summaries (`runs/{id}.json`, append-only); one-page `docs/runbook.md` (quotes the two-regime budget verbatim, nothing rosier); rehearsal checklist.
20. Presentation polish pass (still framework-free); readability rubric prepared.
21. Two back-to-back full dress rehearsals (fresh sessions/addresses; journal proves replay-safety), ≥ 1 with a fresh agent driving the Payer prompt.
- **Gate G3 (explicit ACs — Critic MUST 6)**: spec **AC1–AC7 and AC9** all pass in a clean-room dress rehearsal (AC8's "fresh full pass after the live run" lands at G4 by design); readability rubric passes with an uninvolved narrator; control plane re-verify works live against Clockchain.

### M4 — Live demo + post-run hardening → Gate G4
22. Live stakeholder run → one fresh full `npm run test` pass (fast + slow) → only then the hardening backlog.

---

## Risks and Mitigations
| # | Risk | Rating | Mitigation |
|---|------|--------|------------|
| 1 | **Clockchain is the sole protocol rendezvous** — anchor path AND (via `pollForTransition`) counterparty detection; an outage is a total stop | **HIGH** | **Pinned preflight latency gate** (median-of-5 `get_block` < 1,500 ms, p95 < 4,000 ms, printed); ported rate bounds (223.5 s ceiling); resumable waits; honest `RENDEZVOUS_UNAVAILABLE` closure; demo script includes a hold path (pre-mortem 3). *Honest note: in-window there is no mitigation but the ~120 s cushion; no fallback pretense* |
| 2 | Relay outage in the **verification path** (evidence upload/pull) — relay is out of the anchor path but v2's evidence transport put it in the verification path | Medium | Journal restart-resume (tested); waits resume across relay restarts; **specific integration case: relay killed after `ACKNOWLEDGED`, before verifier pull → resume or named fail-closed** |
| 3 | Evidence upload fails on the stakeholder machine after `ACCEPTED` | Medium | Upload before `PARTY_COMPLETE` with retries in budget; verifier closes `MISSING` honestly; receipts remain publicly visible |
| 4 | Sepolia RPC/gas failure at funding/registration | Medium | All Sepolia work pre-window; preflight; ported gas caps; journal resumes |
| 5 | In-window budget overruns 600 s under live throttling | Medium | Only machine-paced steps remain in-window; worst case ≈ 609 s > 600 s under maximal throttling → named `EXPIRED` by design (two-regime derivation, Deadline architecture); the pinned preflight gate keeps runs out of that regime; G1a measures empirically; deliberate version-bump escape hatch |
| 6 | Fresh agent misreads prompt / claims false success | Medium | Kit owns crypto/state; prompt forbids success claims; verifier sole authority; G2 = 3 agent brands + isolation harness |
| 7 | Vercel site coordination lags (separate repo) | Medium | Local stakeholder page is the M1b deliverable; public page additive; demo never blocks on Vercel — *note: spec AC4's public-monitor criterion is satisfied by the public snapshot + local fallback; recorded here rather than silently downgraded* |
| 8 | Port entanglement | LOW (Architect-verified map; Critic re-verified severance) | M0 step 1 verifies in hours |
| 9 | Scope-shedding of the views under schedule pressure | LOW (was the real M1 risk) | M1 split: G1 = G1a + G1b; views cannot be dropped to make a gate |
| 10 | Two runs' evidence cross-contaminates (replay) | Low | Session-scoped refids; mandate distinctness + subjectRun tests; `npm run negative` replays prior-run evidence every rehearsal |

## Pre-mortem (3 scenarios, deliberate mode)
1. **"Demo froze at ACCEPTED for 25 minutes."** Clockchain throttled mid-window. The window holds only machine-paced steps (two-regime budget: healthy regime completes with minutes of slack; maximal throttling can exceed the window and closes named `EXPIRED`); heartbeats keep the page honest ("still writing to the ledger — no money has moved"). A blown window closes `EXPIRED`, named, on both views — no zombie polling (invariant test forbids poll bounds beyond the window). *Consequence: honest-stall UX is a first-class monitor feature.*
2. **"The stakeholder's agent went rogue."** Fresh Hermes misparsed the prompt, ran something else, declared victory. The kit refuses to run outside a clean checkout matching `repositorySha` + `kitManifestDigest`; `PARTY_COMPLETE` states "not authorization"; verifier and monitor ignore narration (P1). Worst case `EXPIRED`/`MISSING`, honestly displayed. *Consequence: prompt tested against 3 agent brands at G2; kit stdout is all the agent needs.*
3. **"Clockchain went down an hour before the demo."** The pinned preflight gate fails → the run is **not started**; the operator shows rehearsal-drill receipts and the control plane's re-verify on *prior* anchors still works (reads may recover before writes); live segment rescheduled. Mid-run: pre-window → `RENDEZVOUS_UNAVAILABLE` before stakeholder work is wasted; in-window → `EXPIRED`. *Consequence: the demo script includes a rehearsed hold path; failure states are rehearsed, not improvised.*

## Expanded Test Plan (deliberate mode)
- **Unit (< 60 s fast set; no network; no timers > 100 ms):** ported canonical vectors (byte-identical — proves `expirySeconds` untouched); state machine order + every reason code incl. the three `MALFORMED` site families and the `fail()`-default negative assertion; discovery schema + sign/verify + tamper; kit-integrity checks (`repositorySha`, `kitManifestDigest`); mandate/request digest binding; funding journal replay refusal; wallet file/env only; write-intent marker adopt/fail; deadline-coherence invariant (incl. mandate construction guard, caller-side bounds); mandate distinctness + subjectRun-correctness; subjectRun gate (rehearsal input can never reach the emission); `verifyRehearsal` cannot emit; verdict in-memory ≡ directory equivalence.
- **Integration:** relay journal restart-resume; long-poll across relay kill; evidence upload/pull round-trip incl. maximal-valid-triple and oversize rejection; **relay killed post-`ACKNOWLEDGED` pre-pull → resume/named-fail**; role rebind refusal; operator crash between funding and verifier → resume; stubbed-Clockchain full session (donor `test/helpers/` fixtures).
- **E2E (at gates, real testnets):** G1a local live + kill matrix + `npm run negative` + timing measurement; G2 clean-room Hermes + isolated secondaries + non-macOS datapoint.
- **Observability & presentation:** heartbeat ≤ 30 s from every waiting component (asserted); `/healthz`; snapshot schema-validated; `paymentMoved:false` on every status (schema test); no stack traces in public streams (ported redaction test); message-map completeness (no state renders as a raw code); control-plane re-verify against stubbed client; pre-verdict `AUTHORIZED`-absence against both views.

## Verification Steps (gate commands)
- **G0**: `npm run test` (< 60 s fast; slow set too) && `scripts/check-invariants.sh` (AUTHORIZED allowlist + single gated emission site, no Keychain, scoped wait-identifier sweep with named allowlist, reason-code site checklist, single pin source, canonical byte-diff vs donor).
- **G1a**: `npm run operator -- --config config/local.json` + pasted prompt (fresh local agent); kill matrix incl. the evidence-pull window; `npm run negative`; timing report reviewed against the two-regime budget (escape-hatch decision).
- **G1b**: both views against the live local run; presentation tests green.
- **G2**: `scripts/clean-agent-run.mjs` → fresh Hermes < 15 min; Claude Code + Codex under isolation harness; OS mix recorded.
- **G3**: two dress rehearsals; spec AC1–AC7 + AC9 checklist; readability rubric with uninvolved narrator; live re-verify demonstrated.
- **G4**: live run → fresh full pass (fast + slow) → hardening backlog opens.

## ADR
- **Decision**: Fresh repo; port riyadh-v3's protocol core along a **semantic seam** (pure byte-faithful vs adapted-with-budget: `verdict`, `evidence`, `roles-core`, `wallet`, `registration`) on an outbound-only untrusted relay (one URL flag; discovery schema pinned; evidence via relay upload/pull), deadlines fixed by sequencing with one authoritative two-regime budget (healthy regime: minutes of slack; maximal throttling: ≈ 609 s > 600 s closes named `EXPIRED` by design), rehearsal as a topology drill with two-layer `AUTHORIZED` forcing, ERC-8004 + 4 addresses retained, presentation as two framework-free views off one snapshot, clean-room fresh-agent validation.
- **Drivers**: delivery caused 100% of live failures but three delivery assumptions hide inside the proven core; one-prompt stakeholder experience is the hard gate; field-learned invariants are cheap to port, expensive to relearn live.
- **Alternatives**: resume riyadh-v3; minimal greenfield; direct public payer endpoint; rehearsal as protocol drill — each rejected with reasons above.
- **Why chosen**: keeps every field-learned invariant while surfacing the cross-machine adaptations at plan time.
- **Consequences**: `verdict.mjs` adapted (donor 2,578-line test as net); relay carries evidence (rationale for risk 2 updated accordingly); ~6 anchors + 4 registrations per session (well under treasury); one small always-on relay; two spec deviations recorded in the register.
- **Follow-ups**: MCP thin adapter (post-live, optional); Vercel coordination; version-bump decision after G1a timing; hardening after G4; riyadh-v3 archived as donor + evidence.

## Open Items (non-blocking, defaults set)
- Relay host box + domain: operator's choice at M2 step 16 (any provider; AWS optional).
- Demo date: TBD; G3 is the readiness bar.
- Run-1 Payer driver: demo owner (stakeholder-Payer standard via `prompts/payer.md`).

## Changelog
- **v6 (final)** — Critic re-evaluation verdict: **APPROVED** (all round-1 items verified genuinely addressed; three exceeded the ask). Its one non-blocking finding applied immediately rather than deferred: the budget derivation completed with the two previously omitted terms (PROPOSED block-time offset ≤ ~102 s; requestor's own detection + read), honest worst case ≈ 609 s > 600 s stated as the two-regime rule and propagated to risk 5, pre-mortem 1, runbook rule, G1a, ADR. Nits fixed (canonical-v1 rationale; `runner.mjs:1318` throw site). Consensus complete: Planner ×3 revisions, Architect REVISE→APPROVE→(delta)REVISE-1→resolved, Critic REVISE→APPROVED.
- **v5** — Architect iteration-2 delta-review (verdict: REVISE on one item, all else APPROVE):
  - In-window poll bound made **dynamic**: `proposalDeadlineMs − now − ACK_WRITE_BUDGET_MS` (window runs from the PROPOSED block time, and the ACKNOWLEDGED write needs its own ~223.5 s budget); wrapper floor-checks before `pollDuration()` and closes named `EXPIRED` (the ported helper throws generic `FAILED` below the floor — P3). Invariant restated so `600_000 ≤ 600_000` cannot pass; mocked-clock tests added for late-discovery and sub-floor cases.
  - Architect confirmed: evidence-transport bounds, port classification, two-layer subjectRun forcing (called an improvement), deadline sequencing arithmetic, and the REORDERED re-siting all unbroken; every Critic citation re-verified exactly against the donor.
- **v4** — Critic round 1 (verdict: REVISE) incorporated:
  - MUST 1: `AUTHORIZED` allowlist named by site+reason; G0 restated as single gated *emission* site (donor's `evidence.mjs` ban pattern and the display maps allowlisted).
  - MUST 2: `REORDERED` re-sited to `verifier/run.mjs` (new code) with the donor watcher (`watch-bilateral-session.mjs:415`) as reference; `protocol.mjs` stays pure; spec's "collapses into" claim corrected (deviation D3).
  - MUST 3: `MALFORMED` sites enumerated (three families); `fail()` default asserted unchanged by negative test.
  - MUST 4: single budget derivation (~480 s worst / ~120 s cushion) propagated to risks + pre-mortem + runbook rule.
  - MUST 5: preflight latency gate pinned (median-of-5 `get_block` < 1,500 ms, p95 < 4,000 ms, printed).
  - MUST 6: G3 references explicit spec ACs (AC1–AC7 + AC9); spec criteria numbered.
  - MUST 7: discovery schema field list restored + kit integrity mechanism (repositorySha + kitManifestDigest) specified.
  - SHOULD 8–12: risk 2 rationale corrected + evidence-pull kill case; M1 split into M1a/M1b (views unsheddable) + M2/M3 re-baselined to 2 days; donor-test pruning policy; spec-deviation register (D1–D3); two-layer rehearsal forcing + subjectRun-correctness test.
  - NICE 13–14: canonical-v1 mapping stated; registration two-file merge named; evidence bound corrected to 3 MiB + 2 KiB; donor relay wording fixed ("unported", 2,294 L); step numbering fixed; cross-OS datapoint + isolation assertions added to G2 harness.
  - Critic open questions answered in place: control-plane loopback P2 clarification (P2 bullet); cushion arithmetic shown once; verdict-test 60 s handled by measure-then-split; `runner.mjs` `FAILED` sites not retagged (P3 bullet).
- **v3** — Architect APPROVE residuals (mandate construction guard; caller-side poll bound; margin correction) + user Round-5 presentation requirements + stakeholder-Payer elevation.
- **v2** — Architect round 1 (REVISE) incorporated: evidence transport routes + in-memory verdict surface; sequencing fix keeping `expirySeconds="600"`; deadline-coherence invariant; subjectRun gate + topology-drill rehearsal + mandate-distinctness; `payment-request.mjs` + roles severance; port classification; scoped G0 sweep; re-ranked risks; M0 re-baselined.
- v1 — Planner draft.
