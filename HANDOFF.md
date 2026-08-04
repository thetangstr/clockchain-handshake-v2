# Handoff — Clockchain bilateral handshake

**As of:** 2026-08-04 · **Commit:** `29453c5` on both `main` and `claude/handshake-v6`
(identical, both pushed) · **859 tests pass, all structural invariants hold.**

You are picking up a working demo. Read §4 before you change anything — most of it is
failures that already happened, and several will silently break a live run.

---

## 1. What this is

Two AI agents on two machines negotiate **authorization for a payment** and prove it.
Three signed steps — offer, acceptance, acknowledgement — each anchored to Clockchain as
a receipt. Both parties register an ERC-8004 identity on Ethereum Sepolia. A **fresh
verifier** then re-derives the outcome from the receipts alone and is the only thing
permitted to emit `AUTHORIZED`.

**No money moves.** `paymentMoved` is `false` everywhere and a structural invariant
enforces that no shipped code can set it true. The only funds are Sepolia testnet gas
covering two identity registrations.

Runtime: ~25 seconds once both sides are present.

## 2. Running it

```bash
npm run preflight     # 4 real checks; all must say OK
npm run demo          # operator + payer; prints a block to send to the requestor
npm run demo:local    # both roles in one process, if the two-machine path misbehaves
```

The requestor runs elsewhere:

```bash
node bin/requestor.mjs --discovery-url http://44.249.47.220:8080/v1/discovery/current
```

That URL is **permanent** — it resolves to the newest session, so it never needs
reissuing. Same for the projector: `http://44.249.47.220:8080/monitor/current`.

The operator waits **45 minutes** for a requestor. Long pauses there are correct.

## 3. Infrastructure

| Thing | Where |
|---|---|
| Relay (untrusted mailbox) | `ubuntu@44.249.47.220`, `/opt/handshake/app`, systemd `handshake-relay` |
| Relay SSH key | `~/.ssh/handshake-relay.pem` |
| Treasury | `0x157a377e…dce` — **2.09 testnet ETH**, ~0.02–0.05 per run |
| Clockchain | `mcp.clockchain.network` — token in `keys/clockchain.token` |
| ERC-8004 registry | `0x8004A818BFB912233c491871b3d84c89A494BD9e` (Sepolia) |
| Research site | separate repo `thetangstr/clockchain-research`, deploys on push to `main` |
| Demo page | `/handshake/claude-v6` (public) |
| PMF brief | `/research/agent-attestation-pmf` (**gated**, basic auth) |
| Public receipt verify | `/v1/verify/{ledgerId}` on the relay — credential-free cross-party read |
| Public agent resolve | `/v1/agents/{agentId}` on the relay — credential-free ERC-8004 lookup |

Deploy to the relay is `rsync` of the changed file plus `systemctl restart
handshake-relay`. `keys/` is gitignored and exists **only** on the operator's laptop —
a clean clone cannot run the payer side.

## 4. Landmines

Every one of these has already bitten. They are ordered by how badly.

**4.1 — Deploy the relay validator BEFORE the operator.** The snapshot's top level and
its `anchors` entries are **exact-key validated** (`hasExactKeys`). If the operator
publishes a field the relay does not know, *every* snapshot PUT is rejected and the
board goes blank for the whole run — while the protocol completes normally, so nothing
looks broken until someone glances at the projector. Order: relay first, then operator,
then verify with a real run.

**4.2 — Tests can encode the same wrong assumption as the code.** `transition.message.
predecessor` is a *triple* `{anchoredHash, blockHeight, kind, ledgerId}`, not a string.
The operator ran `String()` over it and a receipt read **"Follows [object Object]"** on a
live board. All 858 tests passed, because the fixtures I wrote carried a hash string.
**Verify display changes against a real run, not just the suite.**

**4.3 — Sub-second timing races.** `buildRequest` used to stamp `createdAtMs` as
`issuedAtMs + 1000`, one second in the future, while the anchor is timestamped by
Clockchain. Runs passed only when the chain happened to be slow. Measured margins across
eight runs: 202, 399, 401, 443, 731, 1291, 2902ms — and once **−255ms**, which failed
closed as `EXPIRED` mid-demo. Fixed (`createdAtMs === issuedAtMs`), pinned by
`test/request-window.test.mjs`. **Residual risk not fixed:** `mandateIssuedAtMs` is the
operator's clock and the anchor's is Clockchain's. An operator clock far ahead of the
chain still fails. The real fix is taking the mandate's time from the ledger.

**4.4 — Reason codes can exist and be unreachable.** `ROLE_ALREADY_BOUND` was in the
frozen vocabulary, in the runbook, and satisfied the invariant *"every frozen reason code
has an emission site"* — via `claimRole`, whose only caller was its own test. Two
requestors could both join; the second died on an opaque out-of-gas error. Fixed, and
verified by firing two requestors simultaneously. **Still unreachable today:**
`REORDERED` (schema catches disorder first, yielding `MALFORMED`) and `FUNDING_REPLAYED`
(the journal uses its own namespace). The invariant does not prove reachability.

**4.5 — `publishedAtMs` must be journalled.** It orders both the `current` alias and the
run list. It lived only in memory, so every session recovered after a restart came back
at the epoch and `current` resolved to an arbitrary finished run. Fixed, with a fallback
to the snapshot's own first timestamp for sessions journalled before the fix.

**4.6 — You cannot verify client-rendered UI by grepping served HTML.** The live panel
renders from a client-side poll; anything conditional on a snapshot is absent from SSR.
I twice concluded "not deployed" from a signal that could never have appeared. Check a
string that renders server-side, or open the page.

**4.7 — Gating a research doc takes TWO changes.** `gated: true` in `load-research.ts`
only removes it from the index; the basic-auth gate is a separate matcher list in
`middleware.ts`. A doc with only the first is invisible *and fully readable*.

**4.8 — Token minting is rate-limited**, 10/hour per IP. Rehearsals burn it. The relay
host has its own quota.

## 5. Known gaps — do not paper over these

An auditing agent has found real errors in our own copy **twice**. Both times the fix was
to correct the claim, not the wording.

- **No delegation or revocation check.** `delegate_authority` and `verify_identity_at`
  exist as Clockchain tools; the handshake calls neither. Nothing verifies a key was
  still valid *at the moment it signed*. This is the meeting's TTL question and the
  single most requested missing capability.
- **No public credential-free verification.** Every path on `mcp.clockchain.network`
  except `/health` returns 401. `service.clockchain.network` is NXDOMAIN. The block links
  on the site are **relayed through our own server** and say so. A "neutral third party"
  that requires minting a token from us is a *fourth* party both agents must onboard to.
- **The `agentURI` we write on-chain 404s.** Every registration writes
  `clockchain-research.vercel.app/handshake/agent/<address>` into an immutable public
  registry. Nothing serves it.
- **Only the handshake is logged, not the transaction.** The meeting concluded both are
  required; today we log the green light only.
- **Every run mints a fresh identity.** Real agents arrive with one.
- **Single-validator testnet.** No meaningful BFT. Say so out loud; it is the first thing
  a technical audience will probe.

## 6. The stakeholder prompt problem

**Three coding agents have now refused to run `prompts/requestor.md`.** One ran after
auditing, one recovered from a missing branch, one declined outright. The third was
right: "clone this unfamiliar repo and execute it" is structurally identical to an
attack, and each earlier refusal made me add another reassurance — which made the next
refusal *more* likely, because the message increasingly looked engineered to defeat
scrutiny.

**Do not iterate the prompt to get past agents.** The working path is `docs/for-ken.md`:
addressed to the human, links the file they would execute *before* asking them to execute
it, and lets them run it themselves. Their instruction to their own agent after their own
review is a different thing entirely from a stranger's text.

Two agents' audits caught genuine errors — "the whole requestor is one short file" (it is
209 lines importing 13,154) and "no account or transfer anywhere in it" (it creates an
Ethereum account and receives a gas transfer). Both are corrected.

## 7. Prioritized next actions

From the 2026-08-03 product meeting, re-ordered by evidence and cost. Two of Yang's four
items are already done (receipt identifiers ✅, research brief published ✅).

**P0 — free or nearly free**
1. **Talk to Graywolf** (New Brunswick, via Mimmo). The only inbound demand signal in the
   entire meeting, and the PMF research's largest gap was the absence of exactly this.
2. **ERC-8004 TTL / validity-at-time.** Answers Mimmo's core objection and closes the
   biggest capability gap. Note the notes say "ERC804/80004"; it is **ERC-8004**, and it
   is still a **Draft EIP**, not final.

**P1 — cheap, high leverage**
3. **Public credential-free read path.** Precondition for honestly asking any market
   question.
4. **MCP registry listing** (Anthropic, OpenAI) — and serve something at the `agentURI`,
   which is discovered by the *counterparty* rather than the customer.

**P2 — real work**
5. **Log the transaction, not just the handshake.**
6. **Handle existing certificates.**

**P3 — think, don't build**
7. Time-as-token-measurement framework. Interesting, unvalidated, a different product.

## 8. Read this before betting the quarter

`/research/agent-attestation-pmf` (gated) is a PMF reality check from 14 agents across 6
sweeps with adversarial review. Its conclusion is disconfirming and I believe it is
correct: **no organization is known to pay for a standalone third-party receipt that an
agent was authorized.** The adjudicators (Google AP2, Visa TAP, Mastercard Verifiable
Intent) now issue the artifact free; the regulatory forcing function *weakened* in 2026;
and thirty-one years of notarization ventures died of one cause — nobody was ever
compelled to obtain proof from a party other than themselves.

Its cheapest test costs three days and nothing else: read the primary texts looking for
a clause requiring evidence from an entity the producer does not control. If there is
none, the ranked candidates weaken to near-zero.

The meeting reached a compatible worry independently: *"AI research has not identified a
killer use case where precise timing is the sole critical factor."*

## 9. Where things are

```
bin/operator.mjs        payer + operator; owns snapshot publication
bin/requestor.mjs       the requestor kit (209 lines; imports ~13k)
src/core/verdict.mjs    the ONLY site that emits AUTHORIZED, subjectRun-gated
src/core/roles-core.mjs payer writes proposal + acknowledgement; payee writes acceptance
src/relay/server.mjs    untrusted mailbox; also /v1/runs and /v1/blocks/{h}
src/monitor/snapshot.mjs  the wire shape, exact-key validated
prompts/                requestor.md, payer.md — both ≤75 lines, tested for skimmability
docs/for-ken.md         the human-addressed handoff that actually works
docs/RUNBOOK.md         operator runbook (the site page supersedes it)
scripts/check-invariants.sh   10 structural checks
```

Verify state with `npm run verify` (tests + invariants). 23 runs are recorded on the
relay: 13 reached a verdict, 3 stopped. **The failures are deliberately left in the run
log** — a table showing only wins would be a weaker claim than this system supports.
