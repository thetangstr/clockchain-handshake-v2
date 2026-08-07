# Plan: two agents, with Clockchain as the operator

**Goal.** Today `bin/operator.mjs` is three roles in one process on Yang's laptop:
session host, **payer**, and verifier. The demo becomes: a **payer agent** and a
**requestor agent**, both independent, both joining with one URL — and **Clockchain
runs the middle**: hosts the session, funds both identities, and runs the independent
verifier. Neither party runs the checker that grades them.

```
TODAY                                   TARGET
─────                                   ──────
laptop: operator+payer+verifier         relay host: clockchain-host
   │  mandate, descriptor, verdict         │  session, funding, descriptor, VERDICT
   │                                       │
relay (mailbox) ── requestor agent      relay (mailbox) ─┬─ payer agent (bin/payer.mjs)
                                                         └─ requestor agent (unchanged)
```

## The one constraint that shapes everything

**Signing must stay on each agent's machine.** If the hosted MCP signs on behalf of
the parties, Clockchain can forge both sides and the demo's core claim — "we cannot
produce the other side's signature" — dies. So "do the handshake using the Clockchain
MCP" means: Clockchain the *service* takes over the operator role (host, fund,
verify, all via its own MCP-backed anchoring), while each agent keeps a thin local
kit that holds its run-local key. M3 packages that kit as a *local* MCP server so the
agent literally drives the handshake through tool calls — keys still never leave.

Verified starting points (all in the code today):
- `mintDemoToken({})` — requestor already self-mints; the payer kit does the same
  ([requestor.mjs:176](../bin/requestor.mjs)).
- The descriptor is signed by an **ephemeral ed25519 operator key**
  ([operator.mjs:265](../bin/operator.mjs)) — not the payer's key. That role moves to
  the host unchanged.
- `runPayerRole` / `runPayeeRole` are already severed ([roles-core.mjs](../src/core/roles-core.mjs));
  `buildMandate` already takes `payerAccount` and moves into the payer kit as-is.
- Evidence: requestor `putEvidence`s; the payer's evidence never leaves its machine
  today. The payer kit gains a `putEvidence({role:"payer"})`; the host fetches both.

## M0 — Sever the host (the real work)

New `bin/clockchain-host.mjs`, headless on the relay box (`44.249.47.220`):

1. **Session host** — opens a session, publishes discovery (the `current` alias keeps
   working untouched), assembles + signs the descriptor with its ephemeral key once
   both signed artifacts (mandate, payment request) arrive.
2. **Funder** — funds **both** parties' fresh addresses on `identity_ready`. The
   funding record gains the claimed `role`, and each kit checks the funded address is
   its own (the ROLE_ALREADY_BOUND backstop, now per-role: two payers race-tested the
   same way two requestors were).
3. **Verifier** — `verifyBilateralAuthorization` moves here from
   [operator.mjs:445](../bin/operator.mjs). This is the narrative upgrade: the checker
   is now genuinely a third party, not the payer grading its own trade.
4. **Snapshot publisher** — the host sees every relay message; the board's rule
   ("verdict only ever from the verifier's return value") gets stronger, not weaker.

**Ops step, not code:** `keys/` (funding wallet + password) must be provisioned onto
the relay host (`scp`, 0600, path outside the repo checkout). It exists only on the
laptop today and is gitignored — a fact, not an accident, so do it deliberately.

**Gate M0:** host + both kits as three local processes → `AUTHORIZED`, and the
verdict provably emitted by the host process, not either kit.

## M1 — The payer kit

`bin/payer.mjs`, symmetric to `bin/requestor.mjs`: one URL in, fresh key, self-mint
token, `identity_ready(role:"payer")`, await funding addressed to itself, register
ERC-8004, **build and sign the mandate locally** — with `issuedAtMs` taken from
Clockchain `get_timestamp`, not the local clock. That closes HANDOFF §4.3's residual
risk *before* arbitrary payer machines make clock skew worse, instead of after.

Then `runPayerRole`, upload evidence, and stop **without naming an outcome** — the
same discipline as the requestor: neither party speaks the verdict; only the host's
verifier does, and it appears on the monitor.

Handoff doc in the `for-ken.md` pattern — addressed to the human, code linked before
any ask to run it. **Do not iterate the prompt to satisfy refusing agents** (HANDOFF
§6; three refusals prove the pattern).

**Gate M1:** relay-hosted host + payer kit and requestor kit on two separate
machines → `AUTHORIZED`; two-payers race → second stops `ROLE_ALREADY_BOUND`,
nothing spent.

## M2 — Board and page

- Board roles: "D4D's agent", "BuzzHive's agent", and **"Clockchain — session host &
  independent checker"** as the named middle. Receipts unchanged (terms + signer
  already on them).
- Runbook page: both prompts paste-able; "you (the presenter) run nothing but the
  host" — or nothing at all, if the host runs as systemd.
- **Deploy order is the §4.1 landmine:** relay snapshot validator first, host second,
  kits last; verify with a real run, not the suite (§4.2 — fixtures have lied twice).

**Gate M2:** a stranger-shaped dry run: two fresh agent sessions, two prompts, no
operator terminal on stage, verdict lands on the board.

## M3 (optional) — The kit as a local MCP server

Wrap `payer.mjs`/`requestor.mjs` in a local MCP server (`join_session`,
`publish_terms`, `accept_terms`, `upload_evidence` as tools). The agent experience
becomes "add this MCP server, then drive the handshake by tool calls" — the literal
reading of the request — while signing stays local. Defer if time is short; the CLI
path is the same protocol.

## Costs and risks

- **Gas:** funding both sides ≈ doubles per-run cost to ~0.02–0.03 ETH. Treasury
  (2.09) covers ~70 runs.
- **Token rate limit:** payer machines now mint too — 10/hr/IP is per *their* IP, so
  it spreads load rather than concentrating it.
- **Custodial trap:** any future "just let the server sign" shortcut re-opens
  forgeability. The invariant to add: neither party key ever leaves its kit process.
- **What this is not:** escrow, smart-contract execution, real identities, public
  verification — the deep-interview vision stays parked until this base is standing.

## Order of execution

M0 → M1 are sequential (kit needs the host). M2 overlaps M1. Estimate: M0+M1 one
focused day given the severance already done; M2 half a day; M3 separate.
