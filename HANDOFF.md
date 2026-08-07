# Handoff — two-agent build + AWS migration

**As of:** 2026-08-07 · **Branch:** `main` · **872 tests pass, all 10 structural
invariants hold.** The previous handoff (still valid for context, landmines §4, known
gaps §5, and the stakeholder-prompt lesson §6) is archived at
[docs/handoff-2026-08-04.md](docs/handoff-2026-08-04.md).

## What you are executing

**[docs/two-agent-execution-plan.md](docs/two-agent-execution-plan.md).** That document
is the work. Every design decision in it is already made and validated; your job is to
execute it task by task, in order, passing each Verify block before moving on. Its §0
executor contract binds you; its §6 pitfall register is fifteen ways this exact system
has already failed. Do not redesign. When a STOP trigger fires, write it into §Blockers
below and stop.

Context behind the plan, if you need it: [docs/two-agent-build.md](docs/two-agent-build.md)
(locked decisions D1–D5, verified infrastructure map, phase rationale).

## State of play

| Piece | Status |
|---|---|
| Closing certificate (`src/core/result.mjs`, relay result endpoint, both parties fetch+verify) | ✅ shipped `4d096f1`, live-verified (blocks 3057376/3057397/3057399, agents 9427/9428) |
| Role-aware seating (`roleAlreadySeated`, unblocks two kits per session) | ✅ shipped `f80aa7a` |
| Track A (A1–A8): host severance + payer kit + gates G0/G1 | ⬜ next — start at A1 |
| Track B (B0–B6): MCP → AWS migration, gate GM | ⬜ parallel — start at B0 |
| P2 / P3 / P4 | ⬜ gated on both tracks |

Both tracks are independent until P2. Work them in parallel if you can; if you must pick
one, Track B's first steps (B0–B2) have the longest external waits — start them first,
then do Track A while AWS/DNS steps settle.

## Environment facts you'll need on day one

- Run everything from `/Users/Kailor/Documents/Projects/handshake`. `npm run verify`
  = tests + invariants; it gates every commit.
- `keys/` is gitignored and exists only on this laptop: funding wallet keystore +
  password file + Clockchain token. Treasury `0x157a377e…dce` had ~2.09 testnet ETH on
  08-04; **the new host funds two seats per run (~0.02 + gas)** — check balance in
  `npm run preflight` before gate runs.
- Relay box: `ssh -i ~/.ssh/handshake-relay.pem ubuntu@44.249.47.220`, code at
  `/opt/handshake/app`, service `handshake-relay`. Deploy = rsync + restart (exact
  commands in plan §A7).
- AWS: account `570035913370`, IAM user `Yang`, CLI signed in, region us-west-2.
- Clockchain MCP source: `github.com/thetangstr/clockchain-developer-tools` — clone it
  (plan §B0); it is not on this machine yet.
- Token mints: 10/hour/IP. Budget them around gates.

## Waiting on Yang (the only external dependencies)

1. **GoDaddy visit #1** (plan §B3): add `mcp-aws.clockchain.network` A-record → the new
   Elastic IP, and lower TTL on `mcp.clockchain.network` to 600. Ask once B2 yields the IP.
2. **GoDaddy visit #2** (plan §B5): flip `mcp.clockchain.network` → Elastic IP, in an
   agreed no-demo window.
3. **GCP stays billed/warm** through cutover and until a separate decommission decision.

## Blockers

*(append dated entries here; format: what you ran, what you expected, what you saw)*

— none yet —

## Evidence

*(gate results land here: gate id, date, session id, block heights, anything a skeptic
would ask for)*

- 2026-08-07 — certificate path (pre-G0 live run): session verified end-to-end, operator
  published certificate, requestor + independent third read both verified it against the
  descriptor key. Blocks 3057376 / 3057397 / 3057399, agents 9427 / 9428.

## Migration inventory

*(plan §B0's table gets filled in here — every row, even when the answer is "none")*

— not started —
