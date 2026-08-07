# Build plan: two agents, Clockchain-operated

**Date:** 2026-08-04 · Extends [two-agent-plan.md](two-agent-plan.md); where they differ,
this document wins. Decisions below were made explicitly by Yang; facts marked
*verified* were checked against live infrastructure today.

## Locked decisions

- **D1 — The host belongs to Clockchain's side, not the laptop.** *Verified:*
  `44.249.47.220` is Amazon (AWS Lightsail) — it runs the relay today. The end state
  puts the host under Clockchain's GCP alongside the MCP. *Verified blocker:*
  `gcloud run.services.list` on project `clockchain-mcp` returns PERMISSION_DENIED
  for `thetangstr@gmail.com` — deploy access must be granted before P2 can land
  there. Until then the host runs where the keys already are (laptop), then Lightsail
  or GCP once access is resolved.
- **D2 — No local MCP, ever. The interface is the official `mcp.clockchain.network`.**
  This kills the old M3 and replaces it with P3 below. The custodial constraint
  still holds — the hosted MCP must never hold a party's key — so the pattern is
  **prepare / sign / submit**: the MCP prepares the exact canonical bytes, the
  agent signs them with its own key (the only client-side requirement is an EIP-191
  signature — a wallet, not a server), and submits the signature back. The CLI kits
  remain as reference clients and the test harness, not the product interface.
- **D3 — Always one session open.** The host opens a session on boot and reopens on
  completion. The permanent discovery URL becomes truly self-serve: either agent can
  arrive whenever.
- **D4 — The signed closing certificate ships in P0.** `handshake-result/v1` exists
  in `constants.mjs` with no emitter, and the requestor never receives the verdict
  today. The host emits the signed result to the relay; **both** kits fetch it. This
  is the run's actual deliverable — the closing file.

## P0 — Sever the host (runs on the laptop first)

1. **`bin/clockchain-host.mjs`** — session lifecycle per D3; discovery publishing
   (the `current` alias is untouched); **funding for both roles** with role-tagged
   funding records; descriptor assembly + ephemeral-key signing; the verifier; the
   snapshot publisher; and per D4, emit the signed `handshake-result/v1`.
2. **Relay:** a result endpoint (`PUT`/`GET /v1/sessions/{sid}/result`) with its
   validator. **Deploy the relay first** — landmine §4.1: an unknown field blanks
   the board for the whole run while the protocol completes normally.
3. **Compatibility:** `npm run demo` (the fused operator) keeps working unchanged.
   Parallel paths until P4 cutover — the working demo is not collateral.

**Gate G0:** three local processes → `AUTHORIZED`; verdict and certificate provably
emitted by the host; both kits fetch the certificate; the legacy path still green;
full suite + invariants pass.

## P1 — The payer kit

`bin/payer.mjs`, symmetric to the requestor: one URL → fresh key → self-minted token
→ `identity_ready(role:"payer")` → funding record checked against its own address →
ERC-8004 registration → **mandate built and signed locally, `issuedAtMs` taken from
Clockchain `get_timestamp`** (closes §4.3's residual clock-skew risk before arbitrary
payer machines widen it) → `runPayerRole` → evidence upload → fetch certificate →
exit without naming an outcome. The certificate speaks; the party does not.

Handoff doc in the `for-ken.md` pattern. Do not iterate persuasion (§6 — three
refusals proved the pattern).

**Gate G1:** host on one machine, kits on others → `AUTHORIZED`, certificate on both
sides; two-payers race → second stops `ROLE_ALREADY_BOUND`, nothing spent.

## P2 — Host onto Clockchain infrastructure

**Prerequisite (Yang):** GCP IAM on `clockchain-mcp` (Cloud Run deploy + Secret
Manager), or an explicit decision to use Lightsail instead.

1. Containerize the host; keys via Secret Manager (GCP) or a 0600 file (Lightsail).
2. Deploy; the relay stays on Lightsail this build — its journal is disk state, and
   migrating it is out of scope.
3. Kits' defaults point at the hosted host.

**Gate G2:** a full run with **no process on the laptop**.

## P3 — Handshake tools on the official MCP (the D2 end state)

**Prerequisite:** the `mcp.clockchain.network` server codebase, *or* load-balancer
path routing — precedent verified: the MCP LB already proxies `/playground` to the
Vercel app (`x-cc-via: mcp-lb`), so routing `/handshake` to the host service delivers
the same tools under the official domain without touching the MCP server's code.

Tools (prepare/sign/submit): `handshake_status`, `handshake_prepare_*` (returns the
canonical bytes to sign), `handshake_submit_*` (accepts the signature),
`handshake_get_certificate`. Signing stays with the agent's own wallet.

**Gate G3:** an agent configured with only `mcp.clockchain.network` plus any EIP-191
signing capability completes a full side of the handshake; certificate fetched
through the MCP. **The invariant, restated: no party key ever touches the server.**

## P4 — Board, page, cutover

Roles on the board: the two agents, and **"Clockchain — session host & independent
checker"** as the named middle. Runbook updated; legacy operator path retired only
after a stranger-shaped dry run passes. Landmines carried: §4.1 deploy order, §4.2
verify-with-a-real-run (fixtures have lied twice), §4.8 token quotas.

## Order and estimates

P0 → P1 sequential (~1 focused day together). P2 ~half a day plus the IAM wait.
P3 ~1–2 days once its prerequisite resolves. P4 half a day. P2 and P3 can be
reordered if IAM lands late — nothing in P3's LB route depends on P2.

## Waiting on Yang

1. GCP IAM grant on `clockchain-mcp` (or "use Lightsail" call) — blocks P2.
2. MCP codebase access *or* LB routing confirmation — shapes P3 (the LB route is the
   fallback that needs only what we already run).
