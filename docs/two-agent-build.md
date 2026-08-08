# Build plan: two agents, Clockchain-operated — on AWS

**Historical note (2026-08-08):** P4 is complete. Remaining operator language in
this file is historical plan text, not current public terminology or a live
instruction to restore the retired operator path.

**Date:** 2026-08-07 · Extends [two-agent-plan.md](two-agent-plan.md); where they differ,
this document wins. Decisions were made explicitly by Yang; facts marked *verified*
were checked against live infrastructure or repos on the date above.

## Locked decisions

- **D1 — The host belongs to Clockchain's side, not the laptop.**
- **D2 — No local MCP, ever. The interface is the official `mcp.clockchain.network`.**
  The custodial constraint holds — the hosted MCP never touches a party's key — via
  **prepare / sign / submit**: the MCP prepares canonical bytes, the agent signs with
  its own wallet (EIP-191 is the only client-side requirement), and submits the
  signature. CLI kits remain as reference clients and test harness.
- **D3 — Always one session open.** Host opens on boot, reopens on completion; the
  permanent discovery URL is fully self-serve.
- **D4 — The signed `handshake-result/v1` closing certificate ships in P0**, delivered
  to both parties. The schema exists today with no emitter; the requestor currently
  never receives the verdict at all.
- **D5 — Consolidate on AWS.** The MCP migrates from GCP Cloud Run to AWS, and the
  Lightsail relay is folded into the MCP's deployment to the extent that makes sense.
  The GCP-IAM prerequisite from the previous revision of this plan is **dead**.

## The infrastructure map, verified

| Thing | Where today | Evidence |
|---|---|---|
| MCP API (`mcp.clockchain.network`) | **GCP Cloud Run** | IP `136.68.167.2` → Google LLC; `server: Google Frontend` |
| Chain node (`node.clockchain.network`) | **already AWS** | `54.176.69.37` → Amazon Technologies |
| Relay (mailbox/monitor) | **AWS Lightsail** | `44.249.47.220` → Amazon |
| DNS for `clockchain.network` | **GoDaddy** | NS `ns19/ns20.domaincontrol.com` |
| MCP source | `thetangstr/clockchain-developer-tools` | Dockerfile, `deployment.md`, `CLOUD-RUN.md`, CI in `.github` |

Two implications worth stating plainly. **The migration is smaller than it sounded:**
the chain node — the stateful, scary part — is already on AWS; what moves is a
containerized API service whose deployment is already documented. (*Verified 08-07,
post-login:* the node is **not in Yang's AWS account** `570035913370` — no instance in
us-west-1/2 carries its IP — so it is the Clockchain team's box. M consolidates our
account; the node stays external and unmoved.) And **P3 got
simpler:** with the MCP codebase in hand, the handshake tools are implemented
directly in the MCP server — the load-balancer routing fallback from the previous
revision is withdrawn.

## Phase sequence

```
P0 ── P1 ──────────────┐
        M (migration) ─┼── P2 ── P3 ── P4
```

P0/P1 run on the laptop and depend on nothing above; start immediately. M runs in
parallel. P2 lands the host next to the migrated MCP; P3 puts the tools in it.

## P0 — Sever the host (laptop)

1. `bin/clockchain-host.mjs`: session lifecycle per D3; discovery publishing (the
   `current` alias untouched); **funding for both roles** with role-tagged records;
   descriptor assembly + ephemeral-key signing; the verifier; snapshot publishing;
   and per D4, emission of the signed `handshake-result/v1`.
2. Relay: result endpoint (`PUT`/`GET /v1/sessions/{sid}/result`) + validator.
   **Relay deploys first** — landmine §4.1 (an unknown snapshot field blanks the
   board while the protocol completes normally).
3. Compatibility: legacy `npm run demo` untouched until P4 cutover.

**Gate G0:** three local processes → `AUTHORIZED`; verdict and certificate provably
emitted by the host; both kits fetch the certificate; legacy path green; suite +
invariants pass.

## P1 — The payer kit

`bin/payer.mjs`, symmetric to the requestor: one URL → fresh key → self-minted token
→ `identity_ready(role:"payer")` → funding record checked against own address →
ERC-8004 registration → **mandate signed locally with `issuedAtMs` from Clockchain
`get_timestamp`** (closes §4.3's residual clock-skew risk) → `runPayerRole` →
evidence upload → fetch certificate → exit without naming an outcome.

Handoff doc in the `for-ken.md` pattern; do not iterate persuasion (§6).

**Gate G1:** true multi-machine run → `AUTHORIZED`, certificate on both sides;
two-payers race → second stops `ROLE_ALREADY_BOUND`, nothing spent.

## M — Migrate the MCP to AWS, absorb the relay

Discovery-first, in `clockchain-developer-tools`:

1. **Inventory state.** Read `deployment.md` / `CLOUD-RUN.md` / the server source:
   where do token quotas, receipts/ledger ids, and any secrets live? What does the
   service call — does it reach `node.clockchain.network`, or does the node push to
   it? The answer decides whether anything beyond the container moves.
2. **Deploy in parallel on AWS** (target chosen by what step 1 finds — the Lightsail
   box is sized for a relay, so likely ECS/App Runner-class or a larger instance;
   `clockchain-agent-runtime` already establishes an AWS pattern for Clockchain
   services). GCP stays up and serving throughout.
3. **Verify against the AWS deployment directly** (its own URL, before DNS): token
   mint, `log_action`, `get_block`, a full handshake run pointed at it.
4. **Cut over DNS at GoDaddy** (`mcp.clockchain.network` → AWS), TTL lowered first.
   GCP kept warm for rollback until a full demo passes post-cutover.
5. **Fold in the relay** where sensible: same host/deployment family, one systemd/
   container story, one deploy path. The relay's disk journal moves with it or the
   relay simply stays on its Lightsail box under the same operational umbrella —
   step 1's findings decide, and "makes sense" is the bar, not completionism.

**Gate GM:** a full handshake run + preflight, with `mcp.clockchain.network`
resolving to AWS, and the GCP service no longer in any request path. **Demo
continuity is a hard constraint:** at every moment during M, `npm run demo` works.

## P2 — Host onto the AWS deployment

Containerize `clockchain-host.mjs`; deploy beside the migrated MCP; treasury keys
provisioned deliberately (Secrets Manager or 0600 file per the M-step-1 pattern);
kits' defaults point at it. **Gate G2:** full run with no process on the laptop.

## P3 — Handshake tools in the MCP server

Implemented directly in `clockchain-developer-tools` (codebase in hand — no routing
workaround): `handshake_status`, `handshake_prepare_*` → canonical bytes,
`handshake_submit_*` ← signature, `handshake_get_certificate`.

**Gate G3:** an agent configured with only `mcp.clockchain.network` plus any EIP-191
signing capability completes a full side; certificate fetched through the MCP.
**Invariant: no party key ever touches the server.**

## P4 — Board, page, cutover

Board names the middle: "Clockchain — session host & independent checker." Runbook
updated; legacy operator retired after a stranger-shaped dry run. Landmines carried:
§4.1 deploy order, §4.2 verify-with-a-real-run, §4.8 token quotas.

## Estimates

P0+P1 ≈ one focused day. M ≈ one to two days, dominated by step 1's findings and
DNS TTL waits. P2 ≈ half a day. P3 ≈ one to two days. P4 ≈ half a day.

## Waiting on Yang — all discovered today, none guessed

1. **`aws login`** — the local AWS session is expired (verified); M and P2 cannot
   start without it.
2. **GoDaddy DNS access** for the `mcp.clockchain.network` record — M step 4.
3. **Keep GCP billing/service alive through M** for rollback; decommission is a
   separate, later decision.
